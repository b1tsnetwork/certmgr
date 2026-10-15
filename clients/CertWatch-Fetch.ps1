# PowerShell 7.4+ (Windows/Linux/macOS), OpenSSL required when -IncludePrivateKey.
# Example: ./CertWatch-Fetch.ps1 -BaseUrl https://certwatch.example.org -Profile intranet -Certificate web -Destination C:\certs -TokenFile C:\secrets\certwatch.token -IncludePrivateKey
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$BaseUrl,
    [Parameter(Mandatory=$true)][string]$Profile,
    [Parameter(Mandatory=$true)][string]$Certificate,
    [Parameter(Mandatory=$true)][string]$Destination,
    [Parameter(Mandatory=$true)][string]$TokenFile,
    [switch]$IncludePrivateKey
)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion -lt [version]'7.4') { throw 'PowerShell 7.4+ erforderlich.' }
$base = $BaseUrl.TrimEnd('/')
if (-not $base.StartsWith('https://',[StringComparison]::OrdinalIgnoreCase)) { throw 'HTTPS ist Pflicht.' }
foreach ($value in @($Profile,$Certificate)) {
    if ($value -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$') { throw 'Ungültige Zertifikatskennung.' }
}
$token = [IO.File]::ReadAllText($TokenFile).Trim()
if ($token -notmatch '^cw_[A-Za-z0-9_-]+$') { throw 'Token-Datei ist ungültig.' }
$headers = @{ Authorization = "Bearer $token" }
$api = "$base/api/v1/distribution/$Profile/$Certificate"
New-Item -ItemType Directory -Path $Destination -Force | Out-Null
if ($IncludePrivateKey) {
    if ($IsWindows) {
        # Remove inherited access before creating the temporary private key.
        # Apply the current service account as the only explicit principal.
        $acl = Get-Acl -Path $Destination
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($acl.Access)) { $acl.RemoveAccessRuleAll($rule) | Out-Null }
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $access = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity, [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($access)
        Set-Acl -Path $Destination -AclObject $acl
    } else {
        & chmod 700 $Destination
        if ($LASTEXITCODE -ne 0) { throw 'Zielverzeichnis konnte nicht geschützt werden.' }
    }
}
$stage = Join-Path ([IO.Path]::GetFullPath($Destination)) ('.certwatch-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage -Force | Out-Null
try {
    $manifest = Invoke-RestMethod -Uri "$api/manifest" -Headers $headers -TimeoutSec 40
    if ($manifest.profile -ne $Profile -or $manifest.certificate -ne $Certificate -or $manifest.version -notmatch '^[0-9]{14}-[A-Za-z0-9_-]{8,24}$') { throw 'Ungültige Manifest-Daten.' }
    $version = [string]$manifest.version
    $versionPath = Join-Path $Destination '.certwatch-version'
    $releaseMarker = "$Profile/$Certificate@$version"
    if ((Test-Path $versionPath) -and ((Get-Content $versionPath -Raw).Trim() -eq $releaseMarker) -and (Test-Path (Join-Path $Destination 'fullchain.pem')) -and (-not $IncludePrivateKey -or (Test-Path (Join-Path $Destination 'privkey.pem')))) {
        Write-Output "Unverändert: $Profile/$Certificate ($version)"
        return
    }
    $versionUrl = "$api/versions/$version/artifacts"
    foreach ($file in @('cert.pem','chain.pem','fullchain.pem')) {
        Invoke-WebRequest -Uri "$versionUrl/$file" -Headers $headers -OutFile (Join-Path $stage $file) -TimeoutSec 40 | Out-Null
    }
    $sha = (Get-FileHash -Algorithm SHA256 (Join-Path $stage 'fullchain.pem')).Hash.ToLowerInvariant()
    if ($sha -ne $manifest.version_sha256) { throw 'SHA256 der Zertifikatskette stimmt nicht.' }
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile((Join-Path $stage 'cert.pem'))
    if ($cert.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) { throw 'Zertifikat ist abgelaufen.' }
    $fullCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile((Join-Path $stage 'fullchain.pem'))
    if ($fullCert.Thumbprint -ne $cert.Thumbprint) { throw 'Zertifikat und fullchain.pem stimmen nicht überein.' }
    if ($IncludePrivateKey) {
        if ($null -eq (Get-Command openssl -ErrorAction SilentlyContinue)) { throw 'OpenSSL wird für die Private-Key-Prüfung benötigt.' }
        Invoke-WebRequest -Uri "$versionUrl/privkey.pem" -Headers $headers -OutFile (Join-Path $stage 'privkey.pem') -TimeoutSec 40 | Out-Null
        & openssl x509 -in (Join-Path $stage 'cert.pem') -pubkey -noout -out (Join-Path $stage 'certpub.pem')
        if ($LASTEXITCODE -ne 0) { throw 'Ungültiger Zertifikatsschlüssel.' }
        & openssl pkey -in (Join-Path $stage 'privkey.pem') -pubout -out (Join-Path $stage 'keypub.pem')
        if ($LASTEXITCODE -ne 0) { throw 'Ungültiger privater Schlüssel.' }
        & openssl pkey -pubin -in (Join-Path $stage 'certpub.pem') -outform DER -out (Join-Path $stage 'certpub.der')
        if ($LASTEXITCODE -ne 0) { throw 'Ungültiger Public Key.' }
        & openssl pkey -pubin -in (Join-Path $stage 'keypub.pem') -outform DER -out (Join-Path $stage 'keypub.der')
        if ($LASTEXITCODE -ne 0) { throw 'Ungültiger Private-Key Public-Anteil.' }
        if ((Get-FileHash -Algorithm SHA256 (Join-Path $stage 'certpub.der')).Hash -ne
            (Get-FileHash -Algorithm SHA256 (Join-Path $stage 'keypub.der')).Hash) { throw 'Private Key passt nicht zum Zertifikat.' }
    }
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    foreach ($file in @('cert.pem','chain.pem','fullchain.pem')) { Move-Item -Path (Join-Path $stage $file) -Destination (Join-Path $Destination $file) -Force }
    if ($IncludePrivateKey) {
        Move-Item -Path (Join-Path $stage 'privkey.pem') -Destination (Join-Path $Destination 'privkey.pem') -Force
    }
    [IO.File]::WriteAllText($versionPath,$releaseMarker+"`n")
    if ($IncludePrivateKey -and -not $IsWindows) {
        & chmod 700 $Destination
        & chmod 600 (Join-Path $Destination 'privkey.pem')
        if ($LASTEXITCODE -ne 0) { throw 'Dateirechte konnten nicht gesetzt werden.' }
    }
    Write-Output "Aktualisiert: $Profile/$Certificate ($version)"
} finally {
    Remove-Item -Path $stage -Recurse -Force -ErrorAction SilentlyContinue
}
# The target directory is locked to the invoking Windows service account when
# private distribution is used. Grant additional service identities only if needed.
