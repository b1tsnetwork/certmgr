<#
.SYNOPSIS
  Holt eine zusammengehörige Zertifikatsversion von UCNG Certificate Manager.
.DESCRIPTION
  -Target IIS: PFX/P12 laden und vorhandene HTTPS-Bindung aktualisieren.
  -Target Apache: Fullchain + Private Key im Zielverzeichnis ablegen.
  -Target Files: exakt die für einen Dienst freigegebenen Artefakte verteilen.
  Alle geheimen Artefakte benötigen einen API-Bearer-Token.
  -ServiceID verwendet einen dedizierten Dienst-Token und dessen Format-Whitelist.
.EXAMPLE
  $env:UCNG_CERT_TOKEN = '<Token aus Secret Store>'
  .\Install-CentralCertificate.ps1 -ServerUrl 'https://certs.example.com' `
    -CertificateName 'wildcard-example-com' -Target IIS -SiteName 'Default Web Site' `
    -Port 443 -HostHeader 'portal.example.com'
.EXAMPLE
  ./Install-CentralCertificate.ps1 -ServerUrl https://certs.example.com `
    -ServiceID DIESEN_DIENST_AUS_DER_WEB_UI -Target Apache `
    -Destination /etc/apache2/ucng-certs -ReloadService apache2
#>
[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory)][string]$ServerUrl,
  [string]$CertificateName,
  [string]$ServiceID,
  [ValidateSet('IIS','Apache','Files')][string]$Target = 'Files',
  [string]$Token = $env:UCNG_CERT_TOKEN,
  [string]$SiteName,
  [int]$Port = 443,
  [string]$HostHeader = '',
  [string]$Destination,
  [string]$ReloadService
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ([string]::IsNullOrWhiteSpace($Token)) { throw 'API-Token fehlt: -Token oder Umgebungsvariable UCNG_CERT_TOKEN.' }
if ([bool]$CertificateName -eq [bool]$ServiceID) { throw 'Bitte genau einen Parameter angeben: -CertificateName (alter API-Modus) ODER -ServiceID (neuer Dienst-Modus).' }
if ($CertificateName -and $CertificateName -notmatch '^[a-zA-Z0-9_-][a-zA-Z0-9_.-]{0,127}$') { throw 'Ungültiger Zertifikatsname.' }
if ($ServiceID -and $ServiceID -notmatch '^[a-zA-Z0-9_-][a-zA-Z0-9_.-]{0,127}$') { throw 'Ungültige Dienst-ID.' }
$uri = [uri]$ServerUrl
if ($uri.Scheme -ne 'https' -and -not ($uri.Scheme -eq 'http' -and $uri.Host -in @('localhost','127.0.0.1','::1'))) {
  throw 'ServerUrl muss HTTPS verwenden (HTTP nur für lokale Tests).'
}
if ($Target -eq 'IIS' -and -not $SiteName) { throw 'Für IIS ist -SiteName erforderlich.' }
if ($Target -ne 'IIS' -and -not $Destination) { throw 'Für Apache/Files ist -Destination erforderlich.' }
if ($ReloadService -and $Target -ne 'Apache') { throw '-ReloadService ist nur für Apache erlaubt.' }
if ($ReloadService -and $ReloadService -notmatch '^[a-zA-Z0-9_.@-]+$') { throw 'Ungültiger Service-Name.' }
if ($PSVersionTable.PSVersion.Major -eq 5) { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }
$isUnixPlatform = ($PSVersionTable.PSVersion.Major -ge 6 -and $PSVersionTable.Platform -eq 'Unix')
if ($ServiceID) { $api = $ServerUrl.TrimEnd('/') + '/api/v1/services/' + [uri]::EscapeDataString($ServiceID) }
else { $api = $ServerUrl.TrimEnd('/') + '/api/v1/certificates/' + [uri]::EscapeDataString($CertificateName) }
$headers = @{ Authorization = 'Bearer ' + $Token }
$work = Join-Path ([IO.Path]::GetTempPath()) ('ucngcert-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($work) | Out-Null
if (-not $isUnixPlatform) {
  # Im Windows-Temp des aufrufenden Servicekontos liegt der Ordner bereits im geschützten Profil.
} else { & chmod 700 $work; if ($LASTEXITCODE -ne 0) { throw 'chmod 700 fehlgeschlagen' } }

function Get-Artifact([string]$FileName) {
  $entry = @($manifest.artifacts | Where-Object { $_.name -ceq $FileName })
  if ($entry.Count -ne 1) { throw "Artefakt $FileName nicht verfügbar oder nicht autorisiert." }
  $url = "$api/versions/$version/artifacts/$([uri]::EscapeDataString($FileName))"
  $path = Join-Path $work $FileName
  $param = @{ Uri=$url; Headers=$headers; OutFile=$path; ErrorAction='Stop' }
  if ($PSVersionTable.PSVersion.Major -eq 5) { $param.UseBasicParsing=$true }
  Invoke-WebRequest @param | Out-Null
  $digest = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
  if ($digest -ine [string]$entry[0].sha256) { throw "SHA256-Fehler bei $FileName" }
  return $path
}
function Copy-Restricted([string]$Source,[string]$TargetFile) {
  # Datei in einem geschützten lokalen Zielordner erstellen; vorhandene Datei atomar ersetzen.
  $dir = Split-Path -Parent $TargetFile
  if (-not (Test-Path -LiteralPath $dir)) { [IO.Directory]::CreateDirectory($dir) | Out-Null }
  $tempFile = Join-Path $dir ('.incoming-' + [guid]::NewGuid().ToString('N'))
  try {
    [IO.File]::WriteAllBytes($tempFile, [IO.File]::ReadAllBytes($Source))
    if ($isUnixPlatform) { & chmod 600 $tempFile; if ($LASTEXITCODE -ne 0) { throw 'chmod 600 fehlgeschlagen' } }
    if ([IO.File]::Exists($TargetFile)) {
      # File.Replace tauscht eine vorhandene Datei auf demselben Dateisystem atomar aus.
      [IO.File]::Replace($tempFile, $TargetFile, $null)
    } else { [IO.File]::Move($tempFile, $TargetFile) }
    if ($isUnixPlatform) { & chmod 600 $TargetFile; if ($LASTEXITCODE -ne 0) { throw 'chmod 600 nach Austausch fehlgeschlagen' } }
  } finally { Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue }
}
try {
  $manifest = Invoke-RestMethod -Method Get -Uri $api -Headers $headers -ErrorAction Stop
  if ($ServiceID -and $manifest.service_id -cne $ServiceID) { throw 'Die API hat einen unerwarteten Dienst zurückgegeben.' }
  if ($CertificateName -and $manifest.name -cne $CertificateName) { throw 'Die API hat ein unerwartetes Zertifikat zurückgegeben.' }
  $version = [string]$manifest.version
  if ($version -notmatch '^[0-9a-f]{24}$') { throw 'Die API liefert keine gültige, feste Zertifikatsversion.' }
  $expires = [datetime]$manifest.not_after
  if ($expires.ToUniversalTime() -le [datetime]::UtcNow.AddDays(1)) { throw 'Zertifikat abgelaufen oder innerhalb von 24 Stunden ungültig.' }
  Write-Host "Zertifikat: $($manifest.name) / Version $version (bis $expires)" -ForegroundColor Cyan

  if ($Target -eq 'IIS') {
    $pfxName = 'leaf-chain.pfx'
    if (@($manifest.artifacts | Where-Object { $_.name -ceq $pfxName }).Count -eq 0) { $pfxName = 'leaf-only.pfx' }
    $leafDer = Get-Artifact 'leaf.der'
    $leafCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([IO.File]::ReadAllBytes($leafDer))
    Import-Module WebAdministration -ErrorAction Stop
    $bindings = @(Get-WebBinding -Name $SiteName -Protocol 'https' -ErrorAction Stop | Where-Object {
      $pieces = $_.bindingInformation -split ':'
      $pieces.Count -ge 3 -and $pieces[$pieces.Count - 2] -eq [string]$Port -and $pieces[$pieces.Count - 1] -ieq $HostHeader
    })
    if ($bindings.Count -ne 1) { throw "Erwartet genau eine bestehende HTTPS-Bindung für $SiteName, Port $Port, Host '$HostHeader'; gefunden: $($bindings.Count)." }
    # Die Bindung wird ausschließlich aktualisiert, wenn vorher alle Downloads valide waren.
    if ($PSCmdlet.ShouldProcess($SiteName,"PFX importieren und HTTPS-Bindung für $HostHeader`:$Port aktualisieren")) {
      $cert = Get-Item -LiteralPath ('Cert:\LocalMachine\My\' + $leafCert.Thumbprint) -ErrorAction SilentlyContinue
      if (-not $cert -or -not $cert.HasPrivateKey) {
        $pfx = Get-Artifact $pfxName
        $passwordFile = Get-Artifact 'pfx-password.txt'
        $passwordText = [IO.File]::ReadAllText($passwordFile).Trim()
        $securePassword = ConvertTo-SecureString -String $passwordText -AsPlainText -Force
        $passwordText = $null
        $imported = @(Import-PfxCertificate -FilePath $pfx -CertStoreLocation 'Cert:\LocalMachine\My' -Password $securePassword -ErrorAction Stop)
        $keyCerts = @($imported | Where-Object { $_.HasPrivateKey -and $_.Thumbprint -eq $leafCert.Thumbprint })
        if ($keyCerts.Count -ne 1) { throw 'PFX-Import liefert kein passendes Zertifikat mit privatem Schlüssel.' }
        $cert = $keyCerts[0]
      }
      $bindings[0].AddSslCertificate($cert.Thumbprint,'My')
      Write-Host "IIS-Bindung aktualisiert: $SiteName ($($cert.Thumbprint))" -ForegroundColor Green
    }
  } elseif ($Target -eq 'Apache') {
    $path = [IO.Path]::GetFullPath($Destination)
    if ($PSCmdlet.ShouldProcess($path,"Zertifikatsdateien für $Target ersetzen")) {
      [IO.Directory]::CreateDirectory($path) | Out-Null
      if ($isUnixPlatform) { & chmod 700 $path; if ($LASTEXITCODE -ne 0) { throw 'chmod 700 fehlgeschlagen' } }
      $key = Get-Artifact 'private-key.pem'
      $fullchain = Get-Artifact 'fullchain.pem'
      Copy-Restricted $key (Join-Path $path 'privkey.pem')
      Copy-Restricted $fullchain (Join-Path $path 'fullchain.pem')
      if (@($manifest.artifacts | Where-Object { $_.name -ceq 'chain-intermediates.pem' }).Count) {
        $chain = Get-Artifact 'chain-intermediates.pem'
        Copy-Restricted $chain (Join-Path $path 'chain.pem')
      }
      Write-Host "PEM-Dateien aktualisiert in $path" -ForegroundColor Green
      if ($ReloadService) {
        if (-not $isUnixPlatform) { throw 'Automatisches Apache-Reload über systemctl wird nur auf Linux unterstützt.' }
        & systemctl reload $ReloadService
        if ($LASTEXITCODE -ne 0) { throw "Reload von $ReloadService fehlgeschlagen" }
      }
    }
  } else {
    # Files: anhand des serverseitig eingeschränkten Service-Manifests ALLE
    # ausgewählten Formate herunterladen, SHA256 prüfen und im Ziel ablegen.
    $files = @($manifest.artifacts)
    if ($files.Count -eq 0) { throw 'Manifest hat keine für diesen Token freigegebenen Dateien.' }
    $downloaded = @{}
    foreach ($entry in $files) {
      $file = [string]$entry.name
      if ($file -notmatch '^[a-zA-Z0-9_.-]+$' -or $file -in @('.', '..') -or $file.StartsWith('.')) { throw "Ungültiger Dateiname: $file" }
      $downloaded[$file] = Get-Artifact $file
    }
    $path = [IO.Path]::GetFullPath($Destination)
    if ($PSCmdlet.ShouldProcess($path, "Alle $($files.Count) erlaubten Formate aktualisieren")) {
      [IO.Directory]::CreateDirectory($path) | Out-Null
      if ($isUnixPlatform) { & chmod 700 $path; if ($LASTEXITCODE -ne 0) { throw 'chmod 700 fehlgeschlagen' } }
      foreach ($file in $downloaded.Keys) { Copy-Restricted $downloaded[$file] (Join-Path $path $file) }
      Write-Host "$($files.Count) Dateien aktualisiert in $path" -ForegroundColor Green
    }
  }
} finally {
  $headers.Authorization = ''
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
