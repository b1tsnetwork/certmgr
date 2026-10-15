# PowerShell 7.4+, works with manually converted files (PFX, P12, DER, PEM, P7B etc.)
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$BaseUrl,
  [Parameter(Mandatory)][string]$Profile,
  [Parameter(Mandatory)][string]$Certificate,
  [Parameter(Mandatory)][string]$Destination,
  [Parameter(Mandatory)][string]$TokenFile,
  [Parameter(Mandatory)][string[]]$Artifacts
)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion -lt [version]'7.4') { throw 'PowerShell 7.4+ erforderlich.' }
$base = $BaseUrl.TrimEnd('/')
if ($base -notmatch '^https://') { throw 'HTTPS ist erforderlich.' }
foreach ($v in @($Profile,$Certificate)+$Artifacts) {
  if ($v -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$' -or $v.Contains('..')) { throw "Ungültige Bezeichnung: $v" }
}
$token = [IO.File]::ReadAllText($TokenFile).Trim()
if ($token -notmatch '^cw_[A-Za-z0-9_-]+$') { throw 'Ungültige Token-Datei' }
$headers = @{ Authorization = "Bearer $token" }
$api = "$base/api/v1/distribution/$Profile/$Certificate"
$manifest = Invoke-RestMethod -Uri "$api/manifest" -Headers $headers -TimeoutSec 60
if ($manifest.profile -ne $Profile -or $manifest.certificate -ne $Certificate -or $manifest.version -notmatch '^[A-Za-z0-9_-]+$') { throw 'Ungültiges Manifest' }
New-Item -ItemType Directory -Path $Destination -Force | Out-Null
if ($IsWindows) {
  # Protect target from inherited ACLs before staging sensitive files.
  $acl = Get-Acl $Destination
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($rule in @($acl.Access)) { $acl.RemoveAccessRuleAll($rule) | Out-Null }
  $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
  $access = [System.Security.AccessControl.FileSystemAccessRule]::new(
    $identity,[System.Security.AccessControl.FileSystemRights]::FullControl,
    [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow)
  $acl.AddAccessRule($access)
  Set-Acl $Destination $acl
} else { & chmod 700 $Destination }
$stage = Join-Path $Destination ('.certwatch-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
try {
  foreach ($f in $Artifacts) {
    if ($f -notin @($manifest.artifacts)) { throw "Keine Freigabe für $f" }
    $artifact = Join-Path $stage $f
    Invoke-WebRequest -Uri "$api/versions/$($manifest.version)/artifacts/$f" -Headers $headers -OutFile $artifact -TimeoutSec 60 | Out-Null
    $info = @($manifest.artifact_details | Where-Object name -eq $f)
    if ($info.Count -gt 0) {
      $digest = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
      if ($digest -ne $info[0].sha256 -or (Get-Item $artifact).Length -ne $info[0].size) { throw "SHA256/Größe falsch: $f" }
    }
  }
  foreach ($f in $Artifacts) { Move-Item -LiteralPath (Join-Path $stage $f) -Destination (Join-Path $Destination $f) -Force }
  [IO.File]::WriteAllText((Join-Path $Destination '.certwatch-format-version'),"$Profile/$Certificate@$($manifest.version)`n")
  if (-not $IsWindows) { foreach ($f in $Artifacts) { & chmod 600 (Join-Path $Destination $f) } }
  Write-Output "Aktualisiert: $Profile/$Certificate ($($manifest.version)): $($Artifacts -join ', ')"
} finally {
  Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}
