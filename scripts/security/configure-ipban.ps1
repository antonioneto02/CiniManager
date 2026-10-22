param([switch]$NoInstall)
$ErrorActionPreference = 'Stop'

$Whitelist = '127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,177.104.136.227,200.225.247.91,200.225.247.159,35.205.198.169,' +
             '45.182.132.102,201.48.9.65,151.245.54.63,177.126.4.190,177.198.74.248,177.104.136.224/29,143.137.87.235'
$BanTime = '01:00:00:00,07:00:00:00,30:00:00:00'
$FailedLoginAttemptsBeforeBan = 5
$Tipos = @(
    @{ Type = 'SCANNER';    Threshold = 2 },
    @{ Type = 'RATE_LIMIT'; Threshold = 3 },
    @{ Type = 'LOGIN_FAIL'; Threshold = 5 }
)

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Execute este script como Administrador.' }

$fw = Get-NetFirewallProfile | Where-Object { -not $_.Enabled }
if ($fw) { throw "Windows Firewall desligado em: $($fw.Name -join ', '). Rode enable-host-firewall.ps1 antes." }

$ipbanDir = 'C:\Program Files\IPBan'
$configPath = Join-Path $ipbanDir 'ipban.config'

if (-not (Test-Path $configPath)) {
    if ($NoInstall) { throw "IPBan nao encontrado em $ipbanDir." }
    Write-Host 'Instalando IPBan (instalador oficial DigitalRuby)...'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = 'SilentlyContinue'
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DigitalRuby/IPBan/master/IPBanCore/Windows/Scripts/install_latest.ps1'))
    if (-not (Test-Path $configPath)) { throw 'Instalacao do IPBan falhou.' }
}

auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /failure:enable | Out-Null

Copy-Item $configPath "$configPath.bak-$(Get-Date -Format yyyyMMdd-HHmmss)"
[xml]$xml = Get-Content $configPath -Raw -Encoding UTF8
function Set-AppSetting([string]$key, [string]$value) {
    $node = $xml.configuration.appSettings.add | Where-Object { $_.key -eq $key }
    if (-not $node) {
        $node = $xml.CreateElement('add')
        $node.SetAttribute('key', $key)
        $xml.configuration.appSettings.AppendChild($node) | Out-Null
    }
    $node.SetAttribute('value', $value)
}

Set-AppSetting 'Whitelist' $Whitelist
Set-AppSetting 'BanTime' $BanTime
Set-AppSetting 'FailedLoginAttemptsBeforeBan' "$FailedLoginAttemptsBeforeBan"
Set-AppSetting 'UseDefaultBannedIPAddressHandler' 'false'

$apps = Get-Content (Join-Path $PSScriptRoot 'fail2ban-apps.json') -Raw | ConvertFrom-Json

$logFiles = $xml.configuration.LogFilesToParse.LogFiles
foreach ($antigo in @($logFiles.LogFile | Where-Object { $_.Source -like 'CiniF2B-*' })) {
    $logFiles.RemoveChild($antigo) | Out-Null
}

foreach ($t in $Tipos) {
    $paths = ($apps | ForEach-Object { Join-Path $_.dir "logs\security\$($t.Type.ToLower())-*.log" }) -join "`n"
    $lf = $xml.CreateElement('LogFile')
    $campos = [ordered]@{
        Source                              = "CiniF2B-$($t.Type)"
        PathAndMask                         = $paths
        FailedLoginRegex                    = "CINI-F2B type=$($t.Type) ip=(?<ipaddress>\S+) app=\S+"
        FailedLoginRegexTimestampFormat     = ''
        SuccessfulLoginRegex                = ''
        SuccessfulLoginRegexTimestampFormat = ''
        PlatformRegex                       = 'Windows'
        PingInterval                        = '5000'
        MaxFileSize                         = '16777216'
        FailedLoginThreshold                = "$($t.Threshold)"
    }
    foreach ($k in $campos.Keys) {
        $el = $xml.CreateElement($k)
        if ($k -like '*Regex') { $el.AppendChild($xml.CreateCDataSection($campos[$k])) | Out-Null }
        else { $el.InnerText = $campos[$k] }
        $lf.AppendChild($el) | Out-Null
    }
    $logFiles.AppendChild($lf) | Out-Null
}

$xml.Save($configPath)
Restart-Service IPBAN
Write-Host "IPBan configurado e reiniciado. Log: $ipbanDir\logfile.txt" -ForegroundColor Green
Get-Service IPBAN | Format-Table Name, Status, StartType -AutoSize
