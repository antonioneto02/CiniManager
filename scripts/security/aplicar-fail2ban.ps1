param([switch]$SemReiniciar)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Execute este script como Administrador.' }

$node = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $node) { $node = 'C:\nodejs\node.exe' }
$apps = Get-Content .\fail2ban-apps.json -Raw | ConvertFrom-Json
$containerDe = @{ 'portal-marketing' = 'cini-bom-gourmet' }
$problemas = New-Object System.Collections.ArrayList

Write-Host "`n== 1/6 Integrando guard nas apps Node" -ForegroundColor Cyan
& $node .\integrar-node.js
if ($LASTEXITCODE) { throw 'integrar-node.js falhou' }

Write-Host "`n== 2/6 Copiando modulos" -ForegroundColor Cyan
& .\sync-fail2ban.ps1 | Out-Null
Write-Host 'ok'

Write-Host "`n== 3/6 Conferindo sintaxe" -ForegroundColor Cyan
foreach ($app in $apps) {
    $arquivos = Get-ChildItem $app.dir -Recurse -Depth 2 -Include *.js -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '\\(node_modules|security|public|dist)\\' } |
        Select-String -Pattern 'cini-fail2ban' -List | ForEach-Object Path
    foreach ($f in $arquivos) {
        $saida = & $node --check $f 2>&1
        if ($LASTEXITCODE) { [void]$problemas.Add("SINTAXE $f : $saida"); Write-Host "ERRO $f" -ForegroundColor Red }
    }
}
$python = @{
    'portal-streamlit'     = @('security/cini_fail2ban.py', 'pages/login.py')
    'gerenciador-cargas'   = @('security/cini_fail2ban.py', 'gerenciador_cargas/settings.py', 'gerenciador_cargas/urls.py')
    'central-notificacoes' = @('security/cini_fail2ban.py', 'central_notificacoes.py')
    'client-baixas-pix'    = @('security/cini_fail2ban.py', 'app.py')
}
foreach ($c in $python.Keys) {
    $estado = docker inspect -f '{{.State.Status}}' $c 2>$null
    if ($estado -ne 'running') { Write-Host "$c parado - sintaxe Python nao conferida"; continue }
    $dockerArgs = @('exec', '-w', 'C:\app', $c, 'C:\Python\python.exe', '-m', 'py_compile') + $python[$c]
    $saida = & docker @dockerArgs 2>&1
    if ($LASTEXITCODE) { [void]$problemas.Add("SINTAXE $c : $saida"); Write-Host "ERRO $c : $saida" -ForegroundColor Red }
}
if ($problemas.Count) { throw "Erros de sintaxe - nada foi reiniciado:`n$($problemas -join "`n")" }
Write-Host 'ok'

Write-Host "`n== 4/6 Reconfigurando IPBan" -ForegroundColor Cyan
& .\configure-ipban.ps1 -NoInstall | Out-Null
Write-Host 'ok'

if ($SemReiniciar) { Write-Host "`n-SemReiniciar: apps e log-watcher NAO reiniciados."; return }

Write-Host "`n== 5/6 Reiniciando containers que estao rodando" -ForegroundColor Cyan
$ordem = @($apps | Where-Object { $_.name -ne 'cini-dashboard' }) + @($apps | Where-Object { $_.name -eq 'cini-dashboard' })
$reiniciados = @()
foreach ($app in $ordem) {
    $c = if ($containerDe[$app.name]) { $containerDe[$app.name] } else { $app.name }
    $estado = docker inspect -f '{{.State.Status}}' $c 2>$null
    if ($estado -eq 'running') { docker restart $c | Out-Null; $reiniciados += $app; Write-Host "  $c reiniciado" }
    elseif ($estado) { Write-Host "  $c esta '$estado' - nao mexi" -ForegroundColor DarkGray }
    else { Write-Host "  $c nao existe" -ForegroundColor DarkGray }
}

Write-Host "  aguardando as apps subirem (40s)..."
Start-Sleep 40
foreach ($app in $reiniciados) {
    $ok = $false
    for ($i = 0; $i -lt 6 -and -not $ok; $i++) {
        $tcp = New-Object Net.Sockets.TcpClient
        try { $ok = $tcp.ConnectAsync('127.0.0.1', [int]$app.port).Wait(1500) } catch { } finally { $tcp.Close() }
        if (-not $ok) { Start-Sleep 5 }
    }
    if (-not $ok) { [void]$problemas.Add("$($app.name) (porta $($app.port)) nao voltou a responder") ; Write-Host "  FALHOU $($app.name) porta $($app.port)" -ForegroundColor Red }
}

Write-Host "`n== 6/6 Reiniciando cini-log-watcher" -ForegroundColor Cyan
Restart-Service cini-log-watcher
Get-Service cini-log-watcher | Format-Table Name, Status -AutoSize

if ($problemas.Count) {
    Write-Host "`nATENCAO:" -ForegroundColor Yellow
    $problemas | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
    Write-Host "Veja o log da app com: docker logs --tail 50 <nome>"
} else {
    Write-Host "`nTudo aplicado: $($reiniciados.Count) apps reiniciadas e respondendo." -ForegroundColor Green
}
