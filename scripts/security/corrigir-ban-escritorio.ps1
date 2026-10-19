# Correcao de 19/10/2026: o IP 45.182.132.102 (Cini) foi banido porque a gestao-importacao-pedidos
# contava "acesso negado" como excesso de requisicoes; em seguida o Windows Firewall foi desligado.
# Este script: religa o firewall, desbane o IP, aplica a whitelist nova e reinicia as apps
# (modulo corrigido: recusa por rede nao conta mais para ban).
# Executar como Administrador:  .\corrigir-ban-escritorio.ps1
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Execute este script como Administrador.' }

Write-Host "`n== 1/3 Religando o Windows Firewall (permitir tudo; so os bans do IPBan bloqueiam)" -ForegroundColor Cyan
& .\enable-host-firewall.ps1

Write-Host "`n== 2/3 Desbanindo 45.182.132.102" -ForegroundColor Cyan
'45.182.132.102' | Set-Content 'C:\Program Files\IPBan\unban.txt'
Start-Sleep 20
Get-Content 'C:\Program Files\IPBan\logfile.txt' -Tail 30 | Select-String '45\.182\.132\.102' | Select-Object -Last 2 | ForEach-Object Line

Write-Host "`n== 3/3 Whitelist nova + reinicio das apps" -ForegroundColor Cyan
& .\aplicar-fail2ban.ps1
