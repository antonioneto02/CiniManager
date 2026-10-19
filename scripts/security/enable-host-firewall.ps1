# Liga o Windows Firewall do appserverwin em modo "permitir tudo": o acesso NAO muda,
# so passam a valer as regras de BLOQUEIO que o IPBan cria (bloqueio vence permitir).
# O firewall de borda continua sendo quem decide quais portas ficam expostas.
#
#   .\enable-host-firewall.ps1             -> liga (permitir tudo)
#   .\enable-host-firewall.ps1 -Rollback   -> desliga de novo (estado anterior)
#
# Executar como Administrador.
param([switch]$Rollback)
$ErrorActionPreference = 'Stop'

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Execute este script como Administrador.' }

if ($Rollback) {
    Set-NetFirewallProfile -All -Enabled False
    Write-Host 'Windows Firewall DESLIGADO (rollback). Bans do IPBan deixam de valer.' -ForegroundColor Yellow
} else {
    Set-NetFirewallProfile -All -DefaultInboundAction Allow -DefaultOutboundAction Allow -Enabled True
    Write-Host 'Windows Firewall LIGADO com entrada/saida permitidas por padrao.' -ForegroundColor Green
}

Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -AutoSize
