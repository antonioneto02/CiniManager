# Da ao usuario antonio.neto permissao de alterar os arquivos em C:\Projetos (inclusive os gravados
# pelos containers como ContainerAdministrator) e aplica a whitelist nova do IPBan.
# Executar como Administrador:  .\liberar-permissao.ps1
$ErrorActionPreference = 'Stop'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Execute este script como Administrador.' }

Write-Host 'Liberando permissao em C:\Projetos (pode levar alguns minutos)...' -ForegroundColor Cyan
& icacls.exe 'C:\Projetos' /grant 'antonio.neto:(OI)(CI)M' /T /C /Q
Write-Host "icacls terminou (codigo $LASTEXITCODE)." -ForegroundColor Green

Write-Host "`nAplicando whitelist nova no IPBan..." -ForegroundColor Cyan
& (Join-Path $PSScriptRoot 'configure-ipban.ps1') -NoInstall
