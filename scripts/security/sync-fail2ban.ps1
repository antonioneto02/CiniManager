# Copia CiniManager\shared\cini-fail2ban.js (apps Node) e cini_fail2ban.py (apps Python) para
# <App>\security\ de cada app em fail2ban-apps.json e garante logs/security/ no .gitignore.
# Rodar sempre que alterar a fonte; depois reiniciar as apps.
$ErrorActionPreference = 'Stop'
$shared = Join-Path $PSScriptRoot '..\..\shared' | Resolve-Path
$apps = Get-Content (Join-Path $PSScriptRoot 'fail2ban-apps.json') -Raw | ConvertFrom-Json
$falhas = 0

foreach ($app in $apps) {
    if (-not (Test-Path $app.dir)) { Write-Warning "$($app.name): pasta $($app.dir) nao existe"; continue }
    try {
        if (-not $app.usesSharedSource) {
            $destDir = Join-Path $app.dir 'security'
            New-Item -ItemType Directory -Force $destDir | Out-Null
            $isPython = (Test-Path (Join-Path $app.dir 'requirements.txt')) -and -not (Test-Path (Join-Path $app.dir 'package.json'))
            $arquivo = if ($isPython) { 'cini_fail2ban.py' } else { 'cini-fail2ban.js' }
            Copy-Item (Join-Path $shared $arquivo) (Join-Path $destDir $arquivo) -Force
        }

        $gitignore = Join-Path $app.dir '.gitignore'
        $linhas = if (Test-Path $gitignore) { Get-Content $gitignore } else { @() }
        if (-not ($linhas | Where-Object { $_.Trim() -in @('logs/security/', 'logs/security', 'logs/', 'logs', '/logs', '/logs/') })) {
            Add-Content -Path $gitignore -Value "`nlogs/security/" -Encoding utf8
        }
        Write-Host "$($app.name): ok"
    } catch {
        $falhas++
        Write-Warning "$($app.name): $($_.Exception.Message)"
    }
}
if ($falhas) { Write-Warning "$falhas app(s) com erro - rode como Administrador." }
