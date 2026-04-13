$BACKUP_ROOT = "E:\Projetos\monitor\backups"
$DATE_FOLDER = Get-Date -Format "yyyy-MM-dd"
$DEST        = Join-Path $BACKUP_ROOT $DATE_FOLDER
$KEEP_DAYS   = 30  
$projects = @(
    @{ name = "api-weduu";           path = "C:\Projetos\API_Weduu" },
    @{ name = "erp-cini";            path = "E:\Projetos\Gestao_Portaria\erp_cini" },
    @{ name = "wf-cini";             path = "E:\Projetos\WF_Cini\wf_cini" },
    @{ name = "central-tarefas";     path = "E:\Projetos\Central_Tarefas" },
    @{ name = "hub-cini";            path = "E:\Projetos\Hub_Cini" },
    @{ name = "cini-pricing";        path = "E:\Projetos\Cini-Pricing" },
    @{ name = "api-sicredi";         path = "E:\Projetos\API_Sicredi" },
    @{ name = "notificador-pix";     path = "C:\Projetos\Confirmacao_Pix\NotificadorPIX" },
    @{ name = "whatsapp-bot";        path = "E:\Projetos\Central-Notificacoes\whatsapp-bot" },
    @{ name = "whatsapp-motoristas"; path = "E:\Projetos\Central-Notificacoes\WhatsAppMotoristas" }
)

$sensitivePatterns = @(".env", "*.cer", "*.key", "*.crt", "*.pem", "*.pfx")

function Write-Log($msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$ts] $msg"
}

Write-Log "Iniciando backup para: $DEST"
New-Item -ItemType Directory -Force -Path $DEST | Out-Null

$total = 0
$erros = 0

foreach ($proj in $projects) {
    if (-not (Test-Path $proj.path)) {
        Write-Log "AVISO: Diretório não encontrado: $($proj.path)"
        continue
    }

    $projDest = Join-Path $DEST $proj.name
    New-Item -ItemType Directory -Force -Path $projDest | Out-Null

    foreach ($pattern in $sensitivePatterns) {
        $files = Get-ChildItem -Path $proj.path -Filter $pattern -Recurse -ErrorAction SilentlyContinue |
                 Where-Object { $_.FullName -notmatch "node_modules" }

        foreach ($file in $files) {
            $relativePath = $file.FullName.Substring($proj.path.Length).TrimStart('\')
            $destFile     = Join-Path $projDest $relativePath
            $destDir      = Split-Path $destFile -Parent

            New-Item -ItemType Directory -Force -Path $destDir | Out-Null
            Copy-Item -Path $file.FullName -Destination $destFile -Force
            Write-Log "  Backup: $($proj.name)\$relativePath"
            $total++
        }
    }
}

Write-Log "Backup concluído: $total arquivo(s) copiado(s), $erros erro(s)."
Write-Log "Limpando backups com mais de $KEEP_DAYS dias..."
$cutoff = (Get-Date).AddDays(-$KEEP_DAYS)

Get-ChildItem -Path $BACKUP_ROOT -Directory | Where-Object {
    try {
        $folderDate = [DateTime]::ParseExact($_.Name, "yyyy-MM-dd", $null)
        return $folderDate -lt $cutoff
    } catch { return $false }
} | ForEach-Object {
    Remove-Item -Path $_.FullName -Recurse -Force
    Write-Log "  Removido backup antigo: $($_.Name)"
}

Write-Log "Rotação de backups concluída."
