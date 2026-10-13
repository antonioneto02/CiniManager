$SCRIPTS_DIR = "E:\Projetos\CiniManager"
$CMD_EXE     = "$env:WINDIR\System32\cmd.exe"
$PS_EXE      = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$PS_ARGS_TPL = "-WindowStyle Hidden -NonInteractive -ExecutionPolicy Bypass -File `"{0}`" >> `"{1}`" 2>&1"

function Register-Task($taskName, $scriptFile, $logFile, $trigger) {
    $psArgs  = $PS_ARGS_TPL -f $scriptFile, $logFile
    $action  = New-ScheduledTaskAction -Execute $CMD_EXE -Argument "/c `"$PS_EXE $psArgs`""
    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
        -RestartCount 0 `
        -StartWhenAvailable
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

    try {
        Register-ScheduledTask `
            -TaskName   $taskName `
            -Action     $action `
            -Trigger    $trigger `
            -Settings   $settings `
            -RunLevel   Highest `
            -Force -ErrorAction Stop | Out-Null
        Write-Host "[OK] Tarefa registrada: $taskName" -ForegroundColor Green
    } catch {
        Write-Host "[FALHOU] Tarefa NAO registrada: $taskName - $_" -ForegroundColor Red
        Write-Host "         (precisa rodar este script numa PowerShell como Administrador)" -ForegroundColor Red
    }
}
$triggerHealthCheck = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) -Once -At (Get-Date)
Register-Task `
    -taskName   "CINI - Health Check PM2" `
    -scriptFile "$SCRIPTS_DIR\health-check.ps1" `
    -logFile    "$SCRIPTS_DIR\logs\health-check.log" `
    -trigger    $triggerHealthCheck
$triggerBackup = New-ScheduledTaskTrigger -Daily -At "03:00"

Register-Task `
    -taskName   "CINI - Backup ENV e Certificados" `
    -scriptFile "$SCRIPTS_DIR\backup-env.ps1" `
    -logFile    "$SCRIPTS_DIR\logs\backup.log" `
    -trigger    $triggerBackup
$triggerKillOrphans = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) -Once -At (Get-Date)
Register-Task `
    -taskName   "CINI - Kill Processos Orfaos" `
    -scriptFile "$SCRIPTS_DIR\kill-orphan-processes.ps1" `
    -logFile    "$SCRIPTS_DIR\logs\kill-orphan-processes.log" `
    -trigger    $triggerKillOrphans
New-Item -ItemType Directory -Force -Path "$SCRIPTS_DIR\logs" | Out-Null

Write-Host ""
Write-Host "Tarefas agendadas com sucesso!" -ForegroundColor Cyan
Write-Host ""
Write-Host "Para verificar:" -ForegroundColor Yellow
Write-Host "  Get-ScheduledTask | Where-Object { `$_.TaskName -like 'CINI*' } | Format-Table TaskName, State"
Write-Host ""
Write-Host "Para executar manualmente agora:" -ForegroundColor Yellow
Write-Host "  Start-ScheduledTask -TaskName 'CINI - Health Check PM2'"
Write-Host "  Start-ScheduledTask -TaskName 'CINI - Backup ENV e Certificados'"
