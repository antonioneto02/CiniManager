$DESTINATARIO  = "554188529918"
$ALERT_FILE    = "$PSScriptRoot\last-alerts.json"
$STATE_FILE    = "$PSScriptRoot\health-state.json"
$DB_SERVER     = "localhost"
$DB_NAME       = "dw"
$DB_USER       = "cini.tracking"
$DB_PASSWORD   = "k00b82f6j9TO6alM"
$HEARTBEAT_HORA = 8  

function Write-Log($msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$ts] $msg"
}

function Insert-Notificacao($mensagem) {
    try {
        $connStr = "Server=$DB_SERVER;Database=$DB_NAME;User Id=$DB_USER;Password=$DB_PASSWORD;TrustServerCertificate=True;"
        $conn = New-Object System.Data.SqlClient.SqlConnection($connStr)
        $conn.Open()
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = @"
INSERT INTO [dbo].[FATO_FILA_NOTIFICACOES]
  (TIPO_MENSAGEM, DESTINATARIO, MENSAGEM, STATUS, TENTATIVAS, DTINC)
VALUES
  ('texto', @dest, @msg, 'PENDENTE', 0, GETDATE())
"@
        $cmd.Parameters.AddWithValue("@dest", $DESTINATARIO) | Out-Null
        $cmd.Parameters.AddWithValue("@msg",  $mensagem)      | Out-Null
        $cmd.ExecuteNonQuery() | Out-Null
        $conn.Close()
        return $true
    } catch {
        Write-Log "ERRO ao inserir notificação: $_"
        return $false
    }
}

function Load-Alerts {
    if (Test-Path $ALERT_FILE) {
        try { return Get-Content $ALERT_FILE -Raw | ConvertFrom-Json -AsHashtable }
        catch { }
    }
    return @{}
}

function Save-Alerts($alerts) {
    $alerts | ConvertTo-Json | Set-Content $ALERT_FILE -Encoding UTF8
}

function Load-State {
    if (Test-Path $STATE_FILE) {
        try { return Get-Content $STATE_FILE -Raw | ConvertFrom-Json -AsHashtable }
        catch { }
    }
    return @{}
}

function Save-State($state) {
    $state | ConvertTo-Json | Set-Content $STATE_FILE -Encoding UTF8
}

Write-Log "Verificando status dos processos PM2..."

try {
    $pm2Json   = pm2 jlist 2>$null
    $processes = $pm2Json | ConvertFrom-Json
} catch {
    Write-Log "ERRO ao consultar PM2: $_"
    exit 1
}

if (-not $processes -or $processes.Count -eq 0) {
    Write-Log "Nenhum processo PM2 ativo."
    exit 0
}

$alerts  = Load-Alerts
$state   = Load-State
$now     = Get-Date
$changed = $false
$stateChanged = $false
$appProcesses = $processes | Where-Object { $_.name -notlike "pm2-*" -and $_.name -ne "log-watcher" -and $_.name -ne "cini-dashboard" }

foreach ($proc in $appProcesses) {
    $name   = $proc.name
    $status = $proc.pm2_env.status

    Write-Log "  $name → $status"

    if ($status -ne "online") {
        $jaAvisado = $alerts.ContainsKey($name)
        if (-not $jaAvisado) {
            $ts  = Get-Date -Format "dd/MM/yyyy HH:mm"
            $msg = "🚨 *PROCESSO CAÍDO*`nApp: *$name*`nStatus: *$status*`nHorário: $ts`n`nVer log: pm2 logs $name --lines 30"
            Write-Log "Enviando alerta: $name está $status"
            if (Insert-Notificacao $msg) {
                $alerts[$name] = $now.ToString("o")
                $changed = $true
            }
        } else {
            Write-Log "  (aguardando recuperação de $name)"
        }
    } else {
        if ($alerts.ContainsKey($name)) {
            $ts  = Get-Date -Format "dd/MM/yyyy HH:mm"
            $msg = "✅ *PROCESSO RECUPERADO*`nApp: *$name*`nVoltou ao ar em $ts"
            Write-Log "App $name recuperado. Notificando..."
            Insert-Notificacao $msg | Out-Null
            $alerts.Remove($name)
            $changed = $true
        }
    }
}

$uptimeMin = (Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime | Select-Object -ExpandProperty TotalMinutes
$jaNotificouBoot = $state.ContainsKey("lastBootNotification")
if ($jaNotificouBoot) {
    $lastBoot = [DateTime]::Parse($state["lastBootNotification"])
    $jaNotificouBoot = ($now - $lastBoot).TotalMinutes -lt 60
}

if ($uptimeMin -lt 15 -and -not $jaNotificouBoot) {
    $todosOnline = ($appProcesses | Where-Object { $_.pm2_env.status -ne "online" }).Count -eq 0
    $totalApps   = $appProcesses.Count
    $onlineApps  = ($appProcesses | Where-Object { $_.pm2_env.status -eq "online" }).Count

    $ts  = Get-Date -Format "dd/MM/yyyy HH:mm"
    $msg = "🖥️ *SERVIDOR REINICIADO*`n🕐 $ts`n`n"

    if ($todosOnline) {
        $msg += "✅ Todos os *$totalApps* apps voltaram online:`n"
        foreach ($proc in $appProcesses | Sort-Object { $_.name }) {
            $msg += "  • $($proc.name)`n"
        }
    } else {
        $msg += "⚠️ *$onlineApps/$totalApps* apps online após boot`n"
        foreach ($proc in $appProcesses | Sort-Object { $_.name }) {
            $icon = if ($proc.pm2_env.status -eq "online") { "✅" } else { "❌" }
            $msg += "  $icon $($proc.name)`n"
        }
    }

    Write-Log "Notificando boot do servidor..."
    if (Insert-Notificacao $msg) {
        $state["lastBootNotification"] = $now.ToString("o")
        $stateChanged = $true
    }
}

$horaAtual = $now.Hour
$minAtual  = $now.Minute
$hoje      = $now.ToString("yyyy-MM-dd")
$lastHeartbeat = $state["lastHeartbeat"]
$jaEnviouHoje  = ($lastHeartbeat -eq $hoje)

if ($horaAtual -eq $HEARTBEAT_HORA -and $minAtual -lt 10 -and -not $jaEnviouHoje) {
    $todosOnline = ($appProcesses | Where-Object { $_.pm2_env.status -ne "online" }).Count -eq 0
    $onlineApps  = ($appProcesses | Where-Object { $_.pm2_env.status -eq "online" }).Count
    $totalApps   = $appProcesses.Count

    if ($todosOnline) {
        $linhas = ($appProcesses | Sort-Object { $_.name } | ForEach-Object {
            $mem     = [math]::Round($_.monit.memory / 1024 / 1024)
            $uptime  = if ($_.pm2_env.pm_uptime) {
                $diff = ($now - ([DateTimeOffset]::FromUnixTimeMilliseconds($_.pm2_env.pm_uptime)).DateTime)
                if ($diff.TotalDays -ge 1) { "$([int]$diff.TotalDays)d $($diff.Hours)h" }
                elseif ($diff.TotalHours -ge 1) { "$([int]$diff.TotalHours)h $($diff.Minutes)m" }
                else { "$($diff.Minutes)m" }
            } else { "—" }
            "  ✅ $($_.name) — up $uptime, $mem MB"
        }) -join "`n"

        $msg = "☀️ *BOM DIA — RESUMO DO SERVIDOR*`n🕐 $(Get-Date -Format 'dd/MM/yyyy HH:mm')`n`n*Todos os $totalApps apps estão online:*`n$linhas"
    } else {
        $msg = "⚠️ *RESUMO DIÁRIO*`n🕐 $(Get-Date -Format 'dd/MM/yyyy HH:mm')`n`n*$onlineApps/$totalApps apps online*`n"
        foreach ($proc in $appProcesses | Sort-Object { $_.name }) {
            $icon = if ($proc.pm2_env.status -eq "online") { "✅" } else { "❌" }
            $msg += "  $icon $($proc.name)`n"
        }
    }

    Write-Log "Enviando heartbeat diário..."
    if (Insert-Notificacao $msg) {
        $state["lastHeartbeat"] = $hoje
        $stateChanged = $true
    }
}

if ($changed)      { Save-Alerts $alerts }
if ($stateChanged) { Save-State  $state  }

Write-Log "Health check concluído."
