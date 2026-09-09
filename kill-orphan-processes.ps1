param(
    [switch]$WhatIf
)

$GRACE_SECS = 30

function Write-Log($msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$ts] $msg"
}

Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class ProcCwdReader {
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr Reserved3;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr hProcess, int infoClass, ref PROCESS_BASIC_INFORMATION info, int infoLen, out int returnLen);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr baseAddr, byte[] buffer, int size, out int bytesRead);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll")]
    private static extern bool IsWow64Process(IntPtr hProcess, out bool wow64);

    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ = 0x0010;

    // Offsets validos para Windows x64: PEB.ProcessParameters = 0x20,
    // RTL_USER_PROCESS_PARAMETERS.CurrentDirectory (UNICODE_STRING) = 0x38.
    public static string GetCwd(int pid) {
        IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (hProcess == IntPtr.Zero) return null;
        try {
            bool wow64;
            if (IsWow64Process(hProcess, out wow64) && wow64) return null; // processo 32-bit, offsets diferentes

            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            int retLen;
            int status = NtQueryInformationProcess(hProcess, 0, ref pbi, Marshal.SizeOf(pbi), out retLen);
            if (status != 0 || pbi.PebBaseAddress == IntPtr.Zero) return null;

            byte[] ptrBuf = new byte[8];
            int read;
            if (!ReadProcessMemory(hProcess, IntPtr.Add(pbi.PebBaseAddress, 0x20), ptrBuf, 8, out read) || read != 8) return null;
            long paramsAddr = BitConverter.ToInt64(ptrBuf, 0);
            if (paramsAddr == 0) return null;

            byte[] curDir = new byte[16];
            if (!ReadProcessMemory(hProcess, new IntPtr(paramsAddr + 0x38), curDir, 16, out read) || read != 16) return null;
            ushort length = BitConverter.ToUInt16(curDir, 0);
            long bufferAddr = BitConverter.ToInt64(curDir, 8);
            if (bufferAddr == 0 || length == 0 || length > 4096) return null;

            byte[] strBuf = new byte[length];
            if (!ReadProcessMemory(hProcess, new IntPtr(bufferAddr), strBuf, length, out read) || read <= 0) return null;
            return Encoding.Unicode.GetString(strBuf, 0, read).TrimEnd('\\');
        } finally {
            CloseHandle(hProcess);
        }
    }
}
"@

function Normalize-Path($p) {
    if (-not $p) { return $null }
    return ($p -replace '/', '\').TrimEnd('\').ToLowerInvariant()
}

Write-Log "Verificando processos orfaos (node.exe/python.exe)..."

try {
    $slimJson = pm2 jlist 2>$null | node "$PSScriptRoot\pm2-jlist-slim.js"
    $pm2Apps  = $slimJson | ConvertFrom-Json
} catch {
    Write-Log "ERRO ao consultar PM2: $_"
    exit 1
}

$cwdMap = @{}

foreach ($app in $pm2Apps) {
    $cwd = Normalize-Path $app.cwd
    if (-not $cwd) { continue }

    if (-not $cwdMap.ContainsKey($cwd)) {
        $cwdMap[$cwd] = [pscustomobject]@{
            ValidPids = New-Object System.Collections.Generic.List[int]
            SkipRound = $false
            Broken    = $false
            Names     = New-Object System.Collections.Generic.List[string]
        }
    }
    $entry = $cwdMap[$cwd]
    if (-not $entry.Names.Contains($app.name)) { $entry.Names.Add($app.name) }

    $status = $app.status
    if ($status -in @('launching', 'restarting', 'stopping')) {
        $entry.SkipRound = $true
    }
    if ($status -in @('stopped', 'errored')) {
        $entry.Broken = $true
    }
    if ($status -eq 'online' -and [int64]$app.pid -gt 0) {
        $validPid = [int]$app.pid
        if (-not $entry.ValidPids.Contains($validPid)) { $entry.ValidPids.Add($validPid) }
    }
}

$daemonPid = $null
try {
    $pm2Home = $env:PM2_HOME
    if (-not $pm2Home) { $pm2Home = Join-Path $env:USERPROFILE '.pm2' }
    $pidFile = Join-Path $pm2Home 'pm2.pid'
    if (Test-Path $pidFile) { $daemonPid = [int](Get-Content $pidFile -Raw).Trim() }
} catch {
    Write-Log "AVISO: nao foi possivel ler o PID do daemon do PM2 ($_)."
}

if (-not $daemonPid) {
    Write-Log "ERRO FATAL: nao foi possivel determinar o PID do daemon do PM2. Abortando por seguranca (nunca rodar sem essa protecao)."
    exit 1
}
Write-Log "Daemon do PM2 protegido: PID $daemonPid"
$allProcs  = Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId
$childrenOf = @{}
foreach ($p in $allProcs) {
    $ppid = [int]$p.ParentProcessId
    if (-not $childrenOf.ContainsKey($ppid)) { $childrenOf[$ppid] = New-Object System.Collections.Generic.List[int] }
    $childrenOf[$ppid].Add([int]$p.ProcessId)
}

function Get-DescendantPids($rootPid) {
    $result = New-Object System.Collections.Generic.List[int]
    $queue  = New-Object System.Collections.Generic.Queue[int]
    $queue.Enqueue($rootPid)
    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        if (-not $result.Contains($current)) { $result.Add($current) }
        if ($childrenOf.ContainsKey($current)) {
            foreach ($child in $childrenOf[$current]) { $queue.Enqueue($child) }
        }
    }
    return $result
}

$protectedPids = New-Object System.Collections.Generic.HashSet[int]
[void]$protectedPids.Add($daemonPid)
foreach ($entry in $cwdMap.Values) {
    foreach ($validPid in $entry.ValidPids) {
        foreach ($descendant in (Get-DescendantPids $validPid)) {
            [void]$protectedPids.Add($descendant)
        }
    }
}

$targets = Get-CimInstance Win32_Process -Filter "Name='node.exe' OR Name='python.exe' OR Name='pythonw.exe'" |
    Where-Object {
        $_.ProcessId -ne $daemonPid -and
        $_.CommandLine -notmatch [regex]::Escape('pm2\lib\Daemon.js')
    }

if (-not $targets) {
    Write-Log "Nenhum processo node/python em execucao."
    exit 0
}

$now = Get-Date
$killed = 0
$unmanaged = 0

foreach ($proc in $targets) {
    $procId = [int]$proc.ProcessId
    $cwdRaw = [ProcCwdReader]::GetCwd($procId)

    if (-not $cwdRaw) {
        Write-Log "  PID $procId ($($proc.Name)) - nao foi possivel ler o CWD (permissao ou processo 32-bit), ignorando."
        continue
    }

    $cwd = Normalize-Path $cwdRaw
    if (-not $cwdMap.ContainsKey($cwd)) {
        Write-Log "  [FORA DO PM2] PID $procId ($($proc.Name)) - cwd '$cwdRaw' - nao gerenciado pelo PM2, ignorando."
        $unmanaged++
        continue
    }

    $entry = $cwdMap[$cwd]
    if ($entry.SkipRound) {
        Write-Log "  PID $procId - app '$($entry.Names -join ',')' em transicao no PM2, pulando esta rodada."
        continue
    }

    if ($protectedPids.Contains($procId)) {
        Write-Log "  [OK] PID $procId ($($proc.Name)) - app '$($entry.Names -join ',')' - normal."
        continue
    }

    $ehOrfaoBloqueandoAppQuebrado = $entry.Broken -and $entry.ValidPids.Count -eq 0

    $started = $proc.CreationDate
    if (-not $ehOrfaoBloqueandoAppQuebrado -and $started -and ($now - $started).TotalSeconds -lt $GRACE_SECS) {
        Write-Log "  PID $procId - processo muito recente (<$GRACE_SECS s), aguardando proxima rodada."
        continue
    }
    if ($ehOrfaoBloqueandoAppQuebrado) {
        Write-Log "  PID $procId - app '$($entry.Names -join ',')' esta parado/quebrado no PM2 e sem PID valido - matando sem esperar carencia (provavel orfao segurando a porta)."
    }

    $startedStr = if ($started) { $started.ToString('dd/MM/yyyy HH:mm') } else { '?' }

    if ($WhatIf) {
        Write-Log "  [SIMULACAO] mataria PID $procId ($($proc.Name)) - app '$($entry.Names -join ',')' - cwd '$cwdRaw' - iniciado em $startedStr"
        $killed++
        continue
    }

    try {
        Stop-Process -Id $procId -Force -ErrorAction Stop
        Write-Log "  [MATOU] PID $procId ($($proc.Name)) - app '$($entry.Names -join ',')' - cwd '$cwdRaw' - iniciado em $startedStr"
        $killed++
    } catch {
        Write-Log "  [ERRO] Falha ao matar PID $procId : $_"
    }
}

Write-Log "Concluido. $killed processo(s) orfao(s) morto(s). $unmanaged processo(s) fora do PM2 (ignorados)."
