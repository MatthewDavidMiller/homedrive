# What the sync client costs on Windows and NTFS, as a real process. Run by
# scripts/bench-windows.sh, which serves the store from WSL.
#
# It works in a folder of its own, with its own settings, so it touches
# neither a real installation nor starting at sign-in.

param(
    [Parameter(Mandatory)] [string] $Exe,
    [Parameter(Mandatory)] [string] $Server,
    [int] $Files = 20000,
    [int] $Idle = 320
)

$ErrorActionPreference = 'Stop'
$root = Join-Path $env:TEMP "homedrive-bench-$PID"
$local = Join-Path $root 'local'
New-Item -ItemType Directory -Force -Path $local | Out-Null
$program = Join-Path $root 'homedrive.exe'
Copy-Item $Exe $program
$env:APPDATA = Join-Path $root 'config'
$env:LOCALAPPDATA = Join-Path $root 'state'
$env:HOMEDRIVE_PASSWORD = 'a bench password'
$env:HOMEDRIVE_NO_BROWSER = '1'
$env:HOMEDRIVE_AUTOSTART_NAME = 'homedrive-bench'
New-Item -ItemType Directory -Force -Path $env:APPDATA, $env:LOCALAPPDATA | Out-Null

function Report([string] $Name, [double] $Cpu) {
    $script:daemon.Refresh()
    '{0,-30} {1,8:N2} s CPU {2,8:N1} MB now {3,8:N1} MB peak {4,8:N1} MB private' -f $Name, $Cpu,
        ($script:daemon.WorkingSet64 / 1MB), ($script:daemon.PeakWorkingSet64 / 1MB),
        ($script:daemon.PrivateMemorySize64 / 1MB)
}

function Cpu { $script:daemon.Refresh(); $script:daemon.TotalProcessorTime.TotalSeconds }

# Waits until the daemon has used no CPU for this many seconds.
function Settle([int] $Quiet) {
    $still = 0
    $last = Cpu
    while ($still -lt $Quiet) {
        Start-Sleep -Seconds 1
        $now = Cpu
        if ($now -eq $last) { $still++ } else { $still = 0 }
        $last = $now
    }
}

function Start-Daemon {
    $script:daemon = Start-Process -FilePath $program -ArgumentList 'daemon', '--no-gui' -PassThru
}

try {
    & $program login --server $Server --user bench --device "bench-$PID" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'login failed' }
    & $program add-folder $local --remote "run-$PID" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'add-folder failed' }

    for ($i = 0; $i -lt $Files; $i++) {
        $dir = Join-Path $local ('small\{0}\{1}' -f ($i % 50), ($i % 7))
        if ($i -lt 350) { [IO.Directory]::CreateDirectory($dir) | Out-Null }
        [IO.File]::WriteAllText((Join-Path $dir "$i.txt"), "file $i`n")
    }
    Get-Item $Exe | ForEach-Object { '{0}, {1:N1} MB, {2} files' -f $_.Name, ($_.Length / 1MB), $Files }

    Start-Daemon
    $started = Get-Date
    Settle 20
    $took = [int]((Get-Date) - $started).TotalSeconds - 20
    Report "first sync, $took s" (Cpu)
    Stop-Process -Id $daemon.Id -Force
    $daemon.WaitForExit()

    Start-Daemon
    Settle 5
    Report 'restarted, and scanned once' (Cpu)

    $before = Cpu
    Start-Sleep -Seconds $Idle
    Report "idle for $Idle s" ((Cpu) - $before)

    $before = Cpu
    [IO.File]::WriteAllText((Join-Path $local 'small\0\0\0.txt'), "edited`n")
    Start-Sleep -Seconds 3
    Settle 5
    Report 'one file edited' ((Cpu) - $before)

    $before = Cpu
    [IO.File]::WriteAllText((Join-Path $local 'small\0\0\brand new.txt'), "new`n")
    Start-Sleep -Seconds 3
    Settle 5
    Report 'one file added' ((Cpu) - $before)
} finally {
    if ($daemon) { Stop-Process -Id $daemon.Id -Force -ErrorAction SilentlyContinue; $daemon.WaitForExit() }
    Remove-Item -Recurse -Force -Path $root -ErrorAction SilentlyContinue
}
