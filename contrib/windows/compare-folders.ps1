<#
.SYNOPSIS
Proves every file in one folder arrived in another, byte for byte.

.DESCRIPTION
Read-only: it changes nothing in either folder, and only writes its report.

Every file in -Source must exist in -Destination with the same SHA-256. Files
only in -Destination are listed, but are not a failure: a copy may gain files.

Anything that could not be checked counts as a failure, because a file nobody
could read has not been shown to be safe. Everything skipped is listed in the
report, so nothing is left out silently.

Exit code: 0 all files match, 1 a file is missing or differs or could not be
checked, 2 the comparison could not run.

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File compare-folders.ps1 -Source D:\Old -Destination D:\New
#>
param(
    [Parameter(Mandatory = $true)][string]$Source,
    [Parameter(Mandatory = $true)][string]$Destination,
    # Tab-separated report of everything that is not a plain match; by default
    # on this user's Desktop.
    [string]$Report = (Join-Path ([Environment]::GetFolderPath('Desktop')) 'folder-compare-report.tsv'),
    # File names left out: what sync clients and Windows keep for themselves,
    # not user data.
    [string[]]$SkipFiles = @('.homedrive-root', '.sync_*.db*', '.*sync.log',
        '.sync-exclude.lst', 'desktop.ini', 'Thumbs.db', '~$*'),
    # Folder names left out, with everything inside them.
    [string[]]$SkipFolders = @('.homedrive')
)

$ErrorActionPreference = 'Stop'

# The \\?\ form reaches paths past 260 characters, and names Win32 rewrites.
function Get-LongPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ($full.StartsWith('\\?\')) { return $full }
    if ($full.StartsWith('\\')) { return '\\?\UNC\' + $full.Substring(2) }
    return '\\?\' + $full
}

function Test-Skipped([string]$Name, [string[]]$Patterns) {
    foreach ($p in $Patterns) {
        if ($Name -like $p) { return $true }
    }
    return $false
}

# Lists files under $Root as relative path => FileInfo. What cannot be listed,
# and links, which are not followed, are added to $Problems.
function Get-Tree([string]$Root, [System.Collections.ArrayList]$Problems,
    [System.Collections.ArrayList]$Skipped, [string]$Side) {
    $files = New-Object 'System.Collections.Generic.Dictionary[string,System.IO.FileInfo]' `
        ([StringComparer]::OrdinalIgnoreCase)
    $pending = New-Object System.Collections.Stack
    $pending.Push($Root)
    while ($pending.Count -gt 0) {
        $dir = $pending.Pop()
        $rel = $dir.Substring($Root.Length).TrimStart('\')
        try {
            $entries = (New-Object IO.DirectoryInfo $dir).GetFileSystemInfos()
        } catch {
            [void]$Problems.Add([pscustomobject]@{
                    Status = 'UNREADABLE-FOLDER'; Path = $rel; Detail = "$Side`: $($_.Exception.Message)"
                })
            continue
        }
        foreach ($e in $entries) {
            $path = if ($rel) { "$rel\$($e.Name)" } else { $e.Name }
            $isDir = ($e.Attributes -band [IO.FileAttributes]::Directory) -ne 0
            if (($e.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                # A cloud placeholder is a reparse point too; either way its
                # content was not checked here.
                [void]$Problems.Add([pscustomobject]@{
                        Status = 'LINK-NOT-FOLLOWED'; Path = $path; Detail = "$Side`: not compared"
                    })
                continue
            }
            if ($isDir) {
                if (Test-Skipped $e.Name $SkipFolders) {
                    [void]$Skipped.Add([pscustomobject]@{
                            Status = 'SKIPPED-FOLDER'; Path = $path; Detail = $Side
                        })
                } else {
                    $pending.Push($e.FullName)
                }
            } elseif (Test-Skipped $e.Name $SkipFiles) {
                [void]$Skipped.Add([pscustomobject]@{
                        Status = 'SKIPPED-FILE'; Path = $path; Detail = $Side
                    })
            } else {
                $files[$path] = [IO.FileInfo]$e
            }
        }
    }
    return , $files
}

function Get-Sha256([string]$Path) {
    $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    $stream = New-Object IO.FileStream $Path, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), $share, 1048576
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($sha.ComputeHash($stream))
    } finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

try {
    foreach ($folder in @($Source, $Destination)) {
        if (-not [IO.Directory]::Exists($folder)) { throw "No such folder: $folder" }
    }
    $sourceRoot = Get-LongPath $Source
    $destRoot = Get-LongPath $Destination
    if ($sourceRoot -ieq $destRoot) { throw 'The two folders are the same folder.' }

    $problems = New-Object System.Collections.ArrayList
    $skipped = New-Object System.Collections.ArrayList
    Write-Host 'Listing files...'
    $sourceFiles = Get-Tree $sourceRoot $problems $skipped 'source'
    $destFiles = Get-Tree $destRoot $problems $skipped 'destination'
    $totalBytes = [long]0
    foreach ($f in $sourceFiles.Values) { $totalBytes += $f.Length }
    Write-Host ("Source: {0} files, {1:N1} GB. Destination: {2} files." -f
        $sourceFiles.Count, ($totalBytes / 1GB), $destFiles.Count)

    $matched = 0
    $doneBytes = [long]0
    $count = 0
    $started = Get-Date
    foreach ($item in $sourceFiles.GetEnumerator()) {
        $count++
        $doneBytes += $item.Value.Length
        if (($count % 25) -eq 0 -or $count -eq $sourceFiles.Count) {
            $percent = if ($totalBytes -gt 0) { [int](100 * $doneBytes / $totalBytes) } else { 100 }
            Write-Progress -Activity 'Comparing' -Status "$count of $($sourceFiles.Count) files" -PercentComplete $percent
        }
        $rel = $item.Key
        $from = $item.Value
        $to = $null
        if (-not $destFiles.TryGetValue($rel, [ref]$to)) {
            [void]$problems.Add([pscustomobject]@{
                    Status = 'MISSING'; Path = $rel; Detail = "$($from.Length) bytes, not in the destination"
                })
            continue
        }
        if ($from.Length -ne $to.Length) {
            [void]$problems.Add([pscustomobject]@{
                    Status = 'DIFFERENT'; Path = $rel
                    Detail = "size $($from.Length) vs $($to.Length); source written $($from.LastWriteTime.ToString('s')), destination $($to.LastWriteTime.ToString('s'))"
                })
            continue
        }
        try {
            $same = (Get-Sha256 $from.FullName) -eq (Get-Sha256 $to.FullName)
        } catch {
            [void]$problems.Add([pscustomobject]@{
                    Status = 'UNREADABLE'; Path = $rel; Detail = $_.Exception.Message
                })
            continue
        }
        if ($same) {
            $matched++
        } else {
            [void]$problems.Add([pscustomobject]@{
                    Status = 'DIFFERENT'; Path = $rel
                    Detail = "same size, different content; source written $($from.LastWriteTime.ToString('s')), destination $($to.LastWriteTime.ToString('s'))"
                })
        }
    }
    Write-Progress -Activity 'Comparing' -Completed

    $extra = New-Object System.Collections.ArrayList
    foreach ($rel in $destFiles.Keys) {
        if (-not $sourceFiles.ContainsKey($rel)) {
            [void]$extra.Add([pscustomobject]@{
                    Status = 'ONLY-IN-DESTINATION'; Path = $rel; Detail = "$($destFiles[$rel].Length) bytes"
                })
        }
    }

    @($problems) + @($extra) + @($skipped) | Sort-Object Status, Path |
        Export-Csv -LiteralPath $Report -Delimiter "`t" -NoTypeInformation -Encoding UTF8

    $byStatus = @($problems) | Group-Object Status
    Write-Host ''
    Write-Host ("Matched by SHA-256: {0} of {1} files, in {2:N0} seconds" -f
        $matched, $sourceFiles.Count, ((Get-Date) - $started).TotalSeconds)
    foreach ($g in $byStatus) { Write-Host ("{0}: {1}" -f $g.Name, $g.Count) }
    Write-Host ("Only in the destination (not a failure): {0}" -f $extra.Count)
    Write-Host ("Skipped by name: {0}" -f $skipped.Count)
    Write-Host "Report: $Report"
    Write-Host ''
    if ($problems.Count -eq 0 -and $matched -eq $sourceFiles.Count) {
        Write-Host "PASS: every file in the source is in the destination, byte for byte." -ForegroundColor Green
        exit 0
    }
    Write-Host "FAIL: $($problems.Count) item(s) need a look. See the report." -ForegroundColor Red
    exit 1
} catch {
    Write-Host "Could not compare: $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}
