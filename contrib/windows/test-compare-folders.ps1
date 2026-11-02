# Proves compare-folders.ps1 notices damage, against folders damaged on
# purpose. Run by scripts/test-windows.sh. It works only in the temporary
# folder. Exits 1 if any case is wrong.

$here = $PSScriptRoot
$compare = Join-Path $here 'compare-folders.ps1'
$root = Join-Path $env:TEMP "hd-compare-test-$PID"
$a = "$root\a"
$b = "$root\b"
$report = "$root\report.tsv"
$long = 'd' * 70
$longDir = "$long\$long\$long\$long"
$script:wrong = 0

function Remove-Tree([string]$Path) {
    if ([IO.Directory]::Exists($Path)) { [IO.Directory]::Delete("\\?\$Path", $true) }
}

function Reset-Folders {
    Remove-Tree $a
    Remove-Tree $b
    [void][IO.Directory]::CreateDirectory("$a\sub\deep")
    [IO.File]::WriteAllText("$a\one.txt", 'one')
    [IO.File]::WriteAllText("$a\sub\two.txt", 'two')
    [IO.File]::WriteAllBytes("$a\sub\deep\bin.dat", [byte[]](1..200))
    [IO.File]::WriteAllBytes("$a\empty.bin", [byte[]]@())
    $unicode = -join [char[]](0x65E5, 0x672C, 0x8A9E)
    [IO.File]::WriteAllText("$a\sub\$unicode.txt", 'unicode')
    [void][IO.Directory]::CreateDirectory("\\?\$a\$longDir")
    [IO.File]::WriteAllText("\\?\$a\$longDir\long.txt", 'long')
    # Other sync clients' files, which are left out.
    [IO.File]::WriteAllText("$a\.sync_abc.db", 'state')
    [IO.File]::WriteAllText("$a\Thumbs.db", 'thumbs')
    $null = & robocopy.exe $a $b /E /COPY:DAT /DCOPY:T /XF .sync_*.db* Thumbs.db /R:1 /W:1 /NFL /NDL /NJH /NJS
}

function Test-Case([string]$Label, [int]$Want, [string]$Status = '') {
    $null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $compare `
        -Source $a -Destination $b -Report $report
    $got = $LASTEXITCODE
    $found = $Status -eq '' -or
        @(Import-Csv -LiteralPath $report -Delimiter "`t" | Where-Object Status -EQ $Status).Count -gt 0
    if ($got -eq $Want -and $found) {
        Write-Host "ok: $Label"
    } else {
        Write-Host "WRONG: $Label (exit $got, wanted $Want, status '$Status' found: $found)"
        $script:wrong++
    }
}

try {
    Reset-Folders
    Test-Case 'an exact copy, with long and non-English names' 0

    Reset-Folders
    [IO.File]::Delete("$b\sub\two.txt")
    Test-Case 'a missing file' 1 'MISSING'

    Reset-Folders
    [IO.File]::Delete("\\?\$b\$longDir\long.txt")
    Test-Case 'a missing file past 260 characters' 1 'MISSING'

    Reset-Folders
    [IO.File]::Delete("$b\empty.bin")
    Test-Case 'a missing empty file' 1 'MISSING'

    Reset-Folders
    $file = "$b\sub\deep\bin.dat"
    $written = [IO.File]::GetLastWriteTimeUtc($file)
    $bytes = [IO.File]::ReadAllBytes($file)
    $bytes[100] = $bytes[100] -bxor 1
    [IO.File]::WriteAllBytes($file, $bytes)
    [IO.File]::SetLastWriteTimeUtc($file, $written)
    Test-Case 'one flipped bit, same size and date' 1 'DIFFERENT'

    Reset-Folders
    [IO.File]::WriteAllText("$b\one.txt", 'longer now')
    Test-Case 'a different size' 1 'DIFFERENT'

    Reset-Folders
    [IO.File]::WriteAllText("$b\extra.txt", 'extra')
    Test-Case 'a file only in the destination is no failure' 0 'ONLY-IN-DESTINATION'

    Reset-Folders
    $held = [IO.File]::Open("$b\one.txt", 'Open', 'Read', 'None')
    Test-Case 'a file that cannot be read' 1 'UNREADABLE'
    $held.Dispose()

    Reset-Folders
    [void](New-Item -ItemType Junction -Path "$a\link" -Target "$a\sub")
    Test-Case 'a junction, which is reported, not followed' 1 'LINK-NOT-FOLLOWED'
    [IO.Directory]::Delete("$a\link")

    Reset-Folders
    Test-Case 'skipped names are listed' 0 'SKIPPED-FILE'

    Reset-Folders
    $before = [IO.File]::GetLastWriteTimeUtc("$a\one.txt")
    $count = [IO.Directory]::GetFiles("\\?\$a", '*', 'AllDirectories').Count
    Test-Case 'a clean run' 0
    if ($before -ne [IO.File]::GetLastWriteTimeUtc("$a\one.txt") -or
        $count -ne [IO.Directory]::GetFiles("\\?\$a", '*', 'AllDirectories').Count) {
        Write-Host 'WRONG: the source changed'
        $script:wrong++
    } else {
        Write-Host 'ok: the source is left unchanged'
    }

    $null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $compare `
        -Source "$root\nope" -Destination $b -Report $report
    if ($LASTEXITCODE -eq 2) {
        Write-Host 'ok: a folder that does not exist'
    } else {
        Write-Host "WRONG: a folder that does not exist (exit $LASTEXITCODE)"
        $script:wrong++
    }
} finally {
    Remove-Tree $root
}
exit [int]($script:wrong -gt 0)
