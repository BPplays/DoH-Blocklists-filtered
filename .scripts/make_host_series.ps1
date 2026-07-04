# .\.scripts\make_host_series.ps1 -Hosts 'doh-$.spectrum.com','dns-$.spectrum.com' -Start 1 -End 64 -Formats d1,d2,d3,alpha
param(
    [Parameter(Mandatory)]
    [string[]]$Hosts,
    [int]$Start = 1,
    [int]$End = 64,
    [string]$AlphaStart = 'a',
    [string]$AlphaEnd = 'az',
    [object[]]$Formats
)

function Convert-StringToIndex {
    param([string]$Name)
    $sum = 0
    $mult = 1
    for ($i = $Name.Length - 1; $i -ge 0; $i--) {
        $sum += (([int]$Name[$i] - [int][char]'a' + 1) * $mult)
        $mult *= 26
    }
    return $sum - 1
}

function Convert-IndexToString {
    param([int]$Idx)
    if ($Idx -lt 26) {
        return [char](97 + $Idx)
    }
    $idx = $Idx
    $result = ""
    while ($idx -gt 0) {
        $rem = (($idx - 1) % 26)
        $result = [char](97 + $rem) + $result
        $idx = [math]::Floor(($idx - 1) / 26)
    }
    return $result
}

function Get-AlphaRange {
    param([string]$Start, [string]$End)

    $startIdx = Convert-StringToIndex $Start
    $endIdx   = Convert-StringToIndex $End
    $count    = $endIdx - $startIdx + 1

    $result = @()
    for ($i = 0; $i -lt $count; $i++) {
        $result += (Convert-IndexToString ($startIdx + $i))
    }
    return $result
}

function Parse-Fmt {
    param([object]$Raw)

    if ($null -eq $Raw) {
        return @{ Type = 'Numeric'; Width = 0 }
    }

    $s = $Raw.ToString() -as [string]

    # 'alpha' marker
    if ($s -ieq 'alpha') {
        return @{ Type = 'Alpha' }
    }

    # 'D123' or 'd123' style -> D followed by digits = width
    if ($s -match '^[Dd](\d+)$') {
        $width = [int]$Matches[1]
        return @{ Type = 'Numeric'; Width = $width }
    }

    # Pure digits like '0','00','000' counted as width
    if ($s -match '^0+$') {
        $width = $s.Length
        return @{ Type = 'Numeric'; Width = $width }
    }

    # Fallback: try parsing as raw number (width)
    if ([int]::TryParse($s, [ref]$null)) {
        return @{ Type = 'Numeric'; Width = 0 }
    }

    return @{ Type = 'Unknown'; Value = $s }
}

$numbers = $Start..$End
$alpha   = Get-AlphaRange $AlphaStart $AlphaEnd

if (-not $Formats) {
    $Formats = @('D1','D2','D3','alpha')
}

$result = foreach ($hostTemplate in $Hosts) {

    foreach ($fmtRaw in $Formats) {

        $info = Parse-Fmt $fmtRaw

        if ($info.Type -eq 'Numeric') {
            $w = $info.Width
            foreach ($n in $numbers) {
                $padded = ('{0:D' + $w + '}') -f $n
                $hostTemplate.Replace('$', $padded)
            }
        } elseif ($info.Type -eq 'Alpha') {
            foreach ($a in $alpha) {
                $hostTemplate.Replace('$', $a)
            }
        } else {
            # Unknown format: output verbatim (e.g., for '-formats 0,00,000,alpha' where 0s become int 0)
            foreach ($n in $numbers) {
                $hostTemplate.Replace('$', $info.Value)
            }
        }
    }
}

$result | Select-Object -Unique
