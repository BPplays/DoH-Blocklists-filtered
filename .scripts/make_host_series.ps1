# .\make_host_series.ps1 -Hosts 'doh-$.spectrum.com','dns-$.spectrum.com' -Start 1 -End 64 -Widths 1,2,3 -Formats alpha
param(
    [Parameter(Mandatory)]
    [string[]]$Hosts,
    [int]$Start = 1,
    [int]$End = 64,
    [ValidatePattern('^[a-z]+$')]
    [string]$AlphaStart = 'a',
    [ValidatePattern('^[a-z]+$')]
    [string]$AlphaEnd = 'zz',
    [object[]]$Formats,
    [int[]]$Widths
)

function Convert-AStringToIndex {
    param([string]$Name)
    $sum = 0
    $mult = 1
    for ($i = $Name.Length - 1; $i -ge 0; $i--) {
        $sum += (([int]$Name[$i] - [int]'a' + 1) * $mult)
        $mult *= 26
    }
    return $sum - 1
}

function Convert-IndexToAString {
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
    $startIdx = Convert-AStringToIndex $Start
    $endIdx   = Convert-AStringToIndex $End
    $count    = $endIdx - $startIdx + 1
    if ($count -le 0) { return @() }
    $result = @()
    for ($i = 0; $i -lt $count; $i++) {
        $result += (Convert-IndexToAString ($startIdx + $i))
    }
    return $result
}

$numbers = $Start..$End
$alpha   = Get-AlphaRange -Start $AlphaStart -End $AlphaEnd

$result = @()

# Widths parameter: integer counts of zero-padding per host
if ($Widths) {
    foreach ($hostTemplate in $Hosts) {
        foreach ($w in $Widths) {
            foreach ($n in $numbers) {
                $result += ('{0:D' + $w + '}') -f $n | ForEach-Object { $hostTemplate.Replace('$', $_) }
            }
        }
    }
}

# Formats parameter: 'D<width>' or 'alpha'
if ($Formats) {
    foreach ($fmt in $Formats) {
        if ($null -eq $fmt) { continue }
        $s = $fmt.ToString()
        
        if ($s -ieq 'alpha') {
            foreach ($hostTemplate in $Hosts) {
                foreach ($a in $alpha) {
                    $result += $hostTemplate.Replace('$', $a)
                }
            }
        } elseif ($s -match '^D(\d+)$') {
            $d = [int]$Matches[1]
            foreach ($hostTemplate in $Hosts) {
                foreach ($n in $numbers) {
                    $result += ('{0:D' + $d + '}') -f $n | ForEach-Object { $hostTemplate.Replace('$', $_) }
                }
            }
        } else {
            $result += "$fmt (unrecognized format)"
        }
    }
}

# Default: widths 1,2,3 and alpha
if (-not $Widths -and -not $Formats) {
    foreach ($hostTemplate in $Hosts) {
        for ($w = 1; $w -le 3; $w++) {
            foreach ($n in $numbers) {
                $result += ('{0:D' + $w + '}') -f $n | ForEach-Object { $hostTemplate.Replace('$', $_) }
            }
        }
        foreach ($a in $alpha) {
            $result += $hostTemplate.Replace('$', $a)
        }
    }
}

$result | Where-Object { $_ -notlike '*unrecognized*' } | Select-Object -Unique
