# .\make_host_series.ps1 -Hosts 'doh-$.spectrum.com','dns-$.spectrum.com' -Start 1 -End 64 -Formats 0,00,000,alpha
param(
    [string[]]$Hosts,
    [int]$Start = 1,
    [int]$End = 64,
    [string]$AlphaStart = 'a',
    [string]$AlphaEnd = 'az',
    [ValidateSet('0','00','000','alpha')]
    [string[]]$Formats = @('0','00','000','alpha')
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
    $idx += 1
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

$numbers = $Start..$End
$alpha   = Get-AlphaRange $AlphaStart $AlphaEnd

$result = foreach ($hostTemplate in $Hosts) {

    foreach ($fmt in $Formats) {

        switch ($fmt) {

            '0' {
                foreach ($n in $numbers) {
                    $hostTemplate.Replace('$', $n)
                }
            }

            '00' {
                foreach ($n in $numbers) {
                    $hostTemplate.Replace('$', ('{0:00}' -f $n))
                }
            }

            '000' {
                foreach ($n in $numbers) {
                    $hostTemplate.Replace('$', ('{0:000}' -f $n))
                }
            }

            'alpha' {
                foreach ($a in $alpha) {
                    $hostTemplate.Replace('$', $a)
                }
            }
        }
    }
}

$result | Select-Object -Unique
