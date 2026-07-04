# .\make_host_series.ps1 -Hosts 'doh-$.spectrum.com','dns-$.spectrum.com' -Start 1 -End 64 -Formats 0,00,000,alpha
param(
    [string[]]$Hosts,
    [int]$Start = 1,
    [int]$End = 64,
    [ValidateSet('0','00','000','alpha')]
    [string[]]$Formats = @('0','00','000','alpha')
)

function Get-AlphaRange {
    param([int]$Count)

    $result = @()

    for ($i = 0; $i -lt $Count; $i++) {
        $n = $i
        $s = ""

        do {
			$s = [char][int](97 + ($n % 26)) + $s
            $n = [math]::Floor($n / 26) - 1
        } while ($n -ge 0)

        $result += $s
    }

    return $result
}

$numbers = $Start..$End
$alpha   = Get-AlphaRange ($End - $Start + 1)

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
