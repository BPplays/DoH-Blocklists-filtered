mkdir ./cdncheck

let url = http get https://api.github.com/repos/projectdiscovery/cdncheck/releases/latest |
	get assets |
	where name =~ '(?i)lidnux' and name =~ '(amd64|x64|x86_64)' |
	get browser_download_url


if ( ($url | length) == 0) {
	echo "no matching asset found"

	let url_backup = http get https://api.github.com/repos/projectdiscovery/cdncheck/releases |
		where name =~ '(v1.2.3|v1.2.2)' |
		get url |
		first
	echo $url_backup

	let url = http get $url_backup |
		get assets |
		where name =~ '(?i)linux' and name =~ '(amd64|x64|x86_64)' |
		get browser_download_url
	echo $url
}


if ( ($url | length) == 0) {
	echo "using backup binary cdncheck"
	cp ./.src/cdncheck_backup ./cdncheck/cdncheck
	exit 0
}


let url = $url | first

echo $url
exit 0




http get $url | save -f cdncheck.zip
unzip cdncheck.zip -d ./cdncheck
