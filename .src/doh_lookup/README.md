
```nu
GOOS=linux GOARCH=amd64 go build -buildvcs=false -o ../../.scripts/doh_lookup
```

```nu
GOOS=linux GOARCH=amd64 go build -buildvcs=false -race -o ../../.scripts/doh_lookup

```


```nu
cd ./.src/doh_lookup; GOOS=windows GOARCH=amd64 go build -buildvcs=false -o ../../.scripts/doh_lookup.exe; cd ../..; ./.scripts/doh_lookup.exe -c ./.src/_main.yml -d
```
