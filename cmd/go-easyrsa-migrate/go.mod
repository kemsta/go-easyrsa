module github.com/kemsta/go-easyrsa/cmd/go-easyrsa-migrate

go 1.25.0

require (
	github.com/kemsta/go-easyrsa v1.0.2
	github.com/spf13/cobra v1.10.2
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	go.mozilla.org/pkcs7 v0.9.0 // indirect
	golang.org/x/crypto v0.49.0 // indirect
	software.sslmate.com/src/go-pkcs12 v0.7.0 // indirect
)

replace github.com/kemsta/go-easyrsa => ../..
