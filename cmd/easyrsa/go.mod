module github.com/kemsta/go-easyrsa/cmd/easyrsa

go 1.21

toolchain go1.21.0

replace github.com/kemsta/go-easyrsa => ../../

require (
	github.com/kemsta/go-easyrsa v1.0.1
	github.com/spf13/cobra v1.4.0
)

require (
	github.com/gofrs/flock v0.8.1 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/sys v0.12.0 // indirect
)
