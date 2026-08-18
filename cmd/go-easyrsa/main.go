package main

import (
	"errors"
	"fmt"
	"os"
)

var errSilentExit = errors.New("go-easyrsa: silent exit")

func main() {
	if err := newRootCmd().Execute(); err != nil {
		if !errors.Is(err, errSilentExit) {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}
