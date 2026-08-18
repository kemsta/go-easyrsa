//go:build !(aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris)

package main

import "os"

func openReadOnlyPath(name string) (*os.File, error) {
	return os.Open(name)
}
