//go:build !(aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris)

package pki

import "os"

func openPKIInput(name string) (*os.File, error) {
	return os.Open(name)
}
