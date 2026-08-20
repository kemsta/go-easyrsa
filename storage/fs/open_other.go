//go:build !(aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris)

package fs

import "os"

func openRegularFile(path string) (*os.File, error) {
	return os.Open(path)
}
