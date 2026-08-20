//go:build !(aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris)

package fs

import "os"

func openRootRegular(root *os.Root, name string) (*os.File, error) {
	return root.Open(name)
}
