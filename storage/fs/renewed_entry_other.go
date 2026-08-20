//go:build !(aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris)

package fs

import "os"

func openRenewalEntryFile(_ *os.File, root *os.Root, relativePath, _ string) (*os.File, error) {
	return openRootRegular(root, relativePath)
}
