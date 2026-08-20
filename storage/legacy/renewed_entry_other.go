//go:build !(aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris)

package legacy

import "os"

func openLegacyRenewalEntryFile(_ *os.File, root *os.Root, relativePath, _ string) (*os.File, error) {
	return openLegacyRegular(root, relativePath)
}
