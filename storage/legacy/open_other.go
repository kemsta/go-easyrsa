//go:build !(aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris)

package legacy

import "os"

func openLegacyRegular(root *os.Root, name string) (*os.File, error) {
	return root.Open(name)
}
