//go:build !(aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris)

package main

import "os"

func openLifecycleSource(root *os.Root, name string) (*os.File, error) {
	return root.Open(name)
}
