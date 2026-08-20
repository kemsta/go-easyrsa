//go:build aix || android || darwin || dragonfly || freebsd || illumos || ios || linux || netbsd || openbsd || solaris

package legacy

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func openLegacyRenewalEntryFile(directory *os.File, _ *os.Root, _, name string) (*os.File, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("storage/legacy: open renewed certificate %q: %w", name, err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("storage/legacy: wrap renewed certificate %q", name)
	}
	return file, nil
}
