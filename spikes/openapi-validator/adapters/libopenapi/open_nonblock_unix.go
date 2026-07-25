//go:build unix

package main

import (
	"os"
	"syscall"
)

func openRootFileForRead(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
