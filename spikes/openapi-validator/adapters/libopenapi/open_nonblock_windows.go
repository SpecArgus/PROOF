//go:build windows

package main

import "os"

func openRootFileForRead(root *os.Root, name string) (*os.File, error) {
	return root.Open(name)
}
