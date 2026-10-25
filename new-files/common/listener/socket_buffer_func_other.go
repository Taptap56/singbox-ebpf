//go:build !(unix || windows)

package listener

func setSocketBuffer(fd uintptr, size int) {
}
