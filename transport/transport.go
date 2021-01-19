// Package transport provides different transport layers for software TPM
package transport

import (
	"net"
)

// GetFreePort returns currently unused port
func GetFreePort() (int, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return -1, err
	}
	defer func() {
		_ = listener.Close()
	}()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

// NewConnectionProcessingLoop processes a sequence of commands until an error is obtained
func NewConnectionProcessingLoop(processor func(c net.Conn) error) func(c net.Conn) {
	return func(c net.Conn) {
		for {
			err := processor(c)
			if err != nil {
				break
			}
		}
	}
}
