package mssim

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/rihter007/logruswrap"
)

var successCode uint32

// DummyPlatformProcessor reads platform command and responds with success status code
func DummyPlatformProcessor(c net.Conn, l logruswrap.PrintfLogger) error {
	var command Command
	if err := binary.Read(c, binary.BigEndian, &command); err != nil {
		return fmt.Errorf("failed to read command, err: %v", err)
	}

	log := logruswrap.WrapPrintfLogger(l)
	log.Infof("obtained command: %d", command)

	if err := binary.Write(c, binary.BigEndian, successCode); err != nil {
		return fmt.Errorf("failed to write response code, err: %v", err)
	}
	return nil
}
