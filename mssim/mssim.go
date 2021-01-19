// Package mssim contains functionality for processing MSSIM transport protocol
package mssim

import (
	"bytes"
	"encoding/binary"
	"io"
)

type Command uint32

const (
	TpmSignalPowerOn  Command = 1
	TpmSignalPowerOff Command = 2
	TpmSendCommand    Command = 8
	TpmSignalNVOn     Command = 11
	TpmSessionEnd     Command = 20
)

// Command represents a single MSSIM command
type Request struct {
	Command         Command
	Locality        uint8
	InternalCommand []byte
}

// ParseRequest reads and unmarshalls MSSIM command
func ParseRequest(r io.Reader) (*Request, error) {
	var command Command
	var locality uint8
	var commandSize uint32

	if err := binary.Read(r, binary.BigEndian, &command); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &locality); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.BigEndian, &commandSize); err != nil {
		return nil, err
	}

	internalCommand := make([]byte, commandSize)
	if _, err := io.ReadFull(r, internalCommand); err != nil {
		return nil, err
	}

	return &Request{
		Command:         command,
		Locality:        locality,
		InternalCommand: internalCommand,
	}, nil
}

// CreateResponse creates a MSSIM response frame for specified result code and response body
func CreateResponse(resultCode uint32, internalCommand []byte) ([]byte, error) {
	// Response frame:
	// - uint32 (size of response)
	// - []byte (response)
	// - uint32 (code)
	var buf bytes.Buffer

	if err := binary.Write(&buf, binary.BigEndian, uint32(len(internalCommand))); err != nil {
		return nil, err
	}

	if _, err := buf.Write(internalCommand); err != nil {
		return nil, err
	}

	if err := binary.Write(&buf, binary.BigEndian, resultCode); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
