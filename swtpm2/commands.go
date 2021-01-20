// Package swtpm2 provides a simple golang processor of TPM2 commands
package swtpm2

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var RCFail = tpmutil.RCSuccess + 1

// Commands represents an interface to all supported TPM2 commands
type Commands interface {
	ReadPublic(handle tpmutil.Handle) (*ReadPublicResponse, error)
	ReadPublicNV(index tpmutil.Handle) (*tpm2.NVPublic, error)
	// GetCapability division
	GetCapabilityPCRs(count, property uint32) ([]tpm2.PCRSelection, error)

	StartAuthSession(tpmKey, bindKey tpmutil.Handle, nonceCaller, secret []byte, se tpm2.SessionType, sym, hashAlg tpm2.Algorithm) (tpmutil.Handle, []byte, error)
}

// NewLoopProcessCommand processes a sequence of commands until an error is obtained
func NewLoopProcessCommand(commands Commands) func(rw io.ReadWriter) {
	return func(rw io.ReadWriter) {
		for {
			b, err := ProcessCommand(rw, commands)
			if err != nil {
				break
			}
			if _, err = rw.Write(b); err != nil {
				break
			}
		}
	}
}

// ProcessCommand tries to decode command and invoke an appropriate method of `Commands` interface
// Returns an error if further commands processing is impossible
func ProcessCommand(r io.Reader, commands Commands) ([]byte, error) {
	ch, commandBuffer, err := ParseCommandHeader(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read input command, err: %v", err)
	}

	b, err := executeCommand(ch, commandBuffer, commands)
	if err != nil {
		return PackWithResponseHeader(tpm2.TagNoSessions, RCFail, nil)
	}
	return PackWithResponseHeader(tpm2.TagNoSessions, tpmutil.RCSuccess, b)
}

// ParseCommandHeader tries to obtain a command from the input byte stream
func ParseCommandHeader(r io.Reader) (CommandHeader, []byte, error) {
	var ch CommandHeader
	headerSize := uint32(binary.Size(ch))

	headerBuffer := make([]byte, headerSize)
	_, err := io.ReadFull(r, headerBuffer)
	if err != nil {
		return ch, nil, fmt.Errorf("failed to read expected number of bytes for command header, err: %v", err)
	}

	_, err = tpmutil.Unpack(headerBuffer, &ch)
	if err != nil {
		return ch, nil, fmt.Errorf("failed to unpack bytes for command header, err: %v", err)
	}

	if headerSize > ch.Size {
		return ch, nil, fmt.Errorf("incorrect CommonHeader: header.size < sizeof(header): %d < %d", ch.Size, headerSize)
	}

	var commandBuffer []byte
	if ch.Size > headerSize {
		remainBytes := ch.Size - headerSize
		commandBuffer = make([]byte, remainBytes)
		_, err = io.ReadFull(r, commandBuffer)
		if err != nil {
			return ch, nil, fmt.Errorf("failed to read expected number of bytes for the command, err: %v", err)
		}
	}
	return ch, commandBuffer, err
}

func executeCommand(ch CommandHeader, b []byte, commands Commands) ([]byte, error) {
	switch ch.Cmd {
	case tpm2.CmdReadPublic:
		var handle tpmutil.Handle
		_, err := tpmutil.Unpack(b, &handle)
		if err != nil {
			return nil, err
		}
		resp, err := commands.ReadPublic(handle)
		if err != nil {
			return nil, err
		}
		return resp.Encode()
	case tpm2.CmdReadPublicNV:
		var index tpmutil.Handle
		_, err := tpmutil.Unpack(b, &index)
		if err != nil {
			return nil, err
		}
		resp, err := commands.ReadPublicNV(index)
		if err != nil {
			return nil, err
		}
		raw, err := tpmutil.Pack(*resp)
		if err != nil {
			return nil, err
		}
		return tpmutil.Pack(tpmutil.U16Bytes(raw))
	case tpm2.CmdGetCapability:
		var capa tpm2.Capability
		var count uint32
		var property uint32

		_, err := tpmutil.Unpack(b, &capa, &property, &count)
		if err != nil {
			return nil, err
		}

		switch capa {
		case tpm2.CapabilityPCRs:
			pcrs, err := commands.GetCapabilityPCRs(count, property)
			if err != nil {
				return nil, err
			}
			pcrSelection, err := EncodePCRSelection(pcrs...)
			if err != nil {
				return nil, err
			}

			header, err := tpmutil.Pack(false, tpm2.CapabilityPCRs)
			if err != nil {
				return nil, err
			}

			result := header
			result = append(result, pcrSelection...)
			return result, nil
		default:
			return nil, fmt.Errorf("capability %d is not supported", capa)
		}

	case tpm2.CmdStartAuthSession:
		var tpmKey tpmutil.Handle
		var bindKey tpmutil.Handle

		read, err := tpmutil.Unpack(b, &tpmKey, &bindKey)
		if err != nil {
			return nil, err
		}

		var nonceCaller tpmutil.U16Bytes
		var secret tpmutil.U16Bytes
		var se tpm2.SessionType
		var sym tpm2.Algorithm
		var hashAlg tpm2.Algorithm
		if _, err = tpmutil.Unpack(b[read:], &nonceCaller, &secret, &se, &sym, &hashAlg); err != nil {
			return nil, err
		}

		handle, nonce, err := commands.StartAuthSession(tpmKey, bindKey, nonceCaller, secret, se, sym, hashAlg)
		if err != nil {
			return nil, err
		}

		return tpmutil.Pack(handle, tpmutil.U16Bytes(nonce))
	}
	return nil, fmt.Errorf("command %d is not supported", ch.Cmd)
}
