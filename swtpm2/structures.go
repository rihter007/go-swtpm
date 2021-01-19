package swtpm2

import (
	"encoding/binary"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// CommandHeader represents the header of a command
type CommandHeader struct {
	Tag  tpmutil.Tag
	Size uint32
	Cmd  tpmutil.Command
}

// ResponseHeader represents the header of a response
type ResponseHeader struct {
	Tag  tpmutil.Tag
	Size uint32
	Res  tpmutil.ResponseCode
}

// PackWithResponseHeader wraps response header and values into a single byte array
func PackWithResponseHeader(tag tpmutil.Tag, res tpmutil.ResponseCode, body []byte) ([]byte, error) {
	rh := ResponseHeader{
		Tag: tag,
		Res: res,
	}
	hdrSize := binary.Size(rh)
	bodySize := len(body)
	rh.Size = uint32(hdrSize + bodySize)
	header, err := tpmutil.Pack(rh)
	if err != nil {
		return nil, fmt.Errorf("couldn't pack message header: %v", err)
	}
	if len(body) == 0 {
		return header, nil
	}
	return append(header, body...), nil
}

// ReadPublicResponse is a processing result if ReadPublic command
type ReadPublicResponse struct {
	Public        tpm2.Public
	Name          []byte
	QualifiedName []byte
}

// Encode converts ReadPublicResponse to a byte array
func (rpr *ReadPublicResponse) Encode() ([]byte, error) {
	var resp struct {
		Public        tpmutil.U16Bytes
		Name          tpmutil.U16Bytes
		QualifiedName tpmutil.U16Bytes
	}

	var err error
	resp.Public, err = rpr.Public.Encode()
	if err != nil {
		return nil, err
	}
	resp.Name = tpmutil.U16Bytes(rpr.Name)
	resp.QualifiedName = tpmutil.U16Bytes(rpr.QualifiedName)
	return tpmutil.Pack(resp)
}
