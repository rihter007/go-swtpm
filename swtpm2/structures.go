package swtpm2

import (
	"encoding/binary"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// Regular TPM 2.0 devices use 24-bit mask (3 bytes) for PCR selection.
const sizeOfPCRSelect = 3

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

type TPMPCRSelection struct {
	Hash tpm2.Algorithm
	Size byte
	PCRs tpmutil.RawBytes
}

// EncodePCRSelection encodes given PCR selection
// Copy-paste of tpm2.encodePCRSelection that is not public yet
func EncodePCRSelection(sel ...tpm2.PCRSelection) ([]byte, error) {
	if len(sel) == 0 {
		return tpmutil.Pack(uint32(0))
	}

	// PCR selection is a variable-size bitmask, where position of a set bit is
	// the selected PCR index.
	// Size of the bitmask in bytes is pre-pended. It should be at least
	// sizeOfPCRSelect.
	//
	// For example, selecting PCRs 3 and 9 looks like:
	// size(3)  mask     mask     mask
	// 00000011 00000000 00000001 00000100
	var retBytes []byte
	for _, s := range sel {
		if len(s.PCRs) == 0 {
			return tpmutil.Pack(uint32(0))
		}

		ts := TPMPCRSelection{
			Hash: s.Hash,
			Size: sizeOfPCRSelect,
			PCRs: make(tpmutil.RawBytes, sizeOfPCRSelect),
		}

		// s[i].PCRs parameter is indexes of PCRs, convert that to set bits.
		for _, n := range s.PCRs {
			if n >= 8*sizeOfPCRSelect {
				return nil, fmt.Errorf("PCR index %d is out of range (exceeds maximum value %d)", n, 8*sizeOfPCRSelect-1)
			}
			byteNum := n / 8
			bytePos := byte(1 << byte(n%8))
			ts.PCRs[byteNum] |= bytePos
		}

		tmpBytes, err := tpmutil.Pack(ts)
		if err != nil {
			return nil, err
		}

		retBytes = append(retBytes, tmpBytes...)
	}
	tmpSize, err := tpmutil.Pack(uint32(len(sel)))
	if err != nil {
		return nil, err
	}
	retBytes = append(tmpSize, retBytes...)

	return retBytes, nil
}
