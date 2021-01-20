package swtpm2

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// TPM2 represents a TPM2.0 device
type TPM2 struct {
}

// NewTPM2 creates a new TPM2 object
func NewTPM2() *TPM2 {
	return &TPM2{}
}

// ReadPublic processes ReadPublic command
func (t *TPM2) ReadPublic(handle tpmutil.Handle) (*ReadPublicResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

// ReadPublicNV processes ReadPublicNV command
func (t *TPM2) ReadPublicNV(index tpmutil.Handle) (*tpm2.NVPublic, error) {
	return nil, fmt.Errorf("not implemented")
}

func (t *TPM2) GetCapabilityPCRs(count, property uint32) ([]tpm2.PCRSelection, error) {
	return nil, fmt.Errorf("not implemented")
}

func (t *TPM2) StartAuthSession(tpmKey, bindKey tpmutil.Handle,
	nonceCaller, secret []byte,
	se tpm2.SessionType,
	sym, hashAlg tpm2.Algorithm) (tpmutil.Handle, []byte, error) {

	return tpmutil.Handle(0), nil, fmt.Errorf("not implemented")
}

// TPM2 should implement `Commands` interface
var _ Commands = &TPM2{}
