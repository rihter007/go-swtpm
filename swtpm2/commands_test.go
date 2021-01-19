package swtpm2_test

import (
	"io"
	"sync"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/rihter007/go-swtpm/swtpm2"
	"github.com/stretchr/testify/require"
)

type channelTransport struct {
	remainder []byte
	ch        chan []byte
}

func (ct *channelTransport) Close() error {
	close(ct.ch)
	return nil
}

func (ct *channelTransport) Read(p []byte) (int, error) {
	if len(ct.remainder) > 0 {
		copied := copy(p, ct.remainder)
		ct.remainder = ct.remainder[copied:]
		return copied, nil
	}

	chunk := <-ct.ch
	if chunk == nil {
		return 0, io.EOF
	}
	copied := copy(p, chunk)
	ct.remainder = chunk[copied:]
	return copied, nil
}

func (ct *channelTransport) Write(p []byte) (n int, err error) {
	ct.ch <- p
	return len(p), err
}

func newChannelTransport() *channelTransport {
	return &channelTransport{
		ch: make(chan []byte, 10),
	}
}

type memoryTransport struct {
	input  *channelTransport
	output *channelTransport
}

func (m *memoryTransport) Read(p []byte) (n int, err error) {
	return m.input.Read(p)
}

func (m *memoryTransport) Write(p []byte) (n int, err error) {
	return m.output.Write(p)
}

func connectedTransport() (*memoryTransport, *memoryTransport) {
	input := newChannelTransport()
	output := newChannelTransport()

	client := &memoryTransport{
		input:  input,
		output: output,
	}

	server := &memoryTransport{
		input:  output,
		output: input,
	}

	return client, server
}

type mockedCommands struct {
	readPublic   func(handle tpmutil.Handle) (*swtpm2.ReadPublicResponse, error)
	readPublicNV func(index tpmutil.Handle) (*tpm2.NVPublic, error)
}

func (m *mockedCommands) ReadPublic(handle tpmutil.Handle) (*swtpm2.ReadPublicResponse, error) {
	return m.readPublic(handle)
}

func (m *mockedCommands) ReadPublicNV(index tpmutil.Handle) (*tpm2.NVPublic, error) {
	return m.readPublicNV(index)
}

func TestReadPublic(t *testing.T) {
	clientIO, serverIO := connectedTransport()

	// just fill it somehow
	expectedPublic := tpm2.Public{
		Type: tpm2.AlgRSA,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgRSA,
				KeyBits: 10,
			},
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits:     10,
			ExponentRaw: 1023,
			ModulusRaw:  []byte{0x11, 0x12},
		},
	}

	expectedResponse := &swtpm2.ReadPublicResponse{
		Public:        expectedPublic,
		Name:          []byte("name"),
		QualifiedName: []byte("qualifiedName"),
	}

	var actualHandle tpmutil.Handle
	commands := &mockedCommands{
		readPublic: func(handle tpmutil.Handle) (*swtpm2.ReadPublicResponse, error) {
			actualHandle = handle
			return expectedResponse, nil
		},
	}

	var commandError error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		b, err := swtpm2.ProcessCommand(serverIO, commands)
		commandError = err

		_, err = serverIO.Write(b)
		if err != nil {
			t.Fatalf("failed to write data to a channel transport, err: %v", err)
		}
	}()

	usedHandle := tpmutil.Handle(10)
	public, name, qualifiedName, err := tpm2.ReadPublic(clientIO, usedHandle)

	wg.Wait()
	require.NoError(t, commandError)

	require.NoError(t, err)
	require.Equal(t, usedHandle, actualHandle)
	require.Equal(t, expectedResponse.Public, public)
	require.Equal(t, expectedResponse.Name, name)
	require.Equal(t, expectedResponse.QualifiedName, qualifiedName)
}

func TestReadPublicNV(t *testing.T) {
	clientIO, serverIO := connectedTransport()

	// just fill it somehow
	expectedNVPublic := tpm2.NVPublic{
		NVIndex:    tpmutil.Handle(10),
		NameAlg:    tpm2.AlgSHA1,
		Attributes: tpm2.NVAttr(1234),
		AuthPolicy: tpmutil.U16Bytes{1, 2, 3, 4},
		DataSize:   1000,
	}

	var actualHandle tpmutil.Handle
	commands := &mockedCommands{
		readPublicNV: func(handle tpmutil.Handle) (*tpm2.NVPublic, error) {
			actualHandle = handle
			return &expectedNVPublic, nil
		},
	}

	var commandError error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		b, err := swtpm2.ProcessCommand(serverIO, commands)
		commandError = err

		_, err = serverIO.Write(b)
		if err != nil {
			t.Fatalf("failed to write data to a channel transport, err: %v", err)
		}
	}()

	usedHandle := tpmutil.Handle(10)
	public, err := tpm2.NVReadPublic(clientIO, usedHandle)

	wg.Wait()
	require.NoError(t, commandError)

	require.NoError(t, err)
	require.Equal(t, usedHandle, actualHandle)
	require.Equal(t, expectedNVPublic, public)
}
