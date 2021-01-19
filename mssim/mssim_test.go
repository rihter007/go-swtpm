package mssim_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	go_mssim "github.com/google/go-tpm/tpmutil/mssim"
	"github.com/rihter007/go-swtpm/mssim"
	"github.com/rihter007/go-swtpm/swtpm2"
	"github.com/rihter007/go-swtpm/transport"
	"github.com/stretchr/testify/require"
)

type mockedCommands struct {
	swtpm2.Commands
	readPublic func(handle tpmutil.Handle) (*swtpm2.ReadPublicResponse, error)
}

func (m *mockedCommands) ReadPublic(handle tpmutil.Handle) (*swtpm2.ReadPublicResponse, error) {
	return m.readPublic(handle)
}

func TestMSSIM(t *testing.T) {
	port, err := transport.GetFreePort()
	require.NoError(t, err)
	require.Greater(t, port, 0)

	commandPort := port
	platformPort := port + 1

	conf := go_mssim.Config{
		CommandAddress:  fmt.Sprintf("localhost:%d", commandPort),
		PlatformAddress: fmt.Sprintf("localhost:%d", platformPort),
	}

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
	m := &mockedCommands{
		readPublic: func(handle tpmutil.Handle) (*swtpm2.ReadPublicResponse, error) {
			actualHandle = handle
			return expectedResponse, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var platformServeTCPError error
	var commandServeTCPError error

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		dummyProcessor := func(c net.Conn) error {
			return mssim.DummyPlatformProcessor(c, nil)
		}
		loop := transport.NewConnectionProcessingLoop(dummyProcessor)
		platformServeTCPError = transport.ServeTCP(ctx, platformPort, func(c net.Conn) {
			loop(c)
		}, nil)
	}()

	wg.Add(1)
	var request *mssim.Request
	go func() {
		defer wg.Done()
		commandServeTCPError = transport.ServeTCP(ctx, commandPort, func(c net.Conn) {
			var err error
			request, err = mssim.ParseRequest(c)
			require.NoError(t, err)
			b, err := swtpm2.ProcessCommand(bytes.NewBuffer(request.InternalCommand), m)
			require.NoError(t, err)

			result, err := mssim.CreateResponse(0, b)
			require.NoError(t, err)
			if _, err := c.Write(result); err != nil {
				panic(err)
			}
		}, nil)
	}()

	conn, err := go_mssim.Open(conf)
	require.NoError(t, err)
	require.NotNil(t, conn)

	usedHandle := tpmutil.Handle(10)
	public, name, qualifiedName, err := tpm2.ReadPublic(conn, usedHandle)
	cancel()
	wg.Wait()

	require.NoError(t, platformServeTCPError)
	require.NoError(t, commandServeTCPError)

	require.NoError(t, err)
	require.NotNil(t, request)

	require.Equal(t, mssim.TpmSendCommand, request.Command)

	require.Equal(t, usedHandle, actualHandle)
	require.Equal(t, expectedResponse.Public, public)
	require.Equal(t, expectedResponse.Name, name)
	require.Equal(t, expectedResponse.QualifiedName, qualifiedName)
}
