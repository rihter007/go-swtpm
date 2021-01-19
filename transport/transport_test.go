package transport_test

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/rihter007/go-swtpm/transport"
	"github.com/stretchr/testify/require"
)

func TestTcpTransport(t *testing.T) {
	freePort, err := transport.GetFreePort()
	require.NoError(t, err)
	require.Greater(t, freePort, 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	connectedEvent := make(chan struct{})

	wg.Add(1)
	var serverTCPError error
	go func() {
		defer wg.Done()
		serverTCPError = transport.ServeTCP(ctx, freePort, func(c net.Conn) {
			close(connectedEvent)
		}, nil)
	}()

	c, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", freePort))
	require.NoError(t, err)
	require.NotNil(t, c)
	defer func() {
		require.NoError(t, c.Close())
	}()

	var obtainedConnection bool
	select {
	case <-connectedEvent:
		obtainedConnection = true
	case <-time.After(time.Second):
	}
	require.True(t, obtainedConnection)

	cancel()
	wg.Wait()

	require.NoError(t, serverTCPError)
}
