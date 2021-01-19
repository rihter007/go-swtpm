package transport

import (
	"context"
	"fmt"
	"net"

	"github.com/rihter007/logruswrap"
)

// ServeTCP launches software TPM on a specified port
func ServeTCP(ctx context.Context, port int, handleConnection func(c net.Conn), l logruswrap.PrintfLogger) error {
	if handleConnection == nil {
		panic("handleConnection should not be nil")
	}
	log := logruswrap.WrapPrintfLogger(l)
	lc := net.ListenConfig{}
	address := fmt.Sprintf("localhost:%d", port)
	listener, err := lc.Listen(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("failed to start listening on %s", address)
	}

	internalCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		<-internalCtx.Done()

		log.Debugf("close listener for %s", address)
		if err := listener.Close(); err != nil {
			log.Errorf("failed close listener, err: %v", err)
		}
	}()

	log.Infof("listening on %s", address)
	for {
		c, err := listener.Accept()
		if internalCtx.Err() != nil {
			return nil
		}
		if err != nil {
			log.Errorf("obtained an error during accept: %v on address %s", err, address)
			continue
		}
		log.Debugf("connected from %s on address %s", c.RemoteAddr().String(), address)
		go func(conn net.Conn) {
			handleConnection(conn)
			log.Infof("handling of %s finished", c.RemoteAddr().String())
		}(c)
	}
}
