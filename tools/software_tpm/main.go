package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"github.com/rihter007/go-swtpm/swtpm2"
	"net"
	"os"
	"sync"

	"github.com/facebookincubator/contest/pkg/logging"
	"github.com/rihter007/go-swtpm/mssim"
	"github.com/rihter007/go-swtpm/transport"
	"github.com/sirupsen/logrus"
)

var log = logging.GetLogger("main")

func main() {
	logLevelOptions := "["
	for _, level := range logrus.AllLevels {
		if len(logLevelOptions) > 0 {
			logLevelOptions += ", "
		}
		logLevelOptions += level.String()
	}
	logLevelOptions += "]"

	logLevelLiteral := flag.String("log-level", "info", "Determines the log level, the valid options are: "+logLevelOptions)
	useMssim := flag.Bool("mssim", false, "start in mssim mode")
	port := flag.Int("port", 2321, "Port to start listening commands at")
	flag.Parse()

	logLevel, err := logrus.ParseLevel(*logLevelLiteral)
	if err != nil {
		log.Panic(err)
	}
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logLevel)

	tpmDevice := swtpm2.NewTPM2()
	transportLogger := logging.GetLogger("transport")

	if *useMssim {
		if err := launchMSSIMServer(*port, *port+1, tpmDevice, transportLogger); err != nil {
			log.Errorf("faield to launch server: %v", err)
		}
	} else {
		loop := swtpm2.NewLoopProcessCommand(tpmDevice)
		connectionLoop := func(c net.Conn) {
			loop(c)
		}
		if err := transport.ServeTCP(context.Background(), *port, connectionLoop, transportLogger); err != nil {
			log.Errorf("failed during serving commands on TCP transport, err: %v", err)
		}
	}
}

func launchMSSIMServer(commandPort, platformPort int, commands swtpm2.Commands, transportLogger *logrus.Entry) error {
	log.Infof("launch in mssim mode, command port: %d, platform port %d", commandPort, platformPort)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		loop := transport.NewConnectionProcessingLoop(func(c net.Conn) error {
			return mssim.DummyPlatformProcessor(c, nil)
		})
		if err := transport.ServeTCP(context.Background(), platformPort, loop, transportLogger); err != nil {
			log.Errorf("failed during serving mssim platform commands on TCP transport, err: %v", err)
		}
	}()

	// launch commands processor
	wg.Add(1)
	go func() {
		defer wg.Done()
		processor := func(c net.Conn) error {
			request, err := mssim.ParseRequest(c)
			if err != nil {
				return err
			}

			commandResponse, err := swtpm2.ProcessCommand(bytes.NewBuffer(request.InternalCommand), commands)
			if err != nil {
				return fmt.Errorf("failed to process TPM command, err: %v", err)
			}

			mssimResponse, err := mssim.CreateResponse(mssim.RCSuccess, commandResponse)
			if err != nil {
				return fmt.Errorf("failed creating response frame, err: %v", err)
			}
			bytesWritten, err := c.Write(mssimResponse)
			log.Infof("command processed, response bytes written: %d", bytesWritten)
			return err
		}

		loop := transport.NewConnectionProcessingLoop(processor)
		if err := transport.ServeTCP(context.Background(), commandPort, loop, transportLogger); err != nil {
			log.Errorf("failed during serving mssim commands on TCP transport, err: %v", err)
		}
	}()
	wg.Wait()
	return nil
}
