// Package rpcsrv implements a RPC server for ddc library
package rpcsrv

import (
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
)

var netListener net.Listener

// Start JSON-RPC server on the specified network and address (see net.Listen(network, address)).
// Function returns error in case if net.Listen(network, address) failed,
// errChan is used to send errors that occur later.
func Start(network, address string, errChan chan error) error {
	srv := rpc.NewServer()

	err := srv.Register(new(Builder))
	if err != nil {
		return err
	}

	err = srv.Register(new(Extractor))
	if err != nil {
		return err
	}

	netListener, err = net.Listen(network, address)
	if err != nil {
		return err
	}

	go func() {
		for {
			conn, accErr := netListener.Accept()
			if accErr != nil {
				errChan <- accErr
				continue
			}

			go func(conn net.Conn) {
				codec := jsonrpc.NewServerCodec(conn)
				srv.ServeCodec(codec)
			}(conn)
		}
	}()

	return nil
}

// Stop server
func Stop() error {
	return netListener.Close()
}
