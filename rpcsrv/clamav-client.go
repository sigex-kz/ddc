package rpcsrv

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"time"
)

const (
	chunkSize    = 1024 * 1024
	goodResponse = "stream: OK\n"
)

var clamAVNetwork string
var clamAVAddress string
var clamAVConfigured bool

// ClamAVConfigure enables ClamAV integration via clamd socket.
// Should be called only before Start.
func ClamAVConfigure(network, address string) {
	clamAVNetwork = network
	clamAVAddress = address
	clamAVConfigured = true
}

func clamAVScan(data []byte) error {
	if !clamAVConfigured {
		return nil
	}

	conn, err := net.DialTimeout(clamAVNetwork, clamAVAddress, time.Second)
	if err != nil {
		for range 10 {
			conn, err = net.DialTimeout(clamAVNetwork, clamAVAddress, time.Second)
			if err == nil {
				break
			}
		}
		return err
	}
	defer func() {
		// To calm down errcheck
		closeErr := conn.Close()
		if closeErr != nil {
			return
		}
	}()

	_, err = conn.Write([]byte("nINSTREAM\n"))
	if err != nil {
		return err
	}

	for remainderSize := len(data); remainderSize > 0; remainderSize -= chunkSize {
		thisChunkSize := chunkSize
		if remainderSize < chunkSize {
			thisChunkSize = remainderSize
		}
		if thisChunkSize > math.MaxUint32 || thisChunkSize < 0 {
			panic("thisChunkSize does not fint into uint32")
		}
		thisChunkSizeUint32 := uint32(thisChunkSize)

		thisChunkSizeBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(thisChunkSizeBytes, thisChunkSizeUint32)
		_, err = conn.Write(thisChunkSizeBytes)
		if err != nil {
			return err
		}

		thisChunk := data[len(data)-remainderSize : len(data)-remainderSize+thisChunkSize]
		_, err = conn.Write(thisChunk)
		if err != nil {
			return err
		}
	}

	_, err = conn.Write([]byte{0, 0, 0, 0})
	if err != nil {
		return err
	}

	responseBytes, err := io.ReadAll(conn)
	if err != nil {
		return err
	}

	response := string(responseBytes)
	if response != goodResponse {
		return fmt.Errorf("unexpected response from clamd '%v'", response)
	}

	return nil
}
