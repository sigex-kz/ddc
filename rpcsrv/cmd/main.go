package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/sigex-kz/ddc/rpcsrv"
)

var (
	// AppVersion holds application version.
	// It is set on build with -ldflags "-X main.AppVersion=1.0.0"
	AppVersion string
	// BuildTimeStamp holds Release build timestamp
	// It is set on build with -ldflags "-X 'main.BuildTimeStamp=$(date)'"
	BuildTimeStamp string
)

var portFlag = flag.String("port", "4567", "port to launch RPC server on")
var versionFlag = flag.Bool("version", false, "Show version")

func main() {
	if AppVersion == "" {
		AppVersion = "undefined"
	}

	if _, parseError := strconv.ParseInt(BuildTimeStamp, 10, 64); parseError != nil {
		BuildTimeStamp = "0"
	}

	flag.Parse()

	if *versionFlag {
		fmt.Printf("Version: %s\nBuildTimeStamp:%s\n", AppVersion, BuildTimeStamp)
		return
	}

	errChan := make(chan error)
	err := rpcsrv.Start("tcp", fmt.Sprintf(":%v", *portFlag), errChan)
	if err != nil {
		panic(err)
	}

	osSignalChannel := make(chan os.Signal, 1)
	signal.Notify(osSignalChannel, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(osSignalChannel) // stop waiting for os signals

	select {
	case err = <-errChan:
		panic(err)

	case <-osSignalChannel:
		return
	}

}
