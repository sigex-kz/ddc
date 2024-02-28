// Runs ddc RPC server
package main

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
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
var clamdNetworkFlag = flag.String("clamd-network-type", "unix", "type of network socket to use to connect to clamd (ClamAV)")
var clamdSocketFlag = flag.String("clamd-socket", "", "socket to use to connect to clamd (e.g. \"/var/run/clamav/clamd.ctl\"), disable ClamAV integration if empty")
var prometheusPortFlag = flag.String("prometheus-port", "9001", "port to expose prometheus metrics on, disable if empty")

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

	if *clamdSocketFlag != "" {
		rpcsrv.ClamAVConfigure(*clamdNetworkFlag, *clamdSocketFlag)
	}

	errChan := make(chan error)
	err := rpcsrv.Start("tcp", fmt.Sprintf(":%v", *portFlag), errChan)
	if err != nil {
		panic(err)
	}

	var prometheusServer *http.Server
	if *prometheusPortFlag != "" {
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())

			prometheusServer = &http.Server{
				Addr:              fmt.Sprintf(":%v", *prometheusPortFlag),
				Handler:           mux,
				ReadHeaderTimeout: 1 * time.Second,
				ReadTimeout:       1 * time.Second,
				WriteTimeout:      2 * time.Second,
				IdleTimeout:       120 * time.Second,
			}

			promErr := prometheusServer.ListenAndServe()
			if promErr != nil && !errors.Is(promErr, http.ErrServerClosed) {
				panic(promErr)
			}
		}()
	}

	osSignalChannel := make(chan os.Signal, 1)
	signal.Notify(osSignalChannel, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(osSignalChannel) // stop waiting for os signals

	select {
	case err = <-errChan:
		panic(err)

	case <-osSignalChannel:
		err = prometheusServer.Close()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
		return
	}
}
