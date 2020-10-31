package main

import (
	"html/template"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
)

func main() {
	var err error

	// prepare challenge HTML template
	challengeTemplate, err = template.New("challenge.html").Parse(challengeHTMLTemplate)
	if err != nil {
		Error.Fatalf("challenge service template error: %s\n", err.Error())
	}

	// prepare challenge Lite HTML template
	challengeLiteTemplate, err = template.New("challenge-lite.html").Parse(challengeLightHTMLTemplate)
	if err != nil {
		Error.Fatalf("challenge service template error: %s\n", err.Error())
	}

	// create new HTTP mux and define HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc("/", challengeHandle)
	mux.HandleFunc("/auth", authHandle)
	mux.HandleFunc("/favicon.ico", faviconHandler)

	// run DB cleaner to clean expired keys
	go cleanDB(&db)

	// define net listner for HTTP serve function
	var nl net.Listener

	switch {
	case strings.HasPrefix(cmdAddress, "unix:"):
		// get socket path
		socket := strings.TrimPrefix(cmdAddress, "unix:")

		// remove old Unix socket
		if _, err = os.Stat(socket); !os.IsNotExist(err) {
			if err = syscall.Unlink(socket); err != nil {
				Error.Fatalf("challenge service socket error: %s\n", err.Error())
			}
		}

		// listen on unix socket
		nl, err = net.Listen("unix", socket)
		if err != nil {
			Error.Fatalf("challenge service socket error: %s\n", err.Error())
		}

		// close unix socket on exit
		defer func() {
			if err = nl.Close(); err != nil {
				Error.Fatalf("challenge service socket error: %s\n", err.Error())
			}
		}()

		// change unix socket permissions
		if err = os.Chmod(socket, os.FileMode(0o777)); err != nil {
			Error.Fatalf("challenge service socket error: %s\n", err.Error())
		}
	default:
		// listen on TCP
		nl, err = net.Listen("tcp", cmdAddress)
		if err != nil {
			Error.Fatalf("challenge service TCP error: %s\n", err.Error())
		}
	}

	// start challenge server
	err = http.Serve(nl, mux)
	if err != nil {
		Error.Fatalf("challenge service start error: %s\n", err.Error())
	}
}
