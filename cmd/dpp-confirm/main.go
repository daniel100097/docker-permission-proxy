// dpp-confirm is a host-side confirmation helper for Docker Permission Proxy.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/danielvolz/docker-permission-proxy/internal/confirm"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	socketPath := getenv("DPP_CONFIRM_LISTEN", "/tmp/dpp-confirm.sock")
	if strings.HasPrefix(socketPath, "unix://") {
		socketPath = strings.TrimPrefix(socketPath, "unix://")
	}

	if err := removeStaleSocket(socketPath); err != nil {
		log.Fatalf("FATAL: %v", err)
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("FATAL: listen on %s: %v", socketPath, err)
	}
	defer ln.Close()
	defer os.Remove(socketPath)

	if err := os.Chmod(socketPath, 0660); err != nil {
		log.Fatalf("FATAL: chmod %s: %v", socketPath, err)
	}

	log.Printf("Listening for confirmation requests on %s", socketPath)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("ERROR: accept: %v", err)
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	var req confirm.Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		log.Printf("ERROR: decode request: %v", err)
		_ = json.NewEncoder(conn).Encode(confirm.Response{Allow: false})
		return
	}

	allow, err := confirm.NewDesktop(0).Ask(context.Background(), req)
	if err != nil {
		log.Printf("ERROR: dialog failed for request %s: %v", req.ID, err)
	}
	if err := json.NewEncoder(conn).Encode(confirm.Response{Allow: allow && err == nil}); err != nil {
		log.Printf("ERROR: encode response: %v", err)
	}
}

func removeStaleSocket(socketPath string) error {
	info, err := os.Lstat(socketPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a socket", socketPath)
	}
	return os.Remove(socketPath)
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
