package main

import (
    "fmt"
    "crypto/sha256"
    "crypto/tls"
    "net/http"
)

const (
    PORT       = ":8443"
    PRIV_KEY   = "./private.pem"
    PUBLIC_KEY = "./public.pem"
)

type DeviceID [32]byte

// NewDeviceID generates a new device ID from the raw bytes of a certificate
func NewDeviceID(rawCert []byte) DeviceID {
  var n DeviceID
  hf := sha256.New()
  hf.Write(rawCert)
  hf.Sum(n[:0])
  return n
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
    clientDeviceID := NewDeviceID(r.TLS.PeerCertificates[0].Raw)
    fmt.Fprint(w, clientDeviceID)
    //fmt.Fprint(w, "Nobody should read this.")
}

func main() {

    server := &http.Server{
        TLSConfig: &tls.Config{
	    ClientAuth: tls.RequireAnyClientCert,
	    MinVersion: tls.VersionTLS12,
        },
        Addr: "127.0.0.1:8443",
    }

    http.HandleFunc("/", rootHandler)
    err := server.ListenAndServeTLS(PUBLIC_KEY, PRIV_KEY)
    if err != nil {
        fmt.Printf("main(): %s\n", err)
    }
}
