package main

import (
  "crypto/tls"
  //"crypto/x509"
  "encoding/json"
  "fmt"
  "io"
  //"io/ioutil"
  "log"
	"net/http"
	"net"
  "os"
  "strconv"
	"strings"
  "time"
  "github.com/synctum/common/utils"
  "github.com/gorilla/mux"
)

// 2do: read config file with discovery settings

const (
  CERTIFICATE = "./public.pem"
  PRIVATE_KEY = "./private.pem"
  LISTEN_ADDR = "0.0.0.0" // all interfaces
  DEFAULT_SYNC_PORT = "27182"
  DEFAULT_DISCOVERY_PORT = "31415"
)

type deviceType struct{
  Addr net.IP
  Port uint16
  LocalAddr net.IP
  LocalPort uint16
  LastSeen time.Time
  DeviceID *utils.DeviceID
}

// 2do: persist in database
var devices = make(map[string]*deviceType)

var (
  Trace   *log.Logger
  Info    *log.Logger
  Warning *log.Logger
  Error   *log.Logger
)

func Init(
  traceHandle io.Writer,
  infoHandle io.Writer,
  warningHandle io.Writer,
  errorHandle io.Writer) {

  Trace = log.New(traceHandle,
    "TRACE: ",
    log.Ldate|log.Ltime|log.Lshortfile)

  Info = log.New(infoHandle,
    "INFO: ",
    log.Ldate|log.Ltime|log.Lshortfile)

  Warning = log.New(warningHandle,
    "WARNING: ",
    log.Ldate|log.Ltime|log.Lshortfile)

  Error = log.New(errorHandle,
    "ERROR: ",
    log.Ldate|log.Ltime|log.Lshortfile)
}

func main() {
  // 2do: allow configuration of logging level
  //Init(ioutil.Discard, os.Stdout, os.Stdout, os.Stderr)
  Init(os.Stdout, os.Stdout, os.Stdout, os.Stderr)

  Info.Println("Discovery server starting up")

	server := http.Server{
    // 2do: use addr/port from command line params/config file
		Addr: LISTEN_ADDR + ":" + DEFAULT_DISCOVERY_PORT,
    TLSConfig: &tls.Config{
      ClientAuth: tls.RequireAnyClientCert,
      MinVersion: tls.VersionTLS12,
      CipherSuites: []uint16 {
        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    	},
		},
	}

  r := mux.NewRouter()
  // 2do: test for HTTPS + hostname + certificate CN + key length (?) + key type
  v1 := r.PathPrefix("/v1").Subrouter()

  //register/update a device
  v1.HandleFunc("/devices/", registerDevice).
    Methods("POST")

  //retrieve a device through short ID
  v1.HandleFunc("/devices/{shortID:[A-Z]{5}-[A-Z]{5}-[A-Z]{5}-[A-Z]{5}-[A-Z]{5}-[A-Z]{5}-[A-Z]{5}-[A-Z]{5}}", lookupDevice).
    Methods("GET")

  //retrieve a device through full ID
  v1.HandleFunc("/devices/{shortID:[A-Z]{7}-[A-Z]{7}-[A-Z]{7}-[A-Z]{7}-[A-Z]{7}-[A-Z]{7}-[A-Z]{7}-[A-Z]{7}}", lookupDevice).
    Methods("GET")

  //unregister a device
  v1.HandleFunc("/devices/", unregisterDevice).
    Methods("DELETE")

  http.Handle("/", r)
  // 2do: use cert/key from command line params/config file
  // 2do: check if cert/key are present
  Info.Println("Listening on address " + LISTEN_ADDR + ":" + DEFAULT_DISCOVERY_PORT)
  server.ListenAndServeTLS(CERTIFICATE, PRIVATE_KEY)
}

func registerDevice(res http.ResponseWriter, req *http.Request) {
  // 2do: output some useful req info
  Trace.Println("registerDevice called")

  vars := mux.Vars(req)
  var addr, localAddr net.IP
  var port, localPort uint16
  var device deviceType
  var responseStatus int
  var responseMessage string
  var responseBody struct {
    Status string
    Device deviceType
    Message string
  }

  // send the response constructed below
  defer func(){
    if responseStatus == 0 {
      responseStatus = http.StatusOK
    }
    Trace.Println("reponseStatus: ", responseStatus)
    if responseStatus < 300 {
      responseBody.Status = "success"
      responseBody.Device = device
    } else {
      responseBody.Status = "error"
    }
    if responseMessage == "" {
      responseBody.Message = http.StatusText(responseStatus)
    } else {
      responseBody.Message = responseMessage
    }
    Trace.Println("responseBody.Message: ", responseBody.Message)
    js,err := json.Marshal(&responseBody)
    Trace.Println(string(js))
    if err != nil {
      Error.Println("reponseBody could not be mashalled to JSON")
      responseStatus = http.StatusInternalServerError
      // 2do: could we instead respond with a hand-crafter JSON message in this
      // unlikely case to remain consistent?
      js = []byte("")
    }
    // 2do: test range of statuscode and set jsonresponse accordingly
    res.Header().Set("Content-Type", "application/json")
    res.WriteHeader(responseStatus)
    res.Write(js)
  }()

  //set remote IP
  addr = net.ParseIP(strings.Split(req.RemoteAddr,":")[0])
  if (addr == nil) {
    // should never happen
    Error.Println("External IP address could not be parsed")
    responseStatus = http.StatusInternalServerError
    return
  }

  //set remote port
  portString,ok := vars["port"]
  if ok { // request specified port
    port64,err := strconv.ParseUint(portString, 10, 16)
    if err != nil { // port was specified but invalid
      Warning.Println("Port was specified but not valid")
      responseStatus = http.StatusBadRequest
      responseMessage = "Port was specified but not valid"
      return
    }
    port = uint16(port64)
  } else { // request did not specify port -> set default
    port64,err := strconv.ParseUint(DEFAULT_SYNC_PORT, 10, 16)
    if err != nil { // should never happen (config error)
      Error.Println("DEFAULT_SYNC_PORT could not be parsed")
      responseStatus = http.StatusInternalServerError
      return
    }
    port = uint16(port64)
  }

  //set local IP address if specified
  localAddrString,ok := vars["localaddr"]
  if ok { // localaddr specified
    localAddr = net.ParseIP(localAddrString)
    if localAddr == nil { //local address specified but invalid
      Warning.Println("Local address was specified but not valid")
      responseStatus = http.StatusBadRequest
      responseMessage = "Local address was specified but not valid"
      return
    }
    //2do: test local, !multicast, !localloop, etc
    //set local port
    localPortString,ok := vars["localport"]
    if ok { // request specified localport
      port64,err := strconv.ParseUint(localPortString, 10, 16)
      if err != nil { // localport was specified but invalid
        Warning.Println("Local port was specified but not valid")
        responseStatus = http.StatusBadRequest
        responseMessage = "Local port was specified but not valid"
        return
      }
      localPort = uint16(port64)
    } else { // request did not specify localport -> set default
      port64,err := strconv.ParseUint(DEFAULT_SYNC_PORT, 10, 16)
      if err != nil { // should never happen (config error)
        Error.Println("DEFAULT_SYNC_PORT could not be parsed")
        responseStatus = http.StatusInternalServerError
        return
      }
      localPort = uint16(port64)
    }
  }

  //2do: test if ok
  certificate := req.TLS.PeerCertificates[0]
  deviceID := utils.NewDeviceID(certificate.Raw)

  device = deviceType {
    Addr: addr,
    Port: port,
    LocalAddr: localAddr,
    LocalPort: localPort,
    LastSeen: time.Now(),
    DeviceID: &deviceID,
  }

  // 2do: provide more info on device
  Info.Println("Device updated: ", deviceID.ShortString())
  devices[deviceID.ShortString()] = &device
}

func lookupDevice(w http.ResponseWriter, r *http.Request) {
  vars := mux.Vars(r)
  shortID := vars["shortID"]
  fmt.Fprintln(w, (*devices[shortID]).LastSeen)
}

func unregisterDevice(w http.ResponseWriter, r *http.Request) {
}