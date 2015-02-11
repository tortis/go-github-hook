package ggh

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

type PushEventHandler func(e *PushEvent)

type HookServer struct {
	HookURL     string
	HookPort    string
	Secret      string
	Mux         *http.ServeMux
	PushHandler PushEventHandler
}

func NewHookServer(url, port, secret string, handler PushEventHandler) *HookServer {
	return &HookServer{
		HookURL:     url,
		HookPort:    port,
		Secret:      secret,
		Mux:         http.NewServeMux(),
		PushHandler: handler,
	}
}

func (h *HookServer) Start() error {
	h.Mux.HandleFunc(h.HookURL, h.handler)
	return http.ListenAndServe(fmt.Sprintf(":%s", h.HookPort), h.Mux)
}

func (h *HookServer) handler(w http.ResponseWriter, r *http.Request) {
	// Only listen to POST requests
	if r.Method != "POST" {
		log.Println("Non POST request ignored.")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Get GitHub headers
	eventType := r.Header.Get("X-GitHub-Event")
	eventSignature := r.Header.Get("X-Hub-Signature")
	eventId := r.Header.Get("X-Github-Delivery")

	// Only handle push events
	if eventType != "push" {
		log.Println("Non push event ignored.")
		w.WriteHeader(http.StatusOK)
		return
	}

	log.Println("Received push event: ", eventId)

	// Read the JSON payload
	jsonPayload, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("Failed to read request body.")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Validate the event signature
	sigPieces := strings.Split("=", eventSignature)
	if len(sigPieces) != 2 {
		log.Println("Bad event signature.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sig, err := hex.DecodeString(sigPieces[1])
	if err != nil {
		log.Println("Could not decode hex signature")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	mac := hmac.New(sha1.New, []byte(h.Secret))
	mac.Write(jsonPayload)
	expectedSig := mac.Sum(nil)
	if !hmac.Equal(expectedSig, sig) {
		log.Println("Event signature did not match expected signature. Is your key correct?")
		w.WriteHeader(http.StatusOK)
		return
	}

	// Build object from json
	e := PushEvent{}
	err = json.Unmarshal(jsonPayload, &e)
	if err != nil {
		log.Println("Failed to parse the event payload.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// Call handler (on goroutine?)
	go h.PushHandler(&e)
	w.WriteHeader(http.StatusOK)
}
