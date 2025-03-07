package main

import (
	"bytes"
	"flag"
	"io"
	"log"
	"net/http"
	"time"
)

var backendURL string
var port string

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{
		Timeout: 10 * time.Second, // Set a 10-second timeout
	}

	var requestBodyBuffer []byte
	if r.Body != nil {
		requestBodyBuffer, _ = io.ReadAll(r.Body) // Read the entire body into memory
	}

	contentLength := len(requestBodyBuffer)
	log.Printf("Content-Length of the outgoing request: %d bytes", contentLength)

	// Construct the backend request
	req, err := http.NewRequest(r.Method, backendURL+r.RequestURI, bytes.NewReader(requestBodyBuffer))
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	//log.Println("Making request", backendURL+r.RequestURI, string(requestBodyBuffer))
	// Send request to backend
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to reach backend", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set the status code and copy response body
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func main() {
	flag.StringVar(&backendURL, "server", "http://localhost:8091", "Target backend server URL")
	flag.StringVar(&port, "port", "8080", "Port for the proxy server")
	flag.Parse()

	http.HandleFunc("/", proxyHandler)

	log.Println("Proxy server running on port", port)
	log.Println("Forwarding requests to", backendURL)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal("Error starting proxy:", err)
	}
}
