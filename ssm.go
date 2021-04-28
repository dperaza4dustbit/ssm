package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"crypto/rsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"github.com/go-kit/kit/endpoint"
	httptransport "github.com/go-kit/kit/transport/http"
)

// StringService provides operations on strings.
type StringService interface {
	Wrap(string, *rsa.PrivateKey) (string, error)
	Unwrap(string, *rsa.PrivateKey) (string, error)
	Healthcheck() string
}

// stringService is a concrete implementation of StringService
type stringService struct{}

func (stringService) Wrap(s string, key *rsa.PrivateKey) (string, error) {
    log.Println("Received a wrap request.")
	if s == "" {
		return "", ErrEmpty
	}

    secretMessage := []byte(s)
    label := []byte("ssm_wrap")

    rng := rand.Reader

    ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &key.PublicKey, secretMessage, label)
    if err != nil {
        log.Printf("Error from encryption: %s\n", err)
        return "", err
    }

    encoded := base64.StdEncoding.EncodeToString(ciphertext)

	return encoded, nil
}

func (stringService) Unwrap(s string, key *rsa.PrivateKey) (string, error) {
    log.Println("Received an unwrap request.")
	ciphertext, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
        log.Printf("Error from decoding: %s\n", err)
        return "", err
    }

    label := []byte("ssm_wrap")

    rng := rand.Reader

    plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, key, ciphertext, label)
    if err != nil {
        log.Printf("Error from decryption: %s\n", err)
        return "", err
    }

	return string(plaintext), nil
}

func (stringService) Healthcheck() string {
    log.Println("Received a healthcheck request.")
	return os.Getenv("SSM_VERSION")
}


// ErrEmpty is returned when an input string is empty.
var ErrEmpty = errors.New("empty string")

// For each method, we define request and response structs
type wrapRequest struct {
	S string `json:"key"`
}

type wrapResponse struct {
	V   string `json:"cipher"`
	Err string `json:"err,omitempty"` // errors don't define JSON marshaling
}

type unwrapRequest struct {
	S string `json:"cipher"`
}

type unwrapResponse struct {
	V string `json:"key"`
	Err string `json:"err,omitempty"` // errors don't define JSON marshaling
}

type healthcheckResponse struct {
	V string `json:"version"`
}

// Endpoints are a primary abstraction in go-kit. An endpoint represents a single RPC (method in our service interface)
func makeWrapEndpoint(svc StringService, key *rsa.PrivateKey) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(wrapRequest)
		v, err := svc.Wrap(req.S, key)
		if err != nil {
			return wrapResponse{v, err.Error()}, nil
		}
		return wrapResponse{v, ""}, nil
	}
}

func makeUnwrapEndpoint(svc StringService, key *rsa.PrivateKey) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(unwrapRequest)
		v, err := svc.Unwrap(req.S, key)
		if err != nil {
			return unwrapResponse{v, err.Error()}, nil
		}
		return unwrapResponse{v, ""}, nil
	}
}

func makeHealthcheckEndpoint(svc StringService) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		v := svc.Healthcheck()
		return healthcheckResponse{v}, nil
	}
}

// Transports expose the service to the network. In this first example we utilize JSON over HTTP.
func main() {
	svc := stringService{}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
	    log.Fatalf("Error generating encryption key: %s\n", err)
	}

	wrapHandler := httptransport.NewServer(
		makeWrapEndpoint(svc, key),
		decodeWrapRequest,
		encodeResponse,
	)

	unwrapHandler := httptransport.NewServer(
		makeUnwrapEndpoint(svc, key),
		decodeUnwrapRequest,
		encodeResponse,
	)

	healthcheckHandler := httptransport.NewServer(
		makeHealthcheckEndpoint(svc),
		decodeHealthcheckRequest,
		encodeResponse,
	)

    log.Println("Setting the endpoint handlers.")
	http.Handle("/wrap", wrapHandler)
	http.Handle("/unwrap", unwrapHandler)
	http.Handle("/healthcheck", healthcheckHandler)
	log.Println("Starting Listener on port 8080.")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func decodeWrapRequest(_ context.Context, r *http.Request) (interface{}, error) {
	var request wrapRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		return nil, err
	}
	return request, nil
}

func decodeUnwrapRequest(_ context.Context, r *http.Request) (interface{}, error) {
	var request unwrapRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		return nil, err
	}
	return request, nil
}

func decodeHealthcheckRequest(_ context.Context, r *http.Request) (interface{}, error) {
	return nil, nil
}

func encodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	return json.NewEncoder(w).Encode(response)
}
