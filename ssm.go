package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"database/sql"

	"github.com/go-kit/kit/endpoint"
	httptransport "github.com/go-kit/kit/transport/http"
	_ "github.com/lib/pq"
)

// "github.com/lib/pq"

// StringService provides operations on strings.
type StringService interface {
	Wrap(string, *rsa.PrivateKey) (string, error)
	Unwrap(string, *rsa.PrivateKey) (string, error)
	Healthcheck() (string, string)
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

func (stringService) Healthcheck() (string, string) {
    log.Println("Received a healthcheck request.")
	return os.Getenv("SSM_VERSION"), os.Getenv("SSM_LOCATION")
}


// ErrEmpty is returned when an input string is empty.
var ErrEmpty = errors.New("empty string")

// For each method, we define request and response structs
type wrapRequest struct {
	Key string `json:"key"`
}

type wrapResponse struct {
	Cipher  string `json:"cipher"`
	Err string `json:"err,omitempty"` // errors don't define JSON marshaling
}

type unwrapRequest struct {
	Cipher string `json:"cipher"`
}

type unwrapResponse struct {
	Key string `json:"key"`
	Err string `json:"err,omitempty"` // errors don't define JSON marshaling
}

type healthcheckResponse struct {
	Version string `json:"version"`
	Location  string `json:"location"`
}

// Endpoints are a primary abstraction in go-kit. An endpoint represents a single RPC (method in our service interface)
func makeWrapEndpoint(svc StringService, key *rsa.PrivateKey) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(wrapRequest)
		v, err := svc.Wrap(req.Key, key)
		if err != nil {
			return wrapResponse{v, err.Error()}, nil
		}
		return wrapResponse{v, ""}, nil
	}
}

func makeUnwrapEndpoint(svc StringService, key *rsa.PrivateKey) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(unwrapRequest)
		v, err := svc.Unwrap(req.Cipher, key)
		if err != nil {
			return unwrapResponse{v, err.Error()}, nil
		}
		return unwrapResponse{v, ""}, nil
	}
}

func makeHealthcheckEndpoint(svc StringService) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		v, l := svc.Healthcheck()
		return healthcheckResponse{v, l}, nil
	}
}

func getPSQLParams(baseDir string) map[string]string {
	var paramMap = make(map[string]string)
	dirs, err := os.ReadDir(baseDir)
	log.Println(baseDir)

	if err != nil {
        log.Fatal(err)
    }

	for _, dir := range dirs {
	    dirPath := filepath.Join(baseDir, dir.Name())
		log.Println(dirPath)
        
		typePath := filepath.Join(dirPath, "type")
		dat_type, _ := os.ReadFile(typePath)
		btype := string(dat_type)
		providerPath := filepath.Join(dirPath, "provider")
		dat_provider, _ := os.ReadFile(providerPath)
		provider := string(dat_provider)
		
		if btype == "postgresql" && provider == "redhat" {
		    log.Println("Postgresql binding data found")
		    hostPath := filepath.Join(dirPath, "host")
			dat_host, _ := os.ReadFile(hostPath)
			paramMap["host"] = string(dat_host)

			userPath := filepath.Join(dirPath, "username")
			dat_user, _ := os.ReadFile(userPath)
			paramMap["username"] = string(dat_user)

			passPath := filepath.Join(dirPath, "password")
			dat_pass, _ := os.ReadFile(passPath)
			paramMap["password"] = string(dat_pass)

			portPath := filepath.Join(dirPath, "port")
			dat_port, _ := os.ReadFile(portPath)
			paramMap["port"] = string(dat_port)

			databasePath := filepath.Join(dirPath, "database")
			dat_database, _ := os.ReadFile(databasePath)
			paramMap["database"] = string(dat_database)

			return paramMap
		}
    }
	return paramMap
}

func getMasterKey(baseKey string) string {
    time.Sleep(5 * time.Second)
	connParams := getPSQLParams("/bindings")
	connStr := fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=disable port=%s", connParams["host"],
		connParams["username"], connParams["password"], connParams["database"], connParams["port"])
	//log.Println(connStr)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Println("Error connecting to database")
		log.Fatal(err)
	}

	log.Println("Sucessful connection to database!")

	_, create_err := db.Query("CREATE TABLE IF NOT EXISTS keys (name VARCHAR(10), value TEXT)")

	if create_err != nil {
		log.Println("Error creating keys table")
		log.Fatal(create_err)
	}


	rows := db.QueryRow("SELECT value FROM keys WHERE name = 'MASTERKEY'")
	var value string

	scan_err := rows.Scan(&value)

	if scan_err == nil {
		return value
	} else {
		log.Println("Master Key not found, creating")
	    sqlStatement := `
        INSERT INTO keys (name, value)
        VALUES ($1, $2)`

		_, insert_err := db.Exec(sqlStatement, "MASTERKEY", baseKey)
		if insert_err != nil {
			log.Println("Error inserting master key")
			log.Fatal(insert_err.Error())
		}
	}
	
	return baseKey
}

func getPrivateKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	
	if err != nil {
	    log.Fatalf("Error generating encryption key: %s\n", err)
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyString := base64.StdEncoding.EncodeToString(keyBytes)
	keyString = getMasterKey(keyString)
	keyBytes, _ = base64.StdEncoding.DecodeString(keyString)
	key, err = x509.ParsePKCS1PrivateKey(keyBytes)

	if err != nil {
	    log.Fatalf("Error Parsing encryption key: %s\n", err)
	}

	return key
}

// Transports expose the service to the network. In this first example we utilize JSON over HTTP.
func main() {
	svc := stringService{}
	key := getPrivateKey()

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
