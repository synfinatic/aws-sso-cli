package ecs

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/synfinatic/aws-sso-cli/internal/logger"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

// Use format as defined here: https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/credentials/endpointcreds
type Message struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// WriteCreds returns the JSON of the provided creds to the HTTP client
// https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
func WriteCreds(w http.ResponseWriter, creds *storage.RoleCredentials) {
	if creds.Expired() {
		Expired(w)
		return
	}

	resp := map[string]string{
		"AccessKeyId":     creds.AccessKeyId,
		"Expiration":      creds.ExpireString(),
		"RoleArn":         creds.RoleArn(),
		"SecretAccessKey": creds.SecretAccessKey,
		"Token":           creds.SessionToken,
	}
	JSONResponse(w, resp)
}

// JSONResponse return a JSON blob as a result
func JSONResponse(w http.ResponseWriter, jdata interface{}) {
	log := logger.GetLogger()
	w.Header().Set("Content-Type", CHARSET_JSON)
	if err := json.NewEncoder(w).Encode(jdata); err != nil {
		log.Error(err.Error())
		WriteMessage(w, err.Error(), http.StatusInternalServerError)
	}
}

// OK returns an OK response
func OK(w http.ResponseWriter) {
	WriteMessage(w, "OK", http.StatusOK)
}

// Expired returns a credentials expired response
func Expired(w http.ResponseWriter) {
	WriteMessage(w, "Credentials expired", http.StatusNotFound)
}

// Unavailable returns a credentials unavailable response
func Unavailable(w http.ResponseWriter) {
	WriteMessage(w, "Credentials unavailable", http.StatusNotFound)
}

// Invalid returns an invalid request response
func Invalid(w http.ResponseWriter) {
	WriteMessage(w, "Bad request", http.StatusBadRequest)
}

// InternalServerErrror returns an internal server error response
func InternalServerErrror(w http.ResponseWriter, err error) {
	WriteMessage(w, err.Error(), http.StatusInternalServerError)
}

// WriteMessage returns a JSON message to the caller with the appropriate HTTP Status Code
func WriteMessage(w http.ResponseWriter, msg string, statusCode int) {
	w.Header().Set("Content-Type", CHARSET_JSON)
	w.WriteHeader(statusCode)
	m := Message{
		Code:    strconv.Itoa(statusCode),
		Message: msg,
	}
	_ = json.NewEncoder(w).Encode(m)
}

func WriteListProfilesResponse(w http.ResponseWriter, lpr []ListProfilesResponse) {
	JSONResponse(w, lpr)
}

func WriteListProfileResponse(w http.ResponseWriter, lpr ListProfilesResponse) {
	JSONResponse(w, lpr)
}
