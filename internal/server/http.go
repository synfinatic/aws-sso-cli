package server

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

// Use format as defined here: https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/credentials/endpointcreds
type Message struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// writeMessage returns a JSON message to the caller with the appropriate HTTP Status Code
func writeMessage(w http.ResponseWriter, msg string, statusCode int) {
	w.Header().Set("Content-Type", CHARSET_JSON)
	w.WriteHeader(statusCode)
	m := Message{
		Code:    strconv.Itoa(statusCode),
		Message: msg,
	}
	if err := json.NewEncoder(w).Encode(m); err != nil {
		log.Error(err.Error())
	}
}

// withAuthorizationCheck checks our authToken (if set) and returns 404 on error
func withAuthorizationCheck(authToken string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != authToken {
			writeMessage(w, "Invalid authorization token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// writeCredsToResponse generates the appropriate response for ECS Server queries using the
// provided RoleCredentials
func writeCredsToResponse(creds *storage.RoleCredentials, w http.ResponseWriter) {
	err := json.NewEncoder(w).Encode(map[string]string{
		"AccessKeyId":     creds.AccessKeyId,
		"SecretAccessKey": creds.SecretAccessKey,
		"Token":           creds.SessionToken,
		"Expiration":      creds.ExpireISO8601(),
	})
	if err != nil {
		writeMessage(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
