package gospark

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SkysparkClient represents a client for Skyspark API with SCRAM authentication
type SkysparkClient struct {
	URI      string
	Username string
	Password string
	Client   *http.Client
}

// NewSkysparkClient creates a new Skyspark client
func NewSkysparkClient(uri, username, password string) *SkysparkClient {
	return &SkysparkClient{
		URI:      uri,
		Username: username,
		Password: password,
		Client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Scram performs SCRAM authentication and returns the auth token
func (s *SkysparkClient) Scram() (string, error) {
	// SCRAM Authentication Parameters
	if s.URI == "" {
		return "", fmt.Errorf("Skyspark Client not found")
	}

	// Extract server URL
	serverURL := strings.Split(s.URI, "/api")[0]

	// Send url and username for first introduction in message 1
	handshakeToken, err := s.sendMsg1(serverURL, s.Username)
	if err != nil {
		return "", fmt.Errorf("failed to send message 1: %w", err)
	}

	// Parse handshakeToken from Server Response 1
	handshakeToken = s.getStringBetween(handshakeToken, "=", ",")

	// Create a random but strong id
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	clientNonce := fmt.Sprintf("%x", randomBytes)

	clientFirstMsg := fmt.Sprintf("n=%s,r=%s", s.Username, clientNonce)

	// Send url, Client's First Message, and the handshakeToken in message 2
	serverFirstMsg, err := s.sendMsg2(serverURL, clientFirstMsg, handshakeToken)
	if err != nil {
		return "", fmt.Errorf("failed to send message 2: %w", err)
	}

	// Parse Server Nonce, Server Salt, and Server Iterations from Server Response 2
	serverNonce := s.getStringBetween(serverFirstMsg, "r=", ",")
	serverSalt := s.getStringBetween(serverFirstMsg, "s=", ",")
	serverIterationsStr := strings.TrimPrefix(serverFirstMsg[strings.Index(serverFirstMsg, "i=")+2:], "")
	serverIterations, err := strconv.Atoi(serverIterationsStr)
	if err != nil {
		return "", fmt.Errorf("failed to parse server iterations: %w", err)
	}

	// PBKDF2 for the SHA-256 hashing algorithm
	saltedPassword, err := s.pbkdf2(s.Password, serverSalt, serverIterations, 32)
	if err != nil {
		return "", fmt.Errorf("failed to generate salted password: %w", err)
	}

	gs2Header := base64.StdEncoding.EncodeToString([]byte("n,,"))
	clientFinalNoPf := fmt.Sprintf("c=%s,r=%s", gs2Header, serverNonce)
	authMessage := fmt.Sprintf("%s,%s,%s", clientFirstMsg, serverFirstMsg, clientFinalNoPf)

	// HMAC for SHA-256 hashing for the Client Key
	clientKey := hmac.New(sha256.New, saltedPassword)
	clientKey.Write([]byte("Client Key"))
	clientKeyBytes := clientKey.Sum(nil)

	// Hash the Stored Key
	storedKey := sha256.Sum256(clientKeyBytes)

	// HMAC for SHA-256 hashing for the Client Signature
	clientSignature := hmac.New(sha256.New, storedKey[:])
	clientSignature.Write([]byte(authMessage))
	clientSignatureBytes := clientSignature.Sum(nil)

	// XOR Client Key with Client Signature
	clientProof := make([]byte, len(clientKeyBytes))
	for i := range clientKeyBytes {
		clientProof[i] = clientKeyBytes[i] ^ clientSignatureBytes[i]
	}

	clientFinalMsg := fmt.Sprintf("%s,p=%s", clientFinalNoPf, base64.StdEncoding.EncodeToString(clientProof))

	// Send url, Client's Final Message, and the handshakeToken in message 3
	serverSecondMsg, err := s.sendMsg3(serverURL, clientFinalMsg, handshakeToken)
	if err != nil {
		return "", fmt.Errorf("failed to send message 3: %w", err)
	}

	return serverSecondMsg, nil
}

// sendMsg1 sends the first SCRAM message
func (s *SkysparkClient) sendMsg1(serverURL, username string) (string, error) {
	authMsg := fmt.Sprintf("HELLO username=%s", s.base64URLEncode(username))
	
	req, err := http.NewRequest("GET", serverURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", authMsg)
	req.Header.Set("WWW-Authenticate", "SCRAM")

	resp, err := s.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Return the full response including headers
	return string(body), nil
}

// sendMsg2 sends the second SCRAM message
func (s *SkysparkClient) sendMsg2(serverURL, msg, handshakeToken string) (string, error) {
	authMsg := fmt.Sprintf("SCRAM handshakeToken=%s, data=%s", handshakeToken, s.base64URLEncode(msg))
	
	req, err := http.NewRequest("GET", serverURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", authMsg)
	req.Header.Set("WWW-Authenticate", "SCRAM")

	resp, err := s.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Extract data from response
	data := s.getStringBetween(string(body), "data=", ",")
	if data == "" {
		return "", fmt.Errorf("no data found in response")
	}

	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", fmt.Errorf("failed to decode data: %w", err)
	}

	return string(decoded), nil
}

// sendMsg3 sends the third SCRAM message
func (s *SkysparkClient) sendMsg3(serverURL, msg, handshakeToken string) (string, error) {
	authMsg := fmt.Sprintf("SCRAM handshakeToken=%s, data=%s", handshakeToken, s.base64URLEncode(msg))
	
	req, err := http.NewRequest("GET", serverURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", authMsg)

	resp, err := s.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Extract authToken from response
	authToken := s.getStringBetween(string(body), "authToken=", ",")
	if authToken == "" {
		return "", fmt.Errorf("no authToken found in response")
	}

	return authToken, nil
}

// getStringBetween extracts a substring between two delimiters
func (s *SkysparkClient) getStringBetween(str, start, end string) string {
	startIndex := strings.Index(str, start)
	if startIndex == -1 {
		return ""
	}
	startIndex += len(start)
	
	endIndex := strings.Index(str[startIndex:], end)
	if endIndex == -1 {
		return ""
	}
	
	return str[startIndex : startIndex+endIndex]
}

// base64URLEncode encodes a string using base64 URL-safe encoding
func (s *SkysparkClient) base64URLEncode(input string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(input))
	// Replace + with - and / with _
	encoded = strings.ReplaceAll(encoded, "+", "-")
	encoded = strings.ReplaceAll(encoded, "/", "_")
	// Remove padding
	encoded = strings.TrimRight(encoded, "=")
	return encoded
}

// pbkdf2 implements PBKDF2 with SHA-256
func (s *SkysparkClient) pbkdf2(password, salt string, iterations, keyLen int) ([]byte, error) {
	// Decode the base64 salt
	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to decode salt: %w", err)
	}

	// Use crypto/hmac for PBKDF2 implementation
	key := make([]byte, keyLen)
	block := 1
	offset := 0

	for offset < keyLen {
		// U1 = HMAC(password, salt || INT(block))
		h := hmac.New(sha256.New, []byte(password))
		h.Write(saltBytes)
		h.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := h.Sum(nil)

		// Copy U1 to output
		copyLen := len(u)
		if offset+copyLen > keyLen {
			copyLen = keyLen - offset
		}
		copy(key[offset:], u[:copyLen])
		offset += copyLen

		// U2 through Uc
		for i := 1; i < iterations; i++ {
			h := hmac.New(sha256.New, []byte(password))
			h.Write(u)
			u = h.Sum(nil)

			// XOR with previous U
			for j := range u {
				if offset+j < keyLen {
					key[offset+j] ^= u[j]
				}
			}
		}

		block++
	}

	return key, nil
}

// Curl performs authenticated HTTP requests
func (s *SkysparkClient) Curl(authToken, urlPath string, debug bool) (interface{}, error) {
	addr := s.URI + urlPath
	
	req, err := http.NewRequest("GET", addr, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("BEARER authToken=%s", authToken))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Clean the response body
	cleanBody := s.cleanResponse(string(body))

	if debug {
		return cleanBody, nil
	}

	var result interface{}
	if err := json.Unmarshal([]byte(cleanBody), &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	return result, nil
}

// cleanResponse cleans the response body by replacing certain patterns
func (s *SkysparkClient) cleanResponse(response string) string {
	// Find the body part (after headers)
	bodyStart := strings.Index(response, "\r\n\r\n")
	if bodyStart == -1 {
		bodyStart = strings.Index(response, "\n\n")
	}
	if bodyStart == -1 {
		return response
	}

	body := response[bodyStart:]

	// Replace patterns as in the PHP code
	replacements := map[string]string{
		`":"r:`: `":"`,
		`":"s:`: `":"`,
		`":"n:`: `":"`,
		`":"d:`: `":"`,
		`":"t:`: `":"`,
		`":"p:`: `":"@p:`,
	}

	for old, new := range replacements {
		body = strings.ReplaceAll(body, old, new)
	}

	return body
}

// HuckleberryAPI performs API calls with SCRAM authentication
func (s *SkysparkClient) HuckleberryAPI(function string, values []map[string]interface{}, debug bool) (interface{}, error) {
	authToken, err := s.Scram()
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate: %w", err)
	}

	var getValues []string
	var saveSSValues []string
	var query string

	if len(values) != 0 {
		for _, mainValues := range values {
			for key, value := range mainValues {
				if value != "" && value != nil && value != "null" {
					if key == "s" {
						encodedValue := url.QueryEscape(fmt.Sprintf("%v", value))
						getValues = append(getValues, "%22"+encodedValue+"%22")
						saveSSValues = append(saveSSValues, "%22"+fmt.Sprintf("%v", value)+"%22")
					} else {
						getValues = append(getValues, fmt.Sprintf("%v", value))
						saveSSValues = append(saveSSValues, fmt.Sprintf("%v", value))
					}
				} else {
					getValues = append(getValues, "null")
					saveSSValues = append(saveSSValues, "null")
				}
			}
		}
		query = function + "(" + strings.Join(getValues, ",") + ")"
	} else {
		query = function + "()"
	}

	if debug {
		fmt.Printf("Query: %s\n", query)
	}

	return s.Curl(authToken, query, debug)
} 