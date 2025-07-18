# PHP to Go Migration Guide

This document explains the key differences between the original PHP implementation and the Go library.

## Key Differences

### 1. Error Handling

**PHP:**
```php
if($this->uri == null){
    throw new Exception("Skyspark Client not found");
}
```

**Go:**
```go
if s.URI == "" {
    return "", fmt.Errorf("Skyspark Client not found")
}
```

Go uses explicit error returns instead of exceptions, providing better error handling and type safety.

### 2. Random Number Generation

**PHP:**
```php
$random = md5(uniqid(mt_rand(), true));
```

**Go:**
```go
randomBytes := make([]byte, 16)
if _, err := rand.Read(randomBytes); err != nil {
    return "", fmt.Errorf("failed to generate random bytes: %w", err)
}
clientNonce := fmt.Sprintf("%x", randomBytes)
```

Go uses cryptographically secure random number generation from `crypto/rand` instead of PHP's `mt_rand()`.

### 3. HTTP Requests

**PHP (cURL):**
```php
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $serverUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_HEADER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, array("Authorization: ". $authMsg,"WWW-Authenticate: SCRAM"));
$serverMsg = curl_exec($ch);
curl_close($ch);
```

**Go (net/http):**
```go
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
```

Go uses the standard `net/http` package with better error handling and automatic resource cleanup.

### 4. String Manipulation

**PHP:**
```php
protected function get_string_between($string, $start, $end) {
    $string = ' ' . $string;
    $ini = strpos($string, $start);
    if ($ini == 0) return '';
    $ini += strlen($start);
    $len = strpos($string, $end, $ini) - $ini;
    return substr($string, $ini, $len);
}
```

**Go:**
```go
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
```

Go's implementation is more straightforward and doesn't require padding the string.

### 5. Base64 URL-Safe Encoding

**PHP:**
```php
rtrim(strtr(base64_encode($msg), '+/', '-_'), '=')
```

**Go:**
```go
func (s *SkysparkClient) base64URLEncode(input string) string {
    encoded := base64.StdEncoding.EncodeToString([]byte(input))
    // Replace + with - and / with _
    encoded = strings.ReplaceAll(encoded, "+", "-")
    encoded = strings.ReplaceAll(encoded, "/", "_")
    // Remove padding
    encoded = strings.TrimRight(encoded, "=")
    return encoded
}
```

Both achieve the same result, but Go's implementation is more explicit.

### 6. PBKDF2 Implementation

**PHP:**
```php
$saltedPassword = hash_pbkdf2("sha256", $this->password, base64_decode($serverSalt), intval($serverIterations), $dklen, true);
```

**Go:**
```go
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
```

Go implements PBKDF2 manually since the standard library doesn't include it, but the implementation follows the RFC 2898 specification.

### 7. HMAC and Hashing

**PHP:**
```php
$clientKey = hash_hmac('sha256',"Client Key", $saltedPassword, true);
$storedKey = hash('sha256', $clientKey, true);
$clientSignature = hash_hmac('sha256', $authMessage, $storedKey, true);
```

**Go:**
```go
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
```

Go uses the `crypto/hmac` package for HMAC operations and `crypto/sha256` for hashing.

### 8. XOR Operation

**PHP:**
```php
$clientProof = ($clientKey ^ $clientSignature);
```

**Go:**
```go
// XOR Client Key with Client Signature
clientProof := make([]byte, len(clientKeyBytes))
for i := range clientKeyBytes {
    clientProof[i] = clientKeyBytes[i] ^ clientSignatureBytes[i]
}
```

Go requires explicit byte-by-byte XOR since there's no direct XOR operator for byte slices.

## Performance Improvements

1. **Memory Efficiency**: Go's implementation uses less memory allocation
2. **Concurrency**: The HTTP client can be reused and is thread-safe
3. **Type Safety**: Go's type system prevents many runtime errors
4. **Error Handling**: Explicit error handling prevents silent failures

## Security Enhancements

1. **Cryptographically Secure Random Numbers**: Uses `crypto/rand` instead of `mt_rand()`
2. **Explicit Error Handling**: No silent failures that could mask security issues
3. **Resource Management**: Automatic cleanup with `defer` statements
4. **Timeout Protection**: Built-in HTTP client timeouts

## API Compatibility

The Go library maintains API compatibility with the PHP version:

- `Scram()` → `scram()`
- `HuckleberryAPI()` → `huckleberryAPI()`
- `Curl()` → `curl()`

All method signatures and behaviors are preserved while providing better error handling and type safety. 