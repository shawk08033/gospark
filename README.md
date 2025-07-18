# gospark

A Go library for Skyspark API authentication using SCRAM (Salted Challenge Response Authentication Mechanism).

## Overview

This library provides a Go implementation of the SCRAM authentication protocol used by Skyspark servers. It translates the original PHP implementation into idiomatic Go code with proper error handling and modern Go practices.

## Features

- **SCRAM Authentication**: Complete implementation of SCRAM-SHA-256 authentication
- **PBKDF2 Key Derivation**: Secure password-based key derivation
- **HMAC-SHA256**: Cryptographic message authentication
- **HTTP Client**: Built-in HTTP client with timeout and proper headers
- **API Integration**: High-level API for making authenticated requests
- **Error Handling**: Comprehensive error handling with detailed error messages

## Installation

```bash
go get gospark
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    "gospark"
)

func main() {
    // Create a new client
    client := gospark.NewSkysparkClient(
        "https://your-skyspark-server.com/api",
        "your-username",
        "your-password",
    )

    // Perform authentication
    authToken, err := client.Scram()
    if err != nil {
        log.Fatalf("Authentication failed: %v", err)
    }

    fmt.Printf("Authenticated! Token: %s\n", authToken)
}
```

## API Reference

### NewSkysparkClient

Creates a new Skyspark client instance.

```go
func NewSkysparkClient(uri, username, password string) *SkysparkClient
```

**Parameters:**
- `uri`: The Skyspark server URI (e.g., "https://server.com/api")
- `username`: Your Skyspark username
- `password`: Your Skyspark password

### Scram

Performs SCRAM authentication and returns an auth token.

```go
func (s *SkysparkClient) Scram() (string, error)
```

**Returns:**
- `string`: Authentication token for subsequent requests
- `error`: Any error that occurred during authentication

### HuckleberryAPI

Makes authenticated API calls with automatic authentication handling.

```go
func (s *SkysparkClient) HuckleberryAPI(function string, values []map[string]interface{}, debug bool) (interface{}, error)
```

**Parameters:**
- `function`: The API function name to call
- `values`: Array of parameter maps (can be nil for no parameters)
- `debug`: Whether to enable debug output

**Returns:**
- `interface{}`: The API response (parsed JSON)
- `error`: Any error that occurred

### Curl

Makes authenticated HTTP requests directly.

```go
func (s *SkysparkClient) Curl(authToken, urlPath string, debug bool) (interface{}, error)
```

**Parameters:**
- `authToken`: Authentication token from Scram()
- `urlPath`: API endpoint path
- `debug`: Whether to return raw response instead of parsed JSON

## Usage Examples

### Basic Authentication

```go
client := gospark.NewSkysparkClient(
    "https://your-server.com/api",
    "username",
    "password",
)

authToken, err := client.Scram()
if err != nil {
    log.Fatal(err)
}
```

### API Call with Parameters

```go
result, err := client.HuckleberryAPI("myFunction", []map[string]interface{}{
    {
        "param1": "value1",
        "param2": 123,
        "s": "special_value", // URL encoded automatically
    },
}, false)
```

### API Call without Parameters

```go
result, err := client.HuckleberryAPI("simpleFunction", nil, false)
```

### Direct HTTP Request

```go
authToken, err := client.Scram()
if err != nil {
    log.Fatal(err)
}

response, err := client.Curl(authToken, "/endpoint", false)
```

## Error Handling

The library provides detailed error messages for various failure scenarios:

- Network connectivity issues
- Authentication failures
- Invalid server responses
- JSON parsing errors
- Cryptographic operation failures

## Security Features

- **Cryptographically Secure Random Numbers**: Uses `crypto/rand` for nonce generation
- **HMAC-SHA256**: For message authentication
- **PBKDF2**: For secure key derivation
- **Base64 URL-Safe Encoding**: For transport encoding
- **Timeout Protection**: HTTP client with configurable timeouts

## Dependencies

- `golang.org/x/crypto`: For cryptographic operations
- Standard library packages: `crypto/hmac`, `crypto/sha256`, `crypto/rand`, etc.

## License

This project is licensed under the same terms as the original project.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Example

See the `example/` directory for a complete working example.
Go library to call Skyspark Axon functions via API
