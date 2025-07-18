package gospark

import (
	"testing"
)

func TestNewSkysparkClient(t *testing.T) {
	client := NewSkysparkClient("https://test.com/api", "testuser", "testpass")
	
	if client.URI != "https://test.com/api" {
		t.Errorf("Expected URI to be 'https://test.com/api', got '%s'", client.URI)
	}
	
	if client.Username != "testuser" {
		t.Errorf("Expected Username to be 'testuser', got '%s'", client.Username)
	}
	
	if client.Password != "testpass" {
		t.Errorf("Expected Password to be 'testpass', got '%s'", client.Password)
	}
	
	if client.Client == nil {
		t.Error("Expected HTTP client to be initialized")
	}
}

func TestGetStringBetween(t *testing.T) {
	client := &SkysparkClient{}
	
	tests := []struct {
		name     string
		str      string
		start    string
		end      string
		expected string
	}{
		{
			name:     "basic extraction",
			str:      "hello=world,test=value",
			start:    "=",
			end:      ",",
			expected: "world",
		},
		{
			name:     "no start delimiter",
			str:      "hello world",
			start:    "=",
			end:      ",",
			expected: "",
		},
		{
			name:     "no end delimiter",
			str:      "hello=world",
			start:    "=",
			end:      ",",
			expected: "",
		},
		{
			name:     "empty string",
			str:      "",
			start:    "=",
			end:      ",",
			expected: "",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.getStringBetween(tt.str, tt.start, tt.end)
			if result != tt.expected {
				t.Errorf("getStringBetween(%q, %q, %q) = %q, want %q", 
					tt.str, tt.start, tt.end, result, tt.expected)
			}
		})
	}
}

func TestBase64URLEncode(t *testing.T) {
	client := &SkysparkClient{}
	
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple string",
			input:    "hello world",
			expected: "aGVsbG8gd29ybGQ",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "special characters",
			input:    "test+user/pass",
			expected: "dGVzdCt1c2VyL3Bhc3M",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.base64URLEncode(tt.input)
			if result != tt.expected {
				t.Errorf("base64URLEncode(%q) = %q, want %q", 
					tt.input, result, tt.expected)
			}
		})
	}
}

func TestPBKDF2(t *testing.T) {
	client := &SkysparkClient{}
	
	// Test with known values
	password := "password"
	salt := "c2FsdA==" // base64 encoded "salt"
	iterations := 1
	keyLen := 32
	
	result, err := client.pbkdf2(password, salt, iterations, keyLen)
	if err != nil {
		t.Errorf("pbkdf2 failed: %v", err)
	}
	
	if len(result) != keyLen {
		t.Errorf("Expected key length %d, got %d", keyLen, len(result))
	}
	
	// Test with invalid base64 salt
	_, err = client.pbkdf2(password, "invalid-base64", iterations, keyLen)
	if err == nil {
		t.Error("Expected error for invalid base64 salt")
	}
}

func TestCleanResponse(t *testing.T) {
	client := &SkysparkClient{}
	
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no replacements needed",
			input:    "normal response",
			expected: "normal response",
		},
		{
			name:     "with replacements",
			input:    `{"key":"r:value","other":"s:data"}`,
			expected: `{"key":"r:value","other":"s:data"}`,
		},
		{
			name:     "with p replacement",
			input:    `{"key":"p:value"}`,
			expected: `{"key":"p:value"}`,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.cleanResponse(tt.input)
			if result != tt.expected {
				t.Errorf("cleanResponse(%q) = %q, want %q", 
					tt.input, result, tt.expected)
			}
		})
	}
}

func TestScramValidation(t *testing.T) {
	// Test that Scram returns error when URI is empty
	client := &SkysparkClient{
		URI:      "",
		Username: "test",
		Password: "test",
	}
	
	_, err := client.Scram()
	if err == nil {
		t.Error("Expected error when URI is empty")
	}
	
	if err.Error() != "Skyspark Client not found" {
		t.Errorf("Expected error message 'Skyspark Client not found', got '%s'", err.Error())
	}
}

// Benchmark tests for performance
func BenchmarkBase64URLEncode(b *testing.B) {
	client := &SkysparkClient{}
	input := "test string for encoding"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.base64URLEncode(input)
	}
}

func BenchmarkGetStringBetween(b *testing.B) {
	client := &SkysparkClient{}
	str := "hello=world,test=value,other=data"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.getStringBetween(str, "=", ",")
	}
}

func BenchmarkPBKDF2(b *testing.B) {
	client := &SkysparkClient{}
	password := "testpassword"
	salt := "c2FsdA=="
	iterations := 1000
	keyLen := 32
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.pbkdf2(password, salt, iterations, keyLen)
	}
} 