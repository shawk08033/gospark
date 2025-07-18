package main

import (
	"fmt"
	"log"

	"gospark"
)

func main() {
	// Create a new Skyspark client
	client := gospark.NewSkysparkClient(
		"https://your-skyspark-server.com/api", // Replace with your server URL
		"your-username",                        // Replace with your username
		"your-password",                        // Replace with your password
	)

	// Example 1: Perform SCRAM authentication
	authToken, err := client.Scram()
	if err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}
	fmt.Printf("Authentication successful! Auth token: %s\n", authToken)

	// Example 2: Make an API call with authentication
	// This will automatically handle authentication
	result, err := client.HuckleberryAPI("yourFunction", []map[string]interface{}{
		{
			"param1": "value1",
			"param2": "value2",
			"s":      "special_value", // This will be URL encoded
		},
	}, false) // Set to true for debug output

	if err != nil {
		log.Fatalf("API call failed: %v", err)
	}

	fmt.Printf("API result: %+v\n", result)

	// Example 3: Make a simple API call without parameters
	simpleResult, err := client.HuckleberryAPI("simpleFunction", nil, false)
	if err != nil {
		log.Fatalf("Simple API call failed: %v", err)
	}

	fmt.Printf("Simple API result: %+v\n", simpleResult)

	// Example 4: Make an authenticated HTTP request directly
	// First authenticate
	authToken, err = client.Scram()
	if err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	// Then make a direct request
	response, err := client.Curl(authToken, "/your-endpoint", false)
	if err != nil {
		log.Fatalf("Direct request failed: %v", err)
	}

	fmt.Printf("Direct request result: %+v\n", response)
} 