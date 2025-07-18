.PHONY: test build clean example install

# Default target
all: test build

# Run tests
test:
	go test -v

# Run tests with coverage
test-coverage:
	go test -v -cover

# Run benchmarks
bench:
	go test -bench=.

# Build the library
build:
	go build

# Build the example
example:
	go build -o bin/example example/main.go

# Install the library
install:
	go install

# Clean build artifacts
clean:
	rm -rf bin/
	go clean

# Run the example (requires building first)
run-example: example
	./bin/example

# Format code
fmt:
	go fmt ./...

# Run linter
lint:
	golangci-lint run

# Generate documentation
docs:
	godoc -http=:6060

# Check for security vulnerabilities
security:
	gosec ./...

# Update dependencies
deps:
	go mod tidy
	go mod download

# Show module info
info:
	go mod graph
	go list -m all 