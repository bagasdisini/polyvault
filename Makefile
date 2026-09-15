.PHONY: build test clean lint run init

# Build variables
BINARY_NAME=polyvault
VERSION?=dev
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_FLAGS=-ldflags "-X github.com/bagasdisini/polyvault/cmd/version=$(VERSION) -X github.com/bagasdisini/polyvault/cmd/commit=$(COMMIT)"

# Go variables
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOVET=$(GOCMD) vet
GOMOD=$(GOCMD) mod

## build: Build the binary
build:
	$(GOBUILD) $(BUILD_FLAGS) -o $(BINARY_NAME) .

## test: Run all tests
test:
	$(GOTEST) -v -count=1 ./...

## test-short: Run tests in short mode
test-short:
	$(GOTEST) -short ./...

## test-coverage: Run tests with coverage
test-coverage:
	$(GOTEST) -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

## bench: Run benchmarks
bench:
	$(GOTEST) -bench=. -benchmem ./...

## lint: Run go vet
lint:
	$(GOVET) ./...

## tidy: Run go mod tidy
tidy:
	$(GOMOD) tidy

## clean: Remove build artifacts
clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME).exe
	rm -f coverage.out coverage.html

## run: Build and run the server
run: build
	./$(BINARY_NAME) server

## init: Initialize a new vault
init: build
	./$(BINARY_NAME) init
