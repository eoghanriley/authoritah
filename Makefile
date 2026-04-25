.PHONY: build test lint fmt vet clean

BINARY_NAME=authoritah
BUILD_DIR=./build/bin
CMD_DIR=./cmd/authoritah

build:
	go build -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)

test:
	go test ./...

lint:
	staticcheck ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

clean:
	rm -rf $(BUILD_DIR)

tidy:
	go mod tidy
