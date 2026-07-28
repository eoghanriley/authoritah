.PHONY: build test test-unit test-integration lint fmt vet clean tidy

BINARY_NAME=authoritah
BUILD_DIR=./build/bin
CMD_DIR=./cmd/authoritah

build:
	go build -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)

test: test-unit test-integration

test-unit:
	go test -race -count=1 -failfast ./pkg/... ./cmd/... ./internal/...

test-integration:
	go test -race -count=1 -failfast -v ./tests/integration/...

lint:
	staticcheck ./...

fmt:
	gofmt -w .

fmt-check:
	@UNFORMATTED=$$(gofmt -l .); \
	if [ -n "$$UNFORMATTED" ]; then \
		echo "Unformatted files (run make fmt):"; \
		echo "$$UNFORMATTED"; \
		exit 1; \
	fi

vet:
	go vet ./...

clean:
	rm -rf $(BUILD_DIR)

tidy:
	go mod tidy
