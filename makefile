.PHONY: test run-generators all-docs

run-generators: gen-mocks

install-tools:
	go install go.uber.org/mock/mockgen@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

gen-mocks:
	@echo "no known mock files"

lint:
	golangci-lint run -v

test:
	go test ./...

OUTPUT ?= "$(shell pwd)/didx509-toolkit"
build:
	go build -ldflags="-w -s" -o "${OUTPUT}"

docker:
	docker build -t nutsfoundation/go-didx509-toolkit:local .
