GO_CMD?=go
BINNAME=hcltm
GOPATH?=$$($(GO_CMD) env GOPATH)
EXTERNAL_TOOLS=\
	golang.org/x/tools/cmd/goimports \
	github.com/mitchellh/gox
GOFMT_FILES?=$$(find . -name '*.go')
PKG_TARGET="linux/amd64 darwin/amd64"

default: help

image: ## Create the docker image from the Dockerfile
	@docker build -t $(BINNAME):latest .

dev: ## Build hcltm and copy to your GOPATH/bin
	$(GO_CMD) build -o ${BINNAME} ./cmd/hcltm
	@echo "Copying ${BINNAME} file to ${GOPATH}/bin/${BINNAME}"
	@cp ${BINNAME} ${GOPATH}/bin/${BINNAME}

pkg-linux: ## Build packages with gox
	gox \
		-osarch="linux/amd64" \
		-output="out/{{.OS}}_{{.Arch}}/${BINNAME}" \
		-gocmd=${GO_CMD} \
		-cgo \
		./cmd/hcltm
	cd out/linux_amd64 && tar -zcvf ../hcltm-linux-amd64.tar.gz hcltm

pkg-osx: ## Build packages with gox
	gox \
		-osarch="darwin/amd64" \
		-output="out/{{.OS}}_{{.Arch}}/${BINNAME}" \
		-gocmd=${GO_CMD} \
		-cgo \
		./cmd/hcltm
	cd out/darwin_amd64 && tar -zcvf ../hcltm-darwin-amd64.tar.gz hcltm

fmt: ## Checks go formatting
	goimports -w $(GOFMT_FILES)

install: ## Pretty similar to dev
	$(GO_CMD) install ./cmd/hcltm

bootstrap: ## Install build dependencies
	@for tool in $(EXTERNAL_TOOLS) ; do \
		echo "Installing/Updating $$tool" ; \
		GO111MODULE=off $(GO_CMD) get -u $$tool; \
	done

vet: ## Run go vet
	$(GO_CMD) vet ./...

test: ## Run go test
	$(GO_CMD) test ./...

testvet: vet test ## Run go vet and test

testcover: ## Run go test and go tool cover
	$(GO_CMD) test -coverprofile=cover.txt ./...; go tool cover -html=cover.txt

help: ## Output make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: dev help
