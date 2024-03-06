GO_CMD?=go
BINNAME=threatcl
DOCKERNAME=xntrik/threatcl
DOCKERPLATFORM="linux/amd64,linux/arm64"
GOPATH?=$$($(GO_CMD) env GOPATH)
EXTERNAL_TOOLS=\
	golang.org/x/tools/cmd/goimports
GOFMT_FILES?=$$(find . -name '*.go')
LINUX_PKG_TARGETS="linux/amd64"
MACOS_PKG_TARGETS="darwin/amd64"

default: help

image: ## Create the docker image from the Dockerfile
	@docker build -t $(BINNAME):latest .

imagepush: check-ver-env check-tag-env ## Create a fresh docker image and push to the configured repo
	@docker buildx build --rm --force-rm --platform $(DOCKERPLATFORM) --push -t $(DOCKERNAME):$(TAG) -t $(DOCKERNAME):$(VERSION) .

check-ver-env:
ifndef VERSION
	$(error VERSION is undefined)
endif

check-tag-env:
ifndef TAG
	$(error TAG is undefined)
endif

build: ## Build threatcl and copy to your GOPATH/bin
	$(GO_CMD) build -o ${BINNAME} ./cmd/threatcl

fmt: ## Checks go formatting
	goimports -w $(GOFMT_FILES)

install: ## Pretty similar to dev
	$(GO_CMD) install ./cmd/threatcl

bootstrap: ## Install build dependencies
	@for tool in $(EXTERNAL_TOOLS) ; do \
		echo "Installing/Updating $$tool" ; \
		$(GO_CMD) install $$tool; \
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

.PHONY: build help image imagepush fmt install bootstrap vet test testvet testcover check-tag-env check-ver-env
