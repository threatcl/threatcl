GO_CMD?=go
BINNAME=hcltm
DOCKERNAME=xntrik/hcltm
DOCKERPLATFORM="linux/amd64,linux/arm64"
GOPATH?=$$($(GO_CMD) env GOPATH)
EXTERNAL_TOOLS=\
	golang.org/x/tools/cmd/goimports \
	github.com/mitchellh/gox
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

dev: ## Build hcltm and copy to your GOPATH/bin
	$(GO_CMD) build -o ${BINNAME} ./cmd/hcltm
	@echo "Copying ${BINNAME} file to ${GOPATH}/bin/${BINNAME}"
	@cp ${BINNAME} ${GOPATH}/bin/${BINNAME}

pkg-linux: ## Build packages with gox on linux
	gox \
		-osarch=${LINUX_PKG_TARGETS} \
		-output="out/{{.OS}}_{{.Arch}}/${BINNAME}" \
		-gocmd=${GO_CMD} \
		-cgo \
		./cmd/hcltm
	cd out/linux_amd64 && tar -zcvf ../hcltm-linux-amd64.tar.gz hcltm

pkg-osx: ## Build packages with gox
	gox \
		-osarch=${MACOS_PKG_TARGETS} \
		-output="out/{{.OS}}_{{.Arch}}/${BINNAME}" \
		-gocmd=${GO_CMD} \
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

.PHONY: dev help image imagepush pkg-linux pkg-osx fmg install bootstrap vet test testvet testcover check-tag-env check-ver-env
