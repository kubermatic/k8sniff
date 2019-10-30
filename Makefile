SRC_DIR=$(shell pwd)
BUILD_DIR=$(SRC_DIR)/build
BIN_DIR=$(BUILD_DIR)/bin
K8SNIFF_EXE=$(BIN_DIR)/k8sniff
GOSRC=$(GOPATH)/src
K8SNIFF_SRC_DIR=$(GOSRC)/github.com/kubermatic/k8sniff
DEP_SRC=$(GOSRC)/github.com/golang/dep
DEP_EXE=$(DEP_SRC)/cmd/dep/dep
VENDOR_DIR=$(K8SNIFF_SRC_DIR)/vendor

IMAGE_NAME := k8sniff

# Override with your own Docker registry tag(s)
REPO_TAG ?= platform9/$(IMAGE_NAME)

VERSION ?= 1.0.0
BUILD_NUMBER ?= 000
BUILD_ID := $(BUILD_NUMBER)
IMAGE_TAG ?= $(VERSION)-$(BUILD_ID)
FULL_TAG := $(REPO_TAG):$(IMAGE_TAG)
TAG_FILE := $(BUILD_DIR)/container-full-tag

GO_DEPS := \
	$(GOSRC)/github.com/golang/glog \
	$(GOSRC)/github.com/prometheus/client_golang/prometheus \
	$(GOSRC)/github.com/platform9/cnxmd/pkg/cnxmd

$(GO_DEPS): $(GOPATH_DIR)
	go get $(subst $(GOSRC)/,,$@)

$(DEP_SRC):
	go get -u github.com/golang/dep/cmd/dep

$(DEP_EXE): | $(DEP_SRC)
	cd $(DEP_SRC)/cmd/dep && go build

$(BIN_DIR):
	mkdir -p $@

$(VENDOR_DIR): $(DEP_EXE)
	$(DEP_EXE) ensure

local-k8sniff:
	cd $(SRC_DIR)/cmd/k8sniff && go build -o $${GOPATH}/bin/k8sniff

local-k8sniff-dbg:
	cd $(SRC_DIR)/cmd/k8sniff && go build -gcflags='-N -l' -o $${GOPATH}/bin/k8sniff-dbg

$(K8SNIFF_EXE): | $(BIN_DIR) $(GO_DEPS) $(VENDOR_DIR)
	go build -o $(K8SNIFF_EXE)

k8sniff: $(K8SNIFF_EXE)

clean:
	rm -rf $(BUILD_DIR) $(DEP_SRC) $(VENDOR_DIR) $(TAG_FILE)

k8sniff-clean:
	rm -f $(K8SNIFF_EXE)

$(TAG_FILE): $(K8SNIFF_EXE)
	docker build --tag $(FULL_TAG) -f support/Dockerfile .
	echo -n $(FULL_TAG) > $@

image: $(TAG_FILE)

push: $(TAG_FILE)
	docker push `cat $(TAG_FILE)` && docker rmi `cat $(TAG_FILE)`
