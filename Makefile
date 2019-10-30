SRC_DIR=$(shell pwd)
BUILD_DIR=$(SRC_DIR)/build
BIN_DIR=$(BUILD_DIR)/bin
K8SNIFF_EXE=$(BIN_DIR)/k8sniff
GOSRC=$(GOPATH)/src
K8SNIFF_SRC_DIR=$(GOSRC)/github.com/kubermatic/k8sniff
DEP_SRC=$(GOSRC)/github.com/golang/dep
DEP_EXE=$(DEP_SRC)/cmd/dep/dep
VENDOR_DIR=$(K8SNIFF_SRC_DIR)/vendor

GO_DEPS := \
	$(GOSRC)/github.com/golang/glog \
	$(GOSRC)/github.com/prometheus/client_golang/prometheus \
	$(GOSRC)/github.com/platform9/cnxmd/pkg/cnxmd

$(GO_DEPS): $(GOPATH_DIR)
	go get $(subst $(GOSRC)/,,$@)

# Override with your own Docker registry tag(s)
K8SNIFF_IMAGE_TAG ?= platform9systems/k8sniff
K8SNIFF_DEVEL_IMAGE_TAG ?= platform9systems/k8sniff-devel

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
	rm -rf $(BUILD_DIR) $(DEP_SRC) $(VENDOR_DIR) $(GO_DEPS)

k8sniff-clean:
	rm -f $(K8SNIFF_EXE)

k8sniff-image: $(K8SNIFF_EXE)
	docker build --tag $(K8SNIFF_IMAGE_TAG) -f support/Dockerfile .
	docker push $(K8SNIFF_IMAGE_TAG)

k8sniff-image-devel: $(K8SNIFF_EXE)
	docker build --tag $(K8SNIFF_DEVEL_IMAGE_TAG) -f support/k8sniff-devel/Dockerfile .
	docker push $(K8SNIFF_DEVEL_IMAGE_TAG)
