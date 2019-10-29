
SRC_DIR=$(shell pwd)
BUILD_DIR=$(SRC_DIR)/build
BIN_DIR=$(BUILD_DIR)/bin
BUILD_SRC_DIR=$(BUILD_DIR)/src/github.com/kubermatic
K8SNIFF_SRC_DIR=$(BUILD_SRC_DIR)/k8sniff
K8SNIFF_EXE=$(BIN_DIR)/k8sniff

GO_DEPS := \
	$(GOSRC)/github.com/prometheus/client_golang \
	$(GOSRC)/github.com/platform9/cnxmd \
	$(GOSRC)/github.com/golang/glog

$(GO_DEPS): $(GOPATH_DIR)
	go get $(subst $(GOSRC)/,,$@)

# Override with your own Docker registry tag(s)
K8SNIFF_IMAGE_TAG ?= platform9systems/k8sniff
K8SNIFF_DEVEL_IMAGE_TAG ?= platform9systems/k8sniff-devel

$(BUILD_SRC_DIR):
	mkdir -p $@

$(K8SNIFF_SRC_DIR): | $(BUILD_SRC_DIR)
	mkdir -p $@
	cp -a $(SRC_DIR)/{cmd,pkg} $@/

$(BIN_DIR):
	mkdir -p $@

local-k8sniff:
	cd $(SRC_DIR)/cmd/k8sniff && go build -o $${GOPATH}/bin/k8sniff

local-k8sniff-dbg:
	cd $(SRC_DIR)/cmd/k8sniff && go build -gcflags='-N -l' -o $${GOPATH}/bin/k8sniff-dbg

$(K8SNIFF_EXE): | $(BIN_DIR) $(GO_DEPS)
	go build -o $(K8SNIFF_EXE)

k8sniff: $(K8SNIFF_EXE)

clean:
	rm -rf $(BUILD_DIR)

k8sniff-clean:
	rm -f $(K8SNIFF_EXE)

k8sniff-image: $(K8SNIFF_EXE)
	docker build --tag $(K8SNIFF_IMAGE_TAG) -f support/Dockerfile .
	docker push $(K8SNIFF_IMAGE_TAG)

k8sniff-image-devel: $(K8SNIFF_EXE)
	docker build --tag $(K8SNIFF_DEVEL_IMAGE_TAG) -f support/k8sniff-devel/Dockerfile .
	docker push $(K8SNIFF_DEVEL_IMAGE_TAG)
