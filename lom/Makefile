GO := /usr/local/go/bin/go
GOFMT := $(GO)fmt
INSTALL := /usr/bin/install

BUILD_DIR := build
BIN_DIR := $(BUILD_DIR)/bin
TEST_DIR := $(BUILD_DIR)/test

# Set to -v for verbose o/p. May set it in Env before calling Make
# export TEST_FLAG=-v in shell before calling make or
# TEST_FLAG=-v make all

export GO111MODULE=on

SRC_FILES=$(shell find . -name '*.go' | grep -v '_test.go' | grep -v '/tests/')
TEST_FILES=$(wildcard *_test.go)

# Binaries used in LoM system
ENGINE_BIN := $(BIN_DIR)/LoMEngine
PLUGIN_MANAGER_BIN := $(BIN_DIR)/pluginmgr

# Test binaries/flags
LIB_TEST = $(TEST_DIR)/LibTested
ENGINE_TEST = $(TEST_DIR)/EngineTested
PLUGIN_MANAGER_TEST = $(TEST_DIR)/PluginManagerTested
SONIC_DBCLIENT_TEST =$(TEST_DIR)/SonicDbClientTested
SONIC_LINK_CRC_TEST = $(TEST_DIR)/SonicLinkCrcTested
PLUGINS_COMMON_TEST = $(TEST_DIR)/PluginsCommonTested

format_code:
	@if which $(GOFMT) > /dev/null; then \
		$(GOFMT) -l ./ | xargs -I {} $(GOFMT) -w {}; \
	else \
		echo "Installing gofmt..."; \
		$(GO) get golang.org/x/tools/cmd/gofmt; \
	fi
	@if which sed > /dev/null; then \
		sed -i 's/\t/    /g' $$(find ./ -type f -name '*.go'); \
	else \
		echo "Installing sed..."; \
		apt-get update && apt-get install -y sed; \
	fi

# Define the file coverage extraction function
define extract_file_coverage
	@echo "*******************************************************"
	@echo "Extracting file coverages:"
	@sed -n 's/.*<option value="[^"]\+">\([^<]\+\).* (\([^)]\+\%.*\)<\/option>.*/\1 (\2)/p' $(1)
	@echo "*******************************************************"
endef

.PHONY: all clean

all: | format_code $(ENGINE_BIN) $(PLUGIN_MANAGER_BIN) $(LIB_TEST) $(ENGINE_TEST) $(PLUGIN_MANAGER_TEST) $(SONIC_DBCLIENT_TEST) $(SONIC_LINK_CRC_TEST) $(PLUGINS_COMMON_TEST)

$(ENGINE_BIN): $(SRC_FILES) $(TEST_FILES)
	mkdir -p $(BIN_DIR)
	$(GO) build  -o $@ lom/src/engine
	$(info "Built lom-engine")

$(PLUGIN_MANAGER_BIN): $(SRC_FILES) $(TEST_FILES)
	mkdir -p $(BIN_DIR)
	$(GO) build -o $@ lom/src/pluginmgr
	$(info "Built plugin manager")


$(LIB_TEST): $(SRC_FILES) $(TEST_FILES)
	mkdir -p $(TEST_DIR)
	${GO} test $(TEST_FLAG) -coverprofile=$(TEST_DIR)/LibCoverprofile.out \
		-coverpkg lom/src/lib/lomipc,lom/src/lib/lomcommon \
		-covermode=atomic ./src/lib/lib_test ./src/lib/lib_test/config || (echo "LibTest failed $$?"; exit 1)
	${GO} tool cover -html=$(TEST_DIR)/LibCoverprofile.out -o $(TEST_DIR)/LibCoverprofile.html
	$(call extract_file_coverage,$(TEST_DIR)/LibCoverprofile.html)
	touch $@

$(ENGINE_TEST): $(SRC_FILES) $(TEST_FILES)
	mkdir -p $(TEST_DIR)
	${GO} test $(TEST_FLAG) -coverprofile=$(TEST_DIR)/EngineCoverprofile.out \
		-coverpkg lom/src/engine \
		-covermode=atomic lom/src/engine || (echo "EngineTest failed $$?"; exit 1)
	${GO} tool cover -html=$(TEST_DIR)/EngineCoverprofile.out -o $(TEST_DIR)/EngineCoverprofile.html
	$(call extract_file_coverage,$(TEST_DIR)/EngineCoverprofile.html)
	touch $@

$(PLUGIN_MANAGER_TEST): $(SRC_FILES) $(TEST_FILES)
	mkdir -p $(TEST_DIR)
	${GO} test $(TEST_FLAG) -coverprofile=$(TEST_DIR)/PluginManagerCoverprofile.out \
		-coverpkg lom/src/pluginmgr/pluginmgr_common \
		-covermode=atomic ./src/pluginmgr/pluginmgr_common  || (echo "Plugin manager test failed $$?"; exit 1)
	${GO} tool cover -html=$(TEST_DIR)/PluginManagerCoverprofile.out -o $(TEST_DIR)/PluginManagerCoverprofile.html
	$(call extract_file_coverage,$(TEST_DIR)/PluginManagerCoverprofile.html)
	touch $@

$(SONIC_DBCLIENT_TEST): $(SRC_FILES) $(TEST_FILES)
	mkdir -p $(TEST_DIR)
	${GO} test $(TEST_FLAG) -coverprofile=$(TEST_DIR)/SonicDbClientCoverprofile.out \
		-coverpkg lom/src/plugins/sonic/client/dbclient \
		-covermode=atomic lom/src/plugins/sonic/client/dbclient || (echo "SonicDbClient Test failed $$?"; exit 1)
	${GO} tool cover -html=$(TEST_DIR)/SonicDbClientCoverprofile.out -o $(TEST_DIR)/SonicDbClientCoverprofile.html
	$(call extract_file_coverage,$(TEST_DIR)/SonicDbClientCoverprofile.html)
	touch $@

$(SONIC_LINK_CRC_TEST): $(SRC_FILES) $(TEST_FILES)
	mkdir -p $(TEST_DIR)
	${GO} test $(TEST_FLAG) -coverprofile=$(TEST_DIR)/SonicLinkCrcCoverprofile.out \
                -coverpkg lom/src/plugins/sonic/plugin/detection/link/linkcrc \
                -covermode=atomic lom/src/plugins/sonic/plugin/detection/link/linkcrc || (echo "SonicLinkCrc plugin Test failed $$?"; exit 1)
	${GO} tool cover -html=$(TEST_DIR)/SonicLinkCrcCoverprofile.out -o $(TEST_DIR)/SonicLinkCrcCoverprofile.html
	$(call extract_file_coverage,$(TEST_DIR)/SonicLinkCrcCoverprofile.html)
	touch $@
	
$(PLUGINS_COMMON_TEST): $(SRC_FILES) $(TEST_FILES)
	mkdir -p $(TEST_DIR)
	${GO} test $(TEST_FLAG) -coverprofile=$(TEST_DIR)/PluginsCommonCoverprofile.out \
		-coverpkg lom/src/plugins/plugins_common \
                -covermode=atomic lom/src/plugins/plugins_common || (echo "PluginsCommon Tests failed $$?"; exit 1)
	${GO} tool cover -html=$(TEST_DIR)/PluginsCommonCoverprofile.out -o $(TEST_DIR)/PluginsCommonCoverprofile.html
	$(call extract_file_coverage,$(TEST_DIR)/PluginsCommonCoverprofile.html)
	touch $@

clean:
	rm -rf $(BUILD_DIR)
