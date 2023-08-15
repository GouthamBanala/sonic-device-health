# Select bash for commands
.ONESHELL:
SHELL = /bin/bash
.SHELLFLAGS += -e
USER = $(shell id -un)
UID = $(shell id -u)
GUID = $(shell id -g)


GO := /usr/local/go1.20.3/go/bin/go

GOFMT := $(GO)fmt
INSTALL := /usr/bin/install

BUILD_DIR := build
LIB_DIR := $(BUILD_DIR)/lib
BIN_DIR := $(BUILD_DIR)/bin
TEST_DIR := $(BUILD_DIR)/test
INTEGRATION_TEST_DIR := integration_test

# Set to -v for verbose o/p. May set it in Env before calling Make
# export TEST_FLAG=-v in shell before calling make or
# TEST_FLAG=-v make all

# TEST_FLAG := "-v" Set it for verbose test o/p

ifeq "${TEST_FLAG}" "-v"
PYTEST_VERBOSE= --addopts "-s"
endif

LIB_TEST_FLAGS = -v

export GO111MODULE=on
export LOM_LIB_PATH=$(PWD)/build/lib

SRC_FILES=$(shell find . -name '*.go' | grep -v '_test.go' | grep -v '/tests/')
PY_FILES=$(shell find . -name '*.py' | grep -v '_test.py' | grep -v '/tests/')
TEST_FILES=$(shell find . -name '*test.go')

CMN_C_LIB_FILES=src/lib/clib/lom_clib.go
CMN_C_LIB_FLAG=-buildmode=c-shared
CMN_C_LIB=$(BUILD_DIR)/lib/cmn_c_lib.so

# Binaries used in LoM system
ENGINE_BIN := $(BIN_DIR)/LoMEngine
PLUGIN_MANAGER_BIN := $(BIN_DIR)/LoMPluginMgr

# Test binaries/flags
LIB_TEST = $(TEST_DIR)/LibTested
ENGINE_TEST = $(TEST_DIR)/EngineTested
PLUGIN_MANAGER_TEST = $(TEST_DIR)/PluginManagerTested
SONIC_DBCLIENT_TEST =$(TEST_DIR)/SonicDbClientTested
PY_TEST = $(TEST_DIR)/pytested
SONIC_LINK_CRC_TEST = $(TEST_DIR)/SonicLinkCrcTested
PLUGINS_COMMON_TEST = $(TEST_DIR)/PluginsCommonTested
SONIC_LINK_CRC_MOCKER_TEST = $(TEST_DIR)/linkcrc_mocker
INTEGRATION_TEST = $(TEST_DIR)/integration_test

.NOTPARALLEL:

format_code:
	@if ! which sed > /dev/null; then \
		echo "Installing sed..."; \
		apt-get update && apt-get install -y sed; \
	fi
	@$(GOFMT) -l ./ | xargs -I {} $(GOFMT) -w {};
	@sed -i 's/\t/    /g' $$(find ./ -type f -name '*.go');

define build_golang
    @ # Taken from https://gitlab.com/gitlab-org/gitaly/-/merge_requests/4192
    @ #
    @ # To compute a unique and deterministic value for GNU build-id, we build the Go binary a second time.
    @ # From the first build, we extract its unique and deterministic Go build-id, and use that to derive
    @ # comparably unique and deterministic GNU build-id to inject into the final binary.
    @ # If we cannot extract a Go build-id, we punt and fallback to using a random 32-byte hex string.
    @ # This fallback is unique but non-deterministic, making it sufficient to avoid generating the
    @ # GNU build-id from the empty string and causing guaranteed collisions.
    $(GO) build $3 -o $1 $2
    GO_BUILD_ID=$$( $(GO) tool buildid $1 || openssl rand -hex 32 ) && \
    GNU_BUILD_ID=$$( echo $$GO_BUILD_ID | sha1sum | cut -d' ' -f1 ) && \
    $(GO) build -trimpath -ldflags "-B 0x$$GNU_BUILD_ID" -mod=mod $3 -o $1 $2
endef

# Define the file coverage extraction function
define extract_file_coverage
#!/bin/bash
echo "====================================================================================="
echo -e "Detail file coverage from $$1 :"
echo "_____________________________________________________________________________________"
file_coverage="$$(sed -n 's/.*<option value="[^"]\+">\([^<]\+\).* (\([^)]\+\%.*\)<\/option>.*/\1 (\2)/p' "$$1")"; 
echo "$${file_coverage}"
echo "====================================================================================="
endef
export extract_file_coverage

add-extract_file_coverage: 
	$(shell mkdir -p $(BUILD_DIR))
	$(shell echo > $(BUILD_DIR)/extract_file_coverage.sh)
	@echo "$$extract_file_coverage" >> $(BUILD_DIR)/extract_file_coverage.sh
	$(shell chmod 777 $(BUILD_DIR)/extract_file_coverage.sh)

# Clean up the script file
clean-extract_file_coverage:
	rm -f $(BUILD_DIR)/extract_file_coverage.sh

# Define the aggregate file coverage extraction function
define aggregate_file_coverage
#!/bin/bash
echo "====================================================================================="
echo -e "Aggregate file coverages : "
echo "_____________________________________________________________________________________"
for file in $(TEST_DIR)/*.html; do
    if [ -f "$$file" ]; then
        file_coverage=$$(sed -n 's/.*<option value="[^"]\+">\([^<]\+\).* (\([^)]\+\%.*\)<\/option>.*/\1 (\2)/p' "$$file")
        echo "$$file_coverage"
    fi
done
echo "_____________________________________________________________________________________"
endef
export aggregate_file_coverage

# Print all the source fiules coverages at one place
add-aggregate_file_coverage: 
	$(shell mkdir -p $(BUILD_DIR))
	$(shell echo > $(BUILD_DIR)/aggregate_file_coverage.sh)
	@echo "$$aggregate_file_coverage" >> $(BUILD_DIR)/aggregate_file_coverage.sh
	$(shell chmod 777 $(BUILD_DIR)/aggregate_file_coverage.sh)

# Clean up the script file
clean-aggregate-file_coverage:
	rm -f $(BUILD_DIR)/aggregate_file_coverage.sh

.PHONY: all clean format_code clean-extract_file_coverage add-extract_file_coverage clean-aggregate-file_coverage add-aggregate_file_coverage COMMON_DEPS

COMMON_DEPS := format_code add-extract_file_coverage add-aggregate_file_coverage $(CMN_C_LIB) $(ENGINE_BIN) $(PLUGIN_MANAGER_BIN) $(LIB_TEST) $(ENGINE_TEST) \
	$(PLUGIN_MANAGER_TEST) $(SONIC_DBCLIENT_TEST) $(SONIC_LINK_CRC_TEST) $(SONIC_LINK_CRC_MOCKER_TEST) $(PLUGINS_COMMON_TEST) \
	$(PY_TEST) $(INTEGRATION_TEST)

all: $(COMMON_DEPS)
	$(BUILD_DIR)/aggregate_file_coverage.sh

all-skiptests : $(CMN_C_LIB) $(ENGINE_BIN) $(PLUGIN_MANAGER_BIN) $(SONIC_LINK_CRC_MOCKER_TEST) $(INTEGRATION_TEST)

all-silent: LIB_TEST_FLAGS :=
all-silent: $(COMMON_DEPS)
	$(BUILD_DIR)/aggregate_file_coverage.sh

$(CMN_C_LIB): $(SRC_FILES)
	mkdir -p $(LIB_DIR)
	$(call build_golang,$@,$(CMN_C_LIB_FILES),$(CMN_C_LIB_FLAG))
	@echo -e "Successfully Build c lib\n\n"

$(ENGINE_BIN): $(SRC_FILES)
	mkdir -p $(BIN_DIR)
	$(call build_golang,$@,lom/src/engine,)
	@echo -e "Successfully Build lom-engine\n\n"

$(PLUGIN_MANAGER_BIN): $(SRC_FILES)
	mkdir -p $(BIN_DIR)
	$(call build_golang,$@,lom/src/pluginmgr,)
	@echo -e "Successfully build plugin manager\n\n"

$(LIB_TEST): $(SRC_FILES) $(TEST_FILES)
	mkdir -p $(TEST_DIR)
	${GO} test -p 1 $(TEST_FLAG) -coverprofile=$(TEST_DIR)/LibCoverprofile.out \
		-coverpkg lom/src/lib/lomipc,lom/src/lib/lomcommon \
		-covermode=atomic $(LIB_TEST_FLAGS) ./src/lib/lib_test ./src/lib/lib_test/config || (echo "LibTest failed $$?"; exit 1)
	${GO} tool cover -html=$(TEST_DIR)/LibCoverprofile.out -o $(TEST_DIR)/LibCoverprofile.html
	@if [ -f "$(TEST_DIR)/LibCoverprofile.html" ]; then \
		$(BUILD_DIR)/extract_file_coverage.sh $(TEST_DIR)/LibCoverprofile.html; \
	fi
	touch $@
	@echo -e "Successfully completed LIB Test\n\n"

$(ENGINE_TEST): $(SRC_FILES) $(TEST_FILES)
	mkdir -p $(TEST_DIR)
	${GO} test $(TEST_FLAG) -coverprofile=$(TEST_DIR)/EngineCoverprofile.out \
		-coverpkg lom/src/engine/engine \
		-covermode=atomic $(LIB_TEST_FLAGS) lom/src/engine/engine || (echo "EngineTest failed $$?"; exit 1)
	${GO} tool cover -html=$(TEST_DIR)/EngineCoverprofile.out -o $(TEST_DIR)/EngineCoverprofile.html
	@if [ -f "$(TEST_DIR)/EngineCoverprofile.html" ]; then \
		$(BUILD_DIR)/extract_file_coverage.sh $(TEST_DIR)/EngineCoverprofile.html; \
	fi
	touch $@
	@echo -e "Successfully completed engine Test\n\n"

$(PLUGIN_MANAGER_TEST): $(SRC_FILES) $(TEST_FILES)
	mkdir -p $(TEST_DIR)
	${GO} test -p 1 $(TEST_FLAG) -coverprofile=$(TEST_DIR)/PluginManagerCoverprofile.out \
		-coverpkg lom/src/pluginmgr/pluginmgr_common \
		-covermode=atomic $(LIB_TEST_FLAGS) ./src/pluginmgr/pluginmgr_common  || (echo "Plugin manager test failed $$?"; exit 1)
	${GO} tool cover -html=$(TEST_DIR)/PluginManagerCoverprofile.out -o $(TEST_DIR)/PluginManagerCoverprofile.html
	@if [ -f "$(TEST_DIR)/PluginManagerCoverprofile.html" ]; then \
		$(BUILD_DIR)/extract_file_coverage.sh $(TEST_DIR)/PluginManagerCoverprofile.html; \
	fi
	touch $@
	@echo -e "Successfully completed plugin manager Test\n\n"

$(SONIC_DBCLIENT_TEST): $(SRC_FILES) $(TEST_FILES)
	mkdir -p $(TEST_DIR)
	${GO} test $(TEST_FLAG) -coverprofile=$(TEST_DIR)/SonicDbClientCoverprofile.out \
		-coverpkg lom/src/plugins/plugins_files/sonic/client/dbclient \
		-covermode=atomic $(LIB_TEST_FLAGS) lom/src/plugins/plugins_files/sonic/client/dbclient || (echo "SonicDbClient Test failed $$?"; exit 1)
	${GO} tool cover -html=$(TEST_DIR)/SonicDbClientCoverprofile.out -o $(TEST_DIR)/SonicDbClientCoverprofile.html
	@if [ -f "$(TEST_DIR)/SonicDbClientCoverprofile.html" ]; then \
		$(BUILD_DIR)/extract_file_coverage.sh $(TEST_DIR)/SonicDbClientCoverprofile.html; \
	fi
	touch $@
	@echo -e "Successfully completed sonic DB Test\n\n"

$(PY_TEST): $(SRC_FILES) $(PY_FILES)
	mkdir -p $(TEST_DIR)
	pushd python; \
	python3 setup.py test $(PYTEST_VERBOSE); \
	popd
	@echo -e "Successfully completed Python Test\n\n"

$(SONIC_LINK_CRC_TEST): $(SRC_FILES) $(TEST_FILES)
	mkdir -p $(TEST_DIR)
	${GO} test $(TEST_FLAG) -coverprofile=$(TEST_DIR)/SonicLinkCrcCoverprofile.out \
				-coverpkg lom/src/plugins/plugins_files/sonic/plugin/linkcrc \
				-covermode=atomic $(LIB_TEST_FLAGS) lom/src/plugins/plugins_files/sonic/plugin/linkcrc || (echo "SonicLinkCrc plugin Test failed $$?"; exit 1)
	${GO} tool cover -html=$(TEST_DIR)/SonicLinkCrcCoverprofile.out -o $(TEST_DIR)/SonicLinkCrcCoverprofile.html
	@if [ -f "$(TEST_DIR)/SonicLinkCrcCoverprofile.html" ]; then \
		$(BUILD_DIR)/extract_file_coverage.sh $(TEST_DIR)/SonicLinkCrcCoverprofile.html; \
	fi
	touch $@
	@echo -e "Successfully completed sonic link crc Test\n\n"
	
$(PLUGINS_COMMON_TEST): $(SRC_FILES) $(TEST_FILES)
	mkdir -p $(TEST_DIR)
	${GO} test $(TEST_FLAG) -coverprofile=$(TEST_DIR)/PluginsCommonCoverprofile.out \
		-coverpkg lom/src/plugins/plugins_common \
				-covermode=atomic $(LIB_TEST_FLAGS) lom/src/plugins/plugins_common || (echo "PluginsCommon Tests failed $$?"; exit 1)
	${GO} tool cover -html=$(TEST_DIR)/PluginsCommonCoverprofile.out -o $(TEST_DIR)/PluginsCommonCoverprofile.html
	@if [ -f "$(TEST_DIR)/PluginsCommonCoverprofile.html" ]; then \
		$(BUILD_DIR)/extract_file_coverage.sh $(TEST_DIR)/PluginsCommonCoverprofile.html; \
	fi
	touch $@
	@echo -e "Successfully completed plugins common Test\n\n"

$(SONIC_LINK_CRC_MOCKER_TEST): $(SRC_FILES)
	mkdir -p $(TEST_DIR)
	$(call build_golang,$@,lom/src/plugins/plugins_files/sonic/plugin_integration_tests/linkcrc_mocker,)
	@echo -e "Successfully completed Sonic linkcrc Integration test Mocker\n\n"

$(INTEGRATION_TEST): 
	$(INTEGRATION_TEST_DIR)/src/build.sh build
	@echo -e "Successfully completed packaging Integration tests\n\n"

clean: clean-extract_file_coverage clean-aggregate-file_coverage
	rm -rf $(BUILD_DIR)
	$(INTEGRATION_TEST_DIR)/src/build.sh clean

