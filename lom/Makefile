# This is the Makefile for the LoM system. It allows you to build the system with different configurations.
# Build container for sonic & arista are different.

# For a Sonic build AMD64 architecture, following are exported from the build container:
# DOCKER_BUILD_PLATFORM=sonic
# DOCKER_BUILD_OS=linux
# DOCKER_BUILD_ARCH=amd64
# BUILD_CC=gcc
# BUILD_CXX=g++
# BUILD_CFLAGS=

# For a 32 bit Arista build, following are exported from the build container:
# DOCKER_BUILD_PLATFORM=arista
# DOCKER_BUILD_OS=linux
# DOCKER_BUILD_ARCH=386
# BUILD_CC=/opt/arista/fc18-gcc5.4.0/bin/i686-pc-linux-gnu-gcc
# BUILD_CXX=/opt/arista/fc18-gcc5.4.0/bin/i686-pc-linux-gnu-g++
# BUILD_LDFLAGS="/usr/local/lib"
# BUILD_CFLAGS=

# For a 64 bit Arista build, following are exported from the build container:
# DOCKER_BUILD_PLATFORM=arista
# DOCKER_BUILD_OS=linux
# DOCKER_BUILD_ARCH=amd64
# BUILD_CC=/opt/arista/centos7.5-gcc8.4.0-glibc2.17/bin/x86_64-redhat-linux-gcc
# BUILD_CXX=/opt/arista/centos7.5-gcc8.4.0-glibc2.17/bin/x86_64-redhat-linux-g++
# BUILD_LDFLAGS="-lrt -L/usr/local/lib -L/usr/lib/x86_64-linux-gnu"
# BUILD_CFLAGS="-I/usr/include/security -I/usr/include/ -I/usr/include/x86_64-linux-gnu -O2 -g"

# To build the entire system, use the 'make all' target.
# Example: 'make all'
# This will automatically build the system for the platform specified in the environemnt variables DOCKER_BUILD_PLATFORM, DOCKER_BUILD_OS and DOCKER_BUILD_ARCH.

# For a silent build that suppresses the output of the build process, use the 'make all-silent' target.
# Example: 'make all-silent'

# To build individual components, first prepare the temporary source by running 'make prepare_temp_src'.
# Then, build the individual component.
# Example: 'make prepare_temp_src' and then 'make $(ENGINE_BIN)'
# Replace '$(ENGINE_BIN)' with the actual name of the component you want to build.

# Select bash for commands
.ONESHELL:
SHELL = /bin/bash
.SHELLFLAGS += -e
USER = $(shell id -un)
UID = $(shell id -u)
GUID = $(shell id -g)

GOBIN_PATH := /usr/local/go1.20.3/go/bin
GO := $(GOBIN_PATH)/go
GOFMT := $(GO)fmt
INSTALL := /usr/bin/install

# Use the specified build tags from the environment variables
BUILD_PLATFORM ?= $(DOCKER_BUILD_PLATFORM)
BUILD_OS ?= $(DOCKER_BUILD_OS)
BUILD_ARCH ?= $(DOCKER_BUILD_ARCH)

# Validation checks
ifeq ($(BUILD_PLATFORM),)
$(error Update build container for env variables: DOCKER_BUILD_PLATFORM is not set)
endif

ifeq ($(BUILD_OS),)
$(error Update build container for env variables: DOCKER_BUILD_OS is not set)
endif

ifeq ($(BUILD_ARCH),)
$(error Update build container for env variables: DOCKER_BUILD_ARCH is not set)
endif

ifeq ($(GOPATH),)
export GOPATH=/tmp/go
endif

BUILD_DIR := build
INSTALL_DIR := ../LoM-Install
VENDOR_DIR := vendor
LIB_DIR := $(BUILD_DIR)/lib
BIN_DIR := $(BUILD_DIR)/bin
TEST_DIR := $(BUILD_DIR)/test
INTEGRATION_TEST_DIR := integration_test
BUILD_SRC_DIR := $(BUILD_DIR)/src
SRC_DIR := src
CONFIG_DIR := config
GNMI_DIR := $(BUILD_DIR)/gnmi

# Configuration file
CONFIG_FILE = $(BUILD_DIR)/.config

export PATH := $(PATH):$(GOPATH)/bin:$(GOBIN_PATH):$(BIN_DIR)

# Set to -v for verbose o/p. May set it in Env before calling Make
# export TEST_FLAG=-v in shell before calling make or
# TEST_FLAG=-v make all

# TEST_FLAG := "-v" Set it for verbose test o/p

ifeq "${TEST_FLAG}" "-v"
PYTEST_VERBOSE= --addopts "-s"
endif

# gomonkey mocks don't work with inlining. Hence explicitly disable it.
# https://github.com/agiledragon/gomonkey/issues/34
#
LIB_TEST_FLAGS_NOINLINE = -gcflags=all=-l -p 1
LIB_TEST_FLAGS = -v

export GO111MODULE=on
export LOM_LIB_PATH=$(PWD)/build/lib

# copy all source files to build/src directory
prepare_temp_src:
	@echo "Creating directory structure in $(BUILD_SRC_DIR)..."
	@mkdir -p $(BUILD_SRC_DIR)
	find src -type d -not \( -iname "README.md" -o -iname "README" \) -exec mkdir -p $(BUILD_DIR)/{} \;
	find src -type f -not \( -iname "README.md" -o -iname "README" \) -exec cp {} $(BUILD_DIR)/{} \;
	rm -r $(BUILD_SRC_DIR)/plugins/vendors/
	mkdir -p $(BUILD_SRC_DIR)/plugins/vendors/
	
	# Copy src/plugins/vendors/$(BUILD_PLATFORM) to $(BUILD_SRC_DIR)/plugins/vendors/
	find src/plugins/vendors/$(BUILD_PLATFORM) -type d -not \( -iname "README.md" -o -iname "README" \) -exec mkdir -p $(BUILD_DIR)/{} \;
	find src/plugins/vendors/$(BUILD_PLATFORM) -type f -not \( -iname "README.md" -o -iname "README" \) -exec cp {} $(BUILD_DIR)/{} \;

	#Copy config/$(BUILD_PLATFORM) to $(BUILD_DIR)/config/
	mkdir -p $(BUILD_DIR)/config/
	cp -r $(CONFIG_DIR)/$(BUILD_PLATFORM) $(BUILD_DIR)/config/
	
	#Copy $(INSTALL_DIR)/$(BUILD_PLATFORM) to $(BUILD_DIR)/LoM-Install/
	mkdir -p $(BUILD_DIR)/LoM-Install/
	cp -r $(INSTALL_DIR)/$(BUILD_PLATFORM) $(BUILD_DIR)/LoM-Install/
	find $(INSTALL_DIR) -maxdepth 1 -type f -not \( -iname "README.md" -o -iname "README" \) -exec cp {} $(BUILD_DIR)/LoM-Install/ \;

# RFE:
# 1. Could we get a dedicated .go, just for vendors import.
# 2. We tell Dev to include those that he desire -- So he gets the control on choosing or not-choosing. Like I want to skip building Link-CRC as it has a bug or redundant or ...
# 3. In each vendor root dir, have this file as "inventory.go"
# 4. Right inventrory.go gets copied while building based on chosen vendor.
# Update import statements in pluginmgr_main.go to include platform specific plugins. This is required since vendor specific files must be imported. 
# Update Process : It will Scan the build/src/plugins/vendors/$(BUILD_PLATFORM)/plugin directory and get the plugin names. With it it will add
# the import statements in pluginmgr_main.go
update_import_statements:
	@echo "Updating import statements in $(BUILD_SRC_DIR)/pluginmgr/pluginmgr_main.go..."
	rm -f $(BUILD_SRC_DIR)/pluginmgr/pluginmgr_main.go; \
	cp src/pluginmgr/pluginmgr_main.go $(BUILD_SRC_DIR)/pluginmgr/pluginmgr_main.go; \
	for dir in $(BUILD_SRC_DIR)/plugins/vendors/$(BUILD_PLATFORM)/plugin/*; do \
		if [ -d "$$dir" ]; then \
			plugin_name=$$(basename "$$dir"); \
			import_statement="_ \"lom/src/plugins/vendors/$(BUILD_PLATFORM)/plugin/$$plugin_name\""; \
			sed -i 's|import (|import (\n\t'"$$import_statement\n"'|' $(BUILD_SRC_DIR)/pluginmgr/pluginmgr_main.go; \
		fi \
	done;

# Change import path to properly point to build/src
update_imports_path:
	@find $(BUILD_SRC_DIR) -type f -name '*.go' -exec sed -i 's|"lom/src|"lom/build/src|g' {} \;


SRC_FILES=$(shell find ./$(SRC_DIR) -name '*.go' | grep -v '_test.go' | grep -v '/tests/')
PY_FILES=$(shell find ./python/ -name '*.py' | grep -v '_test.py' | grep -v '/tests/')
TEST_FILES=$(shell find ./$(SRC_DIR) -name '*test.go')
PROTO_FILES=$(shell find ./$(SRC_DIR) -name '*.proto')
PATCH_FILES=$(shell find ./$(SRC_DIR) -name '*.patch')

CMN_C_LIB_FILES=$(BUILD_SRC_DIR)/lib/clib/lom_clib.go
CMN_C_LIB_FLAG=-buildmode=c-shared
CMN_C_LIB=$(BUILD_DIR)/lib/cmn_c_lib.so

# Binaries used in LoM system
ENGINE_BIN := $(BIN_DIR)/LoMEngine
PLUGIN_MANAGER_BIN := $(BIN_DIR)/LoMPluginMgr
CLI_BIN := $(BIN_DIR)/LoMCli
INTEGRATION_TEST_BIN := $(BUILD_DIR)/integration_test_installer.sh
GNMI_SERVER_BIN := $(BIN_DIR)/LoMgNMIServer

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
GNMI_SERVER_TEST = $(TEST_DIR)/gNMIServerTested
ARISTA_INSTALLER = $(INSTALL_DIR)/arista_installer
ARISTA_COMMON_TEST = $(TEST_DIR)/AristaCommonTested
ARISTA_IPTCRC_TEST = $(TEST_DIR)/AristaIptCrcTested

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
	CGO_CFLAGS="$(BUILD_CFLAGS)" CGO_LDFLAGS="$(BUILD_LDFLAGS)" CGO_ENABLED=1 GOOS=$(DOCKER_BUILD_OS) GOARCH=$(DOCKER_BUILD_ARCH) CC=$(BUILD_CC) $(GO) build $3 -o $1 $2; \
	GO_BUILD_ID=$$($(GO) tool buildid $1 || openssl rand -hex 32) && \
	GNU_BUILD_ID=$$(echo $$GO_BUILD_ID | sha1sum | cut -d' ' -f1) && \
	CGO_CFLAGS="$(BUILD_CFLAGS)" CGO_LDFLAGS="$(BUILD_LDFLAGS)" CGO_ENABLED=1 GOOS=$(DOCKER_BUILD_OS) GOARCH=$(DOCKER_BUILD_ARCH) CC=$(BUILD_CC) $(GO) build -trimpath -ldflags "-B 0x$$GNU_BUILD_ID" -mod=mod $3 -o $1 $2;
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
# Remove the old coverage profile if it exists
rm -f $(TEST_DIR)/aggregate_coverage.out
# Find all .out files in the directory
for file in $$(find $(TEST_DIR) -name "*.out"); do
	if [ -f $(TEST_DIR)/aggregate_coverage.out ]; then
		# If the full coverage profile exists, append the current coverage profile to it
		tail -n +2 $$file >> $(TEST_DIR)/aggregate_coverage.out
	else
		# If the full coverage profile does not exist, rename the current coverage profile to be the full coverage profile
		cp $$file $(TEST_DIR)/aggregate_coverage.out
	fi
done
# Generate the HTML coverage report
$(GO) tool cover -html=$(TEST_DIR)/aggregate_coverage.out -o $(TEST_DIR)/aggregate_coverage.html
endef
export aggregate_file_coverage

# Print all the source files coverages at one place
add-aggregate_file_coverage: 
	$(shell mkdir -p $(BUILD_DIR))
	$(shell echo > $(BUILD_DIR)/aggregate_file_coverage.sh)
	@echo "$$aggregate_file_coverage" >> $(BUILD_DIR)/aggregate_file_coverage.sh
	$(shell chmod 777 $(BUILD_DIR)/aggregate_file_coverage.sh)

# Clean up the script file
clean-aggregate-file_coverage:
	rm -f $(BUILD_DIR)/aggregate_file_coverage.sh

.PHONY: all clean format_code clean-extract_file_coverage add-extract_file_coverage clean-aggregate-file_coverage add-aggregate_file_coverage \
		COMMON_DEPS SONIC_DEPS ARISTA_DEPS check_build_platform prepare_temp_src update_import_statements update_imports_path

COMMON_DEPS := prepare_temp_src update_import_statements update_imports_path format_code add-extract_file_coverage add-aggregate_file_coverage \
			  $(ENGINE_BIN) $(CMN_C_LIB) $(PLUGIN_MANAGER_BIN) $(CLI_BIN) gnmi-tools $(GNMI_SERVER_BIN)
COMMON_DEPS_TEST := $(LIB_TEST) $(ENGINE_TEST) $(PLUGIN_MANAGER_TEST) $(PLUGINS_COMMON_TEST) $(PY_TEST) $(GNMI_SERVER_TEST)

SONIC_DEPS := $(SONIC_DBCLIENT_TEST) $(SONIC_LINK_CRC_TEST) $(SONIC_LINK_CRC_MOCKER_TEST) $(INTEGRATION_TEST_BIN)
ARISTA_DEPS := $(ARISTA_COMMON_TEST) $(ARISTA_IPTCRC_TEST) $(ARISTA_INSTALLER) 

ifeq ($(BUILD_PLATFORM), sonic)
	BUILD_DEPS := $(SONIC_DEPS)
	CLEAN_TARGET := clean-sonic
else ifeq ($(BUILD_PLATFORM), arista)
	BUILD_DEPS := $(ARISTA_DEPS)
	CLEAN_TARGET := clean-arista
else
$(error Unsupported BUILD_PLATFORM: $(BUILD_PLATFORM))
endif

# Create the configuration file
check_build_platform:
	@echo "==================================================="	
	@echo "Build requested for the platform $(BUILD_PLATFORM) $(BUILD_OS) $(BUILD_ARCH)"
	@echo "==================================================="
	rm -fr $(BUILD_DIR); \
	mkdir -p $(BUILD_DIR); \
	rm -fr $(VENDOR_DIR); \
	echo "$(BUILD_PLATFORM) $(BUILD_OS) $(BUILD_ARCH)" > $(CONFIG_FILE);

all: check_build_platform $(COMMON_DEPS) $(COMMON_DEPS_TEST) $(BUILD_DEPS)
	$(BUILD_DIR)/aggregate_file_coverage.sh
	@if [ -f "$(TEST_DIR)/aggregate_coverage.html" ]; then \
		$(BUILD_DIR)/extract_file_coverage.sh $(TEST_DIR)/aggregate_coverage.html; \
	fi

all-silent: LIB_TEST_FLAGS :=
all-silent: check_build_platform $(COMMON_DEPS) $(COMMON_DEPS_TEST) $(BUILD_DEPS)
	$(BUILD_DIR)/aggregate_file_coverage.sh
	@if [ -f "$(TEST_DIR)/aggregate_coverage.html" ]; then \
		$(BUILD_DIR)/extract_file_coverage.sh $(TEST_DIR)/aggregate_coverage.html; \
	fi

all-skiptests: check_build_platform $(COMMON_DEPS) $(BUILD_DEPS)
	$(BUILD_DIR)/aggregate_file_coverage.sh
	@if [ -f "$(TEST_DIR)/aggregate_coverage.html" ]; then \
		$(BUILD_DIR)/extract_file_coverage.sh $(TEST_DIR)/aggregate_coverage.html; \
	fi

GO_DEPS := $(VENDOR_DIR)/.done

go.mod:
	$(GO) mod init lom

$(GO_DEPS): go.mod $(PATCH_FILES)
	$(GO) mod vendor
	$(GO) mod download golang.org/x/crypto@v0.0.0-20191206172530-e9b2fee46413
	$(GO) mod download github.com/jipanyang/gnxi@v0.0.0-20181221084354-f0a90cca6fd0
	mkdir -p vendor/golang.org/x/crypto/
	mkdir -p vendor/github.com/jipanyang/gnxi/
	cp -r $(GOPATH)/pkg/mod/golang.org/x/crypto@v0.0.0-20191206172530-e9b2fee46413/* vendor/golang.org/x/crypto/
	cp -r $(GOPATH)/pkg/mod/github.com/jipanyang/gnxi@v0.0.0-20181221084354-f0a90cca6fd0/* vendor/github.com/jipanyang/gnxi/
	chmod -R u+w vendor
	patch -d vendor -p0 < src/gnmi/patches/gnmi_cli.all.patch
	patch -d vendor -p0 < src/gnmi/patches/gnmi_set.patch
	patch -d vendor -p0 < src/gnmi/patches/gnmi_get.patch
	patch -d vendor -p0 < src/gnmi/patches/gnmi_path.patch
	patch -d vendor -p0 < src/gnmi/patches/gnmi_xpath.patch
	# git apply src/gnmi/patches/0001-Updated-to-filter-and-write-to-file.patch
	touch $@


$(CMN_C_LIB): $(SRC_FILES) $(GO_DEPS)
	mkdir -p $(LIB_DIR)
	$(call build_golang,$@,$(CMN_C_LIB_FILES),$(CMN_C_LIB_FLAG))
	@echo -e "Successfully Build c lib\n\n"

$(ENGINE_BIN): $(SRC_FILES)
	mkdir -p $(BIN_DIR)
	$(call build_golang,$@,lom/build/src/engine,)
	@echo -e "Successfully Build lom-engine\n\n"

$(CLI_BIN): $(SRC_FILES)
	mkdir -p $(BIN_DIR)
	$(call build_golang,$@,lom/build/src/tools,)
	@echo -e "Successfully Build lom-cli\n\n"

$(PLUGIN_MANAGER_BIN): $(SRC_FILES)
	mkdir -p $(BIN_DIR)
	$(call build_golang,$@,lom/build/src/pluginmgr,)
	@echo -e "Successfully build plugin manager\n\n"

$(LIB_TEST): $(SRC_FILES) $(TEST_FILES)
	mkdir -p $(TEST_DIR)
	CGO_CFLAGS="$(BUILD_CFLAGS)" CGO_LDFLAGS="$(BUILD_LDFLAGS)" CGO_ENABLED=1 GOOS=$(DOCKER_BUILD_OS) GOARCH=$(DOCKER_BUILD_ARCH) CC=$(BUILD_CC) ${GO} test -p 1 $(TEST_FLAG) -coverprofile=$(TEST_DIR)/LibCoverprofile.out \
	-coverpkg lom/build/src/lib/lomipc,lom/build/src/lib/lomcommon,lom/build/src/lib/lomscripted,lom/build/src/lib/lomtelemetry \
	-covermode=atomic $(LIB_TEST_FLAGS) $(LIB_TEST_FLAGS_NOINLINE) lom/build/src/lib/libtest lom/build/src/lib/libtest/config || (echo "LibTest failed $$?"; exit 1)
	${GO} tool cover -html=$(TEST_DIR)/LibCoverprofile.out -o $(TEST_DIR)/LibCoverprofile.html
	@if [ -f "$(TEST_DIR)/LibCoverprofile.html" ]; then \
		$(BUILD_DIR)/extract_file_coverage.sh $(TEST_DIR)/LibCoverprofile.html; \
	fi
	touch $@
	@echo -e "Successfully completed LIB Test\n\n"

$(ENGINE_TEST): $(SRC_FILES) $(TEST_FILES)
	mkdir -p $(TEST_DIR)
	CGO_CFLAGS="$(BUILD_CFLAGS)" CGO_LDFLAGS="$(BUILD_LDFLAGS)" CGO_ENABLED=1 GOOS=$(DOCKER_BUILD_OS) GOARCH=$(DOCKER_BUILD_ARCH) CC=$(BUILD_CC) ${GO} test -p 1 $(TEST_FLAG) -coverprofile=$(TEST_DIR)/EngineCoverprofile.out \
	-coverpkg lom/build/src/engine/engine \
	-covermode=atomic $(LIB_TEST_FLAGS) $(LIB_TEST_FLAGS_NOINLINE) lom/build/src/engine/engine || (echo "EngineTest failed $$?"; exit 1)
	${GO} tool cover -html=$(TEST_DIR)/EngineCoverprofile.out -o $(TEST_DIR)/EngineCoverprofile.html
	@if [ -f "$(TEST_DIR)/EngineCoverprofile.html" ]; then \
		$(BUILD_DIR)/extract_file_coverage.sh $(TEST_DIR)/EngineCoverprofile.html; \
	fi
	touch $@
	@echo -e "Successfully completed engine Test\n\n"

$(PLUGIN_MANAGER_TEST): $(SRC_FILES) $(TEST_FILES)
	mkdir -p $(TEST_DIR)
	CGO_CFLAGS="$(BUILD_CFLAGS)" CGO_LDFLAGS="$(BUILD_LDFLAGS)" CGO_ENABLED=1 GOOS=$(DOCKER_BUILD_OS) GOARCH=$(DOCKER_BUILD_ARCH) CC=$(BUILD_CC) ${GO} test -p 1 $(TEST_FLAG) -coverprofile=$(TEST_DIR)/PluginManagerCoverprofile.out \
	-coverpkg lom/build/src/pluginmgr/pluginmgr_common \
	-covermode=atomic $(LIB_TEST_FLAGS) $(LIB_TEST_FLAGS_NOINLINE) lom/build/src/pluginmgr/pluginmgr_common  || (echo "Plugin manager test failed $$?"; exit 1)
	${GO} tool cover -html=$(TEST_DIR)/PluginManagerCoverprofile.out -o $(TEST_DIR)/PluginManagerCoverprofile.html
	@if [ -f "$(TEST_DIR)/PluginManagerCoverprofile.html" ]; then \
		$(BUILD_DIR)/extract_file_coverage.sh $(TEST_DIR)/PluginManagerCoverprofile.html; \
	fi
	touch $@
	@echo -e "Successfully completed plugin manager Test\n\n"

$(PY_TEST): $(SRC_FILES) $(PY_FILES)
	mkdir -p $(TEST_DIR)
	pushd python; \
	python3 setup.py test $(PYTEST_VERBOSE); \
	popd
	@echo -e "Successfully completed Python Test\n\n"
	
# To-Do : Goutham/Renuka : gomonkey failing for 386. Need to debug and fix it.
$(PLUGINS_COMMON_TEST): $(SRC_FILES) $(TEST_FILES)
	@if [ "$(BUILD_PLATFORM)" = "arista" ] && [ "$(BUILD_ARCH)" = "386" ]; then \
        echo "Skipping $(PLUGINS_COMMON_TEST) for BUILD_PLATFORM=arista and BUILD_ARCH=386"; \
        touch $@; \
    else \
        mkdir -p $(TEST_DIR); \
	${GO} test $(TEST_FLAG) -coverprofile=$(TEST_DIR)/PluginsCommonCoverprofile.out \
		-coverpkg lom/build/src/plugins/plugins_common \
				-covermode=atomic $(LIB_TEST_FLAGS) $(LIB_TEST_FLAGS_NOINLINE) lom/build/src/plugins/plugins_common || (echo "PluginsCommon Tests failed $$?"; exit 1); \
	${GO} tool cover -html=$(TEST_DIR)/PluginsCommonCoverprofile.out -o $(TEST_DIR)/PluginsCommonCoverprofile.html; \
        if [ -f "$(TEST_DIR)/PluginsCommonCoverprofile.html" ]; then \
		$(BUILD_DIR)/extract_file_coverage.sh $(TEST_DIR)/PluginsCommonCoverprofile.html; \
fi; \
        touch $@; \
        echo -e "Successfully completed plugins common Test\n\n"; \
	fi
	
$(SONIC_DBCLIENT_TEST): $(SRC_FILES) $(TEST_FILES)
	mkdir -p $(TEST_DIR)
	${GO} test $(TEST_FLAG) -coverprofile=$(TEST_DIR)/SonicDbClientCoverprofile.out \
		-coverpkg lom/build/src/plugins/vendors/sonic/client/dbclient \
		-covermode=atomic $(LIB_TEST_FLAGS) $(LIB_TEST_FLAGS_NOINLINE) lom/build/src/plugins/vendors/sonic/client/dbclient || (echo "SonicDbClient Test failed $$?"; exit 1)
	${GO} tool cover -html=$(TEST_DIR)/SonicDbClientCoverprofile.out -o $(TEST_DIR)/SonicDbClientCoverprofile.html
	@if [ -f "$(TEST_DIR)/SonicDbClientCoverprofile.html" ]; then \
		$(BUILD_DIR)/extract_file_coverage.sh $(TEST_DIR)/SonicDbClientCoverprofile.html; \
	fi
	touch $@
	@echo -e "Successfully completed sonic DB Test\n\n"

$(SONIC_LINK_CRC_TEST): $(SRC_FILES) $(TEST_FILES)
	mkdir -p $(TEST_DIR)
	${GO} test $(TEST_FLAG) -coverprofile=$(TEST_DIR)/SonicLinkCrcCoverprofile.out \
				-coverpkg lom/build/src/plugins/vendors/sonic/plugin/linkcrc \
				-covermode=atomic $(LIB_TEST_FLAGS) $(LIB_TEST_FLAGS_NOINLINE) lom/build/src/plugins/vendors/sonic/plugin/linkcrc || (echo "SonicLinkCrc plugin Test failed $$?"; exit 1)
	${GO} tool cover -html=$(TEST_DIR)/SonicLinkCrcCoverprofile.out -o $(TEST_DIR)/SonicLinkCrcCoverprofile.html
	@if [ -f "$(TEST_DIR)/SonicLinkCrcCoverprofile.html" ]; then \
		$(BUILD_DIR)/extract_file_coverage.sh $(TEST_DIR)/SonicLinkCrcCoverprofile.html; \
	fi
	touch $@
	@echo -e "Successfully completed sonic link crc Test\n\n"
	
$(SONIC_LINK_CRC_MOCKER_TEST): $(SRC_FILES)
	mkdir -p $(TEST_DIR)
	$(call build_golang,$@,lom/build/src/plugins/vendors/sonic/plugin_integration_tests/linkcrc_mocker,)
	@echo -e "Successfully completed Sonic linkcrc Integration test Mocker\n\n"

# Integration test for sonic plugins
$(INTEGRATION_TEST_BIN): 
	$(INTEGRATION_TEST_DIR)/src/build.sh build $(INTEGRATION_TEST_BIN)
	@echo -e "Successfully completed packaging Integration tests\n\n"




GNMI_PROTO := $(BUILD_SRC_DIR)/gnmi/proto/.done

# Run this make manually each time a .proto is updated to generate corresponding .pb.go.
# Commit the generated files.
# Calling proto's Makefile from this Makefile breaks when compiling as submodule in SONiC.
#
$(GNMI_PROTO) : $(PROTO_FILES)
	cd $(BUILD_SRC_DIR)/gnmi/proto/ && $(MAKE) -f Makefile all
	touch $(PWD)/$@


# Build only CLI for now.
# 
gnmi-tools: $(GO_DEPS)
	cd $(BUILD_DIR)
	# $(GO) build -o ${BIN_DIR}/gnmi_get -mod=vendor github.com/jipanyang/gnxi/gnmi_get
	# $(GO) build -o ${BIN_DIR}/gnmi_set -mod=vendor github.com/jipanyang/gnxi/gnmi_set
	$(GO) build -o ${BIN_DIR}/gnmi_cli -mod=vendor github.com/openconfig/gnmi/cmd/gnmi_cli
	# $(GO) build -o ${BIN_DIR}/gnoi_client -mod=vendor github.com/sonic-net/sonic-gnmi/gnoi_client
	# $(GO) build -o ${BIN_DIR}/gnmi_dump -mod=vendor github.com/sonic-net/sonic-gnmi/gnmi_dump
	cd -

# To-Do : Goutham/Renuka :  Failing for 386. Need to debug and fix it. Issue at : lom/src/gnmi/utils/shareMem.go. API's not supported for 386.
$(GNMI_SERVER_BIN): $(SRC_FILES)
	@if [ "$(BUILD_PLATFORM)" = "arista" ] && [ "$(BUILD_ARCH)" = "386" ]; then \
		echo "Skipping $(GNMI_SERVER_BIN) for BUILD_PLATFORM=arista and BUILD_ARCH=386"; \
		touch $@; \
	else \
		mkdir -p $(BIN_DIR) \
	$(call build_golang,$@,lom/build/src/gnmi/gnmi_server/,) \
		echo -e "Successfully Build gnmi-server\n\n" \
		touch $@; \
	fi

# To-Do : Goutham/Renuka :  Failing for 386. Need to debug and fix it.
$(GNMI_SERVER_TEST): $(SRC_FILES) $(TEST_FILES)
	@if [ "$(BUILD_PLATFORM)" = "arista" ] && [ "$(BUILD_ARCH)" = "386" ]; then \
        echo "Skipping $(GNMI_SERVER_TEST) because BUILD_PLATFORM=arista and BUILD_ARCH=386"; \
        touch $@; \
    else \
        mkdir -p $(TEST_DIR); \
	${GO} test $(TEST_FLAG) -coverprofile=$(TEST_DIR)/gNMIServerCoverprofile.out \
		-coverpkg lom/build/src/gnmi/gnmi_server/server,lom/build/src/gnmi/lom_data_clients \
		-covermode=atomic $(LIB_TEST_FLAGS) $(LIB_TEST_FLAGS_NOINLINE) \
		-gcflags=all=-l lom/build/src/gnmi/gnmi_server/server lom/build/src/gnmi/lom_data_clients || (echo "gNMIServerTest failed $$?"; exit 1); \
	${GO} tool cover -html=$(TEST_DIR)/gNMIServerCoverprofile.out -o $(TEST_DIR)/gNMIServerCoverprofile.html; \
        if [ -f "$(TEST_DIR)/gNMIServerCoverprofile.html" ]; then \
		$(BUILD_DIR)/extract_file_coverage.sh $(TEST_DIR)/gNMIServerCoverprofile.html; \
fi; \
        touch $@; \
        echo -e "Successfully completed gNMIServer Test\n\n"; \
    fi

#installer for Arista
$(ARISTA_INSTALLER):
	$(BUILD_DIR)/LoM-Install/arista/make-install-archive.sh build
	@echo -e "Successfully completed creating installer for arista \n\n"

	
$(ARISTA_IPTCRC_TEST): $(SRC_FILES) $(TEST_FILES)
	mkdir -p $(TEST_DIR)
	${GO} test -p 1 $(TEST_FLAG) -coverprofile=$(TEST_DIR)/AristaIptCrcCoverprofile.out \
				-coverpkg lom/build/src/plugins/vendors/arista/plugin/iptcrc \
				-covermode=atomic $(LIB_TEST_FLAGS) lom/build/src/plugins/vendors/arista/plugin/iptcrc || (echo "AristaIptCrc plugin Test failed $$?"; exit 1)
	${GO} tool cover -html=$(TEST_DIR)/AristaIptCrcCoverprofile.out -o $(TEST_DIR)/AristaIptCrcCoverprofile.html
	@if [ -f "$(TEST_DIR)/AristaIptCrcCoverprofile.html" ]; then \
		$(BUILD_DIR)/extract_file_coverage.sh $(TEST_DIR)/AristaIptCrcCoverprofile.html; \
	fi
	touch $@
	@echo -e "Successfully completed arista iptcrc Test\n\n"

$(ARISTA_COMMON_TEST): $(SRC_FILES) $(TEST_FILES)
	mkdir -p $(TEST_DIR)
	${GO} test -p 1 $(TEST_FLAG) -coverprofile=$(TEST_DIR)/AristaCommonCoverprofile.out \
				-coverpkg lom/build/src/plugins/vendors/arista/arista_common \
				-covermode=atomic $(LIB_TEST_FLAGS) lom/build/src/plugins/vendors/arista/arista_common || (echo "Aristacommon plugin Test failed $$?"; exit 1)
	${GO} tool cover -html=$(TEST_DIR)/AristaCommonCoverprofile.out -o $(TEST_DIR)/AristaCommonCoverprofile.html
	@if [ -f "$(TEST_DIR)/AristaCommonCoverprofile.html" ]; then \
		$(BUILD_DIR)/extract_file_coverage.sh $(TEST_DIR)/AristaCommonCoverprofile.html; \
	fi
	touch $@
	@echo -e "Successfully completed arista common Test\n\n"

clean-sonic:
	$(INTEGRATION_TEST_DIR)/src/build.sh clean

clean-arista:
	$(BUILD_DIR)/LoM-Install/arista/make-install-archive.sh clean

clean: clean-extract_file_coverage clean-aggregate-file_coverage $(CLEAN_TARGET)
	rm -rf $(BUILD_DIR)
	mkdir -p vendor/
	chmod -R u+rw vendor/
	rm -rf vendor
	# rm -f src/gnmi/proto/go.mod src/gnmi/proto/go.sum src/gnmi/proto/.done


