#! /bin/bash

# may have to set GO111MODULE=off

##export GOPATH=$(pwd;)

##echo $GOPATH

# set -x


# Define output directory
OUTPUT_DIR=$(realpath ./bin)

# Set GOBIN to output directory
export GOBIN=$OUTPUT_DIR

# Install any dependencies specified in go.mod
go mod download -x


install() {
    echo "Installing to "$OUTPUT_DIR
    go install ./...
    echo "Build completed successfully."
}

etest() {
    go test $1 -coverprofile=coverprofile.out  -coverpkg engine -covermode=atomic engine
    if [ $? -ne 0 ]; then
        echo "Failed to run engine test"
        exit -1
    fi
    go tool cover -html=coverprofile.out -o /tmp/coverage.html
    ls -l coverprofile.out /tmp/coverage.html
    echo "View /tmp/coverage.html in Edge"
}

test() {
    go test $1 -coverprofile=coverprofile.out  -coverpkg go/src/lib/lomipc,go/src/lib/lomcommon -covermode=atomic ./src/lib/lib_test
    if [ $? -ne 0 ]; then
        echo "Failed to run test"
        exit -1
    fi
    go tool cover -html=coverprofile.out -o /tmp/coverage.html
    ls -l coverprofile.out /tmp/coverage.html
    echo "View /tmp/coverage.html in Edge"
}


test_plugin_mgr() {
    go test -v -p 1 -cover $1 -coverprofile=coverprofile_plmgr.out -coverpkg gocode/src/lib/lomcommon,gocode/src/pluginmgr/pluginmgr_common,gocode/src/pluginmgr/plugins_common,gocode/src/pluginmgr/plugins_files -covermode=atomic ./src/pluginmgr/pluginmgr_test ./src/pluginmgr/pluginmgr_common
    if [ $? -ne 0 ]; then
        echo "Failed to run plugin manager test"
        exit -1
    fi
   
    go tool cover -html=coverprofile_plmgr.out -o /tmp/coverage_plmgr.html
    ls -l coverprofile_plmgr.out /tmp/coverage_plmgr.html
    echo "View /tmp/coverage_plmgr.html in Edge"
}

clean() {
    echo "run clean"
    rm -rf bin/*
    rm -rf pkg/*
    rm -rf bin/*
    rm -f coverprofile*.out
}

list() {
    tree0
}

cmd="None"

if [ $# -ne 0 ]; then
    cmd=$1
fi  

if [[ "install" == "$cmd"* ]]; then
    install

elif [[ "clean" == "$cmd"* ]]; then
    clean

elif [[ "list" == "$cmd"* ]]; then
    list

elif [[ "test" == "$cmd"* ]]; then
    test ""

elif [[ "test_plugin_mgr" == "$cmd"* ]]; then
    test_plugin_mgr ""

elif [[ "vtest" == "$cmd"* ]]; then
    test "-v"

elif [[ "etest" == "$cmd"* ]]; then
    etest ""

elif [[ "xetest" == "$cmd"* ]]; then
    etest "-v"

else
    echo "($cmd) match None"
    echo "install / test / clean"
fi
