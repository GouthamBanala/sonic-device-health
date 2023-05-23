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
    go test $1 -coverprofile=coverprofile.out  -coverpkg lom/src/lib/lomipc,lom/src/lib/lomcommon -covermode=atomic ./src/lib/lib_test
    if [ $? -ne 0 ]; then
        echo "Failed to run test"
        exit -1
    fi
    go tool cover -html=coverprofile.out -o /tmp/coverage.html
    ls -l coverprofile.out /tmp/coverage.html
    echo "View /tmp/coverage.html in Edge"
}

dbClientTest() { 
  go test $1 -p 1 -coverprofile=dbclient_coverprofile.out� -coverpkg lom/src/vendors/sonic/client/dbclient -covermode=atomic lom/src/vendors/sonic/client/dbclient
  if [ $? -ne 0 ]; then
  	echo "Failed to run test"
  	exit -1
  fi
  cat ./dbclient_coverprofile.out* > dbclient_coverprofile.out
  go tool cover -html=dbclient_coverprofile.out -o /tmp/dbclient_coverage.html
  ls -l dbclient_coverprofile.out /tmp/dbclient_coverage.html
  echo "View /tmp/dbclient_coverage.html in Edge"

}

test_plugin_mgr() {
    #CGO_ENABLED=1 GORACE="log_path=/tmp/race/gou_report"  go test -race -v -p 1 -cover $1 -coverprofile=coverprofile_plmgr.out -coverpkg lom/src/pluginmgr/pluginmgr_common,lom/src/plugins/plugins_common,lom/src/plugins/plugins_files -covermode=atomic ./src/pluginmgr/pluginmgr_common 
    go test -v -p 1 -cover $1 -coverprofile=coverprofile_plmgr.out -coverpkg lom/src/pluginmgr/pluginmgr_common,lom/src/plugins/plugins_common,lom/src/plugins/plugins_files -covermode=atomic ./src/pluginmgr/pluginmgr_common ./src/plugins/plugins_common
    
    if [ $? -ne 0 ]; then
        echo "Failed to run plugin manager test"
        exit -1
    fi
   
    go tool cover -html=coverprofile_plmgr.out -o /tmp/coverage_plmgr.html
    ls -l coverprofile_plmgr.out /tmp/coverage_plmgr.html
    echo "View /tmp/coverage_plmgr.html in Edge"
}

test_plugins_common() {
    #CGO_ENABLED=1 GORACE="log_path=/tmp/race/gou_report"  go test -race -v -p 1 -cover $1 -coverprofile=coverprofile_plmgr.out -coverpkg lom/src/pluginmgr/pluginmgr_common,lom/src/plugins/plugins_common,lom/src/plugins/plugins_files -covermode=atomic ./src/plugins/plugins_common
    go test -v -p 1 -cover $1 -coverprofile=coverprofile_plmgr.out -coverpkg lom/src/pluginmgr/pluginmgr_common,lom/src/plugins/plugins_common,lom/src/plugins/plugins_files -covermode=atomic ./src/plugins/plugins_common
    
    if [ $? -ne 0 ]; then
        echo "Failed to run plugins common test"
        exit -1
    fi
   
    go tool cover -html=coverprofile_plmgr.out -o /tmp/coverage_plugins_common.html
    ls -l coverprofile_plugins_common.out /tmp/coverage_plugins_common.html
    echo "View /tmp/coverage_plugins_common.html in Edge"
}

clean() {
    echo "run clean"
    rm -rf bin/*
    rm -rf pkg/*
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

elif [[ "dbClientTest" == "$cmd"* ]]; then
    dbClientTest ""
    
elif [[ "test_plugin_mgr" == "$cmd"* ]]; then
    test_plugin_mgr ""

elif [[ "test_plugins_common" == "$cmd"* ]]; then
    test_plugins_common ""

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

