#!/bin/bash
echo "building reaperfish in docker container"
cd /rf

#export GOPATH="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>&1 > /dev/null; pwd)"
export GOPATH="/rf"
export GO111MODULE=auto
export GOFLAGS=-mod=vendor
#export PATH="${GOPATH}/bin:${PATH}"

go build reaper.go
if [ $? -eq 0 ]; then
        echo -e "\e[32mSuccess\e[0m"
else
        echo -e "\e[41mFail\e[0m"
fi
