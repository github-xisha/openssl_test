#!/bin/bash

tools_path=$(dirname $(readlink -f "$0"))
project_path=${tools_path}/..

function buildOpenssl(){
    cd ${project_path}/external
    if [ ! -d openssl_v1.1.0 ]; then
        unzip openssl_v1.1.0.zip
    fi
    cd openssl_v1.1.0
    if [ ! -d build ]; then
        mkdir build
    fi
    ./config --prefix=${project_path}/external/openssl_v1.1.0/build --debug && make && make install
    cd build/lib
    rm -rf pkgconfig engines-1.1
    cp -r ${project_path}/external/openssl_v1.1.0/build/include/openssl ${project_path}/include
    cp -a ${project_path}/external/openssl_v1.1.0/build/lib ${project_path}/lib
}

buildOpenssl

