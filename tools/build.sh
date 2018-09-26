#!/bin/bash

tools_path=$(dirname $(readlink -f "$0"))
project_path=${tools_path}/..

function buildOpensslTest(){
    cd ${project_path}/src/
    if [ ! -d build ]; then
        mkdir build
    fi
    cd build
    cmake ..
    make
}

buildOpensslTest

