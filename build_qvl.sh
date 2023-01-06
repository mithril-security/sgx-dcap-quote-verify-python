#!/bin/bash


# Copyright (c) 2017-2018, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

set -e

cd SGXDataCenterAttestationPrimitives/QuoteVerification/QVL/Src/

BUILD_ATTESTATION_APP=OFF
BUILD_TESTS=OFF
BUILD_DOCS=OFF

mkdir -p cmake-build-release
pushd cmake-build-release 
cmake ../ -DBUILD_DOCS=$BUILD_DOCS \
          -DBUILD_ATTESTATION_APP=$BUILD_ATTESTATION_APP \
          -DBUILD_TESTS=$BUILD_TESTS \
          -DCMAKE_C_COMPILER=gcc \
          -DCMAKE_CXX_COMPILER=g++ \
          -DCMAKE_BUILD_TYPE=Release \
          -G "CodeBlocks - Unix Makefiles" \
          --graphviz=graph/test.dot \
          "$@"
make -j20 AttestationLibraryStatic AttestationCommonsStatic AttestationParsersStatic AttestationLibraryStatic
make install
 
popd

# dot -Tpng -o foo.png /workspaces/yassine/draft/SGXDataCenterAttestationPrimitives/QuoteVerification/QVL/Src/cmake-build-release/graph/test.dot
