cmake_minimum_required(VERSION 3.15)

project(SgxDcapQuoteVerifyPython)

set(CMAKE_CXX_STANDARD 17)

# Sanity checks with Clang Tidy (commented because only for dev)
# set(CMAKE_CXX_CLANG_TIDY clang-tidy -header-filter=main.h
# -checks=bugprone-*,cppcoreguidelines-*,portability-*,readability-*,clang-analyzer-*,modernize-*)

add_subdirectory(pybind11)

file(GLOB SOURCE_FILES src/*.cpp)

pybind11_add_module(_core ${SOURCE_FILES})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -Wuninitialized")

find_package(
  Qvl
  REQUIRED
  PATHS
  SGXDataCenterAttestationPrimitives/QuoteVerification/QVL/Src/Build/Release/dist/lib/cmake/Qvl/
)

target_compile_definitions(_core PRIVATE)
target_link_libraries(_core PRIVATE Qvl::AttestationLibraryStatic)
