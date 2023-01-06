cmake_minimum_required(VERSION 3.4...3.18)

#hunter has to be imported before 'project()'
set(HUNTER_STATUS_DEBUG OFF) #set to 'ON' to see debug hunter logs

option(HUNTER_NO_TOOLCHAIN_ID_RECALCULATION "No Toolchain-ID recalculation" ON)
option(HUNTER_KEEP_PACKAGE_SOURCES "Keep third party sources" ON)

include("${CMAKE_CURRENT_SOURCE_DIR}/SGXDataCenterAttestationPrimitives/QuoteVerification/QVL/Src/ThirdParty/hunter/HunterGate.cmake")
HunterGate(
		URL "https://github.com/cpp-pm/hunter/archive/v0.23.316.tar.gz"
		SHA1 "167a33c4cc398504826a1a3014ef66f9ccc35db3"
		FILEPATH "${CMAKE_CURRENT_SOURCE_DIR}/SGXDataCenterAttestationPrimitives/QuoteVerification/QVL/Src/ThirdParty/hunter/config.cmake"
)

project(cmake_example)

set(CMAKE_CXX_STANDARD 17)

# Sanity checks with Clang Tidy (commented because only for dev)
# set(CMAKE_CXX_CLANG_TIDY clang-tidy -header-filter=main.h
# -checks=bugprone-*,cppcoreguidelines-*,portability-*,readability-*,clang-analyzer-*,modernize-*)

add_subdirectory(pybind11)

hunter_add_package(OpenSSL)
find_package(OpenSSL 1.1.1 EXACT REQUIRED)

file(GLOB SOURCE_FILES src/*.cpp)

pybind11_add_module(_core ${SOURCE_FILES})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Werror -Wuninitialized")




add_library(AttestationLibraryStatic STATIC IMPORTED)
set_property(
  TARGET AttestationLibraryStatic
  PROPERTY
    IMPORTED_LOCATION
    "${CMAKE_CURRENT_SOURCE_DIR}/SGXDataCenterAttestationPrimitives/QuoteVerification/QVL/Src/Build/Release/dist/lib/libQuoteVerificationStatic.a"
)
target_include_directories(
  AttestationLibraryStatic
  INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/SGXDataCenterAttestationPrimitives/QuoteVerification/QVL/Src/Build/Release/dist/include/"
)

add_library(AttestationCommonsStatic STATIC IMPORTED)
set_property(
  TARGET AttestationCommonsStatic
  PROPERTY
    IMPORTED_LOCATION
    "${CMAKE_CURRENT_SOURCE_DIR}/SGXDataCenterAttestationPrimitives/QuoteVerification/QVL/Src/Build/Release/dist/lib/libAttestationCommonsStatic.a"
)

add_library(AttestationParsersStatic STATIC IMPORTED)
set_property(
  TARGET AttestationParsersStatic
  PROPERTY
    IMPORTED_LOCATION
    "${CMAKE_CURRENT_SOURCE_DIR}/SGXDataCenterAttestationPrimitives/QuoteVerification/QVL/Src/Build/Release/dist/lib/libAttestationParsersStatic.a"
)
target_include_directories(
  AttestationParsersStatic
  INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/SGXDataCenterAttestationPrimitives/QuoteVerification/QVL/Src/Build/Release/dist/include/"
)

target_compile_definitions(_core PRIVATE)
target_link_libraries(
  _core PRIVATE OpenSSL::Crypto AttestationLibraryStatic
                AttestationParsersStatic AttestationCommonsStatic)
