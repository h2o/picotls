# - Try to find MbedTLS
# set(MBEDTLS_LIBRARY mbedtls)
# set(MBEDTLS_INCLUDE_DIRS ${MBEDTLS_SOURCE_DIR}/include)
find_path(MBEDTLS_INCLUDE_DIRS
    NAMES mbedtls/build_info.h psa/crypto.h
    HINTS ${MBEDTLS_PREFIX}/include/
        ${CMAKE_SOURCE_DIR}/../mbedtls/include/
        ${CMAKE_BINARY_DIR}/../mbedtls/include/
        ../mbedtls/include/ )



set(MBEDTLS_HINTS ${MBEDTLS_PREFIX}/build/library 
    ${CMAKE_BINARY_DIR}/../mbedtls/build/library
    ../mbedtls/build/library ../mbedtls/library)

find_library(MBEDTLS_LIBRARY mbedtls HINTS ${MBEDTLS_HINTS})
find_library(MBEDTLS_CRYPTO mbedcrypto HINTS ${MBEDTLS_HINTS})
find_library(MBEDTLS_X509 mbedx509 HINTS ${MBEDTLS_HINTS})
include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set PTLS_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(MbedTLS REQUIRED_VARS
    MBEDTLS_LIBRARY
    MBEDTLS_CRYPTO
    MBEDTLS_X509
    MBEDTLS_INCLUDE_DIRS)
    
if(MbedTLS_FOUND)
    set(MBEDTLS_LIBRARIES ${MBEDTLS_LIBRARY} ${MBEDTLS_CRYPTO} ${MBEDTLS_X509})
    mark_as_advanced(MBEDTLS_LIBRARIES MBEDTLS_INCLUDE_DIRS)
