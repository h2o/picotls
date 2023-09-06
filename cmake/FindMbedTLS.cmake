# - Try to find MbedTLS
# set(MBEDTLS_LIBRARY mbedtls)
# set(MBEDTLS_INCLUDE_DIRS ${MBEDTLS_SOURCE_DIR}/include)
find_path(MBEDTLS_INCLUDE_DIRS
    NAMES mbedtls/build_info.h psa/crypto.h
    HINTS ${MBEDTLS_PREFIX}/include/
        ${CMAKE_SOURCE_DIR}/../mbedtls/include/
        ${CMAKE_BINARY_DIR}/../mbedtls/include/
        ../mbedtls/include/ )

set(MBEDTLS_HINTS ${MBEDTLS_PREFIX}/build ${CMAKE_BINARY_DIR}/../mbedtls/build ../mbedtls/build)

find_library(MBEDTLS_LIBRARY mbedtls HINTS ${MBEDTLS_HINTS})

mark_as_advanced(MBEDTLS_LIBRARY MBEDTLS_INCLUDE_DIRS)
