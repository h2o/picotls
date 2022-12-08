
find_path(BORINGSSL_ROOT_DIR
    NAMES include/openssl/ssl.h include/openssl/base.h include/openssl/hkdf.h
    HINTS ${BORINGSSL_ROOT_DIR})

find_path(BORINGSSL_INCLUDE_DIR
    NAMES openssl/ssl.h openssl/base.h openssl/hkdf.h
    HINTS ${BORINGSSL_ROOT_DIR}/include)

find_library(BORINGSSL_CRYPTO_LIBRARY
    NAMES libcrypto.a
    HINTS ${BORINGSSL_ROOT_DIR}/build/crypto)

find_library(BORINGSSL_DECREPIT_LIBRARY
    NAMES libdecrepit.a
    HINTS ${BORINGSSL_ROOT_DIR}/build/decrepit)

set(BORINGSSL_LIBRARIES ${BORINGSSL_SSL_LIBRARY} ${BORINGSSL_CRYPTO_LIBRARY} ${BORINGSSL_DECREPIT_LIBRARY}
    CACHE STRING "BoringSSL SSL and crypto libraries" FORCE)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(BoringSSL DEFAULT_MSG
    BORINGSSL_LIBRARIES
    BORINGSSL_INCLUDE_DIR)

mark_as_advanced(
    BORINGSSL_ROOT_DIR
    BORINGSSL_INCLUDE_DIR
    BORINGSSL_LIBRARIES
    BORINGSSL_CRYPTO_LIBRARY
    BORINGSSL_DECREPIT_LIBRARY
)
