# Try to find MbedTLS; recognized hints are:
#  * MBEDTLS_ROOT_DIR
#  * MBEDTLS_LIBDIR
# Upon return,
#  * MBEDTLS_INCLUDE_DIRS
#  * MBEDTLS_LIBRARIES
# will be set.
# Users may supply MBEDTLS_INCLUDE_DIRS or MBEDTLS_LIBRARIES directly.

INCLUDE(FindPackageHandleStandardArgs)

# setup default vars for the hints
IF (NOT DEFINED MBEDTLS_ROOT_DIR)
    SET(MBEDTLS_ROOT_DIR "/usr/local" "/usr")
ENDIF ()
IF (NOT DEFINED MBEDTLS_LIBDIR)
    SET(MBEDTLS_LIBDIR)
    FOREACH (item IN LISTS MBEDTLS_ROOT_DIR)
        LIST(APPEND MBEDTLS_LIBDIR "${item}/lib")
    ENDFOREACH ()
ENDIF ()

# find include directory
IF (NOT DEFINED MBEDTLS_INCLUDE_DIRS)
    SET(HINTS)
    FOREACH (item IN LISTS MBEDTLS_ROOT_DIR)
        LIST(APPEND HINTS "${item}/include")
    ENDFOREACH ()
    FIND_PATH(MBEDTLS_INCLUDE_DIRS
        NAMES mbedtls/build_info.h psa/crypto.h
        HINTS $HINTS)
ENDIF ()

# find libraries
FIND_LIBRARY(MBEDTLS_LIBRARY mbedtls HINTS ${MBEDTLS_LIBDIR})
FIND_LIBRARY(MBEDTLS_X509 mbedx509 HINTS ${MBEDTLS_LIBDIR})
FIND_LIBRARY(MBEDTLS_CRYPTO mbedcrypto HINTS ${MBEDTLS_LIBDIR})

# setup.
# Mbedtls depends on mbedtls x509 and mbedtls crypto.
# Mbedtls x509 depends on mbedtls crypto
# The order of libraries must be mbetls, then x509, then crypto,
# in order to avoid linker issues.
FIND_PACKAGE_HANDLE_STANDARD_ARGS(MbedTLS REQUIRED_VARS
    MBEDTLS_LIBRARY
    MBEDTLS_X509
    MBEDTLS_CRYPTO
    MBEDTLS_INCLUDE_DIRS)
IF (MbedTLS_FOUND)
    SET(MBEDTLS_LIBRARIES ${MBEDTLS_LIBRARY} ${MBEDTLS_X509} ${MBEDTLS_CRYPTO})
    MARK_AS_ADVANCED(MBEDTLS_LIBRARIES MBEDTLS_INCLUDE_DIRS)
ENDIF ()
