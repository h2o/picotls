CMAKE_MINIMUM_REQUIRED(VERSION 2.8.11)
CMAKE_POLICY(SET CMP0003 NEW)

PROJECT(picotls)

FIND_PACKAGE(OpenSSL REQUIRED)

SET(CMAKE_C_FLAGS "-Wall -O2 -g ${CC_WARNING_FLAGS} ${CMAKE_C_FLAGS}")
INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR} deps/micro-ecc deps/cifra/src/ext deps/cifra/src deps/picotest include)

ADD_EXECUTABLE(test-openssl.t deps/picotest/picotest.c t/picotls.c t/openssl.c)
ADD_EXECUTABLE(test-embedded.t deps/micro-ecc/uECC.c deps/cifra/src/aes.c deps/cifra/src/blockwise.c deps/cifra/src/chash.c deps/cifra/src/curve25519.c deps/cifra/src/drbg.c deps/cifra/src/hmac.c deps/cifra/src/gcm.c deps/cifra/src/gf128.c deps/cifra/src/modes.c deps/cifra/src/sha256.c deps/picotest/picotest.c t/picotls.c t/embedded.c)
TARGET_LINK_LIBRARIES(test-openssl.t ${OPENSSL_LIBRARIES})

ADD_CUSTOM_TARGET(check prove --exec '' -v ./*.t DEPENDS test-openssl.t)

ADD_EXECUTABLE(cli lib/picotls.c lib/openssl.c t/cli.c)
TARGET_LINK_LIBRARIES(cli ${OPENSSL_LIBRARIES})

IF ("${CMAKE_SYSTEM_NAME}" MATCHES "SunOS")
    TARGET_LINK_LIBRARIES(cli "socket" "nsl")
ENDIF ()
