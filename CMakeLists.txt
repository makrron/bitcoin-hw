cmake_minimum_required(VERSION 3.27)
project(bitcoin-hw)

# Establecer el estándar de C a usar, C11
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Incluir directorios
include_directories(include)

# Especificar el directorio de los ejecutables
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

# Agregar el ejecutable
add_executable(bitcoin-hw
        src/main.c
        src/base58.c
        src/privateKey.c
        src/publicKey.c
        src/hex_bytes.c
        src/pk2hash.c
        src/generateAddress.c
        src/signature.c
        src/bip38.c
        include/bip38.h
)

# Enlazar contra la biblioteca criptográfica OpenSSL
target_link_libraries(bitcoin-hw crypto)

# Enlazar contra la biblioteca secp256k1
target_link_libraries(bitcoin-hw secp256k1)

# Enlazar con libscrypt
find_library(SCRYPT_LIB scrypt REQUIRED PATHS /usr/local/lib)  # Ajusta la ruta según sea necesario
target_link_libraries(bitcoin-hw ${SCRYPT_LIB})