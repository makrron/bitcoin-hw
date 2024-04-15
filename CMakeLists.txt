cmake_minimum_required(VERSION 3.27)
project(pruebasC)

# Establecer el estándar de C a usar, asumiendo que es C11 si no se usa C++
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Incluir directorios
include_directories(include)

# Especificar el directorio de los ejecutables
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

# Agregar el ejecutable
add_executable(pruebasC
        src/main.c
        src/base58.c
        src/privateKey.c
        src/publicKey.c
        src/hex_bytes.c
        src/pk2hash.c
        src/generateAddress.c
        src/signature.c
)

# Incluir el directorio para archivos de cabecera
target_include_directories(pruebasC PRIVATE include)

# Enlazar contra la biblioteca criptográfica OpenSSL
target_link_libraries(pruebasC crypto)

# Enlazar contra la biblioteca secp256k1
target_link_libraries(pruebasC secp256k1)
