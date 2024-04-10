cmake_minimum_required(VERSION 3.27)
project(pruebasC)

set(CMAKE_CXX_STANDARD 17)

add_executable(pruebasC
        base58.c
        base58.h
        privateKey.c
        privateKey.h
        publicKey.h
        publicKey.c
        hex_to_bytes.c
        hex_to_bytes.h
        main.c
)

# Link against the OpenSSL crypto library
target_link_libraries(pruebasC crypto)
# Añadir -lsecp256k1 para enlazar contra libsecp256k1
target_link_libraries(pruebasC -lsecp256k1)
