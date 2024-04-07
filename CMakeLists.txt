cmake_minimum_required(VERSION 3.27)
project(pruebasC)

set(CMAKE_CXX_STANDARD 17)

add_executable(pruebasC
        main.c
        base58.c
        base58.h
        privateKey.c
        privateKey.h
)

# Link against the OpenSSL crypto library
target_link_libraries(pruebasC crypto)