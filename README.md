# bitcoin-hw

For educational purposes only.

## Descripción

Este proyecto es una implementación educativa de varias funcionalidades relacionadas con Bitcoin, incluyendo la generación de claves privadas y públicas, la conversión de claves privadas a formato WIF, la generación de direcciones P2PKH, y el cifrado de claves privadas utilizando el estándar BIP38.

## Requisitos

- `OpenSSL`
- `libscrypt`
- `libsecp256k1`
- `CMake`
- `GCC` o `Clang`

## Instalación

1. Clona el repositorio:
    ```sh
    git clone https://github.com/makrron/bitcoin-hw.git
    cd bitcoin-hw
    ```

2. Crea un directorio de compilación y navega a él:
    ```sh
    mkdir build
    cd build
    ```

3. Configura el proyecto con CMake:
    ```sh
    cmake ..
    ```

4. Compila el proyecto:
    ```sh
    make
    ```

## Uso

1. Asegúrate de tener un archivo `private_key.txt` en el directorio raíz del proyecto que contenga una clave privada en formato hexadecimal.

2. Ejecuta el binario generado:
    ```sh
    ./bin/bitcoin-hw
    ```

## Funcionalidades

- **Generación de Claves Privadas y Públicas**: Genera claves privadas y sus correspondientes claves públicas.
- **Conversión a WIF**: Convierte claves privadas a formato WIF.
- **Generación de Direcciones P2PKH**: Genera direcciones P2PKH a partir de claves públicas.
- **Cifrado BIP38**: Cifra claves privadas utilizando una contraseña según el estándar BIP38.

## Archivos Principales

- `src/main.c`: Contiene la función principal y ejemplos de uso de las funcionalidades.
- `src/bip38.c`: Implementación del cifrado BIP38.
- `src/bip38.h`: Declaraciones de funciones para el cifrado BIP38.
- `src/base58.c`: Funciones para la codificación Base58.
- `src/privateKey.c`: Funciones para la generación y manejo de claves privadas.
- `src/publicKey.c`: Funciones para la generación y manejo de claves públicas.
- `src/hex_bytes.c`: Funciones para la conversión entre hexadecimal y bytes.
- `src/pk2hash.c`: Funciones para la conversión de claves públicas a hashes.
- `src/generateAddress.c`: Funciones para la generación de direcciones Bitcoin.

## Contribuciones

Las contribuciones son bienvenidas. Por favor, abre un issue o un pull request para discutir cualquier cambio que te gustaría hacer.

## Licencia

Este proyecto está licenciado bajo la Licencia MIT. Consulta el archivo `LICENSE` para más detalles.