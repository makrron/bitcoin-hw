#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "privateKey.h"


int main() {

    char *private_key = NULL;
    private_key = generate_private_key();
    printf("Private Key: %s\n", private_key);

    // Liberar la memoria
    free(private_key);

    return 0;
}

