#include <stdio.h>
#include "sha256.h"


int main(void) {
	unsigned char data[] = { 0x00 };
	unsigned char hash[SHA256_HASH_SIZE];

	SHA256_Context ctx;
	sha256_initialize(&ctx);
	sha256_add_bits(&ctx, &data, 1);
	sha256_calculate(&ctx, hash);

	for (size_t i=0; i<SHA256_HASH_SIZE; i++) {
		printf("%02X", hash[i]);
	}
	printf("\n");

	return 0;
}
