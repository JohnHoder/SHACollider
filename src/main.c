#include <stdio.h>
#include "sha256.h"
#include "libbloom/bloom.h"

#define BITLEN 20
#define BLOOM_ELEMS 10000000
#define BLOOM_PROB 0.0001


size_t trim_hash(unsigned char* hash) {
	// trim the hash (in-place) to just the BITLEN prefix,
	// ie. pad it with 0s to whole bytes and return the (truncated) byte length
	size_t bits = BITLEN % 8;
	size_t len = bits ? (BITLEN / 8) + 1 : (BITLEN / 8);

	if (bits) {
		hash[len-1] = hash[len-1] & (0xFF << (8 - bits));
	}

	return len;
}

int main(void) {
	// 256 bits of stuff
	unsigned char data[SHA256_HASH_SIZE] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
	};

	// bloom filter for efficient in-memory collision detection
	struct bloom bloom;
	bloom_init(&bloom, BLOOM_ELEMS, BLOOM_PROB);

	// trim the initial data and insert that into the bloom filter
	size_t len = trim_hash(data);
	bloom_add(&bloom, data, len);

	unsigned long long steps = 1;
	for (;;) {
		// calculate hash of the first BITLEN bits of data
		SHA256_Context ctx;
		sha256_initialize(&ctx);
		sha256_add_bits(&ctx, &data, BITLEN);
		sha256_calculate(&ctx, data);

#ifdef DEBUG
		// debug print
		for (size_t i=0; i<SHA256_HASH_SIZE; i++) {
			printf("%02X", data[i]);
		}
		printf("\n");
#endif //DEBUG

		// trim the hash
		size_t len = trim_hash(data);

		// check if bloom filter already (probably) contains the hash
		if (bloom_check(&bloom, data, len)) {
			printf("Found possible collision after %llu steps :: ", steps);
			for (size_t i=0; i<len; i++) {
				printf("%02X", data[i]);
			}
			printf("\n");

			// TODO: need to make sure it wasn't a false positive
			// if it was then continue, else break
			// for now we always break
			break;
		}

		// add the trimmed hash to the bloom filter
		bloom_add(&bloom, data, len);

		// rinse and repeat
		steps++;
	}

	return 0;
}
