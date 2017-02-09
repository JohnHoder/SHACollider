#include <stdio.h>
#include "sha256.h"
#include "libbloom/bloom.h"
#include "leveldb/include/leveldb/c.h"

#define BITLEN 43
#define BLOOM_ELEMS 50000000
#define BLOOM_PROB 0.0000000000001


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
	// 256 bits of "random" stuff
	unsigned char data[SHA256_HASH_SIZE] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
	};

	// initialize LevelDB
	leveldb_t *db;
	leveldb_options_t *options = leveldb_options_create();
	leveldb_readoptions_t *roptions = leveldb_readoptions_create();
	leveldb_writeoptions_t *woptions = leveldb_writeoptions_create();
	char *err = NULL;
	char *read;
	size_t read_len;

	leveldb_options_set_create_if_missing(options, 1);
	db = leveldb_open(options, "shadb", &err);

	if (err != NULL) {
		printf("Failed to create/open the LevelDB database.\n");
		return 1;
	}

	leveldb_free(err);
	err = NULL;

	// bloom filter for efficient in-memory collision detection
	struct bloom bloom;
	if (bloom_init(&bloom, BLOOM_ELEMS, BLOOM_PROB)) {
		printf("Failed to init bloom filter! Tried to allocate %.2f MB.\n",
				(double) bloom.bytes / 1024 / 1024);
		bloom_print(&bloom);
		return 1;
	}
	printf("Bloom filter using %ld bytes (%.2f MB) with %.2f bits per element.\n",
			bloom.bytes, (double) bloom.bytes / 1024 / 1024, bloom.bpe);

	// trim the initial data and insert that into the bloom filter & db
	size_t len = trim_hash(data);
	bloom_add(&bloom, data, len);
	leveldb_put(db, woptions, (char*) data, len, "", 0, &err);

	if (err != NULL) {
		printf("LevelDB write fail!\n");
		return 1;
	}

	leveldb_free(err);
	err = NULL;

	unsigned long long steps = 1;
	for(;;) {
		// calculate hash of the first BITLEN bits of data
		SHA256_Context ctx;
		sha256_initialize(&ctx);
		sha256_add_bits(&ctx, &data, BITLEN);
		sha256_calculate(&ctx, data);

#ifdef DEBUG
		// debug print
		for (size_t i=0; i<len; i++) {
			printf("%02X", data[i]);
		}
		printf("\n");
#endif //DEBUG

		// trim the hash
		size_t len = trim_hash(data);

		// check if bloom filter already (probably) contains the hash
		if (bloom_check(&bloom, data, len)) {
			printf("Found possible collision after %llu iterations :: ", steps);
			for (size_t i=0; i<len; i++) {
				printf("%02X", data[i]);
			}
			printf("\n");

			// need to make sure it wasn't a false positive
			// by searching for the hash in LevelDB
			// if it's not found then continue, else break
			read = leveldb_get(db, roptions, (char*) data, len, &read_len, &err);

			if (err != NULL) {
				printf("LevelDB read fail!\n");
				return 1;
			}

			leveldb_free(err);
			err = NULL;

			if (read == NULL) {
				// not found
				printf("Candidate collision hash was a false positive.\n");
				continue;
			} else {
				printf("LevelDB confirmed the collision! \\o/\n");
				break;
			}
		}

		// add the trimmed hash to the bloom filter
		bloom_add(&bloom, data, len);
		// ...and to the database
		leveldb_put(db, woptions, (char*) data, len, "", 0, &err);

		if (steps >= BLOOM_ELEMS) {
			// continuing would drastically increase false-positive rate
			printf("Bloom filter capacity exceeded, exiting.\n");
			break;
		} else {
			// rinse and repeat
			steps++;
			continue;
		}
	}

	bloom_free(&bloom);

	leveldb_close(db);
	leveldb_destroy_db(options, "shadb", &err);

	if (err != NULL) {
		printf("%s\n", err);
		printf("Failed to destroy LevelDB!\n");
		return 1;
	}

	leveldb_free(err);
	err = NULL;

	return 0;
}
