/*
   Test proceduce
   1. Unlock phantomdrive with your password: "pineapple", or whatever, just change the C below.
   2. Create a partition, move some data there. Call sync.
   3. Unmount, Remove USB drive, remove SD card from drive, insert SD to PC.
   5. make kdf && ./kdf /dev/sdX
   6. You should now have unencrypted.blob
   7. This can now be mounted $ sudo losetup -Pf --show *.img # Setup
*/

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include <openssl/aes.h>

#include "../src/crypto.h"
#include "../src/phantomdrive.h"

#define KEY_SIZE 32
#define SECTOR_SIZE 512
#define START_LBA LOCKED_SECTORS
#define INPUT_SKIP_SECTORS START_LBA
#define CHUNK_SIZE (1024 * 1024)

static void u32be(unsigned char *p, uint32_t x)
{
	p[0] = x >> 24;
	p[1] = x >> 16;
	p[2] = x >> 8;
	p[3] = x;
}

static void ecdc_key_to_aes_key(uint8_t aes_key[32], const uint8_t ecdc_key[32])
{
	for (int i = 0; i < 32; i++)
		aes_key[i] = ecdc_key[31 - i];
}

void decrypt(const char* blob, uint8_t key[32]) {
	int fd = open(blob, O_RDONLY);
	if (fd < 0) {
		perror(blob);
		return;
	}

	off_t size = lseek(fd, 0, SEEK_END);
	if (size < 0) {
		perror("lseek");
		close(fd);
		return;
	}

	off_t input_start = (off_t)INPUT_SKIP_SECTORS * SECTOR_SIZE;
	if (input_start > size) {
		fprintf(stderr, "%s is smaller than INPUT_SKIP_SECTORS\n", blob);
		close(fd);
		return;
	}

	size -= input_start;
	if (lseek(fd, input_start, SEEK_SET) < 0) {
		perror("lseek");
		close(fd);
		return;
	}

	unsigned char *buf = malloc(CHUNK_SIZE);
	if (!buf) {
		perror("malloc");
		close(fd);
		return;
	}

	int out = open("unencrypted.blob", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (out < 0) {
		perror("unencrypted.blob");
		close(fd);
		free(buf);
		return;
	}

	AES_KEY aes_key;
	uint8_t openssl_key[32];
	ecdc_key_to_aes_key(openssl_key, key);
	AES_set_encrypt_key(openssl_key, 256, &aes_key);

	off_t total = 0;
	while (total < size) {
		size_t wanted = CHUNK_SIZE;
		if ((off_t)wanted > size - total)
			wanted = (size_t)(size - total);

		ssize_t n = read(fd, buf, wanted);
		if (n < 0) {
			perror("read");
			break;
		}
		if (n == 0)
			break;

		for (ssize_t off = 0; off < n; off += AES_BLOCK_SIZE) {
			off_t abs_off = total + off;
			uint32_t lba = START_LBA + (uint32_t)(abs_off / SECTOR_SIZE);
			uint32_t block = (uint32_t)((abs_off % SECTOR_SIZE) / AES_BLOCK_SIZE);
			unsigned char ctr[AES_BLOCK_SIZE] = {0};
			unsigned char stream[AES_BLOCK_SIZE];

			/* ECDC registers hold low counter word first; AES sees the 128-bit value big-endian. */
			u32be(ctr + 8, lba);
			u32be(ctr + 12, block);

			AES_encrypt(ctr, stream, &aes_key);

			for (int i = 0; i < AES_BLOCK_SIZE && off + i < n; i++)
				buf[off + i] ^= stream[i];
		}

		if (write(out, buf, (size_t)n) != n) {
			perror("write");
			break;
		}

		total += n;
	}

	close(fd);
	close(out);

	free(buf);
}

static int parse_uid_hex(const char *hex, uint8_t uid[8])
{
	if (strlen(hex) != 16) return -1;
	for (int i = 0; i < 8; i++) {
		unsigned int byte;
		if (sscanf(hex + i * 2, "%02x", &byte) != 1) return -1;
		uid[i] = (uint8_t)byte;
	}
	return 0;
}

int main(int argc, char *argv[]) {
	/* Usage: ./kdf <device> <uid_hex>
	 * uid_hex: 16 hex chars (8 bytes) — read from USB serial number descriptor
	 * before the drive re-enumerates, e.g. with: lsusb -v | grep iSerial */
    const uint8_t password[] = "pineapple";
	uint8_t key_bytes[KEY_SIZE];
	uint8_t uid[8] = {0};

	if (argc < 3) {
		printf("Usage: ./kdf <device> <uid_hex>\n");
		printf("  uid_hex: 16 hex chars from USB serial number (iSerial)\n");
		printf("  Example: ./kdf /dev/sdX 0102030405060708\n");
		return 1;
	}

	printf("Using block device: %s\n", argv[1]);

	if (parse_uid_hex(argv[2], uid) != 0) {
		fprintf(stderr, "uid_hex must be exactly 16 hex characters\n");
		return 1;
	}

	derive_key(password, strlen((const char *)password), uid, sizeof(uid), key_bytes);

	printf("Key: ");
	for (int i = 0; i < KEY_SIZE; i++)
		printf("%02x", key_bytes[i]);
	printf("\n");

	decrypt(argv[1], key_bytes);

	return 0;
}
