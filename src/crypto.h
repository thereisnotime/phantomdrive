#ifndef CRYPTO_H_
#define CRYPTO_H_

#include <stdint.h>
#include <stddef.h>

/* SHA-256: compute hash of data into 32-byte output */
void sha256(const uint8_t *data, size_t len, uint8_t hash_out[32]);

/* KDF: derive 32-byte AES-256 key from password via iterated SHA-256.
 * Caller supplies a per-device salt (e.g. chip UID) so that keys are
 * device-specific and pre-built rainbow tables don't cross devices.
 * Round 0: key = SHA256(salt || password), then KDF_ROUNDS times:
 * key = SHA256(key || password). */
void derive_key(const uint8_t *password, size_t pw_len,
                const uint8_t *salt, size_t salt_len,
                uint8_t key_out[32]);

#endif /* CRYPTO_H_ */
