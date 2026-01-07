#ifndef __SHA2_H__
#define __SHA2_H__

#include <stdint.h>

/* SHA256 context structure */
typedef struct {
	uint32_t state[8];
	uint32_t count[2];
	uint8_t buffer[64];
} sha256_ctx;

/* SHA256 initialization state */
extern const uint32_t sha256_init_state[8];

/* SHA256 transform function - processes one 64-byte block */
void sha256_transform(uint32_t *state, const uint8_t *input);

#endif /* __SHA2_H__ */
