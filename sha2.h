#ifndef __SHA2_H__
#define __SHA2_H__

#include <stdint.h>

/* SHA256 transform function - processes one 64-byte block */
void sha256_transform(uint32_t *state, const uint8_t *input);

#endif /* __SHA2_H__ */
