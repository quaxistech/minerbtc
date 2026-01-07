# ASIC-MOD: Version Rolling Implementation

## Overview

This modification to the cpuminer codebase implements a custom "Version Rolling" strategy for Bitcoin mining research purposes. The implementation injects a version rolling loop inside the mining thread to test different block version values.

## Key Changes

### 1. Global Constants (cpu-miner.c, line ~250)

Added a static array `MAGIC_VERSIONS` containing 10 specific uint32_t values:
```c
static const uint32_t MAGIC_VERSIONS[10] = {
    0x3fffe000, 0x3fff0000, 0x3c000000, 0x3e000000, 0x38000000,
    0x3a000000, 0x36000000, 0x30000000, 0x32000000, 0x34000000
};
```

### 2. Midstate Recalculation Function (cpu-miner.c, line ~308)

Implemented `recalc_midstate(struct work *work)` function that:
- Initializes SHA-256 state with standard initial values
- Processes the first 64 bytes of work->data
- Calculates the SHA-256 compression state (midstate)
- Stores the result in work->midstate

This ensures that when the version field (work.data[0]) is modified, the proof-of-work remains mathematically valid.

### 3. Mining Loop Modifications (cpu-miner.c, line ~618)

#### Version Rolling Loop
The miner_thread function now includes:

**Pre-loop Reporting**: 
- Logs block changes with best version found for previous block
- Format: `[ASIC-MOD][BLOCK-CHANGE] Prev Block Best Share found with Version: 0x%08x | Difficulty: %.2f`

**Version Rolling Loop**:
- Iterates through all 10 MAGIC_VERSIONS for each work unit
- For each version:
  1. Applies version to work.data[0]
  2. Recalculates midstate via recalc_midstate()
  3. Calls the appropriate scanhash function (scanhash_c, scanhash_sse2_64, etc.)
  4. If a share is found, logs success and updates best version tracker

**Telemetry Logging**:
- Debug level: Logs each version being tested
- Notice level: Logs successful shares with version information
- Format: `[ASIC-MOD][EXP-SUCCESS] Share accepted! Version: 0x%08x`

### 4. Endianness Handling

The implementation correctly handles endianness:
- work.data from getwork protocol is already in network byte order
- Version field (work.data[0]) can be set directly without byte swapping
- No swab32 needed (this would be required for stratum protocol, but this miner uses getwork)

## Building

```bash
./autogen.sh
CFLAGS="-O3 -Wall" ./configure
make
```

## Usage

Run the miner as usual. The version rolling is automatic:

```bash
./minerd --url http://127.0.0.1:8332/ --user rpcuser --pass rpcpass
```

For verbose output showing version testing:
```bash
./minerd --url http://127.0.0.1:8332/ --user rpcuser --pass rpcpass --debug
```

## Logging

All ASIC-MOD related logs are prefixed with `[ASIC-MOD]`:

- `[ASIC-MOD][BLOCK-CHANGE]` - Reports best version from previous block
- `[ASIC-MOD]` (DEBUG) - Reports which version is being tested
- `[ASIC-MOD][EXP-SUCCESS]` - Reports successful shares with version information

## Technical Notes

1. **Performance Impact**: Each work unit now tests 10 different versions, which increases the total computation time by approximately 10x per work unit.

2. **Thread Safety**: Each mining thread maintains its own static tracking variables for best version/difficulty per block.

3. **Compatibility**: Works with all supported SHA-256 algorithm implementations (C, 4WAY, SSE2_64, VIA, CRYPTOPP, etc.)

4. **Share Submission**: Each successful share is submitted independently, allowing the pool to accept multiple shares per work unit if multiple versions find valid solutions.

## Research Purpose

This modification is designed for research into version rolling strategies. It allows testing how different version field values affect share discovery rates and mining efficiency.
