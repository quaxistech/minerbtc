
/*
 * Copyright 2010 Jeff Garzik
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "cpuminer-config.h"
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#ifndef WIN32
#include <sys/resource.h>
#endif
#include <getopt.h>
#include <jansson.h>
#include <curl/curl.h>
#include "compat.h"
#include "miner.h"

/* SHA256 context for midstate recalculation */
typedef struct {
	uint32_t state[8];
	uint64_t count;
	unsigned char buffer[64];
} sha256_ctx;

/* Magic versions to test */
static const uint32_t MAGIC_VERSIONS[10] = {
	0x3fffe000, 0x3fff0000, 0x3c000000, 0x3e000000, 0x38000000,
	0x3a000000, 0x36000000, 0x30000000, 0x32000000, 0x34000000
};

#define PROGRAM_NAME		"minerd"
#define DEF_RPC_URL		"http://127.0.0.1:8332/"
#define DEF_RPC_USERNAME	"rpcuser"
#define DEF_RPC_PASSWORD	"rpcpass"
#define DEF_RPC_USERPASS	DEF_RPC_USERNAME ":" DEF_RPC_PASSWORD

#ifdef __linux /* Linux specific policy and affinity management */
#include <sched.h>
static inline void drop_policy(void)
{
	struct sched_param param;

#ifdef SCHED_IDLE
	if (unlikely(sched_setscheduler(0, SCHED_IDLE, &param) == -1))
#endif
#ifdef SCHED_BATCH
		sched_setscheduler(0, SCHED_BATCH, &param);
#endif
}

static inline void affine_to_cpu(int id, int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	sched_setaffinity(0, sizeof(&set), &set);
	applog(LOG_INFO, "Binding thread %d to cpu %d", id, cpu);
}
#else
static inline void drop_policy(void)
{
}

static inline void affine_to_cpu(int id, int cpu)
{
}
#endif

/* SHA256 helper functions for midstate calculation */
static inline uint32_t ror32(uint32_t word, unsigned int shift)
{
	return (word >> shift) | (word << (32 - shift));
}

static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z)
{
	return z ^ (x & (y ^ z));
}

static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z)
{
	return (x & y) | (z & (x | y));
}

#define e0(x)       (ror32(x, 2) ^ ror32(x,13) ^ ror32(x,22))
#define e1(x)       (ror32(x, 6) ^ ror32(x,11) ^ ror32(x,25))
#define s0(x)       (ror32(x, 7) ^ ror32(x,18) ^ (x >> 3))
#define s1(x)       (ror32(x,17) ^ ror32(x,19) ^ (x >> 10))

static void sha256_transform_local(uint32_t *state, const unsigned char *input)
{
	uint32_t a, b, c, d, e, f, g, h, t1, t2;
	uint32_t W[64];
	int i;

	/* load the input */
	for (i = 0; i < 16; i++)
		W[i] = ((uint32_t*)(input))[i];

	/* blend */
	for (i = 16; i < 64; i++)
		W[i] = s1(W[i-2]) + W[i-7] + s0(W[i-15]) + W[i-16];

	/* load state */
	a=state[0];  b=state[1];  c=state[2];  d=state[3];
	e=state[4];  f=state[5];  g=state[6];  h=state[7];

	/* iterate - simplified version with only necessary rounds */
	t1 = h + e1(e) + Ch(e,f,g) + 0x428a2f98 + W[ 0]; t2 = e0(a) + Maj(a,b,c); d+=t1; h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0x71374491 + W[ 1]; t2 = e0(h) + Maj(h,a,b); c+=t1; g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0xb5c0fbcf + W[ 2]; t2 = e0(g) + Maj(g,h,a); b+=t1; f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0xe9b5dba5 + W[ 3]; t2 = e0(f) + Maj(f,g,h); a+=t1; e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x3956c25b + W[ 4]; t2 = e0(e) + Maj(e,f,g); h+=t1; d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0x59f111f1 + W[ 5]; t2 = e0(d) + Maj(d,e,f); g+=t1; c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x923f82a4 + W[ 6]; t2 = e0(c) + Maj(c,d,e); f+=t1; b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0xab1c5ed5 + W[ 7]; t2 = e0(b) + Maj(b,c,d); e+=t1; a=t1+t2;
	t1 = h + e1(e) + Ch(e,f,g) + 0xd807aa98 + W[ 8]; t2 = e0(a) + Maj(a,b,c); d+=t1; h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0x12835b01 + W[ 9]; t2 = e0(h) + Maj(h,a,b); c+=t1; g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0x243185be + W[10]; t2 = e0(g) + Maj(g,h,a); b+=t1; f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0x550c7dc3 + W[11]; t2 = e0(f) + Maj(f,g,h); a+=t1; e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x72be5d74 + W[12]; t2 = e0(e) + Maj(e,f,g); h+=t1; d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0x80deb1fe + W[13]; t2 = e0(d) + Maj(d,e,f); g+=t1; c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x9bdc06a7 + W[14]; t2 = e0(c) + Maj(c,d,e); f+=t1; b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0xc19bf174 + W[15]; t2 = e0(b) + Maj(b,c,d); e+=t1; a=t1+t2;
	t1 = h + e1(e) + Ch(e,f,g) + 0xe49b69c1 + W[16]; t2 = e0(a) + Maj(a,b,c); d+=t1; h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0xefbe4786 + W[17]; t2 = e0(h) + Maj(h,a,b); c+=t1; g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0x0fc19dc6 + W[18]; t2 = e0(g) + Maj(g,h,a); b+=t1; f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0x240ca1cc + W[19]; t2 = e0(f) + Maj(f,g,h); a+=t1; e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x2de92c6f + W[20]; t2 = e0(e) + Maj(e,f,g); h+=t1; d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0x4a7484aa + W[21]; t2 = e0(d) + Maj(d,e,f); g+=t1; c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x5cb0a9dc + W[22]; t2 = e0(c) + Maj(c,d,e); f+=t1; b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0x76f988da + W[23]; t2 = e0(b) + Maj(b,c,d); e+=t1; a=t1+t2;
	t1 = h + e1(e) + Ch(e,f,g) + 0x983e5152 + W[24]; t2 = e0(a) + Maj(a,b,c); d+=t1; h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0xa831c66d + W[25]; t2 = e0(h) + Maj(h,a,b); c+=t1; g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0xb00327c8 + W[26]; t2 = e0(g) + Maj(g,h,a); b+=t1; f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0xbf597fc7 + W[27]; t2 = e0(f) + Maj(f,g,h); a+=t1; e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0xc6e00bf3 + W[28]; t2 = e0(e) + Maj(e,f,g); h+=t1; d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0xd5a79147 + W[29]; t2 = e0(d) + Maj(d,e,f); g+=t1; c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x06ca6351 + W[30]; t2 = e0(c) + Maj(c,d,e); f+=t1; b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0x14292967 + W[31]; t2 = e0(b) + Maj(b,c,d); e+=t1; a=t1+t2;
	t1 = h + e1(e) + Ch(e,f,g) + 0x27b70a85 + W[32]; t2 = e0(a) + Maj(a,b,c); d+=t1; h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0x2e1b2138 + W[33]; t2 = e0(h) + Maj(h,a,b); c+=t1; g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0x4d2c6dfc + W[34]; t2 = e0(g) + Maj(g,h,a); b+=t1; f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0x53380d13 + W[35]; t2 = e0(f) + Maj(f,g,h); a+=t1; e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x650a7354 + W[36]; t2 = e0(e) + Maj(e,f,g); h+=t1; d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0x766a0abb + W[37]; t2 = e0(d) + Maj(d,e,f); g+=t1; c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x81c2c92e + W[38]; t2 = e0(c) + Maj(c,d,e); f+=t1; b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0x92722c85 + W[39]; t2 = e0(b) + Maj(b,c,d); e+=t1; a=t1+t2;
	t1 = h + e1(e) + Ch(e,f,g) + 0xa2bfe8a1 + W[40]; t2 = e0(a) + Maj(a,b,c); d+=t1; h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0xa81a664b + W[41]; t2 = e0(h) + Maj(h,a,b); c+=t1; g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0xc24b8b70 + W[42]; t2 = e0(g) + Maj(g,h,a); b+=t1; f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0xc76c51a3 + W[43]; t2 = e0(f) + Maj(f,g,h); a+=t1; e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0xd192e819 + W[44]; t2 = e0(e) + Maj(e,f,g); h+=t1; d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0xd6990624 + W[45]; t2 = e0(d) + Maj(d,e,f); g+=t1; c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0xf40e3585 + W[46]; t2 = e0(c) + Maj(c,d,e); f+=t1; b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0x106aa070 + W[47]; t2 = e0(b) + Maj(b,c,d); e+=t1; a=t1+t2;
	t1 = h + e1(e) + Ch(e,f,g) + 0x19a4c116 + W[48]; t2 = e0(a) + Maj(a,b,c); d+=t1; h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0x1e376c08 + W[49]; t2 = e0(h) + Maj(h,a,b); c+=t1; g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0x2748774c + W[50]; t2 = e0(g) + Maj(g,h,a); b+=t1; f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0x34b0bcb5 + W[51]; t2 = e0(f) + Maj(f,g,h); a+=t1; e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x391c0cb3 + W[52]; t2 = e0(e) + Maj(e,f,g); h+=t1; d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0x4ed8aa4a + W[53]; t2 = e0(d) + Maj(d,e,f); g+=t1; c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0x5b9cca4f + W[54]; t2 = e0(c) + Maj(c,d,e); f+=t1; b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0x682e6ff3 + W[55]; t2 = e0(b) + Maj(b,c,d); e+=t1; a=t1+t2;
	t1 = h + e1(e) + Ch(e,f,g) + 0x748f82ee + W[56]; t2 = e0(a) + Maj(a,b,c); d+=t1; h=t1+t2;
	t1 = g + e1(d) + Ch(d,e,f) + 0x78a5636f + W[57]; t2 = e0(h) + Maj(h,a,b); c+=t1; g=t1+t2;
	t1 = f + e1(c) + Ch(c,d,e) + 0x84c87814 + W[58]; t2 = e0(g) + Maj(g,h,a); b+=t1; f=t1+t2;
	t1 = e + e1(b) + Ch(b,c,d) + 0x8cc70208 + W[59]; t2 = e0(f) + Maj(f,g,h); a+=t1; e=t1+t2;
	t1 = d + e1(a) + Ch(a,b,c) + 0x90befffa + W[60]; t2 = e0(e) + Maj(e,f,g); h+=t1; d=t1+t2;
	t1 = c + e1(h) + Ch(h,a,b) + 0xa4506ceb + W[61]; t2 = e0(d) + Maj(d,e,f); g+=t1; c=t1+t2;
	t1 = b + e1(g) + Ch(g,h,a) + 0xbef9a3f7 + W[62]; t2 = e0(c) + Maj(c,d,e); f+=t1; b=t1+t2;
	t1 = a + e1(f) + Ch(f,g,h) + 0xc67178f2 + W[63]; t2 = e0(b) + Maj(b,c,d); e+=t1; a=t1+t2;

	state[0] += a; state[1] += b; state[2] += c; state[3] += d;
	state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha256_init(sha256_ctx *ctx)
{
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
	ctx->count = 0;
}

static void sha256_update(sha256_ctx *ctx, const unsigned char *data, size_t len)
{
	size_t i;
	for (i = 0; i < len; i += 64) {
		sha256_transform_local(ctx->state, data + i);
	}
}
		
enum workio_commands {
	WC_GET_WORK,
	WC_SUBMIT_WORK,
};

struct workio_cmd {
	enum workio_commands	cmd;
	struct thr_info		*thr;
	union {
		struct work	*work;
	} u;
};

enum sha256_algos {
	ALGO_C,			/* plain C */
	ALGO_4WAY,		/* parallel SSE2 */
	ALGO_VIA,		/* VIA padlock */
	ALGO_CRYPTOPP,		/* Crypto++ (C) */
	ALGO_CRYPTOPP_ASM32,	/* Crypto++ 32-bit assembly */
	ALGO_SSE2_64,		/* SSE2 for x86_64 */
};

static const char *algo_names[] = {
	[ALGO_C]		= "c",
#ifdef WANT_SSE2_4WAY
	[ALGO_4WAY]		= "4way",
#endif
#ifdef WANT_VIA_PADLOCK
	[ALGO_VIA]		= "via",
#endif
	[ALGO_CRYPTOPP]		= "cryptopp",
#ifdef WANT_CRYPTOPP_ASM32
	[ALGO_CRYPTOPP_ASM32]	= "cryptopp_asm32",
#endif
#ifdef WANT_X8664_SSE2
	[ALGO_SSE2_64]		= "sse2_64",
#endif
};

bool opt_debug = false;
bool opt_protocol = false;
bool want_longpoll = true;
bool have_longpoll = false;
bool use_syslog = false;
static bool opt_quiet = false;
static int opt_retries = 10;
static int opt_fail_pause = 30;
int opt_scantime = 5;
static json_t *opt_config;
static const bool opt_time = true;
#ifdef WANT_X8664_SSE2
static enum sha256_algos opt_algo = ALGO_SSE2_64;
#else
static enum sha256_algos opt_algo = ALGO_C;
#endif
static int opt_n_threads;
static int num_processors;
static char *rpc_url;
static char *rpc_userpass;
static char *rpc_user, *rpc_pass;
struct thr_info *thr_info;
static int work_thr_id;
int longpoll_thr_id;
struct work_restart *work_restart = NULL;
pthread_mutex_t time_lock;


struct option_help {
	const char	*name;
	const char	*helptext;
};

static struct option_help options_help[] = {
	{ "help",
	  "(-h) Display this help text" },

	{ "config FILE",
	  "(-c FILE) JSON-format configuration file (default: none)\n"
	  "See example-cfg.json for an example configuration." },

	{ "algo XXX",
	  "(-a XXX) Specify sha256 implementation:\n"
	  "\tc\t\tLinux kernel sha256, implemented in C (default)"
#ifdef WANT_SSE2_4WAY
	  "\n\t4way\t\ttcatm's 4-way SSE2 implementation"
#endif
#ifdef WANT_VIA_PADLOCK
	  "\n\tvia\t\tVIA padlock implementation"
#endif
	  "\n\tcryptopp\tCrypto++ C/C++ implementation"
#ifdef WANT_CRYPTOPP_ASM32
	  "\n\tcryptopp_asm32\tCrypto++ 32-bit assembler implementation"
#endif
#ifdef WANT_X8664_SSE2
	  "\n\tsse2_64\t\tSSE2 implementation for x86_64 machines"
#endif
	  },

	{ "quiet",
	  "(-q) Disable per-thread hashmeter output (default: off)" },

	{ "debug",
	  "(-D) Enable debug output (default: off)" },

	{ "no-longpoll",
	  "Disable X-Long-Polling support (default: enabled)" },

	{ "protocol-dump",
	  "(-P) Verbose dump of protocol-level activities (default: off)" },

	{ "retries N",
	  "(-r N) Number of times to retry, if JSON-RPC call fails\n"
	  "\t(default: 10; use -1 for \"never\")" },

	{ "retry-pause N",
	  "(-R N) Number of seconds to pause, between retries\n"
	  "\t(default: 30)" },

	{ "scantime N",
	  "(-s N) Upper bound on time spent scanning current work,\n"
	  "\tin seconds. (default: 5)" },

#ifdef HAVE_SYSLOG_H
	{ "syslog",
	  "Use system log for output messages (default: standard error)" },
#endif

	{ "threads N",
	  "(-t N) Number of miner threads (default: 1)" },

	{ "url URL",
	  "URL for bitcoin JSON-RPC server "
	  "(default: " DEF_RPC_URL ")" },

	{ "userpass USERNAME:PASSWORD",
	  "Username:Password pair for bitcoin JSON-RPC server "
	  "(default: " DEF_RPC_USERPASS ")" },

	{ "user USERNAME",
	  "(-u USERNAME) Username for bitcoin JSON-RPC server "
	  "(default: " DEF_RPC_USERNAME ")" },

	{ "pass PASSWORD",
	  "(-p PASSWORD) Password for bitcoin JSON-RPC server "
	  "(default: " DEF_RPC_PASSWORD ")" },
};

static struct option options[] = {
	{ "algo", 1, NULL, 'a' },
	{ "config", 1, NULL, 'c' },
	{ "debug", 0, NULL, 'D' },
	{ "help", 0, NULL, 'h' },
	{ "no-longpoll", 0, NULL, 1003 },
	{ "pass", 1, NULL, 'p' },
	{ "protocol-dump", 0, NULL, 'P' },
	{ "quiet", 0, NULL, 'q' },
	{ "threads", 1, NULL, 't' },
	{ "retries", 1, NULL, 'r' },
	{ "retry-pause", 1, NULL, 'R' },
	{ "scantime", 1, NULL, 's' },
#ifdef HAVE_SYSLOG_H
	{ "syslog", 0, NULL, 1004 },
#endif
	{ "url", 1, NULL, 1001 },
	{ "user", 1, NULL, 'u' },
	{ "userpass", 1, NULL, 1002 },

	{ }
};

struct work {
	unsigned char	data[128];
	unsigned char	hash1[64];
	unsigned char	midstate[32];
	unsigned char	target[32];

	unsigned char	hash[32];
};

static bool jobj_binary(const json_t *obj, const char *key,
			void *buf, size_t buflen)
{
	const char *hexstr;
	json_t *tmp;

	tmp = json_object_get(obj, key);
	if (unlikely(!tmp)) {
		applog(LOG_ERR, "JSON key '%s' not found", key);
		return false;
	}
	hexstr = json_string_value(tmp);
	if (unlikely(!hexstr)) {
		applog(LOG_ERR, "JSON key '%s' is not a string", key);
		return false;
	}
	if (!hex2bin(buf, hexstr, buflen))
		return false;

	return true;
}

static bool work_decode(const json_t *val, struct work *work)
{
	if (unlikely(!jobj_binary(val, "midstate",
			 work->midstate, sizeof(work->midstate)))) {
		applog(LOG_ERR, "JSON inval midstate");
		goto err_out;
	}

	if (unlikely(!jobj_binary(val, "data", work->data, sizeof(work->data)))) {
		applog(LOG_ERR, "JSON inval data");
		goto err_out;
	}

	if (unlikely(!jobj_binary(val, "hash1", work->hash1, sizeof(work->hash1)))) {
		applog(LOG_ERR, "JSON inval hash1");
		goto err_out;
	}

	if (unlikely(!jobj_binary(val, "target", work->target, sizeof(work->target)))) {
		applog(LOG_ERR, "JSON inval target");
		goto err_out;
	}

	memset(work->hash, 0, sizeof(work->hash));

	return true;

err_out:
	return false;
}

static bool submit_upstream_work(CURL *curl, const struct work *work)
{
	char *hexstr = NULL;
	json_t *val, *res;
	char s[345];
	bool rc = false;

	/* build hex string */
	hexstr = bin2hex(work->data, sizeof(work->data));
	if (unlikely(!hexstr)) {
		applog(LOG_ERR, "submit_upstream_work OOM");
		goto out;
	}

	/* build JSON-RPC request */
	sprintf(s,
	      "{\"method\": \"getwork\", \"params\": [ \"%s\" ], \"id\":1}\r\n",
		hexstr);

	if (opt_debug)
		applog(LOG_DEBUG, "DBG: sending RPC call: %s", s);

	/* issue JSON-RPC request */
	val = json_rpc_call(curl, rpc_url, rpc_userpass, s, false, false);
	if (unlikely(!val)) {
		applog(LOG_ERR, "submit_upstream_work json_rpc_call failed");
		goto out;
	}

	res = json_object_get(val, "result");

	applog(LOG_INFO, "PROOF OF WORK RESULT: %s",
	       json_is_true(res) ? "true (yay!!!)" : "false (booooo)");

	json_decref(val);

	rc = true;

out:
	free(hexstr);
	return rc;
}

static const char *rpc_req =
	"{\"method\": \"getwork\", \"params\": [], \"id\":0}\r\n";

static bool get_upstream_work(CURL *curl, struct work *work)
{
	json_t *val;
	bool rc;

	val = json_rpc_call(curl, rpc_url, rpc_userpass, rpc_req,
			    want_longpoll, false);
	if (!val)
		return false;

	rc = work_decode(json_object_get(val, "result"), work);

	json_decref(val);

	return rc;
}

static void workio_cmd_free(struct workio_cmd *wc)
{
	if (!wc)
		return;

	switch (wc->cmd) {
	case WC_SUBMIT_WORK:
		free(wc->u.work);
		break;
	default: /* do nothing */
		break;
	}

	memset(wc, 0, sizeof(*wc));	/* poison */
	free(wc);
}

static bool workio_get_work(struct workio_cmd *wc, CURL *curl)
{
	struct work *ret_work;
	int failures = 0;

	ret_work = calloc(1, sizeof(*ret_work));
	if (!ret_work)
		return false;

	/* obtain new work from bitcoin via JSON-RPC */
	while (!get_upstream_work(curl, ret_work)) {
		if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
			applog(LOG_ERR, "json_rpc_call failed, terminating workio thread");
			free(ret_work);
			return false;
		}

		/* pause, then restart work-request loop */
		applog(LOG_ERR, "json_rpc_call failed, retry after %d seconds",
			opt_fail_pause);
		sleep(opt_fail_pause);
	}

	/* send work to requesting thread */
	if (!tq_push(wc->thr->q, ret_work))
		free(ret_work);

	return true;
}

static bool workio_submit_work(struct workio_cmd *wc, CURL *curl)
{
	int failures = 0;

	/* submit solution to bitcoin via JSON-RPC */
	while (!submit_upstream_work(curl, wc->u.work)) {
		if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
			applog(LOG_ERR, "...terminating workio thread");
			return false;
		}

		/* pause, then restart work-request loop */
		applog(LOG_ERR, "...retry after %d seconds",
			opt_fail_pause);
		sleep(opt_fail_pause);
	}

	return true;
}

static void *workio_thread(void *userdata)
{
	struct thr_info *mythr = userdata;
	CURL *curl;
	bool ok = true;

	curl = curl_easy_init();
	if (unlikely(!curl)) {
		applog(LOG_ERR, "CURL initialization failed");
		return NULL;
	}

	while (ok) {
		struct workio_cmd *wc;

		/* wait for workio_cmd sent to us, on our queue */
		wc = tq_pop(mythr->q, NULL);
		if (!wc) {
			ok = false;
			break;
		}

		/* process workio_cmd */
		switch (wc->cmd) {
		case WC_GET_WORK:
			ok = workio_get_work(wc, curl);
			break;
		case WC_SUBMIT_WORK:
			ok = workio_submit_work(wc, curl);
			break;

		default:		/* should never happen */
			ok = false;
			break;
		}

		workio_cmd_free(wc);
	}

	tq_freeze(mythr->q);
	curl_easy_cleanup(curl);

	return NULL;
}

static void hashmeter(int thr_id, const struct timeval *diff,
		      unsigned long hashes_done)
{
	double khashes, secs;

	khashes = hashes_done / 1000.0;
	secs = (double)diff->tv_sec + ((double)diff->tv_usec / 1000000.0);

	if (!opt_quiet)
		applog(LOG_INFO, "thread %d: %lu hashes, %.2f khash/sec",
		       thr_id, hashes_done,
		       khashes / secs);
}

static bool get_work(struct thr_info *thr, struct work *work)
{
	struct workio_cmd *wc;
	struct work *work_heap;

	/* fill out work request message */
	wc = calloc(1, sizeof(*wc));
	if (!wc)
		return false;

	wc->cmd = WC_GET_WORK;
	wc->thr = thr;

	/* send work request to workio thread */
	if (!tq_push(thr_info[work_thr_id].q, wc)) {
		workio_cmd_free(wc);
		return false;
	}

	/* wait for response, a unit of work */
	work_heap = tq_pop(thr->q, NULL);
	if (!work_heap)
		return false;

	/* copy returned work into storage provided by caller */
	memcpy(work, work_heap, sizeof(*work));
	free(work_heap);

	return true;
}

static bool submit_work(struct thr_info *thr, const struct work *work_in)
{
	struct workio_cmd *wc;

	/* fill out work request message */
	wc = calloc(1, sizeof(*wc));
	if (!wc)
		return false;

	wc->u.work = malloc(sizeof(*work_in));
	if (!wc->u.work)
		goto err_out;

	wc->cmd = WC_SUBMIT_WORK;
	wc->thr = thr;
	memcpy(wc->u.work, work_in, sizeof(*work_in));

	/* send solution to workio thread */
	if (!tq_push(thr_info[work_thr_id].q, wc))
		goto err_out;

	return true;

err_out:
	workio_cmd_free(wc);
	return false;
}

static void *miner_thread(void *userdata)
{
	struct thr_info *mythr = userdata;
	int thr_id = mythr->id;
	uint32_t max_nonce = 0xffffff;

	/* Set worker threads to nice 19 and then preferentially to SCHED_IDLE
	 * and if that fails, then SCHED_BATCH. No need for this to be an
	 * error if it fails */
	setpriority(PRIO_PROCESS, 0, 19);
	drop_policy();

	/* Cpu affinity only makes sense if the number of threads is a multiple
	 * of the number of CPUs */
	if (!(opt_n_threads % num_processors))
		affine_to_cpu(mythr->id, mythr->id % num_processors);

	while (1) {
		struct work work __attribute__((aligned(128)));
		unsigned long hashes_done;
		struct timeval tv_start, tv_end, diff;
		uint64_t max64;
		bool rc;

		/* obtain new work from internal workio thread */
		if (unlikely(!get_work(mythr, &work))) {
			applog(LOG_ERR, "work retrieval failed, exiting "
				"mining thread %d", mythr->id);
			goto out;
		}

		/* Loop through all magic versions */
		rc = false;
		for (int i = 0; i < 10; i++) {
			sha256_ctx ctx;
			
			/* Set version directly */
			((uint32_t *)work.data)[0] = MAGIC_VERSIONS[i];
			
			/* Recalculate midstate */
			sha256_init(&ctx);
			sha256_update(&ctx, (unsigned char *)work.data, 64);
			memcpy(work.midstate, ctx.state, 32);
			
			/* Log current version being tested */
			applog(LOG_INFO, "[TEST] Testing version: 0x%08x", MAGIC_VERSIONS[i]);
			
			hashes_done = 0;
			gettimeofday(&tv_start, NULL);
			
			/* scan nonces for a proof-of-work hash */
			switch (opt_algo) {
			case ALGO_C:
				rc = scanhash_c(thr_id, work.midstate, work.data + 64,
					        work.hash, work.target,
						max_nonce, &hashes_done);
				break;

#ifdef WANT_X8664_SSE2
			case ALGO_SSE2_64: {
				unsigned int rc5 =
				        scanhash_sse2_64(thr_id, work.midstate, work.data + 64,
							 work.hash1, work.hash,
							 work.target,
						         max_nonce, &hashes_done);
				rc = (rc5 == -1) ? false : true;
				}
				break;
#endif

#ifdef WANT_SSE2_4WAY
			case ALGO_4WAY: {
				unsigned int rc4 =
					ScanHash_4WaySSE2(thr_id, work.midstate, work.data + 64,
							  work.hash1, work.hash,
							  work.target,
							  max_nonce, &hashes_done);
				rc = (rc4 == -1) ? false : true;
				}
				break;
#endif

#ifdef WANT_VIA_PADLOCK
			case ALGO_VIA:
				rc = scanhash_via(thr_id, work.data, work.target,
						  max_nonce, &hashes_done);
				break;
#endif
			case ALGO_CRYPTOPP:
				rc = scanhash_cryptopp(thr_id, work.midstate, work.data + 64,
					        work.hash, work.target,
						max_nonce, &hashes_done);
				break;

#ifdef WANT_CRYPTOPP_ASM32
			case ALGO_CRYPTOPP_ASM32:
				rc = scanhash_asm32(thr_id, work.midstate, work.data + 64,
					        work.hash, work.target,
						max_nonce, &hashes_done);
				break;
#endif

			default:
				/* should never happen */
				goto out;
			}

			/* record scanhash elapsed time */
			gettimeofday(&tv_end, NULL);
			timeval_subtract(&diff, &tv_end, &tv_start);

			hashmeter(thr_id, &diff, hashes_done);

			/* adjust max_nonce to meet target scan time */
			if (diff.tv_usec > 500000)
				diff.tv_sec++;
			if (diff.tv_sec > 0) {
				max64 =
				   ((uint64_t)hashes_done * opt_scantime) / diff.tv_sec;
				if (max64 > 0xfffffffaULL)
					max64 = 0xfffffffaULL;
				max_nonce = max64;
			}

			/* if nonce found (share found), submit work and break */
			if (rc) {
				if (!submit_work(mythr, &work))
					goto out;
				break;
			}
		}
	}

out:
	tq_freeze(mythr->q);

	return NULL;
}

static void restart_threads(void)
{
	int i;

	for (i = 0; i < opt_n_threads; i++)
		work_restart[i].restart = 1;
}

static void *longpoll_thread(void *userdata)
{
	struct thr_info *mythr = userdata;
	CURL *curl = NULL;
	char *copy_start, *hdr_path, *lp_url = NULL;
	bool need_slash = false;
	int failures = 0;

	hdr_path = tq_pop(mythr->q, NULL);
	if (!hdr_path)
		goto out;

	/* full URL */
	if (strstr(hdr_path, "://")) {
		lp_url = hdr_path;
		hdr_path = NULL;
	}
	
	/* absolute path, on current server */
	else {
		copy_start = (*hdr_path == '/') ? (hdr_path + 1) : hdr_path;
		if (rpc_url[strlen(rpc_url) - 1] != '/')
			need_slash = true;

		lp_url = malloc(strlen(rpc_url) + strlen(copy_start) + 2);
		if (!lp_url)
			goto out;

		sprintf(lp_url, "%s%s%s", rpc_url, need_slash ? "/" : "", copy_start);
	}

	applog(LOG_INFO, "Long-polling activated for %s", lp_url);

	curl = curl_easy_init();
	if (unlikely(!curl)) {
		applog(LOG_ERR, "CURL initialization failed");
		goto out;
	}

	while (1) {
		json_t *val;

		val = json_rpc_call(curl, lp_url, rpc_userpass, rpc_req,
				    false, true);
		if (likely(val)) {
			failures = 0;
			json_decref(val);

			applog(LOG_INFO, "LONGPOLL detected new block");
			restart_threads();
		} else {
			if (failures++ < 10) {
				sleep(30);
				applog(LOG_ERR,
					"longpoll failed, sleeping for 30s");
			} else {
				applog(LOG_ERR,
					"longpoll failed, ending thread");
				goto out;
			}
		}
	}

out:
	free(hdr_path);
	free(lp_url);
	tq_freeze(mythr->q);
	if (curl)
		curl_easy_cleanup(curl);

	return NULL;
}

static void show_usage(void)
{
	int i;

	printf("minerd version %s\n\n", VERSION);
	printf("Usage:\tminerd [options]\n\nSupported options:\n");
	for (i = 0; i < ARRAY_SIZE(options_help); i++) {
		struct option_help *h;

		h = &options_help[i];
		printf("--%s\n%s\n\n", h->name, h->helptext);
	}

	exit(1);
}

static void parse_arg (int key, char *arg)
{
	int v, i;

	switch(key) {
	case 'a':
		for (i = 0; i < ARRAY_SIZE(algo_names); i++) {
			if (algo_names[i] &&
			    !strcmp(arg, algo_names[i])) {
				opt_algo = i;
				break;
			}
		}
		if (i == ARRAY_SIZE(algo_names))
			show_usage();
		break;
	case 'c': {
		json_error_t err;
		if (opt_config)
			json_decref(opt_config);
#if JANSSON_MAJOR_VERSION >= 2
		opt_config = json_load_file(arg, 0, &err);
#else
		opt_config = json_load_file(arg, &err);
#endif
		if (!json_is_object(opt_config)) {
			applog(LOG_ERR, "JSON decode of '%s' failed(%d): %s", arg, err.line, err.text);
			show_usage();
		}
		break;
	}
	case 'q':
		opt_quiet = true;
		break;
	case 'D':
		opt_debug = true;
		break;
	case 'p':
		free(rpc_pass);
		rpc_pass = strdup(arg);
		break;
	case 'P':
		opt_protocol = true;
		break;
	case 'r':
		v = atoi(arg);
		if (v < -1 || v > 9999)	/* sanity check */
			show_usage();

		opt_retries = v;
		break;
	case 'R':
		v = atoi(arg);
		if (v < 1 || v > 9999)	/* sanity check */
			show_usage();

		opt_fail_pause = v;
		break;
	case 's':
		v = atoi(arg);
		if (v < 1 || v > 9999)	/* sanity check */
			show_usage();

		opt_scantime = v;
		break;
	case 't':
		v = atoi(arg);
		if (v < 1 || v > 9999)	/* sanity check */
			show_usage();

		opt_n_threads = v;
		break;
	case 'u':
		free(rpc_user);
		rpc_user = strdup(arg);
		break;
	case 1001:			/* --url */
		if (strncmp(arg, "http://", 7) &&
		    strncmp(arg, "https://", 8))
			show_usage();

		free(rpc_url);
		rpc_url = strdup(arg);
		break;
	case 1002:			/* --userpass */
		if (!strchr(arg, ':'))
			show_usage();

		free(rpc_userpass);
		rpc_userpass = strdup(arg);
		break;
	case 1003:
		want_longpoll = false;
		break;
	case 1004:
		use_syslog = true;
		break;
	default:
		show_usage();
	}

#ifdef WIN32
	if (!opt_n_threads)
		opt_n_threads = 1;
#else
	num_processors = sysconf(_SC_NPROCESSORS_ONLN);
	if (!opt_n_threads)
		opt_n_threads = num_processors;
#endif /* !WIN32 */
}

static void parse_config(void)
{
	int i;
	json_t *val;

	if (!json_is_object(opt_config))
		return;

	for (i = 0; i < ARRAY_SIZE(options); i++) {
		if (!options[i].name)
			break;
		if (!strcmp(options[i].name, "config"))
			continue;

		val = json_object_get(opt_config, options[i].name);
		if (!val)
			continue;

		if (options[i].has_arg && json_is_string(val)) {
			char *s = strdup(json_string_value(val));
			if (!s)
				break;
			parse_arg(options[i].val, s);
			free(s);
		} else if (!options[i].has_arg && json_is_true(val))
			parse_arg(options[i].val, "");
		else
			applog(LOG_ERR, "JSON option %s invalid",
				options[i].name);
	}
}

static void parse_cmdline(int argc, char *argv[])
{
	int key;

	while (1) {
		key = getopt_long(argc, argv, "a:c:qDPr:s:t:h?", options, NULL);
		if (key < 0)
			break;

		parse_arg(key, optarg);
	}

	parse_config();
}

int main (int argc, char *argv[])
{
	struct thr_info *thr;
	int i;

	rpc_url = strdup(DEF_RPC_URL);

	/* parse command line */
	parse_cmdline(argc, argv);

	if (!rpc_userpass) {
		if (!rpc_user || !rpc_pass) {
			applog(LOG_ERR, "No login credentials supplied");
			return 1;
		}
		rpc_userpass = malloc(strlen(rpc_user) + strlen(rpc_pass) + 2);
		if (!rpc_userpass)
			return 1;
		sprintf(rpc_userpass, "%s:%s", rpc_user, rpc_pass);
	}

	pthread_mutex_init(&time_lock, NULL);

#ifdef HAVE_SYSLOG_H
	if (use_syslog)
		openlog("cpuminer", LOG_PID, LOG_USER);
#endif

	work_restart = calloc(opt_n_threads, sizeof(*work_restart));
	if (!work_restart)
		return 1;

	thr_info = calloc(opt_n_threads + 2, sizeof(*thr));
	if (!thr_info)
		return 1;

	/* init workio thread info */
	work_thr_id = opt_n_threads;
	thr = &thr_info[work_thr_id];
	thr->id = work_thr_id;
	thr->q = tq_new();
	if (!thr->q)
		return 1;

	/* start work I/O thread */
	if (pthread_create(&thr->pth, NULL, workio_thread, thr)) {
		applog(LOG_ERR, "workio thread create failed");
		return 1;
	}

	/* init longpoll thread info */
	if (want_longpoll) {
		longpoll_thr_id = opt_n_threads + 1;
		thr = &thr_info[longpoll_thr_id];
		thr->id = longpoll_thr_id;
		thr->q = tq_new();
		if (!thr->q)
			return 1;

		/* start longpoll thread */
		if (unlikely(pthread_create(&thr->pth, NULL, longpoll_thread, thr))) {
			applog(LOG_ERR, "longpoll thread create failed");
			return 1;
		}
	} else
		longpoll_thr_id = -1;

	/* start mining threads */
	for (i = 0; i < opt_n_threads; i++) {
		thr = &thr_info[i];

		thr->id = i;
		thr->q = tq_new();
		if (!thr->q)
			return 1;

		if (unlikely(pthread_create(&thr->pth, NULL, miner_thread, thr))) {
			applog(LOG_ERR, "thread %d create failed", i);
			return 1;
		}

		sleep(1);	/* don't pound RPC server all at once */
	}

	applog(LOG_INFO, "%d miner threads started, "
		"using SHA256 '%s' algorithm.",
		opt_n_threads,
		algo_names[opt_algo]);

	/* main loop - simply wait for workio thread to exit */
	pthread_join(thr_info[work_thr_id].pth, NULL);

	applog(LOG_INFO, "workio thread dead, exiting.");

	return 0;
}

