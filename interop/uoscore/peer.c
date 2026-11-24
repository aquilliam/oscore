/*
 * One OSCORE endpoint run by uoscore-uedhoc, driven over stdin and stdout.
 *
 * Usage: peer SECRET SALT SENDER_ID RECIPIENT_ID [ID_CONTEXT], all in hex
 *
 * Each line of input is "protect HEX" or "unprotect HEX" with a CoAP over UDP
 * message. Each line of output is the resulting message in hex, or "error"
 * and the error code.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oscore.h"

#define MAX_MESSAGE 1200

static struct byte_array unhex(const char *s)
{
	size_t n = strlen(s) / 2;
	uint8_t *b = malloc(n ? n : 1);
	for (size_t i = 0; i < n; i++) {
		unsigned v;
		if (sscanf(s + 2 * i, "%2x", &v) != 1) {
			fprintf(stderr, "uoscore peer: bad hex\n");
			exit(1);
		}
		b[i] = (uint8_t)v;
	}
	return (struct byte_array){ .len = (uint32_t)n, .ptr = b };
}

int main(int argc, char **argv)
{
	static struct context c;
	static char line[2 * MAX_MESSAGE + 16];

	if (argc != 5 && argc != 6) {
		fprintf(stderr, "usage: peer SECRET SALT SENDER_ID RECIPIENT_ID [ID_CONTEXT]\n");
		return 1;
	}
	struct oscore_init_params params = {
		.master_secret = unhex(argv[1]),
		.master_salt = unhex(argv[2]),
		.sender_id = unhex(argv[3]),
		.recipient_id = unhex(argv[4]),
		.id_context = unhex(argc == 6 ? argv[5] : ""),
		.aead_alg = OSCORE_AES_CCM_16_64_128,
		.hkdf = OSCORE_SHA_256,
		.fresh_master_secret_salt = true,
	};
	enum err r = oscore_context_init(&params, &c);
	if (r != ok) {
		fprintf(stderr, "uoscore peer: oscore_context_init: %d\n", r);
		return 1;
	}
	while (fgets(line, sizeof(line), stdin)) {
		uint8_t out[MAX_MESSAGE];
		uint32_t n = sizeof(out);

		line[strcspn(line, "\n")] = 0;
		if (!strncmp(line, "protect ", 8)) {
			struct byte_array in = unhex(line + 8);
			r = coap2oscore(in.ptr, in.len, out, &n, &c);
		} else if (!strncmp(line, "unprotect ", 10)) {
			struct byte_array in = unhex(line + 10);
			r = oscore2coap(in.ptr, in.len, out, &n, &c);
		} else {
			return 1;
		}
		if (r != ok) {
			printf("error %d\n", r);
		} else {
			for (uint32_t i = 0; i < n; i++)
				printf("%02x", out[i]);
			putchar('\n');
		}
		fflush(stdout);
	}
	return 0;
}
