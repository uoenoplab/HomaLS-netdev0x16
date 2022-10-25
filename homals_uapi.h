#ifndef _HOMALS_UAPI_H
#define _HOMALS_UAPI_H

#include <linux/tls.h>

struct homals_crypto_info {
	struct tls12_crypto_info_aes_gcm_128 crypto_info_aes_gcm_128;

	uint32_t addr;
	uint16_t port;

	uint16_t padding;
};

#endif /* _HOMALS_UAPI_H */
