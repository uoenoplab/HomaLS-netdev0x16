#ifndef _HOMALS_H
#define _HOMALS_H

#pragma GCC diagnostic ignored "-Wpointer-sign"
#pragma GCC diagnostic ignored "-Wunused-variable"

#include <net/tls.h>

#include "homa_impl.h"
#include "homals_uapi.h"

#ifdef HOMALS_DEBUG
#define homals_prerr_int(fmt, arg...) printk(KERN_ERR fmt, ##arg)
#define homals_prinf_int(fmt, arg...) printk(KERN_INFO fmt, ##arg)
#else
#define homals_prerr_int(fmt, arg...)                                          \
	{                                                                      \
	}
#define homals_prinf_int(fmt, arg...)                                          \
	{                                                                      \
	}
#endif

// Record Type and TLS Version 17 03 03 - 3 Bytes
// Length - 2 Bytes
// Data - Dynamic size
// Record Type 17 - 1 Bytes (also encrypted with Data)
// AUTH_TAG - 16 Bytes
#define HOMALS_RECORD_EXTRA_PRE_LENGTH 5
#define HOMALS_RECORD_EXTRA_POST_LENGTH 17
#define HOMALS_RECORD_EXTRA_LENGTH                                             \
	(HOMALS_RECORD_EXTRA_PRE_LENGTH + HOMALS_RECORD_EXTRA_POST_LENGTH)

enum {
	HOMALS_BASE,
	HOMALS_SW,
	HOMALS_HW,
	HOMALS_NUM_CONFIG,
};

struct homals_context {
	u8 tx_conf : 3;
	u8 rx_conf : 3;

	void *priv_ctx_tx;
	void *priv_ctx_rx;

	u8 buf[10000];
	int buf_len;
	
	uint32_t addr;
	uint16_t port;

	struct tls12_crypto_info_aes_gcm_128 crypto_info_aes_gcm_128_send;
	struct tls12_crypto_info_aes_gcm_128 crypto_info_aes_gcm_128_recv;

	struct list_head list;
	struct list_head hash_list;
};

struct homals_sw_context {
	struct crypto_aead *tfm;
	u8 nonce[TLS_CIPHER_AES_GCM_128_IV_SIZE +
		 TLS_CIPHER_AES_GCM_128_SALT_SIZE];
	u8 rec_seq[TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE];
};

static inline void hexdump(const char *title, unsigned char *buf,
			   unsigned int len)
{
	homals_prinf_int("%s", title);
	while (len--)
		homals_prinf_int(KERN_CONT "%02x ", *buf++);
	homals_prinf_int(KERN_CONT "\n");
}

static inline int homals_get_tx_conf(const struct homals_context *ctx)
{
	return ctx ? ctx->tx_conf : 0;
}

static inline int homals_get_rx_conf(const struct homals_context *ctx)
{
	return ctx ? ctx->rx_conf : 0;
}

// a copy of homa_data_offset with homals offset
static inline int homals_data_offset(struct sk_buff *skb)
{
	struct data_header *h = (struct data_header *)skb->data;
	return (ntohl(h->message_length) - HOMALS_RECORD_EXTRA_POST_LENGTH -
		HOMALS_RECORD_EXTRA_PRE_LENGTH);
}

static inline void homals_xor_iv_with_seq(u8 *iv, u8 *seq)
{
	int i;
	for (i = 0; i < 8; i++) {
		iv[i + 4] ^= seq[i];
	}
}

static inline bool list_is_null(const struct list_head *list)
{
	return list->prev == NULL && list->next == NULL;
}

extern struct homals_context *homals_get_ctx_hash(const struct homa_sock *hsk,
						  const uint32_t addr,
						  const uint16_t port);

extern struct homals_context *homals_get_ctx(const struct homa_sock *hsk,
					     const uint32_t addr,
					     const uint16_t port);

extern void homals_destroy(struct list_head *homals_contexts);

extern void homals_destroy_ctx(struct homals_context *homals_ctx);

extern int homals_setsockopt(struct sock *sk, int optname, sockptr_t optval,
			     unsigned int optlen);

// SW

static inline void
homals_sw_release_resources_rx(struct homals_context *homals_ctx)
{
	struct homals_sw_context *ctx_rx =
		(struct homals_sw_context *)homals_ctx->priv_ctx_rx;
	if (ctx_rx)
		crypto_free_aead(ctx_rx->tfm);
}

static inline void
homals_sw_release_resources_tx(struct homals_context *homals_ctx)
{
	struct homals_sw_context *ctx_tx =
		(struct homals_sw_context *)homals_ctx->priv_ctx_tx;
	if (ctx_tx)
		crypto_free_aead(ctx_tx->tfm);
}

extern int homals_set_sw_offload(struct sock *sk, struct homals_context *ctx,
				 int tx);

extern int homals_sw_encrypt(struct sk_buff *skb, struct homals_context *ctx);

extern int homals_sw_decrypt(u8 *buffer, int ciphertext_len,
			     struct homals_context *ctx);

extern int homals_sw_decrypt_conf(struct homa_rpc *rpc,
				  struct homals_context *ctx);

extern int homals_message_in_copy_data(struct homa_rpc *rpc,
		struct iov_iter *iter, int max_bytes);

#endif
