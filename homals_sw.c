#include <linux/bug.h>
#include <linux/sched/signal.h>
#include <linux/module.h>
#include <crypto/aead.h>

#include "homals.h"

int homals_set_sw_offload(struct sock *sk, struct homals_context *ctx, int tx)
{
	int rc = 0;
	struct homals_sw_context *sw_ctx = NULL;
	struct tls12_crypto_info_aes_gcm_128 aes_gcm_128 =
		(tx) ? ctx->crypto_info_aes_gcm_128_send :
		       ctx->crypto_info_aes_gcm_128_recv;

	sw_ctx = kmalloc(sizeof(*sw_ctx), GFP_KERNEL);
	if (tx) {
		ctx->priv_ctx_tx = sw_ctx;
	} else {
		ctx->priv_ctx_rx = sw_ctx;
	}

	printk("%s sk %px ctx %px tx %d \n", __FUNCTION__, sk, ctx, tx);
	printk("%s aes_gcm_128.info.version 0x%04X \n", __FUNCTION__,
	       aes_gcm_128.info.version);
	printk("%s aes_gcm_128.info.cipher_type %hu \n", __FUNCTION__,
	       aes_gcm_128.info.cipher_type);
	hexdump("homals_set_sw_offload aes_gcm_128.iv ", aes_gcm_128.iv,
		sizeof(aes_gcm_128.iv));
	hexdump("homals_set_sw_offload aes_gcm_128.key ", aes_gcm_128.key,
		sizeof(aes_gcm_128.key));
	hexdump("homals_set_sw_offload aes_gcm_128.salt ", aes_gcm_128.salt,
		sizeof(aes_gcm_128.salt));
	hexdump("homals_set_sw_offload aes_gcm_128.rec_seq ",
		aes_gcm_128.rec_seq, sizeof(aes_gcm_128.rec_seq));

	sw_ctx->tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	crypto_aead_setkey(sw_ctx->tfm, aes_gcm_128.key,
			   TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	crypto_aead_setauthsize(sw_ctx->tfm, TLS_CIPHER_AES_GCM_128_TAG_SIZE);

	memcpy(sw_ctx->nonce, aes_gcm_128.salt,
	       TLS_CIPHER_AES_GCM_128_SALT_SIZE);
	memcpy(sw_ctx->nonce + 4, aes_gcm_128.iv,
	       TLS_CIPHER_AES_GCM_128_IV_SIZE);
	memcpy(sw_ctx->rec_seq, aes_gcm_128.rec_seq,
	       TLS_CIPHER_AES_GCM_128_SALT_SIZE);

	// hexdump("homals_set_sw_offload sw_ctx->nonce ", sw_ctx->nonce,
	// 	sizeof(sw_ctx->nonce));
	// hexdump("homals_set_sw_offload sw_ctx->rec_seq ", sw_ctx->rec_seq,
	// 	sizeof(sw_ctx->rec_seq));

	printk(KERN_WARNING "%s leaving\n", __FUNCTION__);
	return rc;
}

int homals_sw_encrypt(struct sk_buff *skb, struct homals_context *ctx)
{
	int rc = 0;
	u8 *buf;
	int plaintext_len, buf_len;
	size_t homa_tcphead_len =
		sizeof(struct data_header) - sizeof(struct data_segment);
	struct aead_request *aead_req;
	struct scatterlist sg[1];
	u8 aad[TLS_HEADER_SIZE];
	struct homals_sw_context *ctx_tx =
		(struct homals_sw_context *)ctx->priv_ctx_tx;

	DECLARE_CRYPTO_WAIT(wait);

	buf_len = skb_headlen(skb) - homa_tcphead_len; // extra 1 for data type
	plaintext_len = buf_len - HOMALS_RECORD_EXTRA_PRE_LENGTH -
			HOMALS_RECORD_EXTRA_POST_LENGTH;

	buf = skb->data + homa_tcphead_len;

	// aad - first part
	aad[0] = 0x17;
	aad[1] = 0x03;
	aad[2] = 0x03;
	aad[3] = (buf_len - TLS_HEADER_SIZE) >> 8;
	aad[4] = (buf_len - TLS_HEADER_SIZE);
	memcpy(buf, aad, sizeof(aad));

	// data type - third part
	buf[TLS_HEADER_SIZE + plaintext_len] = 0x17;

	homals_prinf_int("aad | plaintext | authtag (buf_len %d)", buf_len);
	hexdump("", buf, buf_len);

	memcpy(ctx_tx->nonce, ctx->crypto_info_aes_gcm_128_send.iv,
	       sizeof(ctx_tx->nonce));
	homals_xor_iv_with_seq(ctx_tx->nonce, ctx_tx->rec_seq);
	tls_bigint_increment((unsigned char *)ctx_tx->rec_seq, sizeof(ctx_tx->rec_seq));

	hexdump("nonce ", ctx_tx->nonce, sizeof(ctx_tx->nonce));
	hexdump("updated rec_seq ", ctx_tx->rec_seq, sizeof(ctx_tx->rec_seq));

	aead_req = aead_request_alloc(ctx_tx->tfm, GFP_KERNEL);
	aead_request_set_tfm(aead_req, ctx_tx->tfm);
	aead_request_set_ad(aead_req, TLS_HEADER_SIZE);
	sg_init_one(sg, buf, buf_len);
	aead_request_set_callback(aead_req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_crypt(aead_req, sg, sg, plaintext_len + 1,
			       ctx_tx->nonce);
	crypto_wait_req(crypto_aead_encrypt(aead_req), &wait);

	homals_prinf_int("aad | ciphertext | authtag (buf_len %d)", buf_len);
	hexdump("", buf, buf_len);

	aead_request_free(aead_req);
	return rc;
}

int homals_sw_decrypt(u8 *buffer, int ciphertext_len,
		      struct homals_context *ctx)
{
	int rc = 0;
	// int plaintext_len = ciphertext_len - HOMALS_RECORD_EXTRA_LENGTH;
	struct aead_request *aead_req;
	struct scatterlist sg[1];
	struct homals_sw_context *ctx_rx =
		(struct homals_sw_context *)ctx->priv_ctx_rx;

	DECLARE_CRYPTO_WAIT(wait);

	hexdump("aad || ciphertext || authtag: \n", buffer, ciphertext_len);

	memcpy(ctx_rx->nonce, ctx->crypto_info_aes_gcm_128_recv.iv,
	       sizeof(ctx_rx->nonce));
	homals_xor_iv_with_seq(ctx_rx->nonce, ctx_rx->rec_seq);
	tls_bigint_increment((unsigned char *)ctx_rx->rec_seq, sizeof(ctx_rx->rec_seq));
	homals_prinf_int("nonce and updated rec_seq: \n");
	hexdump("ctx_rx->nonce ", ctx_rx->nonce, sizeof(ctx_rx->nonce));
	hexdump("ctx_rx->rec_seq ", ctx_rx->rec_seq, sizeof(ctx_rx->rec_seq));

	aead_req = aead_request_alloc(ctx_rx->tfm, GFP_KERNEL);
	aead_request_set_tfm(aead_req, ctx_rx->tfm);
	aead_request_set_ad(aead_req, TLS_HEADER_SIZE);
	sg_init_one(sg, buffer, ciphertext_len);
	aead_request_set_callback(aead_req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_crypt(aead_req, sg, sg,
			       ciphertext_len - TLS_HEADER_SIZE, ctx_rx->nonce);
	crypto_wait_req(crypto_aead_decrypt(aead_req), &wait);

	hexdump("aad || plaintext || authtag: \n", buffer, ciphertext_len);

	aead_request_free(aead_req);

	return rc;
}

int homals_sw_decrypt_conf(struct homa_rpc *rpc, struct homals_context *ctx)
{
	struct sk_buff *skb = rpc->msgin.packets.next;
	u8 *buf = ctx->buf;
	size_t buf_len = rpc->msgin.total_length +
			 rpc->msgin.num_skbs * sizeof(struct data_segment);
	const int homa_tcphead_len =
		sizeof(struct data_header) - sizeof(struct data_segment);
	int buf_offset = 0;
	int i;

	homals_prinf_int("%s rpc->msgin.total_length %d rpc->msgin.num_skbs %d",
			 __FUNCTION__, rpc->msgin.total_length,
			 rpc->msgin.num_skbs);

	// buf = kmalloc(buf_len, GFP_KERNEL);
	
	for (i = 1; i <= rpc->msgin.num_skbs; i++) {
		skb_copy_bits(skb, homa_tcphead_len, buf + buf_offset,
			      skb->len - homa_tcphead_len);
		buf_offset += skb->len - homa_tcphead_len;
		if (unlikely(skb->len - homa_tcphead_len <
			     sizeof(struct data_segment)))
			buf_len -= sizeof(struct data_segment);

		homals_prinf_int(
			"%s %d. skb %px skb->next %px skb->len %d skb->data_len %d"
			" skb_is_nonlinear %d", __FUNCTION__, i, skb, skb->next, 
			skb->len, skb->data_len, skb_is_nonlinear(skb));
		homals_prinf_int("%s %d. buf_offset %d", __FUNCTION__, i,
				 buf_offset);

		skb = skb->next;
	}

	homals_prinf_int("%s buf_len %ld", __FUNCTION__, buf_len);

	hexdump("homals_sw_decrypt_2seg buffer before decrypt", buf,
		buf_offset);

	// Todo: decryption fail handle
	homals_sw_decrypt(buf, buf_len, ctx);

	ctx->buf_len = buf_len;

	return 0;
}
