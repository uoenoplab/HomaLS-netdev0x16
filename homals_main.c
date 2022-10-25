#include "homals.h"

#define mix(a, b, c)                                                    \
do {                                                                    \
        a -= b; a -= c; a ^= (c >> 13);                                 \
        b -= c; b -= a; b ^= (a << 8);                                  \
        c -= a; c -= b; c ^= (b >> 13);                                 \
        a -= b; a -= c; a ^= (c >> 12);                                 \
        b -= c; b -= a; b ^= (a << 16);                                 \
        c -= a; c -= b; c ^= (b >> 5);                                  \
        a -= b; a -= c; a ^= (c >> 3);                                  \
        b -= c; b -= a; b ^= (a << 10);                                 \
        c -= a; c -= b; c ^= (b >> 15);                                 \
} while (/*CONSTCOND*/0)

static inline uint32_t ms_rthash(const uint32_t addr, const uint16_t port)
{
	uint32_t a = 0x9e3779b9, b = 0x9e3779b9, c = 0; // hask key
	uint8_t *p;

	// b += *ptrs->proto;
	p = (uint8_t *)&port;
	b += p[1] << 16;
	b += p[0] << 8;
	p = (uint8_t *)&addr;
	b += p[3];
	a += p[2] << 24;
	a += p[1] << 16;
	a += p[0] << 8;
	mix(a, b, c);
	return c;
}
#undef mix

struct homals_context *homals_get_ctx_hash(const struct homa_sock *hsk,
					   const uint32_t addr,
					   const uint16_t port)
{
	uint32_t hash_val =
		ms_rthash(addr, port) %
		(sizeof(hsk->homals_ctx_ht) / sizeof(*hsk->homals_ctx_ht));
	struct homals_context *ctx = NULL;
	const struct list_head *ht_ctxs = &hsk->homals_ctx_ht[hash_val];

	homals_prinf_int("%s addr %X ctx->port %d\n", __FUNCTION__, htonl(addr),
			 (int)htons(port));
	homals_prinf_int("%s ht_ctxs->prev %px ht_ctxs->next %px", __FUNCTION__,
			 ht_ctxs->prev, ht_ctxs->next);

	if (unlikely(list_is_null(ht_ctxs)))
		goto out;

	if (unlikely(list_empty(ht_ctxs)))
		goto out;

	list_for_each_entry (ctx, ht_ctxs, hash_list) {
		if (likely(ctx->addr == addr && ctx->port == port)) {
			homals_prinf_int(
				"%s ctx %px ctx->addr %X ctx->port %d ctx->list.next %px\n",
				__FUNCTION__, ctx, htonl(ctx->addr),
				(int)htons(ctx->port), ctx->list.next);
			return ctx;
		}
	}

out:
	homals_prinf_int("%s no match", __FUNCTION__);
	return NULL;
}

struct homals_context *homals_get_ctx(const struct homa_sock *hsk,
				      const uint32_t addr, const uint16_t port)
{
	struct homals_context *ctx = NULL;
	const struct list_head *ctxs = &hsk->homals_contexts;

	homals_prinf_int("%s addr %X ctx->port %d\n", __FUNCTION__, htonl(addr),
			 (int)htons(port));

	if (list_empty(ctxs))
		return NULL;

	list_for_each_entry (ctx, ctxs, list) {
		homals_prinf_int(
			"%s ctx %px ctx->addr %X ctx->port %d ctx->list.next %px\n",
			__FUNCTION__, ctx, htonl(ctx->addr),
			(int)htons(ctx->port), ctx->list.next);
		if (ctx->addr == addr && ctx->port == port) {
			return ctx;
		}
	}

	homals_prinf_int("%s no match", __FUNCTION__);

	return NULL;
}

void homals_destroy(struct list_head *ctxs)
{
	struct homals_context *ctx = NULL;
	struct homals_context *ctx_tmp = NULL;

	if (list_empty(ctxs))
		return;

	list_for_each_entry_safe (ctx, ctx_tmp, ctxs, list) {
		homals_prinf_int(
			"%s ctx %px ctx->addr %X ctx->port %d ctx->list.next %px\n",
			__FUNCTION__, ctx, htonl(ctx->addr),
			(int)htons(ctx->port), ctx->list.next);

		homals_destroy_ctx(ctx);
	}
}

void homals_destroy_ctx(struct homals_context *ctx)
{
	if (ctx) {
		if (ctx->rx_conf == HOMALS_SW)
			homals_sw_release_resources_rx(ctx);
		if (ctx->tx_conf == HOMALS_SW)
			homals_sw_release_resources_tx(ctx);
		if (ctx->priv_ctx_tx)
			kfree(ctx->priv_ctx_tx);
		if (ctx->priv_ctx_rx)
			kfree(ctx->priv_ctx_rx);
		kfree(ctx);
	}
}

static int
homals_setsockopt_conf(struct sock *sk,
		       struct homals_crypto_info *crypto_info_optval,
		       struct homals_context *ctx, int tx)
{
	struct tls12_crypto_info_aes_gcm_128 *crypto_info;
	struct tls12_crypto_info_aes_gcm_128 *alt_crypto_info;

	int rc = 0;
	int conf;

	if (ctx == NULL) {
		rc = -EFAULT;
		goto out;
	}

	homals_prinf_int(KERN_WARNING
			 "homals_setsockopt_conf invoked on Homa socket:"
			 "crypto_info_optval %px, ctx %px\n",
			 crypto_info_optval, ctx);

	crypto_info = tx ? &(ctx->crypto_info_aes_gcm_128_send) :
			   &(ctx->crypto_info_aes_gcm_128_recv);
	alt_crypto_info = !tx ? &(ctx->crypto_info_aes_gcm_128_send) :
				&(ctx->crypto_info_aes_gcm_128_recv);

	homals_prinf_int("%s crypto_info %px", __FUNCTION__, crypto_info);
	homals_prinf_int("%s crypto_info->info.version 0x%04X \n", __FUNCTION__,
			 crypto_info->info.version);
	homals_prinf_int("%s crypto_info->info.cipher_type %hu \n",
			 __FUNCTION__, crypto_info->info.cipher_type);
	homals_prinf_int("%s alt_crypto_info %px", __FUNCTION__, crypto_info);
	homals_prinf_int("%s alt_crypto_info->info.version 0x%04X \n",
			 __FUNCTION__, alt_crypto_info->info.version);
	homals_prinf_int("%s alt_crypto_info->info.cipher_type %hu \n",
			 __FUNCTION__, alt_crypto_info->info.cipher_type);

	/* Currently we don't support set crypto info more than one time */
	if (TLS_CRYPTO_INFO_READY(&crypto_info->info)) {
		rc = -EBUSY;
		goto out;
	}

	/* Copy optval to homals_ctx */
	*crypto_info = crypto_info_optval->crypto_info_aes_gcm_128;

	/* Ensure that TLS verscopy_from_sockptrion and ciphers are same in both directions */
	if (TLS_CRYPTO_INFO_READY(&alt_crypto_info->info)) {
		if (alt_crypto_info->info.version !=
			    crypto_info->info.version ||
		    alt_crypto_info->info.cipher_type !=
			    crypto_info->info.cipher_type) {
			rc = -EINVAL;
			goto out;
		}
	}

	if (ctx->addr == 0 || ctx->port == 0) {
		ctx->addr = crypto_info_optval->addr;
		ctx->port = crypto_info_optval->port;
	}

	printk("%s ctx->addr %X ctx->port %d\n", __FUNCTION__, htonl(ctx->addr),
	       (int)htons(ctx->port));

	rc = homals_set_sw_offload(sk, ctx, tx);
	if (rc)
		goto out;
	conf = HOMALS_SW;

	if (tx)
		ctx->tx_conf = conf;
	else
		ctx->rx_conf = conf;
	goto out;

out:
	return rc;
}

static int homals_setsockopt_select_ctx(struct sock *sk, sockptr_t optval,
					unsigned int optlen, int tx)
{
	int rc = 0;
	struct homals_crypto_info crypto_info_optval;
	struct homals_context *ctx = NULL;

	struct homa_sock *hsk = homa_sk(sk);
	struct list_head *ctxs = &hsk->homals_contexts;

	uint32_t hash_val;
	struct list_head *ht_ctxs;

	size_t optsize;

	if (sockptr_is_null(optval) ||
	    (optlen < sizeof(crypto_info_optval))) {
		rc = -EINVAL;
		printk(KERN_WARNING
		       "%s optval length is not correct, should be sizeof(struct homals_crypto_info)\n",
		       __FUNCTION__);
		goto out;
	}

	// copy key info from userspace
	rc = copy_from_sockptr(&crypto_info_optval, optval,
			       sizeof(struct homals_crypto_info));
	if (rc) {
		rc = -EFAULT;
		goto out;
	}

	switch (crypto_info_optval.crypto_info_aes_gcm_128.info.cipher_type) {
	case TLS_CIPHER_AES_GCM_128:
		optsize = sizeof(struct homals_crypto_info);
		break;
	default:
		printk(KERN_WARNING
		       "%s homals only supports TLS_CIPHER_AES_GCM_128 now\n",
		       __FUNCTION__);
		rc = -EINVAL;
		goto out;
	}

	if (optlen != optsize) {
		rc = -EINVAL;
		printk(KERN_WARNING
		       "%s optval length is not correct, should be sizeof(struct"
			   " homals_crypto_info)\n", __FUNCTION__);
		goto out;
	}

	// search current ctx by (ip, port)
	hash_val = ms_rthash(crypto_info_optval.addr,
			     crypto_info_optval.port) %
		   (sizeof(hsk->homals_ctx_ht) / sizeof(*hsk->homals_ctx_ht));
	ht_ctxs = &hsk->homals_ctx_ht[hash_val];

	ctx = homals_get_ctx_hash(hsk, crypto_info_optval.addr,
				  crypto_info_optval.port);

	// malloc a new ctx if can not find one
	if (ctx == NULL) {
		ctx = kmalloc(sizeof(struct homals_context), GFP_KERNEL);
		list_add_tail(&ctx->list, ctxs);

		if (list_is_null(ht_ctxs))
			INIT_LIST_HEAD(ht_ctxs);

		list_add_tail(&ctx->hash_list, ht_ctxs);
	}

	rc = homals_setsockopt_conf(sk, &crypto_info_optval, ctx, tx);
	if (rc)
		goto err_crypto_info;

	goto out;

err_crypto_info:
	list_del(&ctx->hash_list);
	list_del(&ctx->list);
	memzero_explicit(ctx, sizeof(*ctx));
	homals_destroy_ctx(ctx);
out:
	return rc;
}

int homals_setsockopt(struct sock *sk, int optname, sockptr_t optval,
		      unsigned int optlen)
{
	int rc = 0;

	switch (optname) {
	case TLS_TX:
	case TLS_RX:
		lock_sock(sk);
		rc = homals_setsockopt_select_ctx(sk, optval, optlen,
						  optname == TLS_TX);
		release_sock(sk);
		break;
	default:
		rc = -ENOPROTOOPT;
		break;
	}
	return rc;
}

int homals_message_in_copy_data(struct homa_rpc *rpc,
		struct iov_iter *iter, int max_bytes)
{
	int err;
	int remaining = max_bytes;
	u8* buf = rpc->homals_ctx->buf + HOMALS_RECORD_EXTRA_PRE_LENGTH;
	int buf_remaining = rpc->homals_ctx->buf_len;

	do {
		struct data_segment *d = (struct data_segment *) buf;
		int this_offset = ntohl(d->offset);
		int this_size = ntohl(d->segment_length);

		homals_prinf_int("%s this_size %d this_offset %d rpc->msgin.xfer_offset %d",
			__FUNCTION__, this_size, this_offset, rpc->msgin.xfer_offset);

		if ((this_offset + this_size) <= rpc->msgin.xfer_offset) {
			buf += this_size + sizeof(struct data_segment);
			continue;
		}

		if (this_offset > rpc->msgin.xfer_offset) {
			buf += this_size + sizeof(struct data_segment);
			continue;
		}

		if (rpc->msgin.xfer_offset != this_offset) {
			this_size -= (rpc->msgin.xfer_offset - this_offset);
		}

		if (this_size > remaining)
			this_size = remaining;

		if (unlikely(this_size <= 0))
			continue;

		if ((buf + sizeof(*d) + 
				rpc->msgin.xfer_offset - this_offset) > (buf + buf_remaining))
			return -EFAULT;

		err = copy_to_iter((buf + sizeof(*d) + 
				rpc->msgin.xfer_offset - this_offset), this_size, iter);

		if (err != this_size) {
			return -EFAULT;
		}

		remaining -= this_size;
		rpc->msgin.xfer_offset += this_size;
		buf += this_size + sizeof(struct data_segment);

		buf_remaining = rpc->homals_ctx->buf_len - (buf - rpc->homals_ctx->buf);

		homals_prinf_int("%s this_size %d this_offset %d buf_remaining %d remaining %d",
			__FUNCTION__, this_size, this_offset, buf_remaining, remaining);

	} while ((remaining != 0) && (buf_remaining > HOMALS_RECORD_EXTRA_POST_LENGTH));
	
	if (buf_remaining <= HOMALS_RECORD_EXTRA_POST_LENGTH) {
		memset(rpc->homals_ctx->buf, 0, sizeof(rpc->homals_ctx->buf));
	}

	return max_bytes - remaining;
}
