/* dmg.c
 *
 * hashkill - a hash cracking tool
 * Copyright (C) 2010 Milen Rangelov <gat3way@gat3way.eu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <alloca.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>

#include "plugin.h"
#include "err.h"
#include "hashinterface.h"

int vectorsize;

#undef HTONL
#define HTONL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
	((((unsigned long)(n) & 0xFF00)) << 8) | \
	((((unsigned long)(n) & 0xFF0000)) >> 8) | \
	((((unsigned long)(n) & 0xFF000000)) >> 24))


static int apple_des3_ede_unwrap_key1(unsigned char *wrapped_key,
    int wrapped_key_len, unsigned char *decryptKey)
{
	EVP_CIPHER_CTX ctx;
	unsigned char *TEMP1, *TEMP2, *CEKICV;
	unsigned char IV[8] =
	    { 0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05 };
	int outlen, tmplen, i;


	TEMP1 = alloca(wrapped_key_len);
	TEMP2 = alloca(wrapped_key_len);
	CEKICV = alloca(wrapped_key_len);

	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit_ex(&ctx, EVP_des_ede3_cbc(), NULL, decryptKey, IV);

	if (!EVP_DecryptUpdate(&ctx, TEMP1, &outlen, wrapped_key,
		wrapped_key_len)) {
		return (-1);
	}
	if (!EVP_DecryptFinal_ex(&ctx, TEMP1 + outlen, &tmplen)) {
		/*if (header.len_wrapped_aes_key==48) */ return (-1);
	}
	outlen += tmplen;
	EVP_CIPHER_CTX_cleanup(&ctx);

	for (i = 0; i < outlen; i++) {
		TEMP2[i] = TEMP1[outlen - i - 1];
	}
	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit_ex(&ctx, EVP_des_ede3_cbc(), NULL, decryptKey, TEMP2);
	if (!EVP_DecryptUpdate(&ctx, CEKICV, &outlen, TEMP2 + 8, outlen - 8)) {
		return (-1);
	}
	if (!EVP_DecryptFinal_ex(&ctx, CEKICV + outlen, &tmplen)) {
		return (-1);
	}
	outlen += tmplen;
	EVP_CIPHER_CTX_cleanup(&ctx);
	return 0;
}

char *hash_plugin_summary(void)
{
	return ("dmg \t\tFileVault (v1)  passwords plugin");
}


char *hash_plugin_detailed(void)
{
	return ("dmg - A FileVault (v1) passwords plugin\n"
	    "------------------------------------------------\n"
	    "Use this module to crack Apple DMG images passwords\n"
	    "Input should be a dmg file specified with -f\n"
	    "Supports FileVault v1 images only \n"
	    "Known software that uses this password hashing method:\n"
	    "Apple MacOSX\n"
	    "\nAuthor: Milen Rangelov <gat3way@gat3way.eu>\n");
}

static struct custom_salt {
	unsigned int saltlen;
	unsigned char salt[20];
	unsigned int ivlen;
	unsigned char iv[32];
	int headerver;
	unsigned char chunk[8192];
	uint32_t encrypted_keyblob_size;
	uint8_t encrypted_keyblob[128];
	unsigned int len_wrapped_aes_key;
	unsigned char wrapped_aes_key[296];
	unsigned int len_hmac_sha1_key;
	unsigned char wrapped_hmac_sha1_key[300];
	char scp; /* start chunk present */
	unsigned char zchunk[4096]; /* chunk #0 */
	int cno;
	int data_size;
	unsigned int iterations;
} cs;

hash_stat hash_plugin_parse_hash(char *ciphertext, char *filename)
{
	puts(ciphertext);
	char *ctcopy = strdup(ciphertext);
	char *keeptr = ctcopy;
	char *p = strchr(ciphertext, ':');
	if (p)
		ctcopy = p + 1;

	ctcopy += 5;
	p = strtok(ctcopy, "*");
	cs.headerver = atoi(p);
	if (cs.headerver == 2) {
		p = strtok(NULL, "*");
		cs.saltlen = atoi(p);
		p = strtok(NULL, "*");
		hex2str((char *) cs.salt, p, cs.saltlen * 2);
		p = strtok(NULL, "*");
		cs.ivlen = atoi(p);
		p = strtok(NULL, "*");
		hex2str((char *) cs.iv, p, cs.ivlen * 2);
		p = strtok(NULL, "*");
		cs.encrypted_keyblob_size = atoi(p);
		p = strtok(NULL, "*");
		hex2str((char *) cs.encrypted_keyblob, p,
		    cs.encrypted_keyblob_size * 2);
		p = strtok(NULL, "*");
		cs.cno = atoi(p);
		p = strtok(NULL, "*");
		cs.data_size = atoi(p);
		p = strtok(NULL, "*");
		hex2str((char *) cs.chunk, p, cs.data_size * 2);
		p = strtok(NULL, "*");
		cs.scp = atoi(p);
		if (cs.scp == 1) {
			p = strtok(NULL, "*");
			hex2str((char *) cs.zchunk, p, 4096 * 2);
		}
		if ((p = strtok(NULL, "*")))
			cs.iterations = atoi(p);
		else
			cs.iterations = 1000;
	} else {
		p = strtok(NULL, "*");
		cs.saltlen = atoi(p);
		p = strtok(NULL, "*");
		hex2str((char*)cs.salt, p, cs.saltlen * 2);
		p = strtok(NULL, "*");
		cs.len_wrapped_aes_key = atoi(p);
		p = strtok(NULL, "*");
		hex2str((char*)cs.wrapped_aes_key, p, cs.len_wrapped_aes_key * 2);
		p = strtok(NULL, "*");
		cs.len_hmac_sha1_key = atoi(p);
		p = strtok(NULL, "*");
		hex2str((char*)cs.wrapped_hmac_sha1_key, p, cs.len_hmac_sha1_key * 2);
		if ((p = strtok(NULL, "*")))
			cs.iterations = atoi(p);
		else
			cs.iterations = 1000;
	}
	if (cs.iterations == 0)
		cs.iterations = 1000;

	(void) hash_add_username("DMG hash");

	p = strrchr(keeptr, ':');
	if (!p)
		p = keeptr;
	(void) hash_add_hash(p + 1, 0);
	free(keeptr);
	(void) hash_add_salt("123");
	(void) hash_add_salt2("                              ");
	return hash_ok;
}

hash_stat hash_plugin_check_hash(const char *hash,
    const char *password[VECTORSIZE], const char *salt,
    char *salt2[VECTORSIZE], const char *username, int *num, int threadid)
{
	int a;
	unsigned char derived_key[24];
	unsigned char hmacsha1_key_[20];
	unsigned char aes_key_[32];

	if (cs.headerver == 1) {
		for (a = 0; a < vectorsize; a++) {
			hash_pbkdf2_len(password[a], strlen(password[a]),
			    cs.salt, 20, cs.iterations, sizeof(derived_key),
			    derived_key);
			if ((apple_des3_ede_unwrap_key1(cs.wrapped_aes_key,
				    cs.len_wrapped_aes_key, derived_key) == 0)
			    && (apple_des3_ede_unwrap_key1(cs.
				    wrapped_hmac_sha1_key,
				    cs.len_hmac_sha1_key, derived_key) == 0)
			    ) {
				memcpy(salt2[a],
				    "DMG file        \0\0\0\0\0\0\0\0\0", 20);
				*num = a;
				return hash_ok;
			}
		}
	} else {
		for (a = 0; a < vectorsize; a++) {
			EVP_CIPHER_CTX ctx;
			unsigned char TEMP1[sizeof(cs.wrapped_hmac_sha1_key)];
			int outlen, tmplen;
			AES_KEY aes_decrypt_key;
			unsigned char outbuf[8192];
			unsigned char iv[20];
			HMAC_CTX hmacsha1_ctx;
			int mdlen;
			unsigned char *r;
			const char nulls[16] = { 0 };

			hash_pbkdf2_len(password[a], strlen(password[a]),
			    (unsigned char *) cs.salt, 20, cs.iterations,
			    sizeof(derived_key), derived_key);

			EVP_CIPHER_CTX_init(&ctx);
			EVP_DecryptInit_ex(&ctx, EVP_des_ede3_cbc(), NULL,
			    derived_key, cs.iv);
			if (!EVP_DecryptUpdate(&ctx, TEMP1, &outlen,
				cs.encrypted_keyblob,
				cs.encrypted_keyblob_size)) {
				/* FIXME: should we fail here? */
				EVP_CIPHER_CTX_cleanup(&ctx);
				return 0;
			}
			EVP_DecryptFinal_ex(&ctx, TEMP1 + outlen, &tmplen);
			EVP_CIPHER_CTX_cleanup(&ctx);
			outlen += tmplen;
			memcpy(aes_key_, TEMP1, 32);
			memcpy(hmacsha1_key_, TEMP1, 20);
			HMAC_CTX_init(&hmacsha1_ctx);
			HMAC_Init_ex(&hmacsha1_ctx, hmacsha1_key_, 20,
			    EVP_sha1(), NULL);
			HMAC_Update(&hmacsha1_ctx, (void *) &cs.cno, 4);
			HMAC_Final(&hmacsha1_ctx, iv, (unsigned int *) &mdlen);
			HMAC_CTX_cleanup(&hmacsha1_ctx);
			if (cs.encrypted_keyblob_size == 48)
				AES_set_decrypt_key(aes_key_, 128,
				    &aes_decrypt_key);
			else
				AES_set_decrypt_key(aes_key_, 128 * 2,
				    &aes_decrypt_key);
			AES_cbc_encrypt(cs.chunk, outbuf, cs.data_size,
			    &aes_decrypt_key, iv, AES_DECRYPT);

			/* 16 consecutive nulls */
			if (hash_memmem(outbuf, cs.data_size, (void *) nulls,
				16)) {
				*num = a;
				return hash_ok;
			}

			/* </plist> is a pretty generic signature for Apple */
			if (hash_memmem(outbuf, cs.data_size,
				(void *) "</plist>", 8)) {
				*num = a;
				return hash_ok;

			}

			/* Journalled HFS+ */
			if (hash_memmem(outbuf, cs.data_size,
				(void *) "jrnlhfs+", 8)) {
				*num = a;
				return hash_ok;
			}

			/* Handle compressed DMG files, CMIYC 2012 and self-made samples.
			   Is this test obsoleted by the </plist> one? */
			r = hash_memmem(outbuf, cs.data_size, (void *) "koly",
			    4);
			if (r) {
				unsigned int *u32Version =
				    (unsigned int *) (r + 4);

				if (HTONL(*u32Version) == 4) {
					*num = a;
					return hash_ok;
				}
			}

			/* Handle VileFault sample images */
			if (hash_memmem(outbuf, cs.data_size,
				(void *) "EFI PART", 8)) {
				*num = a;
				return hash_ok;
			}
			if (cs.scp == 1) {
				int cno = 0;

				HMAC_CTX_init(&hmacsha1_ctx);
				HMAC_Init_ex(&hmacsha1_ctx, hmacsha1_key_, 20,
				    EVP_sha1(), NULL);
				HMAC_Update(&hmacsha1_ctx, (void *) &cno, 4);
				HMAC_Final(&hmacsha1_ctx, iv,
				    (unsigned int *) &mdlen);
				HMAC_CTX_cleanup(&hmacsha1_ctx);
				if (cs.encrypted_keyblob_size == 48)
					AES_set_decrypt_key(aes_key_, 128,
					    &aes_decrypt_key);
				else
					AES_set_decrypt_key(aes_key_, 128 * 2,
					    &aes_decrypt_key);

				AES_cbc_encrypt(cs.zchunk, outbuf, 4096,
				    &aes_decrypt_key, iv, AES_DECRYPT);
				if (hash_memmem(outbuf, 4096,
					(void *) "Press any key to reboot",
					23)) {
					*num = a;
					return hash_ok;

				}

			}
		}
	}
	return hash_err;
}


int hash_plugin_hash_length(void)
{
	return 16;
}

int hash_plugin_is_raw(void)
{
	return 1;
}

int hash_plugin_is_special(void)
{
	return 0;
}

void get_vector_size(int size)
{
	vectorsize = size;
}

int get_salt_size(void)
{
	return 4;
}
