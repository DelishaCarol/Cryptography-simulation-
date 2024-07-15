
#if defined snprintf
// This definition of snprintf will generate "warning C4005: 'snprintf': macro
// redefinition" with a subsequent line indicating where the previous definition
// of snprintf was.  This makes it easier to find where snprintf was defined.
	#pragma warning(push, 1)
	#pragma warning(1: 4005) // macro redefinition
	#define snprintf Do not define snprintf as a macro
	#pragma warning(pop)
	#error Macro definition of snprintf conflicts with Standard Library function declaration
#endif


#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "crypto_wrapper.h"

#ifdef OPENSSL
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/dh.h>
#include <openssl/bio.h>

#ifdef WIN
#pragma comment (lib, "libcrypto.lib")
#pragma comment (lib, "openssl.lib")
#endif // #ifdef WIN

static constexpr size_t PEM_BUFFER_SIZE_BYTES	= 10000;
static constexpr size_t HASH_SIZE_BYTES			= 32; //To be define by the participants
static constexpr size_t IV_SIZE_BYTES			= 12; //To be define by the participants
static constexpr size_t GMAC_SIZE_BYTES			= 16; //To be define by the participants

bool CryptoWrapper::hmac_SHA256(IN const BYTE* key, size_t keySizeBytes, IN const BYTE* message, IN size_t messageSizeBytes, OUT BYTE* macBuffer, IN size_t macBufferSizeBytes)
{	
	EVP_MD_CTX* ctx = NULL;
	EVP_PKEY* pkey = NULL;

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
	{
		goto err;
	}

	pkey  = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, keySizeBytes);//
	if (pkey == NULL)
	{
		goto err;
	}

	if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) ==0)
	{
		goto err;
	}

	if (EVP_DigestSignUpdate(ctx, message, messageSizeBytes) != 1)
	{
		goto err;
	}

	if (EVP_DigestSignFinal(ctx, macBuffer, &macBufferSizeBytes) != 1)
	{
		goto err;
	}

	return true;

err:
	printf("Error\n");
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey); 
	return false;
}


bool CryptoWrapper::deriveKey_HKDF_SHA256(IN const BYTE* salt, IN size_t saltSizeBytes,
	IN const BYTE* secretMaterial, IN size_t secretMaterialSizeBytes,
	IN const BYTE* context, IN size_t contextSizeBytes,
	OUT BYTE* outputBuffer, IN size_t outputBufferSizeBytes)
{
	bool ret = false;
	EVP_PKEY_CTX* pctx = NULL;

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if(pctx == NULL)
	{
		printf("failed to get HKDF context\n");
		goto err;	
	}

	
	if (EVP_PKEY_derive_init(pctx) <= 0)
	{
		printf("Failed to initialize HKDF derivation\n");
		goto err;
	}

	if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0)
	{
		printf("Failed to set HKDF hash algorithm\n");
		goto err;
	}

	if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltSizeBytes) <= 0)
	{
		printf("Failed to set HKDF salt\n");
		goto err;
	}

	if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secretMaterial, secretMaterialSizeBytes) <= 0)
	{
		printf("Failed to set HKDF key\n");
		goto err;
	}

	if (EVP_PKEY_derive(pctx, outputBuffer, &outputBufferSizeBytes) <= 0)
	{
		printf("Failed to derive HKDF key\n");
		goto err;
	}
	ret = true;

err:
	EVP_PKEY_CTX_free(pctx);

	return ret;
}

size_t CryptoWrapper::getCiphertextSizeAES_GCM256(IN size_t plaintextSizeBytes)
{
	return plaintextSizeBytes + IV_SIZE_BYTES + GMAC_SIZE_BYTES;
}


size_t CryptoWrapper::getPlaintextSizeAES_GCM256(IN size_t ciphertextSizeBytes)
{
	return (ciphertextSizeBytes > IV_SIZE_BYTES + GMAC_SIZE_BYTES ? ciphertextSizeBytes - IV_SIZE_BYTES - GMAC_SIZE_BYTES : 0);
}

bool CryptoWrapper::encryptAES_GCM256(IN const BYTE* key, IN size_t keySizeBytes,
	IN const BYTE* plaintext, IN size_t plaintextSizeBytes,
	IN const BYTE* aad, IN size_t aadSizeBytes,
	OUT BYTE* ciphertextBuffer, IN size_t ciphertextBufferSizeBytes, OUT size_t* pCiphertextSizeBytes)
{
	BYTE iv[IV_SIZE_BYTES];
	BYTE mac[GMAC_SIZE_BYTES];
	size_t ciphertextSizeBytes = getCiphertextSizeAES_GCM256(plaintextSizeBytes);
	
	if ((plaintext == NULL || plaintextSizeBytes == 0) && (aad == NULL || aadSizeBytes == 0))
	{
		return false;
	}

	if (ciphertextBuffer == NULL || ciphertextBufferSizeBytes == 0)
	{
		if (pCiphertextSizeBytes != NULL)
		{
			*pCiphertextSizeBytes = ciphertextSizeBytes;
			return true;
		}
		else
		{
			return false;
		}
	}

	if (ciphertextBufferSizeBytes < ciphertextSizeBytes)
	{
		return false;
	}

	
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	bool res = false; 
	if (!ctx)
	{
		goto err;
	}

	int len;
	int ciphertext_len;

	if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
	{
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE_BYTES, NULL))
	{
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
	{
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	
	if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, aadSizeBytes))
	{
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	

	if (!EVP_EncryptUpdate(ctx, ciphertextBuffer, &len, plaintext, plaintextSizeBytes))
	{
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	ciphertext_len = len;

	if (!EVP_EncryptFinal_ex(ctx, ciphertextBuffer + len, &len))
	{
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	ciphertext_len += len;

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GMAC_SIZE_BYTES, mac))
	{
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}


	memcpy(ciphertextBuffer + ciphertext_len, mac, GMAC_SIZE_BYTES);

	if (pCiphertextSizeBytes != NULL)
	{
		*pCiphertextSizeBytes = ciphertextSizeBytes;
	}

	res=true;

err:
	EVP_CIPHER_CTX_free(ctx);
	return res;
}

bool CryptoWrapper::decryptAES_GCM256(IN const BYTE* key, IN size_t keySizeBytes,
	IN const BYTE* ciphertext, IN size_t ciphertextSizeBytes,
	IN const BYTE* aad, IN size_t aadSizeBytes,
	OUT BYTE* plaintextBuffer, IN size_t plaintextBufferSizeBytes, OUT size_t* pPlaintextSizeBytes)
{
	if (ciphertext == NULL || ciphertextSizeBytes < (IV_SIZE_BYTES + GMAC_SIZE_BYTES))
	{
		return false;
	}

	size_t plaintextSizeBytes = getPlaintextSizeAES_GCM256(ciphertextSizeBytes);
	
	if (plaintextBuffer == NULL || plaintextBufferSizeBytes == 0)
	{
		if (pPlaintextSizeBytes != NULL)
		{
			*pPlaintextSizeBytes = plaintextSizeBytes;
			return true;
		}
		else
		{
			return false;
		}
	}
	
	if (plaintextBufferSizeBytes < plaintextSizeBytes)
	{
		return false;
	}

	BYTE iv[IV_SIZE_BYTES];
	BYTE mac[GMAC_SIZE_BYTES];

	memcpy(mac, ciphertext + ciphertextSizeBytes - GMAC_SIZE_BYTES, GMAC_SIZE_BYTES);

	bool res = false;
	int len;
	int plaintextLen;

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		EVP_CIPHER_CTX_free(ctx);
		return res;
	}


	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		goto cleanup;

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE_BYTES, NULL)) {
		goto cleanup;
	}


	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
		goto cleanup;


	if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aadSizeBytes))
			goto cleanup;


	if (EVP_DecryptUpdate(ctx, plaintextBuffer, &len, ciphertext, ciphertextSizeBytes) != 1)
		goto cleanup;

	plaintextLen = len;

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GMAC_SIZE_BYTES, mac))
		goto cleanup;

	if (!EVP_DecryptFinal_ex(ctx, plaintextBuffer + len, &len))
		plaintextLen += len;
	else {
		goto cleanup; 
	}

	if (pPlaintextSizeBytes != NULL)
	{
		*pPlaintextSizeBytes = plaintextSizeBytes;
	}
	
	res=true;


cleanup:
	EVP_CIPHER_CTX_free(ctx);
	return res;
}

bool CryptoWrapper::readRSAKeyFromFile(IN const char* keyFilename, IN const char* filePassword, OUT KeypairContext** pKeyContext)
{
	
	BIO* keyBio = BIO_new_file(keyFilename, "rb");
	bool res = false;
	EVP_PKEY* pkey = PEM_read_bio_PrivateKey_ex(keyBio, NULL, NULL, (void*)filePassword, NULL, NULL);
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);

	if (!keyBio) {
		printf("Error in reading file\n");
		goto end;
	}

	if (!pkey) {
		printf("Error in reading pkey\n");
		goto end;
	}
	
	if (!ctx) {
		printf("Error in creating key context\n");
		goto end;
	}
	*pKeyContext = ctx;

	res = true; 

end: 
	EVP_PKEY_free(pkey);
	BIO_free(keyBio);
	return res;
}

bool CryptoWrapper::signMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN KeypairContext* privateKeyContext, OUT BYTE* signatureBuffer, IN size_t signatureBufferSizeBytes)
{
	if (!message || !privateKeyContext || !signatureBuffer)
	{
		return false;
	}

	EVP_MD_CTX* mdctx = EVP_MD_CTX_create();
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);;
	EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(privateKeyContext);
	
	bool result = false;

	if (!mdctx) {
		printf("Error in creating context\n"); 
		goto end; 
	}

	if (!ctx)
	{
		printf("Error in creating PKEY context\n");
		goto end;
	}

	if (!pkey)
	{
		printf("Error in obtaining pkey\n");
		goto end;
	}

	if (EVP_DigestSignInit(mdctx, &ctx, EVP_sha384(), nullptr, pkey) <= 0)
	{
		printf("Error in EVP_DigestSignInit\n");
		goto end;
	}

	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0)
	{
		printf("Error in setting RSA PSS padding\n");
		goto end;
	}

	if (EVP_DigestSignUpdate(mdctx, message, messageSizeBytes) <= 0) {
		printf("Error\n");
		goto end; 
	}

	if (EVP_DigestSignFinal(mdctx, signatureBuffer, &signatureBufferSizeBytes) <= 0) {
		printf("Error in DigestSignFinal");
		goto end;
	}
	result = true; 

	//return false;
end: 
	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	return result; 
}

bool CryptoWrapper::verifyMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN KeypairContext* publicKeyContext, IN const BYTE* signature, IN size_t signatureSizeBytes, OUT bool* result)
{
	if (!message || !publicKeyContext || !signature || !result)
	{
		return false;
	}

	EVP_MD_CTX* mdctx  = EVP_MD_CTX_create();
	EVP_PKEY_CTX* ctx  = nullptr;
	EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(publicKeyContext);
	bool res = false;

	if (!mdctx)
	{
		printf("Error in creating message digest context\n");
		goto end;
	}

	if (!pkey) {
		printf("Error in getting the key\n"); 
		goto end;
	}

	if (EVP_DigestVerifyInit(mdctx, &ctx, EVP_sha384(), nullptr, pkey) <= 0)
	{
		printf("Error in EVP_DigestVerifyInit\n");
		goto end;
	}

	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0)
	{
		printf("Error in setting RSA PSS padding\n");
		goto end;
	}

	if (EVP_DigestVerifyUpdate(mdctx, message, messageSizeBytes) <= 0)
	{
		printf("Error in EVP_DigestVerifyUpdate\n");
		goto end;
	}

	if (EVP_DigestVerifyFinal(mdctx, signature, signatureSizeBytes) <= 0)
	{
		printf("Error in verifying signature\n");
		goto end;
	}

	res=true; 


end:
	EVP_MD_CTX_destroy(mdctx);
	EVP_PKEY_CTX_free(ctx);

	*result = res;
	return res;
}


void CryptoWrapper::cleanKeyContext(INOUT KeypairContext** pKeyContext)
{
	if (*pKeyContext != NULL)
	{
		EVP_PKEY_CTX_free(*pKeyContext);
		*pKeyContext = NULL;
	}
}


bool CryptoWrapper::writePublicKeyToPemBuffer(IN KeypairContext* keyContext, OUT BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{
	EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(keyContext);
	bool res = false; 
	BUF_MEM* bufMem;
	BIO* bio = BIO_new(BIO_s_mem());

	if (!pkey)
	{
		printf("Error\n"); 
		goto err;
	}

	if (!bio)
	{
		goto err;
	}

	if (!PEM_write_bio_PUBKEY(bio, pkey))
	{
		goto err; 
	}
	res = true; 

err:
	BIO_free(bio);
	return res;

	//return false;
}


bool CryptoWrapper::loadPublicKeyFromPemBuffer(INOUT KeypairContext* context, IN const BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{
	BIO* bio = BIO_new_mem_buf(publicKeyPemBuffer, publicKeyBufferSizeBytes);
	EVP_PKEY* publicKey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);

	if (!bio) {
		printf("Error\n");
		goto err; 
	}

	if (!publicKey) {
		goto err;
	}
	
err:
	BIO_free(bio);
	return false;
}

bool CryptoWrapper::startDh(OUT DhContext** pDhContext, OUT BYTE* publicKeyBuffer, IN size_t publicKeyBufferSizeBytes)
{
	bool ret = false;
	BIGNUM* p = NULL;
	BIGNUM* g = NULL;
	unsigned char generator = 2;
	
	EVP_PKEY_CTX* pctx = NULL;
	EVP_PKEY* params = NULL;
	EVP_PKEY_CTX* kctx = NULL;
	EVP_PKEY* keyp = NULL;
	EVP_PKEY_CTX* kpctx = NULL;
	OSSL_PARAM_BLD* param_bld = NULL;
	OSSL_PARAM *param_array = NULL;
	size_t pubkey_len;

	p = BN_get_rfc3526_prime_3072(NULL);
	if (p == NULL)
	{
		goto err;
	}

	g = BN_bin2bn(&generator, 1, NULL);
	if (g == NULL)
	{
		goto err;
	}

	// ...	
	param_bld = OSSL_PARAM_BLD_new();
	if (param_bld == NULL)
	{
		goto err;
	}

	if (!OSSL_PARAM_BLD_push_BN(param_bld, "p", p) || !OSSL_PARAM_BLD_push_BN(param_bld, "g", g))
	{
		goto err;
	}

	param_array = OSSL_PARAM_BLD_to_param(param_bld);
	if (param_array == NULL)
	{
		goto err;
	}

	pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
	if (pctx == NULL)
	{
		goto err;
	}

	if (EVP_PKEY_fromdata_init(pctx) <= 0)
	{
		goto err;
	}

	
	if (EVP_PKEY_fromdata(pctx, &params, EVP_PKEY_KEYPAIR, param_array) <= 0)
	{
		goto err;
	}

	kctx = EVP_PKEY_CTX_new_from_pkey(NULL, params, NULL);
	if (kctx == NULL) {
		goto err;
	}

	if (EVP_PKEY_keygen_init(kctx)<=0){
		goto err;
	}

	if (EVP_PKEY_generate(kctx, &keyp) <=0){
		goto err;
	}

	kpctx = EVP_PKEY_CTX_new_from_pkey(NULL, keyp, NULL);
	if (kctx == NULL) {
		goto err;
	}

	if (!writePublicKeyToPemBuffer(kctx, publicKeyBuffer, publicKeyBufferSizeBytes)) {
		printf("Error\n");
		goto err;
	}

	*pDhContext = keyp;

	ret = true;

	
err:
	BN_free(p);
	BN_free(g);
	OSSL_PARAM_BLD_free(param_bld);
	OSSL_PARAM_free(param_array);
	EVP_PKEY_free(params);
	EVP_PKEY_CTX_free(pctx);
	EVP_PKEY_CTX_free(kctx);
	return ret;

}

bool CreatePeerPublicKey(const BYTE* peerPublicKey, size_t peerPublicKeySizeBytes, EVP_PKEY** genPeerPublicKey)
{ 
	
	BIGNUM* p = NULL;
	BIGNUM* g = NULL;
	BIGNUM* pk = NULL;
	OSSL_PARAM* param = NULL;
	OSSL_PARAM_BLD* param_bld = NULL;
	EVP_PKEY_CTX* ctx = NULL;
	EVP_PKEY* peerKey = NULL;
	bool res = false;

	pk = BN_bin2bn(peerPublicKey, peerPublicKeySizeBytes, NULL);
	if (pk == NULL) {
		printf("Error\n");
		goto err;
	}

	param_bld = OSSL_PARAM_BLD_new();
	if (!param_bld) {
		printf("Error in creating a param bld\n");
		goto err;
	}

	if (OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_P, p)<=0){
		printf("Error\n");
		goto err;
	}

	if (OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_FFC_G, g)<=0){
	
		printf("Error in OSSL_PARAM_BLD_push_BN\n");
		goto err;
	}

	if (OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PUB_KEY, pk)<=0){
		printf("Error\n");
		goto err;
	}

	param = OSSL_PARAM_BLD_to_param(param_bld);
	if (!param) {
		printf("Error\n");
		goto err;
	}

	ctx= EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
	if (!ctx) {
		goto err;
	}

	if (EVP_PKEY_fromdata_init(ctx)<=0){
		printf("Error\n");
		goto err;
	}

	if (EVP_PKEY_fromdata(ctx, &peerKey, EVP_PKEY_PUBLIC_KEY, param)<=0){
		printf("Error\n");
		goto err;
	}

	*genPeerPublicKey = peerKey;

	res = true;

err:
	BN_free(pk);
	BN_free(p);
	BN_free(g);
	OSSL_PARAM_BLD_free(param_bld);
	OSSL_PARAM_free(param);
	EVP_PKEY_CTX_free(ctx);
	return res;

}


bool CryptoWrapper::getDhSharedSecret(INOUT DhContext* dhContext, IN const BYTE* peerPublicKey, IN size_t peerPublicKeySizeBytes, OUT BYTE* sharedSecretBuffer, IN size_t sharedSecretBufferSizeBytes)
{

	bool ret = false;
	EVP_PKEY* genPeerPublicKey = NULL;
	EVP_PKEY_CTX* dctx = NULL;
	size_t secretLen; 

	if (dhContext == NULL || peerPublicKey == NULL || sharedSecretBuffer == NULL)
	{
		goto err;
	}

	if (!CreatePeerPublicKey(peerPublicKey, peerPublicKeySizeBytes, &genPeerPublicKey))
	{
		goto err; 
	}
		

	dctx = EVP_PKEY_CTX_new(dhContext, NULL);
	if (!dctx)
	{
		goto err;
	}

	if (EVP_PKEY_derive_init(dctx) !=1)
	{
		goto err;
	}

	if (EVP_PKEY_derive_set_peer(dctx, genPeerPublicKey) != 1)
	{
		goto err;
	}

	if (EVP_PKEY_derive(dctx, sharedSecretBuffer, &sharedSecretBufferSizeBytes) != 1)
	{
		goto err;
	}

	ret = true;

err:
	EVP_PKEY_CTX_free(dctx);
	EVP_PKEY_free(genPeerPublicKey);
	return ret;
}


void CryptoWrapper::cleanDhContext(INOUT DhContext** pDhContext)
{
	if (*pDhContext != NULL)
	{
		EVP_PKEY_free(*pDhContext);
		*pDhContext = NULL;
	}
}

X509* loadCertificate(const BYTE* certBuffer, size_t certSizeBytes)
{
	int ret = 0;
	BIO* bio = NULL;
	X509* cert = NULL;

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
	{
		printf("BIO_new() fail \n");
		goto err;
	}

	ret = BIO_write(bio, (const void*)certBuffer, (int)certSizeBytes);
	if (ret <= 0)
	{
		printf("BIO_write() fail \n");
		goto err;
	}

	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (cert == NULL)
	{
		printf("PEM_read_bio_X509() fail \n");
		goto err;
	}

err:
	BIO_free(bio);

	return cert;
}

bool CryptoWrapper::checkCertificate(IN const BYTE* cACcertBuffer, IN size_t cACertSizeBytes, IN const BYTE* certBuffer, IN size_t certSizeBytes, IN const char* expectedCN)
{
	bool res = false;
	X509* userCert = NULL;
	X509* caCert = NULL;
	X509_STORE* store = NULL;
	X509_STORE_CTX* ctx = NULL;

	caCert = loadCertificate(cACcertBuffer, cACertSizeBytes);
	if (caCert == NULL)
	{
		printf("loadCertificate() fail \n");
		goto err;
	}

	userCert = loadCertificate(certBuffer, certSizeBytes);
	if (userCert == NULL)
	{
		printf("loadCertificate() fail \n");
		goto err;
	}

	store = X509_STORE_new();
	if (store == NULL)
	{
		printf("Creation of X509 store failed \n");
		goto err;
	}


	if (X509_STORE_add_cert(store, caCert) != 1)
	{
		printf("Creation of X509 failed \n");
		goto err;
	}
	
	ctx = X509_STORE_CTX_new();
	if (ctx == NULL)
	{
		printf("Error\n");
		goto err;
	}

	if (X509_verify_cert(ctx)!=1){
		printf("Error\n");
		goto err;
	}


	if (X509_check_host(userCert, expectedCN, strlen(expectedCN), X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS, NULL)!=1){
		printf("Error\n");
		goto err;
	}
	
	res = true;

// ...

err:
	X509_free(caCert);
	X509_free(userCert);

	X509_STORE_free(store);
	X509_STORE_CTX_free(ctx);

	return res;
}


bool CryptoWrapper::getPublicKeyFromCertificate(IN const BYTE* certBuffer, IN size_t certSizeBytes, OUT KeypairContext** pPublicKeyContext)
{
	bool res = false; 
	
	X509* cert = loadCertificate(certBuffer, certSizeBytes);
	EVP_PKEY* pkey = X509_get_pubkey(cert);
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);

	if (!cert) {
		printf("Error\n");
		goto err;
	}
	if (!pkey) {
		printf("Error\n");
		goto err;
	}

	if (!ctx) {
		printf("Error\n");
		goto err; 
	}

	*pPublicKeyContext = ctx;
	res = true; 
	//return false;
err:
	X509_free(cert);
	EVP_PKEY_free(pkey);
	return res; 
}

#endif // #ifdef OPENSSL

/*
* 
* Usefull links
* -------------------------
* *  
* https://www.intel.com/content/www/us/en/develop/documentation/cpp-compiler-developer-guide-and-reference/top/compiler-reference/intrinsics/intrinsics-for-later-gen-core-proc-instruct-exts/intrinsics-gen-rand-nums-from-16-32-64-bit-ints/rdrand16-step-rdrand32-step-rdrand64-step.html
* https://wiki.openssl.org/index.php/OpenSSL_3.0
* https://www.rfc-editor.org/rfc/rfc3526
* 
* 
* Usefull APIs
* -------------------------
* 
* EVP_MD_CTX_new
* EVP_PKEY_new_raw_private_key
* EVP_DigestSignInit
* EVP_DigestSignUpdate
* EVP_PKEY_CTX_new_id
* EVP_PKEY_derive_init
* EVP_PKEY_CTX_set_hkdf_md
* EVP_PKEY_CTX_set1_hkdf_salt
* EVP_PKEY_CTX_set1_hkdf_key
* EVP_PKEY_derive
* EVP_CIPHER_CTX_new
* EVP_EncryptInit_ex
* EVP_EncryptUpdate
* EVP_EncryptFinal_ex
* EVP_CIPHER_CTX_ctrl
* EVP_DecryptInit_ex
* EVP_DecryptUpdate
* EVP_DecryptFinal_ex
* OSSL_PARAM_BLD_new
* OSSL_PARAM_BLD_push_BN
* EVP_PKEY_CTX_new_from_name
* EVP_PKEY_fromdata_init
* EVP_PKEY_fromdata
* EVP_PKEY_CTX_new
* EVP_PKEY_derive_init
* EVP_PKEY_derive_set_peer
* EVP_PKEY_derive_init
* BIO_new
* BIO_write
* PEM_read_bio_X509
* X509_STORE_new
* X509_STORE_CTX_new
* X509_STORE_add_cert
* X509_verify_cert
* X509_check_host
*
*
*
*/
