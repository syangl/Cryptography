// Homework1: RSA Diff-Hellman
#include <iostream>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <cstring>
#include <string.h>

/**
 * From OpenSSL DH document's description:
 * DH struct
 * {
 *      BIGNUM *p;              // prime number (shared)
 *      BIGNUM *g;              // generator of Z_p (shared)
 *      BIGNUM *priv_key;       // private DH value x
 *      BIGNUM *pub_key;        // public DH value g^x
 *      // ...
 * };
 */

#define SHARE_KEY_SIZE 128
#define PRIME_LENGTH 64 

// 1.0 DH function (Following implement had been discarded by 3.0, it's a 1.0 version. I write here for my learning.)
bool myDH_1_0(){
    // init 
    int sharekey1_len, sharekey2_len;
    uint8_t sharekey1[SHARE_KEY_SIZE], sharekey2[SHARE_KEY_SIZE];
    int code; // DH_check code

    // create DH struct
    DH *d1 = DH_new();
    DH *d2 = DH_new();
    // generate DH parameters
    if (DH_generate_parameters_ex(d1, PRIME_LENGTH, DH_GENERATOR_2, nullptr) <= 0) 
        return false;
    // check DH parameters
    if (DH_check(d1, &code) <= 0){
        if (code & DH_CHECK_P_NOT_PRIME) printf("p is not a prime\n");
        if (code & DH_CHECK_P_NOT_SAFE_PRIME) printf("p is not safe prime\n");
        if (code & DH_UNABLE_TO_CHECK_GENERATOR) printf("unable to check generateor\n");
        if (code & DH_NOT_SUITABLE_GENERATOR) printf("not suitable generator\n");
        return false;
    }

    printf("key1 len: %d\n", DH_size(d1));

    // share d1's params(p,g) with d2
    DH_set0_pqg(d2, BN_dup(DH_get0_p(d1)), nullptr, BN_dup(DH_get0_g(d1)));    
    
    // generate pubk & prik
    if (DH_generate_key(d1) <= 0) return false;
    if (DH_generate_key(d2) <= 0) return false;

    // check pubkey
    if (DH_check_pub_key(d1, DH_get0_pub_key(d1), &code) <= 0){
        if (code & DH_CHECK_PUBKEY_TOO_SMALL) printf("pubkey too small\n");
        if (code & DH_CHECK_PUBKEY_TOO_LARGE) printf("pubkey too large\n");
        return false;
    }
    if (DH_check_pub_key(d2, DH_get0_pub_key(d2), &code) <= 0){
        if (code & DH_CHECK_PUBKEY_TOO_SMALL) printf("pubkey too small\n");
        if (code & DH_CHECK_PUBKEY_TOO_LARGE) printf("pubkey too large\n");
        return false;
    }

    // compute share key (exchange pubk)
    sharekey1_len = DH_compute_key(sharekey1, DH_get0_pub_key(d2), d1);
    sharekey2_len = DH_compute_key(sharekey2, DH_get0_pub_key(d1), d2);
    if (memcmp(sharekey1, sharekey2, sharekey1_len) <= 0) 
        return false;
    else    
        printf("share key successed!\n");

    // free
    DH_free(d1);
    DH_free(d2);

    return true;
};

// 3.0 DH
bool myDH_3_0(){
    // init
    int priv_len = 2 * 112;
    OSSL_PARAM params[3];
    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(nullptr, "DH", nullptr);
    if (ctx == nullptr) return false;

    // OpenSSL ofiicial document ref: https://docs.openssl.org/3.1/man3/OSSL_PARAM_int/#description 
    params[0] = OSSL_PARAM_construct_utf8_string("group", "ffdhe2048", 0);
    params[1] = OSSL_PARAM_construct_int("priv_len", &priv_len);
    params[2] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_keygen_init(ctx) <= 0) return false;
    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) return false;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) return false;
    // free 
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return true;
};

int main(){
    if (!myDH_3_0()) 
        return -1;
    return 0;
}
