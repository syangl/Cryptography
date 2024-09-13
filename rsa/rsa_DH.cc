// Homework1: RSA Diff-Hellman
#include <iostream>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <cstring>
#include <string.h>
#include <openssl/crypto.h>
#include "rsa_gen.h"

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
    // generate Alice and Bob pkey
    EVP_PKEY_CTX *alice_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr);
    EVP_PKEY *alice_pkey = nullptr;
    if (!generate_DH(alice_ctx, alice_pkey, 0)) return false;
    EVP_PKEY_CTX *bob_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr);
    EVP_PKEY *bob_pkey = nullptr;
    if (!generate_DH(bob_ctx, bob_pkey, 1)) return false;

    printf("alice_pkey len: %d  bob_pkey len: %d\n", EVP_PKEY_size(alice_pkey), EVP_PKEY_size(bob_pkey));

    // read Alice's pkey pair
    // read private key
    FILE* alice_prif = fopen(ALICE_PRIVATE_KEY_FILE_NAME, "r");
    EVP_PKEY * alice_prik = PEM_read_PrivateKey(alice_prif, nullptr, nullptr, nullptr);
    fclose(alice_prif);
    if (alice_prik == nullptr) return false;
    // private key bytes
    printf("alice_prik: %d bytes\n", EVP_PKEY_size(alice_prik));
    // read public key
    FILE* alice_pubf = fopen(ALICE_PUBLIC_KEY_FILE_NAME, "r");
    EVP_PKEY * alice_pubk = PEM_read_PUBKEY(alice_pubf, nullptr, nullptr, nullptr);
    fclose(alice_pubf);
    if (alice_pubk == nullptr) return false;
    // // public key bytes
    printf("alice_pubk: %d bytes\n", EVP_PKEY_size(alice_pubk));

    // read Bob's pkey pair
    // read private key
    FILE* bob_prif = fopen(BOB_PRIVATE_KEY_FILE_NAME, "r");
    EVP_PKEY * bob_prik = PEM_read_PrivateKey(bob_prif, nullptr, nullptr, nullptr);
    fclose(bob_prif);
    if (bob_prik == nullptr) return false;
    // private key bytes
    printf("bob_prik: %d bytes\n", EVP_PKEY_size(bob_prik));
    // read public key
    FILE* bob_pubf = fopen(BOB_PUBLIC_KEY_FILE_NAME, "r");
    EVP_PKEY * bob_pubk = PEM_read_PUBKEY(bob_pubf, nullptr, nullptr, nullptr);
    fclose(bob_pubf);
    if (bob_pubk == nullptr) return false;
    // public key bytes
    printf("bob_pubk: %d bytes\n", EVP_PKEY_size(bob_pubk));

    /* suppose Alice and Bob exchanged pubk */

    // derive Alice share key(by using alice_prik and bob_pubk)
    EVP_PKEY_CTX *alice_share_ctx = EVP_PKEY_CTX_new(alice_prik, NULL);
    if (alice_share_ctx == nullptr) return false;
    if (EVP_PKEY_derive_init(alice_share_ctx) <= 0) return false;
    if (EVP_PKEY_derive_set_peer(alice_share_ctx, bob_pubk) <= 0) return false;
    uint8_t * alice_sharekey;
    size_t alice_sk_len = 0;
    if (EVP_PKEY_derive(alice_share_ctx, nullptr, &alice_sk_len) <= 0) return false;
    alice_sharekey = (uint8_t *)OPENSSL_malloc(alice_sk_len);
    if (EVP_PKEY_derive(alice_share_ctx, alice_sharekey, &alice_sk_len) <= 0) return false;

    // derive Bob share key(by using bob_prik and alice_pubk)
    EVP_PKEY_CTX *bob_share_ctx = EVP_PKEY_CTX_new(bob_prik, NULL);
    if (bob_share_ctx == nullptr) return false;
    if (EVP_PKEY_derive_init(bob_share_ctx) <= 0) return false;
    if (EVP_PKEY_derive_set_peer(bob_share_ctx, alice_pubk) <= 0) return false;
    uint8_t * bob_sharekey;
    size_t bob_sk_len = 0;
    if (EVP_PKEY_derive(bob_share_ctx, nullptr, &bob_sk_len) <= 0) return false;
    bob_sharekey = (uint8_t *)OPENSSL_malloc(bob_sk_len);
    if (EVP_PKEY_derive(bob_share_ctx, bob_sharekey, &bob_sk_len) <= 0) return false;

    // verify sharekey
    if (!memcmp(bob_sharekey, alice_sharekey, alice_sk_len))
        printf("DH success\n");
    else    
        printf("DH failed\n");


    // free 
    EVP_PKEY_CTX_free(alice_ctx);
    EVP_PKEY_free(alice_pkey);
    EVP_PKEY_free(alice_prik);
    EVP_PKEY_free(alice_pubk);
    EVP_PKEY_CTX_free(bob_ctx);
    EVP_PKEY_free(bob_pkey);
    EVP_PKEY_free(bob_prik);
    EVP_PKEY_free(bob_pubk);

    return true;
};

int main(){
    if (!myDH_3_0()) 
        return -1;
    return 0;
}
