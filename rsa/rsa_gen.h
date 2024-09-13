// Homework1: rsa keygen file
#ifndef __RSA_GEN_H__
#define __RSA_GEN_H__
#endif

#include <iostream>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <cstring>
#include <string.h>

// PubK
#define PUBLIC_KEY_FILE_NAME "keys/pubk.pem"
// PriK
#define PRIVATE_KEY_FILE_NAME "keys/prik.pem"

// DH PubK
#define ALICE_PUBLIC_KEY_FILE_NAME "keys/Alice_DH_pubk.pem"
// DH PriK
#define ALICE_PRIVATE_KEY_FILE_NAME "keys/Alice_DH_prik.pem"
// DH PubK
#define BOB_PUBLIC_KEY_FILE_NAME "keys/Bob_DH_pubk.pem"
// DH PriK
#define BOB_PRIVATE_KEY_FILE_NAME "keys/Bob_DH_prik.pem"

// generate key
bool generate_rsa(int bits){
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if(ctx==nullptr) return false;
    EVP_PKEY *pkey = nullptr;

    if(EVP_PKEY_keygen_init(ctx) <= 0) return false;
    if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) return false;
    if(EVP_PKEY_keygen(ctx, &pkey) <= 0) return false;

    FILE *prif = nullptr, *pubf = nullptr;

    // generate private key
    prif = fopen(PRIVATE_KEY_FILE_NAME, "w");
    if (prif == nullptr) return false;
    int ret = PEM_write_PrivateKey(prif, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(prif);
    if (ret <= 0) return false;

    // generate public key
    pubf = fopen(PUBLIC_KEY_FILE_NAME, "w");
    if (pubf == nullptr) return false;
    ret = PEM_write_PUBKEY(pubf, pkey);
    fclose(pubf);
    if (ret <= 0) return false;

    EVP_PKEY_CTX_free(ctx); 

    return true;
}

bool generate_DH(EVP_PKEY_CTX *ctx, EVP_PKEY *&pkey, int flag = 0){
    // init
    const char* DH_PRIVATE_KEY_FILE_NAME;
    const char* DH_PUBLIC_KEY_FILE_NAME;
    if (flag = 0) {
        DH_PRIVATE_KEY_FILE_NAME = ALICE_PRIVATE_KEY_FILE_NAME;
        DH_PUBLIC_KEY_FILE_NAME = ALICE_PUBLIC_KEY_FILE_NAME;
    }else{
        DH_PRIVATE_KEY_FILE_NAME = BOB_PRIVATE_KEY_FILE_NAME;
        DH_PUBLIC_KEY_FILE_NAME = BOB_PUBLIC_KEY_FILE_NAME;        
    }
    int priv_len = 2 * 112;
    
    // create ctx
    if(ctx==nullptr) return false;

    // DH params by using safe prime group
    // OpenSSL ofiicial document ref: https://docs.openssl.org/3.1/man3/OSSL_PARAM_int/#description 
    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_utf8_string("group", "ffdhe2048", 0);
    params[1] = OSSL_PARAM_construct_int("priv_len", &priv_len);
    params[2] = OSSL_PARAM_construct_end();

    // genearte key pair 
    // init
    if (EVP_PKEY_keygen_init(ctx) <= 0) return false;
    // set params
    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) return false;
    // generate DH key pair
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) return false;

    FILE *prif = nullptr, *pubf = nullptr;

    // generate private key
    prif = fopen(DH_PRIVATE_KEY_FILE_NAME, "w");
    if (prif == nullptr) return false;
    int ret = PEM_write_PrivateKey(prif, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(prif);
    if (ret <= 0) return false;

    // generate public key
    pubf = fopen(DH_PUBLIC_KEY_FILE_NAME, "w");
    if (pubf == nullptr) return false;
    ret = PEM_write_PUBKEY(pubf, pkey);
    fclose(pubf);
    if (ret <= 0) return false;

    return true;
}


// int main(){
//     // generate key
//     generate_rsa(2048);

//     // alice DH pkey
//     // EVP_PKEY_CTX *alice_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr);
//     // generate_DH(alice_ctx, 0);
//     // bob DH pkey
//     // EVP_PKEY_CTX *bob_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr);
//     // generate_DH(bob_ctx, 1);
//     return 0;
// }



