// Homework1: RSA implement signature & vertify
#include <iostream>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <cstring>
#include <string.h>
#include "rsa_gen.h"

// signature
bool signature(uint8_t* in, uint32_t in_len, uint8_t* out, uint32_t* out_len){
    // read private key
    FILE *prif = fopen(PRIVATE_KEY_FILE_NAME, "r");
    EVP_PKEY *prik = PEM_read_PrivateKey(prif, nullptr, nullptr, nullptr);
    fclose(prif);
    if (prik == nullptr) return false;

    // ctx
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) return false;
    // init ctx
    if (EVP_SignInit(ctx, EVP_sha256()) <= 0) return false;
    // update
    if (EVP_SignUpdate(ctx, in, in_len) <= 0) return false;
    // final
    if (EVP_SignFinal(ctx, out, out_len, prik) <= 0) return false;
    // free
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(prik);
    return true;
}   

// vertification    
bool vertify(uint8_t* in, uint32_t in_len, uint8_t* out, uint32_t out_len){
    // read public key 
    FILE *pubf = fopen(PUBLIC_KEY_FILE_NAME, "r");
    EVP_PKEY * pubk = PEM_read_PUBKEY(pubf, nullptr, nullptr, nullptr);
    fclose(pubf);
    if (pubk == nullptr) return false;

    // create ctx 
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) return false;
    // ctx init
    if (EVP_VerifyInit(ctx, EVP_sha256()) <= 0) return false;
    // update
    if (EVP_VerifyUpdate(ctx, in, in_len) <= 0) return false;
    // final
    if (EVP_VerifyFinal(ctx, out, out_len, pubk) <= 0) return false;
    // free
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pubk);

    return true;
}

int main(){
    // key generate
    generate_rsa(RSA_KEY_SIZE);
    // init 
    const char *text = "THIS IS A RSA TEST!";
    uint32_t text_len = strlen(text);
    uint8_t cipher[512] = {0};
    uint32_t cipher_len = 0;
    uint8_t sign[512] = {0};
    uint32_t sign_len = 0;

    printf("text: %s\n", text);

    // sign
    if (!signature((uint8_t *)text, text_len, sign, &sign_len))
        printf("sign failed\n");
    else  
        printf("sign len: %d\n", sign_len);
    // vertify
    if(!vertify((uint8_t *)text, text_len, sign, sign_len))
        printf("vertify failed\n");
    else
        printf("vertify success\n");

    return 0;
};