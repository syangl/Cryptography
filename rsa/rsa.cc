// RSA implement
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

// generate key
bool generate_rsa(int bits){
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if(ctx==nullptr) return false;
    EVP_PKEY *pkey = nullptr;

    if(EVP_PKEY_keygen_init(ctx) != 1) return false;
    if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) != 1) return false;
    if(EVP_PKEY_keygen(ctx, &pkey) != 1) return false;

    FILE *prif = nullptr, *pubf = nullptr;

    // generate private key
    prif = fopen(PRIVATE_KEY_FILE_NAME, "w");
    if (prif == nullptr) return false;
    int ret = PEM_write_PrivateKey(prif, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(prif);
    if (ret != 1) return false;

    // generate public key
    pubf = fopen(PUBLIC_KEY_FILE_NAME, "w");
    if (pubf == nullptr) return false;
    ret = PEM_write_PUBKEY(pubf, pkey);
    fclose(pubf);
    if (ret != 1) return false;

    EVP_PKEY_CTX_free(ctx); 

    return true;
}






// encrypt function
bool rsa_encrypt(const uint8_t* in, uint32_t in_len, uint8_t* out, size_t* out_len){
    // read public key
    FILE* pubf = fopen(PUBLIC_KEY_FILE_NAME, "r");
    EVP_PKEY * pubk = PEM_read_PUBKEY(pubf, nullptr, nullptr, nullptr);
    fclose(pubf);
    if (pubk == nullptr) return false;

    // // public key bytes
    // int pbuk_len = EVP_PKEY_size(pubk);

    // create ctx with private key
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubk, nullptr);
    if (ctx == nullptr) return false;
    // init ctx  
    if (EVP_PKEY_encrypt_init(ctx) != 1) return false;
    // encrypt
    if (EVP_PKEY_encrypt(ctx, out, out_len, in, in_len) != 1) return false;
    // free ctx
    EVP_PKEY_CTX_free(ctx);

    return true;
}





// decrypt function
bool rsa_decrypt(const uint8_t* in, uint32_t in_len, unsigned char* out, size_t *out_len){
    // read private key
    FILE* prif = fopen(PRIVATE_KEY_FILE_NAME, "r");
    EVP_PKEY * prik = PEM_read_PrivateKey(prif, nullptr, nullptr, nullptr);
    fclose(prif);
    if (prik == nullptr) return false;
    // // private key bytes
    // int prik_len = EVP_PKEY_size(prik);

    // create ctx with private key
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(prik, nullptr);
    if (ctx == nullptr) return false;
    // init ctx  
    if (EVP_PKEY_decrypt_init(ctx) != 1) return false;

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) != 1) return false;
    
    // if (EVP_PKEY_decrypt(ctx, nullptr, out_len, in, in_len) <= 0) return false;
    // out = (unsigned char*)OPENSSL_malloc(*out_len);
    // if (!out) return false;
    // decrypt
    if (EVP_PKEY_decrypt(ctx, out, out_len, in, in_len) <= 0) return false;

    // free ctx
    EVP_PKEY_CTX_free(ctx);

    return true;
}





// signature
bool signature(const uint8_t* in, uint32_t in_len, uint8_t* out, uint32_t* out_len){
    // read private key
    FILE *prif = fopen(PRIVATE_KEY_FILE_NAME, "r");
    EVP_PKEY *prik = PEM_read_PrivateKey(prif, nullptr, nullptr, nullptr);
    fclose(prif);
    if (prik == nullptr) return false;

    // ctx
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) return false;
    // init ctx
    if (EVP_SignInit(ctx, EVP_sha256()) != 1) return false;
    // update
    if (EVP_SignUpdate(ctx, in, in_len) != 1) return false;
    // final
    if (EVP_SignFinal(ctx, out, out_len, prik) != 1) return false;
    // free
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(prik);
    return true;
}   




// vertification    
bool vertify(const uint8_t* in, uint32_t in_len, uint8_t* out, uint32_t out_len){
    // read public key 
    FILE *pubf = fopen(PUBLIC_KEY_FILE_NAME, "r");
    EVP_PKEY * pubk = PEM_read_PUBKEY(pubf, nullptr, nullptr, nullptr);
    fclose(pubf);
    if (pubk == nullptr) return false;

    // create ctx 
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) return false;
    // ctx init
    if (EVP_VerifyInit(ctx, EVP_sha256()) != 1) return false;
    // update
    if (EVP_VerifyUpdate(ctx, in, in_len) != 1) return false;
    // final
    if (EVP_VerifyFinal(ctx, out, out_len, pubk) != 1) return false;
    // free
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pubk);

    return true;
}

// Diff-Hellman
// TODO



int main(){
    // generate key
    generate_rsa(2048);

    // init
    const char * text = "RSA TEST!";
    uint32_t text_len = strlen(text);
    uint8_t cipher[256] = {0};
    size_t cipher_len;
    unsigned char plain[256] = {0};
    size_t plain_len;
    uint8_t sign[256] = {0};
    uint32_t sign_len;

    printf("text: %s\n", text);

    // encrypt 
    rsa_encrypt((const uint8_t*)text, text_len, cipher, &cipher_len);
    printf("encrypt: %s\n", cipher);
    // decrypt
    rsa_decrypt((const uint8_t*)cipher, cipher_len, plain, &plain_len);
    printf("decrypt: %s\n", plain);
    
    // sign
    if (!signature((const uint8_t *)text, text_len, sign, &sign_len))
        printf("sign failed\n");
    else  
        printf("sign: %s\n", sign);
    // vertify
    if(!vertify((const uint8_t*)text, text_len, sign, sign_len))
        printf("vertify failed\n");
    else
        printf("vertify success\n");

    
    // Diff-Hellman
    // TODO


    return 0;
};