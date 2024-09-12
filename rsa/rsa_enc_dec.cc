// RSA implement
// note: 签名算法和加解密不能写在一个文件里，会出问题，分开分别单独写
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

// encrypt function
bool rsa_encrypt(uint8_t* in, uint32_t in_len, uint8_t* out, uint32_t* out_len){
    // read public key
    FILE* pubf = fopen(PUBLIC_KEY_FILE_NAME, "r");
    EVP_PKEY * pubk = PEM_read_PUBKEY(pubf, nullptr, nullptr, nullptr);
    fclose(pubf);
    if (pubk == nullptr) return false;

    // // public key bytes
    printf("pubk: %d bytes\n", EVP_PKEY_size(pubk));

    // create ctx with private key
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubk, nullptr);
    if (ctx == nullptr) return false;
    // init ctx  
    if (EVP_PKEY_encrypt_init(ctx) <= 0) return false;
    // padding
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) return false;
    // encrypt
    if (EVP_PKEY_encrypt(ctx, out, (size_t*)out_len, in, in_len) <= 0) return false;
    // free ctx
    EVP_PKEY_CTX_free(ctx);

    return true;
}

// decrypt function
bool rsa_decrypt(uint8_t* in, uint32_t in_len, uint8_t* out, uint32_t *out_len){
    // read private key
    FILE* prif = fopen(PRIVATE_KEY_FILE_NAME, "r");
    EVP_PKEY * prik = PEM_read_PrivateKey(prif, nullptr, nullptr, nullptr);
    fclose(prif);
    if (prik == nullptr) return false;
    // private key bytes
    printf("prik: %d bytes\n", EVP_PKEY_size(prik));

    // create ctx with private key
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(prik, nullptr);
    if (ctx == nullptr) return false;
    // init ctx  
    if (EVP_PKEY_decrypt_init(ctx) <= 0) return false;
    // padding
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) return false;
    // decrypt
    if (EVP_PKEY_decrypt(ctx, out, (size_t*)out_len, in, in_len) <= 0) return false;
    // free ctx
    EVP_PKEY_CTX_free(ctx);

    return true;
}


int main(){
    // init
    const char *text = "THIS IS A RSA TEST!";
    uint32_t text_len = strlen(text);
    uint8_t cipher[512] = {0};
    uint32_t cipher_len = 0;
    uint8_t plain[512] = {0};
    uint32_t plain_len = 0;

    printf("text: %s len: %d\n", text, text_len);

    // encrypt 
    if (!rsa_encrypt((uint8_t *)text, text_len, cipher, &cipher_len))
        printf("encrypt error!");
    else{
        printf("encrypt len: %d\n", cipher_len);
    }
    // decrypt
    if (!rsa_decrypt(cipher, cipher_len, plain, &plain_len))
        printf("decrypt error!\n");
    else{
        printf("decrypt: %s len: %d\n", plain, plain_len);
    }
  
    return 0;
};