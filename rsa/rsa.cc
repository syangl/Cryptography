// RSA implement
#include <iostream>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <cstring>
#include <string.h>

// generate key
bool generate_rsa(int bits){
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
    EVP_PKEY_keygen(ctx, &pkey);

    FILE *prif = nullptr, *pubf = nullptr;

    // generate private key
    prif = fopen("./keys/rsa_prik.pem", "w");
    PEM_write_PrivateKey(prif, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(prif);

    // generate public key
    pubf = fopen("./keys/rsa_pubk.pem", "w");
    PEM_write_PUBKEY(pubf, pkey);
    fclose(pubf);

    EVP_PKEY_CTX_free(ctx); 

}






// encrypt function
bool rsa_encrypt(const uint8_t* in, uint32_t in_len, uint8_t* out, uint32_t* out_len){
    // read public key
    FILE* pubf = fopen("./keys/rsa_pubk.pem", "r");
    EVP_PKEY * pubk = PEM_read_PUBKEY(pubf, nullptr, nullptr, nullptr);
    fclose(pubf);

    // // public key bytes
    // int pbuk_len = EVP_PKEY_size(pubk);

    // create ctx with private key
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubk, nullptr);

    // init ctx  
    EVP_PKEY_encrypt_init(ctx);
    // encrypt
    size_t len = 0;
    EVP_PKEY_encrypt(ctx, out, &len, in, in_len);
    *out_len = len;
    // free ctx
    EVP_PKEY_CTX_free(ctx);

    return true;
}





// decrypt function
bool rsa_decrypt(const uint8_t* in, uint32_t in_len, uint8_t* out, uint32_t *out_len){
    // read private key
    FILE* prif = fopen("./keys/rsa_prik.pem", "r");
    EVP_PKEY * prik = PEM_read_PrivateKey(prif, nullptr, nullptr, nullptr);
    fclose(prif);

    // // private key bytes
    // int prik_len = EVP_PKEY_size(prik);

    // create ctx with private key
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(prik, nullptr);

    // init ctx  
    EVP_PKEY_decrypt_init(ctx);
    // decrypt
    size_t len = 0;
    EVP_PKEY_decrypt(ctx, out, &len, in, in_len);
    *out_len = len;
    // free ctx
    EVP_PKEY_CTX_free(ctx);

    return true;
}





// signature
bool signature(const uint8_t* in, uint32_t in_len, uint8_t* out, uint32_t* out_len){
    // read private key
    FILE *prif = fopen("./keys/rsa_prik.pem", "r");
    EVP_PKEY *prik = PEM_read_PrivateKey(prif, nullptr, nullptr, nullptr);
    fclose(prif);

    // ctx
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    // init ctx
    EVP_SignInit(ctx, EVP_sha256());
    // update
    EVP_SignUpdate(ctx, in, in_len);
    // final
    uint32_t len = 0;
    EVP_SignFinal(ctx, out, &len, prik);
    *out_len = len;
    // free
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(prik);
    return true;
}




// vertification    
bool vertify(const uint8_t* in, uint32_t in_len, uint8_t* out, uint32_t *out_len){
    // read public key 
    FILE *pubf = fopen("./keys/rsa_pubk.pem", "r");
    EVP_PKEY * pubk = PEM_read_PUBKEY(pubf, nullptr, nullptr, nullptr);
    fclose(pubf);

    // create ctx 
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    // ctx init
    EVP_VerifyInit(ctx, EVP_sha256());
    // update
    EVP_VerifyUpdate(ctx, in, in_len);
    // final
    uint32_t len = 0;
    EVP_VerifyFinal(ctx, out, len, pubk);
    *out_len = len;
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
    const char * text = "THIS IS A RSA TEST!";
    uint32_t text_len = strlen(text);
    uint8_t cipher[256] = {0};
    uint32_t cipher_len;
    uint8_t plain[256] = {0};
    uint32_t plain_len;
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
    if(!vertify((const uint8_t*)text, text_len, sign, &sign_len))
        printf("vertify failed\n");
    else
        printf("vertify success\n");

    
    // Diff-Hellman
    // TODO


    return 0;
};