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


int main(){
    // generate key
    generate_rsa(2048);
    return 0;
}



