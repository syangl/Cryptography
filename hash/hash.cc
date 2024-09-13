// Homework1: hash 
#include <iostream>
#include <openssl/evp.h>
#include <cstring>
#include <string.h>
using namespace std;


// Digest SHA-512
bool digest_sha_512(const char* in, uint32_t in_len, uint8_t* out, uint32_t* out_len){
    // create ctx
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) return false;
    // init ctx
    if (EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr) <= 0) return false;
    // update
    if (EVP_DigestUpdate(ctx, in, in_len) <= 0) return false;
    // final
    if (EVP_DigestFinal(ctx, out, out_len) <= 0) return false;

    return true;
};


int main(){
    const char* text = "HASH TEST!";
    uint32_t text_len = strlen(text);
    uint8_t digest[64] = {0};
    uint32_t digest_len;
    
    if (!digest_sha_512(text, text_len, digest, &digest_len))
        printf("digest fail\n");
    else    
        printf("digest: %s len: %d\n", digest, digest_len) ;

    return 0; 
};
