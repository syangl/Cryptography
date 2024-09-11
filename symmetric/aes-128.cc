// AES-128 implement
#include <iostream>
#include <openssl/evp.h>
#include <cstring>
#include <string.h>


/* encrypt function 
 * params
 * - in: plaint text
 * - in_len: 
 * - out: cipher text (where encrypter saves cipher outcome)
 * - out_len:
 * - key: cipher key
 * - iv: init vector in cbc etc.
 */
bool aes_128_cbc_encrypt(const uint8_t *in, int in_len, uint8_t *out, int *out_len, const uint8_t*key, const uint8_t *iv){
    // local variables for encrypt function
    int update_len = 0; // processed length in EncryptUpdate
    int final_len = 0; // processed length in EncryptFinal
    
    // create evp content ctx (used to save algorithm's middle outcome and final outcome)
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) return false;
    
    // set evp algorithm
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();

    // evp init
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key, iv) != 1) return false;

    // evp update (middle computing process)
    if (EVP_EncryptUpdate(ctx, out, &update_len, in, in_len) != 1) return false; 

    // evp final (compute last block and return final encrypt outcome)
    if (EVP_EncryptFinal_ex(ctx, out+update_len, &final_len) != 1) return false;

    // encrypt out length
    *out_len = update_len + final_len;

    // free ctx    
    EVP_CIPHER_CTX_free(ctx);

    return true;
};


/* decrypt function 
 * params
 * - in: cipher text 
 * - in_len: 
 * - out: plain text (where decrypter saves plain outcome)
 * - out_len:
 * - key: cipher key
 * - iv: init vector in cbc etc.
 */
bool aes_128_cbc_decrypt(const uint8_t *in, int in_len, uint8_t *out, int *out_len, const uint8_t*key, const uint8_t *iv){
    // local variables for decrypt function
    int update_len = 0; // processed length in DecryptUpdate
    int final_len = 0; // processed length in DecryptFinal
    
    // create evp content ctx (used to save algorithm's middle outcome and final outcome)
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) return false;
    
    // set evp algorithm
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();

    // evp init
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key, iv) != 1) return false;

    // evp update (middle computing process)
    if (EVP_DecryptUpdate(ctx, out, &update_len, in, in_len) != 1) return false; 

    // evp final (compute last block and return final decrypt outcome)
    if (EVP_DecryptFinal_ex(ctx, out+update_len, &final_len) != 1) return false;

    // decrypt out length
    *out_len = update_len + final_len;

    // free ctx
    EVP_CIPHER_CTX_free(ctx);

    return true;
}



int main(){// TODO
    // Init key, iv (suppose we have got key and iv)
    uint8_t key[16];
    uint8_t iv[16];
    srand(time(0));
    for (int i = 0; i < 16; i++){
        key[i] = (uint8_t)(rand()%100 + 1);
        iv[i] = (uint8_t)(rand()%100 + 1);
    }

    // Init plain, cipher variable
    const char *text = "This is a homework test!";
    const int text_len = strlen(text);
    printf("text: %s  len: %d\n", text, text_len);
    
    uint8_t cipher[64];
    memset(cipher, 0, 64);
    int cipher_len;
    
    uint8_t plain[64];
    memset(plain, 0, 64);
    int plain_len;
    // Encrypt
    if(aes_128_cbc_encrypt((uint8_t*)text, text_len, cipher, &cipher_len, key, iv) == false)
        return -1;
    else
        printf("encrypt outcome: %s  len: %d\n", cipher, cipher_len);
    // Decrypt
    if(aes_128_cbc_decrypt(cipher, cipher_len, plain, &plain_len, key, iv) == false)
        return -1;
    else
        printf("decrypt outcome: %s  len: %d\n", plain, plain_len);
    
    return 0;
}

