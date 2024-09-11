// AES-128 implement
#include <iostream>
#include <openssl/evp.h>

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
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key, iv) != 1) return false;

    // evp update (middle computing process)
    if (EVP_EncryptUpdate(ctx, out, &update_len, in, in_len) != 1) return false; 

    // evp final (compute last block and return final decrypt outcome)
    if (EVP_EncryptFinal_ex(ctx, out+update_len, &final_len) != 1) return false;

    // decrypt out length
    *out_len = update_len + final_len;

    return true;
}



int main(){// TODO
    // Init key, iv

    // Init plain, cipher variable

    // Encrypt

    // Decrypt

    return 0;
}

