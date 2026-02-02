
#include "cryptography/EvpCipherContext.hh"

#include <openssl/evp.h>
#include <openssl/rand.h>

void EvpCipherContext::freeCipherContext()
{
    EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)this->getCipherContext());
    this->cipherContext = nullptr;
}

void EvpCipherContext::allocateCipherContext()
{
    this->freeCipherContext();
    this->cipherContext = EVP_CIPHER_CTX_new();
}

bool EvpCipherContext::generateIV()
{
    auto *randomData = new unsigned char[IV_SIZE + 1];
    if(RAND_bytes(randomData, IV_SIZE) != 1)
    {
        delete[] randomData;
        return false;
    }
    
    bool ok = this->writeIV(randomData);

    memset(randomData, 0, IV_SIZE);
    delete[] randomData;

    return ok;
}
