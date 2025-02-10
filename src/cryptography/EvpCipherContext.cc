
#include "cryptography/EvpCipherContext.hh"

#include <openssl/evp.h>

void EvpCipherContext::freeCipherContext()
{
    EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)this->getCipherContext());
    this->cipherContext = nullptr;
}

bool EvpCipherContext::allocateCipherContext()
{
    this->freeCipherContext();
    this->cipherContext = EVP_CIPHER_CTX_new();

    return this->getCipherContext() != nullptr;
}
