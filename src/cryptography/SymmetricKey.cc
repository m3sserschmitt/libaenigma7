#include "../../include/cryptography/SymmetricKey.hh"

#include "RandomDataGenerator.hh"

#include <openssl/evp.h>

void SymmetricKey::initIV()
{
    EncrypterData *randomData = RandomDataGenerator::generate(IV_SIZE);
    memcpy(this->ivData, randomData->getData(), IV_SIZE);

    delete randomData;
}

void SymmetricKey::initCipherContext()
{
    this->freeCipherContext();

    this->cipherContext = EVP_CIPHER_CTX_new();
}

void SymmetricKey::initBuffer(Size len)
{
    this->freeBuffer();

    this->buffer = new Byte[len + 1];
    this->bufferSize = len;
}

void SymmetricKey::init(Size bufferSize)
{
    this->initBuffer(bufferSize);
    this->initIV();
    this->initCipherContext();
}

void SymmetricKey::freeCipherContext()
{
    if (this->cipherContext)
    {
        EVP_CIPHER_CTX_free(cipherContext);
        this->cipherContext = nullptr;
    }
}

void SymmetricKey::freeBuffer()
{
    if (this->buffer)
    {
        memset(this->buffer, 0, this->bufferSize);
        delete[] this->buffer;
        this->bufferSize = 0;
        this->buffer = nullptr;
    }
}

EncrypterResult *SymmetricKey::abort()
{
    this->freeCipherContext();
    this->freeBuffer();

    return new EncrypterResult(false);
}

const EncrypterResult *SymmetricKey::lock(const EncrypterData *data)
{
    if (not data or not this->keyData)
    {
        return this->abort();
    }

    init(data->getDataSize() + IV_SIZE);

    if (EVP_EncryptInit_ex(this->cipherContext, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
    {
        return this->abort();
    }

    if (EVP_EncryptInit_ex(cipherContext, NULL, NULL, this->keyData, this->ivData) != 1)
    {
        return this->abort();
    }

    int encrlen;

    if (EVP_EncryptUpdate(cipherContext, this->buffer, &encrlen, data->getData(), data->getDataSize()) != 1)
    {
        return this->abort();
    }

    if(EVP_EncryptFinal_ex(cipherContext, this->buffer + encrlen + IV_SIZE, nullptr) != 1)
    {
        return this->abort();
    }

    if(EVP_CIPHER_CTX_ctrl(cipherContext, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tagData) != 1)
    {
        return this->abort();
    }
}

const EncrypterResult *SymmetricKey::unlock(const EncrypterData *data)
{
}
