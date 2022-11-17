#include "../../include/cryptography/SymmetricKey.hh"
#include "../../include/cryptography/RandomDataGenerator.hh"

#include <openssl/evp.h>

void SymmetricKey::initIV()
{
    EncrypterData *randomData = RandomDataGenerator::generate(IV_SIZE);
    memcpy(this->ivData, randomData->getData(), IV_SIZE);

    delete randomData;
}

void SymmetricKey::initIV(const Byte *ivData)
{
    memcpy(this->ivData, ivData, IV_SIZE);
}

void SymmetricKey::createCipherContext()
{
    this->freeCipherContext();

    this->cipherContext = EVP_CIPHER_CTX_new();
}

void SymmetricKey::createBuffer(Size len)
{
    this->freeBuffer();

    this->buffer = new Byte[len + 1];
    this->bufferSize = len;
}

void SymmetricKey::initEncryption(Size bufferSize)
{
    this->createBuffer(bufferSize);
    this->initIV();
    this->createCipherContext();
}

void SymmetricKey::initDecryption(const EncrypterData *data)
{
    Size encrlen = data->getDataSize() - IV_SIZE - TAG_SIZE;
    const Byte *payload = data->getData();

    this->createBuffer(encrlen);
    this->createCipherContext();
    this->initIV(payload);
    this->initTagData(payload + data->getDataSize() - TAG_SIZE);
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

EncrypterResult *SymmetricKey::prepareEncryptedBuffer()
{
    Bytes buffer = new Byte[this->bufferSize + IV_SIZE + TAG_SIZE + 1];

    memcpy(buffer, this->ivData, IV_SIZE);
    memcpy(buffer + IV_SIZE, this->buffer, this->bufferSize);
    memcpy(buffer + IV_SIZE + this->bufferSize, this->tagData, TAG_SIZE);

    return new EncrypterResult(buffer, this->bufferSize + IV_SIZE + TAG_SIZE);
}

const EncrypterResult *SymmetricKey::lock(const EncrypterData *data)
{
    if (not data)
    {
        return this->abort();
    }

    this->initEncryption(data->getDataSize());

    if (EVP_EncryptInit_ex(this->cipherContext, EVP_aes_256_gcm(), NULL, this->keyData, this->ivData) != 1)
    {
        return this->abort();
    }

    int encrlen;

    if (EVP_EncryptUpdate(cipherContext, this->buffer, &encrlen, data->getData(), data->getDataSize()) != 1)
    {
        return this->abort();
    }

    int encrlen2;

    if(EVP_EncryptFinal_ex(cipherContext, this->buffer + encrlen, &encrlen2) != 1)
    {
        return this->abort();
    }

    if(EVP_CIPHER_CTX_ctrl(cipherContext, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, this->tagData) != 1)
    {
        return this->abort();
    }

    return prepareEncryptedBuffer();
}

const EncrypterResult *SymmetricKey::unlock(const EncrypterData *data)
{
    if (not data)
    {
        return this->abort();
    }
    
    this->initDecryption(data);

    if (EVP_DecryptInit_ex(this->cipherContext, EVP_aes_256_gcm(), NULL, this->keyData, this->ivData) != 1)
    {
        return this->abort();
    }

    int decrlen;

    if (EVP_DecryptUpdate(cipherContext, this->buffer, &decrlen, data->getData() + IV_SIZE, this->bufferSize) != 1)
    {
        return this->abort();
    }

    if(EVP_CIPHER_CTX_ctrl(cipherContext, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tagData) != 1)
    {
        return this->abort();
    }

    int decrlen2;

    if(EVP_DecryptFinal_ex(cipherContext, this->buffer + decrlen, &decrlen2) != 1)
    {
        return this->abort();
    }

    return new EncrypterResult(this->buffer, this->bufferSize);
}
