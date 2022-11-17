#include "../../include/cryptography/SymmetricKey.hh"

#include <openssl/evp.h>

void SymmetricKey::initDecryption(const EncrypterData *data)
{
    Size encrlen = data->getDataSize() - IV_SIZE - TAG_SIZE;
    const Byte *payload = data->getData();

    this->createBuffer(encrlen);
    this->createCipherContext();
    this->initIV(payload);
    this->initTagData(payload + data->getDataSize() - TAG_SIZE);
}

EncrypterResult *SymmetricKey::prepareEncryptedBuffer()
{
    Size bufferSize = this->getBufferSize();
    Size finalDataSize = bufferSize + IV_SIZE + TAG_SIZE;

    Bytes buffer = this->getBuffer();

    Bytes finalData = new Byte[finalDataSize + 1];

    memcpy(finalData, this->ivData, IV_SIZE);
    memcpy(finalData + IV_SIZE, buffer, bufferSize);
    memcpy(finalData + IV_SIZE + bufferSize, this->tagData, TAG_SIZE);

    EncrypterResult *result = new EncrypterResult(finalData, finalDataSize);
    memset(finalData, 0, finalDataSize);
    delete[] finalData;

    return result;
}

const EncrypterResult *SymmetricKey::lock(const EncrypterData *data)
{
    if (not data)
    {
        return this->abort();
    }

    this->initEncryption(data->getDataSize());
    Bytes buffer = this->getBuffer();

    if (EVP_EncryptInit_ex(this->cipherContext, EVP_aes_256_gcm(), NULL, this->keyData, this->ivData) != 1)
    {
        return this->abort();
    }

    int encrlen;

    if (EVP_EncryptUpdate(cipherContext, buffer, &encrlen, data->getData(), data->getDataSize()) != 1)
    {
        return this->abort();
    }

    int encrlen2;

    if(EVP_EncryptFinal_ex(cipherContext, buffer + encrlen, &encrlen2) != 1)
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

    Bytes buffer = this->getBuffer();
    Size bufferSize = this->getBufferSize();

    if (EVP_DecryptInit_ex(this->cipherContext, EVP_aes_256_gcm(), NULL, this->keyData, this->ivData) != 1)
    {
        return this->abort();
    }

    int decrlen;

    if (EVP_DecryptUpdate(cipherContext, buffer, &decrlen, data->getData() + IV_SIZE, bufferSize) != 1)
    {
        return this->abort();
    }

    if(EVP_CIPHER_CTX_ctrl(cipherContext, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tagData) != 1)
    {
        return this->abort();
    }

    int decrlen2;

    if(EVP_DecryptFinal_ex(cipherContext, buffer + decrlen, &decrlen2) != 1)
    {
        return this->abort();
    }

    return new EncrypterResult(buffer, bufferSize);
}
