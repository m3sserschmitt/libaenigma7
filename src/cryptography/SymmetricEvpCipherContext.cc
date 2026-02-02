#include "cryptography/SymmetricEvpCipherContext.hh"

#include <openssl/evp.h>

EncrypterResult *SymmetricEvpCipherContext::createEncryptedData() const
{
    unsigned int bufferSize = this->getOutBufferSize();
    unsigned int finalDataSize = bufferSize + IV_SIZE + TAG_SIZE;

    auto *finalData = new unsigned char[finalDataSize + 1];

    memcpy(finalData, this->getIV(), IV_SIZE);
    memcpy(finalData + IV_SIZE, this->getOutBuffer(), bufferSize);
    memcpy(finalData + IV_SIZE + bufferSize, this->getTag(), TAG_SIZE);

    auto *result = new EncrypterResult(finalData, finalDataSize);

    memset(finalData, 0, finalDataSize);
    delete[] finalData;

    return result;
}

const unsigned char *SymmetricEvpCipherContext::readEncryptedData(const EncrypterData *in, int &cipherLen)
{
    cipherLen = -1;

    if (not in or not in->getData())
    {
        return nullptr;
    }

    unsigned int dataSize = in->getDataSize();
    const unsigned char *data = in->getData();

    if (not this->writeIV(data) or not this->writeTag(data + dataSize - TAG_SIZE))
    {
        return nullptr;
    }

    cipherLen = (int)dataSize - IV_SIZE - TAG_SIZE;
    return data + IV_SIZE;
}

EncrypterResult *SymmetricEvpCipherContext::encrypt(const EncrypterData *in)
{
    if (not in or not in->getData())
    {
        return this->abort();
    }

    this->cleanup();

    this->encryptionAllocateMemory(in);
    this->generateIV();

    if (EVP_EncryptInit_ex((EVP_CIPHER_CTX *)this->getCipherContext(), EVP_aes_256_gcm(), nullptr, (const unsigned char *)this->getKey()->getKeyData(), this->getIV()) != 1)
    {
        return this->abort();
    }

    int len;

    if (EVP_EncryptUpdate((EVP_CIPHER_CTX *)this->getCipherContext(), this->getOutBuffer(), &len, in->getData(), (int)in->getDataSize()) != 1)
    {
        return this->abort();
    }

    int len2;

    if (EVP_EncryptFinal_ex((EVP_CIPHER_CTX *)this->getCipherContext(), this->getOutBuffer() + len, &len2) != 1)
    {
        return this->abort();
    }

    this->setOutBufferSize(len + len2);

    if (EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX *)this->getCipherContext(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, this->getTag()) != 1)
    {
        return this->abort();
    }

    EncrypterResult *result = this->createEncryptedData();

    this->cleanup();

    return result;
}

EncrypterResult *SymmetricEvpCipherContext::decrypt(const EncrypterData *in)
{
    if (not in or not in->getData())
    {
        return this->abort();
    }

    this->cleanup();
    this->decryptionAllocateMemory(in);

    int cipherLen;
    const unsigned char *ciphertext = this->readEncryptedData(in, cipherLen);

    if (not ciphertext or cipherLen < 0)
    {
        return this->abort();
    }

    if (EVP_DecryptInit_ex((EVP_CIPHER_CTX *)this->getCipherContext(), EVP_aes_256_gcm(), nullptr, (const unsigned char *)this->getKey()->getKeyData(), this->getIV()) != 1)
    {
        return this->abort();
    }

    int len;

    if (EVP_DecryptUpdate((EVP_CIPHER_CTX *)this->getCipherContext(), this->getOutBuffer(), &len, ciphertext, cipherLen) != 1)
    {
        return this->abort();
    }

    if (EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX *)this->getCipherContext(), EVP_CTRL_GCM_SET_TAG, TAG_SIZE, this->getTag()) != 1)
    {
        return this->abort();
    }

    int len2;

    if (EVP_DecryptFinal_ex((EVP_CIPHER_CTX *)this->getCipherContext(), this->getOutBuffer() + len, &len2) != 1)
    {
        return this->abort();
    }

    this->setOutBufferSize(len + len2);

    auto *result = new EncrypterResult(this->getOutBuffer(), this->getOutBufferSize());

    this->cleanup();

    return result;
}
