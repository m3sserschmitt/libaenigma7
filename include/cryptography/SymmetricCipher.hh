#ifndef CIPHER_CONTEXT_HH
#define CIPHER_CONTEXT_HH

#include "Cipher.hh"
#include "SymmetricKey.hh"

#include <openssl/evp.h>

class SymmetricCipher : Cipher
{
    Bytes getKeyData() { return (Bytes)this->getKey()->getKeyMaterial(); }

    bool encryptionAllocateMemory(const EncrypterData *in)
    {
        return this->allocateCipherContext() and this->allocateIV() and this->allocateOutBuffer(in->getDataSize()) and this->allocateTag();
    }

    bool decryptionAllocateMemory(const EncrypterData *in)
    {
        Size outBufferSize = in->getDataSize() - IV_SIZE - TAG_SIZE;
        return this->allocateCipherContext() and this->allocateIV() and this->allocateOutBuffer(outBufferSize) and this->allocateTag();
    }

    EncrypterResult *createEncryptedData()
    {
        Size bufferSize = this->getOutBufferSize();
        Size finalDataSize = bufferSize + IV_SIZE + TAG_SIZE;

        Bytes finalData = new Byte[finalDataSize + 1];

        memcpy(finalData, this->getIV(), IV_SIZE);
        memcpy(finalData + IV_SIZE, this->getOutBuffer(), bufferSize);
        memcpy(finalData + IV_SIZE + bufferSize, this->getTag(), TAG_SIZE);

        EncrypterResult *result = new EncrypterResult(finalData, finalDataSize);

        memset(finalData, 0, finalDataSize);
        delete[] finalData;

        return result;
    }

    ConstBytes readEncryptedData(const EncrypterData *in, Size &cipherlen)
    {
        cipherlen = 0;

        if (not in or not in->getData())
        {
            return nullptr;
        }

        Size dataSize = in->getDataSize();
        ConstBytes data = in->getData();

        if (not this->writeIV(data) or not this->writeTag(data + dataSize - TAG_SIZE))
        {
            return nullptr;
        }

        cipherlen = dataSize - IV_SIZE - TAG_SIZE;
        return data + IV_SIZE;
    }

public:
    SymmetricCipher(Key *key) : Cipher(key) {}

    EncrypterResult *encrypt(const EncrypterData *in) override
    {
        if (not in or not in->getData())
        {
            return this->abort();
        }

        this->reset();

        if (not this->encryptionAllocateMemory(in) or not this->generateIV())
        {
            return this->abort();
        }

        if (EVP_EncryptInit_ex(this->getCipherContext(), EVP_aes_256_gcm(), NULL, this->getKeyData(), this->getIV()) != 1)
        {
            return this->abort();
        }

        int len;

        if (EVP_EncryptUpdate(this->getCipherContext(), this->getOutBuffer(), &len, in->getData(), in->getDataSize()) != 1)
        {
            return this->abort();
        }

        int len2;

        if (EVP_EncryptFinal_ex(this->getCipherContext(), this->getOutBuffer() + len, &len2) != 1)
        {
            return this->abort();
        }

        this->setOutBufferSize(len + len2);

        if (EVP_CIPHER_CTX_ctrl(this->getCipherContext(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, this->getTag()) != 1)
        {
            return this->abort();
        }

        EncrypterResult *result = this->createEncryptedData();

        this->reset();

        return result;
    }

    EncrypterResult *decrypt(const EncrypterData *in) override
    {
        if (not in or not in->getData())
        {
            return this->abort();
        }

        this->reset();

        if (not this->decryptionAllocateMemory(in))
        {
            return this->abort();
        }

        Size cipherlen;
        ConstBytes ciphertext = this->readEncryptedData(in, cipherlen);

        if (EVP_DecryptInit_ex(this->getCipherContext(), EVP_aes_256_gcm(), NULL, this->getKeyData(), this->getIV()) != 1)
        {
            return this->abort();
        }

        int len;

        if (EVP_DecryptUpdate(this->getCipherContext(), this->getOutBuffer(), &len, ciphertext, cipherlen) != 1)
        {
            return this->abort();
        }

        if (EVP_CIPHER_CTX_ctrl(this->getCipherContext(), EVP_CTRL_GCM_SET_TAG, TAG_SIZE, this->getTag()) != 1)
        {
            return this->abort();
        }

        int len2;

        if (EVP_DecryptFinal_ex(this->getCipherContext(), this->getOutBuffer() + len, &len2) != 1)
        {
            return this->abort();
        }

        this->setOutBufferSize(len + len2);

        EncrypterResult *result = new EncrypterResult(this->getOutBuffer(), this->getOutBufferSize());

        this->reset();

        return result;
    }

    static Cipher *create(Key *key) { return new SymmetricCipher(key); }
};

#endif