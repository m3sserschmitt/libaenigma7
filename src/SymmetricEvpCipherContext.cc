#include "cryptography/SymmetricEvpCipherContext.hh"

EncrypterResult *SymmetricEvpCipherContext::createEncryptedData() const
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

ConstBytes SymmetricEvpCipherContext::readEncryptedData(const EncrypterData *in, Size &cipherlen)
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

EncrypterResult *SymmetricEvpCipherContext::encrypt(const EncrypterData *in)
{
    if (not in or not in->getData())
    {
        return this->abort();
    }

    this->cleanup();

    if (not this->encryptionAllocateMemory(in) or not this->generateIV())
    {
        return this->abort();
    }

    if (EVP_EncryptInit_ex(this->getCipherContext(), EVP_aes_256_gcm(), NULL, this->getKeyBytes(), this->getIV()) != 1)
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

    if (not this->decryptionAllocateMemory(in))
    {
        return this->abort();
    }

    Size cipherlen;
    ConstBytes ciphertext = this->readEncryptedData(in, cipherlen);

    if (EVP_DecryptInit_ex(this->getCipherContext(), EVP_aes_256_gcm(), NULL, this->getKeyBytes(), this->getIV()) != 1)
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

    this->cleanup();

    return result;
}
