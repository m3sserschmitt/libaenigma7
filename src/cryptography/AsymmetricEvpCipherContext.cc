#include "cryptography/AsymmetricEvpCipherContext.hh"

#include <openssl/evp.h>

EncrypterResult *AsymmetricEvpCipherContext::createEnvelope() const
{
    unsigned int envelopeSize = this->calculateEnvelopeSize();
    unsigned char * envelope = new unsigned char[envelopeSize + 1];

    unsigned int N = this->encryptedKeyLength;
    unsigned int P = this->getOutBufferSize();

    memcpy(envelope, this->encryptedKey, N);
    memcpy(envelope + N, this->getIV(), IV_SIZE);
    memcpy(envelope + N + IV_SIZE, this->getOutBuffer(), P);
    memcpy(envelope + N + IV_SIZE + P, this->getTag(), TAG_SIZE);

    EncrypterResult *result = new EncrypterResult(envelope, envelopeSize);

    memset(envelope, 0, envelopeSize);
    delete[] envelope;

    return result;
}

const unsigned char * AsymmetricEvpCipherContext::readEnvelope(const EncrypterData *in, int &cipherlen)
{
    cipherlen = -1;

    if (not in or not in->getData())
    {
        return nullptr;
    }

    unsigned int N = this->getKeySize();
    unsigned int envelopeSize = in->getDataSize();
    const unsigned char * envelope = in->getData();

    if (not this->writeEncryptedKey(envelope) or not this->writeIV(envelope + N) or not this->writeTag(envelope + envelopeSize - TAG_SIZE))
    {
        return nullptr;
    }

    cipherlen = envelopeSize - N - IV_SIZE - TAG_SIZE;
    return envelope + N + IV_SIZE;
}

EncrypterResult *AsymmetricEvpCipherContext::decrypt(const EncrypterData *in)
{
    if (not in or not in->getData())
    {
        return this->abort();
    }

    this->cleanup();

    if (not this->openEnvelopeAllocateMemory(in))
    {
        return this->abort();
    }

    int cipherlen;
    const unsigned char * ciphertext = this->readEnvelope(in, cipherlen);

    if (not ciphertext or cipherlen < 0)
    {
        return this->abort();
    }

    if (EVP_OpenInit((EVP_CIPHER_CTX *)this->getCipherContext(),
                     EVP_aes_256_gcm(),
                     this->encryptedKey,
                     this->encryptedKeyLength,
                     this->getIV(),
                     (EVP_PKEY *)this->getKey()->getKeyData()) != 1)
    {
        return this->abort();
    }

    int len;

    if (EVP_OpenUpdate((EVP_CIPHER_CTX *)this->getCipherContext(),
                       this->getOutBuffer(),
                       &len, ciphertext, cipherlen) != 1)
    {
        return this->abort();
    }

    if (EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX *)this->getCipherContext(), EVP_CTRL_GCM_SET_TAG, TAG_SIZE, this->getTag()) != 1)
    {
        return this->abort();
    }

    int len2;

    if (EVP_OpenFinal((EVP_CIPHER_CTX *)this->getCipherContext(), this->getOutBuffer() + len, &len2) != 1)
    {
        return this->abort();
    }

    this->setOutBufferSize(len + len2);

    EncrypterResult *result = new EncrypterResult(this->getOutBuffer(), this->getOutBufferSize());

    this->cleanup();

    return result;
}

EncrypterResult *AsymmetricEvpCipherContext::encrypt(const EncrypterData *in)
{
    if (not in or not in->getData())
    {
        return this->abort();
    }

    this->cleanup();

    if (not this->sealEnvelopeAllocateMemory(in))
    {
        return this->abort();
    }

    EVP_PKEY *pkey = (EVP_PKEY *)this->getKey()->getKeyData();

    if (EVP_SealInit((EVP_CIPHER_CTX *)this->getCipherContext(),
                     EVP_aes_256_gcm(),
                     &this->encryptedKey,
                     &this->encryptedKeyLength,
                     this->getIV(),
                     &pkey, 1) != 1)
    {
        return this->abort();
    }

    int len;
    int len2;

    if (EVP_SealUpdate((EVP_CIPHER_CTX *)this->getCipherContext(), this->getOutBuffer(), &len, in->getData(), in->getDataSize()) != 1)
    {
        return this->abort();
    }

    if (EVP_SealFinal((EVP_CIPHER_CTX *)this->getCipherContext(), this->getOutBuffer() + len, &len2) != 1)
    {
        return this->abort();
    }

    if (EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX *)this->getCipherContext(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, this->getTag()) != 1)
    {
        return this->abort();
    }

    this->setOutBufferSize(len + len2);

    EncrypterResult *result = this->createEnvelope();

    this->cleanup();

    return result;
}
