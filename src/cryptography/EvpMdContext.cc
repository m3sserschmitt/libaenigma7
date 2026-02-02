#include "cryptography/EvpMdContext.hh"

#include <openssl/evp.h>

EncrypterResult *EvpMdContext::createSignedData(const EncrypterData *in) const
{
    unsigned int signedDataSize = in->getDataSize() + this->getOutBufferSize();
    auto *signedData = new unsigned char[signedDataSize + 1];

    memcpy(signedData, in->getData(), in->getDataSize());
    memcpy(signedData + in->getDataSize(), this->getOutBuffer(), this->getOutBufferSize());

    auto *result = new EncrypterResult(signedData, signedDataSize);

    delete[] signedData;

    return result;
}

const unsigned char *EvpMdContext::readSignedData(const EncrypterData *in, int &dataSize)
{
    dataSize = -1;

    if (in == nullptr or not in->getData())
    {
        return nullptr;
    }

    unsigned int pKeySize = this->getKeySize();

    if (not this->writeInSig(in->getData() + in->getDataSize() - pKeySize, pKeySize))
    {
        return nullptr;
    }

    dataSize = (int)in->getDataSize() - (int)pKeySize;

    return in->getData();
}

EncrypterResult *EvpMdContext::encrypt(const EncrypterData *in)
{
    if (not in or not in->getData())
    {
        return this->abort();
    }

    this->cleanup();

    if (not this->allocateMdContext())
    {
        return this->abort();
    }

    if (EVP_DigestSignInit((EVP_MD_CTX *)this->mdContext, nullptr, EVP_sha256(), nullptr, (EVP_PKEY *)this->getKey()->getKeyData()) != 1)
    {
        return this->abort();
    }

    if (EVP_DigestSignUpdate((EVP_MD_CTX *)this->mdContext, in->getData(), in->getDataSize()) != 1)
    {
        return this->abort();
    }

    size_t sigLen;

    if (EVP_DigestSignFinal((EVP_MD_CTX *)this->mdContext, nullptr, &sigLen) != 1)
    {
        return this->abort();
    }

    this->allocateOutBuffer(sigLen);

    if (EVP_DigestSignFinal((EVP_MD_CTX *)this->mdContext, this->getOutBuffer(), &sigLen) != 1)
    {
        return this->abort();
    }

    this->setOutBufferSize((int)sigLen);

    EncrypterResult *result = this->createSignedData(in);

    this->cleanup();

    return result;
}

EncrypterResult *EvpMdContext::decrypt(const EncrypterData *in)
{
    if (not in or not in->getData())
    {
        return this->abort();
    }

    this->cleanup();

    this->allocateMdContext();
    this->allocateInSig(this->getKeySize());

    if (EVP_DigestVerifyInit((EVP_MD_CTX *)this->mdContext, nullptr, EVP_sha256(), nullptr, (EVP_PKEY *)this->getKey()->getKeyData()) != 1)
    {
        return this->abort();
    }

    int dataLen;
    const unsigned char *data = this->readSignedData(in, dataLen);

    if (dataLen < 0)
    {
        return this->abort();
    }

    if (EVP_DigestVerifyUpdate((EVP_MD_CTX *)this->mdContext, data, dataLen) != 1)
    {
        return this->abort();
    }

    if (EVP_DigestVerifyFinal((EVP_MD_CTX *)this->mdContext, this->inSig, this->inSigLen) == 1)
    {
        return new EncrypterResult(true);
    }

    return new EncrypterResult(false);
}

void EvpMdContext::freeMdContext()
{
    EVP_MD_CTX_free((EVP_MD_CTX *)this->mdContext);
    this->mdContext = nullptr;
}

bool EvpMdContext::allocateMdContext()
{
    this->freeMdContext();
    this->mdContext = EVP_MD_CTX_new();

    return this->mdContext != nullptr;
}
