#include "cryptography/EvpMdContext.hh"

#include <openssl/evp.h>

EncrypterResult *EvpMdContext::createSignedData(const EncrypterData *in) const
{
    unsigned int signedDataSize = in->getDataSize() + this->getOutBufferSize();
    unsigned char *signedData = new unsigned char[signedDataSize + 1];

    memcpy(signedData, in->getData(), in->getDataSize());
    memcpy(signedData + in->getDataSize(), this->getOutBuffer(), this->getOutBufferSize());

    EncrypterResult *result = new EncrypterResult(signedData, signedDataSize);

    delete[] signedData;

    return result;
}

const unsigned char *EvpMdContext::readSignedData(const EncrypterData *in, int &datasize)
{
    datasize = -1;

    if (not in or not in->getData())
    {
        return nullptr;
    }

    unsigned int pkeySize = this->getKeySize();

    if (not this->writeInSig(in->getData() + in->getDataSize() - pkeySize, pkeySize))
    {
        return nullptr;
    }

    datasize = in->getDataSize() - pkeySize;

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

    size_t siglen;

    if (EVP_DigestSignFinal((EVP_MD_CTX *)this->mdContext, nullptr, &siglen) != 1)
    {
        return this->abort();
    }

    if (not this->allocateOutBuffer(siglen))
    {
        return this->abort();
    }

    if (EVP_DigestSignFinal((EVP_MD_CTX *)this->mdContext, this->getOutBuffer(), &siglen) != 1)
    {
        return this->abort();
    }

    this->setOutBufferSize(siglen);

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

    if (not this->allocateMdContext() or not this->allocateInSig(this->getKeySize()))
    {
        return this->abort();
    }

    if (EVP_DigestVerifyInit((EVP_MD_CTX *)this->mdContext, nullptr, EVP_sha256(), nullptr, (EVP_PKEY *)this->getKey()->getKeyData()) != 1)
    {
        return this->abort();
    }

    int datalen;
    const unsigned char *data = this->readSignedData(in, datalen);

    if (not data or datalen < 0)
    {
        return this->abort();
    }

    if (EVP_DigestVerifyUpdate((EVP_MD_CTX *)this->mdContext, data, datalen) != 1)
    {
        return this->abort();
    }

    if (EVP_DigestVerifyFinal((EVP_MD_CTX *)this->mdContext, this->inSig, this->inSiglen) == 1)
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
