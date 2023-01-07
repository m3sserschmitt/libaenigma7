#include "cryptography/EvpMdContext.hh"

EncrypterResult *EvpMdContext::createSignedData(const EncrypterData *in) const
{
    Size signedDataSize = in->getDataSize() + this->getOutBufferSize();
    Bytes signedData = new Byte[signedDataSize + 1];

    memcpy(signedData, in->getData(), in->getDataSize());
    memcpy(signedData + in->getDataSize(), this->getOutBuffer(), this->getOutBufferSize());

    return new EncrypterResult(signedData, signedDataSize);
}

ConstBytes EvpMdContext::readSignedData(const EncrypterData *in, Size &datasize)
{
    datasize = 0;

    if (not in or not in->getData())
    {
        return nullptr;
    }

    Size pkeySize = this->getPkeySize();
    
    if(not this->writeInSig(in->getData() + in->getDataSize() - pkeySize, pkeySize))
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

    if (EVP_DigestSignInit(this->getMdContext(), nullptr, EVP_sha256(), nullptr, this->getPkey()) != 1)
    {
        return this->abort();
    }

    if (EVP_DigestSignUpdate(this->getMdContext(), in->getData(), in->getDataSize()) != 1)
    {
        return this->abort();
    }

    size_t siglen;

    if (EVP_DigestSignFinal(this->getMdContext(), nullptr, &siglen) != 1)
    {
        return this->abort();
    }

    if (not this->allocateOutBuffer(siglen))
    {
        return this->abort();
    }

    if (EVP_DigestSignFinal(this->getMdContext(), this->getOutBuffer(), &siglen) != 1)
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

    if (not this->allocateMdContext() or not this->allocateInSig(this->getPkeySize()))
    {
        return this->abort();
    }

    if (EVP_DigestVerifyInit(this->getMdContext(), nullptr, EVP_sha256(), nullptr, this->getPkey()) != 1)
    {
        return this->abort();
    }

    Size datalen;
    ConstBytes data = this->readSignedData(in, datalen);

    if(not data or not datalen)
    {
        return this->abort();
    }

    if (EVP_DigestVerifyUpdate(this->getMdContext(), data, datalen) != 1)
    {
        return this->abort();
    }

    if (EVP_DigestVerifyFinal(this->getMdContext(), this->getInSig(), this->getInSiglen()) == 1)
    {
        return new EncrypterResult(true);
    }

    return new EncrypterResult(false);
}
