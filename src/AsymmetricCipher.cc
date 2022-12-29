#include "cryptography/AsymmetricCipher.hh"

EncrypterResult *AsymmetricCipher::createEnvelope() const
{
    Size envelopeSize = this->calculateEnvelopeSize();
    Bytes envelope = new Byte[envelopeSize + 1];

    Size N = this->getEncryptedKeyLength();
    Size P = this->getOutBufferSize();

    memcpy(envelope, this->getEncryptedKey(), N);
    memcpy(envelope + N, this->getIV(), IV_SIZE);
    memcpy(envelope + N + IV_SIZE, this->getOutBuffer(), P);
    memcpy(envelope + N + IV_SIZE + P, this->getTag(), TAG_SIZE);

    EncrypterResult *result = new EncrypterResult(envelope, envelopeSize);

    memset(envelope, 0, envelopeSize);
    delete[] envelope;

    return result;
}

ConstBytes AsymmetricCipher::readEnvelope(const EncrypterData *in, Size &cipherlen)
{
    cipherlen = 0;

    if (not in or not in->getData())
    {
        return nullptr;
    }

    Size N = this->getPkeySize();
    Size envelopeSize = in->getDataSize();
    ConstBytes envelope = in->getData();

    if (not this->writeEncryptedKey(envelope) or not this->writeIV(envelope + N) or not this->writeTag(envelope + envelopeSize - TAG_SIZE))
    {
        return nullptr;
    }

    cipherlen = envelopeSize - N - IV_SIZE - TAG_SIZE;
    return envelope + N + IV_SIZE;
}

EncrypterResult *AsymmetricCipher::decrypt(const EncrypterData *in)
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

    Size cipherlen;
    ConstBytes ciphertext = this->readEnvelope(in, cipherlen);

    if (not ciphertext or not cipherlen)
    {
        return this->abort();
    }

    if (EVP_OpenInit(this->getCipherContext(),
                     EVP_aes_256_gcm(),
                     this->getEncryptedKey(),
                     this->getEncryptedKeyLength(),
                     this->getIV(),
                     this->getPkey()) != 1)
    {
        return this->abort();
    }

    int len;

    if (EVP_OpenUpdate(this->getCipherContext(),
                       this->getOutBuffer(),
                       &len, ciphertext, cipherlen) != 1)
    {
        return this->abort();
    }

    if (EVP_CIPHER_CTX_ctrl(this->getCipherContext(), EVP_CTRL_GCM_SET_TAG, TAG_SIZE, this->getTag()) != 1)
    {
        return this->abort();
    }

    int len2;

    if (EVP_OpenFinal(this->getCipherContext(), this->getOutBuffer() + len, &len2) != 1)
    {
        return this->abort();
    }

    this->setOutBufferSize(len + len2);

    EncrypterResult *result = new EncrypterResult(this->getOutBuffer(), this->getOutBufferSize());

    this->cleanup();

    return result;
}

EncrypterResult *AsymmetricCipher::encrypt(const EncrypterData *in)
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

    EVP_PKEY *pkey = this->getPkey();

    if (EVP_SealInit(this->getCipherContext(),
                     EVP_aes_256_gcm(),
                     this->getEncryptedKeyPtr(),
                     this->getEncryptedKeyLengthPtr(),
                     this->getIV(),
                     &pkey, 1) != 1)
    {
        return this->abort();
    }

    int len;
    int len2;

    if (EVP_SealUpdate(this->getCipherContext(), this->getOutBuffer(), &len, in->getData(), in->getDataSize()) != 1)
    {
        return this->abort();
    }

    if (EVP_SealFinal(this->getCipherContext(), this->getOutBuffer() + len, &len2) != 1)
    {
        return this->abort();
    }

    if (EVP_CIPHER_CTX_ctrl(this->getCipherContext(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, this->getTag()) != 1)
    {
        return this->abort();
    }

    this->setOutBufferSize(len + len2);

    EncrypterResult *result = this->createEnvelope();

    this->cleanup();

    return result;
}