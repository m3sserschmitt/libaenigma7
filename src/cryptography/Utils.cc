#include "cryptography/Constants.hh"
#include "cryptography/AsymmetricKey.hh"

extern "C"
{
    unsigned int GetAesGcmCiphertextSize(unsigned int plaintext)
    {
        return plaintext + IV_SIZE + TAG_SIZE;
    }

    unsigned int GetAesGcmPlaintextSize(unsigned int ciphertext)
    {
        return ciphertext - TAG_SIZE - IV_SIZE;
    }

    unsigned int GetPKeySize(const char *publicKey)
    {
        AsymmetricKey *key = AsymmetricKey::Factory::createPublicKeyFromPem(publicKey, strlen(publicKey), nullptr);

        if(not key)
        {
            return -1;
        }

        int keySize = key->getSize();
        delete key;

        return keySize;
    }

    unsigned int GetEnvelopeSize(unsigned int plaintextLen, const char *publicKey)
    {
        return GetPKeySize(publicKey) + IV_SIZE + TAG_SIZE + plaintextLen;
    }

    unsigned int GetOpenEnvelopeSize(unsigned int envelopeSize, const char *publicKey)
    {
        return envelopeSize - GetPKeySize(publicKey) - IV_SIZE - TAG_SIZE;
    }

    unsigned int GetSignedDataSize(unsigned int dataSize, const char *publicKey)
    {
        return GetPKeySize(publicKey) + dataSize;
    }
}
