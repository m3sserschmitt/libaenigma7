#include "cryptography/Constants.hh"
#include "cryptography/AsymmetricKey.hh"

#include <cstring>

extern "C"
{
    int GetAesGcmCiphertextSize(unsigned int plaintext)
    {
        return plaintext + IV_SIZE + TAG_SIZE;
    }

    int GetAesGcmPlaintextSize(unsigned int ciphertext)
    {
        return ciphertext - TAG_SIZE - IV_SIZE;
    }

    int GetPKeySize(const char *publicKey)
    {
        if(!publicKey)
        {
            return -1;
        }
        
        AsymmetricKey *key = AsymmetricKey::Factory::createPublicKeyFromPem(publicKey, strlen(publicKey), nullptr);

        if(not key)
        {
            return -1;
        }

        int keySize = key->getSize();
        delete key;

        return keySize;
    }

    int GetEnvelopeSize(unsigned int plaintextLen, const char *publicKey)
    {
        int pKeySize = GetPKeySize(publicKey);
        return pKeySize < 0 ? -1 : pKeySize + IV_SIZE + TAG_SIZE + plaintextLen;
    }

    int GetOpenEnvelopeSize(unsigned int envelopeSize, const char *publicKey)
    {
        int pKeySize = GetPKeySize(publicKey);
        return pKeySize < 0 ? -1 : envelopeSize - pKeySize - IV_SIZE - TAG_SIZE;
    }

    int GetSignedDataSize(unsigned int dataSize, const char *publicKey)
    {
        int pKeySize = GetPKeySize(publicKey);
        return pKeySize < 0 ? -1 : pKeySize + dataSize;
    }
}
