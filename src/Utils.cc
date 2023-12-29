#include "cryptography/Constants.hh"

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

    unsigned int GetEnvelopeSize(unsigned int pkeySizeBits, unsigned int plaintextLen)
    {
        return pkeySizeBits / 8 + IV_SIZE + TAG_SIZE + plaintextLen;
    }

    unsigned int GetOpenEnvelopeSize(unsigned int pkeySizeBits, unsigned int envelopeSize)
    {
        return envelopeSize - pkeySizeBits / 8 - IV_SIZE - TAG_SIZE;
    }

    unsigned int GetSignedDataSize(unsigned int pkeySizeBits, unsigned int dataSize)
    {
        return pkeySizeBits / 8 + dataSize;
    }

    unsigned int GetDefaultAddressSize()
    {
        return ADDRESS_SIZE;
    }

    unsigned int GetDefaultPKeySize()
    {
        return PKEY_SIZE;
    }
}
