#ifndef UTILS_HH
#define UTILS_HH

extern "C"
{
    unsigned int GetAesGcmCiphertextSize(unsigned int plaintext);

    unsigned int GetAesGcmPlaintextSize(unsigned int ciphertext);

    unsigned int GetEnvelopeSize(unsigned int pkeySizeBits, unsigned int plaintextLen);

    unsigned int GetOpenEnvelopeSize(unsigned int pkeySizeBits, unsigned int envelopeSize);

    unsigned int GetSignedDataSize(unsigned int pkeySizeBits, unsigned int dataSize);

    unsigned int GetDefaultAddressSize();

    unsigned int GetDefaultPKeySize();
}

#endif
