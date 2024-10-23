#ifndef UTILS_HH
#define UTILS_HH

extern "C"
{
    unsigned int GetAesGcmCiphertextSize(unsigned int plaintext);

    unsigned int GetAesGcmPlaintextSize(unsigned int ciphertext);

    unsigned int GetEnvelopeSize(unsigned int plaintextLen, const char *publicKey);

    unsigned int GetOpenEnvelopeSize(unsigned int envelopeSize, const char *publicKey);

    unsigned int GetSignedDataSize(unsigned int dataSize, const char *publicKey);

    unsigned int GetPKeySize(const char *publicKey);
}

#endif
