#ifndef LIB_AENIGMA_HH
#define LIB_AENIGMA_HH

#include "cryptography/CryptoContext.hh"
#include "cryptography/KernelKeys.hh"

extern "C"
{
#ifndef __ANDROID__
    bool SetMasterPassphraseName(const char *name);

    int CreateMasterPassphrase(const char *passphrase);

    bool RemoveMasterPassphrase();
#endif
    CryptoContext *CreateSymmetricEncryptionContext(const unsigned char *key);

    CryptoContext *CreateSymmetricDecryptionContext(const unsigned char *key);

    CryptoContext *CreateAsymmetricEncryptionContext(const char *key);

    CryptoContext *CreateAsymmetricDecryptionContext(const char *key, const char *passphrase = nullptr);

    CryptoContext *CreateAsymmetricEncryptionContextFromFile(const char *path);

    CryptoContext *CreateAsymmetricDecryptionContextFromFile(const char *key, const char *passphrase = nullptr);

    CryptoContext *CreateSignatureContext(const char *key, const char *passphrase = nullptr);

    CryptoContext *CreateVerificationContext(const char *key);

    CryptoContext *CreateSignatureContextFromFile(const char *path, const char *passphrase = nullptr);

    CryptoContext *CreateVerificationContextFromFile(const char *path);

    void FreeContext(CryptoContext *context);

    const unsigned char *Run(CryptoContext *ctx, const unsigned char *in, unsigned int inLen, int &outLen);

    const EncrypterResult *RunEx(CryptoContext *ctx, const unsigned char *in, unsigned int inLen);

    const unsigned char *SealOnion(const unsigned char *plaintext, unsigned int plaintextLen, const char **keys, const char **addresses, unsigned int count, int &outLen);

    unsigned int DecodeOnionSize(const unsigned char *onion);

    const unsigned char *UnsealOnion(CryptoContext *ctx, const unsigned char *onion, int &plaintextLen);

    bool RunVerification(CryptoContext *ctx, const unsigned char *in, unsigned int outLen);

    unsigned int GetAesGcmCiphertextSize(unsigned int plaintext);

    int GetAesGcmPlaintextSize(unsigned int ciphertext);

    int GetEnvelopeSize(unsigned int plaintextLen, const char *publicKey);

    int GetOpenEnvelopeSize(unsigned int envelopeSize, const char *publicKey);

    int GetSignedDataSize(unsigned int dataSize, const char *publicKey);

    int GetPKeySize(const char *publicKey);

    int GetAddressSize();
}
#endif
