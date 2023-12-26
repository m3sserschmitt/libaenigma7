#ifndef LIB_CRYPTOGRAPHY_HH
#define LIB_CRYPTOGRAPHY_HH

#include "CryptoContext.hh"
#include "CryptoContextBuilder.hh"

extern "C" CryptoContext *CreateSymmetricEncryptionContext(const unsigned char *key);

extern "C" CryptoContext *CreateSymmetricDecryptionContext(const unsigned char *key);

extern "C" CryptoContext *CreateAsymmetricEncryptionContext(const char *key);

extern "C" CryptoContext *CreateAsymmetricDecryptionContext(const char *key, char *passphrase = nullptr);

extern "C" CryptoContext *CreateAsymmetricEncryptionContextFromFile(const char *path);

extern "C" CryptoContext *CreateAsymmetricDecryptionContextFromFile(const char *key, char *passphrase = nullptr);

extern "C" CryptoContext *CreateSignatureContext(const char *key, char *passphrase = nullptr);

extern "C" CryptoContext *CreateVerificationContext(const char *key);

extern "C" CryptoContext *CreateSignatureContextFromFile(const char *path, char *passphrase = nullptr);

extern "C" CryptoContext *CreateVerificationContextFromFile(const char *path);

extern "C" void FreeContext(CryptoContext *context);

extern "C" const unsigned char *EncryptData(CryptoContext *ctx, const unsigned char *plaintext, unsigned int plaintextLen, int &cipherLen);

extern "C" const EncrypterResult *EncryptDataEx(CryptoContext *ctx, const unsigned char *plaintext, unsigned int plaintextLen);

extern "C" const unsigned char *DecryptData(CryptoContext *ctx, const unsigned char *ciphertext, unsigned int cipherLen, int &plaintextLen);

extern "C" const EncrypterResult *DecryptDataEx(CryptoContext *ctx, const unsigned char *ciphertext, unsigned int cipherLen);

extern "C" const unsigned char *SignData(CryptoContext *ctx, const unsigned char *plaintext, unsigned int plaintextLen, int &signatureLen);

extern "C" const EncrypterResult *SignDataEx(CryptoContext *ctx, const unsigned char *plaintext, unsigned int plaintextLen);

extern "C" bool VerifySignature(CryptoContext *ctx, const unsigned char *ciphertext, unsigned int cipherLen);

extern "C" unsigned int GetAesGcmCiphertextSize(unsigned int plaintext);

extern "C" unsigned int GetAesGcmPlaintextSize(unsigned int ciphertext);

extern "C" unsigned int GetEnvelopeSize(unsigned int pkeySizeBits, unsigned int plaintextLen);

extern "C" unsigned int GetOpenEnvelopeSize(unsigned int pkeySizeBits, unsigned int envelopeSize);

extern "C" unsigned int GetSignedDataSize(unsigned int pkeySizeBits, unsigned int dataSize);

#endif
