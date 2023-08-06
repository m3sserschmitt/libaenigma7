#include "contracts/ICryptoContext.hh"

extern "C" ICryptoContext *CreateSymmetricEncryptionContext(const unsigned char *key);

extern "C" ICryptoContext *CreateSymmetricDecryptionContext(const unsigned char *key);

extern "C" ICryptoContext *CreateAsymmetricEncryptionContext(const char *key);

extern "C" ICryptoContext *CreateAsymmetricDecryptionContext(const char *key, char *passphrase = nullptr);

extern "C" ICryptoContext *CreateAsymmetricEncryptionContextFromFile(const char *path);

extern "C" ICryptoContext *CreateAsymmetricDecryptionContextFromFile(const char *key, char *passphrase = nullptr);

extern "C" ICryptoContext *CreateSignatureContext(const char *key, char *passphrase = nullptr);

extern "C" ICryptoContext *CreateVerificationContext(const char *key);

extern "C" ICryptoContext *CreateSignatureContextFromFile(const char *path, char *passphrase = nullptr);

extern "C" ICryptoContext *CreateVerificationContextFromFile(const char *path);

extern "C" void FreeContext(ICryptoContext *context);

extern "C" const unsigned char *EncryptData(ICryptoContext *ctx, const unsigned char *plaintext, unsigned int plaintextLen);

extern "C" const unsigned char *DecryptData(ICryptoContext *ctx, const unsigned char *ciphertext, unsigned int cipherLen);

extern "C" const unsigned char *SignData(ICryptoContext *ctx, const unsigned char *plaintext, unsigned int plaintextLen);

extern "C" bool VerifySignature(ICryptoContext *ctx, const unsigned char *ciphertext, unsigned int cipherLen);

extern "C" unsigned int GetAesGcmCiphertextSize(unsigned int plaintext);

extern "C" unsigned int GetAesGcmPlaintextSize(unsigned int ciphertext);

extern "C" unsigned int GetEnvelopeSize(unsigned int pkeySizeBits, unsigned int plaintextLen);

extern "C" unsigned int GetOpenEnvelopeSize(unsigned int pkeySizeBits, unsigned int envelopeSize);
