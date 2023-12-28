#ifndef FACTORIES_HH
#define FACTORIES_HH

#include "CryptoContext.hh"

extern "C" CryptoContext *CreateSymmetricEncryptionContext(const unsigned char *key);

extern "C" CryptoContext *CreateSymmetricDecryptionContext(const unsigned char *key);

extern "C" CryptoContext *CreateAsymmetricEncryptionContext(const char *key);

extern "C" CryptoContext *CreateAsymmetricDecryptionContext(const char *key, const char *passphrase = nullptr);

extern "C" CryptoContext *CreateAsymmetricEncryptionContextFromFile(const char *path);

extern "C" CryptoContext *CreateAsymmetricDecryptionContextFromFile(const char *key, const char *passphrase = nullptr);

extern "C" CryptoContext *CreateSignatureContext(const char *key, const char *passphrase = nullptr);

extern "C" CryptoContext *CreateVerificationContext(const char *key);

extern "C" CryptoContext *CreateSignatureContextFromFile(const char *path, const char *passphrase = nullptr);

extern "C" CryptoContext *CreateVerificationContextFromFile(const char *path);

extern "C" void FreeContext(CryptoContext *context);

#endif
