#include "contracts/ICryptoContext.hh"

extern "C" ICryptoContext *CreateSymmetricEncryptionContext(const unsigned char *key);

extern "C" ICryptoContext *CreateSymmetricDecryptionContext(const unsigned char *key);


extern "C" ICryptoContext *CreateAsymmetricEncryptionContext(const char *key);

extern "C" ICryptoContext *CreateAsymmetricDecryptionContext(const char *key, char *passphrase = nullptr);


extern "C" ICryptoContext *CreateAsymmetricEncryptionContextFromFile(const char *path);

extern "C" ICryptoContext *CreateAsymmetricDecryptionContextFromFile(const char *key, char *passphrase = nullptr);


extern "C" const unsigned char *AesGcmEncrypt(ICryptoContext *ctx, const unsigned char *plaintext, unsigned int plaintextLen);

extern "C" const unsigned char *AesGcmDecrypt(ICryptoContext *ctx, const unsigned char *ciphertext, unsigned int cipherLen);


extern "C" const unsigned char *RsaEncrypt(ICryptoContext *ctx, const unsigned char *plaintext, unsigned int plaintextLen);

extern "C" const unsigned char *RsaDecrypt(ICryptoContext *ctx, const unsigned char *ciphertext, unsigned int cipherLen);


extern "C" unsigned int GetAesGcmCiphertextSize(unsigned int plaintext);

extern "C" unsigned int GetAesGcmPlaintextSize(unsigned int ciphertext);

extern "C" unsigned int GetRsaSize(unsigned int keySizeBits);
