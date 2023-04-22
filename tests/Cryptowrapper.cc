#include "cryptography/Libcryptography.hh"
#include "cryptography/RandomDataGenerator.hh"

#include <cstring>
#include <iostream>

#define DATA_SIZE 128

using namespace std;

bool testSymmetricCryptoWrapper()
{
    unsigned char *key = RandomDataGenerator::generateKey();
    unsigned char *data = RandomDataGenerator::generate(DATA_SIZE);

    ICryptoContext *encrctx = CreateSymmetricEncryptionContext(key);

    const unsigned char *ciphertext = AesGcmEncrypt(encrctx, data, DATA_SIZE);

    if (not ciphertext)
    {
        return false;
    }

    unsigned int cipherlen = GetAesGcmCiphertextSize(DATA_SIZE);
    ICryptoContext *decrctx = CreateSymmetricDecryptionContext(key);

    const unsigned char *plaintext = AesGcmDecrypt(decrctx, ciphertext, cipherlen);

    if (not plaintext)
    {
        return false;
    }

    return memcmp(data, plaintext, DATA_SIZE) == 0;
}

bool testAsymmetricCryptoWrapper()
{
    unsigned char *data = RandomDataGenerator::generate(DATA_SIZE);

    ICryptoContext *encrctx = CreateAsymmetricEncryptionContextFromFile("./public.pem");

    int cipherlen = GetRsaSize(2048);
    unsigned char *ciphertext = new unsigned char[cipherlen];
    const unsigned char *result = RsaEncrypt(encrctx, data, DATA_SIZE);

    if (not result)
    {
        return false;
    }

    memcpy(ciphertext, result, cipherlen);
    ICryptoContext *decrctx = CreateAsymmetricDecryptionContext("./private.pem");

    const unsigned char *plaintext = RsaDecrypt(decrctx, ciphertext, cipherlen);

    if (not plaintext)
    {
        return false;
    }

    return memcmp(data, plaintext, DATA_SIZE) == 0;
}

int main()
{
    bool success = testSymmetricCryptoWrapper();
    (success and cout << "Symmetric crypto wrapper test successful!\n") or cout << "Symmetric crypto wrapper test failed\n";

    success = testAsymmetricCryptoWrapper();
    (success and cout << "Asymmetric crypto wrapper test successful!\n") or cout << "Asymmetric crypto wrapper test failed\n";

    return EXIT_SUCCESS;
}
