#include <iostream>

#include "../include/cryptography/CryptoContext.hh"
#include "../include/cryptography/AsymmetricKey.hh"

using namespace std;

bool testSymmetricCrypto()
{
    const Byte *key = RandomDataGenerator::generate(SYMMETRIC_KEY_SIZE)->getData();
    const Byte *data = RandomDataGenerator::generate(128)->getData();

    CryptoContext *cryptoContext = new CryptoContext(SymmetricCryptography, Encrypt);

    cryptoContext->setKey(key, SYMMETRIC_KEY_SIZE);
    cryptoContext->setPlaintext(data, 128);
    cryptoContext->run();

    const EncrypterData *ciphertext = cryptoContext->getCiphertext();

    if (ciphertext->isError())
    {
        return false;
    }

    Size datalen = ciphertext->getDataSize();
    Bytes encrdata = new Byte[datalen + 1];
    memcpy(encrdata, ciphertext->getData(), datalen);

    cryptoContext->setup(SymmetricCryptography, Decrypt);
    cryptoContext->setKey(key, SYMMETRIC_KEY_SIZE);
    cryptoContext->setCiphertext(encrdata, datalen);

    cryptoContext->run();

    const EncrypterData *plaintext = cryptoContext->getPlaintext();

    if (plaintext->isError())
    {
        return false;
    }

    return memcmp(data, plaintext->getData(), 128) == 0;
}

bool testAsymmetricCrypto()
{
    const Byte *data = RandomDataGenerator::generate(128)->getData();

    CryptoContext *cryptoContext = new CryptoContext(AsymmetricCryptography, Encrypt);

    cryptoContext->readKey("public.pem");
    cryptoContext->setPlaintext(data, 128);
    cryptoContext->run();

    const EncrypterData *ciphertext = cryptoContext->getCiphertext();

    if (ciphertext->isError())
    {
        return false;
    }

    Size datalen = ciphertext->getDataSize();
    Bytes encrdata = new Byte[datalen + 1];
    memcpy(encrdata, ciphertext->getData(), datalen);

    cryptoContext->setup(AsymmetricCryptography, Decrypt);
    cryptoContext->readKey("private.pem", "test");
    cryptoContext->setCiphertext(encrdata, datalen);

    cryptoContext->run();

    const EncrypterData *plaintext = cryptoContext->getPlaintext();

    if (plaintext->isError())
    {
        return false;
    }

    return memcmp(data, plaintext->getData(), 128) == 0;
}

int main()
{
    bool success = testSymmetricCrypto();
    success and cout << "Symmetric crypto test successful!\n";

    success = testAsymmetricCrypto();
    success and cout << "Asymmetric crypto test successful!\n";

    return EXIT_SUCCESS;
}