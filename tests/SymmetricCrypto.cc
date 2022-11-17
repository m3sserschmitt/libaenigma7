#include <iostream>

#include "../include/cryptography/EncryptionMachine.hh"
#include "../include/cryptography/DecryptionMachine.hh"
#include "../include/cryptography/SymmetricKey.hh"

using namespace std;

int main()
{
    const Byte *keyData = (const Byte *)"encryption key for testing 1234";

    SymmetricKey symmetricKey;
    EncryptionMachine encryptionMachine;
    DecryptionMachine decryptionMachine;

    symmetricKey.setKeyData(keyData);

    encryptionMachine.setData((const Byte *)"test", 4);
    encryptionMachine.setKey(&symmetricKey);

    

    encryptionMachine.run();

    const EncrypterData *encrypterData = encryptionMachine.getResult();

    decryptionMachine.setData(encrypterData->getData(), encrypterData->getDataSize());
    decryptionMachine.setKey(&symmetricKey);

    decryptionMachine.run();

    return EXIT_SUCCESS;
}