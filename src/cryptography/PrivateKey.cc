#include "cryptography/PrivateKey.hh"

#include <cstring>
#include <openssl/bio.h>
#include <openssl/pem.h>

void PrivateKey::setKeyFromBio(void *bio, char *passphrase)
{
    this->setKey(PEM_read_bio_PrivateKey((BIO *)bio, nullptr, nullptr, passphrase));
}

void PrivateKey::setKeyFromFile(FILE *file, char *passphrase)
{
    this->setKey(PEM_read_PrivateKey(file, nullptr, nullptr, passphrase));
}
