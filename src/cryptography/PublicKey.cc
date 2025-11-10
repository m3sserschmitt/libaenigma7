#include "cryptography/PublicKey.hh"

#include <cstring>
#include <openssl/bio.h>
#include <openssl/pem.h>

void PublicKey::setKeyFromBio(void *bio, char *passphrase)
{
    this->setKey(PEM_read_bio_PUBKEY((BIO *)bio, nullptr, nullptr, passphrase));
}
    
void PublicKey::setKeyFromFile(FILE *file, char *passphrase)
{
    this->setKey(PEM_read_PUBKEY(file, nullptr, nullptr, passphrase));
}
