#ifndef ASYMMETRIC_KEY_HH
#define ASYMMETRIC_KEY_HH

#include "Key.hh"

class AsymmetricKey : public Key 
{
public:
    const EncrypterResult *lock(const EncrypterData *) override;

    const EncrypterResult *unlock(const EncrypterData *) override;
};

#endif
