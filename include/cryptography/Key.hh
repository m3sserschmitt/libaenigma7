#ifndef KEY_HH
#define KEY_HH

#include "EncrypterData.hh"
#include "EncrypterResult.hh"

class Key
{
public:
    virtual ~Key() = 0;

    virtual const EncrypterResult *lock(const EncrypterData *) = 0;
    
    virtual const EncrypterResult *unlock(const EncrypterData *) = 0;
};

#endif
