#ifndef KEY_HH
#define KEY_HH

#include "EncrypterData.hh"
#include "EncrypterResult.hh"

class Key
{
    Bytes buffer;
    Size bufferSize;

protected:
    Bytes getBuffer()
    {
        return this->buffer;
    }

    void setBuffer(Bytes buffer)
    {
        this->buffer = buffer;
    }

    Size getBufferSize()
    {
        return this->bufferSize;
    }

    void setBufferSize(Size bufferSize)
    {
        this->bufferSize = bufferSize;
    }

    void freeBuffer()
    {
        if (this->buffer)
        {
            memset(this->buffer, 0, this->bufferSize);
            delete[] this->buffer;

            this->buffer = nullptr;
        }

        this->bufferSize = 0;
    }

    void createBuffer(Size size)
    {
        this->freeBuffer();

        this->buffer = new Byte[size + 1];
        this->bufferSize = size;
    }

public:
    Key()
    {
        this->buffer = nullptr;
        this->bufferSize = 0;
    }

    virtual ~Key()
    {
        this->freeBuffer();
    }

    virtual void setKeyData(const Byte *keyData, Size keylen) = 0;

    virtual const EncrypterResult *lock(const EncrypterData *) = 0;

    virtual const EncrypterResult *unlock(const EncrypterData *) = 0;

    virtual void reset()
    {
        this->freeBuffer();
    }
};

#endif
