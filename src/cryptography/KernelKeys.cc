#ifndef __ANDROID__
#include "cryptography/KernelKeys.hh"
#include "cryptography/Constants.hh"

#include <unistd.h>
#include <keyutils.h>
#include <cstring>

int CreateKernelKey(const char *keyMaterial, unsigned int keyMaterialSize, const char *description, int ringId)
{
    if (keyMaterial == NULL || keyMaterialSize == 0 || description == NULL || keyMaterialSize > MAX_KERNEL_KEY_SIZE)
    {
        return -1;
    }

    key_serial_t ring = keyctl_get_keyring_ID(ringId, 1);

    if (ring < 0)
    {
        return -1;
    }

    key_serial_t handle = add_key(KERNEL_KEY_TYPE, description, keyMaterial, keyMaterialSize, ring);

    if (handle < 0)
    {
        return -1;
    }

    if (keyctl(KEYCTL_LINK, handle, ring) == -1)
    {
        return -1;
    }

    return handle;
}

int ReadKernelKey(int keyId, char *data)
{
    if (keyId < 0 || data == NULL)
    {
        return -1;
    }

    char *buffer = new char[MAX_KERNEL_KEY_SIZE + 1];
    ssize_t bytesRead = keyctl_read(keyId, buffer, MAX_KERNEL_KEY_SIZE);

    if (bytesRead < 0 || bytesRead > MAX_KERNEL_KEY_SIZE)
    {
        memset(buffer, 0, MAX_KERNEL_KEY_SIZE + 1);
        delete[] buffer;
        return -1;
    }

    memcpy(data, buffer, bytesRead);
    data[bytesRead] = 0;

    memset(buffer, 0, MAX_KERNEL_KEY_SIZE + 1);
    delete[] buffer;

    return bytesRead;
}

bool RemoveKernelKey(int keyId)
{
    if (keyId < 0)
    {
        return 0;
    }

    return keyctl(KEYCTL_UNLINK, keyId) != -1;
}

int SearchKernelKey(const char *description, int ringId)
{
    if (description == NULL)
    {
        return -1;
    }

    key_serial_t ring = keyctl_get_keyring_ID(ringId, 1);

    if (ring < 0)
    {
        return -1;
    }

    key_serial_t keyId = keyctl_search(ring, KERNEL_KEY_TYPE, description, 0);

    return keyId < 0 ? -1 : keyId;
}

unsigned int GetKernelKeyMaxSize()
{
    return MAX_KERNEL_KEY_SIZE;
}

#endif
