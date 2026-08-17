#ifndef __ANDROID__
#include "cryptography/KernelKeys.hh"
#include "cryptography/Constants.hh"

#include <stdio.h>
#include <unistd.h>
#include <keyutils.h>
#include <cstring>
#include <sys/fsuid.h>

extern "C" int CreatePersistentKernelKey(const char *keyMaterial, unsigned int keyMaterialSize, const char *description, int ringId)
{
    if (keyMaterial == NULL || keyMaterialSize == 0 || description == NULL || keyMaterialSize > MAX_KERNEL_KEY_SIZE)
    {
        return -1;
    }

    key_serial_t ring = keyctl_get_persistent(-1, ringId);

    if (ring < 0)
    {
        return -1;
    }

    key_serial_t handle = add_key(KERNEL_KEY_TYPE, description, keyMaterial, keyMaterialSize, ring);

    if (handle < 0)
    {
        return -1;
    }

    if (keyctl_setperm(handle, KEY_POS_VIEW | KEY_POS_READ | KEY_POS_WRITE | KEY_POS_SEARCH | KEY_POS_SETATTR) == -1)
    {
        keyctl(KEYCTL_INVALIDATE, handle);
        return -1;
    }

    return handle;
}

extern "C" int CreateKernelKey(const char *keyMaterial, unsigned int keyMaterialSize, const char *description, int ringId)
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

    if (keyctl_setperm(handle, KEY_POS_VIEW | KEY_POS_READ | KEY_POS_WRITE | KEY_POS_SEARCH | KEY_POS_SETATTR) == -1)
    {
        keyctl(KEYCTL_INVALIDATE, handle);
        return -1;
    }

    return handle;
}

extern "C" int ReadKernelKey(int keyId, char *data)
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

extern "C" bool RemoveKernelKey(int keyId)
{
    if (keyId < 0)
    {
        return 0;
    }

    return keyctl_invalidate(keyId) != -1;
}

extern "C" int SearchKernelKey(const char *description, int ringId)
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

extern "C" int SearchPersistentKernelKey(const char *description, int ringId)
{
    if (description == NULL)
    {
        return -1;
    }

    key_serial_t ring = keyctl_get_persistent(-1, ringId);

    if (ring < 0)
    {
        return -1;
    }

    key_serial_t keyId = keyctl_search(ring, KERNEL_KEY_TYPE, description, 0);

    if (keyId < 0)
    {
        return -1;
    }

    return keyId < 0 ? -1 : keyId;
}

extern "C" int GetKernelKeyMaxSize()
{
    return MAX_KERNEL_KEY_SIZE;
}

#endif
