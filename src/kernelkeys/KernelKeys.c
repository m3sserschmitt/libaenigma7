#include "kernelkeys/KernelKeys.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <keyutils.h>

#define KEY_TYPE "user"

int CreateKey(const char *keyName, const char *keyMaterial, unsigned int keyMaterialSize, const char *description, int ringId)
{
    if (keyName == NULL || keyMaterial == NULL || keyMaterialSize == 0 || description == NULL || keyMaterialSize > MAX_KERNEL_KEY_SIZE)
    {
        return -1;
    }

    key_serial_t keyHandle = add_key(KEY_TYPE, description, keyMaterial, keyMaterialSize, ringId);

    if (keyHandle < 0)
    {
        return -1;
    }

    if (keyctl_setperm(keyHandle, KEY_POS_ALL) != 0)
    {
        keyctl(KEYCTL_UNLINK, keyHandle);

        return -1;
    }

    return keyHandle;
}

int ReadKey(int keyId, char *data)
{
    if(keyId < 0 || data == NULL)
    {
        return -1;
    }

    char *buffer = malloc((MAX_KERNEL_KEY_SIZE + 1) * sizeof(char));
    ssize_t bytesRead = keyctl_read(keyId, buffer, MAX_KERNEL_KEY_SIZE);

    if (bytesRead < 0 || bytesRead > MAX_KERNEL_KEY_SIZE)
    {
        memset(buffer, 0, MAX_KERNEL_KEY_SIZE + 1);
        free(buffer);
        return -1;
    }

    memcpy(data, buffer, bytesRead);
    data[bytesRead] = 0;

    memset(buffer, 0, MAX_KERNEL_KEY_SIZE + 1);
    free(buffer);

    return bytesRead;
}

int RemoveKey(int keyId)
{
    if(keyId < 0)
    {
        return 0;
    }

    return keyctl(KEYCTL_UNLINK, keyId) != -1;
}

int SearchKey(const char *keyName, const char *description, int ringId)
{
    if(keyName == NULL || description == NULL)
    {
        return -1;
    }
    
    key_serial_t keyId = keyctl_search(ringId, KEY_TYPE, description, 0);

    if(keyId < 0)
    {
        return -1;
    }

    return keyId;
}

unsigned int GetKernelKeyMaxSize()
{
    return MAX_KERNEL_KEY_SIZE;
}
