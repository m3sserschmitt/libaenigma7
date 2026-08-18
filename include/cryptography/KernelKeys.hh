#ifndef __ANDROID__
#ifndef KERNEL_KEYS_HH
#define KERNEL_KEYS_HH

extern "C"
{
    int CreateKernelKey(const char *keyMaterial, unsigned int keyMaterialSize, const char *description, int ringId);

    int CreatePersistentKernelKey(const char *keyMaterial, unsigned int keyMaterialSize, const char *description, int ringId);

    int ReadKernelKey(int keyId, char *data);

    bool RemoveKernelKey(int keyId);

    int SearchKernelKey(const char *description, int ringId);

    int SearchPersistentKernelKey(const char *description, int ringId);

    int GetKernelKeyMaxSize();
}
#endif
#endif
