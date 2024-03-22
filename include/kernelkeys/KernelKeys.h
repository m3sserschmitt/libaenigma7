#ifndef KERNEL_KEYS
#define KERNEL_KEYS

#define MAX_KERNEL_KEY_SIZE 4096

int CreateKey(const char *keyName, const char *keyMaterial, unsigned int keyMaterialSize, const char *tag, int ringId);

int ReadKey(int keyId, char *data);

int RemoveKey(int keyId);

int SearchKey(const char *keyName, const char *description, int ringId);

unsigned int GetKernelKeyMaxSize();

#endif
