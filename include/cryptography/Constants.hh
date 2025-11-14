#ifndef CONSTANTS_HH
#define CONSTANTS_HH

#define SYMMETRIC_KEY_SIZE 32
#define IV_SIZE 12
#define TAG_SIZE 16
#define ONION_LENGTH_BYTES 2
#define ADDRESS_SIZE 32
#ifndef __ANDROID__
#define MAX_KERNEL_KEY_SIZE 4096
#define MASTER_PASSPHRASE_MAX_NAME_SIZE 1024
#define MASTER_PASSPHRASE_DEFAULT_NAME "aenigma_master_passphrase"
#define KERNEL_KEY_TYPE "user"
#define KERNEL_KEY_KEYRING -2
#endif
#endif
