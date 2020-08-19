#ifndef _MAKE_AESKEY_HPP_
#define _MAKE_AESKEY_HPP_

#include <iostream>
#include <openssl/bn.h>

#define _OUTPUT_

#define KEY_SIZE 32   //32*8 bits
#define IV_SIZE 16    //16*8 bits

#define RAND_TOP -1
#define RAND_BOTTEM 1

class MakeAESKey{
public:
    MakeAESKey();
    ~MakeAESKey();
    void makeKey(void);
    bool ifValid(void);
    unsigned char* getKey(void);
    unsigned char* getIv(void);

private:
    bool isValid;
    BIGNUM* bn;
    unsigned char* key;
    unsigned char* iv;
};

#endif
