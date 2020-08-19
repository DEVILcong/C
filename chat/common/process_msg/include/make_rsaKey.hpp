#ifndef _MAKE_RSAKEY_HPP
#define _MAKE_RSAKEY_HPP

/*生成RSA密钥对，并以EVP_PKEY的格式返回
 *
 */

#include <iostream>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

#define _OUTPUT_

#define RAND_BITS 20
#define RAND_TOP -1
#define RAND_BOTTEM 1
#define RSA_KEY_BITS 2048
#define RSA_KEY_PRIMES 3

class MakeRSAKey{
public:
    MakeRSAKey();
    ~MakeRSAKey();
    void makeKey(void);
    bool ifValid(void);
    EVP_PKEY* getKey();

private:
    bool isValid;
    BIGNUM* bn;
    RSA* rsa;
    EVP_PKEY* keys;
};


#endif
