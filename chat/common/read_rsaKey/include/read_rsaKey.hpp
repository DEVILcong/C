#ifndef _READ_RSAKEY_HPP_
#define _READ_RSAKEY_HPP_

/*传入PEM格式的公钥和私钥文件，以EVP_PKEY的格式返回
 *对应的公钥的私钥，用于加密或解密运算
 */

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include <iostream>

#define _OUTPUT_  //是否std::cout << 错误信息，注释掉不输出

class ReadRSAKey{
public:
    ReadRSAKey(char* path_to_public, char* path_to_private);
    ~ReadRSAKey();
    bool isRunSuccess(void);
    EVP_PKEY* get_public_key(void);
    EVP_PKEY* get_private_key(void);

private:
     bool isSuccess;

     BIO* public_bio;
     BIO* private_bio;
     EVP_PKEY* public_key;
     EVP_PKEY* private_key;
};

#endif
