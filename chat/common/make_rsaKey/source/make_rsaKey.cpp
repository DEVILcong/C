#include "make_rsaKey.hpp"

MakeRSAKey::MakeRSAKey(){
    this->bn = BN_new();
    this->keys = EVP_PKEY_new();
    this->rsa = RSA_new();
}

MakeRSAKey::~MakeRSAKey(){
    BN_free(this->bn);
    EVP_PKEY_free(this->keys);
    RSA_free(this->rsa);
}

void MakeRSAKey::makeKey(void){
    short int status = 0;
    status = BN_rand(this->bn, RAND_BITS, RAND_TOP, RAND_BOTTEM);
    if(1 != status){
#ifdef _OUTPUT_
        std::cout << "ERROR: failed to create random number" << std::endl;
#endif
        this->isValid = false;
        return;
    }

    status = RSA_generate_multi_prime_key(this->rsa, RSA_KEY_BITS, RSA_KEY_PRIMES, this->bn, NULL);
    if(1 != status){
#ifdef _OUTPUT_
        std::cout << "ERROR: failed to create RSA key" << std::endl;
#endif
        this->isValid = false;
        return;
    }

    status = EVP_PKEY_set1_RSA(this->keys, this->rsa);
    if(1 != status){
#ifdef _OUTPUT_
        std::cout << "ERROR: failed to convert RSA to EVP_PKEY" << std::endl;
#endif
        this->isValid = false;
        return;
    }

    this->isValid = true;
    return;
}

bool MakeRSAKey::ifValid(void){
    return this->isValid;
}

EVP_PKEY* MakeRSAKey::getKey(void){
    return this->keys;
}
