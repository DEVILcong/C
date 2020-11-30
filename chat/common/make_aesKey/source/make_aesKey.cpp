#include "make_aesKey.hpp"

MakeAESKey::MakeAESKey(){
    this->key = new unsigned char[KEY_SIZE];
    this->iv = new unsigned char[IV_SIZE];

    this->bn = BN_new();
}

MakeAESKey::~MakeAESKey(){
    delete [] this->key;
    delete [] this->iv;

    BN_free(this->bn);
}

void MakeAESKey::makeKey(void){
    memset(this->key, 0, KEY_SIZE);
    memset(this->iv, 0, IV_SIZE);

    short int status = 0;
    status = BN_rand(this->bn, KEY_SIZE * 8, RAND_TOP, RAND_BOTTEM);
    if(1 != status){
#ifdef _OUTPUT_
        std::cout << "ERROR: failed to create AES key value" << std::endl;
#endif
        this->isValid = false;
        return;
    }

    status = BN_bn2bin(this->bn, this->key);
    //std::cout << BN_bn2hex(this->bn) << std::endl;
    
    status = BN_rand(this->bn, IV_SIZE * 8, RAND_TOP, RAND_BOTTEM);
    if(1 != status){
#ifdef _OUTPUT_
        std::cout << "ERROR: failed to create AES key value" << std::endl;
#endif
        this->isValid = false;
        return;
    }
    
    status = BN_bn2bin(this->bn, this->iv);
    //std::cout << BN_bn2hex(this->bn) << std::endl;
    
    this->isValid = true;
    return;
}

bool MakeAESKey::ifValid(){
    return this->isValid;
}

unsigned char* MakeAESKey::getKey(){
    return this->key;
}

unsigned char* MakeAESKey::getIv(){
    return this->iv;
}
