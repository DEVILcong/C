#include "read_rsaKey.hpp"

ReadRSAKey::ReadRSAKey(char* path_to_public, char* path_to_private){
    this->public_bio = nullptr;
    this->private_bio = nullptr;
    this->public_key = nullptr;
    this->private_key = nullptr;

    this->public_bio = BIO_new_file(path_to_public, "r");
    this->private_bio = BIO_new_file(path_to_private, "r");

    if((this->public_bio == nullptr) || (this->private_bio == nullptr)){
#ifdef _OUTPUT_
        if(this->public_bio == nullptr)
            std::cout << "ERROR: failed to open public pem file" << std::endl;
        if(this->private_bio == nullptr)
            std::cout << "ERROR: failed to open private pem file" << std::endl;
#endif
        this->isSuccess = false;
        return;
    }
    
    this->public_key = PEM_read_bio_PUBKEY(this->public_bio, NULL, 0, NULL);
    this->private_key = PEM_read_bio_PrivateKey(this->private_bio, NULL, 0, NULL);

    if(this->public_key == NULL || this->private_key == NULL){
#ifdef _OUTPUT_
        if(this->public_key == NULL)
            std::cout << "ERROR: failed to get public key" << std::endl;
        if(this->private_key == NULL)
            std::cout << "ERROR: failed to get private key" << std::endl;
#endif
        this->isSuccess = false;
        return;
    }

    this->isSuccess = true;
    return;
}

ReadRSAKey::~ReadRSAKey(){
    BIO_free(this->public_bio);
    BIO_free(this->private_bio);

    EVP_PKEY_free(this->public_key);
    EVP_PKEY_free(this->private_key);
}

bool ReadRSAKey::isRunSuccess(void){
    return this->isSuccess;
}

EVP_PKEY* ReadRSAKey::get_public_key(void){
    return this->public_key;
}

EVP_PKEY* ReadRSAKey::get_private_key(void){
    return this->private_key;    
}
