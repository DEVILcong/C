#include "process_msg.hpp"

deleter::deleter(){}

template<class T>
void deleter::operator()(T* ptr){
    delete [] ptr;
}

ProcessMsg::ProcessMsg(int sha3_256__base64){
    this->init();
}

ProcessMsg::ProcessMsg(EVP_PKEY* RSA_key){
    this->init();

    this->evp_pkey_ctx = EVP_PKEY_CTX_new(RSA_key, NULL);
    if(this->evp_pkey_ctx != NULL)
        this->isValid = true;
}

ProcessMsg::ProcessMsg(unsigned char* key, unsigned char* iv){
    this->init();

    this->aes_key = new unsigned char[AES_256_KEY_LEN];
    this->aes_key_tmp = new unsigned char[AES_256_KEY_LEN];

    this->aes_iv = new unsigned char[AES_256_IV_LEN];
    this->aes_iv_tmp = new unsigned char[AES_256_IV_LEN];

    memcpy(this->aes_key, key, AES_256_KEY_LEN);
    memcpy(this->aes_key_tmp, key, AES_256_KEY_LEN);

    memcpy(this->aes_iv, iv, AES_256_IV_LEN);
    memcpy(this->aes_iv_tmp, iv, AES_256_IV_LEN);

    this->evp_cipher_ctx = EVP_CIPHER_CTX_new();
}

ProcessMsg::~ProcessMsg(){
    // if(this->bio_base64_decode != nullptr)
    //     BIO_free_all(this->bio_base64_decode);

    if(this->bio_base64_encode != nullptr)
        BIO_free_all(this->bio_base64_encode);

    if(this->evp_pkey_ctx != nullptr)
        EVP_PKEY_CTX_free(this->evp_pkey_ctx);

    if(this->evp_cipher_ctx != nullptr)
        EVP_CIPHER_CTX_free(this->evp_cipher_ctx);

    if(this->aes_key != nullptr)
        delete [] this->aes_key;

    if(this->aes_iv != nullptr)
        delete [] this->aes_iv;

    if(this->aes_key_tmp != nullptr)
        delete [] this->aes_key_tmp;

    if(this->aes_iv_tmp != nullptr)
        delete [] this->aes_iv_tmp;
}

void ProcessMsg::init(void){
    OpenSSL_add_all_algorithms();

    this->buffer_length = 0;

    this->d = deleter();

    this->buffer = std::unique_ptr<unsigned char, deleter>(nullptr, this->d);

    this->bio_base64_encode = BIO_new(BIO_f_base64());

    this->evp_pkey_ctx = nullptr;

    this->evp_cipher_ctx = nullptr;

    this->isValid = false;

    this->aes_key = nullptr;
    this->aes_iv = nullptr;

    this->aes_key_tmp = nullptr;
    this->aes_iv_tmp = nullptr;

    return;
}

void ProcessMsg::digest(const char* str, size_t length){

    this->buffer.reset(new unsigned char[DIGEST_SIZE]);

    int status = EVP_Digest(str, length, this->buffer.get(), NULL, DIGEST_METHOD, NULL);

    if(status <= 0){
#ifdef _OUTPUT_
        std::cout << "ERROR: failed to get sha3-256 data" << std::endl;
#endif
        this->isValid = false;
        return;
    }

    this->buffer_length = DIGEST_SIZE;
    this->base64_encode((const char*)(this->buffer.get()), this->buffer_length);

    this->isValid = true;
}

void ProcessMsg::base64_encode(const char* str, size_t length){
    
    BUF_MEM* buf = nullptr;

    BIO* tmp_bio = BIO_new(BIO_s_mem());
    this->bio_base64_encode = BIO_push(this->bio_base64_encode, tmp_bio);

    int status = BIO_write(this->bio_base64_encode, str, length);

    if(status <= 0){
#ifndef _OUTPUT_
        std::cout << "ERROR: failed to write BIO during base64 encode" << std::endl;
#endif
        this->isValid = false;
        return;
    }

    BIO_flush(this->bio_base64_encode);

    BIO_get_mem_ptr(this->bio_base64_encode, &buf);
    if(buf == nullptr){
#ifdef _OUTPUT_
        std::cout << "ERROR: failed when obtain buf ptr during base64 encode" << std::endl;
#endif
        this->isValid = false;
        return;
    }

    if(buf->length == 0){
#ifdef _OUTPUT_
        std::cout << "ERROR: failed to get data during sha3-256";
#endif
        this->isValid = false;
        return;
    }
    
    this->buffer_length = buf->length;
    this->buffer.reset(new unsigned char[this->buffer_length]);
    memset(this->buffer.get(), 0, this->buffer_length);
    memcpy(this->buffer.get(), buf->data, this->buffer_length);

    //std::cout << this->buffer.get() << "\t" << this->buffer_length << std::endl;

    BIO_pop(tmp_bio);
    BIO_free(tmp_bio);
    BIO_reset(this->bio_base64_encode);
     
    this->isValid = true;
    return;

}

void ProcessMsg::base64_decode(const char* str, size_t length){

    this->bio_base64_decode = BIO_new(BIO_f_base64());
    
    if(length <= 65)
        BIO_set_flags(this->bio_base64_decode, BIO_FLAGS_BASE64_NO_NL);  //base64串中是否有换行符

    BIO* tmp_bio = BIO_new_mem_buf(str, length);
    this->bio_base64_decode = BIO_push(this->bio_base64_decode, tmp_bio);
    
    this->buffer.reset(new unsigned char[length]);
    memset(this->buffer.get(), 0, length);

    int status = BIO_read(this->bio_base64_decode, this->buffer.get(), length);

    if(status < 0){
#ifdef _OUTPUT_
        std::cout << "ERROR: failed to decode base64 " << status << std::endl;
#endif
        this->isValid = false;
        return;
    }

    this->buffer_length = status;
    this->isValid = true;

    // BIO_pop(tmp_bio);
    // BIO_free(tmp_bio);

    // if(length <= 65)
    //     BIO_clear_flags(this->bio_base64_decode, BIO_FLAGS_BASE64_NO_NL);

    BIO_free_all(this->bio_base64_decode);
}

void ProcessMsg::RSA_encrypt(const char* str, size_t length){
    int status = 0;
    unsigned int buffer_len = 0;

    status = EVP_PKEY_encrypt_init(this->evp_pkey_ctx);
    if(1 != status){
#ifdef _OUTPUT_
        std::cout << "ERROR: failed to initialize RSA when encrypt" << std::endl;
#endif
        this->isValid = false;
        return;
    }

    status = EVP_PKEY_CTX_set_rsa_padding(this->evp_pkey_ctx, RSA_PKCS1_OAEP_PADDING);
    if(1 != status){
#ifdef _OUTPUT_
        std::cout << "ERROR: failed to set RSA padding when encrypt" << std::endl;
#endif
    }

    status = EVP_PKEY_encrypt(this->evp_pkey_ctx, NULL, &(this->buffer_length), (const unsigned char*)str, length);
    if(1 != status){
#ifdef _OUTPUT_
        std::cout << "ERROR: failed to get RSA buffer length when encrypt" << std::endl;
#endif
        this->isValid = false;
        return;
    }

    this->buffer.reset(new unsigned char[this->buffer_length]);

    status = EVP_PKEY_encrypt(this->evp_pkey_ctx, this->buffer.get(), &(this->buffer_length), (const unsigned char*)str, length);
    if(1 != status){
#ifndef _OUTPUT_
        std::cout << "ERROR: failed to perform RSA encrypt" << std::endl;
#endif
        this->isValid = false;
        return;
    }

    this->base64_encode((const char*)(this->buffer.get()), this->buffer_length);
}

void ProcessMsg::RSA_decrypt(const char* str, size_t length){
    this->isValid = false;
    this->base64_decode(str, length);

    if(this->isValid == false){
#ifdef _OUTPUT_
        std::cout << "ERROR: failed to perform base64 decode when RSA decrypt" << std::endl;
#endif
        this->isValid = false;
        return;
    }
    
    int status = 0;
    unsigned char* tmp_buf = nullptr;
    size_t tmp_buf_length = 0;

    status = EVP_PKEY_decrypt_init(this->evp_pkey_ctx);
    if(1 != status){
#ifdef _OUTPUT_
        std::cout << "ERROR: failed to initialize RSA when decrypt" << std::endl;
#endif
        this->isValid = false;
        return;
    }

    status = EVP_PKEY_CTX_set_rsa_padding(this->evp_pkey_ctx, RSA_PKCS1_OAEP_PADDING);
    if(1 != status){
#ifdef _OUTPUT_
        std::cout << "ERROR: failed to set RSA padding when decrypt" << std::endl;
#endif
    }

    status = EVP_PKEY_decrypt(this->evp_pkey_ctx, NULL, &(tmp_buf_length), this->buffer.get(), this->buffer_length);
    if(1 != status){
#ifdef _OUTPUT_
        std::cout << "ERROR: failed to get RSA buffer length when decrypt" << std::endl;
#endif
        this->isValid = false;
        return;
    }

    tmp_buf = new unsigned char[tmp_buf_length + 2];
    memset(tmp_buf, 0, tmp_buf_length + 2);

    status = EVP_PKEY_decrypt(this->evp_pkey_ctx, tmp_buf, &(tmp_buf_length), this->buffer.get(), this->buffer_length);
    if(1 != status){
#ifndef _OUTPUT_
        std::cout << "ERROR: failed to perform RSA decrypt" << std::endl;
#endif
        this->isValid = false;
        return;
    }

    this->buffer.reset(tmp_buf);
    this->buffer_length = tmp_buf_length;

    this->isValid = true;
    return;
}

void ProcessMsg::AES_256_change_key(unsigned char* key, unsigned char* iv){
    memcpy(this->aes_key, key, AES_256_KEY_LEN);
    memcpy(this->aes_key_tmp, key, AES_256_KEY_LEN);

    memcpy(this->aes_iv, iv, AES_256_IV_LEN);
    memcpy(this->aes_iv_tmp, iv, AES_256_IV_LEN);
}

void ProcessMsg::AES_256_process(const char* str, size_t length, int enc){
    int outlen = 0;

    size_t data_length = 0;
    size_t final_data_length = 0;

    unsigned char* data_ptr = nullptr;
    unsigned char* buf_ptr = nullptr;

    if(0 == enc){
        this->base64_decode(str, length);
        data_ptr = this->buffer.get();
        data_length = this->buffer_length;
    }
    else{
        data_ptr = (unsigned char*)str;
        data_length = length;
    }

    memcpy(this->aes_key_tmp, this->aes_key, AES_256_KEY_LEN);
    memcpy(this->aes_iv_tmp, this->aes_iv, AES_256_IV_LEN);
    
    int status = EVP_CipherInit_ex(this->evp_cipher_ctx, EVP_CIPHER, NULL, this->aes_key_tmp, this->aes_iv_tmp, enc);
    if(1 != status){
#ifdef _OUTPUT_
        std::cout << "ERROR: failed to init when AES-256 process" << std::endl;
#endif
        this->isValid = false;
        return;
    }

    buf_ptr = new unsigned char[data_length + 32];
    memset(buf_ptr, 0, data_length + 32);

    status = EVP_CipherUpdate(this->evp_cipher_ctx, buf_ptr, &outlen, data_ptr, data_length);

    final_data_length += outlen;
        
    status = EVP_CipherFinal_ex(this->evp_cipher_ctx, &(buf_ptr[final_data_length]), &outlen);
    if(1 != status){
#ifdef _OUTPUT_
        std::cout << "ERROR: an error occured when finishing AES-256 process" << std::endl;
#endif
        this->isValid = false;
    }
    final_data_length += outlen;
    
    /*if(0 == enc){
        std::cout << buf_ptr << std::endl;
        std::cout << final_data_length << std::endl;
        std::cout << "****************************\n";
    }*/
    
    this->buffer.reset(buf_ptr);
    this->buffer_length = final_data_length;

    EVP_CIPHER_CTX_reset(this->evp_cipher_ctx);

    if(1 == enc)
        this->base64_encode((const char*)(this->buffer.get()), this->buffer_length);
}

unsigned char* ProcessMsg::get_result(void){
    return this->buffer.get();
}

size_t ProcessMsg::get_result_length(void){
    return this->buffer_length;
}

void ProcessMsg::test(void){

}

void ProcessMsg::print_hex(unsigned char* str, unsigned int length){
    for(char i = 0; i < length; ++i){
        std::cout << std::hex << (int)str[i] << " ";
    }
    std::cout << std::endl;
}
