#include "login.hpp"
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <thread>

int main(void){
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_server_method());
    //SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_load_verify_locations(ssl_ctx, "cacert.pem", NULL);

    SSL_CTX_use_certificate_file(ssl_ctx, "test1.cer", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ssl_ctx, "test1.pem", SSL_FILETYPE_PEM);

    char tmp_tag = 0;
    
    login test(ssl_ctx, nullptr, nullptr);
    tmp_tag = test.get_tag();
    if(tmp_tag < 0){
        std::cout << "failed " << (int)tmp_tag << std::endl;
        return 0;
    }else{
        std::cout << "Successfully create\n";
    }

    test.init();
    tmp_tag = test.get_tag();
        if(tmp_tag < 0){
        std::cout << "failed " << (int)tmp_tag << std::endl;
        return 0;
    }else{
        std::cout << "Suuccessfully init\n";
    }

    std::thread listener(test.listener);
    std::thread cleaner(test.cleaner);

    listener.join();
    cleaner.join();
    
    return 0;
}
