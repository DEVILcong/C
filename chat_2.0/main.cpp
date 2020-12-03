#include "login.hpp"
#include "message_router.hpp"
#include "local_msg_type.hpp"

#include <thread>
#include <iostream>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main(void){
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_server_method());
    //SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_load_verify_locations(ssl_ctx, "../resource/cacert.pem", NULL);

    SSL_CTX_use_certificate_file(ssl_ctx, "../resource/test1.cer", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ssl_ctx, "../resource/test1.pem", SSL_FILETYPE_PEM);

    std::condition_variable local_msg_queue_cv;
    std::mutex local_msg_queue_mtx;
    std::queue<struct local_msg_type_t> local_msg_queue;
    char tmp_tag = 0;
    
    Message_router mr(ssl_ctx, &local_msg_queue_cv, &local_msg_queue_mtx, &local_msg_queue);
    login lg(ssl_ctx, &local_msg_queue_cv, &local_msg_queue_mtx, &local_msg_queue);
    lg.init();

    tmp_tag = mr.get_success_tag();
    if(tmp_tag < 0){
        std::cout << "message router init error " << int(tmp_tag) << std::endl;
        return 0;
    }

    tmp_tag = lg.get_tag();
    if(tmp_tag < 0){
        std::cout << "login module init error " << int(tmp_tag) << std::endl;
        return 0;
    }

    std::thread mr_local_listener(Message_router::local_msg_listener);
    lg.send_userlist_to_server();
    
    std::thread lg_listener(login::listener);
    std::thread lg_cleaner(login::cleaner);

    std::thread mr_worker(Message_router::message_worker);
    std::thread mr_consumer(Message_router::message_consumer);
    std::thread mr_cleaner(Message_router::cleaner);

    lg_listener.join();
    lg_cleaner.join();

    mr_local_listener.join();
    mr_worker.join();
    mr_consumer.join();
    mr_cleaner.join();
}