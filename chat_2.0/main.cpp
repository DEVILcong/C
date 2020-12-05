#include "login.hpp"
#include "message_router.hpp"
#include "local_msg_type.hpp"

#include <thread>
#include <iostream>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <fstream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <json/json.h>

#define JSON_CONFIG_FILE "config.json"
Json::Value json_config;

int main(void){
    std::ifstream json_config_file(JSON_CONFIG_FILE, std::ifstream::in);
    if(!json_config_file.is_open()){
        std::cout << "ERROR: can't find config file which name is config.json, exit\n";
        return 0;
    }

    Json::Reader tmp_json_reader;
    if(!tmp_json_reader.parse(json_config_file, json_config, false)){
        std::cout << "ERROR: can't read config info from config.json, exit\n";
        return 0;
    }

    json_config_file.close();

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    int tmp_tag = 0;

    SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_server_method());
    //SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    //SSL_CTX_load_verify_locations(ssl_ctx, "../resource/cacert.pem", NULL);

    tmp_tag = SSL_CTX_use_certificate_file(ssl_ctx, json_config["main"]["server_pub_cert"].asCString(), SSL_FILETYPE_PEM);
    if(tmp_tag != 1){
        std::cout << "ERROR: can't read server public key file" << std::endl;
        return 0;
    }

    tmp_tag = SSL_CTX_use_PrivateKey_file(ssl_ctx, json_config["main"]["server_priv_key"].asCString(), SSL_FILETYPE_PEM);
    if(tmp_tag != 1){
        std::cout << "ERROR: can't read server private key file" << std::endl;
        return 0;
    }

    std::condition_variable local_msg_queue_cv;
    std::mutex local_msg_queue_mtx;
    std::queue<struct local_msg_type_t> local_msg_queue;

    login lg(ssl_ctx, &local_msg_queue_cv, &local_msg_queue_mtx, &local_msg_queue);
    tmp_tag = lg.get_tag();
    if(tmp_tag < 0){
        std::cout << "ERROR: login module init error " << int(tmp_tag) << std::endl;
        return 0;
    }

    lg.init();
    tmp_tag = lg.get_tag();
    if(tmp_tag < 0){
        std::cout << "ERROR: login module init error " << int(tmp_tag) << std::endl;
        return 0;
    }

    Message_router mr(ssl_ctx, &local_msg_queue_cv, &local_msg_queue_mtx, &local_msg_queue);
    tmp_tag = mr.get_success_tag();
    if(tmp_tag < 0){
        std::cout << "ERROR: message router init error " << int(tmp_tag) << std::endl;
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