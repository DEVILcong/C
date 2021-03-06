#ifndef __LOGIN_HPP__
#define __LOGIN_HPP__

#include <sys/types.h>
#include <sys/socket.h>  //for socket
#include <sys/epoll.h>  //for epoll
#include <errno.h>  //for errno

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <string.h>  //for memset memcpy
#include <arpa/inet.h>  //for htons
#include <netinet/in.h>  //for inet_ntoa
#include <mutex>  //for mutex
#include <condition_variable>
#include <unordered_map>  //for unordered_map
#include <fstream>  //for ofstream
#include <ctime>
#include <chrono>  //for time in logfile
#include <thread>  //for this_thread::sleep_for
#include <queue>
#include <iostream>

#include <sqlite3.h>
#include <json/json.h>
#include <string>  //for string
#include <vector>  //for vector
#include <unistd.h>  //for close()
#include <fcntl.h>  //for fcntl()

#include "local_msg_type.hpp"
#include "process_msg.hpp"

extern Json::Value json_config;

struct aes_key_item_t{
    unsigned char key[AES_256_KEY_LEN];
    unsigned char iv[AES_256_IV_LEN];
};

struct client_socket_t{
   int socket;
   //std::mutex mtx;
   struct in_addr addr;
   SSL* ssl_fd = nullptr;
   unsigned char time = 0;
   unsigned char tried_time = 0;
   unsigned char is_closed = false;
};

// #define LOGIN_MSG_NAME_END_FLAG '$'
// struct login_message_t{
//     //unsigned short int name_length;
//     unsigned char type;
//     unsigned char none = 'N';
//     char name[25];
//     char pass[45];
// };

class login{
public:
    login(SSL_CTX* tmp_ssl_ctx_fd, std::condition_variable* tmp_local_msg_queue_cv, std::mutex* tmp_local_msg_queue_mtx, std::queue<local_msg_type_t>* tmp_local_msg_queue);
    ~login();
    void init();
    char get_tag(void);
    void send_userlist_to_server();
    static void set_continue_tag(bool tmp_tag);
    static void listener(void);
    static void cleaner(void);

private:

    static SSL_CTX* ssl_ctx_fd;
    static std::queue<local_msg_type_t>* local_msg_queue;
    static std::mutex* local_msg_queue_mtx;
    static std::condition_variable* local_msg_queue_cv;

    char success_tag;
    //meanings:
    //0: success
    //-1: open listen socket error
    //-2: bind listen socket to address error
    //-4: can't set listen socket to non-blocking mode
    //-5: can't start listening on listen socket
    //-6: can't add listen socket to epoll
    //-7: can't open log file
    //-8: can't connct to database server
    //-9: can't open server key file
    //-10: can't read from server key file

    static sqlite3* db_sqlite;
    static sqlite3_stmt* db_sqlite_stmt;
    static sqlite3_stmt* db_sqlite_stmt_get_userlist;
    
    static bool db_open();
    static bool db_init();
    static bool db_if_opened();
    static std::string db_get_userlist();
    static bool db_verify(const char* name, const char* passwd);
    static void db_close();

    static struct aes_key_item_t* server_keys_ptr;
    
    static std::mutex continue_tag_mtx;
    volatile static bool continue_tag;

    static int listen_socket;

    static std::ofstream log_file;
    static std::mutex write_log_mtx;

    static int epoll_fd;
    static struct epoll_event* ready_sockets_ptr;

    static std::mutex socket_list_mtx;
    static std::vector<int> socket_catalogue;
    static std::unordered_map<int, client_socket_t> sockets;
    static std::vector<int> to_be_cleaned_val;
    static std::vector<unsigned short int> to_be_cleaned_pos;

    static std::time_t tmp_time_t;
    static std::chrono::system_clock::time_point tmp_now_time;
    static char* now_time(void);
};

#endif
