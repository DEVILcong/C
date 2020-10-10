#ifndef __LOGIN_HPP__
#define __LOGIN_HPP__

#include <sys/types.h>
#include <sys/socket.h>  //for socket
#include <sys/epoll.h>  //for epoll
#include <errno.h>  //for errno

#include <string.h>  //for memset
#include <arpa/inet.h>  //for htons
#include <netinet/in.h>  //for inet_ntoa
#include <mutex>  //for mutex
#include <unordered_map>  //for unordered_map
#include <fstream>  //for ofstream
#include <ctime>
#include <chrono>  //for time in logfile
#include <thread>  //for this_thread::sleep_for
#include <mysql++/mysql++.h>  //for mysql
#include <string>  //for string

#define LISTEN_PORT 22233
#define MAX_SOCKET_NUM 1024
#define MAX_READY_SOCKET_NUM MAX_SOCKET_NUM/2
#define EPOLL_WAIT_TIMEOUT 2
#define MAX_LISTEN_QUEUE 10

#define LOG_FILE_PATH "login.log"
#define MYSQL_SERVER "127.0.0.1"
#define MYSQL_PORT 33060
#define MYSQL_USER "login"
#define MYSQL_PASS "77777777"
#define MYSQL_DB "chat"
#define MYSQL_TABLE "users"

struct client_socket_t{
   int socket;
   //std::mutex mtx;
   unsigned char time = 3;
   unsigned char tried_time = 0;
};

#define LOGIN_MSG_NAME_END_FLAG '$'
struct login_message_t{
    //unsigned short int name_length;
    unsigned char type;
    unsigned char none = 'N';
    char name[25];
    char pass[65];
};

class login{
public:
    login();
    ~login();
    void init();
    static void listener(void);
    static void cleaner(void);

private:
    char success_tag;
    volatile static bool continue_tag;
    static int listen_socket;

    static mysqlpp::Connection conn;
    static mysqlpp::Query query;

    static std::ofstream log_file;
    static std::mutex write_log_mtx;

    static int epoll_fd;
    static std::mutex epoll_mtx;
    static struct epoll_event ready_socks[MAX_READY_SOCKET_NUM];

    static std::mutex socket_list_mtx;
    static std::list<int> socket_catalogue;
    static std::unordered_map<int, client_socket_t> sockets;

    static std::time_t tmp_time_t;
    static std::chrono::system_clock::time_point tmp_now_time;
    static char* now_time(void);
};

#endif
