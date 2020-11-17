#ifndef __MESSAGE_ROUTER_HPP__
#define __MESSAGE_ROUTER_HPP__

#include <unordered_map>
#include <string>
#include <vector>
#include <mutex>
#include <fstream>
#include <chrono>
#include <queue>
#include <shared_mutex>
#include <deque>
#include <thread>
#include <unordered_set>

#include <sys/epoll.h>  //for epoll
#include <sys/types.h>
#include <sys/socket.h>  //for recv
#include <unistd.h>  //for close()
#include <time.h>
#include <errno.h>
#include <string.h>
#include <json/json.h>  //for jsoncpp
#include <mysql++/mysql++.h>

#define MAX_SOCKET_NUM 1024
#define MAX_BUFFER_SIZE 2048
#define EPOLL_TIMEOUT 500
#define MESSAGE_NUM_LIMIT 10   //消息队列中的消息数目低于此值时全部处理，否则处理一半
#define LOG_FILE "message_router.log"

#define SERVER_NAME "server"
#define MSG_TYPE_NORMAL "msg"
#define MSG_TYPE_ERORR "error"
#define MSG_TYPE_KEEPALIVE "keep"
#define MSG_TYPE_GET_USER_LIST "get"
#define MSG_VALUE_FAILED "-1"

#define DB_NAME "chat"
#define DB_SERVER "127.0.0.1"
#define DB_USER_NAME "login"
#define DB_PASSWORD "77777777"
#define DB_PORT 33060
#define DB_TABLE "users"

#define CLIENT_ALIVE_TIME_SECONDS 15
#define CLEANER_START_INTERVAL_SECONDS 5

//消息分界
#define MESSAGE_SPLIT "\n\n"
#define MESSAGE_SPLIT_SIZE 2

struct user_item{
    int socket_fd;
    short int count_down = CLIENT_ALIVE_TIME_SECONDS;
    bool is_down = false;
};

// struct message_item_t{
//     std::string receiver;
//     std::string sender;
//     std::string type;
//     std::string content;
//     unsigned char tried_num = 0;
// };

class Message_router{
public:
    Message_router();
    ~Message_router();
    static bool add_socket(const char* name, const int& socket_fd);
    char get_success_tag(void);
    static void set_if_continue_flag(void);
    static void message_worker(void);
    static void message_consumer(void);
    static void cleaner(void);

private:
    char success_tag;
    //meanings:
    //0: success
    //-1: can't create epoll
    //-2: can't open log file
    //-3: can't connect to mysql server
    //-4: can't get user list from mysql server

    static mysqlpp::Connection mysql_connection;
    
    static bool if_continue_tag;
    static std::mutex if_continue_mtx;

    static std::mutex log_file_mtx;
    static std::ofstream log_file;

    static std::mutex socket_mtx;
    static epoll_event epoll_events[MAX_SOCKET_NUM / 2];
    static int epoll_fd;
    static std::unordered_map<std::string, struct user_item> user_map;
    static std::vector<std::string> all_users_index;
    static std::vector<std::string> user_index;
    static std::unordered_map<int, std::string> user_rindex;

    //static std::mutex message_queue_mtx;
    static std::queue<std::unordered_map<char, std::string>> message_queue;
    static std::unordered_map<std::string, std::vector<std::unordered_map<char, std::string>>> to_be_sent_message_map;

    static time_t tmp_time_t;
    static std::chrono::system_clock::time_point tmp_now_time;
    static char* now_time(void);
};

#endif
