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
#define MSG_TYPE_ERORR "error"
#define MSG_TYPE_KEEPALIVE "keep"
#define MSG_TYPE_GET_USER_LIST "get"
#define MSG_VALUE_FAILED "-1"

struct user_item{
    int socket_fd;
    char count_down = 3;
    bool is_down = false;

    std::unordered_set<std::string> friends;
};

struct message_item{
    std::string receiver;
    std::string sender;
    std::string content;
    unsigned short int no = 0;
    unsigned char tried_num = 0;
};

class Message_router{
public:
    Message_router();
    ~Message_router();
    static bool add_socket(const char* name, const int& socket_fd);
    static void message_worker(void);
    static void message_consumer(void);
    static void cleaner(void);

private:
    char success_tag;

    static mysqlpp::Connection mysql_connection;
    
    static bool if_continue_tag;
    static std::shared_mutex if_continue_mtx;

    static std::mutex log_file_mtx;
    static std::ofstream log_file;

    static std::shared_mutex socket_mtx;
    static epoll_event epoll_events[MAX_SOCKET_NUM / 2];
    static int epoll_fd;
    static std::unordered_map<std::string, struct user_item> user_map;
    static std::vector<std::string> user_index;
    static std::unordered_map<int, std::string> user_rindex;

    static std::shared_mutex message_queue_mtx;
    static std::queue<message_item> message_queue;

    static std::shared_mutex to_be_sent_message_queue_mtx;
    static std::unordered_multimap<std::string, std::string> to_be_sent_message_queue;

    static time_t tmp_time_t;
    static std::chrono::system_clock::time_point tmp_now_time;
    static char* now_time(void);
};

#endif