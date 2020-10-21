#ifndef __MESSAGE_ROUTER_HPP__
#define __MESSAGE_ROUTER_HPP__

#include <unordered_map>
#include <string>
#include <vector>
#include <mutex>
#include <fstream>
#include <chrono>

#include <sys/epoll.h>  //for epoll
#include <unistd.h>  //for close()
#include <time.h>
#include <errno.h>
#include <string.h>

#define MAX_SOCKET_NUM 1024
#define LOG_FILE "message_router.log"

struct socket_item{
    int socket_fd;
    char count_down = 3;
    bool is_down = false;
};

class Message_router{
public:
    Message_router();
    ~Message_router();
    static bool add_socket(const char* name, const int& socket_fd);
    static void cleaner(void);

private:
    char success_tag;

    static bool if_continue_tag;
    static std::mutex if_continue_mtx;

    static std::mutex log_file_mtx;
    static std::ofstream log_file;

    static std::mutex epoll_mtx;
    static int epoll_fd;

    static std::mutex socket_map_mtx;
    static std::unordered_map<std::string, struct socket_item> socket_map;

    static std::mutex socket_index_mtx;
    static std::vector<std::string> socket_index;

    static time_t tmp_time_t;
    static std::chrono::system_clock::time_point tmp_now_time;
    static char* now_time(void);
};

#endif