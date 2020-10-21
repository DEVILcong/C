#include "message_router.hpp"

std::mutex Message_router::log_file_mtx;
std::ofstream Message_router::log_file;

bool Message_router::if_continue_tag;
std::mutex Message_router::if_continue_mtx;

std::mutex Message_router::epoll_mtx;
int Message_router::epoll_fd;

std::mutex Message_router::socket_map_mtx;
std::unordered_map<std::string, struct socket_item> Message_router::socket_map;

std::mutex Message_router::socket_index_mtx;
std::vector<std::string> Message_router::socket_index;

time_t Message_router::tmp_time_t;
std::chrono::system_clock::time_point Message_router::tmp_now_time;

Message_router::Message_router(){
    epoll_fd = epoll_create(MAX_SOCKET_NUM);
    if(epoll_fd < 0){
        this->success_tag = -1;
        return;
    }

    log_file.open(LOG_FILE, std::ofstream::out | std::ofstream::app);
    if(!log_file.is_open()){
        this->success_tag = -2;
        return;
    }

    if_continue_tag = true;
    this->success_tag = 0;
}

Message_router::~Message_router(){
    close(epoll_fd);

    for(std::vector<std::string>::iterator i = socket_index.begin(); i != socket_index.end(); ++i){
        close(socket_map[*i].socket_fd);
    }
}

bool Message_router::add_socket(const char* name, const int& socket_fd){
    struct epoll_event tmp_event;
    struct socket_item tmp_socket_item;
    std::unique_lock<std::mutex> tmp_lock(socket_index_mtx);
    socket_index.push_back(std::string(name));
    tmp_lock.unlock();
    tmp_lock.release();

    tmp_lock = std::unique_lock<std::mutex>(socket_map_mtx);
    tmp_socket_item.socket_fd = socket_fd;
    socket_map[std::string(name)] = tmp_socket_item;
    tmp_lock.unlock();
    tmp_lock.release();

    tmp_event.events = EPOLLIN | EPOLLET;
    tmp_event.data.fd = socket_fd;
    tmp_lock = std::unique_lock<std::mutex>(epoll_mtx);
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket_fd, &tmp_event) < 0){
        tmp_lock = std::unique_lock<std::mutex>(log_file_mtx);
        log_file << now_time() << "\tWarning: can't add client " << name;
        log_file << '\t' << strerror(errno) << std::endl;

        close(socket_fd);
        return false;
    }else{
        tmp_lock = std::unique_lock<std::mutex>(log_file_mtx);
        log_file << now_time() << "\tInfo: add client " << name << std::endl;
    }
    return true;
}

void Message_router::cleaner(void){
    std::vector<std::string> tmp_to_be_closed_vector;
    std::vector<std::vector<std::string>::iterator> tmp_to_be_closed_vector_iterators;
    std::vector<std::vector<std::string>::iterator>::iterator tmp_iterator;
    std::unique_lock<std::mutex> tmp_lock_if_continue_tag(if_continue_mtx, std::defer_lock);
    std::unique_lock<std::mutex> tmp_lock_index(socket_index_mtx, std::defer_lock);
    std::unique_lock<std::mutex> tmp_lock_map(socket_map_mtx, std::defer_lock);
    std::unique_lock<std::mutex> tmp_lock_log_file(log_file_mtx, std::defer_lock);
    struct socket_item tmp_socket_item;

    while(1){
        tmp_lock_if_continue_tag.lock();
        if(if_continue_tag == false){
            tmp_lock_if_continue_tag.unlock();
            break;
        }
        tmp_lock_if_continue_tag.unlock();

        tmp_to_be_closed_vector_iterators.clear();
        tmp_to_be_closed_vector.clear();

        tmp_lock_index.lock();
        tmp_lock_map.lock();

        for(std::vector<std::string>::iterator i = socket_index.begin(); i != socket_index.end(); ++i){
            tmp_socket_item = socket_map[*i];
            if(tmp_socket_item.is_down == true || tmp_socket_item.count_down < 0){
                tmp_to_be_closed_vector.push_back(*i);
                tmp_to_be_closed_vector_iterators.push_back(i);
            }
        }

        tmp_iterator = tmp_to_be_closed_vector_iterators.begin();
        for(std::vector<std::string>::iterator i = tmp_to_be_closed_vector.begin(); i != tmp_to_be_closed_vector.end(); ++i){
            tmp_socket_item = socket_map[*i];
            socket_map.erase(*i);
            socket_index.erase(*tmp_iterator);

            close(tmp_socket_item.socket_fd);

            tmp_lock_log_file.lock();
            log_file << now_time() << '\t' << "Warning: client " << *i << " closed\n";
            log_file.flush();
            tmp_lock_log_file.lock();

            ++tmp_iterator;
        }

        tmp_lock_index.unlock();
        tmp_lock_map.unlock();
    }
}

char* Message_router::now_time(void){
    tmp_now_time = std::chrono::system_clock::now();
    tmp_time_t = std::chrono::system_clock::to_time_t(tmp_now_time);
    return ctime(&tmp_time_t);
}