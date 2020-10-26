#include "message_router.hpp"

std::mutex Message_router::log_file_mtx;
std::ofstream Message_router::log_file;

bool Message_router::if_continue_tag;
std::shared_mutex Message_router::if_continue_mtx;

std::shared_mutex Message_router::socket_mtx;
int Message_router::epoll_fd;
epoll_event Message_router::epoll_events[MAX_SOCKET_NUM / 2];
std::unordered_map<std::string, struct socket_item> Message_router::socket_map;
std::vector<std::string> Message_router::socket_index;
std::unordered_map<int, std::string> Message_router::socket_rindex;

std::shared_mutex Message_router::message_queue_mtx;
std::queue<message_item> Message_router::message_queue;

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
    std::unique_lock<std::shared_mutex> tmp_lock(socket_mtx);
    socket_index.push_back(std::string(name));

    tmp_socket_item.socket_fd = socket_fd;
    socket_map[std::string(name)] = tmp_socket_item;

    socket_rindex[socket_fd] = std::string(name);

    tmp_event.events = EPOLLIN | EPOLLET;
    tmp_event.data.fd = socket_fd;

    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket_fd, &tmp_event) < 0){
        std::unique_lock<std::mutex> tmp_lock2(log_file_mtx);
        log_file << now_time() << "\tWarning: can't add client " << name;
        log_file << '\t' << strerror(errno) << std::endl;

        close(socket_fd);
        return false;
    }else{
        std::unique_lock<std::mutex> tmp_lock2(log_file_mtx);
        log_file << now_time() << "\tInfo: add client " << name << std::endl;
    }
    return true;
}

void Message_router::message_worker(void){
    std::shared_lock<std::shared_mutex> tmp_lock_if_continue_tag(if_continue_mtx, std::defer_lock);
    std::unique_lock<std::mutex> tmp_lock_log_file(log_file_mtx, std::defer_lock);
    std::shared_lock<std::shared_mutex> tmp_lock_socket(socket_mtx, std::defer_lock);
    std::unique_lock<std::shared_mutex> tmp_lock_message_queue(message_queue_mtx, std::defer_lock);
    epoll_event* tmp_epoll_event_ptr = nullptr;
    char data_buffer[MAX_BUFFER_SIZE];
    int tmp_status = 0;

    std::string tmp_message_receiver;
    std::string tmp_message_sender;
    std::string tmp_message_content;
    unsigned short int tmp_message_no;
    Json::Reader tmp_json_reader;
    Json::Value tmp_json_value;

    int ready_num = 0;

    while(1){
        tmp_lock_if_continue_tag.lock();
        if(if_continue_tag == false){
            tmp_lock_if_continue_tag.unlock();
            break;
        }
        tmp_lock_if_continue_tag.unlock();

        tmp_lock_socket.lock();

        memset(epoll_events, 0, MAX_SOCKET_NUM/2 * sizeof(epoll_event));
        memset(data_buffer, 0, MAX_BUFFER_SIZE);

        ready_num = epoll_wait(epoll_fd, epoll_events, MAX_SOCKET_NUM/2, EPOLL_TIMEOUT);
        if(ready_num == -1){
            tmp_lock_log_file.lock();
            log_file << now_time() << '\t' << "Warning: " << strerror(errno) << std::endl;
            log_file.flush();
            tmp_lock_log_file.unlock();
        }else if(ready_num > 0){
            tmp_lock_message_queue.lock();
            tmp_epoll_event_ptr = epoll_events;

            for(int i = 0; i < ready_num; ++i){
                if((tmp_epoll_event_ptr->events | EPOLLRDHUP) || (tmp_epoll_event_ptr->events | EPOLLERR) || (tmp_epoll_event_ptr->events | EPOLLHUP)){
                    socket_map[socket_rindex[tmp_epoll_event_ptr->data.fd]].is_down = true;
                }else{
                    memset(data_buffer, 0, MAX_BUFFER_SIZE);
                    tmp_json_value.clear();

                    tmp_status = recv(tmp_epoll_event_ptr->data.fd, data_buffer, MAX_BUFFER_SIZE, 0);
                    if(tmp_status < 0){
                        tmp_lock_log_file.lock();
                        log_file << now_time() << '\t' << "Warning: read socker error, " << strerror(errno) << std::endl;
                        log_file.flush();
                        tmp_lock_log_file.unlock();
                    }else{
                        tmp_status = tmp_json_reader.parse(data_buffer, data_buffer + tmp_status, tmp_json_value);
                        if(!tmp_status){
                            tmp_lock_log_file.lock();
                            log_file << now_time() << '\t' << "Warning: parse message from " << socket_rindex[tmp_epoll_event_ptr->data.fd] << " error\n";
                            log_file.flush();
                            tmp_lock_log_file.unlock();

                            --socket_map[socket_rindex[tmp_epoll_event_ptr->data.fd]].count_down;
                        }else{
                            tmp_message_receiver = tmp_json_value["receiver"].asString();
                            tmp_message_sender = tmp_json_value["sender"].asString();
                            tmp_message_content = std::string(data_buffer);
                            tmp_message_no = (unsigned short int)tmp_json_value["no"].asUInt();

                            message_queue.emplace(tmp_message_receiver, tmp_message_sender, tmp_message_content);
                        }
                    }
                }

                ++tmp_epoll_event_ptr;
            }
            tmp_lock_message_queue.unlock();
        }

        tmp_lock_socket.unlock();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void Message_router::message_consumer(void){
    struct message_item tmp_message_item;
    std::shared_lock<std::shared_mutex> tmp_lock_if_continue_tag(if_continue_mtx, std::defer_lock);
    std::unique_lock<std::mutex> tmp_lock_log_file(log_file_mtx, std::defer_lock);
    std::unique_lock<std::shared_mutex> tmp_lock_socket(socket_mtx, std::defer_lock);
    std::unique_lock<std::shared_mutex> tmp_lock_message_queue(message_queue_mtx, std::defer_lock);

    int tmp_status = 0;
    int tmp_message_to_handle = 0;
    char tmp_status_to_send = 0;
    std::string tmp_string;
    std::string tmp_message_type;

    Json::FastWriter tmp_json_writer;
    Json::Reader tmp_json_reader;
    Json::Value tmp_json_value;

    while(1){
        tmp_lock_if_continue_tag.lock();
        if(if_continue_tag == false){
            tmp_lock_if_continue_tag.unlock();
            break;
        }
        tmp_lock_if_continue_tag.unlock();

        tmp_lock_message_queue.lock();
        tmp_lock_socket.lock();

        tmp_message_to_handle = message_queue.size();
        tmp_message_to_handle = tmp_message_to_handle > MESSAGE_NUM_LIMIT ? tmp_message_to_handle / 2 : tmp_message_to_handle;

        for(int i = 0; i < tmp_message_to_handle; ++i){
            tmp_message_item = message_queue.front();
            message_queue.pop();

            if(tmp_message_item.receiver != SERVER_NAME){
                tmp_status = send(socket_map[tmp_message_item.receiver].socket_fd, tmp_message_item.content.c_str(), tmp_message_item.content.length(), 0);
                ++socket_map[tmp_message_item.sender].count_down;
                if(socket_map[tmp_message_item.sender].count_down > 3)
                    socket_map[tmp_message_item.sender].count_down = 3;

                if(tmp_status <= 0){
                    tmp_lock_log_file.lock();
                    log_file << now_time() << '\t' << "Warning: send message to " << tmp_message_item.receiver << " failed due to ";
                    log_file << strerror(errno) << std::endl;
                    log_file.flush();
                    tmp_lock_log_file.lock();

                    if(tmp_message_item.tried_num < 3){
                        ++tmp_message_item.tried_num;
                        message_queue.push(tmp_message_item);
                    }else{
                        tmp_json_value.clear();
                        tmp_json_value["receiver"] = tmp_message_item.sender;
                        tmp_json_value["sender"] = SERVER_NAME;
                        tmp_json_value["type"] = MSG_TYPE_ERORR;
                        tmp_json_value["no"] = tmp_message_item.no;
                        tmp_json_value["info"] = MSG_VALUE_FAILED;

                        tmp_string = tmp_json_writer.write(tmp_json_value);
                        tmp_status = send(socket_map[tmp_message_item.sender].socket_fd, tmp_string.c_str(), tmp_string.length(), 0);

                        if(tmp_status <= 0){
                            tmp_lock_log_file.lock();
                            log_file << now_time() << '\t' << "Warning: error info msg can't be sent due to ";
                            log_file << strerror(errno) << std::endl;
                            log_file.flush();
                            tmp_lock_log_file.unlock();
                        }
                    }
                }
            }else{
                tmp_json_value.clear();
                tmp_json_reader.parse(tmp_message_item.content, tmp_json_value);
                tmp_message_type = tmp_json_value["type"].asString();

                if(tmp_message_type == MSG_TYPE_KEEPALIVE){
                    ++socket_map[tmp_json_value["sender"].asString()].count_down;
                    if(socket_map[tmp_message_item.sender].count_down > 3)
                        socket_map[tmp_message_item.sender].count_down = 3;
                }else if(tmp_message_type == MSG_TYPE_GET_USER_LIST){
                    tmp_json_value.clear();
                    tmp_json_value["receiver"] = tmp_message_item.sender;
                    tmp_json_value["sender"] = SERVER_NAME;
                    tmp_json_value["type"] = MSG_TYPE_GET_USER_LIST;
                    tmp_json_value["length"] = socket_index.size();
                    for(std::vector<std::string>::iterator i = socket_index.begin(); i != socket_index.end(); ++i){
                        tmp_json_value["info"].append(Json::Value(*i));
                    }

                    tmp_string = tmp_json_writer.write(tmp_json_value);

                    tmp_status = send(socket_map[tmp_message_item.sender].socket_fd, tmp_string.c_str(), tmp_string.length(), 0);
                    if(tmp_status <= 0){
                        if(tmp_message_item.tried_num < 3){
                            ++tmp_message_item.tried_num;
                            message_queue.push(tmp_message_item);
                        }else{
                            tmp_lock_log_file.lock();
                            log_file << now_time() << '\t' << "Warning: can't send user list to ";
                            log_file << tmp_message_item.sender << std::endl;
                            log_file.flush();
                            tmp_lock_log_file.unlock();
                        }
                    }
                }
            }
        }
        tmp_lock_message_queue.unlock();
        tmp_lock_socket.unlock();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void Message_router::cleaner(void){
    std::vector<std::string> tmp_to_be_closed_vector;
    std::vector<std::vector<std::string>::iterator> tmp_to_be_closed_vector_iterators;
    std::vector<std::vector<std::string>::iterator>::iterator tmp_iterator;
    std::shared_lock<std::shared_mutex> tmp_lock_if_continue_tag(if_continue_mtx, std::defer_lock);
    std::unique_lock<std::shared_mutex> tmp_lock_socket(socket_mtx, std::defer_lock);
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

        tmp_lock_socket.lock();

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
            socket_rindex.erase(tmp_socket_item.socket_fd);
            socket_map.erase(*i);
            socket_index.erase(*tmp_iterator);

            close(tmp_socket_item.socket_fd);

            tmp_lock_log_file.lock();
            log_file << now_time() << '\t' << "Warning: client " << *i << " closed\n";
            log_file.flush();
            tmp_lock_log_file.lock();

            ++tmp_iterator;
        }

        tmp_lock_socket.unlock();
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }
}

char* Message_router::now_time(void){
    tmp_now_time = std::chrono::system_clock::now();
    tmp_time_t = std::chrono::system_clock::to_time_t(tmp_now_time);
    return ctime(&tmp_time_t);
}