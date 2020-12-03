#include "message_router.hpp"

SSL_CTX* Message_router::ssl_ctx_fd = nullptr;
std::condition_variable* Message_router::local_msg_queue_cv = nullptr;
std::mutex* Message_router::local_msg_queue_mtx = nullptr;
std::queue<struct local_msg_type_t>* Message_router::local_msg_queue = nullptr;

std::mutex Message_router::log_file_mtx;
std::ofstream Message_router::log_file;

bool Message_router::if_continue_tag;
std::mutex Message_router::if_continue_mtx;

std::mutex Message_router::socket_mtx;
int Message_router::epoll_fd;
epoll_event Message_router::epoll_events[MAX_SOCKET_NUM / 2];
std::unordered_map<std::string, struct user_item> Message_router::user_map;
std::vector<std::string> Message_router::all_users_index;
std::vector<std::string> Message_router::user_index;
std::unordered_map<int, std::string> Message_router::user_rindex;

//std::mutex Message_router::message_queue_mtx;
std::queue<struct message_item_t> Message_router::message_queue;
std::unordered_map<std::string, std::vector<struct message_item_t>> Message_router::to_be_sent_message_map;

time_t Message_router::tmp_time_t;
std::chrono::system_clock::time_point Message_router::tmp_now_time;

Message_router::Message_router(SSL_CTX* tmp_ssl_ctx_fd = nullptr, std::condition_variable* tmp_local_queue_cv = nullptr, std::mutex* queue_mtx = nullptr, std::queue<struct local_msg_type_t>* queue_ptr = nullptr){
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

    ssl_ctx_fd = tmp_ssl_ctx_fd;
    local_msg_queue_mtx = queue_mtx;
    local_msg_queue = queue_ptr;
    local_msg_queue_cv = tmp_local_queue_cv;

    if_continue_tag = true;
    this->success_tag = 0;
}

Message_router::~Message_router(){
    close(epoll_fd);

    for(std::vector<std::string>::iterator i = user_index.begin(); i != user_index.end(); ++i){
        close(user_map[*i].socket_fd);
    }

    log_file.close();
}

void Message_router::local_msg_listener(){
    struct epoll_event tmp_event;
    struct user_item tmp_user_item;
    std::unordered_map<std::string, std::vector<struct message_item_t>>::iterator tmp_msg_map_iterator;
    std::unique_lock<std::mutex> tmp_lock(socket_mtx, std::defer_lock);
    std::unique_lock<std::mutex> tmp_lock_local_message_queue(*local_msg_queue_mtx, std::defer_lock);
    std::unique_lock<std::mutex> tmp_lock_if_continue(if_continue_mtx, std::defer_lock);

    Json::Value tmp_json_value;
    Json::FastWriter tmp_json_writer;
    Json::Reader tmp_json_reader;
    std::string tmp_string;
    
    struct local_msg_type_t tmp_local_message;
    struct message_item_t tmp_message;

    while(1){
        local_msg_queue_cv->wait(tmp_lock_local_message_queue);

        tmp_lock_if_continue.lock();
        if(!if_continue_tag)
            break;
        tmp_lock_if_continue.unlock();

        char type = local_msg_queue->front().type;
        if(type == LOCAL_MSG_TYPE_USER_LIST){
            tmp_json_reader.parse(local_msg_queue->front().name, tmp_json_value);
            all_users_index.clear();

            for(int i = 0; i < tmp_json_value["length"].asInt(); ++i){
                all_users_index.push_back(tmp_json_value[std::to_string(i)].asString());
            }

            local_msg_queue->pop();

        }else if(type == LOCAL_MSG_TYPE_USER_LOGIN){

            tmp_lock.lock();

            tmp_local_message.name = local_msg_queue->front().name;
            tmp_local_message.socket_fd = local_msg_queue->front().socket_fd;
            tmp_local_message.ssl_fd = local_msg_queue->front().ssl_fd;

            local_msg_queue->pop();

            tmp_event.events = EPOLLIN | EPOLLET | EPOLLRDHUP;
            tmp_event.data.fd = tmp_local_message.socket_fd;

            if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tmp_local_message.socket_fd, &tmp_event) < 0){
                std::unique_lock<std::mutex> tmp_lock2(log_file_mtx);
                log_file << now_time() << "\tWarning: can't add client " << tmp_local_message.name;
                log_file << '\t' << strerror(errno) << std::endl;

                close(tmp_local_message.socket_fd);
            }else{
                user_index.push_back(tmp_local_message.name);
                tmp_user_item.socket_fd = tmp_local_message.socket_fd;
                tmp_user_item.ssl_fd = tmp_local_message.ssl_fd;
                user_map[tmp_local_message.name] = tmp_user_item;

                user_rindex[tmp_local_message.socket_fd] = tmp_local_message.name;

                tmp_json_value.clear();
                tmp_json_value["receiver"] = tmp_local_message.name;
                tmp_json_value["sender"] = SERVER_NAME;
                tmp_json_value["type"] = MSG_TYPE_GET_USER_LIST;
                for(std::vector<std::string>::iterator i = all_users_index.begin(); i != all_users_index.end(); ++i){
                    tmp_json_value["content"].append(Json::Value(*i));
                }

                tmp_string = tmp_json_writer.write(tmp_json_value);

                tmp_message.receiver = tmp_local_message.name;
                tmp_message.sender = SERVER_NAME;
                tmp_message.type = MSG_TYPE_GET_USER_LIST;
                tmp_message.content = tmp_string;
                tmp_message.tried_num = 0;

                message_queue.push(tmp_message);

                tmp_msg_map_iterator= to_be_sent_message_map.find(tmp_local_message.name);
                if(tmp_msg_map_iterator != to_be_sent_message_map.end()){
                    for(auto tmp_iterator = tmp_msg_map_iterator->second.begin(); tmp_iterator != tmp_msg_map_iterator->second.end(); ++tmp_iterator){
                        message_queue.push(*tmp_iterator);
                    }

                    tmp_msg_map_iterator->second.clear();
                    to_be_sent_message_map.erase(tmp_local_message.name);
                }
                
                std::unique_lock<std::mutex> tmp_lock2(log_file_mtx);
                log_file << now_time() << "\tInfo: add client " << tmp_local_message.name << std::endl;
                log_file.flush();
            }

            tmp_lock.unlock();
        }
    }
}

char Message_router::get_success_tag(void){
    return this->success_tag;
}

void Message_router::set_if_continue_flag(void){
    std::unique_lock<std::mutex> tmp_lock_if_continue_flag(if_continue_mtx);

    if_continue_tag = false;

    return;
}

void Message_router::message_worker(void){
    std::unique_lock<std::mutex> tmp_lock_if_continue_tag(if_continue_mtx, std::defer_lock);
    std::unique_lock<std::mutex> tmp_lock_log_file(log_file_mtx, std::defer_lock);
    std::unique_lock<std::mutex> tmp_lock_socket(socket_mtx, std::defer_lock);
    //std::unique_lock<std::mutex> tmp_lock_message_queue(message_queue_mtx, std::defer_lock);
    epoll_event* tmp_epoll_event_ptr = nullptr;
    char data_buffer[MAX_BUFFER_SIZE];
    int tmp_status = 0;

    Json::Reader tmp_json_reader;
    Json::Value tmp_json_value;

    struct message_item_t tmp_message;

    int ready_num = 0;

    while(1){
        tmp_lock_if_continue_tag.lock();
        if(if_continue_tag == false){
            tmp_lock_if_continue_tag.unlock();
            break;
        }
        tmp_lock_if_continue_tag.unlock();

        tmp_lock_socket.lock();
        //std::cout << "worker start" << std::endl;

        memset(epoll_events, 0, MAX_SOCKET_NUM/2 * sizeof(epoll_event));
        memset(data_buffer, 0, MAX_BUFFER_SIZE);

        ready_num = epoll_wait(epoll_fd, epoll_events, MAX_SOCKET_NUM/2, EPOLL_TIMEOUT);
        if(ready_num == -1){
            tmp_lock_log_file.lock();
            log_file << now_time() << '\t' << "Warning: " << strerror(errno) << std::endl;
            log_file.flush();
            tmp_lock_log_file.unlock();
        }else if(ready_num > 0){
            //tmp_lock_message_queue.lock();
            tmp_epoll_event_ptr = epoll_events;

            for(int i = 0; i < ready_num; ++i){
                if((tmp_epoll_event_ptr->events & EPOLLRDHUP) || (tmp_epoll_event_ptr->events & EPOLLERR) || (tmp_epoll_event_ptr->events & EPOLLHUP)){
                    user_map[user_rindex[tmp_epoll_event_ptr->data.fd]].is_down = true;
                }else{
                    memset(data_buffer, 0, MAX_BUFFER_SIZE);
                    tmp_json_value.clear();

                    tmp_status = SSL_read(user_map[user_rindex[tmp_epoll_event_ptr->data.fd]].ssl_fd, data_buffer, MAX_BUFFER_SIZE);
                    //std::cout << "recv msg " << data_buffer << std::endl;
                    if(tmp_status < 0){
                        tmp_lock_log_file.lock();
                        log_file << now_time() << '\t' << "Warning: read socker error, " << strerror(errno) << std::endl;
                        log_file.flush();
                        tmp_lock_log_file.unlock();
                    }else{
                        tmp_status = tmp_json_reader.parse(data_buffer, data_buffer + tmp_status, tmp_json_value);
                        if(!tmp_status){
                            tmp_lock_log_file.lock();
                            log_file << now_time() << '\t' << "Warning: parse message from " << user_rindex[tmp_epoll_event_ptr->data.fd] << " error\n";
                            log_file << '\t' << data_buffer << std::endl;
                            log_file.flush();
                            tmp_lock_log_file.unlock();

                            --user_map[user_rindex[tmp_epoll_event_ptr->data.fd]].count_down;
                        }else{
                            tmp_message.receiver = tmp_json_value["receiver"].asString();
                            tmp_message.sender = tmp_json_value["sender"].asString();
                            tmp_message.type = tmp_json_value["type"].asString();
                            tmp_message.content = std::string(data_buffer);

                            message_queue.push(tmp_message);
                        }
                    }
                }

                ++tmp_epoll_event_ptr;
            }
            //tmp_lock_message_queue.unlock();
        }

        tmp_lock_socket.unlock();
        //std::cout << "worker end\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void Message_router::message_consumer(void){
    std::unique_lock<std::mutex> tmp_lock_if_continue_tag(if_continue_mtx, std::defer_lock);
    std::unique_lock<std::mutex> tmp_lock_log_file(log_file_mtx, std::defer_lock);
    std::unique_lock<std::mutex> tmp_lock_socket(socket_mtx, std::defer_lock);
    //std::unique_lock<std::mutex> tmp_lock_message_queue(message_queue_mtx, std::defer_lock);

    int tmp_status = 0;
    int tmp_message_to_handle = 0;
    char tmp_status_to_send = 0;
    std::string tmp_string;
    std::string tmp_message_type;

    struct message_item_t tmp_message;

    Json::FastWriter tmp_json_writer;
    Json::Reader tmp_json_reader;
    Json::Value tmp_json_value;

    std::unordered_map<std::string, struct user_item>::iterator tmp_user_map_iterator;
    //std::unordered_map<std::string, std::vector<std::unordered_map<char, std::string>>>::iterator tmp_msg_map_iterator;

    while(1){
        tmp_lock_if_continue_tag.lock();
        if(if_continue_tag == false){
            tmp_lock_if_continue_tag.unlock();
            break;
        }
        tmp_lock_if_continue_tag.unlock();

        //tmp_lock_message_queue.lock();
        //std::cout << "consumer start\n";
        tmp_lock_socket.lock();

        tmp_message_to_handle = message_queue.size();
        tmp_message_to_handle = tmp_message_to_handle > MESSAGE_NUM_LIMIT ? tmp_message_to_handle / 2 : tmp_message_to_handle;

        for(int i = 0; i < tmp_message_to_handle; ++i){

            tmp_message.sender = message_queue.front().sender;
            tmp_message.receiver = message_queue.front().receiver;
            tmp_message.type = message_queue.front().type;
            tmp_message.content = message_queue.front().content;
            tmp_message.tried_num = message_queue.front().tried_num;
            message_queue.pop();

            if(tmp_message.receiver != SERVER_NAME){
                //tmp_user_map_iterator = user_map.find(tmp_unordered_map['r']);

                if(user_map.count(tmp_message.receiver) > 0){

                    //std::cout << tmp_message.receiver << " to send exist\n" << tmp_message.content << std::endl;

                    tmp_status = SSL_write(user_map[tmp_message.receiver].ssl_fd, tmp_message.content.c_str(), tmp_message.content.length());
                    SSL_write(user_map[tmp_message.receiver].ssl_fd, MESSAGE_SPLIT, MESSAGE_SPLIT_SIZE);

                    user_map[tmp_message.sender].count_down += 1;
                    if(user_map[tmp_message.sender].count_down > CLIENT_ALIVE_TIME_SECONDS)
                        user_map[tmp_message.sender].count_down = CLIENT_ALIVE_TIME_SECONDS;

                    if(tmp_status <= 0){
                        tmp_lock_log_file.lock();
                        log_file << now_time() << '\t' << "Warning: send message to " << tmp_message.receiver << " failed due to ";
                        log_file << strerror(errno) << std::endl;
                        log_file.flush();
                        tmp_lock_log_file.unlock();

                        if(tmp_message.tried_num < 3){
                            tmp_message.tried_num = tmp_message.tried_num + 1;
                            message_queue.push(tmp_message);
                        }else{
                            to_be_sent_message_map[tmp_message.receiver].push_back(tmp_message);
                            user_map[tmp_message.sender].is_down = true;
                        }
                    }
                }else{
                    to_be_sent_message_map[tmp_message.receiver].push_back(tmp_message);
                }
            }else{
                //tmp_json_value.clear();
                //tmp_json_reader.parse(tmp_unordered_map['c'], tmp_json_value);
                tmp_message_type = tmp_message.type;

                if(tmp_message_type == MSG_TYPE_KEEPALIVE){
                    ++(user_map[tmp_message.sender].count_down);
                    if(user_map[tmp_message.sender].count_down > CLIENT_ALIVE_TIME_SECONDS)
                        user_map[tmp_message.sender].count_down = CLIENT_ALIVE_TIME_SECONDS;

                    //std::cout << "recv keepalive " << tmp_message.sender << '\n';
                }else if(tmp_message_type == MSG_TYPE_GET_USER_LIST){
                    //std::cout << "recv user list\n";
                    tmp_json_value.clear();
                    tmp_json_value["receiver"] = tmp_message.sender;
                    tmp_json_value["sender"] = SERVER_NAME;
                    tmp_json_value["type"] = MSG_TYPE_GET_USER_LIST;
                    for(std::vector<std::string>::iterator i = all_users_index.begin(); i != all_users_index.end(); ++i){
                        tmp_json_value["content"].append(Json::Value(*i));
                    }

                    tmp_string = tmp_json_writer.write(tmp_json_value);

                    tmp_status = SSL_write(user_map[tmp_message.sender].ssl_fd, tmp_string.c_str(), tmp_string.length());
                    send(user_map[tmp_message.sender].socket_fd, MESSAGE_SPLIT, MESSAGE_SPLIT_SIZE, 0);

                    //std::cout << tmp_string << std::endl;
                    if(tmp_status <= 0){
                        if(tmp_message.tried_num < 3){
                            tmp_message.tried_num = tmp_message.tried_num + 1;
                            message_queue.push(tmp_message);
                        }else{
                            tmp_lock_log_file.lock();
                            log_file << now_time() << '\t' << "Warning: can't send user list to ";
                            log_file << tmp_message.sender << std::endl;
                            log_file.flush();
                            tmp_lock_log_file.unlock();
                        }
                    }
                }
            }
        }
        //tmp_lock_message_queue.unlock();
        //std::cout << "consumer end\n";
        tmp_lock_socket.unlock();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void Message_router::cleaner(void){
    std::vector<std::string> tmp_to_be_closed_vector;
    std::vector<std::vector<std::string>::iterator> tmp_to_be_closed_vector_iterators;
    std::vector<std::vector<std::string>::iterator>::iterator tmp_iterator;
    std::unique_lock<std::mutex> tmp_lock_if_continue_tag(if_continue_mtx, std::defer_lock);
    std::unique_lock<std::mutex> tmp_lock_socket(socket_mtx, std::defer_lock);
    std::unique_lock<std::mutex> tmp_lock_log_file(log_file_mtx, std::defer_lock);
    struct user_item tmp_user_item;

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
        //std::cout << "cleaner start\n";

        for(std::vector<std::string>::iterator i = user_index.begin(); i != user_index.end(); ++i){
            tmp_user_item = user_map[*i];
            if(tmp_user_item.is_down == true || tmp_user_item.count_down < 0){
                tmp_to_be_closed_vector.push_back(*i);
                tmp_to_be_closed_vector_iterators.push_back(i);
            }else{
                user_map[*i].count_down -= 1;
            }
        }

        tmp_iterator = tmp_to_be_closed_vector_iterators.begin();
        for(std::vector<std::string>::iterator i = tmp_to_be_closed_vector.begin(); i != tmp_to_be_closed_vector.end(); ++i){
            tmp_user_item = user_map[*i];
            user_rindex.erase(tmp_user_item.socket_fd);
            user_map.erase(*i);
            user_index.erase(*tmp_iterator);

            close(tmp_user_item.socket_fd);

            tmp_lock_log_file.lock();
            log_file << now_time() << '\t' << "Warning: client " << *i << " closed\n";
            log_file.flush();
            tmp_lock_log_file.unlock();

            ++tmp_iterator;
        }

        tmp_lock_socket.unlock();
        //std::cout << "cleaner end\n";
        std::this_thread::sleep_for(std::chrono::seconds(CLEANER_START_INTERVAL_SECONDS));
    }
}

char* Message_router::now_time(void){
    tmp_now_time = std::chrono::system_clock::now();
    tmp_time_t = std::chrono::system_clock::to_time_t(tmp_now_time);
    return ctime(&tmp_time_t);
}
