#include "message_router.hpp"

static mysqlpp::Connection mysql_connection;

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
std::queue<std::unordered_map<char, std::string>> Message_router::message_queue;
std::unordered_map<std::string, std::vector<std::unordered_map<char, std::string>>> Message_router::to_be_sent_message_map;

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

    mysqlpp::Connection conn(false);
    bool status = conn.connect(DB_NAME, DB_SERVER, DB_USER_NAME, DB_PASSWORD, DB_PORT);
    if(!status){
        this->success_tag = -3;
        return;
    }

    std::string tmp_string = "select name from ";
    tmp_string += DB_TABLE;
    mysqlpp::StoreQueryResult tmp_query_result = conn.query(tmp_string.c_str()).store();
    if(tmp_query_result.num_rows() == 0){
        this->success_tag = -4;
        return;
    }

    for(int i = 0; i < tmp_query_result.num_rows(); ++i){
        all_users_index.push_back(std::string(tmp_query_result[i]["name"].c_str()));
    }

    conn.disconnect();

    if_continue_tag = true;
    this->success_tag = 0;
}

Message_router::~Message_router(){
    close(epoll_fd);

    for(std::vector<std::string>::iterator i = user_index.begin(); i != user_index.end(); ++i){
        close(user_map[*i].socket_fd);
    }
}

bool Message_router::add_socket(const char* name, const int& socket_fd){
    struct epoll_event tmp_event;
    struct user_item tmp_user_item;
    std::unordered_map<std::string, std::vector<std::unordered_map<char, std::string>>>::iterator tmp_msg_map_iterator;
    std::unique_lock<std::mutex> tmp_lock(socket_mtx);
    //std::unique_lock<std::mutex> tmp_lock_msg(message_queue_mtx);

    tmp_event.events = EPOLLIN | EPOLLET;
    tmp_event.data.fd = socket_fd;

    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket_fd, &tmp_event) < 0){
        std::unique_lock<std::mutex> tmp_lock2(log_file_mtx);
        log_file << now_time() << "\tWarning: can't add client " << name;
        log_file << '\t' << strerror(errno) << std::endl;

        close(socket_fd);
        return false;
    }else{
        user_index.push_back(std::string(name));
        tmp_user_item.socket_fd = socket_fd;
        user_map[std::string(name)] = tmp_user_item;

        user_rindex[socket_fd] = std::string(name);


        static Json::Value tmp_json_value;
        static Json::FastWriter tmp_json_writer;
        static std::string tmp_string;
        static std::unordered_map<char, std::string> tmp_unordered_map;

        tmp_unordered_map.clear();
        tmp_json_value.clear();
        tmp_json_value["receiver"] = name;
        tmp_json_value["sender"] = SERVER_NAME;
        tmp_json_value["type"] = MSG_TYPE_GET_USER_LIST;
        for(std::vector<std::string>::iterator i = all_users_index.begin(); i != all_users_index.end(); ++i){
            tmp_json_value["content"].append(Json::Value(*i));
        }

        tmp_string = tmp_json_writer.write(tmp_json_value);

        tmp_unordered_map['r'] = name;
        tmp_unordered_map['s'] = SERVER_NAME;
        tmp_unordered_map['t'] = MSG_TYPE_GET_USER_LIST;
        tmp_unordered_map['c'] = tmp_string;
        tmp_unordered_map['l'] = "0";

        message_queue.push(tmp_unordered_map);

        tmp_msg_map_iterator= to_be_sent_message_map.find(name);
        if(tmp_msg_map_iterator != to_be_sent_message_map.end()){
            for(auto tmp_iterator = tmp_msg_map_iterator->second.begin(); tmp_iterator != tmp_msg_map_iterator->second.end(); ++tmp_iterator){
                message_queue.push(*tmp_iterator);
            }

            tmp_msg_map_iterator->second.clear();
            to_be_sent_message_map.erase(name);
        }
        
        std::unique_lock<std::mutex> tmp_lock2(log_file_mtx);
        log_file << now_time() << "\tInfo: add client " << name << std::endl;
        log_file.flush();
    }
    return true;
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

    std::string tmp_message_receiver;
    std::string tmp_message_sender;
    std::string tmp_message_type;
    std::string tmp_message_content;
    Json::Reader tmp_json_reader;
    Json::Value tmp_json_value;

    std::unordered_map<char, std::string> tmp_unordered_map;

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

                    tmp_status = recv(tmp_epoll_event_ptr->data.fd, data_buffer, MAX_BUFFER_SIZE, 0);
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
                            tmp_message_receiver = tmp_json_value["receiver"].asString();
                            tmp_message_sender = tmp_json_value["sender"].asString();
                            tmp_message_type = tmp_json_value["type"].asString();
                            tmp_message_content = std::string(data_buffer);

                            tmp_unordered_map.clear();
                            tmp_unordered_map['r'] = tmp_message_receiver;
                            tmp_unordered_map['s'] = tmp_message_sender;
                            tmp_unordered_map['t'] = tmp_message_type;
                            tmp_unordered_map['c'] = tmp_message_content;
                            tmp_unordered_map['l'] = "0";

                            message_queue.push(tmp_unordered_map);
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
    std::unordered_map<char, std::string> tmp_unordered_map;
    std::unique_lock<std::mutex> tmp_lock_if_continue_tag(if_continue_mtx, std::defer_lock);
    std::unique_lock<std::mutex> tmp_lock_log_file(log_file_mtx, std::defer_lock);
    std::unique_lock<std::mutex> tmp_lock_socket(socket_mtx, std::defer_lock);
    //std::unique_lock<std::mutex> tmp_lock_message_queue(message_queue_mtx, std::defer_lock);

    int tmp_status = 0;
    int tmp_message_to_handle = 0;
    char tmp_status_to_send = 0;
    std::string tmp_string;
    std::string tmp_message_type;

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
            tmp_unordered_map = message_queue.front();
            message_queue.pop();

            if(tmp_unordered_map['r'] != SERVER_NAME){
                //tmp_user_map_iterator = user_map.find(tmp_unordered_map['r']);

                if(user_map.count(tmp_unordered_map['r']) > 0){

                    //std::cout << tmp_unordered_map['r'] << " to send exist\n";
                    //std::cout << user_map[tmp_unordered_map['r']].count_down << '\t' << user_map[tmp_unordered_map['r']].socket_fd << std::endl;

                    tmp_status = send(user_map[tmp_unordered_map['r']].socket_fd, tmp_unordered_map['c'].c_str(), tmp_unordered_map['c'].length(), 0);
                    send(user_map[tmp_unordered_map['r']].socket_fd, MESSAGE_SPLIT, MESSAGE_SPLIT_SIZE, 0);

                    user_map[tmp_unordered_map['s']].count_down += 1;
                    if(user_map[tmp_unordered_map['s']].count_down > CLIENT_ALIVE_TIME_SECONDS)
                        user_map[tmp_unordered_map['s']].count_down = CLIENT_ALIVE_TIME_SECONDS;

                    if(tmp_status <= 0){
                        tmp_lock_log_file.lock();
                        log_file << now_time() << '\t' << "Warning: send message to " << tmp_unordered_map['r'] << " failed due to ";
                        log_file << strerror(errno) << std::endl;
                        log_file.flush();
                        tmp_lock_log_file.unlock();

                        if(std::stoi(tmp_unordered_map['l']) < 3){
                            tmp_unordered_map['l'] = std::to_string(std::stoi(tmp_unordered_map['l']) + 1);
                            message_queue.push(tmp_unordered_map);
                        }else{
                            to_be_sent_message_map[tmp_unordered_map['r']].push_back(tmp_unordered_map);
                            user_map[tmp_unordered_map['s']].is_down = true;
                        }
                    }
                }else{
                    to_be_sent_message_map[tmp_unordered_map['r']].push_back(tmp_unordered_map);
                }
            }else{
                //tmp_json_value.clear();
                //tmp_json_reader.parse(tmp_unordered_map['c'], tmp_json_value);
                tmp_message_type = tmp_unordered_map['t'];

                if(tmp_message_type == MSG_TYPE_KEEPALIVE){
                    ++(user_map[tmp_unordered_map['s']].count_down);
                    if(user_map[tmp_unordered_map['s']].count_down > CLIENT_ALIVE_TIME_SECONDS)
                        user_map[tmp_unordered_map['s']].count_down = CLIENT_ALIVE_TIME_SECONDS;

                    //std::cout << "recv keepalive " << tmp_unordered_map['s'] << '\t' << user_map[tmp_unordered_map['s']].count_down << '\n';
                }else if(tmp_message_type == MSG_TYPE_GET_USER_LIST){
                    //std::cout << "recv user list\n";
                    tmp_json_value.clear();
                    tmp_json_value["receiver"] = tmp_unordered_map['s'];
                    tmp_json_value["sender"] = SERVER_NAME;
                    tmp_json_value["type"] = MSG_TYPE_GET_USER_LIST;
                    for(std::vector<std::string>::iterator i = all_users_index.begin(); i != all_users_index.end(); ++i){
                        tmp_json_value["content"].append(Json::Value(*i));
                    }

                    tmp_string = tmp_json_writer.write(tmp_json_value);

                    tmp_status = send(user_map[tmp_unordered_map['s']].socket_fd, tmp_string.c_str(), tmp_string.length(), 0);
                    send(user_map[tmp_unordered_map['s']].socket_fd, MESSAGE_SPLIT, MESSAGE_SPLIT_SIZE, 0);

                    //std::cout << tmp_string << std::endl;
                    if(tmp_status <= 0){
                        if(std::stoi(tmp_unordered_map['l']) < 3){
                            tmp_unordered_map['l'] = std::to_string(std::stoi(tmp_unordered_map['l']) + 1);
                            message_queue.push(tmp_unordered_map);
                        }else{
                            tmp_lock_log_file.lock();
                            log_file << now_time() << '\t' << "Warning: can't send user list to ";
                            log_file << tmp_unordered_map['s'] << std::endl;
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
