#include "login.hpp"

struct aes_key_item_t* login::server_keys_ptr = nullptr;

SSL_CTX* login::ssl_ctx_fd = nullptr;
std::queue<local_msg_type_t>* login::local_msg_queue = nullptr;
std::mutex* login::local_msg_queue_mtx = nullptr;
std::condition_variable* login::local_msg_queue_cv = nullptr;

std::mutex login::continue_tag_mtx;
volatile bool login::continue_tag;
int login::listen_socket;

sqlite3* login::db_sqlite = nullptr;
sqlite3_stmt* login::db_sqlite_stmt = nullptr;
sqlite3_stmt* login::db_sqlite_stmt_get_userlist = nullptr;

std::ofstream login::log_file;
std::mutex login::write_log_mtx;

int login::epoll_fd;
struct epoll_event* login::ready_sockets_ptr = nullptr;

std::mutex login::socket_list_mtx;
std::vector<int> login::socket_catalogue;
std::unordered_map<int, client_socket_t> login::sockets;
std::vector<int> login::to_be_cleaned_val;
std::vector<unsigned short int> login::to_be_cleaned_pos;

std::time_t login::tmp_time_t;
std::chrono::system_clock::time_point login::tmp_now_time;

login::login(SSL_CTX* tmp_ssl_ctx_fd, std::condition_variable* tmp_local_msg_queue_cv = nullptr, std::mutex* tmp_local_msg_queue_mtx = nullptr, std::queue<local_msg_type_t>* tmp_local_msg_queue = nullptr){
    ssl_ctx_fd = tmp_ssl_ctx_fd;
    local_msg_queue = tmp_local_msg_queue;
    local_msg_queue_mtx = tmp_local_msg_queue_mtx;
    local_msg_queue_cv = tmp_local_msg_queue_cv;

    server_keys_ptr = new(struct aes_key_item_t[json_config["login"]["aes_server_key_num"].asInt()]);
    ready_sockets_ptr = new(epoll_event[json_config["login"]["max_ready_socket_num"].asInt()]);
    
    listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if(listen_socket < 0){
        this->success_tag = -1;
        std::cout << strerror(errno) << std::endl;
        return;
    }

    struct sockaddr_in myaddr;
    memset(&myaddr, 0, sizeof(myaddr));
    myaddr.sin_family = AF_INET;
    myaddr.sin_port = htons(json_config["login"]["listen_port"].asInt());
    myaddr.sin_addr.s_addr = INADDR_ANY;

    if(bind(listen_socket, (const struct sockaddr*)&myaddr, sizeof(myaddr)) == -1){
        this->success_tag = -2;
        std::cout << strerror(errno) << std::endl;
        return;
    }

    this->success_tag = 0;
    
    memset(ready_sockets_ptr, 0, json_config["login"]["max_ready_socket_num"].asInt()*sizeof(epoll_event));
    continue_tag = true;
    
    log_file.open(json_config["login"]["log_file_path"].asString(), std::ofstream::out| std::ofstream::app);
    if(!log_file.is_open())
        this->success_tag = -7;

    return;
}

login::~login(){
    for(std::vector<int>::iterator it = socket_catalogue.begin(); it != socket_catalogue.end(); ++it){
        SSL_shutdown(sockets[*it].ssl_fd);
        SSL_free(sockets[*it].ssl_fd);
        
        close(*it);
    }

    delete [] server_keys_ptr;
    delete [] ready_sockets_ptr;
    
    log_file.close();
    close(epoll_fd);
    close(listen_socket);
    db_close();
}

char login::get_tag(void){
    return this->success_tag;
}

void login::set_continue_tag(bool tmp_tag){
    continue_tag_mtx.lock();
    continue_tag = false;
    continue_tag_mtx.unlock();
}

bool login::db_open(){
    int status = sqlite3_open_v2(json_config["login"]["sqlite_file_path"].asCString(), &db_sqlite, SQLITE_OPEN_READWRITE, NULL);

    if(status != SQLITE_OK){
        std::cout << "ERROR: can't open sqlite database\n";
        std::cout << '\t' << sqlite3_errmsg(db_sqlite) << std::endl;

        return false;
    }

    return true;
}

bool login::db_init(){
    int status = sqlite3_prepare_v2(db_sqlite, json_config["login"]["sql_to_exec_get_passwd"].asCString(), strlen(json_config["login"]["sql_to_exec_get_passwd"].asCString()), &db_sqlite_stmt, nullptr);
    
    if(status != SQLITE_OK){
        std::cout << "ERROR: can't init sqlite database\n";
        std::cout << '\t' << sqlite3_errmsg(db_sqlite) << std::endl;

        return false;
    }

    status = sqlite3_prepare_v2(db_sqlite, json_config["login"]["sql_to_exec_get_all_users"].asCString(), strlen(json_config["login"]["sql_to_exec_get_all_users"].asCString()), &db_sqlite_stmt_get_userlist, nullptr);
    if(status != SQLITE_OK){
        std::cout << "ERROR: can't init sqlite database\n";
        std::cout << '\t' << sqlite3_errmsg(db_sqlite) << std::endl;

        return false;
    }

    return true;
}

bool login::db_if_opened(){
    return true;
}

std::string login::db_get_userlist(){
    sqlite3_reset(db_sqlite_stmt_get_userlist);

    static Json::FastWriter tmp_json_writer;
    static Json::Value tmp_json_value;

    tmp_json_value.clear();

    int user_num = 0;

    std::string tmp_string;
    int status = sqlite3_step(db_sqlite_stmt_get_userlist);

    while(status == SQLITE_ROW){
        tmp_json_value[std::to_string(user_num++)] = std::string((const char*)sqlite3_column_text(db_sqlite_stmt_get_userlist, 0));

        status = sqlite3_step(db_sqlite_stmt_get_userlist);
    }

    tmp_json_value["length"] = user_num;
    tmp_string = tmp_json_writer.write(tmp_json_value);

    return tmp_string;
}

bool login::db_verify(const char* name, const char* passwd){
    sqlite3_reset(db_sqlite_stmt);
    sqlite3_bind_text(db_sqlite_stmt, 1, name, strlen(name), NULL);

    int status = sqlite3_step(db_sqlite_stmt);
    if(status == SQLITE_ROW || status == SQLITE_DONE){
        const unsigned char* tmp_char_ptr = sqlite3_column_text(db_sqlite_stmt, 0);

        if(tmp_char_ptr == nullptr){
            return false;
        }else{
            status = memcmp(passwd, tmp_char_ptr, sizeof(passwd));
            if(status == 0){
                return true;
            }
        }
    }else if(status == SQLITE_ERROR){
        write_log_mtx.lock();
        log_file << login::now_time() << '\t' << "ERROR: can't get data from sqlite\n";
    }

    return false;
}

void login::db_close(void){
    sqlite3_finalize(db_sqlite_stmt);
    sqlite3_close_v2(db_sqlite);
}

void login::send_userlist_to_server(){
    struct local_msg_type_t tmp_local_msg;

    tmp_local_msg.type = LOCAL_MSG_TYPE_USER_LIST;
    tmp_local_msg.ssl_fd = nullptr;
    tmp_local_msg.socket_fd = 0;
    tmp_local_msg.name = db_get_userlist();

    local_msg_queue_mtx->lock();
    local_msg_queue->push(tmp_local_msg);
    local_msg_queue_mtx->unlock();
    local_msg_queue_cv->notify_all();
}

void login::init(){
    epoll_fd = epoll_create(json_config["login"]["max_socket_num"].asInt());
    //std::cout << "Epoll_fd: " << epoll_fd << std::endl;

    if(fcntl(listen_socket, F_SETFL, fcntl(listen_socket, F_GETFL, 0) | O_NONBLOCK) < 0){
        this->success_tag = -4;
        std::cout << strerror(errno) << std::endl;
        return;
    }

    if(listen(listen_socket, json_config["login"]["listen_queue_max_num"].asInt()) < 0){
        this->success_tag = -5;
        std::cout << strerror(errno) << std::endl;
        return;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLET;
    ev.data.fd = listen_socket;
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_socket, &ev) < 0){
        this->success_tag = -6;
        std::cout << strerror(errno) << std::endl;
        std::cout << epoll_fd << '\t' << listen_socket << std::endl;
        return;
    }

    log_file << now_time() << '\t' << "Info: init socket and epoll successfully\n";

    if(!(db_open() && db_init())){
        this->success_tag = -8;
        return;
    }

    log_file << now_time() << '\t' << "Info: open database successfully\n";

    std::ifstream server_keys_file(json_config["login"]["aes_server_key_file"].asString(), std::ifstream::in | std::ifstream::binary);
    if(!server_keys_file.is_open()){
        std::cout << "ERROR: can't open server key file\n";
        this->success_tag = -9;
        return;
    }
    server_keys_file.read((char*)server_keys_ptr, json_config["login"]["aes_server_key_num"].asInt()*sizeof(struct aes_key_item_t));
    if(!server_keys_file){
        std::cout << "ERROR: can't read from server key file\n";
        this->success_tag = -10;
        return;
    }
    log_file << "Info: get server keys successfuly\n";

    this->success_tag = 0;
    return;
}

void login::listener(void){
    int tmp_socket_num = 0;
    struct epoll_event tmp_event;
    int tmp_socket = 0;
    struct sockaddr_in tmp_sockaddr;
    struct client_socket_t tmp_client_socket;
    int tmp_num = 0;
    int tmp_num_2 = 0;
    socklen_t sock_addr_length = sizeof(struct sockaddr);

    Json::Reader tmp_json_reader;
    Json::Value tmp_json_value;
    char recv_buf[json_config["login"]["recv_buffer_max_length"].asInt()];
    std::string tmp_string_recv_all_msg;
    std::string tmp_string_recv_part_msg;
    ProcessMsg tmp_process_msg(server_keys_ptr[0].key, server_keys_ptr[0].iv);

    unsigned short int msg_length;
    char openssl_err_buf[30];

    int status = 0;
    SSL* tmp_ssl_fd = nullptr;
    struct local_msg_type_t tmp_local_msg;

    bool tmp_status = false;

    int max_ready_socket_num = json_config["login"]["max_ready_socket_num"].asInt();
    int epoll_wait_timeout = json_config["login"]["epoll_wait_time_out"].asInt();
    int listen_queue_max_num = json_config["login"]["listen_queue_max_num"].asInt();
    int recv_buffer_max_length = json_config["login"]["recv_buffer_max_length"].asInt();

    while(1){                            //ATTENTION!!!!!!!!
        continue_tag_mtx.lock();
        if(continue_tag == false){
            continue_tag_mtx.unlock();
            break;
        }
        continue_tag_mtx.unlock();
        
        socket_list_mtx.lock();

        memset(ready_sockets_ptr, 0, max_ready_socket_num*sizeof(epoll_event));
        tmp_socket_num = epoll_wait(epoll_fd, ready_sockets_ptr, max_ready_socket_num, epoll_wait_timeout);
        
        if(tmp_socket_num == -1){
            write_log_mtx.lock();
            log_file << now_time() << '\t' << "Warning: epoll_wait return -1, errno is " << errno << std::endl;
            write_log_mtx.unlock();
            continue;

        }
        if(tmp_socket_num > 0){
            for(tmp_num = 0; tmp_num < tmp_socket_num; ++tmp_num){

                if((ready_sockets_ptr[tmp_num].events & EPOLLERR) || !(ready_sockets_ptr[tmp_num].events & EPOLLIN)){
                    write_log_mtx.lock();
                    log_file << now_time() << '\t' << "Warning: socket error\n";
                    write_log_mtx.unlock();
                    continue;
                }else if(ready_sockets_ptr[tmp_num].events & EPOLLRDHUP){   //socket被客户端关闭
                    tmp_socket = ready_sockets_ptr[tmp_num].data.fd;

                    write_log_mtx.lock();
                    log_file << now_time() << '\t' << "Warning: " << inet_ntoa(sockets[tmp_socket].addr) << " close itself\n";
                    write_log_mtx.unlock();
                    
                    sockets[tmp_socket].is_closed = true;
                    continue;
                }
                
                if(ready_sockets_ptr[tmp_num].data.fd == listen_socket){  //信息来自监听socket
                    //std::cout << "Listener accept socket\n";
                    for(tmp_num_2 = 0; tmp_num_2 < listen_queue_max_num; ++tmp_num_2){
                        tmp_socket = accept(listen_socket, (sockaddr*)&tmp_sockaddr, &sock_addr_length);
                        if(tmp_socket == -1 )
                            break;

                        tmp_ssl_fd = SSL_new(ssl_ctx_fd);
                        SSL_set_fd(tmp_ssl_fd, tmp_socket);
                        status = SSL_accept(tmp_ssl_fd);

                        if(status != 1){
                            memset(openssl_err_buf, 0, sizeof(openssl_err_buf));
                            write_log_mtx.lock();
                            log_file << now_time() << '\t' << "ERROR: connection from " << inet_ntoa(tmp_sockaddr.sin_addr);
                            log_file << " can't establish SSL connect\n";
                            log_file << '\t' << ERR_error_string(SSL_get_error(tmp_ssl_fd, status), openssl_err_buf) << std::endl;
                            write_log_mtx.unlock();

                            ERR_print_errors_fp(stderr);

                            SSL_shutdown(tmp_ssl_fd);
                            SSL_free(tmp_ssl_fd);
                            close(tmp_socket);
                        }else{
                            write_log_mtx.lock();
                            log_file << now_time() << '\t' << "Info: new connection " << inet_ntoa(tmp_sockaddr.sin_addr) << std::endl;
                            write_log_mtx.unlock();

                            tmp_event.events = EPOLLIN | EPOLLRDHUP | EPOLLET;
                            tmp_event.data.fd = tmp_socket;
                            if(fcntl(tmp_socket, F_SETFL, fcntl(tmp_socket, F_GETFL, 0) | O_NONBLOCK) == -1){
                                write_log_mtx.lock();
                                log_file << now_time() << '\t' << "Warning: can't add socket to list, errno is " << errno << std::endl;
                                write_log_mtx.unlock();
                                close(tmp_socket);
                                continue;
                            }

                            if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tmp_socket, &tmp_event) == -1){
                                write_log_mtx.lock();
                                log_file << now_time() << '\t' << "Warning: can't add socket to list, errno is " << errno << std::endl;
                                write_log_mtx.unlock();
                                close(tmp_socket);
                                continue;
                            }

                            memset(&tmp_client_socket, 0, sizeof(client_socket_t));
                            tmp_client_socket.socket = tmp_socket;
                            tmp_client_socket.ssl_fd = tmp_ssl_fd;

                            socket_catalogue.insert(socket_catalogue.end(), tmp_socket);
                            sockets.emplace(tmp_socket, tmp_client_socket);
                            sockets[tmp_socket].addr.s_addr = tmp_sockaddr.sin_addr.s_addr;

                            write_log_mtx.lock();
                            log_file << now_time() << '\t' << "Info: add connection successfully\n";
                            write_log_mtx.unlock();
                        }

                    }
                }else{  //信息来自连接的客户端socket
                    tmp_socket = ready_sockets_ptr[tmp_num].data.fd;
                    memset(recv_buf, 0, recv_buffer_max_length);

                    msg_length = SSL_read(sockets[tmp_socket].ssl_fd, recv_buf, recv_buffer_max_length);
                    // for(int i = 0; i < 5 && msg_length <= 0; ++i){
                    //     msg_length = SSL_get_error(sockets[tmp_socket].ssl_fd, msg_length);
                    //     if(msg_length == SSL_ERROR_WANT_READ || msg_length == SSL_ERROR_WANT_WRITE){
                    //         msg_length = SSL_read(sockets[tmp_socket].ssl_fd, &tmp_login_msg, sizeof(login_message_t));
                    //         continue;
                    //     }else{
                    //         break;
                    //     }
                    // }
                    
                    if(msg_length <= 0 || !tmp_json_reader.parse(recv_buf, recv_buf + msg_length, tmp_json_value)){
                        write_log_mtx.lock();
                        log_file << now_time() << '\t' << "Warning: failed to receive valid msg from " << inet_ntoa(sockets[tmp_socket].addr) << std::endl;
                        write_log_mtx.unlock();

                        //sockets[ready_sockets[tmp_num].data.fd].mtx.lock();
                        sockets[tmp_socket].tried_time += 1;
                        sockets[tmp_socket].time += 1;
                        //sockets[ready_sockets[tmp_num].data.fd].mtx.unlock();

                        continue;
                    }else{
                        tmp_num_2 = tmp_json_value["value"].asInt();
                        tmp_string_recv_all_msg = tmp_json_value["info"].asString();

                        tmp_process_msg.AES_256_change_key(server_keys_ptr[tmp_num_2].key, server_keys_ptr[tmp_num_2].iv);
                        tmp_process_msg.AES_256_process(tmp_string_recv_all_msg.data(), tmp_string_recv_all_msg.length(), 0);
                        if(!tmp_process_msg.ifValid()){
                            write_log_mtx.lock();
                            log_file << now_time() << '\t' << "Warning: failed to decrypt msg from " << inet_ntoa(sockets[tmp_socket].addr) << std::endl;
                            write_log_mtx.unlock();

                            //sockets[ready_sockets[tmp_num].data.fd].mtx.lock();
                            sockets[tmp_socket].tried_time += 1;
                            sockets[tmp_socket].time += 1;
                            //sockets[ready_sockets[tmp_num].data.fd].mtx.unlock();

                            continue;
                        }else{
                            tmp_string_recv_all_msg = std::string((const char*)tmp_process_msg.get_result(), tmp_process_msg.get_result_length());
                        }

                        if(!tmp_json_reader.parse(tmp_string_recv_all_msg, tmp_json_value)){
                            write_log_mtx.lock();
                            log_file << now_time() << '\t' << "Warning: failed to receive valid login msg from " << inet_ntoa(sockets[tmp_socket].addr) << std::endl;
                            write_log_mtx.unlock();

                            //sockets[ready_sockets[tmp_num].data.fd].mtx.lock();
                            sockets[tmp_socket].tried_time += 1;
                            sockets[tmp_socket].time += 1;
                            //sockets[ready_sockets[tmp_num].data.fd].mtx.unlock();

                            continue;
                        }else{
                            tmp_string_recv_all_msg = tmp_json_value["username"].asString();
                            tmp_string_recv_part_msg = tmp_json_value["passwd"].asString();
                        }

                        if(!db_if_opened()){
                            continue_tag = false;
                            char data = -3;
                            send(tmp_socket, &data, 1, 0);
                        }else{
                            tmp_status = db_verify(tmp_string_recv_all_msg.data(), tmp_string_recv_part_msg.data());

                            if(!tmp_status){
                                sockets[tmp_socket].tried_time += 1;
                                sockets[tmp_socket].time += 1;
                                
                                write_log_mtx.lock();
                                log_file << now_time() << '\t' << "Info: user "  << tmp_string_recv_all_msg << " from " << inet_ntoa(sockets[tmp_socket].addr) << " authorized failed\n";
                                write_log_mtx.unlock();

                                char data = -1;
                                SSL_write(sockets[tmp_socket].ssl_fd, &data, 1);
                            }else{
                                write_log_mtx.lock();
                                log_file << now_time() << '\t' << "Info: user "  << tmp_string_recv_all_msg << " from " << inet_ntoa(sockets[tmp_socket].addr) << " authorized successfully\n";
                                write_log_mtx.unlock();

                                char data = 0;
                                SSL_write(sockets[tmp_socket].ssl_fd, &data, 1);

                                tmp_local_msg.type = LOCAL_MSG_TYPE_USER_LOGIN;
                                tmp_local_msg.name = tmp_string_recv_all_msg;
                                tmp_local_msg.socket_fd = tmp_socket;
                                tmp_local_msg.ssl_fd = sockets[tmp_socket].ssl_fd;

                                local_msg_queue_mtx->lock();
                                local_msg_queue->push(tmp_local_msg);
                                local_msg_queue_mtx->unlock();
                                local_msg_queue_cv->notify_all();

                                std::vector<int>::iterator i = socket_catalogue.begin();
                                for(i; i != socket_catalogue.end(); ++i){
                                    if(*i == tmp_socket)
                                        break;
                                }
                                socket_catalogue.erase(i);
                                sockets.erase(tmp_socket);
                                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, tmp_socket, NULL);
                            }
                        }
                    }
                }
            }
        }
        write_log_mtx.lock();
        log_file.flush();
        write_log_mtx.unlock();

        socket_list_mtx.unlock();
        std::this_thread::sleep_for(std::chrono::seconds(1));
        //std::cout << now_time() << "    listener  " << tmp_socket_num << std::endl;
    }
}

void login::cleaner(void){
    unsigned short int order_tmp = 0;
    int socket_tmp = 0;

    int socket_max_alive_time = json_config["login"]["socket_max_alive_time"].asInt();
    int login_max_try_time = json_config["login"]["login_max_try_time"].asInt();

    while(1){                   //ATTENTION!!!!!!!
        continue_tag_mtx.lock();
        if(continue_tag == false){
            continue_tag_mtx.unlock();
            break;
        }
        continue_tag_mtx.unlock();

        socket_list_mtx.lock();
        to_be_cleaned_val.clear();
        to_be_cleaned_pos.clear();

        for(order_tmp = 0; order_tmp < socket_catalogue.size(); ++order_tmp){
            socket_tmp = socket_catalogue[order_tmp];
            if(sockets[socket_tmp].time > socket_max_alive_time || sockets[socket_tmp].tried_time > login_max_try_time || sockets[socket_tmp].is_closed == true){
                to_be_cleaned_val.push_back(socket_tmp);
                to_be_cleaned_pos.push_back(order_tmp);
            }
            ++sockets[socket_tmp].time;
        }
    
        for(order_tmp = 0; order_tmp < to_be_cleaned_val.size(); ++order_tmp){
            socket_tmp = to_be_cleaned_val[order_tmp];
            
            write_log_mtx.lock();
            log_file << now_time() << '\t' << "Warning: " << inet_ntoa(sockets[socket_tmp].addr) << " closed\n";
            write_log_mtx.unlock();

            SSL_shutdown(sockets[socket_tmp].ssl_fd);
            SSL_free(sockets[socket_tmp].ssl_fd);

            socket_catalogue.erase(socket_catalogue.begin() + to_be_cleaned_pos[order_tmp] - 1);
            sockets.erase(socket_tmp);

            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, socket_tmp, NULL);
            close(socket_tmp);
        }

        socket_list_mtx.unlock();
        std::this_thread::sleep_for(std::chrono::seconds(1));
        //std::cout << now_time() << "    cleaner\n";
    }
}

char* login::now_time(void){
    tmp_now_time = std::chrono::system_clock::now();
    tmp_time_t = std::chrono::system_clock::to_time_t(tmp_now_time);
    return ctime(&tmp_time_t);
}
