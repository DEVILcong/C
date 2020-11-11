#include "login.hpp"

Message_router* login::mr_ptr;

std::mutex login::continue_tag_mtx;
volatile bool login::continue_tag;
int login::listen_socket;

mysqlpp::Connection login::conn(false);

std::ofstream login::log_file;
std::mutex login::write_log_mtx;

int login::epoll_fd;
struct epoll_event login::ready_sockets[MAX_READY_SOCKET_NUM];

std::mutex login::socket_list_mtx;
std::vector<int> login::socket_catalogue;
std::unordered_map<int, client_socket_t> login::sockets;
std::vector<int> login::to_be_cleaned_val;
std::vector<unsigned short int> login::to_be_cleaned_pos;

std::time_t login::tmp_time_t;
std::chrono::system_clock::time_point login::tmp_now_time;

login::login(Message_router* tmp_mr_ptr){
    listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if(listen_socket < 0){
        this->success_tag = -1;
        std::cout << strerror(errno) << std::endl;
        return;
    }

    struct sockaddr_in myaddr;
    memset(&myaddr, 0, sizeof(myaddr));
    myaddr.sin_family = AF_INET;
    myaddr.sin_port = htons(LISTEN_PORT);
    myaddr.sin_addr.s_addr = INADDR_ANY;

    if(bind(listen_socket, (const struct sockaddr*)&myaddr, sizeof(myaddr)) == -1){
        this->success_tag = -2;
        std::cout << strerror(errno) << std::endl;
        return;
    }

    this->success_tag = 0;
    
    memset(ready_sockets, 0, MAX_READY_SOCKET_NUM*sizeof(epoll_event));
    continue_tag = true;
    
    log_file.open(LOG_FILE_PATH, std::ofstream::out| std::ofstream::app);
    if(!log_file.is_open())
        this->success_tag = -7;

    //std::cout << "Socket: " << listen_socket << std::endl;
    
    mr_ptr = tmp_mr_ptr;
    return;
}

login::~login(){
    for(std::vector<int>::iterator it = socket_catalogue.begin(); it != socket_catalogue.end(); ++it)
        close(*it);

    close(epoll_fd);
    close(listen_socket);
    conn.disconnect();
}

char login::get_tag(void){
    return this->success_tag;
}

void login::set_continue_tag(bool tmp_tag){
    continue_tag_mtx.lock();
    continue_tag = false;
    continue_tag_mtx.unlock();
}

void login::init(){
    epoll_fd = epoll_create(MAX_SOCKET_NUM);
    //std::cout << "Epoll_fd: " << epoll_fd << std::endl;

    if(fcntl(listen_socket, F_SETFL, fcntl(listen_socket, F_GETFL, 0) | O_NONBLOCK) < 0){
        this->success_tag = -4;
        std::cout << strerror(errno) << std::endl;
        return;
    }

    if(listen(listen_socket, MAX_LISTEN_QUEUE) < 0){
        this->success_tag = -5;
        std::cout << strerror(errno) << std::endl;
        return;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = listen_socket;
    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_socket, &ev) < 0){
        this->success_tag = -6;
        std::cout << strerror(errno) << std::endl;
        std::cout << epoll_fd << '\t' << listen_socket << std::endl;
        return;
    }

    log_file << now_time() << '\t' << "Info: init socket and epoll successfully\n";

    if(!conn.connect(MYSQL_DB, MYSQL_SERVER, MYSQL_USER, MYSQL_PASS, MYSQL_PORT_ME)){
        this->success_tag = -8;
        std::cout << strerror(errno) << std::endl;
        return;
    }

    log_file << now_time() << '\t' << "Info: connect to MySql server successfully\n";

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

    std::string to_query = "select password from ";
    to_query += MYSQL_TABLE;
    to_query += " where name=\'";
    mysqlpp::StoreQueryResult tmp_query_result;

    struct login_message_t tmp_login_msg;
    unsigned short int msg_length;

    mysqlpp::Query query = conn.query();


    while(1){                            //ATTENTION!!!!!!!!
        continue_tag_mtx.lock();
        if(continue_tag == false){
            continue_tag_mtx.unlock();
            break;
        }
        continue_tag_mtx.unlock();
        
        socket_list_mtx.lock();

        memset(ready_sockets, 0, MAX_READY_SOCKET_NUM*sizeof(epoll_event));
        tmp_socket_num = epoll_wait(epoll_fd, ready_sockets, MAX_READY_SOCKET_NUM, EPOLL_WAIT_TIMEOUT);
        
        if(tmp_socket_num == -1){
            write_log_mtx.lock();
            log_file << now_time() << '\t' << "Warning: epoll_wait return -1, errno is " << errno << std::endl;
            write_log_mtx.unlock();
            continue;

        }
        if(tmp_socket_num > 0){
            for(tmp_num = 0; tmp_num < tmp_socket_num; ++tmp_num){

                if((ready_sockets[tmp_num].events & EPOLLERR) || !(ready_sockets[tmp_num].events & EPOLLIN)){
                    write_log_mtx.lock();
                    log_file << now_time() << '\t' << "Warning: socket error\n";
                    write_log_mtx.unlock();
                    continue;
                }else if(ready_sockets[tmp_num].events & EPOLLRDHUP){   //socket被客户端关闭
                    tmp_socket = ready_sockets[tmp_num].data.fd;

                    write_log_mtx.lock();
                    log_file << now_time() << '\t' << "Warning: " << inet_ntoa(sockets[tmp_socket].addr) << " close itself\n";
                    write_log_mtx.unlock();
                    
                    sockets[tmp_socket].is_closed = true;
                }
                
                if(ready_sockets[tmp_num].data.fd == listen_socket){  //信息来自监听socket
                    //std::cout << "Listener accept socket\n";
                    for(tmp_num_2 = 0; tmp_num_2 < MAX_LISTEN_QUEUE; ++tmp_num_2){
                        tmp_socket = accept(listen_socket, (sockaddr*)&tmp_sockaddr, &sock_addr_length);
                        if(tmp_socket == -1 )
                            break;
                        
                        write_log_mtx.lock();
                        log_file << now_time() << '\t' << "Info: new connection " << inet_ntoa(tmp_sockaddr.sin_addr) << std::endl;
                        write_log_mtx.unlock();

                        tmp_event.events = EPOLLIN | EPOLLET;
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

                        socket_catalogue.insert(socket_catalogue.end(), tmp_socket);
                        sockets.emplace(tmp_socket, tmp_client_socket);
                        sockets[tmp_socket].addr.s_addr = tmp_sockaddr.sin_addr.s_addr;

                        write_log_mtx.lock();
                        log_file << now_time() << '\t' << "Info: add connection successfully\n";
                        write_log_mtx.unlock();

                    }
                }else{  //信息来自连接的客户端socket
                    tmp_socket = ready_sockets[tmp_num].data.fd;
                    memset(&tmp_login_msg, 0, sizeof(login_message_t));

                    msg_length = recv(tmp_socket, &tmp_login_msg, sizeof(login_message_t), 0); 
                    if(-1 == msg_length || tmp_login_msg.type != 'L'){
                        write_log_mtx.lock();
                        log_file << now_time() << '\t' << "Warning: failed to receive valid msg from " << inet_ntoa(sockets[tmp_socket].addr) << std::endl;
                        write_log_mtx.unlock();

                        //sockets[ready_sockets[tmp_num].data.fd].mtx.lock();
                        sockets[tmp_socket].tried_time += 1;
                        sockets[tmp_socket].time += 1;
                        //sockets[ready_sockets[tmp_num].data.fd].mtx.unlock();
                    }else{
                        if(!conn.connected()){
                            continue_tag = false;
                            char data = -3;
                            send(tmp_socket, &data, 1, 0);
                        }else{
                            query.reset();
                            query << to_query << tmp_login_msg.name << '\'';
                            tmp_query_result = query.store();

                            if(tmp_query_result.num_rows() == 0){
                                sockets[tmp_socket].tried_time += 1;
                                sockets[tmp_socket].time += 1;
                                
                                write_log_mtx.lock();
                                log_file << now_time() << '\t' << "Info: user "  << tmp_login_msg.name<< " from " << inet_ntoa(sockets[tmp_socket].addr) << " authorized failed\n";
                                write_log_mtx.unlock();

                                char data = -1;
                                send(tmp_socket, &data, 1, 0);
                            }else{
                                if(tmp_query_result[0]["password"].compare(tmp_login_msg.pass) != 0){
                                    sockets[tmp_socket].tried_time += 1;
                                    sockets[tmp_socket].time += 1;
                                
                                    write_log_mtx.lock();
                                    log_file << now_time() << '\t' << "Info: user "  << tmp_login_msg.name<< " from " << inet_ntoa(sockets[tmp_socket].addr) << " authorized failed\n";
                                    write_log_mtx.unlock();

                                    char data = -2;
                                    send(tmp_socket, &data, 1, 0);
                                }else{
                                    write_log_mtx.lock();
                                    log_file << now_time() << '\t' << "Info: user "  << tmp_login_msg.name<< " from " << inet_ntoa(sockets[tmp_socket].addr) << " authorized successfully\n";
                                    write_log_mtx.unlock();

                                    char data = 0;
                                    send(tmp_socket, &data, 1, 0);

                                    std::vector<int>::iterator i = socket_catalogue.begin();
                                    for(i; i != socket_catalogue.end(); ++i){
                                        if(*i == tmp_socket)
                                            break;
                                    }
                                    socket_catalogue.erase(i);
                                    sockets.erase(tmp_socket);
                                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, tmp_socket, NULL);

                                    mr_ptr->add_socket(tmp_login_msg.name, tmp_socket);
                                }
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
            if(sockets[socket_tmp].time > 5 || sockets[socket_tmp].tried_time > 3 || sockets[socket_tmp].is_closed == true){
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
