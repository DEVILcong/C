#include <login.hpp>

login::login(){
    listen_socket = socket(AF_INET, SOCKET_STREAM, 0);
    if(listen_socket < 0){
        this->success_tag = -1;
        return;
    }

    struct sockaddr_in myaddr;
    memset(&myaddr, 0, sizeof(myaddr));
    myaddr.sin_family = AF_INET;
    myaddr.sin_port = htons(LISTEN_PORT);
    myaddr.sin_addr.s_addr = INADDR_ANY;

    if(bind(listen_socket, (struct socketaddr*)&myaddr, sizeof(myaddr)) == -1){
        this->success_tag = -2;
        return;
    }

    this->suuccess_tag = 0;
    
    memset(ready_sockets, 0, MAX_READY_SOCKET_NUM*sizeof(epoll_event));
    continue_tag = true;
    
    log_file.open(LOG_FILE_PATH, std::ofstream::out| std::ofstream::app);
    if(!log_file.is_open())
        this->success_tag = -7;

    return;
}

login::~login(){
    for(std::list<int>::iterator it = socket_catalogue.begin(); it != socket_catalogue.end(); ++it)
        close(*it);

    close(epoll_fd);
    conn.disconnect();
}

void login::init(){
    if(epoll_fd = epoll_create(MAX_SOCKET_NUM) == -1){
        this->success_tag = -3;
        return;
    }

    if(fcntl(listen_socket, F_SETFL, fcntl(listen_socket, F_GETFL, 0) | O_NONBLOCK) == -1){
        this->success_tag = -4;
        return;
    }

    if(listen(listen_socket, MAX_LISTEN_QUEUE) == -1){
        this->success_tag = -5;
        return;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = listen_socket;
    if(epoll_ctl(listen_socket, EPOLL_CTL_ADD, &ev) == -1){
        this->success_tag = -6;
        return;
    }

    log_file << now_time() << '\t' << "Info: init socket and epoll successfully\n";

    if(!conn.connect(MYSQL_DB, MYSQL_SERVER, MYSQL_USER, MYSQL_PASS, MYSQL_PORT)){
        this->success_tag = -8;
        return;
    }else{
        query = conn.query();
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

    std::string to_query = "select password from " + MYSQL_TABLE + " where name=\'";
    mysqlpp::StoreQueryResult tmp_query_result;

    struct login_message_t tmp_login_msg;
    unsigned short int msg_length;


    while(continue_tag){
        socket_list_mtx.lock();
        epoll_mtx.lock();
        tmp_socket_num = epoll_wait(epoll_fd, ready_sockets, MAX_READY_SOCKET_NUM, EPOLL_WAIT_TIMEOUT);
        epoll_mtx.unlock();
        
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
                }
                
                if(ready_sockets[tmp_num].data.fd == listen_socket){
                    for(tmp_num_2 = 0; tmp_num_2 < MAX_LISTEN_QUEUE; ++tmp_num_2){
                        tmp_socket = accept(listen_socket, &tmp_sockaddr, sizeof(sockaddr_in));
                        if(tmp_socket == -1 || errno == EAGAIN || errno == EWOULDBLOCK)
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

                        epoll_mtx.lock();
                        if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tmp_socket, &tmp_event) == -1){
                            write_log_mtx.lock();
                            log_file << now_time() << '\t' << "Warning: can't add socket to list, errno is " << errno << std::endl;
                            write_log_mtx.unlock();
                            close(tmp_socket);
                            epoll_mtx.unlock();
                            continue;
                        }
                        epoll_mtx.unlock();

                        socket_catalogue.insert(socket_catalogue.end(), tmp_socket);
                        sockets.emplace(tmp_socket, {tmp_socket});

                        write_log_mtx.lock();
                        log_file << now_time() << '\t' << "Info: add connection successfully\n";
                        write_log_mtx.unlock();
                    }
                }else{
                    memset(&tmp_login_msg, 0, sizeof(login_message_t));
                    msg_length = recv(ready_sockets[tmp_num].data.fd, &tmp_login_msg, sizeof(login_message_t), 0); 
                    if(-1 == msg_length || tmp_login_msg.type != 'L'){
                        write_log_mtx.lock();
                        logfile << now_time() << '\t' << "Warning: failed to receive valid msg from socket " << ready_sockets[tmp_num].data.fd << std::endl;
                        write_log_mtx.unlock();

                        //sockets[ready_sockets[tmp_num].data.fd].mtx.lock();
                        sockets[ready_sockets[tmp_num].data.fd].tried_time += 1;
                        sockets[ready_sockets[tmp_num].data.fd].time += 1;
                        //sockets[ready_sockets[tmp_num].data.fd].mtx.unlock();
                    }else{
                        query.reset();
                        query << to_query << tmp_login_msg.name << '\';
                        tmp_query_result = query.store();

                        if(tmp_query_result.num_rows == 0){
                            sockets[ready_sockets[tmp_num].data.fd].tried_time += 1;
                            sockets[ready_sockets[tmp_num].data.fd].time += 1;
                            
                            write_log_mtx.lock();
                            log_file << now_time() << '\t' << "Info: user "  << tmp_login_msg.name<< " authorize failed\n";
                            write_log_mtx.unlock();
                        }else{
                            if(tmp_query_result[0]["password"].compare(tmp_login_msg.pass) != 0){
                                sockets[ready_sockets[tmp_num].data.fd].tried_time += 1;
                                sockets[ready_sockets[tmp_num].data.fd].time += 1;
                            
                                write_log_mtx.lock();
                                log_file << now_time() << '\t' << "Info: user "  << tmp_login_msg.name << " authorize failed\n";
                                write_log_mtx.unlock();
                            }else{
                                write_log_mtx.lock();
                                log_file << now_time() << '\t' << "Info: user " << tmp_login_msg.name << " authorize successful\n";
                                write_log_mtx.unlock();
                            }
                        }
                    }
                }
            }
        }
        write_log_mtx.lock();
        lof_file.flush();
        write_log_mtx.unlock();

        socket_list_mtx.unlock();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

char* login::now_time(void){
    tmp_now_time = std::chrono::system_clock::now();
    tmp_time_t = std::chrono::system_clock::to_time_t(tmp_now_time);
    return ctime(&tmp_time_t);
}
