#ifndef __MYSOCKET_HPP__
#define __MYSOCKET_HPP__

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

class mysocket{
public:
    mysocket(){};
    ~mysocket(){
        close(this->stored_socket);
    };
    operator =(int& tmp_socket){
        this->stored_socket = tmp_socket
    };
    int value(){
        return this->stored_socket;
    };

private:
    int stored_socket;
}

#endif
