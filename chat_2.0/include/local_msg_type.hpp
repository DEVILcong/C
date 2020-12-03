#ifndef _LOCAL_MSG_TYPE_HPP_
#define _LOCAL_MSG_TYPE_HPP_

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string>

#define LOCAL_MSG_TYPE_USER_LOGIN 1
#define LOCAL_MSG_TYPE_USER_LIST 2

struct local_msg_type_t{
    char type;
    std::string name = " ";
    int socket_fd;
    SSL* ssl_fd;
};


#endif