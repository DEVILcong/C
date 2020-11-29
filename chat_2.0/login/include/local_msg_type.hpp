#ifndef _LOCAL_MSG_TYPE_HPP_
#define _LOCAL_MSG_TYPE_HPP_

#include <openssl/ssl.h>
#include <openssl/err.h>

struct local_msg_type_t{
    char* name;
    int socket_fd;
    SSL* ssl_fd;
};


#endif