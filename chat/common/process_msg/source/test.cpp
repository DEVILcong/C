#include "process_msg.hpp"
#include "make_rsaKey.hpp"

#include <fstream>

int main(int argc, char** argv){
    /*unsigned char* key = new unsigned char[32];
    unsigned char* iv = new unsigned char[16];

    std::ifstream in;
    in.open("aes_key", std::ifstream::in);
    in.read((char*)key, 32);
    in.read((char*)iv, 16);
    in.close();*/

    MakeRSAKey make;
    make.makeKey();

    EVP_PKEY* key = make.getKey();

    ProcessMsg msg(key);

    msg.RSA_encrypt("Hello, My name is Liang Yuecong. I live in Cuijiayu, ShanDong Province. I like learning English very much. My favorite color is black, it's cool. My favorite food is tomato, it's just tasty.", 100);
    size_t length = msg.get_result_length();
    unsigned char* buffer = new unsigned char[length];
    memcpy(buffer, msg.get_result(), length);
    std::cout << length << "\n" << buffer << std::endl;

    msg.RSA_decrypt((char*)buffer, length);
    std::cout << msg.get_result_length() << "\t" << msg.get_result() << std::endl;



    /*delete [] key;
    delete [] iv;
    delete [] buffer;*/
    return 0;
}
