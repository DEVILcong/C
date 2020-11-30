#include "process_msg.hpp"
#include "make_rsaKey.hpp"

#include <fstream>

#define AES_256_KEY_SIZE 32
#define AES_256_IV_SIZE 16

struct aes_key_item_t{
    unsigned char key[AES_256_KEY_SIZE];
    unsigned char iv[AES_256_IV_SIZE];
};

int main(int argc, char** argv){
    struct aes_key_item_t server_keys[30];
    struct aes_key_item_t client_keys[6];

    unsigned char tmp_buffer[35];
    int tmp_length = 0;

    std::ifstream in1("server_keys", std::ifstream::in | std::ifstream::binary);
    std::ifstream in2("client_keys", std::ifstream::in | std::ifstream::binary);

    in1.read((char*)&server_keys, 30 * sizeof(struct aes_key_item_t));
    in2.read((char*)&client_keys, 6 * sizeof(struct aes_key_item_t));

    ProcessMsg process(server_keys[5].key, server_keys[5].iv);
    //process.base64_decode("0hA9SL8E3u/aPUhUK+Aa5w==", 25);
    //std::cout << process.get_result() << std::endl;

    for(int i = 0; i < 30; ++i){
        memset(tmp_buffer, 0, 35);

        process.AES_256_change_key(server_keys[i].key, server_keys[i].iv);
        process.AES_256_process("liangyuecong", 12, 1);

        memcpy(&tmp_buffer, process.get_result(), process.get_result_length());
        tmp_length = process.get_result_length();

        std::cout << tmp_buffer << '\n';

        process.AES_256_process((const char*)tmp_buffer, tmp_length, 0);
        std::cout << process.get_result() << std::endl;

        std::cout << "**********************\n";
    }

    std::cout << "-------------------------------------------------------\n";
    for(int i = 0; i < 5; ++i){
        process.AES_256_change_key(client_keys[i].key, client_keys[i].iv);
        process.AES_256_process("liangyuecong", 12, 1);

        memcpy(&tmp_buffer, process.get_result(), process.get_result_length());
        tmp_length = process.get_result_length();

        std::cout << tmp_buffer << '\t';

        process.AES_256_process((const char*)tmp_buffer, tmp_length-1, 0);
        std::cout << process.get_result() << std::endl;
    }

    in1.close();
    in2.close();
    return 0;
}
