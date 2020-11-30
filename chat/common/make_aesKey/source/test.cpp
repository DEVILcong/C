#include "make_aesKey.hpp"

#include <fstream>
#include <string.h>

struct aes_key_item_t{
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
};

int main(void){
    std::ofstream out1;
    out1.open("client_keys", std::ofstream::out | std::ofstream::app | std::ofstream::binary);

    std::ofstream out2;
    out2.open("server_keys", std::ofstream::out | std::ofstream::app | std::ofstream::binary);

    MakeAESKey make;
    
    struct aes_key_item_t server_keys[30];
    struct aes_key_item_t client_keys[6];

    for(int i = 0; i < 30; ++i){
        make.makeKey();

        if(!make.ifValid()){
            i = i - 1;
            std::cout << "server one failure\n";
        }

        memcpy(server_keys[i].key, make.getKey(), KEY_SIZE);
        memcpy(server_keys[i].iv, make.getIv(), IV_SIZE);
    }

    for(int i = 0; i < 6; ++i){
        make.makeKey();
        
        if(!make.ifValid()){
            i = i - 1;
            std::cout << "client one failure\n";
        }

        memcpy(client_keys[i].key, make.getKey(), KEY_SIZE);
        memcpy(client_keys[i].iv, make.getIv(), IV_SIZE);

    }

    out1.write((const char*)&server_keys, 30 * sizeof(struct aes_key_item_t));
    out2.write((const char*)&client_keys, 6* sizeof(struct aes_key_item_t));

    out1.close();
    out2.close();

    return 0;
}
