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

    std::string tmp_string("zGyGId1aujOnP763PxVqGD4fQe3QJuaEgdVjaDZloN6PHDB1TCLVrpeFpUfCq2xN\nQmQ3gU5m8jJ+K4xMZ2vDCRmbMQIruAX8My3qB9PDP/Flwt8B2oyoi3zaHtB4/m+S\nAc8aMocrLBGl16hMdM5QIZiDRPlPONtAbKX18kVnvhCPfW0f6zcjr1eWlE8Hmzc1\nZXTyezsyxEHoCK7f5dprT8w7H+qhb3bdRQDBuAW/QjAyC2w7AN8mmsDVzbJTQR9C\nurekEQ16z7j0HbABLb4vsaaKJUo28z/re6Y7e7f+9xKpdfqXOB/hp9kbjwIqsc9I\nABN2XEI6ynty+d83A/s+c1CSxgfGj/nZcCxxeEmiPpOyPsFHW8y5Epil4fEy/L9w\nNKEsZCN1mh/fuqYtTCR3mohNxGUplXWhqxStZn74gTKm+zWlYGVU9T4aptgILE33\nptxJCGMVaYLjo5WZlbDx+komEAVqopVxsy1f9hmkPYDlPwk5euoKbtQcbovepWQB\n9g4aKsdyhYjxB84knYe5P3sKu9+OSZY+zwAcZRgYm/DlkDUR48Wq77Z4R1HbdQGh\ndvMlMaZjn6SaXiXOFbKac/w00VgYEnjqhGdEkLOuuECz/8NBKEpxwkZW4YhYveAj\nhx3L99iwOEeOEG2+ESK4qtvOs23/jTU7BvJuLZVDyASpSOD9JemTo7I+IXN7bQsc\nRoiqNCsx01u8ktkKB/6p4lL2d36Oo4bxxBHSl69pUa/mdePpdt+TzB9usrlawZ3d\n61YoQ2NNAFaXYhfzV8zOk77J5wKNv2Wo6eduMcuXHHWbZbh7dWYFn7QuGhr3UjsT");


    ProcessMsg process(server_keys[12].key, server_keys[12].iv);
    process.AES_256_process(tmp_string.c_str(), tmp_string.length(), 0);
    
    std::cout << process.get_result() << std::endl;

    // for(int i = 0; i < 30; ++i){
    //     memset(tmp_buffer, 0, 35);

    //     process.AES_256_change_key(server_keys[i].key, server_keys[i].iv);
    //     process.AES_256_process("liangyuecong", 12, 1);

    //     memcpy(&tmp_buffer, process.get_result(), process.get_result_length());
    //     tmp_length = process.get_result_length();

    //     std::cout << tmp_buffer << '\n';

    //     process.AES_256_process((const char*)tmp_buffer, tmp_length, 0);
    //     std::cout << process.get_result() << std::endl;

    //     std::cout << "**********************\n";
    // }

    // std::cout << "-------------------------------------------------------\n";
    // for(int i = 0; i < 5; ++i){
    //     process.AES_256_change_key(client_keys[i].key, client_keys[i].iv);
    //     process.AES_256_process("liangyuecong", 12, 1);

    //     memcpy(&tmp_buffer, process.get_result(), process.get_result_length());
    //     tmp_length = process.get_result_length();

    //     std::cout << tmp_buffer << '\t';

    //     process.AES_256_process((const char*)tmp_buffer, tmp_length-1, 0);
    //     std::cout << process.get_result() << std::endl;
    // }

    in1.close();
    in2.close();
    return 0;
}
