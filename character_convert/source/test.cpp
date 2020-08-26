#include "character_convert.hpp"
#include <cstring>
#include <iostream>

int main(void){
    CharacterConvert con;
    
    char* name = new char[4];
    name[0] = 0xC1;
    name[1] = 0xBA;
    name[2] = 0xD4;
    name[3] = 0xC2;

    con.convert("GBK", "UTF-8", name, 4);
    //con.result2hex_str();

    std::cout << con.get_size() << std::endl;
    std::cout << con.get_result() << std::endl;

    return 0;    
}
