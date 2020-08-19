#include "make_aesKey.hpp"

#include <fstream>

int main(void){
    std::ofstream out;
    out.open("keys", std::ofstream::out | std::ofstream::app);
    MakeAESKey make;
    make.makeKey();

    out << make.getKey() << make.getIv();

    out.close();

    if(make.ifValid())
        std::cout << "hahahahaha" << std::endl;
    else
        std::cout << "wuwuwuwuwu" << std::endl;
}
