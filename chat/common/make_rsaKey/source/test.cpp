#include "make_rsaKey.hpp"

int main(void){
    MakeRSAKey make;
    make.makeKey();

    if(make.ifValid())
        std::cout << "hahahahaha" << std::endl;
    else
        std::cout << "wuwuwuwuwu" << std::endl;
}
