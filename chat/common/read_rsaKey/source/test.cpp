#include "read_rsaKey.hpp"

int main(int argc, char **argv){
    ReadRSAKey r(argv[1], argv[2]);
    if(r.isRunSuccess())
        std::cout << "hahahaha" << std::endl;
    else
        std::cout << "wuwuwuwu" << std::endl;
}
