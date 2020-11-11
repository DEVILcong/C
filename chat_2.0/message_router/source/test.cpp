#include "login.hpp"
#include "message_router.hpp"

#include <thread>
#include <iostream>

int main(void){
    char tmp_tag = 0;
    
    Message_router mr;
    login lg(&mr);
    lg.init();

    tmp_tag = mr.get_success_tag();
    if(tmp_tag < 0){
        std::cout << "message router init error " << int(tmp_tag) << std::endl;
        return 0;
    }

    tmp_tag = lg.get_tag();
    if(tmp_tag < 0){
        std::cout << "login module init error " << int(tmp_tag) << std::endl;
        return 0;
    }

    std::thread lg_listener(login::listener);
    std::thread lg_cleaner(login::cleaner);

    std::thread mr_worker(Message_router::message_worker);
    std::thread mr_consumer(Message_router::message_consumer);
    std::thread mr_cleaner(Message_router::cleaner);

    lg_listener.join();
    lg_cleaner.join();

    mr_worker.join();
    mr_consumer.join();
    mr_cleaner.join();
}