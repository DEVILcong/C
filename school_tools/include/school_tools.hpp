#ifndef _SCHOOL_TOOLS_HPP_
#define _SCHOOL_TOOLS_HPP_

#include <curl/curl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <iostream>
#include <memory>
#include <regex>

#include "character_convert.hpp"  //utf-8转GBK

#define MAX_BUFFER_SIZE 8192
#define LIGHT_BILL_DOOR "http://172.16.254.43/ahdxDfcxInputDoor.action?id=1"
#define AIR_BILL_DOOR   "http://172.16.254.43/ahdxDfcxInputDoor.action?id=2"
#define CHECK_DOOR      "http://172.16.254.43/ahdxCheckDoor.action"
#define POWER_BILL      "http://172.16.254.43/ahdxDfcx.action"

#define DATA_PATTERN    "<td colspan=\"2\" >.*?:(.*?)&nbsp;&nbsp;&nbsp;&nbsp;.*?:(.*?)</td>"


#define POWER_CATEGORY_LIGHT 0
#define POWER_CATEGORY_AIR_CONDITIONER 1

#define MAIN_IP         "172.16.254.43"

struct data_buffer{
    size_t size;
    char* data;    
};

class character_convert_deleter{
public:
    void operator ()(char* ptr);    
};

class SchoolTools{
public:
    SchoolTools(bool out_flag);  //是否cout打印错误信息
    ~SchoolTools();
    void test();      //示例函数，可直接运行
    bool isSuccess(); //判断上一步操作是否成功，可不用

    //example: "枣园一号楼", "1428", "0"(照明电费)/"1"(空调电费), 后两个参数接收数据 1.电费余额 2.总用电量（度）
    void getPowerBalance(char* buildingID, char* roomID, int category, float* balance, float* all);
    
private:
    bool stdout_flag;
    bool success_flag;
    CURL* curl;
    CURLcode status;
    struct curl_slist* cookies;
    char* errmsg;

    CharacterConvert* converter;

    struct data_buffer buffer;

    void print_msg(char* msg, unsigned char len);
    void curl_config(void);

    void get_power_1(int category);
    bool get_power_check(char* buildingID, char* roomID);
    void get_power_2(char* buildingID, char* roomID, int category, float* balance, float* all);


    static size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata);
};

#endif
