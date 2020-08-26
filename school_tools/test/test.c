#include <curl/curl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata){
    memcpy(userdata, ptr, nmemb);

    return nmemb;
}

int main(void){
    CURL* curl = curl_easy_init();
    char* data = (char*)malloc(4096);
    memset(data, 0, 4096);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, data);

    curl_easy_setopt(curl, CURLOPT_URL, "http://www.baidu.com");

    curl_easy_perform(curl);

    printf("%s\n", data);
    
    
    free(data);
    curl_easy_cleanup(curl);
    return 0;    
}
