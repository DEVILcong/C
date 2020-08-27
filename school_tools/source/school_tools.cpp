#include "school_tools.hpp"

void character_convert_deleter::operator () (char* ptr){
    delete [] ptr;    
}

SchoolTools::SchoolTools(bool out_flag){
    this->stdout_flag = out_flag;
    
    this->success_flag = false;
    this->curl = curl_easy_init();

    this->cookies = nullptr;

    this->errmsg = new char[CURL_ERROR_SIZE];
    memset(errmsg, 0, CURL_ERROR_SIZE);

    this->converter = new CharacterConvert();

    this->buffer.data = new char[MAX_BUFFER_SIZE];
    memset(this->buffer.data, 0, MAX_BUFFER_SIZE);
    this->buffer.size = 0;
    
    if(this->curl == NULL){
        this->success_flag = false;
        return;
    }
    else
        this->success_flag = true;

    this->curl_config();
}

void SchoolTools::curl_config(void){
    memset(this->errmsg, 0, CURL_ERROR_SIZE);
    
    this->status = curl_easy_setopt(this->curl, CURLOPT_TIMEOUT, 5);
    
    this->status = curl_easy_setopt(this->curl, CURLOPT_COOKIEFILE, " ");    //enable cookie support
    this->status = curl_easy_setopt(this->curl, CURLOPT_ERRORBUFFER, this->errmsg);  

    this->status = curl_easy_setopt(this->curl, CURLOPT_WRITEFUNCTION, SchoolTools::write_callback);
    memset(this->buffer.data, 0, MAX_BUFFER_SIZE);
    this->buffer.size = 0;
    this->status = curl_easy_setopt(this->curl, CURLOPT_WRITEDATA, &(this->buffer));

    this->status = curl_easy_setopt(this->curl, CURLOPT_USERAGENT, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36");
}

SchoolTools::~SchoolTools(){
    curl_easy_cleanup(this->curl);
    
    delete [] this->errmsg;
    delete [] this->buffer.data;

    delete this->converter;

    if(this->cookies != nullptr)
        curl_slist_free_all(this->cookies);
}

bool SchoolTools::isSuccess(){
    return this->success_flag;    
}

void SchoolTools::print_msg(char* msg, unsigned char len){
    if(this->stdout_flag){
        for(unsigned char i = 0; i < len; ++i)
            std::cout << msg[i];
        std::cout << std::endl;

        if(len == 0)
            std::cout << curl_easy_strerror(this->status) << std::endl;
    }
    return;
}

size_t SchoolTools::write_callback(char* ptr, size_t size, size_t nmemb, void* userdata){
    struct data_buffer* tmp_buffer = (struct data_buffer*)userdata;
    
    if(tmp_buffer->data == nullptr)
        return 0;
        
     memcpy(&(tmp_buffer->data[tmp_buffer->size]), ptr, nmemb);
     tmp_buffer->size += nmemb;
     
     return nmemb;   
}

void SchoolTools::test(){
    float balance = 0;
    float all = 0;
    this->getPowerBalance("枣园一号楼", "1428", 0, &balance, &all);
    std::cout << balance << "\t" << all << std::endl;

    //this->getPowerBalance("枣园一号楼", "1428", 1, &balance, &all);
    //std::cout << balance << "\t" << all << std::endl;
}

void SchoolTools::getPowerBalance(char* buildingID, char* roomID, int category, float* balance, float* all){
    *balance = -1;
    *all = -1;
    this->get_power_1(category);
    if(this->success_flag){
        this->get_power_2(buildingID, roomID, category, balance, all);
    }

}

void SchoolTools::get_power_1(int category){
    if(this->curl == NULL){
        this->success_flag = false;
        return;    
    }

    curl_easy_reset(this->curl);
    this->curl_config();

    if(category == POWER_CATEGORY_LIGHT)
        curl_easy_setopt(this->curl, CURLOPT_URL, LIGHT_BILL_DOOR);
    else if(category == POWER_CATEGORY_AIR_CONDITIONER)
        curl_easy_setopt(this->curl, CURLOPT_URL, AIR_BILL_DOOR);

    this->status = curl_easy_perform(this->curl);
    if(this->status != CURLE_OK){
        this->print_msg(this->errmsg, strlen(this->errmsg));
        this->success_flag = false;
        return;    
    }

    this->status = curl_easy_getinfo(this->curl, CURLINFO_COOKIELIST, &(this->cookies));
    if(this->status != CURLE_OK){
        this->print_msg(this->errmsg, strlen(this->errmsg));
        this->success_flag = false;
        return;    
    }

    this->success_flag = true;
}

bool SchoolTools::get_power_check(char* buildingID, char* roomID){
    size_t size = 14;  //?areaCode=&kh=
    char* data;
    char* tmp_ID = nullptr;

    size_t full_url_size = 0;
    char* full_url;

    tmp_ID = curl_easy_escape(this->curl, buildingID, 0);
    
    size += strlen(tmp_ID);
    size += strlen(roomID);
    data = new char[size];

    memcpy(data, "?areaCode=", (size_t)10);
    memcpy(&(data[10]), tmp_ID, strlen(tmp_ID));
    memcpy(&(data[10 + strlen(tmp_ID)]), "&kh=", 4);
    memcpy(&(data[10 + strlen(tmp_ID) + 4]), roomID, strlen(roomID));

    full_url_size = strlen(CHECK_DOOR) + strlen(data);
    full_url = new char[full_url_size + 1];
    memset(full_url, 0, full_url_size + 1);     //add a '\0'

    memcpy(full_url, CHECK_DOOR, strlen(CHECK_DOOR));
    memcpy(&(full_url[strlen(CHECK_DOOR)]), data, strlen(data));

    //std::cout << full_url << std::endl;
    
    curl_easy_setopt(this->curl, CURLOPT_URL, full_url);

    //curl_easy_setopt(this->curl, CURLOPT_VERBOSE, 1L);
    this->status = curl_easy_perform(this->curl);
    if(this->status != CURLE_OK){
        this->print_msg(this->errmsg, strlen(this->errmsg));
        return false;    
    }

    //std::cout << this->buffer.data << std::endl;
    
    delete [] data;
    delete [] full_url;
    curl_free(tmp_ID);
    
    if(this->buffer.data[0] == '0')
        return true;
    else 
        return false;
}

void SchoolTools::get_power_2(char* buildingID, char* roomID, int category, float* balance, float* all){
    if(this->curl == NULL){
        this->success_flag = false;
        *balance = -2;
        *all = -2;
        return;    
    }
    
    size_t data_size = 13 + strlen(roomID);
    std::unique_ptr<char[]> data(nullptr);

    curl_easy_reset(this->curl);
    this->curl_config();

    if(category == POWER_CATEGORY_LIGHT)
        curl_easy_setopt(this->curl, CURLOPT_REFERER, LIGHT_BILL_DOOR);
    else if(category == POWER_CATEGORY_AIR_CONDITIONER)
        curl_easy_setopt(this->curl, CURLOPT_REFERER, AIR_BILL_DOOR);

    if(!this->get_power_check(buildingID, roomID)){
        *balance = -3;
        *all = -3;
        this->success_flag = false;
        return;
    }
    this->buffer.size = 0;
    
    curl_easy_setopt(this->curl, CURLOPT_URL, POWER_BILL);

    curl_easy_setopt(this->curl, CURLOPT_POST, 1L);

    this->converter->convert("UTF-8", "GBK", buildingID, (size_t)strlen(buildingID));
    this->converter->result2hex_str();
    
    data_size += this->converter->get_size();
    data.reset(new char[data_size]);
    memset(data.get(), 0, data_size);

    memcpy(data.get(), "areaCode=", (size_t)9);
    memcpy(&(data[9]), this->converter->get_result(), this->converter->get_size() - 1);
    memcpy(&(data[9 + this->converter->get_size() - 1]), "&kh=", (size_t)4);
    memcpy(&(data[9 + this->converter->get_size()  - 1 + 4]), roomID, (size_t)strlen(roomID));

    curl_easy_setopt(this->curl, CURLOPT_POSTFIELDS, data.get());
    curl_easy_setopt(this->curl, CURLOPT_POSTFIELDSIZE, data_size -1);

    //curl_easy_setopt(this->curl, CURLOPT_VERBOSE, 1L);

    this->status = curl_easy_perform(this->curl);
    if(this->status != CURLE_OK){
        this->print_msg(this->errmsg, strlen(this->errmsg));
        this->success_flag = false;
        *balance = -4;
        *all = -4;
        return;    
    }

    //std::cout << this->buffer.size << this->buffer.data << std::endl;
    
    std::regex pattern(DATA_PATTERN);
    std::cmatch result;
    std::regex_search(this->buffer.data, result, pattern);

    if(result.size() != 3){
        this->success_flag = false;
        *balance = -5;
        *all = -5;
        return;
    }

    *balance = std::stof(result[1].str());
    *all = std::stof(result[2].str());
    this->success_flag = true;
}

