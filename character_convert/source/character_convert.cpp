#include "character_convert.hpp"

void char_deleter::operator ()(char* ptr){
    delete [] ptr;    
}

CharacterConvert::CharacterConvert(){
    this->dict[0] = '0';
    this->dict[1] = '1';
    this->dict[2] = '2';
    this->dict[3] = '3';
    this->dict[4] = '4';
    this->dict[5] = '5';
    this->dict[6] = '6';
    this->dict[7] = '7';
    this->dict[8] = '8';
    this->dict[9] = '9';
    this->dict[10] = 'A';
    this->dict[11] = 'B';
    this->dict[12] = 'C';
    this->dict[13] = 'D';
    this->dict[14] = 'E';
    this->dict[15] = 'F';

    
    this->d = char_deleter();
    this->buffer = std::unique_ptr<char, char_deleter>(nullptr, this->d);
    
    this->size = 0;    
}

CharacterConvert::~CharacterConvert(){}

void CharacterConvert::convert(char* fromCode, char* toCode, char* from, size_t from_len){
    iconv_t cd = iconv_open(toCode, fromCode);
    
    this->buffer.reset(new char[from_len * 2]);
    
    char* tmp_to_ptr = this->buffer.get();
    memset(tmp_to_ptr, 0, from_len * 2);
    size_t tmp_to_len = from_len * 2;
    
    char* tmp_from_ptr = from;
    size_t tmp_from_len = from_len;
    
    iconv(cd, &tmp_from_ptr, &tmp_from_len, &tmp_to_ptr, &tmp_to_len);
    
    this->size = from_len * 2 - tmp_to_len;   
}

void CharacterConvert::result2hex_str(){
    char* tmp_out = new char[3 * this->size + 1];
    memset(tmp_out, 0, 3 * this->size + 1);
    char* result = this->buffer.get();
    
    size_t tmp_out_loc = 0;
    unsigned char tmp_data = 0x00;
    for(int i = 0; i < this->size; ++i){
        tmp_out[tmp_out_loc] = '%';

        tmp_data = result[i] & 0xf0;
        tmp_data = tmp_data >> 4;  
        tmp_out[tmp_out_loc + 1] = this->dict[tmp_data];
        
        tmp_data = result[i] & 0x0f;
        tmp_out[tmp_out_loc + 2] = this->dict[tmp_data];
        
        tmp_out_loc += 3; 
    }    

    this->buffer.reset(tmp_out);
    this->size = 3 * this->size + 1;
}

char* CharacterConvert::get_result(){
    return this->buffer.get();    
}

size_t CharacterConvert::get_size(){
    return this->size;
}
