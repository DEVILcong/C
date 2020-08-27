#ifndef _CHARACTER_CONVERT_HPP_
#define _CHARACTER_CONVERT_HPP_

#include <iconv.h>
#include <memory>
#include <cstring>

class char_deleter{
public:
    void operator ()(char*);    
    
};


class CharacterConvert{
public:
    CharacterConvert();
    ~CharacterConvert();
    void convert(char* fromCode, char* toCode, char* from, size_t from_len);
    void result2hex_str();
    char* get_result();
    size_t get_size();

private:
    char_deleter d;
    char dict[16];
    std::unique_ptr<char, char_deleter> buffer;
    size_t size;
    
};

#endif
