/********************************************************************
  > File Name: SHA.hpp
  > Author:xisha
  > Mail: 1540348087@qq.com
  > Created Time: 2018年09月27日 星期四 11时14分28秒
********************************************************************/

#ifndef _SHA_H
#define _SHA_H

#include <iostream>
#include <string>
#include <openssl/sha.h>

template<typename State,
         int OutBytes,
         int BlockBytes,
         int (*Init)(State*),
         int (*Update)(State*,const void*,size_t),
         int (*Final)(uint8_t*,State*)>
class SHA{
public:
    SHA(){ (*Init)(&s); };
    void update(const char* data,size_t len) { (*Update)(&s,data,len); }
    void final(uint8_t* buf) { (*Final)(buf,&s); }
    std::string final()
    {
        std::string v;
        v.resize(hashsize);
        final((uint8_t*)v.data());
        return v;
    }
    static std::string hash(const std::string & str)
    {
        SHA x;
        x.update(str.data(),str.size());
        return x.final();
    }
    static const size_t hashsize=OutBytes;
    static const size_t blocksize=BlockBytes;
private:
    State s;
};

typedef SHA<SHA_CTX,    20, 64,  SHA1_Init, SHA1_Update, SHA1_Final> sha1;
typedef SHA<SHA256_CTX, 28, 64,  SHA224_Init, SHA224_Update, SHA224_Final> sha224;
typedef SHA<SHA256_CTX, 32, 64,  SHA256_Init, SHA256_Update, SHA256_Final> sha256;
typedef SHA<SHA512_CTX, 48, 128, SHA384_Init, SHA384_Update, SHA384_Final> sha384;
typedef SHA<SHA512_CTX, 64, 128, SHA512_Init, SHA512_Update, SHA512_Final> sha512;

#endif
