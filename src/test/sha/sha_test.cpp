/********************************************************************
  > File Name: sha_test.cpp
  > Author:xisha
  > Mail: 1540348087@qq.com
  > Created Time: 2018年09月27日 星期四 09时44分11秒
********************************************************************/

#include "sha.hpp"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <string>
#include <string.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

#define BUF_SIZE 1024
using namespace std;

/*
SHA_DIGEST_LENGTH    20
SHA224_DIGEST_LENGTH 28
SHA256_DIGEST_LENGTH 32
SHA384_DIGEST_LENGTH 48
SHA512_DIGEST_LENGTH 64
*/

void PrintHash(unsigned char* md,int len)
{
    for(int i=0;i<len;++i)
    {
        //cout<<hex<<setw(2)<<setfill('0')<<(int)md[i];
        printf("%02x",md[i]);
    }
    cout<<endl;
}

void SHA1String(string str)
{
    SHA_CTX sc;
    unsigned char md[SHA_DIGEST_LENGTH];
    if(!SHA1_Init(&sc)) return;
    SHA1_Update(&sc,(unsigned char*)str.c_str(),str.size());
    SHA1_Final(md,&sc);
    PrintHash(md,SHA_DIGEST_LENGTH);
    OPENSSL_cleanse((void*)md,sizeof(md));//清零操作,与memset效果一样
    //memset(md,0,SHA_DIGEST_LENGTH);
    PrintHash(md,SHA_DIGEST_LENGTH);
    SHA1((unsigned char*)str.c_str(),str.size(),md);
    PrintHash(md,SHA_DIGEST_LENGTH);
}

void SHA224String(string str)
{
    SHA256_CTX sc;
    unsigned char md[SHA224_DIGEST_LENGTH];
    if(!SHA224_Init(&sc)) return;
    SHA224_Update(&sc,(unsigned char*)str.c_str(),str.size());
    SHA224_Final(md,&sc);
    PrintHash(md,SHA224_DIGEST_LENGTH);
    OPENSSL_cleanse((void*)md,sizeof(md));
    PrintHash(md,SHA224_DIGEST_LENGTH);
    SHA224((unsigned char*)str.c_str(),str.size(),md);
    PrintHash(md,SHA224_DIGEST_LENGTH);
}
void SHA1File(string fileName)
{
    SHA_CTX sc;
    unsigned char md[SHA_DIGEST_LENGTH];
    char buf[BUF_SIZE];
    if(!SHA1_Init(&sc)) return;
    ifstream ifs(fileName.c_str());
    if(ifs.fail())
    {
        cout<<"file open fail"<<endl;
        return;
    }
    while(!ifs.eof())
    {
        memset(buf,0,sizeof(buf));
        ifs.read(buf,sizeof(buf));
        int len=ifs.gcount();
        if(len) SHA1_Update(&sc,buf,len);
    }
    SHA1_Final(md,&sc);
    PrintHash(md,SHA_DIGEST_LENGTH);
}

int main(int argc,char* argv[])
{
    if(2!=argc)
    {
        cout<<"input ./sha_test str"<<endl;
        return -1;
    }
    string str(argv[1]);
    SHA1String(str);
    //SHA1File(str);
    //SHA224String(str);
    
    std::string md=sha1::hash(str);
    PrintHash((unsigned char*)md.c_str(),md.size());
    //cout<<md<<endl;
}


