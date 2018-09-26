/********************************************************************
  > File Name: md5.cpp
  > Author:xisha
  > Mail: 1540348087@qq.com
  > Created Time: 2018年09月26日 星期三 14时38分31秒
********************************************************************/

#include <iostream>
#include <iomanip>
#include <string>
#include <fstream>
#include <openssl/md5.h>
#include <stdio.h>
#include <string.h>

using namespace std; 

#define BUF_SIZE 1024

void Print(unsigned char md[MD5_DIGEST_LENGTH])
{
    for(int i=0;i<MD5_DIGEST_LENGTH;++i)
        cout<<hex<<setw(2)<<setfill('0')<<(int)md[i];
        //printf("%02x",md[i]);
    cout<<endl;
}

void MD5String(string str)
{
    unsigned char md[MD5_DIGEST_LENGTH];
    MD5((const unsigned char*)str.c_str(),str.size(),md);
    Print(md);
}

void MD5File(string fileName)
{
    unsigned char md[MD5_DIGEST_LENGTH];
    char buf[BUF_SIZE];
    MD5_CTX md5_ctx;
    MD5_Init(&md5_ctx);
    ifstream ifs(fileName.c_str()); 
    if(ifs.fail())
    {
        cout<<fileName<<" open fail"<<endl;
        return;
    }
    while(!ifs.eof())
    {
        memset(buf,0,sizeof(buf));
        ifs.read(buf,BUF_SIZE);
        int len=ifs.gcount();
        if(len)
        {
            MD5_Update(&md5_ctx,buf,len);
        }
    }
    MD5_Final(md,&md5_ctx);
    Print(md);
}


int main(int argc,char* argv[])
{
    if(2!=argc)
    {
        cout<<"./md5_test string"<<endl;
        return -1;
    }
    string str=argv[1];
    //MD5String(str);
    MD5File(str);
    return 0;
}


