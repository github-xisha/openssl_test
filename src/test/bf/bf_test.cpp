/********************************************************************
  > File Name: bf_test.cpp
  > Author:xisha
  > Mail: 1540348087@qq.com
  > Created Time: 2018年10月07日 星期日 22时42分09秒
********************************************************************/

#include <iostream>
#include <string>
#include <stdio.h>
#include <string.h>

#include <openssl/blowfish.h>

using namespace std;

void Print(unsigned char* out,int len)
{
    for(int i=0;i<len;++i)
    {
        printf("%02x",out[i]);
    }
    cout<<endl;
}

void BF_CBC(const string & plain)
{
    cout<<"plain size:"<<plain.size()<<endl;
    unsigned char data[]="12345";
    unsigned char ivec[8];
    BF_KEY bf_key;
    BF_set_key(&bf_key,sizeof(data),data);
    //int len=plain.size()%8?(plain.size()/8+1)*8:plain.size();
    int len=plain.size();
    unsigned char* enc_text=(unsigned char*)calloc(1,len+1);//申请的空间要比实际长度大1,否则为8的奇数倍时会出现问题
    unsigned char* dec_text=(unsigned char*)calloc(1,len+1);
    memset(ivec,0,sizeof(ivec));
    BF_cbc_encrypt((unsigned char*)plain.c_str(),enc_text,plain.size(),&bf_key,ivec,BF_ENCRYPT);
    //cout<<"enc:"<<enc_text<<endl;
    Print(enc_text,len);
    memset(ivec,0,sizeof(ivec));
    BF_cbc_encrypt(enc_text,dec_text,len,&bf_key,ivec,BF_DECRYPT);
    cout<<"dec:"<<dec_text<<endl;
}

void BF_CFB(const string & plain)
{
    cout<<"plain size:"<<plain.size()<<endl;
    unsigned char data[]="12345";
    unsigned char ivec[8];
    BF_KEY bf_key;
    BF_set_key(&bf_key,sizeof(data),data);
    int len=plain.size();
    unsigned char* enc_text=(unsigned char*)calloc(1,len+1);//申请的空间要比实际长度大1,否则为8的奇数倍时会出现问题
    unsigned char* dec_text=(unsigned char*)calloc(1,len+1);
    memset(ivec,0,sizeof(ivec));
    int num=0;
    BF_cfb64_encrypt((unsigned char*)plain.c_str(),enc_text,plain.size(),&bf_key,ivec,&num,BF_ENCRYPT);
    Print(enc_text,len);
    memset(ivec,0,sizeof(ivec));
    num=0;
    BF_cfb64_encrypt(enc_text,dec_text,len,&bf_key,ivec,&num,BF_DECRYPT);
    cout<<"dec:"<<dec_text<<endl;
}


void BF_OFB(const string& plain)
{
    cout<<"plain size:"<<plain.size()<<endl;
    unsigned char data[]="abcdef";
    unsigned char ivec[8];
    BF_KEY bf_key;
    BF_set_key(&bf_key,sizeof(data),data);
    int len=plain.size();
    unsigned char* enc_text=(unsigned char*)calloc(1,len+1);//申请的空间要比实际长度大1,否则为8的奇数倍时会出现问题
    unsigned char* dec_text=(unsigned char*)calloc(1,len+1);
    memset(ivec,0,sizeof(ivec));
    int num=0;
    BF_ofb64_encrypt((unsigned char*)plain.c_str(),enc_text,plain.size(),&bf_key,ivec,&num);
    Print(enc_text,len);
    memset(ivec,0,sizeof(ivec));
    num=0;
    BF_ofb64_encrypt(enc_text,dec_text,len,&bf_key,ivec,&num);
    cout<<"dec:"<<dec_text<<endl;
}

int main(int argc,char* argv[])
{
    string plain(argv[1]);
    BF_CBC(plain);
    //BF_CFB(plain);
    //BF_OFB(plain);
}

