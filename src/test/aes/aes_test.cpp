/********************************************************************
  > File Name: aes_test.cpp
  > Author:xisha
  > Mail: 1540348087@qq.com
  > Created Time: 2018年09月28日 星期五 14时37分14秒
********************************************************************/

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
using namespace std;

enum UKeyBits{
    aes_128_cbc=128,
    aes_192_cbc=192,
    aes_256_cbc=256
};

void Print(unsigned char* text,int len)
{
    for(int i=0;i<len;++i)
    {
        printf("%02x",text[i]);
    }
    printf("\n");
}

void AES_128_CBC(string plain_text)
{
    UKeyBits ukeybits=aes_128_cbc;
    unsigned char ukey[ukeybits/8];
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned char* enc_text=NULL;
    unsigned char* dec_text=NULL;
    AES_KEY key;
    int len=0;
    if(plain_text.size()%AES_BLOCK_SIZE==0)
    {
        len=plain_text.size();
    }else{
        len=(plain_text.size()/AES_BLOCK_SIZE+1)*AES_BLOCK_SIZE;
    }
    enc_text=(unsigned char*)calloc(1,len);
    dec_text=(unsigned char*)calloc(1,len);
    cout<<"ukey:";
    for(int i=0;i<ukeybits/8;++i)
    {
        //ukey[i]=32+i;
        ukey[i]=65+i;
        cout<<ukey[i];
    }
    cout<<endl;
    memset(ivec,0,sizeof(ivec));
    AES_set_encrypt_key(ukey,ukeybits,&key);
    AES_cbc_encrypt((unsigned char*)plain_text.c_str(),enc_text,plain_text.size(),&key,ivec,AES_ENCRYPT);
    Print(enc_text,len);
    memset(ivec,0,sizeof(ivec));
    AES_set_decrypt_key(ukey,ukeybits,&key);
    AES_cbc_encrypt(enc_text,dec_text,len,&key,ivec,AES_DECRYPT);
    cout<<"128 dec_text:"<<dec_text<<endl;
    free(enc_text);
    free(dec_text);
    enc_text=NULL;
    dec_text=NULL;
}

void AES_192_CBC(string plain_text)
{
    enum UKeyBits ukeybits=aes_192_cbc;
    unsigned char ukey[ukeybits/8];
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned char* enc_text=NULL;
    unsigned char* dec_text=NULL;
    AES_KEY key;
    int len=0;
    if(plain_text.size()%AES_BLOCK_SIZE==0)
    {
        len=plain_text.size();
    }else{
        len=(plain_text.size()/AES_BLOCK_SIZE+1)*AES_BLOCK_SIZE;
    }
    enc_text=(unsigned char*)calloc(1,len);
    dec_text=(unsigned char*)calloc(1,len);
    for(int i=0;i<24;++i)
    {
        ukey[i]=65+i;
    }
    memset(ivec,0,sizeof(ivec));
    AES_set_encrypt_key(ukey,ukeybits,&key);
    AES_cbc_encrypt((unsigned char*)plain_text.c_str(),enc_text,plain_text.size(),&key,ivec,AES_ENCRYPT);
    Print(enc_text,len);
    memset(ivec,0,sizeof(ivec));
    AES_set_decrypt_key(ukey,ukeybits,&key);
    AES_cbc_encrypt(enc_text,dec_text,len,&key,ivec,AES_DECRYPT);
    cout<<"192 dec_text:"<<dec_text<<endl;
    free(enc_text);
    free(dec_text);
    enc_text=NULL;
}


void AES_256_CBC(string plain_text)
{
    enum UKeyBits ukeybits=aes_256_cbc;
    unsigned char ukey[ukeybits/8];
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned char* enc_text=NULL;
    unsigned char* dec_text=NULL;
    AES_KEY key;
    int len=0;
    if(plain_text.size()%AES_BLOCK_SIZE==0)
    {
        len=plain_text.size();
    }else{
        len=(plain_text.size()/AES_BLOCK_SIZE+1)*AES_BLOCK_SIZE;
    }
    enc_text=(unsigned char*)calloc(1,len);
    dec_text=(unsigned char*)calloc(1,len);
    for(int i=0;i<ukeybits/8;++i)
    {
        ukey[i]=65+i;
    }
    memset(ivec,0,sizeof(ivec));
    AES_set_encrypt_key(ukey,ukeybits,&key);
    AES_cbc_encrypt((unsigned char*)plain_text.c_str(),enc_text,plain_text.size(),&key,ivec,AES_ENCRYPT);
    Print(enc_text,len);
    memset(ivec,0,sizeof(ivec));
    AES_set_decrypt_key(ukey,ukeybits,&key);
    AES_cbc_encrypt(enc_text,dec_text,len,&key,ivec,AES_DECRYPT);
    cout<<"256 dec_text:"<<dec_text<<endl;
    free(enc_text);
    free(dec_text);
    enc_text=NULL;
    dec_text=NULL;
}

void AES_CFB128(string plain_text)
{
    enum UKeyBits ukeybits=aes_128_cbc;
    unsigned char ukey[ukeybits/8];
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned char* enc_text=NULL;
    unsigned char* dec_text=NULL;
    AES_KEY key;
    int len=0;
    
    //if(plain_text.size()%AES_BLOCK_SIZE==0)
    //{
    //    len=plain_text.size();
    //}else{
    //    //len=(plain_text.size()/AES_BLOCK_SIZE+1)*AES_BLOCK_SIZE;
    //    len=plain_text.size();
    //}
    len=plain_text.size();
    enc_text=(unsigned char*)calloc(1,len);
    dec_text=(unsigned char*)calloc(1,len);
    for(int i=0;i<ukeybits/8;++i)
    {
        ukey[i]=65+i;
        //printf("%c",ukey[i]);
    }
    for(int i=0;i<ukeybits/8;++i)
    {
        ivec[i]=65+i;
        //printf("%c",ivec[i]);
    }
    //memset(ivec,0,sizeof(ivec));
    AES_set_encrypt_key(ukey,ukeybits,&key);
    int num=0;
    AES_cfb128_encrypt((unsigned char*)plain_text.data(),enc_text,plain_text.size(),&key,ivec,&num,AES_ENCRYPT);
    //Print(enc_text,len);
    //cout<<"num="<<num<<endl;
    //memset(ivec,0,sizeof(ivec));
    for(int i=0;i<ukeybits/8;++i)
    {
        ivec[i]=65+i;
    }
    //AES_set_decrypt_key(ukey,ukeybits,&key);//为什么在这里不需要设置解密密钥
    num=0;
    AES_cfb128_encrypt(enc_text,dec_text,len,&key,ivec,&num,AES_DECRYPT);
    //cout<<"num="<<num<<endl;
    cout<<"128 dec_text:"<<dec_text<<endl;
    //Print(dec_text,len);
    free(enc_text);
    free(dec_text);
    enc_text=NULL;
    dec_text=NULL;
}


int main(int argc,char* argv[])
{
    if(2!=argc)
    {
        cout<<"./aes_test string"<<endl;
        return -1;
    }
    //AES_128_CBC(argv[1]);
    //AES_192_CBC(argv[1]);
    //AES_256_CBC(argv[1]);
    AES_CFB128(argv[1]);
}



