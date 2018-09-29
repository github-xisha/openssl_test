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

/*
 * 函数：AES_ecb_encrypt()
 * 参数：in    长度为16的整数倍
 *       out   长度为16的整数倍
 *       key   由128位、192位和256位的ukey生成
 */

void AES_ECB(string plain)
{
    //enum UKeyBits ukeybits=aes_128_cbc;
    //enum UKeyBits ukeybits=aes_192_cbc;
    enum UKeyBits ukeybits=aes_256_cbc;
    unsigned char ukey[ukeybits/8];
    unsigned char* plain_text=NULL;
    unsigned char* enc_text=NULL;
    unsigned char* dec_text=NULL;
    AES_KEY key;
    int len=0;
    if(plain.size()%AES_BLOCK_SIZE==0)
    {
        len=plain.size();
    }else{
        len=(plain.size()/AES_BLOCK_SIZE+1)*AES_BLOCK_SIZE;
    }
    plain_text=(unsigned char*)calloc(1,len);
    enc_text=(unsigned char*)calloc(1,len);
    dec_text=(unsigned char*)calloc(1,len);
    unsigned char* pt=plain_text;
    unsigned char* et=enc_text;
    unsigned char* dt=dec_text;

    strncpy((char*)plain_text,plain.c_str(),plain.size());
    cout<<"ukey:";
    for(int i=0;i<ukeybits/8;++i)
    {
        ukey[i]=65+i;
        cout<<ukey[i];
    }
    cout<<endl;
    AES_set_encrypt_key(ukey,ukeybits,&key);
    int i=0;
    while(i<len)
    {
       AES_ecb_encrypt(pt,et,&key,AES_ENCRYPT);
       //AES_encrypt(pt,et,&key);
       pt+=AES_BLOCK_SIZE;
       et+=AES_BLOCK_SIZE;
       i+=AES_BLOCK_SIZE;
    }
    AES_set_decrypt_key(ukey,ukeybits,&key);
    i=0;
    et=enc_text;
    while(i<len)
    {
       AES_ecb_encrypt(et,dt,&key,AES_DECRYPT);
       //AES_decrypt(et,dt,&key);
       et+=AES_BLOCK_SIZE;
       dt+=AES_BLOCK_SIZE;
       i+=AES_BLOCK_SIZE;
    }
    cout<<"dec_text:"<<dec_text<<endl;
}

/*
 * 函数：AES_cbc_encrypt()
 * 参数：in    长度任意
 *       out   长度不小于in,且是16的整数倍(若不是,会有访问越界风险)
 *       key   由128位、192位和256位的ukey生成
 *       ivec  128位
 */
void AES_CBC(string plain_text)
{
    //enum UKeyBits ukeybits=aes_128_cbc;
    //enum UKeyBits ukeybits=aes_192_cbc;
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
    cout<<"ukey:";
    for(int i=0;i<ukeybits/8;++i)
    {
        ukey[i]=65+i;
        cout<<ukey[i];
    }
    cout<<endl;
    //memset(ivec,0,sizeof(ivec));
    cout<<"ivec:";
    for(int i=0;i<AES_BLOCK_SIZE;++i)
    {
        ivec[i]=65+i;
        cout<<ivec[i];
    }
    cout<<endl;
    AES_set_encrypt_key(ukey,ukeybits,&key);
    AES_cbc_encrypt((unsigned char*)plain_text.c_str(),enc_text,plain_text.size(),&key,ivec,AES_ENCRYPT);
    Print(enc_text,len);
    //memset(ivec,0,sizeof(ivec));
    for(int i=0;i<AES_BLOCK_SIZE;++i)
    {
        ivec[i]=65+i;
    }
    AES_set_decrypt_key(ukey,ukeybits,&key);
    AES_cbc_encrypt(enc_text,dec_text,len,&key,ivec,AES_DECRYPT);
    cout<<"dec_text:"<<dec_text<<endl;
    free(enc_text);
    free(dec_text);
    enc_text=NULL;
    dec_text=NULL;
}


/*
 * 函数：AES_cfb128_encrypt()
 * 参数：in    长度任意
 *       out   长度和in保持一致
 *       key   由128位、192位和256位的ukey生成
 *       ivec  128位
 */
void AES_CFB128(string plain_text)
{
    //enum UKeyBits ukeybits=aes_128_cbc;
    //enum UKeyBits ukeybits=aes_192_cbc;
    enum UKeyBits ukeybits=aes_256_cbc;
    unsigned char ukey[ukeybits/8];
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned char* enc_text=NULL;
    unsigned char* dec_text=NULL;
    AES_KEY key;
    int len=0;
    len=plain_text.size();
    enc_text=(unsigned char*)calloc(1,len);
    dec_text=(unsigned char*)calloc(1,len);
    cout<<"ukey:";
    for(int i=0;i<ukeybits/8;++i)
    {
        ukey[i]=65+i;
        printf("%c",ukey[i]);
    }
    cout<<endl;
    cout<<"ivec:";
    for(int i=0;i<AES_BLOCK_SIZE;++i)
    {
        ivec[i]=65+i;
        printf("%c",ivec[i]);
    }
    cout<<endl;
    //memset(ivec,0,sizeof(ivec));
    AES_set_encrypt_key(ukey,ukeybits,&key);
    int num=0;
    AES_cfb128_encrypt((unsigned char*)plain_text.data(),enc_text,plain_text.size(),&key,ivec,&num,AES_ENCRYPT);
    //memset(ivec,0,sizeof(ivec));
    for(int i=0;i<AES_BLOCK_SIZE;++i)
    {
        ivec[i]=65+i;
    }
    //AES_set_decrypt_key(ukey,ukeybits,&key);//为什么在这里不需要设置解密密钥
    //因为在AES_cfb128_encrypt()的底层只调用AES_encrypt()函数对初始化向量ivec进行加密,未使用AES_decrypt(),故不需要设置解密密钥
    num=0;
    AES_cfb128_encrypt(enc_text,dec_text,len,&key,ivec,&num,AES_DECRYPT);
    cout<<"dec_text:"<<dec_text<<endl;
    free(enc_text);
    free(dec_text);
    enc_text=NULL;
    dec_text=NULL;
}

//暂未测试通过！！！
void AES_CFB1(string plain_text)
{
    enum UKeyBits ukeybits=aes_128_cbc;
    unsigned char ukey[ukeybits/8];
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned char* enc_text=NULL;
    unsigned char* dec_text=NULL;
    AES_KEY key;
    int len=0;
    len=plain_text.size();
    enc_text=(unsigned char*)calloc(1,len);
    dec_text=(unsigned char*)calloc(1,len);
    cout<<"ukey:";
    for(int i=0;i<ukeybits/8;++i)
    {
        ukey[i]=65+i;
        printf("%c",ukey[i]);
    }
    cout<<endl;
    cout<<"ivec:";
    for(int i=0;i<AES_BLOCK_SIZE;++i)
    {
        ivec[i]=65+i;
        printf("%c",ivec[i]);
    }
    cout<<endl;
    //memset(ivec,0,sizeof(ivec));
    AES_set_encrypt_key(ukey,ukeybits,&key);
    int num=0;
    AES_cfb1_encrypt((unsigned char*)plain_text.data(),enc_text,plain_text.size(),&key,ivec,&num,AES_ENCRYPT);
    //memset(ivec,0,sizeof(ivec));
    for(int i=0;i<AES_BLOCK_SIZE;++i)
    {
        ivec[i]=65+i;
    }
    num=0;
    AES_cfb1_encrypt(enc_text,dec_text,len,&key,ivec,&num,AES_DECRYPT);
    cout<<"dec_text:"<<dec_text<<endl;
    free(enc_text);
    free(dec_text);
    enc_text=NULL;
    dec_text=NULL;
}

/*
 * 函数：AES_ofb128_encrypt()
 * 参数：in    长度任意
 *       out   长度和in保持一致
 *       key   由128位、192位和256位的ukey生成
 *       ivec  128位
 */
void AES_OFB128(string plain_text)
{
    //enum UKeyBits ukeybits=aes_128_cbc;
    //enum UKeyBits ukeybits=aes_192_cbc;
    enum UKeyBits ukeybits=aes_256_cbc;
    unsigned char ukey[ukeybits/8];
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned char* enc_text=NULL;
    unsigned char* dec_text=NULL;
    AES_KEY key;
    int len=0;
    len=plain_text.size();
    enc_text=(unsigned char*)calloc(1,len);
    dec_text=(unsigned char*)calloc(1,len);
    cout<<"ukey:";
    for(int i=0;i<ukeybits/8;++i)
    {
        ukey[i]=65+i;
        printf("%c",ukey[i]);
    }
    cout<<endl;
    cout<<"ivec:";
    for(int i=0;i<AES_BLOCK_SIZE;++i)
    {
        ivec[i]=65+i;
        printf("%c",ivec[i]);
    }
    cout<<endl;
    //memset(ivec,0,sizeof(ivec));
    AES_set_encrypt_key(ukey,ukeybits,&key);
    int num=0;
    AES_ofb128_encrypt((unsigned char*)plain_text.data(),enc_text,plain_text.size(),&key,ivec,&num);
    //memset(ivec,0,sizeof(ivec));
    for(int i=0;i<AES_BLOCK_SIZE;++i)
    {
        ivec[i]=65+i;
    }
    num=0;
    AES_ofb128_encrypt(enc_text,dec_text,len,&key,ivec,&num);
    cout<<"dec_text:"<<dec_text<<endl;
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
    //AES_ECB(argv[1]);
    //AES_CBC(argv[1]);
    //AES_CFB128(argv[1]);
    AES_CFB1(argv[1]);
    //AES_OFB128(argv[1]);
}



