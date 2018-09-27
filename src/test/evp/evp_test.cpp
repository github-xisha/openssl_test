/********************************************************************
  > File Name: evp_test.cpp
  > Author:xisha
  > Mail: 1540348087@qq.com
  > Created Time: 2018年09月27日 星期四 19时45分23秒
********************************************************************/

#include <iostream>
#include <openssl/evp.h>
#include <stdio.h>

using namespace std;

int do_crypt(FILE *in, FILE *out, int do_encrypt)
{
    unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    EVP_CIPHER_CTX *ctx;
    unsigned char key[] = "0123456789abcdef";
    unsigned char iv[]  = "1234567887654321";
    
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv,do_encrypt);
    
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);
    
    for(;;)
    {
        inlen = fread(inbuf, 1, 1024, in);
        if (inlen <= 0) break;
        if(!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen))
        {
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        fwrite(outbuf, 1, outlen, out);
    }
    if(!EVP_CipherFinal_ex(ctx, outbuf, &outlen))
    {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    fwrite(outbuf, 1, outlen, out);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}


int main(int argc,char* argv[])
{
    if(argc!=3)
    {
        cout<<"input ./evp_test path1 path2"<<endl;
        return -1;
    }
    FILE* in=fopen(argv[1],"r");
    FILE* out=fopen(argv[2],"w+");
    int enc=1;
    int ret=do_crypt(in,out,enc);
    return 0;
}
