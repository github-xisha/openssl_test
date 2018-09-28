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
    unsigned char key[] = "0123456789abcdef";
    unsigned char iv[]  = "1234567887654321";
    
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    //EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv,do_encrypt);
    //EVP_CipherInit_ex(ctx, EVP_get_cipherbynid(419), NULL, key, iv,do_encrypt);
    //EVP_CipherInit_ex(ctx, EVP_get_cipherbynid(NID_aes_128_cbc), NULL, key, iv,do_encrypt);
    //EVP_CipherInit_ex(ctx, EVP_get_cipherbyname(SN_aes_128_cbc), NULL, key, iv,do_encrypt);
    EVP_CipherInit_ex(ctx, EVP_get_cipherbyname(LN_aes_128_cbc), NULL, key, iv,do_encrypt);
    //if(!EVP_CIPHER_CTX_set_padding(ctx,0)) cout<<"set padding error"<<endl;

    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);
    //cout<<"nid="<<EVP_CIPHER_nid(EVP_aes_128_cbc())<<endl;
    //cout<<"nid="<<EVP_CIPHER_CTX_nid(ctx)<<endl;

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
    if(argc!=4)
    {
        cout<<"input ./evp_test path1 path2 path3"<<endl;
        return -1;
    }
    FILE* enc_in=fopen(argv[1],"r");
    FILE* enc_out=fopen(argv[2],"w+");
    int enc=1;
    int ret=do_crypt(enc_in,enc_out,enc);
    fclose(enc_in);
    fclose(enc_out);
    FILE* dec_in=fopen(argv[2],"r");
    FILE* dec_out=fopen(argv[3],"w+");
    enc=0;
    do_crypt(dec_in,dec_out,enc);
    fclose(dec_in);
    fclose(dec_out);
    return 0;
}
