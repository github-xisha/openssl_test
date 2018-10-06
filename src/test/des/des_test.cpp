/********************************************************************
  > File Name: des_test.cpp
  > Author:xisha
  > Mail: 1540348087@qq.com
  > Created Time: 2018年10月06日 星期六 23时05分48秒
********************************************************************/

#include <iostream>
#include <cassert>  
#include <string>    
#include <vector>    
#include <string.h>    
#include "openssl/des.h"    

// 加密 ecb模式    
std::string DES_ENCRYPT_ECB(const std::string &clearText, const std::string &key)  
{  
    std::string cipherText; // 密文    
  
    DES_cblock keyEncrypt;  
    memset(keyEncrypt, 0, 8);  
  
    // 构造补齐后的密钥    
    if (key.length() <= 8)  
        memcpy(keyEncrypt, key.c_str(), key.length());  
    else  
        memcpy(keyEncrypt, key.c_str(), 8);  
  
    // 密钥置换    
    DES_key_schedule keySchedule;  
    DES_set_key_unchecked(&keyEncrypt, &keySchedule);  
  
    // 循环加密，每8字节一次    
    const_DES_cblock inputText;  
    DES_cblock outputText;  
    std::vector<unsigned char> vecCiphertext;  
    unsigned char tmp[8];  
  
    for (int i = 0; i < clearText.length() / 8; i++)  
    {  
        memcpy(inputText, clearText.c_str() + i * 8, 8);  
        DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_ENCRYPT);  
        memcpy(tmp, outputText, 8);  
  
        for (int j = 0; j < 8; j++)  
            vecCiphertext.push_back(tmp[j]);  
    }  
  
    if (clearText.length() % 8 != 0)  
    {  
        int tmp1 = clearText.length() / 8 * 8;  
        int tmp2 = clearText.length() - tmp1;  
        memset(inputText, 0, 8);  
        memcpy(inputText, clearText.c_str() + tmp1, tmp2);  
        // 加密函数    
        DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_ENCRYPT);  
        memcpy(tmp, outputText, 8);  
  
        for (int j = 0; j < 8; j++)  
            vecCiphertext.push_back(tmp[j]);  
    }  
  
    cipherText.clear();  
    cipherText.assign(vecCiphertext.begin(), vecCiphertext.end());  
  
    return cipherText;  
}  
  
// 解密 ecb模式    
std::string DES_DECRYPT_ECB(const std::string &cipherText, const std::string &key)  
{  
    std::string clearText; // 明文    
  
    DES_cblock keyEncrypt;  
    memset(keyEncrypt, 0, 8);  
  
    if (key.length() <= 8)  
        memcpy(keyEncrypt, key.c_str(), key.length());  
    else  
        memcpy(keyEncrypt, key.c_str(), 8);  
  
    DES_key_schedule keySchedule;  
    DES_set_key_unchecked(&keyEncrypt, &keySchedule);  
  
    const_DES_cblock inputText;  
    DES_cblock outputText;  
    std::vector<unsigned char> vecCleartext;  
    unsigned char tmp[8];  
  
    for (int i = 0; i < cipherText.length() / 8; i++)  
    {  
        memcpy(inputText, cipherText.c_str() + i * 8, 8);  
        DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_DECRYPT);  
        memcpy(tmp, outputText, 8);  
  
        for (int j = 0; j < 8; j++)  
            vecCleartext.push_back(tmp[j]);  
    }  
  
    if (cipherText.length() % 8 != 0)  
    {  
        int tmp1 = cipherText.length() / 8 * 8;  
        int tmp2 = cipherText.length() - tmp1;  
        memset(inputText, 0, 8);  
        memcpy(inputText, cipherText.c_str() + tmp1, tmp2);  
        // 解密函数    
        DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_DECRYPT);  
        memcpy(tmp, outputText, 8);  
  
        for (int j = 0; j < 8; j++)  
            vecCleartext.push_back(tmp[j]);  
    }  
  
    clearText.clear();  
    clearText.assign(vecCleartext.begin(), vecCleartext.end());  
  
    return clearText;  
}  


int main(int argc,char* argv[])
{
    if(2!=argc)
    {
        std::cout<<"./des_test string"<<std::endl;
        return -1;
    }
    std::string srcText(argv[1]);
    std::string desKey = "12345";  
    std::string encryptText = DES_ENCRYPT_ECB(srcText, desKey);  
    std::cout << "加密字符： " << std::endl;  
    std::cout << encryptText << std::endl;  
    std::string decryptText = DES_DECRYPT_ECB(encryptText, desKey);  
    std::cout << "解密字符： " << std::endl;  
    std::cout << decryptText << std::endl; 
}

