#pragma once

#define _CRT_SECURE_NO_WARNINGS

#ifndef RSACRYPTOOAEP_H  
#define RSACRYPTOOAEP_H  

#include <string>
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <vector>

#ifdef MYRSA_EXPORTS
#define MYRSA_API __declspec(dllexport)
#else
#define MYRSA_API __declspec(dllimport)
#endif

class MYRSA_API RSACryptoOAEP {
public:
    RSACryptoOAEP();

    RSACryptoOAEP(std::string PuPP, std::string PrPP);

    ~RSACryptoOAEP();

    void set_key_path(std::string pupp, std::string prpp);

    /**
     * 生成 RSA 密钥对并写入 PEM 文件
     *
     * @param 2048          密钥长度
     * @param privPath      私钥文件路径（PEM, PKCS#8）
     * @param pubPath       公钥文件路径（PEM, SubjectPublicKeyInfo）
     * @param passphrase    给私钥加密码（可为 nullptr 表示不加密）
     */
    void generateKeyPair(const std::string& privPath,
        const std::string& pubPath,
        const char* passphrase = nullptr);

    /**
     * 生成 RSA 密钥对并写入 PEM 文件
     *
     * @param 2048          密钥长度
     * @param passphrase    给私钥加密码（可为 nullptr 表示不加密）
     */
    void generateKeyPair(const char* passphrase = nullptr);



    /*加密函数*/
    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plain);

    /*加密函数*/
    std::vector<unsigned char> encrypt(const std::string& plain);

    /*解密函数*/
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& cipher);

    /*解密函数*/
    std::vector<unsigned char> decrypt(const std::string& cipher);

    /*打印密文*/
    void print_plain(std::vector<unsigned char>& cipher);

    /*打印明文*/
    void print_cipher(std::vector<unsigned char>& plain);

private:
    class Impl;      // 前向声明：声明里面有个 Impl 类型
    Impl* pImpl;     // 实际指针：实现细节放里面
    
};

#endif
