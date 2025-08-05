#pragma once

#define _CRT_SECURE_NO_WARNINGS

#ifndef RSACRYPTOOAEP_H  
#define RSACRYPTOOAEP_H  

#include <string>
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <vector>
#include<fstream> 

#ifndef BUILD_DLL
#define DLL_API  __declspec(dllexport)
#else
#define DLL_API  __declspec(dllimport)
#endif

class DLL_API RSACryptoOAEP {
public:
    RSACryptoOAEP();

    RSACryptoOAEP(std::string PuPP, std::string PrPP);

    ~RSACryptoOAEP();

    void set_key_path(std::string pupp, std::string prpp);

    /**
     * 生成 RSA 密钥对并写入 pem 文件
     *
     * @param 2048          密钥长度
     * @param privPath      私钥文件路径（pem, PKCS#8）
     * @param pubPath       公钥文件路径（pem, SubjectPublicKeyInfo）
     * @param passphrase    给私钥加密码（可为 nullptr 表示不加密）
     */
    void generateKeyPair(const std::string& privPath,
        const std::string& pubPath);

    /**
     * 生成 RSA 密钥对并写入 pem 文件
     *
     * @param 2048          密钥长度
     * @param passphrase    给私钥加密码（可为 nullptr 表示不加密）
     */
    void generateKeyPair();



    /*加密函数*/
    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plain);

    /*加密函数*/
    std::vector<unsigned char> encrypt(const std::string& plain);

    std::vector<unsigned char> encrypt(const std::string& keypath, const std::vector<unsigned char>& plain);

    /*解密函数*/
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& cipher);

    /*解密函数*/
    std::vector<unsigned char> decrypt(const std::string& cipher);

    std::vector<unsigned char> decrypt(const std::string& keypath, const std::vector<unsigned char>& cipher);

    /*打印密文*/
    void print_plain(std::vector<unsigned char> cipher);

    /*打印明文*/
    void print_cipher(std::vector<unsigned char> plain);

    /*保存明文或密文*/
    void save(const std::string& filename, const std::vector<unsigned char>& data);

    /*从文件读取明文或密文*/
    std::vector<unsigned char> read_from_file(const std::string& filename);

private:
    class Impl;      // 前向声明：声明里面有个 Impl 类型
    Impl* pImpl;     // 实际指针：实现细节放里面

};

#endif
