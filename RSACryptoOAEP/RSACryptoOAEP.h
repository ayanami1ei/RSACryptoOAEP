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

class  RSACryptoOAEP {
public:
    RSACryptoOAEP();

    RSACryptoOAEP(const std::string& pubk, const std::string& privk);

    ~RSACryptoOAEP();

    void set_key_path(const std::string& pupp, const std::string& prpp);

    /**
     * ���� RSA ��Կ�Բ�д�� pem �ļ�
     *
     * @param 2048          ��Կ����
     * @param privPath      ˽Կ�ļ�·����pem, PKCS#8��
     * @param pubPath       ��Կ�ļ�·����pem, SubjectPublicKeyInfo��
     * @param passphrase    ��˽Կ�����루��Ϊ nullptr ��ʾ�����ܣ�
     */
    void generateKeyPair(const std::string& privPath,
        const std::string& pubPath);

    /**
     * ���� RSA ��Կ�Բ�д�� pem �ļ�
     *
     * @param 2048          ��Կ����
     * @param passphrase    ��˽Կ�����루��Ϊ nullptr ��ʾ�����ܣ�
     */
    void generateKeyPair();



    /*���ܺ���*/
    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plain);

    /*���ܺ���*/
    std::vector<unsigned char> encrypt(const std::string& plain);

    std::vector<unsigned char> encrypt(const std::string& key, const std::vector<unsigned char>& plain);

    /*���ܺ���*/
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& cipher);

    /*���ܺ���*/
    std::vector<unsigned char> decrypt(const std::string& cipher);

    std::vector<unsigned char> decrypt(const std::string& key, const std::vector<unsigned char>& cipher);

    /*дǩ��*/
    std::vector<unsigned char> signature(const std::vector<unsigned char>& orig);
    
    /*��ǩ��*/
    bool designature(const std::vector<unsigned char>& orig,
        const std::vector<unsigned char>& cipher);
    
    /*��ӡ����*/
    void print_plain(std::vector<unsigned char> cipher);

    /*��ӡ����*/
    void print_cipher(std::vector<unsigned char> plain);

    /*�������Ļ�����*/
    void save(const std::string& filename, const std::vector<unsigned char>& data);

    /*���ļ���ȡ���Ļ�����*/
    std::vector<unsigned char> read_from_file(const std::string& filename);

private:
    class Impl;      // ǰ�����������������и� Impl ����
    Impl* pImpl;     // ʵ��ָ�룺ʵ��ϸ�ڷ�����

};

#endif
