//#define BUILD_DLL

#include "RSACryptoOAEP.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/provider.h>

class RSACryptoOAEP::Impl
{
private:
    

public:

    void init_openssl() {
        OSSL_PROVIDER* legacy = OSSL_PROVIDER_load(nullptr, "legacy");
        OSSL_PROVIDER* default_provider = OSSL_PROVIDER_load(nullptr, "default");
        if (!default_provider) {
            std::cerr << "Failed to load default OpenSSL provider\n";
            exit(1);
        }
    }
    std::string privatekey, publickey;
    std::string PrivpemPath, PubpemPath;
    EVP_PKEY* pub;
    EVP_PKEY* priv;

    void throwIf(bool bad, const char* msg);

    /*辅助输出*/
    std::string base64Encode(const std::vector<unsigned char>& data);

    /*公私密钥不匹配时报错*/
    void openssl_error();

    /*加载公钥*/
    EVP_PKEY* load_pub(const std::string& path);
    EVP_PKEY* load_pub();

    /*加载私钥*/
    EVP_PKEY* load_priv(const std::string& path);
    EVP_PKEY* load_priv();

    /*初始化公钥私钥*/
    void init();

    /**
     * 生成 RSA 密钥对并写入 pem 文件
     *
     * @param 2048          密钥长度
     * @param privPath      私钥文件路径（pem, PKCS#8）
     * @param pubPath       公钥文件路径（pem, SubjectPublicKeyInfo）
     * @param passphrase    给私钥加密码（可为 nullptr 表示不加密）
     */
    void generateRSAKeyPair(const std::string& privPath,
        const std::string& pubPath,
        const char* passphrase = nullptr);

    /**
     * 生成 RSA 密钥对并写入 pem 文件
     *
     * @param 2048          密钥长度
     * @param passphrase    给私钥加密码（可为 nullptr 表示不加密）
     */
    void generateRSAKeyPair(const char* passphrase = nullptr);

    /*加密函数*/
    std::vector<unsigned char> rsa_encrypt_oaep(const std::vector<unsigned char>& plain);

    std::vector<unsigned char> rsa_encrypt_oaep(const std::string& key, const std::vector<unsigned char>& cipher);

    /*解密函数*/
    std::vector<unsigned char> rsa_decrypt_oaep(const std::vector<unsigned char>& cipher);

    std::vector<unsigned char> rsa_decrypt_oaep(const std::string& key, const std::vector<unsigned char>& cipher);

    void write_bytes_to_file(const std::string& filename, const std::vector<unsigned char>& data);

    std::vector<unsigned char> read_bytes_from_file(const std::string& filename);

    bool is_file_equal(const std::string& file1, const std::string& file2);

    bool is_equal(const std::vector<unsigned char>& a, const std::vector<unsigned char>& b);

    std::vector<unsigned char> signature(const std::vector<unsigned char>& orig);

    bool designature(const std::vector<unsigned char>& orig,
        const std::vector<unsigned char>& cipher);
};

// private:
void RSACryptoOAEP::Impl::throwIf(bool bad, const char* msg)
{
    if (bad)
    {
        ERR_print_errors_fp(stderr);

#if defined _RELEASE
        std::cerr << "[Error]" << msg << std::endl;
        abort(); // 建议加上
#elif defined _DEBUG
        throw std::runtime_error(msg);
#endif
    }
}

std::string RSACryptoOAEP::Impl::base64Encode(const std::vector<unsigned char>& data)
{
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    // 不换行（默认会换行）
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bio);

    BIO_write(b64, data.data(), data.size());
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bufferPtr);

    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(b64);
    return result;
}

void RSACryptoOAEP::Impl::openssl_error()
{
    ERR_print_errors_fp(stderr);
#if defined _REALESEASE
    abort();
#elif defined _DEBUG
    std::cerr << "OpenSSL 错误" << std::endl;
#endif
}

EVP_PKEY* RSACryptoOAEP::Impl::load_pub(const std::string& path)
{
#if 1
    try
    {
        FILE* file = fopen(path.c_str(), "rb");
        if (!file)
            generateRSAKeyPair(PrivpemPath, PubpemPath);
        file = fopen(path.c_str(), "rb");
        EVP_PKEY* pkey = d2i_PUBKEY_fp(file, nullptr);
        fclose(file);
        if (!pkey)
            openssl_error();
        return pkey;

        /*FILE* fp = fopen(path.c_str(), "rb");
        if (!fp)
        {
            generateRSAKeyPair(PrivpemPath,PubpemPath);
        }

        fp = fopen(path.c_str(), "rb");
        EVP_PKEY* k = der_read_PUBKEY(fp, nullptr, nullptr, nullptr);
        fclose(fp);
        if (!k) throw std::runtime_error("读取公钥失败");
        return k;*/
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[Error] " << ex.what() << '\n';

        return nullptr;
    }
#endif
}

EVP_PKEY* RSACryptoOAEP::Impl::load_pub()
{
    BIO* bio = BIO_new_mem_buf(publickey.data(), static_cast<int>(publickey.size()));
    pub = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);

    if (!pub) {
        // 解析失败，处理错误

		std::cerr << "Failed to load public key from memory buffer.\n";
        return nullptr;
    }

    if (EVP_PKEY_base_id(pub) != EVP_PKEY_RSA) {
        std::cerr << "不是 RSA 密钥" << std::endl;
    }


    BIO_free(bio);
    return pub;
}

EVP_PKEY* RSACryptoOAEP::Impl::load_priv(const std::string& path)
{
    FILE* file = fopen(path.c_str(), "rb");
    if (!file)
        generateRSAKeyPair(PrivpemPath, PubpemPath);
    file = fopen(path.c_str(), "rb");
    EVP_PKEY* pkey = d2i_PrivateKey_fp(file, nullptr);
    fclose(file);
    if (!pkey)
        openssl_error();
    return pkey;

    /*FILE* fp = fopen(path.c_str(), "rb");
    if (!fp)
    {

    }

    fp = fopen(path.c_str(), "rb");
    EVP_PKEY* k = pem_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!k) throw std::runtime_error("读取私钥失败");
    return k;*/
}

EVP_PKEY* RSACryptoOAEP::Impl::load_priv()
{
    BIO* bio = BIO_new_mem_buf(privatekey.data(), static_cast<int>(privatekey.size()));
    priv = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);

    if (EVP_PKEY_base_id(priv) != EVP_PKEY_RSA) {
        std::cerr << "不是 RSA 密钥" << std::endl;
    }

    if (!priv) {
        // 解析失败，处理错误

        std::cerr << "Failed to load private key from memory buffer.\n";
        return nullptr;
    }

    BIO_free(bio);

    return priv;
}

void RSACryptoOAEP::Impl::init()
{
    try
    {
        //pub = load_pub(PubpemPath);
		pub = load_pub();
        if (!pub)
            throw std::runtime_error("无法打开公钥文件");
        //priv = load_priv(PrivpemPath);
		priv = load_priv();
        if (!priv)
            throw std::runtime_error("无法打开私钥文件");
    }
    catch (std::exception& ex)
    {
        std::cerr << "[Error]" << ex.what() << std::endl;
    }
}

std::vector<unsigned char> RSACryptoOAEP::Impl::rsa_encrypt_oaep(const std::vector<unsigned char>& plain)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pub, nullptr);
    if (!ctx)
        openssl_error();

    if (EVP_PKEY_encrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        openssl_error();

    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, plain.data(), plain.size()) <= 0)
        openssl_error();

    std::vector<unsigned char> cipher(outlen);
    if (EVP_PKEY_encrypt(ctx, cipher.data(), &outlen, plain.data(), plain.size()) <= 0)
        openssl_error();

    cipher.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    return cipher;
}

std::vector<unsigned char> RSACryptoOAEP::Impl::rsa_encrypt_oaep(const std::string& key, const std::vector<unsigned char>& plain)
{
	publickey = key;
    auto ret = load_pub();
    if (!ret)
    {
        std::cerr << "Failed to load public key.\n";
        return {};
	}

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pub, nullptr);
    if (!ctx)
        openssl_error();

    if (EVP_PKEY_encrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        openssl_error();

    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, plain.data(), plain.size()) <= 0)
        openssl_error();

    std::vector<unsigned char> cipher(outlen);
    if (EVP_PKEY_encrypt(ctx, cipher.data(), &outlen, plain.data(), plain.size()) <= 0)
        openssl_error();

    cipher.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    return cipher;
}

std::vector<unsigned char> RSACryptoOAEP::Impl::rsa_decrypt_oaep(const std::vector<unsigned char>& cipher)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
    if (!ctx)
        openssl_error();

    if (EVP_PKEY_decrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        openssl_error();

    // ✅ 这两行是关键
    // if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0 ||
    //   EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0)
    // openssl_error();

    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, cipher.data(), cipher.size()) <= 0)
        openssl_error();

    // std::cout << "cipher.size() = " << cipher.size() << ", expected = " << EVP_PKEY_size(priv) << "\n";

    std::vector<unsigned char> plain(outlen);
    auto temp = EVP_PKEY_decrypt(ctx, plain.data(), &outlen, cipher.data(), cipher.size());
    if (temp <= 0)
    {
        // unsigned long e = ERR_get_error();
        // char buf[256];
        // ERR_error_string_n(e, buf, sizeof(buf));
        // std::cerr << "Decrypt error: " << buf << std::endl;
        // std::cout << "EVP_PKEY bits: " << EVP_PKEY_bits(priv) << std::endl;

        std::exception ex("密钥不匹配\n");

        // openssl_error();     // 你原来的 abort 函数
    }

    plain.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    return plain;
}

std::vector<unsigned char> RSACryptoOAEP::Impl::rsa_decrypt_oaep(const std::string& key, const std::vector<unsigned char>& cipher)
{
    privatekey = key;
	auto ret = load_priv();
    if (!ret)
    {
        std::cerr << "Failed to load private key.\n";
		return {};
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
    if (!ctx)
        openssl_error();

    if (EVP_PKEY_decrypt_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        openssl_error();

    // ✅ 这两行是关键
    // if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0 ||
    //   EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0)
    // openssl_error();

    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, cipher.data(), cipher.size()) <= 0)
        openssl_error();

    // std::cout << "cipher.size() = " << cipher.size() << ", expected = " << EVP_PKEY_size(priv) << "\n";

    std::vector<unsigned char> plain(outlen);
    auto temp = EVP_PKEY_decrypt(ctx, plain.data(), &outlen, cipher.data(), cipher.size());
    if (temp <= 0)
    {
        // unsigned long e = ERR_get_error();
        // char buf[256];
        // ERR_error_string_n(e, buf, sizeof(buf));
        // std::cerr << "Decrypt error: " << buf << std::endl;
        // std::cout << "EVP_PKEY bits: " << EVP_PKEY_bits(priv) << std::endl;

        std::exception ex("密钥不匹配\n");

        // openssl_error();     // 你原来的 abort 函数
    }

    plain.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    return plain;
}

std::vector<unsigned char> RSACryptoOAEP::Impl::signature(const std::vector<unsigned char>& orig)
{
    auto ret1 = load_priv();

    if (!ret1)
    {
        std::cerr << "Failed to load private key.\n";
        return {};
    }

#if 0

    // 手动对数据做哈希
    unsigned char hash[32];
    EVP_Digest(orig.data(), orig.size(), hash, NULL, EVP_sha256(), NULL);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
    EVP_PKEY_sign_init(ctx);

    // 可选：设置签名算法和参数（如果需要）
    // 比如 RSA+PKCS1 padding
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    //EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_signature_md(ctx, NULL); // ← 不要重复 hash



    // 第一步：获取签名长度
    size_t siglen = 0;
    EVP_PKEY_sign(ctx, nullptr, &siglen, hash, 32);

    // 第二步：分配内存并签名
    unsigned char* sig = (unsigned char*)OPENSSL_malloc(siglen);
    int ret = EVP_PKEY_sign(ctx, sig, &siglen, hash, 32);

    if (ret <= 0) {
        // 签名失败，打印错误
        ERR_print_errors_fp(stderr);
		OPENSSL_free(sig);
        return {};
    }

    EVP_PKEY_CTX_free(ctx);

    std::vector<unsigned char> r = std::vector<unsigned char>(sig, sig + siglen);

    return r;
#endif

    std::vector<unsigned char>signature;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return {};

    bool success = false;
    do {
        if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, priv) <= 0) break;

        if (EVP_DigestSignUpdate(ctx, orig.data(), orig.size()) <= 0) break;

        size_t sig_len = 0;
        if (EVP_DigestSignFinal(ctx, nullptr, &sig_len) <= 0) break;

        signature.resize(sig_len);
        if (EVP_DigestSignFinal(ctx, signature.data(), &sig_len) <= 0) break;

        signature.resize(sig_len);  // Trim to actual size
        success = true;
    } while (false);

    EVP_MD_CTX_free(ctx);

    std::cout << signature.size() << std::endl;

    return signature;

}

bool RSACryptoOAEP::Impl::designature(const std::vector<unsigned char>& orig,
    const std::vector<unsigned char>& cipher)
{
    auto ret = load_pub();
    if (!ret)
    {
        std::cerr << "Failed to load public key.\n";
        return {};
    }

#if 0
    unsigned char hash[32];
    EVP_Digest(orig.data(), orig.size(), hash, NULL, EVP_sha256(), NULL);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pub, nullptr);
    EVP_PKEY_verify_init(ctx);

    // 设置同样的 padding 和 hash
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    //EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_signature_md(ctx, NULL); // ← 不要重复 hash


    int ret1 = EVP_PKEY_verify(ctx,cipher.data(), cipher.size(), hash, 32);
    
    EVP_PKEY_CTX_free(ctx);

    if (ret1 == 1) {
        // 验证成功
		return true;
    }
    else if (ret1 == 0) {
        // 验证失败
        ERR_print_errors_fp(stderr);
        return false;
    }
    else {
        // 错误
        ERR_print_errors_fp(stderr);
        return false;
    }
#endif
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;

    bool valid = false;
    do {
        if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pub) <= 0) break;

        if (EVP_DigestVerifyUpdate(ctx, orig.data(), orig.size()) <= 0) break;

        int ret = EVP_DigestVerifyFinal(ctx, cipher.data(), cipher.size());
        valid = (ret == 1);
    } while (false);

    EVP_MD_CTX_free(ctx);

    if (!valid)
    {
        ERR_print_errors_fp(stderr);
        std::cout << cipher.size() << std::endl;
    }
    return valid;

}


void RSACryptoOAEP::Impl::generateRSAKeyPair(
    const char* passphrase)
{
    try
    {
        /* 1️⃣ 生成密钥对象 */
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        throwIf(!ctx, "创建 EVP_PKEY_CTX 失败");

        throwIf(EVP_PKEY_keygen_init(ctx) <= 0, "keygen_init 失败");
        throwIf(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 8192) <= 0, "设置位数失败");

        EVP_PKEY* pkey = nullptr;
        throwIf(EVP_PKEY_keygen(ctx, &pkey) <= 0, "生成密钥失败");
        EVP_PKEY_CTX_free(ctx);

        /* 2️⃣ 写私钥（PKCS#8）*/
        /*FILE* fpPriv = fopen(PrivpemPath.c_str(), "wb");
        throwIf(!fpPriv, "无法创建私钥文件");

        if (passphrase) {   // 加密码保护
            throwIf(!pem_write_PKCS8PrivateKey(
                fpPriv, pkey, EVP_aes_256_cbc(),
                const_cast<char*>(passphrase),
                static_cast<int>(std::strlen(passphrase)),
                nullptr, nullptr),
                "写私钥失败");
        }
        else {            // 明文私钥
            throwIf(!pem_write_PrivateKey(
                fpPriv, pkey, nullptr, nullptr, 0, nullptr, nullptr),
                "写私钥失败");
        }
        fclose(fpPriv);*/
        FILE* fpPriv = fopen(PrivpemPath.c_str(), "wb");
        if (!fpPriv)
            perror("fopen"), exit(1);
        if (!i2d_PrivateKey_fp(fpPriv, pkey))
            openssl_error();
        fclose(fpPriv);

        /* 3️⃣ 写公钥（X.509 SubjectPublicKeyInfo）*/
        /*FILE* fpPub = fopen(PubpemPath.c_str(), "wb");
        throwIf(!fpPub, "无法创建公钥文件");
        throwIf(!pem_write_PUBKEY(fpPub, pkey), "写公钥失败");
        fclose(fpPub);*/
        FILE* fpPub = fopen(PubpemPath.c_str(), "wb");
        if (!fpPub)
            perror("fopen"), exit(1);
        if (!i2d_PUBKEY_fp(fpPub, pkey))
            openssl_error();
        fclose(fpPub);

        EVP_PKEY_free(pkey);

        std::cout << "密钥生成完毕！\n";
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[Error] " << ex.what() << '\n';

        return;
    }
}

void RSACryptoOAEP::Impl::generateRSAKeyPair(const std::string& privPath,
    const std::string& pubPath,
    const char* passphrase)
{
    // PrivpemPath = privPath;
    // PubpemPath = pubPath;

    /* 1️⃣ 生成密钥对象 */
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    throwIf(!ctx, "创建 EVP_PKEY_CTX 失败");

    throwIf(EVP_PKEY_keygen_init(ctx) <= 0, "keygen_init 失败");
    throwIf(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 8192) <= 0, "设置位数失败");

    EVP_PKEY* pkey = nullptr;
    throwIf(EVP_PKEY_keygen(ctx, &pkey) <= 0, "生成密钥失败");
    EVP_PKEY_CTX_free(ctx);

    /* 2️⃣ 写私钥（PKCS#8）*/
    /*FILE* fpPriv = fopen(PrivpemPath.c_str(), "wb");
    throwIf(!fpPriv, "无法创建私钥文件");

    if (passphrase) {   // 加密码保护
        throwIf(!pem_write_PKCS8PrivateKey(
            fpPriv, pkey, EVP_aes_256_cbc(),
            const_cast<char*>(passphrase),
            static_cast<int>(std::strlen(passphrase)),
            nullptr, nullptr),
            "写私钥失败");
    }
    else {            // 明文私钥
        throwIf(!pem_write_PrivateKey(
            fpPriv, pkey, nullptr, nullptr, 0, nullptr, nullptr),
            "写私钥失败");
    }
    fclose(fpPriv);*/
    FILE* fpPriv = fopen(PrivpemPath.c_str(), "wb");
    if (!fpPriv)
        perror("fopen"), exit(1);
    if (!PEM_write_PrivateKey(fpPriv, pkey, nullptr, nullptr, 0, nullptr, nullptr))
        openssl_error();
    fclose(fpPriv);

    /* 3️⃣ 写公钥（X.509 SubjectPublicKeyInfo）*/
    /*FILE* fpPub = fopen(PubpemPath.c_str(), "wb");
    throwIf(!fpPub, "无法创建公钥文件");
    throwIf(!pem_write_PUBKEY(fpPub, pkey), "写公钥失败");
    fclose(fpPub);*/
    FILE* fpPub = fopen(PubpemPath.c_str(), "wb");
    if (!fpPub)
        perror("fopen"), exit(1);
    if (!PEM_write_PUBKEY(fpPub, pkey))
        openssl_error();
    fclose(fpPub);

    EVP_PKEY_free(pkey);

    std::cout << "密钥生成完毕！\n";
}

void RSACryptoOAEP::Impl::write_bytes_to_file(const std::string& filename, const std::vector<unsigned char>& data)
{
    std::ofstream ofs(filename, std::ios::binary);
    ofs.write((char*)data.data(), data.size());
    ofs.close();
}

std::vector<unsigned char> RSACryptoOAEP::Impl::read_bytes_from_file(const std::string& filename)
{
    std::ifstream ifs(filename, std::ios::binary);
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(ifs)), {});
}

bool RSACryptoOAEP::Impl::is_file_equal(const std::string& file1, const std::string& file2)
{
    std::ifstream f1(file1, std::ios::binary);
    std::ifstream f2(file2, std::ios::binary);

    std::vector<unsigned char> a((std::istreambuf_iterator<char>(f1)), {});
    std::vector<unsigned char> b((std::istreambuf_iterator<char>(f2)), {});

    return a == b;
}

bool RSACryptoOAEP::Impl::is_equal(const std::vector<unsigned char>& a, const std::vector<unsigned char>& b)
{
    return a == b;
}

//**********************************************************************************************************************************************

// public:
RSACryptoOAEP::RSACryptoOAEP()
{
   // OSSL_PROVIDER_load(NULL, "legacy");
    
    pImpl = new Impl();

    pImpl->init_openssl();
#if 1
    // OpenSSL_add_all_algorithms();
    // ERR_load_crypto_strings();

    try
    {
        

        pImpl->PrivpemPath = "./private.der";
        pImpl->PubpemPath = "./public.der";

        // pImpl->generateRSAKeyPair(nullptr);

        try
        {
            //pub = load_pub(PubpemPath);
            pImpl->pub = pImpl->load_pub(pImpl->PubpemPath);
            if (!pImpl->pub)
                throw std::runtime_error("无法打开公钥文件");
            //priv = load_priv(PrivpemPath);
            pImpl->priv = pImpl->load_priv(pImpl->PrivpemPath);
            if (!pImpl->priv)
                throw std::runtime_error("无法打开私钥文件");
        }
        catch (std::exception& ex)
        {
            std::cerr << "[Error]" << ex.what() << std::endl;
        }

        if (!pImpl->pub || !pImpl->priv)
            throw std::runtime_error("初始化失败");
    }
    catch (std::exception& ex)
    {
        throw std::runtime_error("无法构造");
        std::cerr << "[Error]" << ex.what() << std::endl;
    }
#endif
}

RSACryptoOAEP::RSACryptoOAEP(const std::string& pubk, const std::string& privk)
{
    try
    {
        pImpl = new Impl();

        pImpl->publickey = pubk;
        pImpl->privatekey = privk;
        // pImpl->generateRSAKeyPair(nullptr);

        pImpl->init();

        if (!pImpl->pub || !pImpl->priv)
            throw std::runtime_error("初始化失败");
    }
    catch (std::exception& ex)
    {
        throw std::runtime_error("无法构造");
        std::cerr << "[Error]" << ex.what() << std::endl;
    }
}

void RSACryptoOAEP::set_key_path(const std::string& pupp, const std::string& prpp)
{
    pImpl->PrivpemPath = prpp;
    pImpl->PubpemPath = pupp;
    pImpl->init();
}

void RSACryptoOAEP::generateKeyPair(const std::string& privPath,
    const std::string& pubPath)
{
    return pImpl->generateRSAKeyPair(privPath,
        pubPath);
}

void RSACryptoOAEP::generateKeyPair()
{
    return pImpl->generateRSAKeyPair();
}

std::vector<unsigned char> RSACryptoOAEP::encrypt(const std::vector<unsigned char>& plain)
{
    return pImpl->rsa_encrypt_oaep(plain);
}

std::vector<unsigned char> RSACryptoOAEP::encrypt(const std::string& plain)
{
    std::vector<unsigned char> msg(plain.begin(), plain.end());
    return pImpl->rsa_encrypt_oaep(msg);
}

std::vector<unsigned char> RSACryptoOAEP::encrypt(const std::string& key, const std::vector<unsigned char>& plain)
{
    return pImpl->rsa_encrypt_oaep(key, plain);
}


std::vector<unsigned char> RSACryptoOAEP::decrypt(const std::vector<unsigned char>& cipher)
{
    try
    {
        return pImpl->rsa_decrypt_oaep(cipher);
    }
    catch (std::exception& ex)
    {
        std::cerr << "[Error]" << ex.what();
		return {};
    }
}

std::vector<unsigned char> RSACryptoOAEP::decrypt(const std::string& cipher)
{
    std::vector<unsigned char> msg(cipher.begin(), cipher.end());
    return pImpl->rsa_encrypt_oaep(msg);
}

std::vector<unsigned char> RSACryptoOAEP::decrypt(const std::string& key, const std::vector<unsigned char>& cipher)
{
    try
    {
        return pImpl->rsa_decrypt_oaep(key,cipher);
    }
    catch (std::exception& ex)
    {
        std::cerr << "[Error]" << ex.what();

		return {};
    }
}

/*写签名*/
std::vector<unsigned char> RSACryptoOAEP::signature(const std::vector<unsigned char>& orig)
{
	return pImpl->signature(orig);
}

/*验签名*/
bool RSACryptoOAEP::designature(const std::vector<unsigned char>& orig,
    const std::vector<unsigned char>& cipher)
{
	return pImpl->designature(orig, cipher);
}

void RSACryptoOAEP::print_plain(std::vector<unsigned char> cipher)
{
    std::string b64cipher = pImpl->base64Encode(cipher);
    std::cout /* << "Ciphertext (Base64):\n"*/ << b64cipher << "\n";
}

void RSACryptoOAEP::print_cipher(std::vector<unsigned char> plain)
{
    std::string result(plain.begin(), plain.end());
    std::cout /* << "Recovered text : "*/ << result << "\n";
}

void RSACryptoOAEP::save(const std::string& filename, const std::vector<unsigned char>& data)
{
    pImpl->write_bytes_to_file(filename, data);
}

std::vector<unsigned char> RSACryptoOAEP::read_from_file(const std::string& filename)
{
    return pImpl->read_bytes_from_file(filename);
}

RSACryptoOAEP::~RSACryptoOAEP()
{
    EVP_PKEY_free(pImpl->pub);
    EVP_PKEY_free(pImpl->priv);

    delete pImpl;
}
