#include <windows.h>
#include <bcrypt.h>
#include <iostream>
#include <string>
#include <vector>

#define NT_SUCCESS(status) (((NTSTATUS)(status)) >= 0)
#define BUFFER_SIZE (1024 * 1024) // 1MB缓冲区

struct HashProcessor {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD hashLength = 0;
    std::vector<BYTE> hashValue;
    LPCWSTR algorithm = nullptr;

    bool Initialize() {
        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, algorithm, nullptr, 0);
        if (!NT_SUCCESS(status)) return false;

        // 获取哈希长度
        DWORD cbResult;
        status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&hashLength),
            sizeof(DWORD), &cbResult, 0);
        if (!NT_SUCCESS(status)) return false;

        // 创建哈希对象
        status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
        return NT_SUCCESS(status);
    }

    void Finalize() {
        if (hHash) {
            hashValue.resize(hashLength);
            BCryptFinishHash(hHash, hashValue.data(), hashLength, 0);
            BCryptDestroyHash(hHash);
            hHash = nullptr;
        }
        if (hAlg) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            hAlg = nullptr;
        }
    }

    void Update(const BYTE* data, ULONG size) {
        BCryptHashData(hHash, const_cast<PUCHAR>(data), size, 0);
    }
};

std::string BytesToHex(const BYTE* data, size_t length) {
    static const char hexDigits[] = "0123456789abcdef";
    std::string result;
    result.reserve(length * 2);

    for (size_t i = 0; i < length; ++i) {
        result.push_back(hexDigits[(data[i] >> 4) & 0xF]);
        result.push_back(hexDigits[data[i] & 0xF]);
    }
    return result;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: FileHashCalculator <file_path>\n";
        return 1;
    }

    // 初始化哈希处理器
    HashProcessor md5{ nullptr, nullptr, 0, {}, BCRYPT_MD5_ALGORITHM };
    HashProcessor sha1{ nullptr, nullptr, 0, {}, BCRYPT_SHA1_ALGORITHM };
    HashProcessor sha256{ nullptr, nullptr, 0, {}, BCRYPT_SHA256_ALGORITHM };

    if (!md5.Initialize() || !sha1.Initialize() || !sha256.Initialize()) {
        std::cerr << "Failed to initialize hash algorithms\n";
        return 1;
    }

    // 打开文件
    HANDLE hFile = CreateFileW(argv[1], GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open file (Error: " << GetLastError() << ")\n";
        return 1;
    }

    // 读取文件并计算哈希
    std::vector<BYTE> buffer(BUFFER_SIZE);
    DWORD bytesRead = 0;

    while (ReadFile(hFile, buffer.data(), BUFFER_SIZE, &bytesRead, nullptr) && bytesRead > 0) {
        md5.Update(buffer.data(), bytesRead);
        sha1.Update(buffer.data(), bytesRead);
        sha256.Update(buffer.data(), bytesRead);
    }

    // 最终化哈希计算
    md5.Finalize();
    sha1.Finalize();
    sha256.Finalize();
    CloseHandle(hFile);

    // 输出结果
    std::cout << "MD5:    " << BytesToHex(md5.hashValue.data(), md5.hashValue.size()) << "\n"
        << "SHA1:   " << BytesToHex(sha1.hashValue.data(), sha1.hashValue.size()) << "\n"
        << "SHA256: " << BytesToHex(sha256.hashValue.data(), sha256.hashValue.size()) << "\n";

    // 保持控制台可见
    std::cout << "\nPress Enter to exit...";
    std::cin.ignore();
    return 0;
}