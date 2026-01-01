// hash_manager.cpp - 哈希计算管理器实现
#include "../include/hash_manager.h"
#include <tchar.h>
#include <shlwapi.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")

// ============================================================================
// 构造函数和析构函数
// ============================================================================

HashManager::HashManager()
    : m_cancelled(false)
    , m_progressCallback(NULL)
    , m_callbackUserData(NULL)
{
}

HashManager::~HashManager()
{
}

// ============================================================================
// 设置进度回调
// ============================================================================

void HashManager::SetProgressCallback(ProgressCallback callback, void* userData)
{
    m_progressCallback = callback;
    m_callbackUserData = userData;
}

// ============================================================================
// 字节转十六进制
// ============================================================================

tstring HashManager::BytesToHex(const BYTE* data, DWORD size)
{
    tstring hex;
    hex.reserve(size * 2);

    for (DWORD i = 0; i < size; i++) {
        TCHAR buf[3];
        _stprintf_s(buf, TEXT("%02x"), data[i]);
        hex += buf;
    }

    return hex;
}

// ============================================================================
// 通用哈希计算
// ============================================================================

tstring HashManager::CalculateHash(const tstring& filePath, ALG_ID algId)
{
    tstring result;

    // 打开文件
    HANDLE hFile = CreateFile(
        filePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return result;
    }

    // 获取文件大小
    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);

    // 获取加密上下文
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        // 尝试使用旧的提供程序 (XP 兼容)
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            CloseHandle(hFile);
            return result;
        }
    }

    if (!CryptCreateHash(hProv, algId, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return result;
    }

    // 分块读取和计算
    const DWORD BUFFER_SIZE = 64 * 1024; // 64KB
    BYTE buffer[64 * 1024];
    DWORD bytesRead;
    ULONGLONG totalRead = 0;
    int lastPercent = -1;

    while (!m_cancelled) {
        if (!ReadFile(hFile, buffer, BUFFER_SIZE, &bytesRead, NULL) || bytesRead == 0) {
            break;
        }

        if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
            break;
        }

        totalRead += bytesRead;

        // 报告进度
        if (m_progressCallback && fileSize.QuadPart > 0) {
            int percent = (int)(totalRead * 100 / fileSize.QuadPart);
            if (percent != lastPercent) {
                lastPercent = percent;
                m_progressCallback(filePath, percent, m_callbackUserData);
            }
        }
    }

    if (!m_cancelled) {
        // 获取哈希值
        DWORD hashSize = 0;
        DWORD hashSizeLen = sizeof(hashSize);
        CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&hashSize, &hashSizeLen, 0);

        if (hashSize > 0) {
            std::vector<BYTE> hashValue(hashSize);
            if (CryptGetHashParam(hHash, HP_HASHVAL, hashValue.data(), &hashSize, 0)) {
                result = BytesToHex(hashValue.data(), hashSize);
            }
        }
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);

    return result;
}

// ============================================================================
// 计算数据哈希
// ============================================================================

tstring HashManager::CalculateDataHash(const BYTE* data, SIZE_T size, ALG_ID algId)
{
    tstring result;

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            return result;
        }
    }

    if (!CryptCreateHash(hProv, algId, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return result;
    }

    if (CryptHashData(hHash, data, (DWORD)size, 0)) {
        DWORD hashSize = 0;
        DWORD hashSizeLen = sizeof(hashSize);
        CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&hashSize, &hashSizeLen, 0);

        if (hashSize > 0) {
            std::vector<BYTE> hashValue(hashSize);
            if (CryptGetHashParam(hHash, HP_HASHVAL, hashValue.data(), &hashSize, 0)) {
                result = BytesToHex(hashValue.data(), hashSize);
            }
        }
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return result;
}

// ============================================================================
// 计算文件哈希 (所有算法)
// ============================================================================

FileHashResult HashManager::CalculateFileHash(const tstring& filePath)
{
    FileHashResult result;
    result.filePath = filePath;

    // 检查文件是否存在
    if (!PathFileExists(filePath.c_str())) {
        result.error = TEXT("文件不存在");
        return result;
    }

    // 获取文件大小
    HANDLE hFile = CreateFile(
        filePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER fileSize;
        GetFileSizeEx(hFile, &fileSize);
        result.fileSize = fileSize.QuadPart;
        CloseHandle(hFile);
    }

    // 计算各种哈希
    m_cancelled = false;

    result.md5 = CalculateHash(filePath, CALG_MD5);
    if (m_cancelled) {
        result.error = TEXT("操作已取消");
        return result;
    }

    result.sha1 = CalculateHash(filePath, CALG_SHA1);
    if (m_cancelled) {
        result.error = TEXT("操作已取消");
        return result;
    }

    result.sha256 = CalculateHash(filePath, CALG_SHA_256);
    if (m_cancelled) {
        result.error = TEXT("操作已取消");
        return result;
    }

    return result;
}

// ============================================================================
// 单独计算各种哈希
// ============================================================================

tstring HashManager::CalculateMD5(const tstring& filePath)
{
    return CalculateHash(filePath, CALG_MD5);
}

tstring HashManager::CalculateSHA1(const tstring& filePath)
{
    return CalculateHash(filePath, CALG_SHA1);
}

tstring HashManager::CalculateSHA256(const tstring& filePath)
{
    return CalculateHash(filePath, CALG_SHA_256);
}

// ============================================================================
// 计算数据哈希
// ============================================================================

tstring HashManager::CalculateDataMD5(const BYTE* data, SIZE_T size)
{
    return CalculateDataHash(data, size, CALG_MD5);
}

tstring HashManager::CalculateDataSHA1(const BYTE* data, SIZE_T size)
{
    return CalculateDataHash(data, size, CALG_SHA1);
}

tstring HashManager::CalculateDataSHA256(const BYTE* data, SIZE_T size)
{
    return CalculateDataHash(data, size, CALG_SHA_256);
}

// ============================================================================
// 递归获取目录中的文件
// ============================================================================

void HashManager::GetFilesInDirectory(const tstring& dirPath, bool recursive,
    std::vector<tstring>& files)
{
    tstring searchPath = dirPath;
    if (searchPath.back() != TEXT('\\')) {
        searchPath += TEXT('\\');
    }
    searchPath += TEXT("*");

    WIN32_FIND_DATA fd;
    HANDLE hFind = FindFirstFile(searchPath.c_str(), &fd);

    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (m_cancelled) break;

        tstring name = fd.cFileName;
        if (name == TEXT(".") || name == TEXT("..")) {
            continue;
        }

        tstring fullPath = dirPath;
        if (fullPath.back() != TEXT('\\')) {
            fullPath += TEXT('\\');
        }
        fullPath += name;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (recursive) {
                GetFilesInDirectory(fullPath, true, files);
            }
        } else {
            files.push_back(fullPath);
        }
    } while (FindNextFile(hFind, &fd));

    FindClose(hFind);
}

// ============================================================================
// 批量计算目录哈希
// ============================================================================

std::vector<FileHashResult> HashManager::CalculateDirectoryHashes(
    const tstring& dirPath, bool recursive)
{
    std::vector<FileHashResult> results;
    std::vector<tstring> files;

    m_cancelled = false;

    // 获取文件列表
    GetFilesInDirectory(dirPath, recursive, files);

    // 计算每个文件的哈希
    for (size_t i = 0; i < files.size() && !m_cancelled; i++) {
        FileHashResult result = CalculateFileHash(files[i]);
        results.push_back(result);

        // 报告整体进度
        if (m_progressCallback) {
            int percent = (int)((i + 1) * 100 / files.size());
            m_progressCallback(files[i], percent, m_callbackUserData);
        }
    }

    return results;
}
