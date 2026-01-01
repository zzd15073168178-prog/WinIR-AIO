// hash_manager.h - 哈希计算管理器
#pragma once

#include "common.h"
#include <wincrypt.h>

// CALG_SHA_256 在 XP/2003 的旧版 wincrypt.h 中未定义
// 但 PROV_RSA_AES 提供程序支持它
#ifndef CALG_SHA_256
#define CALG_SHA_256 (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256)
#endif

#ifndef ALG_SID_SHA_256
#define ALG_SID_SHA_256 12
#endif

class HashManager {
public:
    HashManager();
    ~HashManager();

    // 计算文件哈希
    FileHashResult CalculateFileHash(const tstring& filePath);

    // 仅计算指定算法
    tstring CalculateMD5(const tstring& filePath);
    tstring CalculateSHA1(const tstring& filePath);
    tstring CalculateSHA256(const tstring& filePath);

    // 计算数据哈希
    tstring CalculateDataMD5(const BYTE* data, SIZE_T size);
    tstring CalculateDataSHA1(const BYTE* data, SIZE_T size);
    tstring CalculateDataSHA256(const BYTE* data, SIZE_T size);

    // 批量计算
    std::vector<FileHashResult> CalculateDirectoryHashes(const tstring& dirPath,
        bool recursive = false);

    // 取消操作
    void Cancel() { m_cancelled = true; }
    bool IsCancelled() const { return m_cancelled; }
    void Reset() { m_cancelled = false; }

    // 进度回调
    typedef void (*ProgressCallback)(const tstring& filePath, int percent, void* userData);
    void SetProgressCallback(ProgressCallback callback, void* userData);

private:
    bool m_cancelled;
    ProgressCallback m_progressCallback;
    void* m_callbackUserData;

    // 通用哈希计算
    tstring CalculateHash(const tstring& filePath, ALG_ID algId);
    tstring CalculateDataHash(const BYTE* data, SIZE_T size, ALG_ID algId);

    // 字节转十六进制
    tstring BytesToHex(const BYTE* data, DWORD size);

    // 递归获取文件列表
    void GetFilesInDirectory(const tstring& dirPath, bool recursive,
        std::vector<tstring>& files);
};
