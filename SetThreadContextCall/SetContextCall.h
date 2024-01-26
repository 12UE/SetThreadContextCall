#pragma once
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <atomic>
#include <algorithm>
#include <mutex>
#include <vector>
#include <tuple>
#include <thread>
#include <functional>
#include <array>
#include <thread>
#include <future>
#include <chrono>
#include <mutex>
#include <map>
#include <deque>
#include <typeinfo>
#include <minwinbase.h>
#include <fstream>
#include <unordered_set>
#include <winnt.h>
#include <winternl.h>
namespace stc{
#define XORSTR_INLINE	__forceinline
#define XORSTR_NOINLINE __declspec( noinline )
#define XORSTR_CONST	constexpr
#define XORSTR_VOLATILE volatile
#define XORSTR_CONST_INLINE XORSTR_INLINE XORSTR_CONST 
#define XORSTR_CONST_NOINLINE XORSTR_NOINLINE XORSTR_CONST
#define XORSTR_FNV_OFFSET_BASIS 0xCBF29CE484333325
#define XORSTR_FNV_PRIME __TIME__[0] * 0x1000193
#define XORSTR_TYPE_SIZEOF( _VALUE ) sizeof( decltype( _VALUE ) )
#define XORSTR_BYTE( _VALUE, _IDX )	( ( _VALUE >> ( __min( _IDX, ( XORSTR_TYPE_SIZEOF( _VALUE ) ) - 1)  * 8 ) ) & 0xFF )
#define XORSTR_NIBBLE( _VALUE, _IDX ) ( ( _VALUE >> ( __min( _IDX, ( XORSTR_TYPE_SIZEOF( _VALUE ) * 2 ) - 1 ) * 4 ) ) & 0xF )
#define XORSTR_MAKE_INTEGER_SEQUENCE( _LEN_ ) __make_integer_seq< XORSTR_INT_SEQ, SIZE_T, _LEN_ >( )
#define XORSTR_INTEGER_SEQUENCE( _INDICES_ ) XORSTR_INT_SEQ< SIZE_T, _INDICES_... >
    template< typename _Ty, _Ty... Types >
    struct XORSTR_INT_SEQ {};
    XORSTR_CONST_NOINLINE INT XORSTR_ATOI8(IN CHAR Character) noexcept { return (Character >= '0' && Character <= '9') ? (Character - '0') : NULL; }
    XORSTR_CONST_NOINLINE UINT64 XORSTR_KEY(IN SIZE_T CryptStrLength) noexcept {
        UINT64 KeyHash = XORSTR_FNV_OFFSET_BASIS;
        for (SIZE_T i = NULL; i < sizeof(__TIME__); i++) {
            KeyHash = KeyHash ^ (XORSTR_ATOI8(__TIME__[i]) + (CryptStrLength * i)) & 0xFF;
            KeyHash = KeyHash * XORSTR_FNV_PRIME;
        }
        return KeyHash;
    }
    template< typename _CHAR_TYPE_, SIZE_T _STR_LENGTH_ >
    class _XORSTR_ {
        static XORSTR_CONST UINT64 Key = XORSTR_KEY(_STR_LENGTH_);
        static XORSTR_CONST_INLINE _CHAR_TYPE_ CRYPT_CHAR(IN _CHAR_TYPE_ Character, IN SIZE_T KeyIndex) { return (Character ^ ((Key + KeyIndex) ^ (XORSTR_NIBBLE(Key, KeyIndex % 16)))); }
        template< SIZE_T... _INDEX_ >XORSTR_CONST_INLINE _XORSTR_(IN _CHAR_TYPE_ CONST(&String)[_STR_LENGTH_], IN XORSTR_INTEGER_SEQUENCE(_INDEX_) IntSeq) : StringData{ CRYPT_CHAR(String[_INDEX_], _INDEX_)... } {}
        XORSTR_VOLATILE _CHAR_TYPE_ StringData[_STR_LENGTH_];
    public:
        XORSTR_CONST_INLINE _XORSTR_(IN _CHAR_TYPE_ CONST(&String)[_STR_LENGTH_]) : _XORSTR_(String, XORSTR_MAKE_INTEGER_SEQUENCE(_STR_LENGTH_)) {}
        XORSTR_INLINE CONST _CHAR_TYPE_* String(VOID) {
            for (SIZE_T i = NULL; i < _STR_LENGTH_; i++)StringData[i] = CRYPT_CHAR(StringData[i], i);
            return (_CHAR_TYPE_*)(StringData);
        }
    };
    template< SIZE_T _STR_LEN_ >XORSTR_CONST_INLINE _XORSTR_< CHAR, _STR_LEN_ > XorStr(IN CHAR CONST(&String)[_STR_LEN_]) { return _XORSTR_< CHAR, _STR_LEN_ >(String); }
    template< SIZE_T _STR_LEN_ >XORSTR_CONST_INLINE _XORSTR_< WCHAR, _STR_LEN_ > XorStr(IN WCHAR CONST(&String)[_STR_LEN_]) { return _XORSTR_< WCHAR, _STR_LEN_ >(String); }
    template< SIZE_T _STR_LEN_ >XORSTR_CONST_INLINE _XORSTR_< char32_t, _STR_LEN_ > XorStr(IN char32_t CONST(&String)[_STR_LEN_]) { return _XORSTR_< char32_t, _STR_LEN_ >(String); }
#define xor_str( _STR_ ) XorStr( _STR_ ).String()
    typedef struct _PEB_LDR_DATA_64 {
        UINT Length;
        UCHAR Initialized;
        UINT_PTR SsHandle;
        _LIST_ENTRY InLoadOrderModuleList;
        _LIST_ENTRY InMemoryOrderModuleList;
        _LIST_ENTRY InInitializationOrderModuleList;
    }PEB_LDR_DATA64, * PPEB_LDR_DATA64, * PLDT, LDT;
    namespace Win32 {
#if defined(_WIN64)
        typedef struct _LDR_DATA_TABLE_ENTRY64 {
            LIST_ENTRY64 InLoadOrderLinks;
            LIST_ENTRY64 InMemoryOrderLinks;
            LIST_ENTRY64 InInitializationOrderLinks;
            ULONG64 DllBase;
            ULONG64 EntryPoint;
            ULONG64 SizeOfImage;
            UNICODE_STRING FullDllName;
            UNICODE_STRING BaseDllName;
            ULONG Flags;
            USHORT LoadCount;
            USHORT TlsIndex;
            LIST_ENTRY64 HashLinks;
            ULONG64 SectionPointer;
            ULONG64 CheckSum;
            ULONG64 TimeDateStamp;
            ULONG64 LoadedImports;
            ULONG64 EntryPointActivationContext;
            ULONG64 PatchInformation;
            LIST_ENTRY64 ForwarderLinks;
            LIST_ENTRY64 ServiceTagLinks;
            LIST_ENTRY64 StaticLinks;
            ULONG64 ContextInformation;
            ULONG64 OriginalBase;
            LARGE_INTEGER LoadTime;
        }LDR_DATA_TABLE_ENTRY_T, * PLDR_DATA_TABLE_ENTRY_T, LDRT;
        typedef struct _PEB_LDR_DATA_64 {
            UINT Length;
            UCHAR Initialized;
            UINT_PTR SsHandle;
            _LIST_ENTRY InLoadOrderModuleList;
            _LIST_ENTRY InMemoryOrderModuleList;
            _LIST_ENTRY InInitializationOrderModuleList;
        }PEB_LDR_DATA64, * PPEB_LDR_DATA64, * PLDT, LDT;
        typedef struct _PEB64 {
            UCHAR InheritedAddressSpace;
            UCHAR ReadImageFileExecOptions;
            UCHAR BeingDebugged;
            UCHAR Spare;
            UCHAR Padding0[4];
            ULONG64 Mutant;
            ULONG64 ImageBaseAddress;
            PPEB_LDR_DATA64 Ldr;//dll 链表
        } PEB64, * PPEB64, UPEB;
#else
        typedef struct _PEB_LDR_DATA32 {
            ULONG Length;
            UCHAR Initialized;
            ULONG SsHandle;
            LIST_ENTRY32 InLoadOrderModuleList;
            LIST_ENTRY32 InMemoryOrderModuleList;
            LIST_ENTRY32 InInitializationOrderModuleList;
            ULONG EntryInProgress;
        } PEB_LDR_DATA32, * PPEB_LDR_DATA32, * PLDT, LDT;
        typedef struct _PEB32 {
            UCHAR InheritedAddressSpace;
            UCHAR ReadImageFileExecOptions;
            UCHAR BeingDebugged;
            UCHAR Spare;
            ULONG Mutant;
            ULONG ImageBaseAddress;
            PPEB_LDR_DATA32 Ldr;
        } PEB32, * PPEB32, UPEB;
        typedef struct _UNICODE_STRING32 {
            uint16_t Length;
            uint16_t MaximumLength;
            uint32_t Buffer;
        } UNICODE_STRING32;
        typedef struct _LDR_DATA_TABLE_ENTRY32 {
            LIST_ENTRY32 InLoadOrderLinks;
            LIST_ENTRY32 InMemoryOrderLinks;
            LIST_ENTRY32 InInitializationOrderLinks;
            ULONG DllBase;
            ULONG EntryPoint;
            ULONG SizeOfImage;
            UNICODE_STRING32 FullDllName;
            UNICODE_STRING32 BaseDllName;
            ULONG Flags;
            USHORT LoadCount;
            USHORT TlsIndex;
            LIST_ENTRY32 HashLinks;
            ULONG SectionPointer;
            ULONG CheckSum;
            ULONG TimeDateStamp;
            ULONG LoadedImports;
            ULONG EntryPointActivationContext;
            ULONG PatchInformation;
            LIST_ENTRY32 ForwarderLinks;
            LIST_ENTRY32 ServiceTagLinks;
            LIST_ENTRY32 StaticLinks;
            ULONG ContextInformation;
            ULONG OriginalBase;
            LARGE_INTEGER LoadTime;
        } LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32, LDRT;
#endif // (_WIN64)_
    }
    template<typename Pre>
    void GetFiles(const std::string& path, const Pre& bin) {
        WIN32_FIND_DATAA findData{};
        HANDLE hFind = FindFirstFileA((path + "\\*").c_str(), &findData);
        std::vector<std::string> fullPaths;
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                const std::string fileName = findData.cFileName;
                const std::string fullPath = path + "\\" + fileName;
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    fullPaths.emplace_back(fullPath);
                }
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
        }
#pragma omp parallel for schedule(dynamic,1)
        for (int i = 0; i < fullPaths.size(); i++) {
            bin(fullPaths[i].c_str());
        }
    }
    static inline PIMAGE_NT_HEADERS GetNtHeader(LPVOID buffer) {
        auto pDosHeader = (PIMAGE_DOS_HEADER)buffer;
        if (!pDosHeader) return nullptr;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        auto pNtHeader = (PIMAGE_NT_HEADERS)((uintptr_t)buffer + pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE || !pNtHeader) return nullptr;
        return pNtHeader;
    }
    static inline FARPROC GetFunctionByName(LPVOID pDllImageBuffer, LPCSTR lpszFunc) {
        PIMAGE_NT_HEADERS pNtHeader = GetNtHeader(pDllImageBuffer);
        PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pDllImageBuffer +
            pNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress);
        PDWORD AddressOfFunctions = (PDWORD)((PBYTE)pDllImageBuffer + pExport->AddressOfFunctions);
        PDWORD AddressOfNames = (PDWORD)((PBYTE)pDllImageBuffer + pExport->AddressOfNames);
        PUSHORT AddressOfNameOrdinals = (PUSHORT)((PBYTE)pDllImageBuffer + pExport->AddressOfNameOrdinals);
        for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
            if (0 == strcmp(lpszFunc, (char*)pDllImageBuffer + AddressOfNames[i])) {
                return (FARPROC)(AddressOfFunctions[AddressOfNameOrdinals[i]] + (PBYTE)pDllImageBuffer);
            }
        }
        return NULL;

    }
    static inline uintptr_t RVA2Offset(uintptr_t RVA, PIMAGE_NT_HEADERS pNtHeader, LPVOID Data) {
        auto pDosHeader = (PIMAGE_DOS_HEADER)Data;
        auto pSectionHeader = (PIMAGE_SECTION_HEADER)((SIZE_T)Data + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
        for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
            if (RVA >= pSectionHeader[i].VirtualAddress && RVA < (uintptr_t)pSectionHeader[i].VirtualAddress + pSectionHeader[i].Misc.VirtualSize) {
                return RVA - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData;
            }
        }
        return (uintptr_t)0;
    }
#define EXPORT extern "C" __declspec(dllexport) __forceinline
    static inline std::vector<std::string> ScanExport(char* buffer) {//由于映射 buffer会相同
        std::vector<std::string> result;
        auto pNtHeader = GetNtHeader(buffer);
        if (!pNtHeader)return result;
        auto Machine = pNtHeader->FileHeader.Machine;
#ifdef _WIN64		//判断pNtHeader->FileHeader.Machine
        if (Machine != IMAGE_FILE_MACHINE_AMD64 && Machine != IMAGE_FILE_MACHINE_IA64)return result;
#else
        if (Machine != IMAGE_FILE_MACHINE_I386)return result;
#endif // _WIN64
        auto pExportDir = (PIMAGE_DATA_DIRECTORY)&pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!pExportDir)return result;
        auto pExport = (PIMAGE_EXPORT_DIRECTORY)(buffer + RVA2Offset(pExportDir->VirtualAddress, pNtHeader, buffer));
        if (!pExport) return result;
        if (pExport->AddressOfFunctions && pExport->AddressOfNames) {
            for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
                DWORD dwRVA = *(DWORD*)(RVA2Offset(pExport->AddressOfNames, pNtHeader, buffer) + buffer + i * sizeof(std::uint32_t));
                char* funname = (char*)(RVA2Offset(dwRVA, pNtHeader, buffer) + buffer);
                result.emplace_back(funname);
            }
        }
        return result;
    }
    static inline std::vector<std::string> GetImportDirectory() {
        std::vector<std::string> PathList;//程序默认搜索目录
        PathList.reserve(0x1000);
        char szPath[MAX_PATH]{};
        std::ignore = GetCurrentDirectoryA(MAX_PATH, szPath);
        PathList.push_back(szPath);
        std::ignore = GetSystemDirectoryA(szPath, MAX_PATH);
        PathList.push_back(szPath);
        std::ignore = GetWindowsDirectoryA(szPath, MAX_PATH);
        PathList.push_back(szPath);
        char* szEnvPath = nullptr;
        _dupenv_s(&szEnvPath, nullptr, xor_str("PATH"));
        char* szEnvPathTemp = szEnvPath;
        while (szEnvPathTemp) {
            char* szEnvPathTemp2 = strchr(szEnvPathTemp, ';');
            if (szEnvPathTemp2) {
                *szEnvPathTemp2 = '\0';
                PathList.emplace_back(szEnvPathTemp);
                szEnvPathTemp = szEnvPathTemp2 + 1;
            }
            else {
                PathList.emplace_back(szEnvPathTemp);
                break;
            }
        }
        for (auto& path : PathList) { std::transform(path.begin(), path.end(), path.begin(), ::tolower); }
        PathList.erase(std::remove_if(PathList.begin(), PathList.end(), [](std::string& path) {return path.length() == 0; }), PathList.end());
        std::sort(PathList.begin(), PathList.end());
        PathList.erase(std::unique(PathList.begin(), PathList.end()), PathList.end());
        return PathList;
    }
    class SpinLock {
        CRITICAL_SECTION g_cs;
    public:
        SpinLock() {
            InitializeCriticalSection(&g_cs);
        }
        CRITICAL_SECTION& Get() {
            return g_cs;
        }
        ~SpinLock() {
            DeleteCriticalSection(&g_cs);
        }
    };

    template<typename T>
    void writeToFileHelper(std::ofstream& file, const T& value) {
        file.write(reinterpret_cast<const char*>(&value), sizeof(value));
    }
    template<>
    void writeToFileHelper<std::string>(std::ofstream& file, const std::string& value) {
        size_t length = value.size();
        file.write(reinterpret_cast<const char*>(&length), sizeof(length));
        file.write(value.c_str(), value.size());
    }
    template<typename T, typename U>
    void writeToFile(const std::string& filename, const std::unordered_map<T, U>& map) {
        std::ofstream file(filename, std::ios::binary);
        if (!file)return;
        for (const auto& pair : map) {
            writeToFileHelper(file, pair.first);
            writeToFileHelper(file, pair.second);
        }
    }
    template<typename T>
    void readFromFileHelper(std::ifstream& file, T& value) {
        file.read(reinterpret_cast<char*>(&value), sizeof(value));
    }
    template<>
    void readFromFileHelper<std::string>(std::ifstream& file, std::string& value) {
        size_t length = 0;
        file.read(reinterpret_cast<char*>(&length), sizeof(length));
        if (length < 1000000) {  // 举例一个合理的最大长度
            value.resize(length);
            file.read(&value[0], length);
        }
    }
    template<typename T, typename U>
    std::unordered_map<T, U> readFromFile(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file) {
            throw std::runtime_error(xor_str("Unable to open file"));
        }
        std::unordered_map<T, U> map;
        while (file) {
            T key{};
            U value{};
            readFromFileHelper(file, key);
            if (!file) break; // Check if the reading of key was successful
            readFromFileHelper(file, value);
            map[key] = value;
        }
        return map;
    }
    inline bool IsFileExistW(const wchar_t* filename) {
        return GetFileAttributesW(filename) != INVALID_FILE_ATTRIBUTES;
    }
    inline bool IsFileExistA(const char* filename) {
        return GetFileAttributesA(filename) != INVALID_FILE_ATTRIBUTES;
    }
    class FileMapView {
        DWORD GetFileSize() {
            return ::GetFileSize(m_FileHandle, NULL);
        }
    public:
        HANDLE m_FileHandle = INVALID_HANDLE_VALUE;
        void* mapview = nullptr;
        DWORD m_FileSize = 0;
        FileMapView(HANDLE hFile) {
            m_FileHandle = hFile;
            m_FileSize = GetFileSize();
            auto hFileMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
            if (hFileMap && hFileMap != INVALID_HANDLE_VALUE) {
                mapview = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
            }
        }
        ~FileMapView() {
            if (mapview)UnmapViewOfFile(mapview);
            CloseHandle(m_FileHandle);
            m_FileHandle = INVALID_HANDLE_VALUE;
        }
        void* GetBase() {
            return mapview;
        }
        void* operator[](size_t offset) {
            if (offset > m_FileSize)return nullptr;
            return (void*)((uintptr_t)mapview + offset);
        }
    };
    class SystemRoutine {
    private:
        std::unordered_map<std::string, std::string> data;
        std::unordered_map<std::string, HMODULE> modules;
        SpinLock lock;
    public:
        SystemRoutine() {
            EnsureDirectoryExists(xor_str("Cache"));
            //如果当前是64位就读取Cache//Functioncache64.bin 否则读取Cache//Functioncache32.bin
            std::string path{};
            path.reserve(0x100);
            BOOL IsCurrentProcess = TRUE;
            BOOL isWow64 = FALSE; // 定义一个 BOOL 类型的变量来接收返回值
            if (IsWow64Process(GetCurrentProcess(), &isWow64)) {
                if (isWow64) {
                    // 当前进程在 64 位操作系统的 32 位兼容模式下运行
                    path = xor_str("Cache//Functioncache32.bin");
                }
                else {
                    // 当前进程在 64 位操作系统的 64 位模式下运行
                    path = xor_str("Cache//Functioncache64.bin");
                }
            }
            if (IsFileExistA(path.c_str())) data = readFromFile<std::string, std::string>(path);
            if (data.empty()) {
                ScanFile();
            }
        }
        ~SystemRoutine() {
            std::string path;
            BOOL isWow64 = FALSE; // 定义一个 BOOL 类型的变量来接收返回值
            if (IsWow64Process(GetCurrentProcess(), &isWow64)) {
                if (isWow64) {
                    // 当前进程在 64 位操作系统的 32 位兼容模式下运行
                    path = "Cache//Functioncache32.bin";
                }
                else {
                    // 当前进程在 64 位操作系统的 64 位模式下运行
                    path = xor_str("Cache//Functioncache64.bin");
                }
            }

            EnsureDirectoryExists(xor_str("Cache"));  // Ensure the directory exists
            if (!data.empty())writeToFile(path, data);
            for (auto& item : modules) {
                if (item.second) FreeLibrary(item.second);
            }
        }
        bool DirectoryExists(const std::string& dir) {
            DWORD ftyp = GetFileAttributesA(dir.c_str());
            if (ftyp == INVALID_FILE_ATTRIBUTES)return false;
            if (ftyp & FILE_ATTRIBUTE_DIRECTORY)return true;
            return false;
        }
        void EnsureDirectoryExists(const std::string& dir) {
            if (!DirectoryExists(dir))CreateDirectoryA(dir.c_str(), NULL);
        }
        inline HMODULE LoadApi(LPCSTR lpLibFileName) {
            auto iter = modules.find(lpLibFileName);
            if (iter == modules.end()) {
                auto hmodule = LoadLibraryA(lpLibFileName);
                modules.insert(std::make_pair(lpLibFileName, hmodule));
                return hmodule;
            }
            else {
                return iter->second;
            }
        }
        void ScanFile() {
            std::unordered_set<std::string> libPathSet;
            auto pathList = GetImportDirectory();
            libPathSet.reserve(pathList.size());
            for (size_t i = 0; i < pathList.size(); i++) {
                GetFiles(pathList[i], [&](const std::string& szPath) {
                    std::string strPath = szPath;
                    std::transform(strPath.begin(), strPath.end(), strPath.begin(), ::tolower);
                    if (strPath.find(xor_str(".dll")) != std::string::npos) {
                        EnterCriticalSection(&lock.Get());
                        libPathSet.insert(strPath);
                        LeaveCriticalSection(&lock.Get());
                    }
                    });
            }
            std::vector<std::string> libPath(libPathSet.cbegin(), libPathSet.cend());
            libPath.erase(std::remove_if(libPath.begin(), libPath.end(), [](std::string& path) {return path.find(xor_str(".dll")) == std::string::npos; }), libPath.end());
            std::sort(libPath.begin(), libPath.end(), [](std::string& path1, std::string& path2) {return path1.length() < path2.length(); });
#pragma omp parallel for schedule(dynamic,1)
            for (int i = 0; i < (int)libPath.size(); i++) {
                if (IsFileExistA(libPath[i].c_str())) {
                    auto hFile = CreateFileA(libPath[i].c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                    DWORD	dwFileSize = GetFileSize(hFile, 0);
                    std::vector<std::string> ExportFuncList{};
                    if ((dwFileSize / 8 / 1024) > 10) {
                        FileMapView mapview(hFile);
                        ExportFuncList = ScanExport(((char*)mapview.GetBase()));
                    }
                    else {
                        std::unique_ptr<char[]> buffer(new char[dwFileSize]);
                        DWORD dwRead = 0;
                        ReadFile(hFile, buffer.get(), dwFileSize, &dwRead, NULL);
                        ExportFuncList = ScanExport(buffer.get());
                    }
#pragma omp critical
                    for (auto& efun : ExportFuncList) {
                        if (!libPath[i].empty()) {
                            data.emplace(std::make_pair(efun, libPath[i]));
                        }
                    }
                }
            }
        }
        inline std::string GetExportDllName(const std::string& ExportFunctionName) {
            auto iter = data.find(ExportFunctionName);
            if (iter != data.end()) {
                return iter->second;
            }
            else {
                return "";
            }
        }
        void* GetRoutine(const char* _functionName, const char* _moduleName = "") {
            static std::unordered_map<std::string, void*> m_procAddrs;
            auto fullname = std::string(_moduleName) + _functionName;
            auto it = m_procAddrs.find(fullname);
            if (it == m_procAddrs.end()) {
                void* funcPtr = nullptr;
                HMODULE moduleHandle = nullptr;
                auto pLdr = (LDT*)NtCurrentTeb()->ProcessEnvironmentBlock->Ldr;
                auto pData = (Win32::LDRT*)pLdr->InLoadOrderModuleList.Blink;
                if (!pData) {
                    auto pFirst = pData;
                    do {
                        funcPtr = (void*)GetFunctionByName((LPVOID)pData->DllBase, (LPCSTR)_functionName);
                        if (funcPtr) {
                            moduleHandle = (HMODULE)pData->DllBase;
                            break;
                        }
                        pData = (Win32::LDRT*)pData->InLoadOrderLinks.Blink;
                    } while (pData != pFirst && pData->DllBase && !funcPtr);
                }
                if (!moduleHandle) moduleHandle = GetModuleHandleA(_moduleName);
                if (!moduleHandle) {
                    if (std::string(_moduleName).length() > 0) {
                        moduleHandle = LoadApi(_moduleName);
                    }
                    else {
                        auto dllname = GetExportDllName(_functionName);
                        moduleHandle = LoadApi(dllname.c_str());
                    }
                }
                if (moduleHandle) {
                    if (!funcPtr) funcPtr = (void*)GetFunctionByName(moduleHandle, _functionName);
                    if (funcPtr) {
                        m_procAddrs.insert(std::make_pair(fullname, funcPtr));
                    }
                }
                if (funcPtr) {
                    return funcPtr;
                }
                else {
                    return nullptr;
                }
            }
            else {
                return  it->second;
            }
        }
    };
    static SystemRoutine init;
    EXPORT void* GetRoutine(const char* _functionName, const char* _moduleName = "") {
        return init.GetRoutine(_functionName, _moduleName);
    }
    #define INLINE inline   //内联 inline
    #define NOEXCEPT noexcept   //不抛出异常 no throw exception
    #define PAGESIZE 0X1000 //页面大小 page size
    #if defined _WIN64
    #define XIP Rip//instruction pointer    指令指针
    #else
    #define XIP Eip//instruction pointer    指令指针
    #endif
    class NormalHandle {//阐明了句柄的关闭方式和句柄的无效值智能句柄的Traits clarify the handle's close method and handle's invalid value smart handle's Traits
    public:
        INLINE static void Close(HANDLE handle)NOEXCEPT { CloseHandle(handle); }    //关闭句柄 close handle
        INLINE static HANDLE InvalidHandle()NOEXCEPT { return INVALID_HANDLE_VALUE; }   //句柄的无效值 invalid value of handle
        INLINE static bool IsValid(HANDLE handle)NOEXCEPT { return handle != InvalidHandle() && handle; }   //判断句柄是否有效 judge whether handle is valid
        INLINE static DWORD Wait(HANDLE handle, DWORD time)NOEXCEPT { return WaitForSingleObject(handle, time); }//单位:毫秒 unit:ms    等待句柄 wait handle
    };
    template<class Ty>
    class HandleView :public Ty {//采用基础句柄的视图,不负责关闭句柄 use basic handle HandleView,not responsible for closing handle
    public:
        INLINE static void Close(HANDLE handle)NOEXCEPT { /*作为视图并不关闭 as a HandleView  doesn't close*/ }//多态具有自己的行为  polymorphism has its own behavior
    };
    template<class T, class Traits>
    class GenericHandle {//利用RAII机制管理句柄 use RAII mechanism to manage handle
    private:
        T m_handle = Traits::InvalidHandle();
        bool m_bOwner = false;//所有者 owner
        INLINE bool IsValid()NOEXCEPT { return Traits::IsValid(m_handle); }
    public:
        GenericHandle(const T& handle = Traits::InvalidHandle(), bool bOwner = true) :m_handle(handle), m_bOwner(bOwner) {}//构造 m_bOwner默认为true construct m_bOwner default is true
        ~GenericHandle() {
            if (m_bOwner && IsValid()) {//当句柄的所有者为true并且句柄有效时 When the handle owner is true and the handle is valid
                Traits::Close(m_handle);//关闭句柄 close handle
                m_handle = Traits::InvalidHandle();//设置句柄为无效值 set handle to invalid value
                m_bOwner = false;//设置句柄所有者为false set handle owner to false
            }
        }
        GenericHandle(GenericHandle&) = delete;//禁止拷贝构造函数 disable copy constructor
        GenericHandle& operator =(const GenericHandle&) = delete;//禁止拷贝赋值函数 disable copy assignment
        INLINE GenericHandle& operator =(GenericHandle&& other)NOEXCEPT {   //移动赋值 move assignment
            if (m_handle != other.m_handle) {
                m_handle = other.m_handle;
                m_bOwner = other.m_bOwner;
                other.m_handle = Traits::InvalidHandle();
                other.m_bOwner = false;
            }
            return *this;
        }
        //等待句柄 wait handle 单位:毫秒 unit:ms
        INLINE DWORD Wait(DWORD time)NOEXCEPT {
            return Traits::Wait(m_handle, time);
        }
        //判断和T类型是否相同 judge whether is same type with T
        inline bool operator==(const T& handle)NOEXCEPT {//重载== overload ==
            return m_handle == handle;
        }
        //重载!= overload !=
        inline bool operator!=(const T& handle)NOEXCEPT {//重载!= overload !=
            return m_handle != handle;
        }
        INLINE operator T() NOEXCEPT {//将m_handle转换为T类型,实际就是句柄的类型 convert m_handle to T type,actually is the type of handle
            return m_handle;
        }
        INLINE operator bool() NOEXCEPT {//重载bool类型,判断句柄是否有效 overload bool type, judge handle is valid
            return IsValid();
        }
        //重载取地址 overload get address of handle 
        INLINE T* operator&()NOEXCEPT {
            return &m_handle;
        }
        INLINE Traits* operator->()NOEXCEPT {//允许直接调用句柄的方法 allow to call handle's method directly
            return (Traits*)this;//强制转换为Traits类型 force convert to Traits type
        }
    };
    template <typename T>
    std::string GetMapName() {//获取共享内存的名字 get shared memory name
        DWORD pid = GetCurrentProcessId();
        std::string pidstr = std::to_string(pid);
        std::string name = typeid(T).name();
        std::string ret = pidstr + name;
        return ret;
    }
    template<class T>
    class Instance {//共享内存的实例 shared memory instance
        uintptr_t objaddr;
        LPVOID mapaddr;
        bool isOwend = false;
    public:
        HANDLE hFile;
        Instance(uintptr_t objaddr, LPVOID _mapaddr, bool isOwn, HANDLE hFile) :objaddr(objaddr), isOwend(isOwn), hFile(hFile), mapaddr(_mapaddr) {
        }
        ~Instance() {
            if (isOwend) {
                UnmapViewOfFile(mapaddr);//解除映射 unmap view of file 但是还没有关闭映射对象 but not close map object
            }
        }
        INLINE T* get() {
            return (T*)objaddr;
        }
    };
    template<class T>
    class InstanceManger {
    public:
        void* objaddr;//管理指针
        INLINE static Instance<T> CreateInstance(InstanceManger* thisinstance) {
            std::atomic_bool Owend = false;
            HANDLE hFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, GetMapName<T>().c_str());
            if (!hFile) {
                // 创建文件映射 Create file mapping
                hFile = CreateFileMappingA(
                    INVALID_HANDLE_VALUE, // 使用系统分页文件 use system paging file
                    NULL,                 // 默认安全属性   default security attributes
                    PAGE_READWRITE,       // 读写权限   read/write access
                    0,                    // 最大对象大小（高位）   maximum object size (high-order DWORD)
                    sizeof(T),            // 最大对象大小（低位）   maximum object size (low-order DWORD)
                    GetMapName<T>().c_str()); // 映射对象的名字// 映射对象的名字 map object name
                Owend = true;
            }
            if (!hFile) {
                throw std::runtime_error(xor_str("CreateFileMappingA failed with error code: ") + std::to_string(GetLastError()));   //创建文件映射失败 create file mapping failed
            }
            //这里既关闭映射对象又关闭文件句柄 close map object and file handle 因为映射对象一旦关闭,那么映射到内存的对象也会被释放 because once map object is closed,the object map to memory will be released
            auto p = static_cast<T*>(MapViewOfFile(hFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(T)));//映射到内存 map to memory 
            if (Owend && *(uintptr_t*)p == NULL)*(uintptr_t*)p = (uintptr_t)new T();//如果是第一次创建,那么初始化对象 if first create,then initialize object
            Instance<T> ret(*(uintptr_t*)p, (LPVOID)p, Owend, hFile);//映射对象交给Instance管理 map object is managed by Instance
            return ret;
        }
        template<class... Args>
        INLINE static Instance<T> CreateInstance(InstanceManger* thisinstance, Args&&... args) {
            std::atomic_bool Owend = false;
            HANDLE hFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, GetMapName<T>().c_str());
            if (!hFile) {
                // 创建文件映射 Create file mapping
                hFile = CreateFileMappingA(
                    INVALID_HANDLE_VALUE, // 使用系统分页文件   use system paging file
                    NULL,                 // 默认安全属性   default security attributes
                    PAGE_READWRITE,       // 读写权限   read/write access
                    0,                    // 最大对象大小（高位）   maximum object size (high-order DWORD)
                    sizeof(T),            // 最大对象大小（低位）   maximum object size (low-order DWORD)
                    GetMapName<T>().c_str()); // 映射对象的名字 map object name
                Owend = true;
            }
            if (!hFile) {
                throw std::runtime_error(xor_str("CreateFileMappingA failed with error code: ") + std::to_string(GetLastError()));   //创建文件映射失败 create file mapping failed
            }
            auto p = static_cast<T*>(MapViewOfFile(hFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(T)));
            if (Owend && *(uintptr_t*)p == NULL)*(uintptr_t*)p = (uintptr_t)new T(std::forward<Args>(args)...);
            Instance<T> ret(*(uintptr_t*)p, (LPVOID)p, Owend, hFile);
            return ret;
        }
    };
    template<class T>
    INLINE decltype(auto) SingleInstance()NOEXCEPT {
        InstanceManger<T> thisinstance;
        return InstanceManger<T>::CreateInstance(&thisinstance);    //创建一个类的实例 create a instance of class
    }
    template<class T, class... Args>
    INLINE decltype(auto) SingleInstance(Args&&... args)NOEXCEPT {
        InstanceManger<T> thisinstance;
        return InstanceManger<T>::CreateInstance(&thisinstance, args...);   //创建一个类的实例 create a instance of class
    }
    #define DELETE_COPYMOVE_CONSTRUCTOR(TYPE) TYPE(const TYPE&) = delete; TYPE(TYPE&&) = delete; void operator= (const TYPE&) = delete; void operator= (TYPE&&) = delete;
    template<class T>
    class InstanceMangerBase {
        std::vector<T*> instances;//映射的指针 map pointer
        std::vector<HANDLE> handles;//句柄 handle
    public:
        static InstanceMangerBase& GetInstance() {//本身是代码层面的单例模式,方便后期调用 singleton mode is convenient for later call
            static InstanceMangerBase instance;
            return instance;
        }
        ~InstanceMangerBase() {//当析构时释放所有句柄和对象 free all handle and object when destruct
            Clear();
            RemoveHandle();
        }
        INLINE void InsertObj(T* obj) { //插入一个映射对象 insert a map object
            instances.emplace_back(obj);
        }
        INLINE void InsertHandle(HANDLE handle) {   //插入一个句柄 insert a handle
            handles.emplace_back(handle);
        }
        INLINE void RemoveHandle()NOEXCEPT {
            // 对向量进行排序   sort vector
            std::sort(handles.begin(), handles.end());
            // 使用 std::unique 移除相邻的重复元素  use std::unique to remove adjacent duplicate elements
            handles.erase(std::unique(handles.begin(), handles.end()), handles.end());
            //关闭句柄  close handle
            for (auto& it : handles)CloseHandle(it);
            handles.clear();
        }
        INLINE void Clear()NOEXCEPT {
            for (auto& it : instances)delete it;
            instances.clear();
        }
    };
    template<typename T >
    class SingleTon {
    private:
        DELETE_COPYMOVE_CONSTRUCTOR(SingleTon)//删除拷贝构造函数和拷贝赋值函数 delete copy constructor and copy assignment
            static INLINE T* CreateInstance() NOEXCEPT {        //创建一个类的实例 create a instance of class
            auto obj = SingleInstance<T>(); //全局唯一的对象 global unique object
            auto objptr = obj.get();    //获得对象的指针 get object pointer
            InstanceMangerBase<T>::GetInstance().InsertObj(objptr);//获得映射对象的指针 get map object pointer
            InstanceMangerBase<T>::GetInstance().InsertHandle(obj.hFile);//获得映射对象的句柄 get map object handle
            return objptr;
        }//创建一个类的实例 create a instance of class
        template <class... Args>
        INLINE static INLINE T* CreateInstance(Args&& ...args) NOEXCEPT {
            auto obj = SingleInstance<T>(std::forward<Args>(args)...);  //全局唯一的对象 global unique object
            auto objptr = obj.get();    //获得对象的指针 get object pointer
            InstanceMangerBase<T>::GetInstance().InsertObj(objptr); //获得映射对象的指针 get map object pointer
            InstanceMangerBase<T>::GetInstance().InsertHandle(obj.hFile);   //获得映射对象的句柄 get map object handle
            return objptr;
        }
        template <class... Args>
        INLINE static T& GetInstanceImpl(Args&& ...args) NOEXCEPT {
            static std::once_flag flag{};
            static T* instance = nullptr;
            if (!instance) {
                std::call_once(flag, [&]() {//只调用一次保证了当前源码层面的单例模式  call once ensures the singleton mode of current source code
                    instance = CreateInstance(args...);//element constructor through parameters    通过参数构造元素
                });
            }
            return *instance;
        }
        INLINE static T& GetInstanceImpl() NOEXCEPT {
            static std::once_flag flag{};
            static T* instance = nullptr;
            if (!instance) {
                std::call_once(flag, [&]() {//call once  只调用一次
                    instance = CreateInstance();//element constructor through parameters    通过参数构造元素
                });
            }
            return *instance;
        }
    public:
        SingleTon() = default;
        std::atomic_bool m_bInit = false;
        template <class... Args>
        INLINE static T& GetInstance(Args&& ...args) NOEXCEPT {
            T& ptr=GetInstanceImpl(std::forward<Args>(args)...);//获得对象的指针 get object pointer
            if (!ptr.m_bInit) {
                ptr.m_bInit = true;
            }
            return ptr;
        }
        static T* GetInstancePtr() NOEXCEPT {
            //当对象没有初始化时,返回nullptr return nullptr when object is not initialized
            if(m_bInit)return &GetInstanceImpl();//创建一个实例并且返回指针 create a instance and return pointer
        }
    };
    //debugoutput   输出到调试窗口 output to debug window
    template<class T>
    void DebugOutput(const T& t) {
        //转为字符串    convert to string
        std::stringstream ss;
        ss << t;
        OutputDebugStringA(ss.str().c_str());
    }
    class FreeBlock {//空闲块 free block

    public:
        FreeBlock()= default;
        FreeBlock(void* _ptr,size_t _size) :size(_size), ptr(_ptr) {}
        size_t size;//大小 size
        void* ptr;  //指针 pointer
    };
    INLINE BOOL VirtualFreeExApi(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) NOEXCEPT {//远程释放内存 remote free memory
        return VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType);//系统的 VirtualFreeEx  system VirtualFreeEx
    }
    INLINE LPVOID VirtualAllocExApi(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) NOEXCEPT {//最基础的远程释放内存函数 the most basic remote free memory function 分配的粒度为0x1000  allocate granularity is 0x1000
        return VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);// 系统的 VirtualAllocEx  system VirtualAllocEx
    }
    constexpr DWORD CacheMinTTL = 128;
    constexpr DWORD CacheNormalTTL = 200;
    constexpr DWORD CacheMaxTTL = 4096;
    template<class T>
    struct RangeCmp {//仿函数   functor 用于比较范围  used to compare range
        INLINE bool operator()(const std::pair<T, T>& p1, const std::pair<T, T>& p2)const {
            if (p1.first >= p2.first) return false;
            return p1.second < p2.second;
        }
    };
    class FastMutex {
        CRITICAL_SECTION g_cs;
    public:
        FastMutex() { InitializeCriticalSection(&g_cs); }//初始化临界区 initialize critical section
        INLINE CRITICAL_SECTION& Get()NOEXCEPT { return g_cs; }//获得临界区 get critical section
        ~FastMutex() { DeleteCriticalSection(&g_cs); }//删除临界区 delete critical section
    };
    FastMutex lock;
    template<typename _Tx>class CacheItem {//缓存项 cache item
    public:
        using timepoint = std::chrono::time_point<std::chrono::system_clock>;
        timepoint m_endtime;
        _Tx   m_value;
        CacheItem() = default;
        CacheItem(const _Tx& _value, const timepoint& _endtime) :m_endtime(_endtime), m_value(_value) {}
        CacheItem(const _Tx&& _value, const timepoint& _endtime) :m_value(std::move(_value)), m_endtime(_endtime) {}
        ~CacheItem() { m_value.~_Tx(); }
        INLINE bool IsValid(timepoint now)NOEXCEPT { return now < m_endtime; }//通过当前时间判断是否有效 judge whether is valid through current time
    };
    template<typename _Tx, typename _Ty, class Pr = RangeCmp<_Tx>>
    class SimpleRangeCache {
    protected:
        std::map<std::pair<_Tx, _Tx>, CacheItem<_Ty>, Pr> m_Cache;//自定义的比较函数 custom compare function
    public:
        using keyType = std::pair<_Tx, _Tx>;
        using cache_item_type = _Ty;
        using pair_type = typename std::decay_t<decltype(m_Cache)>::value_type;
        using iterator = typename std::decay_t<decltype(m_Cache)>::iterator;
        SimpleRangeCache() { srand((unsigned int)time(0)); }
        ~SimpleRangeCache()noexcept { Clear(); }
        INLINE  void AsyncAddCache(const keyType& _key, const _Ty& _value, DWORD _validtime) NOEXCEPT {
            auto future = std::async(std::launch::async, [&]()->void {
                auto nowTime = std::chrono::system_clock::now();
                auto newValue = CacheItem<_Ty>(_value, nowTime + std::chrono::milliseconds(_validtime + rand() % 30));
                auto lb = m_Cache.find(_key);
                if (lb != m_Cache.end()) {
                    lb->second = newValue;
                }else {
                    EnterCriticalSection(&lock.Get());//加锁 lock
                    m_Cache.insert(lb, pair_type(_key, newValue));
                    LeaveCriticalSection(&lock.Get());//解锁 unlock
                }
                static auto firsttime = std::chrono::system_clock::now();
                if (std::chrono::duration_cast<std::chrono::milliseconds>(nowTime - firsttime).count() > 5000) {//5s
                    firsttime = nowTime;
                    EnterCriticalSection(&lock.Get());//加锁 lock
                    for (auto it = m_Cache.begin(); it != m_Cache.end();) it = (!it->second.IsValid(nowTime)) ? m_Cache.erase(it) : ++it;
                    LeaveCriticalSection(&lock.Get());//解锁 unlock
                }
            });
        }
        INLINE  std::pair<iterator, bool> find(const _Tx& value)NOEXCEPT {
            keyType _key = keyType(value, value);
            if (m_Cache.empty()) return { iterator(),false };
            auto iter = m_Cache.find(_key);
            EnterCriticalSection(&lock.Get());//加锁 lock
            bool IsValidItem = iter->second.IsValid(std::chrono::system_clock::now());
            LeaveCriticalSection(&lock.Get());//解锁 unlock
            return { iter, iter != m_Cache.end() && IsValidItem };
        }
        INLINE  std::pair<iterator, bool> operator[](_Tx&& value)NOEXCEPT {
            return find(value);
        }
        INLINE  void erase(const _Tx& value)NOEXCEPT {//删除缓存    delete cache
            keyType& _key = keyType(value, value);
            if (m_Cache.empty()) return;
            auto iter = m_Cache.find(_key);
            EnterCriticalSection(&lock.Get());//加锁 lock
            if (iter != m_Cache.end()) m_Cache.erase(iter);
            LeaveCriticalSection(&lock.Get());//解锁 unlock
        }
        INLINE  void Clear()NOEXCEPT {
            EnterCriticalSection(&lock.Get());//加锁 lock
            m_Cache.clear();
            LeaveCriticalSection(&lock.Get());//    解锁 unlock
        }
    };
    constexpr INLINE  bool CheckMask(const DWORD value, const DWORD mask)NOEXCEPT {//判断vakue和mask是否相等    judge whether value and mask is equal
        return (mask && (value & mask)) && (value <= mask);
    }
    constexpr auto USERADDR_MIN = 0x10000;
    #ifdef _WIN64
    constexpr auto USERADDR_MAX = 0x7fffffff0000;
    #else
    constexpr auto USERADDR_MAX = 0xBFFE'FFFF;
    #endif
    uintptr_t maxAppAddr = USERADDR_MAX;
    uintptr_t minAppAddr = USERADDR_MIN;
    static SimpleRangeCache<uintptr_t, MEMORY_BASIC_INFORMATION> cache;
    INLINE  SIZE_T VirtualQueryCacheApi(HANDLE hProcess, LPVOID lpAddress, MEMORY_BASIC_INFORMATION* lpMbi) NOEXCEPT {
        if ((uintptr_t)lpAddress > maxAppAddr) return 0;
        auto [result, isHit] = cache.find((uintptr_t)lpAddress);
        if (isHit) {
            if (lpMbi)*lpMbi = result->second.m_value;
            return sizeof(MEMORY_BASIC_INFORMATION);
        }else {
            SIZE_T ret = 0;
            if (hProcess && hProcess != INVALID_HANDLE_VALUE) ret = VirtualQueryEx(hProcess, lpAddress, lpMbi, sizeof(MEMORY_BASIC_INFORMATION));
            if (ret > 0) {
                uintptr_t start = (uintptr_t)lpMbi->AllocationBase;
                uintptr_t end = start + lpMbi->RegionSize, Ratio = 1;
                if (CheckMask(lpMbi->Type, MEM_IMAGE | MEM_MAPPED)) Ratio = 999;
                cache.AsyncAddCache(std::make_pair(start, end), *lpMbi, CacheNormalTTL * Ratio);
            }
            return ret;
        }
    }
    INLINE DWORD VirtualQueryExApi(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)NOEXCEPT {
        return VirtualQueryCacheApi(hProcess, (LPVOID)lpAddress, lpBuffer);//系统的 VirtualQueryEx  system
    }
    INLINE BOOL VirtualProtectExApi(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)NOEXCEPT {
        return VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);//系统的 VirtualProtectEx  system
    }
    //空闲块链表 free block list
    class FreeBlockList :public SingleTon<FreeBlockList> {//单例模式方便后期调用 singleton mode is convenient for later call
        std::deque<FreeBlock> m_freeBlocks;
        std::mutex m_mutex;
    public:
        FreeBlockList(HANDLE hprocess = GetCurrentProcess()) : m_head(nullptr) {
            m_hProcess = hprocess;
        }
        ~FreeBlockList() {//当析构时释放所有空闲块 free all free block when destruct
            std::lock_guard<std::mutex> lock(m_mutex);
            m_freeBlocks.clear();
        }
        INLINE void Add(void* ptr, size_t size) NOEXCEPT {//加入一个空闲块 add a free block
            std::lock_guard<std::mutex> lock(m_mutex);
            m_freeBlocks.push_back({ ptr,size });
        }
        INLINE void* Get(size_t size)NOEXCEPT {//获得一个空闲块 get a free block
            if (size <= 0) return nullptr;
            auto iter=std::find_if(m_freeBlocks.begin(), m_freeBlocks.end(), [&](const FreeBlock& block) {return block.size >= size; });
            if(iter==m_freeBlocks.end()){
                //空闲链表当中没有  find in free block list
                //没有找到合适的空闲块,那么就分配一个新的内存块 find no suitable free block,then allocate a new memory block
                void* ptr = nullptr;
                if (m_hProcess)ptr = VirtualAllocExApi(m_hProcess, nullptr, PAGESIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                Add(ptr, PAGESIZE);
                return Get(size);//递归调用 get recursively call
            }else{
                //空闲链表当中有    find in free block list
                auto &block = *iter;
                //空闲链表当中的块减去size  free block list minus size
                block.size -= size;
                auto ptr = (void*)(((uintptr_t)block.ptr) + block.size);
                std::lock_guard<std::mutex> lock(m_mutex);
                if (block.size == 0)m_freeBlocks.erase(iter);
                return ptr;
            }
            
        }
        INLINE void Free(void* ptr, size_t size)NOEXCEPT {
            //查allocatebase    find allocatebase
            MEMORY_BASIC_INFORMATION mbi{};
            VirtualQueryExApi(m_hProcess, ptr, &mbi, sizeof(mbi));
            //查询空闲列表中有没有和allcatebase相同的块 find whether there is a block same as allocatebase in free list
            std::lock_guard<std::mutex> lock(m_mutex);
            auto iter = std::find_if(m_freeBlocks.begin(), m_freeBlocks.end(), [&](const FreeBlock& block) {return block.ptr == mbi.AllocationBase; });
            if (iter != m_freeBlocks.end()) {
                //如果有,那么就把这个块的大小加上size
                (*iter).size += size;
            }
            //查找当前有没有块大PAGE_SIZE   find whether there is a block larger than PAGE_SIZE
            auto iter2 = std::find_if(m_freeBlocks.begin(), m_freeBlocks.end(), [&](const FreeBlock block) {return block.size > PAGESIZE; });
            //有就释放这个块
            if (iter2 != m_freeBlocks.end()) {
                auto& block = *iter2;
                //释放内存 free memory  
                if(m_hProcess)VirtualFreeExApi(m_hProcess, block.ptr, block.size, MEM_DECOMMIT);
                //释放内存 free memory
                m_freeBlocks.erase(iter2);
            }
        }
        INLINE void* mallocex(size_t size)NOEXCEPT {
            auto ptr = Get(size);
            g_allocMap[ptr] = size;
            return ptr;
        }
        INLINE void freeex(void* ptr)NOEXCEPT {
            auto it = g_allocMap.find(ptr);
            if (it == g_allocMap.end())return;
            Free(ptr, it->second);
            g_allocMap.erase(it);
        }
    private:
        std::unordered_map<void*, size_t> g_allocMap;//记录了每块分配出去的内存大小 record the size of each block of allocated memory
        FreeBlock* m_head;
        GenericHandle<HANDLE, HandleView<NormalHandle>> m_hProcess;//HandleView 句柄视图,不负责关闭句柄 HandleView handle view,not responsible for closing handle
    };
    INLINE void* mallocex(GenericHandle<HANDLE, HandleView<NormalHandle>> hProcess, size_t size) {
        void* ptr = nullptr;
        if(hProcess)ptr=FreeBlockList::GetInstance(hProcess).mallocex(size);//调用单例模式的函数 call singleton function
        return ptr;
    }
    INLINE void freeex(GenericHandle<HANDLE, HandleView<NormalHandle>> hProcess, void* ptr) {
        return FreeBlockList::GetInstance(hProcess).freeex(ptr);   //调用单例模式的函数 call singleton function
    }
    class Shared_Ptr {//一种外部线程的智能指针,当引用计数为0时释放内存 a smart pointer of external thread,release memory when reference count is 0
        GenericHandle<HANDLE, HandleView<NormalHandle>> m_hProcess;//并不持有 进程句柄而是一种视图,不负责关闭进程句柄 not hold process handle but a HandleView,not responsible for closing process handle
        LPVOID BaseAddress = nullptr;
        int refCount = 0;
        void AddRef() NOEXCEPT {
            refCount++;
        }
        INLINE uintptr_t _AllocMemApi(SIZE_T dwSize) NOEXCEPT {//远程分配内存 remote allocate memory
            uintptr_t ptr = NULL;
            if (m_hProcess) {
                ptr = (uintptr_t)mallocex((HANDLE)m_hProcess, dwSize);
                MEMORY_BASIC_INFORMATION mbi{};
                VirtualQueryExApi(m_hProcess, (LPVOID)ptr, &mbi, sizeof(mbi));
                if (mbi.Protect != PAGE_EXECUTE_READWRITE) {
                    DWORD dwoldprotect = 0;
                    VirtualProtectExApi(m_hProcess, (LPVOID)ptr, dwSize, PAGE_EXECUTE_READWRITE, &dwoldprotect);
                }
            }
            return ptr;
        }
        INLINE bool _FreeMemApi(LPVOID lpAddress) NOEXCEPT {//远程释放内存 remote free memory
            freeex((HANDLE)m_hProcess, lpAddress);
            return true;
        }
    public:
        INLINE Shared_Ptr(void* Addr, HANDLE hProc) : m_hProcess(hProc) {
            BaseAddress = Addr;
            AddRef();
        }
        template<class T>
        INLINE Shared_Ptr() NOEXCEPT {
            AddRef();//新建一个指针引用计数加一 reference count plus one means a new pointer points to this memory
            BaseAddress = (LPVOID)_AllocMemApi(sizeof(T));
        }
        INLINE Shared_Ptr(size_t nsize, HANDLE hProc) :m_hProcess(hProc) {
            AddRef();//引用计数加一说明有一个新的指针指向了这块内存 reference count plus one means a new pointer points to this memory
            BaseAddress = (LPVOID)_AllocMemApi(nsize);
        }
        INLINE Shared_Ptr(const Shared_Ptr& other) : BaseAddress(other.BaseAddress), refCount(other.refCount) {
            AddRef();//引用计数加一说明有一个新的指针指向了这块内存 reference count plus one means a new pointer points to this memory
        }
        INLINE Shared_Ptr& operator=(const Shared_Ptr& other) NOEXCEPT {//copy assignment   拷贝赋值
            if (this != &other) {
                Release();
                BaseAddress = other.BaseAddress;
                refCount = other.refCount;
                AddRef();//引用计数加一说明有一个新的指针指向了这块内存 reference count plus one means a new pointer points to this memory
            }
            return *this;
        }
        INLINE Shared_Ptr(Shared_Ptr&& other) NOEXCEPT {//move construct  移动构造
            BaseAddress = other.BaseAddress;
            refCount = other.refCount;
            other.BaseAddress = nullptr;//这样原来的指针就不会释放内存了 so the original pointer will not release memory
            other.refCount = 0;
        }
        INLINE LPVOID get() NOEXCEPT {//获得指针但是增加引用计数 get pointer but increase reference count
            AddRef();
            return BaseAddress;
        }
        INLINE LPVOID raw() const NOEXCEPT { return BaseAddress; }//不增加引用计数的获取raw指针 get raw pointer 
        INLINE ~Shared_Ptr() NOEXCEPT { Release(); }
        INLINE void Release() NOEXCEPT {//release and refCount-- 引用计数减一
            refCount--;
            if (BaseAddress && refCount <= 0) {
                _FreeMemApi(BaseAddress);//释放内存 free memory 只是归还空间到空闲块链表 return space to free block list
                BaseAddress = nullptr;
            }
        }
        INLINE operator bool() NOEXCEPT { return BaseAddress != nullptr; }
        //判等
        INLINE bool operator==(const Shared_Ptr& other) NOEXCEPT { return BaseAddress == other.BaseAddress; }
        //判不等
        INLINE bool operator!=(const Shared_Ptr& other) NOEXCEPT { return BaseAddress != other.BaseAddress; }
    };
    template<class T>Shared_Ptr make_Shared(size_t nsize, HANDLE hprocess) NOEXCEPT { return Shared_Ptr(sizeof(T) * nsize, hprocess); }
    template<class BinFunc>
    INLINE size_t GetFunctionSize(const BinFunc& func) NOEXCEPT {//获取函数大小,纯属经验之谈 get function size,just experience
        auto p = (PBYTE)func;
        for (int i = 0, len = 0; i < 4096; i++) {
            if (p[i] == 0xC2) {
                len = i;
                while (true) {
                    len += 3;
                    if (p[len] == 0xCC || (p[len] == 0x0 && p[len + 1] == 0x0))return len;
                    len = 0;
                    break;
                }
            }
            if (p[i] == 0xC3) {
                len = i;
                while (true) {
                    len++;
                    if ((p[len] == 0xCC && (p[len + 1] == 0 && p[len + 2] == 0 && p[len + 3] == 0 && p[len + 4] == 0 && p[len + 5] == 0)))return len;
                    if (p[len] == 0xFF || p[len] == 0xE9 || p[len] == 0xEB) return len;
                    if ((p[len] == 0xCC && (p[len + 1] >= 0x48)))return len;
                    len = 0;
                    break;
                }
            }
        }
        return (size_t)0;
    }
    template<class T1, class ...Args>struct has_type { static constexpr bool value = false; };
    template<class T1, class T2, class ...Args>struct has_type<T1, T2, Args...> { static constexpr bool value = has_type<T1, T2>::value || has_type<T1, Args...>::value; };
    template<class T1, class T2>struct has_type<T1, T2> { static constexpr bool value = false; };
    template<class T>struct has_type<T, T> { static constexpr bool value = true; }; //same type 同类型 check multiple type 检查多个类型
    template<class T1, class ...Args>constexpr bool has_type_v = has_type<T1, Args...>::value;
    template<typename T>struct remove_const_pointer { using type = typename std::remove_pointer<std::remove_const_t<T>>::type; };//remove const pointer  移除const指针
    template<typename T> using remove_const_pointer_t = typename remove_const_pointer<T>::type;//remove const pointer   移除const指针
    template<class Tx, class Ty> INLINE bool _ucsicmp(const Tx* str1, const Ty* str2) NOEXCEPT {//ignore case compare ignore type wchar_t wstring or char string 忽略大小写比较 忽略类型wchar_t wstring或者char string
        if (!str1 || !str2) throw std::exception(xor_str("str1 or str2 is nullptr"));
        std::wstring wstr1{}, wstr2{};
        std::string  strtemp{};
        auto to_wstring = [](const std::string& str)->std::wstring {
            static std::unordered_map<std::string, int> lengthbuffer;
            auto it = lengthbuffer.find(str);
            int nLen = 0;
            if (it == lengthbuffer.end()) {
                nLen = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, NULL, 0);
                lengthbuffer.insert(std::make_pair(str, nLen));
            }
            else {
                nLen = it->second;
            }
            if (nLen == 0) return L"";
            std::unique_ptr<wchar_t[]> pwszDst(new wchar_t[nLen]);
            if (!pwszDst) return L"";
            static std::unordered_map<std::string, std::wstring> wstringbuffer;
            auto it2 = wstringbuffer.find(str);
            if (it2 == wstringbuffer.end()) {
                MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, pwszDst.get(), nLen);
                wstringbuffer.insert(std::make_pair(str, std::wstring(pwszDst.get())));
            }
            else {
                memcpy(pwszDst.get(), it2->second.c_str(), nLen * sizeof(wchar_t));
            }
            std::wstring wstr(pwszDst.get());
            return wstr;
            };
        if constexpr (!std::is_same_v<remove_const_pointer_t<Tx>, wchar_t>) {
            strtemp = str1;
            wstr1 = to_wstring(strtemp);
        }
        else {
            wstr1 = str1;
        }
        if constexpr (!std::is_same_v<remove_const_pointer_t<Ty>, wchar_t>) {
            strtemp = str2;
            wstr2 = to_wstring(strtemp);
        }
        else {
            wstr2 = str2;
        }
        static std::unordered_map<size_t, bool> equalmap;
        //计算hash值    calculate hash value
        auto hash = [](const std::wstring& str)->size_t {
            static std::hash<std::wstring> hash_fn;
            return hash_fn(str);
        };
        auto hash1 = hash(wstr1);
        //combine hash value 合并hash值
        auto combinehash = [](size_t hash1, size_t hash2)->size_t {
            return hash1 ^ (hash2 << 1);
        };
        auto hash2 = hash(wstr2);
        auto hashvalue = combinehash(hash1, hash2);
        auto it = equalmap.find(hashvalue);
        if(it==equalmap.end()){
           std::transform(wstr1.begin(), wstr1.end(), wstr1.begin(), towlower);//transform to lower 转换为小写
            std::transform(wstr2.begin(), wstr2.end(), wstr2.begin(), towlower);//transform to lower    转换为小写
            auto equal= wstr1.compare(wstr2) == 0;        //容易忘记这里写什么才是正确的,这里是0,因为compare返回0表示相等 easy to forget what to write here is correct,here is 0,because compare return 0 means equal
            equalmap.insert(std::make_pair(hashvalue, equal));
            return equal;
        }else {
            return it->second;
        }

    }
    enum class EnumStatus {
        Continue,
        Break
    };
    //保存原始的对齐方式 save original align
    #pragma pack(push)
    #pragma pack(1)
    template<class Fn, class T>
    class ThreadDataBase {
    public:
        Fn fn;//function    函数
        char eventname[MAX_PATH];
        char funcname[4][MAX_PATH];
        LPVOID pFunc[2];
    };
    template<class Fn, class T>
    class ThreadData :public ThreadDataBase<Fn, T> {
    public:
        T retdata;//return data 返回值
    };
    template <class Fn>
    class ThreadData<Fn, void> :public ThreadDataBase<Fn, void> {//特化当返回值为void的情况 specialize when return value is void
    public:
    };
    template <class Fn, class T, class ...Args>
    class ThreadData2 :public ThreadData<Fn, T> {//Thread Data Struct inherit from ThreadData   线程数据结构继承自ThreadData
    public://这里的T会因为是void而选用ThreadData<Fn, void> T here will use ThreadData<Fn, void> because it is void
        std::tuple<Args...> params;//parameters   参数 多个参数用tuple存储 multiple parameters use tuple to store
    };
    #pragma pack(pop)//恢复原始pack restore original pack   
    //定义函数指针 define function pointer
    typedef HMODULE(WINAPI* PLOADLIBRARYA)(
        LPCSTR lpLibFileName
        );
    typedef FARPROC(WINAPI* PGETPROCADDRESS)(
        HMODULE hModule,
        LPCSTR  lpProcName
        );
    typedef HANDLE(WINAPI* POPENEVENTA)(
        DWORD dwDesiredAccess,
        BOOL bInheritHandle,
        LPCSTR lpName
        );
    typedef BOOL(WINAPI* PSETEVENT)(
        HANDLE hEvent
        );
    typedef BOOL(WINAPI* PCLOSEHANDLE)(
        HANDLE hObject
        );
    template <class Fn, class T>
    T ThreadFunction(void* param) noexcept {
        auto threadData = static_cast<ThreadData<Fn, T>*>(param);
        threadData->retdata = threadData->fn();
        auto pLoadLibrary = (PLOADLIBRARYA)threadData->pFunc[0];
        auto pGetProAddress = (PGETPROCADDRESS)threadData->pFunc[1];
        auto ntdll = pLoadLibrary(threadData->funcname[0]);
        //通过名字打开对应的事件 open event by name 名字已经事先定义好 name is defined in advance
        auto pOpenEventA = (POPENEVENTA)pGetProAddress(ntdll, threadData->funcname[1]);//加载OpenEventA    load OpenEventA
        auto hEventHandle = pOpenEventA(EVENT_ALL_ACCESS, FALSE, threadData->eventname); //打开事件  open event
        auto pSetEvent = (PSETEVENT)pGetProAddress(ntdll, threadData->funcname[2]);//设置事件  set event
        pSetEvent(hEventHandle);
        auto pCloseHandle = (PCLOSEHANDLE)pGetProAddress(ntdll, threadData->funcname[3]);//关闭句柄  close handle
        pCloseHandle(hEventHandle);
        return threadData->retdata;
    }
    template <class Fn, class T>
    void ThreadFunctionNoReturn(void* param) noexcept {
        auto threadData = static_cast<ThreadData<Fn, T>*>(param);
        threadData->fn();
        auto pLoadLibrary = (PLOADLIBRARYA)threadData->pFunc[0];
        auto pGetProAddress = (PGETPROCADDRESS)threadData->pFunc[1];
        auto ntdll = pLoadLibrary(threadData->funcname[0]);
        auto pOpenEventA = (POPENEVENTA)pGetProAddress(ntdll, threadData->funcname[1]);    //加载OpenEventA    load OpenEventA
        auto hEventHandle = pOpenEventA(EVENT_ALL_ACCESS, FALSE, threadData->eventname);    //打开事件  open event
        auto pSetEvent = (PSETEVENT)pGetProAddress(ntdll, threadData->funcname[2]);    //设置事件  set event
        pSetEvent(hEventHandle);
        auto pCloseHandle = (PCLOSEHANDLE)pGetProAddress(ntdll, threadData->funcname[3]);//关闭句柄  close handle
        pCloseHandle(hEventHandle);
    }
    template <class Fn, class T, class... Args>
    decltype(auto) ThreadFunction2(void* param) noexcept {
        auto threadData = static_cast<ThreadData2<Fn, T, Args...>*>(param);
        auto ret = [threadData](auto index) NOEXCEPT{
            threadData->retdata = std::apply(threadData->fn, threadData->params);
            return threadData->retdata;
        }(std::make_index_sequence<sizeof...(Args)>{});
        auto pLoadLibrary = (PLOADLIBRARYA)threadData->pFunc[0];
        auto pGetProAddress = (PGETPROCADDRESS)threadData->pFunc[1];
        auto ntdll = pLoadLibrary(threadData->funcname[0]);
        auto pOpenEventA = (POPENEVENTA)pGetProAddress(ntdll, threadData->funcname[1]);        //加载OpenEventA    load OpenEventA
        auto hEventHandle = pOpenEventA(EVENT_ALL_ACCESS, FALSE, threadData->eventname);        //打开事件  open event
        auto pSetEvent = (PSETEVENT)pGetProAddress(ntdll, threadData->funcname[2]);        //设置事件  set event
        pSetEvent(hEventHandle);
        auto pCloseHandle = (PCLOSEHANDLE)pGetProAddress(ntdll, threadData->funcname[3]);//关闭句柄  close handle
        pCloseHandle(hEventHandle);
        return ret;
    }
    template <class Fn, class T, class... Args>
    void ThreadFunction2NoReturn(void* param) noexcept {
        auto threadData = static_cast<ThreadData2<Fn, T, Args...>*>(param);
        [threadData] (auto index) NOEXCEPT{
            std::apply(threadData->fn, threadData->params);
        }(std::make_index_sequence<sizeof...(Args)>{});
        auto pLoadLibrary = (PLOADLIBRARYA)threadData->pFunc[0];
        auto pGetProAddress = (PGETPROCADDRESS)threadData->pFunc[1];
        auto ntdll = pLoadLibrary(threadData->funcname[0]);
        auto pOpenEventA = (POPENEVENTA)pGetProAddress(ntdll, threadData->funcname[1]);        //加载OpenEventA    load OpenEventA
        auto hEventHandle = pOpenEventA(EVENT_ALL_ACCESS, FALSE, threadData->eventname);        //打开事件  open event
        auto pSetEvent = (PSETEVENT)pGetProAddress(ntdll, threadData->funcname[2]);       //设置事件  set event
        pSetEvent(hEventHandle);
        auto pCloseHandle = (PCLOSEHANDLE)pGetProAddress(ntdll, threadData->funcname[3]);//关闭句柄  close handle
        pCloseHandle(hEventHandle);
    }
    //代码来自于<加密与解密>有关劫持线程注入的代码 第473页 code from <加密与解密> about thread hijacking inject page 473
    typedef class DATA_CONTEXT {
    public:
        BYTE ShellCode[0x30];				//x64:0X00   |->x86:0x00
        LPVOID pFunction;				    //x64:0X30	 |->x86:0x30
        PBYTE lpParameter;					//x64:0X38	 |->x86:0x34
        LPVOID OriginalEip;					//x64:0X40	 |->x86:0x38
    }*PINJECT_DATA_CONTEXT;
    #if defined _WIN64
    INLINE BYTE ContextInjectShell[] = {			//x64.asm 书中并没有给出x64的代码,这里是我自己写的  the book does not give the code of x64,here is my own code
        0x50,								//push	rax
        0x53,								//push	rbx
        0x9c,								//pushfq							//保存flag寄存器    save flag register
        0xe8,0x00,0x00,0x00,0x00,			//call	next
        0x5b,								//pop	rbx
        0x48,0x83,0xeb,0x08,				//sub	rbx,08
        0x51,								//push	rcx	
        0x48,0x83,0xEC,0x28,				//sub	rsp,0x28					//为call 的参数分配空间 allocate space for call parameter
        0x48,0x8b,0x4b,0x38,				//mov	rcx,[rbx+0x38]				//lparam 路径地址   lparam address
        0xff,0x53,0x30,						//call	qword ptr[rbx+0x30]			//call threadproc   call threadproc
        0x48,0x83,0xc4,0x28,				//add	rsp,0x28					//撤销临时空间  undo temporary space
        0x59,								//pop	rcx
        0x48,0x8b,0x43,0x40,				//mov	rax,[rbx+0x40]				//取rip到rax    get rip to rax
        0x48,0x87,0x44,0x24,0x24,			//xchg	[rsp+24],rax				
        0x9d,								//popfq								//还原标志寄存器    restore flag register
        0x5b,								//pop	rbx
        0x58,								//pop	rax
        0xc3,								//retn		
    };
    #else
    INLINE BYTE ContextInjectShell[] = {	//x86.asm 书中的代码  the code in the book
        0x50,								//push	eax
        0x60,								//pushad
        0x9c,								//pushfd
        0xe8,0x00,0x00,0x00,0x00,			//call	next
        0x5b,								//pop	ebx
        0x83,0xeb,0x08,						//sub	ebx,8
        0x3e,0xff,0x73,0x34,				//push	dword ptr ds:[ebx + 0x34]	//lparam
        0x3e,0xff,0x53,0x30,				//call	dword ptr ds:[ebx + 0x30]	//threadproc
        0x3e,0x8b,0x43,0x38,				//mov	eax,dword ptr ds:[ebx+0x38]	//取EIP到eax    get eip to eax
        0x87,0x44,0x24,0x24,				//xchg	eax,[esp+0x24]
        0x9d,								//popfd
        0x61,								//popad
        0xc3								//retn
    };
    #endif
    class Thread {//把线程当做对象来处理  process thread as object
        GenericHandle<HANDLE, NormalHandle> m_GenericHandleThread;//采用智能句柄  use smart handle
        DWORD m_dwThreadId = 0;
        std::atomic_bool m_bAttached = false;
    public:
        Thread() = default;
        Thread(DWORD dwThreadId) NOEXCEPT {    //打开线程 open thread
            m_dwThreadId = dwThreadId;
            m_GenericHandleThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_dwThreadId);
            if (m_GenericHandleThread)m_bAttached = true;
        }
        Thread(const THREADENTRY32& threadEntry) NOEXCEPT {   //从threadentry32构造 construct from threadentry32  to open thread
            m_dwThreadId = threadEntry.th32ThreadID;
            m_GenericHandleThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_dwThreadId);
            if (m_GenericHandleThread)m_bAttached = true;
        }
        Thread(Thread&& other) NOEXCEPT {    //移动构造  move construct
            m_GenericHandleThread = std::move(other.m_GenericHandleThread);
            m_dwThreadId = other.m_dwThreadId;
            bool Attached = other.m_bAttached;
            m_bAttached = Attached;
            other.m_dwThreadId = 0;
            other.m_bAttached = false;
        }
        Thread& operator=(Thread&& other) NOEXCEPT {    //移动赋值 move assignment
            if (this != &other) {
                m_GenericHandleThread = std::move(other.m_GenericHandleThread);
                m_dwThreadId = other.m_dwThreadId;
                bool Attached = other.m_bAttached;
                m_bAttached = Attached;
                other.m_dwThreadId = 0;
                other.m_bAttached = false;
            }
            return *this;
        }
        ~Thread() NOEXCEPT {}
        HANDLE GetHandle() NOEXCEPT { return m_GenericHandleThread; }//获取线程句柄  get thread handle
        operator bool() { return IsRunning(); }
        bool IsRunning() NOEXCEPT {
            //获取线程退出代码  get thread exit code
            if (m_bAttached) {
                DWORD dwExitCode = 0;
                if (GetExitCodeThread(GetHandle(), &dwExitCode)) {
                    if (dwExitCode == STILL_ACTIVE) {
                        return true;
                    }
                }
            }
            return false;
        }
        //获取线程上下文  get thread context
        CONTEXT GetContext() NOEXCEPT {
            CONTEXT context = {};
            if (m_bAttached) {
                context.ContextFlags = CONTEXT_FULL;
                GetThreadContext(GetHandle(), &context);
            }
            return context;
        }
        //设置线程的上下文  set thread context
        void SetContext(const CONTEXT& context) NOEXCEPT {
            if (m_bAttached) {
                SetThreadContext(GetHandle(), &context);
            }
        }
        //暂停线程执行  suspend thread execution
        void Suspend() NOEXCEPT {
            if (m_bAttached) {
                SuspendThread(GetHandle());
            }
        }
        //恢复线程执行  resume thread execution
        void Resume() NOEXCEPT {
            if (m_bAttached) {
                ResumeThread(GetHandle());
            }
        }
    };
    template <typename T>
    class ThreadSafeVector {//线程安全的vector thread safe vector
        std::mutex m_mutex; //lock for vector
        std::vector<T> m_vector;
    public:
        //聚合初始化    aggregate initialization
        ThreadSafeVector(std::initializer_list<T> list) :m_vector(list) {}
        ThreadSafeVector() = default;
        ThreadSafeVector(const ThreadSafeVector& other) {
            m_vector = other.m_vector;
        }
        INLINE ThreadSafeVector(size_t size) {
            m_vector.resize(size);
        }
        INLINE ThreadSafeVector& operator=(const ThreadSafeVector& other) NOEXCEPT {
            m_vector = other.m_vector;
            return *this;
        }
        INLINE ThreadSafeVector(ThreadSafeVector&& other) NOEXCEPT {
            m_vector = std::move(other.m_vector);
        }
        INLINE ThreadSafeVector& operator=(ThreadSafeVector&& other) NOEXCEPT {
            m_vector = std::move(other.m_vector);
            return *this;
        }
        INLINE ~ThreadSafeVector() = default;
        INLINE void push_back(const T& value) NOEXCEPT {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_vector.push_back(value);
        }
        INLINE void push_back(T&& value) NOEXCEPT {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_vector.push_back(std::move(value));
        }
        //emplace back  直接在vector中构造对象 construct object in vector directly
        template<class... Args>
        INLINE void emplace_back(Args&&... args) NOEXCEPT {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_vector.emplace_back(std::forward<Args>(args)...);
        }
        INLINE void pop_back() NOEXCEPT {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_vector.pop_back();
        }
        INLINE void clear() NOEXCEPT {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_vector.clear();
        }
        //data  直接返回vector的data return vector data directly
        INLINE decltype(auto) data() NOEXCEPT {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_vector.data();
        }
        INLINE T& operator[](size_t index) NOEXCEPT {
            return m_vector[index];
        }
        INLINE const T& operator[](size_t index) const {
            return m_vector[index];
        }
        INLINE size_t size() const {
            return m_vector.size();
        }
        INLINE void reserve(size_t size) NOEXCEPT {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_vector.reserve(size);
        }
        //resize
        INLINE void resize(size_t size) NOEXCEPT {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_vector.resize(size);
        }
        INLINE bool empty() const {
            return m_vector.empty();
        }
        INLINE decltype(auto)  begin()const {
            return m_vector.begin();
        }
        INLINE decltype(auto)  begin() NOEXCEPT {
            return m_vector.begin();
        }
        INLINE decltype(auto) end()const {
            return m_vector.end();
        }
        INLINE decltype(auto)  end() NOEXCEPT {
            return m_vector.end();
        }
    };
    enum class EnumRunningMode {
        POINTER_READ,
        POINTER_WRITE
    };
    template<class T>
    INLINE ThreadSafeVector<T> operator+(const ThreadSafeVector<T>& lhs, const ThreadSafeVector<T>& rhs) NOEXCEPT {
        ThreadSafeVector<T> result;
        result.reserve(lhs.size() + rhs.size());
        for (size_t i = 0; i < lhs.size(); i++)result.push_back(lhs[i]);
        for (size_t i = 0; i < rhs.size(); i++)result.push_back(rhs[i]);
        return result;
    }
    class RunningMode {
    public:
        LPVOID OriginAddr;
        EnumRunningMode m_RunningMode;
    };
    class Process :public SingleTon<Process> {//Singleton   单例
        GenericHandle<HANDLE, NormalHandle> m_hProcess;
        DWORD m_pid;//process id    进程id
        EnumRunningMode m_RunningMode = EnumRunningMode::POINTER_READ;
        std::atomic_bool m_bAttached;//atomic bool  原子bool
        ThreadSafeVector<Shared_Ptr> m_vecAllocMem;//vector for allocated memory    保存分配的内存的vector
        std::unordered_map<LPVOID, LPVOID> maptoorigin;//map for save original address and allocated address, key is allocated address value is original address    保存原始地址和分配地址的map，key是分配地址，value是原始地址
        template<typename T, typename ...Args>
        INLINE void preprocess(T& arg, Args&...args) NOEXCEPT {//partially specialized template 部分特化模板
            if constexpr (has_type_v<T, const char*, const wchar_t*>) preprocessparameter(arg);
            if constexpr (std::is_pointer_v<T> && !has_type_v<T, LPVOID, LPCVOID, const char*, const wchar_t*>)ProcessPtr(arg);
            if constexpr (sizeof...(args) > 0)preprocess(args...);
        }
        template<class T, typename ...Args>
        INLINE void postprocess(T& arg, Args&...args) NOEXCEPT {
            if (std::is_pointer_v<T> && !std::is_same_v<T, LPVOID> && !std::is_same_v<T, LPCVOID>)PostprocessPtr(arg);//post process pointer    后处理指针
            if constexpr (sizeof...(args) > 0)postprocess(args...);//keep process   继续处理
        }
        template<typename T>
        INLINE void PostprocessPtr(T& ptr) NOEXCEPT {
            auto iter = maptoorigin.find((LPVOID)ptr);//find original address   查找原始地址
            if (iter != maptoorigin.end()) {
                LPVOID OriginAddr = iter->second;//original address   原始地址
                if (m_RunningMode == EnumRunningMode::POINTER_READ) {
                    _ReadApi((LPVOID)ptr, OriginAddr, sizeof(T));//read value from allocated address to original address    从分配地址读取值到原始地址
                }
            }
        }
        template<typename T>
        INLINE void preprocessparameter(T& arg) NOEXCEPT {}
        INLINE void preprocessparameter(const char*& arg) NOEXCEPT {
            auto nlen = (int)strlen(arg) + 1;
            auto p = make_Shared<char>(nlen * sizeof(char), m_hProcess);
            if (p) {
                m_vecAllocMem.push_back(p);
                _WriteApi((LPVOID)p.get(), (LPVOID)arg, nlen * sizeof(char));
                arg = (const char*)p.raw();
            }
        }//process const char* parameter    处理const char*参数
        INLINE void preprocessparameter(const wchar_t*& arg) {
            auto nlen = (int)wcslen(arg) + 1;
            auto p = make_Shared<wchar_t>(nlen * sizeof(wchar_t), m_hProcess);
            if (p) {
                m_vecAllocMem.push_back(p);
                _WriteApi((LPVOID)p.get(), (LPVOID)arg, nlen * sizeof(wchar_t));
                arg = (const wchar_t*)p.raw();
            }
        }//process const wchar_t* parameter   处理const wchar_t*参数
        template<typename T>
        INLINE void ProcessPtr(T& ptr) NOEXCEPT {
            if (ptr) {
                int Size = sizeof(T);//get size of parameter    获取参数大小
                auto p = make_Shared<BYTE>(Size, m_hProcess);
                if (p) {
                    m_vecAllocMem.emplace_back(p);//emplace back into vector avoid memory leak can be clear through clearmemory   emplace back到vector中避免内存泄漏可以通过clearmemory清除
                    _WriteApi(p.get(), (LPVOID)ptr, Size);//write value to allocated address for parameter is pointer   写入值到分配地址，因为参数是指针
                    if (m_RunningMode == EnumRunningMode::POINTER_READ)maptoorigin.insert(std::make_pair((LPVOID)p.raw(), (LPVOID)ptr));//save original address and allocated address   保存原始地址和分配地址
                    ptr = (T)p.raw();//set parameter to allocated address   设置参数为分配地址
                }
            }
        }
    public:
        INLINE void Attach(const char* _szProcessName) NOEXCEPT {//attach process   附加进程
            //get process id    获取进程id
            auto pid = GetProcessIdByName(_szProcessName);
            if (pid) {
                m_pid = pid;
                m_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_pid);
                if (m_hProcess)m_bAttached = true;
            }
        }
        INLINE void ChangeMode(const EnumRunningMode& Mode) NOEXCEPT {
            m_RunningMode = Mode;
        }
        //readapi
        INLINE ULONG _ReadApi(_In_ LPVOID lpBaseAddress, _In_opt_ LPVOID lpBuffer, _In_ SIZE_T nSize) NOEXCEPT {//ReadProcessMemory
            if (m_bAttached) {
                SIZE_T bytesRead = 0;
                ReadProcessMemory(m_hProcess, lpBaseAddress, lpBuffer, nSize, &bytesRead);
                return bytesRead;
            }
            return 0;
        }
        //writeapi  
        INLINE ULONG _WriteApi(_In_ LPVOID lpBaseAddress, _In_opt_ LPVOID lpBuffer, _In_ SIZE_T nSize) NOEXCEPT {//WriteProcessMemory
            if (m_bAttached) {
                SIZE_T bytesWritten = 0;
                WriteProcessMemory(m_hProcess, lpBaseAddress, lpBuffer, nSize, &bytesWritten);
                return bytesWritten;
            }
            return 0;
        }
        template<class PRE>
        INLINE void EnumThread(PRE pre) NOEXCEPT {//enum thread through snapshot    通过快照枚举线程
            if (m_bAttached) {
                GenericHandle<HANDLE, NormalHandle> hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                if (hSnapshot) {
                    THREADENTRY32 threadEntry{ sizeof(THREADENTRY32), };
                    for (auto bRet = Thread32First(hSnapshot, &threadEntry); bRet; bRet = Thread32Next(hSnapshot, &threadEntry)) {
                        if (threadEntry.th32OwnerProcessID == m_pid) {
                            Thread thread(threadEntry);
                            if (thread && pre(threadEntry) == EnumStatus::Break)break;
                        }
                    }
                }
            }
        }
        INLINE void ClearMemory() NOEXCEPT {
            for (auto& p : m_vecAllocMem) p.Release();
            m_vecAllocMem.clear();
        }
        template <typename T>
        struct is_callable {
            template <typename U>
            static auto test(U* p) -> decltype((*p)(), std::true_type());
            template <typename U>
            static std::false_type test(...);
            static constexpr bool value = decltype(test<T>(nullptr))::value;//is callable
        };
        template<class _Fn, class ...Arg>
        INLINE void SetContextCallNoReturn(__in _Fn&& _Fx, __in Arg ...args) NOEXCEPT {
            static_assert(!is_callable<decltype(_Fx)>::value, "uncallable!");//函数必须可以调用 function must be callable
            SetContextCallNoReturnImpl(_Fx, args...);//返回值保存到retdata return value save to retdata
        }
        INLINE decltype(auto) SetContextCall(auto&& _Fx, auto&& ...args) NOEXCEPT {
            static_assert(!is_callable<decltype(_Fx)>::value, "uncallable!");//函数必须可以调用 function must be callable
            auto retdata = SetContextCallImpl(_Fx, args...);//返回值保存到retdata return value save to retdata
            using RetType = decltype(retdata);
            std::promise<RetType> promise{};//承诺对象
            std::future<RetType> fut = promise.get_future();
            promise.set_value(retdata);//设置承诺值 set promise value
            ClearMemory();//清除内存 clear memory 避免内存泄漏 avoid memory leak
            return fut;
        }
        template<class T, class ...Arg>
        INLINE decltype(auto) SetContextExportedCall(std::string_view funcname, __in Arg ...args) {
            return SetContextExportedCallImpl<T>(funcname, args...);
        }
        template<class T, class ...Arg>
        INLINE decltype(auto) SetContextExportedCallNoReturn(std::string_view funcname, __in Arg ...args) {
			return SetContextExportedCallNoReturnImpl<T>(funcname, args...);
        }
        template<class T, class ...Arg>
        //未导出函数调用  call unexported function
        INLINE decltype(auto) SetContextUndocumentedCall(LPVOID lpfunction,__in Arg ...args) {
			return SetContextUndocumentedCallImpl<T>(lpfunction,args...);
        }
        template<class T, class ...Arg>
        INLINE decltype(auto) SetContextUndocumentedCallNoReturn(LPVOID lpfunction, __in Arg ...args) {
			return SetContextUndocumentedCallNoReturnImpl<T>(lpfunction, args...);
        }
        template<class T>INLINE static T TONULL() NOEXCEPT { return  reinterpret_cast<T>(0); }
    private:
        template<class T, class ...Arg>
        INLINE decltype(auto) SetContextUndocumentedCallNoReturnImpl(LPVOID lpfunction, __in Arg ...args) {
            return SetContextCallNoReturn((T)lpfunction, args...);
        }
        template<class T>
        INLINE decltype(auto) SetContextUndocumentedCallNoReturnImpl(LPVOID lpfunction, std::string_view funcname) {
            return SetContextCallNoReturn((T)lpfunction);
        }
        template<class T, class ...Arg>
        //未导出函数调用  call unexported function
        INLINE decltype(auto) SetContextUndocumentedCallImpl(LPVOID lpfunction,__in Arg ...args) {
            return SetContextCall((T)lpfunction, args...);
        }
        template<class T>
        INLINE decltype(auto) SetContextUndocumentedCallImpl(LPVOID lpfunction) {
            return SetContextCall((T)lpfunction);
        }
        template<class T, class ...Arg>
        INLINE decltype(auto) SetContextExportedCallNoReturnImpl(std::string_view funcname, __in Arg ...args) {
            auto lpfunction = GetRoutine(funcname.data());
            return SetContextCallNoReturn((T)lpfunction, args...);
        }
        template<class T>
        INLINE decltype(auto) SetContextExportedCallNoReturnImpl(std::string_view funcname) {
            auto lpfunction = GetRoutine(funcname.data());
            return SetContextCallNoReturn((T)lpfunction);
        }
        template<class T, class ...Arg>
        INLINE decltype(auto) SetContextExportedCallImpl(std::string_view funcname, __in Arg ...args) {
            auto lpfunction = GetRoutine(funcname.data());
            return SetContextCall((T)lpfunction, args...);
        }
        template<class T>
        INLINE decltype(auto) SetContextExportedCallImpl(std::string_view funcname) {
            auto lpfunction = GetRoutine(funcname.data());
            return SetContextCall((T)lpfunction);
        }
        template <class _Fn>
        INLINE void SetContextCallNoReturnImpl(_Fn&& _Fx) NOEXCEPT {
            using RetType = void;
            uintptr_t _paramAddr = 0;
            ThreadData<std::decay_t<_Fn>, RetType> threadData;//thread data 线程数据
            strcpy_s(threadData.eventname, xor_str("SetContextCallImpl"));//event name   事件名
            strcpy_s(threadData.funcname[0], xor_str("kernel32.dll"));//kernel32.dll
            strcpy_s(threadData.funcname[1], xor_str("OpenEventA"));//OpenEventA
            strcpy_s(threadData.funcname[2], xor_str("SetEvent"));//SetEvent
            strcpy_s(threadData.funcname[3], xor_str("CloseHandle"));//CloseHandle
            //创建事件  create event
            GenericHandle<HANDLE, NormalHandle> hEvent = CreateEventA(NULL, FALSE, FALSE, threadData.eventname);
            if (hEvent) {
                threadData.pFunc[0] = (LPVOID)LoadLibraryA;
                threadData.pFunc[1] = (LPVOID)GetProcAddress;
                EnumThread([&](auto& te32)->EnumStatus {
                    auto thread = Thread(te32);//construct thread   构造线程
                    thread.Suspend();//suspend thread   暂停线程
                    auto ctx = thread.GetContext();//get context    获取上下文
                    auto lpShell = make_Shared<DATA_CONTEXT>(1, m_hProcess);//allocate memory for datacontext   分配内存
                    m_vecAllocMem.emplace_back(lpShell);//push back to vector for free memory   push back到vector中以释放内存
                    DATA_CONTEXT dataContext{};
                    memcpy(dataContext.ShellCode, ContextInjectShell, sizeof(ContextInjectShell));
                    threadData.fn = _Fx;
                    auto pFunction = &ThreadFunctionNoReturn<std::decay_t<_Fn>, RetType>;//get function address 获取函数地址
                    auto length = GetFunctionSize((BYTE*)pFunction);//get function length    获取函数长度
                    auto lpFunction = make_Shared<BYTE>(length, m_hProcess);//allocate memory for function  分配内存
                    m_vecAllocMem.emplace_back(lpFunction);
                    _WriteApi((LPVOID)lpFunction.get(), (LPVOID)pFunction, length);//write function to memory   写入函数到内存  
                    dataContext.pFunction = (LPVOID)lpFunction.raw();//set function address
                    dataContext.OriginalEip = (LPVOID)ctx.XIP;//set original eip    设置原始eip
                    using parametertype = decltype(threadData);//get parameter type 获取参数类型
                    auto lpParameter = make_Shared<parametertype>(1, m_hProcess);//allocate memory for parameter    分配内存
                    m_vecAllocMem.emplace_back(lpParameter);
                    _WriteApi((LPVOID)lpParameter.get(), &threadData, sizeof(parametertype));//write parameter to memory    写入参数到内存
                    dataContext.lpParameter = (PBYTE)lpParameter.raw();
                    _paramAddr = (uintptr_t)lpParameter.raw();
                    ctx.XIP = (uintptr_t)lpShell.raw();//set xip    设置xip
                    _WriteApi((LPVOID)lpShell.get(), &dataContext, sizeof(DATA_CONTEXT));//write datacontext to memory  写入datacontext到内存
                    thread.SetContext(ctx);//set context    设置上下文
                    thread.Resume();//resume thread 恢复线程
                    return EnumStatus::Break;
                    });
                hEvent.Wait(INFINITE);//wait event  等待事件
                ClearMemory();
            }
        }
        template<class _Fn, class ...Arg>
        INLINE void SetContextCallNoReturnImpl(__in _Fn&& _Fx, __in Arg ...args) NOEXCEPT {
            using RetType = void;
            if (!m_bAttached) return RetType();
            uintptr_t _paramAddr = 0;
            ThreadData2<std::decay_t<_Fn>, RetType, std::decay_t<Arg>...> threadData;
            strcpy_s(threadData.eventname, xor_str("SetContextCallImpl"));//event name   事件名
            strcpy_s(threadData.funcname[0], xor_str("kernel32.dll"));//kernel32.dll
            strcpy_s(threadData.funcname[1], xor_str("OpenEventA"));//OpenEventA
            strcpy_s(threadData.funcname[2], xor_str("SetEvent"));//SetEvent
            strcpy_s(threadData.funcname[3], xor_str("CloseHandle"));//CloseHandle
            //创建事件
            GenericHandle<HANDLE, NormalHandle> hEvent = CreateEventA(NULL, FALSE, FALSE, threadData.eventname);
            if (hEvent) {
                //设置函数地址
                threadData.pFunc[0] = (LPVOID)LoadLibraryA;
                threadData.pFunc[1] = (LPVOID)GetProcAddress;
                EnumThread([&](auto& te32)->EnumStatus {
                    auto thread = Thread(te32);//construct thread   构造线程
                    thread.Suspend();//suspend thread   暂停线程
                    auto ctx = thread.GetContext();//get context    获取上下文
                    auto lpShell = make_Shared<DATA_CONTEXT>(1, m_hProcess);//allocate memory   分配内存
                    m_vecAllocMem.emplace_back(lpShell);//
                    DATA_CONTEXT dataContext{};
                    memcpy(dataContext.ShellCode, ContextInjectShell, sizeof(ContextInjectShell));
                    if constexpr (sizeof...(args) > 0) preprocess(args...);//process parameter  处理参数
                    threadData.fn = _Fx;
                    threadData.params = std::tuple(std::forward<Arg>(args)...);//tuple parameters   tuple参数
                    auto pFunction = &ThreadFunction2NoReturn<std::decay_t<_Fn>, RetType, std::decay_t<Arg>...>;//get function address  获取函数地址
                    int length = GetFunctionSize((BYTE*)pFunction);//get function length    获取函数长度
                    auto lpFunction = make_Shared<BYTE>(length, m_hProcess);//allocate memory for function  分配内存
                    m_vecAllocMem.emplace_back(lpFunction);//push back to vector for free memory    push back到vector中以释放内存
                    _WriteApi((LPVOID)lpFunction.get(), (LPVOID)pFunction, length);//write function to memory   写入函数到内存
                    dataContext.pFunction = (LPVOID)lpFunction.raw();//set function address 设置函数地址
                    dataContext.OriginalEip = (LPVOID)ctx.XIP;//set original eip    设置原始eip
                    using parametertype = decltype(threadData);
                    auto lpParameter = make_Shared<parametertype>(1, m_hProcess);//allocate memory for parameter    分配内存
                    m_vecAllocMem.emplace_back(lpParameter);//push back to vector for free memory   push back到vector中以释放内存
                    _WriteApi((LPVOID)lpParameter.get(), &threadData, sizeof(parametertype));//write parameter  写入参数
                    dataContext.lpParameter = (PBYTE)lpParameter.raw();//set parameter address  设置参数地址
                    _paramAddr = (uintptr_t)lpParameter.raw();//set parameter address   设置参数地址
                    ctx.XIP = (uintptr_t)lpShell.raw();//set xip
                    _WriteApi((LPVOID)lpShell.get(), &dataContext, sizeof(DATA_CONTEXT));//write datacontext    写入datacontext
                    thread.SetContext(ctx);//set context    设置上下文
                    thread.Resume();//resume thread  恢复线程
                    return EnumStatus::Break;
                    });
                hEvent.Wait(INFINITE);//wait event
                if (maptoorigin.size() > 0)postprocess(args...);//post process parameter    后处理参数
                maptoorigin.clear();//clear map
                ClearMemory();
            }
        }
        template<class _Fn, class ...Arg>
        decltype(auto) SetContextCallImpl(__in _Fn&& _Fx, __in Arg ...args) NOEXCEPT {
            using RetType = std::common_type<decltype(_Fx(args...))>::type;//return type is common type or not
            if (!m_bAttached) return RetType();
            uintptr_t _paramAddr = 0;
            ThreadData2<std::decay_t<_Fn>, RetType, std::decay_t<Arg>...> threadData;
            strcpy_s(threadData.eventname, xor_str("SetContextCallImpl"));//event name
            strcpy_s(threadData.funcname[0], xor_str("kernel32.dll"));//kernel32.dll
            strcpy_s(threadData.funcname[1], xor_str("OpenEventA"));//OpenEventA
            strcpy_s(threadData.funcname[2], xor_str("SetEvent"));//SetEvent
            strcpy_s(threadData.funcname[3], xor_str("CloseHandle"));//CloseHandle
            //创建事件  create event
            GenericHandle<HANDLE, NormalHandle> hEvent = CreateEventA(NULL, FALSE, FALSE, threadData.eventname);
            if (hEvent) {
                threadData.pFunc[0] = (LPVOID)LoadLibraryA;
                threadData.pFunc[1] = (LPVOID)GetProcAddress;
                EnumThread([&](auto& te32)->EnumStatus {
                    auto thread = Thread(te32);//construct thread   构造线程
                    thread.Suspend();//suspend thread   暂停线程
                    auto ctx = thread.GetContext();//get context    获取上下文
                    auto lpShell = make_Shared<DATA_CONTEXT>(1, m_hProcess);//allocate memory   分配内存
                    m_vecAllocMem.emplace_back(lpShell);//
                    DATA_CONTEXT dataContext{};
                    memcpy(dataContext.ShellCode, ContextInjectShell, sizeof(ContextInjectShell));
                    if constexpr (sizeof...(args) > 0) preprocess(args...);//process parameter  处理参数
                    threadData.fn = _Fx;
                    threadData.params = std::tuple(std::forward<Arg>(args)...);//tuple parameters   tuple参数
                    auto pFunction = &ThreadFunction2<std::decay_t<_Fn>, RetType, std::decay_t<Arg>...>;//get function address  获取函数地址
                    auto length = GetFunctionSize((BYTE*)pFunction);//get function length    获取函数长度
                    auto lpFunction = make_Shared<BYTE>(length, m_hProcess);//allocate memory for function  分配内存
                    m_vecAllocMem.emplace_back(lpFunction);//push back to vector for free memory    push back到vector中以释放内存
                    _WriteApi((LPVOID)lpFunction.get(), (LPVOID)pFunction, length);//write function to memory   写入函数到内存
                    dataContext.pFunction = (LPVOID)lpFunction.raw();//set function address  设置函数地址
                    dataContext.OriginalEip = (LPVOID)ctx.XIP;//set original eip    设置原始eip
                    using parametertype = decltype(threadData);
                    auto lpParameter = make_Shared<parametertype>(1, m_hProcess);//allocate memory for parameter    分配内存
                    m_vecAllocMem.emplace_back(lpParameter);//push back to vector for free memory   push back到vector中以释放内存
                    _WriteApi((LPVOID)lpParameter.get(), &threadData, sizeof(parametertype));//write parameter  写入参数
                    dataContext.lpParameter = (PBYTE)lpParameter.raw();//set parameter address  设置参数地址
                    _paramAddr = (uintptr_t)lpParameter.raw();//set parameter address  设置参数地址
                    ctx.XIP = (uintptr_t)lpShell.raw();//set xip   设置xip
                    _WriteApi((LPVOID)lpShell.get(), &dataContext, sizeof(DATA_CONTEXT));//write datacontext    写入datacontext
                    thread.SetContext(ctx);//set context    设置上下文
                    thread.Resume();//resume thread   恢复线程
                    return EnumStatus::Break;
                    });
                hEvent.Wait(INFINITE);//wait event  等待事件
                if (maptoorigin.size() > 0)postprocess(args...);//post process parameter   后处理参数
                maptoorigin.clear();//clear map  清除map
                _ReadApi((LPVOID)_paramAddr, &threadData, sizeof(threadData));//read parameter for return value  读取参数以返回值
                return threadData.retdata;//return value    返回值
            }
        }
        template <class _Fn>
        INLINE decltype(auto) SetContextCallImpl(_Fn&& _Fx) NOEXCEPT {
            using RetType = std::common_type<decltype(_Fx())>::type;//return type is common type or not 返回类型是常见类型还是不是
            if (!m_bAttached) return RetType();//return default value   返回默认值
            uintptr_t _paramAddr = 0;
            ThreadData<std::decay_t<_Fn>, RetType> threadData;//thread data 线程数据
            strcpy_s(threadData.eventname, xor_str("SetContextCallImpl"));//event name   事件名
            strcpy_s(threadData.funcname[0], xor_str("kernel32.dll"));//kernel32.dll  kernel32.dll
            strcpy_s(threadData.funcname[1], xor_str("OpenEventA"));//OpenEventA 
            strcpy_s(threadData.funcname[2], xor_str("SetEvent"));//SetEvent
            strcpy_s(threadData.funcname[3], xor_str("CloseHandle"));//CloseHandle
            //创建事件  create event
            GenericHandle<HANDLE, NormalHandle> hEvent = CreateEventA(NULL, FALSE, FALSE, threadData.eventname);
            threadData.pFunc[0] = (LPVOID)LoadLibraryA;
            threadData.pFunc[1] = (LPVOID)GetProcAddress;
            EnumThread([&](auto& te32)->EnumStatus {
                auto thread = Thread(te32);//construct thread   构造线程
                thread.Suspend();//suspend thread   暂停线程
                auto ctx = thread.GetContext();//get context    获取上下文
                auto lpShell = make_Shared<DATA_CONTEXT>(1, m_hProcess);//allocate memory for datacontext   分配内存
                m_vecAllocMem.emplace_back(lpShell);//push back to vector for free memory   push back到vector中以释放内存
                DATA_CONTEXT dataContext{};
                memcpy(dataContext.ShellCode, ContextInjectShell, sizeof(ContextInjectShell));
                threadData.fn = _Fx;
                auto pFunction = &ThreadFunction<std::decay_t<_Fn>, RetType>;//get function address 获取函数地址
                auto length = GetFunctionSize((BYTE*)pFunction);//get function length    获取函数长度
                auto lpFunction = make_Shared<BYTE>(length, m_hProcess);//allocate memory for function  分配内存
                m_vecAllocMem.emplace_back(lpFunction);
                _WriteApi((LPVOID)lpFunction.get(), (LPVOID)pFunction, length);//write function to memory   写入函数到内存
                dataContext.pFunction = (LPVOID)lpFunction.raw();//set function address 设置函数地址
                dataContext.OriginalEip = (LPVOID)ctx.XIP;//set original eip    设置原始eip
                using parametertype = decltype(threadData);//get parameter type  获取参数类型
                auto lpParameter = make_Shared<parametertype>(1, m_hProcess);//allocate memory for parameter    分配内存
                m_vecAllocMem.emplace_back(lpParameter);
                _WriteApi((LPVOID)lpParameter.get(), &threadData, sizeof(parametertype));//write parameter to memory    写入参数到内存
                dataContext.lpParameter = (PBYTE)lpParameter.raw();
                _paramAddr = (uintptr_t)lpParameter.raw();
                ctx.XIP = (uintptr_t)lpShell.raw();//set xip   设置xip
                _WriteApi((LPVOID)lpShell.get(), &dataContext, sizeof(DATA_CONTEXT));//write datacontext to memory  写入datacontext到内存
                thread.SetContext(ctx);//set context    设置上下文
                thread.Resume();//resume thread  恢复线程
                return EnumStatus::Break;
                });
            hEvent.Wait(INFINITE);//wait event
            _ReadApi((LPVOID)_paramAddr, &threadData, sizeof(threadData));//read parameter for return value 读取参数以返回值
            return threadData.retdata;//return value    返回值
        }
        INLINE DWORD GetProcessIdByName(const char* processName) NOEXCEPT {//get process id by name   通过名称获取进程id
            DWORD pid = 0;
            //返回GenericHandle是为了防止忘记关闭句柄，因为GenericHandle析构函数会自动关闭句柄预防内存泄漏  return GenericHandle is for prevent forget close handle, because GenericHandle destructor will close handle automatically to prevent memory leak
            GenericHandle<HANDLE, NormalHandle> hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot) {
                //PROCESSENTRY32W processEntry = { sizeof(PROCESSENTRY32W), };
                PROCESSENTRY32W processEntry{ sizeof(PROCESSENTRY32W), };
                //采用for循环遍历进程快照，直到找到进程名为processName的进程 use for loop to enumerate process snapshot until find process name is processName
                for (auto bRet = Process32FirstW(hSnapshot, &processEntry); bRet; bRet = Process32NextW(hSnapshot, &processEntry)) {
                    //比较进程名 compare process name 不区分大小写不区分char*和wchar_t* case insensitive for char* and wchar_t*
                    if (_ucsicmp(processEntry.szExeFile, processName)) {
                        pid = processEntry.th32ProcessID;
                        break;
                    }
                }
            }
            return pid;
        }
    };
    template<class _PRE>
    float Test_Speed(int Times, _PRE bin) {
        DWORD time1 = clock();  //获取开始时间  get start time
        float count = 0;    //计数器  counter
        while (count < Times) { //循环执行  loop execute
            bin();
            count++;    //计数器加一  counter plus one
        }
        float elpstime = clock() - (float)time1;    //计算时间差  calculate time difference
        auto total = count / (elpstime / 1000.0f);  //计算速度  calculate speed 公式为：执行次数/（时间差/1000）    formula is: execute times / (time difference / 1000)
        printf(xor_str("Speed: %0.0f/s\r\n"), total);    //输出速度  output speed
        return total;   //返回速度  return speed
    }
}



