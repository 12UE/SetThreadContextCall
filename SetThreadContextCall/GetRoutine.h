#pragma once
#include <typeinfo>
#include<minwinbase.h>
#include<fstream>
#include<unordered_set>
#include<winnt.h>
#include<winternl.h>
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
EXPORT void* GetRoutine(const char* _functionName, const char* _moduleName="") {
	return init.GetRoutine(_functionName, _moduleName);
}


