#include <iostream>
#include <Windows.h>
#include <Zydis/Zydis.h>//through vcpkg install Zydis:x64-windows:vcpkg.exe install Zydis:x64-windows-static
#include <TlHelp32.h>
#pragma comment(lib,"Zydis.lib")//vcpkg use static lib
#include <atomic>
#include <algorithm>
#include <mutex>
#include <vector>
#include <tuple>
#include <thread>
#include <functional>
#include <array>
#if defined _WIN64
using UDWORD = DWORD64;
#define XIP Rip//instruction pointer
#define XAX Rax//accumulator
#define U64_ "%llx"  //U64_ When using, be careful not to add "%" again
#else
using UDWORD = DWORD32;
#define XIP Eip//instruction pointer
#define XAX Eax//accumulator
#define U64_ "%x"//U64_ When using, be careful not to add "%" again
#endif
#include"SharedPtr.h"
UDWORD GetLength(BYTE* _buffer, UDWORD _length = 65535) {//Get the length of the function default 65535 because the function is not so long
    ZyanU64 runtime_address = (ZyanU64)_buffer;
    ZyanUSize offset = 0;
    ZydisDisassembledInstruction instruction{};
    int length = 0;
#ifdef _WIN64
    while (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, runtime_address, _buffer + offset, _length - offset, &instruction))) {//disassemble
#else
    while (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_COMPAT_32, runtime_address, _buffer + offset, _length - offset, &instruction))) {//disassemble
#endif // !_WIN64
        offset += instruction.info.length;
        runtime_address += instruction.info.length;//add instruction length
        length += instruction.info.length;//add instruction length
        if (instruction.info.mnemonic == ZYDIS_MNEMONIC_RET) break;
    }
    return length;
    }
template<typename T>struct remove_const_pointer { using type = typename std::remove_pointer<std::remove_const_t<T>>::type; };//remove const pointer
template<typename T> using remove_const_pointer_t = typename remove_const_pointer<T>::type;//remove const pointer
template<class Tx, class Ty> inline size_t _ucsicmp(const Tx * str1, const Ty * str2) {//ignore case compare ignore type wchar_t wstring or char string
    if (!str1 || !str2) throw std::exception("str1 or str2 is nullptr");
    std::wstring wstr1{}, wstr2{};
    std::string  strtemp{};
    if constexpr (!std::is_same_v<remove_const_pointer_t<Tx>, wchar_t>) {
        strtemp = str1;
        wstr1 = std::wstring(strtemp.begin(), strtemp.end());//transform to wstring
    }else {
        wstr1 = str1;
    }
    if constexpr (!std::is_same_v<remove_const_pointer_t<Ty>, wchar_t>) {
        strtemp = str2;
        wstr2 = std::wstring(strtemp.begin(), strtemp.end());//transform to wstring
    }else {
        wstr2 = str2;
    }
    std::transform(wstr1.begin(), wstr1.end(), wstr1.begin(), towlower);//transform to lower
    std::transform(wstr2.begin(), wstr2.end(), wstr2.begin(), towlower);//transform to lower
    return wstr1.compare(wstr2);
}
#define DELETE_COPYMOVE_CONSTRUCTOR(TYPE) TYPE(const TYPE&)=delete;TYPE(TYPE&&) = delete;void operator= (const TYPE&) = delete;void operator= (TYPE&&) = delete;
template<typename T >
class SingleTon {
private:
    DELETE_COPYMOVE_CONSTRUCTOR(SingleTon)
public:
    SingleTon() = default;
    template <class... Args>
    static T& GetInstance(Args&& ...args) {//get instance this function is thread safe and support parameter
        static std::once_flag flag{};
        static std::shared_ptr<T> instance = nullptr;
        if (!instance) {
            std::call_once(flag, [&]() {//call once
                instance = std::make_shared<T>(args...);//element constructor through parameters
                });
        }
        return *instance.get();//return instance
    }
};
#define EnumStatus_Continue (int)0
#define EnumStatus_Break (int)1
//保存原始pack
#pragma pack(push)
#pragma pack(1)
template<typename T, typename... Args>
class ThreadData {
public:
    std::tuple<Args...> datas;
    T retdata{};
    template <std::size_t... Indices>
    auto GetParamHelper(const std::tuple<Args...>& tpl, std::index_sequence<Indices...>) {
        return std::make_tuple(std::get<Indices>(tpl)...);
    }
    auto GetParam() {
        return GetParamHelper(datas, std::index_sequence_for<Args...>{});
    }
};
template <class Fn,class T>
struct ThreadData2 {//Thread Data Struct
    Fn fn;
    T retdata{};
};
#pragma pack(pop)
template <class T, class... Args, size_t... Indices>
decltype(auto) ThreadFunctionImpl(ThreadData<T, Args...>* threadData, std::index_sequence<Indices...>) noexcept {
    T retdata = std::get<0>(threadData->datas)(std::get<Indices+1>(threadData->datas)...);
    threadData->retdata = retdata;
    return retdata;
}
template <class T, class... Args>
decltype(auto) ThreadFunction(void* param) noexcept {
    auto threadData = static_cast<ThreadData<T, Args...>*>(param);
    return ThreadFunctionImpl(threadData, std::make_index_sequence<sizeof...(Args) - 1>{});
}
template <class Fn,class T>
T ThreadFunction2(void* param) noexcept {
    auto threadData = static_cast<ThreadData2<Fn,T>*>(param);
    threadData->retdata = threadData->fn();
    return threadData->retdata;
}
typedef class DATA_CONTEXT {
public:
    BYTE ShellCode[0x30];				//x64:0X00   |->x86:0x00
    LPVOID pFunction;				    //x64:0X30	 |->x86:0x30
    PBYTE lpParameter;					//x64:0X38	 |->x86:0x34
    LPVOID OriginalEip;					//x64:0X40	 |->x86:0x38
}*PINJECT_DATA_CONTEXT;
#if defined _WIN64
inline BYTE ContextInjectShell[] = {			//x64.asm
    0x50,								//push	rax
    0x53,								//push	rbx
    0x9c,								//pushfq							//保存flag寄存器
    0xe8,0x00,0x00,0x00,0x00,			//call	next
    0x5b,								//pop	rbx
    0x48,0x83,0xeb,0x08,				//sub	rbx,08
    0x51,								//push	rcx	
    0x48,0x83,0xEC,0x28,				//sub	rsp,0x28					//为call 的参数分配空间
    0x48,0x8b,0x4b,0x38,				//mov	rcx,[rbx+0x38]				//lparam 路径地址
    0xff,0x53,0x30,						//call	qword ptr[rbx+0x30]			//call threadproc
    0x48,0x83,0xc4,0x28,				//add	rsp,0x28					//撤销临时空间
    0x59,								//pop	rcx
    0x48,0x8b,0x43,0x40,				//mov	rax,[rbx+0x40]				//取rip到rax
    0x48,0x87,0x44,0x24,0x24,			//xchg	[rsp+24],rax				
    0x9d,								//popfq								//还原标志寄存器
    0x5b,								//pop	rbx
    0x58,								//pop	rax
    0xc3,								//retn		
};
#else
inline BYTE ContextInjectShell[] = {	//x86.asm
    0x50,								//push	eax
    0x60,								//pushad
    0x9c,								//pushfd
    0xe8,0x00,0x00,0x00,0x00,			//call	next
    0x5b,								//pop	ebx
    0x83,0xeb,0x08,						//sub	ebx,8
    0x3e,0xff,0x73,0x34,				//push	dword ptr ds:[ebx + 0x34]	//lparam
    0x3e,0xff,0x53,0x30,				//call	dword ptr ds:[ebx + 0x30]	//threadproc
    0x3e,0x8b,0x43,0x38,				//mov	eax,dword ptr ds:[ebx+0x38]	//取EIP到eax
    0x87,0x44,0x24,0x24,				//xchg	eax,[esp+0x24]
    0x9d,								//popfd
    0x61,								//popad
    0xc3								//retn
};
#endif
class Thread {
    HANDLE m_hThread = INVALID_HANDLE_VALUE;
    DWORD m_dwThreadId = 0;
    bool m_bAttached = false;
public:
    Thread() = default;
    //打开线程
    Thread(DWORD dwThreadId) {
        m_dwThreadId = dwThreadId;
        m_hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_dwThreadId);
        m_bAttached = true;
    }
    //从threadentry32构造
    Thread(const THREADENTRY32& threadEntry) {
        m_dwThreadId = threadEntry.th32ThreadID;
        m_hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_dwThreadId);
        m_bAttached = true;
    }
    //移动构造
    Thread(Thread&& other) {
        m_hThread = other.m_hThread;
        m_dwThreadId = other.m_dwThreadId;
        m_bAttached = other.m_bAttached;
        other.m_hThread = INVALID_HANDLE_VALUE;
        other.m_dwThreadId = 0;
        other.m_bAttached = false;
    }
    //移动赋值
    Thread& operator=(Thread&& other) {
        if (this != &other) {
            m_hThread = other.m_hThread;
            m_dwThreadId = other.m_dwThreadId;
            m_bAttached = other.m_bAttached;
            other.m_hThread = INVALID_HANDLE_VALUE;
            other.m_dwThreadId = 0;
            other.m_bAttached = false;
        }
        return *this;
    }
    //关闭线程句柄
    ~Thread() {
        if (m_bAttached)CloseHandle(m_hThread);
    }
    //获取线程句柄
    HANDLE GetHandle() {return m_hThread;}
    bool IsRunning() {
        //获取线程退出代码
        DWORD dwExitCode = 0;
        if (GetExitCodeThread(m_hThread, &dwExitCode)) {
            if (dwExitCode == STILL_ACTIVE) {
                return true;
            }
        }
        return false;
    }
    //获取上下文
    CONTEXT GetContext() {
        CONTEXT context = { 0 };
        context.ContextFlags = CONTEXT_FULL;
        GetThreadContext(m_hThread, &context);
        return context;
    }
    //设置上下文
    void SetContext(CONTEXT& context) {
        SetThreadContext(m_hThread, &context);
    }
    //暂停
    void Suspend() {
        SuspendThread(m_hThread);
    }
    //恢复
    void Resume() {
        ResumeThread(m_hThread);
    }
};  //forward declaration
template<typename T>
T gettype(const T& arg) {
    return decltype(arg);
}
class Process :public SingleTon<Process> {//Singleton
    HANDLE m_hProcess = INVALID_HANDLE_VALUE;
    DWORD m_pid;//process id
    std::atomic_bool m_bAttached;//atomic bool
    std::vector<Shared_Ptr> m_vecAllocMem;//vector for allocated memory
    template<typename T, typename ...Args>
    void preprocess(T& arg, Args&...args) {//partially specialized template
        if constexpr (std::is_same_v<T, const char*>|| std::is_same_v<T, const wchar_t*>) preprocessparameter(arg);
        if constexpr(sizeof...(args)>0)preprocess(args...);
    }
    template<typename T>void preprocessparameter(T& arg) {}
    void preprocessparameter(const char*& arg);//process const char* parameter
    void preprocessparameter(const wchar_t*& arg);//process const wchar_t* parameter
public:
    void Attach(const char* _szProcessName) {//attach process
        //get process id
        auto pid = GetProcessIdByName(_szProcessName);
        if (pid != 0) {
            m_pid = pid;
            m_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_pid);
            m_bAttached = true;
        }
    }
    //readapi
    ULONG _ReadApi(_In_ LPVOID lpBaseAddress, _In_opt_ LPVOID lpBuffer, _In_ SIZE_T nSize) {//ReadProcessMemory
        if (m_bAttached) {
            SIZE_T bytesRead = 0;
            ReadProcessMemory(m_hProcess, lpBaseAddress, lpBuffer, nSize, &bytesRead);
            return bytesRead;
        }
        return 0;
    }
    ULONG _WriteApi(_In_ LPVOID lpBaseAddress, _In_opt_ LPVOID lpBuffer, _In_ SIZE_T nSize) {//WriteProcessMemory
        if (m_bAttached) {
            SIZE_T bytesWritten = 0;
            WriteProcessMemory(m_hProcess, lpBaseAddress, lpBuffer, nSize, &bytesWritten);
            return bytesWritten;
        }
        return 0;
    }
    UDWORD _AllocMemApi(SIZE_T dwSize, LPVOID PageBase = NULL) {//return allocated memory address
        if (m_bAttached) {
            auto allocatedMemory = VirtualAllocEx(m_hProcess, PageBase, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            return reinterpret_cast<UDWORD>(allocatedMemory);
        }
        return 0;
    }
    int _FreeMemApi(LPVOID lpAddress) {//free memory
        if (m_bAttached)return VirtualFreeEx(m_hProcess, lpAddress, 0, MEM_RELEASE);
        return 0;
    }
    template<class PRE>
    void EnumThread(PRE pre) {//enum thread through snapshot
        if (m_bAttached) {
            auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                THREADENTRY32 threadEntry = { 0 };
                threadEntry.dwSize = sizeof(THREADENTRY32);
                if (Thread32First(hSnapshot, &threadEntry)) {
                    do {
                        if (threadEntry.th32OwnerProcessID == m_pid) {
                            Thread thread(threadEntry.th32ThreadID);
                            if (thread.IsRunning()) {
                                if (pre(threadEntry) ==EnumStatus_Break){
                                    break;
                                }
                            }
                        }
                    } while (Thread32Next(hSnapshot, &threadEntry));
                }
                CloseHandle(hSnapshot);
            }
        }
    }
    template<class _Fn, class ...Arg>
    decltype(auto) SetContextCallImpl(__in _Fn&& _Fx, __in Arg&& ...args){
        using RetType = decltype(_Fx(args...));
        if(!m_bAttached)return RetType();
        RetType retdata{};
        Thread _thread{};
        CONTEXT _ctx{};
        UDWORD ParamAddr = 0;
        EnumThread([&](const THREADENTRY32& te32)->int {
            auto thread = Thread(te32.th32ThreadID);
            thread.Suspend();
            auto ctx = thread.GetContext();
            auto lpShell = make_Shared<DATA_CONTEXT>(1, m_hProcess);
            DATA_CONTEXT dataContext{};
            memcpy(dataContext.ShellCode, ContextInjectShell, sizeof(ContextInjectShell));
            if constexpr (sizeof...(args) > 0) preprocess(args...);
            ThreadData<RetType, std::decay_t<_Fn>, std::decay_t<Arg>...> threadData{ std::tuple(std::forward<std::decay_t<_Fn>>(_Fx), std::forward<Arg>(args)...),RetType() };
            auto pFunction = &ThreadFunction<RetType, std::decay_t<_Fn>, std::decay_t<Arg>...>;
            int length = GetLength((BYTE*)pFunction);
            auto lpFunction = make_Shared<BYTE>(length, m_hProcess);
            _WriteApi((LPVOID)lpFunction.get(), (LPVOID)pFunction, length);
            dataContext.pFunction = (LPVOID)lpFunction.raw();
            dataContext.OriginalEip = (LPVOID)ctx.XIP;
            using parametertype = decltype(threadData);
            auto lpParameter = make_Shared<parametertype>(1, m_hProcess);
            _WriteApi((LPVOID)lpParameter.get(), &threadData, sizeof(parametertype));
            dataContext.lpParameter = (PBYTE)lpParameter.get();
            ParamAddr = (UDWORD)lpParameter.raw();
            _ctx = ctx;
            ctx.XIP = (UDWORD)lpShell.raw();
            _WriteApi((LPVOID)lpShell.get(), &dataContext, sizeof(DATA_CONTEXT));
            thread.SetContext(ctx);
            thread.Resume();
            _thread = std::move(thread);
            return EnumStatus_Break;
        });
        do{
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
            _thread.Suspend();
            _ctx = _thread.GetContext();
            _thread.Resume();
        }while((UDWORD)_ctx.XIP<=(UDWORD)_ctx.XIP);
        for(auto& p:m_vecAllocMem)p.Release();
        ThreadData<RetType, std::decay_t<_Fn&&>, std::decay_t<Arg>...> _threadData{ std::tuple(std::forward<std::decay_t<_Fn&&>>(_Fx), std::forward<Arg>(args)...),RetType() };
        using parametertype = decltype(_threadData);
        _ReadApi((LPVOID)ParamAddr, &_threadData, sizeof(parametertype));
        retdata = _threadData.retdata;
        return retdata;
    }
    template <class _Fn>
    decltype(auto) SetContextCallImpl(_Fn&& _Fx) {
        using RetType=std::decay_t<decltype(_Fx())>;
        if (!m_bAttached)return RetType();
        RetType retdata{};
        UDWORD paramaddr= 0;
        ThreadData2< std::decay_t<_Fn>, RetType> threadData{ std::decay_t<_Fn>(_Fx),RetType() };
        using parametertype = decltype(threadData);
        CONTEXT _context{};
        Thread _thread{};
        UDWORD oldXIP = 0;
        EnumThread([&](THREADENTRY32 te32)->int {
            auto thread = Thread(te32.th32ThreadID);
            thread.Suspend();
            auto ctx = thread.GetContext();
            _context = ctx;
            auto lpShell = make_Shared<DATA_CONTEXT>(1, m_hProcess);
            if (!lpShell)return EnumStatus_Break;
            m_vecAllocMem.emplace_back(lpShell);
            DATA_CONTEXT dataContext{};
            memcpy(dataContext.ShellCode, ContextInjectShell, sizeof(ContextInjectShell));
            auto pFunction = &ThreadFunction2<std::decay_t<_Fn>, RetType>;
            int length = GetLength((BYTE*)pFunction);
            auto lpFunction = make_Shared<BYTE>(length, m_hProcess);
            if (!lpFunction)return EnumStatus_Break;
            m_vecAllocMem.emplace_back(lpFunction);
            _WriteApi((LPVOID)lpFunction.get(), (LPVOID)pFunction, length);
            dataContext.pFunction = (LPVOID)lpFunction.raw();
            dataContext.OriginalEip = (LPVOID)ctx.XIP;
            auto lpParameter = make_Shared<parametertype>(1, m_hProcess);
            if (!lpParameter)return EnumStatus_Break;
            m_vecAllocMem.emplace_back(lpParameter);
            paramaddr = (UDWORD)lpParameter.raw();
            _WriteApi((LPVOID)lpParameter.get(), &threadData, sizeof(parametertype));
            dataContext.lpParameter = (PBYTE)lpParameter.get();
            oldXIP = ctx.XIP;
            ctx.XIP = (UDWORD)lpShell.raw();
            _WriteApi((LPVOID)lpShell.get(), &dataContext, sizeof(DATA_CONTEXT));
            thread.SetContext(ctx);
            thread.Resume();
            _thread = std::move(thread);
            return EnumStatus_Break;
        });
        CONTEXT _ctx = { 0 };
        do {
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
            _thread.Suspend();
            _ctx = _thread.GetContext();
            _thread.Resume();
        } while ((UDWORD)_ctx.XIP <= oldXIP);
        for (auto& p : m_vecAllocMem)p.Release();
        _ReadApi((LPVOID)paramaddr, &threadData, sizeof(parametertype));
        retdata = threadData.retdata;
        return retdata;
    }
    template<class _Fn, class ...Arg>
    decltype(auto) SetContextCall(__in _Fn&& _Fx, __in Arg&& ...args) {
        return SetContextCallImpl(_Fx, args...);
    }
private:

    DWORD GetProcessIdByName(const char* processName) {//get process id by name
        DWORD pid = 0;
        auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 processEntry = { 0 };
            processEntry.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnapshot, &processEntry)) {
                do {
                    if (_ucsicmp(processEntry.szExeFile, processName) == 0) {
                        pid = processEntry.th32ProcessID;
                        break;
                    }
                } while (Process32Next(hSnapshot, &processEntry));
            }
            CloseHandle(hSnapshot);
        }
        return pid;
    }
};




void Process::preprocessparameter(const char*& arg) {//process parameter
    auto nlen = (int)strlen(arg) + 1;
    auto p = make_Shared<char>(nlen * sizeof(char), m_hProcess);
    if (p) {
        m_vecAllocMem.push_back(p);
        _WriteApi((LPVOID)p.get(), (LPVOID)arg, nlen * sizeof(char));
        arg = (const char*)p.raw();
    }
}
void Process::preprocessparameter(const wchar_t*& arg) {//process parameter
    auto nlen = (int)wcslen(arg) + 1;
    auto p = make_Shared<wchar_t>(nlen * sizeof(wchar_t), m_hProcess);
    if (p) {
        m_vecAllocMem.push_back(p);
        _WriteApi((LPVOID)p.get(), (LPVOID)arg, nlen * sizeof(wchar_t));
        arg = (const wchar_t*)p.raw();
    }
}

int main()
{
    auto& Process = Process::GetInstance();//get instance
    Process.Attach("notepad.exe");//attach process

    auto ret=Process.SetContextCall(GetCurrentProcessId);
    std::cout << ret << std::endl;
    return 0;
}


