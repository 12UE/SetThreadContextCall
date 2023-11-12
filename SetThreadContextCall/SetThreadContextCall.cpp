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
#include<thread>
#include <future>
#include <chrono>
#include <mutex>
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
template<class Fn, class T>
class ThreadData {
public:
    Fn fn;
    T retdata;
};
template <class Fn,class T,class ...Args>
class ThreadData2:public ThreadData<Fn,T> {//Thread Data Struct
public:
    std::tuple<Args...> params;
    std::size_t TupleSize(){
        return sizeof...(Args);
    }
    int GetParamsSize() {
        return (sizeof(Args) + ...);
    }
};
#pragma pack(pop)

template <class Fn, class T>
T ThreadFunction(void* param) noexcept {
    auto threadData = static_cast<ThreadData<Fn, T>*>(param);
    threadData->retdata = threadData->fn();
    return threadData->retdata;
}
template <class Fn, class T, class... Args>
decltype(auto) ThreadFunction2(void* param) noexcept {
    auto threadData = static_cast<ThreadData2<Fn, T, Args...>*>(param);
    return [threadData](auto index) {
        T retdata = std::apply(threadData->fn, threadData->params);
        threadData->retdata = retdata;
        return retdata;
    }(std::make_index_sequence<sizeof...(Args)>{});
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
inline BYTE ContextInjectShell[] = {	//x86.asm
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
class Thread {
    HANDLE m_hThread = INVALID_HANDLE_VALUE;
    DWORD m_dwThreadId = 0;
    bool m_bAttached = false;
public:
    Thread() = default;
    //打开线程 open thread
    Thread(DWORD dwThreadId) {
        m_dwThreadId = dwThreadId;
        m_hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_dwThreadId);
        m_bAttached = true;
    }
    //从threadentry32构造 construct from threadentry32
    Thread(const THREADENTRY32& threadEntry) {
        m_dwThreadId = threadEntry.th32ThreadID;
        m_hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_dwThreadId);
        m_bAttached = true;
    }
    //移动构造  move construct
    Thread(Thread&& other) {
        m_hThread = other.m_hThread;
        m_dwThreadId = other.m_dwThreadId;
        m_bAttached = other.m_bAttached;
        other.m_hThread = INVALID_HANDLE_VALUE;
        other.m_dwThreadId = 0;
        other.m_bAttached = false;
    }
    //移动赋值 move assignment
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
    //关闭线程句柄  close thread handle
    ~Thread() {
        if (m_bAttached)CloseHandle(m_hThread);
    }
    //获取线程句柄  get thread handle
    HANDLE GetHandle() {return m_hThread;}
    bool IsRunning() {
        //获取线程退出代码  get thread exit code
        DWORD dwExitCode = 0;
        if (GetExitCodeThread(m_hThread, &dwExitCode)) {
            if (dwExitCode == STILL_ACTIVE) {
                return true;
            }
        }
        return false;
    }
    //获取上下文    get context
    CONTEXT GetContext() {
        CONTEXT context = { 0 };
        context.ContextFlags = CONTEXT_FULL;
        GetThreadContext(m_hThread, &context);
        return context;
    }
    //设置上下文    set context
    void SetContext(CONTEXT& context) {
        SetThreadContext(m_hThread, &context);
    }
    //暂停  suspend
    void Suspend() {
        SuspendThread(m_hThread);
    }
    //恢复  resume
    void Resume() {
        ResumeThread(m_hThread);
    }
    //PostThreadMessage 
    BOOL _PostThreadMessage(UINT Msg, WPARAM wParam, LPARAM lParam) {
        return ::PostThreadMessageA(m_dwThreadId, Msg, wParam, lParam);
    }
};
template <typename T>
class ThreadSafeVector {
    std::mutex m_mutex;
    std::vector<T> m_vector;
public:
    //聚合初始化    aggregate initialization
    ThreadSafeVector(std::initializer_list<T> list) :m_vector(list) {}
    ThreadSafeVector() = default;
    ThreadSafeVector(const ThreadSafeVector& other) {
        m_vector = other.m_vector;
    }
    ThreadSafeVector(size_t size) {
        m_vector.resize(size);
    }
    ThreadSafeVector& operator=(const ThreadSafeVector& other) {
        m_vector = other.m_vector;
        return *this;
    }
    ThreadSafeVector(ThreadSafeVector&& other) {
        m_vector = std::move(other.m_vector);
    }
    ThreadSafeVector& operator=(ThreadSafeVector&& other) {
        m_vector = std::move(other.m_vector);
        return *this;
    }
    ~ThreadSafeVector() = default;
    void push_back(const T& value) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_vector.push_back(value);
    }
    void push_back(T&& value) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_vector.push_back(std::move(value));
    }
    //emplace back
    template<class... Args>
    void emplace_back(Args&&... args) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_vector.emplace_back(std::forward<Args>(args)...);
    }
    void pop_back() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_vector.pop_back();
    }
    void clear() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_vector.clear();
    }
    //data
    decltype(auto) data() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_vector.data();
    }
    T& operator[](size_t index) {
        return m_vector[index];
    }
    const T& operator[](size_t index) const {
        return m_vector[index];
    }
    size_t size() const {
        return m_vector.size();
    }
    void reserve(size_t size) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_vector.reserve(size);
    }
    //resize
    void resize(size_t size) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_vector.resize(size);
    }
    void assign(size_t size, const T& value) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_vector.assign(size, value);
    }
    void assign(std::initializer_list<T> list) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_vector.assign(list);
    }
    //迭代器assign  iterator assign
    template<class InputIt>
    void assign(InputIt first, InputIt last) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_vector.assign(first, last);
    }
    bool empty() const
    {
        return m_vector.empty();
    }
    void safe_erase(typename std::vector<T>::iterator it) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_vector.erase(it);
    }
    //不安全的删除  unsafe erase
    void erase(typename std::vector<T>::iterator it) {
        m_vector.erase(it);
    }
    //unsafe
    decltype(auto)  begin()const {
        return m_vector.begin();
    }
    decltype(auto)  begin() {
        return m_vector.begin();
    }
    decltype(auto) end()const {
        return m_vector.end();
    }
    decltype(auto)  end() {
        return m_vector.end();
    }
    //crbegin
    decltype(auto) crbegin() {
        return m_vector.crbegin();
    }
    decltype(auto) crend() {
        return m_vector.crend();
    }
    void unsafe_erase(typename std::vector<T>::iterator it) {
        m_vector.erase(it);
    }
    decltype(auto) cbegin() const {
        return m_vector.begin();
    }
    decltype(auto) cend() const {
        return m_vector.end();
    }
};
template<class T>
inline ThreadSafeVector<T> operator+(const ThreadSafeVector<T>& lhs, const ThreadSafeVector<T>& rhs) {
    ThreadSafeVector<T> result;
    result.reserve(lhs.size() + rhs.size());
    for (size_t i = 0; i < lhs.size(); i++)result.push_back(lhs[i]);
    for (size_t i = 0; i < rhs.size(); i++)result.push_back(rhs[i]);
    return result;
}
class Process :public SingleTon<Process> {//Singleton
    HANDLE m_hProcess = INVALID_HANDLE_VALUE;
    DWORD m_pid;//process id
    std::atomic_bool m_bAttached;//atomic bool
    ThreadSafeVector<Shared_Ptr> m_vecAllocMem;//vector for allocated memory
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
                THREADENTRY32 threadEntry = { sizeof(THREADENTRY32), };
                if (Thread32First(hSnapshot, &threadEntry)) {
                    do {
                        if (threadEntry.th32OwnerProcessID == m_pid) {
                            Thread thread(threadEntry);
                            if (thread.IsRunning())if (pre(threadEntry) == EnumStatus_Break)break;
                        }
                    } while (Thread32Next(hSnapshot, &threadEntry));
                }
                CloseHandle(hSnapshot);
            }
        }
    }
    void ClearMemory() {
        for (auto& p : m_vecAllocMem) p.Release();
        m_vecAllocMem.clear();
    }
    template<class _Fn, class ...Arg>
    decltype(auto) SetContextCallImpl(__in _Fn&& _Fx, __in Arg ...args){
        using RetType = std::common_type<decltype(_Fx(args...))>::type;
        if (!m_bAttached) return RetType();
        Thread _thread{};
        CONTEXT _ctx{};
        UDWORD _paramAddr = 0;
        ThreadData2<std::decay_t<_Fn>, RetType, std::decay_t<Arg>...> threadData;
        EnumThread([&](THREADENTRY32& te32)->int {
            auto thread = Thread(te32.th32ThreadID);
            thread.Suspend();
            auto ctx = thread.GetContext();
            auto lpShell = make_Shared<DATA_CONTEXT>(1, m_hProcess);
            m_vecAllocMem.emplace_back(lpShell);
            DATA_CONTEXT dataContext{};
            memcpy(dataContext.ShellCode, ContextInjectShell, sizeof(ContextInjectShell));
            if constexpr (sizeof...(args) > 0) preprocess(args...);
            threadData.fn = _Fx;
            threadData.params = std::tuple(std::forward<Arg>(args)...);
            auto pFunction = &ThreadFunction2<std::decay_t<_Fn>, RetType, std::decay_t<Arg>...>;
            int length = GetLength((BYTE*)pFunction);
            auto lpFunction = make_Shared<BYTE>(length, m_hProcess);
            m_vecAllocMem.emplace_back(lpFunction);
            _WriteApi((LPVOID)lpFunction.get(), (LPVOID)pFunction, length);
            dataContext.pFunction = (LPVOID)lpFunction.raw();
            dataContext.OriginalEip = (LPVOID)ctx.XIP;
            using parametertype = decltype(threadData);
            auto lpParameter = make_Shared<parametertype>(1, m_hProcess);
            m_vecAllocMem.emplace_back(lpParameter);
            _WriteApi((LPVOID)lpParameter.get(), &threadData, sizeof(parametertype));
            dataContext.lpParameter = (PBYTE)lpParameter.raw();
            _paramAddr = (UDWORD)lpParameter.raw();
            _ctx = ctx;
            ctx.XIP = (UDWORD)lpShell.raw();
            _WriteApi((LPVOID)lpShell.get(), &dataContext, sizeof(DATA_CONTEXT));
            thread.SetContext(ctx);
            thread.Resume();
            _thread = std::move(thread);
            return EnumStatus_Break;
        });
        WaitThread(_thread, _ctx.XIP);
        _ReadApi((LPVOID)_paramAddr, &threadData, sizeof(threadData));
        return threadData.retdata;
    }
    template <class _Fn>
    decltype(auto) SetContextCallImpl(_Fn&& _Fx) {
        using RetType = std::common_type<decltype(_Fx())>::type;
        if (!m_bAttached) return RetType();
        Thread _thread{};
        CONTEXT _ctx{};
        UDWORD _paramAddr = 0;
        ThreadData<std::decay_t<_Fn>, RetType> threadData;
        EnumThread([&](THREADENTRY32& te32)->int {
            auto thread = Thread(te32.th32ThreadID);
            thread.Suspend();
            auto ctx = thread.GetContext();
            auto lpShell = make_Shared<DATA_CONTEXT>(1, m_hProcess);
            m_vecAllocMem.emplace_back(lpShell);
            DATA_CONTEXT dataContext{};
            memcpy(dataContext.ShellCode, ContextInjectShell, sizeof(ContextInjectShell));
            
            threadData.fn = _Fx;
            auto pFunction = &ThreadFunction<std::decay_t<_Fn>, RetType>;
            int length = GetLength((BYTE*)pFunction);
            auto lpFunction = make_Shared<BYTE>(length, m_hProcess);
            m_vecAllocMem.emplace_back(lpFunction);
            _WriteApi((LPVOID)lpFunction.get(), (LPVOID)pFunction, length);
            dataContext.pFunction = (LPVOID)lpFunction.raw();
            dataContext.OriginalEip = (LPVOID)ctx.XIP;
            using parametertype = decltype(threadData);
            auto lpParameter = make_Shared<parametertype>(1, m_hProcess);
            m_vecAllocMem.emplace_back(lpParameter);
            _WriteApi((LPVOID)lpParameter.get(), &threadData, sizeof(parametertype));
            dataContext.lpParameter = (PBYTE)lpParameter.raw();
            _paramAddr = (UDWORD)lpParameter.raw();
            _ctx = ctx;
            ctx.XIP = (UDWORD)lpShell.raw();
            _WriteApi((LPVOID)lpShell.get(), &dataContext, sizeof(DATA_CONTEXT));
            thread.SetContext(ctx);
            thread.Resume();
            _thread = std::move(thread);
            return EnumStatus_Break;
        });
        WaitThread(_thread, _ctx.XIP);
        _ReadApi((LPVOID)_paramAddr, &threadData, sizeof(threadData));
        return threadData.retdata;
    }
    template <typename T>
    struct is_callable {
        template <typename U>
        static auto test(U* p) -> decltype((*p)(), std::true_type());
        template <typename U>
        static std::false_type test(...);
        static constexpr bool value = decltype(test<T>(nullptr))::value;
    };
    template<class _Fn, class ...Arg>
    decltype(auto) SetContextCall(__in _Fn&& _Fx, __in Arg&& ...args) {
        static_assert(!is_callable<_Fn>::value, "uncallable!");
        auto retdata=SetContextCallImpl(_Fx, args...);
        using RetType=decltype(retdata);
        std::promise<RetType> promise{};
        std::future<RetType> fut= promise.get_future();
        promise.set_value(retdata);
        ClearMemory();
        return fut;
    }
private:
    void WaitThread(Thread& thread,UDWORD xip) {
       CONTEXT _ctx{};
       do {
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
           _ctx = thread.GetContext();
       } while ((UDWORD)_ctx.XIP <= xip);
    }
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
HWND NullToHwnd(){
    return reinterpret_cast<HWND>(NULL);
}
HANDLE NullToHandle(){
    return reinterpret_cast<HANDLE>(NULL);
}
int main(){
    auto& Process = Process::GetInstance();//get instance
    Process.Attach("notepad.exe");//attach process
    Process.SetContextCall(MessageBoxA, NullToHwnd(), "hello", "world", MB_OK);//call MessageBoxA
    return 0;
}


