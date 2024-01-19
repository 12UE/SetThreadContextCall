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
#include<unordered_map>
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
class Shared_Ptr {
    HANDLE m_hProcess = nullptr;
    LPVOID BaseAddress = nullptr;
    int refCount = 0;
    void AddRef() {
        refCount++;
    }
    UDWORD _AllocMemApi(SIZE_T dwSize, LPVOID PageBase = NULL) {
        auto allocatedMemory = VirtualAllocEx(m_hProcess, PageBase, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        return reinterpret_cast<UDWORD>(allocatedMemory);
    }
    bool _FreeMemApi(LPVOID lpAddress) {
        return VirtualFreeEx(m_hProcess, lpAddress, 0, MEM_RELEASE);
    }
public:
    Shared_Ptr(void* Addr, HANDLE hProc) : m_hProcess(hProc) {
        BaseAddress = Addr;
        AddRef();
    }
    template<class T>
    Shared_Ptr() {
        AddRef();
        BaseAddress = (LPVOID)_AllocMemApi(sizeof(T));
    }
    Shared_Ptr(size_t nsize, HANDLE hProc) :m_hProcess(hProc) {
        AddRef();
        //virtualallocex
        BaseAddress = (LPVOID)_AllocMemApi(nsize);

    }
    Shared_Ptr(const Shared_Ptr& other) : BaseAddress(other.BaseAddress), refCount(other.refCount) {
        AddRef();
    }
    Shared_Ptr& operator=(const Shared_Ptr& other) {//copy assignment
        if (this != &other) {
            Release();
            BaseAddress = other.BaseAddress;
            refCount = other.refCount;
            AddRef();
        }
        return *this;
    }
    LPVOID get() {
        AddRef();
        return BaseAddress;
    }
    LPVOID raw() {
        return BaseAddress;
    }
    UDWORD getUDWORD() {
        AddRef();
        return (UDWORD)BaseAddress;
    }
    ~Shared_Ptr() {
        Release();
    }
    void Release() {//release and refCount--
        refCount--;
        if (BaseAddress && refCount <= 0) {
            _FreeMemApi(BaseAddress);
            BaseAddress = nullptr;
        }
    }
    operator bool() {
        return BaseAddress != nullptr;
    }
};
template<class T>Shared_Ptr make_Shared(size_t nsize, HANDLE hprocess) { return Shared_Ptr(sizeof(T) * nsize, hprocess); }
template<class BinFunc>
inline size_t GetFunctionSize(const BinFunc& func) {
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
template<class Tx, class Ty> inline size_t _ucsicmp(const Tx * str1, const Ty * str2) {//ignore case compare ignore type wchar_t wstring or char string 忽略大小写比较 忽略类型wchar_t wstring或者char string
    if (!str1 || !str2) throw std::exception("str1 or str2 is nullptr");
    std::wstring wstr1{}, wstr2{};
    std::string  strtemp{};
    if constexpr (!std::is_same_v<remove_const_pointer_t<Tx>, wchar_t>) {
        strtemp = str1;
        wstr1 = std::wstring(strtemp.begin(), strtemp.end());//transform to wstring 转换为wstring
    }else {
        wstr1 = str1;
    }
    if constexpr (!std::is_same_v<remove_const_pointer_t<Ty>, wchar_t>) {
        strtemp = str2;
        wstr2 = std::wstring(strtemp.begin(), strtemp.end());//transform to wstring 转换为wstring
    }else {
        wstr2 = str2;
    }
    std::transform(wstr1.begin(), wstr1.end(), wstr1.begin(), towlower);//transform to lower 转换为小写
    std::transform(wstr2.begin(), wstr2.end(), wstr2.begin(), towlower);//transform to lower    转换为小写
    return wstr1.compare(wstr2);
}
class NormalHandle {
public:
    static void Close(HANDLE& handle) {
        if (IsValid(handle)) {
            CloseHandle(handle);
            handle = InvalidHandle();
        }
    }
    static HANDLE InvalidHandle() {
        return INVALID_HANDLE_VALUE;
    }
    static bool IsValid(HANDLE handle) {
        return handle != INVALID_HANDLE_VALUE;
    }
};
template<class T,class Traits>
class GenericHandle {
private:
    T m_handle = Traits::InvalidHandle();
    //所有者 owner
    bool m_bOwner = false;
public:
    //构造 m_bOwner默认为true construct m_bOwner default is true
    GenericHandle(T handle = Traits::InvalidHandle(), bool bOwner = true) :m_handle(handle), m_bOwner(bOwner) {}
    //析构
    ~GenericHandle() {
        if (m_bOwner) {
            Traits::Close(m_handle);
            m_bOwner = false;
        }
    }
    GenericHandle(GenericHandle&) = delete;
    GenericHandle& operator =(const GenericHandle&) = delete;
    //右值引用右值赋值 move assignment
    GenericHandle& operator =(GenericHandle&& other) {
        if (this != &other) {
            m_handle = other.m_handle;
            m_bOwner = other.m_bOwner;
            other.m_handle = Traits::InvalidHandle();
            other.m_bOwner = false;
        }
        return *this;
    }
    //右值引用右值构造 move construct
    GenericHandle(GenericHandle&& other) {
        m_handle = other.m_handle;
        m_bOwner = other.m_bOwner;
        other.m_handle = Traits::InvalidHandle();
        other.m_bOwner = false;
    }
    //获取句柄 get handle
    T GetHandle() {
        return m_handle;
    }
};
#define DELETE_COPYMOVE_CONSTRUCTOR(TYPE) TYPE(const TYPE&)=delete;TYPE(TYPE&&) = delete;void operator= (const TYPE&) = delete;void operator= (TYPE&&) = delete;
template<typename T >
class SingleTon {
private:
    DELETE_COPYMOVE_CONSTRUCTOR(SingleTon)
    std::atomic_bool bflag=false;
    HANDLE hEvent = INVALID_HANDLE_VALUE;
    static inline std::shared_ptr<T> CreateInstance() {
        return std::make_shared<T>();
    }
    template <class... Args>
    static inline std::shared_ptr<T> CreateInstance(Args&& ...args) {
        return std::make_shared<T>(args...);
    }
    template <class... Args>
    inline static T& GetInstanceImpl(Args&& ...args) {
        static std::once_flag flag{};
        static std::shared_ptr<T> instance = nullptr;
        if (!instance) {
            std::call_once(flag, [&]() {//call once
                instance = CreateInstance(args...);//element constructor through parameters    通过参数构造元素
            });
        }
        if (instance->bflag) {
            throw std::exception("SingleTon has been created");
        }
        else {
            return *instance.get();
        }
    }
    inline static T& GetInstanceImpl() {
        static std::once_flag flag{};
        static std::shared_ptr<T> instance = nullptr;
        if (!instance) {
            std::call_once(flag, [&]() {//call once
                instance = CreateInstance();//element constructor through parameters    通过参数构造元素
            });
        }
        if (instance->bflag) {
            throw std::exception("SingleTon has been created");
        }else {
            return *instance.get();
        }
    }
public:
    SingleTon() {
        //按类名的typeid作为事件名 create event name by typeid
        std::string eventname = typeid(T).name();
        //创建互斥量 create event
        hEvent = CreateEventA(NULL, FALSE, FALSE, eventname.c_str());
        if (hEvent == NULL)throw std::exception("CreateEventA failed");
        //检查互斥量是否已经被创建 check event is created
        bflag = (GetLastError() == ERROR_ALREADY_EXISTS) ? true : false;
    }
    ~SingleTon() {
        if (hEvent != INVALID_HANDLE_VALUE) {
            CloseHandle(hEvent);//关闭事件 close event
            hEvent = INVALID_HANDLE_VALUE;//置为无效值 set invalid value
        }
    }
    template <class... Args>
    inline static T& GetInstance(Args&& ...args) {//get instance this function is thread safe and support parameter    此函数是线程安全的并且支持参数
        return GetInstanceImpl(args...);
    }
       
};
#define EnumStatus_Continue (int)0
#define EnumStatus_Break (int)1
//保存原始的对齐方式 save original align
#pragma pack(push)
#pragma pack(1)
template<class Fn, class T>
class ThreadDataBase {
public:
    Fn fn;//function    函数
    char eventname[MAX_PATH];
    char funcname[3][MAX_PATH];
    LPVOID pFunc[2];
};
template<class Fn, class T>
class ThreadData:public ThreadDataBase<Fn,T> {
public:
    T retdata;//return data 返回值
};
template <class Fn>
class ThreadData<Fn, void>:public ThreadDataBase<Fn, void> {
public:
};
template <class Fn, class T, class ...Args>
class ThreadData2 :public ThreadData<Fn, T> {//Thread Data Struct inherit from ThreadData   线程数据结构继承自ThreadData
public:
    std::tuple<Args...> params;//parameters   参数
};
#pragma pack(pop)//恢复原始pack restore original pack   
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
template <class Fn, class T>
T ThreadFunction(void* param) noexcept {
    auto threadData = static_cast<ThreadData<Fn, T>*>(param);
    threadData->retdata = threadData->fn();
    auto pLoadLibrary = (PLOADLIBRARYA)threadData->pFunc[0];
    auto pGetProAddress = (PGETPROCADDRESS)threadData->pFunc[1];
    //加载OpenEventA    load OpenEventA
    auto ntdll = pLoadLibrary(threadData->funcname[0]);
    auto pOpenEventA = (POPENEVENTA)pGetProAddress(ntdll, threadData->funcname[1]);
    //打开事件  open event
    auto hEventHandle = pOpenEventA(EVENT_ALL_ACCESS, FALSE, threadData->eventname);
    //设置事件  set event
    auto pSetEvent = (PSETEVENT)pGetProAddress(ntdll, threadData->funcname[2]);
    pSetEvent(hEventHandle);
    return threadData->retdata;
}
template <class Fn, class T>
void ThreadFunctionNoReturn(void* param) noexcept {
    auto threadData = static_cast<ThreadData<Fn, T>*>(param);
    threadData->fn();
    auto pLoadLibrary = (PLOADLIBRARYA)threadData->pFunc[0];
    auto pGetProAddress = (PGETPROCADDRESS)threadData->pFunc[1];
    //加载OpenEventA    load OpenEventA
    auto ntdll = pLoadLibrary(threadData->funcname[0]);
    auto pOpenEventA = (POPENEVENTA)pGetProAddress(ntdll, threadData->funcname[1]);
    //打开事件  open event
    auto hEventHandle = pOpenEventA(EVENT_ALL_ACCESS, FALSE, threadData->eventname);
    //设置事件  set event
    auto pSetEvent = (PSETEVENT)pGetProAddress(ntdll, threadData->funcname[2]);
    pSetEvent(hEventHandle);
}
template <class Fn, class T, class... Args>
decltype(auto) ThreadFunction2(void* param) noexcept {
    auto threadData = static_cast<ThreadData2<Fn, T, Args...>*>(param);
    auto ret = [threadData](auto index) {
        threadData->retdata = std::apply(threadData->fn, threadData->params);
        return threadData->retdata;
        }(std::make_index_sequence<sizeof...(Args)>{});
        auto pLoadLibrary = (PLOADLIBRARYA)threadData->pFunc[0];
        auto pGetProAddress = (PGETPROCADDRESS)threadData->pFunc[1];
        //加载OpenEventA    load OpenEventA
        auto hEvent = pLoadLibrary(threadData->funcname[0]);
        auto pOpenEventA = (POPENEVENTA)pGetProAddress(hEvent, threadData->funcname[1]);
        //打开事件  open event
        auto hEventHandle = pOpenEventA(EVENT_ALL_ACCESS, FALSE, threadData->eventname);
        //设置事件  set event
        auto pSetEvent = (PSETEVENT)pGetProAddress(hEvent, threadData->funcname[2]);
        pSetEvent(hEventHandle);
        return ret;
}
template <class Fn, class T, class... Args>
void ThreadFunction2NoReturn(void* param) noexcept {
    auto threadData = static_cast<ThreadData2<Fn, T, Args...>*>(param);
    [threadData](auto index) {
        std::apply(threadData->fn, threadData->params);
        }(std::make_index_sequence<sizeof...(Args)>{});
        auto pLoadLibrary = (PLOADLIBRARYA)threadData->pFunc[0];
        auto pGetProAddress = (PGETPROCADDRESS)threadData->pFunc[1];
        //加载OpenEventA    load OpenEventA
        auto hEvent = pLoadLibrary(threadData->funcname[0]);
        auto pOpenEventA = (POPENEVENTA)pGetProAddress(hEvent, threadData->funcname[1]);
        //打开事件  open event
        auto hEventHandle = pOpenEventA(EVENT_ALL_ACCESS, FALSE, threadData->eventname);
        //设置事件  set event
        auto pSetEvent = (PSETEVENT)pGetProAddress(hEvent, threadData->funcname[2]);
        pSetEvent(hEventHandle);
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
    GenericHandle<HANDLE, NormalHandle> m_GenericHandleThread;
    DWORD m_dwThreadId = 0;
    bool m_bAttached = false;
public:
    Thread() = default;
    //打开线程 open thread
    Thread(DWORD dwThreadId) {
        m_dwThreadId = dwThreadId;
        auto m_hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_dwThreadId);
        m_GenericHandleThread = m_hThread;
        m_bAttached = true;
    }
    //从threadentry32构造 construct from threadentry32  to open thread
    Thread(const THREADENTRY32& threadEntry) {
        m_dwThreadId = threadEntry.th32ThreadID;
       auto m_hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_dwThreadId);
        m_GenericHandleThread = m_hThread;
        m_bAttached = true;
    }
    //移动构造  move construct
    Thread(Thread&& other) {
        m_GenericHandleThread = std::move(other.m_GenericHandleThread);
        m_dwThreadId = other.m_dwThreadId;
        m_bAttached = other.m_bAttached;
        other.m_dwThreadId = 0;
        other.m_bAttached = false;
    }
    //移动赋值 move assignment
    Thread& operator=(Thread&& other) {
        if (this != &other) {
            m_GenericHandleThread = std::move(other.m_GenericHandleThread);
            m_dwThreadId = other.m_dwThreadId;
            m_bAttached = other.m_bAttached;
            other.m_dwThreadId = 0;
            other.m_bAttached = false;
        }
        return *this;
    }
    //关闭线程句柄  close thread handle
    ~Thread() {

    }
    //获取线程句柄  get thread handle
    HANDLE GetHandle() { return m_GenericHandleThread.GetHandle(); }
    bool IsRunning() {
        //获取线程退出代码  get thread exit code
        DWORD dwExitCode = 0;
        if (GetExitCodeThread(GetHandle(), &dwExitCode)) {
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
        GetThreadContext(GetHandle(), &context);
        return context;
    }
    //设置上下文    set context
    void SetContext(CONTEXT& context) {
        SetThreadContext(GetHandle(), &context);
    }
    //暂停  suspend
    void Suspend() {
        SuspendThread(GetHandle());
    }
    //恢复  resume
    void Resume() {
        ResumeThread(GetHandle());
    }
    //PostThreadMessage 
    BOOL _PostThreadMessage(UINT Msg, WPARAM wParam, LPARAM lParam) {
        return ::PostThreadMessageA(m_dwThreadId, Msg, wParam, lParam);
    }
    void QueApc(void* Addr) {
        QueueUserAPC((PAPCFUNC)Addr, GetHandle(), 0);
    }
    //设置线程优先级  set thread priority
    void SetPriority(int nPriority = THREAD_PRIORITY_HIGHEST) {
        SetThreadPriority(GetHandle(), nPriority);
    }
};
template <typename T>
class ThreadSafeVector {
    std::mutex m_mutex; //lock for vector
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
template<typename T,typename ...Args>
concept Callable = requires(T t,Args...args) { //check callable concept 检查可调用概念
    { t(args...) };
};
#define POINTER_READ 0
#define POINTER_WRITE 1
template<class T>
inline ThreadSafeVector<T> operator+(const ThreadSafeVector<T>&lhs, const ThreadSafeVector<T>&rhs) {
    ThreadSafeVector<T> result;
    result.reserve(lhs.size() + rhs.size());
    for (size_t i = 0; i < lhs.size(); i++)result.push_back(lhs[i]);
    for (size_t i = 0; i < rhs.size(); i++)result.push_back(rhs[i]);
    return result;
}
class Process :public SingleTon<Process> {//Singleton   单例
    HANDLE m_hProcess = INVALID_HANDLE_VALUE;
    DWORD m_pid;//process id    进程id
    int m_RunningMode = POINTER_READ;
    std::atomic_bool m_bAttached;//atomic bool  原子bool
    ThreadSafeVector<Shared_Ptr> m_vecAllocMem;//vector for allocated memory    保存分配的内存的vector
    std::unordered_map<LPVOID, LPVOID> maptoorigin;//map for save original address and allocated address, key is allocated address value is original address    保存原始地址和分配地址的map，key是分配地址，value是原始地址
    template<typename T, typename ...Args>
    void preprocess(T& arg, Args&...args) {//partially specialized template 部分特化模板
        if constexpr (has_type_v<T,const char*,const wchar_t *>) preprocessparameter(arg);
        if constexpr (std::is_pointer_v<T> && !has_type_v<T,LPVOID,LPCVOID,const char*,const wchar_t*>)ProcessPtr(arg);
        if constexpr (sizeof...(args) > 0)preprocess(args...);
    }
    template<class T, typename ...Args>
    void postprocess(T& arg, Args&...args) {
        if (std::is_pointer_v<T> && !std::is_same_v<T, LPVOID> && !std::is_same_v<T, LPCVOID>)PostprocessPtr(arg);//post process pointer    后处理指针
        if constexpr (sizeof...(args) > 0)postprocess(args...);//keep process   继续处理
    }
    template<typename T>
    void PostprocessPtr(T& ptr) {
        auto iter = maptoorigin.find((LPVOID)ptr);//find original address   查找原始地址
        if (iter != maptoorigin.end()) {
            LPVOID OriginAddr = iter->second;//original address   原始地址
            if (m_RunningMode == POINTER_READ){
                _ReadApi((LPVOID)ptr, OriginAddr, sizeof(T));//read value from allocated address to original address    从分配地址读取值到原始地址
            }
        }
    }
    template<typename T>
    void preprocessparameter(T& arg) {}
    void preprocessparameter(const char*& arg) {
        auto nlen = (int)strlen(arg) + 1;
        auto p = make_Shared<char>(nlen * sizeof(char), m_hProcess);
        if (p) {
            m_vecAllocMem.push_back(p);
            _WriteApi((LPVOID)p.get(), (LPVOID)arg, nlen * sizeof(char));
            arg = (const char*)p.raw();
        }
    }//process const char* parameter    处理const char*参数
    void preprocessparameter(const wchar_t*& arg){
        auto nlen = (int)wcslen(arg) + 1;
        auto p = make_Shared<wchar_t>(nlen * sizeof(wchar_t), m_hProcess);
        if (p) {
            m_vecAllocMem.push_back(p);
            _WriteApi((LPVOID)p.get(), (LPVOID)arg, nlen * sizeof(wchar_t));
            arg = (const wchar_t*)p.raw();
        }
    }//process const wchar_t* parameter   处理const wchar_t*参数
    template<typename T>
    void ProcessPtr(T& ptr) {
        if (ptr) {
            int Size = sizeof(T);//get size of parameter    获取参数大小
            auto p = make_Shared<BYTE>(Size, m_hProcess);
            if (p) {
                m_vecAllocMem.emplace_back(p);//emplace back into vector avoid memory leak can be clear through clearmemory   emplace back到vector中避免内存泄漏可以通过clearmemory清除
                _WriteApi(p.get(), (LPVOID)ptr, Size);//write value to allocated address for parameter is pointer   写入值到分配地址，因为参数是指针
                if(m_RunningMode==POINTER_READ)maptoorigin.insert(std::make_pair((LPVOID)p.raw(), (LPVOID)ptr));//save original address and allocated address   保存原始地址和分配地址
                ptr = (T)p.raw();//set parameter to allocated address   设置参数为分配地址
            }
        }
    }
public:
    void Attach(const char* _szProcessName) {//attach process   附加进程
        //get process id    获取进程id
        auto pid = GetProcessIdByName(_szProcessName);
        if (pid != 0) {
            m_pid = pid;
            m_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_pid);
            m_bAttached = true;
        }
    }
    void ChangeMode(int Mode) {
        m_RunningMode = Mode;
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
    //writeapi
    ULONG _WriteApi(_In_ LPVOID lpBaseAddress, _In_opt_ LPVOID lpBuffer, _In_ SIZE_T nSize) {//WriteProcessMemory
        if (m_bAttached) {
            SIZE_T bytesWritten = 0;
            WriteProcessMemory(m_hProcess, lpBaseAddress, lpBuffer, nSize, &bytesWritten);
            return bytesWritten;
        }
        return 0;
    }
    //allocmemapi
    UDWORD _AllocMemApi(SIZE_T dwSize, LPVOID PageBase = NULL) {//return allocated memory address
        if (m_bAttached) {
            auto allocatedMemory = VirtualAllocEx(m_hProcess, PageBase, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            return reinterpret_cast<UDWORD>(allocatedMemory);
        }
        return 0;
    }
    //freememapi
    int _FreeMemApi(LPVOID lpAddress) {//free memory
        if (m_bAttached)return VirtualFreeEx(m_hProcess, lpAddress, 0, MEM_RELEASE);
        return 0;
    }
    template<class PRE>
    void EnumThread(PRE pre) {//enum thread through snapshot    通过快照枚举线程
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
    decltype(auto) SetContextCallImpl(__in _Fn&& _Fx, __in Arg ...args) {
        using RetType = std::common_type<decltype(_Fx(args...))>::type;//return type is common type or not
        if (!m_bAttached) return RetType();
        Thread _thread{};
        CONTEXT _ctx{};
        UDWORD _paramAddr = 0;
        ThreadData2<std::decay_t<_Fn>, RetType, std::decay_t<Arg>...> threadData;
        strcpy_s(threadData.eventname, "SetContextCallImpl");//event name
        strcpy_s(threadData.funcname[0], "kernel32.dll");//kernel32.dll
        strcpy_s(threadData.funcname[1], "OpenEventA");//OpenEventA
        strcpy_s(threadData.funcname[2], "SetEvent");//SetEvent
        //创建事件  create event
        auto hEvent = CreateEventA(NULL, FALSE, FALSE, threadData.eventname);
        //获取地址  get address
        auto pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandleA(threadData.funcname[0]), "LoadLibraryA");
        auto pGetProcAddress = (LPVOID)GetProcAddress;
        //设置函数地址  set function address
        threadData.pFunc[0] = (LPVOID)pLoadLibrary;
        threadData.pFunc[1] = (LPVOID)pGetProcAddress;
        EnumThread([&](auto& te32)->int {
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
            int length = GetFunctionSize((BYTE*)pFunction);//get function length    获取函数长度
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
            _paramAddr = (UDWORD)lpParameter.raw();//set parameter address  设置参数地址
            _ctx = ctx;//save context   保存上下文
            ctx.XIP = (UDWORD)lpShell.raw();//set xip   设置xip
            _WriteApi((LPVOID)lpShell.get(), &dataContext, sizeof(DATA_CONTEXT));//write datacontext    写入datacontext
            thread.SetContext(ctx);//set context    设置上下文
            thread.Resume();//resume thread   恢复线程
            _thread = std::move(thread);//move thread   移动线程
            return EnumStatus_Break;
            });
        WaitForSingleObject(hEvent, INFINITE);//wait event  等待事件
        CloseHandle(hEvent);//close event   关闭事件
        if(maptoorigin.size()>0)postprocess(args...);//post process parameter   后处理参数
        maptoorigin.clear();//clear map  清除map
        _ReadApi((LPVOID)_paramAddr, &threadData, sizeof(threadData));//read parameter for return value  读取参数以返回值
        return threadData.retdata;//return value    返回值
    }
    template <class _Fn>
    decltype(auto) SetContextCallImpl(_Fn&& _Fx) {
        using RetType = std::common_type<decltype(_Fx())>::type;//return type is common type or not 返回类型是常见类型还是不是
        if (!m_bAttached) return RetType();//return default value   返回默认值
        Thread _thread{};
        CONTEXT _ctx{};
        UDWORD _paramAddr = 0;
        ThreadData<std::decay_t<_Fn>, RetType> threadData;//thread data
        strcpy_s(threadData.eventname, "SetContextCallImpl");//event name
        strcpy_s(threadData.funcname[0], "kernel32.dll");//kernel32.dll
        strcpy_s(threadData.funcname[1], "OpenEventA");//OpenEventA
        strcpy_s(threadData.funcname[2], "SetEvent");//SetEvent
        //创建事件  create event
        auto hEvent = CreateEventA(NULL, FALSE, FALSE, threadData.eventname);
        //获取地址  get address
        auto pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandleA(threadData.funcname[0]), "LoadLibraryA");
        auto pGetProcAddress = (LPVOID)GetProcAddress;
        //设置函数地址  set function address
        threadData.pFunc[0] = (LPVOID)pLoadLibrary;
        threadData.pFunc[1] = (LPVOID)pGetProcAddress;
        EnumThread([&](auto& te32)->int {
            auto thread = Thread(te32);//construct thread   构造线程
            thread.Suspend();//suspend thread   暂停线程
            auto ctx = thread.GetContext();//get context    获取上下文
            auto lpShell = make_Shared<DATA_CONTEXT>(1, m_hProcess);//allocate memory for datacontext   分配内存
            m_vecAllocMem.emplace_back(lpShell);//push back to vector for free memory   push back到vector中以释放内存
            DATA_CONTEXT dataContext{};
            memcpy(dataContext.ShellCode, ContextInjectShell, sizeof(ContextInjectShell));
            threadData.fn = _Fx;
            auto pFunction = &ThreadFunction<std::decay_t<_Fn>, RetType>;//get function address 获取函数地址
            int length = GetFunctionSize((BYTE*)pFunction);//get function length    获取函数长度
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
            _paramAddr = (UDWORD)lpParameter.raw();
            _ctx = ctx;//store context  保存上下文
            ctx.XIP = (UDWORD)lpShell.raw();//set xip   设置xip
            _WriteApi((LPVOID)lpShell.get(), &dataContext, sizeof(DATA_CONTEXT));//write datacontext to memory  写入datacontext到内存
            thread.SetContext(ctx);//set context    设置上下文
            thread.Resume();//resume thread  恢复线程
            _thread = std::move(thread);//store thread  存储线程
            return EnumStatus_Break;
            });
        WaitForSingleObject(hEvent, INFINITE);//wait event  等待事件
        CloseHandle(hEvent);//close event   关闭事件
        _ReadApi((LPVOID)_paramAddr, &threadData, sizeof(threadData));//read parameter for return value 读取参数以返回值
        return threadData.retdata;//return value    返回值
    }
    template <typename T>
    struct is_callable {
        template <typename U>
        static auto test(U* p) -> decltype((*p)(), std::true_type());
        template <typename U>
        static std::false_type test(...);
        static constexpr bool value = decltype(test<T>(nullptr))::value;//is callable
    };
    template <class _Fn>
    void SetContextCallNoReturnImpl(_Fn&& _Fx) {
        using RetType = void;
        Thread _thread{};
        CONTEXT _ctx{};
        UDWORD _paramAddr = 0;
        ThreadData<std::decay_t<_Fn>, RetType> threadData;//thread data
        strcpy_s(threadData.eventname, "SetContextCallImpl");//event name
        strcpy_s(threadData.funcname[0], "kernel32.dll");//kernel32.dll
        strcpy_s(threadData.funcname[1], "OpenEventA");//OpenEventA
        strcpy_s(threadData.funcname[2], "SetEvent");//SetEvent
        //创建事件  create event
        auto hEvent = CreateEventA(NULL, FALSE, FALSE, threadData.eventname);
        //获取地址  get address
        auto pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandleA(threadData.funcname[0]), "LoadLibraryA");
        auto pGetProcAddress = (LPVOID)GetProcAddress;
        //设置函数地址  set function address
        threadData.pFunc[0] = (LPVOID)pLoadLibrary;
        threadData.pFunc[1] = (LPVOID)pGetProcAddress;
        EnumThread([&](auto& te32)->int {
            auto thread = Thread(te32);//construct thread   构造线程
            thread.Suspend();//suspend thread   暂停线程
            auto ctx = thread.GetContext();//get context    获取上下文
            auto lpShell = make_Shared<DATA_CONTEXT>(1, m_hProcess);//allocate memory for datacontext   分配内存
            m_vecAllocMem.emplace_back(lpShell);//push back to vector for free memory   push back到vector中以释放内存
            DATA_CONTEXT dataContext{};
            memcpy(dataContext.ShellCode, ContextInjectShell, sizeof(ContextInjectShell));
            threadData.fn = _Fx;
            auto pFunction = &ThreadFunctionNoReturn<std::decay_t<_Fn>, RetType>;//get function address 获取函数地址
            int length = GetFunctionSize((BYTE*)pFunction);//get function length    获取函数长度
            auto lpFunction = make_Shared<BYTE>(length, m_hProcess);//allocate memory for function  分配内存
            m_vecAllocMem.emplace_back(lpFunction);
            _WriteApi((LPVOID)lpFunction.get(), (LPVOID)pFunction, length);//write function to memory   写入函数到内存
            dataContext.pFunction = (LPVOID)lpFunction.raw();//set function address
            dataContext.OriginalEip = (LPVOID)ctx.XIP;//set original eip
            using parametertype = decltype(threadData);//get parameter type
            auto lpParameter = make_Shared<parametertype>(1, m_hProcess);//allocate memory for parameter
            m_vecAllocMem.emplace_back(lpParameter);
            _WriteApi((LPVOID)lpParameter.get(), &threadData, sizeof(parametertype));//write parameter to memory
            dataContext.lpParameter = (PBYTE)lpParameter.raw();
            _paramAddr = (UDWORD)lpParameter.raw();
            _ctx = ctx;//store context
            ctx.XIP = (UDWORD)lpShell.raw();//set xip
            _WriteApi((LPVOID)lpShell.get(), &dataContext, sizeof(DATA_CONTEXT));//write datacontext to memory
            thread.SetContext(ctx);//set context
            thread.Resume();//resume thread
            _thread = std::move(thread);//store thread
            return EnumStatus_Break;
            });
        WaitForSingleObject(hEvent, INFINITE);//wait event
        CloseHandle(hEvent);//close event
    }
    template<class _Fn, class ...Arg>
    void SetContextCallNoReturn(__in _Fn&& _Fx, __in Arg ...args) {
        using RetType = void;
        if (!m_bAttached) return RetType();
        Thread _thread{};
        UDWORD _paramAddr = 0;
        CONTEXT _ctx{};
        ThreadData2<std::decay_t<_Fn>, RetType, std::decay_t<Arg>...> threadData;
        strcpy_s(threadData.eventname, "SetContextCallImpl");//event name
        strcpy_s(threadData.funcname[0], "kernel32.dll");//kernel32.dll
        strcpy_s(threadData.funcname[1], "OpenEventA");//OpenEventA
        strcpy_s(threadData.funcname[2], "SetEvent");//SetEvent
        //创建事件
        auto hEvent = CreateEventA(NULL, FALSE, FALSE, threadData.eventname);
        //获取地址
        auto pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandleA(threadData.funcname[0]), "LoadLibraryA");
        auto pGetProcAddress = (LPVOID)GetProcAddress;
        //设置函数地址
        threadData.pFunc[0] = (LPVOID)pLoadLibrary;
        threadData.pFunc[1] = (LPVOID)pGetProcAddress;
        EnumThread([&](auto& te32)->int {
            auto thread = Thread(te32);//construct thread
            thread.Suspend();//suspend thread
            auto ctx = thread.GetContext();//get context
            auto lpShell = make_Shared<DATA_CONTEXT>(1, m_hProcess);//allocate memory
            m_vecAllocMem.emplace_back(lpShell);//
            DATA_CONTEXT dataContext{};
            memcpy(dataContext.ShellCode, ContextInjectShell, sizeof(ContextInjectShell));
            if constexpr (sizeof...(args) > 0) preprocess(args...);//process parameter
            threadData.fn = _Fx;
            threadData.params = std::tuple(std::forward<Arg>(args)...);//tuple parameters
            auto pFunction = &ThreadFunction2NoReturn<std::decay_t<_Fn>, RetType, std::decay_t<Arg>...>;//get function address
            int length = GetFunctionSize((BYTE*)pFunction);//get function length
            auto lpFunction = make_Shared<BYTE>(length, m_hProcess);//allocate memory for function
            m_vecAllocMem.emplace_back(lpFunction);//push back to vector for free memory
            _WriteApi((LPVOID)lpFunction.get(), (LPVOID)pFunction, length);//write function
            dataContext.pFunction = (LPVOID)lpFunction.raw();//set function address
            dataContext.OriginalEip = (LPVOID)ctx.XIP;//set original eip
            using parametertype = decltype(threadData);
            auto lpParameter = make_Shared<parametertype>(1, m_hProcess);//allocate memory for parameter
            m_vecAllocMem.emplace_back(lpParameter);//push back to vector for free memory
            _WriteApi((LPVOID)lpParameter.get(), &threadData, sizeof(parametertype));//write parameter
            dataContext.lpParameter = (PBYTE)lpParameter.raw();//set parameter address
            _paramAddr = (UDWORD)lpParameter.raw();//set parameter address
            _ctx = ctx;//save context
            ctx.XIP = (UDWORD)lpShell.raw();//set xip
            _WriteApi((LPVOID)lpShell.get(), &dataContext, sizeof(DATA_CONTEXT));//write datacontext
            thread.SetContext(ctx);//set context
            thread.Resume();//resume thread
            _thread = std::move(thread);//move thread
            return EnumStatus_Break;
            });
        WaitForSingleObject(hEvent, INFINITE);//wait event
        CloseHandle(hEvent);//close event
        if (maptoorigin.size() > 0)postprocess(args...);//post process parameter
        maptoorigin.clear();//clear map
    }

    decltype(auto) SetContextCall(auto&& _Fx, auto&& ...args) {
        static_assert(!is_callable<decltype(_Fx)>::value, "uncallable!");
        auto retdata = SetContextCallImpl(_Fx, args...);
        using RetType = decltype(retdata);
        std::promise<RetType> promise{};
        std::future<RetType> fut = promise.get_future();
        promise.set_value(retdata);
        ClearMemory();
        return fut;
    }
    template<class T>
    static T TONULL() { //return null value  返回空值
        return  reinterpret_cast<T>(0);
    }
private:
    DWORD GetProcessIdByName(const char* processName) {//get process id by name   通过名称获取进程id
        DWORD pid = 0;
        auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W processEntry = { sizeof(PROCESSENTRY32W), };
            if (Process32FirstW(hSnapshot, &processEntry)) {
                do {
                    if (_ucsicmp(processEntry.szExeFile, processName) == 0) {
                        pid = processEntry.th32ProcessID;
                        break;
                    }
                } while (Process32NextW(hSnapshot, &processEntry));
            }
            CloseHandle(hSnapshot);
        }
        return pid;
    }
};

int main()
{
    auto& Process = Process::GetInstance();//get instance   获取实例
    Process.Attach("notepad.exe");//attach process  附加进程
    std::cout<<Process.SetContextCall(MessageBoxA, Process::TONULL<HWND>(), "MSG", "CAP", MB_OK).get();
    return 0;
}


