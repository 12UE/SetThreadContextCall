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
#define INLINE inline
#define NOEXCEPT noexcept
template<class T>
class InitObj {
public:
    T obj;
    InitObj() {
        void* ptr = &obj;
        DWORD size = sizeof(T);
        memcpy(ptr, &size, sizeof(DWORD));
    }
    operator T() {
        return obj;
    }
    T* operator->() {
        return &obj;
    }
    T* operator&() {
        return &obj;
    }
};
#define PAGESIZE 0X1000
#if defined _WIN64
using UDWORD = DWORD64;
#define XIP Rip//instruction pointer
#else
using UDWORD = DWORD32;
#define XIP Eip//instruction pointer
#endif
class NormalHandle {//阐明了句柄的关闭方式和句柄的无效值智能句柄的Traits clarify the handle's close method and handle's invalid value smart handle's Traits
public:
    INLINE static void Close(HANDLE handle)NOEXCEPT { CloseHandle(handle); }
    INLINE static HANDLE InvalidHandle()NOEXCEPT { return INVALID_HANDLE_VALUE; }
    INLINE static bool IsValid(HANDLE handle)NOEXCEPT { return handle != InvalidHandle() && handle; }
    INLINE static DWORD Wait(HANDLE handle,DWORD time)NOEXCEPT{return WaitForSingleObject(handle, time);}//单位:毫秒 unit:ms
};
template<class Ty>
class HandleView:public Ty{//采用基础句柄的视图,不负责关闭句柄 use basic handle HandleView,not responsible for closing handle
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
        if (this != &other) {
            m_handle = other.m_handle;
            m_bOwner = other.m_bOwner;
            other.m_handle = Traits::InvalidHandle();
            other.m_bOwner = false;
        }
        return *this;
    }
    INLINE GenericHandle(GenericHandle&& other)NOEXCEPT {//移动构造 move construct
        m_handle = other.m_handle;
        m_bOwner = other.m_bOwner;
        other.m_handle = Traits::InvalidHandle();
        other.m_bOwner = false;
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
};
#define DELETE_COPYMOVE_CONSTRUCTOR(TYPE) TYPE(const TYPE&)=delete;TYPE(TYPE&&) = delete;void operator= (const TYPE&) = delete;void operator= (TYPE&&) = delete;
template<typename T >
class SingleTon {//这种单例是线程安全的,同一个进程内只会创建一个实例 This singleton is thread safe, only one instance will be created in the same process
private:
    DELETE_COPYMOVE_CONSTRUCTOR(SingleTon)//删除拷贝构造函数和拷贝赋值函数 delete copy constructor and copy assignment
    std::atomic_bool bflag = false;//标记是否已经创建了实例 mark whether the instance has been created
    GenericHandle<HANDLE, NormalHandle> hEvent;//智能句柄 smart handle
    static INLINE std::shared_ptr<T> CreateInstance() NOEXCEPT { return std::make_shared<T>(); }//创建一个类的实例 create a instance of class
    template <class... Args>
    static INLINE std::shared_ptr<T> CreateInstance(Args&& ...args) NOEXCEPT { return std::make_shared<T>(args...); }//用参数构造一个类的实例 create a instance of class by parameters 两个CreateInstance函数是为了支持参数构造两个CreateInstance函数是为了支持参数构造
    std::string GetCurrentProcessName() NOEXCEPT {//获取当前进程名 get current process name
        char szProcessName[MAX_PATH] = { 0 };//预留空间 reserve space
        GetModuleFileNameA(NULL, szProcessName, MAX_PATH);
        return szProcessName;
    }
    template <class... Args>
    INLINE static T& GetInstanceImpl(Args&& ...args) NOEXCEPT {
        static std::once_flag flag{};
        static std::shared_ptr<T> instance = nullptr;
        if (!instance) {
            std::call_once(flag, [&]() {//call once   只调用一次
                instance = CreateInstance(args...);//element constructor through parameters    通过参数构造元素
            });
        }
        if (instance->bflag) {
            throw std::exception("SingleTon has been created");
        }else {
            return *instance.get();
        }
    }
    INLINE static T& GetInstanceImpl() NOEXCEPT {
        static std::once_flag flag{};
        static std::shared_ptr<T> instance = nullptr;
        if (!instance) {
            std::call_once(flag, [&]() {//call once  只调用一次
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
        std::string eventname = typeid(T).name()+GetCurrentProcessName();//可选择性的加上dll的名字 optionally add dll name
        //将/替换为_ replace / with _
        std::replace(eventname.begin(), eventname.end(), '\\', '_');//\\符号不能创建事件 属于特殊符号 \\ symbol can't create event is special symbol
        //创建互斥量 create event
        hEvent = CreateEventA(NULL, FALSE, FALSE, eventname.c_str());//利用同名事件来检查是否已经创建了实例 use same name event to check whether the instance has been created
        //检查互斥量是否已经被创建 check event is created
        bflag = (GetLastError() == ERROR_ALREADY_EXISTS) ? true : false;
        if (!hEvent)throw std::exception("CreateEventA failed");
    }
    ~SingleTon() { }
    template <class... Args>
    INLINE static T& GetInstance(Args&& ...args) NOEXCEPT {//get instance this function is thread safe and support parameter    此函数是线程安全的并且支持参数
        return GetInstanceImpl(std::forward<Args>(args)...);
    }
};
//debugoutput
template<class T>
void DebugOutput(const T& t) {
    //转为字符串
    std::stringstream ss;
    ss << t;
    OutputDebugStringA(ss.str().c_str());
}
class FreeBlock {//空闲块 free block
public:
    size_t size;//大小 size
    void* ptr;  //指针 pointer
    FreeBlock* next;//下一个块 next block 其实就是一个链表 actually is a linked list
};
INLINE BOOL VirtualFreeExApi(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {//远程释放内存 remote free memory
    return VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType);//系统的 VirtualFreeEx  system VirtualFreeEx
}
INLINE LPVOID VirtualAllocExApi(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {//最基础的远程释放内存函数 the most basic remote free memory function 分配的粒度为0x1000  allocate granularity is 0x1000
    return VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);// 系统的 VirtualAllocEx  system VirtualAllocEx
}
constexpr DWORD CacheMinTTL = 128;
constexpr DWORD CacheNormalTTL = 200;
constexpr DWORD CacheMaxTTL = 4096;
template<class T>
struct RangeCmp {//仿函数
    bool operator()(const std::pair<T, T>& p1, const std::pair<T, T>& p2) const {
        if (p1.first >= p2.first) return false;
        return p1.second < p2.second;
    }
};
class FastMutex {
    CRITICAL_SECTION g_cs;
public:
    FastMutex() {InitializeCriticalSection(&g_cs);}
    CRITICAL_SECTION& Get() {return g_cs;}
    ~FastMutex() {DeleteCriticalSection(&g_cs);}
};
FastMutex lock;
template<typename _Tx>class CacheItem {
public:
    using timepoint = std::chrono::time_point<std::chrono::system_clock>;
    timepoint m_endtime;
    _Tx   m_value;
    CacheItem() = default;
    CacheItem(const _Tx& _value, const timepoint& _endtime) :m_endtime(_endtime), m_value(_value) {}
    CacheItem(const _Tx&& _value, const timepoint& _endtime) :m_value(std::move(_value)), m_endtime(_endtime) {}
    ~CacheItem() { m_value.~_Tx(); }
    inline bool IsValid(timepoint now)noexcept { return now < m_endtime; }
};
template<typename _Tx, typename _Ty, class Pr = RangeCmp<_Tx>>
class SimpleRangeCache {
protected:
    std::map<std::pair<_Tx, _Tx>, CacheItem<_Ty>, Pr> m_Cache;
public:
    using keyType = std::pair<_Tx, _Tx>;
    using cache_item_type = _Ty;
    using pair_type = typename std::decay_t<decltype(m_Cache)>::value_type;
    using iterator = typename std::decay_t<decltype(m_Cache)>::iterator;
    SimpleRangeCache() {
        srand((unsigned int)time(0));
    }
    ~SimpleRangeCache()noexcept {
        EnterCriticalSection(&lock.Get());
        m_Cache.clear();
        LeaveCriticalSection(&lock.Get());
    }
    inline void AsyncAddCache(const keyType& _key, const _Ty& _value, DWORD _validtime) {
        auto future=std::async(std::launch::async, [&]()->void {
            auto nowTime = std::chrono::system_clock::now();
            auto newValue = CacheItem<_Ty>(_value, nowTime + std::chrono::milliseconds(_validtime + rand() % 30));
            auto lb = m_Cache.find(_key);
            if (lb != m_Cache.end()) {
                lb->second = newValue;
            }else {
                EnterCriticalSection(&lock.Get());
                m_Cache.insert(lb, pair_type(_key, newValue));
                LeaveCriticalSection(&lock.Get());
            }
            static auto firsttime = std::chrono::system_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(nowTime - firsttime).count() > 5000) {//5s
                firsttime = nowTime;
                EnterCriticalSection(&lock.Get());
                for (auto it = m_Cache.begin(); it != m_Cache.end();) it = (!it->second.IsValid(nowTime)) ? m_Cache.erase(it) : ++it;
                LeaveCriticalSection(&lock.Get());
            }
        });
    }
    inline std::pair<iterator, bool> find(const _Tx& value) {
        keyType _key = keyType(value, value);
        if (m_Cache.empty()) return { iterator(),false };
        auto iter = m_Cache.find(_key);
        EnterCriticalSection(&lock.Get());
        bool IsValidItem = iter->second.IsValid(std::chrono::system_clock::now());
        LeaveCriticalSection(&lock.Get());
        return { iter, iter != m_Cache.end() && IsValidItem };
    }
    inline std::pair<iterator, bool> operator[](_Tx&& value) {
        return find(value);
    }
    inline void erase(const _Tx& value) {//删除缓存
        keyType &_key = keyType(value, value);
        if (m_Cache.empty()) return;
        auto iter = m_Cache.find(_key);
        EnterCriticalSection(&lock.Get());
        if (iter != m_Cache.end()) m_Cache.erase(iter);
        LeaveCriticalSection(&lock.Get());
    }
    inline void Clear() {
        EnterCriticalSection(&lock.Get());
        m_Cache.Clear();
        LeaveCriticalSection(&lock.Get());
    }
};
constexpr inline bool CheckMask(const DWORD value, const DWORD mask) {//判断vakue和mask是否相等
    return (mask && (value & mask)) && (value <= mask);
}
constexpr auto USERADDR_MIN = 0x10000;
#ifdef _WIN64
constexpr auto USERADDR_MAX = 0x7fffffff0000;
#else
constexpr auto USERADDR_MAX = 0xBFFE'FFFF;
#endif
UDWORD maxAppAddr = USERADDR_MAX;
UDWORD minAppAddr = USERADDR_MIN;
static SimpleRangeCache<UDWORD, MEMORY_BASIC_INFORMATION> cache;
inline SIZE_T VirtualQueryCacheApi(HANDLE hProcess,LPVOID lpAddress, MEMORY_BASIC_INFORMATION* lpMbi) {
    if ((UDWORD)lpAddress > maxAppAddr) return 0;
    auto [result, isHit] = cache.find((UDWORD)lpAddress);
    if (isHit) {
        if (lpMbi)*lpMbi = result->second.m_value;
        return sizeof(MEMORY_BASIC_INFORMATION);
    }
    else {
        auto ret = VirtualQueryEx(hProcess,lpAddress, lpMbi, sizeof(MEMORY_BASIC_INFORMATION));
        if (ret > 0) {
            UDWORD start = (UDWORD)lpMbi->AllocationBase;
            UDWORD end = start + lpMbi->RegionSize, Ratio = 1;
            if (CheckMask(lpMbi->Type, MEM_IMAGE | MEM_MAPPED)) Ratio = 999;
            cache.AsyncAddCache(std::make_pair(start, end), *lpMbi, CacheNormalTTL * Ratio);
        }
        return ret;
    }
}
INLINE DWORD VirtualQueryExApi(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) {//远程查询内存 remote query memory
    return VirtualQueryCacheApi(hProcess, (LPVOID)lpAddress, lpBuffer);//系统的 VirtualQueryEx  system
}
//空闲块链表 free block list
class FreeBlockList:public SingleTon<FreeBlockList> {//单例模式方便后期调用 singleton mode is convenient for later call
public:
    FreeBlockList(HANDLE hprocess=GetCurrentProcess()) : m_head(nullptr) {
        m_hProcess = hprocess;
    }
    ~FreeBlockList() {//当析构时释放所有空闲块 free all free block when destruct
        auto block = m_head;
        while (block) {
            auto next = block->next;
            if(m_hProcess)VirtualFreeExApi(m_hProcess,block->ptr, block->size, MEM_RELEASE);
            delete block;
            block = next;
        }
        g_allocMap.clear();
    }
    INLINE void Add(void* ptr, size_t size) NOEXCEPT {//加入一个空闲块 add a free block
        auto block = new FreeBlock();
        block->ptr = ptr;
        block->size = size;
        block->next = m_head;
        m_head = block;
    }
    INLINE void* Get(size_t size)NOEXCEPT {//获得一个空闲块 get a free block
        if (size <= 0) return nullptr;
        auto p = &m_head;
        while (*p) {
            if ((*p)->size >= size) {
                auto block = *p;
                if (block->size > size) {
                    // 如果块的大小大于请求的大小，那么我们需要分割这个块 if block size is greater than requested size, we need to split this block
                    auto newBlock = new FreeBlock();
                    newBlock->ptr = (char*)block->ptr + size;
                    newBlock->size = block->size - size;
                    newBlock->next = block->next;
                    *p = newBlock;
                }
                else {
                    // 否则，我们只需删除这个块 delete this block
                    *p = block->next;
                }
                return block->ptr;
            }
            p = &(*p)->next;
        }
        // 如果没有找到足够大的块，那么我们需要向系统申请更多的内存 get more memory from system if not found enough memory
        auto allocSize = (size > PAGESIZE) ? size : PAGESIZE;
        LPVOID ptr=NULL;
        if (m_hProcess)ptr=VirtualAllocExApi(m_hProcess, nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);//调用系统的api分配内存 call system api to allocate memory
        if (ptr == nullptr) {
            std::cerr << "VirtualAlloc failed." << std::endl;
            return nullptr;
        }
        SIZE_T written = 0;
        //分配一个临时空间用于存0   allocate a temporary space to store 0
        std::unique_ptr<char[]> temp(new char[allocSize]());
        memset(temp.get(), 0, allocSize);
        if (!WriteProcessMemory(m_hProcess,ptr, temp.get(), allocSize, &written)) {//将0写入到分配的内存 write 0 to allocated memory
            std::cerr << "WriteProcessMemory failed." << std::endl;
        }
        Add(ptr, allocSize);//加入到空闲块链表 add to free block list
        return Get(size);  // 重新尝试获取内存 get memory again
    }
    INLINE void Free(void* ptr, size_t size)NOEXCEPT {
        //查allocatebase
        MEMORY_BASIC_INFORMATION mbi{};
        VirtualQueryExApi(m_hProcess, ptr, &mbi, sizeof(mbi));
        //合并到空闲链表当中allcatebase相同的块
        auto p = &m_head;
        while (*p) {
            auto allocatebase = mbi.AllocationBase;
            if ((*p)->ptr == allocatebase) {
              //合并size到块内
                auto block = *p;
                block->size += size;//合并size到块内
                break;
            }
            p = &(*p)->next;//下一个块 next block
        }
        //释放内存 free memory
        //遍历空闲链表，如果有相邻的块，那么合并这两个块
        p = &m_head;
        while (*p) {
            auto block = *p;
            auto next = block->next;
            if (next && (char*)block->ptr + block->size == next->ptr) {
                block->size += next->size;
                block->next = next->next;
                delete next;
                continue;
            }
            p = &(*p)->next;
        }
        //如果空闲块的大小大于PAGESIZE，那么释放内存
        p = &m_head;
        while (*p) {
            auto block = *p;
            auto next = block->next;
            if (block->size > PAGESIZE) {
                if (m_hProcess)VirtualFreeExApi(m_hProcess,block->ptr, block->size, MEM_DECOMMIT);
                *p = next;
                delete block;
            }
            p = &(*p)->next;
        }
    }
    INLINE void* mallocex(size_t size)NOEXCEPT {
        auto ptr =Get(size);
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
    GenericHandle<HANDLE, HandleView<NormalHandle>> m_hProcess;//HandleView
};
INLINE void* mallocex(HANDLE hProcess,size_t size) {
    return FreeBlockList::GetInstance(hProcess).mallocex(size);//调用单例模式的函数 call singleton function
}
INLINE void freeex(HANDLE hProcess,void* ptr) {
    return FreeBlockList::GetInstance(hProcess).freeex(ptr);   //调用单例模式的函数 call singleton function
}
class Shared_Ptr {//一种外部线程的智能指针,当引用计数为0时释放内存 a smart pointer of external thread,release memory when reference count is 0
    GenericHandle<HANDLE, HandleView<NormalHandle>> m_hProcess;//并不持有 进程句柄而是一种视图,不负责关闭进程句柄 not hold process handle but a HandleView,not responsible for closing process handle
    LPVOID BaseAddress = nullptr;
    int refCount = 0;
    void AddRef() NOEXCEPT {
        refCount++;
    }
    INLINE UDWORD _AllocMemApi(SIZE_T dwSize) NOEXCEPT {//远程分配内存 remote allocate memory
        return (UDWORD)mallocex(m_hProcess,dwSize);
    }
    INLINE bool _FreeMemApi(LPVOID lpAddress) NOEXCEPT {//远程释放内存 remote free memory
        freeex(m_hProcess,lpAddress);
        return true;
    }
public:
    INLINE Shared_Ptr(void* Addr, HANDLE hProc) : m_hProcess(hProc){
        BaseAddress = Addr;
        AddRef();
    }
    template<class T>
    INLINE Shared_Ptr() NOEXCEPT {
        AddRef();//新建一个指针引用计数加一 reference count plus one means a new pointer points to this memory
        BaseAddress = (LPVOID)_AllocMemApi(sizeof(T));
    }
    INLINE Shared_Ptr(size_t nsize, HANDLE hProc) :m_hProcess(hProc){
        AddRef();//引用计数加一说明有一个新的指针指向了这块内存 reference count plus one means a new pointer points to this memory
        BaseAddress = (LPVOID)_AllocMemApi(nsize);
    }
    INLINE Shared_Ptr(const Shared_Ptr& other) : BaseAddress(other.BaseAddress), refCount(other.refCount){
        AddRef();//引用计数加一说明有一个新的指针指向了这块内存 reference count plus one means a new pointer points to this memory
    }
    INLINE Shared_Ptr& operator=(const Shared_Ptr& other) NOEXCEPT {//copy assignment   拷贝赋值
        if (this != &other){
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
    INLINE LPVOID raw() const NOEXCEPT {return BaseAddress;}//不增加引用计数的获取raw指针 get raw pointer without increasing reference count
    INLINE UDWORD getUDWORD() NOEXCEPT {//返回远程地址的UDWORD值 return UDWORD value of remote address
        AddRef();
        return (UDWORD)BaseAddress;
    }
    INLINE ~Shared_Ptr() NOEXCEPT { Release();}
    INLINE void Release() NOEXCEPT {//release and refCount-- 引用计数减一
        refCount--;
        if (BaseAddress && refCount <= 0){
            _FreeMemApi(BaseAddress);//释放内存 free memory 只是归还空间到空闲块链表 return space to free block list
            BaseAddress = nullptr;
        }
    }
    INLINE operator bool() NOEXCEPT {return BaseAddress != nullptr;}
    //判等
    INLINE bool operator==(const Shared_Ptr& other) NOEXCEPT {return BaseAddress == other.BaseAddress;}
    //判不等
    INLINE bool operator!=(const Shared_Ptr& other) NOEXCEPT {return BaseAddress != other.BaseAddress;}
};
template<class T>Shared_Ptr make_Shared(size_t nsize, HANDLE hprocess) NOEXCEPT { return Shared_Ptr(sizeof(T) * nsize, hprocess); }
template<class BinFunc>
INLINE size_t GetFunctionSize(const BinFunc& func) NOEXCEPT {//获取函数大小,纯属经验之谈 get function size,just experience
    auto p = (PBYTE)func;
    for (int i = 0, len = 0; i < 4096; i++){
        if (p[i] == 0xC2){
            len = i;
            while (true){
                len += 3;
                if (p[len] == 0xCC || (p[len] == 0x0 && p[len + 1] == 0x0))return len;
                len = 0;
                break;
            }
        }
        if (p[i] == 0xC3){
            len = i;
            while (true){
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
template<class Tx, class Ty> INLINE size_t _ucsicmp(const Tx * str1, const Ty * str2) NOEXCEPT {//ignore case compare ignore type wchar_t wstring or char string 忽略大小写比较 忽略类型wchar_t wstring或者char string
    if (!str1 || !str2) throw std::exception("str1 or str2 is nullptr");
    std::wstring wstr1{}, wstr2{};
    std::string  strtemp{};
    if constexpr (!std::is_same_v<remove_const_pointer_t<Tx>, wchar_t>){
        strtemp = str1;
        wstr1 = std::wstring(strtemp.begin(), strtemp.end());//transform to wstring 转换为wstring 仅是一种截断转换对于26个字母来说是安全的 only a kind of truncation conversion is safe for 26 letters
    }else {
        wstr1 = str1;
    }
    if constexpr (!std::is_same_v<remove_const_pointer_t<Ty>, wchar_t>){
        strtemp = str2;
        wstr2 = std::wstring(strtemp.begin(), strtemp.end());//transform to wstring 转换为wstring 仅是一种截断转换对于26个字母来说是安全的 only a kind of truncation conversion is safe for 26 letters
    }else {
        wstr2 = str2;
    }
    std::transform(wstr1.begin(), wstr1.end(), wstr1.begin(), towlower);//transform to lower 转换为小写
    std::transform(wstr2.begin(), wstr2.end(), wstr2.begin(), towlower);//transform to lower    转换为小写
    return wstr1.compare(wstr2);
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
class ThreadData:public ThreadDataBase<Fn,T> {
public:
    T retdata;//return data 返回值
};
template <class Fn>
class ThreadData<Fn, void>:public ThreadDataBase<Fn, void> {//特化当返回值为void的情况 specialize when return value is void
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
    auto ret = [threadData](auto index) NOEXCEPT {
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
    [threadData](auto index) NOEXCEPT {
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
        if(m_GenericHandleThread)m_bAttached = true;
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
        m_bAttached= Attached;
        other.m_dwThreadId = 0;
        other.m_bAttached = false;
    }
    Thread& operator=(Thread&& other) NOEXCEPT {    //移动赋值 move assignment
        if (this != &other){
            m_GenericHandleThread = std::move(other.m_GenericHandleThread);
            m_dwThreadId = other.m_dwThreadId;
            bool Attached = other.m_bAttached;
            m_bAttached= Attached;
            other.m_dwThreadId = 0;
            other.m_bAttached = false;
        }
        return *this;
    }
    ~Thread() NOEXCEPT {}
    HANDLE GetHandle() NOEXCEPT { return m_GenericHandleThread; }//获取线程句柄  get thread handle
    operator bool(){
        return IsRunning();
    }
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
    bool IsBlock() {
        //等待 wait 如果线程处于死锁状态，那么WaitForSingleObject会返回WAIT_TIMEOUT  if thread is in deadlock state,WaitForSingleObject will return WAIT_TIMEOUT
        if (m_bAttached) {
            DWORD dwRet = m_GenericHandleThread.Wait(0);
            if (dwRet == WAIT_TIMEOUT) {
                return false;
            }
            else if (dwRet == WAIT_OBJECT_0) {
                return true;
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
    void SetContext(CONTEXT& context) NOEXCEPT {
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
    //PostThreadMessage  向线程发送消息  send message to thread
    BOOL _PostThreadMessage(UINT Msg, WPARAM wParam, LPARAM lParam) NOEXCEPT {//向线程发送消息  send message to thread
        BOOL bRet = FALSE;
        if (m_bAttached) {
            bRet=::PostThreadMessageA(m_dwThreadId, Msg, wParam, lParam);
        }
        return bRet;
    }
    void QueApc(void* Addr) NOEXCEPT {//往线程中注入APC inject APC to thread
        if (m_bAttached) {
            QueueUserAPC((PAPCFUNC)Addr, GetHandle(), 0);
        }
    }
    //设置线程优先级  set thread priority 竟然还会触发APC的强制执行  it will trigger APC to execute forcibly
    void SetPriority(int nPriority = THREAD_PRIORITY_HIGHEST) NOEXCEPT {
        if (m_bAttached) {
            SetThreadPriority(GetHandle(), nPriority);
        }
    }
};
template <typename T>
class ThreadSafeVector {//线程安全的vector thread safe vector
    std::mutex m_mutex; //lock for vector
    std::vector<T> m_vector;
public:
    //聚合初始化    aggregate initialization
    ThreadSafeVector(std::initializer_list<T> list) :m_vector(list){}
    ThreadSafeVector() = default;
    ThreadSafeVector(const ThreadSafeVector& other){
        m_vector = other.m_vector;
    }
    INLINE ThreadSafeVector(size_t size){
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
    //emplace back
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
    //data
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
    INLINE void assign(size_t size, const T& value) NOEXCEPT {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_vector.assign(size, value);
    }
    INLINE void assign(std::initializer_list<T> list) NOEXCEPT {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_vector.assign(list);
    }
    //迭代器assign  iterator assign
    template<class InputIt>
    INLINE void assign(InputIt first, InputIt last) NOEXCEPT {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_vector.assign(first, last);
    }
    INLINE bool empty() const{
        return m_vector.empty();
    }
    INLINE void safe_erase(typename std::vector<T>::iterator it) NOEXCEPT {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_vector.erase(it);
    }
    //不安全的删除  unsafe erase
    INLINE void erase(typename std::vector<T>::iterator it) NOEXCEPT {
        m_vector.erase(it);
    }
    //unsafe
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
    //crbegin
    INLINE decltype(auto) crbegin() NOEXCEPT {
        return m_vector.crbegin();
    }
    INLINE decltype(auto) crend() NOEXCEPT {
        return m_vector.crend();
    }
    INLINE void unsafe_erase(typename std::vector<T>::iterator it) NOEXCEPT {
        m_vector.erase(it);
    }
    INLINE decltype(auto) cbegin() const {
        return m_vector.begin();
    }
    INLINE decltype(auto) cend() const {
        return m_vector.end();
    }
};
enum class EnumRunningMode{
    POINTER_READ,
    POINTER_WRITE
};
template<class T>
INLINE ThreadSafeVector<T> operator+(const ThreadSafeVector<T>&lhs, const ThreadSafeVector<T>&rhs) NOEXCEPT {
    ThreadSafeVector<T> result;
    result.reserve(lhs.size() + rhs.size());
    for (size_t i = 0; i < lhs.size(); i++)result.push_back(lhs[i]);
    for (size_t i = 0; i < rhs.size(); i++)result.push_back(rhs[i]);
    return result;
}
class RunningMode{
public:
    LPVOID OriginAddr; 
    EnumRunningMode m_RunningMode;
};
class Process :public SingleTon<Process> {//Singleton   单例
    GenericHandle<HANDLE,NormalHandle> m_hProcess;
    DWORD m_pid;//process id    进程id
    EnumRunningMode m_RunningMode = EnumRunningMode::POINTER_READ;
    std::atomic_bool m_bAttached;//atomic bool  原子bool
    ThreadSafeVector<Shared_Ptr> m_vecAllocMem;//vector for allocated memory    保存分配的内存的vector
    std::unordered_map<LPVOID, LPVOID> maptoorigin;//map for save original address and allocated address, key is allocated address value is original address    保存原始地址和分配地址的map，key是分配地址，value是原始地址
    template<typename T, typename ...Args>
    INLINE void preprocess(T& arg, Args&...args) NOEXCEPT {//partially specialized template 部分特化模板
        if constexpr (has_type_v<T,const char*,const wchar_t *>) preprocessparameter(arg);
        if constexpr (std::is_pointer_v<T> && !has_type_v<T,LPVOID,LPCVOID,const char*,const wchar_t*>)ProcessPtr(arg);
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
        if (iter != maptoorigin.end()){
            LPVOID OriginAddr = iter->second;//original address   原始地址
            if (m_RunningMode == EnumRunningMode::POINTER_READ){
                _ReadApi((LPVOID)ptr, OriginAddr, sizeof(T));//read value from allocated address to original address    从分配地址读取值到原始地址
            }
        }
    }
    template<typename T>
    INLINE void preprocessparameter(T& arg) NOEXCEPT {}
    INLINE void preprocessparameter(const char*& arg) NOEXCEPT {
        auto nlen = (int)strlen(arg) + 1;
        auto p = make_Shared<char>(nlen * sizeof(char), m_hProcess);
        if (p){
            m_vecAllocMem.push_back(p);
            _WriteApi((LPVOID)p.get(), (LPVOID)arg, nlen * sizeof(char));
            arg = (const char*)p.raw();
        }
    }//process const char* parameter    处理const char*参数
    INLINE void preprocessparameter(const wchar_t*& arg){
        auto nlen = (int)wcslen(arg) + 1;
        auto p = make_Shared<wchar_t>(nlen * sizeof(wchar_t), m_hProcess);
        if (p){
            m_vecAllocMem.push_back(p);
            _WriteApi((LPVOID)p.get(), (LPVOID)arg, nlen * sizeof(wchar_t));
            arg = (const wchar_t*)p.raw();
        }
    }//process const wchar_t* parameter   处理const wchar_t*参数
    template<typename T>
    INLINE void ProcessPtr(T& ptr) NOEXCEPT {
        if (ptr){
            int Size = sizeof(T);//get size of parameter    获取参数大小
            auto p = make_Shared<BYTE>(Size, m_hProcess);
            if (p){
                m_vecAllocMem.emplace_back(p);//emplace back into vector avoid memory leak can be clear through clearmemory   emplace back到vector中避免内存泄漏可以通过clearmemory清除
                _WriteApi(p.get(), (LPVOID)ptr, Size);//write value to allocated address for parameter is pointer   写入值到分配地址，因为参数是指针
                if(m_RunningMode== EnumRunningMode::POINTER_READ)maptoorigin.insert(std::make_pair((LPVOID)p.raw(), (LPVOID)ptr));//save original address and allocated address   保存原始地址和分配地址
                ptr = (T)p.raw();//set parameter to allocated address   设置参数为分配地址
            }
        }
    }
public:
    INLINE void Attach(const char* _szProcessName) NOEXCEPT {//attach process   附加进程
        //get process id    获取进程id
        auto pid = GetProcessIdByName(_szProcessName);
        if (pid != 0){
            m_pid = pid;
            m_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_pid);
            if(m_hProcess)m_bAttached = true;
        }
    }
    INLINE void ChangeMode(const EnumRunningMode& Mode) NOEXCEPT {
        m_RunningMode = Mode;
    }
    //readapi
    INLINE ULONG _ReadApi(_In_ LPVOID lpBaseAddress, _In_opt_ LPVOID lpBuffer, _In_ SIZE_T nSize) NOEXCEPT {//ReadProcessMemory
        if (m_bAttached){
            SIZE_T bytesRead = 0;
            ReadProcessMemory(m_hProcess, lpBaseAddress, lpBuffer, nSize, &bytesRead);
            return bytesRead;
        }
        return 0;
    }
    //writeapi  
    INLINE ULONG _WriteApi(_In_ LPVOID lpBaseAddress, _In_opt_ LPVOID lpBuffer, _In_ SIZE_T nSize) NOEXCEPT {//WriteProcessMemory
        if (m_bAttached){
            SIZE_T bytesWritten = 0;
            WriteProcessMemory(m_hProcess, lpBaseAddress, lpBuffer, nSize, &bytesWritten);
            return bytesWritten;
        }
        return 0;
    }
    template<class PRE>
    INLINE void EnumThread(PRE pre) NOEXCEPT {//enum thread through snapshot    通过快照枚举线程
        if (m_bAttached){
            GenericHandle<HANDLE,NormalHandle> hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hSnapshot){
                InitObj<THREADENTRY32> threadEntry{};
                for (auto bRet = Thread32First(hSnapshot, &threadEntry); bRet; bRet = Thread32Next(hSnapshot, &threadEntry)) {
                    if (threadEntry->th32OwnerProcessID == m_pid) {
                        Thread thread(threadEntry);
                        if (thread&& pre(threadEntry) == EnumStatus::Break)break;
                    }
                }
            }
        }
    }
    INLINE void ClearMemory() NOEXCEPT {
        for (auto& p : m_vecAllocMem) p.Release();
        m_vecAllocMem.clear();
    }
    template<class _Fn, class ...Arg>
    decltype(auto) SetContextCallImpl(__in _Fn&& _Fx, __in Arg ...args) NOEXCEPT {
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
        strcpy_s(threadData.funcname[3], "CloseHandle");//CloseHandle
        //创建事件  create event
        GenericHandle<HANDLE,NormalHandle> hEvent = CreateEventA(NULL, FALSE, FALSE, threadData.eventname);
        //设置函数地址  set function address
        threadData.pFunc[0] = (LPVOID)GetProcAddress(GetModuleHandleA(threadData.funcname[0]), "LoadLibraryA");
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
            _paramAddr = (UDWORD)lpParameter.raw();//set parameter address  设置参数地址
            _ctx = ctx;//save context   保存上下文
            ctx.XIP = (UDWORD)lpShell.raw();//set xip   设置xip
            _WriteApi((LPVOID)lpShell.get(), &dataContext, sizeof(DATA_CONTEXT));//write datacontext    写入datacontext
            thread.SetContext(ctx);//set context    设置上下文
            thread.Resume();//resume thread   恢复线程
            _thread = std::move(thread);//move thread   移动线程
            return EnumStatus::Break;
            });
        hEvent.Wait(INFINITE);//wait event
        if(maptoorigin.size()>0)postprocess(args...);//post process parameter   后处理参数
        maptoorigin.clear();//clear map  清除map
        _ReadApi((LPVOID)_paramAddr, &threadData, sizeof(threadData));//read parameter for return value  读取参数以返回值
        return threadData.retdata;//return value    返回值
    }
    template <class _Fn>
    INLINE decltype(auto) SetContextCallImpl(_Fn&& _Fx) NOEXCEPT {
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
        strcpy_s(threadData.funcname[3], "CloseHandle");//CloseHandle
        //创建事件  create event
        GenericHandle<HANDLE, NormalHandle> hEvent = CreateEventA(NULL, FALSE, FALSE, threadData.eventname);
        //获取地址  get address
        auto pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandleA(threadData.funcname[0]), "LoadLibraryA");
        auto pGetProcAddress = (LPVOID)GetProcAddress;
        //设置函数地址  set function address
        threadData.pFunc[0] = (LPVOID)pLoadLibrary;
        threadData.pFunc[1] = (LPVOID)pGetProcAddress;
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
            _paramAddr = (UDWORD)lpParameter.raw();
            _ctx = ctx;//store context  保存上下文
            ctx.XIP = (UDWORD)lpShell.raw();//set xip   设置xip
            _WriteApi((LPVOID)lpShell.get(), &dataContext, sizeof(DATA_CONTEXT));//write datacontext to memory  写入datacontext到内存
            thread.SetContext(ctx);//set context    设置上下文
            thread.Resume();//resume thread  恢复线程
            _thread = std::move(thread);//store thread  存储线程
            return EnumStatus::Break;
        });
        hEvent.Wait(INFINITE);//wait event
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
    INLINE void SetContextCallNoReturnImpl(_Fn&& _Fx) NOEXCEPT {
        using RetType = void;
        Thread _thread{};
        CONTEXT _ctx{};
        UDWORD _paramAddr = 0;
        ThreadData<std::decay_t<_Fn>, RetType> threadData;//thread data
        strcpy_s(threadData.eventname, "SetContextCallImpl");//event name
        strcpy_s(threadData.funcname[0], "kernel32.dll");//kernel32.dll
        strcpy_s(threadData.funcname[1], "OpenEventA");//OpenEventA
        strcpy_s(threadData.funcname[2], "SetEvent");//SetEvent
        strcpy_s(threadData.funcname[3], "CloseHandle");//CloseHandle
        //创建事件  create event
        GenericHandle<HANDLE, NormalHandle> hEvent = CreateEventA(NULL, FALSE, FALSE, threadData.eventname);
        //获取地址  get address
        auto pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandleA(threadData.funcname[0]), "LoadLibraryA");
        auto pGetProcAddress = (LPVOID)GetProcAddress;
        //设置函数地址  set function address
        threadData.pFunc[0] = (LPVOID)pLoadLibrary;
        threadData.pFunc[1] = (LPVOID)pGetProcAddress;
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
            return EnumStatus::Break;
            });
        hEvent.Wait(INFINITE);//wait event
    }
    template<class _Fn, class ...Arg>
    INLINE void SetContextCallNoReturn(__in _Fn&& _Fx, __in Arg ...args) NOEXCEPT {
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
        strcpy_s(threadData.funcname[3], "CloseHandle");//CloseHandle
        //创建事件
        GenericHandle<HANDLE, NormalHandle> hEvent = CreateEventA(NULL, FALSE, FALSE, threadData.eventname);
        //获取地址
        auto pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandleA(threadData.funcname[0]), "LoadLibraryA");
        auto pGetProcAddress = (LPVOID)GetProcAddress;
        //设置函数地址
        threadData.pFunc[0] = (LPVOID)pLoadLibrary;
        threadData.pFunc[1] = (LPVOID)pGetProcAddress;
        EnumThread([&](auto& te32)->EnumStatus {
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
            return EnumStatus::Break;
        });
        hEvent.Wait(INFINITE);//wait event
        if (maptoorigin.size() > 0)postprocess(args...);//post process parameter
        maptoorigin.clear();//clear map
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
    template<class T>
    INLINE static T TONULL() NOEXCEPT { //return null value  返回空值
        return  reinterpret_cast<T>(0);
    }
private:
    INLINE DWORD GetProcessIdByName(const char* processName) NOEXCEPT {//get process id by name   通过名称获取进程id
        DWORD pid = 0;
        //返回GenericHandle是为了防止忘记关闭句柄，因为GenericHandle析构函数会自动关闭句柄预防内存泄漏  return GenericHandle is for prevent forget close handle, because GenericHandle destructor will close handle automatically to prevent memory leak
        GenericHandle<HANDLE,NormalHandle> hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot){
            //PROCESSENTRY32W processEntry = { sizeof(PROCESSENTRY32W), };
            InitObj<PROCESSENTRY32W> processEntry{};
            //采用for循环遍历进程快照，直到找到进程名为processName的进程 use for loop to enumerate process snapshot until find process name is processName
            for (auto bRet = Process32FirstW(hSnapshot, &processEntry); bRet; bRet = Process32NextW(hSnapshot, &processEntry)){
                //比较进程名 compare process name 不区分大小写不区分char*和wchar_t* case insensitive for char* and wchar_t*
                if (_ucsicmp(processEntry->szExeFile, processName) == 0){
                    pid = processEntry->th32ProcessID;
                    break;
                }
            }
        }
        return pid;
    }
};
int main(){
    auto& Process = Process::GetInstance();//get instance   获取实例
    Process.Attach("notepad.exe");//attach process  附加进程
    std::cout << Process.SetContextCall(MessageBoxA, Process::TONULL<HWND>(), "MSG", "CAP", MB_OK).get();
    return 0;
}


