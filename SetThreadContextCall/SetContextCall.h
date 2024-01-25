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
namespace stc{
    #define INLINE inline
    #define NOEXCEPT noexcept
    #define PAGESIZE 0X1000
    #if defined _WIN64
    #define XIP Rip//instruction pointer
    #else
    #define XIP Eip//instruction pointer
    #endif
    class NormalHandle {//�����˾���Ĺرշ�ʽ�;������Чֵ���ܾ����Traits clarify the handle's close method and handle's invalid value smart handle's Traits
    public:
        INLINE static void Close(HANDLE handle)NOEXCEPT { CloseHandle(handle); }
        INLINE static HANDLE InvalidHandle()NOEXCEPT { return INVALID_HANDLE_VALUE; }
        INLINE static bool IsValid(HANDLE handle)NOEXCEPT { return handle != InvalidHandle() && handle; }
        INLINE static DWORD Wait(HANDLE handle, DWORD time)NOEXCEPT { return WaitForSingleObject(handle, time); }//��λ:���� unit:ms
    };
    template<class Ty>
    class HandleView :public Ty {//���û����������ͼ,������رվ�� use basic handle HandleView,not responsible for closing handle
    public:
        INLINE static void Close(HANDLE handle)NOEXCEPT { /*��Ϊ��ͼ�����ر� as a HandleView  doesn't close*/ }//��̬�����Լ�����Ϊ  polymorphism has its own behavior
    };
    template<class T, class Traits>
    class GenericHandle {//����RAII���ƹ����� use RAII mechanism to manage handle
    private:
        T m_handle = Traits::InvalidHandle();
        bool m_bOwner = false;//������ owner
        INLINE bool IsValid()NOEXCEPT { return Traits::IsValid(m_handle); }
    public:
        GenericHandle(const T& handle = Traits::InvalidHandle(), bool bOwner = true) :m_handle(handle), m_bOwner(bOwner) {}//���� m_bOwnerĬ��Ϊtrue construct m_bOwner default is true
        ~GenericHandle() {
            if (m_bOwner && IsValid()) {//�������������Ϊtrue���Ҿ����Чʱ When the handle owner is true and the handle is valid
                Traits::Close(m_handle);//�رվ�� close handle
                m_handle = Traits::InvalidHandle();//���þ��Ϊ��Чֵ set handle to invalid value
                m_bOwner = false;//���þ��������Ϊfalse set handle owner to false
            }
        }
        GenericHandle(GenericHandle&) = delete;//��ֹ�������캯�� disable copy constructor
        GenericHandle& operator =(const GenericHandle&) = delete;//��ֹ������ֵ���� disable copy assignment
        INLINE GenericHandle& operator =(GenericHandle&& other)NOEXCEPT {   //�ƶ���ֵ move assignment
            if (m_handle != other.m_handle) {
                m_handle = other.m_handle;
                m_bOwner = other.m_bOwner;
                other.m_handle = Traits::InvalidHandle();
                other.m_bOwner = false;
            }
            return *this;
        }
        //�ȴ���� wait handle ��λ:���� unit:ms
        INLINE DWORD Wait(DWORD time)NOEXCEPT {
            return Traits::Wait(m_handle, time);
        }
        //�жϺ�T�����Ƿ���ͬ judge whether is same type with T
        inline bool operator==(const T& handle)NOEXCEPT {//����== overload ==
            return m_handle == handle;
        }
        //����!= overload !=
        inline bool operator!=(const T& handle)NOEXCEPT {//����!= overload !=
            return m_handle != handle;
        }
        INLINE operator T() NOEXCEPT {//��m_handleת��ΪT����,ʵ�ʾ��Ǿ�������� convert m_handle to T type,actually is the type of handle
            return m_handle;
        }
        INLINE operator bool() NOEXCEPT {//����bool����,�жϾ���Ƿ���Ч overload bool type, judge handle is valid
            return IsValid();
        }
        //����ȡ��ַ
        INLINE T* operator&()NOEXCEPT {
            return &m_handle;
        }
        INLINE Traits* operator->()NOEXCEPT {//����ֱ�ӵ��þ���ķ��� allow to call handle's method directly
            return (Traits*)this;
        }
    };
    template <typename T>
    std::string GetMapName() {//��ȡ�����ڴ������ get shared memory name
        DWORD pid = GetCurrentProcessId();
        std::string pidstr = std::to_string(pid);
        std::string name = typeid(T).name();
        std::string ret = pidstr + name;
        return ret;
    }
    template<class T>
    class Instance {//�����ڴ��ʵ�� shared memory instance
        uintptr_t objaddr;
        LPVOID mapaddr;
        bool isOwend = false;
    public:
        HANDLE hFile;
        Instance(uintptr_t objaddr, LPVOID _mapaddr, bool isOwn, HANDLE hFile) :objaddr(objaddr), isOwend(isOwn), hFile(hFile), mapaddr(_mapaddr) {
        }
        ~Instance() {
            if (isOwend) {
                UnmapViewOfFile(mapaddr);//���ӳ�� unmap view of file ���ǻ�û�йر�ӳ����� but not close map object
            }
        }
        INLINE T* get() {
            return (T*)objaddr;
        }
    };
    template<class T>
    class InstanceManger {
    public:
        void* objaddr;//����ָ��
        INLINE static Instance<T> CreateInstance(InstanceManger* thisinstance) {
            std::atomic_bool Owend = false;
            HANDLE hFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, GetMapName<T>().c_str());
            if (!hFile) {
                // �����ļ�ӳ�� Create file mapping
                hFile = CreateFileMappingA(
                    INVALID_HANDLE_VALUE, // ʹ��ϵͳ��ҳ�ļ� use system paging file
                    NULL,                 // Ĭ�ϰ�ȫ����   default security attributes
                    PAGE_READWRITE,       // ��дȨ��   read/write access
                    0,                    // �������С����λ��   maximum object size (high-order DWORD)
                    sizeof(T),            // �������С����λ��   maximum object size (low-order DWORD)
                    GetMapName<T>().c_str()); // ӳ����������// ӳ���������� map object name
                Owend = true;
            }
            if (!hFile) {
                throw std::runtime_error("CreateFileMappingA failed with error code: " + std::to_string(GetLastError()));
            }
            //����ȹر�ӳ������ֹر��ļ���� close map object and file handle ��Ϊӳ�����һ���ر�,��ôӳ�䵽�ڴ�Ķ���Ҳ�ᱻ�ͷ� because once map object is closed,the object map to memory will be released
            auto p = static_cast<T*>(MapViewOfFile(hFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(T)));//ӳ�䵽�ڴ� map to memory 
            if (Owend && *(uintptr_t*)p == NULL)*(uintptr_t*)p = (uintptr_t)new T();//����ǵ�һ�δ���,��ô��ʼ������ if first create,then initialize object
            Instance<T> ret(*(uintptr_t*)p, (LPVOID)p, Owend, hFile);//ӳ����󽻸�Instance���� map object is managed by Instance
            return ret;
        }
        template<class... Args>
        INLINE static Instance<T> CreateInstance(InstanceManger* thisinstance, Args&&... args) {
            std::atomic_bool Owend = false;
            HANDLE hFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, GetMapName<T>().c_str());
            if (!hFile) {
                // �����ļ�ӳ�� Create file mapping
                hFile = CreateFileMappingA(
                    INVALID_HANDLE_VALUE, // ʹ��ϵͳ��ҳ�ļ�   use system paging file
                    NULL,                 // Ĭ�ϰ�ȫ����   default security attributes
                    PAGE_READWRITE,       // ��дȨ��   read/write access
                    0,                    // �������С����λ��   maximum object size (high-order DWORD)
                    sizeof(T),            // �������С����λ��   maximum object size (low-order DWORD)
                    GetMapName<T>().c_str()); // ӳ���������� map object name
                Owend = true;
            }
            if (!hFile) {
                throw std::runtime_error("CreateFileMappingA failed with error code: " + std::to_string(GetLastError()));
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
        return InstanceManger<T>::CreateInstance(&thisinstance);
    }
    template<class T, class... Args>
    INLINE decltype(auto) SingleInstance(Args&&... args)NOEXCEPT {
        InstanceManger<T> thisinstance;
        return InstanceManger<T>::CreateInstance(&thisinstance, args...);
    }
    #define INLINE inline
    #define NOEXCEPT noexcept
    #define DELETE_COPYMOVE_CONSTRUCTOR(TYPE) TYPE(const TYPE&) = delete; TYPE(TYPE&&) = delete; void operator= (const TYPE&) = delete; void operator= (TYPE&&) = delete;
    template<class T>
    class InstanceMangerBase {
        std::vector<T*> instances;//ӳ���ָ�� map pointer
        std::vector<HANDLE> handles;//��� handle
    public:
        static InstanceMangerBase& GetInstance() {//�����Ǵ������ĵ���ģʽ,������ڵ��� singleton mode is convenient for later call
            static InstanceMangerBase instance;
            return instance;
        }
        ~InstanceMangerBase() {//������ʱ�ͷ����о���Ͷ��� free all handle and object when destruct
            Clear();
            RemoveHandle();
        }
        INLINE void InsertObj(T* obj) {
            instances.emplace_back(obj);
        }
        INLINE void InsertHandle(HANDLE handle) {
            handles.emplace_back(handle);
        }
        INLINE void RemoveHandle()NOEXCEPT {
            // ��������������   sort vector
            std::sort(handles.begin(), handles.end());

            // ʹ�� std::unique �Ƴ����ڵ��ظ�Ԫ��  use std::unique to remove adjacent duplicate elements
            handles.erase(std::unique(handles.begin(), handles.end()), handles.end());
            //�رվ��  close handle
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
        DELETE_COPYMOVE_CONSTRUCTOR(SingleTon)//ɾ���������캯���Ϳ�����ֵ���� delete copy constructor and copy assignment
            static INLINE T* CreateInstance() NOEXCEPT {
            auto obj = SingleInstance<T>();
            auto objptr = obj.get();
            InstanceMangerBase<T>::GetInstance().InsertObj(objptr);//���ӳ������ָ�� get map object pointer
            InstanceMangerBase<T>::GetInstance().InsertHandle(obj.hFile);//���ӳ�����ľ�� get map object handle
            return objptr;
        }//����һ�����ʵ�� create a instance of class
        template <class... Args>
        INLINE static INLINE T* CreateInstance(Args&& ...args) NOEXCEPT {
            auto obj = SingleInstance<T>(std::forward<Args>(args)...);
            auto objptr = obj.get();
            InstanceMangerBase<T>::GetInstance().InsertObj(objptr);
            InstanceMangerBase<T>::GetInstance().InsertHandle(obj.hFile);
            return objptr;
        }
        template <class... Args>
        INLINE static T& GetInstanceImpl(Args&& ...args) NOEXCEPT {
            static std::once_flag flag{};
            static T* instance = nullptr;
            if (!instance) {
                std::call_once(flag, [&]() {//call once   ֻ����һ��
                    instance = CreateInstance(args...);//element constructor through parameters    ͨ����������Ԫ��
                    });
            }
            return *instance;
        }
        INLINE static T& GetInstanceImpl() NOEXCEPT {
            static std::once_flag flag{};
            static T* instance = nullptr;
            if (!instance) {
                std::call_once(flag, [&]() {//call once  ֻ����һ��
                    instance = CreateInstance();//element constructor through parameters    ͨ����������Ԫ��
                    });
            }
            return *instance;
        }
    public:
        SingleTon() = default;
        template <class... Args>
        INLINE static T& GetInstance(Args&& ...args) NOEXCEPT {
            return GetInstanceImpl(std::forward<Args>(args)...);
        }
        static T* GetInstancePtr() NOEXCEPT {
            return &GetInstanceImpl();
        }
    };
    //debugoutput
    template<class T>
    void DebugOutput(const T& t) {
        //תΪ�ַ���    convert to string
        std::stringstream ss;
        ss << t;
        OutputDebugStringA(ss.str().c_str());
    }
    class FreeBlock {//���п� free block
    public:
        size_t size;//��С size
        void* ptr;  //ָ�� pointer
        FreeBlock* next;//��һ���� next block ��ʵ����һ������ actually is a linked list
    };
    INLINE BOOL VirtualFreeExApi(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) NOEXCEPT {//Զ���ͷ��ڴ� remote free memory
        return VirtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType);//ϵͳ�� VirtualFreeEx  system VirtualFreeEx
    }
    INLINE LPVOID VirtualAllocExApi(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) NOEXCEPT {//�������Զ���ͷ��ڴ溯�� the most basic remote free memory function ���������Ϊ0x1000  allocate granularity is 0x1000
        return VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);// ϵͳ�� VirtualAllocEx  system VirtualAllocEx
    }
    constexpr DWORD CacheMinTTL = 128;
    constexpr DWORD CacheNormalTTL = 200;
    constexpr DWORD CacheMaxTTL = 4096;
    template<class T>
    struct RangeCmp {//�º���   functor
        INLINE bool operator()(const std::pair<T, T>& p1, const std::pair<T, T>& p2)const {
            if (p1.first >= p2.first) return false;
            return p1.second < p2.second;
        }
    };
    class FastMutex {
        CRITICAL_SECTION g_cs;
    public:
        FastMutex() { InitializeCriticalSection(&g_cs); }
        INLINE CRITICAL_SECTION& Get()NOEXCEPT { return g_cs; }
        ~FastMutex() { DeleteCriticalSection(&g_cs); }
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
        INLINE bool IsValid(timepoint now)NOEXCEPT { return now < m_endtime; }
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
        SimpleRangeCache() { srand((unsigned int)time(0)); }
        ~SimpleRangeCache()noexcept { Clear(); }
        INLINE  void AsyncAddCache(const keyType& _key, const _Ty& _value, DWORD _validtime) NOEXCEPT {
            auto future = std::async(std::launch::async, [&]()->void {
                auto nowTime = std::chrono::system_clock::now();
                auto newValue = CacheItem<_Ty>(_value, nowTime + std::chrono::milliseconds(_validtime + rand() % 30));
                auto lb = m_Cache.find(_key);
                if (lb != m_Cache.end()) {
                    lb->second = newValue;
                }
                else {
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
        INLINE  std::pair<iterator, bool> find(const _Tx& value)NOEXCEPT {
            keyType _key = keyType(value, value);
            if (m_Cache.empty()) return { iterator(),false };
            auto iter = m_Cache.find(_key);
            EnterCriticalSection(&lock.Get());
            bool IsValidItem = iter->second.IsValid(std::chrono::system_clock::now());
            LeaveCriticalSection(&lock.Get());
            return { iter, iter != m_Cache.end() && IsValidItem };
        }
        INLINE  std::pair<iterator, bool> operator[](_Tx&& value)NOEXCEPT {
            return find(value);
        }
        INLINE  void erase(const _Tx& value)NOEXCEPT {//ɾ������    delete cache
            keyType& _key = keyType(value, value);
            if (m_Cache.empty()) return;
            auto iter = m_Cache.find(_key);
            EnterCriticalSection(&lock.Get());
            if (iter != m_Cache.end()) m_Cache.erase(iter);
            LeaveCriticalSection(&lock.Get());
        }
        INLINE  void Clear()NOEXCEPT {
            EnterCriticalSection(&lock.Get());
            m_Cache.clear();
            LeaveCriticalSection(&lock.Get());
        }
    };
    constexpr INLINE  bool CheckMask(const DWORD value, const DWORD mask)NOEXCEPT {//�ж�vakue��mask�Ƿ����    judge whether value and mask is equal
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
        }
        else {
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

        return VirtualQueryCacheApi(hProcess, (LPVOID)lpAddress, lpBuffer);//ϵͳ�� VirtualQueryEx  system
    }
    //���п����� free block list
    class FreeBlockList :public SingleTon<FreeBlockList> {//����ģʽ������ڵ��� singleton mode is convenient for later call
    public:
        FreeBlockList(HANDLE hprocess = GetCurrentProcess()) : m_head(nullptr) {
            m_hProcess = hprocess;
        }
        ~FreeBlockList() {//������ʱ�ͷ����п��п� free all free block when destruct
            auto block = m_head;
            while (block) {
                auto next = block->next;
                if (m_hProcess)VirtualFreeExApi(m_hProcess, block->ptr, block->size, MEM_RELEASE);
                delete block;
                block = next;
            }
            g_allocMap.clear();
        }
        INLINE void Add(void* ptr, size_t size) NOEXCEPT {//����һ�����п� add a free block
            auto block = new FreeBlock();
            block->ptr = ptr;
            block->size = size;
            block->next = m_head;
            m_head = block;
        }
        INLINE void* Get(size_t size)NOEXCEPT {//���һ�����п� get a free block
            if (size <= 0) return nullptr;
            auto p = &m_head;
            while (*p) {
                if ((*p)->size >= size) {
                    auto block = *p;
                    if (block->size > size) {
                        // �����Ĵ�С��������Ĵ�С����ô������Ҫ�ָ������ if block size is greater than requested size, we need to split this block
                        auto newBlock = new FreeBlock();
                        newBlock->ptr = (char*)block->ptr + size;
                        newBlock->size = block->size - size;
                        newBlock->next = block->next;
                        *p = newBlock;
                    }
                    else {
                        // ��������ֻ��ɾ������� delete this block
                        *p = block->next;
                    }
                    return block->ptr;
                }
                p = &(*p)->next;
            }
            // ���û���ҵ��㹻��Ŀ飬��ô������Ҫ��ϵͳ���������ڴ� get more memory from system if not found enough memory
            auto allocSize = (size > PAGESIZE) ? size : PAGESIZE;
            LPVOID ptr = NULL;
            if (m_hProcess)ptr = VirtualAllocExApi(m_hProcess, nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);//����ϵͳ��api�����ڴ� call system api to allocate memory
            if (ptr == nullptr) {
                std::cerr << "VirtualAlloc failed." << std::endl;
                return nullptr;
            }
            Add(ptr, allocSize);//���뵽���п����� add to free block list
            return Get(size);  // ���³��Ի�ȡ�ڴ� get memory again
        }
        INLINE void Free(void* ptr, size_t size)NOEXCEPT {
            //��allocatebase
            MEMORY_BASIC_INFORMATION mbi{};
            VirtualQueryExApi(m_hProcess, ptr, &mbi, sizeof(mbi));
            //�ϲ�������������allcatebase��ͬ�Ŀ�
            auto p = &m_head;
            while (*p) {
                auto allocatebase = mbi.AllocationBase;
                if ((*p)->ptr == allocatebase) {
                    //�ϲ�size������
                    auto block = *p;
                    block->size += size;//�ϲ�size������
                    break;
                }
                p = &(*p)->next;//��һ���� next block
            }
            //�ͷ��ڴ� free memory  
            //��������������������ڵĿ飬��ô�ϲ���������    traverse free block list,if there is adjacent block,then merge these two block
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
            //������п�Ĵ�С����PAGESIZE����ô�ͷ��ڴ�    if free block size is greater than PAGESIZE,then free memory
            p = &m_head;
            while (*p) {
                auto block = *p;
                auto next = block->next;
                if (block->size > PAGESIZE) {
                    if (m_hProcess)VirtualFreeExApi(m_hProcess, block->ptr, block->size, MEM_DECOMMIT);
                    *p = next;
                    delete block;
                }
                p = &(*p)->next;
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
        std::unordered_map<void*, size_t> g_allocMap;//��¼��ÿ������ȥ���ڴ��С record the size of each block of allocated memory
        FreeBlock* m_head;
        GenericHandle<HANDLE, HandleView<NormalHandle>> m_hProcess;//HandleView �����ͼ,������رվ�� HandleView handle view,not responsible for closing handle
    };
    INLINE void* mallocex(GenericHandle<HANDLE, HandleView<NormalHandle>> hProcess, size_t size) {
        void* ptr = nullptr;
        if(hProcess)ptr=FreeBlockList::GetInstance(hProcess).mallocex(size);//���õ���ģʽ�ĺ��� call singleton function
        return ptr;
    }
    INLINE void freeex(GenericHandle<HANDLE, HandleView<NormalHandle>> hProcess, void* ptr) {
        return FreeBlockList::GetInstance(hProcess).freeex(ptr);   //���õ���ģʽ�ĺ��� call singleton function
    }
    class Shared_Ptr {//һ���ⲿ�̵߳�����ָ��,�����ü���Ϊ0ʱ�ͷ��ڴ� a smart pointer of external thread,release memory when reference count is 0
        GenericHandle<HANDLE, HandleView<NormalHandle>> m_hProcess;//�������� ���̾������һ����ͼ,������رս��̾�� not hold process handle but a HandleView,not responsible for closing process handle
        LPVOID BaseAddress = nullptr;
        int refCount = 0;
        void AddRef() NOEXCEPT {
            refCount++;
        }
        INLINE uintptr_t _AllocMemApi(SIZE_T dwSize) NOEXCEPT {//Զ�̷����ڴ� remote allocate memory
            return (uintptr_t)mallocex((HANDLE)m_hProcess, dwSize);
        }
        INLINE bool _FreeMemApi(LPVOID lpAddress) NOEXCEPT {//Զ���ͷ��ڴ� remote free memory
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
            AddRef();//�½�һ��ָ�����ü�����һ reference count plus one means a new pointer points to this memory
            BaseAddress = (LPVOID)_AllocMemApi(sizeof(T));
        }
        INLINE Shared_Ptr(size_t nsize, HANDLE hProc) :m_hProcess(hProc) {
            AddRef();//���ü�����һ˵����һ���µ�ָ��ָ��������ڴ� reference count plus one means a new pointer points to this memory
            BaseAddress = (LPVOID)_AllocMemApi(nsize);
        }
        INLINE Shared_Ptr(const Shared_Ptr& other) : BaseAddress(other.BaseAddress), refCount(other.refCount) {
            AddRef();//���ü�����һ˵����һ���µ�ָ��ָ��������ڴ� reference count plus one means a new pointer points to this memory
        }
        INLINE Shared_Ptr& operator=(const Shared_Ptr& other) NOEXCEPT {//copy assignment   ������ֵ
            if (this != &other) {
                Release();
                BaseAddress = other.BaseAddress;
                refCount = other.refCount;
                AddRef();//���ü�����һ˵����һ���µ�ָ��ָ��������ڴ� reference count plus one means a new pointer points to this memory
            }
            return *this;
        }
        INLINE Shared_Ptr(Shared_Ptr&& other) NOEXCEPT {//move construct  �ƶ�����
            BaseAddress = other.BaseAddress;
            refCount = other.refCount;
            other.BaseAddress = nullptr;//����ԭ����ָ��Ͳ����ͷ��ڴ��� so the original pointer will not release memory
            other.refCount = 0;
        }
        INLINE LPVOID get() NOEXCEPT {//���ָ�뵫���������ü��� get pointer but increase reference count
            AddRef();
            return BaseAddress;
        }
        INLINE LPVOID raw() const NOEXCEPT { return BaseAddress; }//���������ü����Ļ�ȡrawָ�� get raw pointer 
        INLINE ~Shared_Ptr() NOEXCEPT { Release(); }
        INLINE void Release() NOEXCEPT {//release and refCount-- ���ü�����һ
            refCount--;
            if (BaseAddress && refCount <= 0) {
                _FreeMemApi(BaseAddress);//�ͷ��ڴ� free memory ֻ�ǹ黹�ռ䵽���п����� return space to free block list
                BaseAddress = nullptr;
            }
        }
        INLINE operator bool() NOEXCEPT { return BaseAddress != nullptr; }
        //�е�
        INLINE bool operator==(const Shared_Ptr& other) NOEXCEPT { return BaseAddress == other.BaseAddress; }
        //�в���
        INLINE bool operator!=(const Shared_Ptr& other) NOEXCEPT { return BaseAddress != other.BaseAddress; }
    };
    template<class T>Shared_Ptr make_Shared(size_t nsize, HANDLE hprocess) NOEXCEPT { return Shared_Ptr(sizeof(T) * nsize, hprocess); }
    template<class BinFunc>
    INLINE size_t GetFunctionSize(const BinFunc& func) NOEXCEPT {//��ȡ������С,��������̸֮ get function size,just experience
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
    template<class T>struct has_type<T, T> { static constexpr bool value = true; }; //same type ͬ���� check multiple type ���������
    template<class T1, class ...Args>constexpr bool has_type_v = has_type<T1, Args...>::value;
    template<typename T>struct remove_const_pointer { using type = typename std::remove_pointer<std::remove_const_t<T>>::type; };//remove const pointer  �Ƴ�constָ��
    template<typename T> using remove_const_pointer_t = typename remove_const_pointer<T>::type;//remove const pointer   �Ƴ�constָ��
    template<class Tx, class Ty> INLINE bool _ucsicmp(const Tx* str1, const Ty* str2) NOEXCEPT {//ignore case compare ignore type wchar_t wstring or char string ���Դ�Сд�Ƚ� ��������wchar_t wstring����char string
        if (!str1 || !str2) throw std::exception("str1 or str2 is nullptr");
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
        std::transform(wstr1.begin(), wstr1.end(), wstr1.begin(), towlower);//transform to lower ת��ΪСд
        std::transform(wstr2.begin(), wstr2.end(), wstr2.begin(), towlower);//transform to lower    ת��ΪСд
        return wstr1.compare(wstr2) == 0;//������������дʲô������ȷ��,������0,��Ϊcompare����0��ʾ��� easy to forget what to write here is correct,here is 0,because compare return 0 means equal
    }
    enum class EnumStatus {
        Continue,
        Break
    };
    //����ԭʼ�Ķ��뷽ʽ save original align
    #pragma pack(push)
    #pragma pack(1)
    template<class Fn, class T>
    class ThreadDataBase {
    public:
        Fn fn;//function    ����
        char eventname[MAX_PATH];
        char funcname[4][MAX_PATH];
        LPVOID pFunc[2];
    };
    template<class Fn, class T>
    class ThreadData :public ThreadDataBase<Fn, T> {
    public:
        T retdata;//return data ����ֵ
    };
    template <class Fn>
    class ThreadData<Fn, void> :public ThreadDataBase<Fn, void> {//�ػ�������ֵΪvoid����� specialize when return value is void
    public:
    };
    template <class Fn, class T, class ...Args>
    class ThreadData2 :public ThreadData<Fn, T> {//Thread Data Struct inherit from ThreadData   �߳����ݽṹ�̳���ThreadData
    public://�����T����Ϊ��void��ѡ��ThreadData<Fn, void> T here will use ThreadData<Fn, void> because it is void
        std::tuple<Args...> params;//parameters   ���� ���������tuple�洢 multiple parameters use tuple to store
    };
    #pragma pack(pop)//�ָ�ԭʼpack restore original pack   
    //���庯��ָ�� define function pointer
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
        //ͨ�����ִ򿪶�Ӧ���¼� open event by name �����Ѿ����ȶ���� name is defined in advance
        auto pOpenEventA = (POPENEVENTA)pGetProAddress(ntdll, threadData->funcname[1]);//����OpenEventA    load OpenEventA
        auto hEventHandle = pOpenEventA(EVENT_ALL_ACCESS, FALSE, threadData->eventname); //���¼�  open event
        auto pSetEvent = (PSETEVENT)pGetProAddress(ntdll, threadData->funcname[2]);//�����¼�  set event
        pSetEvent(hEventHandle);
        auto pCloseHandle = (PCLOSEHANDLE)pGetProAddress(ntdll, threadData->funcname[3]);//�رվ��  close handle
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
        auto pOpenEventA = (POPENEVENTA)pGetProAddress(ntdll, threadData->funcname[1]);    //����OpenEventA    load OpenEventA
        auto hEventHandle = pOpenEventA(EVENT_ALL_ACCESS, FALSE, threadData->eventname);    //���¼�  open event
        auto pSetEvent = (PSETEVENT)pGetProAddress(ntdll, threadData->funcname[2]);    //�����¼�  set event
        pSetEvent(hEventHandle);
        auto pCloseHandle = (PCLOSEHANDLE)pGetProAddress(ntdll, threadData->funcname[3]);//�رվ��  close handle
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
        auto pOpenEventA = (POPENEVENTA)pGetProAddress(ntdll, threadData->funcname[1]);        //����OpenEventA    load OpenEventA
        auto hEventHandle = pOpenEventA(EVENT_ALL_ACCESS, FALSE, threadData->eventname);        //���¼�  open event
        auto pSetEvent = (PSETEVENT)pGetProAddress(ntdll, threadData->funcname[2]);        //�����¼�  set event
        pSetEvent(hEventHandle);
        auto pCloseHandle = (PCLOSEHANDLE)pGetProAddress(ntdll, threadData->funcname[3]);//�رվ��  close handle
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
        auto pOpenEventA = (POPENEVENTA)pGetProAddress(ntdll, threadData->funcname[1]);        //����OpenEventA    load OpenEventA
        auto hEventHandle = pOpenEventA(EVENT_ALL_ACCESS, FALSE, threadData->eventname);        //���¼�  open event
        auto pSetEvent = (PSETEVENT)pGetProAddress(ntdll, threadData->funcname[2]);       //�����¼�  set event
        pSetEvent(hEventHandle);
        auto pCloseHandle = (PCLOSEHANDLE)pGetProAddress(ntdll, threadData->funcname[3]);//�رվ��  close handle
        pCloseHandle(hEventHandle);
    }
    //����������<���������>�йؽٳ��߳�ע��Ĵ��� ��473ҳ code from <���������> about thread hijacking inject page 473
    typedef class DATA_CONTEXT {
    public:
        BYTE ShellCode[0x30];				//x64:0X00   |->x86:0x00
        LPVOID pFunction;				    //x64:0X30	 |->x86:0x30
        PBYTE lpParameter;					//x64:0X38	 |->x86:0x34
        LPVOID OriginalEip;					//x64:0X40	 |->x86:0x38
    }*PINJECT_DATA_CONTEXT;
    #if defined _WIN64
    INLINE BYTE ContextInjectShell[] = {			//x64.asm ���в�û�и���x64�Ĵ���,���������Լ�д��  the book does not give the code of x64,here is my own code
        0x50,								//push	rax
        0x53,								//push	rbx
        0x9c,								//pushfq							//����flag�Ĵ���    save flag register
        0xe8,0x00,0x00,0x00,0x00,			//call	next
        0x5b,								//pop	rbx
        0x48,0x83,0xeb,0x08,				//sub	rbx,08
        0x51,								//push	rcx	
        0x48,0x83,0xEC,0x28,				//sub	rsp,0x28					//Ϊcall �Ĳ�������ռ� allocate space for call parameter
        0x48,0x8b,0x4b,0x38,				//mov	rcx,[rbx+0x38]				//lparam ·����ַ   lparam address
        0xff,0x53,0x30,						//call	qword ptr[rbx+0x30]			//call threadproc   call threadproc
        0x48,0x83,0xc4,0x28,				//add	rsp,0x28					//������ʱ�ռ�  undo temporary space
        0x59,								//pop	rcx
        0x48,0x8b,0x43,0x40,				//mov	rax,[rbx+0x40]				//ȡrip��rax    get rip to rax
        0x48,0x87,0x44,0x24,0x24,			//xchg	[rsp+24],rax				
        0x9d,								//popfq								//��ԭ��־�Ĵ���    restore flag register
        0x5b,								//pop	rbx
        0x58,								//pop	rax
        0xc3,								//retn		
    };
    #else
    INLINE BYTE ContextInjectShell[] = {	//x86.asm ���еĴ���  the code in the book
        0x50,								//push	eax
        0x60,								//pushad
        0x9c,								//pushfd
        0xe8,0x00,0x00,0x00,0x00,			//call	next
        0x5b,								//pop	ebx
        0x83,0xeb,0x08,						//sub	ebx,8
        0x3e,0xff,0x73,0x34,				//push	dword ptr ds:[ebx + 0x34]	//lparam
        0x3e,0xff,0x53,0x30,				//call	dword ptr ds:[ebx + 0x30]	//threadproc
        0x3e,0x8b,0x43,0x38,				//mov	eax,dword ptr ds:[ebx+0x38]	//ȡEIP��eax    get eip to eax
        0x87,0x44,0x24,0x24,				//xchg	eax,[esp+0x24]
        0x9d,								//popfd
        0x61,								//popad
        0xc3								//retn
    };
    #endif
    class Thread {//���̵߳�������������  process thread as object
        GenericHandle<HANDLE, NormalHandle> m_GenericHandleThread;//�������ܾ��  use smart handle
        DWORD m_dwThreadId = 0;
        std::atomic_bool m_bAttached = false;
    public:
        Thread() = default;
        Thread(DWORD dwThreadId) NOEXCEPT {    //���߳� open thread
            m_dwThreadId = dwThreadId;
            m_GenericHandleThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_dwThreadId);
            if (m_GenericHandleThread)m_bAttached = true;
        }
        Thread(const THREADENTRY32& threadEntry) NOEXCEPT {   //��threadentry32���� construct from threadentry32  to open thread
            m_dwThreadId = threadEntry.th32ThreadID;
            m_GenericHandleThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_dwThreadId);
            if (m_GenericHandleThread)m_bAttached = true;
        }
        Thread(Thread&& other) NOEXCEPT {    //�ƶ�����  move construct
            m_GenericHandleThread = std::move(other.m_GenericHandleThread);
            m_dwThreadId = other.m_dwThreadId;
            bool Attached = other.m_bAttached;
            m_bAttached = Attached;
            other.m_dwThreadId = 0;
            other.m_bAttached = false;
        }
        Thread& operator=(Thread&& other) NOEXCEPT {    //�ƶ���ֵ move assignment
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
        HANDLE GetHandle() NOEXCEPT { return m_GenericHandleThread; }//��ȡ�߳̾��  get thread handle
        operator bool() { return IsRunning(); }
        bool IsRunning() NOEXCEPT {
            //��ȡ�߳��˳�����  get thread exit code
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
        //��ȡ�߳�������  get thread context
        CONTEXT GetContext() NOEXCEPT {
            CONTEXT context = {};
            if (m_bAttached) {
                context.ContextFlags = CONTEXT_FULL;
                GetThreadContext(GetHandle(), &context);
            }
            return context;
        }
        //�����̵߳�������  set thread context
        void SetContext(const CONTEXT& context) NOEXCEPT {
            if (m_bAttached) {
                SetThreadContext(GetHandle(), &context);
            }
        }
        //��ͣ�߳�ִ��  suspend thread execution
        void Suspend() NOEXCEPT {
            if (m_bAttached) {
                SuspendThread(GetHandle());
            }
        }
        //�ָ��߳�ִ��  resume thread execution
        void Resume() NOEXCEPT {
            if (m_bAttached) {
                ResumeThread(GetHandle());
            }
        }
    };
    template <typename T>
    class ThreadSafeVector {//�̰߳�ȫ��vector thread safe vector
        std::mutex m_mutex; //lock for vector
        std::vector<T> m_vector;
    public:
        //�ۺϳ�ʼ��    aggregate initialization
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
        //emplace back  ֱ����vector�й������ construct object in vector directly
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
        //data  ֱ�ӷ���vector��data return vector data directly
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
    class Process :public SingleTon<Process> {//Singleton   ����
        GenericHandle<HANDLE, NormalHandle> m_hProcess;
        DWORD m_pid;//process id    ����id
        EnumRunningMode m_RunningMode = EnumRunningMode::POINTER_READ;
        std::atomic_bool m_bAttached;//atomic bool  ԭ��bool
        ThreadSafeVector<Shared_Ptr> m_vecAllocMem;//vector for allocated memory    ���������ڴ��vector
        std::unordered_map<LPVOID, LPVOID> maptoorigin;//map for save original address and allocated address, key is allocated address value is original address    ����ԭʼ��ַ�ͷ����ַ��map��key�Ƿ����ַ��value��ԭʼ��ַ
        template<typename T, typename ...Args>
        INLINE void preprocess(T& arg, Args&...args) NOEXCEPT {//partially specialized template �����ػ�ģ��
            if constexpr (has_type_v<T, const char*, const wchar_t*>) preprocessparameter(arg);
            if constexpr (std::is_pointer_v<T> && !has_type_v<T, LPVOID, LPCVOID, const char*, const wchar_t*>)ProcessPtr(arg);
            if constexpr (sizeof...(args) > 0)preprocess(args...);
        }
        template<class T, typename ...Args>
        INLINE void postprocess(T& arg, Args&...args) NOEXCEPT {
            if (std::is_pointer_v<T> && !std::is_same_v<T, LPVOID> && !std::is_same_v<T, LPCVOID>)PostprocessPtr(arg);//post process pointer    ����ָ��
            if constexpr (sizeof...(args) > 0)postprocess(args...);//keep process   ��������
        }
        template<typename T>
        INLINE void PostprocessPtr(T& ptr) NOEXCEPT {
            auto iter = maptoorigin.find((LPVOID)ptr);//find original address   ����ԭʼ��ַ
            if (iter != maptoorigin.end()) {
                LPVOID OriginAddr = iter->second;//original address   ԭʼ��ַ
                if (m_RunningMode == EnumRunningMode::POINTER_READ) {
                    _ReadApi((LPVOID)ptr, OriginAddr, sizeof(T));//read value from allocated address to original address    �ӷ����ַ��ȡֵ��ԭʼ��ַ
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
        }//process const char* parameter    ����const char*����
        INLINE void preprocessparameter(const wchar_t*& arg) {
            auto nlen = (int)wcslen(arg) + 1;
            auto p = make_Shared<wchar_t>(nlen * sizeof(wchar_t), m_hProcess);
            if (p) {
                m_vecAllocMem.push_back(p);
                _WriteApi((LPVOID)p.get(), (LPVOID)arg, nlen * sizeof(wchar_t));
                arg = (const wchar_t*)p.raw();
            }
        }//process const wchar_t* parameter   ����const wchar_t*����
        template<typename T>
        INLINE void ProcessPtr(T& ptr) NOEXCEPT {
            if (ptr) {
                int Size = sizeof(T);//get size of parameter    ��ȡ������С
                auto p = make_Shared<BYTE>(Size, m_hProcess);
                if (p) {
                    m_vecAllocMem.emplace_back(p);//emplace back into vector avoid memory leak can be clear through clearmemory   emplace back��vector�б����ڴ�й©����ͨ��clearmemory���
                    _WriteApi(p.get(), (LPVOID)ptr, Size);//write value to allocated address for parameter is pointer   д��ֵ�������ַ����Ϊ������ָ��
                    if (m_RunningMode == EnumRunningMode::POINTER_READ)maptoorigin.insert(std::make_pair((LPVOID)p.raw(), (LPVOID)ptr));//save original address and allocated address   ����ԭʼ��ַ�ͷ����ַ
                    ptr = (T)p.raw();//set parameter to allocated address   ���ò���Ϊ�����ַ
                }
            }
        }
    public:
        INLINE void Attach(const char* _szProcessName) NOEXCEPT {//attach process   ���ӽ���
            //get process id    ��ȡ����id
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
        INLINE void EnumThread(PRE pre) NOEXCEPT {//enum thread through snapshot    ͨ������ö���߳�
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
        template<class _Fn, class ...Arg>
        decltype(auto) SetContextCallImpl(__in _Fn&& _Fx, __in Arg ...args) NOEXCEPT {
            using RetType = std::common_type<decltype(_Fx(args...))>::type;//return type is common type or not
            if (!m_bAttached) return RetType();
            uintptr_t _paramAddr = 0;
            ThreadData2<std::decay_t<_Fn>, RetType, std::decay_t<Arg>...> threadData;
            strcpy_s(threadData.eventname, "SetContextCallImpl");//event name
            strcpy_s(threadData.funcname[0], "kernel32.dll");//kernel32.dll
            strcpy_s(threadData.funcname[1], "OpenEventA");//OpenEventA
            strcpy_s(threadData.funcname[2], "SetEvent");//SetEvent
            strcpy_s(threadData.funcname[3], "CloseHandle");//CloseHandle
            //�����¼�  create event
            GenericHandle<HANDLE, NormalHandle> hEvent = CreateEventA(NULL, FALSE, FALSE, threadData.eventname);
            if (hEvent) {
                threadData.pFunc[0] = (LPVOID)LoadLibraryA;
                threadData.pFunc[1] = (LPVOID)GetProcAddress;
                EnumThread([&](auto& te32)->EnumStatus {
                    auto thread = Thread(te32);//construct thread   �����߳�
                    thread.Suspend();//suspend thread   ��ͣ�߳�
                    auto ctx = thread.GetContext();//get context    ��ȡ������
                    auto lpShell = make_Shared<DATA_CONTEXT>(1, m_hProcess);//allocate memory   �����ڴ�
                    m_vecAllocMem.emplace_back(lpShell);//
                    DATA_CONTEXT dataContext{};
                    memcpy(dataContext.ShellCode, ContextInjectShell, sizeof(ContextInjectShell));
                    if constexpr (sizeof...(args) > 0) preprocess(args...);//process parameter  �������
                    threadData.fn = _Fx;
                    threadData.params = std::tuple(std::forward<Arg>(args)...);//tuple parameters   tuple����
                    auto pFunction = &ThreadFunction2<std::decay_t<_Fn>, RetType, std::decay_t<Arg>...>;//get function address  ��ȡ������ַ
                    auto length = GetFunctionSize((BYTE*)pFunction);//get function length    ��ȡ��������
                    auto lpFunction = make_Shared<BYTE>(length, m_hProcess);//allocate memory for function  �����ڴ�
                    m_vecAllocMem.emplace_back(lpFunction);//push back to vector for free memory    push back��vector�����ͷ��ڴ�
                    _WriteApi((LPVOID)lpFunction.get(), (LPVOID)pFunction, length);//write function to memory   д�뺯�����ڴ�
                    dataContext.pFunction = (LPVOID)lpFunction.raw();//set function address  ���ú�����ַ
                    dataContext.OriginalEip = (LPVOID)ctx.XIP;//set original eip    ����ԭʼeip
                    using parametertype = decltype(threadData);
                    auto lpParameter = make_Shared<parametertype>(1, m_hProcess);//allocate memory for parameter    �����ڴ�
                    m_vecAllocMem.emplace_back(lpParameter);//push back to vector for free memory   push back��vector�����ͷ��ڴ�
                    _WriteApi((LPVOID)lpParameter.get(), &threadData, sizeof(parametertype));//write parameter  д�����
                    dataContext.lpParameter = (PBYTE)lpParameter.raw();//set parameter address  ���ò�����ַ
                    _paramAddr = (uintptr_t)lpParameter.raw();//set parameter address  ���ò�����ַ
                    ctx.XIP = (uintptr_t)lpShell.raw();//set xip   ����xip
                    _WriteApi((LPVOID)lpShell.get(), &dataContext, sizeof(DATA_CONTEXT));//write datacontext    д��datacontext
                    thread.SetContext(ctx);//set context    ����������
                    thread.Resume();//resume thread   �ָ��߳�
                    return EnumStatus::Break;
                    });
                hEvent.Wait(INFINITE);//wait event
                if (maptoorigin.size() > 0)postprocess(args...);//post process parameter   �������
                maptoorigin.clear();//clear map  ���map
                _ReadApi((LPVOID)_paramAddr, &threadData, sizeof(threadData));//read parameter for return value  ��ȡ�����Է���ֵ
                return threadData.retdata;//return value    ����ֵ
            }
        }
        template <class _Fn>
        INLINE decltype(auto) SetContextCallImpl(_Fn&& _Fx) NOEXCEPT {
            using RetType = std::common_type<decltype(_Fx())>::type;//return type is common type or not ���������ǳ������ͻ��ǲ���
            if (!m_bAttached) return RetType();//return default value   ����Ĭ��ֵ
            uintptr_t _paramAddr = 0;
            ThreadData<std::decay_t<_Fn>, RetType> threadData;//thread data
            strcpy_s(threadData.eventname, "SetContextCallImpl");//event name
            strcpy_s(threadData.funcname[0], "kernel32.dll");//kernel32.dll
            strcpy_s(threadData.funcname[1], "OpenEventA");//OpenEventA
            strcpy_s(threadData.funcname[2], "SetEvent");//SetEvent
            strcpy_s(threadData.funcname[3], "CloseHandle");//CloseHandle
            //�����¼�  create event
            GenericHandle<HANDLE, NormalHandle> hEvent = CreateEventA(NULL, FALSE, FALSE, threadData.eventname);
            threadData.pFunc[0] = (LPVOID)LoadLibraryA;
            threadData.pFunc[1] = (LPVOID)GetProcAddress;
            EnumThread([&](auto& te32)->EnumStatus {
                auto thread = Thread(te32);//construct thread   �����߳�
                thread.Suspend();//suspend thread   ��ͣ�߳�
                auto ctx = thread.GetContext();//get context    ��ȡ������
                auto lpShell = make_Shared<DATA_CONTEXT>(1, m_hProcess);//allocate memory for datacontext   �����ڴ�
                m_vecAllocMem.emplace_back(lpShell);//push back to vector for free memory   push back��vector�����ͷ��ڴ�
                DATA_CONTEXT dataContext{};
                memcpy(dataContext.ShellCode, ContextInjectShell, sizeof(ContextInjectShell));
                threadData.fn = _Fx;
                auto pFunction = &ThreadFunction<std::decay_t<_Fn>, RetType>;//get function address ��ȡ������ַ
                auto length = GetFunctionSize((BYTE*)pFunction);//get function length    ��ȡ��������
                auto lpFunction = make_Shared<BYTE>(length, m_hProcess);//allocate memory for function  �����ڴ�
                m_vecAllocMem.emplace_back(lpFunction);
                _WriteApi((LPVOID)lpFunction.get(), (LPVOID)pFunction, length);//write function to memory   д�뺯�����ڴ�
                dataContext.pFunction = (LPVOID)lpFunction.raw();//set function address ���ú�����ַ
                dataContext.OriginalEip = (LPVOID)ctx.XIP;//set original eip    ����ԭʼeip
                using parametertype = decltype(threadData);//get parameter type  ��ȡ��������
                auto lpParameter = make_Shared<parametertype>(1, m_hProcess);//allocate memory for parameter    �����ڴ�
                m_vecAllocMem.emplace_back(lpParameter);
                _WriteApi((LPVOID)lpParameter.get(), &threadData, sizeof(parametertype));//write parameter to memory    д��������ڴ�
                dataContext.lpParameter = (PBYTE)lpParameter.raw();
                _paramAddr = (uintptr_t)lpParameter.raw();
                ctx.XIP = (uintptr_t)lpShell.raw();//set xip   ����xip
                _WriteApi((LPVOID)lpShell.get(), &dataContext, sizeof(DATA_CONTEXT));//write datacontext to memory  д��datacontext���ڴ�
                thread.SetContext(ctx);//set context    ����������
                thread.Resume();//resume thread  �ָ��߳�
                return EnumStatus::Break;
                });
            hEvent.Wait(INFINITE);//wait event
            _ReadApi((LPVOID)_paramAddr, &threadData, sizeof(threadData));//read parameter for return value ��ȡ�����Է���ֵ
            return threadData.retdata;//return value    ����ֵ
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
            static_assert(!is_callable<decltype(_Fx)>::value, "uncallable!");//����������Ե��� function must be callable
            using RetType = void;
            uintptr_t _paramAddr = 0;
            ThreadData<std::decay_t<_Fn>, RetType> threadData;//thread data
            strcpy_s(threadData.eventname, "SetContextCallImpl");//event name
            strcpy_s(threadData.funcname[0], "kernel32.dll");//kernel32.dll
            strcpy_s(threadData.funcname[1], "OpenEventA");//OpenEventA
            strcpy_s(threadData.funcname[2], "SetEvent");//SetEvent
            strcpy_s(threadData.funcname[3], "CloseHandle");//CloseHandle
            //�����¼�  create event
            GenericHandle<HANDLE, NormalHandle> hEvent = CreateEventA(NULL, FALSE, FALSE, threadData.eventname);
            if (hEvent) {
                threadData.pFunc[0] = (LPVOID)LoadLibraryA;
                threadData.pFunc[1] = (LPVOID)GetProcAddress;
                EnumThread([&](auto& te32)->EnumStatus {
                    auto thread = Thread(te32);//construct thread   �����߳�
                    thread.Suspend();//suspend thread   ��ͣ�߳�
                    auto ctx = thread.GetContext();//get context    ��ȡ������
                    auto lpShell = make_Shared<DATA_CONTEXT>(1, m_hProcess);//allocate memory for datacontext   �����ڴ�
                    m_vecAllocMem.emplace_back(lpShell);//push back to vector for free memory   push back��vector�����ͷ��ڴ�
                    DATA_CONTEXT dataContext{};
                    memcpy(dataContext.ShellCode, ContextInjectShell, sizeof(ContextInjectShell));
                    threadData.fn = _Fx;
                    auto pFunction = &ThreadFunctionNoReturn<std::decay_t<_Fn>, RetType>;//get function address ��ȡ������ַ
                    auto length = GetFunctionSize((BYTE*)pFunction);//get function length    ��ȡ��������
                    auto lpFunction = make_Shared<BYTE>(length, m_hProcess);//allocate memory for function  �����ڴ�
                    m_vecAllocMem.emplace_back(lpFunction);
                    _WriteApi((LPVOID)lpFunction.get(), (LPVOID)pFunction, length);//write function to memory   д�뺯�����ڴ�
                    dataContext.pFunction = (LPVOID)lpFunction.raw();//set function address
                    dataContext.OriginalEip = (LPVOID)ctx.XIP;//set original eip
                    using parametertype = decltype(threadData);//get parameter type
                    auto lpParameter = make_Shared<parametertype>(1, m_hProcess);//allocate memory for parameter
                    m_vecAllocMem.emplace_back(lpParameter);
                    _WriteApi((LPVOID)lpParameter.get(), &threadData, sizeof(parametertype));//write parameter to memory
                    dataContext.lpParameter = (PBYTE)lpParameter.raw();
                    _paramAddr = (uintptr_t)lpParameter.raw();
                    ctx.XIP = (uintptr_t)lpShell.raw();//set xip
                    _WriteApi((LPVOID)lpShell.get(), &dataContext, sizeof(DATA_CONTEXT));//write datacontext to memory
                    thread.SetContext(ctx);//set context
                    thread.Resume();//resume thread
                    return EnumStatus::Break;
                    });
                hEvent.Wait(INFINITE);//wait event
                ClearMemory();
            }
        }
        template<class _Fn, class ...Arg>
        INLINE void SetContextCallNoReturn(__in _Fn&& _Fx, __in Arg ...args) NOEXCEPT {
            static_assert(!is_callable<decltype(_Fx)>::value, "uncallable!");//����������Ե��� function must be callable
            using RetType = void;
            if (!m_bAttached) return RetType();
            uintptr_t _paramAddr = 0;
            ThreadData2<std::decay_t<_Fn>, RetType, std::decay_t<Arg>...> threadData;
            strcpy_s(threadData.eventname, "SetContextCallImpl");//event name
            strcpy_s(threadData.funcname[0], "kernel32.dll");//kernel32.dll
            strcpy_s(threadData.funcname[1], "OpenEventA");//OpenEventA
            strcpy_s(threadData.funcname[2], "SetEvent");//SetEvent
            strcpy_s(threadData.funcname[3], "CloseHandle");//CloseHandle
            //�����¼�
            GenericHandle<HANDLE, NormalHandle> hEvent = CreateEventA(NULL, FALSE, FALSE, threadData.eventname);
            if (hEvent) {
                //���ú�����ַ
                threadData.pFunc[0] = (LPVOID)LoadLibraryA;
                threadData.pFunc[1] = (LPVOID)GetProcAddress;
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
                    _paramAddr = (uintptr_t)lpParameter.raw();//set parameter address
                    ctx.XIP = (uintptr_t)lpShell.raw();//set xip
                    _WriteApi((LPVOID)lpShell.get(), &dataContext, sizeof(DATA_CONTEXT));//write datacontext
                    thread.SetContext(ctx);//set context
                    thread.Resume();//resume thread
                    return EnumStatus::Break;
                    });
                hEvent.Wait(INFINITE);//wait event
                if (maptoorigin.size() > 0)postprocess(args...);//post process parameter
                maptoorigin.clear();//clear map
                ClearMemory();
            }
        }
        INLINE decltype(auto) SetContextCall(auto&& _Fx, auto&& ...args) NOEXCEPT {
            static_assert(!is_callable<decltype(_Fx)>::value, "uncallable!");//����������Ե��� function must be callable
            auto retdata = SetContextCallImpl(_Fx, args...);//����ֵ���浽retdata return value save to retdata
            using RetType = decltype(retdata);
            std::promise<RetType> promise{};//��ŵ����
            std::future<RetType> fut = promise.get_future();
            promise.set_value(retdata);//���ó�ŵֵ set promise value
            ClearMemory();//����ڴ� clear memory �����ڴ�й© avoid memory leak
            return fut;
        }
        template<class T>
        INLINE static T TONULL() NOEXCEPT { //return null value  ���ؿ�ֵ
            return  reinterpret_cast<T>(0);
        }
    private:
        INLINE DWORD GetProcessIdByName(const char* processName) NOEXCEPT {//get process id by name   ͨ�����ƻ�ȡ����id
            DWORD pid = 0;
            //����GenericHandle��Ϊ�˷�ֹ���ǹرվ������ΪGenericHandle�����������Զ��رվ��Ԥ���ڴ�й©  return GenericHandle is for prevent forget close handle, because GenericHandle destructor will close handle automatically to prevent memory leak
            GenericHandle<HANDLE, NormalHandle> hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot) {
                //PROCESSENTRY32W processEntry = { sizeof(PROCESSENTRY32W), };
                PROCESSENTRY32W processEntry{ sizeof(PROCESSENTRY32W), };
                //����forѭ���������̿��գ�ֱ���ҵ�������ΪprocessName�Ľ��� use for loop to enumerate process snapshot until find process name is processName
                for (auto bRet = Process32FirstW(hSnapshot, &processEntry); bRet; bRet = Process32NextW(hSnapshot, &processEntry)) {
                    //�ȽϽ����� compare process name �����ִ�Сд������char*��wchar_t* case insensitive for char* and wchar_t*
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
        DWORD time1 = clock();
        float count = 0;
        while (count < Times) {
            bin();
            count++;
        }
        float elpstime = clock() - (float)time1;
        auto total = count / (elpstime / 1000.0f);
        printf("Speed: %0.0f/s\r\n", total);
        return total;
    }
}



