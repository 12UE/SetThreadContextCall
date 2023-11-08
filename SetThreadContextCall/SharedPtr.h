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
    Shared_Ptr(size_t nsize,HANDLE hProc):m_hProcess(hProc) {
        AddRef();
        //virtualallocex
        BaseAddress=(LPVOID)_AllocMemApi(nsize);

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
template<class T>Shared_Ptr make_Shared(size_t nsize,HANDLE hprocess) { return Shared_Ptr(sizeof(T) * nsize,hprocess); }
