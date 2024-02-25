#include"SetContextCall.h"
using namespace stc;
//定义一个void类型的函数指针
typedef void(*pFunc)();
void startProcessIfNotFound(const wchar_t* exeName) {
    // 创建进程快照
    auto findprocess = [&](const wchar_t* processName)->bool{
        PROCESSENTRY32 pe32{};
        GenericHandle<HANDLE, NormalHandle> hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to create process snapshot." << std::endl;
            return false;
        }

        // 设置结构体大小
        pe32.dwSize = sizeof(PROCESSENTRY32);

        // 获取第一个进程信息
        if (!Process32First(hProcessSnap, &pe32)) {
            std::cerr << "Failed to get process info." << std::endl;
            return false;
        }

        bool found = false;
        // 遍历进程快照，查找指定的exeName
        do {
            if (wcscmp(pe32.szExeFile, exeName) == 0) {
                found = true;
                break;
            }
        } while (Process32Next(hProcessSnap, &pe32));
        return found;
     };
    
    auto found = findprocess(exeName);
    if (!found) {
        ShellExecute(NULL, L"open", exeName, NULL, NULL, SW_SHOWNORMAL);
        Sleep(1000);
        std::cout << "sleeped done!" << "\n";
    }
    else {
        std::wcout << "Process " << exeName << " is already running." << std::endl;
    }
}
int main() {
    auto& Process = Process::GetInstance();//get instance   ťńČĄĘľŔý
    //判断当前有没有运行记事本
    startProcessIfNotFound(L"notepad.exe");

    Process.Attach("notepad.exe");//attach process  ¸˝źÓ˝řłĚ
    while (true) {
        Process.SetContextCall(MessageBoxA, Process::TONULL<HWND>(), "cap", "ok", MB_OK);
    }
    std::cout << "done";
    return 0;
}