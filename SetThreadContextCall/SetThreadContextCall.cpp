﻿#include"SetContextCall.h"
using namespace stc;
//定义一个void类型的函数指针
typedef void(*pFunc)();
void startProcessIfNotFound(const char* exeName) {
    // 创建进程快照
    auto findprocess = [&](const char* processName)->bool{
        PROCESSENTRY32W pe32{ sizeof(PROCESSENTRY32W) ,};
        THANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (!hProcessSnap)return false;
        auto found = false;
        for (auto bRet = Process32FirstW(hProcessSnap, &pe32); bRet; bRet = Process32NextW(hProcessSnap, &pe32)) {
            if (_ucsicmp(pe32.szExeFile, processName)) {
                found = true;
                break;
            }
        }
        return found;
    };
    auto found = findprocess(exeName);
    if (!found) {
        while (true) {
            if (!findprocess(exeName)) {
                ShellExecuteA(NULL, "open", exeName, NULL, NULL, SW_SHOWNORMAL);
            }else {
                break;
            }
            Sleep(100);
        }
        std::cout << "sleeped done!" << "\n";
    }else {
        std::cout << "Process " << exeName << " is already running." << std::endl;
    }
}
int main() {
    auto& Process = Process::GetInstance();//get instance
    //判断当前有没有运行记事本
    startProcessIfNotFound("notepad.exe");
    Process.Attach("notepad.exe");//attach process
    Process.SetContextCall(MessageBoxA, Process::TONULL<HWND>(), "cap", "ok", MB_OK);
    std::cout << "done";
    getchar();//程序在这里暂停
    return 0;
}