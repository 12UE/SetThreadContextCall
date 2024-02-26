#include"SetContextCall.h"
using namespace stc;
//定义一个void类型的函数指针
typedef void(*pFunc)();

int main() {
    auto& Process = Process::GetInstance();//get instance
    //判断当前有没有运行记事本
    startProcessIfNotFound("notepad.exe");
    Process.Attach("notepad.exe");//attach process
    auto fut=Process.SetContextCall(MessageBoxA, Process::TONULL<HWND>(), "OK", "cap", MB_OK);
    std::cout <<"return value:" << fut.get() << std::endl;
    std::cout << "done";
    getchar();//程序在这里暂停
    return 0;
}