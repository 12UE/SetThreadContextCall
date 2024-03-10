#include"SetContextCall.h"
using namespace stc;
//定义一个void类型的函数指针
typedef void(*pFunc)();

int main() {
    auto& Process = Process::GetInstance();//get instance
    //判断当前有没有运行记事本
    startProcessIfNotFound("notepad.exe");
    Process.Attach("notepad.exe");//attach process
    int i = 0;
    while (1) {
        auto ret = Process.SetContextCall(MessageBoxA, Process::TONULL<HWND>(), "OK", "cap", MB_OK);
        std::cout << "return value:" << ret << "times:" << std::dec << ++i << std::endl;
    }
    std::cout << "excute done" << std::endl;
    getchar();
    return 0;
}