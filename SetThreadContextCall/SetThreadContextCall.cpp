#include"SetContextCall.h"
using namespace stc;
//定义一个void类型的函数指针
typedef void(*pFunc)();
int main() {
    auto& Process = Process::GetInstance();//get instance   ťńČĄĘľŔý
    Process.Attach("notepad.exe");//attach process  ¸˝źÓ˝řłĚ
        Process.SetContextCall(MessageBoxA, Process::TONULL<HWND>(), "cap", "ok", MB_OK);
        std::cout << "done";
    return 0;
}