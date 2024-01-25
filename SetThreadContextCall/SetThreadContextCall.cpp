#include"SetContextCall.h"
using namespace stc;
int main() {
    auto& Process = Process::GetInstance();//get instance   获取实例
    Process.Attach("notepad.exe");//attach process  附加进程
    Test_Speed(1e+2, [&]() {
        Process.SetContextCallNoReturn(MessageBoxA, Process::TONULL<HWND>(), "cap", "msg", MB_OK);
    });

    return 0;
}