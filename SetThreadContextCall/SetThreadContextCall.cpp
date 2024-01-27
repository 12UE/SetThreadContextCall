#include"SetContextCall.h"
using namespace stc;
int main() {
    auto& Process = Process::GetInstance();//get instance   获取实例
    Process.Attach("notepad.exe");//attach process  附加进程
    std::cout<<Process.SetContextCall(MessageBoxA,Process::TONULL<HWND>(),"MSG","OK",MB_OK).get();
    

    return 0;
}