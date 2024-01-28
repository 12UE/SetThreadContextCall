#include"SetContextCall.h"
using namespace stc;
int main() {
    auto &process=Process::GetInstance();
    process.Attach("notepad.exe");
    int i = 0;
    while (true)
    {
        process.SetContextCall(MessageBoxA, Process::TONULL<HWND>(), "OK", "msg", MB_OK);
        std::cout<< i++ << std::endl;
    }
    

    

    return 0;
}