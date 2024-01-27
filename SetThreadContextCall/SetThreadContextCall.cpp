#include"SetContextCall.h"
using namespace stc;
int main() {
    auto &process=Process::GetInstance();
    process.Attach("notepad.exe");
    process.SetContextCall(MessageBoxA, Process::TONULL<HWND>(), "OK", "msg", MB_OK);

    

    return 0;
}