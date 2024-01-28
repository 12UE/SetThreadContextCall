#include"SetContextCall.h"
using namespace stc;
int main() {
    auto &process=Process::GetInstance();
    process.Attach("notepad.exe");
    int i = 0;
    while (true)
    {
        process.SetContextCallNoReturn(GetCurrentProcessId);
        
    }
    

    

    return 0;
}