#include"SetContextCall.h"
using namespace stc;
//定义一个void类型的函数指针
typedef void(*pFunc)();
int main() {
    auto &process=Process::GetInstance();
    process.Attach("notepad.exe");
    int i = 0;
    while (true)
    {
        process.InitObject
        
    }
    

    

    return 0;
}