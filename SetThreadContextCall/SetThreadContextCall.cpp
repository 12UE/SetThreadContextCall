#include"SetContextCall.h"
using namespace stc;
//����һ��void���͵ĺ���ָ��
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