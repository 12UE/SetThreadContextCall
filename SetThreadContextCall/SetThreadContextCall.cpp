#include"SetContextCall.h"
using namespace stc;
int main() {
    auto& Process = Process::GetInstance();//get instance   ��ȡʵ��
    Process.Attach("notepad.exe");//attach process  ���ӽ���
    std::cout<<Process.SetContextCall(MessageBoxA,Process::TONULL<HWND>(),"MSG","OK",MB_OK).get();
    

    return 0;
}