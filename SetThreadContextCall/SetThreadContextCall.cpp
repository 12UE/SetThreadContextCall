#include"SetContextCall.h"
using namespace stc;
int main() {
    auto& Process = Process::GetInstance();//get instance   ��ȡʵ��
    Process.Attach("notepad.exe");//attach process  ���ӽ���
    Test_Speed(1e+2, [&]() {
        Process.SetContextCallNoReturn(MessageBoxA, Process::TONULL<HWND>(), "cap", "msg", MB_OK);
    });

    return 0;
}