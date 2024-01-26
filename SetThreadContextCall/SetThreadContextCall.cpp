#include"SetContextCall.h"
using namespace stc;
//定义ShowMessageBoxTimeout
typedef  int(WINAPI* MessageBoxTimeoutA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType, WORD wLanguageId, DWORD dwMilliseconds);
int main() {
    auto& Process = Process::GetInstance();//get instance   获取实例
    Process.Attach("notepad.exe");//attach process  附加进程
    LPVOID addr = GetRoutine("MessageBoxTimeoutA");
    Process.SetContextUndocumentedCall<MessageBoxTimeoutA>(addr, Process::TONULL<HWND>(), "MSG", "CAP", MB_OK,0, 5000);
    

    return 0;
}