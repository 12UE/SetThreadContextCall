#include"SetContextCall.h"
using namespace stc;
//����ShowMessageBoxTimeout
typedef  int(WINAPI* MessageBoxTimeoutA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType, WORD wLanguageId, DWORD dwMilliseconds);
int main() {
    auto& Process = Process::GetInstance();//get instance   ��ȡʵ��
    Process.Attach("notepad.exe");//attach process  ���ӽ���
    LPVOID addr = GetRoutine("MessageBoxTimeoutA");
    Process.SetContextUndocumentedCall<MessageBoxTimeoutA>(addr, Process::TONULL<HWND>(), "MSG", "CAP", MB_OK,0, 5000);
    

    return 0;
}