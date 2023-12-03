# SetThreadContextCall
Thread hijacking involves seizing control of a running thread in order to execute custom code. This technique is often used in low-level programming or hacking scenarios. One method of thread hijacking is through the use of the `Call` function.
The `Call` function allows the hijacker to redirect the execution flow of a target thread by modifying its instruction pointer (IP). The hijacker first suspends the target thread to ensure safe manipulation of its state. Then, it alters the IP to point to a custom code block or function.
Once the thread is resumed, it will start executing the custom code instead of its original instructions. This allows the hijacker to inject their own logic into the target thread's execution flow. The custom code can perform actions such as logging, modifying memory, or executing malicious operations.
It's worth noting that thread hijacking using `Call` is a powerful and potentially dangerous technique. It requires a deep understanding of assembly language, thread management, and system internals. Additionally, unauthorized use of thread hijacking can be considered illegal and against security practices.
Please use this information responsibly and for educational purposes only.
### notice
Build Environment: Visual Studio 2022 Profresional.  

External Support Library: Zydis .  

Recommended to use Vcpkg to install and use the static library.  

## usege:
```C++
int main()
{
    auto& Process = Process::GetInstance();//get instance
    Process.Attach("notepad.exe");//attach process

    std::cout<<Process.SetContextCall(GetCurrentProcessId).get();//call GetCurrentProcessId
    return 0;
}
```
or  
```C++
int main()
{
    auto& Process = Process::GetInstance();//get instance
    Process.Attach("notepad.exe");//attach process
    MEMORY_BASIC_INFORMATION        mbi;
    std::cout << Process.SetContextCall(VirtualQuery, (LPVOID)0X142670D80, &mbi, sizeof(mbi)).get();//call GetCurrentProcessId
    return 0;
}
```
### Disclaimer

This open-source project (hereinafter referred to as "the Project") is provided by the developer free of charge and is released under an open-source license agreement. The Project is intended for reference and learning purposes only, and users should assume all risks associated with its use.

The Project is provided without any express or implied warranties, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. The developer does not warrant that the Project's functionality will meet your requirements or that its operation will be uninterrupted or error-free.

Under no circumstances shall the developer be liable for any direct, indirect, incidental, special, or consequential damages resulting from the use of the Project, including but not limited to loss of business profits, whether arising from contract, tort, or other legal theories, even if the developer has been advised of the possibility of such damages.

By using the Project, you acknowledge that you have read and agree to comply with this disclaimer. If you do not agree with this disclaimer, please do not use the Project. The developer reserves the right to change this disclaimer at any time without notice.
# SetThreadContextCall
线程劫持，是一种黑客的绝技，能够操纵运行中的线程，让它们按照自己的意志行事。这种技术需要精通汇编语言，熟悉线程管理和系统内核。其中一种常用的方法，就是利用Call函数，改变目标线程的执行方向。 Call函数的作用，就是让目标线程跳转到一个新的地址，执行那里的代码。劫持者要先暂停目标线程，才能安全地修改它的状态。然后，他就可以把目标线程的指令指针（IP），也就是它的下一步行动，指向自己准备好的代码块或函数。 当目标线程恢复运行时，它就会发现自己不知不觉地走上了一条不归路。它开始执行劫持者的代码，而不是原本的指令。这样，劫持者就可以在目标线程的执行流中植入自己的逻辑。他可以利用这个机会，做一些记录、修改内存或执行恶意操作等事情。 使用Call进行线程劫持，是一种非常强大但也非常危险的技术。它可以让劫持者在不被察觉的情况下，对目标线程进行任意的操控。但是，这种技术也可能违反法律和安全规范，造成严重的后果。 请您谨慎地使用这些信息，仅用于学习和研究。
### 注意
编译环境:Visual Studio 2022 Profresional.  

外部支持库zydis (推荐用vcpkg安装使用静态库). 
### 免责声明

该开源项目（以下简称“本项目”）是由开发者无偿提供的，并基于开放源代码许可协议发布。本项目仅供参考和学习使用，使用者应该自行承担风险。

本项目没有任何明示或暗示的保证，包括但不限于适销性、特定用途适用性和非侵权性。开发者不保证本项目的功能符合您的需求，也不保证本项目的操作不会中断或错误。

在任何情况下，开发者都不承担由使用本项目而导致的任何直接、间接、偶然、特殊或后果性损失，包括但不限于商业利润的损失，无论这些损失是由合同、侵权行为还是其他原因造成的，即使开发者已被告知此类损失的可能性。

使用本项目即表示您已经阅读并同意遵守此免责声明。如果您不同意此免责声明，请不要使用本项目。开发者保留随时更改此免责声明的权利，恕不另行通知
 

