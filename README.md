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
# SetThreadContextCall
线程劫持，是一种黑客的绝技，能够操纵运行中的线程，让它们按照自己的意志行事。这种技术需要精通汇编语言，熟悉线程管理和系统内核。其中一种常用的方法，就是利用Call函数，改变目标线程的执行方向。 Call函数的作用，就是让目标线程跳转到一个新的地址，执行那里的代码。劫持者要先暂停目标线程，才能安全地修改它的状态。然后，他就可以把目标线程的指令指针（IP），也就是它的下一步行动，指向自己准备好的代码块或函数。 当目标线程恢复运行时，它就会发现自己不知不觉地走上了一条不归路。它开始执行劫持者的代码，而不是原本的指令。这样，劫持者就可以在目标线程的执行流中植入自己的逻辑。他可以利用这个机会，做一些记录、修改内存或执行恶意操作等事情。 使用Call进行线程劫持，是一种非常强大但也非常危险的技术。它可以让劫持者在不被察觉的情况下，对目标线程进行任意的操控。但是，这种技术也可能违反法律和安全规范，造成严重的后果。 请您谨慎地使用这些信息，仅用于学习和研究。
### 注意
编译环境:Visual Studio 2022 Profresional.  

外部支持库zydis (推荐用vcpkg安装使用静态库).  

