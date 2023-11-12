# SetThreadContextCall
Thread hijacking involves seizing control of a running thread in order to execute custom code. This technique is often used in low-level programming or hacking scenarios. One method of thread hijacking is through the use of the `Call` function.
The `Call` function allows the hijacker to redirect the execution flow of a target thread by modifying its instruction pointer (IP). The hijacker first suspends the target thread to ensure safe manipulation of its state. Then, it alters the IP to point to a custom code block or function.
Once the thread is resumed, it will start executing the custom code instead of its original instructions. This allows the hijacker to inject their own logic into the target thread's execution flow. The custom code can perform actions such as logging, modifying memory, or executing malicious operations.
It's worth noting that thread hijacking using `Call` is a powerful and potentially dangerous technique. It requires a deep understanding of assembly language, thread management, and system internals. Additionally, unauthorized use of thread hijacking can be considered illegal and against security practices.
Please use this information responsibly and for educational purposes only.
usege:
```C++
int main()
{
    auto& Process = Process::GetInstance();//get instance
    Process.Attach("notepad.exe");//attach process

    std::cout<<Process.SetContextCall(GetCurrentProcessId).get();//call GetCurrentProcessId
    return 0;
}
```
