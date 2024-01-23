# Chinese
# SetThreadContextCall
线程劫持，是一种黑客的绝技，能够操纵运行中的线程，让它们按照自己的意志行事。这种技术需要精通汇编语言，熟悉线程管理和系统内核。其中一种常用的方法，就是利用Call函数，改变目标线程的执行方向。 Call函数的作用，就是让目标线程跳转到一个新的地址，执行那里的代码。劫持者要先暂停目标线程，才能安全地修改它的状态。然后，他就可以把目标线程的指令指针（IP），也就是它的下一步行动，指向自己准备好的代码块或函数。 当目标线程恢复运行时，它就会发现自己不知不觉地走上了一条不归路。它开始执行劫持者的代码，而不是原本的指令。这样，劫持者就可以在目标线程的执行流中植入自己的逻辑。他可以利用这个机会，做一些记录、修改内存或执行恶意操作等事情。 使用Call进行线程劫持，是一种非常强大但也非常危险的技术。它可以让劫持者在不被察觉的情况下，对目标线程进行任意的操控。但是，这种技术也可能违反法律和安全规范，造成严重的后果。 请您谨慎地使用这些信息，仅用于学习和研究。  

进程虚拟地址：数据的写入与获取的挑战
在计算机科学中，内存管理是一个复杂而关键的领域。操作系统需要在运行时管理和分配内存，以确保程序的顺利运行。然而，这个过程并非总是那么直观，特别是当涉及到内部指针操作时。本文将探讨ReadProcessMemory和memcpy函数，以及为什么在进程内部的虚拟地址上获取数据可能是毫无意义的。

ReadProcessMemory与memcpy简介
ReadProcessMemory是Windows操作系统中的一个函数，它允许一个进程读取另一个进程的内存。这个函数通常用于调试器和其他需要访问其他进程内存的应用程序。

memcpy是一个标准的C库函数，用于在内存中复制字节，通常用于复制数组或者结构体。它在单个进程的上下文中工作，可以用于复制任何可以访问的内存区域。

内部虚拟地址的挑战
尽管ReadProcessMemory和memcpy都可以用于操作内存，但是在进程内部的虚拟地址上获取数据可能是毫无意义的。这是因为每个进程都有自己的虚拟地址空间，这些地址空间是相互隔离的。因此，一个进程中的指针在另一个进程中可能没有意义，或者可能指向完全不同的数据。

此外，虚拟地址并不总是对应于实际的物理内存。操作系统使用虚拟内存技术，将虚拟地址映射到物理内存。这意味着，即使你有一个进程的虚拟地址，你也不能直接访问它对应的物理内存。你需要通过操作系统提供的机制，如ReadProcessMemory或memcpy，来访问这些内存
### 注意
编译环境:Visual Studio 2022 Profresional.  只支持x64因为x86取函数长度有问题
## 使用方法
```C++
int main()
{
    auto& Process = Process::GetInstance();//get instance
    Process.Attach("notepad.exe");//attach process

    std::cout<<Process.SetContextCall(GetCurrentProcessId).get();//call GetCurrentProcessId
    return 0;
}
```
或者 
```C++
int main()
{
    auto& Process = Process::GetInstance();//get instance
    Process.Attach("notepad.exe");//attach process
    MEMORY_BASIC_INFORMATION        mbi{};
    std::cout << Process.SetContextCall(VirtualQuery, (LPVOID)0X142670D80, &mbi, sizeof(mbi)).get();//call GetCurrentProcessId random address
    return 0;
}
```
### 免责声明

该开源项目（以下简称“本项目”）是由开发者无偿提供的，并基于开放源代码许可协议发布。本项目仅供参考和学习使用，使用者应该自行承担风险。

本项目没有任何明示或暗示的保证，包括但不限于适销性、特定用途适用性和非侵权性。开发者不保证本项目的功能符合您的需求，也不保证本项目的操作不会中断或错误。

在任何情况下，开发者都不承担由使用本项目而导致的任何直接、间接、偶然、特殊或后果性损失，包括但不限于商业利润的损失，无论这些损失是由合同、侵权行为还是其他原因造成的，即使开发者已被告知此类损失的可能性。

使用本项目即表示您已经阅读并同意遵守此免责声明。如果您不同意此免责声明，请不要使用本项目。开发者保留随时更改此免责声明的权利，恕不另行通知
# English
# SetThreadContextCall
Thread hijacking involves seizing control of a running thread in order to execute custom code. This technique is often used in low-level programming or hacking scenarios. One method of thread hijacking is through the use of the `Call` function.
The `Call` function allows the hijacker to redirect the execution flow of a target thread by modifying its instruction pointer (IP). The hijacker first suspends the target thread to ensure safe manipulation of its state. Then, it alters the IP to point to a custom code block or function.
Once the thread is resumed, it will start executing the custom code instead of its original instructions. This allows the hijacker to inject their own logic into the target thread's execution flow. The custom code can perform actions such as logging, modifying memory, or executing malicious operations.
It's worth noting that thread hijacking using `Call` is a powerful and potentially dangerous technique. It requires a deep understanding of assembly language, thread management, and system internals. Additionally, unauthorized use of thread hijacking can be considered illegal and against security practices.
Please use this information responsibly and for educational purposes only.
### notice
Build Environment: Visual Studio 2022 Profresional.  

Recommended to use Vcpkg to install and use the static library.  
Process Virtual Address: The Challenges of Data Writing and Retrieval
In computer science, memory management is a complex and critical field. The operating system needs to manage and allocate memory during runtime to ensure the smooth operation of programs. However, this process is not always intuitive, especially when it comes to internal pointer operations. This article will explore the ReadProcessMemory and memcpy functions, and why retrieving data from virtual addresses within a process may be meaningless.

Introduction to ReadProcessMemory and memcpy
ReadProcessMemory is a function in the Windows operating system that allows one process to read the memory of another process. This function is commonly used by debuggers and other applications that need to access the memory of other processes.

memcpy is a standard C library function used to copy bytes in memory, often used for copying arrays or structures. It works within the context of a single process and can be used to copy any accessible memory area.

The Challenge of Internal Virtual Addresses
Although ReadProcessMemory and memcpy can both be used for memory operations, retrieving data from virtual addresses within a process may be meaningless. This is because each process has its own virtual address space, and these address spaces are isolated from each other. Therefore, a pointer in one process may have no meaning in another process, or it may point to completely different data.

In addition, virtual addresses do not always correspond to actual physical memory. The operating system uses virtual memory technology to map virtual addresses to physical memory. This means that even if you have a virtual address of a process, you cannot directly access its corresponding physical memory. You need to use mechanisms provided by the operating system, such as ReadProcessMemory or memcpy, to access this memory.

### Disclaimer

This open-source project (hereinafter referred to as "the Project") is provided by the developer free of charge and is released under an open-source license agreement. The Project is intended for reference and learning purposes only, and users should assume all risks associated with its use.

The Project is provided without any express or implied warranties, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement. The developer does not warrant that the Project's functionality will meet your requirements or that its operation will be uninterrupted or error-free.

Under no circumstances shall the developer be liable for any direct, indirect, incidental, special, or consequential damages resulting from the use of the Project, including but not limited to loss of business profits, whether arising from contract, tort, or other legal theories, even if the developer has been advised of the possibility of such damages.

By using the Project, you acknowledge that you have read and agree to comply with this disclaimer. If you do not agree with this disclaimer, please do not use the Project. The developer reserves the right to change this disclaimer at any time without notice.
# Japaness
### スレッドコンテキストコール
スレッドハイジャックは、カスタムコードを実行するために実行中のスレッドを制御する技術です。この技術は、低レベルのプログラミングやハッキングのシナリオでよく使用されます。スレッドハイジャックの一つの方法は、Call関数の使用です。 Call関数は、ハイジャッカーが指示ポインタ（IP）を変更してターゲットスレッドの実行フローをリダイレクトすることを可能にします。ハイジャッカーはまず、ターゲットスレッドの状態を安全に操作するためにターゲットスレッドを一時停止します。次に、IPをカスタムコードブロックまたは関数を指すように変更します。 スレッドが再開されると、元の指示ではなくカスタムコードを実行し始めます。これにより、ハイジャッカーは自身のロジックをターゲットスレッドの実行フローに注入することができます。カスタムコードは、ログの記録、メモリの変更、または悪意のある操作の実行などのアクションを実行することができます。 Callを使用したスレッドハイジャッキングは強力で、潜在的に危険な技術であることに注意が必要です。アセンブリ言語、スレッド管理、システム内部の深い理解が必要です。また、スレッドハイジャッキングの無許可の使用は、違法であり、セキュリティの慣行に反すると見なされる可能性があります。 この情報を責任を持って、教育目的のみで使用してください。

### 注意
ビルド環境：Visual Studio 2022 Professional。

プロセス仮想アドレス：データの書き込みと取得の課題 コンピュータ科学では、メモリ管理は複雑で重要な分野です。オペレーティングシステムは、プログラムのスムーズな動作を確保するために、ランタイム中にメモリを管理および割り当てる必要があります。しかし、このプロセスは常に直感的ではなく、特に内部ポインタ操作に関してはそうではありません。この記事では、ReadProcessMemoryとmemcpy関数を探り、プロセス内の仮想アドレスからデータを取得することが無意味である可能性について説明します。

ReadProcessMemoryとmemcpyの紹介 ReadProcessMemoryは、Windowsオペレーティングシステムの関数で、あるプロセスが別のプロセスのメモリを読み取ることを可能にします。この関数は、他のプロセスのメモリにアクセスする必要があるデバッガやその他のアプリケーションで一般的に使用されます。

memcpyは、メモリ内のバイトをコピーするための標準的なCライブラリ関数で、通常は配列や構造体のコピーに使用されます。これは単一のプロセスのコンテキスト内で動作し、任意のアクセス可能なメモリ領域のコピーに使用することができます。

内部仮想アドレスの課題 ReadProcessMemoryとmemcpyの両方がメモリ操作に使用できる一方で、プロセス内の仮想アドレスからデータを取得することは無意味である可能性があります。これは、各プロセスが独自の仮想アドレス空間を持ち、これらのアドレス空間が互いに隔離されているためです。したがって、あるプロセスのポインタは、別のプロセスでは意味をなさないか、完全に異なるデータを指す可能性があります。

さらに、仮想アドレスは常に実際の物理メモリに対応しているわけではありません。オペレーティングシステムは仮想メモリ技術を使用して、仮想アドレスを物理メモリにマッピングします。これは、プロセスの仮想アドレスを持っていても、その対応する物理メモリに直接アクセスすることはできないことを意味します。このメモリにアクセスするためには、ReadProcessMemoryやmemcpyなど、オペレーティングシステムが提供するメカニズムを使用する必要があります。この説明が役立つことを願っています！
### 免責事項
このオープンソースプロジェクト（以下、「本プロジェクト」とします）は、開発者が無償で提供し、オープンソースライセンスに基づいて公開されています。本プロジェクトは参考と学習のためだけに提供され、利用者は自己のリスクを負うべきです。

本プロジェクトには、明示的または暗黙的な保証は一切ありません。これには、商品性、特定目的への適合性、および非侵害性の保証が含まれます。開発者は、本プロジェクトの機能があなたの要求を満たすこと、または本プロジェクトの操作が中断されないこと、またはエラーが発生しないことを保証しません。

いかなる場合でも、開発者は、本プロジェクトの使用によって生じた直接的、間接的、偶発的、特別な、または結果的な損害について、契約、不法行為、またはその他の理由にかかわらず、一切の責任を負いません。これには、ビジネスプロフィットの損失が含まれます。これらの損失が契約、不法行為、またはその他の理由によるものであるかどうか、また開発者がこのような損失の可能性を通知されていたとしても、開発者は一切の責任を負いません。

本プロジェクトを使用することで、あなたはこの免責事項を読み、同意することを表明します。もし、あなたがこの免責事項に同意しない場合は、本プロジェクトを使用しないでください。開発者は、この免責事項をいつでも変更する権利を保有しており、事前の通知はありません。この情報を責任を持って、教育目的のみで使用してください

 

