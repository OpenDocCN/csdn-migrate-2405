# C++ 专家编程（四）

> 原文：[`annas-archive.org/md5/57ea316395e58ce0beb229274ec493fc`](https://annas-archive.org/md5/57ea316395e58ce0beb229274ec493fc)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：C++多线程 API

虽然 C++在标准模板库（STL）中有本地的多线程实现，但基于操作系统和框架的多线程 API 仍然非常常见。这些 API 的示例包括 Windows 和 POSIX（可移植操作系统接口）线程，以及由 Qt、Boost 和 POCO 库提供的线程。

本章将详细介绍每个 API 提供的功能，以及它们之间的相似之处和不同之处。最后，我们将使用示例代码来查看常见的使用场景。

本章涵盖的主题包括以下内容：

+   可用多线程 API 的比较

+   每个 API 的使用示例

# API 概述

在 C++ 2011（C++11）标准之前，开发了许多不同的线程实现，其中许多限于特定的软件平台。其中一些至今仍然相关，例如 Windows 线程。其他已被标准取代，其中 POSIX 线程（Pthreads）已成为类 UNIX 操作系统的事实标准。这包括基于 Linux 和 BSD 的操作系统，以及 OS X（macOS）和 Solaris。

许多库被开发出来，以使跨平台开发更容易。尽管 Pthreads 有助于使类 UNIX 操作系统更或多或少兼容，但要使软件在所有主要操作系统上可移植，需要一个通用的线程 API。这就是为什么创建了 Boost、POCO 和 Qt 等库。应用程序可以使用这些库，并依赖于库来处理平台之间的任何差异。

# POSIX 线程

Pthreads 最初是在 1995 年的 POSIX.1c 标准（线程扩展，IEEE Std 1003.1c-1995）中定义的，作为 POSIX 标准的扩展。当时，UNIX 被选择为制造商中立的接口，POSIX 统一了它们之间的各种 API。

尽管有这种标准化的努力，Pthread 在实现它的操作系统之间仍然存在差异（例如，在 Linux 和 OS X 之间），这是由于不可移植的扩展（在方法名称中标有 _np）。

对于 pthread_setname_np 方法，Linux 实现需要两个参数，允许设置除当前线程以外的线程名称。在 OS X（自 10.6 起），此方法只需要一个参数，允许设置当前线程的名称。如果可移植性是一个问题，就必须注意这样的差异。

1997 年后，POSIX 标准修订由 Austin 联合工作组管理。这些修订将线程扩展合并到主标准中。当前的修订是 7，也称为 POSIX.1-2008 和 IEEE Std 1003.1，2013 版--标准的免费副本可在线获得。

操作系统可以获得符合 POSIX 标准的认证。目前，这些如下表所述：

| **名称** | **开发者** | **自版本** | **架构（当前）** | **备注** |
| --- | --- | --- | --- | --- |
| AIX | IBM | 5L | POWER | 服务器操作系统 |
| HP-UX | Hewlett-Packard | 11i v3 | PA-RISC, IA-64 (Itanium) | 服务器操作系统 |
| IRIX | Silicon Graphics (SGI) | 6 | MIPS | 已停产 |
| Inspur K-UX | Inspur | 2 | X86_64, | 基于 Linux |
| Integrity | Green Hills Software | 5 | ARM, XScale, Blackfin, Freescale Coldfire, MIPS, PowerPC, x86。 | 实时操作系统 |
| OS X/MacOS | Apple | 10.5 (Leopard) | X86_64 | 桌面操作系统 |
| QNX Neutrino | BlackBerry | 1 | Intel 8088, x86, MIPS, PowerPC, SH-4, ARM, StrongARM, XScale | 实时，嵌入式操作系统 |
| Solaris | Sun/Oracle | 2.5 | SPARC, IA-32 (<11), x86_64, PowerPC (2.5.1) | 服务器操作系统 |
| Tru64 | DEC, HP, IBM, Compaq | 5.1B-4 | Alpha | 已停产 |
| UnixWare | Novell, SCO, Xinuos | 7.1.3 | x86 | 服务器操作系统 |

其他操作系统大多是兼容的。以下是相同的示例：

| **名称** | **平台** | **备注** |
| --- | --- | --- |
| Android | ARM, x86, MIPS | 基于 Linux。Bionic C 库。 |
| BeOS (Haiku) | IA-32, ARM, x64_64 | 限于 x86 的 GCC 2.x。 |
| Darwin | PowerPC，x86，ARM | 使用 macOS 基于的开源组件。 |
| FreeBSD | IA-32，x86_64，sparc64，PowerPC，ARM，MIPS 等 | 基本上符合 POSIX。可以依赖已记录的 POSIX 行为。一般来说，比 Linux 更严格地遵守规范。 |
| Linux | Alpha，ARC，ARM，AVR32，Blackfin，H8/300，Itanium，m68k，Microblaze，MIPS，Nios II，OpenRISC，PA-RISC，PowerPC，s390，S+core，SuperH，SPARC，x86，Xtensa 等 | 一些 Linux 发行版（见前表）被认证为符合 POSIX。这并不意味着每个 Linux 发行版都符合 POSIX。一些工具和库可能与标准不同。对于 Pthreads，这可能意味着在 Linux 发行版之间（不同的调度程序等）以及与实现 Pthreads 的其他操作系统之间的行为有时会有所不同。 |
| MINIX 3 | IA-32，ARM | 符合 POSIX 规范标准 3（SUSv3，2004 年）。 |
| NetBSD | Alpha，ARM，PA-RISC，68k，MIPS，PowerPC，SH3，SPARC，RISC-V，VAX，x86 等 | 几乎完全兼容 POSX.1（1990），并且大部分符合 POSIX.2（1992）。 |
| 核心 RTOS | ARM，MIPS，PowerPC，Nios II，MicroBlaze，SuperH 等 | Mentor Graphics 的专有 RTOS，旨在嵌入式应用。 |
| NuttX | ARM，AVR，AVR32，HCS12，SuperH，Z80 等 | 轻量级 RTOS，可在 8 到 32 位系统上扩展，专注于 POSIX 兼容性。 |
| OpenBSD | Alpha，x86_64，ARM，PA-RISC，IA-32，MIPS，PowerPC，SPARC 等 | 1995 年从 NetBSD 分叉出来。类似的 POSIX 支持。 |
| OpenSolaris/illumos | IA-32，x86_64，SPARC，ARM | 与商业 Solaris 发行版兼容认证。 |
| VxWorks | ARM，SH-4，x86，x86_64，MIPS，PowerPC | 符合 POSIX，并获得用户模式执行环境的认证。 |

由此可见，遵循 POSIX 规范并不是一件明显的事情，也不能指望自己的代码在每个平台上都能编译。每个平台还将有其自己的标准扩展，用于标准中省略的但仍然有用的功能。然而，Pthreads 在 Linux、BSD 和类似软件中被广泛使用。

# Windows 支持

也可以使用 POSIX API，例如以下方式：

| **名称** | **兼容性** |
| --- | --- |
| Cygwin | 大部分完整。为 POSIX 应用程序提供完整的运行时环境，可以作为普通的 Windows 应用程序分发。 |
| MinGW | 使用 MinGW-w64（MinGW 的重新开发），Pthreads 支持相当完整，尽管可能会缺少一些功能。 |
| Windows Subsystem for Linux | WSL 是 Windows 10 的一个功能，允许 Ubuntu Linux 14.04（64 位）镜像的工具和实用程序在其上本地运行，尽管不能使用 GUI 功能或缺少内核功能。否则，它提供与 Linux 类似的兼容性。此功能目前要求运行 Windows 10 周年更新，并按照微软提供的说明手动安装 WSL。 |

一般不建议在 Windows 上使用 POSIX。除非有充分的理由使用 POSIX（例如，大量现有的代码库），否则最好使用其中一个跨平台 API（本章后面将介绍），这样可以消除任何平台问题。

在接下来的章节中，我们将看一下 Pthreads API 提供的功能。

# PThreads 线程管理

这些都是以`pthread_`或`pthread_attr_`开头的函数。这些函数都适用于线程本身及其属性对象。

使用 Pthreads 的基本方法如下：

```cpp
#include <pthread.h> 
#include <stdlib.h> 

#define NUM_THREADS     5 
```

主要的 Pthreads 头文件是`pthread.h`。这提供了对除了信号量（稍后在本节中讨论）之外的所有内容的访问。我们还在这里定义了一个希望启动的线程数的常量：

```cpp
void* worker(void* arg) { 
    int value = *((int*) arg); 

    // More business logic. 

    return 0; 
} 
```

我们定义了一个简单的`Worker`函数，稍后将把它传递给新线程。为了演示和调试目的，可以首先添加一个简单的基于`cout`或`printf`的业务逻辑，以打印发送到新线程的值。

接下来，我们定义`main`函数如下：

```cpp
int main(int argc, char** argv) { 
    pthread_t threads[NUM_THREADS]; 
    int thread_args[NUM_THREADS]; 
    int result_code; 

    for (unsigned int i = 0; i < NUM_THREADS; ++i) { 
        thread_args[i] = i; 
        result_code = pthread_create(&threads[i], 0, worker, (void*) &thread_args[i]); 
    } 
```

我们在上述函数中的循环中创建所有线程。每个线程实例在创建时被分配一个线程 ID（第一个参数），并且`pthread_create()`函数返回一个结果代码（成功时为零）。线程 ID 是在将来的调用中引用线程的句柄。

函数的第二个参数是`pthread_attr_t`结构实例，如果没有则为 0。这允许配置新线程的特性，例如初始堆栈大小。当传递零时，将使用默认参数，这些参数因平台和配置而异。

第三个参数是一个指向新线程将启动的函数的指针。此函数指针被定义为一个返回指向 void 数据的指针的函数（即自定义数据），并接受指向 void 数据的指针。在这里，作为参数传递给新线程的数据是线程 ID：

```cpp
    for (int i = 0; i < NUM_THREADS; ++i) { 
        result_code = pthread_join(threads[i], 0); 
    } 

    exit(0); 
} 
```

接下来，我们使用`pthread_join()`函数等待每个工作线程完成。此函数接受两个参数，要等待的线程的 ID，以及`Worker`函数的返回值的缓冲区（或零）。

管理线程的其他函数如下：

+   `void pthread_exit`(`void *value_ptr`)：

此函数终止调用它的线程，使提供的参数值可用于调用`pthread_join()`的任何线程。

+   `int pthread_cancel`(`pthread_t` thread)：

此函数请求取消指定的线程。根据目标线程的状态，这将调用其取消处理程序。

除此之外，还有`pthread_attr_*`函数来操作和获取有关`pthread_attr_t`结构的信息。

# 互斥锁

这些函数的前缀为`pthread_mutex_`或`pthread_mutexattr_`。它们适用于互斥锁及其属性对象。

Pthreads 中的互斥锁可以被初始化、销毁、锁定和解锁。它们还可以使用`pthread_mutexattr_t`结构自定义其行为，该结构具有相应的`pthread_mutexattr_*`函数用于初始化和销毁其属性。

使用静态初始化的 Pthread 互斥锁的基本用法如下：

```cpp
static pthread_mutex_t func_mutex = PTHREAD_MUTEX_INITIALIZER; 

void func() { 
    pthread_mutex_lock(&func_mutex); 

    // Do something that's not thread-safe. 

    pthread_mutex_unlock(&func_mutex); 
} 
```

在这段代码的最后，我们使用了`PTHREAD_MUTEX_INITIALIZER`宏，它为我们初始化了互斥锁，而无需每次都输入代码。与其他 API 相比，人们必须手动初始化和销毁互斥锁，尽管使用宏在某种程度上有所帮助。

之后，我们锁定和解锁互斥锁。还有`pthread_mutex_trylock()`函数，它类似于常规锁定版本，但如果引用的互斥锁已经被锁定，它将立即返回而不是等待它被解锁。

在此示例中，互斥锁没有被显式销毁。然而，这是 Pthreads 应用程序中正常内存管理的一部分。

# 条件变量

这些函数的前缀为`pthread_cond_`或`pthread_condattr_`。它们适用于条件变量及其属性对象。

Pthreads 中的条件变量遵循相同的模式，除了具有相同的`pthread_condattr_t`属性结构管理外，还有初始化和`destroy`函数。

此示例涵盖了 Pthreads 条件变量的基本用法：

```cpp
#include <pthread.h> 
#include <stdlib.h>
#include <unistd.h>

   #define COUNT_TRIGGER 10 
   #define COUNT_LIMIT 12 

   int count = 0; 
   int thread_ids[3] = {0,1,2}; 
   pthread_mutex_t count_mutex; 
   pthread_cond_t count_cv; 
```

在上述代码中，我们获取标准头文件，并定义一个计数触发器和限制，其目的将很快变得清楚。我们还定义了一些全局变量：计数变量，我们希望创建的线程的 ID，以及互斥锁和条件变量：

```cpp
void* add_count(void* t)  { 
    int tid = (long) t; 
    for (int i = 0; i < COUNT_TRIGGER; ++i) { 
        pthread_mutex_lock(&count_mutex); 
        count++; 
        if (count == COUNT_LIMIT) { 
            pthread_cond_signal(&count_cv); 
        } 

        pthread_mutex_unlock(&count_mutex); 
        sleep(1); 
    } 

    pthread_exit(0); 
} 
```

在获取`count_mutex`的独占访问权限后，前面的函数本质上只是将全局计数器变量增加。它还检查计数触发值是否已达到。如果是，它将发出条件变量的信号。

为了让也运行此函数的第二个线程有机会获得互斥锁，我们在循环的每个周期中睡眠 1 秒：

```cpp
void* watch_count(void* t) { 
    int tid = (int) t; 

    pthread_mutex_lock(&count_mutex); 
    if (count < COUNT_LIMIT) { 
        pthread_cond_wait(&count_cv, &count_mutex); 
    } 

    pthread_mutex_unlock(&count_mutex); 
    pthread_exit(0); 
} 
```

在这个第二个函数中，在检查是否已经达到计数限制之前，我们先锁定全局互斥锁。这是我们的保险，以防此函数运行的线程在计数达到限制之前没有被调用。

否则，我们等待条件变量提供条件变量和锁定的互斥锁。一旦发出信号，我们解锁全局互斥锁，并退出线程。

这里需要注意的一点是，此示例未考虑虚假唤醒。Pthreads 条件变量容易受到这种唤醒的影响，这需要使用循环并检查是否已满足某种条件：

```cpp
int main (int argc, char* argv[]) { 
    int tid1 = 1, tid2 = 2, tid3 = 3; 
    pthread_t threads[3]; 
    pthread_attr_t attr; 

    pthread_mutex_init(&count_mutex, 0); 
    pthread_cond_init (&count_cv, 0); 

    pthread_attr_init(&attr); 
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE); 
    pthread_create(&threads[0], &attr, watch_count, (void *) tid1); 
    pthread_create(&threads[1], &attr, add_count, (void *) tid2); 
    pthread_create(&threads[2], &attr, add_count, (void *) tid3); 

    for (int i = 0; i < 3; ++i) { 
        pthread_join(threads[i], 0); 
    } 

    pthread_attr_destroy(&attr); 
    pthread_mutex_destroy(&count_mutex); 
    pthread_cond_destroy(&count_cv); 
    return 0; 
}  
```

最后，在`main`函数中，我们创建三个线程，其中两个运行将计数器增加的函数，第三个运行等待其条件变量被发出信号的函数。

在这种方法中，我们还初始化全局互斥锁和条件变量。我们创建的线程还明确设置了“可连接”属性。

最后，我们等待每个线程完成，然后进行清理，在退出之前销毁属性结构实例、互斥锁和条件变量。

使用`pthread_cond_broadcast()`函数，还可以向等待条件变量的所有线程发出信号，而不仅仅是队列中的第一个线程。这使得可以更优雅地使用条件变量，例如，当有很多工作线程等待新数据集到达时，无需单独通知每个线程。

# 同步

实现同步的函数以`pthread_rwlock_`或`pthread_barrier_`为前缀。这些实现读/写锁和同步屏障。

**读/写锁**（**rwlock**）与互斥锁非常相似，只是它具有额外的功能，允许无限线程同时读取，而只限制写入访问一个线程。

使用`rwlock`与使用互斥锁非常相似：

```cpp
#include <pthread.h> 
int pthread_rwlock_init(pthread_rwlock_t* rwlock, const pthread_rwlockattr_t* attr); 
pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER; 
```

在最后的代码中，我们包含相同的通用头文件，并使用初始化函数或通用宏。有趣的部分是当我们锁定`rwlock`时，可以仅进行只读访问：

```cpp
int pthread_rwlock_rdlock(pthread_rwlock_t* rwlock); 
int pthread_rwlock_tryrdlock(pthread_rwlock_t* rwlock); 
```

这里，如果锁已经被锁定，第二种变体会立即返回。也可以按以下方式锁定它以进行写访问：

```cpp
int pthread_rwlock_wrlock(pthread_rwlock_t* rwlock); 
int pthread_rwlock_trywrlock(pthread_rwlock_t * rwlock); 
```

这些函数基本上是相同的，唯一的区别是在任何给定时间只允许一个写入者，而多个读取者可以获得只读锁定。

屏障是 Pthreads 的另一个概念。这些是类似于一组线程的屏障的同步对象。在这些线程中的所有线程都必须在任何一个线程可以继续执行之前到达屏障。在屏障初始化函数中，指定了线程计数。只有当所有这些线程都使用`pthread_barrier_wait()`函数调用`barrier`对象后，它们才会继续执行。

# 信号量

如前所述，信号量不是原始 Pthreads 扩展的一部分。出于这个原因，它们在`semaphore.h`头文件中声明。

实质上，信号量是简单的整数，通常用作资源计数。为了使它们线程安全，使用原子操作（检查和锁定）。POSIX 信号量支持初始化、销毁、增加和减少信号量以及等待信号量达到非零值的操作。

# 线程本地存储（TLC）

使用 Pthreads，TLS 是通过键和设置线程特定数据的方法来实现的：

```cpp
pthread_key_t global_var_key;

void* worker(void* arg) {
    int *p = new int;
    *p = 1;
    pthread_setspecific(global_var_key, p);
    int* global_spec_var = (int*) pthread_getspecific(global_var_key);
    *global_spec_var += 1;
    pthread_setspecific(global_var_key, 0);
    delete p;
    pthread_exit(0);
}
```

在工作线程中，我们在堆上分配一个新的整数，并将全局密钥设置为其自己的值。将全局变量增加 1 后，其值将为 2，而不管其他线程做什么。我们可以在此线程完成后将全局变量设置为 0，并删除分配的值：

```cpp
int main(void) {
    pthread_t threads[5];

    pthread_key_create(&global_var_key, 0);
    for (int i = 0; i < 5; ++i)
        pthread_create(&threads[i],0,worker,0);
    for (int i = 0; i < 5; ++i) {
        pthread_join(threads[i], 0);
    }
    return 0;
}
```

设置并使用全局密钥来引用 TLS 变量，但我们创建的每个线程都可以为该密钥设置自己的值。

虽然线程可以创建自己的密钥，但与本章中正在查看的其他 API 相比，处理 TLS 的这种方法相当复杂。

# Windows 线程

相对于 Pthreads，Windows 线程仅限于 Windows 操作系统和类似系统（例如 ReactOS 和其他使用 Wine 的操作系统）。这提供了一个相当一致的实现，可以轻松地由支持对应的 Windows 版本来定义。

在 Windows Vista 之前，线程支持缺少诸如条件变量之类的功能，同时具有 Pthreads 中找不到的功能。根据一个人的观点，使用 Windows 头文件定义的无数“类型定义”类型可能也会让人感到烦扰。

# 线程管理

一个使用 Windows 线程的基本示例，从官方 MSDN 文档示例代码中改编而来，看起来像这样：

```cpp
#include <windows.h> 
#include <tchar.h> 
#include <strsafe.h> 

#define MAX_THREADS 3 
#define BUF_SIZE 255  
```

在包含一系列 Windows 特定的头文件（用于线程函数、字符字符串等）之后，我们定义了要创建的线程数以及`Worker`函数中消息缓冲区的大小。

我们还定义了一个结构类型（通过`void pointer: LPVOID`传递），用于包含我们传递给每个工作线程的示例数据：

```cpp
typedef struct MyData { 
 int val1; 
 int val2; 
} MYDATA, *PMYDATA;

DWORD WINAPI worker(LPVOID lpParam) { 
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE); 
    if (hStdout == INVALID_HANDLE_VALUE) { 
        return 1; 
    } 

    PMYDATA pDataArray =  (PMYDATA) lpParam; 

    TCHAR msgBuf[BUF_SIZE]; 
    size_t cchStringSize; 
    DWORD dwChars; 
    StringCchPrintf(msgBuf, BUF_SIZE, TEXT("Parameters = %d, %dn"),  
    pDataArray->val1, pDataArray->val2);  
    StringCchLength(msgBuf, BUF_SIZE, &cchStringSize); 
    WriteConsole(hStdout, msgBuf, (DWORD) cchStringSize, &dwChars, NULL); 

    return 0;  
}  
```

在`Worker`函数中，我们将提供的参数转换为我们自定义的结构类型，然后使用它将其值打印到字符串上，然后输出到控制台。

我们还验证是否有活动的标准输出（控制台或类似）。用于打印字符串的函数都是线程安全的。

```cpp
void errorHandler(LPTSTR lpszFunction) { 
    LPVOID lpMsgBuf; 
    LPVOID lpDisplayBuf; 
    DWORD dw = GetLastError();  

    FormatMessage( 
        FORMAT_MESSAGE_ALLOCATE_BUFFER |  
        FORMAT_MESSAGE_FROM_SYSTEM | 
        FORMAT_MESSAGE_IGNORE_INSERTS, 
        NULL, 
        dw, 
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
        (LPTSTR) &lpMsgBuf, 
        0, NULL); 

        lpDisplayBuf = (LPVOID) LocalAlloc(LMEM_ZEROINIT,  
        (lstrlen((LPCTSTR) lpMsgBuf) + lstrlen((LPCTSTR) lpszFunction) + 40) * sizeof(TCHAR));  
        StringCchPrintf((LPTSTR)lpDisplayBuf,  
        LocalSize(lpDisplayBuf) / sizeof(TCHAR), 
        TEXT("%s failed with error %d: %s"),  
        lpszFunction, dw, lpMsgBuf);  
        MessageBox(NULL, (LPCTSTR) lpDisplayBuf, TEXT("Error"), MB_OK);  

        LocalFree(lpMsgBuf); 
        LocalFree(lpDisplayBuf); 
} 
```

在这里，定义了一个错误处理程序函数，该函数获取最后一个错误代码的系统错误消息。获取最后一个错误的代码后，将格式化要输出的错误消息，并显示在消息框中。最后，释放分配的内存缓冲区。

最后，`main`函数如下：

```cpp
int _tmain() {
         PMYDATA pDataArray[MAX_THREADS];
         DWORD dwThreadIdArray[MAX_THREADS];
         HANDLE hThreadArray[MAX_THREADS];
         for (int i = 0; i < MAX_THREADS; ++i) {
               pDataArray[i] = (PMYDATA) HeapAlloc(GetProcessHeap(),
                           HEAP_ZERO_MEMORY, sizeof(MYDATA));                     if (pDataArray[i] == 0) {
                           ExitProcess(2);
             }
             pDataArray[i]->val1 = i;
             pDataArray[i]->val2 = i+100;
             hThreadArray[i] = CreateThread(
                  NULL,          // default security attributes
                  0,             // use default stack size
                  worker,        // thread function name
                  pDataArray[i], // argument to thread function
                  0,             // use default creation flags
                  &dwThreadIdArray[i]);// returns the thread identifier
             if (hThreadArray[i] == 0) {
                         errorHandler(TEXT("CreateThread"));
                         ExitProcess(3);
             }
   }
         WaitForMultipleObjects(MAX_THREADS, hThreadArray, TRUE, INFINITE);
         for (int i = 0; i < MAX_THREADS; ++i) {
               CloseHandle(hThreadArray[i]);
               if (pDataArray[i] != 0) {
                           HeapFree(GetProcessHeap(), 0, pDataArray[i]);
               }
         }
         return 0;
}
```

在`main`函数中，我们在循环中创建我们的线程，为线程数据分配内存，并在启动线程之前为每个线程生成唯一数据。每个线程实例都传递了自己的唯一参数。

之后，我们等待线程完成并重新加入。这本质上与在 Pthreads 上调用`join`函数相同——只是这里，一个函数调用就足够了。

最后，关闭每个线程句柄，并清理之前分配的内存。

# 高级管理

使用 Windows 线程进行高级线程管理包括作业、纤程和线程池。作业基本上允许将多个线程链接在一起成为一个单一单元，从而可以一次性更改所有这些线程的属性和状态。

纤程是轻量级线程，运行在创建它们的线程的上下文中。创建线程预期自己调度这些纤程。纤程还有类似 TLS 的**纤程本地存储**（**FLS**）。

最后，Windows 线程 API 提供了一个线程池 API，允许在应用程序中轻松使用这样的线程池。每个进程也提供了一个默认的线程池。

# 同步

使用 Windows 线程，可以使用临界区、互斥锁、信号量、**轻量级读写器**（**SRW**）锁、屏障和变体来实现互斥和同步。

同步对象包括以下内容：

| **名称** | **描述** |
| --- | --- |
| 事件 | 允许使用命名对象在线程和进程之间进行事件信号传递。 |
| 互斥锁 | 用于线程间和进程同步，协调对共享资源的访问。 |
| 信号量 | 标准信号量计数对象，用于线程间和进程同步。 |
| 可等待定时器 | 可由多个进程使用的定时器对象，具有多种使用模式。 |
| 临界区 | 临界区本质上是互斥锁，限于单个进程，这使得它们比使用互斥锁更快，因为缺少内核空间调用。 |
| 轻量级读写锁 | SRW 类似于 Pthreads 中的读/写锁，允许多个读取者或单个写入者线程访问共享资源。 |
| 交错变量访问 | 允许对一系列变量进行原子访问，否则不能保证原子性。这使得线程可以共享变量，而无需使用互斥锁。 |

# 条件变量

使用 Windows 线程实现条件变量是非常简单的。它使用临界区（`CRITICAL_SECTION`）和条件变量（`CONDITION_VARIABLE`）以及条件变量函数来等待特定的条件变量，或者发出信号。

# 线程本地存储

**线程本地存储**（**TLS**）与 Windows 线程类似于 Pthreads，首先必须创建一个中央键（TLS 索引），然后各个线程可以使用该全局索引来存储和检索本地值。

与 Pthreads 一样，这涉及相似数量的手动内存管理，因为 TLS 值必须手动分配和删除。

# Boost

Boost 线程是 Boost 库集合中相对较小的一部分。然而，它被用作成为 C++11 中多线程实现基础的基础，类似于其他 Boost 库最终完全或部分地成为新的 C++标准。有关多线程 API 的详细信息，请参阅本章中的 C++线程部分。

C++11 标准中缺少的功能，在 Boost 线程中是可用的，包括以下内容：

+   线程组（类似于 Windows 作业）

+   线程中断（取消）

+   带超时的线程加入

+   额外的互斥锁类型（在 C++14 中改进）

除非绝对需要这些功能，或者无法使用支持 C++11 标准（包括 STL 线程）的编译器，否则没有理由使用 Boost 线程而不是 C++11 实现。

由于 Boost 提供了对本机操作系统功能的包装，使用本机 C++线程可能会减少开销，具体取决于 STL 实现的质量。

```cpp
POCO
```

POCO 库是对操作系统功能的相当轻量级的包装。它不需要兼容 C++11 的编译器或任何类型的预编译或元编译。

# 线程类

`Thread`类是对 OS 级别线程的简单包装。它接受从`Runnable`类继承的`Worker`类实例。官方文档提供了一个基本示例，如下所示：

```cpp
#include "Poco/Thread.h" 
#include "Poco/Runnable.h" 
#include <iostream> 

class HelloRunnable: public Poco::Runnable { 
    virtual void run() { 
        std::cout << "Hello, world!" << std::endl; 
    } 
}; 

int main(int argc, char** argv) { 
    HelloRunnable runnable; 
    Poco::Thread thread; 
    thread.start(runnable); 
    thread.join(); 
    return 0; 
} 
```

上述代码是一个非常简单的“Hello world”示例，其中一个工作线程仅通过标准输出输出一个字符串。线程实例分配在堆栈上，并在入口函数的范围内等待工作线程完成，使用`join()`函数。

POCO 的许多线程功能与 Pthreads 非常相似，尽管在配置线程和其他对象等方面有明显的偏差。作为一个 C++库，它使用类方法来设置属性，而不是填充结构并将其作为参数传递。

# 线程池

POCO 提供了一个默认的线程池，有 16 个线程。这个数字可以动态改变。与常规线程一样，线程池需要传递一个从`Runnable`类继承的`Worker`类实例：

```cpp
#include "Poco/ThreadPool.h" 
#include "Poco/Runnable.h" 
#include <iostream> 

class HelloRunnable: public Poco::Runnable { 
    virtual void run() { 
        std::cout << "Hello, world!" << std::endl; 
    } 
}; 

int main(int argc, char** argv) { 
    HelloRunnable runnable; 
    Poco::ThreadPool::defaultPool().start(runnable); 
    Poco::ThreadPool::defaultPool().joinAll(); 
    return 0; 
} 
```

工作线程实例被添加到线程池中，并运行它。当我们添加另一个工作线程实例，更改容量或调用`joinAll()`时，线程池会清理空闲一定时间的线程。结果，单个工作线程将加入，并且没有活动线程，应用程序退出。

# 线程本地存储（TLS）

在 POCO 中，TLS 被实现为一个类模板，允许人们将其用于几乎任何类型。

正如官方文档所述：

```cpp
#include "Poco/Thread.h" 
#include "Poco/Runnable.h" 
#include "Poco/ThreadLocal.h" 
#include <iostream> 

class Counter: public Poco::Runnable { 
    void run() { 
        static Poco::ThreadLocal<int> tls; 
        for (*tls = 0; *tls < 10; ++(*tls)) { 
            std::cout << *tls << std::endl; 
        } 
    } 
}; 

int main(int argc, char** argv) { 
    Counter counter1; 
    Counter counter2; 
    Poco::Thread t1; 
    Poco::Thread t2; 
    t1.start(counter1); 
    t2.start(counter2); 
    t1.join(); 
    t2.join(); 
    return 0; 
} 
```

在上面的 worker 示例中，我们使用`ThreadLocal`类模板创建了一个静态 TLS 变量，并定义它包含一个整数。

因为我们将它定义为静态的，所以每个线程只会创建一次。为了使用我们的 TLS 变量，我们可以使用箭头(`->`)或星号(`*`)运算符来访问它的值。在这个例子中，我们在`for`循环的每个周期增加 TLS 值，直到达到限制为止。

这个例子表明，两个线程将生成自己的一系列 10 个整数，计数相同的数字而互不影响。

# 同步

POCO 提供的同步原语如下：

+   互斥量

+   FastMutex

+   事件

+   条件

+   信号量

+   RWLock

这里需要注意的是`FastMutex`类。这通常是一种非递归的互斥类型，只是在 Windows 上是递归的。这意味着人们通常应该假设任一类型在同一线程中可以多次锁定同一互斥量。

人们还可以使用`ScopedLock`类与互斥量一起使用，确保它封装的互斥量在当前作用域结束时被释放。

事件类似于 Windows 事件，只是它们限于单个进程。它们构成了 POCO 中条件变量的基础。

POCO 条件变量的功能与 Pthreads 等方式基本相同，只是它们不会出现虚假唤醒。通常情况下，条件变量会因为优化原因而出现这些随机唤醒。通过不需要显式检查条件变量等待返回时是否满足条件，减轻了开发者的负担。

# C++线程

C++中的本地多线程支持在第十二章中有详细介绍，*本地 C++线程和原语*。

正如本章中 Boost 部分提到的，C++多线程支持在很大程度上基于 Boost 线程 API，使用几乎相同的头文件和名称。API 本身再次让人联想到 Pthreads，尽管在某些方面有显著的不同，比如条件变量。

接下来的章节将专门使用 C++线程支持进行示例。

# 将它们组合在一起

在本章涵盖的 API 中，只有 Qt 多线程 API 可以被认为是真正高级的。尽管其他 API（包括 C++11）包含一些更高级的概念，包括线程池和异步运行器，不需要直接使用线程，但 Qt 提供了一个完整的信号-槽架构，使得线程间通信异常容易。

正如本章所介绍的，这种便利也伴随着一个代价，即需要开发应用程序以适应 Qt 框架。这可能在项目中是不可接受的。

哪种 API 是正确的取决于个人的需求。然而，可以相对公平地说，当可以使用 C++11 线程、POCO 等 API 时，使用直接的 Pthreads、Windows 线程等并没有太多意义，这些 API 可以在不显著降低性能的情况下轻松地实现跨平台。

所有这些 API 在核心功能上至少在某种程度上是可比较的。

# 总结

在本章中，我们详细介绍了一些较流行的多线程 API 和框架，将它们并列在一起，以了解它们的优势和劣势。我们通过一些示例展示了如何使用这些 API 来实现基本功能。

在下一章中，我们将详细介绍如何同步线程并在它们之间进行通信。


# 第十三章：线程同步和通信

一般来说，线程用于相对独立地处理任务，但有许多情况下，人们希望在线程之间传递数据，甚至控制其他线程，比如来自中央任务调度器线程。本章将介绍如何使用 C++11 线程 API 完成这些任务。

本章涵盖的主题包括以下内容：

+   使用互斥锁、锁和类似的同步结构

+   使用条件变量和信号来控制线程

+   安全地传递和共享线程之间的数据

# 安全第一

并发的核心问题在于确保在线程之间通信时对共享资源的安全访问。还有线程能够进行通信和同步的问题。

多线程编程的挑战在于能够跟踪线程之间的每次交互，并确保每种形式的访问都得到保护，同时不会陷入死锁和数据竞争的陷阱。

在本章中，我们将看一个涉及任务调度程序的相当复杂的例子。这是一种高并发、高吞吐量的情况，许多不同的要求与许多潜在的陷阱相结合，我们将在下面看到。

# 调度程序

具有大量同步和线程之间通信的多线程良好示例是任务调度。在这里，目标是尽快接受传入任务并将其分配给工作线程。

在这种情况下，有许多不同的方法可行。通常情况下，工作线程会在一个活跃的循环中运行，不断地轮询中央队列以获取新任务。这种方法的缺点包括在轮询上浪费处理器周期，以及在同步机制（通常是互斥锁）上形成的拥塞。此外，当工作线程数量增加时，这种主动轮询方法的扩展性非常差。

理想情况下，每个工作线程都会空闲等待直到再次需要它。为了实现这一点，我们必须从另一方面解决问题：不是从工作线程的角度，而是从队列的角度。就像操作系统的调度程序一样，调度程序既知道需要处理的任务，也知道可用的工作线程。

在这种方法中，一个中央调度程序实例将接受新任务并积极地将它们分配给工作线程。该调度程序实例还可以管理这些工作线程，例如它们的数量和优先级，具体取决于传入任务的数量和任务的类型或其他属性。

# 高层视图

在其核心，我们的调度程序或调度器非常简单，就像一个队列，所有调度逻辑都内置其中，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/289f6379-e42c-4b22-80de-d73338c3445d.png)

从前面的高层视图可以看出，实际上并没有太多内容。然而，正如我们将在下面看到的，实际实现确实有许多复杂之处。

# 实现

和往常一样，我们从`main`函数开始，它包含在`main.cpp`中：

```cpp
#include "dispatcher.h"
#include "request.h"

#include <iostream>
#include <string>
#include <csignal>
#include <thread>
#include <chrono>

using namespace std;

sig_atomic_t signal_caught = 0;
mutex logMutex; 
```

我们包含的自定义头文件是我们调度程序实现的头文件，以及我们将使用的`request`类。

在全局范围内，我们定义了一个用于信号处理程序的原子变量，以及一个将同步输出（在标准输出上）的互斥锁，用于我们的日志方法：

```cpp
void sigint_handler(int sig) {
    signal_caught = 1;
} 
```

我们的信号处理函数（用于`SIGINT`信号）只是设置了我们之前定义的全局原子变量：

```cpp
void logFnc(string text) {
    logMutex.lock();
    cout << text << "n";
    logMutex.unlock();
} 
```

在我们的日志函数中，我们使用全局互斥锁来确保对标准输出的写入是同步的：

```cpp
int main() {
    signal(SIGINT, &sigint_handler);
    Dispatcher::init(10); 
```

在`main`函数中，我们安装了`SIGINT`的信号处理程序，以允许我们中断应用程序的执行。我们还在`Dispatcher`类上调用静态的`init()`函数来初始化它：

```cpp
    cout << "Initialised.n";
        int cycles = 0;
    Request* rq = 0;
    while (!signal_caught && cycles < 50) {
        rq = new Request();
        rq->setValue(cycles);
        rq->setOutput(&logFnc);
        Dispatcher::addRequest(rq);
        cycles++;
    } 
```

接下来，我们设置循环，在其中我们将创建新的请求。在每个循环中，我们创建一个新的`Request`实例，并使用其`setValue()`函数设置一个整数值（当前循环编号）。在将此新请求添加到`Dispatcher`时，我们还在请求实例上设置了我们的日志函数，使用其静态的`addRequest()`函数。

这个循环将继续，直到达到最大循环次数，或者使用*Ctrl*+*C*或类似方法发出`SIGINT`信号为止：

```cpp
        this_thread::sleep_for(chrono::seconds(5));
        Dispatcher::stop();
    cout << "Clean-up done.n";
    return 0; 
} 
```

最后，我们使用线程的`sleep_for()`函数和`chrono`STL 头文件中的`chrono::seconds()`函数等待 5 秒。

在返回之前，我们还调用了`Dispatcher`上的`stop()`函数。

# 请求类

`Dispatcher`的请求始终派生自纯虚拟的`AbstractRequest`类：

```cpp
#pragma once
#ifndef ABSTRACT_REQUEST_H
#define ABSTRACT_REQUEST_H

class AbstractRequest {
    //
    public:
    virtual void setValue(int value) = 0;
    virtual void process() = 0;
    virtual void finish() = 0;
};
#endif 
```

这个`AbstractRequest`类定义了一个具有三个函数的 API，派生类总是必须实现这些函数。其中，`process()`和`finish()`函数是最通用的，可能在任何实际实现中使用。`setValue()`函数是特定于此演示实现的，可能会被调整或扩展以适应实际情况。

使用抽象类作为请求的基础的优势在于，它允许`Dispatcher`类处理许多不同类型的请求，只要它们都遵循相同的基本 API。

使用这个抽象接口，我们实现了一个基本的`Request`类如下所示：

```cpp
#pragma once
#ifndef REQUEST_H
#define REQUEST_H

#include "abstract_request.h"

#include <string>

using namespace std;

typedef void (*logFunction)(string text);

class Request : public AbstractRequest {
    int value;
    logFunction outFnc;
    public:    void setValue(int value) { this->value = value; }
    void setOutput(logFunction fnc) { outFnc = fnc; }
    void process();
    void finish();
};
#endif 
```

在其头文件中，我们首先定义了函数指针的格式。之后，我们实现了请求 API，并在基本 API 中添加了`setOutput()`函数，该函数接受用于记录日志的函数指针。这两个 setter 函数仅将提供的参数分配给它们各自的私有类成员。

接下来，类函数的实现如下所示：

```cpp
#include "request.h"
void Request::process() {
    outFnc("Starting processing request " + std::to_string(value) + "...");
    //
}
void Request::finish() {
    outFnc("Finished request " + std::to_string(value));
} 
```

这两个实现都非常基本；它们仅使用函数指针来输出指示工作线程状态的字符串。

在实际实现中，可以在`process()`函数中添加业务逻辑，而`finish()`函数包含完成请求的任何功能，例如将映射写入字符串。

# Worker 类

接下来是`Worker`类。这包含了`Dispatcher`将调用以处理请求的逻辑。

```cpp
#pragma once
#ifndef WORKER_H
#define WORKER_H

#include "abstract_request.h"

#include <condition_variable>
#include <mutex>

using namespace std;

class Worker {
    condition_variable cv;
    mutex mtx;
    unique_lock<mutex> ulock;
    AbstractRequest* request;
    bool running;
    bool ready;
    public:
    Worker() { running = true; ready = false; ulock = unique_lock<mutex>(mtx); }
    void run();
    void stop() { running = false; }
    void setRequest(AbstractRequest* request) { this->request = request; ready = true; }
    void getCondition(condition_variable* &cv);
};
#endif 
```

虽然将请求添加到`Dispatcher`不需要任何特殊逻辑，但`Worker`类确实需要使用条件变量来与调度程序同步。对于 C++11 线程 API，这需要一个条件变量、一个互斥锁和一个唯一锁。

唯一的锁封装了互斥锁，并最终将与条件变量一起使用，我们马上就会看到。

除此之外，我们定义了启动和停止工作线程的方法，设置要处理的新请求，并获取其内部条件变量的访问权限。

接下来，其余的实现如下所示：

```cpp
#include "worker.h"
#include "dispatcher.h"

#include <chrono>

using namespace std;

void Worker::getCondition(condition_variable* &cv) {
    cv = &(this)->cv;
}

void Worker::run() {
    while (running) {
        if (ready) {
            ready = false;
            request->process();
            request->finish();
        }
        if (Dispatcher::addWorker(this)) {
            // Use the ready loop to deal with spurious wake-ups.
            while (!ready && running) {
                if (cv.wait_for(ulock, chrono::seconds(1)) == cv_status::timeout) {
                    // We timed out, but we keep waiting unless  
                    // the worker is 
                    // stopped by the dispatcher. 
                }
            }
        }
    }
} 
```

除了条件变量的`getter`函数之外，我们定义了`run()`函数，`dispatcher`将在启动每个工作线程时运行它。

其主循环仅检查`stop()`函数是否已被调用，这会将运行布尔值设置为`false`，并结束工作线程。这是由`Dispatcher`在关闭时使用的，允许它终止工作线程。由于布尔值通常是原子的，因此可以同时设置和检查，而无需风险或需要互斥锁。

继续进行，`ready`变量的检查是为了确保在线程首次运行时实际上有一个请求在等待。在工作线程的第一次运行时，不会有请求在等待，因此，尝试处理一个请求将导致崩溃。在`Dispatcher`设置新请求时，这个布尔变量将被设置为`true`。

如果有请求在等待，`ready`变量将再次设置为`false`，之后请求实例将调用其`process()`和`finish()`函数。这将在工作线程的线程上运行请求的业务逻辑，并完成它。

最后，工作线程使用其静态的`addWorker()`函数将自己添加到调度程序。如果没有新请求可用，此函数将返回`false`，并导致工作线程等待直到有新请求可用。否则，工作线程将继续处理`Dispatcher`设置的新请求。

如果被要求等待，我们进入一个新的循环。这个循环将确保当条件变量被唤醒时，是因为我们收到了`Dispatcher`的信号（`ready`变量设置为`true`），而不是因为虚假唤醒。

最后，我们使用之前创建的唯一锁实例和超时进入条件变量的实际`wait()`函数。如果超时发生，我们可以终止线程，或者继续等待。在这里，我们选择什么都不做，只是重新进入等待循环。

# 调度程序

最后一项是`Dispatcher`类本身：

```cpp
    #pragma once
    #ifndef DISPATCHER_H
    #define DISPATCHER_H

    #include "abstract_request.h"
    #include "worker.h"

    #include <queue>
    #include <mutex>
    #include <thread>
    #include <vector>

    using namespace std;

    class Dispatcher {
        static queue<AbstractRequest*> requests;
        static queue<Worker*> workers;
        static mutex requestsMutex;
        static mutex workersMutex;
        static vector<Worker*> allWorkers;
        static vector<thread*> threads;
        public:
        static bool init(int workers);
        static bool stop();
        static void addRequest(AbstractRequest* request);
        static bool addWorker(Worker* worker);
     };
     #endif 
```

大部分内容都很熟悉。到目前为止，您已经推测到，这是一个完全静态的类。

接下来，它的实现如下：

```cpp
    #include "dispatcher.h"

    #include <iostream>
    using namespace std;

    queue<AbstractRequest*> Dispatcher::requests;
    queue<Worker*> Dispatcher::workers;
    mutex Dispatcher::requestsMutex;
    mutex Dispatcher::workersMutex;
    vector<Worker*> Dispatcher::allWorkers;
    vector<thread*> Dispatcher::threads; 

    bool Dispatcher::init(int workers) {
        thread* t = 0;
        Worker* w = 0;
        for (int i = 0; i < workers; ++i) {
            w = new Worker;
            allWorkers.push_back(w);
            t = new thread(&Worker::run, w);
            threads.push_back(t);
        }
   return true;
 } 
```

设置静态类成员后，定义了`init()`函数。它启动指定数量的工作线程，并在各自的向量数据结构中保留对每个工作线程和线程实例的引用：

```cpp
    bool Dispatcher::stop() {
        for (int i = 0; i < allWorkers.size(); ++i) {
            allWorkers[i]->stop();
        }
            cout << "Stopped workers.n";
            for (int j = 0; j < threads.size(); ++j) {
            threads[j]->join();
                    cout << "Joined threads.n";
        }
    }
```

在`stop()`函数中，每个工作实例都调用其`stop()`函数。这将导致每个工作线程终止，就像我们在`Worker`类描述中看到的那样。

最后，我们等待每个线程加入（即完成）后再返回：

```cpp
    void Dispatcher::addRequest(AbstractRequest* request) {
        workersMutex.lock();
        if (!workers.empty()) {
            Worker* worker = workers.front();
            worker->setRequest(request);
            condition_variable* cv;
            worker->getCondition(cv);
            cv->notify_one();
            workers.pop();
            workersMutex.unlock();
        }
        else {
            workersMutex.unlock();
            requestsMutex.lock();
            requests.push(request);
            requestsMutex.unlock();
        }
    } 
```

`addRequest()`函数是有趣的地方。在这个函数中，添加了一个新的请求。接下来会发生什么取决于是否有工作线程在等待新请求。如果没有工作线程在等待（工作队列为空），则将请求添加到请求队列。

互斥锁的使用确保对这些队列的访问是安全的，因为工作线程将同时尝试访问这两个队列。

这里需要注意的一个重要问题是死锁的可能性。也就是说，两个线程将持有资源的锁，第二个线程在释放自己的锁之前等待第一个线程释放锁。在单个作用域中使用多个互斥锁的每种情况都存在这种潜力。

在这个函数中，死锁的潜在可能性在于释放工作线程互斥锁，并在获取请求互斥锁时。在这个函数持有工作线程互斥锁并尝试获取请求锁（当没有工作线程可用时），有可能另一个线程持有请求互斥锁（寻找要处理的新请求），同时尝试获取工作线程互斥锁（找不到请求并将自己添加到工作线程队列）。

解决方法很简单：在获取下一个互斥锁之前释放一个互斥锁。在一个人觉得必须持有多个互斥锁的情况下，非常重要的是检查和测试潜在死锁的代码。在这种特殊情况下，当不再需要时，或在获取请求互斥锁之前，显式释放工作线程互斥锁，从而防止死锁。

这段代码的另一个重要方面是它如何通知工作线程。正如我们在 if/else 块的第一部分中看到的，当工作线程队列不为空时，从队列中获取一个工作线程，设置请求，然后引用并发出条件变量的信号或通知。

在内部，条件变量使用我们在`Worker`类定义中提供的互斥锁，以确保对它的原子访问。当在条件变量上调用`notify_one()`函数（在其他 API 中通常称为`signal()`）时，它将通知等待条件变量返回并继续的线程队列中的第一个线程。

在`Worker`类的`run()`函数中，我们将等待此通知事件。收到通知后，工作线程将继续处理新请求。然后，线程引用将从队列中删除，直到它再次添加自己，一旦完成请求处理：

```cpp
    bool Dispatcher::addWorker(Worker* worker) {
        bool wait = true;
        requestsMutex.lock();
        if (!requests.empty()) {
            AbstractRequest* request = requests.front();
            worker->setRequest(request);
            requests.pop();
            wait = false;
            requestsMutex.unlock();
        }
        else {
            requestsMutex.unlock();
            workersMutex.lock();
            workers.push(worker);
            workersMutex.unlock();
        }
            return wait;
    } 
```

通过这个最后一个函数，工作线程在完成请求处理后会将自己添加到队列中。它类似于之前的函数，即首先将传入的工作线程与可能在请求队列中等待的任何请求进行匹配。如果没有可用的请求，工作线程将被添加到工作线程队列中。

在这里需要注意的是，我们返回一个布尔值，指示调用线程是否应该等待新请求，还是在尝试将自己添加到队列时已经收到了新请求。

虽然这段代码比之前的函数更简单，但由于在同一范围内处理了两个互斥锁，它仍然存在潜在的死锁问题。在这里，我们首先释放我们持有的互斥锁，然后再获取下一个互斥锁。

# Makefile

这个`Dispatcher`示例的 makefile 非常基本--它收集当前文件夹中的所有 C++源文件，并使用`g++`将它们编译成一个二进制文件：

```cpp
    GCC := g++

    OUTPUT := dispatcher_demo
    SOURCES := $(wildcard *.cpp)
    CCFLAGS := -std=c++11 -g3

    all: $(OUTPUT)
        $(OUTPUT):
        $(GCC) -o $(OUTPUT) $(CCFLAGS) $(SOURCES)
        clean:
        rm $(OUTPUT)
        .PHONY: all
```

# 输出

编译应用程序后，运行它会产生以下输出，总共有 50 个请求：

```cpp
    $ ./dispatcher_demo.exe
    Initialised.
    Starting processing request 1...
    Starting processing request 2...
    Finished request 1
    Starting processing request 3...
    Finished request 3
    Starting processing request 6...
    Finished request 6
    Starting processing request 8...
    Finished request 8
    Starting processing request 9...
    Finished request 9
    Finished request 2
    Starting processing request 11...
    Finished request 11
    Starting processing request 12...
    Finished request 12
    Starting processing request 13...
    Finished request 13
    Starting processing request 14...
    Finished request 14
    Starting processing request 7...
    Starting processing request 10...
    Starting processing request 15...
    Finished request 7
    Finished request 15
    Finished request 10
    Starting processing request 16...
    Finished request 16
    Starting processing request 17...
    Starting processing request 18...
    Starting processing request 0...
```

在这一点上，我们已经清楚地看到，即使每个请求几乎不需要时间来处理，请求显然是并行执行的。第一个请求（请求 0）只在第 16 个请求之后开始处理，而第二个请求在第九个请求之后就已经完成了。

决定首先处理哪个线程和因此哪个请求的因素取决于操作系统调度程序和基于硬件的调度，如第九章中所述，“处理器和操作系统上的多线程实现”。这清楚地显示了即使在单个平台上，也不能对多线程应用程序的执行做出多少假设。

```cpp
    Starting processing request 5...
    Finished request 5
    Starting processing request 20...
    Finished request 18
    Finished request 20
    Starting processing request 21...
    Starting processing request 4...
    Finished request 21
    Finished request 4   
```

在前面的代码中，第四个和第五个请求也以相当延迟的方式完成。

```cpp

    Starting processing request 23...
    Starting processing request 24...
    Starting processing request 22...
    Finished request 24
    Finished request 23
    Finished request 22
    Starting processing request 26...
    Starting processing request 25...
    Starting processing request 28...
    Finished request 26
    Starting processing request 27...
    Finished request 28
    Finished request 27
    Starting processing request 29...
    Starting processing request 30...
    Finished request 30
    Finished request 29
    Finished request 17
    Finished request 25
    Starting processing request 19...
    Finished request 0
```

在这一点上，第一个请求终于完成了。这可能表明，与后续请求相比，第一个请求的初始化时间总是会延迟。多次运行应用程序可以确认这一点。重要的是，如果处理顺序很重要，这种随机性不会对应用程序产生负面影响。

```cpp
    Starting processing request 33...
    Starting processing request 35...
    Finished request 33
    Finished request 35
    Starting processing request 37...
    Starting processing request 38...
    Finished request 37
    Finished request 38
    Starting processing request 39...
    Starting processing request 40...
    Starting processing request 36...
    Starting processing request 31...
    Finished request 40
    Finished request 39
    Starting processing request 32...
    Starting processing request 41...
    Finished request 32
    Finished request 41
    Starting processing request 42...
    Finished request 31
    Starting processing request 44...
    Finished request 36
    Finished request 42
    Starting processing request 45...
    Finished request 44
    Starting processing request 47...
    Starting processing request 48...
    Finished request 48
    Starting processing request 43...
    Finished request 47
    Finished request 43
    Finished request 19
    Starting processing request 34...
    Finished request 34
    Starting processing request 46...
    Starting processing request 49...
    Finished request 46
    Finished request 49
    Finished request 45
```

第 19 个请求也变得相当延迟，再次显示了多线程应用程序有多么不可预测。如果我们在这里并行处理大型数据集，每个请求中都有数据块，我们可能需要在某些时候暂停以考虑这些延迟，否则我们的输出缓存可能会变得太大。

由于这样做会对应用程序的性能产生负面影响，人们可能不得不考虑低级优化，以及在特定处理器核心上对线程进行调度，以防止这种情况发生。

```cpp
    Stopped workers.
    Joined threads.
    Joined threads.
    Joined threads.
    Joined threads.
    Joined threads.
    Joined threads.
    Joined threads.
    Joined threads.
    Joined threads.
    Joined threads.
    Clean-up done.
```

最初启动的 10 个工作线程在这里终止，因为我们调用了`Dispatcher`的`stop()`函数。

# 数据共享

在本章给出的示例中，我们看到了如何在线程之间共享信息以及同步线程--这是通过从主线程传递给调度程序的请求，每个请求都会传递给不同的线程。

线程之间共享数据的基本思想是要共享的数据以某种方式存在，可以被两个或更多个线程访问。之后，我们必须确保只有一个线程可以修改数据，并且在读取数据时数据不会被修改。通常，我们会使用互斥锁或类似的方法来确保这一点。

# 使用读写锁

读写锁在这里是一种可能的优化，因为它允许多个线程同时从单个数据源读取。如果一个应用程序中有多个工作线程反复读取相同的信息，使用读写锁比基本的互斥锁更有效，因为读取数据的尝试不会阻塞其他线程。

读写锁因此可以被用作互斥锁的更高级版本，即根据访问类型调整其行为。在内部，它建立在互斥锁（或信号量）和条件变量之上。

# 使用共享指针

首先通过 Boost 库提供，并在 C++11 中引入，共享指针是使用引用计数对堆分配实例进行内存管理的抽象。它们在某种程度上是线程安全的，因为可以创建多个共享指针实例，但引用的对象本身不是线程安全的。

根据应用程序的情况，这可能就足够了。要使它们真正线程安全，可以使用原子操作。我们将在第十五章中更详细地讨论这个问题，*原子操作 - 与硬件交互*。

# 总结

在本章中，我们看了如何在一个相当复杂的调度器实现中以安全的方式在线程之间传递数据。我们还看了所述调度器的结果异步处理，并考虑了一些潜在的替代方案和优化方法来在线程之间传递数据。

在这一点上，你应该能够安全地在线程之间传递数据，以及同步访问其他共享资源。

在下一章中，我们将看一下本地 C++线程和基元 API。


# 第十四章：本地 C++线程和原语

从 2011 年的 C++标准修订版开始，多线程 API 正式成为 C++**标准模板库**（**STL**）的一部分。这意味着线程、线程原语和同步机制对于任何新的 C++应用程序都是可用的，无需安装第三方库或依赖操作系统的 API。

本章将介绍本地 API 中可用的多线程功能，直到 2014 年标准添加的功能。将展示一些示例以详细使用这些功能。

本章的主题包括以下内容：

+   C++ STL 中的多线程 API 提供的功能

+   每个功能的详细使用示例

# STL 线程 API

在第十章中，*C++多线程 API*，我们看了一下在开发多线程 C++应用程序时可用的各种 API。在第十一章中，*线程同步和通信*，我们使用本地 C++线程 API 实现了一个多线程调度程序应用程序。

# Boost.Thread API

通过包含 STL 中的`<thread>`头文件，我们可以访问`std::thread`类，该类具有由其他头文件提供的互斥（互斥锁等）设施。这个 API 本质上与`Boost.Thread`的多线程 API 相同，主要区别在于对线程的更多控制（带超时的加入，线程组和线程中断），以及在原语（如互斥锁和条件变量）之上实现的一些额外的锁类型。

一般来说，当 C++11 支持不可用时，或者这些额外的`Boost.Thread`功能是应用程序的要求，并且不容易以其他方式添加时，应该使用`Boost.Thread`作为备用。由于`Boost.Thread`建立在可用的（本地）线程支持之上，因此与 C++11 STL 实现相比，它还可能增加开销。

# 2011 年标准

C++标准的 2011 年修订版（通常称为 C++11）增加了许多新功能，其中最关键的是添加了本地多线程支持，这增加了在 C++中创建、管理和使用线程的能力，而无需使用第三方库。

这个标准为核心语言规范了内存模型，允许多个线程共存，并启用了诸如线程本地存储之类的功能。C++03 标准中已经添加了初始支持，但 C++11 标准是第一个充分利用这一特性的标准。

如前所述，实际的线程 API 本身是在 STL 中实现的。C++11（C++0x）标准的一个目标是尽可能多地将新功能放入 STL 中，而不是作为核心语言的一部分。因此，为了使用线程、互斥锁等，必须首先包含相关的 STL 头文件。

负责新多线程 API 的标准委员会各自设定了自己的目标，因此一些希望加入的功能最终未能成为标准的一部分。这包括终止另一个线程或线程取消等功能，这些功能受到 POSIX 代表的强烈反对，因为取消线程可能会导致正在销毁的线程资源清理出现问题。

以下是此 API 实现提供的功能：

+   `std::thread`

+   `std::mutex`

+   `std::recursive_mutex`

+   `std::condition_variable`

+   `std::condition_variable_any`

+   `std::lock_guard`

+   `std::unique_lock`

+   `std::packaged_task`

+   `std::async`

+   `std::future`

接下来，我们将详细介绍每个功能的示例。首先，我们将看看 C++标准的下一个修订版本添加了哪些初始功能。

# C++14

2014 年的标准向标准库添加了以下功能：

+   `std::shared_lock`

+   `std::shared_timed_mutex`

这两者都在`<shared_mutex>`STL 头文件中定义。由于锁是基于互斥锁的，因此共享锁依赖于共享互斥锁。

# 线程类

`thread`类是整个线程 API 的核心；它包装了底层操作系统的线程，并提供了我们启动和停止线程所需的功能。

通过包含`<thread>`头文件，可以访问此功能。

# 基本用法

创建线程后立即启动：

```cpp
#include <thread> 

void worker() { 
   // Business logic. 
} 

int main () { 
   std::thread t(worker);
   return 0; 
} 
```

上述代码将启动线程，然后立即终止应用程序，因为我们没有等待新线程执行完毕。

为了正确执行这个操作，我们需要等待线程完成，或者重新加入如下：

```cpp
#include <thread> 

void worker() { 
   // Business logic. 
} 

int main () { 
   std::thread t(worker); 
   t.join(); 
   return 0; 
} 
```

这段代码将执行，等待新线程完成，然后返回。

# 传递参数

也可以向新线程传递参数。这些参数值必须是可移动构造的，这意味着它是一个具有移动或复制构造函数（用于右值引用）的类型。实际上，对于所有基本类型和大多数（用户定义的）类来说，这是成立的：

```cpp
#include <thread> 
#include <string> 

void worker(int n, std::string t) { 
   // Business logic. 
} 

int main () { 
   std::string s = "Test"; 
   int i = 1; 
   std::thread t(worker, i, s); 
   t.join(); 
   return 0; 
} 
```

在上述代码中，我们将一个整数和一个字符串传递给`thread`函数。该函数将接收这两个变量的副本。当传递引用或指针时，生命周期问题、数据竞争等会变得更加复杂，可能会成为一个问题。

# 返回值

传递给`thread`类构造函数的函数返回的任何值都将被忽略。要将信息返回给创建新线程的线程，必须使用线程间同步机制（如互斥锁）和某种共享变量。

# 移动线程

2011 年的标准在`<utility>`头文件中添加了`std::move`。使用这个模板方法，可以在对象之间移动资源。这意味着它也可以移动线程实例：

```cpp
#include <thread> 
#include <string> 
#include <utility> 

void worker(int n, string t) { 
   // Business logic. 
} 

int main () { 
   std::string s = "Test"; 
   std::thread t0(worker, 1, s); 
   std::thread t1(std::move(t0)); 
   t1.join(); 
   return 0; 
} 
```

在这个版本的代码中，我们在将线程移动到另一个线程之前创建了一个线程。因此线程 0 停止存在（因为它立即完成），并且`thread`函数的执行在我们创建的新线程中恢复。

因此，我们不必等待第一个线程重新加入，只需要等待第二个线程。

# 线程 ID

每个线程都有一个与之关联的标识符。这个 ID 或句柄是 STL 实现提供的唯一标识符。可以通过调用`thread`类实例的`get_id()`函数或调用`std::this_thread::get_id()`来获取调用该函数的线程的 ID：

```cpp
#include <iostream>
 #include <thread>
 #include <chrono>
 #include <mutex>

 std::mutex display_mutex;

 void worker() {
     std::thread::id this_id = std::this_thread::get_id();

     display_mutex.lock();
     std::cout << "thread " << this_id << " sleeping...n";
     display_mutex.unlock();

     std::this_thread::sleep_for(std::chrono::seconds(1));
 }

 int main() {
    std::thread t1(worker);
    std::thread::id t1_id = t1.get_id();

    std::thread t2(worker);
    std::thread::id t2_id = t2.get_id();

    display_mutex.lock();
    std::cout << "t1's id: " << t1_id << "n";
    std::cout << "t2's id: " << t2_id << "n";
    display_mutex.unlock();

    t1.join();
    t2.join();

    return 0;
 } 

```

这段代码将产生类似于以下的输出：

```cpp
t1's id: 2
t2's id: 3
thread 2 sleeping...
thread 3 sleeping...
```

在这里，可以看到内部线程 ID 是一个整数（`std::thread::id`类型），相对于初始线程（ID 为 1）。这类似于大多数本机线程 ID，比如 POSIX 的线程 ID。这些也可以使用`native_handle()`获得。该函数将返回底层的本机线程句柄。当希望使用 STL 实现中不可用的特定 PThread 或 Win32 线程功能时，这是特别有用的。

# 休眠

可以使用两种方法延迟执行线程（休眠）。一种是`sleep_for()`，它至少延迟指定的持续时间，但可能更长：

```cpp
#include <iostream> 
#include <chrono> 
#include <thread> 
        using namespace std::chrono_literals;

        typedef std::chrono::time_point<std::chrono::high_resolution_clock> timepoint; 
int main() { 
         std::cout << "Starting sleep.n"; 

         timepoint start = std::chrono::high_resolution_clock::now(); 

         std::this_thread::sleep_for(2s); 

         timepoint end = std::chrono::high_resolution_clock::now(); 
         std::chrono::duration<double, std::milli> elapsed = end - 
         start; 
         std::cout << "Slept for: " << elapsed.count() << " msn"; 
} 
```

上述代码展示了如何休眠大约 2 秒，使用具有当前操作系统上可能的最高精度的计数器来测量确切的持续时间。

请注意，我们可以直接指定秒数，使用秒后缀。这是 C++14 添加到`<chrono>`头文件的功能。对于 C++11 版本，需要创建一个 std::chrono::seconds 的实例并将其传递给`sleep_for()`函数。

另一种方法是`sleep_until()`，它接受一个类型为`std::chrono::time_point<Clock, Duration>`的单个参数。使用这个函数，可以设置线程休眠，直到达到指定的时间点。由于操作系统的调度优先级，这个唤醒时间可能不是指定的确切时间。

# 屈服

可以告诉操作系统当前线程可以重新调度，以便其他线程可以运行。为此，可以使用`std::this_thread::yield()`函数。此函数的确切结果取决于底层操作系统实现及其调度程序。在 FIFO 调度程序的情况下，调用线程可能会被放在队列的末尾。

这是一个高度专业化的函数，具有特殊的用例。在未验证其对应用程序性能的影响之前，不应使用它。

# 分离

启动线程后，可以在线程对象上调用`detach()`。这实际上将新线程与调用线程分离，这意味着前者将在调用线程退出后继续执行。

# 交换

使用`swap()`，可以作为独立方法或作为线程实例的函数，可以交换线程对象的基础线程句柄：

```cpp
#include <iostream> 
#include <thread> 
#include <chrono> 

void worker() { 
   std::this_thread::sleep_for(std::chrono::seconds(1)); 
} 

int main() { 
         std::thread t1(worker); 
         std::thread t2(worker); 

         std::cout << "thread 1 id: " << t1.get_id() << "n"; 
         std::cout << "thread 2 id: " << t2.get_id() << "n"; 

         std::swap(t1, t2); 

         std::cout << "Swapping threads..." << "n"; 

         std::cout << "thread 1 id: " << t1.get_id() << "n"; 
         std::cout << "thread 2 id: " << t2.get_id() << "n"; 

         t1.swap(t2); 

         std::cout << "Swapping threads..." << "n"; 

         std::cout << "thread 1 id: " << t1.get_id() << "n"; 
         std::cout << "thread 2 id: " << t2.get_id() << "n"; 

         t1.join(); 
         t2.join(); 
} 
```

此代码的可能输出如下：

```cpp
thread 1 id: 2
thread 2 id: 3
Swapping threads...
thread 1 id: 3
thread 2 id: 2
Swapping threads...
thread 1 id: 2
thread 2 id: 3
```

其效果是每个线程的状态与另一个线程的状态交换，实质上交换了它们的身份。

# 互斥锁

`<mutex>`头文件包含多种类型的互斥锁和锁。互斥锁类型是最常用的类型，提供基本的锁定/解锁功能，没有更多的复杂性。

# 基本用法

在本质上，互斥锁的目标是排除同时访问的可能性，以防止数据损坏，并防止由于使用非线程安全例程而导致崩溃。

一个需要使用互斥锁的示例代码如下：

```cpp
#include <iostream> 
#include <thread> 

void worker(int i) { 
         std::cout << "Outputting this from thread number: " << i << "n"; 
} 

int main() { 
         std::thread t1(worker, 1);
         std::thread t2(worker, 2); 

         t1.join(); 
   t2.join(); 

   return 0; 
} 
```

如果一个人尝试直接运行上述代码，就会注意到两个线程的文本输出会被混在一起，而不是依次输出。原因是标准输出（无论是 C 还是 C++风格）不是线程安全的。虽然应用程序不会崩溃，但输出会是一团糟。

对此的修复很简单，如下所示：

```cpp
#include <iostream> 
#include <thread> 
#include <mutex> 

std::mutex globalMutex; 

void worker(int i) { 
   globalMutex.lock(); 
         std::cout << "Outputting this from thread number: " << i << "n"; 
   globalMutex.unlock(); 
} 

int main() { 
         std::thread t1(worker, 1);
         std::thread t2(worker, 2); 

         t1.join(); 
   t2.join(); 

   return 0; 
} 
```

在这种情况下，每个线程首先需要获取`mutex`对象的访问权。由于只有一个线程可以访问`mutex`对象，另一个线程将等待第一个线程完成对标准输出的写入，两个字符串将按预期依次出现。

# 非阻塞锁定

可能不希望线程阻塞并等待`mutex`对象可用：例如，当一个人只想知道是否另一个线程已经处理了请求，并且没有必要等待其完成时。

为此，互斥锁带有`try_lock()`函数，可以做到这一点。

在下面的示例中，我们可以看到两个线程尝试递增相同的计数器，但是当一个线程无法立即访问共享计数器时，它会递增自己的计数器：

```cpp
#include <chrono> 
#include <mutex> 
#include <thread> 
#include <iostream> 

std::chrono::milliseconds interval(50); 

std::mutex mutex; 
int shared_counter = 0;
int exclusive_counter = 0; 

void worker0() { 
   std::this_thread::sleep_for(interval);

         while (true) { 
               if (mutex.try_lock()) { 
                     std::cout << "Shared (" << job_shared << ")n"; 
                     mutex.unlock(); 
                     return; 
               } 
         else { 
                     ++exclusive_counter; 
                           std::cout << "Exclusive (" << exclusive_counter << ")n"; 
                           std::this_thread::sleep_for(interval); 
               } 
         } 
} 

void worker1() { 
   mutex.lock(); 
         std::this_thread::sleep_for(10 * interval); 
         ++shared_counter; 
         mutex.unlock(); 
} 

int main() { 
         std::thread t1(worker0); 
         std::thread t2(worker1); 

         t1.join(); 
         t2.join(); 
}
```

在上述示例中，两个线程运行不同的`worker`函数，但它们都有一个共同点，即它们都会在一段时间内休眠，并在醒来时尝试获取共享计数器的互斥锁。如果成功，它们将增加计数器，但只有第一个工作线程会输出这个事实。

第一个工作线程还会记录当它没有获得共享计数器时，但只增加了它自己的独立计数器。结果输出可能看起来像这样：

```cpp
Exclusive (1)
Exclusive (2)
Exclusive (3)
Shared (1)
Exclusive (4)
```

# 定时互斥锁

定时互斥锁是常规互斥锁类型，但具有一些额外的函数，可以控制在尝试获取锁期间的时间段，即`try_lock_for`和`try_lock_until`。

前者在指定的时间段（`std::chrono`对象）内尝试获取锁，然后返回结果（true 或 false）。后者将等待直到将来的特定时间点，然后返回结果。

这些功能的使用主要在于提供常规互斥锁的阻塞（`lock`）和非阻塞（`try_lock`）方法之间的中间路径。一个人可能希望使用单个线程等待一些任务，而不知道何时任务将变为可用，或者任务可能在某个特定时间点过期，此时等待它就不再有意义了。

# 锁卫

锁卫是一个简单的互斥锁包装器，它处理对`mutex`对象的锁定以及在锁卫超出范围时的释放。这是一个有用的机制，可以确保不会忘记释放互斥锁，并且在必须在多个位置释放相同的互斥锁时，可以帮助减少代码的混乱。

尽管重构，例如大的 if/else 块可以减少需要释放互斥锁的情况，但最好还是使用这个锁卫包装器，不用担心这些细节：

```cpp
#include <thread> 
#include <mutex> 
#include <iostream> 

int counter = 0; 
std::mutex counter_mutex; 

void worker() { 
         std::lock_guard<std::mutex> lock(counter_mutex); 
   if (counter == 1) { counter += 10; } 
   else if (counter >= 10) { counter += 15; } 
   else if (counter >= 50) { return; } 
         else { ++counter; } 

   std::cout << std::this_thread::get_id() << ": " << counter << 'n'; 
} 

int main() { 
    std::cout << __func__ << ": " << counter << 'n'; 

    std::thread t1(worker); 
    std::thread t2(worker); 

    t1.join(); 
    t2.join(); 

    std::cout << __func__ << ": " << counter << 'n'; 
} 
```

在前面的例子中，我们看到一个小的 if/else 块，其中一个条件导致`worker`函数立即返回。如果没有锁卫，我们必须确保在从函数返回之前在此条件下也解锁互斥锁。

然而，有了锁卫，我们就不必担心这些细节，这使我们可以专注于业务逻辑，而不是担心互斥锁管理。

# 唯一锁

唯一锁是一个通用的互斥锁包装器。它类似于定时互斥锁，但具有附加功能，主要是所有权的概念。与其他锁类型不同，唯一锁不一定拥有它包装的互斥锁，如果有的话。互斥锁可以在唯一锁实例之间以及使用`swap()`函数转移这些互斥锁的所有权。

唯一锁实例是否拥有其互斥锁的所有权，以及它是否被锁定或未锁定，是在创建锁时首先确定的，可以从其构造函数中看到。例如：

```cpp
std::mutex m1, m2, m3; 
std::unique_lock<std::mutex> lock1(m1, std::defer_lock); 
std::unique_lock<std::mutex> lock2(m2, std::try_lock); 
std::unique_lock<std::mutex> lock3(m3, std::adopt_lock); 
```

最后一个代码中的第一个构造函数不锁定分配的互斥锁（延迟）。第二个尝试使用`try_lock()`锁定互斥锁。最后，第三个构造函数假定它已经拥有提供的互斥锁。

除此之外，其他构造函数允许定时互斥锁的功能。也就是说，它将等待一段时间，直到达到某个时间点，或者直到获得锁。

最后，使用`release()`函数可以断开锁与互斥锁之间的关联，并返回`mutex`对象的指针。然后调用者负责释放互斥锁上的任何剩余锁，并进一步处理它。

这种类型的锁通常不会单独使用，因为它非常通用。大多数其他类型的互斥锁和锁都要简单得多，并且可能在 99%的情况下满足所有需求。唯一锁的复杂性因此既是优点也是风险。

然而，它通常被 C++11 线程 API 的其他部分使用，例如我们马上就会看到的条件变量。

唯一锁可能有用的一个领域是作为作用域锁，允许使用作用域锁而不必依赖 C++17 标准中的原生作用域锁。看这个例子：

```cpp
#include <mutex>
std::mutex my_mutex
int count = 0;
int function() {
         std::unique_lock<mutex> lock(my_mutex);
   count++;
}  
```

当我们进入函数时，我们使用全局互斥锁实例创建一个新的 unique_lock。在这一点上，互斥锁被锁定，之后我们可以执行任何关键操作。

当函数作用域结束时，唯一锁的析构函数被调用，这导致互斥锁再次被解锁。

# 作用域锁

作用域锁是在 2017 年标准中首次引入的，它是一个互斥锁包装器，用于获取（锁定）提供的互斥锁，并确保在作用域锁超出范围时解锁。它与锁卫的不同之处在于它是多个互斥锁的包装器，而不是一个。

当在单个作用域中处理多个互斥时，这可能是有用的。使用作用域锁的一个原因是为了避免意外引入死锁和其他不愉快的复杂情况，例如一个互斥被作用域锁锁定，另一个锁仍在等待，另一个线程实例具有完全相反的情况。

作用域锁的一个特性是，它试图避免这种情况，从理论上讲，使得这种类型的锁具有死锁安全性。

# 递归互斥

递归互斥是互斥的另一种子类型。尽管它具有与常规互斥完全相同的功能，但它允许最初锁定互斥的调用线程重复锁定同一互斥。通过这样做，互斥在拥有线程解锁它的次数与锁定它的次数相同之前，不会对其他线程可用。

使用递归互斥的一个很好的理由是，例如在使用递归函数时。使用常规互斥时，需要发明某种进入点，在进入递归函数之前锁定互斥。

使用递归互斥时，递归函数的每次迭代都会再次锁定递归互斥，并在完成一次迭代后解锁互斥。结果是互斥锁定和解锁的次数相同。

因此，这里可能存在的一个复杂情况是，递归互斥可以被锁定的最大次数在标准中没有定义。当达到实现的限制时，如果尝试锁定它，将抛出`std::system_error`，或者在使用非阻塞的`try_lock`函数时返回 false。

# 递归定时互斥

递归定时互斥是，正如其名称所示，定时互斥和递归互斥功能的融合。因此，它允许使用定时条件函数递归锁定互斥。

尽管这增加了确保互斥锁定的次数与线程锁定次数相同的挑战，但它仍然为更复杂的算法提供了可能性，比如前面提到的任务处理程序。

# 共享互斥

`<shared_mutex>`头文件是在 2014 年标准中首次添加的，通过添加`shared_timed_mutex`类。在 2017 年标准中，还添加了`shared_mutex`类。

自 C++17 以来，共享互斥头文件一直存在。除了通常的互斥访问之外，这个`mutex`类还增加了提供互斥访问的能力。这允许多个线程对资源进行读访问，而写线程仍然可以获得独占访问。这类似于 Pthreads 的读写锁。

添加到这种互斥类型的函数如下：

+   `lock_shared()`

+   `try_lock_shared()`

+   `unlock_shared()`

这种互斥的共享功能的使用应该是相当不言自明的。理论上，无限数量的读者可以获得对互斥的读访问，同时确保只有一个线程可以随时写入资源。

# 共享定时互斥

这个头文件自 C++14 以来一直存在。它通过这些函数向定时互斥添加了共享锁定功能：

+   `lock_shared()`

+   `try_lock_shared()`

+   `try_lock_shared_for()`

+   `try_lock_shared_until()`

+   `unlock_shared()`

这个类本质上是共享互斥和定时互斥的融合，正如其名称所示。这里有趣的是，它在更基本的共享互斥之前被添加到了标准中。

# 条件变量

从本质上讲，条件变量提供了一种机制，通过这种机制，一个线程的执行可以被另一个线程控制。这是通过一个共享变量来实现的，一个线程会等待这个变量，直到被另一个线程发出信号。这是我们在第十一章中看到的调度器实现的一个基本部分，*线程同步和通信*。

对于 C++11 API，条件变量及其相关功能在`<condition_variable>`头文件中定义。

条件变量的基本用法可以从第十一章的调度器代码中总结出来，*线程同步和通信*。

```cpp
 #include "abstract_request.h"

 #include <condition_variable>
 #include <mutex> 

using namespace std;

 class Worker {
    condition_variable cv;
    mutex mtx;
    unique_lock<mutex> ulock;
    AbstractRequest* request;
    bool running;
    bool ready;
    public:
    Worker() { running = true; ready = false; ulock = unique_lock<mutex>(mtx); }
    void run();
    void stop() { running = false; }
    void setRequest(AbstractRequest* request) { this->request = request; ready = true; }
    void getCondition(condition_variable* &cv);
 }; 
```

在前面的`Worker`类声明中定义的构造函数中，我们看到了 C++11 API 中条件变量的初始化方式。步骤如下：

1.  创建`condition_variable`和`mutex`实例。

1.  将互斥锁分配给一个新的`unique_lock`实例。使用我们在这里用于锁的构造函数，分配的互斥锁也在分配时被锁定。

1.  条件变量现在可以使用了：

```cpp
#include <chrono>
using namespace std;
void Worker::run() {
    while (running) {
        if (ready) {
            ready = false;
            request->process();
            request->finish();
        }
        if (Dispatcher::addWorker(this)) {
            while (!ready && running) {
                if (cv.wait_for(ulock, chrono::seconds(1)) == 
                cv_status::timeout) {
                    // We timed out, but we keep waiting unless the 
                    worker is
                    // stopped by the dispatcher.
                }
            }
        }
    }
} 
```

在这里，我们使用条件变量的`wait_for()`函数，并传递我们之前创建的唯一锁实例和我们想要等待的时间。这里我们等待 1 秒。如果我们在这个等待中超时，我们可以自由地重新进入等待（就像这里做的那样）在一个连续的循环中，或者继续执行。

还可以使用简单的`wait()`函数执行阻塞等待，或者使用`wait_for()`等待到某个特定的时间点。

正如我们之前看到的，这个工作线程的代码使用`ready`布尔变量的原因是为了检查是否真的是另一个线程发出了条件变量的信号，而不仅仅是一个虚假的唤醒。这是大多数条件变量实现（包括 C++11）都容易受到的不幸的复杂性。

由于这些随机唤醒事件，有必要确保我们确实是有意醒来的。在调度器代码中，这是通过唤醒工作线程的线程也设置一个`Boolean`值来完成的，工作线程可以唤醒。

我们是否超时，或者被通知，或者遭受虚假唤醒，都可以通过`cv_status`枚举来检查。这个枚举知道这两种可能的情况：

+   `timeout`

+   `no_timeout`

信号或通知本身非常简单：

```cpp
void Dispatcher::addRequest(AbstractRequest* request) {
    workersMutex.lock();
    if (!workers.empty()) {
          Worker* worker = workers.front();
          worker->setRequest(request);
          condition_variable* cv;
          worker->getCondition(cv);
          cv->notify_one();
          workers.pop();
          workersMutex.unlock();
    }
    else {
          workersMutex.unlock();
          requestsMutex.lock();
          requests.push(request);
          requestsMutex.unlock();
    }
          } 
```

在`Dispatcher`类的前面的函数中，我们尝试获取一个可用的工作线程实例。如果找到，我们按如下方式获取对工作线程条件变量的引用：

```cpp
void Worker::getCondition(condition_variable* &cv) {
    cv = &(this)->cv;
 } 
```

设置工作线程上的新请求也会将`ready`变量的值更改为 true，从而允许工作线程检查它确实被允许继续。

最后，条件变量被通知，任何等待它的线程现在可以继续使用`notify_one()`。这个特定的函数将信号传递给条件变量中 FIFO 队列中的第一个线程。在这里，只有一个线程会被通知，但如果有多个线程在等待相同的条件变量，调用`notify_all()`将允许 FIFO 队列中的所有线程继续。

# Condition_variable_any

`condition_variable_any`类是`condition_variable`类的泛化。它与后者的不同之处在于它允许使用除`unique_lock<mutex>`之外的其他互斥机制。唯一的要求是所使用的锁符合`BasicLockable`的要求，这意味着它提供了`lock()`和`unlock()`函数。

# 在线程退出时通知所有

`std::notify_all_at_thread_exit()`函数允许（分离的）线程通知其他线程它已经完全完成，并且正在销毁其范围内的所有对象（线程本地）。它的功能是在发出提供的条件变量信号之前将提供的锁移动到内部存储中。

结果就像锁被解锁并且在条件变量上调用了`notify_all()`一样。

可以给出一个基本（非功能性）示例如下：

```cpp
#include <mutex> 
#include <thread> 
#include <condition_variable> 
using namespace std; 

mutex m; 
condition_variable cv;
bool ready = false; 
ThreadLocal result;

void worker() { 
   unique_lock<mutex> ulock(m); 
   result = thread_local_method(); 
         ready = true; 
         std::notify_all_at_thread_exit(cv, std::move(ulock)); 
} 

int main() { 
         thread t(worker); 
         t.detach(); 

         // Do work here. 

         unique_lock<std::mutex> ulock(m); 
         while(!ready) { 
               cv.wait(ulock); 
         } 

         // Process result 
} 
```

在这里，工作线程执行一个创建线程本地对象的方法。因此，主线程必须首先等待分离的工作线程完成。如果主线程完成任务时后者尚未完成，它将使用全局条件变量进入等待。在工作线程中，设置`ready`布尔值后，调用`std::notify_all_at_thread_exit()`。

这样做有两个目的。在调用函数后，不允许更多的线程等待条件变量。它还允许主线程等待分离的工作线程的结果变得可用。

# Future

C++11 线程支持 API 的最后一部分在`<future>`中定义。它提供了一系列类，实现了更高级的多线程概念，旨在更容易地进行异步处理，而不是实现多线程架构。

在这里，我们必须区分两个概念：`future`和`promise`。前者是最终结果（未来的产品），将被读取者/消费者使用。后者是写入者/生产者使用的。

`future`的一个基本示例是：

```cpp
#include <iostream>
#include <future>
#include <chrono>

bool is_prime (int x) {
  for (int i = 2; i < x; ++i) if (x%i==0) return false;
  return true;
}

int main () {
  std::future<bool> fut = std::async (is_prime, 444444443);
  std::cout << "Checking, please wait";
  std::chrono::milliseconds span(100);
  while (fut.wait_for(span) == std::future_status::timeout) {               std::cout << '.' << std::flush;
   }

  bool x = fut.get();
  std::cout << "n444444443 " << (x?"is":"is not") << " prime.n";
  return 0;
}
```

这段代码异步调用一个函数，传递一个参数（可能是质数）。然后它进入一个活动循环，同时等待异步函数调用返回的`future`完成。它在等待函数上设置了 100 毫秒的超时。

一旦`future`完成（在等待函数上没有超时），我们就可以获得结果值，本例中告诉我们提供给函数的值实际上是一个质数。

在本章的*async*部分，我们将更详细地看一下异步函数调用。

# Promise

`promise`允许在线程之间传输状态。例如：

```cpp
#include <iostream> 
#include <functional>
#include <thread> 
#include <future> 

void print_int (std::future<int>& fut) {
  int x = fut.get();
  std::cout << "value: " << x << 'n';
}

int main () {
  std::promise<int> prom;
  std::future<int> fut = prom.get_future();
  std::thread th1 (print_int, std::ref(fut));
  prom.set_value (10);                            
  th1.join();
  return 0;
```

上面的代码使用了传递给工作线程的`promise`实例，以将一个值传输到另一个线程，本例中是一个整数。新线程等待我们从`promise`创建的`future`完成，这个`future`是从主线程接收到的。

当我们在`promise`上设置值时，`promise`就完成了。这完成了`future`并结束了工作线程。

在这个特定的例子中，我们对`future`对象进行了阻塞等待，但也可以使用`wait_for()`和`wait_until()`，分别等待一段时间或一个时间点，就像我们在上一个例子中对`future`进行的操作一样。

# 共享 future

`shared_future`就像一个普通的`future`对象一样，但可以被复制，这允许多个线程读取其结果。

创建一个`shared_future`与创建一个普通的`future`类似。

```cpp
std::promise<void> promise1; 
std::shared_future<void> sFuture(promise1.get_future()); 
```

最大的区别是普通的`future`被传递给它的构造函数。

之后，所有可以访问`future`对象的线程都可以等待它，并获取其值。这也可以用于类似条件变量的方式来通知线程。

# 包装任务

`packaged_task`是任何可调用目标（函数、绑定、lambda 或其他函数对象）的包装器。它允许异步执行，并将结果可用于`future`对象。它类似于`std::function`，但自动将其结果传输到`future`对象。

例如：

```cpp
#include <iostream> 
#include <future> 
#include <chrono>
#include <thread>

using namespace std; 

int countdown (int from, int to) { 
   for (int i = from; i != to; --i) { 
         cout << i << 'n'; 
         this_thread::sleep_for(chrono::seconds(1)); 
   } 

   cout << "Finished countdown.n"; 
   return from - to; 
} 

int main () { 
   packaged_task<int(int, int)> task(countdown);
   future<int> result = task.get_future();
   thread t (std::move(task), 10, 0);

   //  Other logic. 

   int value = result.get(); 

   cout << "The countdown lasted for " << value << " seconds.n"; 

   t.join(); 
   return 0; 
} 
```

上面的代码实现了一个简单的倒计时功能，从 10 倒数到 0。创建任务并获取其`future`对象的引用后，我们将其推送到一个线程，同时传递`worker`函数的参数。

倒计时工作线程的结果在完成后立即可用。我们可以使用`future`对象的等待函数，方式与`promise`一样。 

# Async

`promise`和`packaged_task`的更简单的版本可以在`std::async()`中找到。这是一个简单的函数，它接受一个可调用对象（函数、绑定、lambda 等）以及它的任何参数，并返回一个`future`对象。

以下是`async()`函数的一个基本示例：

```cpp
#include <iostream>
#include <future>

using namespace std; 

bool is_prime (int x) { 
   cout << "Calculating prime...n"; 
   for (int i = 2; i < x; ++i) { 
         if (x % i == 0) { 
               return false; 
         } 
   } 

   return true; 
} 

int main () { 
   future<bool> pFuture = std::async (is_prime, 343321); 

   cout << "Checking whether 343321 is a prime number.n"; 

   // Wait for future object to be ready. 

   bool result = pFuture.get(); 
   if (result) {
         cout << "Prime found.n"; 
   } 
   else { 
         cout << "No prime found.n"; 
   } 

   return 0; 
} 
```

前面代码中的`worker`函数确定提供的整数是否为质数。正如我们所看到的，结果代码比使用`packaged_task`或`promise`要简单得多。

# 启动策略

除了`std::async()`的基本版本之外，还有第二个版本，允许将启动策略作为其第一个参数进行指定。这是一个`std::launch`类型的位掩码值，可能的取值如下：

```cpp
* launch::async 
* launch::deferred 
```

`async`标志意味着立即为`worker`函数创建一个新线程和执行上下文。`deferred`标志意味着这将被推迟，直到在`future`对象上调用`wait()`或`get()`。指定两个标志会导致函数根据当前系统情况自动选择方法。

未明确指定位掩码值的`std::async()`版本默认为后者，即自动方法。

# 原子操作

在多线程中，原子操作的使用也非常重要。C++11 STL 出于这个原因提供了一个`<atomic>`头文件。这个主题在第十五章中得到了广泛覆盖，即*原子操作-与硬件交互*。

# 总结

在本章中，我们探讨了 C++11 API 中的整个多线程支持，以及 C++14 和 C++17 中添加的特性。

我们看到了如何使用描述和示例代码来使用每个特性。现在我们可以使用本机 C++多线程 API 来实现多线程、线程安全的代码，以及使用异步执行特性来加速并并行执行函数。

在下一章中，我们将看一下多线程代码实现中不可避免的下一步：调试和验证所得应用程序。
