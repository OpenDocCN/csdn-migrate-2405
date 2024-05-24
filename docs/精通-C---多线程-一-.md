# 精通 C++ 多线程（一）

> 原文：[`annas-archive.org/md5/D8BD7CE4843A1A81E0B93B3CA07CBEC9`](https://annas-archive.org/md5/D8BD7CE4843A1A81E0B93B3CA07CBEC9)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

多线程应用程序在单处理器环境中执行多个线程，以实现。本书充满了实际示例，将帮助您成为在 C++中编写健壮的并发和并行应用程序的专家。在本书中，您将深入了解多线程和并发的基础知识，并了解如何实现它们。在此过程中，您将探索原子操作以优化代码性能，并将并发应用于分布式计算和 GPGPU 处理。

# 本书涵盖的内容

第一章《重新审视多线程》总结了 C++中的多线程，重新审视了您应该已经熟悉的所有概念，并通过使用 C++ 2011 修订版中添加的本机线程支持进行了多线程的基本示例。

第二章《处理器和操作系统上的多线程实现》在前一章讨论的硬件实现提供的基础上构建，展示了操作系统如何利用这些功能并使其可用于应用程序。它还讨论了进程和线程如何允许使用内存和处理器，以防止应用程序和线程相互干扰。

第三章《C++多线程 API》探讨了各种多线程 API，这些 API 可以作为操作系统级 API（例如 Win32 和 POSIX）提供，也可以作为框架（例如 Boost、Qt 和 POCO）提供。它简要介绍了每个 API，列出了与其他 API 相比的差异，以及它可能对您的应用程序具有的优势和劣势。

第四章《线程同步和通信》将前几章学到的主题，探讨了使用 C++ 14 的本机线程 API 实现的高级多线程实现，允许多个线程在没有任何线程安全问题的情况下进行通信。它还涵盖了许多类型的同步机制之间的区别，包括互斥锁、锁和条件变量。

第五章《本机 C++线程和原语》包括线程、并发、本地存储，以及该 API 支持的线程安全性。在前一章的示例基础上，它讨论并探讨了如何使用 C++ 11 和 C++ 14 提供的完整功能集来扩展和优化线程安全性。

第六章《调试多线程代码》教会您如何使用诸如 Valgrind（Memcheck、DRD、Helgrind 等）之类的工具来分析应用程序的多线程性能，找到热点，并解决或预防由并发访问导致的问题。

第七章《最佳实践》涵盖了常见的陷阱和注意事项，以及如何在它们回来困扰你之前发现它们。它还通过示例探讨了许多常见和不太常见的场景。

第八章《原子操作-与硬件一起工作》详细介绍了原子操作：它们是什么以及如何最好地使用它们。评估了跨 CPU 架构的编译器支持，并评估了在代码中实现原子操作是否值得投入时间。它还探讨了这种优化如何限制代码的可移植性。

第九章，*使用分布式计算进行多线程*，汲取了前几章的教训，并将它们应用到多系统、集群级别的规模上。使用基于 OpenMPI 的示例，它展示了如何在多个系统上进行多线程处理，比如计算机集群中的节点。

第十章，*使用 GPGPU 进行多线程*，展示了在 GPGPU 应用程序中使用多线程的情况（例如，CUDA 和 OpenCL）。使用基于 OpenCL 的示例，探讨了一个基本的多线程应用程序，可以并行执行任务。本章汲取了前几章的教训，并将其应用于视频卡和衍生硬件（例如，机架式矢量处理器硬件）上的处理。

# 您需要什么

要按照本书中的说明，您需要在系统上安装任何操作系统（Windows、Linux 或 macOS）和任何 C++编译器。

# 本书适用对象

本书适用于希望扩展多线程和并发处理知识的中级 C++开发人员。您应该具有多线程的基本经验，并且能够在命令行上使用 C++开发工具链。

# 约定

在这本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是这些样式的一些示例以及它们的含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“`randGen()`方法接受两个参数，定义返回值的范围：”

代码块设置如下：

```cpp
cout_mtx.lock();
 cout << "Thread " << tid << " adding " << rval << ". New value: " << val << ".\n";
 cout_mtx.unlock();

 values_mtx.lock();
 values.push_back(val);
 values_mtx.unlock();
}

```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```cpp
cout_mtx.lock();
 cout << "Thread " << tid << " adding " << rval << ". New value: " << val << ".\n";
 cout_mtx.unlock();

 values_mtx.lock();
 values.push_back(val);
 values_mtx.unlock();
}

```

任何命令行输入或输出都以以下方式编写：

```cpp
$ make
g++ -o ch01_mt_example -std=c++11 ch01_mt_example.cpp

```

新术语和重要单词以粗体显示。例如，屏幕上看到的单词，比如菜单或对话框中的单词，会出现在文本中。

警告或重要说明会出现在这样的地方。

提示和技巧会出现在这样的地方。

# 第一章：重新审视多线程

如果您正在阅读本书，很可能您已经在 C++中进行了一些多线程编程，或者可能是其他语言。本章旨在从 C++的角度纯粹回顾这个主题，通过一个基本的多线程应用程序，同时也涵盖了本书中将要使用的工具。在本章结束时，您将拥有继续阅读后续章节所需的所有知识和信息。

本章涵盖的主题包括以下内容：

+   使用本地 API 在 C++中进行基本的多线程

+   编写基本的 makefile 和使用 GCC/MinGW

+   使用`make`编译程序并在命令行上执行

# 入门

在本书的过程中，我们将假设使用基于 GCC 的工具链（在 Windows 上是 GCC 或 MinGW）。如果您希望使用其他工具链（如 clang、MSVC、ICC 等），请查阅这些工具链提供的文档以获取兼容的命令。

为了编译本书提供的示例，将使用 makefile。对于不熟悉 makefile 的人来说，它们是一种简单但功能强大的基于文本的格式，用于与`make`工具一起自动化构建任务，包括编译源代码和调整构建环境。`make`于 1977 年首次发布，至今仍然是最受欢迎的构建自动化工具之一。

假设您熟悉命令行（Bash 或等效），并且建议使用 MSYS2（Windows 上的 Bash）。

# 多线程应用程序

在其最基本的形式中，多线程应用程序由一个具有两个或多个线程的进程组成。这些线程可以以各种方式使用；例如，通过使用一个线程来处理每个传入事件或事件类型，使进程能够以异步方式响应事件，或者通过将工作分配到多个线程中来加快数据处理速度。

对事件的异步响应的示例包括在单独的线程上处理图形用户界面（GUI）和网络事件，以便两种类型的事件都不必等待对方，也不会阻止事件及时得到响应。通常，一个线程执行一个任务，比如处理 GUI 或网络事件，或者处理数据。

对于这个基本示例，应用程序将以一个单一线程开始，然后启动多个线程，并等待它们完成。每个新线程将在完成之前执行自己的任务。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00005.gif)

让我们从应用程序的包含和全局变量开始：

```cpp
#include <iostream>
#include <thread>
#include <mutex>
#include <vector>
#include <random>

using namespace std;

// --- Globals
mutex values_mtx;
mutex cout_mtx;
vector<int> values;

```

I/O 流和向量头文件对于任何使用过 C++的人来说应该是很熟悉的：前者用于标准输出（`cout`），而向量用于存储一系列的值。

`c++11`中的 random 头文件是新的，顾名思义，它提供了用于生成随机序列的类和方法。我们在这里使用它来使我们的线程做一些有趣的事情。

最后，线程和互斥锁的包含是我们多线程应用程序的核心；它们提供了创建线程的基本手段，并允许它们之间进行线程安全的交互。

接下来，我们创建两个互斥锁：一个用于全局向量，一个用于`cout`，因为后者不是线程安全的。

接下来，我们创建主函数如下：

```cpp
int main() {
    values.push_back(42);

```

我们将一个固定值推送到向量实例中；这个值将在我们稍后创建的线程中使用：

```cpp
    thread tr1(threadFnc, 1);
    thread tr2(threadFnc, 2);
    thread tr3(threadFnc, 3);
    thread tr4(threadFnc, 4);

```

我们创建新线程，并为它们提供要使用的方法的名称，同时传递任何参数--在这种情况下，只是一个整数：

```cpp

    tr1.join();
    tr2.join();
    tr3.join();
    tr4.join();

```

接下来，我们通过在每个线程实例上调用`join()`来等待每个线程完成：

```cpp

    cout << "Input: " << values[0] << ", Result 1: " << values[1] << ", Result 2: " << values[2] << ", Result 3: " << values[3] << ", Result 4: " << values[4] << "\n";

    return 1;
}

```

在这一点上，我们期望每个线程都已经完成了它应该做的事情，并将结果添加到向量中，然后我们读取并向用户显示。

当然，这几乎没有显示应用程序中真正发生的事情，主要只是使用线程的基本简单性。接下来，让我们看看我们传递给每个线程实例的方法内部发生了什么：

```cpp
void threadFnc(int tid) {
    cout_mtx.lock();
    cout << "Starting thread " << tid << ".\n";
    cout_mtx.unlock();

```

在前面的代码中，我们可以看到传递给线程方法的整数参数是线程标识符。为了指示线程正在启动，输出包含线程标识符的消息。由于我们在这里使用了`非线程安全`方法，我们使用`cout_mtx`互斥实例来安全地执行此操作，确保只有一个线程可以在任何时候写入`cout`：

```cpp
    values_mtx.lock();
    int val = values[0];
    values_mtx.unlock();

```

当我们获得向量中的初始值集时，我们将其复制到一个局部变量中，以便我们可以立即释放向量的互斥锁，使其他线程可以使用该向量：

```cpp
    int rval = randGen(0, 10);
    val += rval;

```

最后两行包含了线程创建的本质：它们获取初始值，并向其添加一个随机生成的值。`randGen()`方法接受两个参数，定义返回值的范围：

```cpp

    cout_mtx.lock();
    cout << "Thread " << tid << " adding " << rval << ". New value: " << val << ".\n";
    cout_mtx.unlock();

    values_mtx.lock();
    values.push_back(val);
    values_mtx.unlock();
}

```

最后，我们（安全地）记录一条消息，通知用户此操作的结果，然后将新值添加到向量中。在这两种情况下，我们使用相应的互斥锁来确保在使用其他线程访问资源时不会发生重叠。

一旦方法达到这一点，包含它的线程将终止，主线程将少一个要等待重新加入的线程。线程的加入基本上意味着它停止存在，通常会将返回值传递给创建线程的线程。这可以显式发生，主线程等待子线程完成，或者在后台进行。

最后，让我们来看看`randGen()`方法。在这里，我们可以看到一些多线程特定的添加：

```cpp
int randGen(const int& min, const int& max) {
    static thread_local mt19937 generator(hash<thread::id>()(this_thread::get_id()));
    uniform_int_distribution<int> distribution(min, max);
    return distribution(generator)
}

```

前面的方法接受一个最小值和最大值，如前所述，限制了此方法可以返回的随机数的范围。在其核心，它使用基于 mt19937 的`generator`，它采用了一个具有 19937 位状态大小的 32 位**Mersenne Twister**算法。这对于大多数应用程序来说是一个常见且合适的选择。

这里需要注意的是`thread_local`关键字的使用。这意味着即使它被定义为静态变量，其范围也将被限制在使用它的线程中。因此，每个线程都将创建自己的`generator`实例，在 STL 中使用随机数 API 时这一点很重要。

内部线程标识符的哈希用作`generator`的种子。这确保每个线程都为其`generator`实例获得一个相当独特的种子，从而获得更好的随机数序列。

最后，我们使用提供的最小和最大限制创建一个新的`uniform_int_distribution`实例，并与`generator`实例一起使用它来生成我们返回的随机数。

# Makefile

为了编译前面描述的代码，可以使用 IDE，或者在命令行上输入命令。正如本章开头提到的，我们将在本书的示例中使用 makefile。这样做的重大优势是不必反复输入相同的广泛命令，并且它可以在支持`make`的任何系统上使用。

进一步的优点包括能够自动删除先前生成的工件，并且只编译那些已更改的源文件，以及对构建步骤的详细控制。

这个示例的 makefile 相当基本：

```cpp
GCC := g++

OUTPUT := ch01_mt_example
SOURCES := $(wildcard *.cpp)
CCFLAGS := -std=c++11 -pthread

all: $(OUTPUT)

$(OUTPUT):
    $(GCC) -o $(OUTPUT) $(CCFLAGS) $(SOURCES)

clean:
    rm $(OUTPUT)

.PHONY: all

```

从上到下，我们首先定义我们将使用的编译器（`g++`），设置输出二进制文件的名称（在 Windows 上的`.exe`扩展名将自动添加后缀），然后收集源文件和任何重要的编译器标志。

通配符功能允许一次性收集与其后的字符串匹配的所有文件的名称，而无需单独定义文件夹中每个源文件的名称。

对于编译器标志，我们只对启用`c++11`功能感兴趣，对于这一点，GCC 仍然需要提供这个编译器标志。

对于`all`方法，我们只需告诉`make`使用提供的信息运行`g++`。接下来，我们定义一个简单的清理方法，只需删除生成的二进制文件，最后，我们告诉`make`不要解释文件夹或文件夹中名为`all`的任何文件，而是使用带有`.PHONY`部分的内部方法。

当我们运行这个 makefile 时，我们看到以下命令行输出：

```cpp
$ make
g++ -o ch01_mt_example -std=c++11 ch01_mt_example.cpp

```

之后，在同一文件夹中找到一个名为`ch01_mt_example`（在 Windows 上附加了`.exe`扩展名）的可执行文件。执行此二进制文件将导致类似以下的命令行输出：

```cpp
$ ./ch01_mt_example.exe

Starting thread 1.

Thread 1 adding 8\. New value: 50.

Starting thread 2.

Thread 2 adding 2\. New value: 44.

Starting thread 3.

Starting thread 4.

Thread 3 adding 0\. New value: 42.

Thread 4 adding 8\. New value: 50.

Input: 42, Result 1: 50, Result 2: 44, Result 3: 42, Result 4: 50

```

在这里可以看到线程及其输出的异步性质。虽然线程`1`和`2`似乎是同步运行的，按顺序启动和退出，但线程`3`和`4`显然是异步运行的，因为它们在记录其动作之前同时启动。因此，在长时间运行的线程中，几乎不可能确定日志输出和结果将以何种顺序返回。

虽然我们使用一个简单的向量来收集线程的结果，但无法确定`Result 1`是否真的来自我们在开始时分配 ID 为 1 的线程。如果我们需要这些信息，我们需要通过使用包含有关处理线程或类似信息的信息结构来扩展我们返回的数据。

例如，可以像这样使用`struct`：

```cpp
struct result {
    int tid;
    int result;
};

```

然后，向量将被更改为包含结果实例而不是整数实例。可以直接将初始整数值作为其参数之一传递给线程，或者通过其他方式传递。

# 其他应用程序

本章的示例主要适用于需要并行处理数据或任务的应用程序。对于前面提到的基于 GUI 的应用程序，具有业务逻辑和网络相关功能，启动所需线程的主应用程序的基本设置将保持不变。但是，每个线程都将是完全不同的方法，而不是每个线程都相同。

对于这种类型的应用程序，线程布局将如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00006.gif)

如图所示，主线程将启动 GUI、网络和业务逻辑线程，后者将与网络线程通信以发送和接收数据。业务逻辑线程还将从 GUI 线程接收用户输入，并发送更新以在 GUI 上显示。

# 总结

在本章中，我们讨论了使用本机线程 API 在 C++中实现多线程应用程序的基础知识。我们看了如何让多个线程并行执行任务，并探讨了如何在多线程应用程序中正确使用 STL 中的随机数 API。

在下一章中，我们将讨论多线程是如何在硬件和操作系统中实现的。我们将看到这种实现如何根据处理器架构和操作系统而异，以及这如何影响我们的多线程应用程序。


# 第二章：处理器和操作系统上的多线程实现

任何多线程应用程序的基础是由处理器硬件实现所需功能以及这些功能如何被操作系统转换为应用程序使用的 API 所形成的。了解这个基础对于开发对多线程应用程序的最佳实现方式至关重要。

本章将探讨多年来硬件和操作系统是如何演变到当前的实现和 API 的，展示了前一章的示例代码最终如何转换为对处理器和相关硬件的命令。

本章涵盖的主题包括以下内容：

+   为了支持多线程概念而发展的处理器硬件的演变

+   操作系统如何改变以使用这些硬件特性

+   各种架构中内存安全和内存模型背后的概念

+   操作系统之间各种进程和线程模型的差异

# 定义进程和线程

基本上，对于**操作系统**（**OS**）来说，一个进程由一个或多个线程组成，每个线程处理自己的状态和变量。可以将其视为分层配置，操作系统作为基础，为（用户）进程的运行提供支持。然后，每个进程由一个或多个线程组成。进程之间的通信由操作系统提供的**进程间通信**（**IPC**）来处理。

在图形视图中，这看起来像下面这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00007.gif)

操作系统中的每个进程都有自己的状态，进程中的每个线程也有自己的状态，相对于该进程中的其他线程。虽然 IPC 允许进程之间进行通信，但线程可以以各种方式与进程内的其他线程进行通信，我们将在接下来的章节中更深入地探讨这些方式。这通常涉及线程之间的某种共享内存。

应用程序是从特定的可执行格式的二进制数据中加载的，例如，**可执行和可链接格式**（**ELF**），通常用于 Linux 和许多其他操作系统。对于 ELF 二进制文件，应该始终存在以下数量的部分：

+   `.bss`

+   `.data`

+   `.rodata`

+   `.text`

`.bss`部分基本上是分配未初始化的内存，包括空数组，因此在可执行文件中不占用任何空间，因为在可执行文件中存储纯零行是没有意义的。类似地，还有`.data`部分包含初始化数据。其中包括全局表、变量等。最后，`.rodata`部分类似于`.data`，但正如其名称所示，是只读的。其中包含硬编码的字符串等内容。

在`.text`部分，我们找到实际的应用程序指令（代码），这些指令将由处理器执行。整个内容将被操作系统加载，从而创建一个进程。这样的进程布局如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00008.gif)

这是从 ELF 格式二进制文件启动时进程的样子，尽管在内存中的最终格式在基本上任何操作系统中都大致相同，包括从 PE 格式二进制文件启动的 Windows 进程。二进制文件中的每个部分都加载到它们各自的部分中，BSS 部分分配给指定的大小。`.text`部分与其他部分一起加载，并且一旦完成，将执行其初始指令，从而启动进程。

在诸如 C++之类的系统语言中，可以看到在这样的进程中变量和其他程序状态信息是如何存储在堆栈（变量存在于作用域内）和堆（使用 new 运算符）中的。堆栈是内存的一部分（每个线程分配一个），其大小取决于操作系统及其配置。在创建新线程时，通常也可以通过编程方式设置堆栈大小。

在操作系统中，一个进程由一块内存地址组成，其大小由其内存指针的大小限制。对于 32 位操作系统，这将限制该块为 4GB。在这个虚拟内存空间中，操作系统分配了一个基本的堆栈和堆，两者都可以增长，直到所有内存地址都被耗尽，进程进一步尝试分配更多内存将被拒绝。

堆栈对操作系统和硬件都是一个概念。本质上，它是一组所谓的堆栈帧的集合，每个堆栈帧由与任务的执行框架相关的变量、指令和其他数据组成。

从硬件角度来看，堆栈是任务（x86）或进程状态（ARM）的一部分，这是处理器定义执行实例（程序或线程）的方式。这个硬件定义的实体包含了一个线程的整个状态。有关此内容的更多详细信息，请参见以下各节。

# x86（32 位和 64 位）中的任务

在 Intel IA-32 系统编程指南第 3A 卷中，任务定义如下：

“任务是处理器可以分派、执行和挂起的工作单元。它可以用于执行程序、任务或进程、操作系统服务实用程序、中断或异常处理程序，或内核或执行实用程序。”

“IA-32 架构提供了一种保存任务状态、分派任务执行和从一个任务切换到另一个任务的机制。在保护模式下，所有处理器执行都是在任务内部进行的。即使是简单的系统也必须定义至少一个任务。更复杂的系统可以使用处理器的任务管理设施来支持多任务应用程序。”

IA-32（Intel x86）手册中的这段摘录总结了硬件如何支持和实现对操作系统、进程以及这些进程之间的切换的支持。

重要的是要意识到，对于处理器来说，没有进程或线程这样的东西。它所知道的只是执行线程，定义为一系列指令。这些指令被加载到内存的某个地方，并且当前位置和变量数据（变量）的创建情况都在进程的数据部分中被跟踪，当应用程序在数据部分中执行时。

每个任务也在硬件定义的保护环中运行，操作系统的任务通常在环 0 上运行，用户任务在环 3 上运行。环 1 和 2 很少被使用，除非在 x86 架构的现代操作系统中有特定的用例。这些环是硬件强制执行的特权级别，例如严格分离内核和用户级任务。

32 位和 64 位任务的任务结构在概念上非常相似。它的官方名称是**任务状态结构**（**TSS**）。对于 32 位 x86 CPU，它的布局如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00009.gif)

以下是字段：

+   **SS0**：第一个堆栈段选择器字段

+   **ESP0**：第一个 SP 字段

对于 64 位 x86_64 CPU，TSS 布局看起来有些不同，因为在这种模式下不支持基于硬件的任务切换：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00010.gif)

在这里，我们有类似的相关字段，只是名称不同：

+   **RSPn**：特权级别 0 到 2 的 SP

+   **ISTn**：中断堆栈表指针

尽管在 32 位模式下，x86 CPU 支持任务之间的硬件切换，但大多数操作系统将每个 CPU 仅使用单个 TSS 结构，而不管模式如何，并且在软件中实际执行任务之间的切换。这部分是出于效率原因（仅交换变化的指针），部分是由于只有通过这种方式才可能的功能，例如测量进程/线程使用的 CPU 时间，并调整线程或进程的优先级。在软件中执行此操作还简化了代码在 64 位和 32 位系统之间的可移植性，因为前者不支持基于硬件的任务切换。

在基于软件的任务切换期间（通常通过中断），ESP/RSP 等存储在内存中，并用下一个计划任务的值替换。这意味着一旦执行恢复，TSS 结构现在将具有新任务的**堆栈指针**（**SP**）、段指针、寄存器内容和所有其他细节。

中断的来源可以是基于硬件或软件。硬件中断通常由设备用于向 CPU 发出信号，表示它们需要 OS 的注意。调用硬件中断的行为称为中断请求，或 IRQ。

软件中断可能是由 CPU 本身的异常条件引起的，也可能是 CPU 指令集的一个特性。OS 内核通过触发软件中断来执行任务切换的操作。

# ARM 中的进程状态

在 ARM 架构中，应用程序通常在非特权的**异常级别 0**（**EL0**）级别运行，这与 x86 架构上的 ring 3 相当，而 OS 内核在 EL1 中。ARMv7（AArch32，32 位）架构将 SP 放在通用寄存器 13 中。对于 ARMv8（AArch64，64 位），为每个异常级别实现了一个专用的 SP 寄存器：`SP_EL0`，`SP_EL1`等。

对于任务状态，ARM 架构使用**程序状态寄存器**（**PSR**）实例来表示**当前程序状态寄存器**（**CPSR**）或**保存的程序状态寄存器**（**SPSR**）程序状态寄存器。PSR 是**进程状态**（**PSTATE**）的一部分，它是进程状态信息的抽象。

虽然 ARM 架构与 x86 架构有很大不同，但在使用基于软件的任务切换时，基本原则并未改变：保存当前任务的 SP，寄存器状态，并在恢复处理之前将下一个任务的详细信息放入其中。

# 堆栈

正如我们在前面的部分中看到的，堆栈与 CPU 寄存器一起定义了一个任务。正如前面提到的，这个堆栈由堆栈帧组成，每个堆栈帧定义了该特定任务执行实例的（局部）变量、参数、数据和指令。值得注意的是，尽管堆栈和堆栈帧主要是软件概念，但它是任何现代操作系统的重要特性，在许多 CPU 指令集中有硬件支持。从图形上看，可以像下面这样进行可视化：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00011.jpeg)

SP（x86 上的 ESP）指向堆栈顶部，另有另一个指针（x86 上的扩展基指针（EBP））。每个帧包含对前一个帧的引用（调用者返回地址），由操作系统设置。

在使用调试器与 C++应用程序时，当请求回溯时，基本上就是看到了堆栈的各个帧，显示了一直到当前帧的初始堆栈帧。在这里，可以检查每个单独帧的细节。

# 定义多线程

在过去的几十年中，与计算机处理任务方式相关的许多不同术语已经被创造并广泛使用。其中许多也被交替使用，正确与否。其中一个例子是多线程与多处理的比较。

在这里，后者意味着在具有多个物理处理器的系统中每个处理器运行一个任务，而前者意味着在单个处理器上同时运行多个任务，从而产生它们都在同时执行的错觉：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00012.gif)

多处理和多任务之间的另一个有趣区别是，后者使用时间片来在单个处理器核上运行多个线程。这与多线程不同，因为在多任务系统中，没有任务会在同一 CPU 核上以并发方式运行，尽管任务仍然可以被中断。

从软件角度来看，进程和进程内的线程之间共享的内存空间的概念是多线程系统的核心。尽管硬件通常不知道这一点--只看到操作系统中的单个任务。然而，这样的多线程进程包含两个或多个线程。每个线程都执行自己的一系列任务。

在其他实现中，例如英特尔的 x86 处理器上的**超线程**（**HT**），这种多线程是在硬件中实现的，通常被称为 SMT（有关详细信息，请参见*同时多线程（SMT）*部分）。启用 HT 后，每个物理 CPU 核被呈现给操作系统为两个核。硬件本身将尝试同时执行分配给这些所谓的虚拟核心的任务，并安排可以同时使用处理核心的不同元素的操作。实际上，这可以在不需要任何类型的优化的操作系统或应用程序的情况下显着提高性能。

当然，操作系统仍然可以进行自己的调度，以进一步优化任务的执行，因为硬件对其正在执行的指令的许多细节并不知情。

启用 HT 的外观如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00013.jpeg)

在上述图形中，我们看到内存（RAM）中四个不同任务的指令。其中两个任务（线程）同时执行，CPU 的调度器（在前端）试图安排指令，以便尽可能多地并行执行指令。在这种情况下不可能时，会出现所谓的流水线气泡（白色），表示执行硬件处于空闲状态。

加上内部 CPU 优化，这导致了非常高的指令吞吐量，也称为**每秒指令数**（**IPC**）。与 CPU 的 GHz 评级不同，这个 IPC 数字通常更重要，用于确定 CPU 的性能。

# 弗林分类

不同类型的计算机架构使用迈克尔·J·弗林在 1966 年首次提出的系统进行分类。这个分类系统有四个类别，根据处理硬件的输入和输出流的数量来定义其能力：

+   **单指令，单数据**（**SISD**）：单个指令被提取以操作单个数据流。这是 CPU 的传统模型。

+   **单指令，多数据**（**SIMD**）：使用这种模型，单个指令可以并行操作多个数据流。这是图形处理单元（**GPU**）等矢量处理器使用的模型。

+   **多指令，单数据**（**MISD**）：这个模型最常用于冗余系统，通过不同的处理单元对相同的数据执行相同的操作，最终验证结果以检测硬件故障。这通常由航空电子系统等使用。

+   **多指令，多数据**（**MIMD**）：对于这个模型，多处理系统非常适用。多个处理器上的多个线程处理多个数据流。这些线程不是相同的，就像 SIMD 一样。

需要注意的一点是，这些类别都是根据多处理来定义的，这意味着它们指的是硬件的固有能力。使用软件技术，几乎可以在甚至是常规的 SISD 架构上近似任何方法。然而，这是多线程的一部分。

# 对称与非对称多处理

在过去的几十年中，许多系统都包含了多个处理单元。这些可以大致分为对称多处理（SMP）和非对称多处理（AMP）系统。

AMP 的主要特点是将第二处理器作为外围连接到主 CPU。这意味着它不能运行控制软件，而只能运行用户应用程序。这种方法也被用于连接使用不同架构的 CPU，以允许例如在 Amiga，68k 系统上运行 x86 应用程序。

在 SMP 系统中，每个 CPU 都是对等的，可以访问相同的硬件资源，并以合作的方式设置。最初，SMP 系统涉及多个物理 CPU，但后来，多个处理器核心集成在单个 CPU 芯片上：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00014.gif)

随着多核 CPU 的普及，SMP 是嵌入式开发之外最常见的处理类型，其中单处理（单核，单处理器）仍然非常普遍。

从技术上讲，系统中的声音、网络和图形处理器可以被视为与 CPU 相关的非对称处理器。随着**通用 GPU**（GPGPU）处理的增加，AMP 变得更加相关。

# 松散和紧密耦合的多处理

多处理系统不一定要在单个系统内实现，也可以由多个连接在网络中的系统组成。这样的集群被称为松散耦合的多处理系统。我们在第九章中涵盖了分布式计算，*分布式计算中的多线程*。

这与紧密耦合的多处理系统形成对比，紧密耦合的多处理系统是通过单个印刷电路板（PCB）上使用相同的低级高速总线或类似的方式集成在一起。

# 将多处理与多线程结合

几乎任何现代系统都结合了多处理和多线程，这要归功于多核 CPU，它将两个或更多处理核心集成在单个处理器芯片上。对操作系统来说，这意味着它必须在多个处理核心之间调度任务，同时也必须在特定核心上调度它们，以提取最大性能。

这是任务调度器的领域，我们稍后会看一下。可以说这是一个值得一本书的话题。

# 多线程类型

与多处理类似，多线程也不是单一实现，而是两种主要实现。这两者之间的主要区别在于处理器在单个周期内可以同时执行的线程数量。多线程实现的主要目标是尽可能接近 100%的处理器硬件利用率。多线程利用线程级和进程级并行性来实现这一目标。

接下来我们将介绍两种多线程类型。

# 时间多线程

也被称为超线程，**时间多线程**（TMT）的主要子类型是粗粒度和细粒度（或交错）。前者在不同任务之间快速切换，保存每个任务的上下文，然后切换到另一个任务的上下文。后者在每个周期中切换任务，导致 CPU 流水线包含来自各种任务的指令，从中得到*交错*这个术语。

细粒度类型在桶处理器中实现。它们比 x86 和其他架构具有优势，因为它们可以保证特定的时间（对于硬实时嵌入式系统很有用），并且由于可以做出的假设较少，实现起来更不复杂。

# 同时多线程（SMT）

SMT 实现在超标量 CPU 上（实现指令级并行性），其中包括 x86 和 ARM 架构。SMT 的定义特征也由其名称指示，特别是其能够在每个核心中并行执行多个线程。

通常，每个核心有两个线程是常见的，但某些设计支持每个核心最多八个并发线程。这样做的主要优势是能够在线程之间共享资源，明显的缺点是多个线程的冲突需得到管理。另一个优势是由于缺乏硬件资源重复，使得结果 CPU 更节能。

英特尔的超线程技术本质上是英特尔的 SMT 实现，从 2002 年的一些奔腾 4 CPU 开始提供基本的双线程 SMT 引擎。

# 调度程序

存在许多任务调度算法，每个算法都专注于不同的目标。有些可能寻求最大化吞吐量，其他人则最小化延迟，而其他人可能寻求最大化响应时间。哪种调度程序是最佳选择完全取决于系统所用于的应用程序。

对于桌面系统，调度程序通常尽可能保持通用，通常优先考虑前台应用程序，以便为用户提供最佳的桌面体验。

对于嵌入式系统，特别是在实时、工业应用中，通常会寻求保证定时。这允许进程在恰当的时间执行，这在例如驱动机械、机器人或化工过程中至关重要，即使延迟几毫秒也可能成本高昂甚至致命。

调度程序类型还取决于操作系统的多任务状态--合作式多任务系统无法提供关于何时可以切换运行中进程的许多保证，因为这取决于活动进程何时让出。

使用抢占式调度程序，进程在不知情的情况下进行切换，允许调度程序更多地控制进程在哪些时间点运行。

基于 Windows NT 的操作系统（Windows NT，2000，XP 等）使用所谓的多级反馈队列，具有 32 个优先级级别。这种类型的优先级调度程序允许对任务进行优先级排序，从而可以微调产生的体验。

Linux 最初（内核 2.4）也使用了基于多级反馈队列的优先级调度程序，类似于具有 O(n)调度程序的 Windows NT。在 2.6 版本中，这被替换为 O(1)调度程序，允许进程在恒定的时间内被调度。从 Linux 内核 2.6.23 开始，默认调度程序是**完全公平调度程序**（**CFS**），它确保所有任务获得可比较的 CPU 时间份额。

以下是一些常用或知名操作系统使用的调度算法类型：

| **操作系统** | **抢占** | **算法** |
| --- | --- | --- |
| Amiga OS | 是 | 优先级轮转调度 |
| FreeBSD | 是 | 多级反馈队列 |
| Linux 内核 2.6.0 之前 | 是 | 多级反馈队列 |
| Linux 内核 2.6.0-2.6.23 | 是 | O(1)调度程序 |
| Linux 内核 2.6.23 之后 | 是 | 完全公平调度程序 |
| 经典 Mac OS 9 之前 | 无 | 合作式调度程序 |
| Mac OS 9 | 一些 | 用于 MP 任务的抢占式调度程序，以及用于进程和线程的合作式调度程序 |
| OS X/macOS | 是 | 多级反馈队列 |
| NetBSD | 是 | 多级反馈队列 |
| Solaris | 是 | 多级反馈队列 |
| Windows 3.1x | 无 | 合作式调度程序 |
| Windows 95, 98, Me | Half | 32 位进程使用抢占式调度程序，16 位进程使用合作式调度程序 |
| Windows NT（包括 2000、XP、Vista、7 和 Server） | 是 | 多级反馈队列 |

（来源：[`en.wikipedia.org/wiki/Scheduling_(computing)`](https://en.wikipedia.org/wiki/Scheduling_(computing))）

抢占列指示调度程序是否具有抢占性，下一列提供了更多细节。可以看到，抢占式调度程序非常常见，所有现代桌面操作系统都使用它。

# 跟踪演示应用程序

在第一章的演示代码中，*重新审视多线程*，我们看了一个简单的`c++11`应用程序，它使用四个线程来执行一些处理。在本节中，我们将从硬件和操作系统的角度来看同一个应用程序。

当我们看`main`函数中的代码开头时，我们看到创建了一个包含单个（整数）值的数据结构：

```cpp
int main() {
    values.push_back(42);

```

操作系统创建新任务和相关的堆栈结构后，在堆栈上分配了一个向量数据结构的实例（针对整数类型进行了定制）。这个大小在二进制文件的全局数据部分（ELF 的 BSS）中指定。

当应用程序使用其入口函数（默认为`main()`）开始执行时，数据结构被修改为包含新的整数值。

接下来，我们创建四个线程，为每个线程提供一些初始数据：

```cpp
    thread tr1(threadFnc, 1);
    thread tr2(threadFnc, 2);
    thread tr3(threadFnc, 3);
    thread tr4(threadFnc, 4);

```

对于操作系统来说，这意味着创建新的数据结构，并为每个新线程分配一个堆栈。对于硬件来说，如果不使用基于硬件的任务切换，最初不会改变任何东西。

此时，操作系统的调度程序和 CPU 可以结合起来尽可能高效和快速地执行这组任务（线程），利用硬件的特性，包括 SMP、SMT 等。

在此之后，主线程等待其他线程停止执行：

```cpp
    tr1.join();
    tr2.join();
    tr3.join();
    tr4.join();

```

这些是阻塞调用，标记主线程被阻塞，直到这四个线程（任务）执行完成。此时，操作系统的调度程序将恢复主线程的执行。

在每个新创建的线程中，我们首先在标准输出上输出一个字符串，确保锁定互斥锁以确保同步访问：

```cpp
void threadFnc(int tid) {
    cout_mtx.lock();
    cout << "Starting thread " << tid << ".\n";
    cout_mtx.unlock();

```

互斥锁本质上是一个存储在堆栈或堆上的单个值，然后使用原子操作访问。这意味着需要某种形式的硬件支持。使用这个，任务可以检查它是否被允许继续，还是必须等待并再次尝试。

在这段特定的代码中，这个互斥锁允许我们在标准 C++输出流上输出，而不会受到其他线程的干扰。

在这之后，我们将向一个本地变量复制向量中的初始值，再次确保它是同步完成的：

```cpp
    values_mtx.lock();
    int val = values[0];
    values_mtx.unlock();

```

这里发生的事情与之前相同，只是现在互斥锁允许我们读取向量中的第一个值，而不会在我们使用它时有其他线程访问甚至更改它的风险。

接着生成一个随机数如下：

```cpp
    int rval = randGen(0, 10);
    val += rval;

```

这使用了以下`randGen()`方法：

```cpp
int randGen(const int& min, const int& max) {
    static thread_local mt19937 generator(hash<thread::id>() (this_thread::get_id()));
    uniform_int_distribution<int> distribution(min, max);
    return distribution(generator);
}

```

这种方法之所以有趣，是因为它使用了线程局部变量。线程局部存储是线程特有的内存部分，用于全局变量，但必须保持限制在特定线程中。

对于像这里使用的静态变量来说，这是非常有用的。`generator`实例是静态的，因为我们不希望每次使用这种方法时都重新初始化它，但我们也不希望在所有线程之间共享这个实例。通过使用线程局部的静态实例，我们可以实现这两个目标。为每个线程创建并使用一个静态实例。

`Thread`函数最后以相同的一系列互斥锁结束，并将新值复制到数组中。

```cpp
    cout_mtx.lock();
    cout << "Thread " << tid << " adding " << rval << ". New value: " << val << ".\n";
    cout_mtx.unlock();

    values_mtx.lock();
    values.push_back(val);
    values_mtx.unlock();
}

```

在这里，我们看到对标准输出流的同步访问，然后是对值数据结构的同步访问。

# 互斥实现

互斥是多线程应用程序中数据的线程安全访问的原则。可以在硬件和软件中实现这一点。**互斥**（**mutex**）是大多数实现中这种功能的最基本形式。

# 硬件

在单处理器（单处理器核心），非 SMT 系统上最简单的基于硬件的实现是禁用中断，从而防止任务被更改。更常见的是采用所谓的忙等待原则。这是互斥的基本原则--由于处理器获取数据的方式，只有一个任务可以获取和读/写共享内存中的原子值，即与 CPU 寄存器相同（或更小）大小的变量。这在第八章“原子操作-与硬件一起工作”中有进一步详细说明。

当我们的代码尝试锁定互斥锁时，这实际上是读取这样一个原子内存区域的值，并尝试将其设置为其锁定值。由于这是一个单操作，只有一个任务可以在任何给定时间更改该值。其他任务将不得不等待，直到它们可以在这个忙等待周期中获得访问，如图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00015.jpeg)

# 软件

基于忙等待的软件定义的互斥实现。一个例子是**Dekker**算法，它定义了一个系统，其中两个进程可以同步，利用忙等待等待另一个进程离开临界区。

该算法的伪代码如下：

```cpp
    variables
        wants_to_enter : array of 2 booleans
        turn : integer

    wants_to_enter[0] ← false
    wants_to_enter[1] ← false
    turn ← 0 // or 1

```

```cpp
p0:
    wants_to_enter[0] ← true
    while wants_to_enter[1] {
        if turn ≠ 0 {
            wants_to_enter[0] ← false
            while turn ≠ 0 {
                // busy wait
            }
            wants_to_enter[0] ← true
        }
    }
    // critical section
    ...
    turn ← 1
    wants_to_enter[0] ← false
    // remainder section

```

```cpp
p1:
    wants_to_enter[1] ← true
    while wants_to_enter[0] {
        if turn ≠ 1 {
            wants_to_enter[1] ← false
            while turn ≠ 1 {
                // busy wait
            }
            wants_to_enter[1] ← true
        }
    }
    // critical section
    ...
    turn ← 0
    wants_to_enter[1] ← false
    // remainder section

```

（引用自：[`en.wikipedia.org/wiki/Dekker's_algorithm`](https://en.wikipedia.org/wiki/Dekker's_algorithm)）

在上述算法中，进程表明他们打算进入临界区，检查是否轮到他们（使用进程 ID），然后在进入后将其意图设置为 false。只有当进程再次将其意图设置为 true 时，它才会再次进入临界区。如果它希望进入，但`turn`与其进程 ID 不匹配，它将忙等待直到条件变为真。

软件基础的互斥算法的一个主要缺点是，它们只在禁用代码的**乱序**（**OoO**）执行时才能工作。 OoO 意味着硬件积极重新排序传入的指令，以优化它们的执行，从而改变它们的顺序。由于这些算法要求各个步骤按顺序执行，它们在 OoO 处理器上不再起作用。

# 总结

在本章中，我们看到了进程和线程在操作系统和硬件中的实现方式。我们还研究了处理器硬件的各种配置以及涉及调度的操作系统元素，以了解它们如何提供各种类型的任务处理。

最后，我们再次运行了上一章的多线程程序示例，并考虑了在执行过程中操作系统和处理器发生了什么。

在下一章中，我们将看看通过操作系统和基于库的实现提供的各种多线程 API，以及比较这些 API 的示例。


# 第三章：C++多线程 API

虽然 C++在**标准模板库**（**STL**）中有本地的多线程实现，但基于操作系统和框架的多线程 API 仍然非常常见。这些 API 的例子包括 Windows 和**POSIX**（**可移植操作系统接口**）线程，以及`Qt`、`Boost`和`POCO`库提供的线程。

本章详细介绍了每个 API 提供的功能，以及它们之间的相似之处和不同之处。最后，我们将使用示例代码来查看常见的使用场景。

本章涵盖的主题包括以下内容：

+   可用多线程 API 的比较

+   每个 API 的用法示例

# API 概述

在**C++ 2011**（**C++11**）标准之前，开发了许多不同的线程实现，其中许多限于特定的软件平台。其中一些至今仍然相关，例如 Windows 线程。其他已被标准取代，其中**POSIX Threads**（**Pthreads**）已成为类 UNIX 操作系统的事实标准。这包括基于 Linux 和基于 BSD 的操作系统，以及 OS X（macOS）和 Solaris。

许多库被开发出来，以使跨平台开发更容易。尽管 Pthreads 有助于使类 UNIX 操作系统更或多或少地兼容，但要使软件在所有主要操作系统上可移植，需要一个通用的线程 API。这就是为什么会创建诸如 Boost、POCO 和 Qt 等库。应用程序可以使用这些库，并依赖于库来处理平台之间的任何差异。

# POSIX 线程

Pthreads 最初是在 1995 年的`POSIX.1c`标准（*Threads extensions*，IEEE Std 1003.1c-1995）中定义的，作为 POSIX 标准的扩展。当时，UNIX 被选择为制造商中立的接口，POSIX 统一了它们之间的各种 API。

尽管有这种标准化的努力，Pthread 在实现它的操作系统之间仍存在差异（例如，在 Linux 和 OS X 之间），这是由于不可移植的扩展（在方法名中标有`_np`）。

对于`pthread_setname_np`方法，Linux 实现需要两个参数，允许设置除当前线程以外的线程的名称。在 OS X（自 10.6 起），此方法只需要一个参数，允许设置当前线程的名称。如果可移植性是一个问题，就必须注意这样的差异。

1997 年后，POSIX 标准的修订由奥斯汀联合工作组负责。这些修订将线程扩展合并到主标准中。当前的修订是第 7 版，也被称为 POSIX.1-2008 和 IEEE Std 1003.1，2013 版--标准的免费副本可在线获得。

操作系统可以获得符合 POSIX 标准的认证。目前，这些如表中所述：

| **名称** | **开发者** | **自版本** | **架构（当前）** | **备注** |
| --- | --- | --- | --- | --- |
| AIX | IBM | 5L | POWER | 服务器操作系统 |
| HP-UX | 惠普 | 11i v3 | PA-RISC, IA-64 (Itanium) | 服务器操作系统 |
| IRIX | Silicon Graphics（SGI） | 6 | MIPS | 已停产 |
| Inspur K-UX | 浪潮 | 2 | X86_64 | 基于 Linux |
| Integrity | Green Hills Software | 5 | ARM, XScale, Blackfin, Freescale Coldfire, MIPS, PowerPC, x86. | 实时操作系统 |
| OS X/MacOS | 苹果 | 10.5（Leopard） | X86_64 | 桌面操作系统 |
| QNX Neutrino | BlackBerry | 1 | Intel 8088, x86, MIPS, PowerPC, SH-4, ARM, StrongARM, XScale | 实时嵌入式操作系统 |
| Solaris | Sun/Oracle | 2.5 | SPARC, IA-32（<11），x86_64，PowerPC（2.5.1） | 服务器操作系统 |
| Tru64 | DEC, HP, IBM, Compaq | 5.1B-4 | Alpha | 已停产 |
| UnixWare | Novell, SCO, Xinuos | 7.1.3 | x86 | 服务器操作系统 |

其他操作系统大多是兼容的。以下是相同的例子：

| **名称** | **平台** | **备注** |
| --- | --- | --- |
| Android | ARM, x86, MIPS | 基于 Linux。Bionic C 库。 |
| BeOS (Haiku) | IA-32, ARM, x64_64 | 仅限于 x86 的 GCC 2.x。 |
| Darwin | PowerPC、x86、ARM | 使用 macOS 基础的开源组件。 |
| FreeBSD | IA-32、x86_64、sparc64、PowerPC、ARM、MIPS 等等 | 基本上符合 POSIX 标准。可以依赖已记录的 POSIX 行为。一般而言，比 Linux 更严格地遵守标准。 |
| Linux | Alpha、ARC、ARM、AVR32、Blackfin、H8/300、Itanium、m68k、Microblaze、MIPS、Nios II、OpenRISC、PA-RISC、PowerPC、s390、S+core、SuperH、SPARC、x86、Xtensa 等等 | 一些 Linux 发行版（见前面的表）被认证为符合 POSIX 标准。这并不意味着每个 Linux 发行版都符合 POSIX 标准。一些工具和库可能与标准不同。对于 Pthreads，这可能意味着在 Linux 发行版之间的行为有时会有所不同（不同的调度程序等），并且与其他实现 Pthreads 的操作系统相比也会有所不同。 |
| MINIX 3 | IA-32、ARM | 符合 POSIX 规范标准 3（SUSv3, 2004）。 |
| NetBSD | Alpha、ARM、PA-RISC、68k、MIPS、PowerPC、SH3、SPARC、RISC-V、VAX、x86 等等 | 几乎完全兼容 POSIX.1（1990），并且大部分符合 POSIX.2（1992）。 |
| Nuclear RTOS | ARM、MIPS、PowerPC、Nios II、MicroBlaze、SuperH 等等 | Mentor Graphics 公司推出的专有 RTOS，面向嵌入式应用。 |
| NuttX | ARM、AVR、AVR32、HCS12、SuperH、Z80 等等 | 轻量级的 RTOS，可在 8 到 32 位系统上扩展，且高度符合 POSIX 标准。 |
| OpenBSD | Alpha、x86_64、ARM、PA-RISC、IA-32、MIPS、PowerPC、SPARC 等等 | 1995 年从 NetBSD 分叉出来。具有类似的 POSIX 支持。 |
| OpenSolaris/illumos | IA-32、x86_64、SPARC、ARM | 与商业 Solaris 发行版兼容认证。 |
| VxWorks | ARM、SH-4、x86、x86_64、MIPS、PowerPC | 符合 POSIX 标准，并获得用户模式执行环境认证。 |

由此可见，遵循 POSIX 规范并不是一件明显的事情，也不能保证代码在每个平台上都能编译。每个平台还会有自己的一套标准扩展，用于标准中省略的但仍然有用的功能。然而，Pthreads 在 Linux、BSD 和类似的软件中被广泛使用。

# Windows 支持

也可以使用 POSIX API，例如以下方式：

| **名称** | **符合度** |
| --- | --- |
| Cygwin | 大部分完整。提供了一个完整的运行时环境，用于将 POSIX 应用程序作为普通的 Windows 应用程序进行分发。 |
| MinGW | 使用 MinGW-w64（MinGW 的重新开发版本），对 Pthreads 的支持相当完整，尽管可能会缺少一些功能。 |
| Windows Subsystem for Linux | WSL 是 Windows 10 的一个功能，允许 Ubuntu Linux 14.04（64 位）镜像的工具和实用程序在其上本地运行，尽管不能运行使用 GUI 功能或缺少内核功能的程序。否则，它提供了与 Linux 类似的兼容性。这个功能目前需要运行 Windows 10 周年更新，并按照微软提供的说明手动安装 WSL。 |

一般不建议在 Windows 上使用 POSIX。除非有充分的理由使用 POSIX（例如，大量现有代码库），否则最好使用跨平台 API（本章后面将介绍），以解决任何平台问题。

在接下来的章节中，我们将看一下 Pthreads API 提供的功能。

# PThreads 线程管理

这些函数都以 `pthread_` 或 `pthread_attr_` 开头。这些函数都适用于线程本身及其属性对象。

使用 Pthreads 的基本线程看起来像下面这样：

```cpp
#include <pthread.h> 
#include <stdlib.h> 

#define NUM_THREADS     5 

```

主要的 Pthreads 头文件是 `pthread.h`。这样可以访问除了信号量（稍后在本节中讨论）之外的所有内容。我们还在这里定义了希望启动的线程数量的常量：

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

我们在前面的函数中使用循环创建所有线程。每个线程实例在创建时都会被分配一个线程 ID（第一个参数），并且`pthread_create()`函数会返回一个结果代码（成功时为零）。线程 ID 是在将来调用中引用线程的句柄。

函数的第二个参数是一个`pthread_attr_t`结构实例，如果没有则为 0。这允许配置新线程的特性，例如初始堆栈大小。当传递零时，将使用默认参数，这些参数因平台和配置而异。

第三个参数是指向新线程将启动的函数的指针。这个函数指针被定义为一个返回指向 void 数据（即自定义数据）的指针的函数，并接受一个指向 void 数据的指针。在这里，作为参数传递给新线程的数据是线程 ID：

```cpp
    for (int i = 0; i < NUM_THREADS; ++i) { 
        result_code = pthread_join(threads[i], 0); 
    } 

    exit(0); 
} 

```

接下来，我们使用`pthread_join()`函数等待每个工作线程完成。此函数接受两个参数，要等待的线程 ID 和`Worker`函数的返回值的缓冲区（或零）。

管理线程的其他函数如下：

+   `void pthread_exit`(`void *value_ptr`):

这个函数终止调用它的线程，使得提供的参数值可以被任何调用`pthread_join()`的线程使用。

+   `int pthread_cancel`(`pthread_t` thread):

这个函数请求取消指定的线程。根据目标线程的状态，这将调用其取消处理程序。

除此之外，还有`pthread_attr_*`函数来操作和获取有关`pthread_attr_t`结构的信息。

# 互斥锁

这些是以`pthread_mutex_`或`pthread_mutexattr_`为前缀的函数。它们适用于互斥锁及其属性对象。

Pthreads 中的互斥锁可以被初始化、销毁、锁定和解锁。它们还可以使用`pthread_mutexattr_t`结构自定义其行为，该结构具有相应的`pthread_mutexattr_*`函数用于初始化和销毁属性。

使用静态初始化的 Pthread 互斥锁的基本用法如下：

```cpp
static pthread_mutex_t func_mutex = PTHREAD_MUTEX_INITIALIZER; 

void func() { 
    pthread_mutex_lock(&func_mutex); 

    // Do something that's not thread-safe. 

    pthread_mutex_unlock(&func_mutex); 
} 

```

在最后一段代码中，我们使用了`PTHREAD_MUTEX_INITIALIZER`宏，它可以为我们初始化互斥锁，而无需每次都输入代码。与其他 API 相比，人们必须手动初始化和销毁互斥锁，尽管宏的使用在一定程度上有所帮助。

之后，我们锁定和解锁互斥锁。还有`pthread_mutex_trylock()`函数，它类似于常规锁定版本，但如果引用的互斥锁已经被锁定，它将立即返回而不是等待它被解锁。

在这个例子中，互斥锁没有被显式销毁。然而，这是 Pthreads 应用程序中正常内存管理的一部分。

# 条件变量

这些函数的前缀要么是`pthread_cond_`，要么是`pthread_condattr_`。它们适用于条件变量及其属性对象。

Pthreads 中的条件变量遵循相同的模式，除了具有初始化和`destroy`函数外，还有用于管理`pthread_condattr_t`属性结构的相同函数。

这个例子涵盖了 Pthreads 条件变量的基本用法：

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

在前面的代码中，我们获取了标准头文件，并定义了一个计数触发器和限制，其目的将在一会儿变得清晰。我们还定义了一些全局变量：一个计数变量，我们希望创建的线程的 ID，以及一个互斥锁和条件变量：

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

前面的函数本质上只是在使用`count_mutex`获得独占访问权后向全局计数变量添加。它还检查计数触发值是否已达到。如果是，它将发出条件变量的信号。

为了给第二个线程，也运行此函数，一个机会获得互斥锁，我们在循环的每个周期中睡眠 1 秒：

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

在这第二个函数中，在检查是否已达到计数限制之前，我们会锁定全局互斥锁。这是我们的保险，以防此函数运行的线程在计数达到限制之前不被调用。

否则，我们在提供条件变量和锁定互斥锁的情况下等待条件变量。一旦收到信号，我们就解锁全局互斥锁，并退出线程。

这里需要注意的一点是，这个示例没有考虑虚假唤醒。Pthreads 条件变量容易受到这种唤醒的影响，这需要使用循环并检查是否已满足某种条件：

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

最后，我们等待每个线程完成，然后在退出之前清理，销毁属性结构实例、互斥锁和条件变量。

使用`pthread_cond_broadcast()`函数，进一步可以向等待条件变量的所有线程发出信号，而不仅仅是队列中的第一个线程。这使得可以更优雅地在某些应用程序中使用条件变量，例如，有很多工作线程在等待新数据集到达，而无需单独通知每个线程。

# 同步

实现同步的函数以`pthread_rwlock_`或`pthread_barrier_`为前缀。这些实现读/写锁和同步屏障。

**读/写锁**（**rwlock**）与互斥锁非常相似，只是它具有额外的功能，允许无限数量的线程同时读取，而只限制写访问一个线程。

使用`rwlock`与使用互斥锁非常相似：

```cpp
#include <pthread.h> 
int pthread_rwlock_init(pthread_rwlock_t* rwlock, const pthread_rwlockattr_t* attr); 
pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER; 

```

在最后的代码中，我们包括相同的通用头文件，并使用初始化函数或通用宏。有趣的部分是当我们锁定`rwlock`时，可以仅用于只读访问：

```cpp
int pthread_rwlock_rdlock(pthread_rwlock_t* rwlock); 
int pthread_rwlock_tryrdlock(pthread_rwlock_t* rwlock); 

```

在这里，如果锁已经被锁定，第二种变体会立即返回。也可以按以下方式锁定它以进行写访问：

```cpp
int pthread_rwlock_wrlock(pthread_rwlock_t* rwlock); 
int pthread_rwlock_trywrlock(pthread_rwlock_t * rwlock); 

```

这些函数基本上是相同的，只是在任何给定时间只允许一个写入者，而多个读取者可以获得只读锁。

屏障是 Pthreads 的另一个概念。这些是同步对象，对于一些线程起到屏障的作用。在任何一个线程可以继续执行之前，所有这些线程都必须到达屏障。在屏障初始化函数中，指定了线程计数。只有当所有这些线程都使用`pthread_barrier_wait()`函数调用`barrier`对象后，它们才会继续执行。

# 信号量

如前所述，信号量不是原始 Pthreads 扩展到 POSIX 规范的一部分。出于这个原因，它们在`semaphore.h`头文件中声明。

实质上，信号量是简单的整数，通常用作资源计数。为了使它们线程安全，使用原子操作（检查和锁定）。POSIX 信号量支持初始化、销毁、增加和减少信号量，以及等待信号量达到非零值。

# 线程本地存储（TLC）

使用 Pthreads，TLS 是通过使用键和方法来设置特定于线程的数据来实现的：

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

在工作线程中，我们在堆上分配一个新的整数，并将全局密钥设置为其自己的值。在将全局变量增加 1 之后，其值将为 2，而不管其他线程做什么。我们可以在完成此线程的操作后将全局变量设置为 0，并删除分配的值：

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

设置并使用全局密钥来引用 TLS 变量，然而我们创建的每个线程都可以为此密钥设置自己的值。

虽然线程可以创建自己的密钥，但与本章中正在查看的其他 API 相比，处理 TLS 的这种方法相当复杂。

# Windows 线程

相对于 Pthreads，Windows 线程仅限于 Windows 操作系统和类似系统（例如 ReactOS 和其他使用 Wine 的操作系统）。这提供了一个相当一致的实现，可以轻松地由支持对应的 Windows 版本来定义。

在 Windows Vista 之前，线程支持缺少诸如条件变量之类的功能，同时具有 Pthreads 中找不到的功能。根据一个人的观点，使用 Windows 头文件中定义的无数“类型定义”类型可能也会让人感到烦恼。

# 线程管理

从官方 MSDN 文档示例代码改编的使用 Windows 线程的基本示例如下：

```cpp
#include <windows.h> 
#include <tchar.h> 
#include <strsafe.h> 

#define MAX_THREADS 3 
#define BUF_SIZE 255  

```

在包含一系列 Windows 特定的头文件用于线程函数、字符字符串等之后，我们在`Worker`函数中定义了要创建的线程数以及消息缓冲区的大小。

我们还定义了一个结构类型（通过`void 指针：LPVOID`传递），用于包含我们传递给每个工作线程的示例数据：

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

在`Worker`函数中，我们将提供的参数转换为我们自定义的结构类型，然后使用它将其值打印到字符串上，然后在控制台上输出。

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

在这里，定义了一个错误处理函数，该函数获取最后一个错误代码的系统错误消息。在获取最后一个错误的代码之后，将格式化要输出的错误消息，并显示在消息框中。最后，释放分配的内存缓冲区。

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

在`main`函数中，我们在循环中创建线程，为线程数据分配内存，并在启动线程之前为每个线程生成唯一数据。每个线程实例都传递了自己的唯一参数。

之后，我们等待线程完成并重新加入。这本质上与在 Pthreads 上调用`join`函数的单个线程相同--只是这里，一个函数调用就足够了。

最后，关闭每个线程句柄，并清理之前分配的内存。

# 高级管理

使用 Windows 线程进行高级线程管理包括作业、纤程和线程池。作业基本上允许将多个线程链接到一个单元中，从而可以一次性更改所有这些线程的属性和状态。

纤程是轻量级线程，运行在创建它们的线程的上下文中。创建线程预期自己调度这些纤程。纤程还具有类似 TLS 的**纤程本地存储**（**FLS**）。

最后，Windows 线程 API 提供了一个线程池 API，允许在应用程序中轻松使用这样的线程池。每个进程也都提供了一个默认的线程池。

# 同步

使用 Windows 线程，可以使用临界区、互斥体、信号量、**轻量级读写器**（**SRW**）锁、屏障和变体来实现互斥和同步。

同步对象包括以下内容：

| **名称** | **描述** |
| --- | --- |
| 事件 | 允许使用命名对象在线程和进程之间进行事件信号传递。 |
| 互斥体 | 用于线程间和进程间同步，以协调对共享资源的访问。 |
| 信号量 | 用于线程间和进程同步的标准信号量计数对象。 |
| 可等待定时器 | 可由多个进程使用的定时器对象，具有多种使用模式。 |
| 临界区 | 临界区本质上是限于单个进程的互斥锁，这使得它们比使用互斥锁更快，因为它们不需要内核空间调用。 |
| Slim reader/writer lock | SRW 类似于 Pthreads 中的读/写锁，允许多个读取者或单个写入者线程访问共享资源。 |
| 原子变量访问 | 允许对一系列变量进行原子访问，否则不能保证原子性。这使得线程可以共享变量而无需使用互斥锁。 |

# 条件变量

使用 Windows 线程实现条件变量是相当简单的。它使用临界区（`CRITICAL_SECTION`）和条件变量（`CONDITION_VARIABLE`）以及条件变量函数来等待特定条件变量，或者发出信号。

# 线程本地存储

**线程本地存储**（**TLS**）与 Windows 线程类似于 Pthreads，因为首先必须创建一个中央键（TLS 索引），然后各个线程可以使用该全局索引来存储和检索本地值。

与 Pthreads 一样，这涉及到相似数量的手动内存管理，因为 TLS 值必须手动分配和删除。

# Boost

Boost 线程是 Boost 库集合中相对较小的一部分。然而，它被用作成为 C++11 中多线程实现基础，类似于其他 Boost 库最终完全或部分地成为新的 C++标准。有关多线程 API 的详细信息，请参阅本章中的 C++线程部分。

C++11 标准中缺少的功能，在 Boost 线程中是可用的，包括以下内容：

+   线程组（类似于 Windows 作业）

+   线程中断（取消）

+   带超时的线程加入

+   其他互斥锁类型（C++14 改进）

除非绝对需要这些功能，或者无法使用支持 C++11 标准（包括 STL 线程）的编译器，否则没有理由使用 Boost 线程而不是 C++11 实现。

由于 Boost 提供了对本机操作系统功能的封装，使用本机 C++线程可能会减少开销，具体取决于 STL 实现的质量。

# Qt

Qt 是一个相对高级的框架，这也反映在其多线程 API 中。Qt 的另一个定义特征是，它包装了自己的代码（QApplication 和 QMainWindow），并使用元编译器（`qmake`）来实现其信号-槽架构和框架的其他定义特征。

因此，Qt 的线程支持不能直接添加到现有代码中，而是需要调整代码以适应框架。

# QThread

在 Qt 中，`QThread`类不是一个线程，而是一个围绕线程实例的广泛封装，它添加了信号-槽通信、运行时支持和其他功能。这在 QThread 的基本用法中得到体现，如下面的代码所示：

```cpp
class Worker : public QObject { 
    Q_OBJECT 

    public: 
        Worker(); 
        ~Worker(); 

    public slots: 
        void process(); 

    signals: 
        void finished(); 
        void error(QString err); 

    private: 
}; 

```

上述代码是一个基本的`Worker`类，它将包含我们的业务逻辑。它派生自`QObject`类，这也允许我们使用信号-槽和其他固有的`QObject`特性。信号-槽架构在其核心本质上只是一种方式，允许侦听器注册（连接到）由 QObject 派生类声明的信号，从而实现跨模块、跨线程和异步通信。

它有一个可以调用以开始处理的单一方法，并且有两个信号——一个用于表示完成，一个用于表示错误。

实现如下所示：

```cpp
Worker::Worker() { }  
Worker::~Worker() { } 

void Worker::process() { 
    qDebug("Hello World!"); 
    emit finished(); 
} 

```

构造函数可以扩展以包括参数。任何在`process()`方法中分配的堆分配变量（使用`malloc`或`new`）必须在`process()`方法中分配，而不是在构造函数中，因为`Worker`实例将在其中运行线程上下文中操作，我们马上就会看到。

要创建一个新的 QThread，我们将使用以下设置：

```cpp
QThread* thread = new QThread; 
Worker* worker = new Worker(); 
worker->moveToThread(thread); 
connect(worker, SIGNAL(error(QString)), this, SLOT(errorString(QString))); 
connect(thread, SIGNAL(started()), worker, SLOT(process())); 
connect(worker, SIGNAL(finished()), thread, SLOT(quit())); 
connect(worker, SIGNAL(finished()), worker, SLOT(deleteLater())); 
connect(thread, SIGNAL(finished()), thread, SLOT(deleteLater())); 
thread->start(); 

```

基本过程是在堆上创建一个新的 QThread 实例（这样它就不会超出范围），以及我们的`Worker`类的堆分配实例。然后使用其`moveToThread()`方法将新的工作线程移动到新的线程实例中。

接下来，将连接各种信号到相关的槽，包括我们自己的`finished()`和`error()`信号。线程实例的`started()`信号将连接到我们的工作线程上的槽，以启动它。

最重要的是，必须将工作线程的某种完成信号连接到线程上的`quit()`和`deleteLater()`槽。然后将线程的`finished()`信号连接到工作线程上的`deleteLater()`槽。这将确保在工作线程完成时清理线程和工作线程实例。

# 线程池

Qt 提供线程池。这些需要从`QRunnable`类继承，并实现`run()`函数。然后将此自定义类的实例传递给线程池的`start`方法（全局默认池或新池）。然后线程池会处理此工作线程的生命周期。

# 同步

Qt 提供以下同步对象：

+   `QMutex`

+   `QReadWriteLock`

+   `QSemaphore`

+   `QWaitCondition`（条件变量）

这些应该是相当不言自明的。Qt 的信号-槽架构的另一个好处是，它还允许在线程之间异步通信，而无需关注低级实现细节。

# QtConcurrent

QtConcurrent 命名空间包含针对编写多线程应用程序的高级 API，旨在使编写多线程应用程序成为可能，而无需关注低级细节。

函数包括并发过滤和映射算法，以及允许在单独线程中运行函数的方法。所有这些都返回一个`QFuture`实例，其中包含异步操作的结果。

# 线程本地存储

Qt 通过其`QThreadStorage`类提供 TLS。它处理指针类型值的内存管理。通常，人们会将某种数据结构设置为 TLS 值，以存储每个线程的多个值，例如在`QThreadStorage`类文档中描述的那样：

```cpp
QThreadStorage<QCache<QString, SomeClass> > caches; 

void cacheObject(const QString &key, SomeClass* object) { 
    caches.localData().insert(key, object); 
} 

void removeFromCache(const QString &key) { 
    if (!caches.hasLocalData()) { return; } 

    caches.localData().remove(key); 
} 

```

# POCO

POCO 库是围绕操作系统功能的相当轻量级的包装器。它不需要 C++11 兼容的编译器或任何种类的预编译或元编译。

# 线程类

`Thread`类是围绕操作系统级线程的简单包装器。它接受从`Runnable`类继承的`Worker`类实例。官方文档提供了一个基本示例如下：

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

上述代码是一个非常简单的“Hello world”示例，其中一个工作线程只通过标准输出输出一个字符串。线程实例分配在堆栈上，并在入口函数的范围内等待工作线程使用`join()`函数完成。

在许多线程函数中，POCO 非常类似于 Pthreads，尽管在配置线程和其他对象等方面有明显的偏差。作为 C++库，它使用类方法设置属性，而不是填充结构并将其作为参数传递。

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

工作实例被添加到线程池中，并运行它。当我们添加另一个工作实例、更改容量或调用`joinAll()`时，线程池会清理空闲一定时间的线程。因此，单个工作线程将加入，没有活动线程后，应用程序退出。

# 线程本地存储（TLS）

在 POCO 中，TLS 被实现为一个类模板，允许人们将其用于几乎任何类型。

根据官方文档的详细说明：

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

在前面的工作示例中，我们使用`ThreadLocal`类模板创建了一个静态 TLS 变量，并定义它包含一个整数。

因为我们将其定义为静态的，它将只在每个线程中创建一次。为了使用我们的 TLS 变量，我们可以使用箭头（`->`）或星号（`*`）运算符来访问其值。在这个例子中，我们在`for`循环的每个周期增加 TLS 值，直到达到限制为止。

这个例子演示了两个线程将生成它们自己的一系列 10 个整数，计数相同的数字而互不影响。

# 同步

POCO 提供的同步原语如下：

+   互斥

+   FastMutex

+   事件

+   条件

+   信号量

+   RWLock

这里需要注意的是`FastMutex`类。这通常是一种非递归互斥类型，但在 Windows 上是递归的。这意味着人们通常应该假设任一类型在同一线程中可以被同一线程多次锁定。

人们还可以使用`ScopedLock`类与互斥体一起使用，它确保封装的互斥体在当前作用域结束时被释放。

事件类似于 Windows 事件，不同之处在于它们仅限于单个进程。它们构成了 POCO 中条件变量的基础。

POCO 条件变量的功能与 Pthreads 等方式基本相同，不同之处在于它们不会出现虚假唤醒。通常条件变量会出现这些随机唤醒以进行优化。通过不必须明确检查条件变量等待返回时是否满足其条件，减轻了开发者的负担。

# C++线程

C++中的本地多线程支持在第五章中得到了广泛的覆盖，*本地 C++线程和原语*。

正如本章中 Boost 部分所述，C++多线程支持在很大程度上基于 Boost 线程 API，几乎使用相同的头文件和名称。API 本身再次让人联想到 Pthreads，尽管在某些方面有显著的不同，例如条件变量。

即将发布的章节将专门使用 C++线程支持作为示例。

# 整合

在本章涵盖的 API 中，只有 Qt 多线程 API 可以被认为是真正的高级。尽管其他 API（包括 C++11）具有一些更高级的概念，包括线程池和不需要直接使用线程的异步运行器，但 Qt 提供了一个完整的信号-槽架构，使得线程间通信异常容易。

正如本章所述，这种便利也伴随着成本，即必须开发自己的应用程序以适应 Qt 框架。这可能在项目中是不可接受的。

哪种 API 是正确的取决于人们的需求。然而，可以相对公平地说，当人们可以使用诸如 C++11 线程、POCO 等 API 时，直接使用 Pthreads、Windows 线程等并没有太多意义，这些 API 可以在不显著降低性能的情况下简化开发过程，并在各个平台上获得广泛的可移植性。

所有这些 API 在其核心功能上至少在某种程度上是可比较的。

# 总结

在本章中，我们详细研究了一些较流行的多线程 API 和框架，将它们并列起来，以了解它们的优势和劣势。我们通过一些示例展示了如何使用这些 API 来实现基本功能。

在下一章中，我们将详细讨论如何同步线程并在它们之间进行通信。


# 第四章：线程同步和通信

虽然通常线程用于相对独立地处理任务，但有许多情况下，人们希望在线程之间传递数据，甚至控制其他线程，比如来自中央任务调度器线程。本章将介绍如何使用 C++11 线程 API 完成这些任务。

本章涵盖的主题包括以下内容：

+   使用互斥锁、锁和类似的同步结构

+   使用条件变量和信号来控制线程

+   在线程之间安全地传递和共享数据

# 安全第一

并发的核心问题是确保在线程之间进行通信时对共享资源进行安全访问。还有线程能够进行通信和同步的问题。

多线程编程的挑战在于能够跟踪线程之间的每次交互，并确保每种形式的访问都得到保护，同时不会陷入死锁和数据竞争的陷阱。

在本章中，我们将看一个涉及任务调度器的相当复杂的例子。这是一种高并发、高吞吐量的情况，许多不同的要求与许多潜在的陷阱相结合，我们将在下面看到。

# 调度程序

多线程与大量线程之间的同步和通信的一个很好的例子是任务调度。在这里，目标是尽快接受传入的任务并将它们分配给工作线程。

在这种情况下，有许多不同的方法。通常情况下，有工作线程在活动循环中运行，不断轮询中央队列以获取新任务。这种方法的缺点包括在轮询上浪费处理器周期，并且在使用的同步机制（通常是互斥锁）上形成的拥塞。此外，当工作线程数量增加时，这种主动轮询方法的扩展性非常差。

理想情况下，每个工作线程都会空闲等待直到再次需要。为了实现这一点，我们必须从另一方面解决问题：不是从工作线程的角度，而是从队列的角度。就像操作系统的调度程序一样，调度程序既知道需要处理的任务，也知道可用的工作线程。

在这种方法中，一个中央调度器实例将接受新任务并主动分配给工作线程。该调度器实例还可以管理这些工作线程，例如它们的数量和优先级，这取决于传入任务的数量和任务的类型或其他属性。

# 高层视图

在其核心，我们的调度程序或调度器非常简单，像一个队列，所有调度逻辑都内置其中，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-mltrd/img/00016.jpeg)

从前面的高层视图可以看出，实际上并没有太多内容。然而，正如我们将在下面看到的，实际的实现确实有许多复杂之处。

# 实施

像往常一样，我们从`main`函数开始，包含在`main.cpp`中：

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

我们包括的自定义头文件是我们的调度器实现和我们将使用的`request`类。

全局上，我们定义了一个用于信号处理程序的原子变量，以及一个将同步输出（在标准输出上）的互斥锁，来自我们的日志方法：

```cpp
void sigint_handler(int sig) {
    signal_caught = 1;
} 

```

我们的信号处理函数（用于`SIGINT`信号）只是设置了我们之前定义的全局原子变量：

```cpp
void logFnc(string text) {
    logMutex.lock();
    cout << text << "\n";
    logMutex.unlock();
} 

```

在我们的日志函数中，我们使用全局互斥锁来确保对标准输出的写入是同步的：

```cpp
int main() {
    signal(SIGINT, &sigint_handler);
    Dispatcher::init(10); 

```

在`main`函数中，我们安装`SIGINT`的信号处理程序，以允许我们中断应用程序的执行。我们还调用`Dispatcher`类的静态`init()`函数来初始化它：

```cpp
    cout << "Initialised.\n";
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

接下来，我们设置循环，在其中我们将创建新的请求。在每个周期中，我们创建一个新的`Request`实例，并使用其`setValue()`函数设置一个整数值（当前周期号）。在将此新请求添加到`Dispatcher`时，我们还在请求实例上设置我们的日志函数，使用其静态的`addRequest()`函数。

这个循环将继续，直到达到最大周期数，或者使用*Ctrl*+*C*或类似方法发出`SIGINT`信号为止：

```cpp
        this_thread::sleep_for(chrono::seconds(5));
        Dispatcher::stop();
    cout << "Clean-up done.\n";
    return 0; 
} 

```

最后，我们使用线程的`sleep_for()`函数和`chrono`STL 头文件中的`chrono::seconds()`函数等待 5 秒。

我们还在返回之前在`Dispatcher`上调用`stop()`函数。

# 请求类

对于`Dispatcher`的请求总是派生自纯虚拟的`AbstractRequest`类：

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

这个`AbstractRequest`类定义了一个具有三个函数的 API，派生类始终必须实现这些函数。其中，`process()`和`finish()`函数是最通用的，可能在任何实际实现中使用。`setValue()`函数是特定于此演示实现的，可能会被调整或扩展以适应实际情况。

使用抽象类作为请求的基础的优势在于，只要它们都遵循相同的基本 API，`Dispatcher`类就可以处理许多不同类型的请求。

使用这个抽象接口，我们实现一个基本的`Request`类如下：

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

在头文件中，我们首先定义函数指针的格式。之后，我们实现请求 API，并将`setOutput()`函数添加到基本 API 中，该函数接受用于记录日志的函数指针。这两个 setter 函数仅将提供的参数分配给它们各自的私有类成员。

接下来，给出类函数的实现如下：

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

在实际实现中，可以将业务逻辑添加到`process()`函数中，而`finish()`函数包含完成请求的任何功能，例如将映射写入字符串。

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

虽然将请求添加到`Dispatcher`不需要任何特殊逻辑，但`Worker`类需要使用条件变量来与调度程序同步。对于 C++11 线程 API，这需要一个条件变量，一个互斥锁和一个唯一的锁。

唯一的锁封装了互斥锁，并且最终将与条件变量一起使用，我们将在下一刻看到。

除此之外，我们定义了启动和停止工作线程的方法，设置新请求进行处理的方法，以及获取其内部条件变量的访问权限。

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

除了条件变量的`getter`函数之外，我们定义了`run()`函数，`dispatcher`将在启动每个工作线程时运行。

它的主循环仅检查`stop()`函数是否已被调用，该函数会将运行布尔值设置为`false`，并结束工作线程。这在`Dispatcher`关闭时被使用，允许它终止工作线程。由于布尔值通常是原子的，设置和检查可以同时进行，而无需风险或需要互斥锁。

接下来，对`ready`变量的检查是为了确保在线程首次运行时实际上有一个请求在等待。在工作线程的第一次运行时，没有请求会等待，因此，尝试处理一个请求将导致崩溃。当`Dispatcher`设置一个新请求时，这个布尔变量将被设置为`true`。

如果有请求在等待，`ready`变量将再次设置为`false`，之后请求实例将调用其`process()`和`finish()`函数。这将在工作线程的线程上运行请求的业务逻辑，并完成它。

最后，工作线程使用其静态的`addWorker()`函数将自己添加到调度器。如果没有新请求可用，此函数将返回`false`，并导致工作线程等待直到有新请求可用。否则，工作线程将继续处理`Dispatcher`设置的新请求。

如果要求等待，我们进入一个新的循环。这个循环将确保当条件变量被唤醒时，是因为我们得到了`Dispatcher`（`ready`变量设置为`true`）的信号，而不是因为虚假唤醒。

最后，我们使用之前创建的唯一锁实例和超时进入条件变量的实际`wait()`函数。如果超时发生，我们可以终止线程，或者继续等待。在这里，我们选择什么都不做，只是重新进入等待循环。

# 调度器

作为最后一项，我们有`Dispatcher`类本身：

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

大部分内容都会看起来很熟悉。到目前为止，您已经推测到，这是一个完全静态的类。

继续，其实现如下：

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

在设置静态类成员之后，定义了`init()`函数。它启动指定数量的工作线程，并在各自的向量数据结构中保留对每个工作线程和线程实例的引用：

```cpp
    bool Dispatcher::stop() {
        for (int i = 0; i < allWorkers.size(); ++i) {
            allWorkers[i]->stop();
        }
            cout << "Stopped workers.\n";
            for (int j = 0; j < threads.size(); ++j) {
            threads[j]->join();
                    cout << "Joined threads.\n";
        }
    }

```

在`stop()`函数中，每个工作线程实例都调用其`stop()`函数。这将导致每个工作线程终止，正如我们在`Worker`类描述中看到的那样。

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

`addRequest()`函数是有趣的地方。在这个函数中，添加了一个新请求。接下来会发生什么取决于是否有工作线程在等待新请求。如果没有工作线程在等待（工作线程队列为空），则将请求添加到请求队列中。

使用互斥锁确保对这些队列的访问是安全的，因为工作线程将同时尝试访问这两个队列。

这里需要注意的一个重要问题是死锁的可能性。也就是说，两个线程将持有资源的锁，第二个线程在释放自己的锁之前等待第一个线程释放其锁。在单个作用域中使用多个互斥锁的每种情况都具有这种潜力。

在这个函数中，死锁的潜在可能性在于释放工作线程互斥锁，并在获取请求互斥锁时。在这个函数持有工作线程互斥锁并尝试获取请求锁（当没有工作线程可用时），有可能另一个线程持有请求互斥锁（寻找要处理的新请求）同时尝试获取工作线程互斥锁（找不到请求并将自己添加到工作线程队列）。

解决方案很简单：在获取下一个互斥锁之前释放一个互斥锁。在某人觉得必须持有多个互斥锁时，必须仔细检查和测试自己的代码是否存在潜在的死锁。在这种特殊情况下，当不再需要工作线程互斥锁时，或在获取请求互斥锁之前，显式释放工作线程互斥锁，从而防止死锁。

这段代码的另一个重要方面是它如何向工作线程发出信号。正如可以在 if/else 块的第一部分看到的那样，当工作线程队列不为空时，从队列中获取一个工作线程，设置请求，然后引用并发出条件变量的信号，或通知。

在内部，条件变量使用我们在`Worker`类定义中提供的互斥锁来保证对它的原子访问。当在条件变量上调用`notify_one()`函数（在其他 API 中通常称为`signal()`）时，它将通知等待条件变量返回并继续的线程队列中的第一个线程。

在`Worker`类的`run()`函数中，我们将等待这个通知事件。收到通知后，工作线程将继续处理新的请求。然后线程引用将从队列中移除，直到它再次添加自己，一旦它完成了处理请求：

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

在这个最后的函数中，工作线程在处理完一个请求后会将自己添加到队列中。它与之前的函数类似，首先会主动匹配等待在请求队列中的任何请求。如果没有可用的请求，工作线程将被添加到工作线程队列中。

这里需要注意的是，我们返回一个布尔值，指示调用线程是否应该等待新的请求，或者在尝试添加自己到队列时是否已经收到了新的请求。

虽然这段代码比之前的函数要简单，但由于在同一范围内处理了两个互斥锁，它仍然存在潜在的死锁问题。在这里，我们首先释放我们持有的互斥锁，然后再获取下一个互斥锁。

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

此时，我们已经清楚地看到，即使每个请求几乎没有时间来处理，请求仍然明显是并行执行的。第一个请求（请求 0）只有在第 16 个请求之后才开始处理，而第二个请求在第九个请求之后就已经完成了。

决定哪个线程，因此，哪个请求首先被处理的因素取决于操作系统调度程序和基于硬件的调度，如第二章中所述，“处理器和操作系统上的多线程实现”。这清楚地显示了即使在单个平台上，也不能对多线程应用程序的执行做出多少假设。

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

此时，第一个请求终于完成了。这可能表明，与后续请求相比，第一个请求的初始化时间总是会延迟。多次运行应用程序可以确认这一点。重要的是，如果处理顺序很重要，这种随机性不会对应用程序产生负面影响。

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

第 19 个请求也变得相当延迟，再次显示了多线程应用程序有多么不可预测。如果我们在这里并行处理大型数据集，每个请求中都有数据块，我们可能需要在某些时刻暂停以应对这些延迟，否则我们的输出缓存可能会变得太大。

由于这样做会对应用程序的性能产生负面影响，人们可能需要考虑低级优化，以及在特定处理器核心上对线程进行调度，以防止这种情况发生。

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

最初启动的所有 10 个工作线程在这里终止，因为我们调用了`Dispatcher`的`stop()`函数。

# 共享数据

在本章的示例中，我们看到了如何在线程之间共享信息，除了同步线程之外--这是我们从主线程传递到调度程序的请求的形式，每个请求都会传递到不同的线程中。

在线程之间共享数据的基本思想是要共享的数据以某种方式存在于两个或更多个线程都可以访问的地方。之后，我们必须确保只有一个线程可以修改数据，并且在读取数据时数据不会被修改。通常，我们会使用互斥锁或类似的方法来确保这一点。

# 使用读/写锁

在这里，读写锁是一种可能的优化，因为它们允许多个线程同时从单个数据源读取。如果一个应用程序中有多个工作线程反复读取相同的信息，使用读写锁比基本互斥锁更有效，因为尝试读取数据不会阻塞其他线程。

读写锁因此可以被用作互斥锁的更高级版本，即，它可以根据访问类型调整其行为。在内部，它建立在互斥锁（或信号量）和条件变量之上。

# 使用共享指针

共享指针首先通过 Boost 库提供，并在 C++11 中引入，它们是使用引用计数对堆分配实例进行内存管理的抽象。它们在某种程度上是线程安全的，因为可以创建多个共享指针实例，但引用的对象本身并不是线程安全的。

根据应用程序的不同，这可能已经足够了。为了使它们真正线程安全，可以使用原子操作。我们将在第八章中更详细地讨论这个问题，*原子操作 - 与硬件一起工作*。

# 总结

在本章中，我们讨论了如何以安全的方式在相当复杂的调度程序实现中在线程之间传递数据。我们还研究了所述调度程序的结果异步处理，并考虑了在线程之间传递数据的一些潜在替代方案和优化。

在这一点上，您应该能够安全地在线程之间传递数据，并同步访问其他共享资源。

在下一章中，我们将研究本地 C++线程和基本 API。
