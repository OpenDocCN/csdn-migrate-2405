# C++ 系统编程秘籍（二）

> 原文：[`annas-archive.org/md5/8831de64312a5d338410ec40c70fd171`](https://annas-archive.org/md5/8831de64312a5d338410ec40c70fd171)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：处理进程和线程

进程和线程是任何计算的基础。一个程序很少只由一个线程或进程组成。在本章中，你将学习处理线程和进程的基本示例。你还将学习处理线程相对于**可移植操作系统接口**（**POSIX**）来说是多么容易和方便。学习这些技能是作为系统开发人员核心技能的重要部分。C++标准库中没有*进程*的概念，因此将使用 Linux 本地实现。

本章将涵盖以下示例：

+   启动一个新进程

+   杀死一个进程

+   创建一个新线程

+   创建一个守护进程

# 技术要求

为了让你立即尝试这些程序，我们已经设置了一个 Docker 镜像，其中包含了本书中需要的所有工具和库。这是基于 Ubuntu 19.04 的。

为了设置它，按照以下步骤：

1.  从[www.docker.com](https://www.docker.com/)下载并安装 Docker Engine。

1.  通过运行以下命令从 Docker Hub 拉取镜像：`docker pull kasperondocker/system_programming_cookbook:latest`。

1.  镜像现在应该可用。输入以下命令查看镜像：`docker images`。

1.  现在你应该至少有这个镜像：`kasperondocker/system_programming_cookbook`。

1.  使用以下命令以交互式 shell 运行 Docker 镜像：`docker run -it --cap-add sys_ptrace kasperondocker/system_programming_cookbook:latest /bin/bash`。

1.  正在运行的容器上的 shell 现在可用。输入`root@39a5a8934370/# cd /BOOK/`以获取所有按章节开发的程序。

需要`--cap-add sys_ptrace`参数来允许 Docker 容器中的**GNU 项目调试器**（**GDB**）设置断点，默认情况下 Docker 不允许。

**免责声明**：C++20 标准已经在二月底的布拉格会议上由 WG21 批准（即技术上完成）。这意味着本书使用的 GCC 编译器版本 8.3.0 不包括（或者对 C++20 的新功能支持非常有限）。因此，Docker 镜像不包括 C++20 示例代码。GCC 将最新功能的开发保留在分支中（你必须使用适当的标志，例如`-std=c++2a`）；因此，鼓励你自己尝试。所以，克隆并探索 GCC 合同和模块分支，玩得开心。

# 启动一个新进程

这个示例将展示如何通过程序启动一个新的进程。C++标准不包括对进程的任何支持，因此将使用 Linux 本地实现。能够在程序中管理进程是一项重要的技能，这个示例将教会你进程的基本概念，**进程标识符**（**PID**），父 PID 和所需的系统调用。

# 如何做...

这个示例将展示如何启动一个子进程，以及如何通过使用 Linux 系统调用使父进程等待子进程完成。将展示两种不同的技术：第一种是父进程只 fork 子进程；第二种是子进程使用`execl`系统调用运行一个应用程序。

系统调用的另一种选择是使用外部库（或框架），比如**Boost**库。

1.  首先，在一个名为`process_01.cpp`的新文件中输入程序：

```cpp
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <iostream>

int main(void)
{
    pid_t child;
    int status;
    std::cout << "I am the parent, my PID is " << getpid()
        << std::endl;
    std::cout << "My parent's PID is " << getppid() << std::endl;
    std::cout << "I am going to create a new process..."
        << std::endl;
    child = fork();
    if (child == -1)
    {
```

1.  我们必须考虑一个子进程可能没有被 fork 的情况，所以我们需要写这部分：

```cpp
        // fork() returns -1 on failure
        std::cout << "fork() failed." << std::endl;
        return (-1);
    }
    else if (child == 0)
    {
```

1.  这个分支是一个快乐的情况，父进程可以正确地 fork 它的子进程。这里的子进程只是将它的 PID 打印到标准输出：

```cpp
      std::cout << "I am the child, my PID is " << std::endl;
      std::cout << "My parent's PID is " << getppid() << std::endl;
    }
    else
    {
```

1.  现在，我们必须让父进程等待子进程完成：

```cpp
        wait(&status); // wait for the child process to finish...
        std::cout << "I am the parent, my PID is still "
            << getpid() << std::endl;
    }
    return (0);
}
```

现在，让我们开发前一个程序的`fork-exec`版本。

1.  首先，在一个名为`process_02.cpp`的新文件中输入程序：

```cpp
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <iostream>

int main(void)
{
    pxid_t child;
    int status;
    std::cout << "I am the parent, my PID is " 
              << getpid() << std::endl;
    std::cout << "My parent's PID is " 
              << getppid() << std::endl;
    std::cout << "I am going to create a new process..." 
              << std::endl;
    child = fork();
    if (child == -1)
    {
        // fork() returns -1 on failure
        std::cout << "fork() failed." << std::endl;
        return 1;
    }
    else if (child == 0)
    {
```

1.  以下代码块显示了使用`execl`*运行`ls -l`的子部分：*

```cpp
        if (execl("/usr/bin/ls", "ls", "-l", NULL) < 0) 
        {
            std::cout << "execl failed!" << std::endl;
            return 2;
        }
        std::cout << "I am the child, my PID is " 
                  << getpid() << std::endl;
        std::cout << "My parent's PID is " 
                  << getppid() << std::endl;
    }
    else
    {
        wait(&status); // wait for the child process to finish...
    }
    return (0);
}
```

下一节将描述两种不同方法（`fork`与`fork-exec`）的详细信息。

# 它是如何工作的...

让我们分析前面的两个例子：

1.  `fork`系统调用：通过编译`g++ process_01.cpp`并运行`./a.out`，输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/ee5c3fb9-61b9-4ed8-a7c1-ba0ba262c4d8.png)

通过调用`fork`，程序创建了调用进程的副本。这意味着这两个进程具有相同的代码，尽管它们是两个完全不同的进程，但代码库将是相同的。用户必须在`else if (child == 0)`部分中挂接子代码。最终，父进程将不得不等待子进程完成任务，使用`wait(&status);`调用。另一种选择是`waitpid (123, &status, WNOHANG);`调用，它等待特定的 PID（或者如果第一个参数是`-1`，则等待所有子进程）。`WNOHANG`使`waitpid`立即返回，即使子进程的状态不可用。

如果父进程不等待子进程完成会发生什么？也就是说，如果没有`wait(&status);`调用会发生什么？从技术上讲，父进程将完成，而仍在运行的子进程将成为**僵尸**。这在 Linux 内核 2.6 版本之前是一个巨大的问题，因为僵尸进程会一直停留在系统中，直到它们被*等待*。子进程现在由`init`进程（其 PID 为`1`）接管，后者定期等待可能会死亡的子进程。

1.  `fork-exec`系统调用：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/ba51686a-cefb-4c91-9f71-5b4a93a1fc55.png)

创建进程的最常见方法是`fork`/`exec`组合。正如我们所见，`fork`创建一个完全新的进程，具有自己的 PID，但现在，`else if (child == 0)`部分执行一个外部进程，该进程具有不同的代码库。这个例子只是调用`ls -l`命令来列出文件和目录，但开发人员可以在这里放置任何可执行文件。

# 还有更多...

为什么应该使用进程而不是线程是一个重要的方面需要考虑。答案取决于情况，但一般来说，应该考虑以下方面：

+   线程在启动它的进程的相同内存空间中运行。这一方面既有利也有弊。主要的含义是，如果一个线程崩溃，整个应用程序都会崩溃。

+   线程之间的通信比进程间通信要快得多。

+   一个进程可以通过`setrlimit`以较低的权限生成，以限制不受信任的代码可用的资源。

+   在进程中设计的程序比在线程中设计的程序更分离。

在这个步骤中看到的`fork`/`execl`/`wait`调用有许多变体。`man pages`提供了对整个调用系列的全面文档。以下屏幕截图是关于`man execl`的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/67bf3f79-e515-41b1-9a1a-779d804c909d.png)

# 另请参阅

请参阅第一章，*开始系统编程*，以便了解`man pages`和 Linux 的基础知识。

# 杀死一个进程

在上一个步骤中，我们已经看到了启动新进程的两种方式，其中父进程总是等待子进程完成任务。这并不总是这样。有时，父进程应该能够杀死子进程。在这个步骤中，我们将看到如何做到这一点的一个例子。

# 做好准备

作为先决条件，重要的是要通过*启动新进程*的步骤。

# 如何做...

在这一部分，我们创建一个程序，其中父进程 fork 其子进程，子进程将执行一个无限循环，父进程将杀死它：

1.  让我们开发将被父进程杀死的子程序：

```cpp
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <iostream>

int main(void)
{
    std::cout << "Running child ..." << std::endl;
    while (true)
        ;
}
```

1.  接下来，我们必须开发父程序（`/BOOK/Chapter03`文件夹中的`process_03.cpp`）：

```cpp
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <iostream>
int main(void)
{
    pid_t child;
    int status;
    std::cout << "I am the parent, my PID is " << getpid() 
              << std::endl;
    child = fork();
    std::cout << "Forked a child process with PID = " 
              << child << std::endl;
    if (child == -1)
    {
        std::cout << "fork() failed." << std::endl;
        return 1;
    }
    else if (child == 0)
    {
```

1.  接下来，在父程序的子部分中，我们启动了在上一步中开发的子程序：

```cpp
        std::cout << "About to run the child process with PID = " 
                  << child << std::endl;
        if (execl("./child.out", "child.out", NULL) < 0)
        {
            std::cout << "error in executing child proceess " 
                      << std::endl;
            return 2;
        }
    }
    else
    {
```

1.  在父程序的父节（`else`部分）中，我们必须杀死子进程并检查它是否被正确杀死：

```cpp
        std::cout << "killing the child process with PID = " 
                  << child << std::endl;
        int status = kill (child, 9);
        if (status == 0)
            std::cout << "child process killed ...." << std::endl;
        else
            std::cout << "there was a problem killing
                the process with PID = " 
                      << child << std::endl;
    }
    return (0);
}
```

我们已经看到了父程序和子程序，父程序杀死了子进程。在下一节中，我们将学习这些程序的机制。

# 它是如何工作的...

在这之前，我们需要编译子程序和父程序——`g++ process_03.cpp`和`g++ -o child.out process_04.cpp`。

在编译`process_04.cpp`时，我们必须指定`-o child.out`，这是父进程所需的（进程名为`a.out`）。通过运行它，产生的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/93a1d294-77bb-4e04-b466-55e24149172d.png)

执行显示，PID 为 218 的子进程被父进程正确杀死。

这个教程中的代码只是*启动一个新进程*教程的变体。不同之处在于现在，父进程在其编制的一部分中杀死子进程`int status = kill (child, 9);`。`kill`系统调用接受要杀死的进程的 PID 作为第一个参数，作为第二个参数的是要发送给子进程的信号。接受的信号如下：

+   `1` = `HUP`（挂断）

+   `2` = `INT`（中断）

+   `3` = `QUIT`（退出）

+   `6` = `ABRT`（中止）

+   `9` = `KILL`（不可捕获，不可忽略的终止）

+   `14` = `ALRM`（闹钟）

+   `15` = `TERM`（软件终止信号）

`man 2 kill`，`kill`系统调用，向进程发送信号。成功时返回`0`；否则返回`-1`。你需要包含`#include <sys/types.h>`和`#include <signal.h>`来使用它。

# 还有更多...

在第二章的*理解并发性*教程中，我们提供了两种基于`std::thread`和`std::async`的替代解决方案（并且鼓励使用它们），如果可能的话。下一个教程还提供了`std::thread`使用的具体示例。

# 创建一个新线程

进程并不是构建软件系统的唯一方式；一个轻量级的替代方案是使用线程。这个教程展示了如何使用 C++标准库创建和管理线程。我们已经知道使用 C++标准库的主要优势是它的可移植性和不依赖外部库（例如 Boost）。

# 如何做...

我们将编写的代码将是对大整数向量求和的并发版本。向量被分成两部分；每个线程计算其部分的总和，主线程显示结果。

1.  让我们定义一个包含 100,000 个整数的向量，并在`main`方法中生成随机数：

```cpp
#include <iostream>
#include <thread>
#include <vector>
#include <algorithm>

void threadFunction (std::vector<int> &speeds, int start, int
    end, int& res);

int main()
{    
    std::vector<int> speeds (100000);
    std::generate(begin(speeds), end(speeds), [] () 
        { return rand() % 10 ; });

```

1.  接下来，启动第一个线程，传递前 50,000 个整数：

```cpp
    int th1Result = 0;
    std::thread t1 (threadFunction, std::ref(speeds), 0, 49999, 
        std::ref(th1Result));

```

1.  然后，启动第二个线程，传递第二个 50,000 个整数：

```cpp
    int th2Result = 0;    
    std::thread t2 (threadFunction, std::ref(speeds), 50000, 99999, 
        std::ref(th2Result));

```

1.  等待两个线程的结果：

```cpp
    t1.join();
    t2.join();
    std::cout << "Result = " << th1Result + th2Result
        << std::endl;
    return 0;
}

void threadFunction (std::vector<int> &speeds, int start, int 
    end, int& res)
{
    std::cout << "starting thread ... " << std::endl;
    for (int i = start; i <= end; ++i)
    res += speeds[i];
    std::cout << "end thread ... " << std::endl;
}
```

下一节解释了动态。

# 它是如何工作的...

通过使用`g++ thread_01.cpp -lpthread`编译程序并执行它，输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/49847d80-39be-498e-864d-f9653ab3426d.png)

在*步骤 1*中，我们定义了`threadFunction`方法，这是基本的线程单元，负责从`start`到`end`对`speeds`中的元素求和，并将结果保存在`res`输出变量中。

在*步骤 2*和*步骤 3*中，我们启动了两个线程来计算`t1`线程的前 50,000 个项目的计算和第二个`t2`线程的 50,000 个项目。这两个线程并发运行，所以我们需要等待它们完成。在*步骤 4*中，我们等待`th1`和`th2`的结果完成，将两个结果—`th1Results`和`th2Results`—相加，并将它们打印在标准输出（`stdout`）中。

# 还有更多...

*启动一个新进程*食谱展示了如何创建一个进程，以及在哪些情况下进程适合解决方案。一个值得强调的重要方面是，线程在创建它的进程的**相同地址空间**中运行。尽管线程仍然是一种在更独立（可运行）模块中构建系统软件的好方法，但如果线程崩溃（由于段错误，或者如果某种原因调用了**`terminate`**等），整个应用程序都会崩溃。

从积极的一面来看，正如我们在前面的代码中看到的，线程之间的通信非常简单高效。此外，线程彼此之间，以及创建它们的进程，共享**静态**和**堆**内存。

尽管这个食谱中的代码很简单，但它展示了如何并发执行一个任务（大数组的总和）。值得一提的是，如果算法没有设计为并发运行，也就是说，如果线程之间存在依赖关系，那么多线程应用程序就毫无价值。

在这种情况下，重要的是要注意，如果两个线程同时在两个处理器上运行，我们会使用**并行**这个词。在这种情况下，我们没有这个保证。

我们使用了 C++标准库中的`std::thread`，但是同样的例子也可以使用`std::async`来编写。《第二章》《重温 C++》展示了两种方法的例子。您可以尝试使用第二种方法重写这个食谱的代码。

# 另请参阅

在《第二章》《重温 C++》中的*理解并发*食谱中，介绍了一个包括`std::thread`和`std::async`的并发主题的食谱。您还可以阅读 Scott Meyers 的《Effective Modern C++》和 Bjarne Stroustrup 的《C++程序设计语言》中专门介绍线程的部分。

# 创建守护进程

系统编程实际上是与操作系统资源密切打交道，创建进程、线程、释放资源等等。有些情况下，我们需要一个进程*无限期地*运行；也就是说，一个进程首先提供一些服务或管理资源，然后一直运行下去。在后台*无限期运行*的进程称为**守护进程**。这个食谱将展示如何以编程方式生成一个守护进程。

# 操作步骤如下...

如前所述，守护进程是一个无限期运行的进程。为了被分类为*守护进程*，一个进程必须具有一些明确定义的属性，这将在这个食谱中用一个程序来展示。

1.  输入以下代码通过调用`umask`系统调用重置子进程的初始访问权限：

```cpp
#include <unistd.h>
#include <sys/stat.h>
#include <iostream>

int main(void)
{
    pid_t child;
    int status;
    std::cout << "I am the parent, my PID is " << getpid()
        << std::endl;
    std::cout << "I am going to create a new daemon process..."
        << std::endl;

    // 1\. clear file creation mask
    umask(0);

```

1.  输入代码以 fork 一个子进程：

```cpp
    child = fork();
    if (child == -1)
    {
        std::cout << "fork() failed." << std::endl;
        return (-1);
    }
    else if (child == 0) // child (daemon) process
    {

```

1.  在子进程上输入`setsid`命令：

```cpp
        setsid();

```

1.  将工作目录更改为子进程（现在是一个守护进程）：

```cpp
        if (chdir("/") < 0)
            std::cout << "Couldn't change directly" << std::endl;

```

1.  运行守护进程特定的任务——在这种情况下，只需睡眠`10`秒：

```cpp
        // Attach here the daemon specific long running
        // tasks ... sleep for now.
        sleep (10);
    }

```

1.  父进程在`fork`后退出：

```cpp
    return (0);
}
```

下一节将更详细地解释这六点。

# 工作原理...

使用`g++ daemon_01.cpp`（在 Docker 镜像的`/BOOK/Chapter03`文件夹中）编译代码并运行。输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/d3d2b3b2-859c-41b4-a28e-75a75e9411ee.png)

当我们在 shell 上运行一个进程时，终端会等待子进程完成后才准备好接受另一个命令。我们可以使用`&`符号运行命令（例如，`ls -l &`），shell 会提示终端输入另一个命令。请注意，子进程仍然在与父进程相同的会话中。要使一个进程成为守护进程，应该遵循以下规则（*2*和*3*是强制的；其他是可选的）：

1.  使用参数`0`调用`umask`（`umask(0)`）：当父进程创建子进程时，文件模式创建掩码会被继承（也就是说，子进程将继承父进程的初始访问权限）。我们要确保重置它们。

1.  **在 fork 后使父进程退出**：在前面的代码中，父进程创建了子进程后返回。

1.  **调用** `setsid`。这做了三件事：

+   子进程成为一个新创建会话的领导者。

+   它成为一个新的进程组的领导者。

+   它与其控制终端解除关联。

1.  **更改工作目录**：父进程可能在一个临时（或挂载的）文件夹中运行，这个文件夹可能不会长时间存在。将当前文件夹设置为满足守护进程的长期期望是一个好习惯。

1.  **日志记录**：由于守护服务不再与任何终端设备相关联，将标准输入、输出和错误重定向到`/dev/null`是一个好习惯。

# 还有更多...

到目前为止，一个进程有一个 PID 作为其唯一标识符。它还属于一个具有**进程组 ID**（**PGID**）的组。进程组是一个或多个进程的集合。同一组中的所有进程可以从同一个终端接收信号。每个组都有一个领导者，PGID 的值与领导者的 PID 相同。

一个会话是一个或多个进程组的集合。这个示例表明可以通过调用`setsid`方法创建一个新的会话。

一个会话可以有一个（单一的）控制终端。`ps -efj`命令显示所有使用`PID`、`PPID`和`PGID`以及每个进程的控制终端（`TTY`）信息的进程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/68f40447-735e-48ba-a16b-4a44ac8be662.png)

输出显示`./a.out`守护进程的`PID = 19`，它是组的领导者（`PGID = 19`），并且它没有连接到任何控制终端（`TTY= ?`）。

# 参见

W.R. Stevens 的*UNIX 环境高级编程*第十三章专门讨论了守护进程。


# 第四章：深入了解内存管理

内存在处理系统开发时是核心概念之一。分配、释放、学习内存管理方式，以及了解 C++可以提供什么来简化和管理内存，都是至关重要的。本章将通过学习如何使用 C++智能指针、对齐内存、内存映射 I/O 和分配器来帮助您理解内存的工作原理。

本章将涵盖以下主题：

+   学习自动与动态内存

+   学习何时使用`unique_ptr`，以及对大小的影响

+   学习何时使用`shared_ptr`，以及对大小的影响

+   分配对齐内存

+   检查分配的内存是否对齐

+   处理内存映射 I/O

+   亲自处理分配器

# 技术要求

为了让您立即尝试这些程序，我们设置了一个 Docker 镜像，其中包含本书中将需要的所有工具和库。这是基于 Ubuntu 19.04 的。

为了设置它，请按照以下步骤进行：

1.  从[www.docke](https://www.docker.com/)[r.com](https://www.docker.com/)下载并安装 Docker Engine。

1.  通过运行以下命令从 Docker Hub 拉取镜像：`docker pull kasperondocker/system_programming_cookbook:latest`。

1.  现在应该可以使用该镜像。键入以下命令查看镜像：`docker images`。

1.  现在您应该至少有这个镜像：`kasperondocker/system_programming_cookbook`。

1.  通过以下命令以交互式 shell 运行 Docker 镜像：`docker run -it --cap-add sys_ptrace kasperondocker/system_programming_cookbook:latest /bin/bash`。

1.  正在运行的容器上的 shell 现在可用。键入`root@39a5a8934370/# cd /BOOK/`以获取按章节开发的所有程序。

需要`--cap-add sys_ptrace`参数以允许 Docker 容器中的 GNU Project Debugger（GDB）设置断点，默认情况下 Docker 不允许。

**免责声明**：C++20 标准已经在二月底的布拉格会议上由 WG21 批准（即技术上最终确定）。这意味着本书使用的 GCC 编译器版本 8.3.0 不包括（或者对 C++20 的新功能支持非常有限）。因此，Docker 镜像不包括 C++20 的代码。GCC 将最新功能的开发保留在分支中（您必须使用适当的标志，例如`-std=c++2a`）；因此，鼓励您自行尝试。因此，请克隆并探索 GCC 合同和模块分支，并尽情玩耍。

# 学习自动与动态内存

本教程将重点介绍 C++提供的两种主要策略来分配内存：**自动**和**动态**内存分配。当变量的作用域持续到其定义的块的持续时间时，变量是自动的，并且其分配和释放是自动的（即不由开发人员决定）。变量分配在堆栈上。

如果变量在内存的动态部分（自由存储区，通常称为*堆*）中分配，并且分配和释放由开发人员决定，则变量是动态的。动态内存分配提供的更大灵活性伴随着更多的工作量，以避免内存泄漏、悬空指针等。

# 如何做...

本节将展示自动和动态变量分配的两个示例。

1.  让我们创建一个我们需要的实用类：

```cpp
class User
{
public:
    User(){
        std::cout << "User constructor" << std::endl;
    };
    ~User(){
        std::cout << "User Destructor" << std::endl;
    };

    void cheers() 
    {
        std::cout << " hello!" << std::endl;};
    };
};
```

1.  现在，让我们创建`main`模块来显示自动内存使用情况：

```cpp
#include <iostream>

int main()
{
    std::cout << "Start ... " << std::endl;
    {
        User developer;
        developer.cheers();
    }
    std::cout << "End ... " << std::endl;
}
```

1.  现在，我们将为动态内存使用编写`main`模块：

```cpp
#include <iostream>

int main()
{
    std::cout << "Start ... " << std::endl;
    {
        User* developer = new User();
        developer->cheers();
        delete developer;
    }
    std::cout << "End ... " << std::endl;
}
```

这两个程序，尽管结果相同，但展示了处理内存的两种不同方式。

# 工作原理...

在第一步中，我们定义了一个`User`类，用于展示自动和动态内存分配之间的区别。它的构造函数和析构函数将用于显示类何时分配和释放。

在*步骤 2*中，我们可以看到变量只是定义为`User developer;`。C++运行时将负责在堆栈上分配内存并释放内存，而开发人员无需额外工作。这种类型的内存管理更快，更容易，但有两个主要成本：

+   内存量是有限的。

+   变量仅在内部`{ }`块中有效和可见，其中它被分配。

在*步骤 3*中，相同的对象分配在动态内存（即**堆**）上。主要区别在于现在开发人员负责分配和释放所需的内存量。如果内存没有被释放（使用`free`），就会发生泄漏。动态管理内存的优点如下：

+   灵活性：指针引用分配的内存（`developer`变量）可以在整个程序中使用。

+   可用的内存量远远超过自动内存管理的内存量。

# 还有更多...

使用更新的 C++标准（从版本 11 开始），可以安全地避免使用`new`和`delete`，而使用智能指针（`shared_ptr`和`unique_ptr`）。这两个工具将在不再使用内存时负责释放内存。第二章，*重温 C++*，提供了智能指针的复习。

# 另请参阅

接下来的两个配方将展示何时使用`unique_ptr`和`shared_ptr`。

# 学习何时使用`unique_ptr`，以及大小的影响

在上一个配方中，我们已经学习了 C++中管理内存的两种基本方式：自动和动态。我们还了解到，与自动内存（即从堆栈中可用）相比，动态内存对开发人员的数量更多，并提供了更大的灵活性。另一方面，处理动态内存可能是一种不愉快的体验：

+   指针不指示它指向数组还是单个对象。

+   释放分配的内存时，您不知道是否必须使用`delete`还是`delete[]`，因此您必须查看变量的定义方式。

+   没有明确的方法告诉指针是否悬空。

这些只是您在处理动态内存以及`new`和`delete`时可能遇到的一些问题。`unique_ptr`是一个智能指针，这意味着它知道何时应该释放内存，从而减轻了开发人员的负担。在本配方中，您将学习如何正确使用`unique_ptr`和`make_unique`。

# 如何做...

在本节中，我们将开发一个程序，以了解为什么`unique_ptr`是处理动态内存的便捷方式；第二个方面是了解`unique_ptr`是否与原始指针大小相同：

1.  我们将重用上一个配方中开发的`User`类。

1.  让我们编写`main`程序，使用`make_unique`分配`User`对象并使用`unique_ptr`：

```cpp
#include <iostream>

int main()
{
    std::cout << "Start ... " << std::endl;
    {
        auto developer = std::make_unique<User>();
        developer->cheers();
    }
    std::cout << "End ... " << std::endl;
}
```

1.  让我们看看内存的影响：

```cpp
auto developer = std::make_unique<User>();
developer->cheers();

User* developer2 = new User();
std::cout << "developer size = " << sizeof (developer) << std::endl;
std::cout << "developer2 size = " << sizeof (developer2) << std::endl;
delete developer2;
```

您认为`developer`和`developer2`之间的大小差异是多少？

# 它是如何工作的...

在*步骤 2*中，我们使用`unique_ptr`来定义使用`std::make_unique`分配的变量。一旦分配了变量，由于析构函数会自动为我们释放内存，因此不会有内存泄漏的风险。输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/a9d63859-8852-406f-8c0e-3474395f5d97.png)

在*步骤 3*中，我们想要检查`unique_ptr`是否与原始指针相比增加了任何内存。好消息是，`unique_ptr`与原始指针版本的大小相同。此步骤的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/541b1ef5-331f-4f88-b69d-1e6006d78c37.png)

`developer`和`developer2`变量的大小相同，开发人员可以以相同的方式处理它们。

一个经验法则是仅对具有**独占所有权的资源**使用`unique_ptr`，这代表了大多数开发人员的用例。

# 还有更多...

默认情况下，`unique_ptr`调用对象的默认`delete`析构函数，但可以指定自定义的`delete`析构函数。如果指针变量不代表独占所有权，而是共享所有权，将其转换为`shared_ptr`很容易。

重要的一点要强调的是，`make_unique`不是 C++11 标准库的一部分，而是 C++14 库的一部分。如果你使用的是 C++11 标准库，它的实现是非常简单的。

# 另请参阅

第二章，*重温 C++*有一个专门讨论智能指针的配方，其中有一个关于共享和独特指针的配方。建议阅读的是 Scott Meyers 的*Effective Modern C++*。

# 学习何时使用 shared_ptr，以及大小的影响

在前面的配方中，我们已经学会了如何以一种非常方便的方式管理动态内存（在堆上分配），使用`unique_ptr`。我们也学到了`unique_ptr`必须在内存的独占所有权或由内存管理的资源的情况下使用。但是，如果我们有一个资源是由多个实体共同拥有的呢？如果我们必须在所有者完成工作后释放要管理的内存呢？好吧，这正是`shared_ptr`的用例。就像`unique_ptr`一样，对于`shared_ptr`，我们不必使用`new`来分配内存，但是有一个模板函数（C++标准库的一部分），`make_shared`。 

# 如何做到...

在本节中，我们将开发一个程序来展示如何使用`shared_ptr`。您将了解到只有在所有者不再使用内存时，内存才会被释放：

1.  我们将重用第一个配方中开发的`User`类。现在让我们编写`main`模块：

```cpp
int main()
{
    std::cout << "Start ... " << std::endl;
    auto shared1 = std::make_shared<User>();
    {
        auto shared2 = shared1;
        shared2->cheers(); std::cout << " from shared2"
            << std::endl;
        shared1->cheers(); std::cout << " from shared1"
            << std::endl;
    }
    std::cout << "End ... " << std::endl;
}
```

1.  现在，让我们通过编写这个程序来看一下`shared_ptr`使用的内存：

```cpp
int main()
{
    std::cout << "Start ... " << std::endl;
    auto shared1 = std::make_shared<User>();
   {
        auto shared2 = shared1;
        User* newAllocation = new User();
        auto uniqueAllocation = std::make_unique<User>();

        std::cout << "shared2 size = " << sizeof (shared2)
            << std::endl;
        std::cout << "newAllocation size = " <<
            sizeof (newAllocation) << std::endl;
        std::cout << "uniqueAllocation size = " <<
            sizeof (uniqueAllocation) << std::endl;

        delete newAllocation;
    }
    std::cout << "End ... " << std::endl;
}
```

在这一点上，我们应该知道`unique_ptr`的大小与原始指针相比（正如我们在*学习何时使用 unique_ptr 以及大小的影响*配方中所学到的）。`shared_ptr`变量的大小是多少？还是一样的？在下一节中，我们将了解这个重要的方面。

# 它是如何工作的...

在前面的第一个程序中，我们展示了如何使用`shared_ptr`。首先，我们分配了一个内存块，其中包含了一个类型为`User`的对象，`auto shared1 = std::make_shared<User>();`。到目前为止，`User`资源由`shared1`变量拥有。接下来，我们将`shared1`变量分配给`shared2`，通过`auto shared2 = shared1;`。这意味着包含`User`对象的内存现在由`shared1`和`shared2`指向。使用构造函数复制`auto shared2 (shared1);`也可以达到相同的目标。由于`User`现在由两个变量指向，所以使用的内存只有在所有变量超出范围时才会被释放。事实上，输出证明了内存在主块结束时被释放（`User`的析构函数被调用），而不是在内部块结束时，就像`unique_ptr`一样。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/a75c73de-d7b4-4ff1-9412-af044422965d.png)

`shared_ptr`对内存的影响与`unique_ptr`不同。原因是`shared_ptr`的实现需要一个原始指针来跟踪内存（与`unique_ptr`一样），以及另一个原始指针用于资源的引用计数。

这个引用计数变量必须是原子的，因为它可以被不同的线程增加和减少：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/2bbb9914-5677-489e-adc5-d9acef0e9550.png)

`shared_ptr`变量的内存大小通常是原始指针的两倍，正如在运行第二个程序时在前面的输出中所看到的。

# 还有更多...

另一个有趣的点不容忽视的是，由于`shared_ptr`包含原子变量，它通常比普通变量慢。

# 另请参阅

第二章，*重温 C++*，有一个专门介绍智能指针的示例，其中包括一个关于共享指针和唯一指针的示例。建议阅读 Scott Meyers 的*Effective Modern C++*。

# 分配对齐内存

编写系统程序可能需要使用在内存中对齐的数据，以便有效地访问硬件（在某些情况下，甚至是访问硬件）。例如，在 32 位架构机器上，我们将内存分配对齐到 4 字节边界。在这个示例中，您将学习如何使用 C++11 的`std::aligned_storage`来分配对齐内存。当然，还有其他更传统的机制来分配对齐内存，但本书的目标是尽可能使用 C++标准库工具。

# 如何做...

在本节中，我们将编写一个程序，该程序将使用使用`std::aligned_storage`分配的内存，并将展示`std::alignment_of`的使用：

1.  让我们从编写一个程序开始，检查当前计算机上整数和双精度浮点数的默认对齐边界是多少：

```cpp
#include <type_traits>
#include <iostream>
int main()
{
    std::cout << "int alignment = " << std::alignment_of<int>
        ::value << std::endl;
    std::cout << "double alignment = " << 
        std::alignment_of<double>::value << std::endl;
    return (0);
}
```

1.  现在，让我们编写一个程序来分配对齐到特定大小的内存。为此，让我们使用`std::aligned_storage`：

```cpp
#include <type_traits>
#include <iostream>
typedef std::aligned_storage<sizeof(int), 8>::type intAligned;
int main()
{
    intAligned i, j;
    new (&i) int();
    new (&j) int();

    int* iu = &reinterpret_cast<int&>(i);
    *iu = 12;
    int* ju = &reinterpret_cast<int&>(j);
    *ju = 13;

    std::cout << "alignment = " << std::alignment
        _of<intAligned>::value << std::endl;
    std::cout << "value = " << *iu << std::endl;
    std::cout << "value2 = " << reinterpret_cast<int&>(i)
        << std::endl;
    return (0);
}
```

分配对齐内存可能会很棘手，C++标准库（从第 11 版开始）提供了这两个功能（`std::alignment_of`，`std::aligned_storage`）来简化它。下一节将描述其背后的机制。

# 它是如何工作的...

第一个程序非常简单，通过`std::alignment_of`显示了两种原始类型在内存中的自然对齐。通过编译（`g++ alignedStorage.cpp`）并运行程序，我们得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/cb15931f-34a9-47f0-8177-6b312346afba.png)

这意味着每个整数将在`4`字节的边界上对齐，并且浮点类型将在`8`字节处对齐。

在第二个程序中，我们需要一个对齐到`8`字节的整数。通过编译并运行可执行文件，输出将类似于这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/9f9a06a2-f91c-41b7-a846-570c3b5837e4.png)

你可能已经注意到，我已经使用了`-g`选项进行了编译（添加调试符号）。我们这样做是为了在 GDB 中的内存转储中显示整数的内存正确地对齐在`8`字节处：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/71381006-7525-4b1d-9919-2163adf644e0.png)

从调试会话中，我们可以看到通过`x/20bd iu`（`x`=*内存转储*）命令，我们在`iu`变量地址之后转储了`20`字节的内存。我们可以看到这里有一些有趣的东西：`iu`和`ju`变量都对齐在`8`字节处。每个内存行显示`8`字节（测试一下：`0x7ffc57654470`* - * `0x7ffc57654468` = `8`）。

# 还有更多...

玩弄内存总是有风险的，这些新的 C++特性（以及`std`命名空间中的其他可用特性）帮助我们**玩得更安全**。建议仍然是一样的：过早的优化必须谨慎使用；只有在必要时才进行优化（即使用对齐内存）。最后一个建议：不建议使用`reinterpret_cast`，因为它在低级别操纵内存。在使用它时，您需要知道自己在做什么。

# 另请参阅

Bjarne Stroustrup 的*The C++ Programming Language, Fourth Edition*的最新版本有一段关于*内存对齐*（*6.2.9*）和*aligned_storage*（*35.4.1*）的段落。

# 检查分配的内存是否对齐

在前一个示例中，您已经学会了如何使用 C++11 来分配对齐内存。现在的问题是：我们如何知道内存是否正确对齐？这个示例将教会您这一点。

# 如何做...

我们将使用前面的程序，并稍作修改，看看如何检查指针是否对齐：

1.  让我们修改前面的程序，如下所示：

```cpp
#include <type_traits>
#include <iostream>

using intAligned8 = std::aligned_storage<sizeof(int), 8>::type;
using intAligned4 = std::aligned_storage<sizeof(int), 4>::type;

int main()
{
    intAligned8 i; new(&i) int();
    intAligned4 j; new (&j) int();

    int* iu = &reinterpret_cast<int&>(i);
    *iu = 12;
    int* ju = &reinterpret_cast<int&>(j);
    *ju = 13;

    if (reinterpret_cast<unsigned long>(iu) % 8 == 0)
        std::cout << "memory pointed by the <iu> variable 
        aligned to 8 byte" << std::endl;
    else
        std::cout << "memory pointed by the <iu> variable NOT 
        aligned to 8 bytes" << std::endl;
    if (reinterpret_cast<unsigned long>(ju) % 8 == 0)
        std::cout << "memory pointed by the <ju> variable aligned to 
        8 bytes" << std::endl;
    else
        std::cout << "memory pointed by the <ju> variable NOT 
        aligned to 8 bytes" << std::endl;

    return (0);
}
```

我们特意创建了两个 typedef，一个用于对齐到`8`字节（`intAligned8`），一个用于对齐到`4`字节（`intAligned4`）。

# 它是如何工作的...

在程序中，我们定义了两个变量`i`和`j`，分别为`intAligned8`和`intAligned4`类型。借助这两个变量（分别对齐到`8`和`4`字节），我们可以通过检查除以`8`的结果是否为`0`来验证它们是否正确对齐：`((unsigned long)iu % 8 == 0)`。这确保了`iu`指针对齐到`8`字节。对`ju`变量也是同样的操作。通过运行前面的程序，我们将得到这个结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/d2ddef14-28cf-4cc5-9991-e6f703144054.png)

预期的结果：`iu`正确对齐到`8`字节，而`ju`没有。

# 还有更多...

正如您可能已经注意到的，我们使用`reinterpret_cast`来允许模数（`%`）运算符，而不是 C 风格的转换`((unsigned long)iu % 8 == 0)`。如果您在 C++中开发，建议使用命名转换（`static_cast`、`reinterpret_cast`、`const_cast`、`dynamic_cast`）有两个基本原因：

+   允许程序员表达转换的意图

+   使转换安全

# 参见

有关此主题的更多信息可以在 W. Richard Stevens 和 Stephen A. Rago 的*UNIX 环境高级编程*中找到。

当一部分内存对齐时，编译器可以进行很好的优化。编译器无法知道这一点，因此无法进行任何优化。最新的 C++20 标准添加了`std::assume_aligned`功能。这告诉编译器指针的值是对齐到一定字节数的内存地址。可能发生的情况是，当我们分配一些对齐的内存时，该内存的指针会传递给其他函数。

`std::assume_aligned`功能告诉编译器假定指针指向的内存已经对齐，因此可以进行优化：

```cpp
void myFunc (int* p)
{
    int* pAligned = std::assume_aligned<64>(p);
    // using pAligned from now on.
}

```

`std::assume_aligned<64>(p);`功能告诉编译器`p`已经对齐到至少`64`字节。如果内存未对齐，将会得到未定义的行为。

# 处理内存映射 I/O

有时，我们需要以非常规或者说不常见的方式操作内存。正如我们所见，内存是使用`new`分配的，并使用`delete`（或者更好的是`make_unique`和`make_shared`）释放的。可能存在需要跳过某些层的情况——也就是说，使用 Linux 系统调用；出于性能考虑；或者因为我们无法使用 C++标准库来映射自定义行为。这就是`mmap` Linux 系统调用的情况（`man 2 mmap`）。`mmap`是一个符合 POSIX 标准的系统调用，允许程序员将文件映射到内存的一部分。除其他功能外，`mmap`还允许分配内存，本教程将教您如何实现。

# 如何做...

本节将展示两个`mmap`用例：第一个是如何将文件映射到内存的一部分；第二个是如何使用`mmap`分配内存。让我们首先编写一个将文件映射到内存的程序。

1.  在 shell 中，让我们创建一个名为`mmap_write.cpp`的新源文件。我们需要打开一个文件进行映射：

```cpp
 int fd = open(FILEPATH, O_RDWR | O_CREAT | O_TRUNC, (mode_t)0600);
 if (fd == -1)
 {
    std::cout << "Error opening file " << FILEPATH << std::endl;
    return 1;
 }
```

1.  其次，我们需要在文件中创建一个空间，以便以后使用（`mmap`不会执行此操作）：

```cpp
int result = lseek(fd, FILESIZE-1, SEEK_SET);
if (result == -1)
{
    close(fd);
    std::cout << "Error calling lseek " << std::endl;
    return 2;
}

result = write(fd, "", 1);
if (result != 1)
{
    close(fd);
    std::cout << "Error writing into the file " << std::endl;
    return 3;
}
```

1.  然后，我们可以将文件（由`fd`文件描述符表示）映射到`map`变量：

```cpp
 int* map = (int*) mmap(0, FILESIZE, PROT_READ | PROT_WRITE, 
     MAP_SHARED, fd, 0);
 if (map == MAP_FAILED)
 {
     close(fd);
     std::cout << "Error mapping the file " << std::endl;
     return 4;
 }
```

1.  最后，我们需要向其中写入一些值：

```cpp
for (int i = 1; i <=NUM_OF_ITEMS_IN_FILE; ++i)
    map[i] = 2 * i;
```

1.  不要忘记关闭使用的资源：

```cpp
if (munmap(map, FILESIZE) == -1)
    std::cout << "Error un-mapping" << std::endl;

close(fd);
```

1.  到目前为止所看到的步骤都与使用`mmap`写入文件有关。为了完整起见，在这一步中，我们将开发一个读取名为`mmap_read.cpp`的文件的程序，它与我们之前看到的非常相似。在这里，我们只会看到重要的部分（Docker 镜像包含读取器和写入器的完整版本）：

```cpp
int* map = (int*) mmap(0, FILESIZE, PROT_READ, MAP_SHARED, fd, 0);
if (map == MAP_FAILED)
{
    close(fd);
    std::cout << "Error mapping the file " << std::endl;
    return 4;
}

for (int i = 1; i <= NUM_OF_ITEMS_IN_FILE; ++i)
    std::cout << "i = " << map[i] << std::endl;
```

现在让我们学习如何使用`mmap`来分配内存。

1.  现在让我们使用`mmap`分配内存：

```cpp
#include <sys/mman.h>
#include <iostream>
#include <cstring>

constexpr auto SIZE = 1024;

int main(int argc, char *argv[])
{
    auto* mapPtr = (char*) mmap(0, SIZE, 
                                PROT_READ | PROT_WRITE, 
                                MAP_PRIVATE | MAP_ANONYMOUS, 
                                -1, 0);
 if (mapPtr == MAP_FAILED)
 {
     std::cout << "Error mapping memory " << std::endl;
     return 1;
 }
 std::cout << "memory allocated available from: " << mapPtr
   << std::endl;

 strcpy (mapPtr, "this is a string!");
 std::cout << "mapPtr val = " << mapPtr << std::endl;

 if (munmap(mapPtr, SIZE) == -1)
     std::cout << "Error un-mapping" << std::endl;

 return 0;
}
```

尽管简单，这两个程序向您展示了如何使用`mmap`分配内存和管理文件。在下一节中，我们将看到它是如何工作的。

# 它是如何工作的...

在第一个程序中，我们学习了`mmap`的最常见用法：将文件映射到内存的一部分。由于在 Linux 中几乎可以将任何资源映射到文件，这意味着我们可以使用`mmap`将几乎任何东西映射到内存中。它确实接受文件描述符。通过首先编译和运行`mmap_write.cpp`程序，我们能够在内存中写入一个整数列表的文件。生成的文件将被命名为`mmapped.txt`。有趣的部分是运行`mmap_read.cpp`读取程序。让我们编译并运行它：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/04bbe152-7fff-49a6-a27f-fc23edc804d7.png)

正如我们所看到的，它正确地从文件中打印出所有的整数。

严格来说，`mmap`并不在堆内存或堆栈上分配内存。它是一个单独的内存区域，仍然在进程的虚拟空间中。`munmap`则相反：它释放映射的内存，并将数据刷新到文件（这种行为可以通过`msync`系统调用来控制）。

第二个程序展示了`mmap`的第二种用法：以一种替代`new`和`malloc`的方式分配内存。我们可以看到在调用`mmap`时有一些不同之处：

+   `MAP_PRIVATE`：修改是私有的。对内存所做的任何修改都不会反映到文件或其他映射中。文件被映射为写时复制。

+   `MAP_ANONYMOUS`：表示将分配大小为`SIZE`的一部分内存，并且不与任何特定文件关联。

+   我们传递了第五个参数`-1`，因为我们想要分配内存（即没有文件描述符）。

我们分配了 1KB 的内存并使用了一个字符串。输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/b4a4ef22-fc72-4027-89d9-435480e7b79c.png)

同样，当我们使用`free`或`delete`释放内存时，我们需要使用`munmap`释放映射的内存。

# 还有更多...

有几个值得一提的优点关于`mmap`：

1.  从内存映射文件读取和写入避免了使用`mmap`与`MAP_SHARED`或`MAP_SHARED_VALIDATE`标志时`read()`和`write()`所需的复制。实际上，当我们向文件写入一块数据时，缓冲区从用户空间移动到内核空间，当读取一块数据时也是如此。

1.  读写内存映射文件实际上是一个简单的内存访问。内存映射文件只在内存中读写；在`munmap`调用时，内存被刷新回文件。这种行为可以通过`msync`系统调用的`MS_SYNC`、`MS_ASYNC`和`MS_INVALIDATE`标志参数来控制。

1.  非常方便的是，当多个进程将同一文件映射到内存中时，数据在所有进程之间共享（`MAP_SHARED`）。

# 另请参阅

查看`man 2 mmap`以获取更多信息。更多信息可以在 Robert Love 的《Linux 系统编程，第二版》中找到。

# 实际操作分配器

C++ **标准模板库**（**STL**）容器是管理资源的一种简单有效的方式。容器的一个巨大优势是它们可以管理（几乎）任何类型的数据。然而，在处理系统编程时，我们可能需要为容器提供一种替代的内存管理方式。分配器正是这样的：它们为容器提供了自定义实现。

# 如何做...

在本教程中，您将学习实现自己的自定义分配器（在本例中基于`mmap`）以提供给标准库容器（`std::vector`）：

1.  让我们首先创建一个空的分配器模板：

```cpp
template<typename T>
class mmap_allocator
{
public:
    using value_type = T;

    template<typename U> struct rebind {
        using alloc = mmap_allocator<U>;
    };

    mmap_allocator(){};
    template <typename U>
    mmap_allocator(const mmap_allocator<U> &alloc) noexcept {};

    T* allocate(std::size_t n){};

    void deallocate(T* p, std::size_t n) {}
};
```

1.  正如您所看到的，有复制构造函数、`allocate`和`deallocate`方法需要实现。让我们逐一实现它们（在这种情况下不需要实现默认构造函数）：

```cpp
    mmap_allocator(const mmap_allocator<U> &alloc) noexcept {
      (void) alloc;};
```

1.  接下来，实现`allocate`方法：

```cpp
    std::cout << "allocating ... n = " << n << std::endl;
    auto* mapPtr = static_cast<T*> (mmap(0, sizeof(T) * n, 
                                    PROT_READ | PROT_WRITE, 
                                    MAP_PRIVATE | MAP_ANONYMOUS, 
                                    -1, 0));
    if (mapPtr != MAP_FAILED)
        return static_cast<T*>(mapPtr);
    throw std::bad_alloc();
```

1.  最后，实现`deallocate`方法：

```cpp
    std::cout << "deallocating ... n = " << n << std::endl;
    (void) n;
    munmap(p, sizeof(T) * n);
```

1.  `main`方法如下：

```cpp
int main ()
{
    std::vector<int, mmap_allocator<int>> mmap_vector = {1, 2,
        3, 4, 5};

    for (auto i : mmap_vector)
        std::cout << i << std::endl;

    return 0;
}
```

正如你所看到的，使用`std::vector`对用户来说是无缝的。唯一的区别是要指定我们想要使用的分配器。这个容器将使用`mmap`和`munmap`来分配和释放内存，而不是基于`new`和`delete`的默认实现。

# 它是如何工作的...

这个程序的核心部分是两个方法：`allocate`，它返回表示分配的内存的指针，和`deallocate`，它接受要释放的内存的指针。

在第一步中，我们勾画了我们将用于分配和释放内存的接口。它是一个模板类，因为我们希望它对任何类型都有效。正如之前讨论的，我们必须实现的两种方法是`allocate`和`deallocate`。

在第二步中，我们开发了复制构造函数，当我们想要构造一个对象并传入相同类型的对象的输入时，它将被调用。我们只是返回一个`typedef`，它将指定新对象使用的分配器。

在第三步中，我们实现了构造函数，它基本上使用`mmap`为类型为`T`的对象`n`分配空间。我们已经在上一个示例中看到了`mmap`的使用，所以你可以再次阅读那个示例。

在第四步中，我们实现了`deallocate`方法，这种情况下它调用`munmap`方法，用于删除指定地址范围的映射。

最后，`main`方法展示了如何在`std::vector`中使用我们的自定义分配器（也可以是任何容器，例如 list）。在变量`mmap_vector`的定义中，我们传递了两个参数：第一个是`int`，用于告诉编译器它将是一个整数向量，第二个是`mmap_allocator<int>`，用于指示使用我们的自定义分配器`mmap_allocator`，而不是默认的分配器。

# 还有更多...

在系统编程中，有一个预先分配的内存**池**的概念，系统预留并且必须在资源的整个生命周期中使用。在这个示例中看到的`map_allocator`类可以很容易地修改为在构造函数中预先分配一部分内存，并且从内存池中获取和释放它，而不影响系统内存。

# 另请参阅

Scott Meyers 的《Effective Modern C++》和 Bjarne Stroustrup 的《The C++ Programming Language》详细介绍了这些主题。有关`mmap`的更多细节，请参阅*处理内存映射 I/O*示例。


# 第五章：使用互斥锁、信号量和条件变量

本章将重点介绍您可以使用的最常见机制，以同步对共享资源的访问。我们将研究的同步机制可以防止临界区域（负责资源的程序段）在两个或多个进程或线程中同时执行。在本章中，您将学习如何使用 POSIX 和 C++标准库同步构建块，如互斥锁、`std::condition_variable`、`std::promise`和`std::future`。

本章将涵盖以下示例：

+   使用 POSIX 互斥锁

+   使用 POSIX 信号量

+   POSIX 信号量的高级用法

+   同步构建块

+   学习使用简单事件进行线程间通信

+   学习使用条件变量进行线程间通信

# 技术要求

为了让您可以立即尝试本章中的所有程序，我们已经设置了一个 Docker 镜像，其中包含本书中将需要的所有工具和库。它基于 Ubuntu 19.04。

为了设置它，按照以下步骤进行：

1.  从[www.docker.com](http://www.docker.com)下载并安装 Docker Engine。

1.  从 Docker Hub 拉取镜像：`docker pull kasperondocker/system_programming_cookbook:latest`。

1.  镜像现在应该可用。输入`docker images`命令查看镜像。

1.  您应该有以下镜像：`kasperondocker/system_programming_cookbook`。

1.  使用`docker run -it --cap-add sys_ptrace kasperondocker/system_programming_cookbook:latest /bin/bash`命令以交互式 shell 运行 Docker 镜像。

1.  正在运行的容器上的 shell 现在可用。使用`root@39a5a8934370/# cd /BOOK/`获取本书中将开发的所有程序。 

`--cap-add sys_ptrace`参数是为了允许 GDB 设置断点。Docker 默认情况下不允许这样做。

# 使用 POSIX 互斥锁

这个示例将教你如何使用 POSIX 互斥锁来同步多个线程对资源的访问。我们将通过开发一个包含一个方法（临界区域）的程序来实现这一点，该方法将执行一个不能并发运行的任务。我们将使用`pthread_mutex_lock`、`pthread_mutex_unlock`和`pthread_mutex_init` POSIX 方法来同步线程对其的访问。

# 如何做...

在这个示例中，我们将创建一个多线程程序，只需将一个整数增加到`200000`。为此，我们将开发负责增加计数器的临界区域，必须对其进行保护。然后，我们将开发主要部分，该部分将创建两个线程并管理它们之间的协调。让我们继续：

1.  打开一个名为`posixMutex.cpp`的新文件，并开发其结构和临界区域方法：

```cpp
#include <pthread.h>
#include <iostream>

struct ThreadInfo
{
    pthread_mutex_t lock;
    int counter;
};

void* increment(void *arg)
{
    ThreadInfo* info = static_cast<ThreadInfo*>(arg);
    pthread_mutex_lock(&info->lock);

    std::cout << "Thread Started ... " << std::endl;
    for (int i = 0; i < 100000; ++i)
        info->counter++;
    std::cout << "Thread Finished ... " << std::endl;

    pthread_mutex_unlock(&info->lock);
    return nullptr;
}
```

1.  现在，在`main`部分，添加所需的用于线程同步的锁的`init`方法：

```cpp
int main()
{
    ThreadInfo thInfo;
    thInfo.counter = 0;
    if (pthread_mutex_init(&thInfo.lock, nullptr) != 0)
    {
        std::cout << "pthread_mutex_init failed!" << std::endl;
        return 1;
    }
```

1.  现在我们有了将执行`increment`（即需要保护的临界区域）的方法和将管理线程之间同步的锁，让我们创建线程：

```cpp
    pthread_t t1;
    if (pthread_create(&t1, nullptr, &increment, &thInfo) != 0)
    {
        std::cout << "pthread_create for t1 failed! " << std::endl;
        return 2;
    }

    pthread_t t2;
    if (pthread_create(&t2, nullptr, &increment, &thInfo) != 0)
    {
        std::cout << "pthread_create for t2 failed! " << std::endl;
        return 3;
    }
```

1.  现在，我们需要等待线程完成任务：

```cpp
    pthread_join(t1, nullptr);
    pthread_join(t2, nullptr);
    std::cout << "Threads elaboration finished. Counter = " 
              << thInfo.counter << std::endl;
    pthread_mutex_destroy(&thInfo.lock);
    return 0;
```

这个程序（在 Docker 镜像的`/BOOK/Chapter05/`文件夹下可用）向我们展示了如何使用 POSIX 互斥锁接口来同步多个线程对共享资源（在本例中是计数器）的使用。我们将在下一节中详细解释这个过程。

# 工作原理...

在第一步中，我们创建了传递参数给线程所需的`struct`：`struct ThreadInfo`。在这个`struct`中，我们放置了保护资源`counter`所需的锁和计数器本身。然后，我们开发了`increment`功能。`increment`逻辑上需要锁定`pthread_mutex_lock(&info->lock);`资源，增加计数器（或者临界区域需要的其他操作），然后解锁`pthread_mutex_unlock(&info->lock);`资源，以便其他线程执行相同的操作。

在第二步中，我们开始开发`main`方法。我们做的第一件事是使用`pthread_mutex_init`初始化锁互斥锁。在这里，我们需要传递指向本地分配资源的指针。

在第三步中，我们创建了两个线程`th1`和`th2`。它们负责同时运行`increment`方法。这两个线程是使用`pthread_create` POSIX API 创建的，通过传递在*步骤 2*中分配的`thInfo`的地址。如果线程成功创建，它将立即开始处理。

在第四步和最后一步中，我们等待`th1`和`th2`都完成将计数器的值打印到标准输出，我们期望的值是`200000`。通过编译`g++ posixMutex.cpp -lpthread`并运行`./a.out`程序，我们得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/5918fefd-5ad2-4e38-80ca-a057d0b440b7.png)

正如我们所看到的，这两个线程从未重叠执行。因此，关键部分的计数器资源得到了正确管理，输出结果符合我们的预期。

# 还有更多...

在这个示例中，为了完整起见，我们使用了`pthread_create`。完全相同的目标可以通过使用 C++标准库中的`std::thread`和`std::async`来实现。

`pthread_mutex_lock()`函数锁定互斥锁。如果互斥锁已经被锁定，调用线程将被阻塞，直到互斥锁变为可用。`pthread_mutex_unlock`函数如果当前线程持有互斥锁，则解锁互斥锁；否则，将导致未定义的行为。

# 另请参阅

欢迎您修改此程序，并使用`std::thread`或`std::async`与 C++标准库中的`pthread_mutex_lock`和`pthread_mutex_unlock`结合使用。请参阅第二章，*重温 C++*，以便在这个主题上进行刷新。

# 使用 POSIX 信号量

POSIX 互斥锁显然不是您可以用来同步访问共享资源的唯一机制。这个示例将向您展示如何使用另一个 POSIX 工具来实现相同的结果。信号量与互斥锁不同，这个示例将教会您它们的基本用法，而下一个示例将向您展示更高级的用法。信号量是线程和/或进程之间的通知机制。作为一个经验法则，尝试使用互斥锁作为同步机制，使用信号量作为通知机制。在这个示例中，我们将开发一个类似于我们在*使用 POSIX 互斥锁*示例中构建的程序，但这次，我们将使用信号量来保护关键部分。

# 如何做...

在这个示例中，我们将创建一个多线程程序，以增加一个整数直到达到`200000`。同样，负责增量的代码部分必须受到保护，我们将使用 POSIX 信号量。`main`方法将创建两个线程，并确保正确销毁资源。让我们开始吧：

1.  让我们打开一个名为`posixSemaphore.cpp`的新文件，并开发结构和关键部分方法：

```cpp
#include <pthread.h>
#include <semaphore.h>
#include <iostream>

struct ThreadInfo
{
    sem_t sem;
    int counter;
};

void* increment(void *arg)
{
    ThreadInfo* info = static_cast<ThreadInfo*>(arg);
    sem_wait(&info->sem);

    std::cout << "Thread Started ... " << std::endl;
    for (int i = 0; i < 100000; ++i)
        info->counter++;
    std::cout << "Thread Finished ... " << std::endl;

    sem_post(&info->sem);
    return nullptr;
}
```

1.  现在，在`main`部分，添加用于线程之间同步所需的锁的`init`方法：

```cpp
int main()
{
    ThreadInfo thInfo;
    thInfo.counter = 0;
    if (sem_init(&thInfo.sem, 0, 1) != 0)
    {
        std::cout << "sem_init failed!" << std::endl;
        return 1;
    }
```

1.  现在`init`部分已经完成，让我们编写将启动两个线程的代码：

```cpp
pthread_t t1;
if (pthread_create(&t1, nullptr, &increment, &thInfo) != 0)
{
    std::cout << "pthread_create for t1 failed! " << std::endl;
    return 2;
}

pthread_t t2;
if (pthread_create(&t2, nullptr, &increment, &thInfo) != 0)
{
    std::cout << "pthread_create for t2 failed! " << std::endl;
    return 3;
}
```

1.  最后，这是结束部分：

```cpp
    pthread_join(t1, nullptr);
    pthread_join(t2, nullptr);

    std::cout << "posixSemaphore:: Threads elaboration
        finished. Counter = " 
              << thInfo.counter << std::endl;
    sem_destroy(&thInfo.sem);
    return 0;
}
```

我们现在使用 POSIX 信号量运行与 POSIX 互斥锁相同的程序。正如您所看到的，程序的设计并没有改变-真正改变的是我们用来保护关键部分的 API。

# 工作原理...

第一部分包含用于与`increment`方法通信的结构以及方法本身的定义。与程序的互斥版本相比，主要区别在于我们现在包括了`#include <semaphore.h>`头文件，以便我们可以使用 POSIX 信号量 API。然后，在结构中，我们使用`sem_t`类型，这是实际将保护临界区的信号量。`increment`方法有两个屏障来保护实际逻辑：`sem_wait(&info->sem);`和`sem_post(&info->sem);`。这两种方法都是原子地分别减少和增加`sem`计数器。`sem_wait(&info->sem);`通过将计数器减少`1`来获取锁。如果计数器的值大于 0，则获取锁，并且线程可以进入临界区。`sem_post(&info->sem);`在退出临界区时只是将计数器增加 1。

在第二步中，我们通过调用`sem_init` API 来初始化信号量。在这里，我们传递了三个参数：

+   要初始化的信号量。

+   `pshared`参数。这表明信号量是在进程的线程之间共享还是在进程之间共享。`0`表示第一个选项。

+   最后一个参数表示信号量的初始值。通过将`1`传递给`sem_init`，我们要求信号量保护一个资源。通过`sem_wait`和`sem_post`，信号量将在内部自动增加和减少该计数器，让每个线程一次进入临界区。

在第三步中，我们创建了使用`increment`方法的两个线程。

在最后一步中，我们等待两个线程完成处理`pthread_join`，并且在本节中最重要的是，我们通过传递到目前为止使用的信号量结构来销毁信号量结构`sem_destroy`。

让我们编译并执行程序：`g++ posixSemaphore.cpp -lpthread`。即使在这种情况下，我们也需要通过将`-lpthread`选项传递给 g++来将程序链接到`libpthread.a`，因为我们使用了`pthreads`。这样做的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/6b0aabdc-b066-4e25-b9fc-5300752d41a4.png)

如预期的那样，输出显示计数器为`200000`。它还显示两个线程没有重叠。

# 还有更多...

我们通过向`sem_init`方法传递值`1`，将`sem_t`用作二进制信号量。信号量可以用作*计数信号量*，这意味着将一个大于 1 的值传递给`init`方法。在这种情况下，这意味着临界区将被*N*个线程同时访问。

有关 GNU/Linux man 页面的更多信息，请在 shell 中键入`man sem_init`。

# 另请参阅

您可以在下一个配方中了解有关*计数信号量*的更多信息，那里我们将学习互斥锁和信号量之间的区别。

您可以修改此程序，并使用`pthread_mutex_lock`和`pthread_mutex_unlock`与 C++标准库中的`std::thread`或`std::async`结合使用。

# POSIX 信号量高级用法

*使用 POSIX 信号量*配方向我们展示了如何使用 POSIX 信号量来保护临界区。在这个配方中，您将学习如何将其用作计数信号量和通知机制。我们将通过开发一个经典的发布-订阅程序来实现这一点，其中有一个发布者线程和一个消费者线程。这里的挑战是我们希望将队列中的最大项目数限制为一个定义的值。

# 如何做...

在这个配方中，我们将编写一个代表计数信号量的典型用例的程序 - 一个生产者-消费者问题，我们希望将队列中的项目数限制为某个数字。让我们开始吧：

1.  让我们打开一个名为`producerConsumer.cpp`的新文件，并编写我们在两个线程中需要的结构：

```cpp
#include <pthread.h>
#include <semaphore.h>
#include <iostream>
#include <vector>

constexpr auto MAX_ITEM_IN_QUEUE = 5;

struct QueueInfo
{
    sem_t mutex;
    sem_t full;
    sem_t empty;
    std::vector<int> queue;
};
```

1.  现在，让我们为`producer`编写代码：

```cpp
void* producer(void *arg)
{
    QueueInfo* info = (QueueInfo*)arg;
    std::cout << "Thread Producer Started ... " << std::endl;
    for (int i = 0; i < 1000; i++)
    {
        sem_wait(&info->full);

        sem_wait(&info->mutex);
        info->queue.push_back(i);
        std::cout << "Thread Producer Started ... size = " 
                  << info->queue.size() << std::endl;
        sem_post(&info->mutex);

        sem_post(&info->empty);
    }
    std::cout << "Thread Producer Finished ... " << std::endl;
    return nullptr;
}
```

1.  我们对`consumer`做同样的操作：

```cpp
void* consumer(void *arg)
{
    QueueInfo* info = (QueueInfo*)arg;
    std::cout << "Thread Consumer Started ... " << std::endl;
    for (int i = 0; i < 1000; i++)
    {
        sem_wait(&info->empty);

        sem_wait(&info->mutex);
        if (!info->queue.empty())
        {
            int b = info->queue.back();
            info->queue.pop_back();
        }
        sem_post(&info->mutex);

        sem_post(&info->full);
    }
    std::cout << "Thread Consumer Finished ... " << std::endl;
    return nullptr;
}
```

1.  现在，我们需要编写`main`方法，以便初始化资源（例如信号量）：

```cpp
int main()
{
    QueueInfo thInfo;
    if (sem_init(&thInfo.mutex, 0, 1) != 0 ||
        sem_init(&thInfo.full, 0, MAX_ITEM_IN_QUEUE) != 0 ||
        sem_init(&thInfo.empty, 0, 0) != 0)
    {
        std::cout << "sem_init failed!" << std::endl;
        return 1;
    }

    pthread_t producerPthread;
    if (pthread_create(&producerPthread, nullptr, &producer, 
        &thInfo) != 0)
    {
        std::cout << "pthread_create for producer failed! "
            << std::endl;
        return 2;
    }
    pthread_t consumerPthread;
    if (pthread_create(&consumerPthread, nullptr, &consumer, 
        &thInfo) != 0)
    {
        std::cout << "pthread_create for consumer failed! "
           << std::endl;
        return 3;
    }
```

1.  最后，我们需要编写释放资源的部分：

```cpp
    pthread_join(producerPthread, nullptr);
    pthread_join(consumerPthread, nullptr);

    sem_destroy(&thInfo.mutex);
    sem_destroy(&thInfo.full);
    sem_destroy(&thInfo.empty);
    return 0;
}
```

这个程序是基于信号量的典型消费者-生产者问题的实现，演示了如何将对资源的使用限制为*N*（在我们的例子中为`MAX_ITEM_IN_QUEUE`）。这个概念可以应用于其他问题，包括如何限制对数据库的连接数等。如果我们不是启动一个生产者，而是启动两个生产者线程，会发生什么？

# 它是如何工作的...

在程序的第一步中，我们定义了`struct`，这是让两个线程进行通信所需的。它包含以下内容：

+   一个`full`信号量（计数信号量）：此信号量设置为`MAX_ITEM_IN_QUEUE`。这限制了队列中项目的数量。

+   一个`empty`信号量（计数信号量）：此信号量在队列为空时通知进程。

+   一个`mutex`信号量（二进制信号量）：这是一个使用信号量实现的互斥锁，用于提供对队列访问的互斥排他。

+   队列：使用`std::vector`实现。

在第二步中，我们实现了`producer`方法。该方法的核心部分是`for`循环的实现。生产者的目标是将项目推送到队列中，同时不超过`MAX_ITEM_IN_QUEUE`个项目，因此生产者尝试通过递减`full`信号量（我们在`sem_init`中初始化为`MAX_ITEM_IN_QUEUE`）进入临界区，然后将项目推送到队列并递增空信号量（这允许消费者继续从队列中读取）。我们为什么需要通知消费者可以读取项目？换句话说，为什么我们需要在生产者中调用`sem_post(&info->empty);`？如果我们不这样做，消费者线程将不断读取项目，并且会将`full`信号量增加到大于`MAX_ITEM_IN_QUEUE`的值，导致队列中的项目超过`MAX_ITEM_IN_QUEUE`。

在第三步中，我们实现了`consumer`方法。这与`producer`相似。消费者所做的是等待通知以从队列中读取项目（使用`sem_wait(&info->empty);`），然后从队列中读取，并递增`full`信号量。这最后一步可以理解为：我刚刚从队列中消费了一个项目。

第四步是我们启动了两个线程并初始化了三个信号量。

第五步是结束部分。

如果我们启动更多的生产者，代码仍然可以工作，因为`full`和`empty`信号量将确保我们之前描述的行为，而队列上的`mutex`确保每次只有一个项目写入/读取。

POSIX 互斥锁和信号量都可以在线程和进程之间使用。要使信号量在进程之间工作，我们只需要在`sem_init`方法的第二个参数中传递一个不为 0 的值。对于互斥锁，我们需要在调用`pthread_mutexattr_setpshared`时传递`PTHREAD_PROCESS_SHARED`标志。通过构建和运行程序，我们将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/df663e70-e7d1-4142-85b6-54910957bcbb.png)

让我们在下一节中了解更多关于这个示例。 

# 还有更多...

值得注意的是，信号量可以初始化为三种可能的值（`sem_init`方法的第三个参数）：

+   对于`1`：在这种情况下，我们将信号量用作互斥锁。

+   对于`N`：在这种情况下，我们将信号量用作*计数信号量*。

+   对于`0`：我们将信号量用作通知机制（参见前面的`empty`信号量示例）。

一般来说，信号量必须被视为线程或进程之间的通知机制。

何时应该使用 POSIX 信号量和 POSIX 互斥锁？尝试使用互斥锁作为同步机制，使用信号量作为通知机制。此外，要考虑到在 Linux 内核中，POSIX 互斥锁通常比 POSIX 信号量更快。

最后一件事：请记住，POSIX 互斥锁和信号量都会使任务进入休眠状态，而自旋锁则不会。实际上，当互斥锁或信号量被锁定时，Linux 调度程序会将任务放入等待队列中。

# 另请参阅

请查看以下列表以获取更多信息：

+   本章中的*使用 POSIX 互斥锁*配方，以了解如何编写 POSIX 互斥锁

+   本章中的*使用 POSIX 信号量*配方，以了解如何编写 POSIX 互斥锁

+   *Linux 内核开发*，作者 Robert Love

# 同步构建模块

从这个配方和接下来的两个配方开始，我们将回到 C++世界。在这个配方中，我们将学习关于 C++同步构建模块。具体来说，我们将学习如何结合**资源获取即初始化**（**RAII**）的概念，使用`std::lock_guard`和`std::unique_lock`，这是一种使代码更健壮和可读的面向对象编程习惯。`std::lock_guard`和`std::unique_lock`将 C++互斥锁的概念封装在两个具有 RAII 概念的类中。`std::lock_guard`是最简单和最小的保护，而`std::unique_lock`在其上添加了一些功能。

# 如何做...

在这个配方中，我们将开发两个程序，以便学习如何使用`std::unique_lock`和`std::lock_guard`。让我们开始吧：

1.  从 shell 中创建一个名为`lock_guard.cpp`的新文件。然后，编写`ThreadInfo`结构和`increment`（线程）方法的代码：

```cpp
#include <iostream>
#include <mutex>
#include <thread>

struct ThreadInfo
{
    std::mutex mutex;
    int counter;
};

void increment(ThreadInfo &info)
{
    std::lock_guard<std::mutex> lock(info.mutex);
    std::cout << "Thread Started ... " << std::endl;

    for (int i = 0; i < 100000; ++i)
        info.counter++;

    std::cout << "Thread Finished ... " << std::endl;
}
```

1.  现在，按照以下方式编写`main`方法的代码：

```cpp
int main()
{
    ThreadInfo thInfo;

    std::thread t1 (increment, std::ref(thInfo));
    std::thread t2 (increment, std::ref(thInfo));

    t1.join();
    t2.join();

    std::cout << "Threads elaboration finished. Counter = " 
              << thInfo.counter << std::endl;
    return 0;
}
```

1.  让我们为`std::unique_lock`编写相同的程序。从 shell 中创建一个名为`unique_lock.cpp`的新文件，并编写`ThreadInfo`结构和`increment`（线程）方法的代码：

```cpp
#include <iostream>
#include <mutex>
#include <thread>
struct ThreadInfo
{
    std::mutex mutex;
    int counter;
};

void increment(ThreadInfo &info)
{
    std::unique_lock<std::mutex> lock(info.mutex);
    std::cout << "Thread Started ... " << std::endl;
    // This is a test so in a real scenario this is not be needed.
    // it is to show that the developer here has the possibility to 
    // unlock the mutex manually.
    // if (info.counter < 0)
    // {
    //    lock.unlock();
    //    return;
    // }
    for (int i = 0; i < 100000; ++i)
        info.counter++;
    std::cout << "unique_lock:: Thread Finished ... " << std::endl;
}
```

1.  关于`main`方法，在这里与我们在*使用 POSIX 互斥锁*配方中看到的没有区别：

```cpp
int main()
{
    ThreadInfo thInfo;

    std::thread t1 (increment, std::ref(thInfo));
    std::thread t2 (increment, std::ref(thInfo));

    t1.join();
    t2.join();

    std::cout << "Unique_lock:: Threads elaboration finished. 
        Counter = " 
              << thInfo.counter << std::endl;
    return 0;
}
```

这两个程序是我们在*使用 POSIX 互斥锁*配方中编写的 C++版本。请注意代码的简洁性。

# 工作原理...

`lock_guard.cpp`程序的*步骤 1*定义了所需的`ThreadInfo`结构和`increment`方法。我们首先看到的是使用`std::mutex`作为关键部分的保护机制。现在，`increment`方法简化了，开发人员的头疼减少了。请注意，我们有`std::lock_guard<std::mutex> lock(info.mutex);`变量定义。正如我们在方法中看到的那样，在最后没有`unlock()`调用-为什么？让我们看看`std::lock_guard`的工作原理：它的构造函数锁定互斥锁。由于`std::lock_guard`是一个类，当对象超出范围时（在这种情况下是在方法的末尾），析构函数被调用。`std::lock_guard`析构函数中调用`std::mutex`对象的解锁。这意味着无论`increment`方法发生什么，构造函数都会被调用，因此不存在死锁的风险，开发人员不必关心`unlock()`。我们在这里描述的是 RAII C++技术，它将`info.mutex`对象的生命周期与`lock`变量的生命周期绑定在一起。

*步骤 2*包含用于管理两个线程的主要代码。在这种情况下，C++具有更清晰和简单的接口。线程是用`std::thread t1 (increment, std::ref(thInfo));`创建的。在这里，`std::thread`接受两个参数：第一个是线程将调用的方法，而第二个是传递给增量方法的`ThreadInfo`。

`unique_lock.cpp`程序是我们迄今为止描述的`lock_guard`的版本。主要区别在于`std::unique_lock`给开发者更多的自由。在这种情况下，我们修改了`increment`方法，以模拟互斥体对`if (info.counter < 0)`情况的解锁需求。使用`std::unique_lock`，我们能够在任何时候手动`unlock()`互斥体并从方法中返回。我们无法在`std::lock_guard`类上做同样的事情。当然，`lock_guard`无论如何都会在作用域结束时解锁，但我们想要强调的是，使用`std::unique_lock`，开发者有自由在任何时候手动解锁互斥体。

通过编译`lock_guard.cpp`：`g++ lock_guard.cpp -lpthread`并运行生成的可执行文件，我们得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/bd008ce4-2587-419a-b206-6f98ee10173c.png)

对于`unique_lock.cpp`也是一样：`g++ unique_lock.cpp -lpthread`，输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/113fd27c-e7a5-4481-9a8f-49d066070a57.png)

正如预期的那样，两个输出完全相同，使用`lock_guard`的代码更清晰，从开发者的角度来看，肯定更安全。

# 还有更多...

正如我们在这个食谱中看到的，`std::lock_guard`和`std::unique_lock`是我们与`std::mutex`一起使用的模板类。`unique_lock`可以与其他互斥体对象一起定义，例如**`std::timed_mutex`**，它允许我们在特定时间内获取锁：

```cpp
#include <chrono>
using std::chrono::milliseconds;

std::timed_mutex timedMutex;
std::unique_lock<std::timed_mutex> lock {timedMutex, std::defer_lock};
lock.try_lock_for(milliseconds{5});
```

`lock`对象将尝试在`5`毫秒内获取锁。当添加`std::defer_lock`时，我们必须小心，它不会在构造时自动锁定互斥体。这只会在`try_lock_for`成功时发生。

# 另请参阅

这里是您可以参考的参考资料列表：

+   *Linux 内核开发*，作者 Robert Love

+   本章的*使用 POSIX 互斥体*食谱

+   本章的*使用 POSIX 信号量*食谱

+   第二章，*重温 C++*，进行 C++的复习

# 使用简单事件学习线程间通信

到目前为止，我们知道如何使用 POSIX 和 C++标准库机制来同步关键部分。有一些用例不需要显式使用锁；相反，我们可以使用更简单的通信机制。`std::promise`和`std::future`可用于允许两个线程进行通信，而无需同步的麻烦。

# 如何做...

在这个食谱中，我们将编写一个程序，将问题分成两部分：线程 1 将运行一个高强度的计算，并将结果发送给线程 2，线程 2 是结果的消费者。我们将使用`std::promise`和`std::future`来实现这一点。让我们开始吧：

1.  打开一个名为`promiseFuture.cpp`的新文件，并将以下代码输入其中：

```cpp
#include <iostream>
#include <future>

struct Item
{
    int age;
    std::string nameCode;
    std::string surnameCode;
};

void asyncProducer(std::promise<Item> &prom);
void asyncConsumer(std::future<Item> &fut);
```

1.  编写`main`方法：

```cpp
int main()
{
    std::promise<Item> prom;
    std::future<Item> fut = prom.get_future();

    std::async(asyncProducer, std::ref(prom));
    std::async(asyncConsumer, std::ref(fut));

    return 0;
}
```

1.  消费者负责通过`std::future`获取结果并使用它：

```cpp
void asyncConsumer(std::future<Item> &fut)
{
    std::cout << "Consumer ... got the result " << std::endl;
    Item item = fut.get();
    std::cout << "Age = " << item.age << " Name = "
        << item.nameCode
              << " Surname = " << item.surnameCode << std::endl;
}
```

1.  生产者执行处理以获取项目并将其发送给等待的消费者：

```cpp
void asyncProducer(std::promise<Item> &prom)
{
    std::cout << "Producer ... computing " << std::endl;

    Item item;
    item.age = 35;
    item.nameCode = "Jack";
    item.surnameCode = "Sparrow";

    prom.set_value(item);
}
```

这个程序展示了`std::promise`和`std::future`的典型用例，其中不需要互斥体或信号量进行一次性通信。

# 它是如何工作的...

在*步骤 1*中，我们定义了`struct Item`以在生产者和消费者之间使用，并声明了两个方法的原型。

在*步骤 2*中，我们使用`std::async`定义了两个任务，通过传递定义的 promise 和 future。

在*步骤 3*中，`asyncConsumer`方法使用`fut.get()`方法等待处理结果，这是一个阻塞调用。

在*步骤 4*中，我们实现了`asyncProducer`方法。这个方法很简单，只是返回一个预定义的答案。在实际情况下，生产者执行高强度的处理。

这个简单的程序向我们展示了如何简单地将问题从信息的生产者（promise）和信息的消费者中解耦，而不必关心线程之间的同步。这种使用`std::promise`和`std::future`的解决方案只适用于一次性通信（也就是说，我们不能在两个线程中发送和获取项目时进行循环）。

# 还有更多...

`std::promise`和`std::future`只是 C++标准库提供的并发工具。除了`std::future`之外，C++标准库还提供了`std::shared_future`。在这个配方中，我们有一个信息生产者和一个信息消费者，但如果有更多的消费者呢？`std::shared_future`允许多个线程等待相同的信息（来自`std::promise`）。

# 另请参阅

Scott Meyers 的书*Effective Modern C++*和 Bjarne Stroustrup 的书*The C++ Programming Language*详细介绍了这些主题。

您也可以通过 C++核心指南中的*CP:并发和并行*（[`github.com/isocpp/CppCoreGuidelines/blob/master/CppCoreGuidelines.md#cp-concurrency-and-parallelism`](https://github.com/isocpp/CppCoreGuidelines/blob/master/CppCoreGuidelines.md#cp-concurrency-and-parallelism)）部分了解更多关于并发的内容。

# 学习使用条件变量进行线程间通信

在这个配方中，您将了解到标准库中提供的另一个 C++工具，它允许多个线程进行通信。我们将使用`std::condition_variable`和`std::mutex`来开发一个生产者-消费者程序。

# 如何做...

这个配方中的程序将使用`std::mutex`来保护队列免受并发访问，并使用`std::condition_variable`来通知消费者队列中已经推送了一个项目。让我们开始吧：

1.  打开一个名为`conditionVariable.cpp`的新文件，并将以下代码输入其中：

```cpp
#include <iostream>
#include <queue>
#include <condition_variable>
#include <thread>

struct Item
{
    int age;
    std::string name;
    std::string surname;
};

std::queue<Item> queue;
std::condition_variable cond;
std::mutex mut;

void producer();
void consumer();
```

1.  现在，让我们编写`main`方法，为消费者和生产者创建线程：

```cpp
int main()
{
    std::thread t1 (producer);
    std::thread t2 (consumer);

    t1.join();
    t2.join();
    return 0;
}
```

1.  让我们定义`consumer`方法：

```cpp
void consumer()
{
    std::cout << "Consumer ... " << std::endl;
    while(true)
    {
        std::unique_lock<std::mutex> lck{mut};
        std::cout << "Consumer ... loop ... START" << std::endl;
        cond.wait(lck);
        // cond.wait(lck, []{ return !queue.empty();});
        auto item = queue.front();
        queue.pop();
        std::cout << "Age = " << item.age << " Name = " 
                  << item.name << " Surname = " << item.surname
                    << std::endl;
        std::cout << "Queue Size = " << queue.size() << std::endl;
        std::cout << "Consumer ... loop ... END" << std::endl;
        lck.unlock();
    }
}
```

1.  最后，让我们定义`producer`方法：

```cpp
void producer()
{
    while(true)
    {
        Item item;
        item.age = 35;
        item.name = "Jack";
        item.surname = "Sparrow";
        std::lock_guard<std::mutex> lock {mut};
        std::cout << "Producer ... loop ... START" << std::endl;
        queue.push(item);
        cond.notify_one();
        std::cout << "Producer ... loop ... END" << std::endl;
    }
}
```

尽管我们开发的程序解决了我们在上一个配方中看到的典型的生产者-消费者问题，但代码更符合惯用法，易于阅读，且更少出错。

# 它是如何工作的...

在第一步中，我们定义了需要从生产者传递给消费者的`struct Item`。这一步中有趣的一点是`std::queue`变量的定义；它使用一个互斥量来同步对队列的访问，并使用`std::condition_variable`来从生产者向消费者通信一个事件。

在第二步中，我们定义了生产者和消费者线程，并调用了`join()`方法。

在第三步中，消费者方法基本上做了四件事：获取锁以从队列中读取项目，等待生产者通过条件变量`cond`发出通知，从队列中弹出一个项目，然后释放锁。有趣的是，条件变量使用`std::unique_lock`而不是`std::lock_guard`，原因很简单：一旦在条件变量上调用`wait()`方法，锁就会（在内部）被释放，以便生产者不被阻塞。当生产者调用`notify_one`方法时，消费者上的`cond`变量会被唤醒并再次锁定互斥量。这使得它可以安全地从队列中弹出一个项目，并在最后再次释放锁`lck.unlock()`。在`cond.wait()`之后（注释掉的代码），还有一种通过传递第二个参数，谓词来调用`wait()`的替代方法，如果第二个参数返回 false，它将继续等待。在我们的情况下，如果队列不为空，消费者将不会等待。

最后一步非常简单：我们创建一个项目，用互斥锁`lock_guard`锁定它，并将其推送到队列中。请注意，通过使用`std::lock_guard`，我们不需要调用 unlock；`lock`变量的析构函数会处理这个问题。在结束当前循环之前，我们需要做的最后一件事是用`notify_one`方法通知消费者。

`g++ conditionVariable.cpp -lpthread`的编译和`./a.out`程序的执行将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/726a088f-c4c0-4c67-8d11-ddca1550ff4b.png)

请注意，由于`condition_variable`是异步的，生产者比消费者快得多，因此需要支付一定的延迟。正如您可能已经注意到的，生产者和消费者会无限运行，因此您必须手动停止进程（*Ctrl* + *C*）。

# 还有更多...

在这个示例中，我们在生产者中使用了`condition_variable`的`notify_one`方法。另一种方法是使用`notify_all`，它会通知所有等待的线程。

另一个需要强调的重要方面是，当生产者希望通知等待的线程之一发生在计算中的事件，以便消费者可以采取行动时，最好使用条件变量。例如，假设生产者通知消费者已经推送了一个特殊项目，或者生产者通知队列管理器队列已满，因此必须生成另一个消费者。

# 另请参阅

+   在第二章的*创建新线程*一节，*重温 C++*，以了解更多信息或刷新自己关于 C++中的线程。

+   《C++编程语言》，作者 Bjarne Stroustrup，详细介绍了这些主题。
