# C++ 系统编程秘籍（三）

> 原文：[`annas-archive.org/md5/8831de64312a5d338410ec40c70fd171`](https://annas-archive.org/md5/8831de64312a5d338410ec40c70fd171)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：管道、先进先出（FIFO）、消息队列和共享内存

进程之间的通信是软件系统的重要部分，选择适当的通信技术并不是一项简单的任务。开发人员在做出选择时应牢记的一个重要区别是进程是否将在同一台机器上运行。本章重点介绍了第一类，您将学习如何基于管道、**先进先出**（**FIFO**）、消息队列和共享内存开发**进程间通信**（**IPC**）解决方案。它将从第一个配方中概述四种 IPC 的特性和类型之间的区别。然后，每种类型的配方将提供实用信息，以便将它们应用到您的日常工作中。本章不包含任何特定于 C++的解决方案，以便让您熟悉 Linux 本地机制。

本章将涵盖以下主题：

+   学习不同类型的 IPC

+   学习如何使用最古老的 IPC 形式——管道

+   学习如何使用 FIFO

+   学习如何使用消息队列

+   学习如何使用共享内存

# 技术要求

为了让您立即尝试这些程序，我们设置了一个 Docker 镜像，其中包含了本书中将需要的所有工具和库。这是基于 Ubuntu 19.04 的。

为了设置它，请按照以下步骤进行：

1.  从[www.docker.com](http://www.docker.com)下载并安装 Docker Engine。

1.  通过运行以下命令从 Docker Hub 拉取镜像：`docker pull kasperondocker/system_programming_cookbook:latest`。

1.  镜像现在应该可用。键入以下命令以查看镜像：`docker images`。

1.  您现在应该至少有这个镜像：`kasperondocker/system_programming_cookbook`。

1.  使用以下命令运行 Docker 镜像，获取交互式 shell 的帮助：`docker run -it --cap-add sys_ptrace kasperondocker/system_programming_cookbook:latest /bin/bash`。

1.  正在运行的容器上的 shell 现在可用。键入 `root@39a5a8934370/# cd /BOOK/` 以获取所有按章节开发的程序。

需要`--cap-add sys_ptrace`参数以允许 Docker 容器中的**GNU 项目调试器**（**GDB**）设置断点，默认情况下 Docker 不允许这样做。

**免责声明**：C++20 标准已经在二月底的布拉格会议上由 WG21 批准（即技术上最终确定）。这意味着本书使用的 GCC 编译器版本 8.3.0 不包括（或者对 C++20 的新功能支持非常有限）。因此，Docker 镜像不包括 C++20 配方代码。GCC 将最新功能的开发保留在分支中（您必须使用适当的标志，例如`-std=c++2a`）；因此，鼓励您自行尝试。因此，请克隆并探索 GCC 合同和模块分支，并尽情玩耍。

# 学习不同类型的 IPC

本配方的目标是在同一台机器上运行的进程中提供不同 IPC 解决方案之间的指导。它将从开发人员的角度（您的角度！）提供主要特征的概述，解释它们之间的不同之处。

# 操作步骤...

以下表格显示了 Linux 机器上始终可用的四种 IPC 类型，其中列代表我们认为开发人员在进行设计选择时应考虑的独特因素：

|  | **进程关系需要？** | **需要同步？** | **通信类型** | **范围** | **涉及内核？** |
| --- | --- | --- | --- | --- | --- |
| **管道** | 是 | 通常不 | 半双工 | 同一台机器 | 是 |
| **FIFO** | 否 | 通常不 | 半双工 | 通常是同一台机器 | 是 |
| **消息队列** | 否 | 通常不 | 半双工 | 同一台机器 | 是 |
| **共享内存** | 否 | 是 | 半双工 | 同一台机器 | 是 |

表的列具有以下描述：

+   **进程之间的关系是否需要？**：这表明实现特定 IPC 是否需要进程之间的关系（例如父子关系）。

+   **需要同步？**：这表明您是否需要考虑进程之间的任何形式的同步（例如互斥锁，信号量等；参见第五章，*使用互斥锁、信号量和条件变量*）或不需要。

+   **通信类型**：两个或多个实体之间的通信可以是半双工（最接近的类比是对讲机，只有一个人可以同时说话）或全双工（例如电话，两个人可以同时交谈）。这可能对设计的解决方案产生深远影响。

+   **范围**：这表明解决方案是否可以应用于更广泛的范围，即在不同机器上的进程之间的 IPC。

+   **涉及的内核？**：这警告您有关通信过程中内核的参与。*它是如何工作...*部分将解释为什么这很重要。

在下一节中，我们将逐行分析表中突出显示的单个特征。

# 它是如何工作...

列表中的第一个 IPC 机制是**管道**。管道需要两个进程之间的关系（例如父子关系）才能工作。为了使管道对两个进程都**可见**（与 FIFO 相反），需要这种关系。这就像一个变量必须对一个方法可见才能使用一样。在管道的示例中，我们将看到这是如何在技术上工作的。

通信类型是半双工：数据从进程*A*流向进程*B*，因此不需要同步。为了在两个进程之间实现全双工通信类型，必须使用两个管道。由于两个进程必须有关系才能使用管道，管道不能用作两台不同机器上的进程之间的通信机制。Linux 内核参与通信，因为数据被复制到内核，然后进一步复制到接收进程。

表中的第二个 IPC 机制是**FIFO**（或**命名管道**）。它是命名管道，因为它需要一个路径名来创建，实际上，它是一种特殊类型的文件。这使得 FIFO 可供任何进程使用，即使它们之间没有关系。他们所需要的只是 FIFO 的路径（同样，一个文件名）所有进程都会使用。在这种情况下也不需要同步。但是，我们必须小心，因为有些情况下需要同步，正如`man page`所指定的。

POSIX.1 规定，少于`pipe_BUF`字节的写操作必须是原子的（即，输出数据被作为连续序列写入管道）。超过`pipe_BUF`字节的写操作可能是非原子的（即，内核可能会将数据与其他进程写入的数据交错）。POSIX.1 要求`pipe_BUF`至少为 512 字节（在 Linux 上，`pipe_BUF`为 4,096 字节）。精确的语义取决于文件描述符是否为非阻塞（`O_NONBLOCK`）；管道是否有多个写入者；以及要写入的字节数*n*。

一般规则是，如果你对进程之间应该发生多少数据交换有任何疑问，总是提供一个同步机制（例如互斥锁、信号量和其他许多机制）。FIFO（同样，管道）提供了半双工通信机制，除非为每个进程提供两个 FIFO（每个进程一个读取器和一个写入器）；在这种情况下，它将成为全双工通信。FIFO 通常用于同一台机器上的进程之间的 IPC，但是，由于它基于文件，如果文件对其他机器可见，FIFO 可能潜在地用于不同机器上的进程之间的 IPC。即使在这种情况下，内核也参与了 IPC，数据从内核空间复制到进程的用户空间。

**消息队列**是存储在内核中的消息的链表。这个定义已经包含了一部分信息；这是内核提供的一种通信机制，同样，这意味着数据来回从/到内核进行复制。消息队列不需要进程之间的任何关系；它们必须共享一个键才能访问相同的队列。如果消息小于或等于`pipe_BUF`，Linux 内核保证队列上的操作的原子性。在这种情况下，需要一种同步机制。消息队列不能在机器范围之外使用。

表中的最后一个 IPC 机制是**共享内存**。这是最快的 IPC 形式。这是有代价的，因为使用共享内存的进程应该使用一种同步形式（例如互斥锁或信号量），正如`man page`所建议的那样（`man shm_overview`）。

每当有一个需要保护的临界区时，进程必须使用我们在第五章中看到的机制来同步访问，*使用互斥锁、信号量和条件变量*。

进程必须在同一台机器上运行才能使用相同的共享内存，并且使用一个键进行标识，消息队列也是如此。由于共享内存位于内核空间，数据会从内核空间复制到读取和删除数据的进程中。

# 还有更多...

这四种 IPC 形式最初是在 Unix System V 上开发的，然后在更现代的 POSIX 标准中重新实现，Linux 支持这些标准。有些情况下，进程不在同一台机器上，在这种情况下，我们需要使用其他机制，比如套接字，我们将在下一章中看到。当然，套接字具有更广泛的适用性，因为它可以在网络上的任何位置将进程进行通信。

这种泛化，可以这么说，是有代价的：它们比本食谱中描述的机制慢。因此，作为开发人员，在做设计选择时必须考虑这一因素。

# 另请参阅

+   第五章*，使用互斥锁、信号量和条件变量*：关于你可以使用的同步机制。

+   第七章*，网络编程*：为了补充本章关于套接字（面向连接和无连接）的概念。

# 学习如何使用最古老的 IPC 形式-管道

在上一篇食谱中，你学会了如何根据一些关键因素选择 IPC。现在是时候动手使用四种通信类型了，这篇食谱专注于管道。在这篇食谱中，你将学习如何使用管道通过使用两个管道使两个进程进行全双工通信。我们将不使用任何形式的同步，因为通常情况下是不需要的。在*它是如何工作的...*部分，我们将看到为什么不需要以及何时不需要。

# 如何做...

在本节中，我们将开发一个程序，该程序将创建两个进程，其唯一目标是相互发送消息。正如我们所见，使用管道，数据只能单向流动。为了进行双向通信，并模拟一般情况，我们将使用两个管道：

1.  我们实例化了要发送的两条消息及其大小，稍后我们将需要它们：

```cpp
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

char* msg1 = "Message sent from Child to Parent";
char* msg2 = "Message sent from Parent to Child";
#define MSGSIZE 34
#define IN      0
#define OUT 1
```

1.  接下来，我们进入初始化部分。我们需要为接收到的消息、`childToParent`和`parentToChild`管道以及我们用于跟踪子进程的**进程标识符**（PID）实例化空间：

```cpp
int main()
{
    char inbufToParent[MSGSIZE];
    char inbufToChild[MSGSIZE];
    int childToParent[2], parentToChild[2], pid, nbytes;

    inbufToParent[0] = 0;
    inbufToChild[0] = 0;
    if (pipe(childToParent) < 0)
        return 1;

    if (pipe(parentToChild) < 0)
        return 1;
```

1.  现在，让我们看看子部分。这部分有两个部分：第一个部分是子进程向父进程发送`msg1`消息；第二个部分是子进程从父进程接收`msg2`消息：

```cpp
if ((pid = fork()) > 0)
{
        printf("Created child with PID = %d\n", pid);
        close(childToParent[IN]);
        write(childToParent[OUT], msg1, strlen(msg1));
        close(childToParent[OUT]);

        close (parentToChild[OUT]);

        read(parentToChild[IN], inbufToChild, strlen(msg2));
        printf("%s\n", inbufToChild);
        close (parentToChild[IN]);
        wait(NULL);
}
```

1.  最后，让我们看看父代码。它有两个部分：一个用于从子进程接收消息，另一个用于回复消息：

```cpp
else
{
        close (childToParent[OUT]);
        read(childToParent[IN], inbufToParent, strlen(msg1));
        printf("%s\n", inbufToParent);
        close (childToParent[IN]);

        close (parentToChild[IN]);
        write(parentToChild[OUT], msg2, strlen(msg2));
        close (parentToChild[OUT]);
}
return 0;
```

我们以编程方式实现了我们在第一章中学到的内容，即*开始系统编程*，用于 shell（参见*学习 Linux 基础知识- shell*配方）。这些步骤在下一节中详细介绍。

# 工作原理...

在第一步中，我们只是定义了`msg1`和`msg2`，供两个进程使用，并定义了`MSGSIZE`，用于读取它们所需的消息长度。

第二步基本上定义了两个管道`childToParent`和`parentToChild`，每个都是两个整数的数组。它们由`pipe`系统调用用于创建两个通信缓冲区，进程可以通过`childToParent[0]`和`childToParent[1]`文件描述符访问。消息被写入`childToParent[1]`，并且按照 FIFO 策略从`childToParent[0]`读取。为了避免缓冲区未初始化的情况，此步骤将`inbuf1`和`inbuf2`的指针设置为`0`。

第三步处理子代码。它向`childToParent[1]`写入，然后从`parentToChild[0]`读取。子进程写入`childToParent[1]`的内容可以由父进程在`childToParent[0]`上读取。`read`和`write`系统调用会导致进程进入内核模式，并临时将输入数据保存在内核空间，直到第二个进程读取它。要遵循的一个规则是未使用的管道端点必须关闭。在我们的情况下，我们写入`childToParent[1]`；因此，我们关闭了管道的`read`端`childToParent[0]`，一旦读取完毕，我们关闭了`write`端，因为它不再使用。

第四步，与第三步非常相似，具有与子代码对称的代码。它在`childToParent[0]`管道上读取，并在`parentToChild[1]`上写入，遵循相同的关闭未使用管道端点的规则。

从分析的代码来看，现在应该清楚为什么管道不能被非祖先进程使用了：`childToParent`和`parentToChild`文件描述符必须在运行时对父进程和子进程可见。

如果我们在 Docker 容器的`/BOOK/Chapter06/`文件夹中用`gcc pipe.c`编译代码并运行它，输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/91aaa497-4f77-4015-8784-f09f8d31dffd.png)

这表明父进程和子进程正确地发送和接收了这两条消息。

# 还有更多...

对于绝大多数用例，管道旨在与少量数据一起使用，但可能存在需要大量数据的情况。我们在本章中遵循的标准 POSIX 规定，`write`少于`pipe_BUF`字节必须是原子的。它进一步规定，`pipe_BUF`必须至少为 512 字节（在 Linux 上为 4KB）；否则，您必须通过使用信号量和互斥锁等机制在用户级别处理同步。

# 另请参阅

+   第一章，*开始系统编程*，从 shell 的角度展示了管道的概念。

+   第五章，*使用互斥锁、信号量和条件变量*具有添加同步所需的工具，以防要发送和接收的数据大于`pipe_BUF`。

# 学习如何使用 FIFO

在上一个配方中看到的管道是临时的，也就是说当没有进程打开它们时，它们就会消失。**FIFO**（也称为**命名管道**）是不同的；它们是特殊的管道，作为文件系统上的特殊文件存在。原则上，任何进程，只要有合适的权限，都可以访问 FIFO。这是 FIFO 的独特特性。使用文件允许我们编程一个更通用的通信机制，以便让进程进行通信，即使它们没有祖先关系；换句话说，我们可以使用 FIFO 让任意两个文件进行通信。在这个配方中，你将学习如何编程 FIFO。

# 如何做...

在本节中，我们将开发一个非常原始的基于 FIFO 的聊天程序，从而产生两个不同的程序，在运行时将允许两个用户进行聊天：

1.  让我们创建一个名为`fifo_chat_user1.c`的文件，并添加我们稍后需要的包含和`MAX_LENGTH`定义，以确定两个用户可以交换的消息的最大长度：

```cpp
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_LENGTH 128
```

1.  接下来，从`main`开始。在这里，我们需要定义`fd`文件描述符以打开文件；我们打算存储文件的路径；我们将用来存储`msgReceived`和`msgToSend`消息的两个字符串；最后，使用`mkfifo`系统调用在定义的路径中创建 FIFO：

```cpp
int main()
{
    char* fifoChat = "/tmp/chat";
    mkfifo(fifoChat, 0600);

    char msgReceived[MAX_LENGTH], msgToSend[MAX_LENGTH];
```

1.  现在我们需要一个无限循环来连续`write`和`read`。我们通过创建两个部分来实现：在`write`部分，我们以写模式打开`fifoChat`文件，使用`fgets`从用户获取消息，并将`msgToSend`写入由`fd`文件描述符表示的文件。在读者部分，我们以读模式打开文件，并使用`read`方法读取文件的内容，打印输出，并关闭`fd`：

```cpp
    while (1)
    {
        int fdUser1 = open(fifoChat, O_WRONLY);
        printf("User1: ");
        fgets(msgToSend, MAX_LENGTH, stdin);
        write(fdUser1, msgToSend, strlen(msgToSend)+1);
        close(fdUser1);

        int fdUser2 = open(fifoChat, O_RDONLY);
        read(fdUser2, msgReceived, sizeof(msgReceived));
        printf("User2: %s\n", msgReceived);
        close(fdUser2);
    }
    return 0;
}
```

1.  第二个程序非常相似。唯一的区别是`while`循环，它是相反的。在这里，我们有`read`部分，然后是`write`部分。你可以将`fifo_chat_user1.c`文件复制到`fifo_chat_user2.c`并进行修改，如下所示：

```cpp
while (1)
{
        int fdUser2 = open(myfifo, O_RDONLY);
        read(fdUser2, msgReceived, sizeof(msgReceived));
        printf("User1: %s\n", msgReceived);
        close(fdUser2);

        int fdUser1 = open(myfifo, O_WRONLY);
        printf("User2: ");
        fgets(msgToSend, MAX_LENGTH, stdin);
        write(fdUser1, msgToSend, strlen(msgToSend)+1);
        close(fdUser1);
}
```

尽管这不是您会在周围找到的最互动的聊天，但它绝对有助于实验 FIFO。在下一节中，我们将分析本节中所见的步骤。

# 它是如何工作的...

让我们首先编译并运行这两个程序。在这种情况下，我们希望为可执行文件提供不同的名称，以便加以区分：

```cpp
gcc fifo_chat_user1.c -o chatUser1

gcc fifo_chat_user2.c -o chatUser2
```

这将创建两个可执行文件：`chatUser1`和`chatUser2`。让我们在两个单独的终端中运行它们，并进行聊天：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/7359f0c3-5c8e-4a74-95fa-74763e739dbf.png)

在*步骤 1*中，我们基本上将`MAX_LENGTH`定义为`128`字节，并添加了我们需要的定义。

在*步骤 2*中，我们创建了`mkfifo`指定路径的 FIFO，该路径指向`/tmp/chat`文件，权限为`6`（用户读写），`0`（用户所属组无读、无写、无执行权限），`0`（其他用户无读、无写、无执行权限）。这些设置可以在调用`mkfifo`后进行检查：

```cpp
root@d73a2ef8d899:/BOOK/chapter6# ls -latr /tmp/chat
prw------- 1 root root 0 Oct 1 23:40 /tmp/chat
```

在*步骤 3*中，我们使用`open`方法打开了 FIFO。值得一提的是，`open`是用于打开常规文件的相同方法，并且在返回的描述符上，我们可以调用`read`和`write`，就像在普通文件上一样。在这一步中，我们创建了一个无限循环，允许用户进行聊天。如您所见，在*步骤 4*中，`read`和`write`部分被交换，以便第二个用户在第一个用户写入时读取，反之亦然。

FIFO 由内核使用 FIFO 策略进行内部管理。每次我们从 FIFO 中`write`或`read`数据时，数据都会从内核传递到内核。您应该记住这一点。消息从`chat1`可执行文件传递，然后在内核空间中，当`chat2`程序调用`read`方法时，再次回到用户空间。

# 还有更多...

到目前为止，应该很清楚 FIFO 是一个特殊的管道。这意味着我们对管道的限制也适用于 FIFO。例如，除非发送的数据量超过了`pipe_BUF`限制，否则不需要同步，标准 POSIX 将其定义为 512 字节，Linux 将其设置为 4 KB。

要强调的另一个方面是，命名管道（FIFO）可以在*N*到*M*通信类型（即多个读取者和多个写入者）中使用。如果满足前述条件，内核将保证操作（`read`和`write`调用）的原子性。

# 另请参阅

+   第三章，*处理进程和线程*

+   第五章，*使用互斥锁、信号量和条件变量*

# 学习如何使用消息队列

POSIX 兼容操作系统（然后是 Linux 内核）直接支持的另一种机制是消息队列。消息队列本质上是存储在内核中的消息的链表，每个队列由一个 ID 标识。在这个配方中，我们将使用消息队列重写聊天程序，突出显示其主要优缺点。

# 如何做...

在本节中，我们将从*学习如何使用 FIFO*的配方中重写聊天程序。这将使您能够亲身体验 FIFO 和消息队列之间的相似之处和不同之处：

1.  创建一个名为`mq_chat_user_1.c`的新文件，并添加以下包含和定义：

```cpp
#include <stdio.h>
#include <string.h>
#include <mqueue.h>

#define MAX_MESSAGES 10
#define MAX_MSG_SIZE 256
```

1.  在`main`方法中，现在让我们定义两个消息队列描述符（`user1Desc`和`user2Desc`），以便稍后存储`mq_open`方法的结果。我们必须定义和初始化`mq_attr`结构以存储我们将创建的消息队列的配置：

```cpp
int main()
{
    mqd_t user1Desc, user2Desc;
    char message[MAX_MSG_SIZE];
    char message2[MAX_MSG_SIZE];

    struct mq_attr attr;
    attr.mq_flags = 0;
    attr.mq_maxmsg = MAX_MESSAGES;
    attr.mq_msgsize = MAX_MSG_SIZE;
    attr.mq_curmsgs = 0;
```

1.  我们可以打开两个`/user1`和`/user2`消息队列：

```cpp
    if ((user1Desc = mq_open ("/user1", O_WRONLY | O_CREAT,
         "0660", &attr)) == -1)
    {
        perror ("User1: mq_open error");
        return (1);
     }
     if ((user2Desc = mq_open ("/user2", O_RDONLY | O_CREAT,
         "0660", &attr)) == -1)
     {
         perror ("User2: mq_open error");
         return (1);
     }
```

1.  程序的核心部分是循环，用于从两个用户那里发送和接收消息。为此，我们必须：

1.  使用`mq_send`方法向用户 2 发送消息，使用`user1Desc`消息队列描述符。

1.  使用`mq_receive`从`user2Desc`消息队列描述符接收用户 2 发送给我们的消息：

```cpp
    while (1)
    {
        printf("USER 1: ");
        fgets(message, MAX_MSG_SIZE, stdin);
        if (mq_send (user1Desc, message, strlen (message)
            + 1, 0) == -1)
        {
            perror ("Not able to send message to User 2");
            continue;
        }
        if (mq_receive (user2Desc, message2, MAX_MSG_SIZE,
             NULL) == -1)
        {
            perror ("tried to receive a message from User 2
                but I've failed!");
            continue;
        }
        printf("USER 2: %s\n", message2);
    }
    return 0;
}
```

1.  我们需要另一个程序来回复给用户 1。这个程序非常相似；唯一的区别是它在`user2Desc`上发送消息（这次以写模式打开），并从`user1Desc`（以读模式打开）读取消息。

现在让我们运行程序。我们需要通过在 shell 中输入以下两个命令来编译`mq_chat_user_1.c`和`mq_chat_user_2.c`程序：

```cpp
gcc mq_chat_user_1.c -o user1 -g -lrt
gcc mq_chat_user_2.c -o user2 -g -lrt
```

我们正在编译和链接程序，并生成`user1`和`user2`可执行文件。我们已经添加了`-lrt`（这是 POSIX.1b 实时扩展库），因为我们需要包含 POSIX 消息队列实现。请记住，使用`-l`时，您正在要求编译器在链接阶段考虑特定的库。在下一节中，我们将看到输出，并分析之前看到的所有步骤。

# 它是如何工作的...

通过运行`./user1`和`./user2`可执行文件，我们将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/5838d556-e1d8-4538-a817-e7b1fcbe6004.png)

让我们看看以下步骤：

1.  **步骤 1**：我们需要`#include <stdio.h>`进行用户输入/输出，`#include <string.h>`通过`strlen`获取字符串的长度，以及`#include <mqueue.h>`以访问消息队列接口。在这一步中，我们已经定义了队列中的最大消息数（`10`）和队列中消息的最大大小（`256`字节）。

1.  **步骤 2**：在程序的`main`方法中，我们定义了两个消息队列描述符（`user1Desc`和`user2Desc`）来保持对消息队列的引用；两个消息数组（`message`和`message2`）用于在两个用户之间存储要发送和接收的消息；最后，我们定义并初始化了`struct mq_attr`结构，用于初始化我们将在下一步中使用的消息队列。

1.  **步骤 3**：在这一步中，我们已经打开了两个消息队列。它们分别是`/user1`和`/user2`，位于`/dev/mqueue`中：

```cpp
root@1f5b72ed6e7f:/BOOK/chapter6# ll /dev/mqueue/user*
------x--- 1 root root 80 Oct 7 13:11 /dev/mqueue/user1*
------x--- 1 root root 80 Oct 7 13:11 /dev/mqueue/user2*
```

`mq_chat_user_1.c`以只写模式打开`/user1`消息队列，并在不存在时创建它。它还以只读模式打开`/user2`，并在不存在时创建它。应该清楚的是，如果当前进程没有消息队列的访问权限（我们以`660`打开），`mq_open`将失败。

1.  **步骤 4**：这一步包含了程序的主要逻辑。它有一个无限循环，从用户 1 发送消息到用户 2，然后从用户 2 接收到用户 1。发送消息所使用的方法是`mq_send`。它需要消息队列描述符、要发送的消息、消息的长度（`+1`，因为我们需要包括终止符）以及消息的优先级（在这种情况下我们没有使用）。`mq_send`（参见`man mq_send`了解更多信息）如果队列中没有足够的空间，会阻塞直到有足够的空间为止。

发送完毕后，我们调用`mq_receive`方法（参见`man mq_receive`了解更多信息）来从用户 2 获取可能的消息。它需要消息队列描述符、将包含消息的数组、我们可以接收的最大大小以及优先级。请记住，如果队列中没有消息，`mq_receive`会阻塞。

有关更多信息，请参阅`man mq_receive`页面。

由于发送和接收是核心概念，让我们通过一个示意图来更深入地分析它们：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/6f49dbd8-e83c-495b-b7b7-fb2546928205.png)

**(1)** 在这种情况下，用户 1 进程调用`mq_send`。Linux 内核会将要发送的消息从用户空间复制到内核空间。在**(3)**中也是同样的情况。

**(2)** 当用户 2 进程在相同的消息队列（`user1Desc`）上调用`mq_receive`时，Linux 内核会将消息从内核空间复制到用户空间，将数据复制到`message2`缓冲区中。在**(4)**中也是同样的情况。

# 还有更多...

可能会有情况需要根据优先级从队列中获取消息，这在这种情况下我们没有使用。您能修改这个示例程序以包括优先级吗？您需要修改什么？

您可能已经注意到，我们在这个示例中使用了`perror`方法。`perror`方法会在标准输出中打印出最后一个错误（`errno`），以描述性格式出现。开发者的优势在于不必显式地获取`errno`值并将其转换为字符串；这一切都会自动完成。

对于消息队列，我们描述管道和 FIFO 的原子性概念也是适用的。如果消息小于`pipe_BUF`，则消息的传递是保证原子性的。否则，开发者必须提供同步机制。

# 另请参阅

在第三章的示例中，*处理进程和线程*（关于线程）和第五章的示例中，*使用互斥锁、信号量和条件变量*（关于同步）。通常情况下，`man`页面提供了丰富的信息源，建议的起点是`man mq_overview`。 

# 学习如何使用共享内存

在我们迄今为止看到的所有 IPC 机制中，内核在进程之间的通信中起着积极的作用，正如我们所学到的那样。信息确实是从 Linux 内核流向进程，反之亦然。在本示例中，我们将学习最快的进程间通信形式，它不需要内核作为进程之间的中介。尽管 System V API 是广泛可用的，但我们将使用最新的、更简单、设计更好的 POSIX API。我们将使用共享内存重写我们的聊天应用程序，并深入研究它。

# 如何做...

在本节中，我们将重点介绍使用 POSIX 共享内存 API 开发简单的聊天应用程序。由于内核不直接参与通信过程，我们需要提供同步机制来保护关键部分（共享内存）免受两个进程的读写：

1.  让我们首先添加我们需要的包含和定义。我们将有两个共享内存空间（`STORAGE_ID1`和`STORAGE_ID2`）来实现进程之间的双向通信：

```cpp
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define STORAGE_ID1 "/SHM_USER1"
#define STORAGE_ID2 "/SHM_USER2"
#define STORAGE_SIZE 32
```

1.  在`main`方法中，我们需要两个数组来存储发送和接收的消息。此外，我们需要以读写模式打开两个共享内存空间，并且如果不存在则创建，并且标志指示文件所有者的读写权限（分别为`S_IRUSR`和`S_IWUSR`）：

```cpp
int main(int argc, char *argv[])
{
    char message1[STORAGE_SIZE];
    char message2[STORAGE_SIZE];

    int fd1 = shm_open(STORAGE_ID1, O_RDWR | O_CREAT, S_IRUSR | 
        S_IWUSR);
    int fd2 = shm_open(STORAGE_ID2, O_RDWR | O_CREAT, S_IRUSR | 
        S_IWUSR);
    if ((fd1 == -1) || (fd2 == -1))
    {
        perror("open");
        return 10;
    }
```

1.  由于共享内存基于`mmap`（我们实质上将文件映射到内存的一部分），我们需要扩展文件描述符 1（`fd1`）指向的文件到我们需要的大小`STORAGE_SIZE`。然后，我们需要将两个文件描述符映射到共享模式（`MAP_SHARED`）的一部分内存，并且当然，要检查错误：

```cpp
    // extend shared memory object as by default it's initialized 
    //  with size 0
    int res1 = ftruncate(fd1, STORAGE_SIZE);
    if (res1 == -1)
    {
        perror("ftruncate");
        return 20;
    }

    // map shared memory to process address space
    void *addr1 = mmap(NULL, STORAGE_SIZE, PROT_WRITE, MAP_SHARED, 
        fd1, 0);
    void *addr2 = mmap(NULL, STORAGE_SIZE, PROT_WRITE, MAP_SHARED, 
        fd2, 0);
    if ((addr1 == MAP_FAILED) || (addr2 == MAP_FAILED))
    {
        perror("mmap");
        return 30;
    }
```

1.  在`main`循环中，与前两个示例一样，我们在两个共享内存实例中进行`read`和`write`操作：

```cpp
    while (1)
    {
        printf("USER 1: ");
        fgets(message1, STORAGE_SIZE, stdin);
        int len = strlen(message1) + 1;
        memcpy(addr1, message1, len);

        printf("USER 2 (enter to get the message):"); getchar();
        memcpy(message2, addr2, STORAGE_SIZE);
        printf("%s\n", message2);
    }

    return 0;
}
```

1.  第二个程序与此程序相似。您可以在`/BOOK/Chapter06`文件夹中找到它们：`shm_chat_user1.c`（我们描述的那个）和`shm_chat_user2.c`。

让我们通过在 shell 上输入以下两个命令来编译和链接两个`shm_chat_user1.c`和`shm_chat_user2.c`程序：

```cpp
gcc shm_chat_user1.c -o user1 -g -lrt
gcc shm_chat_user2.c -o user2 -g -lrt
```

输出将是两个二进制文件：`user1`和`user2`。在这种情况下，我们也添加了`-lrt`，因为我们需要包含 POSIX 共享内存实现（如果没有它，链接阶段将抛出`undefined reference to 'shm_open'`错误）。在下一节中，我们将分析本节中所见的所有步骤。

# 它是如何工作的...

运行`./user1`和`./user2`程序将产生以下交互：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/4d2095df-4516-4651-bdfa-36f932343e57.png)

让我们按照以下步骤进行：

+   **步骤 1**：第一步只包括我们需要的一些头文件：`stdio.h`用于标准输入/输出（例如`perror`，`printf`等）；`mman.h`用于共享内存 API；`mmap`和`fcntl.h`用于`shm_open`标志（例如`O_CREAT`，`O_RDWR`等）；`unistd.h`用于`ftruncate`方法；`string.h`用于`strlen`和`memcpy`方法。

我们定义了`STORAGE_ID1`和`STORAGE_ID2`来标识两个共享内存对象，它们将在`/dev/shm`文件夹中可用：

```cpp
root@1f5b72ed6e7f:/BOOK/chapter6# ll /dev/shm/SHM_USER*
-rw------- 1 root root 32 Oct 7 23:26 /dev/shm/SHM_USER1
-rw------- 1 root root 0 Oct 7 23:26 /dev/shm/SHM_USER2
```

+   **步骤 2**：在这一步中，我们在堆栈上为两条消息（`message1`和`message2`）分配了空间，我们将使用它们在进程之间发送和接收消息。然后，我们创建并打开了两个新的共享内存对象，并检查是否有任何错误。

+   **步骤 3**：一旦两个共享内存对象可用，我们需要扩展两个文件（通过两个文件描述符`fd1`和`fd2`，每个程序一个）并且非常重要的是将`fd1`和`fd2`映射到当前进程的虚拟地址空间。

+   第 4 步：这一步是程序的核心部分。在这里，有一些有趣的事情需要注意。首先，我们可以看到，与 FIFO、管道和消息队列不同，这里没有数据在用户空间和内核空间之间的移动。我们只是在本地缓冲区（在堆栈上分配）和我们映射的内存之间进行内存复制，反之亦然。第二个因素是，由于我们只处理内存复制，性能将优于其他 IPC 机制。

这一步的机制非常简单：我们要求用户输入一条消息并将其存储在`message1`缓冲区中，然后将缓冲区复制到内存映射地址`addr1`。读取部分（我们从第二个用户那里读取消息的地方）也很简单：我们将消息从内存复制到本地缓冲区`message2`。

# 还有更多...

正如您所看到的，这个配方中两个进程之间没有同步。这是为了让您只关注一个方面：与共享内存的通信。读者再次被邀请改进此代码，通过使用线程使其更加交互，并通过使用同步机制使其更加安全。

自 2.6.19 内核以来，Linux 支持使用访问控制列表（ACL）来控制虚拟文件系统中对象的权限。有关更多信息，请参阅`man acl`。

# 另请参阅

关于线程和同步的配方：

+   第三章，处理进程和线程

+   第五章，使用互斥锁、信号量和条件变量


# 第七章：网络编程

在第六章中，*管道，先进先出（FIFO），消息队列和共享内存*，我们学习了不同的 IPC 技术，允许在同一台机器上运行的进程相互通信。在本章中（补充了第六章中的内容），你将学习两个在两台不同计算机上运行的进程如何实现相同的结果。这里介绍的主题是当今互联网运行的基础。你将亲自学习连接导向和无连接导向通信之间的区别，定义端点的特征，最后学习两个使用 TCP/IP 和 UDP/IP 的方法。

本章将涵盖以下主题：

+   学习连接导向通信的基础知识

+   学习无连接导向通信的基础知识

+   学习通信端点是什么

+   学习使用 TCP/IP 与另一台机器上的进程进行通信

+   学习使用 UDP/IP 与另一台机器上的进程进行通信

+   处理字节序

# 技术要求

为了让你立即开始使用这些程序，我们设置了一个 Docker 镜像，其中包含了本书中需要的所有工具和库。它基于 Ubuntu 19.04。

为了设置它，按照以下步骤进行：

1.  从[www.docker.com](https://www.docker.com/)下载并安装 Docker Engine。

1.  使用`docker pull kasperondocker/system_programming_cookbook:latest`从 Docker Hub 拉取镜像。

1.  镜像现在应该可用。输入`docker images`查看镜像。

1.  现在你应该至少有`kasperondocker/system_programming_cookbook`。

1.  使用`docker run -it --cap-add sys_ptrace kasperondocker/system_programming_cookbook:latest /bin/bash`运行 Docker 镜像与交互式 shell。

1.  正在运行的容器上的 shell 现在可用。使用`root@39a5a8934370/# cd /BOOK/`获取按章节列出的所有程序。

`--cap-add sys_ptrace`参数是为了允许 Docker 容器中的**GNU 项目调试器**（**GDB**）设置断点，Docker 默认情况下不允许。要在同一个容器上启动第二个 shell，运行`docker exec -it container-name bash`命令。你可以从`docker ps`命令中获取容器名称。

免责声明：C++20 标准已经在二月底的布拉格会议上得到了 WG21 的批准（也就是在技术上已经最终确定）。这意味着本书使用的 GCC 编译器版本 8.3.0 不包括（或者对 C++20 的新功能支持非常有限）。因此，Docker 镜像不包括 C++20 的代码。GCC 将最新功能的开发保留在分支中（你必须使用适当的标志，例如`-std=c++2a`）；因此，鼓励你自己尝试。所以，克隆并探索 GCC 的合同和模块分支，玩得开心。

# 学习连接导向通信的基础知识

如果你坐在桌前浏览互联网，很可能你正在使用连接导向类型的通信。当你通过 HTTP 或 HTTPS 请求页面时，在实际通信发生之前，你的机器和你试图联系的服务器之间建立了连接。互联网通信的*事实上*标准是**传输控制协议**（**TCP**）。在本章中，你将学习它是什么，为什么它很重要，你还将学习（在命令行上）什么是连接。

# 如何做到这一点...

在本节中，我们将使用命令行来了解当我们与远程机器建立连接时发生了什么。具体来说，我们将学习 TCP/IP 连接的内部方面。让我们按照以下步骤进行：

1.  使用 Docker 镜像运行后，打开一个 shell，输入以下命令，然后按*Enter*键：

```cpp
tcpdump -x tcp port 80
```

1.  打开另一个 shell，输入以下命令，然后按*Enter*：

```cpp
telnet amazon.com 80
```

1.  在第一个 shell 中，您将看到类似以下的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/5a48ff38-c4f1-4ee1-934f-f71da9db0be1.png)

所有这些可能看起来很神秘，但实际上很简单。下一节将详细解释它是如何工作的。

# 它是如何工作的...

基于连接的通信是基于两个实体之间建立连接的假设。在本节中，我们将探讨连接到底是什么。

第一步使用`tcpdump`（`man tcpdump`），这是一个在网络上转储所有流量的命令行工具。在我们的情况下，它将把端口`80`上的所有 TCP 流量写入标准输出，并以十六进制表示形式显示数据。按下*Enter*后，`tcpdump`将切换到监听模式。

第二步使用`telnet`与在`amazon.com`端口`80`上运行的远程服务建立连接。按下*Enter*后，几秒钟后，连接将建立。

在第三步中，我们看到了本地机器通过`telnet`（或`man telnet`，以其全名命名）服务与`amazon.com`（转换为 IP）之间的连接输出。要记住的第一件事是，TCP 中的连接是一个称为**三次握手**的三步过程。客户端发送*SYN*，服务器回复*SYN+ACK*，客户端回复*ACK*。以下图表示了 TCP 头规范：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/a90e0c44-8eec-4e64-b1de-f2cb80cfd1ff.png)

在*SYN* | *SYN+ACK* | *ACK*阶段，客户端和服务器交换了什么数据以成功建立连接？让我们一步一步地来看：

1.  客户端向服务器(`amazon.com`)发送*SYN*：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/40eb9534-c86f-4741-9bba-1c40ba1910ca.png)

让我们从`0xe8f4`和`0x050`开始（以太网头部在此之前，这超出了本章的范围）。从前面的 TCP 头部中可以看到，前两个字节表示源端口（`0xe8f4` = `59636`），接下来的两个字节表示目标端口（`0x0050` = `80`）。在接下来的四个字节中，客户端设置了一个称为序列号的随机数：`0x9bd0 | 0xb114`。在这种情况下，确认号没有设置。为了将此数据包标记为*SYN*，客户端必须将*SYN*位设置为`1`，确实下两个字节的值为`0xa002`，在二进制中为`1010 0000 0000 0010`。我们可以看到倒数第二位设置为 1（将其与前面的屏幕截图中的 TCP 头部进行比较）。

1.  服务器向客户端发送*SYN+ACK*：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/e30cbd29-ea67-47fc-92dd-8dad6943277d.png)

服务器收到来自客户端的*SYN*后，必须以*SYN+ACK*进行响应。忽略前 16 个字节，即以太网头部，我们可以看到以下内容：2 个字节表示源端口（`0x0050` = `80`），第二个 2 个字节表示目标端口（`0xe8f4` = `59636`）。然后我们开始看到一些有趣的东西：服务器在序列号中放入一个随机数，这种情况下是`0x1afe = | 0x5e1e`，在确认号中，是从客户端接收的序列号+1 = `0x9bd0 | 0xb11**5**`。正如我们所学的，服务器必须将标志设置为*SYN+ACK*，根据 TCP 头规范，通过将两个字节设置为`0x7012` = `0111 0000 000**1** 00**1**0`来正确实现。高亮部分分别是*ACK*和*SYN*。然后 TCP 数据包被发送回客户端。

1.  客户端向服务器(`amazon.com`)发送*ACK*：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/626f2c3e-2a7b-4b54-9cb3-a082f5324929.png)

三次握手算法的最后一步是接收客户端发送的 ACK 数据包。消息由两个字节组成，表示源端口（`0xe8f4` = `59636`）和目标端口（`0x050` = `80`）；这次的序列号包含了服务器最初从客户端接收到的值，`0x9bd0 | 0xb115`；确认号包含了服务器接收到的随机值加 1：`0x1afe = | 0x5e1**f**`。最后，通过设置值`0x5010` = `0101 0000 000**1** 0000`来发送*ACK*（被突出显示的部分是*ACK*；与之前的 TCP 头部图片进行比较）。

# 还有更多...

到目前为止，您学到的协议在 RFC 793 中有描述（[`tools.ietf.org/html/rfc793`](https://tools.ietf.org/html/rfc793)）。如果互联网正常工作，那是因为所有网络供应商、设备驱动程序实现和许多程序都完美地实现了这个 RFC（以及其他相关标准）。TCP RFC 定义的远不止我们在这个配方中学到的内容，它严格关注于连接性。它定义了流量控制（通过窗口的概念）和可靠性（通过序列号和其中的*ACK*的概念）。

# 另请参阅

+   *学习使用 TCP/IP 与另一台机器上的进程进行通信*的配方显示了两台机器上的两个进程如何进行通信。连接部分隐藏在系统调用中，我们将看到。

+   第三章，*处理进程和线程*，了解有关进程和线程的内容。

# 学习无连接导向通信的基础知识

在*学习面向连接的通信的基础知识*配方中，我们学到了面向连接的通信与流量控制是可靠的。要使两个进程进行通信，我们必须首先建立连接。这显然会在性能方面产生成本，我们并不总是能够支付——例如，当您观看在线电影时，可用的带宽可能不足以支持 TCP 所带来的所有功能。

在这种情况下，底层通信机制很可能是无连接的。*事实上*的标准无连接通信协议是**用户数据协议**（**UDP**），它与 TCP 处于相同的逻辑级别。在这个配方中，我们将学习命令行上的 UDP 是什么样子。

# 如何做...

在本节中，我们将使用`tcpdump`和`netcast`（`nc`）来分析 UDP 上的无连接链路：

1.  Docker 镜像正在运行时，打开一个 shell，输入以下命令，然后按*Enter*：

```cpp
tcpdump -i lo udp port 45998 -X
```

1.  让我们打开另一个 shell，输入以下命令，然后按*Enter*：

```cpp
echo -n "welcome" | nc -w 1 -u localhost 45998
```

1.  在第一个 shell 中，您将看到类似以下的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/e671d1fb-07cb-4c1a-a09e-5187ebd9b0e9.png)

这似乎也很神秘，但实际上很简单。下一节将详细解释这些步骤。

# 它是如何工作的...

在 UDP 连接中，没有连接的概念。在这种情况下，数据包被发送到接收器。没有流量控制，连接也不可靠。正如您从下图中看到的那样，UDP 头确实非常简单：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/a29b794e-a166-43b2-96de-6adc69398346.png)

*步骤 1*使用`tcpdump`监听端口`45998`，在`loopback`接口上使用`UDP`协议（`-i lo`），通过打印每个数据包的十六进制和 ASCII 数据来查看数据。

*步骤 2*使用`netcast`命令`nc`（`man nc`）发送一个包含字符串`welcome`的 UDP 数据包（`-u`）到本地主机。

*步骤 3* 显示了 UDP 协议的详细信息。我们可以看到源端口（由发送方随机选择）为 `0xdb255` = `56101`，目标端口正确设置为 `0xb3ae` = `459998`。接下来，我们将长度设置为 `0x000f` = `15`，校验和设置为 `0xfe22` = `65058`。长度为 `15` 字节，因为 `7` 字节是接收到的数据长度，`8` 字节是 UDP 标头的长度（源端口 + 目标端口 + 长度 + 校验和）。

没有重传，没有控制流，没有连接。无连接的链接实际上只是发送方发送给接收方的消息，知道可能不会收到它。

# 还有更多...

我们已经讨论了连接，并在 UDP 标头中看到了源端口和目标端口的概念。发送方和接收方的地址存储在其他地方，即在 **IP**（**Internet** **Protocol** 的缩写）层中，逻辑上位于 UDP 层的下方。IP 层具有发送方和接收方地址（IP 地址）的信息，用于将 UDP 数据包从客户端路由到服务器，反之亦然。

UDP 在 RFC 768 中有详细定义，网址为 [`www.ietf.org/rfc/rfc768.txt`](https://www.ietf.org/rfc/rfc768.txt)。

# 另请参阅

+   第一章，*开始系统编程*，回顾命令管道

+   *无连接导向通信基础* 配方，与 TCP 协议进行比较

# 了解通信端点是什么

当两个实体相互通信时，它们本质上是交换信息。为了使这种情况发生，每个实体都必须清楚地知道将信息发送到何处。从程序员的角度来看，参与通信的每个实体都必须有一个清晰的端点。本配方将教你端点是什么，并将在命令行上显示如何识别它们。

# 如何做...

在本节中，我们将使用 `netstat` 命令行实用程序来检查和了解端点是什么：

1.  使用运行 Docker 镜像的 shell，输入以下命令，然后按 *Enter*：

```cpp
b07d3ef41346:/# telnet amazon.com 443
```

1.  打开第二个 shell 并输入以下命令：

```cpp
b07d3ef41346:/# netstat -ntp
```

下一节将解释这两个步骤。

# 工作原理...

在 *步骤 1* 中，我们使用 `telnet` 实用程序连接到本地机器，与 `amazon.com` 远程主机的端口 `443`（HTTP）连接。此命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/62b15a2f-680e-4b7e-af13-a937e1bc9e0a.png)

它正在等待命令，我们不会发送命令，因为我们真正关心的是连接。

在 *步骤 2* 中，我们想要了解我们在本地机器（`localhost`）和远程主机（`amazon.com` 端口 `443`）之间建立的连接的详细信息。为此，我们执行了 *步骤 2* 中的命令。输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/027525f4-3f59-4b27-b3c6-6ef58b76f388.png)

我们可以从此命令行的输出中检索到什么信息？嗯，我们可以检索到一些非常有用的信息。让我们看看我们可以从前面的屏幕截图中学到什么，从左到右阅读代码：

+   `tcp` 代表连接的类型。这是一个面向连接的连接，这意味着本地和远程主机经历了我们在 *学习面向连接的通信基础* 配方中看到的三次握手。

+   `Recv-Q` 是一个队列，其中包含本地主机上当前进程要处理的数据。

+   `Send-Q` 是一个队列，其中包含本地主机上当前进程要发送到远程进程的数据。

+   `Local Address` 是 IP 地址和端口号的组合，实际上代表了我们通信的第一个端点，即本地端点。从编程的角度来看，这样的端点通常被称为 `Socket`，它是一个代表 `IP` 和 `PORT` 的整数。在这种情况下，端点是 `172.17.0.2:40850`。

+   `Foreign Address`，就像`Local Address`一样，是`IP`和`PORT`的组合，代表远程端点，在这种情况下是`176.32.98.166:443`。请注意，`443`是一个众所周知的端口，代表`https`服务。

+   `State`代表两个端点之间连接的状态，在这种情况下是`ESTABLISHED`。

+   `PID/Program Name`，或者在我们的例子中，`65`/`telnet`，代表使用两个端点与远程主机通信的本地进程。

当程序员谈论`socket`时，他们是在谈论通信的每个端点的`IP`和`PORT`。正如我们所见，Linux 使得分析通信的两个端点和它们附加的进程变得容易。

一个重要的方面要强调的是，`PORT`代表一个服务。在我们的例子中，本地进程 telnet 使用 IP `176.32.98.166`连接到端口`80`的远程主机，我们知道那里运行着一个 HTTP 守护程序。但是我们如何知道特定服务的端口号？有一个由**IANA**（即**Internet Assigned Numbers Authority**的缩写）维护的众所周知的端口列表（[`www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml`](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)）。例如，预期 HTTPS 服务在`PORT 443`上运行，`sftp`（即**Secure File Transfer Protocol**的缩写）在`PORT 22`上运行，依此类推。

# 还有更多...

`port`信息是一个 16 位无符号整数值（即`unsigned int`），由 IANA（[`www.iana.org/`](https://www.iana.org/)）维护，并分为以下范围：

+   0-1023：众所周知的端口。众所周知的端口，例如 HTTP、SFTP 和 HTTPS。

+   1024-49151：注册端口。组织可以要求为其目的注册的端口。

+   49152-65535：动态、私有或临时端口。可自由使用。

# 另请参阅

+   *学习基本的无连接导向通信*的方法来学习无连接通信的工作原理

+   *学习基本的连接导向通信*的方法来学习带有连接的通信工作原理

+   *学习使用 TCP/IP 与另一台机器上的进程通信*的方法来学习如何开发连接导向的程序

+   *学习使用 UDP/IP 与另一台机器上的进程通信*的方法来学习如何开发无连接导向的程序

# 学习使用 TCP/IP 与另一台机器上的进程通信

这个方法将向您展示如何使用连接导向的机制连接两个程序。这个方法将使用 TCP/IP，这是互联网上的*事实*标准。到目前为止，我们已经了解到 TCP/IP 是一种可靠的通信形式，它的连接分为三个阶段。现在是时候编写一个程序来学习如何使两个程序相互通信了。尽管使用的语言将是 C++，但通信部分将使用 Linux 系统调用编写，因为它不受 C++标准库支持。

# 如何做...

我们将开发两个程序，一个客户端和一个服务器。服务器将启动并在准备接受传入连接的特定端口上进行`listen`。客户端将启动并连接到由 IP 和端口号标识的服务器：

1.  使用运行的 Docker 镜像，打开一个 shell 并创建一个新文件`clientTCP.cpp`。让我们添加一些稍后需要的头文件和常量：

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <iostream>

constexpr unsigned int SERVER_PORT = 50544;
constexpr unsigned int MAX_BUFFER = 128;
```

1.  让我们现在开始编写`main`方法。我们首先初始化`socket`并获取与服务器相关的信息：

```cpp
int main(int argc, char *argv[])
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
    {
        std::cerr << "socket error" << std::endl;
        return 1;
    }
    struct hostent* server = gethostbyname(argv[1]);
    if (server == nullptr) 
    {
        std::cerr << "gethostbyname, no such host" << std::endl;
        return 2;
    }
```

1.  接下来，我们想要连接到服务器，但我们需要正确的信息，即`serv_addr`：

```cpp
    struct sockaddr_in serv_addr;
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
          (char *)&serv_addr.sin_addr.s_addr, 
          server->h_length);
    serv_addr.sin_port = htons(SERVER_PORT);
    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof
        (serv_addr)) < 0)
    {
        std::cerr << "connect error" << std::endl;
        return 3;
    }
```

1.  服务器将回复连接`ack`，因此我们调用`read`方法：

```cpp
    std::string readBuffer (MAX_BUFFER, 0);
    if (read(sockfd, &readBuffer[0], MAX_BUFFER-1) < 0)
    {
        std::cerr << "read from socket failed" << std::endl;
        return 5;
    }
    std::cout << readBuffer << std::endl;
```

1.  现在我们可以通过调用`write`系统调用将数据发送到服务器：

```cpp
    std::string writeBuffer (MAX_BUFFER, 0);
    std::cout << "What message for the server? : ";
    getline(std::cin, writeBuffer);
    if (write(sockfd, writeBuffer.c_str(), strlen(write
        Buffer.c_str())) < 0) 
    {
        std::cerr << "write to socket" << std::endl;
        return 4;
    }
```

1.  最后，让我们进行清理部分，关闭 socket：

```cpp
    close(sockfd);
    return 0;
}
```

1.  现在让我们开发服务器程序。在第二个 shell 中，我们创建`serverTCP.cpp`文件：

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <arpa/inet.h>

constexpr unsigned int SERVER_PORT = 50544;
constexpr unsigned int MAX_BUFFER = 128;
constexpr unsigned int MSG_REPLY_LENGTH = 18;
```

1.  在第二个 shell 中，首先，我们需要一个将标识我们连接的`socket`描述符：

```cpp
int main(int argc, char *argv[])
{
     int sockfd =  socket(AF_INET, SOCK_STREAM, 0);
     if (sockfd < 0)
     {
          std::cerr << "open socket error" << std::endl;
          return 1;
     }

     int optval = 1;
     setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const
       void *)&optval , sizeof(int));

```

1.  我们必须将`socket`绑定到本地机器上的一个端口和`serv_addr`：

```cpp
     struct sockaddr_in serv_addr, cli_addr;
     bzero((char *) &serv_addr, sizeof(serv_addr));
     serv_addr.sin_family = AF_INET;
     serv_addr.sin_addr.s_addr = INADDR_ANY;
     serv_addr.sin_port = htons(SERVER_PORT);
     if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof
        (serv_addr)) < 0)
     {
          std::cerr << "bind error" << std::endl;
          return 2;
     }
```

1.  接下来，我们必须等待并接受任何传入的连接：

```cpp
     listen(sockfd, 5);
     socklen_t clilen = sizeof(cli_addr);
     int newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, 
         &clilen);
     if (newsockfd < 0)
     {
          std::cerr << "accept error" << std::endl;
          return 3;
     }
```

1.  一旦我们建立了连接，我们就会记录谁连接到标准输出（使用他们的 IP 和端口），并发送一个确认*ACK*：

```cpp
     std::cout << "server: got connection from = "
               << inet_ntoa(cli_addr.sin_addr)
               << " and port = " << ntohs(cli_addr.sin_port)
                  << std::endl;
     write(incomingSock, "You are connected!", MSG_REPLY_LENGTH);
```

1.  我们建立了连接（三次握手，记得吗？），所以现在我们可以读取来自客户端的任何数据：

```cpp
     std::string buffer (MAX_BUFFER, 0);
     if (read(incomingSock, &buffer[0], MAX_BUFFER-1) < 0)
     {
          std::cerr << "read from socket error" << std::endl;
          return 4;
     }
     std::cout << "Got the message:" << buffer << std::endl;
```

1.  最后，我们关闭两个套接字：

```cpp
     close(incomingSock);
     close(sockfd);
     return 0;
}
```

我们已经写了相当多的代码，现在是时候解释所有这些是如何工作的了。

# 它是如何工作的...

客户端和服务器都有一个非常常见的算法，我们必须描述它以便你理解和概括这个概念。客户端的算法如下：

```cpp
socket() -> connect() -> send() -> receive()
```

在这里，`connect()`和`receive()`都是阻塞调用（即，调用程序将等待它们的完成）。`connect`短语特别启动了我们在*学习面向连接的通信基础*中详细描述的三次握手。

服务器的算法如下：

```cpp
socket() -> bind() -> listen() -> accept() -> receive() -> send()
```

在这里，`accept`和`receive`都是阻塞调用。现在让我们详细分析客户端和服务器的代码。

客户端代码分析如下：

1.  第一步只包含了在前面客户端算法部分列出的四个 API 的必要包含文件。请注意，常量采用纯 C++风格，不是使用`#define`宏定义，而是使用`constexpr`。区别在于后者由编译器管理，而前者由预处理器管理。作为一个经验法则，你应该总是尽量依赖编译器。

1.  `socket()`系统调用创建了一个套接字描述符，我们将其命名为`sockfd`，它将用于与服务器发送和接收信息。这两个参数表示套接字将是一个 TCP（`SOCK_STREAM`）/IP（`PF_INET`）套接字类型。一旦我们有了一个有效的套接字描述符，并在调用`connect`方法之前，我们需要知道服务器的详细信息；为此，我们使用`gethostbyname()`方法，它会返回一个指向`struct hostent *`的指针，其中包含有关主机的信息，给定一个类似`localhost`的字符串。

1.  我们现在准备调用`connect()`方法，它将负责三次握手过程。通过查看它的原型（`man connect`），我们可以看到它除了套接字外，还需要一个`const struct sockaddr *address`结构，因此我们需要将相应的信息复制到其中，并将其传递给`connect()`；这就是为什么我们使用`utility`方法`bcopy()`（`bzero()`只是在使用之前重置`sockaddr`结构的辅助方法）。

1.  我们现在已经准备好发送和接收数据。一旦建立了连接，服务器将发送一个确认消息（`You are connected!`）。你是否注意到我们正在使用`read()`方法通过套接字从服务器接收信息？这就是在 Linux 环境中编程的美和简单之处。一个方法可以支持多个接口——事实上，我们能够使用相同的方法来读取文件、通过套接字接收数据，以及做许多其他事情。

1.  我们可以向服务器发送消息。使用的方法是，你可能已经猜到了，是`write()`。我们将`socket`传递给它，它标识了连接，我们希望服务器接收的消息，以及消息的长度，这样 Linux 就知道何时停止从缓冲区中读取。

1.  通常情况下，我们需要关闭、清理和释放任何使用的资源。在这种情况下，我们需要通过使用`close()`方法关闭套接字描述符。

服务器代码分析如下：

1.  我们使用了类似于客户端的代码，但包含了一些头文件和三个定义的常量，我们稍后会使用和解释。

1.  我们必须通过调用`socket()` API 来定义套接字描述符。请注意，客户端和服务器之间没有区别。我们只需要一个能够管理 TCP/IP 类型连接的套接字。

1.  我们必须将在上一步中创建的套接字描述符绑定到本地机器上的网络接口和端口。我们使用`bind()`方法来实现这一点，它将地址（作为第二个参数传递的`const struct sockaddr *address`）分配给作为第一个参数传递的套接字描述符。调用`setsockopt()`方法只是为了避免绑定错误，即`地址已在使用`。

1.  通过调用`listen()` API 开始监听任何传入的连接。`listen()`系统调用非常简单：它获取我们正在监听的`socket`描述符以及保持在挂起连接队列中的最大连接数，我们在这种情况下设置为`5`。然后我们在套接字描述符上调用`accept()`。`accept`方法是一个阻塞调用：这意味着它将阻塞，直到有一个新的传入连接可用，然后它将返回一个表示套接字描述符的整数。`cli_addr`结构被填充了连接的信息，我们用它来记录谁连接了（`IP`和`端口`）。

1.  这一步只是步骤 10 的逻辑延续。一旦服务器接受连接，我们就会在标准输出上记录谁连接了（以他们的`IP`和`端口`表示）。我们通过查询`accept`方法填充的`cli_addr`结构中的信息来实现这一点。

1.  在这一步中，我们通过`read()`系统调用从连接的客户端接收信息。我们传入输入，传入连接的套接字描述符，`buffer`（数据将被保存在其中），以及我们想要读取的数据的最大长度（`MAX_BUFFER-1`）。

1.  然后清理和释放任何可能使用和/或分配的资源。在这种情况下，我们必须关闭使用的两个套接字描述符（服务器的`sockfd`和传入连接的`incomingSock`）。

通过按照这个顺序构建和运行服务器和客户端，我们得到以下输出：

+   服务器构建和输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/6cb2d008-c48a-4572-95b5-c20f08518f1a.png)

+   客户端构建和输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/56ff6da3-b779-438d-95c5-6821223a16ac.png)

这证明了我们在这个教程中学到的东西。

# 还有更多...

我们如何改进服务器应用程序以管理多个并发的传入连接？我们实现的服务器算法是顺序的；在`listen()`之后，我们只是等待`accept()`，直到最后关闭连接。您应该按照以下步骤进行练习：

1.  无限循环运行`accept()`，以便服务器始终处于准备好为客户端提供服务的状态。

1.  为每个接受的连接启动一个新线程。您可以使用`std::thread`或`std::async`来实现这一点。

另一个重要的实践是注意客户端和服务器之间交换的数据。通常，它们同意使用彼此都知道的协议。它可能是一个 Web 服务器，在这种情况下将涉及客户端和服务器之间的 HTML、文件、资源等的交换。如果是监控和控制系统，可能是由特定标准定义的协议。

# 另请参阅

+   第三章，*处理进程和线程*，以便回顾一下进程和线程是如何工作的，以改进这里描述的服务器解决方案

+   *学习面向连接的通信基础*这个教程来学习 TCP 连接的工作原理

+   *学习通信端点是什么*这个教程来学习端点是什么以及它与套接字的关系

# 学习使用 UDP/IP 与另一台机器上的进程进行通信

当一个进程与另一个进程通信时，可靠性并不总是决定通信机制的主要标准。有时，我们需要的是快速通信，而不需要 TCP 协议实现的连接、流量控制和所有其他控制，以使其可靠。这适用于视频流，**互联网语音**（**VoIP**）通话等情况。在这个示例中，我们将学习如何编写 UDP 代码，使两个（或更多）进程相互通信。

# 如何做到的...

我们将开发两个程序，一个客户端和一个服务器。服务器将启动，将套接字绑定到本地地址，然后只接收来自客户端的数据：

1.  使用运行的 Docker 镜像，打开一个 shell，创建一个新文件`serverUDP.cpp`，并添加一些以后会用到的标头和常量：

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <arpa/inet.h>

```

```cpp
constexpr unsigned int SERVER_PORT = 50544;
constexpr unsigned int MAX_BUFFER = 128;
```

1.  在`main`函数中，我们必须实例化`数据报`类型的套接字，并设置选项以在每次重新运行服务器时重用地址：

```cpp
int main(int argc, char *argv[])
{
     int sockfd =  socket(AF_INET, SOCK_DGRAM, 0);
     if (sockfd < 0) 
     {
          std::cerr << "open socket error" << std::endl;
          return 1;
     }
     int optval = 1;
     setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void 
         *)&optval , sizeof(int));
```

1.  我们必须将创建的套接字与本地地址绑定：

```cpp
     struct sockaddr_in serv_addr, cli_addr;
     bzero((char *) &serv_addr, sizeof(serv_addr));
     serv_addr.sin_family = AF_INET;  
     serv_addr.sin_addr.s_addr = INADDR_ANY;  
     serv_addr.sin_port = htons(SERVER_PORT);
     if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof
        (serv_addr)) < 0)
     {
          std::cerr << "bind error" << std::endl;
          return 2;
     }
```

1.  我们现在准备从客户端接收数据包，这次使用`recvfrom` API：

```cpp
     std::string buffer (MAX_BUFFER, 0);
     unsigned int len;
     if (recvfrom(sockfd, &buffer[0], 
                  MAX_BUFFER, 0, 
                  (struct sockaddr*)& cli_addr, &len) < 0)
     {
          std::cerr << "recvfrom failed" << std::endl;
          return 3;
     }
     std::cout << "Got the message:" << buffer << std::endl;
```

1.  我们想用`sendto` API 向客户端发送一个*ACK*消息：

```cpp
     std::string outBuffer ("Message received!");
     if (sendto(sockfd, outBuffer.c_str(), 
                outBuffer.length(), 0, 
                (struct sockaddr*)& cli_addr, len) < 0)
     {
          std::cerr << "sendto failed" << std::endl;
          return 4;
     }
```

1.  最后，我们可以关闭套接字：

```cpp
     close(sockfd);
     return 0; 
}
```

1.  现在让我们创建客户端程序。在另一个 shell 中，创建文件`clientUDP.cpp`：

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <iostream>

constexpr unsigned int SERVER_PORT = 50544;
constexpr unsigned int MAX_BUFFER = 128;
```

1.  我们必须实例化`数据报`类型的套接字：

```cpp
int main(int argc, char *argv[])
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) 
    {
        std::cerr << "socket error" << std::endl;
        return 1;
    }
```

1.  我们需要获取主机信息，以便能够识别要发送数据包的服务器，我们通过调用`gethostbyname` API 来实现：

```cpp
    struct hostent* server = gethostbyname(argv[1]);
    if (server == NULL) 
    {
        std::cerr << "gethostbyname, no such host" << std::endl;
        return 2;
    }

```

1.  将主机信息复制到`sockaddr_in`结构中以识别服务器：

```cpp
    struct sockaddr_in serv_addr, cli_addr;
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
          (char *)&serv_addr.sin_addr.s_addr, 
          server->h_length);
    serv_addr.sin_port = htons(SERVER_PORT);
```

1.  我们可以使用套接字描述符、用户的消息和服务器地址向服务器发送消息：

```cpp
    std::string outBuffer (MAX_BUFFER, 0);
    std::cout << "What message for the server? : ";
    getline(std::cin, outBuffer);
    unsigned int len = sizeof(serv_addr);
    if (sendto(sockfd, outBuffer.c_str(), MAX_BUFFER, 0, 
               (struct sockaddr *) &serv_addr, len) < 0)
    {
        std::cerr << "sendto failed" << std::endl;
        return 3;
    }
```

1.  我们知道服务器会用*ACK*回复，所以让我们用`recvfrom`方法接收它：

```cpp
    std::string inBuffer (MAX_BUFFER, 0);
    unsigned int len_cli_add;
    if (recvfrom(sockfd, &inBuffer[0], MAX_BUFFER, 0, 
                 (struct sockaddr *) &cli_addr, &len_cli_add) < 0)
    {
        std::cerr << "recvfrom failed" << std::endl;
        return 4;
    }
    std::cout << inBuffer << std::endl;
```

1.  最后，像往常一样，我们要负责关闭和释放所有使用的结构：

```cpp
    close(sockfd);
    return 0;
}
```

让我们深入了解代码，看看所有这些是如何工作的。

# 它是如何工作的...

在*学习使用 TCP/IP 与另一台机器上的进程通信*的示例中，我们学习了客户端和服务器的 TCP 算法。UDP 算法更简单，正如你所看到的，连接部分是缺失的：

**UDP 客户端的算法：**

```cpp
socket() ->  sendto() -> recvfrom()
```

**UDP 服务器的算法：**

```cpp
socket() -> bind() ->  recvfrom() -> sendto()
```

现在看看它们现在简单多了——例如，服务器在这种情况下不会`listen`和`accept`传入的连接。

服务器端的代码分析如下：

1.  我们刚刚定义了一些标头和两个常量，表示服务器将公开服务的端口（`SERVER_PORT`）和数据的最大大小（`MAX_BUFFER`）。

1.  在这一步中，我们定义了套接字（`sockfd`），就像我们在 TCP 代码中所做的那样，但这次我们使用了`SOCK_DGRAM`（UDP）类型。为了避免`Address already in use`的绑定问题，我们设置了选项以允许套接字重用地址。

1.  接下来是`bind`调用。它接受`int socket`、`const struct sockaddr *address`和`socklen_t address_len`这些参数，基本上是套接字、要绑定套接字的地址和地址结构的长度。在`address`变量中，我们指定我们正在监听所有可用的本地网络接口（`INADDR_ANY`），并且我们将使用 Internet 协议版本 4（`AF_INET`）。

1.  我们现在可以通过使用`recvfrom`方法开始接收数据。该方法以套接字描述符（`sockfd`）、用于存储数据的缓冲区（`buffer`）、我们可以存储的数据的最大大小、一个标志（在本例中为`0`）来设置接收消息的特定属性、数据报发送者的地址（`cli_addr`）和地址的长度（`len`）作为输入。最后两个参数将被填充返回，这样我们就知道是谁发送了数据报。

1.  现在我们可以向客户端发送一个*ACK*。我们使用`sendto`方法。由于 UDP 是一种无连接协议，我们没有连接的客户端，所以我们需要以某种方式传递这些信息。我们通过将`cli_addr`和长度(`len`)传递给`sendto`方法来实现这一点，这些信息是由`recvfrom`方法返回的。除此之外，我们还需要传递套接字描述符(`sockfd`)、要发送的缓冲区(`outBuffer`)、缓冲区的长度(`outBuffer.length()`)和标志(`0`)。

1.  然后，我们只需要在程序结束时进行清理。我们必须使用`close()`方法关闭套接字描述符。

客户端代码分析如下：

1.  在这一步中，我们找到了与`serverUDP.cpp`源文件中的`SERVER_PORT`和`MAX_BUFFER`相同的头文件。

1.  我们必须通过调用`socket`方法来定义数据报类型的套接字，再次将`AF_INET`和`SOCK_DGRAM`作为输入。

1.  由于我们需要知道将数据报发送给谁，客户端应用程序在命令行上输入服务器的地址(例如`localhost`)，我们将其作为输入传递给`gethostbyname`，它返回主机地址(`server`)。

1.  我们使用`server`变量填充`serv_addr`结构，用于标识我们要发送数据报的服务器的地址(`serv_addr.sin_addr.s_addr`)、端口(`serv_addr.sin_port`)和协议的族(`AF_INET`)。

1.  然后，我们可以使用`sendto`方法通过传递`sockfd`、`outBuffer`、`MAX_BUFFER`、设置为`0`的标志、服务器的地址`serv_addr`及其长度(`len`)来将用户消息发送到服务器。同样，在这个阶段，客户端不知道消息的接收者是谁，因为它没有连接到任何人，这就是为什么必须正确填写`serv_addr`结构，以便它包含有效的地址。

1.  我们知道服务器会发送一个应用程序*ACK*，所以我们必须接收它。我们调用`recvfrom`方法，将套接字描述符(`sockfd`)作为输入，用于存储返回数据的缓冲区(`buffer`)，我们可以获取的数据的最大大小，以及设置为`0`的标志。`recvfrom`返回消息发送者的地址及其长度，我们分别将其存储在`cli_addr`和`len`中。

让我们先运行服务器，然后再运行客户端。

按照以下方式运行服务器：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/bdbbe7da-c8df-4197-912f-246ee3751e02.png)

按照以下方式运行客户端：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/9a159ad9-61df-452c-91f6-b98de7bbfb2a.png)

这展示了 UDP 的工作原理。

# 还有更多...

另一种使用 UDP 协议的方式是以多播或广播格式发送数据报，作为一种无连接通信类型。多播是一种通信技术，用于将相同的数据报发送到多个主机。代码不会改变；我们只需设置多播组的 IP，以便它知道要发送消息的位置。这是一种方便和高效的*一对多*通信方式，可以节省大量带宽。另一种选择是以广播模式发送数据报。我们必须使用子网掩码设置接收者的 IP，形式为`172.30.255.255`。消息将发送到同一子网中的所有主机。

欢迎您通过以下步骤改进服务器代码：

1.  设置一个无限循环，使用`recvfrom()`，以便您始终有一个准备好为客户端提供服务的服务器。

1.  为每个接受的连接启动一个新线程。您可以使用`std::thread`或`std::async`来实现这一点。

# 另请参阅

+   第三章，*处理进程和线程*，以了解如何处理进程和线程以改进此处描述的服务器解决方案

+   *学习基于无连接的通信的基础知识*，以了解 UDP 连接的工作原理

+   *学习通信端点是什么*，以了解端点是什么，以及它与套接字的关系

# 处理字节序

在系统级编写代码可能意味着处理不同处理器的架构。在这样做时，程序员在 C++20 之前必须自行处理的一件事是**字节序**。字节序指的是数字的二进制表示中字节的顺序。幸运的是，最新的 C++标准帮助我们在编译时输入端口信息。本文将教你如何*意识到*字节序，并编写可以在小端和大端架构上运行的代码。

# 如何做...

我们将开发一个程序，该程序将在编译时查询机器，以便我们可以有意识地决定如何处理以不同格式表示的数字：

1.  我们需要包含`<bit>`头文件；然后我们可以使用`std::endian`枚举：

```cpp
#include <iostream>
#include <bit>

int main()
{ 
    if (std::endian::native == std::endian::big)
        // prepare the program to read/write 
        // in big endian ordering.
        std::cout << "big" << std::endl;
    else if (std::endian::native == std::endian::little)
        // prepare the program to read/write 
        // in little endian ordering.
        std::cout << "little" << std::endl; 

 return 0;
}
```

让我们在下一节更仔细地看看这对我们有什么影响。

# 它是如何工作的...

大端和小端是两种主要的数据表示类型。小端排序格式意味着最不重要的字节（也称为 LSB）放在最高地址，而在大端机器上，最重要的字节（也称为 MSB）放在最低地址。对于十六进制值 0x1234 的表示，示例如下：

|  | **地址** | **地址+1（字节）** |
| --- | --- | --- |
| **大端** | `12` | `34` |
| **小端** | `34` | `12` |

步骤 1 中代码片段的主要目标是回答一个问题：我如何知道我正在处理什么样的机器架构？新的 C++20 枚举`std::endian`完美地帮助我们解决了这个问题。怎么做？首先是从*端口意识*方面。将`std::endian`作为 C++标准库的一部分，帮助程序员随时查询底层机器的端口架构。其次：对于共享资源，两个程序必须就格式达成一致（就像 TCP 协议那样，即以*网络顺序*发送信息），以便读者（或者如果在网络上传输数据，则是接收者）可以进行适当的转换。

另一个问题是：我应该怎么做？有两件事你应该做：一件与应用程序的观点有关，另一件与网络有关。在这两种情况下，如果你的应用程序与另一台具有不同字节序格式的机器交换数据（例如交换文件或共享文件系统等），或者将数据发送到具有不同架构的机器上，则必须确保你的数据能够被理解。为此，你可以使用`hton`、`ntoh`宏等；这可以确保数字从主机转换为网络（对于`hton`）和从网络转换为主机（对于`ntoh`）。我们必须提到，大多数互联网协议使用大端格式，这就是为什么如果你从大端机器调用`hton`，该函数将不执行任何转换的原因。

英特尔 x86 系列和 AMD64 系列处理器都使用小端格式，而 IBM z/Architecture、Freescale 和所有 Motorola 68000 遗产处理器都使用大端格式。还有一些处理器（如 PowerPC）可以切换字节序。

# 还有更多...

理论上，除了小端和大端之外，还存在其他数据表示格式。一个例子是 Honeywell 316 微型计算机使用的中端格式。

# 另请参阅

+   *学习使用 TCP/IP 与另一台机器上的进程通信*配方

+   *学习使用 UDP/IP 与另一台机器上的进程通信*配方


# 第八章：处理控制台 I/O 和文件

本章涵盖了基于 C++标准库的控制台、流和文件 I/O 的示例。我们在其他章节中已经读取了程序中的参数，但还有其他几种方法可以做到这一点。我们将深入研究这些主题，并学习每种主题的替代方法、技巧和最佳实践，具体而专门的实践示例。

我们的主要重点再次是尽可能多地使用 C++（及其标准库）来编写系统编程软件，因此代码将具有非常有限的 C 和 POSIX 解决方案。

本章将涵盖以下主题：

+   实现与控制台 I/O 的交互

+   操作 I/O 字符串

+   处理文件

# 技术要求

为了让您从一开始就尝试这些程序，我们设置了一个 Docker 镜像，其中包含了本书中将需要的所有工具和库。它基于 Ubuntu 19.04。

为了设置它，请按照以下步骤操作：

1.  从[www.docker.com](https://www.docker.com/)下载并安装 Docker Engine。

1.  从 Docker 中拉取图像

Hub：`docker pull kasperondocker/system_programming_cookbook:latest`

1.  现在应该可以使用图像。输入以下命令查看图像：`docker images`

1.  现在应该有这个镜像：`kasperondocker/system_programming_cookbook`

1.  使用以下命令运行 Docker 镜像，并使用交互式 shell：`docker run -it **-**-cap-add sys_ptrace kasperondocker/system_programming_cookbook:latest /bin/bash`

1.  正在运行的容器上现在可用 shell。使用`root@39a5a8934370/# cd /BOOK/`获取本书中开发的所有程序，按章节组织。

需要`--cap-add sys_ptrace`参数，以允许 Docker 容器中的 GDB 设置断点，Docker 默认情况下不允许。

# 实现与控制台 I/O 的交互

这个示例专注于控制台 I/O。我们编写的大多数程序都需要与用户进行某种交互：我们需要获取输入，进行一些处理，然后返回输出。例如，想象一下您可以在一个应用程序中收集的用户输入。在这个示例中，我们将编写代码，展示从控制台获取输入和返回输出的不同方法。

# 如何做...

让我们写一些代码：

1.  在运行 Docker 镜像的情况下，让我们创建一个名为`console_01.cpp`的新文件，并将以下代码输入其中：

```cpp
#include <iostream>
#include <string>
int main ()
{
    std::string name;
    std::cout << "name: ";
    std::cin >> name;

    std::string surname;
    std::cout << "surname: ";
    std::cin >> surname;

    int age;
    std::cout << "age: ";
    std::cin >> age;

    std::cout << "Hello " << name << ", " 
              << surname << ": " << age << std::endl;
    return 0;
}
```

1.  现在创建另一个名为`console_02.cpp`的文件，并输入以下代码以查看此方法的限制：

```cpp
#include <iostream>
#include <string>
int main ()
{
    std::string fullNameWithCin;
    std::cout << "full Name got with cin: ";
    std::cin >> fullNameWithCin;

    std::cout << "hello " << fullNameWithCin << std::endl;
    return 0;
}
```

1.  最后，让我们创建一个新文件并命名为`console_03.cpp`；让我们看看`std::getline`和`std::cin`如何克服这个先前的限制：

```cpp
#include <iostream>
#include <string>

int main ()
{
    std::string fullName;
    std::cout << "full Name: ";
    std::getline (std::cin, fullName);
    std::cout << "Hello " << fullName << std::endl;
    return 0;
}
```

尽管这些都是非常简单的示例，但它们展示了使用 C++与控制台标准输入和输出进行交互的方式。

# 工作原理...

在第一步中，`console_01.cpp`程序只使用`std::cin`和`std::cout`来获取用户的`name`和`surname`信息，并将其保存在`std::string`变量中。这些是在需要与标准输入和输出进行简单交互时要使用的第一件事情。通过构建和运行`console_01.cpp`文件，我们将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/2c32601b-b89d-43d4-857c-f37964704b56.png)

该示例的第二步显示了`std::cin`和`std::cout`的限制。用户在命令行中向正在运行的进程提供`name`和`surname`，但奇怪的是，`fullNameWithCin`变量中只存储了名字，完全跳过了姓氏。为什么？原因很简单：`std:cin`总是将空格、制表符或换行符视为从标准输入中捕获的值的分隔符。那么我们如何从标准输入中获取完整的行呢？通过编译和运行`console_02.cpp`，我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/ebac7a09-1cfb-49bb-aa61-fe0dcce7482a.png)

第三步展示了`getline`函数与`std::cin`结合使用，从标准输入获取完整的行。`std::getline`从`std::cin`获取行并将其存储在`fullName`变量中。一般来说，`std::getline`接受任何`std::istream`作为输入，并有可能指定分隔符。标准库中可用的原型如下：

```cpp
istream& getline (istream& is, string& str, char delim);
istream& getline (istream&& is, string& str, char delim);
istream& getline (istream& is, string& str);
istream& getline (istream&& is, string& str);
```

这使得`getline`成为一个非常灵活的方法。通过构建和运行`console_03.cpp`，我们得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/313c17da-22e0-4075-9502-54c86b4e5119.png)

让我们看看下面的例子，我们将一个流传递给方法，用于存储提取的信息片段的变量，以及分隔符：

```cpp
#include <iostream>
#include <string>
#include <sstream>

int main ()
{
    std::istringstream ss("ono, vaticone, 43");

    std::string token;
    while(std::getline(ss, token, ','))
    {
        std::cout << token << '\n';
    }

    return 0;
}
```

前面方法的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/6272f92b-7756-45a2-b4c5-a7fb7102e7b7.png)

这可以为构建自己的标记方法奠定基础。

# 还有更多...

`std::cin`和`std::cout`允许链式请求，这使得代码更易读和简洁：

```cpp
std::cin >> name >> surname;
std::cout << name << ", " << surname << std::endl;
```

`std::cin`期望用户传递他们的名字，然后是他们的姓氏。它们必须用空格、制表符或换行符分隔。

# 另请参阅

+   *学习如何操作 I/O 字符串*配方涵盖了如何操作字符串作为控制台 I/O 的补充。

# 学习如何操作 I/O 字符串

字符串操作是几乎任何软件的一个非常重要的方面。能够简单有效地操作字符串是软件开发的一个关键方面。你将如何读取应用程序的配置文件或解析它？这个配方将教你 C++提供了哪些工具，使这成为一个愉快的任务，使用`std::stringstream`类。

# 如何做...

在这一部分，我们将使用`std::stringstream`开发一个程序来解析流，这些流实际上可以来自任何来源：文件、字符串、输入参数等等。

1.  让我们开发一个程序，打印文件的所有条目。将以下代码输入到一个新的 CPP 文件`console_05.cpp`中：

```cpp
#include <iostream>
#include <string>
#include <fstream>

int main ()
{
    std::ifstream inFile ("file_console_05.txt", std::ifstream::in);
    std::string line;
    while( std::getline(inFile, line) )
        std::cout << line << std::endl;

    return 0;
}
```

1.  当我们需要将字符串解析为变量时，`std::stringstream`非常方便。让我们通过在一个新文件`console_06.cpp`中编写以下代码来看看它的作用：

```cpp
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>

int main ()
{
    std::ifstream inFile ("file_console_05.txt",
        std::ifstream::in);
    std::string line;
    while( std::getline(inFile, line) )
    {
        std::stringstream sline(line);
        std::string name, surname; 
        int age{};
        sline >> name >> surname >> age;
        std::cout << name << "-" << surname << "-"<< age << 
            std::endl;
    }
    return 0;
}
```

1.  而且，为了补充第二步，解析和创建字符串流也很容易。让我们在`console_07.cpp`中做这个：

```cpp
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>

int main ()
{
    std::stringstream sline;
    for (int i = 0; i < 10; ++i)
        sline << "name = name_" << i << ", age = " << i*7 << 
            std::endl;

    std::cout << sline.str();
    return 0;
}
```

前面的三个程序展示了在 C++中解析字符串是多么简单。下一节将逐步解释它们。

# 它是如何工作的...

*步骤 1*表明`std::getline`接受任何流作为输入，不仅仅是标准输入（即`std::cin`）。在这种情况下，它获取来自文件的流。我们包括`iostream`用于`std::cout`，`string`用于使用字符串，以及`fstream`用于读取文件。

然后，我们使用`std::fstream`（文件流）打开`file_console_05.txt`文件。在它的构造函数中，我们传递文件名和标志（在这种情况下，只是信息，它是一个带有`std::ifstream::in`的输入文件）。我们将文件流传递给`std::getline`，它将负责将每行从流中复制并存储在`std::string`变量`line`中，然后将其打印出来。这个程序的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/867418ac-6e1b-4f44-ba9c-7ce3e3c45e78.png)

*步骤 2*展示了相同的程序读取`file_console_05.txt`文件，但是这次我们想解析文件的每一行。我们通过将`line`字符串变量传递给`sline` `std::stringstream`变量来实现这一点。`std::stringstream`提供了方便和易于使用的解析能力。

只需写入一行`sline >> name >> surname >> age`，`std::stringstream`类的`operator>>`将把`name`、`surname`和`age`保存到相应的变量中，并处理类型转换（即对于`age`变量，从`string`到`int`），假设这些变量按照这个顺序出现在文件中。`operator>>`将解析字符串，并通过跳过前导**空格**，对每个标记调用适当的方法（例如`basic_istream& operator>>( short& value );`或`basic_istream& operator>>( long long& value );`等）。该程序的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/137a9b31-5a6d-45c2-9966-1de8b3c8cc6b.png)

*步骤 3*表明，将流解析为变量的简单性也适用于构建流。相同的`std::stringstream`变量`sline`与`<<`运算符一起使用，表示数据流现在流向`string stream`变量，该变量在以下截图中以两行打印到标准输出。该程序的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/0bfd621e-e616-449c-b2a4-5c4a1be90335.png)

`std::stringstream`使得解析字符串和流变得非常容易，无论它们来自何处。

# 还有更多...

如果您正在寻找低延迟，使用`std::stringstream`进行流操作可能不是您的首选。我们始终建议您测量性能并根据数据做出决定。如果是这种情况，您可以尝试不同的解决方案：

+   如果可以的话，只需专注于代码的低延迟部分进行优化。

+   使用标准的 C 或 C++方法编写您的层来解析数据，例如典型的`atoi()`方法。

+   使用任何开源低延迟框架。

# 另请参阅

+   *实现与控制台之间的 I/O*教程介绍了如何处理来自控制台的 I/O。

# 处理文件

这个教程将教会你处理文件所需的基本知识。C++标准库在历史上提供了一个非常好的接口，但 C++ 17 添加了一个名为`std::filesystem`的命名空间，进一步丰富了功能。尽管如此，我们不会利用 C++17 的`std::filesystem`命名空间，因为它已经在第二章中介绍过了，*重温 C++*。想想一个具体的用例，比如创建一个配置文件，或者你需要复制该配置文件的情况。这个教程将教会你如何使用 C++轻松完成这个任务。

# 如何做...

在本节中，我们将编写三个程序，学习如何使用`std::fstream`、`std::ofstream`和`std::ifstream`处理文件：

1.  让我们开发一个程序，通过使用`std::ofstream`打开并写入一个新文件`file_01.cpp`：

```cpp
#include <iostream>
#include <fstream>

int main ()
{
    std::ofstream fout;
    fout.open("file_01.txt");

    for (int i = 0; i < 10; ++i)
        fout << "User " << i << " => name_" << i << " surname_" 
            << i << std::endl;

    fout.close();
}
```

1.  在一个新的源文件`file_02.cpp`中，让我们从文件中读取并打印到标准输出：

```cpp
#include <iostream>
#include <fstream>

int main ()
{
    std::ifstream fiut;
    fiut.open("file_01.txt");

    std::string line;
    while (std::getline(fiut, line))
        std::cout << line << std::endl;

    fiut.close();
}
```

1.  现在我们想要结合打开文件进行读写的灵活性。我们将使用`std::fstream`将`file_01.txt`的内容复制到`file_03.txt`，然后打印其内容。在另一个源文件`file_03.cpp`中，输入以下代码：

```cpp
#include <iostream>
#include <fstream>

int main ()
{
    std::fstream fstr;
    fstr.open("file_03.txt", std::ios::trunc | std::ios::out | std::ios::in);

    std::ifstream fiut;
    fiut.open("file_01.txt");
    std::string line;
    while (std::getline(fiut, line))
        fstr << line << std::endl;
    fiut.close();

    fstr.seekg(0, std::ios::beg);
    while (std::getline(fstr, line))
        std::cout << line << std::endl; 
    fstr.close();
}

```

让我们看看这个教程是如何工作的。

# 它是如何工作的...

在深入研究前面三个程序之前，我们必须澄清标准库在文件流方面的结构。让我们看一下下表：

|  |  | `<fstream>` |
| --- | --- | --- |
| `<ios>` | <--`<ostream>` | <--`ofstream` |
| `<ios>` | <-- `<istream>` | <--`ifstream` |

让我们分解如下：

+   `<ostream>`：负责输出流的流类。

+   `<istream>`：负责输入流的流类。

+   `ofstream`：用于向文件写入的流类。在`fstream`头文件中存在。

+   `ifstream`：用于从文件读取的流类。在`fstream`头文件中存在。

`std::ofstream`和`std::ifstream`都继承自`std::ostream`和`std::istream`的通用流类。正如你可以想象的那样，`std::cin`和`std::cout`也继承自`std::istream`和`std::ostream`（在上表中未显示）。

*步骤 1*：我们首先包含`<iostream>`和`<fstream>`，以便使用`std::cout`和`std::ofstream`来读取`file_01.txt`文件。然后我们调用`open`方法，在这种情况下，打开文件以写入模式，因为我们使用`std::ofstream`类。现在我们准备使用`<<`运算符将字符串写入`fout`文件流中。最后，我们必须关闭流，这将关闭文件。通过编译和运行程序，我们将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/54d34028-d689-4189-be42-0a164bbe3750.png)

*步骤 2*：在这种情况下，我们做相反的操作：从`file_01.txt`文件中读取并打印到标准输出。唯一的区别在于，这种情况下我们使用`std::ifstream`类，它表示一个读取文件流。通过调用`open()`方法，文件以读取模式（`std::ios::in`）打开。通过使用`std::getline`方法，我们可以将文件的所有行打印到标准输出。输出如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/d24e9dd6-2fda-49c5-905b-b1e690ba9987.png)

最后的第三步展示了`std::fstream`类的用法，它通过允许我们以读写模式（`std::ios::out` | `std::ios::in`）打开文件，给了我们更多的自由。我们还希望如果文件存在，则截断文件（`std::ios::trunc`）。有许多其他选项可用于传递给`std::fstream`构造函数。

# 还有更多...

C++17 通过将`std::filesystem`添加到标准库中取得了巨大的改进。这并不是完全新的 - 它受到 Boost 库的巨大启发。公开的主要成员如下：

| **方法名称** | **描述** |
| --- | --- |
| `path` | 表示路径 |
| `filesystem_error` | 文件系统错误的异常 |
| `directory_iterator` | 一个用于遍历目录内容的迭代器（递归版本也可用） |
| `space_info` | 文件系统上空闲和可用空间的信息 |
| `perms` | 标识文件系统权限系统 |

在`std::filesystem`命名空间中，还有一些辅助函数，可以提供有关文件的信息，例如`is_directory()`、`is_fifo()`、`is_regular_file()`、`is_socket()`等等。

# 另请参阅

+   第二章中的*理解文件系统*配方，*重温 C++*，对该主题进行了复习。


# 第九章：处理时间接口

时间在操作系统和应用程序中以多种形式使用。通常，应用程序需要处理以下**时间类别**：

+   **时钟**：实际的时间和日期，就像您手表上读到的那样

+   **时间点**：用于对应用程序的使用情况（例如处理器或资源）进行分析、监视和故障排除所花费的处理时间

+   **持续时间**：单调时间，即某个事件的经过时间

在这一章中，我们将从 C++和 POSIX 的角度处理所有这些方面，以便您在工具箱中有更多可用的工具。本章的示例将教您如何使用时间点来测量事件，以及为什么应该使用稳定的时钟，以及时间超出限制的情况以及如何减轻它。您将学习如何使用 POSIX 和 C++ `std::chrono`来实现这些概念。

本章将涵盖以下示例：

+   学习 C++时间接口

+   使用 C++20 日历和时区

+   学习 Linux 时间

+   处理时间休眠和超出限制

# 技术要求

要立即尝试本章中的程序，我们已经设置了一个包含本书所需的所有工具和库的 Docker 镜像。它基于 Ubuntu 19.04。

为了设置它，按照以下步骤进行：

1.  从[www.docker.com](https://www.docker.com/)下载并安装 Docker Engine。

1.  从 Docker Hub 拉取镜像：`docker pull kasperondocker/system_programming_cookbook:latest`。

1.  镜像现在应该可用。输入以下命令查看镜像：`docker images`。

1.  您应该有以下镜像：`kasperondocker/system_programming_cookbook`。

1.  使用`docker run -it --cap-add sys_ptrace kasperondocker/system_programming_cookbook:latest /bin/bash`命令以交互式 shell 运行 Docker 镜像。

1.  正在运行的容器上的 shell 现在可用。转到`root@39a5a8934370/# cd /BOOK/`以获取本书中将开发的所有程序。

需要`--cap-add sys_ptrace`参数以允许**GDB**（GNU 项目调试器的缩写）设置断点，Docker 默认情况下不允许。

**免责声明**：C++20 标准已经在二月底的布拉格的 WG21 会议上获得批准（即技术上已经最终确定）。这意味着本书使用的 GCC 编译器版本 8.3.0 不包括（或者对 C++20 的新功能支持非常有限）。因此，Docker 镜像不包括 C++20 示例代码。GCC 将最新功能的开发保留在分支中（您必须使用适当的标志，例如`-std=c++2a`）；因此，鼓励您自行尝试。因此，请克隆并探索 GCC 合同和模块分支，并尽情享受。

# 学习 C++时间接口

C++11 标准确实标志着时间方面的重要进展。在此之前（C++标准 98 及之前），系统和应用程序开发人员必须依赖于特定于实现的 API（即 POSIX）或外部库（例如`boost`）来操作**时间**，这意味着代码的可移植性较差。本示例将教您如何使用标准时间操作库编写 C++代码。

# 如何做...

让我们编写一个程序来学习 C++标准中支持的**时钟**、**时间点**和**持续时间**的概念：

1.  创建一个新文件并将其命名为`chrono_01.cpp`。首先我们需要一些包含：

```cpp
#include <iostream>
#include <vector>
#include <chrono>
```

1.  在`main`部分，我们需要一些东西来测量，所以让我们用一些整数填充一个`std::vector`：

```cpp
int main ()
{
    std::cout << "Starting ... " << std::endl;
    std::vector <int> elements;
    auto start = std::chrono::system_clock::now();

    for (auto i = 0; i < 100'000'000; ++i)
        elements.push_back(i);

    auto end = std::chrono::system_clock::now();
```

1.  现在我们有了两个时间点`start`和`end`，让我们计算差异（即持续时间）并打印出来看看花了多长时间：

```cpp
    // default seconds
    std::chrono::duration<double, std::milli> diff = end - start;
    std::cout << "Time Spent for populating a vector with     
        100M of integer ..." 
              << diff.count() << "msec" << std::endl;
```

1.  现在，我们想以另一种格式打印`start`变量；例如，以`ctime`的日历本地时间格式：

```cpp
    auto tpStart = std::chrono::system_clock::to_time_t(start);
    std::cout << "Start: " << std::ctime(&tpStart) << std::endl;

    auto tpEnd = std::chrono::system_clock::to_time_t(end);
    std::cout << "End: " << std::ctime(&tpEnd) << std::endl;
    std::cout << "Ended ... " << std::endl;
}
```

这个程序使用了一些`std::chrono`的特性，比如标准库中可用的`system_clock`、`time_point`和持续时间，并且自 C++标准的第 11 版以来一直在使用。

# 它是如何工作的...

*步骤 1*负责包含我们稍后需要的头文件：`<iostream>`用于标准输出，`<vector>`和`<chrono>`用于时间。

*步骤 2*定义了一个名为`elements`的**int 类型的向量**。由于这个，我们可以在`chrono`命名空间中的`system_clock`类上调用`now()`方法来获取当前时间。虽然我们使用了`auto`，这个方法返回一个表示时间点的`time_point`对象。然后，我们循环了 1 亿次来填充`elements`数组，以突出我们使用了新的 C++14 特性来表示*100,000,000*，这提高了代码的可读性。最后，我们通过调用`now()`方法并将`time_point`对象存储在`end`变量中来获取另一个时间点。

在*步骤 3*中，我们看了执行循环需要多长时间。为了计算这个时间，我们实例化了一个`duration`对象，它是一个需要两个参数的模板类：

+   **表示**：表示滴答数的类型。

+   **周期**：这可以是（等等）`std::nano`、`std:micro`、`std::milli`等。

周期的默认值是`std::seconds`。然后，我们只需在标准输出上写`diff.cout()`，它表示`start`和`end`之间的毫秒数。计算这种差异的另一种方法是使用`duration_cast`；例如，`std::chrono::duration_cast<std::chrono::milliseconds> (end-start).count()`。

在*步骤 4*中，我们以日历`localtime`表示打印`start`和`end`的`time_point`变量（注意，容器时间可能与主机容器不同步）。为了做到这一点，我们需要通过使用`system_clock`类的`to_time_t()`静态变量将它们转换为`time_t`，然后将它们传递给`std::ctime`方法。

现在，让我们构建并运行这个：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/b733171a-695f-4db6-b3ae-eab79b55b5d8.png)

我们将在下一节中更多地了解这个示例。

# 还有更多...

我们开发的程序使用了`system_clock`类。在`chrono`命名空间中有三个时钟类：

+   `system_clock`：这代表了所谓的**挂钟时间**。它可以在任何时刻被调整，比如当通过闰秒引入额外的不精确性或用户刚刚设置它时。在大多数实现中，它的纪元（即其起点）使用 UNIX 时间，这意味着起点从 1970 年 1 月 1 日开始计数。

+   `steady_clock`：这代表了所谓的**单调时钟**。它永远不会被调整。它保持稳定。在大多数实现中，它的起点是机器启动时的时间。为了计算某个事件的经过时间，你应该考虑使用这种类型的时钟。

+   `high_resolution_clock`：这是可用最短滴答的时钟。它可能只是`system_clock`或`steady_clock`的别名，或者是一个完全不同的实现。这是由实现定义的。

另一个需要记住的方面是，C++20 标准包括了`time_of_day`、日历和时区。

# 另请参阅

+   *学习 Linux 时间*的简要比较

+   *Bjarne Stroustrup 的《C++之旅，第二版》*

# 使用 C++20 日历和时区

C++20 标准丰富了`std::chrono`命名空间的日历功能。它们包括你所期望的所有典型功能，以及一种更成语化和直观的玩法。这个示例将教你一些最重要的功能，以及如何与`std::chrono`命名空间的日历部分交互是多么简单。

# 如何做...

让我们看一些代码：

1.  创建一个新文件，确保你包含了`<chrono>`和`<iostream>`。我们有一个日期，我们想知道`bday`会在星期几。

```cpp
#include <chrono>
#include <iostream>

using namespace std;
using namespace std::chrono;

int main ()
{
    auto bday = January/30/2021;
    cout << weekday(bday) << endl;

    auto anotherDay = December/25/2020;
    if (bday == anotherDay)
        cout << "the two date represent the same day" << endl;
    else
        cout << "the two dates represent two different days"    
            << endl;
}
```

1.  有一整套类可以让您玩转日历。让我们来看看其中一些：

```cpp
#include <chrono>
#include <iostream>

using namespace std;
using namespace std::chrono;

int main ()
{
    auto today = year_month_day{ floor<days>(system_clock::now()) };
    auto ymdl = year_month_day_last(today.year(), month*day* last{ month{ 2 } });
    auto last_day_feb = year_month_day{ ymdl };
    std::cout << "last day of Feb is: " << last_day_feb
        << std::endl;

    return 0;
}
```

1.  让我们玩玩时区，并打印不同时区的时间列表：

```cpp
#include <chrono>
#include <iostream>

using namespace std;
using namespace std::chrono;

int main()
{
    auto zone_names = {
       "Asia/Tokyo",
       "Europe/Berlin",
       "Europe/London",
       "America/New_York",
    };

    auto localtime = zoned_time<milliseconds>(date::current_zone(),
                                              system_clock::now());
    for(auto const& name : zone_names)
        cout << name
             << zoned_time<milliseconds>(name, localtime)
             << std::endl;

    return 0;
}
```

1.  一个经常使用的功能是用于找到两个时区之间的差异：

```cpp
#include <chrono>
#include <iostream>

using namespace std;
using namespace std::chrono;

int main()
{
    auto current = system_clock::now();
    auto lon = zoned_time{"Europe/London", current_time};
    auto newYork = zoned_time{"America/New_York", current_time};
    cout <<"Time Difference between London and New York:" 
         << (lon.get_local_time() - newYork.get_local_time())
             << endl;

    return 0;
}
```

让我们深入了解`std::chrono`日历部分，以了解更多关于这个示例的内容。

# 它是如何工作的...

在新的 C++20 标准中有许多日历和时区辅助函数可用。这个示例只是触及了表面，但仍然让我们了解了处理时间是多么容易。`std::chrono`日历和时区功能的参考可以在[`en.cppreference.com/w/cpp/chrono`](https://en.cppreference.com/w/cpp/chrono)上找到。

*步骤 1*使用`weekday`方法来获取一周的日期（使用公历）。在调用`weekday`方法之前，我们需要获取一个特定的日期，使用 C++20，我们可以直接设置`auto bday = January/30/2021`，这代表一个日期。现在，我们可以将其传递给`weekday`方法来获取特定的一周日期，在我们的例子中是星期六。一个有用的属性是我们可以比较日期，就像我们可以在`bday`和`anotherDay`变量之间进行比较。`weekday`以及所有其他`std::chrono`日历方法都处理闰秒。

*步骤 2*展示了`year_month_day`和`year_month_day_last`方法的使用。该库包含了一整套类似于这两个方法的类，例如`month_day`和`month_day_lat`等等。它们显然有不同的范围，但原则仍然相同。在这一步中，我们对二月的最后一天感兴趣。我们使用`year_month_day{ floor<days>(system_clock::now()) }`将当前日期设置在`today`变量中，然后将`today`传递给`year_month_day_last`方法，它将返回类似`2020/02/last`的内容，我们将其存储在`ymdl`变量中。我们可以再次使用`year_month_day`方法来获取二月的最后一天。我们可以跳过一些步骤，直接调用`year_month_day_last`方法。我们进行这一步是为了教育目的。

*步骤 3*进入时区范围。此步骤中的代码片段通过迭代`zone_names`数组打印出一个时区列表。在这里，我们首先通过循环遍历每个由字符串标识的时区来获取`localtime`。然后，我们使用`zoned_time`方法将`localtime`转换为由`name`变量标识的时区。

在*步骤 4*中，我们涵盖了一个有趣且经常发生的问题：找到两个时区之间的时间差。原则没有改变；我们仍然使用`zoned_time`方法来获取两个时区的本地时间，这些时区在这种情况下是`"America/New_York"`和`"Europe/London"`。然后，我们减去两个本地时间以获取差异。

# 还有更多...

`std::chrono`日历提供了各种各样的方法，欢迎您去探索。完整的列表可以在[`en.cppreference.com/w/cpp/chrono`](https://en.cppreference.com/w/cpp/chrono)上找到。

# 另请参阅

+   《C++之旅，第二版》，作者 Bjarne Stroustrup，第 13.7 章，时间

# 学习 Linux 时间。

在 C++11 之前，标准库没有包含任何直接的时间管理支持，因此系统开发人员必须使用*外部*来源。所谓外部，指的是外部库（例如 Boost ([`www.boost.org/`](https://www.boost.org/)））或特定于操作系统的 API。我们认为系统开发人员有必要了解 Linux 中的时间概念。这个示例将帮助您掌握**时钟**、**时间点**和**持续时间**等概念，使用 POSIX 标准。

# 如何做...

在这个示例中，我们将编写一个程序，以便我们可以学习关于 Linux 中**时钟**、**时间点**和**持续时间**的概念。让我们开始吧：

1.  在 shell 中，创建一个名为`linux_time_01.cpp`的新文件，并添加以下包含和函数原型：

```cpp
#include <iostream>
#include <time.h>
#include <vector>

void timespec_diff(struct timespec* start, struct timespec* stop, struct timespec* result);
```

1.  现在，我们想要看到`clock_gettime`调用中`CLOCK_REALTIME`和`CLOCK_MONOTONIC`之间的差异。我们需要定义两个`struct timespec`变量：

```cpp
int main ()
{
    std::cout << "Starting ..." << std::endl;
    struct timespec tsRealTime, tsMonotonicStart;
    clock_gettime(CLOCK_REALTIME, &tsRealTime);
    clock_gettime(CLOCK_MONOTONIC, &tsMonotonicStart);
```

1.  接下来，我们需要打印`tsRealTime`和`tsMonoliticStart`变量的内容以查看它们之间的差异：

```cpp
    std::cout << "Real Time clock (i.e.: wall clock):"
        << std::endl;
    std::cout << " sec :" << tsRealTime.tv_sec << std::endl;
    std::cout << " nanosec :" << tsRealTime.tv_nsec << std::endl;

    std::cout << "Monotonic clock:" << std::endl;
    std::cout << " sec :" << tsMonotonicStart.tv_sec << std::endl;
    std::cout << " nanosec :" << tsMonotonicStart.tv_nsec+
        << std::endl;
```

1.  我们需要一个任务来监视，所以我们将使用`for`循环来填充一个`std::vector`。之后，我们立即在`tsMonotonicEnd`变量中获取一个时间点：

```cpp
    std::vector <int> elements;
    for (int i = 0; i < 100'000'000; ++i)
        elements.push_back(i);

    struct timespec tsMonotonicEnd;
    clock_gettime(CLOCK_MONOTONIC, &tsMonotonicEnd);
```

1.  现在，我们想要打印任务的持续时间。为此，我们调用`timespec_diff`（辅助方法）来计算`tsMonotonicEnd`和`tsMonotonicStart`之间的差异：

```cpp
    struct timespec duration;
    timespec_diff (&tsMonotonicStart, &tsMonotonicEnd, &duration);

    std::cout << "Time elapsed to populate a vector with
        100M elements:" << std::endl;
    std::cout << " sec :" << duration.tv_sec << std::endl;
    std::cout << " nanosec :" << duration.tv_nsec << std::endl;
    std::cout << "Finished ..." << std::endl;
}
```

1.  最后，我们需要实现一个辅助方法来计算`start`和`stop`变量表示的时间之间的时间差（即持续时间）：

```cpp
// helper method
void timespec_diff(struct timespec* start, struct timespec* stop, struct timespec* result)
{
    if ((stop->tv_nsec - start->tv_nsec) < 0) 
    {
        result->tv_sec = stop->tv_sec - start->tv_sec - 1;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec
          + 100'000'0000;
    } 
    else 
    {
        result->tv_sec = stop->tv_sec - start->tv_sec;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec;
    }
    return;
}
```

上述程序展示了如何收集时间点以计算事件的持续时间。现在，让我们深入了解该程序的细节。

# 工作原理...

首先，让我们编译并执行程序：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/f4a8718b-5a8b-46ac-a1d0-cd3365395fdf.png)

我们可以立即注意到，实时时钟（秒）远远大于单调时钟（秒）。通过一些数学运算，您会注意到第一个大约是 49 年，而后者大约是 12 小时。为什么会这样？第二个观察是我们的代码花费了`1 秒`和`644348500`纳秒来填充 1 亿个项目的向量。让我们收集一些见解来解释这一点。

*步骤 1*只是添加了一些包含和我们编写的原型，用于计算时间差。

*步骤 2*定义了两个变量，`struct timespec tsRealTime`和`struct timespec tsMonotonicStart`，它们将用于存储两个时间点。然后，我们两次调用`clock_gettime()`方法，一次传递`CLOCK_REALTIME`和`tsRealTime`变量。我们再次传递`CLOCK_MONOTONIC`和`tsMonotonicStart`变量。`CLOCK_REALTIME`和`CLOCK_MONOTONIC`都是`clockid_t`类型。当使用`CLOCK_REALTIME`调用`clock_gettime()`时，我们得到的时间将是`挂钟`时间（或实时时间）。

这个时间点有与我们在*学习 C++时间接口*中看到的`std::chrono::SYSTEM_CLOCK`相同的问题。它可以被调整（例如，如果系统时钟与 NTP 同步），因此不适合计算事件的经过时间（或持续时间）。当使用`CLOCK_MONOTONIC`参数调用`clock_gettime()`时，时间不会调整，大多数实现会从系统启动开始计时（即从机器启动开始计算时钟滴答）。这非常适合事件持续时间的计算。

*步骤 3*只是打印时间点的结果，即`tsRealTime`和`tsMonotonicStart`。我们可以看到第一个包含自 1970 年 1 月 1 日以来的秒数（大约 49 年），而后者包含自我的机器启动以来的秒数（大约 12 小时）。

*步骤 4*只是在`std::vector`中添加了 1 亿个项目，然后在`tsMonotonicEnd`中获取了另一个时间点，这将用于计算此事件的持续时间。

*步骤 5*计算了`tsMonotonicStart`和`tsMonotonicEnd`之间的差异，并通过调用`timespec_diff()`辅助方法将结果存储在`duration`变量中。

*步骤 6*实现了`timespec_diff()`方法，逻辑上计算(`tsMonotonicEnd - tsMonotonicStart`)。

# 还有更多...

对于`clock_gettime()`方法，我们使用 POSIX 作为对应的设置方法：`clock_settime()`。对于`gettimeofday()`也是如此：`settimeofday()`。

值得强调的是，`gettimeofday()`是`time()`的扩展，返回一个`struct timeval`（即秒和微秒）。这种方法的问题在于它可以被调整。这是什么意思？让我们想象一下，您使用`usegettimeofday()`在事件之前获取一个时间点来测量，然后在事件之后获取另一个时间点来测量。在这里，您会计算两个时间点之间的差异，认为一切都很好。这里可能会出现什么问题？想象一下，在您获取的两个时间点之间，**网络时间协议**（**NTP**）服务器要求本地机器调整本地时钟以使其与时间服务器同步。由于受到 NTP 同步的影响，计算出的持续时间将不准确。NTP 只是一个例子。本地时钟也可以以其他方式进行调整。

# 另请参阅

+   用于与 C++时间接口进行比较的*了解 C++时间接口*配方

+   *Linux 系统编程，第二版*，作者*Robert Love

# 处理时间休眠和超时

在系统编程的上下文中，时间不仅涉及测量事件持续时间或读取时钟的行为。还可以将进程置于休眠状态一段时间。这个配方将教你如何使用基于秒的 API、基于微秒的 API 和具有纳秒分辨率的`clock_nanosleep()`方法来使进程进入休眠状态。此外，我们将看到时间超时是什么，以及如何最小化它们。

# 如何做...

在这一部分，我们将编写一个程序，学习如何使用不同的 POSIX API 来使程序进入休眠状态。我们还将看看 C++的替代方法：

1.  打开一个 shell 并创建一个名为`sleep.cpp`的新文件。我们需要添加一些稍后需要的头文件：

```cpp
#include <iostream>
#include <chrono>
#include <thread>    // sleep_for
#include <unistd.h>  // for sleep
#include <time.h>    // for nanosleep and clock_nanosleep
```

1.  我们将使用`sleep()`方法和`std::chrono::steady_clock`类作为时间点，将程序置于休眠状态`1`秒，以计算持续时间：

```cpp
int main ()
{
    std::cout << "Starting ... " << std::endl;

    auto start = std::chrono::steady_clock::now();
    sleep (1);
    auto end = std::chrono::steady_clock::now();
    std::cout << "sleep() call cause me to sleep for: " 
              << std::chrono::duration_cast<std::chrono::
                  milliseconds> (end-start).count() 
              << " millisec" <<     std::endl;
```

1.  让我们看看`nanosleep()`是如何工作的。我们仍然使用`std::chrono::steady_clock`来计算持续时间，但我们需要一个`struct timespec`。我们将使进程休眠约`100`毫秒：

```cpp
    struct timespec reqSleep = {.tv_sec = 0, .tv_nsec = 99999999};
    start = std::chrono::steady_clock::now();
    int ret = nanosleep (&reqSleep, NULL);
    if (ret)
         std::cerr << "nanosleep issue" << std::endl;
    end = std::chrono::steady_clock::now();
    std::cout << "nanosleep() call cause me to sleep for: " 
              << std::chrono::duration_cast<std::
                  chrono::milliseconds> (end-start).count() 
              << " millisec" << std::endl;
```

1.  将进程置于休眠状态的更高级方法是使用`clock_nanosleep()`，它允许我们指定一些有趣的参数（更多细节请参见下一节）：

```cpp
    struct timespec reqClockSleep = {.tv_sec = 1, 
        .tv_nsec = 99999999};
    start = std::chrono::steady_clock::now();
    ret = clock_nanosleep (CLOCK_MONOTONIC, 0,
        &reqClockSleep, NULL);
    if (ret)
        std::cerr << "clock_nanosleep issue" << std::endl;
    end = std::chrono::steady_clock::now();
    std::cout << "clock_nanosleep() call cause me to sleep for: " 
              << std::chrono::duration_cast<std::chrono::
                  milliseconds> (end-start).count() 
              << " millisec" << std::endl;
```

1.  现在，让我们看看如何使用 C++标准库（通过`std::this_thread::sleep_for`模板方法）将当前线程置于休眠状态：

```cpp
    start = std::chrono::steady_clock::now();
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    end = std::chrono::steady_clock::now();
    std::cout << "std::this_thread::sleep_for() call
      cause me to sleep for: " 
              << std::chrono::duration_cast<std::chrono::
                  milliseconds> (end-start).count() 
              << " millisec" << std::endl;
    std::cout << "End ... " << std::endl;
}
```

现在，让我们更详细地了解这些步骤。

# 它是如何工作的...

程序将以四种不同的方式进入休眠状态。让我们来看看运行时间：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-sys-prog-cb/img/a3c3be5d-eca0-4e1b-97a5-1d4492bd48a0.png)

*步骤 1*只包含我们需要的头文件：`<iostream>`用于标准输出和标准错误（`cout`和`cerr`），`<chrono>`用于将用于测量实际休眠的时间点，`<thread>`用于`sleep_for`方法，`<unistd>`用于`sleep()`，`<time.h>`用于`nanosleep()`和`clock_nanosleep()`。

*步骤 2*使用`sleep()`方法使进程休眠`1`秒。我们使用`steady_clock::now()`来获取时间点，使用`duration_cast`来转换差异并获取实际持续时间。要精确，`sleep()`返回`0`，如果进程成功休眠至少指定时间量，但它可以返回一个介于 0 和指定秒数之间的值，这代表了**未**休眠的时间。

*步骤 3*展示了如何使用`nanosleep()`使进程进入睡眠状态。我们决定使用这种方法，因为在 Linux 上已经弃用了`usleep()`。`nanosleep()`比`sleep()`更有优势，因为它具有纳秒分辨率，并且`POSIX.1b`是标准化的。`nanosleep()`在成功时返回`0`，在错误时返回`-1`。它通过将`errno`全局变量设置为发生的特定错误来实现这一点。`struct timespec`变量包含`tv_sec`和`tv_nsec`（秒和纳秒）。

*步骤 4*使用了一个更复杂的`clock_nanosleep()`。这种方法包含了我们尚未看到的两个参数。第一个参数是`clock_id`，接受，除其他外，`CLOCK_REALTIME`和`CLOCK_MONOTONIC`，我们在前面的配方中已经看过了。作为一个经验法则，如果你要睡到绝对时间（挂钟时间），你应该使用第一个，如果你要睡到相对时间值，你应该使用第二个。根据我们在前面的配方中看到的，这是有道理的。

第二个参数是一个标志；它可以是`TIME_ABSTIME`或`0`。如果传递第一个，那么`reqClockSleep`变量将被视为绝对时间，但如果传递`0`，那么它将被视为相对时间。为了进一步澄清绝对时间的概念，它可能来自前一次调用`clock_gettime()`，它将绝对时间点存储在一个变量中，比如`ts`。通过向其添加`2`秒，我们可以将`&ts`（即变量`ts`的地址）传递给`clock_nanosleep()`，它将等待到那个特定的绝对时间。

*步骤 5*让当前线程的进程进入睡眠状态（在这种情况下，当前线程是主线程，所以整个进程将进入睡眠状态）1.5 秒（1,500 毫秒=1.5 秒）。`std::this_thread::sleep_for`简单而有效。它是一个模板方法，接受一个参数作为输入；也就是说，`duration`，它需要表示类型和周期（`_Rep`和`_Period`），正如我们在*学习 C++时间接口*配方中看到的。在这种情况下，我们只传递了毫秒的周期，并将表示保留在其默认状态。

这里有一个问题我们应该注意：**时间超出**。我们在这个配方中使用的所有接口都保证进程将至少睡眠*所请求的时间*。否则它们会返回错误。它们可能会因为不同的原因而睡眠时间略长于我们请求的时间。一个原因可能是由于选择了不同的任务来运行的调度程序。当计时器的粒度大于所请求的时间时，就会出现这个问题。例如，考虑一下计时器显示的时间（`10msec`）和睡眠时间为`5msec`。我们可能会遇到一个情况，进程必须等待比预期多`5`毫秒，这是 100%的增加。时间超出可以通过使用支持高精度时间源的方法来减轻，例如`clock_nanosleep()`、`nanosleep()`和`std::this_thread::sleep_for()`。

# 还有更多...

我们没有明确提到`nanosleep()`和`clock_nanosleep()`的线程影响。这两种方法都会导致当前线程进入睡眠状态。在 Linux 上，睡眠意味着线程（或者如果是单线程应用程序，则是进程）将进入**不可运行**状态，以便 CPU 可以继续执行其他任务（请记住，Linux 不区分线程和进程）。

# 另请参阅

+   *学习 C++时间接口*的一篇评论，审查`std::chrono::duration<>`模板类

+   *学习 Linux 时间*的一篇评论，审查**REALTIME**和**MONOTONIC**的概念
