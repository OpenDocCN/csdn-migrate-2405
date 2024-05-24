# 精通 Linux 嵌入式编程（四）

> 原文：[`zh.annas-archive.org/md5/3996AD3946F3D9ECE4C1612E34BFD814`](https://zh.annas-archive.org/md5/3996AD3946F3D9ECE4C1612E34BFD814)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：了解进程和线程

在前面的章节中，我们考虑了创建嵌入式 Linux 平台的各个方面。现在是时候开始了解如何使用该平台创建工作设备了。在本章中，我将讨论 Linux 进程模型的含义以及它如何包含多线程程序。我将探讨使用单线程和多线程进程的利弊。我还将研究调度，并区分时间共享和实时调度策略。

虽然这些主题与嵌入式计算无关，但对于嵌入式设备的设计者来说，了解这些主题非常重要。关于这个主题有很多好的参考书籍，其中一些我在本章末尾引用，但一般来说，它们并不考虑嵌入式用例。因此，我将集中讨论概念和设计决策，而不是函数调用和代码。

# 进程还是线程？

许多熟悉**实时操作系统**（RTOS）的嵌入式开发人员认为 Unix 进程模型很繁琐。另一方面，他们认为 RTOS 任务和 Linux 线程之间存在相似性，并倾向于使用一对一的映射将现有设计转移到线程。我曾多次看到整个应用程序都是使用包含 40 个或更多线程的一个进程来实现的设计。我想花一些时间考虑这是否是一个好主意。让我们从一些定义开始。

进程是一个内存地址空间和一个执行线程，如下图所示。地址空间对进程是私有的，因此在不同进程中运行的线程无法访问它。这种内存分离是由内核中的内存管理子系统创建的，该子系统为每个进程保留一个内存页映射，并在每次上下文切换时重新编程内存管理单元。我将在第十一章*管理内存*中详细描述这是如何工作的。地址空间的一部分映射到一个文件，其中包含程序正在运行的代码和静态数据：

![进程还是线程？](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_10_01.jpg)

随着程序的运行，它将分配资源，如堆栈空间，堆内存，文件引用等。当进程终止时，系统将回收这些资源：所有内存都被释放，所有文件描述符都被关闭。

进程可以使用**进程间通信**（IPC）（如本地套接字）相互通信。我将在后面谈论 IPC。

线程是进程内的执行线程。所有进程都从运行`main()`函数的一个线程开始，称为主线程。您可以使用 POSIX 线程函数`pthread_create(3)`创建额外的线程，导致额外的线程在相同的地址空间中执行，如下图所示。由于它们在同一个进程中，它们共享资源。它们可以读写相同的内存并使用相同的文件描述符，因此线程之间的通信很容易，只要您注意同步和锁定问题：

![进程还是线程？](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_10_02.jpg)

因此，基于这些简要细节，您可以想象一个假设系统的两种极端设计，该系统有 40 个 RTOS 任务被移植到 Linux。

您可以将任务映射到进程，并通过 IPC 进行通信，例如通过套接字发送消息，有 40 个单独的程序。这样做可以大大减少内存损坏问题，因为每个进程中运行的主线程都受到其他线程的保护，还可以减少资源泄漏，因为每个进程在退出后都会被清理。然而，进程之间的消息接口非常复杂，当一组进程之间有紧密的合作时，消息的数量可能会很大，因此成为系统性能的限制因素。此外，40 个进程中的任何一个可能会终止，也许是因为出现错误导致崩溃，剩下的 39 个继续运行。每个进程都必须处理其邻居不再运行并优雅地恢复的情况。

在另一个极端，您可以将任务映射到线程，并将系统实现为包含 40 个线程的单个进程。合作变得更容易，因为它们共享相同的地址空间和文件描述符。发送消息的开销减少或消除，线程之间的上下文切换比进程之间的快。缺点是引入了一个任务破坏另一个任务的堆栈的可能性。如果任何一个线程遇到致命错误，整个进程将终止，带走所有的线程。最后，调试复杂的多线程进程可能是一场噩梦。

您应该得出的结论是，这两种设计都不是理想的，有更好的方法。但在我们达到这一点之前，我将更深入地探讨进程和线程的 API 和行为。

# 进程

进程保存了线程可以运行的环境：它保存了内存映射、文件描述符、用户和组 ID 等。第一个进程是`init`进程，它是由内核在启动期间创建的，PID 为 1。此后，进程是通过复制创建的，这个操作称为 forking。

## 创建一个新进程

创建进程的`POSIX`函数是`fork(2)`。这是一个奇怪的函数，因为对于每次成功调用，都有两个返回值：一个在进行调用的进程中，称为父进程，另一个在新创建的进程中，称为子进程，如下图所示：

![创建一个新进程](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_10_03.jpg)

在调用之后，子进程是父进程的精确副本，它有相同的堆栈、相同的堆、相同的文件描述符，并执行与`fork(2)`后面的相同代码行。程序员唯一能够区分它们的方法是查看 fork 的返回值：对于子进程，返回值为零，对于父进程，返回值大于零。实际上，在父进程中返回的值是新创建的子进程的 PID。还有第三种可能性，即返回值为负，意味着 fork 调用失败，仍然只有一个进程。

尽管这两个进程最初是相同的，但它们处于单独的地址空间中。一个进程对变量的更改不会被另一个进程看到。在底层，内核不会对父进程的内存进行物理复制，这将是一个相当缓慢的操作，并且会不必要地消耗内存。相反，内存是共享的，但标记有**写时复制**（**CoW**）标志。如果父进程或子进程修改了这个内存，内核首先会进行复制，然后写入复制。这样做既有了高效的 fork 函数，又保留了进程地址空间的逻辑分离。我将在第十一章*管理内存*中讨论 CoW。

## 终止进程

进程可以通过调用`exit(3)`函数自愿停止，或者通过接收未处理的信号而被迫停止。特别是，一个信号`SIGKILL`无法被处理，因此将总是杀死一个进程。在所有情况下，终止进程将停止所有线程，关闭所有文件描述符，并释放所有内存。系统会向父进程发送一个`SIGCHLD`信号，以便它知道发生了这种情况。

进程有一个返回值，由`exit(3)`的参数组成，如果它正常终止，或者如果它被杀死，则由信号编号组成。这主要用于 shell 脚本：它允许您测试程序的返回值。按照惯例，`0`表示成功，其他值表示某种失败。

父进程可以使用`wait(2)`或`waitpid(2)`函数收集返回值。这会导致一个问题：子进程终止和其父进程收集返回值之间会有延迟。在这段时间内，返回值必须存储在某个地方，现在已经死掉的进程的 PID 号码不能被重用。处于这种状态的进程是`僵尸`，在 ps 或 top 中是 Z 状态。只要父进程调用`wait(2)`或`waitpid(2)`，每当它被通知子进程的终止（通过`SIGCHLD`信号，参见*Linux 系统编程*，由*Robert Love*，*O'Reilly Media*或*The Linux Programming Interface*，由*Michael Kerrisk*，*No Starch Press*有关处理信号的详细信息），僵尸存在的时间太短，无法在进程列表中显示出来。如果父进程未能收集返回值，它们将成为一个问题，因为您将无法创建更多进程。

这是一个简单的示例，显示了进程的创建和终止：

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
int main(void)
{
  int pid;
  int status;
  pid = fork();
  if (pid == 0) {
    printf("I am the child, PID %d\n", getpid());
    sleep(10);
    exit(42);
  } else if (pid > 0) {
    printf("I am the parent, PID %d\n", getpid());
    wait(&status);
    printf("Child terminated, status %d\n",
    WEXITSTATUS(status));
  } else
    perror("fork:");
  return 0;
}
```

`wait(2)`函数会阻塞，直到子进程退出并存储退出状态。当您运行它时，会看到类似这样的东西：

```
I am the parent, PID 13851
I am the child, PID 13852
Child terminated with status 42
```

子进程继承了父进程的大部分属性，包括用户和组 ID（UID 和 GID），所有打开的文件描述符，信号处理和调度特性。

## 运行不同的程序

`fork`函数创建一个正在运行程序的副本，但它不运行不同的程序。为此，您需要其中一个`exec`函数：

```
int execl(const char *path, const char *arg, ...);
int execlp(const char *file, const char *arg, ...);
int execle(const char *path, const char *arg,
           ..., char * const envp[]);
int execv(const char *path, char *const argv[]);
int execvp(const char *file, char *const argv[]);
int execvpe(const char *file, char *const argv[],
           char *const envp[]);
```

每个都需要一个要加载和运行的程序文件的路径。如果函数成功，内核将丢弃当前进程的所有资源，包括内存和文件描述符，并为正在加载的新程序分配内存。当调用`exec*`的线程返回时，它不会返回到调用后的代码行，而是返回到新程序的`main()`函数。这是一个命令启动器的示例：它提示输入一个命令，例如`/bin/ls`，然后分叉和执行您输入的字符串：

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
int main(int argc, char *argv[])
{
  char command_str[128];
  int pid;
  int child_status;
  int wait_for = 1;
  while (1) {
    printf("sh> ");
    scanf("%s", command_str);
    pid = fork();
    if (pid == 0) {
      /* child */
      printf("cmd '%s'\n", command_str);
      execl(command_str, command_str, (char *)NULL);
      /* We should not return from execl, so only get to this line if it failed */
      perror("exec");
      exit(1);
    }
    if (wait_for) {
      waitpid(pid, &child_status, 0);
      printf("Done, status %d\n", child_status);
    }
  }
  return 0;
}
```

有一个函数复制现有进程，另一个丢弃其资源并将不同的程序加载到内存中，这可能看起来有点奇怪，特别是因为`fork`后几乎立即跟随`exec`。大多数操作系统将这两个操作合并为一个单独的调用。

然而，这确实有明显的优势。例如，它使得在 shell 中实现重定向和管道非常容易。想象一下，您想要获取目录列表，这是事件的顺序：

1.  在 shell 提示符处键入`ls`。

1.  shell 分叉一个自身的副本。

1.  子进程执行`/bin/ls`。

1.  `ls`程序将目录列表打印到`stdout`（文件描述符 1），该文件描述符连接到终端。您会看到目录列表。

1.  `ls`程序终止，shell 重新获得控制。

现在，想象一下，您希望通过重定向输出使用`>`字符将目录列表写入文件。现在的顺序如下：

1.  您键入`ls > listing.txt`。

1.  shell 分叉一个自身的副本。

1.  子进程打开并截断文件`listing.txt`，并使用`dup2(2)`将文件的文件描述符复制到文件描述符 1（`stdout`）。

1.  子进程执行`/bin/ls`。

1.  程序像以前一样打印列表，但这次是写入到`listing.txt`。

1.  `ls`程序终止，shell 重新获得控制。

请注意，在第三步有机会修改子进程执行程序之前的环境。`ls`程序不需要知道它正在写入文件而不是终端。`stdout`可以连接到管道，因此`ls`程序仍然不变，可以将输出发送到另一个程序。这是 Unix 哲学的一部分，即将许多小组件组合在一起，每个组件都能很好地完成一项工作，如*The Art of Unix Programming*，作者*Eric Steven Raymond, Addison Wesley*中所述；（2003 年 9 月 23 日）ISBN 978-0131429017，特别是在*Pipes, Redirection, and Filters*部分。

## 守护进程

我们已经在几个地方遇到了守护进程。守护进程是在后台运行的进程，由`init`进程，`PID1`拥有，并且不连接到控制终端。创建守护进程的步骤如下：

1.  调用`fork()`创建一个新进程，之后父进程应该退出，从而创建一个孤儿进程，将被重新分配给`init`。

1.  子进程调用`setsid(2)`，创建一个新的会话和进程组，它是唯一的成员。这里确切的细节并不重要，你可以简单地将其视为一种将进程与任何控制终端隔离的方法。

1.  将工作目录更改为根目录。

1.  关闭所有文件描述符，并将`stdin`、`stdout`和`sterr`（描述符 0、1 和 2）重定向到`/dev/null`，以便没有输入，所有输出都被隐藏。

值得庆幸的是，所有前面的步骤都可以通过一个函数调用`daemon(3)`来实现。

## 进程间通信

每个进程都是一个内存岛。你可以通过两种方式将信息从一个进程传递到另一个进程。首先，你可以将它从一个地址空间复制到另一个地址空间。其次，你可以创建一个两者都可以访问的内存区域，从而共享数据。

通常第一种方法与队列或缓冲区结合在一起，以便进程之间有一系列消息传递。这意味着消息需要复制两次：首先到一个临时区域，然后到目的地。一些例子包括套接字、管道和 POSIX 消息队列。

第二种方法不仅需要一种将内存映射到两个（或更多）地址空间的方法，还需要一种同步访问该内存的方法，例如使用信号量或互斥体。POSIX 有所有这些功能的函数。

还有一组较旧的 API 称为 System V IPC，它提供消息队列、共享内存和信号量，但它不像 POSIX 等效果那样灵活，所以我不会在这里描述它。`svipc(7)`的 man 页面概述了这些设施，*The Linux Programming Interface*，作者*Michael Kerrisk*，*No Starch Press*和*Unix Network Programming, Volume 2*，作者*W. Richard Stevens*中有更多细节。

基于消息的协议通常比共享内存更容易编程和调试，但如果消息很大，则速度会慢。

### 基于消息的 IPC

有几种选项，我将总结如下。区分它们的属性是：

+   消息流是单向还是双向。

+   数据流是否是字节流，没有消息边界，或者是保留边界的离散消息。在后一种情况下，消息的最大大小很重要。

+   消息是否带有优先级标记。

以下表格总结了 FIFO、套接字和消息队列的这些属性：

| 属性 | FIFO | Unix 套接字：流 | Unix 套接字：数据报 | POSIX 消息队列 |
| --- | --- | --- | --- | --- |
| 消息边界 | 字节流 | 字节流 | 离散 | 离散 |
| 单/双向 | 单向 | 双向 | 单向 | 单向 |
| 最大消息大小 | 无限制 | 无限制 | 在 100 KiB 到 250 KiB 范围内 | 默认：8 KiB，绝对最大：1 MiB |
| 优先级级别 | 无 | 无 | 无 | 0 到 32767 |

#### Unix（或本地）套接字

Unix 套接字满足大多数要求，并且与套接字 API 的熟悉度结合在一起，它们是迄今为止最常见的机制。

Unix 套接字使用地址族`AF_UNIX`创建，并绑定到路径名。对套接字的访问取决于套接字文件的访问权限。与 Internet 套接字一样，套接字类型可以是`SOCK_STREAM`或`SOCK_DGRAM`，前者提供双向字节流，后者提供保留边界的离散消息。Unix 套接字数据报是可靠的，这意味着它们不会被丢弃或重新排序。数据报的最大大小取决于系统，并且可以通过`/proc/sys/net/core/wmem_max`获得。通常为 100 KiB 或更大。

Unix 套接字没有指示消息优先级的机制。

#### FIFO 和命名管道

FIFO 和命名管道只是相同事物的不同术语。它们是匿名管道的扩展，用于在父进程和子进程之间通信，并用于在 shell 中实现管道。

FIFO 是一种特殊类型的文件，由命令`mkfifo(1)`创建。与 Unix 套接字一样，文件访问权限决定了谁可以读和写。它们是单向的，意味着有一个读取者和通常一个写入者，尽管可能有几个。数据是纯字节流，但保证了小于管道关联缓冲区的消息的原子性。换句话说，小于此大小的写入将不会分成几个较小的写入，因此读取者将一次性读取整个消息，只要读取端的缓冲区大小足够大。现代内核的 FIFO 缓冲区的默认大小为 64 KiB，并且可以使用`fcntl(2)`和`F_SETPIPE_SZ`增加到`/proc/sys/fs/pipe-max-size`中的值，通常为 1 MiB。

没有优先级的概念。

#### POSIX 消息队列

消息队列由名称标识，名称必须以斜杠`/`开头，并且只能包含一个`/`字符：消息队列实际上保存在类型为`mqueue`的伪文件系统中。您可以通过`mq_open(3)`创建队列并获取对现有队列的引用，该函数返回一个文件。每条消息都有一个优先级，并且消息按优先级和年龄顺序从队列中读取。消息的最大长度可以达到`/proc/sys/kernel/msgmax`字节。默认值为 8 KiB，但您可以将其设置为范围为 128 字节到 1 MiB 的任何大小，方法是将该值写入`/proc/sys/kernel/msgmax`字节。每条消息都有一个优先级。它们按优先级和年龄顺序从队列中读取。由于引用是文件描述符，因此您可以使用`select(2)`、`poll(2)`和其他类似的函数等待队列上的活动。

参见 Linux man 页面*mq_overview(7)*。

### 基于消息的 IPC 的总结

Unix 套接字最常用，因为它们提供了除消息优先级之外的所有所需功能。它们在大多数操作系统上都有实现，因此具有最大的可移植性。

FIFO 很少使用，主要是因为它们缺乏数据报的等效功能。另一方面，API 非常简单，使用常规的`open(2)`、`close(2)`、`read(2)`和`write(2)`文件调用。

消息队列是这组中最不常用的。内核中的代码路径没有像套接字（网络）和 FIFO（文件系统）调用那样进行优化。

还有更高级的抽象，特别是 dbus，它正在从主流 Linux 转移到嵌入式设备。DBus 在表面下使用 Unix 套接字和共享内存。

### 基于共享内存的 IPC

共享内存消除了在地址空间之间复制数据的需要，但引入了对其进行同步访问的问题。进程之间的同步通常使用信号量来实现。

#### POSIX 共享内存

要在进程之间共享内存，首先必须创建一个新的内存区域，然后将其映射到每个希望访问它的进程的地址空间中，如下图所示：

![POSIX 共享内存](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_10_04.jpg)

POSIX 共享内存遵循我们在消息队列中遇到的模式。段的标识以`/`字符开头，并且正好有一个这样的字符。函数`shm_open(3)`接受名称并返回其文件描述符。如果它不存在并且设置了`O_CREAT`标志，那么将创建一个新段。最初它的大小为零。使用（名字有点误导的）`ftruncate(2)`将其扩展到所需的大小。

一旦你有了共享内存的描述符，你可以使用`mmap(2)`将其映射到进程的地址空间中，因此不同进程中的线程可以访问该内存。

这是一个例子：

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>  /* For mode constants */
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>
#include <semaphore.h>
#define SHM_SEGMENT_SIZE 65536
#define SHM_SEGMENT_NAME "/demo-shm"
#define SEMA_NAME "/demo-sem"

static sem_t *demo_sem;
/*
 * If the shared memory segment does not exist already, create it
 * Returns a pointer to the segment or NULL if there is an error
 */

static void *get_shared_memory(void)
{
  int shm_fd;
  struct shared_data *shm_p;
  /* Attempt to create the shared memory segment */
  shm_fd = shm_open(SHM_SEGMENT_NAME, O_CREAT | O_EXCL | O_RDWR, 0666);

  if (shm_fd > 0) {
    /* succeeded: expand it to the desired size (Note: dont't do "this every time because ftruncate fills it with zeros) */
    printf ("Creating shared memory and setting size=%d\n",
    SHM_SEGMENT_SIZE);

    if (ftruncate(shm_fd, SHM_SEGMENT_SIZE) < 0) {
      perror("ftruncate");
      exit(1);
    }
    /* Create a semaphore as well */
    demo_sem = sem_open(SEMA_NAME, O_RDWR | O_CREAT, 0666, 1);

    if (demo_sem == SEM_FAILED)
      perror("sem_open failed\n");
  }
  else if (shm_fd == -1 && errno == EEXIST) {
    /* Already exists: open again without O_CREAT */
    shm_fd = shm_open(SHM_SEGMENT_NAME, O_RDWR, 0);
    demo_sem = sem_open(SEMA_NAME, O_RDWR);

    if (demo_sem == SEM_FAILED)
      perror("sem_open failed\n");
  }

  if (shm_fd == -1) {
    perror("shm_open " SHM_SEGMENT_NAME);
    exit(1);
  }
  /* Map the shared memory */
  shm_p = mmap(NULL, SHM_SEGMENT_SIZE, PROT_READ | PROT_WRITE,
    MAP_SHARED, shm_fd, 0);

  if (shm_p == NULL) {
    perror("mmap");
    exit(1);
  }
  return shm_p;
}
int main(int argc, char *argv[])
{
  char *shm_p;
  printf("%s PID=%d\n", argv[0], getpid());
  shm_p = get_shared_memory();

  while (1) {
    printf("Press enter to see the current contents of shm\n");
    getchar();
    sem_wait(demo_sem);
    printf("%s\n", shm_p);
    /* Write our signature to the shared memory */
    sprintf(shm_p, "Hello from process %d\n", getpid());
    sem_post(demo_sem);
  }
  return 0;
}
```

Linux 中的内存来自于`tmpfs`文件系统，挂载在`/dev/shm`或`/run/shm`中。

# 线程

现在是时候看看多线程进程了。线程的编程接口是 POSIX 线程 API，最初在 IEEE POSIX 1003.1c 标准（1995 年）中定义，通常称为 Pthreads。它作为 C 库的附加部分实现，`libpthread.so`。在过去 15 年左右，已经有两个版本的 Pthreads，Linux Threads 和**本地 POSIX 线程库**（**NPTL**）。后者更符合规范，特别是在处理信号和进程 ID 方面。它现在相当占主导地位，但你可能会遇到一些使用 Linux Threads 的旧版本 uClibc。

## 创建新线程

创建线程的函数是`pthread_create(3)`：

```
int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg);
```

它创建一个从`start_routine`函数开始的新执行线程，并将一个描述符放在`pthread_t`指向的`thread`中。它继承调用线程的调度参数，但这些参数可以通过在`attr`中传递指向线程属性的指针来覆盖。线程将立即开始执行。

`pthread_t`是程序内引用线程的主要方式，但是线程也可以通过像`ps -eLf`这样的命令从外部看到：

```
UID    PID  PPID   LWP  C  NLWP  STIME        TTY           TIME CMD
...
chris  6072  5648  6072  0   3    21:18  pts/0 00:00:00 ./thread-demo
chris  6072  5648  6073  0   3    21:18  pts/0 00:00:00 ./thread-demo

```

程序`thread-demo`有两个线程。`PID`和`PPID`列显示它们都属于同一个进程，并且有相同的父进程，这是你所期望的。不过，标记为`LWP`的列很有趣。`LWP`代表轻量级进程，在这个上下文中，是线程的另一个名称。该列中的数字也被称为**线程 ID**或**TID**。在主线程中，TID 与 PID 相同，但对于其他线程，它是一个不同（更高）的值。一些函数将在文档规定必须给出 PID 的地方接受 TID，但请注意，这种行为是特定于 Linux 的，不具有可移植性。以下是`thread-demo`的代码：

```
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>

static void *thread_fn(void *arg)
{
  printf("New thread started, PID %d TID %d\n",
  getpid(), (pid_t)syscall(SYS_gettid));
  sleep(10);
  printf("New thread terminating\n");
  return NULL;
}

int main(int argc, char *argv[])
{
  pthread_t t;
  printf("Main thread, PID %d TID %d\n",
  getpid(), (pid_t)syscall(SYS_gettid));
  pthread_create(&t, NULL, thread_fn, NULL);
  pthread_join(t, NULL);
  return 0;
}
```

有一个`getttid(2)`的 man 页面解释说你必须直接进行 Linux `syscall`，因为没有 C 库包装器，如所示。

给定内核可以调度的线程总数是有限的。该限制根据系统的大小而变化，从小型设备上的大约 1,000 个到较大嵌入式设备上的数万个。实际数量可以在`/proc/sys/kernel/threads-max`中找到。一旦达到这个限制，`fork()`和`pthread_create()`将失败。

## 终止线程

线程在以下情况下终止：

+   它到达其`start_routine`的末尾

+   它调用`pthread_exit(3)`

+   它被另一个线程调用`pthread_cancel(3)`取消

+   包含线程的进程终止，例如，因为一个线程调用`exit(3)`，或者进程接收到一个未处理、屏蔽或忽略的信号

请注意，如果一个多线程程序调用`fork(2)`，只有发出调用的线程会存在于新的子进程中。`fork`不会复制所有线程。

线程有一个返回值，是一个 void 指针。一个线程可以通过调用`pthread_join(2)`等待另一个线程终止并收集其返回值。在前面部分提到的`thread-demo`代码中有一个例子。这会产生一个与进程中的僵尸问题非常相似的问题：线程的资源，例如堆栈，在另一个线程加入之前无法被释放。如果线程保持未加入状态，程序中就会出现资源泄漏。

## 使用线程编译程序

对 POSIX 线程的支持是 C 库的一部分，在库`libpthread.so`中。然而，构建带有线程的程序不仅仅是链接库：必须对编译器生成的代码进行更改，以确保某些全局变量，例如`errno`，每个线程都有一个实例，而不是整个进程共享一个。

### 提示

构建一个多线程程序时，您必须在编译和链接阶段添加开关`-pthread`。

## 线程间通信

线程的一个巨大优势是它们共享地址空间，因此可以共享内存变量。这也是一个巨大的缺点，因为它需要同步以保持数据一致性，类似于进程之间共享的内存段，但需要注意的是，对于线程，所有内存都是共享的。线程可以使用**线程本地存储**（**TLS**）创建私有内存。

`pthreads`接口提供了实现同步所需的基本功能：互斥锁和条件变量。如果您需要更复杂的结构，您将不得不自己构建它们。

值得注意的是，之前描述的所有 IPC 方法在同一进程中的线程之间同样有效。

## 互斥排除

为了编写健壮的程序，您需要用互斥锁保护每个共享资源，并确保每个读取或写入资源的代码路径都先锁定了互斥锁。如果您始终遵循这个规则，大部分问题应该可以解决。剩下的问题与互斥锁的基本行为有关。我会在这里简要列出它们，但不会详细介绍：

+   **死锁**：当互斥锁永久锁定时会发生。一个经典的情况是致命的拥抱，其中两个线程分别需要两个互斥锁，并且已经锁定了其中一个，但没有锁定另一个。每个块都在等待另一个已经锁定的锁，因此它们保持原样。避免致命拥抱问题的一个简单规则是确保互斥锁总是以相同的顺序锁定。其他解决方案涉及超时和退避期。

+   **优先级反转**：由于等待互斥锁造成的延迟，实时线程可能会错过截止日期。优先级反转的特定情况发生在高优先级线程因等待被低优先级线程锁定的互斥锁而被阻塞。如果低优先级线程被中间优先级的其他线程抢占，高优先级线程将被迫等待无限长的时间。有互斥锁协议称为优先级继承和优先级上限，它们以每次锁定和解锁调用在内核中产生更大的处理开销来解决问题。

+   **性能差**：互斥锁会给代码引入最小的开销，只要线程大部分时间不必在其上阻塞。然而，如果您的设计有一个被许多线程需要的资源，争用比变得显著。这通常是一个设计问题，可以通过使用更细粒度的锁定或不同的算法来解决。

## 改变条件

合作线程需要一种方法来通知彼此发生了变化并需要关注。这个东西称为条件，警报通过条件变量`condvar`发送。

条件只是一个可以测试以给出`true`或`false`结果的东西。一个简单的例子是一个包含零个或一些项目的缓冲区。一个线程从缓冲区中取出项目，并在空时休眠。另一个线程将项目放入缓冲区，并通知另一个线程已经这样做了，因为另一个线程正在等待的条件已经改变。如果它正在休眠，它需要醒来并做一些事情。唯一的复杂性在于条件是一个共享资源，因此必须受到互斥锁的保护。以下是一个简单的例子，遵循了前一节描述的生产者-消费者关系：

```
pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
pthread_mutex_t mutx = PTHREAD_MUTEX_INITIALIZER;

void *consumer(void *arg)
{
  while (1) {
    pthread_mutex_lock(&mutx);
    while (buffer_empty(data))
      pthread_cond_wait(&cv, &mutx);
    /* Got data: take from buffer */
    pthread_mutex_unlock(&mutx);
    /* Process data item */
  }
  return NULL;
}

void *producer(void *arg)
{
  while (1) {
    /* Produce an item of data */
    pthread_mutex_lock(&mutx);
    add_data(data);
    pthread_mutex_unlock(&mutx);
    pthread_cond_signal(&cv);
  }
  return NULL;
}
```

请注意，当消费者线程在`condvar`上阻塞时，它是在持有锁定的互斥锁的情况下这样做的，这似乎是下一次生产者线程尝试更新条件时产生死锁的原因。为了避免这种情况，`pthread_condwait(3)`在线程被阻塞后解锁互斥锁，并在唤醒它并从等待中返回时再次锁定它。

## 问题的分区

现在我们已经介绍了进程和线程的基础知识以及它们之间的通信方式，是时候看看我们可以用它们做些什么了。

以下是我在构建系统时使用的一些规则：

+   **规则 1**：保持具有大量交互的任务。

通过将紧密相互操作的线程放在一个进程中，最小化开销。

+   **规则 2**：不要把所有的线程放在一个篮子里。

另一方面，为了提高韧性和模块化，尽量将交互有限的组件放在单独的进程中。

+   **规则 3**：不要在同一个进程中混合关键和非关键线程。

这是对规则 2 的进一步阐释：系统的关键部分，可能是机器控制程序，应尽可能简单，并以比其他部分更严格的方式编写。它必须能够在其他进程失败时继续运行。如果有实时线程，它们必须是关键的，并且应该单独放入一个进程中。

+   **规则 4**：线程不应该过于亲密。

编写多线程程序时的一个诱惑是在线程之间交织代码和变量，因为它们都在一个程序中，很容易做到。不要让线程之间的交互模块化。

+   **规则 5**：不要认为线程是免费的。

创建额外的线程非常容易，但成本很高，尤其是在协调它们的活动所需的额外同步方面。

+   **规则 6**：线程可以并行工作。

线程可以在多核处理器上同时运行，从而提高吞吐量。如果有一个庞大的计算任务，可以为每个核心创建一个线程，并充分利用硬件。有一些库可以帮助你做到这一点，比如 OpenMP。你可能不应该从头开始编写并行编程算法。

Android 设计是一个很好的例子。每个应用程序都是一个单独的 Linux 进程，这有助于模块化内存管理，尤其是确保一个应用程序崩溃不会影响整个系统。进程模型也用于访问控制：一个进程只能访问其 UID 和 GID 允许的文件和资源。每个进程中都有一组线程。有一个用于管理和更新用户界面的线程，一个用于处理来自操作系统的信号，几个用于管理动态内存分配和释放 Java 对象，以及至少两个线程的工作池，用于使用 Binder 协议从系统的其他部分接收消息。

总之，进程提供了韧性，因为每个进程都有受保护的内存空间，当进程终止时，包括内存和文件描述符在内的所有资源都被释放，减少了资源泄漏。另一方面，线程共享资源，因此可以通过共享变量轻松通信，并且可以通过共享对文件和其他资源的访问来合作。线程通过工作池和其他抽象提供并行性，在多核处理器上非常有用。

# 调度

我想在本章中要讨论的第二个重要主题是调度。Linux 调度器有一个准备运行的线程队列，其工作是在 CPU 上安排它们。每个线程都有一个调度策略，可以是时间共享或实时。时间共享线程有一个 niceness 值，它增加或减少它们对 CPU 时间的权利。实时线程有一个优先级，较高优先级的线程将抢占较低优先级的线程。调度器与线程一起工作，而不是进程。每个线程都会被安排，不管它运行在哪个进程中。

调度器在以下情况下运行：

+   线程通过调用`sleep()`或阻塞 I/O 调用来阻塞

+   时间共享线程耗尽了其时间片

+   中断会导致线程解除阻塞，例如，因为 I/O 完成。

关于 Linux 调度器的背景信息，我建议阅读*Linux Kernel Development*中关于进程调度的章节，作者是 Robert Love，Addison-Wesley Professional 出版社，ISBN-10: 0672329468。

## 公平性与确定性

我将调度策略分为时间共享和实时两类。时间共享策略基于公平原则。它们旨在确保每个线程获得公平的处理器时间，并且没有线程可以独占系统。如果一个线程运行时间过长，它将被放到队列的末尾，以便其他线程有机会运行。同时，公平策略需要调整到正在执行大量工作的线程，并为它们提供资源以完成工作。时间共享调度很好，因为它可以自动调整到各种工作负载。

另一方面，如果你有一个实时程序，公平性是没有帮助的。相反，你需要一个确定性的策略，它至少会给你最小的保证，即你的实时线程将在正确的时间被调度，以便它们不会错过截止日期。这意味着实时线程必须抢占时间共享线程。实时线程还有一个静态优先级，调度器可以用它来在多个实时线程同时运行时进行选择。Linux 实时调度器实现了一个相当标准的算法，它运行最高优先级的实时线程。大多数 RTOS 调度器也是以这种方式编写的。

两种类型的线程可以共存。需要确定性调度的线程首先被调度，剩下的时间被分配给时间共享线程。

## 时间共享策略

时间共享策略是为了公平而设计的。从 Linux 2.6.23 开始，使用的调度器是**Completely Fair Scheduler**（**CFS**）。它不像通常意义上的时间片。相反，它计算了一个线程如果拥有其公平份额的 CPU 时间的运行总数，并将其与实际运行时间进行平衡。如果它超过了它的权利，并且有其他时间共享线程在等待运行，调度器将暂停该线程并运行等待线程。

时间共享策略有：

+   `SCHED_NORMAL`（也称为`SCHED_OTHER`）：这是默认策略。绝大多数 Linux 线程使用此策略。

+   `SCHED_BATCH`：这类似于 `SCHED_NORMAL`，只是线程以更大的粒度进行调度；也就是说它们运行的时间更长，但必须等待更长时间才能再次调度。其目的是减少后台处理（批处理作业）的上下文切换次数，从而减少 CPU 缓存的使用。

+   `SCHED_IDLE`：这些线程只有在没有其他策略的线程准备运行时才运行。这是最低优先级。

有两对函数用于获取和设置线程的策略和优先级。第一对以 PID 作为参数，并影响进程中的主线程：

```
struct sched_param {
  ...
  int sched_priority;
  ...
};
int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param);
int sched_getscheduler(pid_t pid);
```

第二对函数操作 `pthread_t`，因此可以更改进程中其他线程的参数：

```
pthread_setschedparam(pthread_t thread, int policy, const struct sched_param *param);
pthread_getschedparam(pthread_t thread, int *policy, struct sched_param *param);
```

### Niceness

有些时间共享线程比其他线程更重要。您可以使用 `nice` 值来指示这一点，它将线程的 CPU 权利乘以一个缩放因子。这个名字来自于 Unix 早期的函数调用 `nice(2)`。通过减少系统上的负载，线程变得`nice`，或者通过增加负载来朝相反方向移动。值的范围是从 19（非常 nice）到 -20（非常不 nice）。默认值是 0，即平均 nice 或一般般。

`nice` 值可以更改 `SCHED_NORMAL` 和 `SCHED_BATCH` 线程的值。要减少 niceness，增加 CPU 负载，您需要 `CAP_SYS_NICE` 权限，这仅适用于 root 用户。

几乎所有更改 `nice` 值的函数和命令的文档（`nice(2)` 和 `nice` 以及 `renice` 命令）都是关于进程的。但实际上它与线程有关。正如前一节中提到的，您可以使用 TID 替换 PID 来更改单个线程的 `nice` 值。标准描述中 `nice` 的另一个不一致之处：`nice` 值被称为线程的优先级（有时甚至错误地称为进程的优先级）。我认为这是误导性的，并且将概念与实时优先级混淆了，这是完全不同的东西。

## 实时策略

实时策略旨在实现确定性。实时调度程序将始终运行准备运行的最高优先级实时线程。实时线程总是抢占时间共享线程。实质上，通过选择实时策略而不是时间共享策略，您是在说您对该线程的预期调度有内部知识，并希望覆盖调度程序的内置假设。

有两种实时策略：

+   `SCHED_FIFO`：这是一个运行到完成的算法，这意味着一旦线程开始运行，它将一直运行，直到被更高优先级的实时线程抢占或在系统调用中阻塞或终止（完成）。

+   `SCHED_RR`：这是一个循环调度算法，如果线程超过其时间片（默认为 100 毫秒），它将在相同优先级的线程之间循环。自 Linux 3.9 以来，可以通过 `/proc/sys/kernel/sched_rr_timeslice_ms` 控制 `timeslice` 值。除此之外，它的行为方式与 `SCHED_FIFO` 相同。

每个实时线程的优先级范围为 1 到 99，99 是最高的。

要给线程一个实时策略，您需要 `CAP_SYS_NICE` 权限，默认情况下只有 root 用户拥有该权限。

实时调度的一个问题，无论是在 Linux 还是其他地方，是线程变得计算密集，通常是因为错误导致其无限循环，这会阻止优先级较低的实时线程以及所有时间共享线程运行。系统变得不稳定，甚至可能完全锁死。有几种方法可以防范这种可能性。

首先，自 Linux 2.6.25 以来，默认情况下调度程序保留了 5% 的 CPU 时间用于非实时线程，因此即使是失控的实时线程也不能完全停止系统。它通过两个内核控制进行配置：

+   `/proc/sys/kernel/sched_rt_period_us`

+   `/proc/sys/kernel/sched_rt_runtime_us`

它们的默认值分别为 1,000,000（1 秒）和 950,000（950 毫秒），这意味着每秒钟有 50 毫秒用于非实时处理。如果要使实时线程能够占用 100％，则将`sched_rt_runtime_us`设置为`-1`。

第二个选择是使用看门狗，无论是硬件还是软件，来监视关键线程的执行，并在它们开始错过截止日期时采取行动。

## 选择策略

实际上，时间共享策略满足了大多数计算工作负载。I/O 绑定的线程花费大量时间被阻塞，因此总是有一些剩余的权利。当它们解除阻塞时，它们几乎立即被调度。与此同时，CPU 绑定的线程将自然地占用剩余的任何 CPU 周期。可以将积极的优先级值应用于不太重要的线程，将负值应用于重要的线程。

当然，这只是平均行为，不能保证这种情况总是存在。如果需要更确定的行为，则需要实时策略。标记线程为实时的因素包括：

+   它有一个必须生成输出的截止日期

+   错过截止日期将损害系统的有效性

+   它是事件驱动的

+   它不是计算绑定的

实时任务的示例包括经典的机器人臂伺服控制器，多媒体处理和通信处理。

## 选择实时优先级

选择适用于所有预期工作负载的实时优先级是一个棘手的问题，也是避免首先使用实时策略的一个很好的理由。

选择优先级的最常用程序称为**速率单调分析**（**RMA**），根据 1973 年 Liu 和 Layland 的论文。它适用于具有周期性线程的实时系统，这是一个非常重要的类别。每个线程都有一个周期和一个利用率，即其执行期的比例。目标是平衡负载，以便所有线程都能在下一个周期之前完成其执行阶段。RMA 规定，如果：

+   最高优先级给予具有最短周期的线程

+   总利用率低于 69％

总利用率是所有个体利用率的总和。它还假设线程之间的交互或在互斥锁上阻塞的时间是可以忽略不计的。

# 进一步阅读

以下资源提供了有关本章介绍的主题的更多信息：

+   《Unix 编程艺术》，作者*Eric Steven Raymond*，*Addison Wesley*；（2003 年 9 月 23 日）ISBN 978-0131429017

+   《Linux 系统编程，第二版》，作者*Robert Love*，*O'Reilly Media*；（2013 年 6 月 8 日）ISBN-10：1449339530

+   《Linux 内核开发》，*Robert Love*，*Addison-Wesley Professional*；（2010 年 7 月 2 日）ISBN-10：0672329468

+   《Linux 编程接口》，作者*Michael Kerrisk*，*No Starch Press*；（2010 年 10 月）ISBN 978-1-59327-220-3

+   《UNIX 网络编程：卷 2：进程间通信，第二版》，作者*W. Richard Stevens*，*Prentice Hall*；（1998 年 8 月 25 日）ISBN-10：0132974290

+   《使用 POSIX 线程编程》，作者*Butenhof*，*David R*，*Addison-Wesley*，*Professional*

+   《硬实时环境中的多道程序调度算法》，作者*C. L. Liu*和*James W. Layland*，*ACM 杂志*，1973 年，第 20 卷，第 1 期，第 46-61 页

# 总结

内置在 Linux 和附带的 C 库中的长期 Unix 传统几乎提供了编写稳定和弹性嵌入式应用程序所需的一切。问题在于，对于每项工作，至少有两种方法可以实现您所期望的结果。

在本章中，我专注于系统设计的两个方面：将其分成单独的进程，每个进程都有一个或多个线程来完成工作，以及对这些线程进行调度。我希望我已经为您解开了一些疑惑，并为您进一步研究所有这些内容提供了基础。

在下一章中，我将研究系统设计的另一个重要方面，即内存管理。


# 第十一章：管理内存

本章涵盖了与内存管理相关的问题，这对于任何 Linux 系统都是一个重要的话题，但对于嵌入式 Linux 来说尤其重要，因为系统内存通常是有限的。在简要回顾了虚拟内存之后，我将向您展示如何测量内存使用情况，如何检测内存分配的问题，包括内存泄漏，以及当内存用尽时会发生什么。您必须了解可用的工具，从简单的工具如`free`和`top`，到复杂的工具如 mtrace 和 Valgrind。

# 虚拟内存基础知识

总之，Linux 配置 CPU 的内存管理单元，向运行的程序呈现一个虚拟地址空间，从零开始，到 32 位处理器上的最高地址`0xffffffff`结束。该地址空间被分成 4 KiB 的页面（也有一些罕见的系统使用其他页面大小）。

Linux 将这个虚拟地址空间分为一个称为用户空间的应用程序区域和一个称为内核空间的内核区域。这两者之间的分割由一个名为`PAGE_OFFSET`的内核配置参数设置。在典型的 32 位嵌入式系统中，`PAGE_OFFSET`是`0xc0000000`，将低 3 GiB 分配给用户空间，将顶部 1 GiB 分配给内核空间。用户地址空间是针对每个进程分配的，因此每个进程都在一个沙盒中运行，与其他进程分离。内核地址空间对所有进程都是相同的：只有一个内核。

这个虚拟地址空间中的页面通过**内存管理单元**（**MMU**）映射到物理地址，后者使用页表执行映射。

每个虚拟内存页面可能是：

+   未映射，访问将导致`SIGSEGV`

+   映射到进程私有的物理内存页面

+   映射到与其他进程共享的物理内存页面

+   映射并与设置了`写时复制`标志的共享：写入被内核捕获，内核复制页面并将其映射到原始页面的进程中，然后允许写入发生

+   映射到内核使用的物理内存页面

内核可能还会将页面映射到保留的内存区域，例如，以访问设备驱动程序中的寄存器和缓冲内存

一个明显的问题是，为什么我们要这样做，而不是像典型的 RTOS 那样直接引用物理内存？

虚拟内存有许多优点，其中一些在这里描述：

+   无效的内存访问被捕获，并通过`SIGSEGV`通知应用程序

+   进程在自己的内存空间中运行，与其他进程隔离

+   通过共享公共代码和数据来有效利用内存，例如在库中

+   通过添加交换文件来增加物理内存的表面数量的可能性，尽管在嵌入式目标上进行交换是罕见的

这些都是有力的论据，但我们必须承认也存在一些缺点。很难确定应用程序的实际内存预算，这是本章的主要关注点之一。默认的分配策略是过度承诺，这会导致棘手的内存不足情况，我稍后也会讨论。最后，内存管理代码在处理异常（页面错误）时引入的延迟使系统变得不太确定，这对实时程序很重要。我将在第十四章 *实时编程*中介绍这一点。

内核空间和用户空间的内存管理是不同的。以下部分描述了基本的区别和你需要了解的事情。

# 内核空间内存布局

内核内存的管理方式相当直接。它不是按需分页的，这意味着对于每个使用`kmalloc()`或类似函数进行的分配，都有真正的物理内存。内核内存从不被丢弃或分页出去。

一些体系结构在内核日志消息中显示了启动时内存映射的摘要。这个跟踪来自一个 32 位 ARM 设备（BeagleBone Black）：

```
Memory: 511MB = 511MB total
Memory: 505980k/505980k available, 18308k reserved, 0K highmem
Virtual kernel memory layout:
  vector  : 0xffff0000 - 0xffff1000   (   4 kB)
  fixmap  : 0xfff00000 - 0xfffe0000   ( 896 kB)
  vmalloc : 0xe0800000 - 0xff000000   ( 488 MB)
  lowmem  : 0xc0000000 - 0xe0000000   ( 512 MB)
  pkmap   : 0xbfe00000 - 0xc0000000   (   2 MB)
  modules : 0xbf800000 - 0xbfe00000   (   6 MB)
    .text : 0xc0008000 - 0xc0763c90   (7536 kB)
    .init : 0xc0764000 - 0xc079f700   ( 238 kB)
    .data : 0xc07a0000 - 0xc0827240   ( 541 kB)
     .bss : 0xc0827240 - 0xc089e940   ( 478 kB)
```

505980 KiB 可用的数字是内核在开始执行但在开始进行动态分配之前看到的空闲内存量。

内核空间内存的使用者包括以下内容：

+   内核本身，换句话说，从内核映像文件在启动时加载的代码和数据。这在前面的代码中显示在段`.text`、`.init`、`.data`和`.bss`中。一旦内核完成初始化，`.init`段就被释放。

+   通过 slab 分配器分配的内存，用于各种内核数据结构。这包括使用`kmalloc()`进行的分配。它们来自标记为`lowmem`的区域。

+   通过`vmalloc()`分配的内存，通常比通过`kmalloc()`可用的内存大。这些位于 vmalloc 区域。

+   用于设备驱动程序访问属于各种硬件部分的寄存器和内存的映射，可以通过阅读`/proc/iomem`来查看。这些来自 vmalloc 区域，但由于它们映射到主系统内存之外的物理内存，它们不占用任何真实的内存。

+   内核模块，加载到标记为模块的区域。

+   其他低级别的分配在其他地方没有被跟踪。

## 内核使用多少内存？

不幸的是，对于这个问题并没有一个完整的答案，但接下来的内容是我们能得到的最接近的。

首先，你可以在之前显示的内核日志中看到内核代码和数据占用的内存，或者你可以使用`size`命令，如下所示：

```
$ arm-poky-linux-gnueabi-size vmlinux
text      data     bss       dec       hex       filename
9013448   796868   8428144   18238460  1164bfc   vmlinux

```

通常，与总内存量相比，大小很小。如果不是这样，你需要查看内核配置，并删除那些你不需要的组件。目前正在努力允许构建小内核：搜索 Linux-tiny 或 Linux Kernel Tinification。后者有一个项目页面[`tiny.wiki.kernel.org/`](https://tiny.wiki.kernel.org/)。

你可以通过阅读`/proc/meminfo`来获取有关内存使用情况的更多信息：

```
# cat /proc/meminfo
MemTotal:         509016 kB
MemFree:          410680 kB
Buffers:            1720 kB
Cached:            25132 kB
SwapCached:            0 kB
Active:            74880 kB
Inactive:           3224 kB
Active(anon):      51344 kB
Inactive(anon):     1372 kB
Active(file):      23536 kB
Inactive(file):     1852 kB
Unevictable:           0 kB
Mlocked:               0 kB
HighTotal:             0 kB
HighFree:              0 kB
LowTotal:         509016 kB
LowFree:          410680 kB
SwapTotal:             0 kB
SwapFree:              0 kB
Dirty:                16 kB
Writeback:             0 kB
AnonPages:         51248 kB
Mapped:            24376 kB
Shmem:              1452 kB
Slab:              11292 kB
SReclaimable:       5164 kB
SUnreclaim:         6128 kB
KernelStack:        1832 kB
PageTables:         1540 kB
NFS_Unstable:          0 kB
Bounce:                0 kB
WritebackTmp:          0 kB
CommitLimit:      254508 kB
Committed_AS:     734936 kB
VmallocTotal:     499712 kB
VmallocUsed:       29576 kB
VmallocChunk:     389116 kB
```

这些字段的描述在`proc(5)`的 man 页面中。内核内存使用是以下内容的总和：

+   **Slab**：由 slab 分配器分配的总内存

+   **KernelStack**：执行内核代码时使用的堆栈空间

+   **PageTables**：用于存储页表的内存

+   **VmallocUsed**：由`vmalloc()`分配的内存

在 slab 分配的情况下，你可以通过阅读`/proc/slabinfo`来获取更多信息。类似地，在`/proc/vmallocinfo`中有 vmalloc 区域的分配细分。在这两种情况下，你需要对内核及其子系统有详细的了解，以确切地看到哪个子系统正在进行分配以及原因，这超出了本讨论的范围。

使用模块，你可以使用`lsmod`来查找代码和数据占用的内存空间：

```
# lsmod
Module            Size  Used by
g_multi          47670  2
libcomposite     14299  1 g_multi
mt7601Usta       601404  0
```

这留下了低级别的分配，没有记录，这阻止我们生成一个准确的内核空间内存使用情况。当我们把我们知道的所有内核和用户空间分配加起来时，这将出现为缺失的内存。

# 用户空间内存布局

Linux 采用懒惰的分配策略，只有在程序访问时才映射物理内存页面。例如，使用`malloc(3)`分配 1 MiB 的缓冲区返回一个内存地址块的指针，但没有实际的物理内存。在页表条目中设置一个标志，以便内核捕获任何读取或写入访问。这就是所谓的页错误。只有在这一点上，内核才尝试找到一个物理内存页，并将其添加到进程的页表映射中。值得用一个简单的程序来演示这一点：

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#define BUFFER_SIZE (1024 * 1024)

void print_pgfaults(void)
{
  int ret;
  struct rusage usage;
  ret = getrusage(RUSAGE_SELF, &usage);
  if (ret == -1) {
    perror("getrusage");
  } else {
    printf ("Major page faults %ld\n", usage.ru_majflt);
    printf ("Minor page faults %ld\n", usage.ru_minflt);
  }
}

int main (int argc, char *argv[])
{
  unsigned char *p;
  printf("Initial state\n");
  print_pgfaults();
  p = malloc(BUFFER_SIZE);
  printf("After malloc\n");
  print_pgfaults();
  memset(p, 0x42, BUFFER_SIZE);
  printf("After memset\n");
  print_pgfaults();
  memset(p, 0x42, BUFFER_SIZE);
  printf("After 2nd memset\n");
  print_pgfaults();
  return 0;
}
```

当你运行它时，你会看到这样的东西：

```
Initial state
Major page faults 0
Minor page faults 172
After malloc
Major page faults 0
Minor page faults 186
After memset
Major page faults 0
Minor page faults 442
After 2nd memset
Major page faults 0
Minor page faults 442
```

在初始化程序环境时遇到了 172 个次要页面错误，并在调用`getrusage(2)`时遇到了 14 个次要页面错误（这些数字将根据您使用的体系结构和 C 库的版本而变化）。重要的部分是填充内存时的增加：442-186 = 256。缓冲区为 1 MiB，即 256 页。第二次调用`memset(3)`没有任何区别，因为现在所有页面都已映射。

正如您所看到的，当内核捕获到对未映射的页面的访问时，将生成页面错误。实际上，有两种页面错误：次要和主要。次要错误时，内核只需找到一个物理内存页面并将其映射到进程地址空间，如前面的代码所示。主要页面错误发生在虚拟内存映射到文件时，例如使用`mmap(2)`，我将很快描述。从该内存中读取意味着内核不仅需要找到一个内存页面并将其映射进来，还需要从文件中填充数据。因此，主要错误在时间和系统资源方面要昂贵得多。

# 进程内存映射

您可以通过`proc`文件系统查看进程的内存映射。例如，这是`init`进程的 PID 1 的映射：

```
# cat /proc/1/maps
00008000-0000e000 r-xp 00000000 00:0b 23281745   /sbin/init
00016000-00017000 rwxp 00006000 00:0b 23281745   /sbin/init
00017000-00038000 rwxp 00000000 00:00 0          [heap]
b6ded000-b6f1d000 r-xp 00000000 00:0b 23281695   /lib/libc-2.19.so
b6f1d000-b6f24000 ---p 00130000 00:0b 23281695   /lib/libc-2.19.so
b6f24000-b6f26000 r-xp 0012f000 00:0b 23281695   /lib/libc-2.19.so
b6f26000-b6f27000 rwxp 00131000 00:0b 23281695   /lib/libc-2.19.so
b6f27000-b6f2a000 rwxp 00000000 00:00 0
b6f2a000-b6f49000 r-xp 00000000 00:0b 23281359   /lib/ld-2.19.so
b6f4c000-b6f4e000 rwxp 00000000 00:00 0
b6f4f000-b6f50000 r-xp 00000000 00:00 0          [sigpage]
b6f50000-b6f51000 r-xp 0001e000 00:0b 23281359   /lib/ld-2.19.so
b6f51000-b6f52000 rwxp 0001f000 00:0b 23281359   /lib/ld-2.19.so
beea1000-beec2000 rw-p 00000000 00:00 0          [stack]
ffff0000-ffff1000 r-xp 00000000 00:00 0          [vectors]
```

前三列显示每个映射的开始和结束虚拟地址以及权限。权限在这里显示：

+   `r` = 读

+   `w` = 写

+   `x` = 执行

+   `s` = 共享

+   `p` = 私有（写时复制）

如果映射与文件相关联，则文件名将出现在最后一列，第四、五和六列包含从文件开始的偏移量，块设备号和文件的 inode。大多数映射都是到程序本身和它链接的库。程序可以分配内存的两个区域，标记为`[heap]`和`[stack]`。使用`malloc(3)`分配的内存来自前者（除了非常大的分配，我们稍后会讨论）；堆栈上的分配来自后者。两个区域的最大大小由进程的`ulimit`控制：

+   **堆**：`ulimit -d`，默认无限制

+   **堆栈**：`ulimit -s`，默认 8 MiB

超出限制的分配将被`SIGSEGV`拒绝。

当内存不足时，内核可能决定丢弃映射到文件且只读的页面。如果再次访问该页面，将导致主要页面错误，并从文件中重新读取。

# 交换

交换的想法是保留一些存储空间，内核可以将未映射到文件的内存页面放置在其中，以便它可以释放内存供其他用途使用。它通过交换文件的大小增加了物理内存的有效大小。这并非是万能药：将页面复制到交换文件和从交换文件复制页面都会产生成本，这在承载工作负载的真实内存太少的系统上变得明显，并开始*磁盘抖动*。

在嵌入式设备上很少使用交换，因为它与闪存存储不兼容，常量写入会迅速磨损。但是，您可能希望考虑交换到压缩的 RAM（zram）。

## 交换到压缩内存（zram）

zram 驱动程序创建名为`/dev/zram0`、`/dev/zram1`等的基于 RAM 的块设备。写入这些设备的页面在存储之前会被压缩。通过 30%至 50%的压缩比，您可以预期整体空闲内存增加约 10%，但会增加更多的处理和相应的功耗。它在一些低内存的 Android 设备上使用。

要启用 zram，请使用以下选项配置内核：

```
CONFIG_SWAP
CONFIG_CGROUP_MEM_RES_CTLR
CONFIG_CGROUP_MEM_RES_CTLR_SWAP
CONFIG_ZRAM
```

然后，通过将以下内容添加到`/etc/fstab`来在启动时挂载 zram：

```
/dev/zram0 none swap defaults zramsize=<size in bytes>,swapprio=<swap partition priority>
```

您可以使用以下命令打开和关闭交换：

```
# swapon /dev/zram0
# swapoff /dev/zram0
```

# 使用 mmap 映射内存

进程开始时，一定数量的内存映射到程序文件的文本（代码）和数据段，以及它链接的共享库。它可以在运行时使用`malloc(3)`在堆上分配内存，并通过局部作用域变量和通过`alloca(3)`分配的内存在堆栈上分配内存。它还可以在运行时动态加载库使用`dlopen(3)`。所有这些映射都由内核处理。但是，进程还可以使用`mmap(2)`以显式方式操纵其内存映射：

```
void *mmap(void *addr, size_t length, int prot, int flags,
  int fd, off_t offset);
```

它从具有描述符`fd`的文件中的`offset`开始映射`length`字节的内存，并在成功时返回映射的指针。由于底层硬件以页面为单位工作，`length`被舍入到最接近的整页数。保护参数`prot`是读、写和执行权限的组合，`flags`参数至少包含`MAP_SHARED`或`MAP_PRIVATE`。还有许多其他标志，这些标志在 man 页面中有描述。

mmap 有许多用途。以下是其中一些。

## 使用 mmap 分配私有内存

您可以使用 mmap 通过设置`MAP_ANONYMOUS`标志和`fd`文件描述符为`-1`来分配一个私有内存区域。这类似于使用`malloc(3)`从堆中分配内存，只是内存是按页对齐的，并且是页的倍数。内存分配在与库相同的区域。事实上，出于这个原因，一些人称该区域为 mmap 区域。

匿名映射更适合大型分配，因为它们不会用内存块固定堆，这会增加碎片化的可能性。有趣的是，您会发现`malloc(3)`（至少在 glibc 中）停止为超过 128 KiB 的请求从堆中分配内存，并以这种方式使用 mmap，因此在大多数情况下，只使用 malloc 是正确的做法。系统将选择满足请求的最佳方式。

## 使用 mmap 共享内存

正如我们在第十章中看到的，*了解进程和线程*，POSIX 共享内存需要使用 mmap 来访问内存段。在这种情况下，您设置`MAP_SHARED`标志，并使用`shm_open()`的文件描述符：

```
int shm_fd;
char *shm_p;

shm_fd = shm_open("/myshm", O_CREAT | O_RDWR, 0666);
ftruncate(shm_fd, 65536);
shm_p = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
  MAP_SHARED, shm_fd, 0);
```

## 使用 mmap 访问设备内存

正如我在第八章中提到的，*介绍设备驱动程序*，驱动程序可以允许其设备节点被 mmap，并与应用程序共享一些设备内存。确切的实现取决于驱动程序。

一个例子是 Linux 帧缓冲区，`/dev/fb0`。该接口在`/usr/include/linux/fb.h`中定义，包括一个`ioctl`函数来获取显示的大小和每像素位数。然后，您可以使用 mmap 来请求视频驱动程序与应用程序共享帧缓冲区并读写像素：

```
int f;
int fb_size;
unsigned char *fb_mem;

f = open("/dev/fb0", O_RDWR);
/* Use ioctl FBIOGET_VSCREENINFO to find the display dimensions
  and calculate fb_size */
fb_mem = mmap(0, fb_size, PROT_READ | PROT_WRITE, MAP_SHARED, f, 0);
/* read and write pixels through pointer fb_mem */
```

第二个例子是流媒体视频接口，Video 4 Linux，版本 2，或者 V4L2，它在`/usr/include/linux/videodev2.h`中定义。每个视频设备都有一个名为`/dev/videoN`的节点，从`/dev/video0`开始。有一个`ioctl`函数来请求驱动程序分配一些视频缓冲区，你可以将其映射到用户空间。然后，只需要循环缓冲区并根据播放或捕获视频流的情况填充或清空它们。

# 我的应用程序使用了多少内存？

与内核空间一样，分配、映射和共享用户空间内存的不同方式使得回答这个看似简单的问题变得相当困难。

首先，您可以询问内核认为有多少可用内存，可以使用`free`命令来执行此操作。以下是输出的典型示例：

```
             total     used     free   shared  buffers   cached
Mem:        509016   504312     4704        0    26456   363860
-/+ buffers/cache:   113996   395020
Swap:            0        0        0
```

### 提示

乍一看，这看起来像是一个几乎没有内存的系统，只有 4704 KiB 的空闲内存，占用了 509,016 KiB 的不到 1%。然而，请注意，26,456 KiB 在缓冲区中，而 363,860 KiB 在缓存中。Linux 认为空闲内存是浪费的内存，因此内核使用空闲内存用于缓冲区和缓存，因为它们在需要时可以被收缩。从测量中去除缓冲区和缓存可以得到真正的空闲内存，即 395,020 KiB；占总量的 77%。在使用 free 时，标有`-/+ buffers/cache`的第二行上的数字是重要的。

您可以通过向`/proc/sys/vm/drop_caches`写入 1 到 3 之间的数字来强制内核释放缓存：

```
# echo 3 > /proc/sys/vm/drop_caches
```

实际上，该数字是一个位掩码，用于确定您要释放的两种广义缓存中的哪一种：1 表示页面缓存，2 表示 dentry 和 inode 缓存的组合。这些缓存的确切作用在这里并不特别重要，只是内核正在使用的内存可以在短时间内被回收。

# 每个进程的内存使用

有几种度量方法可以衡量进程使用的内存量。我将从最容易获得的两种开始——**虚拟集大小**（**vss**）和**驻留内存大小**（**rss**），这两种在大多数`ps`和`top`命令的实现中都可以获得：

+   **Vss**：在`ps`命令中称为 VSZ，在`top`中称为 VIRT，是进程映射的内存总量。它是`/proc/<PID>/map`中显示的所有区域的总和。这个数字的兴趣有限，因为只有部分虚拟内存在任何时候都被分配到物理内存。

+   **Rss**：在`ps`中称为 RSS，在`top`中称为 RES，是映射到物理内存页面的内存总和。这更接近进程的实际内存预算，但是有一个问题，如果将所有进程的 Rss 相加，您将高估内存的使用，因为一些页面将是共享的。

## 使用 top 和 ps

BusyBox 的`top`和`ps`版本提供的信息非常有限。以下示例使用了`procps`包中的完整版本。

`ps`命令显示了 Vss（VSZ）和 Rss（RSS）以及包括`vsz`和`rss`的自定义格式，如下所示：

```
# ps -eo pid,tid,class,rtprio,stat,vsz,rss,comm

  PID   TID CLS RTPRIO STAT    VSZ   RSS COMMAND
    1     1 TS       - Ss     4496  2652 systemd
  ...
  205   205 TS       - Ss     4076  1296 systemd-journal
  228   228 TS       - Ss     2524  1396 udevd
  581   581 TS       - Ss     2880  1508 avahi-daemon
  584   584 TS       - Ss     2848  1512 dbus-daemon
  590   590 TS       - Ss     1332   680 acpid
  594   594 TS       - Ss     4600  1564 wpa_supplicant
```

同样，`top`显示了每个进程的空闲内存和内存使用的摘要：

```
top - 21:17:52 up 10:04,  1 user,  load average: 0.00, 0.01, 0.05
Tasks:  96 total,   1 running,  95 sleeping,   0 stopped,   0 zombie
%Cpu(s):  1.7 us,  2.2 sy,  0.0 ni, 95.9 id,  0.0 wa,  0.0 hi,  0.2 si,  0.0 st
KiB Mem:    509016 total,   278524 used,   230492 free,    25572 buffers
KiB Swap:        0 total,        0 used,        0 free,   170920 cached

PID USER      PR  NI  VIRT  RES  SHR S  %CPU %MEM    TIME+  COMMAND
1098 debian    20   0 29076  16m 8312 S   0.0  3.2   0:01.29 wicd-client
  595 root      20   0 64920 9.8m 4048 S   0.0  2.0   0:01.09 node
  866 root      20   0 28892 9152 3660 S   0.2  1.8   0:36.38 Xorg
```

这些简单的命令让您感受到内存的使用情况，并在看到进程的 Rss 不断增加时第一次表明您有内存泄漏的迹象。然而，它们在绝对内存使用的测量上并不是非常准确。

## 使用 smem

2009 年，Matt Mackall 开始研究进程内存测量中共享页面的计算问题，并添加了两个名为**唯一集大小**或**Uss**和**比例集大小**或**Pss**的新指标：

+   **Uss**：这是分配给物理内存并且对进程唯一的内存量；它不与任何其他内存共享。这是如果进程终止将被释放的内存量。

+   **Pss**：这将共享页面的计算分配给所有映射了它们的进程。例如，如果一个库代码区域有 12 页长，并且被六个进程共享，每个进程将累积两页的 Pss。因此，如果将所有进程的 Pss 数字相加，就可以得到这些进程实际使用的内存量。换句话说，Pss 就是我们一直在寻找的数字。

这些信息可以在`/proc/<PID>/smaps`中找到，其中包含了`/proc/<PID>/maps`中显示的每个映射的附加信息。以下是这样一个文件中的一个部分，它提供了有关`libc`代码段的映射的信息：

```
b6e6d000-b6f45000 r-xp 00000000 b3:02 2444 /lib/libc-2.13.so
Size:                864 kB
Rss:                 264 kB
Pss:                   6 kB
Shared_Clean:        264 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         0 kB
Referenced:          264 kB
Anonymous:             0 kB
AnonHugePages:         0 kB
Swap:                  0 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Locked:                0 kB
VmFlags: rd ex mr mw me
```

### 注意

请注意，Rss 为 264 KiB，但由于它在许多其他进程之间共享，因此 Pss 只有 6 KiB。

有一个名为 smem 的工具，它汇总了`smaps`文件中的信息，并以各种方式呈现，包括饼图或条形图。smem 的项目页面是[`www.selenic.com/smem`](https://www.selenic.com/smem)。它在大多数桌面发行版中都作为一个软件包提供。但是，由于它是用 Python 编写的，在嵌入式目标上安装它需要一个 Python 环境，这可能会给一个工具带来太多麻烦。为了解决这个问题，有一个名为`smemcap`的小程序，它可以在目标上捕获`/proc`的状态，并将其保存到一个 TAR 文件中，以便稍后在主机计算机上进行分析。它是 BusyBox 的一部分，但也可以从`smem`源代码编译而成。

以`root`身份本地运行`smem`，你会看到这些结果：

```
# smem -t
 PID User  Command                   Swap      USS     PSS     RSS
 610 0     /sbin/agetty -s ttyO0 11     0      128     149     720
1236 0     /sbin/agetty -s ttyGS0 1     0      128     149     720
 609 0     /sbin/agetty tty1 38400      0      144     163     724
 578 0     /usr/sbin/acpid              0      140     173     680
 819 0     /usr/sbin/cron               0      188     201     704
 634 103   avahi-daemon: chroot hel     0      112     205     500
 980 0     /usr/sbin/udhcpd -S /etc     0      196     205     568
  ...
 836 0     /usr/bin/X :0 -auth /var     0     7172    7746    9212
 583 0     /usr/bin/node autorun.js     0     8772    9043   10076
1089 1000  /usr/bin/python -O /usr/     0     9600   11264   16388
------------------------------------------------------------------
  53 6                                  0    65820   78251  146544
```

从输出的最后一行可以看出，在这种情况下，总的 Pss 大约是 Rss 的一半。

如果你没有或不想在目标上安装 Python，你可以再次以`root`身份使用`smemcap`来捕获状态：

```
# smemcap > smem-bbb-cap.tar
```

然后，将 TAR 文件复制到主机并使用`smem -S`读取，尽管这次不需要以`root`身份运行：

```
$ smem -t -S smem-bbb-cap.tar
```

输出与本地运行时的输出相同。

## 其他需要考虑的工具

另一种显示 Pss 的方法是通过`ps_mem`([`github.com/pixelb/ps_mem`](https://github.com/pixelb/ps_mem))，它以更简单的格式打印几乎相同的信息。它也是用 Python 编写的。

Android 也有一个名为`procrank`的工具，可以通过少量更改在嵌入式 Linux 上进行交叉编译。你可以从[`github.com/csimmonds/procrank_linux`](https://github.com/csimmonds/procrank_linux)获取代码。

# 识别内存泄漏

内存泄漏发生在分配内存后不释放它，当它不再需要时。内存泄漏并不是嵌入式系统特有的问题，但它成为一个问题的部分原因是目标本来就没有太多内存，另一部分原因是它们经常长时间运行而不重启，导致泄漏变成了一个大问题。

当你运行`free`或`top`并看到可用内存不断减少时，即使你清除缓存，你会意识到有一个泄漏，如前面的部分所示。你可以通过查看每个进程的 Uss 和 Rss 来确定罪魁祸首（或罪魁祸首）。

有几种工具可以识别程序中的内存泄漏。我将看两种：`mtrace`和`Valgrind`。

## mtrace

`mtrace`是 glibc 的一个组件，它跟踪对`malloc(3)`、`free(3)`和相关函数的调用，并在程序退出时识别未释放的内存区域。你需要在程序内部调用`mtrace()`函数开始跟踪，然后在运行时，将路径名写入`MALLOC_TRACE`环境变量，以便写入跟踪信息的文件。如果`MALLOC_TRACE`不存在或文件无法打开，`mtrace`钩子将不会安装。虽然跟踪信息是以 ASCII 形式写入的，但通常使用`mtrace`命令来查看它。

这是一个例子：

```
#include <mcheck.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
  int j;
  mtrace();
  for (j = 0; j < 2; j++)
    malloc(100);  /* Never freed:a memory leak */
  calloc(16, 16);  /* Never freed:a memory leak */
  exit(EXIT_SUCCESS);
}
```

当运行程序并查看跟踪时，你可能会看到以下内容：

```
$ export MALLOC_TRACE=mtrace.log
$ ./mtrace-example
$ mtrace mtrace-example mtrace.log

Memory not freed:
-----------------
           Address     Size     Caller
0x0000000001479460     0x64  at /home/chris/mtrace-example.c:11
0x00000000014794d0     0x64  at /home/chris/mtrace-example.c:11
0x0000000001479540    0x100  at /home/chris/mtrace-example.c:15
```

不幸的是，`mtrace`在程序运行时不能告诉你有关泄漏内存的信息。它必须先终止。

## Valgrind

Valgrind 是一个非常强大的工具，可以发现内存问题，包括泄漏和其他问题。一个优点是你不必重新编译要检查的程序和库，尽管如果它们已经使用`-g`选项编译，以便包含调试符号表，它的工作效果会更好。它通过在模拟环境中运行程序并在各个点捕获执行来工作。这导致 Valgrind 的一个很大的缺点，即程序以正常速度的一小部分运行，这使得它对测试任何具有实时约束的东西不太有用。

### 注意

顺便说一句，这个名字经常被错误发音：Valgrind 的 FAQ 中说*grind*的发音是短的*i*--就像*grinned*（押韵*tinned*）而不是*grined*（押韵*find*）。FAQ、文档和下载都可以在[`valgrind.org`](http://valgrind.org)找到。

Valgrind 包含几个诊断工具：

+   **memcheck**：这是默认工具，用于检测内存泄漏和内存的一般误用

+   **cachegrind**：这个工具计算处理器缓存命中率

+   **callgrind**：这个工具计算每个函数调用的成本

+   **helgrind**：这个工具用于突出显示 Pthread API 的误用、潜在死锁和竞争条件

+   **DRD**：这是另一个 Pthread 分析工具

+   **massif**：这个工具用于分析堆和栈的使用情况

您可以使用`-tool`选项选择您想要的工具。Valgrind 可以在主要的嵌入式平台上运行：ARM（Cortex A）、PPC、MIPS 和 32 位和 64 位的 x86。它在 Yocto Project 和 Buildroot 中都作为一个软件包提供。

要找到我们的内存泄漏，我们需要使用默认的`memcheck`工具，并使用选项`--leakcheck=full`来打印出发现泄漏的行：

```
$ valgrind --leak-check=full ./mtrace-example
==17235== Memcheck, a memory error detector
==17235== Copyright (C) 2002-2013, and GNU GPL'd, by Julian Seward et al.
==17235== Using Valgrind-3.10.0.SVN and LibVEX; rerun with -h for copyright info
==17235== Command: ./mtrace-example
==17235==
==17235==
==17235== HEAP SUMMARY:
==17235==  in use at exit: 456 bytes in 3 blocks
==17235==  total heap usage: 3 allocs, 0 frees, 456 bytes allocated
==17235==
==17235== 200 bytes in 2 blocks are definitely lost in loss record 1 of 2
==17235==    at 0x4C2AB80: malloc (in /usr/lib/valgrind/vgpreload_memcheck-linux.so)
==17235==    by 0x4005FA: main (mtrace-example.c:12)
==17235==
==17235== 256 bytes in 1 blocks are definitely lost in loss record 2 of 2
==17235==    at 0x4C2CC70: calloc (in /usr/lib/valgrind/vgpreload_memcheck-linux.so)
==17235==    by 0x400613: main (mtrace-example.c:14)
==17235==
==17235== LEAK SUMMARY:
==17235==    definitely lost: 456 bytes in 3 blocks
==17235==    indirectly lost: 0 bytes in 0 blocks
==17235==      possibly lost: 0 bytes in 0 blocks
==17235==    still reachable: 0 bytes in 0 blocks
==17235==         suppressed: 0 bytes in 0 blocks
==17235==
==17235== For counts of detected and suppressed errors, rerun with: -v
==17235== ERROR SUMMARY: 2 errors from 2 contexts (suppressed: 0 from 0)
```

# 内存不足

标准的内存分配策略是**过度承诺**，这意味着内核将允许应用程序分配比物理内存更多的内存。大多数情况下，这很好用，因为应用程序通常会请求比实际需要的更多的内存。它还有助于`fork(2)`的实现：可以安全地复制一个大型程序，因为内存页面是带有`copy-on-write`标志的共享的。在大多数情况下，`fork`后会调用`exec`函数，这样就会取消内存共享，然后加载一个新程序。

然而，总有可能某个特定的工作负载会导致一组进程同时尝试兑现它们被承诺的分配，因此需求超过了实际存在的内存。这是一种**内存不足**的情况，或者**OOM**。在这一点上，除了杀死进程直到问题消失之外别无选择。这是内存不足杀手的工作。

在我们讨论这些之前，有一个内核分配的调整参数在`/proc/sys/vm/overcommit_memory`中，你可以将其设置为：

+   `0`：启发式过度承诺（这是默认设置）

+   `1`：始终过度承诺，永不检查

+   `2`：始终检查，永不过度承诺

选项 1 只有在运行与大型稀疏数组一起工作并分配大量内存但只写入其中一小部分的程序时才真正有用。在嵌入式系统的环境中，这样的程序很少见。

选项 2，永不过度承诺，似乎是一个不错的选择，如果您担心内存不足，也许是在任务或安全关键的应用中。它将失败于大于承诺限制的分配，这个限制是交换空间的大小加上总内存乘以过度承诺比率。过度承诺比率由`/proc/sys/vm/overcommit_ratio`控制，默认值为 50%。

例如，假设您有一台设备，配备了 512MB 的系统 RAM，并设置了一个非常保守的比率为 25%：

```
# echo 25 > /proc/sys/vm/overcommit_ratio
# grep -e MemTotal -e CommitLimit /proc/meminfo
MemTotal:         509016 kB
CommitLimit:      127252 kB
```

没有交换空间，因此承诺限制是`MemTotal`的 25%，这是预期的。

`/proc/meminfo`中还有另一个重要的变量：`Committed_AS`。这是迄今为止需要满足所有分配的总内存量。我在一个系统上找到了以下内容：

```
# grep -e MemTotal -e Committed_AS /proc/meminfo
MemTotal:         509016 kB
Committed_AS:     741364 kB
```

换句话说，内核已经承诺了比可用内存更多的内存。因此，将`overcommit_memory`设置为`2`意味着所有分配都会失败，而不管`overcommit_ratio`如何。要使系统正常工作，我要么必须安装双倍的 RAM，要么严重减少正在运行的进程数量，大约有 40 个。

在所有情况下，最终的防御是 OOM killer。它使用一种启发式方法为每个进程计算 0 到 1000 之间的糟糕分数，然后终止具有最高分数的进程，直到有足够的空闲内存。您应该在内核日志中看到类似于这样的内容：

```
[44510.490320] eatmem invoked oom-killer: gfp_mask=0x200da, order=0, oom_score_adj=0
...
```

您可以使用`echo f > /proc/sysrq-trigger`来强制发生 OOM 事件。

您可以通过将调整值写入`/proc/<PID>/oom_score_adj`来影响进程的糟糕分数。值为`-1000`意味着糟糕分数永远不会大于零，因此永远不会被杀死；值为`+1000`意味着它将始终大于 1000，因此将始终被杀死。

# 进一步阅读

以下资源提供了有关本章介绍的主题的进一步信息：

+   *Linux 内核开发，第 3 版*，作者*Robert Love*，*Addison Wesley*，*O'Reilly Media*; (2010 年 6 月) ISBN-10: 0672329468

+   *Linux 系统编程，第 2 版*，作者*Robert Love*，*O'Reilly Media*; (2013 年 6 月 8 日) ISBN-10: 1449339530

+   *了解 Linux VM 管理器*，作者*Mel Gorman*：[`www.kernel.org/doc/gorman/pdf/understand.pdf`](https://www.kernel.org/doc/gorman/pdf/understand.pdf)

+   *Valgrind 3.3 - Gnu/Linux 应用程序的高级调试和性能分析*，作者*J Seward*，*N. Nethercote*和*J. Weidendorfer*，*Network Theory Ltd*; (2008 年 3 月 1 日) ISBN 978-0954612054

# 摘要

在虚拟内存系统中考虑每个内存使用的字节是不可能的。但是，您可以使用`free`命令找到一个相当准确的总空闲内存量，不包括缓冲区和缓存所占用的内存。通过在一段时间内监视它，并使用不同的工作负载，您应该对它将保持在给定限制内感到自信。

当您想要调整内存使用情况或识别意外分配的来源时，有一些资源可以提供更详细的信息。对于内核空间，最有用的信息在于`/proc: meminfo`，`slabinfo`和`vmallocinfo`。

在获取用户空间的准确测量方面，最佳指标是 Pss，如`smem`和其他工具所示。对于内存调试，您可以从诸如`mtrace`之类的简单跟踪器获得帮助，或者您可以选择使用 Valgrind memcheck 工具这样的重量级选项。

如果您担心内存不足的后果，您可以通过`/proc/sys/vm/overcommit_memory`微调分配机制，并且可以通过`oom_score_adj`参数控制特定进程被杀死的可能性。

下一章将全面介绍如何使用 GNU 调试器调试用户空间和内核代码，以及您可以从观察代码运行中获得的见解，包括我在这里描述的内存管理函数。


# 第十二章：使用 GDB 进行调试

错误是难免的。识别和修复它们是开发过程的一部分。有许多不同的技术用于查找和表征程序缺陷，包括静态和动态分析，代码审查，跟踪，性能分析和交互式调试。我将在下一章中介绍跟踪器和性能分析器，但在这里，我想集中讨论通过调试器观察代码执行的传统方法，也就是我们的情况下的 GNU 调试器 GDB。GDB 是一个强大而灵活的工具。您可以使用它来调试应用程序，检查程序崩溃后生成的后期文件（`core`文件），甚至逐步执行内核代码。

在本章中，我将向您展示如何使用 GDB 调试应用程序，如何查看核心文件以及如何调试内核代码，重点是与嵌入式 Linux 相关的方面。

# GNU 调试器

GDB 是用于编译语言的源级调试器，主要用于 C 和 C++，尽管也支持各种其他语言，如 Go 和 Objective。您应该阅读您正在使用的 GDB 版本的说明，以了解对各种语言的支持的当前状态。项目网站是[`www.gnu.org/software/gdb`](http://www.gnu.org/software/gdb)，其中包含了许多有用的信息，包括 GDB 手册。

GDB 默认具有命令行用户界面，有些人可能会觉得这个界面令人望而却步，但实际上，只要稍加练习，就会发现它很容易使用。如果您不喜欢命令行界面，那么有很多 GDB 的前端用户界面可供选择，我稍后会描述其中的三个。

# 准备调试

您需要使用调试符号编译要调试的代码。GCC 提供了两个选项：`-g`和`-ggdb`。后者添加了特定于 GDB 的调试信息，而前者生成了适合您使用的目标操作系统的适当格式的信息，使其更具可移植性。在我们的特定情况下，目标操作系统始终是 Linux，无论您使用`-g`还是`-ggdb`都没有太大区别。更有趣的是，这两个选项都允许您指定调试信息的级别，从 0 到 3：

+   0：这根本不生成调试信息，等同于省略`-g`或`-ggdb`开关

+   1：这产生的信息很少，但包括函数名称和外部变量，足以生成回溯

+   2：这是默认设置，包括有关局部变量和行号的信息，以便您可以进行源级调试并逐步执行代码

+   3：这包括额外的信息，其中包括 GDB 正确处理宏扩展

在大多数情况下，`-g`足够了，但如果您在通过代码时遇到问题，特别是如果它包含宏，那么请保留`-g3`或`-ggdb3`。

要考虑的下一个问题是代码优化级别。编译器优化往往会破坏源代码和机器代码之间的关系，这使得通过源代码进行步进变得不可预测。如果您遇到这样的问题，您很可能需要在不进行优化的情况下进行编译，省略`-O`编译开关，或者至少将其降低到级别 1，使用编译开关`-O1`。

一个相关的问题是堆栈帧指针，GDB 需要它们来生成当前函数调用的回溯。在某些架构上，GCC 不会在更高级别的优化（`-O2`）中生成堆栈帧指针。如果您发现自己确实需要使用`-O2`进行编译，但仍然希望进行回溯，您可以使用`-fno-omit-frame-pointer`来覆盖默认行为。还要注意一下手动优化的代码，通过添加`-fomit-frame-pointer`来省略帧指针：您可能需要暂时将它们移除。

# 使用 GDB 调试应用程序

您可以使用 GDB 以两种方式调试应用程序。如果您正在开发要在台式机和服务器上运行的代码，或者在任何编译和运行代码在同一台机器上的环境中运行代码，那么自然会本地运行 GDB。然而，大多数嵌入式开发都是使用交叉工具链进行的，因此您希望调试在设备上运行的代码，但是要从具有源代码和工具的交叉开发环境中控制它。我将专注于后一种情况，因为它没有得到很好的记录，但它是嵌入式开发人员最有可能遇到的情况。我不打算在这里描述使用 GDB 的基础知识，因为已经有许多关于该主题的良好参考资料，包括 GDB 手册和本章末尾建议的进一步阅读。

我将从一些关于使用 gdbserver 的细节开始，然后向您展示如何配置 Yocto 项目和 Buildroot 进行远程调试。

# 使用 gdbserver 进行远程调试

远程调试的关键组件是调试代理 gdbserver，它在目标上运行并控制正在调试的程序的执行。Gdbserver 通过网络连接或 RS-232 串行接口连接到在主机上运行的 GDB 的副本。

通过 gdbserver 进行调试几乎与本地调试相同，但并非完全相同。区别主要集中在涉及两台计算机并且它们必须处于正确状态以进行调试。以下是一些需要注意的事项：

+   在调试会话开始时，您需要使用 gdbserver 在目标上加载要调试的程序，然后在主机上使用交叉工具链中的 GDB 单独加载 GDB。

+   GDB 和 gdbserver 需要在调试会话开始之前相互连接。

+   在主机上运行的 GDB 需要告诉它在哪里查找调试符号和源代码，特别是对于共享库。

+   GDB 的`run`命令无法按预期工作。

+   gdbserver 在调试会话结束时将终止，如果您想要另一个调试会话，您需要重新启动它。

+   您需要在主机上为要调试的二进制文件获取调试符号和源代码，但不一定需要在目标上。通常目标上没有足够的存储空间，因此在部署到目标之前需要对它们进行剥离。

+   GDB/gdbserver 组合不具有本地运行的 GDB 的所有功能：例如，gdbserver 无法在`fork()`后跟随子进程，而本地 GDB 可以。

+   如果 GDB 和 gdbserver 是不同版本或者是相同版本但配置不同，可能会发生一些奇怪的事情。理想情况下，它们应该使用您喜欢的构建工具从相同的源构建。

调试符号会显著增加可执行文件的大小，有时会增加 10 倍。如第五章中所述，*构建根文件系统*，可以在不重新编译所有内容的情况下删除调试符号。这项工作的工具是您交叉工具链中的 strip。您可以使用以下开关来控制 strip 的侵略性：

+   `--strip-all`：（默认）删除所有符号

+   `--strip-unneeded`：删除不需要进行重定位处理的符号

+   `--strip-debug`：仅删除调试符号

### 提示

对于应用程序和共享库，`--strip-all`（默认）是可以的，但是对于内核模块，您会发现它会阻止模块加载。改用`--strip-unneeded`。我仍在研究`–strip-debug`的用例。

考虑到这一点，让我们看看在 Yocto 项目和 Buildroot 中进行调试涉及的具体内容。

## 设置 Yocto 项目

Yocto 项目在 SDK 的一部分中为主机构建了交叉 GDB，但是您需要对目标配置进行更改以在目标映像中包含 gdbserver。您可以显式添加该软件包，例如通过将以下内容添加到`conf/local.conf`，再次注意这个字符串的开头必须有一个空格：

```
IMAGE_INSTALL_append = " gdbserver"
```

或者，您可以将`tools-debug`添加到`EXTRA_IMAGE_FEATURES`中，这将同时将 gdbserver 和 strace 添加到目标映像中（我将在下一章中讨论`strace`）：

```
EXTRA_IMAGE_FEATURES = "debug-tweaks tools-debug"
```

## 设置 Buildroot

使用 Buildroot，您需要同时启用选项来为主机构建交叉 GDB（假设您正在使用 Buildroot 内部工具链），并为目标构建 gdbserver。具体来说，您需要启用：

+   `BR2_PACKAGE_HOST_GDB`，在菜单**工具链** | **为主机构建交叉 gdb**

+   `BR2_PACKAGE_GDB`，在菜单**目标软件包** | **调试、性能分析和基准测试** | **gdb**

+   `BR2_PACKAGE_GDB_SERVER`，在菜单**目标软件包** | **调试、性能分析和基准测试** | **gdbserver**

# 开始调试

现在，您在目标上安装了 gdbserver，并且在主机上安装了交叉 GDB，您可以开始调试会话了。

## 连接 GDB 和 gdbserver

GDB 和 gdbserver 之间的连接可以通过网络或串行接口进行。在网络连接的情况下，您可以使用 TCP 端口号启动 gdbserver 进行监听，并且可以选择接受连接的 IP 地址。在大多数情况下，您不需要关心将连接到哪个 IP 地址，因此只需提供端口号即可。在此示例中，gdbserver 等待来自任何主机的端口`10000`的连接：

```
# gdbserver :10000 ./hello-world
Process hello-world created; pid = 103
Listening on port 10000

```

接下来，从您的工具链启动 GDB，将相同的程序作为参数传递，以便 GDB 可以加载符号表：

```
$ arm-poky-linux-gnueabi-gdb hello-world

```

在 GDB 中，您使用`target remote`命令进行连接，指定目标的 IP 地址或主机名以及它正在等待的端口：

```
(gdb) target remote 192.168.1.101:10000

```

当 gdbserver 看到来自主机的连接时，它会打印以下内容：

```
Remote debugging from host 192.168.1.1

```

串行连接的过程类似。在目标上，您告诉 gdbserver 要使用哪个串行端口：

```
# gdbserver /dev/ttyO0 ./hello-world

```

您可能需要使用`stty`或类似的程序预先配置端口波特率。一个简单的示例如下：

```
# stty -F /dev/ttyO1 115200

```

`stty`还有许多其他选项，请阅读手册以获取更多详细信息。值得注意的是，该端口不能用于其他用途，例如，您不能使用作为系统控制台使用的端口。在主机上，您可以使用`target remote`加上电缆末端的串行设备来连接到 gdbserver。在大多数情况下，您将希望使用 GDB 命令`set remotebaud`设置主机串行端口的波特率：

```
(gdb) set remotebaud 115200
(gdb) target remote /dev/ttyUSB0

```

## 设置 sysroot

GDB 需要知道共享库的调试符号和源代码的位置。在本地调试时，路径是众所周知的，并内置到 GDB 中，但是在使用交叉工具链时，GDB 无法猜测目标文件系统的根目录在哪里。您可以通过设置 sysroot 来实现。Yocto 项目和 Buildroot 处理库符号的方式不同，因此 sysroot 的位置也大不相同。

Yocto 项目在目标文件系统映像中包含调试信息，因此您需要解压在`build/tmp/deploy/images`中生成的目标映像 tar 文件，例如：

```
$ mkdir ~/rootfs
$ cd ~/rootfs
$ sudo tar xf ~/poky/build/tmp/deploy/images/beaglebone/core-image-minimal-beaglebone.tar.bz2Then you can point sysroot to the root of the unpacked files:
(gdb) set sysroot /home/chris/MELP/rootfs

```

Buildroot 根据`BR2_ENABLE_DEBUG`编译具有最小或完整调试符号的库，将它们放入分段目录，然后在将它们复制到目标映像时剥离它们。因此，对于 Buildroot 来说，sysroot 始终是分段区域，而不管根文件系统从何处提取。

## GDB 命令文件

每次运行 GDB 时，您需要做一些事情，例如设置 sysroot。将这些命令放入命令文件中，并在每次启动 GDB 时运行它们非常方便。GDB 从`$HOME/.gdbinit`读取命令，然后从当前目录中的`.gdbinit`读取命令，然后从使用`-x`参数在命令行上指定的文件中读取命令。然而，出于安全原因，最近的 GDB 版本将拒绝从当前目录加载`.gdbinit`。您可以通过向`$HOME/.gdbinit`添加以下行来覆盖该行为，以便为单个目录禁用检查：

```
add-auto-load-safe-path /home/chris/myprog/.gdbinit

```

您还可以通过添加以下内容全局禁用检查：

```
set auto-load safe-path /

```

我个人偏好使用`-x`参数指向命令文件，这样可以暴露文件的位置，以免忘记它。

为了帮助您设置 GDB，Buildroot 创建一个包含正确 sysroot 命令的 GDB 命令文件，位于`output/staging/usr/share/buildroot/gdbinit`中。它将包含类似于这样的命令：

```
set sysroot /home/chris/buildroot/output/host/usr/arm-buildroot-linux-gnueabi/sysroot

```

## GDB 命令概述

GDB 有很多命令，这些命令在在线手册和*进一步阅读*部分提到的资源中有描述。为了帮助您尽快上手，这里列出了最常用的命令。在大多数情况下，命令都有一个缩写形式，该缩写形式在完整命令下面列出。

### 断点

以下表格显示了断点的命令：

| 命令 | 用途 |
| --- | --- |
| `break <location>``b <location>` | 在函数名、行号或行上设置断点。例如："main"、"5"和"sortbug.c:42" |
| `info break``i b` | 列出断点 |
| `delete break <N>``d b <N>` | 删除断点`N` |

### 运行和步进

以下表格显示了运行和步进的命令：

| 命令 | 用途 |
| --- | --- |
| `run``r` | 将程序的新副本加载到内存中并开始运行。这对使用 gdbserver 进行远程调试是无效的 |
| `continue`c | 从断点继续执行 |
| `Ctrl-C` | 停止正在调试的程序 |
| `step``s` | 执行一行代码，进入调用的任何函数 |
| `next``n` | 执行一行代码，跳过函数调用 |
| `finish` | 运行直到当前函数返回 |

### 信息命令

以下表格显示了获取信息的命令：

| 命令 | 用途 |
| --- | --- |
| `backtrace``bt` | 列出调用堆栈 |
| `info threads` | 从断点继续执行 |
| `Info libs` | 停止程序 |
| `print <variable>``p <variable>` | 打印变量的值，例如`print foo` |
| `list` | 列出当前程序计数器周围的代码行 |

## 运行到断点

Gdbserver 将程序加载到内存中，并在第一条指令处设置断点，然后等待来自 GDB 的连接。当连接建立时，您将进入调试会话。但是，您会发现如果立即尝试单步执行，您将收到此消息：

```
Cannot find bounds of current function

```

这是因为程序在汇编语言中编写的代码中停止了，该代码为 C 和 C++程序创建了运行时环境。C 或 C++代码的第一行是`main()`函数。假设您想在`main()`处停止，您可以在那里设置断点，然后使用`continue`命令（缩写为`c`）告诉 gdbserver 从程序开始处的断点继续执行并停在 main 处：

```
(gdb) break main
Breakpoint 1, main (argc=1, argv=0xbefffe24) at helloworld.c:8
8 printf("Hello, world!\n");

```

如果此时您看到以下内容：

```
warning: Could not load shared library symbols for 2 libraries, e.g. /lib/libc.so.6.

```

这意味着您忘记了设置 sysroot！

这与本地启动程序非常不同，您只需键入`run`。实际上，如果您在远程调试会话中尝试键入`run`，您要么会看到一条消息，说明远程目标不支持`run`，要么在较旧版本的 GDB 中，它将在没有任何解释的情况下挂起。

# 调试共享库

要调试由构建工具构建的库，您需要对构建配置进行一些更改。对于在构建环境之外构建的库，您需要做一些额外的工作。

## Yocto 项目

Yocto 项目构建二进制包的调试变体，并将它们放入`build/tmp/deploy/<package manager>/<target architecture>`中。以下是此示例的调试包，这里是 C 库的示例：

```
build/tmp/deploy/rpm/armv5e/libc6-dbg-2.21-r0.armv5e.rpm

```

您可以通过将`<package name-dbg>`添加到目标配方来有选择地将这些调试包添加到目标映像中。对于`glibc`，该包的名称为`glibc-dbg`。或者，您可以简单地告诉 Yocto 项目通过将`dbg-pkgs`添加到`EXTRA_IMAGE_FEATURES`来安装所有调试包。请注意，这将大大增加目标映像的大小，可能会增加数百兆字节。

Yocto 项目将调试符号放在名为`.debug`的隐藏目录中，分别位于`lib`和`usr/lib`目录中。GDB 知道在 sysroot 中的这些位置查找符号信息。

调试软件包还包含安装在目标镜像中的源代码副本，位于目录`usr/src/debug/<package name>`中，这也是尺寸增加的原因之一。您可以通过向您的配方添加以下内容来阻止它发生：

```
PACKAGE_DEBUG_SPLIT_STYLE = "debug-without-src"

```

不过，请记住，当您使用 gdbserver 进行远程调试时，您只需要在主机上具有调试符号和源代码，而不需要在目标上具有。没有什么能阻止您从已安装在目标上的镜像的副本中删除`lib/.debug`、`usr/lib/.debug`和`usr/src`目录。

## Buildroot

Buildroot 通常是直截了当的。您只需要重新构建带有行级调试符号的软件包，为此您需要启用以下内容：

+   在菜单**构建选项** | **使用调试符号构建软件包**

这将在`output/host/usr/<arch>/sysroot`中创建带有调试符号的库，但目标镜像中的副本仍然被剥离。如果您需要在目标上使用调试符号，也许是为了本地运行 GDB，您可以通过将**构建选项** | **目标上的二进制文件剥离命令**设置为`none`来禁用剥离。

## 其他库

除了使用调试符号进行构建之外，您还需要告诉 GDB 在哪里找到源代码。GDB 有一个用于源文件的搜索路径，您可以使用`show directories`命令查看：

```
(gdb) show directories
Source directories searched: $cdir:$cwd

```

这些是默认搜索路径：`$cdir`是编译目录，即源代码编译的目录；`$cwd`是 GDB 的当前工作目录。

通常这些就足够了，但如果源代码已经移动，您将需要使用如下所示的 directory 命令：

```
(gdb) dir /home/chris/MELP/src/lib_mylib
Source directories searched: /home/chris/MELP/src/lib_mylib:$cdir:$cwd

```

# 即时调试

有时，程序在运行一段时间后会开始表现异常，您可能想知道它在做什么。GDB 的`attach`功能正是这样。我称它为即时调试。它在本地和远程调试会话中都可用。

在远程调试的情况下，您需要找到要调试的进程的 PID，并使用`--attach`选项将其传递给 gdbserver。例如，如果 PID 为 109，您将输入：

```
# gdbserver --attach :10000 109
Attached; pid = 109
Listening on port 10000

```

这将强制进程停止，就像它处于断点处一样，这样您就可以以正常方式启动交叉 GDB，并连接到 gdbserver。

完成后，您可以分离，允许程序在没有调试器的情况下继续运行：

```
(gdb) detach
Detaching from program: /home/chris/MELP/helloworld/helloworld, process 109
Ending remote debugging.

```

# 调试分支和线程

当您调试的程序进行分支时会发生什么？调试会跟随父进程还是子进程？这种行为由`follow-fork-mode`控制，可能是`parent`或`child`，默认为 parent。不幸的是，当前版本的 gdbserver 不支持此选项，因此它仅适用于本地调试。如果您确实需要在使用 gdbserver 时调试子进程，一种解决方法是修改代码，使得子进程在分支后立即循环一个变量，这样您就有机会附加一个新的 gdbserver 会话，并设置变量以使其退出循环。

当多线程进程中的线程命中断点时，默认行为是所有线程都会停止。在大多数情况下，这是最好的做法，因为它允许您查看静态变量，而不会被其他线程更改。当您恢复线程的执行时，所有已停止的线程都会启动，即使您是单步执行，尤其是最后一种情况可能会导致问题。有一种方法可以修改 GDB 处理已停止线程的方式，通过称为`scheduler-locking`的参数。通常它是`off`，但如果将其设置为`on`，则只有在断点处停止的线程会恢复，其他线程将保持停止状态，这样您就有机会查看线程在没有干扰的情况下的操作。直到您关闭`scheduler-locking`为止，这种情况将继续存在。Gdbserver 支持此功能。

# 核心文件

核心文件捕获了程序在终止时的状态。当错误发生时，您甚至不必在调试器旁边。因此，当您看到`Segmentation fault (core dumped)`时，请不要耸肩；调查核心文件并提取其中的信息宝库。

首先要注意的是，默认情况下不会创建核心文件，而只有在进程的核心文件资源限制为非零时才会创建。您可以使用`ulimit -c`更改当前 shell 的限制。要删除核心文件大小的所有限制，请键入以下内容：

```
$ ulimit -c unlimited

```

默认情况下，核心文件命名为`core`，并放置在进程的当前工作目录中，该目录由`/proc/<PID>/cwd`指向。这种方案存在一些问题。首先，在查看具有多个名为`core`的文件的设备时，不明显知道每个文件是由哪个程序生成的。其次，进程的当前工作目录很可能位于只读文件系统中，或者可能没有足够的空间来存储`core`文件，或者进程可能没有权限写入当前工作目录。

有两个文件控制着`core`文件的命名和放置。第一个是`/proc/sys/kernel/core_uses_pid`。向其写入`1`会导致将正在死亡的进程的 PID 号附加到文件名中，只要您可以从日志文件中将 PID 号与程序名称关联起来，这就有些有用。

更有用的是`/proc/sys/kernel/core_pattern`，它可以让您对`core`文件有更多的控制。默认模式是`core`，但您可以将其更改为由这些元字符组成的模式：

+   `％p`：PID

+   `％u`：转储进程的真实 UID

+   `％g`：转储进程的真实 GID

+   `％s`：导致转储的信号编号

+   `％t`：转储时间，表示自 1970-01-01 00:00:00 +0000（UTC）以来的秒数。

+   `％h`：主机名

+   `％e`：可执行文件名

+   `％E`：可执行文件的路径名，斜杠（`/`）替换为感叹号（`!`）

+   `％c`：转储进程的核心文件大小软资源限制

您还可以使用以绝对目录名开头的模式，以便将所有`core`文件收集到一个地方。例如，以下模式将所有核心文件放入`/corefiles`目录，并使用程序名称和崩溃时间命名它们：

```
# echo /corefiles/core.%e.%t > /proc/sys/kernel/core_pattern

```

核心转储后，您会发现类似以下内容：

```
$ ls /corefiles/
core.sort-debug.1431425613

```

有关更多信息，请参阅 man 页面*core(5)*。

对于核心文件的更复杂处理，您可以将它们传输到进行一些后处理的程序。核心模式以管道符号`|`开头，后跟程序名称和参数。例如，我的 Ubuntu 14.04 有这个核心模式：

```
|/usr/share/apport/apport %p %s %c %P

```

Apport 是 Canonical 使用的崩溃报告工具。这种方式运行的崩溃报告工具在进程仍在内存中运行时运行，并且内核将核心镜像数据传递给它的标准输入。因此，该程序可以处理图像，可能会剥离其中的部分以减小文件系统中的大小，或者仅在核心转储时扫描它以获取特定信息。该程序可以查看各种系统数据，例如，读取程序的`/proc`文件系统条目，并且可以使用 ptrace 系统调用来操作程序并从中读取数据。但是，一旦核心镜像数据从标准输入中读取，内核就会进行各种清理，使有关该进程的信息不再可用。

## 使用 GDB 查看核心文件

以下是查看核心文件的 GDB 会话示例：

```
$ arm-poky-linux-gnueabi-gdb sort-debug /home/chris/MELP/rootdirs/rootfs/corefiles/core.sort-debug.1431425613
[...]
Core was generated by `./sort-debug'.
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0x000085c8 in addtree (p=0x0, w=0xbeac4c60 "the") at sort-debug.c:41
41     p->word = strdup (w);

```

这显示程序在第 43 行停止。`list`命令显示附近的代码：

```
(gdb) list
37    static struct tnode *addtree (struct tnode *p, char *w)
38    {
39        int cond;
40
41        p->word = strdup (w);
42        p->count = 1;
43        p->left = NULL;
44        p->right = NULL;
45

```

`backtrace`命令（缩写为`bt`）显示了我们到达这一点的路径：

```
(gdb) bt
#0  0x000085c8 in addtree (p=0x0, w=0xbeac4c60 "the") at sort-debug.c:41
#1  0x00008798 in main (argc=1, argv=0xbeac4e24) at sort-debug.c:89

```

一个明显的错误：`addtree()`被空指针调用。

# GDB 用户界面

GDB 是通过 GDB 机器接口 GDB/MI 进行低级控制的，该接口用于将 GDB 包装在用户界面中或作为更大程序的一部分，并且大大扩展了可用的选项范围。

我只提到了那些在嵌入式开发中有用的功能。

## 终端用户界面

**终端用户界面**（**TUI**）是标准 GDB 软件包的可选部分。其主要特点是代码窗口，显示即将执行的代码行以及任何断点。它绝对改进了命令行模式 GDB 中的`list`命令。

TUI 的吸引力在于它只需要工作，不需要任何额外的设置，并且由于它是文本模式，因此在运行`gdb`时可以通过 ssh 终端会话在目标上使用。大多数交叉工具链都使用 TUI 配置 GDB。只需在命令行中添加`-tui`，您将看到以下内容：

![终端用户界面](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_12_01.jpg)

## 数据显示调试器

**数据显示调试器**（**DDD**）是一个简单的独立程序，可以让您以最小的麻烦获得 GDB 的图形用户界面，尽管 UI 控件看起来有些过时，但它确实做到了必要的一切。

`--debugger`选项告诉 DDD 使用您的工具链中的 GDB，并且您可以使用 GDB 命令文件的`-x`参数：

```
$ ddd --debugger arm-poky-linux-gnueabi-gdb -x gdbinit sort-debug

```

以下屏幕截图展示了其中一个最好的功能：数据窗口，其中包含以您希望的方式重新排列的项目。如果双击指针，它会展开为一个新的数据项，并且链接会显示为箭头：

![数据显示调试器](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_12_02.jpg)

## Eclipse

Eclipse，配备了**C 开发工具包**（**CDT**）插件，支持使用 GDB 进行调试，包括远程调试。如果您在 Eclipse 中进行所有的代码开发，这是显而易见的工具，但是，如果您不是经常使用 Eclipse，那么可能不值得为了这个任务而设置它。我需要整整一章的篇幅来充分解释如何配置 CDT 以使用交叉工具链并连接到远程设备，因此我将在本章末尾的参考资料中为您提供更多信息。接下来的屏幕截图显示了 CDT 的调试视图。在右上窗口中，您可以看到进程中每个线程的堆栈帧，右上方是显示变量的监视窗口。中间是代码窗口，显示了调试器停止程序的代码行。

![Eclipse](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-emb-linux-prog/img/B03982_12_03.jpg)

# 调试内核代码

调试应用程序代码有助于了解代码的工作方式以及在代码发生故障时发生了什么，并且您可以对内核进行相同的操作，但有一些限制。

您可以使用`kgdb`进行源级调试，类似于使用`gdbserver`进行远程调试。还有一个自托管的内核调试器`kdb`，对于轻量级任务非常方便，例如查看指令是否执行并获取回溯以找出它是如何到达那里的。最后，还有内核 oops 消息和紧急情况，它们告诉您有关内核异常原因的很多信息。

## 使用 kgdb 调试内核代码

在使用源代码调试器查看内核代码时，您必须记住内核是一个复杂的系统，具有实时行为。不要期望调试像应用程序一样容易。逐步执行更改内存映射或切换上下文的代码可能会产生奇怪的结果。

`kgdb`是多年来一直是 Linux 主线的内核 GDB 存根的名称。内核 DocBook 中有用户手册，您可以在[`www.kernel.org/doc/htmldocs/kgdb/index.html`](https://www.kernel.org/doc/htmldocs/kgdb/index.html)找到在线版本。

连接到 kgdb 的广泛支持方式是通过串行接口，通常与串行控制台共享，因此此实现称为`kgdboc`，意思是控制台上的 kgdb。为了工作，它需要支持 I/O 轮询而不是中断的平台 tty 驱动程序，因为 kgdb 在与 GDB 通信时必须禁用中断。一些平台支持通过 USB 进行 kgdb，还有一些可以通过以太网工作的版本，但不幸的是，这些都没有进入主线 Linux。

内核的优化和堆栈帧也适用于内核，但内核的限制是，内核被写成至少为`-O1`的优化级别。您可以通过在运行`make`之前设置`KCGLAGS`来覆盖内核编译标志。

然后，这些是您需要进行内核调试的内核配置选项：

+   `CONFIG_DEBUG_INFO`在**内核调试** | **编译时检查和编译器选项** | **使用调试信息编译内核菜单**中

+   `CONFIG_FRAME_POINTER`可能是您的架构的一个选项，并且在**内核调试** | **编译时检查和编译器选项** | **使用帧指针编译内核菜单**中

+   `CONFIG_KGDB`在**内核调试** | **KGDB：内核调试器菜单**中

+   `CONFIG_KGDB_SERIAL_CONSOLE`在**内核调试** | **KGDB：内核调试器** | **KGDB：使用串行控制台菜单**中

除了`uImage`或`zImage`压缩内核映像，您还需要以 ELF 对象格式的内核映像，以便 GDB 可以将符号加载到内存中。这个文件称为在构建 Linux 的目录中生成的`vmlinux`。在 Yocto 项目中，您可以请求在目标映像中包含一个副本，这对于这个和其他调试任务非常方便。它构建为一个名为`kernel-vmlinux`的软件包，您可以像其他软件包一样安装，例如将其添加到`IMAGE_INSTALL_append`列表中。该文件放入引导目录，名称如下：

```
boot/vmlinux-3.14.26ltsi-yocto-standard

```

在 Buildroot 中，您将在构建内核的目录中找到`vmlinux`，该目录位于`output/build/linux-<version string>/vmlinux`中。

## 一个示例调试会话

展示它的最佳方法是通过一个简单的例子。

您需要告诉`kgdb`要使用哪个串行端口，可以通过内核命令行或通过`sysfs`在运行时进行设置。对于第一种选项，请将`kgdboc=<tty>,<波特率>`添加到命令行，如下所示：

```
kgdboc=ttyO0,115200

```

对于第二个选项，启动设备并将终端名称写入`/sys/module/kgdboc/parameters/kgdboc`文件，如下所示：

```
# echo ttyO0 > /sys/module/kgdboc/parameters/kgdboc

```

请注意，您不能以这种方式设置波特率。如果它与控制台相同的`tty`，则已经设置，如果不是，请使用`stty`或类似的程序。

现在您可以在主机上启动 GDB，选择与正在运行的内核匹配的`vmlinux`文件：

```
$ arm-poky-linux-gnueabi-gdb ~/linux/vmlinux

```

GDB 从`vmlinux`加载符号表，并等待进一步的输入。

接下来，关闭连接到控制台的任何终端仿真器：您将要在 GDB 中使用它，如果两者同时活动，一些调试字符串可能会损坏。

现在，您可以返回到 GDB 并尝试连接到`kgdb`。但是，您会发现此时从`target remote`得到的响应是无用的：

```
(gdb) set remotebaud 115200
(gdb) target remote /dev/ttyUSB0
Remote debugging using /dev/ttyUSB0
Bogus trace status reply from target: qTStatus

```

问题在于此时`kgdb`没有在监听连接。您需要在可以与之进行交互的 GDB 会话之前中断内核。不幸的是，就像您在应用程序中一样，仅在 GDB 中键入*Ctrl* + *C*是无效的。您需要通过例如通过 ssh 在目标板上启动另一个 shell，并向目标板的`/proc/sysrq-trigger`写入`g`来强制内核陷入：

```
# echo g > /proc/sysrq-trigger

```

目标在这一点上停止。现在，您可以通过电缆主机端的串行设备连接到`kgdb`：

```
(gdb) set remotebaud 115200
(gdb) target remote /dev/ttyUSB0
Remote debugging using /dev/ttyUSB0
0xc009a59c in arch_kgdb_breakpoint ()

```

最后，GDB 掌控了。您可以设置断点，检查变量，查看回溯等。例如，设置一个在`sys_sync`上的断点，如下所示：

```
(gdb) break sys_sync
Breakpoint 1 at 0xc0128a88: file fs/sync.c, line 103.
(gdb) c
Continuing.

```

现在目标恢复了。在目标上输入`sync`调用`sys_sync`并触发断点。

```
[New Thread 87]
[Switching to Thread 87]

Breakpoint 1, sys_sync () at fs/sync.c:103

```

如果您已经完成了调试会话并想要禁用`kgdboc`，只需将`kgdboc`终端设置为 null：

```
# echo "" >  /sys/module/kgdboc/parameters/kgdboc

```

## 调试早期代码

在系统完全引导时执行您感兴趣的代码的情况下，前面的示例适用。如果您需要尽早进入系统，可以通过在`kgdboc`选项之后添加`kgdbwait`到命令行来告诉内核在引导期间等待：

```
kgdboc=ttyO0,115200 kgdbwait

```

现在，当您引导时，您将在控制台上看到这个：

```
 1.103415] console [ttyO0] enabled
[    1.108216] kgdb: Registered I/O driver kgdboc.
[    1.113071] kgdb: Waiting for connection from remote gdb...

```

此时，您可以关闭控制台，并以通常的方式从 GDB 连接。

## 调试模块

调试内核模块会带来额外的挑战，因为代码在运行时被重定位，所以您需要找出它所在的地址。这些信息通过`sysfs`呈现。模块的每个部分的重定位地址存储在`/sys/module/<module name>/sections`中。请注意，由于 ELF 部分以点'.'开头，它们显示为隐藏文件，如果要列出它们，您将需要使用`ls -a`。重要的是`.text`、`.data`和`.bss`。

以模块名为`mbx`为例：

```
# cat /sys/module/mbx/sections/.text
0xbf000000
# cat /sys/module/mbx/sections/.data
0xbf0003e8
# cat /sys/module/mbx/sections/.bss
0xbf0005c0

```

现在，您可以在 GDB 中使用这些数字来加载模块的符号表：

```
(gdb) add-symbol-file /home/chris/mbx-driver/mbx.ko 0xbf000000 \
-s .data 0xbf0003e8 -s .bss 0xbf0005c0
add symbol table from file "/home/chris/mbx-driver/mbx.ko" at
 .text_addr = 0xbf000000
 .data_addr = 0xbf0003e8
 .bss_addr = 0xbf0005c0

```

现在一切应该正常工作：您可以设置断点并检查模块中的全局和局部变量，就像在`vmlinux`中一样：

```
(gdb) break mbx_write

Breakpoint 1 at 0xbf00009c: file /home/chris/mbx-driver/mbx.c, line 93.

(gdb) c
Continuing.

```

然后，强制设备驱动程序调用`mbx_write`，它将触发断点：

```
Breakpoint 1, mbx_write (file=0xde7a71c0, buffer=0xadf40 "hello\n\n",
 length=6, offset=0xde73df80)
 at /home/chris/mbx-driver/mbx.c:93

```

## 使用 kdb 调试内核代码

尽管`kdb`没有`kgdb`和 GDB 的功能，但它确实有其用途，并且作为自托管的工具，没有外部依赖需要担心。`kdb`具有一个简单的命令行界面，您可以在串行控制台上使用它。您可以使用它来检查内存、寄存器、进程列表、`dmesg`，甚至设置断点以在特定位置停止。

要配置通过串行控制台访问`kgd`，请启用`kgdb`，如前所示，然后启用此附加选项：

+   `CONFIG_KGDB_KDB`，位于**KGDB:** **内核调试** | **内核调试器** | **KGDB_KDB: 包括 kgdb 的 kdb 前端**菜单中

现在，当您强制内核陷入陷阱时，您将在控制台上看到`kdb` shell，而不是进入 GDB 会话：

```
# echo g > /proc/sysrq-trigger
[   42.971126] SysRq : DEBUG

Entering kdb (current=0xdf36c080, pid 83) due to Keyboard Entry
kdb>

```

在`kdb` shell 中有很多事情可以做。`help`命令将打印所有选项。这是一个概述。

获取信息：

+   `ps`：显示活动进程

+   `ps A`：显示所有进程

+   `lsmod`：列出模块

+   `dmesg`：显示内核日志缓冲区

断点：

+   `bp`：设置断点

+   `bl`：列出断点

+   `bc`：清除断点

+   `bt`：打印回溯

+   `go`：继续执行

检查内存和寄存器：

+   `md`：显示内存

+   `rd`：显示寄存器

这是设置断点的一个快速示例：

```
kdb> bp sys_sync
Instruction(i) BP #0 at 0xc01304ec (sys_sync)
 is enabled  addr at 00000000c01304ec, hardtype=0 installed=0

kdb> go

```

内核恢复正常，控制台显示正常的 bash 提示符。如果键入`sync`，它会触发断点并再次进入`kdb`：

```
Entering kdb (current=0xdf388a80, pid 88) due to Breakpoint @ 0xc01304ec

```

`kdb`不是源代码调试器，因此您无法查看源代码或单步执行。但是，您可以使用`bt`命令显示回溯，这对于了解程序流程和调用层次结构很有用。

当内核执行无效的内存访问或执行非法指令时，内核 oops 消息将被写入内核日志。其中最有用的部分是回溯，我想向您展示如何使用其中的信息来定位导致故障的代码行。我还将解决如果 oops 消息导致系统崩溃时如何保留 oops 消息的问题。

## 查看 oops

oops 消息看起来像这样：

```
[   56.225868] Unable to handle kernel NULL pointer dereference at virtual address 00000400[   56.229038] pgd = cb624000[   56.229454] [00000400] *pgd=6b715831, *pte=00000000, *ppte=00000000[   56.231768] Internal error: Oops: 817 [#1] SMP ARM[   56.232443] Modules linked in: mbx(O)[   56.233556] CPU: 0 PID: 98 Comm: sh Tainted: G   O  4.1.10 #1[   56.234234] Hardware name: ARM-Versatile Express[   56.234810] task: cb709c80 ti: cb71a000 task.ti: cb71a000[   56.236801] PC is at mbx_write+0x14/0x98 [mbx][   56.237303] LR is at __vfs_write+0x20/0xd8[   56.237559] pc : [<bf0000a0>]    lr : [<c0307154>]  psr: 800f0013[   56.237559] sp : cb71bef8  ip : bf00008c  fp : 00000000[   56.238183] r10: 00000000  r9 : cb71a000  r8 : c02107c4[   56.238485] r7 : cb71bf88  r6 : 000afb98  r5 : 00000006  r4 : 00000000[   56.238857] r3 : cb71bf88  r2 : 00000006  r1 : 000afb98  r0 : cb61d600
[   56.239276] Flags: Nzcv  IRQs on  FIQs on  Mode SVC_32  ISA ARM  Segment user[   56.239685] Control: 10c5387d  Table: 6b624059  DAC: 00000015[   56.240019] Process sh (pid: 98, stack limit = 0xcb71a220)

```

`PC is at mbx_write+0x14/0x98 [mbx]`告诉您大部分您想知道的内容：最后一条指令在名为`mbx`的内核模块中的`mbx_write`函数中。此外，它是从函数开始的偏移量`0x14`字节，该函数的长度为`0x98`字节。

接下来，看一下回溯：

```
[   56.240363] Stack: (0xcb71bef8 to 0xcb71c000)[   56.240745] bee0:                                                       cb71bf88 cb61d600[   56.241331] bf00: 00000006 c0307154 00000000 c020a308 cb619d88 00000301 00000000 00000042[   56.241775] bf20: 00000000 cb61d608 cb709c80 cb709c78 cb71bf60 c0250a54 00000000 cb709ee0[   56.242190] bf40: 00000003 bef4f658 00000000 cb61d600 cb61d600 00000006 000afb98 cb71bf88[   56.242605] bf60: c02107c4 c030794c 00000000 00000000 cb61d600 cb61d600 00000006 000afb98[   56.243025] bf80: c02107c4 c0308174 00000000 00000000 00000000 000ada10 00000001 000afb98[   56.243493] bfa0: 00000004 c0210640 000ada10 00000001 00000001 000afb98 00000006 00000000[   56.243952] bfc0: 000ada10 00000001 000afb98 00000004 00000001 00000020 000ae274 00000000[   56.244420] bfe0: 00000000 bef4f49c 0000fcdc b6f1aedc 600f0010 00000001 00000000 00000000[   56.245653] [<bf0000a0>] (mbx_write [mbx]) from [<c0307154>] (__vfs_write+0x20/0xd8)[   56.246368] [<c0307154>] (__vfs_write) from [<c030794c>] (vfs_write+0x90/0x164)[   56.246843] [<c030794c>] (vfs_write) from [<c0308174>] (SyS_write+0x44/0x9c)[   56.247265] [<c0308174>] (SyS_write) from [<c0210640>] (ret_fast_syscall+0x0/0x3c)[   56.247737] Code: e5904090 e3520b01 23a02b01 e1a05002 (e5842400)[   56.248372] ---[ end trace 999c378e4df13d74 ]---

```

在这种情况下，我们并没有学到更多，只是`mbx_write`是从虚拟文件系统代码中调用的。

找到与`mbx_write+0x14`相关的代码行将非常好，我们可以使用`objdump`。我们可以从`objdump -S`中看到`mbx_write`在`mbx.ko`中的偏移量为`0x8c`，因此最后执行的指令位于`0x8c + 0x14 = 0xa0`。现在，我们只需要查看该偏移量并查看其中的内容：

```
$ arm-poky-linux-gnueabi-objdump -S mbx.kostatic ssize_t mbx_write(struct file *file,const char *buffer, size_t length, loff_t * offset){  8c:   e92d4038        push    {r3, r4, r5, lr}  struct mbx_data *m = (struct mbx_data *)file->private_data;  90:   e5904090        ldr     r4, [r0, #144]  ; 0x90  94:   e3520b01        cmp     r2, #1024       ; 0x400  98:   23a02b01        movcs   r2, #1024       ; 0x400  if (length > MBX_LEN)    length = MBX_LEN;    m->mbx_len = length;  9c:   e1a05002        mov     r5, r2  a0:   e5842400        str     r2, [r4, #1024] ; 0x400

```

这显示了它停止的指令。代码的最后一行显示在这里：

```
m->mbx_len = length;

```

您可以看到`m`的类型是`struct mbx_data *`。这是定义该结构的地方：

```
#define MBX_LEN 1024 struct mbx_data {  char mbx[MBX_LEN];  int mbx_len;};
```

因此，看起来`m`变量是一个空指针，这导致了 oops。

## 保存 oops

解码 oops 只有在首次捕获它时才可能。如果系统在启动期间在启用控制台之前或在挂起后崩溃，则不会看到它。有机制可以将内核 oops 和消息记录到 MTD 分区或持久内存中，但这里有一种在许多情况下都有效且需要很少事先考虑的简单技术。

只要在重置期间内存内容未被损坏（通常情况下不会），您可以重新启动到引导加载程序并使用它来显示内存。您需要知道内核日志缓冲区的位置，记住它是文本消息的简单环形缓冲区。符号是`__log_buf`。在内核的`System.map`中查找此内容：

```
$ grep __log_buf System.mapc0f72428 b __log_buf

```

然后，通过减去`PAGE_OFFSET`，`0xc0000000`，并在 BeagleBone 上加上 RAM 的物理起始地址`0x80000000`，将内核逻辑地址映射到 U-Boot 可以理解的物理地址，因此`c0f72428 - 0xc0000000 + 0x80000000 = 80f72428`。

然后使用 U-Boot 的`md`命令显示日志：

```
U-Boot# md 80f7242880f72428: 00000000 00000000 00210034 c6000000    ........4.!.....80f72438: 746f6f42 20676e69 756e694c 6e6f2078    Booting Linux on80f72448: 79687020 61636973 5043206c 78302055     physical CPU 0x80f72458: 00000030 00000000 00000000 00730084    0.............s.80f72468: a6000000 756e694c 65762078 6f697372    ....Linux versio80f72478: 2e34206e 30312e31 68632820 40736972    n 4.1.10 (chris@80f72488: 6c697562 29726564 63672820 65762063    builder) (gcc ve80f72498: 6f697372 2e34206e 20312e39 6f726328    rsion 4.9.1 (cro80f724a8: 6f747373 4e2d6c6f 2e312047 302e3032    sstool-NG 1.20.080f724b8: 20292029 53203123 5720504d 4f206465    ) ) #1 SMP Wed O
80f724c8: 32207463 37312038 3a31353a 47203335    ct 28 17:51:53 G

```

### 注意

从 Linux 3.5 开始，内核日志缓冲区中的每行都有一个 16 字节的二进制头，其中编码了时间戳、日志级别和其他内容。在 Linux Weekly News 的一篇名为*走向更可靠的日志记录*的文章中有关于此的讨论，网址为[`lwn.net/Articles/492125/`](https://lwn.net/Articles/492125/)。

# 额外阅读

以下资源提供了有关本章介绍的主题的更多信息：

+   *使用 GDB、DDD 和 Eclipse 进行调试的艺术*，作者*Norman Matloff*和*Peter Jay Salzman*，*No Starch Press*；第 1 版（2008 年 9 月 28 日），ISBN 978-1593271749

+   *GDB 口袋参考*，作者*Arnold Robbins*，*O'Reilly Media*；第 1 版（2005 年 5 月 12 日），ISBN 978-0596100278

+   *熟悉 Eclipse：交叉编译*，[`2net.co.uk/tutorial/eclipse-cross-compile`](http://2net.co.uk/tutorial/eclipse-cross-compile)

+   *熟悉 Eclipse：远程访问和调试*，[`2net.co.uk/tutorial/eclipse-rse`](http://2net.co.uk/tutorial/eclipse-rse)

# 总结

用于交互式调试的 GDB 是嵌入式开发人员工具箱中的一个有用工具。它是一个稳定的、有文档支持的、众所周知的实体。它有能力通过在目标上放置代理来远程调试，无论是用于应用程序的 `gdbserver` 还是用于内核代码的 `kgdb`，尽管默认的命令行用户界面需要一段时间才能习惯，但有许多替代的前端。我提到的三个是 TUI、DDD 和 Eclipse，这应该涵盖了大多数情况，但还有其他前端可以尝试。

调试的第二种同样重要的方法是收集崩溃报告并离线分析它们。在这个类别中，我已经查看了应用程序的核心转储和内核 oops 消息。

然而，这只是识别程序中缺陷的一种方式。在下一章中，我将讨论分析和优化程序的方法，即性能分析和跟踪。
