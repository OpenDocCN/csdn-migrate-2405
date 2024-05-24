# Linux 系统编程技巧（四）

> 原文：[`zh.annas-archive.org/md5/450F8760AE780F24827DDA7979D9DDE8`](https://zh.annas-archive.org/md5/450F8760AE780F24827DDA7979D9DDE8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用 systemd 处理您的守护进程

现在我们知道如何构建我们自己的守护进程，是时候看看我们如何使用**systemd**让 Linux 来处理它们了。在本章中，我们将学习 systemd 是什么，如何启动和停止服务，什么是单元文件，以及如何创建它们。我们还将学习守护进程如何记录到 systemd 中以及如何读取这些日志。

然后，我们将了解 systemd 可以处理的不同类型的服务和守护进程，并将上一章的守护进程放到 systemd 控制下。

在本章中，我们将涵盖以下示例：

+   了解 systemd

+   为守护进程编写一个单元文件

+   启用和禁用服务，以及启动和停止它

+   为 systemd 创建一个更现代的守护进程

+   使新的守护进程成为 systemd 服务

+   阅读日志

# 技术要求

对于这个示例，您需要一台使用 systemd 的 Linux 发行版的计算机——今天几乎每个发行版都是如此，只有一些少见的例外。

您还需要 GCC 编译器和 Make 工具。这些工具的安装说明在*第一章*中有涵盖。您还需要本章的通用 Makefile，在本章的 GitHub 存储库中可以找到，以及本章的所有代码示例。本章的 GitHub 存储库文件夹的 URL 是[`github.com/PacktPublishing/Linux-System-Programming-Techniques/tree/master/ch7`](https://github.com/PacktPublishing/Linux-System-Programming-Techniques/tree/master/ch7)。

查看以下链接以查看“代码实战”视频：[`bit.ly/3cxmXab`](https://bit.ly/3cxmXab)

# 了解 systemd

在这个示例中，我们将探讨 systemd 是什么，它如何处理系统以及所有系统的服务。

从历史上看，Linux 一直由几个较小的部分管理。例如，`init`是系统上的第一个进程，它启动其他进程和守护进程来启动系统。系统守护进程由 shell 脚本处理，也称为*init 脚本*。日志记录是通过守护进程自己通过文件或`syslog`来完成的。网络也是由多个脚本处理的（在一些 Linux 发行版中仍然是这样）。

然而，现在整个系统都由 systemd 处理。例如，系统上的第一个进程现在是`systemd`（我们在之前的章节中已经看到了）。守护进程由称为*单元文件*的东西处理，它在系统上创建了一种统一的控制守护进程的方式。日志记录由**journald**处理，它是 systemd 的日志记录守护进程。但请注意，**syslog**仍然被许多守护进程用于额外的日志记录。在本章的*使新的守护进程成为 systemd 服务*部分中，我们将重新编写*第六章*中的守护进程，以记录到日志中。

了解 systemd 的工作原理将使您能够在编写守护进程的单元文件时正确使用它。它还将帮助您以“新”的方式编写守护进程，以利用 systemd 的日志记录功能。您将成为一个更好的系统管理员，也将成为一个更好的 Linux 开发人员。

## 准备工作

对于这个示例，您只需要一个使用 systemd 的 Linux 发行版，大多数发行版今天都使用 systemd。

如何做…

在这个示例中，我们将看一下 systemd 涉及的一些组件。这将让我们俯瞰 systemd、journald、它的命令和**单元文件**。所有的细节将在本章的后续示例中介绍：

1.  在控制台窗口中键入`systemctl`并按*Enter*。这将显示您机器上当前所有活动的*单元*。如果您浏览列表，您会注意到一个单元可以是任何东西——硬盘、声卡、挂载的网络驱动器、各种服务、定时器等等。

1.  我们在上一步看到的所有服务都作为单元文件存储在`/lib/systemd/system`或`/etc/systemd/system`中。转到这些目录并查看文件。这些都是典型的单元文件。

1.  现在是时候来看一下日志，即 systemd 的日志。我们需要以`sudo journalctl`命令运行此命令，或者首先切换到 root 用户，然后输入`journalctl`。这将显示 systemd 和其所有服务的整个日志。按*Spacebar*键几次以在日志中向下滚动。要转到日志的末尾，在日志显示时输入大写*G*。

## 它是如何工作的...

这三个步骤让我们对 systemd 有了一个概述。在接下来的教程中，我们将更深入地介绍细节。

已安装的软件包将其单元文件放在`/lib/systemd/system`中，如果是 Debian/Ubuntu 系统，则放在`/usr/lib/systemd/system`中，如果是 CentOS/Fedora 系统。但是，在 CentOS/Fedora 上，`/lib`是指向`/usr/lib`的符号链接，因此`/lib/systemd/system`是通用的。

所谓的*local*单元文件放在`/etc/systemd/system`中。本地单元文件意味着特定于此系统的单元文件，例如，由管理员修改或手动添加的某些程序。

## 还有更多...

在 systemd 之前，Linux 有其他的初始化系统。我们已经简要提到了第一个`init`。那个初始化系统`init`通常被称为*Sys-V-style init*，来自 UNIX 版本五（V）。

在 Sys-V-style init 之后，出现了 Upstart，这是 Ubuntu 开发的`init`的完全替代品。Upstart 也被 CentOS 6 和 Red Hat Enterprise Linux 6 使用。

然而，如今，大多数主要的 Linux 发行版都使用 systemd。由于 systemd 是 Linux 的一个重要组成部分，这使得所有发行版几乎都是相似的。十五年前，从一个发行版跳到另一个发行版并不容易。如今，这变得更容易了。

## 另请参阅

系统上有多个手册页面，我们可以阅读以更深入地了解 systemd、其命令和日志：

+   `man systemd`

+   `man systemctl`

+   `man journalctl`

+   `man systemd.unit`

# 为守护进程编写单元文件

在这个教程中，我们将把我们在*第六章*中编写的守护程序，*生成进程和使用作业控制*，变成 systemd 下的一个服务。这个守护程序是 systemd 称之为*forking daemon*的，因为它就是这样。它分叉。这通常是守护程序的工作方式，它们仍然被广泛使用。在本章的*将新守护程序变成 systemd 服务*部分中，我们将稍微修改它以记录到 systemd 的日志中。但首先，让我们将我们现有的守护程序变成一个服务。

## 准备工作

在这个教程中，您将需要我们在*第六章*中编写的文件`my-daemon-v2.c`，*生成进程和使用作业控制*。如果您没有该文件，在 GitHub 的本章目录中有一份副本，网址为[`github.com/PacktPublishing/Linux-System-Programming-Techniques/blob/master/ch7/my-daemon-v2.c`](https://github.com/PacktPublishing/Linux-System-Programming-Techniques/blob/master/ch7/my-daemon-v2.c)。

除了`my-daemon-v2.c`，您还需要 GCC 编译器、Make 工具和本章*技术要求*部分中涵盖的通用 Makefile。

## 如何做...

在这里，我们将把我们的守护程序置于 systemd 的控制之下：

1.  如果您还没有编译`my-daemon-v2`，我们需要从那里开始。像我们迄今为止制作的任何其他程序一样编译它：

```
$> make my-daemon-v2
gcc -Wall -Wextra -pedantic -std=c99    my-daemon-v2.c   -o my-daemon-v2
```

1.  为了使其成为系统守护程序，我们应该将其放在其中一个专门用于此目的的目录中。一个很好的地方是`/usr/local/sbin`。`/usr/local 目录`通常是我们想要放置我们自己添加到系统中的东西的地方，也就是第三方的东西。`sbin`子目录用于系统二进制文件或超级用户二进制文件（因此在*bin*之前有一个*s*）。要将我们的守护程序移到这里，我们需要成为 root 用户：

```
$> sudo mv my-daemon-v2 /usr/local/sbin/
```

1.  现在来写守护程序的*单元文件*，这才是令人兴奋的部分。以 root 身份创建文件`/etc/systemd/system/my-daemon.service`。使用`sudo`或`su`成为 root。在文件中写入下面显示的内容并保存。单元文件分为几个部分。在这个文件中，部分是`[Unit]`、`[Service]`和`[Install]`。`[Unit]`部分包含有关单元的信息，例如我们的描述。`[Service]`部分包含有关此服务应如何工作和行为的信息。在这里，我们有`ExecStart`，其中包含守护程序的路径。我们还有`Restart=on-failure`。这告诉 systemd 如果守护程序崩溃，应重新启动它。然后我们有`Type`指令，在我们的情况下是 forking。请记住，我们的守护程序创建了一个自己的分支，父进程退出。这就是*forking*类型的含义。我们告诉 systemd 类型，以便它知道如何处理守护程序。然后我们有`PIDFile`，其中包含我们的`WantedBy`设置为`multi-user.target`。这意味着当系统进入多用户阶段时，此守护程序应该启动：

```
[Unit]
Description=A small daemon for testing
[Service]
ExecStart=/usr/local/sbin/my-daemon-v2
Restart=on-failure
Type=forking
PIDFile=/var/run/my-daemon.pid
[Install]
WantedBy=multi-user.target
```

1.  为了让系统识别我们的新单元文件，我们需要*重新加载*systemd 守护程序本身。这将读取我们的新文件。这必须以 root 身份完成：

```
$> sudo systemctl daemon-reload
```

1.  我们现在可以使用`systemctl`的`status`命令来查看 systemd 是否识别我们的新守护程序。请注意，我们在这里从单元文件中看到了描述，以及实际使用的单元文件。我们还看到守护程序当前是*禁用*和*未激活*的：

```
$> sudo systemctl status my-daemon
. my-daemon.service - A small daemon for testing
   Loaded: loaded (/etc/systemd/system/my-daemon.service; disabled; vendor preset: enabled)
   Active: inactive (dead)
```

## 它是如何工作的...

为守护程序创建一个 systemd 服务并不比这更难。一旦我们学会了 systemd 和单元文件，就比在旧日写*init 脚本*更容易。只用了九行，我们就将守护程序置于 systemd 的控制之下。

单元文件大部分都是不言自明的。在我们的情况下，对于一个传统的分叉守护程序，我们将类型设置为*forking*并指定一个 PID 文件。然后 systemd 使用 PID 文件中的 PID 号来跟踪守护程序的状态。这样，如果 systemd 注意到 PID 从系统中消失，它就可以重新启动守护程序。

在状态消息中，我们看到服务被*禁用*和*未激活*。**禁用**意味着系统启动时不会自动启动。**未激活**意味着它还没有启动。

## 还有更多...

如果您为使用网络的守护程序编写一个单元文件，例如互联网守护程序，您可以明确告诉 systemd 等待直到网络准备就绪。为了实现这一点，我们在`[Unit]`部分下添加以下行：

```
After=network-online.target
```

```
Wants=network-online.target
```

当然，您也可以为其他依赖关系使用`After`和`Wants`。还有另一个依赖语句可以使用，称为`Requires`。

它们之间的区别在于`After`指定了单元的顺序。具有`After`的单元将在所需单元启动后等待启动。然而，`Wants`和`Requires`只指定了依赖关系，而不是顺序。使用`Wants`，即使其他所需单元未成功启动，单元仍将启动。但是使用`Requires`，如果所需单元未启动，单元将无法启动。

## 另请参阅

在`man systemd.unit`中有关于单元文件的不同部分以及我们可以在每个部分中使用的指令的大量信息。

# 启用和禁用服务 - 以及启动和停止它

在上一个教程中，我们使用一个单元文件将我们的守护程序添加为 systemd 的一个服务。在这个教程中，我们将学习如何启用、启动、停止和禁用它。启用和启动以及禁用和停止服务之间有区别。

启用服务意味着系统启动时将自动启动。启动服务意味着它将立即启动，无论它是否已启用。禁用服务意味着它将不再在系统启动时启动。停止服务会立即停止它，无论它是否已启用或禁用。

了解如何做所有这些可以让你控制系统的服务。

## 准备工作

为了使这个教程起作用，你首先需要完成前面的教程，*为守护进程编写一个单元文件*。

## 如何做...

1.  让我们首先再次检查守护进程的状态。它应该是禁用和未激活的：

```
$> systemctl status my-daemon
. my-daemon.service - A small daemon for testing
   Loaded: loaded (/etc/systemd/system/my-daemon.service; disabled; vendor preset: enabled)
   Active: inactive (dead)
```

1.  现在我们将*启用*它，这意味着它将在启动时自动启动（当系统进入*多用户模式*时）。由于这是一个修改系统的命令，我们必须以 root 身份发出此命令。还要注意当我们启用它时发生了什么。没有什么神秘的事情发生；它只是从我们的单元文件创建一个符号链接到`/etc/systemd/system/multi-user.target.wants/my-daemon.service`。请记住，`multi-user.target`是我们在单元文件中指定的目标。因此，当系统达到多用户级别时，systemd 将启动该目录中的所有服务：

```
$> sudo systemctl enable my-daemon
Created symlink /etc/systemd/system/multi-user.target.wants/my-daemon.service → /etc/systemd/system/my-daemon.service.
```

1.  现在让我们检查一下守护进程的状态，因为我们已经启用了它。现在它应该显示*已启用*而不是*已禁用*。但是，它仍然是*未激活*（未启动）：

```
$> sudo systemctl status my-daemon
. my-daemon.service - A small daemon for testing
   Loaded: loaded (/etc/systemd/system/my-daemon.service; enabled; vendor preset: enabled)
   Active: inactive (dead)
```

1.  现在是启动守护进程的时候了：

```
$> sudo systemctl start my-daemon
```

1.  让我们再次检查状态。它应该是启用和活动的（也就是已启动）。这一次，我们将获得比以前更多关于守护进程的信息。我们将看到它的 PID、状态、内存使用情况等。我们还将在最后看到日志的片段：

```
$> sudo systemctl status my-daemon
. my-daemon.service - A small daemon for testing
   Loaded: loaded (/etc/systemd/system/my-daemon.service; enabled; vendor preset: enabled)
   Active: active (running) since Sun 2020-12-06 14:50:35 CET; 9s ago
  Process: 29708 ExecStart=/usr/local/sbin/my-daemon-v2 (code=exited, status=0/SUCCESS)
 Main PID: 29709 (my-daemon-v2)
    Tasks: 1 (limit: 4915)
   Memory: 152.0K
   CGroup: /system.slice/my-daemon.service
           └─29709 /usr/local/sbin/my-daemon-v2
dec 06 14:50:35 red-dwarf systemd[1]: Starting A small daemon for testing...
dec 06 14:50:35 red-dwarf systemd[1]: my-daemon.service: Can't open PID file /run/my-daemon.pid (yet?) after start
dec 06 14:50:35 red-dwarf systemd[1]: Started A small daemon for testing.
```

1.  让我们验证一下，如果守护进程崩溃或被杀死，systemd 是否会重新启动它。首先，我们用`ps`查看进程。然后我们用`KILL`信号杀死它，所以它没有机会正常退出。然后我们再次用`ps`查看它，并注意到它有一个新的 PID，因为它是一个新的进程。旧的进程被杀死了，systemd 启动了一个新的实例：

```
$> ps ax | grep my-daemon-v2
923 pts/12   S+     0:00 grep my-daemon-v2
29709 ?        S      0:00 /usr/local/sbin/my-daemon-v2
$> sudo kill -KILL 29709
$> ps ax | grep my-daemon-v2
 1103 ?        S      0:00 /usr/local/sbin/my-daemon-v2
 1109 pts/12   S+     0:00 grep my-daemon-v2
```

1.  我们还可以查看守护进程在`/tmp`目录中写入的文件：

```
$> tail -n 5 /tmp/my-daemon-is-alive.txt 
Daemon alive at Sun Dec  6 15:24:11 2020
Daemon alive at Sun Dec  6 15:24:41 2020
Daemon alive at Sun Dec  6 15:25:11 2020
Daemon alive at Sun Dec  6 15:25:41 2020
Daemon alive at Sun Dec  6 15:26:11 2020
```

1.  最后，让我们停止守护进程。我们还将检查它的状态，并检查进程是否已经消失了`ps`：

```
$> sudo systemctl stop my-daemon
$> sudo systemctl status my-daemon
. my-daemon.service - A small daemon for testing
   Loaded: loaded (/etc/systemd/system/my-daemon.service; enabled; vendor preset: enabled)
   Active: inactive (dead) since Sun 2020-12-06 15:27:49 CET; 7s ago
  Process: 1102 ExecStart=/usr/local/sbin/my-daemon-v2 (code=exited, status=0/SUCCESS)
 Main PID: 1103 (code=killed, signal=TERM)
dec 06 15:18:41 red-dwarf systemd[1]: Starting A small daemon for testing...
dec 06 14:50:35 red-dwarf systemd[1]: my-daemon.service: Can't open PID file /run/my-daemon.pid (yet?) after start
dec 06 15:18:41 red-dwarf systemd[1]: Started A small daemon for testing.
dec 06 15:27:49 red-dwarf systemd[1]: Stopping A small daemon for testing...
dec 06 15:27:49 red-dwarf systemd[1]: my-daemon.service: Succeeded.
dec 06 15:27:49 red-dwarf systemd[1]: Stopped A small daemon for testing.
$> ps ax | grep my-daemon-v2
 2769 pts/12   S+     0:00 grep my-daemon-v2
```

1.  为了防止守护进程在系统重新启动时启动，我们还必须*禁用*该服务。请注意这里发生了什么。当我们启用服务时创建的符号链接现在被删除了：

```
$> sudo systemctl disable my-daemon
Removed /etc/systemd/system/multi-user.target.wants/my-daemon.service.
```

## 它是如何工作的...

当我们启用或禁用一个服务时，systemd 会在*target*目录中创建一个符号链接。在我们的情况下，目标是*multi-user*，也就是当系统达到多用户级别时。

在第五步，当我们启动守护进程时，我们在状态输出中看到了*Main PID*。这个 PID 与守护进程创建的`/var/run/my-daemon.pid`文件中的 PID 匹配。这就是 systemd 如何跟踪*forking*守护进程的方式。在下一个教程中，我们将看到如何在 systemd 中创建一个不需要 fork 的守护进程。

# 为 systemd 创建一个更现代的守护进程

由 systemd 处理的守护进程不需要 fork 或关闭它们的文件描述符。相反，建议使用标准输出和标准错误将守护进程的日志写入日志。日志是 systemd 的日志记录设施。

在这个教程中，我们将编写一个新的守护进程，一个不会 fork 并留下`/tmp/my-daemon-is-alive.txt`文件的守护进程（与之前一样）。这种类型的守护进程有时被称为`my-daemon-v2.c`，被称为**SysV 风格守护进程**。**SysV**是 systemd 之前的 init 系统的名称。

## 准备工作

对于这个教程，你只需要本章节*技术要求*部分列出的内容。

## 如何做...

在这个教程中，我们将编写一个**新式守护进程**：

1.  这个程序有点长，所以我把它分成了几个步骤。将代码写入文件并保存为`new-style-daemon.c`。所有代码都放在一个文件中，即使有几个步骤。我们将首先编写所有的`include`语句，信号处理程序的函数原型和`main()`函数体。请注意，我们这里不进行 fork。我们也不关闭任何文件描述符或流。相反，我们将“*守护程序活着*”文本写入标准输出。请注意，我们需要在这里*刷新*stdout。通常，流是行缓冲的，这意味着它们在每个新行上都会被刷新。但是当 stdout 被重定向到其他地方时，比如使用 systemd，它会被完全缓冲。为了能够看到打印的文本，我们需要刷新它；否则，在停止守护程序或缓冲区填满之前，我们将看不到日志中的任何内容：

```
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
void sigHandler(int sig);
int main(void)
{
    time_t now; /* for the current time */
    struct sigaction action; /* for sigaction */
    /* prepare for sigaction */
    action.sa_handler = sigHandler;
    sigfillset(&action.sa_mask);
    action.sa_flags = SA_RESTART;
    /* register the signal handler */
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGUSR1, &action, NULL);
    sigaction(SIGHUP, &action, NULL);
    for (;;) /* main loop */
    {
        time(&now); /* get current date & time */
        printf("Daemon alive at %s", ctime(&now));
        fflush(stdout);
        sleep(30);
    }
    return 0;
}
```

1.  现在我们将编写信号处理程序的函数。请注意，我们在这里捕获了`SIGHUP`和`SIGTERM`。`SIGHUP`经常用于重新加载任何配置文件，而无需重新启动整个守护程序。捕获`SIGTERM`是为了让守护程序在自己之后进行清理（关闭所有打开的文件描述符或流并删除任何临时文件）。我们这里没有任何配置文件或临时文件，所以我们将消息打印到标准输出：

```
void sigHandler(int sig)
{
    if (sig == SIGUSR1)
    {
        printf("Hello world!\n");
    }
    else if (sig == SIGTERM)
    {
        printf("Doing some cleanup...\n");
        printf("Bye bye...\n");
        exit(0);
    }
    else if (sig == SIGHUP)
    {
        printf("HUP is used to reload any " 
            "configuration files\n");
    }
} 
```

1.  现在是时候编译守护程序，这样我们就可以使用它了：

```
$> make new-style-daemon
gcc -Wall -Wextra -pedantic -std=c99    new-style-daemon.c   -o new-style-daemon
```

1.  我们可以交互式运行它以验证它是否正常工作：

```
$> ./new-style-daemon 
Daemon alive at Sun Dec  6 18:51:47 2020
Ctrl+C
```

## 它是如何工作的...

这个守护程序的工作方式几乎与我们编写的任何其他程序一样。无需进行任何 forking、更改工作目录、关闭文件描述符或流，或者其他任何操作。它只是一个常规程序。

请注意，我们不在信号处理程序中刷新 stdout 缓冲区。每次程序接收到信号并打印消息时，程序都会回到`for`循环中，打印另一条“*守护程序活着*”消息，然后在`for`循环中的`fflush(stdout)`处刷新。如果信号是`SIGTERM`，则在`exit(0)`时刷新所有缓冲区，因此我们这里也不需要刷新。

在下一个食谱中，我们将使这个程序成为 systemd 服务。

## 另请参阅

您可以在`man 7 daemon`中获取更多深入的信息。

# 使新守护程序成为 systemd 服务

现在我们已经在上一个食谱中制作了一个**新式守护程序**，我们将看到为这个守护程序制作一个单元文件更容易。

了解如何编写单元文件以适应新式守护程序非常重要，因为越来越多的守护程序是以这种方式编写的。在为 Linux 制作新的守护程序时，我们应该以这种新的方式制作它们。

## 准备工作

对于这个食谱，您需要完成上一个食谱。我们将在这里使用那个食谱中的守护程序。

## 如何做...

在这里，我们将使**新式守护程序**成为 systemd 服务：

1.  让我们首先将守护程序移动到`/usr/local/sbin`，就像我们对传统守护程序所做的那样。请记住，您需要以 root 身份进行操作：

```
$> sudo mv new-style-daemon /usr/local/sbin/
```

1.  现在我们将编写新的单元文件。创建`/etc/systemd/system/new-style-daemon.service`文件，并给它以下内容。请注意，我们不需要在这里指定任何 PID 文件。另外，请注意，我们已将`Type=forking`更改为`Type=simple`。Simple 是 systemd 服务的默认类型：

```
[Unit]
Description=A new-style daemon for testing
[Service]
ExecStart=/usr/local/sbin/new-style-daemon
Restart=on-failure
Type=simple
[Install]
WantedBy=multi-user.target
```

1.  重新加载 systemd 守护程序，以便识别新的单元文件：

```
$> sudo systemctl daemon-reload
```

1.  启动守护程序，并检查其状态。请注意，我们也会在这里看到一个“*守护程序活着*”消息。这是日志中的一个片段。请注意，这次我们不会*启用*服务。除非我们希望它自动启动，否则我们不需要启用服务：

```
$> sudo systemctl start new-style-daemon
$> sudo systemctl status new-style-daemon
. new-style-daemon.service - A new-style daemon for testing
   Loaded: loaded (/etc/systemd/system/new-style-daemon.service; disabled; vendor preset: enabled
   Active: active (running) since Sun 2020-12-06 19:51:25 CET; 7s ago
 Main PID: 8421 (new-style-daemo)
    Tasks: 1 (limit: 4915)
   Memory: 244.0K
   CGroup: /system.slice/new-style-daemon.service
           └─8421 /usr/local/sbin/new-style-daemon
dec 06 19:51:25 red-dwarf systemd[1]: Started A new-style daemon for testing.
dec 06 19:51:25 red-dwarf new-style-daemon[8421]: Daemon alive at Sun Dec  6 19:51:25 2020
```

1.  让守护程序运行，并在下一个食谱中查看日志。

## 它是如何工作的...

由于这个守护程序没有 forking，systemd 可以在没有 PID 文件的情况下跟踪它。对于这个守护程序，我们使用了`Type=simple`，这是 systemd 中的默认类型。

当我们在*Step 4*中启动守护进程并检查其状态时，我们看到了“*守护进程活动*”消息的第一行。我们可以在不使用`sudo`的情况下查看守护进程的状态，但是我们就看不到日志的片段（因为它可能包含敏感数据）。

由于我们在`for`循环中的每个`printf()`后刷新了标准输出缓冲区，因此每次写入新条目时，日志都会实时更新。

在下一个步骤中，我们将查看日志。

# 阅读日志

在这个步骤中，我们将学习如何阅读日志。日志是 systemd 的日志记录设施。守护进程打印到标准输出或标准错误的所有消息都会添加到日志中。但是我们在这里可以找到的不仅仅是系统守护进程的日志。还有系统的引导消息，等等。

了解如何阅读日志可以让您更轻松地找到系统和守护进程中的错误。

## 准备工作

对于这个步骤，您需要`new-style-daemon`服务正在运行。如果您的系统上没有运行它，请返回到上一个步骤，了解如何启动它。

## 如何做...

在这个步骤中，我们将探讨如何阅读日志以及我们可以在其中找到什么样的信息。我们还将学习如何跟踪特定服务的日志：

1.  我们将首先检查来自我们的服务`new-style-daemon`的日志。 `-u`选项代表*单元*：

```
$> sudo journalctl -u new-style-daemon
```

现在日志可能已经很长了，所以您可以通过按*Spacebar*向下滚动日志。要退出日志，请按*Q*。

1.  请记住，我们为`SIGUSR1`实现了一个信号处理程序？让我们尝试向我们的守护进程发送该信号，然后再次查看日志。但是这次，我们将使用`--lines 5`仅显示日志中的最后五行。通过使用`systemctl status`找到进程的 PID。注意“*Hello world*”消息（在以下代码中已突出显示）：

```
$> systemctl status new-style-daemon
. new-style-daemon.service - A new-style daemon for testing
   Loaded: loaded (/etc/systemd/system/new-style-daemon.service; disabled; vendor preset: enabled
   Active: active (running) since Sun 2020-12-06 19:51:25 CET; 31min ago
 Main PID: 8421 (new-style-daemo)
    Tasks: 1 (limit: 4915)
   Memory: 412.0K
   CGroup: /system.slice/new-style-daemon.service
           └─8421 /usr/local/sbin/new-style-daemon
$> sudo kill -USR1 8421
$> sudo journalctl -u new-style-daemon --lines 5
-- Logs begin at Mon 2020-11-30 18:05:24 CET, end at Sun 2020-12-06 20:24:46 CET. --
dec 06 20:23:31 red-dwarf new-style-daemon[8421]: Daemon alive at Sun Dec  6 20:23:31 2020
dec 06 20:24:01 red-dwarf new-style-daemon[8421]: Daemon alive at Sun Dec  6 20:24:01 2020
dec 06 20:24:31 red-dwarf new-style-daemon[8421]: Daemon alive at Sun Dec  6 20:24:31 2020
dec 06 20:24:42 red-dwarf new-style-daemon[8421]: Hello world!
dec 06 20:24:42 red-dwarf new-style-daemon[8421]: Daemon alive at Sun Dec  6 20:24:42 2020
```

1.  还可以*跟踪*服务的日志，即“实时”查看。打开第二个终端并运行以下命令。`-f`代表*跟踪*：

```
$> sudo journalctl -u new-style-daemon -f
```

1.  现在，在第一个终端中，使用`sudo kill -USR1 8421`发送另一个`USR1`信号。您会立即在第二个终端中看到“*Hello world*”消息，而不会有任何延迟。要退出跟踪模式，只需按*Ctrl* + *C*。

1.  `journalctl`命令提供了广泛的过滤功能。例如，可以使用`--since`和`--until`仅选择两个日期之间的日志条目。也可以省略其中一个来查看自特定日期以来或直到特定日期的所有消息。在这里，我们展示了两个日期之间的所有消息：

```
$> sudo journalctl -u new-style-daemon \
> --since "2020-12-06 20:32:00" \
> --until "2020-12-06 20:33:00"
-- Logs begin at Mon 2020-11-30 18:05:24 CET, end at Sun 2020-12-06 20:37:01 CET. --
dec 06 20:32:12 red-dwarf new-style-daemon[8421]: Daemon alive at Sun Dec  6 20:32:12 2020
dec 06 20:32:42 red-dwarf new-style-daemon[8421]: Daemon alive at Sun Dec  6 20:32:42 2020
```

1.  通过省略`-u`选项和单元名称，我们可以查看所有服务的所有日志条目。试一下，用*Spacebar*滚动浏览。您还可以尝试只查看最后 10 行，就像我们之前用`--line 10`一样。

现在是时候停止`new-style-daemon`服务了。在停止服务后，我们还将查看日志中的最后五行。注意来自守护进程的告别消息。这是我们为`SIGTERM`信号制作的信号处理程序。当我们在 systemd 中停止服务时，它会发送一个`SIGTERM`信号给服务：

```
$> sudo systemctl stop new-style-daemon
$> sudo journalctl -u new-style-daemon --lines 5
-- Logs begin at Mon 2020-11-30 18:05:24 CET, end at Sun 2020-12-06 20:47:02 CET. --
dec 06 20:46:44 red-dwarf systemd[1]: Stopping A new-style daemon for testing...
dec 06 20:46:44 red-dwarf new-style-daemon[8421]: Doing some cleanup...
dec 06 20:46:44 red-dwarf new-style-daemon[8421]: Bye bye...
dec 06 20:46:44 red-dwarf systemd[1]: new-style-daemon.service: Succeeded.
dec 06 20:46:44 red-dwarf systemd[1]: Stopped A new-style daemon for testing.
```

## 工作原理...

由于日志负责处理所有发送到标准输出和标准错误的消息，我们不需要自己处理日志记录。这使得编写由 systemd 处理的 Linux 守护进程变得更容易。正如我们在查看日志时看到的那样，每条消息都有一个时间戳。这使得在寻找错误时可以轻松地过滤出特定的日期或时间。

使用`-f`选项跟踪特定服务的日志在尝试新的或未知服务时很常见。

## 另请参阅

`man journalctl`的手册页面上甚至有更多关于如何过滤日志的技巧和提示。


# 第八章：创建共享库

在本章中，我们将学习库是什么，以及为什么它们是 Linux 的重要组成部分。我们还将了解静态库和动态库之间的区别。当我们知道库是什么时，我们开始编写我们自己的库——静态和动态的。我们还快速查看动态库的内部。

使用库有许多好处，例如，开发人员不需要一遍又一遍地重新发明功能，因为通常库中已经存在一个现有的功能。动态库的一个重要优势是，生成的程序大小要小得多，并且即使在程序编译完成后，库也是可升级的。

在本章中，我们将学习如何制作具有有用功能的自己的库，并将其安装到系统上。知道如何制作和安装库使您能够以标准化的方式与他人共享您的功能。

在本章中，我们将涵盖以下配方：

+   库的作用和意义

+   创建静态库

+   使用静态库

+   创建动态库

+   在系统上安装动态库

+   在程序中使用动态库

+   编译一个静态链接的程序

# 技术要求

在本章中，我们将需要**GNU 编译器集合**（**GCC**）编译器和 Make 工具。您可以在*第一章*中找到这些工具的安装说明，*获取必要的工具并编写我们的第一个 Linux 程序*。本章的所有代码示例都可以在本章的 GitHub 目录中找到，网址为[`github.com/PacktPublishing/Linux-System-Programming-Techniques/tree/master/ch8`](https://github.com/PacktPublishing/Linux-System-Programming-Techniques/tree/master/ch8)。

点击以下链接查看《代码实战》视频：[`bit.ly/3fygqOm`](https://bit.ly/3fygqOm)

# 库的作用和意义

在我们深入了解库的细节之前，了解它们是什么以及它们对我们的重要性是至关重要的。了解静态库和动态库之间的区别也很重要：

这些知识将使您在制作自己的库时能够做出更明智的选择。

**动态库**是动态**链接**到使用它的二进制文件的。这意味着库代码不包含在二进制文件中。库驻留在二进制文件之外。这有几个优点。首先，由于库代码不包含在其中，生成的二进制文件大小会更小。其次，库可以在不需要重新编译二进制文件的情况下进行更新。缺点是我们不能将动态库从系统中移动或删除。如果这样做，二进制文件将不再起作用。

另一方面，**静态库**包含在二进制文件中。这样做的优点是一旦编译完成，二进制文件将完全独立于库。缺点是二进制文件会更大，并且库不能在不重新编译二进制文件的情况下更新。

我们已经在*第三章**中看到了一个动态库的简短示例，在 Linux 中深入 C*。

在这个配方中，我们将看一些常见的库。我们还将通过包管理器在系统上安装一个新的库，然后在程序中使用它。

## 准备工作

对于这个配方，您将需要 GCC 编译器。您还需要通过`su`或`sudo`以 root 访问系统。

## 操作方法…

在这个配方中，我们将探索一些常见的库，看看它们在系统上的位置，然后安装一个新的库并查看库的内部。在这个配方中，我们只处理动态库。

1.  让我们首先看看您系统中已经存在的许多库。这些库将驻留在一个或多个这些目录中，具体取决于您的发行版：

```
/usr/lib
/usr/lib64
/usr/lib32
```

1.  现在，我们将使用 Linux 发行版软件包管理器在系统上安装一个新的库。我们将安装的库是用于**cURL**的，这是一个从互联网上获取文件或数据的应用程序和库，例如通过**超文本传输协议**（**HTTP**）。根据您的发行版，按照以下说明进行操作：

- **Debian/Ubuntu**:

```
   $> sudo apt install libcurl4-openssl-dev
```

- **Fedora/CentOS/Red Hat**:

```
   $> sudo dnf install libcurl-devel
```

1.  现在，让我们使用`nm`来查看库的内部。但首先，我们需要使用`whereis`找到它。不同发行版的库路径是不同的。这个示例来自 Debian 10 系统。我们要找的文件是`.so`文件。请注意，我们使用`grep`和`nm`一起使用，只列出带有`T`的行。这些是库提供的函数。如果我们去掉`grep`部分，我们还会看到这个库依赖的函数。我们还在命令中添加了`head`，因为函数列表很长。如果您想看到所有函数，请省略`head`：

```
$> whereis libcurl
libcurl: /usr/lib/x86_64-linux-gnu/libcurl.la
/usr/lib/x86_64-linux-gnu/libcurl.a /usr/lib/x86_64
linux-gnu/libcurl.so
$> nm -D /usr/lib/x86_64-linux-gnu/libcurl.so \
> | grep " T " | head -n 7
000000000002f750 T curl_easy_cleanup
000000000002f840 T curl_easy_duphandle
00000000000279b0 T curl_easy_escape
000000000002f7e0 T curl_easy_getinfo
000000000002f470 T curl_easy_init
000000000002fc60 T curl_easy_pause
000000000002f4e0 T curl_easy_perform
```

1.  现在我们对库有了更多了解，我们可以在程序中使用它。在文件中编写以下代码，并将其保存为`get-public-ip.c`。该程序将向位于`ifconfig.me`的 Web 服务器发送请求，并给出您的公共**Internet Protocol**（**IP**）地址。cURL 库的完整手册可以在[`curl.se/libcurl/c/`](https://curl.se/libcurl/c/)上找到。请注意，我们不从 cURL 打印任何内容。库将自动打印从服务器接收到的内容：

```
#include <stdio.h>
#include <curl/curl.h>
int main(void)
{
    CURL *curl;
    curl = curl_easy_init();
    if(curl) 
    {
        curl_easy_setopt(curl, CURLOPT_URL, 
            "https://ifconfig.me"); 
        curl_easy_perform(curl); 
        curl_easy_cleanup(curl);
    }
    else
    {
        fprintf(stderr, "Cannot initialize curl\n");
        return 1;
    }
    return 0;
}
```

1.  编译代码。请注意，我们还必须使用`-l`选项链接到 cURL 库：

```
$> gcc -Wall -Wextra -pedantic -std=c99 -lcurl \
> get-public-ip.c -o get-public-ip
```

1.  现在，最后，我们可以运行程序来获取我们的公共 IP 地址。我的 IP 地址在下面的输出中被掩盖了：

```
$> ./get-public-ip 
158.174.xxx.xxx
```

## 工作原理…

在这里，我们已经看到了使用库添加新功能所涉及的所有步骤。我们使用软件包管理器在系统上安装了库。我们使用`whereis`找到了它的位置，使用`nm`调查了它包含的函数，最后在程序中使用了它。

`nm`程序提供了一种快速查看库包含哪些函数的方法。我们在这个示例中使用的`-D`选项是用于动态库的。我们使用`grep`只查看库提供的函数；否则，我们还会看到这个库依赖的函数（这些行以`U`开头）。

由于这个库不是`libc`的一部分，我们需要使用`-l`选项将其链接到`gcc`。库的名称应该紧跟在`l`后面，没有任何空格。

[ifconfig.me](http://ifconfig.me) 网站是一个返回请求该站点的客户端的公共 IP 的站点和服务。

## 还有更多…

cURL 也是一个程序。许多 Linux 发行版都预装了它。cURL 库提供了一种方便的方式，在您自己的程序中使用 cURL 函数。

您可以运行`curl ifconfig.me`来获得与我们编写的程序相同的结果，假设您已经安装了 cURL。

# 创建一个静态库

在*第三章*中，*深入 Linux 中的 C 编程*，我们看到了如何创建动态库以及如何从当前工作目录链接它。在这个示例中，我们将创建一个**静态库**。

静态库在编译过程中包含在二进制文件中。优点是二进制文件更具可移植性和独立性。我们可以在编译后删除静态库，程序仍然可以正常工作。

缺点是二进制文件会稍微变大，而且在将库编译到程序中后无法更新库。

了解如何创建静态库将使在新程序中分发和重用您的函数变得更加容易。

## 准备工作

对于这个示例，我们将需要 GCC 编译器。我们还将在这个示例中使用一个名为`ar`的工具。`ar`程序几乎总是默认安装的。

## 如何做…

在这个教程中，我们将制作一个小的静态库。该库将包含两个函数：一个用于将摄氏度转换为华氏度，另一个用于将摄氏度转换为开尔文：

1.  让我们从编写库函数开始。在文件中写入以下代码，并将其保存为`convert.c`。该文件包含我们的两个函数：

```
float c_to_f(float celsius)
{
    return (celsius*9/5+32);
}
float c_to_k(float celsius)
{
    return (celsius + 273.15);
}
```

1.  我们还需要一个包含这些函数原型的头文件。创建另一个文件，并在其中写入以下代码。将其保存为`convert.h`：

```
float c_to_f(float celsius);
float c_to_k(float celsius);
```

1.  制作库的第一步是将`convert.c`编译成 GCC 的`-c`选项：

```
$> gcc -Wall -Wextra -pedantic -std=c99 -c convert.c
```

1.  我们现在应该在当前目录中有一个名为`convert.o`的文件。我们可以使用`file`命令来验证这一点，它还会告诉我们文件的类型：

```
$> file convert.o
convert.o: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped
```

1.  使其成为静态库的最后一步是使用`ar`命令将其打包。`-c`选项表示*创建*存档；`-v`选项表示*详细*输出；`-r`选项表示*替换*具有相同名称的成员。名称`libconvert.a`是我们的库将得到的结果文件名：

```
$> ar -cvr libconvert.a convert.o 
a - convert.o
```

1.  在继续之前，让我们用`nm`查看我们的静态库：

```
$> nm libconvert.a 
convert.o:
0000000000000000 T c_to_f
0000000000000037 T c_to_k
```

## 它是如何工作的…

正如我们在这里看到的，静态库只是存档中的一个对象文件。

当我们用`file`命令查看对象文件时，我们注意到它说*not stripped*，这意味着所有的**符号**仍然在文件中。*符号*是暴露函数的东西，使得程序可以访问和使用它们。在下一个教程中，我们将回到符号和*stripped*与*not stripped*的含义。

## 参见

在其手册页`man 1 ar`中有关`ar`的大量有用信息，例如，可以修改和删除已经存在的静态库。

# 使用静态库

在这个教程中，我们将在程序中使用上一个教程中创建的静态库。使用静态库比使用动态库要容易一些。我们只需将静态库（存档文件）添加到将编译为最终二进制文件的文件列表中。

知道如何使用静态库将使您能够使用其他人的库并重用自己的代码作为静态库。

## 准备工作

对于这个教程，您将需要`convert.h`文件和静态库文件`libconvert.a`。您还需要 GCC 编译器。

## 如何做…

在这里，我们将编写一个小程序，该程序使用我们在上一个教程中创建的库中的函数：

1.  在文件中写入以下代码，并将其保存为`temperature.c`。注意从当前目录包含头文件的语法。

该程序接受两个参数：一个选项（`-f`或`-k`，分别表示华氏度或开尔文）和一个摄氏度作为浮点值。然后程序将根据所选的选项将摄氏度转换为华氏度或开尔文：

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "convert.h"
void printUsage(FILE *stream, char progname[]);
int main(int argc, char *argv[])
{
    if ( argc != 3 )
    {
        printUsage(stderr, argv[0]);
        return 1;
    }
    if ( strcmp(argv[1], "-f") == 0 )
    {
        printf("%.1f C = %.1f F\n", 
            atof(argv[2]), c_to_f(atof(argv[2])));
    }
    else if ( strcmp(argv[1], "-k") == 0  )
    {
        printf("%.1f C = %.1f F\n", 
            atof(argv[2]), c_to_k(atof(argv[2])));
    }
    else
    {
        printUsage(stderr, argv[0]);
        return 1;
    }

    return 0;
}
void printUsage(FILE *stream, char progname[])
{
    fprintf(stream, "%s [-f] [-k] [temperature]\n"
        "Example: %s -f 25\n", progname, progname);
}
```

1.  让我们编译这个程序。要包含静态库，我们只需将其添加到 GCC 的文件列表中。还要确保`convert.h`头文件在您当前的工作目录中：

```
$> gcc -Wall -Wextra -pedantic -std=c99 \
> temperature.c libconvert.a -o temperature
```

1.  现在我们可以用一些不同的温度测试程序：

```
$> ./temperature -f 30
30.0 C = 86.0 F
$> ./temperature -k 15
15.0 C = 288.1 F
```

1.  最后，使用`nm`查看生成的`temperature`二进制文件：

```
c_to_f, c_to_k, printUsage, and main (the Ts). We also see which functions from dynamic libraries the program is depending on—for example, printf (preceded by a U). What we see here are called *symbols*. 
```

1.  由于该二进制文件将用作独立程序，我们不需要符号。可以使用`strip`命令从二进制文件中*strip*符号。这会使程序的大小变小一点。一旦我们从二进制文件中删除了符号，让我们再次用`nm`查看它：

```
$> strip temperature
$> nm temperature
nm: temperature: no symbols
```

1.  我们可以用`file`命令查看程序或库是否被剥离。请记住，静态库不能被剥离；否则，链接器将无法看到函数，链接将失败：

```
$> file temperature
temperature: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter/lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=95f583af98ff899c657ac33d6a014493c44c362b, stripped
$> file convert.o
convert.o: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped
```

## 它是如何工作的…

当我们想在程序中使用静态库时，我们将存档文件的文件名和程序的`c`文件提供给 GCC，从而生成一个包含静态库的二进制文件。

在最后几个步骤中，我们使用`nm`检查了二进制文件，显示了所有符号。然后我们使用`strip`命令剥离 - 移除 - 这些符号。如果我们使用`file`命令查看`ls`，`more`，`sleep`等程序，我们会注意到这些程序也被*剥离*。这意味着程序已经删除了其符号。

静态库必须保持其符号不变。如果它们被移除 - 剥离 - 链接器将找不到函数，链接过程将失败。因此，我们永远不应该剥离我们的静态库。

# 创建一个动态库

虽然静态库方便且易于创建和使用，**动态库**更常见。正如我们在本章开头看到的那样，许多开发人员选择提供库而不仅仅是程序 - 例如，cURL。

在这个配方中，我们将重新制作本章前面介绍的“创建静态库”配方中的库，使其成为一个动态库。

了解如何创建动态库使您能够将代码分发为其他开发人员易于实现的库。

## 准备工作

对于这个配方，您将需要本章前面的“创建静态库”中的两个`convert.c`和`convert.h`文件。您还需要 GCC 编译器。

## 如何做…

在这里，我们从本章前面的“创建静态库”中的`convert.c`创建一个动态库：

1.  首先，让我们删除之前创建的对象文件和旧的静态库。这样可以确保我们不会错误地使用错误的对象文件或错误的库：

```
$> rm convert.o libconvert.a
```

1.  我们需要做的第一件事是从`c`文件创建一个新的对象文件。`-c`选项创建一个对象文件，而不是最终的二进制文件。`-fPIC`选项告诉 GCC 生成所谓的`file`：

```
$> gcc -Wall -Wextra -pedantic -std=c99 -c -fPIC \
> convert.c
$> file convert.o 
convert.o: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped
```

1.  下一步是创建一个`.so`文件，`-shared`选项做了它说的 - 它创建了一个共享对象。`-Wl`选项意味着我们想要将所有逗号分隔的选项传递给链接器。在这种情况下，传递给链接器的选项是`-soname`，参数是`libconvert.so`，它将动态库的名称设置为*libconvert.so*。最后，`-o`选项指定了输出文件的名称。然后，我们使用`nm`列出了这个共享库提供的符号。由`T`前缀的符号是这个库提供的符号：

```
$> gcc -shared -Wl,-soname,libconvert.so -o \
> libconvert.so.1 convert.o
$> nm -D libconvert.so.1
00000000000010f5 T c_to_f
000000000000112c T c_to_k
                 w __cxa_finalize
                 w __gmon_start__
                 w _ITM_deregisterTMCloneTable
                 w _ITM_registerTMCloneTable
```

## 工作原理…

创建动态库涉及两个步骤：创建一个位置无关的对象文件，并将该文件打包成一个`.so`文件。

共享库中的代码在运行时加载。由于它无法预测自己将在内存中的何处结束，因此需要是位置无关的。这样，代码将在内存中的任何位置正确工作。

`-Wl，-soname，libconvert.so` GCC 选项可能需要进一步解释。`-Wl`选项告诉 GCC 将逗号分隔的单词视为链接器的选项。由于我们不能使用空格 - 那将被视为一个新的选项 - 我们用逗号代替`-soname`和`libconvert.so`。然而，链接器将其视为`-soname libconvert.so`。

`soname`是*共享对象名称*的缩写，它是库中的内部名称。在引用库时使用这个名称。

使用`-o`选项指定的实际文件名有时被称为库的*真实名称*。使用包含库版本号的真实名称是一个标准约定，例如在这个例子中使用`1`。也可以包括一个次要版本 - 例如，`1.3`。在我们的例子中，它看起来像这样：`libconvert.so.1.3`。*真实名称*和*soname*都必须以`lib`开头，缩写为*库*。总的来说，这给我们提供了真实名称的五个部分：

+   `lib`（库的缩写）

+   `convert`（库的名称）

+   `.so`（扩展名，缩写为*共享对象*）

+   `.1`（库的主要版本）

+   `.3`（库的次要版本，可选）

## 还有更多…

与静态库相反，动态库可以被剥离并且仍然可以工作。但是请注意，剥离必须在创建`.so`文件的动态库之后进行。如果我们剥离对象（`.o`）文件，那么我们将丢失所有符号，使其无法链接。但是`.so`文件将符号保留在一个称为`.dynsym`的特殊表中，`strip`命令不会触及。可以使用`readelf`命令的`--symbols`选项在剥离的动态库上查看此表。因此，如果`nm`命令在动态库上回复*no symbols*，可以尝试使用`readelf --symbols`。

## 另请参阅

**GCC**是一个庞大的软件，有很多选项。GNU 的网站上提供了每个 GCC 版本的 PDF 手册。这些手册大约有 1000 页，可以从 https://gcc.gnu.org/onlinedocs/下载。

# 在系统上安装动态库

我们现在已经看到如何创建静态库和动态库，在*第三章**，深入 Linux 中的 C 编程*中，我们甚至看到了如何从我们的主目录中使用动态库。但现在，是时候将动态库系统范围内安装，以便计算机上的任何用户都可以使用它了。

知道如何在系统上安装动态库将使您能够为任何用户添加系统范围的库。

## 准备工作

对于这个步骤，您将需要在上一个步骤中创建的`libconvert.so.1`动态库。您还需要 root 访问系统，可以通过`sudo`或`su`来获取。

## 如何做...

安装动态库只是将库文件和头文件移动到正确的目录并运行命令的问题。但是，我们应该遵循一些约定：

1.  我们需要做的第一件事是将库文件复制到系统的正确位置。用户安装的库的常见目录是`/usr/local/lib`，我们将在这里使用。由于我们将文件复制到家目录之外的地方，我们需要以 root 用户的身份执行该命令。我们将在这里使用`install`来设置用户、组和模式，因为它是系统范围的安装，我们希望它由 root 拥有。它还应该是可执行的，因为它将在运行时被包含和执行：

```
$> sudo install -o root -g root -m 755 \
> libconvert.so.1 /usr/local/lib/libconvert.so.1
```

1.  现在，我们必须运行`ldconfig`命令，它将创建必要的链接并更新缓存。

```
$> sudo ldconfig
$> cd /usr/local/lib/
$> ls -og libconvert*
lrwxrwxrwx 1 15 dec 27 19:12 libconvert.so ->
libconvert.so.1
-rwxr-xr-x 1 15864 dec 27 18:16 libconvert.so.1
```

1.  我们还必须将头文件复制到系统目录；否则，用户将不得不手动下载并跟踪头文件，这不太理想。用户安装的头文件的一个好地方是`/usr/local/include`。单词*include*来自 C 语言的`#include`行：

```
$> sudo install -o root -g root -m 644 convert.h \
> /usr/local/include/convert.h
```

1.  由于我们已经在整个系统中安装了库和头文件，我们可以继续从当前工作目录中删除它们。这样做将确保我们在下一个步骤中使用正确的文件：

```
$> rm libconvert.so.1 convert.h
```

## 它是如何工作的...

我们使用`install`程序安装了库文件和头文件。这个程序非常适合这样的任务，因为它可以在单个命令中设置用户（`-o`选项）、组（`-g`选项）和模式（`-m`选项）。如果我们使用`cp`来复制文件，它将由创建它的用户拥有。我们总是希望系统范围内的二进制文件、库和头文件由 root 用户拥有，以确保安全。

`/usr/local`目录是用户创建的东西的一个好地方。我们将库放在`/usr/local/lib`下，将头文件放在`/usr/local/include`下。系统库和头文件通常放在`/usr/lib`和`/usr/include`中。

当我们稍后使用库时，系统将在以`.so`结尾的文件中查找它，因此我们需要一个指向库的符号链接，名称为`libconvert.so`。但我们不需要自己创建该链接；`ldconfig`已经为我们处理了。

另外，由于我们已经将头文件放在`/usr/local/include`中，我们不再需要在当前工作目录中拥有该文件。现在我们可以像包含任何其他系统头文件一样使用相同的语法。我们将在下一个示例中看到这一点。

# 在程序中使用动态库

现在我们已经创建了一个动态库并将其安装在系统上，现在是时候在程序中尝试它了。实际上，自从本书的开头以来，我们一直在使用动态库而不自知。诸如`printf()`等函数都是标准库的一部分。在本章前面的*库的作用和原因*示例中，我们使用了另一个名为 cURL 的动态库。在这个示例中，我们将使用我们在上一个示例中安装的自己的库。

了解如何使用自定义库将使您能够使用其他开发人员的代码，这将加快开发过程。通常没有必要重新发明轮子。

## 准备工作

对于这个示例，我们将需要本章前面的*使用静态库*示例中的`temperature.c`代码。该程序将使用动态库。在尝试此示例之前，您还需要完成上一个示例。

## 如何做...

在这个示例中，我们将使用`temperature.c`代码来利用我们在上一个示例中安装的库：

1.  由于我们将使用`/usr/local/include`，我们必须修改`temperature.c`中的`#include`行。`temperature.c`中的*第 4 行*当前显示为：

```
#include "convert.h"
```

将前面的代码更改为：

```
#include <convert.h>
```

然后，将其保存为`temperature-v2.c`。

1.  现在我们可以继续编译程序了。GCC 将使用系统范围的头文件和库文件。请记住，我们需要使用`-l`选项链接到库。这样做时，我们必须省略`lib`部分和`.so`结尾：

```
$> gcc -Wall -Wextra -pedantic -std=c99 \
> -lconvert temperature-v2.c -o temperature-v2
```

1.  然后，让我们尝试一些不同的温度：

```
$> ./temperature-v2 -f 34
34.0 C = 93.2 F
$> ./temperature-v2 -k 21
21.0 C = 294.1 F
```

1.  我们可以使用`ldd`验证动态链接的库。当我们在我们的程序上运行此工具时，我们会看到我们的`libconvert.so`库，`libc`和称为`vdso`（*虚拟动态共享对象*）的东西：

```
$> ldd temperature-v2
        linux-vdso.so.1 (0x00007fff4376c000)
        libconvert.so => /usr/local/lib/libconvert.so (0x00007faaeefe2000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007faaeee21000)
        /lib64/ld-linux-x86-64.so.2 (0x00007faaef029000)
```

## 它是如何工作的...

当我们从当前目录包含本地头文件时，语法是`#include "file.h"`。但对于系统范围的头文件，语法是`#include <file.h>`。

由于库现在安装在系统目录之一中，我们不需要指定路径。仅需使用`-lconvert`链接到库即可。这样做时，所有常见的系统范围目录都会搜索该库。当我们使用`-l`进行链接时，我们省略了文件名的`lib`部分和`.so`结尾——链接器会自行解决这个问题。

在最后一步中，我们使用`ldd`验证了我们正在使用`libconvert.so`的系统范围安装。在这里，我们还看到了标准 C 库`libc`和称为`vdso`的东西。标准 C 库具有我们一次又一次使用的所有常用函数，例如`printf()`。然而，`vdso`库有点更加神秘，这不是我们要在这里讨论的内容。简而言之，它将一小部分经常使用的系统调用导出到用户空间，以避免过多的上下文切换，这将影响性能。

还有更多...

在本章中，我们已经谈论了很多关于`ld`的内容。为了更深入地了解链接器，我建议您阅读其手册页，使用`man 1 ld`。

## 另请参阅

有关`ldd`的更多信息，请参阅`man 1 ldd`。

对于好奇的人，可以在`man 7 vdso`中找到有关`vdso`的详细解释。

# 编译静态链接程序

现在我们对库和链接有了如此深刻的理解，我们可以创建一个**静态链接**程序——也就是说，一个将所有依赖项编译到其中的程序。这使得程序基本上不依赖于其他库。制作静态链接程序并不常见，但有时可能是可取的——例如，如果由于某种原因需要将单个预编译的二进制文件分发到许多计算机而不必担心安装所有的库。但请注意：并不总是可能创建完全不依赖于其他程序的程序。如果一个程序使用了依赖于另一个库的库，这就不容易实现。

制作和使用静态链接程序的缺点是它们的大小变得更大。此外，不再能够更新程序的库而不重新编译整个程序。因此，请记住这只在极少数情况下使用。

但是，通过了解如何编译静态链接程序，你不仅可以增强你的知识，还可以将预编译的二进制文件分发到没有必要的库的系统上，而且可以在许多不同的发行版上实现。

## 准备工作

对于这个示例，你需要完成前两个示例——换句话说，你需要在系统上安装`libconvert.so.1`库，并且需要编译`temperature-v2.c`。像往常一样，你还需要 GCC 编译器。

## 如何做…

在这个示例中，我们将编译`temperature-v2.c`的静态链接版本。然后，我们将从系统中删除库，并注意到静态链接的程序仍然可以工作，而另一个则不能：

重要提示

在 Fedora 和 CentOS 上，默认情况下不包括`libc`的静态库。要安装它，运行`sudo dnf install glibc-static`。

1.  为了静态链接到库，我们需要所有库的静态版本。这意味着我们必须重新创建库的存档（`.a`）版本，并将其安装。这些步骤与本章前面的*创建静态库*示例中的步骤相同。首先，如果我们仍然有对象文件，我们将删除它。然后，我们创建一个新的对象文件，并从中创建一个存档：

```
$> rm convert.o
$> gcc -Wall -Wextra -pedantic -std=c99 -c convert.c
$> ar -cvr libconvert.a convert.o 
a - convert.o
```

1.  接下来，我们必须在系统上安装静态库，最好与动态库放在同一个位置。静态库不需要可执行文件，因为它是在编译时包含的，而不是在运行时包含的：

```
$> sudo install -o root -g root -m 644 \
> libconvert.a /usr/local/lib/libconvert.a
```

1.  现在，编译`temperature-v2.c`的静态链接版本。`-static`选项使二进制文件静态链接，这意味着它将在二进制文件中包含库代码：

```
$> gcc -Wall -Wextra -pedantic -std=c99 -static \
> temperature-v2.c -lconvert -o temperature-static
```

1.  在我们尝试这个程序之前，让我们用`ldd`来检查它，并用`du`来查看它的大小。请注意，在我的系统上，二进制文件现在几乎有 800 千字节（在另一个系统上，它有 1.6 兆字节）。与动态版本相比，动态版本只有大约 20 千字节：

```
$> du -sh temperature-static 
788K    temperature-static
$> du -sh temperature-v2
20K     temperature-v2
$> ldd temperature-static 
        not a dynamic executable
```

1.  现在，让我们尝试这个程序：

```
$> ./temperature-static -f 20
20.0 C = 68.0 F
```

1.  让我们从系统中删除静态和动态库：

```
$> sudo rm /usr/local/lib/libconvert.a \
> /usr/local/lib/libconvert.so \ 
> /usr/local/lib/libconvert.so.1
```

1.  现在，让我们尝试动态链接的二进制文件，由于我们已经删除了它所依赖的库，所以它不应该工作：

```
$> ./temperature-v2 -f 25
./temperature-v2: error while loading shared
libraries: libconvert.so: cannot open shared object
file: No such file or directory
```

1.  最后，让我们尝试静态链接的二进制文件，它应该和以前一样正常工作：

```
$> ./temperature-static -f 25
25.0 C = 77.0 F
```

## 工作原理…

静态链接的程序包括所有库的所有代码，这就是为什么在这个示例中我们的二进制文件变得如此庞大。要构建一个静态链接的程序，我们需要程序所有库的静态版本。这就是为什么我们需要重新创建静态库并将其放在系统目录中的原因。我们还需要标准 C 库的静态版本，如果我们使用的是 CentOS 或 Fedora 机器，我们会安装它。在 Debian/Ubuntu 上，它已经安装好了。


# 第九章：终端 I/O 和更改终端行为

在本章中，我们将学习**TTY**（**TeleTYpewriter**的缩写）和**PTY**（**Pseudo-TeletYpewriter**的缩写）是什么，以及如何获取有关它们的信息。我们还将学习如何设置它们的属性。然后，我们编写一个接收输入但不回显文本的小程序——非常适合密码提示。我们还编写一个检查当前终端大小的程序。

终端可以采用多种形式——例如，在 X 中的终端窗口（图形前端）；通过*Ctrl* + *Alt* + *F1*到*F7*访问的七个终端；旧的串行终端；拨号终端；或者远程终端，比如**Secure Shell**（**SSH**）。

**TTY**是硬件终端，比如通过*Ctrl* + *Alt* + *F1*到*F7*访问的控制台，或者串行控制台。

一个`xterm`，`rxvt`，`tmux`。也可以是远程终端，比如 SSH。

由于我们在日常生活中都使用 Linux 终端，了解如何获取有关它们的信息并控制它们可以帮助我们编写更好的软件。一个例子是在密码提示中隐藏密码。

在本章中，我们将涵盖以下内容：

+   查看终端信息

+   使用`stty`更改终端设置

+   调查 TTY 和 PTY 并向它们写入

+   检查它是否是 TTY

+   创建一个 PTY

+   禁用密码提示的回显

+   读取终端大小

# 技术要求

在本章中，我们将需要所有常用的工具，比如`screen`。如果您还没有安装，可以使用您发行版的软件包管理器进行安装——例如，对于 Debian/Ubuntu，可以使用`sudo apt-get install screen`，对于 CentOS/Fedora，可以使用`sudo dnf install screen`。

本章的所有代码示例都可以从[`github.com/PacktPublishing/Linux-System-Programming-Techniques/tree/master/ch9`](https://github.com/PacktPublishing/Linux-System-Programming-Techniques/tree/master/ch9)下载。

查看以下链接以查看实际操作视频：[`bit.ly/2O8j7Lu`](https://bit.ly/2O8j7Lu)

# 查看终端信息

在这个配方中，我们将学习更多关于 TTY 和 PTY 是什么，以及如何读取它们的属性和信息。这将有助于我们在本章中继续了解 TTY。在这里，我们将学习如何找出我们正在使用的 TTY 或 PTY，它在文件系统中的位置，以及如何读取它的属性。

## 准备工作

这个配方没有特殊要求。我们只会使用已经安装的标准程序。

## 如何做…

在这个配方中，我们将探讨如何找到自己的 TTY，它具有什么属性，它的对应文件在哪里，以及它是什么类型的 TTY：

1.  首先在终端中输入`tty`。这将告诉您在系统上使用的 TTY。在单个系统上可以有许多 TTY 和 PTY。它们每个都由系统上的一个文件表示：

```
$> tty
/dev/pts/24
```

1.  现在，让我们检查一下那个文件。正如我们在这里看到的，这是一种特殊的文件类型，称为*字符特殊*：

```
$> ls -l /dev/pts/24
crw--w---- 1 jake tty 136, 24 jan  3 23:19 /dev/pts/24
$> file /dev/pts/24 
/dev/pts/24: character special (136/24)
```

1.  现在，让我们使用一个名为`stty`的程序来检查终端的属性。`-a`选项告诉`stty`显示所有属性。我们得到的信息，例如终端的大小（行数和列数）；它的速度（只在串行终端、拨号等上重要）；用于`-parenb`的*Ctrl*键组合。所有没有减号的值，比如`cs8`，都是启用的：

```
$> stty -a
speed 38400 baud; rows 14; columns 88; line = 0;
intr = ^C; quit = ^\; erase = ^?; kill = ^U; eof = ^D; eol = M-^?; eol2 = M-^?;
swtch = <undef>; start = ^Q; stop = ^S; susp = ^Z; rprnt = ^R; werase = ^W; lnext = ^V;
discard = ^O; min = 1; time = 0;
-parenb -parodd -cmspar cs8 hupcl -cstopb cread -clocal -crtscts
-ignbrk brkint -ignpar -parmrk -inpck -istrip -inlcr -igncr icrnl ixon -ixoff -iuclc
ixany imaxbel iutf8
opost -olcuc -ocrnl onlcr -onocr -onlret -ofill -ofdel nl0 cr0 tab0 bs0 vt0 ff0
isig icanon iexten echo echoe echok -echonl -noflsh -xcase -tostop -echoprt echoctl
echoke -flusho -extproc
```

1.  还可以查看另一个终端的属性，假设您拥有它，这意味着已登录用户必须是您。如果我们尝试查看另一个用户的终端，将会收到*权限被拒绝*的错误：

```
$> stty -F /dev/pts/33 
speed 38400 baud; line = 0;
lnext = <undef>; discard = <undef>; min = 1; time = 0; -brkint -icrnl ixoff -imaxbel iutf8
-icanon -echo
$> stty -F /dev/tty2
stty: /dev/tty2: Permission denied
```

## 工作原理…

单个 Linux 系统可以有数百或数千个已登录用户。每个用户都通过 TTY 或 PTY 连接。在过去，这通常是硬件终端(TTY)通过串行线连接到计算机。如今，硬件终端相当罕见；相反，我们通过**SSH**登录或使用终端程序。

在我们的例子中，当前用户登录在`/dev/pts/24`上；那是*pts*，而不是*pty*。PTY 有两个部分，一个主部分和一个从属部分。**PTS**代表*伪终端从属*，我们连接的就是这部分。主部分打开/创建伪终端，但我们使用的是从属部分。我们将在本章稍后深入探讨这个概念。

在*步骤 3*中我们使用的设置（`-parenb`和`cs8`）意味着`parenb`被禁用，因为它有一个减号，而`cs8`被启用。`parenb`选项将生成一个奇偶校验位，并期望在输入中返回一个。奇偶校验位在拨号连接和串行通信中被广泛使用。`cs8`选项将字符大小设置为 8 位。

`stty`程序可以用来查看和设置终端的属性。在下一个食谱中，我们将返回到`stty`来更改一些值。

只要我们是终端设备的所有者，我们就可以读写它，就像我们在食谱的最后一步中看到的那样。

## 另请参阅

在`man 1 tty`和`man 1 stty`中有很多有用的信息。

# 使用 stty 更改终端设置

在这个食谱中，我们将学习如何更改终端的设置（或属性）。在上一个食谱中，我们用`stty -a`列出了我们当前的设置。在这个食谱中，我们将改变其中一些设置，使用相同的`stty`程序。

了解如何更改终端设置将使您能够根据自己的喜好进行调整。

## 准备好

这个食谱没有特殊要求。

## 如何做…

在这里，我们将更改当前终端的一些设置：

1.  让我们首先关闭`whoami`，并得到一个答案。请注意，当您输入时，您看不到`whoami`命令：

```
$> stty -echo
$> *whoami* jake 
$> 
```

1.  要再次打开回显，我们再次输入相同的命令，但不带减号。请注意，当您输入时，您看不到`stty`命令：

```
$> *stty echo*
$> whoami
jake
```

1.  我们还可以更改特殊的键序列——例如，通常情况下，EOF 字符是*Ctrl* + *D*。如果需要，我们可以将其重新绑定为一个单点（`.`）：

```
$> stty eof .
```

1.  现在输入一个单点（`.`），您当前的终端将退出或注销。当您启动一个新终端或重新登录时，设置将恢复正常。

1.  为了保存设置以便以后重用，我们首先进行必要的更改——例如，将 EOF 设置为一个点。然后，我们使用`stty --save`。该选项将打印一长串十六进制数字——这些数字就是设置。因此，为了保存它们，我们可以将`stty --save`的输出重定向到一个文件中：

```
$> stty eof .
$> stty --save
5500:5:bf:8a3b:3:1c:7f:15:2e:0:1:0:11:13:1a:0:12:f:17:16:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0
$> stty --save > my-tty-settings
```

1.  现在，按下一个点来注销。

1.  重新登录（或重新打开终端窗口）。尝试输入一个点，什么也不会发生。为了重新加载我们的设置，我们使用上一步的`my-tty-settings`文件。`$()`序列*展开*括号内的命令，然后用作`stty`的参数：

```
$> stty $(cat my-tty-settings)
```

1.  现在，我们可以再次尝试按下一个点来注销。

## 它是如何工作的…

终端通常是一个“愚蠢”的设备，因此需要大量的设置才能使其正常工作。这也是旧硬件电传打字机的遗留物之一。`stty`程序用于在终端设备上设置属性。

带有减号的选项被否定，即被禁用。没有减号的选项是启用的。在我们的例子中，我们首先关闭了回显，这是密码提示的常见做法，等等。

没有真正的方法可以保存 TTY 的设置，除了我们在这里看到的通过将其保存到文件并稍后重新读取它。

# 调查 TTY 和 PTY 并向它们写入

在这个食谱中，我们将学习如何列出当前登录的用户，他们使用的 TTY 以及他们正在运行的程序。我们还将学习如何向这些用户和终端写入。正如我们将在这个食谱中看到的，我们可以像写入文件一样向**终端设备**写入，假设我们有正确的权限。

知道如何写入其他终端会加深对终端工作原理和终端的理解。它还使您能够编写一些有趣的软件，并且最重要的是，它将使您成为一个更好的系统管理员。它还教会您有关终端安全的知识。

## 如何做…

我们将首先调查已登录用户；然后，我们将学习如何向他们发送消息：

1.  为了使事情变得更有趣，打开三到四个终端窗口。如果您没有使用**X-Window System**，请在多个 TTY 上登录。或者，如果您正在使用远程服务器，请多次登录。

1.  现在，在其中一个终端中键入`who`命令。您将获得所有已登录用户的列表，他们正在使用的 TTY/PTY，以及他们登录的日期和时间。在我的例子中，我通过 SSH 登录了多次。如果您正在使用具有多个`xterm`应用程序的本地计算机，则将看到`(:0)`而不是**Internet Protocol**（**IP**）地址：

```
$> who
root     tty1         Jan  5 16:03
jake     pts/0        Jan  5 16:04 (192.168.0.34)
jake     pts/1        Jan  5 16:04 (192.168.0.34)
jake     pts/2        Jan  5 16:04 (192.168.0.34)
```

1.  还有一个类似的命令`w`，甚至显示每个终端上的用户当前正在使用的程序：

```
$> w
 16:09:33 up 7 min,  4 users,  load average: 0.00, 0.16, 0.13
USER  TTY    FROM          LOGIN@  IDLE  JCPU   PCPU WHAT
root  tty1   -             16:03   6:05  0.07s  0.07s -bash
jake  pts/0  192.168.0.34  16:04   5:25  0.01s  0.01s -bash
jake  pts/1  192.168.0.34  16:04   0.00s 0.04s  0.01s w
jake  pts/2  192.168.0.34  16:04   5:02  0.02s  0.02s -bash
```

1.  让我们找出我们正在使用哪个终端：

```
$> tty
/dev/pts/1
```

1.  现在我们知道我们正在使用哪个终端，让我们向另一个用户和终端发送消息。在本书的开头，我提到一切都只是一个文件或一个进程。即使对于终端也是如此。这意味着我们可以使用常规重定向向终端发送数据：

```
$> echo "Hello" > /dev/pts/2
```

文本*Hello*现在将出现在 PTS2 终端上。

1.  仅当发送消息的用户与另一个终端上已登录的用户相同时，使用`echo`向终端发送消息才有效。例如，如果我尝试向 root 已登录的 TTY1 发送消息，它不起作用——有一个很好的原因：

```
$> echo "Hello" > /dev/tty1
-bash: /dev/tty1: Permission denied
```

1.  然而，存在一个允许用户向彼此终端写入的程序，假设他们已经允许。该程序称为`write`。要允许或禁止消息，我们使用`mesg`程序。如果您可以在终端上以 root（或其他用户）登录，请这样做，然后允许消息（字母`y`代表*yes*）：

```
#> tty
/dev/tty1
#> whoami
root
#> mesg y
```

1.  现在，从另一个用户，我们可以向该用户和终端写入：

```
$> write root /dev/tty1
Hello! How are you doing?
*Ctrl*+*D*
```

该消息现在将出现在 TTY1 上，其中 root 已登录。

1.  还有另一个命令允许用户在*所有*终端上写入。但是，root 是唯一可以向关闭消息的用户发送消息的用户。当以 root 身份登录时，请发出以下命令，向所有已登录用户写入有关即将重新启动的消息：

```
#> wall "The machine will be rebooted later tonight"
```

这将在所有用户的终端上显示一个消息，如下所示：

```
Broadcast message from root (tty1) (Tue Jan  5 16:59:33)
The machine will be rebooted later tonight
```

## 工作原理…

由于所有终端都由文件表示在文件系统上，因此向它们发送消息很容易。然而，常规权限也适用，以防止用户向其他用户写入或窥视其终端。

使用`write`程序，用户可以快速地向彼此写入消息，而无需任何第三方软件。

## 还有更多…

`wall`程序用于警告用户即将重新启动或关闭计算机。例如，如果 root 发出`shutdown -h +5`命令以安排在 5 分钟内关闭计算机，所有用户都将收到警告。使用`wall`程序会自动发送该警告。

## 另请参阅

有关本配方中涵盖的命令的更多信息，请参阅以下手册页面：

+   `man 1 write`

+   `man 1 wall`

+   `man 1 mesg`

# 检查它是否是 TTY

在这个配方中，我们将开始查看一些 C 函数来检查 TTY。在这里，我们指的是 TTY 的广义，即 TTY 和 PTY。

我们将在这里编写的程序将检查 stdout 是否是终端。如果不是，它将打印错误消息。

知道如何检查 stdin、stdout 或 stderr 是否是终端设备将使您能够为需要终端才能工作的程序编写错误检查。

## 准备工作

对于这个配方，我们需要 GCC 编译器，Make 工具和通用 Makefile。通用 Makefile 可以从本章的 GitHub 文件夹下载，网址为 https://github.com/PacktPublishing/Linux-System-Programming-Techniques/tree/master/ch9。

## 如何做…

在这里，我们将编写一个小程序，如果 stdout 不是终端，则打印错误消息：

1.  在文件中编写以下小程序并将其保存为`ttyinfo.c`。我们在这里使用了两个新函数。第一个是`isatty()`，它检查一个`ttyname()`，它打印连接到 stdout（或实际上是路径）的终端的名称：

```
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
int main(void)
{
    if ( (isatty(STDOUT_FILENO) == 1) )
    {
        printf("It's a TTY with the name %s\n",
            ttyname(STDOUT_FILENO));
    }
    else
    {
        perror("isatty");
    }
    printf("Hello world\n");
    return 0;
}
```

1.  编译程序：

```
$> make ttyinfo
gcc -Wall -Wextra -pedantic -std=c99    ttyinfo.c   -o ttyinfo
```

1.  让我们尝试一下这个程序。首先，我们不使用任何重定向来运行它。程序将打印终端的名称和文本*Hello world*：

```
$> ./ttyinfo 
It's a TTY with the name /dev/pts/10
Hello world
```

1.  但是，如果我们将文件描述符 1 重定向到文件，它就不再是终端（因为那个文件描述符指向文件而不是终端）。这将打印一个错误消息，但*Hello world*消息仍然被重定向到文件：

```
$> ./ttyinfo > my-file
isatty: Inappropriate ioctl for device
$> cat my-file 
Hello world
```

1.  为了证明这一点，我们可以将文件描述符 1“重定向”到`/dev/stdout`。然后一切将像往常一样工作，因为文件描述符 1 再次成为 stdout：

```
$> ./ttyinfo > /dev/stdout
It's a TTY with the name /dev/pts/10
Hello world
```

1.  另一个证明这一点的步骤是重定向到我们自己的终端设备。这将类似于我们在上一个配方中看到的，当我们使用`echo`将文本打印到终端时：

```
$> tty
/dev/pts/10
$> ./ttyinfo > /dev/pts/10 
It's a TTY with the name /dev/pts/10
Hello world
```

1.  为了进行实验，让我们打开第二个终端。使用`tty`命令找到新终端的 TTY 名称（在我的情况下是`/dev/pts/26`）。然后，从第一个终端再次运行`ttyinfo`程序，但将文件描述符 1（stdout）重定向到第二个终端：

```
$> ./ttyinfo > /dev/pts/26
```

在*当前*终端上不会显示任何输出。但是，在*第二*终端上，我们可以看到程序的输出，以及第二个终端的名称：

```
It's a TTY with the name /dev/pts/26
Hello world
```

## 工作原理...

我们使用`STDOUT_FILENO`宏，它与`isatty()`和`ttyname()`一起使用，只是整数 1-也就是文件描述符 1。

请记住，当我们用`>`符号重定向 stdout 时，我们重定向文件描述符 1。

通常，文件描述符 1 是 stdout，它连接到您的终端。如果我们使用`>`字符将文件描述符 1 重定向到文件，它将指向该文件。由于常规文件不是终端，我们会从程序（从`isatty()`函数的`errno`变量）得到一个错误消息。

当我们将文件描述符 1 重新重定向回`/dev/stdout`时，它再次成为 stdout，不会打印错误消息。

在最后一步中，当我们将程序的输出重定向到另一个终端时，所有文本都被重定向到该终端。不仅如此-程序打印的 TTY 名称确实是第二个终端的。原因是连接到文件描述符 1 的终端设备确实是那个终端（在我的情况下是`/dev/pts/26`）。

## 另请参阅

有关我们在配方中使用的函数的更多信息，我建议您阅读`man 3 isatty`和`man 3 ttyname`。

# 创建一个 PTY

在这个配方中，我们将创建一个`screen`并开始输入，字符将被打印到主设备和从设备上。从设备是`screen`程序连接的地方，在这种情况下是我们的终端。主设备通常是静默的并在后台运行，但为了演示目的，我们也会在主设备上打印字符。

了解如何创建 PTY 使您能够编写自己的终端应用程序，如`xterm`，Gnome 终端，`tmux`等。

## 准备工作

对于这个配方，您将需要 GCC 编译器，Make 工具和`screen`程序。有关`screen`的安装说明，请参阅本章的*技术要求*部分。

## 如何做...

在这里，我们将编写一个创建 PTY 的小程序。然后我们将使用`screen`连接到这个 PTY 的从端口-PTS。然后我们可以输入字符，它们会被打印回 PTS 上：

1.  我们将首先为这个配方编写程序。这里有很多新概念，所以代码被分成了几个步骤。将所有代码写在一个名为`my-pty.c`的单个文件中。我们将首先定义`_XOPEN_SOURCE`（用于`posix_openpt()`），并包括我们需要的所有头文件：

```
#define _XOPEN_SOURCE 600
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h> 
```

1.  接下来，我们将开始`main()`函数并定义一些我们需要的变量：

```
int main(void)
{
   char rxbuf[1];
   char txbuf[3];
   int master; /* for the pts master fd */
   int c; /* to catch read's return value */ 
```

1.  现在，是时候使用`posix_openpt()`创建 PTY 设备了。这将返回一个文件描述符，我们将保存在`master`中。然后，我们运行`grantpt()`，它将把设备的所有者设置为当前用户，组设置为*tty*，并将设备的模式更改为`620`。在使用之前，我们还必须使用`unlockpt()`进行解锁。为了知道我们应该连接到哪里，我们还使用`ptsname()`打印从属设备的路径：

```
   master = posix_openpt(O_RDWR);
   grantpt(master);
   unlockpt(master);
   printf("Slave: %s\n", ptsname(master));
```

1.  接下来，我们创建程序的主循环。在循环中，我们从 PTS 中读取一个字符，然后再次将其写回 PTS。在这里，我们还将字符打印到主设备上，以便我们知道它是主/从设备对。由于终端设备相当原始，我们必须手动检查**回车**字符（*Enter*键），并且打印**换行**和回车以换行：

```
  while(1) /* main loop */
   {
      /* read from the master file descriptor */
      c = read(master, rxbuf, 1);
      if (c == 1)
      {
         /* convert carriage return to '\n\r' */
         if (rxbuf[0] == '\r')
         {
            printf("\n\r"); /* on master */
            sprintf(txbuf, "\n\r"); /* on slave */
         }
         else
         { 
            printf("%c", rxbuf[0]); 
            sprintf(txbuf, "%c", rxbuf[0]);
         }
         fflush(stdout);
         write(master, txbuf, strlen(txbuf));
      }
```

1.  如果没有收到任何字符，则连接到从属设备的设备已断开。如果是这种情况，我们将返回，因此退出程序：

```
      else /* if c is not 1, it has disconnected */
      {
         printf("Disconnected\n\r");
         return 0;
      } 
   }
   return 0;
}
```

1.  现在，是时候编译程序以便我们可以运行它了：

```
$> make my-pty
gcc -Wall -Wextra -pedantic -std=c99    my-pty.c   -o my-pty
```

1.  现在，在当前终端中运行程序并记下从主设备获得的从属路径：

```
$> ./my-pty
Slave: /dev/pts/31
```

1.  在继续连接之前，让我们检查一下设备。在这里，我们将看到我的用户拥有它，它确实是一个*字符特殊*设备，对终端来说很常见：

```
$> ls -l /dev/pts/31
crw--w---- 1 jake tty 136, 31 jan  3 20:32 /dev/pts/31
$> file /dev/pts/31
/dev/pts/31: character special (136/31)
```

1.  现在，打开一个新的终端并连接到您从主设备获得的从属路径。在我的情况下，它是`/dev/pts/31`。要连接到它，我们将使用`screen`：

```
$> screen /dev/pts/31
```

1.  现在，我们可以随意输入，所有字符都将被打印回给我们。它们也将出现在主设备上。要断开并退出`screen`，首先按下*Ctrl* + *A*，然后输入一个单独的*K*，如 kill。然后会出现一个问题（*真的要杀死这个窗口吗[y/n]*）；在这里输入*Y*。现在您将在启动`my-pty`的终端中看到*已断开*，程序将退出。

## 它是如何工作的...

我们使用`posix_openpt()`函数打开一个新的 PTY。我们使用`O_RDWR`设置为读和写。通过打开一个新的 PTY，在`/dev/pts/`中创建了一个新的字符设备。这就是我们后来使用`screen`连接的字符设备。

由于`posix_openpt()`返回一个文件描述符，我们可以使用所有常规的文件描述符系统调用来读取和写入数据，比如`read`和`write`。

终端设备，比如我们在这里创建的设备，相当原始。如果我们按下*Enter*，光标将返回到行的开头。首先不会创建新行。这实际上是*Enter*键以前的工作方式。为了解决这个问题，我们在程序中检查读取的字符是否是回车（*Enter*键发送的内容），如果是，我们将首先打印一个换行字符，然后是一个回车。

如果我们只打印换行符，我们只会得到一个新行，就在当前光标下面。这种行为是从旧式电传打字机设备留下的。在打印当前字符（或换行和回车）后，我们使用`fflush()`。原因是在主端打印的字符（`my-pty`程序运行的地方）后面没有新行。Stdout 是行缓冲的，这意味着它只在换行时刷新。但是由于我们希望在输入每个字符时都能看到它，我们必须在每个字符上刷新它，使用`fflush()`。

## 另请参阅

手册页面中有很多有用的信息。我特别建议您阅读以下手册页面：`man 3 posix_openpt`，`man 3 grantpt`，`man 3 unlockpt`，`man 4 pts`和`man 4 tty`。

# 禁用密码提示的回显

为了防止用户的密码被肩窥，最好隐藏他们输入的内容。隐藏密码不被显示的方法是禁用**回显**。在这个示例中，我们将编写一个简单的密码程序，其中禁用了回显。

在编写需要某种秘密输入的程序（如密码或密钥）时，了解如何禁用回显是关键。

## 准备工作

对于这个示例，你需要 GCC 编译器、Make 工具和通用的 Makefile。

## 如何做...

在这个示例中，我们将构建一个带有密码提示的小程序

1.  由于本示例中的代码将会相当长，有些部分有点晦涩，我已经将代码分成了几个步骤。但请注意，所有的代码都应该放在一个文件中。将文件命名为`passprompt.c`。让我们从`include`行、`main()`函数和我们需要的变量开始。名为`term`的`termios`类型的结构是一个特殊的结构，它保存了终端的属性：

```
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
int main(void)
{
    char mypass[] = "super-secret";
    char buffer[80];
    struct termios term;
```

1.  接下来，我们将首先禁用回显，但首先需要使用`tcgetattr()`获取终端的所有当前设置。一旦我们获得了所有设置，我们就修改它们以禁用回显。我们这样做的方式是使用`ECHO`。`~`符号否定一个值。稍后在*它是如何工作...*部分会详细介绍：

```
    /* get the current settings */
    tcgetattr(STDIN_FILENO, &term);
    /* disable echoing */
    term.c_lflag = term.c_lflag & ~ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &term);
```

1.  然后，我们编写密码提示的代码；这里没有什么新鲜的，我们已经知道了：

```
    printf("Enter password: ");
    scanf("%s", buffer);
    if ( (strcmp(mypass, buffer) == 0) )
    {
        printf("\nCorrect password, welcome!\n");
    }
    else
    {
        printf("\nIncorrect password, go away!\n");
    }    
```

1.  然后，在退出程序之前，我们必须再次打开回显；否则，即使程序退出后，回显也将保持关闭。这样做的方法是`ECHO`。这将撤销我们之前所做的事情：

```
    /* re-enable echoing */
    term.c_lflag = term.c_lflag | ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &term);
    return 0;
}
```

1.  现在，让我们编译程序：

```
$> make passprompt
gcc -Wall -Wextra -pedantic -std=c99    passprompt.c   -o passprompt
```

1.  现在，我们可以尝试这个程序，我们会注意到我们看不到自己输入的内容：

```
$> ./passprompt 
Enter password: *test*+*Enter*
Incorrect password, go away!
$> ./passprompt 
Enter password: *super-secret*+*Enter*
Correct password, welcome!
```

## 它是如何工作的...

使用`tcsetattr()`对终端进行更改的方法是使用`tcgetattr()`获取当前属性，然后修改它们，最后将这些更改后的属性应用到终端上。

`tcgetattr()`和`tcsetattr()`的第一个参数都是我们要更改的文件描述符。在我们的情况下，是 stdin。

`tcgetattr()`的第二个参数是属性将被保存的结构。

`tcsetattr()`的第二个参数确定更改何时生效。在这里，我们使用`TCSAFLUSH`，这意味着更改发生在所有输出被写入后，所有接收但未读取的输入将被丢弃。

`tcsetattr()`的第三个参数是包含属性的结构。

为了保存和设置属性，我们需要一个名为`termios`的结构（与我们使用的头文件同名）。该结构包含五个成员，其中四个是模式。这些是输入模式（`c_iflag`）、输出模式（`c_oflag`）、控制模式（`c_cflag`）和本地模式（`c_lflag`）。我们在这里改变的是本地模式。

首先，我们在`c_lflag`成员中有当前的属性，它是一个无符号整数，由一堆位组成。这些位就是属性。

然后，要关闭一个设置，例如，在我们的情况下关闭回显，我们对`ECHO`宏进行否定（"反转"它），然后使用按位与（`&`符号）将其添加回`c_lflag`。

`ECHO`宏是`010`（八进制 10），或者十进制 8，二进制中是`00001000`（8 位）。取反后是`11110111`。然后对这些位与原始设置的其他位进行按位与操作。

按位与操作的结果然后应用到终端上，使用`tcsetattr()`关闭回显。

在结束程序之前，我们通过对新值进行按位或操作来逆转这个过程，然后使用`tcsetattr()`应用该值，再次打开回显。

## 还有更多...

我们可以通过这种方式设置很多属性，例如，可以禁用中断和退出信号的刷新等。`man 3 tcsetattr()`手册页中列出了每种模式使用的宏的完整列表。

# 读取终端大小

在这个示例中，我们将继续深入研究我们的终端。在这里，我们编写一个有趣的小程序，实时报告终端的大小。当你调整终端窗口的大小时（假设你正在使用 X 控制台应用程序），你会立即看到新的大小被报告。

为了使这个工作，我们将使用一个特殊的`ioctl()`函数。

了解如何使用这两个工具、转义序列和`ioctl()`将使您能够在终端上做一些有趣的事情。

## 准备工作

为了充分利用这个配方，最好使用`xterm`，`rxvt`，*Konsole*，*Gnome Terminal*等。

您还需要 GCC 编译器，Make 工具和通用 Makefile。

## 如何做…

在这里，我们将编写一个程序，首先使用特殊的转义序列清除屏幕，然后获取终端的大小并打印到屏幕上：

1.  在文件中写入以下代码并将其保存为`terminal-size.c`。程序使用一个无限循环，因此要退出程序，我们必须使用*Ctrl* + *C*。在循环的每次迭代中，我们首先通过打印特殊的*转义序列*来清除屏幕。然后，我们使用`ioctl()`获取终端大小并在屏幕上打印大小：

```
#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
int main(void)
{
   struct winsize termsize;
   while(1)
   {
      printf("\033[1;1H\033[2J");
      ioctl(STDOUT_FILENO, TIOCGWINSZ, &termsize);
      printf("Height: %d rows\n", 
         termsize.ws_row);
      printf("Width: %d columns\n", 
         termsize.ws_col);
      sleep(0.1);
   }
   return 0;
} 
```

1.  编译程序：

```
$> make terminal-size
gcc -Wall -Wextra -pedantic -std=c99    terminal-size.c   -o terminal-size
```

1.  现在，在终端窗口中运行程序。当程序正在运行时，调整窗口大小。您会注意到大小会立即更新。使用*Ctrl* + *C*退出程序：

```
$> ./terminal-size
Height: 20 rows
Width: 97 columns
*Ctrl*+*C*
```

## 它是如何工作的…

首先，我们定义一个名为`termsize`的结构，类型为`winsize`。我们将在这个结构中保存终端大小。该结构有两个成员（实际上有四个，但只使用了两个）。成员是`ws_row`表示行数和`wc_col`表示列数。

然后，为了清除屏幕，我们使用`printf()`打印一个特殊的转义序列，`\033[1;1H\033[2J`。`\033`序列是转义码。在转义码之后，我们有一个`[`字符，然后我们有实际的代码告诉终端要做什么。第一个`1;1H`将光标移动到位置 1,1（第一行和第一列）。然后，我们再次使用`\033`转义码，以便我们可以使用另一个代码。首先，我们有`[`字符，就像以前一样。然后，我们有`[2J`代码，这意味着擦除整个显示。

一旦我们清除了屏幕并移动了光标，我们使用`ioctl()`来获取终端大小。第一个参数是文件描述符；在这里，我们使用 stdout。第二个参数是要发送的命令；在这里，它是`TIOCGWINSZ`以获取终端大小。这些宏/命令可以在`man 2 ioctl_tty`手册页中找到。第三个参数是`winsize`结构。

一旦我们在`winsize`结构中有了尺寸，我们就使用`printf()`打印值。

为了避免耗尽系统资源，我们在下一次迭代之前睡眠 0.1 秒。

## 还有更多…

在`man 4 console_codes`手册页中，有许多其他代码可以使用。您可以做任何事情，从使用颜色到粗体字体，到移动光标，到响铃终端等等。

例如，要以闪烁的品红色打印*Hello*，然后重置为默认值，您可以使用以下命令：

```
printf("\033[35;5mHello!\033[0m\n");
```

但请注意，并非所有终端都能闪烁。

## 另请参阅

有关`ioctl()`的更多信息，请参阅`man 2 ioctl`和`man 2 ioctl_tty`手册页。后者包含有关`winsize`结构和宏/命令的信息。


# 第十章：使用不同类型的 IPC

在本章中，我们将学习通过所谓的**进程间通信**（**IPC**）的各种方式。我们将编写使用不同类型的 IPC 的各种程序，从信号和管道到 FIFO、消息队列、共享内存和套接字。

进程有时需要交换信息-例如，在同一台计算机上运行的客户端和服务器程序的情况下。也可能是一个分叉成两个进程的进程，它们需要以某种方式进行通信。

这种 IPC 可以以多种方式进行。在本章中，我们将学习一些最常见的方式。

如果您想编写不仅仅是最基本程序的程序，了解 IPC 是必不可少的。迟早，您将拥有由多个部分或多个程序组成的程序，需要共享信息。

在本章中，我们将介绍以下配方：

+   使用信号进行 IPC-为守护程序构建客户端

+   使用管道进行通信

+   FIFO-在 shell 中使用它

+   FIFO-构建发送方

+   FIFO-构建接收方

+   消息队列-创建发送方

+   消息队列-创建接收方

+   使用共享内存在子进程和父进程之间进行通信

+   在不相关的进程之间使用共享内存

+   Unix 套接字-创建服务器

+   Unix 套接字-创建客户端

让我们开始吧！

# 技术要求

对于本章，您将需要*第三章*中的 GCC 编译器，Make 工具和通用的 Makefile，*深入 Linux 中的 C 语言*。如果您尚未安装这些工具，请参阅*第一章*，*获取必要的工具并编写我们的第一个 Linux 程序*，以获取安装说明。

本章的所有代码示例和通用的 Makefile 都可以从 GitHub 上下载，网址为[`github.com/PacktPublishing/Linux-System-Programming-Techniques/tree/master/ch10`](https://github.com/PacktPublishing/Linux-System-Programming-Techniques/tree/master/ch10)。

查看以下链接以查看代码演示视频：[`bit.ly/3u3y1C0`](https://bit.ly/3u3y1C0)

# 使用信号进行 IPC-为守护程序构建客户端

在本书中，我们已经多次使用了信号。但是，当我们这样做时，我们总是使用`kill`命令来发送`my-daemon-v2`，来自*第六章*，*生成进程和使用作业控制*。

这是使用信号进行**IPC**的典型示例。守护程序有一个小的“客户端程序”来控制它，以便可以停止它，重新启动它，重新加载其配置文件等。

知道如何使用信号进行 IPC 是编写可以相互通信的程序的坚实起点。

## 准备工作

对于这个配方，你需要 GCC 编译器，Make 工具和通用的 Makefile。您还需要*第六章*中的`my-daemon-v2.c`文件，*生成进程和使用作业控制*。在本章的 GitHub 目录中有该文件的副本，网址为[`github.com/PacktPublishing/Linux-System-Programming-Techniques/tree/master/ch10`](https://github.com/PacktPublishing/Linux-System-Programming-Techniques/tree/master/ch10)。

## 如何做…

在这个配方中，我们将向*第六章*中的守护程序添加一个小的客户端程序，*生成进程和使用作业控制*。这个程序将向守护程序发送信号，就像`kill`命令一样。但是，这个程序只会向守护程序发送信号，不会发送给其他进程：

1.  在文件中编写以下代码并将其保存为`my-daemon-ctl.c`。这个程序有点长，所以它分成了几个步骤。不过所有的代码都放在同一个文件中。我们将从包含行、使用函数的原型和我们需要的所有变量开始：

```
#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <sys/types.h>
#include <signal.h>
#include <getopt.h>
#include <string.h>
#include <linux/limits.h>
void printUsage(char progname[], FILE *fp);
int main(int argc, char *argv[])
{
   FILE *fp;
   FILE *procfp;
   int pid, opt;
   int killit = 0;
   char procpath[PATH_MAX] = { 0 };
   char cmdline[PATH_MAX] = { 0 };
   const char pidfile[] = "/var/run/my-daemon.pid";
   const char daemonPath[] = 
      "/usr/local/sbin/my-daemon-v2";
```

1.  然后，我们希望能够解析命令行选项。我们只需要两个选项；即，`-h`用于帮助，`-k`用于杀死守护进程。默认情况下是显示守护进程的状态：

```
   /* Parse command-line options */
   while ((opt = getopt(argc, argv, "kh")) != -1)
   {
      switch (opt)
      {
         case 'k': /* kill the daemon */
            killit = 1;
            break;
         case 'h': /* help */
            printUsage(argv[0], stdout);
            return 0;
         default: /* in case of invalid options */
            printUsage(argv[0], stderr);
            return 1;
      }
   }
```

1.  现在，让我们打开`/proc`中的`cmdline`文件。然后，我们必须打开该文件并从中读取完整的命令行路径：

```
   if ( (fp = fopen(pidfile, "r")) == NULL )
   {
      perror("Can't open PID-file (daemon isn't "
         "running?)");
   }
   /* read the pid (and check if we could read an 
    * integer) */
   if ( (fscanf(fp, "%d", &pid)) != 1 )
   {
      fprintf(stderr, "Can't read PID from %s\n", 
         pidfile);
      return 1;
   }
   /* build the /proc path */
   sprintf(procpath, "/proc/%d/cmdline", pid);
   /* open the /proc path */
   if ( (procfp = fopen(procpath, "r")) == NULL )
   {
      perror("Can't open /proc path"
         " (no /proc or wrong PID?)");
      return 1;
   }
   /* read the cmd line path from proc */
   fscanf(procfp, "%s", cmdline); 
```

1.  既然我们既有 PID 又有完整的命令行，我们可以再次检查 PID 是否属于`/usr/local/sbin/my-daemon-v2`而不是其他进程：

```
   /* check that the PID matches the cmdline */
   if ( (strncmp(cmdline, daemonPath, PATH_MAX)) 
      != 0 )
   {
      fprintf(stderr, "PID %d doesn't belong "
         "to %s\n", pid, daemonPath);
      return 1;
   }
```

1.  如果我们给程序加上`-k`选项，我们必须将`killit`变量设置为 1。因此，在这一点上，我们必须杀死进程。否则，我们只是打印一条消息，说明守护进程正在运行：

```
   if ( killit == 1 )
   {
      if ( (kill(pid, SIGTERM)) == 0 )
      {
         printf("Successfully terminated " 
            "my-daemon-v2\n");
      }
      else
      {
         perror("Couldn't terminate my-daemon-v2");
         return 1;
      }        
   }
   else
   {
      printf("The daemon is running with PID %d\n", 
         pid);
   }
   return 0;
}
```

1.  最后，我们为`printUsage()`函数创建函数：

```
void printUsage(char progname[], FILE *fp)
{
   fprintf(fp, "Usage: %s [-k] [-h]\n", progname);
   fprintf(fp, "If no options are given, a status "
      "message is displayed.\n"
      "-k will terminate the daemon.\n"
      "-h will display this usage help.\n");       
}
```

1.  现在，我们可以编译程序了：

```
$> make my-daemon-ctl
gcc -Wall -Wextra -pedantic -std=c99    my-daemon ctl.c   -o my-daemon-ctl
```

1.  在继续之前，请确保你已经禁用并停止了*第七章**，使用 systemd 管理守护进程*中的`systemd`服务：

```
$> sudo systemctl disable my-daemon
$> sudo systemctl stop my-daemon
```

1.  现在编译守护进程（`my-daemon-v2.c`），如果你还没有这样做的话：

```
$> make my-daemon-v2
gcc -Wall -Wextra -pedantic -std=c99    my-daemon-v2.c   -o my-daemon-v2
```

1.  然后，手动启动守护进程（这次没有`systemd`服务）：

```
$> sudo ./my-daemon-v2
```

1.  现在，我们可以尝试使用我们的新程序来控制守护进程。请注意，我们不能像普通用户一样杀死守护进程：

```
$> ./my-daemon-ctl 
The daemon is running with PID 17802 and cmdline ./my-daemon-v2
$> ./my-daemon-ctl -k
Couldn't terminate daemon: Operation not permitted
$> sudo ./my-daemon-ctl -k
Successfully terminated daemon
```

1.  如果守护进程被杀死后我们重新运行程序，它会告诉我们没有 PID 文件，因此守护进程没有运行：

```
$> ./my-daemon-ctl 
Can't open PID-file (daemon isn't running?): No such file or directory
```

## 工作原理…

由于守护进程创建了 PID 文件，我们可以使用该文件获取正在运行的守护进程的 PID。当守护进程终止时，它会删除 PID 文件，因此如果没有 PID 文件，我们可以假设守护进程没有运行。

如果 PID 文件存在，首先我们从文件中读取 PID。然后，我们使用 PID 来组装该 PID 的`/proc`文件系统中的`cmdline`文件的路径。Linux 系统上的每个进程都在`/proc`文件系统中有一个目录。在每个进程的目录中，有一个名为`cmdline`的文件。该文件包含进程的完整命令行。例如，如果守护进程是从当前目录启动的，它包含`./my-daemon-v2`，而如果它是从`/usr/local/sbin/my-daemon-v2`启动的，它包含完整路径。

例如，如果守护进程的 PID 是`12345`，那么`cmdline`的完整路径是`/proc/12345/cmdline`。这就是我们用`sprintf()`组装的内容。

然后，我们读取`cmdline`的内容。稍后，我们使用该文件的内容来验证 PID 是否与名称为`my-daemon-v2`的进程匹配。这是一项安全措施，以免误杀错误的进程。如果使用`KILL`信号杀死守护进程，它就没有机会删除 PID 文件。如果将来另一个进程获得相同的 PID，我们就有可能误杀该进程。PID 号最终会被重用。

当我们有了守护进程的 PID 并验证它确实属于正确的进程时，我们将根据`-k`选项指定的内容获取其状态或将其杀死。

这就是许多用于控制复杂守护进程的控制程序的工作方式。

## 另请参阅

有关`kill()`系统调用的更多信息，请参阅`man 2 kill`手册页。

# 使用管道进行通信

在这个示例中，我们将创建一个程序，进行分叉，然后使用**管道**在两个进程之间进行通信。有时，当我们**分叉**一个进程时，**父进程**和**子进程**需要一种通信方式。管道通常是实现这一目的的简单方法。

当你编写更复杂的程序时，了解如何在父进程和子进程之间进行通信和交换数据是很重要的。

## 准备工作

对于这个示例，我们只需要 GCC 编译器、Make 工具和通用 Makefile。

## 如何做…

让我们编写一个简单的分叉程序：

1.  将以下代码写入一个文件中，并将其命名为`pipe-example.c`。我们将逐步介绍代码。请记住，所有代码都在同一个文件中。

我们将从包含行和`main()`函数开始。然后，我们将创建一个大小为 2 的整数数组。管道将在以后使用该数组。数组中的第一个整数（0）是管道读端的文件描述符。第二个整数（1）是管道的写端：

```
#define _POSIX_C_SOURCE  200809L
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#define MAX 128
int main(void)
{
   int pipefd[2] = { 0 };
   pid_t pid;
   char line[MAX];
```

1.  现在，我们将使用`pipe()`系统调用创建管道。我们将把整数数组作为参数传递给它。之后，我们将使用`fork()`系统调用进行分叉：

```
   if ( (pipe(pipefd)) == -1 )
   {
      perror("Can't create pipe");
      return 1;
   }   
   if ( (pid = fork()) == -1 )
   {
      perror("Can't fork");
      return 1;
   }
```

1.  如果我们在父进程中，我们关闭读端（因为我们只想从父进程中写入）。然后，我们使用`dprintf()`向管道的文件描述符（写端）写入消息：

```
   if (pid > 0)
   {
      /* inside the parent */
      close(pipefd[0]); /* close the read end */
      dprintf(pipefd[1], "Hello from parent");
   }
```

1.  在子进程中，我们做相反的操作；也就是说，我们关闭管道的写端。然后，我们使用`read()`系统调用从管道中读取数据。最后，我们使用`printf()`打印消息：

```
   else
   {
      /* inside the child */
      close(pipefd[1]); /* close the write end */
      read(pipefd[0], line, MAX-1);
      printf("%s\n", line); /* print message from
                             * the parent */
   }
   return 0;
}
```

1.  现在编译程序，以便我们可以运行它：

```
$> make pipe-example
gcc -Wall -Wextra -pedantic -std=c99    pipe-example.c   -o pipe-example
```

1.  让我们运行程序。父进程使用管道向子进程发送消息`Hello from parent`。然后，子进程在屏幕上打印该消息：

```
$> ./pipe-example 
Hello from parent
```

## 工作原理…

`pipe()`系统调用将两个文件描述符返回给整数数组。第一个，`pipefd[0]`，是管道的读端，而另一个，`pipefd[1]`，是管道的写端。在父进程中，我们向管道的*写端*写入消息。然后，在子进程中，我们从管道的*读端*读取数据。但在进行任何读写操作之前，我们关闭在各自进程中没有使用的管道端。

管道是一种比较常见的 IPC 技术。但是它们有一个缺点，即它们只能在相关进程之间使用；也就是说，具有共同父进程（或父进程和子进程）的进程。

还有另一种形式的管道可以克服这个限制：所谓的*命名管道*。命名管道的另一个名称是 FIFO。这是我们将在下一个示例中介绍的内容。

## 另请参阅

有关`pipe()`系统调用的更多信息可以在`man 2 pipe`手册页中找到。

# FIFO - 在 shell 中使用它

在上一个示例中，我提到`pipe()`系统调用有一个缺点——它只能在相关进程之间使用。但是，我们可以使用另一种类型的管道，称为**命名管道**。另一个名称是**先进先出**（**FIFO**）。命名管道可以在任何进程之间使用，无论是否相关。

命名管道，或者 FIFO，实际上是一种特殊类型的文件。`mkfifo()`函数在文件系统上创建该文件，就像创建任何其他文件一样。然后，我们可以使用该文件在进程之间读取和写入数据。

还有一个名为`mkfifo`的命令，我们可以直接从 shell 中使用它来创建命名管道。我们可以使用它在不相关的命令之间传输数据。

在这个命名管道的介绍中，我们将介绍`mkfifo`命令。在接下来的两个示例中，我们将编写一个使用`mkfifo()`函数的 C 程序，然后再编写另一个程序来读取管道的数据。

了解如何使用命名管道将为您作为用户、系统管理员和开发人员提供更多的灵活性。您不再只能在相关进程之间使用管道。您可以自由地在系统上的任何进程或命令之间传输数据，甚至可以在不同的用户之间传输数据。

## 准备工作

在这个示例中，我们不会编写任何程序，因此没有特殊要求。

## 操作步骤…

在这个示例中，我们将探讨`mkfifo`命令，并学习如何使用它在不相关的进程之间传输数据：

1.  我们将首先创建一个命名管道——一个 FIFO 文件。我们将在`/tmp`目录中创建它，这是临时文件的常见位置。但是，您可以在任何您喜欢的地方创建它：

```
$> mkfifo /tmp/my-fifo
```

1.  让我们通过使用`file`和`ls`命令来确认这确实是一个 FIFO。请注意我的 FIFO 的当前权限模式。它可以被所有人读取。但是在您的`umask`取决于您的系统，这可能会有所不同。但是，如果我们要传输敏感数据，我们应该对此保持警惕。在这种情况下，我们可以使用`chmod`命令进行更改：

```
$> file /tmp/my-fifo 
/tmp/my-fifo: fifo (named pipe)
$> ls -l /tmp/my-fifo 
prw-r--r-- 1 jake jake 0 jan 10 20:03 /tmp/my-fifo
```

1.  现在，我们可以尝试向管道发送数据。由于管道是一个文件，我们将在这里使用重定向而不是管道符号。换句话说，我们将数据重定向到管道。在这里，我们将`uptime`命令的输出重定向到管道。一旦我们将数据重定向到管道，进程将挂起，这是正常的，因为没有人在另一端接收数据。它实际上并不挂起；它*阻塞*：

```
$> uptime -p > /tmp/my-fifo
```

1.  打开一个新的终端并输入以下命令以从管道接收数据。请注意，第一个终端中的进程现在将结束：

```
$> cat < /tmp/my-fifo 
up 5 weeks, 6 days, 2 hours, 11 minutes
```

1.  我们也可以做相反的事情；也就是说，我们可以首先打开接收端，然后向管道发送数据。这将**阻塞**接收进程，直到获得一些数据。运行以下命令设置接收端，并让其运行：

```
$> cat < /tmp/my-fifo
```

1.  现在，我们使用相同的`uptime`命令向管道发送数据。请注意，一旦数据被接收，第一个进程将结束：

```
$> uptime -p > /tmp/my-fifo
```

1.  还可以从多个进程向 FIFO 发送数据。打开三个新的终端。在每个终端中，输入以下命令，但将第二个终端替换为 2，第三个终端替换为 3：

```
$> echo "Hello from terminal 1" > /tmp/my-fifo
```

1.  现在，打开另一个终端并输入以下命令。这将接收所有消息：

```
$> cat < /tmp/my-fifo
Hello from terminal 3
Hello from terminal 1
Hello from terminal 2
```

## 它是如何工作的…

FIFO 只是文件系统上的一个文件，尽管是一个特殊的文件。一旦我们将数据重定向到 FIFO，该进程将**阻塞**（或“挂起”），直到另一端接收到数据。

同样，如果我们首先启动接收进程，该进程将阻塞，直到获取管道的数据。这种行为的原因是 FIFO 不是我们可以保存数据的常规文件。我们只能用它重定向数据；也就是说，它只是一个*管道*。因此，如果我们向其发送数据，但另一端没有任何东西，进程将在那里等待，直到有人在另一端接收它。数据在管道中无处可去，直到有人连接到接收端。

还有更多...

如果系统上有多个用户，您可以尝试使用 FIFO 向它们发送消息。这样做为我们提供了一种在用户之间复制和粘贴数据的简单方法。请注意，FIFO 的权限模式必须允许其他用户读取它（如果需要，还可以写入它）。可以在创建 FIFO 时直接设置所需的权限模式，使用`-m`选项。例如，`mkfifo /tmp/shared-fifo -m 666`将允许任何用户读取和写入 FIFO。

## 另请参阅

在`man 1 mkfifo`手册页中有关于`mkfifo`命令的更多信息。有关 FIFO 的更深入解释，请参阅`man 7 fifo`手册页。

# FIFO - 构建发送方

现在我们知道了 FIFO 是什么，我们将继续编写一个可以创建和使用 FIFO 的程序。在这个示例中，我们将编写一个创建 FIFO 然后向其发送消息的程序。在下一个示例中，我们将编写一个接收该消息的程序。

了解如何在程序中使用 FIFO 将使您能够编写可以直接使用 FIFO 进行通信的程序，而无需通过 shell 重定向数据。

## 准备工作

我们需要常规工具；即 GCC 编译器、Make 工具和通用 Makefile。

## 如何做…

在这个示例中，我们将编写一个创建 FIFO 并向其发送消息的程序：

1.  在文件中写入以下代码并将其保存为`fifo-sender.c`。这段代码有点长，所以我们将在这里逐步介绍它。请记住，所有代码都放在同一个文件中。让我们从`#include`行、信号处理程序的原型和一些全局变量开始：

```
#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
void cleanUp(int signum);
int fd; /* the FIFO file descriptor */
const char fifoname[] = "/tmp/my-2nd-fifo";
```

1.  现在，我们可以开始编写`main()`函数。首先，我们将为`sigaction()`函数创建结构体。然后，我们将检查用户是否提供了消息作为参数：

```
int main(int argc, char *argv[])
{
   struct sigaction action; /* for sigaction */
   if ( argc != 2 )
   {
      fprintf(stderr, "Usage: %s 'the message'\n",
         argv[0]);
      return 1;
   }
```

1.  现在，我们必须为我们想要捕获的所有信号注册信号处理程序。我们这样做是为了在程序退出时删除 FIFO。请注意，我们还注册了`SIGPIPE`信号——关于这一点，我们将在*它是如何工作的…*部分详细说明：

```
   /* prepare for sigaction and register signals
    * (for cleanup when we exit) */
   action.sa_handler = cleanUp;
   sigfillset(&action.sa_mask);
   action.sa_flags = SA_RESTART;
   sigaction(SIGTERM, &action, NULL);
   sigaction(SIGINT, &action, NULL);
   sigaction(SIGQUIT, &action, NULL);
   sigaction(SIGABRT, &action, NULL);
   sigaction(SIGPIPE, &action, NULL);
```

1.  现在，让我们使用模式`644`创建 FIFO。由于模式`644`是八进制的，我们需要在 C 代码中写为`0644`；否则，它将被解释为 644 十进制（在 C 中以 0 开头的任何数字都是八进制数）。之后，我们必须使用`open()`系统调用打开 FIFO——与我们用于打开常规文件的系统调用相同：

```
   if ( (mkfifo(fifoname, 0644)) != 0 )
   {
      perror("Can't create FIFO");
      return 1;
   }
   if ( (fd = open(fifoname, O_WRONLY)) == -1)
   {
      perror("Can't open FIFO");
      return 1;
   }
```

1.  现在，我们必须创建一个无限循环。在这个循环内，我们将每秒打印一次用户提供的消息。循环结束后，我们将关闭文件描述符并删除 FIFO 文件。不过在正常情况下，我们不应该达到这一步：

```
   while(1)
   {
      dprintf(fd, "%s\n", argv[1]);
      sleep(1);
   }
   /* just in case, but we shouldn't reach this */
   close(fd);
   unlink(fifoname);
   return 0;
}
```

1.  最后，我们必须创建`cleanUp()`函数，这是我们注册为信号处理程序的函数。我们使用这个函数在程序退出之前进行清理。然后，我们必须关闭文件描述符并删除 FIFO 文件：

```
void cleanUp(int signum)
{
   if (signum == SIGPIPE)
      printf("The receiver stopped receiving\n");
   else
      printf("Aborting...\n");
   if ( (close(fd)) == -1 )
      perror("Can't close file descriptor");
   if ( (unlink(fifoname)) == -1)
   {
      perror("Can't remove FIFO");
      exit(1);
   }
   exit(0);
}
```

1.  让我们编译程序：

```
$> make fifo-sender
gcc -Wall -Wextra -pedantic -std=c99    fifo-sender.c   -o fifo-sender
```

1.  让我们运行程序：

```
$> ./fifo-sender 'Hello everyone, how are you?'
```

1.  现在，启动另一个终端，以便使用`cat`接收消息。我们在程序中使用的文件名是`/tmp/my-2nd-fifo`。消息将每秒重复一次。几秒钟后，按下*Ctrl* + *C*退出`cat`：

```
$> cat < /tmp/my-2nd-fifo 
Hello everyone, how are you?
Hello everyone, how are you?
Hello everyone, how are you?
*Ctrl**+**P* 
```

1.  现在，返回到第一个终端。您会注意到它显示*接收器停止接收*。

1.  在第一个终端中再次启动`fifo-sender`程序。

1.  再次转到第二个终端，并重新启动`cat`程序以接收消息。让`cat`程序继续运行：

```
$> cat < /tmp/my-2nd-fifo
```

1.  当第二个终端上的 cat 程序正在运行时，返回到第一个终端，并通过按下*Ctrl* + *C*中止`fifo-sender`程序。请注意，这次它显示*Aborting*：

```
Ctrl+C
^CAborting...
```

第二个终端中的`cat`程序现在已退出。

## 它是如何工作的…

在这个程序中，我们注册了一个之前没有见过的额外信号：`SIGPIPE`信号。当另一端终止时，在我们的情况下是`cat`程序，我们的程序将收到一个`SIGPIPE`信号。如果我们没有捕获该信号，我们的程序将以信号 141 退出，并且不会发生清理。从这个退出代码，我们可以推断出这是由于`SIGPIPE`信号引起的，因为 141-128 = 13；信号 13 是`SIGPIPE`。有关保留返回值的解释，请参见*第二章*中的*图 2.2*，*使您的程序易于脚本化*。

在`cleanUp()`函数中，我们使用该信号号（`SIGPIPE`，它是 13 的宏）在接收器停止接收数据时打印特殊消息。

如果我们改为通过按下*Ctrl* + *C*中止`fifo-sender`程序，我们会得到另一条消息；即*Aborted*。

`mkfifo()`函数为我们创建了一个指定模式的 FIFO 文件。在这里，我们将模式指定为一个八进制数。在 C 中，任何以 0 开头的数字都是八进制数。

由于我们使用`open()`系统调用打开 FIFO，我们得到了一个`dprintf()`来将用户的消息打印到管道中。程序的第一个参数—`argv[1]`—是用户的消息。

只要 FIFO 在程序中保持打开状态，`cat`也将继续监听。这就是为什么我们可以在循环中每秒重复一次消息。

## 另请参阅

有关`mkfifo()`函数的深入解释，请参阅`man 3 mkfifo`。

有关可能信号的列表，请参阅`kill -L`。

要了解有关`dprintf()`的更多信息，请参阅`man 3 dprintf`手册页。

# FIFO – 构建接收器

在上一个示例中，我们编写了一个创建 FIFO 并向其写入消息的程序。我们还使用`cat`进行了测试以接收消息。在这个示例中，我们将编写一个 C 程序，从 FIFO 中读取。

从 FIFO 中读取与从常规文件或标准输入读取没有任何不同。

## 准备工作

在开始本教程之前，最好先完成上一个教程。我们将使用上一个教程中的程序将数据写入我们将在本教程中接收的 FIFO 中。

您还需要常规工具；即 GCC 编译器、Make 工具和通用 Makefile。

## 操作步骤如下...

在本教程中，我们将为前一个教程中编写的发送程序编写一个接收程序。让我们开始：

1.  将以下代码写入文件并保存为`fifo-receiver.c`。我们将使用文件流打开 FIFO，然后在循环中逐个字符读取，直到我们得到**文件结束**（**EOF**）：

```
#include <stdio.h>
int main(void)
{
    FILE *fp;
    signed char c;
    const char fifoname[] = "/tmp/my-2nd-fifo";
    if ( (fp = fopen(fifoname, "r")) == NULL )
    {
        perror("Can't open FIFO");
        return 1;
    }
    while ( (c = getc(fp)) != EOF )
        putchar(c);
    fclose(fp);
    return 0;
}
```

1.  编译程序：

```
$> make fifo-receiver
gcc -Wall -Wextra -pedantic -std=c99    fifo-receiver.c   -o fifo-receiver
```

1.  从上一个教程中启动`fifo-sender`并让其运行：

```
$> ./fifo-sender 'Hello from the sender'
```

1.  打开第二个终端并运行我们刚刚编译的`fifo-receiver`。在几秒钟后按*Ctrl* + *C*中止它：

```
fifo-sender will also abort, just like when we used the cat command to receive the data.
```

## 工作原理...

由于 FIFO 是文件系统上的一个文件，我们可以使用 C 中的常规函数（如文件流、`getc()`、`putchar()`等）从中接收数据。

这个程序类似于*第五章*中的`stream-read.c`程序，*使用文件 I/O 和文件系统操作*，只是这里我们逐个字符读取而不是逐行读取。

## 另请参阅

有关`getc()`和`putchar()`的更多信息，请参阅`man 3 getc`和`man 3 putchar`手册页。

# 消息队列 - 创建发送程序

另一种流行的 IPC 技术是**消息队列**。这基本上就是名字所暗示的。一个进程将消息留在队列中，另一个进程读取它们。

Linux 上有两种类型的消息队列：`mq_`函数，如`mq_open()`，`mq_send()`等。

了解如何使用消息队列使您能够从各种 IPC 技术中进行选择。

## 准备工作

对于本教程，我们只需要 GCC 编译器和 Make 工具。

## 操作步骤如下...

在本教程中，我们将创建发送程序。这个程序将创建一个新的消息队列并向其中添加一些消息。在下一个教程中，我们将接收这些消息：

1.  将以下代码写入文件并保存为`msg-sender.c`。由于代码中有一些新内容，我已将其分解为几个步骤。所有代码都放在一个文件中，名为`msg-sender.c`。

让我们从所需的头文件开始。我们还为最大消息大小定义了一个宏。然后，我们将创建一个名为`msgattr`的`mq_attr`类型的结构。然后设置它的成员；也就是说，我们将`mq_maxmsg`设置为 10，`mq_msgsize`设置为`MAX_MSG_SIZE`。第一个`mq_maxmsg`指定队列中的消息总数。第二个`mq_msgsize`指定消息的最大大小：

```
#include <stdio.h>
#include <mqueue.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#define MAX_MSG_SIZE 2048
int main(int argc, char *argv[])
{
   int md; /* msg queue descriptor */
   /* attributes for the message queue */
   struct mq_attr msgattr;
   msgattr.mq_maxmsg = 10;
   msgattr.mq_msgsize = MAX_MSG_SIZE;
```

1.  我们将把程序的第一个参数作为消息。因此，在这里，我们将检查用户是否输入了参数：

```
   if ( argc != 2)
   {
      fprintf(stderr, "Usage: %s 'my message'\n",
         argv[0]);
      return 1;
   }
```

1.  现在，是时候用`mq_open()`打开并创建消息队列了。第一个参数是队列的名称；在这里，它是`/my_queue`。第二个参数是标志，我们的情况下是`O_CREATE`和`O_RDWR`。这些是我们之前见过的相同标志，例如`open()`。第三个参数是权限模式；再次，这与文件相同。第四个和最后一个参数是我们之前创建的结构。`mq_open()`函数然后将消息队列描述符返回给`md`变量。

最后，我们使用`mq_send()`将消息发送到队列。这里，首先，我们给它`md`描述符。然后，我们有要发送的消息，在本例中是程序的第一个参数。然后，作为第三个参数，我们必须指定消息的大小。最后，我们必须为消息设置一个优先级；在这种情况下，我们将选择 1。它可以是任何正数（无符号整数）。

在退出程序之前，我们将做的最后一件事是使用`mq_close()`关闭消息队列描述符：

```
   md = mq_open("/my_queue", O_CREAT|O_RDWR, 0644, 
      &msgattr); 
   if ( md == -1 )
   {
      perror("Creating message queue");
      return 1;
   }
   if ( (mq_send(md, argv[1], strlen(argv[1]), 1))
      == -1 )
   {
      perror("Message queue send");
      return 1;
   }
   mq_close(md);
   return 0;
}
```

1.  编译程序。请注意，我们必须链接`rt`库，该库代表**实时扩展库**：

```
$> gcc -Wall -Wextra -pedantic -std=c99 -lrt \
> msg-sender.c -o msg-sender
```

1.  现在，运行程序并向队列发送三到四条消息：

```
$> ./msg-sender "The first message to the queue"
$> ./msg-sender "The second message"
$> ./msg-sender "And another message"
```

## 工作原理…

在这个食谱中，我们使用了 POSIX 消息队列函数来创建一个新队列，然后向其发送消息。当我们创建队列时，我们指定该队列可以包含最多 10 条消息，使用`msgattr`的`mq_maxmsg`成员。

我们还使用`mq_msgsize`成员将每条消息的最大长度设置为 2,048 个字符。

当我们调用`mq_open()`时，我们将队列命名为`/my_queue`。消息队列必须以斜杠开头。

队列创建后，我们使用`mq_send()`向其发送消息。

在这个食谱的最后，我们向队列发送了三条消息。这些消息现在已排队，等待接收。在下一个食谱中，我们将学习如何编写一个接收这些消息并在屏幕上打印它们的程序。

## 另请参阅

在 Linux 的`man 7 mq_overview`手册页中有关于 POSIX 消息队列功能的很好的概述。

# 消息队列 - 创建接收器

在上一个食谱中，我们构建了一个程序，创建了一个名为`/my_queue`的消息队列，然后向其发送了三条消息。在这个食谱中，我们将创建一个接收来自该队列的消息的程序。

## 准备工作

在开始这个食谱之前，您需要完成上一个食谱。否则，我们将收不到任何消息。

您还需要 GCC 编译器和 Make 工具来完成这个食谱。

## 操作步骤…

在这个食谱中，我们将接收上一个食谱中发送的消息：

1.  在文件中写入以下代码，并将其保存为`msg-receiver.c`。这段代码比发送程序的代码要长一些，因此它被分成了几个步骤，每个步骤都解释了一部分代码。不过，请记住，所有代码都放在同一个文件中。我们将从头文件、变量、结构和名为`buffer`的字符指针开始。稍后我们将使用它来分配内存：

```
#include <stdio.h>
#include <mqueue.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
int main(void)
{
   int md; /* msg queue descriptor */
   char *buffer;
   struct mq_attr msgattr;
```

1.  下一步是使用`mq_open()`打开消息队列。这次，我们只需要提供两个参数；队列的名称和标志。在这种情况下，我们只想从队列中读取：

```
   md = mq_open("/my_queue", O_RDONLY);
   if (md == -1 )
   {
      perror("Open message queue");
      return 1;
   }
```

1.  现在，我们还想使用`mq_getattr()`获取消息队列的属性。一旦我们有了队列的属性，我们就可以使用其`mq_msgsize`成员使用`calloc()`为该大小的消息分配内存。在本书中，我们之前没有看到`calloc()`。第一个参数是我们要为其分配内存的元素数，而第二个参数是每个元素的大小。然后，`calloc()`函数返回指向该内存的指针（在我们的情况下，就是`buffer`）：

```
   if ( (mq_getattr(md, &msgattr)) == -1 )
   {
      perror("Get message attribute");
      return 1;
   }
   buffer = calloc(msgattr.mq_msgsize, 
      sizeof(char));
   if (buffer == NULL)
   {
      fprintf(stderr, "Couldn't allocate memory");
      return 1;
   }
```

1.  接下来，我们将使用`mq_attr`结构的另一个成员`mq_curmsgs`，它包含队列中当前的消息数。首先，我们将打印消息数。然后，我们将使用`for`循环遍历所有消息。在循环内部，首先使用`mq_receive`接收消息。然后，我们使用`printf()`打印消息。最后，在迭代下一条消息之前，我们使用`memset()`将整个内存重置为 NULL 字符。

`mq_receive`的第一个参数是描述符，第二个参数是消息所在的缓冲区，第三个参数是消息的大小，第四个参数是消息的优先级，在这种情况下是 NULL，表示我们首先接收所有最高优先级的消息：

```
   printf("%ld messages in queue\n", 
      msgattr.mq_curmsgs);
   for (int i = 0; i<msgattr.mq_curmsgs; i++)
   {
      if ( (mq_receive(md, buffer, 
      msgattr.mq_msgsize, NULL)) == -1 )
      {
         perror("Message receive");
         return 1;
      }
      printf("%s\n", buffer);
      memset(buffer, '\0', msgattr.mq_msgsize);
   }
```

1.  最后，我们有一些清理工作要做。首先，我们必须使用`free()`释放缓冲区指向的内存。然后，我们必须关闭`md`队列描述符，然后使用`mq_unlink()`从系统中删除队列：

```
   free(buffer);
   mq_close(md);
   mq_unlink("/my_queue");
   return 0;
}
```

1.  现在，是时候编译程序了：

```
$> gcc -Wall -Wextra -pedantic -std=c99 -lrt \
> msg-reveiver.c -o msg-reveiver
```

1.  最后，让我们使用我们的新程序接收消息：

```
$> ./msg-reveiver 
3 messages in queue
The first message to the queue
The second message
And another message
```

1.  如果我们现在尝试重新运行程序，它将简单地指出没有这样的文件或目录存在。这是因为我们使用`mq_unlink()`删除了消息队列：

```
$> ./msg-reveiver 
Open message queue: No such file or directory
```

## 工作原理…

在上一个示例中，我们向`/my_queue`发送了三条消息。使用本示例中创建的程序，我们接收了这些消息。

要打开队列，我们使用了创建队列时使用的相同函数；也就是`mq_open()`。但这一次——因为我们正在打开一个已经存在的队列——我们只需要提供两个参数；即队列的名称和标志。

对`mq_`函数的每次调用都进行错误检查。如果发生错误，我们将使用`perror()`打印错误消息，并返回到 shell 并返回 1。

在从队列中读取实际消息之前，我们使用`mq_getattr()`获取队列的属性。通过这个函数调用，我们填充了`mq_attr`结构。对于读取消息来说，最重要的两个成员是`mq_msgsize`，它是队列中每条消息的最大大小，以及`mq_curmsgs`，它是当前队列中的消息数。

我们使用`mq_msgsize`中的最大消息大小来使用`calloc()`为消息缓冲区分配内存。`calloc()`函数返回“零化”的内存，而它的对应函数`malloc()`则不会。

要分配内存，我们需要创建一个指向我们想要的类型的指针。这就是我们在程序开始时使用`char *buffer`所做的。`calloc()`函数接受两个参数：要分配的元素数量和每个元素的大小。在这里，我们希望元素的数量与`mq_msgsize`值包含的相同。而每个元素都是`char`，所以每个元素的大小应该是`sizeof(char)`。然后函数返回一个指向内存的指针，在我们的情况下保存在`char`指针的`buffer`中。

然后，当我们接收队列消息时，我们在循环的每次迭代中将它们保存在这个缓冲区中。

循环遍历所有消息。我们从`mq_curmsgs`成员中得到消息的数量。

最后，一旦我们读完了所有的消息，我们关闭并删除了队列。

## 另请参阅

关于`mq_attr`结构的更多信息，我建议你阅读`man 3 mq_open`手册页面。

我们在这个和上一个示例中涵盖的每个函数都有自己的手册页面；例如，`man 3 mq_send`，`man 3 mq_recevie`，`man 3 mq_getattr`等等。

如果你对`calloc()`和`malloc()`函数不熟悉，我建议你阅读`man 3 calloc`。这个手册页面涵盖了`malloc()`，`calloc()`，`free()`和一些其他相关函数。

`memset()`函数也有自己的手册页面；即`man 3 memset`。

# 使用共享内存在子进程和父进程之间通信

在这个示例中，我们将学习如何在两个相关的进程——父进程和子进程之间使用**共享内存**。共享内存以各种形式存在，并且可以以不同的方式使用。在本书中，我们将专注于 POSIX 共享内存函数。

Linux 中的共享内存可以在相关进程之间使用，正如我们将在本示例中探讨的那样，还可以在无关的进程之间使用`/dev/shm`目录。我们将在下一个示例中看到这一点。

在这个示例中，我们将使用*匿名*共享内存——即不由文件支持的内存。

共享内存就像它听起来的那样——一块在进程之间共享的内存。

了解如何使用共享内存将使您能够编写更高级的程序。

## 准备工作

对于这个示例，您只需要 GCC 编译器和 Make 工具。

## 如何做…

在这个示例中，我们将编写一个使用共享内存的程序。首先，在分叉之前，进程将向共享内存写入一条消息。然后，在分叉之后，子进程将替换共享内存中的消息。最后，父进程将再次替换共享内存的内容。让我们开始吧：

1.  将以下代码写入一个文件中，并将其命名为`shm-parent-child.c`。像往常一样，我将把代码分成几个较小的步骤。尽管所有的代码都放在同一个文件中。首先，我们将写入所有的头文件。这里有相当多的头文件。我们还将为我们的内存大小定义一个宏。然后，我们将我们的三条消息写成字符数组常量：

```
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#define DATASIZE 128
int main(void)
{
   char *addr;
   int status;
   pid_t pid;
   const char startmsg[] = "Hello, we are running";
   const char childmsg[] = "Hello from child";
   const char parentmsg[] = "New msg from parent";
```

1.  现在来到令人兴奋的部分——映射共享内存空间。我们需要向内存映射函数`mmap()`提供总共六个参数。

第一个参数是内存地址，我们将其设置为 NULL——这意味着内核会为我们处理它。

第二个参数是内存区域的大小。

第三个参数是内存应该具有的保护。在这里，我们将其设置为可写和可读。

第四个参数是我们的标志，我们将其设置为共享和匿名——这意味着它可以在进程之间共享，并且不会由文件支持。

第五个参数是文件描述符。但在我们的情况下，我们使用的是匿名的，这意味着这块内存不会由文件支持。因此，出于兼容性原因，我们将其设置为-1。

最后一个参数是偏移量，我们将其设置为 0：

```
   addr = mmap(NULL, DATASIZE, 
      PROT_WRITE | PROT_READ, 
      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
   if (addr == MAP_FAILED)
   {
      perror("Memory mapping failed");
      return 1;
   }
```

1.  现在内存已经准备好了，我们将使用`memcpy()`将我们的第一条消息复制到其中。`memcpy()`的第一个参数是指向内存的指针，在我们的例子中是`addr`字符指针。第二个参数是我们要从中复制的数据或消息，在我们的例子中是`startmsg`。最后一个参数是我们要复制的数据的大小，在这种情况下是`startmsg`中字符串的长度+1。`strlen()`函数不包括终止的空字符；这就是为什么我们需要加 1。

然后，我们打印进程的 PID 和共享内存中的消息。之后，我们进行分叉：

```
   memcpy(addr, startmsg, strlen(startmsg) + 1);
   printf("Parent PID is %d\n", getpid());
   printf("Original message: %s\n", addr);
   if ( (pid = fork()) == -1 )
   {
      perror("Can't fork");
      return 1;
   }
```

1.  如果我们在子进程中，我们将子进程的消息复制到共享内存中。如果我们在父进程中，我们将等待子进程。然后，我们可以将父进程的消息复制到内存中，并打印两条消息。最后，我们将通过取消映射共享内存来清理。尽管这并不是严格要求的：

```
   if (pid == 0)
   {
      /* child */
      memcpy(addr, childmsg, strlen(childmsg) + 1);
   }
   else if(pid > 0)
   {
      /* parent */
      waitpid(pid, &status, 0);
      printf("Child executed with PID %d\n", pid);
      printf("Message from child: %s\n", addr);
      memcpy(addr, parentmsg, 
         strlen(parentmsg) + 1);
      printf("Parent message: %s\n", addr);
   }
   munmap(addr, DATASIZE);
   return 0;
}
```

1.  编译程序，以便我们可以试一试。请注意，我们在这里使用了另一个 C 标准——`MAP_ANONYMOUS`宏，但**GNU11**有。**GNU11**是**C11**标准，带有一些额外的 GNU 扩展。还要注意，我们链接了*实时扩展*库：

```
$> gcc -Wall -Wextra -std=gnu11 -lrt \
> shm-parent-child.c -o shm-parent-child
```

1.  现在，我们可以测试程序了：

```
$> ./shm-parent-child 
Parent PID is 9683
Original message: Hello, we are running
Child executed with PID 9684
Message from child: Hello from child
Parent message: New msg from parent
```

## 工作原理…

共享内存是不相关进程、相关进程和线程之间的常见 IPC 技术。在这个示例中，我们看到了如何在父进程和子进程之间使用共享内存。

使用`mmap()`映射内存区域。这个函数返回映射内存的地址。如果发生错误，它将返回`MAP_FAILED`宏。一旦我们映射了内存，我们就检查指针变量是否为`MAP_FAILED`，并在出现错误时中止它。

一旦我们映射了内存并获得了指向它的指针，我们就使用`memcpy()`将数据复制到其中。

最后，我们使用`munmap()`取消映射内存。这并不是严格必要的，因为当最后一个进程退出时，它将被取消映射。但是，不这样做是一个不好的习惯。您应该始终在使用后进行清理，并释放任何分配的内存。

## 另请参阅

有关`mmap()`和`munmap()`的更详细解释，请参见`man 2 mmap`手册页。有关`memcpy()`的详细解释，请参见`man 3 memcpy`手册页。

有关各种 C 标准及 GNU 扩展的更详细解释，请参见[`gcc.gnu.org/onlinedocs/gcc/Standards.html`](https://gcc.gnu.org/onlinedocs/gcc/Standards.html)。

# 在不相关进程之间使用共享内存

在之前的示例中，我们在子进程和父进程之间使用了共享内存。在这个示例中，我们将学习如何使用文件描述符将映射内存共享给两个不相关的进程。以这种方式使用共享内存会自动在`/dev/shm`目录中创建内存的底层文件，其中**shm**代表**共享内存**。

了解如何在不相关的进程之间使用共享内存扩大了您使用这种 IPC 技术的范围。

## 准备工作

对于这个示例，您只需要 GCC 编译器和 Make 工具。

## 操作步骤…

首先，我们将编写一个程序，打开并创建一个共享内存的文件描述符，并映射内存。然后，我们将编写另一个程序来读取内存区域。与之前的示例不同，这次我们将在这里写入和检索一个由三个浮点数组成的**数组**，而不仅仅是一个消息。

### 创建写入程序

首先让我们创建写入程序：

1.  第一步是创建一个程序，用于创建共享内存并向其写入一些数据。将以下代码写入文件并保存为`write-memory.c`。和往常一样，代码将被分成几个步骤，但所有代码都放在一个文件中。

就像在之前的示例中一样，我们将有一堆头文件。然后，我们将创建所有需要的变量。在这里，我们需要一个文件描述符变量。请注意，即使我在这里称其为文件描述符，它实际上是一个内存区域的描述符。`memid`包含内存映射描述符的名称。然后，我们必须使用`shm_open()`来打开和创建“文件描述符”：

```
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#define DATASIZE 128
int main(void)
{
   int fd;
   float *addr;
   const char memid[] = "/my_memory";
   const float numbers[3] = { 3.14, 2.718, 1.202};
   /* create shared memory file descriptor */
   if ( (fd = shm_open(memid, 
      O_RDWR | O_CREAT, 0600)) == -1)
   {
      perror("Can't open memory fd");
      return 1;
   }
```

1.  文件支持的内存最初大小为 0 字节。要将其扩展到我们的 128 字节，我们必须使用`ftruncate()`进行截断。

```
   /* truncate memory to DATASIZE */
   if ( (ftruncate(fd, DATASIZE)) == -1 )
   {
      perror("Can't truncate memory");
      return 1;
   }
```

1.  现在，我们必须映射内存，就像我们在之前的示例中所做的那样。但是这次，我们将给它`fd`文件描述符，而不是-1。我们还省略了`MAP_ANONYMOUS`部分，从而使这个内存由文件支持。然后，我们必须使用`memcpy()`将我们的浮点数数组复制到内存中。为了让读取程序有机会读取内存，我们必须暂停程序，并使用`getchar()`等待*Enter*键。然后，只需要清理工作，取消映射内存，并使用`shm_unlink()`删除文件描述符和底层文件：

```
   /* map memory using our file descriptor */
   addr = mmap(NULL, DATASIZE, PROT_WRITE, 
      MAP_SHARED, fd, 0);
   if (addr == MAP_FAILED)
   {
      perror("Memory mapping failed");
      return 1;
   }
   /* copy data to memory */
   memcpy(addr, numbers, sizeof(numbers));
   /* wait for enter */
   printf("Hit enter when finished ");
   getchar();
   /* clean up */
   munmap(addr, DATASIZE);
   shm_unlink(memid);
   return 0;
}
```

1.  现在，让我们编译这个程序：

```
$> gcc -Wall -Wextra -std=gnu11 -lrt write-memory.c \
> -o write-memory
```

### 创建读取程序

现在，让我们创建读取程序：

1.  现在，我们将编写一个程序，用于读取内存区域并打印数组中的数字。编写以下程序并将其保存为`read-memory.c`。这个程序类似于`write-memory.c`，但不是向内存写入，而是从内存读取：

```
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#define DATASIZE 128
int main(void)
{
   int fd;
   float *addr;
   const char memid[] = "/my_memory";
   float numbers[3];
   /* open memory file descriptor */
   fd = shm_open(memid, O_RDONLY, 0600);
   if (fd == -1)
   {
      perror("Can't open file descriptor");
      return 1;
   }
   /* map shared memory */
   addr = mmap(NULL, DATASIZE, PROT_READ, 
      MAP_SHARED, fd, 0);
   if (addr == MAP_FAILED)
   {
      perror("Memory mapping failed");
      return 1;
   }
   /* read the memory and print the numbers */
   memcpy(numbers, addr, sizeof(numbers));
   for (int i = 0; i<3; i++)
   {
      printf("Number %d: %.3f\n", i, numbers[i]);
   }
   return 0;
}
```

1.  现在，编译这个程序：

```
$> gcc -Wall -Wextra -std=gnu11 -lrt read-memory.c \
> -o read-memory
```

### 测试一切

按照以下步骤进行：

1.  现在，是时候尝试一切了。打开终端并运行我们编译的`write-memory`程序。让程序保持运行：

```
$> ./write-memory 
Hit enter when finished
```

1.  打开另一个终端，查看`/dev/shm`中的文件：

```
$> ls -l /dev/shm/my_memory 
-rw------- 1 jake jake 128 jan 18 19:19 /dev/shm/my_memory
```

1.  现在运行我们刚刚编译的`read-memory`程序。这将从共享内存中检索三个数字并将它们打印在屏幕上：

```
$> ./read-memory 
Number 0: 3.140
Number 1: 2.718
Number 2: 1.202
```

1.  返回运行`write-memory`程序的终端，然后按*Enter*。这样做将清理并删除文件。完成后，让我们看看文件是否仍然在`/dev/shm`中：

```
./write-memory 
Hit enter when finished Enter
$> ls -l /dev/shm/my_memory
ls: cannot access '/dev/shm/my_memory': No such file or directory
```

## 工作原理…

使用非匿名共享内存与我们在之前的示例中所做的类似。唯一的例外是，我们首先使用`shm_open()`打开一个特殊的文件描述符。正如您可能已经注意到的，标志与常规的`open()`调用相似；即，`O_RDWR`用于读取和写入，`O_CREATE`用于在文件不存在时创建文件。以这种方式使用`shm_open()`会在`/dev/shm`目录中创建一个文件，文件名由第一个参数指定。甚至权限模式设置方式与常规文件相同——在我们的情况下，`0600`用于用户读写，其他人没有权限。

我们从`shm_open()`获得的文件描述符然后传递给`mmap()`调用。我们还在`mmap()`调用中省略了`MAP_ANONYMOUS`宏，就像我们在前面的示例中看到的那样。跳过`MAP_ANONYMOUS`意味着内存将不再是匿名的，这意味着它将由文件支持。我们使用`ls -l`检查了这个文件，并看到它确实有我们给它的名称和正确的权限。

我们编写的下一个程序使用`shm_open()`打开了相同的共享内存文件描述符。在`mmap()`之后，我们循环遍历了内存区域中的浮点数。

最后，一旦我们在`write-memory`程序中按下*Enter*，`/dev/shm`中的文件将使用`shm_unlink()`被删除。

## 另请参阅

在`man 3 shm_open`手册页中有关于`shm_open()`和`shm_unlink()`的更多信息。

# Unix 套接字-创建服务器

**Unix 套接字**类似于**TCP/IP**套接字，但它们只是本地的，并且由文件系统上的套接字文件表示。但是与 Unix 套接字一起使用的整体函数与 TCP/IP 套接字的几乎相同。Unix 套接字的完整名称是*Unix 域套接字*。

Unix 套接字是程序在本地机器上进行通信的常见方式。

了解如何使用 Unix 套接字将使编写需要在它们之间通信的程序变得更容易。

## 准备工作

在这个示例中，您只需要 GCC 编译器、Make 工具和通用 Makefile。

## 如何做…

在这个示例中，我们将编写一个充当服务器的程序。它将从客户端接收消息，并在每次接收到消息时回复“*消息已收到*”。当服务器或客户端退出时，它还会自行清理。让我们开始吧：

1.  将以下代码写入文件并保存为`unix-server.c`。这段代码比我们以前的大多数示例都要长，因此它被分成了几个步骤。不过所有的代码都在同一个文件中。

这里有相当多的头文件。我们还将为我们将接受的最大消息长度定义一个宏。然后，我们将为`cleanUp()`函数编写原型，该函数将用于清理文件。这个函数也将被用作信号处理程序。然后，我们将声明一些全局变量（以便它们可以从`cleanUp()`中访问）：

```
#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#define MAXLEN 128
void cleanUp(int signum);
const char sockname[] = "/tmp/my_1st_socket";
int connfd;
int datafd;
```

1.  现在，是时候开始编写`main()`函数并声明一些变量了。到目前为止，这大部分对您来说应该是熟悉的。我们还将在这里为所有信号注册信号处理程序。新的是`sockaddr_un`结构。这将包含套接字类型和文件路径：

```
int main(void)
{
   int ret;
   struct sockaddr_un addr;
   char buffer[MAXLEN];
   struct sigaction action;
   /* prepare for sigaction */
   action.sa_handler = cleanUp;
   sigfillset(&action.sa_mask);
   action.sa_flags = SA_RESTART;
   /* register the signals we want to handle */
   sigaction(SIGTERM, &action, NULL);
   sigaction(SIGINT, &action, NULL);
   sigaction(SIGQUIT, &action, NULL);
   sigaction(SIGABRT, &action, NULL);
   sigaction(SIGPIPE, &action, NULL);
```

1.  现在我们已经准备好了所有的信号处理程序、变量和结构，我们可以使用`socket()`函数创建一个套接字文件描述符。一旦处理好了这个问题，我们将设置连接的类型（*family*类型）和套接字文件的路径。然后，我们将调用`bind()`，这将为我们绑定套接字，以便我们可以使用它：

```
   /* create socket file descriptor */
   connfd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
   if ( connfd == -1 )
   {
      perror("Create socket failed");
      return 1;
   }
   /* set address family and socket path */
   addr.sun_family = AF_UNIX;
   strcpy(addr.sun_path, sockname);
   /* bind the socket (we must cast our sockaddr_un
    * to sockaddr) */
   if ( (bind(connfd, (const struct sockaddr*)&addr, 
      sizeof(struct sockaddr_un))) == -1 )
   {
      perror("Binding socket failed");
      return 1;
   }
```

1.  现在，我们将通过调用`listen()`准备好连接的套接字文件描述符。第一个参数是套接字文件描述符，而第二个参数是我们想要的后备大小。一旦我们做到了这一点，我们将使用`accept()`接受一个连接。这将给我们一个新的套接字（`datafd`），我们将在发送和接收数据时使用它。一旦连接被接受，我们可以在本地终端上打印*客户端已连接*：

```
   /* prepare for accepting connections */
   if ( (listen(connfd, 20)) == -1 )
   {
      perror("Listen error");
      return 1;
   }
   /* accept connection and create new file desc */
   datafd = accept(connfd, NULL, NULL);
   if (datafd == -1 )
   {
      perror("Accept error");
      return 1;
   }
   printf("Client connected\n");
```

1.  现在，我们将开始程序的主循环。在外部循环中，我们只会在接收到消息时写一个确认消息。在内部循环中，我们将从新的套接字文件描述符中读取数据，将其保存在`buffer`中，然后在我们的终端上打印出来。如果`read()`返回-1，那么出现了问题，我们必须跳出内部循环读取下一行。如果`read()`返回 0，那么客户端已断开连接，我们必须运行`cleanUp()`并退出：

```
   while(1) /* main loop */
   {
      while(1) /* receive message, line by line */
      {
         ret = read(datafd, buffer, MAXLEN);
         if ( ret == -1 )
         {
            perror("Error reading line");
            cleanUp(1);
         }
         else if ( ret == 0 )
         {
            printf("Client disconnected\n");
            cleanUp(1);
         }
         else
         {
            printf("Message: %s\n", buffer);
            break;
         }
      }
   /* write a confirmation message */
   write(datafd, "Message received\n", 18);
   }
   return 0;
}
```

1.  最后，我们必须创建`cleanUp()`函数的主体：

```
void cleanUp(int signum)
{
   printf("Quitting and cleaning up\n");
   close(connfd);
   close(datafd);
   unlink(sockname);
   exit(0);
}
```

1.  现在编译程序。这次，我们将从 GCC 得到一个关于`cleanUp（）`函数中未使用的变量`signum`的警告。这是因为我们从未在`cleanUp（）`内部使用过`signum`变量，所以我们可以安全地忽略这个警告：

```
$> make unix-server
gcc -Wall -Wextra -pedantic -std=c99    unix-server.c   -o unix-server
unix-server.c: In function 'cleanUp':
unix-server.c:94:18: warning: unused parameter 'signum' [-Wunused-parameter]
 void cleanUp(int signum)
              ~~~~^~~~~~
```

1.  运行程序。由于我们没有客户端，它暂时不会说或做任何事情。但是它确实创建了套接字文件。将程序保持不变：

```
$> ./unix-server
```

1.  打开一个新的终端并查看套接字文件。在这里，我们可以看到它是一个套接字文件：

```
$> ls -l /tmp/my_1st_socket 
srwxr-xr-x 1 jake jake 0 jan 19 18:35 /tmp/my_1st_socket
$> file /tmp/my_1st_socket 
/tmp/my_1st_socket: socket
```

1.  现在，回到运行服务器程序的终端，并使用*Ctrl* + *C*中止它。然后，看看文件是否还在那里（不应该在那里）：

```
./unix-server
Ctrl+C
Quitting and cleaning up
$> file /tmp/my_1st_socket 
/tmp/my_1st_socket: cannot open `/tmp/my_1st_socket' (No such file or directory)
```

## 它是如何工作的…

`sockaddr_un`结构是 Unix 域套接字的特殊结构。还有一个称为`sockaddr_in`的结构，用于 TCP/IP 套接字。`_un`结尾代表 Unix 套接字，而`_in`代表互联网家族套接字。

我们用来创建套接字文件描述符的`socket（）`函数需要三个参数：地址族（`AF_UNIX`），类型（`SOCK_SEQPACKET`，提供双向通信），和协议。我们将协议指定为 0，因为在套接字中没有可以选择的协议。

还有一个称为`sockaddr`的一般结构。当我们将我们的`sockaddr_un`结构作为`bind（）`的参数传递时，我们需要将其强制转换为一般类型`sockaddr`，因为这是函数期望的——更确切地说，是`sockaddr`指针。我们为`bind（）`提供的最后一个参数是结构的大小；也就是`sockaddr_un`。

一旦我们创建了套接字并用`bind（）`绑定了它，我们就用`listen（）`准备好接受传入的连接。

最后，我们使用`accept（）`接受传入的连接。这给了我们一个新的套接字文件描述符，然后我们用它来发送和接收消息。

## 另请参阅

在这个示例中，我们使用的函数的手册页中有一些更深入的信息。我建议你把它们都看一遍：

+   `man 2 socket`

+   `man 2 bind`

+   `man 2 listen`

+   `man 2 accept`

# Unix 套接字 - 创建客户端

在上一个示例中，我们创建了一个 Unix 域套接字服务器。在这个示例中，我们将为该套接字创建一个客户端，然后在客户端和服务器之间进行通信。

在这个示例中，我们将看到如何使用套接字在服务器和客户端之间进行通信。了解如何在套接字上进行通信对于使用套接字是至关重要的。

## 准备工作

在做这个示例之前，你应该已经完成了上一个示例；否则，你就没有服务器可以交谈了。

对于这个示例，你还需要 GCC 编译器、Make 工具和通用的 Makefile。

## 如何做…

在这个示例中，我们将为上一个示例中编写的服务器编写一个客户端。一旦它们连接，客户端就可以向服务器发送消息，服务器将以*收到消息*作出回应。让我们开始吧：

1.  在文件中写入以下代码并将其保存为`unix-client.c`。由于这段代码也有点长，它被分成了几个步骤。但所有的代码都在`unix-client.c`文件中。这个程序的前半部分与服务器的前半部分类似，只是我们有两个缓冲区而不是一个，而且没有信号处理：

```
#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#define MAXLEN 128
int main(void)
{
   const char sockname[] = "/tmp/my_1st_socket";
   int fd;
   struct sockaddr_un addr;
   char sendbuffer[MAXLEN];
   char recvbuffer[MAXLEN];
   /* create socket file descriptor */
   fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
   if ( fd == -1 )
   {
      perror("Create socket failed");
      return 1;
   }
   /* set address family and socket path */
   addr.sun_family = AF_UNIX;
   strcpy(addr.sun_path, sockname);
```

1.  现在，我们将使用`connect（）`来初始化与服务器的连接，而不是使用`bind（）`，`listen（）`和`accept（）`。`connect（）`函数接受与`bind（）`相同的参数：

```
   /* connect to the server */
   if ( (connect(fd, (const struct sockaddr*) &addr, 
      sizeof(struct sockaddr_un))) == -1 )
   {
      perror("Can't connect");
      fprintf(stderr, "The server is down?\n");
      return 1;
   }
```

1.  现在我们已经连接到服务器，我们可以使用`write（）`来通过套接字文件描述符发送消息。在这里，我们将使用`fgets（）`将用户的消息读入缓冲区，将**换行符**转换为**空字符**，然后将缓冲区写入文件描述符：

```
   while(1) /* main loop */
   {
      /* send message to server */
      printf("Message to send: ");
      fgets(sendbuffer, sizeof(sendbuffer), stdin);
      sendbuffer[strcspn(sendbuffer, "\n")] = '\0';
      if ( (write(fd, sendbuffer, 
         strlen(sendbuffer) + 1)) == -1 )
      {
         perror("Couldn't write");
         break;
      }
      /* read response from server */
      if ( (read(fd, recvbuffer, MAXLEN)) == -1 )
      {
         perror("Can't read");
         return 1;
      }
      printf("Server said: %s\n", recvbuffer);
   }
   return 0;
}
```

1.  编译程序：

```
$> make unix-client
gcc -Wall -Wextra -pedantic -std=c99    unix-client.c   -o unix-client
```

1.  现在让我们尝试运行程序。由于服务器尚未启动，它不会工作：

```
$> ./unix-client 
Can't connect: No such file or directory
The server is down?
```

1.  在一个单独的终端中启动服务器并让它保持运行：

```
$> ./unix-server
```

1.  返回到具有客户端的终端并重新运行它：

```
$> ./unix-client 
Message to send:
```

现在你应该在服务器上看到一条消息，上面写着*客户端已连接*。

1.  在客户端程序中写一些消息。当您按下*Enter*键时，您应该会在服务器上看到它们出现。发送几条消息后，按下*Ctrl* + *C*：

```
$> ./unix-client 
Message to send: Hello, how are you?
Server said: Message received
Message to send: Testing 123           
Server said: Message received
Message to send: Ctrl+C
```

1.  切换到带有服务器的终端。您应该会看到类似于这样的内容：

```
Client connected
Message: Hello, how are you?
Message: Testing 123
Client disconnected
Quitting and cleaning up
```

## 工作原理…

在上一个示例中，我们编写了一个套接字服务器。在这个示例中，我们编写了一个客户端，使用`connect()`系统调用连接到该服务器。这个系统调用接受与`bind()`相同的参数。一旦连接建立，服务器和客户端都可以使用`write()`和`read()`从套接字文件描述符中写入和读取（双向通信）。

因此，实质上，一旦连接建立，它与使用文件描述符读写文件并没有太大不同。

## 另请参阅

有关`connect()`系统调用的更多信息，请参阅`man 2 connect`手册页。
