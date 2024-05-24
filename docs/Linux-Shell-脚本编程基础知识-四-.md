# Linux Shell 脚本编程基础知识（四）

> 原文：[`zh.annas-archive.org/md5/0DC4966A30F44E218A64746C6792BE8D`](https://zh.annas-archive.org/md5/0DC4966A30F44E218A64746C6792BE8D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：欢迎来到进程

正在执行的程序称为**进程**。当操作系统启动时，多个进程会启动，以提供各种功能和用户界面，以便用户可以轻松执行所需的任务。例如，当我们启动命令行服务器时，我们将看到一个带有 bash 或任何其他已启动的 shell 进程的终端。

在 Linux 中，我们对进程有完全控制权。它允许我们创建、停止和终止进程。在本章中，我们将看到如何使用诸如`top`、`ps`和`kill`之类的命令以及通过更改其调度优先级来创建和管理进程。我们还将看到信号如何导致进程突然终止，以及使用命令 trap 在脚本中处理信号的方法。我们还将看到进程的一个美妙特性，即进程间通信，它允许它们相互通信。

本章将详细介绍以下主题：

+   进程管理

+   列出和监视进程

+   进程替换

+   进程调度优先级

+   信号

+   陷阱

+   进程间通信

# 进程管理

管理进程非常重要，因为进程是消耗系统资源的主要因素。系统用户应该注意他们正在创建的进程，以确保进程不会影响任何其他关键进程。

## 进程创建和执行

在 bash 中，创建进程非常容易。执行程序时，会创建一个新进程。在 Linux 或基于 Unix 的系统中，创建新进程时会为其分配一个唯一的 ID，称为 PID。PID 值始终是从`1`开始的正数。根据系统是否具有`init`或`systemd`，它们始终获得 PID 值 1，因为这将是系统中的第一个进程，它是所有其他进程的祖先。

PID 的最大值在`pid_max`文件中定义，该文件应该位于`/proc/sys/kernel/`目录中。默认情况下，`pid_max`文件包含值`32768`（最大 PID + 1），这意味着系统中最多可以同时存在`32767`个进程。我们可以根据需要更改`pid_max`文件的值。

为了更好地理解进程创建，我们将从 bash 创建一个新进程`vi`：

```
$ vi hello.txt

```

在这里，我们创建了一个新进程`vi`，它打开编辑器中的`hello.txt`文件以读写文本。调用`vi`命令会导致二进制文件`/usr/bin/vi`执行并执行所需的任务。创建另一个进程的进程称为该进程的父进程。在本例中，`vi`是从 bash 创建的，因此 bash 是进程`vi`的父进程。创建子进程的方法称为 forking。在 fork 过程中，子进程继承其父进程的属性，如 GID、真实和有效的 UID 和 GID、环境变量、共享内存和资源限制。

要知道在前一节中创建的`vi`进程的 PID，我们可以使用诸如`pidof`和`ps`之类的命令。例如，在新终端中运行以下命令以了解`vi`进程的 pid：

```
$ pidof vi  # Process ID of vi process
21552
$ ps -o ppid= -p 21552	# Knowing parent PID of vi process
1785

```

任务完成后，进程终止并且 PID 可根据需要自由分配给新进程。

有关每个进程的详细信息可在`/proc/`目录中找到。对于`/proc/`中的每个进程，都会创建一个名为 PID 的目录，其中包含其详细信息。

进程在其生命周期中可以处于以下任何状态之一：

+   **运行**：在此状态下，进程正在运行或准备运行

+   **等待**：进程正在等待资源

+   **停止**：进程已停止；例如，收到信号后

+   **僵尸**：进程已成功退出，但其状态变化尚未被父进程确认

## 进程终止

在正常情况下，完成任务后，进程会终止并释放分配的资源。如果 shell 已经派生了任何子进程，那么它将等待它们完成任务（而不是后台进程）。在某些情况下，进程可能不会正常工作，可能会等待或消耗比预期更长的时间。在其他一些情况下，可能会发生进程现在不再需要的情况。在这种情况下，我们可以从终端杀死进程并释放资源。

要终止一个进程，我们可以使用`kill`命令。如果系统上有的话，也可以使用`killall`和`pkill`命令。

### 使用 kill 命令

`kill`命令向指定的进程发送指定的信号。如果没有提供信号，则发送默认的`SIGTERM`信号。我们将在本章后面更多地了解有关信号的信息。

以下是使用`kill`命令的语法：

```
kill PID

```

AND

```
kill -signal PID

```

要杀死一个进程，首先获取该进程的`PID`如下：

```
$ pidof firefox    # Getting PID of firefox process if running
1663
$ kill 1663    # Firefox will be terminated
$ vi hello.txt  # Starting a vi process
$ pidof vi
22715
$ kill -SIGSTOP 22715  # Sending signal to stop vi process
[1]+  Stopped                 vi

```

在这里，我们使用`SIGSTOP`信号来停止进程而不是杀死它。要杀死，我们可以使用`SIGKILL`信号或与此信号相关的值，即`9`。

```
$ kill -9 22715  # Killing vi process

```

OR

```
$ kill -SIGKILL 22715  # Killing vi process

```

### 使用 killall 命令

按名称而不是 PID 来记住一个进程更容易。`killall`命令使得杀死一个进程更容易，因为它将命令名称作为参数来杀死一个进程。

以下是`killall`命令的语法：

```
killall process_name

```

AND

```
killall -signal process_name

```

例如，我们可以按名称杀死`firefox`进程，如下所示：

```
$ killall firefox  # Firefox application gets terminated

```

## 使用 pkill 命令

`pkill`命令也可以用来按名称杀死一个进程。与`killall`命令不同，默认情况下，`pkill`命令会找到所有以其参数中指定的名称开头的进程。

例如，以下命令演示了`pkill`如何根据参数中指定的部分名称杀死`firefox`进程：

```
$ pkill firef    # Kills processes beginning with name firef and hence firefox

```

`pkill`命令应该谨慎使用，因为它会杀死所有匹配的进程，这可能不是我们的意图。我们可以使用`pgrep`命令和`-l`选项来确定将要被`pkill`杀死的进程。`pgrep`命令根据其名称和属性找到进程。运行以下命令来列出所有以`firef`和`fire`字符串开头的进程名称及其 PID：

```
$ pgrep firef
 8168 firefox

```

这里，`firefox`是匹配的进程名称，其 PID 是`8168`：

```
$ pgrep fire
 747 firewalld
 8168 firefox

```

我们还可以告诉`pkill`使用`--exact`或`-x`选项来精确匹配进程名称杀死进程，如下所示：

```
$ pgrep -x -l  firef  # No match found
$ pkill -x fire  # Nothing gets killed
$ pgrep --exact -l firefox	  # Process firefox found
8168 firefox
$ pkill --exact firefox  # Process firefox will be killed

```

pkill 命令还可以使用`-signal_name`选项向所有匹配的进程发送特定信号，如下所示：

```
$  pkill -SIGKILL firef

```

上述命令向所有以`firef`开头的进程发送`SIGKILL`信号。

# 列出和监视进程

在运行中的系统中，我们经常会注意到突然系统反应缓慢。这可能是因为运行的应用程序消耗了大量内存，或者进程正在进行 CPU 密集型工作。很难预测哪个应用程序导致系统反应变慢。为了知道原因，了解正在运行的所有进程以及了解进程的监视行为（例如消耗的 CPU 或内存量）是很有帮助的。

## 列出进程

要知道系统中运行的进程列表，我们可以使用`ps`命令。

### 语法

`ps`命令的语法如下：

```
ps [option]

```

有很多选项可以使用`ps`命令。常用选项在下表中有解释。

#### 简单的进程选择

以下表格显示了可以组合在一起使用以获得更好结果选择的多个选项：

| 选项 | 描述 |
| --- | --- |
| `-A`, `-e` | 选择所有进程 |
| `-N` | 选择不满足条件的所有进程，即否定选择 |
| `T` | 选择与当前终端相关的进程 |
| `r` | 限制选择只有运行中的进程 |
| `x` | 选择没有控制终端的进程，例如在引导过程中启动的守护进程 |
| `a` | 选择终端上的进程，包括所有用户 |

#### 按列表选择进程

以下选项接受以空格分隔或逗号分隔的列表形式的单个参数；它们可以多次使用：

| 选项 | 描述 |
| --- | --- |
| `-C cmdlist` | 通过名称选择进程。提供在`cmdlist`中选择的名称列表。 |
| `-g grplist` | 通过`grplist`参数列表中提供的有效组名选择进程。 |
| `-G grplist` | 通过`grplist`参数列表中提供的真实组名选择进程。 |
| `-p pidlist` | 通过`pidlist`中提到的 PID 选择进程。 |
| `-t ttylist` | 通过`ttylist`中提到的终端选择进程。 |
| `-U userlist` | 通过`userlist`中提到的真实用户 ID 或名称选择进程。 |
| `-u userlist` | 通过`userlist`中提到的有效用户 ID 或名称选择进程。 |

#### 输出格式控制

以下选项用于选择如何显示`ps`命令的输出：

| 选项 | 描述 |
| --- | --- |
| 显示作业格式。 |
| `-f` | 用于完整格式列表。它还打印传递给命令的参数。 |
| `u` | 显示面向用户的格式。 |
| `-l` | 显示长格式。 |
| `v` | 显示虚拟内存格式。 |

### 列出所有带有详细信息的进程

要了解系统上的所有进程，可以使用`-e`选项。要获得更详细的输出，请与`u`选项一起使用：

```
$ ps -e u | wc -l    # Total number of processes in system
211
$ ps -e u | tail -n5  # Display only last 5 line of result

```

![列出所有带有详细信息的进程](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_07_01.jpg)

我们可以从输出中看到所有用户的进程。实际显示输出的命令——即**ps -e u | tail -n5**——也作为两个单独的运行进程在`ps`输出中提到。

在 BSD 风格中，使用`aux`选项可以获得与`-e u`相同的结果：

```
$ ps aux

```

在基于 Linux 的操作系统上，`aux`以及`-e u`选项都可以正常工作。

### 列出特定用户运行的所有进程

要了解特定用户正在运行哪些进程，可以使用`-u`选项，后面跟着用户名。也可以提供多个用户名，用逗号（,）分隔。

```
$ ps u -u root | wc -l
130
$ ps u -u root | tail -n5	# Display last 5 results

```

前面的命令显示以下结果：

![列出用户运行的所有进程](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_07_02.jpg)

我们看到所有进程都是以 root 用户身份运行的。其他用户的进程已被过滤掉。

### 在当前终端中运行的进程

了解当前终端中运行哪些进程很有用。这有助于决定是否终止运行中的终端。我们可以使用`T`或`t`选项制作当前终端中运行的进程列表。

```
$ ps ut

```

以下命令的输出如下：

![在当前终端中运行的进程](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_07_03.jpg)

我们可以从输出中看到，`bash`和`ps uT`命令（我们刚刚执行以显示结果）是当前终端中唯一运行的进程。

### 按命令名称列出进程

我们还可以使用`-C`选项按名称了解进程的详细信息，后面跟着命令名称。多个命令名称可以用逗号（`,`）分隔：

```
$ ps u -C firefox,bash

```

获得以下输出：

![按命令名称列出进程](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_07_04.jpg)

## 进程的树形格式显示

`pstree`命令以树形结构显示运行中的进程，这样很容易理解进程的父子关系。

使用`-p`选项运行`pstree`命令，以树形格式显示进程及其 PID 号，如下所示：

```
$ pstree -p

```

![进程的树形格式显示](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_07_05.jpg)

从 `pstree` 输出中，我们可以看到所有进程的父进程是 `systemd`。这是作为负责执行其余进程的第一个进程启动的。在括号中，提到了每个进程的 PID 号码。我们可以看到 `systemd` 进程得到了 PID 1，这是固定的。在基于 `init` 的操作系统上，`init` 将是所有进程的父进程，并且具有 PID 1。

要查看特定 PID 的进程树，我们可以使用 `pstree` 并将 PID 号码作为参数：

```
$ pstree -p 1627  # Displays process tree of PID 1627 with PID number

```

![进程的树状格式显示](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_07_06.jpg)

使用 `pstree` 命令并带有 `-u` 选项来查看进程的 UID 和父进程不同时：

```
$ pstree -pu 1627

```

![进程的树状格式显示](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_07_07.jpg)

我们可以看到最初，`bash` 由用户 `skumari` 以 PID `1627` 运行。在树的下方，`sudo` 命令以 root 用户身份运行。

## 监视进程

在运行时了解进程消耗了多少内存和 CPU 是非常重要的，以确保没有内存泄漏和过度 CPU 计算的发生。有一些命令，如 `top`、`htop` 和 `vmstat`，可以用来监视每个进程消耗的内存和 CPU。在这里，我们将讨论 `top` 命令，因为它是预装在基于 Linux 的操作系统中的。

`top` 命令显示 CPU、内存、交换和当前正在运行的任务数量的动态实时使用情况。

运行 `top` 而不带任何选项会给出以下结果：

```
$ top

```

![监视进程](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_07_08.jpg)

在 `top` 命令输出中，第一行告诉我们系统自上次启动以来的时间长度、用户数量和平均负载。

第二行告诉我们任务的数量及其状态 - 运行、睡眠、停止和僵尸。

第三行给出了 CPU 使用情况的详细信息。不同的 CPU 使用情况显示在下表中：

| 值 | 描述 |
| --- | --- |
| `us` | 在运行非优先用户进程中花费的 CPU 时间百分比 |
| `sy` | 在内核空间中花费的 CPU 时间百分比 - 即运行内核进程 |
| `ni` | 运行优先用户进程的 CPU 时间百分比 |
| `id` | 空闲时间百分比 |
| `wa` | 等待 I/O 完成所花费的时间百分比 |
| `hi` | 服务硬件中断所花费的时间百分比 |
| `si` | 服务软件中断所花费的时间百分比 |
| `st` | 虚拟机消耗的时间百分比 |

第四行告诉我们关于总、空闲、已使用和缓冲的 RAM 内存使用情况。

第五行告诉我们关于总交换内存、空闲和已使用的交换内存。

其余行提供了关于运行进程的详细信息。每列的含义在下表中描述：

| 列 | 描述 |
| --- | --- |
| PID | 进程 ID |
| USER | 任务所有者的有效用户名 |
| PR | 任务的优先级（值越低，优先级越高） |
| NI | 任务的优先级。负的优先级值意味着更高的优先级，正的意味着较低的优先级 |
| VIRT | 进程使用的虚拟内存大小 |
| RES | 未交换的物理内存进程 |
| SHR | 进程可用的共享内存量 |
| S | 进程状态 - D（不可中断的睡眠），R（运行），S（睡眠），T（被作业控制信号停止），t（被调试器停止），Z（僵尸） |
| %CPU | 进程当前使用的 CPU 百分比 |
| %MEM | 进程当前使用的物理内存百分比 |
| TIME+ | CPU 时间，百分之一秒 |
| COMMAND | 命令名称 |

当 top 在运行时，我们也可以重新排序和修改输出。要查看帮助，请使用 *?* 或 *h* 键，将显示帮助窗口，其中包含以下详细信息：

![监视进程](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_07_09.jpg)

要根据特定字段进行排序，最简单的方法是在 `top` 运行时按下 *f* 键。一个新窗口会打开，显示所有列。打开的窗口如下所示：

![监视进程](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_07_10.jpg)

使用上下箭头导航并选择列。要根据特定字段进行排序，请按下*s*键，然后按*q*键切换回顶部输出窗口。

在这里，我们选择了 NI，然后按下了*s*键和*q*键。现在，`top`输出将按`nice`数字排序。排序后的`top`输出如下所示：

![监视进程](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_07_11.jpg)

# 进程替换

我们知道可以使用管道将命令的输出作为另一个命令的输入。例如：

```
$ cat file.txt | less

```

在这里，`cat`命令的输出——即`file.txt`的内容——作为输入传递给了 less 命令。我们可以将仅一个进程的输出（在本例中为 cat 进程）重定向为另一个进程的输入。

我们可能需要将多个进程的输出作为另一个进程的输入。在这种情况下，使用进程替换。进程替换允许进程从一个或多个进程的输出中获取输入，而不是文件。

使用进程替换的语法如下：

将输入文件替换为列表

```
<(list)

```

或者

通过列表替换输出文件(s)

```
>(list)

```

在这里，`list`是一个命令或一系列命令。进程替换使列表的行为类似于文件，方法是给列表命名，然后在命令行中替换该名称。

## 比较两个进程的输出

要比较两组数据，我们使用`diff`命令。但是，我们知道`diff`命令需要两个文件作为输入来生成差异。因此，我们必须首先将两组数据保存到两个单独的文件中，然后运行`diff`。保存差异内容会增加额外的步骤，这是不好的。为了解决这个问题，我们可以在执行`diff`时使用进程替换功能。

例如，我们想要知道目录中的隐藏文件。在 Linux 和基于 Unix 的系统中，以`。`（点）开头的文件称为隐藏文件。要查看隐藏文件，可以使用`ls`命令的`-a`选项：

```
$ ls -l ~  # Long list home directory content excluding hidden files
$ ls -al ~   # Long list home directory content including hidden files

```

要仅获取目录中的隐藏文件，请对从前两个命令获得的排序输出运行`diff`命令：

```
$ diff  <(ls -l ~ | tr -s " " | sort -k9) <(ls -al ~ | tr -s " " | sort -k9)

```

![比较两个进程的输出](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_07_12.jpg)

在这里，我们将`ls -l ~ | tr -s " " | sort -k9`和`ls -al ~ | tr -s " " | sort -k9`命令作为输入数据提供给`diff`命令，而不是传递两个文件。

# 进程调度优先级

在进程的生命周期中，它可能需要 CPU 和其他资源来保持正常执行。我们知道系统中同时运行多个进程，并且它们可能需要 CPU 来完成操作。为了共享可用的 CPU 和资源，进行进程调度，以便每个进程有机会利用 CPU。创建进程时，会设置初始优先级值。根据优先级值，进程获得 CPU 时间。

进程调度优先级范围是从`-20`到`19`。这个值也被称为 nice 值。nice 值越低，进程的调度优先级就越高。因此，具有`-20`的进程将具有最高的调度优先级，而具有 nice 值`19`的进程将具有最低的调度优先级。

要查看进程的 nice 值，可以使用`ps`或`top`命令。进程的相应 nice 值在 NI 列中可用：

```
$ ps -l

```

![进程调度优先级](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_07_13.jpg)

在`ps`输出中，我们可以看到 bash 和`ps`进程的`NI`列中的 nice 值为`0`。

## 更改调度优先级

系统中的每个进程都分配了一些优先级，这取决于它的 nice 值。根据优先级，进程获得 CPU 时间和其他资源来使用。有时，可能会发生进程需要快速执行，但由于较低的调度优先级而等待释放 CPU 资源很长时间。在这种情况下，我们可能希望增加其调度优先级以更快地完成任务。我们可以使用`nice`和`renice`命令来更改进程的调度优先级。

### 使用 nice

`nice`命令以用户定义的调度优先级启动进程。默认情况下，用户创建的进程的 nice 值为`0`。要验证这一点，请运行不带任何选项的`nice`命令：

```
$ nice
0

```

让我们创建一个实际消耗 CPU 和资源的新`firefox`进程：

```
$ killall firefox  # Terminate any firefox if already running
$ firefox &    # Firefox launched in background
$ top

```

![使用 nice](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_07_14.jpg)

我们可以看到`firefox`的 nice 值为`0`，CPU 使用率为 8.7%。

现在，我们将终止当前的`firefox`并启动另一个`firefox`，其 nice 值为`10`。这意味着`firefox`的优先级将低于其他用户创建的进程。

要创建一个具有不同 nice 值的进程，可以使用`nice`的`-n`选项：

```
$ killall firefox
$ nice -n 10 firefox &

```

或者

```
$ nice -10 firefox &

```

要查看`firefox`现在的 nice 值，请检查`top`输出：

```
$ top

```

![使用 nice](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_07_15.jpg)

我们可以看到`firefox`进程的 nice 值为`10`。要提供更多的调度优先级——即为进程设置负的 nice 值——需要 root 权限。

以下示例将设置`firefox`进程为更高的调度优先级：

```
$  nice -n -10 firefox

```

或者

```
$ sudo  nice --10 firefox

```

### 使用 renice

`nice`命令只能在启动进程时修改 nice 值。但是，如果我们想要更改正在运行的进程的调度优先级，则应使用`renice`命令。`renice`命令改变一个或多个正在运行的进程的调度优先级。

使用`renice`的语法如下：

```
renice [-n] priority [-g|-p|-u] identifier

```

在这里，`-g`选项考虑后续参数——即 GID 作为标识符。

`-p`选项考虑后续参数——即 PID 作为标识符。

`-u`选项考虑后续参数——即用户名或 UID 作为标识符。

如果没有提供`-g`、`-p`或`-u`选项，则将标识符视为 PID。

例如，我们将更改属于某个用户的所有进程的优先级。首先，查看由用户拥有的进程的当前优先级：

```
$  top -u skumari    # User is skumari

```

![使用 renice](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_07_16.jpg)

现在，我们将使用`renice`和`-u`选项修改所有进程的优先级：

```
$ sudo renice -n -5 -u skumari

```

让我们查看由用户`skumari`拥有的进程的新的 nice 值：

```
$ top -u skumari

```

![使用 renice](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_07_17.jpg)

要修改几个进程的调度优先级，请使用进程的 PID 进行修改。以下示例修改了 PID 分别为`1505`和`5969`的进程 plasmashell 和 Firefox：

```
$ sudo renice -n 2 -p 1505 5969
$ top -u skumari

```

![使用 renice](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_07_18.jpg)

现在，我们可以看到进程 plasmashell 和 Firefox 的 nice 值为`2`。

# 信号

信号是一种软件中断，用于通知进程发生外部事件。在正常执行中，进程按预期继续运行。现在，由于某种原因，用户可能希望取消正在运行的`进程`。当进程从终端启动时，当我们按下*Ctrl* + *c*键或运行`kill`命令时，它将终止。

当我们在终端中运行进程时按下*Ctrl* + *c*键时，会生成信号`SIGINT`并发送到前台运行的进程。此外，当对进程调用`kill`命令时，会生成`SIGKILL`信号并终止进程。

## 可用信号

在所有可用的信号中，我们将在这里讨论经常使用的信号：

| 信号名称 | 值 | 默认操作 | 描述 |
| --- | --- | --- | --- |
| SIGHUP | 1 | Term | 此信号用于挂起或控制进程的死亡 |
| SIGINT | 2 | Term | 此信号用于从键盘中断，如 ctrl + c，ctrl + z |
| SIGQUIT | 3 | 核心 | 此信号用于从键盘退出 |
| SIGILL | 4 | Core | 用于非法指令 |
| SIGTRAP | 5 | Core | 此信号用于跟踪或断点陷阱 |
| SIGABRT | 6 | Core | 用于中止信号 |
| SIGFPE | 8 | Core | 浮点异常 |
| SIGKILL | 9 | Term | 进程立即终止 |
| SIGSEGV | 11 | Core | 无效内存引用 |
| SIGPIPE | 13 | Term | 管道破裂 |
| SIGALRM | 14 | Term | 警报信号 |
| SIGTERM | 15 | Term | 终止进程 |
| SIGCHLD | 17 | Ign | 子进程停止或终止 |
| SIGSTOP | 19 | Stop | 此信号用于停止进程 |
| SIGPWR | 30 | Term | 电源故障 |

在上表中，我们提到了信号名称和值。在**默认操作**部分中使用的术语的含义如下：

+   Term: 终止

+   Core: 终止进程并转储核心

+   Ign: 忽略信号

+   Stop: 停止进程

根据信号的类型，可以采取以下任何一种操作：

+   进程可以忽略信号，这意味着不会采取任何操作。除了`SIGKILL`和`SIGSTOP`之外，大多数信号都可以被忽略。`SIGKILL`和`SIGSTOP`信号无法被捕获、阻止或忽略。这允许内核在任何时间点杀死或停止任何进程。

+   可以通过编写信号处理程序代码来处理信号，指定接收到特定信号后要采取的必要操作。

+   每个信号都有一个默认操作，因此让信号执行默认操作；例如，如果发送`SIGKILL`信号，则终止进程。

要了解所有信号及其相应的值，请使用`kill`命令和`-l`选项：

```
$ kill -l

```

![可用信号](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_07_19.jpg)

`kill`命令还提供了一种在以下方式中将信号编号转换为名称的方法：

```
kill -l signal_number

$ kill -l 9
KILL
$ kill -l 29
IO
$ kill -l 100  # invalid signal number gives error
bash: kill: 100: invalid signal specification

```

要向进程发送信号，可以使用`kill`、`pkill`和`kilall`命令：

```
$ kill -9 6758  # Sends SIGKILL process to PID 6758
$ killall -1 foo  # Sends SIGHUP signal to process foo
$ pkill -19 firef  # Sends SIGSTOP signal to processes' name beginning with firef

```

# 陷阱

当一个进程正在运行时，我们在中间杀死这个进程，进程会立即终止而不再执行任何操作。编写程序的程序员可能希望在程序实际终止之前执行一些任务；例如，清理创建的临时目录，保存应用程序状态，保存日志等。在这种情况下，程序员希望监听信号并在允许终止进程之前执行所需的任务。

考虑以下 shell 脚本示例：

```
#!/bin/bash
# Filename: my_app.sh
# Description: Reverse a file

echo "Enter file to be reversed"
read filename

tmpfile="/tmp/tmpfile.txt"
# tac command is used to print a file in reverse order
tac $filename > $tmpfile
cp $tmpfile $filename
rm $tmpfile
```

该程序从用户文件中获取输入，然后反转文件内容。此脚本创建一个临时文件来保存文件的反转内容，然后将其复制到原始文件。最后，它删除临时文件。

当我们执行此脚本时，可能正在等待用户输入文本文件名，或者在反转文件时（大文件需要更多时间来反转内容）。在此期间，如果进程被终止，那么临时文件可能不会被删除。程序员的任务是确保删除临时文件。

为了解决这样的问题，我们可以处理信号，执行必要的任务，然后终止进程。这可以通过使用`trap`命令来实现。该命令允许您在脚本接收到信号时执行命令。

使用`trap`的语法如下：

```
$ trap action signals

```

在这里，我们可以提供要执行的`trap`操作。操作可以是一个或多个执行命令。

在`trap`的上述语法中，`signals`指的是要执行操作的一个或多个信号名称。

以下 shell 脚本演示了`trap`如何在接收到信号后执行任务以防止进程突然退出：

```
#!/bin/bash
# Filename: my_app_with_trap.sh
# Description: Reverse a file and perform action on receiving signals

echo "Enter file to be reversed"
read filename

tmpfile="/tmp/tmpfile.txt"
# Delete temporary file on receiving any of signals
# SIGHUP SIGINT SIGABRT SIGTERM SIGQUIT and then exit from script
trap "rm $tmpfile; exit" SIGHUP SIGINT SIGABRT SIGTERM SIGQUIT
# tac command is used to print a file in reverse order
tac $filename > $tmpfile
cp $tmpfile $filename
rm $tmpfile
```

在这个修改后的脚本中，当接收到`SIGHUP`、`SIGINT`、`SIGABRT`、`SIGTERM`或`SIGQUIT`等信号时，将执行`rm` `$tmpfile; exit`。这意味着首先删除临时文件，然后可以退出脚本。

# 进程间通信

一个进程可以单独完成某些事情，但不是所有事情。如果两个或更多进程可以以共享结果、发送或接收消息等形式相互通信，那将是非常有用和良好的资源利用。在基于 Linux 或 Unix 的操作系统中，两个或更多进程可以使用 IPC 相互通信。

IPC 是进程之间通信并由内核管理的技术。

IPC 可以通过以下任一方式进行：

+   **命名管道**：这允许进程从中读取和写入。

+   **共享内存**：这是由一个进程创建的，并且可以被多个进程读取和写入。

+   **消息队列**：这是一个结构化和有序的内存段列表，进程可以以队列方式存储或检索数据。

+   **信号量**：这为访问相同资源的进程提供了同步机制。它具有用于控制多个进程对共享资源访问的计数器。

在讨论命名管道时，在第六章中，*处理文件*，我们学习了进程如何使用命名管道进行通信。

## 使用 ipcs 查看 IPC 的信息

`ipcs`命令提供了有关 IPC 设施的信息，对于这些设施，调用进程具有读取访问权限。它可以提供有关三种资源的信息：共享内存、消息队列和信号量。

使用`ipcs`的语法如下：

```
ipcs option

```

选项如下：

| 选项 | 描述 |
| --- | --- |
| `-a` | 显示所有资源的信息—共享内存、消息队列和信号量 |
| `-q` | 显示有关活动消息队列的信息 |
| `-m` | 显示有关活动共享内存段的信息 |
| `-s` | 显示有关活动信号量集的信息 |
| `-i ID` | 显示 ID 的详细信息。与`-q`、`-m`或`-s`选项一起使用。 |
| `-l` | 显示资源限制 |
| `-p` | 显示资源创建者和最后操作者的 PID |
| `-b` | 以字节打印大小 |
| `--human` | 以人类可读的格式打印大小 |

### IPC 提供的信息列表

我们可以使用`ipcs`命令不带选项或带`-a`：

```
$ ipcs

```

或

```
$ ipcs -a

```

![IPC 提供的信息列表](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_07_20.jpg)

要仅查看共享内存段，我们可以使用带有`-m`选项的`ipcs`：

```
$ ipcs -m --human

```

![IPC 提供的信息列表](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_07_21.jpg)

在这里，`--human`选项通过以 KB 和 MB 的大小而不是以字节的方式提供大小，使大小列以更可读的格式显示。

要查找有关资源 ID 的详细信息，请使用`ipcs`命令，后跟`-i`选项和资源 ID：

```
$ ipcs -m -i 393217

```

![IPC 提供的信息列表](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_07_22.jpg)

### 知道最近进行 IPC 的进程的 PID

我们可以使用`-p`选项知道最近访问特定 IPC 资源的进程的 PID：

```
$ ipcs -m -p

```

![知道最近进行 IPC 的进程的 PID](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_07_23.jpg)

在这里，`cpid`列显示创建共享内存资源的进程的`pid`，而`lpid`指的是最后访问共享内存资源的进程的 PID。

# 摘要

阅读完本章后，您将了解 Linux 和基于 UNIX 的系统中的进程是什么。您现在应该知道如何创建、停止、终止和监视进程。您还应该知道如何向进程发送信号，并使用`trap`命令在 shell 脚本中管理接收到的信号。您还学会了不同进程如何使用 IPC 进行通信以共享资源或发送和接收消息。

在下一章中，您将了解任务可以自动化的不同方式以及它们如何在指定时间运行而无需进一步人工干预。您还将学习如何以及为什么创建启动文件，并如何在 shell 脚本中嵌入其他编程语言，如 Python。


# 第八章：安排任务和在脚本中嵌入语言

到目前为止，我们已经了解了各种有用的 shell 实用程序以及如何将它们写入 shell 脚本，以避免一遍又一遍地编写相同的指令。通过编写脚本自动化任务可以减少任务的数量，但是我们仍然需要在需要时运行这些脚本。有时，我们希望在特定时间运行命令或脚本，例如，系统管理员必须在凌晨 12:30 对数据中心中可用的系统进行清理和维护。为了执行所需的操作，系统管理员将在凌晨 12:30 左右登录到计算机并进行必要的工作。但是如果他或她的家庭网络出现故障，数据中心又很远怎么办？在那一刻执行任务将会很不方便和困难。还有一些需要每天或每小时执行的任务，例如监视每个用户的网络使用情况，进行系统备份等。一遍又一遍地执行重复的任务将会非常无聊。

在本章中，我们将看到如何通过使用`at`和`crontab`实用程序在特定时间或时间间隔内安排任务来解决这些问题。我们还将看到 systemd（系统启动后启动的第一个进程，PID 1）如何管理系统启动后需要的进程。我们还将看到 systemd 如何管理不同的服务和系统日志。最后，我们将学习如何在 shell 脚本中嵌入其他脚本语言，以获得 shell 脚本中的额外功能。

本章将详细介绍以下主题：

+   在特定时间运行任务

+   Cron 作业

+   管理 Crontab 条目

+   systemd

+   嵌入语言

# 在特定时间运行任务

通常，当我们运行命令或脚本时，它会立即开始执行。但是，如果我们希望在特定时间后运行它呢？例如，我想从互联网上下载大量数据，但不想在工作时减慢我的互联网带宽。因此，我想在凌晨 1:00 运行我的下载脚本，因为在凌晨 1:00 之后我不会使用互联网进行任何工作。使用`at`命令可以在指定的时间后安排下载脚本或命令。我们还可以使用`atq`命令列出已安排的任务，或使用`atrm`命令删除任何已安排的任务。

## 使用`at`执行脚本

我们将使用`at`命令在指定时间运行任务。使用`at`命令的语法如下：

```
at [Option] specified_time

```

在前面的语法中，`specified_time`指的是命令或脚本应该运行的时间。时间可以采用以下格式：

| 时间格式 | 描述 |
| --- | --- |
| HH:MM | 一天中特定的时间，以小时（HH）和分钟（MM）表示。如果时间已经过去，则假定为第二天。时间以 24 小时制表示。 |
| noon | 白天 12:00。 |
| teatime | 下午 4 点或下午 4 点。 |
| midnight | 凌晨 12:00。 |
| today | 指的是同一天的当前时间。 |
| tomorrow | 指的是第二天的当前时间。 |
| AM 或 PM | 用于在时间后缀中指定 12 小时制的时间，例如 4:00PM。 |
| now + count time-units | 在一定时间后以相同时间运行脚本。计数可以是整数。时间单位可以是分钟，小时，天，周，月或年。 |
| 日期 | 日期可以以月份-日期和可选年份的形式给出。日期可以采用以下格式之一：MMDD[CC]YY，MM/DD/[CC]YY，DD.MM.[CC]YY，或[CC]YY-MM-DD。 |

`at`命令的选项在以下表中解释：

| 选项 | 描述 |
| --- | --- |
| `-f FILE` | 指定要执行的脚本文件。 |
| `-l` | `atq`命令的别名。 |
| `-m` | 在作业完成时向用户发送电子邮件。 |
| `-M` | 不向用户发送电子邮件。 |
| `-r` | `atrm`命令的别名。 |
| `-t time` | 在指定时间运行作业。时间的格式为[[CC]YY]MMDDhhmm[.ss]。 |
| `-c job_number` | 在标准输出上打印与`job_number`相关的作业。 |
| `-v` | 打印作业将被执行的时间。 |

### 安排命令

以下命令被安排在 14:00 运行，它将文件系统的使用情况存储在一个名为`file_system_usage.log`的文件中，存储在用户的主目录中：

```
$ at 14:00
warning: commands will be executed using /bin/sh
at> df > ~/file_system_usage.log
at> <EOT>
job 33 at Mon Sep 21 14:00:00 2015

```

当我们像上面那样运行`at`命令时，会打印一个警告消息**warning: commands will be executed using /bin/sh**，指定将使用哪个 shell 来执行命令。在下一行，我们将看到`at prompt`，在那里我们可以指定要在 14:00 执行的命令列表。在我们的情况下，我们输入了`df > ~/file_system_usage.log`命令，这意味着运行`df`命令并将其结果保存在`file_system_usage.log`文件中。

一旦输入要输入的命令列表完成，按下*Enter*键，然后在下一行使用*Ctrl* + *d*键从`at`提示中退出。在获得正常的 shell 提示之前，我们将看到消息，显示创建的作业编号和作业将被执行的时间戳。在我们的情况下，作业编号是`33`，时间戳是`Mon Sep 21 14:00:00 2015`。

一旦我们指定的时间戳结束，我们可以检查`file_system_usage.log`文件的内容。

当特定的预定作业运行时，我们可以在`stdout`上打印将要执行的内容：

```
$ at -c 33  # Lists content of job 33

```

![安排命令](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_08_01.jpg)

我们可以看到`df > ~/file_system_usage.log`命令将被执行。其余的行指定了任务将在什么环境中执行。

现在，考虑一个由 root 用户安排的作业：

```
# at -v 4am
Mon Sep 21 04:00:00 2015

warning: commands will be executed using /bin/sh
at> reboot
at> <EOT>
job 34 at Mon Sep 21 04:00:00 2015

```

编号为`34`的作业是由用户 root 安排的。这个作业系统将在凌晨 4 点重启。

### 安排脚本文件

我们可以使用`at`命令的`-f`选项来安排脚本文件在特定时间执行。

例如，我们想要在下周下午 4 点运行`loggedin_user_detail.sh`脚本。这个脚本列出了登录的用户以及在脚本在预定时间执行时他们正在运行的进程。脚本的内容如下：

```
$ cat  loggedin_user_detail.sh
#!/bin/bash
# Filename: loggedin_user_detail.sh
# Description: Collecting information of loggedin users

users_log_file=~/users_log_file.log
echo "List of logged in users list at time 'date'" > $users_log_file
users=('who | cut -d' ' -f1 | sort | uniq')
echo ${users[*]} >> $users_log_file

for i in ${users[*]}
do
 echo "Processes owned by user $i" >> $users_log_file
 ps u -u $i >> $users_log_file
 echo
done
$ chmod +x  loggedin_user_detail.sh  # Provide execute permission

```

现在，要在下周下午 4 点运行上述脚本，我们将运行以下命令：

```
$at -f loggedin_user_detail.sh 4pm + 1 week
warning: commands will be executed using /bin/sh
job 42 at Sun Sep 27 16:00:00 2015

```

我们可以看到这个作业已经被安排在一周后运行。

## 列出预定的任务

有时候，一个任务被安排在特定的时间运行，但我们忘记了任务应该在什么时间运行。我们可以使用`atq`或`at`命令的`-l`选项来查看已经安排的任务：

```
$ atq
33      Mon Sep 21 14:00:00 2015 a skumari
42      Sun Sep 27 16:00:00 2015 a skumari

```

`atq`命令显示了当前用户安排的作业，包括作业编号、时间和用户名：

```
$ sudo atq
34      Mon Sep 21 04:00:00 2015 a root
33      Mon Sep 21 14:00:00 2015 a skumari
42      Sun Sep 27 16:00:00 2015 a skumari

```

使用`sudo`运行`atq`命令，列出所有用户安排的作业。

## 删除预定的任务

如果不再需要执行某个预定的任务，我们也可以删除该任务。当我们想要修改任务执行的时间时，删除任务也是有用的。要修改时间，首先删除预定的任务，然后再用新的时间创建相同的任务。

例如，我们不想在凌晨 1 点而不是凌晨 4 点重启系统。为此，root 用户将首先使用`atrm`命令删除作业`34`：

```
# atrm 34
$ sudo atq    # Updated lists of tasks
 33      Mon Sep 21 14:00:00 2015 a skumari
 42      Sun Sep 27 16:00:00 2015 a skumari
# at 1am
warning: commands will be executed using /bin/sh
 at> reboot
 at> <EOT>
job 47 at Mon Sep 21 01:00:00 2015
$ sudo atq
 33      Mon Sep 21 14:00:00 2015 a skumari
 42      Sun Sep 27 16:00:00 2015 a skumari
 47      Mon Sep 21 01:00:00 2015 a root

```

我们可以看到，由 root 用户安排的任务现在将在凌晨 1 点而不是凌晨 4 点运行。

# 定时任务

Cron 作业是定期运行的任务或作业，与`at`命令不同。例如，在办公室，我的工作是保持公司员工的详细信息是保密的。为了确保信息安全和更新，而不会丢失任何信息，我将不得不在外部设备上备份最新数据，如硬盘或闪存驱动器。根据员工人数，我可能需要每分钟、每小时、每天或每周备份一次。手动备份每次都是困难、繁琐且浪费时间的。通过了解如何安排 cron 作业，可以很容易地实现。系统管理员经常创建 Cron 作业来安排定期执行的任务，例如备份系统、保存每个登录用户的日志、监视和报告每个用户的网络使用情况、执行系统清理、安排系统更新等。

Cron 由两部分组成：cron 守护进程和 cron 配置。

## Cron 守护进程

当系统启动时，cron 守护进程会自动启动并在后台持续运行。守护进程被称为 crond，并由 systemd 或 init 进程启动，这取决于您的系统。它的任务是以一分钟的间隔定期检查配置文件，并检查是否有任何任务需要完成。

## Cron 配置

Cron 配置包含 Cron 作业的文件和目录。它们位于`/etc/`目录中。与 cron 配置相关的最重要的文件是`crontab`。在 Linux 系统中，与 cron 相关的配置文件如下：

+   `/etc/cron.hourly/`：其中包含每小时运行的脚本

+   `/etc/cron.daily/`：其中包含每天运行的脚本

+   `/etc/cron.weekly/`：其中包含每周运行的脚本

+   `/etc/cron.monthly/`：其中包含每月运行的脚本

+   `/etc/crontab`：其中包含命令以及它们应该运行的间隔

+   `/etc/cron.d/`：其中包含命令以及它们应该运行的间隔的文件目录

脚本可以直接添加到`cron.hourly/`、`cron.daily/`、`cron.weekly/`或`cron.monthly/`中的任何一个目录中，以便按小时、每天、每周或每月的基础运行它们。

以下是一个简单的 shell 脚本`firefox_memcheck.sh`，它检查 Firefox 进程是否正在运行。如果 Firefox 正在运行，并且其内存使用大于 30％，则重新启动 Firefox：

```
#!/bin/sh
# Filename: firefox_memcheck.sh
# Desription: Resatrts application firefix if memory usage is more than 30%

pid='pidof firefox' # Get pid of firefox
if [ $pid -gt 1 ]
then
  # Get current memory usage of firefox
  current_mem_usage='ps -u --pid $pid| tail -n1 | tr -s ' ' | cut -d ' ' -f 4'
  # Check if firefox memory  usage is more than 30% or not
  if [ $(echo "$current_mem_usage > 30" | bc) -eq 1 ]
  then
    kill $pid   # Kill firefox if memory usage is > 30%
    firefox &   # Launch firefox
  fi
fi
```

我们可以将此脚本添加到系统的`/etc/cron.hourly/`目录中，它将持续检查我们的 Firefox 内存使用情况。此脚本可以修改为监视其他进程的内存使用情况。

## crontab 条目

通过将脚本放入`cron.{hourly, daily, weekly, monthly}`中，我们只能设置每小时、每天、每周和每月的间隔任务。如果一个任务需要以 2 天间隔、10 天间隔、90 分钟间隔等运行，该怎么办？为了实现这一点，我们可以将任务添加到`/etc/crontab`文件或`/etc/cron.d/`目录中。每个用户可能都有自己的 crontab 条目，与每个用户相关的文件位于`/var/spool/`中。

crontab 条目如下所示：

![Crontab entries](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_08_02.jpg)

我们可以从上述截图中看到，crontab 条目有五个星号。每个星号定义了一个特定的持续时间。我们可以用建议的值替换*，或者保持不变。如果在字段中提到*，那么它意味着考虑该字段的所有实例。

时间语法也可以描述如下：

+   指定**分钟**值介于 0 到 59 之间

+   指定**小时**范围从 0 到 23

+   指定**天数**范围从 1 到 31

+   指定**月份**范围从 1 到 12，或者我们可以写 Jan，Feb，... Dec

+   指定**一周中的某一天**范围从 0 到 6，或者我们可以写 sun（0），mon（1），...，sat（6）

所有五个字段由空格分隔。然后是一个**用户名**，指定命令将由哪个用户执行。指定用户名是可选的，默认情况下会作为 root 运行。最后一个字段是计划执行的命令。

演示如何编写 crontab 条目的示例如下：

```
20 7 * * 0 foo command

```

每个字段的解释如下：

+   `20`：第 20 分钟

+   `7`：上午 7 点

+   `*`：每天

+   `*`：每个月

+   `0`：星期日

+   `foo`：此命令将作为 foo 用户运行

+   `command`：要执行的指定命令

因此，命令将在每个星期日的上午 7:20 作为 root 运行。

我们可以使用逗号（，）指定字段的多个实例：

```
30 20,22 * * * command

```

在这里，`command`将在每天的 8:30 PM 和 10:30 PM 运行。

我们还可以使用连字符（`-`）在字段中指定一段时间的范围：

```
35 7-11 * * 0-3 command

```

这意味着在星期日、星期一、星期二和星期三的 7:35、8:35、9:35、10:35 和 11:35 运行命令。

要在特定间隔运行脚本，我们可以使用正斜杠（/）指定如下：

```
20-45/4 8 9 4 * command

```

该命令将在 4 月 9 日的 8:20 AM 至 8:45 AM 之间以 4 分钟的间隔运行。

### Crontab 中的特殊字符串

Crontab 还可以指定以下字符串：

| 字符串 | 描述 |
| --- | --- |
| `@hourly` | 每小时运行一次，相当于 0 * * * * |
| `@daily`或`@midnight` | 每天运行一次，相当于 0 0 * * * |
| `@weekly` | 每周运行一次，相当于 0 0 * * 0 |
| `@monthly` | 每月运行一次，相当于 0 0 1 * * |
| `@yearly`或`@annually` | 每年运行一次，相当于 0 0 1 1 * |
| `@reboot` | 在系统启动时运行 |

# 管理 crontab 条目

我们不直接添加或修改 crontab 的条目。可以使用`crontab`命令来添加、修改和列出 crontab 的条目。每个用户都可以有自己的 crontab，可以在其中添加、删除或修改任务。默认情况下，对所有用户启用，但如果系统管理员想要限制某些用户，可以将该用户添加到`/etc/cron.deny`文件中。

使用`crontab`命令的语法如下：

```
crontab [-u user] file
crontab [-u user] [option]

```

crontab 的选项在下表中解释：

| 选项 | 描述 |
| --- | --- |
| `-u user` | 追加要修改其`crontab`的用户的名称 |
| `-l` | 在`stdout`上显示当前的 crontab |
| `-e` | 使用`EDITOR env`指定的编辑器编辑当前的`crontab` |
| `-r` | 删除当前的`crontab` |
| `-i` | 与`-r`选项一起使用时，交互式删除当前的`crontab` |

## 列出 crontab 条目

要列出`crontab`条目，我们使用当前用户的`-l`选项：

```
$ crontab -l
no crontab for foo

```

输出显示用户`foo`没有`crontab`条目。这意味着用户`foo`尚未在其`crontab`中添加任何任务。

要以 root 用户身份查看`crontab`，请输入以下命令：

```
# crontab -l
no crontab for root

```

或者，使用以下命令：

```
$ sudo crontab -l

```

## 编辑 crontab 条目

当前用户的 crontab 可以使用`-e`选项与 crontab 进行编辑或修改：

```
$ crontab -e

```

执行上述命令后，将打开一个编辑器，用户可以在其中将任务添加到`crontab`文件中。在我们的情况下，启动了`vi`编辑器。以下条目已添加到用户`foo crontab`条目中：

![编辑 crontab 条目](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_08_03.jpg)

从编辑器保存并退出后，获得的输出如下：

```
no crontab for foo - using an empty one
crontab: installing new crontab
```

要查看用户`foo`的修改后的`crontab`条目，再次运行`-l`选项：

```
$ crontab -l

```

![编辑 crontab 条目](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_08_04.jpg)

要创建用户 root 的`crontab`条目，我们可以作为 root 使用`-e`选项运行`crontab`：

```
# crontab -e

```

或者

```
$ sudo crontab -e

```

运行上述命令后，编辑器将打开以修改用户 root 的`crontab`，在添加条目后如下所示：

![编辑 crontab 条目](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_08_05.jpg)

要查看 root 的`crontab`条目，我们可以使用`crontab -l`作为 root 用户：

```
# crontab -l

```

![编辑 crontab 条目](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_08_06.jpg)

root 用户还可以查看和修改另一个用户的`crontab`条目。这是通过指定`-u`选项，后跟用户名来完成的：

```
# crontab -u foo -e  # Modifying crontab of user foo as root

```

用户`foo`的 crontab 将如下所示打开以进行修改：

![编辑 crontab 条目](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_08_07.jpg)

要查看另一个用户的`crontab`条目，运行以下命令：

```
# crontab -u foo -l

```

我们可以如下显示用户`foo`的`crontab`：

![编辑 crontab 条目](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_08_08.jpg)

使用`crontab`命令创建 crontab 条目，并将其存储在`/var/spool/cron/`目录中。文件以用户名命名：

```
# ls /var/spool/cron
root  foo

```

我们可以看到为用户`root`和`foo`创建了一个文件。

## 删除 crontab 条目

我们还可以使用`crontab`命令的`-r`选项来删除`crontab`。默认情况下，将删除当前用户的`crontab`。使用`-i`选项允许交互式删除`crontab`：

```
# crontab -i -r
crontab: really delete root's crontab? Y

```

通过运行上述命令，已删除了用户 root 的`crontab`条目。我们可以通过运行`-l`选项来验证这一点：

```
# crontab -l
no crontab for root

#  ls /var/spool/cron
foo

```

用户 root 还可以通过在`-u`选项中指定用户来删除其他用户的`crontab`：

```
# crontab -r -i -u foo
crontab: really delete foo's crontab? n

```

我们指定了`n`（否）而不是`y`（是），因此将中止删除用户`foo crontab`。

现在让我们删除它：

```
# crontab -r -i -u foo
crontab: really delete foo's crontab? Y

```

现在，用户`foo`的`crontab`条目已被删除。要验证，请运行以下命令：

```
$  crontab -l
no crontab for foo

```

# systemd

如今，大多数 Linux 发行版系统，如 Fedora、Ubuntu、Arch Linux、Debian、openSUSE 等，已经从`init`切换到了 systemd。systemd 是系统启动后第一个启动的进程，具有 PID 1。它控制和管理其他应该在系统启动后启动的进程。它也被称为操作系统的基本构建块。要了解基于 init 的系统，请参考维基百科链接[`en.wikipedia.org/wiki/Init`](https://en.wikipedia.org/wiki/Init)。

## systemd 单元

systemd 有几个单元，每个单元包含一个关于服务、套接字、设备、挂载点、交换文件或分区、启动目标等的配置文件。

以下表格解释了一些单元文件：

| 单元类型 | 文件扩展名 | 描述 |
| --- | --- | --- |
| 服务单元 | `.service` | 系统服务 |
| 设备单元 | `.device` | 内核识别的设备文件 |
| 挂载单元 | `.mount` | 文件系统挂载点 |
| 定时器单元 | `.timer` | 一个 systemd 定时器 |
| 交换单元 | `.swap` | 交换文件 |

要列出系统中安装的所有单元文件，请使用`systemctl`命令和`list-unit-files`选项：

```
$ systemctl list-unit-files | head -n 12

```

![systemd 单元](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_08_09.jpg)

要列出单元类型的单元文件，请使用`list-unit-files`和`--type`选项。运行以下命令将只显示系统中可用的服务单元：

```
$ systemctl list-unit-files --type=service | head -n 10

```

![systemd 单元](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_08_10.jpg)

## 管理服务

systemd 管理系统中所有可用的服务，从 Linux 内核启动到系统关闭的时间。Linux 系统中的服务是在后台运行或等待使用的应用程序。服务管理文件的文件名后缀为`.service`。

在基于 systemd 的 Linux 系统中，用户或管理员可以使用`systemctl`命令管理服务。

### 服务状态

要列出当前服务的状态并检查它是否正在运行，使用`systemctl status`：

例如，要查看我的`NetworkManager`服务的状态，请运行以下命令：

```
$ systemctl status -l NetworkManager.service 

```

![服务状态](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_08_11.jpg)

我们可以看到`NetworkManager`服务正在运行并处于活动状态。它还提供了与当前`NetworkManager`服务相关的详细信息。

让我们看看另一个名为`sshd`的服务的状态。`sshd`服务控制是否可以对系统进行`ssh`连接：

```
$ systemctl status sshd.service

```

![服务状态](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_08_12.jpg)

这表明服务`sshd`目前处于非活动状态。

如果不需要详细的输出，那么我们可以只使用`is-active`选项来查看服务状态：

```
$ systemctl is-active sshd.service 
unknown
$ systemctl is-active NetworkManager.service
active

```

这里，`active`表示服务正在运行，`unknown`表示服务未运行。

### 启用和禁用服务

当系统启动时，systemd 会自动启动一些服务。也可能有一些服务没有运行。要在系统启动后启用服务运行，使用`systemctl enable`，要在系统启动时停止系统运行的服务，使用`systemctl disable`。

执行以下命令将允许 systemd 在系统启动后运行`sshd`服务：

```
# systemctl enable sshd.service

```

执行以下命令将允许 systemd 在系统启动时不运行`sshd.service`：

```
# systemctl disable sshd.service

```

要检查服务是否已启用，请运行`systemctl is-enabled`命令：

```
$ systemctl is-enabled sshd.service
disabled
$ systemctl is-enabled NetworkManager.service
enabled

```

这意味着`sshd`服务当前在系统启动时被禁用，而`NetworkManager`服务在启动时由`systemd`启用。

### 启动和停止服务

当系统运行时，有时我们可能需要一些服务在运行。例如，要在我的当前系统中从另一台系统进行`ssh`，`sshd`服务必须在运行。

例如，让我们看看`sshd`服务的当前状态：

```
$ systemctl is-active sshd.service
unknown

```

`sshd`服务当前未运行。让我们尝试在系统中进行`ssh`：

```
$ ssh foo@localhost  # Doing ssh to same machine  # Doing ssh to same machine
 ssh: connect to host localhost port 22: Connection refused

```

我们可以看到`ssh`连接已被拒绝。

现在，让我们开始运行`sshd`服务。我们可以使用以下命令`systemctl start`来启动服务：

```
# systemctl start sshd.service 
$ systemctl is-active sshd.service
active

```

现在，`sshd`服务正在运行。再次尝试从另一台机器进行`ssh`：

```
$ ssh foo@localhost
Last login: Fri Sep 25 23:10:21 2015 from 192.168.1.101

```

现在，登录已成功。

我们甚至可以使用`systemctl restart`命令重新启动正在运行的服务。当服务已被修改时，这是必需的。然后，要启用修改的设置，我们只需重新启动它。

```
#  systemctl restart sshd.service

```

上述命令将重新启动`sshd`服务。

当不再需要`ssh`时，停止运行它是安全的。这可以避免对机器的匿名访问。要停止运行服务，请运行`systemctl stop`命令：

```
# systemctl stop sshd.service
$ systemctl is-active sshd.service
unknown

```

## 查看系统日志

要检查用户是在个人还是企业机器上工作，查看系统日志对于追踪问题和获取系统中发生的活动的详细信息非常重要。查看系统日志在监视和确保网络流量不易受攻击方面起着重要作用。在基于 systemd 的系统上，系统日志由其一个组件`journald`收集和管理。它的任务是收集应用程序和内核的日志。日志文件位于`/var/log/journal/`目录中。

要查看`journald`收集的日志，使用`journalctl`命令：

```
# journalctl

```

运行上述命令会显示所有收集的系统日志，从旧的开始，逐渐增加到新的日志。

### 查看最新的日志条目

要查看最新的日志条目并持续打印追加到日志中的新条目，请使用`-f`选项：

```
$ journalctl -f

```

![查看最新的日志条目](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_08_13.jpg)

要查看自系统上次启动以来捕获的日志条目，请使用`-b`选项：

```
$ journalctl -b

```

![查看最新的日志条目](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_08_14.jpg)

### 查看特定时间间隔的日志

我们还可以查看特定时间间隔的日志。例如，要查看最近 1 小时的日志，我们可以运行以下命令：

```
$  journalctl --since "1 hour ago" --until now

```

要查看自 2015 年 7 月 1 日至今的日志条目，我们可以运行以下命令：

```
$ journalctl --since 2015-07-01

```

要查看从 2015 年 8 月 7 日下午 7:23 到 2015 年 8 月 9 日上午 7 点的日志，我们可以运行以下命令：

```
$ journalctl --since "2015-08-07 19:23:00" --until "2015-08-09 7:00:00" 

```

# 嵌入语言

与其他脚本编程语言（如 Python、Ruby、Perl 和 AWK）相比，Shell 脚本提供了一定的功能集。这些语言提供了与 Shell 脚本语言相比的附加功能。在 Linux 和基于 UNIX 的系统上，要使用这些语言，如果它们没有预装，我们必须单独安装它们。

考虑一个简单的例子：有一个 json 或 XML 文件，我们想解析它并检索其中存储的数据。使用 shell 及其命令来做这件事非常困难且容易出错，但如果我们了解 Python 或 Ruby 语言，我们可以很容易地做到这一点，然后将其嵌入到 shell 脚本中。应该嵌入 shell 脚本中的另一种语言以减少工作量并实现更好的性能。

在 shell 脚本中嵌入其他语言的语法如下：

| 脚本语言 | 嵌入到 shell 脚本中的语法 |
| --- | --- |
| Python（Python 版本 2） | `python -c` ' '。在单引号中编写要处理的 Python 代码 |
| Python3 | `python3 -c` ' '。在单引号中编写要处理的 Python 版本 3 代码 |
| Perl | `perl -e` ' '。在单引号中编写 Perl 代码。 |
| Ruby | `ruby -e` ' '。在单引号中编写 Ruby 代码。 |
| AWK | 这可以用作命令实用程序。有关可用选项，请参阅 awk man 页面。 |

## 嵌入 Python 语言

要在 shell 脚本中嵌入 Python 语言，我们将使用`python -c " Python Code"`。要了解 Python，请参阅官方网站[`www.python.org/`](https://www.python.org/)。

一个简单的 Python 示例是在 Python 中打印`Hello World`，如下所示：

```
print "Hello World"
```

将此嵌入到 shell 脚本中，我们可以编写以下代码

```
#!/bin/bash
# Filename: python_print.sh
# Description: Embeding python in shell script

# Printing using Python
python -c 'print "Hello World"'
```

我们现在将执行`python_print.sh`脚本如下：

```
$ sh python_print.sh
Hello World

```

要在 shell 脚本中嵌入多行 Python 代码，请使用以下代码：

```
 python -  <<EOF
# Python code
EOF
```

这里，**python -**指示 python 命令从 stdin 获取输入，`EOF`是一个标签，指示获取 stdin 输入直到遇到`EOF`文本。

以下示例在 shell 脚本中嵌入 Python 语言，并从用户的 Gmail 帐户中获取未读邮件：

```
#!/bin/bash
# Filename: mail_fetch.sh
# Description: Fetching unread email from gmail by embedding python in shell script

# Enter username and password of your gmail account
echo Enter your gmail username:
read USER
echo Enter password:
read -s PASSWD

echo Running python code
python - <<CODE
# Importing required Python module

import urllib2
import getpass
import xml.etree.ElementTree as ET

# Function to get unread messages in XML format
def get_unread_msgs(user, passwd):
    auth_handler = urllib2.HTTPBasicAuthHandler()
    auth_handler.add_password(
        realm='mail.google.com',
        uri='https://mail.google.com',
        user=user,
        passwd=passwd
    )
    opener = urllib2.build_opener(auth_handler)
    urllib2.install_opener(opener)
    feed = urllib2.urlopen('https://mail.google.com/mail/feed/atom')
    return feed.read()

xml_data = get_unread_msgs("$USER", "$PASSWD")
root = ET.fromstring(xml_data)

# Getting Title of unread emails
print "Title of unread messages:"
print "........................"
count=0
for e in root.iter('{http://purl.org/atom/ns#}title'):
    print e.text

CODE

echo "Done!"
```

执行此脚本后，示例输出如下：

```
$ sh mail_fetch.sh
Enter your gmail username:
foo@gmail.com
Enter password:

Running python code
Title of unread messages:
.....................……………..
Gmail - Inbox for foo@gmail.com
Unread message1
unread message2
Unread message3
Done!
```

## 嵌入 AWK 语言

Awk 是一种用于文本处理的编程语言，主要用于获取相关数据和报告工具。要了解更多关于 AWK 编程语言的信息，请参阅其 man 页面或访问网站[`www.gnu.org/software/gawk/manual/gawk.html`](http://www.gnu.org/software/gawk/manual/gawk.html)。

Awk 语言可以很容易地在 shell 脚本中使用。例如，考虑在运行系统上执行`df`命令的输出：

```
$ df -h

```

![嵌入 AWK 语言](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_08_15.jpg)

要使用`awk`获取第四列，即`Avail`字段，我们可以编写一个使用`awk`的 shell 脚本如下：

```
#!/bin/bash
# Filename: awk_embed.sh
# Description: Demonstrating using awk in shell script

# Fetching 4th column of command df output
df -h |awk '{ print $4 }'
```

![嵌入 AWK 语言](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sh-scp-ess/img/4335_08_16.jpg)

考虑另一个例子，我们将使用一个输入文件，该文件将是系统的`/etc/passwd`文件。该文件包含有关 Linux 或基于 UNIX 的系统上每个用户或帐户的基本信息。

`/etc/passwd`文件的每一行如下所示：

```
root:x:0:0:root:/root:/bin/bash

```

有七个字段，每个字段由冒号（:）分隔。要了解每个字段的详细含义，请参阅[`en.wikipedia.org/wiki/Passwd`](https://en.wikipedia.org/wiki/Passwd)上的维基百科链接。

以下 shell 脚本利用 awk 功能并从`/etc/passwd`文件中显示一些有用的信息。例如，我们将考虑以下作为`passwd`文件的内容：

```
$ cat passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt

$ cat passwd_file_info.sh	   # Shell script content
#!/bin/bash
# Filename: passwd_file_info.sh
# Desciption: Fetches useful information from /etc/passwd file using awk

# Fetching 1st and 3rd field i.e. Username and UID and separate them with blank space
awk -F":" '{ print "Username: " $1 "\tUID:" $3 }' passwd

# Searching line whose user is root
echo "User root information"
awk '$1 ~ /^root/' passwd

```

运行此脚本会得到以下结果：

```
$ sh passwd_file_info.sh
Username: root  UID:0
Username: bin   UID:1
Username: daemon        UID:2
Username: adm   UID:3
Username: lp    UID:4
Username: sync  UID:5
Username: shutdown      UID:6
Username: halt  UID:7

User root information
root:x:0:0:root:/root:/bin/bash 

```

### 注意

还可以在 shell 脚本中使用编译语言，如 C、C++和 Java。为此，编写命令来编译和执行代码。

# 摘要

阅读完本章后，你现在应该知道如何使用`at`命令安排任务在特定时间执行。你还应该知道创建 Cron 作业的好处，这些作业需要多次执行。你还应该学会如何使用`crontab`命令来添加、修改、列出和删除 crontab 条目。你还应该对`systemd`有很好的理解——这是系统上创建的第一个进程，它管理其他系统进程、服务和日志。你还应该知道如何在 shell 脚本中嵌入其他脚本语言，比如 Python、AWK、Ruby 等。

阅读完所有这些章节并练习了例子后，你现在应该对 shell 脚本有信心了。作为命令行的大师，你现在能够编写自己的 shell 脚本来解决日常任务。最后，如果这本书中没有涵盖的内容，你知道应该查看任何命令的 man 页面以获取帮助。
