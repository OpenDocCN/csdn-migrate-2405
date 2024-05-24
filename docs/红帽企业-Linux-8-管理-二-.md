# 红帽企业 Linux 8 管理（二）

> 原文：[`zh.annas-archive.org/md5/0CCDE6F20D3A1D212C45A9BF7E65144A`](https://zh.annas-archive.org/md5/0CCDE6F20D3A1D212C45A9BF7E65144A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：常规操作工具

在本书的这一部分，我们已经安装了一个系统，并且已经涵盖了一些可以创建来自动化任务的脚本，所以我们已经到了可以专注于系统本身的地步。

拥有一个正确配置的系统不仅需要安装，还需要了解如何在特定时间运行任务，保持所有服务适当运行，并配置时间同步、服务管理、引导目标（运行级别）和计划任务，所有这些内容我们将在本章中介绍。

在本章中，您将学习如何检查服务的状态，如何启动、停止和排除故障，以及如何为服务器或整个网络保持系统时钟同步。

将涵盖的主题列表如下：

+   使用 systemd 管理系统服务

+   使用 cron 和 systemd 进行任务调度

+   学习使用 chrony 和 ntp 进行时间同步

+   检查空闲资源 - 内存和磁盘（free 和 df）

+   查找日志，使用 journald 和阅读日志文件，包括日志保存和轮换

# 技术要求

您可以使用我们在本书开头创建的虚拟机来完成本章。此外，为了测试*NTP 服务器*，可能需要创建第二个虚拟机，该虚拟机将连接到第一个虚拟机作为客户端，遵循我们用于第一个虚拟机的相同过程。此外，所需的软件包将在文本中指示。

# 使用 systemd 管理系统服务

在本节中，您将学习如何使用**systemd**管理**系统服务**，运行时目标，以及有关**systemd**的服务状态。您还将学习如何管理系统引导目标和应该在系统引导时启动的服务。

`systemd`（您可以在[`www.freedesktop.org/wiki/Software/systemd/`](https://www.freedesktop.org/wiki/Software/systemd/)了解一些）被定义为用于管理系统的系统守护程序。它作为对传统启动和启动方式的重新设计而出现，它看待与传统方式相关的限制。

当我们考虑系统启动时，我们有初始**内核**和**ramdisk**的加载和执行，但在此之后，服务和脚本接管，使文件系统可用。这有助于准备提供我们系统所需功能的服务，例如以下内容：

+   硬件检测

+   附加文件系统激活

+   网络初始化（有线，无线等）

+   网络服务（时间同步，远程登录，打印机，网络文件系统等）

+   用户空间设置

然而，大多数在`systemd`出现之前存在的工具都是按顺序进行操作，导致整个启动过程（从启动到用户登录）变得冗长并且容易受到延迟的影响。

传统上，这也意味着我们必须等待所需的服务完全可用，然后才能启动依赖于它的下一个服务，增加了总启动时间。

一些尝试的方法，比如使用*monit*或其他允许我们定义依赖关系、监视进程甚至从故障中恢复的工具，但总的来说，这是重用现有工具来执行其他功能，试图赢得关于启动最快的系统的竞赛。

重要提示

`systemd`重新设计了这个过程，专注于简单性：启动更少的进程并进行更多的并行执行。这个想法本身听起来很简单，但需要重新设计过去被视为理所当然的很多东西，以便专注于改进操作系统性能的新方法的需求。

这种重新设计带来了许多好处，但也伴随着代价：它彻底改变了系统以前的启动方式，因此在不同供应商中对`systemd`的采用引起了很多争议，甚至社区也做出了一些努力提供不带 systemd 的变种。

合理地启动服务，只启动必需的服务，是提高效率的好方法，例如，当系统断开连接时，没有蓝牙硬件或没有人在打印时，就没有必要启动蓝牙、打印机或网络服务。减少等待启动的服务，系统启动不会因为等待而延迟，而是专注于真正需要关注的服务。

除此之外，并行执行允许我们让每个服务花费所需的时间准备好，但不会让其他服务等待，因此一般来说，并行运行服务初始化允许我们最大限度地利用 CPU、磁盘等，而每个服务的等待时间被其他活动的服务使用。

`systemd`还会在实际守护程序启动之前预先创建监听套接字，因此对其他服务有依赖关系的服务可以启动并处于等待状态，直到其依赖项启动。这样做是为了不让它们丢失任何发送给它们的消息，因此当服务最终启动时，它将执行所有待处理的操作。

让我们多了解一些关于*systemd*，因为它将需要用于我们将在本章中描述的几个操作。 

*Systemd*具有单位的概念，它们只是配置文件。这些单位可以根据其文件扩展名进行分类为不同类型：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/Table_4.1.jpg)

提示

不要被不同的`systemd`单位类型所压倒。一般来说，最常见的是**Service**、**Timer**、**Socket**和**Target**。

当然，这些单位文件应该被找到在一些特定的文件夹中：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/Table_4.2.jpg)

正如我们之前提到的关于套接字，当系统访问该路径时，路径、总线等单位文件被激活，允许在另一个服务需要它们时启动服务。这为降低系统启动时间增加了更多的优化。

通过这样，我们已经了解了*systemd*单位类型。现在，让我们专注于单位文件的文件结构。

## *systemd*单位文件结构

让我们通过一个例子来动手实践：一个系统已经部署并启用了`sshd`，我们需要在网络初始化后运行它，这样可以提供连接。

正如我们之前提到的，`systemd`使用单位文件，我们可以检查前面提到的文件夹，或者使用`systemctl list-unit-files`列出它们。记住，每个文件都是一个定义*systemd*应该做什么的配置文件；例如，`/usr/lib/systemd/system/chronyd.service`：

![图 4.1 - chronyd.service 的内容]

](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_04_001.jpg)

图 4.1 - chronyd.service 的内容

这个文件不仅定义了要启动的传统程序和 PID 文件，还定义了依赖关系、冲突和软依赖关系，这为`systemd`提供了足够的信息来决定正确的方法。

如果你熟悉"*inifiles*"，这个文件使用了那种方法，即使用方括号`[`和`]`表示部分，然后在每个部分的设置中使用`key=value`的配对。

部分名称是区分大小写的，因此如果不使用正确的命名约定，它们将无法被正确解释。

部分指令的命名如下：

+   [单位]

+   [安装]

每种类型都有额外的条目：

+   [服务]

+   [套接字]

+   [挂载]

+   [自动挂载]

+   [交换]

+   [路径]

+   [定时器]

+   [切片]

正如你所看到的，我们为每种类型都有特定的部分。如果我们执行`man systemd.unit`，它将为你提供示例，以及你正在使用的*systemd*版本的所有支持的值：

![图 4.2 - systemd.unit 的 man 页面]

](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_04_002.jpg)

图 4.2 - systemd.unit 的 man 页面

通过这样，我们已经审查了单位文件的文件结构。现在，让我们使用*systemctl*来实际管理服务的状态。

## 管理服务在启动时启动和停止

服务可以启用或禁用；也就是说，服务将或不会在系统启动时被激活。

如果您熟悉 RHEL 中以前可用的工具，通常会使用`chkconfig`根据其默认的`rc.d/`设置来定义服务的状态。

可以通过以下命令启用`sshd`等服务：

```
#systemctl enable sshd
```

也可以通过以下命令禁用：

```
#systemctl disable sshd
```

这将创建或删除`/etc/systemd/system/multi-user.target.wants/sshd.service`。注意路径中的`multi-user.target`，它相当于我们用来配置其他方法（如**initscripts**）的运行级别。

提示

尽管传统的`chkconfig sshd on/off`或`service start/stop/status/restart sshd`的用法是有效的，但最好习惯于本章中描述的`systemctl`方法。

前面的命令在启动时启用或禁用服务，但要执行即时操作，我们需要发出不同的命令。

要启动`sshd`服务，请使用以下命令：

```
#systemctl start sshd
```

要停止它，请使用以下命令：

```
#systemctl stop sshd
```

当然，我们也可以检查服务的状态。以下是通过`systemctl status sshd`查看`systemd`的示例：

![图 4.3 - sshd 守护程序的状态](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_04_003.jpg)

图 4.3 - sshd 守护程序的状态

此状态信息提供了有关定义服务的单元文件、其在启动时的默认状态、它是否正在运行、其 PID、其资源消耗的其他详细信息，以及服务的一些最近的日志条目，这在调试简单的服务启动故障时非常有用。

检查`systemctl list-unit-files`的输出是很重要的，因为它报告了系统中定义的单元文件，以及每个单元文件的当前状态和供应商预设。

现在我们已经介绍了如何启动/停止和检查服务的状态，让我们来管理实际的系统引导状态本身。

## 管理引导目标

我们在启动时定义的默认状态在谈论**运行级别**时很重要。

运行级别根据使用定义了一组预定义的服务；也就是说，它们定义了在使用特定功能时将启动或停止哪些服务。

例如，有一些运行级别用于定义以下内容：

+   **停止模式**

+   **单用户模式**

+   **多用户模式**

+   **网络化多用户**

+   **图形**

+   **重新启动**

这些运行级别允许在运行级别更改时启动/停止一组预定义的服务。当然，级别以前是基于彼此的，并且非常简单：

+   停止所有服务，然后停止或关闭系统。

+   单用户模式为一个用户启动一个 shell。

+   多用户模式在虚拟终端上启用常规登录守护程序。

+   网络化就像多用户，但网络已启动。

+   图形就像网络化，但通过显示管理器（`gdm`或其他）进行图形登录。

+   重新启动就像停止，但在处理服务结束时，它会发出重新启动而不是停止。

这些运行级别（以及系统启动时的默认运行级别）以前是在`/etc/inittab`中定义的，但文件占位符提醒我们以下内容：

```
# inittab is no longer used.
#
# ADDING CONFIGURATION HERE WILL HAVE NO EFFECT ON YOUR SYSTEM.
#
# Ctrl-Alt-Delete is handled by /usr/lib/systemd/system/ctrl-alt-del.target
#
# systemd uses 'targets' instead of runlevels. By default, there are two main targets:
#
# multi-user.target: analogous to runlevel 3
# graphical.target: analogous to runlevel 5
#
# To view current default target, run:
# systemctl get-default
#
# To set a default target, run:
# systemctl set-default TARGET.target
```

因此，通过对`systemd`进行此更改，现在可以检查可用的引导目标并定义它们的新方法。

我们可以通过列出此文件夹来找到可用的系统目标：

```
#ls -l /usr/lib/systemd/system/*.target
```

或者更正确地说，我们可以使用`systemctl`，如下所示：

```
#systemctl list-unit-files *.target
```

当您在系统上检查输出时，您会发现 0 到 6 的运行级别的一些兼容别名，这些别名与传统的运行级别提供兼容性。

例如，对于常规服务器使用，当您在没有图形模式下运行时，默认目标将是`multi-user.target`，当您使用图形模式时将是`graphical.target`。

我们可以按照`/etc/inittab`中的占位符的指示，通过执行以下命令来定义要使用的新运行级别：

```
#sysemctl set-default TARGET.target
```

我们可以使用以下命令验证活动状态：

```
#systemctl get-default
```

这就引出了下一个问题：*目标定义是什么样的*？让我们来看一下以下截图中的输出：

![图 4.4 - 从其目标单元定义的运行级别 5 的内容](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_04_004.jpg)

图 4.4 - 从其目标单元定义的运行级别 5 的内容

如您所见，它被设置为另一个目标（**multi-user.target**）的依赖项，并且对其他服务（如**display-manager.service**）有一些要求，还有其他冲突，只有在其他目标完成时才能达到该目标。

通过这种方式，`systemd`可以选择适当的服务启动顺序和达到配置的引导目标的依赖关系。

有了这些，我们已经了解了服务的状态，以及如何在启动时启动、停止和启用它，但是还有其他任务我们应该以周期性的方式在系统中执行。让我们进一步探讨这个话题。

# 使用 cron 和 systemd 进行任务调度

您将在本节中学习的技能将涉及为业务服务和维护安排周期性任务。

对于常规的系统使用，有一些需要定期执行的任务，范围从临时文件夹清理、更新缓存的刷新率，到与库存系统进行检查等等。

设置它们的传统方式是通过`cronie`软件包。

Cronie 实现了一个与传统的*vixie cron*兼容的守护程序，允许我们定义用户和系统 crontab。

Crontab 定义了必须执行的任务的几个参数。让我们看看它是如何工作的。

## 系统范围的 crontab

系统范围的 crontab 可以在`/etc/crontab`中定义，也可以在`/etc/cron.d`中的单独文件中定义。还存在其他附加文件夹，如`/etc/cron.hourly`、`/etc/cron.daily`、`/etc/cron.weekly`和`/etc/cron.monthly`。

在*每小时*、*每天*、*每周*或*每月*的文件夹中，您可以找到脚本或符号链接。当满足自上次执行以来的时间段（一小时、一天、一周、一个月）时，将执行该脚本。

相比之下，在`/etc/crontab`或`/etc/cron.d`以及用户 crontab 中，使用标准的作业定义。

通过指定与执行周期相关的参数、将执行作业的用户（除了用户 crontab 外）和要执行的命令来定义作业：

```
# Run the hourly jobs
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root
01 * * * * root run-parts /etc/cron.hourly
```

通过查看标准的`/etc/crontab`文件，我们可以检查每个字段的含义：

```
# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name  command to be executed
```

基于此，如果我们检查初始示例`01 * * * * root run-parts /etc/cron.hourly`，我们可以推断如下：

+   每分钟运行`01`。

+   每小时运行。

+   每天运行。

+   每月运行。

+   每周的每一天运行。

+   以`root`身份运行。

+   执行`run-parts /etc/cron.hourly`命令。

简而言之，这意味着作业将以`root`用户身份在每小时的第一分钟运行。

有时，可能会看到一个指示，比如**/number*，这意味着作业将在该数字的倍数上执行。例如，**/3*将在第一列上每 3 分钟运行一次，在第二列上每 3 小时运行一次，依此类推。

我们可以通过 cron 执行从命令行执行的任何命令，并且默认情况下，输出将通过邮件发送给运行作业的用户。通常的做法是在 crontab 文件中定义将接收电子邮件的用户的`MAILTO`变量，或者将它们重定向到适当的日志文件以获取标准输出和标准错误（`stdout`和`stderr`）。

## 用户 crontab

与系统范围的**crontab**一样，用户可以定义自己的 crontab，以便用户执行任务。例如，这对于为人类用户或服务的系统帐户运行周期性脚本非常有用。

用户 crontab 的语法与系统范围的语法相同。但是，用户名的列不在那里，因为它总是作为定义 crontab 本身的用户执行。

用户可以通过`crontab -l`检查其 crontab：

```
[root@el8-692807 ~]# crontab -l
no crontab for root
```

可以通过编辑`crontab -e`来创建一个新的，这将打开一个文本编辑器，以便创建一个新的条目。

让我们通过创建一个条目来举例说明，就像这样：

```
*/2 * * * * date >> datecron
```

当我们退出编辑器时，它会回复以下内容：

```
crontab: installing new crontab
```

这将在`/var/spool/cron/`文件夹中创建一个文件，文件名为创建它的用户。它是一个文本文件，因此您可以直接检查其内容。

一段时间后（至少 2 分钟），我们将在我们的`$HOME`文件夹中有一个包含每次执行内容的文件（因为我们使用*追加*重定向；即`>>`）：

```
[root@el8-692807 ~]# cat datecron 
Mon Jan 11 21:02:01 GMT 2021
Mon Jan 11 21:04:01 GMT 2021
```

现在我们已经了解了传统的 crontab，让我们了解一下 systemd 的做事方式；也就是使用定时器。

## Systemd 定时器

除了常规的**Cron 守护程序**，cron 风格的 systemd 功能是使用**定时器**。定时器允许我们通过一个单元文件定义将要执行的作业。

我们可以使用以下代码检查系统中已经可用的定时器：

```
>systemctl list-unit-files *.timer
...
timers.target                          static
dnf-makecache.timer                    enabled
fstrim.timer                           disabled
systemd-tmpfiles-clean.timer           static
...
```

例如，我们来看一下`fstrim.timer`，它用于 SSD 驱动器在`/usr/lib/systemd/system/fstrim.timer`执行修剪：

```
[Unit]
Description=Discard unused blocks once a week
Documentation=man:fstrim
..
[Timer]
OnCalendar=weekly
AccuracySec=1h
Persistent=true
…
[Install]
WantedBy=timers.target
```

上述定时器设置了每周执行`fstrim.service`：

```
[Unit]
Description=Discard unused blocks

[Service]
Type=oneshot
ExecStart=/usr/sbin/fstrim -av
```

正如`fstrim -av`命令所示，我们只执行一次。

服务定时器与服务本身一样，作为单元文件的一个优点是，它可以通过`/etc/cron.d/`文件与常规的*cron*守护程序一起部署和更新，这由*systemd*处理。

现在我们对如何安排任务有了更多了解，但要获得完整的图片，安排总是需要适当的时间，所以下面我们将介绍这一点。

# 学习使用 chrony 和 NTP 进行时间同步

在本节中，您将了解**时间同步**的重要性以及如何配置服务。

对于连接的系统，保持与时间相关的真相是很重要的（考虑银行账户、收款转账、出款支付等，这些都必须被正确地时间戳和排序）。此外，考虑用户连接之间的日志跟踪、发生的问题等；它们都需要同步，以便我们可以在涉及到的所有不同系统之间进行诊断和调试。

您可能会认为在系统配置时定义的系统时钟应该是正常的，但仅仅设置系统时钟是不够的，因为时钟往往会漂移；内部电池可能导致时钟漂移或甚至重置，甚至强烈的 CPU 活动也会影响它。为了保持时钟的准确性，它们需要定期与修正漂移并尝试预测未来漂移的参考时钟同步。

系统时钟可以与*GPS*设备同步，例如，或者更容易地与其他连接到更精确时钟的系统同步（其他 GPS 设备、原子钟等）。**网络时间协议**（**NTP**）是一种互联网协议，通过 UDP 用于维护客户端和服务器之间的通信。

提示

NTP 通过层级来组织服务器。层级 0 设备是 GPS 设备或原子钟，直接向服务器发送信号，层级 1 服务器（主服务器）连接到层级 0 设备，层级 2 服务器连接到层级 1 服务器，依此类推...这种层级结构允许我们减少对更高层级服务器的使用，同时为我们的系统保持可靠的时间来源。

客户端连接到服务器，并比较接收到的时间以减少网络延迟的影响。

让我们看看 NTP 客户端是如何工作的。

## NTP 客户端

在 RHEL8 中，*chrony*在启用时充当服务器和客户端（通过`chronyc`命令），并且具有一些功能，使其适用于当前的硬件和用户需求，例如波动的网络（笔记本电脑挂起/恢复或不稳定的连接）。

一个有趣的特性是*chrony*在初始同步后不会**step**时钟，这意味着时间不会*跳跃*。相反，系统时钟会以更快或更慢的速度运行，以便在一段时间后，它将与其使用的参考时钟同步。这使得时间从操作系统和应用程序的角度来看是连续的：秒针比起钟表来说要快或慢，直到它们与参考时钟匹配。

Chrony 通过`/etc/chrony.conf`进行配置，并充当客户端，因此它连接到服务器以检查它们是否有资格成为时间源。传统的**server**指令和**pool**之间的主要区别在于后者可以接收多个条目，而前者只使用一个。可以有多个服务器和池，因为实际上，一旦删除了重复项，服务器将被添加到可能的源列表中。

对于*pool*或*server*指令，有几个可用的选项（在`man chrony.conf`中有描述），例如`iburst`，它可以加快检查速度，以便它们可以快速过渡到同步状态。

可以使用`chronyc sources`来检查实际的时间源：

![图 4.5 – chronyc sources 输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_04_005.jpg)

图 4.5 – chronyc sources 输出

正如我们所看到的，我们可以根据第一列（**M**）知道每个服务器的状态是什么：

+   **^**：这是一个服务器

+   **=**：这是一个对等体

在第二列（S）中，我们可以看到每个条目的不同状态：

+   *****：这是我们当前的同步服务器。

+   **+**：这是另一个可接受的时间源。

+   **?**：用于指示已失去网络连接的源。

+   **x**：此服务器被认为是虚假的滴答器（与其他来源相比，其时间被认为是不一致的）。

+   **~**：具有高变异性的源（它也会在守护程序启动期间出现）。

因此，我们可以看到我们的系统连接到一个正在考虑`ts1.sct.de`作为参考的服务器，这是一个 stratum 2 服务器。

可以通过`chronyc tracking`命令检查更详细的信息：

![图 4.6 – Chronyc 跟踪输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_04_006.jpg)

图 4.6 – Chronyc 跟踪输出

这提供了关于我们的时钟和参考时钟的更详细信息。前面截图中的每个字段具有以下含义：

+   **字段**：描述。

+   **参考 ID**：系统已同步的服务器的 ID 和名称/IP。

+   **Stratum**：我们的 stratum 级别。在此示例中，我们的同步服务器是一个 stratum 3 时钟。

+   **参考时间**：上次处理参考的时间。

+   **系统时间**：在正常模式下运行时（没有时间跳跃），这指的是系统与参考时钟的偏离。

+   **最后偏移**：最后一次时钟更新的估计偏移。如果是正数，这表示我们的本地时间超前于我们的来源。

+   **RMS 偏移**：偏移值的长期平均值。

+   **频率**：如果*chronyd*不修复它，系统时钟的错误率，以百万分之一表示。

+   **剩余频率**：反映当前参考时钟测量之间的任何差异。

+   **偏差**：频率的估计误差。

+   **根延迟**：到 stratum -1 同步服务器的总网络延迟。

+   **根分散**：通过连接到我们同步的 stratum -1 服务器的所有计算机累积的总分散。

+   **更新间隔**：最后两次时钟更新之间的间隔。

+   `/usr/share/doc/program/`），等等。例如，关于此处列出的每个字段的更详细信息可以通过`man chronyc`命令找到。

要配置客户端的其他选项，除了安装时提供的选项或通过 kickstart 文件提供的选项，我们可以编辑`/etc/chrony.cnf`文件。

让我们学习如何将我们的系统转换为我们网络的 NTP 服务器。

## NTP 服务器

正如我们之前介绍的，*chrony*也可以配置为您的网络的服务器。在这种模式下，我们的系统将向其他主机提供准确的时钟信息，而不消耗来自更高层级服务器的外部带宽或资源。

这个配置也是通过`/etc/chrony.conf`文件进行的，我们将在这里添加一个新的指令；即`allow`：

```
# Allow NTP client access from all hosts
allow all
```

此更改使*chrony*能够监听所有主机请求。或者，我们可以定义一个子网或主机来监听，例如`allow 1.1.1.1`。可以使用多个指令来定义不同的子网。另外，您可以使用*deny*指令来阻止特定主机或子网访问我们的 NTP 服务器。

服务时间从我们的服务器已经与之同步的基础开始，以及一个外部 NTP 服务器，但让我们考虑一个没有连接性的环境。在这种情况下，我们的服务器将不连接到外部来源，也不会提供时间。

*chrony*允许我们为我们的服务器定义一个虚假的层级。这是通过配置文件中的`local`指令完成的。这允许守护程序获得更高的本地层级，以便它可以向其他主机提供时间；例如：

```
local stratum 3 orphan
```

通过这个指令，我们将本地层级设置为 3，并使用**orphan**选项，这将启用一个特殊模式，在这个模式下，所有具有相同本地层级的服务器都会被忽略，除非没有其他来源可供选择，且其参考 ID 小于本地 ID。这意味着我们可以在我们的断开网络中设置几个 NTP 服务器，但只有一个会成为参考。

现在我们已经涵盖了时间同步，我们将深入资源监视。稍后，我们将研究日志记录。所有这些都与我们系统的时间参考有关。

# 检查空闲资源 - 内存和磁盘（free 和 df）

在这一部分，您将检查系统**资源**的可用性，例如**内存**和**磁盘**。

保持系统平稳运行意味着使用监视，以便我们可以检查服务是否正在运行，以及系统是否为它们提供了资源来执行它们的任务。

有一些简单的命令可以用来监视最基本的用例：

+   磁盘

+   CPU

+   内存

+   网络

这包括几种监视方式，例如一次性监视、连续监视，或者甚至在一段时间内进行诊断性能更好。

## 内存

内存可以通过`free`命令进行监视。它提供了有关可用和正在使用多少*RAM*和*SWAP*的详细信息，这也表明了多少内存被共享、缓冲或缓存使用。

Linux 倾向于使用所有可用的内存；任何未使用的 RAM 都会被指向缓存或缓冲区，以及未被使用的内存页面。如果可用，这些将被交换到磁盘上：

```
# free
              total        used        free      shared  buff/cache   available
Mem:         823112      484884       44012        2976      294216      318856
Swap:       8388604      185856     8202748
```

例如，在上面的输出中，我们可以看到系统总共有 823 MB 的 RAM，并且它正在使用一些交换空间和一些内存用于缓冲。这个系统没有大量交换，因为它几乎处于空闲状态（我们将在本章后面检查负载平均值），所以我们不应该担心它。

当 RAM 使用量很高且没有更多的交换空间可用时，内核会包括一种保护机制，称为**OOM-Killer**。它根据执行时间、资源使用情况等确定系统中应终止哪些进程以恢复系统，使其正常运行。然而，这是有代价的，因为内核知道可能已经失控的进程。然而，杀手可能会杀死数据库和 Web 服务器，并使系统处于不稳定状态。对于生产服务器，有时候典型的做法是，不是让 OOM-Killer 开始以不受控制的方式杀死进程，而是调整一些关键进程的值，使它们不被杀死，或者导致系统崩溃。

系统崩溃用于收集可以稍后通过包含导致崩溃的原因以及可以进行诊断的内存转储的调试信息。

我们将在*第十六章*中回到这个话题，*使用 tuned 进行内核调优和管理性能配置文件*。让我们继续检查正在使用的磁盘空间。

## 磁盘空间

可以通过`df`检查磁盘空间，它为每个文件系统提供数据输出。这表示文件系统及其大小、可用空间、利用率百分比和挂载点。

让我们在我们的示例系统中检查一下：

```
> df
Filesystem                    1K-blocks     Used Available Use% Mounted on
devtmpfs                         368596        0    368596   0% /dev
tmpfs                            411556        0    411556   0% /dev/shm
tmpfs                            411556    41724    369832  11% /run
tmpfs                            411556        0    411556   0% /sys/fs/cgroup
/dev/mapper/rhel-root          40935908 11026516  29909392  27% 
/dev/sda2                       1038336   517356    520980  50% /boot
/dev/sda1                        102182     7012     95170   7% /boot/efi
tmpfs                             82308        0     82308   0% /run/user/1000
```

通过使用这个工具，可以轻松关注利用率较高且剩余空间较少的文件系统，以防止问题发生。

重要提示

如果文件正在被写入，比如由一个进程记录其输出，那么删除文件只会将文件从文件系统中取消链接，但由于进程仍然保持文件句柄打开，直到进程停止，空间才会被回收。在必须尽快释放磁盘空间的紧急情况下，最好通过重定向清空文件，比如`echo "" > filename`。这样可以在进程仍在运行时立即恢复磁盘空间。使用`rm`命令会要求进程被完成。

接下来我们将检查 CPU 使用率。

## CPU

在监视 CPU 方面，我们可以利用多种工具，比如`ps`：

![图 4.7 - ps aux 命令的输出（系统中的每个进程）](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_04_007.jpg)

图 4.7 - ps aux 命令的输出（系统中的每个进程）

`ps`命令是检查正在运行的进程以及资源消耗情况的事实标准。

对于任何其他命令，我们都可以写很多关于可以使用的所有不同命令参数的内容（所以，再次，查看 man 页面以获取详细信息），但通常来说，尽量了解它们的基本用法或对你更有用的用法。其他情况，请查看手册。例如，`ps aux`提供了足够的信息供正常使用（系统中的每个进程）。

`top`工具，如下面的截图所示，会定期刷新屏幕，并可以对运行中的进程进行排序，比如 CPU 使用率、内存使用率等。此外，`top`还显示了关于内存使用情况、负载平均、运行中的进程等的五行摘要：

![图 4.8 - 在我们的测试系统上执行 top 命令](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_04_008.jpg)

图 4.8 - 在我们的测试系统上执行 top 命令

CPU 使用率并不是唯一可能使系统变得缓慢的因素。现在，让我们稍微了解一下负载平均指标。

## 负载平均

负载平均通常以三个数字的形式提供，比如`负载平均：0.81，1.00，1.17`，分别是 1、5 和 15 分钟的平均值。这表示系统有多忙；数值越高，响应越差。每个时间段比较的值给我们一个概念，即系统负载是增加的（1 或 5 分钟内的值较高，15 分钟内的值较低），还是正在减少（15 分钟内的值较高，5 和 1 分钟内的值较低），因此这成为了一个快速找出是否发生了什么或者正在发生的方法。如果系统通常具有较高的负载平均值（超过 1.00），那么深入挖掘可能的原因（对其功率需求过高，可用资源不多等）是一个好主意。

现在我们已经介绍了基础知识，让我们继续看一些额外的检查，我们可以对系统资源的使用进行。

## 其他监控工具

例如，对于`ifconfig`，可以匹配接收到的传输包、接收到的包、错误等的值。

当目标是执行更完整的监控时，我们应该确保`/var/log/sa/`。

每天记录和存储的历史数据（`##`）可以在`/var/log/sa/sa##`和`/var/log/sa/sar##`中查询，以便我们可以与其他天进行比较。通过以更高的频率运行数据收集器（由*systemd*定时器执行），我们可以在调查问题时增加特定时期的细粒度。

然而，*sar*文件的外观显示了大量的数据：

![图 4.9 - 示例系统上/var/log/sar02 的内容](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_04_009.jpg)

图 4.9 - 示例系统上/var/log/sar02 的内容

在这里，我们可以看到 8-0 设备每秒有 170.27 次事务和 14.51%的利用率。在这种情况下，设备的名称使用主/次的值，我们可以在`/dev/`文件夹中检查。我们可以通过运行`ls -l /dev/*|grep 8`来查看，如下面的截图所示：

![图 4.10 - 用于定位与主 8 和次 0 对应的设备的/dev/目录列表](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_04_010.jpg)

图 4.10 - 用于定位与主 8 和次 0 对应的设备的/dev/目录列表

在这里，我们可以看到这对应于`/dev/sda`上的完整硬盘统计信息。

提示

通过**sar**处理数据是了解系统运行情况的好方法，但由于*sysstat*软件包在 Linux 中已经存在很长时间，因此有一些工具，如[`github.com/mbaldessari/sarstats`](https://github.com/mbaldessari/sarstats)，可以帮助我们处理记录的数据并以 PDF 文件的形式呈现图形化。

在下图中，我们可以看到不同驱动器的系统服务时间，以及系统崩溃时的标签。这有助于我们识别该点的系统活动：

![图 4.11 - 他们示例 PDF 中的磁盘服务时间的 Sarstats 图形，网址为 https://acksyn.org/software/sarstats/sar01.pdf](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_04_011.jpg)

图 4.11 - 他们示例 PDF 中的磁盘服务时间的 Sarstats 图形，网址为[`acksyn.org/software/sarstats/sar01.pdf`](https://acksyn.org/software/sarstats/sar01.pdf )

现代监控系统资源的工具已经发展，**Performance Co-Pilot**（**pcp**和可选的**pcp-gui**软件包）可以设置更强大的选项。只需记住，pcp 要求我们还在系统上启动数据收集器。

RHEL8 还包括**cockpit**，在进行服务器安装时默认安装。该软件包提供了一组工具，可以通过扩展其功能的插件将其作为其他产品的一部分。

cockpit 提供的 Web 服务可以在主机 IP 的 9090 端口上访问，因此您应该访问`https://localhost:9090`以获取登录屏幕，以便我们可以使用系统凭据登录。

重要提示

如果未安装或不可用 cockpit，请确保执行`dnf install cockpit`来安装该软件包，并使用`systemctl enable --now cockpit.socket`启动服务。如果您远程访问服务器，而不是使用`localhost`，请在允许防火墙连接之后使用服务器主机名或 IP 地址进行连接`firewall-cmd --add-service=cockpit`，如果之前未这样做。

登录后，我们将看到一个显示相关系统信息和链接到其他部分的仪表板，如下面的截图所示：

![图 4.12 - 登录系统仪表板后的 Cockpit 屏幕](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_04_12.jpg)

图 4.12 - 登录系统仪表板后的 Cockpit 屏幕

正如您所看到的，*cockpit*包括几个选项卡，可用于查看系统状态，甚至执行一些管理任务，如**SELinux**、软件更新、订阅等。

例如，我们可以查看性能图表，如下面的截图所示：

![图 4.13 - 用于使用图表的 Cockpit 仪表板的图形](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_04_13.jpg)

图 4.13 - 仪表板中的 Cockpit 图表

Cockpit 允许我们从图形界面检查服务状态、软件包升级状态以及其他配置设置，还可以远程连接到其他系统。这些可以从左侧的侧边菜单中选择。

有更适合大规模部署监控和管理的工具，比如*Ansible*和*Satellite*，因此熟悉我们用于故障排除和简单脚本构建的工具非常重要。这使我们能够结合到目前为止学到的知识，快速生成需要我们注意的事项的提示。

通过这样，我们已经介绍了一些检查资源使用情况的基础知识。现在，让我们看看如何查找有关正在运行的服务和我们可以审查的错误的信息。

# 查找日志，使用 journald 和阅读日志文件，包括日志保存和轮换

在本节中，您将学习如何通过日志审查系统的状态。

在本章的前面部分，我们学习了如何通过*systemd*管理系统服务，检查它们的状态和检查它们的日志。传统上，不同的守护程序和系统组件用于在`/var/log/`文件夹下创建文件，这些文件基于守护程序或服务的名称。如果服务用于创建多个日志，则会在服务的文件夹内创建这些日志（例如**httpd**或**samba**）。

系统日志守护程序`rsyslogd`有一个新的*systemd*伙伴，名为`systemd-journald.service`，它也存储日志，但它不是使用传统的纯文本格式，而是使用二进制格式，可以通过`journalctl`命令查询。

熟悉阅读日志文件非常重要，因为这是故障排除的基础，因此让我们学习一下一般日志记录以及如何使用它。

日志包含生成它的服务的状态信息。它们可能具有一些常见的格式，并且通常可以配置，但它们倾向于使用一些常见的元素，例如以下内容：

+   时间戳

+   生成条目的模块

+   消息

以下是一个例子：

```
Jan 03 22:36:47 el8-692807 sshd[50197]: Invalid user admin from 49.232.135.77 port 47694
```

在这种情况下，我们可以看到有人尝试以`admin`用户从 IP 地址`49.232.135.77`登录到我们的系统。

我们可以将该事件与其他日志相关联，例如通过`journalctl -u systemd-logind`查看登录子系统的日志。在这个例子中，我们找不到`admin`用户的任何登录（这是预期的，因为在这个系统中未定义`admin`用户）。

此外，我们还可以看到主机名`el8-692807`，生成它的服务`sshd`，`50197`和该服务记录的消息。

除了*journalctl*，我们还可以查看其他日志，以便在希望检查系统健康状况时使用。让我们以`/var/log/messages`为例：

![图 4.14 - /var/log/messages 摘录](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_04_014.jpg)

图 4.14 - /var/log/messages 摘录

在这个例子中，我们可以看到系统在遵循类似初始行的输出时运行了一些命令。例如，在前面的例子中，我们可以看到`sysstat`每 10 分钟执行一次，以及`dnf`缓存已更新。

让我们看一下标准系统安装中可用的重要日志列表（请注意，文件名是相对于`/var/log`文件夹的）：

+   `boot.log`：存储系统在启动过程中发出的消息。它可能包含用于提供带颜色的输出的转义代码。

+   `audit/audit.log`：包含由内核审计子系统生成的存储消息。

+   `secure`：包含安全相关的消息，比如`sshd`登录尝试失败。

+   `dnf.log`：由 DNF 软件包管理器生成的日志，例如缓存刷新。

+   `firewalld`：由*firewalld*守护程序生成的输出。

+   `lastlog`：这是一个包含有关最近登录系统的用户信息的二进制文件（可通过`last`命令查询）。

+   `messages`：默认的日志记录设施。这意味着任何不是特定日志的内容都会在这里。通常，这是开始检查系统发生了什么的最佳位置。

+   `maillog`：邮件子系统的日志。启用后，它会尝试传递消息。接收到的任何消息都将存储在这里。通常，配置服务器的出站邮件，以便可以传递系统警报或脚本输出。

+   `btmp`：系统访问失败的二进制日志。

+   `wtmp`：系统访问的二进制日志。

+   `sa/sar*`：*sysstat*实用程序的文本日志（二进制文件，命名为*sa*，加上日期编号，通过夜间的*cron*作业转换）。

根据已安装的服务、使用的安装方法等，可能存在其他日志文件。熟悉可用的日志非常重要，当然，要审查它们的内容，以了解消息的格式、每天创建多少个日志以及它们产生了什么样的信息。

利用已记录的信息，我们将获得有关如何配置每个单独的守护进程的提示。这使我们能够调整日志级别，从仅显示错误到更详细地调试问题。这意味着我们可以配置所需的日志旋转，以避免因为日志占用了所有空间而导致系统稳定性受到风险。

## 日志旋转

在正常的系统操作期间，有许多守护进程在使用，并且系统本身会生成用于故障排除和系统检查的日志。

一些服务可能允许我们根据日期定义要写入的日志文件，但通常的标准是将日志记录到`/var/log`目录中类似守护进程名称的文件中；例如，`/var/log/cron`。写入同一文件将导致文件不断增长，直到存储日志的驱动器被填满，这在一段时间后（有时在公司定义的政策下）可能不再有意义。

简化日志旋转过程的`cron`条目。它是通过`/etc/logrotate.conf`配置的，并且每天执行一次，如下所示：

![图 4.15 - 日志和旋转日志的示例清单（使用日期扩展）](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_04_015.jpg)

图 4.15 - 日志和旋转日志的示例清单（使用日期扩展）

如果我们检查配置文件的内容，我们会发现它包括一些文件定义，可以直接在那里或通过`/etc/logrotate.d/`文件夹中的附加文件中定义，这样每个程序都可以在安装、删除或更新软件包时满足自己的要求，而不会影响其他程序。

为什么这很重要？因为，如果您还记得本章早些时候的一些建议（关于磁盘空间），如果`logrotate`只是删除文件并创建新文件，实际的磁盘空间将不会被释放，并且写入日志的守护进程将继续写入它正在写入的文件（通过文件句柄）。为了克服这一点，每个定义文件可以定义一个后旋转命令。这会向日志旋转过程发出信号，以便它可以关闭，然后重新打开用于记录的文件。一些程序可能需要像`kill -SIGHUP PID`这样的信号，或者在执行时需要特殊参数，比如`chronyc cyclelogs`。

有了这些定义，`logrotate`将能够为每个服务应用配置，并同时保持服务在一个健全的状态下运行。

配置还可以包括特殊指令，例如以下内容：

+   `missingok`

+   `nocreate`

+   `nopytruncate`

+   `notifempty`

您可以在`logrotate.conf`中找到更多关于它们（以及其他内容）的信息（是的，一些软件包还包括配置文件的 man 页面，因此尝试检查`man logrotate.conf`以获取完整的详细信息！）。

主文件中剩下的一般配置允许我们定义一些常见的指令，比如要保留多少天的日志，是否要在旋转日志文件的文件扩展名中使用日期，是否要在旋转日志上使用压缩，我们希望多频繁地执行旋转等等。

让我们看一些例子。

以下示例将在“每日”基础上旋转，保留`30`个旋转日志，对它们进行“压缩”，并在其尾部文件名中使用“日期”作为扩展名。

```
rotate 30
daily
compress
dateext
```

在这个例子中，它将在“每周”基础上保留`4`个旋转日志（因此是 4 周），并对日志进行“压缩”，但对每个旋转日志使用序列号（这意味着每次旋转发生时，以前旋转的日志的序列号也会增加）：

```
rotate 4
weekly
compress
```

这种方法的一个优点（不使用`dateext`）是日志命名约定是可预测的，因为我们有`daemon.log`作为当前日志，`daemon.1.log`作为以前的日志，依此类推。这使得编写日志解析和处理脚本变得更容易。

# 总结

在本章中，我们了解了`systemd`以及它如何以优化的方式负责引导所需的系统服务。我们还学习了如何检查服务的状态，如何启用、禁用、启动和停止它们，以及如何使系统引导到我们引导系统的不同目标中。

时间同步被介绍为一个必不可少的功能，它确保我们的服务正常运行。它还允许我们确定系统时钟的状态，以及如何作为网络的时钟服务器。

我们还使用系统工具来监视资源使用情况，学习如何检查系统创建的日志以了解不同工具的功能状态，以及如何确保日志被正确维护，以便在不再相关时丢弃旧条目。

在下一章中，我们将深入探讨使用不同用户、组和权限来保护系统。


# 第五章：使用用户、用户组和权限保护系统

安全性是管理系统的关键部分，了解安全概念以便为任何系统管理员提供正确的资源访问权限是必要的。

在本章中，我们将回顾`sudo`中的安全基础知识，作为为系统中不同用户分配管理员权限的一种方式（甚至禁用 root 帐户）。我们还将深入研究文件权限以及如何改变它们，使用扩展功能来使命令以不同的用户或组运行，或者简化目录中的组协作。

我们将涵盖以下主题：

+   创建、修改和删除本地用户账户和用户组

+   管理用户组和审查分配

+   调整密码策略

+   为管理任务配置 sudo 访问权限

+   检查、审查和修改文件权限

+   使用特殊权限

让我们开始学习权限和安全性，包括用户账户和用户组。

# 创建、修改和删除本地用户账户和用户组

当准备系统供用户访问时，系统管理员必须做的第一项任务之一是为访问系统的人创建新的用户帐户。在本节中，我们将回顾如何创建和删除本地帐户，以及如何将它们分配给用户组。

第一步是在系统中创建一个新用户帐户。这是通过使用`useradd`命令完成的。让我们通过运行以下命令将`user01`添加到系统中：

```
[root@rhel8 ~]# useradd user01
[root@rhel8 ~]# grep user01 /etc/passwd
user01:x:1001:1001::/home/user01:/bin/bash
[root@rhel8 ~]# id user01
uid=1001(user01) gid=1001(user01) groups=1001(user01)
```

有了这个，用户就创建好了。

重要提示

为了能够添加用户，我们需要管理员权限。在当前配置中，我们通过以`root`身份运行命令来实现这一点。

帐户是使用系统中配置的默认选项创建的，例如以下选项：

+   `su` as `root`. We will see how to add a password to the user next.

+   `user01`，UID 为`1001`。

+   `1001`。

+   **描述**：在创建用户时未添加描述。此字段为空白。

+   `home`目录创建在`/home/$USER`中，在本例中为`/home/user01`。这将是用户的默认和主目录，也是存储他们个人偏好和文件的地方。初始内容从`/etc/skel`复制而来。

+   `bash`。

提示

创建新用户时应用的默认选项在`/etc/default/useradd`文件中定义。

用户创建后，我们可以通过以`root`身份运行`passwd`命令，后跟要更改的用户名，来添加（或更改）密码：

```
[root@rhel8 ~]# passwd user01
Changing password for user user01.
New password: redhat
BAD PASSWORD: The password is shorter than 8 characters
Retype new password: redhat
passwd: all authentication tokens updated successfully
```

现在用户有了新分配的密码。请注意两件事：

+   用户`root`可以更改任何用户的密码，而无需知道先前的密码（完全重置密码）。当用户度假回来后不记得密码时，这是很有用的。

+   在示例中，我们显示了分配的密码`redhat`，但屏幕上没有显示。密码太简单，不符合默认的复杂性标准，但是作为`root`，我们仍然可以分配它。

让我们使用之前学过的`id`命令来检查新用户：

```
[root@rhel8 ~]# id user01
uid=1001(user01) gid=1001(user01) groups=1001(user01)
```

在本节中采取的步骤之后，我们现在在系统中有了用户，并且可以使用。我们可以用`useradd`自定义用户创建的主要选项如下：

+   `-u`或`--uid`：为用户分配特定的 UID。

+   `-g`或`--gid`：为用户分配一个主组。可以通过编号（GID）或名称指定。该组需要先创建。

+   `-G`或`--groups`：通过提供逗号分隔的列表使用户成为其他组的一部分。

+   `-c`或`--comment`：为用户提供描述，如果要使用空格，则在引号之间指定。

+   `-d`或`--home-dir`：为用户定义主目录。

+   `-s`或`--shell`：为用户分配自定义 shell。

+   `-p`或`--password`：提供密码给用户的一种方法。密码应该已经加密才能使用这种方法。建议*不*使用此选项，因为有捕获加密密码的方法。请改用`passwd`。

+   `-r`或`--system`：创建系统账户而不是用户账户。

如果我们需要更改用户的任何属性，例如描述，我们可以使用`usermod`工具。让我们将描述修改为`user01`：

```
[root@rhel8 ~]# usermod -c "User 01" user01
[root@rhel8 ~]# grep user01 /etc/passwd
user01:x:1001:1001:User 01:/home/user01:/bin/bash
```

`usermod`命令使用与`useradd`相同的选项。现在定制您当前的用户将会很容易。

让我们以创建`user02`为例，演示如何使用选项：

```
[root@rhel8 ~]# useradd --uid 1002 --groups wheel \
--comment "User 02" --home-dir /home/user02 \
--shell /bin/bash user02
[root@rhel8 ~]# grep user02 /etc/passwd
user02:x:1002:1002:User 02:/home/user02:/bin/bash
[root@rhel8 ~]# id user02
uid=1002(user02) gid=1002(user02) groups=1002(user02),10(wheel)
```

提示

当命令行太长时，可以添加字符`\`，然后按*Enter*并在新行上继续命令。

现在我们知道如何创建用户，但我们可能也需要创建一个组并将我们的用户添加到其中。让我们使用`groupadd`命令创建`finance`组：

```
[root@rhel8 ~]# groupadd finance
[root@rhel8 ~]# grep finance /etc/group
finance:x:1003:
```

我们可以将`user01`和`user02`用户添加到`finance`组：

```
[root@rhel8 ~]# usermod -aG finance user01
[root@rhel8 ~]# usermod -aG finance user02
[root@rhel8 ~]# grep finance /etc/group
finance:x:1003:user01,user02
```

重要提示

我们使用`-aG`选项将用户添加到组中，而不是修改用户所属的组。

一旦我们知道如何创建用户和组，让我们看看如何使用`userdel`命令删除它们：

```
[root@rhel8 ~]# userdel user01
[root@rhel8 ~]# grep user01 /etc/passwd
[root@rhel8 ~]# id user01
id: 'user01': no such user
[root@rhel8 ~]# grep user02 /etc/passwd
user02:x:1002:1002:User 02:/home/user02:/bin/bash
[root@rhel8 ~]# id user02
uid=1002(user02) gid=1002(user02) groups=1002(user02),10(wheel),1003(finance)
[root@rhel8 ~]# ls /home/
user  user01  user02
[root@rhel8 ~]# rm -rf /home/user01/
```

如您所见，我们需要手动删除`home`目录。这种删除用户的方式很好，如果我们想保留其数据以备将来使用。

要完全删除用户，我们应用选项`-r`。让我们尝试使用`user02`：

```
[root@rhel8 ~]# userdel -r user02
[root@rhel8 ~]# ls /home/
user  user01
[root@rhel8 ~]# grep user02 /etc/passwd
[root@rhel8 ~]# id user02
id: 'user02': no such user
```

现在让我们使用`groupdel`命令删除`finance`组：

```
[root@rhel8 ~]# groupdel finance
[root@rhel8 ~]# grep finance /etc/group
```

正如我们所见，简单易行地在 RHEL 中创建用户和组并进行简单分配。在下一节中，让我们更深入地了解如何管理组和对其进行分配。

# 管理组和审查分配

我们已经看到如何使用`groupadd`创建组，并使用`groupdel`删除组。让我们看看如何使用`groupmod`修改已创建的组。

让我们创建一个要操作的组。我们将通过运行以下命令创建拼写错误的`acounting`组：

```
[root@rhel8 ~]# groupadd -g 1099 acounting
[root@rhel8 ~]# tail -n1 /etc/group
acounting:x:1099: 
```

您看到我们在名称上犯了一个错误，没有拼写成`accounting`。我们甚至可能已经向其中添加了一些用户账户，我们需要修改它。我们可以使用`groupmod`并运行以下命令来这样做：

```
[root@rhel8 ~]# groupmod -n accounting acounting
[root@rhel8 ~]# tail -n1 /etc/group
accounting:x:1099:
```

现在我们已经看到了如何修改组名。我们可以使用`-g`选项修改不仅名称，还有 GID：

```
[root@rhel8 ~]# groupmod -g 1111 accounting
[root@rhel8 ~]# tail -n1 /etc/group
accounting:x:1111:
```

我们可以通过运行`groups`命令来查看分配给用户的组：

```
[root@rhel8 ~]# groups user
user : user wheel
```

有了这个，我们已经准备好在 Linux 系统中管理组和用户。让我们继续讨论密码策略。

# 调整密码策略

如*第三章*中提到的，*基本命令和简单的 Shell 脚本*，用户存储在`/etc/passwd`文件中，而加密密码存储在`/etc/shadow`文件中。

提示

哈希算法是这样做的，它从提供的数据（即文件或单词）生成一串精确的字符，或哈希。它以一种方式进行，以便它总是从相同的原始数据生成相同的哈希，但是几乎不可能从哈希中重新创建原始数据。这就是为什么它们用于存储密码或验证下载文件的完整性。

让我们通过以`root`身份运行`grep`用户对`/etc/shadow`进行查找来看一个例子：

```
user:$6$tOT/cvZ4PWRcl8XX$0v3.ADE/ibzlUGbDLer0ZYaMPNRJ5gK17LeKnoMfKK9 .nFz8grN3IafmHvoHPuh3XrU81nJu0.is5znztB64Y/:18650:0:99999:7:3:19113:
```

与密码文件一样，`/etc/shadow`中存储的数据每行有一个条目，字段由冒号(`:`)分隔。

+   `user`：账户名称。它应该与`/etc/passwd`中的名称相同。

+   `$6$tOT/cvZ4PWRcl8XX$0v3.ADE/ibzlUGbDLer0ZYaMPNRJ5gK17LeKnoMfKK 9.nFz8grN3IafmHvoHPuh3XrU81nJu0.is5znztB64Y/`：密码哈希。它包含三个由`$`分隔的部分：

- `$6`：用于加密文件的算法。在这种情况下，值`6`表示 SHA-512。数字`1`是用于旧的、现在不安全的 MD5 算法。

- `$tOT/cvZ4PWRcl8XX`：密码`$0v3.ADE/ibzlUGbDLer0ZYaMPNRJ5gK17LeKnoMfKK9.nFz8grN3IafmHvoHPuh3XrU81nJu0.is5znztB64Y/`：加密密码哈希。使用盐和 SHA-512 算法，创建此令牌。当用户验证时，该过程再次运行，如果生成相同的哈希，则验证密码并授予访问权限。

+   `18650`：密码上次更改的时间和日期。格式是自 1970-01-01 00:00 UTC 以来的天数（这个日期也被称为**纪元**）。

+   `0`：用户可以再次更改密码之前的最少天数。

+   `99999`：用户必须再次更改密码之前的最大天数。如果为空，密码不会过期。

+   `7`：用户将被警告密码即将过期的天数。

+   `3`：用户即使密码过期仍然可以登录的天数。

+   `19113`：密码应该过期的日期。如果为空，它不会在特定日期过期。

+   `<empty>`：最后一个冒号留下来方便我们轻松添加新字段。

提示

要将`date`字段转换为可读日期，可以运行以下命令：`date -d '1970-01-01 UTC + 18650 days'`。

我们如何更改密码的过期日期？用于此操作的工具是`chage`，用于`/etc/shadow`：

+   `-d`或`--lastday`：密码上次更改的时间和日期。格式为`YYYY-MM-DD`。

+   `-m`或`--mindays`：用户可以再次更改密码之前的最少天数。

+   `-W`或`--warndays`：用户将被警告密码即将过期的天数。

+   `-I`或`--inactive`：密码过期后，账户被锁定之前必须经过的天数。

+   `-E`或`--expiredate`：用户账户将被锁定的日期。日期应以`YYYY-MM-DD`格式表示。

让我们试一下。首先，我们创建`usertest`账户：

```
[root@rhel8 ~]# adduser usertest
[root@rhel8 ~]# grep usertest /etc/shadow
usertest:!!:18651:0:99999:7:::
```

重要提示

在 RHEL 8 中，`adduser`和`useradd`工具是相同的工具。随时以您感觉最舒适的方式输入。

您会注意到在前面的示例中，从两个感叹号`!!`中，粗体显示密码未设置，并且我们正在使用默认值。让我们更改密码并检查差异。使用您喜欢的任何密码：

```
[root@rhel8 ~]# passwd usertest
Changing password for user usertest.
New password: 
Retype new password: 
passwd: all authentication tokens updated successfully.
[root@rhel8 ~]# grep usertest /etc/shadow
usertest:$6$4PEVPj7M4GD8CH.4$VqiYY.IXetwZA/g54bFP1ZJwQ/yc6bnaFauHGA1 1eFzsGh/uFbJwxZCQTFHIASuamBz.27gb4ZpywwOA840eI.:18651:0:99999:7:::
```

密码哈希已创建，并且上次更改的日期与当前日期相同。让我们建立一些选项：

```
[root@rhel8 ~]# chage --mindays 0 --warndays 7 --inactive 3 --expiredate 2030-01-01 usertest
[root@rhel8 ~]# grep usertest /etc/shadow
usertest:$6$4PEVPj7M4GD8CH.4$VqiYY.IXetwZA/g54bFP1ZJwQ/yc6bnaFauHGA1 1eFzsGh/uFbJwxZCQTFHIASuamBz.27gb4ZpywwOA 840eI.:18651:0:99999:7:3:21915:
[root@rhel8 ~]# date -d '1970-01-01 UTC + 21915 days'
mar ene  1 01:00:00 CET 2030
```

请注意`/etc/shadow`文件中与`chage`指定的值对应的更改。我们可以使用`chage`的`-l`选项检查更改：

```
[root@rhel8 ~]# chage -l usertest
Last password change                  : ene 24, 2021
Password expires                      : never
Password inactive                     : never
Account expires                       : ene 01, 2030
Minimum number of days between password change   : 0
Maximum number of days between password change   : 99999
Number of days of warning before password expires: 7
```

要更改默认值，我们应该编辑`/etc/login.defs`。让我们检查最常见更改的部分：

```
# Password aging controls:
#
#    PASS_MAX_DAYS    Maximum number of days a password may be used.
#    PASS_MIN_DAYS    Minimum number of days allowed between password changes.
#    PASS_MIN_LEN    Minimum acceptable password length.
#    PASS_WARN_AGE    Number of days warning given before a password expires.
#
PASS_MAX_DAYS    99999
PASS_MIN_DAYS    0
PASS_MIN_LEN     5
PASS_WARN_AGE    7
```

请花几分钟时间查看`/etc/login.defs`中的选项。

现在，我们可能会遇到一个用户已经离开公司的情况。我们如何锁定账户，使用户无法访问系统？`usermod`命令有`-L`选项，用于**锁定**账户。让我们试一下。首先，让我们登录系统：

![图 5.1 - 用户账户 usertest 登录系统](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_05_001.jpg)

图 5.1 - 用户账户 usertest 登录系统

现在让我们锁定账户：

```
[root@rhel8 ~]# usermod -L usertest
[root@rhel8 ~]# grep usertest /etc/shadow
usertest:!$6$4PEVPj7M4GD8CH.4$VqiYY.IXetwZA/g54bFP1ZJwQ/yc6bnaFauHGA 11eFzsGh/uFbJwxZCQTFHIASuamBz.27gb4ZpywwOA840eI.:18651:0:99999:7:3:21915:
```

请注意，在密码哈希之前添加了`!`字符。这是用于锁定的机制。让我们再次尝试登录：

![图 5.2 - 用户账户 usertest 无法登录系统](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_05_002.jpg)

图 5.2 - 用户账户 usertest 无法登录系统

可以使用`-U`选项解锁账户：

```
[root@rhel8 ~]# usermod -U usertest
[root@rhel8 ~]# grep usertest /etc/shadow
usertest:$6$4PEVPj7M4GD8CH.4$VqiYY.IXetwZA/g54bFP1ZJwQ/yc6bnaFauHGA1 1eFzsGh/uFbJwxZCQTFHIASuamBz.27gb4ZpywwOA840eI.:18651:0:99999:7:3:21915:
```

现在您可以看到`!`字符已被移除。随时尝试再次登录。

重要提示

要完全阻止访问账户，而不仅仅是使用密码登录（还有其他机制），我们应该将到期日期设置为`1`。

另一个常见的用例是当您希望用户访问系统时，比如拥有一个网络共享目录（即通过 NFS 或 CIFS，如*第十二章*中所解释的，*管理本地存储和文件系统*），但您不希望他们能够在系统中运行命令。为此，我们可以使用一个非常特殊的 shell，即`nologin` shell。让我们使用`usermod`将该 shell 分配给`usertest`用户账户：

```
[root@rhel8 ~]# usermod -s /sbin/nologin usertest
[root@rhel8 ~]# grep usertest /etc/passwd
usertest:x:1001:1001::/home/usertest:/sbin/nologin
[root@rhel8 ~]# su - usertest
Last login: sun jan 24 16:18:07 CET 2021 on pts/0
This account is currently not available.
[root@rhel8 ~]# usermod -s /bin/bash usertest
[root@rhel8 ~]# su - usertest
Last login: sun jan 24 16:18:15 CET 2021 on pts/0
[usertest@rhel8 ~]$
```

请注意，这次我们正在审查`/etc/passwd`中的更改，因为这是修改所应用的地方。

如您所见，很容易为任何用户设置密码过期的值，锁定它们，或限制对系统的访问。让我们继续进行更多的管理任务以及如何委派管理员访问权限。

# 为管理任务配置 sudo 访问权限

在 RHEL 中，有一种方法可以将管理访问权限委派给用户，这是通过一个名为**sudo**的工具来实现的，它代表**Super User Do**。

它不仅允许您授予用户或组完整的管理员特权，还可以对某些用户可以执行的特权命令进行非常精细的控制。

让我们首先了解默认配置以及如何更改它。

## 理解 sudo 配置

该工具的主要配置文件位于`/etc/sudoers`中，并包括默认配置的这一部分：

```
root ALL=(ALL)  ALL
%wheel    ALL=(ALL)  ALL 
## Read drop-in files from /etc/sudoers.d (the # here does not mean a comment)
#includedir /etc/sudoers.d
```

让我们逐行分析这些行，以了解它们的作用。

第一行使`root`用户可以使用`sudo`运行任何命令：

```
root ALL=(ALL)  ALL
```

第二行使`wheel`组中的用户可以使用`sudo`运行任何命令。我们稍后将解释语法的细节：

```
%wheel    ALL=(ALL)  ALL
```

重要提示

除非有重要原因，否则请不要禁用`wheel`组指令。其他程序期望它可用，并且禁用它可能会导致一些问题。

第三行和所有以`#`开头的行都被视为注释，它们仅用于添加描述性内容，对最终配置没有影响：

```
 ## Read drop-in files from /etc/sudoers.d (the # here does not mean a comment)
```

第四行是对前一规则的唯一例外。此行使目录`/etc/sudoers.d`成为配置文件的来源。我们可以在该文件夹中放置一个文件，`sudo`将使用它：

```
#includedir /etc/sudoers.d
```

最后一条规则的例外是以`~`结尾或包含`.`（点）字符的文件。

正如您所见，默认配置使`root`和`wheel`组的成员能够使用`sudo`作为管理员运行任何命令。

最简单的方法是将用户添加到`wheel`组，以授予该用户完整的管理员特权。修改`usertest`账户使其成为管理员账户的示例如下：

```
[root@rhel8 ~]# usermod -aG wheel usertest
[root@rhel8 ~]# groups usertest
usertest : usertest wheel
```

重要提示

对于云实例，账户 root 没有分配有效密码。为了能够管理所述的云实例，在某些云中，如`wheel`组。在 AWS 的情况下，默认用户账户是`ec2-user`。在其他云中，还创建了一个自定义用户，并将其添加到`wheel`组中。

与其他敏感文件一样，为了编辑`/etc/sudoers`文件，有一个工具不仅可以确保两个管理员不同时编辑它，还可以确保语法正确。在这种情况下，编辑它的工具是`visudo`。

## 使用 sudo 运行管理员命令

在这些示例中，我们将使用`user`账户。您可能还记得，在*第一章*中，*安装 RHEL8*，我们启用了请求账户成为管理员的复选框。在幕后，该账户被添加到`wheel`组中，因此我们可以开始使用`sudo`来运行管理员命令。

让我们使用`user`账户登录并尝试运行一个管理命令，比如`adduser`：

```
[root@rhel8 ~]# su - user
Last login: dom ene 24 19:40:31 CET 2021 on pts/0
[user@rhel8 ~]$ adduser john
adduser: Permission denied.
adduser: cannot lock /etc/passwd; try again later.
```

正如您所见，我们收到了`Permission denied`的错误消息。要能够使用`sudo`运行它，我们只需要将其添加到命令行的开头：

```
[user@rhel8 ~]$ sudo adduser john
We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.
[sudo] password for user:
[user@rhel8 ~]$ id john
uid=1002(john) gid=1002(john) groups=1002(john)
```

在这种情况下，我们看到第一次成功运行`sudo`时显示了一个警告消息。然后我们被要求输入*我们自己的密码* - 不是管理员密码，因为可能根本就没有管理员密码，而是我们为运行`sudo`的用户设置的密码。一旦密码正确输入，命令就会运行并在系统日志中注册：

```
jan 24 19:44:26 rhel8.example.com sudo[2879]: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/sbin/adduser john
```

重要提示

一旦成功运行了`sudo`，它将记住验证 15 分钟（作为默认行为）。这样做是为了在一个会话中运行多个管理命令时，你不必一遍又一遍地输入密码。要将其增加到 30 分钟，我们可以使用`visudo`添加以下行：`Defaults:USER timestamp_timeout=30`。

有时候你想要一个交互式会话，这样就不需要一遍又一遍地输入`sudo`。为此，`-i`选项非常有用。让我们试一下：

```
[user@rhel8 ~]$ sudo -i
[sudo] password for user: 
[root@rhel8 ~]#
```

现在让我们开始定制`sudoers`文件中`sudo`的配置。

## 配置 sudoers

在前一节中，我们已经看到了默认的`/etc/sudoers`文件的详细信息。让我们看几个例子，如何进行更细粒度的配置。

让我们首先让`sudo`在`sudoers`文件中运行管理员命令时不需要为`wheel`组中的用户请求密码。我们可以运行`visudo`，并使以`%wheel`开头的行如下所示：

```
%wheel        ALL=(ALL)       NOPASSWD: ALL
```

保存它。注意配置文件中有一行被注释掉的配置。现在让我们试一下：

```
[user@rhel8 ~]$ sudo adduser ellen
[user@rhel8 ~]$ id ellen
uid=1003(ellen) gid=1003(ellen) groups=1003(ellen)
```

现在我们可以使用你喜欢的编辑器创建一个文件，使新用户账户`ellen`能够运行管理员命令。让我们创建`/etc/sudoers.d/ellen`文件，并添加以下内容：

```
ellen ALL=(ALL)  ALL
```

通过这个，我们正在使用`/etc/sudoers.d`目录来扩展`sudo`配置。

尽管它不是 RHCSA 考试的一部分，我们将在这里回顾`sudoers`的详细配置。正如你所看到的，有三个字段，用空格或制表符分隔，来定义配置文件中的策略。让我们来回顾一下：

+   第一个字段是指定受策略影响的对象：

- 我们可以通过简单地在第一个字段中放入用户名来添加用户。

- 我们可以通过在第一个字段中使用`％`字符来添加组。

+   第二个字段是策略适用的位置：

- 到目前为止，我们使用了`ALL=(ALL)`来指定一切。

- 在这个字段的第一部分，我们可以定义要运行的计算机组，比如`SERVERS=10.0.0.0/255.255.255.0`。

- 在第二部分，我们可以指定命令，比如`NETWORK=/usr/sbin/ip`。

- 括号中是可以用来运行命令的用户账户。

+   第三个字段是指定哪些命令将使用密码，哪些不会。

语法如下：

```
user  hosts = (run-as) commands
```

让我们看一个例子：

```
Runas_AliasDB = oracle
Host_Alias SERVERS=10.0.0.0/255.255.255.0
Cmnd_Alias NETWORK=/ust/sbin/ip
pete  SERVERS=NETWORK 
julia SERVERS=(DB)ALL
```

我们已经看到了如何在 RHEL 中为用户提供管理访问权限，甚至如何以非常细粒度的方式进行。现在让我们继续看看如何处理文件权限的部分。

# 检查、回顾和修改文件权限

到目前为止，我们已经学会了如何创建用户和组，甚至为它们提供管理能力。现在是时候看看权限是如何在文件和目录级别工作的了。

正如你记得的，在*第三章*，*基本命令和简单 Shell 脚本*中，我们已经看到了如何查看应用于文件的权限。现在让我们回顾一下并深入了解。

让我们使用`-l`选项列出一些示例文件的权限信息。记得以`root`用户身份运行（或使用`sudo`）：

```
[root@rhel8 ~]# ls -l /usr/bin/bash
-rwxr-xr-x. 1 root root 1150704 jun 23  2020 /usr/bin/bash
[root@rhel8 ~]# ls -l /etc/passwd
-rw-r--r--. 1 root root 1324 ene 24 21:35 /etc/passwd
[root@rhel8 ~]# ls -l /etc/shadow
----------. 1 root root 1008 ene 24 21:35 /etc/shadow
[root@rhel8 ~]# ls -ld /tmp
drwxrwxrwt. 8 root root 172 ene 25 17:35 /tmp
```

记住，在 Linux 中，*一切都是文件*。

现在让我们使用`/usr/bin/bash`的权限来回顾一下权限包括的五个不同信息块：

```
-rwxr-xr-x.
```

这些块如下：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_05_Table_01.jpg)

让我们再次回顾一下，因为它们非常重要。

块 1 是文件可能具有的特殊权限。如果它是一个常规文件并且没有特殊权限（就像在这种情况下一样），它将显示为`-`：

+   目录将显示为`d`。

+   链接，通常是符号链接，将显示为`l`。

+   特殊权限以不同的用户或组运行文件，称为`s`。

+   一个特殊权限，以便所有者只能删除或重命名文件，称为`t`。

块 2 是文件所有者的*用户*的权限，由三个字符组成：

+   第一个，`r`，是分配的读权限。

+   第二个，`w`，是分配的写权限。

+   第三个，`x`，是可执行权限。（请注意，目录的可执行权限意味着能够进入它们。）

块 3 是*组*的权限。它由相同的三个字符组成，用于读、写和执行（`rwx`）。在这种情况下，缺少写权限。

块 4 是*其他*的权限。它也由相同的三个字符组成，用于读、写和执行（`rwx`），就像之前一样。和之前的块一样，缺少写权限。

块 5 表示文件应用了**SELinux**上下文。有关此主题的更多信息，请参见*第十章*，*使用 SELinux 使系统更加安全*。

要更改文件的权限，我们将使用`chmod`命令。

首先，让我们创建一个文件：

```
[root@rhel8 ~]# touch file.txt
[root@rhel8 ~]# ls -l file.txt 
-rw-r--r--. 1 root root 0 ene 27 18:30 file.txt
```

正如您所看到的，文件是以您的用户名作为所有者，您的主要组作为组，并且具有一组默认权限创建的。新创建的文件权限的默认值由`umask`定义，在 RHEL 中，新创建的文件权限的默认值如下：

+   **用户**：读和写

+   **组**：读

+   **其他人**：读

要使用`chmod`更改权限，我们使用三个字符指定更改：

+   第一个，确定更改影响的对象：

- `u`：用户

- `g`：组

- `o`：其他

+   第二个是添加或删除权限：

- `+`：添加

- `-`：删除

+   第三个，确定要更改的权限：

- `r`：读

- `w`：写

- `x`：执行

因此，要向组添加写权限，我们可以运行以下命令：

```
[root@rhel8 ~]# chmod g+w file.txt 
[root@rhel8 ~]# ls -l file.txt 
-rw-rw-r--. 1 root root 0 ene 27 18:30 file.txt
```

要删除其他人的读权限，我们运行以下命令：

```
[root@rhel8 ~]# chmod o-r file.txt 
[root@rhel8 ~]# ls -l file.txt 
-rw-rw----. 1 root root 0 ene 27 18:30 file.txt
```

权限以四个八进制数字存储。这意味着特殊权限以 0 到 7 的数字存储，与用户、组和其他权限的存储方式相同，每个权限都有 0 到 7 的数字。

一些示例如下所示：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_05_Table_02.jpg)

它是如何工作的？我们为每个权限分配一个数字（2 的幂）：

+   **无**：0

+   **执行**：2⁰ = 1

+   **写**：2¹ = 2

+   **读**：2² = 4

我们添加它们：

```
rwx = 4 + 2 + 1 = 7
rw- = 4 + 2 = 6 
r-x = 4 + 1 = 5
r-- = 4
--- = 0
```

这就是我们可以使用数字分配权限的方式。现在让我们试一试：

```
[root@rhel8 ~]# chmod 0755 file.txt 
[root@rhel8 ~]# ls -l file.txt 
-rwxr-xr-x. 1 root root 0 ene 27 18:30 file.txt
[root@rhel8 ~]# chmod 0640 file.txt 
[root@rhel8 ~]# ls -l file.txt 
-rw-r-----. 1 root root 0 ene 27 18:30 file.txt
[root@rhel8 ~]# chmod 0600 file.txt 
[root@rhel8 ~]# ls -l file.txt 
-rw-------. 1 root root 0 ene 27 18:30 file.txt
```

正如我们之前所说，权限的默认配置是由`umask`设置的。我们可以很容易地看到这个值：

```
[root@rhel8 ~]# umask 
0022
```

所有新创建的文件都删除了`执行`权限（`1`）。

使用这个`umask`，`0022`，这是 RHEL 中默认提供的，我们将删除`组`和`其他`的`写`权限（`2`）。

即使不建议更改`umask`，我们可以尝试一下来了解它是如何工作的。让我们从使用最宽松的`umask`，`0000`开始，看看如何将所有`读`和`写`权限分配给新创建的文件：

```
[root@rhel8 ~]# umask 0000
[root@rhel8 ~]# touch file2.txt
[root@rhel8 ~]# ls -l file2.txt 
-rw-rw-rw-. 1 root root 0 ene 27 18:33 file2.txt
```

现在让我们使用更严格的`umask`来限制`组`和`其他`的权限：

```
[root@rhel8 ~]# umask 0066
[root@rhel8 ~]# touch file3.txt
[root@rhel8 ~]# ls -l file3.txt 
-rw-------. 1 root root 0 ene 27 18:33 file3.txt
```

如果我们尝试更高的数字，它将无法工作并返回错误：

```
[root@rhel8 ~]# umask 0088
-bash: umask: 0088: octal number out of range
```

您可以看到`0066`和`0077`的效果是一样的：

```
[root@rhel8 ~]# umask 0077
[root@rhel8 ~]# touch file4.txt
[root@rhel8 ~]# ls -l file4.txt 
-rw-------. 1 root root 0 ene 27 18:35 file4.txt
```

让我们在我们的会话中重新建立`umask`，以默认值继续练习：

```
[root@rhel8 ~]# umask 0022
```

现在，我们可能需要为特定用户或组创建一个目录，或更改文件的所有者。为了能够更改文件或目录的所有权，使用`chown`或`chgrp`工具。让我们看看它是如何工作的。让我们移动到`/var/tmp`并为`finance`和`accounting`创建文件夹：

```
[root@rhel8 ~]# cd /var/tmp/
[root@rhel8 tmp]# mkdir finance
[root@rhel8 tmp]# mkdir accounting
[root@rhel8 tmp]# ls -l
total 0
drwxr-xr-x. 2 root root 6 ene 27 19:35 accounting
drwxr-xr-x. 2 root root 6 ene 27 19:35 finance
```

现在让我们创建`finance`和`accounting`的组：

```
[root@rhel8 tmp]# groupadd finance
[root@rhel8 tmp]# groupadd accounting
groupadd: group 'accounting' already exists
```

在这个例子中，`accounting`组已经创建。让我们使用`chgrp`为每个目录更改组：

```
[root@rhel8 tmp]# chgrp accounting accounting/
[root@rhel8 tmp]# chgrp finance finance/
[root@rhel8 tmp]# ls -l
total 0
drwxr-xr-x. 2 root accounting 6 ene 27 19:35 accounting
drwxr-xr-x. 2 root finance    6 ene 27 19:35 finance
```

现在我们为`sonia`和`matilde`创建用户，并将它们分别分配给`finance`和`accounting`：

```
[root@rhel8 tmp]# adduser sonia
[root@rhel8 tmp]# adduser matilde
[root@rhel8 tmp]# usermod -aG finance sonia
[root@rhel8 tmp]# usermod -aG accounting matilde
[root@rhel8 tmp]# groups sonia
sonia : sonia finance
[root@rhel8 tmp]# groups matilde
matilde : matilde accounting
```

现在我们可以为每个用户在其组文件夹下创建一个个人文件夹：

```
[root@rhel8 tmp]# cd finance/
[root@rhel8 finance]# mkdir personal_sonia
[root@rhel8 finance]# chown sonia personal_sonia
[root@rhel8 finance]# ls -l
total 0
drwxr-xr-x. 2 sonia root 6 ene 27 19:44 personal_sonia
[root@rhel8 finance]# chgrp sonia personal_sonia/
[root@rhel8 finance]# ls -l
total 0
drwxr-xr-x. 2 sonia sonia 6 ene 27 19:44 personal_sonia
```

有一种方法可以使用`:`分隔符指定用户和组给`chown`。让我们用`matilde`试试：

```
[root@rhel8 tmp]# cd ../accounting
[root@rhel8 accounting]# mkdir personal_matilde
[root@rhel8 accounting]# chown matilde:matilde \
personal_matilde
[root@rhel8 accounting]# ls -l
total 0
drwxr-xr-x. 2 matilde matilde 6 ene 27 19:46 personal_matilde
```

如果我们想要更改整个分支的权限，我们可以使用`chown`命令的`-R`选项进行递归。让我们复制一个分支并更改其权限：

```
[root@rhel8 accounting]# cp -rv /usr/share/doc/audit personal_matilde/
'/usr/share/doc/audit' -> 'personal_matilde/audit'
'/usr/share/doc/audit/ChangeLog' -> 'personal_matilde/audit/ChangeLog'
'/usr/share/doc/audit/README' -> 'personal_matilde/audit/README'
'/usr/share/doc/audit/auditd.cron' -> 'personal_matilde/audit/auditd.cron'
[root@rhel8 accounting]# chown -R matilde:matilde \
personal_matilde/audit
[root@rhel8 accounting]# ls -l personal_matilde/audit/
total 20
-rw-r--r--. 1 matilde matilde  271 ene 28 04:56 auditd.cron
-rw-r--r--. 1 matilde matilde 8006 ene 28 04:56 ChangeLog
-rw-r--r--. 1 matilde matilde 4953 ene 28 04:56 README
```

通过这些，我们对 RHEL 中的权限、它们的默认行为以及如何使用它们有了很好的理解。

让我们继续讨论一些关于权限的更高级的话题。

# 使用特殊权限

正如我们在前一节中看到的，有一些特殊权限可以应用到文件和目录。让我们从回顾 Set-UID（或**suid**）和 Set-GUID（或**sgid**）开始。

## 理解和应用 Set-UID

让我们回顾一下 Set-UID 如何应用到文件和目录：

+   **应用到文件的 Set-UID 权限**：当应用到可执行文件时，该文件将以文件所有者运行，应用权限。

+   **应用到目录的 Set-UID 权限**：没有效果。

让我们检查一个具有 Set-UID 的文件：

```
[root@rhel8 ~]# ls -l /usr/bin/passwd 
-rwsr-xr-x. 1 root root 33544 dic 13  2019 /usr/bin/passwd
```

`passwd`命令需要`root`权限才能更改`/etc/shadow`文件中的哈希值。

要应用这些权限，我们可以使用`chmod`命令，应用`u+s`权限：

```
[root@rhel8 ~]# touch testsuid
[root@rhel8 ~]# ls -l testsuid 
-rw-r--r--. 1 root root 0 ene 28 05:16 testsuid
[root@rhel8 ~]# chmod u+s testsuid 
[root@rhel8 ~]# ls -l testsuid 
-rwsr--r--. 1 root root 0 ene 28 05:16 testsuid
```

提示

在将`root`分配给文件时，给文件分配`suid`时要非常小心。如果您将文件的写权限留下，任何用户都可以更改内容并以`root`身份执行任何操作。

## 理解和应用 Set-GID

让我们回顾一下 Set-GID 如何应用到文件和目录：

+   **应用到文件的 Set-GID 权限**：当应用到可执行文件时，该文件将以文件的组权限运行。

+   **应用到目录的 Set-GID 权限**：在该目录中创建的新文件将具有该目录的组应用到它们。

让我们检查一个具有 Set-GID 的文件：

```
[root@rhel8 ~]# ls -l /usr/bin/write
-rwxr-sr-x. 1 root tty 21232 jun 26  2020 /usr/bin/write
```

我们可以尝试使用`chmod`命令将权限应用到文件，使用`g+s`：

```
[root@rhel8 ~]# touch testgid
[root@rhel8 ~]# chmod g+s testgid 
[root@rhel8 ~]# ls -l testgid 
-rw-r-sr--. 1 root root 0 ene 28 05:23 testgid
```

现在让我们尝试一下目录。让我们回到我们之前的例子：

```
[root@rhel8 ~]# cd /var/tmp/
[root@rhel8 tmp]# ls
accounting  finance
[root@rhel8 tmp]# chmod g+s accounting finance
[root@rhel8 tmp]# ls -l
total 0
drwxr-sr-x. 3 root accounting 30 ene 27 19:46 accounting
drwxr-sr-x. 3 root finance    28 ene 27 19:44 finance
[root@rhel8 tmp]# touch finance/testfinance
[root@rhel8 tmp]# ls -l finance/testfinance 
-rw-r--r--. 1 root finance 0 ene 28 05:27 finance/testfinance
[root@rhel8 tmp]# touch accounting/testaccounting
[root@rhel8 tmp]# ls -l accounting/testaccounting 
-rw-r--r--. 1 root accounting 0 ene 28 05:27 accounting/testaccounting
```

您可以看到，在将 Set-GID 应用到文件夹后，它们显示了组的`s`权限（加粗显示）。此外，在这些目录中创建新文件时，分配给它们的组与父目录的组相同（也加粗显示）。这样我们就确保了组权限被正确分配。

## 使用粘着位

最后要使用的权限是**粘着位**。它只对目录产生影响，它的作用很简单：当用户在具有粘着位的目录中创建文件时，只有该用户才能编辑或删除该文件。

让我们来看一个例子：

```
[root@rhel8 ~]# ls -ld /tmp
drwxrwxrwt. 8 root root 172 ene 28 04:31 /tmp
```

我们可以将这些应用到前面的例子中，也可以使用`chmod`来使用`o+t`：

```
[root@rhel8 ~]# cd /var/tmp/
[root@rhel8 tmp]# ls -l
total 0
drwxr-sr-x. 3 root accounting 52 ene 28 05:27 accounting
drwxr-sr-x. 3 root finance    47 ene 28 05:27 finance
[root@rhel8 tmp]# chmod o+t accounting finance
[root@rhel8 tmp]# ls -l
total 0
drwxr-sr-t. 3 root accounting 52 ene 28 05:27 accounting
drwxr-sr-t. 3 root finance    47 ene 28 05:27 finance
```

让我们试一试。我们将用户`sonia`添加到`accounting`组。我们将为`/var/tmp/accounting`目录的组授予写权限。然后，我们将使用用户`matilde`创建一个文件，并尝试使用用户`sonia`删除它。让我们开始：

```
[root@rhel8 ~] # usermod -aG accounting sonia
[root@rhel8 ~]# cd /var/tmp/
[root@rhel8 tmp]# chmod g+w accounting
[root@rhel8 tmp]# ls -l
total 0
drwxrwsr-t. 3 root accounting 52 ene 28 05:27 accounting
drwxr-sr-t. 3 root finance    47 ene 28 05:27 finance
[root@rhel8 tmp]# su - matilde
Last login: jue ene 28 05:41:09 CET 2021 on pts/0
[matilde@rhel8 ~]$ cd /var/tmp/accounting/
[matilde@rhel8 accounting]$ touch teststickybit
[matilde@rhel8 accounting]$ exit
logout
[root@rhel8 tmp]# su - sonia
[sonia@rhel8 ~]$ cd /var/tmp/accounting/
[sonia@rhel8 accounting]$ ls -l teststickybit 
-rw-rw-r--. 1 matilde accounting 0 Jan 28 05:43 teststickybit
[sonia@rhel8 accounting]$ rm -f teststickybit 
rm: cannot remove 'teststickybit': Operation not permitted
```

提示

特殊权限的数字值为：`suid` = `4`；`sgid` = `2`；`粘着位` = `1`。

通过这些，我们已经完成了如何管理 RHEL 中的权限。

# 总结

在本章中，我们已经回顾了 RHEL 中使用传统权限实现的权限管理系统。我们已经学会了如何创建用户帐户和组，以及如何确保密码被正确管理。我们还学会了系统中密码是如何存储的，甚至学会了如何阻止用户访问 shell。我们创建了文件和文件夹，为它们分配了权限，并确保用户可以遵守一套规则进行协作。

这些是在 RHEL 中管理访问权限的基础知识，当管理系统时，这将非常有用，以避免安全问题。由于这是一个非常重要的话题，我们建议仔细阅读本章内容，阅读所示命令的`man`页面，并努力对该主题有一个真正的理解，这将避免将来出现任何不舒服的情况。

现在，您已经准备好开始为用户提供服务并管理他们的访问权限了，这将是我们下一章要涵盖的内容。请记住要在这里学到的知识进行充分的练习和测试。


# 第六章：启用网络连接

当我们在第一章安装系统时，我们启用了网络接口。然而，网络配置是，或者可以是，更多的。

连接到网络的服务器可能需要额外的接口来配置其他网络；例如，用于访问备份服务器，从其他服务器执行内部服务，甚至访问存储，该存储不是直接通过存储阵列网络（SAN）呈现为本地驱动器，而是作为例如**Internet Small Computer System Interface** (**iSCSI**) 驱动器。

此外，服务器可能使用冗余网络功能，以确保在卡片、交换机等出现故障时，服务器仍然可以被访问并正常运行。

在本章中，我们将学习如何使用不同方法为我们的 RHEL 机器定义网络配置，并进行一些基本的网络故障排除。

这些知识将是关键的，因为服务器通常用于向其他系统提供服务，我们需要网络来实现这一目的。

在本章中，我们将涵盖以下主题：

+   探索 RHEL 中的网络配置

+   配置文件和 NetworkManager

+   使用 IPv4 和 IPv6 配置网络接口

+   配置主机名和主机名解析（DNS）

+   防火墙配置概述

+   测试连通性

让我们开始网络实践吧！

# 技术要求

您可以继续使用我们在本书开头创建的虚拟机*第一章*，*安装 RHEL8*。此外，为了测试网络通信，创建第二个虚拟机或重用我们在前几章中创建的虚拟机以测试**Network Time Protocol** (**NTP**) 配置可能会很有用，因为我们将使用它来检查连通性。文本中将指示所需的任何附加软件包。本章所需的任何附加文件可以从[`github.com/PacktPublishing/Red-Hat-Enterprise-Linux-8-Administration`](https://github.com/PacktPublishing/Red-Hat-Enterprise-Linux-8-Administration)下载。

# 探索 RHEL 中的网络配置

网络由不同的设备组成，它们被互联起来，以便信息和资源可以在它们之间共享；例如，互联网访问、打印机、文件等。

网络自计算机诞生以来就一直存在。最初，最常见的是非 IP-based 网络，通常用于在本地网络中共享数据，但随着互联网服务的扩展和对应用程序或远程服务的需求，IP 网络得到了扩展，并引入了内部网的概念，其中使用**Transmission Control Protocol/Internet Protocol** (**TCP**/**IP**)作为传输，应用程序开始更像互联网服务（甚至基于互联网服务）。

基于 IP 的网络迁移还使其他协议（如**Network Basic Input/Output System** (**NetBIOS**)）适应了它，以便它们可以在其上运行（它曾经在**NetBIOS Extended User Interface** (**NetBEUI**)上运行，即使其他网络如**InfiniBand**或**Remote Direct Memory Access** (**RDMA**)仍在使用，但它们不像 TCP/IP 那样常见）。

当然，TCP/IP 是建立在其他协议之上的。您可以在[`www.redhat.com/sysadmin/osi-model-bean-dip`](https://www.redhat.com/sysadmin/osi-model-bean-dip)检查 OSI 层定义。然而，仍涉及一些概念。当我们熟悉 TCP/IP 和网络时，我们将涵盖这些内容。

在我们进入实际细节之前，我们需要澄清一些我们从现在开始将使用的常见 TCP/IP 和网络关键词：

+   **IP 地址**：这是用于与网络上其他设备交互的地址。

+   `255.255.255.0`或`/24`。

+   网关：这是设备的 IP 地址，当目标设备在我们的网络掩码之外时，它将获取我们所有的流量，以便我们无法直接到达它。

+   DNS：这是服务器或服务器的 IP 地址，用于将域名转换为 IP 地址，以便主机可以连接到它们。

+   MAC 地址：这是物理接口地址。它对于每张卡是唯一的，并帮助在网络中识别卡，以便将适当的流量发送到它。

+   网络接口卡（NIC）：这张卡允许我们的设备连接到网络。它可能是无线的、有线的等等。

+   扩展服务集识别（ESSID）：这是无线网络的名称。

+   虚拟专用网络（VPN）：这是在客户端和服务器之间创建的虚拟网络。一旦建立，它允许您直接连接到服务，就好像它们是本地的，即使客户端和服务器在不同的地方。例如，VPN 网络用于允许远程工作者使用他们的私人互联网连接连接到公司网络。

+   虚拟局域网（VLAN）：这允许我们在实际布线之上定义虚拟网络。然后，我们可以使用特定的头字段来使它们被网络设备正确理解和处理。

+   IPv6：这是 IPv4 的替代协议，而 IPv4 仍然是今天网络中主要的协议。

在接下来的部分中，当我们解释在 Red Hat Enterprise Linux（RHEL）系统中如何设置和定义网络时，我们将使用其中一些术语。

一般来说，当系统连接时，网络上的设备之间建立了一些关系。有时，一些主机是服务提供者，通常被称为服务器，而消费者被称为客户端。当网络中的系统扮演角色时，这些网络被称为点对点（P2P）网络。

在接下来的部分，我们将熟悉配置文件和在系统中配置网络的不同方法。

# 了解配置文件和 NetworkManager

现在我们已经了解了一些网络的关键词和概念，是时候看看我们可以在哪里使用它们来使我们的系统联网了。

传统上，网络接口是通过系统中的文本文件进行配置的，在`/etc/sysconfig/network-scripts/`文件夹下。这些脚本是通过`network-scripts`包提供的实用程序处理的，该包负责使用定义的配置使网络堆栈正常运行。

重要提示

尽管`network-scripts`包是可用的并且可以安装，但它被认为是已弃用的，这意味着该包是提供和可用的，但在未来的操作系统的主要版本中可能会消失，因此它们只会被提供以便过渡到更新的方法。

NetworkManager 是一个实用程序，于 2004 年创建，旨在使桌面用户的网络配置和使用更加简单。在那时，所有的配置都是通过文本文件完成的，而且更多或更少是静态的。一旦系统连接到网络，信息几乎没有变化。随着无线网络的采用，需要更多的灵活性来自动化和简化连接到不同网络、不同配置文件、VPN 等。

NetworkManager 是为了填补这些空白而创建的，旨在成为许多发行版中使用的组件，但从一个新的角度来看，例如，它在启动时查询硬件抽象层（HAL）以了解可用的网络设备及其更改。

想象一台笔记本电脑系统；它可以连接到有线电缆，当您将其移动到另一个位置或小隔间时断开连接，可以连接到无线网络等等。所有这些事件都会传递给 NetworkManager，它会重新配置网络接口、路由、与无线网络进行身份验证，并使用户的生活比传统方式更加轻松。

提示

可以使用几个命令查询连接到系统的硬件，具体取决于硬件的连接方式；例如，通过诸如`lsusb`、`lspci`或`lshw`（分别通过安装`usbutils`、`pciutils`和`lshw`软件包提供）等实用程序。

在下面的屏幕截图中，我们可以看到与 NetworkManager 相关的可用软件包，通过`dnf search network manager`命令获取：

![图 6.1-可用于安装的 NetworkManagermanager 相关软件包在 Red Hat Enterprise Linux 8 系统中](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_06_001.jpg)

图 6.1-在 Red Hat Enterprise Linux 8 系统中可用于安装的 NetworkManagermanager 相关软件包

`NetworkManagermanager`配置在`/etc/NetworkManager`文件夹中的文件中，特别是`NetworkManager.conf`和该文件夹中可用的文件：

+   `conf.d`

+   `dispatcher.d`

+   `dnsmasq-shared.d`

+   `dnsmasq.d`

+   `system-connections`

不记得 dispatcher 是什么？记得使用`man networkmanager`获取详细信息！

NetworkManager 的 man 页面解释了这些脚本是根据网络事件按字母顺序执行的，并将接收两个参数：事件的设备名称和操作。

您可以执行以下几种操作：

+   `pre-up`：接口已连接到网络，但尚未激活。必须在连接被通知为已激活之前执行脚本。

+   `up`：接口已激活。

+   `pre-down`：接口正在停用，但尚未从网络断开连接。在强制断开连接的情况下（丢失无线连接或丢失载波），这不会被执行。

+   `down`：接口已停用。

+   `vpn-up`/`vpn-down`/`vpn-pre-up`/`vpn-pre-down`：类似于前面的接口，但用于 VPN 连接。

+   `hostname`：主机名已更改。

+   `dhcp4-change`/`dhcp6-change`：DHCP 租约已更改（已续订、已重新绑定等）。

+   `connectivity-change`：连接转换，如无连接，系统上线等。

现在我们已经了解了一些关于 NetworkManager 及其工作和设计的知识，让我们学习如何配置网络接口。

# 使用 IPv4 和 IPv6 配置网络接口

有几种配置网络接口和几种网络配置的方法。这将帮助我们确定我们需要做什么以及所需的参数和设置。

让我们看一些例子：

+   服务器可能有两个或更多的**网络接口卡**（**NIC**）以实现冗余，但一次只有一个处于活动状态。

+   服务器可能使用干线网络，并要求我们在其上定义 VLAN 以访问或提供网络中的不同服务。

+   两个或更多个 NIC 可能会组合在一起，通过组队提供增加的输出和冗余。

也可以通过几种方式进行配置：

+   `nmtui`：用于配置网络的基于文本的界面

+   `nmcli`：NetworkManager 的命令行界面

+   `nm-connection-editor`：可用于图形环境的图形工具

+   通过文本配置文件

重要提示

在编辑网络配置之前，请确保可以以其他方式访问正在配置的系统。对于服务器，可以通过远程管理卡或物理控制台访问。配置错误可能导致系统无法访问。

在我们继续之前，让我们了解一些关于 IPv4 和 IPv6 的知识

## IPv4 和 IPv6...这是什么意思？

IPv4 是在 1983 年创建的，使用 32 位地址空间，提供 2³²个唯一地址（`4,294,967,296`），但在这些可能的地址中，有大块保留用于特殊用途。IPv6 在 2017 年被批准为互联网标准，是我写作时的最新版本，它使用 128 位地址空间，即 2¹²⁸（3.4 x 10³⁸个地址）。

长话短说，当时 IPv4 地址数量似乎很大，但今天，手机、平板电脑、计算机、笔记本电脑、服务器、灯泡、智能插座和所有其他**物联网**（**IoT**）设备都需要 IP 地址，公共 IP 地址的数量已经用尽，这意味着无法再分配更多。这导致一些**互联网服务提供商**（**ISP**）使用诸如**运营商级网络地址转换**（**CGNAT**）之类的技术，类似于私人网络所做的，这使得来自多个设备的所有流量看起来都来自同一个 IP，并且设备在两个网络上进行交互（路由器），以便对原始请求者的出站和入站数据包进行正确路由。

那为什么没有 IPv6 呢？主要问题是 IPv4 和 IPv6 不兼容，即使 IPv6 在 1998 年是一个草案，也并非所有网络设备都兼容它，可能尚未经过测试。请查看[`www.ripe.net/support/training/videos/ipv6/transition-mechanisms`](https://www.ripe.net/support/training/videos/ipv6/transition-mechanisms)获取更多详细信息。

在下一节中，我们将学习如何使用名为`nmtui`的 NetworkManager 的基于文本的用户界面来配置网络接口。

## 使用 nmtui 配置接口

`nmtui`提供了一个基于文本的配置界面。这是在终端上运行`nmtui`时会看到的初始屏幕：

![图 6.2 - nmtui 欢迎屏幕显示可以执行的操作菜单](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_06_002.jpg)

图 6.2 - nmtui 欢迎屏幕显示可以执行的操作菜单

让我们探索接口的可用选项。在这种情况下，让我们选择**编辑连接**。在出现的屏幕上，向下移动并编辑我们系统中的**有线连接**选项，以进入以下屏幕：

![图 6.3 - 编辑连接页面，IPv4 选项已展开](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_06_003.jpg)

图 6.3 - 编辑连接页面，IPv4 选项已展开

很难为每个步骤展示截图，因为文本界面的优势之一是我们可以将许多选项压缩成一个简单的屏幕。然而，前面的截图使我们能够轻松理解每个所需参数：

+   IP 地址

+   子网掩码

+   网关

+   搜索域

+   路由

如您所见，有复选框可用于忽略路由或在连接设置为“自动”时获取的 DNS 参数。此外，还有其他接口选项：“禁用”，“链路本地”，“手动”和“共享”。

让我们讨论“自动”选项，这意味着接口将被设置为自动配置。这是配置的最常见设置之一。不过，这并不意味着一切都是自动完成的。让我们深入了解一下。

在一个网络（企业、私人等）中，通常会有一个专门的服务或服务器执行**动态主机路由协议**（**DHCP**）。DHCP 是在 TCP/IP 之上运行的协议，允许您动态配置主机，使用之前由网络管理员或某个设备及其默认设置进行的配置。

DHCP 允许您自动配置（从客户端）网络配置的许多方面，如 IP、子网掩码、网关、DNS、搜索域、时间服务器等。接收到的配置将被分配一个在一段时间内有效的租约。之后，系统会尝试更新它，或者如果系统被关闭或断开连接，租约将被释放。

通常，DHCP 配置被认为与动态 IP 绑定在一起，但请记住，DHCP 服务器可以使用两种不同的方法：可以重复使用不同系统连接的 IP 池，也可以将 MAC 地址固定映射到静态 IP。

例如，让我们考虑一个`192.168.1.0/24`子网。

我们可以将 ISP 路由器定义为 IP`192.168.1.1`，因为子网（`/24`）的原因，这意味着 IPv4 地址的最后一部分可以从 0 到 255 范围。

利用该 IP 范围，我们可以设置主机从最后 100 个 IP 中的动态配置和动态 IP 中获取，将前面的 IP 留给固定设备（即使它们动态获取配置），如打印机、存储设备等。

正如我们之前提到的，我们可以为服务器创建预留，但通常对于总是使用相同地址的设备，配置静态地址也是常见做法。这样，如果 DHCP 服务器不可用，服务器仍然可以从其他服务或配置了静态地址的其他服务器/设备中访问。

提示

只是为了熟悉这个概念，IP 地址在 IPv4 中以点分隔四组数字表示，例如`192.168.2.12`，而在 IPv6 中，数字以`:`分隔；例如`2001:db8:0:1::c000:207`。

## 使用 nm-connection-editor 配置接口

如果我们的系统已安装了图形环境，而我们的测试系统没有安装图形环境，我们可以使用图形配置工具。如果没有安装，请在图形会话内的 shell 控制台中执行`dnf install nm-connection-editor`。

提示

要安装图形界面，您可以运行`dnf groupinstall "Server with GUI" -y`命令，或者在安装过程中选择它。

在下面的屏幕截图中，我们可以看到通过执行`nm-connection-editor`打开的窗口。它类似于本章前面显示的`nmtui`的文本界面：

![图 6.4 - nm-connection-editor 的初始屏幕](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_06_004.jpg)

图 6.4 - nm-connection-editor 的初始屏幕

在这里，我们可以看到**+**、**-**和*齿轮*按钮，分别用于添加/删除或配置突出显示的连接。

让我们点击**有线连接**选项，然后点击**齿轮**图标打开详细信息：

![图 6.5 - 编辑网络连接的对话框](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_06_005.jpg)

图 6.5 - 编辑网络连接的对话框

在对话框中，我们可以看到简单命令行配置工具中的字段，以及每个选项组的额外字段和不同的选项卡。

要记住的重要字段是**在**通用**选项卡中用于**自动连接优先**的字段。这使我们的系统在有连接可用时自动启用该网卡。

通过检查不同的选项卡，您会发现有很多选择，比如标记连接为计量。这意味着，例如，如果通过手机进行连接，如果网络使用没有受到控制，可能会有额外的费用。

当我们创建额外的网络时，我们可以根据系统中安装的软件包定义物理或虚拟设备（如果您还记得我们在搜索 NetworkManager 时看到的软件包列表，我们有不同 VPN、Wi-Fi 等软件包），如下面的屏幕截图所示：

![图 6.6 - 带有 Wi-Fi、OpenVPN、PPTP 插件的 nm-connection-editor 蓝牙等已安装](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_06_006.jpg)

图 6.6 – 带有 Wi-Fi、OpenVPN、PPTP、蓝牙等插件的 nm-connection-editor 已安装

对于服务器环境，最常见的网络类型是**绑定**、**桥接**和**团队**（**以太网**的一部分），而对于桌面电脑，最常见的网络类型是**以太网**、**Wi-Fi**和**宽带**。

每种类型的连接都有一些要求。例如，对于绑定、桥接和团队，我们需要多个可以组合的网络接口。

现在，让我们继续在下一节中审查`nmcli`的用法。

## 使用 nmcli 配置接口

`nmcli`是 NetworkManager 的命令行界面。它不仅允许我们检查，还允许我们配置系统中的网络接口，即使使用它可能需要比`nmtui`需要更多的记忆技巧，但它赋予用户和管理员脚本能力来自动设置系统的网络。

提示

大多数命令允许我们使用自动补全；也就是说，按下*Tab*键将在命令行上使用自动补全列表来建议语法。例如，在命令行上输入`nmcli dev`并按下*Tab*将自动补全命令为`nmcli device`。在这种情况下，这可能并不像`nmcli`接受两个参数都有效那样重要，但对于其他命令来说，正确拼写是必须的才能使代码正常工作。

让我们从使用`nmcli dev`检查系统中可用的连接开始，然后使用`nmcli con show`查看其详细信息：

![图 6.7 – nmcli dev 和 nmcli con show](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_06_007.jpg)

图 6.7 – nmcli dev 和 nmcli con show

例如，当控制网络连接时，例如使用`nmcli con up "Wired Connection"`或使用`nmcli con down ens3`禁用它时，我们应该记住我们关于 NetworkManager 的解释：如果连接在系统中可用，NetworkManager 可能会在断开连接后立即重新激活它，因为连接和所需的设备在我们的系统中是可用的。

现在，让我们创建一个新接口来说明通过 IPv4 添加新连接的过程：

```
nmcli con add con-name eth0 type ethernet \
 ifname eth0 ipv4.address 192.168.1.2/24 \
 ipv4.gateway 192.168.1.254
```

我们也可以使用 IPv6：

```
nmcli con add con-name eth0 type ethernet \
 ifname eth0 ipv6.address 2001:db8:0:1::c000:207/64 \
 ipv6.gateway 2001:db8:0:1::1 ipv4.address \
 192.0.1.3/24 ipv4.gateway 192.0.1.1
```

执行了上述命令后，我们可以使用`nmcli connection show eth0`检查已定义的网络连接，并验证是否应用了正确的设置（或者当然也可以通过`nmtui`、`nm-connection-editor`或在磁盘上创建的文本文件来验证，因为信息是共享和存储在系统中的）。

当我们审查`nmcli connection show interface`的输出时，输出包含一些用点分隔的键，例如以下内容：

+   ipv4.address

+   ipv4.gateway

+   ipv6.address

+   ipv6.gateway

+   connection.id

我们可以使用这些键通过`nmcli con mod $key $value`来定义新的值，如下例所示：

![图 6.8 – 修改网络连接名称的示例连接 ID 和 IP 地址的](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_06_008.jpg)

图 6.8 – 修改网络连接名称和 IP 地址的示例

当然，在进行了上述测试后，我们也可以使用`nmcli con del datacenter`来删除连接以避免系统中的问题。

以下命令可用于使用`nmcli`工具修改连接：

+   `nmcli con show`: 显示连接的状态。

+   `nmcli con show NAME`: 显示名为`NAME`的连接的详细信息。

+   `nmcli dev status`: 显示系统中设备的状态。请注意，这意味着**设备**，而不是可能正在使用这些设备的连接。

+   `nmcli con add con-NAME`: 添加新连接。

+   `nmci con mod NAME`: 修改连接。

+   `nmcli con up NAME`: 启动连接。

+   `nmcli con down NAME`: 断开连接（仍然可以通过 NetworkManager 重新启用）。

+   `nmcli con del NAME`: 从系统中删除连接定义。

提示

查看`man nmcli-examples`以找到包含在系统文档中的更多示例。

## 使用文本文件配置接口

在前面的小节中，我们探讨了如何使用不同的方法配置网络，但最终，所有这些配置最终都会被写入磁盘作为接口定义文件（这也提供了与先前提到的`network-scripts`的向后兼容性）。

与其从头开始创建接口定义，不如看看当我们用以下命令创建接口时`nmcli`做了什么：

```
nmcli con add con-name eth0 type ethernet ifname eth0 ipv6.address 2001:db8:0:1::c000:207/64 ipv6.gateway 2001:db8:0:1::1 ipv4.address 192.0.1.3/24 ipv4.gateway 192.0.1.1
```

上述命令将生成`/etc/sysconfig/network-scripts/ifcfg-eth0`文件，我们可以在下面的截图中看到：

![图 6.9-/etc/sysconfig/network-scripts/ifcfg-eth0 连接定义的内容](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_06_009.jpg)

图 6.9-/etc/sysconfig/network-scripts/ifcfg-eth0 连接定义的内容

正如我们所看到的，默认情况下，我们指定了一个以`Ethernet`（`TYPE`）类型的网络接口，使用`eth0`设备，以及提供的 IPv4 和 IPv6 地址和网关。键的名称与使用`nmcli`定义的键不同，原因是我们具有向后兼容性。

请注意，在上面的例子中，`ONBOOT`字段已经设置为`yes`，这意味着当系统启动时，接口将自动启用。如果我们使用`nmcli`，我们可以通过`connection.autoconnect`配置键来检查状态，这也将默认情况下使连接在启动时自动启用。

我们可以直接编辑这些文件，但是为了让 NetworkManager 意识到将要引入的更改，必须执行`nmcli con reload`。这将同步对各个文件所做的更改。

例如，我们可以更正上述文件中的一个设置，因为对于静态定义的 IP，通常会定义`BOOTPROTO=none`。使用你喜欢的方法修改`/etc/sysconfig/network-scripts/ifcfg-eth0`文件（`vim`，`nano`，`sed`或其他）。要获取其他细节，我们可以使用`nmcli`进行检查，并且也可以更改 IP 地址。

请注意，在下面的截图中，更改在发出`reload`命令之前不会出现在`nmcli`中：

![图 6.10-编辑接口定义的过程在重新加载连接之前不会显示在 nmcli 上](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_06_010.jpg)

图 6.10-编辑接口定义的过程在重新加载连接之前不会显示在 nmcli 上

当然，我们也可以从头开始创建网络定义，直到 NetworkManager 的到来和传播，这种方法在脚本编写中被使用，包括通过 kickstart 文件进行的 Anaconda 自动安装。

让我们用 IPv4 中的命令创建一个简单的网络定义，如下面截图中所示：

![图 6.11-使用配置文件创建连接（可以作为脚本的一部分）](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_06_011.jpg)

图 6.11-使用配置文件创建连接（可以作为脚本的一部分）

在这里，你不仅可以看到连接的创建，还可以看到之前的状态，接口定义，系统的 NetworkManager 视图，以及重新加载的配置文件的比较。请注意，设备列为空，因为我们为该连接定义了一个在我们系统中不存在的接口。

重要提示

网络接口定义可能会变成一场噩梦，因为接口名称本身受到几条规则的约束，比如接口在总线上的位置，以前是否曾见过等。一般来说，一旦系统检测到网络卡，就会编写一个自定义规则，将接口的 MAC 地址与自定义命名约定进行匹配。这样做是为了在重新启动或新软件更新改变我们必须枚举卡的方式时不会发生变化。您可以通过查看官方 RHEL8 手册了解更多信息[`access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/consistent-network-interface-device-naming_configuring-and_managing-networking`](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/consistent-network-interface-device-naming_configuring-and_managing-networking)。

现在我们已经回顾了在我们的系统中配置网络的不同方法，让我们了解一下命名解析。

# 配置主机名和主机名解析（DNS）

记住 IP 地址，无论是 IPv4 还是 IPv6 地址，都可能变成一场噩梦。为了简化事情，对主机名和 DNS 采用了更加人性化的方法，我们可以将这些更容易记住的名称转换为系统用于连接的 IP 地址。

主机名是我们分配给主机以便它们被识别的名称，但当它们与 DNS 服务器一起使用时，我们必须有其他主机能够将它们解析为可以连接的 IP 地址。

我们可以使用`hostname`命令查看或临时修改当前主机名，如下面的屏幕截图所示：

![图 6.12 - 查询和更改主机的主机名](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_06_012.jpg)

图 6.12 - 查询和更改主机的主机名

请记住，这种更改只是暂时的；只要我们重新启动服务器，它就会使用配置的更改。

要定义一个新的配置主机名，我们将使用`hostnamectl set-hostname`命令，如下面的屏幕截图所示：

![图 6.13 - 检查先前配置的主机名和定义通过 hostnamectl 定义新主机名](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_06_013.jpg)

图 6.13 - 检查先前配置的主机名和通过 hostnamectl 定义新主机名

请注意在上面的示例中，我们有`临时主机名`与`静态主机名`，这指的是使用`hostname`而不是`hostnamectl`定义的名称的临时状态。

在名称解析方面，我们可以采取几种方法。当然，一种方法是使用 DNS 服务器，我们将在本节稍后解释，但还有其他方法。

一般来说，系统有几个解析器，并且这些解析器在`/etc/nsswitch.conf`配置文件中定义。这些解析器不仅用于网络命名，还用于解析用户，例如，企业`nsswitch.conf`指示我们的系统使用以下条目进行主机解析：`hosts: files dns myhostname`。

这意味着我们将我们的`/etc/`目录中的文件作为我们的第一个来源。在主机名的情况下，这指的是`/etc/hosts`文件。如果在该文件中定义了条目，将使用指定的值；如果没有，则`/etc/resolv.conf`文件将确定如何进行解析。这些文件，特别是`resolv.conf`，在系统部署和连接激活时进行配置。NetworkManager 负责更新通过 DHCP 获得的值（如果使用了自动配置），或者如果执行了手动配置，则使用指定的 DNS 服务器。

在下面的屏幕截图中，我们可以看到在我们的`/etc/hosts`文件中定义的条目，如何因为名称不存在而无法 ping 主机，以及在手动向`/etc/hosts`文件添加条目后，我们的系统能够到达它：

![图 6.14 - 向我们的本地系统添加静态主机条目](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_06_014.jpg)

图 6.14 - 向我们的本地系统添加静态主机条目

正如我们之前提到的，DNS 解析是通过`/etc/resolv.conf`中的配置完成的，默认情况下包含`search`参数和`nameserver`参数。如果我们查看`resolv.conf`的 man 页面，我们可以获得常见参数的描述：

+   `nameserver`：包含要使用的名称服务器的 IP。目前，`resolv`库在系统中每次最多使用三个条目（每个占一行）进行解析。每次解析都是按顺序进行的，因此如果一个服务器失败，它将超时，尝试下一个，依此类推。

+   `domain`：本地域名。它允许我们使用相对于我们主机的本地域的短名称。如果未列出，它将基于我们系统的主机名进行计算（第一个`.`之后的所有内容）。

+   `search`：默认情况下，这包含本地域名，它是我们可以尝试使用以解析提供的短名称的域名列表。它限制为 6 个域和 256 个字符。域和搜索是互斥的，因为文件中的最后一个将被使用。

提示

DNS 解析通过向特殊服务器（DNS）请求域的相关数据来实现。这是以分层方式进行的，顶层通用服务器被称为**根服务器**。DNS 服务器不仅包含将主机名转换为 IP 的注册表或条目，还包括有关发送电子邮件时要使用的邮件服务器、安全验证详细信息、反向条目等信息。此外，DNS 服务器还可以通过为某些域返回无效 IP 来阻止对服务的访问，或者通过使用比 ISP 提供的更快的 DNS 服务器来加快互联网导航速度。当域名注册时，在根表中为该域创建一个新条目，指向 DNS 服务器。这将负责该域的解析，并且稍后，这些条目将在互联网上进行填充和缓存，以加快解析速度。

如果我们想修改连接定义的 DNS 服务器，记得使用`nmcli con mod NAME ipv4.dns IP`（或 IPv6 等效），并在之前使用`+`符号，如`+ipv4.dns`，以将新条目添加到 DNS 服务器列表中。对`resolv.conf`的任何手动更改可能会被覆盖。

现在我们已经了解了 DNS 的工作原理以及我们的系统如何使用它，让我们看看如何保护系统网络访问。

# 防火墙配置概述

当系统连接到网络时，许多正在运行的服务可以从其他系统访问。这是连接系统的目标。然而，我们也希望保持系统安全，远离未经授权的使用。

**防火墙**是一种软件层，位于网络卡和服务之间，允许我们对允许或不允许的内容进行微调。

我们无法完全阻止所有传入连接到我们的系统，因为经常传入连接是我们的系统发出的请求的响应。

连接是通过名为`iptables`、`ip6tables`、`ebtables`和`arptables`的内核框架来阻止的。

重要说明

正如我们之前在网络配置方面解释的那样，防火墙中的错误配置可能会将您锁在系统外，因此在设置一些限制性规则时一定要非常小心，以便在远程访问系统时可以重新登录系统。

`firewalld`软件包应该包含在基本安装中。一旦安装，它将提供`firewall-cmd`命令与服务进行交互。

firewalld 使用区域的概念，允许我们为每个区域预定义一组规则。这些也可以分配给网络连接。例如，对于可能在连接之间漫游的笔记本电脑，当您使用家庭或公司连接时，可能更相关，而当您使用来自咖啡厅的 Wi-Fi 时，它们将默认为更安全的设置。

firewalld 还使用预定义的服务，以便防火墙知道应该基于已启用的服务和区域来启用哪些端口和协议。

让我们看看可用的区域以及有关家庭区域的更多详细信息：

![图 6.15 - 可用区域和家庭区域的配置](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_06_015.jpg)

图 6.15 - 可用区域和家庭区域的配置

如我们所见，已定义了几个区域：

+   `public`：这是新添加接口的默认区域。它允许我们使用 cockpit SSH 和 DHCP 客户端，并拒绝与传出流量无关的所有传入流量。

+   `block`：拒绝所有传入流量，除非与传出流量相关。

+   `dmz`：拒绝所有传入流量，除非与传出或 SSH 连接相关。

+   `drop`：丢弃所有与传出流量无关的传入数据包（甚至不是 ping）。

+   `external`：阻止所有传入流量，除了与传出流量相关的流量。它还允许 SSH，并将流量伪装为来自此接口的流量。

+   `home`：除了 public，还允许`smb`和`mdns`。

+   `internal`：基于家庭区域。

+   `trusted`：允许所有传入流量。

+   `work`：阻止所有传入流量，除了与传出或 SSH/cockpit/DHCP 流量相关的流量。

接下来，我们将学习如何在配置防火墙时使用这些区域。

## 配置防火墙

正如本节介绍中所示，防火墙可以通过`firewall-cmd`命令进行配置（以及在*第四章*中早些时候在本书中描述的 cockpit web 界面）。最常用的命令选项如下：

+   `firewall-cmd --get-zones`：列出可用的区域。

+   `firewall-cmd --get-active-zones`：列出已分配的活动区域和接口。

+   `firewall-cmd --list-all`：转储当前配置。

+   `firewall-cmd --add-service`：将服务添加到当前区域。

+   `firewall-cmd --add-port`：将端口/协议添加到当前区域。

+   `firewall-cmd --remove-service`：从当前区域中移除服务。

+   `firewall-cmd --remove-port`：从当前区域中移除端口/协议。

重要提示

请注意，在上述命令之后，您需要提到端口号和服务名称以添加或删除服务/端口。

+   `firewall-cmd --reload`：从保存的数据重新加载配置，从而丢弃运行时配置。

+   `firewall-cmd –get-default-zone`：获取默认区域。

+   `firewall-cmd --set-default-zone`：定义要使用的默认区域。

例如，当我们在系统中安装 HTTP 服务器（用于提供网页）时，必须启用 TCP 端口`80`。

让我们在示例系统中尝试安装、运行和打开 HTTP 端口：

```
dnf –y install httpd
systemctl enable httpd
systemctl start httpd
firewall-cmd –add-service=http
curl localhost
```

最后一个命令将向本地`http`服务器发出请求以获取结果。如果您可以访问其他系统，可以尝试连接到我们一直在使用的服务器的 IP，以查看系统提供的默认网页。

在下面的屏幕截图中，我们可以看到`curl localhost`命令的输出：

![图 6.16 - 请求由我们的系统托管的网页的 curl 输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_06_016.jpg)

图 6.16 - 请求由我们的系统托管的网页的 curl 输出

到目前为止，我们已经审查了如何配置一些基本的防火墙规则，所以我们准备检查网络的连通性。

# 测试网络连通性

在前面的章节中，我们正在与网络接口、地址和防火墙规则进行交互，这些规则定义、限制或允许连接到我们的系统。在本节中，我们将回顾一些基本工具，用于验证网络连接是否存在。

请注意，以下命令假定防火墙未设置为严格模式，并且我们可以使用**Internet 控制消息协议**（**ICMP**）来访问托管服务的服务器。在安全网络中，服务可能正在运行，但不会回答 ping - 它可能只会回答服务查询本身。

我们可以在这里使用几个命令，因此请考虑以下建议来诊断问题：

+   检查本地接口的 IP 地址、子网掩码和网关。

+   使用`ping`命令和网关的 IP 地址验证正确的网络配置。

+   使用`ping`命令对`/etc/resolv.conf`中的 DNS 服务器进行 ping，以查看是否可达。或者，使用`host`或`dig`命令查询 DNS 服务器。

+   如果据说有外部网络连接，请尝试访问外部 DNS 服务器，如`8.8.8.8`或`1.1.1.1`，或使用`curl`或`wget`请求一些已知服务的网页；例如，`curl nasa.gov`。

这应该让您对问题可能出在哪有一个大概的想法，根据您在测试中达到的距离。请记住，还有其他工具，比如`tracepath`，它将显示 TCP 数据包在到达目的地之前经过的跳数。每个命令的 man 页面将为您提供有关其用法的提示和示例。

在下面的屏幕截图中，您可以看到针对一个 Web 服务器的`tracepath`的输出：

![图 6.17 - 对西班牙瓦伦西亚大学网站的 tracepath 命令的输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_06_17.jpg)

图 6.17 - 对西班牙瓦伦西亚大学网站的 tracepath 命令的输出

正如我们所看到的，跨越不同服务器执行了 11 个步骤，直到我们的数据包到达目的地主机。这使我们了解了数据包如何穿越互联网到达目标系统。

# 总结

在本章中，我们学习了使用不同方法配置网络接口，可以通过手动交互或通过允许我们脚本或自动配置的方法。

还介绍了一些用于帮助我们找到一些基本错误的网络问题的故障排除方法。

正如我们在本章的介绍中提到的，网络是我们的系统到达其他服务并向其他系统提供服务的基础。我们还介绍了更复杂的网络设置的概念，超出了 RHCSA 级别的范围，但至少熟悉我们职业生涯中将要使用的关键词是有趣的。

在下一章中，我们将涵盖一些与安全相关的重要主题，例如在我们的系统中添加、打补丁和管理软件。
