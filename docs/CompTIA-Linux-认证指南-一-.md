# CompTIA Linux 认证指南（一）

> 原文：[`zh.annas-archive.org/md5/1D0BEDF2E9AB87F7188D92631B85ED3E`](https://zh.annas-archive.org/md5/1D0BEDF2E9AB87F7188D92631B85ED3E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Linux+认证证明了技术能力，并提供了对 Linux 操作系统的广泛认识。获得 Linux+认证的专业人士展示了对安装，操作，管理和故障排除服务的重要知识。

CompTIA Linux+认证指南是对该认证的概述，让您深入了解系统架构。您将了解如何安装和卸载 Linux 发行版，然后使用各种软件包管理器。一旦您掌握了所有这些，您将继续在命令行界面（CLI）操作文件和进程，并创建，监视，终止，重新启动和修改进程。随着您的进步，您将能够使用显示管理器，并学习如何创建，修改和删除用户帐户和组，以及了解如何自动执行任务。最后一组章节将帮助您配置日期并设置本地和远程系统日志记录。除此之外，您还将探索不同的互联网协议，以及发现网络配置，安全管理，Shell 脚本和 SQL 管理。

通过本书，您不仅将通过练习问题和模拟考试来掌握所有模块，而且还将为通过 LX0-103 和 LX0-104 认证考试做好充分准备。

# 本书适合人群

CompTIA Linux+认证指南适用于希望获得 CompTIA Linux+证书的人。本指南还适用于系统管理员和新手 Linux 专业人士，他们有兴趣提高他们的 Linux 和 Shell 脚本技能。不需要 Linux 的先前知识，尽管对 Shell 脚本的一些了解会有所帮助。

# 本书涵盖的内容

第一章，*配置硬件设置*，本章重点介绍查看中断，查看`/proc/interrupts`，查看 CPU 信息，查看`/proc/cpuinfo`，查看 raid 状态，查看`/proc/mdstat`，设备目录`/dev`，`/proc`虚拟目录，`lsmod`命令和用法，`modprobe`命令和用法，`lspci`命令和用法。

第二章，*系统引导*，本章重点介绍系统引导的过程，查看 GRUB 和 GRUB2 配置文件，重点关注计时器，默认引导条目，在 GRUB/GRUB2 引导菜单中传递参数，`chkconfig`命令，systemctl，各种启动/停止`scripts0`。

第三章，*更改运行级别和引导目标*，本章重点介绍运行级别和引导目标的介绍，LINUX 发行版中可用的运行级别和引导目标的类型，运行级别和引导目标之间的区别，在 CLI 中使用运行级别，还在 CLI 中使用引导目标。

第四章，*设计硬盘布局*，本章重点介绍在 CLI 上创建分区/分割物理硬盘，重点介绍`fdisk`实用程序的使用，`parted`实用程序，创建，删除，定义分区类型，使用各种`mkfs`命令格式化硬盘的步骤。

第五章，*安装 Linux 发行版*，本章重点介绍安装 Linux 发行版，特别是 CentOS 的 Red Hat 风味和 Ubuntu 的 Debian 风味，读者将通过使用 Live CD 的一种常见方法来安装 Linux 发行版。

第六章，使用 Debian 软件包管理，在 Linux 中，软件可以通过多种方式添加、删除。这里重点介绍了在 Debian 发行版中添加软件的方式，特别是使用 CLI 中的 dpkg、apt-get、aptitude 命令，以及 GUI 中的 synaptic，读者将学习如何在 Debian 发行版中添加、删除、更新、擦除软件。

第七章，使用 YUM 软件包管理，在本章中，我们重点介绍了在 Red Hat 发行版中添加软件的方式，特别是使用 CLI 中的 yum、dnf、rpm 命令，以及 GUI 中的 yumex，读者将学习如何在 Red Hat 环境中添加、删除、更新和擦除软件。

第八章，执行文件管理，在本章中，读者将了解 Linux 提供的各种命令，这些命令是常见发行版用于在 CLI 中操作文件、进程的。这些命令可以分为几类：文件系统导航、文件操作、目录操作、文件位置和文件检查、CPU 硬件标识、进程优先级、操作进程的 CPU 优先级。

第九章，创建、监视、终止和重新启动进程，在 Linux 中，进程或多或少等同于正在运行的程序。init/systemd 是内核启动时运行的第一个进程。本章重点介绍了如何创建进程，监视现有进程的硬件使用情况，终止/杀死进程或在 CLI 中重新启动进程。

第十章，修改进程执行，有时您可能希望优先处理重要程序而不是其他程序，还可以将一些程序发送到后台，允许用户继续使用 shell 或将一些程序带到前台。本章重点介绍了使用 nice 和 renice、fg、bg 命令来实现这一点的方法。

第十一章，显示管理器，本章重点介绍了 Linux 发行版中可用的各种显示管理器，如 X 显示管理器（XDM）、KDE 显示管理器（KDM）、Gnome 显示管理器（GDM）、Light 显示管理器（LightDM），用于处理 GUI 登录，它们都使用 XDMCP - X 显示管理器控制协议，启动本地计算机的 X 服务器。

第十二章，管理用户和组帐户，本章重点介绍了用户和组管理，包括用户帐户创建、修改现有用户帐户、删除用户帐户、组创建、修改用户组、删除组，以及在管理用户和组时要考虑的最佳实践。重点是使用诸如 useradd、usermod、userdel、groupadd、groupmod、groupdel、who、w、change、passwd、last、whoami 等命令，以及配置文件，如/etc/passwd、/etc/shadow、/etc/group、/etc/skel 文件。

第十三章，自动化任务，本章重点介绍了在 Linux 环境中自动化常见的管理任务以及在设置给定任务的自动化时要考虑的常用方法。重点是使用诸如 crontab、at、atq、atrm、anacron 等命令，以及配置文件，如/etc/at.deny、/etc/at.allow、/etc/cron.{daily,hourly,monthly,weekly}、/etc/cron.allow、/etc/anacrontab。

第十四章，维护系统时间和日志，本章重点介绍配置日期和时间以及设置时区。此外，设置在 Linux 发行版中使用`rsyslog`，`logrotate`进行本地日志记录以及配置日志记录发送到远程`syslog`服务器进行管理的步骤。涵盖的命令包括`tzselect`，`tzconfig`，`date`，`journalctl`，目录包括`/etc/timezone`，`/etc/localtime`，`/usr/share/zoneinfo`，`/etc/logrotate.conf`，`/etc/logrotate.d/`，`/etc/systemd/journald.conf`，`/var/log/`，`/var/log/journal/`，`/etc/rsyslog.conf`。

第十五章，互联网协议基础，本章重点介绍互联网等网络如何工作的基本原理，通过解释两台计算机如何相互通信，我们深入研究互联网协议（IP）寻址，特别是 IPv4，IPv4 的各种类别，如 A 类，B 类，C 类，CIDR 表示法，然后我们看子网划分。接下来我们看一下 IPv6，IPv6 地址的格式，众所周知的 IPv6 地址，缩短 IPv6 地址的方法。

最后，我们看一下一些著名协议（如 UDP，TCP 和 ICMP）及其端口号之间的区别。

第十六章，网络配置和故障排除，本章重点介绍 Linux 环境中的基本网络配置，包括配置 IPv4 地址，子网掩码，默认网关。接下来我们看一下配置 IPv6 地址，默认网关，然后我们专注于配置客户端 DNS，最后我们专注于网络故障排除。命令如`ifup`，`ifdown`，`ifconfig`，`ip`，`ip link`，`ip route`，`route`，`ping`，`ping6`，`netstat`，`traceroute`，`traceroute6`，`tracepath`，`tracepath6`，`dig`，`host`，`hostname`。

第十七章，执行安全管理任务，本章重点介绍 Linux 环境中执行安全管理任务，重点放在设置主机安全，授予用户特殊权限与 sudoers，日期加密。涵盖的命令有`sudo`，`ssh-keygen`，`ssh-agent`，`ssh-add`，`gpg`，配置文件包括`/etc/sudoers`，`/etc/hosts.allow`，`/etc/hosts.deny`，`~/.ssh/id_rsa`，`~/.ssh/id_rsa.pub`，`/etc/ssh/ssh_host_rsa_key`，`~/.ssh/authorized_keys`，`/etc/ssh_known_hosts`。

第十八章，Shell 脚本和 SQL 数据管理，本章重点介绍 Linux 环境中的 Shell 脚本和 SQL 数据管理。首先，我们看一下编写脚本时的基本格式，识别脚本的解释器，配置脚本为可执行，使用`for`，`while`循环，`if`语句。然后我们将注意力集中在 SQL 数据管理上，我们涵盖基本的 SQL 命令，如`insert`，`update`，`select`，`delete`，`from`，`where`，`group by`，`order by`，`join`。

第十九章，模拟考试-1，这个模拟考试将包括现实世界的考试问题和答案。您将获得来自真实场景的示例，详细的指导和关键主题的权威覆盖。最近测试的现实考试问题，为您带来为 CompTIA LX0-103/LX0-104 考试做准备的最佳方法。

第二十章，模拟考试-2，这个模拟考试将包括现实世界的考试问题和答案。您将获得来自真实场景的示例，详细的指导和关键主题的权威覆盖。最近测试的现实考试问题，为您带来为 CompTIA LX0-103/LX0-104 考试做准备的最佳方法。

# 为了充分利用本书

假设一些读者可能对 Linux 操作系统有限或没有知识。还假设一些读者是 Linux 用户，但可能需要对与 Linux 环境交互有所恢复。

巩固每一章记忆的关键是获取各种 Linux 发行版的副本；即 CentOS、Fedora 和 Ubuntu。然后在虚拟环境中安装各种操作系统，如 VMware 或 VirtualBox。接下来，通过在各种 Linux 发行版中练习，跟随每一章（各章节相互独立，因此您可以选择任意一章来学习/练习），以更好地掌握每一章。在练习了各种章节之后，您将在 Linux 环境中变得更加高效；这将使您在混合环境中更加适应，其中既有 Windows 操作系统，也有 Linux 操作系统。

您可以在本书的第五章中的*安装 Linux 发行版*教程中跟随操作开始安装。

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781789344493_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/9781789344493_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“要实时查看 shell 中的运行级别，我们可以使用`runlevel`命令。”

代码块设置如下：

```
while <condition>
do
          <command1>
          <command2 
```

任何命令行输入或输出都以以下方式编写：

```
$[philip@localhost Desktop]$ who -r
run-level 5 2018-06-20 08:20 last=S
[philip@localhost Desktop]$ 
```

**粗体**：表示一个新术语，一个重要的词，或者你在屏幕上看到的词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“从管理面板中选择系统信息。”

警告或重要说明会以这种方式出现。

提示和技巧会以这种方式出现。


# 第一章：配置硬件设置

本章涵盖了查看中断。它专注于`/proc/interrupts`，CPU 信息查看（`/proc/cpuinfo`），查看已安装的物理内存。它还查看了`/proc/meminfo`，`free`命令，查看交换内存，以及使用`dd`，`mkswap`，`swapon`和`swapoff`命令添加和删除额外的交换内存。RAID 状态（`查看/proc/mdstat`）也有概述，还有设备目录`/dev`，`/proc`虚拟目录，`lsmod`命令和用法，`modprobe`命令及其用法，以及`lspci`命令和用法。`/proc`目录是一个虚拟文件系统，在启动时创建，用于存储有关系统的各种硬件信息。

首先，让我们把所有的干扰因素排除在外。浏览各个目录并使用这些命令非常有益，可以让您在 Linux 环境中获取硬件信息。

本章将涵盖以下主题：

+   查看 CPU，RAM 和交换信息

+   中断和设备

+   模块

# 查看 CPU，RAM 和交换信息

让我们看看如何在 Linux 系统上查看 CPU，RAM 和交换信息。

首先，我们将专注于获取有关 CPU 的信息，因此我们将查看`/proc/cpuinfo`文件。我们可以从中获取有关 CPU 的详细信息，包括供应商 ID，CPU 系列，型号名称，CPU 速率（以 MHZ 为单位），其缓存大小以及核心数量等。以下是运行`cat`命令并与`/proc/cpuinfo`一起的摘录：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00005.jpeg)

关于 CPU 还提供了更多信息：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00006.jpeg)

从前面的输出中，我们可以看到有关我们运行`cat /proc/cpuinfo`命令的 CPU 的详细信息。

接下来，让我们看看如何收集有关系统中安装的**随机存取内存**（**RAM**）的物理内存量的信息。我们将专注于两个命令，即`cat /proc/meminfo`和`free`命令。

再次使用 Linux 系统进行演示，我们将查看`/cat /proc/meminfo`命令的输出：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00007.jpeg)

以下截图显示了更多的内存使用信息：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00008.jpeg)

从前面的输出中，我们可以看到一些重要的字段，即前三个字段（`MemTotal`，`MemFree`和`MemAvailable`），它们反映了我们物理内存（RAM）的当前状态。

现在让我们再看另一个命令，即`free`命令。这个命令将以更易读的格式给出内存信息。使用我们的测试 Linux 系统，我们将运行`free`命令：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00009.jpeg)

仅运行`free`命令将以 KB 为单位给出前面的结果。我们可以在`free`命令上添加一些选项以使其更加明确。以下是我们可以在 Ubuntu 发行版上使用的`free`命令的选项列表：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00010.jpeg)

这些是我们可以在 Ubuntu 发行版上使用`free`命令的一些选项：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00011.jpeg)

同样，如果我们在 CentOS 7 发行版上查看`free`命令的主页面，我们可以看到类似的选项：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00012.jpeg)

在 CentOS 7 发行版上，我们可以使用`free`命令传递的一些其他选项如下所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00013.jpeg)

让我们尝试一些`free`命令的选项：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00014.jpeg)

前面的输出是`free`命令中最常用的选项之一（`-h`）。我们甚至可以进一步使用（`-g`）选项来显示以 GB 为单位的物理内存总量：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00015.jpeg)

我们甚至可以使用另一个很棒的选项（`-l`）来查看低内存和高内存的统计信息：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00016.jpeg)

在前面的截图中，我们不仅显示了 RAM 信息，还显示了我们的交换内存。它显示在最后一行。如果我们只想看到交换内存，我们可以使用另一个命令`swapon`：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00017.jpeg)

以下是在 Ubuntu 发行版上`swapon`主页上可以使用的一些选项：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00018.jpeg)

在 Ubuntu 发行版上，`swapon`命令可以传递更多选项，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00019.jpeg)

以下是在 CentOS 7 发行版上`swapon`主页上可以使用的一些选项：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00020.jpeg)

在 CentOS 7 发行版上，`swapon`命令可以传递更多选项，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00021.jpeg)

我们还可以从`/proc`目录中查看交换信息，具体在`/proc/swaps`中：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00022.jpeg)

从前面的输出中，我们可以看到交换空间正在使用`/dev/sda4`分区。现在，如果由于某种原因我们的物理内存用完了，并且我们已经用完了交换空间，那么我们可以添加更多物理内存或添加更多交换空间。因此，让我们专注于添加更多交换空间的步骤。

我们需要使用`dd`命令创建一个空白文件。请注意，您需要 root 访问权限才能在 shell 中运行此命令：

```
trainer@trainer-virtual-machine:~$ dd if=/dev/zero of=/root/myswapfile bs=1M count=1024
dd: failed to open '/root/myswapfile': Permission denied
trainer@trainer-virtual-machine:~$
```

从前面的输出中，我们可以看到收到了`Permission denied`的消息，所以让我们切换到 root 并尝试重新运行该命令：

```
root@trainer-virtual-machine:/home/trainer# dd if=/dev/zero of=/root/myswapfile bs=1M count=1024
1024+0 records in
1024+0 records out
1073741824 bytes (1.1 GB, 1.0 GiB) copied, 17.0137 s, 63.1 MB/s
root@trainer-virtual-machine:/home/trainer#
```

我们刚刚使用名称`myswapfile`创建了一个`swap`文件。现在我们需要运行`mkswap`命令，并在 shell 中调用我们刚刚创建的`swap`文件：

```
root@trainer-virtual-machine:~# mkswap myswapfile
Setting up swapspace version 1, size = 1024 MiB (1073737728 bytes)
no label, UUID=e3b8cc8f-ad94-4df9-8608-c9679e6946bb
root@trainer-virtual-machine:~#
```

现在，最后一步是打开`swap`文件，以便系统根据需要使用它：

```
root@trainer-virtual-machine:~# swapon myswapfile
swapon: /root/myswapfile: insecure permissions 0644, 0600 suggested.
root@trainer-virtual-machine:~#
```

我们收到了一个关于不安全权限的警告消息。我们将在后面的章节中讨论权限。现在，我们将继续使用现有的权限。最后一步是验证`swap`文件确实可供我们的系统使用：

```
root@trainer-virtual-machine:~# swapon
NAME                TYPE       SIZE   USED    PRIO
/dev/sda4           partition  5.9G   960K    -1
/root/myswapfile    file       1024M   0B     -2
root@trainer-virtual-machine:~#
```

现在，我们的系统已经可以使用新创建的`swap`文件。我们还可以运行`free`命令，现在会发现交换内存增加了 1GB：

```
root@trainer-virtual-machine:~# free -h
 total   used   free  shared  buff/cache   available
Mem:  1.9G    848M    72M   13M    1.0G        924M
Swap: 6.8G    960K    6.8G
root@trainer-virtual-machine:~#
```

为了使更改在重新启动时安全，您需要在`/etc/fstab`中添加一个条目。

如果我们不再想使用`swap`文件，我们可以使用`swapoff`命令将`myswapfile`从交换内存中删除。以下是我们在 shell 中如何完成这个任务：

```
root@trainer-virtual-machine:~# swapoff myswapfile
root@trainer-virtual-machine:~#
```

现在让我们重新运行`swapon`命令，然后运行`free`命令来验证`myswapfile`确实已从交换使用中移除：

```
root@trainer-virtual-machine:~# swapon
NAME       TYPE      SIZE   USED   PRIO
/dev/sda4 partition  5.9G   1.6M   -1 root@trainer-virtual-machine:~# free -h
 total   used    free   shared  buff/cache available
Mem:   1.9G    931M    133M   17M     917M        845M
Swap:  5.8G    1.6M    5.8G
root@trainer-virtual-machine:~#
```

正如我们所看到的，`myswapfile`不再可用于作为交换内存使用。以下是在 Ubuntu 发行版上可以与`swapoff`命令一起使用的选项：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00023.jpeg)

`swapoff`命令可以传递更多选项，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00024.jpeg)

以下是在 CentOS 7 发行版上`swapoff`命令可以使用的选项：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00025.jpeg)

`swapoff`命令可以传递更多选项，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00026.jpeg)

# 中断和设备

现在让我们转换方向，看看我们的 Linux 系统中可用的**中断请求**（**IRQs**）和设备。您可以将中断视为我们在需要特定物品时使用的服务热线。我们会打电话给服务热线。对于 Linux 系统中的设备，理论仍然是一样的；每当它需要 CPU 的注意时，它会通过中断发送信号。传统的 32 位架构支持多达 16 个中断：0-15。更新的架构支持的中断远远超过 16 个。

让我们再次查看`/proc`目录，重点关注`/proc/interrupts`：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00027.jpeg)

以下截图显示了更多的中断：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00028.jpeg)

下面的截图显示了更多的中断：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00029.jpeg)

从前面的输出中，我们可以看到有更多的中断可用。输出从左到右读取，左边表示中断号，向右移动表示正在使用中断的设备或服务。我们可以看到定时器正在使用中断`0`。

现在，让我们把注意力转向设备。在 Linux 系统中使用设备时，设备被表示为文件。这使我们能够与系统中的实际硬件进行通信。有一些常用的设备，比如硬盘、DVD 和 USB 等。硬盘被表示为`sd(n)`；例如：`/dev/sda`、`/dev/sdb`、`/dev/sdc`等。硬盘分区以`sd(n)`的形式表示；例如：`/dev/sda1`、`/dev/sda2`、`/dev/sdb1`等。同样，软盘被表示为`fd.`。还有一些特殊用途的文件，比如`/dev/null`、`/dev/zero`和`/dev/tty*`。当你想要从另一个命令发送输出并且不需要输出时，你会使用`/dev/null`。这被称为重定向。`/dev/zero`与我们之前介绍的`dd`命令一起使用，用于创建空文件。`/dev/tty*`用于远程登录。让我们看看 Linux 环境中如何显示设备。

我们将使用我们的测试 Linux 系统查看`/proc/devices`：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00030.jpeg)

从前面的输出中，硬盘和分区以`/dev/sdXY`的格式表示，其中`X`表示硬盘，`Y`表示分区。我们可以告诉`ls`命令将输出过滤为仅包含硬盘和分区信息：

```
root@trainer-virtual-machine:~# ls /dev/sd*
/dev/sda  /dev/sda1  /dev/sda2  /dev/sda3  /dev/sda4
root@trainer-virtual-machine:~#
```

# 模块

你是否曾经想过在 Linux 环境中*驱动程序*发生了什么？好吧，不用再想了。大多数来自 Microsoft Windows 背景的人习惯于通过驱动程序与硬件进行交互。在 Linux 中，我们将驱动程序称为模块。这并不像听起来那么可怕。每当我们使用一块硬件时，我们都会加载和卸载模块。例如，当我们插入 USB 驱动器时，模块会被加载到后台，并在我们移除 USB 驱动器时自动卸载。就是这么灵活。

让我们来看看如何使用`lsmod`命令查看安装在 Linux 系统中的模块：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00031.jpeg)

以下截图显示了更多可用的模块：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00032.jpeg)

根据前面的输出，我们可以看到在这个 Linux 系统中有许多模块可供使用。我们从左到右读取输出，在`Used by`列下看到一个`0`值。这意味着该模块目前未被使用。

现在让我们看看使用`rmmod`命令删除模块的过程。我们将删除`usbhid`模块，因为它目前没有在使用。我们可以通过使用`lsmod | grep usbhid`快速验证这一点：

```
root@trainer-virtual-machine:~# lsmod | grep usbhid
usbhid                 49152  0
```

太好了！让我们继续使用`rmmod`命令删除该模块：

```
root@trainer-virtual-machine:~# rmmod usbhid
root@trainer-virtual-machine:~#
root@trainer-virtual-machine:~# lsmod | grep usbhid
root@trainer-virtual-machine:~#
```

好了，`usbhid`模块现在已经不再加载在 Linux 系统中。但是，它仍然驻留在那里，因为它已经编译进内核了。在 Ubuntu 发行版上，`rmmod`只有几个选项：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00033.jpeg)

同样，在 CentOS 7 发行版上使用`rmmod`的选项如下：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00034.jpeg)

为了重新安装`usbhid`模块，我们将使用另一个常用命令`insmod`。让我们看看`insmod`在 shell 中是如何工作的：

```
root@trainer-virtual-machine:~# insmod usbhid
insmod: ERROR: could not load module usbhid: No such file or directory
root@trainer-virtual-machine:~#
```

现在，根据前面的输出，似乎有些矛盾，`insmod`命令无法找到`usbhid`模块。别担心，这个模块已经编译进内核了。也就是说，我们可以使用另一个有用的命令`modprobe`。这个命令比`insmod`更受欢迎，因为`modprobe`在我们使用`modprobe`添加模块时实际上在后台调用`insmod`。有趣的是，`modprobe`也可以用来移除模块。它通过在后台调用`rmmod`来实现这一点。

我们可以使用`insmod`本身来安装`usbhid`模块。唯一的问题是，您必须指定模块的绝对路径。另一方面，`mobprobe`使用模块目录，即`/lib/modules/$(KERNEL_RELEASE)/`，用于模块，并根据`/etc/modprobe.d/`目录中定义的规则加载模块。

因此，让我们使用`modprobe`在 shell 中安装`usbhid`模块。

```
root@trainer-virtual-machine:~# modprobe -v usbhid
insmod /lib/modules/4.4.0-24-generic/kernel/drivers/hid/usbhid/usbhid.ko
root@trainer-virtual-machine:~#
```

我们在`modprobe`命令中使用了`-v`选项，因为默认情况下它不会显示后台发生的情况。正如您所看到的，`modprobe`确实在后台调用`insmod`。现在我们可以使用`modprobe`删除这个`usbhid`模块，我们会看到它确实在后台调用`rmmod`：

```
root@trainer-virtual-machine:~# modprobe -r -v usbhid
rmmod usbhid
root@trainer-virtual-machine:~#
```

从前面的输出可以明显看出，`modprobe`确实在后台调用`rmmod`来移除模块。

以下是在 Ubuntu 发行版上可以与`modprobe`命令一起使用的一些选项：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00035.jpeg)

`modprobe`命令可以传递的一些其他选项如下截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00036.jpeg)

`modprobe`命令可以传递的一些其他选项如下截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00037.jpeg)

以下是在 CentOS 7 发行版上可以与`modprobe`命令一起使用的一些选项：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00038.jpeg)

`modprobe`命令可以传递的一些其他选项如下截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00039.jpeg)

`modprobe`命令可以传递的更多选项如下截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00040.jpeg)

# 总结

在本章中，我们关注硬件设置，查看了各个目录中的 CPU、RAM 和交换信息。我们使用了各种命令。此外，我们还涉及了 Linux 系统中可用的各种中断和中断。然后，我们查看了设备，以文件的形式。最后，我们使用了模块。我们看到了 Linux 系统中当前可用的各种模块，并学习了安装和移除模块的步骤。

在下一章中，我们将专注于系统引导过程。此外，将介绍各种引导管理器。这对于每个 Linux 工程师来说都是另一个关键方面。简而言之，没有引导管理器，系统将无法引导，除非我们从某种媒体引导。掌握这些知识将使您作为 Linux 工程师处于领先地位。完成下一章后，您将在认证方面具有更大的优势。希望很快能见到您。

# 问题

1.  哪个目录被创建为虚拟文件系统？

A. `/dev`

B. `/lib`

C. `/proc`

D. 以上都不是

1.  查看 CPU 信息的命令是什么？

A. `less /proc`

B. `more /proc`

C. `cat /proc`

D. `cat /proc/cpuinfo`

1.  查看`/proc`目录中的 RAM 的命令是什么？

A. `tail /proc/free`

B. `less /proc/free`

C. `cat /proc/meminfo`

D. `cat /proc/RAM`

1.  `free`命令的哪个选项以友好的格式显示内存信息？

A. `free -F`

B. `free -L`

C. `free -h`

D. `free –free`

1.  用于告诉系统文件是`swap`文件的命令是什么？

A. `doswap`

B. `format swap`

C. `mkswap`

D. `swap`

1.  使用哪个命令来激活`swap`文件？

A. `Swap`

B. `onSwap`

C. `swap`

D. `swapon`

1.  显示交换分区信息的命令是什么？

A. `mkswap`

B. `swapon`

C. `swap`

D. `swapoff`

1.  哪个设备文件可以重定向消息以发送到丢弃？

A. `/dev/discard`

B. `/dev/null`

C. `/dev/redirect`

D. `以上都不是`

1.  用于显示 Linux 系统中当前可用模块的命令是什么？

A. `insmod`

B. `depmod`

C. `rmmod`

D. `lsmod`

1.  使用哪个命令来安装模块，而不必指定绝对路径？

A. `rmmod`

B. `modules`

C. `modrm`

D. `modprobe`

# 进一步阅读

+   该网站将为您提供有关当前 CompTIA Linux+认证的所有必要信息：[`www.comptia.org/`](https://www.comptia.org/)

+   这个网站将为您提供与 LPI 考试相关的详细信息，特别是通过通过 CompTIA Linux+考试获得的 LPIC - Level 1：[`www.lpi.org/`](http://www.lpi.org/)

+   这个网站提供了各种可用的 Linux 内核的详细信息：[`www.kernel.org/`](https://www.kernel.org/)


# 第二章：系统引导

在上一章中，我们涵盖了我们日常管理的常见硬件设置。我们提到了一些命令，可以用来识别 Linux 系统中的硬件。本章将从那里继续，并进一步进行，这次重点是系统引导的过程。它查看了 GRUB 和 GRUB2 配置文件，重点关注了计时器、默认引导项以及向 GRUB/GRUB2 引导菜单传递参数。它还涵盖了 `chkconfig`、`pstree`、`ps`、`systemctl` 和 `dmeg` 命令，以及各种启动/停止脚本。

本章将涵盖以下主题：

+   解释引导过程

+   理解 GRUB 和 GRUB2

+   使用 GRUB

+   使用 GRUB2

# 解释引导过程

在 Linux 中，在启动过程中，会在硬盘上查找引导扇区。一旦找到引导扇区，它会搜索引导加载程序。引导加载程序然后加载引导管理器。在 Linux 中，这通常是 GRUB 或 GRUB2。在这个阶段之后，用户会看到一个引导菜单。最后，用户有机会选择要加载的操作系统或编辑现有条目。可用的选项通常是不同版本的 Linux 内核。有时，它可能是完全不同的 Linux 发行版。然而，在混合环境中，你可能会接触到另一个操作系统，比如 Microsoft Windows。

用户选择 Linux 内核后，根据 Linux 发行版的不同，会启动一个名为 `init` 的单个进程，它代表*初始化*。`init` 通常被称为*System V init* 或 SysV，因为 System V 是第一个商业 Unix 操作系统。大多数早期的 Linux 发行版与 System V 操作系统相同。用于管理 Linux 发行版的另一个守护进程称为 `systemd`，代表 System Management Daemon。以下是我们刚刚讨论的过程的简单流程：

*引导扇区 > 引导加载程序 > 引导菜单 => 操作系统加载*

在 Linux 中，你可能会遇到术语**守护进程**。请放心，这只是指一个进程。

在我们深入之前，让我们记住 `init` 和 `systemd` 之间最大的区别之一：`init` 逐个启动脚本，而 `systemd` 同时并行启动多个脚本。话虽如此，在使用 `init` 的 CentOS 5 系统上，以下是 `pstree` 命令的输出：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00041.gif)

从前面的输出中，我们可以看到所有起源于 `init` 的进程；因此，它们被视为子进程。

注意：出于简洁起见，一些输出已在整个章节中被省略。

我们还可以利用 `ps` 命令在我们的 CentOS 5 系统上查看 `init` 使用的实际进程号：

```
[philip@localhost Desktop]$ ps -aux
 Warning: bad syntax, perhaps a bogus '-'? See /usr/share/doc/procps-3.2.8/FAQ
 USER PID %CPU  %MEM  VSZ RSS TTY STAT START TIME COMMAND
 root  1   0.3  0.1  19364 1524 ? Ss 05:48   0:01 /sbin/init
 root  2   0.0  0.0   0    0    ? S  05:48   0:00 [kthreadd]
 root  3   0.0  0.0   0    0    ? S  05:48   0:00 [migration/0]
 root  4   0.0  0.0   0    0    ? S  05:48   0:00 [ksoftirqd/0]
 root  5   0.0  0.0   0    0    ? S  05:48   0:00 [migration/0]
 root  6   0.0  0.0   0    0    ? S  05:48   0:00 [watchdog/0]
 root  7   0.2  0.0   0    0    ? S  05:48   0:00 [events/0]
 root  8   0.0  0.0   0    0    ? S  05:48   0:00 [cgroup]
 root  9   0.0  0.0   0    0    ? S  05:48   0:00 [khelper]
 root  10  0.0  0.0   0    0    ? S  05:48   0:00 [netns]
 root  11  0.0  0.0   0    0    ? S  05:48   0:00 [async/mgr]
 root  12  0.0  0.0   0    0    ? S  05:48   0:00 [pm]
 root  13  0.0  0.0   0    0    ? S  05:48   0:00 [sync_supers]
 root  14  0.0  0.0   0    0    ? S  05:48   0:00 [bdi-default]
 root  15  0.0  0.0   0    0    ? S  05:48   0:00 [kintegrityd/]
 root  16  0.5  0.0   0    0    ? S  05:48   0:01 [kblockd/0]
```

从前面的输出中，我们可以看到第一个启动的进程是 `PID 1`，它确实是 `init` 进程。

以下是我们可以与 `ps` 命令一起使用的一些选项：

```
[philip@localhost Desktop]$ ps --help
 ********* simple selection ********* ********* selection by list *********
 -A all processes -C by command name
 -N negate selection -G by real group ID (supports names)
 -a all w/ tty except session leaders -U by real user ID (supports names)
 -d all except session leaders -g by session OR by effective group name
 -e all processes -p by process ID
 T all processes on this terminal -s processes in the sessions given
 a all w/ tty, including other users -t by tty
 g OBSOLETE -- DO NOT USE -u by effective user ID (supports names)
 r only running processes U processes for specified users
 x processes w/o controlling ttys t by tty
 *********** output format ********** *********** long options ***********
 -o,o user-defined -f full --Group --User --pid --cols --ppid
 -j,j job control s signal --group --user --sid --rows --info
 -O,O preloaded -o v virtual memory --cumulative --format --deselect
 -l,l long u user-oriented --sort --tty --forest --version
 -F extra full X registers --heading --no-heading --context
 ********* misc options *********
 -V,V show version L list format codes f ASCII art forest
 -m,m,-L,-T,H threads S children in sum -y change -l format
 -M,Z security data c true command name -c scheduling class
 -w,w wide output n numeric WCHAN,UID -H process hierarchy
 [philip@localhost Desktop]$ 
```

现在，让我们把注意力转向 `systemd`。我们将在我们的 Linux 系统上运行 `pstree` 命令：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00042.jpeg)

从前面的输出中，我们可以看到系统生成的所有其他进程。这些被称为子进程。

我们也可以在 CentOS 7 发行版上运行 `pstree` 命令，并看到类似的结果：

```
[philip@localhost ~]$ pstree
 systemd─┬─ModemManager───2*[{ModemManager}]
 ├─NetworkManager─┬─dhclient
 │ └─3*[{NetworkManager}]
 ├─VGAuthService
 ├─abrt-watch-log
 ├─abrtd
 ├─accounts-daemon───2*[{accounts-daemon}]
 ├─alsactl
 ├─anacron
 ├─at-spi-bus-laun─┬─dbus-daemon───{dbus-daemon}
 │ └─3*[{at-spi-bus-laun}]
 ├─at-spi2-registr───2*[{at-spi2-registr}]
 ├─atd
 ├─auditd─┬─audispd─┬─sedispatch
 │ │ └─{audispd}
 │ └─{auditd}
 ├─avahi-daemon───avahi-daemon
 ├─chronyd
 ├─colord───2*[{colord}]
 ├─crond
 ├─cupsd
 ├─2*[dbus-daemon───{dbus-daemon}]
 ├─dbus-launch
 ├─dconf-service───2*[{dconf-service}]
 ├─dnsmasq───dnsmasq
```

在几乎所有较新的 Linux 发行版中，`systemd` 已经取代了 `init`。

现在，让我们使用 `ps` 命令查看 Linux 系统上 `systemd` 使用的进程号：

```
root@ubuntu:/home/philip# ps -aux
 USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
 root 1 0.0 0.5 185620 4996 ? Ss Jun19 0:05 /lib/systemd/systemd --system --d
 root 2 0.0 0.0 0 0 ? S Jun19 0:00 [kthreadd]
 root 3 0.0 0.0 0 0 ? S Jun19 0:06 [ksoftirqd/0]
 root 5 0.0 0.0 0 0 ? S< Jun19 0:00 [kworker/0:0H]
 root 7 0.0 0.0 0 0 ? S Jun19 0:06 [rcu_sched]
 root 8 0.0 0.0 0 0 ? S Jun19 0:00 [rcu_bh]
 root 9 0.0 0.0 0 0 ? S Jun19 0:00 [migration/0]
 root 10 0.0 0.0 0 0 ? S Jun19 0:00 [watchdog/0]
 root 11 0.0 0.0 0 0 ? S Jun19 0:00 [kdevtmpfs]
 root 12 0.0 0.0 0 0 ? S< Jun19 0:00 [netns]
 root 13 0.0 0.0 0 0 ? S< Jun19 0:00 [perf]
 root 14 0.0 0.0 0 0 ? S Jun19 0:00 [khungtaskd]
 root 15 0.0 0.0 0 0 ? S< Jun19 0:00 [writeback]
 root 16 0.0 0.0 0 0 ? SN Jun19 0:00 [ksmd]
 root 17 0.0 0.0 0 0 ? SN Jun19 0:01 [khugepaged]
 root 18 0.0 0.0 0 0 ? S< Jun19 0:00 [crypto]
 root 19 0.0 0.0 0 0 ? S< Jun19 0:00 [kintegrityd]
 root 20 0.0 0.0 0 0 ? S< Jun19 0:00 [bioset]
 root 21 0.0 0.0 0 0 ? S< Jun19 0:00 [kblockd]
 root 22 0.0 0.0 0 0 ? S< Jun19 0:00 [ata_sff]
 root 23 0.0 0.0 0 0 ? S< Jun19 0:00 [md]
 root 24 0.0 0.0 0 0 ? S< Jun19 0:00 [devfreq_wq]

Some output is omitted for the sake of brevity.
```

从前面的输出中，我们可以清楚地看到系统确实被列为第一个启动的进程。

`systemd` 模拟 `init`。例如，我们可以使用 `service` 命令启动/停止守护进程。

现在，为了查看在 Linux 发行版上启动的进程，我们可以在我们的 CentOS 7 发行版上运行 `chkconfig` 命令：

```
[philip@localhost Desktop]$ chkconfig
 NetworkManager 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 abrt-ccpp 0:off 1:off 2:off 3:on 4:off 5:on 6:off
 abrtd 0:off 1:off 2:off 3:on 4:off 5:on 6:off
 acpid 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 atd 0:off 1:off 2:off 3:on 4:on 5:on 6:off
 auditd 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 blk-availability 0:off 1:on 2:on 3:on 4:on 5:on 6:off
 bluetooth 0:off 1:off 2:off 3:on 4:on 5:on 6:off
 cpuspeed 0:off 1:on 2:on 3:on 4:on 5:on 6:off
 crond 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 cups 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 dnsmasq 0:off 1:off 2:off 3:off 4:off 5:off 6:off
 firstboot 0:off 1:off 2:off 3:on 4:off 5:on 6:off
 haldaemon 0:off 1:off 2:off 3:on 4:on 5:on 6:off
 htcacheclean 0:off 1:off 2:off 3:off 4:off 5:off 6:off
 httpd 0:off 1:off 2:off 3:off 4:off 5:off 6:off
 ip6tables 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 iptables 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 irqbalance 0:off 1:off 2:off 3:on 4:on 5:on 6:off
 kdump 0:off 1:off 2:off 3:on 4:on 5:on 6:off
 lvm2-monitor 0:off 1:on 2:on 3:on 4:on 5:on 6:off
 mdmonitor 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 messagebus 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 netconsole 0:off 1:off 2:off 3:off 4:off 5:off 6:off
 netfs 0:off 1:off 2:off 3:on 4:on 5:on 6:off
 network 0:off 1:off 2:on 3:on 4:on 5:on 6:off
```

在前面的输出中，我们只显示使用`init`的守护程序。这对于运行原生`init`的系统非常有用，比如早期的 Linux 发行版。

以下是可以与使用`init`的旧 Linux 发行版一起传递的`chkconfig`命令的最常用选项：

| `--level levels` | 指定操作应适用于的运行级别。它以 0 到 6 的数字字符串给出。例如，`--level 35`指定运行级别 3 和 5。 |
| --- | --- |
| `--add name` | 此选项通过`chkconfig`添加一个新的服务进行管理。添加新服务时，`chkconfig`确保该服务在每个运行级别中都有启动或杀死条目。如果任何运行级别缺少这样的条目，`chkconfig`将根据`init`脚本中的默认值创建适当的条目。请注意，LSB 分隔的`INIT INFO`部分中的默认条目优先于`initscript`中的默认运行级别；如果存在任何`required-start`或`required-stop`条目，则脚本的启动和停止优先级将根据这些依赖关系进行调整。 |
| `--del name` | 服务从`chkconfig`管理中删除，并且`/etc/rc[0-6].d`中与之相关的任何符号链接都将被删除。请注意，将来安装此服务的软件包可能会运行`chkconfig --add`，这将重新添加这些链接。要禁用服务，请运行`chkconfig name off`。 |
| `--override name` | 如果服务名称的配置与在`/etc/chkconfig.d/name`中没有覆盖文件的情况下指定`--add`选项完全相同，并且现在`/etc/chkconfig.d/name`存在并且与基本`initscript`不同，这将更改服务名称的配置，使其遵循覆盖而不是基本配置。 |
| `--list name` | 此选项列出`chkconfig`知道的所有服务，以及它们在每个运行级别中是停止还是启动的。如果指定了名称，则只显示有关服务名称的信息。 |

为了查看在较新的 Linux 发行版中启动的守护程序，我们将使用`systemctl`命令：

```
[philip@localhost ~]$ systemctl
 add-requires hybrid-sleep reload-or-restart
 add-wants is-active reload-or-try-restart
 cancel is-enabled rescue
 cat is-failed reset-failed
 condreload isolate restart
 condrestart is-system-running set-default
 condstop kexec set-environment
 daemon-reexec kill set-property
 daemon-reload link show
 default list-dependencies show-environment
 delete list-jobs snapshot
 disable list-sockets start
 edit list-timers status
 emergency list-unit-files stop
 enable list-units suspend
 exit mask switch-root
 force-reload poweroff try-restart
 get-default preset unmask
 halt reboot unset-environment
 help reenable
 hibernate reload
 [philip@localhost ~]$ 
```

从前面的输出中，我们可以看到可以与`systemctl`命令一起传递的各种选项；我们将使用`systemctl`的`list-unit-files`选项：

```
[philip@localhost ~]$ systemctl list-unit-files
 UNIT FILE                           STATE
 proc-sys-fs-binfmt_misc.automount   static
 dev-hugepages.mount                 static
 dev-mqueue.mount                    static
 proc-fs-nfsd.mount                  static
 proc-sys-fs-binfmt_misc.mount       static
 sys-fs-fuse-connections.mount       static
 sys-kernel-config.mount             static
 sys-kernel-debug.mount              static
 tmp.mount                           disabled
 var-lib-nfs-rpc_pipefs.mount        static
 brandbot.path                       disabled
 cups.path                           enabled
 systemd-ask-password-console.path   static
 systemd-ask-password-plymouth.path  static
 systemd-ask-password-wall.path      static
```

为了简洁起见，省略了一些输出：

```
 umount.target                    static
 virt-guest-shutdown.target       static
 chrony-dnssrv@.timer             disabled
 fstrim.timer                     disabled
 mdadm-last-resort@.timer         static
 systemd-readahead-done.timer     indirect
 systemd-tmpfiles-clean.timer     static
392 unit files listed.
```

从前面的输出中，我们可以看到列出了 392 个单元。我们可以更具体地查找只启用/运行的服务：

```
[philip@localhost ~]$ systemctl list-unit-files | grep enabled
 cups.path                                   enabled
 abrt-ccpp.service                           enabled
 abrt-oops.service                           enabled
 abrt-vmcore.service                         enabled
 abrt-xorg.service                           enabled
 abrtd.service                               enabled
 accounts-daemon.service                     enabled
 atd.service                                 enabled
 auditd.service                              enabled
 autovt@.service                             enabled
 avahi-daemon.service                        enabled
 bluetooth.service                           enabled
 chronyd.service                             enabled
 crond.service                               enabled
 cups.service                                enabled
 dbus-org.bluez.service                      enabled
 dbus-org.fedoraproject.FirewallD1.service   enabled
 dbus-org.freedesktop.Avahi.service          enabled
 dbus-org.freedesktop.ModemManager1.service  enabled
 dbus-org.freedesktop.NetworkManager.service enabled
 dbus-org.freedesktop.nm-dispatcher.service  enabled
 display-manager.service                     enabled
 dmraid-activation.service                   enabled
 firewalld.service                           enabled
```

我们还可以使用`systemctl`命令查看守护程序的状态、守护程序被执行的目录以及守护程序的**进程 ID**（**PID**）。我们将使用`status`选项：

```
[philip@localhost ~]$ systemctl status sshd.service
 ● sshd.service - OpenSSH server daemon
 Loaded: loaded (/usr/lib/systemd/system/sshd.service; enabled; vendor preset: enabled)
 Active: active (running) since Wed 2018-06-20 09:35:31 PDT; 1h 43min ago
 Docs: man:sshd(8)
 man:sshd_config(5)
 Main PID: 1072 (sshd)
 CGroup: /system.slice/sshd.service
 └─1072 /usr/sbin/sshd -D
 [philip@localhost ~]$ 
```

我们也可以使用`systemctl`命令停止、启动、重启、启用和禁用守护程序。假设我们想使用`systemctl`命令停止`ssd`服务。我们只需这样做：

```
[philip@localhost ~]$ systemctl stop sshd
```

现在，当我们在 CentOS 7 系统上按下*Enter*键时，我们将收到一个身份验证提示，因为我们正在尝试以标准用户身份停止`sshd`服务：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00043.jpeg)

`sshd`被认为是一个系统服务。此外，在`systemd`的上下文中，一个单元是一个服务，反之亦然。

现在我们将输入 root 密码：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00044.jpeg)

现在`sshd`服务已经停止：

```
[philip@localhost ~]$ systemctl stop sshd
 [philip@localhost ~]$
```

现在让我们重新检查`sshd`服务的状态，以确认它确实已经停止，使用`systemctl`命令：

```
[philip@localhost ~]$ systemctl status sshd.service
 ● sshd.service - OpenSSH server daemon
 Loaded: loaded (/usr/lib/systemd/system/sshd.service; enabled; vendor preset: enabled)
 Active: inactive (dead) since Wed 2018-06-20 11:20:16 PDT; 21min ago
 Docs: man:sshd(8)
 man:sshd_config(5)
 Main PID: 1072 (code=exited, status=0/SUCCESS)
 [philip@localhost ~]$ 
```

从前面的代码中，我们可以得出`sshd`服务已经停止。

# DMESG

现在，当系统启动时，屏幕上会快速显示与我们的系统各个方面相关的许多消息，从硬件到服务。在故障排除时，能够查看这些消息将非常有用。收集尽可能多的信息以帮助故障排除总是很有用。

我们还可以利用另一个强大的命令，即`dmesg`命令：

```
philip@ubuntu:~$ dmesg
 [ 0.000000] Initializing cgroup subsys cpuset
 [ 0.000000] Initializing cgroup subsys cpu
 [ 0.000000] Initializing cgroup subsys cpuacct
 [ 0.000000] Linux version 4.4.0-128-generic (buildd@lcy01-amd64-019) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.9) ) #154-Ubuntu SMP Fri May 25 14:15:18 UTC 2018 (Ubuntu 4.4.0-128.154-generic 4.4.131)
 [ 0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-4.4.0-128-generic root=UUID=adb5d090-3400-4411-aee2-dd871c39db38 ro find_preseed=/preseed.cfg auto noprompt priority=critical locale=en_US quiet
```

为了简洁起见，省略了一些输出：

```
[ 13.001702] audit: type=1400 audit(1529517046.911:8): apparmor="STATUS" operation="profile_load" profile="unconfined" name="/usr/bin/evince" pid=645 comm="apparmor_parser"
 [ 19.155619] e1000: ens33 NIC Link is Up 1000 Mbps Full Duplex, Flow Control: None
 [ 19.156584] IPv6: ADDRCONF(NETDEV_CHANGE): ens33: link becomes ready
 [ 105.095992] do_trap: 33 callbacks suppressed
 [ 105.095996] traps: pool[2056] trap int3 ip:7f778e83c9eb sp:7f776b1eb6f0 error:0
 philip@ubuntu:~$
```

从前面的输出中，我们可以看到各种信息，包括 CPU 检测、PCI 驱动程序和以太网等。

# GRUB 和 GRUB2

现在，我们将转变方向，讨论引导管理器的工作是呈现引导菜单，用户可以从中选择要加载或编辑的操作系统/ Linux 内核。首先，我们将重点放在 GRUB 上，然后转到 GRUB2。

# GRUB

GRUB 代表**Grand Unified Bootloader**。GRUB 主要用于引导 Linux 发行版。但是，GRUB 可以与其他引导加载程序一起使用。一个常见的用例是与 Microsoft 操作系统双引导，它通过将控制权移交给 Windows 引导加载程序来实现这一点。

GRUB 使用`/boot/grub/grub.conf`文件。有时您会看到`/boot/grub/menu.lst`，但是这个文件只是`/boot/grub/grub.conf`的符号链接。使用 CentOS 6.5 发行版，运行以下命令：

```
[root@localhost ~]# ls -l /boot/grub
 total 274
 -rw-r--r--. 1 root root 63 Jun 20 01:47    device.map
 -rw-r--r--. 1 root root 13380 Jun 20 01:47 e2fs_stage1_5
 -rw-r--r--. 1 root root 12620 Jun 20 01:47 fat_stage1_5
 -rw-r--r--. 1 root root 11748 Jun 20 01:47 ffs_stage1_5
 -rw-------. 1 root root 769 Jun 20 01:48   grub.conf
 -rw-r--r--. 1 root root 11756 Jun 20 01:47 iso9660_stage1_5
 -rw-r--r--. 1 root root 13268 Jun 20 01:47 jfs_stage1_5
 lrwxrwxrwx. 1 root root 11 Jun 20 01:47    menu.lst -> ./grub.conf
 -rw-r--r--. 1 root root 11956 Jun 20 01:47 minix_stage1_5
 -rw-r--r--. 1 root root 14412 Jun 20 01:47 reiserfs_stage1_5
 -rw-r--r--. 1 root root 1341 Nov 14 2010   splash.xpm.gz
 -rw-r--r--. 1 root root 512 Jun 20 01:47    stage1
 -rw-r--r--. 1 root root 126100 Jun 20 01:47 stage2
 -rw-r--r--. 1 root root 12024 Jun 20 01:47  ufs2_stage1_5
 -rw-r--r--. 1 root root 11364 Jun 20 01:47  vstafs_stage1_5
 -rw-r--r--. 1 root root 13964 Jun 20 01:47  xfs_stage1_5
 [root@localhost ~]#
```

从前面的输出中，我们可以看到`/boot/grub/grub.conf`，还有符号链接`/boot/grub/menu.lst`。

我们可以查看实际的`/boot/grub/grub.conf`文件：

```
[root@localhost ~]# cat /boot/grub/grub.conf
 # grub.conf generated by anaconda
 #
 # Note that you do not have to rerun grub after making changes to this file
 # NOTICE: You have a /boot partition. This means that
 # all kernel and initrd paths are relative to /boot/, eg.
 # root (hd0,0)
 # kernel /vmlinuz-version ro root=/dev/sda2
 # initrd /initrd-[generic-]version.img
 #boot=/dev/sda
 default=0
 timeout=5
 splashimage=(hd0,0)/grub/splash.xpm.gz
 hiddenmenu
 title CentOS (2.6.32-431.el6.x86_64)
 root (hd0,0)
 kernel /vmlinuz-2.6.32-431.el6.x86_64 ro root=UUID=05527d71-25b6-4931-a3bb-8fe505f3fa64 rd_NO_LUKS rd_NO_LVM LANG=en_US.UTF-8 rd_NO_MD SYSFONT=latarcyrheb-sun16 crashkernel=auto KEYBOARDTYPE=pc KEYTABLE=us rd_NO_DM rhgb quiet
 initrd /initramfs-2.6.32-431.el6.x86_64.img
 [root@localhost ~]#
```

从前面的输出中，常见的选项将是以下内容。`default=0`表示它是菜单中要启动的第一个条目。`timeout=5`给出了菜单显示的秒数（在这种情况下为 5），在加载 Linux 内核或 Windows 引导加载程序从 GRUB 手中接管之前。`splashimage=(hd0,0)/grub/splash.xpm.gz`是引导菜单的背景图像。`root (hd0,0)`指的是第一个硬盘和第一个硬盘上的第一个分区。

# GRUB2

GRUB2 在菜单呈现方式上使用了更加程序化的方法。乍一看，GRUB2 可能看起来令人生畏，但请放心，它并不像看起来那么复杂。语法类似于编程语言，有很多*if...then*语句。以下是 CentOS 7 系统上`/boot/grub/grub.cfg`的样子：

```
[root@localhost ~]# cat /boot/grub2/grub.cfg
 #
 # DO NOT EDIT THIS FILE
 #
 # It is automatically generated by grub2-mkconfig using templates
 # from /etc/grub.d and settings from /etc/default/grub
 #
### BEGIN /etc/grub.d/00_header ###
 set pager=1
if [ -s $prefix/grubenv ]; then
 load_env
 fi
 if [ "${next_entry}" ] ; then
 set default="${next_entry}"
 set next_entry=
```

```
 save_env next_entry
 set boot_once=true
 else
 set default="${saved_entry}"
 fi
```

出于简洁起见，以下部分输出被省略。以下显示了`/boot/grub/grub.cfg`的最后部分：

```
### BEGIN /etc/grub.d/10_linux ###
 menuentry 'CentOS Linux (3.10.0-693.el7.x86_64) 7 (Core)' --class centos --class gnu-linux --class gnu --class os --unrestricted $menuentry_id_option 'gnulinux-3.10.0-693.el7.x86_64-advanced-16e2de7b-b679-4a12-888e-55081af4dad8' {
 load_video
 set gfxpayload=keep
 insmod gzio
 insmod part_msdos
 insmod xfs
 set root='hd0,msdos1'
 if [ x$feature_platform_search_hint = xy ]; then
 search --no-floppy --fs-uuid --set=root --hint-bios=hd0,msdos1 --hint-efi=hd0,msdos1 --hint-baremetal=ahci0,msdos1 --hint='hd0,msdos1' 40c7c63f-1c93-438a-971a-5331e265419b
 else
 search --no-floppy --fs-uuid --set=root 40c7c63f-1c93-438a-971a-5331e265419b
 fi
 linux16 /vmlinuz-3.10.0-693.el7.x86_64 root=UUID=16e2de7b-b679-4a12-888e-55081af4dad8 ro crashkernel=auto rhgb quiet LANG=en_US.UTF-8
 initrd16 /initramfs-3.10.0-693.el7.x86_64.img
 }
 ### END /etc/grub.d/10_linux ###
```

因此，要解释`/boot/grub/grub.cfg`文件，我们要查找以`menuentry`开头的行。这些行开始了操作系统的实际菜单条目，例如 Linux 发行版或 Windows 操作系统。

条目被包含在大括号{}中。

# 与 GRUB 一起工作

现在我们将与 GRUB 进行交互。我们将添加一个自定义引导条目。这将在重新启动时呈现。我们将使用`vi`命令，它将在可视编辑器中打开`/boot/grub/grub.conf`：

在使用 GRUB 之前，始终备份您的`/boot/grub/grub.conf`。

```
[root@localhost ~]# cat /boot/grub/grub.conf
 # grub.conf generated by anaconda
 #
 # Note that you do not have to rerun grub after making changes to this file
 # NOTICE: You have a /boot partition. This means that
 # all kernel and initrd paths are relative to /boot/, eg.
 # root (hd0,0)
 # kernel /vmlinuz-version ro root=/dev/sda2
 # initrd /initrd-[generic-]version.img
 #boot=/dev/sda
 default=0
 timeout=5
 splashimage=(hd0,0)/grub/splash.xpm.gz
 hiddenmenu
 title CentOS (2.6.32-431.el6.x86_64)
 root (hd0,0)
 kernel /vmlinuz-2.6.32-431.el6.x86_64 ro root=UUID=05527d71-25b6-4931-a3bb-8fe505f3fa64 rd_NO_LUKS rd_NO_LVM LANG=en_US.UTF-8 rd_NO_MD SYSFONT=latarcyrheb-sun16 crashkernel=auto KEYBOARDTYPE=pc KEYTABLE=us rd_NO_DM rhgb quiet
 initrd /initramfs-2.6.32-431.el6.x86_64.img
 [root@localhost ~]# vi /boot/grub/grub.conf
```

现在我们在`vi`中。我们将按下键盘上的*I*进入插入模式，使用下箭头键向下滚动，直到达到最后一行，然后按*Enter*进入新行：

```
# grub.conf generated by anaconda
 #
 # Note that you do not have to rerun grub after making changes to this file
 # NOTICE: You have a /boot partition. This means that
 # all kernel and initrd paths are relative to /boot/, eg.
 # root (hd0,0)
 # kernel /vmlinuz-version ro root=/dev/sda2
 # initrd /initrd-[generic-]version.img
 #boot=/dev/sda
 default=0
 timeout=5
 splashimage=(hd0,0)/grub/splash.xpm.gz
 hiddenmenu
 title CentOS (2.6.32-431.el6.x86_64)
 root (hd0,0)
 kernel /vmlinuz-2.6.32-431.el6.x86_64 ro root=UUID=05527d71-25b6-4931-a3bb-8fe505f3fa64 rd_NO_LUKS rd_NO_LVM LANG=en_US.UTF-8 rd_NO_MD SYSFONT=latarcyrheb-sun16 crashkernel=auto KEYBOARDTYPE=pc KEYTABLE=us rd_NO_DM rhgb quiet
 initrd /initramfs-2.6.32-431.el6.x86_64.img
~
 ~
 ~
 -- INSERT --
```

接下来，我们将使用以下关键字启动我们的条目：`title`、`root`、`kernel`和`initrd`。我们将插入我们自己的自定义值，如下所示：

```
# grub.conf generated by anaconda
 #
 # Note that you do not have to rerun grub after making changes to this file
 # NOTICE: You have a /boot partition. This means that
 # all kernel and initrd paths are relative to /boot/, eg.
 # root (hd0,0)
 # kernel /vmlinuz-version ro root=/dev/sda2
 # initrd /initrd-[generic-]version.img
 #boot=/dev/sda
 default=0
 timeout=5
 splashimage=(hd0,0)/grub/splash.xpm.gz
 hiddenmenu
 title CentOS (2.6.32-431.el6.x86_64)
 root (hd0,0)
 kernel /vmlinuz-2.6.32-431.el6.x86_64 ro root=UUID=05527d71-25b6-4931-a3bb-8fe505f3fa64 rd_NO_LUKS rd_NO_LVM LANG=en_US.UTF-8 rd_NO_MD SYSFONT=latarcyrheb-sun16 crashkernel=auto KEYBOARDTYPE=pc KEYTABLE=us rd_NO_DM rhgb quiet
 initrd /initramfs-2.6.32-431.el6.x86_64.img
 title CompTIA Linux+ (Our.Custom.Entry)
 root (hd0,0)
 kernel /vmlinuz-2.6.32-431.el6.x86 ro
 initrd /initramfs-2.6.32-431.el6.x86_64.img
 -- INSERT --
```

现在我们将保存并退出`vi`。我们使用`:wq`来保存我们的更改并退出`vi`：

```
title CompTIA Linux+ (Our.Custom.Entry)
 root (hd0,0)
 kernel /vmlinuz-2.6.32-431.el6.x86 ro
 initrd /initramfs-2.6.32-431.el6.x86_64.img
 :wq
```

根据前面的输出，这是我们自定义条目的分解：

+   `title`定义了我们的自定义引导条目。

+   `root (hd0,0)` 告诉它搜索第一个硬盘和第一个硬盘上的第一个分区。

+   `kernel /vmlinuz-2.6.32-431.el6.x86 ro` 告诉 GRUB 查找 Linux 内核的位置。在这种情况下，它是`vmlinuz-2.6.32-431.el6.x86 ro`（`ro`表示以只读方式加载内核）。

+   `inidrd /initramfs-2.6.32-431.el6.x86_64.img`指定要使用的初始 RAM 磁盘文件（这有助于系统启动）。

最后一步是重新启动我们的 CentOS 系统，并显示 GRUB 引导菜单：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00045.gif)

从前面的输出中，我们可以看到我们的新自定义引导条目显示在 GRUB 中，这很棒。我们可以实时交互，就在 GRUB 菜单上。假设我们想要在这些条目中添加或删除选项。我们只需按下*E*键，如下所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00046.gif)

现在我们可以再次按*E*键编辑该项。假设我们想指定根文件系统位于`/dev/`；我们可以按照以下截图所示进行操作：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00047.gif)

现在，我们可以按*Enter*键保存我们的更改，按*Esc*键返回到上一个屏幕；我们将看到新添加的选项：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00048.gif)

从前面的输出中，我们可以看到在 GRUB 引导菜单中实时工作以及如何在 GRUB 中添加自定义引导项是多么容易。

在 GRUB 中，第一个硬盘和第一个分区被标识为`(hd0, 0)`，而在 Linux shell 中，第一个硬盘和第一个分区被标识为`(sda1)`。

# 使用 GRUB2

我们以与 GRUB 略有不同的方式在 GRUB2 中添加自定义引导项。在 GRUB2 中，我们不是编辑实际的`/boot/grub/grub.cfg`，而是使用`/etc/default/grub`和`/etc/grub.d`。让我们列出`/etc/grub.d`以查看所有可用的文件：

```
philip@ubuntu:~$ ls -l /etc/grub.d/
 total 76
 -rwxr-xr-x 1 root root 9791 Apr 15 2016 00_header
 -rwxr-xr-x 1 root root 6258 Mar 15 2016 05_debian_theme
 -rwxr-xr-x 1 root root 12261 Apr 15 2016 10_linux
 -rwxr-xr-x 1 root root 11082 Apr 15 2016 20_linux_xen
 -rwxr-xr-x 1 root root 1992 Jan 28 2016 20_memtest86+
 -rwxr-xr-x 1 root root 11692 Apr 15 2016 30_os-prober
 -rwxr-xr-x 1 root root 1418 Apr 15 2016 30_uefi-firmware
 -rwxr-xr-x 1 root root 214 Apr 15 2016 40_custom
 -rwxr-xr-x 1 root root 216 Apr 15 2016 41_custom
 -rw-r--r-- 1 root root 483 Apr 15 2016 README
 philip@ubuntu:~$
```

在使用 GRUB2 之前，始终备份您的`/boot/grub/grub.cfg`。

从前面的输出中，我们可以看到许多文件。它们的名称以数字开头，并且数字是按顺序读取的。假设我们想在 GRUB2 中添加一个自定义的引导项。我们将创建一个自定义项并命名为`/etc/grub/40_custom`。我们将在`vi`中看到以下代码：

```
#!/bin/sh
 exec tail -n +3 $0
 # This file provides an easy way to add custom menu entries. Simply type the
 # menu entries you want to add after this comment. Be careful not to change
 # the 'exec tail' line above.
 echo "Test Entry"
 cat << EOF
 menuentry "CompTIA_LINUX+" {
 set root ='hd0,0'
}
 EOF
```

从前面的输出中，我们可以看到语法与编程有些相似。在 GRUB2 中，它是一种完整的编程语言。下一步是保存我们的更改，然后运行`grub-mkconfig`（名称暗示我们在谈论旧版 GRUB，但实际上是指 GRUB2）。这取决于 Linux 发行版。在 CentOS 7 中，您将看到以`grub2`开头的命令：

```
root@ubuntu:/home/philip# grub-mkconfig
 Generating grub configuration file ...
 #
 # DO NOT EDIT THIS FILE
 #
 # It is automatically generated by grub-mkconfig using templates
 # from /etc/grub.d and settings from /etc/default/grub
 #
### BEGIN /etc/grub.d/00_header ###
 if [ -s $prefix/grubenv ]; then
 set have_grubenv=true
 load_env
 fi
```

出于简洁起见，以下部分输出被省略：

```
### BEGIN /etc/grub.d/40_custom ###
 # This file provides an easy way to add custom menu entries. Simply type the
 # menu entries you want to add after this comment. Be careful not to change
 # the 'exec tail' line above.
 echo "Test Entry"
 cat << EOF
 menuentry "CompTIA_LINUX+" {
 set root ='hd0,0'
}
 EOF
```

当我们运行此命令时，`grub-mkconfig`命令会找到自定义项。然后生成一个新的引导菜单。在系统下一次重启时，我们将看到新的引导菜单。我们还可以更改`/etc/default/grub`中的选项，包括默认操作系统、计时器等。以下是`/etc/default/grub`的内容：

```
root@ubuntu:/home/philip# cat /etc/default/grub
 # If you change this file, run 'update-grub' afterwards to update
 # /boot/grub/grub.cfg.
 # For full documentation of the options in this file, see:
 # info -f grub -n 'Simple configuration'
GRUB_DEFAULT=0
 GRUB_HIDDEN_TIMEOUT=0
 GRUB_HIDDEN_TIMEOUT_QUIET=true
 GRUB_TIMEOUT=10
 GRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo Debian`
 GRUB_CMDLINE_LINUX_DEFAULT="quiet"
 GRUB_CMDLINE_LINUX="find_preseed=/preseed.cfg auto noprompt priority=critical locale=en_US"
```

根据前面的输出，计时器值设置为`10`。还要注意默认值为`0`。在配置文件中继续向下，我们看到以下代码：

```
# Uncomment to enable BadRAM filtering, modify to suit your needs
# This works with Linux (no patch required) and with any kernel that obtains
# the memory map information from GRUB (GNU Mach, kernel of FreeBSD ...)
#GRUB_BADRAM="0x01234567,0xfefefefe,0x89abcdef,0xefefefef"
# Uncomment to disable graphical terminal (grub-pc only)
#GRUB_TERMINAL=console
# The resolution used on graphical terminal
# note that you can use only modes which your graphic card supports via VBE
# you can see them in real GRUB with the command `vbeinfo'
#GRUB_GFXMODE=640x480
# Uncomment if you don't want GRUB to pass "root=UUID=xxx" parameter to Linux
#GRUB_DISABLE_LINUX_UUID=true
# Uncomment to disable generation of recovery mode menu entries
#GRUB_DISABLE_RECOVERY="true"
# Uncomment to get a beep at grub start
#GRUB_INIT_TUNE="480 440 1"
```

现在，让我们重新启动 Ubuntu 系统并查看 GRUB2 引导菜单：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00049.jpeg)

从前面的截图中，我们现在可以在 GRUB2 中看到我们的自定义菜单选项。我们甚至可以通过按 E 键滚动浏览条目并编辑它们。

在 GRUB2 中，第一个硬盘从`0`开始，第一个分区从`1`开始，与旧版 GRUB 不同。

# 总结

在本章中，我们看了一下引导过程。然后讨论了`init`和`systemd`。我们使用了`pstree`命令并看到了加载的第一个进程。此外，我们使用了`ps`命令来识别进程号。然后，我们查看了通常会在屏幕上滚动的引导消息，使用`dmesg`命令。显示的消息为我们提供了关于引导时加载的内容的提示。此外，我们可以使用显示的消息来帮助我们进行故障排除。接下来，我们讨论了 GRUB 和 GRUB2，查看了 GRUB 的结构，特别是`/boot/grub/grub/conf`。我们看了如何在 GRUB 中添加自定义菜单项。我们看了如何在引导菜单中实时与 GRUB 交互。之后，我们看了 GRUB2，重点是`/boot/grub/grub.cfg`的结构。此外，我们还看了在 GRUB2 配置中起作用的其他位置：`/etc/default/grub/`和`/etc/grub.d/`目录。然后，我们使用`/etc/grub.d/40_custom`文件在`/etc/grub.d/`中添加了自定义菜单项。之后，我们使用`grub-mkconfig`（Ubuntu 发行版）更新了 GRUB2。最后，我们实时与 GRUB2 引导菜单进行了交互。

在下一章中，我们将专注于运行级别和引导目标。这些是我们作为 Linux 工程师需要充分理解的关键主题。我们将使用各种方法在命令行上管理系统。我们将涵盖`runlevel`、`init`和`systemctl`等命令。在下一章中，有很多有用的信息可以获得。了解运行级别的工作原理至关重要。此外，还有引导目标的概念。在大多数较新的发行版中，您将接触到引导目标。这将帮助您在命令行环境中管理 Linux 系统。在下一章中，您的技能将继续增长。这将进一步使您更接近成功，获得认证。

# 问题

1.  引导加载程序位于硬盘的哪个位置？

A. 引导扇区

B. 次要分区

C. 逻辑分区

D. 以上都不是

1.  哪个是第一个商业 Unix 操作系统？

A. systemd

B. upstart

C. System X

D. System V

1.  哪个命令显示从父进程开始的进程，然后是子进程？

A. `dnf`

B. `systemctl`

C. ` pstree`

D. `ps`

1.  在 CentOS 5 系统上启动的第一个进程是什么？

A. `systemd`

B. `init`

C. `kickstart`

D. `upstart`

1.  在 Linux 内核的较新版本中，`init`被什么取代了？

A. `telinit`

B. `systemctl`

C. `systemb`

D. `systemd`

1.  哪个命令列出了在 CentOS 7 发行版上运行的进程？

A. `systemd list-unit-files`

B. `systemX list-unit-files`

C. `systemctl list-unit-files`

D. `service status unit-files`

1.  哪个命令列出了系统引导时加载的硬件驱动程序？

A. `cat /var/log/messages`

B. `tail –f /var/log/startup`

C. `head /var/messages`

D. `dmesg`

1.  在 CentOS 5 发行版中，GRUB 配置文件位于哪个目录？

A. `/boot/`

B. `/grub/boot/`

C. `/boot/grub/`

D. `/grub/grub-config/`

1.  在 GRUB 中添加自定义菜单项时，是什么启动了自定义菜单项？

A. `title`

B. `menu entry`

C. `操作系统`

D. `default =0`

1.  在 GRUB2 中添加自定义菜单项时，是什么启动了自定义菜单项？

A. `title`

B. `root = /vmlinuz/`

C. `menuentry`

D. `menu entry`

1.  哪个字母键用于在 GRUB 引导菜单中实时编辑条目？

A. *C*

B. *E*

C. *B*

D. *A*

# 进一步阅读

+   您可以在[`www.centos.org.`](https://www.centos.org)获取有关 CentOS 发行版的更多信息，如安装、配置最佳实践等。

+   以下网站为您提供了许多有用的提示和 Linux 社区用户的最佳实践，特别是适用于 Debian 发行版，如 Ubuntu：[`askubuntu.com.`](https://askubuntu.com)

+   以下链接为您提供了一般信息，涉及适用于 CentOS 和 Ubuntu 的各种命令。您可以在那里发布您的问题，其他社区成员将会回答：[`www.linuxquestions.org.`](https://www.linuxquestions.org)


# 第三章：更改运行级别和引导目标

在上一章中，我们关注了引导过程。之后，重点转移到了 Linux 发行版中可用的各种引导管理器。特别是，我们使用了迄今为止最流行的引导管理器 GRUB 和 GRUB2。我们查看了它们各自的配置文件，重点关注了计时器、默认引导条目以及在 GRUB/GRUB2 引导菜单中传递参数。最后，我们创建了单独的示例，以便为 GRUB 和 GRUB2 的引导菜单添加一个自定义引导条目。本章重点介绍了运行级别和引导目标的概念，以及 Linux 发行版中可用的运行级别和引导目标的类型，以及运行级别和引导目标之间的区别。我们还将看看如何在 CLI 中使用运行级别和引导目标。

在本章中，我们将涵盖以下主题：

+   运行级别简介

+   引导目标简介

+   使用运行级别

+   使用引导目标

# 运行级别简介

运行级别的概念可以追溯到 SysV 时代，每个运行级别都有一个目的。不同的任务需要在系统引导时运行各种守护进程。这在服务器环境中特别有用，我们试图尽量减少服务器的开销。通常我们会为服务器分配一个角色。这样做可以减少在给定服务器上需要安装的应用程序数量。例如，Web 服务器通常会有一个用于向用户提供内容的应用程序和一个用于查找的数据库。

另一个典型的用例是打印服务器。这通常只用于管理打印作业。也就是说，从运行级别的角度来看，我们通常会减少在给定服务器内运行的服务数量。对于那些来自 Windows 背景的人来说，想想安全模式。通常，我们会进入安全模式以最小化加载的程序和驱动程序。运行级别进一步扩展了这个想法，我们可以告诉 Linux 发行版我们想要在给定的运行级别中启动/停止什么。有趣的是，我们在 Linux 发行版中可以使用多个运行级别。您会在使用 SysV init 的 Linux 发行版中找到运行级别。

看一下下表：

| **运行级别 ** | **0  ** | ** 1   ** | **2** | **3** | **4** | **5** | **6** |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **守护进程** | **关闭** | **开启** | **开启** | **开启** | **开启** | **开启** | **关闭** |

根据上表，每当一个守护进程处于“关闭”状态时，这意味着该守护进程在该运行级别中不会运行。同样，每当一个守护进程处于“开启”状态时，它被配置为在特定的运行级别中运行。

守护进程和服务通常可以互换使用。

运行级别通常具有各种启动/停止脚本，每当在支持`init`的 Linux 发行版中选择运行级别时都会运行这些脚本。我们可以查看 CentOS 6.5 系统，看看使用了哪个运行级别。我们将查看`/etc/inittab`配置文件：

```
[philip@localhost Desktop]$ cat /etc/inittab
 # inittab is only used by upstart for the default runlevel.
 #
 # ADDING OTHER CONFIGURATION HERE WILL HAVE NO EFFECT ON YOUR SYSTEM.
 #
 # System initialization is started by /etc/init/rcS.conf
 #
 # Individual runlevels are started by /etc/init/rc.conf
 #
```

```
 # Ctrl-Alt-Delete is handled by /etc/init/control-alt-delete.conf
 #
 # Terminal gettys are handled by /etc/init/tty.conf and /etc/init/serial.conf,
 # with configuration in /etc/sysconfig/init.
 #
 # For information on how to write upstart event handlers, or how
 # upstart works, see init(5), init(8), and initctl(8).
 #
 # Default runlevel. The runlevels used are:
 # 0 - halt (Do NOT set initdefault to this)
 # 1 - Single user mode
 # 2 - Multiuser, without NFS (The same as 3, if you do not have networking)
 # 3 - Full multiuser mode
 # 4 - unused
 # 5 - X11
 # 6 - reboot (Do NOT set initdefault to this)
 #
 id:5:initdefault:
 [philip@localhost Desktop]$
```

从前面的输出中，CentOS 发行版支持七个运行级别。特别是，运行级别 5 是向用户呈现图形用户界面的运行级别。

其他流行的运行级别是`0`用于停止或关闭系统，`1`用于单用户模式（通常用于恢复）和`6`用于重新启动系统。上面写着`id:5:initdefault:`的那一行告诉 CentOS 在系统引导时使用哪个运行级别。

现在让我们看看支持`init`的 Ubuntu 6.06 发行版上的`/etc/inittab`：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00050.jpeg)

从前面的输出中，我们可以关注一下这一行，上面写着`id:2:initdefault:`。`2`告诉 Linux 内核在系统引导时使用运行级别 2。默认情况下，Ubuntu 6.06 使用运行级别 2。实际上，在 Ubuntu 中，运行级别 2-5 被认为是多用户的；在运行级别 2-5 之间没有区别。

在 CentOS 6.5 中，我们可以使用`chkconfig`命令来检查各种运行级别中运行的守护进程；这将给出各种服务的简要摘要：

```
[philip@localhost Desktop]$ chkconfig
 NetworkManager 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 abrt-ccpp 0:off 1:off 2:off 3:on 4:off 5:on 6:off
 abrtd 0:off 1:off 2:off 3:on 4:off 5:on 6:off
 acpid 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 atd 0:off 1:off 2:off 3:on 4:on 5:on 6:off
 auditd 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 blk-availability 0:off 1:on 2:on 3:on 4:on 5:on 6:off
 bluetooth 0:off 1:off 2:off 3:on 4:on 5:on 6:off
 cpuspeed 0:off 1:on 2:on 3:on 4:on 5:on 6:off
 crond 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 cups 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 dnsmasq 0:off 1:off 2:off 3:off 4:off 5:off 6:off
 firstboot 0:off 1:off 2:off 3:on 4:off 5:on 6:off
 haldaemon 0:off 1:off 2:off 3:on 4:on 5:on 6:off
 htcacheclean 0:off 1:off 2:off 3:off 4:off 5:off 6:off
 httpd 0:off 1:off 2:off 3:off 4:off 5:off 6:off
 ip6tables 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 iptables 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 irqbalance 0:off 1:off 2:off 3:on 4:on 5:on 6:off
 kdump 0:off 1:off 2:off 3:on 4:on 5:on 6:off
 lvm2-monitor 0:off 1:on 2:on 3:on 4:on 5:on 6:off
 mdmonitor 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 messagebus 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 netconsole 0:off 1:off 2:off 3:off 4:off 5:off 6:off
 netfs 0:off 1:off 2:off 3:on 4:on 5:on 6:off
 network 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 ntpd 0:off 1:off 2:off 3:off 4:off 5:off 6:off
 ntpdate 0:off 1:off 2:off 3:off 4:off 5:off 6:off
 portreserve 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 postfix 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 psacct 0:off 1:off 2:off 3:off 4:off 5:off 6:off
 quota_nld 0:off 1:off 2:off 3:off 4:off 5:off 6:off
 rdisc 0:off 1:off 2:off 3:off 4:off 5:off 6:off
 restorecond 0:off 1:off 2:off 3:off 4:off 5:off 6:off
 rngd 0:off 1:off 2:off 3:off 4:off 5:off 6:off
 rsyslog 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 saslauthd 0:off 1:off 2:off 3:off 4:off 5:off 6:off
 smartd 0:off 1:off 2:off 3:off 4:off 5:off 6:off
 snmpd 0:off 1:off 2:off 3:off 4:off 5:off 6:off
 snmptrapd 0:off 1:off 2:off 3:off 4:off 5:off 6:off
 spice-vdagentd 0:off 1:off 2:off 3:off 4:off 5:on 6:off
 sshd 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 sysstat 0:off 1:on 2:on 3:on 4:on 5:on 6:off
 udev-post 0:off 1:on 2:on 3:on 4:on 5:on 6:off
 vmware-tools 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 vmware-tools-thinprint 0:off 1:off 2:on 3:on 4:on 5:on 6:off
 wdaemon 0:off 1:off 2:off 3:off 4:off 5:off 6:off
 winbind 0:off 1:off 2:off 3:off 4:off 5:off 6:off
 wpa_supplicant 0:off 1:off 2:off 3:off 4:off 5:off 6:off
 [philip@localhost Desktop]$
```

从前面的输出中，我们可以看到各种服务。有些在多个运行级别中运行，而有些完全关闭。例如，网络服务；它设置为`0：关闭 1：关闭 2：开启 3：开启 4：开启 5：开启 6：关闭`。这告诉系统在运行级别 2-5 中启动网络服务，在运行级别 0-1 和 6 中关闭网络服务。大多数服务仅在运行级别 2-5 中运行。

我们可以查看`/etc/rc.d/`，看看各种脚本是如何设置的，以便启动/停止：

```
[philip@localhost Desktop]$ ls -l /etc/rc.d
 total 60
 drwxr-xr-x. 2 root root 4096 Jun 20 01:49 init.d
 -rwxr-xr-x. 1 root root 2617 Nov 22 2013 rc
 drwxr-xr-x. 2 root root 4096 Jun 20 01:49 rc0.d
 drwxr-xr-x. 2 root root 4096 Jun 20 01:49 rc1.d
 drwxr-xr-x. 2 root root 4096 Jun 20 01:49 rc2.d
 drwxr-xr-x. 2 root root 4096 Jun 20 01:49 rc3.d
 drwxr-xr-x. 2 root root 4096 Jun 20 01:49 rc4.d
 drwxr-xr-x. 2 root root 4096 Jun 20 01:49 rc5.d
 drwxr-xr-x. 2 root root 4096 Jun 20 01:49 rc6.d
 -rwxr-xr-x. 1 root root 220 Jun 20 01:48 rc.local
 -rwxr-xr-x. 1 root root 19688 Nov 22 2013 rc.sysinit
 [philip@localhost Desktop]$ 
```

根据前面的输出，每个相应运行级别（0-6）都有各自的目录。此外，我们甚至可以进一步深入文件系统层次结构并暴露子目录。让我们选择`/etc/rc.d/rc5.d`并暴露其内容：

```
[philip@localhost Desktop]$ ls -l /etc/rc.d/rc5.d/
 total 0
 lrwxrwxrwx. 1 root root 16 Jun 20 01:44 K01smartd -> ../init.d/smartd
 lrwxrwxrwx. 1 root root 17 Jun 20 01:44 K05wdaemon -> ../init.d/wdaemon
 lrwxrwxrwx. 1 root root 16 Jun 20 01:44 K10psacct -> ../init.d/psacct
 lrwxrwxrwx. 1 root root 19 Jun 20 01:41 K10saslauthd -> ../init.d/saslauthd
 lrwxrwxrwx. 1 root root 22 Jun 20 01:41 K15htcacheclean -> ../init.d/htcacheclean
 lrwxrwxrwx. 1 root root 15 Jun 20 01:41 K15httpd -> ../init.d/httpd
 lrwxrwxrwx. 1 root root 17 Jun 20 01:41 K50dnsmasq -> ../init.d/dnsmasq
 lrwxrwxrwx. 1 root root 20 Jun 20 01:40 K50netconsole -> ../init.d/netconsole
 lrwxrwxrwx. 1 root root 15 Jun 20 01:41 K50snmpd -> ../init.d/snmpd
 lrwxrwxrwx. 1 root root 19 Jun 20 01:41 K50snmptrapd -> ../init.d/snmptrapd
 lrwxrwxrwx. 1 root root 17 Jun 20 01:47 K73winbind -> ../init.d/winbind
 lrwxrwxrwx. 1 root root 14 Jun 20 01:41 K74ntpd -> ../init.d/ntpd
 lrwxrwxrwx. 1 root root 17 Jun 20 01:41 K75ntpdate -> ../init.d/ntpdate
 lrwxrwxrwx. 1 root root 19 Jun 20 01:44 K75quota_nld -> ../init.d/quota_nld
 lrwxrwxrwx. 1 root root 24 Jun 20 01:44 K84wpa_supplicant -> ../init.d/wpa_supplicant
 lrwxrwxrwx. 1 root root 21 Jun 20 01:40 K87restorecond -> ../init.d/restorecond
 lrwxrwxrwx. 1 root root 15 Jun 20 01:40 K89rdisc -> ../init.d/rdisc
 lrwxrwxrwx. 1 root root 14 Jun 20 01:44 K99rngd -> ../init.d/rngd
 lrwxrwxrwx. 1 root root 17 Jun 20 01:43 S01sysstat -> ../init.d/sysstat
 lrwxrwxrwx. 1 root root 22 Jun 20 01:43 S02lvm2-monitor -> ../init.d/lvm2-monitor
 lrwxrwxrwx. 1 root root 22 Jun 20 01:49 S03vmware-tools -> ../init.d/vmware-tools
 lrwxrwxrwx. 1 root root 19 Jun 20 01:41 S08ip6tables -> ../init.d/ip6tables
 lrwxrwxrwx. 1 root root 18 Jun 20 01:40 S08iptables -> ../init.d/iptables
 lrwxrwxrwx. 1 root root 17 Jun 20 01:40 S10network -> ../init.d/network
 lrwxrwxrwx. 1 root root 16 Jun 20 01:44 S11auditd -> ../init.d/auditd
 lrwxrwxrwx. 1 root root 21 Jun 20 01:38 S11portreserve -> ../init.d/portreserve
 lrwxrwxrwx. 1 root root 17 Jun 20 01:41 S12rsyslog -> ../init.d/rsyslog
 lrwxrwxrwx. 1 root root 18 Jun 20 01:44 S13cpuspeed -> ../init.d/cpuspeed
```

在整个章节中，出于简洁起见，一些输出被省略了。

从前面的输出中，运行级别 5 有许多守护进程。我们通过使用命名约定来识别守护进程。以`K`开头的文件用于终止/停止进程，以`S`开头的文件用于启动进程。此外，大多数脚本都是符号链接，指向`/etc/rc.d/init.d/`目录。

同样地，我们可以在较新的 CentOS 发行版中暴露各种启动/停止脚本。例如，让我们选择 CentOS 6.5 并解剖其中一个目录。在 CentOS 6.5 系统上，这是其中一个停止脚本的显示：

```
[philip@localhost Desktop]$ cat /etc/rc.d/rc5.d/S13irqbalance
 #! /bin/sh
 ### BEGIN INIT INFO
 # Provides: irqbalance
 # Default-Start: 3 4 5
 # Default-Stop: 0 1 6
 # Short-Description: start and stop irqbalance daemon
 # Description: The irqbalance daemon will distribute interrupts across
 # the cpus on a multiprocessor system with the purpose of
 # spreading the load
 ### END INIT INFO
 # chkconfig: 2345 13 87 # This is an interactive program, we need the current locale # Source function library.
 . /etc/init.d/functions
```

正如我们所看到的，这些脚本涉及的内容更多。继续向下移动，我们可以看到以下代码：

```
# Check that we're a priviledged user
 [ `id -u` = 0 ] || exit 0
prog="irqbalance"
[ -f /usr/sbin/irqbalance ] || exit 0
# fetch configuration if it exists
 # ONESHOT=yes says to wait for a minute, then look at the interrupt
 # load and balance it once; after balancing exit and do not change
 # it again.
 # The default is to keep rebalancing once every 10 seconds.
 ONESHOT=
 [ -f /etc/sysconfig/irqbalance ] && . /etc/sysconfig/irqbalance
 case "$IRQBALANCE_ONESHOT" in
 y*|Y*|on) ONESHOT=--oneshot ;;
 *) ONESHOT= ;;
 esac
RETVAL=0
start() {
 if [ -n "$ONESHOT" -a -f /var/run/irqbalance.pid ]; then
 exit 0
 fi
 echo -n $"Starting $prog: "
 if [ -n "$IRQBALANCE_BANNED_CPUS" ];
 then
 export IRQBALANCE_BANNED_CPUS=$IRQBALANCE_BANNED_CPUS
 fi
 daemon irqbalance --pid=/var/run/irqbalance.pid $IRQBALANCE_ARGS $ONESHOT
 RETVAL=$?
 echo
 return $RETVAL
 }
stop() {
 echo -n $"Stopping $prog: "
 killproc irqbalance
 RETVAL=$?
 echo
 [ $RETVAL -eq 0 ] && rm -f /var/lock/subsys/irqbalance
 return $RETVAL
 }
restart() {
 stop
 start
 }
# See how we were called.
 case "$1" in
 start)
 start
 ;;
 stop)
 stop
 ;;
 status)
 status irqbalance
 ;;
 restart|reload|force-reload)
 restart
 ;;
 condrestart)
 [ -f /var/lock/subsys/irqbalance ] && restart || :
 ;;
 *)
 echo $"Usage: $0 {start|stop|status|restart|reload|condrestart|force-reload}"
 exit 1
 ;;
 esac
exit $?
 [philip@localhost Desktop]$
```

最后，从前面的输出中，我们可以清楚地看到这些脚本是以程序方式编写的。

# 引导目标简介

引导目标的概念是一个全新的游戏规则。引导目标在使用`systemd`时使用。我们可以看到性能提高了，因为只有对特定套接字的请求在需要时才会启动。此外，`systemd`模拟了`init`以实现兼容性，而在后台`systemd`正在进行工作。当我们使用引导目标时，我们使用单元。对于给定的引导目标，存在许多守护进程。让我们看看 Ubuntu 发行版中可用的引导目标：

```
root@ubuntu:/home/philip# systemctl list-units --type target
 UNIT           LOAD    ACTIVE   SUB  DESCRIPTION
 basic.target      loaded active active Basic System
 cryptsetup.target loaded active active Encrypted Volumes
 getty.target      loaded active active Login Prompts
 graphical.target  loaded active active Graphical Interface
 local-fs-pre.target loaded active active Local File Systems (Pre)
 local-fs.target   loaded active active Local File Systems
 multi-user.target loaded active active Multi-User System
 network.target    loaded active active Network
 nss-user-lookup.target loaded active active User and Group Name Lookups
 paths.target     loaded active active Paths
 remote-fs-pre.target loaded active active Remote File Systems (Pre)
 remote-fs.target loaded active active Remote File Systems
 slices.target   loaded active active Slices
 sockets.target  loaded active active Sockets
 sound.target    loaded active active Sound Card
 swap.target     loaded active active Swap
 sysinit.target  loaded active active System Initialization
 time-sync.target loaded active active System Time Synchronized
 timers.target   loaded active active Timers
LOAD = Reflects whether the unit definition was properly loaded.
 ACTIVE = The high-level unit activation state, i.e. generalization of SUB.
 SUB = The low-level unit activation state, values depend on unit type.
19 loaded units listed. Pass --all to see loaded but inactive units, too.
 To show all installed unit files use 'systemctl list-unit-files'.
 root@ubuntu:/home/philip#
```

从前面的输出中，只会显示当前加载的目标。`graphical.target`类似于`init`中的运行级别 5。要查看所有引导目标，我们可以这样做：

```
root@ubuntu:/home/philip# systemctl list-units --type target --all
 UNIT             LOAD ACTIVE SUB DESCRIPTION
 basic.target       loaded active active Basic System
 cryptsetup.target  loaded active active Encrypted Volumes
 emergency.target   loaded inactive dead Emergency Mode
 failsafe-graphical.target loaded inactive dead Graphical failsafe fallback
 final.target       loaded inactive dead Final Step
 getty.target       loaded active active Login Prompts
 graphical.target   loaded active active Graphical Interface
 halt.target        loaded inactive dead Halt
 local-fs-pre.target loaded active active Local File Systems (Pre)
 local-fs.target    loaded active active Local File Systems
 multi-user.target    loaded active active Multi-User System
 network-online.target loaded inactive dead Network is Online
 network-pre.target    loaded inactive dead Network (Pre)
 network.target            loaded active active Network
 nss-user-lookup.target    loaded active active User and Group Name Lookups
 paths.target                loaded active active Paths
 reboot.target               loaded inactive dead Reboot
 remote-fs-pre.target        loaded active active
```

从前面的输出中，我们可以看到活动的引导目标，以及不活动的引导目标。

现在，假设我们想要查看与特定目标相关的实际守护进程。我们将运行以下命令：

```
root@ubuntu:/home/philip# systemctl list-dependencies graphical.target
```

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00051.jpeg)

从前面的输出中，我们可以看到`graphical.target`中有许多守护进程。其中一个守护进程是`NetworkManager.service`，用于系统内的网络。阅读这个的方式是：

+   **绿色圆圈**：表示服务当前正在运行

+   **红色圆圈**：表示服务目前未运行

# 使用运行级别

我们可以像在本章中看到的那样，为各种任务使用各种运行级别。让我们使用 CentOS 6.5 发行版。要实时在 shell 中查看运行级别，我们可以使用`runlevel`命令：

```
[philip@localhost Desktop]$ runlevel
N 5
[philip@localhost Desktop]$
```

从前面的输出中，`N`表示先前的运行级别。在我们的情况下，我们没有改变运行级别。`5`表示我们当前处于运行级别 5。我们还可以运行另一个命令来显示运行级别。我们可以使用带有`-r`选项的`who`命令，如下所示：

```
[philip@localhost Desktop]$ who -r
 run-level 5 2018-06-20 08:09
 [philip@localhost Desktop]$
```

从前面的输出中，我们可以看到更详细的描述，即使用`who –r`命令的`run-level 5`。

现在，我们可以通过利用`init`或`telinit`命令来改变我们的 CentOS 6.5 发行版的运行级别。让我们看看如何从运行级别 5 更改到运行级别 1：

```
[philip@localhost Desktop]$ who -r
 run-level 5 2018-06-20 08:09
 [philip@localhost Desktop]$ init 1
```

当我们按下*Enter*时，我们会收到一个错误；原因是，在 CentOS 6.5 发行版中，我们需要 root 权限将运行级别 5 更改为运行级别 1：

```
[philip@localhost Desktop]$ init 1
 init: Need to be root
 [philip@localhost Desktop]$
```

现在，让我们以 root 用户的身份进行身份验证并重试`init 1`命令：

```
[philip@localhost Desktop]$ su -
 Password:
 [root@localhost ~]# init 1
```

现在，我们将被放置到运行级别 1，这将删除 GUI 并直接进入 shell。这个运行级别 1 通常被称为**单用户**，我们将用于恢复：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00052.gif)

从前面的输出中，我们运行了`runlevel`和`who -r`命令，并验证了我们确实在运行级别 1 中。

现在，让我们将系统恢复到 GUI 状态，即运行级别 5：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00053.gif)

现在，当我们在 GUI 中运行`runlevel`命令时，我们将看到之前的运行级别 1 替换`runlevel`命令中的`N`为`S`：

```
[philip@localhost Desktop]$ runlevel
 S 5
 [philip@localhost Desktop]$
```

同样，我们可以使用`who -r`选项运行`who`命令以查看更多信息：

```
[philip@localhost Desktop]$ who -r
run-level 5 2018-06-20 08:20 last=S
[philip@localhost Desktop]$ 
```

现在，假设我们想在某个运行级别打开一个守护程序。我们将使用`dnsmasq`进行演示。首先，让我们验证`dnsmasq`服务当前是否关闭：

```
[philip@localhost Desktop]$ chkconfig | grep dnsmasq
dnsmasq 0:off 1:off 2:off 3:off 4:off 5:off 6:off
[philip@localhost Desktop]$ 
```

太好了！现在让我们只在运行级别 3-5 中打开`dnsmasq`守护程序：

```
[philip@localhost Desktop]$ chkconfig --levels 345 dnsmasq on
You do not have enough privileges to perform this operation.
[philip@localhost Desktop]$ 
```

从前面的输出中，我们得到了一个错误，因为我们需要 root 权限才能在相应的运行级别中打开/关闭守护程序。让我们以 root 用户身份重试：

```
[philip@localhost Desktop]$ su -
Password:
[root@localhost ~]# chkconfig --levels 345 dnsmasq on
[root@localhost ~]#
```

太好了！现在让我们重新运行`chkconfig`命令，并只查找`dnsmasq`守护程序：

```
[root@localhost ~]# chkconfig | grep dnsmasq
dnsmasq 0:off 1:off 2:off 3:on 4:on 5:on 6:off
[root@localhost ~]# 
```

从前面的输出中，我们可以看到`dnsmasq`守护程序现在在运行级别 3-5 中设置为`on`。

# 使用引导目标

我们可以使用`systemctl`命令来处理引导目标。我们在本章前面提到了`systemctl`。让我们使用 Ubuntu 发行版。我们可以通过以下方式实时查看在 shell 中当前默认运行的`target`：

```
philip@ubuntu:~$ systemctl get-default
graphical.target
philip@ubuntu:~$
```

从前面的输出中，我们可以看到`graphical.target`是默认运行的目标。现在，如果我们想在不同的目标之间切换，我们可以使用`systemctl`命令。让我们切换到`multi-user.target`：

```
philip@ubuntu:~$ systemctl isolate multi-user.target
```

一旦我们按下*Enter*键，系统将要求我们进行身份验证：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00054.jpeg)

我们也可以运行`systemctl`来验证`multi-user.target`的状态：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00055.gif)

我们可以使用`systemctl`命令将系统返回到 GUI 环境：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00056.gif)

此外，我们可以使用`systemctl`命令查看一个目标的结构：

```
philip@ubuntu:~$ systemctl show network.target
 Id=network.target
 Names=network.target
 WantedBy=networking.service systemd-networkd.service NetworkManager.service
 Conflicts=shutdown.target
 Before=network-online.target rc-local.service
 After=NetworkManager.service network-pre.target systemd-networkd.service network
 Documentation=man:systemd.special(7) http://www.freedesktop.org/wiki/Software/sy
 Description=Network
```

```
 LoadState=loaded
 ActiveState=active
 SubState=active
 FragmentPath=/lib/systemd/system/network.target
 UnitFileState=static
 UnitFilePreset=enabled
 StateChangeTimestamp=Wed 2018-06-20 10:50:52 PDT
 StateChangeTimestampMonotonic=18205063
 InactiveExitTimestamp=Wed 2018-06-20 10:50:52 PDT
 InactiveExitTimestampMonotonic=18205063
 ActiveEnterTimestamp=Wed 2018-06-20 10:50:52 PDT
 ActiveEnterTimestampMonotonic=18205063
 ActiveExitTimestampMonotonic=0
 InactiveEnterTimestampMonotonic=0
 CanStart=no
```

从前面的输出中，一个关键值是`WantedBy`。这告诉我们谁依赖于`network.target`。我们可以看到`NetworkManager.service`依赖于`network.target`。还有关于`StateChangeTimestamp`、`Documentation`、`LoadState`和`Description`等的详细信息。

# 总结

在本章中，我们与运行级别进行了交互。我们看到了各种可用的运行级别，并在运行级别之间进行了切换。我们看到了默认的运行级别（运行级别 5），并使用了`runlevel`、`who`和`init`命令进行交互。然后，我们专注于引导目标。我们查看了默认的引导目标，并看到了每个引导目标下的各种单元。然后我们在引导目标之间进行了更改，并看到需要进行身份验证。我们使用了带有各种选项的`systemctl`命令，以及`runlevel`和`who`命令。我们验证了我们确实在另一个引导目标中。我们得出结论，`graphical.target`类似于运行级别 5，而`mutli-user.target`类似于运行级别 3。最后，我们简要地看了一下引导目标的结构。

在下一章中，我们将专注于硬盘布局的设计。在进行任何部署之前，硬盘布局至关重要。因此，下一章在这方面承载了很大的重要性，需要对我们如何管理硬盘进行深思熟虑。我们将涵盖`fdisk`和`parted`等技术。您将从下一章中掌握的技术将有助于您作为 Linux 工程师在未来的部署中。从下一章中获得的这种赋权是建立信心的关键因素，有助于您未来在认证方面取得成功。

# 问题

1.  在 CentOS 发行版中，GUI 显示在哪个运行级别？

1.  1

1.  5

1.  2

1.  3

1.  在 Ubuntu 发行版中打印当前运行级别的命令是什么？

1.  `run-level`

1.  `systemdctl`

1.  `runlevel`

1.  `who –b`

1.  哪个备用命令显示运行级别信息？

1.  `who -v`

1.  `who -l`

1.  `who -b`

1.  `who –r`

1.  在阅读运行级别输出时，*N*代表什么？

1.  当前运行级别

1.  在更改为当前运行级别之前的先前运行级别

1.  在更改为先前运行级别之前的先前当前运行级别

1.  当前正在使用的运行级别

1.  阅读运行级别输出时，*S*代表什么？

1.  单一登录用户

1.  超级用户

1.  单入口超级用户

1.  单用户

1.  用于更改运行级别的命令是什么？

1.  `int`

1.  `init`

1.  `runlevel`

1.  `change-run-level`

1.  还可以使用哪个命令来更改运行级别？

1.  `runlevel`

1.  `shutdown`

1.  `telinit`

1.  `telnit`

1.  用于查看默认引导目标的命令是什么？

1.  `systemctl get-default`

1.  `systemctl set-default`

1.  `systemctl-default`

1.  `systemctl-get-default`

1.  哪个命令可以用于列出给定目标的守护进程？

1.  `systemctl list-dependencies`

1.  `systemctl list-dependencies –type list`

1.  `systemctl list-dependencies –type target`

1.  `systemctl list-dependencies target`

1.  哪个命令在不同目标之间切换？

1.  `systemctl isolate target`

1.  `systemctl isolate multi-user.target`

1.  `systemctl isolate-target-multi-user`

1.  `systemctl isolate-multiuser.target`

1.  哪个命令显示目标的状态？

1.  `systemctl status multi-user.target`

1.  `systemctl status-multi-user.target`

1.  `systemctl-status multi-user.target`

1.  `systemctl-status-multiuser.target`

# 进一步阅读

+   您可以在[`www.centos.org.`](https://www.centos.org)获取有关 CentOS 发行版的更多信息，例如安装、配置最佳实践等。

+   以下网站为您提供了许多有用的提示和 Linux 社区用户的最佳实践，特别是针对 Debian 发行版，如 Ubuntu：[`askubuntu.com.`](https://askubuntu.com)

+   以下链接提供了一般信息，涉及适用于 CentOS 和 Ubuntu 的各种命令。您可以在以下链接发布问题，其他社区成员将会回答：[`www.linuxquestions.org`](https://www.linuxquestions.org).
