# CompTIA Linux 认证指南（四）

> 原文：[`zh.annas-archive.org/md5/1D0BEDF2E9AB87F7188D92631B85ED3E`](https://zh.annas-archive.org/md5/1D0BEDF2E9AB87F7188D92631B85ED3E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：创建、监视、终止和重新启动进程

在上一章中，我们详细讨论了文件管理。然后，我们介绍了如何在 shell 中创建文件。此外，我们还看到了文件的各种权限，并学习了如何更改它们。接着，我们转向 Linux 环境中的目录。最后，我们在 shell 环境的上下文中使用了管道和重定向。此外，我们还了解了另一个强大的命令——`tee`命令。

在本章中，我们将探讨用于管理各种进程的各种技术。首先，我们将使用非常流行的命令——`ps`命令实时调查进程。这个`ps`命令在第二章中简要介绍了一下，*启动系统*，在*解释引导过程*部分。在本章中，我们更加强调`ps`命令，探索可以传递的更多选项，从而暴露重要信息。之后，我们进入管理守护进程的方法；首先，我们从非常流行的`top`命令开始。这种处理进程的方法在整个 Linux 社区广泛使用。这主要是因为`top`命令提供各种守护进程的实时统计信息。除此之外，我们还可以控制守护进程的行为。接着，我们转向另一种管理进程的常见方法：`service`命令。最后，我们介绍了管理守护进程的最新方法；即`systemctl`命令。这在第二章中简要介绍了，*启动系统*，在*解释引导过程*部分。在本章中，我们更深入地探讨了使用`systemctl`命令进行守护进程管理的常见做法。

在本章中，我们将涵盖以下主题：

+   `ps`命令

+   使用`top`命令查看和管理进程

+   使用`service`命令管理进程

+   使用`systemctl`命令管理进程

# ps 命令

`ps`命令代表**进程状态**，是当今环境中最流行的命令之一。它显示系统中正在运行的当前进程；当我们在 Linux 环境中工作时，我们经常忽视使一切成为可能的底层进程。`ps`命令显示的所有信息都来自一个非常流行的目录；即`/proc`文件系统。`/proc`文件系统实际上并不是一个真正的文件系统；它实际上是一个虚拟文件系统。它在启动时加载，几乎可以在今天的每个 Linux 发行版中找到`/proc`文件系统。让我们深入了解`ps`命令。

首先，我们可以显示在当前 shell 中启动的任何进程：

```
[philip@localhost ~]$ ps
 PID         TTY        TIME        CMD
 2220        pts/0      00:00:00    bash
 95677       pts/0      00:00:00    ps
[philip@localhost ~]$
```

根据前面的输出，我们在当前 shell 中没有启动任何其他进程，除了`ps`命令本身和 Bash shell。我们还可以使用`ps`命令列出当前系统中的所有进程；我们将传递`-A`参数：

```
[philip@localhost ~]$ ps -A
 PID    TTY      TIME       CMD
 1   ?        00:00:31   systemd
 2   ?        00:00:00   kthreadd
 3   ?        00:00:02   ksoftirqd/0
 5   ?        00:00:00   kworker/0:0H
 7   ?        00:00:00   migration/0
 8   ?        00:00:00   rcu_bh
 9   ?        00:00:12   rcu_sched
 10  ?        00:00:11   watchdog/0
 12  ?        00:00:00   kdevtmpfs
 13  ?        00:00:00   netns
 14  ?        00:00:00   khungtaskd
 15  ?        00:00:00   writeback
 95730  ?        00:00:00   kworker/0:3
 95747  ?        00:00:00   sleep
 95748  pts/0    00:00:00   ps
[philip@localhost ~]$
```

当我们使用`-A`或`-e`参数运行`ps`命令时，它只会打印出每个进程的进程 ID 和名称。但是，我们可以进一步扩展这个输出。我们可以传递`-a`和`-u`。这将打印出当前用户在终端中打开的进程：

```
[philip@localhost ~]$ ps -au
```

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00111.jpeg)

要查看系统中当前用户拥有的所有进程，我们传递`-x`选项：

```
[philip@localhost ~]$ ps -x
PID  TTY  STAT  TIME COMMAND
1487  ?    Sl   0:00 /usr/bin/gnome-keyring-daemon --daemonize --login
1491  ?    Ssl  0:01 /usr/libexec/gnome-session-binary --session gnome-classic
1498  ?    S    0:00 dbus-launch --sh-syntax --exit-with-session
1499  ?    Ssl  0:00 /bin/dbus-daemon --fork --print-pid 4 --print-address 6 --session
1567  ?    Sl   0:00 /usr/libexec/gvfsd
1572  ?    Sl   0:00 /usr/libexec/gvfsd-fuse /run/user/1000/gvfs -f -o big_writes
1664  ?    Ss   0:00 /usr/bin/ssh-agent /bin/sh -c exec -l /bin/bash -c "env
```

```
GNOME_SHELL_SESSION_MODE=classic gnome-session --session gnome-cla
1683  ?    Sl   0:00 /usr/libexec/at-spi-bus-launcher
1688  ?    Sl   0:00 /bin/dbus-daemon --config-file=/usr/share/defaults/at-spi2/accessibility.conf --nofork --print-address 3
```

我们还可以将用户作为参数的一部分指定为`-u`：

```
[philip@localhost ~]$ ps -au root
 PID  TTY   TIME      CMD
 1   ?     00:00:31  systemd
 2   ?     00:00:00  kthreadd
 3   ?     00:00:02  ksoftirqd/0
 5   ?     00:00:00  kworker/0:0H
```

我们还可以看到所有用户以及每个守护进程的可执行文件的路径；我们传递`-aux`或`aux-`；这是**伯克利软件发行**（**BSD**）语法。BSD 是 Unix 的另一种风味。以下是 Linux 语法的示例：

```
[philip@localhost ~]$ ps -aux
USER    PID %CPU %MEM  VSZ     RSS   TTY  STAT  START   TIME 
COMMAND
root      1    0.0  0.4  193700  4216  ?    Ss    Aug08  0:31 /usr/lib/systemd/systemd --switched-root --system --deserialize 21
root      2    0.0  0.0   0      0     ?    S     Aug08  0:00 
[kthreadd]
root      3    0.0  0.0   0      0     ?    S     Aug08  0:02 [ksoftirqd/0]
root      5    0.0  0.0   0      0     ?    S     Aug08  0:00 [kworker/0:0H]
dbus      570  0.0  0.2  36524  2236   ?    Ssl   Aug08  0:14 /bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activati
chrony    571  0.0  0.0  115640 672    ?     S    Aug08  0:00 /usr/sbin/chronyd
avahi     585  0.0  0.0  30072  28     ?     S    Aug08  0:00 avahi-daemon: chroot helper
philip    2209 0.0  0.0 313472  644    ?     Sl   Aug08  0:00 /usr/libexec/gvfsd-metadata
philip    2213 0.0  1.0 720692 10608   ?     Sl   Aug08   0:05 /usr/libexec/gnome-terminal-server
```

太棒了！根据前面的输出，我们可以看到各种用户帐户。一些帐户是实际的系统帐户，例如`dbus`帐户。我们还可以指定用户帐户 ID：

```
[philip@localhost ~]$ ps -ux 1000
USER PID  %CPU  %MEM    VSZ    RSS  TTY  STAT START   TIME 
COMMAND
philip   1487  0.0   0.0    462496 996   ?    Sl   Aug08   0:00 /usr/bin/gnome-keyring-daemon --daemonize --login
philip  1491   0.0   0.1    761348 1512  ?    Ssl  Aug08   0:01 /usr/libexec/gnome-session-binary --session gnome-classic
philip  1498   0.0   0.0    13976   0    ?    S    Aug08   0:00 
dbus-launch --sh-syntax --exit-with-session
philip  1499   0.0   0.1    36284   1276 ?    Ssl  Aug08   0:00 /bin/dbus-daemon --fork --print-pid 4 --print-address 6 --session
philip  1567   0.0  0.0     386352   0   ?    Sl   Aug08   0:00 /usr/libexec/gvfsd
philip  1572   0.0  0.0     415548   52  ?    Sl   Aug08   0:00 /usr/libexec/gvfsd-fuse /run/user/1000/gvfs -f -o big_writes
```

除此之外，还可以显示由特定组拥有的进程。是的！通过传递组名或 ID 来实现。如果我们传递组名，那么我们使用`-g`：

```
[philip@localhost ~]$ ps -fg postfix
UID        PID    PPID  C  STIME  TTY      TIME      CMD
postfix    1110   1108  0  Aug08   ?    00:00:00  qmgr -l -t unix -u
postfix    95714  1108  0  06:12   ?    00:00:00  pickup -l -t unix -u
[philip@localhost ~]$
```

要传递组 ID，我们传递`-G`选项：

```
[philip@localhost ~]$ ps -fg 89
UID         PID    PPID   C  STIME  TTY         TIME   CMD
[philip@localhost ~]$
[philip@localhost ~]$ ps -fG 89
UID         PID    PPID  C   STIME  TTY   TIME       CMD
postfix     1110   1108  0   Aug08  ?     00:00:00   qmgr -l -t unix -u
postfix     95714  1108  0   06:12  ?     00:00:00   pickup -l -t unix -u
[philip@localhost ~]$
```

干得好！我们还可以通过指定**进程 ID**（**PID**）来搜索进程。我们传递`-f`，它将打印一个长列表，以及`-p`选项，它期望一个数值：

```
[philip@localhost ~]$ ps -fp 1982
UID       PID   PPID  C  STIME   TTY  TIME      CMD
philip    1982  1     0  Aug08   ?    00:00:00  /usr/libexec/tracker-store
[philip@localhost ~]$
```

有趣的是，我们甚至可以在同一行上指定多个进程；我们用逗号分隔进程：

```
[philip@localhost ~]$ ps -fp 1982,2001,2219
UID         PID   PPID  C  STIME   TTY  TIME     CMD
philip     1982   1     0  Aug08   ?    00:00:00 /usr/libexec/tracker-store
```

```
philip     2001   1730  0  Aug08   ?    00:00:00 /usr/libexec/ibus-engine-simple
philip     2219   2213  0  Aug08    ?   00:00:00 gnome-pty-helper
[philip@localhost ~]$
```

干得好！还可以通过传递`-o`选项来查找命令指定的进程 ID：

```
[philip@localhost ~]$ ps -fp 955 -o comm=sshd
[philip@localhost ~]$
```

根据前面的输出，仅显示了相应 PID 的实际可执行文件。

还可以使用`ps`命令获取内存和 CPU 信息；我们传递`-e`选项以及`-o`选项。然后，我们需要传递我们感兴趣的列名称。以下是我们如何完成这个任务：

```
[philip@localhost ~]$ ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head     -14
PID    PPID    CMD                           %MEM   %CPU
1710   1491    /usr/bin/gnome-shell           17.9   0.0
1926   1491    /usr/bin/gnome-software --g    7.1    0.0
1042   989     /usr/bin/X :0 -background n    2.5    0.0
95581  633     /sbin/dhclient -d -q -sf /u    1.3    0.0
2213   1       /usr/libexec/gnome-terminal    1.1    0.0
605    1       /usr/lib/polkit-1/polkitd -    1.1    0.0
1872   1491    /usr/libexec/gnome-settings    0.8    0.0
633    1       /usr/sbin/NetworkManager --    0.8    0.0
1890   1491    nautilus-desktop --force       0.7    0.0
2050   1915    /usr/libexec/evolution-cale    0.6    0.0
1291   1       /usr/libexec/packagekitd       0.6    0.0
632    1       /usr/bin/python -Es /usr/sb    0.4    0.0
1990   1915    /usr/libexec/evolution-cale    0.4    0.0
[philip@localhost ~]$
```

太棒了！根据前面的输出，我们指定了`pid,ppid,cmd,%mem,%cpu`。除此之外，还添加了`--sort`选项。这将查找使用最多系统 RAM 的进程，并从最高到最低显示这些进程。此外，我们添加了`head`命令；这将只显示内容的顶部部分。

我们指定只想看到前 14 行。但是，`ps`命令的输出不是实时刷新的；我们可以使用另一个流行的命令来查看输出实时刷新，而不是我们必须重新运行命令。我们使用`watch`命令来完成这个任务：

```
[philip@localhost ~]$ watch -n 1 'ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head'
```

运行前面的命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00112.jpeg)

根据前面的截图，我们已经对输出进行了排序，以查看在系统中占用大部分 CPU 的进程。我们可以以分层视图查看`ps`命令的输出；我们将添加`-f`和`--forest`选项：

```
[philip@localhost ~]$ ps -af --forest
UID         PID   PPID  C  STIME  TTY     TIME      CMD
philip      99053 2220  0  07:29  pts/0   00:00:00  ps -af --forest
[philip@localhost ~]$ ps -axf --forest
PID TTY      STAT   TIME COMMAND
 2 ?        S      0:00 [kthreadd]
 3 ?        S      0:02  \_ [ksoftirqd/0]
 517?        S<sl   0:00 /sbin/auditd
519 ?        S<sl   0:01  \_ /sbin/audispd
521 ?        S<     0:00   \_ /usr/sbin/sedispatch
543 ?        SNsl   0:04     /usr/libexec/rtkit-daemon
1664 ?        Ss    0:00    \_ /usr/bin/ssh-agent /bin/sh -c exec -l /bin/bash -c "env GNOME_SHELL_SESSION_MODE=classic gnome-session --sessi
1710 ?        Sl     5:01    \_ /usr/bin/gnome-shell
1730 ?        Sl     0:00    |  \_ ibus-daemon --xim --panel disable
1743 ?        Sl     0:00    |     \_ /usr/libexec/ibus-dconf
2001 ?        Sl     0:00    |       \_ /usr/libexec/ibus-engine-simple
1872 ?        Sl     0:18     \_ /usr/libexec/gnome-settings-daemon
```

# 杀死命令

`kill`命令用于终止进程。我们可以利用刚刚介绍的`ps`命令来识别进程，然后调用`kill`命令来结束进程。以下是我们如何使用`kill`命令停止进程的方法：

```
[philip@localhost ~]$ ps -p 1788
PID   TTY       TIME     CMD
1788   ?        00:00:00 goa-daemon
[philip@localhost ~]$
[philip@localhost ~]$ kill -9 1788
[philip@localhost ~]$ ps -fp 1788
UID         PID   PPID  C STIME TTY        TIME CMD
[philip@localhost ~]$
```

太棒了！我们使用了`9`数字，这意味着发送`SIGKILL`。要查看我们可以传递的各种信号，我们可以使用`kill`命令的`-l`选项：

```
[philip@localhost ~]$ kill -l
1) SIGHUP      2) SIGINT       3) SIGQUIT    4) SIGILL    5) SIGTRAP         6) SIGABRT     7) SIGBUS       8) SIGFPE     9) SIGKILL  10) SIGUSR111) SIGSEGV       12) SIGUSR2      13) SIGPIPE   14) SIGALRM 15) SIGTERM 
16) SIGSTKFLT 17) SIGCHLD      18) SIGCONT   19) SIGSTOP 20) SIGTSTP
21) SIGTTIN   22) SIGTTOU      23) SIGURG    24) SIGXCPU 25) SIGXFSZ
26) SIGVTALRM 27) SIGPROF      28) SIGWINCH  29) SIGIO   30) SIGPWR 
31) SIGSYS     34) SIGRTMIN    35) SIGRTMIN+1 36) SIGRTMIN+2 
37) SIGRTMIN+3 38) SIGRTMIN+4  39) SIGRTMIN+5 40) SIGRTMIN+6 
41) SIGRTMIN+7 42) SIGRTMIN+8  43) SIGRTMIN+9 44) SIGRTMIN+10            45) SIGRTMIN+11 46) SIGRTMIN+12 47) SIGRTMIN+13 48) SIGRTMIN+14            49) SIGRTMIN+15 50) SIGRTMAX-14 51) SIGRTMAX-13 52) SIGRTMAX-12            53) SIGRTMAX-11 54) SIGRTMAX-10 55) SIGRTMAX-9 56) SIGRTMAX-8             57) SIGRTMAX-7  58) SIGRTMAX-6 59) SIGRTMAX-5 60) SIGRTMAX-4               61) SIGRTMAX-3  62) SIGRTMAX-2 63) SIGRTMAX-1 64) SIGRTMAX 
[philip@localhost ~]$
```

要使用信号名称停止进程，我们传递`-s`选项：

```
[philip@localhost ~]$ ps -fp 1990
UID     PID   PPID  C STIME  TTY   TIME      CMD
philip  1990  1915  0 Aug08  ?     00:00:00  /usr/libexec/evolution-calendar-factory-subprocess --factory contacts --bus-name org.gnome.evolution
[philip@localhost ~]$ kill -s SIGKILL 1915
[philip@localhost ~]$ ps -fp 1915
UID       PID   PPID  C STIME TTY          TIME CMD
[philip@localhost ~]$
```

在调用`kill`命令时，停止使用`SIGTERM`时应该小心。

# pstree 命令

还有另一种`ps`命令的变体，可用于查看系统中的进程——`pstree`命令。这将以分层布局呈现所有进程。它看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00113.jpeg)

根据前面的截图，一些进程是父进程：它们有子进程。我们还可以通过传递`-h`选项来突出显示特定进程：

```
[root@localhost Desktop]# pstree -h 1735
rsyslogd───3*[{rsyslogd}]
[root@localhost Desktop]#The Process Grep commonly known as pgrep is another popular method
```

我们还可以仅显示特定于用户的进程；我们传递`用户名`：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00114.jpeg)

根据前面的截图，我们可以看到用户父进程是`gdm-x-session`；然后有子进程，从`Xorg`开始，向下移动树。

# pgrep 命令

**进程 Grep**，通常称为`pgrep`，是另一种在 shell 中查找进程 ID 的流行方法。如果我们知道进程名称，那么我们可以使用`pgrep`命令指定它：

```
[root@localhost Desktop]# pgrep rsyslogd
545
[root@localhost Desktop]#
```

根据前面的命令，我们可以看到`rsyslogd`的 PID。我们还可以找到特定用户的进程。为此，我们传递`-u`选项：

```
[root@localhost Desktop]# pgrep -u root rsyslogd
545
[root@localhost Desktop]#
```

干得好！

# pkill 命令

`pkill`命令是另一种用于终止进程的已知方法。它使我们能够在终止给定进程时使用进程名称。在其最简单的形式中，它如下：

```
[philip@localhost ~]$ pgrep rsyslogd
545
[philip@localhost ~]$ pkill rsyslogd
pkill: killing pid 545 failed: Operation not permitted
[philip@localhost ~]$ su
Password:
[root@localhost philip]# pkill rsyslogd
[root@localhost philip]# pgrep rsyslogd
[root@localhost philip]#
```

厉害了！根据前面的代码输出，我们可以看到`pkill`命令的有效性。

# 使用 top 命令查看和管理进程

`top`命令，意思是*进程表*，在性质上类似于 Windows 任务管理器。您会发现许多 Linux 发行版支持`top`命令。`top`命令主要用于获取系统的 CPU 和内存利用率。输出是通过创建一个由用户指定标准选择的运行进程列表来构造的；输出是实时的。每个进程的 PID 都列在第一列中。让我们开始吧：

```
[philip@localhost ~]$ top
top - 12:50:44 up 5 days, 11:44,  2 users,  load average: 0.01, 0.02, 0.05
Tasks: 165 total,   1 running, 164 sleeping,   0 stopped,   0 zombie
%Cpu(s): 12.1 us,  1.4 sy,  0.0 ni, 86.1 id,  0.0 wa,  0.0 hi,  0.4 si,  0.0 st
KiB Mem :   999696 total,    95804 free,   633636 used,   270256 buff/cache
KiB Swap:  2097148 total,  1852900 free,   244248 used.   137728 avail Mem
PID   USER    PR    NI VIRT    RES  SHR S %CPU %MEM   TIME+  COMMAND                                                                          1710 philip   20    0  1943720 175920  15680 S  9.3 17.6 5:32.99 gnome-shell 
1042 root     20    0  306324  26188  1864 S  5.6 2.6 1:13.99 X                                                                                 2213 philip   20    0  721204  11976  5992 S  2.7 1.2 0:15.04 gnome-terminal-                                                                  1934 philip   20   0  389192  6308  1952 S  0.3  0.6   5:25.10 vmtoolsd
```

```
103282 philip 20   0  157716   2260   1540 R  0.3  0.2   0:00.28 top                                                                              1  root       20   0  193700   4248   2484 S  0.0  0.4   0:33.67 systemd                                                                          2 root        20   0       0      0      0 S  0.0  0.0   0:00.21 kthreadd                                                                          
```

在最右边，有一个`COMMAND`列；这显示了可执行文件。我们可以过滤我们想要显示的用户及其相应的进程；我们在`top`中使用`-u`选项：

```
[philip@localhost ~]$ top -u philip
top - 12:55:24 up 5 days, 11:49,  2 users,  load average: 0.25, 0.08, 0.06
Tasks: 164 total,   2 running, 162 sleeping,   0 stopped,   0 zombie
%Cpu(s): 55.4 us,  6.8 sy,  0.0 ni, 36.5 id,  1.4 wa,  0.0 hi,  0.0 si,  0.0 st
KiB Mem :   999696 total,    73184 free,   641804 used,   284708 buff/cache
KiB Swap:  2097148 total,  1856364 free,   240784 used.   128952 avail Mem
PID   USER  PR NI VIRT    RES    SHR   S %CPU %MEM  TIME+  COMMAND 
1710 philip 20 0 1943720 177568  16612 S 42.7 17.8 5:39.32 gnome-shell 
2213 philip 20 0 721204  12256   6228  S  2.6  1.2  0:15.61 gnome-terminal-                                                                  1934 philip 20 0 389192  6308   1952  S  0.3  0.6   5:25.37 vmtoolsd 
103360 philip  20   0  157716   2260   1544 R  0.3  0.2   0:00.06 top                                                                               1487 philip  20  0 462496   1504  1004 S  0.0  0.2 0:00.08 gnome-keyring-d                                                                  1491 philip  20 0 761348 2140 1220 S 0.0 0.2  0:01.77 gnome-session-b                                                                  1498 philip  20 0 13976   0     0  S  0.0  0.0 0:00.00 dbus-launch                                                                      1499 philip  20   0  36284 160 600 S  0.0  0.2   0:00.72 dbus-daemon                                                                      1567 philip  20   0  386352    864    592 S0.0 0.1 0:00.02 gvfsd                                                                             
```

根据前面的输出，只显示了用户`philip`的进程。我们可以通过在`top`命令中按*C*来查看所有进程的绝对路径。这是按下*C*时得到的截图：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00115.jpeg)

太棒了！现在我们可以看到每个进程的位置。我们还可以更改输出的刷新频率；默认值是每三秒。我们从`top`命令中按下*D*键：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00116.jpeg)

根据前面的屏幕截图，当按下*D*键时，会出现一行新的内容：`Change delay from 3.0 to`。这提示我们要指定一个数字。我在这里输入`2`，这样更新将每两秒刷新一次。现在，当我再次按下*D*键时，我们会注意到提示中的差异：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00117.jpeg)

干得好！要查看`top`的帮助，我们可以按*H*：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00118.jpeg)

我们可以更改`top`实用程序中内存的显示方式；根据当前的内存输出，当我们按下*M*时，显示将切换：

```
top - 13:09:50 up 5 days, 12:03,  2 users, load average: 0.00, 0.04, 0.05
Tasks: 164 total,   1 running, 163 sleeping,   0 stopped,   0 zombie
%Cpu(s):  4.1 us,  0.7 sy,  0.0 ni, 95.2 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
```

根据前面的屏幕截图，内存部分被隐藏了。当我们再次按下*M*键时，这将改变：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00119.jpeg)

太棒了！如果我们再次按下*M*键，我们会看到一种图形设计：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00120.jpeg)

干得好！现在我们有漂亮的条形图，指示了 RAM 和交换的内存使用情况。同样，我们可以通过 CPU 更改输出的显示；为此，我们按*T*：

```
top - 13:19:23 up 5 days, 12:13,  2 users,  load average: 0.30, 0.11, 0.07
Tasks: 163 total,   3 running, 160 sleeping,   0 stopped,   0 zombie
2 sleeping,   0 stopped,   0 zombie
%Cpu(s):   9.6/1.4    11[|||||||||||                                                                                         ]
KiB Mem :   999696 total,    73524 free,   641328 used,   284844 buff/cache
KiB Swap:  2097148 total,  1856532 free,   240616 used.   129444 avail Mem
```

太棒了！当我们按*T*时，它会将条形图变成阴影输出：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00121.gif)

除此之外，进程还可以以分层输出的方式显示；我们按*Shift* + *V*：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00122.jpeg)

要关闭层次视图，我们只需再次切换*Shift* + *V*：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00123.jpeg)

我们还可以使用`top`命令停止一个进程；我们按*K*，这是在`top`命令中杀死进程的快捷键：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00124.jpeg)

基于前面的命令，会出现一行新的内容：`PID to signal/kill [default pid = 1710]`，我们需要指定一个进程 ID：

```
KiB Swap:2097148 total, 1856800 free, 240348 used. 129084 avail Mem
Send pid 1718 signal [15/sigterm]
PID  USER   PR NI VIRT   RES    SHR   S %CPU %MEM  TIME+   COMMAND                                                                          1710 philip 20 0 1944552 176788 16840 S  1.5 17.7  6:36.40 gnome-shell                                                                       2213 philip 20 0 721724  16020   8740 S  0.5 1.6   0:22.60 gnome-terminal-
```

现在我们需要指定要发送给进程的信号；默认是`15/sigterm`。我们将接受默认值；这将在不必退出`top`实用程序的情况下终止进程。

# 使用`service`命令管理进程

`service`命令最初用于在`systemd`之前的早期 Linux 发行版上运行 SysVinit 脚本。根据您要完成的任务，您用于启动、停止或重新启动服务的方法将取决于您的发行版是使用`systemd`还是`init`。大多数 Linux 工程师更喜欢使用`service`命令而不是在系统环境中处理进程的较新方法。因此，在大多数较新的发行版中支持`service`命令。`service`命令的语法是：

```
service <process> <status>
```

要查看运行 SysV 脚本的系统上的所有服务，我们将使用 CentOS 6.5 系统：

```
[philip@localhost Desktop]$ service --status-all
abrt-ccpp hook is installed
abrtd (pid  2254) is running...
abrt-dump-oops is stopped
acpid (pid  1964) is running...
atd (pid  2273) is running...
auditd (pid  1710) is running...
Usage: /etc/init.d/bluetooth {start|stop}
cpuspeed is stopped
crond (pid  2262) is running...
cupsd (pid  1874) is running...
dnsmasq (pid  2087) is running...
firstboot is not scheduled to run
hald (pid  1975) is running...
htcacheclean is stopped
httpd is stopped
winbindd is stopped
wpa_supplicant (pid  1875) is running...
[philip@localhost Desktop]$
```

`service`命令读取的脚本以`rc`开头。我们可以快速查看所有相关脚本：

```
[philip@localhost Desktop]$ ls -l /etc | grep rc.
lrwxrwxrwx.  1 root root     11 Jun 20 01:37 init.d -> rc.d/init.d
lrwxrwxrwx.  1 root root      7 Jun 20 01:40 rc -> rc.d/rc
lrwxrwxrwx.  1 root root     10 Jun 20 01:40 rc0.d -> rc.d/rc0.d
lrwxrwxrwx.  1 root root     10 Jun 20 01:40 rc1.d -> rc.d/rc1.d
lrwxrwxrwx.  1 root root     10 Jun 20 01:40 rc2.d -> rc.d/rc2.d
lrwxrwxrwx.  1 root root     10 Jun 20 01:40 rc3.d -> rc.d/rc3.d
lrwxrwxrwx.  1 root root     10 Jun 20 01:40 rc4.d -> rc.d/rc4.d
lrwxrwxrwx.  1 root root     10 Jun 20 01:40 rc5.d -> rc.d/rc5.d
lrwxrwxrwx.  1 root root     10 Jun 20 01:40 rc6.d -> rc.d/rc6.d
drwxr-xr-x. 10 root root   4096 Jun 20 05:50 rc.d
lrwxrwxrwx.  1 root root     13 Jun 20 01:40 rc.local -> rc.d/rc.local
lrwxrwxrwx.  1 root root     15 Jun 20 01:40 rc.sysinit -> rc.d/rc.sysinit
[philip@localhost Desktop]$
```

要控制进程的状态，我们可以这样做：

```
[philip@localhost Desktop]$ service crond status
crond (pid  4457) is running...
[philip@localhost Desktop]$
```

根据前面的命令，这个特定进程目前正在运行。我们可以更改这一点；假设我们想要停止`crond`进程。我们只需用`stop`替换`status`：

```
[philip@localhost Desktop]$ service crond stop
User has insufficient privilege.
[philip@localhost Desktop]$
```

根据前面的输出，我们遇到了一个障碍；这可以很容易地通过成为 root 用户来解决：

```
[root@localhost Desktop]# service crond stop
Stopping crond:                                            [  OK  ]
[root@localhost Desktop]#
```

太棒了！现在我们可以重新运行`service`命令；这次使用`status`选项：

```
[root@localhost Desktop]# service crond status
crond is stopped
[root@localhost Desktop]#
```

然后我们完成了。服务已经停止。要开始备份这个进程，我们只需用`start`替换`stop`：

```
[root@localhost Desktop]# service crond start
Starting crond:                                            [  OK  ]
[root@localhost Desktop]#
```

现在让我们再次尝试启动这个进程：

```
[root@localhost Desktop]# service crond status
crond (pid  6606) is running...
[root@localhost Desktop]#
```

干得好！如果出于某种原因，我们对进程进行了更改并需要重新启动进程，那么我们可以通过多种方式来做到。我们可以停止进程，然后再次启动它：

```
[root@localhost Desktop]# service crond stop
Stopping crond:                                            [  OK  ]
[root@localhost Desktop]# service crond start
Starting crond:                                            [  OK  ]
[root@localhost Desktop]#
```

此外，我们可以使用`restart`选项：

```
[root@localhost Desktop]# service crond restart
Stopping crond:                                            [  OK  ]
Starting crond:                                            [  OK  ]
[root@localhost Desktop]#
```

最后，我们可以使用`reload`选项；这个选项将重新读取已经进行的任何更改的配置文件：

```
[root@localhost Desktop]# service crond reload
Reloading crond:                                           [  OK  ]
[root@localhost Desktop]# service crond status
crond (pid  6703) is running...
[root@localhost Desktop]#
```

太棒了！

# 使用 systemctl 命令管理进程

在大多数使用 system 的新发行版上，我们将使用`systemctl`命令来管理进程。Linux 开发人员也留下了对`service`命令的支持；如果我们尝试使用`service`命令终止一个进程，那么我们会发现它实际上会将我们的请求重定向到`systemctl`命令。让我们试试看：

```
[root@localhost philip]# service crond status
Redirecting to /bin/systemctl status crond.service
crond.service - Command Scheduler
Loaded: loaded (/usr/lib/systemd/system/crond.service; enabled; vendor preset: enabled)
Active: active (running) since Thu 2018-08-02 07:13:38 PDT; 1 weeks 5 days ago
 Main PID: 991 (crond)
CGroup: /system.slice/crond.service
 └─991 /usr/sbin/crond -n
Aug 02 07:13:38 localhost.localdomain systemd[1]: Started Command Scheduler.
Aug 02 07:13:38 localhost.localdomain systemd[1]: Starting Command Scheduler...
Aug 02 07:13:38 localhost.localdomain crond[991]: (CRON) INFO (RANDOM_DELAY will be scaled with factor 15% if used.)
Aug 02 07:13:43 localhost.localdomain crond[991]: (CRON) INFO (running with inotify support)
[root@localhost philip]#
```

太棒了！根据输出，我们可以看到`service`命令实际上正在被重定向：

```
[root@localhost philip]# service crond status
Redirecting to /bin/systemctl status crond.service
crond.service - Command Scheduler
```

现在让我们尝试使用管理进程的新方法；我们将使用`systemctl`命令。格式如下：

```
systemctl <action><process>
```

我们可以在 shell 中使用这个：

```
[root@localhost philip]# systemctl status atd
atd.service - Job spooling tools
Loaded: loaded (/usr/lib/systemd/system/atd.service; enabled; vendor preset: enabled)
Active: active (running) since Thu 2018-08-02 07:13:38 PDT; 1 weeks 5 days ago
Main PID: 993 (atd)
CGroup: /system.slice/atd.service
 └─993 /usr/sbin/atd -f
Aug 02 07:13:38 localhost.localdomain systemd[1]: Started Job spooling tools.
Aug 02 07:13:38 localhost.localdomain systemd[1]: Starting Job spooling tools...
[root@localhost philip]#
```

使用`systemctl`启动一个进程，我们传递`start`选项：

```
[root@localhost philip]# systemctl start rsyslog.service
[root@localhost philip]#
```

我们可以通过传递`status`选项来检查进程的状态：

```
[root@localhost philip]# systemctl status rsyslog.service
rsyslog.service - System Logging Service
Loaded: loaded (/usr/lib/systemd/system/rsyslog.service; enabled; vendor preset: enabled)
 Active: active (running) since Tue 2018-08-14 08:29:22 PDT; 5s ago
 Docs:
man:rsyslogd(8)
 http://www.rsyslog.com/doc/
Main PID: 117499 (rsyslogd)
 CGroup: /system.slice/rsyslog.service
 └─117499 /usr/sbin/rsyslogd -n
Aug 14 08:29:22 localhost.localdomain systemd[1]: Starting System Logging Service...
Aug 14 08:29:22 localhost.localdomain rsyslogd[117499]:  [origin software="rsyslogd" swVersion="8.24.0" x-pid="117499" x-info="http://www.rs...] start
Aug 14 08:29:22 localhost.localdomain systemd[1]: Started System Logging Service.
Hint: Some lines were ellipsized, use -l to show in full.
[root@localhost philip]#
```

您会注意到，与早期 Linux 发行版中的旧 service 命令相比，`systemctl`命令的输出要直观得多。我们也可以使用`systemctl`命令停止一个进程；我们传递`stop`选项：

```
[root@localhost philip]# systemctl stop rsyslog.service
[root@localhost philip]# systemctl status rsyslog.service
rsyslog.service - System Logging Service
Loaded: loaded (/usr/lib/systemd/system/rsyslog.service; enabled; vendor preset: enabled)
Active: inactive (dead) since Tue 2018-08-14 08:38:38 PDT; 8s ago
Docs: man:rsyslogd(8)
http://www.rsyslog.com/doc/
Process: 117499 ExecStart=/usr/sbin/rsyslogd -n $SYSLOGD_OPTIONS (code=exited, status=0/SUCCESS)
Main PID: 117499 (code=exited, status=0/SUCCESS)
Aug 14 08:29:22 localhost.localdomain systemd[1]: Starting System Logging Service...
Aug 14 08:29:22 localhost.localdomain rsyslogd[117499]:  [origin software="rsyslogd" swVersion="8.24.0" x-pid="117499" x-info="http://www.rs...] start
Aug 14 08:29:22 localhost.localdomain systemd[1]: Started System Logging Service.
Aug 14 08:38:38 localhost.localdomain rsyslogd[117499]:  [origin software="rsyslogd" swVersion="8.24.0" x-pid="117499" x-info="http://www.rs...nal 15.
Aug 14 08:38:38 localhost.localdomain systemd[1]: Stopping System Logging Service...
Aug 14 08:38:38 localhost.localdomain systemd[1]: Stopped System Logging Service.
Hint: Some lines were ellipsized, use -l to show in full.
[root@localhost philip]#
```

此外，我们可以重新启动或重新加载一个进程：

```
[root@localhost philip]# systemctl restart rsyslog.service
[root@localhost philip]# systemctl status rsyslog.service
rsyslog.service -
System Logging Service
Loaded: loaded (/usr/lib/systemd/system/rsyslog.service; enabled; vendor preset: enabled)
 Active: active (running) since Tue 2018-08-14 08:39:37 PDT; 2s ago
 Docs: man:rsyslogd(8)
 http://www.rsyslog.com/doc/
Main PID: 117730 (rsyslogd)
CGroup: /system.slice/rsyslog.service
 └─117730 /usr/sbin/rsyslogd -n
Aug 14 08:39:37 localhost.localdomain systemd[1]: Starting System Logging Service...
Aug 14 08:39:37 localhost.localdomain rsyslogd[117730]:  [origin software="rsyslogd" swVersion="8.24.0" x-pid="117730" x-info="http://www.rs...] start
Aug 14 08:39:37 localhost.localdomain systemd[1]: Started System Logging Service.
Hint: Some lines were ellipsized, use -l to show in full.
[root@localhost philip]#
```

根据前面的输出，当我们传递`restart`选项时，它只是启动了进程。使用`systemctl`命令处理的进程在使用`systemctl`命令时被视为单元。我们可以通过传递`list-units`文件来查看这些单元：

```
[root@localhost philip]# systemctl list-units --all --state=active
UNIT    LOAD   ACTIVE SUB       DESCRIPTION
proc-sys-fs-binfmt_misc.automount                              loaded active waiting   Arbitrary Executable File Formats File System Automount Point
dev-cdrom.device                                               loaded active plugged   VMware_Virtual_IDE_CDROM_Drive
dev-disk-by\x2did-ata\x2dVMware_Virtual_IDE_CDROM_Drive_10000000000000000001.device loaded active plugged   VMware_Virtual_IDE_CDROM_Drive
dev-disk-by\x2dpath-pci\x2d0000:00:07.1\x2data\x2d2.0.device   loaded active plugged   VMware_Virtual_IDE_CDROM_Drive
dev-disk-by\x2dpath-pci\x2d0000:00:10.0\x2dscsi\x2d0:0:0:0.device loaded active plugged   VMware_Virtual_S
dev-disk-by\x2dpath-pci\x2d0000:00:10.0\x2dscsi\x2d0:0:0:0\x2dpart1.device loaded active plugged   VMware_Virtual_S 1
dev-disk-by\x2dpath-pci\x2d0000:00:10.0\x2dscsi\x2d0:0:0:0\x2dpart2.device loaded active plugged   VMware_Virtual_S 2
dev-disk-by\x2dpath-pci\x2d0000:00:10.0\x2dscsi\x2d0:0:0:0\x2dpart3.device loaded active plugged   VMware_Virtual_S 3
dev-disk-by\x2duuid-16e2de7b\x2db679\x2d4a12\x2d888e\x2d55081af4dad8.device loaded active plugged   VMware_Virtual_S 3
sys-devices-virtual-net-virbr0\x2dnic.device                   loaded active plugged   /sys/devices/virtual/net/virbr0-nic
[root@localhost philip]#
```

各种进程存储在`/usr/lib/systemd/system`中：

```
[root@localhost philip]# ls /usr/lib/systemd/system
abrt-ccpp.service       iscsiuio.socket          shutdown.target
abrtd.service           kdump.service            shutdown.target.wants
abrt-oops.service       kexec.target             sigpwr.target
abrt-pstoreoops.service kexec.target.wants       sleep.target
abrt-vmcore.service     kmod-static-nodes.service  -.slice
abrt-xorg.service       kpatch.service            slices.target
accounts-daemon.service ksm.service               smartcard.target
alsa-restore.service    ksmtuned.service          smartd.service
alsa-state.service      libstoragemgmt.service    sockets.target
alsa-store.service      libvirtd.service          sockets.target.wants
[root@localhost philip]#
```

正如您所看到的，有各种各样的进程是使用`systemctl`命令进行管理的。

# 总结

在本章中，我们处理了与在 shell 中处理进程相关的各个方面。我们从`ps`命令开始。展示了在 shell 中显示当前运行的进程的方法。接下来，我们看到了如何打印系统上运行的所有进程。然后是暴露每个进程使用的命令。然后，我们专注于过滤特定用户的输出，也可以通过用户 ID 进行过滤。之后，我们触及了对进程进行过滤，也可以通过进程 ID 进行过滤。除此之外，我们还处理了按组进行过滤。然后，我们将显示更改为树状布局。

此外，我们看到了如何获取内存和 CPU 信息；我们调用`watch`命令实时更新结果。最后，我们看到了如何使用`ps`命令结合`kill`命令终止一个进程。接下来，我们触及了`pstree`命令；这以分层格式呈现进程。我们甚至操纵了它的输出来缩小到特定的进程；此外，我们还检查了特定用户的进程。

在此之后，我们触及了`pgrep`命令，也称为进程 grep。这是另一种查找进程 ID 的方法；可以提供进程名称，也可以指定要显示的用户。在此之后，我们触及了`pkill`命令；顾名思义，它用于终止一个进程。我们在演示中看到了这一点。之后，我们使用`top`命令，使用各种技术来操作结果的输出，并探讨了如何在`top`命令中终止一个进程。

接下来，我们使用了`service`命令；我们谈到了我们通常在哪里找到它，并查看了它在较新的 Linux 发行版中的支持。使用`service`命令进行了各种演示。最后，我们使用了`systemctl`命令；这是迄今为止在使用系统的较新 Linux 发行版中管理进程的最佳方法，而不是使用 SysVinit 脚本的较旧的 Linux 发行版。

在下一章中，我们将深入探讨管理进程。有时我们希望优先考虑一个进程而不是另一个。这是下一章的重点。这不仅能让您管理系统上的进程，还能让您比其他人更有优势，从而让您更接近认证。希望能在那里见到您。

# 问题

1.  哪个命令打印在新终端中启动的进程？

A. `pkill`

B. `chmod`

C. `ps`

D. `chage`

1.  `ps`命令的哪个选项可以用于打印系统中运行的所有进程？

A. `-B`

B. `-b`

C. `-e`

D. `-x`

1.  `ps`命令的哪个选项可以用于以分层布局打印输出？

A. `-forest`

B. `--forest`

C. `--tree`

D. `-tree`

1.  `ps`命令的哪个选项用于指定用户进程？

A. `-x`

B. `-a`

C. `-u`

D. `-d`

1.  `kill`命令的哪个选项用于显示各种 SIG 术语？

A. `-`

B. `-l`

C. `-i`

D. `-d`

1.  使用`kill`命令时，哪个数字等同于`SIGKILL`？

A. `8`

B. `10`

C. `7`

D. `9`

1.  `top`命令的哪个选项可以指定用户？

A. `-u`

B. `-p`

C. `-v`

D. `-a`

1.  `top`实用程序中用哪个字母设置刷新结果的频率？

A. `-a`

B. `b`

C. `d`

D. `e`

1.  哪个选项可以用于使用`service`命令重新读取进程配置？

A. `reboot`

B. `stop`

C. `status`

D. `reload`

1.  在由`systemctl`命令管理的系统中，单位`/processes`位于哪个目录？

A. `/var/lib/systemd`

B. `/usr/lib/systemd/system`

C. `/usr/systemd/system`

D. `/usr/system/systemd`

# 进一步阅读

+   有关进程的更多信息，请参阅：[`www.tutorialspoint.com.`](https://www.tutorialspoint.com)

+   这个网站为您提供了许多有关进程的有用提示：[`www.linux.com.`](https://www.linux.com)

+   这个最后的链接为您提供了与各种命令相关的一般信息。您可以在那里发布您的问题，其他社区成员将会回答：[`www.linuxquestions.org.`](https://www.linuxquestions.org)


# 第十章：修改进程执行

在上一章中，我们揭示了暴露当前在 shell 中运行的进程的各种方法。此外，我们还看到了如何获取内存和 CPU 信息，以及如何使用`ps`命令结合`kill`命令终止进程。接下来，我们接触了`pstree`命令。接着，我们接触了`pgrep`命令；也称为进程 Grep。之后，我们接触了`pkill`命令；顾名思义，它用于终止进程。之后，我们使用了`top`命令。接下来，我们使用了`service`命令。最后，我们使用了`systemctl`命令。

与前几章相比，本章内容较少，但在资源管理方面具有重要意义。首先，进一步讨论了进程管理，这次重点是进程在进程调度器中的重要性（有时您可能会听到内核调度器这个术语；它们是指同一件事）。通常，我们面临着与资源限制相关的挑战。这将以多种方式加以解决。考虑到这一点，我们将探讨在 Linux 发行版的范围内尝试更改进程优先级时应遵循的各种准则。第一部分关注`nice`命令。接下来是`renice`命令。最后，重点将放在前台进程与后台进程上。

我们将在本章中涵盖以下主题：

+   `nice`命令

+   `renice`命令

+   前台进程与后台进程

# nice 命令

简而言之，`nice`命令用于调整进程的 niceness，以便与 CPU 资源的可用性相关。当我们说“niceness”时，这是指对特定进程在 CPU 资源方面给予的关注或优先级。我们可以增加或减少给定进程的优先级。每当 CPU 被一系列进程拖垮时，这就变得相关起来，每个进程都在争夺自己的关注。通过改变特定进程的 niceness，我们影响了进程的调度。

我们可以使用`ps`命令查看进程的当前`nice`值；我们会传递`al`选项：

```
root@ubuntu:/home/philip# ps -al
F S UID PID  PPID C PRI  NI ADDR SZ WCHAN TTY  TIME CMD
4 S  0  2423 2271 0 80   0 - 13698 poll_s pts/17   00:00:00 sudo
4 S  0   2437 2423 0 80  0 - 13594 wait   pts/17   00:00:00 su
4 S  0   2438 2437 0 80  0 - 5304 wait   pts/17   00:00:00 bash
0 R  0   3063 2438 0 80  0 - 7229 -      pts/17   00:00:00 ps
root@ubuntu:/home/philip#
```

出于简洁起见，某些输出已被省略。根据前面的输出，`NI`列代表进程的当前 niceness。您会注意到大多数进程的 niceness 值都设置为`0`。我们还可以过滤`ps`命令的输出；我们可以使用`grep`命令：

```
root@ubuntu:/home/philip# ps -eo pid,ppid,ni,comm | grep update
 2402   1841   0 update-notifier
 2421   1611  10 update-manager
root@ubuntu:/home/philip#
```

干得漂亮！基于此，我们可以看到有一些进程的 niceness 值默认不是`0`。有趣的是，我们还可以利用另一个命令来查看进程的当前 niceness；我们可以使用`top`命令：

```
root@ubuntu:/home/philip# top
PID USER   PR  NI    VIRT   RES  SHR S %CPU %MEM   TIME+   COMMAND                                           3020 root  20   0   41800  3880  3176 R  6.7  0.4   0:00.01 top 
1 root     20   0  185164  4532  3100 S  0.0  0.5   0:01.92 systemd 
2 root     20   0     0   0     0 S  0.0  0.0   0:00.00   kthreadd                                         3 root    20    0     0   0     0 S  0.0  0.0   0:00.16  ksoftirqd/0 
9 root    rt   0     0    0     0 S  0.0  0.0   0:00.00  migration/0 
10 root   rt   0     0    0     0 S  0.0  0.0   0:00.00  watchdog/0 
15 root   0   -20    0    0     0 S  0.0  0.0   0:00.00  writeback 
16 root   25   5     0    0     0 S  0.0  0.0   0:00.00  ksmd 
17 root   39  19     0    0     0 S  0.0  0.0   0:00.00  khugepaged 
```

第四列`NI`代表每个进程的 niceness。另一个关键列是第三列`PR`；这代表 Linux 内核所看到的实际优先级。`PRI`列不可由用户配置。此外，`PRI`列下的`rt`表示这些进程的优先级是由实时调度处理的。

我们不能改变`PRI`列下的值。

我们可以通过传递`--help`选项来查看`nice`命令的语法：

```
root@ubuntu:/home/philip# nice --help
Usage: nice [OPTION] [COMMAND [ARG]...]
Run COMMAND with an adjusted niceness, which affects process scheduling.
With no COMMAND, print the current niceness.  Niceness values range from
-20 (most favorable to the process) to 19 (least favorable to the process).
Mandatory arguments to long options are mandatory for short options too.
 -n, --adjustment=N   add integer N to the niceness (default 10)
 --help     display this help and exit
 --version  output version information and exit
```

您的 shell 可能有自己的`nice`版本，通常会取代此处描述的版本。有关其支持的选项的详细信息，请参阅您的 shell 文档。

GNU coreutils 在线帮助可以在以下网址找到：[`www.gnu.org/software/coreutils`](http://www.gnu.org/software/coreutils)

完整的文档可以在以下网址找到：[`www.gnu.org/software/coreutils/nice`](http://www.gnu.org/software/coreutils/nice)

或者在本地通过以下方式查看：info '(coreutils) nice invocation'

`root@ubuntu:/home/philip#`

根据前述语法，我们可以设置的范围是从`-19（最高优先级）到 20（最低优先级）`。让我们运行不带任何选项的`nice`命令：

```
root@ubuntu:/home/philip# nice
0
root@ubuntu:/home/philip#
```

很好！值`0`表示启动 shell 的优先级。请记住，普通用户无法更改其他用户的进程的优先级；只有 root 用户才能更改任何用户的优先级。默认情况下，如果我们运行`nice`命令而没有指定优先级值，那么优先级将设置为`10`。让我们验证一下：

```
root@ubuntu:/home/philip# ps -alx | grep cron
1  0  3419  1611  30 10  29008  2540 hrtime SNs  ?   0:00 cron
0  0  3435 2438 20 0 14224 952 pipe_w S+ pts/17 0:00 grep --color=auto cron
root@ubuntu:/home/philip# nice cron
cron: can't lock /var/run/crond.pid, otherpid may be 3419: Resource temporarily unavailable
root@ubuntu:/home/philip#
```

根据前面的输出，`NI`值没有改变。这是因为进程已经启动。`nice`命令无法改变当前正在运行的进程的优先级。我们可以通过停止进程来解决这个问题：

```
root@ubuntu:/home/philip# systemctl stop cron
root@ubuntu:/home/philip#
```

现在，让我们尝试使用`nice`命令启动`cron`进程：

```
root@ubuntu:/home/philip# ps -alx | grep cron
0     0   3463   2438  20   0  14224   900 pipe_w S+   pts/17     0:00 grep --color=auto cron
root@ubuntu:/home/philip# nice cron
root@ubuntu:/home/philip# ps -alx | grep cron
1 0 3467 1611 30 10 29008  2732 hrtime SNs  ? 0:00 cron
0 0 3469 2438 20 0 14224 940 pipe_w S+ pts/17 0:00 grep --color=auto cron
root@ubuntu:/home/philip#
```

太棒了！我们可以清楚地看到`NI`值已更改为`10`，即使我们没有指定优先级值。如果我们想指定一个值，那么我们通过在数字前面放置一个`-`来传递它。让我们再次使用`cron`进程：

```
root@ubuntu:/home/philip# systemctl stop cron
root@ubuntu:/home/philip# systemctl status cron
cron.service - Regular background program processing daemon
 Loaded: loaded (/lib/systemd/system/cron.service; enabled; vendor preset: enabled)
 Active: failed (Result: exit-code) since Thu 2018-08-16 11:30:00 PDT; 8min ago
 Docs: man:cron(8)
 Process: 3430 ExecStart=/usr/sbin/cron -f $EXTRA_OPTS (code=exited, status=1/FAILURE)
 Main PID: 3430 (code=exited, status=1/FAILURE)
root@ubuntu:/home/philip# pgrep cron
3467
root@ubuntu:/home/philip#
```

有时，停止进程时可能会遇到类似的错误。您可以使用`systemctl`命令或`service`命令，但进程仍将继续运行。我们可以通过使用前一章学到的知识轻松解决这个问题；我们可以调用`kill`命令：

```
root@ubuntu:/home/philip# kill -9 3467
root@ubuntu:/home/philip# pgrep cron
root@ubuntu:/home/philip#
```

干得好！现在让我们尝试使用一个优先级值启动`cron`进程：

```
root@ubuntu:/home/philip# nice -15 cron
root@ubuntu:/home/philip# pgrep cron
3636
root@ubuntu:/home/philip# ps -alx | grep cron
1 0 3636 1611  35 15 29008 2616 hrtime SNs  ?  0:00 cron
0 0 3658 2438  20 0 14224 920 pipe_w S+ pts/17 0:00 grep --color=auto cron
root@ubuntu:/home/philip#
```

但是有一个问题。如果我们运行`system1`命令来检查状态，我们将看到以下内容：

```
root@ubuntu:/home/philip# systemctl status cron
cron.service - Regular background program processing daemon
 Loaded: loaded (/lib/systemd/system/cron.service; enabled; vendor preset: enabled)
 Active: failed (Result: exit-code) since Thu 2018-08-16 11:30:00 PDT; 21min ago
 Docs: man:cron(8)
 Process: 3430 ExecStart=/usr/sbin/cron -f $EXTRA_OPTS (code=exited, status=1/FAILURE)
 Main PID: 3430 (code=exited, status=1/FAILURE)
Aug 16 11:30:00 ubuntu systemd[1]: cron.service: Unit entered failed state.
Aug 16 11:30:00 ubuntu systemd[1]: cron.service: Failed with result 'exit-code'.
root@ubuntu:/home/philip#
```

我们收到此错误的原因是，当我们使用使用`systemd`的 Linux 发行版时，我们需要编辑`/lib/systemd/system/`中的服务文件。在我们的情况下，它将是`/lib/systemd/system/cron.service`。这是`/lib/systemd/system/cron.service`配置文件：

```
root@ubuntu:/home/philip# cat /lib/systemd/system/cron.service
[Unit]
Description=Regular background program processing daemon
Documentation=man:cron(8)
[Service]
EnvironmentFile=-/etc/default/cron
ExecStart=/usr/sbin/cron -f $EXTRA_OPTS
IgnoreSIGPIPE=false
KillMode=process
[Install]
WantedBy=multi-user.target
root@ubuntu:/home/philip#
```

`[Service]`部分是我们放置`Nice=value`的地方。这是我们将存储`cron`进程的优先级并消除`systemctl`正在生成的错误的方法：

```
root@ubuntu:/home/philip# cat /lib/systemd/system/cron.service
[Unit]
Description=Regular background program processing daemon
Documentation=man:cron(8)
[Service]
Nice=15
EnvironmentFile=-/etc/default/cron
ExecStart=/usr/sbin/cron -f $EXTRA_OPTS
IgnoreSIGPIPE=false
KillMode=process
[Install]
WantedBy=multi-user.target
root@ubuntu:/home/philip#
```

现在，一旦我们对`systemd`服务进行了任何更改，我们需要运行这个命令：

```
root@ubuntu:/home/philip# systemctl daemon-reload
root@ubuntu:/home/philip#
```

太棒了！此外，您希望在`ExecStart`之前放置`Nice=`，因为如果您将其放在之后，它将不会对进程产生影响。我们现在将停止现有的`cron`进程并使用`systemctl`启动`cron`；错误将消失，`systemctl`将很高兴：

```
root@ubuntu:/home/philip# systemctl stop cron
root@ubuntu:/home/philip# ps -alx | grep cro
0   0 3904  2438 20  0  14224  1016 pipe_w S+ pts/17  0:00 grep --color=auto cro
root@ubuntu:/home/philip# systemctl start cron
root@ubuntu:/home/philip# ps -alx | grep cro
4  0 3907  1  35  15  29008  2988 hrtime SNs  ?  0:00 /usr/sbin/cron -f
0  0 3911  2438  20  0 14224  1024 pipe_w S+   pts/17     0:00 grep --color=auto cro
root@ubuntu:/home/philip#
```

干得好！现在我们可以看到`cron`进程的`NI`设置为`15`。这仅适用于`cron`等系统服务。另一种方法是传递`--adjustment=`选项；我们将在等号（`=`）后指定一个优先级值：

```
root@ubuntu:/home/philip# systemctl stop cron
root@ubuntu:/home/philip# nice --adjustment=13 cron
root@ubuntu:/home/philip# ps -alx | grep cro
1  0 3941   1611  33  13  29008  2576 hrtime SNs  ?   0:00 cron
0  0 3943   2438  20   0  14224  1008 pipe_w S+  pts/17 0:00 grep --color=auto cro
root@ubuntu:/home/philip#
```

当然，`systemctl`会抱怨：

```
root@ubuntu:/home/philip# systemctl status cron
cron.service - Regular background program processing daemon
 Loaded: loaded (/lib/systemd/system/cron.service; enabled; vendor preset: enabled)
 Active: inactive (dead) since Thu 2018-08-16 12:13:32 PDT; 1min 3s ago
 Docs: man:cron(8)
 Process: 3907 ExecStart=/usr/sbin/cron -f $EXTRA_OPTS (code=killed, signal=TERM)
 Main PID: 3907 (code=killed, signal=TERM)
root@ubuntu:/home/philip#
```

但是我们可以很容易地通过使用我们刚学到的技术来解决这个问题；通过在`/lib/systemd/system/cron.service`中指定声明：

```
root@ubuntu:/home/philip# cat /lib/systemd/system/cron.service
[Unit]
Description=Regular background program processing daemon
Documentation=man:cron(8)
[Service]
Nice=13
EnvironmentFile=-/etc/default/cron
ExecStart=/usr/sbin/cron -f $EXTRA_OPTS
IgnoreSIGPIPE=false
KillMode=process
[Install]
WantedBy=multi-user.target
root@ubuntu:/home/philip#
root@ubuntu:/home/philip# systemctl daemon-reload
root@ubuntu:/home/philip# systemctl start cron
root@ubuntu:/home/philip# ps -alx | grep cro
4  0  4084   1  33  13  29008  2956 hrtime SNs ? 0:00 /usr/sbin/cron -f
0  0  4088   2438  20   0  14224  1076 pipe_w S+   pts/17  0:00 grep --color=auto cro
root@ubuntu:/home/philip#
```

太棒了！

在修改系统进程时要非常谨慎，就像在这些演示中看到的那样。

# renice 命令

当我们使用`nice`命令时，很明显它无法更改正在运行的进程的调度优先级；正如我们刚才看到的，我们需要停止然后启动进程。这就是`renice`命令的优势所在。我们可以利用`renice`命令在进程运行时更改优先级。要查看语法，我们将传递`--help`选项：

```
root@ubuntu:/home/philip# renice --help
Usage:
 renice [-n] <priority> [-p|--pid] <pid>...
renice [-n] <priority>  -g|--pgrp <pgid>...
 renice [-n] <priority>  -u|--user <user>...
Alter the priority of running processes.
Options:
 -n, --priority <num>   specify the nice increment value
 -p, --pid <id>         interpret argument as process ID (default)
 -g, --pgrp <id>        interpret argument as process group ID
 -u, --user <name>|<id> interpret argument as username or user ID
 -h, --help     display this help and exit
 -V, --version  output version information and exit
For more details see renice(1).
root@ubuntu:/home/philip#
```

首先，让我们使用`ps`命令查看进程的优先级，然后更改其优先级：

```
root@ubuntu:/home/philip# ps -alx | grep ssh
4     0   3375      1  20   0   9996  4900 poll_s Ss   ?          0:00 /usr/sbin/sshd -D
0    0   4196   2438  20   0  14224   936 pipe_w S+   pts/17     0:00 grep --color=auto ssh
root@ubuntu:/home/philip#
root@ubuntu:/home/philip# renice -2 3375
3375 (process ID) old priority 0, new priority -2
```

```
root@ubuntu:/home/philip# ps -alx | grep ssh
4  0  3375  1  18  -2   9996  4900 poll_s S<s  ? 0:00 /usr/sbin/sshd -D
0  0   4209   2438  20  0  14224  1080 pipe_w S+ pts/17 0:00 grep --color=auto ssh
root@ubuntu:/home/philip#
```

根据前面的输出，`renice`命令期望进程的 PID。此外，当我们指定一个`-`后跟一个数字时，它会将其解释为负`-`号并分配一个负值。此外，`systemctl`命令不会抱怨，因为使用`renice`命令时不需要停止和启动进程以应用更改：

```
root@ubuntu:/home/philip# systemctl status sshd
ssh.service - OpenBSD Secure Shell server
Loaded: loaded (/lib/systemd/system/ssh.service; enabled; vendor preset: enabled)
Active: active (running) since Thu 2018-08-16 11:25:39 PDT; 1h 20min ago
 Main PID: 3375 (sshd)
CGroup: /system.slice/ssh.service
└─3375 /usr/sbin/sshd -D
root@ubuntu:/home/philip#
```

干得好！我们还可以为特定用户更改优先级；我们将传递`-u`选项。让我们为所有属于某个用户的进程更改优先级：

```
root@ubuntu:/home/philip# ps -alu philip
F S UID  PID PPID C  PRI  NI ADDR SZ WCHAN  TTY  TIME CMD
4 S  1000 1507 1  0  80  0 - 11319 ep_pol   ?  00:00:00 systemd
5 S  1000  1508 1507 0 80 0 - 36293 sigtim  ?   00:00:00 (sd-pam)
1 S  1000  1599  1  0  80  0 - 51303 poll_s ? 00:00:00 gnome-keyring-d
4 S  1000  1611 1349  0  80 0 - 11621 poll_s ?  00:00:00 upstart
1 S  1000  1696 1611  0  80  0 - 10932 ep_pol ? 00:00:00 dbus-daemon
0 S  1000   1708  1611 0 80 0 - 21586 poll_s ? 00:00:00 window-stack-br
1 S  1000   1721 1611  0  80 0 - 8215 poll_s ? 00:00:00 upstart-udev-br
1 S  1000   1735   1611 0 80 0 - 8198 poll_s ? 00:00:00 upstart-dbus-br
1 S  1000 1737 1611  0 80  0 -  8198 poll_s ? 00:00:00 upstart-dbus-br
1 S  1000 1743 1611  0 80 0 - 10321 poll_s ? 00:00:00 upstart-file-br
root@ubuntu:/home/philip# renice 3 -u philip
root@ubuntu:/home/philip # ps -alu philip
F S UID PID   PPID  C PRI  NI ADDR SZ WCHAN TTY TIME CMD
4 S  1000 1507  1   0  83 3 - 11319 ep_pol ? 00:00:00 systemd
5 S  1000 1508  1507 0 83  3 - 36293 sigtim ? 00:00:00 (sd-pam)
1 S  1000 1599  1   0  83  3 - 51303 poll_s ? 00:00:00 gnome-keyring-d
4 S  1000 1611  1349 0  83 3 - 11621 poll_s ? 00:00:00 upstart
1 S  1000 1696  1611 0  83 3 - 10932 ep_pol ? 00:00:00 dbus-daemon
0 S  1000 1708  1611 0 83  3 - 21586 poll_s ? 00:00:00 window-stack-br
1 S  1000 1721  1611 0 83  3 - 8215 poll_s ? 00:00:00 upstart-udev-br
1 S  1000 1735  1611 0 83  3 - 8198 poll_s ? 00:00:00 upstart-dbus-br
1 S  1000 1737  1611 0 83  3 - 8198 poll_s ? 00:00:00 upstart-dbus-br
1 S  1000 1743  1611 0  83 3 - 10321 poll_s ? 00:00:00 upstart-file-br
```

干得好！已经为指定用户拥有的每个进程更改了优先级。

# 前台进程与后台进程

在 shell 中工作时，实际上是在所谓的前台工作；除非我们停止当前进程，否则我们无法执行任何其他任务。有时候，您会想要将一些进程发送到后台进行处理；这将允许您在 shell 中继续工作，同时后台中的进程也在运行。要验证是否有任何后台运行的进程，我们可以使用`jobs`命令。让我们试一试：

```
root@ubuntu:/home/philip# jobs
root@ubuntu:/home/philip#
```

从前面的输出中，我们可以看到当前没有作业在后台运行。要了解进程如何影响您在 shell 中的工作，让我们看看`yes`实用程序；这可以在大多数 Linux 发行版中找到。`yes`实用程序将一直运行，直到我们暂停或停止它；当我们执行`yes`实用程序时，它将阻止我们执行任何命令：

```
root@ubuntu:/home/philip# yes
y
y
y
```

要停止此实用程序，我们将使用*Ctrl* + *C*的组合：

```
y
^C
root@ubuntu:/home/philip#
```

这将无意中停止`yes`实用程序。`yes`实用程序的语法如下：

+   `yes <STRING>`：如果我们省略字符串，它将像前面的代码中显示的那样输出一个`y`

+   `yes <OPTIONS>`：可用选项为 version 和 help

如果我们重新运行`yes`实用程序，并且决定不停止它，而是决定暂停它，我们将使用*Ctrl* + *Z*的组合。这将实际上将`yes`实用程序放在后台：

```
root@ubuntu:/home/philip# yes
y
y
y
^Z
[1]+  Stopped                 yes
root@ubuntu:/home/philip#
```

这次，当我们运行`jobs`命令时，我们会看到有一个作业被列出：

```
root@ubuntu:/home/philip# jobs
[1]+  Stopped                 yes
root@ubuntu:/home/philip#
```

这已经暂停了`yes`实用程序并将其放在后台，使我们能够继续在命令提示符下工作。另一个例子来说明前台进程阻止 shell，从而阻止我们执行任何其他命令的概念，是我们启动了一个实用程序，例如`vim`或任何 GUI 程序。

让我们选择一个 GUI 来演示；这将更加突出这一点。我们将从 shell 启动`gedit`实用程序：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00125.jpeg)

根据前面的输出，shell 正在阻止我们输入任何其他命令，直到我们暂停或关闭`gedit`实用程序。让我们暂停`gedit`实用程序：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00126.jpeg)

从前面的输出中，您会注意到`gedit`实用程序已经冻结，这意味着我们无法从`gedit`实用程序内执行任何操作。现在让我们再次运行`jobs`命令：

```
root@ubuntu:/home/philip# jobs
[1]-  Stopped                 yes
[2]+  Stopped                 gedit
root@ubuntu:/home/philip#
```

干得好！现在有两个作业被列出。如果我们决定要恢复其中一个作业，我们可以使用另一个强大的命令：`fg`命令。`fg`命令的语法如下：

```
fg %<job id>
```

要看到这一点，让我们从其停止状态恢复`gedit`实用程序：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00127.jpeg)

太棒了！现在我们可以在从命令提示符启动的`gedit`实用程序中工作。但是，有一个问题。当我们按下*Ctrl* + *Z*时，程序会停止。在实际环境中，我们希望将发送到后台的进程继续运行。这将加快我们的生产力，使我们能够执行同时进行的工作。请放心，事实上，通过另一种技术是可能的，我们可以在 shell 中执行命令时使用。`&`用于启动进程并将其发送到后台。让我们关闭`gedit`和`yes`实用程序：

```
root@ubuntu:/home/philip# fg
y
y
^C
root@ubuntu:/home/philip# jobs
root@ubuntu:/home/philip#
```

现在，我们将使用`&`启动`gedit`实用程序并将其直接发送到后台：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00128.jpeg)

干得好！现在我们可以在`gedit`实用程序中工作，或者我们可以继续在命令提示符下工作。此外，当我们运行`jobs`命令时，我们将看到`gedit`实用程序的状态为`running`：

```
root@ubuntu:/home/philip# jobs
[1]+  Running                 gedit &
root@ubuntu:/home/philip#
```

太棒了！还有另一种方法可以恢复在后台停止的作业并指示它们在后台运行。这是通过利用另一个强大的命令实现的：`bg`命令。这是我们如果已经停止了`gedit`程序，我们将如何恢复`gedit`程序并指示它在后台运行：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00129.jpeg)

干得好！`bg`命令做了两件事。首先，它恢复了`gedit`实用程序。然后在命令的末尾放置了`&`。正如我们之前看到的，`&`指示进程在后台运行。如果有多个作业，我们将指定作业 ID 或作业名称：

```
root@ubuntu:/home/philip# gnome-calculator
** (gnome-calculator:9649): WARNING **: currency.vala:407: Currency ZAR is not provided by IMF or ECB
^Z
[2]+  Stopped                 gnome-calculator
root@ubuntu:/home/philip# jobs
[1]-  Running                 gedit &
[2]+  Stopped                 gnome-calculator
root@ubuntu:/home/philip#
root@ubuntu:/home/philip# bg 2
[2]+ gnome-calculator &
root@ubuntu:/home/philip# jobs
[1]-  Running                 gedit &
[2]+  Running                 gnome-calculator &
root@ubuntu:/home/philip#
```

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00130.jpeg)

太棒了！我们可以看到这两个实用程序都是打开的，并且可以与命令提示符同时使用。

# 摘要

在本章中，我们已经介绍了处理进程的各种方法。首先，我们专注于使用`nice`命令调度进程。每当 CPU 上的工作负载上升时，各种进程都在争夺 CPU 的资源。使用各种命令暴露了每个进程的 niceness，例如：`ps`和`top`。接下来，我们进行了一些演示，演示了如何设置进程的 niceness。这使我们进入了运行`systemd`的系统；我们看到了在`systemd`系统上更改进程的 niceness 的问题。这导致我们修改了进程的配置文件，以便在启动进程时`systemd`能够识别 niceness。之后，我们转向了`renice`命令，特别是处理当前正在运行的进程以及更改正在运行的进程的 niceness 的方法。这通过更改 niceness 来说明，不仅适用于给定的进程，而且我们还能够更改由用户拥有的所有进程的 niceness。`systemd`识别了正在运行的进程的更改，而无需我们修改任何特定的配置。但是，如果进程停止并启动或重新启动，那么我们设置的 niceness 将被删除。要解决这个问题并使 niceness 持续存在，意味着编辑给定进程的配置文件。最后，我们在前台和后台的背景下处理了进程。前台进程的概念影响我们在命令提示符上工作，直到前台进程被挂起或关闭。当我们被要求执行多个操作时，这大大降低了生产力。解决方法是让进程在后台运行，从而使您能够有效地在命令提示符下执行功能。

在下一章中，我们将把注意力转向显示管理器的世界。通常，大多数用户都习惯于在 GUI 环境中工作。因此，重点将涵盖今天 Linux 发行版中普遍存在的常见显示管理器，以及当前 Linux+考试目标中的显示管理器。首先，我们将涉及**X 显示管理器**（**XDM**）。接下来，将讨论 KDE 显示管理器。然后将讨论**Gnome 显示管理器**（**GDM**）。最后，本章将涵盖**Light 显示管理器**（**LDM**）。这一章对于您的考试准备至关重要，就像以前的所有章节一样。这将使您能够使用今天 Linux 环境中常见的各种显示管理器。

# 问题

1.  使用`ps`命令的哪个选项打印每个进程的 niceness？

A. *n*

B. *l*

C. *a*

D. *x*

1.  使用`ps`命令表示每个进程的 niceness 的哪一列？

A. `NI`

B. `ni`

C. `N1`

D. `nice`

1.  使用`top`命令表示每个进程的 niceness 的哪一列？

A. `ni`

B. `PNI`

C. `pnic`

D. `NI`

1.  在使用`nice`命令时，哪个值不是有效值？

A. `-20`

B. `-19`

C. `20`

D. `19`

1.  哪个 niceness 值具有最高优先级？

A. `-21`

B. `-32`

C. `-19`

D. `-20`

1.  使用`systemd`存储进程配置文件的目录是哪个？

A. `/usr/lib/systemd/system`

B. `/lib/systemd/system`

C. `/lib/systemd/system/service`

D. `/lib/systemd/service`

1.  在使用`systemd`编辑服务文件后需要运行哪个命令？

A. `systemctl daemon-reload`

B. `systemctl --daemon-reload`

C. `systemctl daemon --reload`

D. `systemctl daemonreload`

1.  在使用`renice`命令时，指定 niceness 值后会发生什么？

A. `进程名称`

B. `PID`

C. `进程名称 + PID`

D. 以上都不是

1.  哪个命令可以从后台恢复一个进程，并阻止你执行其他命令，直到当前进程结束为止？

A. fg

B. bg

C. jobs

D. job

1.  哪个命令可以从后台恢复一个进程，但将其放在后台，允许你在命令提示符下执行其他命令？

A. `fg`

B. `jobs`

C. `bg`

D. `CTRL+C`

# 进一步阅读

+   你可以通过查看[`www.tecmint.com`](https://www.tecmint.com)来获取有关管理进程的更多信息。

+   这个网站提供了很多有用的关于处理进程的技巧和最佳实践：[`www.digitalocean.com`](https://www.digitalocean.com)。

+   这个链接提供了一般性的信息，涉及适用于 CentOS 和 Ubuntu 的各种命令。你可以在那里发布你的问题，其他社区成员将能够回答：[`www.linuxquestions.org`](https://www.linuxquestions.org)。


# 第十一章：显示管理器

在上一章中，我们介绍了处理进程的各种方法。首先，我们专注于使用`nice`命令调度进程。每当 CPU 的工作负载增加时，各种进程都在争夺 CPU 的资源；使用各种命令（如`ps`和`top`）暴露了每个进程的 niceness。之后，我们转向`renice`命令，特别是处理当前正在运行的进程，以及更改正在运行的进程的 niceness 的方法。最后，我们在前台与后台的进程上工作。

在本章中，将介绍显示管理器。通常，大多数用户习惯在 GUI 环境中工作。我们将看看当今 Linux 发行版中普遍存在的显示管理器。显示管理器有时会与桌面混淆；显示管理器管理 GUI 登录提示，该提示在用户启动时呈现。桌面是用户用来执行各种任务的 X Windows 集合。一些桌面的例子包括 XFCE KDE，GNOME 和 Unity 等。此外，还将介绍当前 Linux+考试目标中的显示管理器。首先，我们将介绍**X 显示管理器**（**XDM**）。接下来，将讨论**KDE 显示管理器**（**KDM**）。然后是**GNOME 显示管理器**（**GDM**）。最后，本章将介绍**轻量级显示管理器**（**Lightdm**）。

本章将涵盖以下主题：

+   使用 XDM

+   使用 KDM

+   使用 GDM

+   使用 Lightdm

# 使用 XDM

XDM 管理一组 X 服务器。这可以是系统上的本地 X 服务器，也可以是网络上另一个 X 服务器上的远程 X 服务器。XDM 实用程序在某种程度上类似于较旧的 SysVinit，因此您可能会对 X 服务器的概念感到困惑。X 服务器是 X Window 系统中的一个程序；它在本地机器上运行。它通常管理对图形卡、显示器以及本地机器上的键盘和鼠标的访问。那么 X Window 系统是什么？嗯，X Window 系统，通常称为 X，是一个由跨平台、免费的客户端-服务器基础设施组成的整套系统，用于管理单个或一系列计算机上的**图形用户界面**（**GUI**），就像在网络环境中一样。在 X 的上下文中，客户端/服务器的工作方式有点奇怪；每台本地机器上都运行一个 X 服务器。然后，X 服务器访问 X 客户端；X 客户端是 GUI 应用程序。另一个有趣的地方是 X 客户端可以在本地运行，也可以在网络上远程运行。X 服务器充当中间人，实际的 X 客户端与 X 服务器进行交互；然后 X 服务器与实际的显示设备进行交互。X 服务器使用**X 显示管理器控制协议**（**XDMCP**）。XDM 旨在成为命令行登录提示的图形替代品。用户提供其登录凭据后，XDM 启动其 X 会话。

使用 XDM 的第一步是安装它。我们将使用 CentOS 6.5 系统。我们将搜索`xdm`：

```
[root@localhost Desktop]# yum search xdm
Loaded plugins: fastestmirror, refresh-packagekit, security
=========================================== N/S Matched: xdm ===========================================
libXdmcp-devel.i686 : Development files for libXdmcp
libXdmcp-devel.x86_64 : Development files for libXdmcp
xorg-x11-xdm.x86_64 : X.Org X11 xdm - X Display Manager
libXdmcp.i686 : X Display Manager Control Protocol library
libXdmcp.x86_64 : X Display Manager Control Protocol library
xorg-x11-server-Xdmx.x86_64 : Distributed Multihead X Server and utilities
 Name and summary matches only, use "search all" for everything.
[root@localhost Desktop]#
```

太棒了！默认情况下，CentOS 6.5 使用 GDM；我们将安装 XDM 进行演示：

```
[root@localhost Desktop]# yum install xorg-x11-xdm.x86_64
Loaded plugins: fastestmirror, refresh-packagekit, security
Loading mirror speeds from cached hostfile
 * updates: centos.mirror.iweb.ca
Setting up Install Process
Resolving Dependencies
--> Processing Dependency: libXaw.so.7()(64bit) for package: 1:xorg-x11-xdm-1.1.6-14.1.el6.x86_64
Installed:
 xorg-x11-xdm.x86_64 1:1.1.6-14.1.el6 
Dependency Installed:
 libXaw.x86_64 0:1.0.11-2.el6                       libXpm.x86_64 0:3.5.10-2.el6 
Complete!
[root@localhost Desktop]#
```

出于简洁起见，某些输出已被省略。接下来，我们将看看配置目录；这在`/etc/X11`内：

```
[root@localhost Desktop]# ls /etc/X11
applnk  fontpath.d  prefdm  xdm  xinit  Xmodmap  xorg.conf.d  Xresources
[root@localhost Desktop]#
[root@localhost xdm]# ll
total 40
-rwxr-xr-x. 1 root root  510 Aug 19  2010 GiveConsole
-rwxr-xr-x. 1 root root  244 Aug 19  2010 TakeConsole
-rw-r--r--. 1 root root 3597 Aug 19  2010 Xaccess
-rw-r--r--. 1 root root 1394 Aug 19  2010 xdm-config
-rwxr-xr-x. 1 root root  183 Aug 19  2010 Xreset
-rw-r--r--. 1 root root 2381 Aug 19  2010 Xresources
-rw-r--r--. 1 root root  484 Aug 19  2010 Xservers
lrwxrwxrwx. 1 root root   17 Aug 24 07:55 Xsession -> ../xinit/Xsession
-rwxr-xr-x. 1 root root  938 Aug 19  2010 Xsetup_0
-rwxr-xr-x. 1 root root  181 Aug 19  2010 Xstartup
-rwxr-xr-x. 1 root root  303 Aug 19  2010 Xwilling
[root@localhost xdm]#
```

这些是使 XDM 发光的必要文件。默认情况下，CentOS 6.5 不会使用 XDM；这可以通过编辑`/etc/X11/preferdm`轻松解决：

```
[root@localhost xdm]# cat /etc/X11/prefdm
#!/bin/sh
PATH=/sbin:/usr/sbin:/bin:/usr/bin
# We need to source this so that the login screens get translated
[ -f /etc/sysconfig/i18n ] && . /etc/sysconfig/i18n
# Run preferred X Display Manager
quit_arg=
preferred=
exit 1
[root@localhost xdm]#
```

出于简洁起见，某些输出已被省略。我们应该在`preferred=`行中指定显示管理器。我们还可以编辑`/etc/sysconfig/desktop`来采取另一种方法：

```
[root@localhost xdm]# ls /etc/sysconfig | grep desktop
[root@localhost xdm]#
```

根据前面的输出，我们需要创建`/etc/sysconfig/`桌面文件。让我们试试看：

```
[root@localhost xdm]# which xdm
/usr/bin/xdm
[root@localhost xdm]# vim /etc/sysconfig/desktop
[root@localhost philip]# cat /etc/sysconfig/desktop
preferred=/usr/bin/xdm
[root@localhost philip]#
```

根据前面的示例，我们已经创建了一个文件并存储了 XDM 的位置，这是使用`which`命令得出的。`which`命令可用于查找可执行文件的位置。

现在，让我们重新启动系统以使这些更改生效：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00131.jpeg)

干得漂亮！现在我们看到了 XDM 登录界面。XDM 的配置文件存储在`/etc/X11/xdm`中：

```
[root@localhost philip]# ll /etc/X11/xdm
total 40
-rwxr-xr-x. 1 root root 510 Aug 19 2010 GiveConsole
-rwxr-xr-x. 1 root root 244 Aug 19 2010 TakeConsole
-rw-r--r--. 1 root root 3597 Aug 19 2010 Xaccess
-rw-r--r--. 1 root root 1394 Aug 19 2010 xdm-config
-rwxr-xr-x. 1 root root 183 Aug 19 2010 Xreset
-rw-r--r--. 1 root root 2381 Aug 19 2010 Xresources
-rw-r--r--. 1 root root 484 Aug 19 2010 Xservers
lrwxrwxrwx. 1 root root 17 Aug 24 07:55 Xsession -> ../xinit/Xsession
-rwxr-xr-x. 1 root root 938 Aug 19 2010 Xsetup_0
-rwxr-xr-x. 1 root root 181 Aug 19 2010 Xstartup
-rwxr-xr-x. 1 root root 303 Aug 19 2010 Xwilling
[root@localhost philip]#
```

现在我们可以专注于`/etc/X11/xdm/Xaccess`：

```
# To control which addresses xdm listens for requests on:
#  LISTEN     address [list of multicast groups ... ]
# The first form tells xdm which displays to respond to itself.
#  LISTEN     * ff02:0:0:0:0:0:0:12b
# This example shows listening for multicast on all scopes up
# to site-local
# LISTEN      * ff01:0:0:0:0:0:0:12b ff02:0:0:0:0:0:0:12b ff03:0:0:0:0:0:0:12b ff04:0:0:0:0:0:0:12b ff05:0:0:0:0:0:0:12b
[root@localhost philip]#
```

出于简洁起见，某些输出已被省略。前面的文件控制 XDM 将监听哪些地址以进行传入请求。另一个重要文件，在远程使用 XDM 时，是`/etc/X11/xdm/xdm-config`：

```
[root@localhost philip]# cat /etc/X11/xdm/xdm-config
! The following three resources set up display :0 as the console.
DisplayManager._0.setup:            /etc/X11/xdm/Xsetup_0
DisplayManager._0.startup:          /etc/X11/xdm/GiveConsole
DisplayManager._0.reset:            /etc/X11/xdm/TakeConsole
DisplayManager*loginmoveInterval:      10
! SECURITY: do not listen for XDMCP or Chooser requests
! Comment out this line if you want to manage X terminals with xdm
DisplayManager.requestPort:    0
[root@localhost philip]#
```

出于简洁起见，某些输出已被省略。最后一行`DisplayManager.requestPort: 0`需要被注释掉，以便我们可以使用 XDM 管理远程会话。

# 使用 KDM

KDM 是当今 Linux 发行版中更受欢迎的显示管理器之一。KDM 基于 X 显示管理器的源代码开发，由 KDE 开发。多年来，它一直是 KDE 框架的显示管理器，但最近发生了变化。为了看到 KDM，我们将使用`dnf`命令在我们的 Fedora 28 系统上。Fedora 28 使用 GDM。

我们将使用`groupinstall`选项为演示安装 KDE 桌面；这将安装 KDE 桌面所需的所有必要软件包：

```
[root@localhost philip]# dnf groupinstall KDE
Install  412 Packages
Upgrade    3 Packages
Total download size: 425 M
Is this ok [y/N]: y
 xorg-x11-apps.x86_64 7.7-20.fc28 
 xorg-x11-fonts-misc.noarch 7.5-19.fc28 
 xorg-x11-xbitmaps.noarch 1.1.1-13.fc28 
Upgraded:
 firewalld.noarch 0.5.3-2.fc28        firewalld-filesystem.noarch 0.5.3-2.fc28
 python3-firewall.noarch 0.5.3-2.fc28
Complete!
[root@localhost philip]#
```

接下来，我们将使用`dnf`命令安装`kdm`实用程序和其他组件：

```
[root@localhost philip]# dnf install kdm kde-settings-kdm
Last metadata expiration check: 0:12:52 ago on Mon 27 Aug 2018 11:16:03 AM EDT.
Dependencies resolved.
====================================================================
Package           Arch         Version        Repository  Size
====================================================================
Installing:
 kdm              x86_64  1:4.11.22-22.fc28    fedora     740 k
 kdm-settings     noarch  1:4.11.22-22.fc28    fedora     186 k
====================================================================
Install  5 Packages
Total download size: 1.2 M
Installed size: 2.3 M
Is this ok [y/N]: y
Installed:
 kdm.x86_64 1:4.11.22-22.fc28 
 kdm-settings.noarch 1:4.11.22-22.fc28 
 kgreeter-plugins.x86_64 1:4.11.22-22.fc28 
 libkworkspace.x86_64 1:4.11.22-22.fc28 
 qimageblitz.x86_64 0.0.6-15.fc28 
Complete!
[root@localhost philip]#
```

太棒了！出于简洁起见，某些输出已被省略。`kdm`实用程序已被安装。最后，我们将安装系统切换器；这将允许我们从 GDM 切换到 KDM：

```
[root@localhost philip]# dnf install system-switch-displaymanager.noarch
Last metadata expiration check: 0:16:52 ago on Mon 27 Aug 2018 11:16:03 AM EDT.
Dependencies resolved.
====================================================================
Package                       Arch   Version     Repository  Size
Installing:
system-switch-displaymanager noarch 1.5.1-3.fc28 fedora 17 k
Transaction Summary
Installed:
 system-switch-displaymanager.noarch 1.5.1-3.fc28 
Complete!
[root@localhost philip]#
```

干得漂亮！现在我们可以调用`system-switch`实用程序来从 GDM3 切换到 KDM：

```
[root@localhost philip]# system-switch-displaymanager KDM
Created symlink /etc/systemd/system/display-manager.service → /usr/lib/systemd/system/kdm.service.
Your default graphical display manager has successfully been switched.
[root@localhost philip]#
```

太棒了！现在，让我们重新启动我们的 Fedora 28 系统以使更改生效：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00132.jpeg)

根据前面的输出，我们现在可以看到 Fedora 28 系统正在使用`kdm`实用程序作为显示管理器，而不是`gdm`。我们还可以在会话类型下看到各种桌面。Plasma 是我们安装的 KDE 风格桌面。让我们登录到 Plasma 桌面并确认我们确实正在使用`kdm`实用程序：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00133.jpeg)

太棒了！所以我们成功地将我们的桌面更改为了 KDE 风格的 Plasma，现在我们可以查看`/etc/systemd/system/display-manager.service`以验证正在使用哪个显示管理器：

```
[root@localhost philip]# ls -l /etc/systemd/system/display-manager.service
lrwxrwxrwx. 1 root root 35 Aug 27 11:34 /etc/systemd/system/display-manager.service -> /usr/lib/systemd/system/kdm.service
[root@localhost philip]#
```

干得漂亮！我们清楚地看到我们确实已经将我们的显示管理器更改为了 KDM。我们还可以使用`systemctl`命令检查 KDM 的状态：

```
[root@localhost philip]# systemctl status kdm.service
kdm.service - The KDE login manager
 Loaded: loaded (/usr/lib/systemd/system/kdm.service; enabled; vendor preset: disabled)
 Active: active (running) since Mon 2018-08-27 11:36:40 EDT; 14min ago
 Main PID: 821 (kdm)
 Tasks: 3 (limit: 2331)
 Memory: 121.6M
 CGroup: /system.slice/kdm.service
 ├─821 /usr/bin/kdm vt1
 └─894 /usr/libexec/Xorg -br -novtswitch -quiet :0 vt1 -background none -nolisten tcp -auth /var/run/kdm/A:0-fPUysb
Aug 27 11:36:40 localhost.localdomain systemd[1]: Started The KDE login manager.
Aug 27 11:36:40 localhost.localdomain kdm[821]: plymouth is running
[root@localhost philip]#
```

根据前面的输出，我们可以看到`kdm.service`确实是活动的并正在运行。为了进一步验证，我们还可以检查 GDM 的状态：

```
[root@localhost philip]# systemctl status gdm.service
gdm.service - GNOME Display Manager
 Loaded: loaded (/usr/lib/systemd/system/gdm.service; disabled; vendor preset: disabled)
 Active: inactive (dead)
[root@localhost philip]#
```

干得漂亮！根据前面的输出，我们可以看到`gdm`实用程序目前处于非活动状态。KDM 的各种配置文件可以在`/etc/kde/kdm`中找到：

```
[root@localhost philip]# ls -l /etc/kde/kdm
-rw-r--r--. 1 root root 22985 Jun 12  2016 kdmrc
-rw-r--r--. 1 root root  3607 Apr 26  2010 Xaccess
-rw-r--r--. 1 root root  2381 Apr 26  2010 Xresources
-rwxr-xr-x. 1 root root   207 Jul  8  2008 Xsession
-rwxr-xr-x. 1 root root   938 Apr 26  2010 Xsetup
-rwxr-xr-x. 1 root root   303 Apr 26  2010 Xwilling
[root@localhost philip]#
```

根据前面的示例，我们可以看到这些文件的名称与本章前面介绍的 XDM 文件类似。

# 使用 GDM

GDM 是当今 Linux 环境中另一个流行的显示管理器。特别是在 CentOS 和 Fedora 等 Red Hat 发行版中，您会发现 GDM。它提供了一个 GUI 登录提示，用户有机会提供他们的登录凭据。此外，如果我们安装了多个桌面，我们还可以选择登录后加载哪个桌面。正如我们之前看到的，我们可以确定我们更喜欢使用哪个显示管理器。让我们为这个演示选择我们的 Ubuntu 系统。首先，让我们检查我们的 Ubuntu 16 系统上是否安装了 GDM（Ubuntu 中的 GDM3）：

```
root@ubuntu:/etc# ls /etc/ | grep gdm3
root@ubuntu:/etc# ls /etc/X11/
app-defaults  default-display-manager  openbox  xdm    xkb                 Xreset    Xresources  Xsession.d        xsm
cursors       fonts                    rgb.txt  xinit  xorg.conf.failsafe  Xreset.d  Xsession    Xsession.options
root@ubuntu:/etc#
```

根据前面的输出，GDM3 目前尚未安装。让我们也添加一个桌面，以便我们可以看到选择桌面的选项在哪里。我们将在我们的 Ubuntu 系统中安装 GNOME 桌面。我们将使用`apt-get`命令，特别是`ubuntu-gnome-desktop`软件包：

```
root@ubuntu:/etc# apt-get install ubuntu-gnome-desktop
Reading package lists... Done
Building dependency tree 
Reading state information... Done
The following additional packages will be installed:
python-boto python-cffi-backend python-chardet python-cloudfiles python-cryptography python-enum34 python-idna python-ipaddress
 python-libxml2 python-lockfile python-ndg-httpsclient python-openssl python-pkg-resources python-pyasn1 python-requests python-six
 python-urllib3 rhythmbox-plugin-magnatune seahorse-daemon ssh-askpass-gnome telepathy-gabble telepathy-haze telepathy-idle
 telepathy-logger telepathy-salut tracker tracker-extract tracker-miner-fs ubuntu-gnome-default-settings ubuntu-gnome-wallpapers
 ubuntu-gnome-wallpapers-xenial unoconv wodim xserver-xorg-legacy xsltproc yelp-tools zsync
Suggested packages:
 argyll-doc gir1.2-colordgtk-1.0 db5.3-util vcdimager libdvdcss2 dvdauthor readom python-paramiko python-oauthlib ncftp lftp
After this operation, 447 MB of additional disk space will be used.
Do you want to continue? [Y/n] y
Processing triggers for initramfs-tools (0.122ubuntu8.11) ...
update-initramfs: Generating /boot/initrd.img-4.4.0-134-generic
root@ubuntu:/etc#
```

出于简洁起见，某些输出已被省略。接下来，让我们安装`gdm`实用程序。请注意，在 Ubuntu 中它的名称是`gdm3`，而在 Fedora 中它的名称是`gdm`，两者是相同的，只是命名约定不同。

在处理 Debian 发行版时，请考虑`gdm3`，在处理 Red Hat 发行版时，请考虑`gdm`。

当我们安装`ubuntu-gnome-desktop`时，实际上为我们安装了`gdm3`，为我们节省了一些时间。我们可以通过查看`/etc`来验证这一点：

```
root@ubuntu:/etc# ls -l /etc | grep gdm
drwxr-xr-x  8 root root    4096 Aug 27 11:43 gdm3
root@ubuntu:/etc#
```

太棒了！根据之前的代码，我们可以看到`gdm3`实际上已经安装。目前，这不会更改显示管理器，因为我们尚未指定要使用`gdm3`。要解决这个问题，我们只需运行`dpkg-reconfigure`命令并传递`gdm3`：

```
root@ubuntu:/etc# dpkg-reconfigure gdm3
```

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00134.jpeg)

根据前面的输出，Lightdm 被设置为默认的显示管理器。我们可以使用键盘上下滚动并选择要设置为默认的显示管理器。我们将选择 gdm3：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00135.jpeg)

```
root@ubuntu:/etc# dpkg-reconfigure gdm3
root@ubuntu:/etc#
```

干得好！现在，我们可以检查`/etc/X11/`来验证当前设置的显示管理器：

```
root@ubuntu:/etc# cat /etc/X11/default-display-manager
/usr/sbin/gdm3
root@ubuntu:/etc#
```

根据以前的代码，我们可以看到`gdm3`已经设置。我们可以使用`systemctl`命令来采用另一种技术：

```
root@ubuntu:/etc# systemctl status lightdm
lightdm.service - Light Display Manager
 Loaded: loaded (/lib/systemd/system/lightdm.service; static; vendor preset: enabled)
 Drop-In: /lib/systemd/system/display-manager.service.d
 └─xdiagnose.conf
 Active: active (running) since Fri 2018-08-24 12:46:32 PDT; 2 days ago
 Docs: man:lightdm(1)
 Main PID: 1011 (lightdm)
 CGroup: /system.slice/lightdm.service
 ├─1011 /usr/sbin/lightdm
 └─1038 /usr/lib/xorg/Xorg -core :0 -seat seat0 -auth /var/run/lightdm/root/:0 -nolisten tcp vt7 -novtswitch
Warning: Journal has been rotated since unit was started. Log output is incomplete or unavailable.
root@ubuntu:/etc#
```

根据前面的代码，我们可以看到当前的 Lightdm 仍然处于活动状态。现在，让我们检查`gdm3`：

```
root@ubuntu:/etc# systemctl status gdm3
gdm.service - GNOME Display Manager
 Loaded: loaded (/lib/systemd/system/gdm.service; static; vendor preset: enabled)
 Active: inactive (dead)
root@ubuntu:/etc#
```

根据那个输出，我们可能会认为我们有问题，但事实是只有当我们重新启动系统时，更改才会生效：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00136.jpeg)

太棒了！根据之前的截图，我们可以看到系统已经启动了 GDM3。此外，我们可以选择要加载的桌面。让我们选择 GNOME。现在，让我们重新运行`systemctl`命令来验证我们确实正在运行 GDM3：

```
root@ubuntu:/home/philip# systemctl status lightdm
lightdm.service - Light Display Manager
 Loaded: loaded (/lib/systemd/system/lightdm.service; static; vendor preset: e
 Active: inactive (dead)
 Docs: man:lightdm(1)
root@ubuntu:/home/philip#
```

看起来不错！现在让我们检查一下 GDM3：

```
root@ubuntu:/home/philip# systemctl status gdm
gdm.service - GNOME Display Manager
 Loaded: loaded (/lib/systemd/system/gdm.service; static; vendor preset: enabl
 Drop-In: /lib/systemd/system/display-manager.service.d
 └─xdiagnose.conf
 Active: active (running) since Mon 2018-08-27 12:33:26 PDT; 3min 22s ago
 Process: 990 ExecStartPre=/usr/share/gdm/generate-config (code=exited, status=
 Process: 983 ExecStartPre=/bin/sh -c [ "$(cat /etc/X11/default-display-manager
 Main PID: 1006 (gdm3)
 CGroup: /system.slice/gdm.service
 └─1006 /usr/sbin/gdm3
root@ubuntu:/home/philip#
```

太棒了！根据我们在前面的输出中看到的，毫无疑问，我们正在运行 GDM3。

# 使用 Lightdm

**轻型显示管理器**，即**Lightdm**或`lightdm`（在命令行上），一直在 Linux 世界中引起轰动。Lightdm 曾取代 KDM，并且是 Ubuntu 16 之前的首选显示管理器。在后来的 Ubuntu 版本中，它被 GDM 取代。它提供了一个 GUI 来管理用户登录。Lightdm 是跨平台的，这意味着它支持各种桌面。让我们在我们的 Fedora 28 系统中安装 Lightdm。以前我们有 KDM。让我们使用`dnf`命令：

```
[root@localhost philip]# dnf install lightdm lightdm-gtk
ast metadata expiration check: 4:55:54 ago on Mon 27 Aug 2018 11:16:03 AM EDT.
Dependencies resolved.
==============================================================
Package           Arch      Version       Repository     Size
==============================================================
Installing:
lightdm          x86_64   1.26.0-1.fc28     updates      222 k
lightdm-gtk      x86_64   2.0.5-1.fc28      fedora       139 k
Installing dependencies:
lightdm-gobject  x86_64   1.26.0-1.fc28     updates       72 k
Transaction Summary
==============================================================
Install  3 Packages
Total download size: 433 k
Installed size: 1.2 M
Is this ok [y/N]: y
Installed:
 lightdm.x86_64 1.26.0-1.fc28   lightdm-gtk.x86_64 2.0.5-1.fc28           lightdm-gobject.x86_64 1.26.0-1.fc28 
Complete!
[root@localhost philip]#
```

太棒了！现在我们将使用`system-switch-displaymanger`命令切换到`lightdm`：

```
[root@localhost philip]# system-switch-displaymanager lightdm
Created symlink /etc/systemd/system/display-manager.service → /usr/lib/systemd/system/lightdm.service.
Your default graphical display manager has successfully been switched.
[root@localhost philip]#
```

为了验证，我们可以使用`ls`命令查看`systemd`中的服务：

```
[root@localhost philip]# ls -l /etc/systemd/system/display-manager.service
lrwxrwxrwx. 1 root root 39 Aug 27 16:17 /etc/systemd/system/display-manager.service -> /usr/lib/systemd/system/lightdm.service
[root@localhost philip]#
```

太棒了！我们还可以使用`systemctl`命令来检查显示管理器的状态：

```
[root@localhost philip]# systemctl status kdm
kdm.service - The KDE login manager
 Loaded: loaded (/usr/lib/systemd/system/kdm.service; disabled; vendor preset: disabled)
 Active: active (running) since Mon 2018-08-27 11:36:40 EDT; 4h 42min ago
 Main PID: 821 (kdm)
 Tasks: 3 (limit: 2331)
 Memory: 101.0M
[root@localhost philip]#
```

根据以前的代码，我们可以看到 KDM 仍然处于活动状态。让我们检查一下`lightdm`：

```
[root@localhost philip]# systemctl status lightdm
lightdm.service - Light Display Manager
 Loaded: loaded (/usr/lib/systemd/system/lightdm.service; enabled; vendor preset: disabled)
 Active: inactive (dead)
 Docs: man:lightdm(1)
[root@localhost philip]#
```

要使更改生效，请重新启动系统：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00137.jpeg)

太棒了！根据前面的代码，我们现在在我们的 Fedora 28 系统中运行 Lightdm。此外，我们可以选择在屏幕右上角加载哪个桌面。登录后，我们可以进行验证。我们将使用`systemctl`命令：

```
[root@localhost philip]# systemctl status kdm
kdm.service - The KDE login manager
 Loaded: loaded (/usr/lib/systemd/system/kdm.service; disabled; vendor preset: disabled)
 Active: inactive (dead)
[root@localhost philip]#
```

这就是我们希望看到的。同样，当我们检查`lightdm`时，我们看到以下内容：

```
[root@localhost philip]# systemctl status lightdm
lightdm.service - Light Display Manager
 Loaded: loaded (/usr/lib/systemd/system/lightdm.service; enabled; vendor preset: disabled)
 Active: active (running) since Mon 2018-08-27 16:23:18 EDT; 4min 0s ago
 Docs: man:lightdm(1)
 Main PID: 840 (lightdm)
 Tasks: 8 (limit: 2331)
 Memory: 84.3M
[root@localhost philip]#
```

干得好！根据那个，我们可以确认我们在我们的 Fedora 28 系统中运行 Lightdm。

# 总结

在本章中，我们的重点是显示管理器，特别是 XDM、KDM、GDM 和 Lightdm。还确定了显示管理器和桌面之间的区别。我们首先在 CentOS 系统中使用 XDM 进行工作。我们关注了 XDM 存储的目录。除此之外，我们还关注了 XDM 的访问控制。接下来，我们将注意力转移到 KDM；KDM 在 Ubuntu 发行版中占主导地位，直到后来被替换。我们概述了安装和配置系统以使用 KDM 的方法。接下来，我们转向了 GDM。我们看到 GDM 在大多数 Linux 发行版中实际上是如何使用的。在 Ubuntu 和 Fedora 发行版中工作时，突出了名称的不同。我们演示了安装 GDM 的步骤。此外，我们还涵盖了在混合环境中安装一些桌面；这被证明是相当简单的。然后，还演示了选择桌面的过程。最后，我们介绍了 Lightdm。Lightdm 也很受欢迎，因为它在 Ubuntu 中取代了 KDM，并最终被 GDM 取代。我们使用 Fedora 28 发行版重点介绍了运行 Lightdm 的技术。本章的重点是安装显示管理器和在显示管理器之间切换的过程。

在下一章中，重点将放在用户和组帐户上。到目前为止，我们一直在处理 Linux 环境中的各个方面。首先，将重点放在管理用户帐户的过程上（例如用户创建和删除，目录修改，设置密码，权限和所有权）。接下来，将关注组。我们将深入探讨用于管理组的技术，创建和删除组的过程，将用户分配到组和权限等。我鼓励您再次加入我，以便在即将到来的章节中更好地为管理用户和组做好准备。

# 问题

1.  XDM 代表什么？

A. X 显示管理器

B. XD 管理器

C. X 桌面管理器

D. 以上都不是

1.  XDM 配置文件存储在哪个目录中？

A. `/etc/XDM/xdm`

B. `/etc/X11/xdm`

C. `/etc/X1/xdm`

D. `/etc/XM/xdm`

1.  哪个配置文件控制 XDM 的资源？

A. `Xaccess`

B. `Xresources`

C. `Xsession`

D. `Xdisplay`

1.  CentOS 6.5 中哪个配置文件指定要使用哪个显示管理器？

A. `/etc/desktop`

B. `/etc/X11/xdm`

C. `/etc/sysconfig/desktop`

D. `/etc/desktop`

1.  `dnf`命令中的哪个选项可以用来安装 KDE 桌面作为一个完整的包？

A. `--install`

B. `groupinstall`

C. `--group`

D. `--install-group`

1.  在 Fedora 28 中用于更改显示管理器的软件包是什么？

A. `displaymanager-switcher`

B. `system-displaymanager`

C. `system-switch-displaymanager`

D. `switch-displaymanager`

1.  KDM 登录提示中的哪个选项允许用户指定要加载哪个桌面？

A. 会话类型

B. 桌面类型

C. 登录桌面类型

D. 会话桌面

1.  哪个命令用于在 Ubuntu 16 中在显示管理器之间切换？

A. `chage`

B. `apt-cache`

C. `system-switcher`

D. `dpkg-reconfigure`

1.  Ubuntu 16 中的哪个配置文件显示默认的显示管理器？

A. `/etc/desktop`

B. `/etc/preferdm`

C. `/etc/X11/default-display-manager`

D. `/default-display-manager`

1.  哪个命令可以将 Fedora 28 中当前的显示管理器识别为一个服务？

A. `ls -l /etc/systemd/system/display.manager.service`

B. `ls -l /etc/systemd/system/display-manager.service`

C. `ls -l /etc/systemd/system/dm.service`

D. `ls -l /etc/systemd/system/display.service`

# 进一步阅读

+   这个网站提供了关于 GDM 的有用信息：[`wiki.gnome.org`](https://wiki.gnome.org)

+   这个网站提供了关于 KDM 的有用信息：[`forum.kde.org`](https://forum.kde.org)

+   这个网站提供了关于各种显示管理器的有用信息：[`superuser.com`](https://superuser.com)
