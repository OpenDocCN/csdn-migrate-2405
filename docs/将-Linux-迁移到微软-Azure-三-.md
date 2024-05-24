# 将 Linux 迁移到微软 Azure（三）

> 原文：[`zh.annas-archive.org/md5/DFC4E6F489A560394D390945DB597424`](https://zh.annas-archive.org/md5/DFC4E6F489A560394D390945DB597424)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：诊断和纠正防火墙问题

在上一章中，我们发现了如何使用`telnet`、`ping`、`curl`、`netstat`、`tcpdump`和`ip`等命令来解决与网络相关的问题。您还了解了**TCP 协议**的工作原理，以及如何使用**DNS**将域名转换为 IP。

在本章中，我们将再次解决与网络相关的问题；然而，这一次我们将了解 Linux 的软件防火墙`iptables`的工作原理以及如何解决防火墙引起的网络问题。

# 诊断防火墙

第五章*网络故障排除*是关于网络和如何排除网络配置错误的。在本章中，我们将把这个讨论扩展到防火墙。在解决防火墙问题时，我们可能会使用与第五章*网络故障排除*相同的一些命令，并重复很多相同的过程。这是因为每当你使用防火墙来保护系统时，你都会阻止某些类型的网络流量，防火墙的配置错误可能会影响系统的任何网络流量。

我们将像其他章节一样，从解决报告的问题开始这一章。

# 似曾相识

在第五章*网络故障排除*中，我们的故障排除是在一位开发人员打来电话报告公司的博客报告了数据库连接错误后开始的。经过故障排除，我们发现这个错误是由于数据库服务器上的静态路由配置错误造成的。然而，今天（几天后），我们再次接到同一开发人员报告相同的问题。

当开发人员访问`http://blog.example.com`时，他收到一个错误，指出存在数据库连接问题。*又来了！*

由于数据收集的第一步是复制问题，我们应该做的第一件事是在我们自己的浏览器上打开公司的博客。

![似曾相识](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel-tbst-gd/img/00007.jpeg)

事实上，似乎同样的错误再次出现了；现在要找出原因。

# 从历史问题中解决问题

**数据收集器**的第一反应可能是简单地按照第五章*网络故障排除*中的相同故障排除步骤进行。然而，**适配器**和**受过教育的猜测**故障排除者知道几天前的问题是由于静态路由，他们会首先登录到数据库服务器并检查是否存在相同的静态路由。

也许有人只是错误地重新添加了它，或者路由没有完全从系统的配置文件中删除：

```
[db]# ip route show
default via 10.0.2.2 dev enp0s3  proto static  metric 1024
10.0.2.0/24 dev enp0s3  proto kernel  scope link  src 10.0.2.15
169.254.0.0/16 dev enp0s8  scope link  metric 1003
192.168.33.0/24 dev enp0s8  proto kernel  scope link  src 192.168.33.12

```

然而，不幸的是，我们的运气并不那么好；从`ip`命令的结果中，我们可以看到来自第五章*网络故障排除*的静态路由不存在。

由于路由不存在，我们需要重新从第一步开始，检查博客服务器是否能够连接到数据库服务器。

# 基本故障排除

我们应该进行的第一个测试是从博客服务器到数据库服务器的简单 ping。这将很快回答这两台服务器是否能够进行通信：

```
[blog]$ ping db.example.com
PING db.example.com (192.168.33.12) 56(84) bytes of data.
64 bytes from db.example.com (192.168.33.12): icmp_seq=1 ttl=64 time=0.420 ms
64 bytes from db.example.com (192.168.33.12): icmp_seq=2 ttl=64 time=0.564 ms
64 bytes from db.example.com (192.168.33.12): icmp_seq=3 ttl=64 time=0.562 ms
64 bytes from db.example.com (192.168.33.12): icmp_seq=4 ttl=64 time=0.479 ms
^C
--- db.example.com ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3006ms
rtt min/avg/max/mdev = 0.420/0.506/0.564/0.062 ms

```

从`ping`命令的结果中，我们可以看到博客服务器可以与数据库服务器通信，或者说，博客服务器向数据库服务器发送了**ICMP 回显请求**并收到了**ICMP 回显回复**。我们可以测试的下一个连接是到端口`3306`，即 MySQL 端口的连接。

我们将使用`telnet`命令测试这种连接：

```
[blog]$ telnet db.example.com 3306
Trying 192.168.33.12...
telnet: connect to address 192.168.33.12: No route to host

```

然而，`telnet`失败了。这表明博客服务器与数据库服务器上的数据库服务实际上存在问题。

## 验证 MariaDB 服务

现在我们已经确定了博客服务器无法与数据库服务器通信，我们需要确定原因。在假设问题严格是与网络相关之前，我们应该首先验证数据库服务是否正在运行。为了做到这一点，我们只需登录到数据库服务器并检查正在运行的数据库进程。

我们可以使用多种方法来验证数据库进程是否在运行。在下面的例子中，我们将再次使用`ps`命令：

```
[db]$ ps -elf | grep maria
0 S mysql     1529  1123  0  80   0 - 226863 poll_s 12:21 ? 00:00:04 /usr/libexec/mysqld --basedir=/usr --datadir=/var/lib/mysql --plugin-dir=/usr/lib64/mysql/plugin --log-error=/var/log/mariadb/mariadb.log --pid-file=/var/run/mariadb/mariadb.pid --socket=/var/lib/mysql/mysql.sock

```

通过`ps`命令，我们能够看到正在运行的**MariaDB**进程。在前面的例子中，我们使用了`ps -elf`命令来显示所有进程，然后使用`grep`命令来过滤输出以找到 MariaDB 服务。

从结果来看，数据库服务实际上是在运行的；但这并不能确定这个进程是否在端口`3306`上接受连接。为了验证这一点，我们可以使用`netstat`命令来识别服务器上正在监听的端口：

```
[db]$ netstat -na | grep LISTEN
tcp      0     0 127.0.0.1:25          0.0.0.0:*             LISTEN
tcp      0     0 0.0.0.0:46788         0.0.0.0:*             LISTEN
tcp      0     0 0.0.0.0:3306          0.0.0.0:*             LISTEN
tcp      0     0 0.0.0.0:111           0.0.0.0:*             LISTEN
tcp      0     0 0.0.0.0:22            0.0.0.0:*             LISTEN
tcp6     0     0 ::1:25                     :::*             LISTEN
tcp6     0     0 :::111                     :::*             LISTEN
tcp6     0     0 :::22                      :::*             LISTEN
tcp6     0     0 :::49464                   :::*             LISTEN

```

从`netstat`命令中，我们可以看到系统上有很多端口是打开的，端口`3306`就是其中之一。

由于我们知道博客服务器无法与端口`3306`建立连接，我们可以再次从多个地方测试连接。第一个地方是数据库服务器本身，第二个地方是我们的笔记本电脑，就像我们在第五章 *网络故障排除*中所做的那样。

由于数据库服务器没有安装`telnet`客户端，我们可以使用`curl`命令来执行这个测试：

```
[blog]$ curl -v telnet://localhost:3306
* About to connect() to localhost port 3306 (#0)
*   Trying 127.0.0.1...
* Connected to localhost (127.0.0.1) port 3306 (#0)
R
* RCVD IAC EC

```

### 提示

在本书中，我会反复强调知道执行任务的多种方法是很重要的。`telnet`是一个非常简单的例子，但这个概念适用于系统管理员执行的每一个任务。

既然我们已经确定了数据库服务器可以从本地服务器访问，我们现在可以从我们的笔记本电脑上测试：

```
[laptop]$ telnet 192.168.33.12 3306
Trying 192.168.33.12...
telnet: connect to address 192.168.33.12: Connection refused
telnet: Unable to connect to remote host

```

从我们的笔记本电脑上看，连接到数据库服务是不可用的，但如果我们测试另一个端口，比如`22`会发生什么呢？

```
[laptop]$ telnet 192.168.33.12 22
Trying 192.168.33.12...
Connected to 192.168.33.12.
Escape character is '^]'.
SSH-2.0-OpenSSH_6.4
^]
telnet>

```

这是一个有趣的结果；从笔记本电脑上，我们能够连接到端口`22`，但无法连接到端口`3306`。既然端口`22`在笔记本电脑上是可用的，那么在博客服务器上呢？

```
[blog]$ telnet db.example.com 22
Trying 192.168.33.12...
Connected to db.example.com.
Escape character is '^]'.
SSH-2.0-OpenSSH_6.4
^]

```

这些结果非常有趣。在上一章中，当我们的连接问题是由于错误配置的静态路由时，博客服务器和数据库服务器之间的所有通信都中断了。

然而，在这个问题的情况下，博客服务器无法连接到端口`3306`，但它可以在端口`22`上与数据库服务器通信。使这个问题更有趣的是，在数据库服务器上本地，端口`3306`是可用的并且接受连接。

这些关键信息是指示我们的问题可能实际上是由于防火墙引起的第一个迹象。现在可能还为时过早使用数据收集器，但是一个适配器或有经验的猜测故障排除者可能已经在这一点上形成了一个假设，即这个问题是由于防火墙引起的。

## 使用 tcpdump 进行故障排除

在第五章 *网络故障排除*中，我们广泛使用了`tcpdump`来识别我们的问题；我们能否用`tcpdump`来判断问题是防火墙问题？也许可以，我们肯定可以使用`tcpdump`来更好地查看问题。

首先，我们将从博客服务器捕获到端口`22`的连接（我们知道这个连接是有效的）。`tcpdump`将在数据库服务器上过滤端口`22`运行；我们还将使用`-i`（接口）标志和`any`选项，使`tcpdump`捕获所有网络接口上的流量：

```
[db]# tcpdump -nnnvvv -i any port 22
tcpdump: listening on any, link-type LINUX_SLL (Linux cooked), capture size 65535 bytes

```

一旦`tcpdump`运行起来，我们可以从博客服务器发起到端口`22`的连接，看看一个完整的健康连接是什么样子的：

```
03:03:15.670771 IP (tos 0x10, ttl 64, id 17278, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.11.34133 > 192.168.33.12.22: Flags [S], cksum 0x977b (correct), seq 2193487479, win 14600, options [mss 1460,sackOK,TS val 7058697 ecr 0,nop,wscale 6], length 0
03:03:15.670847 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.12.22 > 192.168.33.11.34133: Flags [S.], cksum 0xc396 (correct), seq 3659372781, ack 2193487480, win 14480, options [mss 1460,sackOK,TS val 7018839 ecr 7058697,nop,wscale 6], length 0
03:03:15.671295 IP (tos 0x10, ttl 64, id 17279, offset 0, flags [DF], proto TCP (6), length 52)
 192.168.33.11.34133 > 192.168.33.12.22: Flags [.], cksum 0x718b (correct), seq 1, ack 1, win 229, options [nop,nop,TS val 7058697 ecr 7018839], length 0

```

从捕获的数据中，我们可以看到一个标准的健康连接。我们可以看到连接来自 IP`192.168.33.11`，即博客服务器的 IP。我们还可以看到连接通过端口`22`到达了 IP`192.168.33.12`。我们可以从以下行中看到所有这些信息：

```
192.168.33.11.34133 > 192.168.33.12.22: Flags [S], cksum 0x977b (correct), seq 2193487479, win 14600, options [mss 1460,sackOK,TS val 7058697 ecr 0,nop,wscale 6], length 0

```

从第二个捕获的数据包中，我们可以看到数据库服务器对博客服务器的**SYN-ACK**回复：

```
 192.168.33.12.22 > 192.168.33.11.34133: Flags [S.], cksum 0x0b15 (correct), seq 3659372781, ack 2193487480, win 14480, options [mss 1460,sackOK,TS val 7018839 ecr 7058697,nop,wscale 6], length 0

```

我们可以看到`SYN-ACK`回复来自`192.168.33.12` IP 地址到`192.168.33.11` IP 地址。到目前为止，TCP 连接似乎正常，第三个捕获的数据包肯定证实了这一点：

```
 192.168.33.11.34133 > 192.168.33.12.22: Flags [.], cksum 0x718b (correct), seq 1, ack 1, win 229, options [nop,nop,TS val 7058697 ecr 7018839], length 0

```

第三个数据包是来自博客服务器的**SYN-ACK-ACK**。这意味着不仅博客服务器的`SYN`数据包到达并得到`SYN-ACK`的回复，数据库服务器的`SYN-ACK`数据包也被博客服务器接收，并得到了`SYN-ACK-ACK`的回复。这是端口`22`的完整三次握手。

现在，让我们来看看到端口`3306`的连接。为此，我们将使用相同的`tcpdump`命令，这次将端口更改为`3306`：

```
[db]# tcpdump -nnnvvv -i any port 3306
tcpdump: listening on any, link-type LINUX_SLL (Linux cooked), capture size 65535 bytes

```

在`tcpdump`运行时，我们可以从博客服务器使用`telnet`建立连接：

```
[blog]$ telnet db.example.com 3306
Trying 192.168.33.12...
telnet: connect to address 192.168.33.12: No route to host

```

如预期的那样，`telnet`命令未能连接；让我们看看`tcpdump`在此期间是否捕获了任何数据包：

```
06:04:25.488396 IP (tos 0x10, ttl 64, id 44350, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.11.55002 > 192.168.33.12.3306: Flags [S], cksum 0x7699 (correct), seq 3266396266, win 14600, options [mss 1460,sackOK,TS val 12774740 ecr 0,nop,wscale 6], length 0

```

事实上，看起来`tcpdump`确实捕获了一个数据包，但只有一个。

捕获的数据包是从`192.168.33.11`（博客服务器）发送到`192.168.33.12`（数据库服务器）的`SYN`数据包。这表明来自博客服务器的数据包到达了数据库服务器；但我们看不到回复数据包。

正如您在上一章中学到的，当我们对`tcpdump`应用过滤器时，我们经常会错过一些东西。在这种情况下，我们正在过滤`tcpdump`以查找从端口`3306`发送或接收的流量。由于我们知道问题的服务器是博客服务器，我们可以通过使用`tcpdump`的主机过滤器来更改我们的过滤器，以捕获来自博客服务器 IP`192.168.33.11`的所有流量。我们可以通过使用`tcpdump`的主机过滤器来实现这一点：

```
[db]# tcpdump -nnnvvv -i any host 192.168.33.11
tcpdump: listening on any, link-type LINUX_SLL (Linux cooked), capture size 65535 bytes

```

再次运行`tcpdump`，我们可以再次从博客服务器使用`telnet`发起连接：

```
[blog]$ telnet db.example.com 3306
Trying 192.168.33.12...
telnet: connect to address 192.168.33.12: No route to host

```

同样，预期地，telnet 连接失败了；然而，这次我们可以从`tcpdump`中看到更多信息：

```
06:16:49.729134 IP (tos 0x10, ttl 64, id 23760, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.11.55003 > 192.168.33.12.3306: Flags [S], cksum 0x9be6 (correct), seq 1849431125, win 14600, options [mss 1460,sackOK,TS val 13518981 ecr 0,nop,wscale 6], length 0
06:16:49.729199 IP (tos 0xd0, ttl 64, id 40207, offset 0, flags [none], proto ICMP (1), length 88)
 192.168.33.12 > 192.168.33.11: ICMP host 192.168.33.12 unreachable - admin prohibited, length 68

```

这一次我们实际上可以看到相当多有用的信息，直接表明我们的问题是由于系统防火墙引起的。

看起来`tcpdump`能够捕获两个数据包。让我们分析一下它能够捕获到的内容，以更好地理解发生了什么：

```
06:16:49.729134 IP (tos 0x10, ttl 64, id 23760, offset 0, flags [DF], proto TCP (6), length 60)
 192.168.33.11.55003 > 192.168.33.12.3306: Flags [S], cksum 0x9be6 (correct), seq 1849431125, win 14600, options [mss 1460,sackOK,TS val 13518981 ecr 0,nop,wscale 6], length 0

```

第一个数据包与我们之前看到的一样，是从博客服务器到数据库服务器端口`3306`的简单`SYN`请求。然而，第二个数据包非常有趣：

```
06:16:49.729199 IP (tos 0xd0, ttl 64, id 40207, offset 0, flags [none], proto ICMP (1), length 88)
 192.168.33.12 > 192.168.33.11: ICMP host 192.168.33.12 unreachable - admin prohibited, length 68

```

第二个数据包甚至不是基于 TCP 的数据包，而是一个**ICMP**数据包。在第五章*网络故障排除*中，我们讨论了 ICMP 回显请求和回复数据包，以及它们如何被`ping`命令用于识别主机是否可用。然而，ICMP 用于的不仅仅是`ping`命令。

## 理解 ICMP

ICMP 协议被用作跨网络发送消息的控制协议。回显请求和回显回复消息只是这种协议的一个例子。这种协议也经常用于通知其他系统的错误。

在这种情况下，数据库服务器正在向博客服务器发送一个 ICMP 数据包，通知它 IP 主机`192.168.33.12`无法访问：

```
proto ICMP (1), length 88)
 192.168.33.12 > 192.168.33.11: ICMP host 192.168.33.12 unreachable - admin prohibited, length 68

```

数据库服务器不仅说它是不可达的，还告诉博客服务器不可达的原因是因为连接被管理上禁止了。这种回复是防火墙是连接问题的来源的明显迹象，因为通常管理上禁止是防火墙会使用的消息类型。

### 理解连接被拒绝

当尝试连接到不可用的服务或未被监听的端口时，Linux 内核会发送一个回复。然而，这个回复是一个 TCP 重置，告诉远程系统重置连接。

通过在运行`tcpdump`时连接到无效端口，我们可以看到这一点。在博客服务器上，如果我们运行`tcpdump`，端口`5000`目前没有被使用。使用`port`过滤器，我们将看到所有到该端口的流量：

```
[blog]# tcpdump -vvvnnn -i any port 5000
tcpdump: listening on any, link-type LINUX_SLL (Linux cooked), capture size 65535 bytes

```

通过在端口 5000 上捕获所有流量，我们现在可以使用 telnet 尝试连接：

```
[laptop]$ telnet 192.168.33.11 5000
Trying 192.168.33.11...
telnet: connect to address 192.168.33.11: Connection refused
telnet: Unable to connect to remote host

```

实际上我们已经看到了一些不同的东西。之前，当我们在数据库服务器上对端口`3306`执行`telnet`时，`telnet`命令打印了不同的消息。

```
telnet: connect to address 192.168.33.12: No route to host

```

这是因为之前进行 telnet 连接时，服务器收到了 ICMP 目的地不可达数据包。

然而，这次发送了不同的回复。我们可以在`tcpdump`捕获的数据包中看到这个回复：

```
06:57:42.954091 IP (tos 0x10, ttl 64, id 47368, offset 0, flags [DF], proto TCP (6), length 64)
 192.168.33.1.53198 > 192.168.33.11.5000: Flags [S], cksum 0xca34 (correct), seq 1134882056, win 65535, options [mss 1460,nop,wscale 5,nop,nop,TS val 511014642 ecr 0,sackOK,eol], length 0
06:57:42.954121 IP (tos 0x10, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 40)
 192.168.33.11.5000 > 192.168.33.1.53198: Flags [R.], cksum 0xd86e (correct), seq 0, ack 1134882057, win 0, length 0

```

这次，发送回来的数据包是一个 TCP 重置：

```
192.168.33.11.5000 > 192.168.33.1.53198: Flags [R.],

```

重置数据包通常是由于简单的连接错误导致的问题，因为这是客户端尝试连接不再可用的端口时的标准 TCP 响应。

重置数据包也可以由拒绝连接的应用程序发送。然而，ICMP 目的地不可达通常是防火墙拒绝数据包时会收到的回复；也就是说，如果防火墙服务配置为回复的话。

# 迄今为止你学到的内容的快速总结

到目前为止，我们已经确定博客服务器能够通过端口`22`与数据库服务器建立连接。与我们之前的情况不同，这个连接实际上能够执行完整的三次握手。然而，博客服务器无法通过端口`3306`与数据库服务器执行三次握手。

当博客服务器尝试通过端口 3306 与数据库服务器建立连接时，数据库服务器会发送一个 ICMP 目的地不可达的数据包回到博客服务器。这个数据包实际上是告诉博客服务器，对数据库的连接尝试被拒绝了。然而，数据库服务是启动的，并且在端口 3306 上监听（通过`netstat`验证）。除了端口被监听外，如果我们从数据库服务器本身`telnet`到端口 3306，连接是建立的。

考虑到所有这些数据点，可能是数据库服务器启用了防火墙服务并阻止了对端口 3306 的连接。

# 使用 iptables 管理 Linux 防火墙

在管理 Linux 中的防火墙服务时，有许多选项，最流行的是`iptables`和`ufw`。对于 Ubuntu 发行版，`ufw`是默认的防火墙管理工具；然而，总体而言，`iptables`是跨多个 Linux 发行版中最流行的。然而，这两者本身只是**Netfilter**的用户界面。

Netfilter 是 Linux 内核中的一个框架，允许数据包过滤以及网络和端口转换。诸如`iptables`命令之类的工具只是与`netfilter`框架交互，以应用这些规则。

在本书中，我们将集中在使用`iptables`命令和服务来管理我们的防火墙规则。它不仅是最流行的防火墙工具，而且在基于 Red Hat 的操作系统中已经是默认的防火墙服务很长一段时间了。即使在 Red Hat Enterprise Linux 7 中出现了更新的`firewalld`服务，这只是一个管理`iptables`的服务。

## 验证 iptables 是否在运行

由于我们怀疑问题是由系统防火墙配置引起的，我们应该首先检查防火墙是否正在运行以及定义了什么规则。由于`iptables`作为一个服务运行，第一步就是简单地检查该服务的状态：

```
[db]# ps -elf | grep iptables
0 R root      4189  3220  0  80   0 - 28160 -      16:31 pts/0 00:00:00 grep --color=auto iptables

```

以前，当我们去检查一个服务是否在运行时，我们通常会使用`ps`命令。这对于 MariaDB 或 Apache 等服务非常有效；然而，`iptables`是不同的。因为`iptables`只是一个与`netfilter`交互的命令，`iptables`服务不像大多数其他服务那样是一个守护进程。事实上，当你启动`iptables`服务时，你只是应用了保存的`netfilter`规则，当你停止服务时，你只是刷新了这些规则。我们将在本章稍后探讨这个概念，但现在我们只是检查`iptables`服务是否在运行：

```
[db]# service iptables status
Redirecting to /bin/systemctl status  iptables.service
iptables.service - IPv4 firewall with iptables
 Loaded: loaded (/usr/lib/systemd/system/iptables.service; enabled)
 Active: active (exited) since Wed 2015-04-01 16:36:16 UTC; 4min 56s ago
 Process: 4202 ExecStop=/usr/libexec/iptables/iptables.init stop (code=exited, status=0/SUCCESS)
 Process: 4332 ExecStart=/usr/libexec/iptables/iptables.init start (code=exited, status=0/SUCCESS)
 Main PID: 4332 (code=exited, status=0/SUCCESS)

Apr 01 16:36:16 db.example.com systemd[1]: Starting IPv4 firewall with iptables...
Apr 01 16:36:16 db.example.com iptables.init[4332]: iptables: Applying firewall rules: [  OK  ]
Apr 01 16:36:16 db.example.com systemd[1]: Started IPv4 firewall with iptables.

```

随着 Red Hat Enterprise Linux 7 的发布，Red Hat 已经迁移到了`systemd`，它取代了标准的`init`系统。随着这一迁移，服务命令不再是管理服务的首选命令。这个功能已经将`systemd`的控制命令移动到了`systemctl`命令。

对于 RHEL 7，至少`service`命令仍然可以执行；然而，这个命令只是`systemctl`的一个包装器。以下是使用`systemctl`命令检查`iptables`服务状态的命令。在本书中，我们将使用`systemctl`命令而不是传统的 service 命令：

```
[db]# systemctl status iptables.service
iptables.service - IPv4 firewall with iptables
 Loaded: loaded (/usr/lib/systemd/system/iptables.service; enabled)
 Active: active (exited) since Wed 2015-04-01 16:36:16 UTC; 26min ago
 Process: 4202 ExecStop=/usr/libexec/iptables/iptables.init stop (code=exited, status=0/SUCCESS)
 Process: 4332 ExecStart=/usr/libexec/iptables/iptables.init start (code=exited, status=0/SUCCESS)
 Main PID: 4332 (code=exited, status=0/SUCCESS)

Apr 01 16:36:16 db.example.com systemd[1]: Starting IPv4 firewall with iptables...
Apr 01 16:36:16 db.example.com iptables.init[4332]: iptables: Applying firewall rules: [  OK  ]
Apr 01 16:36:16 db.example.com systemd[1]: Started IPv4 firewall with iptables.

```

从前面的`systemctl`输出中，我们可以看到当前`iptables`服务是活动的。我们可以从`systemctl`输出的第三行来识别这一点：

```
 Active: active (exited) since Wed 2015-04-01 16:36:16 UTC; 26min ago

```

当`iptables`服务没有运行时，情况看起来会有很大不同：

```
[db]# systemctl status iptables.service
iptables.service - IPv4 firewall with iptables
 Loaded: loaded (/usr/lib/systemd/system/iptables.service; enabled)
 Active: inactive (dead) since Thu 2015-04-02 02:55:26 UTC; 1s ago
 Process: 4489 ExecStop=/usr/libexec/iptables/iptables.init stop (code=exited, status=0/SUCCESS)
 Process: 4332 ExecStart=/usr/libexec/iptables/iptables.init start (code=exited, status=0/SUCCESS)
 Main PID: 4332 (code=exited, status=0/SUCCESS)

Apr 01 16:36:16 db.example.com systemd[1]: Starting IPv4 firewall with iptables...
Apr 01 16:36:16 db.example.com iptables.init[4332]: iptables: Applying firewall rules: [  OK  ]
Apr 01 16:36:16 db.example.com systemd[1]: Started IPv4 firewall with iptables.
Apr 02 02:55:26 db.example.com systemd[1]: Stopping IPv4 firewall with iptables...
Apr 02 02:55:26 db.example.com iptables.init[4489]: iptables: Setting chains to policy ACCEPT: nat filter [  OK  ]
Apr 02 02:55:26 db.example.com iptables.init[4489]: iptables: Flushing firewall rules: [  OK  ]
Apr 02 02:55:26 db.example.com iptables.init[4489]: iptables: Unloading modules: [  OK  ]
Apr 02 02:55:26 db.example.com systemd[1]: Stopped IPv4 firewall with iptables.

```

从上面的例子中，`systemctl`显示`iptables`服务处于非活动状态：

```
 Active: inactive (dead) since Thu 2015-04-02 02:55:26 UTC; 1s ago

```

`systemctl`的一个好处是，在使用状态选项运行时，输出包括来自服务的日志消息：

```
Apr 02 02:55:26 db.example.com systemd[1]: Stopping IPv4 firewall with iptables...
Apr 02 02:55:26 db.example.com iptables.init[4489]: iptables: Setting chains to policy ACCEPT: nat filter [  OK  ]
Apr 02 02:55:26 db.example.com iptables.init[4489]: iptables: Flushing firewall rules: [  OK  ]
Apr 02 02:55:26 db.example.com iptables.init[4489]: iptables: Unloading modules: [  OK  ]
Apr 02 02:55:26 db.example.com systemd[1]: Stopped IPv4 firewall with iptables.

```

从上面的代码中，我们可以看到`iptables`服务停止过程中使用的所有状态消息。

## 显示正在执行的 iptables 规则

现在我们知道`iptables`服务是*活动*和运行的，我们还应该查看已定义和正在执行的`iptables`规则。为此，我们将使用`iptables`命令和`-L`（列表）和`-n`（数字）标志：

```
[db]# iptables -L -n
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            state RELATED,ESTABLISHED
ACCEPT     icmp --  0.0.0.0/0            0.0.0.0/0
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            state NEW tcp dpt:22
REJECT     all  --  0.0.0.0/0            0.0.0.0/0            reject- with icmp-host-prohibited
ACCEPT     tcp  --  192.168.0.0/16       0.0.0.0/0            state NEW tcp dpt:3306

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination
REJECT     all  --  0.0.0.0/0            0.0.0.0/0            reject- with icmp-host-prohibited

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination

```

在执行`iptables`时，标志`-L`和`-n`不会合并。与大多数其他命令不同，`iptables`有一个特定的格式，需要一些标志与其他标志分开。在这种情况下，`-L`标志与其他选项分开。我们可以给`-n`添加`-v`（详细）选项，但不能添加`-L`。以下是使用详细选项执行的示例：

```
[db]# iptables -L -nv

```

从`iptables -L -n`的输出中，似乎在这台服务器上有相当多的`iptables`规则。让我们分解这些规则，以便更好地理解它们。

## 理解 iptables 规则

在我们进入单个规则之前，我们应该首先了解一下`iptables`和防火墙的一些一般规则。

### 顺序很重要

要知道的第一个重要规则是顺序很重要。如果我们查看`iptables -L -n`返回的数据，我们可以看到有多个规则，这些规则的顺序决定了如何解释这些规则。

我喜欢把`iptables`想象成一个清单；当接收到一个数据包时，`iptables`会从上到下检查清单。当它找到一个符合条件的规则时，就会应用该规则。

这是人们在使用`iptables`时经常犯的一个最常见的错误，即在从上到下的顺序之外放置规则。

### 默认策略

通常情况下，`iptables`有两种用法，即除非明确阻止，否则允许所有流量，或者除非明确允许，否则阻止所有流量。这些方法被称为**默认允许**和**默认拒绝**策略。

根据 Linux 防火墙的期望用途，可以使用任一策略。然而，通常情况下，默认拒绝策略被认为是更安全的方法，因为这个策略要求为所讨论的服务器的每种访问类型添加一条规则。

### 分解 iptables 规则

由于`iptables`从上到下处理规则，为了更好地理解现有的规则，我们将从下到上查看`iptables`规则：

```
Chain FORWARD (policy ACCEPT)
target     prot opt source               destination
REJECT     all  --  0.0.0.0/0            0.0.0.0/0            reject- with icmp-host-prohibited

```

我们看到的第一条规则是`FORWARD`链的所有协议从任何源到任何目的地进行`REJECT`。这是否意味着`iptables`将阻止所有东西？是的，但只针对正在转发的数据包。

`iptables`命令将网络流量类型分类为表和链。表包括正在执行的高级操作，如过滤、网络地址转换或更改数据包。

在每个表中，还有几个“链”。链用于定义要应用规则的流量类型。在`FORWARD`链的情况下，这匹配正在转发的流量，通常用于路由。

应用规则的下一个链是`INPUT`链：

```
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            state RELATED,ESTABLISHED
ACCEPT     icmp --  0.0.0.0/0            0.0.0.0/0
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            state NEW tcp dpt:22
REJECT     all  --  0.0.0.0/0            0.0.0.0/0            reject- with icmp-host-prohibited
ACCEPT     tcp  --  192.168.0.0/16       0.0.0.0/0            state NEW tcp dpt:3306

```

这个链适用于进入本地系统的流量；基本上，这些规则只适用于到达系统的流量：

```
ACCEPT     tcp  --  192.168.0.0/16       0.0.0.0/0            state NEW tcp dpt:3306

```

如果我们查看链中的最后一条规则，我们可以看到它明确定义了系统应该接受源 IP 在`192.168.0.0/16`网络中，目标 IP 为 0.0.0.0/0 的 TCP 流量，就像`netstat`一样是一个通配符。这条规则的最后部分定义了这条规则仅适用于目标端口为`3306`的新连接。

简单来说，这条规则将允许 192.168.0.0/16 网络中的任何 IP 访问数据库服务器的任何本地 IP 的 3306 端口。

特别是这条规则应该允许来自我们博客服务器（192.168.33.11）的流量，但是上面的规则呢？

```
REJECT     all  --  0.0.0.0/0            0.0.0.0/0            reject- with icmp-host-prohibited

```

前面的规则明确规定系统应该从源 IP 为`0.0.0.0/0`到目标 IP 为`0.0.0.0/0`的所有协议进行`REJECT`，并回复一个 ICMP 数据包，说明主机被禁止。根据我们之前的网络故障排除，我们知道`0.0.0.0/0`网络是所有网络的通配符。

这意味着这条规则将拒绝所有流量到系统，有效地使我们的系统使用“默认拒绝”策略。然而，这并不是定义“默认拒绝”策略的常见方法。

如果我们查看这个链规则集的顶部，我们会看到以下内容：

```
Chain INPUT (policy ACCEPT)

```

这本质上是说`INPUT`链本身具有`ACCEPT`策略，这意味着链本身使用“默认允许”策略。但是，这个链中有一条规则将拒绝所有流量。

这意味着，虽然链的策略在技术上不是默认拒绝，但这条规则实际上实现了相同的效果。除非在此规则之前明确允许流量，否则流量将被拒绝，有效地使链成为“默认拒绝”策略。

在这一点上，我们有一个有趣的问题；`INPUT`链中的最后一条规则明确允许从 192.168.0.0/16 源网络到 3306 端口（`MariaDB`端口）的流量。然而，上面的规则拒绝了从任何地方到任何地方的所有流量。如果我们花一点时间记住`iptables`是基于顺序的，那么我们很容易看出这可能是一个问题。

问题可能只是允许端口 3306 的规则是在阻止所有流量的规则之后定义的；基本上，数据库流量被默认拒绝规则阻止。

然而，在我们根据这些信息采取行动之前，我们应该继续查看`iptables`规则，因为可能还有另一条规则定义了对抗这两条底部规则的规则：

```
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            state NEW tcp dpt:22

```

`INPUT`链中倒数第三条规则确实解释了为什么 SSH 流量按预期工作。该规则明确说明，当连接是针对端口`22`的新连接时，系统应该从任何来源到任何目的地接受所有 TCP 协议流量。

这条规则基本上定义了所有新的 TCP 连接到端口`22`都是允许的。由于它在默认拒绝规则之前，这意味着在任何情况下都不会被该规则阻止端口`22`的新连接。

如果我们查看`INPUT`链中倒数第四条规则，我们会看到一条非常有趣的规则：

```
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0

```

这条规则似乎告诉系统应该从任何 IP（`0.0.0.0/0`）接受所有协议到任何 IP（`0.0.0.0/0`）。如果我们查看这条规则并应用顺序很重要的逻辑；那么这条规则应该允许我们的数据库流量。

不幸的是，`iptables`输出有时可能会误导，因为这条规则没有显示规则的一个关键部分；接口：

```
[db]# iptables -L -nv
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source destination
 36  2016 ACCEPT     all  --  *      *       0.0.0.0/0 0.0.0.0/0            state RELATED,ESTABLISHED
 0     0 ACCEPT     icmp --  *      *       0.0.0.0/0 0.0.0.0/0
 0     0 ACCEPT     all  --  lo     *       0.0.0.0/0 0.0.0.0/0
 0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0 0.0.0.0/0            state NEW tcp dpt:22
 394 52363 REJECT     all  --  *      *       0.0.0.0/0 0.0.0.0/0            reject-with icmp-host-prohibited
 0     0 ACCEPT     tcp  --  *      *       192.168.0.0/16 0.0.0.0/0            state NEW tcp dpt:3306

```

如果我们在`iptables`命令中添加`-v`（详细）标志，我们可以看到更多信息。特别是，我们可以看到一个名为“in”的新列，它代表接口：

```
 0     0 ACCEPT     all  --  lo     *       0.0.0.0/0 0.0.0.0/0

```

如果我们再仔细看一下这条规则，我们会发现接口列显示该规则仅适用于`loopback`接口上的流量。由于我们的数据库流量是在`enp0s8`接口上的，数据库流量不符合这条规则：

```
 0     0 ACCEPT     icmp --  *      *       0.0.0.0/0 0.0.0.0/0

```

倒数第五条规则非常相似，只是它专门允许从任何 IP 到任何 IP 的所有 ICMP 流量。这解释了为什么我们的**ping**请求有效，因为这条规则将允许 ICMP 回显请求和回显回复通过防火墙。

然而，倒数第六条规则与其他规则有很大不同：

```
 36  2016 ACCEPT     all  --  *      *       0.0.0.0/0 0.0.0.0/0            state RELATED,ESTABLISHED

```

这条规则确实说明系统应该从任何 IP（0.0.0.0/0）接受所有协议到任何 IP（0.0.0.0/0）；但是该规则仅限于`RELATED`和`ESTABLISHED`数据包。

在审查端口`22`的`iptables`规则时，我们可以看到该规则仅限于`NEW`连接。这基本上意味着用于启动到端口`22`的新连接的数据包，如`SYN`和`SYN-ACK-ACK`是允许的。

当规则说明`ESTABLISHED`状态被允许时，`iptables`将允许属于已建立的 TCP 连接的数据包：

这意味着新的 SSH 连接是由端口`22`的规则允许的。

```
 0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0 0.0.0.0/0            state NEW tcp dpt:22

```

然后，一旦 TCP 连接建立，它将被以下规则允许：

```
 36  2016 ACCEPT     all  --  *      *       0.0.0.0/0 0.0.0.0/0            state RELATED,ESTABLISHED

```

### 整合规则

现在我们已经查看了所有的`iptables`规则，我们可以对为什么我们的数据库流量无法工作做出合理的猜测。

在`iptables`规则集中，我们可以看到拒绝所有流量的规则在允许端口**3306**上的数据库连接之前被定义：

```
 394 52363 REJECT     all  --  *      *       0.0.0.0/0 0.0.0.0/0            reject-with icmp-host-prohibited
 0     0 ACCEPT     tcp  --  *      *       192.168.0.0/16 0.0.0.0/0            state NEW tcp dpt:3306

```

由于系统无法启动新连接，它们无法建立连接，这将被以下规则允许：

```
 36  2016 ACCEPT     all  --  *      *       0.0.0.0/0 0.0.0.0/0            state RELATED,ESTABLISHED

```

我们可以通过查看定义的规则来确定所有这些，但这也需要对`iptables`有相当了解。

还有另一种相对较简单的方法来确定哪些规则正在阻止或允许流量。

### 查看 iptables 计数器

通过`iptables`的详细输出，我们不仅可以看到规则适用的接口，还可以看到两列非常有用。这两列是**pkts**和**bytes**：

```
[db]# iptables -L -nv
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source destination
 41  2360 ACCEPT     all  --  *      *       0.0.0.0/0 0.0.0.0/0            state RELATED,ESTABLISHED

```

`pkts`列是`iptables`详细输出中的第一列，该列包含规则应用的数据包数。如果我们看前面的规则，我们可以看到这条规则已经应用于`41`个数据包。`bytes`列是第二列，用于表示规则应用的字节数。对于我们前面的例子，该规则已经应用了 2,360 字节。

我们可以使用`iptables`中的数据包和字节计数器来识别应用于我们的数据库流量的规则。为此，我们只需要通过刷新浏览器并运行`iptables –L –nv`来触发数据库活动，以识别哪些规则的计数器增加了。我们甚至可以通过使用`iptables`命令后跟`–Z`（清零）标志来清除当前值，使这更加容易：

```
[db]# iptables –Z

```

如果我们重新执行`iptables`的详细列表，我们可以看到计数器对于除了`ESTABLISHED`和`RELATED`规则（每个连接都会匹配的规则，包括我们的 SSH 会话）之外的所有内容都是`0`：

```
[db]# iptables -L -nv
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source destination
 7   388 ACCEPT     all  --  *      *       0.0.0.0/0 0.0.0.0/0            state RELATED,ESTABLISHED
 0     0 ACCEPT     icmp --  *      *       0.0.0.0/0 0.0.0.0/0
 0     0 ACCEPT     all  --  lo     *       0.0.0.0/0 0.0.0.0/0
 0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0 0.0.0.0/0            state NEW tcp dpt:22
 0     0 REJECT     all  --  *      *       0.0.0.0/0 0.0.0.0/0            reject-with icmp-host-prohibited
 0     0 ACCEPT     tcp  --  *      *       192.168.0.0/16 0.0.0.0/0            state NEW tcp dpt:3306

```

清除这些值后，我们现在可以刷新我们的网络浏览器并启动一些数据库流量：

```
[db]# iptables -L -nv
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source destination
 53  3056 ACCEPT     all  --  *      *       0.0.0.0/0 0.0.0.0/0            state RELATED,ESTABLISHED
 0     0 ACCEPT     icmp --  *      *       0.0.0.0/0 0.0.0.0/0
 0     0 ACCEPT     all  --  lo     *       0.0.0.0/0 0.0.0.0/0
 0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0 0.0.0.0/0            state NEW tcp dpt:22
 45  4467 REJECT     all  --  *      *       0.0.0.0/0 0.0.0.0/0            reject-with icmp-host-prohibited
 0     0 ACCEPT     tcp  --  *      *       192.168.0.0/16 0.0.0.0/0            state NEW tcp dpt:3306

```

如果我们再次以详细模式运行`iptables –L`，我们可以看到，事实上，正如我们所怀疑的，数据包被默认的拒绝规则拒绝了。我们可以通过这个事实看到，自从我们使用`–Z`标志将计数器清零以来，这条规则已经拒绝了`45`个数据包。

使用`-Z`标志和计数器是一种非常有用的方法；然而，在某些情况下可能不起作用。在繁忙的系统和规则众多的系统上，仅仅使用计数器来显示匹配的规则可能会很困难。因此，重要的是要建立对`iptables`的经验，了解其复杂性。

### 纠正 iptables 规则排序

更改`iptables`可能有点棘手，不是因为它难以使用（尽管命令语法有点复杂），而是因为修改`iptables`规则有两个步骤。如果忘记了其中一步（这经常发生），问题可能会意外地持续存在。

#### iptables 规则的应用方式

当`iptables`服务启动时，启动脚本不会像系统上的其他服务那样启动守护进程。`iptables`服务所做的就是简单地应用保存规则文件（`/etc/sysconfig/iptables`）中定义的规则。

然后这些规则被加载到内存中，它们成为活动规则。这意味着，如果我们只是重新排列内存中的规则，而不修改保存的文件，下次服务器重新启动时，我们的更改将会丢失。

另一方面，如果我们只修改了保存的文件，但没有重新排列内存中的`iptables`规则，我们的更改将不会生效，直到下一次重新启动`iptables`服务。

我经常看到这两种情况发生，有人简单地忘记了其中一步。这种情况会给他们正在处理的问题带来更多的复杂性。

#### 修改 iptables 规则

对于这种情况，我们将选择一种既执行又易于记忆的简单方法。我们首先编辑`/etc/sysconfig/iptables`文件，其中包含所有定义的`iptables`规则。然后重新启动`iptables`服务，这将导致当前规则被清除，并应用`/etc/sysconfig/iptables`文件中的新规则。

要编辑`iptables`文件，我们可以简单地使用`vi`：

```
[db]# vi /etc/sysconfig/iptables
# Generated by iptables-save v1.4.21 on Mon Mar 30 02:27:35 2015
*nat
:PREROUTING ACCEPT [10:994]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
COMMIT
# Completed on Mon Mar 30 02:27:35 2015
# Generated by iptables-save v1.4.21 on Mon Mar 30 02:27:35 2015
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [140:11432]
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
-A INPUT -p tcp -m state --state NEW -m tcp --src 192.168.0.0/16 -- dport 3306 -j ACCEPT
-A FORWARD -j REJECT --reject-with icmp-host-prohibited
COMMIT
# Completed on Mon Mar 30 02:27:35 2015

```

这个文件的内容与`iptables -L`的输出有些不同。前面的规则实际上只是可以附加到`iptables`命令的选项。例如，如果我们想要添加一个允许流量到端口 22 的规则，我们可以简单地复制并粘贴前面的规则，加上`-dport 22`，并在前面加上`iptables`命令。以下是这个命令的示例：

```
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT

```

当`iptables`服务脚本添加`iptables`规则时，它们也只是简单地将这些规则附加到`iptables`命令上。

从`iptables`文件的内容中，我们可以看到需要重新排序的两个规则：

```
-A INPUT -j REJECT --reject-with icmp-host-prohibited
-A INPUT -p tcp -m state --state NEW -m tcp --src 192.168.0.0/16 -- dport 3306 -j ACCEPT

```

为了解决我们的问题，我们只需将这两个规则更改为以下内容：

```
-A INPUT -p tcp -m state --state NEW -m tcp --src 192.168.0.0/16 -- dport 3306 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited

```

更改完成后，我们可以通过按*Esc*然后在 vi 中输入`:wq`来**保存**并**退出**文件。

#### 测试我们的更改

现在文件已保存，我们应该可以简单地重新启动`iptables`服务，规则将生效。唯一的问题是，如果我们没有正确编辑`iptables`文件会怎么样？

我们当前的`iptables`配置有一个规则，阻止除了上面允许的连接之外的所有流量。如果我们不小心将该规则放在允许端口 22 之前会怎么样？这意味着当我们重新启动`iptables`服务时，我们将无法建立 SSH 连接，而且由于这是我们管理此服务器的唯一方法，这个简单的错误可能会产生严重后果。

在对`iptables`进行更改时，应始终谨慎。即使只是重新启动`iptables`服务，最好还是查看`/etc/sysconfig/iptables`中保存的规则，以确保没有意外的更改会将用户和您自己锁定在管理系统之外。

为了避免这种情况，我们可以使用`screen`命令。`screen`命令用于打开伪终端，即使我们的 SSH 会话断开，它也会继续运行。即使断开是由于防火墙更改引起的。

要启动`screen`，我们只需执行命令`screen`：

```
[db]# screen

```

一旦我们进入`screen`会话，我们将做的不仅仅是重新启动`iptables`。我们实际上将编写一个`bash`一行命令，重新启动`iptables`，将输出打印到屏幕上，以确保我们的会话仍然有效，等待两分钟，然后最终停止`iptables`服务：

```
[db]# systemctl restart iptables; echo "still here?"; sleep 120; systemctl stop iptables

```

当我们运行此命令时，我们将看到两种情况中的一种，要么我们的 SSH 会话将关闭，这很可能意味着我们的`iptables`规则中有错误，要么我们将在屏幕上看到一条消息，上面写着**还在这里吗？**。

如果我们看到**还在这里吗？**的消息，这意味着我们的`iptables`规则没有锁定我们的 SSH 会话：

```
[db]# systemctl restart iptables.service; echo "still here?"; sleep 120; systemctl stop iptables.service
still here?

```

由于命令已完成且我们的 SSH 会话未终止，我们现在可以简单地重新启动`iptables`，而不用担心被锁定在外面。

### 提示

在规则生效后建立新的 SSH 会话总是一个好主意，而不是结束之前的 SSH 会话。这可以验证您是否可以发起新的 SSH 会话，如果不起作用，您仍然可以使用旧的 SSH 会话来解决问题。

当我们这次重新启动`iptables`时，我们的新规则将生效：

```
# systemctl restart iptables.service
# iptables -L -nv
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source destination
 15   852 ACCEPT     all  --  *      *       0.0.0.0/0 0.0.0.0/0            state RELATED,ESTABLISHED
 0     0 ACCEPT     icmp --  *      *       0.0.0.0/0 0.0.0.0/0
 0     0 ACCEPT     all  --  lo     *       0.0.0.0/0 0.0.0.0/0
 0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0 0.0.0.0/0            state NEW tcp dpt:22
 0     0 ACCEPT     tcp  --  *      *       192.168.0.0/16 0.0.0.0/0            state NEW tcp dpt:3306
 0     0 REJECT     all  --  *      *       0.0.0.0/0 0.0.0.0/0            reject-with icmp-host-prohibited

```

现在，我们可以看到接受端口`3306`流量的规则在默认拒绝规则之前。如果我们刷新浏览器，我们还可以验证`iptables`的更改是否纠正了问题。

![测试我们的更改](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel-tbst-gd/img/00008.jpeg)

看起来是这样的！

如果我们再次查看详细模式下的`iptables`列表，我们还可以看到我们的规则匹配得有多好：

```
# iptables -L -nv
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source destination
 119 19352 ACCEPT     all  --  *      *       0.0.0.0/0 0.0.0.0/0            state RELATED,ESTABLISHED
 0     0 ACCEPT     icmp --  *      *       0.0.0.0/0 0.0.0.0/0
 0     0 ACCEPT     all  --  lo     *       0.0.0.0/0 0.0.0.0/0
 0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0 0.0.0.0/0            state NEW tcp dpt:22
 2   120 ACCEPT     tcp  --  *      *       192.168.0.0/16 0.0.0.0/0            state NEW tcp dpt:3306
 39  4254 REJECT     all  --  *      *       0.0.0.0/0 0.0.0.0/0            reject-with icmp-host-prohibited

```

从`iptables`的统计数据中，我们可以看到有两个数据包匹配了我们的规则。这与网站的正常运行一起，意味着我们对规则进行的微小更改对`iptables`允许或拒绝的内容产生了巨大影响。

# 总结

在本章中，我们遇到了一个看似简单的网络问题，即我们的博客应用程序连接到其数据库。在数据收集阶段，我们使用了诸如`netstat`和`tcpdump`之类的命令来检查网络数据包，并很快发现博客服务器收到了一个 ICMP 数据包，表明数据库服务器拒绝了博客服务器的 TCP 数据包。

从那时起，我们怀疑问题是防火墙问题，经过使用`iptables`命令调查后，我们注意到防火墙规则是无序的。

之后，我们能够使用“试错”阶段来解决问题。这个特定的问题是一个非常常见的问题，我个人在许多不同的环境中都见过。这主要是由于对`iptables`的工作原理以及如何正确定义规则的知识不足。虽然本章只涵盖了`iptables`中一种类型的配置错误，但本章中使用的一般故障排除方法可以应用于大多数情况。

在第七章中，《文件系统错误和恢复》，我们将开始探讨文件系统错误以及如何从中恢复 - 这是一个棘手的话题，一个错误的命令可能意味着数据丢失，这是任何系统管理员都不想看到的。


# 第七章：文件系统错误和恢复

在第五章*网络故障排除*和第六章*诊断和纠正防火墙问题*中，我们使用了许多工具来排除由于错误配置的路由和防火墙导致的网络连接问题。网络相关问题非常常见，这两个示例问题也是常见的情况。在本章中，我们将专注于与硬件相关的问题，并从排除文件系统错误开始。

就像其他章节一样，我们将从发现的错误开始，排除问题直到找到原因和解决方案。在这个过程中，我们将发现许多用于排除文件系统问题的不同命令和日志。

# 诊断文件系统错误

与之前的章节不同，那时最终用户向我们报告了问题，这一次我们自己发现了问题。在数据库服务器上执行一些日常任务时，我们尝试创建数据库备份，并收到以下错误：

```
[db]# mysqldump wordpress > /data/backups/wordpress.sql
-bash: /data/backups/wordpress.sql: Read-only file system

```

这个错误很有趣，因为它不一定来自`mysqldump`命令，而是来自写入`/data/backups/wordpress.sql`文件的 bash 重定向。

如果我们看一下错误，它非常具体，我们试图将备份写入的文件系统是`只读`的。`只读`是什么意思？

## 只读文件系统

在 Linux 上定义和挂载文件系统时，你有很多选项，但有两个选项最能定义文件系统的可访问性。这两个选项分别是`rw`表示读写，**ro**表示只读。当文件系统以读写选项挂载时，这意味着文件系统的内容可以被读取，并且具有适当权限的用户可以向文件系统写入新文件/目录。

当文件系统以只读模式挂载时，这意味着用户可以读取文件系统，但新的写入请求将被拒绝。

## 使用`mount`命令列出已挂载的文件系统

由于我们收到的错误明确指出文件系统是只读的，我们下一个逻辑步骤是查看服务器上已挂载的文件系统。为此，我们将使用`mount`命令：

```
[db]# mount
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime,seclabel)
devtmpfs on /dev type devtmpfs (rw,nosuid,seclabel,size=228500k,nr_inodes=57125,mode=755)
securityfs on /sys/kernel/security type securityfs (rw,nosuid,nodev,noexec,relatime)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,seclabel)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,seclabel,gid=5,mode=620,ptmxmode=000)
tmpfs on /run type tmpfs (rw,nosuid,nodev,seclabel,mode=755)
tmpfs on /sys/fs/cgroup type tmpfs (rw,nosuid,nodev,noexec,seclabel,mode=755)
selinuxfs on /sys/fs/selinux type selinuxfs (rw,relatime)
systemd-1 on /proc/sys/fs/binfmt_misc type autofs (rw,relatime,fd=33,pgrp=1,timeout=300,minproto=5,maxproto=5,direct)
mqueue on /dev/mqueue type mqueue (rw,relatime,seclabel)
hugetlbfs on /dev/hugepages type hugetlbfs (rw,relatime,seclabel)
debugfs on /sys/kernel/debug type debugfs (rw,relatime)
sunrpc on /var/lib/nfs/rpc_pipefs type rpc_pipefs (rw,relatime)
nfsd on /proc/fs/nfsd type nfsd (rw,relatime)
/dev/sda1 on /boot type xfs (rw,relatime,seclabel,attr2,inode64,noquota)
192.168.33.13:/nfs on /data type nfs4 (rw,relatime,vers=4.0,rsize=65536,wsize=65536,namlen=255,hard,proto=tcp,port=0,timeo=600,retrans=2,sec=sys,clientaddr=192.168.33.12,local_lock=none,addr=192.168.33.13)

```

`mount`命令在处理文件系统时非常有用。它不仅可以用于显示已挂载的文件系统（如前面的命令所示），还可以用于附加（或挂载）和卸载文件系统。

### 已挂载的文件系统

称文件系统为已挂载的文件系统是一种常见的说法，表示文件系统已*连接*到服务器。对于文件系统，它们通常有两种状态，要么是已连接（已挂载），内容对用户可访问，要么是未连接（未挂载），对用户不可访问。在本章的后面，我们将使用`mount`命令来介绍挂载和卸载文件系统。

`mount`命令不是查看已挂载或未挂载文件系统的唯一方法。另一种方法是简单地读取`/proc/mounts`文件：

```
[db]# cat /proc/mounts 
rootfs / rootfs rw 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
sysfs /sys sysfs rw,seclabel,nosuid,nodev,noexec,relatime 0 0
devtmpfs /dev devtmpfs rw,seclabel,nosuid,size=228500k,nr_inodes=57125,mode=755 0 0
securityfs /sys/kernel/security securityfs rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /dev/shm tmpfs rw,seclabel,nosuid,nodev 0 0
devpts /dev/pts devpts rw,seclabel,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0
tmpfs /run tmpfs rw,seclabel,nosuid,nodev,mode=755 0 0
tmpfs /sys/fs/cgroup tmpfs rw,seclabel,nosuid,nodev,noexec,mode=755 0 0
selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0
systemd-1 /proc/sys/fs/binfmt_misc autofs rw,relatime,fd=33,pgrp=1,timeout=300,minproto=5,maxproto=5,direct 0 0
mqueue /dev/mqueue mqueue rw,seclabel,relatime 0 0
hugetlbfs /dev/hugepages hugetlbfs rw,seclabel,relatime 0 0
debugfs /sys/kernel/debug debugfs rw,relatime 0 0
sunrpc /var/lib/nfs/rpc_pipefs rpc_pipefs rw,relatime 0 0
nfsd /proc/fs/nfsd nfsd rw,relatime 0 0
/dev/sda1 /boot xfs rw,seclabel,relatime,attr2,inode64,noquota 0 0
192.168.33.13:/nfs /data nfs4 rw,relatime,vers=4.0,rsize=65536,wsize=65536,namlen=255,hard,proto=tcp,port=0,timeo=600,retrans=2,sec=sys,clientaddr=192.168.33.12,local_lock=none,addr=192.168.33.13 0 0

```

实际上，`/proc/mounts`文件的内容与`mount`命令的输出非常接近，主要区别在于每行末尾的两个数字列。为了更好地理解这个文件和`mount`命令的输出，让我们更仔细地看一下`/proc/mounts`中`/boot`文件系统的条目：

```
/dev/sda1 /boot xfs rw,seclabel,relatime,attr2,inode64,noquota 0 0

```

`/proc/mounts`文件有六列数据——**设备**、**挂载点**、**文件系统类型**、**选项**，以及两个未使用的列，用于向后兼容。为了更好地理解这些值，让我们更好地理解这些列。

第一列设备指定了用于文件系统的设备。在前面的例子中，/boot 文件系统所在的设备是/dev/sda1。

从设备的名称（sda1）可以识别出一个关键信息。这个设备是另一个设备的分区，我们可以通过设备名称末尾的数字来识别。

这个设备，从名称上看似乎是一个物理驱动器（假设是硬盘），名为/dev/sda；这个驱动器至少有一个分区，其设备名称为/dev/sda1。每当一个驱动器上有分区时，分区会被创建为自己的设备，每个设备都被分配一个编号；在这种情况下是 1，这意味着它是第一个分区。

### 使用 fdisk 列出可用分区

我们可以通过使用 fdisk 命令来验证这一点：

```
[db]# fdisk -l /dev/sda

Disk /dev/sda: 42.9 GB, 42949672960 bytes, 83886080 sectors
Units = sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disk label type: dos
Disk identifier: 0x0009c844

 Device Boot      Start         End      Blocks   Id  System
/dev/sda1   *        2048     1026047      512000   83  Linux
/dev/sda2         1026048    83886079    41430016   8e  Linux LVM

```

fdisk 命令可能很熟悉，因为它是一个用于创建磁盘分区的跨平台命令。但它也可以用来列出分区。

在前面的命令中，我们使用了-l（列出）标志来列出分区，然后是我们想要查看的设备/dev/sda。然而，fdisk 命令显示的不仅仅是这个驱动器上可用的分区。它还显示了磁盘的大小：

```
Disk /dev/sda: 42.9 GB, 42949672960 bytes, 83886080 sectors

```

我们可以从 fdisk 命令打印的第一行中看到这一点，根据这一行，我们的设备/dev/sda 的大小为 42.9GB。如果我们看输出的底部，还可以看到在这个磁盘上创建的分区：

```
 Device Boot      Start         End      Blocks   Id  System
/dev/sda1   *        2048     1026047      512000   83  Linux
/dev/sda2         1026048    83886079    41430016   8e  Linux LVM

```

从前面的列表中，看起来/dev/sda 有两个分区，/dev/sda1 和/dev/sda2。使用 fdisk，我们已经能够识别出关于这个文件系统物理设备的许多细节。如果我们继续查看/proc/mounts 的详细信息，我们应该能够识别出一些其他非常有用的信息，如下所示：

```
/dev/sda1 /boot xfs rw,seclabel,relatime,attr2,inode64,noquota 0 0

```

前一行中的第二列*挂载点*标注了这个文件系统挂载到的路径。在这种情况下，路径是/boot；/boot 本身只是根文件系统上的一个目录。然而，一旦存在于设备/dev/sda1 上的文件系统被挂载，/boot 现在就是它自己的文件系统。

为了更好地理解这个概念，我们将使用 mount 和 umount 命令来挂载和卸载/boot 文件系统：

```
[db]# ls /boot/
config-3.10.0-123.el7.x86_64
grub
grub2
initramfs-0-rescue-dee83c8c69394b688b9c2a55de9e29e4.img
initramfs-3.10.0-123.el7.x86_64.img
initramfs-3.10.0-123.el7.x86_64kdump.img
initrd-plymouth.img
symvers-3.10.0-123.el7.x86_64.gz
System.map-3.10.0-123.el7.x86_64
vmlinuz-0-rescue-dee83c8c69394b688b9c2a55de9e29e4
vmlinuz-3.10.0-123.el7.x86_64

```

如果我们在/boot 路径上执行一个简单的 ls 命令，我们可以看到这个目录中有很多文件。从/proc/mounts 文件和 mount 命令中，我们知道/boot 上有一个文件系统挂载：

```
[db]# mount | grep /boot
/dev/sda1 on /boot type xfs (rw,relatime,seclabel,attr2,inode64,noquota)

```

为了卸载这个文件系统，我们可以使用 umount 命令：

```
[db]# umount /boot
[db]# mount | grep /boot

```

umount 命令的任务非常简单，它卸载已挂载的文件系统。

### 提示

前面的命令是卸载文件系统可能是危险的示例。一般来说，您应该首先验证文件系统在卸载之前是否正在被访问。

/boot 文件系统现在已经卸载，当我们执行 ls 命令时会发生什么？

```
# ls /boot

```

/boot 路径仍然有效。但现在它只是一个空目录。这是因为/dev/sda1 上的文件系统没有挂载；因此，该文件系统上存在的任何文件目前在这个系统上都无法访问。

如果我们使用 mount 命令重新挂载文件系统，我们将看到文件重新出现：

```
[db]# mount /boot
[db]# ls /boot
config-3.10.0-123.el7.x86_64
grub
grub2
initramfs-0-rescue-dee83c8c69394b688b9c2a55de9e29e4.img
initramfs-3.10.0-123.el7.x86_64.img
initramfs-3.10.0-123.el7.x86_64kdump.img
initrd-plymouth.img
symvers-3.10.0-123.el7.x86_64.gz
System.map-3.10.0-123.el7.x86_64
vmlinuz-0-rescue-dee83c8c69394b688b9c2a55de9e29e4
vmlinuz-3.10.0-123.el7.x86_64

```

正如我们所看到的，当 mount 命令给出路径参数时，该命令将尝试挂载该文件系统。然而，当没有给出参数时，mount 命令将简单地显示当前挂载的文件系统。

在本章的后面，我们将探讨使用 mount 以及它如何理解文件系统应该在何处以及如何挂载；现在，让我们来看一下/proc/mounts 输出中的下一列：

```
/dev/sda1 /boot xfs rw,seclabel,relatime,attr2,inode64,noquota 0 0

```

第三列文件系统类型表示正在使用的文件系统类型。在许多操作系统中，特别是 Linux，通常可以使用多种类型的文件系统。在上面的情况下，我们的引导文件系统设置为`xfs`，这是 Red Hat Enterprise Linux 7 的新默认文件系统。

在使用`xfs`之前，旧版本的 Red Hat 默认使用`ext3`或`ext4`文件系统。Red Hat 仍然支持`ext3/4`文件系统和其他文件系统，因此`/proc/mounts`文件中可能列出了许多不同的文件系统类型。

对于`/boot`文件系统，了解文件系统类型并不立即有用；然而，在我们深入研究这个问题时，可能需要知道如何查找底层文件系统的类型：

```
/dev/sda1 /boot xfs rw,seclabel,relatime,attr2,inode64,noquota 0 0

```

第四列选项显示了文件系统挂载的选项。

当文件系统被挂载时，可以为该文件系统指定特定选项，以改变文件系统的默认行为。在上面的例子中，提供了相当多的选项；让我们分解这个列表，以更好地理解指定了什么：

+   `**inode64**`**：这使文件系统能够创建大于 32 位长度的索引节点号**

+   **noquota**：这禁用了对该文件系统的磁盘配额和强制执行**

**从描述中可以看出，这些选项可以极大地改变文件系统的行为。在排除任何文件系统问题时，查看这些选项也非常重要：**

```
**/dev/sda1 /boot xfs rw,seclabel,relatime,attr2,inode64,noquota 0 0** 
```

`/proc/mounts`输出的最后两列，表示为`0 0`，实际上在`/proc/mounts`中没有使用。这些列实际上只是为了与`/etc/mtab`向后兼容而添加的，`/etc/mtab`是一个类似的文件，但不像`/proc/mounts`那样被认为是最新的。

**这两个文件之间的区别在于它们的用途。`/etc/mtab`文件是为用户或应用程序设计的，用于读取和利用，而`/proc/mounts`文件是由内核本身使用的。因此，`/proc/mounts`文件被认为是最权威的版本。**

### **回到故障排除**

**如果我们回到手头的问题，我们在向`/data/backups`目录写入备份时收到了错误。使用`mount`命令，我们可以确定该目录存在于哪个文件系统上：**

```
**# mount | grep "data"**
**192.168.33.13:/nfs on /data type nfs4 (rw,relatime,vers=4.0,rsize=65536,wsize=65536,namlen=255,hard,proto=tcp,port=0,timeo=600,retrans=2,sec=sys,clientaddr=192.168.33.12,local_lock=none,addr=192.168.33.13)** 
```

**现在我们更好地理解了`mount`命令的格式，我们可以从上面的命令行中识别出一些关键信息。我们可以看到，此文件系统的设备设置为（`192.168.33.13:/nfs`），`mount`点（要附加的路径）设置为（`/data`），文件系统类型为（`nfs4`），并且文件系统设置了相当多的选项。**

**# NFS - 网络文件系统

查看`/data`文件系统，我们可以看到文件系统类型设置为`nfs4`。这种文件系统类型意味着文件系统是一个**网络文件系统**（**NFS**）。

NFS 是一种允许服务器与其他远程服务器共享导出目录的服务。`nfs4`文件系统类型是一种特殊的文件系统，允许远程服务器访问此服务，就像它是一个标准文件系统一样。

文件系统类型中的`4`表示要使用的版本，这意味着远程服务器要使用 NFS 协议的第 4 版。

### 提示

目前，NFS 最流行的版本是版本 3 和版本 4，版本 4 是 Red Hat Enterprise Linux 6 和 7 的默认版本。版本 3 和版本 4 之间有相当多的区别；然而，这些区别都不足以影响我们的故障排除方法。如果您在使用 NFS 版本 3 时遇到问题，那么您很可能可以按照我们将在本章中遵循的相同类型的步骤进行操作。

现在我们已经确定了文件系统是 NFS 文件系统，让我们看看它挂载的选项：

```
192.168.33.13:/nfs on /data type nfs4 (rw,relatime,vers=4.0,rsize=65536,wsize=65536,namlen=255,hard,proto=tcp,port=0,timeo=600,retrans=2,sec=sys,clientaddr=192.168.33.12,local_lock=none,addr=192.168.33.13)

```

从我们收到的错误来看，文件系统似乎是“只读”的，但如果我们查看列出的选项，第一个选项是`rw`。这意味着 NFS 文件系统本身已被挂载为“读写”，这应该允许对此文件系统进行写操作。

为了测试问题是与路径`/data/backups`还是挂载的文件系统`/data`有关，我们可以使用`touch`命令来测试在此文件系统中创建文件：

```
# touch /data/file.txt
touch: cannot touch '/data/file.txt': Read-only file system

```

甚至`touch`命令也无法在此文件系统上创建新文件。这清楚地表明文件系统存在问题；唯一的问题是是什么导致了这个问题。

如果我们查看此文件系统挂载的选项，没有任何导致文件系统为“只读”的原因；这意味着问题很可能不在于文件系统的挂载方式，而是其他地方。

由于问题似乎与 NFS 文件系统的挂载方式无关，而且这个文件系统是基于网络的，下一个有效的步骤将是验证与 NFS 服务器的网络连接。

## NFS 和网络连接

就像网络故障排除一样，我们的第一个测试将是 ping NFS 服务器，看看是否有响应；但问题是：*我们应该 ping 哪个服务器？*

答案在文件系统挂载的设备名称中（`192.168.33.13:/nfs`）。挂载 NFS 文件系统时，设备的格式为`<nfs 服务器>:<共享目录>`。在我们的示例中，这意味着我们的`/data`文件系统正在从服务器`192.168.33.13`挂载`/nfs`目录。为了测试连接性，我们可以简单地`ping` IP `192.168.33.13`：

```
[db]# ping 192.168.33.13
PING 192.168.33.13 (192.168.33.13) 56(84) bytes of data.
64 bytes from 192.168.33.13: icmp_seq=1 ttl=64 time=0.495 ms
64 bytes from 192.168.33.13: icmp_seq=2 ttl=64 time=0.372 ms
64 bytes from 192.168.33.13: icmp_seq=3 ttl=64 time=0.364 ms
64 bytes from 192.168.33.13: icmp_seq=4 ttl=64 time=0.337 ms
^C
--- 192.168.33.13 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3001ms
rtt min/avg/max/mdev = 0.337/0.392/0.495/0.060 ms

```

从`ping`结果来看，NFS 服务器似乎是正常的；但 NFS 服务呢？我们可以通过使用`curl`命令`telnet`到 NFS 端口来验证与 NFS 服务的连接。但首先，我们需要确定应连接到哪个端口。

在早期章节中排除数据库连接问题时，我们主要使用了众所周知的端口；由于 NFS 使用了几个不太常见的端口，我们需要确定要连接的端口：

这样做的最简单方法是在`/etc/services`文件中搜索端口：

```
[db]# grep nfs /etc/services 
nfs             2049/tcp        nfsd shilp      # Network File System
nfs             2049/udp        nfsd shilp      # Network File System
nfs             2049/sctp       nfsd shilp      # Network File System
netconfsoaphttp 832/tcp                 # NETCONF for SOAP over HTTPS
netconfsoaphttp 832/udp                 # NETCONF for SOAP over HTTPS
netconfsoapbeep 833/tcp                 # NETCONF for SOAP over BEEP
netconfsoapbeep 833/udp                 # NETCONF for SOAP over BEEP
nfsd-keepalive  1110/udp                # Client status info
picknfs         1598/tcp                # picknfs
picknfs         1598/udp                # picknfs
shiva_confsrvr  1651/tcp   shiva-confsrvr   # shiva_confsrvr
shiva_confsrvr  1651/udp   shiva-confsrvr   # shiva_confsrvr
3d-nfsd         2323/tcp                # 3d-nfsd
3d-nfsd         2323/udp                # 3d-nfsd
mediacntrlnfsd  2363/tcp                # Media Central NFSD
mediacntrlnfsd  2363/udp                # Media Central NFSD
winfs           5009/tcp                # Microsoft Windows Filesystem
winfs           5009/udp                # Microsoft Windows Filesystem
enfs            5233/tcp                # Etinnae Network File Service
nfsrdma         20049/tcp               # Network File System (NFS) over RDMA
nfsrdma         20049/udp               # Network File System (NFS) over RDMA
nfsrdma         20049/sctp              # Network File System (NFS) over RDMA

```

`/etc/services`文件是许多 Linux 发行版中包含的静态文件。它用作查找表，将网络端口映射到简单易读的名称。从前面的输出中，我们可以看到`nfs`名称映射到 TCP 端口`2049`；这是 NFS 服务的默认端口。我们可以利用这个端口来测试连接性，如下所示：

```
[db]# curl -vk telnet://192.168.33.13:2049
* About to connect() to 192.168.33.13 port 2049 (#0)
*   Trying 192.168.33.13...
* Connected to 192.168.33.13 (192.168.33.13) port 2049 (#0)

```

我们的`telnet`似乎成功了；我们可以进一步验证它，使用`netstat`命令：

```
[db]# netstat -na | grep 192.168.33.13
tcp        0      0 192.168.33.12:756       192.168.33.13:2049      ESTABLISHED

```

看起来连接性不是问题，如果我们的问题与连接性无关，也许是 NFS 共享的配置有问题。

我们实际上可以使用一个命令验证 NFS 共享的设置和网络连接性——`showmount`。

## 使用`showmount`命令

`showmount`命令可用于显示通过`-e`（显示导出）标志导出的目录。此命令通过查询指定主机上的 NFS 服务来工作。

对于我们的问题，我们将查询`192.168.33.13`上的 NFS 服务：

```
[db]# showmount -e 192.168.33.13
Export list for 192.168.33.13:
/nfs 192.168.33.0/24

```

`showmount`命令的格式使用两列。第一列是共享的目录。第二个是共享该目录的网络或主机名。

在前面的示例中，我们可以看到从此主机共享的目录是`/nfs`目录。这与设备名称`192.168.33.13:/nfs`中列出的目录相匹配。

`/nfs`目录正在共享的网络是`192.166.33.0/24`网络，正如我们在网络章节中学到的那样，它是`192.168.33.0`到`192.168.33.255`的缩写。我们已经知道从以前的故障排除中，我们所在的数据库服务器位于该网络中。

我们还可以看到自从之前执行`netstat`命令以来，这并没有改变：

```
[db]# netstat -na | grep 192.168.33.13
tcp        0      0 192.168.33.12:756       192.168.33.13:2049      ESTABLISHED

```

`netstat`命令的第四列显示了在`已建立`的 TCP 连接中使用的本地 IP 地址。根据前面的输出，我们可以看到`192.168.33.12`地址是我们的数据库服务器的 IP（在前几章中已经看到）。

到目前为止，关于这个 NFS 共享的一切看起来都是正确的，从这里开始，我们需要登录到 NFS 服务器继续故障排除。

## NFS 服务器配置

一旦登录到 NFS 服务器，我们应该首先检查 NFS 服务是否正在运行：

```
[db]# systemctl status nfs
nfs-server.service - NFS server and services
 Loaded: loaded (/usr/lib/systemd/system/nfs-server.service; enabled)
 Active: active (exited) since Sat 2015-04-25 14:01:13 MST; 17h ago
 Process: 2226 ExecStart=/usr/sbin/rpc.nfsd $RPCNFSDARGS (code=exited, status=0/SUCCESS)
 Process: 2225 ExecStartPre=/usr/sbin/exportfs -r (code=exited, status=0/SUCCESS)
 Main PID: 2226 (code=exited, status=0/SUCCESS)
 CGroup: /system.slice/nfs-server.service

```

使用`systemctl`，我们可以简单地查看服务状态；从前面的输出来看，这是正常的。这是可以预料的，因为我们能够`telnet`到 NFS 服务并使用`showmount`命令来查询它。

### 探索`/etc/exports`

由于 NFS 服务正在运行且正常，下一步是检查定义了哪些目录被导出以及它们如何被导出的配置；`/etc/exports`文件：

```
[nfs]# ls -la /etc/exports
-rw-r--r--. 1 root root 40 Apr 26 08:28 /etc/exports
[nfs]# cat /etc/exports
/nfs  192.168.33.0/24(rw,no_root_squash)

```

这个文件的格式实际上与`showmount`命令的输出类似。

第一列是要共享的目录，第二列是要与之共享的网络。然而，在这个文件中，在网络定义之后还有额外的信息。

网络/子网列后面跟着一组括号，里面包含各种`NFS`选项。这些选项与我们在`/proc/mounts`文件中看到的挂载选项非常相似。

这些选项可能是我们`只读`文件系统的根本原因吗？很可能。让我们分解这两个选项以更好地理解：

+   `rw`：这允许在共享目录上进行读取和写入

+   `no_root_squash`：这禁用了`root_squash`；`root_squash`是一个将 root 用户映射到匿名用户的系统

不幸的是，这两个选项都不能强制文件系统处于`只读`模式。事实上，根据这些选项的描述，它们似乎表明这个 NFS 共享应该处于`读写`模式。

在对`/etc/exports`文件执行`ls`时，出现了一个有趣的事实：

```
[nfs]# ls -la /etc/exports
-rw-r--r--. 1 root root 40 Apr 26 08:28 /etc/exports

```

`/etc/exports`文件最近已经被修改。我们的共享文件系统实际上是以`只读`方式共享的，但是最近有人改变了`/etc/exports`文件，将文件系统导出为`读写`方式。

这种情况是完全可能的，实际上，这是 NFS 的一个常见问题。NFS 服务并不会不断地读取`/etc/exports`文件以寻找更改。事实上，只有在服务启动时才会读取这个文件。

对`/etc/exports`文件的任何更改都不会生效，直到重新加载服务或使用`exportfs`命令刷新导出的文件系统为止。

### 识别当前的导出

一个非常常见的情况是，有人对这个文件进行了更改，然后忘记运行命令来刷新导出的文件系统。我们可以使用`exportfs`命令来确定是否是这种情况：

```
[nfs]# exportfs -s
/nfs  192.168.33.0/24(rw,wdelay,no_root_squash,no_subtree_check,sec=sys,rw,secure,no_root_squash,no_all_squash)

```

当给出`-s`（显示当前导出）标志时，`exportfs`命令将简单地列出现有的共享目录，包括目录共享的选项。

从前面的输出可以看出，这个文件系统与许多未在`/etc/exports`中列出的选项共享。这是因为通过 NFS 共享的所有目录都有一个默认的选项列表，用于管理目录的共享方式。在`/etc/exports`中指定的选项实际上是用来覆盖默认设置的。

为了更好地理解这些选项，让我们分解它们：

+   `rw`：这允许在共享目录上进行读取和写入。

+   `wdelay`：这会导致 NFS 在怀疑另一个客户端正在进行写入时暂停写入请求。这旨在减少多个客户端连接时的写入冲突。

+   `no_root_squash`：这禁用了`root_squash`，它是一个将 root 用户映射到匿名用户的系统。

+   `no_subtree_check`：这禁用了`subtree`检查；子树检查实质上确保对导出子目录的目录的请求将遵守子目录更严格的策略。

+   `sec=sys`：这告诉 NFS 使用用户 ID 和组 ID 值来控制文件访问的权限和授权。

+   `secure`：这确保 NFS 只接受客户端端口低于 1024 的请求，实质上要求它来自特权 NFS 挂载。

+   `no_all_squash`：这禁用了`all_squash`，用于强制将所有权限映射到匿名用户和组。

似乎这些选项也没有解释“只读”文件系统。这似乎是一个非常棘手的故障排除问题，特别是当 NFS 服务似乎配置正确时。

### 从另一个客户端测试 NFS

由于 NFS 服务器的配置似乎正确，客户端（数据库服务器）也似乎正确，我们需要缩小问题是在客户端还是服务器端。

我们可以通过在另一个客户端上挂载文件系统并尝试相同的写入请求来做到这一点。根据配置，似乎我们只需要另一个服务器在`192.168.33.0/24`网络中执行此测试。也许我们之前章节中的博客服务器是一个好的客户端选择？

### 提示

在某些环境中，对这个问题的答案可能是否定的，因为 Web 服务器通常被认为比数据库服务器不太安全。但是，由于这只是本书的一个测试环境，所以可以接受。

一旦我们登录到博客服务器，我们可以测试是否可以使用`showmount`命令看到挂载：

```
[blog]# showmount -e 192.168.33.13
Export list for 192.168.33.13:
/nfs 192.168.33.0/24

```

这回答了两个问题。第一个是 NFS 客户端软件是否安装；由于`showmount`命令存在，答案很可能是“是”。

第二个问题是 NFS 服务是否可以从博客服务器访问，这也似乎是肯定的。

为了测试挂载，我们将简单地使用`mount`命令：

```
[blog]# mount -t nfs 192.168.33.13:/nfs /mnt

```

要使用`mount`命令挂载文件系统，语法是：`mount -t <文件系统类型> <设备> <挂载点>`。在上面的示例中，我们只是将`192.168.33.13:/nfs`设备挂载到了`/mnt`目录，文件系统类型为`nfs`。

在运行命令时，我们没有收到任何错误，但为了确保文件系统被正确挂载，我们可以使用`mount`命令，就像我们之前做的那样：

```
[blog]# mount | grep /mnt
192.168.33.13:/nfs on /mnt type nfs4 (rw,relatime,vers=4.0,rsize=65536,wsize=65536,namlen=255,hard,proto=tcp,port=0,timeo=600,retrans=2,sec=sys,clientaddr=192.168.33.11,local_lock=none,addr=192.168.33.13)

```

从`mount`命令的输出中，似乎`mount`请求成功，并且处于“读写”模式，这意味着`mount`选项类似于数据库服务器上使用的选项。

现在我们可以尝试使用`touch`命令在文件系统中创建文件来测试文件系统：

```
# touch /mnt/testfile.txt 
touch: cannot touch '/mnt/testfile.txt': Read-only file system

```

看起来问题不在客户端的配置上，因为即使我们的新客户端也无法写入这个文件系统。

### 提示

作为提示，在前面的示例中，我将`/nfs`共享挂载到了`/mnt`。`/mnt`目录被用作通用挂载点，通常被认为是可以使用的。但是，最好的做法是在挂载到`/mnt`之前确保没有其他东西挂载到`/mnt`。

# 使挂载永久化

当前，即使我们使用`mount`命令挂载了 NFS 共享，这个挂载的文件系统并不被认为是持久的。下次系统重新启动时，NFS 挂载将不会重新挂载。

这是因为在系统启动时，启动过程的一部分是读取`/etc/fstab`文件并`mount`其中定义的任何文件系统。

为了更好地理解这是如何工作的，让我们看一下数据库服务器上的`/etc/fstab`文件：

```
[db]# cat /etc/fstab

#
# /etc/fstab
# Created by anaconda on Mon Jul 21 23:35:56 2014
#
# Accessible filesystems, by reference, are maintained under '/dev/disk'
# See man pages fstab(5), findfs(8), mount(8) and/or blkid(8) for more info
#
/dev/mapper/os-root /                       xfs     defaults        1 1
UUID=be76ec1d-686d-44a0-9411-b36931ee239b /boot                   xfs     defaults        1 2
/dev/mapper/os-swap swap                    swap    defaults        0 0
192.168.33.13:/nfs  /data      nfs  defaults  0 0

```

`/etc/fstab`文件的内容实际上与`/proc/mounts`文件的内容非常相似。`/etc/fstab`文件中的第一列用于指定要挂载的设备，第二列是要挂载到的路径或挂载点，第三列只是文件系统类型，第四列是`mount`文件系统的选项。

然而，这些文件在`/etc/fstab`文件中的最后两列是不同的。这最后两列实际上是有意义的。在`fstab`文件中，第五列由`dump`命令使用。

`dump`命令是一个简单的备份实用程序，它读取`/etc/fstab`以确定要备份的文件系统。当执行 dump 实用程序时，任何值设置为`0`的文件系统都不会被备份。

尽管这个实用程序在今天并不经常使用，但`/etc/fstab`文件中的这一列是为了向后兼容而保留的。

`/etc/fstab`文件中的第六列对今天的系统非常重要。此列用于表示在引导过程中执行文件系统检查或`fsck`的顺序（通常在故障后）。

文件系统检查或`fsck`是一个定期运行的过程，检查文件系统中的错误并尝试纠正它们。这是我们将在本章稍后介绍的一个过程。

## 卸载/mnt 文件系统

由于我们不希望 NFS 共享的文件系统保持挂载在博客服务器的`/mnt`路径上，我们需要卸载文件系统。

我们可以像之前对`/boot`文件系统所做的那样，使用`umount`命令来执行此操作：

```
[blog]# umount /mnt
[blog]# mount | grep /mnt

```

从博客服务器上，我们只需使用`umount`，然后是客户端的`/mnt`挂载点来`卸载`NFS`挂载`。现在我们已经这样做了，我们可以回到 NFS 服务器继续排除故障。

# 再次排除 NFS 服务器故障

由于我们确定即使新客户端也无法写入`/nfs`共享，我们现在已经缩小了问题很可能是在服务器端而不是客户端。

早些时候，在排除 NFS 服务器故障时，我们几乎检查了关于 NFS 的所有内容。我们验证了服务实际上正在运行，可以被客户端访问，`/etc/exports`中的数据是正确的，并且当前导出的目录与`/etc/exports`中的内容匹配。此时，只剩下一个地方需要检查：`日志`文件。

默认情况下，NFS 服务没有像 Apache 或 MariaDB 那样拥有自己的日志文件。相反，RHEL 系统上的此服务利用`syslog`设施；这意味着我们的日志将在`/var/log/messages`中。

`messages`日志是基于 Red Hat Enterprise Linux 的 Linux 发行版中非常常用的日志文件。实际上，默认情况下，除了 cron 作业和身份验证之外，RHEL 系统上的每条高于 info 日志级别的 syslog 消息都会发送到`/var/log/messages`。

由于 NFS 服务将其日志消息发送到本地`syslog`服务，因此其消息也包含在`messages`日志中。

## 查找 NFS 日志消息

如果我们不知道 NFS 日志被发送到`/var/log/messages`日志文件中怎么办？有一个非常简单的技巧来确定哪个日志文件包含 NFS 日志消息。

通常，在 Linux 系统上，所有系统服务的日志文件都位于`/var/log`中。由于我们知道系统上大多数日志的默认位置，我们可以简单地浏览这些文件，以确定哪些文件可能包含 NFS 日志消息：

```
[nfs]# cd /var/log
[nfs]# grep -rc nfs ./*
./anaconda/anaconda.log:14
./anaconda/syslog:44
./anaconda/anaconda.xlog:0
./anaconda/anaconda.program.log:7
./anaconda/anaconda.packaging.log:16
./anaconda/anaconda.storage.log:56
./anaconda/anaconda.ifcfg.log:0
./anaconda/ks-script-Sr69bV.log:0
./anaconda/ks-script-lfU6U2.log:0
./audit/audit.log:60
./boot.log:4
./btmp:0
./cron:470
./cron-20150420:662
./dmesg:26
./dmesg.old:26
./grubby:0
./lastlog:0
./maillog:112386
./maillog-20150420:17
./messages:3253
./messages-20150420:11804
./sa/sa15:1
./sa/sar15:1
./sa/sa16:1
./sa/sar16:1
./sa/sa17:1
./sa/sa19:1
./sa/sar19:1
./sa/sa20:1
./sa/sa25:1
./sa/sa26:1
./secure:14
./secure-20150420:63
./spooler:0
./tallylog:0
./tuned/tuned.log:0
./wtmp:0
./yum.log:0

```

`grep`命令递归（`-r`）搜索每个文件中的字符串"`nfs`"，并输出包含字符串的行数的文件名及计数（`-c`）。

在前面的输出中，有两个日志文件包含了最多数量的字符串"`nfs`"。第一个是`maillog`，这是用于电子邮件消息的系统日志；这不太可能与 NFS 服务相关。

第二个是`messages`日志文件，正如我们所知，这是系统默认的日志文件。

即使没有关于特定系统日志记录方法的先验知识，如果您对 Linux 有一般了解，并且熟悉前面的示例中的技巧，通常可以找到包含所需数据的日志。

既然我们知道要查找的日志文件，让我们浏览一下`/var/log/messages`日志。

## 阅读`/var/log/messages`

由于这个`log`文件可能相当大，我们将使用`tail`命令和`-100`标志，这会导致`tail`只显示指定文件的最后`100`行。通过将输出限制为`100`行，我们应该只看到最相关的数据：

```
[nfs]# tail -100 /var/log/messages
Apr 26 10:25:44 nfs kernel: md/raid1:md127: Disk failure on sdb1, disabling device.
md/raid1:md127: Operation continuing on 1 devices.
Apr 26 10:25:55 nfs kernel: md: unbind<sdb1>
Apr 26 10:25:55 nfs kernel: md: export_rdev(sdb1)
Apr 26 10:27:20 nfs kernel: md: bind<sdb1>
Apr 26 10:27:20 nfs kernel: md: recovery of RAID array md127
Apr 26 10:27:20 nfs kernel: md: minimum _guaranteed_  speed: 1000 KB/sec/disk.
Apr 26 10:27:20 nfs kernel: md: using maximum available idle IO bandwidth (but not more than 200000 KB/sec) for recovery.
Apr 26 10:27:20 nfs kernel: md: using 128k window, over a total of 511936k.
Apr 26 10:27:20 nfs kernel: md: md127: recovery done.
Apr 26 10:27:41 nfs nfsdcltrack[4373]: sqlite_remove_client: unexpected return code from delete: 8
Apr 26 10:27:59 nfs nfsdcltrack[4375]: sqlite_remove_client: unexpected return code from delete: 8
Apr 26 10:55:06 nfs dhclient[3528]: can't create /var/lib/NetworkManager/dhclient-05be239d-0ec7-4f2e-a68d-b64eec03fcb2-enp0s3.lease: Read-only file system
Apr 26 11:03:43 nfs chronyd[744]: Could not open temporary driftfile /var/lib/chrony/drift.tmp for writing
Apr 26 11:55:03 nfs rpc.mountd[4552]: could not open /var/lib/nfs/.xtab.lock for locking: errno 30 (Read-only file system)
Apr 26 11:55:03 nfs rpc.mountd[4552]: can't lock /var/lib/nfs/xtab for writing

```

即使`100`行也可能相当繁琐，我已将输出截断为只包含相关行。这显示了相当多带有字符串"`nfs`"的消息；然而，并非所有这些消息都来自 NFS 服务。由于我们的 NFS 服务器主机名设置为`nfs`，因此来自该系统的每个日志条目都包含字符串"`nfs`"。

然而，即使如此，我们仍然看到了一些与`NFS`服务相关的消息，特别是以下行：

```
Apr 26 10:27:41 nfs nfsdcltrack[4373]: sqlite_remove_client: unexpected return code from delete: 8
Apr 26 10:27:59 nfs nfsdcltrack[4375]: sqlite_remove_client: unexpected return code from delete: 8
Apr 26 11:55:03 nfs rpc.mountd[4552]: could not open /var/lib/nfs/.xtab.lock for locking: errno 30 (Read-only file system)
Apr 26 11:55:03 nfs rpc.mountd[4552]: can't lock /var/lib/nfs/xtab for writing

```

这些日志条目的有趣之处在于其中一个明确指出服务`rpc.mountd`由于文件系统为`只读`而无法打开文件。然而，它试图打开的文件`/var/lib/nfs/.xtab.lock`并不是我们 NFS 共享的一部分。

由于这个文件系统不是我们 NFS 的一部分，让我们快速查看一下这台服务器上挂载的文件系统。我们可以再次使用`mount`命令来做到这一点：

```
[nfs]# mount
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime,seclabel)
devtmpfs on /dev type devtmpfs (rw,nosuid,seclabel,size=241112k,nr_inodes=60278,mode=755)
securityfs on /sys/kernel/security type securityfs (rw,nosuid,nodev,noexec,relatime)
selinuxfs on /sys/fs/selinux type selinuxfs (rw,relatime)
systemd-1 on /proc/sys/fs/binfmt_misc type autofs (rw,relatime,fd=33,pgrp=1,timeout=300,minproto=5,maxproto=5,direct)
mqueue on /dev/mqueue type mqueue (rw,relatime,seclabel)
debugfs on /sys/kernel/debug type debugfs (rw,relatime)
hugetlbfs on /dev/hugepages type hugetlbfs (rw,relatime,seclabel)
sunrpc on /var/lib/nfs/rpc_pipefs type rpc_pipefs (rw,relatime)
nfsd on /proc/fs/nfsd type nfsd (rw,relatime)
/dev/mapper/md0-root on / type xfs (ro,relatime,seclabel,attr2,inode64,noquota)
/dev/md127 on /boot type xfs (ro,relatime,seclabel,attr2,inode64,noquota)
/dev/mapper/md0-nfs on /nfs type xfs (ro,relatime,seclabel,attr2,inode64,noquota)

```

与另一台服务器一样，有相当多的挂载文件系统，但我们并不对所有这些感兴趣；只对其中的一小部分感兴趣。

```
/dev/mapper/md0-root on / type xfs (ro,relatime,seclabel,attr2,inode64,noquota)
/dev/md127 on /boot type xfs (ro,relatime,seclabel,attr2,inode64,noquota)
/dev/mapper/md0-nfs on /nfs type xfs (ro,relatime,seclabel,attr2,inode64,noquota)

```

前面的三行是我们应该感兴趣的行。这三个挂载的文件系统是我们系统定义的持久文件系统。如果我们查看这三个持久文件系统，我们可以找到一些有趣的信息。

`/`或根文件系统存在于设备`/dev/mapper/md0-root`上。这个文件系统对我们的系统非常重要，因为看起来这台服务器配置为在根文件系统(`/`)下安装整个操作系统，这是一种相当常见的设置。这个文件系统包括了问题文件`/var/lib/nfs/.xtab.lock`。

`/boot`文件系统存在于设备`/dev/md127`上，根据名称判断，这很可能是使用 Linux 软件 RAID 系统的阵列设备。`/boot`文件系统和根文件系统一样重要，因为`/boot`包含了服务器启动所需的所有文件。没有`/boot`文件系统，这个系统很可能无法重新启动，并且在下一次系统重启时会发生内核崩溃。

最后一个文件系统`/nfs`使用了`/dev/mapper/md0-nfs`设备。根据我们之前的故障排除，我们确定了这个文件系统是通过 NFS 服务导出的文件系统。

## 只读文件系统

如果我们回顾错误和`mount`的输出，我们将开始在这个系统上识别一些有趣的错误：

```
Apr 26 11:55:03 nfs rpc.mountd[4552]: could not open /var/lib/nfs/.xtab.lock for locking: errno 30 (Read-only file system)

```

错误报告称，`.xtab.lock`文件所在的文件系统是`只读`的：

```
/dev/mapper/md0-root on / type xfs (ro,relatime,seclabel,attr2,inode64,noquota)

```

从`mount`命令中，我们可以看到问题的文件系统是`/`文件系统。在查看`/`或根文件系统的选项后，我们可以看到这个文件系统实际上是使用`ro`选项挂载的。

实际上，如果我们查看这三个文件系统的选项，我们会发现`/`、`/boot`和`/nfs`都是使用`ro`选项挂载的。`rw`挂载文件系统为`读写`，`ro`选项挂载文件系统为`只读`。这意味着目前这些文件系统不能被任何用户写入。

所有三个定义的文件系统都以`只读`模式挂载是相当不寻常的配置。为了确定这是否是期望的配置，我们可以检查`/etc/fstab`文件，这是之前用来识别持久文件系统的同一个文件：

```
[nfs]# cat /etc/fstab
#
# /etc/fstab
# Created by anaconda on Wed Apr 15 09:39:23 2015
#
# Accessible filesystems, by reference, are maintained under '/dev/disk'
# See man pages fstab(5), findfs(8), mount(8) and/or blkid(8) for more info
#
/dev/mapper/md0-root    /                       xfs     defaults        0 0
UUID=7873e886-78d5-46cc-b4d9-0c385995d915 /boot                   xfs     defaults        0 0
/dev/mapper/md0-nfs     /nfs                    xfs     defaults        0 0
/dev/mapper/md0-swap    swap                    swap    defaults        0 0

```

从`/etc/fstab`文件的内容来看，这些文件系统并没有配置为以`只读`模式挂载。相反，这些文件系统是以“默认”选项挂载的。

在 Linux 上，`xfs`文件系统的“默认”选项将文件系统挂载为“读写”模式，而不是“只读”模式。如果我们查看数据库服务器上的`/etc/fstab`文件，我们可以验证这种行为：

```
[db]# cat /etc/fstab 
#
# /etc/fstab
# Created by anaconda on Mon Jul 21 23:35:56 2014
#
# Accessible filesystems, by reference, are maintained under '/dev/disk'
# See man pages fstab(5), findfs(8), mount(8) and/or blkid(8) for more info
#
/dev/mapper/os-root /                       xfs     defaults        1 1
UUID=be76ec1d-686d-44a0-9411-b36931ee239b /boot                   xfs     defaults        1 2
/dev/mapper/os-swap swap                    swap    defaults        0 0
192.168.33.13:/nfs  /data      nfs  defaults  0 0

```

在数据库服务器上，我们可以看到`/`或根文件系统的文件系统选项也设置为“默认”。然而，当我们使用`mount`命令查看文件系统选项时，我们可以看到`rw`选项以及一些其他默认选项被应用：

```
[db]# mount | grep root
/dev/mapper/os-root on / type xfs (rw,relatime,seclabel,attr2,inode64,noquota)

```

这证实了三个持久文件系统的“只读”状态不是期望的配置。

### 识别磁盘问题

如果`/etc/fstab`文件系统被特别配置为以“读写”方式挂载文件系统，并且`mount`命令显示文件系统以“只读”模式挂载。这清楚地表明所涉及的文件系统可能在引导过程的一部分挂载后被重新挂载。

正如我们之前讨论的，当 Linux 系统引导时，它会读取`/etc/fstab`文件并挂载所有定义的文件系统。但是，挂载文件系统的过程就此停止。默认情况下，没有持续监视`/etc/fstab`文件进行更改并挂载或卸载修改后的文件系统的过程。

实际上，看到新创建的文件系统未挂载但在`/etc/fstab`文件中指定是很常见的，因为有人在编辑`/etc/fstab`文件后忘记使用`mount`命令将其挂载。

然而，很少见到文件系统被挂载为“只读”，但之后`fstab`被更改。

实际上，对于我们的情况来说，这并不容易实现，因为`/etc/fstab`是不可访问的，因为`/`文件系统是“只读”的：

```
[nfs]# touch /etc/fstab
touch: cannot touch '/etc/fstab': Read-only file system

```

这意味着我们的文件系统处于“只读”模式，是在这些文件系统最初被挂载后执行的。

实际上，导致这种状态的罪魁祸首实际上是我们之前浏览的日志消息：

```
Apr 26 10:25:44 nfs kernel: md/raid1:md127: Disk failure on sdb1, disabling device.
md/raid1:md127: Operation continuing on 1 devices.
Apr 26 10:25:55 nfs kernel: md: unbind<sdb1>
Apr 26 10:25:55 nfs kernel: md: export_rdev(sdb1)
Apr 26 10:27:20 nfs kernel: md: bind<sdb1>
Apr 26 10:27:20 nfs kernel: md: recovery of RAID array md127
Apr 26 10:27:20 nfs kernel: md: minimum _guaranteed_  speed: 1000 KB/sec/disk.
Apr 26 10:27:20 nfs kernel: md: using maximum available idle IO bandwidth (but not more than 200000 KB/sec) for recovery.
Apr 26 10:27:20 nfs kernel: md: using 128k window, over a total of 511936k.
Apr 26 10:27:20 nfs kernel: md: md127: recovery done.

```

从`/var/log/messages`日志文件中，我们实际上可以看到在某个时候，软件 RAID（`md`）存在问题，标记磁盘`/dev/sdb1`为失败。

在 Linux 中，默认情况下，如果物理磁盘驱动器失败或以其他方式对内核不可用，Linux 内核将以“只读”模式重新挂载驻留在该物理磁盘上的文件系统。正如前面的错误消息中所述，`sdb1`物理磁盘和`md127` RAID 设备的故障似乎是文件系统变为“只读”的根本原因。

由于软件 RAID 和硬件问题是下一章的主题，我们将推迟故障排除 RAID 和磁盘问题至第八章，“硬件故障排除”。

# 恢复文件系统

现在我们知道文件系统为何处于“只读”模式，我们可以解决它。将文件系统从“只读”模式强制转换为“读写”模式实际上非常容易。但是，由于我们不知道导致文件系统进入“只读”模式的故障的所有情况，我们必须小心谨慎。

从文件系统错误中恢复可能非常棘手；如果操作不当，我们很容易陷入破坏文件系统或以其他方式导致部分甚至完全数据丢失的情况。

由于我们有多个文件系统处于“只读”模式，我们将首先从`/boot`文件系统开始。我们之所以从`/boot`文件系统开始，是因为这从技术上讲是最好的文件系统来体验数据丢失。由于`/boot`文件系统仅在服务器引导过程中使用，我们可以确保在`/boot`文件系统恢复之前不重新启动此服务器。

在可能的情况下，最好在采取任何行动之前备份数据。在接下来的步骤中，我们将假设`/boot`文件系统定期备份。

## 卸载文件系统

为了恢复这个文件系统，我们将执行三个步骤。在第一步中，我们将卸载`/boot`文件系统。在采取任何其他步骤之前卸载文件系统，我们将确保文件系统不会被主动写入。这一步将大大减少在恢复过程中文件系统损坏的机会。

但是，在卸载文件系统之前，我们需要确保没有应用程序或服务正在尝试写入我们正在尝试恢复的文件系统。

为了确保这一点，我们可以使用`lsof`命令。 `lsof`命令用于列出打开的文件；我们可以浏览此列表，以确定`/boot`文件系统中是否有任何文件是打开的。

如果我们只是运行没有选项的`lsof`，它将打印所有当前打开的文件：

```
[nfs]# lsof
COMMAND    PID TID           USER   FD      TYPE             DEVICE SIZE/OFF       NODE NAME
systemd      1               root  cwd       DIR              253,1 4096        128 /

```

通过向`lsof`添加“-r”（重复）标志，我们告诉它以重复模式运行。然后我们可以将此输出传输到`grep`命令，其中我们可以过滤在`/boot`文件系统上打开的文件的输出：

```
[nfs]# lsof -r | grep /boot

```

如果前面的命令一段时间内没有产生任何输出，可以安全地继续卸载文件系统。如果命令打印出任何打开的文件，最好找到适当的进程读取/写入文件系统并在卸载文件系统之前停止它们。

由于我们的例子在`/boot`文件系统上没有打开的文件，我们可以继续卸载`/boot`文件系统。为此，我们将使用`umount`命令：

```
[nfs]# umount /boot

```

幸运的是，`umount`命令没有出现错误。如果文件正在被写入，我们在卸载时可能会收到错误。通常，此错误包括一条消息，指出**设备正忙**。为了验证文件系统已成功卸载，我们可以再次使用`mount`命令：

```
[nfs]# mount | grep /boot

```

现在`/boot`文件系统已经卸载，我们可以执行我们恢复过程的第二步。我们现在可以检查和修复文件系统。

## 文件系统检查与 fsck

Linux 有一个非常有用的文件系统检查命令，可以用来检查和修复文件系统。这个命令叫做`fsck`。

然而，`fsck`命令实际上并不只是一个命令。每种文件系统类型都有其自己的检查一致性和修复问题的方法。 `fsck`命令只是一个调用相应文件系统的适当命令的包装器。

例如，当对`ext4`文件系统运行`fsck`命令时，实际执行的命令是`e2fsck`。 `e2fsck`命令用于`ext2`到`ext4`文件系统类型。

我们可以以两种方式调用`e2fsck`，直接或间接通过`fsck`命令。在这个例子中，我们将使用`fsck`方法，因为这可以用于 Linux 支持的几乎所有文件系统。

要使用`fsck`命令简单地检查文件系统的一致性，我们可以不带标志运行它，并指定要检查的磁盘设备：

```
[nfs]# fsck /dev/sda1
fsck from util-linux 2.20.1
e2fsck 1.42.9 (4-Feb-2014)
cloudimg-rootfs: clean, 85858/2621440 files, 1976768/10485504 blocks

```

在前面的例子中，我们可以看到文件系统没有发现任何错误。如果有的话，我们会被问及是否希望`e2fsck`实用程序来纠正这些错误。

如果我们愿意，我们可以通过传递“-y”（是）标志使`fsck`自动修复发现的问题：

```
[nfs]# fsck -y /dev/sda1
fsck from util-linux 2.20.1
e2fsck 1.42 (29-Nov-2011)
/dev/sda1 contains a file system with errors, check forced.
Pass 1: Checking inodes, blocks, and sizes
Inode 2051351 is a unknown file type with mode 0137642 but it looks 
like it is really a directory.
Fix? yes

Pass 2: Checking directory structure
Entry 'test' in / (2) has deleted/unused inode 49159\.  Clear? yes

Pass 3: Checking directory connectivity
Pass 4: Checking reference counts
Pass 5: Checking group summary information

/dev/sda1: ***** FILE SYSTEM WAS MODIFIED *****
/dev/sda1: 96/2240224 files (7.3% non-contiguous), 3793508/4476416 blocks

```

此时，`e2fsck`命令将尝试纠正它发现的任何错误。幸运的是，从我们的例子中，错误能够被纠正；然而，也有时候情况并非如此。

### fsck 和 xfs 文件系统

当对`xfs`文件系统运行`fsck`命令时，结果实际上是完全不同的：

```
[nfs]# fsck /dev/md127 
fsck from util-linux 2.23.2
If you wish to check the consistency of an XFS filesystem or
repair a damaged filesystem, see xfs_repair(8).

```

`xfs`文件系统不同于`ext2/3/4`文件系统系列，因为每次挂载文件系统时都会执行一致性检查。这并不意味着您不能手动检查和修复文件系统。要检查`xfs`文件系统，我们可以使用`xfs_repair`实用程序：

```
[nfs]# xfs_repair -n /dev/md127
Phase 1 - find and verify superblock...
Phase 2 - using internal log
 - scan filesystem freespace and inode maps...
 - found root inode chunk
Phase 3 - for each AG...
 - scan (but don't clear) agi unlinked lists...
 - process known inodes and perform inode discovery...
 - agno = 0
 - agno = 1
 - agno = 2
 - agno = 3
 - process newly discovered inodes...
Phase 4 - check for duplicate blocks...
 - setting up duplicate extent list...
 - check for inodes claiming duplicate blocks...
 - agno = 0
 - agno = 1
 - agno = 2
 - agno = 3
No modify flag set, skipping phase 5
Phase 6 - check inode connectivity...
 - traversing filesystem ...
 - traversal finished ...
 - moving disconnected inodes to lost+found ...
Phase 7 - verify link counts...
No modify flag set, skipping filesystem flush and exiting.

```

使用`-n`（不修改）标志后跟要检查的设备执行`xfs_repair`实用程序时，它只会验证文件系统的一致性。在这种模式下运行时，它根本不会尝试修复文件系统。

要以修复文件系统的模式运行`xfs_repair`，只需省略`-n`标志，如下所示：

```
[nfs]# xfs_repair /dev/md127
Phase 1 - find and verify superblock...
Phase 2 - using internal log
 - zero log...
 - scan filesystem freespace and inode maps...
 - found root inode chunk
Phase 3 - for each AG...
 - scan and clear agi unlinked lists...
 - process known inodes and perform inode discovery...
 - agno = 0
 - agno = 1
 - agno = 2
 - agno = 3
 - process newly discovered inodes...
Phase 4 - check for duplicate blocks...
 - setting up duplicate extent list...
 - check for inodes claiming duplicate blocks...
 - agno = 0
 - agno = 1
 - agno = 2
 - agno = 3
Phase 5 - rebuild AG headers and trees...
 - reset superblock...
Phase 6 - check inode connectivity...
 - resetting contents of realtime bitmap and summary inodes
 - traversing filesystem ...
 - traversal finished ...
 - moving disconnected inodes to lost+found ...
Phase 7 - verify and correct link counts...
Done

```

从前面的`xfs_repair`命令的输出来看，我们的`/boot`文件系统似乎不需要任何修复过程。

### 这些工具是如何修复文件系统的？

你可能会认为使用`fsck`和`xfs_repair`等工具修复这个文件系统非常容易。原因很简单，这是因为`xfs`和`ext2/3/4`等文件系统的设计。`xfs`和`ext2/3/4`家族都是日志文件系统；这意味着这些类型的文件系统会记录对文件系统对象（如文件、目录等）所做的更改。 

这些更改将保存在日志中，直到更改提交到主文件系统。`xfs_repair`实用程序只是查看这个日志，并重放未提交到主文件系统的最后更改。这些文件系统日志使文件系统在意外断电或系统重新启动等情况下非常有韧性。

不幸的是，有时文件系统的日志和诸如`xfs_repair`之类的工具并不足以纠正情况。

在这种情况下，还有一些更多的选项，比如以强制模式运行修复。然而，这些选项应该总是保留作为最后的努力，因为它们有时会导致文件系统损坏。

如果你发现自己有一个损坏且无法修复的文件系统，最好的办法可能就是重新创建文件系统并恢复备份，如果有备份的话...

## 挂载文件系统

现在`/boot`文件系统已经经过检查和修复，我们可以简单地重新挂载它以验证数据是否正确。为此，我们可以简单地运行`mount`命令，然后跟上`/boot`：

```
[nfs]# mount /boot
[nfs]# mount | grep /boot
/dev/md127 on /boot type xfs (rw,relatime,seclabel,attr2,inode64,noquota)

```

当文件系统在`/etc/fstab`文件中定义时，可以只使用`mount`点调用`mount`和`umount`命令。这将导致这两个命令根据`/etc/fstab`文件中的定义来`mount`或`unmount`文件系统。

从`mount`的输出来看，我们的`/boot`文件系统现在是`读写`而不是`只读`。如果我们执行`ls`命令，我们也应该仍然看到我们的原始数据：

```
[nfs]# ls /boot
config-3.10.0-229.1.2.el7.x86_64                         initrd-plymouth.img
config-3.10.0-229.el7.x86_64                             symvers-3.10.0-229.1.2.el7.x86_64.gz
grub                                                     symvers-3.10.0-229.el7.x86_64.gz
grub2                                                    System.map-3.10.0-229.1.2.el7.x86_64
initramfs-0-rescue-3f370097c831473a8cfec737ff1d6c55.img  System.map-3.10.0-229.el7.x86_64
initramfs-3.10.0-229.1.2.el7.x86_64.img                  vmlinuz-0-rescue-3f370097c831473a8cfec737ff1d6c55
initramfs-3.10.0-229.1.2.el7.x86_64kdump.img             vmlinuz-3.10.0-229.1.2.el7.x86_64
initramfs-3.10.0-229.el7.x86_64.img                      vmlinuz-3.10.0-229.el7.x86_64
initramfs-3.10.0-229.el7.x86_64kdump.img

```

看来我们的恢复步骤取得了成功！现在我们已经用`/boot`文件系统测试过它们，我们可以开始修复`/nfs`文件系统了。

## 修复其他文件系统

修复`/nfs`文件系统的步骤实际上与`/boot`文件系统的步骤基本相同，只有一个主要的区别，如下所示：

```
[nfs]# lsof -r | grep /nfs
rpc.statd 1075            rpcuser  cwd       DIR              253,1 40     592302 /var/lib/nfs/statd
rpc.mount 2282               root  cwd       DIR              253,1 4096    9125499 /var/lib/nfs
rpc.mount 2282               root    4u      REG                0,3 0 4026532125 /proc/2280/net/rpc/nfd.export/channel
rpc.mount 2282               root    5u      REG                0,3 0 4026532129 /proc/2280/net/rpc/nfd.fh/channel

```

使用`lsof`检查`/nfs`文件系统上的打开文件时，我们可能看不到 NFS 服务进程。然而，很有可能 NFS 服务在`lsof`命令停止后会尝试访问这个共享文件系统中的文件。为了防止这种情况，最好（如果可能的话）在对共享文件系统进行任何更改时停止 NFS 服务：

```
[nfs]# systemctl stop nfs

```

一旦 NFS 服务停止，其余步骤都是一样的：

```
[nfs]# umount /nfs
[nfs]# xfs_repair /dev/md0/nfs
Phase 1 - find and verify superblock...
Phase 2 - using internal log
 - zero log...
 - scan filesystem freespace and inode maps...
 - found root inode chunk
Phase 3 - for each AG...
 - scan and clear agi unlinked lists...
 - process known inodes and perform inode discovery...
 - agno = 0
 - agno = 1
 - agno = 2
 - agno = 3
 - process newly discovered inodes...
Phase 4 - check for duplicate blocks...
 - setting up duplicate extent list...
 - check for inodes claiming duplicate blocks...
 - agno = 0
 - agno = 1
 - agno = 2
 - agno = 3
Phase 5 - rebuild AG headers and trees...
 - reset superblock...
Phase 6 - check inode connectivity...
 - resetting contents of realtime bitmap and summary inodes
 - traversing filesystem ...
 - traversal finished ...
 - moving disconnected inodes to lost+found ...
Phase 7 - verify and correct link counts...
done

```

文件系统修复后，我们可以简单地按如下方式重新挂载它：

```
[nfs]# mount /nfs
[nfs]# mount | grep /nfs
nfsd on /proc/fs/nfsd type nfsd (rw,relatime)
/dev/mapper/md0-nfs on /nfs type xfs (rw,relatime,seclabel,attr2,inode64,noquota)

```

重新挂载`/nfs`文件系统后，我们可以看到选项显示为`rw`，这意味着它是`可读写`的。

### 恢复`/`（根）文件系统

`/`或`root`文件系统有点不同。它不同，因为它是包含大部分 Linux 软件包、二进制文件和命令的顶层文件系统。这意味着我们不能简单地卸载这个文件系统，否则就会丢失重新挂载它所需的工具。

因此，我们实际上将使用`mount`命令重新挂载`/`文件系统，而无需先卸载它：

```
[nfs]# mount -o remount /

```

为了告诉`mount`命令卸载然后重新挂载文件系统，我们只需要传递`-o`（选项）标志，后面跟着选项`remount`。`-o`标志允许您从命令行传递文件系统选项，如`rw`或`ro`。当我们重新挂载`/`文件系统时，我们只是传递重新挂载文件系统选项：

```
# mount | grep root
/dev/mapper/md0-root on / type xfs (rw,relatime,seclabel,attr2,inode64,noquota)

```

如果我们使用`mount`命令来显示已挂载的文件系统，我们可以验证`/`文件系统已重新挂载为`读写`访问。由于文件系统类型为`xfs`，重新挂载应该导致文件系统执行一致性检查和修复。如果我们对`/`文件系统的完整性有任何疑问，下一步应该是简单地重新启动 NFS 服务器。

如果服务器无法挂载`/`文件系统，`xfs_repair`实用程序将自动调用。

# 验证

目前，我们可以看到 NFS 服务器的文件系统问题已经恢复。我们现在应该验证我们的 NFS 客户端能否写入 NFS 共享。但在这之前，我们还应该先重新启动之前停止的 NFS 服务：

```
[nfs]# systemctl start nfs
[nfs]# systemctl status nfs
nfs-server.service - NFS server and services
 Loaded: loaded (/usr/lib/systemd/system/nfs-server.service; enabled)
 Active: active (exited) since Mon 2015-04-27 22:20:46 MST; 6s ago
 Process: 2278 ExecStopPost=/usr/sbin/exportfs -f (code=exited, status=0/SUCCESS)
 Process: 3098 ExecStopPost=/usr/sbin/exportfs -au (code=exited, status=1/FAILURE)
 Process: 3095 ExecStop=/usr/sbin/rpc.nfsd 0 (code=exited, status=0/SUCCESS)
 Process: 3265 ExecStart=/usr/sbin/rpc.nfsd $RPCNFSDARGS (code=exited, status=0/SUCCESS)
 Process: 3264 ExecStartPre=/usr/sbin/exportfs -r (code=exited, status=0/SUCCESS)
 Main PID: 3265 (code=exited, status=0/SUCCESS)
 CGroup: /system.slice/nfs-server.service

```

一旦 NFS 服务启动，我们可以使用`touch`命令从客户端进行测试：

```
[db]# touch /data/testfile.txt
[db]# ls -la /data/testfile.txt 
-rw-r--r--. 1 root root 0 Apr 28 05:24 /data/testfile.txt

```

看起来我们已经成功解决了问题。

另外，如果我们注意到对 NFS 共享的请求花费了很长时间，可能需要在客户端上卸载并重新挂载 NFS 共享。如果 NFS 客户端没有意识到 NFS 服务器已重新启动，这是一个常见问题。

# 总结

在本章中，我们深入探讨了文件系统的挂载方式，NFS 的配置以及文件系统进入`只读`模式时应该采取的措施。我们甚至进一步手动修复了一个物理磁盘设备出现问题的文件系统。

在下一章中，我们将进一步解决硬件故障的问题。这意味着查看硬件消息日志，解决硬盘 RAID 集的故障以及许多其他与硬件相关的故障排除步骤。
