# Linux 快速学习手册（四）

> 原文：[`zh.annas-archive.org/md5/d44a95bd11f73f80156880d7ba808e3a`](https://zh.annas-archive.org/md5/d44a95bd11f73f80156880d7ba808e3a)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

Sudo 的威力

在本章中，您将学习如何为系统上的非 root 用户授予权限，以便他们可以运行特权命令。在现实生活中，系统管理员不应该将 root 密码给系统上的任何用户。但是，系统上的一些用户可能需要运行特权命令；现在的问题是：*非 root 用户如何可以运行特权命令而不获取对系统的 root 访问权限？*好吧，让我来告诉你！

# 第十五章：特权命令的示例

您会发现大多数需要 root 权限的命令在`/sbin`和`/usr/sbin`目录中。让我们切换到用户`smurf`：

```
elliot@ubuntu-linux:~$ su - smurf 
Password:
smurf@ubuntu-linux:~$
```

现在让我们看看`smurf`是否可以向系统添加新用户：

```
smurf@ubuntu-linux:~$ useradd bob 
useradd: Permission denied.
```

用户`smurf`收到了权限被拒绝的错误。那是因为`useradd`命令是一个特权命令。好吧！让我们尝试安装`terminator`软件包，我必须说这是一个非常酷的终端仿真器：

```
smurf@ubuntu-linux:~$ apt-get install terminator
E: Could not open lock file /var/lib/dpkg/lock-frontend - open
 (13: Permission denied)
E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), 
are you root?
```

再次！用户`smurf`遇到了错误。没有 root 权限生活就不好玩，我听到你在说。

# 使用 sudo 授予权限

用户`smurf`现在非常难过，因为他无法在系统上添加用户`bob`或安装`terminator`软件包。您可以使用`visudo`命令授予用户`smurf`运行他想要的两个特权命令的权限。

以 root 用户身份运行`visudo`命令：

```
root@ubuntu-linux:~# visudo
```

这将打开文件`/etc/sudoers`，以便您可以编辑它：

```
# This file MUST be edited with the 'visudo' command as root. 
#
# Please consider adding local content in /etc/sudoers.d/ instead of 
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file. 
#
Defaults           env_reset
Defaults           mail_badpass 
# Host alias specification 
# User alias specification 
# Cmnd alias specification
# User privilege specification 
root               ALL=(ALL:ALL) ALL
# Members of the admin group may gain root privileges
%admin             ALL=(ALL) ALL
# Allow members of group sudo to execute any command
%sudo              ALL=(ALL:ALL) ALL
# See sudoers(5) for more information on "#include" directives: 
#includedir /etc/sudoers.d
```

所有以井号字符开头的行都是注释，因此只关注这些行：

```
root   ALL=(ALL:ALL) ALL
%admin ALL=(ALL) ALL
%sudo  ALL=(ALL:ALL) ALL
```

第一行`root ALL=(ALL:ALL) ALL`是一个规则，授予用户`root`在系统上运行所有命令的权限。

现在我们可以添加一个规则，授予用户`smurf`运行`useradd`命令的权限。`/etc/sudoers`文件中规则的语法规范如下：

```
user hosts=(user:group) commands
```

现在将以下规则添加到`/etc/sudoers`文件中：

```
smurf    ALL=(ALL)       /usr/sbin/useradd
```

`ALL`关键字表示没有限制。请注意，您还必须包括命令的完整路径。现在，保存并退出文件，然后切换到用户`smurf`：

```
root@ubuntu-linux:~# su - smurf 
smurf@ubuntu-linux:~$
```

现在在`useradd`命令之前加上`sudo`，如下所示：

```
smurf@ubuntu-linux:~$ sudo useradd bob 
[sudo] password for smurf: 
smurf@ubuntu-linux:~$ 
```

它将提示用户`smurf`输入密码；输入密码，就这样！用户`bob`已添加：

```
smurf@ubuntu-linux:~$ id bob
uid=1005(bob) gid=1005(bob) groups=1005(bob) 
smurf@ubuntu-linux:~$
```

酷！所以`smurf`现在可以向系统添加用户；但是，他仍然无法在系统上安装任何软件包：

```
smurf@ubuntu-linux:~$ sudo apt-get install terminator
Sorry, user smurf is not allowed to execute '/usr/bin/apt-get install 
terminator' as root on ubuntu-linux.
```

现在让我们来修复这个问题。切换回 root 用户，并运行`visudo`命令来编辑用户`smurf`的`sudo`规则：

```
smurf ALL=(ALL) NOPASSWD: /usr/sbin/useradd, /usr/bin/apt-get install terminator
```

请注意，我还添加了`NOPASSWD`，这样`smurf`就不会被提示输入密码。我还添加了安装`terminator`软件包的命令。现在，保存并退出，然后切换回用户`smurf`，尝试安装`terminator`软件包：

```
smurf@ubuntu-linux:~$ sudo apt-get install terminator 
Reading package lists... Done
Building dependency tree
Reading state information... Done
The following packages were automatically installed and are no longer required: 
 gsfonts-x11 java-common
Use 'sudo apt autoremove' to remove them. 
The following NEW packages will be installed:
 terminator
```

成功！请注意，`sudo`规则只授予`smurf`安装`terminator`软件包的权限。如果他尝试安装其他软件包，他将收到错误提示：

```
smurf@ubuntu-linux:~$ sudo apt-get install cmatrix
Sorry, user smurf is not allowed to execute '/usr/bin/apt-get install cmatrix' 
as root on ubuntu-linux.
```

# 用户和命令别名

您可以使用用户别名在`/etc/sudoers`文件中引用多个用户。例如，您可以创建一个名为`MANAGERS`的用户别名，其中包括`usersmurf`和`bob`，如下所示：

```
User_Alias MANAGERS = smurf,bob
```

您可以使用命令别名将多个命令分组在一起。例如，您可以创建一个名为`USER_CMDS`的命令别名，其中包括`useradd`、`userdel`和`usermod`命令：

```
Cmnd_Alias USER_CMDS = /usr/sbin/useradd, /usr/sbin/userdel, /usr/sbin/usermod
```

现在您可以同时使用别名：

```
MANAGERS ALL=(ALL) USER_CMDS
```

授予用户`smurf`和`bob`运行`useradd`、`userdel`和`usermod`命令的权限。

# 组权限

您还可以在`/etc/sudoers`文件中指定组。组名前面加上百分号字符，如下所示：

```
%group hosts=(user:group) commands
```

以下规则将授予`developers`组在系统上安装任何软件包的权限：

```
%developers ALL=(ALL) NOPASSWD: /usr/bin/apt-get install
```

以下规则将授予`developers`组在系统上运行任何命令的权限：

```
%developers ALL=(ALL) NOPASSWD: ALL
```

# 列出用户权限

您可以使用命令`sudo -lU`来显示用户可以运行的`sudo`命令列表：

```
sudo -lU username 
```

例如，您可以运行以下命令：

```
root@ubuntu-linux:~# sudo -lU smurf
Matching Defaults entries for smurf on ubuntu-linux: 
 env_reset, mail_badpass

User smurf may run the following commands on ubuntu-linux:
 (ALL) NOPASSWD: /usr/sbin/useradd, /usr/bin/apt-get install terminator
```

列出用户`smurf`可以运行的所有`sudo`命令。

如果用户不被允许运行任何`sudo`命令，则`sudo-lU`命令的输出将如下所示：

```
root@ubuntu-linux:~# sudo -lU rachel
User rachel is not allowed to run sudo on ubuntu-linux.
```

# visudo 与/etc/sudoers

您可能已经注意到，我使用`visudo`命令编辑文件`/etc/sudoers`，您可能会问自己一个非常合理的问题：为什么不直接编辑文件`/etc/sudoers`而不使用`visudo`？好吧，我将以实际的方式回答您的问题。

首先，运行`visudo`命令并添加以下行：

```
THISLINE=WRONG
```

现在尝试保存并退出：

```
root@ubuntu-linux:~# visudo
>>> /etc/sudoers: syntax error near line 14 <<< 
What now?
Options are:
 (e)dit sudoers file again
 e(x)it without saving changes to sudoers file 
 (Q)uit and save changes to sudoers file (DANGER!)
What now?
```

正如您所看到的，`visudo`命令检测到错误，并指定了错误发生的行号。

为什么这很重要？好吧，如果您保存了带有错误的文件，`/etc/sudoers`中的所有`sudo`规则都将无法工作！让我们按`Q`保存更改，然后尝试列出用户`smurf`可以运行的`sudo`命令：

```
What now? Q
root@ubuntu-linux:~# sudo -lU smurf
>>> /etc/sudoers: syntax error near line 14 <<< 
sudo: parse error in /etc/sudoers near line 14 
sudo: no valid sudoers sources found, quitting 
sudo: unable to initialize policy plugin
```

我们遇到了一个错误，所有的`sudo`规则现在都被破坏了！返回并运行`visudo`命令，删除包含错误的行。

如果您直接编辑文件`/etc/sudoers`而不使用`visudo`命令，它将不会检查语法错误，这可能会导致灾难性后果，就像您看到的那样。因此，这里的经验法则是：在编辑`/etc/sudoers`文件时始终使用`visudo`。

# 知识检查

对于以下练习，打开您的终端并尝试解决以下任务：

1.  添加一个`sudo`规则，使用户`smurf`可以运行`fdisk`命令。

1.  添加一个`sudo`规则，使`developers`组可以运行`apt-get`命令。

1.  列出用户`smurf`的所有`sudo`命令。


网络出了什么问题？

当网络出现问题时，我们都会感到愤怒。没有连接到互联网，这个世界就没有乐趣。在本章中，你将学习 Linux 网络的基础知识。你还将学习如何检查两个主机之间的网络连接，并获得对 DNS 工作原理的实际理解，以及更多！

# 第十六章：测试网络连接

在 Linux 机器上检查是否有互联网访问的简单方法是尝试连接互联网上的任何远程主机（服务器）。这可以通过使用`ping`命令来完成。一般来说，`ping`命令的语法如下：

```
ping [options] host
```

例如，要测试你是否能够到达`google.com`，你可以运行以下命令：

```
root@ubuntu-linux:~# ping google.com
PING google.com (172.217.1.14) 56(84) bytes of data.
64 bytes from iad23s25-in-f14.1e100.net (172.217.1.14): icmp_seq=1 ttl=55 time=38.7 ms 
64 bytes from iad23s25-in-f14.1e100.net (172.217.1.14): icmp_seq=2 ttl=55 time=38.7 ms 
64 bytes from iad23s25-in-f14.1e100.net (172.217.1.14): icmp_seq=3 ttl=55 time=40.4 ms 
64 bytes from iad23s25-in-f14.1e100.net (172.217.1.14): icmp_seq=4 ttl=55 time=36.6 ms 
64 bytes from iad23s25-in-f14.1e100.net (172.217.1.14): icmp_seq=5 ttl=55 time=40.8 ms 
64 bytes from iad23s25-in-f14.1e100.net (172.217.1.14): icmp_seq=6 ttl=55 time=38.6 ms 
64 bytes from iad23s25-in-f14.1e100.net (172.217.1.14): icmp_seq=7 ttl=55 time=38.9 ms 
64 bytes from iad23s25-in-f14.1e100.net (172.217.1.14): icmp_seq=8 ttl=55 time=37.1 ms
^C
--- google.com ping statistics ---
8 packets transmitted, 8 received, 0% packet loss, time 66ms 
rtt min/avg/max/mdev = 36.555/38.724/40.821/1.344 ms
```

`ping`命令发送一个叫做**ICMP 回显请求**的数据包（数据单位）到指定的主机，并等待主机发送一个叫做**ICMP 回显回复**的数据包来确认它确实收到了初始数据包。如果主机像我们在例子中看到的那样回复，那么就证明我们能够到达主机。这就像你给朋友家寄一个包裹，等待朋友发短信确认收到一样。

请注意，没有任何选项，`ping`命令会持续发送数据包，直到你按下*Ctrl* + *C*。

你可以使用`-c`选项来指定你想发送到主机的数据包数量。例如，只向`google.com`发送三个数据包，你可以运行以下命令：

```
root@ubuntu-linux:~# ping -c 3 google.com
PING google.com (172.217.1.14) 56(84) bytes of data.

64 bytes from iad23s25-in-f14.1e100.net (172.217.1.14): icmp_seq=1 ttl=55 time=39.3 ms 
64 bytes from iad23s25-in-f14.1e100.net (172.217.1.14): icmp_seq=2 ttl=55 time=49.7 ms 
64 bytes from iad23s25-in-f14.1e100.net (172.217.1.14): icmp_seq=3 ttl=55 time=40.8 ms

--- google.com ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 59ms rtt min/avg/max/mdev = 39.323/43.267/49.708/4.595 ms
```

如果你没有连接到互联网，你将从`ping`命令得到以下输出：

```
root@ubuntu-linux:~# ping google.com
ping: google.com: Name or service not known
```

# 列出你的网络接口

你可以通过查看`/sys/class/net`目录的内容来列出系统上可用的网络接口：

```
root@ubuntu-linux:~# ls /sys/class/net 
eth0 lo wlan0
```

我的系统上有三个网络接口：

1.  `eth0`：以太网接口

1.  `lo`：回环接口

1.  `wlan0`：Wi-Fi 接口

请注意，根据你的计算机硬件，你可能会得到不同的网络接口名称。

## ip 命令

你也可以使用`ip link show`命令查看系统上可用的网络接口：

```
root@ubuntu-linux:~# ip link show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
 link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast state DOWN mode DEFAULT group default qlen 1000
 link/ether f0:de:f1:d3:e1:e1 brd ff:ff:ff:ff:ff:ff
3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DORMANT group default qlen 1000
 link/ether 10:0b:a9:6c:89:a0 brd ff:ff:ff:ff:ff:ff
```

## nmcli 命令

我更喜欢的另一种方法是使用`nmcli`设备状态命令：

```
root@ubuntu-linux:~# nmcli device status 
DEVICE TYPE STATE CONNECTION
wlan0 wifi      connected   SASKTEL0206-5G 
eth0  ethernet  unavailable --
lo    loopback  unmanaged   --
```

你可以从输出中看到每个网络接口的连接状态。我目前是通过我的 Wi-Fi 接口连接到互联网的。

# 检查你的 IP 地址

没有手机号码，你就不能给朋友打电话；同样，你的计算机需要一个 IP 地址才能连接到互联网。你可以使用许多不同的方法来检查你的机器的 IP 地址。你可以使用老式（但仍然流行的）`ifconfig`命令，后面跟着连接到互联网的网络接口的名称：

```
root@ubuntu-linux:~# ifconfig wlan0
wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500
 inet 172.16.1.73 netmask 255.255.255.0 broadcast 172.16.1.255 
       inet6 fe80::3101:321b:5ec3:cf9 prefixlen 64 scopeid 0x20<link> 
       ether 10:0b:a9:6c:89:a0 txqueuelen 1000 (Ethernet)
 RX packets 265 bytes 27284 (26.6 KiB)
 RX errors 0 dropped 0 overruns 0 frame 0
 TX packets 165 bytes 28916 (28.2 KiB)
 TX errors 0 dropped 0 overruns 0 carrier 0 collisions 0
```

你也可以使用`-a`选项列出所有网络接口：

```
root@ubuntu-linux:~# ifconfig -a
eth0: flags=4099<UP,BROADCAST,MULTICAST> mtu 1500
 ether f0:de:f1:d3:e1:e1 txqueuelen 1000 (Ethernet) 
      RX packets 0 bytes 0 (0.0 B)
 RX errors 0 dropped 0 overruns 0 frame 0
 TX packets 0 bytes 0 (0.0 B)
 TX errors 0 dropped 0 overruns 0 carrier 0 collisions 0 
      device interrupt 20 memory 0xf2500000-f2520000

lo: flags=73<UP,LOOPBACK,RUNNING> mtu 65536
 inet 127.0.0.1 netmask 255.0.0.0
 inet6 ::1 prefixlen 128 scopeid 0x10<host>
 loop txqueuelen 1000 (Local Loopback) 
     RX packets 4 bytes 156 (156.0 B)
 RX errors 0 dropped 0 overruns 0 frame 0
 TX packets 4 bytes 156 (156.0 B)
 TX errors 0 dropped 0 overruns 0 carrier 0 collisions 0

wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500
 inet 172.16.1.73 netmask 255.255.255.0 broadcast 172.16.1.255 
     inet6 fe80::3101:321b:5ec3:cf9 prefixlen 64 scopeid 0x20<link> 
     ether 10:0b:a9:6c:89:a0 txqueuelen 1000 (Ethernet)
 RX packets 482 bytes 45500 (44.4 KiB)
 RX errors 0 dropped 0 overruns 0 frame 0
 TX packets 299 bytes 57788 (56.4 KiB)
 TX errors 0 dropped 0 overruns 0 carrier 0 collisions 0
```

你可以从输出中看到，我只通过我的 Wi-Fi 接口（`wlan0`）连接到互联网，我的 IP 地址是`172.16.1.73`。

**回环是什么？**

回环（或`lo`）是计算机用来与自身通信的虚拟接口；它主要用于故障排除。回环接口的 IP 地址是`127.0.0.1`，如果你想 ping 自己！尽管 ping `127.0.0.1`。

你也可以使用更新的`ip`命令来检查你的机器的 IP 地址。例如，你可以运行`ip address show`命令来列出并显示所有的网络接口的状态：

```
root@ubuntu-linux:~# ip address show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
 inet 127.0.0.1/8 scope host lo
 valid_lft forever preferred_lft forever 
    inet6 ::1/128 scope host
 valid_lft forever preferred_lft forever
2: eth0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast state 
        DOWN link/ether f0:de:f1:d3:e1:e1 brd ff:ff:ff:ff:ff:ff
3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state 
    UP link/ether 10:0b:a9:6c:89:a0 brd ff:ff:ff:ff:ff:ff
 inet 172.16.1.73/24 brd 172.16.1.255 scope global dynamic 
      noprefixroute wlan0 valid_lft 85684sec preferred_lft 85684sec
 inet6 fe80::3101:321b:5ec3:cf9/64 scope link noprefixroute 
      valid_lft forever preferred_lft forever
```

# 检查你的网关地址

你的计算机从路由器那里获取了一个 IP 地址；这个路由器也被称为默认网关，因为它将你连接到外部世界（互联网）。这些路由器随处可见；它们在你家、咖啡店、学校、医院等等。

你可以通过运行以下任一命令来检查你的默认网关的 IP 地址：

+   `route -n`

+   `netstat -rn`

+   `ip route`

让我们从第一个命令`route -n`开始：

```
root@ubuntu-linux:~# route -n Kernel IP routing table
Destination Gateway       Genmask       Flags  Metric Ref Use Iface
0.0.0.0     172.16.1.254  0.0.0.0       UG     600     0   0 wlan0
172.16.1.0  0.0.0.0       255.255.255.0 U      600     0   0 wlan0
```

您可以从输出中看到我的默认网关 IP 地址为`172.16.1.254`。现在让我们尝试第二个命令`netstat -rn`：

```
root@ubuntu-linux:~# netstat -rn 
Kernel IP routing table
Destination   Gateway      Genmask       Flags  MSS Window irtt Iface
0.0.0.0       172.16.1.254 0.0.0.0       UG     0   0      0    wlan0
172.16.1.0    0.0.0.0      255.255.255.0 U      0   0      0    wlan0
```

输出几乎看起来相同。现在输出与第三个命令`ip route`有一点不同：

```
root@ubuntu-linux:~# ip route
default via 172.16.1.254 dev wlan0 proto dhcp metric 600
172.16.1.0/24 dev wlan0 proto kernel scope link src 172.16.1.73 metric 600
```

默认网关 IP 地址显示在第一行：默认通过`172.16.1.254`。您还应该能够 ping 默认网关：

```
root@ubuntu-linux:~# ping -c 2 172.16.1.254
PING 172.16.1.254 (172.16.1.254) 56(84) bytes of data.
64 bytes from 172.16.1.254: icmp_seq=1 ttl=64 time=1.38 ms
64 bytes from 172.16.1.254: icmp_seq=2 ttl=64 time=1.62 ms

--- 172.16.1.254 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 3ms rtt min/avg/max/mdev = 1.379/1.501/1.624/0.128 ms
```

# 使用 traceroute 飞行

您现在已经准备好离开家去上班了。您必须通过不同的街道最终到达目的地，对吧？嗯，这与您尝试在互联网上到达主机（网站）时非常相似；您采取的路线从默认网关开始，以目的地结束。

您可以使用`traceroute`命令跟踪到任何目的地的路由。`traceroute`命令的一般语法如下：

```
traceroute destination
```

例如，您可以通过运行以下命令跟踪从您的计算机到`google.com`的路由：

```
root@ubuntu-linux:~# traceroute google.com
traceroute to google.com (172.217.1.14), 30 hops max, 60 byte packets
 1 172.16.1.254 (172.16.1.254) 15.180 ms 15.187 ms 15.169 ms
 2 207-47-195-169.ngai.static.sasknet.sk.ca (207.47.195.169) 24.059 ms
 3 142.165.0.110 (142.165.0.110) 50.060 ms 54.305 ms 54.903 ms
 4 72.14.203.189 (72.14.203.189) 53.720 ms 53.997 ms 53.948 ms
 5 108.170.250.241 (108.170.250.241) 54.185 ms 35.506 ms 108.170.250.225
 6 216.239.35.233 (216.239.35.233) 37.005 ms 35.729 ms 38.655 ms
 7 yyz10s14-in-f14.1e100.net (172.217.1.14) 41.739 ms 41.667 ms 41.581 ms
```

正如您所看到的，我的机器花了七次旅行（跳跃）才到达我的最终目的地`google.com`。请注意，第一跳是我的默认网关，最后一跳是目的地。

当您在解决连接问题时，`traceroute`命令非常有用。例如，要到达特定目的地可能需要很长时间；在这种情况下，`traceroute`可以帮助您检测到达目的地路径上的任何故障点。

# 破坏您的 DNS

互联网上的每个网站（目的地）都必须有一个 IP 地址。然而，我们人类对数字不太擅长，所以我们发明了**域名系统**（**DNS**）。DNS 的主要功能是将名称（域名）与 IP 地址关联起来；这样，我们在浏览互联网时就不需要记住 IP 地址了...感谢上帝的 DNS！

每次您在浏览器上输入域名时，DNS 都会将（解析）域名转换为其相应的 IP 地址。您的 DNS 服务器的 IP 地址存储在文件`/etc/resolv.conf`中：

```
root@ubuntu-linux:~# cat /etc/resolv.conf 
# Generated by NetworkManager
nameserver 142.165.200.5
```

我正在使用由我的**互联网服务提供商**（**ISP**）提供的 DNS 服务器`142.165.200.5`。您可以使用`nslookup`命令来查看 DNS 的工作情况。`nslookup`命令的一般语法如下：

```
nslookup domain_name
```

`nslookup`命令使用 DNS 获取域名的 IP 地址。例如，要获取`facebook.com`的 IP 地址，您可以运行以下命令：

```
root@ubuntu-linux:~# nslookup facebook.com 
Server: 142.165.200.5
Address: 142.165.200.5#53

Non-authoritative answer:
Name: facebook.com 
Address: 157.240.3.35 
Name: facebook.com
Address: 2a03:2880:f101:83:face:b00c:0:25de
```

请注意，它在输出的第一行显示了我的 DNS 服务器的 IP 地址。您还可以看到`facebook.com`的 IP 地址`157.240.3.35`。

您还可以 ping`facebook.com`：

```
root@ubuntu-linux:~# ping -c 2 facebook.com
PING facebook.com (157.240.3.35) 56(84) bytes of data.
64 bytes from edge-star-mini-shv-01-sea1.facebook.com (157.240.3.35): 
icmp_seq=1 ttl=55 time=34.6 ms
64 bytes from edge-star-mini-shv-01-sea1.facebook.com (157.240.3.35): 
icmp_seq=2 ttl=55 time=33.3 ms

--- facebook.com ping statistics ---

2 packets transmitted, 2 received, 0% packet loss, time 2ms 
rtt min/avg/max/mdev = 33.316/33.963/34.611/0.673 ms
```

现在让我们破坏一切！我妈妈曾经告诉我，我必须破坏一切，这样我才能理解它们是如何工作的。让我们看看没有 DNS 的生活是什么样子，通过清空文件`/etc/resolv.conf`：

```
root@ubuntu-linux:~# echo > /etc/resolv.conf 
root@ubuntu-linux:~# cat /etc/resolv.conf

root@ubuntu-linux:~#
```

现在让我们对`facebook.com`进行`nslookup`：

```
root@ubuntu-linux:~# nslookup facebook.com
```

您会看到它挂起，因为它无法再解析域名。现在让我们尝试 ping`facebook.com`：

```
root@ubuntu-linux:~# ping facebook.com
ping: facebook.com: Temporary failure in name resolution
```

您会收到错误消息`名称解析临时失败`，这是说您的 DNS 出了问题的一种花哨方式！但是，您仍然可以通过使用其 IP 地址来 ping`facebook.com`：

```
root@ubuntu-linux:~# ping -c 2 157.240.3.35
PING 157.240.3.35 (157.240.3.35) 56(84) bytes of data.
64 bytes from 157.240.3.35: icmp_seq=1 ttl=55 time=134 ms
64 bytes from 157.240.3.35: icmp_seq=2 ttl=55 time=34.4 ms

--- 157.240.3.35 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 2ms 
rtt min/avg/max/mdev = 34.429/84.150/133.872/49.722 ms
```

让我们修复我们的 DNS，但这次我们将不使用我们的 ISP 的 DNS 服务器；相反，我们将使用 Google 的公共 DNS 服务器`8.8.8.8`：

```
root@ubuntu-linux:~# echo "nameserver 8.8.8.8" > /etc/resolv.conf 
root@ubuntu-linux:~# cat /etc/resolv.conf
nameserver 8.8.8.8
```

现在让我们再次对`facebook.com`进行`nslookup`：

```
root@ubuntu-linux:~# nslookup facebook.com Server: 8.8.8.8
Address: 8.8.8.8#53

Non-authoritative answer:
Name: facebook.com 
Address: 31.13.80.36 
Name: facebook.com
Address: 2a03:2880:f10e:83:face:b00c:0:25de
```

请注意，我的活动 DNS 现在已更改为`8.8.8.8`。我还得到了`facebook.com`的不同 IP 地址，这是因为 Facebook 在世界各地的许多不同服务器上运行。

# 更改您的主机名

每个网站都有一个在互联网上唯一标识它的域名；同样，计算机有一个在网络上唯一标识它的主机名。

您计算机的主机名存储在文件`/etc/hostname`中：

```
root@ubuntu-linux:~# cat /etc/hostname 
ubuntu-linux
```

您可以使用主机名来访问同一网络（子网）中的其他计算机。例如，我有另一台计算机，主机名为`backdoor`，目前正在运行，我可以 ping 它：

```
root@ubuntu-linux:~# ping backdoor
PING backdoor (172.16.1.67) 56(84) bytes of data.
64 bytes from 172.16.1.67 (172.16.1.67): icmp_seq=1 ttl=64 time=3.27 ms
64 bytes from 172.16.1.67 (172.16.1.67): icmp_seq=2 ttl=64 time=29.3 ms
64 bytes from 172.16.1.67 (172.16.1.67): icmp_seq=3 ttl=64 time=51.4 ms
^C
--- backdoor ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 20ms 
rtt min/avg/max/mdev = 3.272/27.992/51.378/19.662 ms
```

请注意，`backdoor`位于相同的网络（子网）并且具有 IP 地址`172.16.1.67`。我也可以 ping 自己：

```
root@ubuntu-linux:~# ping ubuntu-linux
PING ubuntu-linux (172.16.1.73) 56(84) bytes of data.
64 bytes from 172.16.1.73 (172.16.1.73): icmp_seq=1 ttl=64 time=0.025 ms
64 bytes from 172.16.1.73 (172.16.1.73): icmp_seq=2 ttl=64 time=0.063 ms
^C
--- ubuntu-linux ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 14ms 
rtt min/avg/max/mdev = 0.025/0.044/0.063/0.019 ms
```

这是一种聪明的方法来显示您计算机的 IP 地址-简单地 ping 自己！

您可以使用`hostnamectl`命令来查看和设置计算机的主机名：

```
root@ubuntu-linux:~# hostnamectl 
    Static hostname: ubuntu-linux
 Icon name: computer-vm 
            Chassis: vm
 Machine ID: 106fd80252e541faafa4e54a250d1216 
            Boot ID: c5508514af114b4b80c55d4267c25dd4
 Virtualization: oracle
 Operating System: Ubuntu 18.04.3 LTS 
             Kernel: Linux 4.15.0-66-generic
 Architecture: x86-64
```

要更改计算机的主机名，您可以使用`hostnamectl set-hostname`命令，然后跟上新的主机名：

```
hostnamectl set-hostname new_hostname
```

例如，您可以通过运行以下命令将计算机的主机名更改为`myserver`：

```
root@ubuntu-linux:~# hostnamectl set-hostname myserver 
root@ubuntu-linux:~# su -
root@myserver:~#
```

请记住，您需要打开一个新的 shell 会话，以便您的 shell 提示显示新的主机名。您还可以看到文件`/etc/hostname`已更新，因为它包含新的主机名：

```
root@ubuntu-linux:~# cat /etc/hostname 
myserver
```

# 重新启动您的网络接口

这可能是一种被滥用的方法，但有时重新启动是许多与计算机相关的问题的最快解决方法！我自己也常常滥用重新启动解决大部分计算机问题。

您可以使用`ifconfig`命令将网络接口关闭；您必须在网络接口名称后面跟随`down`标志，如下所示：

```
ifconfig interface_name down
```

例如，我可以通过运行以下命令关闭我的 Wi-Fi 接口`wlan0`：

```
root@myserver:~# ifconfig wlan0 down
```

您可以使用`up`标志来启用网络接口：

```
ifconfig interface_name up
```

例如，我可以通过运行以下命令重新启动我的 Wi-Fi 接口：

```
root@myserver:~# ifconfig wlan0 up
```

您可能还希望同时重新启动所有网络接口。这可以通过以下方式重新启动`NetworkManager`服务来完成：

```
root@myserver:~# systemctl restart NetworkManager
```

现在是时候通过一个可爱的知识检查练习来测试您对 Linux 网络的理解了。

# 知识检查

对于以下练习，打开您的终端并尝试解决以下任务：

1.  将您的主机名更改为`darkarmy`。

1.  显示您的默认网关的 IP 地址。

1.  从您的计算机到`www.ubuntu.com`的路由跟踪。

1.  显示您的 DNS 的 IP 地址。

1.  显示`www.distrowatch.com`的 IP 地址。

1.  关闭您的以太网接口。

1.  重新启动您的以太网接口。


Bash 脚本很有趣

在 Linux 中完成特定任务时，你经常会发现自己一遍又一遍地运行相同的一组命令。这个过程会浪费很多宝贵的时间。在本章中，你将学习如何创建 bash 脚本，以便在 Linux 中更加高效。

# 第十七章：创建简单脚本

我们的第一个 bash 脚本将是一个简单的脚本，它将在屏幕上输出一行“你好，朋友！”。在艾略特的主目录中，创建一个名为`hello.sh`的文件，并插入以下两行：

```
elliot@ubuntu-linux:~$ cat hello.sh 
#!/bin/bash
echo "Hello Friend!"
```

现在我们需要将脚本设置为可执行：

```
elliot@ubuntu-linux:~$ chmod a+x hello.sh
```

最后，运行脚本：

```
elliot@ubuntu-linux:~$ ./hello.sh 
Hello Friend!
```

恭喜！你现在已经创建了你的第一个 bash 脚本！让我们花一分钟时间讨论一些事情；每个 bash 脚本必须做到以下几点：

+   `#!/bin/bash`

+   要可执行

你必须在任何 bash 脚本的第一行插入`#!/bin/bash`；字符序列`#!`被称为 shebang 或 hashbang，后面跟着 bash shell 的路径。

# PATH 变量

你可能已经注意到我使用了`./hello.sh`来运行脚本；如果省略前导的`./`，你会得到一个错误：

```
elliot@ubuntu-linux:~$ hello.sh 
hello.sh: command not found
```

shell 找不到命令`hello.sh`。当你在终端上运行一个命令时，shell 会在存储在`PATH`变量中的一组目录中寻找该命令。

你可以使用`echo`命令查看你的`PATH`变量的内容：

```
elliot@ubuntu-linux:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

冒号字符分隔每个目录的路径。你不需要包括这些目录中任何命令或脚本（或任何可执行文件）的完整路径。到目前为止，你学到的所有命令都驻留在`/bin`和`/sbin`中，它们都存储在你的`PATH`变量中。因此，你可以运行`pwd`命令：

```
elliot@ubuntu-linux:~$ pwd
/home/elliot
```

没有必要包含它的完整路径：

```
elliot@ubuntu-linux:~$ /bin/pwd
/home/elliot
```

好消息是你可以很容易地将一个目录添加到你的`PATH`变量中。例如，要将`/home/elliot`添加到你的`PATH`变量中，你可以使用`export`命令如下：

```
elliot@ubuntu-linux:~$ export PATH=$PATH:/home/elliot
```

现在你不需要前导的`./`来运行`hello.sh`脚本：

```
elliot@ubuntu-linux:~$ hello.sh 
Hello Friend!
```

它将运行，因为 shell 现在也在`/home/elliot`目录中寻找可执行文件：

```
elliot@ubuntu-linux:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/elliot
```

好了！现在让我们创建几个更多的 bash 脚本。我们将创建一个名为`hello2.sh`的脚本，它打印出“你好，朋友！”然后显示你当前的工作目录：

```
elliot@ubuntu-linux:~$ cat hello2.sh 
#!/bin/bash
echo "Hello Friend!" 
pwd
```

现在让我们运行它：

```
elliot@ubuntu-linux:~$ hello2.sh
-bash: /home/elliot/hello2.sh: Permission denied
```

糟糕！我忘记了要将其设置为可执行：

```
elliot@ubuntu-linux:~$ chmod a+x hello2.sh 
elliot@ubuntu-linux:~$ ./hello2.sh
Hello Friend!
/home/elliot
```

# 读取用户输入

让我们创建我们的`hello.sh`脚本的更好版本。我们将让用户输入他/她的名字，然后我们将向用户打招呼；创建一个名为`greet.sh`的脚本，包含以下几行：

```
elliot@ubuntu-linux:~$ cat greet.sh 
#!/bin/bash
echo "Please enter your name:" 
read name
echo "Hello $name!"
```

现在让脚本可执行，然后运行它：

```
elliot@ubuntu-linux:~$ chmod a+x greet.sh 
elliot@ubuntu-linux:~$ ./greet.sh
Please enter your name:
```

当你运行脚本时，它会提示你输入你的名字；我输入了`Elliot`作为我的名字：

```
elliot@ubuntu-linux:~$ ./greet.sh 
Please enter your name:
Elliot
Hello Elliot!
```

脚本向我打招呼说“你好，艾略特！”。我们使用`read`命令获取用户输入，并注意在`echo`语句中，我们使用了美元符号`$`来打印变量`name`的值。

让我们创建另一个脚本，从用户那里读取文件名，然后输出文件的大小（以字节为单位）；我们将命名我们的脚本为`size.sh`：

```
elliot@ubuntu-linux:~$ cat size.sh
#!/bin/bash
echo "Please enter a file path:" 
read file
filesize=$(du -bs $file| cut -f1)
echo "The file size is $filesize bytes"
```

并且永远不要忘记将脚本设置为可执行：

```
elliot@ubuntu-linux:~$ chmod a+x size.sh
```

现在让我们运行脚本：

```
elliot@ubuntu-linux:~$ size.sh 
Please enter a file path
/home/elliot/size.sh
The file size is 128 bytes
```

我使用`size.sh`作为文件路径，输出为 128 字节；是真的吗？让我们来检查一下：

```
elliot@ubuntu-linux:~$ du -bs size.sh
128 size.sh
```

的确如此；请注意脚本中的以下一行：

```
filesize=$(du -bs $file| cut -f1)
```

它将`du -bs $file | cut -f1`命令的结果存储在变量`filesize`中：

```
elliot@ubuntu-linux:~$ du -bs size.sh | cut -f1 
128
```

还要注意，命令`du -bs $file cut -f1`被括号和美元符号（在左边）包围；这被称为命令替换。一般来说，命令替换的语法如下：

```
var=$(command)
```

`command`的结果将存储在变量`var`中。

# 向脚本传递参数

除了从用户那里读取输入，你还可以将参数传递给 bash 脚本。例如，让我们创建一个名为`size2.sh`的 bash 脚本，它做的事情与脚本`size.sh`相同，但是不是从用户那里读取文件，而是将其作为参数传递给脚本`size2.sh`：

```
elliot@ubuntu-linux:~$ cat size2.sh 
#!/bin/bash
filesize=$(du -bs $1| cut -f1)
echo "The file size is $filesize bytes"
```

现在让我们将脚本设置为可执行：

```
elliot@ubuntu-linux:~$ chmod a+x size2.sh
```

最后，你可以运行脚本：

```
elliot@ubuntu-linux:~$ size2.sh /home/elliot/size.sh 
The file size is 128 bytes
```

你将得到与`size.sh`相同的输出。注意我们提供了文件路径

`/home/elliot/size.sh`作为脚本`size2.sh`的参数。

我们在脚本`size2.sh`中只使用了一个参数，它由`$1`引用。你也可以传递多个参数；让我们创建另一个脚本`size3.sh`，它接受两个文件（两个参数）并输出每个文件的大小：

```
elliot@ubuntu-linux:~$ cat size3.sh #!/bin/bash
filesize1=$(du -bs $1| cut -f1) 
filesize2=$(du -bs $2| cut -f1) 
echo "$1 is $filesize1 bytes" 
echo "$2 is $filesize2 bytes"
```

现在使脚本可执行并运行它：

```
elliot@ubuntu-linux:~$ size3.sh /home/elliot/size.sh /home/elliot/size3.sh
/home/elliot/size.sh is 128 bytes
/home/elliot/size3.sh is 136 bytes
```

太棒了！如你所见，第一个参数由`$1`引用，第二个参数由`$2`引用。所以一般来说：

```
bash_script.sh argument1 argument2 argument3 ...
 $1         $2         $3
```

# 使用 if 条件

你可以通过使其在不同的情况下表现不同来为你的 bash 脚本增加智能。为此，我们使用条件`if`语句。

一般来说，`if 条件`的语法如下：

```
if [ condition is true ]; then 
    do this ...
fi
```

例如，让我们创建一个名为`empty.sh`的脚本，它将检查文件是否为空：

```
elliot@ubuntu-linux:~$ cat empty.sh 
#!/bin/bash
filesize=$(du -bs $1 | cut -f1) 
if [ $filesize -eq 0 ]; then 
echo "$1 is empty!"
fi
```

现在让我们使脚本可执行，并创建一个名为`zero.txt`的空文件：

```
elliot@ubuntu-linux:~$ chmod a+x empty.sh 
elliot@ubuntu-linux:~$ touch zero.txt
```

现在让我们在文件`zero.txt`上运行脚本：

```
elliot@ubuntu-linux:~$ ./empty.sh zero.txt 
zero.txt is empty!
```

如你所见，脚本正确地检测到`zero.txt`是一个空文件；这是因为在这种情况下测试条件为真，因为文件`zero.txt`的确是零字节大小的：

```
if [ $filesize -eq 0 ];
```

我们使用了`-eq`来测试相等。现在如果你在一个非空文件上运行脚本，将不会有输出：

```
elliot@ubuntu-linux:~$ ./empty.sh size.sh 
elliot@ubuntu-linux:~$
```

我们需要修改脚本`empty.sh`，以便在传递非空文件时显示输出；为此，我们将使用`if-else`语句：

```
if [ condition is true ]; then 
    do this ...
else
    do this instead ...
fi
```

让我们通过添加以下`else`语句来编辑`empty.sh`脚本：

```
elliot@ubuntu-linux:~$ cat empty.sh 
#!/bin/bash
filesize=$(du -bs $1 | cut -f1) 
if [ $filesize -eq 0 ]; then 
echo "$1 is empty!"
else
echo "$1 is not empty!" 
fi
```

现在让我们重新运行脚本：

```
elliot@ubuntu-linux:~$ ./empty.sh size.sh 
size.sh is not empty!
elliot@ubuntu-linux:~$ ./empty.sh zero.txt 
zero.txt is empty!
```

如你所见，现在它完美地运行了！

你也可以使用`elif`（**else-if**）语句来创建多个测试条件：

```
if [ condition is true ]; then 
    do this ...
elif [ condition is true]; then 
    do this instead ...
fi
```

让我们创建一个名为`filetype.sh`的脚本，它检测文件类型。脚本将输出文件是普通文件、软链接还是目录：

```
elliot@ubuntu-linux:~$ cat filetype.sh 
#!/bin/bash
file=$1
if [ -f $1 ]; then
echo "$1 is a regular file" 
elif [ -L $1 ]; then
echo "$1 is a soft link" 
elif [ -d $1 ]; then 
echo "$1 is a directory" 
fi
```

现在让我们使脚本可执行，并创建一个指向`/tmp`的软链接，名为`tempfiles`：

```
elliot@ubuntu-linux:~$ chmod a+x filetype.sh 
elliot@ubuntu-linux:~$ ln -s /tmp tempfiles
```

现在在任何目录上运行脚本：

```
elliot@ubuntu-linux:~$ ./filetype.sh /bin
/bin is a directory
```

它正确地检测到`/bin`是一个目录。现在在任何普通文件上运行脚本：

```
elliot@ubuntu-linux:~$ ./filetype.sh zero.txt 
zero.txt is a regular file
```

它正确地检测到`zero.txt`是一个普通文件。最后，在任何软链接上运行脚本：

```
elliot@ubuntu-linux:~$ ./filetype.sh tempfiles 
tempfiles is a soft link
```

它正确地检测到`tempfiles`是一个软链接。

以下`man`页面包含了所有的测试条件：

```
elliot@ubuntu-linux:~$ man test
```

所以永远不要死记硬背！利用并使用 man 页面。

# 在 bash 脚本中循环

循环的能力是 bash 脚本的一个非常强大的特性。例如，假设你想要在终端上打印出"Hello world"这一行 20 次；一个天真的方法是创建一个有 20 个`echo`语句的脚本。幸运的是，循环提供了一个更聪明的解决方案。

## 使用 for 循环

`for`循环有几种不同的语法。如果你熟悉 C++或 C 编程，那么你会认出以下`for`循环的语法：

```
for ((initialize ; condition ; increment)); do
// do something 
done
```

使用前面提到的 C 风格语法；以下`for`循环将打印出"Hello World"二十次：

```
for ((i = 0 ; i < 20 ; i++)); do 
    echo "Hello World"
done
```

循环将整数变量`i`初始化为`0`，然后测试条件（`i < 20`）；如果为真，则执行 echo "Hello World"这一行，并递增变量`i`一次，然后循环再次运行，直到`i`不再小于`20`。

现在让我们创建一个名为`hello20.sh`的脚本，其中包含我们刚讨论的`for`循环：

```
elliot@ubuntu-linux:~$ cat hello20.sh 
#!/bin/bash
for ((i = 0 ; i < 20 ; i++)); do 
 echo "Hello World"
done
```

现在使脚本可执行并运行它：

```
elliot@ubuntu-linux:~$ chmod a+x hello20.sh 
elliot@ubuntu-linux:~$ hello20.sh
Hello World 
Hello World
Hello World 
Hello World 
Hello World 
Hello World 
Hello World 
Hello World 
Hello World 
Hello World 
Hello World 
Hello World 
Hello World 
Hello World 
Hello World 
Hello World 
Hello World 
Hello World 
Hello World 
Hello World
```

它输出了"Hello World"这一行二十次，正如我们所预期的那样。除了 C 风格的语法，你也可以在`for`循环中使用范围语法：

```
for i in {1..20}; do 
    echo "Hello World"
done
```

这也将输出"Hello World"20 次。这种范围语法在处理文件列表时特别有用。为了演示，创建以下五个文件：

```
elliot@ubuntu-linux:~$ touch one.doc two.doc three.doc four.doc five.doc
```

现在假设我们想要将所有五个文件的扩展名从`.doc`改为

`.document`。我们可以创建一个名为`rename.sh`的脚本，其中包含以下`for`循环：

```
#!/bin/bash
for i in /home/elliot/*.doc; do
    mv $i $(echo $i | cut -d. -f1).document
done
```

使脚本可执行并运行它：

```
#!/bin/bash
elliot@ubuntu-linux:~$ chmod a+x rename.sh 
elliot@ubuntu-linux:~$ ./rename.sh 
elliot@ubuntu-linux:~$ ls *.document
five.document four.document one.document three.document two.document
```

正如你所看到的，它将所有扩展名为`.doc`的文件重命名为`.document`。现在想象一下，如果你想对一百万个文件执行此操作。如果你不懂 bash 脚本，你可能要花十年的时间。我们都应该感谢 Linux 之神的 bash 脚本。

## 使用`while`循环

`while`循环是另一个流行且直观的循环。`while`循环的一般语法如下：

```
while [ condition is true ]; do
  // do something 
done
```

例如，我们可以创建一个简单的脚本`numbers.sh`，打印从一到十的数字：

```
elliot@ubuntu-linux:~$ cat numbers.sh 
#!/bin/bash
number=1
while [ $number -le 10 ]; do 
echo $number 
number=$(($number+1))
done
```

使脚本可执行并运行它：

```
elliot@ubuntu-linux:~$ chmod a+x numbers.sh 
elliot@ubuntu-linux:~$ ./numbers.sh
1
2
3
4
5
6
7
8
9
10
```

脚本很容易理解；我们首先将变量 number 初始化为`1`：

```
number=1
```

然后我们创建了一个测试条件，只要变量`number`小于或等于 10，`while`循环将继续运行：

```
while [ $number -le 10 ]; do
```

在`while`循环的主体中，我们首先打印变量`number`的值，然后将其增加 1。请注意，要评估算术表达式，它需要在双括号内，如`$((arithmetic-expression))`：

```
echo $number 
number=$(($number+1))
```

现在是时候玩一些有趣的东西了！我们将创建一个猜数字游戏。但在我们开始之前，让我向你介绍一个非常酷的命令。你可以使用`shuf`命令来生成随机排列。例如，要生成 1 到 10 之间数字的随机排列，你可以运行以下命令：

```
elliot@ubuntu-linux:~$ shuf -i 1-10 
1
6
5
2
10
8
3
9
7
4
```

请记住，我的输出很可能与你的输出不同，因为它是随机的！你有一百万分之一的机会和我有相同的输出。

现在我们可以使用`-n`选项从排列中选择一个数字。这个数字也将是随机的。因此，要生成 1 到 10 之间的随机数，你可以运行以下命令：

```
elliot@ubuntu-linux:~$ shuf -i 1-10 -n 1
6
```

输出将是 1 到 10 之间的一个随机数。`shuf`命令将在我们的游戏中发挥关键作用。我们将生成 1 到 10 之间的随机数，然后我们将看看用户（玩家）猜中随机数需要多少次尝试。

这是我们精心制作的脚本`game.sh`：

```
elliot@ubuntu-linux:~$ cat game.sh 
#!/bin/bash
random=$(shuf -i 1-10 -n 1) #generate a random number between 1 and 10\. 
echo "Welcome to the Number Guessing Game"
echo "The lucky number is between 1 and 10." 
echo "Can you guess it?"
tries=1
while [ true ]; do
echo -n "Enter a Number between 1-10: " 
read number
if [ $number -gt $random ]; then 
echo "Too high!"
elif [ $number -lt $random ]; then 
echo "Too low!"
else
echo "Correct! You got it in $tries tries" 
break #exit the loop
fi 
tries=$(($tries+1)) 
done
```

现在使脚本可执行并运行它来开始游戏：

```
elliot@ubuntu-linux:~$ chmod a+x game.sh 
elliot@ubuntu-linux:~$ game.sh
Welcome to the Number Guessing Game 
The lucky number is between 1 and 10\. 
Can you guess it?
Enter a Number between 1-10: 4 
Too low!
Enter a Number between 1-10: 7 
Too low!
Enter a Number between 1-10: 9 
Too high!
Enter a Number between 1-10: 8 
Correct! You got it in 4 tries
```

在我的第一次尝试游戏中，我猜了四次；我打赌你可以轻松地击败我！

让我们逐行查看我们的游戏脚本。我们首先生成一个 1 到 10 之间的随机数，并将其赋值给变量`random`：

```
random=$(shuf -i 1-10 -n 1) #generate a random number between 1 and 10.
```

请注意，你可以在你的 bash 脚本中添加注释，就像我在这里使用井号字符，后面跟上你的注释一样。

然后我们打印三行来向玩家解释游戏规则：

```
echo "Welcome to the Number Guessing Game" 
echo "The lucky number is between 1 and 10." 
echo "Can you guess it?"
```

接下来，我们将变量`tries`初始化为`1`，以便我们可以跟踪玩家猜了多少次：

```
tries=1
```

然后我们进入游戏循环：

```
while [ true ]; do
```

请注意，测试条件`while [ true ]`将始终为`true`，因此循环将永远运行（无限循环）。

游戏循环中我们做的第一件事是要求玩家输入 1 到 10 之间的数字：

```
echo -n "Enter a Number between 1-10: " 
read number
```

然后我们测试玩家输入的数字是大于、小于还是等于`random`数字：

```
if [ $number -gt $random ]; then 
echo "Too high!"
elif [ $number -lt $random ]; then 
echo "Too low!"
else
echo "Correct! You got it in $tries tries" 
break #exit the loop
fi
```

如果`number`大于`random`，我们告诉玩家猜测太高，以便玩家下次更容易猜对。同样，如果`number`小于`random`，我们告诉玩家猜测太低。否则，如果是正确的猜测，那么我们打印玩家用来做出正确猜测的总次数，并且我们从循环中退出。

请注意，你需要`break`语句来退出无限循环。没有`break`语句，循环将永远运行。

最后，我们每次猜错（高或低）都会将`tries`的数量增加 1：

```
tries=$(($tries+1))
```

我必须警告你，这个游戏很容易上瘾！特别是当你和朋友一起玩时，看谁能在最少的尝试次数中猜对。

## 使用`until`循环

`for`和`while`循环都会在测试条件为`true`时运行。相反，`until`循环会在测试条件为`false`时继续运行。也就是说，它会在测试条件为`true`时停止运行。

`until`循环的一般语法如下：

```
until [condition is true]; do 
  [commands]
done
```

例如，我们可以创建一个简单的脚本`3x10.sh`，打印出`3`的前十个倍数：

```
elliot@ubuntu-linux:~$ cat 3x10.sh 
#!/bin/bash
counter=1
until [ $counter -gt 10 ]; do 
echo $(($counter * 3)) 
counter=$(($counter+1))
done
```

现在让脚本可执行，然后运行它：

```
elliot@ubuntu-linux:~$ chmod a+x 3x10.sh 
elliot@ubuntu-linux:~$ 3x10.sh
3
6
9
12
15
18
21
24
27
30
```

脚本很容易理解，但你可能会在尝试理解`until`循环的测试条件时有点困惑：

```
until [ $counter -gt 10 ]; do
```

测试条件基本上是这样说的：“直到`counter`大于 10，继续运行！”

请注意，我们可以使用具有相反测试条件的`while`循环来实现相同的结果。你只需否定`until`循环的测试条件，就会得到`while`循环的等价形式：

```
while [ $counter -le 10 ]; do
```

在数学中，大于（`>`）的相反（否定）是小于或等于（`≤`）。很多人忘记了`等于`部分。不要成为那些人中的一个！

# Bash 脚本函数

当你的脚本变得越来越大时，事情可能会变得非常混乱。为了克服这个问题，你可以使用 bash 函数。函数的理念是你可以重用脚本的部分，从而产生更有组织和可读性的脚本。

bash 函数的一般语法如下：

```
function_name () {
<commands>
}
```

让我们创建一个名为`hello`的函数，打印出“Hello World”这一行。我们将`hello`函数放在一个名为`fun1.sh`的新脚本中：

```
elliot@ubuntu-linux:~$ cat fun1.sh 
#!/bin/bash

hello () {
echo "Hello World"
}

hello     # Call the function hello() 
hello     # Call the function hello() 
hello     # Call the function hello()
```

现在让脚本可执行，然后运行它：

```
elliot@ubuntu-linux:~$ chmod a+x fun1.sh 
elliot@ubuntu-linux:~$ ./fun1.sh
Hello World 
Hello World 
Hello World
```

该脚本将在终端上输出“Hello World”三次。请注意，我们调用（使用）了函数`hello`三次。

## 传递函数参数

函数也可以像脚本一样接受参数。为了演示，我们将创建一个名为`math.sh`的脚本，其中有两个函数`add`和`sub`：

```
elliot@ubuntu-linux:~$ cat math.sh 
#!/bin/bash

add () {
echo "$1 + $2 =" $(($1+$2))
}

sub () {
echo "$1 - $2 =" $(($1-$2))
}

add 7 2
sub 7 2
```

使脚本可执行，然后运行它：

```
elliot@ubuntu-linux:~$ chmod a+x math.sh 
elliot@ubuntu-linux:~$ ./math.sh
7 + 2 = 9
7 - 2 = 5
```

该脚本有两个函数`add`和`sub`。`add`函数计算并输出任意两个数字的总和。另一方面，`sub`函数计算并输出任意两个数字的差。

# 你不能浏览网页

我们将用一个相当酷的 bash 脚本`noweb.sh`来结束本章，确保没有用户在 Firefox 浏览器上浏览网页时玩得开心：

```
elliot@ubuntu-linux:~$ cat noweb.sh 
#!/bin/bash

shutdown_firefox() { 
killall firefox 2> /dev/null
}

while [ true ]; do 
shutdown_firefox
sleep 10 #wait for 10 seconds 
done
```

现在将 Firefox 作为后台进程打开：

```
elliot@ubuntu-linux:~$ firefox & 
[1] 30436
```

最后，使脚本可执行，并在后台运行脚本：

```
elliot@ubuntu-linux:~$ chmod a+x noweb.sh 
elliot@ubuntu-linux:~$ ./noweb.sh &
[1] 30759
```

一旦运行你的脚本，Firefox 就会关闭。此外，如果以`root`用户身份运行脚本，系统用户将无法享受 Firefox！

# 知识检查

对于以下练习，打开你的终端并尝试解决以下任务：

1.  创建一个 bash 脚本，显示当前月份的日历。

1.  修改你的脚本，以便显示任何年份（作为参数传递）的日历。

1.  修改你的脚本，以便显示从`2000`年到`2020`年的所有年份的日历。


您需要一个 Cron 作业

在本章中，您将学习如何通过使用 cron 作业自动化 Linux 中的乏味任务，这是 Linux 中最有用和强大的实用程序之一。由于 cron 作业，Linux 系统管理员可以在周末休息，并与他们所爱的人一起度假。Cron 作业允许您安排任务在特定时间运行。使用 cron 作业，您可以安排运行备份，监视系统资源等任务。

# 第十八章：我们的第一个 cron 作业

以下图表显示了 cron 作业的典型格式：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/lrn-linux-qk/img/368be940-510d-44f8-93c7-aa92c3ba3270.png)

图 1：Cron 作业格式

Cron 作业是特定于用户的，因此每个用户都有自己的 cron 作业列表。例如，用户`elliot`可以运行命令`crontab -l`来显示他们的 cron 作业：

```
elliot@ubuntu-linux:~$ crontab -l 
no crontab for elliot
```

目前，用户`elliot`没有任何 cron 作业。

让我们继续创建 Elliot 的第一个 cron 作业。我们将创建一个每分钟运行一次的 cron 作业，它将简单地将“一分钟已经过去。”这一行追加到文件`/home/elliot/minutes.txt`中。

您可以运行命令`crontab -e`来编辑或创建 cron 作业：

```
elliot@ubuntu-linux:~$ crontab -e
```

现在添加以下行，然后保存并退出：

```
* * * * * echo "A minute has passed." >> /home/elliot/minutes.txt
```

退出后，您将看到消息：“crontab：正在安装新的 cron 表”：

```
elliot@ubuntu-linux:~$ crontab -e 
crontab: installing new crontab
```

最后，用户`elliot`可以列出他们的 cron 作业，以验证新的 cron 作业是否已安排：

```
elliot@ubuntu-linux:~$ crontab -l
* * * * * echo "A minute has passed." >> /home/elliot/minutes.txt
```

现在，等待几分钟，然后检查文件`/home/el- liot/minutes.txt`的内容：

```
elliot@ubuntu-linux:~$ cat /home/elliot/minutes.txt 
A minute has passed.
A minute has passed. 
A minute has passed. 
A minute has passed. 
A minute has passed.
```

我等了五分钟，然后查看文件，看到“一分钟已经过去。”这一行被添加了五次到文件`minutes.txt`中，所以我知道 cron 作业运行正常。

# 每五分钟运行一次

让我们创建另一个每五分钟运行一次的 cron 作业。例如，您可能希望创建一个每五分钟检查系统负载平均值的 cron 作业。

运行命令`crontab -e`以添加新的 cron 作业：

```
elliot@ubuntu-linux:~$ crontab -e
```

现在添加以下行，然后保存并退出：

```
*/5 * * * * uptime >> /home/elliot/load.txt
```

最后，让我们查看已安装的 cron 作业列表，以验证新的 cron 作业是否已安排：

```
elliot@ubuntu-linux:~$ crontab -e 
crontab: installing new crontab 
elliot@ubuntu-linux:~$ crontab -l
* * * * * echo "A minute has passed" >> /home/elliot/minutes.txt
*/5 * * * * uptime >> /home/elliot/load.txt
```

现在我们可以看到为用户`elliot`安装了两个 cron 作业。

等待五到十分钟，然后检查文件`/home/elliot/load.txt`的内容。如果您没有秒表，运行命令`sleep 300`并等待直到完成：

```
elliot@ubuntu-linux:~$ sleep 300
```

我给自己泡了一些绿茶，然后十分钟后回来查看文件`/home/elliot/load.txt`：

```
elliot@ubuntu-linux:~$ cat /home/elliot/load.txt
14:40:01 up 1 day, 5:13, 2 users, load average: 0.41, 0.40, 0.37
14:45:01 up 1 day, 5:18, 2 users, load average: 0.25, 0.34, 0.35
```

预期内，这个 cron 作业在这十分钟内运行了两次；我建议您再过二十四小时再次查看文件`/home/elliot/load.txt`，您将看到一份关于系统负载平均值的可爱报告。

# 更多 cron 示例

您还可以安排 cron 作业以在多个时间间隔运行。例如，以下 cron 作业将在星期日的每个小时的`5`、`20`和`40`分钟运行：

```
5,20,40 * * * sun task-to-run
```

您还可以指定时间范围。例如，一个在`工作日`（星期一->星期五）的`6:30` PM 运行的 cron 作业将具有以下格式：

```
30 18 * * 1-5 task-to-run
```

注意`0`是星期日，`1`是星期一，依此类推。

要查看更多 cron 示例，可以查看`crontab`手册的第五部分：

```
elliot@ubuntu-linux:~$ man 5 crontab
```

# 自动化系统打补丁

作为 Linux 系统管理员，您经常需要打补丁（更新）系统。有时，生产服务器安排在不愉快的时间更新，比如周末的午夜，凌晨`04:00`，凌晨`02:00`等，这可能会让您发疯。自动化这样繁忙的任务并多睡一会儿会很好，对吧？

让我们切换到`root`用户，然后创建一个名为`auto_patch.sh`的 bash 脚本

在`/root`中：

```
root@ubuntu-linux:~# cat auto_patch.sh 
#!/bin/bash
apt-get -y update 
apt-get -y upgrade 
shutdown -r now
```

注意脚本`auto_patch.sh`很小，只有三行。我们已经使用了

`-y`选项与`apt-get`命令一起使用，这将自动回答系统更新期间的所有提示为“是”；这很重要，因为在脚本运行时你不会坐在电脑前！

现在使脚本可执行：

```
root@ubuntu-linux:~# chmod +x auto_patch.sh
```

最后，您需要安排一个 cron 作业来运行`auto_patch.sh`脚本。假设系统已安排在每周六凌晨 01:00 更新。在这种情况下，您可以创建以下 cron 作业：

```
0 1 * * sat /root/auto_patch.sh
```

请记住，`auto_patch.sh`永远不会部署在任何真实的服务器上。我只是在向您介绍自动化的概念。您需要编辑`auto_patch.sh`以检查命令退出代码，因为期望一切都会顺利进行是天真的。一个优秀的系统管理员总是创建能处理各种预期错误的健壮脚本。

# 运行一次作业

您必须在`auto_patch.sh`运行后的某个时间删除 cron 作业，否则它将每周继续更新系统！为此，还存在另一个专门用途的实用程序`at`；即，安排运行一次作业。

我们首先需要安装`at`软件包：

```
root@ubuntu-linux:~# apt-get -y install at
```

现在，您可以安排在本周六凌晨 01:00 运行`auto_patch.sh`脚本，使用以下命令：

```
root@ubuntu-linux:~# at 01:00 AM Sat -f /root/patch.sh
```

请记住，`at`作业只运行一次，因此在周六之后，`auto_patch.sh`脚本将不会再次运行。

您可以通过阅读其手册页了解更多关于`at`的信息：

```
root@ubuntu-linux:~# man at
```

# 知识检查

对于以下练习，打开您的终端并尝试解决以下任务：

1.  为 root 用户创建一个 cron 作业，每 10 分钟运行一次。该 cron 作业将简单地将行“已经过去 10 分钟！”附加到文件`/root/minutes.txt`中。

1.  为 root 用户创建一个 cron 作业，每年圣诞节（12 月 25 日凌晨 1 点）运行一次。该 cron 作业将简单地将行“圣诞快乐！”附加到文件`/root/holidays.txt`中。


存档和压缩文件

在本章中，您将学习如何将一组文件放在一个单独的存档中。您还将学习如何使用各种压缩方法压缩存档文件。

# 第十九章：创建存档

让我们为`/home/elliot`目录中的所有 bash 脚本创建一个备份。作为`root`用户，在`/root`中创建一个名为`backup`的目录：

```
root@ubuntu-linux:~# mkdir /root/backup
```

要创建存档，我们使用磁带存档命令`tar`。创建存档的一般语法如下：

```
tar -cf archive_name files
```

`-c`选项是`--create`的简写，用于创建存档。`-f`选项是`--file`的简写，用于指定存档名称。

现在让我们在`/root/backup`中为`/home/elliot`中的所有 bash 脚本创建一个名为`scripts.tar`的存档。为此，我们首先切换到`/home/elliot`目录：

```
root@ubuntu-linux:~# cd /home/elliot 
root@ubuntu-linux:/home/elliot#
```

然后我们运行命令：

```
root@ubuntu-linux:/home/elliot# tar -cf /root/backup/scripts.tar *.sh
```

这将在`/root/backup`中创建存档文件`scripts.tar`，并且不会有命令输出：

```
root@ubuntu-linux:/home/elliot# ls -l /root/backup/scripts.tar
-rw-r--r-- 1 root root 20480 Nov 1 23:12 /root/backup/scripts.tar
```

我们还可以添加`-v`选项以查看正在存档的文件：

```
root@ubuntu-linux:/home/elliot# tar -cvf /root/backup/scripts.tar *.sh 
3x10.sh
detect.sh 
empty.sh 
filetype.sh 
fun1.sh 
game.sh 
hello20.sh 
hello2.sh 
hello3.sh 
hello.sh 
math.sh 
mydate.sh 
noweb.sh 
numbers.sh 
rename.sh 
size2.sh 
size3.sh 
size.sh
```

# 查看存档内容

您可能想要查看存档的内容。为此，您可以使用`-t`选项以及后跟存档名称的`-f`选项：

```
tar -tf archive
```

例如，要查看我们刚刚创建的`scripts.tar`存档的内容，可以运行以下命令：

```
root@ubuntu-linux:/home/elliot# tar -tf /root/backup/scripts.tar 
3x10.sh
detect.sh 
empty.sh 
filetype.sh 
fun1.sh 
game.sh 
hello20.sh 
hello2.sh 
hello3.sh 
hello.sh 
math.sh 
mydate.sh 
noweb.sh 
numbers.sh 
rename.sh 
size2.sh 
size3.sh 
size.sh
```

如您所见，它列出了`scripts.tar`存档中的所有文件。

# 提取存档文件

您可能还想从存档中提取文件。为了演示，让我们在`/root`中创建一个名为`myscripts`的目录：

```
root@ubuntu-linux:/# mkdir /root/myscripts
```

要从存档中提取文件，我们使用`-x`选项以及后跟存档名称的`-f`选项。然后，我们使用`-C`选项，后跟目标目录，如下所示：

```
tar -xf archive -C destination
```

因此，要将`scripts.tar`存档中的所有文件提取到`/root/myscripts`目录中，您可以运行以下命令：

```
root@ubuntu-linux:/# tar -xf /root/backup/scripts.tar -C /root/myscripts
```

`-x`选项是`--extract`的简写，用于从存档中提取文件。我们还使用了`-C`选项，它在执行任何操作之前基本上会切换到`/root/myscripts`目录，因此文件被提取到`/root/myscripts`而不是当前目录。

现在让我们验证文件确实提取到了`/root/myscripts`目录中：

```
root@ubuntu-linux:/# ls /root/myscripts
3x10.sh 
empty.sh 
fun1.sh 
hello20.sh 
hello3.sh 
math.sh 
noweb.sh 
rename.sh 
size3.sh 
detect.sh 
filetype.sh 
game.sh 
hello2.sh 
hello.sh 
mydate.sh 
numbers.sh 
size2.sh 
size.sh
```

果然，我们在`/root/myscripts`目录中看到了所有的 bash 脚本！

# 使用 gzip 进行压缩

单独将文件放在存档中并不会节省磁盘空间。我们需要压缩存档以节省磁盘空间。在 Linux 上有许多压缩方法可供我们使用。但是，我们只将介绍三种最流行的压缩方法。

在 Linux 上最受欢迎的压缩方法可能是`gzip`，好处是它非常快速。您可以使用`tar`命令的`-z`选项将存档文件压缩为`gzip`，如下所示：

```
tar -czf compressed_archive archive_name
```

因此，要将`scripts.tar`存档压缩为名为`scripts.tar.gz`的`gzip`压缩存档，您首先需要切换到`/root/backup`目录，然后运行以下命令：

```
root@ubuntu-linux:~/backup# tar -czf scripts.tar.gz scripts.tar
```

现在，如果列出`backup`目录的内容，您将看到新创建的`gzip`压缩存档`scripts.tar.gz`：

```
root@ubuntu-linux:~/backup# ls 
scripts.tar scripts.tar.gz
```

通过使用`-z`选项进行了魔术操作，该选项使用`gzip`压缩方法压缩了存档。就是这样！请注意，这与创建存档非常相似：我们只是添加了`-z`选项-这是唯一的区别。

现在让我们在两个存档上运行`file`命令：

```
root@ubuntu-linux:~/backup# file scripts.tar 
scripts.tar: POSIX tar archive (GNU) 
root@ubuntu-linux:~/backup# file scripts.tar.gz
scripts.tar.gz: gzip compressed data, last modified: Sat Nov 2 22:13:44 2019, 
from Unix
```

如您所见，`file`命令检测到了两个存档的类型。现在让我们比较一下两个存档的大小（以字节为单位）：

```
root@ubuntu-linux:~/backup# du -b scripts.tar scripts.tar.gz 
20480 scripts.tar
1479 scripts.tar.gz
```

与未压缩存档`scripts.tar`相比，压缩存档`scripts.tar.gz`的大小要小得多，这是我们预期的。如果要将压缩存档`scripts.tar.gz`中的文件提取到`/root/myscripts`，可以运行： 

```
root@ubuntu-linux:~/backup# tar -xf scripts.tar.gz -C /root/myscripts
```

请注意，这与提取未压缩存档的内容的方式完全相同。

# 使用 bzip2 进行压缩

`bzip2`是 Linux 上另一种流行的压缩方法。平均而言，`bzip2`比`gzip`慢；然而，`bzip2`在将文件压缩到更小的大小方面做得更好。

你可以使用`tar`命令的`-j`选项来使用`bzip2`压缩压缩存档，如下所示：

```
tar -cjf compressed_archive archive_name
```

注意这里唯一的区别是我们使用`bzip2`压缩的`-j`选项，而不是`gzip`压缩的`-z`选项。

因此，要将`scripts.tar`存档压缩成名为`scripts.tar.bz2`的`bzip2`压缩存档，你首先需要切换到`/root/backup`目录，然后运行以下命令：

```
root@ubuntu-linux:~/backup# tar -cjf scripts.tar.bz2 scripts.tar
```

现在，如果你列出`backup`目录的内容，你会看到新创建的`bzip2`压缩的存档`scripts.tar.bz2`：

```
root@ubuntu-linux:~/backup# ls
scripts.tar scripts.tar.bz2 scripts.tar.gz
```

让我们在`bzip2`压缩的存档`scripts.tar.bz2`上运行`file`命令：

```
root@ubuntu-linux:~/backup# file scripts.tar.bz2 
scripts.tar.bz2: bzip2 compressed data, block size = 900k
```

它正确地检测到了用于存档`scripts.tar.bz2`的压缩方法。太棒了-现在让我们比较`gzip`压缩的存档`scripts.tar.gz`和`bzip2`压缩的存档`scripts.tar.bz2`的大小（以字节为单位）：

```
root@ubuntu-linux:~/backup# du -b scripts.tar.bz2 scripts.tar.gz 
1369 scripts.tar.bz2
1479 scripts.tar.gz
```

注意`bzip2`压缩的存档`scripts.tar.bz2`比`gzip`压缩的存档`scripts.tar.gz`要小。如果你想要将压缩存档`scripts.tar.bz2`中的文件提取到`/root/myscripts`，你可以运行：

```
root@ubuntu-linux:~/backup# tar -xf scripts.tar.bz2 -C /root/myscripts
```

注意它与提取`gzip`压缩的存档的内容的方式完全相同。

# 使用 xz 压缩

`xz`压缩方法是 Linux 上另一种流行的压缩方法。平均而言，`xz`压缩在减小（压缩）文件大小方面做得比所有三种压缩方法中的其他方法都要好。

你可以使用`tar`命令的`-J`选项来使用`xz`压缩压缩存档，如下所示：

```
tar -cJf compressed_name archive_name
```

注意这里我们使用大写字母`J`与`xz`压缩。因此，要将`scripts.tar`存档压缩成名为`scripts.tar.xz`的`xz`压缩存档，你首先需要切换到`/root/backup`目录，然后运行以下命令：

```
root@ubuntu-linux:~/backup# tar -cJf scripts.tar.xz scripts.tar
```

现在，如果你列出`backup`目录的内容，你会看到新创建的`xz`压缩的存档`scripts.tar.xz`：

```
root@ubuntu-linux:~/backup# ls
scripts.tar scripts.tar.bz2 scripts.tar.gz scripts.tar.xz
```

让我们在`scripts.tar.xz`上运行`file`命令：

```
root@ubuntu-linux:~/backup# file scripts.tar.xz 
scripts.tar.xz: XZ compressed data
```

它正确地检测到了用于存档`scripts.tar.xz`的压缩方法。

# 性能测量

你可以使用`time`命令来测量命令（或程序）执行所需的时间。`time`命令的一般语法如下：

```
time command_or_program
```

例如，要测量`date`命令执行所需的时间，你可以运行以下命令：

```
root@ubuntu-linux:~# time date 
Sun Nov 3 16:36:33 CST 2019

real 0m0.004s 
user 0m0.003s 
sys 0m0.000s
```

在我的系统上运行`date`命令只用了四毫秒；这相当快！

`gzip`压缩方法是所有三种压缩方法中最快的；好吧，让我们看看我是在撒谎还是在说实话！切换到`/root/backup`目录：

```
root@ubuntu-linux:~# cd /root/backup 
root@ubuntu-linux:~/backup#
```

现在让我们看看为`/boot`中的所有文件创建一个`gzip`压缩的存档文件需要多长时间：

```
root@ubuntu-linux:~/backup# time tar -czf boot.tar.gz /boot 
real 0m4.717s
user 0m4.361s 
sys 0m0.339s
```

在我的系统上，运行`gzip`花了 4.717 秒！现在让我们测量创建相同目录`/boot`的`bzip2`压缩存档所需的时间：

```
root@ubuntu-linux:~/backup# time tar -cjf boot.tar.bz2 /boot 
real 0m19.306s
user 0m18.809s 
sys   0m0.359s
```

`bzip2`花了巨大的 19.306 秒！你可以看到`gzip`压缩比`bzip2`快得多。现在让我们看看创建相同目录`/boot`的`xz`压缩存档所需的时间：

```
root@ubuntu-linux:~/backup# time tar -cJf boot.tar.xz /boot 
real 0m53.745s
user 0m52.679s 
sys   0m0.873s
```

`xz`几乎花了整整一分钟！我们可以得出结论，`gzip`绝对是我们讨论的所有三种压缩方法中最快的。

最后，让我们检查三个压缩存档的大小（以字节为单位）：

```
root@ubuntu-linux:~/backup# du -b boot.* 
97934386 boot.tar.bz2
98036178 boot.tar.gz
94452156 boot.tar.xz
```

正如你所看到的，`xz`在压缩文件方面做得最好。`bzip2`排名第二，`gzip`排名最后。

# 知识检查

对于以下练习，打开你的终端并尝试解决以下任务：

1.  在`/root`中为`/var`中的所有文件创建一个名为`var.tar.gz`的`gzip`存档。

1.  在`/root`中为`/tmp`中的所有文件创建一个名为`tmp.tar.bz2`的`bzip2`存档。

1.  在`/root`目录中为`/etc`目录中的所有文件创建一个名为`etc.tar.xz`的`xz`归档文件。
