# CompTIA Linux 认证指南（七）

> 原文：[`zh.annas-archive.org/md5/1D0BEDF2E9AB87F7188D92631B85ED3E`](https://zh.annas-archive.org/md5/1D0BEDF2E9AB87F7188D92631B85ED3E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十七章：执行管理安全任务

在上一章中，我们涵盖了 IPv4、IPv6、客户端 DNS 和网络故障排除。我们使用 IPv4 并讨论了 IPv4 路由，然后我们对 IPv6 做了同样的事情。这导致了客户端 DNS 和网络故障排除；我们涵盖了一些命令行工具，这些工具有助于排除潜在的网络连接问题。

在本章中，我们将专注于安全：主机安全、SSH 和加密。首先，我们将介绍主机安全；`/etc/sudoers`、`/etc/hosts.allow`和`/etc/.hosts.deny`文件将是我们的主要关注点。接下来，我们将使用 SSH。我们将专注于设置 SSH 所涉及的步骤，以及生成密钥的步骤。我们还将研究使用 SSH 登录到远程系统的步骤。此外，我们将使用各种可用的 SSH 文件。加密将是我们接下来的重点；我们将探讨加密和解密文件的方法。这将是一个重要的章节，涉及到保护 Linux 系统的安全。

本章我们将涵盖以下主题：

+   主机安全

+   SSH

+   加密

# 主机安全

在 Linux 中，我们可以执行一系列安全任务来保护我们的系统。到目前为止，我们一直以 root 用户的身份执行大部分管理任务。我们能否以普通用户的身份执行其中一些任务呢？我们可以使用普通用户帐户并赋予其某些 root 权限，而无需实际以 root 用户身份登录。这是通过`/etc/sudoers`文件实现的。在本演示中，我们将使用 Fedora 28 系统。如果我们尝试查看`/boot/grub2/`中的引导文件，将会看到以下内容：

```
[philip@localhost ~]$ ls /boot/grub2/
ls: cannot open directory '/boot/grub2/': Permission denied
[philip@localhost ~]$
```

根据前面的信息，用户没有足够的权限查看`/boot/grub2`的内容；我们收到了`Permission denied`的消息。此外，如果我们尝试进行更改（例如添加 IP 地址），将会看到以下内容：

```
[philip@localhost ~]$ ip a s ens33
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
 link/ether 00:0c:29:04:35:bd brd ff:ff:ff:ff:ff:ff
 inet 172.16.175.129/24 brd 172.16.175.255 scope global dynamic noprefixroute ens33
 valid_lft 1700sec preferred_lft 1700sec
 inet 172.16.11.0/23 scope global ens33
 valid_lft forever preferred_lft forever
 inet6 2001:db8:0:f101::3/64 scope global
 valid_lft forever preferred_lft forever
 inet6 fe80::413:ea63:2e8a:5f2b/64 scope link noprefixroute
 valid_lft forever preferred_lft forever
[philip@localhost ~]$ ip a a 10.20.1.1/24 dev ens33
RTNETLINK answers: Operation not permitted
[philip@localhost ~]$
```

根据前面的信息，我们将执行第一个命令——`IP`命令，使用`a`和`s`选项（`a`表示地址，`s`表示显示），但是当我们尝试添加 IP 地址时，会收到`Operation not permitted`的消息。消息会有所不同，具体取决于您尝试查看的内容，就像`ls`命令的情况一样，而不是在后面的演示中进行更改。

# su 命令

解决标准用户权限问题的一种技术是使用`su`命令；`su`表示**substitute user**。`su`命令的基本语法如下：

```
su <option>
```

根据前面的命令，我们还可以使用`su`命令而不使用任何选项，如下所示：

```
[philip@localhost ~]$ su
Password:
[root@localhost philip]#
```

太棒了！当我们使用`su`命令而不使用任何选项时，它会提示我们输入 root 密码，然后以 root 用户身份登录。但是，由于安全问题，这可能不是理想的做法。更好的方法是执行命令，但不要以 root 用户身份登录；这可以通过传递`-l`选项来实现，该选项需要用户帐户的名称，以及`-c`选项，该选项需要命令。以下命令显示了我们如何使用`su`命令有效地显示`/boot/grub2/`目录的内容，并同时以标准用户身份登录：

```
[philip@localhost ~]$ su -l root -c 'ls /boot/grub2/'
Password:
device.map  fonts  grub.cfg  grubenv  i386-pc  locale  themes
[philip@localhost ~]$
```

太棒了！`/boot/grub2/`目录的内容现在将被显示。但是，内容将以白色（除了白色）显示；我们可以传递`--color`选项来指示`ls`命令显示颜色，就像我们以 root 用户身份登录一样。如下所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00164.jpeg)

太棒了！我们可以看到当省略`--color`选项时，与在 ls 命令中包括它相比的区别。此外，当命令之间有空格时，我们必须用单引号（'）括起整个命令。另一个有用的选项是`-s`选项；这告诉 su 命令使用用户提供的指定 shell，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00165.jpeg)

太棒了！当我们使用`-s`选项并指定了 shell（在我们的案例中是`/usr/sbin/sh`）时，我们不需要在 ls 命令中指定`--color`选项。

使用 su 命令的另一种方法是传递`-`选项，这意味着 root 用户，如下所示：

```
[philip@localhost ~]$ su - -c 'ls /boot/grub2/' -s /usr/bin/sh
Password:
device.map  fonts  grub.cfg  grubenv  i386-pc  locale  themes
[philip@localhost ~]$
```

完美！内容被显示出来，我们没有指定登录`root`。我们可以通过查看/etc/shells 文件来看到可用的 shell 列表，如下所示：

```
[philip@localhost ~]$ cat /etc/shells
/bin/sh
/bin/bash
/sbin/nologin
/usr/bin/sh
/usr/bin/bash
/usr/sbin/nologin
/usr/bin/tmux
/bin/tmux
[philip@localhost ~]$
```

太棒了！我们可以看到可以与 su 命令的`-s`选项一起使用的各种 shell。到目前为止，我们只查看了 su 命令的内容，但我们也可以对其进行更改。以下命令显示了我们如何使用 su 命令进行更改：

```
[philip@localhost ~]$ su - -c 'ip a a 172.20.1.1/24 dev ens33'
Password:
[philip@localhost ~]$ ip a s ens33 | grep inet
 inet 172.16.175.129/24 brd 172.16.175.255 scope global dynamic noprefixroute ens33
 inet 172.16.11.0/23 scope global ens33
 inet 172.20.1.1/24 scope global ens33
 inet6 2001:db8:0:f101::3/64 scope global
 inet6 fe80::413:ea63:2e8a:5f2b/64 scope link noprefixroute
[philip@localhost ~]$
```

太棒了！IP 地址已成功添加。

使用 su 命令的一个主要缺点是，每个用户都必须知道 root 密码才能执行它。

# sudo 命令

sudo 命令解决了普通用户需要 root 密码的困境，只要用户帐户位于/etc/sudoers 配置文件中。sudo 命令的基本语法如下：

```
sudo <command>
```

除了前面的命令，我们只需指定要执行的命令，这通常需要 root 权限。让我们尝试 sudo 命令，如下所示：

```
[philip@localhost ~]$ sudo ls /boot/grub2/
[sudo] password for philip:
device.map  fonts  grub.cfg  grubenv  i386-pc  locale  themes
[philip@localhost ~]$
```

太棒了！当我们执行 sudo 命令并传递需要 root 权限的命令时，我们会提示输入标准用户的密码，而不是 root 用户的密码。之后，我们可以传递另一个带有 sudo 命令的命令，我们不会被提示输入密码，如下面的代码片段所示：

```
[philip@localhost ~]$ sudo ip a a 192.168.5.5/24 dev ens33
[philip@localhost ~]$ ip a | grep inet
 inet 127.0.0.1/8 scope host lo
 inet6 ::1/128 scope host
 inet 172.16.175.129/24 brd 172.16.175.255 scope global dynamic noprefixroute ens33
 inet 172.16.11.0/23 scope global ens33
 inet 172.20.1.1/24 scope global ens33
 inet 192.168.5.5/24 scope global ens33
 inet6 2001:db8:0:f101::3/64 scope global
 inet6 fe80::413:ea63:2e8a:5f2b/64 scope link noprefixroute
[philip@localhost ~]$
```

太棒了！命令成功执行，而不需要用户的密码。这是可能的，因为有一个超时设置，保存了用户的密码；超时后，我们将被提示再次输入用户的密码。然而，在用户打开另一个终端的情况下，情况并非如此，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00166.jpeg)

太棒了！我们可以看到超时值不会影响新的终端，因为用户被提示输入他们的密码。

有时我们可能希望增加超时值，特别是当我们要长时间工作时。放心，我们可以通过在/etc/sudoers 文件中搜索 env_reset 并在其旁边附加 timestamp_timeout 选项来增加超时值。/etc/sudoers 文件的内容如下：

```
## Sudoers allows particular users to run various commands as
## the root user, without needing the root password.
## This file must be edited with the 'visudo' command.
## Host Aliases
## Groups of machines. You may prefer to use hostnames (perhaps using
## wildcards for entire domains) or IP addresses instead.
# Host_Alias     FILESERVERS = fs1, fs2
# Host_Alias     MAILSERVERS = smtp, smtp2
## User Aliases
## These aren't often necessary, as you can use regular groups
## (ie, from files, LDAP, NIS, etc) in this file - just use %groupname
## rather than USERALIAS
# User_Alias ADMINS = jsmith, mikem
## Command Aliases
## These are groups of related commands...
## Networking
# Cmnd_Alias NETWORKING = /sbin/route, /sbin/ifconfig, /bin/ping, /sbin/dhclient, /usr/bin/net, /sbin/iptables, /usr/bin/rfcomm, /usr/bin/wvdial, /sbin/iwconfig, /sbin/mii-tool
## Installation and management of software
Defaults    env_reset
Defaults    env_keep =  "COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS"
## Allow root to run any commands anywhere
root       ALL=(ALL)            ALL
## Allows people in group wheel to run all commands
%wheel                ALL=(ALL)            ALL
## Same thing without a password
# %wheel            ALL=(ALL)            NOPASSWD: ALL
#includedir /etc/sudoers.d
[philip@localhost ~]$
```

在前面的代码中，为了简洁起见，省略了一些输出。我们可以更改许多选项。例如，要增加超时值，我们可以使用 visudo 编辑/etc/sudoers；强烈建议不要使用 visudo 之外的任何编辑器，如下所示：

```
[philip@localhost ~]$ sudo cat /etc/sudoers | grep env_reset
Defaults    env_reset,timestamp_timeout=60
[philip@localhost ~]$
```

太棒了！我们添加了`timestamp_timeout=60`；这告诉 sudo 保存用户的密码 60 分钟。另一个有用的选项是在用户输入密码时显示输出；可以显示用户输入的每个按键的星号（*）。这是通过在 env_reset 选项旁边附加 pwfeedback 选项来实现的，如下所示：

```
[philip@localhost ~]$ sudo cat /etc/sudoers | grep env_reset
Defaults    env_reset,timestamp_timeout=60,pwfeedback
[philip@localhost ~]$
```

根据前面的命令，当用户首次尝试使用 sudo 命令时，密码将用星号表示，如下所示：

```
[philip@localhost ~]$ sudo ls /boot/grub2/
[sudo] password for philip: *******
device.map  fonts  grub.cfg  grubenv  i386-pc  locale  themes
[philip@localhost ~]$
```

太棒了！我们现在可以看到代表输入密码的星号。

当我们添加新用户时，新用户不会自动添加到/etc/sudoers 文件中。我们必须手动添加用户，如下所示：

```
[philip@localhost ~]$ sudo useradd teddy
[philip@localhost ~]$ sudo passwd teddy
Changing password for user teddy.
New password:
BAD PASSWORD: The password fails the dictionary check - it is based on a dictionary word
Retype new password:
passwd: all authentication tokens updated successfully.
[philip@localhost ~]$
```

现在，我们可以切换用户，要么通过在计算机上注销并重新登录，要么使用`su`命令，如下所示：

```
[philip@localhost ~]$ su teddy
Password:
[teddy@localhost philip]$
```

我们已经成功以新用户登录；现在，当我们尝试发出`sudo`命令时，结果将如下所示：

```
[teddy@localhost philip]$ sudo ls /boot/grub2/
We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:
 #1) Respect the privacy of others.
 #2) Think before you type.
 #3) With great power comes great responsibility.
[sudo] password for teddy:
teddy is not in the sudoers file.  This incident will be reported.
[teddy@localhost philip]$
```

我们收到了一条通知消息，但当我们输入新用户的密码时，我们收到了可怕的`teddy 不在 sudoers 文件中`消息，以及`此事件将被报告`。这基本上告诉我们，我们必须将新用户添加到`/etc/sudoer`文件中。有多种方法可以做到这一点；其中一种可能是最简单的方法是将新用户添加到`wheel`组。`wheel`组可以执行所有命令，如在`/etc/sudoer`文件中所示：

```
[philip@localhost ~]$ sudo cat /etc/sudoers | grep wheel
## Allows people in group wheel to run all commands
%wheel                ALL=(ALL)            ALL
# %wheel            ALL=(ALL)            NOPASSWD: ALL
[philip@localhost ~]$
```

如您所见，`wheel`组存在，并具有完全访问权限；我们可以使用`usermod`命令并传递`-a`和`-G`选项（`a`表示追加，`G`表示组），如下所示：

```
[philip@localhost ~]$ usermod -aG wheel teddy
usermod: Permission denied.
usermod: cannot lock /etc/passwd; try again later.
[philip@localhost ~]$
```

我们需要 root 权限来修改另一个用户的属性；我们可以使用`sudo`命令，如下所示：

```
[philip@localhost ~]$ sudo usermod -aG wheel teddy
[philip@localhost ~]$ su teddy
Password:
 [teddy@localhost philip]$ sudo ls /boot/grub2/
[sudo] password for teddy: 
device.map  fonts  grub.cfg  grubenv  i386-pc  locale  themes
[teddy@localhost philip]$
```

太棒了！新用户现在可以使用`sudo`命令。让我们来看看在`/etc/sudoer`中添加条目的语法，如下所示：

```
[teddy@localhost philip]$ sudo cat /etc/sudoers | grep %
%wheel                ALL=(ALL)           ALL
[teddy@localhost philip]$
Based on the above, the syntax for an entry is as follows:
<user/group> <system/ALL> = <effective user/ALL> <command(s)>
```

我们可以为特定用户或组定义一个条目（在组名前面必须加上`%`）；然后我们可以指定要为哪个系统添加条目，要允许哪个用户执行命令，最后是实际的命令。让我们试试；我们将从新用户中删除`wheel`组，并为新用户创建一个条目，如下所示：

```
[philip@localhost ~]$ sudo usermod -G "" teddy
[philip@localhost ~]$ groups teddy
teddy : teddy
[philip@localhost ~]$ sudo cat /etc/sudoers | grep teddy
teddy ALL=(ALL) /usr/sbin/ls
[philip@localhost ~]$
```

太棒了！我们已经限制了新用户只能执行`ls`和`cat`命令；可以通过以下方式证明：

```
[philip@localhost ~]$ su teddy
Password:
[teddy@localhost philip]$ sudo ls /boot/grub2/
device.map  fonts  grub.cfg  grubenv  i386-pc  locale  themes
[teddy@localhost philip]$ sudo cat /etc/resolv.conf
Sorry, user teddy is not allowed to execute '/usr/bin/cat /etc/resolv.conf' as root on localhost.localdomain.
[teddy@localhost philip]$
```

太棒了！新用户只能以 root 权限使用`ls`命令，并且无法使用`sudo`命令进行任何其他更改。此外，我们可以授予新用户执行我们指定的尽可能多的命令的能力，如下所示：

```
[philip@localhost ~]$ sudo cat /etc/sudoers | grep teddy
teddy    ALL=(ALL)            /usr/bin/ls,         /usr/bin/cat
[philip@localhost ~]$
[teddy@localhost philip]$ sudo ls /boot/grub2/
device.map  fonts  grub.cfg  grubenv  i386-pc  locale  themes
[teddy@localhost philip]$ sudo cat /etc/resolv.conf
# Generated by NetworkManager
nameserver 8.8.8.8
[teddy@localhost philip]$
[teddy@localhost philip]$ sudo ip a a 172.16.20.1/24 dev ens33
Sorry, user teddy is not allowed to execute '/usr/sbin/ip a a 172.16.20.1/24 dev ens33' as root on localhost.localdomain.
[teddy@localhost philip]$
```

太棒了！我们为新用户添加了`cat`命令，使新用户能够以 root 权限执行`cat`命令。要记住的一件事是，当将多个命令放在一起时，必须在命令之间按*Tab*键放置制表符。我们可以与`sudo`命令一起使用的另一个选项是`-l`选项；这将列出当前用户的权限，如下所示：

```
[philip@localhost ~]$ sudo -l
Matching Defaults entries for philip on localhost:
 !visiblepw, env_reset, timestamp_timeout=60, pwfeedback, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2
 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME
 LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
User philip may run the following commands on localhost:
 (ALL) ALL
[philip@localhost ~]$
```

如您所见，用户`philip`可以使用`sudo`命令运行所有命令。但是，如果我们对其他用户`teddy`运行带有`-l`的`sudo`命令，我们将看到用户的访问权限，如下所示：

```
[teddy@localhost philip]$ sudo -l
[sudo] password for teddy: 
Matching Defaults entries for teddy on localhost:
 !visiblepw, env_reset, timestamp_timeout=60, pwfeedback, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2
 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME
 LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
User teddy may run the following commands on localhost:
 (ALL) /usr/bin/ls, /usr/bin/cat
[teddy@localhost philip]$
```

太棒了！我们只能看到`teddy`可以以 root 权限执行两个命令。还可以使用`-u`选项传递用户名，并指定要使用`sudo`执行的命令，如下所示：

```
[philip@localhost ~]$ sudo -u teddy cat /etc/resolv.conf
# Generated by NetworkManager
nameserver 8.8.8.8
[philip@localhost ~]$ sudo -u teddy ip a a 10.10.10.10/24 dev ens33
RTNETLINK answers: Operation not permitted
[philip@localhost ~]$
```

太棒了！另一个有用的选项是`-v`，它将重置用户的身份验证超时，如下所示：

```
[philip@localhost ~]$ sudo -v
[philip@localhost ~]$
```

类似地，可以通过使用`sudo`传递`-k`选项立即终止身份验证会话，如下所示：

```
[philip@localhost ~]$ sudo -k
[philip@localhost ~]$ sudo ls /boot/grub2/
[sudo] password for philip: 
device.map  fonts  grub.cfg  grubenv  i386-pc  locale  themes
[philip@localhost ~]$
```

太棒了！在前面的代码中，用户在尝试使用`-k`选项执行`sudo`命令时必须提供他们的密码。

到目前为止，我们在第一次执行`sudo`时一直提供用户的密码；可以在不输入密码的情况下运行`sudo`。我们在为新用户添加的条目中添加`NOPASSWD`选项，如下所示：

```
[philip@localhost ~]$ sudo cat /etc/sudoers | grep teddy
teddy    ALL=(ALL)            NOPASSWD:/usr/bin/ls,               /usr/bin/cat
[philip@localhost ~]$
[philip@localhost ~]$ su teddy
Password:
[teddy@localhost philip]$ sudo cat /etc/resolv.conf
# Generated by NetworkManager
nameserver 8.8.8.8
[teddy@localhost philip]$ sudo ls /boot/grub2/
device.map  fonts  grub.cfg  grubenv  i386-pc  locale  themes
[teddy@localhost philip]$
```

太棒了！每当用户`teddy`尝试执行`sudo`命令时，他们将不再被提示输入密码。

# TCP 包装

我们可以通过使用 TCP 包装在 Linux 系统中添加另一层安全性。**TCP 包装**在流入系统时过滤流量。 TCP 包装检查流量与两个文件：`/etc/hosts.allow`和`/etc/hosts.deny`。规则采用自上而下的方式应用，这意味着始终先应用第一条规则。我们可以查看`/etc/hosts.allow`的内容，如下所示：

```
[philip@localhost ~]$ cat /etc/hosts.allow
#
# hosts.allow  This file contains access rules which are used to
# allow or deny connections to network services that
# either use the tcp_wrappers library or that have been
# started through a tcp_wrappers-enabled xinetd.
# See 'man 5 hosts_options' and 'man 5 hosts_access'
# for information on rule syntax.
# See 'man tcpd' for information on tcp_wrappers
#
[philip@localhost ~]$
```

该文件只包含以`#`开头的注释。创建规则的基本语法如下：

```
<daemon>:        <client list> [:<option>: <option>:…]      
```

我们可以使用文本编辑器（如 vi 或 nano）添加规则，如下所示：

```
[philip@localhost ~]$ sudo cat /etc/hosts.allow
#
vsftpd:                  172.16.175.
[philip@localhost ~]$
```

在上述命令中，我们为`vsftpd`添加了一个规则；这是 FTP 的安全版本。然后我们指定了客户端列表——子网`172.16.175.`。`.`表示该子网中的任何 IP 地址都可以访问`vsftpd`。定义规则的另一种方法是指定域，如下所示：

```
[philip@localhost ~]$ sudo cat /etc/hosts.allow
#
vsftpd:                  .packtpub.com
[philip@localhost ~]$
```

太棒了！`.packtpub.com`内的任何人都可以访问本地系统上的`vsftpd`。此外，我们可以在规则中使用关键字`ALL`；这匹配一切，并且可以放在守护程序或客户端列表部分，如下所示：

```
[philip@localhost ~]$ sudo cat /etc/hosts.allow
vsftpd:                  .packtpub.com
in.telnetd:           ALL
[philip@localhost ~]$
```

太棒了！每个人都可以访问本地系统上的 Telnet 服务。还可以通过传递`spawn`选项来执行另一个命令。当我们想要记录谁正在尝试访问本地系统上的特定服务时，这是有用的。我们使用`spawn`选项如下：

```
[philip@localhost ~]$ sudo cat /etc/hosts.allow
vsftpd:                  .packtpub.com: spawn /bin/echo `/bin/date` from %h>>/var/log/vsftp.log : allow
in.telnetd:           ALL
[philip@localhost ~]$
```

太棒了！`spawn`选项创建一个包含当前日期（`/bin/date`）的消息，然后将其附加到尝试访问`vsftpd`的系统的主机名（`%h`）中；然后将其附加到`/var/log/vsftp.log`中。然后我们可以查看`/etc/hosts.deny`文件，如下所示：

```
[philip@localhost ~]$ sudo cat /etc/hosts.deny
# hosts.deny   This file contains access rules which are used to
#              deny connections to network services that either use
#              the tcp_wrappers library or that have been
#              The rules in this file can also be set up in
#              /etc/hosts.allow with a 'deny' option instead.
#              See 'man 5 hosts_options' and 'man 5 hosts_access'
#              for information on rule syntax.
#              See 'man tcpd' for information on tcp_wrappers
 [philip@localhost ~]$
```

在上述命令中，`/etc/hosts.deny`只包含注释（`#`）。建议在此文件中拒绝一切，如下所示：

```
[philip@localhost ~]$ sudo cat /etc/hosts.deny
ALL:ALL
[philip@localhost ~]$
```

太棒了！我们指定了`ALL:ALL:`，以拒绝除`/etc/hosts.allow`中列出的规则之外的所有内容。

# SSH

我们主要使用 SSH 来安全登录到远程系统。大多数 Linux 发行版默认安装了 SSH 软件包。为了验证 SSH 是否正在运行，我们使用`systemctl`命令；我们传递`status`选项，如下所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00167.jpeg)

SSH 守护程序`ssh.service`目前正在运行（特别是安全外壳服务器）。我们可以使用的另一种验证 SSH 服务是否正在运行的方法是`netstat`命令；我们传递`ntlp`选项（`n`用于显示端口号，`t`用于 TCP 协议，`l`用于当前监听，`p`用于程序 ID/程序名称），如下所示：

```
root@Linuxplus:/home/philip# netstat -ntlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address Foreign Address State       PID/Program name 
tcp  0   0  0.0.0.0:514     0.0.0.0:*  LISTEN  519/rsyslogd 
tcp  0   0  127.0.0.53:53   0.0.0.0:*  LISTEN  431/systemd-resolve
tcp  0   0  0.0.0.0:22      0.0.0.0:*  LISTEN  1152/sshd 
tcp  0   0  127.0.0.1:631   0.0.0.0:*  LISTEN  2638/cupsd 
tcp6 0   0  :::514          :::*       LISTEN  519/rsyslogd 
tcp6 0   0  :::22           :::*       LISTEN  1152/sshd 
tcp6 0   0  ::1:631         :::*       LISTEN  2638/cupsd 
root@Linuxplus:/home/philip#
```

正如您所看到的，SSH 服务器守护程序目前正在 TCP 端口`22`上运行。建立与远程系统的连接的基本语法如下：

```
ssh <remote system>
```

我们只需运行`ssh`命令并仅传递远程系统；我们将从 Fedora 28 系统使用`ssh`命令并尝试连接到 Ubuntu 18 系统，如下所示：

```
 [philip@localhost ~]$ ssh 172.16.175.130
The authenticity of host '172.16.175.130 (172.16.175.130)' can't be established.
ECDSA key fingerprint is SHA256:SfI3vfS3yRRWSGN2jgAG7K5aQc65c/zVt/lz+D8mQBQ.
ECDSA key fingerprint is MD5:a2:03:c5:38:b3:83:88:fa:85:b5:5f:e6:91:eb:87:c1.
Are you sure you want to continue connecting (yes/no)?yes
Warning: Permanently added '172.16.175.130' (ECDSA) to the list of known hosts.
philip@172.16.175.130's password:
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-20-generic x86_64)
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.
philip@Linuxplus:~$
```

在上述命令中，为简洁起见省略了一些输出。如果您指定不带任何选项的命令，SSH 程序将使用当前用户`philip`，并显示服务器的指纹。这将在 Fedora 28 系统中的`~/.ssh/known_hosts`中添加用户`philip`。我们可以查看文件，如下所示：

```
[philip@localhost ~]$ cat .ssh/known_hosts
172.16.175.130 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPhEHNo6YSOE+ZZ9vHVmQqBPFQd8WtAUFoGYAJe3VPQJlhjhc9bxy+vwsetQiEIKTyMgnfrOC7LNbhxxmJ4IX8w=
[philip@localhost ~]$
```

太棒了！我们在 Fedora 28 系统上的用户`philip`的`~/.ssh/known_hosts`中有 Ubuntu 系统的信息。还可以使用`ssh`命令使用不同的用户名；我们指定`-l`选项，如下所示：

```
[philip@localhost ~]$ ssh -l hacker 172.16.175.130
hacker@172.16.175.130's password:
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-20-generic x86_64)
$ exit
Connection to 172.16.175.130 closed.
[philip@localhost ~]$
```

我们能够使用不同的用户通过 SSH 登录。还要注意，我们收到了之前识别服务器指纹的消息。这是因为信息先前存储在`~/.ssh/known_hosts`中。如果我们使用文本编辑器（如 vi 或 nano）删除内容，我们将再次收到身份验证消息，如下所示：

```
[philip@localhost ~]$ cat .ssh/known_hosts
[philip@localhost ~]$
[philip@localhost ~]$ ssh -l hacker 172.16.175.130
The authenticity of host '172.16.175.130 (172.16.175.130)' can't be established.
ECDSA key fingerprint is SHA256:SfI3vfS3yRRWSGN2jgAG7K5aQc65c/zVt/lz+D8mQBQ.
ECDSA key fingerprint is MD5:a2:03:c5:38:b3:83:88:fa:85:b5:5f:e6:91:eb:87:c1.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '172.16.175.130' (ECDSA) to the list of known hosts.
hacker@172.16.175.130's password:
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-20-generic x86_64)
[philip@localhost ~]$
```

太棒了！我们删除了内容，然后再次收到了身份验证消息。

到目前为止，每次我们尝试启动 SSH 会话时都会提示输入密码。但是，可以绕过密码提示并无阻碍地登录到系统。我们使用 SSH 密钥进行身份验证；这被称为**基于密钥的身份验证**。基于密钥的身份验证涉及创建一对密钥：私钥和公钥。私钥存储在客户端系统上，公钥存储在目标系统上。特别是，我们使用`ssh-keygen`命令在目标系统上生成 SSH 密钥。接下来，我们将客户端系统上的密钥复制过去；我们使用`ssh-copy-id`命令复制密钥。当您首次使用基于密钥的身份验证连接时，服务器会使用公钥向客户端系统传输一条消息，然后可以使用客户端系统上的私钥来解释这条消息。

让我们使用`ssh-keygen`命令在我们需要登录的客户端系统上生成 SSH 密钥；这将是 Fedora 28 系统，如下所示：

```
[philip@localhost ~]$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/philip/.ssh/id_rsa):
```

默认情况下，算法是`rsa`，存储密钥对的位置在当前用户的主目录中（`~/.ssh/id_rsa`）。我们接受默认值并按*Enter*，如下所示：

```
[philip@localhost ~]$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/philip/.ssh/id_rsa):
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
```

我们必须指定一个`passphrase`；我们将使用一个超级秘密的`passphrase`，然后按*Enter*，如下所示：

```
[philip@localhost ~]$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/philip/.ssh/id_rsa):
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /home/philip/.ssh/id_rsa.
Your public key has been saved in /home/philip/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:BwdFiHu2iEyvnnXhnY+1tNpZmlaZZdL1Zugwda9PJ7g philip@localhost.localdomain
The key's randomart image is:
+---[RSA 2048]----+
|       ..+o      |
|      . ..    . o|
|       .. .  . ++|
|    . . oo  o o O|
|   o o +S..  = X |
|    o o..+ .. B o|
|     .. o o oo.+.|
|    .o .   *EB  .|
|   .o     ooO    |
+----[SHA256]-----+
[philip@localhost ~]$
```

太棒了！密钥是使用 2,048 位密钥大小生成的。现在，我们可以在用户的主目录上运行`ls`命令，并查看`~/.ssh`目录中的内容，如下所示：

```
[philip@localhost ~]$ ls -a .ssh
.  ..  id_rsa  id_rsa.pub  known_hosts
[philip@localhost ~]$
```

太棒了！除了我们之前介绍的`known_hosts`文件之外，我们现在有两个额外的文件：`id_rsa`（这是私钥）和`id_rsa.pub`（这是公钥）。我们可以使用`cat`命令查看内容：

```
[philip@localhost ~]$ cat ~/.ssh/id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNvsCDZaUs6mralW+c1QnQ9cMeUqW0c/4IF8DThVK0Bi4CPnQApafJZrOyeQeJbLxORCJf+YLkE+DWREwJw0EU21PkiZeij0DEIlspqToo6BkKDPfXXCl35OQxSUXERlAhGQQpVSbEJLy0WZsbs6iAy4ohmKcCWeEdHLz/3p0VUyd3NHvXaLsyno/Qa2ZOBOOZgwUeHUA/p0zykUff7M4kIyGYatt1/vYKDH+UOC5fyB/nLtvrq7P1MrlfMGyEjtc7nFDEHz4VeAP1iUItKEzsyrqEH/KbAa3/ZeSoSfaFxoKvEtSKF5tnICyVp6uiUTNfi/cN74dmiDfG+vtcF0nt philip@localhost.localdomain
[philip@localhost ~]$
```

太棒了！下一步是使用`ssh-copy-id`命令将客户端系统的公钥复制到目标服务器，我们的情况下，服务器是 Ubuntu 系统。在运行`ssh-copy-id`命令之前，让我们检查一下 Ubuntu 系统上的`~/.ssh`目录，如下所示：

```
philip@Linuxplus:~$ ls -a ~/.ssh
.  ..
philip@Linuxplus:~$
```

如您所见，`~/.ssh`目前是空的。现在，让我们在客户端系统上执行`ssh-copy-id`命令，如下所示：

```
[philip@localhost ~]$ ssh-copy-id philip@172.16.175.130
/usr/bin/ssh-copy-id: INFO: Source of key(s) to be installed: "/home/philip/.ssh/id_rsa.pub"
/usr/bin/ssh-copy-id: INFO: attempting to log in with the new key(s), to filter out any that are already installed
/usr/bin/ssh-copy-id: INFO: 1 key(s) remain to be installed -- if you are prompted now it is to install the new keys
philip@172.16.175.130's password:
Number of key(s) added: 1
Now try logging into the machine, with:   "ssh 'philip@172.16.175.130'"
and check to make sure that only the key(s) you wanted were added.
[philip@localhost ~]$
```

太棒了！公钥`~/.ssh/id_rsa.pub`已安全传输到服务器系统。现在，让我们再次检查 Ubuntu 系统上的`~/.ssh`目录，如下所示：

```
philip@Linuxplus:~$ ls -a ~/.ssh
.  ..  authorized_keys
philip@Linuxplus:~$
```

太棒了！我们现在有一个`authorized_keys`文件，位于`~/.ssh`目录中。我们可以使用`cat`命令验证公钥是否与客户端系统上的公钥相同，如下所示：

```
philip@Linuxplus:~$ cat ~/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDNvsCDZaUs6mralW+c1QnQ9cMeUqW0c/4IF8DThVK0Bi4CPnQApafJZrOyeQeJbLxORCJf+YLkE+DWREwJw0EU21PkiZeij0DEIlspqToo6BkKDPfXXCl35OQxSUXERlAhGQQpVSbEJLy0WZsbs6iAy4ohmKcCWeEdHLz/3p0VUyd3NHvXaLsyno/Qa2ZOBOOZgwUeHUA/p0zykUff7M4kIyGYatt1/vYKDH+UOC5fyB/nLtvrq7P1MrlfMGyEjtc7nFDEHz4VeAP1iUItKEzsyrqEH/KbAa3/ZeSoSfaFxoKvEtSKF5tnICyVp6uiUTNfi/cN74dmiDfG+vtcF0nt philip@localhost.localdomain
philip@Linuxplus:~$
```

太棒了！最后一步是在客户端系统（Fedora 28）上运行`ssh`命令，并验证我们能够登录到服务器（Ubuntu 18）而不使用密码，如下所示：

```
[philip@localhost ~]$ ssh 172.16.175.130
Enter passphrase for key '/home/philip/.ssh/id_rsa':
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-20-generic x86_64)
Last login: Thu Sep 13 16:47:50 2018 from 172.16.175.129
philip@Linuxplus:~$
```

```
ssh-add command:
```

```
[philip@localhost ~]$ ssh-agent
SSH_AUTH_SOCK=/tmp/ssh-qLovqqH69q1D/agent.79449; export SSH_AUTH_SOCK;
SSH_AGENT_PID=79450; export SSH_AGENT_PID;
echo Agent pid 79450;
 [philip@localhost ~]$
```

太棒了！我们启动了`ssh agent`，它创建了必要的变量并启动了进程。接下来，我们将使用`ssh-add`命令和`-l`选项运行；这将列出`ssh agent`知道的所有身份，如下所示：

```
[philip@localhost ~]$ ssh-add -l
The agent has no identities.
[philip@localhost ~]$
```

如您在上述命令中所见，代理没有已知的身份；我们现在将使用`ssh-add`命令添加我们之前创建的身份，不带任何选项，如下所示：

```
[philip@localhost ~]$ ssh-add
Enter passphrase for /home/philip/.ssh/id_rsa:
Identity added: /home/philip/.ssh/id_rsa (/home/philip/.ssh/id_rsa)
[philip@localhost ~]$ ssh-add -l
2048 SHA256:BwdFiHu2iEyvnnXhnY+1tNpZmlaZZdL1Zugwda9PJ7g /home/philip/.ssh/id_rsa (RSA)
[philip@localhost ~]$
```

太棒了！您现在可以看到我们之前生成的私钥的身份。现在，我们将尝试启动 SSH 会话，如下所示：

```
[philip@localhost ~]$ ssh 172.16.175.130
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-20-generic x86_64)
Last login: Fri Sep 14 10:06:44 2018 from 172.16.175.129
philip@Linuxplus:~$ exit
[philip@localhost ~]$
```

太棒了！我们成功登录，而无需输入用户密码或`passphrase`。SSH 配置存储在`/etc/ssh/ssh_config`中：

```
philip@localhost ~]$ cat /etc/ssh/ssh_config
# $OpenBSD: ssh_config,v 1.33 2017/05/07 23:12:57 djm Exp $
# IdentityFile ~/.ssh/id_dsa
# IdentityFile ~/.ssh/id_ecdsa
# IdentityFile ~/.ssh/id_ed25519
# Port 22
# Protocol 2
#   Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc
#   MACs hmac-md5,hmac-sha1,umac-64@openssh.com
#   EscapeChar ~
#   Tunnel no
#   TunnelDevice any:any
# To modify the system-wide ssh configuration, create a  *.conf  file under
#  /etc/ssh/ssh_config.d/  which will be automatically included below
Include /etc/ssh/ssh_config.d/*.conf
[philip@localhost ~]$
```

在上述代码中，为了简洁起见，一些输出已被省略。所有设置都使用它们的默认值。

另一个保存`known_hosts`的位置是`/etc/ssh/known_hosts`；这允许管理员添加局域网内所有服务器的身份。这种方法可以防止每次新用户尝试启动 SSH 会话到服务器时出现身份验证消息。我们可以复制`~./ssh/known_hosts`的内容到`/etc/ssh/known_hosts`，如果我们尝试以另一个用户登录，我们将不会看到身份验证消息：

```
[philip@localhost ~]$ cat ~/.ssh/known_hosts
172.16.175.130 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPhEHNo6YSOE+ZZ9vHVmQqBPFQd8WtAUFoGYAJe3VPQJlhjhc9bxy+vwsetQiEIKTyMgnfrOC7LNbhxxmJ4IX8w=
[philip@localhost ~]$ cat /etc/ssh/ssh_known_hosts
172.16.175.130 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPhEHNo6YSOE+ZZ9vHVmQqBPFQd8WtAUFoGYAJe3VPQJlhjhc9bxy+vwsetQiEIKTyMgnfrOC7LNbhxxmJ4IX8w=
[philip@localhost ~]$
 [philip@localhost ~]$ ssh hacker@172.16.175.130
hacker@172.16.175.130's password:
Welcome to Ubuntu 18.04 LTS (GNU/Linux 4.15.0-20-generic x86_64)
$ exit
Connection to 172.16.175.130 closed.
[philip@localhost ~]$ ssh teddy@172.16.175.130
teddy@172.16.175.130's password:
[philip@localhost ~]$
```

很好。没有一个用户收到了身份验证消息。请注意，他们被提示输入各自的密码，因为我们只为`philip`用户设置了基于密钥的身份验证；我们必须为每个用户生成密钥。

# 加密

在当今的环境中，保护我们的数据至关重要。我们可以使用各种加密方法；在我们的环境中，我们将使用 GNU 隐私保护（GnuPG 或 GPG）来加密和解密我们的文件和文件夹。在进行加密和解密时，我们将使用 gpg 命令。

首先，我们将使用最基本的形式加密文件，即对称加密；这需要密码。以下命令显示了我们如何使用 gpg 命令执行对称加密，使用-c 或--symmetric 选项：

```
[philip@localhost ~]$ cd Documents/
[philip@localhost Documents]$ ls
date_schedule  lsa_schedule  ls.txt  schedule  ssh  STDERR.txt  STDIN_STDOUT  STDIN_STDOUT.txt  TestFile1  The_Tee_command.txt
[philip@localhost Documents]$ gpg -c The_Tee_command.txt
Enter passphrase:
```

我们必须输入密码/密码短语，然后重新输入，如下所示：

```
[philip@localhost Documents]$ gpg -c The_Tee_command.txt
Repeat passphrase:
[philip@localhost Documents]$
[philip@localhost Documents]$ ls -l | grep The
-rw-r--r--. 1 root   root   370 Aug  7 14:53 The_Tee_command.txt
-rw-rw-r--. 1 philip philip 307 Sep 14 11:01 The_Tee_command.txt.gpg
[philip@localhost Documents]$
```

太棒了！创建了一个带有.gpg 扩展名的新文件；这是加密文件。我们可以尝试使用 cat 命令查看内容：

```
[philip@localhost Documents]$ cat The_Tee_command.txt.gpg
```

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00168.jpeg)

内容已加密，我们现在可以删除原始内容，只留下加密内容，如下所示：

```
[philip@localhost Documents]$ rm The_Tee_command.txt
rm: remove write-protected regular file 'The_Tee_command.txt'? yes
[philip@localhost Documents]$ ls -l | grep The
-rw-rw-r--. 1 philip philip 307 Sep 14 11:01 The_Tee_command.txt.gpg
[philip@localhost Documents]$
```

现在，只剩下加密文件。我们可以通过传递-d 选项来解密此文件，如下所示：

```
[philip@localhost Documents]$ gpg -d The_Tee_command.txt.gpg
gpg: AES encrypted data
Enter passphrase:
```

我们必须提供密码来解密文件，如下所示：

```
[philip@localhost Documents]$ gpg -d The_Tee_command.txt.gpg
gpg: AES encrypted data
Enter passphrase:
gpg: AES encrypted data
gpg: encrypted with 1 passphrase
#
# hosts.allow This file contains access rules which are used to
#             allow or deny connections to network services that
#             either use the tcp_wrappers library or that have been
#             started through a tcp_wrappers-enabled xinetd.
#
#              See 'man 5 hosts_options' and 'man 5 hosts_access'
#              for information on rule syntax.
#              See 'man tcpd' for information on tcp_wrappers
#
[philip@localhost Documents]$ ls -l | grep The
-rw-rw-r--. 1 philip philip 307 Sep 14 11:01 The_Tee_command.txt.gpg
[philip@localhost Documents]$
```

太棒了！文件的内容被显示出来，但是，正如我们所看到的，当我们运行 ls 命令时，我们仍然只有加密文件，没有生成新文件。请放心；我们可以传递-o 选项将输出保存到文件中，如下所示：

```
[philip@localhost Documents]$ gpg -o The_Tee_command.txt -d The_Tee_command.txt.gpg
gpg: AES encrypted data
gpg: encrypted with 1 passphrase
[philip@localhost Documents]$ ls -l | grep The
-rw-rw-r--. 1 philip philip 370 Sep 14 11:10 The_Tee_command.txt
-rw-rw-r--. 1 philip philip 307 Sep 14 11:01 The_Tee_command.txt.gpg
[philip@localhost Documents]$
```

太棒了！现在，我们既有加密文件，也有未加密文件。

我们还可以使用私钥/公钥对进行加密和解密。首先，我们必须使用 gpg 命令和--gen-key 选项生成密钥对，如下所示：

```
[philip@localhost Documents]$ gpg --gen-key
gpg (GnuPG) 1.4.22; Copyright (C) 2015 Free Software Foundation, Inc.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Please select what kind of key you want:
 (1) RSA and RSA (default)
 (2) DSA and Elgamal
 (3) DSA (sign only)
 (4) RSA (sign only)
Your selection?
```

我们必须选择密钥类型，“RSA 和 RSA”是默认值；我们将接受默认值，如下所示：

```
RSA keys may be between 1024 and 4096 bits long.
```

我们还必须指定密钥的大小，默认值为 2048；我们将选择 4096，因为更长的密钥更安全：

```
What keysize do you want? (2048) 4096
Requested keysize is 4096 bits
Please specify how long the key should be valid.
 0 = key does not expire
 <n>  = key expires in n days
 <n>w = key expires in n weeks
 <n>m = key expires in n months
 <n>y = key expires in n years
Key is valid for? (0) 1y
```

我们还必须指定密钥何时过期，默认值为`0`，表示永不过期。我们将选择`1y`，表示一年后过期：

```
Key expires at Sat 14 Sep 2019 11:15:50 AM EDT
Is this correct? (y/N) y
You need a user ID to identify your key; the software constructs the user ID
from the Real Name, Comment and Email Address in this form:
 "Heinrich Heine (Der Dichter) <heinrichh@duesseldorf.de>"
Real name: Philip Inshanally
```

然后，我们必须确认过期日期并指定“真实姓名”；我们将按以下信息填写信息：

```
Email address: pinshanally@gmail.com
Comment: It's always good to help others
You selected this USER-ID:
 "Philip Inshanally (It's always good to help others) <pinshanally@gmail.com>"
Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit?
```

现在我们必须通过输入`O`来确认，如下所示：

```
Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? O
You need a Passphrase to protect your secret key.
Repeat passphrase:
```

我们还必须保护我们的秘密密钥，如下所示：

```
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
.+++++
...+++++
We need to generate a lot of random bytes. It is a good idea to perform
some other action (type on the keyboard, move the mouse, utilize the
disks) during the prime generation; this gives the random number
generator a better chance to gain enough entropy.
...............+++++
...+++++
gpg: key 73941CF4 marked as ultimately trusted
public and secret key created and signed.
gpg: checking the trustdb
gpg: 3 marginal(s) needed, 1 complete(s) needed, PGP trust model
gpg: depth: 0  valid:   1  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 1u
gpg: next trustdb check due at 2019-09-14
pub   4096R/73941CF4 2018-09-14 [expires: 2019-09-14]
 Key fingerprint = 3C24 9577 0081 C03B 4D88  2D34 60E4 B83C 7394 1CF4
uid                  Philip Inshanally (It's always good to help others) <pinshanally@gmail.com>
sub   4096R/B29CE2BA 2018-09-14 [expires: 2019-09-14]
[philip@localhost Documents]$
```

太棒了！我们已成功生成了密钥对；我们可以通过使用 gpg 命令传递--list-keys 选项来验证这一点，如下所示：

```
[philip@localhost Documents]$ gpg --list-keys
/home/philip/.gnupg/pubring.gpg
-------------------------------
pub   4096R/73941CF4 2018-09-14 [expires: 2019-09-14]
uid                  Philip Inshanally (It's always good to help others) <pinshanally@gmail.com>
sub   4096R/B29CE2BA 2018-09-14 [expires: 2019-09-14]
[philip@localhost Documents]$
```

太棒了！正如您所看到的，我们的公钥信息在`/home/philip/.gnupg/pubring.gpg`中：

```
[philip@localhost Documents]$ ls -a ~/.gnupg/
.  ..  gpg.conf  pubring.gpg  pubring.gpg~  random_seed  secring.gpg  trustdb.gpg
[philip@localhost Documents]$
```

我们现在可以看到我们的公钥信息。接下来，我们将检查我们的私钥信息；我们将使用 gpg 命令传递--list-secret-keys 选项，如下所示：

```
[philip@localhost Documents]$ gpg --list-secret-keys
/home/philip/.gnupg/secring.gpg
-------------------------------
sec   4096R/73941CF4 2018-09-14 [expires: 2019-09-14]
uid                  Philip Inshanally (It's always good to help others) <pinshanally@gmail.com>
ssb   4096R/B29CE2BA 2018-09-14
[philip@localhost Documents]$
```

太棒了！我们可以看到有关私钥的信息；即私钥位于`/home/philip/.gnupg/secring.gpg`，如下所示：

```
[philip@localhost Documents]$ ls -a ~/.gnupg/
.  ..  gpg.conf  pubring.gpg  pubring.gpg~  random_seed  secring.gpg  trustdb.gpg
[philip@localhost Documents]$
```

太棒了！我们现在可以使用刚刚创建的公钥进行加密，通过 gpg 命令传递-r 选项，如下所示：

```
[philip@localhost Documents]$ gpg -e The_Tee_command.txt
You did not specify a user ID. (you may use "-r")
Current recipients:
Enter the user ID.  End with an empty line: pinshanally@gmail.com
Current recipients:
4096R/B29CE2BA 2018-09-14 "Philip Inshanally (It's always good to help others) <pinshanally@gmail.com>"
Enter the user ID.  End with an empty line:
File `The_Tee_command.txt.gpg' exists. Overwrite? (y/N) y
[philip@localhost Documents]$ ls
date_schedule  ls.txt    ssh         STDIN_STDOUT      TestFile1            The_Tee_command.txt.gpg
lsa_schedule   schedule  STDERR.txt  STDIN_STDOUT.txt  The_Tee_command.txt
[philip@localhost Documents]$
```

我们没有使用命令指定用户 ID，因此我们被提示指定用户 ID；然后我们按*Enter*移动到第二行，`输入用户 ID`。以空行结束：`""`，我们只需按*Enter*生成一个空行。之后，我们必须确认是否要覆盖之前加密的文件，当我们执行对称加密时。我们还可以使用`-r`选项指定`用户 ID`。让我们试一试：

```
[philip@localhost Documents]$ rm The_Tee_command.txt.gpg
[philip@localhost Documents]$ gpg -e -r pinshanally@gmail.com The_Tee_command.txt
[philip@localhost Documents]$ ls -l | grep The
-rw-rw-r--. 1 philip philip 370 Sep 14 11:10 The_Tee_command.txt
-rw-rw-r--. 1 philip philip 827 Sep 14 11:34 The_Tee_command.txt.gpg
[philip@localhost Documents]$
```

太棒了！我们没有被提示输入`用户 ID`，因为我们使用了`-r`选项来指定它。为了解密文件，我们需要传递`-d`选项，如下所示：

```
[philip@localhost Documents]$ gpg -d The_Tee_command.txt.gpg
You need a passphrase to unlock the secret key for
user: "Philip Inshanally (It's always good to help others) <pinshanally@gmail.com>"
4096-bit RSA key, ID B29CE2BA, created 2018-09-14 (main key ID 73941CF4)
Enter passphrase:
user: "Philip Inshanally (It's always good to help others) <pinshanally@gmail.com>"
4096-bit RSA key, ID B29CE2BA, created 2018-09-14 (main key ID 73941CF4)
gpg: encrypted with 4096-bit RSA key, ID B29CE2BA, created 2018-09-14
 "Philip Inshanally (It's always good to help others)<pinshanally@gmail.com>"
# hosts.allow     This file contains access rules which are used to
#                 allow or deny connections to network services that
#                either use the tcp_wrappers library or that have been
#               started through a tcp_wrappers-enabled xinetd.
#
#            See 'man 5 hosts_options' and 'man 5 hosts_access'
#             for information on rule syntax.
#              See 'man tcpd' for information on tcp_wrappers
[philip@localhost Documents]$
```

在上述代码中，我们遇到了与对称解密时相同的问题；显示的内容没有被保存。我们可以通过传递`-o`选项来快速解决这个问题：

```
[philip@localhost Documents]$ ls -l | grep The
-rw-rw-r--. 1 philip philip 370 Sep 14 11:10 The_Tee_command.txt
-rw-rw-r--. 1 philip philip 827 Sep 14 11:34 The_Tee_command.txt.gpg
[philip@localhost Documents]$ rm The_Tee_command.txt
[philip@localhost Documents]$ gpg -o The_Tee_command.txt -d The_Tee_command.txt.gpg
You need a passphrase to unlock the secret key for
user: "Philip Inshanally (It's always good to help others) <pinshanally@gmail.com>"
4096-bit RSA key, ID B29CE2BA, created 2018-09-14 (main key ID 73941CF4)
Enter passphrase:
gpg: encrypted with 4096-bit RSA key, ID B29CE2BA, created 2018-09-14
 "Philip Inshanally (It's always good to help others) <pinshanally@gmail.com>"
[philip@localhost Documents]$ ls -l | grep The
-rw-rw-r--. 1 philip philip 370 Sep 14 11:39 The_Tee_command.txt
-rw-rw-r--. 1 philip philip 827 Sep 14 11:34 The_Tee_command.txt.gpg
[philip@localhost Documents]$
```

太棒了！文件成功解密了。

我们还可以编辑密钥；我们可以使用`gpg`命令传递`--edit-key`选项，如下所示：

```
[philip@localhost Documents]$ gpg --edit-key pinshanally@gmail.com
gpg (GnuPG) 1.4.22; Copyright (C) 2015 Free Software Foundation, Inc.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Secret key is available.
pub  4096R/73941CF4  created: 2018-09-14  expires: 2019-09-14  usage: SC 
 trust: ultimate      validity: ultimate
sub  4096R/B29CE2BA  created: 2018-09-14  expires: 2019-09-14  usage: E 
[ultimate] (1). Philip Inshanally (It's always good to help others)<pinshanally@gmail.com>
gpg>
```

在上述命令中，我们可以进行多项更改。例如，如果我们想禁用密钥，我们可以输入`disable`，如下所示：

```
gpg> disable
gpg> list
pub  4096R/73941CF4  created: 2018-09-14  expires: 2019-09-14  usage: SC 
 trust: ultimate      validity: ultimate
*** This key has been disabled
sub  4096R/B29CE2BA  created: 2018-09-14  expires: 2019-09-14  usage: E 
[ultimate] (1). Philip Inshanally (It's always good to help others) <pinshanally@gmail.com>
Please note that the shown key validity is not necessarily correct
unless you restart the program.
gpg>
```

在上述命令中，我们改变了密钥的状态为`***此密钥已被禁用***`；让我们保存并退出，看看这样做的效果：

```
gpg> save
Key not changed so no update needed.
[philip@localhost Documents]$ rm The_Tee_command.txt.gpg
[philip@localhost Documents]$
[philip@localhost Documents]$ gpg -e -r pinshanally@gmail.com The_Tee_command.txt
gpg: pinshanally@gmail.com: skipped: public key not found
gpg: The_Tee_command.txt: encryption failed: public key not found
[philip@localhost Documents]$
```

当我们尝试使用密钥加密文件时，出现了错误。我们可以通过在`gpg`控制台内将`disable`更改为`enable`来快速解决这个问题，如下所示：

```
philip@localhost Documents]$ gpg --edit-key pinshanally@gmail.com
gpg (GnuPG) 1.4.22; Copyright (C) 2015 Free Software Foundation, Inc.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Secret key is available.
pub  4096R/73941CF4  created: 2018-09-14  expires: 2019-09-14  usage: SC 
 trust: ultimate      validity: ultimate
*** This key has been disabled
sub  4096R/B29CE2BA  created: 2018-09-14  expires: 2019-09-14  usage: E 
[ultimate] (1). Philip Inshanally (It's always good to help others) <pinshanally@gmail.com>
gpg> enable
gpg> list
pub  4096R/73941CF4  created: 2018-09-14  expires: 2019-09-14  usage: SC 
 trust: ultimate      validity: ultimate
sub  4096R/B29CE2BA  created: 2018-09-14  expires: 2019-09-14  usage: E 
[ultimate] (1). Philip Inshanally (It's always good to help others) <pinshanally@gmail.com>
Please note that the shown key validity is not necessarily correct
unless you restart the program.
gpg> save
Key not changed so no update needed.
[philip@localhost Documents]$
[philip@localhost Documents]$ gpg -e -r pinshanally@gmail.com The_Tee_command.txt
gpg: checking the trustdb
gpg: 3 marginal(s) needed, 1 complete(s) needed, PGP trust model
gpg: depth: 0  valid:   1  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 1u
gpg: next trustdb check due at 2019-09-14
[philip@localhost Documents]$ ls -l | grep The
-rw-rw-r--. 1 philip philip 370 Sep 14 11:54 The_Tee_command.txt
-rw-rw-r--. 1 philip philip 827 Sep 14 11:55 The_Tee_command.txt.gpg
[philip@localhost Documents]$
```

太棒了！

# 总结

在本章中，我们介绍了 Linux 环境中可用的各种安全功能。首先，我们介绍了以 root 权限访问命令；特别是，我们看了`su`和`sudo`命令。然后我们转向 TCP 包装器，重点介绍了`/etc/hosts.allow`和`/etc/hosts.deny`文件。我们看了这两个文件如何通过允许`/etc/hosts.allow`文件中的访问和在`/etc/hosts.deny`文件中拒绝所有内容来互补。

接下来，我们介绍了 SSH；我们看了如何在客户端和服务器之间设置 SSH 访问，允许无需输入密码即可无缝登录，并介绍了如何使用密码短语。然后我们缓存了密码短语，这样用户在登录服务器时就不必输入密码短语了。最后，我们深入讨论了加密。我们专注于对称加密，其中涉及密码短语；然后我们通过使用密钥对来进一步加强了加密。最后，我们看了如何编辑密钥的属性。

在下一章（也是最后一章）中，我们将通过专注于 shell 脚本和 SQL 数据管理来完成本书。在 Linux 环境中工作时，理解一些 shell 脚本和 SQL 管理技能是至关重要的。

# 问题

1.  在`/etc/hosts.allow`中每次激活规则时，以下哪个命令可以启动另一个命令？

A. 所有

B. 拒绝

C. 生成

D. 记录

1.  `su`代表什么？

A. 超级用户

B. 切换用户

C. 切换用户

D. 以上都不是

1.  当我们在没有任何选项的情况下使用`su`命令时，会要求哪个用户的密码？

A. 根用户

B. 当前用户

C. SSH 密码短语

D. 以上都不是

1.  以下哪个选项允许使用`su`命令在不登录的情况下执行命令？

A. `-a`

B. `-c`

C. `-d`

D. `-l`

1.  在`/etc/sudoers`中声明组时，以下哪个符号必须在组前面？

A. `-`

B. `^`

C. `-$`

D. ％

1.  以下哪个命令用于创建 SSH 密钥对？

A. `ssh-keygen`

B. `ssh-key-gen`

C. `ssh-create-key`

D. `ssh-key`

1.  以下哪个命令用于向 SSH 代理添加身份？

A. `ssh-add`

B. `ssh-agent`

C. `ssh.service`

D. `ssh-daemon`

1.  以下哪个命令可以安全地复制 SSH 公钥？

A. `ssh-copy`

B. `ssh-copy-id`

C. `ssh-cp`

D. `ssh-id-copy`

1.  以下哪个选项用于使用`gpg`命令加密文件？

A. `-d`

B. `-e`

C. `-r`

D. `-a`

1.  以下哪个选项用于在`gpg`命令中提供身份？

A. `-f`

B. `-e`

C. `-r`

D. `-a`

# 进一步阅读

+   以下网站提供了有关`sudo`的有用信息：[`www.computerhope.com/unix/sudo.htm`](https://www.computerhope.com/unix/sudo.htm)

+   以下网站提供了有关 SSH 的有用信息：[`www.ssh.com`](https://www.ssh.com)

+   以下网站提供了有关加密的有用信息：[`linuxaria.com`](http://linuxaria.com)


# 第十八章：Shell 脚本和 SQL 数据管理

在上一章中，我们涵盖了 Linux 环境中可用的各种安全功能。首先，我们讨论了以 root 权限执行命令。然后，我们转向 TCP 包装，重点放在`/etc/hosts.allow`和`/etc/hosts.deny`文件上。接下来，我们涵盖了 SSH；我们看了如何在客户端和服务器之间设置 SSH 访问。最后，我们深入讨论了加密。

在本章中，也是本书的最后一章，我们将涵盖 Shell 脚本和 SQL 管理的基础知识。首先，我们将看一下编写 shell 脚本的语法；然后是使用各种循环编写脚本，比如`for`和`while`循环。接下来，我们将涵盖使用`if`语句编写 shell 脚本。最后，我们将通过涵盖 SQL 管理的基础知识来结束本章（和本书）。

我们将在本章中涵盖以下主题：

+   Shell 脚本

+   SQL 数据管理

# Shell 脚本

在本节中，我们将涵盖 shell 脚本，从基础知识开始，然后转向使用循环和`if`语句编写脚本。

以下主题将在本节中涵盖：

+   Shell 脚本的基础知识

+   使用`for`循环编写脚本

+   使用`while`循环编写脚本

+   使用`if`语句编写脚本

# Shell 脚本的基础知识

在命令行上，我们经常需要定期执行一系列相同的命令。将这些命令捆绑在一起并简化这个过程，执行单个命令或脚本来完成一个需要重复输入单个命令的整体目标将是理想的。这就是 shell 脚本的优势所在。我们可以将我们的命令，无论有多长，放入一个单独的文件中；给它一个合适的名称；并根据需要执行脚本。以下代码显示了创建 shell 脚本的基本语法：

```
#! /bin/sh
```

上述命令是脚本中的第一行；它用于定义 shell 解释器。前面的字符`#!`通常被称为 shebang、sha-bang、hashbang、pound-bang 或 hash-pling。`/bin/sh`对象定义了应该使用哪个解释器来运行这个脚本；在这种情况下，它是 Shell 命令语言（`sh`）。另一个常见的解释器是：

```
#!/bin/bash
```

这与先前的声明类似，我们有`#!`，这表明我们将定义要使用的 shell 解释器；在这种情况下，我们使用的是 Bourne Again Shell，或者说是 Bash。这个 shell 提供了比常规的`sh` shell 更多的扩展；事实上，大多数较新的 Linux 发行版都默认使用 Bash 作为 shell。我们可以通过在终端中输入以下命令来轻松识别正在使用的 shell：

```
[philip@localhost Documents]$ echo $SHELL
/bin/bash
[philip@localhost Documents]$
```

太棒了！环境变量`SHELL`存储当前的 shell；返回的值表明我们正在运行 bash shell。另一种识别 shell 的方法如下：

```
[philip@localhost Documents]$ echo $0
bash
[philip@localhost Documents]$
```

太棒了！正在使用 bash shell。此外，我们可以使用`ps`命令来显示当前的 shell，如下所示：

```
[philip@localhost Documents]$ ps
 PID TTY          TIME CMD
 74972 pts/1    00:00:03 bash
 75678 pts/1    00:00:39 dnf
 92796 pts/1    00:00:00 ps
[philip@localhost Documents]$
```

太棒了！对于我们的目的，我们将使用`#!/bin/bash`来编写脚本。要开始编写你的第一个脚本，打开一个文本编辑器，比如 vi 或 nano，然后输入以下内容：

```
philip@localhost Documents]$ vi myFirstScript.sh
```

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00169.jpeg)

太棒了！我们在第一行中有我们的声明；我们定义了`/bin/bash` shell。接下来，我们有两行以`#`符号开头。除了顶部的第一行之外的任何行都被称为注释。也就是说，最后两行是注释。我们可以通过保存我们的脚本来证明这一点；我们可以使用`:wq`，这将保存并退出我们的脚本，如下所示：

```
[philip@localhost Documents]$ cat myFirstScript.sh
#!/bin/bash
#This is a comment
#echo 'This is also a comment'
[philip@localhost Documents]$
```

```
chmod command, as follows:
```

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00170.jpeg)

太棒了！我们使用了`+x`，它为用户、组和其他人打开了执行位；此外，脚本的名称已更改为绿色，表示该文件现在可执行。要运行此脚本，我们使用以下命令：

```
[philip@localhost Documents]$ ./myFirstScript.sh
[philip@localhost Documents]$
```

太棒了！脚本被执行了；但是内容没有显示。这是因为到目前为止我们只定义了注释；在脚本内部还没有定义其他内容。让我们让我们的脚本显示一条简短的消息。使用 vi 或 nano 打开脚本，输入以下内容：

```
[philip@localhost Documents]$ cat myFirstScript.sh
#!/bin/bash
#This is a comment
#echo 'This is also a comment'
echo 'Hello world'
[philip@localhost Documents]$
```

太棒了！我们已经添加了要执行的第一个命令：`echo`命令。这将简单地回复传递的内容，如下所示：

```
[philip@localhost Documents]$ ./myFirstScript.sh
Hello world
[philip@localhost Documents]$
```

太棒了！我们成功地编写了我们的第一个脚本。让我们添加另一个命令，以说明脚本的有效性；我们将添加`date`命令，每次执行脚本时都会提供日期，如下所示：

```
[philip@localhost Documents]$ cat myFirstScript.sh
#!/bin/bash
#This is a comment
#echo 'This is also a comment'
echo 'Hello world'
date
[philip@localhost Documents]$ ./myFirstScript.sh
Hello world
Mon Sep 17 10:04:48 EDT 2018
[philip@localhost Documents]$
```

太棒了！我们现在有两个命令，每次运行脚本时都会执行。除了将输出发送到显示器，我们还可以执行其他任务。例如，我们可以创建一个归档文件；让我们以创建`/home/philip/Downloads`目录的`.tar`文件为例，如下所示：

```
[philip@localhost Documents]$ cat myFirstScript.sh
#!/bin/bash
#This is a comment
#echo 'This is also a comment'
echo 'Hello world'
date
tar -cvf mytar.tar /home/philip/Downloads
[philip@localhost Documents]$
```

在上述代码中，我们使用`tar`命令创建了`/home/philip/Downloads`目录的归档。现在，我们可以运行脚本来查看结果，如下所示：

```
[philip@localhost Documents]$ ./myFirstScript.sh
Hello world
Mon Sep 17 10:35:37 EDT 2018
tar: Removing leading `/' from member names
/home/philip/Downloads/
/home/philip/Downloads/home/
/home/philip/Downloads/home/philip/
/home/philip/Downloads/home/philip/Downloads/
/home/philip/Downloads/home/philip/Downloads/song.mp3
[philip@localhost Documents]$ ls  | grep tar
mytar.tar
[philip@localhost Documents]$
```

太棒了！我们的脚本成功了，并且创建了一个扩展名为`.tar`的归档文件。此外，我们可以创建一个从用户那里获取输入的脚本，使用`read`命令。让我们创建另一个脚本，命名为`input.sh`，使用 vi 或 nano，如下所示：

```
[philip@localhost Documents]$ ls -l input.sh
-rw-rw-r--. 1 philip philip 75 Sep 17 10:42 input.sh
[philip@localhost Documents]$ cat input.sh
#!/bin/bash

echo 'Whats your name?'
read name
echo 'your name is $name'
[philip@localhost Documents]$ chmod +x input.sh
[philip@localhost Documents]$
```

太棒了！我们创建了一个`input.sh`脚本；我们使用`read`命令来存储用户的输入。存储在`name`中的值称为变量。通过在变量名前面加上`$`来显示它在最后一行中。脚本的结果如下所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00171.jpeg)

提示会暂停，直到我们输入内容；我们将输入一个名字并查看结果，如下所示：

```
[philip@localhost Documents]$ ./input.sh
Whats your name?
Philip
your name is: Philip
[philip@localhost Documents]$
```

太棒了！我们输入的名字被添加到了最后一行。我们还可以通过以下语法来定义变量：

```
<variable name> = <value>
```

在上述代码中，我们给变量命名，然后指定一个值。

让我们创建一个名为`myvar.sh`的新脚本，使用 vi 或 nano。以下代码显示了如何使用新脚本定义变量：

```
[philip@localhost Documents]$ vi myvar.sh
[philip@localhost Documents]$ cat myvar.sh
#!/bin/bash

OUR_VAR="Philip Inshanally"

echo "The variable which we defined is $OUR_VAR"
[philip@localhost Documents]$ chmod +x myvar.sh
[philip@localhost Documents]$ ./myvar.sh
The variable which we defined is Philip Inshanally
[philip@localhost Documents]$
```

太棒了！我们定义了一个变量`OUR_VAR`，并给它赋值`Philip Inshanally`；然后在`echo`命令中调用它，通过在变量名前面放置`$`符号。正如你所看到的，有多种定义变量的方式。当单词之间有空格时，变量值需要用括号括起来。如果只有一个单词或数字，就不需要用括号括起来。

不要用括号括住单词或数字。

# 使用 for 循环编写脚本

有时，逐行在脚本中写出每个命令可能会很麻烦。我们可以通过使用循环来实现相同的目标，根据满足的表达式执行命令。`for`循环的基本语法如下：

```
for          <condition>
do
                <command1>
                <command2>
                …
                <commandN>
done
```

第一行定义了一个条件，一旦条件满足，我们就有一系列命令。为了看到这个过程，让我们创建一个脚本，名为`myForLoop.sh`，使用 vi 或 nano：

```
[philip@localhost Documents]$ vi myForLoop.sh
[philip@localhost Documents]$ chmod +x myForLoop.sh
[philip@localhost Documents]$ cat myForLoop.sh
#!/bin/bash
echo 'This script displays how a for loop works'
for o in {1..10}
do
 echo "The loop is running for the: $o time"
done
[philip@localhost Documents]$
```

太棒了！以`for o in {1..10}`开头的行定义了我们想要执行`for`循环的次数；它将被执行 10 次。`do`部分下的命令是将要执行的命令；`$o`是在`for`部分中定义的变量。结果如下：

```
[philip@localhost Documents]$ ./myForLoop.sh
This script displays how a for loop works
The loop is running for the: 1 time
The loop is running for the: 2 time
The loop is running for the: 3 time
The loop is running for the: 4 time
The loop is running for the: 5 time
The loop is running for the: 6 time
The loop is running for the: 7 time
The loop is running for the: 8 time
The loop is running for the: 9 time
The loop is running for the: 10 time
[philip@localhost Documents]$
```

太棒了！这个条件也可以用以下格式来写：

```
[philip@localhost Documents]$ cat myForLoop.sh
#!/bin/bash
echo 'This script displays how a for loop works'
#for o in {1..10}
for p in 1 2 3 4 5 6 7 8 9 10 11 12
do
 echo "The loop is running for the: $p time"
done
[philip@localhost Documents]$
 [philip@localhost Documents]$ ./myForLoop.sh
This script displays how a for loop works
The loop is running for the: 1 time
The loop is running for the: 2 time
The loop is running for the: 3 time
The loop is running for the: 4 time
The loop is running for the: 5 time
The loop is running for the: 6 time
The loop is running for the: 7 time
The loop is running for the: 8 time
The loop is running for the: 9 time
The loop is running for the: 10 time
The loop is running for the: 11 time
The loop is running for the: 12 time
[philip@localhost Documents]$
```

太棒了！我们写下了用空格分隔的值，脚本成功了。我们还可以像 C 编程语言一样，用三个部分指定条件，如下所示：

```
[philip@localhost Documents]$ cat myForLoop.sh
#!/bin/bash

echo 'This script displays how a for loop works'

#for o in {1..10}
#for p in 1 2 3 4 5 6 7 8 9 10 11 12
for ((p=1; p<=6; p++))
do
 echo "The loop is running for the: $p time"
done
[philip@localhost Documents]$
 [philip@localhost Documents]$ ./myForLoop.sh
This script displays how a for loop works
The loop is running for the: 1 time
The loop is running for the: 2 time
The loop is running for the: 3 time
The loop is running for the: 4 time
The loop is running for the: 5 time
The loop is running for the: 6 time
[philip@localhost Documents]$
```

太棒了！在上述代码中，`for ((p=1; p<=6; p++))`行定义了一个变量并为其赋值`p=1;`，`p<=6`检查条件，`p++`表示只要条件满足就递增变量的值。

# 使用 while 循环编写脚本

另一个在脚本中可以使用的流行循环是`while`循环。`while`循环的基本语法如下：

```
while <condition>
do
                <command1>
                <command2>
                …
                <commandN>
done
```

在上述代码中，我们指定一个条件，只要条件满足，循环就会被执行。

使用 vi 或 nano 创建一个名为`myWhile.sh`的脚本，如下所示：

```
[philip@localhost Documents]$ vi myWhile.sh
[philip@localhost Documents]$ chmod +x myWhile.sh
[philip@localhost Documents]$ cat myWhile.sh
#!/bin/bash

d=1

while (( $d <= 8 ))
do
 echo "The number is $d times"
 d=$(( d+1 ))
done
[philip@localhost Documents]$
```

太棒了！首先，我们定义了一个变量，`d=1`，然后我们指定了一个条件，`(( $d <= 8 ))`，它检查变量`d`是否小于或等于`8`；随后，我们使用`echo`命令根据条件提供文本。最后一部分，`d=$(( d+1 ))`，将在满足每个条件后递增变量，如下所示：

```
[philip@localhost Documents]$ ./myWhile.sh
The number is 1 times
The number is 2 times
The number is 3 times
The number is 4 times
The number is 5 times
The number is 6 times
The number is 7 times
The number is 8 times
[philip@localhost Documents]$
```

太棒了！用于条件的另一种技术是在`while`语句之后使用`:`。`:`将始终为`True`；这意味着循环直到我们使用*Ctrl* + *C*结束脚本才会结束。让我们使用 vi 或 nano 创建另一个名为`infinite.sh`的脚本，如下所示：

```
[philip@localhost Documents]$ vi infinite.sh
[philip@localhost Documents]$ chmod +x infinite.sh
[philip@localhost Documents]$ cat infinite.sh
#!/bin/bash
while :
do
 echo "You can enter text and press Enter as many times (exit using CTRL+c)"
 read someText
 echo "You typed $someText"
done
[philip@localhost Documents]$
```

会出现提示，允许我们输入任何内容；一旦我们按下*Enter*键，将显示另一条消息，包括我们输入的任何内容。这将无限继续，直到我们使用*Ctrl* + *C*退出脚本，如下所示：

```
[philip@localhost Documents]$ ./infinite.sh
You can enter text and press Enter as many times (exit using CTRL+c)
Hi 
You typed Hi
You can enter text and press Enter as many times (exit using CTRL+c)
How are you?
You typed How are you?
You can enter text and press Enter as many times (exit using CTRL+c)
I can keep typing
You typed I can keep typing
You can enter text and press Enter as many times (exit using CTRL+c)
and typing 
You typed and typing
You can enter text and press Enter as many times (exit using CTRL+c)
I can exit by using the keystroke as shown in the message above
You typed I can exit by using the keystroke as shown in the message above
You can enter text and press Enter as many times (exit using CTRL+c)
^C
[philip@localhost Documents]$
```

太棒了！脚本直到我们使用*Ctrl* + *C*组合键才退出。展示`while`循环有效性的另一种方法是在脚本退出前查找一个字符串。使用 vi 或 nano 创建另一个名为`whileString.sh`的脚本，如下所示：

```
[philip@localhost Documents]$ vi whileString.sh
[philip@localhost Documents]$ chmod +x whileString.sh
[philip@localhost Documents]$ cat whileString.sh
#!/bin/bash
someString=begin
while [ "$someString" != "quit" ]
do
 echo "Enter some text (type quit to exit)"
 read someString
 echo "You entered: $someString"
done
[philip@localhost Documents]$
```

太棒了！我们声明了一个变量，`someString=begin`；这可以是您选择的任何值。接下来，我们检查了一个条件，`[ "$someString" != "quit" ]`，它寻找`quit`字符串。只要字符串不是`quit`，脚本将无限运行，直到我们输入`quit`或按下*Ctrl* + *C*退出脚本，如下所示：

```
[philip@localhost Documents]$ ./whileString.sh
Enter some text (type quit to exit)
Hi
You entered: Hi
Enter some text (type quit to exit)
my name is Philip
You entered: my name is Philip
Enter some text (type quit to exit)
How are you
You entered: How are you
Enter some text (type quit to exit)
quit
You entered: quit
[philip@localhost Documents]$
```

太棒了！我们可以继续输入文本，脚本将继续运行，除非我们输入 quit 或按下*Ctrl* + *C*，这将退出脚本。

请注意，我们使用方括号([])括住文本；当测试字符串值时，脚本将无法使用常规括号(())。

# 使用 if 语句编写脚本

我们可以在脚本中使用`if`语句来测试条件。`if`语句的基本语法如下：

```
if [some condition]; then
                execute something
fi
or
if [[some condition]]; then
                execute something
fi
```

我们可以创建一个简单的`if`脚本，使用上述代码作为指导。有时，我们可能需要使用双方括号，它们比旧的单方括号样式提供了增强功能。让我们使用 vi 或 nano 创建一个名为`myif.sh`的脚本，如下所示：

```
[philip@localhost Documents]$ vi myif.sh
[philip@localhost Documents]$ cat myif.sh
#!/bin/bash

echo "Welcome to our if statement script"
if [[ $1 == 4 ]]; then
 echo "You're very smart"
fi
echo "See you soon!"
[philip@localhost Documents]$ chmod +x myif.sh
[philip@localhost Documents]$ ./myif.sh
Welcome to our if statement script
See you soon!
[philip@localhost Documents]$
```

我们使用`echo`命令显示欢迎消息；然后我们使用`if [[ $1 == 4 ]]; then`；此语句正在检查`4`。脚本被执行；但是我们没有看到`if`语句内的`echo`命令被执行。为了看到`if`语句内的消息，我们必须在运行脚本时输入一个值，如下所示：

```
[philip@localhost Documents]$ ./myif.sh 4
Welcome to our if statement script
You're very smart
See you soon!
[philip@localhost Documents]$
```

太棒了；`if`结构内的语句被执行，但是，如果我们传递的值不是`4`，我们将看到以下内容：

```
[philip@localhost Documents]$ ./myif.sh 3
Welcome to our if statement script
See you soon!
[philip@localhost Documents]$
```

由于我们传递的值不等于被检查的值，`if`语句内的命令没有被执行。我们可以在`if`语句中添加另一个部分来处理另一个响应；我们可以使用`else`子句。以下是注入到`if`语句中的`else`子句的语法：

```
if [[some condition]]; then
                execute something
else
                execute something else
fi
```

我们可以使用 vi 或 nano 编辑我们的`my.sh`脚本，并添加一个`else`子句来处理任何其他响应，如下所示：

```
[philip@localhost Documents]$ vi myif.sh
[philip@localhost Documents]$ cat myif.sh
#!/bin/bash
echo "Welcome to our if statement script"
if [[ $1 == 4 ]]; then
 echo "You're very smart"
else
 echo " Better luck next time"
fi
echo "See you soon!"
[philip@localhost Documents]$
```

太棒了！我们可以运行注入了`else`子句的脚本，结果如下：

```
[philip@localhost Documents]$ ./myif.sh 3
Welcome to our if statement script
Better luck next time
See you soon!
[philip@localhost Documents]$ ./myif.sh 2
Welcome to our if statement script
Better luck next time
See you soon!
[philip@localhost Documents]$ ./myif.sh 4
Welcome to our if statement script
You're very smart
See you soon!
[philip@localhost Documents]$
```

太棒了！当用户输入除`4`以外的值时，我们会看到不同的消息。此外，我们可以在另一个`if`语句中嵌套一个`if`语句。嵌套`if`语句的基本语法如下：

```
if [[first condition]]; then
execute something
elif [[second condition]]; then
                execute something else
 elif [[third condition]]; then
                execute something else
else
                execute_a_last_resort_command
fi
```

我们可以编辑我们的`myif.sh`脚本，使用 vi 或 nano，并添加第二个`elif`语句，如下所示：

```
[philip@localhost Documents]$ cat myif.sh
#!/bin/bash
echo "Welcome to our if statement script"
if [[ $1 == 4 ]]; then
 echo "You're very smart"
elif [[ $1 == 2 ]]; then
 echo "You've got your elseif value correct!"
else
 echo "Reach for the sky"
fi
echo "See you soon!"
[philip@localhost Documents]$
```

我们已经添加了`elif [[ $1 == 2 ]]; then`，它检查值`2`。一旦满足此条件，将显示一条消息，如下所示：

```
[philip@localhost Documents]$ ./myif.sh 2
Welcome to our if statement script
You've got your elseif value correct!
See you soon!
[philip@localhost Documents]$ ./myif.sh 3
Welcome to our if statement script
Reach for the sky
See you soon!
[philip@localhost Documents]$ ./myif.sh 4
Welcome to our if statement script
You're very smart
See you soon!
[philip@localhost Documents]$
```

太棒了！我们可以看到当我们输入与`elif`条件匹配的值时，`elif`条件下的命令将被执行。此外，当我们输入与`if`或`elif`条件都不匹配的值时，将显示一个全捕获消息。

还可以在单个`if`语句或`elif`语句上测试多个条件。让我们使用 vi 或 nano 编辑我们的`myif.sh`，如下所示：

```
[philip@localhost Documents]$ cat myif.sh
#!/bin/bash
echo "Welcome to our if statement script"
if [[ $1 == 4 ]] || [[ $1 == 3 ]] ; then
 echo "You're very smart"
elif [[ $1 == 2 ]]; then
 echo "You've got your elseif value correct!"
else
 echo "Reach for the sky"
fi
echo "See you soon!"
[philip@localhost Documents]$
```

在上述代码中，我们在`if`语句中添加了第二个条件；即`if [[ $1 == 4 ]] || [[ $1 == 3 ]] ; then`。`||`表示*或*。这是检查是否满足任一条件，并且命令将在`if`语句下执行，如下所示：

```
[philip@localhost Documents]$ ./myif.sh 4
Welcome to our if statement script
You're very smart
See you soon!
[philip@localhost Documents]$ ./myif.sh 3
Welcome to our if statement script
You're very smart
See you soon!
 [philip@localhost Documents]$
```

太棒了！一旦`if`子句中满足任一条件，命令就会在`if`子句下执行。此外，还有`&&`命令，用于比较条件；这意味着必须满足两个条件。我们可以快速编辑我们的`myif.sh`脚本，并添加`&&`，如下所示：

```
[philip@localhost Documents]$ cat myif.sh
#!/bin/bash
echo "Welcome to our if statement script"
if [[ $1 == 4 ]] || [[ $1 == 3 ]] ; then
 echo "You're very smart"
elif [[ $1 == 2 ]] && [[ $1 != 1 ]] ; then
 echo "You've got your elseif value correct!"
else
 echo "Reach for the sky"
fi
echo "See you soon!"
[philip@localhost Documents]$
```

当用户输入`2`时，将满足`elif`条件；这是因为两个条件都需要为真。如果用户输入除`2`以外的任何值，将执行全捕获`else`子句，如下所示：

```
[philip@localhost Documents]$ ./myif.sh 1
Welcome to our if statement script
Reach for the sky
See you soon!
[philip@localhost Documents]$ ./myif.sh 2
Welcome to our if statement script
You've got your elseif value correct!
See you soon!
[philip@localhost Documents]$
```

太棒了！`elif`子句中满足了两个条件，导致命令在`elif`子句下执行。

# SQL 数据管理

**结构化查询语言**（**SQL**）是用于数据库操作的一种广为人知的语言。有各种版本的 SQL。我们将使用 MySQL 的开放标准：`mysql-community-server`软件包。首先，我们需要在我们的 Fedora 28 系统中安装 MySQL `YUM`存储库；我们将使用`dnf`命令，如下所示：

```
[philip@localhost Documents]$ sudo dnf install https://dev.mysql.com/get/mysql80-community-release-fc28-1.noarch.rpm
==========================================================================================================================
 Package       Arch  Version    Repository                   Size
==========================================================================================================================
Installing:
mysql80-community-release    noarch  fc28-1       @commandline                 30 k

Transaction Summary
==========================================================================================================================
Install  1 Package
Total size: 30 k
Installed size: 29 k
Is this ok [y/N]: y
Installed:
mysql80-community-release.noarch fc28-1                                                                                
Complete!
[philip@localhost Documents]$
```

太棒了！存储库已成功安装。现在，我们将安装服务器，如下所示：

```
[philip@localhost Documents]$ sudo dnf install mysql-community-server
MySQL 8.0 Community Server                                                                302 kB/s | 215 kB     00:00 
MySQL Connectors Community                                                                 32 kB/s |  15 kB     00:00 
MySQL Tools Community                                                                      75 kB/s |  28 kB     00:00 

Total download size: 359 M
Installed size: 1.6 G
Is this ok [y/N]: y
```

在上述代码中，为了简洁起见，省略了一些输出。该软件包将占用超过 1GB 的空间；下载所需的时间将根据您的互联网连接而有所不同。进度将如下所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00172.jpeg)

过一段时间，我们将看到以下内容：

```
Installed:
 mysql-community-server.x86_64 8.0.12-1.fc28                 mecab.x86_64 0.996-2.fc28 
 mysql-community-client.x86_64 8.0.12-1.fc28                 mysql-community-common.x86_64 8.0.12-1.fc28 
 mysql-community-libs.x86_64 8.0.12-1.fc28 
Complete!
[philip@localhost Documents]$
```

太棒了！下一步是启用`mysqld`服务；我们将使用`systemctl`命令，如下所示：

```
[philip@localhost Documents]$ sudo systemctl start mysqld
[philip@localhost Documents]$ sudo systemctl enable mysqld
[philip@localhost Documents]$ systemctl status mysqld
```

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00173.jpeg)

太棒了！`mysqld.service`已成功启动。在安装过程中，为`mysql`服务器生成了一个随机的`root`密码；我们必须查看`/var/log/mysqld.log`文件中的内容，如下所示：

```
[philip@localhost Documents]$ grep 'A temporary password is generated for root@localhost' /var/log/mysqld.log |tail -1
2018-09-17T19:25:35.229434Z 5 [Note] [MY-010454] [Server] A temporary password is generated for root@localhost: #a7RCyoyzwOF
[philip@localhost Documents]$
```

`mysql`的`root`的随机密码是`#a7RCyoyzwOF`。最后，我们应该保护我们的`mysql`数据库；我们将使用`mysql_secure_installation`命令，如下所示：

```
[philip@localhost Documents]$ mysql_secure_installation
Securing the MySQL server deployment.
Enter password for user root:
The existing password for the user account root has expired. Please set a new password.
New password:
```

首先，我们必须输入随机密码；然后，我们必须设置一个新密码，如下所示：

```
New password:
Re-enter new password:
The 'validate_password' component is installed on the server.
The subsequent steps will run with the existing configuration
of the component.
Using existing password for root.
Estimated strength of the password: 100
Change the password for root ? ((Press y|Y for Yes, any other key for No) :
```

默认情况下，安装了`validate_password`插件；这设置了密码规范。我们必须输入一个密码，该密码由至少一个大写字符、一个小写字符、一个数字和一个特殊字符组成。总密码长度必须至少为八个字符，如下所示：

```
Do you wish to continue with the password provided?(Press y|Y for Yes, any other key for No) : y
By default, a MySQL installation has an anonymous user,
allowing anyone to log into MySQL without having to have
a user account created for them. This is intended only for
testing, and to make the installation go a bit smoother.
You should remove them before moving into a production
environment.
Remove anonymous users? (Press y|Y for Yes, any other key for No) : y
```

默认情况下，会生成一个匿名用户帐户；我们将选择`y`来删除它并继续：

```
Normally, root should only be allowed to connect from
'localhost'. This ensures that someone cannot guess at
the root password from the network.
Disallow root login remotely? (Press y|Y for Yes, any other key for No) :
```

我们将允许`root`用户远程登录，因此我们将按下一个键，这一步将被跳过，如下所示：

```
 ... skipping.
By default, MySQL comes with a database named 'test' that
anyone can access. This is also intended only for testing,
and should be removed before moving into a production
environment.
Remove test database and access to it? (Press y|Y for Yes, any other key for No) : y
 - Dropping test database...
Success.
 - Removing privileges on test database...
Success.
Reloading the privilege tables will ensure that all changes
made so far will take effect immediately.
Reload privilege tables now? (Press y|Y for Yes, any other key for No) : y
Success.
All done!
[philip@localhost Documents]$
```

与默认安装相比，`mysql`现在更安全了。我们现在可以使用`mysql`命令登录`mysql`数据库，如下所示：

```
[philip@localhost Documents]$ mysql -u root -p
Enter password:
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 21
Server version: 8.0.12 MySQL Community Server - GPL
Copyright (c) 2000, 2018, Oracle and/or its affiliates. All rights reserved.
Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
mysql>
```

太棒了！我们现在将创建我们的第一个数据库；我们将使用`create database`命令：

```
mysql> create database netaccess;
Query OK, 1 row affected (0.10 sec)
mysql>
```

太棒了！我们现在将创建一个可以访问我们数据库的用户；我们将使用`create user`命令：

```
mysql> create user 'philip'@'172.16.175.130' identified by 'password123';
ERROR 1819 (HY000): Your password does not satisfy the current policy requirements
mysql>
```

在上述代码中，密码要求再次未被满足；我们可以通过降低设置或删除`validate_password`组件来解决这个问题。我们将删除`validate_password`组件，如下所示：

```
mysql> uninstall plugin validate_password;
ERROR 1305 (42000): PLUGIN validate_password does not exist
mysql> exit
Bye
[philip@localhost Documents]$ mysql -h localhost -u root -p
Enter password:
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 22
Server version: 8.0.12 MySQL Community Server - GPL
mysql> UNINSTALL COMPONENT 'file://component_validate_password';
Query OK, 0 rows affected (0.10 sec)
mysql> exit
Bye
[philip@localhost Documents]$
```

太棒了！我们使用`UNINSTALL COMPONENT`命令删除了`component_validate_password`。现在，我们可以像之前一样登录并继续：

```
mysql> grant all on netaccess.* to 'philip'@'172.16.175.130';
Query OK, 0 rows affected (0.06 sec)
mysql>
```

太棒了！最后一步是重新加载授权表；我们将使用`flush`命令，如下所示：

```
mysql> flush privileges
 -> ;
Query OK, 0 rows affected (0.00 sec)
mysql>
```

太棒了！当我们离开`;`时，命令没有被执行。我们总是需要以分号（;）结束。现在，我们可以从我们的 Ubuntu 系统通过网络进行测试。我们将不得不在 Ubuntu 18 系统上安装`mysql-client`，如下所示：

```
philip@Linuxplus:~$ mysql
Command 'mysql' not found, but can be installed with:
sudo apt install mysql-client-core-5.7 
sudo apt install mariadb-client-core-10.1
philip@Linuxplus:~$ sudo apt install mysql-client-core-5.7 
[sudo] password for philip:
Reading package lists... Done
Building dependency tree 
Setting up mysql-client-core-5.7 (5.7.23-0ubuntu0.18.04.1) ...
Processing triggers for libc-bin (2.27-3ubuntu1) ...
philip@Linuxplus:~$ mysql -h 172.16.175.129 -u philip -p
Enter password:
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 25
Server version: 8.0.12 MySQL Community Server - GPL
Copyright (c) 2000, 2018, Oracle and/or its affiliates. All rights reserved.
Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
mysql>
```

太棒了！我们成功连接了托管在我们的 Fedora 28 系统上的`mysql`服务器，使用 Ubuntu 18 客户端通过网络。我们现在可以使用各种命令，比如`show databases`命令：

```
mysql> show databases;
+--------------------+
| Database |
+--------------------+
| information_schema |
| netaccess |
+--------------------+
2 rows in set (0.06 sec)
mysql>
```

太棒了！我们可以看到两个数据库：我们之前创建的一个和一个内部数据库。但是，如果我们以 root 用户身份运行此命令，我们将看到所有可用的数据库，如下所示：

```
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| netaccess          |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.00 sec)
mysql>
```

太棒了！查看数据库的另一种方法是使用带有`-e`选项的`mysql`命令；这允许我们从 shell 执行命令。以下代码片段显示了我们如何列出数据库：

```
philip@Linuxplus:~$ mysql -h 172.16.175.129 -u philip -p -e "show databases"
Enter password:
+--------------------+
| Database           |
+--------------------+
| information_schema |
| netaccess          |
+--------------------+
philip@Linuxplus:~$
```

太棒了！接下来，我们可以使用`use`命令切换到指定的数据库。以下代码显示了我们如何指定要使用的数据库：

```
mysql> use netaccess;
Database changed
mysql>
```

我们现在在`netaccess`数据库中。要开始使用数据库，我们必须首先创建一个表；在创建表之前，我们需要知道要创建什么类型的表。例如，假设我们想创建一个关于公共场所的表；我们将希望有一个用于场所名称的字段。如果我们只创建一个带有场所名称的表，那将不太吸引人；我们将希望添加其他方面，比如提供的服务和位置等。正如您所看到的，表可以包含各种选项。首先，我们将使用我们示例中提到的字段；我们将使用`create table`命令，如下所示：

```
mysql> create table Public_Places (name VARCHAR(20), location VARCHAR(30), service_provided VARCHAR(30));
Query OK, 0 rows affected (9.44 sec)
mysql>
```

太棒了！我们成功创建了我们的第一个表。我们可以使用`show tables`命令查看表：

```
mysql> show tables;
+---------------------+
| Tables_in_netaccess |
+---------------------+
| Public_Places       |
+---------------------+
1 row in set (0.11 sec)
mysql>
```

我们可以看到我们的表已列出。我们可以使用`describe`命令查看我们创建的字段。以下代码显示了我们如何使用`describe`命令：

```
mysql> describe Public_Places;
+------------------+-------------+------+-----+---------+-------+
| Field            | Type        | Null | Key | Default | Extra |
+------------------+-------------+------+-----+---------+-------+
| name             | varchar(20) | YES  |     | NULL    |       |
| location         | varchar(30) | YES  |     | NULL    |       |
| service_provided | varchar(30) | YES  |     | NULL    |       |
+------------------+-------------+------+-----+---------+-------+
3 rows in set (0.23 sec)
mysql>
```

太棒了！我们可以看到字段及其类型；`varchar`类型的长度可以是 0 到 65,535 之间的值。目前，表是空的，所以我们必须填充它。

# 插入命令

我们可以使用`insert`命令填充表。基本语法如下：

```
insert into <table> <field(s)><value(s)>
```

我们可以向我们之前创建的表中添加一些信息，如下所示：

```
mysql> insert into Public_Places values('Police Station', 'Capital City', 'serve and protect');
Query OK, 1 row affected (0.17 sec)
mysql>
```

太棒了！我们指定了值并使用`insert`命令传递了这些值，将数据存储在表中。插入数据的另一种方法是只插入部分字段的数据；我们必须指定字段名称以进行选择性插入。以下代码显示了如何将数据插入到表的某些部分：

```
mysql> insert into Public_Places (name, location) values('Telephone Company', 'Georgetown');
Query OK, 1 row affected (0.16 sec)
mysql>
```

太棒了！我们只为两个字段（`name`和`location`）插入了值。插入数据的另一种方法是使用带有`-e`选项的`mysql`命令，如下所示：

```
philip@Linuxplus:~$ mysql -h 172.16.175.129 -u philip -p -e "USE netaccess; INSERT INTO Public_Places values ('Hospital' , 'Georgetown', 'healthcare');"
Enter password:
philip@Linuxplus:~$
```

太棒了！数据已成功输入到表中。

# 选择命令

到目前为止，我们一直在向我们的表中添加内容。但是，我们还没有看到我们添加的值。我们可以使用`select`命令查看表的内容，如下所示：

```
mysql> select * from Public_Places;
+-------------------+--------------+-------------------+
| name              | location     | service_provided  |
+-------------------+--------------+-------------------+
| Police Station    | Capital City | serve and protect |
| Telephone Company | Georgetown   | NULL              |
| Hospital          | Georgetown   | healthcare        |
+-------------------+--------------+-------------------+
3 rows in set (0.00 sec)
mysql>
```

太棒了！我们可以看到我们迄今为止在我们的表中输入的所有值。此外，我们可以通过指定`where`子句执行选择性搜索，如下所示：

```
mysql> select * from Public_Places where name='Telephone Company';
+-------------------+------------+------------------+
| name              | location   | service_provided |
+-------------------+------------+------------------+
| Telephone Company | Georgetown | NULL             |
+-------------------+------------+------------------+
1 row in set (0.00 sec)
mysql>
```

太棒了！我们还可以使用以下方法进行搜索：

```
mysql> select name, service_provided from Public_Places;
+-------------------+-------------------+
| name              | service_provided  |
+-------------------+-------------------+
| Police Station    | serve and protect |
| Telephone Company | NULL              |
| Hospital          | healthcare        |
+-------------------+-------------------+
3 rows in set (0.00 sec)
mysql> select service_provided from Public_Places;
+-------------------+
| service_provided  |
+-------------------+
| serve and protect |
| NULL              |
| healthcare        |
+-------------------+
3 rows in set (0.00 sec)
mysql>
```

太棒了！

# 更新命令

我们可以使用`update`命令对表进行更改，如下所示：

```
mysql> update Public_Places set service_provided='Telephones' where name='Telephone Company';
Query OK, 1 row affected (0.05 sec)
Rows matched: 1  Changed: 1  Warnings: 0
mysql>
```

太棒了！我们已经填写了`Telephone Company`的`service_provided`字段的数据；可以使用`select`命令进行验证，如下所示：

```
mysql> select * from Public_Places;
+-------------------+--------------+-------------------+
| name              | location     | service_provided  |
+-------------------+--------------+-------------------+
| Police Station    | Capital City | serve and protect |
| Telephone Company | Georgetown   | Telephones        |
| Hospital          | Georgetown   | healthcare        |
+-------------------+--------------+-------------------+
3 rows in set (0.00 sec)
mysql>
```

太棒了！我们可以看到`service_provided`字段已经填充。此外，我们可以使用`update`命令更改数据，如下所示：

```
mysql> update Public_Places set location='Kaieteur Falls' where name='Hospital';
Query OK, 1 row affected (0.15 sec)
Rows matched: 1  Changed: 1  Warnings: 0
mysql> select * from Public_Places;
+-------------------+----------------+-------------------+
| name              | location       | service_provided  |
+-------------------+----------------+-------------------+
| Police Station    | Capital City   | serve and protect |
| Telephone Company | Georgetown     | Telephones        |
| Hospital          | Kaieteur Falls | healthcare        |
+-------------------+----------------+-------------------+
3 rows in set (0.00 sec)
mysql> update Public_Places set name='GPF' where name='Police Station';
Query OK, 1 row affected (0.16 sec)The dele
Rows matched: 1  Changed: 1  Warnings: 0
mysql> select * from Public_Places;
+-------------------+----------------+-------------------+
| name              | location       | service_provided  |
+-------------------+----------------+-------------------+
| GPF               | Capital City   | serve and protect |
| Telephone Company | Georgetown     | Telephones        |
| Hospital          | Kaieteur Falls | healthcare        |
+-------------------+----------------+-------------------+
3 rows in set (0.00 sec)
mysql>
```

太棒了！

# 删除命令

我们可以使用`delete`命令从表的字段中删除值，如下所示：

```
mysql> delete from Public_Places where name='Hospital';
Query OK, 1 row affected (0.18 sec)
mysql> select * from Public_Places;
+-------------------+--------------+-------------------+
| name              | location     | service_provided  |
+-------------------+--------------+-------------------+
| GPF               | Capital City | serve and protect |
| Telephone Company | Georgetown   | Telephones        |
+-------------------+--------------+-------------------+
2 rows in set (0.01 sec)
mysql>
```

太棒了！使用`delete`命令指定的字段已被删除。

# from 选项

我们可以使用`from`选项来指定要使用的表；例如，如果我们指定一个不存在的表，我们将看到以下消息：

```
mysql> select * from myTable;
ERROR 1146 (42S02): Table 'netaccess.myTable' doesn't exist
mysql>
```

表不存在，因此在执行查询时，我们必须使用`from`选项输入正确的表。

# where 条件

当我们想要执行一些选择性操作时，我们可以使用`where`条件。我们之前使用过`select`，`update`和`delete`命令的`where`条件。作为提醒，我们可以如下使用`where`条件：

```
mysql> select * from Public_Places where name='GPF';
+------+--------------+-------------------+
| name | location     | service_provided  |
+------+--------------+-------------------+
| GPF  | Capital City | serve and protect |
+------+--------------+-------------------+
1 row in set (0.00 sec)
mysql>
```

太棒了！只显示符合条件的结果。

# group by 选项

我们可以使用`group by`选项根据我们指定的条件提供结果，如下所示：

```
mysql> select name from Public_Places group by name;
+-------------------+
| name              |
+-------------------+
| GPF               |
| Telephone Company |
+-------------------+
2 rows in set (0.02 sec)
mysql>
```

太棒了！结果根据指定的条件进行分组。当我们有包含数字的表时，这是非常有用的，例如客户 ID，员工 ID 和订单等。

# order by 选项

我们可以使用`order by`选项按升序或降序对表中的数据进行排序。以下代码显示了如何使用`order by`选项：

```
mysql> select * from Public_Places order by service_provided;
+-------------------+--------------+-------------------+
| name              | location     | service_provided  |
+-------------------+--------------+-------------------+
| GPF               | Capital City | serve and protect |
| Telephone Company | Georgetown   | Telephones        |
+-------------------+--------------+-------------------+
2 rows in set (0.02 sec)
mysql>
```

根据默认设置，数据按升序排序；但是，我们可以通过传递`DESC`关键字以降序显示结果，如下所示：

```
mysql> select * from Public_Places order by service_provided DESC;
+-------------------+--------------+-------------------+
| name              | location     | service_provided  |
+-------------------+--------------+-------------------+
| Telephone Company | Georgetown   | Telephones        |
| GPF               | Capital City | serve and protect |
+-------------------+--------------+-------------------+
2 rows in set (0.00 sec)
mysql>
```

太棒了！结果以降序显示。

# 连接选项

我们可以通过传递`join`选项来使用简单的连接；这可以用于合并来自不同表的行，以查看表之间的共同因素。我创建了两个表，如下所示：

```
mysql> select * from Cust;
+--------+-------------------------+--------------------+
| custID | custName                | location           |
+--------+-------------------------+--------------------+
|      1 | Philip Inshanally       | Georgetown, Guyana |
|      2 | Matthew Zach Inshanally | Georgetown, Guyana |
+--------+-------------------------+--------------------+
2 rows in set (0.03 sec)
mysql> select * from Purchase;
+---------+------------+-----------+
| orderID | purchaseID | orderDate |
+---------+------------+-----------+
|       2 |   20150202 | 201800902 |
|       1 |   10031984 |  20180310 |
+---------+------------+-----------+
2 rows in set (0.00 sec)
mysql>
```

相同的列是每个表的第一列；`Cust`表将其称为`custID`，而`Purchase`表将其称为 ordered。基于此，我们可以创建一个选择查询，将两个表合并，如下所示：

```
mysql> SELECT Purchase.orderID, Cust.custName, Purchase.orderDate FROM Purchase INNER JOIN Cust ON Purchase.orderID=Cust.custID;
+---------+-------------------------+-----------+
| orderID | custName                | orderDate |
+---------+-------------------------+-----------+
|       1 | Philip Inshanally       |  20180310 |
|       2 | Matthew Zach Inshanally | 201800902 |
+---------+-------------------------+-----------+
2 rows in set (0.01 sec)
mysql>
```

太棒了！我们通过在`Purchase.orderID`，`Cust.custName`，`Purchase.orderDate`前放置表的名称来引用字段；这定义了表的呈现方式。

接下来的部分，`FROM Purchase INNER JOIN Cust ON Purchase.orderID=Cust.custID;`，定义了内容将来自`Purchase`表，并且将使用`Purchase.orderID=Cust.custID`的共同列进行连接，从而产生包含来自两个表的数据的结果。

这被称为内部连接；它返回在两个表中具有匹配值的数据。

# 总结

在本章中，我们学习了 shell 脚本和 SQL 管理。首先，我们介绍了 shell 脚本的基础知识。接下来，我们通过使用`for`循环编写脚本。然后，我们使用了`while`循环。最后，我们在脚本中使用了`if`语句。

接下来，我们使用了 SQL 管理。首先，我们安装了 MySQL 存储库，然后安装了 MySQL 的社区服务器版本。然后，我们对我们的`mysql`服务器进行了安全设置。然后，我们开始创建数据库，然后创建表。然后，我们开始使用各种技术管理表中的数据；最后，我们创建了额外的表，以演示内部连接。

我很高兴编写了这本书中的每一章。我相信您在职业生涯中会从这本书中学到很多。感谢您选择这本书并将其收入您的收藏。下次再见，我是 Philip Inshanally，提醒您要时刻心存感激。很快再见！

# 问题

1.  哪些字符标识了定义解释器的行的开头？

A. `＃$`

B. `＃@`

C. `＃！`

D. `＃^`

1.  以下哪个环境变量存储当前的 shell？

A. `SHELL`

B. `BASH`

C. `SH`

D. `TCSH`

1.  以下哪个关键字结束了`for`循环？

A. `do`

B. `do 循环`

C. `完成`

D. `fi`

1.  如果脚本位于当前目录中，需要在`/`前面放置哪个字符才能运行脚本？

A. `.`

B. `：`

C. `;`

D. `“`

1.  以下哪个命令可以创建一个变量来存储用户的输入？

A. `执行`

B. `暂停`

C. `写入`

D. `读取`

1.  以下哪个字符可以用来测试两个条件，并在任一条件为真时返回`TRUE`？

A. `&&`

B. `||`

C. `//`

D. `==`

1.  在使用`select`命令执行`mysql`查询时，以下哪个字符用作通配符？

A. `+`

B. `/`

C. `*`

D. `-`

1.  在使用`select`命令时，以下哪个选项用于检查条件？

A. `来自`

B. `if`

C. `where`

D. `连接`

1.  以下哪个命令将使用 mysql 创建一个表？

A. `创建表`

B. `创建表`

C. `创建表`

D. `创建表`

1.  以下哪个命令可以用于使用`mysql`更改值？

A. `插入`

B. `删除`

C. `更新`

D. `连接`

# 进一步阅读

+   以下网站提供有关 shell 脚本的有用信息：[`www.shellscript.sh`](https://www.shellscript.sh)

+   以下网站提供有关循环的有用信息：[`www.tutorialspoint.com`](https://www.tutorialspoint.com)

+   以下网站提供有关 mysql 的有用信息：[`www.w3schools.com`](https://www.w3schools.com)
