# CompTIA Linux 认证指南（五）

> 原文：[`zh.annas-archive.org/md5/1D0BEDF2E9AB87F7188D92631B85ED3E`](https://zh.annas-archive.org/md5/1D0BEDF2E9AB87F7188D92631B85ED3E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：管理用户和组帐户

在上一章中，我们介绍了显示管理器。我们涉及了 XDM、KDM、GDM 和 Lightdm。我们确定了显示管理器和桌面之间的区别。我们首先在 CentOS 系统中使用 XDM。接下来，我们将注意力转移到 KDM。在此之后，GDM 成为我们议程的下一个内容。此外，我们还介绍了在其中安装一些桌面。最后，我们介绍了 Lightdm。使用 Fedora 28 发行版，重点介绍了使 Lightdm 运行起来的技术。上一章的重点是安装各种显示管理器和在它们之间切换的过程。

在本章中，主题将是用户和组帐户。到目前为止，我们已经涵盖了 Linux 环境中的许多关键领域。我们的重点从管理用户帐户的过程开始；诸如用户创建和删除、目录修改、设置密码、权限和所有权等内容将是重点。在此之后，我们将进入分组的范围；我们将深入探讨用于管理组的技术。将涵盖创建和删除组、将用户分配给组、权限等内容。我鼓励您再次加入我，以便更好地管理用户和组。

我们将在本章中涵盖以下主题：

+   创建新用户时使用的目录

+   管理用户帐户

+   管理组

# 创建新用户时使用的目录

每次我们在系统中使用`useradd`命令创建新用户时，都会发生一系列事件。首先，存在一种结构，用于生成新用户的目录。该结构存储在骨架目录中；这位于`/etc/skel`目录中。`/etc/skel`目录包含文件和文件夹，这些文件和文件夹将被复制到新用户的主目录中。我们可以使用我们的 Ubuntu 系统查看骨架目录：

```
root@ubuntu:/home/philip# ls -a /etc/skel/
.  ..  .bash_logout  .bashrc  examples.desktop  .profile
root@ubuntu:/home/philip#
```

每个新用户都从这里拉取其结构。点（`.`）表示隐藏文件。文件如`/etc/skel/.logout`、`/etc/.skel/.bashrc`和`/etc/skel/.profile`。

# The .bash_logout

请注意，`.bash_history`是存储注销期间执行的命令的地方。它只是清除屏幕以确保注销时的隐私。这可以在以下命令中看到：

```
root@ubuntu:/home/philip# cat /home/philip/.bash_logout
# ~/.bash_logout: executed by bash(1) when login shell exits.
# when leaving the console clear the screen to increase privacy
if [ "$SHLVL" = 1 ]; then
 [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q
fi
root@ubuntu:/home/philip#
```

# The .bashrc

`/etc/skel/.bashrc`通常用于存储各种别名。通过查看`/etc/skel/.bashrc`可以看到这一点：

```
root@ubuntu:/home/philip# cat /etc/skel/.bashrc
# colored GCC warnings and errors
#export GCC_COLORS='error=01;31:warning=01;35:note=01;36:caret=01;32:locus=01:quote=01'
# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
root@ubuntu:/home/philip#
```

为了简洁起见，一些输出已被省略。根据前面的输出，我们已经为我们定义了一些别名；其中一个例子是`alias ll='ls -af'`。

# The .profile

让我们将`/etc/skel/.profile`视为它执行了许多任务的文件；其中之一是检查`$Home/.bashrc`的存在。通过查看`/etc/skel/.profile`可以看到这一点：

```
root@ubuntu:/home/philip# cat /etc/skel/.profile
#umask 022
# if running bash
if [ -n "$BASH_VERSION" ]; then
 # include .bashrc if it exists
 if [ -f "$HOME/.bashrc" ]; then
 . "$HOME/.bashrc"
 fi
fi
# set PATH so it includes user's private bin directories
PATH="$HOME/bin:$HOME/.local/bin:$PATH"
root@ubuntu:/home/philip#
```

为了简洁起见，一些输出已被省略。根据前面的输出，我们可以看到`#if running bash`部分。另一种看到这些目录确实被复制过来的方法是查看现有用户。我们将使用`ls`命令结合`egrep`命令：

```
root@ubuntu:/home/philip# ls -a ~ | egrep '.bash|.profile'
.bash_history
.bashrc
.profile
root@ubuntu:/home/philip#
```

干得好！根据前面的输出，我们可以看到`.bash_history`、`.bashrc`和`.profile`。

# The .bash_history

在命令提示符下执行的每个命令都存储在`.bash_history`中。此外，`.bash_history`只有在我们开始在命令提示符下运行命令后才会创建。以下是对`/home/philip/.bash_history`的简要查看：

```
root@ubuntu:/home/philip# cat /home/philip/.bash_history
ls /etc/grub.d/
cat /var/log/Xorg.0.log | less
startx
sudo su
Xorg -configure
rm /tmp/.X0-lock
sudo su
su
sudo su
root@ubuntu:/home/philip#
```

为了简洁起见，一些输出已被省略。

此外，我们可以检查另一个用户是否存在各种`.bash`文件：

```
root@ubuntu:/home/philip# ls -a /home/philip | egrep '.bash|.profile'
.bash_history
.bash_logout
.bashrc
.profile
root@ubuntu:/home/philip#
```

干得好！我们可以看到`.bash_history`、`.bash_logout`、`.bashrc`和`.profile`。

另一种识别在使用`useradd`命令创建新用户时是否使用`/etc/skel`目录的方法是调用`useradd`命令并传递`-D`选项：

```
root@ubuntu:/home/philip# useradd -D
GROUP=100
HOME=/home
INACTIVE=-1
EXPIRE=
SHELL=/bin/sh
SKEL=/etc/skel
CREATE_MAIL_SPOOL=no
root@ubuntu:/home/philip#
```

根据前面的输出，我们得到了大量信息。特别是，`SKEL=/etc/skel`指示创建新用户时要使用的目录。

# 管理用户帐户

到目前为止，在前面的章节中，我们使用了两个用户帐户；一个是标准用户，另一个是 root 用户。在 Linux 中，我们可以通过 GUI 实用程序或命令行创建用户帐户。在 shell 中，我们使用`useradd`命令来创建新用户帐户。在较新的发行版中，还有`adduser`命令。在某些发行版中，如 CentOS，`adduser`是一个符号链接。可以在这里看到：

```
[root@localhost philip]# ll /usr/sbin/adduser
lrwxrwxrwx. 1 root root 7 Jun 20 09:19 /usr/sbin/adduser -> useradd
[root@localhost philip]#
```

在 Ubuntu 上，`adduser`命令与`useradd`命令是分开的：

```
root@ubuntu:/home/philip# ll /usr/sbin/adduser
-rwxr-xr-x 1 root root 37276 Jul  2  2015 /usr/sbin/adduser*
root@ubuntu:/home/philip#
```

使用`useradd`命令的基本语法是`useradd <option> username`。默认情况下，标准用户无法创建用户帐户。可以在这里看到：

```
philip@ubuntu:~$ useradd tom
useradd: Permission denied.
useradd: cannot lock /etc/passwd; try again later.
philip@ubuntu:~$
```

根据前面的输出，我们收到了`Permission denied`的消息。

默认情况下，标准用户无法创建用户帐户。

创建新用户时，我们将继续使用 root 用户。我们将在第十七章 *执行安全管理任务*中介绍使用`sudoers`文件管理权限。这里是使用 root 用户：

```
root@ubuntu:/home/philip# useradd tom
root@ubuntu:/home/philip#
```

根据前面的输出，我们没有得到任何指示来验证新用户是否已创建。请放心，我们可以通过查看`/home`目录来确认：

```
root@ubuntu:/home/philip# cat /etc/passwd
rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false
saned:x:119:127::/var/lib/saned:/bin/false
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
philip:x:1000:1000:philip,,,:/home/philip:/bin/bash
gdm:x:121:129:Gnome Display Manager:/var/lib/gdm3:/bin/false
geoclue:x:122:130::/var/lib/geoclue:/bin/false
tom:x:1001:1001::/home/tom:
root@ubuntu:/home/philip#
```

为了简洁起见，已省略了一些输出。最后一个条目显示了新用户的信息。我们读取这些信息的方式如下：

```
tom=user
x=password placeholder
1001=UID
1001=GID
/home/tome=home directory for Tom
```

但是，如果我们比较另一个用户的条目，我们会得到这个：

```
 philip:x:1000:1000:philip,,,:/home/philip:/bin/bash
```

根据前面的输出，最后的`:/bin/bash`部分定义了用户的 shell。我们创建的用户没有分配 shell。此外，我们需要为用户设置密码。为了设置密码，我们将使用`passwd`命令：

```
root@ubuntu:/home/philip# passwd tom
Enter new UNIX password:
Retype new UNIX password:
passwd: password updated successfully
root@ubuntu:/home/philip#
```

干得漂亮！现在，让我们注销并尝试使用`tom`账户登录：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00138.jpeg)

干得漂亮！我们可以看到新用户出现了，但当我们尝试登录时，系统会将我们弹出，因为我们已为用户定义了一个 shell。让我们通过删除用户并再次添加用户来解决这个问题。我们将使用`userdel`命令删除用户：

```
root@ubuntu:/home/philip# userdel -r tom
userdel: tom mail spool (/var/mail/tom) not found
userdel: tom home directory (/home/tom) not found
root@ubuntu:/home/philip#
root@ubuntu:/home/philip# cat /etc/passwd
philip:x:1000:1000:philip,,,:/home/philip:/bin/bash
gdm:x:121:129:Gnome Display Manager:/var/lib/gdm3:/bin/false
geoclue:x:122:130::/var/lib/geoclue:/bin/false
root@ubuntu:/home/philip#
```

太棒了！现在，让我们创建用户并传递`-s`选项。这将为用户定义一个 shell，以便与`useradd`命令一起使用：

```
root@ubuntu:/home/philip# useradd -s /bin/bash tom
root@ubuntu:/home/philip# cat /etc/passwd:
philip:x:1000:1000:philip,,,:/home/philip:/bin/bash
gdm:x:121:129:Gnome Display Manager:/var/lib/gdm3:/bin/false
geoclue:x:122:130::/var/lib/geoclue:/bin/false
tom:x:1001:1001::/home/tom:/bin/bash
root@ubuntu:/home/philip#
```

干得漂亮！现在我们可以看到在最后一个条目中，用户`tom`已被分配了`/bin/bash` shell。`/etc/passwd`的另一个有趣部分是每个帐户中的`x`。

我们说它代表密码，但我们并没有将`x`设置为密码，那么`x`是什么意思呢？嗯，`x`只是表示密码已加密；它实际上存储在一个单独的位置。`/etc/shadow`目录存储密码。我们可以查看`/etc/shadow`目录以供参考：

```
root@ubuntu:/home/philip# passwd tom
Enter new UNIX password:
Retype new UNIX password:
passwd: password updated successfully
root@ubuntu:/home/philip#
root@ubuntu:/home/philip# cat /etc/shadow
messagebus:*:16911:0:99999:7:::
uuidd:*:16911:0:99999:7:::
lightdm:*:16911:0:99999:7:::
whoopsie:*:16911:0:99999:7:::
avahi-autoipd:*:16911:0:99999:7:::
avahi:*:16911:0:99999:7:::
dnsmasq:*:16911:0:99999:7:::
colord:*:16911:0:99999:7:::
gdm:*:17770:0:99999:7:::
geoclue:*:17770:0:99999:7:::
tom:!:17778:0:99999:7:::
root@ubuntu:/home/philip#
```

为了简洁起见，已省略了一些输出。根据前面的输出，我们可以看到每个帐户的实际加密密码。

# chage 命令

关于用户帐户的另一个有趣方面涉及密码的过期时间；密码的过期时间。我们可以使用`chage`命令查看给定用户的过期时间。让我们为用户`tom`创建一个密码，然后检查新用户的密码过期设置：

更改密码过期参数需要 root 权限。

```
root@ubuntu:/home/philip# passwd tom
Enter new UNIX password:
Retype new UNIX password:
passwd: password updated successfully
root@ubuntu:/home/philip#
```

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00139.jpeg)

太棒了！根据前面的输出，我们使用了`-l`选项来显示过期设置；我们可以看到一些有价值的信息，特别是`上次密码更改`、`密码过期`和`帐户过期`。我们可以通过传递各种选项来更改这些值。例如，让我们更改`帐户过期`。我们使用`-E`选项：

```
root@ubuntu:/home/philip# chage -E 2018-09-04 tom
root@ubuntu:/home/philip# chage -l tom
Last password change                                                                : Sep 04, 2018
Password expires                                                                    : never
Password inactive                                                                   : never
Account expires                                                                     : Sep 04, 2018
Minimum number of days between password change                                       : 0
Maximum number of days between password change                                      : 99999
Number of days of warning before password expires                                   : 7
root@ubuntu:/home/philip#
```

干得漂亮！根据前面的输出，我们已将帐户设置为在此演示的当前时间到期。现在，为了查看此更改的效果，我们将打开另一个终端并尝试以用户`tom`的身份登录：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00140.jpeg)

干得好！根据前面的输出，我们看到了尝试以用户`tom`的身份登录时返回的消息。要删除用户`tom`的此过期时间，我们将使用`-1`作为值：

```
root@ubuntu:/home/philip# chage -E -1 tom
root@ubuntu:/home/philip# chage -l tom
Last password change                                                                : Sep 04, 2018
Password expires                                                                    : never
Password inactive                                                                   : never
Account  expires                                                                    : never
Minimum number of days between password change                                      : 0
Maximum number of days between password change                                      : 99999
Number of days of warning before password expires                                   : 7
root@ubuntu:/home/philip#
```

现在，我们将能够以用户`tom`的身份登录：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00141.jpeg)

太棒了！根据前面的内容，我们可以看到使用`chage`命令的有效性。要查看可以与`chage`命令一起传递的可用选项，我们可以执行：

```
root@ubuntu:/home/philip# chage
```

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00142.jpeg)

# usermod 命令

我们之前看到，要进行任何更改，我们必须使用`useradd`命令删除用户。每次我们决定更改时，这可能会很麻烦；相反，我们可以利用另一个强大的命令：`usermod`命令。`usermod`命令的基本语法如下：

```
usermod <option> username
```

使用我们的测试用户`tom`，我们可以使用`usermod`命令更改许多参数。例如，我们可以锁定用户`tom`的帐户，这将阻止用户`tom`登录系统。要锁定帐户，我们将使用`-L`选项：

```
root@ubuntu:/home/philip# cat /etc/passwd
philip:x:1000:1000:philip,,,:/home/philip:/bin/bash
gdm:x:121:129:Gnome Display Manager:/var/lib/gdm3:/bin/false
geoclue:x:122:130::/var/lib/geoclue:/bin/false
tom:x:1001:1001::/home/tom:
root@ubuntu:/home/philip# usermod -L tom
root@ubuntu:/home/philip#
```

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00143.jpeg)

干得好！根据前面的输出，用户`tom`无法登录。值得注意的是，在`/etc/shadow`中用户`tom`的条目显示在第二个字段的密码前面有`!`，这表示密码：

```
root@ubuntu:/home/philip# cat /etc/shadow | grep tom
tom:!$6$uJ52BA2n$SWGisIpNTTOSygIX6swWdkS/gLPGZacEzCz2Ht6qfUHIr7ZIxkJyUjEyqN9ncb1yIFIXYnePz4HVzrwqJA1DZ0:17778:0:99999:7:::
root@ubuntu:
 root@ubuntu:/home/philip# cat /etc/shadow | grep philip
philip:$1$8gQrKziP$v6Uv6
root@ubuntu:/home/philip#
```

根据前面的内容，用户`philip`的密码前面没有`!`。验证帐户是否已锁定的另一种方法是使用`passwd`命令。我们传递`--status`选项：

```
root@ubuntu:/home/philip# passwd --status tom
tom L 09/04/2018 0 99999 7 -1
root@ubuntu:/home/philip#
```

干得好！请注意，`L`表示用户帐户当前已锁定。我们可以使用`usermod`命令并传递`-U`选项来解锁用户帐户：

```
root@ubuntu:/home/philip# usermod -U tom
root@ubuntu:/home/philip# passwd --status tom
tom P 09/04/2018 0 99999 7 -1
root@ubuntu:/home/philip#
```

干得好！根据前面的输出，`P`表示用户`tom`有一个可用的密码；这意味着帐户是解锁的：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00144.jpeg)

太棒了！现在，当我们再次查看`etc/shadow`时，我们将不再看到哈希密码前面的`!`：

```
root@ubuntu:/home/philip# cat /etc/shadow | grep tom
tom:$6$uJ52BA2n$SWGisIpNTTOSygIX6swWdkS/gLPGZacEzCz2Ht6qfUHIr7ZIxkJyUjEyqN9ncb1yIFIXYnePz4HVzrwqJA1DZ0:17778:0:99999:7:::
root@ubuntu:/home/philip#
```

太棒了！如果我们添加用户而没有指定 shell，我们还可以为用户定义一个 shell；我们使用`usermod`命令传递`-s`选项：

```
root@ubuntu:/home/philip# cat /etc/passwd
gdm:x:121:129:Gnome Display Manager:/var/lib/gdm3:/bin/false
geoclue:x:122:130::/var/lib/geoclue:/bin/false
tom:x:1001:1001::/home/tom:
root@ubuntu:/home/philip# usermod -s /bin/bash tom
root@ubuntu:/home/philip# cat /etc/passwd
gdm:x:121:129:Gnome Display Manager:/var/lib/gdm3:/bin/false
geoclue:x:122:130::/var/lib/geoclue:/bin/false
tom:x:1001:1001::/home/tom:/bin/bash
root@ubuntu:/home/philip#
```

干得好！锁定帐户的另一种方法是使用`passwd`命令；我们传递`-l`选项。让我们锁定用户`tom`：

```
root@ubuntu:/home/philip# passwd -l tom
passwd: password expiry information changed.
root@ubuntu:/home/philip# passwd --status tom
tom L 09/04/2018 0 99999 7 -1
root@ubuntu:/home/philip#
```

再次，当我们尝试以用户`tom`的身份登录时，我们将看到这个：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00145.jpeg)

干得好！此外，我们还可以使用`passwd`命令解锁帐户；我们将传递`-u`选项：

```
root@ubuntu:/home/philip# passwd -u tom
passwd: password expiry information changed.
```

```
root@ubuntu:/home/philip# passwd --status tom
tom P 09/04/2018 0 99999 7 -1
root@ubuntu:/home/philip#
```

太棒了！请注意，root 用户仍然可以使用`tom`用户登录，是的！我们可以通过再次锁定用户`tom`来说明这一点：

```
root@ubuntu:/home/philip# passwd -l tom
passwd: password expiry information changed.
root@ubuntu:/home/philip# passwd --status tom
tom L 09/04/2018 0 99999 7 -1
root@ubuntu:/home/philip# cat /etc/shadow | grep tom
tom:!$6$uJ52BA2n$SWGisIpNTTOSygIX6swWdkS/gLPGZacEzCz2Ht6qfUHIr7ZIxkJyUjEyqN9ncb1yIFIXYnePz4HVzrwqJA1DZ0:17778:0:99999:7:::
root@ubuntu:/home/philip#
```

根据前面的输出，从所有迹象来看，用户`tom`的帐户似乎已被禁用，但是看看这个：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00146.jpeg)

太棒了！当有人尝试以用户`tom`的身份登录时，他们将被阻止，除非他们首先成为 root 用户，因为锁定**不会**阻止 root 用户访问已锁定的帐户。

root 用户可以访问任何帐户。

当我们管理用户帐户时，其中一些基本信息来自一个特殊的配置文件：`/etc/login.def`文件。我们可以查看`/etc/login.def`：

```
root@ubuntu:/home/philip# cat /etc/login.defs
# /etc/login.defs - Configuration control definitions for the login package.
# Three items must be defined:  MAIL_DIR, ENV_SUPATH, and ENV_PATH.
# If unspecified, some arbitrary (and possibly incorrect) value will
SU_NAME                           su
PASS_MAX_DAYS            99999
PASS_MIN_DAYS             0
PASS_WARN_AGE          7
root@ubuntu:/home/philip#
```

出于简洁起见，某些输出已被省略。根据前面的输出，我们可以看到`su`和`chage`命令的设置。

# w 命令

`w`命令显示系统中当前登录的用户。我们可以查看`w`命令：

```
root@ubuntu:/home/philip# w
 08:00:03 up 22:14,  4 users,  load average: 0.04, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
philip   tty2     :1               Mon13    7days  1:35   0.29s /sbin/upstart --user
root@ubuntu:/home/philip#
```

根据前面的输出，我们从左到右有从用户开始的字段。一些有趣的字段是`FROM`字段，因为它显示用户登录的位置（如果是通过网络，它将显示 IP 地址），以及`LOGIN@`字段，因为它显示用户登录的日期。我们可以通过传递`--help`选项来查看可用的选项：

```
root@ubuntu:/home/philip# w --help
Usage:
 w [options]
Options:
 -h, --no-header     do not print header
 -u, --no-current    ignore current process username
 -s, --short         short format
 -f, --from          show remote hostname field
 -o, --old-style     old style output
 -i, --ip-addr       display IP address instead of hostname (if possible)
 --help     display this help and exit
 -V, --version  output version information and exit
For more details see w(1).
root@ubuntu:/home/philip#
```

# who 命令

`who`命令是另一个用于显示当前登录用户的流行命令。我们只需使用`who`而不带任何选项：

```
root@ubuntu:/home/philip# who
philip   tty2         2018-09-03 13:29 (:1)
root@ubuntu:/home/philip#
```

太棒了！但等等，我们实际上可以确定系统启动的日期和时间，是的！我们传递`-a`选项：

```
root@ubuntu:/home/philip# who -a
 system boot  2018-08-27 12:33
LOGIN      tty1         2018-09-03 13:29             13792 id=tty1
 run-level 5  2018-08-27 12:33           tty2         2018-08-30 06:34              1434 id=      term=0 exit=0
 tty2         2018-08-30 06:35              9661 id=      term=0 exit=0
 tty2         2018-09-03 13:17             10231 id=      term=0 exit=0
philip   + tty2         2018-09-03 13:29  old        13815 (:1)
root@ubuntu:/home/philip#
Excellent! The first entry “system boot”, displays the date and time the system booted up. We can see the available options by passing the “--help” option:
root@ubuntu:/home/philip# who --help
Usage: who [OPTION]... [ FILE | ARG1 ARG2 ]
Print information about users who are currently logged in.
 -a, --all         same as -b -d --login -p -r -t -T -u  -b, --boot        time of last system boot
 -d, --dead        print dead processes
 -H, --heading     print line of column headings
 --ips         print ips instead of hostnames. with --lookup,
 canonicalizes based on stored IP, if available,                    rather than stored hostname
 -l, --login       print system login processes
 --lookup      attempt to canonicalize hostnames via DNS  -m                only hostname and user associated with stdin
 -p, --process     print active processes spawned by init
 -q, --count       all login names and number of users logged on  -r, --runlevel    print current runlevel
 -s, --short       print only name, line, and time (default)  -t, --time        print last system clock change
 -T, -w, --mesg    add user's message status as +, - or ?
 -u, --users       list users logged in
 --message     same as -T
 --writable    same as -T
 --help     display this help and exit
 --version  output version information and exit
root@ubuntu:/home/philip#
```

# last 命令

另一个用于显示最近登录用户的流行命令是`last`命令。我们只需输入`last`：

```
root@ubuntu:/home/philip# last
tom   pts/18   172.16.175.129   Tue Sep  4 08:31   still logged in
wtmp begins Tue Sep  4 08:31:36 2018
root@ubuntu:/home/philip#
```

根据前面的输出，用户`tom`已经通过网络登录。我们可以通过传递`--help`选项来查看可用的选项：

```
root@ubuntu:/home/philip# last --help
Usage:
 last [options] [<username>...] [<tty>...]
Show a listing of last logged in users.
Options:
 -<number>            how many lines to show
 -a, --hostlast       display hostnames in the last column
 -d, --dns            translate the IP number back into a hostname
 -f, --file <file>    use a specific file instead of /var/log/wtmp
 -F, --fulltimes      print full login and logout times and dates
 -i, --ip             display IP numbers in numbers-and-dots notation
 -n, --limit <number> how many lines to show
 -R, --nohostname     don't display the hostname field
 -s, --since <time>   display the lines since the specified time
 -t, --until <time>   display the lines until the specified time
 -p, --present <time> display who were present at the specified time
 -w, --fullnames      display full user and domain names
 -x, --system         display system shutdown entries and run level changes
 --time-format <format>  show timestamps in the specified <format>:
 notime|short|full|iso
 -h, --help     display this help and exit
 -V, --version  output version information and exit
root@ubuntu:/home/philip#
```

干得好！

# whoami 命令

我们可以使用`whoami`命令快速查看当前用户的信息。`whoami`命令显示当前登录会话的所有者：

```
root@ubuntu:/home/philip# whoami
root
root@ubuntu:/home/philip#
```

干得好！我们可以通过传递`--help`选项来查看`whoami`命令的可用选项：

```
root@ubuntu:/home/philip# whoami --help
Usage: whoami [OPTION]...
Print the user name associated with the current effective user ID.
Same as id -un.
 --help     display this help and exit
 --version  output version information and exit
GNU coreutils online help: <http://www.gnu.org/software/coreutils/>
Full documentation at: <http://www.gnu.org/software/coreutils/whoami>
or available locally via: info '(coreutils) whoami invocation'
root@ubuntu:/home/philip#
```

# 管理组

到目前为止，我们一直在系统中创建用户帐户；那么组帐户呢？当我们使用`useradd`命令创建帐户时，事实上我们也间接地创建了一个与用户同名的组帐户。为了证明这一点，让我们看一下`/etc/login.def`文件：

```
root@ubuntu:/home/philip# cat /etc/login.defs | grep GRO
#             TTYGROUP          Login tty will be assigned this group ownership.
# which owns the terminals, define TTYGROUP to the group number and
# TTYPERM to 0620\.  Otherwise leave TTYGROUP commented out and assign
TTYGROUP          tty
# If USERGROUPS_ENAB is set to "yes", that will modify this UMASK default value
USERGROUPS_ENAB yes
#CONSOLE_GROUPS                      floppy:audio:cdrom
root@ubuntu:/home/philip#
```

根据前面的输出，`USERGROUPS_ENAB yes`变量允许使用与用户名相同的名称创建一个组。我们还可以通过查看`/etc/group`来查看可用的组：

```
root@ubuntu:/home/philip# cat /etc/group
pulse-access:x:125:
rtkit:x:126:
saned:x:127:
philip:x:1000:
sambashare:x:128:philip
gdm:x:129:
geoclue:x:130:
tom:x:1001:
root@ubuntu:/home/philip#
```

为了简洁起见，已省略了一些输出。根据前面的输出，当我们创建用户名`tom`时，也创建了一个名为`tom`的组。但是，我们也可以使用另一个强大的命令`groupadd`来创建一个组：

```
root@ubuntu:/home/philip# groupadd Hacki
root@ubuntu:/home/philip# cat /etc/group
philip:x:1000:
sambashare:x:128:philip
gdm:x:129:
geoclue:x:130:
tom:x:1001:
Hacki:x:1002:
root@ubuntu:/home/philip#
```

太棒了！现在我们看到我们新创建的`Hacki`组正在显示。同样，我们可以使用`groupdel`命令删除一个组：

```
root@ubuntu:/home/philip# groupdel Hacki
root@ubuntu:/home/philip# cat /etc/group
philip:x:1000:
sambashare:x:128:philip
gdm:x:129:
geoclue:x:130:
tom:x:1001:
root@ubuntu:/home/philip#
```

太棒了！现在，让我们重新创建一个`Hacki`组：

```
root@ubuntu:/home/philip# groupadd Hacki
root@ubuntu:/home/philip# cat /etc/group
tom:x:1001:
Hacki:x:1002:
root@ubuntu:/home/philip#
```

可以使用`usermod`命令将用户添加到另一个组。让我们使用`tom`用户：

```
root@ubuntu:/home/philip# usermod -G Hacki,tom tom
root@ubuntu:/home/philip# cat /etc/group
tom:x:1001:tom
Hacki:x:1002:tom
root@ubuntu:/home/philip#
```

现在，我们可以看到用户`tom`是`tom`和`Hacki`组的一部分。另一种为用户分组的方法是使用`id`命令：

```
root@ubuntu:/home/philip# id tom
uid=1001(tom) gid=1001(tom) groups=1001(tom),1002(Hacki)
root@ubuntu:/home/philip#
```

干得好！此外，我们可以通过在`usermod`命令中使用`-g`来将组作为用户的主组：

```
root@ubuntu:/home/philip# usermod -g Hacki tom
root@ubuntu:/home/philip# id tom
uid=1001(tom) gid=1002(Hacki) groups=1002(Hacki) ,1001(tom)
root@ubuntu:/home/philip# cat /etc/group | grep tom
tom:x:1001:
Hacki:x:1002:tom
root@ubuntu:/home/philip#
```

太棒了！根据前面的输出，用户`tom`属于的唯一组是`Hacki`组。也可以给组添加密码；我们使用`gpasswd`命令。请注意，`/etc/gshadow`存储每个组的密码。我们可以看一下：

```
root@ubuntu:/home/philip# cat /etc/gshadow
philip:!::
sambashare:!::philip
gdm:!::
geoclue:!::
tom:!::tom
Hacki:!::
root@ubuntu:/home/philip#
```

为了简洁起见，已省略了一些输出。`！`感叹号表示相应组没有设置密码。让我们为`Hacki`组设置密码：

```
root@ubuntu:/home/philip# gpasswd Hacki
Changing the password for group Hacki
New Password:
Re-enter new password:
root@ubuntu:/home/philip# cat /etc/gshadow
geoclue:!::
tom:!::tom
Hacki:$6$eOvgO//4tAi/0C$v/FxkZyQLE0BLJ9jfrQ3sElm3kyNbhThl8DFXokZmAWzK1AKQFztSLOBpNsvOESOsWIz6DXKt4Erg.J7ElZut1::tom
root@ubuntu:/home/philip#
```

太棒了！现在我们可以看到密码的哈希版本已经取代了`！`感叹号。

还有另一个命令可以用来创建或更改组的密码：`groupmod`命令。让我们使用`groupmod`命令为`tom`组分配一个密码：

```
root@ubuntu:/home/philip# groupmod -p password tom
root@ubuntu:/home/philip# cat /etc/gshadow
gdm:!::
geoclue:!::
tom:password::tom
Hacki:$6$eOvgO//4tAi/0C$v/FxkZyQLE0BLJ9jfrQ3sElm3kyNbhThl8DFXokZmAWzK1AKQFztSLOBpNsvOESOsWIz6DXKt4Erg.J7ElZut1::tom
root@ubuntu:/home/philip#
```

干得好！根据前面的输出，与`gpasswd`命令相反，当我们使用`groupmod`命令时，它期望一个加密密码。我们指定了一个明文密码；因此，我们看到密码被暴露了。

# 总结

在本章中，我们涵盖了一系列管理用户和组帐户的技术。首先，我们调查了新用户的主目录所在的各个目录。接下来，我们处理了用户帐户的创建。我们看到了如何添加或删除用户帐户。此外，我们还看到了如何为用户帐户设置密码。此外，我们还研究了保存用户密码的各种配置文件，特别是关注了`/etc/passwd`和`/etc/shadow`文件。在此之后，我们处理了修改用户帐户的属性。

我们提到了锁定和解锁用户帐户。此外，我们使用`chage`命令处理了密码过期设置。最后，我们关注了组。我们涵盖了创建组以及添加和删除组的步骤。此外，我们还看到了如何将组分配给用户；同样，我们还看到了如何分配主组。最后，我们看了一下为组设置密码的方法。

在下一章中，我们的重点将是自动化任务。我们将介绍常用于执行任务的实用程序。此外，我们将介绍在 Linux 系统中执行任务的权限。我希望您加入我下一章，因为它包含了有关任务自动化的重要信息。

# 问题

1.  哪个配置文件通常在 `/etc/skel` 目录中存储别名？

A. `/etc/skel/bash`

B. `/etc/skel/bash_rc`

C. `/etc/skel/.bash_rc`

D. `/etc/skel/.bashrc`

1.  哪个配置文件在用户退出系统时清除屏幕？

A. `/etc.skel/.bash_logout`

B. `/etc/skel/bash_logout`

C. `/etc/skel/.logout`

D. `/etc/skel/.bashlogout`

1.  哪个配置文件存储执行的命令？

A. `/etc/skel/.bash_history`

B. `~/.bash_history`

C. `/etc/skel/bash_history`

D. `~/.history`

1.  哪个选项打印 `useradd` 命令的默认值？

A. `-d`

B. `-b`

C. `-D`

D. `--defaults`

1.  哪个选项允许在使用 `useradd` 时指定 shell？

A. `-c`

B. `-d`

C. `-S`

D. `-s`

1.  `adduser` 命令在 Fedora 28 中是指向哪个命令的符号链接？

A. `adduser`

B. `add-user`

C. `user-mod`

D. `user-add`

1.  哪个选项与 `chage` 命令一起将打印出帐户到期设置？

A. `-a`

B. `-l`

C. `-c`

D. `-d`

1.  `passwd --status` 命令中的哪个代码表示帐户已锁定？

A. `P`

B. `A`

C. `L`

D. `N`

1.  哪个选项与 `groupmod` 命令一起指定用户的主要组？

A. `-g`

B. `-G`

C. `-A`

D. `-b`

1.  用于更改组密码的命令是哪个？

A. `adduser`

B. `groupedit`

C. `groupmod`

D. `grouppasswd`

# 进一步阅读

+   该网站提供了有用信息：`/etc/skel`：[`unix.stackexchange.com`](https://unix.stackexchange.com)

+   该网站提供了有关用户帐户创建的有用信息：[`www.linfo.org`](http://www.linfo.org)

+   该网站提供了有关各种组的有用信息：[`www.linuxguide.it`](http://www.linuxguide.it)


# 第十三章：自动化任务

在上一章中，我们涵盖了管理用户和组帐户的各种技术。首先，我们调查了新用户的主目录来自哪些目录。接下来，我们处理了用户帐户的创建。此外，我们查看了用户密码保存的各种配置文件。最后，我们关注了组。我们介绍了创建组的步骤，以及添加、删除和为组分配密码。

在本章中，我们的重点转向自动化，特别是自动化任务。我们将涵盖使用各种方法进行任务调度。我们经常在日常工作中处理各种任务，而不是手动和重复地在一段时间内运行任务；实施某种额外的自动化是一个好的实践，我们将关注任务执行权限。

在本章中，我们将涵盖以下主题：

+   `at`，`atq`和`arm`命令

+   `crontab`文件和`anacron`命令

+   使用配置文件进行任务权限

# 使用`at`，`atq`和`atrm`命令管理自动化

在本节中，我们将介绍在 Linux 系统中自动化各种类型任务的常见方法。首先，我们将介绍`at`命令。接下来，我们将使用`atq`命令处理队列。最后，我们将以使用`atrm`命令删除作业的技术结束本节。

# at 命令

`at`命令安排一个任务在固定时间运行；它只运行一次。您可以安排一个简单的任务，比如将一些输出附加到文件，或者像备份数据库这样复杂的任务。启动`at`实用程序的基本语法如下：

```
at <time>
```

我们可以看到`at`命令在我们的 Fedora 28 系统上的运行情况；我们只需输入`at`而不指定任何选项：

```
[root@localhost philip]# at
Garbled time
[root@localhost philip]#
```

根据前面的命令，如果不指定时间，`at`实用程序将返回`Garbled time`。这是我们如何指定时间的方法：

```
[root@localhost philip]# at 18:10
warning: commands will be executed using /bin/sh
at>
```

根据前面的输出，一旦输入日期（在这种情况下，我们输入了格式为 HH:MM 的时间），它就会启动`at`实用程序，并出现`warning: commands will be executed using /bin/sh`的警告；这告诉我们`at`实用程序在执行时将使用哪个 shell。从这里，我们可以输入任何我们想在指定时间运行的命令。例如：

```
[root@localhost philip]# at 18:10
warning: commands will be executed using /bin/sh
at> ls -l > /home/philip/Documents/schedule
at>
```

看起来似乎没有什么改变；要保存更改，我们必须告诉`at`实用程序我们已经完成输入命令。这是使用*Ctrl* + *D*组合完成的：

```
[root@localhost philip]# at 18:10
warning: commands will be executed using /bin/sh
at> ls -l > /home/philip/Documents/schedule
at> <EOT>
job 1 at Tue Sep  4 18:10:00 2018
[root@localhost philip]#
```

根据前面的输出，`at`实用程序已经安排了一个任务在当前时间的`18:10`运行。使用`at`实用程序安排任务的另一种方法是以 12 小时制指定时间。这是我们如何做到的：

```
[root@localhost philip]# at 9:00 PM
warning: commands will be executed using /bin/sh
at> date > /home/philip/Documents/date_schedule
at> <EOT>
job 2 at Tue Sep  4 21:00:00 2018
[root@localhost philip]#
```

太棒了！根据前面的输出，我们已经使用 12 小时制指定了时间，通过添加`PM`。这告诉`at`实用程序在当前时间从`9:00 PM`执行作业。此外，我们还可以使用关键词指定时间。例如，我们可以说`tomorrow`，`noon tomorrow`，`next week`，`next Monday`，`fri`等等。这是它的样子：

```
[root@localhost philip]# at next monday
warning: commands will be executed using /bin/sh
at> ls -l /etc > /home/philip/Documents/ls_schedule
at> <EOT>
job 4 at Mon Sep 10 09:11:00 2018
[root@localhost philip]#
```

很棒！根据前面的输出，`at`实用程序已经使用当前日期来计算何时执行。此外，`<EOT>`是按下*Ctrl* + *D*的结果。指定运行`at`实用程序的另一种方法是使用关键词的组合。例如，我们可以指定`now + 4 weeks`，`now + 6 years`，`now + 25 minutes`等等。这是它的样子：

```
[root@localhost philip]# at now + 15 minutes
warning: commands will be executed using /bin/sh
at> ls -a /var/log > /home/philip/Documents/lsa_schedule
at> <EOT>
job 5 at Thu Sep  6 09:32:00 2018
[root@localhost philip]# date
Thu Sep  6 09:19:25 EDT 2018
[root@localhost philip]#
```

太棒了！根据前面的输出，我们可以看到`at`实用程序使用当前日期和时间进行计算。此外，我们还可以指定年份来查看其计算：

```
[root@localhost philip]# at now + 25 years
warning: commands will be executed using /bin/sh
at> systemctl status sshd.service > /home/philip/Documents/ssh_25yrs_schedule
at> <EOT>
job 7 at Sun Sep  6 09:25:00 2043
[root@localhost philip]#
```

很棒！根据前面的输出，`at`实用程序将在当前时间的 25 年后运行此任务。我们可以看到一些可以与`at`实用程序一起传递的常见选项列表，我们传递`-help`选项：

```
[root@localhost philip]# at -help
Usage: at [-V] [-q x] [-f file] [-mMlbv] timespec ...
 at [-V] [-q x] [-f file] [-mMlbv] -t time
 at -c job ...
 atq [-V] [-q x]
 at [ -rd ] job ...
 atrm [-V] job ...
 batch
[root@localhost philip]#
Awesome job!
```

# atq 命令

到目前为止，我们一直在使用`at`实用程序创建一些要执行的任务。跟踪使用`at`命令安排运行的任务将是很好的；`atq`命令正是这样做的。要了解其工作原理，我们可以运行`atq`命令：

```
[root@localhost philip]# atq
4              Mon Sep 10 09:11:00 2018 a root
7              Sun Sep  6 09:25:00 2043 a root
[root@localhost philip]#
```

根据前面的输出，我们列出了两个要由`at`实用程序运行的作业。当我们以 root 用户身份运行`atq`命令时，所有作业都将由`at`命令列出；当我们以标准用户身份运行`at`命令时，只有用户作业将被列出。这是它的外观：

```
[root@localhost philip]# exit
exit
[philip@localhost ~]$ atq
[philip@localhost ~]$
```

根据前面的输出，用户不知道根用户使用`at`命令安排的作业。此外，我们可以使用`at`命令查看队列；我们传递`-l`选项：

```
[root@localhost philip]# at -l
4              Mon Sep 10 09:11:00 2018 a root
7              Sun Sep  6 09:25:00 2043 a root
[root@localhost philip]#
```

很棒！根据前面的命令，我们可以看到输出与`atq`命令的输出相同。这是因为`at`命令与`atq`命令一起使用的`-l`选项只是`atq`命令的别名。

# atrm 命令

使用`at`实用程序安排运行作业是很好的。但是，我们需要对安排的作业有一定的控制。如果我们决定取消作业，可以使用`atrm`命令。`atrm`命令用于取消`at`实用程序执行之前的作业。例如，我们使用`at`实用程序安排了一次重启：

```
[root@localhost philip]# at now + 5 minutes
warning: commands will be executed using /bin/sh
at> reboot
at> <EOT>
job 8 at Thu Sep  6 10:06:00 2018
[root@localhost philip]# date
Thu Sep  6 10:01:21 EDT 2018
[root@localhost philip]#
```

根据前面的命令，我们已经指定使用`at`命令在五分钟内重新启动系统。现在，如果出于某种原因我们想要取消此作业，我们可以使用`atrm`命令。我们会这样做：

```
 [root@localhost philip]# atq
4              Mon Sep 10 09:11:00 2018 a root
8              Thu Sep  6 10:06:00 2018 a root
7              Sun Sep  6 09:25:00 2043 a root
[root@localhost philip]# atrm 8
[root@localhost philip]# atq
4              Mon Sep 10 09:11:00 2018 a root
7              Sun Sep  6 09:25:00 2043 a root
[root@localhost philip]#
```

很好！根据前面的命令，我们使用`atq`命令列出了计划的作业；然后我们使用`atrm`命令并指定作业 ID 来删除它。此外，我们可以使用`at`实用程序删除作业；为此，我们传递`-r`或`-d`选项：

```
[root@localhost philip]# atq
4              Mon Sep 10 09:11:00 2018 a root
7              Sun Sep  6 09:25:00 2043 a root
[root@localhost philip]# at -r 4
[root@localhost philip]# atq
7              Sun Sep  6 09:25:00 2043 a root
[root@localhost philip]#
```

很好！根据前面的输出，我们可以看到使用`at`命令的`-r`选项删除了 ID 为`4`的作业。`at`命令的`-d`选项的工作方式相同：

```
[root@localhost philip]# atq
7              Sun Sep  6 09:25:00 2043 a root
[root@localhost philip]#
[root@localhost philip]# at -d 7
[root@localhost philip]# atq
[root@localhost philip]#
Excellent!
```

# 使用 cron、crontab 和 anacron 进行自动化管理

在本节中，我们将介绍一些管理任务的技术，这些任务通常需要运行多次。首先，我们将从各种`cron`目录开始。接下来，我们将使用`crontab`。最后，我们将介绍`anacron`。重点是它们不是彼此的替代品，而是在 Linux 系统中管理任务中扮演关键角色。

# Cron

正如我们之前看到的，`at`实用程序只运行一次任务。有时我们需要多次运行任务。每次要执行给定的作业时，必须亲自输入`at`实用程序的任务，这很麻烦。例如，备份，这是大多数 Linux 管理员负责执行的最常见任务之一。

鉴于这些情况，我们可以使用`cron`实用程序，更具体地说是`/etc/cron.*`目录；我们放置我们想要运行的任务。作业可以每小时，每天或每月运行。Cron 使用`crond`守护程序。在 Ubuntu 中，`cron`守护程序称为`cron`或`cron.service`，而在 Fedora 28 中，`cron`守护程序称为`crond`或`crond.service`。我们可以按以下方式在 Ubuntu 上检查`cron`守护程序的状态：

```
root@philip-virtual-machine:/home/philip# systemctl status crond
Unit crond.service could not be found.
root@philip-virtual-machine:/home/philip# systemctl status cron
cron.service - Regular background program processing daemon
 Loaded: loaded (/lib/systemd/system/cron.service; enabled; vendor preset: enabled)
 Active: active (running) since Thu 2018-09-06 10:58:35 EDT; 10min ago
 Docs: man:cron(8)
 Main PID: 608 (cron)
 Tasks: 1 (limit: 4636)
 CGroup: /system.slice/cron.service
 └─608 /usr/sbin/cron -f
root@philip-virtual-machine:/home/philip#
```

根据前面的输出，`cron`守护程序称为`cron.service`。让我们在 Fedora 28 中检查`cron`守护程序：

```
[root@localhost philip]# systemctl status cron
Unit cron.service could not be found.
[root@localhost philip]# systemctl status crond
crond.service - Command Scheduler
 Loaded: loaded (/usr/lib/systemd/system/crond.service; enabled; vendor preset: enabled)
 Active: active (running) since Tue 2018-09-04 08:56:09 EDT; 2 days ago
 Main PID: 867 (crond)
 Tasks: 1 (limit: 2331)
 Memory: 3.3M
 CGroup: /system.slice/crond.service
 └─867 /usr/sbin/crond -n
 [root@localhost philip]#
```

很好！如在 Fedora 28 中所示，cron 服务称为`crond.service`。接下来，让我们看看`cron`目录：

```
root@philip-virtual-machine:/home/philip# ls -l /etc/cron.hourly/
total 0
root@philip-virtual-machine:/home/philip#
```

根据前面的输出，没有计划每小时运行的任务。但是，我们将在`/etc/cron.daily`目录中放置一些任务：

```
root@philip-virtual-machine:/home/philip# ls -l /etc/cron.daily/
total 52
-rwxr-xr-x 1 root root  311 May 29  2017 0anacron
-rwxr-xr-x 1 root root  376 Nov 20  2017 apport
-rwxr-xr-x 1 root root 1478 Apr 20 06:08 apt-compat
-rwxr-xr-x 1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x 1 root root  384 Dec 12  2012 cracklib-runtime
-rwxr-xr-x 1 root root 1176 Nov  2  2017 dpkg
-rwxr-xr-x 1 root root  372 Aug 21  2017 logrotate
-rwxr-xr-x 1 root root 1065 Apr  7 06:39 man-db
-rwxr-xr-x 1 root root  538 Mar  1  2018 mlocate
-rwxr-xr-x 1 root root  249 Jan 25  2018 passwd
-rwxr-xr-x 1 root root 3477 Feb 20  2018 popularity-contest
-rwxr-xr-x 1 root root  246 Mar 21 13:20 ubuntu-advantage-tools
-rwxr-xr-x 1 root root  214 Jul 12  2013 update-notifier-common
root@philip-virtual-machine:/home/philip#
```

根据前面的输出，有许多任务，如`passwd`、`dpkg`、`mlocate`等，每天都有安排运行。同样，我们可以查看`/etc/cron.monthly`内部：

```
root@philip-virtual-machine:/home/philip# ls -al /etc/cron.monthly/
total 24
drwxr-xr-x   2 root root  4096 Apr 26 14:23 .
drwxr-xr-x 124 root root 12288 Sep  6 10:58 ..
-rwxr-xr-x   1 root root   313 May 29  2017 0anacron
-rw-r--r--   1 root root   102 Nov 16  2017 .placeholder
root@philip-virtual-machine:/home/philip#
```

太棒了！我们可以更深入地查看一个已安排的任务。让我们看看`/etc/cron.daily/passwd`任务：

```
root@philip-virtual-machine:/home/philip# cat /etc/cron.daily/passwd
#!/bin/sh
cd /var/backups || exit 0
for FILE in passwd group shadow gshadow; do
 test -f /etc/$FILE              || continue
 cmp -s $FILE.bak /etc/$FILE     && continue
 cp -p /etc/$FILE $FILE.bak && chmod 600 $FILE.bak
done
root@philip-virtual-machine:/home/philip#
```

根据前面的输出，我们可以看到任务被写成脚本。

# Crontab

正如我们刚才看到的，我们可以将任务放在各自的`/etc/cron.*`目录中。然后每小时、每天或每月执行一次。但是，我们可以获得更灵活性；我们可以将脚本放在`/etc/cron.*`目录中，而不是将脚本放在`crontab`本身中。我们可以查看`/etc/crontab`文件：

```
root@philip-virtual-machine:/home/philip# cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# m h dom mon dow user            command
17 *        * * *      root    cd / && run-parts --report /etc/cron.hourly
25 6        * * *      root       test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6        * * 7      root       test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6        1 * *      root       test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
root@philip-virtual-machine:/home/philip#
```

太棒了！我们可以看到前面的输出中，我们涵盖的脚本在最后部分；它们由`crontab`执行。我们可以在`crontab`中添加我们自己的条目。我们使用`-e`选项与`crontab`一起，这意味着进入编辑模式：

```
root@philip-virtual-machine:/home/philip# crontab -e
Select an editor.  To change later, run 'select-editor'.
/bin/nano    <---- easiest
/usr/bin/vim.tiny
/bin/ed
Choose 1-3 [1]:
```

现在，我们需要指定使用哪个编辑器；我们将接受默认值：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00147.jpeg)

太棒了！根据前面的截图，我们有一些关于如何定义条目的指导方针。让我们定义自己的条目：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00148.jpeg)

根据前面的截图，我们已经定义了我们的条目，每半分钟运行一次，每天运行一次；`ls`命令将针对`/boot`目录运行，并将其输出追加保存到`/home/philip/Documents/ls_crontab`。定义时间的语法如下：

```
0/30         minute
*             hour
*             day of month
*             month
*             hour
```

完成条目创建后，我们需要写入更改；我们使用 nano 编辑器，所以按下*Ctrl* + *O*来写入更改：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00149.jpeg)

现在，`crontab`文件将为用户生成，如下所示：

```
crontab: installing new crontab
root@philip-virtual-machine:/home/philip#
Awesome! Now, we can pass the “-l” option with the crontab command :
root@philip-virtual-machine:/home/philip# crontab -l
# Output of the crontab jobs (including errors) is sent through
# email to the user the crontab file belongs to (unless redirected).
# For example, you can run a backup of all your user accounts
# at 5 a.m every week with:
# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
# For more information see the manual pages of crontab(5) and cron(8)
# m h  dom mon dow   command
*/30 * * * * ls -l /boot >> /home/philip/Documents/ls_crontab
root@philip-virtual-machine:/home/philip#
```

根据前面的输出，我们可以看到我们的条目在底部。30 分钟后，我们的文件将生成，我们可以看到输出：

```
root@philip-virtual-machine:/home/philip# cat Documents/ls_crontab
total 66752
-rw-r--r-- 1 root root  1536934 Apr 24 00:56 abi-4.15.0-20-generic
-rw-r--r-- 1 root root   216807 Apr 24 00:56 config-4.15.0-20-generic
drwxr-xr-x 5 root root     4096 Sep  6 10:30 grub
-rw-r--r-- 1 root root 53739884 Sep  6 10:45 initrd.img-4.15.0-20-generic
-rw-r--r-- 1 root root   182704 Jan 28  2016 memtest86+.bin
-rw-r--r-- 1 root root   184380 Jan 28  2016 memtest86+.elf
-rw-r--r-- 1 root root   184840 Jan 28  2016 memtest86+_multiboot.bin
-rw-r--r-- 1 root root        0 Apr 24 00:56 retpoline-4.15.0-20-generic
-rw------- 1 root root  4038188 Apr 24 00:56 System.map-4.15.0-20-generic
-rw-r--r-- 1 root root  8249080 Apr 26 14:40 vmlinuz-4.15.0-20-generic
root@philip-virtual-machine:/home/philip#
root@philip-virtual-machine:/home/philip# date
Thu Sep  6 12:00:05 EDT 2018
root@philip-virtual-machine:/home/philip#
```

太棒了，我们将再等待 30 分钟，然后查看追加的输出：

```
root@philip-virtual-machine:/home/philip# date
Thu Sep  6 12:30:18 EDT 2018
root@philip-virtual-machine:/home/philip# cat Documents/ls_crontab
total 66752
-rw-r--r-- 1 root root  1536934 Apr 24 00:56 abi-4.15.0-20-generic
-rw-r--r-- 1 root root   216807 Apr 24 00:56 config-4.15.0-20-generic
drwxr-xr-x 5 root root     4096 Sep  6 10:30 grub
-rw-r--r-- 1 root root 53739884 Sep  6 10:45 initrd.img-4.15.0-20-generic
-rw-r--r-- 1 root root   182704 Jan 28  2016 memtest86+.bin
-rw-r--r-- 1 root root   184380 Jan 28  2016 memtest86+.elf
-rw-r--r-- 1 root root   184840 Jan 28  2016 memtest86+_multiboot.bin
-rw-r--r-- 1 root root        0 Apr 24 00:56 retpoline-4.15.0-20-generic
-rw------- 1 root root  4038188 Apr 24 00:56 System.map-4.15.0-20-generic
-rw-r--r-- 1 root root  8249080 Apr 26 14:40 vmlinuz-4.15.0-20-generic
total 66752
-rw-r--r-- 1 root root  1536934 Apr 24 00:56 abi-4.15.0-20-generic
-rw-r--r-- 1 root root   216807 Apr 24 00:56 config-4.15.0-20-generic
drwxr-xr-x 5 root root     4096 Sep  6 10:30 grub
-rw-r--r-- 1 root root 53739884 Sep  6 10:45 initrd.img-4.15.0-20-generic
-rw-r--r-- 1 root root   182704 Jan 28  2016 memtest86+.bin
-rw-r--r-- 1 root root   184380 Jan 28  2016 memtest86+.elf
-rw-r--r-- 1 root root   184840 Jan 28  2016 memtest86+_multiboot.bin
-rw-r--r-- 1 root root        0 Apr 24 00:56 retpoline-4.15.0-20-generic
-rw------- 1 root root  4038188 Apr 24 00:56 System.map-4.15.0-20-generic
-rw-r--r-- 1 root root  8249080 Apr 26 14:40 vmlinuz-4.15.0-20-generic
root@philip-virtual-machine:/home/philip#
```

太棒了！请注意，标准用户看不到 root 用户的`crontab`作业：

```
philip@philip-virtual-machine:~$ crontab -l
no crontab for philip
philip@philip-virtual-machine:~$
```

但是，root 用户可以通过使用`-u`选项查看任何用户的条目：

```
root@philip-virtual-machine:/home/philip# crontab -u philip -l
no crontab for philip
root@philip-virtual-machine:/home/philip#
```

太棒了！

# Anacron

有趣的是，Anacron 并不是作为`cron`的替代品，而是用于系统有时关闭的情况。此外，Anacron 并不期望系统一直开启。例如，笔记本电脑会不时关闭。Anacron 的另一个显著特点是持续时间以天或月为单位，而不是以小时或分钟为单位。如果有一个工作需要在特定时间执行，而系统关闭了，放心，当系统启动时，Anacron 会执行该工作。我们可以查看`anacrontab`文件：

```
root@philip-virtual-machine:/home/philip# cat /etc/anacrontab
# /etc/anacrontab: configuration file for anacron
# See anacron(8) and anacrontab(5) for details.
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
HOME=/root
LOGNAME=root
# These replace cron's entries
1              5              cron.daily            run-parts --report /etc/cron.daily
7              10           cron.weekly       run-parts --report /etc/cron.weekly
@monthly           15           cron.monthly     run-parts --report /etc/cron.monthly
root@philip-virtual-machine:/home/philip# 
```

根据前面的输出，我们可以看到`anacrontab`文件中有一些`cron`条目。我们可以看到`anacron`是`cron`的补充，而不是替代`cron`。我们读取`anacrontab`文件中的条目的方式如下：

```
1                                                                            =Daily, other                                                                                      possible values are                                                                              7 = weekly,
                                                                             @daily, @monthly
5         
=Delay in minutes
cron.daily                                                                   = Job ID
run-parts --report /etc/cron.daily                                           = Command
```

我们可以在`/var/spool/anacron`目录中获取有关作业的信息：

```
root@philip-virtual-machine:/home/philip# ls -l /var/spool/anacron/
total 12
-rw------- 1 root root 9 Sep  6 10:44 cron.daily
-rw------- 1 root root 9 Sep  6 10:53 cron.monthly
-rw------- 1 root root 9 Sep  6 10:48 cron.weekly
root@philip-virtual-machine:/home/philip#
```

太棒了！我们可以查看其中一个文件，看到作业上次运行的时间：

```
root@philip-virtual-machine:/home/philip# cat /var/spool/anacron/cron.daily
20180906
root@philip-virtual-machine:/home/philip#
```

太好了！根据前面的输出，我们可以看到作业执行的时间戳。要查看`anacron`在前台处理的作业，我们可以使用`anacron`的`-d`选项：

```
root@philip-virtual-machine:/home/philip# anacron -d
Anacron 2.3 started on 2018-09-06
Normal exit (0 jobs run)
root@philip-virtual-machine:/home/philip#
```

根据前面的输出，当前没有正在执行的作业。我们可以通过编辑`/etc/anacrontab`文件创建一个条目：

```
root@philip-virtual-machine:/home/philip# cat /etc/anacrontab
# /etc/anacrontab: configuration file for anacron
# See anacron(8) and anacrontab(5) for details.
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
HOME=/root
LOGNAME=root
# These replace cron's entries
1              5              cron.daily            run-parts --report /etc/cron.daily
7              10           cron.weekly       run-parts --report /etc/cron.weekly
@monthly           15           cron.monthly     run-parts --report /etc/cron.monthly
1              10           test                        /bin/ls -l /boot > /home/philip/Documents/ls_anacron
root@philip-virtual-machine:/home/philip#
Excellent! Now, can check the /var/spool/anacrontab:
root@philip-virtual-machine:/home/philip# ls -l /var/spool/anacron/
total 12
-rw------- 1 root root 9 Sep  6 10:44 cron.daily
-rw------- 1 root root 9 Sep  6 10:53 cron.monthly
-rw------- 1 root root 9 Sep  6 10:48 cron.weekly
-rw------- 1 root root 0 Sep  6 13:47 test
root@philip-virtual-machine:/home/philip#
```

根据前面的输出，我们现在看到了我们自定义条目的新条目。我们可以查看文件内部：

```
root@philip-virtual-machine:/home/philip# cat /var/spool/anacron/test
root@philip-virtual-machine:/home/philip#
```

根据前面的输出，文件是空的，因为作业尚未运行。我们可以通过使用`anacron`的`-T`选项在`anacrontab`文件中检查语法错误：

```
root@philip-virtual-machine:/home/philip# anacron -T
root@philip-virtual-machine:/home/philip#
```

根据前面的输出，没有发现语法错误。我们可以使用`-u`选项更新作业的时间戳，而不运行作业：

```
root@philip-virtual-machine:/home/philip# anacron -u
root@philip-virtual-machine:/home/philip#
```

我们没有看到任何输出，因为时间戳是在后台更新的。我们可以添加`-d`选项，然后我们将看到前台发生的情况：

```
root@philip-virtual-machine:/home/philip# anacron -d -u
Updated timestamp for job `cron.daily' to 2018-09-06
Updated timestamp for job `cron.weekly' to 2018-09-06
Updated timestamp for job `test' to 2018-09-06
Updated timestamp for job `cron.monthly' to 2018-09-06
root@philip-virtual-machine:/home/philip#
```

太棒了！我们可以通过使用`anacron`的`-f`选项立即执行作业：

```
root@philip-virtual-machine:/home/philip# anacron -d -f
Anacron 2.3 started on 2018-09-06
Will run job `cron.daily' in 5 min.
Will run job `cron.weekly' in 10 min.
Will run job `test' in 10 min.
Will run job `cron.monthly' in 15 min.
^C
root@philip-virtual-machine:/home/philip#
```

根据前面的输出，anacron 正在尝试执行作业；但是它必须等待每个作业的延迟时间。这就是`-n`的威力所在；它会忽略设置的延迟：

```
root@philip-virtual-machine:/home/philip# anacron -d -f -n
Anacron 2.3 started on 2018-09-06
Will run job `cron.daily'
Will run job `cron.weekly'
Will run job `test'
Will run job `cron.monthly'
Jobs will be executed sequentially
Job `cron.daily' started
Job `cron.daily' terminated
Job `cron.weekly' started
Job `cron.weekly' terminated (mailing output)
anacron: Can't find sendmail at /usr/sbin/sendmail, not mailing output
Job `test' started
Job `test' terminated (exit status: 1) (mailing output)
anacron: Can't find sendmail at /usr/sbin/sendmail, not mailing output
Job `cron.monthly' started
Job `cron.monthly' terminated
Normal exit (4 jobs run)
root@philip-virtual-machine:/home/philip#
```

太好了！现在，我们可以检查`/home/philip/Documents`中的`ls_anacron`文件：

```
root@philip-virtual-machine:/home/philip# ls -l /home/philip/Documents/
total 4
-rw-r--r-- 1 root root    0 Sep  6 14:11 ls_anacron
-rw-r--r-- 1 root root 3405 Sep  6 14:00 ls_crontab
root@philip-virtual-machine:/home/philip#
```

太好了！我们可以查看`ls_anacron`文件的内容：

```
root@philip-virtual-machine:/home/philip# cat /home/philip/Documents/ls_anacron
abi-4.15.0-20-generic
config-4.15.0-20-generic
grub
initrd.img-4.15.0-20-generic
memtest86+.bin
memtest86+.elf
memtest86+_multiboot.bin
retpoline-4.15.0-20-generic
System.map-4.15.0-20-generic
vmlinuz-4.15.0-20-generic
root@philip-virtual-machine:/home/philip#
```

完美！

# 使用配置文件的任务权限

我们可以使用`/etc/at.allow`、`/etc/at.deny`、`/etc/cron.allow`和`/etc/cron.deny`来限制对`at`和`cron`实用程序的访问。如果这些文件不存在，我们可以创建它们；`/etc/at.allow`和`/etc/cron.allow`文件就足够了。对于`/etc/at.allow`文件，我们执行以下操作：

```
root@philip-virtual-machine:/home/philip# cat /etc/at.allow
cat: /etc/at.alow: No such file or directory
root@philip-virtual-machine:/home/philip# cat /etc/cron.allow
cat: /etc/cron.allow: No such file or directory
We can use an editor and create the file and store the usernames, one username per line:
root@philip-virtual-machine:/home/philip# cat /etc/at.allow
philip
harry
teddy
root@philip-virtual-machine:/home/philip#
root@philip-virtual-machine:/home/philip# cat /etc/cron.allow
philip
harry
teddy
root@philip-virtual-machine:/home/philip#
```

太棒了！现在，只有这些用户可以使用`at`或`cron`来执行作业。

# 总结

在本章中，我们讨论了命令行上的自动化。我们涉及了`at`实用程序，重点是创建一个只运行一次的作业。接下来，我们关注了`atq`实用程序以及它如何显示`at`实用程序将运行的所有预定作业。此外，我们还看到了如何利用`at`实用程序的一个选项来使我们能够查看作业队列。接着，我们看了`atrm`实用程序，主要关注了删除预定作业的能力。除此之外，我们还看到了使用`at`命令和传递选项来停止作业的可能性。然后我们讨论了`cron`，重点是各种`cron`目录；每个目录在自动化任务方面都发挥着重要作用。接下来，我们使用了`crontab`；我们看到了语法的细节，然后在`crontab`中创建了一个自定义条目。在此之后，我们使用了`anacron`。我们看到了`anacron`的用例以及它如何补充`cron`。然后我们创建了我们自己的自定义条目，并执行了作业，以便更好地理解`anacron`。最后，我们看了自动化方面的限制；主要是限制对`at`和`cron`实用程序的访问。

在下一章中，我们的重点将放在时间管理上，特别是维护系统时间和执行日志记录，包括本地和远程。下一章对于任何在网络环境中工作并且每天都需要进行监视的人来说都是非常重要的。我邀请你来加入我，一起来体验另一个激动人心的章节。

# 问题

1.  如果在`at`命令中没有传递选项，将会输出什么？

A. 无效的语法

B. 混乱的时间

C. 没有输出

D. 以上都不是

1.  哪个是有效的`at`命令？

A. 在下下个早上 9:00

B. 在今晚 9:00

C. 在下周一的早上 9:00

D. 以上都不是

1.  在`at`实用程序中，`<EOT>`是什么意思？

A. 时间结束

B. 按下了*CTRL*+ *D*

C. 按下了*CTRL* + *X*

D. 以上都不是

1.  哪个选项使用`at`命令打印队列？

A. `-a`

B. `-c`

C. `-d`

D. `-l`

1.  哪个选项使用`at`命令删除作业？

A. `-a`

B. `-c`

C. `-a`

D. `-r`

1.  使用`at`命令可以打印创建的作业队列的哪个其他命令？

A. `atrm`

B. `atc`

C. `atq`

D. `atr`

1.  哪个选项可以使用`crontab`每分钟运行一个作业？

A. `1/30 * * * *`

B. `*/20 * * * *`

C. `*****`

D. `****1`

1.  哪个选项用于打开`crontab`并开始进行更改？

A. `-a`

B. `-e`

C. `-b`

D. `-c`

1.  哪个单词可以代表 anacron 中的 7？

A. `@daily`

B. `@monthly`

C. `@weekly`

D. `@sunday`

1.  哪个选项强制`anacron`在其计划之前运行作业？

A. `-f`

B. `-e`

C. `-c`

D. `-a`

# 进一步阅读

+   这个网站提供了关于`at`实用程序的有用信息：[`linuxconfig.org`](https://linuxconfig.org)

+   这个网站提供了关于`cron`的有用信息：[`code.tutsplus.com`](https://code.tutsplus.com)

+   该网站提供关于`anacron`的有用信息：[`linux.101hacks.com`](https://linux.101hacks.com)


# 第十四章：维护系统时间和日志记录

在上一章中，我们处理了命令行上的自动化。我们涉及了`at`、`atq`和`atrm`命令。在此之后，我们使用了各种`cron`目录，然后介绍了`crontab`实用程序。此外，我们还介绍了`anacron`。最后，我们讨论了自动化的限制。

在本章中，我们的重点是维护系统时间和执行日志记录。首先，我们将介绍系统时间的配置，通过网络同步时间。然后，我们将关注各种日志文件。最后，我们将在不同的 Linux 系统之间执行远程日志记录。

在本章中，我们将涵盖以下主题：

+   日期配置

+   设置本地系统日志

+   配置远程日志记录

# 日期配置

在大多数 Linux 环境中，将系统与正确的时间同步是至关重要的。我们可以使用`date`命令来显示当前日期。我们可以通过简单运行以下命令来查看系统日期和时间：

```
root@philip-virtual-machine:/home/philip# date
Thu Sep  6 16:25:56 EDT 2018
root@philip-virtual-machine:/home/philip#
```

根据前面的输出，我们可以看到当前日期。还可以使用`date`命令设置日期和时间。为了能够以字符串格式指定日期，我们传递`-s`选项：

```
philip@philip-virtual-machine:~$ date -s "19 Dec 2020 12:00:00"
date: cannot set date: Operation not permitted
Sat Dec 19 12:00:00 EST 2020
philip@philip-virtual-machine:~$
```

根据前面的输出，我们遇到了一个障碍；这是因为我们需要 root 权限才能更改日期。让我们再试一次，这次作为 root 用户：

```
root@philip-virtual-machine:/home/philip# date -s "19 Dec 2020 12:00:00"
Sat Dec 19 12:00:00 EST 2020
root@philip-virtual-machine:/home/philip# date
Fri Sep  7 09:51:24 EDT 2018
root@philip-virtual-machine:/home/philip#
```

哇！发生了什么？嗯，事情是这样的：系统配置为自动同步时间。这可以通过使用另一个强大的命令来验证：`timedatectl`命令。我们可以运行`timedatectl`命令来查看当前的同步设置：

```
root@philip-virtual-machine:/home/philip# timedatectl
 Local time: Fri 2018-09-07 09:57:49 EDT
 Universal time: Fri 2018-09-07 13:57:49 UTC
 RTC time: Fri 2018-09-07 13:57:49
 Time zone: America/New_York (EDT, -0400)
 System clock synchronized: yes
systemd-timesyncd.service active: yes
 RTC in local TZ: no
root@philip-virtual-machine:/home/philip#
```

太棒了！根据前面的输出，`systemd-timesyncd.service active: yes`部分表明系统确实已设置为同步。此外，我们可以传递`status`选项，这将返回类似的结果：

```
root@philip-virtual-machine:/home/philip# timedatectl status
 Local time: Fri 2018-09-07 10:02:38 EDT
 Universal time: Fri 2018-09-07 14:02:38 UTC
 RTC time: Fri 2018-09-07 14:02:38
 Time zone: America/New_York (EDT, -0400)
 System clock synchronized: yes
systemd-timesyncd.service active: yes
 RTC in local TZ: no
root@philip-virtual-machine:/home/philip#
```

太棒了！我们可以手动设置时间，但首先需要通过使用`timedatectl`命令传递`set-ntp`选项来禁用自动同步：

```
root@philip-virtual-machine:/home/philip# timedatectl set-ntp false
root@philip-virtual-machine:/home/philip#
root@philip-virtual-machine:/home/philip# timedatectl status
 Local time: Fri 2018-09-07 10:04:27 EDT
 Universal time: Fri 2018-09-07 14:04:27 UTC
 RTC time: Fri 2018-09-07 14:04:27
 Time zone: America/New_York (EDT, -0400)
 System clock synchronized: yes
systemd-timesyncd.service active: no
 RTC in local TZ: no
root@philip-virtual-machine:/home/philip#
```

干得好！根据前面的命令，我们现在可以看到`systemd-timesyncd.service active: no`部分已更改为`no`。我们现在可以尝试再次使用`date`命令更改日期：

```
root@philip-virtual-machine:/home/philip# date
Fri Sep  7 10:06:28 EDT 2018
root@philip-virtual-machine:/home/philip# date -s "19 Dec 2020 12:00:00"
Sat Dec 19 12:00:00 EST 2020
root@philip-virtual-machine:/home/philip# date
Sat Dec 19 12:00:01 EST 2020
root@philip-virtual-machine:/home/philip#
```

太棒了！命令已成功执行并更改了当前日期。我们还可以使用数字值来表示月份，如下所示：

```
root@philip-virtual-machine:/home/philip# date -s "20240101 13:00:00"
Mon Jan  1 13:00:00 EST 2024
root@philip-virtual-machine:/home/philip# date
Mon Jan  1 13:00:08 EST 2024
root@philip-virtual-machine:/home/philip#
```

根据前面的输出，我们可以看到日期和时间已更改以反映新的设置。除此之外，还可以使用连字符分隔日期，如下所示：

```
root@philip-virtual-machine:/home/philip# date -s "2000-10-05 07:00:00"
Thu Oct  5 07:00:00 EDT 2000
root@philip-virtual-machine:/home/philip# date
Thu Oct  5 07:00:02 EDT 2000
root@philip-virtual-machine:/home/philip#
```

太棒了！我们还可以使用正则表达式来设置时间。我们可以使用`+%T`来设置时间：

```
root@philip-virtual-machine:/home/philip# date
Thu Oct  5 03:06:43 EDT 2000
root@philip-virtual-machine:/home/philip#
root@philip-virtual-machine:/home/philip# date +%T -s "20:00:00"
20:00:00
root@philip-virtual-machine:/home/philip# date
Thu Oct  5 20:00:03 EDT 2000
root@philip-virtual-machine:/home/philip#
```

太棒了！还可以使用`date`命令仅更改小时；我们传递`+%H`选项：

```
root@philip-virtual-machine:/home/philip# date +%H -s "4"
04
root@philip-virtual-machine:/home/philip# date
Thu Oct  5 04:00:03 EDT 2000
root@philip-virtual-machine:/home/philip#
```

太棒了！还可以使用`timedatectl`命令更改日期和时间。我们可以通过传递`set-time`选项来更改日期：

```
root@philip-virtual-machine:/home/philip# timedatectl set-time 10:00:00
root@philip-virtual-machine:/home/philip# date
Thu Oct  5 10:00:02 EDT 2000
root@philip-virtual-machine:/home/philip# timedatectl
 Local time: Thu 2000-10-05 10:00:06 EDT
 Universal time: Thu 2000-10-05 14:00:06 UTC
 RTC time: Thu 2000-10-05 14:00:06
 Time zone: America/New_York (EDT, -0400)
 System clock synchronized: no systemd-timesyncd.service active: no
 RTC in local TZ: no
root@philip-virtual-machine:/home/philip#
```

太棒了！还可以通过传递`set-time`选项来仅设置日期：

```
root@philip-virtual-machine:/home/philip# timedatectl set-time 2019-03-01
root@philip-virtual-machine:/home/philip# date
Fri Mar  1 00:00:02 EST 2019
root@philip-virtual-machine:/home/philip#
```

根据前面的输出，日期已更改，但请注意时间也已更改。我们可以通过合并日期和时间来解决这个问题：

```
root@philip-virtual-machine:/home/philip# timedatectl set-time '2019-03-01 10:00:00'
root@philip-virtual-machine:/home/philip# date
Fri Mar  1 10:00:01 EST 2019
root@philip-virtual-machine:/home/philip#
```

太棒了！我们还可以使用`timedatectl`命令更改时区；我们可以通过传递`list-timezones`选项来查看可用的时区：

```
root@philip-virtual-machine:/home/philip# timedatectl list-timezones
Africa/Abidjan
Africa/Accra
Africa/Addis_Ababa
Africa/Algiers
Africa/Asmara
Africa/Bamako
Africa/Bangui
America/Guayaquil
America/Guyana
root@philip-virtual-machine:/home/philip#
```

出于简洁起见，某些输出已被省略。我们通过传递`set-timezone`选项来更改时区：

```
root@philip-virtual-machine:/home/philip# timedatectl
 Local time: Fri 2019-03-01 10:15:43 EST
 Universal time: Fri 2019-03-01 15:15:43 UTC
 RTC time: Fri 2019-03-01 15:15:43
 Time zone: America/New_York (EST, -0500)
 System clock synchronized: no
systemd-timesyncd.service active: no
 RTC in local TZ: no
root@philip-virtual-machine:/home/philip# timedatectl set-timezone America/Guyana
root@philip-virtual-machine:/home/philip# timedatectl
 Local time: Fri 2019-03-01 11:15:59 -04
 Universal time: Fri 2019-03-01 15:15:59 UTC
 RTC time: Fri 2019-03-01 15:16:00
 Time zone: America/Guyana (-04, -0400)
 System clock synchronized: no
systemd-timesyncd.service active: no
 RTC in local TZ: no
root@philip-virtual-machine:/home/philip#
```

太棒了！我们已成功更改了时区。时区信息存储在`/etc/timezone`和`/etc/localtime`文件中。它是指向`/usr/share/zoneinfo/<timezone>`的符号链接；`<timezone>`是我们指定的任何内容：

```
root@philip-virtual-machine:/home/philip# ls -l /etc/localtime
lrwxrwxrwx 1 root root 36 Mar  1 11:15 /etc/localtime -> ../usr/share/zoneinfo/America/Guyana
root@philip-virtual-machine:/home/philip#
root@philip-virtual-machine:/home/philip# cat /etc/timezone
America/Guyana
root@philip-virtual-machine:/home/philip#
```

太棒了！根据前面的输出，我们可以看到`/etc/timezone`和`/etc/localtime`已更新为指定的时区。

# tzselect 命令

`tzselect`命令可用于更改系统的时区。当我们启动`tzselect`命令时，它将以交互模式询问一系列问题。可以通过以下方式说明这一点：

```
root@philip-virtual-machine:/home/philip# tzselect
Please identify a location so that time zone rules can be set correctly.
Please select a continent, ocean, "coord", or "TZ".
 1) Africa
 2) Americas
 3) Antarctica
 4) Asia
 5) Atlantic Ocean
 6) Australia
 7) Europe]
 8) Indian Ocean
 9) Pacific Ocean
10) coord - I want to use geographical coordinates.
11) TZ - I want to specify the time zone using the Posix TZ format.
#?
```

根据前面的输出，我们需要输入代表大陆的数字：

```
#? 2
Please select a country whose clocks agree with yours.
 1) Anguilla          19) Dominican Republic   37) Peru
 2) Antigua & Barbuda 20) Ecuador              38) Puerto Rico
 3) Argentina         21) El Salvador          39) St Barthelemy
 4) Aruba             22) French Guiana        40) St Kitts & Nevis
 5) Bahamas           23) Greenland            41) St Lucia
 6) Barbados          24) Grenada              42) St Maarten (Dutch)
 7) Belize            25) Guadeloupe           43) St Martin (French)
 8) Bolivia           26) Guatemala            44) St Pierre & Miquelon
 9) Brazil            27) Guyana               45) St Vincent
#?
```

出于简洁起见，一些输出已被省略。然后我们必须指定国家：

```
The following information has been given:
 Guyana
Therefore TZ='America/Guyana' will be used.
Selected time is now:     Fri Mar  1 11:27:49 -04 2019.
Universal Time is now:   Fri Mar  1 15:27:49 UTC 2019.
Is the above information OK?
1) Yes
2) No
#?
```

根据前面的输出，我们需要确认信息：

```
#? 1
You can make this change permanent for yourself by appending the line
 TZ='America/Guyana'; export TZ
to the file '.profile' in your home directory; then log out and log in again.
Here is that TZ value again, this time on standard output so that you
can use the /usr/bin/tzselect command in shell scripts:
America/Guyana
root@philip-virtual-machine:/home/philip#
```

我们需要在当前用户的主目录的`.profile`中添加`TZ='America/Guyana'; export TZ`行；然后用户需要注销并重新登录以使更改永久生效。当然，我们已经通过使用前面的命令：`timedatectl`命令使我们的更改永久生效。

# tzconfig 命令

`tzconfig`命令是更改系统时区的旧方法。实际上已经不可用了；取而代之的是 Ubuntu 中的`tzdata`命令。

这可以通过运行`tzconfig`命令来说明：

```
root@philip-virtual-machine:/home/philip# tzconfig
WARNING: the tzconfig command is deprecated, please use:
 dpkg-reconfigure tzdata
root@philip-virtual-machine:/home/philip#
```

根据前面的命令，我们需要运行`dpkg-reconfigure tzdata`命令；这将启动一个交互式对话框：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00150.jpeg)

现在我们需要使用键盘滚动；然后按*Enter*键选择所需的大陆。然后会出现这个：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00151.jpeg)

根据前面的输出，然后滚动到所需的国家并按*Enter*键；这将使用你突出显示的国家的时区：

```
root@philip-virtual-machine:/home/philip# dpkg-reconfigure tzdata
Current default time zone: 'America/Guyana'
Local time is now: Fri Mar 1 11:40:31 -04 2019.
Universal Time is now: Fri Mar 1 15:40:31 UTC 2019.
root@philip-virtual-machine:/home/philip#
```

太棒了！改变时区的另一种方法是手动删除`/etc/localtime`并创建一个符号链接，指向`/usr/share/zoneinfo`内所需的时区。这是它的样子：

```
root@philip-virtual-machine:/etc# unlink localtime
root@philip-virtual-machine:/etc# ln -s /usr/share/zoneinfo/America/Paramaribo localtime
root@philip-virtual-machine:/etc# ll /etc/localtime
lrwxrwxrwx 1 root root 38 Mar  1 13:01 /etc/localtime -> /usr/share/zoneinfo/America/Paramaribo
root@philip-virtual-machine:/etc#
root@philip-virtual-machine:/etc# timedatectl
 Local time: Fri 2019-03-01 13:03:57 -03
Universal time: Fri 2019-03-01 16:03:57 UTC
 RTC time: Fri 2019-03-01 16:03:57
 Time zone: America/Paramaribo (-03, -0300)
 System clock synchronized: no
systemd-timesyncd.service active: no
 RTC in local TZ: no
root@philip-virtual-machine:/etc#
root@philip-virtual-machine:/etc# cat /etc/timezone
America/Guyana
root@philip-virtual-machine:/etc#
```

从前面的输出中，我们可以看到时区信息在`timedatectl`命令中已更新。但是在`/etc/timezone`中没有更新。为了更新`/etc/timezone`，我们需要运行`dpkg-reconfigure tzdata`命令：

```
root@philip-virtual-machine:/etc# dpkg-reconfigure tzdata
Current default time zone: 'America/Paramaribo'
Local time is now:      Fri Mar  1 13:07:43 -03 2019.
Universal Time is now:  Fri Mar  1 16:07:43 UTC 2019.
root@philip-virtual-machine:/etc# cat /etc/timezone
America/Paramaribo
root@philip-virtual-machine:/etc#         
```

太棒了！

# hwclock 命令

还有另一个时钟；即使系统关机时也在运行的时钟；这是硬件时钟。我们可以查看硬件时钟的时间如下：

```
root@philip-virtual-machine:/etc# date
Fri Mar  1 13:11:49 -03 2019
root@philip-virtual-machine:/etc# hwclock
2019-03-01 13:11:51.634343-0300
root@philip-virtual-machine:/etc#
```

从前面的输出中，我们可以看到日期和时间是相对接近的。我们可以将硬件时钟设置为与系统时间同步，如下所示：

```
root@philip-virtual-machine:/etc# hwclock --systohc
root@philip-virtual-machine:/etc# date
Fri Mar  1 12:17:04 -04 2019
root@philip-virtual-machine:/etc# hwclock
2019-03-01 12:17:06.556082-0400
root@philip-virtual-machine:/etc#
```

还可以配置系统时间与硬件时钟同步。我们可以这样做：

```
root@philip-virtual-machine:/etc# hwclock --hctosys
root@philip-virtual-machine:/etc# date
Fri Mar  1 12:18:52 -04 2019
root@philip-virtual-machine:/etc# hwclock
2019-03-01 12:18:54.571552-0400
root@philip-virtual-machine:/etc#
```

硬件时钟从`/etc/adjtime`中获取设置，如下所示：

```
root@philip-virtual-machine:/etc# cat /etc/adjtime
0.000000 1551457021 0.000000
1551457021
UTC
root@philip-virtual-machine:/etc#
```

还有硬件时钟；我们可以使用`hwclock`命令查看硬件时钟。如果我们使用 UTC 时间，我们可以在`hwclock`命令中使用`--utc`选项：

```
root@philip-virtual-machine:/home/philip# hwclock -r --utc
2018-09-06 16:30:27.493714-0400
root@philip-virtual-machine:/home/philip#
```

如前面的命令所示，硬件时钟的日期以 UTU 形式呈现。除此之外，我们还可以使用`--show`选项来显示类似的结果：

```
root@philip-virtual-machine:/home/philip# hwclock --show --utc
2018-09-06 16:31:43.025628-0400
root@philip-virtual-machine:/home/philip#
```

太棒了！

# 设置本地系统日志记录

在 Linux 环境中，具有可用于识别系统潜在瓶颈的日志非常重要。幸运的是，默认情况下我们已经打开了日志记录。有不同类型的日志文件可供检查；主要是`/var/log`目录包含了系统不同方面的各种日志文件。我们可以查看`/var/log`目录：

```
root@philip-virtual-machine:/etc# cd /var
```

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00152.jpeg)

从前面的输出中，首先是`/var/log/syslog`文件。这包含了有关系统运行情况的相关信息。我们可以查看`/var/log/syslog`文件：

```
root@philip-virtual-machine:/var# ll /var/log/syslog
-rw-r----- 1 syslog adm 48664 Mar 1 15:38 /var/log/syslog
root@philip-virtual-machine:/var# tail -f /var/log/syslog
Mar  1 14:31:52 philip-virtual-machine snapd[725]: 2019/03/01 14:31:52.052401 autorefresh.go:327: Cannot prepare auto-refresh change: cannot refresh snap-declaration for "core": Get https://api.snapcraft.io/api/v1/snaps/assertions/snap-declaration/16/99T7MUlRhtI3U0QFgl5mXXESAiSwt776?max-format=2: net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers)
Mar  1 14:31:52 philip-virtual-machine snapd[725]: 2019/03/01 14:31:52.053013 stateengine.go:101: state ensure error: cannot refresh snap-declaration for "core": Get https://api.snapcraft.io/api/v1/snaps/assertions/snap-declaration/16/99T7MUlRhtI3U0QFgl5mXXESAiSwt776?max-format=2: net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers)
Mar  1 14:38:03 philip-virtual-machine gnome-shell[1576]: Object Gdm.UserVerifierProxy (0x560080fc4cd0), has been already deallocated - impossible to access to it. This might be caused by the fact that the object has been destroyed from C code using something such as destroy(), dispose(), or remove() vfuncs
^C
root@philip-virtual-machine:/var#
```

出于简洁起见，一些输出已被省略。我们使用`tail`命令和`-f`选项；这将打印出最近生成的日志，存储在`/var/log/syslog`文件中。另一个有用的日志文件是`/var/log/auth.log`。这显示了各种认证消息。我们可以查看`/var/log/auth.log`文件：

```
root@philip-virtual-machine:/var# tail -f /var/log/auth.log
Mar  1 13:17:01 philip-virtual-machine CRON[7162]: pam_unix(cron:session): session closed for user root
Mar  1 13:30:01 philip-virtual-machine CRON[7167]: pam_unix(cron:session): session opened for user root by (uid=0)
Mar  1 13:30:01 philip-virtual-machine CRON[7167]: pam_unix(cron:session): session closed for user rootMar  1 14:00:01 philip-virtual-machine CRON[7178]: pam_unix(cron:session): session opened for user root by (uid=0)
Mar  1 14:00:01 philip-virtual-machine CRON[7178]: pam_unix(cron:session): session closed for user root
Mar  1 14:17:01 philip-virtual-machine CRON[7184]: pam_unix(cron:session): session opened for user
 ^C
root@philip-virtual-machine:/var#
```

太棒了！在前面的输出中，我们可以看到与 root 用户有关的各种日志。此外，如果有人试图侵入系统，这些登录尝试也会出现在这里：

```
root@philip-virtual-machine:/var/log# tail -f /var/log/auth.log
Mar  4 10:39:04 philip-virtual-machine sshd[26259]: Failed password for invalid user tom from 172.16.175.129 port 39010 ssh2
Mar  4 10:39:04 philip-virtual-machine sshd[26259]: Connection closed by invalid user tom 172.16.175.129 port 39010 [preauth]
Mar  4 10:39:04 philip-virtual-machine sshd[26259]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=172.16.175.129
Mar  4 10:39:09 philip-virtual-machine sshd[26261]: Invalid user harry from 172.16.175.129 port 39012
Mar  4 10:39:10 philip-virtual-machine sshd[26261]: pam_unix(sshd:auth): check pass; user unknown
Mar  4 10:39:10 philip-virtual-machine sshd[26261]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=172.16.175.129
Mar  4 10:39:12 philip-virtual-machine sshd[26261]: Failed password for invalid user harry from 172.16.175.129 port 39012 ssh2
Mar  4 10:39:13 philip-virtual-machine sshd[26261]: pam_unix(sshd:auth): check pass; user unknown
Mar  4 10:39:15 philip-virtual-machine sshd[26261]: Failed password for invalid user harry from 172.16.175.129 port 39012 ssh2
Mar  4 10:39:16 philip-virtual-machine sshd[26261]: pam_unix(sshd:auth): check pass; user unknown
Mar  4 10:39:18 philip-virtual-machine sshd[26261]: Failed password for invalid user harry from 172.16.175.129 port 39012 ssh2
Mar  4 10:39:18 philip-virtual-machine sshd[26261]: Connection closed by invalid user harry 172.16.175.129 port 39012 [preauth]
Mar  4 10:39:18 philip-virtual-machine sshd[26261]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=172.16.175.129
```

太棒了！我们可以看到有关用户尝试登录系统的认证消息。另一个有用的日志文件是`/var/log/kern.log`。此文件包含与启动期间内核相关的各种消息。我们可以查看这个文件：

```
root@philip-virtual-machine:/var/log# tail -f /var/log/kern.log
Mar 1 15:40:32 philip-virtual-machine kernel: [106182.510455] hrtimer: interrupt took 7528791 ns
Mar 2 04:58:37 philip-virtual-machine kernel: [154065.757609] sched: RT throttling activated
Mar 4 10:07:45 philip-virtual-machine kernel: [345414.648164] IPv6: ADDRCONF(NETDEV_UP): ens33: link is not ready
Mar 4 10:07:45 philip-virtual-machine kernel: [345414.653620] IPv6: ADDRCONF(NETDEV_UP): ens33: link is not ready
Mar 4 10:07:45 philip-virtual-machine kernel: [345414.655942] e1000: ens33 NIC Link is Up 1000 Mbps Full Duplex, Flow Control: None
Mar 4 10:07:45 philip-virtual-machine kernel: [345414.656712] IPv6: ADDRCONF(NETDEV_CHANGE): ens33: link becomes ready
^C
root@philip-virtual-machine:/var/log#
```

在前面的文件中，我们可以看到与中断和网络有关的日志。在 Fedora 28 系统上，当我们检查`/var/log`文件时，我们会注意到没有`/var/log/syslog`文件：

```
[root@localhost philip]# ls /var/log
anaconda         dnf.log               hawkey.log           pluto            vmware-network.7.log
audit            dnf.log-20180805      hawkey.log-20180805  ppp    vmware-network.8.log
blivet-gui       dnf.log-20180812      hawkey.log-20180812  README vmware-network.9.log
boot.log         dnf.log-20180827      hawkey.log-20180827  samba  vmware-network.log
btmp             dnf.log-20180904      hawkey.log-20180904  speech-dispatcher     vmware-vgauthsvc.log.0
btmp-20180904     dnf.rpm.log           httpd                sssd             vmware-vmsvc.log
chrony           dnf.rpm.log-20180805  journal              tallylog         wtmp
cups             dnf.rpm.log-20180812  kdm.log              vmware-network.1.log  Xorg.0.log
dnf.librepo.log  dnf.rpm.log-20180827  kdm.log-20180904     vmware-network.2.log  Xorg.0.log.old
dnf.librepo.log-20180805  dnf.rpm.log-20180904  lastlog              vmware-network.3.log
dnf.librepo.log-20180812  firewalld             libvirt              vmware-network.4.log
dnf.librepo.log-20180827  gdm                   lightdm              vmware-network.5.log
dnf.librepo.log-20180904  glusterfs             mariadb              vmware-network.6.log
[root@localhost philip]#
```

根据前面的输出，Fedora 28 正在使用`systemd`。这已经用`journal`替换了`/var/log/messages`和`/var/log/syslog`。这反过来又是在`journald`守护程序内实现的。我们可以使用`journalctl`命令查看日志。要查看所有日志文件，我们可以简单地输入`journalctl`而不带任何选项：

```
root@localhost philip]# journalctl
-- Logs begin at Tue 2018-07-31 10:57:23 EDT, end at Fri 2018-09-07 15:51:56 EDT. --
Jul 31 10:57:23 localhost.localdomain kernel: Linux version 4.16.3-301.fc28.x86_64 (mockbuild@bkernel02.phx2.fedoraprojec>
Jul 31 10:57:23 localhost.localdomain kernel: Command line: BOOT_IMAGE=/vmlinuz-4.16.3-301.fc28.x86_64 root=/dev/mapper/f>
Jul 31 10:57:23 localhost.localdomain kernel: Disabled fast string operations
Jul 31 10:57:23 localhost.localdomain kernel: x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'
Jul 31 10:57:23 localhost.localdomain kernel: x86/fpu: Supporting XSAVE feature 0x002: 'SSE registers'
Jul 31 10:57:23 localhost.localdomain kernel: x86/fpu: Enabled xstate features 0x3, context size is 576 bytes, using 'sta>
Jul 31 10:57:23 localhost.localdomain kernel: e820: BIOS-provided physical RAM map:
Jul 31 10:57:23 localhost.localdomain kernel: BIOS-e820: [mem 0x0000000000000000-0x000000000009ebff] usable
Jul 31 10:57:23 localhost.localdomain kernel: BIOS-e820: [mem 0x000000000009ec00-0x000000000009ffff] reserved
Jul 31 10:57:23 localhost.localdomain kernel: BIOS-e820: [mem 0x00000000000dc000-0x00000000000fffff] reserved
 [root@localhost philip]#
```

为了简洁起见，已省略了一些输出。有许多日志消息。我们可以过滤我们想要显示的内容。例如，要查看自最近系统引导以来的日志，我们可以传递`-b`选项：

```
[root@localhost philip]# journalctl -b
-- Logs begin at Tue 2018-07-31 10:57:23 EDT, end at Fri 2018-09-07 15:52:26 EDT. --
Sep 04 08:55:38 localhost.localdomain kernel: Linux version 4.16.3-301.fc28.x86_64 (mockbuild@bkernel02.phx2.fedoraprojec>
Sep 04 08:55:38 localhost.localdomain kernel: Command line: BOOT_IMAGE=/vmlinuz-4.16.3-301.fc28.x86_64 root=/dev/mapper/f>
Sep 04 08:55:38 localhost.localdomain kernel: Disabled fast string operations
Sep 04 08:55:38 localhost.localdomain kernel: x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'
Sep 04 08:55:38 localhost.localdomain kernel: x86/fpu: Supporting XSAVE feature 0x002: 'SSE registers'
Sep 04 08:55:38 localhost.localdomain kernel: x86/fpu: Enabled xstate features 0x3, context size is 576 bytes, using 'sta>
Sep 04 08:55:38 localhost.localdomain kernel: e820: BIOS-provided physical RAM map:
Sep 04 08:55:38 localhost.localdomain kernel: BIOS-e820: [mem 0x0000000000000000-0x000000000009ebff] usable
[root@localhost philip]#
```

在前面的输出中，我们看到了相当多的消息。我们甚至可以通过传递`--utc`选项显示带有 UTC 时间戳的日志：

```
[root@localhost philip]# journalctl -b --utc
-- Logs begin at Tue 2018-07-31 14:57:23 UTC, end at Fri 2018-09-07 19:52:26 UTC. --
Sep 04 12:55:38 localhost.localdomain kernel: Linux version 4.16.3-301.fc28.x86_64 (mockbuild@bkernel02.phx2.fedoraprojec>
Sep 04 12:55:38 localhost.localdomain kernel: Command line: BOOT_IMAGE=/vmlinuz-4.16.3-301.fc28.x86_64 root=/dev/mapper/f>
Sep 04 12:55:38 localhost.localdomain kernel: Disabled fast string operations
Sep 04 12:55:38 localhost.localdomain kernel: x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'
[root@localhost philip]#
```

太棒了！根据前面的输出，第一行`-- Logs begin at Tue 2018-07-31 14:57:23 UTC, end at Fri 2018-09-07 19:52:26 UTC. --`表示时间戳是 UTC 时间。`journalctl`文件还将信息存储在`/var/log/journal`中，如下所示：

```
[root@localhost philip]# ls /var/log/journal/
30012ff3b6d648a09e33e4927d140504
[root@localhost philip]#
```

我们甚至可以深入了解并查看`/var/journal/30012ff3b6d648a09e33e4927d140504`下的更多日志文件，如下所示：

```
[root@localhost philip]# ls /var/log/journal/30012ff3b6d648a09e33e4927d140504/
system@000572748a062ca4-7a3da8346cf70fb7.journal~
system@0005746b23e241ef-7ed07e858f3a6f48.journal~
system@0005746c7d7bed2f-80a58e1cfa65a3dd.journal~
system@0005750b2d37139f-3ddba79811cf1357.journal~
system@123e7dba3db2484697ae1cc5bfff550d-0000000000000001-0005750b2cb5f7d4.journal
system.journal
user-1000@000572749f063152-ae4ff154ee396e12.journal~
user-1000@4e535b252cc04ea69811c152632aafcd-0000000000000907-000572749f062b74.journal
user-1000.journal
[root@localhost philip]#
```

太棒了！我们可以使用`journalctl`来公开这些信息。例如，我们可以查看与先前引导有关的日志；这可以通过传递`--list-boots`选项来查看：

```
[root@localhost philip]# journalctl --utc --list-boots
-6 6d6ff5ab30284bbe8da4c97e54298944 Tue 2018-07-31 14:57:23 UTC—Tue 2018-07-31 20:17:06 UTC
-5 a7a23120abff44c8bca6807f1711c1c2 Thu 2018-08-02 14:22:09 UTC—Sun 2018-08-12 14:18:21 UTC
-4 905ba9f3c37d46b69920466e9a93a67d Mon 2018-08-27 13:59:47 UTC—Mon 2018-08-27 15:06:04 UTC
-3 e4d2ad4c25df41a2b905fdcb8cfae312 Mon 2018-08-27 15:06:18 UTC—Mon 2018-08-27 15:37:50 UTC
-2 ae1c87d6ea6842da91eb4a1cba331ead Mon 2018-08-27 15:38:18 UTC—Mon 2018-08-27 20:22:15 UTC
-1 7cfc215cb74149748fe717b688630bd3 Mon 2018-08-27 20:22:33 UTC—Wed 2018-08-29 12:50:59 UTC
 0 d3cb4fafa63a41f99bd3cc4da0b74d1d Tue 2018-09-04 12:55:38 UTC—Fri 2018-09-07 19:59:02 UTC
[root@localhost philip]#
```

根据前面的输出，我们可以看到包含引导信息的七个文件；我们可以通过传递文件的偏移量来查看这些文件中的任何一个。每个文件的偏移量是第一列中的值。让我们看一下`-6`偏移量：

```
[root@localhost philip]# journalctl -b -6 --utc
-- Logs begin at Tue 2018-07-31 14:57:23 UTC, end at Fri 2018-09-07 20:01:02 UTC. --
Jul 31 14:57:23 localhost.localdomain kernel: Linux version 4.16.3-301.fc28.x86_64 (mockbuild@bkernel02.phx2.fedoraprojec>
Jul 31 14:57:23 localhost.localdomain kernel: Command line: BOOT_IMAGE=/vmlinuz-4.16.3-301.fc28.x86_64 root=/dev/mapper/f>
Jul 31 14:57:23 localhost.localdomain kernel: Disabled fast string operations
Jul 31 14:57:23 localhost.localdomain kernel: x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'
Jul 31 14:57:23 localhost.localdomain kernel: x86/fpu: Supporting XSAVE feature 0x002: 'SSE registers'
Jul 31 14:57:23 localhost.localdomain kernel: x86/fpu: Enabled xstate features 0x3, context size is 576 bytes, using 'sta>
Jul 31 14:57:23 localhost.localdomain kernel: e820: BIOS-provided physical RAM map:
 [root@localhost philip]#
```

为了简洁起见，已省略了一些输出。我们可以查看`/etc/systemd/journald.conf`：

```
[root@localhost philip]# cat /etc/systemd/journald.conf
[Journal]
#Storage=auto
#Compress=yes
#Seal=yes
#SplitMode=uid
#SyncIntervalSec=5m
#RateLimitIntervalSec=30s
#RateLimitBurst=1000
#SystemMaxUse=
#SystemKeepFree=
#SystemMaxFileSize=
#SystemMaxFiles=100
#RuntimeMaxUse=
#RuntimeKeepFree=
#RuntimeMaxFileSize=
#RuntimeMaxFiles=100
#MaxRetentionSec=
#MaxFileSec=1month
#ForwardToSyslog=no
#ForwardToKMsg=no
#ForwardToConsole=no
#ForwardToWall=yes
#TTYPath=/dev/console
#MaxLevelStore=debug
#MaxLevelSyslog=debug
#MaxLevelKMsg=notice
#MaxLevelConsole=info
#MaxLevelWall=emerg
#LineMax=48K
[root@localhost philip]#
```

为了简洁起见，已省略了一些输出。根据前面的输出，所有设置都是默认的；`＃`表示注释。我们可以通过传递`--since`选项来指定我们想要查看日志信息的日期：

```
root@localhost philip]# journalctl --since today --utc
-- Logs begin at Tue 2018-07-31 14:57:23 UTC, end at Fri 2018-09-07 20:01:02 UTC. --
Sep 07 04:00:58 localhost.localdomain systemd[1]: Started Update a database for mlocate.
Sep 07 04:00:58 localhost.localdomain audit[1]: SERVICE_START pid=1 uid=0 auid=4294967295 ses=4294967295 subj=system_u:sy>
Sep 07 04:00:58 localhost.localdomain systemd[1]: Starting update of the root trust anchor for DNSSEC validation in unbou>
Sep 07 04:00:59 localhost.localdomain systemd[1]: Started update of the root trust anchor for DNSSEC validation in unboun>
Sep 07 04:00:59 localhost.localdomain audit[1]: SERVICE_START pid=1 uid=0 auid=4294967295 ses=4294967295 subj=system_u:sy>
Sep 07 04:00:59 localhost.localdomain audit[1]: SERVICE_STOP pid=1 uid=0 auid=4294967295 ses=4294967295 subj=system_u:sys>
Sep 07 04:01:01 localhost.localdomain CROND[13532]: (root) CMD (run-parts /etc/cron.hourly)
Sep 07 04:01:01 localhost.localdomain run-parts[13535]: (/etc/cron.hourly) starting 0anacron
Sep 07 04:01:01 localhost.localdomain run-parts[13543]: (/etc/cron.hourly) finished 0anacron
Sep 07 04:01:01 localhost.localdomain anacron[13541]: Anacron started on 2018-09-07
Sep 07 04:01:01 localhost.localdomain anacron[13541]: Normal exit (0 jobs run)
Sep 07 04:01:19 localhost.localdomain audit[1]: SERVICE_STOP pid=1 uid=0 auid=4294967295 ses=4294967295 subj=system_u:sys>
Sep 07 04:05:16 localhost.localdomain dhclient[1011]: DHCPREQUEST on ens33 to 172.16.175.254 port 67 (xid=0x1269bc29)
[root@localhost philip]#
```

太棒了！为了简洁起见，已省略了一些输出。我们还可以用数字指定日期：

```
[root@localhost philip]# journalctl --since "2018-09-07 15:00:00"
-- Logs begin at Tue 2018-07-31 10:57:23 EDT, end at Fri 2018-09-07 16:11:54 EDT. --
Sep 07 15:01:01 localhost.localdomain CROND[16031]: (root) CMD (run-parts /etc/cron.hourly)
Sep 07 15:01:01 localhost.localdomain run-parts[16034]: (/etc/cron.hourly) starting 0anacron
Sep 07 15:01:01 localhost.localdomain run-parts[16040]: (/etc/cron.hourly) finished 0anacron
Sep 07 15:09:56 localhost.localdomain dhclient[1011]: DHCPREQUEST on ens33 to 172.16.175.254 port 67 (xid=0x1269bc29)
Sep 07 15:09:56 localhost.localdomain dhclient[1011]: DHCPACK from 172.16.175.254 (xid=0x1269bc29)
Sep 07 15:09:56 localhost.localdomain NetworkManager[833]: <info>  [1536347396.3834] dhcp4 (ens33):   address 172.16.175.>
Sep 07 15:09:56 localhost.localdomain NetworkManager[833]: <info>  [1536347396.3842] dhcp4 (ens33):   plen 24 (255.255.25>
Sep 07 15:09:56 localhost.localdomain NetworkManager[833]: <info>  [1536347396.3845] dhcp4 (ens33):   gateway 172.16.175.2
[root@localhost philip]#
```

为了简洁起见，已省略了一些输出。但是，我们可以看到与网络有关的信息。同样，我们可以在`/var/log/audit/audit.log`中查看认证信息。以下是此文件的摘录：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00153.jpeg)

干得好！从摘录中，我们可以看到登录尝试进入 Fedora 系统。此外，我们可以利用`journalctl`命令显示认证信息。我们可以传递`-u`选项并指定要查找的服务：

```
[root@localhost philip]# journalctl -u sshd.service
-- Logs begin at Tue 2018-07-31 10:57:23 EDT, end at Mon 2018-09-10 12:06:49 EDT. --
Sep 10 12:05:28 localhost.localdomain sshd[27585]: Invalid user ted from 172.16.175.132 port 37406
Sep 10 12:05:29 localhost.localdomain sshd[27585]: pam_unix(sshd:auth): check pass; user unknown
Sep 10 12:05:29 localhost.localdomain sshd[27585]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty>
Sep 10 12:05:31 localhost.localdomain sshd[27585]: Failed password for invalid user ted from 172.16.175.132 port 37406 ss>
Sep 10 12:05:32 localhost.localdomain sshd[27585]: pam_unix(sshd:auth): check pass; user unknown
Sep 10 12:05:34 localhost.localdomain sshd[27585]: Failed password for invalid user ted from 172.16.175.132 port 37406 ss>
Sep 10 12:05:54 localhost.localdomain sshd[27585]: pam_unix(sshd:auth): check pass; user unknown
Sep 10 12:05:56 localhost.localdomain sshd[27585]: Failed password for invalid user ted from 172.16.175.132 port 37406 ss>
Sep 10 12:05:56 localhost.localdomain sshd[27585]: Connection closed by invalid user ted 172.16.175.132 port 37406 [preau>
Sep 10 12:05:56 localhost.localdomain sshd[27585]: PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruse>
[root@localhost philip]#
```

从中，我们可以看到`journalctl`实用程序的有效性。

# 配置远程日志记录

查看本地系统的日志文件总是很好，但是如何管理远程日志呢？好吧，可以配置 Linux 系统执行远程日志记录。我们必须安装（如果尚未安装）日志记录软件。在本演示中，我们将使用 Fedora 28 作为日志记录客户端，Ubuntu 18 系统作为日志记录服务器。此外，我们将使用`rsyslog`作为日志记录软件。默认情况下，它已经安装在 Ubuntu 18 系统中。但是，在 Fedora 28 上，我们将不得不安装`rsyslog`软件。首先，让我们在 Fedora 28 中安装`rsyslog`软件。我们使用`dnf`命令，如下所示：

```
[root@localhost philip]# dnf search rsyslog
Last metadata expiration check: 1:38:20 ago on Mon 10 Sep 2018 10:41:18 AM EDT.
============================================= Name Exactly Matched: rsyslog ==============================================
rsyslog.x86_64 : Enhanced system logging and kernel message trapping daemon
============================================ Summary & Name Matched: rsyslog =============================================
rsyslog-mysql.x86_64 : MySQL support for rsyslog
rsyslog-hiredis.x86_64 : Redis support for rsyslog
rsyslog-doc.noarch : HTML documentation for rsyslog
[root@localhost philip]#
```

为了简洁起见，已省略了一些输出。我们找到了`rsyslog`软件包。接下来，我们将传递`install`选项以安装`rsyslog`软件包：

```
[root@localhost philip]# dnf install rsyslog.x86_64
Last metadata expiration check: 2:42:37 ago on Mon 10 Sep 2018 10:41:18 AM EDT.
Dependencies resolved.
==========================================================================================================================
 Package                       Arch                     Version                           Repository                 Size
==========================================================================================================================
Installing:
 rsyslog                       x86_64                   8.37.0-1.fc28                     updates                   697 k
Installing dependencies:
 libestr                       x86_64                   0.1.9-10.fc28                     fedora                     26 k
 libfastjson                   x86_64                   0.99.8-2.fc28                     fedora                     36 k
Transaction Summary
==========================================================================================================================
Install  3 Packages
Total download size: 759 k
Installed size: 2.2 M
Is this ok [y/N]: y
Installed:
 rsyslog.x86_64 8.37.0-1.fc28           libestr.x86_64 0.1.9-10.fc28           libfastjson.x86_64 0.99.8-2.fc28 
Complete!
[root@localhost philip]#
```

同样，出于简洁起见，某些输出已被省略。我们已成功安装了`rsyslog`软件包。现在，我们需要在文本编辑器（如 vi 或 nano）中编辑`/etc/rsyslog.conf`，并指定远程日志服务器的 IP 地址。我们是这样做的：

```
[root@localhost philip]# cat /etc/rsyslog.conf
# rsyslog configuration file
# For more information see /usr/share/doc/rsyslog-*/rsyslog_conf.html
# or latest version online at http://www.rsyslog.com/doc/rsyslog_conf.html
# If you experience problems, see http://www.rsyslog.com/doc/troubleshoot.html
#queue.maxdiskspace="1g"         # 1gb space limit (use as much as possible)
#queue.saveonshutdown="on"       # save messages to disk on shutdown
#queue.type="LinkedList"         # run asynchronously
#action.resumeRetryCount="-1"    # infinite retries if host is down
# # Remote Logging (we use TCP for reliable delivery)
# # remote_host is: name/ip, e.g. 192.168.0.1, port optional e.g. 10514
#Target="remote_host" Port="XXX" Protocol="tcp")
*.*         @172.16.175.132:514
[root@localhost philip]#
```

太棒了！出于简洁起见，某些输出已被省略。在前面的输出中，我们添加了最后一个条目`*.* @172.16.175.132:514`。这是通知本地系统将所有日志设施的`*.`消息以及所有`.*`严重性发送到`172.16.175.132`远程系统，使用`UDP`协议和`514`端口号。我们也可以更具体；例如，我们可以通过指定`emerg`关键字仅从每个设施发送紧急消息：

```
[root@localhost philip]# cat /etc/rsyslog.conf
# rsyslog configuration file
#queue.maxdiskspace="1g"         # 1gb space limit (use as much as possible)
#queue.saveonshutdown="on"       # save messages to disk on shutdown
#queue.type="LinkedList"         # run asynchronously
#action.resumeRetryCount="-1"    # infinite retries if host is down
# # Remote Logging (we use TCP for reliable delivery)
# # remote_host is: name/ip, e.g. 192.168.0.1, port optional e.g. 10514
#Target="remote_host" Port="XXX" Protocol="tcp")
*.emerg               @172.16.175.132:514
[root@localhost philip]#
```

每个具有紧急消息的设施都将通过 UDP 发送到远程服务器。到目前为止，我们一直在使用 UDP 发送日志，但也可以使用 TCP 发送日志。为了使用 TCP 作为传输方式，我们需要在第一个`@`前面再添加一个`@`。我们将把消息类型从`emerg`更改为`info`，并使用 TCP 作为传输协议，如下所示：

```
[root@localhost philip]# cat /etc/rsyslog.conf
# rsyslog configuration file
 #queue.saveonshutdown="on"       # save messages to disk on shutdown
#queue.type="LinkedList"         # run asynchronously
#action.resumeRetryCount="-1"    # infinite retries if host is down
# # Remote Logging (we use TCP for reliable delivery)
# # remote_host is: name/ip, e.g. 192.168.0.1, port optional e.g. 10514
#Target="remote_host" Port="XXX" Protocol="tcp")
*.info    @@172.16.175.132:514
[root@localhost philip]#
```

太棒了！出于简洁起见，某些输出已被省略。现在，最后一步是重新启动`rsyslog`守护进程，以使新更改生效。我们使用`systemctl`命令，如下所示，重新启动`rsyslog`守护进程：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00154.jpeg)

现在我们可以看到`rsyslog`守护进程正在运行。请注意在`systemctl`状态的底部，有一些关于连接到`172/16.175.132`的日志。这是因为我们尚未配置远程服务器以接受来自 Fedora 系统的日志。现在我们将前往 Ubuntu 系统并编辑`/etc/rsyslog.conf`并添加以下内容：

```
root@philip-virtual-machine:/var/log# cat /etc/rsyslog.conf
# provides UDP syslog reception
#module(load="imudp")
#input(type="imudp" port="514")
# provides TCP syslog reception
module(load="imtcp")
input(type="imtcp" port="514")
root@philip-virtual-machine:/var/log#
```

太棒了！出于简洁起见，某些输出已被省略。我们已经去掉了`TCP`部分的注释。最后一步是重新启动`rsyslog`守护进程；可以使用`systemctl`命令，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/comptia-linux-crt-gd/img/00155.jpeg)

我们可以看到`rsyslog`守护进程正常运行。现在，为了测试，我们将检查`/var/log/syslog`以查看来自 Fedora 日志客户端的日志。我们可以使用另一个强大的命令来生成测试日志：`logger`命令。以下是我们如何使用`logger`命令。

在 Fedora 28 `rsyslog`客户端上，我们发出以下命令：

```
[root@localhost philip]# logger This is the Fedora Logging client 172.16.175.129
[root@localhost philip]# logger This is another Logging test from the Fedora client 172.16.175.129
[root@localhost philip]#
```

在 Ubuntu 18 `rsyslog`服务器上，我们将看到以下内容：

```
root@philip-virtual-machine:/home/philip# tail -f /var/log/syslog
Sep 10 14:20:46 localhost dbus-daemon[720]: [system] Successfully activated service 'net.reactivated.Fprint'
Sep 10 14:20:46 localhost systemd[1]: Started Fingerprint Authentication Daemon.
Sep 10 14:20:50 localhost kscreenlocker_greet[58309]: QObject::disconnect: No such signal QObject::screenChanged(QScreen*)
Sep 10 14:22:25 localhost philip[58396]: This is the Fedora Logging client 172.16.175.129
Sep 10 14:23:04 localhost philip[58403]: This is another Logging test from the Fedora client 172.16.175.129
^C
root@philip-virtual-machine:/home/philip#
```

太棒了！我们可以看到`rsyslog`客户端确实将日志通过网络发送到 Ubuntu 18 `rsyslog`服务器。

# 摘要

在本章中，主要关注系统时间和日志的维护。特别是，我们看了一下如何操纵系统时间；我们广泛使用了`date`和`timedatectl`命令。此外，我们还涉及了用于更改日期的正则表达式。此外，我们还处理了硬件时钟；我们看到了如何同步系统时钟和硬件时钟。接下来，我们处理了日志记录；我们探索了常见的日志文件。在 Ubuntu 环境中，我们探索了`/var/log/syslog`文件，而在 Fedora 28 中，我们广泛使用了`journalctl`命令来查看日志。最后，我们处理了远程日志记录；我们在 Fedora 28 中安装了`rsyslog`软件包，并将其配置为`rsyslog`客户端。然后，我们转到 Ubuntu 18 并配置了其`/etc/rsyslog.conf`文件以接受远程日志并使用 TCP 作为传输协议。然后，我们在 Fedora 系统上生成了测试日志，并验证了我们在 Ubuntu `rsyslog`服务器上收到了日志。

在下一章中，我们将深入探讨互联网协议的世界。我们将涉及各种 IPv4 地址和 IPv6 地址。此外，我们将介绍对 IPv4 地址进行子网划分以及缩短冗长的 IPv6 地址的方法。最后，我们将介绍一些著名的协议。

# 问题

1.  使用`date`命令设置日期的选项是什么？

A. `-s`

B. `-S`

C. `-t`

D. `-u`

1.  在`timedatectl`命令中，哪个选项用于关闭同步？

A. `--set-ntp`

B. `--set-sync`

C. `set-ntp`

D. `set-sync`

1.  使用哪个正则表达式只设置`date`命令的时间？

A. -$%t

B. +$T

C. -$t

D. +%T

1.  使用`timedatectl`命令设置时间的选项是什么？

A. set-time

B. set-clock

C. set-sync

D. --set-zone

1.  从`/usr/share/zoneinfo/<zone>`生成哪个文件？

A. `/etc/synczone`

B. `/etc/timedate`

C. `/etc/clock`

D. `/etc/localtime`

1.  在新的 Ubuntu 发行版中，哪个命令替代了`tzconfig`命令？

A. `tztime`

B. `tzdata`

C. `tzzone`

D. `tzclock`

1.  用于设置时区的命令是什么？

A. tzsync

B. tzselect

C. tzdate

D. tztime

1.  `journalctl`命令的哪个选项列出特定守护进程的日志？

1.  -a

1.  -e

1.  -b

1.  -u

1.  当我们在`/etc/rsyslog.conf`中有`*.* @@1.2.3.4`时，使用了哪种协议？

1.  ICMP

1.  UDP

1.  ECHO

1.  TCP

1.  哪个命令可以用于发送测试消息，作为验证`rsyslog`客户端与`rsyslog`服务器通信的一部分？

1.  `send-message`

1.  `nc`

1.  `logger`

1.  `logrotate`

# 更多阅读

+   这个网站提供了关于日志的有用信息：[`www.digitalocean.com/community/tutorials/how-to-view-and-configure-linux-logs-on-ubuntu-and-centos`](https://www.digitalocean.com/community/tutorials/how-to-view-and-configure-linux-logs-on-ubuntu-and-centos)

+   这个网站提供了关于时钟的有用信息：[`www.systutorials.com/docs/linux/man/n-clock/`](https://www.systutorials.com/docs/linux/man/n-clock/)

+   这个网站提供了关于日志的有用信息：[`freelinuxtutorials.com/tutorials/configure-centralized-syslog-server-in-linux-setup-syslog-clients-on-different-platforms/`](http://freelinuxtutorials.com/tutorials/configure-centralized-syslog-server-in-linux-setup-syslog-clients-on-different-platforms/)
