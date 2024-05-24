# 将 Linux 迁移到微软 Azure（五）

> 原文：[`zh.annas-archive.org/md5/DFC4E6F489A560394D390945DB597424`](https://zh.annas-archive.org/md5/DFC4E6F489A560394D390945DB597424)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：理解 Linux 用户和内核限制

在上一章中，我们使用了`lsof`和`strace`等工具来确定应用程序问题的根本原因。

在本章中，我们将再次确定应用程序相关问题的根本原因。但是，我们还将专注于学习和理解 Linux 用户和内核的限制。

# 一个报告的问题

就像上一章专注于自定义应用程序的问题一样，今天的问题也来自同一个自定义应用程序。

今天，我们将处理应用支持团队报告的一个问题。然而，这一次支持团队能够为我们提供相当多的信息。

我们在第九章中处理的应用程序，*使用系统工具来排除应用程序问题*，现在通过`端口 25`接收消息并将其存储在队列目录中。定期会运行一个作业来处理这些排队的消息，但是这个作业*似乎不再工作*。

应用支持团队已经注意到队列中积压了大量消息。然而，尽管他们已经尽可能地排除了问题，但他们卡住了，需要我们的帮助。

# 为什么作业失败了？

由于报告的问题是定时作业不起作用，我们应该首先关注作业本身。在这种情况下，我们有应用支持团队可以回答任何问题。所以，让我们再多了解一些关于这个作业的细节。

## 背景问题

以下是一系列快速问题，应该能够为您提供额外的信息：

+   作业是如何运行的？

+   如果需要，我们可以手动运行作业吗？

+   这个作业执行什么？

这三个问题可能看起来很基础，但它们很重要。让我们首先看一下应用团队提供的答案：

+   作业是如何运行的？

*作业是作为 cron 作业执行的。*

+   如果需要，我们可以手动运行作业吗？

*是的，可以根据需要手动执行作业。*

+   这个作业执行什么？

*作业以 vagrant 用户身份执行/opt/myapp/bin/processor 命令*。

前面的三个问题很重要，因为它们将为我们节省大量的故障排除时间。第一个问题关注作业是如何执行的。由于报告的问题是作业不起作用，我们还不知道问题是因为作业没有运行还是作业正在执行但由于某种原因失败。

第一个问题的答案告诉我们，这个作业是由在 Linux 上运行的**cron 守护程序**`crond`执行的。这很有用，因为我们可以使用这些信息来确定作业是否正在执行。一般来说，有很多方法可以执行定时作业。有时执行定时作业的软件在不同的系统上运行，有时在同一个本地系统上运行。

在这种情况下，作业是由`crond`在同一台服务器上执行的。

第二个问题也很重要。就像我们在上一章中需要手动启动应用程序一样，我们可能也需要对这个报告的问题执行这个故障排除步骤。根据答案，似乎我们可以根据需要多次执行这个命令。

第三个问题很有用，因为它不仅告诉我们正在执行哪个命令，还告诉我们要注意哪个作业。cron 作业是一种非常常见的调度任务的方法。一个系统通常会有许多已调度的 cron 作业。

## cron 作业是否在运行？

由于我们知道作业是由`crond`执行的，我们应该首先检查作业是否正在执行。为此，我们可以在相关服务器上检查 cron 日志。例如，考虑以下日志：

```
# ls -la /var/log/cron*
-rw-r--r--. 1 root root 30792 Jun 10 18:05 /var/log/cron
-rw-r--r--. 1 root root 28261 May 18 03:41 /var/log/cron-20150518
-rw-r--r--. 1 root root  6152 May 24 21:12 /var/log/cron-20150524
-rw-r--r--. 1 root root 42565 Jun  1 15:50 /var/log/cron-20150601
-rw-r--r--. 1 root root 18286 Jun  7 16:22 /var/log/cron-20150607

```

具体来说，在基于 Red Hat 的 Linux 系统上，我们可以检查`/var/log/cron`日志文件。我在前一句中指定了“基于 Red Hat 的”是因为在非 Red Hat 系统上，cron 日志可能位于不同的日志文件中。例如，基于 Debian 的系统默认为`/var/log/syslog`。

如果我们不知道哪个日志文件包含 cron 日志，有一个简单的技巧可以找到它。只需运行以下命令行：

```
# grep -ic cron /var/log/* | grep -v :0
/var/log/cron:400
/var/log/cron-20150518:379
/var/log/cron-20150524:86
/var/log/cron-20150601:590
/var/log/cron-20150607:248
/var/log/messages:1
/var/log/secure:1

```

前面的命令将使用`grep`在`/var/log`中的所有日志文件中搜索字符串`cron`。该命令还将搜索`Cron`、`CRON`、`cRon`等，因为我们在`grep`命令中添加了`-i`（不区分大小写）标志。这告诉`grep`在不区分大小写的模式下搜索。基本上，这意味着任何匹配单词`cron`的地方都会被找到，即使单词是大写或混合大小写。我们还在`grep`命令中添加了`-c`（计数）标志，这会导致它计算它找到的实例数：

```
/var/log/cron:400

```

如果我们看第一个结果，我们可以看到`grep`在`/var/log/cron`中找到了 400 个“cron”单词的实例。

最后，我们将结果重定向到另一个带有`-v`标志和`:0`的`grep`命令。这个`grep`将获取第一次执行的结果，并省略（-v）任何包含字符串`:0`的行。这对于将结果限制为只有包含其中的`cron`字符串的文件非常有用。

从前面的结果中，我们可以看到文件`/var/log/cron`中包含了最多的“cron”单词实例。这一事实本身就是`/var/log/cron`是`crond`守护程序的日志文件的一个很好的指示。

既然我们知道哪个日志文件包含了我们正在寻找的日志消息，我们可以查看该日志文件的内容。由于这个日志文件非常大，我们将使用`less`命令来读取这个文件：

```
# less /var/log/cron

```

由于这个日志中包含了相当多的信息，我们只会关注能帮助解释问题的日志条目。以下部分是一组有趣的日志消息，应该能回答我们的作业是否正在运行：

```
Jun 10 18:01:01 localhost CROND[2033]: (root) CMD (run-parts /etc/cron.hourly)
Jun 10 18:01:01 localhost run-parts(/etc/cron.hourly)[2033]: starting 0anacron
Jun 10 18:01:01 localhost run-parts(/etc/cron.hourly)[2042]: finished 0anacron
Jun 10 18:01:01 localhost run-parts(/etc/cron.hourly)[2033]: starting 0yum-hourly.cron
Jun 10 18:01:01 localhost run-parts(/etc/cron.hourly)[2048]: finished 0yum-hourly.cron
Jun 10 18:05:01 localhost CROND[2053]: (vagrant) CMD (/opt/myapp/bin/processor --debug --config /opt/myapp/conf/config.yml > /dev/null)
Jun 10 18:10:01 localhost CROND[2086]: (root) CMD (/usr/lib64/sa/sa1 1 1)
Jun 10 18:10:01 localhost CROND[2087]: (vagrant) CMD (/opt/myapp/bin/processor --debug --config /opt/myapp/conf/config.yml > /dev/null)
Jun 10 18:15:01 localhost CROND[2137]: (vagrant) CMD (/opt/myapp/bin/processor --debug --config /opt/myapp/conf/config.yml > /dev/null)
Jun 10 18:20:01 localhost CROND[2147]: (root) CMD (/usr/lib64/sa/sa1 1 1)

```

前面的日志消息显示了相当多的行。让我们分解日志以更好地理解正在执行的内容。考虑以下行：

```
Jun 10 18:01:01 localhost CROND[2033]: (root) CMD (run-parts /etc/cron.hourly)
Jun 10 18:01:01 localhost run-parts(/etc/cron.hourly)[2033]: starting 0anacron
Jun 10 18:01:01 localhost run-parts(/etc/cron.hourly)[2042]: finished 0anacron
Jun 10 18:01:01 localhost run-parts(/etc/cron.hourly)[2033]: starting 0yum-hourly.cron
Jun 10 18:01:01 localhost run-parts(/etc/cron.hourly)[2048]: finished 0yum-hourly.cron

```

前几行似乎不是我们正在寻找的作业，而是`cron.hourly`作业。

在 Linux 系统上，有多种方法可以指定 cron 作业。在 RHEL 系统上，`/etc/`目录下有几个以`cron`开头的目录：

```
# ls -laF /etc/ | grep cron
-rw-------.  1 root root      541 Jun  9  2014 anacrontab
drwxr-xr-x.  2 root root       34 Jan 23 15:43 cron.d/
drwxr-xr-x.  2 root root       62 Jul 22  2014 cron.daily/
-rw-------.  1 root root        0 Jun  9  2014 cron.deny
drwxr-xr-x.  2 root root       44 Jul 22  2014 cron.hourly/
drwxr-xr-x.  2 root root        6 Jun  9  2014 cron.monthly/
-rw-r--r--.  1 root root      451 Jun  9  2014 crontab
drwxr-xr-x.  2 root root        6 Jun  9  2014 cron.weekly/

```

`cron.daily`、`cron.hourly`、`cron.monthly`和`cron.weekly`目录都是可以包含脚本的目录。这些脚本将按照目录名称中指定的时间运行。

例如，让我们看一下`/etc/cron.hourly/0yum-hourly.cron`：

```
# cat /etc/cron.hourly/0yum-hourly.cron
#!/bin/bash

# Only run if this flag is set. The flag is created by the yum-cron init
# script when the service is started -- this allows one to use chkconfig and
# the standard "service stop|start" commands to enable or disable yum-cron.
if [[ ! -f /var/lock/subsys/yum-cron ]]; then
 exit 0
fi

# Action!
exec /usr/sbin/yum-cron /etc/yum/yum-cron-hourly.conf

```

前面的文件是一个简单的`bash`脚本，`crond`守护程序将每小时执行一次，因为它在`cron.hourly`目录中。一般来说，这些目录中包含的脚本是由系统服务放在那里的。不过，这些目录也对系统管理员开放，可以放置他们自己的脚本。

## 用户 crontabs

如果我们继续查看日志文件，我们可以看到一个与我们自定义作业相关的条目：

```
Jun 10 18:10:01 localhost CROND[2087]: (vagrant) CMD (/opt/myapp/bin/processor --debug --config /opt/myapp/conf/config.yml > /dev/null)

```

这一行显示了应用支持团队引用的`processor`命令。这一行必须是应用支持团队遇到问题的作业。日志条目告诉我们很多有用的信息。首先，它为我们提供了传递给这个作业的命令行选项：

```
/opt/myapp/bin/processor --debug --config /opt/myapp/conf/config.yml > /dev/null

```

它还告诉我们作业是以`vagrant`身份执行的。不过，这个日志条目告诉我们最重要的是作业正在执行。

既然我们知道作业正在执行，我们应该验证作业是否成功。为了做到这一点，我们将采取一种简单的方法，手动执行作业：

```
$ /opt/myapp/bin/processor --debug --config /opt/myapp/conf/config.yml
Initializing with configuration file /opt/myapp/conf/config.yml
- - - - - - - - - - - - - - - - - - - - - - - - - -
Starting message processing job
Traceback (most recent call last):
 File "app.py", line 28, in init app (app.c:1488)
IOError: [Errno 24] Too many open files: '/opt/myapp/queue/1433955823.29_0.txt'

```

我们应该从 cron 任务的末尾省略`> /dev/null`，因为这将把输出重定向到`/dev/null`。这是一种常见的丢弃 cron 作业输出的方法。对于此手动执行，我们可以利用输出来帮助解决问题。

一旦执行，作业似乎会失败。它不仅失败了，而且还产生了一个错误消息：

```
IOError: [Errno 24] Too many open files: '/opt/myapp/queue/1433955823.29_0.txt'

```

这个错误很有趣，因为它似乎表明应用程序打开了太多文件。*这有什么关系呢？*

# 了解用户限制

在 Linux 系统上，每个进程都受到限制。这些限制是为了防止进程使用太多的系统资源。

虽然这些限制适用于每个用户，但是可以为每个用户设置不同的限制。要检查`vagrant`用户默认设置的限制，我们可以使用`ulimit`命令：

```
$ ulimit -a
core file size          (blocks, -c) 0
data seg size           (kbytes, -d) unlimited
scheduling priority             (-e) 0
file size               (blocks, -f) unlimited
pending signals                 (-i) 3825
max locked memory       (kbytes, -l) 64
max memory size         (kbytes, -m) unlimited
open files                      (-n) 1024
pipe size            (512 bytes, -p) 8
POSIX message queues     (bytes, -q) 819200
real-time priority              (-r) 0
stack size              (kbytes, -s) 8192
cpu time               (seconds, -t) unlimited
max user processes              (-u) 3825
virtual memory          (kbytes, -v) unlimited
file locks                      (-x) unlimited

```

当我们执行`ulimit`命令时，我们是以 vagrant 用户的身份执行的。这很重要，因为当我们以任何其他用户（包括 root）的身份运行`ulimit`命令时，输出将是该用户的限制。

如果我们查看`ulimit`命令的输出，我们可以看到有很多可以设置的限制。

## 文件大小限制

让我们来看一下并分解一些关键限制：

```
file size               (blocks, -f) unlimited

```

第一个有趣的项目是`文件大小`限制。这个限制将限制用户可以创建的文件的大小。vagrant 用户的当前设置是`无限制`，但如果我们将这个值设置为一个较小的数字会发生什么呢？

我们可以通过执行`ulimit -f`，然后跟上要限制文件的块数来做到这一点。例如，考虑以下命令行：

```
$ ulimit -f 10

```

将值设置为`10`后，我们可以通过再次运行`ulimit -f`来验证它是否生效，但这次不带值：

```
$ ulimit -f
10

```

现在我们的限制设置为 10 个块，让我们尝试使用`dd`命令创建一个 500MB 的文件：

```
$ dd if=/dev/zero of=/var/tmp/bigfile bs=1M count=500
File size limit exceeded

```

关于 Linux 用户限制的一个好处是通常提供的错误是不言自明的。我们可以从前面的输出中看到，`dd`命令不仅无法创建文件，还收到了一个错误，指出文件大小限制已超出。

## 最大用户进程限制

另一个有趣的限制是`最大进程`限制：

```
max user processes              (-u) 3825

```

这个限制防止用户一次运行*太多的进程*。这是一个非常有用和有趣的限制，因为它可以轻松地防止一个恶意应用程序接管系统。

这也可能是您经常会遇到的限制。这对于启动许多子进程或线程的应用程序尤其如此。要查看此限制如何工作，我们可以将设置更改为`10`：

```
$ ulimit -u 10
$ ulimit -u
10

```

与文件大小限制一样，我们可以使用`ulimit`命令修改进程限制。但这次，我们使用`-u`标志。每个用户限制都有自己独特的标志与`ulimit`命令。我们可以在`ulimit -a`的输出中看到这些标志，当然，每个标志都在`ulimit`的 man 页面中引用。

既然我们已经将我们的进程限制为`10`，我们可以通过运行一个命令来看到限制的执行：

```
$ man ulimit
man: fork failed: Resource temporarily unavailable

```

通过 SSH 登录 vagrant 用户，我们已经在使用多个进程。很容易遇到`10`个进程的限制，因为我们运行的任何新命令都会超出我们的登录限制。

从前面的例子中，我们可以看到当执行`man`命令时，它无法启动子进程，因此返回了一个错误，指出`资源暂时不可用`。

## 打开文件限制

我想要探索的最后一个有趣的用户限制是`打开文件`限制：

```
open files                      (-n) 1024

```

`打开文件`限制将限制进程打开的文件数不超过定义的数量。此限制可用于防止进程一次打开太多文件。当防止应用程序占用系统资源过多时，这是一种很有用的方法。

像其他限制一样，让我们看看当我们将这个限制减少到一个非常不合理的数字时会发生什么：

```
$ ulimit -n 2
$ ls
-bash: start_pipeline: pgrp pipe: Too many open files
ls: error while loading shared libraries: libselinux.so.1: cannot open shared object file: Error 24

```

与其他示例一样，我们在这种情况下收到了一个错误，即`Too many open files`。但是，这个错误看起来很熟悉。如果我们回顾一下从我们的计划作业收到的错误，我们就会明白为什么。

```
IOError: [Errno 24] Too many open files: '/opt/myapp/queue/1433955823.29_0.txt'

```

将我们的最大打开文件数设置为`2`后，`ls`命令产生了一个错误；这个错误与我们的应用程序之前执行时收到的完全相同的错误消息。

这是否意味着我们的应用程序试图打开的文件比我们的系统配置允许的要多？这是一个很有可能的情况。

# 更改用户限制

由于我们怀疑`open files`限制阻止了应用程序的执行，我们可以将其限制设置为更高的值。但是，这并不像执行`ulimit -n`那样简单；执行时得到的输出如下：

```
$ ulimit -n
1024
$ ulimit -n 5000
-bash: ulimit: open files: cannot modify limit: Operation not permitted
$ ulimit -n 4096
$ ulimit -n
4096

```

在我们的示例系统上，默认情况下，vagrant 用户被允许将`open files`限制提高到`4096`。从前面的错误中我们可以看到，任何更高的值都被拒绝；但是像大多数 Linux 一样，我们可以改变这一点。

## limits.conf 文件

我们一直在使用和修改的用户限制是 Linux 的 PAM 系统的一部分。PAM 或可插拔认证模块是一个提供模块化认证系统的系统。

例如，如果我们的系统要使用 LDAP 进行身份验证，`pam_ldap.so`库将用于提供此功能。但是，由于我们的系统使用本地用户进行身份验证，因此`pam_localuser.so`库处理用户身份验证。

如果我们阅读`/etc/pam.d/system-auth`文件，我们可以验证这一点：

```
$ cat /etc/pam.d/system-auth
#%PAM-1.0
# This file is auto-generated.
# User changes will be destroyed the next time authconfig is run.
auth        required      pam_env.so
auth        sufficient    pam_unix.so nullok try_first_pass
auth        requisite     pam_succeed_if.so uid >= 1000 quiet_success
auth        required      pam_deny.so

account     required      pam_unix.so
account     sufficient    pam_localuser.so
account     sufficient    pam_succeed_if.so uid < 1000 quiet
account     required      pam_permit.so

password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok
password    required      pam_deny.so

session     optional      pam_keyinit.so revoke
session     required      pam_limits.so
-session     optional      pam_systemd.so
session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session     required      pam_unix.so

```

如果我们看一下前面的例子，我们可以看到`pam_localuser.so`与`account`一起列在第一列：

```
account     sufficient    pam_localuser.so

```

这意味着`pam_localuser.so`模块是一个`sufficient`模块，允许账户被使用，这基本上意味着如果他们有正确的`/etc/passwd`和`/etc/shadow`条目，用户就能够登录。

```
session     required      pam_limits.so

```

如果我们看一下前面的行，我们可以看到用户限制是在哪里执行的。这行基本上告诉系统`pam_limits.so`模块对所有用户会话都是必需的。这有效地确保了`pam_limits.so`模块识别的用户限制在每个用户会话上都得到执行。

这个 PAM 模块的配置位于`/etc/security/limits.conf`和`/etc/security/limits.d/`中。

```
$ cat /etc/security/limits.conf
#This file sets the resource limits for the users logged in via PAM.
#        - core - limits the core file size (KB)
#        - data - max data size (KB)
#        - fsize - maximum filesize (KB)
#        - memlock - max locked-in-memory address space (KB)
#        - nofile - max number of open files
#        - rss - max resident set size (KB)
#        - stack - max stack size (KB)
#        - cpu - max CPU time (MIN)
#        - nproc - max number of processes
#        - as - address space limit (KB)
#        - maxlogins - max number of logins for this user
#        - maxsyslogins - max number of logins on the system
#        - priority - the priority to run user process with
#        - locks - max number of file locks the user can hold
#        - sigpending - max number of pending signals
#        - msgqueue - max memory used by POSIX message queues (bytes)
#        - nice - max nice priority allowed to raise to values: [-20, 19]
#        - rtprio - max realtime priority
#
#<domain>      <type>  <item>         <value>
#

#*               soft    core            0
#*               hard    rss             10000
#@student        hard    nproc           20
#@faculty        soft    nproc           20
#@faculty        hard    nproc           50
#ftp             hard    nproc           0
#@student        -       maxlogins       4

```

当我们阅读`limits.conf`文件时，我们可以看到关于用户限制的相当多有用的信息。

在这个文件中，列出了可用的限制以及该限制强制执行的描述。例如，在前面的命令行中，我们可以看到`open files`限制的数量：

```
#        - nofile - max number of open files

```

从这一行我们可以看到，如果我们想改变用户可用的打开文件数，我们需要使用`nofile`类型。除了列出每个限制的作用，`limits.conf`文件还包含了为用户和组设置自定义限制的示例：

```
#ftp             hard    nproc           0

```

通过这个例子，我们可以看到我们需要使用什么格式来设置限制；但我们应该将限制设置为多少呢？如果我们回顾一下作业中的错误，我们会发现错误列出了`/opt/myapp/queue`目录中的一个文件：

```
IOError: [Errno 24] Too many open files: '/opt/myapp/queue/1433955823.29_0.txt'

```

可以肯定地说，应用程序正在尝试打开此目录中的文件。因此，为了确定这个进程需要打开多少文件，让我们通过以下命令行找出这个目录中有多少文件存在：

```
$ ls -la /opt/myapp/queue/ | wc -l
492304

```

前面的命令使用`ls -la`列出`queue/`目录中的所有文件和目录，并将输出重定向到`wc -l`。`wc`命令将从提供的输出中计算行数（`-l`），这基本上意味着在`queue/`目录中有 492,304 个文件和/或目录。

鉴于数量很大，我们应该将`打开文件`限制数量设置为`500000`，足以处理`queue/`目录，以防万一再多一点。我们可以通过将以下行附加到`limits.conf`文件来实现这一点：

```
# vi /etc/security/limits.conf

```

在使用`vi`或其他文本编辑器添加我们的行之后，我们可以使用`tail`命令验证它是否存在：

```
$ tail /etc/security/limits.conf
#@student        hard    nproc           20
#@faculty        soft    nproc           20
#@faculty        hard    nproc           50
#ftp             hard    nproc           0
#@student        -       maxlogins       4

vagrant    soft  nofile    100000
vagrant    hard  nofile    500000

# End of file

```

更改这些设置并不意味着我们的登录 shell 立即具有`500000`的限制。我们的登录会话仍然设置了`4096`的限制。

```
$ ulimit -n
4096

```

我们还不能将其增加到该值以上。

```
$ ulimit -n 9000
-bash: ulimit: open files: cannot modify limit: Operation not permitted

```

为了使我们的更改生效，我们必须再次登录到我们的用户。

正如我们之前讨论的，这些限制是由 PAM 设置的，在我们的 shell 会话登录期间应用。由于这些限制是在登录期间设置的，所以我们仍然受到上次登录时采用的先前数值的限制。

要获取新的限制，我们必须注销并重新登录（或生成一个新的登录会话）。在我们的例子中，我们将注销我们的 shell 并重新登录。

```
$ ulimit -n
100000
$ ulimit -n 501000
-bash: ulimit: open files: cannot modify limit: Operation not permitted
$ ulimit -n 500000
$ ulimit -n
500000

```

如果我们看一下前面的命令行，我们会发现一些非常有趣的东西。

当我们这次登录时，我们的文件限制数量被设置为`100000`，这恰好是我们在`limits.conf`文件中设置的`soft`限制。这是因为`soft`限制是每个会话默认设置的限制。

`hard`限制是该用户可以设置的高于`soft`限制的最高值。我们可以在前面的例子中看到这一点，因为我们能够将`nofile`限制设置为`500000`，但不能设置为`501000`。

### 未来保护定时作业

我们将`soft`限制设置为`100000`的原因是因为我们计划在未来处理类似的情况。将`soft`限制设置为`100000`，运行这个定时作业的 cron 作业将被限制为 100,000 个打开文件。然而，由于`hard`限制设置为`500000`，某人可以在他们的登录会话中手动运行具有更高限制的作业。

只要`queue`目录中的文件数量不超过 500,000，就不再需要任何人编辑`/etc/security/limits.conf`文件。

## 再次运行作业

现在我们的限制已经增加，我们可以尝试再次运行作业。

```
$ /opt/myapp/bin/processor --debug --config /opt/myapp/conf/config.yml
Initializing with configuration file /opt/myapp/conf/config.yml
- - - - - - - - - - - - - - - - - - - - - - - - - -
Starting message processing job
Traceback (most recent call last):
 File "app.py", line 28, in init app (app.c:1488)
IOError: [Errno 23] Too many open files in system: '/opt/myapp/queue/1433955989.86_5.txt'

```

我们再次收到了一个错误。然而，这次错误略有不同。

在上一次运行中，我们收到了以下错误。

```
IOError: [Errno 24] Too many open files: '/opt/myapp/queue/1433955823.29_0.txt'

```

然而，这一次我们收到了这个错误。

```
IOError: [Errno 23] Too many open files in system: '/opt/myapp/queue/1433955989.86_5.txt'

```

这种差异非常微妙，但在第二次运行时，我们的错误说明了**系统中打开的文件太多**，而我们第一次运行时没有包括`in system`。这是因为我们遇到了不同类型的限制，不是**用户**限制，而是**系统**限制。

# 内核可调参数

Linux 内核本身也可以对系统设置限制。这些限制是基于内核参数定义的。其中一些参数是静态的，不能在运行时更改；而其他一些可以。当内核参数可以在运行时更改时，这被称为**可调参数**。

我们可以使用`sysctl`命令查看静态和可调内核参数及其当前值。

```
# sysctl -a | head
abi.vsyscall32 = 1
crypto.fips_enabled = 0
debug.exception-trace = 1
debug.kprobes-optimization = 1
dev.hpet.max-user-freq = 64
dev.mac_hid.mouse_button2_keycode = 97
dev.mac_hid.mouse_button3_keycode = 100
dev.mac_hid.mouse_button_emulation = 0
dev.parport.default.spintime = 500
dev.parport.default.timeslice = 200

```

由于有许多参数可用，我使用`head`命令将输出限制为前 10 个。我们之前收到的错误提到了系统上的限制，这表明我们可能遇到了内核本身施加的限制。

唯一的问题是我们如何知道哪一个？最快的答案当然是搜索谷歌。由于有很多内核参数（我们正在使用的系统上有 800 多个），简单地阅读`sysctl –a`的输出并找到正确的参数是困难的。

一个更现实的方法是简单地搜索我们要修改的参数类型。我们的情况下，一个例子搜索可能是`Linux 参数最大打开文件数`。如果我们进行这样的搜索，很可能会找到参数以及如何修改它。然而，如果谷歌不是一个选择，还有另一种方法。

一般来说，内核参数的名称描述了参数控制的内容。

例如，如果我们要查找禁用 IPv6 的内核参数，我们首先会搜索`net`字符串，如网络：

```
# sysctl -a | grep -c net
556

```

然而，这仍然返回了大量结果。在这些结果中，我们可以看到字符串`ipv6`。

```
# sysctl -a | grep -c ipv6
233

```

尽管如此，还是有相当多的结果；但是，如果我们添加一个搜索字符串`disable`，我们会得到以下输出：

```
# sysctl -a | grep ipv6 | grep disable
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.enp0s3.disable_ipv6 = 0
net.ipv6.conf.enp0s8.disable_ipv6 = 0
net.ipv6.conf.lo.disable_ipv6 = 0

```

我们终于可以缩小可能的参数范围。但是，我们还不完全知道这些参数的作用。至少目前还不知道。

如果我们通过`/usr/share/doc`进行快速搜索，可能会找到一些解释这些设置作用的文档。我们可以通过使用`grep`在该目录中进行递归搜索来快速完成这个过程。为了保持输出简洁，我们可以添加`-l`（列出文件），这会导致`grep`只列出包含所需字符串的文件名：

```
# grep -rl net.ipv6 /usr/share/doc/
/usr/share/doc/grub2-tools-2.02/grub.html

```

在基于 Red Hat 的 Linux 系统中，`/usr/share/doc`目录用于系统手册之外的额外文档。如果我们只能使用系统本身的文档，`/usr/share/doc`目录是首要检查的地方之一。

## 查找打开文件的内核参数

由于我们喜欢用较困难的方式执行任务，我们将尝试识别潜在限制我们的内核参数，而不是在 Google 上搜索。这样做的第一步是在`sysctl`输出中搜索字符串`file`。

我们搜索`file`的原因是因为我们遇到了文件数量的限制。虽然这可能不会提供我们要识别的确切参数，但至少搜索会让我们有个起点：

```
# sysctl -a | grep file
fs.file-max = 48582
fs.file-nr = 1088  0  48582
fs.xfs.filestream_centisecs = 3000

```

事实上，搜索`file`可能实际上是一个非常好的选择。仅仅根据参数的名称，对我们可能感兴趣的两个参数是`fs.file-max`和`fs.file-nr`。在这一点上，我们不知道哪一个控制打开文件的数量，或者这两个参数是否有任何作用。

要了解更多信息，我们可以搜索`doc`目录。

```
# grep -r fs.file- /usr/share/doc/
/usr/share/doc/postfix-2.10.1/README_FILES/TUNING_README:
fs.file-max=16384

```

看起来一个名为`TUNING_README`的文档，位于 Postfix 服务文档中，提到了我们至少一个值的参考。让我们查看一下文件，看看这个文档对这个内核参数有什么说法：

```
* Configure the kernel for more open files and sockets. The details are
 extremely system dependent and change with the operating system version. Be
 sure to verify the following information with your system tuning guide:

 o Linux kernel parameters can be specified in /etc/sysctl.conf or changed
 with sysctl commands:

 fs.file-max=16384
 kernel.threads-max=2048

```

如果我们阅读文件中列出我们的内核参数周围的内容，我们会发现它明确指出了*配置内核以获得更多打开文件和套接字*的参数。

这个文档列出了两个内核参数，允许更多的打开文件和套接字。第一个被称为`fs.file-max`，这也是我们在`sysctl`搜索中识别出的一个。第二个被称为`kernel.threads-max`，这是相当新的。

仅仅根据名称，似乎我们想要修改的可调参数是`fs.file-max`参数。让我们看一下它的当前值：

```
# sysctl fs.file-max
fs.file-max = 48582

```

我们可以通过执行`sysctl`命令，后跟参数名称（如前面的命令行所示）来列出此参数的当前值。这将简单地显示当前定义的值；看起来设置为`48582`，远低于我们当前的用户限制。

### 提示

在前面的例子中，我们在一个 postfix 文档中找到了这个参数。虽然这可能很好，但并不准确。如果您经常需要在本地搜索内核参数，最好安装`kernel-doc`软件包。`kernel-doc`软件包包含了大量信息，特别是关于可调参数的信息。

## 更改内核可调参数

由于我们认为`fs.file-max`参数控制系统可以打开的最大文件数，我们应该更改这个值以允许我们的作业运行。

像大多数 Linux 上的系统配置项一样，有更改此值的临时和重新启动的选项。之前我们将`limits.conf`文件设置为允许 vagrant 用户能够以`软`限制打开 100,000 个文件，以`硬`限制打开 500,000 个文件。问题是我们是否希望这个用户能够正常操作打开 500,000 个文件？还是应该是一次性任务来纠正我们目前面临的问题？

答案很简单：*这取决于情况！*

如果我们看一下我们目前正在处理的情况，所讨论的工作已经有一段时间没有运行了。因此，队列中积压了大量的消息。但是这些并不是正常的情况。

早些时候，当我们将用户限制设置为 100,000 个文件时，我们这样做是因为这对于这个作业来说是一个相当合适的值。考虑到这一点，我们还应该将内核参数设置为略高于`100000`的值，但不要太高。

对于这种情况和环境，我们将执行两个操作。第一个是配置系统默认允许*125,000 个打开文件*。第二个是将当前参数设置为*525,000 个打开文件*，以便成功运行预定的作业。

### 永久更改可调整的值

由于我们想要将`fs.file-max`的值默认更改为`125000`，我们需要编辑`sysctl.conf`文件。`sysctl.conf`文件是一个系统配置文件，允许您为可调整的内核参数指定自定义值。在系统每次重新启动时，该文件都会被读取并应用其中的值。

为了将我们的`fs.file-max`值设置为`125000`，我们只需将以下行追加到这个文件中：

```
# vi /etc/sysctl.conf
fs.file-max=125000

```

现在我们已经添加了我们的自定义值，我们需要告诉系统应用它。

如前所述，`sysctl.conf`文件在重新启动时生效，但是我们也可以随时使用`sysctl`命令和`-p`标志将设置应用到这个文件。

```
# sysctl -p
fs.file-max = 125000

```

给定`-p`标志后，`sysctl`命令将读取并将值应用到指定的文件，或者如果没有指定文件，则应用到`/etc/sysctl.conf`。由于我们在`-p`标志后没有指定文件，`sysctl`命令将应用到`/etc/sysctl.conf`中添加的值，并打印修改的值。

让我们通过再次执行`sysctl`来验证它是否被正确应用。

```
# sysctl fs.file-max
fs.file-max = 125000

```

事实上，似乎值已经被正确应用了，但是将它设置为`525000`呢？

### 临时更改可调整的值

虽然更改`/etc/sysctl.conf`到一个更高的值，然后应用并恢复更改可能很简单。但是有一个更简单的方法可以临时更改可调整的值。

当提供`-w`选项时，`sysctl`命令允许修改可调整的值。为了看到这一点，我们将使用它将`fs.file-max`值设置为`525000`。

```
# sysctl -w fs.file-max=525000
fs.file-max = 525000

```

就像我们应用`sysctl.conf`文件的值一样，当我们执行`sysctl –w`时，它打印了应用的值。如果我们再次验证它们，我们会看到值被设置为`525000`个文件：

```
# sysctl fs.file-max
fs.file-max = 525000

```

## 最后再次运行作业

现在我们已经将 vagrant 用户的`打开文件`限制设置为`500000`，整个系统设置为`525000`。我们可以再次手动执行这个作业，这次应该会成功：

```
$ /opt/myapp/bin/processor --debug --config /opt/myapp/conf/config.yml
Initializing with configuration file /opt/myapp/conf/config.yml
- - - - - - - - - - - - - - - - - - - - - - - - - -
Starting message processing job
Added 492304 to queue
Processing 492304 messages
Processed 492304 messages

```

这次作业执行时没有提供任何错误！我们可以从作业的输出中看到`/opt/myapp/queue`中的所有文件都被处理了。

# 回顾一下

现在我们已经解决了问题，让我们花点时间看看我们是如何解决这个问题的。

## 打开文件太多

为了排除我们的问题，我们手动执行了一个预定的 cron 作业。如果我们回顾之前的章节，这是一个复制问题并亲自看到的一个典型例子。

在这种情况下，作业没有执行它应该执行的任务。为了找出原因，我们手动运行了它。

在手动执行期间，我们能够识别出以下错误：

```
IOError: [Errno 24] Too many open files: '/opt/myapp/queue/1433955823.29_0.txt'

```

这种错误非常常见，是由作业超出用户限制而导致的，该限制阻止单个用户打开太多文件。为了解决这个问题，我们在`/etc/security/limits.conf`文件中添加了自定义设置。

这些更改将我们用户的“打开文件”限制默认设置为`100000`。我们还允许用户通过`hard`设置临时将“打开文件”限制增加到`500000`：

```
IOError: [Errno 23] Too many open files in system: '/opt/myapp/queue/1433955989.86_5.txt'

```

修改这些限制后，我们再次执行了作业，并遇到了类似但不同的错误。

这次，“打开文件”限制是系统本身施加的，这种情况下对系统施加了全局限制，即 48000 个打开文件。

为了解决这个问题，我们在`/etc/sysctl.conf`文件中设置了永久设置为`125000`，并临时将该值更改为`525000`。

从那时起，我们能够手动执行作业。然而，自从我们改变了默认限制以来，我们还为这个作业提供了更多资源以正常执行。只要没有超过 10 万个文件的积压，这个作业将来都应该能够正常执行。

## 稍微整理一下。

说到正常执行，为了减少内核对打开文件的限制，我们可以再次执行`sysctl`命令，并加上`-p`选项。这将把值重置为`/etc/sysctl.conf`文件中定义的值。

```
# sysctl -p
fs.file-max = 125000

```

这种方法的一个注意事项是，`sysctl -p`只会重置`/etc/sysctl.conf`中指定的值；*默认情况下只包含少量可调整的值*。如果修改了`/etc/sysctl.conf`中未指定的值，`sysctl -p`方法将不会将该值重置为默认值。

# 总结

在本章中，我们对 Linux 中强制执行的内核和用户限制非常熟悉。这些设置非常有用，因为任何利用许多资源的应用程序最终都会遇到其中之一。

在下一章中，我们将专注于一个非常常见但非常棘手的问题。我们将专注于故障排除和确定系统内存耗尽的原因。当系统内存耗尽时，会有很多后果，比如应用程序进程被终止。


# 第十一章：从常见故障中恢复

在上一章中，我们探讨了 Linux 服务器上存在的用户和系统限制。我们看了看现有的限制以及如何更改应用程序所需的默认值。

在本章中，我们将运用我们的故障排除技能来处理一个资源耗尽的系统。

# 报告的问题

今天的章节，就像其他章节一样，将以某人报告问题开始。报告的问题是 Apache 不再在服务器上运行，该服务器为公司的博客`blog.example.com`提供服务。

报告问题的另一位系统管理员解释说，有人报告博客宕机，当他登录服务器时，他发现 Apache 不再运行。在那时，我们的同行不确定接下来该怎么做，并请求我们的帮助。

## Apache 真的宕机了吗？

当报告某个服务宕机时，我们应该做的第一件事是验证它是否真的宕机。这本质上是我们故障排除过程中的*为自己复制*步骤。对于 Apache 这样的服务，我们也应该相当快地验证它是否真的宕机。

根据我的经验，我经常被告知服务宕机，而实际上并非如此。服务器可能出现问题，但技术上并没有宕机。上线或宕机的区别会改变我们需要执行的故障排除步骤。

因此，我总是首先执行的步骤是验证服务是否真的宕机，还是服务只是没有响应。

为了验证 Apache 是否真的宕机，我们将使用`ps`命令。正如我们之前学到的，这个命令将打印当前运行的进程列表。我们将将这个输出重定向到`grep`命令，以检查是否有`httpd`（Apache）服务的实例在运行：

```
# ps -elf | grep http
0 S root      2645  1974  0  80   0 - 28160 pipe_w 21:45 pts/0 00:00:00 grep --color=auto http

```

从上述`ps`命令的输出中，我们可以看到没有以`httpd`命名的进程在运行。在正常情况下，我们期望至少看到几行类似于以下示例的内容：

```
5 D apache    2383     1  0  80   0 - 115279 conges 20:58 ? 00:00:04 /usr/sbin/httpd -DFOREGROUND

```

由于在进程列表中找不到`httpd`进程，我们可以得出结论，Apache 实际上在这个系统上宕机了。现在的问题是，为什么？

## 为什么它宕机了？

在简单地启动 Apache 服务解决问题之前，我们将首先弄清楚为什么 Apache 服务没有运行。这是一个称为**根本原因分析**（**RCA**）的过程，这是一个正式的过程，用于了解最初导致问题的原因。

在下一章中，我们将对这个过程非常熟悉。在本章中，我们将保持简单，专注于为什么 Apache 没有运行。

我们要查看的第一个地方是`/var/log/httpd`中的 Apache 日志。在之前的章节中，我们在排除其他与 Web 服务器相关的问题时了解了这些日志。正如我们在之前的章节中看到的，应用程序和服务日志在确定服务发生了什么事情方面非常有帮助。

由于 Apache 不再运行，我们对最近发生的事件更感兴趣。如果服务遇到致命错误或被停止，应该在日志文件的末尾显示相应的消息。

因为我们只对最近发生的事件感兴趣，所以我们将使用`tail`命令显示`error_log`文件的最后 10 行。`error_log`文件是第一个要检查的日志，因为它是发生异常的最可能地方：

```
# tail /var/log/httpd/error_log
[Sun Jun 21 20:51:32.889455 2015] [mpm_prefork:notice] [pid 2218] AH00163: Apache/2.4.6  PHP/5.4.16 configured -- resuming normal operations
[Sun Jun 21 20:51:32.889690 2015] [core:notice] [pid 2218] AH00094: Command line: '/usr/sbin/httpd -D FOREGROUND'
[Sun Jun 21 20:51:33.892170 2015] [mpm_prefork:error] [pid 2218] AH00161: server reached MaxRequestWorkers setting, consider raising the MaxRequestWorkers setting
[Sun Jun 21 20:53:42.577787 2015] [mpm_prefork:notice] [pid 2218] AH00170: caught SIGWINCH, shutting down gracefully [Sun Jun 21 20:53:44.677885 2015] [core:notice] [pid 2249] SELinux policy enabled; httpd running as context system_u:system_r:httpd_t:s0
[Sun Jun 21 20:53:44.678919 2015] [suexec:notice] [pid 2249] AH01232: suEXEC mechanism enabled (wrapper: /usr/sbin/suexec)
[Sun Jun 21 20:53:44.703088 2015] [auth_digest:notice] [pid 2249] AH01757: generating secret for digest authentication ...
[Sun Jun 21 20:53:44.704046 2015] [lbmethod_heartbeat:notice] [pid 2249] AH02282: No slotmem from mod_heartmonitor
[Sun Jun 21 20:53:44.732504 2015] [mpm_prefork:notice] [pid 2249] AH00163: Apache/2.4.6  PHP/5.4.16 configured -- resuming normal operations
[Sun Jun 21 20:53:44.732568 2015] [core:notice] [pid 2249] AH00094: Command line: '/usr/sbin/httpd -D FOREGROUND'

```

从`error_log`文件内容中，我们可以看到一些有趣的信息。让我们快速浏览一下一些更具信息量的日志条目。

```
[Sun Jun 21 20:53:42.577787 2015] [mpm_prefork:notice] [pid 2218] AH00170: caught SIGWINCH, shutting down gracefully

```

前一行显示 Apache 进程在`Sunday, Jun 21`的`20:53`被关闭。我们可以看到错误消息清楚地说明了`优雅地关闭`。然而，接下来的几行似乎表明 Apache 服务只在`2`秒后重新启动：

```
[Sun Jun 21 20:53:44.677885 2015] [core:notice] [pid 2249] SELinux policy enabled; httpd running as context system_u:system_r:httpd_t:s0
[Sun Jun 21 20:53:44.678919 2015] [suexec:notice] [pid 2249] AH01232: suEXEC mechanism enabled (wrapper: /usr/sbin/suexec)
[Sun Jun 21 20:53:44.703088 2015] [auth_digest:notice] [pid 2249] AH01757: generating secret for digest authentication ...
[Sun Jun 21 20:53:44.704046 2015] [lbmethod_heartbeat:notice] [pid 2249] AH02282: No slotmem from mod_heartmonitor
[Sun Jun 21 20:53:44.732504 2015] [mpm_prefork:notice] [pid 2249] AH00163: Apache/2.4.6  PHP/5.4.16 configured -- resuming normal operations

```

关机日志条目显示了一个进程 ID 为`2218`，而前面的五行显示了一个进程 ID 为`2249`。第五行还声明了`恢复正常运行`。这四条消息似乎表明 Apache 进程只是重新启动了。很可能，这是 Apache 的优雅重启。

Apache 的优雅重启是在修改其配置时执行的一个相当常见的任务。这是一种在不完全关闭和影响 Web 服务的情况下重新启动 Apache 进程的方法。

```
[Sun Jun 21 20:53:44.732568 2015] [core:notice] [pid 2249] AH00094: Command line: '/usr/sbin/httpd -D FOREGROUND'

```

然而，这 10 行告诉我们最有趣的事情是，Apache 打印的最后一个日志只是一个通知。当 Apache 被优雅地停止时，它会在`error_log`文件中记录一条消息，以显示它正在被停止。

由于 Apache 进程不再运行，并且没有日志条目显示它是正常关闭或非正常关闭，我们得出结论，无论 Apache 为什么不运行，它都没有正常关闭。

如果一个人使用`apachectl`或`systemctl`命令关闭了服务，我们会期望看到类似于之前例子中讨论的消息。由于日志文件的最后一行没有显示关闭消息，我们只能假设这个进程是在异常情况下被终止或终止的。

现在，问题是*是什么导致了 Apache 进程以这种异常方式终止？*

Apache 发生了什么事情的线索可能在于 systemd 设施，因为 Red Hat Enterprise Linux 7 服务，比如 Apache，已经被迁移到了 systemd。在启动时，`systemd`设施会启动任何已经配置好的服务。

当`systemd`启动的进程被终止时，这个活动会被`systemd`捕获。根据进程终止后发生的情况，我们可以使用`systemctl`命令来查看`systemd`是否捕获了这个事件：

```
# systemctl status httpd
httpd.service - The Apache HTTP Server
 Loaded: loaded (/usr/lib/systemd/system/httpd.service; enabled)
 Active: failed (Result: timeout) since Fri 2015-06-26 21:21:38 UTC; 22min ago
 Process: 2521 ExecStop=/bin/kill -WINCH ${MAINPID} (code=exited, status=0/SUCCESS)
 Process: 2249 ExecStart=/usr/sbin/httpd $OPTIONS -DFOREGROUND (code=killed, signal=KILL)
 Main PID: 2249 (code=killed, signal=KILL)
 Status: "Total requests: 1649; Current requests/sec: -1.29; Current traffic:   0 B/sec"

Jun 21 20:53:44 blog.example.com systemd[1]: Started The Apache HTTP Server.
Jun 26 21:12:55 blog.example.com systemd[1]: httpd.service: main process exited, code=killed, status=9/KILL
Jun 26 21:21:20 blog.example.com systemd[1]: httpd.service stopping timed out. Killing.
Jun 26 21:21:38 blog.example.com systemd[1]: Unit httpd.service entered failed state.

```

`systemctl status`命令的输出显示了相当多的信息。由于我们在之前的章节中已经涵盖了这个问题，我将跳过这个输出的大部分，只看一些能告诉我们 Apache 服务发生了什么的部分。

看起来有趣的前两行是：

```
 Process: 2249 ExecStart=/usr/sbin/httpd $OPTIONS -DFOREGROUND (code=killed, signal=KILL)
 Main PID: 2249 (code=killed, signal=KILL)

```

在这两行中，我们可以看到进程 ID 为`2249`，这也是我们在`error_log`文件中看到的。这是在`6 月 21 日星期日`启动的 Apache 实例的进程 ID。我们还可以从这些行中看到，进程`2249`被终止了。这似乎表明有人或某物终止了我们的 Apache 服务：

```
Jun 21 20:53:44 blog.example.com systemd[1]: Started The Apache HTTP Server.
Jun 26 21:12:55 blog.example.com systemd[1]: httpd.service: main process exited, code=killed, status=9/KILL
Jun 26 21:21:20 blog.example.com systemd[1]: httpd.service stopping timed out. Killing.
Jun 26 21:21:38 blog.example.com systemd[1]: Unit httpd.service entered failed state.

```

如果我们看一下`systemctl`状态输出的最后几行，我们可以看到`systemd`设施捕获的事件。我们可以看到的第一个事件是 Apache 服务在`6 月 21 日 20:53`启动。这并不奇怪，因为它与我们在`error_log`中看到的信息相符。

然而，最后三行显示 Apache 进程随后在`6 月 26 日 21:21`被终止。不幸的是，这些事件并没有准确显示 Apache 进程被终止的原因或是谁终止了它。它告诉我们的是 Apache 被终止的确切时间。这也表明`systemd`设施不太可能停止了 Apache 服务。

## 那个时候还发生了什么？

由于我们无法从 Apache 日志或`systemctl status`中确定原因，我们需要继续挖掘以了解是什么导致了这个服务的停止。

```
# date
Sun Jun 28 18:32:33 UTC 2015

```

由于 26 号已经过去了几天，我们有一些有限的地方可以寻找额外的信息。我们可以查看`/var/log/messages`日志文件。正如我们在前面的章节中发现的，`messages`日志包含了系统中许多不同设施的各种信息。如果有一个地方可以告诉我们那个时候系统发生了什么，那就是那里。

### 搜索 messages 日志

`messages`日志非常庞大，在其中有许多日志条目：

```
# wc -l /var/log/messages
21683 /var/log/messages

```

因此，我们需要过滤掉与我们的问题无关或不在我们问题发生时的日志消息。我们可以做的第一件事是搜索日志中 Apache 停止的那一天的消息：`June 26`：

```
# tail -1 /var/log/messages
Jun 28 20:44:01 localhost systemd: Started Session 348 of user vagrant.

```

从前面提到的`tail`命令中，我们可以看到`/var/log/messages`文件中的消息格式是日期、主机名、进程，然后是消息。日期字段是一个三个字母的月份，后面跟着日期数字和 24 小时时间戳。

由于我们的问题发生在 6 月 26 日，我们可以搜索这个日志文件中字符串"`Jun 26`"的任何实例。这应该提供所有在 26 日写入的消息：

```
# grep -c "Jun 26" /var/log/messages
17864

```

显然这仍然是相当多的日志消息，太多了，无法全部阅读。鉴于这个数量，我们需要进一步过滤消息，也许可以按进程来过滤：

```
# grep "Jun 26" /var/log/messages | cut -d\  -f1,2,5 | sort -n | uniq -c | sort -nk 1 | tail
 39 Jun 26 journal:
 56 Jun 26 NetworkManager:
 76 Jun 26 NetworkManager[582]:
 76 Jun 26 NetworkManager[588]:
 78 Jun 26 NetworkManager[580]:
 79 Jun 26 systemd-logind:
 110 Jun 26 systemd[1]:
 152 Jun 26 NetworkManager[574]:
 1684 Jun 26 systemd:
 15077 Jun 26 kernel:

```

上面的代码通常被称为**bash**一行代码。这通常是一系列命令，它们将它们的输出重定向到另一个命令，以提供一个单独的命令无法执行或生成的功能或输出。在这种情况下，我们有一个一行代码，它显示了 6 月 26 日记录最多的进程。

### 分解这个有用的一行代码

上面提到的一行代码一开始可能有点复杂，但一旦我们分解这个一行代码，它就变得容易理解了。这是一个有用的一行代码，因为它使得在日志文件中识别趋势变得更容易。

让我们分解这个一行代码，以更好地理解它的作用：

```
# grep "Jun 26" /var/log/messages | cut -d\  -f1,2,5 | sort | uniq -c | sort -nk 1 | tail

```

我们已经知道第一个命令的作用；它只是在`/var/log/messages`文件中搜索字符串"`Jun 26`"的任何实例。其他命令是我们以前没有涉及过的命令，但它们可能是有用的命令。

#### cut 命令

这个一行代码中的`cut`命令用于读取`grep`命令的输出，并只打印每行的特定部分。要理解它是如何工作的，我们应该首先运行在`cut`命令结束的一行代码：

```
# grep "Jun 26" /var/log/messages | cut -d\  -f1,2,5
Jun 26 systemd:
Jun 26 systemd:
Jun 26 systemd:
Jun 26 systemd:
Jun 26 systemd:
Jun 26 systemd:
Jun 26 systemd:
Jun 26 systemd:
Jun 26 systemd:
Jun 26 systemd:

```

前面的`cut`命令通过指定分隔符并按该分隔符切割输出来工作。

分隔符是用来将行分解为多个字段的字符；我们可以用`-d`标志来指定它。在上面的例子中，`-d`标志后面跟着"`\`"；反斜杠是一个转义字符，后面跟着一个空格。这告诉`cut`命令使用一个空格字符作为分隔符。

`-f`标志用于指定应该显示的`fields`。这些字段是分隔符之间的文本字符串。

例如，让我们看看下面的命令：

```
$ echo "Apples:Bananas:Carrots:Dried Cherries" | cut -d: -f1,2,4
Apples:Bananas:Dried Cherries

```

在这里，我们指定"`:`"字符是`cut`的分隔符。我们还指定它应该打印第一、第二和第四个字段。这导致打印了 Apples（第一个字段）、Bananas（第二个字段）和 Dried Cherries（第四个字段）。第三个字段 Carrots 被省略了。这是因为我们没有明确告诉`cut`命令打印第三个字段。

现在我们知道了`cut`是如何工作的，让我们看看它是如何处理`messages`日志条目的。

这是一个日志消息的样本：

```
Jun 28 21:50:01 localhost systemd: Created slice user-0.slice.

```

当我们执行这个一行代码中的`cut`命令时，我们明确告诉它只打印第一、第二和第五个字段：

```
# grep "Jun 26" /var/log/messages | cut -d\  -f1,2,5
Jun 26 systemd:

```

通过在我们的`cut`命令中指定一个空格字符作为分隔符，我们可以看到这会导致`cut`只打印每个日志条目的月份、日期和程序。单独看可能并不那么有用，但随着我们继续查看这个一行代码，cut 提供的功能将变得至关重要。

#### sort 命令

接下来的`sort`命令在这个一行代码中实际上被使用了两次：

```
# grep "Jun 26" /var/log/messages | cut -d\  -f1,2,5 | sort | head
Jun 26 audispd:
Jun 26 audispd:
Jun 26 audispd:
Jun 26 audispd:
Jun 26 audispd:
Jun 26 auditd[539]:
Jun 26 auditd[539]:
Jun 26 auditd[542]:
Jun 26 auditd[542]:
Jun 26 auditd[548]:

```

这个命令实际上很简单，它的作用是对`cut`命令的输出进行排序。

为了更好地解释这一点，让我们看下面的例子：

```
# cat /var/tmp/fruits.txt 
Apples
Dried Cherries
Carrots
Bananas

```

上面的文件再次包含几种水果，这一次它们不是按字母顺序排列的。然而，如果我们使用`sort`命令来读取这个文件，这些水果的顺序将会改变：

```
# sort /var/tmp/fruits.txt 
Apples
Bananas
Carrots
Dried Cherries

```

正如我们所看到的，现在的顺序是按字母顺序排列的，尽管水果在文件中的顺序是不同的。`sort`的好处在于它可以用几种不同的方式对文本进行排序。实际上，在我们的一行命令中`sort`的第二个实例中，我们使用`-n`标志对文本进行了数字排序：

```
# cat /var/tmp/numbers.txt
10
23
2312
23292
1212
129191
# sort -n /var/tmp/numbers.txt 
10
23
1212
2312
23292
129191

```

### uniq 命令

我们的一行命令包含`sort`命令的原因很简单，就是为了对发送到`uniq -c`的输入进行排序：

```
# grep "Jun 26" /var/log/messages | cut -d\  -f1,2,5 | sort | uniq -c | head
 5 Jun 26 audispd:
 2 Jun 26 auditd[539]:
 2 Jun 26 auditd[542]:
 3 Jun 26 auditd[548]:
 2 Jun 26 auditd[550]:
 2 Jun 26 auditd[553]:
 15 Jun 26 augenrules:
 38 Jun 26 avahi-daemon[573]:
 19 Jun 26 avahi-daemon[579]:
 19 Jun 26 avahi-daemon[581]:

```

`uniq`命令可以用来识别匹配的行，并将这些行显示为单个唯一行。为了更好地理解这一点，让我们看看下面的例子：

```
$ cat /var/tmp/duplicates.txt 
Apple
Apple
Apple
Apple
Banana
Banana
Banana
Carrot
Carrot

```

我们的示例文件"`duplicates.txt`"包含多个重复的行。当我们用`uniq`读取这个文件时，我们只会看到每一行的唯一内容：

```
$ uniq /var/tmp/duplicates.txt 
Apple
Banana
Carrot

```

这可能有些有用；但是，我发现使用`-c`标志，输出可能会更有用：

```
$ uniq -c /var/tmp/duplicates.txt 
 4 Apple
 3 Banana
 2 Carrot

```

使用`-c`标志，`uniq`命令将计算它找到每行的次数。在这里，我们可以看到有四行包含单词苹果。因此，`uniq`命令在单词苹果之前打印了数字 4，以显示这行有四个实例：

```
$ cat /var/tmp/duplicates.txt 
Apple
Apple
Orange
Apple
Apple
Banana
Banana
Banana
Carrot
Carrot
$ uniq -c /var/tmp/duplicates.txt 
 2 Apple
 1 Orange
 2 Apple
 3 Banana
 2 Carrot

```

`uniq`命令的一个注意事项是，为了获得准确的计数，每个实例都需要紧挨在一起。当我们在苹果行的组之间添加单词橙子时，可以看到会发生什么。

### 把所有东西都联系在一起

如果我们再次看看我们的命令，现在我们可以更好地理解它在做什么：

```
# grep "Jun 26" /var/log/messages | cut -d\  -f1,2,5 | sort | uniq -c | sort -n | tail
 39 Jun 26 journal:
 56 Jun 26 NetworkManager:
 76 Jun 26 NetworkManager[582]:
 76 Jun 26 NetworkManager[588]:
 78 Jun 26 NetworkManager[580]:
 79 Jun 26 systemd-logind:
 110 Jun 26 systemd[1]:
 152 Jun 26 NetworkManager[574]:
 1684 Jun 26 systemd:
 15077 Jun 26 kernel:

```

上面的命令将过滤并打印`/var/log/messages`中与字符串"`Jun 26`"匹配的所有日志消息。然后输出将被发送到`cut`命令，该命令打印每行的月份、日期和进程。然后将此输出发送到`sort`命令，以将输出排序为相互匹配的组。排序后的输出然后被发送到`uniq -c`，它计算每行出现的次数并打印一个带有计数的唯一行。

然后，我们添加另一个`sort`来按`uniq`添加的数字对输出进行排序，并添加`tail`来将输出缩短到最后 10 行。

那么，这个花哨的一行命令到底告诉我们什么呢？嗯，它告诉我们`kernel`设施和`systemd`进程正在记录相当多的内容。实际上，与其他列出的项目相比，我们可以看到这两个项目的日志消息比其他项目更多。

然而，`systemd`和`kernel`在`/var/log/messages`中有更多的日志消息可能并不奇怪。如果有另一个写入许多日志的进程，我们将能够在一行输出中看到这一点。然而，由于我们的第一次运行没有产生有用的结果，我们可以修改一行命令来缩小输出范围：

```
Jun 26 19:51:10 localhost auditd[550]: Started dispatcher: /sbin/audispd pid: 562

```

如果我们看一下`messages`日志条目的格式，我们会发现在进程之后，可以找到日志消息。为了进一步缩小我们的搜索范围，我们可以在输出中添加一点消息。

我们可以通过将`cut`命令的字段列表更改为"`1,2,5-8`"来实现这一点。通过在`5`后面添加"`-8`"，我们发现`cut`命令显示从 5 到 8 的所有字段。这样做的效果是在我们的一行命令中包含每条日志消息的前三个单词：

```
# grep "Jun 26" /var/log/messages | cut -d\  -f1,2,5-8 | sort | uniq -c | sort -n | tail -30
 64 Jun 26 kernel: 131055 pages RAM
 64 Jun 26 kernel: 5572 pages reserved
 64 Jun 26 kernel: lowmem_reserve[]: 0 462
 77 Jun 26 kernel: [  579]
 79 Jun 26 kernel: Out of memory:
 80 Jun 26 kernel: [<ffffffff810b68f8>] ? ktime_get_ts+0x48/0xe0
 80 Jun 26 kernel: [<ffffffff81102e03>] ? proc_do_uts_string+0xe3/0x130
 80 Jun 26 kernel: [<ffffffff8114520e>] oom_kill_process+0x24e/0x3b0
 80 Jun 26 kernel: [<ffffffff81145a36>] out_of_memory+0x4b6/0x4f0
 80 Jun 26 kernel: [<ffffffff8114b579>] __alloc_pages_nodemask+0xa09/0xb10
 80 Jun 26 kernel: [<ffffffff815dd02d>] dump_header+0x8e/0x214
 80 Jun 26 kernel: [ pid ]
 81 Jun 26 kernel: [<ffffffff8118bc3a>] alloc_pages_vma+0x9a/0x140
 93 Jun 26 kernel: Call Trace:
 93 Jun 26 kernel: [<ffffffff815e19ba>] dump_stack+0x19/0x1b
 93 Jun 26 kernel: [<ffffffff815e97c8>] page_fault+0x28/0x30
 93 Jun 26 kernel: [<ffffffff815ed186>] __do_page_fault+0x156/0x540
 93 Jun 26 kernel: [<ffffffff815ed58a>] do_page_fault+0x1a/0x70
 93 Jun 26 kernel: Free swap 
 93 Jun 26 kernel: Hardware name: innotek
 93 Jun 26 kernel: lowmem_reserve[]: 0 0
 93 Jun 26 kernel: Mem-Info:
 93 Jun 26 kernel: Node 0 DMA:
 93 Jun 26 kernel: Node 0 DMA32:
 93 Jun 26 kernel: Node 0 hugepages_total=0
 93 Jun 26 kernel: Swap cache stats:
 93 Jun 26 kernel: Total swap =
 186 Jun 26 kernel: Node 0 DMA
 186 Jun 26 kernel: Node 0 DMA32
 489 Jun 26 kernel: CPU 

```

如果我们还增加`tail`命令以显示最后 30 行，我们可以看到一些有趣的趋势。非常有趣的第一行是输出中的第四行：

```
 79 Jun 26 kernel: Out of memory:

```

似乎`kernel`打印了以术语"`Out of memory`"开头的`79`条日志消息。虽然这似乎有点显而易见，但似乎这台服务器可能在某个时候耗尽了内存。

接下来的两行看起来也支持这个理论：

```
 80 Jun 26 kernel: [<ffffffff8114520e>] oom_kill_process+0x24e/0x3b0
 80 Jun 26 kernel: [<ffffffff81145a36>] out_of_memory+0x4b6/0x4f0

```

第一行似乎表明内核终止了一个进程；第二行再次表明出现了*内存耗尽*的情况。这个系统可能已经耗尽了内存，并在这样做时终止了 Apache 进程。这似乎非常可能。

## 当 Linux 系统内存耗尽时会发生什么？

在 Linux 上，内存的管理方式与其他操作系统有些不同。当系统内存不足时，内核有一个旨在回收已使用内存的进程；这个进程称为**内存耗尽终结者**（**oom-kill**）。

`oom-kill`进程旨在终止使用大量内存的进程，以释放这些内存供关键系统进程使用。我们将稍后讨论`oom-kill`，但首先，我们应该了解 Linux 如何定义内存耗尽。

### 最小空闲内存

在 Linux 上，当空闲内存量低于定义的最小值时，将启动 oom-kill 进程。这个最小值当然是一个名为`vm.min_free_kbytes`的内核可调参数。该参数允许您设置系统始终可用的内存量（以千字节为单位）。

当可用内存低于此参数的值时，系统开始采取行动。在深入讨论之前，让我们首先看看我们系统上设置的这个值，并重新了解 Linux 中的内存管理方式。

我们可以使用与上一章相同的`sysctl`命令查看当前的`vm.min_free_kbytes`值：

```
# sysctl vm.min_free_kbytes
vm.min_free_kbytes = 11424

```

当前值为`11424`千字节，约为 11 兆字节。这意味着我们系统的空闲内存必须始终大于 11 兆字节，否则系统将启动 oom-kill 进程。这似乎很简单，但正如我们从第四章中所知道的那样，Linux 管理内存的方式并不一定那么简单：

```
# free
 total       used       free     shared    buffers cached
Mem:        243788     230012      13776         60          0 2272
-/+ buffers/cache:     227740      16048
Swap:      1081340     231908     849432

```

如果我们在这个系统上运行`free`命令，我们可以看到当前的内存使用情况以及可用内存量。在深入讨论之前，我们将分解这个输出，以便重新理解 Linux 如何使用内存。

```
 total       used       free     shared    buffers  cached
Mem:        243788     230012      13776         60          0 2272

```

在第一行中，我们可以看到系统总共有 243MB 的物理内存。我们可以在第二列中看到目前使用了 230MB，第三列显示有 13MB 未使用。系统测量的正是这个未使用的值，以确定当前是否有足够的最小所需内存空闲。

这很重要，因为如果我们记得第四章中所说的，我们使用第二个“内存空闲”值来确定有多少内存可用。

```
 total       used       free     shared    buffers cached
Mem:        243788     230012      13776         60          0 2272
-/+ buffers/cache:     227740      16048

```

在`free`的第二行，我们可以看到系统在考虑缓存使用的内存量时的已使用和空闲内存量。正如我们之前学到的，Linux 系统非常积极地缓存文件和文件系统属性。所有这些缓存都存储在内存中，我们可以看到，在运行这个`free`命令的瞬间，我们的缓存使用了 2,272 KB 的内存。

当空闲内存（不包括缓存）接近`min_free_kbytes`值时，系统将开始回收一些用于缓存的内存。这旨在允许系统尽可能地缓存，但在内存不足的情况下，为了防止 oom-kill 进程的启动，这个缓存变得可丢弃：

```
Swap:      1081340     231908     849432

```

`free`命令的第三行将我们带到 Linux 内存管理的另一个重要步骤：交换。正如我们从前一行中看到的，当执行这个`free`命令时，系统将大约 231MB 的数据从物理内存交换到交换设备。

这是我们期望在运行内存不足的系统上看到的情况。当`free`内存开始变得稀缺时，系统将开始获取物理内存中的内存对象并将它们推送到交换内存中。

系统开始执行这些交换活动的侵略性取决于内核参数`vm.swappiness`中定义的值：

```
$ sysctl vm.swappiness
vm.swappiness = 30

```

在我们的系统上，`swappiness`值目前设置为`30`。这个可调参数接受 0 到 100 之间的值，其中 100 允许最激进的交换策略。

当`swappiness`值较低时，系统会更倾向于将内存对象保留在物理内存中尽可能长的时间，然后再将它们移动到交换设备上。

#### 快速回顾

在进入 oom-kill 之前，让我们回顾一下当 Linux 系统上的内存开始变得紧张时会发生什么。系统首先会尝试释放用于磁盘缓存的内存对象，并将已使用的内存移动到交换设备上。如果系统无法通过前面提到的两个过程释放足够的内存，内核就会启动 oom-kill 进程。

### oom-kill 的工作原理

如前所述，oom-kill 进程是在空闲内存不足时启动的一个进程。这个进程旨在识别使用大量内存并且对系统操作不重要的进程。

那么，oom-kill 是如何确定这一点的呢？嗯，实际上是由内核确定的，并且不断更新。

我们在前面的章节中讨论了系统上每个运行的进程都有一个在`/proc`文件系统中的文件夹。内核维护着这个文件夹，里面有很多有趣的文件。

```
# ls -la /proc/6689/oom_*
-rw-r--r--. 1 root root 0 Jun 29 15:23 /proc/6689/oom_adj
-r--r--r--. 1 root root 0 Jun 29 15:23 /proc/6689/oom_score
-rw-r--r--. 1 root root 0 Jun 29 15:23 /proc/6689/oom_score_adj

```

前面提到的三个文件与 oom-kill 进程及每个进程被杀死的可能性有关。我们要看的第一个文件是`oom_score`文件：

```
# cat /proc/6689/oom_score
40

```

如果我们`cat`这个文件，我们会发现它只包含一个数字。然而，这个数字对于 oom-kill 进程非常重要，因为这个数字就是进程 6689 的 OOM 分数。

OOM 分数是内核分配给一个进程的一个值，用来确定相应进程对 oom-kill 的优先级高低。分数越高，进程被杀死的可能性就越大。当内核为这个进程分配一个值时，它基于进程使用的内存和交换空间的数量以及对系统的重要性。

你可能会问自己，“我想知道是否有办法调整我的进程的 oom 分数。” 这个问题的答案是肯定的，有！这就是另外两个文件`oom_adj`和`oom_score_adj`发挥作用的地方。这两个文件允许您调整进程的 oom 分数，从而控制进程被杀死的可能性。

目前，`oom_adj`文件将被淘汰，取而代之的是`oom_score_adj`。因此，我们将只关注`oom_score_adj`文件。

#### 调整 oom 分数

`oom_score_adj`文件支持从-1000 到 1000 的值，其中较高的值将增加 oom-kill 选择该进程的可能性。让我们看看当我们为我们的进程添加 800 的调整时，我们的 oom 分数会发生什么变化：

```
# echo "800" > /proc/6689/oom_score_adj 
# cat /proc/6689/oom_score
840

```

仅仅通过改变内容为 800，内核就检测到了这个调整并为这个进程的 oom 分数增加了 800。如果这个系统在不久的将来内存耗尽，这个进程绝对会被 oom-kill 杀死。

如果我们将这个值改为-1000，这实际上会排除该进程被 oom-kill 杀死的可能性。

## 确定我们的进程是否被 oom-kill 杀死

现在我们知道了系统内存不足时会发生什么，让我们更仔细地看看我们的系统到底发生了什么。为了做到这一点，我们将使用`less`来读取`/var/log/messages`文件，并寻找`kernel: Out of memory`消息的第一个实例：

```
Jun 26 00:53:39 blog kernel: Out of memory: Kill process 5664 (processor) score 265 or sacrifice child

```

有趣的是，“内存不足”日志消息的第一个实例是在我们的 Apache 进程被杀死之前的 20 小时。更重要的是，被杀死的进程是一个非常熟悉的进程，即上一章的“处理器”cronjob。

这一条日志记录实际上可以告诉我们关于该进程以及为什么 oom-kill 选择了该进程的很多信息。在第一行，我们可以看到内核给了处理器进程一个`265`的分数。虽然不是最高分，但我们已经看到 265 分很可能比此时运行的大多数进程的分数都要高。

这似乎表明处理器作业在这个时候使用了相当多的内存。让我们继续查看这个文件，看看在这个系统上可能发生了什么其他事情：

```
Jun 26 00:54:31 blog kernel: Out of memory: Kill process 5677 (processor) score 273 or sacrifice child

```

在日志文件中再往下看一点，我们可以看到处理器进程再次被杀死。似乎每次这个作业运行时，系统都会耗尽内存。

为了节约时间，让我们跳到第 21 个小时，更仔细地看看我们的 Apache 进程被杀死的时间：

```
Jun 26 21:12:54 localhost kernel: Out of memory: Kill process 2249 (httpd) score 7 or sacrifice child
Jun 26 21:12:54 localhost kernel: Killed process 2249 (httpd) total-vm:462648kB, anon-rss:436kB, file-rss:8kB
Jun 26 21:12:54 localhost kernel: httpd invoked oom-killer: gfp_mask=0x200da, order=0, oom_score_adj=0

```

看起来`messages`日志一直都有我们的答案。从前面几行可以看到进程`2249`，这恰好是我们的 Apache 服务器进程 ID：

```
Jun 26 21:12:55 blog.example.com systemd[1]: httpd.service: main process exited, code=killed, status=9/KILL

```

在这里，我们看到`systemd`检测到该进程在`21:12:55`被杀死。此外，我们可以从消息日志中看到 oom-kill 在`21:12:54`针对该进程进行了操作。在这一点上，毫无疑问，该进程是被 oom-kill 杀死的。

## 系统为什么耗尽了内存？

在这一点上，我们能够确定 Apache 服务在内存耗尽时被系统杀死。不幸的是，oom-kill 并不是问题的根本原因，而是一个症状。虽然它是 Apache 服务停止的原因，但如果我们只是重新启动进程而不做其他操作，问题可能会再次发生。

在这一点上，我们需要确定是什么导致系统首先耗尽了内存。为了做到这一点，让我们来看看消息日志文件中“内存不足”消息的整个列表：

```
# grep "Out of memory" /var/log/messages* | cut -d\  -f1,2,10,12 | uniq -c
 38 /var/log/messages:Jun 28 process (processor)
 1 /var/log/messages:Jun 28 process (application)
 10 /var/log/messages:Jun 28 process (processor)
 1 /var/log/messages-20150615:Jun 10 process (python)
 1 /var/log/messages-20150628:Jun 22 process (processor)
 47 /var/log/messages-20150628:Jun 26 process (processor)
 32 /var/log/messages-20150628:Jun 26 process (httpd)

```

再次使用`cut`和`uniq -c`命令，我们可以在消息日志中看到一个有趣的趋势。我们可以看到内核已经多次调用了 oom-kill。我们可以看到即使今天系统也启动了 oom-kill 进程。

现在我们应该做的第一件事是弄清楚这个系统有多少内存。

```
# free -m
 total       used       free     shared    buffers cached
Mem:           238        206         32          0          0 2
-/+ buffers/cache:        203         34
Swap:         1055        428        627

```

使用`free`命令，我们可以看到系统有`238` MB 的物理内存和`1055` MB 的交换空间。然而，我们也可以看到只有`34` MB 的内存是空闲的，系统已经交换了`428` MB 的物理内存。

很明显，对于当前的工作负载，该系统分配的内存根本不够。

如果我们回顾一下 oom-kill 所针对的进程，我们可以看到一个有趣的趋势：

```
# grep "Out of memory" /var/log/messages* | cut -d\  -f10,12 | sort | uniq -c
 1 process (application)
 32 process (httpd)
 118 process (processor)
 1 process (python)

```

在这里，很明显，被最频繁杀死的两个进程是`httpd`和`processor`。我们之前了解到，oom-kill 根据它们使用的内存量来确定要杀死的进程。这意味着这两个进程在系统上使用了最多的内存，但它们到底使用了多少内存呢？

```
# ps -eo rss,size,cmd | grep processor
 0   340 /bin/sh -c /opt/myapp/bin/processor --debug --config /opt/myapp/conf/config.yml > /dev/null
130924 240520 /opt/myapp/bin/processor --debug --config /opt/myapp/conf/config.yml
 964   336 grep --color=auto processor

```

使用`ps`命令来专门显示**rss**和**size**字段，我们在第四章中学到了，*故障排除性能问题*，我们可以看到`processor`作业使用了`130` MB 的常驻内存和`240` MB 的虚拟内存。

如果系统只有`238` MB 的物理内存，而进程使用了`240` MB 的虚拟内存，最终，这个系统的物理内存会不足。

# 长期和短期解决问题

像本章讨论的这种问题可能有点棘手，因为它们通常有两种解决路径。有一个长期解决方案和一个短期解决方案；两者都是必要的，但一个只是临时的。

## 长期解决方案

对于这个问题的长期解决方案，我们确实有两个选择。我们可以增加服务器的物理内存，为 Apache 和 Processor 提供足够的内存来完成它们的任务。或者，我们可以将 processor 移动到另一台服务器上。

由于我们知道这台服务器经常杀死 Apache 服务和`processor`任务，很可能是系统上的内存对于执行这两个角色来说太低了。通过将`processor`任务（以及很可能是其一部分的自定义应用程序）移动到另一个系统，我们将工作负载移动到一个专用服务器。

基于处理器的内存使用情况，增加新服务器的内存也可能是值得的。似乎`processor`任务使用了足够的内存，在目前这样的低内存服务器上可能会导致内存不足的情况。

确定哪个长期解决方案最好取决于环境和导致系统内存不足的应用程序。在某些情况下，增加服务器的内存可能是更好的选择。

在虚拟和云环境中，这个任务非常容易，但这并不总是最好的答案。确定哪个答案更好取决于你所使用的环境。

## 短期解决方案

假设两个长期解决方案都需要几天时间来实施。就目前而言，我们的系统上 Apache 服务仍然处于停机状态。这意味着我们的公司博客也仍然处于停机状态；为了暂时解决问题，我们需要重新启动 Apache。

然而，我们不应该只是用`systemctl`命令简单地重新启动 Apache。在启动任何内容之前，我们实际上应该首先重新启动服务器。

当大多数 Linux 管理员听到“让我们重启”这句话时，他们会感到沮丧。这是因为作为 Linux 系统管理员，我们很少需要重启系统。我们被告知在更新内核之外重启 Linux 服务器是一件不好的事情。

在大多数情况下，我们认为重新启动服务器不是正确的解决方案。然而，我认为系统内存不足是一个特殊情况。

我认为，在启动 oom-kill 时，应该在完全恢复到正常状态之前重新启动相关系统。

我这样说的原因是 oom-kill 进程可以杀死任何进程，包括关键的系统进程。虽然 oom-kill 进程确实会通过 syslog 记录被杀死的进程，但 syslog 守护程序只是系统上的另一个可以被 oom-kill 杀死的进程。

即使 oom-kill 没有在 oom-kill 杀死许多不同进程的情况下杀死 syslog 进程，要确保每个进程都正常运行可能会有些棘手。特别是当处理问题的人经验较少时。

虽然你可以花时间确定正在运行的进程，并确保重新启动每个进程，但简单地重新启动服务器可能更快，而且可以说更安全。因为你知道在启动时，每个定义为启动的进程都将被启动。

虽然并非每个系统管理员都会同意这种观点，但我认为这是确保系统处于稳定状态的最佳方法。但重要的是要记住，这只是一个短期解决方案，重新启动后，除非有变化，系统可能会再次出现内存不足的情况。

对于我们的情况，最好是在服务器的内存增加或作业可以移至专用系统之前禁用`processor`作业。然而，在某些情况下，这可能是不可接受的。像长期解决方案一样，防止再次发生这种情况是情境性的，并取决于你所管理的环境。

由于我们假设短期解决方案是我们示例的正确解决方案，我们将继续重新启动系统：

```
# reboot
Connection to 127.0.0.1 closed by remote host.

```

系统恢复在线后，我们可以使用`systemctl`命令验证 Apache 是否正在运行。

```
# systemctl status httpd
httpd.service - The Apache HTTP Server
 Loaded: loaded (/usr/lib/systemd/system/httpd.service; enabled)
 Active: active (running) since Wed 2015-07-01 15:37:22 UTC; 1min 29s ago
 Main PID: 1012 (httpd)
 Status: "Total requests: 0; Current requests/sec: 0; Current traffic:   0 B/sec"
 CGroup: /system.slice/httpd.service
 ├─1012 /usr/sbin/httpd -DFOREGROUND
 ├─1439 /usr/sbin/httpd -DFOREGROUND
 ├─1443 /usr/sbin/httpd -DFOREGROUND
 ├─1444 /usr/sbin/httpd -DFOREGROUND
 ├─1445 /usr/sbin/httpd -DFOREGROUND
 └─1449 /usr/sbin/httpd -DFOREGROUND

Jul 01 15:37:22 blog.example.com systemd[1]: Started The Apache HTTP Server.

```

如果我们在这个系统上再次运行`free`命令，我们可以看到内存利用率要低得多，至少直到现在为止。

```
# free -m
 total       used       free     shared    buffers cached
Mem:           238        202         35          4          0 86
-/+ buffers/cache:        115        122
Swap:         1055          0       1055

```

# 总结

在本章中，我们运用了我们的故障排除技能，确定了影响公司博客的问题以及这个问题的根本原因。我们能够运用在之前章节学到的技能和技术，确定 Apache 服务已经停止。我们还确定了这个问题的根本原因是系统内存耗尽。

通过调查日志文件，我们发现系统上占用最多内存的两个进程是 Apache 和一个名为`processor`的自定义应用程序。此外，通过识别这些进程，我们能够提出长期建议，以防止此问题再次发生。

除此之外，我们还学到了当 Linux 系统内存耗尽时会发生什么。

在下一章中，我们将把你到目前为止学到的一切付诸实践，通过对一个无响应系统进行根本原因分析。


# 第十二章：意外重启的根本原因分析

在本章中，我们将对您在之前章节中学到的故障排除方法和技能进行测试。我们将对最困难的真实场景之一进行根本原因分析：意外重启。

正如我们在第一章中讨论的，*故障排除最佳实践*，根本原因分析比简单的故障排除和解决问题要复杂一些。在企业环境中，您会发现每个导致重大影响的问题都需要进行根本原因分析（RCA）。这是因为企业环境通常有关于应该如何处理事件的成熟流程。

一般来说，当发生重大事件时，受到影响的组织希望避免再次发生。即使在技术环境之外的许多行业中也可以看到这一点。

正如我们在第一章中讨论的，*故障排除最佳实践*，一个有用的根本原因分析具有以下特征：

+   问题的报告方式

+   问题的实际根本原因

+   事件和采取的行动的时间线

+   任何关键数据点

+   防止事件再次发生的行动计划

对于今天的问题，我们将使用一个事件来构建一个样本根本原因分析文档。为此，我们将使用您在之前章节中学到的信息收集和故障排除步骤。在做所有这些的同时，您还将学会处理意外重启，这是确定根本原因的最糟糕的事件之一。

意外重启困难的原因在于系统重启时通常会丢失您需要识别问题根本原因的信息。正如我们在之前的章节中所看到的，我们在问题发生期间收集的数据越多，我们就越有可能确定问题的原因。

在重启期间丢失的信息往往是确定根本原因和未确定根本原因之间的区别。

# 深夜警报

随着我们在章节中的进展和为最近的雇主解决了许多问题，我们也在获得他们对我们能力的信任。最近，我们甚至被放在了**值班**轮换中，这意味着如果在工作时间之后出现问题，我们的手机将通过短信收到警报。

当然，值班的第一个晚上我们收到了一个警报；这个警报不是一个好消息。

*警报：blog.example.com 不再响应 ICMP Ping*

当我们被加入到值班轮换中时，我们的团队负责人告诉我们，任何在工作时间之后发生的重大事件都必须进行根本原因分析。这样做的原因是为了让我们组中的其他人学习和了解我们是如何解决问题以及如何防止再次发生的。

正如我们之前讨论的，有用的根本原因分析的关键组成部分之一是列出事情发生的时间。我们时间线中的一个重大事件是我们收到警报的时间；根据我们的短信消息，我们可以看到我们在 2015 年 7 月 5 日 01:52 收到了警报，或者说；7 月 5 日凌晨 1:52（欢迎来到值班！）。

# 确定问题

从警报中，我们可以看到我们的监控系统无法对我们公司的博客服务器执行`ICMP` ping。我们应该做的第一件事是确定我们是否可以`ping`服务器：

```
$ ping blog.example.com
PING blog.example.com (192.168.33.11): 56 data bytes
64 bytes from 192.168.33.11: icmp_seq=0 ttl=64 time=0.832 ms
64 bytes from 192.168.33.11: icmp_seq=1 ttl=64 time=0.382 ms
64 bytes from 192.168.33.11: icmp_seq=2 ttl=64 time=0.240 ms
64 bytes from 192.168.33.11: icmp_seq=3 ttl=64 time=0.234 ms
^C
--- blog.example.com ping statistics ---
4 packets transmitted, 4 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 0.234/0.422/0.832/0.244 ms

```

看起来我们能够 ping 通相关服务器，所以也许这是一个虚警？以防万一，让我们尝试登录系统：

```
$ ssh 192.168.33.11 -l vagrant
vagrant@192.168.33.11's password: 
$

```

看起来我们能够登录，系统正在运行；让我们开始四处看看，检查是否能够确定任何问题。

正如在之前的章节中介绍的，我们总是运行的第一个命令是`w`：

```
$ w
01:59:46 up 9 min,  1 user,  load average: 0.00, 0.01, 0.02
USER     TTY        LOGIN@   IDLE   JCPU   PCPU WHAT
vagrant  pts/0     01:59    2.00s  0.03s  0.01s w

```

在这种情况下，这个小习惯实际上效果很好。通过`w`命令的输出，我们可以看到这台服务器只运行了`9`分钟。看来我们的监控系统无法 ping 通我们的服务器，因为它正在重新启动。

### 提示

我们应该注意到我们能够确定服务器在登录后重新启动；这将是我们时间表中的一个关键事件。

## 有人重新启动了这台服务器吗？

虽然我们刚刚确定了警报的根本原因，但这并不是问题的根本原因。我们需要确定服务器为什么重新启动。服务器不经常（至少不应该）自行重新启动；有时可能只是有人在未告知其他人的情况下对该服务器进行维护。我们可以使用`last`命令查看最近是否有人登录到该服务器：

```
$ last
vagrant  pts/0        192.168.33.1     Sun Jul  5 01:59   still logged in 
joe  pts/1        192.168.33.1     Sat Jun  6 18:49 - 21:37  (02:48) 
bob  pts/0        10.0.2.2         Sat Jun  6 18:16 - 21:37  (03:21) 
billy  pts/0        10.0.2.2         Sat Jun  6 17:09 - 18:14  (01:05) 
doug  pts/0        10.0.2.2         Sat Jun  6 15:26 - 17:08  (01:42) 

```

`last`命令的输出从顶部开始显示最新的登录。这些数据来自`/var/log/wtmp`，用于存储登录详细信息。在`last`命令的输出末尾，我们看到以下行：

```
wtmp begins Mon Jun 21 23:39:24 2014

```

这告诉我们`wtmp`日志文件的历史记录；这是一个非常有用的信息。如果我们想查看特定数量的登录，我们可以简单地添加“-n”标志，后面跟上我们希望看到的登录数量。

这通常是非常有用的；但是，由于我们不知道最近在这台机器上有多少次登录，我们将使用默认设置。

从我们收到的输出中，我们可以看到最近没有人登录到这台服务器。除非有人亲自按下电源按钮或拔掉系统，否则我们可以假设没有人重新启动服务器。

### 提示

这是我们时间表中应该使用的另一个事实/事件。

## 日志告诉我们什么？

由于没有人重新启动这台服务器，我们的下一个假设是这台服务器是由软件或硬件问题重新启动的。我们下一个合乎逻辑的步骤是查看系统日志文件，以确定发生了什么事情：

```
01:59:46 up 9 min,  1 user,  load average: 0.00, 0.01, 0.02

```

```
less command to read /var/log/messages:
```

```
Jul  5 01:48:01 localhost auditd[560]: Audit daemon is low on disk space for logging
Jul  5 01:48:01 localhost auditd[560]: Audit daemon is suspending logging due to low disk space.
Jul  5 01:50:02 localhost watchdog[608]: loadavg 25 9 3 is higher than the given threshold 24 18 12!
Jul  5 01:50:02 localhost watchdog[608]: shutting down the system because of error -3
Jul  5 01:50:12 localhost rsyslogd: [origin software="rsyslogd" swVersion="7.4.7" x-pid="593" x-info="http://www.rsyslog.com"] exiting on signal 15.
Jul  5 01:50:32 localhost systemd: Time has been changed
Jul  5 01:50:32 localhost NetworkManager[594]: <info> dhclient started with pid 722
Jul  5 01:50:32 localhost NetworkManager[594]: <info> Activation (enp0s3) Stage 3 of 5 (IP Configure Start) complete.
Jul  5 01:50:32 localhost vboxadd-service: Starting VirtualBox Guest Addition service [  OK  ]
Jul  5 01:50:32 localhost systemd: Started LSB: VirtualBox Additions service.
Jul  5 01:50:32 localhost dhclient[722]: Internet Systems Consortium DHCP Client 4.2.5
Jul  5 01:50:32 localhost dhclient[722]: Copyright 2004-2013 Internet Systems Consortium.
Jul  5 01:50:32 localhost dhclient[722]: All rights reserved.
Jul  5 01:50:32 localhost dhclient[722]: For info, please visit https://www.isc.org/software/dhcp/
Jul  5 01:50:32 localhost dhclient[722]: 
Jul  5 01:50:32 localhost NetworkManager: Internet Systems Consortium DHCP Client 4.2.5
Jul  5 01:50:32 localhost NetworkManager: Copyright 2004-2013 Internet Systems Consortium.
Jul  5 01:50:32 localhost NetworkManager: All rights reserved.
Jul  5 01:50:32 localhost NetworkManager: For info, please visit https://www.isc.org/software/dhcp/
Jul  5 01:50:32 localhost NetworkManager[594]: <info> (enp0s3): DHCPv4 state changed nbi -> preinit
Jul  5 01:50:32 localhost dhclient[722]: Listening on LPF/enp0s3/08:00:27:20:5d:4b
Jul  5 01:50:32 localhost dhclient[722]: Sending on   LPF/enp0s3/08:00:27:20:5d:4b
Jul  5 01:50:32 localhost dhclient[722]: Sending on   Socket/fallback
Jul  5 01:50:32 localhost dhclient[722]: DHCPREQUEST on enp0s3 to 255.255.255.255 port 67 (xid=0x3ae55b57)

```

由于这里有相当多的信息，让我们稍微分解一下我们看到的内容。

第一个任务是找到一个清楚写在启动时的日志消息。通过识别写在启动时的日志消息，我们将能够确定在重新启动之前和之后写入了哪些日志。我们还将能够确定我们的根本原因文档的启动时间：

```
Jul  5 01:50:12 localhost rsyslogd: [origin software="rsyslogd" swVersion="7.4.7" x-pid="593" x-info="http://www.rsyslog.com"] exiting on signal 15.
Jul  5 01:50:32 localhost systemd: Time has been changed
Jul  5 01:50:32 localhost NetworkManager[594]: <info> dhclient started with pid 722
Jul  5 01:50:32 localhost NetworkManager[594]: <info> Activation (enp0s3) Stage 3 of 5 (IP Configure Start) complete.

```

看起来有希望的第一个日志条目是`NetworkManager`在`01:50:32`的消息。这条消息说明`NetworkManager`服务已启动`dhclient`。

`dhclient`进程用于发出 DHCP 请求并根据回复配置网络设置。这个过程通常只在网络被重新配置或在启动时调用：

```
Jul  5 01:50:12 localhost rsyslogd: [origin software="rsyslogd" swVersion="7.4.7" x-pid="593" x-info="http://www.rsyslog.com"] exiting on signal 15.

```

如果我们查看前一行，我们可以看到在 01:50:12，`rsyslogd`进程正在“退出信号 15”。这意味着在关机期间发送了终止信号给`rsyslogd`进程，这是一个非常标准的过程。

我们可以确定在 01:50:12 服务器正在关机过程中，在 01:50:32 服务器正在启动过程中。这意味着我们应该查看 01:50:12 之前的所有内容，以确定系统为什么重新启动。

### 提示

关机时间和启动时间也将需要用于我们的根本原因时间表。

从之前捕获的日志中，我们可以看到在 01:50 之前有两个进程写入了`/var/log/messages`；`auditd`和看门狗进程。

```
Jul  5 01:48:01 localhost auditd[560]: Audit daemon is low on disk space for logging
Jul  5 01:48:01 localhost auditd[560]: Audit daemon is suspending logging due to low disk space.

```

让我们首先看一下`auditd`进程。我们可以在第一行看到“磁盘空间不足”的消息。我们的系统是否因为磁盘空间不足而遇到问题？这是可能的，我们现在可以检查一下：

```
# df -h
Filesystem               Size  Used Avail Use% Mounted on
/dev/mapper/centos-root   39G   39G   32M 100% /
devtmpfs                 491M     0  491M   0% /dev
tmpfs                    498M     0  498M   0% /dev/shm
tmpfs                    498M  6.5M  491M   2% /run
tmpfs                    498M     0  498M   0% /sys/fs/cgroup
/dev/sda1                497M  104M  394M  21% /boot

```

看起来文件系统已经满了，但这本身通常不会导致重新启动。考虑到第二个`auditd`消息显示**守护程序正在暂停记录**；这也不像是重新启动过程。让我们继续查看，看看我们还能识别出什么：

```
Jul  5 01:50:02 localhost watchdog[608]: loadavg 25 9 3 is higher than the given threshold 24 18 12!
Jul  5 01:50:02 localhost watchdog[608]: shutting down the system because of error -3

```

`看门狗`进程的接下来两条消息很有趣。第一条消息指出服务器的`loadavg`高于指定的阈值。第二条消息非常有趣，因为它明确指出了“关闭系统”。

`看门狗`进程可能重新启动了这台服务器吗？也许是的，但首要问题是，`看门狗`进程是什么？

## 了解新的进程和服务

在查看`messages`日志时发现一个从未使用或见过的进程并不罕见：

```
# ps -eo cmd | sort | uniq | wc -l
115

```

即使在我们的基本示例系统上，进程列表中有 115 个独特的命令。特别是当你加入一个新版本，比如写作时的 Red Hat Enterprise Linux 7（较新的版本）。每个新版本都带来新的功能，甚至可能意味着默认运行新的进程。要跟上这一切是非常困难的。

就我们的例子而言，`看门狗`就是这种情况之一。在这一点上，除了从名称中推断出它是观察事物之外，我们不知道这个进程的作用。那么我们如何了解更多关于它的信息呢？好吧，我们要么谷歌一下，要么查看`man`：

```
$ man watchdog
NAME
 watchdog - a software watchdog daemon

SYNOPSIS
 watchdog [-F|--foreground] [-f|--force] [-c filename|--config-file filename] [-v|--verbose] [-s|--sync] [-b|--softboot] [-q|--no-action]

DESCRIPTION
 The  Linux  kernel  can  reset  the system if serious problems are detected.  This can be implemented via special watchdog hardware, or via a slightly less reliable software-only watchdog inside the kernel. Either way, there needs to be a daemon that tells the kernel the system is working fine. If the daemon stops doing that, the system is reset.

 watchdog is such a daemon. It opens /dev/watchdog, and keeps writing to it often enough to keep the kernel from resetting, at least once per minute. Each write delays the reboot time another minute. After a minute  of  inactivity the watchdog hardware will cause the reset. In the case of the software watchdog the ability to reboot will depend on the state of the machines and interrupts.

 The watchdog daemon can be stopped without causing a reboot if the device /dev/watchdog is closed correctly, unless your kernel is compiled with the CONFIG_WATCHDOG_NOWAYOUT option enabled.

```

根据`man`页面，我们已经确定`看门狗`服务实际上用于确定服务器是否健康。如果`看门狗`无法做到这一点，它可能会重新启动服务器：

```
Jul  5 01:50:02 localhost watchdog[608]: shutting down the system because of error -3

```

从这条日志消息中看来，`看门狗`软件是导致重新启动的原因。是不是因为文件系统已满，`看门狗`才重新启动了系统？

如果我们继续阅读`man`页面，我们将看到另一条有用的信息，如下所示：

```
TESTS
 The watchdog daemon does several tests to check the system status:

 ·  Is the process table full?

 ·  Is there enough free memory?

 ·  Are some files accessible?

 ·  Have some files changed within a given interval?

 ·  Is the average work load too high?

```

在这个列表的最后一个“测试”中，它指出`看门狗`守护程序可以检查平均工作负载是否过高：

```
Jul  5 01:50:02 localhost watchdog[608]: loadavg 25 9 3 is higher than the given threshold 24 18 12!

```

根据`man`页面和前面的日志消息，似乎`看门狗`并不是因为文件系统而重新启动服务器，而是因为服务器的负载平均值。

### 提示

在继续之前，让我们注意到在 01:50:02，`看门狗`进程启动了重新启动。

# 是什么导致了高负载平均值？

虽然我们已经确定了重新启动服务器的原因，但我们仍然没有找到问题的根本原因。我们仍然需要弄清楚是什么导致了高负载平均值。不幸的是，这被归类为重新启动期间丢失的信息。

如果系统仍然经历着高负载平均值，我们可以简单地使用`top`或`ps`来找出哪些进程正在使用最多的 CPU 时间。然而，一旦系统重新启动，任何导致高负载平均值的进程都将被重新启动。

除非这些进程再次导致高负载平均值，否则我们无法确定来源。

```
$ w
 02:13:07 up  23 min,  1 user,  load average: 0.00, 0.01, 0.05
USER     TTY        LOGIN@   IDLE   JCPU   PCPU WHAT
vagrant  pts/0     01:59    3.00s  0.26s  0.10s sshd: vagrant [priv]

```

然而，我们能够确定负载平均值开始增加的时间和增加到多高。随着我们进一步调查，这些信息可能会有用，因为我们可以用它来确定问题开始出现的时间。

要查看负载平均值的历史视图，我们可以使用`sar`命令：

```
$ sar

```

幸运的是，看起来`sar`命令的收集间隔设置为每`2`分钟。默认值为 10 分钟，这意味着我们通常会看到每 10 分钟的一行：

```
01:42:01 AM    all    0.01    0.00    0.06     0.00     0.00    99.92
01:44:01 AM    all    0.01    0.00    0.06     0.00     0.00    99.93
01:46:01 AM    all    0.01    0.00    0.06     0.00     0.00    99.93
01:48:01 AM    all   33.49    0.00    2.14     0.00     0.00    64.37
01:50:05 AM    all   87.80    0.00   12.19     0.00     0.00     0.01
Average:       all    3.31    0.00    0.45     0.00     0.00    96.24

01:50:23 AM       LINUX RESTART

01:52:01 AM   CPU   %user   %nice   %system   %iowait   %steal  %idle
01:54:01 AM   all   0.01    0.00     0.06     0.00       0.00   99.93
01:56:01 AM   all   0.01    0.00     0.05     0.00       0.00   99.94
01:58:01 AM   all   0.01    0.00     0.05     0.00       0.00   99.94
02:00:01 AM   all   0.03    0.00     0.10     0.00       0.00   99.87

```

从输出中可以看出，在`01:46`，这个系统几乎没有 CPU 使用率。然而，从`01:48`开始，用户空间的 CPU 利用率达到了`33`％。

此外，似乎在`01:50`，`sar`能够捕获到 CPU 利用率达到`99.99`％，其中用户使用了`87.8`％，系统使用了`12.19`％。

### 提示

以上都是我们在根本原因总结中可以使用的好事实。

有了这个，我们现在知道我们的问题是在`01:44`和`01:46`之间开始的，我们可以从 CPU 使用情况中看出。

让我们使用`-q`标志来查看负载平均值，看看负载平均值是否与 CPU 利用率匹配：

```
# sar -q
Again, we can narrow events down even further:
01:42:01 AM        0      145     0.00      0.01      0.02         0
01:44:01 AM        0      145     0.00      0.01      0.02         0
01:46:01 AM        0      144     0.00      0.01      0.02         0
01:48:01 AM       14      164     4.43      1.12      0.39         0
01:50:05 AM       37      189    25.19      9.14      3.35         0
Average:           1      147     0.85      0.30      0.13         0

01:50:23 AM       LINUX RESTART

01:52:01 AM   runq-sz  plist-sz  ldavg-1   ldavg-5  ldavg-15  blocked
01:54:01 AM         0       143     0.01      0.04      0.02        0
01:56:01 AM         1       138     0.00      0.02      0.02        0
01:58:01 AM         0       138     0.00      0.01      0.02        0
02:00:01 AM         0       141     0.00      0.01      0.02        0

```

通过**负载平均**的测量，我们可以看到即使在`01:46`时 CPU 利用率很高，一切都很平静。然而，在接下来的`01:48`运行中，我们可以看到**运行队列**为 14，1 分钟负载平均值为 4。

## 运行队列和负载平均值是什么？

由于我们正在查看运行队列和负载平均值，让我们花一点时间来理解这些值的含义。

在一个非常基本的概念中，运行队列值显示了处于等待执行状态的进程数量。

更多细节，请考虑一下 CPU 及其工作原理。单个 CPU 一次只能执行一个任务。如今大多数服务器都有多个核心，有时每台服务器还有多个处理器。在 Linux 上，每个核心和线程（对于超线程 CPU）都被视为单个 CPU。

每个 CPU 都能一次执行一个任务。如果我们有两个 CPU 服务器，我们的服务器可以同时执行两个任务。

假设我们的双 CPU 系统需要同时执行四个任务。系统可以执行其中两个任务，但另外两个任务必须等到前两个任务完成后才能执行。当出现这种情况时，等待的进程将被放入“运行队列”。当系统中有进程在运行队列中时，它们将被优先处理，并在 CPU 可用时执行。

在我们的`sar`捕获中，我们可以看到 01:48 时运行队列值为 14；这意味着在那一刻，有 14 个任务在运行队列中等待 CPU。

### 负载平均值

负载平均值与运行队列有些不同，但并不完全相同。负载平均值是在一定时间内的平均运行队列值。在我们前面的例子中，我们可以看到`ldavg-1`（这一列是最近一分钟的平均运行队列长度）。

运行队列值和 1 分钟负载平均值可能会有所不同，因为由`sar`报告的运行队列值是在执行时的值，而 1 分钟负载平均值是 60 秒内的运行队列平均值。

```
01:46:01 AM        0      144      0.00      0.01      0.02         0
01:48:01 AM       14      164      4.43      1.12      0.39         0
01:50:05 AM       37      189     25.19      9.14      3.35         0

```

高运行队列的单次捕获未必意味着存在问题，特别是如果 1 分钟负载平均值不高的话。然而，在我们的例子中，我们可以看到在`01:48`时，我们的运行队列中有 14 个任务在队列中，在`01:50`时，我们的运行队列中有 37 个任务在队列中。

另外，我们可以看到在`01:50`时，我们的 1 分钟负载平均值为 25。

根据与 CPU 利用率的重叠，似乎大约在 01:46 - 01:48 左右，发生了导致 CPU 利用率高的事件。除了这种高利用率外，还有许多需要执行但无法执行的任务。

### 提示

我们应该花一点时间记录下我们在`sar`中看到的时间和值，因为这些将是根本原因总结所必需的细节。

# 调查文件系统是否已满

早些时候，我们注意到文件系统已经满了。不幸的是，我们安装的`sysstat`版本没有捕获磁盘空间使用情况。一个有用的事情是确定文件系统填满的时间与我们的运行队列开始增加的时间相比：

```
Jul  5 01:48:01 localhost auditd[560]: Audit daemon is low on disk space for logging
Jul  5 01:48:01 localhost auditd[560]: Audit daemon is suspending logging due to low disk space.

```

从我们之前看到的日志消息中，我们可以看到`auditd`进程在`01:48`识别出低磁盘空间。这与我们看到运行队列急剧增加的时间非常接近。

这正建立在一个假设的基础上，即问题的根本原因是文件系统填满，导致一个进程要么启动了许多 CPU 密集型任务，要么阻塞了 CPU 以执行其他任务。

虽然这是一个合理的理论，但我们必须证明它是真实的。我们可以更接近证明这一点的方法之一是确定在这个系统上利用了大部分磁盘空间的是什么：

```
# du -k / | sort -nk 1 | tail -25
64708  /var/cache/yum/x86_64/7/epel
67584  /var/cache/yum/x86_64/7/base
68668  /usr/lib/firmware
75888  /usr/lib/modules/3.10.0-123.el7.x86_64/kernel/drivers
80172  /boot
95384  /usr/share/locale
103548  /usr/lib/locale
105900  /usr/lib/modules/3.10.0-123.el7.x86_64/kernel
116080  /usr/lib/modules
116080  /usr/lib/modules/3.10.0-123.el7.x86_64
148276  /usr/bin
162980  /usr/lib64
183640  /var/cache/yum
183640  /var/cache/yum/x86_64
183640  /var/cache/yum/x86_64/7
184396  /var/cache
285240  /usr/share
317628  /var
328524  /usr/lib
1040924  /usr
2512948  /opt/myapp/logs
34218392  /opt/myapp/queue
36731428  /opt/myapp
36755164  /opt
38222996  /

```

前面的一行代码是一个非常有用的方法，用于识别哪些目录或文件使用了最多的空间。

## du 命令

前面的一行命令使用了`sort`命令，你在第十一章中学到了有关`sort`命令的知识，*从常见故障中恢复*，对`du`的输出进行排序。`du`命令是一个非常有用的命令，可以估算给定目录使用的空间量。

例如，如果我们想知道`/var/tmp`目录使用了多少空间，我们可以很容易地通过以下`du`命令来确定：

```
# du -h /var/tmp
0  /var/tmp/systemd-private-Wu4ixe/tmp
0  /var/tmp/systemd-private-Wu4ixe
0  /var/tmp/systemd-private-pAN90Q/tmp
0  /var/tmp/systemd-private-pAN90Q
160K  /var/tmp

```

`du`的一个有用属性是，默认情况下，它不仅会列出`/var/tmp`，还会列出其中的目录。我们可以看到有几个目录里面什么都没有，但`/var/tmp/`目录包含了 160 kb 的数据。

```
# du -h /var/tmp/
0  /var/tmp/systemd-private-Wu4ixe/tmp
0  /var/tmp/systemd-private-Wu4ixe
0  /var/tmp/systemd-private-pAN90Q/tmp
0  /var/tmp/systemd-private-pAN90Q
4.0K  /var/tmp/somedir
164K  /var/tmp/

```

### 注意

重要的是要知道`/var/tmp`的大小是`/var/tmp`中的内容的大小，其中包括其他子目录。

为了说明前面的观点，我创建了一个名为`somedir`的目录，并在其中放了一个 4 kb 的文件。我们可以从随后的`du`命令中看到，`/var/tmp`目录现在显示已使用 164 kb。

`du`命令有很多标志，可以让我们改变它输出磁盘使用情况的方式。在前面的例子中，由于`-h`标志的存在，这些值以人类可读的格式打印出来。在一行命令中，由于`-k`标志的存在，这些值以千字节表示：

```
2512948  /opt/myapp/logs
34218392  /opt/myapp/queue
36731428  /opt/myapp
36755164  /opt
38222996  /

```

如果我们回到一行命令，我们可以从输出中看到，在`/`中使用的 38 GB 中，有 34 GB 在`/opt/myapp/queue`目录中。这个目录对我们来说非常熟悉，因为我们在之前的章节中曾解决过这个目录的问题。

根据我们以往的经验，我们知道这个目录用于排队接收自定义应用程序接收的消息。

考虑到这个目录的大小，有可能在重新启动之前，自定义应用程序在这台服务器上运行，并填满了文件系统。

我们已经知道这个目录占用了系统上大部分的空间。确定这个目录中最后一个文件的创建时间将会很有用，因为这将给我们一个大致的应用上次运行的时间范围：

```
# ls -l
total 368572
drwxrwxr-x. 2 vagrant vagrant        40 Jun 10 17:03 bin
drwxrwxr-x. 2 vagrant vagrant        23 Jun 10 16:55 conf
drwxrwxr-x. 2 vagrant vagrant        49 Jun 10 16:40 logs
drwxr-xr-x. 2 root    root    272932864 Jul  5 01:50 queue
-rwxr-xr-x. 1 vagrant vagrant       116 Jun 10 16:56 start.sh

```

我们实际上可以通过在`/opt/myapp`目录中执行`ls`来做到这一点。从前面的输出中，我们可以看到`queue/`目录上次修改是在 7 月 5 日 01:50。这与我们的问题非常吻合，至少证明了在重新启动之前自定义应用程序是在运行的。

### 提示

这个目录上次更新的时间戳以及这个应用程序运行的事实都是我们在总结中要记录的项目。

根据前面的信息，我们可以在这一点上安全地说，在事故发生时，自定义应用程序正在运行，并且已经创建了足够的文件来填满文件系统。

我们还可以说，在文件系统达到 100％利用率时，服务器的负载平均值突然飙升。

根据这些事实，我们可以提出一个假设；我们目前的工作理论是，一旦应用程序填满了文件系统，它就不再能创建文件。这可能导致相同的应用程序阻塞 CPU 时间或产生许多 CPU 任务，从而导致负载平均值升高。

## 为什么队列目录没有被处理？

由于我们知道自定义应用程序是文件系统问题的根源，我们还需要回答为什么。

在之前的章节中，你学到了这个应用程序的队列目录是由作为`vagrant`用户运行的`cronjob`处理的。让我们通过查看`/var/log/cron`日志文件来看一下上次运行该 cron 作业的时间：

```
Jun  6 15:28:01 localhost CROND[3115]: (vagrant) CMD (/opt/myapp/bin/processor --debug --config /opt/myapp/conf/config.yml > /dev/null)

```

根据`/var/log/cron`目录的记录，作业上次运行的时间是`6 月 6 日`。这个时间线大致与这个进程被移动到另一个系统的时间相吻合，之后服务器就没有内存了。

处理器作业是否停止了但应用程序没有停止？可能是，我们知道应用程序正在运行，但让我们检查一下`processor`作业。

我们可以使用`crontab`命令检查处理器作业是否已被删除：

```
# crontab -l -u vagrant
#*/4 * * * * /opt/myapp/bin/processor --debug --config /opt/myapp/conf/config.yml > /dev/null

```

`-l`（列出）标志将导致`crontab`命令打印或列出为执行它的用户定义的 cronjobs。当添加`-u`（用户）标志时，它允许我们指定要列出 cronjobs 的用户，在这种情况下是`vagrant`用户。

从列表中看来，`processor`作业并没有被删除，而是被禁用了。我们可以看到它已被禁用，因为该行以`#`开头，这用于在`crontab`文件中指定注释。

这基本上将工作变成了一条注释，而不是一个计划任务。这意味着`crond`进程不会执行这项工作。

## 您所学到的内容的检查点

在这一点上，让我们对我们能够确定和收集的内容进行一次检查点。

登录系统后，我们能够确定服务器已经重新启动。我们能够在`/var/log/messages`中看到`watchdog`进程负责重新启动服务器：

```
Jul  5 01:50:02 localhost watchdog[608]: loadavg 25 9 3 is higher than the given threshold 24 18 12!

```

根据`/var/log/messages`中的日志消息，看门狗进程因负载过高而重新启动了服务器。从`sar`中，我们可以看到负载平均值在几分钟内从 0 上升到 25。

在进行调查时，我们还能够确定服务器的`/`（根）文件系统已满。不仅满了，而且有趣的是，在系统重新启动前几分钟它大约使用了 100％。

文件系统处于这种状态的原因是因为`/opt/myapp`中的自定义应用程序仍在运行并在`/opt/myapp/queue`中创建文件。然而，清除此队列的作业未运行，因为它已在 vagrant 用户的`crontab`中被注释掉。

基于此，我们可以说我们问题的根本原因很可能是由于文件系统填满，这是由于应用程序正在运行但未处理消息造成的。

### 有时你不能证明一切

在这一点上，我们已经确定了导致负载平均值升高的几乎所有原因。由于我们没有在事件发生时运行的进程的快照，我们无法确定是自定义应用程序。根据我们能够收集到的信息，我们也无法确定是因为文件系统填满而触发的。

我们可以通过在另一个系统中复制此场景来测试这个理论，但这不一定是在周末凌晨 2:00 要做的事情。通常，将问题复制到这个程度通常是作为后续活动来执行的。

在这一点上，根据我们找到的数据，我们可以相当肯定地确定根本原因。在许多情况下，这是你能得到的最接近的，因为你可能没有时间收集数据，或者根本没有数据来确定根本原因。

# 防止再次发生

由于我们对发生的原因有了相当自信的假设，现在我们可以继续进行我们根本原因分析的最后一步；防止问题再次发生。

正如我们在本章开头讨论的那样，所有有用的根本原因分析报告都包括一个行动计划。有时，这个行动计划是在问题发生时立即执行的。有时，这个计划是作为长期解决方案稍后执行的。

对于我们的问题，我们将采取即时行动和长期行动。

## 即时行动

我们需要采取的第一个即时行动是确保系统的主要功能健康。在这种情况下，服务器的主要功能是为公司的博客提供服务。

![即时行动](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel-tbst-gd/img/00009.jpeg)

通过在浏览器中访问博客地址很容易检查。从前面的截图中我们可以看到博客正在正常工作。为了确保，我们也可以验证 Apache 服务是否正在运行：

```
# systemctl status httpd
httpd.service - The Apache HTTP Server
 Loaded: loaded (/usr/lib/systemd/system/httpd.service; enabled)
 Active: active (running) since Sun 2015-07-05 01:50:36 UTC; 3 days ago
 Main PID: 1015 (httpd)
 Status: "Total requests: 0; Current requests/sec: 0; Current traffic:   0 B/sec"
 CGroup: /system.slice/httpd.service
 ├─1015 /usr/sbin/httpd -DFOREGROUND
 ├─2315 /usr/sbin/httpd -DFOREGROUND
 ├─2316 /usr/sbin/httpd -DFOREGROUND
 ├─2318 /usr/sbin/httpd -DFOREGROUND
 ├─2319 /usr/sbin/httpd -DFOREGROUND
 ├─2321 /usr/sbin/httpd -DFOREGROUND
 └─5687 /usr/sbin/httpd -DFOREGROUND

Jul 05 01:50:36 blog.example.com systemd[1]: Started The Apache HTTP Server.

```

从这个情况来看，我们的 Web 服务器自重启以来一直在线，这很好，因为这意味着博客自重启以来一直在工作。

### 提示

有时，根据系统的重要性，甚至在调查问题之前，首先验证系统是否正常运行可能是很重要的。与任何事情一样，这实际上取决于环境，因为关于哪个先来的硬性规定并不是绝对的。

现在我们知道博客正在正常工作，我们需要解决磁盘已满的问题。

```
# ls -la /opt/myapp/queue/ | wc -l
495151

```

与之前的章节一样，似乎`queue`目录中有很多等待处理的消息。为了正确清除这些消息，我们需要手动运行`processor`命令，但还需要进行一些额外的步骤：

```
# sysctl -w fs.file-max=500000
fs.file-max = 500000

```

我们必须采取的第一步是增加系统一次可以打开的文件数量。我们根据过去使用 processor 应用程序和大量消息的经验得知这一点。

```
# su - vagrant
$ ulimit -n 500000
$ ulimit -a
core file size          (blocks, -c) 0
data seg size           (kbytes, -d) unlimited
scheduling priority             (-e) 0
file size               (blocks, -f) unlimited
pending signals                 (-i) 7855
max locked memory       (kbytes, -l) 64
max memory size         (kbytes, -m) unlimited
open files                      (-n) 500000
pipe size            (512 bytes, -p) 8
POSIX message queues     (bytes, -q) 819200
real-time priority              (-r) 0
stack size              (kbytes, -s) 8192
cpu time               (seconds, -t) unlimited
max user processes              (-u) 4096
virtual memory          (kbytes, -v) unlimited
file locks                      (-x) unlimited

```

第二步是增加对`vagrant`用户施加的用户限制；具体来说，是增加打开文件数量的限制。这一步需要在我们执行`processor`命令的同一个 shell 会话中执行。完成这一步后，我们可以手动执行`processor`命令来处理排队的消息：

```
$ /opt/myapp/bin/processor --debug --config /opt/myapp/conf/config.yml
Initializing with configuration file /opt/myapp/conf/config.yml
- - - - - - - - - - - - - - - - - - - - - - - - - -
Starting message processing job
Added 495151 to queue
Processing 495151 messages
Processed 495151 messages

```

现在消息已经被处理，我们可以使用`df`命令重新检查文件系统利用率：

```
# df -h
Filesystem               Size  Used Avail Use% Mounted on
/dev/mapper/centos-root   39G  3.8G   35G  10% /
devtmpfs                 491M     0  491M   0% /dev
tmpfs                    498M     0  498M   0% /dev/shm
tmpfs                    498M   13M  485M   3% /run
tmpfs                    498M     0  498M   0% /sys/fs/cgroup
/dev/sda1                497M  104M  394M  21% /boot

```

正如我们所看到的，`/`文件系统的利用率已降至`10%`。

为了确保我们不会再次填满这个文件系统，我们验证自定义应用程序当前是否已停止：

```
# ps -elf | grep myapp
0 R root      6535  2537  0  80   0 - 28160 -      15:09 pts/0    00:00:00 grep --color=auto myapp

```

由于我们看不到以应用程序命名的任何进程在运行，我们可以确信该应用程序当前未运行。

## 长期行动

这带我们来到我们的**长期行动**。长期行动是我们将在根本原因总结中推荐的行动，但此刻不会采取的行动。

建议的第一个长期行动是永久删除该系统中的自定义应用程序。由于我们知道该应用程序已迁移到另一个系统，因此在这台服务器上不再需要。但是，删除该应用程序不是我们应该在凌晨 2 点或在验证它是否真的不再需要之前就进行的事情。

第二个长期行动是调查添加监控解决方案，可以定期对运行中的进程和这些进程的 CPU/状态进行快照。如果在这次根本原因分析调查中有这些信息，我们将能够毫无疑问地证明哪个进程导致了高负载。由于这些信息不可用，我们只能做出合理的猜测。

再次强调，这不是我们想在深夜电话中处理的任务，而是标准工作日的事情。

# 根本原因分析示例

现在我们已经获得了所有需要的信息，让我们创建一个根本原因分析报告。实际上，这份报告可以是任何格式，但我发现以下内容比较有效。

## 问题总结

2015 年 7 月 5 日凌晨 1:50 左右，服务器`blog.example.com`意外重启。由于服务器负载平均值过高，`watchdog`进程启动了重启过程。

经过调查，高负载平均值似乎是由一个自定义的电子邮件应用程序引起的，尽管它已经迁移到另一台服务器，但仍处于运行状态。

根据可用数据，似乎应用程序占用了根文件系统的 100%。

虽然我无法获得重启前的进程状态，但似乎高负载平均值也可能是由于同一应用程序无法写入磁盘而引起的。

## 问题详情

事件报告的时间为 2015 年 7 月 5 日`01:52`

事件的时间线将是：

+   在`01:52`收到了一条短信警报，说明`blog.example.com`通过 ICMP ping 不可访问。

+   执行的第一步故障排除是对服务器进行 ping：

+   ping 显示服务器在线

+   在`01:59`登录服务器并确定服务器已重新启动。

+   搜索`/var/log/messages`文件，并确定`watchdog`进程在`01:50:12`重新启动了服务器：

+   `watchdog`在`01:50:02`开始了重新启动过程

+   在调查过程中，我们发现在事件发生时没有用户登录

+   服务器在`01:50:32`开始了引导过程

+   在调查过程中，发现服务器在`01:48:01`已经没有可用的磁盘空间。

+   该系统的负载平均值在大约相同的时间开始增加，达到`01:50:05`时为 25。

+   我们确定`/opt/myapp/queue`目录在`01:50`最后修改，并包含大约 34GB 的数据，导致 100%的磁盘利用率：

+   这表明自定义电子邮件应用程序一直在服务器重新启动之前运行

+   我们发现自 6 月 6 日以来`processor`作业没有运行，这意味着消息没有被处理。

## 根本原因

由于自定义应用程序在未通过 cron 执行`processor`作业的情况下运行，文件系统达到 100%利用率。收集的数据表明这导致了高负载平均值，触发了`watchdog`进程重新启动服务器。

## 行动计划

我们应该采取以下步骤：

+   验证 Apache 正在运行并且`Blog`是可访问的

+   验证系统重新启动后自定义应用程序未在运行

+   在 02:15 手动执行了处理器作业，解决了磁盘空间问题

### 需要采取进一步行动

+   从服务器中删除自定义应用程序，以防止应用程序意外启动

+   调查添加进程列表监视，以捕获在类似问题期间利用 CPU 时间的进程：

+   将有助于解决类似情况

正如您在前面的报告中所看到的，我们有一个高层次的时间线，显示了我们能够确定的内容，我们如何确定的，以及我们采取的解决问题的行动。这是一个良好的根本原因分析的所有关键组成部分。

# 总结

在本章中，我们介绍了如何应对一个非常困难的问题：意外的重新启动。我们使用了本书中看到的工具和方法来确定根本原因并创建根本原因报告。

我们在整本书中大量使用日志文件；在本章中，我们能够使用这些日志文件来识别重新启动服务器的进程。我们还确定了`watchdog`决定重新启动服务器的原因，这是由于高负载平均值。

我们能够使用`sar`、`df`、`du`和`ls`等工具来确定高负载平均值的时间和原因。这些工具都是您在整本书中学到的命令。

通过本章，我们涵盖了本书中早期涵盖的许多示例。您学会了如何解决 Web 应用程序、性能问题、自定义应用程序和硬件问题。我们使用了真实世界的示例和解决方案。

尽管本书涵盖了相当多的主题，但本书的目标是向您展示如何解决红帽企业 Linux 系统的故障排除问题。示例可能很常见，也可能有些罕见，但这些示例中使用的命令是在故障排除过程中日常使用的命令。所涵盖的主题都提供了与 Linux 相关的核心能力，并将为您提供解决本书未直接涵盖的问题所需的知识。
