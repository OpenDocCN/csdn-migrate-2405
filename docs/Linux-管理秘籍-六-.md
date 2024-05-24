# Linux 管理秘籍（六）

> 原文：[`zh.annas-archive.org/md5/d1276a108c48d7de17a374836db89ea5`](https://zh.annas-archive.org/md5/d1276a108c48d7de17a374836db89ea5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：权限、SELinux 和 AppArmor

在本章中，我们将涵盖以下主题：

+   Linux 文件权限

+   修改文件权限

+   用户和组

+   AppArmor 和修改

+   SELinux 和修改

+   检查 SELinux 是否正在运行，以及保持其运行的重要性

+   重置 SELinux 权限

# 介绍

在早期，早在 90 年代的迷雾中，Linux 在访问控制方面并不多……然后是权限和属性。权限和属性是文件的元素，它们决定了系统和用户对该文件（或文件夹）的访问权限，以及在交互方面对文件的操作能力。在基本水平上，您可以使用`ls`查看权限信息（稍后会详细介绍），但现在先看以下示例：

```
$ ls -l .
total 0
-rw-rw-r--. 1 vagrant vagrant 0 Oct 28 10:42 examplefile
```

在本章中，我们将学习从基本的 Linux 权限到 SELinux 和 AppArmor。我们还将探讨可能由 SELinux 或 AppArmor 引起的故障排除问题。我们还将学习不要禁用扩展权限控制的重要性。

在安全方面，锁定系统显然很重要，而在极端情况下，您可以创建一个系统，其中每个程序都对其他程序一无所知（实际上使每个程序都被隔离）。

虽然安全性从来都不是坏事，但平衡至关重要。您不希望开始为 Ubuntu 安装中的每个文件的权限而感到紧张，那里有成千上万个文件，除非您在完成之前就疯了……除非这确实是您唯一的工作，或者您想要一个特别乏味的爱好，否则就放手去做吧！

# 技术要求

在本章中，我们将使用以下`Vagrantfile`；请注意，我们只使用两台机器：CentOS 突出显示 SELinux 的功能和能力，以及 Ubuntu 安装用于 AppArmor：

```
# -*- mode: ruby -*-
# vi: set ft=ruby :

$provisionScript = <<-SCRIPT
sed -i 's/console=tty0 console=ttyS0,115200n8//g' /boot/grub2/grub.cfg
systemctl restart sshd
SCRIPT

Vagrant.configure("2") do |config|

 config.vm.define "centos7" do |centos7|
 centos7.vm.box = "centos/7"
 centos7.vm.box_version = "1804.02"
 centos7.vm.provision "shell",
 inline: $provisionScript
 end

 config.vm.define "ubuntu1804" do |ubuntu1804|
 ubuntu1804.vm.box = "ubuntu/bionic64"
 ubuntu1804.vm.box_version = "20180927.0.0"
 end

end
```

在撰写本文时，此处使用的`provisionScript`是为了修复本章中一个部分的轻微问题。如果您在使用此脚本时遇到问题，请随时从配置中删除它（在相关部分中稍后会有一条注释，我们会在那里讨论`.autorelabel`）。

# Linux 文件权限

首先，我们将回到基础知识，看一下默认的 Linux 文件权限。

在本节中，我们将使用 CentOS 框上的一个文件和一个目录，以突出一些重要的基本知识，这些知识可以帮助我们继续前进。

Unix 和类 Unix 系统上的文件权限与 Windows 和其他操作系统安装中的文件权限不同。如果您将使用 Unix 文件系统（如 XFS）格式化的硬盘连接到 Windows 框，它可能无法准确读取文件的权限（除非您有软件可以为您执行此操作）。近年来，由于 Windows 10 中包含的 Windows 子系统等因素，这些界限已经有所模糊，但基本原则基本上是正确的。

# 准备工作

跳到您的 CentOS 框。在本节中，我们讨论的所有内容都适用于 Linux 发行版：

```
$ vagrant ssh centos7
```

按照以下方式创建一个文件、一个目录和该目录中的一个文件：

```
$ touch examplefile
$ mkdir exampledir
$ touch exampledir/examplefile-in-exampledir
```

# 操作步骤

在*准备工作*部分的文件就绪后，运行`ls -l`查看我们创建的内容：

```
$ ls -l
total 0
drwxrwxr-x. 2 vagrant vagrant 39 Oct 28 11:01 exampledir
-rw-rw-r--. 1 vagrant vagrant 0 Oct 28 11:00 examplefile
```

此处使用的`-l`表示使用长列表格式，并且不仅用于打印找到的文件和文件夹，还用于为我们提供更完整的图片。

# 工作原理

我们需要对此进行详细说明，因为乍一看，它可能会显得相当令人困惑：

# exampledir

从`exampledir`开始，让我们看看这个目录的权限和所有权。

```
drwxrwxr-x. 2 vagrant vagrant
```

我们有一系列字母、一个数字`2`，然后是两个名字，`vagrant`和`vagrant`。

```
drwxrwxr-x.
```

开头的`d`很容易理解；它表示列出的项目实际上是一个目录。

```
drwxrwxr-x.
```

然后，我们有三个看起来相似的元素，其中第一个是用户权限。在这里，权限是读、写和执行。

这意味着用户将能够在目录中 `touch`（创建）文件，`mv`（重命名）它们，`ls`（列出）它们，`cat`/`less`（读取）它们，甚至 `rm`（删除）它们，如果他们愿意的话。

```
drwxrwxr-x.
```

接下来，我们有组权限，这里再次是读、写和执行。

```
drwxrwxr-x.
```

第三，我们有每个人的权限，这种情况下任何人都可以读取或进入目录。

他们将无法创建、重命名或删除现有文件，因为他们没有写 (`w`) 权限。

即使是有经验的系统管理员也会忘记这一点。如果你在一个可以访问目录中文件内容的组中，但目录本身的权限不允许这样做，你将无法完成操作。我听到一些与这个小提示相关的相当显著的叹息声。

我们还有块末尾的 `.`。现在我们不用太担心这个，但它表示目录已经应用了安全上下文：

```
drwxrwxr-x. 2
```

在这种情况下，数字 `2` 指的是指向索引节点的位置的数量（实际存储数据的磁盘上的位置）。在这种情况下为什么是 `2` 是因为每次创建一个目录时都会创建两个条目，可以用 `ls -la` 查看：

```
$ ls -la exampledir/
total 0
drwxrwxr-x. 2 vagrant vagrant 39 Oct 28 11:18 .
drwx------. 4 vagrant vagrant 132 Oct 28 11:01 ..
-rw-rw-r--. 1 vagrant vagrant 0 Oct 28 11:18 examplefile-in-exampledir
```

在这里，我们可以看到两个特殊条目，`.` 和 `..`，分别指代这个目录和父目录。

因此，有两个链接指向这个目录；第一个是来自父目录 (`/home/vagrant/exampledir`)，第二个是来自目录本身 (`/home/vagrant/exampledir/.`)。搞糊涂了吗？

现在是一个更容易的部分，`vagrant vagrant` 条目：

```
vagrant vagrant
```

这些只是用户，然后是组，他们的权限反映在 `drwxrwxr-x.` 块中。没有每个人的条目，因为那样就没有意义了。

# 示例文件

继续讨论 `examplefile`，我们有以下内容：

```
-rw-rw-r--. 1 vagrant vagrant  0 Oct 28 11:00 examplefile
```

在这里，我们可以看到与 `exampledir` 几乎相同，有一些变化。

`d` 被 `a` 替换了，意味着我们正在处理一个实际文件。

```
-rw-rw-r--.
```

用户和组的权限只有读和写，这意味着文件可以被读取和修改，但用户和组还不能执行。

```
-rw-rw-r--.
```

其他所有人的权限只有读，这意味着文件可以使用 `cat`/`less`，但不能被修改或执行。

```
-rw-rw-r--. 1
```

最后，我们可以看到链接数为 `1`，这是有道理的，因为底层索引节点没有从其他地方引用。

# 还有更多...

还有一些有用的东西要提一下，即使我们在这里没有涉及。

# 对目录和文件的根访问

`god/super/almighty` 用户 (`root`) 几乎对系统上的所有东西都有完全的访问权限，这意味着你可能会看到人们采取的一个常见快捷方式是以下内容，如果他们对无法读取文件感到沮丧：

```
$ sudo cat examplefile
```

这将起作用，因为 `root` 有这个权限，但是养成使用 `sudo` 处理所有事情的坏习惯是不好的。要有选择地使用它，并在任意在命令前加上 `sudo` 之前考虑一下你在做什么。 （大多数情况下，这是对我自己的一条信息，因为我和其他人一样，也经常犯这个错误。）

# 其他执行字符

在执行列中，除了普通的 `x` 外，还可能看到其他字符，其中最常见的是 `s` 和 `t`。

看看 `wall` 程序的这些权限：

```
$ ls -l /usr/bin/wall
-r-xr-sr-x. 1 root tty 15344 Jun 9 2014 /usr/bin/wall
```

请注意组中的 `s` 替代了 `x`。

这被称为 `setuid` 和 `setgid` 位，取决于它是在用户还是组三元组中，它有效地将执行用户的权限更改为所有者或组的权限，再次取决于三元组。在这种情况下，执行 `wall` 命令的用户获得 `tty` 组的权限（允许 `wall` 输出到所有 `tty`）。

在这里，我正在使用 `wall` 作为 vagrant 用户：

```
$ wall There is no Hitchhikers Movie! 
$ 
Broadcast message from vagrant@localhost.localdomain (pts/0) (Sun Oct 28 11:52:12 2018):

There is no Hitchhikers Movie!
```

`t` 条目，或者叫做粘性位，再次非常罕见，但它最常设置在 `/tmp` 目录上：

```
$ ls -la /tmp
total 0
drwxrwxrwt. 8 root root 172 Oct 28 11:54 .
<SNIP>
```

记住`.`字符指的是这个目录。

它设置了只有`/tmp`中文件的所有者才能重命名或删除该文件，这意味着如果我以`vagrant`用户的身份在`/tmp`中创建文件，其他人就不能来删除我的文件（除了`root`）。在视觉上，它看起来像下面这样：

```
$ rm /tmp/test2 
rm: remove write-protected regular empty file '/tmp/test2'? y
rm: cannot remove '/tmp/test2': Operation not permitted
```

还有其他两个执行字符，但这些是最常见的。

# 修改文件权限

创建文件是很好的，但最终我们会遇到默认权限不可接受的情况。

一个很好的例子是 SSH，除非在你的公钥和私钥上有一些特别严格的文件权限，否则它根本不会工作。

所以，"三剑客"来了，以`chown`，`chmod`和`chattr`的形式。

如果你想要真的很烦人，并且容易失去朋友，坚持称呼这些为它们的全称：改变所有权，改变模式和改变属性。

# 准备工作

在本节中，我们将再次使用我们的`Vagrantfile`中的 CentOS VM，因为我们所做的一切都是普遍适用的。

SSH 到你的 CentOS VM：

```
$ vagrant ssh centos7
```

进入`/home`目录（上一级）并创建一个文件，一个目录，以及该目录中的一个文件：

```
$ cd /home
$ sudo touch permissionfile
$ sudo mkdir permissiondir
$ sudo touch permissiondir/permissionfile-in-permissiondir
```

我们还将创建另一个虚拟用户，我们可以用来解释本节中正在做的事情：

```
$ sudo adduser packt -s /bin/bash -p '$1$2QzaOp2Q$Ke2yWZ1N2h4rk8r8P95Sv/'

```

请注意，我们设置的密码是'correcthorsebatterystaple'。

# 如何做...

我们将按顺序运行三个命令（`chown`，`chmod`和`chattr`）。

# chown

从最简单的部分开始，我们将查看所讨论文件的所有权。

首先列出我们已经拥有的内容：

```
$ ls -lha
total 0
drwxr-xr-x. 4 root root 64 Oct 28 12:37 .
dr-xr-xr-x. 18 root root 239 Oct 28 12:35 ..
drwxr-xr-x. 2 root root 45 Oct 28 12:37 permissiondir
-rw-r--r--. 1 root root 0 Oct 28 12:37 permissionfile
drwx------. 3 vagrant vagrant 74 May 12 18:54 vagrant
```

假设我们想让我们的 vagrant 用户可以写入`permissionfile`，而不是当前只能读取它的能力。请注意以下内容：

```
$ echo "RFCs are great if boring." > permissionfile
-bash: permissionfile: Permission denied
```

我们将使用`chown`进行更改，通过传递我们想要将文件更改为的用户和组：

```
$ sudo chown vagrant:root permissionfile
```

现在，检查权限：

```
$ ls -l permissionfile
-rw-r--r--. 1 vagrant root 0 Oct 28 12:37 permissionfile
```

这意味着我们作为 vagrant 用户现在可以写入文件：

```
$ echo "RFCs are great if boring." > permissionfile
$ cat permissionfile
RFCs are great if boring.
```

但是，其他用户（不是`root`）无法写入文件：

```
$ su - packt -c "echo IMPOSSIBLE > /home/permissionfile"
Password: 
-bash: /home/permissionfile: Permission denied
```

在这里，我们使用`su`以 Packt 用户的身份执行命令，并且我们展示了尽管我们尝试向文件`echo IMPOSSIBLE`，但失败了。我们使用了`permissionfile`的完整路径，以确保我们没有在 Packt 用户的`home`目录中创建文件。

# chmod

我们在这里对旧的 Packt 用户有点不公平，所以让我们给每个人都有写入文件的能力，而不仅仅是`vagrant`：

```
$ sudo chmod 646 permissionfile $ ls -l permissionfile
-rw-r--rw-. 1 vagrant root 26 Oct 28 12:48 permissionfile
```

现在，我们应该能够像任何用户一样写入文件，而不仅仅是 vagrant：

```
$ su - packt -c "echo POSSIBLE > /home/permissionfile"
Password: 
$ cat permissionfile 
POSSIBLE
```

# chattr

我开始觉得我们在这里太宽容了，所以让我们完全锁定文件，这样没有人（甚至是全能的`root`）都不能乱动它：

```
$ sudo chattr +i permissionfile
```

我们已经使文件不可变！

```
$ echo "RFCs are great if boring." > permissionfile
-bash: permissionfile: Permission denied
```

我们可以使用`lsattr`命令来查看这一点：

```
$ lsattr permissionfile
----i----------- permissionfile
```

甚至`root`也无法修改文件：

```
$ sudo echo "RFCs are great if boring." > permissionfile
-bash: permissionfile: Permission denied
```

`chattr`可以应用各种属性到文件上，但我敢打赌不可变选项是最常用的。

要删除属性，再次使用`chattr`：

```
$ sudo chattr -i permissionfile
```

# 它是如何工作的...

再次运行每个命令，让我们简要看一下我们做了什么。

# chown

首先，我们改变了文件的所有权：

```
$ sudo chown vagrant:root permissionfile
```

在这里，我们以最基本的方式使用`chown`，指定文件应属于哪个用户和组。这些值是用冒号分隔的，尽管如果你像我一样保守，偶尔会使用已弃用和不正确的句号(`.`)。

如果你只想保留组，你可以只指定一个用户：

```
$ sudo chown vagrant permissionfile
```

# chmod

接下来，我们更改了我们的文件，以便任何人都可以写入它：

```
$ sudo chmod 646 permissionfile
```

在这里，我们传递了一些八进制值给`permissionfile`，以便依次更改用户、组和其他人的权限。

我不会详细介绍这一点，但实际上，第一个数字表示用户三元组应该是什么值，然后是组的三元组，然后是其他人。

我们的用户得到了`6`的值，这意味着读/写；我们的组只能读取`4`，其他人可以读/写`6`。

这是因为每个值都有一个数字等价物，如下所示：

+   `x` = `1`

+   `w` = `2`

+   `r` = `4`

所以，`6`值是`4`+`2`，或者`r`/`w`，而`4`值只是`r`。

你可以设置`777`，这意味着对所有事物和所有人都有`r`/`w`/`x`权限，这经常是由不理解文件权限的人所做的。这不是一个好的做法，应该在故障排除之外加以阻止。如果我发现有人在生产环境中对文件运行了`chmod 777`，那么这个人将被取消访问权限，并且会在他们的日历中快速介绍权限。

# chattr

最后，我们改变了文件的一个属性，具体是使文件对`root`甚至是不可变的，然后我们再次移除了标志。

除了不可变之外，`chattr`主页中列出了许多其他标志，其中一些在特定情况下可能会有用：

+   `a`：文件只能被追加（对日志有用）

+   `c`：透明压缩和解压

+   `s`：导致文件的块在文件删除时被清零并写回磁盘

并非所有属性都受到所有文件系统的尊重；检查你的文件系统是否也支持它们（提示：`ext4`不支持很多）。

# 还有更多...

在我们结束本节之前，还有一两件事情需要注意。

# 在 chmod 中避免八进制表示法（如果你讨厌它）

在`chmod`世界中，你并不一定非要使用八进制格式；它确实给了你其他更容易阅读的选项：

```
$ sudo chmod uo=rw,g=r permissionfile
```

前面的命令会给用户和其他人读/写权限，给组读权限。

或者，你可以向权限添加一个值：

```
$ sudo chmod g+x permissionfile 
```

这将授予组额外的执行文件的能力：

```
$ ls -l permissionfile
-rw-r-xrw-. 1 vagrant root 26 Oct 28 13:03 permissionfile
```

# 分层权限

我们创建了一个目录，并在该目录中创建了一个文件，所以让我们快速了解一下理解目录权限。

首先，我们的`permissiondir`看起来是这样的：

```
$ ls -la permissiondir
total 0
drwxr-xr-x. 2 root root 45 Oct 28 12:37 .
drwxr-xr-x. 5 root root 77 Oct 28 12:37 ..
-rw-r--r--. 1 root root 0 Oct 28 12:37 permissionfile-in-permissiondir
```

尽管我们想要，但我们目前无法重命名这个文件，因为它太长了：

```
$ mv permissiondir/permissionfile-in-permissiondir permissiondir/permissionfile2
mv: cannot move 'permissiondir/permissionfile-in-permissiondir' to 'permissiondir/permissionfile2': Permission denied
```

所以，让我们为这个文件设置所有人的写权限：

```
$ sudo chmod 646 permissiondir/permissionfile-in-permissiondir
```

现在，让我们再试一次：

```
$ mv permissiondir/permissionfile-in-permissiondir permissiondir/permissionfile2
mv: cannot move 'permissiondir/permissionfile-in-permissiondir' to 'permissiondir/permissionfile2': Permission denied
```

嗯。

好的，这是因为实际上是目录权限阻止我们移动文件，而不是文件权限。我们必须修改包含文件的目录，因为权限不允许我们重命名（`mv`）文件：

```
$ sudo chmod 667 permissiondir/
```

现在我们应该能够移动文件了，因为我们的权限现在非常宽松：

```
$ mv permissiondir/permissionfile-in-permissiondir permissiondir/permissionfile2
```

成功！

# 另请参阅

在本节中我们没有涵盖的一件事是**访问控制列表**（**ACLs**），它可以用来进一步扩展文件的权限。

首先在我们的`permissionfile`中放入一个小命令来执行某些操作：

```
$ echo "printf 'Fire indeed hot'" > permissionfile
```

假设我们想要查看文件的整个访问控制列表；我们将使用`getfacl`：

```
$ getfacl permissionfile 
# file: permissionfile
# owner: vagrant
# group: root
user::rw-
group::r-x
other::rw-
```

在这里，我们可以看到所有者是`vagrant`，用户有`rw`。

但是，如果我们希望 Packt 能够执行该文件，而不影响其他权限呢？目前，Packt 不能，因为它不在`root`组中。

一个潜在的解决方案是`setfacl`：

```
$ setfacl -m u:packt:rwx permissionfile
```

现在我们可以看到`ls`中有一个小`+`号，显示我们的文件有扩展的访问控制：

```
$ ls -l permissionfile
-rw-r-xrw-+ 1 vagrant root 26 Oct 28 13:03 permissionfile
```

而且，我们可以再次使用`getfacl`来查看这些：

```
$ getfacl permissionfile 
# file: permissionfile
# owner: vagrant
# group: root
user::rw-
user:packt:rwx
group::r-x
mask::rwx
other::rw-
```

这意味着我们的`vagrant`用户无法执行该文件：

```
$ ./permissionfile
-bash: ./permissionfile: Permission denied
```

但是，我们的 Packt 用户可以：

```
$ su - packt -c "/home/permissionfile" 
Password: 
Fire indeed hot
```

# 技术要求

在本节中，我们将跳转到我们的 CentOS 和 Ubuntu 虚拟机上，以突出用户和组处理方法上的一些重要差异。

# 用户和组

我们已经涵盖了文件权限方面的用户和组，但是简要地回顾一下我们对用户和组的了解是个好主意。

在本节中，我们将深入探讨用户和组的简要介绍，确定进程正在以哪个用户运行，它如何更改为该用户，并通过使用`/etc/passwd`和类似命令来查找系统中存在哪些用户。

# 准备工作

使用 Vagrant 连接到你的 Ubuntu 和 CentOS 虚拟机，在不同的窗口中或者依次进行：

```
$ vagrant ssh centos7 $ vagrant ssh ubuntu1804
```

# 如何做...

在几个简短的部分中，我们将看一下用户和组的不同元素。

# whoami

如果你需要知道你是谁，通过深层反思和内心沉思来问问自己。

如果你需要知道有哪些用户登录到服务器上（或者以某个用户身份运行命令），这将会更容易：

```
$ whoami
vagrant $ sudo whoami
root
```

# 系统上的用户

要显示系统上有哪些用户，请查看`/etc/passwd`。

在 CentOS 上，它看起来会像这样：

```
$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
nfsnobody:x:65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
chrony:x:998:996::/var/lib/chrony:/sbin/nologin
vagrant:x:1000:1000:vagrant:/home/vagrant:/bin/bash
packt:x:1001:1001::/home/packt:/bin/bash
```

而在 Ubuntu 上，它看起来会像这样：

```
$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
vagrant:x:1000:1000:,,,:/home/vagrant:/bin/bash
ubuntu:x:1001:1001:Ubuntu:/home/ubuntu:/bin/bash
```

大多数这些用户你不会自己创建；它们大部分是系统用户，或者与你安装的软件捆绑在一起。

# 系统上的组

组的发现方式与用户类似，同样，你不会创建大部分组。

对于 CentOS，请注意以下内容：

```
$ cat /etc/group
root:x:0:
bin:x:1:
daemon:x:2:
sys:x:3:
adm:x:4:
tty:x:5:
disk:x:6:
lp:x:7:
mem:x:8:
kmem:x:9:
wheel:x:10:
<SNIP>
postfix:x:89:
chrony:x:996:
screen:x:84:
vagrant:x:1000:vagrant
packt:x:1001:
```

对于 Ubuntu，请注意以下内容：

```
$ cat /etc/group
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,ubuntu
tty:x:5:
<SNIP>
landscape:x:112:
admin:x:113:
netdev:x:114:ubuntu
vboxsf:x:115:
vagrant:x:1000:
ubuntu:x:1001:
```

我已经加粗了这个 Ubuntu 和 CentOS 系统之间的第一个重大区别，即`wheel`和`admin`组。`wheel`在我们的 Ubuntu 系统上不存在，因为它已被`admin`组取代；这意味着 Ubuntu 上的`visudo`文件引用了`admin`组的成员，而不是`wheel`。记住这一点。

# 使用用户的守护进程

在我们的 Ubuntu 系统上，`syslogd`守护进程是使用`syslog`用户运行的。

我们可以通过定位我们的`rsyslogd`进程并检查最左边列中的用户来确认这一点：

```
$ pidof rsyslogd
917
$ ps -up 917
USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
syslog 917 0.0 0.4 263036 4416 ? Ssl 10:41 0:00 /usr/sbin/rsyslogd -n
```

我们可以通过查看`/etc/rsyslog.conf`配置文件来找到这个用户是如何被发现的：

```
$ grep PrivDrop /etc/rsyslog.conf
$PrivDropToUser syslog
$PrivDropToGroup syslog
```

如果你想快速排除以`root`身份运行的进程，你可以使用一个快速的一行命令，比如下面的（尽管这并不完美）。

这是我们的 CentOS 虚拟机上的情况：

```
$ ps aux | grep -v root
USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
dbus 558 0.0 0.5 66428 2568 ? Ssl 12:34 0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation
rpc 559 0.0 0.2 69220 1060 ? Ss 12:34 0:00 /sbin/rpcbind -w
polkitd 568 0.0 1.6 538436 8020 ? Ssl 12:34 0:00 /usr/lib/polkit-1/polkitd --no-debug
chrony 581 0.0 0.3 117752 1828 ? S 12:34 0:00 /usr/sbin/chronyd
postfix 1088 0.0 0.8 89792 4080 ? S 12:35 0:00 qmgr -l -t unix -u
vagrant 3369 0.0 0.5 154904 2688 ? S 14:11 0:00 sshd: vagrant@pts/0
vagrant 3370 0.0 0.5 15776 2660 pts/0 Ss 14:11 0:00 -bash
postfix 3399 0.0 0.8 89724 4052 ? S 14:15 0:00 pickup -l -t unix -u
vagrant 3404 0.0 0.3 55140 1872 pts/0 R+ 14:32 0:00 ps aux
```

# 它是如何工作的...

通常，不同的用户和组将具有特定的用途，有意地分隔开来，以便它们在自己的权利范围内不会太强大。如果你有一个多租户系统（这在今天非常罕见），有多个人登录进行日常工作，你希望确保这个人不能通过做一些愚蠢的事情，比如覆盖盒子上的日志，让其他人的生活变得更加困难。

你可以通过将所有人类用户放在一个组中来解决这个问题，然后允许他们拥有自己的有限访问权限的用户，然后给予该组访问共享目录和他们可能需要使用的应用程序的权限。

进程有选择放弃它们的特权的选项，尽管并非所有进程都会默认这样做，如果你想再走这一步，通常需要大量工作来设置。在这里，我们看到`syslog`启动（作为`root`），然后立即降低自己的特权级别到`syslog`用户和组的级别。

`rsyslogd`必须以`root`身份启动的原因是因为它绑定到低于`1024`的端口，这些端口是只有`root`程序可以访问的受限端口。

一些发行版和操作系统对此的处理方式比其他的更加严格，但就像所有与安全相关的事情一样，这就像是安全的洋葱的另一层。

# 还有更多...

看看你的 Ubuntu 虚拟机上的这个用户：

```
$ grep apt /etc/passwd
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
```

它有一个下划线，在整个`/etc/passwd`文件中是唯一一个有下划线的；这可能是为什么呢？

一个潜在的原因是它是一个系统账户，应用程序维护者或开发者决定用下划线字符表示这一点，就像其他操作系统一样。

# AppArmor 和修改

在本节中，我们将在 Ubuntu 上使用 AppArmor，并确定它对我们的系统有什么影响。

AppArmor 默认安装在 Ubuntu 上。它最初是由 SUSE 开发的，但 Canonical 似乎已经坚定地将他们的旗帜插在了 AppArmor 星球上，在 Ubuntu 7.04 中引入了它，并在 7.10（2007 年）中默认启用了它。

像 SELinux 一样，AppArmor 是将强制访问控制（MAC）引入 Linux 的一种方式；它自 2.6.36 内核以来就已经包含在内。

# 准备工作

在本节中，我们将使用我们的 Ubuntu 虚拟机。

SSH 到你的 Ubuntu 虚拟机：

```
$ vagrant ssh ubuntu1804
```

# 如何做...

首先，让我们确保`apparmor`正在运行，使用我们的老朋友`systemctl`：

```
$ systemctl status apparmor
● apparmor.service - AppArmor initialization
 Loaded: loaded (/lib/systemd/system/apparmor.service; enabled; vendor preset: enabled)
 Active: active (exited) since Sun 2018-10-28 10:41:23 UTC; 4h 21min ago
 Docs: man:apparmor(7)
 http://wiki.apparmor.net/
 Process: 426 ExecStart=/etc/init.d/apparmor start (code=exited, status=0/SUCCESS)
 Main PID: 426 (code=exited, status=0/SUCCESS)

Warning: Journal has been rotated since unit was started. Log output is incomplete or unavailable.
```

要查看加载了哪些配置文件以及它们运行在什么模式下，使用`apparmor_status`：

```
$ sudo apparmor_status 
apparmor module is loaded.
15 profiles are loaded.
15 profiles are in enforce mode.
 /sbin/dhclient
 /usr/bin/lxc-start
 /usr/bin/man
 /usr/lib/NetworkManager/nm-dhcp-client.action
 /usr/lib/NetworkManager/nm-dhcp-helper
 /usr/lib/connman/scripts/dhclient-script
 /usr/lib/snapd/snap-confine
 /usr/lib/snapd/snap-confine//mount-namespace-capture-helper
 /usr/sbin/tcpdump
 lxc-container-default
 lxc-container-default-cgns
 lxc-container-default-with-mounting
 lxc-container-default-with-nesting
 man_filter
 man_groff
0 profiles are in complain mode.
0 processes have profiles defined.
0 processes are in enforce mode.
0 processes are in complain mode.
0 processes are unconfined but have a profile defined.
```

要了解 AppArmor 如何限制应用程序，让我们对`tcpdump`配置文件进行修改并重新启动 AppArmor：

```
$ sudo sed -i 's/capability net_raw,/#capability net_raw,/g' /etc/apparmor.d/usr.sbin.tcpdump
$ sudo systemctl restart apparmor
```

在这里我们做的是删除`tcpdump`捕获的能力，使其变得相当无用：

```
$ sudo tcpdump -i enp0s3
tcpdump: enp0s3: You don't have permission to capture on that device
(socket: Operation not permitted)
```

如果我们查看内核日志，我们可以看到我们试图运行`tcpdump`时的拒绝：

```
$ sudo journalctl -k --since 15:34 --no-pager
-- Logs begin at Sun 2018-10-28 10:41:21 UTC, end at Sun 2018-10-28 15:39:29 UTC. --
Oct 28 15:34:34 ubuntu-bionic kernel: kauditd_printk_skb: 6 callbacks suppressed
Oct 28 15:34:34 ubuntu-bionic kernel: audit: type=1400 audit(1540740874.554:97): apparmor="DENIED" operation="capable" profile="/usr/sbin/tcpdump" pid=3365 comm="tcpdump" capability=13 capname="net_raw"
```

请注意我们之前用`sed`删除的`net_raw`能力名称。

# 它是如何工作的...

AppArmor 的配置文件是使用`apparmor_parser`程序编写并加载到内核中的。大多数情况下，这些配置文件将位于`/etc/apparmor.d/`中；尽管如果一个程序没有配置文件，AppArmor 也不会阻止它运行。

当实际的 systemd 单元启动时，会运行一个`init.d`脚本（位于`/etc/init.d/apparmor`），该脚本会实际调用`apparmor_parser`。

当配置文件以强制执行模式运行时，就像前面的十五个配置文件一样，它们必须遵守策略定义，否则它们将无法在策略要求之外行事，并且违规行为将被记录。如果配置文件处于投诉模式，则策略不会被执行，但违规行为将被记录以供以后审查。

配置文件通常以用点替换可执行文件的斜杠位置来命名：

```
/sbin/dhclient -> sbin.dhclient
/usr/sbin/tcpdump -> usr.sbin.tcpdump
```

如果我们看一下`tcpdump`配置文件的前几行，我们就可以开始看到配置文件是如何构建的：

```
$ cat /etc/apparmor.d/usr.sbin.tcpdump 
# vim:syntax=apparmor
#include <tunables/global>

/usr/sbin/tcpdump {
 #include <abstractions/base>
 #include <abstractions/nameservice>
 #include <abstractions/user-tmp>

 #capability net_raw,
 capability setuid,
 capability setgid,
 capability dac_override,
 network raw,
 network packet,

 # for -D
 @{PROC}/bus/usb/ r,
 @{PROC}/bus/usb/** r,
<SNIP>
```

我们可以首先看到指定了二进制文件的名称，然后是一些包括的内容（这些规则也可以在其他程序中使用）。

接下来，我们有`capability`，包括我们注释掉的那个。有一系列的 capabilities，可以在`man (7) capabilities`页面上查看，其中列出了像`CAP_NET_RAW`和`CAP_SETGID`这样的名称，但这里它们都是小写。

当我们删除了这个`capability`时，`tcpdump`失去了使用 RAW 和 PACKET sockets 的能力，以及绑定到任何地址进行透明代理的能力。

在更下面，我们可以看到文件的作者如何使用注释和`tcpdump`的标志来描述他们允许的权限。在下面的例子中，他们特别允许使用`gzip`和`bzip2`，以便`-z`选项起作用：

```
 # for -z
 /{usr/,}bin/gzip ixr,
 /{usr/,}bin/bzip2 ixr,
```

可以使用令人惊讶的详细的`apparmor.d`手册页来比较和理解语法。

# 还有更多...

虽然 AppArmor 很好，它确实做到了它所宣传的，但也有一些注意事项：

+   它依赖于开发人员编写和提供配置文件（或其他人贡献时间）

+   在默认安装中包含配置文件之前，配置文件必须是无懈可击的，这可能是十年后仍然如此之少的原因

+   它相当不为人知，大多数人甚至在默认情况下都不会去理会它

它也会偏离路径，而不是 inode，这意味着你可以做一些事情，比如创建一个硬链接来绕过限制：

```
$ sudo ln /usr/sbin/tcpdump /usr/sbin/tcpdump-clone
```

诚然，如果你在一个盒子上并且有`sudo`，那么在那一点上游戏基本上就结束了：

```
$ sudo tcpdump -i enp0s3
tcpdump: enp0s3: You don't have permission to capture on that device
(socket: Operation not permitted)
$ sudo tcpdump-clone -i enp0s3
tcpdump-clone: verbose output suppressed, use -v or -vv for full protocol decode
listening on enp0s3, link-type EN10MB (Ethernet), capture size 262144 bytes
15:52:52.803301 IP ubuntu-bionic.ssh > _gateway.37936: Flags [P.], seq 410213354:410213518, ack 1991801602, win 36720, length 164
<SNIP>
```

你可能会问为什么你的系统需要这样的东西，如果它很容易调整和绕过，但答案相对简单。

如果你在公共互联网上有一个 web 服务器，很有可能它会在某个时候受到攻击，当这种情况发生时，你可能已经完全更新，并受到了零日漏洞的攻击（尽管可能性很小）。然后你的 web 服务器可能会被攻破，攻击你的个人可能会利用它来尝试建立一个运行在不同端口上的不同进程，甚至利用它开始读取它不应该读取的文件。

强制访问控制在很大程度上确保了这种情况不会发生，对于攻击的另一方来说，生活变得更加沮丧。他们可能攻击了你的 web 服务器，但那就是他们所能做的。

# SELinux 和修改

像 AppArmor 一样，**安全增强型 Linux**（**SELinux**）是一种在 Linux 中引入强制访问控制的方式，只是它有一些关键的不同：

+   它比 AppArmor 更广泛使用和令人讨厌

+   它主要用于基于 Red Hat 的发行版

如果你在企业世界中，或者正在考虑进入那里，SELinux 是一个很好的工具，可以添加到你的工具箱中。

你可能还记得我们之前已经提到过 SELinux，做了一些小的更改，允许诸如 SSH 在不同端口上运行；在这里，我们进一步探讨了它。

# 准备工作

在本节中，我们将使用我们的 CentOS 虚拟机。

通过 SSH 连接到你的 CentOS 虚拟机，转发`8080`：

```
$ vagrant ssh centos7 -- -L 127.0.0.1:5858:127.0.0.1:5858
```

确保为 NGINX 和一些实用程序安装了，并且为这个示例启动了 NGINX：

```
$ sudo yum install epel-release -y
$ sudo yum install policycoreutils-python setroubleshoot -y
$ sudo yum install nginx -y
$ sudo systemctl enable --now nginx
```

# 如何做...

我们要改变 NGINX 默认监听的端口，以展示 SELinux 有多么让人头疼。

首先，通过使用`curl`并打印返回码来检查 NGINX 是否在端口`80`（默认端口）上运行：

```
$ curl -I localhost:80 
HTTP/1.1 200 OK
Server: nginx/1.12.2
Date: Mon, 29 Oct 2018 17:36:35 GMT
Content-Type: text/html
Content-Length: 3700
Last-Modified: Tue, 06 Mar 2018 09:26:21 GMT
Connection: keep-alive
ETag: "5a9e5ebd-e74"
Accept-Ranges: bytes
```

在这里使用`-I`意味着我们不会拉入一屏幕的代码，而是只获取相关信息，比如返回码（`200`表示 OK）。

很好，所以一切都正常工作，SELinux 没有阻碍。

如果我们想让 NGINX 监听不同的端口呢？比如我们转发的那个？让我们试试：

```
$ sudo sed -i 's/80 default_server;/5858 default_server;/g' /etc/nginx/nginx.conf
$ sudo systemctl restart nginx
Job for nginx.service failed because the control process exited with error code. See "systemctl status nginx.service" and "journalctl -xe" for details.
```

再次运行我们的`curl`命令，使用新端口应该会报错（显然，因为服务启动失败）：

```
$ curl -I localhost:5858
curl: (7) Failed connect to localhost:5858; Connection refused
```

奇怪...但也不是真的。

这是因为 NGINX 只允许在某些端口上运行，`80`是其中一个，`8080`是另一个，等等。`5858`是奇怪和怪异的；为什么一个 Web 服务器要在上面运行？

因此，我们必须更新 SELinux 以允许 NGINX 在新端口上运行：

```
$ sudo semanage port --add --type http_port_t --proto tcp 5858
ValueError: Port tcp/5858 already defined
```

哦该死，看起来`5858`已经为其他东西定义了（在这种情况下是 Node.js - 诅咒你 Node.js！）。

幸运的是，这并不是世界末日，我们只需要修改端口而不是添加一个：

```
$ sudo semanage port --modify --type http_port_t --proto tcp 5858
```

现在，我们可以重新启动 NGINX，应该可以正常工作：

```
$ sudo systemctl restart nginx
$ curl -I localhost:5858
HTTP/1.1 200 OK
Server: nginx/1.12.2
Date: Mon, 29 Oct 2018 18:17:37 GMT
Content-Type: text/html
Content-Length: 3700
Last-Modified: Tue, 06 Mar 2018 09:26:21 GMT
Connection: keep-alive
ETag: "5a9e5ebd-e74"
Accept-Ranges: bytes
```

你也可以在浏览器中访问它：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/3b5564f2-b3e8-47cd-a5a2-d9bb5e33f22a.png)

是的，它说的是 Fedora，而且是错误的。

所以，这是第一步，但现在我们决定，不使用默认的 NGINX 欢迎页面，而是要在`/srv/webserver/arbitrary-location/`中显示我们的文件。

首先，让我们创建这个目录结构，并在其中放一个简单的文件来提供服务：

```
$ sudo mkdir -p /srv/webserver/arbitrary-location/
$ echo "HELLO WORLD" | sudo tee /srv/webserver/arbitrary-location/index.html
HELLO WORLD
```

接下来，让我们检查一下我们在现有页面位置上的权限，并确保它们是一样的：

```
$ ls -lha /usr/share/nginx/html/
total 20K
drwxr-xr-x. 2 root root 99 Oct 29 17:36 .
drwxr-xr-x. 4 root root 33 Oct 29 17:36 ..
-rw-r--r--. 1 root root 3.6K Mar 6 2018 404.html
-rw-r--r--. 1 root root 3.7K Mar 6 2018 50x.html
-rw-r--r--. 1 root root 3.7K Mar 6 2018 index.html
-rw-r--r--. 1 root root 368 Mar 6 2018 nginx-logo.png
-rw-r--r--. 1 root root 2.8K Mar 6 2018 poweredby.png
```

我们将确保我们的权限是一样的：

```
$ ls -lha /srv/webserver/arbitrary-location/
total 4.0K
drwxr-xr-x. 2 root root 24 Oct 29 18:43 .
drwxr-xr-x. 4 root root 62 Oct 29 18:40 ..
-rw-r--r--. 1 root root 12 Oct 29 18:43 index.html
```

接下来，我们将更新我们的 NGINX 配置，将日志记录到这个新位置：

```
$ sudo sed -i 's/\/usr\/share\/nginx\/html/\/srv\/webserver\/arbitrary-location/g' /etc/nginx/nginx.conf
```

现在，我们重新启动我们的服务：

```
$ sudo systemctl restart nginx
```

让我们再试一下我们的`curl`，这次省略`-I`，这样我们就可以得到我们的页面：

```
$ curl localhost:5858
<html>
<head><title>403 Forbidden</title></head>
<body bgcolor="white">
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx/1.12.2</center>
</body>
</html>
```

哎呀...看起来不对。

毫不奇怪，SELinux 是罪魁祸首，但修复它是一组相当简单的命令，我们可以用来纠正文件的`fcontext`：

```
$ sudo semanage fcontext --add --type httpd_sys_content_t /srv/webserver/arbitrary-location/index.html
$ sudo restorecon /srv/webserver/arbitrary-location/index.html
```

现在再试一下我们的`curl`应该会给我们返回消息：

```
$ curl localhost:5858
HELLO WORLD
```

我们也可以在浏览器中查看它：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/5778bc90-f8c0-4a88-a7d6-bb5d0719bda6.png)

如果这不值得泰特现代美术馆，我不知道还有什么值得。

# 它是如何工作的...

当我们更改端口并重新启动服务时，我们遇到了一些错误：

```
$ sudo journalctl -e -u nginx --no-pager | tail -n 8
Oct 29 17:43:17 localhost.localdomain systemd[1]: Starting The nginx HTTP and reverse proxy server...
Oct 29 17:43:17 localhost.localdomain nginx[4334]: nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
Oct 29 17:43:17 localhost.localdomain nginx[4334]: nginx: [emerg] bind() to 0.0.0.0:5858 failed (13: Permission denied)
Oct 29 17:43:17 localhost.localdomain nginx[4334]: nginx: configuration file /etc/nginx/nginx.conf test failed
Oct 29 17:43:17 localhost.localdomain systemd[1]: nginx.service: control process exited, code=exited status=1
Oct 29 17:43:17 localhost.localdomain systemd[1]: Failed to start The nginx HTTP and reverse proxy server.
Oct 29 17:43:17 localhost.localdomain systemd[1]: Unit nginx.service entered failed state.
Oct 29 17:43:17 localhost.localdomain systemd[1]: nginx.service failed.
```

注意`5858`端口上的具体`Permission denied`条目。

你可以使用我们之前作为实用程序安装的一部分安装的`semanage`命令来查询 SELinux 端口类型及其编号：

```
$ sudo semanage port -l | grep http
http_cache_port_t tcp 8080, 8118, 8123, 10001-10010
http_cache_port_t udp 3130
http_port_t tcp 80, 81, 443, 488, 8008, 8009, 8443, 9000
pegasus_http_port_t tcp 5988
pegasus_https_port_t tcp 5989
```

在这里，我们可以看到，虽然`80`和其他端口被允许作为 HTTP 端口，但`5858`最初并不在其中。

在我们添加了刚刚显示的额外端口之后，这个命令看起来有些不同：

```
$ sudo semanage port -l | grep http
http_cache_port_t tcp 8080, 8118, 8123, 10001-10010
http_cache_port_t udp 3130
http_port_t tcp 5858, 80, 81, 443, 488, 8008, 8009, 8443, 9000
pegasus_http_port_t tcp 5988
pegasus_https_port_t tcp 5989
```

因此，SELinux 现在允许使用这个端口。

就文件而言，我们可以使用`ls -Z`选项来检查 NGINX 需要文件具有的`fcontext`。

如图所示，我们对默认文件运行了它：

```
$ ls -lhaZ /usr/share/nginx/html/
drwxr-xr-x. root root system_u:object_r:httpd_sys_content_t:s0 .
drwxr-xr-x. root root system_u:object_r:usr_t:s0 ..
-rw-r--r--. root root system_u:object_r:httpd_sys_content_t:s0 404.html
-rw-r--r--. root root system_u:object_r:httpd_sys_content_t:s0 50x.html
-rw-r--r--. root root system_u:object_r:httpd_sys_content_t:s0 index.html
-rw-r--r--. root root system_u:object_r:httpd_sys_content_t:s0 nginx-logo.png
-rw-r--r--. root root system_u:object_r:httpd_sys_content_t:s0 poweredby.png
```

这是确定你需要给新文件的上下文的好方法。

当我们应用我们的新策略规则并将策略值恢复到系统时，我们的文件突然可以被 NGINX 使用了。

# 还有更多...

SELinux 实际上并不像每个人想象的那样糟糕，它已经走过了很长的路，不再像以前那样默默地失败。一般来说，当您需要为系统和程序找到正确的配置时，现在有大量的工具和调试程序可供选择，尽管它们可能会填满整整一本书。

如果您从本节中获得了任何信息，请了解禁用 SELinux 不是答案（即将其设置为宽松模式），并且在开发环境之外，您所做的一切只会让您的未来变得不太安全。

`semanage`并不是管理 SELinux 策略的唯一方法，但它非常易于使用，是一个很好的介绍自己进入策略文件的精彩世界的方式。

# 另请参阅

一般来说，桌面系统不使用 SELinux，除了 Fedora 之外，因此，如果您真的想开始尝试它，可以启动安装了 Fedora 的虚拟机，并查看诸如`audit2allow`和`chcon`之类的工具。

# 检查 SELinux 是否正在运行，以及保持其运行的重要性

在本节中，我们将看看如何检查 SELinux 在我们的系统上是否启用并运行，并且我们将使用 SELinux 在运行过程中写入的日志。同时，我们将使用`setroubleshoot`来帮助我们确定我们尝试做的事情可能出现的问题。

再次强调，有一段时间，当 SELinux 开始成为一个事物时，人们立即将其摒弃。大多数在线指南都会以不朽的话语“务必检查 SELinux 是否已禁用”开始。幸运的是，这种心态现在大多已经消失了，人们已经接受 SELinux 作为他们唯一真正的上帝。

当您遇到由 SELinux 引起的问题时，很容易就会有冲动直接禁用它。如果问题出现在生产服务器上，并且您面临着修复的压力，这种冲动就会变得更加强烈。不要采用禁用 SELinux 的简单解决方案，因为这样做只会在将来给您带来麻烦。

也就是说，我现在将讨论如何禁用 SELinux（以帮助故障排除！）。

# 准备工作

在本节中，我们将使用我们的 CentOS 虚拟机。

SSH 到您的 CentOS 虚拟机：

```
$ vagrant ssh centos7
```

如果在上一节中未安装，请确保已安装 NGINX 和各种工具：

```
$ sudo yum install epel-release -y
$ sudo yum install policycoreutils-python setroubleshoot -y
$ sudo yum install nginx -y
$ sudo systemctl enable --now nginx
```

# 如何做…

首先，您可以使用`sestatus`轻松检查 SELinux 的当前状态：

```
$ sestatus
SELinux status: enabled
SELinuxfs mount: /sys/fs/selinux
SELinux root directory: /etc/selinux
Loaded policy name: targeted
Current mode: enforcing
Mode from config file: enforcing
Policy MLS status: enabled
Policy deny_unknown status: allowed
Max kernel policy version: 31
```

在这里，我们看到它是“启用”的，并且它正在运行的模式是“强制”，这意味着策略的违规行为将被拒绝。

要临时禁用 SElinux（即在运行时），有一个相对简单的命令：

```
$ sudo setenforce Permissive
```

但这将在启动时再次更改。

现在，让我们将其保持启用状态：

```
$ sudo setenforce Enforcing
```

接下来，我们将再次更改我们希望 NGINX 使用的端口，重新启动 NGINX，观察它失败，并看看我们如何确定问题所在。

更改端口可以这样完成：

```
$ sudo sed -i 's/5858 default_server;/5757 default_server;/g' /etc/nginx/nginx.conf 
```

如果您没有在上一节更改端口（您是从头开始的），那么您将想要将此处显示的`5858`替换为`80`。

使用`systemctl`最容易重新启动 NGINX：

```
$ sudo systemctl restart nginx
Job for nginx.service failed because the control process exited with error code. See "systemctl status nginx.service" and "journalctl -xe" for details.
```

现在我们可以确定为什么它失败了：

```
$ sudo sealert -a /var/log/audit/audit.log
```

这可能会给您很多结果，特别是如果您已经运行该系统一段时间，但在最后附近应该会有一个类似以下内容的报告：

```
--------------------------------------------------------------------------------

SELinux is preventing /usr/sbin/nginx from name_bind access on the tcp_socket port 5757.

***** Plugin bind_ports (92.2 confidence) suggests ************************

If you want to allow /usr/sbin/nginx to bind to network port 5757
Then you need to modify the port type.
Do
# semanage port -a -t PORT_TYPE -p tcp 5757
 where PORT_TYPE is one of the following: http_cache_port_t, http_port_t, jboss_management_port_t, jboss_messaging_port_t, ntop_port_t, puppet_port_t.

***** Plugin catchall_boolean (7.83 confidence) suggests ******************

If you want to allow nis to enabled
Then you must tell SELinux about this by enabling the 'nis_enabled' boolean.

Do
setsebool -P nis_enabled 1

***** Plugin catchall (1.41 confidence) suggests **************************

If you believe that nginx should be allowed name_bind access on the port 5757 tcp_socket by default.
Then you should report this as a bug.
You can generate a local policy module to allow this access.
Do
allow this access for now by executing:
# ausearch -c 'nginx' --raw | audit2allow -M my-nginx
# semodule -i my-nginx.pp

Additional Information:
Source Context system_u:system_r:httpd_t:s0
Target Context system_u:object_r:unreserved_port_t:s0
Target Objects port 5757 [ tcp_socket ]
Source nginx
Source Path /usr/sbin/nginx
Port 5757
Host <Unknown>
Source RPM Packages nginx-1.12.2-2.el7.x86_64
Target RPM Packages 
Policy RPM selinux-policy-3.13.1-192.el7_5.3.noarch
Selinux Enabled True
Policy Type targeted
Enforcing Mode Enforcing
Host Name localhost.localdomain
Platform Linux localhost.localdomain
                              3.10.0-862.2.3.el7.x86_64 #1 SMP Wed May 9
                              18:05:47 UTC 2018 x86_64 x86_64
Alert Count 1
First Seen 2018-10-30 17:27:06 UTC
Last Seen 2018-10-30 17:27:06 UTC
Local ID 65a65b11-892c-4795-8a1f-163822aa3a0f

Raw Audit Messages
type=AVC msg=audit(1540920426.452:335): avc: denied { name_bind } for pid=4551 comm="nginx" src=5757 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:unreserved_port_t:s0 tclass=tcp_socket

type=SYSCALL msg=audit(1540920426.452:335): arch=x86_64 syscall=bind success=no exit=EACCES a0=6 a1=5580c9397668 a2=10 a3=7fff97b00870 items=0 ppid=1 pid=4551 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm=nginx exe=/usr/sbin/nginx subj=system_u:system_r:httpd_t:s0 key=(null)

Hash: nginx,httpd_t,unreserved_port_t,tcp_socket,name_bind
```

在顶部加粗显示的是`sealert`认为问题的一行摘要；在这种情况下，它是正确的。

然后，它会给出一个`semanage`命令，类似于我们之前使用的命令，用于修改策略。

它还为您提供了两个命令`ausearch`和`semodule`，您可以使用这两个命令生成一个本地策略，该策略有效地与基本策略一起使用，但可以与诸如 Ansible 安装脚本之类的东西一起使用。

例如，您有一个 Ansible 角色，该角色在自定义端口上安装 NGINX，但这没关系，因为您可以将基于文本的策略与配置捆绑在一起，并在 Ansible 配置运行中加载它。

让我们运行这些命令：

```
$ sudo ausearch -c 'nginx' --raw | audit2allow -M my-nginx
******************** IMPORTANT ***********************
To make this policy package active, execute:

semodule -i my-nginx.pp$ sudo semodule -i my-nginx.pp
```

现在，尝试重新启动 NGINX，并`curl`我们的新端口：

```
$ sudo systemctl restart nginx
$ curl -I localhost:5757
HTTP/1.1 200 OK
Server: nginx/1.12.2
Date: Tue, 30 Oct 2018 17:41:42 GMT
Content-Type: text/html
Content-Length: 12
Last-Modified: Mon, 29 Oct 2018 18:43:12 GMT
Connection: keep-alive
ETag: "5bd754c0-c"
Accept-Ranges: bytes
```

哇！

# 它是如何工作的...

SELinux 的配置（就其是否正在运行以及处于什么模式）设置在`/etc/selinux/config`文件中：

```
$ cat /etc/selinux/config 

# This file controls the state of SELinux on the system.
# SELINUX= can take one of these three values:
# enforcing - SELinux security policy is enforced.
# permissive - SELinux prints warnings instead of enforcing.
# disabled - No SELinux policy is loaded.
SELINUX=enforcing
# SELINUXTYPE= can take one of three two values:
# targeted - Targeted processes are protected,
# minimum - Modification of targeted policy. Only selected processes are protected. 
# mls - Multi Level Security protection.
SELINUXTYPE=targeted
```

如果您想永久禁用 SELinux，这是您需要更改的文件，将`enforcing`翻转为`permissive`甚至`disabled`。

在加载的自定义策略方面，我们正在研究一些更复杂的东西。

这个命令生成了两个文件：

```
$ sudo ausearch -c 'nginx' --raw | audit2allow -M my-nginx
$ ls
my-nginx.pp my-nginx.te
```

`.pp`文件是一个已编译的策略，准备加载，而`.te`文件是一个可供您确认的人类可读文件。

当我们使用`semodule -i`命令加载策略时，我们激活了它。

您可以再次使用`semodule`查看您的活动策略：

```
$ sudo semodule -l | grep my-nginx
my-nginx 1.0
```

# 还有更多...

`audit2allow`尽力而为，但它并不总是完全正确地获取策略文件（或者它们具有太大的权限，从而使 SELinux 无效）。除非您真的非常有信心，否则请让某人在加载之前对您的配置进行理智检查。

# 另请参阅

我在一开始就说过，确保 SELinux 正在运行并确保您保持其运行是非常重要的。

禁用它并保持禁用所产生的问题应该是显而易见的，但为了给您一个形象的描述，请注意以下内容。

这是星期五的最后一天，就在圣诞节假期之前，大部分员工已经离开，之前他们做了一些最后的检查，以确保您的电子商务网站在圣诞节和节礼日期间保持运行。

您正要下班时，注意到网站出现了问题，导致客户认为他们可以在最新的任天堂游戏机上获得三百点，而您不能容忍任何这种胡闹。

您进去手动更改，添加额外的配置文件以正确加载价格，并重新启动服务。

服务没有重新启动。

恐慌开始蔓延。

你的胃一下子就空了。

远处有人发出了一声吼叫。

以速度和灵巧，您禁用了 SELinux，重新启动了服务，并使一切恢复在线。网站已经上线，控制台现在显示正确的价格。

呼——您回家吃了几个肉馅饼来庆祝。

然后，一整年都没有人注意到 SELinux 被禁用，直到下一次圣诞节推送软件的时候，使用您的 CI/CD 基础设施，该基础设施还确保 SELinux 已启用。当这种情况发生时，网站就会崩溃。

每个人都陷入恐慌，没有人确定发生了什么，但您并不在乎，因为您早就因为公司让您工作愚蠢的时间而辞职，并且决定搬到日本开始一个水果种植业务。

一切都着火了。

看到你做了什么吗？

保持 SELinux 启用！

# 重置 SELinux 权限

在本节中，我们将讨论重置 SELinux 权限，并简要介绍如何在您忘记密码的情况下重置`root`密码，同时考虑到会阻碍您的 SELinux。

# 准备好了

连接到您的 CentOS VM：

```
$ vagrant ssh centos7
```

# 如何做...

首先，重要的是要理解，对于 SELinux，我们实际上有一个运行中的配置和一个保存的配置。当您运行系统时，重要的是您对 SELinux 所做的任何更改都要保存下来，以便在 SELinux 重新标记的情况下加载。

要看到这一点，让我们复制一些上下文。

首先，看一下我们的`.bashrc`文件的上下文（因为它立即可用）：

```
$ ls -lhaZ .bashrc 
-rw-r--r--. vagrant vagrant unconfined_u:object_r:user_home_t:s0 .bashrc
```

这有四个部分：我们有一个用户（`unconfined_u`），一个角色（`object_r`），一个类型（`user_home_t`），以及资源的敏感性（`s0.`）类型对我们来说很重要。

假设我们想要更改类型；我们可以通过从另一个文件中复制类型来实时更改（在这种情况下，是`authorized_keys`文件，看起来像这样）：

```
$ ls -lhaZ .ssh/authorized_keys 
-rw-------. vagrant vagrant unconfined_u:object_r:ssh_home_t:s0 .ssh/authorized_keys $ chcon --reference=.ssh/authorized_keys .bashrc
```

现在请注意，当我们查看我们的`.bashrc`文件时，SELinux 上下文已经改变了：

```
$ ls -lhaZ .bashrc 
-rw-r--r--. vagrant vagrant unconfined_u:object_r:ssh_home_t:s0 .bashrc
```

但`chcon`不是永久的，我们实际上改变了 SELinux 的运行配置，这意味着我们可以用一个简单的命令来重置它：

```
$ restorecon .bashrc 
$ ls -lhaZ .bashrc 
-rw-r--r--. vagrant vagrant unconfined_u:object_r:user_home_t:s0 .bashrc
```

你可能还记得之前，我们是用`semanage`来向文件添加新的上下文，然后用`restorecon`来应用该上下文。

解决临时上下文更改的另一种方法是重新标记你的文件系统。

让我们再次进行更改，再次复制`authorized_keys`上下文：

```
$ chcon --reference=.ssh/authorized_keys .bashrc
```

现在，让我们把一个非常具体的文件放在一个非常具体的位置，然后重新启动：

```
$ sudo touch /.autorelabel
$ sudo reboot
```

一旦你的机器重新启动，再次查看文件的上下文：

```
$ ls -lhaZ .bashrc 
-rw-r--r--. vagrant vagrant unconfined_u:object_r:user_home_t:s0 .bashrc
```

而且，你还会发现我们添加的`.autorelabel`文件已经被自动删除了。

本章的`Vagrantfile`非常明确地在 CentOS VM 的引导过程中删除了一些控制台选项。这是因为如果你不这样做，`.autorelabel`函数就不会起作用。如果你在这个修复过程中遇到问题，请尝试在物理机或原始 VM 上进行（*在开发环境中*）。

# 它是如何工作的……

`restorecon`的作用是检查文件的上下文是否符合它所期望的真相，如果发现任何问题，它将使用它所知道的静态配置进行纠正。

当我们运行`.autorelabel`函数时，实际上是在我们的系统在启动时运行了`fixfiles relabel`命令，之后我们触摸的文件被删除。你会注意到这次启动可能会花更长的时间，因为它在启动时要做更多的工作。

# 还有更多……

默认情况下，`restorecon`只会恢复`type`上下文，并将其他上下文保留为它发现的样子。这可以通过`-F`标志来覆盖。

我们还提到了重置`root`用户密码，这在 SELinux 的情况下变得非常烦人。

假设你忘记了你的盒子的`root`密码；解决这个问题的方法是进入单用户模式，更改密码，然后重新启动……或者至少，过去是这样的。

现在，所涉及的步骤看起来是这样的：

1.  重新启动系统。

1.  在超时之前编辑你的安装的 GRUB 条目。

1.  确保`linux16`行是`rw`而不是`ro`，并将`init`更改为类似`/bin/bash`的东西。

1.  继续引导过程。

1.  确保你的`/`目录被挂载为`rw`，你可以编辑文件。

1.  运行`passwd`来更新`root`密码。

1.  在`/`目录中运行`touch .autorelabel`，然后重新启动。

1.  检查你是否可以登录。

如果你跳过了`touch .autorelabel`这一步，它就不会起作用，你就得重新开始。

从长远来看，这并不算什么，但在当时可能会令人恼火。

# 总结-权限、SELinux 和 AppArmor

什么时候为时已晚？

当你已经尽一切可能来解决你的问题时呢？

你有检查并确认工作的良好备份吗？

你是不是快要抓狂了？

已经三天了，你自周二以来就没有见过阳光了吗？

权限可能会很棘手和尴尬，有时最好的办法就是说：“算了，这个系统已经太糟糕了，我要重新开始。”我对这种事情的一般准则是我跳过了多少顿饭来修复问题，如果超过一顿，那就是跳过了太多的饭。

在此之前，我做过很愚蠢的事情，我认为在这本书中我已经非常清楚地表明了。我曾经递归地将整个系统的权限改为`777`（这会造成很多问题），我曾经删除目录以释放空间，结果发现那个目录实际上对系统的健康非常重要（我不会分享是哪一个，但它里面有文件和非文件）。我甚至阻止了一个意外的`rm`，比我打算的`rm`多得多，然后努力工作，试图弄清楚我实际上已经损坏了多少文件系统。

简而言之，我已经把系统搞得乱七八糟，以至于它们在技术上是可以修复的，但花费的时间超过了恢复的痛苦。

SELinux、AppArmor 和简单的 Linux 权限可能会让你在互联网上搜寻晦涩的错误信息，希望有人遇到过和你完全相同的问题，并且他们决定分享他们的解决方案（只要不是“没事了，我解决了，关闭这个帖子”）。

但是，所有这些说法，macOS 系统，甚至 POSIX 标准文件权限，都很重要。这可能会耗费时间和令人讨厌，但使用诸如`audit2allow`之类的工具可以大大降低你的血压，同时增加你的厉害程度，学习正确的`chmod`咒语可以将你的故障排除速度提高十倍。

在大多数情况下，你从官方仓库安装的软件会被合理地设置好，只要第三方值得信赖，你甚至可能会发现后来添加的其他仓库也包含他们软件的适当 SELinux 权限。情况比 SELinux 刚开始出现时好多了。

我记得以前人们在他们的指南中建议将 SELinux 禁用作为第一步，我很高兴我们已经走出了那些日子，但有时候还是很诱人。

当你快要绝望，只想让你的应用程序工作时，禁用 SELinux 可能是最诱人的时刻。坚定不移，坚定不移，告诉自己你不会被电脑打败。

这不像是你要对抗 HAL 9000 一样。


# 第九章：容器和虚拟化

在本章中，我们将涵盖以下主题：

+   什么是容器？

+   安装 Docker

+   运行你的第一个 Docker 容器

+   调试一个容器

+   搜索容器（和安全性）

+   什么是虚拟化？

+   启动我们的 VM 的 QEMU 机器

+   使用 virsh 和 virt-install

+   比较本地安装、容器和虚拟机的优势

+   虚拟化选项的简要比较（VMware、proxmox 等）

# 介绍

坦率地说：容器和虚拟化是我在与计算机和服务器相关的事情中最喜欢谈论的之一。能够在你的计算机内安装一个完全不同的计算机的概念，对我来说就是一个充满智慧的概念。

这不是一个新概念；这个原则已经存在了相当长的时间，即使我的第一台 OS9 计算机也能在一定程度上进行虚拟化。更早的时候，这个术语的根源可以追溯到 20 世纪 60 年代，尽管它的含义与现代用语中的含义略有不同。

你可能已经使用过**虚拟机**（**VM**），尽管你可能甚至不知道你已经使用过。如今，虚拟机速度很快，与在底层硬件上运行相比，性能损失可以忽略不计，这要归功于虚拟化的优势，这意味着你不再需要模拟与虚拟机相关的一切，而是直接将虚拟机指令传递给主机计算机的 CPU。

虚拟机无疑是托管和开发的强大工具，能够快速启动和关闭机器，在你不断破坏东西或寻找一种安全且廉价的方式来分割一个庞大的服务器时，它就是一个救世主。

如今，容器在某种程度上已经取代了虚拟机的地位，尽管它们各自都有优势，它们存在于和谐中，而不是不断争斗。

与虚拟机不同，容器更像是系统的一部分，有一个共享的核心。

当你在 Linux 系统上使用容器时，你共享主机机器的内核，而不是安装你自己的内核，并且通常不需要模拟额外的硬件，比如磁盘控制器。

再次强调，容器和容器化并不是新概念，这个想法自从 FreeBSD 上的 jails 以及后来的 Solaris 上的 Zones（它们以一种形式或另一种形式仍然存在，我们稍后会看到）以来就一直存在。然而，最近几年，随着**Docker**的推出，它们已经迅速发展，使得容器的整个概念对人们来说更容易接受（而且他们的营销手段也很出色）。

在本章中，我们将研究容器和虚拟机，讨论各自的利弊，并谈论虚拟环境的管理。

# 技术要求

在本节和本章中，我们将主要使用我们的 Ubuntu 机器。

主要是因为 Ubuntu 默认包含了我们需要的更多最新元素，而 CentOS 由于其长期的使用寿命，许多东西都是向后修补的。

请随意使用以下`Vagrantfile`：

```
# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|

 config.vm.define "ubuntu1804" do |ubuntu1804|
   ubuntu1804.vm.box = "ubuntu/bionic64"
   ubuntu1804.vm.box_version = "20180927.0.0"
 end

 config.vm.define "centos7" do |centos7|
   centos7.vm.box = "centos/7"
   centos7.vm.box_version = "1804.02"
 end

end
```

# 什么是容器？

在本节中，我们将深入探讨容器的实际含义，比我们在介绍中涵盖的更深入一些。

我们不会深入探讨（因为我们会迷失并不得不打电话给詹姆斯·卡梅隆来帮助我们），但我们会触及容器的核心是什么，以及它与运行一个完整的虚拟机有何不同。

# 准备工作

SSH 到你的 Ubuntu 虚拟机：

```
$ vagrant ssh ubuntu1804
```

# 如何做…

我们将创建一个容器，而不使用市场上最流行的工具。

容器利用某些内核特性（命名空间和 cgroups），这意味着它们不严格可移植到 Windows 和 Mac 等系统。

首先，我们将为我们的容器创建一个存储池：

```
$ sudo lxc storage create example-pool dir
```

不鼓励在生产中使用目录存储池。最好使用使用 LVM 或 ZFS 的定制解决方案，但是对于测试和示例，这是可以的。

接下来，我们将使用此存储池启动一个容器：

```
$ sudo lxc launch ubuntu:18.04 example-container -s example-pool
Creating example
Retrieving image: rootfs: 31% (1.63MB/s)
```

前面的检索可能需要一些时间，这将取决于您的网络连接速度。

在这个过程结束时，我们的容器应该已经创建。我们可以使用以下命令列出它：

```
$ sudo lxc list
+-------------------+---------+------+------+------------+-----------+
| NAME | STATE | IPV4 | IPV6 | TYPE | SNAPSHOTS |
+-------------------+---------+------+------+------------+-----------+
| example-container | RUNNING | | | PERSISTENT | 0 |
+-------------------+---------+------+------+------------+-----------+
```

然后，我们可以在其中执行命令：

```
$ sudo lxc exec example-container hostname
example-container
```

在这里，我们运行的命令在我们的主机 VM 上运行时，会告诉我们`ubuntu-bionic`。因此，通过与我们的`lxc`命令一起检查它，我们可以证明它正在容器中运行。

如果我们想要进入容器，我们可以简单地启动一个 shell：

```
$ sudo lxc exec example-container bash
root@example-container:~# hostname
example-container
```

就是这样 - 一个非常快速的操作系统切片，位于您的操作系统内部！

完成后，只需键入`exit`或按*Ctrl* + *D*退出容器：

```
root@example-container:~# exit
```

然后，我们可以使用以下命令销毁它：

```
$ sudo lxc stop example-container
$ sudo lxc delete example-container
```

人们在 LXC 世界和 Docker 世界经常忘记的一件事是，你不仅仅需要处理容器。我们已经删除了容器，但是如果您真的想要清理干净，您还必须删除下载的镜像和存储池。

# 它是如何工作的...

稍微详细解释一下 cgroups 和命名空间的评论，实际上容器是内核和用户空间工具的功能，使事情看起来很好。 LXC 是一个工具，它抽象了复杂性，简化了我们的半隔离机器的设置为几个易于使用的命令。

# cgroups（Linux 控制组）

以下是*Linux 程序员手册*的摘录：

“控制组，通常称为 cgroups，是 Linux 内核的一个功能，允许将进程组织成分层组，然后可以限制和监视各种类型资源的使用。内核的 cgroup 接口通过一个名为 cgroupfs 的伪文件系统提供。分组是在核心 cgroup 内核代码中实现的，而资源跟踪和限制是在一组每种资源类型子系统（内存、CPU 等）中实现的。”

实际上，这意味着内核有能力将进程组合成堆栈，然后可以控制和监视其资源使用情况。

# 命名空间

不要引起趋势，这里再次是*Linux 程序员手册*：

“命名空间将全局系统资源封装在一个抽象中，使得在命名空间内的进程看起来好像它们有自己的隔离实例的全局资源。对全局资源的更改对于属于命名空间的其他进程是可见的，但对其他进程是不可见的。命名空间的一个用途是实现容器。”

实际上，这意味着您的单个网络接口可以连接多个命名空间，使用这些命名空间的进程将认为这是该设备的唯一实例。

网络接口并不是唯一的例子，但它们是更明显的候选者，因为每个 VM 都需要一个 NIC。

# 我们创建的细节

当我们在本节开始时创建存储池时，我们实际上是在通知我们的系统（`lxd`守护程序）需要使用特定目录来存储容器，即下面的`/var/lib/lxd/storage-pools/`：

```
$ sudo ls /var/lib/lxd/storage-pools/example-pool
containers
```

当我们启动容器时，我们首先从默认的互联网位置下载了一个预打包的镜像，作为我们创建的容器的基础。

在这里，它被视为一个字母数字字符串，但实际上是 Ubuntu 18.04 的精简容器形式：

```
$ sudo ls -lhA /var/lib/lxd/images/
total 175M
-rw-r--r-- 1 root root 788 Nov 4 15:44 30b9f587eb6fb50566f4183240933496d7b787f719aafb4b58e6a341495a38ad
-rw-r--r-- 1 root root 175M Nov 4 15:47 30b9f587eb6fb50566f4183240933496d7b787f719aafb4b58e6a341495a38ad.rootfs
```

注意这个容器的大小，`175 M`，这是人们强调容器的主要优势之一（它们很小，这实际上是更大的例子之一）。

当我们的容器正在运行时，我们可以从主机上看到它作为一组进程：

```
$ ps uf -p 3908 --ppid 3908 --ppid 3919 
```

输出应该看起来像以下截图：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/4de248d9-dd2c-40aa-a38a-950383b5813c.png)

因此，这个容器在里面有大部分的操作系统，它是从我们下载的镜像继承而来的，尽管它显然不包含与主机 VM 共享的内核。

想象一个容器就像一个橙子（我也很喜欢橙子），其中每个片段都可以存在为自己的一小部分多汁的好处，但没有橙子的外皮给它结构和传递养分，它就毫无用处。这与虚拟机形成对比，后者更像是一个永远年轻的小蜘蛛（听我说完），每个都独立存在为活生生的生物，但它们仍然骑在它们母亲的背上，准备向任何接触到它们的人提供一剂神秘的恐怖。

# 还有更多...

目前，您应该在由 LXC 创建的容器中，位于由 Vagrant 管理的虚拟机（并利用 VirtualBox）之上，位于您自己的笔记本电脑、台式机或服务器上。

这可能有点难以想象，但很多聪明的人花了很多时间来确保这种设置可以无问题地工作。

# LXD 守护程序

像往常一样，我们可以使用`systemctl`来可视化我们的服务：

```
$ systemctl status lxd
● lxd.service - LXD - main daemon
 Loaded: loaded (/lib/systemd/system/lxd.service; indirect; vendor preset: enabled)
 Active: active (running) since Sun 2018-11-04 15:41:14 UTC; 33min ago
 Docs: man:lxd(1)
 Process: 2058 ExecStartPost=/usr/bin/lxd waitready --timeout=600 (code=exited, status=0/SUCCESS)
 Process: 2036 ExecStartPre=/usr/lib/x86_64-linux-gnu/lxc/lxc-apparmor-load (code=exited, status=0/SUCCESS)
 Main PID: 2057 (lxd)
 Tasks: 16
 CGroup: /system.slice/lxd.service
 └─2057 /usr/lib/lxd/lxd --group lxd --logfile=/var/log/lxd/lxd.log
```

# 另请参阅

在本节的开头，我们在容器内运行了`hostname`，但这并不能让您知道容器在做什么。我发现特别方便的一件事是能够检查运行在我的容器中的进程，而不必先挖出我的`ps`命令的进程 ID。

在这里，我使用以下命令：

```
$ sudo lxc exec example-container top
```

这给了我以下输出：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/339e1759-742e-4a74-8e37-1a88d8cc6913.png)

请注意，它比主机机器安静得多，实际上只有很少的守护程序在容器中运行。

# 安装 Docker

迄今为止，在 Linux 上运行容器的最流行的解决方案（至少在撰写本文时）是 Docker。

最初是 Docker Inc.（当时是 dotCloud）为了更好地利用其**PaaS**（**平台即服务**）公司中的容器而开始的，Docker 很快在开源世界中获得了广泛的认可，并很快被视为计算的未来在许多领域（愤世嫉俗的系统管理员通常是在开发人员得知之后才出现的）。

因为它实际上是一种使用已经存在的内核特性的简单方式，并且包括 Docker Hub，供人们上传和下载预构建的镜像，这使得容器变得简单。

很快，人们开始将一切都容器化，从 Firefox 到 Nginx，再到整个发行版，只是因为。

我坚信 Docker 使得上传和下载他们的镜像变得容易，这有助于其成功。正如我已经提到的，容器的概念可以追溯到九十年代，但当时没有“监狱”或“区域”供人们下载预构建的软件集合。Docker Hub 在一个已经流行的平台上提供了这一点。

# 准备工作

大多数发行版都以某种形式在传统存储库中提供 Docker。然而，这经常与上游不一致，或者只是老旧的，因此在您的环境中利用上游 Docker 存储库是一个好主意。

SSH 到您的 Ubuntu 虚拟机：

```
$ vagrant ssh ubuntu1804
```

# 如何做...

Docker 保持了一个页面，介绍了如何在您选择的发行版上安装 Docker（参见[`docs.docker.com/install`](https://docs.docker.com/install)）。以下是 Ubuntu 的简化指令。

运行更新以确保您已准备好安装 Docker：

```
$ sudo apt update
```

安装 GPG 密钥，然后添加存储库本身：

```
$ wget https://download.docker.com/linux/ubuntu/gpg
$ sudo apt-key add gpg $ sudo apt-add-repository 'deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable'
```

像往常一样，检查 GPG 指纹是否与官方来源一致。

现在，我们终于可以安装 Docker 本身了（这可能需要一些时间）：

```
$ sudo apt install docker-ce -y
```

我们还可以使用`systemctl`来检查我们的 Docker 守护程序的状态：

```
$ systemctl status docker
● docker.service - Docker Application Container Engine
 Loaded: loaded (/lib/systemd/system/docker.service; enabled; vendor preset: enabled)
 Active: active (running) since Sun 2018-11-04 16:56:26 UTC; 52s ago
 Docs: https://docs.docker.com
 Main PID: 11257 (dockerd)
 Tasks: 23
 CGroup: /system.slice/docker.service
 ├─11257 /usr/bin/dockerd -H fd://
 └─11275 docker-containerd --config /var/run/docker/containerd/containerd.toml
```

您可能已经注意到我们还没有启动和启用此服务。这主要是因为派生自 Debian 的系统喜欢为您启动服务...我个人不喜欢这种方法的原因有很多，但它就是这样。

# 它是如何工作的...

在开始之前，你可能已经注意到我们不断使用一个名为`docker-ce`的软件包，这是有很好的原因的。

Docker 有两个基本版本，**社区版（CE）**和**企业版（EE）**。大多数情况下，你只会在野外看到 CE，它完全可以满足你的所有需求。

我们在这里所做的只是直接去软件的作者那里添加他们自己的 GPG 密钥和存储库信息，以及我们的 Ubuntu 默认设置。Docker 是一个非常动态的程序，意味着它经常发布并且发布量很大。在撰写本文时，我们安装了`18.06.1-ce`，但在你知道之前可能会发生变化。Docker 采用年-月发布格式：

```
$ docker --version
Docker version 18.06.1-ce, build e68fc7a
```

我们还安装了两个主要组件（以及许多工具和附加组件），即 Docker 命令行工具和 Docker 守护程序。

Docker 的工作方式与其他用户空间工具相同，利用内核功能。它的独特之处在于它可以是多么用户友好。

你主要通过命令行工具`docker`来使用 Docker，而这个工具又与 Docker 守护程序进行通信。这个守护程序负责管理它被指示创建的容器，并维护它从 Docker Hub 或其他注册表中拉取的图像。

Docker 注册表是图像的存储库。最受欢迎的是 Docker Hub，但没有什么能阻止你创建自己的注册表，或者使用现成的解决方案来管理一个，比如 Artifactory。

现在要注意的最后一个组件是 Docker 正在使用的运行时，即`runC`（通用容器运行时）。

运行时实际上只是 Docker 将用于运行容器的统一系统集合的名称（想象一下 cgroups 和命名空间捆绑成一个词，尽管还有其他功能）。这意味着，虽然`runC`是特定于 Linux 的，但如果 Windows 有一个容器运行时（Host Compute Service），那么 Docker 可以使用它。

这并不使容器在操作系统之间通用 - 你不能在 Linux 上创建一个容器，然后在特定于 Windows 的运行时中运行它，但这确实使得 Docker 工具通用。

# 还有更多...

获取有关 Docker 安装的所有信息的最简单方法是使用`docker info`命令：

```
$ sudo docker info
Containers: 0
 Running: 0
 Paused: 0
 Stopped: 0
Images: 1
Server Version: 18.06.1-ce
Storage Driver: overlay2
 Backing Filesystem: extfs
 Supports d_type: true
 Native Overlay Diff: true
Logging Driver: json-file
Cgroup Driver: cgroupfs
Plugins:
 Volume: local
 Network: bridge host macvlan null overlay
 Log: awslogs fluentd gcplogs gelf journald json-file logentries splunk syslog
Swarm: inactive
Runtimes: runc
Default Runtime: runc
Init Binary: docker-init
containerd version: 468a545b9edcd5932818eb9de8e72413e616e86e
runc version: 69663f0bd4b60df09991c08812a60108003fa340
init version: fec3683
Security Options:
 apparmor
 seccomp
 Profile: default
Kernel Version: 4.15.0-34-generic
Operating System: Ubuntu 18.04.1 LTS
OSType: linux
Architecture: x86_64
CPUs: 2
Total Memory: 985.3MiB
Name: ubuntu-bionic
ID: T35X:R7ZX:MYMH:3PLU:DGXP:PSBE:KQ7O:YN4O:NBTN:4BHM:XFEN:YE5W
Docker Root Dir: /var/lib/docker
Debug Mode (client): false
Debug Mode (server): false
Registry: https://index.docker.io/v1/
Labels:
Experimental: false
Insecure Registries:
 127.0.0.0/8
Live Restore Enabled: false

WARNING: No swap limit support
```

# 稍微更多

我没有涉及的一件事是`containerd`和`CRI-O`之类的东西。如果你已经了解这些术语，那么我之所以没有提到它们，是因为它们远远超出了本书试图实现的范围。

我鼓励任何对 Docker 及其各个组件感兴趣的人，去阅读专门的文献，因为如果你全面了解当今最流行的容器化工具，未来几年你将不会失业。

# 另请参阅

你有没有在使用 Docker 时注意到`pigz`？这是一个特别有趣的软件，因为它基本上是`gzip`的并行版本。当你解压文件并且有 18 个核心时，最好尽可能多地使用它们，而不是过载一个核心。

# 运行你的第一个 Docker 容器

我们已经在 LXC 部分使用了一个容器，但现在我们将使用更流行的容器运行系统。

本节将涵盖一些基本命令，而不会深入讨论。

# 准备工作

在本节中，我们将使用我们的 Ubuntu 虚拟机，但请确保先设置好上一节的 Docker。

SSH 到你的虚拟机，并确保在安装 Docker 之前使用上一节设置上游 Docker 存储库：

```
$ vagrant ssh ubuntu1804
```

# 如何做...

与 LXC 部分一样，我们将启动一个 Ubuntu 容器，然后与其进行交互。

从以下命令开始：

```
$ sudo docker run -itd --rm alpine /bin/ash
Unable to find image 'alpine:latest' locally
latest: Pulling from library/alpine
4fe2ade4980c: Pull complete 
Digest: sha256:621c2f39f8133acb8e64023a94dbdf0d5ca81896102b9e57c0dc184cadaf5528
Status: Downloaded newer image for alpine:latest
5396b707087a161338b6f74862ef949d3081b83bbdcbc3693a35504e5cfbccd4
```

现在容器已经启动运行，你可以用`docker ps`查看它：

```
$ sudo docker ps
CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES
5396b707087a alpine "/bin/ash" 45 seconds ago Up 44 seconds ecstatic_lalande
```

如果你愿意，你也可以使用`docker exec`进入它：

```
$ sudo docker exec -it ecstatic_lalande /bin/ash
/ # 
```

你也可以使用`docker attach`，它在表面上完成了相同的事情（让你访问容器中的 shell）。这种方法的唯一问题是，你将附加到活动进程，这意味着当你关闭会话时，容器也会停止。

再次离开容器（`exit`）将带你回到你的 VM 提示符。

从这里，你可以停止你的容器：

```
$ sudo docker stop ecstatic_lalande
ecstatic_lalande
```

这可能需要几秒钟。

容器现在已被删除，我们可以通过另一个`docker ps`来确认：

```
$ sudo docker ps -a
CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES
```

# 它是如何工作的...

让我们分解我们的命令。

# 创建一个容器

从创建新容器开始，这是我们使用的命令：

```
$ sudo docker run -itd --rm alpine /bin/ash
```

在这里，我们告诉 Docker 我们想要在一个新的容器中`run`一个命令：

```
docker run
```

然后，我们通知它我们希望它是交互式的，有一个伪 TTY，并且启动分离的（将我们带回 VM shell）：

```
-itd
```

接下来，我们告诉 Docker，当容器停止时，我们希望它自动删除自己：

```
--rm
```

这是一个相对较新的功能，只是因为人们没有意识到容器在停止后仍然存在，人们最终会得到数百个已停止的容器列表。

最后，我们说我们想使用什么镜像（来自 Docker Hub），以及要运行什么命令（这里是 Alpine Linux 的默认 shell，`ash`）：

```
alpine /bin/ash
```

# 列出我们的容器

其次，我们使用以下命令列出我们的新容器：

```
$ sudo docker ps
```

这显示了所有我们的容器（或者在这种情况下，只有一个）的`CONTAINER ID`、`IMAGE`、`COMMAND`、`CREATED`、`STATUS`、`PORTS`和`NAMES`。

`CONTAINER ID`部分是一个随机字符串分配，`NAMES`部分显示了你的容器的随机生成的友好名称（尽管这也可以在创建时定义）。

当我们后来在我们的列表命令中添加了`-a`时，是为了显示容器并没有因为停止而被从初始列表中省略，因为`-a`标志将显示所有容器，而不仅仅是正在运行的容器。

# 在我们的容器中执行命令

接下来，我们跳进容器内，启动另一个（在创建时已经启动的）shell 会话：

```
$ sudo docker exec -it ecstatic_lalande /bin/ash
```

在这里，我们通过在容器内使用交互式会话和另一个伪 TTY 来执行命令（在这里用`docker ps`中的友好名称表示）。

这将把我们放在容器内。如果我们运行`top`，我们将看到我们已经启动的`/bin/ash`命令的两个实例：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/4340b198-411c-4038-b90f-ad36e8361aec.png)

你有没有注意到`/bin/ash`实例中的一个是`PID 1`？

# 停止我们的容器

一旦我们再次跳出来，然后停止正在运行的容器：

```
$ sudo docker stop ecstatic_lalande
```

这需要几秒钟，但是一旦完成，容器将消失（正如我们所看到的），尽管它使用的镜像（alpine）将保留下来。

因为我们的镜像仍然存在，所以下次你想用它做点什么时，你就不必再下载它了！

# 调试一个容器

在这一部分，我们将再次启动我们的容器，进行一些更改，并检查我们的更改是否产生了影响。

这有助于突出容器的瞬时性质，以及你可以在运行的实例中做些什么。

# 准备工作

在这一部分，我们将继续使用我们的 Ubuntu VM。

如果还没有连接，通过 SSH 连接到你的 VM，并启动一个容器：

```
$ vagrant ssh ubuntu1804 $ sudo docker run -itd --rm -p8080:8080 alpine /bin/ash
```

# 如何做...

现在你应该有一个正在运行的 docker 容器，在这里列出为`docker ps`：

```
$ sudo docker ps
CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES
0f649283dcaf alpine "/bin/ash" 41 seconds ago Up 39 seconds 0.0.0.0:8080->8080/tcp compassionate_boyd
```

请注意，我们在这个例子中还有一个端口转发，即端口`8080`。

在这种情况下，端口转发与其他情况相同-我们正在将主机的一个端口转发到容器中的一个端口。

尝试使用`curl`命令访问端口：

```
$ curl localhost:8080
curl: (56) Recv failure: Connection reset by peer
```

现在，跳到 VM，让我们在指定的端口上启动一个 Web 服务器：

```
$ sudo docker exec -it compassionate_boyd /bin/ash
```

首先，我们需要安装一些额外的 busybox 东西：

```
# apk add busybox-extras
```

现在，我们可以在端口`8080`上启动一个小型 Web 服务器，然后退出容器：

```
# touch index.html
# echo "I hated reading Shakespeare in school." > index.html
# httpd -p8080
# exit
```

现在，从你的 VM，你将能够`curl`你的容器的新 Web 服务器：

```
$ curl localhost:8080
I hated reading Shakespeare in school.
```

停止容器，然后启动一个新的：

```
$ sudo docker stop compassionate_boyd
compassionate_boyd
$ sudo docker run -itd --rm -p8080:8080 alpine /bin/ash
592eceb397e7ea059c27a46e4559c3ce7ee0976ed90297f52bcbdb369e214921
```

请注意，当你再次`curl`你的端口时，它将不起作用，因为你之前对运行的容器所做的所有更改都已丢失，并且一个新的容器已经取而代之：

```
$ curl localhost:8080
curl: (56) Recv failure: Connection reset by peer
```

# 它是如何工作的...

我们在这里所做的只是强调容器本质上是短暂的，虽然你可以停止和启动相同的容器（在`docker run`命令中去掉`--rm`），但在将容器标记并上传到某个注册表之前，你都处于一个瞬态状态。

通常不建议通过启动一个容器然后在其中安装大量软件来构建容器，然后离开并保存它以供以后使用。更好的方法是使用`Dockerfile`或其他自动化和可重复构建容器的方法。

我们还指出，虽然 Docker 容器应该是一个独立的小实体，但这并不意味着你不能进入其中查看发生了什么，甚至安装额外的软件来帮助你进行调试，如果你愿意的话。

# 还有更多...

如果你有兴趣使用`Dockerfile`来做我们在这里做的事情，这是一个相当简单的方法，尽管它在技术上超出了本书的范围。

以下内容足以让你开始：

```
FROM alpine

MAINTAINER Your Deity of Choice

RUN apk add busybox-extras
RUN touch index.html
RUN echo "I really hated reading Shakespeare in school." > index.html

EXPOSE 8080/tcp

CMD ["/usr/sbin/httpd", "-p8080", "-f"]
```

然后，你可以使用以下类似的方法构建：

```
$ sudo docker build .
<SNIP>
Successfully built d097226c4e7c
```

然后，你可以启动你的结果容器（分离，并转发端口）：

```
$ sudo docker run -itd -p8080:8080 d097226c4e7c
```

我们在`Dockerfile`中添加了`-f`，以确保进程保持在前台（容器不会立即停止）：

```
$ curl localhost:8080
I really hated reading Shakespeare in school.
```

# 搜索容器（和安全性）

在这一部分，你大部分时间都需要访问某种类型的浏览器，尽管在紧急情况下，你可能可以打电话给朋友让他们帮你做互联网搜索（如果你是一个真正好的朋友，而且他们确实没有更好的事情要做的话）。

我们还将使用我们的虚拟机来练习我们发现的东西。

我们将在 Docker Hub 上搜索容器，并提及下载和使用公共镜像的安全性问题。

这一部分并不是为了吓唬你，就像你不应该害怕运行任何你找到的自由软件一样——这是在做尽职调查。

# 准备工作

跳到你的 Ubuntu 虚拟机上（如果你还没有安装 docker，请从上一节安装）：

```
$ vagrant ssh ubuntu1804
```

# 如何做...

从你选择的浏览器（对我来说是 Firefox），前往[`hub.docker.com`](https://hub.docker.com)。

你将会看到一个类似以下的页面：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/fc79e940-83c1-4660-9a05-a88c0b474f6e.png)

这里有一些暗示，即标题为“新手入门 Docker？”的部分。尽管第一句话可能会让人觉得需要创建 Docker ID 才能开始使用，但实际上并不需要。你可能会发现这样做很方便，甚至可能有充分的理由创建一个 ID，但最初（至少在撰写本文时）绝对没有必要这样做。

相反，使用屏幕顶部的搜索栏，输入`redis`：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/e5f3b6f7-83c8-4bfc-b402-760e156a2832.png)

哇！那是很多存储库！

这就是关于 Docker 的第一件好事。因为创建镜像并上传到 Docker Hub（我自己有几个）是如此容易，所以你想要的东西可能会有多个版本。

在这里，我们可以看到顶部的结果只是简单地命名为 redis，而不是像其他的`<username>/redis-foo`。

当一个镜像是官方的时候，它会得到特权的荣誉，只有它的软件的明确名称，就像在这种情况下的 redis 一样。

点击它：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/8d5a1c09-ddaf-4cba-851d-5bb77087e479.png)

这里有几件事情需要注意。

+   幸运的是，我们得到了一个开始的命令，即右边的`docker pull redis`。

+   我们得到了存储库信息，这是默认视图，为我们提供了简短和完整的描述。在实践中，这可以是维护者想要的任何长度。

+   最后，此刻，我们在顶部得到了一个标签部分。现在点击这个：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/69cd9d17-f020-4149-8ed7-09dd57f44d04.png)

标签，就像 Git 一样，是表示您要下载的容器的特定版本的一种方式。

默认标签是最新的，如果您要运行以下命令，它就是您要下载的镜像（正如您可以在我们的命令后面立即看到的那样）：

```
$ sudo docker run -d redis
Unable to find image 'redis:latest' locally
latest: Pulling from library/redis
f17d81b4b692: Pull complete 
b32474098757: Pull complete 
<SNIP>
```

如果我们想要专门拉取 Redis 的 Alpine 版本（即在 Alpine Linux 上安装的 Redis），我们将运行以下命令：

```
$ sudo docker run -d redis:alpine
Unable to find image 'redis:alpine' locally
alpine: Pulling from library/redis
4fe2ade4980c: Already exists 
fb758dc2e038: Pull complete 
989f7b0c858b: Pull complete 
<SNIP>
```

请注意，我们拉取了除基本版本之外的每个版本，而基本版本已经存在于我们的设置中。

看这里！您使用 Docker Hub 寻找了每个人最喜欢的内存数据库的一个版本！

# 它是如何工作的...

我们在这里做的就是从全球 Docker Registry 中拉取一个功能性镜像；这是默认的，最重要的，最大的，最原始的，也是最好的（根据一些人的说法）。

Docker Hub 是一个更小的存储库，每个人都可以在他们构建（或分叉）的容器上加上自己的标记，从而增加了世界软件的种类。

显然这有缺点，正如我在前面讽刺的一行中所暗示的那样。这意味着因为将您的镜像轻松地推送到 Docker Hub，发现您想要的一个镜像可能变得越来越令人沮丧。

人们也可能是恶意的，上传的容器可能确实做了他们所说的事情，同时又利用您计算机的整个核心来挖掘比特币（尽管当这种事情发生时，通常会很快被发现）。作为系统管理员、DevOps 人员、公司的万金油，您需要弄清楚容器在做什么，以及它是否符合您的需求。

我遵循一些基本原则：

+   检查`Dockerfile`和源是否免费提供：

+   通常，Docker Hub 上的存储库是从 GitLab 或其他源代码托管站点触发的构建，这意味着您可以检查容器背后的代码

+   检查容器的下载次数：

+   虽然这并不是质量的指标，因为经常软件的第一个镜像是最受欢迎的，但它通常是千里眼原则的一个很好的例子。如果成千上万的人在使用它，那么它隐藏在容器中的恶意内容的可能性更高（尽管仍有可能）。

+   检查是否为官方项目的 Docker 容器：

+   像 Redis、Kibana 和 Swift 这样的项目都有官方的 Docker 容器，所以通常我会选择它们的产品而不是其他的。

+   该项目可能还有未标记为官方的容器，仍然带有创建者的名字。在我看来，这些容器明显优于 Jane Bloggs 的容器。

+   这并不是说非官方的容器不好，或者它们不满足稍微不同的需求，但是，十有八九，我发现情况并非如此。

+   您能自己构建吗？

+   假设`Dockerfile`是免费许可的，您可以从 GitLab 上将其复制到您的构建服务器上，以创建自己的镜像。至少这样，您知道在过程结束时您看到的就是您得到的（假设您没有从您从未听说过的一些可疑第三方存储库中下载软件作为构建的一部分）。

尽管如此 - 听起来我对自制容器非常不满 - Docker 已经赢得了容器至高无上的战争，因为它在市场上占据了主导地位，并且易于使用（无论是构建容器还是找到它们的简单性）。

Docker Hub 意味着即使我没有本地存储库配置，但我安装了 Docker，我很快就可以在 Alpine 容器上运行一个 Web 服务器，它连接到一个 MariaDB 容器，位于 Gentoo 之上。

然后，该容器可以将日志馈送到一个容器化的 Elasticsearch 实例，运行在 Slackware 上，就在同一主机上，大约十分钟内完成。

# 还有更多...

如果你愿意的话，你也可以从命令行搜索：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/5af54ef9-20f8-4d9a-91f4-80fc5d4482b5.png)

说实话，我从来不这样做，主要是因为现在每个人都随身携带一个浏览器。然而，我知道有些人是纯粹主义者。

# 什么是虚拟化？

如果你随机翻开这本书的这一页，那么你现在可能知道虚拟化实际上是什么。如果你按照正常的方式，从头开始阅读，那么你很可能已经明白你几乎在整本书中都在使用虚拟化。

虚拟化是在一个机器内部虚拟化（我知道对吧？）另一台机器的行为。不像容器，我们从 USB 控制器到软盘驱动器（说真的）都进行了可视化。

这个概念并不新鲜，但技术在不断发展。

对于我们的例子，你可能和我一样，转而使用了带有 VirtualBox 的 Vagrant。我选择这种方式是因为 VirtualBox 随处可见，适用于 macOS、Linux 和 Windows（以及其他操作系统！）。这有很大的优势，但也有劣势。

虚拟化本质上与其运行的主机的软件和硬件密切相关。考虑到这一点，你可能会理解为什么企业通常选择不在所有地方使用 VirtualBox（尽管有 Windows 和 Linux 机器），而是分别使用 HyperV 和 KVM……它们更本地化。

在 Linux 领域，虚拟化软件的选择是**KVM**（**Kernel Virtual Machine**）。

旁白：KVM 是一个糟糕的产品或软件名称。在决定使用 Kernel Virtual Machine 之前，它已经有了一个含义，全世界的数据中心工程师自从它诞生以来一直在诅咒这个特定的三个字母缩写。键盘视频鼠标是一个标准，在我脑海中，当我听到这些字母时，我仍然想象着数据中心的崩溃车。

# 准备工作

在本节中，我们将研究容器和虚拟化之间的一些基本区别。

我们将首次使用我们的 Ubuntu 虚拟机和 CentOS 虚拟机。

登录到你的 CentOS 和 Ubuntu 虚拟机：

```
$ vagrant ssh ubuntu1804
$ vagrant ssh centos7
```

# 如何做到…

在我们的容器步骤中，我们简要地看到了在主机虚拟机上运行的内核与容器内部运行的内核是相同的。

在这一步中，我们将在我们的两个虚拟机上运行相同的命令并比较输出：

```
$ uname -a
Linux ubuntu-bionic 4.15.0-36-generic #39-Ubuntu SMP Mon Sep 24 16:19:09 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux $ uname -a
Linux localhost.localdomain 3.10.0-862.2.3.el7.x86_64 #1 SMP Wed May 9 18:05:47 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```

我们的 Ubuntu 系统正在运行内核 4.15.0，而我们的 CentOS 系统正在运行版本 3.10.0。

这就是容器的第一个优势，它们能够运行完全不同版本的 Linux 内核。

在这方面的第二个优势是虚拟机不必与其主机相同的操作系统：你可以在 Linux 主机上模拟 Windows、FreeBSD，甚至 macOS 机器，以及几乎任何相同的组合。

macOS 有点特殊（它总是这样吗？）因为存在许可问题，你必须以非常特定的方式进行操作，但是可以做到。

让我们看看另一件有点酷的事情。

在我们的 CentOS 虚拟机上，我列出了磁盘：

```
$ lsblk
NAME MAJ:MIN RM SIZE RO TYPE MOUNTPOINT
sda 8:0 0 40G 0 disk 
├─sda1 8:1 0 1M 0 part 
├─sda2 8:2 0 1G 0 part /boot
└─sda3 8:3 0 39G 0 part 
 ├─VolGroup00-LogVol00 253:0 0 37.5G 0 lvm /
 └─VolGroup00-LogVol01 253:1 0 1.5G 0 lvm [SWAP]
```

这些不是物理驱动器，它们是虚拟的，因此你可以无限次地搞乱它们的配置，而不会损坏主机的引导潜力。

这是我一直在抱怨的一件事情，主要是因为我曾经在容器中运行了一堆 Ansible，完全搞砸了我在笔记本电脑上的安装。这个 Ansible，尽管当时我并不知道，强制性地改变了磁盘分区和布局，并且在容器的情况下，列在`/dev/`中的设备是你机器上的设备，这意味着我已经彻底毁掉了我的本地安装。幸运的是，我在重启之前弄清楚了发生了什么，并且能够在重新安装之前保存需要的工作，但我再也不这样做了。我还改变了测试，使用 Vagrant 和虚拟机代替……

现在，显然也有缺点——你基本上是在运行整个机器，这意味着它们必须启动（尽管你可以将它缩短到几秒钟），并且启动速度比大多数容器慢。

你可能也只需要安装一个程序（比如在 Windows 虚拟机上安装 Steam），但你会得到其他东西，意味着无论你想要还是不想要，你都会得到 Edge 浏览器、画图和那些烦人的文件夹，比如`文档`部分中的`音乐`、`视频`和`图片`，甚至在服务器安装中也是如此。

# 工作原理...

它在现代计算机上运行，主要是利用 CPU 的特性。

当你模拟你的硬件时，无论是使用 VirtualBox 还是 KVM，你真正做的是为 CPU 创建一整套独立的指令。如果我们在不原生支持 VM 的 CPU 上模拟 VM，并且无法以接近原生速度处理它们的指令，你必须甚至模拟 CPU，这可能是昂贵和缓慢的（稍后详细介绍）。

一般来说，过去十年的 CPU 将具有 AMD-V（在 AMD 的情况下）或 VT-x（在 Intel 的情况下），这意味着你的虚拟机在原始处理速度方面几乎无法与主机机器区分开来。

还有**完全虚拟化**和**半虚拟化**，前者意味着模拟一切（比如，在 x86_64 处理器上模拟 aarch64 处理器），后者意味着，虽然进程的执行是分离的，但实际使用的处理器与主机是相同的（我们之前讨论过的 CPU 虚拟化感知）。

# 还有更多...

使用虚拟机还有更多酷炫的功能，这些功能在容器中是不可能的。

假设你是一个玩家，你真的不喜欢使用 Windows，但勉强承认你真的想和你的朋友一起玩文明，他们都是狂热的 Windows 迷。你可以（在某种程度上）在 Linux 内部做到这一点。

好吧，好吧，这样说有点不诚实，暗示你是在 Linux 内部进行操作，但这里有一个方法。

你启动一个虚拟机，安装 Windows（合法），然后将你的显卡连接到你的虚拟机...

什么？

是的！

通过 PCI-passthrough，完全可以将显卡分配给虚拟机，将显示器插入背面，然后在单独的屏幕上进行所有游戏（使用相同的鼠标和键盘）。

进展！

# 启动一个带有我们的虚拟机的 QEMU 机器

在这一部分，我们将在我们的虚拟机内启动一个虚拟机，并尝试连接到它。

请注意。你可能会认为本节的元素很慢。这不是你的机器或你自己的配置的错，这是物理的错，也是我们尚未拥有消费级量子计算的事实。

# 准备好了

SSH 到你的 Ubuntu 虚拟机：

```
$ vagrant ssh ubuntu1804
```

在 Ubuntu 上安装运行虚拟机的适当组件：

```
$ sudo apt install qemu -y
```

# 如何做...

我们将下载一个 Alpine ISO 并尝试在虚拟机内进行安装（在我们的虚拟机内）：

```
$ wget http://dl-cdn.alpinelinux.org/alpine/v3.8/releases/x86_64/alpine-virt-3.8.1-x86_64.iso
```

我选择 Alpine 是因为它很小，只有 32MB。

接下来，我们需要创建一个虚拟磁盘来安装我们的操作系统：

```
$ qemu-img create example-disk 4G
Formatting 'example-disk', fmt=raw size=4294967296
```

现在，我们可以使用 QEMU 在我们的虚拟驱动器上启动我们的 ISO：

```
$ qemu-system-x86_64 -drive file=example-disk,format=raw -cdrom alpine-virt-3.8.1-x86_64.iso -boot d -nographic
```

幸运的话，你应该能看到以下内容：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/9fb5b5b4-7578-419b-9698-0d4ea89aa886.png)

在命令行提示符下，你应该能够以 root 用户登录（默认情况下没有密码）：

```
localhost login: root
Welcome to Alpine!

The Alpine Wiki contains a large amount of how-to guides and general
information about administrating Alpine systems.
See <http://wiki.alpinelinux.org>.

You can setup the system with the command: setup-alpine

You may change this message by editing /etc/motd.

localhost:~# 
```

Alpine 的功能类似于一个接近实时 CD 的东西，所以我们现在可以继续进行快速安装到本地驱动器：

```
# setup-alpine
```

你会被问到一些标准问题。大多数情况下，你可以用默认答案，但为了完整起见，这是我做的：

+   键盘：`gb`

+   键盘变体：`gb`

+   主机名：`[默认（localhost）]`

+   接口：`[默认（eth0）]`

+   IP 地址：`[默认（dhcp）]`

+   手动网络配置：`[默认（否）]`

+   密码：随机

+   时区：`[默认（UTC）]`

+   代理：`[默认（无）]`

+   镜像：`3`（英国，你可能会找到更接近你的）

+   SSH 服务器：`[默认（openssh）]`

+   要使用的磁盘：`sda`

+   使用方法：`sys`

+   擦除并继续：`y`

完成后，你将在你的 Ubuntu 虚拟机内安装了 Alpine Linux 虚拟机。

关闭 Alpine 安装：

```
# poweroff
```

你会发现自己又回到了你的 Ubuntu 虚拟机。现在，我们将再次启动 Alpine，但这次我们将省略 ISO 文件和`-boot`参数：

```
$ qemu-system-x86_64 -drive file=example-disk,format=raw -nographic
```

正如我在开头所说的，所有这些步骤都可能需要很长时间才能完成，这取决于你的计算机的年龄。

启动后，你会发现自己又回到了 Alpine 安装界面，这次是从我们的虚拟驱动器启动的：

```
Welcome to Alpine Linux 3.8
Kernel 4.14.69-0-virt on an x86_64 (/dev/ttyS0)

localhost login: root
Password: 
Welcome to Alpine!

The Alpine Wiki contains a large amount of how-to guides and general
information about administrating Alpine systems.
See <http://wiki.alpinelinux.org>.

You can setup the system with the command: setup-alpine

You may change this message by editing /etc/motd.

localhost:~# 
```

要终止会话，要么再次关闭虚拟机，要么按下*Ctrl* + *A*，然后按下*X*。

# 工作原理...

逐步分解我们在这里所做的事情，我们首先从 Alpine 网站下载了一个 ISO 映像。这是最容易解释的事情，因为我们实际上是使用 ISO 作为我们安装的真相来源。你也可以做一些其他的事情，比如将`/dev/cdrom`传递给你的虚拟机，如果你希望使用你机器上的物理驱动器（并且你生活在 2009 年）。

一旦我们有了 ISO 映像，我们就创建了一个基于文件的块设备来安装。这样我们可以将一个安装与另一个安装分开，甚至可以将安装从一台机器移动到另一台机器。还有其他不涉及使用文件的解决方案-你可以对 LVM 设置进行分区，将一些空间分配给你的虚拟机，或者你可以连接一个物理磁盘，并将整个磁盘分配给安装。

我们使用`qemu-img`创建文件，但你也可以使用其他工具，比如`fallocate`来完成同样的工作。

接下来，我们使用以下命令启动了我们的虚拟机：

```
$ qemu-system-x86_64 -drive file=example-disk,format=raw -cdrom alpine-virt-3.8.1-x86_64.iso -boot d -nographic
```

具体来说，我们有以下内容：

```
qemu-system-x86_64
```

这是我们想要模拟的 QEMU 架构。我选择了 x86_64，因为它是最常见的架构，也是我们下载的 ISO 期望找到的架构。如果我们愿意的话，我们也可以使用`qemu-system-aarch64`，并且提供适当的磁盘映像：

```
-drive file=example-disk,format=raw
```

在这里，我们向 QEMU 传递了一个要使用的驱动器，具体是我们刚刚创建的`example-disk`文件，以及它创建的格式：

```
-cdrom alpine-virt-3.8.1-x86_64.iso
```

我们明确告诉 QEMU 我们要使用我们下载的 ISO：

```
-boot d
```

我们想要从 CD-ROM 而不是虚拟驱动器启动：

```
-nographic
```

我们在这里是一个通过 SSH 连接的服务器，所以我们不能为我们的虚拟机使用图形输出。这个选项将串行输入和输出重定向到控制台。

# 还有更多...

除了速度之外，没有什么能阻止你将 QEMU 驱动的虚拟机用作完整的机器。

你可以安装软件包，甚至运行`htop`之类的东西：

```
# apk add htop
```

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/9e5f8e7c-10a6-43e1-93e1-db890fa186a5.png)

# 另请参阅

你可能注意到了很多我们没有使用的选项，QEMU 的系统工具功能非常强大。通常，人们不直接使用 QEMU 构建虚拟机，他们依赖更亮眼和更用户友好的工具来完成工作。

在服务器上，Virsh 是一个不错的选择（本章后面会介绍），在桌面机器上，**虚拟机管理器（virt-manager）**是一个非常常见的安装包，它还可以让你连接到远程（无头）服务器，使用点击按钮设置虚拟机。

# 使用 virsh 和 virt-install

`virsh`和`virt-install`对于刚开始在 Linux 上使用虚拟机的人来说是很好的工具。现在听起来有点老土，但如果你能在命令行上做得很好，你会想知道为什么你以前需要一个点击按钮的 GUI 来帮你完成工作。

当我们这样谈论客户端时，我们指的是`libvirt`库的前端，它是一个设计用来使与内核的虚拟化功能交互更容易的 C 工具包。

`virsh`和`virt-install`与`libvirt`通信，而`libvirt`又与内核通信。

# 准备工作

SSH 到您的 Ubuntu VM，然后安装`virtinst`、`libvirt-clients`、`libvirt-bin`和`libvirt-daemon`软件包：

```
$ vagrant ssh ubuntu1804 $ sudo apt update
$ sudo apt install virtinst libvirt-clients libvirt-bin libvirt-daemon -y
```

# 如何做...

首先，我们将使用我们安装的`virt-install`工具创建 VM，然后我们将使用`virsh`对其进行探测。

创建 VM 是简单的步骤；真正麻烦的是维护机器时带来的痛苦。

# virt-install

首先，让我们使用之前下载的 Alpine ISO 来启动和安装虚拟机。

如果您没有从上一节获得 ISO，这是重新下载它的命令：

```
$ wget http://dl-cdn.alpinelinux.org/alpine/v3.8/releases/x86_64/alpine-virt-3.8.1-x86_64.iso
```

这次让我们使用`fallocate`创建一个块设备：

```
$ fallocate -l 2G ex-alpine-2-disk
```

现在，让我们使用一行命令来配置我们的域（域是这里用于机器和其他部分的集体术语）：

```
$ sudo virt-install --name ex-alpine-2 --memory 512 --disk ex-alpine-2-disk --cdrom alpine-virt-3.8.1-x86_64.iso --graphics none --os-variant virtio26
```

我们在这里使用`virtio26`作为 OS 变体，因为没有明确的`alpine`选项。相反，这告诉`virt-install`我们正在安装的操作系统使用的是 2.6 之后的内核，并且支持 VirtIO 设备（用于磁盘、网络等）。这使我们拥有一个正常运行的 VM，这很好。

假设一切顺利，您应该再次看到 Alpine 的引导顺序。

使用`root`用户和空密码登录，然后按照上一节的步骤进行安装（安装到 vda 设备）。

安装完成后，使用*Ctrl* + *]*从控制台断开连接。

# virsh

完全可以像我们之前看到的传统 Unix 风格的命令行上的一系列命令一样使用 Virsh。

但是，使用 Virsh 进行交互也是完全可以接受的，它有自己的模式。

使用以下命令启动 Virsh 终端：

```
$ sudo virsh
Welcome to virsh, the virtualization interactive terminal.

Type: 'help' for help with commands
 'quit' to quit

virsh #
```

现在，我们将与我们刚刚创建的机器进行交互。首先在命令行上列出它：

```
virsh # list
 Id Name State
----------------------------------------------------
 3 ex-alpine-2 running
```

默认情况下，此命令将显示正在运行的域。

如果我们连接到我们的 VM 并连续按*Enter*几次，我们可以与我们的安装进行交互：

```
virsh # console ex-alpine-2 
Connected to domain ex-alpine-2
Escape character is ^]

localhost:~# 
localhost:~# 
localhost:~# 
```

再次使用*Ctrl* + *]*退出 VM。

让我们在我们拥有的基本域上进行构建，首先看看`virt-install`通过`dominfo`给我们的东西：

```
virsh # dominfo ex-alpine-2
Id: 5
Name: ex-alpine-2
UUID: 80361635-25a3-403b-9d15-e292df27908b
OS Type: hvm
State: running
CPU(s): 1
CPU time: 81.7s
Max memory: 524288 KiB
Used memory: 524288 KiB
Persistent: yes
Autostart: disable
Managed save: no
Security model: apparmor
Security DOI: 0
Security label: libvirt-80361635-25a3-403b-9d15-e292df27908b (enforcing)
```

现在这是有趣的部分-我们实际上还没有在安装后重新启动我们的 VM，所以让我们使用`virsh`来发出命令：

```
virsh # destroy ex-alpine-2 
Domain ex-alpine-2 destroyed
virsh # start ex-alpine-2 
Domain ex-alpine-2 started
```

是的，销毁在这里是一个令人困惑的词，但这是因为 VM 的实际状态是短暂的。数据在驱动器上是安全的。实际配置是域的一部分，所以当我们发出`destroy`和`start`命令时，我们实际上并没有删除任何东西。我不喜欢这个术语，但这只是你学会接受的东西。

现在，我们可以再次从`virsh`连接到我们的 VM 控制台（这一部分可能需要一些时间）：

```
virsh # console ex-alpine-2 
Connected to domain ex-alpine-2
Escape character is ^]

Welcome to Alpine Linux 3.8
Kernel 4.14.69-0-virt on an x86_64 (/dev/ttyS0)

localhost login: 
```

而且，随时可以使用*Ctrl* + *]*断开连接。

Virsh 充满了技巧，我最喜欢的是轻松编辑域的配置 XML 的方法。

发出以下`edit`命令：

```
virsh # edit ex-alpine-2 

Select an editor. To change later, run 'select-editor'.
 1\. /bin/nano <---- easiest
 2\. /usr/bin/vim.basic
 3\. /usr/bin/vim.tiny
 4\. /bin/ed

Choose 1-4 [1]: 2
```

您应该进入您选择的编辑器，并看到您的 VM 的配置文件：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/e8f22a38-a1a7-47c6-a008-a97db952c3d2.png)

这在某种程度上是另一种做事情的方式。如果您习惯直接编辑文件，这可能比使用命令行更适合您（根据我的经验，有一些选项是不可能不深入研究这个文件就无法完成的）。

在离开`virsh`世界之前，还有一些事情，首先是`version`命令：

```
virsh # version
Compiled against library: libvirt 4.0.0
Using library: libvirt 4.0.0
Using API: QEMU 4.0.0
Running hypervisor: QEMU 2.11.1
```

这是一个很好的方法来确定您连接到的 hypervisor 版本，`libvirt`库版本和 API。

您还可以检查 vCPU 计数：

```
virsh # vcpucount ex-alpine-2 
maximum config 1
maximum live 1
current config 1
current live 1
```

然后，您可以调整数字：

```
virsh # setvcpus ex-alpine-2 2 --maximum --config --hotpluggable
```

我们还从`dominfo`中知道我们给了我们的 VM 512 MiB 的内存，所以让我们降低它以腾出其他 VM 的空间：

```
virsh # setmem ex-alpine-2 --size 400MiB
```

我们也可以提高它，但不能超过 VM 已经设置的最大内存（至少在这种状态下）。

# 它是如何工作的...

正如之前所暗示的，当你使用`virt-install`创建一个虚拟机时，实际上你正在编写一个包含虚拟机外观和行为的初始 XML 文件。

这个文件实际上存在于`/etc/libvirt/qemu/ex-alpine-2.xml`，可以像系统上的任何其他文件一样读取（`virsh`只是让它更容易，就像`systemctl cat`一样）。

当我们使用诸如`virt-install`、`virt-viewer`或任何`virt-*`套件时，我们可以省去很多打字和文件复制。你可以编写一个运行簿，只需几条命令就可以重新创建一个环境。然后，Virsh 存在于查询你的设置并获取有关你已经启动的解决方案的一些基本信息。

我们可以使用`virsh autostart`之类的东西在启动时启动一个虚拟机，如下所示：

```
virsh # autostart ex-alpine-2 
Domain ex-alpine-2 marked as autostarted
```

通过这样做，我们使位于`/usr/lib/libvirt/libvirt-guests.sh`的脚本能够在启动时启动虚拟机。

这个脚本又被一个`systemd`单元触发：

```
$ systemctl cat libvirt-guests
# /lib/systemd/system/libvirt-guests.service
[Unit]
Description=Suspend/Resume Running libvirt Guests
Wants=libvirtd.service
Requires=virt-guest-shutdown.target
After=network.target
After=time-sync.target
After=libvirtd.service
After=virt-guest-shutdown.target
Documentation=man:libvirtd(8)
Documentation=https://libvirt.org

[Service]
EnvironmentFile=-/etc/default/libvirt-guests
# Hack just call traditional service until we factor
# out the code
ExecStart=/usr/lib/libvirt/libvirt-guests.sh start
ExecStop=/usr/lib/libvirt/libvirt-guests.sh stop
Type=oneshot
RemainAfterExit=yes
StandardOutput=journal+console
TimeoutStopSec=0

[Install]
WantedBy=multi-user.target
```

# 还有更多...

看看`virt`套件的其他部分：

```
$ virt-
virt-admin virt-convert virt-install virt-pki-validate virt-viewer virt-xml-validate 
virt-clone virt-host-validate virt-login-shell virt-sanlock-cleanup virt-xml
```

每件事都有一个工具，而每个工具都有一个工具。

当你有几分钟的时候，看一下`virt-clone`和`virt-viewer` - 它们是我最喜欢的。

# 比较本地安装、容器和虚拟机的优势

我们将看一下本地安装、容器和虚拟机的一些明显的优缺点，以及在何时使用其中一种可能是理想的。

# 准备工作

如果你想在本节中跟着做，确保你已经安装并设置好了 Docker，并且启用了 QEMU 工具（都是从前面的部分）。

SSH 到你的 Ubuntu 虚拟机：

```
$ vagrant ssh ubuntu1804
```

现在，你可能想在我们的 Vagrant VM 中安装 Vagrant（用于接下来的 VM 示例）：

```
$ sudo apt install vagrant -y
```

一旦你把自己添加到适当的组中，就退出你的 VirtualBox 虚拟机，然后再进入这一部分。

# 如何做...

从命令行开始，让我们启动一个 Nginx 实例。

你可以用三种方式之一来解决这个问题。

1.  使用`apt`从默认存储库安装 Nginx

1.  使用 Docker 从 Docker Hub 拉取官方 Nginx 镜像

1.  设置一个虚拟机并在其中安装 Nginx，使用主机的端口转发

这些可以以以下方式完成：

```
$ sudo apt install nginx -y $ sudo docker run -p80 -d --rm nginx $ cat << HERE > Vagrantfile
# -*- mode: ruby -*-
# vi: set ft=ruby :

\$provisionScript = <<-SCRIPT
apt install nginx -y
SCRIPT

Vagrant.configure("2") do |config|

 config.vm.define "debian8" do |debian8|
 debian8.vm.box = "debian/jessie64"
 debian8.vm.network "forwarded_port", guest: 80, host: 8080
 debian8.vm.provision "shell",
 inline: \$provisionScript

 debian8.vm.provider "libvirt" do |lv|
 lv.driver = "qemu"
 lv.memory = 256
 lv.cpus = 1

 end

 end

end
HERE
$ sudo vagrant up
```

我在这里使用了一个`Vagrantfile`，因为这是我们在本书中一直使用的，但我们还可以以其他方式启动一个虚拟机。如果在你的虚拟机中已经运行了其他虚拟机（来自上一节），这也可能行不通，而且可能太慢而根本无法工作。

这些不同方法的优缺点是什么？

# 本地 Nginx 安装

首先是本地安装。这是最简单的方法，因为我们只是安装了默认 Ubuntu 存储库中 readily 可用的软件。

优点：

+   它以 Ubuntu 的方式进行配置（即一些 Ubuntu 默认设置，比如启动脚本），并且几乎可以保证与你的设置兼容

+   它安装非常快

+   只要存储库保持最新，它也会保持最新，从同一位置安装的其他软件应该以本地方式与它交互，避免手动指定依赖关系之类的事情

+   这显然会很快，并且能够利用你的主机提供的任何东西

+   你通常可以期待在官方论坛上或者如果你与 Ubuntu 有特定的支持合同（他们可能会假设你已经从他们的默认存储库安装了东西），在问题上得到合理的帮助。

缺点：

+   你不能轻松地安装多个版本的 Nginx；虽然这是可能的，但需要更多的工作

+   你不能轻易删除所有的配置和文件，否则可能会留下一些东西（导致重新安装很麻烦）

+   Nginx 与系统的其他部分没有那么分离

# Docker Nginx 安装

接下来，我们在一个 Nginx Docker 容器中设置一个端口转发。

这里的优点如下：

+   启动你的实例很快

+   可以启动多个实例，而不必担心交叉污染

+   这些进程与主机机器相对分离（尽管可能会发生漏洞）

+   容器可以在瞬间被拆除和重新部署，而不必担心残留的文件可能会给您带来问题

一些消极的方面如下：

+   您必须先下载容器

+   映射端口（未明确定义时）会导致随机 NAT'd 端口，而不是默认的端口`80`

+   您可能最终得到的容器中的操作系统与主机操作系统不同（这可能会导致内部安全合规性问题）

+   现在，您在系统上运行的软件实际上有了两个真实来源

+   容器内的配置不一致-如果您修改了容器，必须明确保存容器的状态

+   调试变得稍微更加麻烦

+   如果您需要进行诸如服务文件测试之类的操作，通常没有 init 系统

# 虚拟机 Nginx 安装

这里有一个小考虑因素，那就是我们在虚拟机内运行了一个虚拟机，但这突显了一些问题。

一些积极的方面是：

+   它几乎完全隔离了操作系统（除了一些像熔断这样的漏洞）

+   对于虚拟机的资源分配有很好的控制

+   随心所欲地拆除和启动

+   如果您需要根据软件要求进行硬件更改，虚拟机是唯一容易实现这一点的方法

一些消极的方面是：

+   虚拟机可能比容器慢，而且您必须考虑很多因素（例如，如果您的服务器已经是虚拟机）

+   为了一个程序（在这个例子中），您正在运行一个完全独立的操作系统和内核

+   由于需要用于其他操作系统的磁盘空间，虚拟机通常占用更多空间

+   除了主机之外，您还必须管理另一台机器的更新

+   您需要密切关注资源隔离，这可能意味着额外的监控（特别是如果您做一些诸如特定 CPU 固定的事情）

# 它的工作原理...

这并不是要劝阻您选择任何特定的软件安装方法，选择一种方法而不是另一种方法有很多原因。

我曾在主要使用虚拟机的环境中工作，不想使用虚拟机内的虚拟机，我通过使用容器而不是虚拟机来测试软件。

同样，正如之前提到的，我曾通过在 Docker 容器内进行硬件配置更改而搞砸了主机安装，导致主机系统永远无法再次启动。

根据经验，您很快就会厌倦管理不同的安装方法，并且在某些系统中，有些东西是从默认存储库安装的，有些是从 Snaps 安装的，有些是从 Flatpak 安装的，有些是利用 Docker 容器，这些都变得非常陈旧，非常快。

在这个例子中，我很难不选择在 Web 服务器上使用 Docker，特别是因为它提供的管理功能。我可以轻松安装多个 Nginx 实例，并且相对有信心它们永远不会知道另一个实例的存在，而无需以奇特而奇妙的方式隔离配置文件。

这从来都不是简单的。

另外，值得记住的是，因为我们在虚拟机中使用了 Vagrant 和`libvirt`，我们可以用 Virsh 看到我们的虚拟机：

```
virsh # list
 Id    Name                           State
----------------------------------------------------
 22    vagrant_debian8                running

virsh # 
```

我们也可以用 docker 看到我们的容器：

```
$ sudo docker ps
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS                   NAMES
4f610d2a6bef        nginx               "nginx -g 'daemon of..."   3 hours ago         Up 3 hours          0.0.0.0:32768->80/tcp   gallant_curie
```

# 虚拟化选项的简要比较（VMware、proxmox 等）

在虚拟化方面，每个人都有自己喜欢的解决方案。

到目前为止，您现在应该知道两个选项，即 VirtualBox（我们在本书中一直在使用）和 QEMU/KVM。但是，这并不是您可用的唯一选项，如果您想在服务器上运行虚拟机，就像容器不仅限于 Docker 一样。

在这里，我们将介绍一些其他选项，其中大部分您可能在职业生涯中的某个时候都会遇到：

+   VMware ESXi

+   Proxmox

+   OpenStack

# 准备就绪

打开您选择的网络浏览器。

# 如何做到…

我们将看一些可供我们选择的选项，每个选项都有一个专门的部分。

# VMware ESXi

VMware 的各种产品之一（现在是戴尔的子公司）ESXi 不是 Linux；它是一个专用的“操作系统”，位于硬件之上，虚拟机可以配置在 ESXi 之上。

这是一种许可产品，不是开源的，但它与 VMware 管理产品很好地配合（例如，您可以轻松地在一个集群中拥有多个由集中式服务器管理的虚拟机）。

就优点而言，VMware ESXi 为您提供以下内容：

+   专用的虚拟化程序，专门设计用于执行一项任务，并且执行得很好

+   易于设置-点击几下，您就可以安装好一个盒子

+   包括一系列服务器在内的广泛硬件支持

+   易于使用的软件和易于理解的菜单（在本作者看来）

就缺点而言，您可能会考虑以下几点：

+   VMware ESXi 不是开源的；这可能会影响您的决定

+   作为专用的虚拟机服务器，ESXi 不能做任何其他值得注意的事情。

+   作为一种产品，它可能会变得昂贵，虽然可以购买支持并签署协议，但您可能会选择完全基于预算的免费产品

VMware 可以从[`www.vmware.com/products/esxi-and-esx.html`](https://www.vmware.com/products/esxi-and-esx.html)获得：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/26a21fbb-86bf-4db1-b667-6f27cab36ac1.png)

就个人而言，我承认曾多次使用 VMware 产品，用于各种工作，它确实如广告中所说的那样，没有太多华丽的东西。在适当的情况下，它可以优雅地处理诸如虚拟机故障转移之类的事情，而且它非常简单，任何人都可以放在控制台前轻松地进行导航（尽管我不是他们首次尝试基于 Web 的 GUI 的铁杆粉丝）。

# Proxmox 虚拟环境

另一个专用的虚拟化程序安装，Proxmox（VE），是一个基于 Linux（具体来说是 Debian）的操作系统，同样具有广泛的硬件支持和友好的 GUI，让您轻松上手。

这个开源解决方案非常适合家庭实验室环境，并且可以很好地扩展到大型安装，这意味着您可以为开发人员和生产部署部署相同的解决方案。

就优点而言，您可能会考虑以下几点：

+   它是开源的，这可能再次影响您的决定

+   它是免费的（就像啤酒一样），并提供付费支持和培训的选项

+   它基于已知和得到良好支持的技术，如 KVM 和 QEMU

+   它支持容器以及虚拟机

就负面方面而言，您可能会考虑以下几点：

+   安装基础和事实上它并不像 VMware ESXi 和其他产品那样出名（尽管这也可能对您产生积极的影响）

+   作为专用的虚拟化安装，您的 Proxmox 服务器不会做任何其他重要的事情（如 ESXi）

Proxmox Virtual Environment 可以在[`www.proxmox.com/en/downloads`](https://www.proxmox.com/en/downloads)获得：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/6bce4ecb-af3b-4130-a14c-7aeaa5eebe6c.png)

Proxmox 虚拟化主页

同样，根据个人经验，我相对轻松地设置了三个节点的 Proxmox 集群，并实现了自动故障转移，我与使用 Proxmox 的每个人交谈时似乎都很欣赏它在紧要关头是一个多么好的解决方案，同时又知道在需要时它可以进一步扩展。

# OpenStack

OpenStack 是新生力量，是一系列技术的集合，当它们组合在一起时，可以与任何更大的虚拟化环境提供者相媲美。

它可以成为虚拟机主机、容器主机、文件存储提供者、块存储提供者，并且它具有快速的开发周期，不断推出新功能。

与此列表上的其他两种解决方案不同，OpenStack 是赋予几种不同软件组件的名称。

对于优点，考虑以下几点：

+   OpenStack 有一个热情洋溢且专注的社区支持

+   这些组件是开源的，由全球各地的人共同开发

+   许多公司提供 OpenStack 解决方案并提供不同级别的支持

+   如果你对 OpenStack 很了解，你未来五十年不会失业（推测）

在缺点方面，我可能会因此收到一些恶意邮件：

+   OpenStack 有一个快速的开发周期，这意味着如果你不及时更新就会被落下

+   OpenStack 可以安装在你想要的任何 Linux 发行版上，这意味着在许多情况下你也必须管理底层操作系统

+   在我看到 OpenStack 被使用的地方，几乎需要一个专门的 OpenStack 团队来保持管理的最新状态

+   要以可用的方式设置它并不容易，尽管开发环境确实存在

+   有多种关于什么是一个好的 OpenStack 部署的观点

+   当你遇到一个被忽视的 OpenStack 解决方案时，这真是一件让人头疼的事

如果你想尝试 OpenStack（我鼓励你这样做），可以在这里找到入门指南：[`wiki.openstack.org/wiki/Getting_Started`](https://wiki.openstack.org/wiki/Getting_Started)。

还有一个起始页面，包括指向 devstack 开发环境的链接：

![](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-adm-cb/img/9e96ca1d-b327-4cb8-95b9-2dae73c252ec.png)

个人想法-我认识一些非常聪明的人，他们热爱 OpenStack 并对其赞不绝口，但这是一个需要大量关注和专注的领域。

# 它是如何工作的...

有多种做同样事情的方式。这对大多数经验来说都是真的，尤其是在 Unix 和类 Unix（Linux）世界中更是如此。

在这里，我们有三个很好的软件和解决方案的例子，它们允许你以大多数用户友好的方式控制虚拟机部署，尽管你可能认为所有这些解决方案都比你需要的复杂得多。

我在这里提到它们是因为知道这些选择是存在的很好，并且即使你开始时通过在 Ubuntu 安装上本地安装虚拟机（使用 VirtualBox 或 KVM 和 Libvirt），你可能希望将来扩展到更宏伟的东西。

另一个要考虑的选择是公共云服务，虽然我稍后会详细讨论这些，但值得注意的是有几家提供商可以帮你摆脱管理底层软件的麻烦，让你只需安装和创建虚拟机。

如果你没有硬件或资源，甚至没有预算，你可以按小时使用公共云服务。

看看 Scaleway，Digital Ocean 和 AWS（特别是他们的 Lightsail 产品）。

# 总结-容器和虚拟化

短短几年前，Linux 社区出现了一个运动。容器突然无处不在，并对在一个瞬息万变的世界中可能发生的事情做出了奇妙的承诺。容器将解决你在软件方面所面临的每一个问题，它们将解决你曾经遇到的每一个安全问题，并且它们将在夜晚哄你入睡并喂养你的宠物。

我们现在知道，虽然容器很棒，它们确实是许多情况下的一个很好的解决方案，但它们并不是万能的。仍然会有一些情况，软件在裸机上运行会更好，或者虚拟机比容器更合理，你知道吗？那没关系。

如果你想的话，不要让我劝阻你尝试在容器中运行你自己的项目-这绝对是一个很好的学习经验，你可能会发现这实际上是提升和转移你的安装的最佳方式，但不要得意忘形。

虚拟机始终会有它们的位置，虽然很多测试、部署和开发环境已经转向无服务器容器部署的方式，但一个良好的本地虚拟机仍然可以提供一个不错的工作方式，特别是如果你想了解某些软件如何与整个操作系统交互（无论是一个单片应用程序，还是许多组成一个程序的小应用程序）。

归根结底，这就像我们世界上的大多数事情一样。仅仅因为你可以用一种方式做某事，并不一定意味着这是最好的方式；同样，这并不意味着你提出的解决方案不好，它可能完全适合你的需求——只是了解所有选项会很方便。

我真诚地希望我能在这本书中进行更多的探索，并深入了解管理和维护虚拟机和容器的不同方式和方法，但这不是一本关于这些东西的书——它应该是对 Linux 管理世界的一个概览。

还记得圣战吗？我也遇到过一些人反对容器的概念，认为它们是各种各样的“困难”和“毫无意义”的解决方案。如果你站在这一边并为之奋斗，要做好失败的准备，因为目前容器支持者的军队比反对者大得多。
