# Linux 系统编程实用手册（四）

> 原文：[`zh.annas-archive.org/md5/9713B9F84CB12A4F8624F3E68B0D4320`](https://zh.annas-archive.org/md5/9713B9F84CB12A4F8624F3E68B0D4320)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：进程凭证

在本章和下一章中，读者将学习有关进程凭证和能力的概念和实践。除了在 Linux 应用程序开发中具有实际重要性之外，本章本质上更深入地探讨了一个经常被忽视但极其关键的方面：安全性。本章和下一章的内容非常相关。

我们将这一关键领域的覆盖分为两个主要部分，每个部分都是本书的一个章节：

+   在本章中，详细讨论了传统风格的 Unix 权限模型，并展示了在不需要根密码的情况下以 root 权限运行程序的技术。

+   在第八章 *进程能力*中，讨论了现代方法，POSIX 能力模型的一些细节。

我们将尝试清楚地向读者表明，虽然重要的是了解传统机制及其运作方式，但了解现代安全性方法也同样重要。无论如何看待它，安全性都是非常重要的，尤其是在当今。Linux 在各种设备上运行——从微小的物联网和嵌入式设备到移动设备、台式机、服务器和超级计算平台——使安全性成为所有利益相关者的关键关注点。因此，在开发软件时应使用现代能力方法。

在本章中，我们将广泛介绍传统的 Unix 权限模型，它究竟是什么，以及它是如何提供安全性和稳健性的。一点黑客攻击总是有趣的！

您将了解以下内容：

+   Unix 权限模型的运行

+   真实和有效的身份证

+   强大的系统调用来查询和设置进程凭证

+   黑客攻击（一点点）

+   `sudo(8)`实际上是如何工作的

+   保存的身份证

+   关于安全性的重要思考

在这个过程中，几个示例允许您以实际操作的方式尝试概念，以便真正理解它们。

# 传统的 Unix 权限模型

从 1970 年初开始，Unix 操作系统通常具有一个优雅而强大的系统，用于管理系统上共享对象的安全性。这些对象包括文件和目录——也许是最常考虑的对象。文件、目录和符号链接是文件系统对象；还有其他几个，包括内存对象（任务、管道、共享内存区域、消息队列、信号量、密钥、套接字）和伪文件系统（proc、sysfs、debugfs、cgroupfs 等）及其对象。重点是所有这些对象都以某种方式共享，因此它们需要某种保护机制，以防止滥用；这种机制称为 Unix 权限模型。

您可能不希望其他人读取、写入和删除您的文件；Unix 权限模型使这在各种粒度级别上成为可能；再次，以文件和目录作为常见目标，您可以在目录级别设置权限，或者在该目录中的每个文件（和目录）上设置权限。

为了明确这一点，让我们考虑一个典型的共享对象——磁盘上的文件。让我们创建一个名为`myfile`的文件：

```
$ cat > myfile
This is my file.
It has a few lines of not
terribly exciting content.

A blank line too! WOW.

You get it...
Ok fine, a useful line: we shall keep this file in the book's git repo.
Bye.
$ ls -l myfile
-rw-rw-r-- 1 seawolf seawolf 186 Feb 17 13:15 myfile
$
```

所有显示的输出都来自 Ubuntu 17.10 x86_64 Linux 系统；用户以`seawolf`登录。

# 用户级别的权限

之前我们对之前的`myfile`文件进行了快速的`ls -l`；第一个字符`-`当然显示它是一个常规文件；接下来的九个字符`rw-rw-r--`是文件权限。如果您记得，这些被分成三组——**所有者**（**U**）、**组**（**G**）和**其他人**（**O**）（或公共）权限，每个组包含三个权限位：**r**、**w**和**x**（读取、写入和执行访问）。这张表总结了这些信息：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/22f3bf7d-102d-4c63-a232-e52f883ff328.png)

解释一下，我们可以看到文件的所有者可以读取和写入它，组成员也可以，但其他人（既不是所有者也不属于文件所属的组）只能对`myfile`执行读操作。这就是安全性！

因此，让我们举个例子：我们尝试使用`echo`命令写入文件`myfile`：

```
echo "I can append this string" >> myfile
```

它会起作用吗？嗯，答案是，这取决于：如果文件的所有者或组成员（在本例中是 seawolf）正在运行 echo(1)进程，那么访问类别将相应地设置为 U 或 G，是的，它将成功（因为 U|G 对文件具有写访问权限）。但是，如果进程的访问类别是其他或公共，它将失败。

# Unix 权限模型是如何工作的

关于这个主题的一个非常重要的理解点是：正在处理的共享对象（这里是`myfile`文件）和正在对对象执行某些访问（rwx）的进程（这里是 echo 进程）都很重要。更正确地说，它们的权限属性很重要。下一次讨论将有助于澄清这一点。

让我们一步一步地考虑这个问题：

1.  使用登录名`seawolf`的用户登录到系统。

1.  成功后，系统会生成一个 shell；用户现在处于 shell 提示符下。（在这里，我们考虑的是登录到**命令行界面**（CLI）控制台的传统情况，而不是 GUI 环境。）

每个用户都有一条记录；它存储在`/etc/passwd`文件中。让我们为这个用户`grep`文件：

```
$ grep seawolf /etc/passwd
seawolf:x:1000:1000:Seawolf,,,:/home/seawolf:/bin/bash
$ 
```

通常，只需这样做：`grep $LOGNAME /etc/passwd`

`passwd`条目是一个有七列的行，它们是以冒号分隔的字段；它们如下：

```
username:<passwd>:UID:GID:descriptive_name:home_dir:program
```

有几个字段需要解释一下：

+   第二个字段`<passwd>`在现代 Linux 系统上总是显示为`x`；这是为了安全。即使加密密码也不会显示出来（黑客很可能可以通过暴力算法破解它；它在一个只有 root 用户才能访问的文件`/etc/shadow`中）。

+   第三和第四个字段是用户的**用户标识符**（UID）和**组标识符**（GID）。

+   第七个字段是成功登录时要运行的程序；通常是 shell（如前所述），但也可以是其他任何东西。

要以编程方式查询`/etc/passwd`，请查看`getpwnam_r`，`getpwent_r`库层 API。

最后一点是关键的：系统为登录的用户生成一个 shell。shell 是 CLI 环境中人类用户和系统之间的**用户界面**（UI）。毕竟，它是一个进程；在 Linux 上，bash 通常是我们使用的 shell。当您登录时收到的 shell 称为您的登录 shell。这很重要，因为它的特权决定了它启动的所有进程的特权——实际上，您在系统上工作时拥有的特权是从您的登录 shell 派生的。

让我们查找我们的 shell 进程：

```
$ ps
  PID  TTY          TIME  CMD
13833 pts/5     00:00:00  bash
30500 pts/5     00:00:00  ps
$ 
```

这就是了；我们的 bash 进程有一个**进程标识符**（PID——一个唯一的整数标识进程）为 13833。现在，进程还有其他与之关联的属性；对于我们当前的目的来说，关键的是进程**用户标识符**（UID）和进程**组标识符**（GID）。

可以查找进程的 UID、GID 值吗？让我们尝试使用`id(1)`命令：

```
$ id
uid=1000(seawolf) gid=1000(seawolf) groups=1000(seawolf),4(adm),24(cdrom),27(sudo),[...]
$ 
```

`id(1)`命令向我们显示，进程 UID 是 1000，进程 GID 也恰好是 1000。（用户名是`seawolf`，这个用户属于几个组。）在前面的例子中，我们已经以用户`seawolf`的身份登录；`id`命令反映了这一事实。请注意，我们现在从这个 shell 运行的每个进程都将继承这个用户帐户的特权，也就是说，它将以与登录 shell 相同的 UID 和 GID 运行！

您可能会合理地问：进程的 UID 和 GID 值是从哪里获取的？嗯，想想看：我们以用户`seawolf`的身份登录，这个帐户的`/etc/passwd`条目的第三个和第四个字段是进程 UID 和 GID 的来源。

因此，每次我们从这个 shell 运行一个进程，该进程将以 UID 1000 和 GID 1000 运行。

我们想要了解操作系统如何准确地检查我们是否可以执行以下操作：

```
echo "I can append this string" >> myfile
```

因此，这里的关键问题是：在运行时，当前的 echo 进程尝试写入`myfile`文件时，内核如何确定写入访问是否被允许。为了做到这一点，操作系统必须确定以下内容：

+   所讨论的文件的所有权和组成员资格是什么？

+   进程尝试访问的访问类别是什么（例如，是 U|G|O）？

+   对于该访问类别，权限掩码是否允许访问？

回答第一个问题：文件的所有权和组成员信息（以及关于文件的更多信息）作为文件系统的关键数据结构的属性进行传递——**信息节点**（**inode**）。inode 数据结构是一个每个文件的结构，并且存在于内核中（文件系统；当文件首次被访问时，它被读入内存）。用户空间当然可以通过系统调用访问这些信息。因此，文件所有者 ID 存储在 inode 中——让我们称之为`file_UID`。类似地，`file_GID`也将存在于 inode 对象中。

对于好奇的读者：您可以使用强大的`stat(2)`系统调用自己查询任何文件对象的 inode。（像往常一样，查阅它的手册页）。事实上，我们在[附录 A](https://www.packtpub.com/sites/default/files/downloads/File_IO_Essentials.pdf)中使用了`stat(2)`，*文件 I/O 基础*。

# 确定访问类别

先前提出的第二个问题：它将以哪种访问类别运行？这是很重要的问题。

访问类别将是**所有者**（**U**）、**组**（**G**）或**其他**（**O**）中的一个；它们是互斥的。操作系统用于确定访问类别的算法大致如下：

```
if process_UID == file_UID
then
     access_category = U
else if process_GID == file_GID
then
     access_category = G
else
     access_category = O
fi
```

实际上，情况要复杂一些：一个进程可以同时属于多个组。因此，在检查权限时，内核会检查所有组；如果进程属于其中任何一个组，访问类别就设置为 G。

最后，对于该访问类别，检查权限掩码（rwx）；如果相关位被设置，进程将被允许进行操作；如果没有，就不会被允许。

让我们看看以下命令：

```
$ ls -l myfile
-rw-rw-r-- 1 seawolf seawolf 186 Feb 17 13:15 myfile
$ 
```

另一种澄清的方法——`stat(1)`命令（当然是`stat(2)`系统调用的包装器）显示了文件`myfile`的 inode 内容，就像这样：

```
$ stat myfile 
  File: myfile
  Size: 186           Blocks: 8          IO Block: 4096   regular file
Device: 801h/2049d    Inode: 1182119     Links: 1
Access: (0664/-rw-rw-r--)  Uid: ( 1000/ seawolf)   Gid: ( 1000/ seawolf)
Access: 2018-02-17 13:15:52.818556856 +0530
Modify: 2018-02-17 13:15:52.818556856 +0530
Change: 2018-02-17 13:15:52.974558288 +0530
 Birth: -
$ 
```

显然，我们正在强调`file_UID == 1000`和`file_GID == 1000`。

在我们的 echo 示例中，我们发现，根据谁登录，组成员资格和文件权限，可以出现一些情景。

因此，为了正确理解这一点，让我们设想一些情景（从现在开始，我们将只是将进程 UID 称为`UID`，将进程 GID 值称为`GID`，而不是`process_UID|GID`）：

+   **用户以 seawolf 身份登录**：[UID 1000，GID 1000]

+   **用户以 mewolf 身份登录**：[UID 2000，GID 1000]

+   **用户以 cato 身份登录**：[UID 3000，GID 3000]

+   **用户以 groupy 身份登录**：[UID 4000，GID 3000，GID 2000，GID 1000]

一旦登录，用户尝试执行以下操作：

```
echo "I can append this string" >> <path/to/>myfile
```

发生了什么？哪个会起作用（权限允许），哪个不会？通过先前的算法运行先前的情景，确定关键的访问类别，你会看到；以下表总结了这些情况：

| **案例＃** | **登录为** | **（进程）UID** | **（进程）GID** | **访问类别** **（U&#124;G&#124;O）** | **Perm** **bitmask** | **允许写入？** |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | seawolf | 1000 | 1000 | U | `r**w**-` | Y |
| 2 | mewolf | 2000 | 1000 | G | `r**w**-` | Y |
| 3 | cato | 3000 | 3000 | O | `r**-**-` | N |
| 4 | groupy | 4000 | 4000,3000, 2000,1000 | G | `r**w**-` | Y |

前面的描述仍然有点太简单了，但是作为一个很好的起点。实际上，在幕后发生了更多的事情；接下来的部分将阐明这一点。

在此之前，我们将稍微偏离一下：`chmod(1)`命令（当然会变成`chmod(2)`系统调用）用于设置对象的权限。因此，如果我们这样做：`chmod g-w myfile`来从组类别中删除写权限，那么之前的表将会改变（获得 G 访问权限的行现在将不允许写入）。

这里有一个有趣的观察：渴望获得 root 访问权限的进程是那些`UID = 0`的进程；这是一个特殊的值！

接下来，严谨地说，echo 命令实际上可以以两种不同的方式运行：一种是作为一个进程，当二进制可执行文件（通常是`/bin/echo`）运行时，另一种是作为一个内置的 shell 命令；换句话说，没有新的进程，shell 进程本身——通常是`bash`——运行它。

# 真实和有效 ID

我们从前面的部分了解到，正在处理的共享对象（这里是文件 myfile）和执行某些访问操作的进程（这里是 echo 进程）在权限方面都很重要。

让我们更深入地了解与权限模型相关的进程属性。到目前为止，我们已经了解到每个进程都与一个 UID 和一个 GID 相关联，从而允许内核运行其内部算法，并确定是否应该允许对资源（或对象）的访问。

如果我们深入研究，我们会发现每个进程 UID 实际上不是一个单一的整数值，而是两个值：

+   **真实用户 ID**（**RUID**）

+   **有效用户 ID**（**EUID**）

同样，组信息不是一个整数 GID 值，而是两个整数：

+   **真实组 ID**（**RGID**）

+   **有效组 ID**（**EGID**）

因此，关于特权，每个进程都有与之关联的四个整数值：

{RUID, EUID, RGID, EGID}；这些被称为**进程凭证**。

严格来说，进程凭证还包括其他几个进程属性——进程 PID、PPID、PGID、会话 ID 以及真实和有效用户和组 ID。在我们的讨论中，为了清晰起见，我们将它们的含义限制在最后一个——真实和有效用户和组 ID。

但它们究竟是什么意思呢？

每个进程都必须在某人的所有权和组成员身份下运行；这个某人当然是登录的用户和组 ID。

真实 ID 是与登录用户关联的原始值；实际上，它们只是来自该用户的`/etc/passwd`记录的 UID:GID 对。回想一下，`id(1)`命令恰好显示了这些信息：

```
$ id
uid=1000(seawolf) gid=1000(seawolf) groups=1000(seawolf),4(adm), [...]
$ 
```

显示的`uid`和`gid`值是从`/etc/passwd`记录中的 seawolf 获取的。实际上，`uid/gid`值分别成为运行进程的 RUID/RGID 值！

真实数字反映了你最初的身份——以整数标识符的登录帐户信息。另一种说法是：真实数字反映了谁拥有该进程。

那么有效值呢？

有效值是为了通知操作系统，当前进程正在以什么样的特权（用户和组）运行。以下是一些关键点：

+   在执行权限检查时，操作系统使用进程的有效值，而不是真实（原始）值。

+   `EUID = 0`是操作系统实际检查的内容，以确定进程是否具有 root 特权。

默认情况下如下：

+   EUID = RUID

+   EGID = RGID

这意味着，对于前面的例子，以下是正确的：

```
{RUID, EUID, RGID, EGID} = {1000, 1000, 1000, 1000}
```

是的。这引发了一个问题（你不觉得吗？）：如果真实和有效 ID 是相同的，那么为什么我们需要四个数字呢？两个就够了，对吧？

嗯，事实是：它们通常（默认情况下）是相同的，但它们可以改变。让我们看看这是如何发生的。

再次强调一下：在 Linux 上，文件系统操作的权限检查是基于另一个进程凭证-文件系统 UID（或 fsuid；类似地，fsgid）。然而，总是情况是 fsuid/fsgid 对遮蔽了 EUID/EGID 对的凭证-从而有效地使它们相同。这就是为什么在我们的讨论中我们忽略`fs[u|g]id`并专注于通常的真实和有效的用户和组 ID。

在那之前，想想这种情况：一个用户登录并在 shell 上；他们有什么特权？好吧，只需运行`id(1)`程序；输出将显示 UID 和 GID，我们现在知道实际上是{RUID，EUID}和{RGID，EGID}对，具有相同的值。

为了更容易阅读的例子，让我们随便将 GID 值从 1000 更改为 2000。所以，现在，如果值是 UID=1000 和 GID=2000，用户现在运行，我们应该说，vi 编辑器，现在情况是这样的，参考给定的表，进程凭证 - 正常情况：

| **进程凭证** **/ 进程** | **RUID** | **EUID** | **RGID** | **EGID** |
| --- | --- | --- | --- | --- |
| bash | 1000 | 1000 | 2000 | 2000 |
| vi | 1000 | 1000 | 2000 | 2000 |

# 一个谜题-普通用户如何更改他们的密码？

假设你以`seawolf`登录。出于安全原因，你想要将你的弱密码（`hello123`，哎呀！）更新为一个强密码。我们知道密码存储在`/etc/passwd`文件中。好吧，我们也知道在现代 Unix 系统（包括 Linux）中，为了更好的安全性，密码是*shadowed*：实际上存储在一个名为`/etc/shadow`的文件中。让我们来看看：

```
$ ls -l /etc/shadow
-rw-r----- 1 root shadow 891 Jun  1  2017 /etc/shadow
$ 
```

（请记住，我们在 Ubuntu 17.10 x86_64 系统上；我们经常指出这一点，因为在不同的发行版上，确切的输出可能会有所不同，如果安装了诸如 SELinux 之类的内核安全机制。）

正如上面所强调的，你可以看到文件所有者是 root，组成员是 shadow，UGO 的权限掩码为`[rw-][r--][---]`。这意味着以下内容：

+   所有者（root）可以执行读/写操作

+   组（shadow）可以执行只读操作

+   其他人无法对文件进行任何操作

你可能也知道，你用来更改密码的实用程序叫做`passwd(1)`（当然，它是一个二进制可执行程序，并且不应与`/etc/passwd(5)`数据库混淆）。

所以，想一想，我们有一个谜题：要更改你的密码，你需要对`/etc/shadow`有写访问权限，但是，显然，只有 root 有对`/etc/shadow`的写访问权限。那么，它是如何工作的呢？（我们知道它是如何工作的。你以普通用户身份登录，而不是 root。你可以使用`passwd(1)`实用程序来更改你的密码-试一试看。）所以，这是一个很好的问题。

线索就在二进制可执行实用程序本身-`passwd`。让我们来看看；首先，磁盘上的实用程序在哪里？参考以下代码：

```
$ which passwd
/usr/bin/passwd
$ 
```

让我们深入挖掘-引用前面的命令并进行长列表：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/c5b6b6b0-6a8f-4d00-a131-8fc186010ed5.png)

你能发现任何异常吗？

这是所有者执行位：它不是你可能期望的`x`，而是一个`s`！（实际上，这就是在前面的长列表中可执行文件名字的漂亮红色背后的原因。）

这是一个特殊的权限位：对于一个二进制可执行文件，当所有者的执行位中有一个`s`时，它被称为 setuid 二进制文件。这意味着每当执行 setuid 程序时，生成的进程的**有效用户 ID**（**EUID**）会改变（从默认值：原始 RUID 值）变为等于二进制可执行文件的所有者；在前面的例子中，EUID 将变为 root（因为`/usr/bin/passwd`文件的所有者是 root）。

现在，我们根据手头的新信息重新绘制上一个表（进程凭证-正常情况），关于 setuid passwd 可执行文件：

| **进程凭证** **/ 进程** | **RUID** | **EUID** | **RGID** | **EGID** |
| --- | --- | --- | --- | --- |
| bash | 1000 | 1000 | 2000 | 2000 |
| vi | 1000 | 1000 | 2000 | 2000 |
| /usr/bin/passwd | 1000 | 0 | 2000 | 2000 |

表：进程凭据 - setuid-root 情况（第三行）

因此，这回答了它是如何工作的：EUID 是特殊值**`0`**（root），操作系统现在将进程视为 root 进程，并允许其写入`/etc/shadow`数据库。

例如`/usr/bin/passwd`这样的程序，通过 setuid 位继承了 root 访问权限，并且文件所有者是 root：这些类型的程序称为 setuid root 二进制文件（它们也被称为 set-user-ID-root 程序）。

引用一个受挫的开发人员对所有测试人员的反应：*这不是一个 bug；这是一个功能！* 好吧，它就是：setuid 功能非常了不起：完全不需要编程，您就能够提高进程的特权级别，持续一段时间。

想想这个。如果没有这个功能，非 root 用户（大多数用户）将无法更改他们的密码。要求系统管理员执行此操作（想象一下拥有几千名员工具有 Linux 账户的大型组织）不仅会让系统管理员考虑自杀，还必须向系统管理员提供您的新密码，这可能并不是一个明智的安全实践。

# setuid 和 setgid 特殊权限位

我们可以看到 setuid 程序二进制文件是前面讨论的一个重要内容；让我们再次总结一下：

+   拥有所有者执行位设置为`s`的二进制可执行文件称为**setuid 二进制文件**。

+   如果该可执行文件的所有者是 root，则称为**setuid-root 二进制文件**。

+   当您执行 setuid 程序时，关键点在于 EUID 设置为二进制可执行文件的所有者：

+   因此，使用 setuid-root 二进制文件，进程将以 root 身份运行！

+   当进程死掉后，您将回到具有常规（默认）进程凭据或特权的 shell。

在概念上类似于 setuid 的是 setgid 特殊权限位的概念：

+   拥有组执行位设置为`s`的二进制可执行文件称为 setgid 二进制文件。

+   当您执行 setgid 程序时，关键点在于 EGID 设置为二进制可执行文件的组成员身份。

+   当进程死掉后，您将回到具有常规（默认）进程凭据或特权的 shell。

如前所述，请记住，`set[u|g]id`特殊权限位只对二进制可执行文件有意义，对于脚本（bash、Perl 等）尝试设置这些位将完全没有效果。

# 使用`chmod`设置 setuid 和 setgid 位

也许到现在为止，您已经想到了，但是我到底如何设置这些特殊权限位呢？

这很简单：您可以使用`chmod(1)`命令（或系统调用）；此表显示了如何使用 chmod 设置`setuid/setgid`权限位：

| 通过`chmod`： | 设置 setuid 的符号 | 设置 setgid 的符号 |
| --- | --- | --- |
| 符号表示 | `u+s` | `g+s` |
| 八进制符号 | `4<八进制 #> (例如 4755)` | `2<八进制 #> (例如 2755)` |

举个简单的例子，拿一个简单的`Hello, world` C 程序并编译它：

```
gcc hello.c -o hello
```

现在我们设置了 setuid 位，然后删除它，并设置了 setgid 位（通过`u-s,g+s`参数进行一次操作：通过`chmod`），然后删除了 setgid 位，同时长时间列出二进制可执行文件以便查看权限：

```
$ ls -l hello
-rwxrwxr-x 1 seawolf seawolf 8336 Feb 17 19:02 hello
$ chmod u+s hello ; ls -l hello
-rwsrwxr-x 1 seawolf seawolf 8336 Feb 17 19:02 hello
$ chmod u-s,g+s hello ; ls -l hello
-rwxrwsr-x 1 seawolf seawolf 8336 Feb 17 19:02 hello
$ chmod g-s hello ; ls -l hello
-rwxrwxr-x 1 seawolf seawolf 8336 Feb 17 19:02 hello
$
```

（由于这个`Hello, world`程序只是简单地打印到 stdout，没有其他作用，因此 setuid/setgid 位没有任何感知效果。）

# 黑客尝试 1

嗯，嗯，对于您这位像黑客一样思考的读者（干得好！），为什么不这样做以获得最终奖励，即 root shell！

+   编写一个生成 shell 的 C 程序（`system(3)`库 API 使这变得简单）；我们将代码称为`rootsh_hack1.c`。我们希望得到一个 root shell 作为结果！

+   编译它，得到`a.out`。如果我们现在运行`a.out`，没什么大不了的；我们将得到一个具有我们已经拥有的相同特权的 shell。所以尝试这个：

+   使用`chmod(1)`更改权限以设置`setuid`位。

+   使用`chown(1)`将`a.out`的所有权更改为 root。

+   运行它：我们现在应该得到一个 root shell。

哇！让我们试试这个！

代码很简单（我们这里不显示头文件的包含）*：*

```
$ cat rootsh_hack1.c
[...]
int main(int argc, char **argv)
{
    /* Just spawn a shell.
     * If this process runs as root,
     * then, <i>Evil Laugh</i>, we're now root!
     */
    system("/bin/bash");
    exit (EXIT_SUCCESS);
}
```

现在编译并运行：

```
$ gcc rootsh_hack1.c -Wall
$ ls -l a.out 
-rwxrwxr-x 1 seawolf seawolf 8344 Feb 20 10:15 a.out
$ ./a.out 
seawolf@seawolf-mindev:~/book_src/ch7$ id -u
1000
seawolf@seawolf-mindev:~/book_src/ch7$ exit
exit
$
```

如预期的那样，当没有特殊的`set[u|g]id`权限位运行时，a.out 进程以普通特权运行，生成一个与相同所有者（seawolf）的 shell——正是`id -u`命令证明的。

现在，我们尝试我们的黑客行为：

```
$ chmod u+s a.out 
$ ls -l a.out 
-rwsrwxr-x 1 seawolf seawolf 8344 Feb 20 10:15 a.out
$ 
```

成功了！好吧，不要太兴奋：我们已经将其变成了一个 setuid 二进制文件，但所有者仍然是`seawolf`；因此在运行时不会有任何区别：进程 EUID 将变为二进制可执行文件的所有者`seawolf`本身：

```
$ ./a.out 
seawolf@seawolf-mindev:~/book_src/ch7$ id -u
1000
seawolf@seawolf-mindev:~/book_src/ch7$ exit
exit
$
```

嗯。是的，所以我们现在需要做的是将所有者更改为 root：

```
$ chown root a.out 
chown: changing ownership of 'a.out': Operation not permitted
$ 
```

抱歉要打破你的幻想，新手黑客：这行不通。这就是安全性；使用`chown(1)`，你只能更改你拥有的文件（或对象）的所有权，猜猜？只能更改为你自己的帐户！只有 root 可以使用`chown`将对象的所有权设置为其他任何人。

从安全性方面来看这是有道理的。它甚至更进一步；看看这个：我们将成为 root 并运行`chown`（当然只是通过`sudo`）：

```
$ sudo chown root a.out 
[sudo] password for seawolf: xxx
$ ls -l a.out 
-rwxrwxr-x 1 root seawolf 8344 Feb 20 10:15 a.out*
$ 
```

你注意到了吗？即使`chown`成功了，setuid 位也被清除了！这就是安全性。

好吧，让我们甚至通过手动在 root-owned a.out 上设置 setuid 位来颠覆这一点（请注意，除非我们已经拥有 root 访问权限或密码，否则这是不可能的）：

```
$ sudo chmod u+s a.out 
$ ls -l a.out 
-rwsrwxr-x 1 root seawolf 8344 Feb 20 10:15 a.out
$ 
```

啊！现在它是一个 setuid-root 二进制可执行文件（确实，你在这里看不到，但 a.out 的颜色变成了红色）。没有人会阻止我们！看看这个：

```
$ ./a.out 
seawolf@seawolf-mindev:~/book_src/ch7$ id -u
1000
seawolf@seawolf-mindev:~/book_src/ch7$ exit
exit
$ 
```

生成的 shell 的（R）UID 为 1000，而不是 0。发生了什么？

真是个惊喜！即使拥有 root 所有权和 setuid 位，我们也无法获得 root shell。怎么回事？当然是因为安全性：当通过`system(3)`运行时，现代版本的 bash 拒绝在启动时以 root 身份运行。这张截图显示了`system(3)`的 man 页面上相关部分，显示了我们正在讨论的警告（[`man7.org/linux/man-pages/man3/system.3.html`](http://man7.org/linux/man-pages/man3/system.3.html)）：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/9f6be597-f178-489f-9896-f946f56b8a9a.png)

第二段总结了这一点：

```
... as a security measure, bash 2 drops privileges on startup. 
```

# 系统调用

我们从之前的讨论中了解到，每个活动进程都有一组四个整数值，有效确定其特权，即真实和有效的用户和组 ID；它们被称为进程凭证。

如前所述，我们将它们称为{RUID，EUID，RGID，EGID}。

有效的 ID 以粗体字显示，以重申这样一个事实，即当涉及实际检查权限时，内核使用有效的 ID。

进程凭证存储在哪里？操作系统将这些信息作为相当大的进程属性数据结构的一部分（当然是每个进程）保存在内核内存空间中。

在 Unix 上，这种每个进程的数据结构称为**进程控制块**（**PCB**）；在 Linux 上，它被称为进程描述符或简单地称为任务结构。

重点是：如果数据在内核地址空间中，那么获取（查询或设置）的唯一方法是通过系统调用。

# 查询进程凭证

如何在 C 程序中以编程方式查询真实和有效的 UID / GID？以下是用于这样做的系统调用：

```
#include <unistd.h>
#include <sys/types.h>

uid_t getuid(void);
uid_t geteuid(void);

gid_t getgid(void);
gid_t getegid(void);
```

这很简单：

+   `getuid(2)`返回真实 UID；`geteuid(2)`返回有效 UID

+   `getgid(2)`返回真实 GID；`getegid(2)`返回有效 GID

+   `uid_t`和`gid_t`是 glibc 对无符号整数的 typedef

这是一个很好的提示，可以找出任何给定数据类型的 typedef：你需要知道包含定义的头文件。只需这样做：

`$ echo | gcc -E -xc -include 'sys/types.h' - | grep uid_t`

`typedef unsigned int __uid_t;`

`typedef __uid_t uid_t;`

`$`

来源*：[`stackoverflow.com/questions/2550774/what-is-size-t-in-c`](https://stackoverflow.com/questions/2550774/what-is-size-t-in-c)。

一个问题出现了：前面的系统调用没有带任何参数；它们返回真实或有效的[U|G]ID，是的，但是为哪个进程？答案当然是调用进程，发出系统调用的进程。

# 代码示例

我们编写了一个简单的 C 程序（`ch7/query_creds.c`）；运行时，它会将其进程凭证打印到标准输出（我们展示了相关代码）：

```
#define SHOW_CREDS() do {        \
  printf("RUID=%d EUID=%d\n"    \
         "RGID=%d EGID=%d\n",    \
        getuid(), geteuid(),    \
        getgid(), getegid());   \
} while (0)

int main(int argc, char **argv)
{
    SHOW_CREDS();
    if (geteuid() == 0) {
        printf("%s now effectively running as root! ...\n", argv[0]);
        sleep(1);
    }
    exit (EXIT_SUCCESS);
}
```

构建并尝试运行它：

```
$ ./query_creds
RUID=1000 EUID=1000
RGID=1000 EGID=1000
$ sudo ./query_creds
[sudo] password for seawolf: xxx 
RUID=0 EUID=0
RGID=0 EGID=0
./query_creds now effectively running as root! ...
$ 
```

注意以下内容：

+   在第一次运行时，四个进程凭证的值是通常的值（在我们的例子中是 1000）。还要注意，默认情况下 EUID = RUID，EGID = RGID。

+   但在第二次运行时我们使用了`sudo`：一旦我们输入正确的密码，进程就以 root 身份运行，这当然可以从这里直接看到：四个进程凭证的值现在都是零，反映了 root 权限。

# Sudo - 它是如何工作的

`sudo(8)`实用程序允许您以另一个用户的身份运行程序；如果没有进一步的限定，那么另一个用户就是 root。当然，出于安全考虑，您必须正确输入 root 密码（或者像一些发行版允许桌面计算那样，如果用户属于 sudo 组，可以输入用户自己的密码）。

这带来了一个非常有趣的问题：`sudo(8)`程序究竟是如何工作的？它比你想象的要简单！参考以下代码：

```
$ which sudo
/usr/bin/sudo
$ ls -l $(which sudo)
-rwsr-xr-x 1 root root 145040 Jun 13  2017 /usr/bin/sudo
$ 
```

我们注意到，可执行文件 sudo 实际上是一个设置了 setuid-root 权限的程序！所以想一想：每当您使用 sudo 运行一个程序时，sudo 进程就会立即以 root 权限运行——不需要密码，也不需要麻烦。但是，出于安全考虑，用户必须输入密码；一旦他们正确输入密码，sudo 就会继续执行并以 root 身份执行您想要的命令。如果用户未能正确输入密码（通常在三次尝试内），sudo 将中止执行。

# 保存的 ID 是什么？

所谓的保存的 ID 是一个方便的功能；操作系统能够保存进程的初始有效用户 ID（EUID）的值。它有什么作用呢？这允许我们从进程启动时的原始 EUID 值切换到一个非特权的普通值（我们马上就会详细介绍），然后从当前特权状态切换回保存的 EUID 值（通过`seteuid(2)`系统调用）；因此，最初保存的 EUID 被称为**保存的 ID**。

实际上，我们可以随时在我们的进程之间切换特权和非特权状态！

在我们涵盖了更多的材料之后，一个例子将有助于澄清事情。

# 设置进程凭证

我们知道，从 shell 中，查看当前运行的用户是谁的一个方便的方法是运行简单的`id(1)`命令；它会显示真实的 UID 和真实的 GID（以及我们所属的所有附加组）。就像我们之前做的那样，让我们在用户`seawolf`登录时尝试一下：

```
$ id
uid=1000(seawolf) gid=1000(seawolf) groups=1000(seawolf),4(adm),24(cdrom),27(sudo), [...]
$ 
```

再次考虑`sudo(8)`实用程序；要以另一个用户而不是 root 身份运行程序，我们可以使用`-u`或`--user=`开关来使用`sudo`。例如，让我们以用户`mail`的身份运行`id(1)`程序：

```
$ sudo -u mail id
[sudo] password for seawolf: xxx
uid=8(mail) gid=8(mail) groups=8(mail)
$ 
```

预期的是，一旦我们提供正确的密码，`sudo`就会以邮件用户的身份运行`id`程序，`id`的输出现在显示我们的（真实）用户和组 ID 现在是邮件用户账户的！（而不是 seawolf），这正是预期的效果。

但`sudo(8)`是如何做到的呢？我们从前一节了解到，当运行`sudo`（无论带有什么参数），它至少最初总是以 root 身份运行。现在的问题是，它如何以另一个用户账户的凭证运行？

答案是：存在几个系统调用可以改变进程的特权（RUID、EUID、RGID、EGID）：`setuid(2)`、`seteuid(2)`、`setreuid(2)`、`setresuid(2)`以及它们的 GID 对应的函数。

让我们快速看一下 API 签名：

```
#include <sys/types.h>
#include <unistd.h>

int setuid(uid_t uid);
int setgid(gid_t gid);

int seteuid(uid_t euid);
int setegid(gid_t egid);

int setreuid(uid_t ruid, uid_t euid);
int setregid(gid_t rgid, gid_t egid);
```

`setuid(2)`系统调用允许进程将其 EUID 设置为传递的值。如果进程具有 root 权限（稍后在下一章中，当我们了解 POSIX 能力模型时，我们将更好地限定这样的陈述），那么 RUID 和保存的 setuid（稍后解释）也将设置为这个值。

所有的`set*gid()`调用都类似于它们的 UID 对应物。

在 Linux 操作系统上，seteuid 和 setegid API，虽然被记录为系统调用，实际上是`setreuid(2)`和`setregid(2)`系统调用的包装器。

# 黑客攻击尝试 2

啊，黑客攻击！好吧，至少让我们试一试。

我们知道`EUID 0`是一个特殊值——它意味着我们拥有 root 权限。想想看——我们有一个`setuid(2)`系统调用。所以，即使我们没有特权，为什么不快速地做一个

`setuid(0);`变得特权，并像 root 一样黑客攻击！

嗯，如果上面的黑客攻击真的奏效，Linux 就不会成为一个非常强大和受欢迎的操作系统。它不会奏效，朋友们：上面的系统调用调用将失败返回`-1`；`errno`将被设置为`EPERM`，错误消息（来自`perror(3)`或`strerror(3)`）将是这样的：操作不允许。

为什么呢？在内核中有一个简单的规则：一个非特权进程可以将其有效 ID 设置为其真实 ID，不允许其他值。换句话说，一个非特权进程可以设置以下内容：

+   它的 EUID 到它的 RUID

+   它的 EGID 到它的 RGID

就是这样。

当然，（root）特权进程可以将其四个凭据设置为任何它选择的值。这并不奇怪——这是作为 root 的权力的一部分。

`seteuid(2)`将进程的有效用户 ID 设置为传递的值；对于一个非特权进程，它只能将其 EUID 设置为其 RUID，EUID 或保存的 setuid。

`setreuid(2)`将真实和有效的 UID 分别设置为传递的值；如果传递了`-1`，则相应的值将保持不变。（这可能间接影响保存的值。）`set[r]egid(2)`调用在组 ID 方面是相同的。

让我们实际操作一下我们刚刚谈到的内容：

```
$ cat rootsh_hack2.c
[...]
int main(int argc, char **argv)
{
    /* Become root */
    if (setuid(0) == -1)
        WARN("setuid(0) failed!\n");

    /* Now just spawn a shell;
     * <i>Evil Laugh</i>, we're now root!
     */
    system("/bin/bash");
    exit (EXIT_SUCCESS);
}
```

构建并运行它。这个屏幕截图显示了一个名为 seawolf 的虚拟机，以及右下角的一个`ssh`连接的终端窗口（我们以用户 seawolf 的身份登录）；看到`rootsh_hack2`程序正在那里运行：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/d3dee453-cdca-432e-a761-cb3fe1bfbcc6.png)

研究前面屏幕截图中`ssh`终端窗口的输出，我们可以看到以下内容：

+   原始的 bash 进程（shell）的 PID 是 6012。

+   id 命令显示我们正在以（真实的）UID = 1000（即 seawolf 用户）运行。

+   我们运行`rootsh_hack2`；显然，`setuid(0)`失败了；显示了错误消息：操作不允许。

+   尽管如此，这只是一个警告消息；执行继续进行，进程生成另一个 bash 进程，实际上是另一个 shell。

+   它的 PID 是 6726（证明它与原始 shell 不同）。

+   id(1)仍然是 1000，证明我们并没有真正取得什么重大成就。

+   我们退出，回到我们最初的 shell。

但是，如果我们（或者更糟糕的是，一个黑客）能够欺骗这个进程以 root 身份运行呢！？怎么做？当然是将其设置为 setuid-root 可执行文件；然后我们就麻烦了：

```
$ ls -l rootsh_hack2
-rwxrwxr-x 1 seawolf seawolf 8864 Feb 19 18:03 rootsh_hack2
$ sudo chown root rootsh_hack2
[sudo] password for seawolf: 
$ sudo chmod u+s rootsh_hack2
$ ls -l rootsh_hack2
-rwsrwxr-x 1 root seawolf 8864 Feb 19 18:03 rootsh_hack2
$ ./rootsh_hack2
root@seawolf-mindev:~/book_src/ch7# id -u
0
root@seawolf-mindev:~/book_src/ch7# ps
  PID TTY          TIME CMD
 7049 pts/0    00:00:00 rootsh_hack2
 7050 pts/0    00:00:00 sh
 7051 pts/0    00:00:00 bash
 7080 pts/0    00:00:00 ps
root@seawolf-mindev:~/book_src/ch7# exit
exit
$ 
```

所以，我们只是模拟被欺骗：在这里我们使用 sudo(8);我们输入密码，从而将二进制可执行文件更改为 setuid-root，一个真正危险的程序。它运行，并生成了一个现在被证明是 root shell 的进程（注意，`id(1)`命令证明了这一事实）；我们执行`ps`然后`exit`。

我们也意识到，我们之前的黑客尝试失败了——当 shell 作为运行参数时，系统（3）API 拒绝提升权限，这在安全方面是很好的。但是，这次黑客尝试（＃2）证明你可以轻松地颠覆这一点：只需在调用 system（`/bin/bash`）之前发出`setuid（0）`的调用，它就成功地提供了一个 root shell——当然，只有在进程首先以 root 身份运行时才会成功：要么通过 setuid-root 方法，要么只是使用 sudo（8）。

# 一边——一个用于识别 setuid-root 和 setgid 安装程序的脚本

我们现在开始理解，`setuid/setgid`程序可能很方便，但从安全的角度来看，它们可能是潜在的危险，并且必须仔细审计。这种审计的第一步是找出 Linux 系统上这些二进制文件是否存在以及确切存在的位置。

为此，我们编写一个小的 shell（bash）脚本；它将识别并显示系统上安装的`setuid-root`和`setgid`程序（通常情况下，您可以从书的 Git 存储库下载并尝试该脚本）。

脚本基本上执行其工作，如下所示（它实际上循环遍历一个目录数组；为简单起见，我们显示了扫描`/bin`目录的直接示例）：

```
 echo "Scanning /bin ..."
 ls -l /bin/ | grep "^-..s" | awk '$3=="root" {print $0}'
```

`ls -l`的输出被管道传输到`grep（1）`，它使用一个正则表达式，如果第一个字符是`-`（一个常规文件），并且所有者执行位是 s——换句话说，是一个 setuid 文件；`awk（1）`过滤器确保只有所有者是 root 时，我们才将结果字符串打印到 stdout。

我们在两个 Linux 发行版上运行 bash 脚本。

在 x86_64 上的 Ubuntu 17.10 上：

```
$ ./show_setuidgid.sh
------------------------------------------------------------------
System Information (LSB):
------------------------------------------------------------------
No LSB modules are available.
Distributor ID:    Ubuntu
Description:    Ubuntu 17.10
Release:    17.10
Codename:    artful
kernel: 4.13.0-32-generic
------------------------------------------------------------------
Scanning various directories for (traditional) SETUID-ROOT binaries ...
------------------------------------------------------------------
Scanning /bin            ...
-rwsr-xr-x 1 root root   30800 Aug 11  2016 fusermount
-rwsr-xr-x 1 root root   34888 Aug 14  2017 mount
-rwsr-xr-x 1 root root  146128 Jun 23  2017 ntfs-3g
-rwsr-xr-x 1 root root   64424 Mar 10  2017 ping
-rwsr-xr-x 1 root root   40168 Aug 21  2017 su
-rwsr-xr-x 1 root root   26696 Aug 14  2017 umount
------------------------------------------------------------------
Scanning /usr/bin        ...
-rwsr-xr-x 1 root root       71792 Aug 21  2017 chfn
-rwsr-xr-x 1 root root       40400 Aug 21  2017 chsh
-rwsr-xr-x 1 root root       75344 Aug 21  2017 gpasswd
-rwsr-xr-x 1 root root       39944 Aug 21  2017 newgrp
-rwsr-xr-x 1 root root       54224 Aug 21  2017 passwd
-rwsr-xr-x 1 root root      145040 Jun 13  2017 sudo
-rwsr-xr-x 1 root root       18448 Mar 10  2017 traceroute6.iputils
------------------------------------------------------------------
Scanning /sbin           ...
------------------------------------------------------------------
Scanning /usr/sbin       ...
------------------------------------------------------------------
Scanning /usr/local/bin  ...
------------------------------------------------------------------
Scanning /usr/local/sbin ...
------------------------------------------------------------------

Scanning various directories for (traditional) SETGID binaries ...
------------------------------------------------------------------
Scanning /bin            ...
------------------------------------------------------------------
Scanning /usr/bin        ...
-rwxr-sr-x 1 root tty        14400 Jul 27  2017 bsd-write
-rwxr-sr-x 1 root shadow     62304 Aug 21  2017 chage
-rwxr-sr-x 1 root crontab    39352 Aug 21  2017 crontab
-rwxr-sr-x 1 root shadow     22808 Aug 21  2017 expiry
-rwxr-sr-x 1 root mlocate    38992 Apr 28  2017 mlocate
-rwxr-sr-x 1 root ssh       362640 Jan 16 18:58 ssh-agent
-rwxr-sr-x 1 root tty        30792 Aug 14  2017 wall
------------------------------------------------------------------
Scanning /sbin           ...
-rwxr-sr-x 1 root shadow   34816 Apr 22  2017 pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow   34816 Apr 22  2017 unix_chkpwd
------------------------------------------------------------------
Scanning /usr/sbin       ...
------------------------------------------------------------------
Scanning /usr/local/bin  ...
------------------------------------------------------------------
Scanning /usr/local/sbin ...
------------------------------------------------------------------
$
```

显示系统信息横幅（以便我们可以获取系统详细信息，主要是使用`lsb_release`实用程序获得的）。然后，脚本扫描各种系统目录，打印出它找到的所有`setuid-root`和`setgid`二进制文件。熟悉的例子，`passwd`和`sudo`被突出显示。

# setgid 示例- wall

作为`setgid`二进制文件的一个很好的例子，看看 wall（1）实用程序，从脚本的输出中复制：

```
-rwxr-sr-x 1 root tty        30792 Aug 14  2017 wall
```

wall（1）程序用于向所有用户控制台（tty）设备广播任何消息（通常由系统管理员执行）。现在，要写入`tty`设备（回想一下，朋友们，第一章，*Linux 系统架构*，以及如果不是一个进程，它就是一个文件 Unix 哲学），我们需要什么权限？让我们以第二个终端`tty2`设备为例：

```
$ ls -l /dev/tty2
crw--w---- 1 root tty 4, 2 Feb 19 18:04 /dev/tty2
$ 
```

我们可以看到，要写入前面的设备，我们要么需要 root，要么必须是`tty`组的成员。再次查看 wall（1）实用程序的长列表；它是一个 setgid 二进制可执行文件，组成员是`tty`；因此，当任何人运行它时，wall 进程将以`tty`的有效组 ID（EGID）运行！这解决了问题——没有代码。没有麻烦。

这是一个截图，显示了 wall 的使用：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/a0736e00-379a-4550-8e77-0709bca6be26.png)

在前台，有一个连接的`ssh`（到 Ubuntu VM；您可以在后台看到它）终端窗口。它以常规用户的身份发出`wall`命令：由于`setgid tty`*，*它有效！

现在你可以在 x86_64 上的 Fedora 27 上运行之前的脚本：

```
$ ./show_setuidgid.sh 1
------------------------------------------------------------------
System Information (LSB):
------------------------------------------------------------------
LSB Version:    :core-4.1-amd64:core-4.1-noarch
Distributor ID:    Fedora
Description:    Fedora release 27 (Twenty Seven)
Release:    27
Codename:    TwentySeven
kernel: 4.14.18-300.fc27.x86_64
------------------------------------------------------------------
Scanning various directories for (traditional) SETUID-ROOT binaries ...
------------------------------------------------------------------
Scanning /bin            ...
------------------------------------------------------------------
Scanning /usr/bin        ...
-rwsr-xr-x.   1 root root       52984 Aug  2  2017 at
-rwsr-xr-x.   1 root root       73864 Aug 14  2017 chage
-rws--x--x.   1 root root       27992 Sep 22 14:07 chfn
-rws--x--x.   1 root root       23736 Sep 22 14:07 chsh
-rwsr-xr-x.   1 root root       57608 Aug  3  2017 crontab
-rwsr-xr-x.   1 root root       32040 Aug  7  2017 fusermount
-rwsr-xr-x.   1 root root       31984 Jan 12 20:36 fusermount-glusterfs
-rwsr-xr-x.   1 root root       78432 Aug 14  2017 gpasswd
-rwsr-xr-x.   1 root root       36056 Sep 22 14:07 mount
-rwsr-xr-x.   1 root root       39000 Aug 14  2017 newgidmap
-rwsr-xr-x.   1 root root       41920 Aug 14  2017 newgrp
-rwsr-xr-x.   1 root root       39000 Aug 14  2017 newuidmap
-rwsr-xr-x.   1 root root       27880 Aug  4  2017 passwd
-rwsr-xr-x.   1 root root       27688 Aug  4  2017 pkexec
-rwsr-xr-x.   1 root root       32136 Sep 22 14:07 su
---s--x--x.   1 root root      151416 Oct  4 18:55 sudo
-rwsr-xr-x.   1 root root       27880 Sep 22 14:07 umount
------------------------------------------------------------------
Scanning /sbin           ...
------------------------------------------------------------------
Scanning /usr/sbin       ...
-rwsr-xr-x. 1 root root    114840 Jan 19 23:25 mount.nfs
-rwsr-xr-x. 1 root root     89600 Aug  4  2017 mtr
-rwsr-xr-x. 1 root root     11256 Aug 21  2017 pam_timestamp_check
-rwsr-xr-x. 1 root root     36280 Aug 21  2017 unix_chkpwd
-rws--x--x. 1 root root     40352 Aug  5  2017 userhelper
-rwsr-xr-x. 1 root root     11312 Jan  2 21:06 usernetctl
------------------------------------------------------------------
Scanning /usr/local/bin  ...
------------------------------------------------------------------
Scanning /usr/local/sbin ...
------------------------------------------------------------------

Scanning various directories for (traditional) SETGID binaries ...
------------------------------------------------------------------
Scanning /bin            ...
------------------------------------------------------------------
Scanning /usr/bin        ...
-rwxr-sr-x.   1 root cgred      15640 Aug  3  2017 cgclassify
-rwxr-sr-x.   1 root cgred      15600 Aug  3  2017 cgexec
-rwx--s--x.   1 root slocate    40528 Aug  4  2017 locate
-rwxr-sr-x.   1 root tty        19584 Sep 22 14:07 write
------------------------------------------------------------------
Scanning /sbin           ...
------------------------------------------------------------------
Scanning /usr/sbin       ...
-rwx--s--x. 1 root lock     15544 Aug  4  2017 lockdev
-rwxr-sr-x. 1 root root      7144 Jan  2 21:06 netreport
------------------------------------------------------------------
Scanning /usr/local/bin  ...
------------------------------------------------------------------
Scanning /usr/local/sbin ...
------------------------------------------------------------------
$ 
```

似乎出现了更多的 setuid-root 二进制文件；此外，在 Fedora 上，`write（1）`是等效于`wall（1）`的`setgid tty`实用程序。

# 放弃特权

从先前的讨论中，似乎`set*id()`系统调用（`setuid(2)`，`seteuid(2)`，`setreuid(2)`，`setresuid(2)`）只对 root 有用，因为只有具有 root 权限的进程才能使用这些系统调用来更改进程凭据。嗯，这并不是完全的真相；还有另一个重要的情况，适用于非特权进程。

考虑这种情况：我们的程序规范要求初始化代码以 root 权限运行；其余代码则不需要。显然，我们不希望为了运行我们的程序而给最终用户 root 访问权限。我们该如何解决这个问题呢？

将程序设置为 setuid-root 会很好地解决问题。正如我们所看到的，setuid-root 进程将始终以 root 身份运行；但在初始化工作完成后，我们可以切换回非特权正常状态。我们如何做到这一点？通过`setuid(2)`：回想一下，对于特权进程，setuid 会将 EUID 和 RUID 都设置为传递的值；因此我们将其传递给进程的 RUID，这是通过 getuid 获得的。

```
setuid(getuid());    // make process unprivileged
```

这是一个有用的语义（通常，`seteuid(getuid()`)就是我们需要的）。我们使用这个语义来再次成为我们真正的自己——相当哲学，不是吗？

在**信息安全**（**infosec**）领域，有一个重要的原则是：减少攻击面。将根特权进程转换为非特权（一旦其作为根完成工作）有助于实现这一目标（至少在某种程度上）。

# 保存的 UID - 一个快速演示

在前一节中，我们刚刚看到了有用的`seteuid(getuid()`)语义如何用于将 setuid 特权进程切换到常规非特权状态（这是很好的设计，更安全）。但是如果我们有这个要求呢：

```
Time t0: initialization code: must run as root
Time t1: func1(): must *not* run as root
Time t2: func2(): must run as root
Time t3: func3(): must *not* run as root
[...]
```

为了实现最初必须以 root 身份运行的语义，我们当然可以创建程序为 setuid-root 程序。然后，在 t1 时，我们发出`setuid(getuid()`)放弃 root 权限。

但是我们如何在 t2 时重新获得 root 权限呢？啊，这就是保存的 setuid 功能变得宝贵的地方。而且，这样做很容易；以下是实现这种情况的伪代码：

```
t0: we are running with root privilege due to *setuid-root* binary  
    executable being run
 saved_setuid = geteuid()   // save it
t1: seteuid(getuid())      // must *not* run as root
t2: seteuid(saved_setuid)  // switch back to the saved-set, root
t3: seteuid(getuid())      // must *not* run as root
```

我们接下来用实际的 C 代码来演示相同的情况。请注意，为了使演示按预期工作，用户必须通过以下方式将二进制可执行文件变成 setuid-root 二进制文件：

```
make savedset_demo
sudo chown root savedset_demo
sudo chmod u+s savedset_demo
```

以下代码检查了在开始时，进程确实是以 root 身份运行的；如果不是，它将中止并显示一条消息，要求用户将二进制文件设置为 setuid-root 二进制文件：

```
int main(int argc, char **argv)
{
    uid_t saved_setuid;

    printf("t0: Init:\n");
    SHOW_CREDS();
    if (0 != geteuid())
        FATAL("Not a setuid-root executable,"
            " aborting now ...\n"
            "[TIP: do: sudo chown root %s ;"
            " sudo chmod u+s %s\n"
            " and rerun].\n"
            , argv[0], argv[0], argv[0]);
    printf(" Ok, we're effectively running as root! (EUID==0)\n");

    /* Save the EUID, in effect the "saved set UID", so that
     * we can switch back and forth
     */
    saved_setuid = geteuid();

    printf("t1: Becoming my original self!\n");
    if (seteuid(getuid()) == -1)
        FATAL("seteuid() step 2 failed!\n");
    SHOW_CREDS();

    printf("t2: Switching to privileged state now...\n");
    if (seteuid(saved_setuid) == -1)
        FATAL("seteuid() step 3 failed!\n");
    SHOW_CREDS();
    if (0 == geteuid())
        printf(" Yup, we're root again!\n");

    printf("t3: Switching back to unprivileged state now ...\n");
    if (seteuid(getuid()) == -1)
        FATAL("seteuid() step 4 failed!\n");
    SHOW_CREDS();

    exit (EXIT_SUCCESS);
}
```

这是一个样本运行：

```
$ make savedset_demo
gcc -Wall -o savedset_demo savedset_demo.c common.o
#sudo chown root savedset_demo
#sudo chmod u+s savedset_demo
$ ls -l savedset_demo
-rwxrwxr-x 1 seawolf seawolf 13144 Feb 20 09:22 savedset_demo*
$ ./savedset_demo
t0: Init:
RUID=1000 EUID=1000
RGID=1000 EGID=1000
FATAL:savedset_demo.c:main:48: Not a setuid-root executable, aborting now ...
[TIP: do: sudo chown root ./savedset_demo ; sudo chmod u+s ./savedset_demo
 and rerun].
$ 
```

程序失败了，因为它检测到在开始时并没有有效地以 root 身份运行，这意味着它一开始就不是一个 setuid-root 二进制可执行文件。因此，我们必须通过`sudo chown ...`然后`sudo chmod ...`来使其成为 setuid-root 二进制可执行文件。（请注意，我们已经将执行此操作的代码放在了 Makefile 中，但已经将其注释掉，这样你作为读者就可以练习一下）。

这个截图显示了一旦我们这样做，它会按预期运行，在特权和非特权状态之间来回切换：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/fda744b4-4daa-439c-b624-92f428e976c7.png)

请注意，真正关键的系统调用来回切换，毕竟是 setuid(2)；还要注意 EUID 在不同时间点的变化（从 t0 的 0 到 t1 的 1000，再到 t2 的 0，最后在 t3 回到 1000）。

还要注意，为了提供有趣的例子，我们大多数情况下使用的是 setuid-root 二进制文件。你不需要这样做：将文件所有者更改为其他人（比如邮件用户），实际上会使其成为一个 setuid-mail 二进制可执行文件，这意味着当运行时，进程 RUID 将是通常的 1000（seawolf），但 EUID 将是邮件用户的 RUID。

# setres[u|g]id(2)系统调用

这里有一对包装调用 - `setresuid(2)`和`setresgid(2)`；它们的签名：

```
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>

int setresuid(uid_t ruid, uid_t euid, uid_t suid);
int setresgid(gid_t rgid, gid_t egid, gid_t sgid);
```

这对系统调用就像是早期的`set*id()`API 的超集。使用`setresuid(2)`系统调用，进程可以一次性设置 RUID、EUID 和保存的 set-id，只需一个系统调用（系统调用名称中的**res**代表**real**、**effective**和**saved**-set-ID）。

非特权（即非 root）进程只能使用此系统调用将三个 ID 之一设置为当前 RUID、当前 EUID 或当前保存的 UID，没有其他选项（通常的安全原则在起作用）。传递`-1`意味着保持相应的值不变。特权（root）进程当然可以使用调用将三个 ID 设置为任何值。（通常情况下，`setresgid(2)`系统调用是相同的，只是它设置组凭据）。

一些真实的开源软件项目确实使用了这个系统调用；OpenSSH 项目（Linux 端口称为 OpenSSH-portable）和著名的 sudo(8)实用程序就是很好的例子。

OpenSSH：来自其 git 存储库：[`github.com/openssh/openssh-portable/`](https://github.com/openssh/openssh-portable/)：

`uidswap.c`：`permanently_drop_suid():`

```
void permanently_drop_suid(uid_t uid)
[...]
debug("permanently_drop_suid: %u", (u_int)uid);
if (setresuid(uid, uid, uid) < 0)
    fatal("setresuid %u: %.100s", (u_int)uid, strerror(errno));

[...]

/* Verify UID drop was successful */
    if (getuid() != uid || geteuid() != uid) {
        fatal("%s: euid incorrect uid:%u euid:%u (should be %u)",
            __func__, (u_int)getuid(), (u_int)geteuid(), (u_int)uid);
}
```

有趣的是注意到确保 UID 降级成功所付出的努力——接下来会更多地讨论这一点！

对 sudo(8)执行`strace(1)`（请注意，我们必须以 root 身份跟踪它，因为尝试以普通用户身份跟踪 setuid 程序时不起作用，因为在跟踪时，setuid 位被故意忽略；此输出来自 Ubuntu Linux 系统）：

```
$ id mail uid=8(mail) gid=8(mail) groups=8(mail) $ sudo strace -e trace=setuid,setreuid,setresuid sudo -u mail id
[...]
setresuid(-1, 0, -1)                    = 0
setresuid(-1, -1, -1)                   = 0
setresuid(-1, 8, -1)                    = 0
setresuid(-1, 0, -1)                    = 0
[...]
```

显然，sudo 使用`setresuid(2)`系统调用来设置权限、凭据，确实是适当的（在上面的示例中，进程 EUID 被设置为邮件用户的 EUID，RUID 和保存的 ID 被保持不变）。

# 重要的安全注意事项

以下是一些关于安全性的关键要点：

+   如果设计不当，使用 setuid 二进制文件是一种安全风险。特别是对于 setuid-root 程序，它们应该被设计和测试，以确保在进程处于提升的特权状态时，它永远不会生成一个 shell 或盲目接受用户命令（然后在内部执行）。

+   您必须检查任何`set*id()`系统调用（`setuid(2)`、`seteuid(2)`、`setreuid(2)`、`setresuid(2)`）的失败情况。

考虑这个伪代码：

```
run setuid-root program; EUID = 0
  do required work as root
switch to 'normal' privileges: setuid(getuid())
  do remaining work as non-root
  [...]
```

思考一下：如果前面的`setuid(getuid())`调用失败了（无论什么原因），而我们没有检查呢？剩下的工作将继续以 root 访问权限运行，很可能会招致灾难！（请参阅 OpenSSH-portable Git 存储库中的示例代码，了解仔细检查的真实示例。）让我们看看以下几点：

+   `setuid(2)`系统调用在某种意义上是有缺陷的：如果真实 UID 是 root，那么保存的 UID 也是 root；因此，您无法放弃权限！显然，这对于 setuid-root 应用程序等来说是危险的。作为替代方案，使用`setreuid(2)` API 使根进程暂时放弃权限，并稍后重新获得（通过交换它们的 RUID 和 EUID 值）。

+   即使您拥有系统管理员（root）访问权限，也不应该以 root 身份登录！您可能会（非常容易地）被欺骗以 root 身份运行危险程序（黑客经常使用这种技术在系统上安装 rootkit；一旦成功，确实会考虑您的系统已被入侵）。

+   当一个进程创建一个共享对象（比如一个文件）时，它将由谁拥有，组将是什么？换句话说，内核将在文件的 inode 元数据结构中设置什么值作为 UID 和 GID？答案是：文件的 UID 将是创建进程的 EUID，文件的 GID（组成员资格）将是创建进程的 EGID。这将对权限产生后续影响。

我们建议您，读者，一定要阅读第九章，*进程执行*！在其中，我们展示了传统权限模型在许多方面存在缺陷，以及为什么以及如何使用更优越的 Linux Capabilities 模型。

# 总结

在本章中，读者已经了解了关于传统 Unix 安全模型设计和实施的许多重要观念。除此之外，我们还涵盖了传统 Unix 权限模型、进程真实和有效 ID 的概念、用于查询和设置它们的 API、`sudo(8)`、保存的 ID 集。

再次强调：我们强烈建议您也阅读以下内容[第八章]，*进程能力*！在其中，我们展示了传统权限模型存在缺陷，以及您应该使用更优越、现代的 Linux 能力模型。


# 第八章：进程功能

在两章中，您将学习有关进程凭据和功能的概念和实践。除了在 Linux 应用程序开发中具有实际重要性之外，本章本质上深入探讨了一个经常被忽视但极为重要的方面：安全性。

我们将这一关键领域的覆盖分为两个主要部分，每个部分都是本书的一个章节：

+   在第七章中，*进程凭据*，传统风格的 Unix 权限模型被详细讨论，并展示了以 root 权限运行程序但不需要 root 密码的技术。

+   在第八章中，*进程功能*，*现代*方法，POSIX 功能模型，被详细讨论。

我们将尝试清楚地向读者展示，虽然了解传统机制及其运作方式很重要，但就*安全*而言，这成为了一个经典的弱点。无论如何看待它，安全性都是至关重要的，尤其是在当今这个时代；Linux 运行在各种设备上——从微型物联网和嵌入式设备到移动设备、台式机、服务器和超级计算平台——使安全成为所有利益相关者的关键关注点。因此，在开发软件时应该使用现代功能方法。

在本章中，我们将详细介绍*现代方法*——POSIX 功能模型。我们将讨论它究竟是什么，以及它如何提供安全性和健壮性。读者将了解以下内容：

+   现代 POSIX 功能模型究竟是什么

+   为什么它优于旧的（传统的）Unix 权限模型

+   如何在 Linux 上使用功能

+   将功能嵌入到进程或二进制可执行文件中

+   安全提示

在此过程中，我们将使用代码示例，让您尝试其中一些功能，以便更好地理解它们。

# 现代 POSIX 功能模型

考虑这个（虚构的）情景：Vidya 正在为 Alan 和他的团队开发 Linux 应用程序的项目。她正在开发一个捕获网络数据包并将其保存到文件中的组件（以供以后分析）。该程序名为**packcap**。然而，为了成功捕获网络数据包，packcap 必须以*root*权限运行。现在，Vidya 明白以*root*身份运行应用程序不是一个好的安全实践；不仅如此，她知道客户不会接受这样的说法：哦，它没用？你必须以 root 登录或通过 sudo 运行它。通过 sudo(8)运行它可能听起来合理，但是，当你停下来想一想，这意味着 Alan 的每个团队成员都必须被给予*root*密码，这是完全不可接受的。

那么，她如何解决这个问题呢？答案突然出现在她脑海中：将*packcap*二进制文件设置为*setuid-*root 文件可执行；这样，当它被启动时，进程将以*root*权限运行，因此不需要 root 登录/密码或 sudo。听起来很棒。

# 动机

这种 setuid-root 方法——正是传统的解决上面简要描述的问题的方式。那么，今天有什么变化（好吧，现在已经有好几年了）？简而言之：*对黑客攻击的安全关注*。现实情况是：所有真实世界的非平凡程序都有缺陷（错误）——隐藏的、潜伏的、未发现的，也许，但确实存在。现代真实世界软件项目的广泛范围和复杂性使这成为一个不幸的现实。某些错误导致*漏洞*“泄漏”到软件产品中；这正是黑客寻求*利用*的内容。众所周知，但令人畏惧的**缓冲区溢出**（***BoF***）攻击是基于几个广泛使用的库 API 中的软件漏洞！（我们强烈建议阅读 David Wheeler 的书*安全编程* *HOWTO - 创建安全软件*——请参阅 GitHub 存储库的*进一步阅读*部分。）

**在代码级别上，安全问题就是错误；一旦修复，问题就消失了。**（在 GitHub 存储库的*进一步阅读*部分中查看 Linux 对此的评论链接。）

那么重点是什么？简而言之，重点就是：您交付给客户的 setuid-root 程序（packcap）可能包含不幸的、目前未知的软件漏洞，黑客可能会发现并利用它们（是的，这有一个专门的工作描述——**白帽黑客**或**渗透测试**）。

如果进程*被黑客入侵*以普通特权—非 root—运行，那么损害至少被限制在该用户帐户中，不会进一步扩散。但是，如果进程以 root 特权运行并且攻击成功，黑客可能最终会在系统上获得*root shell*。系统现在已经受到损害——任何事情都可能发生（秘密可能被窃取，后门和 rootkit 被安装，DoS 攻击变得微不足道）。

不仅仅是关于安全，通过限制特权，您还会获得损坏控制的好处；错误和崩溃将会造成有限的损害——情况比以前要好得多。

# POSIX 功能

那么，回到我们虚构的 packcap 示例应用程序，我们如何运行该进程——似乎需要 root——而不具备 root 特权（不允许 root 登录，setuid-root*或 sudo(8)）并且使其正确执行任务？

进入 POSIX 功能模型：在这个模型中，与其像 root（或其他）用户一样给予进程*全面访问*，不如将特定功能*嵌入到进程和/或二进制文件中*。 Linux 内核从很早开始就支持 POSIX 功能模型——2.2 Linux 内核（在撰写本文时，我们现在处于 4.x 内核系列）。从实际的角度来看，我们将描述的功能从 Linux 内核版本 2.6.24（2008 年 1 月发布）开始可用。

这就是它的工作原理：每个进程——实际上，每个*线程*——作为其操作系统元数据的一部分，包含一个位掩码。这些被称为*功能位*或*功能集*，因为*每个* *位代表一个功能***。**通过仔细设置和清除位，内核（以及用户空间，如果具有该功能）因此可以在每个线程基础上设置*细粒度权限*（我们将在以后的第十四章中详细介绍多线程，现在，将术语*线程*视为可互换使用*进程*）。

更现实的是，正如我们将在接下来看到的，内核保持*每个线程活动的多个功能集（capsets）*；每个 capset 由两个 32 位无符号值的数组组成。

例如，有一个称为`CAP_DAC_OVERRIDE`的功能位**；**它通常会被清除（0）。如果设置，那么进程将绕过内核的所有文件权限检查——无论是读取、写入还是执行！（这被称为**DAC**：**自主访问控制**。）

在这一点上，查看一些功能位的更多示例将是有用的（完整列表可在这里的*功能（7）*功能页面上找到：[`linux.die.net/man/7/capabilities`](https://linux.die.net/man/7/capabilities)）。以下是一些片段：

```
[...]
CAP_CHOWN
              Make arbitrary changes to file UIDs and GIDs (see chown(2)).

CAP_DAC_OVERRIDE
              Bypass file read, write, and execute permission checks.  (DAC is an abbreviation of "discretionary access control".)
[...]

CAP_NET_ADMIN
              Perform various network-related operations:
              * interface configuration;
              * administration of IP firewall, masquerading, and accounting;
              * modify routing tables;
[...]

CAP_NET_RAW
              * Use RAW and PACKET sockets;
              * bind to any address for transparent proxying.
[...]

CAP_SETUID
              * Make arbitrary manipulations of process UIDs (setuid(2),
                setreuid(2), setresuid(2), setfsuid(2));

[...]

 CAP_SYS_ADMIN
              Note: this capability is overloaded; see Notes to kernel
              developers, below.

              * Perform a range of system administration operations
                including: quotactl(2), mount(2), umount(2), swapon(2),
                setdomainname(2);
              * perform privileged syslog(2) operations (since Linux 2.6.37,
                CAP_SYSLOG should be used to permit such operations);
              * perform VM86_REQUEST_IRQ vm86(2) command;
              * perform IPC_SET and IPC_RMID operations on arbitrary 
                System V IPC objects;
              * override RLIMIT_NPROC resource limit;
              * perform operations on trusted and security Extended
                Attributes (see xattr(7));
              * use lookup_dcookie(2);
*<< a lot more follows >>*
[...]
```

*实际上，功能模型提供了细粒度的权限；一种将 root 用户的（过度）巨大的权限切割成可管理的独立部分的方法。*

因此，在我们虚构的 packcap 示例的背景下理解重要的好处，考虑这一点：使用传统的 Unix 权限模型，最好的情况下，发布的二进制文件将是一个 setuid-root 二进制可执行文件；进程将以 root 权限运行。在最好的情况下，没有错误，没有安全问题（或者如果有，它们没有被发现），一切都会顺利进行-幸运的是。但是，我们不相信运气，对吧？（用李·查德的主角杰克·里彻的话来说，“希望最好，为最坏做准备”）。在最坏的情况下，代码中潜在的漏洞可以被利用，有黑客会不知疲倦地工作，直到他们找到并利用它们。整个系统可能会受到威胁。

另一方面，使用现代 POSIX 功能模型，packcap 二进制可执行文件将*不需要*设置 setuid，更不用说 setuid-root；进程将以普通权限运行。工作仍然可以完成，因为我们嵌入了*能力*来精确完成这项工作（在这个例子中，是网络数据包捕获），绝对没有其他东西。即使代码中存在可利用的漏洞，黑客可能也不会有动力去找到并利用它们；这个简单的原因是，即使他们设法获得访问权限（比如，任意代码执行赏金），他们可以利用的只是运行进程的非特权用户的帐户。这对黑客来说是没有动力的（好吧，这是一个玩笑，但其中蕴含着真理）。

想想看：Linux 功能模型是实现一个被广泛接受的安全实践的一种方式：*最小特权原则（PoLP）*：产品（或项目）中的每个模块只能访问其合法工作所需的信息和资源，而不多。

# 功能-一些血腥的细节

Linux 功能是一个相当复杂的主题。对于本书的目的，我们深入讨论了系统应用开发人员从讨论中获益所需的深度。要获取完整的详细信息，请查看这里的功能手册（7）：[`man7.org/linux/man-pages/man7/capabilities.7.html`](http://man7.org/linux/man-pages/man7/capabilities.7.html)，以及这里的内核文档：[`github.com/torvalds/linux/blob/master/Documentation/security/credentials.rst`](https://github.com/torvalds/linux/blob/master/Documentation/security/credentials.rst)

# 操作系统支持

**功能位掩码**（**s**）通常被称为**功能集**-我们将这个术语缩写为**capset**。

要使用 POSIX 功能模型的功能，首先，操作系统本身必须为其提供“生命支持”；完全支持意味着以下内容：

+   每当进程或线程尝试执行某些操作时，内核能够检查线程是否被允许这样做（通过检查线程有效 capset 中设置适当位）-请参见下一节。

+   必须提供系统调用（通常是包装器库 API），以便线程可以查询和设置其 capsets。

+   Linux 内核文件系统代码必须具有一种设施，以便可以将功能嵌入（或附加）到二进制可执行文件中（以便当文件“运行”时，进程会获得这些功能）。

现代 Linux（特别是 2.6.24 版本及以后的内核）支持所有三种，因此完全支持功能模型。

# 通过 procfs 查看进程功能

为了更详细地了解，我们需要一种快速的方法来“查看”内核并检索信息；Linux 内核的**proc 文件系统**（通常缩写为**procfs**）就提供了这个功能（以及更多）。

Procfs 是一个伪文件系统，通常挂载在/proc 上。探索 procfs 以了解更多关于 Linux 的信息是一个好主意；在 GitHub 存储库的*进一步阅读*部分中查看一些链接。

在这里，我们只关注手头的任务：要了解详细信息，procfs 公开了一个名为`/proc/self`的目录（它指的是当前进程的上下文，有点类似于 OOP 中的*this*指针）；在它下面，一个名为*status*的伪文件揭示了有关所讨论的进程（或线程）的有趣细节。进程的 capsets 被视为“Cap*”，所以我们只需按照这个模式进行 grep。在下一段代码中，我们对一个常规的非特权进程（*grep*本身通过*self*目录）以及一个特权（root）进程（*systemd/init PID 1*）执行此操作，以查看差异：

进程/线程 capsets：常规进程（如 grep）：

```
$ grep -i cap /proc/self/status 
CapInh:    0000000000000000
CapPrm:    0000000000000000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000
```

进程/线程 capsets：特权（root）进程（如 systemd/init PID 1）：

```
$ grep -i cap /proc/1/status 
CapInh:    0000000000000000
CapPrm:    0000003fffffffff
CapEff:    0000003fffffffff
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000
$ 
```

在一个表中列举：

| **线程能力集（capset）** | **非特权任务的典型值** | **特权任务的典型值** |
| --- | --- | --- |
| CapInh（继承） | `0x0000000000000000` | `0x0000000000000000` |
| CapPrm（允许） | `0x0000000000000000` | `0x0000003fffffffff` |
| CapEff（有效） | `0x0000000000000000` | `0x0000003fffffffff` |
| CapBnd（有界） | `0x0000003fffffffff` | `0x0000003fffffffff` |
| CapAmb（环境） | `0x0000000000000000` | `0x0000000000000000` |

（此表描述了 Fedora 27/Ubuntu 17.10 Linux 在 x86_64 上的输出）。

广义上，有两种类型的*能力集*：

+   线程能力集

+   文件能力集

# 线程能力集

在线程 capsets 中，实际上有几种类型。

Linux 每个**线程**的能力集：

+   **允许（Prm）：**线程的有效能力的整体限制*超集*。如果一个能力被丢弃，它就永远无法重新获得。

+   **可继承（Inh）：**这里的继承是指在*exec*操作中吸收 capset 属性。当一个进程执行另一个进程时，capsets 会发生什么？（关于 exec 的详细信息将在后面的章节中处理。现在，可以说如果 bash 执行 vi，那么我们称 bash 为前任，vi 为继任）。

继任进程是否会继承前任的 capsets？是的，继承的是*可继承的 capset*。从前面的表中，我们可以看到对于非特权进程，继承的 capset 都是零，这意味着在执行操作中没有能力被继承。因此，如果一个进程想要执行另一个进程，并且（继任）进程必须以提升的特权运行，它应该使用环境能力。

+   **有效（Eff）：**这些是内核在检查给定线程的权限时实际使用的能力。

+   **环境（Amb）：**（从 Linux 4.3 开始）。这些是在执行操作中继承的能力。位必须同时存在（设置为 1）在允许和可继承的 capsets 中，只有这样它才能是“环境”。换句话说，如果一个能力从 Prm 或 Inh 中清除，它也会在 Amb 中清除。

如果执行了一个*set[u|g]id*程序或者一个带有*文件能力*（我们将会看到）的程序，环境集会被清除。通常，在执行期间，环境 capset 会被添加到 Prm 并分配给继任进程的 Eff。

+   **边界（Bnd）：**这个 capset 是在执行期间赋予进程的能力的一种*限制*方式。它的效果是：

+   当进程执行另一个进程时，允许的集合是原始允许和有界 capset 的 AND 运算：*Prm = Prm* AND *Bnd.* 这样，你可以限制继任进程的允许 capset。

+   只有在边界集中的能力才能被添加到可继承的 capset 中。

+   此外，从 Linux 2.6.25 开始，能力边界集是一个每个线程的属性。

执行程序不会对 capsets 产生影响，除非以下情况之一成立：

+   继承者是一个 setuid-root 或 setgid 程序

+   文件能力设置在被执行的二进制可执行文件上

这些线程 capsets 如何以编程方式查询和更改？这正是*capget(2)*和*capset(2)*系统调用的用途。然而，我们建议使用库级别的包装 API *cap_get_proc(3)*和*cap_set_proc(3)*。

# 文件能力集

有时，我们需要能力将能力“嵌入”到二进制可执行文件中（关于这一点的讨论在下一节中）。这显然需要内核文件系统支持。在早期的 Linux 中，这个系统是一个内核可配置选项；从 Linux 内核 2.6.33 开始，文件能力总是编译到内核中，因此总是存在。

文件 capsets 是一个强大的安全功能——你可以说它们是旧的*set[u|g]id*功能的现代等价物。首先，要使用它们，操作系统必须支持它们，并且进程（或线程）需要`CAP_FSETCAP`能力。这是关键：（之前的）线程 capsets 和（即将到来的）文件 capsets 最终确定了*exec*操作后线程的能力。

以下是 Linux 文件能力集：

+   允许（Prm）：自动允许的能力

+   可继承（Inh）

+   有效（Eff）：这是一个单一的位：如果设置，新的 Prm capset 会在 Eff 集中提升；否则，不会。

再次理解上述信息提供的警告：这不是完整的细节。要获取它们，请在这里查看关于 capabilities(7)的 man 页面：[`linux.die.net/man/7/capabilities`](https://linux.die.net/man/7/capabilities)。

这是来自该 man 页面的截图片段，显示了*exec*操作期间确定能力的算法：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/f94536e7-3ae1-470b-82bb-4a039d23102c.png)

# 将能力嵌入程序二进制文件

我们已经了解到，能力模型的细粒度是与旧式的仅限 root 或 setuid-root 方法相比的一个主要安全优势。因此，回到我们的虚构的 packcap 程序：我们想要使用*能力*，而不是 setuid-root。因此，经过仔细研究可用的能力，我们得出结论，我们希望将以下能力赋予我们的程序：

+   `CAP_NET_ADMIN`

+   `CAP_NET_RAW`

查看 credentials(7)的 man 页面会发现，第一个给予进程执行所有必需的网络管理请求的能力；第二个给予使用“原始”套接字的能力。

但是开发人员如何将这些所需的能力嵌入到编译后的二进制可执行文件中呢？啊，这很容易通过`getcap(8)`和`setcap(8)`实用程序实现。显然，你使用`getcap(8)`来查询给定文件的能力，使用`setcap(8)`*在给定文件上设置它们*。

“如果尚未安装，请在系统上安装 getcap(8)和 setcap(8)实用程序（本书的 GitHub 存储库提供了必需和可选软件包的列表）”

警惕的读者会注意到这里有些可疑：如果你能够任意设置二进制可执行文件的能力，那么安全在哪里？（我们可以在文件/bin/bash 上设置`CAP_SYS_ADMIN`，它现在将以 root 身份运行。）因此，事实是，只有在文件上已经具有`CAP_FSETCAP`能力时，才能在文件上设置能力；从手册中得知：

```
CAP_SETFCAP (since Linux 2.6.24)
              Set file capabilities.
```

实际上，实际上，你会以 root 身份通过 sudo(8)执行 setcap(8)；这是因为只有在以 root 权限运行时才能获得 CAP_SETFCAP 能力。

因此，让我们做一个实验：我们构建一个简单的`hello world`程序（`ch8/hello_pause.c`）；唯一的区别是这样：我们在`printf`之后调用`pause(2)`系统调用；`pause`会使进程休眠（永远）：

```
int main(void)
{
    printf("Hello, Linux System Programming, World!\n");
    pause();
    exit(EXIT_SUCCESS);
}
```

然后，我们编写另一个 C 程序来*查询*任何给定进程上的功能；`ch8/query_pcap.c`的代码：

```
[...]
#include <sys/capability.h>

int main(int argc, char **argv)
{
    pid_t pid;
    cap_t pcaps;
    char *caps_text=NULL;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s PID\n"
                " PID: process to query capabilities of\n"
                , argv[0]);
        exit(EXIT_FAILURE);
    }
    pid = atoi(argv[1]);

    [...]
    pcaps = cap_get_pid(pid);
    if (!pcaps)
        FATAL("cap_get_pid failed; is process %d valid?\n", pid);

    caps_text = cap_to_text(pcaps, NULL);
    if (!caps_text)
        FATAL("caps_to_text failed\n", argv[1]);

    printf("\nProcess %6d : capabilities are: %s\n", pid, caps_text);
    cap_free(caps_text);
    exit (EXIT_SUCCESS);
}
```

很简单：`cap_get_pid(3)` API 返回功能状态，基本上是目标进程的`capsets`。唯一的麻烦是它是通过一个叫做`cap_t`的内部数据类型表示的；要读取它，我们必须将其转换为人类可读的 ASCII 文本；你猜对了，`cap_to_text (3)`*.* API 正好有这个功能。我们使用它并打印结果。（嘿，注意我们必须在使用后`cap_free(3)`释放变量；手册告诉我们这一点。）

这些与功能有关的 API 中的一些（广义上的`cap_*`）需要在系统上安装`libcap`库。如果尚未安装，请使用您的软件包管理器进行安装（正确的软件包通常称为`libcap-dev[el*]`）。显然，您必须链接`libcap`库（我们在 Makefile 中使用`-lcap`来这样做）。

让我们试一试：

```
$ ./query_pcap 
Usage: ./query_pcap PID
 PID: process to query capabilities of
$ ./query_pcap 1
Process      1 : capabilities are: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
$ 
```

进程 PID 1，传统上（Sys V）是*init*，但现在是`systemd`，以*root*权限运行；因此，当我们使用我们的程序查询其 capsets（实际上，我们得到的是有效的 capset 返回），我们得到了一个相当长的功能列表！（如预期的那样。）

接下来，我们在后台构建和运行`hello_pause`进程；然后我们查询它的功能：

```
$ make hello_pause
gcc -Wall   -c -o hello_pause.o hello_pause.c
gcc -Wall -o hello_pause hello_pause.c common.o
$ ./hello_pause &
[1] 14303
Hello, Linux System Programming, World!
$ ./query_pcap 14303
Process  14303 : capabilities are: =
$ 
```

我们的`hello_pause`进程当然是没有特权的，也没有任何功能嵌入其中；因此，如预期的那样，我们看到它*没有*功能。

现在是有趣的部分：首先，我们使用`setcap(8)`实用程序将功能嵌入到我们的`hello_pause`二进制可执行文件中：

```
$ setcap cap_net_admin,cap_net_raw+ep ./hello_pause
unable to set CAP_SETFCAP effective capability: Operation not permitted
$ sudo setcap cap_net_admin,cap_net_raw+ep ./hello_pause
[sudo] password for <xyz>: xxx
$ 
```

这是有道理的：作为`root`（从技术上讲，现在我们明白了，具有`CAP_SYS_ADMIN`功能），我们当然具有`CAP_SETFCAP`功能，因此成功使用`setcap(8)`。从语法上讲，我们需要指定给`setcap(8)`一个功能列表，后面跟着一个操作列表；以前，我们已经指定了`cap_net_admin,cap_net_raw`功能，以及*添加到有效和允许*作为操作列表（使用`+ep`语法）。

现在，我们重新尝试我们的小实验：

```
$ ./hello_pause &
[2] 14821
Hello, Linux System Programming, World!
$ ./query_pcap 14821
Process  14821 : capabilities are: = cap_net_admin,cap_net_raw+ep
$ 
```

是的！*新的*`hello_pause`进程确实具有我们希望它具有的功能。

如果传统的 setuid-root 和现代（文件）功能都嵌入到一个二进制可执行文件中会发生什么？嗯，在这种情况下，运行时*只有文件中嵌入的功能*会生效；进程的 EUID 为 0，但*不会*具有完整的*root*功能。

# 功能愚蠢的二进制

不过，注意一下：上面的`hello_pause`程序*实际上并不知道*它实际上具有这些功能；换句话说，它在程序上并没有做任何事情来查询或设置自己的 POSIX 功能。然而，通过文件功能模型（和 setcap(8)实用程序），我们已经“注入”了功能。*这种类型的二进制因此被称为* **功能愚蠢的二进制***。*

从安全性的角度来看，这仍然远远优于使用笨拙的 setuid-root，但如果应用程序本身在运行时使用 API 来查询和设置功能，它可能会变得更加“智能”。我们可以将这种类型的应用程序视为**功能智能二进制*****。

通常，在移植传统的 setuid-root（或更糟糕的，只是*root*）类型的应用程序时，开发人员会剥离它的 setuid-root 位，从二进制文件中删除*root*所有权，然后通过运行 setcap(8)将其转换为*功能愚蠢*二进制。这是迈向更好安全性（或“加固”）的第一步。

# Getcap 和类似的实用程序

`getcap(8)`实用程序可用于查找嵌入在（二进制）*文件*中的功能。作为一个快速的例子，让我们在 shell 程序和 ping 实用程序上运行`getcap`：

```
$ getcap /bin/bash
$ getcap /usr/bin/ping
/usr/bin/ping = cap_net_admin,cap_net_raw+p
$ 
```

很明显，bash 没有任何文件 capsets——这正是我们所期望的。另一方面，Ping 有，因此它可以在不需要 root 特权的情况下执行其职责。

通过一个 bash 脚本（类似于我们在上一章中看到的）充分演示了`getcap`实用程序的用法：`ch8/show_caps.sh`。运行它以查看系统上安装的各种嵌入文件能力的程序（留作读者的一个简单练习）。

与`getcap(8)`类似的是`capsh(1)`实用程序——一个**capability shell wrapper**；查看其手册页以获取详细信息。

与我们编写的`query_pcap`程序类似的是`getpcaps(1)`实用程序。

# Wireshark——一个典型案例

因此：我们在本主题开头编写的故事并非完全虚构——好吧，它确实是，但它有一个引人注目的现实世界平行：著名的*Wireshark*（以前称为 Ethereal）网络数据包嗅探器和协议分析器应用程序。

在旧版本中，Wireshark 曾作为`setuid-root`进程运行，以执行数据包捕获。

现代版本的 Wireshark 将数据包捕获分离到一个名为**dumpcap1**的程序中。它不作为 setuid-root 进程运行，而是嵌入了所需的能力位，使其具有执行其工作所需的特权——数据包捕获。

现在黑客成功攻击它的潜在回报大大降低了——黑客最多只能获得运行 Wireshark 的用户和 wireshark 组的特权（EUID，EGID）而不是*root*！我们使用*ls(1)*和*getcap(1)*来查看这一点，如下所示：

```
$ ls -l /bin/dumpcap
-rwxr-x---. 1 root wireshark 107K Jan 19 19:45 /bin/dumpcap
$ getcap /bin/dumpcap
/bin/dumpcap = cap_net_admin,cap_net_raw+ep
$ 
```

请注意，在上面的长列表中，其他（O）访问类别没有权限；只有 root 用户和 Wireshark 成员可以执行 dumpcap(1)。（不要以 root 身份执行它；那样你将打败整个安全性的目的）。

FYI，实际的数据包捕获代码在一个名为`pcap—packet` capture 的库中：

```
# ldd /bin/dumpcap | grep pcap
    libpcap.so.1 => /lib64/libpcap.so.1 (0x00007f9723c66000)
# 
```

供您参考：Red Hat 发布的安全公告详细介绍了 wireshark 的安全问题：[`access.redhat.com/errata/RHSA-2012:0509`](https://access.redhat.com/errata/RHSA-2012:0509)。以下摘录证明了一个重要观点：

...在 Wireshark 中发现了几个缺陷。如果 Wireshark 从网络上读取了格式不正确的数据包或打开了恶意的转储文件，它可能会崩溃，甚至可能**以运行 Wireshark 的用户的身份执行任意代码**。（CVE-2011-1590，CVE-2011-4102，CVE-2012-1595）...

突出显示的文本很关键：即使黑客成功执行任意代码，它也将以运行 Wireshark 的用户的特权而不是 root 特权执行！

关于如何使用 POSIX 功能设置 W*ireshark*的详细信息在这里（在名为*GNU/Linux distributions*的部分下）：[`wiki.wireshark.org/CaptureSetup/CapturePrivileges`](https://wiki.wireshark.org/CaptureSetup/CapturePrivileges)。

现在应该很清楚了：**dumpcap**是一个*capability-dumb*二进制文件；Wireshark 进程（或文件）本身没有任何特权。安全性胜出，两全其美。

# 以编程方式设置能力

我们已经看到了如何构建一个*capability-dumb*二进制文件；现在让我们弄清楚如何在程序内部在运行时添加或删除进程（线程）能力。

getcap 的另一面当然是 setcap——我们已经在命令行上使用过这个实用程序。现在让我们使用相关的 API。

要理解的是：要使用进程 capsets，我们需要在内存中拥有所谓的“能力状态”。为了获得这个能力状态，我们使用`cap_get_proc(3)`API（当然，正如前面提到的，所有这些 API 都来自`libcap`库，我们将将其链接到其中）。一旦我们有了一个工作上下文，即能力状态，我们将使用`cap_set_flag(3)`API 来设置事务：

```
 #include <sys/capability.h>
       int cap_set_flag(cap_t cap_p, cap_flag_t flag, int ncap,
                       const cap_value_t *caps, cap_flag_value_t value);
```

第一个参数是我们从`cap_get_proc()`*得到的功能状态；*第二个参数是我们希望影响的功能集之一：有效的、允许的或继承的。第三个参数是我们用这个 API 调用操作的功能数量。第四个参数——这是我们如何识别我们希望添加或删除的功能的地方，但是如何？我们传递一个`cap_value_t`数组的指针。当然，我们必须初始化数组；每个元素都持有一个功能。最后，第五个参数`value`可以是两个值之一：`CAP_SET`用于*设置*功能，`CAP_CLEAR`用于*删除*它。

到目前为止，所有的工作都是在内存上下文中进行的——功能状态变量；它实际上并没有影响到进程（或线程）的功能集。为了实际设置进程的功能集，我们使用*cap_set_proc(3)* API：

`int cap_set_proc(cap_t cap_p);`

它的参数是我们仔细设置的功能状态变量。*现在*功能将被设置。

还要意识到，除非我们以*root*身份运行它（当然我们不会这样做——这确实是整个重点），我们不能只提高我们的功能。因此，在`Makefile`内部，一旦程序二进制文件构建完成，我们就对二进制可执行文件本身（`set_pcap`）执行`sudo setcap`，增强它的功能；我们赋予它的允许和有效功能集中的`CAP_SETUID`和`CAP_SYS_ADMIN`功能位。

下一个程序简要演示了一个进程如何添加或删除功能（当然是*在*它的允许功能集内）。当选项 1 运行时，它添加了`CAP_SETUID`功能，并通过一个简单的测试函数（`test_setuid()`）“证明”了它。这里有一个有趣的地方：由于二进制*文件*已经在其中嵌入了两个功能（我们在`Makefile`中进行了`setcap(8)`），我们实际上*需要删除*`CAP_SYS_ADMIN`功能（从它的有效集中）。

当选项 2 运行时，我们希望有两个功能——`CAP_SETUID`和`CAP_SYS_ADMIN`；它会工作，因为这些功能已经嵌入到有效和允许的功能集中。

这是`ch8/set_pcap.c`的相关代码***:***

```
int main(int argc, char **argv)
{
    int opt, ncap;
    cap_t mycaps;
 cap_value_t caps2set[2];

    if (argc < 2)
        usage(argv, EXIT_FAILURE);

    opt = atoi(argv[1]);
    if (opt != 1 && opt != 2)
        usage(argv, EXIT_FAILURE);

    /* Simple signal handling for the pause... */
    [...]

    //--- Set the required capabilities in the Thread Eff capset
    mycaps = cap_get_proc();
    if (!mycaps)
        FATAL("cap_get_proc() for CAP_SETUID failed, aborting...\n");

    if (opt == 1) {
        ncap = 1;
        caps2set[0] = CAP_SETUID;
    } else if (opt == 2) {
        ncap = 2;
        caps2set[1] = CAP_SYS_ADMIN;
    }
    if (cap_set_flag(mycaps, CAP_EFFECTIVE, ncap, caps2set,
               CAP_SET) == -1) {
        cap_free(mycaps);
        FATAL("cap_set_flag() failed, aborting...\n");
    }

/* For option 1, we need to explicitly CLEAR the CAP_SYS_ADMIN capability; this is because, if we don't, it's still there as it's a file capability embedded into the binary, thus becoming part of the process Eff+Prm capsets. Once cleared, it only shows up in the Prm Not in the Eff capset! */
    if (opt == 1) {
        caps2set[0] = CAP_SYS_ADMIN;
        if (cap_set_flag(mycaps, CAP_EFFECTIVE, 1, caps2set, 
                CAP_CLEAR) == -1) {
            cap_free(mycaps);
            FATAL("cap_set_flag(clear CAP_SYS_ADMIN) failed, aborting...\n");
        }
    }

  /* Have the caps take effect on the process.
  * Without sudo(8) or file capabilities, it fails - as expected.
  * But, we have set the file caps to CAP_SETUID (in the Makefile),
  * thus the process gets that capability in it's effective and
  * permitted capsets (as we do a '+ep'; see below):"
     *  sudo setcap cap_setuid,cap_sys_admin+ep ./set_pcap
     */
    if (cap_set_proc(mycaps) == -1) {
        cap_free(mycaps);
        FATAL("cap_set_proc(CAP_SETUID/CAP_SYS_ADMIN) failed, aborting...\n",
                (opt==1?"CAP_SETUID":"CAP_SETUID,CAP_SYS_ADMIN"));
    }
    [...]

    printf("Pausing #1 ...\n");
    pause();
    test_setuid();
    cap_free(mycaps);

    printf("Now dropping all capabilities and reverting to original self...\n");
    drop_caps_be_normal();
    test_setuid();

    printf("Pausing #2 ...\n");
    pause();
    printf(".. done, exiting.\n");
    exit (EXIT_SUCCESS);
}
```

让我们构建它：

```
$ make set_pcap
gcc -Wall -o set_pcap set_pcap.c common.o -lcap
sudo setcap cap_setuid,cap_sys_admin+ep ./set_pcap
$ getcap ./set_pcap
./set_pcap = cap_setuid,cap_sys_admin+ep
$ 
```

注意`setcap(8)`已经将文件功能嵌入到二进制可执行文件`set_pcap`中（由`getcap(8)`验证）。

试一下；我们首先用选项`2`运行它：

```
$ ./set_pcap 2 &
[1] 3981
PID   3981 now has CAP_SETUID,CAP_SYS_ADMIN capability.
Pausing #1 ...
$ 
```

`pause(2)`系统调用使进程进入睡眠状态；这是故意这样做的，以便我们可以尝试一些东西（见下一个代码）。顺便说一句，为了使用这个，程序已经设置了一些最小的信号处理；然而，这个主题将在后续章节中详细讨论。现在，只要理解暂停（和相关的信号处理）允许我们真正“暂停”进程，检查东西，一旦完成，发送一个信号继续它：

```
$ ./query_pcap 3981
Process   3981 : capabilities are: = cap_setuid,cap_sys_admin+ep
$ grep -i cap /proc/3981/status 
Name:    set_pcap
CapInh:    0000000000000000
CapPrm:    0000000000200080
CapEff:    0000000000200080
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000
$ 
```

上面，我们通过我们自己的`query_pcap`程序和 proc 文件系统检查了进程。`CAP_SETUID`和`CAP_SYS_ADMIN`功能都存在于*允许*和*有效*功能集中。

为了继续这个过程，我们发送一个信号；一个简单的方法是通过`kill(1)`命令（详细内容见后面的第十一章，*信号-第一部分*）。现在有很多东西要看：

```
$ kill %1
*(boing!)*
test_setuid:
RUID = 1000 EUID = 1000
RUID = 1000 EUID = 0
Now dropping all capabilities and reverting to original self...
test_setuid:
RUID = 1000 EUID = 1000
!WARNING! set_pcap.c:test_setuid:55: seteuid(0) failed...
perror says: Operation not permitted
RUID = 1000 EUID = 1000
Pausing #2 ...
$ 
```

有趣的**(boing!)**只是过程通知我们发生了信号处理。(忽略它。)我们调用`test_setuid()`函数，函数代码：

```
static void test_setuid(void)
{
    printf("%s:\nRUID = %d EUID = %d\n", __FUNCTION__, 
        getuid(), geteuid());
    if (seteuid(0) == -1)
        WARN("seteuid(0) failed...\n");
    printf("RUID = %d EUID = %d\n", getuid(), geteuid());
}
```

我们尝试用`seteuid(0)`代码行成为*root*（有效）。输出显示我们已经成功做到了，因为 EUID 变成了`0`。之后，我们调用`drop_caps_be_normal()`函数，它“删除”了所有功能*并*使用之前看到的`setuid(getuid())`语义将我们恢复为“我们的原始自己”；函数代码：

```
static void drop_caps_be_normal(void)
{
    cap_t none;

    /* cap_init() guarantees all caps are cleared */
    if ((none = cap_init()) == NULL)
        FATAL("cap_init() failed, aborting...\n");
    if (cap_set_proc(none) == -1) {
        cap_free(none);
        FATAL("cap_set_proc('none') failed, aborting...\n");
    }
    cap_free(none);

    /* Become your normal true self again! */
    if (setuid(getuid()) < 0)
        FATAL("setuid to lower privileges failed, aborting..\n");
}
```

程序输出确实显示我们的 EUID 现在恢复为非零（`1000`的 RUID），并且`seteuid(0)`失败，正如预期的那样（现在我们已经删除了功能和 root 权限）。

然后进程再次调用`pause(2)`（输出中的“暂停#2…”语句），以使进程保持活动状态；现在我们可以看到这个：

```
$ ./query_pcap 3981
Process   3981 : capabilities are: =
$ grep -i cap /proc/3981/status 
Name:    set_pcap
CapInh:    0000000000000000
CapPrm:    0000000000000000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000
$ 
```

确实，所有的能力都已经被放弃了。（我们把用选项`1`运行程序的测试案例留给读者。）

这里有一个有趣的观点：你可能会遇到这样的说法`CAP_SYS_ADMIN`是新的 root。真的吗？让我们来测试一下：如果我们只将`CAP_SYS_ADMIN`能力嵌入到二进制文件中，并修改代码在选项`1`下运行时不丢弃它会发生什么？乍一看，似乎这并不重要 - 我们仍然能够成功执行`seteuid(0)`，因为我们实际上是以这种能力作为根用户运行的。但是猜猜看？它不起作用！底线是：这教会我们，虽然这个说法听起来不错，但它并不完全正确！我们仍然需要`CAP_SETUID`能力来执行`set*id()`系统调用的任意使用。

我们把这个案例的代码编写和测试留给读者作为练习。

# 杂项

还有一些其他杂项，但仍然有用的观察和提示：

# ls 显示不同的二进制文件

Fedora 27（x86_64）的屏幕截图显示了`*ls* -l`在显示不同的二进制可执行文件类型时显示的漂亮颜色：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/40ef71dc-ca7b-45cc-841e-95a96ec8fdf1.png)

这些二进制文件到底是什么？让我们按照上面显示的顺序列出：

+   `dumpcap`：一个文件功能二进制可执行文件

+   `passwd`：一个`setuid-root`二进制可执行文件

+   `ping`：一个文件功能二进制可执行文件

+   `write`：一个`setgid-tty`二进制可执行文件

注意：精确的含义和着色在 Linux 发行版之间肯定会有所不同；所显示的输出来自 Fedora 27 x86_64 系统。

# 权限模型分层

现在我们已经在上一章中看到了传统的 UNIX 权限和本章中的现代 POSIX 能力模型的细节，我们对其进行了概述。现代 Linux 内核的现实情况是，传统模型实际上是建立在更新的能力模型之上的；以下表格显示了这种“分层”：

| **优缺点** | **模型/属性** |
| --- | --- |
| 更简单，更不安全 | UNIX 权限进程和带有 UID、GID 值的文件 |
|  | 进程凭证：{RUID, RGID, EUID, EGID} |
| 更复杂，更安全 | POSIX 能力 |
|  | 线程 Capsets，文件 Capsets |
|  | 每个线程：{继承的，允许的，有效的，有界的，环境的} capsets 二进制文件：{继承的，允许的，有效的} capsets |

由于这种分层，有一些观察结果需要注意：

+   在上层：看起来像一个单一的整数，进程 UID 和 GID，实际上在底层是两个整数 - 真实和有效的用户|组 ID。

+   中间层：产生四个进程凭证：{RUID, EUID, RGID, EGID}。

+   底层：这又集成到现代 Linux 内核中 POSIX 能力模型中：

+   所有内核子系统和代码现在都使用能力模型来控制和确定对对象的访问。

+   现在*root* - 实际上是“新”root - 取决于（过载的）能力位`CAP_SYS_ADMIN`的设置。

+   一旦存在`CAP_SETUID`能力，set*id()系统调用可以任意用于设置真实/有效 ID：

+   因此，您可以使 EUID = 0，依此类推。

# 安全提示

关于安全性的关键点的快速总结如下：

+   显然，尽可能不再使用过时的 root 模式；这包括（不）使用 setuid-root 程序。相反，您应该使用能力，并且只为进程分配所需的能力：

+   直接或通过`libcap(3)`API（“能力智能”二进制文件）进行编程。

+   通过二进制文件的`setcap(8)`文件功能间接设置。

+   如果上述是通过 API 路线完成的，那么一旦需要该能力，您应立即考虑放弃该能力（并且只在需要时提高它）。

+   容器：一种“热门”的相当新的技术（本质上，容器在某种意义上是轻量级虚拟机），它们被认为是“安全”的，因为它们有助于隔离运行的代码。然而，现实并不那么乐观：容器部署通常缺乏对安全性的考虑，导致高度不安全的环境。您可以通过明智地使用 POSIX 能力模型在安全方面获得很大的好处。有关如何要求 Docker（一种流行的容器技术产品）放弃能力并从而大大提高安全性的有趣的 RHEL 博客在这里详细介绍：[`rhelblog.redhat.com/2016/10/17/secure-your-containers-with-this-one-weird-trick/`](https://rhelblog.redhat.com/2016/10/17/secure-your-containers-with-this-one-weird-trick/)。

# FYI - 在内核层面

（以下段落仅供参考，如果对更深入的细节感兴趣，请查看，或者随意跳过。）

在 Linux 内核中，所有任务（进程和线程）元数据都保存在一个称为*task_struct*（也称为*进程描述符*）的数据结构中。关于 Linux 所谓的*任务的安全上下文*的信息保存在这个任务结构中，嵌入在另一个称为**cred**（缩写为**凭证**）的数据结构中。这个结构*cred*包含了我们讨论过的一切：现代 POSIX 能力位掩码（或能力集）以及传统风格的进程特权：RUID、EUID、RGID、EGID（以及 set[u|g]id 和 fs[u|g]id 位）。

我们之前看到的`procfs`方法实际上是从这里查找凭据信息。黑客显然对访问凭据结构并能够在运行时修改它感兴趣：在适当的位置填充零可以让他们获得 root 权限！这听起来离谱吗？在 GitHub 存储库的*进一步阅读*部分中查看*(一些) Linux 内核利用*。不幸的是，这种情况经常发生。

# 总结

在本章中，读者已经了解了关于现代 POSIX 能力模型（在 Linux 操作系统上）的设计和实现的重要思想。除其他事项外，我们已经介绍了什么是 POSIX 能力，以及为什么它们很重要，特别是从安全的角度来看。还介绍了将能力嵌入运行时进程或二进制可执行文件。

讨论的整个目的，始于上一章，是让应用程序开发人员认识到在开发代码时出现的关键安全问题。我们希望我们已经让您，读者，感到紧迫，当然还有处理现代安全性的知识和工具。今天的应用程序不仅仅是要工作；它们必须以安全性为考量来编写！否则……


# 第九章：进程执行

想象这样的情景：作为一个系统程序员（在 Linux 上使用 C 语言）在一个项目上工作时，有一个要求，即在图形用户界面（GUI）前端应用程序中，当最终用户点击某个按钮时，应用程序必须显示系统生成的 PDF 文档的内容。我们可以假设有一个 PDF 阅读器软件应用程序可供我们使用。但是，你要如何在 C 代码中运行它？

本章将教你如何执行这一重要任务。在这里，我们将学习一些核心的 Unix/Linux 系统编程概念：Unix `exec`模型的工作原理，前身/后继术语，以及如何使用多达七个`exec`系列 API 来使整个过程在代码中实际运行。当然，在这个过程中，会使用代码示例来清楚地说明这些概念。

简而言之，读者将学习以下关键领域：

+   `exec`操作的含义及其语义

+   测试`exec`操作

+   使用`exec`的错误和正确方式

+   使用`exec`进行错误处理

+   七个`exec`系列 API 及其在代码中的使用方法。

# 技术要求

本章的一个练习要求安装 Poppler 软件包（PDF 工具）；可以按以下方式安装：

在 Ubuntu 上：`sudo apt install poppler-utils`

在 Fedora 上：`sudo dnf install poppler-utils-<version#>`

关于 Fedora 案例：要获取版本号，只需输入上述命令，然后在输入`poppler-utils-`后按两次*Tab*键；它将自动完成并提供一个选择列表。选择最新版本并按*Enter*。

# 进程执行

在这里，我们研究 Unix/Linux 操作系统在系统程序员级别上如何执行程序。首先，我们将教你理解重要的`exec`语义；一旦这清楚了，你就可以使用`exec`系列 API 来编程。

# 将程序转换为进程

如前所述，程序是存储介质上的二进制文件；它本身是一个死对象。要运行它，使其成为一个进程，我们必须执行它。当你从 shell 中运行程序时，它确实会变得活跃并成为一个进程。

这里是一个快速示例：

```
$ ps
 PID TTY          TIME CMD
 3396 pts/3    00:00:00 bash
21272 pts/3    00:00:00 ps
$ 
```

从前面的代码中可以看出，从 shell（本身就是一个进程：bash）中运行或执行`ps(1)`程序；`ps`确实运行了；它现在是一个进程；它完成了它的工作（在这里打印出当前在这个终端会话中活动的进程），然后礼貌地死去，让我们回到 shell 的提示符。

稍加思考就会发现，要使`ps(1)`程序成为`ps`进程，操作系统可能需要做一些工作。确实如此：操作系统通过一个名为`execve(2)`的 API，一个系统调用，执行程序并最终使其成为运行中的进程。不过，现在让我们暂时把 API 放在一边，专注于概念。

# exec Unix 公理

我们在第二章中学到，即虚拟内存，一个进程可以被视为一个盒子（一个矩形），具有虚拟地址空间（VAS）；VAS 由称为段的同质区域（技术上称为映射）组成。基本上，一个进程的 VAS 由几个段组成：文本（代码）段、数据段、库（和其他）映射以及栈。为了方便起见，这里再次呈现了表示进程 VAS 的图表：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/ec63b079-fa41-4cab-be3a-c912d5369c85.png)

图 1：进程虚拟地址空间（VAS）

底端的虚拟地址为`0`，地址随着向上增加；我们有一个向上增长的堆和一个向下增长的栈。

机器上的每个进程都有这样的进程 VAS；因此，可以推断出，我们之前的小例子中的 shell，bash，也有这样的进程 VAS（以及所有其他属性，如进程标识符（PID）、打开的文件等）。

所以，让我们想象一下，shell 进程 bash 的 PID 是 3,396。现在，当我们从 shell 运行`ps`时，实际上发生了什么？

显然，作为第一步，shell 会检查`ps`是否是一个内置命令；如果是，它会运行它；如果不是，也就是我们的情况，它会继续到第二步。现在，shell 解析`PATH`环境变量，并且在`/bin`中找到了`ps`。第三步，有趣的一步！，是 shell 进程现在通过 API 执行`/bin/ps`。我们将把确切的 API 讨论留到以后；现在，我们只是把可能的 API 称为`exec`API。

不要为了树木而忘记了森林；我们现在要谈到的一个关键点是：当`exec`发生时，调用进程（bash）通过让（除其他设置外）`ps`覆盖其虚拟地址空间（VAS）来执行被调用的进程（`ps`）。是的，你没看错——Unix 和因此 Linux 上的进程执行是通过一个进程——“调用者”——被要执行的进程——“被调用者”——覆盖来实现的。

术语

这里有一些重要的术语可以帮助我们：调用`exec`（在我们的例子中是 bash）的进程被称为“前任”；被调用和执行的进程（在我们的例子中是 ps）被称为“继任”。

# exec 操作期间的关键点

以下总结了前任进程执行继任进程时需要注意的重要点：

+   继任进程覆盖（或叠加）了前任的虚拟地址空间。

+   实际上，前任的文本、数据、库和堆栈段现在被继任的替换了。

+   操作系统将负责大小调整。

+   没有创建新进程——继任现在在旧前任的上下文中运行。

+   前任属性（包括但不限于 PID 和打开文件）因此被继任者自动继承。

（敏锐的读者可能会问，为什么在我们之前的例子中，`ps`的 PID 不是 3,396？请耐心等待，我们将在 GitHub 存储库中得到确切的答案）。

+   在成功的 exec 中，没有可能返回到前任；它已经消失了。口头上说，执行 exec 就像对前任自杀一样：成功执行后，继任就是唯一留下的；返回到前任是不可能的：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/b9370fcb-5c9a-4169-a06e-d84998fdf879.png)*图 2：exec 操作*

# 测试 exec 公理

你能测试上面描述的`exec`公理吗？当然。我们可以用三种不同的方式来尝试。

# 实验 1 - 在 CLI 上，不花俏

按照以下简单的步骤：

1.  启动一个 shell（通常是一个基于 GUI 的 Linux 上的终端窗口）

1.  在窗口中，或者更准确地说，在 shell 提示符中，输入这个：

```
 $ exec ps
```

你注意到了什么？你能解释一下吗？

嘿，请先试一下，然后再继续阅读。

是的，终端窗口进程在这里是前任；在 exec 之后，它被继任进程`ps`覆盖，完成它的工作并退出（你可能没有看到输出，因为它消失得太快了）。`ps`是继任进程，当然，我们不能返回到前任（终端窗口）——`ps`已经完全替换了它的 VAS。因此，终端窗口实际上消失了。

# 实验 2 - 在 CLI 上，再次

这一次，我们会让你更容易！按照给定的步骤进行：

1.  启动一个 shell（通常是一个基于 GUI 的 Linux 上的终端窗口）。

1.  在窗口中，或者更准确地说，在 shell 提示符中，先运行`ps`，然后是`bash`——是的，我们在这里生成一个子 shell，然后再次运行`ps`。（查看下一个截图；注意原始和子 shell Bash 进程的 PID - 3,396 和 13,040）。

1.  在子 shell 中，`exec` `ps`命令；这个`ps`继任进程覆盖（或叠加）了前任进程——bash 子 shell 的进程镜像。

1.  观察输出：在`exec ps`命令输出中，`ps`的 PID 是 bash 子 shell 进程的 PID：13,040！这表明它是在该进程的上下文中运行。

1.  还要注意，现在我们又回到了原始的 bash shell 进程 PID 3,396，因为当然，我们无法返回到前身：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/1fe76029-5ac1-418b-bdac-2c603d074b07.png)

第三次实验运行很快就会开始，一旦我们有了一些`exec`API 来玩耍。

# 不归路

对于系统程序员来说，重要的是要理解，一旦`exec`操作成功，就不会返回到前身进程。为了说明这一点，考虑这里的粗略调用图：

```
main()
         foo()
              exec(something)
         bar()
```

`main()`调用`foo()`*，*它调用`exec(something)`；一旦`exec`成功，`bar()`就永远不会运行了！

为什么不呢？我们无法在前身的执行路径中到达它，因为整个执行上下文现在已经改变 - 到了后继进程的上下文（某个东西）。PID 仍然保持不变。

只有在`exec`失败时，函数`bar()`才会获得控制（当然，我们仍然会处于前身的上下文中）。

作为进一步的细节，注意`exec()`操作本身可能成功，但被执行的进程`something`失败。没关系；这不会改变语义；`bar()`仍然不会执行，因为后继者已经接管了。

# 家庭时间 - exec 家族 API

现在我们已经理解了`exec`的语义，是时候看看如何在程序中执行`exec`操作了。Unix 和 Linux 提供了几个 C API，实际上有七个，最终都是做同样的工作：它们让前身进程`exec`后继进程。

所以，有七个 API 都做同样的事情？大多数是的；因此它们被称为`exec`家族 API。

让我们来看看它们：

```
#include <unistd.h>
extern char **environ;

int execl(const char *path, const char *arg, ...);
int execlp(const char *file, const char *arg, ...);
int execle(const char *path, const char *arg, ...,
            char * const envp[]);
int execv(const char *path, char *const argv[]);
int execvp(const char *file, char *const argv[]);
int execvpe(const char *file, char *const argv[],
             char *const envp[]);
    execvpe(): _GNU_SOURCE
```

等等，虽然我们说有七个 API，但上面的列表只有六个；确实：第七个在某种意义上是特殊的，没有显示在上面。像往常一样，耐心等待一下；我们会介绍的！

事实上，尽管每个 API 最终都会执行相同的工作，但根据您所处的情况（方便性），使用特定的 API 会有所帮助。让我们不要挑剔，至少现在，忽略它们的差异；相反，让我们专注于理解第一个；其余的将自动而轻松地跟随。

看看第一个 API，`execl(3)`：

```
int execl(const char *path, const char *arg, ...);
```

它需要两个、三个还是更多的参数？如果你对此还不熟悉，省略号`...`表示可变参数列表或`varargs`，这是编译器支持的一个特性。

第一个参数是您想要执行的应用程序的路径名。

从第二个参数开始，`varargs`，传递给后继进程的参数包括`argv[0]`。想想，在上面的简单实验中，我们通过 shell 进程在命令行上传递了参数；实际上，真正传递给后继进程所需参数的是前身，也就是 shell 进程。这是有道理的：除了前身，谁还会传递参数给后继者呢？

编译器如何知道你何时传递参数？简单：你必须用空指针终止参数列表：`execl(const char *pathname_to_successor_program, const char *argv0, const char *argv1, ..., const char *argvn, (char *)0);`

现在你可以看到为什么它被命名为`execl`：当然，`execl` API 执行`exec`；最后一个字母`l`表示长格式；后继进程的每个参数都传递给它。

为了澄清这一点，让我们写一个简单的示例 C 程序；它的工作是调用`uname`进程：

为了可读性，这里只显示了代码的相关部分；要查看和运行它，整个源代码在这里可用：[`github.com/PacktPublishing/Hands-on-System-Programming-with-Linux`](https://github.com/PacktPublishing/Hands-on-System-Programming-with-Linux)。

```
int main(int argc, char **argv)
{
    if (argc < 2) {
        [...]
    }

    /* Have us, the predecessor, exec the successor! */
    if (execl("/bin/uname", "uname", argv[1], (char *)0) == -1)
        FATAL("execl failed\n");

    printf("This should never get executed!\n");
    exit (EXIT_SUCCESS);
}
```

以下是一些需要注意的要点：

+   `execl` API 的第一个参数是继承者的路径名。

+   第二个参数是程序的名称。小心：一个相当典型的新手错误是漏掉它！

+   在这种简单的情况下，我们只传递用户发送的参数`argv[1]`：`-a`或`-r`；我们甚至没有进行健壮的错误检查，以确保用户传递了正确的参数（我们把它留给你作为练习）。

+   如果我们只尝试用一个单独的`0`来进行空终止，编译器会抱怨，警告如下（这可能取决于你使用的`gcc`编译器版本）：

`warning: missing sentinel in function call [-Wformat=]`。

为了消除警告，你必须像代码中所示的那样用`(char *)`对`0`进行强制转换。

+   最后，我们使用`printf()`来演示控制永远不会到达它。为什么呢？嗯，想想看：

+   要么`execl`成功；因此继承者进程（`uname`）接管。

+   或者`execl`失败；`FATAL`宏执行错误报告并终止前身。

让我们构建并尝试一下：

```
$ ./execl_eg
Usage: ./execl_eg {-a|-r}
 -a : display all uname info
 -r : display only kernel version
$
```

传递一个参数；我们在这里展示一些例子：

```
$ ./execl_eg -r
4.13.0-36-generic
$ ./execl_eg -a
Linux seawolf-mindev 4.13.0-36-generic #40-Ubuntu SMP Fri Feb 16 20:07:48 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
$ ./execl_eg -eww
uname: invalid option -- 'e'
Try 'uname --help' for more information.
$ 
```

它确实有效（尽管，正如从最后一个案例中可以看到的那样，`execl_eg`程序的参数错误检查并不好）。

我们鼓励你自己尝试这个简单的程序；事实上，多做一些实验：例如，将第一个参数更改为一些未知的内容（例如`/bin/oname`）并看看会发生什么。

# 错误的方法

有时，为了展示正确的做法，首先看看错误的做法是有用的！

# 错误处理和 exec

一些程序员炫耀：他们不使用*if*条件来检查`exec` API 是否失败；他们只是在`exec`后写下一行代码作为失败情况！

例如，拿前面的程序，但将代码更改为这样，这是错误的做法：

```
execl("/bin/uname", "uname", argv[1], (char *)0);
FATAL("execl failed\n");
```

它有效，是的：控制将永远到达`'FATAL()'`行的唯一原因是 exec 操作失败。这听起来很酷，但请不要这样编码。要专业一点，遵循规则和良好的编码风格指南；你会成为一个更好的程序员并为此感到高兴！（一个无辜的新手程序员甚至可能没有意识到上面的`execl`之后是实际的错误处理；谁能怪他呢？他可能会尝试在那里放一些业务逻辑！）

# 传递零作为参数

假设我们有一个（虚构的）要求：从我们的 C 代码中，我们必须执行程序`/projectx/do_this_now`并传递三个参数：`-1`，`0`和`55`。就像这样：

`/projectx/do_this_now -1 0 55`

回想一下`exec` API 的语法：

`execl(const char *pathname_to_successor_program, const char *argv0, const char *argv1, ..., const char *argvn, (char *)0);`

所以，这似乎相当琐碎；让我们做吧：

`execl("/projectx/do_this_now", "do_this_now", -1, 0, 55, (char *)0);`

哎呀！编译器会，或者*可能*会，将继承者的第二个参数`0`（在`-1`之后）解释为`NULL`终结符，因此不会看到后面的参数`55`。

修复这很容易；我们只需要记住*每个传递给继承者进程的参数都是字符指针类型*，而不是整数；`NULL`终结符本身是一个整数（尽管为了让编译器满意，我们将其强制转换为`(char *)`），就像这样：

`execl("/projectx/do_this_now", "do_this_now", "-1", "0", "55", (char *)0);`

# 指定继承者的名称

不，我们这里不是在讨论如何黑掉谁将继承伊丽莎白二世王位的问题，抱歉。我们所指的是：如何正确指定继承进程的名称；也就是说，我们是否可以以编程方式将其更改为我们喜欢的任何内容？

乍一看，它看起来确实很琐碎：`execl`的第二个参数是要传递给后继的`argv[0]`参数；实际上，它看起来像是它的名称！所以，让我们试一试：我们编写了一对 C 程序；第一个程序，前身（`ch9/predcs_name.c`）从用户那里传递一个名称参数。然后通过`execl`执行我们的另一个程序`successor_setnm`，并将用户提供的名称作为第一个参数传递给后继（在 API 中，它将后继的`argv[0]`参数设置为前身的`argv[1]`），如下所示：`execl("./successor_setnm", argv[1], argv[1], (char *)0);`

回想一下`execl`的语法：`execl(pathname_to_successor_program, argv0, argv1, ..., argvn, 0);`

因此，这里的想法是：前身已将后继的`argv[0]`值设置为`argv[1]`，因此后继的名称应该是前身的`argv[1]`。然而，它并没有成功；请看一次运行的输出：

```
$ ./predcs_name 
Usage: ./predcs_name {successor_name} [do-it-right]
$ ./predcs_name UseThisAsName &
[1] 12571
UseThisAsName:parameters received:
argv[0]=UseThisAsName
argv[1]=UseThisAsName
UseThisAsName: attempt to set name to 1st param "UseThisAsName" [Wrong]
UseThisAsName: pausing now...
$ 
$ ps
 PID TTY          TIME CMD
 1392 pts/0    00:00:01 Bash
12571 pts/0    00:00:00 successor_setnm
12576 pts/0    00:00:00 ps
$ 
```

我们故意让后继进程调用`pause(2)`系统调用（它只是导致它休眠，直到它收到一个信号）。这样，我们可以在后台运行它，然后运行`ps`来查找后继 PID 和名称！

有趣的是：我们发现，虽然在`ps`输出中名称不是我们想要的（上面），但在`printf`中是正确的；这意味着`argv[0]`已经正确接收并设置为后继。

好的，我们必须清理一下；现在让我们杀死后台进程：

```
$ jobs
[1]+  Running                 ./predcs_name UseThisAsName &
$ kill %1
[1]+  Terminated              ./predcs_name UseThisAsName
$ 
```

因此，现在显而易见的是，我们之前所做的还不够：为了在操作系统层面反映我们想要的名称，我们需要一种替代的 API；这样的 API 之一是`prctl(2)`系统调用（甚至是`pthread_setname_np(3)`线程 API）。在这里不详细介绍，我们使用`PR_SET_NAME`参数（通常，请参阅`prctl(2)`的 man 页面以获取完整详情）。因此，使用`prctl(2)`系统调用的正确代码（仅显示`successor_setnm.c`中的相关代码片段）如下：

```
[...]
    if (argc == 3) { /* the "do-it-right" case! */
        printf("%s: setting name to \"%s\" via prctl(2)"
                " [Right]\n", argv[0], argv[2]);
        if (prctl(PR_SET_NAME, argv[2], 0, 0, 0) < 0)
            FATAL("prctl failed\n");
    } else { /* wrong way... */
        printf("%s: attempt to implicitly set name to \"%s\""
            " via the argv[0] passed to execl [Wrong]\n",
            argv[0], argv[1]);
    }
[...]
$ ./predcs_name 
Usage: ./predcs_name {successor_name} [do-it-right]
$ 
```

所以，我们现在以正确的方式运行它（逻辑涉及传递一个可选的第二个参数，该参数将用于“正确”设置后继进程的名称）：

```
$ ./predcs_name NotThis ThisNameIsRight &
[1] 12621
ThisNameIsRight:parameters received:
argv[0]=ThisNameIsRight
argv[1]=NotThis
argv[2]=ThisNameIsRight
ThisNameIsRight: setting name to "ThisNameIsRight" via prctl(2) [Right]
ThisNameIsRight: pausing now...
$ ps
 PID TTY          TIME CMD
 1392 pts/0    00:00:01 Bash
12621 pts/0    00:00:00 ThisNameIsRight
12626 pts/0    00:00:00 ps
$ kill %1
[1]+  Terminated              ./predcs_name NotThis ThisNameIsRight
$ 
```

这次它的工作完全符合预期。

# 剩下的 exec 系列 API

很好，我们已经详细介绍了如何正确和不正确地使用`exec` API 系列中的第一个`execl(3)`。剩下的呢？让我们来看看它们；为了方便读者，以下是列表：

```
#include <unistd.h>
extern char **environ;

int execl(const char *path, const char *arg, ...);
int execlp(const char *file, const char *arg, ...);
int execle(const char *path, const char *arg, ...,
            char * const envp[]);
int execv(const char *path, char *const argv[]);
int execvp(const char *file, char *const argv[]);
int execvpe(const char *file, char *const argv[],
             char *const envp[]);
    execvpe(): _GNU_SOURCE
```

正如多次提到的，`execl`的语法是这样的：`execl(const char *pathname_to_successor_program, const char *argv0, const char *argv1, ..., const char *argvn, (char *)0);`

记住，它的名字是`execl`；`l`意味着长格式可变参数列表：后继进程的每个参数依次传递给它。

现在让我们看看家族中的其他 API。

# execlp API

`execlp`是`execl`的一个小变体：

`int **execlp**(const char ***file**, const char *arg, ...);`

与之前一样，`execlp`中的`l`意味着长格式可变参数列表；`p`意味着环境变量`PATH`用于搜索要执行的程序。您可能知道，PATH 环境变量由一组以冒号（`:`）分隔的目录组成，用于搜索要运行的程序文件；第一个匹配项是要执行的程序。

例如，在我们的 Ubuntu VM 上（我们以用户`seawolf`登录）：

```
$ echo $PATH
/home/seawolf/bin:/home/seawolf/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
$ 
```

因此，如果您通过`execlp`执行一个进程，您不需要给出绝对或完整的路径名作为第一个参数，而只需要给出程序名；看看以下两个示例的区别：

`execl("/bin/uname", "uname", argv[1], (char *)0);`

`**execlp**("uname", "uname", argv[1], (char *)0);`

使用`execl`，您必须指定`uname`的完整路径名；使用`execlp`，您不需要；库例程将执行查找 PATH 和找到`uname`的匹配的工作！（它会在`/bin`中找到第一个匹配项）。

使用`which`工具来定位一个程序，实际上是在路径中找到它的第一个匹配项。例如：

`$ which uname`

`/bin/uname`

`$`

这个`execlp`自动搜索路径的事实确实很方便；但需要注意的是，这可能会牺牲安全性！

黑客编写称为特洛伊木马的程序——基本上是假装成其他东西的程序；这显然是危险的。如果黑客能够在你的家目录中放置一个`uname`的特洛伊木马版本，并修改 PATH 环境变量以首先搜索你的家目录，那么当你（以为）运行`uname`时，他们就可以控制你。

出于安全原因，最好在执行程序时指定完整的`pathname`（因此，避免使用`execlp`、`execvp`和`execvpe`API）。

如果 PATH 环境变量未定义会怎么样？在这种情况下，API 会默认搜索进程的当前工作目录（`cwd`）以及一个叫做`confstr`路径，通常默认为目录`/bin`，然后是`/usr/bin`。

# execle API

现在是关于`execle(3)`的 API；它的签名是：

`int **execle**(const char *path, const char *arg, ...,char * const envp[]);`

和之前一样，`execle`中的`l`表示长格式可变参数列表；`e`表示我们可以传递一个环境变量数组给后续进程。

进程环境由一组`<name>=<value>`变量对组成。环境实际上对每个进程都是唯一的，并存储在进程堆栈段中。你可以通过`printenv`、`env`或`set`命令（`set`是一个 shell 内置命令）来查看整个列表。在程序中，使用`extern char **environ`来访问进程的环境。

默认情况下，后继进程将继承前驱进程的环境。如果这不是所需的，该怎么办；例如，我们想要执行一个进程，但更改 PATH 的值（或者引入一个新的环境变量）。为此，前驱进程将复制环境，根据需要修改它（可能添加、编辑、删除变量），然后将指向新环境的指针传递给后继进程。这正是最后一个参数`char * const envp[]`的用途。

旧的 Unix 程序曾经接受`main()`的第三个参数：`char **arge`，表示进程环境。现在这被认为是不推荐的；应该使用`extern environ`代替。

没有机制只传递一些环境变量给后续进程；整个一堆环境变量——以字符串的二维数组形式（本身是`NULL`结尾）必须被传递。

# execv API

*execv(3)* API 的签名是：

`int **execv**(const char *path, char *const argv[]);`

可以看到，第一个参数是后继进程的路径名。第二个参数与上面的环境列表类似，是一个二维字符串数组（每个字符串都以`NULL`结尾），保存所有要传递给后继进程的参数，从`argv[0]`开始。想想看，这与我们 C 程序员如此习惯的东西是一样的；这就是 C 中`main()`函数的签名：

`int main(int argc, char *argv[]);`

`argc`，当然，是接收到的参数数量，包括程序名称本身（保存在`argv[0]`中），而**`argv`**是指向一个二维字符串数组的指针（每个字符串都以`NULL`结尾），保存从`argv[0]`开始的所有参数。

因此，我们口头上称之为短格式（与之前使用的长格式`l`风格相对）。当你看到`v`（代表 argv）时，它代表短格式参数传递风格。

现在，剩下的两个 API 很简单：

+   `execvp(3)`：短格式参数，以及被搜索的路径。

+   `execvpe(3)`：短格式参数，正在搜索的路径，以及显式传递给后继的环境列表。此外，这个 API 要求定义特性测试宏`_GNU_SOURCE`（顺便说一句，在本书的所有源代码中我们都这样做）。

带有`p`的`exec`函数——搜索`PATH`的函数——`execlp`、`execvp`和`execvpe`具有一个额外的特性：如果它们正在搜索的文件被找到但没有权限打开它，它们不会立即失败（就像其他`exec` API 会失败并将`errno`设置为`EACCESS`一样）；相反，它们将继续搜索`PATH`的其余部分以寻找文件。

# 在操作系统级别执行

到目前为止，我们已经涵盖了七个*exec API 家族*中的六个。最后，第七个是`execve(2)`。你注意到了吗？括号中的`2`表示它是一个系统调用（回想一下第一章中关于系统调用的细节）。

事实上，所有前面的六个`exec` API 都在`glibc`库层内；只有`execve(2)`是一个系统调用。你会意识到，最终，要使一个进程能够执行另一个程序——从而启动或运行一个后继程序——将需要操作系统级别的支持。所以，是的，事实是，所有上述六个`exec` API 只是包装器；它们转换它们的参数并调用`execve`系统调用。

这是`execve(2)`的签名：

`int execve(const char *filename, char *const argv[], char *const envp[]);`

看一下 exec API 家族的总结表。

# 总结表 - exec API 家族

这是一个总结所有七个`exec`家族 API 的表：

| **Exec API** | **参数：长格式（l）** | **参数：短格式（v）** | **搜索路径？（p）** | **传递环境？（e）** | **API 层** |
| --- | --- | --- | --- | --- | --- |
| `execl` | Y | N | N | N | Lib |
| `execlp` | Y | N | Y | N | Lib |
| `execle` | Y | N | N | Y | Lib |
| `execv` | N | Y | N | N | Lib |
| `execvp` | N | Y | Y | N | Lib |
| `execvpe` | N | Y | Y | Y | Lib |
| `execve` | N | Y | N | Y | SysCall |

exec API 的格式：`exec<foo>`，其中`<foo>`是`{l,v,p,e}`的不同组合。

所有列出的 API，在成功时，正如我们所学的那样，都不会返回。只有在失败时，你才会看到一个返回值；根据通常的规范，全局变量`errno`将被设置以反映错误的原因，可以方便地通过`perror(3)`或`strerror(3)`API 来查找（例如，在本书提供的源代码中，查看`common.h`头文件中的`FATAL`宏）。

# 代码示例

在本章的介绍中，我们提到了一个要求：从 GUI 前端，显示系统生成的 PDF 文档的内容。让我们在这里做这个。

为此，我们需要一个 PDF 阅读器应用程序；我们可以假设我们有一个。事实上，在许多 Linux 发行版中，evince 应用程序是一个很好的 PDF 阅读器应用程序，通常预装（在 Ubuntu 和 Fedora 等发行版上是真的）。

在这里，我们不会使用 GUI 前端应用程序，我们将使用老式的 C 语言编写一个 CLI 应用程序，给定一个 PDF 文档的`路径名`，执行 evince PDF 阅读器应用程序。我们要显示哪个 PDF 文档？啊，这是一个惊喜！（看一下）：

为了可读性，只显示代码的相关部分如下；要查看和运行它，整个源代码在这里可用：

[`github.com/PacktPublishing/Hands-on-System-Programming-with-Linux`](https://github.com/PacktPublishing/Hands-on-System-Programming-with-Linux)。

```
const char *pdf_reader_app="/usr/bin/evince";
static int exec_pdf_reader_app(char *pdfdoc)
{
    char * const pdf_argv[] = {"evince", pdfdoc, 0};

    if (execv(pdf_reader_app, pdf_argv) < 0) {
        WARN("execv failed");
        return -1;
    }
    return 0; /* never reached */
}
```

我们从`main()`中调用前面的函数如下：

```
   if (exec_pdf_reader_app(argv[1]) < 0)
        FATAL("exec pdf function failed\n");
```

我们构建它，然后执行一个示例运行：

```
$ ./pdfrdr_exec
Usage: ./pdfrdr_exec {pathname_of_doc.pdf}
$ ./pdfrdr_exec The_C_Programming_Language_K\&R_2ed.pdf 2>/dev/null 
$ 
```

这是一个动作的截图！

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-sys-prog-linux/img/6ff50ecc-cff5-47a5-9b82-fc5ec961629c.png)

如果我们只在控制台上运行 Linux（没有 GUI）？那么，当然，前面的应用程序将无法工作（而且 evince 甚至可能没有安装）。这是这种情况的一个例子：

```
$ ./pdfrdr_exec ~/Seawolf_MinDev_User_Guide.pdf 
!WARNING! pdfrdr_exec.c:exec_pdf_reader_app:33: execv failed
perror says: No such file or directory
FATAL:pdfrdr_exec.c:main:48: exec pdf function failed
perror says: No such file or directory
$ 
```

在这种情况下，为什么不尝试修改上述应用程序，改用 CLI PDF 工具集呢；其中一个这样的工具集来自 Poppler 项目（见下面的注释）。其中一个有趣的实用工具是`pdftohtml`。为什么不使用它来从 PDF 文档生成 HTML 呢？我们把这留给读者作为一个练习（请参阅 GitHub 存储库上的*问题*部分）。

这些有用的 PDF 实用程序是由一个名为 Poppler 的开源项目提供的。您可以在 Ubuntu 上轻松安装这些 PDF 实用程序：`sudo apt install poppler-utils`

我们可以很容易地跟踪`pdfrdr_exec`程序中发生的情况；在这里，我们使用`ltrace(1)`来查看发出的库调用：

```
$ ltrace ./pdfrdr_exec The_C_Programming_Language_K\&R_2ed.pdf 
execv("/usr/bin/evince", 0x7ffcd861fc00 <no return ...>
--- Called exec() ---
g_static_resource_init(0x5575a5aff400, 0x7ffc5970f888, 0x7ffc5970f8a0, 32) = 0
ev_get_locale_dir(2, 0x7ffc5970f888, 0x7ffc5970f8a0, 32)                  = 0x7fe1ad083ab9
[...]
```

关键调用：当然可以看到`execv`；有趣的是，`ltrace`友好地告诉我们它没有返回值...。然后我们看到了 evince 软件本身的库 API。

如果我们使用`strace(1)`来查看发出的系统调用呢？

```
$ strace ./pdfrdr_exec The_C_Programming_Language_K\&R_2ed.pdf 
execve("./pdfrdr_exec", ["./pdfrdr_exec", "The_C_Programming_Language_K&R_2"...], 0x7fff7f7720f8 /* 56 vars */) = 0
brk(NULL)                               = 0x16c0000
access("/etc/ld.so.preload", R_OK)      = 0
openat(AT_FDCWD, "/etc/ld.so.preload", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=0, ...}) = 0
[...]
```

是的，第一个是`execve(2)`，证明了`execv(3)`库 API 调用了`execve(2)`系统调用。当然，输出的其余部分是 evince 进程执行时发出的系统调用。

# 总结

本章介绍了 Unix/Linux 的`exec`编程模型；前身和后继进程的关键概念，以及后继进程（或多或少地）如何覆盖前身。介绍了七个`exec`家族 API，以及几个代码示例。还介绍了错误处理、后继名称规范等内容。系统程序员现在将有足够的知识来编写正确执行给定程序的 C 代码。
