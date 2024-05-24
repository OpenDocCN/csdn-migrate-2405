# Python 渗透测试秘籍（一）

> 原文：[`annas-archive.org/md5/A471ED08BCFF5C02AB69EE891B13A9E1`](https://annas-archive.org/md5/A471ED08BCFF5C02AB69EE891B13A9E1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Python 是一种动态但解释性语言，属于高级编程语言。凭借其清晰的语法和丰富的库，它被用作通用语言。基于 Python 的解释性质，它经常被视为一种脚本语言。Python 在信息安全领域占主导地位，因为它不太复杂，拥有无限的库和第三方模块。安全专家更倾向于使用 Python 作为开发信息安全工具包的语言，例如 w3af、sqlmap 等。Python 的模块化设计和代码可读性使其成为安全研究人员和专家编写脚本和构建安全测试工具的首选语言。

包括模糊测试器、代理、扫描器甚至利用漏洞在内的信息安全工具都是用 Python 编写的。此外，Python 是当前几个开源渗透测试工具的语言，从用于内存分析的 volatility 到用于抽象化邮件检查过程的 libPST。对于信息安全研究人员来说，学习 Python 是正确的选择，因为有大量的逆向工程和利用库可供使用。因此，在需要扩展或调整这些工具的困难情况下，学习 Python 可能会对你有所帮助。

在本书中，我们将探讨安全研究人员如何使用这些工具和库来辅助他们的日常工作。接下来的页面将帮助你学习检测和利用各种类型的漏洞，同时增强你对无线应用和信息收集概念的了解。继续阅读，探索使用 Python 进行渗透测试的实用方法，构建高效的代码并节省时间。

# 本书涵盖内容

第一章，“渗透测试中为什么选择 Python？”，从 Python 在安全测试中的重要性开始，向读者展示如何配置基本环境。

第二章，“设置 Python 环境”，介绍了如何在不同操作系统中设置环境以开始使用它们进行渗透测试。

第三章，“使用 Python 进行网络抓取”，解码了如何使用 Python 脚本下载网页，并为你提供了网络抓取的基础知识，随后详细描述了如何使用正则表达式从下载的网页中获取信息，并且还介绍了如何请求和下载动态网站页面以爬取其中的数据。

第四章，“使用 Python 进行数据解析”，向你展示了如何使用 Python 模块解析 HTML 表格，从网站下载表格数据，并从 HTML 文档中提取数据，并使用脚本生成.csv/Excel 表格。

第五章，“使用 Scrapy 和 BeautifulSoup 进行网络抓取”，将教你如何使用 Python Scrapy 模块构建和运行网络爬虫来爬取网页。还将解释如何使用 Scrapy 的交互式 shell，在终端内快速尝试和调试你的抓取代码。它还涉及如何从 Scrapy 爬取的网页中提取链接，并使用这些链接获取网站上的更多页面。学习如何检测和遍历到其他页面的链接，并使用 Scrapy 模块从这些页面获取数据。

第六章，“使用 Python 进行网络扫描”，教授了如何创建一个扫描器来扫描 IP 的开放端口以获取详细信息，以及如何使用 Scapy 创建一个隐蔽扫描脚本。此外，还介绍了如何使用 Python 创建一个扫描一系列 IP 的脚本，以及如何使用 LanScan Python 3 模块来扫描网络。使用 LanScan，我们可以收集关于本地网络上的主机和设备的信息。

第七章，“使用 Python 进行网络嗅探”，是关于如何编写基本数据包嗅探器的详细指南，以及如何使用 Python 编写脚本来解析嗅探到的数据包，如何使用 Python 模块解析和格式化 MAC 地址，如何使用 Python 模块解码嗅探到的数据包，以及如何使用 Pyshark，一个 TShark 的 Python 封装。

第八章，“Scapy 基础”，介绍了如何使用 Scapy Python 模块创建数据包，以及如何使用 Scapy 发送数据包并接收答复。此外，还解释了如何编写脚本来从 pcap 文件中读取并使用 Scapy 模块进行写回。Scapy 主要是关于将协议层叠在一起以创建自定义数据包。本节将帮助读者更清晰地了解使用 Scapy 进行数据包层叠以及如何使用 Scapy 来嗅探网络数据包。

第九章，“Wi-Fi 嗅探”，介绍了如何使用 Python 模块编写脚本来扫描并获取可用的 Wi-Fi 设备列表。您还将学习如何使用 Python 模块编写脚本来查找隐藏的 Wi-Fi SSID，以及如何使用 Scapy 编写脚本来暴露隐藏的 SSID。此外，还介绍了如何使用 Scapy 编写脚本对隐藏的 Wi-Fi SSID 进行字典攻击，以及如何使用 Scapy 设置一个虚假的接入点。

第十章，“第 2 层攻击”，探讨了如何编写脚本来监视网络上所有新连接到特定网络的设备，并如何编写脚本来运行地址解析协议（ARP）缓存投毒攻击。您还将学习如何使用 Python Scapy 模块创建 MAC 洪水攻击的脚本，以及如何使用 Python 编写脚本来创建 VLAN 跳跃攻击。此外，我们还将介绍如何使用 Python 编写脚本来在 VLAN 跳跃中欺骗 ARP。

第十一章，“TCP/IP 攻击”，着重介绍了如何使用 Python 模块编写脚本来欺骗 IP 地址。您还将学习如何使用 Python 编写脚本来创建 SYN 洪水攻击，以及如何使用 Python 编写脚本来在局域网上嗅探密码。

第十二章，“漏洞开发简介”，将帮助您了解 CPU 寄存器及其重要性的基础知识，并解释内存转储技术以及 CPU 指令的基础知识。

第十三章，“Windows 漏洞开发”，将帮助您了解 Windows 内存布局的细节，这将有助于漏洞开发。您还将学习如何使用 Python 脚本进行缓冲区溢出攻击，并如何使用 Python 编写脚本来利用结构化异常处理（SEH）。此外，我们将详细了解如何使用 Python 编写脚本来利用 Egg Hunters 来攻击 Windows 应用程序。

第十四章，“Linux 漏洞开发”，解释了如何使用 Python 编写脚本来运行 Linux 格式字符串漏洞，以及如何在 Linux 环境中利用缓冲区溢出。

# 本书所需内容

基本上，需要安装 Python 的计算机。可以使用虚拟机来模拟易受攻击的机器和进行测试。

# 本书适合谁

这本书非常适合那些熟悉 Python 或类似语言，并且不需要基本编程概念的帮助，但希望了解渗透测试的基础知识和渗透测试人员面临的问题的人。

# 章节

在本书中，您会发现一些经常出现的标题（准备工作和操作步骤）。为了清晰地说明如何完成食谱，我们使用这些部分如下：

# 准备工作

本节告诉您在食谱中可以期待什么，并描述了为食谱设置任何软件或任何先决设置所需的方法。

# 操作步骤…

本节包含按照食谱所需的步骤。

# 约定

在本书中，您会发现许多文本样式，用于区分不同类型的信息。以下是一些样式的示例及其含义解释。文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下：“它将被提取到`Python-3.6.2`文件夹中”

代码块设置如下：

```py
import urllib.request
import urllib.parse
import re
from os.path import basename 
```

任何命令行输入或输出都是这样写的：

```py
$ sudo apt-get install python 
```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“这将显示一个选项 Package Control: Install Package。”

警告或重要提示会显示如下。

提示和技巧会显示如下。


# 第一章：为什么要在渗透测试中使用 Python？

在本章中，我们将涵盖以下内容：

+   为什么 Python 是安全脚本的绝佳选择

+   Python 3 语言基础知识和差异

# 介绍

深入研究 Python 及其模块在安全脚本编写中的用途之前，我们需要了解一下语言基础知识和不同版本。此外，如果我们能了解一下为什么 Python 是安全脚本的绝佳选择，那就太好了。

# 为什么 Python 是安全脚本的绝佳选择

在大规模安全攻击和泄露之后，安全/渗透测试在质量领域日益受到重视。作为编程领域中的一种流行语言，从过去几年出版的工具、书籍和脚本来看，Python 已经成为安全研究人员和黑客最喜欢的脚本语言。

# 准备就绪

尽管网络和应用程序安全充斥着许多自动化和半自动化测试工具，但并不总能保证成功。工具和脚本的改进是渗透测试的关键，总会有一些任务需要自动化或以其他方式完成。成为成功的现实世界渗透测试人员涉及许多自定义脚本和编程任务。

# 如何做...

这些是 Python 在安全脚本和编程中受欢迎的主要原因。

# Python 可以以解释和编译形式使用

Python 程序可以在任何需要编译的情况下编译，并且不需要频繁更改。这将使 Python 程序运行得更快，并提供更好的机会来消除漏洞和错误。此外，解释程序比编译程序运行得慢得多，并且更容易受到漏洞和攻击的影响。

Python 代码不使用编译器，可以在几乎任何运行 Python shell 的设备上运行。此外，它与脚本语言有一些其他相似之处。因此，Python 可以用于执行脚本语言的功能。

# 语法和缩进布局

Python 的语法和缩进布局使得在审查程序时很容易弄清楚发生了什么。缩进还使程序更易读，并有助于使协作编程更容易。

# 简单的学习曲线

学习一门新的编程语言总是一项艰巨的任务。但 Python 的设计是为了让即使是初学者程序员也能轻松学会。Python 之所以得到程序员的广泛接受，主要是因为它易于学习，并且其设计理念强调代码的可读性，这将帮助初学者开发人员通过阅读代码本身学到很多东西。此外，Python 的**读取评估打印循环**（**REPL**）为开发人员提供了一个机会来玩弄代码并进行实验。标准的 Python 库保留了许多功能，我们可以轻松地执行复杂的功能。

# 强大的第三方库

一旦学会了 Python，你就可以利用支持大量库的平台。**Python 软件包索引**（**PyPI**）是一个存储库，其中包含超过 85,000 个可重用的 Python 模块和脚本，你可以在你的脚本中使用。Python 是安全研究人员学习的最佳语言，因为它拥有大量的逆向工程和利用库。

# 跨平台（随处编码）

Python 可以在 Linux、Microsoft Windows、macOS X 和许多其他操作系统和设备上运行。在 macOS X 计算机上编写的 Python 程序将在 Linux 系统上运行，反之亦然。此外，只要计算机安装了 Python 解释器，Python 程序就可以在 Microsoft Windows 计算机上运行。

# Python 3 语言基础知识和差异

Python 3.0 首次发布于 2008 年。尽管 Python 3 被认为与旧版本不兼容，但许多其特性都被移植以支持旧版本。了解 Python 版本及其差异有助于更好地理解我们的配方。

# 准备就绪

如果您是 Python 的新手，可能会对可用的不同版本感到困惑。在进一步了解细节之前，让我们先看一下 Python 的最新主要版本以及 Python 2 和 Python 3 之间的主要区别。

# 如何做...

这些是主要的 Python 版本。

# Python 2

2000 年末发布，它具有许多更多的编程功能，包括帮助自动化内存管理的循环检测垃圾收集器。增加的 unicode 支持有助于标准化字符，列表推导有助于基于现有列表创建列表等其他功能。在 Python 版本 2.2 中，类型和类被合并为一个层次结构。

# Python 3

Python 3 于 2008 年末发布，以更新和修复先前版本 Python 的内置设计缺陷。Python 3 开发的主要重点是清理代码库并减少冗余。

起初，由于与 Python 2 的不兼容性，Python 3 的采用过程非常缓慢。此外，许多软件包库仅适用于 Python 2。后来，随着开发团队宣布将终止对 Python 2 的支持，并且更多的库已被移植或迁移到 Python 3，Python 3 的采用率有所增加。

# Python 2.7

Python 2.7 于 2010 年发布，并计划作为 2.x 版本的最后一个版本。其目的是通过提供两者之间的兼容性来使 Python 2.x 用户更容易将其功能和库移植到 Python 3，其中包括支持测试自动化的单元测试，用于解析命令行选项的 argparse，以及更方便的 collections 类。

# Python 2.7 和 Python 3 之间的主要区别

以下是 Python 2.x 和 Python 3 之间的一些主要区别：

+   **打印**：在 Python 2 中，`print`是一个语句。因此，打印时无需用括号括起文本。但在 Python 3 中，`print`是一个函数。因此，您必须将要打印的字符串传递给带括号的函数。

+   **整数除法**：Python 2 将小数点后没有任何数字的数字视为整数，这可能会导致在除法过程中出现一些意外的结果。

+   **列表推导循环变量泄漏**：在 Python 2 中，将列表推导中迭代的变量*泄漏*到周围范围，这个列表推导循环变量*泄漏*bug 已在 Python 3 中修复。

+   **Unicode 字符串**：Python 2 要求您使用**u**前缀显式标记 unicode 字符串。但是，Python 3 默认将字符串存储为 unicode。

+   **引发异常**：Python 3 需要不同的语法来引发异常。

从 Python 2.x 到 Python 3.x 的过渡正在缓慢进行，但正在进行中。要注意的是，Python 2.x 和 Python 3 之间存在实质性差异，因此您可能需要处理在您不太熟悉的版本中编写的代码。


# 第二章：设置 Python 环境

在本章中，我们将涵盖以下内容：

+   在 Linux 中设置 Python 环境

+   在 macOS 中设置 Python 环境

+   在 Windows 中设置 Python 环境

# 介绍

在本章中，我们将学习如何在您的计算机上设置 Python。除了 Windows 之外，大多数操作系统默认都安装了 Python 解释器。要检查 Python 解释器是否已安装，您可以打开一个命令行窗口，输入`python`并按下*Enter*键--您将得到如下结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00005.jpeg)

您可以从 Python 官方网站--[`www.python.org/`](https://www.python.org/)下载最新的 Python 二进制文件和源代码。

# 在 Linux 中设置 Python 环境

让我们逐步了解如何在 Linux 系统上设置 Python 环境。首先，我们可以学习如何安装 Python，如果它不是默认安装的。

# 准备工作

由于我们在不同风味的 Linux 发行版中有许多包管理器，如`apt`/`apt-get`和`dpkg`。对于基于 Debian 的发行版，如 Ubuntu，`yum`（Yellowdog）适用于 CentOS/RHEL，`zypper`和`yast`适用于 SuSE Linux，这些包管理器将帮助我们在 Linux 发行版中轻松安装 Python。有了这个，你只需发出一个命令，包管理器就会搜索所需的包及其依赖项，下载这些包，并将它们安装在你的系统中。

# 如何做…

首先，您必须在系统上安装 Python。

# 安装 Python

1.  如果您使用的是基于 Debian 的发行版，如 Ubuntu，您可以使用以下命令安装 Python：

```py
$ sudo apt-get install python
```

如果您的系统运行 CentOS/RHEL，请使用以下命令安装 Python：

```py
$ sudo yum install python  
```

如果是 SuSE Linux 发行版，请使用以下命令安装 Python：

```py
$ sudo yum install python 
```

1.  在终端中使用以下命令检查已安装的 Python 解释器的版本：

```py
$ python -version  
```

这将打印当前安装的 Python 版本。

1.  如果您想安装特定版本的 Python，我们可以从[`www.python.org/`](https://www.python.org/)网站下载 Python 源代码并手动安装。为此，您可以从[`www.python.org/ftp/python/`](https://www.python.org/ftp/python/)下载所需的源存档。

您可以使用以下命令下载；确保用您需要的版本号替换版本号：

```py
$ wget https://www.python.org/ftp/python/3.6.2/Python-3.6.2.tgz      
```

1.  然后，我们必须使用以下命令提取下载的存档：

```py
$ tar -xvzf Python-3.6.2.tgz    
```

它将被提取到一个`Python-3.6.2`文件夹中。

1.  现在您可以配置、构建和安装 Python，为此您需要在系统上安装 C 编译器。如果没有安装，您可以按照以下步骤进行：

+   +   对于 Debian/Ubuntu：

```py
$ sudo apt-get install gcc
```

+   +   对于 CentOs/RHEL：

```py
$ yum install gcc
```

然后，您可以运行 configure 来配置构建，然后使用`make altinstall`命令安装构建：

```py
$ cd Python-3.6.2
$ ./configure --prefix=/usr/local
$ make altinstall  
```

安装后，您可以看到系统上安装的 Python 的两个版本，并且您可以选择在运行脚本时使用哪个版本。

# 建立虚拟环境

现在您可以学习设置一个虚拟环境，这将帮助您设置一个隔离的脚本环境。这将帮助我们将不同项目所需的依赖项保持在不同的位置。此外，它有助于保持全局 site-packages 干净，并与项目依赖项分开：

1.  您可以使用`pip`在系统中安装虚拟环境模块：

```py
$ pip install virtualenv 
```

1.  然后使用以下命令测试安装：

```py
$ virtualenv --version 
```

1.  尝试在`project`文件夹内创建一个新的虚拟环境：

```py
$ mkdir new-project-folder
$ cd new-project-folder
$ virtualenv new-project
```

这将在当前目录中创建一个名为`new-project`的文件夹。

如果您想要使用您选择的 Python 解释器创建一个虚拟环境，如下所示：

```py
$ virtualenv -p /usr/bin/python3 new-project  
```

1.  您可以使用以下命令激活这个虚拟环境：

```py
$ source new-project/bin/activate  
```

1.  如果您在虚拟环境中完成了工作，可以使用以下命令停用并退出虚拟环境：

```py
$ deactivate  
```

1.  我们可以使用`virtualenvwrapper`使其更简单。`virtualenvwrapper`有助于将所有虚拟环境保存在一个地方。要安装`virtualenvwrapper`，我们可以使用`pip`命令：

```py
$ pip install virtualenvwrapper  
```

我们必须设置`WORKON_HOME`变量，该变量是保存所有虚拟环境的文件夹：

```py
$ export WORKON_HOME=~/Envs
$ source /usr/local/bin/virtualenvwrapper.sh  
```

1.  使用`virtualenvwrapper`，我们可以按以下方式创建项目：

```py
$ mkvirtualenv new-project  
```

这将在`WORKON_HOME`内创建虚拟环境，即`~/Envs`。

1.  要激活创建的项目，我们可以使用以下命令：

```py
$ workon new-project    
```

1.  更方便的是，我们可以使用以下单个命令创建虚拟环境和`project`文件夹：

```py
$ mkproject new-project    
```

1.  最后，我们可以使用`deactivate`命令退出虚拟环境。

# 设置编辑器或 IDE

最后，您需要一个文本编辑器或 IDE 来编辑脚本。由于 Python 程序只是我们可以直接编辑的文本文件，如果您没有喜欢的文本编辑器，**sublime text3**是一个不错的选择：

1.  要安装 sublime text3，您可以从[`www.sublimetext.com/3`](https://www.sublimetext.com/3)下载最新版本。

1.  您可以使用以下命令从命令行安装 sublime text3：

```py
$ sudo add-apt-repository ppa:webupd8team/sublime-text-3
$ sudo apt-get update
$ sudo apt-get install sublime-text-installer
```

1.  如果您可以为 sublime text3 安装`Anaconda`软件包，那将更好。要安装它，请使用键盘快捷键*Ctrl +Shift* + *P*，然后输入`install`。这将显示一个选项 Package Control: Install Package。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00006.jpeg)

1.  选择此选项并搜索软件包`Anaconda`。选择要安装的软件包。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00007.jpeg)

# 在 macOS 中设置 Python 环境

同样，在 Linux 环境中，macOS 也默认安装了 Python。但是，您需要了解基本的安装步骤，因为这将有助于更新和重新安装。

# 准备就绪

首先，如果您尚未安装 Xcode，请从 App Store 安装 Xcode。然后使用以下命令更新命令行工具：

```py
$ xcode-select --install 
```

此外，我们还需要安装`Homebrew`，这是 macOS 的软件包管理器，为此打开终端并输入以下命令：

```py
$ ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"  
```

# 如何做...

现在，您可以使用`Homebrew`软件包管理器在 macOS 中安装 Python。

# 安装 Python

1.  搜索`Homebrew`以查找可以安装的选项：

```py
$ brew search python 
```

这将得到以下结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00008.jpeg)

1.  要安装 Python 3，可以运行以下命令：

```py
$ brew install python3  
```

随着 Python 3 一起，`brew`将安装`pip3`和`setuptools`。

1.  要设置虚拟环境和`virtualenvwrapper`，您可以按照我们在 Linux 环境中所做的相同步骤。

1.  要安装 sublime text3，从[`www.sublimetext.com/3`](https://www.sublimetext.com/3)获取软件包并运行安装程序。配置 Sublime text 3 的其他所有内容与 Linux 环境中的相同。

# 在 Windows 中设置 Python 环境

在 Windows 中，默认情况下未安装 Python 解释器。因此，我们必须下载并安装 Python。

# 如何做...

我们可以从官方网站下载 Python 并在系统中安装它。执行以下步骤：

1.  转到 Python 的官方网站（[`python.org/download/`](http://python.org/download/)）并下载最新版本的 Windows MSI 安装程序。

1.  运行安装程序。

1.  您可以选择安装启动器供所有用户（推荐），然后单击立即安装以完成安装。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00009.jpeg)

1.  安装完成后，最好将您的版本的默认 Python 目录添加到`PATH`中。

如果您已将 Python 安装在`C:\Python36\`中，则应将以下目录添加到您的`PATH`--`C:\Python36\;C:\Python36\Scripts\`。

为此，请转到我的电脑 | 属性 | 高级系统设置 | 环境变量，并编辑`PATH`变量以添加新目录。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00010.jpeg)

1.  现在，您可以像为其他环境安装一样安装虚拟环境和`virtualenvwrapper`。

1.  此外，您还可以下载并安装 sublime text 3 作为编辑器。


# 第三章：使用 Python 进行 Web 抓取

在本章中，我们将涵盖以下配方：

+   使用 Python 脚本下载网页

+   更改用户代理

+   下载文件

+   使用正则表达式从下载的网页中获取信息

+   请求和下载动态网站页面

+   动态 GET 请求

# 介绍

Web 抓取是自动从 Web 中提取数据并以便于您轻松分析或利用的格式的过程。`urllib` Python 模块帮助您从 Web 服务器下载数据。

# 使用 Python 脚本下载网页

要从 Web 服务器下载网页，可以使用标准 Python 库的一部分的`urllib`模块。`urllib`包括用于从 URL 检索数据的函数。

# 准备就绪

要了解基础知识，我们可以使用 Python 交互式终端。在终端窗口中输入`python`并按*Enter*。这将打开 Python（Python 2.x）交互式终端。

# 如何做...

在 Python 2.x 和 Python 3.x 中执行此操作的命令存在一些差异，主要是`print`语句。因此，请注意语法上的差异。这将有助于我们即将介绍的配方。

# 使用 Python 2

1.  首先，导入所需的模块`urllib`：

```py
>>> import urllib  
```

1.  使用`urlopen`方法，您可以下载网页：

```py
>>> webpage = urllib.urlopen("https://www.packtpub.com/")  
```

1.  我们可以使用`read`方法像返回对象一样读取文件：

```py
>>> source =  webpage.read()  
```

1.  完成后关闭对象：

```py
>>>  webpage.close()  
```

1.  现在我们可以打印 HTML，它是以字符串格式存在的：

```py
>>> print source  
```

1.  更新程序以将源字符串的内容写入计算机上的本地文件非常容易：

```py
>>> f = open('packtpub-home.html', 'w')
 >>> f.write(source)
 >>> f.close  
```

# 使用 Python 3

在 Python 3 中，`urllib`和`urllib2`都是`urllib`模块的一部分，因此在使用`urllib`时存在一些差异。此外，`urllib`包含以下模块：

+   `urllib.request`

+   `urllib.error`

+   `urllib.parse`

+   `urllib.robotparser`

`urllib.request`模块用于在 Python 3 中打开和获取 URL：

1.  首先从`urllib`包中导入`urllib.request`模块：

```py
>>> import urllib.request
```

1.  使用`urlopen`方法获取网页：

```py
>>> webpage = urllib.request.urlopen("https://www.packtpub.com/")  
```

1.  使用`read`方法读取对象：

```py
>>> source =  webpage.read()  
```

1.  关闭对象：

```py
>>> webpage.close()  
```

1.  打印源码：

```py
>>> print(source)  
```

1.  您可以将源字符串的内容写入计算机上的本地文件，如下所示。确保输出文件处于二进制模式：

```py
>>> f = open('packtpub-home.html', 'wb')
 >>> f.write(source)
 >>> f.close  
```

Python 2 模块`urllib`和`urllib2`帮助执行与 URL 请求相关的操作，但两者具有不同的功能。

`urllib`提供了`urlencode`方法，用于生成`GET`请求。但是，`urllib2`不支持`urlencode`方法。此外，`urllib2`可以接受请求对象并修改 URL 请求的标头，但`urllib`只能接受 URL，并且无法修改其中的标头。

# 更改用户代理

许多网站使用用户代理字符串来识别浏览器并相应地提供服务。由于我们使用`urllib`访问网站，它不会识别此用户代理并可能以奇怪的方式行事或失败。因此，在这种情况下，我们可以为我们的请求指定用户代理。

# 如何做...

我们在请求中使用自定义用户代理字符串如下：

1.  首先，导入所需的模块：

```py
>>> import urllib.request  
```

1.  然后定义我们计划为请求指定的用户代理：

```py
>>> user_agent = ' Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0'  
```

1.  为请求设置标头：

```py
>>> headers = {'User-Agent': user_agent}  
```

1.  创建请求如下：

```py
>>> request = urllib.request.Request("https://www.packtpub.com/", headers=headers)  
```

1.  使用`urlopen`请求网页：

```py
>>> with urllib.request.urlopen(request) as response:
...     with open('with_new_user_agent.html', 'wb') as out:
...         out.write(response.read())  
```

# 下载文件

我们可以利用`requests` Python 模块下载文件。`requests`模块是 Python 中一个**简单易用**的 HTTP 库，具有各种应用。此外，它有助于与 Web 服务建立无缝的交互。

# 准备就绪

首先，您必须安装`requests`库。可以通过输入以下命令使用`pip`来完成：

```py
pip install requests  
```

# 如何做...

让我们尝试使用`requests`模块下载一个简单的图像文件。打开 Python 2：

1.  像往常一样，首先导入`requests`库：

```py
>>> import requests  
```

1.  通过将 URL 传递给`get`方法创建 HTTP 响应对象：

```py
>>> response = requests.get("https://rejahrehim.com/images/me/rejah.png")  
```

1.  现在将 HTTP 请求发送到服务器并将其保存到文件中：

```py
>>> with open("me.png",'wb') as file:
...           file.write(response.content)
```

如果是一个大文件，`response.``content`将是一个大字符串，无法将所有数据保存在一个字符串中。在这里，我们使用`iter_content`方法以块的方式加载数据。

1.  在这里，我们可以创建一个 HTTP 响应对象作为`stream`：

```py
response = requests.get("https://rejahrehim.com/images/me/rejah.png", stream = True)

```

1.  然后，发送请求并使用以下命令保存文件：

```py
>>> with open("me.png",'wb') as file:
...        for chunk in response.iter_content(chunk_size=1024):
...        if chunk:
...             file.write(chunk) 
```

这将在 Python 3 中起作用。还要确保在 Python 3 环境中安装所需的库。

# 使用正则表达式从下载的网页中获取信息

**正则表达式**（**re**）模块有助于从下载的网页中找到特定的文本模式。正则表达式可用于解析网页中的数据。

例如，我们可以尝试使用正则表达式模块下载网页中的所有图像。

# 如何做...

为此，我们可以编写一个 Python 脚本，可以下载网页中的所有 JPG 图像：

1.  在您的工作目录中创建一个名为`download_image.py`的文件。

1.  在文本编辑器中打开此文件。您可以使用 sublime text3。

1.  像往常一样，导入所需的模块：

```py
import urllib2
import re
from os.path import basename
from urlparse import urlsplit  
```

1.  像在上一个配方中那样下载网页：

```py
url='https://www.packtpub.com/'    
response = urllib2.urlopen(url)
source = response.read()
file = open("packtpub.txt", "w")
file.write(source)
file.close()  
```

1.  现在，迭代下载的网页中的每一行，搜索图像 URL，并下载它们：

```py
patten = '(http)?s?:?(\/\/[^"]*\.(?:png|jpg|jpeg|gif|png|svg))'
for line in open('packtpub.txt'):
    for m in re.findall(patten, line): 
        fileName = basename(urlsplit(m[1])[2])
        try:
            img = urllib2.urlopen('https:' + m[1]).read()
            file = open(fileName, "w")
            file.write(img)
            file.close()
        except:
            pass
        break
```

第一个*for 循环*迭代下载的网页中的行。第二个*for 循环*使用正则表达式模式搜索每一行的图像 URL。

如果找到模式，则使用`urlparse`模块中的`urlsplit()`方法提取图像的文件名。然后，我们下载图像并将其保存到本地系统。

相同的脚本可以以最小的更改重写为 Python 3：

```py
import urllib.request 
import urllib.parse 
import re 
from os.path import basename  
url = 'https://www.packtpub.com/'  
response = urllib.request.urlopen(url) 
source = response.read() 
file = open("packtpub.txt", "wb") 
file.write(source) 
file.close()  
patten = '(http)?s?:?(\/\/[^"]*\.(?:png|jpg|jpeg|gif|png|svg))' 
for line in open('packtpub.txt'): 
    for m in re.findall(patten, line): 
        print('https:' + m[1]) 
        fileName = basename(urllib.parse.urlsplit(m[1])[2]) 
        print(fileName) 
        try: 
            img = urllib.request.urlopen('https:' + m[1]).read() 
            file = open(fileName, "wb") 
            file.write(img) 
            file.close() 
        except: 
            pass 
        break 
```

在 Python 3 中，请求和`urlparse`模块与`urllib`组合为`urllib.request`和`urllib.parse`。使用正则表达式模式，我们可以解析网页的许多有用信息。

您可以在[`docs.python.org/3.7/library/re.html`](https://docs.python.org/3.7/library/re.html)了解更多关于正则表达式模块的信息。

# 请求和下载动态网站页面

对于具有表单或接收用户输入的网站，我们必须提交`GET`请求或`POST`请求。现在让我们尝试使用 Python 创建`GET`请求和`POST`请求。查询字符串是向 URL 添加键值对的方法。

# 转义无效字符

在上一个配方中，如果我们在最后一步中删除 try catch 块，会发生什么？

```py
patten = '(http)?s?:?(\/\/[^"]*\.(?:png|jpg|jpeg|gif|png|svg))' 
for line in open('packtpub.txt'): 
    for m in re.findall(patten, line):          
        fileName = basename(urlsplit(m[1])[2])                
        img = urllib2.urlopen('https:' + m[1]).read() 
        file = open(fileName, "w") 
        file.write(img) 
        file.close()  
        break 
```

由于 URL 格式错误，脚本将在几次请求后失败。URL 中出现了一些额外的字符，这导致了`urllib`请求失败。

# 如何做...

不可能记住哪些字符是无效的，并手动用百分号转义它们，但内置的 Python 模块`urllib.parse`具有解决此问题所需的方法。

现在我们可以尝试通过转义/URL 编码请求来修复这个问题。将脚本重写如下：

```py
patten = '(http)?s?:?(\/\/[^"]*\.(?:png|jpg|jpeg|gif|png|svg))' 
for line in open('packtpub.txt'): 
    for m in re.findall(patten, line): 
        print('https:' + m[1]) 
        fileName = basename(urllib.parse.urlsplit(m[1])[2]) 
        print(fileName) 
        request = 'https:' + urllib.parse.quote(m[1]) 
        img = urllib.request.urlopen(request).read() 
        file = open(fileName, "wb") 
        file.write(img) 
        file.close()  
        break 
```

# 动态 GET 请求

现在我们知道，只要有 URL，Python 就可以以编程方式下载网站。如果我们必须下载多个页面，这些页面只有查询字符串不同，那么我们可以编写一个脚本来做到这一点，而不是反复运行脚本，而是在一次运行中下载我们需要的所有内容。

# 如何做...

查看此 URL- [`www.packtpub.com/all?search=&offset=12&rows=&sort=`](https://www.packtpub.com/all?search=&offset=12&rows=&sort=)。在这里，定义页面号（*offset**）的查询字符串变量是 12 的倍数：

要下载所有这些页面中的所有图像，我们可以将前一个配方重写如下：

1.  导入所需的模块：

```py
import urllib.request 
import urllib.parse 
import re 
from os.path import basename 
```

1.  定义 URL 和查询字符串：

```py
url = 'https://www.packtpub.com/' 
queryString = 'all?search=&offset=' 
```

1.  通过 12 的倍数迭代偏移量：

```py
for i in range(0, 200, 12): 
    query = queryString + str(i) 
    url += query 
    print(url) 
    response = urllib.request.urlopen(url) 
    source = response.read() 
    file = open("packtpub.txt", "wb") 
    file.write(source) 
    file.close() 
    patten = '(http)?s?:?(\/\/[^"]*\.(?:png|jpg|jpeg|gif|png|svg))' 
    for line in open('packtpub.txt'): 
        for m in re.findall(patten, line): 
            print('https:' + m[1]) 
            fileName = basename(urllib.parse.urlsplit(m[1])[2]) 
            print(fileName) 
            request = 'https:' + urllib.parse.quote(m[1]) 
            img = urllib.request.urlopen(request).read() 
            file = open(fileName, "wb") 
            file.write(img) 
            file.close() 
            break 
```


# 第四章：使用 Python 进行数据解析

在本章中，我们将涵盖以下示例：

+   解析 HTML 表格

+   从 HTML 文档中提取数据

+   解析 XML 数据

# 介绍

由于我们已经在之前的示例中下载了网页，现在我们可以讨论如何处理这些文件并解析它们以获取所需的信息。

# 解析 HTML 表格

从服务器下载 HTML 页面后，我们必须从中提取所需的数据。Python 中有许多模块可以帮助我们做到这一点。在这里，我们可以使用 Python 包`BeautifulSoup`。

# 准备工作

和往常一样，确保你安装了所有必需的包。对于这个脚本，我们需要`BeautifulSoup`和`pandas`。你可以使用`pip`安装它们：

```py
pip install bs4 
pip install pandas  
```

`pandas`是 Python 中的一个开源数据分析库。

# 操作步骤...

我们可以从下载的页面中解析 HTML 表格，如下所示：

1.  和往常一样，我们必须导入脚本所需的模块。在这里，我们导入`BeautifulSoup`来解析 HTML 和`pandas`来处理解析的数据。此外，我们还必须导入`urllib`模块以从服务器获取网页：

```py
import urllib2 
import pandas as pd 
from bs4 import BeautifulSoup 
```

1.  现在我们可以从服务器获取 HTML 页面；为此，我们可以使用`urllib`模块：

```py
url = "https://www.w3schools.com/html/html_tables.asp" 
try: 
    page = urllib2.urlopen(url) 
except Exception as e: 
    print e 
    pass 
```

1.  然后，我们可以使用`BeautifulSoup`来解析 HTML 并从中获取`table`：

```py
soup = BeautifulSoup(page, "html.parser") 
table = soup.find_all('table')[0] 
```

在这里，它将获取网页上的第一个表格。

1.  现在我们可以使用`pandas`库为表格创建一个`DataFrame`：

```py
new_table = pd.DataFrame(columns=['Company', 'Contact', 'Country'], index=range(0, 7)) 
```

这将创建一个具有三列和六行的`DataFrame`。列将显示公司名称、联系方式和国家。

1.  现在我们必须解析数据并将其添加到`DataFrame`中：

```py
row_number = 0 
for row in table.find_all('tr'): 
    column_number = 0 
    columns = row.find_all('td') 
    for column in columns: 
        new_table.iat[row_number, columns_number] = column.get_text() 
        columns_number += 1 
    row_number += 1  
print new_table 
```

这将打印`DataFrame`。

`DataFrame`是一个二维的、带标签的数据结构，具有可能不同类型的列。它更像是`dict`的系列对象。

1.  这个脚本可以在 Python 3 中运行，需要做一些更改，如下所示：

```py
import urllib.request 
import pandas as pd 
from bs4 import BeautifulSoup  
url = "https://www.w3schools.com/html/html_tables.asp" 
try: 
    page = urllib.request.urlopen(url) 
except Exception as e: 
    print(e) 
    pass 
soup = BeautifulSoup(page, "html.parser")  
table = soup.find_all('table')[0]  
new_table = pd.DataFrame(columns=['Company', 'Contact', 'Country'], index=range(0, 7))  
row_number = 0 
for row in table.find_all('tr'): 
    column_number = 0 
    columns = row.find_all('td') 
    for column in columns: 
        new_table.iat[row_number, column_number] = column.get_text() 
        column_number += 1 
    row_number += 1  
print(new_table) 
```

主要的更改是对`urllib`模块和`print`语句的修改。

你可以在[`pandas.pydata.org/pandas-docs/stable/`](https://pandas.pydata.org/pandas-docs/stable/)了解更多关于`pandas`数据分析工具包的信息。

# 从 HTML 文档中提取数据

我们可以使用`pandas`库将解析的数据提取到.csv 或 Excel 格式。

# 准备工作

要使用`pandas`模块中导出解析数据到 Excel 的函数，我们需要另一个依赖模块`openpyxl`，所以请确保你使用`pip`安装了`openpyxl`：

```py
pip install openpyxl  
```

# 操作步骤...

我们可以将数据从 HTML 提取到.csv 或 Excel 文档中，如下所示：

1.  要创建一个.csv 文件，我们可以使用`pandas`中的`to_csv()`方法。我们可以将上一个示例重写如下：

```py
import urllib.request 
import pandas as pd 
from bs4 import BeautifulSoup  
url = "https://www.w3schools.com/html/html_tables.asp" 
try: 
    page = urllib.request.urlopen(url) 
except Exception as e: 
    print(e) 
    pass 
soup = BeautifulSoup(page, "html.parser")  
table = soup.find_all('table')[0]  
new_table = pd.DataFrame(columns=['Company', 'Contact', 'Country'], index=range(0, 7))  
row_number = 0 
for row in table.find_all('tr'): 
    column_number = 0 
    columns = row.find_all('td') 
    for column in columns: 
        new_table.iat[row_number, column_number] = column.get_text() 
        column_number += 1 
    row_number += 1  
new_table.to_csv('table.csv') 
```

这将创建一个名为`table.csv`的.csv 文件。

1.  同样地，我们可以使用`to_excel()`方法将数据导出到 Excel。

将上一个脚本的最后一行改为以下内容：

```py
new_table.to_excel('table.xlsx') 
```

# 解析 XML 数据

有时，我们会从服务器得到一个 XML 响应，我们需要解析 XML 以提取数据。我们可以使用`xml.etree.ElementTree`模块来解析 XML 文件。

# 准备工作

我们必须安装所需的模块，`xml`：

```py
pip install xml  
```

# 操作步骤...

以下是我们如何使用 XML 模块解析 XML 数据：

1.  首先导入所需的模块。由于这个脚本是在 Python 3 中，确保你导入了正确的模块：

```py
from urllib.request import urlopen 
from xml.etree.ElementTree import parse 
```

1.  现在使用`urllib`模块中的`urlopen`方法获取 XML 文件：

```py
url = urlopen('http://feeds.feedburner.com/TechCrunch/Google') 
```

1.  现在使用`xml.etree.ElementTree`模块中的`parse`方法解析 XML 文件：

```py
xmldoc = parse(url) 
```

1.  现在迭代并打印 XML 中的细节：

```py
for item in xmldoc.iterfind('channel/item'): 
    title = item.findtext('title') 
    desc = item.findtext('description') 
    date = item.findtext('pubDate') 
    link = item.findtext('link')  
    print(title) 
    print(desc) 
    print(date) 
    print(link) 
    print('---------') 
```

1.  这个脚本可以重写为 Python 2 中运行，如下所示：

```py
from urllib2 import urlopen 
from xml.etree.ElementTree import parse  
url = urlopen('http://feeds.feedburner.com/TechCrunch/Google') 
xmldoc = parse(url) 
xmldoc.write('output.xml') 
for item in xmldoc.iterfind('channel/item'): 
   title = item.findtext('title') 
   desc = item.findtext('description') 
   date = item.findtext('pubDate') 
   link = item.findtext('link')  
    print title 
    print desc 
    print date 
    print link 
    print '---------' 
```

这也可以导出到 Excel 或.csv，就像我们在之前的示例中所做的那样。


# 第五章：使用 Scrapy 和 BeautifulSoup 进行网络抓取

在本章中，我们将涵盖以下内容：

+   使用 Scrapy 的网络蜘蛛

+   Scrapy shell

+   将提取器与 Scrapy 链接起来

+   使用 Scrapy 登录网站后进行抓取

# 介绍

**Scrapy**是最强大的 Python 网络爬虫框架之一，它可以帮助高效地抓取网页的许多基本功能。

# 使用 Scrapy 的网络蜘蛛

网络蜘蛛从要访问的 URL 或 URL 列表开始，当蜘蛛获取新页面时，它会分析页面以识别所有超链接，并将这些链接添加到要爬行的 URL 列表中。只要发现新数据，这个动作就会递归地继续下去。

网络蜘蛛可以找到新的 URL 并对其进行索引以进行爬行，或者从中下载有用的数据。在下面的示例中，我们将使用 Scrapy 创建一个网络蜘蛛。

# 准备工作

我们可以从 Python 的`pip`命令安装 Scrapy：

```py
pip install scrapy   
```

确保您有安装 Scrapy 所需的权限。如果权限出现任何错误，请使用`sudo`命令。

# 如何操作...

让我们用 Scrapy 创建一个简单的蜘蛛：

1.  要创建一个新的蜘蛛项目，请打开终端并转到我们的蜘蛛所在的文件夹：

```py
$ mkdir new-spider
$ cd new-spider  
```

1.  然后运行以下命令创建一个带有`scrapy`的新蜘蛛项目：

```py
$ scrapy startproject books  
```

这将创建一个名为`books`的项目，并创建一些有用的文件来创建爬虫。现在你有了一个文件夹结构，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00011.jpeg)

1.  现在我们可以使用以下命令创建一个爬虫：

```py
$ scrapy genspider home books.toscrape.com  
```

这将生成名为`home`的蜘蛛的代码，因为我们计划爬取`books.toscrape.com`的主页。现在`spiders`文件夹内的文件夹结构将如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00012.jpeg)

1.  如您所见，`spiders`文件夹内有一个名为`home.py`的文件。我们可以打开`home.py`并开始编辑它。`home.py`文件将包含以下代码：

```py
# -*- coding: utf-8 -*- 
import scrapy 
class HomeSpider(scrapy.Spider): 
    name = 'home' 
    allowed_domains = ['books.toscrape.com'] 
    start_urls = ['http://books.toscrape.com/'] 
    def parse(self, response): 
        pass 
```

`HomeSpider`是`scrapy.spider`的子类。名称设置为`home`，这是我们在生成蜘蛛时提供的。`allowed_domains`属性定义了此爬虫的授权域，`start_urls`定义了爬虫要开始的 URL。

正如其名称所示，`parse`方法解析了所访问的 URL 的内容。

1.  尝试使用以下命令运行蜘蛛：

```py
$ scrapy crawl home    
```

1.  现在我们可以重写蜘蛛以浏览分页链接：

```py
from scrapy.spiders import CrawlSpider, Rule 
from scrapy.linkextractors import LinkExtractor  
class HomeSpider(CrawlSpider): 
    name = 'home' 
    allowed_domains = ['books.toscrape.com'] 
    start_urls = ['http://books.toscrape.com/'] 
    rules = (Rule(LinkExtractor(allow=(), restrict_css=('.next',)), 
             callback="parse_page", 
             follow=True),)  
    def parse_page(self, response): 
        print(response.url) 
```

要浏览多个页面，我们可以使用`CrawlSpider`的子类。从`scrapy.spider`导入`CrawlSpider`和`Rule`模块。对于提取链接，我们可以使用`scrapy.linkextractors`中的`LinkExtractor`。

然后我们需要设置`rules`变量，用于设置通过页面的规则。在这里，我们使用`restrict_css`参数来设置`css`类以到达下一页。可以通过在浏览器中检查网页来找到下一页 URL 的`css`类，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00013.jpeg)

1.  通过以下命令运行爬虫来检查爬虫：

```py
$ scrapy crawl home  
```

这将打印出蜘蛛解析的所有 URL。

1.  让我们重写脚本以获取书籍的“标题”和“价格”。为此，我们必须为我们的项目创建一个类，因此在`book`项目内，我们将创建另一个名为`item.py`的文件，并定义我们要提取的项目：

```py
from scrapy.item import Item, Field 
class BookItem(Item): 
    title = Field() 
    price = Field() 
```

在这里，我们定义了一个新类，其中包含我们希望从我们的蜘蛛中提取的细节。现在文件夹结构将如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00014.jpeg)

1.  然后，更新`spider/home.py`文件以提取数据：

```py
from scrapy.spiders import CrawlSpider, Rule 
from scrapy.linkextractors import LinkExtractor 
from books.item import BookItem 
class HomeSpider(CrawlSpider): 
    name = 'home' 
    allowed_domains = ['books.toscrape.com'] 
    start_urls = ['http://books.toscrape.com/'] 
    rules = (Rule(LinkExtractor(allow=(), restrict_css=('.next',)), 
             callback="parse_page", 
             follow=True),) 
    def parse_page(self, response): 
        items = [] 
        books = response.xpath('//ol/li/article') 
        index = 0 
        for book in books: 
            item = BookItem() 
            title = books.xpath('//h3/a/text()')[index].extract() 
            item['title'] = str(title).encode('utf-8').strip() 
            price = books.xpath('//article/div[contains(@class, "product_price")]/p[1]/text()')[index].extract() 
            item['price'] = str(price).encode('utf-8').strip() 
            items.append(item) 
            index += 1 
            yield item 
```

更新`parse_page`方法以从每个页面提取“标题”和“价格”详情。要从页面中提取数据，我们必须使用选择器。在这里，我们使用了`xpath`选择器。XPath 是一种常用的语法或语言，用于浏览 XML 和 HTML 文档。

在`parse_page`方法中，最初，我们选择了网站上放置书籍详细信息的所有文章标签，并遍历每个文章标签以解析书籍的标题和价格。

1.  要获取标签的`xpath`选择器，我们可以使用谷歌 Chrome 浏览器的 XPath 工具，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00015.jpeg)

我们可以使用 Firefox Inspector 如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00016.jpeg)

1.  现在我们可以运行爬虫，将数据提取到`.csv`文件中：

```py
$ scrapy crawl home -o book-data.csv -t csv   
```

这将在当前目录中创建一个名为`book-data.csv`的文件，其中包含提取的详细信息。

您可以在[`doc.scrapy.org/en/latest/topics/selectors.html`](https://doc.scrapy.org/en/latest/topics/selectors.html)了解有关选择器（如 XPath）以及如何从页面中选择详细信息的更多信息。

# Scrapy shell

Scrapy shell 是一个命令行界面，可帮助调试脚本而无需运行整个爬虫。我们必须提供一个 URL，Scrapy shell 将打开一个接口，与爬虫在其回调中处理的对象进行交互，例如响应对象。

# 如何做...

我们可以通过一些简单的 Scrapy 交互式 shell 用法。步骤如下：

1.  打开一个终端窗口，然后输入以下命令：

```py
$ Scrapy shell http://books.toscrape.com/  
```

加载 Scrapy shell 后，它将打开一个接口，与响应对象进行交互，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00017.jpeg)

1.  我们可以使用这个接口来调试`response`对象的选择器：

```py
>>> response.xpath('//ol/li/article')  
```

这将打印选择器输出。有了这个，我们可以创建和测试爬虫的提取规则。

1.  我们还可以从代码中打开 Scrapy shell 以调试提取规则中的错误。为此，我们可以使用`inspect_response`方法：

```py
from scrapy.spiders import CrawlSpider, Rule 
from scrapy.linkextractors import LinkExtractor 
from scrapy.shell import inspect_response  
class HomeSpider(CrawlSpider): 
    name = 'home' 
    allowed_domains = ['books.toscrape.com'] 
    start_urls = ['http://books.toscrape.com/'] 
    rules = (Rule(LinkExtractor(allow=(), restrict_css=('.next',)), 
             callback="parse_page", 
             follow=True),)  
    def parse_page(self, response): 
        if len(response.xpath('//ol/li/article')) < 5: 
            title = response.xpath('//h3/a/text()')[0].extract() 
            print(title) 
        else: 
            inspect_response(response, self) 
```

如果条件失败，这将打开一个 shell 接口。在这里，我们已经导入了`inspect_response`并使用它来从代码中调试爬虫。

# 使用 Scrapy 的链接提取器

正如它们的名称所示，链接提取器是用于从 Scrapy 响应对象中提取链接的对象。Scrapy 具有内置的链接提取器，例如`scrapy.linkextractors`。

# 如何做...

让我们用 Scrapy 构建一个简单的链接提取器：

1.  与上一个示例一样，我们必须创建另一个 spider 来获取所有链接。

在新的`spider`文件中，导入所需的模块：

```py
import scrapy 
from scrapy.linkextractor import LinkExtractor 
from scrapy.spiders import Rule, CrawlSpider  
```

1.  创建一个新的`spider`类并初始化变量：

```py
class HomeSpider2(CrawlSpider): 
    name = 'home2' 
    allowed_domains = ['books.toscrape.com'] 
    start_urls = ['http://books.toscrape.com/']
```

1.  现在我们必须初始化爬取 URL 的规则：

```py
rules = [ 
    Rule( 
        LinkExtractor( 
            canonicalize=True, 
            unique=True 
        ), 
        follow=True, 
        callback="parse_page" 
    ) 
]   
```

此规则命令提取所有唯一和规范化的链接，并指示程序跟随这些链接并使用`parse_page`方法解析它们

1.  现在我们可以使用`start_urls`变量中列出的 URL 列表启动 spider：

```py
def start_requests(self): 
    for url in self.start_urls: 
        yield scrapy.Request(url, callback=self.parse, dont_filter=True)  
```

`start_requests()`方法在打开爬虫进行爬取时调用一次

1.  现在我们可以编写解析 URL 的方法：

```py
def parse_page(self, response): 
    links = LinkExtractor(canonicalize=True, unique=True).extract_links(response) 
        for link in links: 
            is_allowed = False 
            for allowed_domain in self.allowed_domains: 
                if allowed_domain in link.url: 
                    is_allowed = True 
            if is_allowed: 
                print link.url 
```

该方法提取相对于当前响应的所有规范化和唯一的链接。它还验证链接的 URL 的域是否属于授权域中的一个。

# 使用 Scrapy 登录网站后进行爬取

有时我们必须登录网站才能访问我们计划提取的数据。使用 Scrapy，我们可以轻松处理登录表单和 cookies。我们可以利用 Scrapy 的`FormRequest`对象；它将处理登录表单并尝试使用提供的凭据登录。

# 准备工作

当我们访问一个需要身份验证的网站时，我们需要用户名和密码。在 Scrapy 中，我们需要相同的凭据来登录。因此，我们需要为我们计划抓取的网站获取一个帐户。

# 如何做...

以下是我们如何使用 Scrapy 来爬取需要登录的网站：

1.  要使用`FormRequest`对象，我们可以按如下方式更新`parse_page`方法：

```py
def parse(self, response): 
    return scrapy.FormRequest.from_response( 
        response, 
        formdata={'username': 'username', 'password': 'password'}, 
        callback=self.parse_after_login 
     ) 
```

在这里，响应对象是我们需要填写登录表单的页面的 HTTP 响应。`FormRequest`方法包括我们需要登录的凭据以及用于登录后解析页面的`callback`方法。

1.  在保持登录会话的情况下进行分页，我们可以使用前面一篇食谱中使用的方法。


# 第六章：使用 Python 进行网络扫描

在本章中，我们将涵盖以下内容：

+   简单端口扫描器

+   IP 范围/网络扫描器

+   隐蔽扫描

+   FIN 扫描

+   XMAS 扫描

+   TCP ACK 扫描

+   LanScan

# 介绍

在渗透测试和网络分析中，网络扫描器在获取本地网络中可用主机和运行在这些主机上的应用程序的详细信息方面发挥着重要作用。网络扫描有助于识别主机上运行的可用 UDP 和 TCP 网络服务，并有助于确定主机使用的操作系统（OSs）。

# 简单端口扫描器

端口扫描器旨在检查服务器或主机机器上的开放端口。它帮助攻击者识别主机机器上运行的服务，并利用其中的漏洞。

# 准备工作

我们可以使用`socket`模块编写一个简单的端口扫描器。`socket`模块是 Python 中默认的低级网络接口。

# 如何做...

我们可以使用`socket`模块创建一个简单的端口扫描器，以下是步骤：

1.  创建一个名为`port-scanner.py`的新文件并在编辑器中打开它。

1.  导入所需的模块，如下所示：

```py
import socket,sys,os 
```

导入`socket`模块以及`sys`和`os`模块

1.  现在我们可以定义我们的扫描器的变量：

```py
host = 'example.com' 
open_ports =[] 
start_port = 1 
end_port = 10 
```

在这里，我们定义了我们计划扫描的起始和结束端口

1.  从域名获取 IP：

```py
ip = socket.gethostbyname(host) 
```

这里我们使用`socket`模块中的`gethostbyname`方法。这将返回域的 IP

1.  现在我们可以编写一个函数来`探测`端口：

```py
def probe_port(host, port, result = 1): 
  try: 
    sockObj = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    sockObj.settimeout(0.5) 
    r = sockObj.connect_ex((host, port))   
    if r == 0: 
      result = r 
    sock.close() 
  except Exception ase: 
    pass 
  return result 
```

在这里，我们创建了一个名为`sockObj`的套接字对象，并尝试将其连接到端口。如果连接成功，则端口是打开的。创建的`socket`对象使用 IPv4 套接字系列（`AF_INET`）和 TCP 类型连接（`SOCK_STREAM`）。对于 UDP 类型连接，我们必须使用`SOCK_DGRAM`。

最后，它将返回作为函数输出的结果。

1.  现在我们将编写一个*for*循环来迭代端口范围，并使用`probe_port`方法探测端口：

```py
for port in range(start_port, end_port+1): 
    sys.stdout.flush() 
    print (port) 
    response = probe_port(host, port) 
    if response == 0: 
        open_ports.append(port) 
    if not port == end_port: 
        sys.stdout.write('\b' * len(str(port))) 
```

如果端口是打开的，则将结果添加到列表`open_port`

1.  最后，按以下方式打印结果列表：

```py
if open_ports: 
  print ("Open Ports") 
  print (sorted(open_ports)) 
else: 
  print ("Sorry, No open ports found.!!") 
```

1.  现在我们可以尝试更改前面的脚本以扫描默认端口列表。

为此，我们将定义一个默认端口列表：

```py
common_ports = { 21, 22, 23, 25, 53, 69, 80, 88, 109, 110,  
                 123, 137, 138, 139, 143, 156, 161, 389, 443,  
                 445, 500, 546, 547, 587, 660, 995, 993, 2086,  
                 2087, 2082, 2083, 3306, 8443, 10000  
                } 
```

此外，我们更改循环以调用`probe_port`，如下所示：

```py
for p in sorted(common_ports): 
  sys.stdout.flush() 
  print p 
  response = probe_port(host, p) 
  if response == 0: 
    open_ports.append(p) 
  if not p == end_port: 
    sys.stdout.write('\b' * len(str(p))) 
```

# IP 范围/网络扫描器

我们可以使用 ICMP 数据包创建一个网络扫描器。由于 ICMP 不是 IP 协议，我们必须直接访问网络堆栈。因此，我们可以使用 Scapy 生成 ICMP 数据包并将其发送到主机。

# 准备工作

要开始抓取，我们必须安装所需的 Python 包。这里我们使用 Scapy 进行数据包生成。要安装 Scapy，我们可以使用`pip`。由于我们使用的是 Python 3，请确保为 Python 3 安装 Scapy。还要安装其依赖模块`netifaces`：

```py
pip3 install scapy-python3
pip3 install netifaces  
```

# 如何做...

以下是使用`scapy`模块创建简单网络扫描器的步骤：

1.  创建一个名为`network-scanner.py`的文件并在编辑器中打开它。

1.  导入脚本所需的模块：

```py
import socket, re 
from scapy.all import * 
```

1.  为了获取系统的本地 IP，我们使用`socket`模块中的`getsockname`方法。但是，它需要一个连接。因此，我们创建一个 UDP 套接字连接以连接到 Google DNS，并使用此连接来枚举本地 IP：

```py
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
s.connect(('8.8.8.8', 80)) 
ip = s.getsockname()[0] 
```

1.  现在我们提取本地 IP 并使用正则表达式截断最后的 IP 数字：

```py
end = re.search('^[\d]{1,3}.[\d]{1,3}.[\d]{1,3}.[\d]{1,3}', ip) 
create_ip = re.search('^[\d]{1,3}.[\d]{1,3}.[\d]{1,3}.', ip) 
```

1.  现在创建一个生成 ICMP 数据包并将其发送到主机的函数。这里我们使用 Scapy：

```py
def is_up(ip): 
    icmp = IP(dst=ip)/ICMP() 
    resp = sr1(icmp, timeout=10) 
    if resp == None: 
        return False 
    else: 
        return True  
```

1.  创建另一个函数来检查 IP 是否为环回（`127.0.0.1`）：

```py
def CheckLoopBack(ip): 
    if (end.group(0) == '127.0.0.1'): 
        return True 
```

1.  现在通过迭代最后的 IP 数字运行网络扫描以扫描网络中的所有 IP：

```py
try: 
    if not CheckLoopBack(create_ip): 
        conf.verb = 0  
        for i in range(1, 10): 
            test_ip = str(create_ip.group(0)) + str(i) 
            if is_up(test_ip): 
                print (test_ip + " Is Up") 
except KeyboardInterrupt: 
    print('interrupted!') 
```

`conf.verb = 0`将禁用 Scapy 中的详细模式，以避免来自 Scapy 的日志

1.  确保以管理员权限运行脚本，因为 Scapy 需要管理员访问权限来创建数据包：

```py
sudo python3 network-scanner.py  
```

# 隐蔽扫描

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00018.jpeg)

隐蔽扫描是一种 TCP 扫描形式。在这里，端口扫描器创建原始 IP 数据包并将其发送到主机以监视响应。这种类型的扫描也被称为半开放扫描或 SYN 扫描，因为它从不打开完整的 TCP 连接。这种类型的扫描器创建一个 SYN 数据包并将其发送到主机。如果目标端口是打开的，主机将用一个 SYN-ACK 数据包做出响应。然后客户端将用一个 RST 数据包做出响应，以在完成握手之前关闭连接。如果端口是关闭但未被过滤，目标将立即用一个 RST 数据包做出响应。

要创建一个 SYN 扫描器，我们将使用 Scapy 模块。这是一个功能强大的交互式数据包操作程序和库。

# 准备工作

对于扫描端口，我们将向正在扫描的主机发送自定义数据包，并解析响应以分析结果。我们需要 Scapy 来生成并发送数据包到主机。确保系统中安装了`scapy`模块。

# 如何实现...

我们可以通过以下步骤创建一个 SYN 扫描器：

1.  创建一个名为`syn-scanner.py`的新文件，并在编辑器中打开它。

1.  像往常一样，导入所需的模块：

```py
from scapy.all import * 
```

这将导入`scapy`模块

1.  现在我们可以声明变量，并且如果需要，也可以将这些变量作为参数传递：

```py
host = 'www.dvwa.co.uk' 
ip = socket.gethostbyname(host) 
openp = [] 
filterdp = [] 
common_ports = { 21, 22, 23, 25, 53, 69, 80, 88, 109, 110,  
                123, 137, 138, 139, 143, 156, 161, 389,       443, 445, 500, 546, 547, 587, 660, 995,       993, 2086, 2087, 2082, 2083, 3306, 8443,       10000 } 
```

1.  现在我们可以创建一个函数来检查主机是正常运行还是宕机：

```py
def is_up(ip): 
    icmp = IP(dst=ip)/ICMP() 
    resp = sr1(icmp, timeout=10) 
    if resp == None: 
        return False 
    else: 
        return True 
```

我们创建并发送一个 ICMP 数据包到主机。如果主机正常运行，它将做出响应。

1.  接下来，我们可以创建一个使用 SYN 数据包扫描端口的函数：

```py
def probe_port(ip, port, result = 1): 
    src_port = RandShort() 
    try: 
        p = IP(dst=ip)/TCP(sport=src_port, dport=port, flags='F') 
        resp = sr1(p, timeout=2) # Sending packet 
        if str(type(resp)) == "<type 'NoneType'>": 
            result = 1 
        elif resp.haslayer(TCP): 
            if resp.getlayer(TCP).flags == 0x14: 
                result = 0 
            elif (int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]): 
                result = 2 
    except Exception as e: 
        pass 
    return result 
```

在这里，我们将一个随机端口设置为目标端口，然后创建一个带有源端口、目标端口和目标 IP 的 SYN 数据包。然后我们将发送数据包并分析响应。如果响应类型为`None`，则端口是关闭的。如果响应具有 TCP 层，则我们必须检查其中的标志值。标志有九位，但我们只检查控制位，它们有六位。它们是：

+   +   URG = 0x20

+   ACK = 0x10

+   PSH = 0x08

+   RST = 0x04

+   SYN = 0x02

+   FIN = 0x01

以下是 TCP 层的头部结构：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00019.jpeg)

因此，如果标志值为 0x12，则响应具有 SYN 标志，我们可以认为端口是打开的。如果值为 0x14，则标志是 RST/ACK，因此端口是关闭的。

1.  然后我们将检查主机是否正常运行，循环遍历常见端口列表，并在主机正常运行时扫描每个端口：

```py
 if is_up(ip): 
        for port in common_ports: 
            print (port) 
            response = probe_port(ip, port) 
            if response == 1: 
                openp.append(port) 
            elif response == 2: 
                filterdp.append(port) 
        if len(openp) != 0: 
            print ("Possible Open or Filtered Ports:") 
            print (openp) 
        if len(filterdp) != 0: 
            print ("Possible Filtered Ports:") 
            print (filterdp) 
        if (len(openp) == 0) and (len(filterdp) == 0): 
            print ("Sorry, No open ports found.!!") 
    else: 
        print ("Host is Down") 
```

扫描常见端口列表中的每个端口，并将识别出的打开端口添加到打开端口列表中，然后打印列表

1.  确保以`sudo`身份运行脚本，因为我们正在使用 Scapy，而 Scapy 需要管理员权限：

```py
sudo python3 syn-scanner.py 
```

# FIN 扫描

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00020.jpeg)

SYN 扫描可以被防火墙阻止。然而，设置了 FIN 标志的数据包具有绕过防火墙的能力。它的工作原理是这样的--对于一个 FIN 数据包，关闭的端口会用一个 RST 数据包做出响应，而打开的端口会忽略这些数据包。如果是一个 ICMP 数据包，类型为 3，代码为 1、2、3、9、10 或 13，我们可以推断出端口被过滤，端口状态无法被找到。我们可以使用 Scapy 创建 FIN 数据包并扫描端口。

# 如何实现...

我们可以按照以下方式创建一个 FIN 扫描器：

1.  就像我们在上一个步骤中所做的那样，我们必须创建另一个文件`fin-scanner.py`，并在编辑器中打开它。

1.  然后导入所需的模块：

```py
from scapy.all import * 
```

1.  就像我们为 SYN 扫描器所做的那样，设置变量并创建函数来检查服务器是否正常运行：

```py
host = 'www.dvwa.co.uk' 
ip = socket.gethostbyname(host) 
openp = [] 
filterdp = [] 
common_ports = { 21, 22, 23, 25, 53, 69, 80, 88, 109, 110,  
                 123, 137, 138, 139, 143, 156, 161, 389, 443,  
                 445, 500, 546, 547, 587, 660, 995, 993, 2086,  
                 2087, 2082, 2083, 3306, 8443, 10000  
                } 
def is_up(ip): 
    icmp = IP(dst=ip)/ICMP() 
    resp = sr1(icmp, timeout=10) 
    if resp == None: 
        return False 
    else: 
        return True  
```

1.  现在我们可以创建探测端口的函数如下：

```py
def probe_port(ip, port, result = 1): 
    src_port = RandShort() 
    try: 
        p = IP(dst=ip)/TCP(sport=src_port, dport=port, flags='F') 
        resp = sr1(p, timeout=2) # Sending packet 
        if str(type(resp)) == "<type 'NoneType'>": 
            result = 1 
        elif resp.haslayer(TCP): 
            if resp.getlayer(TCP).flags == 0x14: 
                result = 0 
            elif (int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]): 
                result = 2 
    except Exception as e: 
        pass 
    return result 
```

在这里，我们将标志更改为`F`以进行`FIN`，同时创建要发送的数据包

1.  最后，我们将检查主机是否正常运行，循环遍历常见端口列表，并在主机正常运行时扫描每个端口：

```py
 if is_up(ip): 
        for port in common_ports: 
            print (port) 
            response = probe_port(ip, port) 
            if response == 1: 
                openp.append(port) 
            elif response == 2: 
                filterdp.append(port) 
        if len(openp) != 0: 
            print ("Possible Open or Filtered Ports:") 
            print (openp) 
        if len(filterdp) != 0: 
            print ("Possible Filtered Ports:") 
            print (filterdp) 
        if (len(openp) == 0) and (len(filterdp) == 0): 
            print ("Sorry, No open ports found.!!") 
    else: 
        print ("Host is Down") 
```

# XMAS 扫描

使用 XMAS 扫描，我们将发送一个 TCP 数据包，其中包含一堆标志（PSH，FIN 和 URG）。如果端口关闭，我们将收到一个 RST。如果端口是打开的或被过滤的，那么服务器将不会有任何响应。这与 FIN 扫描类似，只是在创建数据包的部分不同。

# 如何做...

使用 Scapy 创建 XMAS 扫描器的步骤如下：

1.  创建我们为上一个配方创建的文件的副本（*FIN 扫描*）。由于它非常相似，我们只需要更改数据包创建部分。

1.  要创建并发送一个带有 PSH、FIN 和 URG 标志的数据包，请更新`probe_port`方法中的数据包制作部分，如下所示：

```py
p = IP(dst=ip)/TCP(sport=src_port, dport=port, flags='FPU') 
```

只更新标志参数。这里我们将标志设置为`FPU`，表示 PSH、FIN 和 URG 的组合。

# TCP ACK 扫描

ACK 标志扫描对于验证服务器是否被防火墙、IPS 或其他网络安全控制所阻塞非常有用。与 FIN 扫描一样，我们将发送一个 TCP ACK 数据包。没有响应或 ICMP 错误表明存在有状态的防火墙，因为端口被过滤，如果我们收到一个 RST-ACK，那么有状态的防火墙就不存在：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00021.jpeg)

# 如何做...

使用 Scapy 创建 TCP ACK 扫描器的步骤如下：

1.  像往常一样，导入所需的模块并设置变量。还要定义检查主机状态的方法：

```py
from scapy.all import * 
# define the host, port 
host = 'rejahrehim.com' 
ip = socket.gethostbyname(host) 
port = 80 
# define the method to check the status of host 
def is_up(ip): 
    icmp = IP(dst=ip)/ICMP() 
    resp = sr1(icmp, timeout=10) 
    if resp == None: 
        return False 
    else: 
        return True 
```

1.  要发送一个带有`ACK`标志的 TCP 数据包，请更新上一个配方中的`probe_port`方法，如下所示：

```py
def probe_port(ip, port, result = 1): 
    src_port = RandShort() 
    try: 
        p = IP(dst=ip)/TCP(sport=src_port, dport=port, flags='A', seq=12345) 
        resp = sr1(p, timeout=2) # Sending packet 
        if str(type(resp)) == "<type 'NoneType'>": 
            result = 1 
        elif resp.haslayer(TCP): 
            if resp.getlayer(TCP).flags == 0x4: 
                result = 0 
            elif (int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]): 
                result = 1 
    except Exception as e: 
        pass 
    return result 
```

在这里，我们创建一个 TCP ACK 数据包并将其发送到主机

1.  最后，运行扫描程序，如下所示：

```py
 if is_up(ip): 
            response = probe_port(ip, port) 
            if response == 1: 
                 print ("Filtered | Stateful firewall present") 
            elif response == 0: 
                 print ("Unfiltered | Stateful firewall absent") 
    else: 
        print ("Host is Down") 
```

# LanScan

LanScan 是一个 Python 3 模块，可以帮助扫描给定的本地网络。它可以列出所有设备及其开放的端口。LanScan 还可以帮助获取有关网络接口和网络的信息。

# 准备工作

我们可以使用`pip`安装`lanscan`：

```py
pip3 install lanscan  
```

# 如何做...

以下是 LanScan 的一些用例：

1.  LanScan 有一些我们可以用来扫描局域网的选项。要获取系统中可用接口的详细信息，我们可以使用`interfaces`选项：

```py
sudo lanscan interfaces  
```

这将打印出可用的接口，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00022.jpeg)

1.  我们可以使用 network 命令获取连接的网络列表：

```py
sudo lanscan networks
```

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00023.jpeg)

1.  我们可以从终端窗口开始本地网络扫描。这需要管理员权限：

```py
sudo lanscan scan  
```

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00024.jpeg)

这将列出 LAN 网络中的 IP 地址以及每个系统中的开放端口


# 第七章：使用 Python 进行网络嗅探

在本章中，我们将涵盖以下内容：

+   Python 中的数据包嗅探器

+   解析数据包

+   PyShark

# 介绍

嗅探器是一个可以拦截网络流量并嗅探数据包以进行分析的程序。随着数据流在网络上流动，嗅探器可以捕获每个数据包，解码数据包的原始数据以获取数据包头部中各个字段的值，并根据适当的规范分析其内容。网络数据包嗅探器可以用 Python 编写。

# Python 中的数据包嗅探器

可以使用 socket 模块创建一个简单的 Python 数据包嗅探器。我们可以使用原始套接字类型来获取数据包。原始套接字提供对支持套接字抽象的底层协议的访问。由于原始套接字是互联网套接字 API 的一部分，它们只能用于生成和接收 IP 数据包。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00025.jpeg)

# 准备工作

由于 socket 模块的一些行为取决于操作系统套接字 API，并且在不同操作系统下使用原始套接字没有统一的 API，我们需要使用 Linux 操作系统来运行此脚本。因此，如果您使用的是 Windows 或 macOS，请确保在虚拟 Linux 环境中运行此脚本。此外，大多数操作系统需要 root 访问权限才能使用原始套接字 API。

# 操作步骤...

以下是使用`socket`模块创建基本数据包嗅探器的步骤：

1.  创建一个名为`basic-packet-sniffer-linux.py`的新文件，并在编辑器中打开它。

1.  导入所需的模块：

```py
import socket 
```

1.  现在我们可以创建一个`INET`原始套接字：

```py
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) 
```

读取和写入原始套接字都需要先创建一个原始套接字。这里我们使用`INET`族的原始套接字。套接字的族参数描述了套接字的地址族。以下是地址族常量：

+   +   `AF_LOCAL`：用于本地通信

+   `AF_UNIX`：Unix 域套接字

+   `AF_INET`：IP 版本 4

+   `AF_INET6`：IP 版本 6

+   `AF_IPX`：Novell IPX

+   `AF_NETLINK`：内核用户界面设备

+   `AF_X25`：保留给 X.25 项目

+   `AF_AX25`：业余无线电 AX.25

+   `AF_APPLETALK`：Appletalk DDP

+   `AF_PACKET`：低级数据包接口

+   `AF_ALG`：与内核加密 API 的接口

传递的下一个参数是套接字的类型。以下是套接字类型的可能值：

+   +   `SOCK_STREAM`：流（连接）套接字

+   `SOCK_DGRAM`：数据报（无连接）套接字

+   `SOCK_RAW`：原始套接字

+   `SOCK_RDM`：可靠交付的消息

+   `SOCK_SEQPACKET`：顺序数据包套接字

+   `SOCK_PACKET`：用于在开发级别获取数据包的 Linux 特定方法

最后一个参数是数据包的协议。此协议号由**互联网数字分配机构**（**IANA**）定义。我们必须了解套接字的族；然后我们才能选择协议。由于我们选择了`AF_INET`（IPV4），我们只能选择基于 IP 的协议。

1.  接下来，开始一个无限循环，从套接字接收数据：

```py
while True: 
  print(s.recvfrom(65565)) 
```

套接字模块中的`recvfrom`方法帮助我们从套接字接收所有数据。传递的参数是缓冲区大小；`65565`是最大缓冲区大小。

1.  现在用 Python 运行程序：

```py
sudo python3 basic-packet-sniffer-linux.py 
```

结果将如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00026.jpeg)![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00027.jpeg)

# 解析数据包

现在我们可以尝试解析我们嗅探到的数据，并解包头部。要解析数据包，我们需要了解以太网帧和 IP 数据包头部。

以太网帧结构如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00028.jpeg)

前六个字节是**目标 MAC**地址，接下来的六个字节是**源 MAC**。最后两个字节是**以太网类型**。其余部分包括**数据**和**CRC 校验和**。根据 RFC 791，IP 头部如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00029.jpeg)

IP 头部包括以下部分：

+   **协议版本（四位）**：前四位。这代表了当前的 IP 协议。

+   **头部长度（四位）**：IP 头部的长度以 32 位字为单位表示。由于这个字段是四位，允许的最大头部长度为 60 字节。通常值为`5`，表示五个 32 位字：*5 * 4 = 20 字节*。

+   **服务类型（八位）**：前三位是优先位，接下来的四位表示服务类型，最后一位未使用。

+   **总长度（16 位）**：这表示 IP 数据报的总长度（以字节为单位）。这是一个 16 位字段。IP 数据报的最大大小为 65,535 字节。

+   **标志（三位）**：第二位表示**不分段**位。当设置了这一位时，IP 数据报永远不会被分段。第三位表示**更多分段**位。如果设置了这一位，则表示一个被分段的 IP 数据报，在它之后还有更多分段。

+   **生存时间（八位）**：这个值表示 IP 数据报在被丢弃之前经过的跳数。

+   **协议（八位）**：这表示将数据传递给 IP 层的传输层协议。

+   **头部校验和（16 位）**：这个字段有助于检查 IP 数据报的完整性。

+   **源 IP 和目标 IP（每个 32 位）**：这些字段分别存储源地址和目标地址。

有关 IP 头部的更多详细信息，请参考 RFC 791 文档：[`tools.ietf.org/html/rfc791`](https://tools.ietf.org/html/rfc791)

# 如何做到...

以下是解析数据包的步骤：

1.  创建一个名为`basic-parse-packet-packet-linux.py`的新文件，并导入解析数据包所需的模块：

```py
from struct import * 
import sys 
```

1.  现在我们可以创建一个函数来解析以太网头部：

```py
def ethernet_head(raw_data): 
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])  
    dest_mac = get_mac_addr(dest) 
    src_mac = get_mac_addr(src) 
    proto = socket.htons(prototype) 
    data = raw_data[14:] 
    return dest_mac, src_mac, proto, data  
```

在这里，我们使用`struct`模块中的`unpack`方法来解包头部。从以太网帧结构中，前六个字节是目标 MAC 地址，接下来的 6 个字节是源 MAC 地址，最后的无符号短整型是以太网类型。最后，剩下的是数据。因此，这个函数返回目标 MAC 地址、源 MAC 地址、协议和数据。

1.  现在我们可以创建一个主函数，在`ethernet_head()`中解析这个函数并获取详细信息：

```py
def main(): 
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))  
    while True: 
        raw_data, addr = s.recvfrom(65535) 
        eth = ethernet(raw_data) 
        print('\nEthernet Frame:') 
        print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0], eth[1], eth[2])) 

main() 
```

1.  现在我们可以检查以太网帧中的数据部分并解析 IP 头部。我们可以创建另一个函数来解析`ipv4`头部：

```py
def ipv4_head(raw_data): 
    version_header_length = raw_data[0] 
    version = version_header_length >> 4 
    header_length = (version_header_length & 15) * 4 
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20]) 
    data = raw_data[header_length:] 
    return version, header_length, ttl, proto, src, target, data 
```

根据 IP 头部，我们将使用`struct`中的`unpack`方法来解包头部，并返回`版本`、`头部长度`、`TTL`、协议源和目标 IP。

1.  现在更新`main()`以打印 IP 头部：

```py
def main(): 
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))  
    while True: 
        raw_data, addr = s.recvfrom(65535) 
        eth = ethernet(raw_data) 
        print('\nEthernet Frame:') 
        print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0], eth[1], eth[2]))  
        if eth[2] == 8: 
            ipv4 = ipv4(ethp[4]) 
            print( '\t - ' + 'IPv4 Packet:') 
            print('\t\t - ' + 'Version: {}, Header Length: {}, TTL:{},'.format(ipv4[1], ipv4[2], ipv4[3])) 
            print('\t\t - ' + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4[4], ipv4[5], ipv4[6])) 
```

1.  目前，打印出的 IP 地址不是可读格式，因此我们可以编写一个函数来格式化它们：

```py
def get_ip(addr): 
    return '.'.join(map(str, addr)) 
```

确保更新`ipv4_head`函数通过在返回输出之前添加以下行来格式化 IP 地址：

```py
src = get_ip(src) 
target = get_ip(target) 
```

1.  现在我们已经解包了网络层，接下来要解包的是传输层。我们可以从 IP 头部的协议 ID 中确定协议。以下是一些协议的协议 ID：

+   **TCP**：6

+   **ICMP**：1

+   **UDP**：17

+   **RDP**：27

1.  接下来，我们可以创建一个函数来解包 TCP 数据包：

```py
def tcp_head( raw_data): 
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack( 
        '! H H L L H', raw_data[:14]) 
    offset = (offset_reserved_flags >> 12) * 4 
    flag_urg = (offset_reserved_flags & 32) >> 5 
    flag_ack = (offset_reserved_flags & 16) >> 4 
    flag_psh = (offset_reserved_flags & 8) >> 3 
    flag_rst = (offset_reserved_flags & 4) >> 2 
    flag_syn = (offset_reserved_flags & 2) >> 1 
    flag_fin = offset_reserved_flags & 1 
    data = raw_data[offset:] 
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data 
```

TCP 数据包根据 TCP 数据包头的结构进行解包：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00030.jpeg)

1.  现在我们可以更新`main()`以打印 TCP 头部的详细信息。在`ipv4`部分内添加以下行：

```py
if ipv4[4] == 6:  
    tcp = tcp_head(ipv4[7]) 
    print(TAB_1 + 'TCP Segment:') 
    print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp[0], tcp[1])) 
    print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp[2], tcp[3])) 
    print(TAB_2 + 'Flags:') 
    print(TAB_3 + 'URG: {}, ACK: {}, PSH:{}'.format(tcp[4], tcp[5], tcp[6])) 
    print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp[7], tcp[8], tcp[9]))  
    if len(tcp[10]) > 0: 
         # HTTP 
        if tcp[0] == 80 or tcp[1] == 80: 
             print(TAB_2 + 'HTTP Data:') 
                 try: 
                    http = HTTP(tcp[10]) 
                    http_info = str(http[10]).split('\n') 
                    for line in http_info: 
                       print(DATA_TAB_3 + str(line)) 
                 except: 
                       print(format_multi_line(DATA_TAB_3, tcp[10])) 
                 else: 
                      print(TAB_2 + 'TCP Data:') 
                      print(format_multi_line(DATA_TAB_3, tcp[10])) 
```

1.  类似地，更新函数以解包 UDP 和 ICMP 数据包。

数据包根据数据包头结构进行解包。以下是 ICMP 的数据包头结构：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00031.jpeg)

根据图表，我们可以使用以下代码解包数据包：

```py
elif ipv4[4] == 1: 
    icmp = icmp_head(ipv4[7]) 
    print('\t -' + 'ICMP Packet:') 
    print('\t\t -' + 'Type: {}, Code: {}, Checksum:{},'.format(icmp[0], icmp[1], icmp[2])) 
    print('\t\t -' + 'ICMP Data:') 
    print(format_multi_line('\t\t\t', icmp[3])) 
```

以下是 UDP 的数据包头结构：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00032.jpeg)

就像我们对 ICMP 所做的那样，我们可以按照以下方式解包 UDP 数据包头：

```py
elif ipv4[4] == 17: 
    udp = udp_head(ipv4[7]) 
    print('\t -' + 'UDP Segment:') 
    print('\t\t -' + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp[0], udp[1], udp[2])) 
```

现在保存并以所需权限运行脚本：

```py
sudo python3 basic-parse-packet-linux.py  
```

输出将打印所有被嗅探到的数据包。因此，它会一直打印，直到我们用键盘中断停止。输出如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00033.jpeg)

# PyShark

PyShark 是 Wireshark CLI（TShark）的包装器，因此我们可以在 PyShark 中拥有所有 Wireshark 解码器。我们可以使用 PyShark 来嗅探接口，或者分析`pcap`文件。

# 准备就绪

在使用此模块时，请确保在系统上安装 Wireshark 并使用`pip`命令安装`pyshark`：

```py
pip3 install pyshark  
```

还要确保在计算机上安装了 TShark。TShark 是基于终端的 Wireshark，PyShark 用于数据包捕获功能。

在这里了解更多关于 TShark 的信息：[`www.wireshark.org/docs/wsug_html_chunked/AppToolstshark.html`](https://www.wireshark.org/docs/wsug_html_chunked/AppToolstshark.html)

# 如何做...

让我们尝试一些 PyShark 的例子。确保在系统中安装了 TShark。

1.  为了更好地理解，我们可以使用 Python 交互式终端并查看 PyShark 的功能。请注意，这些命令也可以包含在脚本中。唯一的依赖是 TShark。

1.  导入`pyshark`模块：

```py
>>> import pyshark 
```

1.  现在将`pcap`文件加载到`pyshark`中：

```py
>>> cap = pyshark.FileCapture('sample.pcap') 
```

我们可以使用以下命令从实时接口进行嗅探：

```py
 >>> cap = pyshark.LiveCapture(interface='wlp3s0b1')
                  >>> cap.sniff(timeout=3)
```

这将嗅探接口的下一个 3 秒

1.  现在您可以从`cap`变量中获取数据包的详细信息。

要打印出第一个数据包的详细信息，我们可以使用以下命令：

```py
>>> print(cap[0]) 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00034.jpeg)

您可以使用`dir()`查看所有可能的选项：

```py
>>> print(dir(cap[0])) 
```

为了以漂亮的格式查看它们，我们可以使用`pprint`模块：

```py
>>> import pprint 
>>> pprint.pprint(dir(cap[0])) 
```

这将打印 PyShark 中数据包的所有可能选项。输出如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00035.jpeg)

1.  您可以按如下方式迭代每个数据包：

```py
for pkt in cap: print(pkt.highest_layer)
```

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00036.jpeg)

1.  我们可以按如下方式获取经过筛选的数据包流到`pyshark`：

```py
cap = pyshark.LiveCapture(interface='en0', bpf_filter='ip and tcp port 80')  
cap.sniff(timeout=5) 
```

这将过滤数据包，除了 TCP/IP 到端口`80`
