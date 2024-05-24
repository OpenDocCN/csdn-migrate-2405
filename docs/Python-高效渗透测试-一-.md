# Python 高效渗透测试（一）

> 原文：[`annas-archive.org/md5/DB873CDD9AEEB99C3C974BBEDB35BB24`](https://annas-archive.org/md5/DB873CDD9AEEB99C3C974BBEDB35BB24)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Python 是一种高级通用语言，具有清晰的语法和全面的标准库。Python 通常被称为脚本语言，在信息安全领域占据主导地位，因为它具有低复杂性、无限的库和第三方模块。安全专家已经确定 Python 是一种用于开发信息安全工具包的语言，例如 w3af。模块化设计、易读的代码和完全开发的库套件使 Python 适合安全研究人员和专家编写脚本并构建安全测试工具。

基于 Python 的工具包括各种类型的模糊测试工具、代理甚至偶尔的漏洞利用。Python 是当前几种开源渗透测试工具的主要语言，从用于内存分析的 Volatility 到用于抽象检查电子邮件过程的 libPST。学习 Python 是一个很好的选择，因为有大量的逆向工程和利用库可供使用。因此，在需要扩展或调整这些工具的困难情况下，学习 Python 可能会对您有所帮助。

在本书中，我们将了解渗透测试人员如何使用这些工具和库来帮助他们的日常工作。

# 本书内容

第一章，“Python Scripting Essentials”，通过提供 Python 脚本的基本概念、安装第三方库、线程、进程执行、异常处理和渗透测试来打破僵局。

第二章，“Analyzing Network Traffic with Scapy”，介绍了一个数据包操作工具 Scapy，它允许用户嗅探、创建、发送和分析数据包。本章提供了使用 Scapy 进行网络流量调查、解析 DNS 流量、数据包嗅探、数据包注入和被动 OS 指纹识别的见解。这使您能够在网络上创建和发送自定义数据包，并分析各种协议的原始输出。

第三章，“Application Fingerprinting with Python”，讨论了使用 Python 对 Web 应用程序进行指纹识别的基础知识。您将掌握使用 Python 库进行 Web 抓取、收集电子邮件、OS 指纹识别、应用程序指纹识别和信息收集的技术。

第四章，“Attack Scripting with Python”，解决了使用 Python 脚本进行攻击的问题，详细介绍了攻击技术和 OWASP 的顶级漏洞。您将学会编写脚本来利用这些漏洞。

第五章，“Fuzzing and Brute-Forcing”，告诉您模糊测试和暴力破解仍然是测试人员需要解决的主要攻击。本章总结了模糊测试和暴力破解密码、目录和文件位置；暴力破解 ZIP 文件；HTML 表单认证；以及 Sulley 模糊测试框架。这使用户能够使用 Python 扩展模糊测试工具以满足渗透测试的要求。

第六章，“Debugging and Reverse Engineering”，描述了渗透测试人员应该掌握的调试和逆向工程技术。使用 Capstone 和 PyDBG 呈现了调试技术。

第七章，“Crypto, Hash, and Conversion Functions”，总结了 Python 密码工具包，帮助您编写脚本来查找不同类型的密码哈希。

第八章，“Keylogging and Screen Grabbing”，讨论了键盘记录和屏幕截图技术的基础。这些技术是使用 PyHook 呈现的，它可以帮助使用 Python 记录键盘事件和截取屏幕截图。

第九章, *攻击自动化*，详细描述了通过 SSH 暴力破解、使用 paramiko 进行 SFTP 自动化、Nmap 自动化、W3af 自动化、Metasploit 集成以及防病毒和 IDS 规避来进行攻击自动化。

第十章, *展望未来*，深入了解了一些用 Python 编写的工具，可以用于渗透测试。您可以使用这些工具来提高渗透测试的技能。

# 你需要什么来读这本书

基本上你需要一台安装了 Python 的计算机。

# 这本书适合谁

这本书非常适合那些熟悉 Python 或类似语言，并且在基本编程概念上不需要帮助，但想要了解渗透测试的基础知识和渗透测试人员面临的问题。

# 约定

在本书中，您会发现一些区分不同信息类型的文本样式。以下是这些样式的一些示例及其含义的解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“我们可以通过使用`include`指令包含其他上下文。”

代码块设置如下：

```py
import socket
socket.setdefaulttimeout(3)
newSocket = socket.socket()
newSocket.connect(("localhost",22))
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```py
import socket
socket.setdefaulttimeout(3)
newSocket = socket.socket() newSocket.connect(("localhost",22))
```

任何命令行输入或输出都以以下方式编写：

```py
$ pip install packagename

```

Python 交互式终端命令和输出以以下方式编写。

```py
>>> packet=IP(dst='google.com')

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，比如菜单或对话框中的单词，会出现在文本中，就像这样：“点击**OS X**链接”。

### 注意

警告或重要提示会以这种方式出现。

### 提示

提示和技巧会以这种方式出现。


# 第一章：Python 脚本基础知识

Python 仍然是渗透测试（pentesting）和信息安全领域中的主导语言。基于 Python 的工具包括各种工具（用于输入大量随机数据以查找错误和安全漏洞）、代理和甚至利用框架。如果您对渗透测试任务感兴趣，Python 是最好的学习语言，因为它拥有大量的逆向工程和利用库。

多年来，Python 已经接受了许多更新和升级。例如，Python 2 于 2000 年发布，Python 3 于 2008 年发布。不幸的是，Python 3 不向后兼容，因此大部分用 Python 2 编写的程序在 Python 3 中将无法运行。尽管 Python 3 于 2008 年发布，但大多数库和程序仍在使用 Python 2。为了更好地进行渗透测试，测试人员应该能够阅读、编写和重写 Python 脚本。

作为一种脚本语言，安全专家更倾向于使用 Python 作为开发安全工具包的语言。其易读的代码、模块化设计和大量的库为安全专家和研究人员提供了一个起点，可以用它来创建复杂的工具。Python 带有一个庞大的库（标准库），几乎包含了从简单的 I/O 到特定于平台的 API 调用的所有内容。许多默认和用户贡献的库和模块可以帮助我们在渗透测试中构建工具来完成有趣的任务。

在本章中，我们将涵盖以下内容：

+   在不同操作系统中设置脚本环境

+   安装第三方 Python 库

+   使用虚拟环境

+   Python 语言基础知识

# 设置脚本环境

您的**脚本环境**基本上是您日常工作中使用的计算机，以及您用来编写和运行 Python 程序的所有工具。最好的学习系统就是您现在正在使用的系统。本节将帮助您在计算机上配置 Python 脚本环境，以便您可以创建和运行自己的程序。

如果您在计算机上使用的是 Mac OS X 或 Linux 安装，可能已经预先安装了 Python 解释器。要查看是否已安装，请打开终端并输入`python`。您可能会看到类似以下内容：

```py
$ python
Python 2.7.6 (default, Mar 22 2014, 22:59:56) 
[GCC 4.8.2] on linux2
Type "help", "copyright", "credits" or "license" for more
information.
>>> 

```

从前面的输出中，我们可以看到在这个系统中安装了`Python 2.7.6`。通过在终端中输入`python`，您启动了交互模式下的 Python 解释器。在这里，您可以尝试使用 Python 命令，您输入的内容将立即运行并显示输出。

您可以使用您喜欢的文本编辑器来编写 Python 程序。如果没有的话，可以尝试安装 Geany 或 Sublime Text，它们非常适合您。这些都是简单的编辑器，提供了编写和运行 Python 程序的简单方式。在 Geany 中，输出显示在单独的终端窗口中，而 Sublime Text 使用嵌入式终端窗口。Sublime Text 是收费的，但它有灵活的试用政策，允许您在没有任何限制的情况下使用编辑器。它是为初学者设计的少数跨平台文本编辑器之一，具有针对专业人士的全套功能。

## 在 Linux 中设置

Linux 系统的构建方式使用户可以轻松开始 Python 编程。大多数 Linux 发行版已经预装了 Python。例如，最新版本的 Ubuntu 和 Fedora 都预装了 Python 2.7。此外，最新版本的 Redhat Enterprise（RHEL）和 CentOS 都预装了 Python 2.6。不过，您可能还是想要检查一下。

如果未安装 Python，安装 Python 的最简单方法是使用发行版的默认包管理器，如`apt-get`，`yum`等。通过在终端中输入以下命令来安装 Python：

+   对于 Debian / Ubuntu Linux / Kali Linux 用户，请使用以下命令：

```py
 $ sudo apt-get install python2

```

+   对于 Red Hat / RHEL / CentOS Linux 用户，请使用以下命令：

```py
 $sudo yum install python

```

要安装 Geany，请利用您的发行版软件包管理器：

+   对于 Debian / Ubuntu Linux / Kali Linux 用户，请使用以下命令：

```py
 $sudo apt-get install geany geany-common

```

+   对于 Red Hat / RHEL / CentOS Linux 用户，请使用以下命令：

```py
 $ sudo yum install geany

```

## 在 Mac 中设置

尽管 Macintosh 是学习 Python 的好平台，但实际上使用 Mac 的许多人在计算机上运行某些 Linux 发行版，或者在虚拟 Linux 机器中运行 Python。最新版本的 Mac OS X，Yosemite，预装了 Python 2.7。验证它是否正常工作后，安装 Sublime Text。

要在 Mac 上运行 Python，您必须安装 GCC，可以通过下载 XCode，较小的命令行工具来获得。此外，我们需要安装 Homebrew，一个软件包管理器。

要安装 Homebrew，请打开终端并运行以下命令：

```py
$ ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"

```

安装 Homebrew 后，您必须将 Homebrew 目录插入到您的`PATH`环境变量中。您可以通过在您的`~/.profile`文件中包含以下行来实现：

```py
export PATH=/usr/local/bin:/usr/local/sbin:$PATH

```

现在我们准备安装 Python 2.7。在终端中运行以下命令，其余的将由命令完成：

```py
$ brew install python

```

要安装 Sublime Text，请转到 Sublime Text 的下载页面[`www.sublimetext.com/3`](http://www.sublimetext.com/3)，然后单击**OS X**链接。这将为您的 Mac 获取 Sublime Text 安装程序。

## 在 Windows 中设置

Windows 上没有预先安装 Python。要检查是否已安装，请打开命令提示符，输入单词`python`，然后按*Enter*。在大多数情况下，您将收到一条消息，指出 Windows 不认识`python`作为命令。

我们必须下载一个安装程序，将 Python 设置为 Windows。然后我们必须安装和配置 Geany 以运行 Python 程序。

转到 Python 的下载页面[`www.python.org/downloads/windows/`](https://www.python.org/downloads/windows/)，并下载与您的系统兼容的 Python 2.7 安装程序。如果您不知道您的操作系统架构，请下载 32 位安装程序，它将适用于两种架构，但 64 位只适用于 64 位系统。

要安装 Geany，请转到 Geany 的下载页面[`www.geany.org/Download/Releases`](http://www.geany.org/Download/Releases)，并下载包含描述**Full Installer including GTK 2.16**的完整安装程序变体。默认情况下，Geany 不知道 Python 在系统中的位置。因此，我们需要手动配置它。

为此，在 Geany 中编写一个`Hello world`程序，并将其另存为`hello.py`，然后运行它。

您可以使用三种方法在 Geany 中运行 Python 程序：

+   选择**构建** | **执行**

+   按下**F5**

+   点击带有三个齿轮图标的图标

![在 Windows 中设置](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/eff-py-pentest/img/image_01_001.jpg)

在 Geany 中运行`hello.py`程序时，请执行以下步骤：

1.  转到**构建** | **设置构建命令**。

1.  然后使用`C:\Python27\python -m py_compile "%f"`输入 python 命令选项。

1.  使用`C:\Python27\python "%f"`执行命令。

1.  现在您可以在 Geany 中编写代码时运行 Python 程序。

建议将 Kali Linux 发行版作为虚拟机运行，并将其用作脚本编写环境。Kali Linux 预装了许多工具，基于 Debian Linux，因此您还可以安装各种其他工具和库。此外，一些库在 Windows 系统上可能无法正常工作。

# 安装第三方库

在本书中，我们将使用许多 Python 库，本节将帮助您安装和使用第三方库。

## Setuptools 和 pip

最有用的第三方 Python 软件之一是**Setuptools**。使用 Setuptools，您可以使用单个命令下载和安装任何符合条件的 Python 库。

在任何系统上安装 Setuptools 的最佳方法是从[`bootstrap.pypa.io/ez_setup.py`](https://bootstrap.pypa.io/ez_setup.py)下载`ez_setup.py`文件，并使用您的 Python 安装运行此文件。

在 Linux 中，在终端中运行以下命令，正确路径指向`ez_setup.py`脚本：

```py
$ sudo python path/to/ez_setup.py

```

对于安装了 PowerShell 3 的 Windows 8 或旧版本的 Windows，以管理员权限启动 PowerShell，并在其中运行以下命令：

```py
> (Invoke-WebRequest https://bootstrap.pypa.io/ez_setup.py).Content | python -

```

对于未安装 PowerShell 3 的 Windows 系统，请使用 Web 浏览器从上述链接下载`ez_setup.py`文件，并使用您的 Python 安装运行该文件。

Pip 是一个包管理系统，用于安装和管理用 Python 编写的软件包。成功安装 Setuptools 后，您可以通过简单地打开命令提示符并运行以下命令来安装`pip`：

```py
$ easy_install pip

```

或者，您还可以使用默认的发行版包管理器安装`pip`：

+   在 Debian、Ubuntu 和 Kali Linux 上：

```py
 $ sudo apt-get install python-pip

```

+   在 Fedora 上：

```py
 $ sudo yum install python-pip

```

现在您可以从命令行运行`pip`。尝试使用`pip`安装一个软件包：

```py
$ pip install packagename

```

## 使用虚拟环境

虚拟环境有助于分离不同项目所需的依赖项，通过在虚拟环境中工作，还有助于保持全局 site-packages 目录的清洁。

### 使用 virtualenv 和 virtualwrapper

**Virtualenv**是一个 Python 模块，用于为我们的脚本实验创建隔离的 Python 环境，它会创建一个包含所有必要可执行文件和模块的文件夹，用于基本的 Python 项目。

您可以使用以下命令安装`virtualenv`：

```py
 $ sudo pip install virtualenv

```

要创建一个新的虚拟环境，请创建一个文件夹，并从命令行进入该文件夹：

```py
$ cd your_new_folder 
$ virtualenv name-of-virtual-environment 

```

这将在当前工作目录中使用提供的名称初始化一个文件夹，其中包含所有 Python 可执行文件和`pip`库，然后将帮助在您的虚拟环境中安装其他软件包。

您可以通过提供更多参数来选择您选择的 Python 解释器，例如以下命令：

```py
$ virtualenv -p /usr/bin/python2.7 name-of-virtual-environment 

```

这将创建一个使用 Python 2.7 的虚拟环境。在开始使用此虚拟环境之前，我们必须激活它：

```py
$ source name-of-virtual-environment/bin/activate

```

![使用 virtualenv 和 virtualwrapper](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/eff-py-pentest/img/image_01_002.jpg)

现在，在命令提示符的左侧，将显示活动虚拟环境的名称。在此提示符中使用`pip`安装的任何软件包都将属于活动虚拟环境，该环境将与所有其他虚拟环境和全局安装隔离开来。

您可以使用以下命令退出当前虚拟环境：

```py
$ deactivate

```

**Virtualenvwrapper**提供了一种更好的使用`virtualenv`的方法。它还将所有虚拟环境组织在一个地方。

要安装，我们可以使用`pip`，但在安装`virtualwrapper`之前，让我们确保已安装了`virtualenv`。

Linux 和 OS X 用户可以使用以下方法安装它：

```py
$ pip install virtualenvwrapper

```

还要将以下三行添加到您的 shell 启动文件，例如`.bashrc`或`.profile`：

```py
export WORKON_HOME=$HOME/.virtualenvs 
export PROJECT_HOME=$HOME/Devel 
source /usr/local/bin/virtualenvwrapper.sh 

```

这将把您的主目录中的`Devel`文件夹设置为您的虚拟环境项目的位置。

对于 Windows 用户，我们可以使用另一个软件包：`virtualenvwrapper-win`。这也可以使用`pip`安装：

```py
$ pip install virtualenvwrapper-win

```

使用`virtualwrapper`创建一个虚拟环境：

```py
$ mkvirtualenv your-project-name

```

这将在`~/Envs`中创建一个以提供的名称命名的文件夹。

要激活此环境，我们可以使用`workon`命令：

```py
$ workon your-project-name

```

这两个命令可以组合成一个单一的命令，如下所示：

```py
$ mkproject your-project-name

```

我们可以使用`virtualenv`中的相同 deactivate 命令来停用虚拟环境。要删除虚拟环境，可以使用以下命令：

```py
$ rmvirtualenv your-project-name

```

# Python 语言基础知识

在本节中，我们将介绍变量、字符串、数据类型、网络和异常处理的概念。对于有经验的程序员，本节将是对您已经了解的 Python 知识的总结。

## 变量和类型

Python 在变量方面非常出色。变量指向存储在内存位置中的数据。这个内存位置可能包含不同的值，比如整数、实数、布尔值、字符串、列表和字典。

当您给变量设置某个值时，Python 会解释并声明变量。例如，如果我们设置*a = 1*和*b = 2*。

然后我们用以下代码打印这两个变量的和：

```py
print (a+b) 

```

结果将是`3`，因为 Python 会判断*a*和*b*都是数字。

然而，如果我们赋值*a = "1"* 和 *b = "2"*。那么输出将是`12`，因为*a*和*b*都将被视为字符串。在这里，我们不需要在使用变量之前声明变量或其类型，因为每个变量都是一个对象。`type()`方法可用于获取变量类型。

## 字符串

与其他任何编程语言一样，字符串是 Python 中的重要内容之一。它们是不可变的。因此，一旦定义，它们就无法更改。有许多 Python 方法可以修改字符串。它们不会对原始字符串进行任何操作，而是创建一个副本并在修改后返回。字符串可以用单引号、双引号或在多行的情况下，我们可以使用三引号语法进行分隔。我们可以使用`\`字符来转义字符串中的额外引号。

常用的字符串方法如下：

+   `string.count('x')`: 这将返回字符串中`'x'`的出现次数

+   `string.find('x')`: 这将返回字符串中字符`'x'`的位置

+   `string.lower()`: 这将把字符串转换为小写

+   `string.upper()`: 这将把字符串转换为大写

+   `string.replace('a', 'b')`: 这将用`b`替换字符串中的所有`a`

此外，我们可以使用`len()`方法获取字符串中字符的数量，包括空格：

```py
#!/usr/bin/python 
a = "Python" 
b = "Python\n" 
c = "Python  " 

print len(a) 
print len(b) 
print len(c) 

```

您可以在这里阅读更多关于字符串函数的内容：[`docs.python.org/2/library/string.html`](https://docs.python.org/2/library/string.html)。

## 列表

列表允许我们在其中存储多个*变量*，并提供了一种更好的方法来对 Python 中的对象数组进行排序。它们还有一些方法可以帮助我们操作其中的值：

```py
list = [1,2,3,4,5,6,7,8] 
print (list[1])  

```

这将打印`2`，因为 Python 索引从 0 开始。要打印整个列表，请使用以下代码：

```py
list = [1,2,3,4,5,6,7,8]
for x in list:
 print (x)

```

这将循环遍历所有元素并将它们打印出来。

有用的列表方法如下：

+   `.append(value)`: 这将在列表末尾添加一个元素

+   `.count('x')`: 这将获取列表中`'x'`的数量

+   `.index('x')`: 这将返回列表中`'x'`的索引

+   `.insert('y','x')`: 这将在位置`'y'`插入`'x'`

+   `.pop()`: 这将返回最后一个元素并将其从列表中删除

+   `.remove('x')`: 这将从列表中删除第一个`'x'`

+   `.reverse()`: 这将颠倒列表中的元素

+   `.sort()`: 这将按字母顺序或数字顺序对列表进行排序

## 字典

Python 字典是一种存储键值对的方法。Python 字典用大括号`{}`括起来。例如：

```py
dictionary = {'item1': 10, 'item2': 20} 
print(dictionary['item2']) 

```

这将输出`20`。我们不能使用相同的键创建多个值。这将覆盖重复键的先前值。字典上的操作是唯一的。字典不支持切片。

我们可以使用 update 方法将两个不同的字典合并为一个。此外，如果存在冲突，update 方法将合并现有元素：

```py
a = {'apples': 1, 'mango': 2, 'orange': 3} 
b = {'orange': 4, 'lemons': 2, 'grapes ': 4} 
a.update(b) 

Print a 

```

这将返回以下内容：

```py
{'mango': 2, 'apples': 1, 'lemons': 2, 'grapes ': 4, 'orange': 4} 

```

要从字典中删除元素，我们可以使用`del`方法：

```py
del a['mango'] 
print a 

```

这将返回以下内容：

```py
{'apples': 1, 'lemons': 2, 'grapes ': 4, 'orange': 4}
```

## 网络

套接字是计算机网络通信的基本组成部分。所有网络通信都通过套接字进行。因此，套接字是任何通信渠道的虚拟端点，这些通信渠道发生在两个应用程序之间，这两个应用程序可能位于同一台计算机上，也可能位于不同的计算机上。

Python 中的 socket 模块为我们提供了一种更好的方式来创建 Python 网络连接。因此，要使用这个模块，我们必须在脚本中导入它：

```py
import socket 
socket.setdefaulttimeout(3) 
newSocket = socket.socket() 
newSocket.connect(("localhost",22)) 
response = newSocket.recv(1024) 
print response 

```

此脚本将从服务器获取响应标头。我们将在后面的章节中更多地讨论网络。

## 处理异常

尽管我们编写了语法正确的脚本，但在执行它们时可能会出现一些错误。因此，我们必须正确处理这些错误。在 Python 中处理异常的最简单方法是使用`try-except`：

尝试在 Python 解释器中将一个数字除以零：

```py
>>> 10/0
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
ZeroDivisionError: integer division or modulo by zero

```

因此，我们可以使用`try-except`块重写这个脚本：

```py
try: 
   answer = 10/0 
except ZeroDivisionError, e: 
   answer = e 
print answer 

```

这将返回错误`整数除法或取模为零`。

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，文件将直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  使用您的电子邮件地址和密码登录或注册到我们的网站。

1.  将鼠标指针悬停在顶部的**支持**选项卡上。

1.  单击**代码下载和勘误**。

1.  在**搜索**框中输入书名。

1.  选择您要下载代码文件的书籍。

1.  从下拉菜单中选择您购买此书的地点。

1.  单击**代码下载**。

您还可以通过单击书的网页上的`代码文件`按钮来下载代码文件，该网页位于 Packt Publishing 网站上。可以通过在**搜索**框中输入书名来访问此页面。请注意，您需要登录到您的 Packt 帐户。

下载文件后，请确保使用以下最新版本的软件解压或提取文件夹：

+   WinRAR / 7-Zip for Windows

+   Zipeg / iZip / UnRarX for Mac

+   7-Zip / PeaZip for Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Effective-Python-Penetration-Testing`](https://github.com/PacktPublishing/Effective-Python-Penetration-Testing)。我们还有其他丰富的图书和视频代码包可供下载，网址为[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)。快去看看吧！

# 摘要

现在我们已经了解了编码前必须进行的基本安装和配置。此外，我们已经学习了 Python 语言的基础知识，这可能有助于我们在后面的章节中加快脚本编写的速度。在下一章中，我们将讨论使用 Scapy 进行更多的网络流量调查、数据包嗅探和数据包注入。


# 第二章：使用 Scapy 分析网络流量

流量分析是拦截和分析网络流量以推断通信信息的过程。两个主机之间交换的数据包大小，通信系统的详细信息，通信的时间和持续时间是攻击者的一些有价值的信息。在本章中，我们将学习如何使用 Python 脚本分析网络流量：

+   网络基础知识

+   原始套接字编程

+   使用 Scapy 进行数据包嗅探

+   使用 Scapy 进行数据包注入

+   使用 Scapy 解析 DNS 流量

+   使用 Scapy 进行操作系统指纹识别

# 套接字模块

网络套接字是一种使用标准 Unix 文件描述符与其他计算机通信的方式，它允许在同一台或不同机器上的两个不同进程之间进行通信。套接字几乎类似于低级文件描述符，因为诸如`read()`和`write()`之类的命令也可以与套接字一样与文件一起使用。

Python 有两个基本的套接字模块：

+   **套接字**：标准的 BSD 套接字 API。

+   **SocketServer**：一个以服务器为中心的模块，定义了处理同步网络请求的类，简化了网络服务器的开发。

## 套接字

`socket`模块几乎包含了构建套接字服务器或客户端所需的一切。在 Python 的情况下，`socket`返回一个对象，可以对其应用套接字方法。

### 套接字模块中的方法

套接字模块具有以下类方法：

+   `socket.socket(family, type)`：创建并返回一个新的套接字对象

+   `socket.getfqdn(name)`: 将字符串 IP 地址转换为完全合格的域名

+   `socket.gethostbyname(hostname)`：将主机名解析为 IP 地址

**实例方法**需要从`socket`返回的套接字实例。`socket`模块具有以下实例方法：

+   `sock.bind( (address, port) )`：将套接字绑定到地址和端口

+   `sock.accept()`: 返回带有对等地址信息的客户端套接字

+   `sock.listen(backlog)`: 将套接字置于监听状态

+   `sock.connect( (address, port) )`：将套接字连接到定义的主机和端口

+   `sock.recv( bufferLength[, flags] )`：从套接字接收数据，最多`buflen`（要接收的最大字节数）字节

+   `sock.recvfrom( bufferLength[, flags] )`：从套接字接收数据，最多`buflen`字节，并返回数据来自的远程主机和端口

+   `sock.send( data[, flags] )`：通过套接字发送数据

+   `sock.sendall( data[, flags] )`：通过套接字发送数据，并继续发送数据，直到所有数据都已发送或发生错误

+   `sock.close()`: 关闭套接字

+   `sock.getsockopt( lvl, optname )`：获取指定套接字选项的值

+   `sock.setsockopt( lvl, optname, val )`：设置指定套接字选项的值

### 创建套接字

可以通过在`socket`模块中调用类方法`socket()`来创建套接字。这将返回指定域中的套接字。该方法的参数如下：

+   **地址族**：Python 支持三种地址族。

+   **AF_INET**：用于 IP 版本 4 或 IPv4 互联网寻址。

+   **AF_INET6**：用于 IPv6 互联网寻址。

+   **AF_UNIX**：用于**UNIX 域套接字**（**UDS**）。

+   **套接字类型**：通常，套接字类型可以是`SOCK_DGRAM`用于**用户数据报协议**（**UDP**）或`SOCK_STREAM`用于**传输控制协议**（**TCP**）。`SOCK_RAW`用于创建原始套接字。

+   **协议**：通常保持默认值。默认值为 0。

以下是创建套接字的示例：

```py
import socket #Imported sockets module 
import sys 
try: 
   #Create an AF_INET (IPv4), STREAM socket (TCP) 
   tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
except socket.error, e: 
   print 'Error occurred while creating socket. Error code: ' + str(e[0]) + ' , Error message : ' + e[1] 
   sys.exit(); 
print 'Success!' 

```

### 连接到服务器并发送数据

创建的套接字可以在服务器端或客户端端使用。

套接字对象的`connect()`方法用于将客户端连接到主机。这个*实例方法*接受主机名或一个包含主机名/地址和端口号的元组作为参数。

我们可以重写前面的代码，向服务器发送消息如下：

```py
import socket #Imported sockets module  
import sys  

TCP_IP = '127.0.0.1'  
TCP_PORT = 8090 #Reserve a port  
BUFFER_SIZE = 1024  
MESSAGE_TO_SERVER = "Hello, World!"  

try:  
    #Create an AF_INET (IPv4), STREAM socket (TCP)  
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
except socket.error, e:  
    print 'Error occurred while creating socket. Error code: ' + str(e[0]) + ' , Error message : ' + e[1] 
    sys.exit();  

tcp_socket.connect((TCP_IP, TCP_PORT))  

try :  
    #Sending message  
    tcp_socket.send(MESSAGE_TO_SERVER)  
except socket.error, e: 
    print 'Error occurred while sending data to server. Error code: ' + str(e[0]) + ' , Error message : ' + e[1] 
    sys.exit()  

print 'Message to the server send successfully' 

```

### 接收数据

我们需要一个服务器来接收数据。要在服务器端使用套接字，`socket`对象的`bind()`方法将套接字绑定到地址。它以元组作为输入参数，其中包含套接字的地址和用于接收传入请求的端口。`listen()`方法将套接字放入监听模式，`accept()`方法等待传入连接。`listen()`方法接受一个表示最大排队连接数的参数。因此，通过将此参数指定为`3`，这意味着如果有三个连接正在等待处理，那么第四个连接将被拒绝：

```py
import socket #Imported sockets module 

TCP_IP = '127.0.0.1' 
TCP_PORT = 8090 
BUFFER_SIZE = 1024 #Normally use 1024, to get fast response from the server use small size 

try: 
   #Create an AF_INET (IPv4), STREAM socket (TCP) 
   tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
except socket.error, e: 
   print 'Error occurred while creating socket. Error code: ' + str(e[0]) + ' , Error message : ' + e[1] 
   sys.exit(); 

tcp_socket.bind((TCP_IP, TCP_PORT)) 
# Listen for incoming connections  (max queued connections: 2) 
tcp_socket.listen(2) 
print 'Listening..' 

#Waits for incoming connection (blocking call) 
connection, address = tcp_socket.accept() 
print 'Connected with:', address 

```

方法`accept()`将返回服务器和客户端之间的活动连接。可以使用`recv()`方法从连接中读取数据，并使用`sendall()`进行传输：

```py
data = connection.recv(BUFFER_SIZE) 
print "Message from client:", data 

connection.sendall("Thanks for connecting")  # response for the message from client 
connection.close() 

```

最好通过将`socket_accept`放在循环中来保持服务器处于活动状态，如下所示：

```py
#keep server alive  
while True:  
   connection, address = tcp_socket.accept()  
   print 'Client connected:', address  

   data = connection.recv(BUFFER_SIZE)  
   print "Message from client:", data  

   connection.sendall("Thanks for connecting")  #Echo the message from client  

```

将此保存到`server.py`并在终端中启动服务器如下：

```py
 $ python  server.py

```

然后服务器终端可能如下所示：

![接收数据](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/eff-py-pentest/img/image_02_001.jpg)

现在我们可以修改客户端脚本以从服务器接收响应：

```py
import socket #Imported sockets module  
import sys  

TCP_IP = '127.0.0.1'  
TCP_PORT = 8090 # Reserve a port  
BUFFER_SIZE = 1024  
MESSAGE_TO_SERVER = "Hello, World!"  

try:  
    #Create an AF_INET (IPv4), STREAM socket (TCP)  
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
except socket.error,  e:  
    print 'Error occured while creating socket. Error code: ' + str(e[0]) + ' , Error message : ' + e[1] 
    sys.exit();  

tcp_socket.connect((TCP_IP, TCP_PORT))  

try :  
    #Sending message  
    tcp_socket.send(MESSAGE_TO_SERVER)  
except socket.error, e: 
    print 'Error occurred while sending data to server. Error code: ' + str(e[0]) + ' , Error message : ' + e[1] 
    sys.exit() 

print 'Message to the server send successfully'  
data = tcp_socket.recv(BUFFER_SIZE)  
tcp_socket.close() #Close the socket when done  
print "Response from server:", data 

```

将此保存到`client.py`并运行。请确保服务器脚本正在运行。客户端终端可能如下所示：

![接收数据](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/eff-py-pentest/img/image_02_002.jpg)

### 处理多个连接

在上一个示例中，我们使用 while 循环来处理不同的客户端；这只能一次与一个客户端交互。为了使服务器与多个客户端交互，我们必须使用多线程。当`main`程序接受连接时，它会创建一个新线程来处理此连接的通信，然后返回以接受更多连接。

我们可以使用线程模块为服务器接受的每个连接创建线程处理程序。

`start_new_thread()`接受两个参数：

+   要运行的函数名称

+   传递给该函数的参数元组

让我们看看如何使用线程重写前面的示例：

```py
import socket #Imported sockets module  
import sys  
from thread import *  

TCP_IP = '127.0.0.1'  
TCP_PORT = 8090 # Reserve a port  

try:  
    #create an AF_INET (IPv4), STREAM socket (TCP)  
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
except socket.error, e:  
    print 'Error occured while creating socket. Error code: ' + str(e[0]) + ' , Error message : ' + e[1] 
    sys.exit();  

#Bind socket to host and port  
tcp_socket.bind((TCP_IP, TCP_PORT))  
tcp_socket.listen(10)  
print 'Listening..'  

#Function for handling connections. Used to create threads  
def ClientConnectionHandler(connection):  
    BUFFER_SIZE = 1024  
    #Sending message to client  
    connection.send('Welcome to the server')  

    #infinite loop to keep the thread alive.  
    while True:  
        #Receiving data from client  
        data = connection.recv(BUFFER_SIZE)  
        reply = 'Data received:' + data  
        if not data:  
            break  
        connection.sendall(reply)  

    #Exiting loop  
    connection.close()  

#keep server alive always (infinite loop)  
while True:  
    connection, address = tcp_socket.accept()  
    print 'Client connected:', address  
    start_new_thread(ClientConnectionHandler ,(connection,))  

tcp_socket.close() 

```

### 提示

有关套接字模块的更多详细信息，请访问[`docs.python.org/2.7/library/socket.html`](https://docs.python.org/2.7/library/socket.html)。

## SocketServer

`SocketServer`是一个有趣的模块，它是用于创建网络服务器的框架。它具有预定义的类，用于使用 TCP、UDP、UNIX 流和 UNIX 数据报处理同步请求。我们还可以使用混合类创建每种类型服务器的分叉和线程版本。在许多情况下，您可以简单地使用现有的服务器类。`SocketServer`模块中定义的五种不同的服务器类如下：

+   `BaseServer`: 定义 API，不直接使用

+   `TCPServer`: 使用 TCP/IP 套接字

+   `UDPServer`: 使用数据报套接字

+   `UnixStreamServer`: Unix 域流套接字

+   `UnixDatagramServer`: Unix 域数据报套接字

要使用此模块构建服务器，我们必须传递要监听的地址（由地址和端口号组成的元组）和一个请求处理程序类。请求处理程序将接收传入的请求并决定采取什么行动。这个类必须有一个方法，覆盖以下任何一个`RequestHandler`方法；大多数情况下，我们可以简单地覆盖`handle()`方法。对于每个请求，都会创建此类的新实例：

+   `setup()`: 在`handle()`方法之前调用以准备请求处理程序的请求

+   `handle()`: 解析传入的请求，处理数据并响应请求

+   `finish()`: 在`handle()`方法之后调用以清理`setup()`期间创建的任何内容

### 使用 SocketServer 模块的简单服务器

以下脚本显示了如何使用`SocketServer`创建一个简单的回显服务器：

```py
import SocketServer #Imported SocketServer module  

#The RequestHandler class for our server.  
class TCPRequestHandler( SocketServer.StreamRequestHandler ):  
  def handle( self ):  
   self.data = self.request.recv(1024).strip()  
   print "{} wrote:".format(self.client_address[0])  
   print self.data  
   #Sending the same data  
   self.request.sendall(self.data)  

#Create the server, binding to localhost on port 8090  
server = SocketServer.TCPServer( ("", 8090), TCPRequestHandler ) 
#Activate the server; this will keep running untile we interrupt 
server.serve_forever() 

```

脚本的第一行导入了`SocketServer`模块：

```py
import SocketServer 

```

然后我们创建了一个请求处理程序，该处理程序继承了`SocketServer.StreamRequestHandler`类，并覆盖了`handle()`方法来处理服务器的请求。`handle()`方法接收数据，打印它，然后向客户端发送相同的数据：

```py
class TCPRequestHandler( SocketServer.StreamRequestHandler ):  
  def handle( self ):  
   self.data = self.request.recv(1024).strip()  
   print "{} wrote:".format(self.client_address[0])  
   print self.data  
   # sending the same data  
   self.request.sendall(self.data) 

```

对于服务器的每个请求，都会实例化这个请求处理程序类。这个服务器是使用`SocketServer.TCPServer`类创建的，我们提供服务器将绑定到的地址和请求处理程序类。它将返回一个`TCPServer`对象。最后，我们调用`serve_forever()`方法来启动服务器并处理请求，直到我们发送一个显式的`shutdown()`请求（键盘中断）：

```py
tcp_server = SocketServer.TCPServer( ("", 8090), TCPRequestHandler )  
tcp_server.serve_forever() 

```

### 提示

有关 Socket 模块的更多详细信息，请访问[`xahlee.info/python_doc_2.7.6/library/socketserver.html`](http://xahlee.info/python_doc_2.7.6/library/socketserver.html)。

# 原始套接字编程

我们在互联网上发送和接收的所有内容都涉及数据包；我们接收的每个网页和电子邮件都作为一系列数据包发送，我们发送的每个内容都作为一系列数据包离开。数据以一定大小的字节分成数据包。每个数据包携带用于识别其目的地、源和互联网使用的协议的其他细节以及我们数据的一部分的信息。网络数据包分为三部分：

+   **标头**：这包含了数据包携带的指令

+   **有效载荷**：这是数据包的数据

+   **尾部**：这是尾部，通知接收设备数据包的结束

像 TCP/IP 这样的协议的标头由内核或操作系统堆栈提供，但我们可以使用原始套接字为该协议提供自定义标头。原始套接字在 Linux 的本机套接字 API 中得到支持，但在 Windows 中不支持。尽管原始套接字在应用程序中很少使用，但在网络安全应用程序中广泛使用。

所有数据包都以相同的格式结构化，包括 IP 标头和可变长度的数据字段。首先是以太网标头，固定大小为 14 个字节，然后是 IP 标头（如果是 IP 数据包），或者 TCP 标头（如果是 TCP 数据包），根据以太网标头的最后两个字节指定的以太网类型：

![原始套接字编程](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/eff-py-pentest/img/image_02_004.jpg)

在以太网标头中，前六个字节是目标主机，接着是六个字节的源主机。最后两个字节是以太网类型：

![原始套接字编程](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/eff-py-pentest/img/image_02_006.jpg)

IP 标头长 20 个字节；前 12 个字节包括版本、**IHL**、**总长度**、**标志**等，接下来的四个字节表示源地址。最后四个字节是目标地址：

![原始套接字编程](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/eff-py-pentest/img/image_02_008.jpg)

### 提示

有关 IP 数据包结构的更多详细信息，请访问[`www.freesoft.org/CIE/Course/Section3/7.htm`](http://www.freesoft.org/CIE/Course/Section3/7.htm)。

## 创建原始套接字

要使用 Python 创建原始套接字，应用程序必须在系统上具有根权限。以下示例创建了一个`IPPROTO_RAW`套接字，这是一个原始 IP 数据包：

```py
import socket #Imported sockets module  

try: 
  #create an INET, raw socket  
  raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)  
except socket.error as e:  
  print 'Error occurred while creating socket. Error code: ' + str(e[0]) + ' , Error message : ' + e[1] 
  sys.exit() 

```

创建`raw`套接字后，我们必须构造要发送的数据包。这些数据包类似于 C 语言中的结构，而在 Python 中不可用，因此我们必须使用 Python 的`struct`模块来按照先前指定的结构打包和解包数据包。

## 基本原始套接字嗅探器

最基本的`raw`套接字嗅探器如下：

```py
import socket #Imported sockets module  

try:  
  #create an raw socket  
  raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))  
except socket.error, e:  
  print 'Error occurred while creating socket. Error code: ' + str(e[0]) + ' , Error message : ' + e[1] 
  sys.exit();  

while True:  
  packet = raw_socket.recvfrom(2048)  
  print packet 

```

像往常一样，在第一行导入了 socket 模块。稍后我们使用以下代码创建了一个套接字：

```py
raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
```

第一个参数表示数据包接口是`PF_PACKET（Linux 特定，我们必须在 Windows 上使用 AF_INET）`，第二个参数指定它是原始套接字。第三个参数指示我们感兴趣的协议。值`0x0800`指定我们对 IP 协议感兴趣。之后，我们调用`recvfrom`方法以无限循环接收数据包：

```py
while True:  
  packet = raw_socket.recvfrom(2048)  
  print packet 

```

现在我们可以解析`packet`，因为前 14 个字节是以太网头部，其中前 6 个字节是目标主机，接下来的 6 个字节是源主机。让我们重写无限循环并添加代码来解析以太网头部的目标主机和源主机。首先我们可以按如下方式去掉以太网头部：

```py
ethernet_header = packet[0][0:14] 

```

然后我们可以使用`struct`解析和解包头部，如下所示：

```py
eth_header = struct.unpack("!6s6s2s", ethernet_header) 

```

这将返回一个包含三个十六进制值的元组。我们可以使用`binascii`模块中的`hexlify`将其转换为十六进制值：

```py
print "destination:" + binascii.hexlify(eth_header[0]) + " Source:" + binascii.hexlify(eth_header[1]) +  " Type:" + binascii.hexlify(eth_header[2] 

```

同样，我们可以获取 IP 头部，即数据包中的接下来 20 个字节。前 12 个字节包括版本、IHL、长度、标志等，我们对此不感兴趣，但接下来的 8 个字节是源 IP 地址和目标 IP 地址，如下所示：

```py
ip_header = packet[0][14:34] 
ip_hdr = struct.unpack("!12s4s4s", ip_header) 
print "Source IP:" + socket.inet_ntoa(ip_hdr[1]) + " Destination IP:" + socket.inet_ntoa(ip_hdr[2])) 

```

最终脚本如下：

```py
import socket #Imported sockets module  
import struct  
import binascii  

try:  
  #Create an raw socket  
  raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))  
except socket.error, e:  
  print 'Error occurred while creating socket. Error code: ' + str(e[0]) + ' , Error message : ' + e[1] 
  sys.exit();  

while True:  
  packet = raw_socket.recvfrom(2048)  
  ethernet_header = packet[0][0:14]  
  eth_header = struct.unpack("!6s6s2s", ethernet_header)  
  print "destination:" + binascii.hexlify(eth_header[0]) + " Source:" + binascii.hexlify(eth_header[1]) +  " Type:" + binascii.hexlify(eth_header[2])  
  ip_header = packet[0][14:34]  
  ip_hdr = struct.unpack("!12s4s4s", ip_header)  
  print "Source IP:" + socket.inet_ntoa(ip_hdr[1]) + " Destination IP:" + socket.inet_ntoa(ip_hdr[2]) 

```

这将输出网络卡的源和目标 MAC 地址，以及数据包的源和目标 IP。确保数据包接口设置正确。`PF_PACKE`是 Linux 特定的，我们必须在 Windows 上使用`AF_INET`。同样，我们可以解析 TCP 头部。

### 提示

有关`struct`模块的更多详细信息，请阅读[`docs.python.org/3/library/struct.html`](https://docs.python.org/3/library/struct.html)。

## 原始套接字数据包注入

我们可以使用原始套接字发送自定义制作的数据包。与之前一样，我们可以使用 socket 模块创建原始套接字，如下所示：

```py
import socket #Imported sockets module  

try:  
  #create an INET, raw socket  
  raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))  
except socket.error, e:  
  print ('Error occurred while creating socket. Error code: ' + str(e[0]) + ' , Error message : ' + e[1])  
  sys.exit() 

```

要注入数据包，我们需要将套接字绑定到一个接口：

```py
raw_socket.bind(("wlan0", socket.htons(0x0800))) 

```

现在我们可以使用`struct`的`pack`方法创建以太网数据包，其中包含源地址、目标地址和以太网类型。此外，我们可以向数据包添加一些数据并发送它：

```py
packet =  struct.pack("!6s6s2s", '\xb8v?\x8b\xf5\xfe', 'l\x19\x8f\xe1J\x8c', '\x08\x00') 
raw_socket.send(packet + "Hello") 

```

注入 IP 数据包的整个脚本如下：

```py
import socket #Imported sockets module  
import struct  

try:  
  #Create an raw socket  
  raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))  
except socket.error as e:  
  print 'Error occurred while creating socket. Error code: ' + str(e[0]) + ' , Error message : ' + e[1] 
  sys.exit();  

raw_socket.bind(("wlan0", socket.htons(0x0800)))  
packet =  struct.pack("!6s6s2s", '\xb8v?\x8b\xf5\xfe', 'l\x19\x8f\xe1J\x8c', '\x08\x00')  
raw_socket.send(packet + "Hello")  

```

# 使用 Scapy 调查网络流量

在前面的部分中，我们使用原始套接字嗅探和注入数据包，其中我们必须自己进行解析、解码、创建和注入数据包。此外，原始套接字不兼容所有操作系统。有许多第三方库可以帮助我们处理数据包。Scapy 是一个非常强大的交互式数据包操作库和工具，它在所有这些库中脱颖而出。Scapy 为我们提供了不同级别的命令，从基本级别到高级级别，用于调查网络。我们可以在两种不同的模式下使用 Scapy：在终端窗口内交互式地使用，以及通过将其作为库导入到 Python 脚本中以编程方式使用。

让我们使用交互模式启动 Scapy。交互模式类似于 Python shell；要激活它，只需在终端中以 root 权限运行 Scapy：

```py
 $ sudo scapy

```

这将返回一个交互式的 Scapy 终端：

![使用 Scapy 调查网络流量](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/eff-py-pentest/img/image_02_010.jpg)

以下是一些交互式使用的基本命令：

+   `ls()`: 显示 Scapy 支持的所有协议

+   `lsc()`: 显示 Scapy 支持的命令列表

+   `conf`: 显示所有配置选项

+   `help()`: 显示特定命令的帮助信息，例如，`help(sniff)`

+   `show()`: 显示有关特定数据包的详细信息，例如，`Newpacket.show()`

Scapy 有助于基于其支持的大量协议创建自定义数据包。现在我们可以在交互式 Scapy shell 中使用 Scapy 创建简单的数据包：

```py
>>> packet=IP(dst='google.com')
>>> packet.ttl=10

```

这将创建一个数据包；现在我们可以使用以下方法查看数据包：

```py
>>> packet.show()

```

数据包的使用如下截图所示：

![使用 Scapy 调查网络流量](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/eff-py-pentest/img/image_02_012.jpg)

Scapy 通过每个数据包中的层和每个层中的字段来创建和解析数据包。每个层都封装在父层内。Scapy 中的数据包是 Python 字典，因此每个数据包都是一组嵌套字典，每个层都是父层的子字典。`summary()`方法将提供数据包层的详细信息：

```py
>>> packet[0].summary()
'Ether / IP / UDP 192.168.1.35:20084 > 117.206.55.151:43108 / Raw'

```

数据包的层结构可以通过括号的嵌套（`<`和`>`）更好地看到：

```py
>>> packet[0]
<Ether  dst=6c:19:8f:e1:4a:8c src=b8:76:3f:8b:f5:fe type=0x800 |<IP  version=4L ihl=5L tos=0x0 len=140 id=30417 flags=DF frag=0L ttl=64 proto=udp chksum=0x545f src=192.168.1.35 dst=117.206.55.151 options=[] |<UDP  sport=20084 dport=43108 len=120 chksum=0xd750 |<Raw  load='\x90\x87]{\xa1\x9c\xe7$4\x07\r\x7f\x10\x83\x84\xb5\x1d\xae\xa1\x9eWgX@\xf1\xab~?\x7f\x84x3\xee\x98\xca\xf1\xbdtu\x93P\x8f\xc9\xdf\xb70-D\x82\xf6I\xe0\x84\x0e\xcaH\xd0\xbd\xf7\xed\xf3y\x8e>\x11}\x84T\x05\x98\x02h|\xed\t\xb1\x85\x9f\x8a\xbc\xdd\x98\x07\x14\x10\no\x00\xda\xbf9\xd9\x8d\xecZ\x9a2\x93\x04CyG\x0c\xbd\xf2V\xc6<"\x82\x1e\xeb' |>>>>

```

我们可以通过名称或列表索引中的索引号深入特定层。例如，我们可以使用以下方法获取前面数据包的 UDP 层：

```py
>>> packet[0]
.[UDP].summary()

```

或者您可以使用以下方法获取 UDP 层：

```py
>>> packet[0]
.[2].summary()

```

使用 Scapy，我们可以解析每个层中字段的值。例如，我们可以使用以下方法获取以太网层中的源字段：

```py
 >>> packet[0]
    [Ether].src

```

## 使用 Scapy 进行数据包嗅探

使用 Scapy，使用`sniff`方法`sniff`数据包非常简单。我们可以在 Scapy shell 中运行以下命令，在接口`eth0`中`sniff`：

```py
>>>packet = sniff(iface="eth0", count=3)

```

这将从`eth0`接口获取三个数据包。使用`hexdump()`，我们可以以`hex`格式转储数据包：

![使用 Scapy 进行数据包嗅探](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/eff-py-pentest/img/image_02_014.jpg)

`sniff()`方法的参数如下：

+   `count`：要捕获的数据包数量，但 0 表示无限

+   `iface`：嗅探的接口；仅在此接口上嗅探数据包

+   `prn`：在每个数据包上运行的函数

+   `store`：是否存储或丢弃嗅探到的数据包；当我们只需要监视时设置为 0

+   `timeout`：在给定时间后停止嗅探；默认值为 none

+   `filter`：采用 BPF 语法过滤器以过滤嗅探

如果我们想查看更多的数据包内容，`show()`方法很好。它将以更清晰的方式显示数据包，并产生格式化的打印输出，如下所示：

```py
>>>packet[1].show()

```

此命令将产生以下输出：

![使用 Scapy 进行数据包嗅探](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/eff-py-pentest/img/image_02_016.jpg)

要实时查看嗅探到的数据包，我们必须使用 lambda 函数，以及`summary()`或`show()`方法：

```py
 >>> packet=sniff(filter="icmp", iface="eth0″, count=3, prn=lambda x:x.summary())

```

此外，使用 Scapy 还可以将数据包写入`pcap`文件。要将数据包写入`pcap`文件，我们可以使用`wrpcap()`方法：

```py
 >>>wrpcap("pkt-output.cap" packets)

```

这将把数据包写入`pkt-output.cap`文件。我们可以使用`rdpcap()`从`pcap`文件中读取：

```py
 >>> packets = rdpcap("pkt-output.cap")

```

## 使用 Scapy 进行数据包注入

在注入之前，我们必须创建一个伪造的数据包。使用 Scapy，如果我们知道数据包的分层结构，创建数据包非常简单。要创建 IP 数据包，我们使用以下语法：

```py
 >>> packet = IP (dst="packtpub.com")

```

要向此数据包添加更多子层，我们只需添加以下内容：

```py
 >>> packet = IP (dst="packtpub.com")/ICMP()/"Hello Packt"

```

这将创建一个具有 IP 层、`ICMP`层和原始有效载荷的数据包，如`"Hello Packt"`。`show()`方法将显示此数据包如下：

```py
>>> packet.show()
###[ IP ]###
 version= 4
 ihl= None
 tos= 0x0
 len= None
 id= 1
 flags= 
 frag= 0
 ttl= 64
 proto= icmp
 chksum= None
 src= 192.168.1.35
 dst= Net('packtpub.com')
 \options\
###[ ICMP ]###
 type= echo-request
 code= 0
 chksum= None
 id= 0x0
 seq= 0x0
###[ Raw ]###
 load= 'Hello world'

```

发送数据包有两种方法：

+   `sendp()`: 第二层发送；发送第二层数据包

+   `send()`: 第三层发送；仅发送第三层数据包，如 IPv4 和 Ipv6

发送命令的主要参数如下：

+   `iface`：发送数据包的接口

+   `inter`：两个数据包之间的时间（以秒为单位）

+   `loop`：设置为`1`以无限发送数据包

+   `packet`：数据包或数据包列表

如果我们使用的是第二层发送，我们必须添加一个以太网层并提供正确的接口来发送数据包。但是对于第三层，发送所有这些路由信息将由 Scapy 自己处理。因此，让我们使用第三层发送先前创建的数据包：

```py
>>> send(packet)

```

我们可以使用另一个 Scapy 交互式终端来嗅探我们发送的数据包。输出将如下所示，第二个数据包是我们从`packtpub.com`收到的响应：

![使用 Scapy 进行数据包注入](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/eff-py-pentest/img/image_02_017.jpg)

类似地，要发送第二层数据包，我们必须添加以太网标头和接口，如下所示：

```py
 >>> sendp(Ether()/IP(dst="packtpub.com")/ICMP()/"Layer 2 packet", iface="eth0")

```

## Scapy 发送和接收方法

这些方法用于在期望收到响应时发送数据包或一组数据包。有四种不同类型的发送和接收方法。它们如下：

+   `sr()`: 第三层发送和接收，返回答案和未答案数据包

+   `sr1()`: 第 3 层发送和接收，仅返回答案或已发送的数据包

+   `srp()`: 第 2 层发送和接收，返回答案和未答复的数据包

+   `srp1()`: 第 2 层发送和接收，仅返回答案或已发送的数据包

这些方法几乎与`send()`方法相似。要发送数据包并接收其响应，请使用以下命令：

```py
>>> packet = IP (dst="packtpub.com")/ICMP()/"Hello Packt"
>>> sr(packet)
Begin emission:
.Finished to send 1 packets.
.*
Received 3 packets, got 1 answers, remaining 0 packets
(<Results: TCP:0 UDP:0 ICMP:1 Other:0>, <Unanswered: TCP:0 UDP:0 ICMP:0 Other:0>)

```

在等待响应时，Scapy 收到了三个数据包，并在收到响应时退出。如果我们使用`sr1()`，这将仅等待一个响应并打印响应数据包。同样，我们可以使用`srp()`和`srp1()`方法发送第 2 层数据包。

## 使用 Scapy 进行编程

早些时候，我们在交互模式下使用了 Scapy。但在某些情况下，我们可能需要在脚本中使用 Scapy。如果在我们的程序中导入了 Scapy，Scapy 可以作为一个库来使用。我们可以按照以下方式导入所有 Scapy 函数：

```py
from scapy.all import* 

```

或者，如果我们只需要一些功能，我们可以导入特定的包，如下所示：

```py
from scapy.all Ether, IP, TCP, sr1 

```

例如，我们可以创建一个 DNS 请求。使用`sr1()`方法，我们可以创建并获取 DNS 请求的响应。由于 DNS 数据包是由 IP 和 UDP 数据包构建的，因此我们可以在其中创建一个包含 IP 和 UDP 层的 DNS 数据包：

```py
from scapy.all import * #Import Scapy 
# Create a DNS request Packet to 8.8.8.8  
dns_packet = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="packtpub.com")) 

# Send packet and get the response 
dns_request = sr1(dns_packet,verbose=1) 
# Print the response 
print dns_request[DNS].summary() 

```

我们必须以 root 权限运行此脚本。如果 verbose 选项为`1`，输出将如下所示：

```py
$ sudo python dns_scapy.py 
 WARNING: No route found for IPv6 destination :: (no default route?)
 Begin emission:
 Finished to send 1 packets
 Received 18 packets, got 1 answers, remaining 0 packets
 DNS Ans "83.166.169.231"

```

要解析 DNS 数据包，我们可以使用`sniff()`方法。`sniff()`中的`prn`参数可用于更改 Scapy 对每个数据包的输出。它有助于用我们自己的函数替换默认的 Scapy 打印输出，因此我们可以决定 Scapy 如何打印每个数据包的输出。在以下示例中，每次通过过滤器匹配数据包并使用 Scapy 进行嗅探时，我们都使用`select_DNS()`函数：

```py
from scapy.all import * #Import Scapy 
from datetime import datetime 
interface = 'eth0' #Interface to sniff 
filter_bpf = 'udp and port 53' #BPF filter to filter udp packets in port 53 

#Runs this for each packet 
def select_DNS(packet): 
    packet_time = packet.sprintf('%sent.time%') 
    try: 
        if DNSQR in packet and packet.dport == 53: 
        #Print queries 
           print 'DNS queries Message from '+ packet[IP].src + '
           to ' + packet[IP].dst +' at ' + packet_time 

        elif DNSRR in packet and packet.sport == 53: 
        #Print responses 
           print 'DNS responses Message from '+ packet[IP].src + '
           to ' + packet[IP].dst +' at ' + packet_time 
    except: 
        pass 
#Sniff the packets  
sniff(iface=interface, filter=filter_bpf, store=0, prn=select_DNS) 

```

像往常一样，在前两行中导入了必要的模块 Scapy 和 datetime；稍后，我们声明了要嗅探的接口和使用**伯克利数据包过滤器**（**BPF**）语法从端口`53`获取`udp`数据包的过滤器：

```py
from scapy.all import * #Import Scapy 
from datetime import datetime 

interface = 'eth0' #Interface to sniff 
filter_bpf = 'udp and port 53' #BPF filter to filter udp packets in port 53 

```

然后我们声明了每次使用`sniff()`方法嗅探数据包时要调用的函数。这将修改`sniff()`中的默认打印摘要并提供自定义输出。在这里，它将检查 DNS 数据包并输出其源目的地和时间。`prn`参数用于将此函数绑定到`sniff()`方法：

```py
def select_DNS(packet): 
    packet_time = packet.sprintf('%sent.time%') 
    try: 
        if DNSQR in packet and packet.dport == 53: 
        #Print queries 
           print 'DNS queries Message from '+ packet[IP].src + '
           to ' + packet[IP].dst +' at ' + packet_time 

        elif DNSRR in packet and packet.sport == 53: 
        #Print responses 
           print 'DNS responses Message from '+ packet[IP].src + '
           to ' + packet[IP].dst +' at ' + packet_time 
    except: 
        pass 

```

最后，我们将使用`sniff()`方法和`select_DNS()`函数作为`prn`参数进行调用。

```py
sniff(iface=interface, filter=filter_bpf, store=0, prn=select_DNS) 

```

### 提示

有关伯克利数据包过滤器（BPF）语法的更多详细信息，请阅读[`biot.com/capstats/bpf.html`](http://biot.com/capstats/bpf.html)。

让我们来检查另一个操作系统指纹识别的示例；我们可以通过两种方法来实现：

+   Nmap 指纹识别

+   p0f

如果您的系统上安装了 Nmap，我们可以利用其主动 OS 指纹数据库与 Scapy 一起使用。确保签名数据库位于`conf.nmap_base`中指定的路径中。如果您使用默认安装目录，Scapy 将自动检测指纹文件。

我们可以使用以下命令加载`nmap`模块：

```py
load_module("nmap") 

```

然后我们可以使用`nmap_fp()`函数开始对操作系统进行指纹识别。

```py
nmap_fp("192.168.1.1",oport=443,cport=1) 

```

如果我们安装了`p0f`，我们可以使用它来识别操作系统。确保配置`conf.p0f_base`是正确的。我们可以从单个捕获的数据包中猜测操作系统，方法如下：

```py
sniff(prn=prnp0f) 

```

### 提示

有关 Scapy 的更多详细信息，请阅读[`www.secdev.org/projects/scapy/doc/usage.html`](http://www.secdev.org/projects/scapy/doc/usage.html)。

# 总结

我们已经学习了使用各种 Python 模块进行数据包制作和嗅探的基础知识，并且发现 Scapy 非常强大且易于使用。到目前为止，我们已经学习了套接字编程和 Scapy 的基础知识。在我们的安全评估过程中，我们可能需要原始输出和对数据包拓扑的基本访问权限，以便我们可以自行分析和做出决策。Scapy 最吸引人的部分是可以将其导入并用于创建网络工具，而无需从头开始创建数据包。

我们将在下一章更详细地讨论使用 Python 进行应用指纹识别。


# 第三章：使用 Python 进行应用指纹识别

在 Web 应用程序安全评估期间的一个重要步骤是指纹识别。作为安全研究人员/渗透测试人员，我们必须精通指纹识别，这可以提供有关底层技术（如软件或框架版本、Web 服务器信息、操作系统等）的大量信息。这有助于我们发现影响应用程序和服务器的所有众所周知的漏洞。

在本章中，我们将涵盖以下主题：

+   网络爬虫

+   电子邮件收集

+   操作系统指纹识别

+   EXIF 数据提取

+   应用指纹识别

# 网络爬虫

尽管一些网站提供 API，但大多数网站主要设计供人类使用，只提供为人类格式化的 HTML 页面。如果我们想要程序从这样的网站获取一些数据，我们必须解析标记以获取所需的信息。网络爬虫是使用计算机程序分析网页并获取所需数据的方法。

有许多方法可以使用 Python 模块从网站获取内容：

+   使用`urllib`/`urllib2`创建将获取网页的 HTTP 请求，并使用`BeautifulSoup`解析 HTML

+   要解析整个网站，我们可以使用 Scrapy（[`scrapy.org`](http://scrapy.org)），它有助于创建网络爬虫

+   使用 requests 模块获取并使用 lxml 解析

## urllib / urllib2 模块

Urllib 是一个高级模块，允许我们脚本化不同的服务，如 HTTP、HTTPS 和 FTP。

### urllib/urllib2 的有用方法

Urllib/urllib2 提供了一些方法，可用于从 URL 获取资源，包括打开网页，编码参数，操作和创建标头等。我们可以按以下方式使用其中一些有用的方法：

+   使用`urlopen()`打开网页。当我们将 URL 传递给`urlopen()`方法时，它将返回一个对象，我们可以使用`read()`属性以字符串格式从该对象获取数据，如下所示：

```py
        import urllib 

        url = urllib.urlopen("http://packtpub.com/") 

        data = url.read() 

        print data 

```

+   下一个方法是参数编码：`urlencode()`。它接受字段字典作为输入，并创建参数的 URL 编码字符串：

```py
        import urllib 

        fields = { 
          'name' : 'Sean', 
          'email' : 'Sean@example.com' 
        } 

        parms = urllib.urlencode(fields) 
        print parms 

```

+   另一种方法是使用参数发送请求，例如，使用 GET 请求：URL 是通过附加 URL 编码的参数来构建的：

```py
        import urllib 
        fields = { 
          'name' : 'Sean', 
          'email' : 'Sean@example.com' 
        } 
        parms = urllib.urlencode(fields) 
        u = urllib.urlopen("http://example.com/login?"+parms) 
        data = u.read() 

        print data 

```

+   使用 POST 请求方法，URL 编码的参数分别传递给方法`urlopen()`：

```py
        import urllib 
        fields = { 
          'name' : 'Sean', 
          'email' : 'Sean@example.com' 
        } 
        parms = urllib.urlencode(fields) 
        u = urllib.urlopen("http://example.com/login", parms) 
        data = u.read() 
        print data 

```

+   如果我们使用响应头，那么可以使用`info()`方法检索 HTTP 响应头，它将返回类似字典的对象：

```py
        u = urllib.urlopen("http://packtpub.com", parms) 
        response_headers = u.info() 
        print response_headers 

```

+   输出如下：

![urllib/urllib2 的有用方法](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/eff-py-pentest/img/image_03_001.jpg)

+   我们还可以使用`keys()`来获取所有响应头键：

```py
>>> print response_headers.keys() 
['via', 'x-country-code', 'age', 'expires', 'server',
        'connection', 'cache-control', 'date', 'content-type']

```

+   我们可以按如下方式访问每个条目：

```py
>>>print response_headers['server'] 
nginx/1.4.5 

```

### 注意

Urllib 不支持 cookies 和身份验证。它只支持 GET 和 POST 请求。Urllib2 是建立在 urllib 之上的，具有更多功能。

+   我们可以使用 code 方法获取状态码：

```py
        u = urllib.urlopen("http://packtpub.com", parms) 
        response_code = u.code 
        print response_code 

```

+   我们可以使用`urllib2`修改请求头，如下所示：

```py
        headers = { 
         'User-Agent' : 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64;
        rv:41.0) Gecko/20100101 Firefox/41.0' 
        }
        request = urllib2.Request("http://packtpub.com/",
         headers=headers)
        url = urllib2.urlopen(request)
        response = url.read()

```

+   可以如下使用 cookies：

```py
        fields = {  
        'name' : 'sean',  
        'password' : 'password!',  
        'login' : 'LogIn'  
        }  

        # Here we creates a custom opener with cookies enabled 
        opener = urllib2.build_opener(  
        urllib2.HTTPCookieProcessor()  
        )  

        # creates request 
        request = urllib2.Request(  
          "http://example.com/login",  
          urllib.urlencode(fields))  

        # Login request sending 
        url = opener.open(request)  
        response = url.read()  

        # Now we can access the private pages with the cookie  
        # got from the above login request 
        url = opener.open("http://example.com/dashboard")  
        response = url.read() 

```

### 请求模块

我们也可以使用 requests 模块而不是`urllib`/`urllib2`，这是一个更好的选择，因为它支持完全的 REST API，并且它只需将字典作为参数而不需要任何编码的参数：

```py
import requests 
response = requests.get("http://packtpub.com", parms) 

# Response 
print response.status_code # Response Code   
print response.headers # Response Headers   
print response.content # Response Content 

# Request 
print response.request.headers # Headers we sent 

```

### 使用 BeautifulSoup 解析 HTML

前面的模块只能用于获取文件。如果我们想要解析通过`urlopen`获得的 HTML，我们必须使用`BeautifulSoup`模块。`BeautifulSoup`接受来自`urlopen`的原始 HTML 和 XML 文件，并从中提取数据。要运行解析器，我们必须创建一个解析器对象并提供一些数据。它将扫描数据并触发各种处理程序方法。Beautiful Soup 4 适用于 Python 2.6+和 Python 3。

以下是一些简单的示例：

+   要使 HTML 格式化，使用以下代码：

```py
         from bs4 import BeautifulSoup  

         parse = BeautifulSoup('<html><head><title>Title of the
         page</title></head><body><p id="para1" 
         align="center">This is a paragraph<b>one</b><a 
         href="http://example1.com">Example Link 1</a> </p><p 
         id="para2">This is a paragraph<b>two</b><a 
         href="http://example2.com">Example Link 2</a></p></body>
         </html>')  

         print parse.prettify()  

```

+   输出如下：

![使用 BeautifulSoup 解析 HTML](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/eff-py-pentest/img/image_03_004.jpg)

+   使用`BeautifulSoup`导航 HTML 的一些示例方法如下：

```py
parse.contents[0].name
>>> u'html'
parse.contents[0].contents[0].name
>>> u'head'
head = soup.contents[0].contents[0]
head.parent.name
>>> u'html'
head.next
>>> <title>Page title</title>
head.nextSibling.name
>>> u'body'
head.nextSibling.contents[0]
>>> <p id="para1" align="center">This is a 
        paragraph<b>one</b><a href="http://example1.com">Example 
        Link 1</a> </p>
head.nextSibling.contents[0].nextSibling
>>> <p id="para2">This is a paragraph<b>two</b><a 
        href="http://example2.com">Example Link 2</a></p> 

```

+   搜索 HTML 标签和属性的一些方法如下：

```py
parse.find_all('a')
>>> [<a href="http://example1.com">Example Link 1</a>, <a
        href="http://example2.com">Example Link 2</a>]
parse.find(id="para2")
>>> <p id="para2">This is a paragraph<b>two</b><a 
        href="http://example2.com">Example Link 2</a></p>

```

### 下载页面上的所有图像

现在我们可以编写一个脚本来下载页面上的所有图像，并将它们保存在特定位置：

```py
# Importing required modules 
import requests   
from bs4 import BeautifulSoup   
import urlparse #urlparse is renamed to urllib.parse in Python  

# Get the page with the requests 
response = requests.get('http://www.freeimages.co.uk/galleries/food/breakfast/index.htm')   

# Parse the page with BeautifulSoup 
parse = BeautifulSoup(response.text) 

# Get all image tags 
image_tags = parse.find_all('img') 

# Get urls to the images 
images = [ url.get('src') for url in image_tags] 
# If no images found in the page 

if not images:   
    sys.exit("Found No Images") 
# Convert relative urls to absolute urls if any 
images = [urlparse.urljoin(response.url, url) for url in images]   
print 'Found %s images' % len(images) 

# Download images to downloaded folder 
for url in images:   
    r = requests.get(url) 
    f = open('downloaded/%s' % url.split('/')[-1], 'w') 
    f.write(r.content) 
    f.close() 
    print 'Downloaded %s' % url 

```

# 使用 lxml 解析 HTML

另一个强大、快速、灵活的解析器是 lxml 附带的 HTML 解析器。由于 lxml 是一个用于解析 XML 和 HTML 文档的广泛库，它可以处理过程中混乱的标签。

让我们从一个例子开始。

在这里，我们将使用 requests 模块检索网页并用 lxml 解析它：

```py
#Importing modules 
from lxml import html 
import requests 

response = requests.get('http://packtpub.com/') 
tree = html.fromstring(response.content) 

```

现在整个 HTML 保存在`tree`中，以一种良好的树结构，我们可以用两种不同的方式来检查：XPath 或 CSS 选择。XPath 用于在结构化文档（如 HTML 或 XML）中导航元素和属性以查找信息。

我们可以使用任何页面检查工具，如 Firebug 或 Chrome 开发者工具，来获取元素的 XPath：

![使用 lxml 解析 HTML](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/eff-py-pentest/img/image_03_007.jpg)

如果我们想要从列表中获取书名和价格，找到源代码中的以下部分。

```py
<div class="book-block-title" itemprop="name">Book 1</div> 

```

从中我们可以创建 Xpath 如下：

```py
#Create the list of Books: 

books = tree.xpath('//div[@class="book-block-title"]/text()') 

```

然后我们可以使用以下代码打印列表：

```py
print books 

```

### 注意

在[lxml.de](http://lxml.de)上了解更多关于 lxml 的信息。

## Scrapy

Scrapy 是一个用于网页抓取和爬取的开源框架。这可以用来解析整个网站。作为一个框架，它有助于为特定需求构建蜘蛛。除了 Scrapy，我们还可以使用 mechanize 编写可以填写和提交表单的脚本。

我们可以利用 Scrapy 的命令行界面来为新的爬虫脚本创建基本样板。Scrapy 可以通过`pip`安装。

要创建一个新的蜘蛛，我们必须在安装 Scrapy 后在终端中运行以下命令：

```py
 $ scrapy startproject testSpider

```

这将在当前工作目录`testSpider`中生成一个项目文件夹。这也将在文件夹内创建一个基本结构和文件，用于我们的 spider：

![Scrapy](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/eff-py-pentest/img/image_03_010.jpg)

Scrapy 有 CLI 命令来创建一个蜘蛛。要创建一个蜘蛛，我们必须输入`startproject`命令生成的文件夹：

```py
 $ cd testSpider

```

然后我们必须输入生成蜘蛛命令：

```py
 $ scrapy genspider pactpub pactpub.com

```

这将生成另一个名为`spiders`的文件夹，并在该文件夹内创建所需的文件。然后，文件夹结构将如下所示：

![Scrapy](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/eff-py-pentest/img/image_03_011.jpg)

现在打开`items.py`文件，并在子类中定义一个新项目，名为`TestspiderItem`：

```py
from scrapy.item import Item, Field 
class TestspiderItem(Item): 
    # define the fields for your item here: 
    book = Field() 

```

大部分爬取逻辑都是由 Scrapy 在`spider`文件夹内的`pactpub`类中提供的，所以我们可以扩展这个来编写我们的`spider`。为了做到这一点，我们必须编辑 spider 文件夹中的`pactpub.py`文件。

在`pactpub.py`文件中，首先我们导入所需的模块：

```py
from scrapy.spiders import Spider 
from scrapy.selector import Selector 
from pprint import pprint 
from testSpider.items import TestspiderItem 

```

然后，我们必须扩展 Scrapy 的 spider 类，以定义我们的`pactpubSpider`类。在这里，我们可以定义域和爬取的初始 URL：

```py
# Extend  Spider Class 
class PactpubSpider(Spider): 
    name = "pactpub" 
    allowed_domains = ["pactpub.com"] 
    start_urls = ( 
        'https://www.pactpub.com/all', 
    ) 

```

之后，我们必须定义解析方法，它将创建我们在`items.py`文件中定义的`TestspiderItem()`的一个实例，并将其分配给项目变量。

然后我们可以添加要提取的项目，可以使用 XPATH 或 CSS 样式选择器。

在这里，我们使用 XPATH 选择器：

```py
    # Define parse 
    def parse(self, response): 
        res = Selector(response) 
        items = [] 
        for sel in res.xpath('//div[@class="book-block"]'): 
            item = TestspiderItem() 
            item['book'] = sel.xpath('//div[@class="book-block-title"]/text()').extract() 
            items.append(item) 
        return items 

```

现在我们准备运行`spider`。我们可以使用以下命令运行它：

```py
 $ scrapy crawl pactpub --output results.json

```

这将使用我们定义的 URL 启动 Scrapy，并且爬取的 URL 将传递给`testspiderItems`，并为每个项目创建一个新实例。

## 电子邮件收集

使用之前讨论的 Python 模块，我们可以从网页中收集电子邮件和其他信息。

要从网站获取电子邮件 ID，我们可能需要编写定制的抓取脚本。

在这里，我们讨论了一种从网页中提取电子邮件的常见方法。

让我们通过一个例子。在这里，我们使用`BeautifulSoup`和 requests 模块：

```py
# Importing Modules  
from bs4 import BeautifulSoup 
import requests 
import requests.exceptions 
import urlparse 
from collections import deque 
import re 

```

接下来，我们将提供要爬取的 URL 列表：

```py
# List of urls to be crawled 
urls = deque(['https://www.packtpub.com/']) 

```

接下来，我们将处理过的 URL 存储在一个集合中，以便不重复处理它们：

```py
# URLs that we have already crawled 
scraped_urls = set() 

```

收集的电子邮件也存储在一个集合中：

```py
# Crawled emails 
emails = set() 

```

当我们开始抓取时，我们将从队列中获取一个 URL 并处理它，并将其添加到已处理的 URL 中。此外，我们将一直这样做，直到队列为空为止：

```py
# Scrape urls one by one queue is empty 
while len(urls): 
    # move next url from the queue to the set of Scraped urls 
    url = urls.popleft() 
    scrapped_urls.add(url) 

```

使用`urlparse`模块，我们将获得基本 URL。这将用于将相对链接转换为绝对链接：

```py
    # Get  base url 
    parts = urlparse.urlsplit(url) 
    base_url = "{0.scheme}://{0.netloc}".format(parts) 
    path = url[:url.rfind('/')+1] if '/' in parts.path else url 

```

URL 的内容将在 try-catch 中可用。如果出现错误，它将转到下一个 URL：

```py
    # get url's content 
    print("Scraping %s" % url) 
    try: 
        response = requests.get(url) 
    except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError): 
        # ignore  errors 
        continue 

```

在响应中，我们将搜索电子邮件并将找到的电子邮件添加到电子邮件集合中：

```py
    # Search e-mail addresses and add them into the output set 
    new_emails = set(re.findall(r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+", response.text, re.I)) 
    emails.update(new_emails) 

```

在抓取页面后，我们将获取所有链接到其他页面的链接并更新 URL 队列：

```py
    # find and process all the anchors 
    for anchor in soup.find_all("a"): 
        # extract link url 
        link = anchor.attrs["href"] if "href" in anchor.attrs else '' 
        # resolve relative links 
        if link.startswith('/'): 
            link = base_url + link 
        elif not link.startswith('http'): 
            link = path + link 
        # add the new url to the queue 

        if not link in urls and not link in scraped_urls: 
            urls.append(link) 

```

# OS 指纹识别

渗透测试中的常见过程是识别主机使用的操作系统。通常，这涉及到像 hping 或 Nmap 这样的工具，在大多数情况下，这些工具为了获取这样的信息而相当激进，并可能在目标主机上引发警报。OS 指纹主要分为两类：主动 OS 指纹和被动 OS 指纹。

主动指纹识别是发送数据包到远程主机并分析相应响应的方法。在被动指纹识别中，它分析来自主机的数据包，因此不会向主机发送任何流量，并充当嗅探器。在被动指纹识别中，它嗅探 TCP/IP 端口，因此可以避免被防火墙检测或停止。被动指纹识别通过分析 IP 头数据包中的初始**生存时间**（**TTL**）以及 TCP 会话的第一个数据包中的 TCP 窗口大小来确定目标 OS。TCP 会话的第一个数据包通常是 SYN（同步）或 SYN/ACK（同步和确认）数据包。

以下是一些操作系统的正常数据包规格：

| **OS** | **初始 TTL** | **TCP 窗口大小** |
| --- | --- | --- |
| Linux 内核 2.x | 64 毫秒 | 5,840 千字节 |
| Android / Chrome OS | 64 毫秒 | 5,720 千字节 |
| Windows XP | 128 毫秒 | 65,535 千字节 |
| Windows 7/ Server 2008 | 128 毫秒 | 8,192 千字节 |
| Cisco 路由器（IOS 12.4） | 255 毫秒 | 4,128 千字节 |
| FreeBSD | 64 毫秒 | 65,535 千字节 |

被动 OS 指纹识别不如主动方法准确，但它有助于渗透测试人员避免被检测到。

在指纹系统时另一个有趣的领域是**初始序列号**（**ISN**）。在 TCP 中，对话的成员通过使用 ISN 来跟踪已看到的数据和下一个要发送的数据。在建立连接时，每个成员都将选择一个 ISN，随后的数据包将通过将该数字加一来编号。

Scrapy 可用于分析 ISN 增量以发现易受攻击的系统。为此，我们将通过在循环中发送一定数量的 SYN 数据包来收集来自目标的响应。

使用`sudo`权限启动交互式 Python 解释器并导入 Scrapy：

```py
>>> from scrapy.all import *
>>> ans,unans=srloop(IP(dst="192.168.1.123")/TCP(dport=80,flags="S"))

```

在收集了一些响应后，我们可以打印数据进行分析：

```py
>>> temp = 0
>>> for s,r in ans:
...     temp = r[TCP].seq - temp
...     print str(r[TCP].seq) + "\t+" + str(temp)

```

这将打印出用于分析的 ISN 值。

如果我们安装了 Nmap，我们可以使用 Nmap 的主动指纹数据库与 Scapy 一起使用，方法如下；确保我们已经配置了 Nmap 的指纹数据库`conf.nmap_base`：

```py
>>> from scapy.all import *
>>> from scapy.modules.nmap import *
>>> conf.nmap_base ="/usr/share/nmap/nmap-os-db" 
>>> nmap_fp("192.168.1.123")

```

此外，如果我们的系统上安装了`p0f`，我们还可以使用它来猜测 Scapy 的 OS：

```py
>>> from scapy.all import *
>>> from scapy.modules.pof import *
>>> conf.p0f_base ="/etc/p0f/p0f.fp"
>>> conf.p0fa_base ="/etc/p0f/p0fa.fp"
>>> conf.p0fr_base ="/etc/p0f/p0fr.fp"
>>> conf.p0fo_base ="/etc/p0f/p0fo.fp"
>>> sniff(prn=prnp0f) 

```

# 获取图像的 EXIF 数据

我们可以从在线发布的图像中找到大量信息。对于我们用智能手机或相机拍摄的每张照片，它都记录了日期、时间、快门速度、光圈设置、ISO 设置、是否使用了闪光灯、焦距等等。这些信息存储在照片中，被称为*EXIF*数据。当我们复制一张图像时，EXIF 数据也会被复制，作为图像的一部分。这可能会带来隐私问题。例如，使用 GPS 启用的手机拍摄的照片，可以显示拍摄的位置和时间，以及设备的唯一 ID 号：

```py
import os,sys 

from PIL import Image 

from PIL.ExifTags import TAGS 

for (i,j) in Image.open('image.jpg')._getexif().iteritems(): 

        print '%s = %s' % (TAGS.get(i), j) 

```

首先，我们导入了`PIL`图像和`PIL TAGS`模块。`PIL`是 Python 中的图像处理模块。它支持许多文件格式，并具有强大的图像处理能力。然后我们遍历结果并打印数值。

还有许多其他模块支持 EXIF 数据提取，比如`ExifRead`。

# Web 应用指纹识别

Web 应用指纹识别是安全评估信息收集阶段的主要部分。它帮助我们准确识别应用程序并找出已知的漏洞。这也允许我们根据信息定制有效载荷或利用技术。最简单的方法是在浏览器中打开网站并查看其特定关键字的源代码。同样，使用 Python，我们可以下载页面然后运行一些基本的正则表达式，这可以给你结果。

我们可以使用`urllib`/`requests`模块与 BeautifulSoup 或 lxml 结合下载网站，就像我们在本章讨论的那样。

# 总结

在本章中，我们讨论了下载和解析网站的可能方法。使用本章讨论的基本方法，我们可以构建自己的扫描器和网络爬虫。

在下一章中，我们将讨论更多使用 Python 的攻击脚本技术。
