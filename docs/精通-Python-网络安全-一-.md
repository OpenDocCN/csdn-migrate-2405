# 精通 Python 网络安全（一）

> 原文：[`zh.annas-archive.org/md5/2fd2c4f6d02f5009e067781f7b1aee0c`](https://zh.annas-archive.org/md5/2fd2c4f6d02f5009e067781f7b1aee0c)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

最近，Python 开始受到越来越多的关注，最新的 Python 更新添加了许多可用于执行关键任务的包。我们的主要目标是帮助您利用 Python 包来检测和利用漏洞，并解决网络挑战。

本书将首先带您了解与网络和安全相关的 Python 脚本和库。然后，您将深入了解核心网络任务，并学习如何解决网络挑战。随后，本书将教您如何编写安全脚本，以检测网络或网站中的漏洞。通过本书，您将学会如何利用 Python 包实现端点保护，以及如何编写取证和加密脚本。

# 本书适合对象

本书非常适合网络工程师、系统管理员以及希望解决网络和安全挑战的任何安全专业人士。对 Python 及其网络和安全包感兴趣的安全研究人员和开发人员也会从本书中受益匪浅。

# 本书涵盖内容

第一章，*使用 Python 脚本*，向您介绍了 Python 语言、面向对象编程、数据结构、以及使用 Python 进行开发的方法和开发环境。

第二章，*系统编程包*，教授您有关系统编程的主要 Python 模块，涵盖主题包括读写文件、线程、套接字、多线程和并发。

第三章，*套接字编程*，为您提供了使用 socket 模块进行 Python 网络编程的一些基础知识。socket 模块公开了编写 TCP 和 UDP 客户端以及服务器所需的所有必要部分，用于编写低级网络应用程序。

第四章，*HTTP 编程*，涵盖了 HTTP 协议和主要的 Python 模块，如 urllib 标准库和 requests 包。我们还涵盖了 HTTP 身份验证机制以及如何使用 requests 模块来管理它们。

第五章，*分析网络流量*，为您提供了使用 Scapy 在 Python 中分析网络流量的一些基础知识。调查人员可以编写 Scapy 脚本来调查通过嗅探混杂网络接口的实时流量，或加载先前捕获的`pcap`文件。

第六章，*从服务器获取信息*，探讨了允许提取服务器公开的信息的模块，如 Shodan。我们还研究了获取服务器横幅和 DNS 服务器信息，并向您介绍了模糊处理。

第七章，*与 FTP、SSH 和 SNMP 服务器交互*，详细介绍了允许我们与 FTP、SSH 和 SNMP 服务器交互的 Python 模块。

第八章，*使用 Nmap 扫描器*，介绍了 Nmap 作为端口扫描器，并介绍了如何使用 Python 和 Nmap 实现网络扫描，以获取有关网络、特定主机以及在该主机上运行的服务的信息。此外，我们还介绍了编写例程以查找 Nmap 脚本中给定网络可能存在的漏洞。

第九章，*与 Metasploit 框架连接*，介绍了 Metasploit 框架作为利用漏洞的工具，并探讨了如何使用`python-msfprc`和`pymetasploit`模块。

第十章，“与漏洞扫描器交互”，介绍了 Nessus 和 Nexpose 作为漏洞扫描器，并为它们在服务器和 Web 应用程序中发现的主要漏洞提供了报告工具。此外，我们还介绍了如何使用 Python 中的`nessrest`和`Pynexpose`模块对它们进行程序化操作。

第十一章，“识别 Web 应用程序中的服务器漏洞”，涵盖了 OWASP 方法论中的 Web 应用程序中的主要漏洞，以及 Python 生态系统中用于 Web 应用程序漏洞扫描的工具。我们还介绍了如何测试服务器中的 openSSL 漏洞。

第十二章，“从文档、图片和浏览器中提取地理位置和元数据”，探讨了 Python 中用于从图片和文档中提取地理位置和元数据、识别 Web 技术以及从 Chrome 和 Firefox 中提取元数据的主要模块。

第十三章，“加密和隐写术”，深入探讨了 Python 中用于加密和解密信息的主要模块，如`pycrypto`和 cryptography。此外，我们还介绍了隐写术技术以及如何使用`stepic`模块在图片中隐藏信息。

# 为了充分利用本书

您需要在本地计算机上安装 Python 发行版，内存至少为 4GB。

在第九章、第十章和第十一章中，我们将使用一个名为 metasploitable 的虚拟机，用于进行与端口分析和漏洞检测相关的一些测试。可以从 SourceForge 页面下载：

[`sourceforge.net/projects/metasploitable/files/Metasploitable2`](https://sourceforge.net/projects/metasploitable/files/Metasploitable2)

对于第九章，您还需要安装 Kali Linux 发行版和 Python，以执行 Metasploit Framework。

在本书中，您可以找到基于 Python 2 和 3 版本的示例。虽然许多示例可以在 Python 2 中运行，但使用最新版本的 Python 3 会获得最佳体验。在撰写本文时，最新版本为 2.7.14 和 3.6.15，并且这些示例已针对这些版本进行了测试。

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packt.com](http://www.packt.com)。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在“搜索”框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩软件解压文件夹：

+   Windows 上的 WinRAR/7-Zip

+   Mac 上的 Zipeg/iZip/UnRarX

+   Linux 上的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security`](https://github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security)。如果代码有更新，将在现有的 GitHub 存储库中进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在此处下载：[`www.packtpub.com/sites/default/files/downloads/9781788992510_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/9781788992510_ColorImages.pdf)

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。例如："将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。"

代码块设置如下：

```py
import requests
if __name__ == "__main__":
    response = requests.get("http://www.python.org")
    for header in response.headers.keys():
        print(header  + ":" + response.headers[header])
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```py
import requests
http_proxy = "http://<ip_address>:<port>"
proxy_dictionary = { "http" : http_proxy}
requests.get("http://example.org", proxies=proxy_dictionary)
```

任何命令行输入或输出都将按如下方式编写：

```py
$ pip install packagename
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。例如："从管理面板中选择系统信息。"

警告或重要提示会以这种方式出现。提示和技巧会以这种方式出现。


# 第一章：使用 Python 脚本

在本章中，我们将介绍 Python 脚本、集合、函数、异常处理和面向对象编程。我们将回顾如何创建类、对象以及 Python 初始化对象的特点，包括使用特殊属性和方法。还将介绍一种方法、工具和开发环境。

本章将涵盖以下主题：

+   编程和安装 Python

+   数据结构和 Python 集合

+   Python 函数和异常处理

+   Python 中的面向对象编程

+   包括如何管理模块、包、依赖项、传递参数、使用虚拟环境以及 Python 脚本的`STB`模块的 OMSTD 方法论

+   Python 脚本开发的主要开发环境

+   与 Python IDE 交互和调试

# 技术要求

在开始阅读本书之前，您应该了解 Python 编程的基础知识，如基本语法、变量类型、数据类型元组、列表字典、函数、字符串和方法。在[python.org/downloads/](http://python.org/downloads/)上提供了两个版本，3.6.5 和 2.7.14。

本章的示例和源代码可在 GitHub 存储库的`chapter 1`文件夹中找到：[`github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security`](https://github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security)。

# 编程和安装 Python

Python 是一种易于阅读和编写的字节编译的面向对象编程语言。这种语言非常适合安全专业人员，因为它允许快速创建测试以及可重用的项目以供将来使用。由于许多安全工具都是用 Python 编写的，它为对已经编写的工具进行扩展和添加功能提供了许多机会。

# 介绍 Python 脚本

在本书中，我们将使用两个版本。如果您使用 Debian 或 Kali 等 Linux 发行版，那么不会有问题，因为 Python 是多平台的，并且在大多数 Linux 发行版中默认安装了 2.7 版本。

# 为什么选择 Python？

有很多选择 Python 作为主要编程语言的原因：

+   多平台和开源语言。

+   简单、快速、强大的语言。

+   许多关于计算机安全的库、模块和项目都是用 Python 编写的。

+   有很多文档和一个非常庞大的用户社区。

+   这是一种设计用于用几行代码创建强大程序的语言，而在其他语言中，只有在包含每种语言的许多特性之后才有可能实现。

+   适用于原型和快速概念测试（PoC）。

# 多平台

Python 解释器可在许多平台上使用（Linux、DOS、Windows 和 macOS X）。我们在 Python 中创建的代码在第一次执行时会被翻译成字节码。因此，在我们要执行 Python 中开发的程序或脚本的系统中，我们需要安装解释器。

# 面向对象编程

面向对象编程是一种范式，程序是通过“对象类”来定义的，它们通过发送消息来相互通信。它是程序化、结构化和模块化编程范式的演变，并在 Java、Python 或 C++等语言中实现。

类定义了对象中指定的行为和可用状态，并允许更直接地表示建模问题所需的概念，允许用户定义新类型。

对象的特点是：

+   区分它们之间的身份

+   通过方法定义它们的行为

+   通过属性和属性定义它们的状态

类允许在新类型的数据和与对象相关的功能之间进行分组，有利于在实现的细节和其使用的基本属性之间进行分离。这样，目标是不显示更多的相关信息，隐藏类的状态和内部方法，这被称为“封装”，它是继承自模块化编程的原则。

在使用类的一个重要方面是它们不是直接操作的，而是用来定义新类型。类为对象（类的实例）定义属性和行为。类充当一组对象的模板，这些对象被认为属于该类。

面向对象编程中使用的最重要的技术包括：

+   **抽象**：对象可以执行任务，与其他对象交互，或者修改和报告它们的状态，而无需沟通这些操作是如何执行的。

+   **封装**：对象通过清晰的接口阻止其他对象修改其内部状态或调用内部方法，并且只通过这个接口与其他对象相关联。

+   **多态性**：不同的行为可以与相同的名称相关联。

+   **继承**：对象通过建立层次结构与其他对象相关联，有可能一些对象继承其他对象的属性和方法，扩展它们的行为和/或专业化。对象以这种方式分组在形成层次结构的类中。

# 获取和安装 Python

在 Linux 和 Windows 平台上，Python 的安装速度很快。Windows 用户可以使用一个简单的安装程序，使配置工作变得容易。在 Linux 上，您可以选择从源代码构建安装，但这并不是强制的，您可以使用经典的包管理依赖，如 apt-get。

许多 Linux 发行版预装了 Python 2。在这样的系统上安装 Python 3 时，重要的是要记住我们并没有替换 Python 2 的安装。这样，当我们安装 Python 3 时，它可以与同一台机器上的 Python 2 并行安装。安装 Python 3 后，可以使用 Python3 可执行文件调用 python 解释器。

# 在 Windows 上安装 Python

Windows 用户可以从主 Python 网站获取安装程序：[`www.python.org/ftp/python/2.7.15/python-2.7.15.msi`](https://www.python.org/ftp/python/2.7.15/python-2.7.15.msi)。只需双击安装程序，然后按照安装步骤进行安装。它应该在`C:/Python27/`创建一个目录；这个目录将有`Python.exe`解释器以及所有默认安装的库。

Python 安装允许您自定义环境的安装位置。Python 2.7.14 的默认位置是`C:\Python27`，尽管您可以指定其他位置。当寻找特定模块和工具时，这个路径将是相关的。

如果要包括文档或安装一系列实用程序（如`pip`软件包管理器或 IDLE 开发环境，用于编辑和执行脚本），则可以自定义安装。建议您保留已标记的选项，以便安装它们，使我们拥有尽可能完整的环境：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/5d69cf39-2c64-4588-8b80-95fb8f541609.png)

重要的是要检查“将 python.exe 添加到路径”框。这将允许您从任何路径直接从命令提示符运行 Python，而无需转到安装目录。

在安装 Python 版本的 Windows 时，您还可以看到 IDLE 可用，这是 Python 的编辑器或 IDE（集成开发环境），它将允许我们编写和测试代码。安装完成后，我们可以验证一切是否正确：

1.  打开安装的文件夹

1.  输入`C:\Python27\Lib\idlelib`

1.  双击运行`**idle.bat**`文件

Windows 用户的另一个选择是 WinPython，可以在**[`winpython.github.io`](http://winpython.github.io)**上找到。

WinPython 是一个 Python 发行版；您可以在 Windows 7/8/10 操作系统上安装它进行科学和教育用途。

这个发行版与其他发行版不同，因为它：

+   **无需安装**：WinPython 完全存在于自己的目录中，无需任何操作系统安装

+   **便携式**：您可以轻松地压缩您的 Python 项目并在其他机器上进行安装

# 在 Linux 上安装 Python

Python 默认安装在大多数 Gnu/Linux 发行版中。如果我们想要在 Ubuntu 或基于 Debian 的发行版中安装它，我们可以通过`apt-get`软件包管理器来实现：

```py
sudo apt-get install python2.7
```

# Python 集合

在本节中，我们将回顾不同类型的数据集合，如列表、元组和字典。我们将看到用于管理这些数据结构的方法和操作，以及一个实际示例，我们将在其中回顾主要用例。

# 列表

Python 中的列表相当于 C 等编程语言中的动态向量结构。我们可以通过在一对方括号之间封装它们的元素并用逗号分隔来表示文字。列表的第一个元素的索引为 0。索引运算符允许访问元素，并通过在方括号中添加其索引来在列表中表达语法上：

考虑以下示例：程序员可以通过使用`append()`方法添加项目来构建列表，打印项目，然后在再次打印之前对它们进行排序。在以下示例中，我们定义了一个协议列表，并使用 Python 列表的主要方法，如 append、index 和 remove：

```py
>>> protocolList = []
>>> protocolList.append("ftp")
>>> protocolList.append("ssh")
>>> protocolList.append("smtp")
>>> protocolList.append("http")
>>> print protocolList
```

```py
['ftp','ssh','smtp','http']
```

```py
>>> protocolList.sort()
>>> print protocolList
```

```py
['ftp','http','smtp','ssh']
```

```py
>>> type(protocolList)
<type 'list'>
>>> len(protocolList)
```

```py
4
```

要访问特定位置，我们使用`index`方法，要删除一个元素，我们使用 remove 方法：

```py
>>> position = protocolList.index("ssh")
>>> print "ssh position"+str(position)
```

```py
ssh position 3
```

```py
>>> protocolList.remove("ssh")
>>> print protocolList
```

```py
['ftp','http','smtp']
```

```py
>>> count = len(protocolList)
>>> print "Protocol elements "+str(count)
```

```py
Protocol elements 3
```

要打印整个协议列表，请使用以下代码。这将循环遍历所有元素并将它们打印出来：

```py
>>> for protocol in protocolList:
>>      print (protocol)
```

```py
ftp
http
smtp
```

列表还有一些方法，可以帮助我们操纵其中的值，并允许我们在其中存储多个变量，并为 Python 中的对象数组提供更好的排序方法。这些是最常用的用于操纵列表的方法：

+   **.append(value):** 在列表末尾添加一个元素

+   **.count('x'):** 获取列表中'x'的数量

+   **.index('x'):** 返回列表中'x'的索引

+   **.insert('y','x'):** 在位置'y'插入'x'

+   **.pop():** 返回最后一个元素并从列表中删除它

+   **.remove('x'):** 从列表中删除第一个'x'

+   **.reverse():** 反转列表中的元素

+   **.sort():** 按字母顺序升序或按数字顺序升序对列表进行排序

# 反转列表

我们在列表中拥有的另一个有趣的操作是通过`reverse()`方法返回列表的可能性：

```py
>>> protocolList.reverse()
>>> print protocolList
```

```py
['smtp','http','ftp']
```

执行相同操作的另一种方法是使用`-1`索引。这种快速简便的技术显示了如何以相反的顺序访问列表的所有元素：

```py
>>> protocolList[::-1]
>>> print protocolList
```

```py
['smtp','http','ftp']
```

# 理解列表

理解列表允许您创建一个可迭代对象的新列表。基本上，它们包含必须为迭代每个元素的循环内的表达式。

基本语法是：

```py
new_list = [expression for_loop_one_or_more conditions]
```

列表理解也可以用于迭代字符串：

```py
>>> protocolList = ["FTP", "HTTP", "SNMP", "SSH"]
>>> protocolList_lower= [protocol.lower() for protocol in protocolList]
>>> print(protocolList_lower) # Output: ['ftp', 'http', 'snmp', 'ssh']
```

# 元组

元组类似于列表，但其大小和元素是不可变的，也就是说，其值不能被更改，也不能添加比最初定义的更多的元素。元组由括号括起来。如果我们尝试修改元组的元素，我们会收到一个错误，指示元组对象不支持元素的赋值：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/a3849051-44d7-4322-833b-2bceec82c9a3.png)

# 字典

Python 字典数据结构允许我们将值与键关联起来。键是任何不可变对象。与键关联的值可以通过索引运算符访问。在 Python 中，使用哈希表实现字典。

Python 字典是一种存储键值对的方法。Python 字典用大括号`{}`括起来。字典，也称为关联矩阵，得名于将键和值相关联的集合。例如，让我们看一个具有名称和数字的协议字典：

```py
>>> services = {"ftp":21, "ssh":22, "smtp":25, "http":80}
```

字典的限制在于我们不能使用相同的键创建多个值。这将覆盖重复键的先前值。字典的操作是唯一的。我们可以使用`update`方法将两个不同的字典合并为一个。此外，`update`方法将在元素冲突时合并现有元素：

```py
>>> services = {"ftp":21, "ssh":22, "smtp":25, "http":80}
>>> services2 = {"ftp":21, "ssh":22, "snmp":161, "ldap":389}
>>> services.update(services2)
>>> print services
```

这将返回以下字典：

```py
{"ftp":21, "ssh":22, "smtp":25, "http":80,"snmp":161, "ldap":389}
```

第一个值是键，第二个是与键关联的值。作为键，我们可以使用任何不可变的值：我们可以使用数字、字符串、布尔值或元组，但不能使用列表或字典，因为它们是可变的。

字典与列表或元组的主要区别在于，存储在字典中的值不是通过它们的索引访问的，因为它们没有顺序，而是通过它们的键，再次使用`[]`运算符。

与列表和元组一样，您也可以使用此运算符重新分配值：

```py
>>> services["http"]= 8080
```

构建字典时，每个键都用冒号与其值分隔，我们用逗号分隔项。`.keys()`方法将返回字典的所有键的列表，`.items()`方法将返回字典中所有元素的完整列表。

以下是使用这些方法的示例：

+   `services.keys()`是一个方法，将返回字典中的所有键。

+   `services.items()`是一个方法，将返回字典中所有项目的完整列表。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/81e31826-beac-4f5c-aaca-e6bdafed7960.png)

从性能的角度来看，字典中的键在存储时被转换为哈希值，以节省空间并在搜索或索引字典时提高性能。还可以打印字典并按特定顺序浏览键。以下代码提取字典元素，然后对其进行排序：

```py
>>> items = services.items()
>>> print items
```

```py
[('ftp', 21), ('smtp',25), ('ssh', 22), ('http', 80), ('snmp', 161)]
```

```py
>>> items.sort()
>>> print items
```

```py
[('ftp', 21), ('http', 80), ('smtp', 25), ('snmp', 161), ('ssh', 22)]
```

我们可以提取字典中每个元素的键和值：

```py
>>> keys = services.keys()
>>> print keys
```

```py
['ftp', 'smtp', 'ssh', 'http', 'snmp']
```

```py
>>> keys.sort()
>>> print keys
```

```py
['ftp', 'http', 'smtp', 'snmp', 'ssh']
```

```py
>>> values = services.values()
>>> print values
```

```py
[21, 25, 22, 80, 161]
```

```py
>>> values.sort()
>>> print values
```

```py
[21, 22, 25, 80, 161]
```

```py
>>> services.has_key('http')
```

```py
True
```

```py
>>> services['http']
```

```py
80
```

最后，您可能希望遍历字典并提取和显示所有的“键:值”对：

```py
>>> for key,value in services.items():
        print key,value
ftp 21
smtp 25
ssh 22
http 80
snmp 161
```

# Python 函数和异常管理

在本节中，我们将回顾 Python 函数和异常管理。我们将看到一些声明和在脚本代码中使用它们的示例。我们还将回顾我们可以在 Python 中找到的主要异常，以便在我们的脚本中包含。

# Python 函数

在 Python 中，函数提供了有组织的可重用代码块。通常，这允许程序员编写一块代码来执行单个相关操作。虽然 Python 提供了许多内置函数，程序员可以创建用户定义的函数。除了通过将程序分成部分来帮助我们编程和调试外，函数还允许我们重用代码。

Python 函数是使用 def 关键字定义的，后面跟着函数名和函数参数。函数的主体由要执行的 Python 语句组成。在函数的末尾，您可以选择向函数调用者返回一个值，或者默认情况下，如果您没有指定返回值，它将返回 None 对象。

例如，我们可以定义一个函数，给定一个数字序列和一个通过参数传递的项目，如果元素在序列中，则返回 True，否则返回 False：

```py
>>> def contains(sequence,item):
        for element in sequence:
                if element == item:
                        return True
        return False
>>> print contains([100,200,300,400],200)
```

```py
True
```

```py
>>> print contains([100,200,300,400],300)
```

```py
True
```

```py
>>> print contains([100,200,300,400],350)
```

```py
False
```

# 异常管理

异常是 Python 在程序执行期间检测到的错误。当解释器遇到异常情况时，例如尝试将数字除以 0 或尝试访问不存在的文件时，它会生成或抛出异常，通知用户存在问题。

如果未捕获异常，执行流程将被中断，并在控制台中显示与异常相关的信息，以便程序员解决问题。

让我们看一个小程序，当尝试将 1 除以 0 时会引发异常。如果我们执行它，将会得到以下错误消息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/13968d79-9053-41f1-bfb8-a73c3e2f14fc.png)

首先显示的是回溯，它由导致异常的调用列表组成。正如我们在堆栈跟踪中看到的那样，错误是由第 7 行的 calculate()调用引起的，该调用又在第 5 行调用 division(1, 0)，最终在 division 的第 2 行执行 a/b 语句。

Python 语言提供了异常处理能力来做到这一点。我们使用 try/except 语句来提供异常处理。现在，程序尝试执行除以零的操作。当错误发生时，我们的异常处理捕获错误并在屏幕上打印消息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/994fd36f-cd81-417b-b530-651d019d1475.png)

在下面的示例中，我们尝试创建一个文件类型的 f 对象。如果未将文件作为参数传递，则会抛出 IOError 类型的异常，我们通过 try-except 捕获到这个异常：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/867ef05a-d3b5-41e1-9ce7-d4d4dbaa17b6.png)

默认情况下提供的一些异常列在此处（它们派生自的类在括号中）：

+   **BaseException**：所有异常继承的类。

+   异常（BaseException）：所有不输出的异常的超类。

+   **ZeroDivisionError**（ArithmeticError）：当除法或模块运算的第二个参数为`0`时引发。

+   **EnvironmentError**（StandardError）：与输入/输出相关的错误的父类。

+   **IOError**（EnvironmentError）：输入/输出操作中的错误。

+   **OSError**（EnvironmentError）：系统调用中的错误。

+   **ImportError**（StandardError）：未找到要导入的模块或模块元素。

# Python 作为面向对象的语言

在本节中，我们将回顾 Python 中的面向对象编程和继承。

面向对象编程是当今最常用的范例之一。虽然它适用于我们在日常生活中可以找到的许多情况，在 Python 中，我们可以将其与其他范例结合起来，以充分利用语言并在保持最佳代码设计的同时提高我们的生产力。

Python 是一种面向对象的语言，允许您定义类并从这些定义实例化对象。由 class 语句开头的块是类定义。在块中定义的函数是其方法，也称为成员函数。

Python 创建对象的方式是使用 class 关键字。Python 对象是方法、变量和属性的集合。您可以使用相同的类定义创建许多对象。以下是协议对象定义的简单示例：

您可以在`protocol.py`文件中找到以下代码。

```py
class protocol(object):

 def __init__(self, name, number,description):
 self.name = name
 self.number = number
 self.description = description

 def getProtocolInfo(self):
 return self.name+ " "+str(self.number)+ " "+self.description
```

`__init__`方法是一个特殊的方法，正如其名称所示，它充当构造方法来执行任何必要的初始化过程。

该方法的第一个参数是一个特殊的关键字，我们使用 self 标识符来引用当前对象。它是对对象本身的引用，并提供了一种访问其属性和方法的方式。

self 参数相当于在 C++或 Java 等语言中找到的指针。在 Python 中，self 是语言的保留字，是强制性的，它是常规方法的第一个参数，并且通过它可以访问类的属性和方法。

要创建对象，请在类名后面写上任何必要的参数，这些参数将传递给`__init__`方法，这是在实例化类时调用的方法：

```py
>>> protocol_http= protocol("HTTP", 80, "Hypertext transfer protocol")
```

现在我们已经创建了我们的对象，我们可以通过 object.attribute 和`object.method()`语法访问其属性和方法：

```py
>>> protocol_http.name
>>> protocol_http.number
>>> protocol_http.description
>>> protocol_http.getProtocolInfo()
```

# 继承

面向对象编程语言的主要概念是：封装、继承和多态。在面向对象语言中，对象通过建立层次关系与其他对象相关联，有可能一些对象继承其他对象的属性和方法，扩展它们的行为和/或特化。

继承允许我们从另一个类生成一个新类，继承其属性和方法，根据需要进行调整或扩展。要指示一个类从另一个类继承，我们需要将被继承的类的名称放在括号中。

在面向对象编程术语中，有人说“B 继承自 A”，“B 是从 A 派生出来的类”，“A 是 B 的基类”，或者“A 是 B 的超类”。

这有助于代码的重用，因为你可以在基类中实现基本行为和数据，并在派生类中对其进行特化：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/6b5697ad-3499-43a3-8f4a-278cea025cb2.png)

# OMSTD 方法和 Python 脚本的 STB 模块

OMSTD 代表安全工具开发的开放方法论，它是 Python 开发安全工具的方法和一套良好实践。本指南适用于 Python 开发，尽管实际上你可以将相同的想法扩展到其他语言。在这一点上，我将讨论方法和一些技巧，我们可以遵循使代码更易读和可重用。

# Python 包和模块

Python 编程语言是一种高级通用语言，具有清晰的语法和完整的标准库。通常被称为脚本语言，安全专家们已经将 Python 作为开发信息安全工具包的语言。模块化设计、易读的代码和完全开发的库集为安全研究人员和专家构建工具提供了一个起点。

Python 自带了一个全面的标准库，提供了从提供简单 I/O 访问的集成模块到特定平台 API 调用的一切。Python 的美妙之处在于用户贡献的模块、包和个体框架。项目越大，不同方面之间的顺序和分离就越重要。在 Python 中，我们可以使用模块的概念来实现这种分离。

# Python 中的模块是什么？

模块是一个我们可以从程序中使用的函数、类和变量的集合。标准 Python 发行版中有大量的模块可用。

导入语句后面跟着模块的名称，使我们能够访问其中定义的对象。导入的对象通过模块的标识符、点运算符和所需对象的标识符，可以从导入它的程序或模块中访问。

模块可以被定义为包含 Python 定义和声明的文件。文件的名称是附加了`.py`后缀的模块的名称。我们可以从定义一个简单的模块开始，该模块将存在于与我们将要编写的`main.py`脚本相同的目录中：

+   `main.py`

+   `my_module.py`

在`my_module.py`文件中，我们将定义一个简单的`test()`函数，它将打印“This is my first module”：

```py
 # my_module.py
 def test():
    print("This is my first module")
```

在我们的`main.py`文件中，我们可以将这个文件作为一个模块导入，并使用我们新定义的 test()方法，就像这样：

```py
# main.py
 import my_module

 def main():
    my_module.test()

 if __name__ == '__main__':
    main()
```

这就是我们需要在 Python 程序中定义一个非常简单的`python`模块的全部内容。

# Python 模块和 Python 包之间的区别

当我们使用 Python 时，了解 Python 模块和`Python`包之间的区别很重要。重要的是要区分它们；包是包含一个或多个模块的模块。

软件开发的一部分是基于编程语言中的模块添加功能。随着新的方法和创新的出现，开发人员提供这些功能构建块作为模块或包。在 Python 网络中，其中大多数模块和包都是免费的，其中包括完整的源代码，允许您增强提供的模块的行为并独立验证代码。

# 在 Python 中传递参数

为了完成这个任务，最好使用默认安装 Python 时自带的`argparse`模块。

有关更多信息，您可以查看官方网站：[`docs.python.org/3/library/argparse.html`](https://docs.python.org/3/library/argparse.html)。

以下是如何在我们的脚本中使用它的示例：

您可以在文件名`testing_parameters.py`中找到以下代码

```py
import argparse

parser = argparse.ArgumentParser(description='Testing parameters')
parser.add_argument("-p1", dest="param1", help="parameter1")
parser.add_argument("-p2", dest="param2", help="parameter2")
params = parser.parse_args()
print params.param1
print params.param2
```

在 params 变量中，我们有用户从命令行输入的参数。要访问它们，您必须使用以下内容：

```py
params.<Name_dest>
```

其中一个有趣的选项是可以使用 type 属性指示参数的类型。例如，如果我们希望某个参数被视为整数，我们可以这样做：

```py
parser.add_argument("-param", dest="param", type="int")
```

另一件有助于使我们的代码更易读的事情是声明一个充当参数全局对象的类：

```py
class Parameters:
 """Global parameters"""
    def __init__(self, **kwargs):
        self.param1 = kwargs.get("param1")
        self.param2 = kwargs.get("param2")
```

例如，如果我们想要同时向函数传递多个参数，我们可以使用这个全局对象，其中包含全局执行参数。例如，如果我们有两个参数，我们可以这样构建对象：

您可以在文件名`params_global.py`中找到以下代码

```py
import argparse

class Parameters:
 """Global parameters"""

    def __init__(self, **kwargs):
        self.param1 = kwargs.get("param1")
        self.param2 = kwargs.get("param2")

def view_parameters(input_parameters):
    print input_parameters.param1
    print input_parameters.param2

parser = argparse.ArgumentParser(description='Passing parameters in an object')
parser.add_argument("-p1", dest="param1", help="parameter1")
parser.add_argument("-p2", dest="param2", help="parameter2")
params = parser.parse_args()
input_parameters = Parameters(param1=params.param1,param2=params.param2)
view_parameters(input_parameters)
```

在上一个脚本中，我们可以看到我们使用`argparse`模块获取参数，并将这些参数封装在 Parameters 类的对象中。通过这种做法，我们可以在对象中封装参数，以便从脚本的不同点轻松检索这些参数。

# 在 Python 项目中管理依赖项

如果我们的项目依赖于其他库，理想情况是有一个文件，其中包含这些依赖项，以便我们的模块的安装和分发尽可能简单。为此任务，我们可以创建一个名为`requirements.txt`的文件，如果我们使用 pip 实用程序调用它，将降低所讨论模块需要的所有依赖项。

使用 pip 安装所有依赖项：

```py
pip -r requirements.txt
```

在这里，`pip`是`Python`包和依赖项管理器，而`requirements.txt`是详细列出项目所有依赖项的文件。

# 生成 requirements.txt 文件

我们还有可能从项目源代码创建`requirements.txt`文件。

为此任务，我们可以使用`pipreqs`模块，其代码可以从 GitHub 存储库下载：[`github.com/bndr/pipreqs`](https://github.com/bndr/pipreqs)

这样，该模块可以使用`pip install pipreqs`命令或通过 GitHub 代码存储库使用`python setup.py install`命令进行安装。

有关该模块的更多信息，您可以查询官方 pypi 页面：

[`pypi.python.org/pypi/pipreqs`](https://pypi.python.org/pypi/pipreqs)。

要生成`requirements.txt`文件，您必须执行以下命令：

```py
 pipreqs <path_project>
```

# 使用虚拟环境

在使用 Python 时，强烈建议您使用 Python 虚拟环境。虚拟环境有助于分离项目所需的依赖项，并保持我们的全局目录清洁，不受`project`包的影响。虚拟环境为安装 Python 模块提供了一个单独的环境，以及 Python 可执行文件和相关文件的隔离副本。您可以拥有尽可能多的虚拟环境，这意味着您可以配置多个模块配置，并且可以轻松地在它们之间切换。

从版本 3 开始，Python 包括一个`venv`模块，提供了这个功能。文档和示例可在[`docs.python.org/3/using/windows.html#virtual-environments`](https://docs.python.org/3/using/windows.html#virtual-environments)找到

还有一个独立的工具可用于早期版本，可以在以下位置找到：

[`virtualenv.pypa.io/en/latest`](https://virtualenv.pypa.io/en/latest)

# 使用 virtualenv 和 virtualwrapper

当您在本地计算机上安装`Python`模块而不使用虚拟环境时，您正在全局在操作系统中安装它。此安装通常需要用户根管理员，并且该`Python`模块为每个用户和每个项目安装。

在这一点上，最佳实践是如果您需要在多个 Python 项目上工作，或者您需要一种在许多项目中使用所有关联库的方法，那么最好安装 Python 虚拟环境。

Virtualenv 是一个允许您创建虚拟和隔离环境的`Python`模块。基本上，您创建一个包含项目所需的所有可执行文件和模块的文件夹。您可以使用以下命令安装 virtualenv：

```py
$ sudo pip install virtualenv
```

要创建一个新的虚拟环境，请创建一个文件夹，并从命令行进入该文件夹：

```py
$ cd your_new_folder $ virtualenv name-of-virtual-environment
```

例如，这将创建一个名为 myVirtualEnv 的新环境，您必须激活它才能使用它：

```py
$ cd myVirtualEnv/ $ virtualenv myVirtualEnv $ source bin/activate
```

执行此命令将在您当前的工作目录中启动一个名为指示的文件夹，其中包含 Python 的所有可执行文件和允许您在虚拟环境中安装不同包的`pip`模块。

Virtualenv 就像一个沙盒，当您工作时，项目的所有依赖项都将被安装，所有模块和依赖项都是分开保存的。如果用户在他们的计算机上安装了相同版本的 Python，那么相同的代码将在虚拟环境中运行，而不需要任何更改。

`Virtualenvwrapper`允许您更好地组织在您的计算机上所有虚拟管理的环境，并提供更优化的方式来使用`virtualenv`。

我们可以使用 pip 命令安装`virtualwrapper`，因为它在官方 Python 存储库中可用。安装它的唯一要求是先前安装了`virtualenv`：

```py
$ pip install virtualenvwrapper
```

要在 Windows 中创建一个虚拟环境，您可以使用`virtualenv`命令：

```py
virtualenv venv
```

当我们执行前面的命令时，我们会看到这个结果：![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/9c138124-d264-4e0d-8fec-dff36f65f947.png)

在 Windows 中执行`virtualenv`命令会生成四个文件夹：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/bb6e3654-f1bc-4599-a2a5-d9df33dd48b3.png)

在 scripts 文件夹中，有一个名为`activate.bat`的脚本，用于激活虚拟环境。一旦激活，我们将拥有一个干净的模块和库环境，并且我们将不得不下载我们项目的依赖项，以便将它们复制到这个目录中，使用以下代码：

```py
cd venv\Scripts\activate (venv) > pip install -r requirements.txt
```

这是活动文件夹，当我们可以找到 active.bat 脚本时：![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/fdaf0e17-8d1d-447b-9900-c131a7463a14.png)

# STB（Security Tools Builder）模块

这个工具将允许我们创建一个基础项目，我们可以在其上开始开发我们自己的工具。

该工具的官方存储库是[`github.com/abirtone/STB`](https://github.com/abirtone/STB)。

对于安装，我们可以通过下载源代码并执行`setup.py`文件来完成，这将下载`requirements.txt`文件中的依赖项。

我们也可以使用`**pip install stb**`命令来完成。

执行`**stb**`命令时，我们会得到以下屏幕，要求我们提供信息来创建我们的项目：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/3701b9aa-a4ca-4a4c-98e2-1bd182c5e566.png)

使用此命令，我们将获得一个带有`setup.py`文件的应用程序骨架，如果我们想要将该工具安装为系统中的命令，则可以执行：

```py
python setup.py install
```

当我们执行前面的命令时，我们会得到下一个文件夹结构：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/de04da7e-a815-4716-8c4c-7efe0105b0d9.png)

这也创建了一个包含允许我们执行它的文件的`port_scanning_lib`文件夹：

```py
python port_scanning.py –h
```

如果我们使用帮助选项（-h）执行脚本，我们会看到一系列可以使用的参数：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/7b7a9cde-99c8-4a5d-ad17-130bb441799e.png)

我们可以看到在`port_scanning.py`文件中生成的代码：

```py
parser = argparse.ArgumentParser(description='%s security tool' % "port_scanning".capitalize(), epilog = examples, formatter_class = argparse.RawTextHelpFormatter)

# Main options
parser.add_argument("target", metavar="TARGET", nargs="*")
parser.add_argument("-v", "--verbosity", dest="verbose", action="count", help="verbosity level: -v, -vv, -vvv.", default=1)
parsed_args = parser.parse_args()

# Configure global log
log.setLevel(abs(5 - parsed_args.verbose) % 5)

# Set Global Config
config = GlobalParameters(parsed_args)
```

在这里，我们可以看到定义的参数，并且使用`GlobalParameters`对象传递`parsed_args`变量中的参数。要执行的方法在`**api.py**`文件中找到。

例如，在这一点上，我们可以从命令行中检索输入的参数：

```py
# ----------------------------------------------------------------------
#
# API call
#
# ----------------------------------------------------------------------
def run(config):
    """
    :param config: GlobalParameters option instance
    :type config: `GlobalParameters`

    :raises: TypeError
     """
     if not isinstance(config, GlobalParameters):
         raise TypeError("Expected GlobalParameters, got '%s' instead" % type(config))

# --------------------------------------------------------------------------
# INSERT YOUR CODE HERE # TODO
# --------------------------------------------------------------------------
print config
print config.target
```

我们可以从命令行执行脚本，将我们的 ip 目标作为参数传递：

```py
python port_scanning.py 127.0.0.1
```

如果我们现在执行，我们可以看到如何在输出中获得首次引入的参数：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/46600ebf-0ca5-46dd-94bd-a8a7ef1f3af1.png)

# 脚本开发的主要开发环境

在本节中，我们将审查 Pycharm 和 WingIDE 作为 Python 脚本的开发环境。

# 设置开发环境

为了快速开发和调试 Python 应用程序，绝对必须使用稳固的 IDE。如果您想尝试不同的选项，我们建议您查看 Python 官方网站上的列表，那里可以根据操作系统和需求查看工具：[`wiki.python.org/moin/IntegratedDevelopmentEnvironments`](https://wiki.python.org/moin/IntegratedDevelopmentEnvironments)。

在所有环境中，我们将强调以下内容：

+   **Pycharm: **[`www.jetbrains.com/pycharm`](http://www.jetbrains.com/pycharm)

+   **Wing IDE**: [`wingware.com`](https://wingware.com)

# Pycharm

PyCharm 是由 Jetbrains 公司开发的 IDE，基于同一公司的 IDE IntelliJ IDEA，但专注于 Java，并且是 Android Studio 的基础。

PyCharm 是多平台的，我们可以在 Windows，Linux 和 macOS X 上找到二进制文件。 PyCharm 有两个版本：社区和专业，其特性与 Web 框架集成和数据库支持相关。

在此网址上，我们可以看到社区版和专业版之间的比较：[`www.jetbrains.com/pycharm`](http://www.jetbrains.com/pycharm)

这个开发环境的主要优势是：

+   自动完成，语法高亮，分析工具和重构。

+   与 Django，Flask，Pyramid，Web2Py，jQuery 和 AngularJS 等 Web 框架集成。

+   高级调试器。

+   与 SQLAlchemy（ORM），Google App Engine，Cython 兼容。

+   与版本控制系统的连接：Git，CVS，Mercurial。

# WingIDE

WingIDE 是一个多平台环境，可在 Windows，Mac 和 Linux 上使用，并提供了与调试和变量探索相关的所有功能。

WingIDE 具有丰富的功能集，可以轻松支持复杂 Python 应用程序的开发。使用 WingIDE，您可以检查变量，堆栈参数和内存位置，而不会在记录它们之前更改任何值。断点是调试过程中最常用的功能。 Wing Personal 是这个 Python IDE 的免费版本，可以在[`wingware.com/downloads/wingide-personal`](https://wingware.com/downloads/wingide-personal)找到

WingIDE 使用您系统中安装的 Python 配置：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/7f4752ae-8d20-42c4-9fb5-5b518dfa22b7.png)

# 使用 WingIDE 进行调试

在这个例子中，我们正在调试一个接受两个输入参数的 Python 脚本：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/609a7394-7c59-4fe9-b2ca-ec68e47e0d8b.png)

一个有趣的话题是在我们的程序中添加断点的可能性，使用`Add Breakpoint`选项，这样，我们可以调试并查看变量的内容，就在我们设置断点的地方：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/d8fa3334-2f5d-4c58-b545-51588db32702.png)

我们可以在调用`view_parameters`方法时设置断点。

要以调试模式执行带参数的脚本，您必须编辑脚本的属性，并在调试标记中添加脚本需要的参数：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/43824730-490c-44bd-8424-18ca965c8fe3.png)

如果我们在函数内部执行调试模式并设置断点，我们可以看到本地**字符串变量**中参数的内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/c044a72c-4ac9-4fc8-af31-9f3f516ae7f3.png)

在下面的截图中，我们可以可视化 params 变量的值，该变量包含我们正在调试的值：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/53fc3235-2be1-4166-aae1-ef20f6f7ea24.png)

# 摘要

在本章中，我们学习了如何在 Windows 和 Linux 操作系统上安装 Python。我们回顾了主要的数据结构和集合，如列表、元组和字典。我们还回顾了函数、异常处理的管理，以及如何创建类和对象，以及属性和特殊方法的使用。然后我们看了开发环境和一种介绍 Python 编程的方法论。OMSTD 是 Python 开发安全工具的一种方法论和最佳实践。最后，我们回顾了主要的开发环境，PyCharm 和 WingIDE，用于 Python 脚本开发。

在下一个章节中，我们将探讨用于处理操作系统和文件系统、线程和并发的编程系统包。

# 问题

1.  Python 2.x 和 3.x 之间有什么区别？

1.  Python 开发人员使用的编程范式是什么，这个范式背后的主要概念是什么？

1.  Python 中的哪种数据结构允许我们将值与键关联起来？

1.  Python 脚本的主要开发环境是什么？

1.  作为 Python 开发安全工具的一套良好实践方法，我们可以遵循什么方法论？

1.  有助于创建隔离的 Python 环境的`Python`模块是什么？

1.  哪个工具允许我们创建一个基础项目，我们可以在其上开始开发我们自己的工具？

1.  我们如何在 Python 开发环境中调试变量？

1.  我们如何在`pycharm`中添加断点？

1.  我们如何在 Wing IDE 中添加断点？

# 进一步阅读

在这些链接中，您将找到有关提到的工具和官方 Python 文档的更多信息，以便查找其中一些被评论模块的信息：

+   [`winpython.github.io`](http://winpython.github.io)

+   [`docs.python.org/2.7/library/`](https://docs.python.org/2.7/library/)

+   [`docs.python.org/3.6/library/`](https://docs.python.org/3.6/library/)

+   [`virtualenv.pypa.io/en/latest`](https://virtualenv.pypa.io/en/latest)

+   [`wiki.python.org/moin/IntegratedDevelopmentEnvironments`](https://wiki.python.org/moin/IntegratedDevelopmentEnvironments)


# 第二章：系统编程包

在本章中，我们将介绍 Python 中的主要模块，用于与 Python 解释器、操作系统和执行命令。我们将回顾如何使用文件系统，读取和创建文件。此外，我们将回顾线程管理和其他用于多线程和并发的模块。我们将以对`socket.io`模块实现异步服务器的回顾结束本章。

本章将涵盖以下主题：

+   介绍 Python 中的系统模块

+   使用文件系统

+   Python 中的线程

+   Python 中的多线程和并发

+   Python `Socket.io`

# 技术要求

本章的示例和源代码可在 GitHub 存储库的`chapter 2`文件夹中找到：[`github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security.`](https://github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security.)

您需要一些关于操作系统中的命令执行的基本知识，并在本地计算机上安装 Python 发行版。

# 介绍 Python 中的系统模块

在本节中，我们将解释 Python 中用于与 Python 解释器、操作系统以及使用子进程模块执行命令的主要模块。

# 系统模块

`sys`模块将允许我们与解释器进行交互，并且它包含了与正在进行的执行相关的大部分信息，由解释器更新，以及一系列函数和低级对象。

`**sys.argv**`包含执行脚本的参数列表。列表中的第一项是脚本的名称，后面是参数列表。

例如，我们可能希望在运行时解析命令行参数。sys.argv 列表包含所有命令行参数。sys.argv[0]索引包含 Python 解释器脚本的名称。argv 数组中的其余项目包含下一个命令行参数。因此，如果我们传递了三个额外的参数，sys.argv 应该包含四个项目。

您可以在`**sys_arguments.py**`文件中找到以下代码：

```py
import sys
print "This is the name of the script:",sys.argv[0]
print "The number of arguments is: ",len(sys.argv)
print "The arguments are:",str(sys.argv)
print "The first argument is ",sys.argv[1]
```

前面的脚本可以使用一些参数执行，例如以下内容：

```py
$ python sys_arguments.py one two three
```

如果我们使用三个参数执行前面的脚本，我们可以看到以下结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/65980509-35c9-4adc-abe0-556185adc047.png)

在此示例中，我们获得了许多系统变量：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/75dd2dae-c18d-4937-a697-07d4de09d0b8.png)

这些是恢复该信息的主要属性和方法：

+   **sys.platform**：返回当前操作系统

+   **sys.stdin,sys,stdout,sys.stderr**：分别指向标准输入、标准输出和标准错误输出的文件对象

+   **sys.version**：返回解释器版本

+   **sys.getfilesystemencoding()**：返回文件系统使用的编码

+   **sys.getdefaultencoding()**：返回默认编码

+   **sys.path**：返回解释器在导入指令使用或在不使用完整路径的文件名时搜索模块的所有目录列表

您可以在 Python 在线模块文档中找到更多信息：[`docs.python.org/library/sys`](http://docs.python.org/library/sys)。

# 操作系统模块

操作系统(os)模块是访问操作系统中不同函数的最佳机制。使用此模块将取决于所使用的操作系统。如果使用此模块，我们将不得不根据从一个操作系统切换到另一个操作系统来调整脚本。

该模块允许我们与操作系统环境、文件系统和权限进行交互。在此示例中，我们检查作为命令行参数传递的文本文件的名称是否存在于当前执行路径中，并且当前用户是否具有对该文件的读取权限。

您可以在`os`模块子文件夹中的`check_filename.py`文件中找到以下代码：

```py
import sys
import os

if len(sys.argv) == 2:
    filename = sys.argv[1]
    if not os.path.isfile(filename):
        print '[-] ' + filename + ' does not exist.'
        exit(0)
if not os.access(filename, os.R_OK):
        print '[-] ' + filename + ' access denied.'
        exit(0)
```

# 当前工作目录的内容

在这个例子中，`os`模块用于使用`os.getcwd()`方法列出当前工作目录的内容。

您可以在`os`模块子文件夹中的`show_content_directory.py`文件中找到以下代码：

```py
import os
pwd = os.getcwd()
list_directory = os.listdir(pwd)
for directory in list_directory:
    print directory
```

这是上述代码的主要步骤：

1.  导入`os`模块。

1.  使用`os`模块，调用`**os.getcwd()**`方法检索当前工作目录路径，并将该值存储在 pwd 变量中。

1.  获取当前目录路径的目录列表。使用`**os.listdir()**`方法获取当前工作目录中的文件名和目录。

1.  遍历列表目录以获取文件和目录。

以下是从操作系统模块中恢复信息的主要方法：

+   **os.system()**：允许我们执行 shell 命令

+   **os.listdir(path)**：返回作为参数传递的目录的内容列表

+   **os.walk(path)**：导航提供的路径目录中的所有目录，并返回三个值：路径目录，子目录的名称以及当前目录路径中的文件名的列表。

在这个例子中，我们检查当前路径内的文件和目录。

您可以在`os`模块子文件夹中的**`check_files_directory.py`**文件中找到以下代码：

```py
import os
for root,dirs,files in os.walk(".",topdown=False):
    for name in files:
        print(os.path.join(root,name))
    for name in dirs:
        print name
```

# 确定操作系统

下一个脚本确定代码是否在 Windows OS 或 Linux 平台上运行。`**platform.system()**`方法告诉我们正在运行的操作系统。根据返回值，我们可以看到在 Windows 和 Linux 中 ping 命令是不同的。Windows OS 使用 ping -n 1 发送一个 ICMP ECHO 请求的数据包，而 Linux 或其他操作系统使用 ping -c 1。

您可以在`os`模块子文件夹中的**`operating_system.py`**文件中找到以下代码：

```py
import os
import platform
operating_system = platform.system()
print operating_system
if (operating_system == "Windows"):
    ping_command = "ping -n 1 127.0.0.1"
elif (operating_system == "Linux"):
    ping_command = "ping -c 1 127.0.0.1"
else :
    ping_command = "ping -c 1 127.0.0.1"
print ping_command
```

# 子进程模块

标准的子进程模块允许您从 Python 调用进程并与它们通信，将数据发送到输入(stdin)，并接收输出信息(stdout)。使用此模块是执行操作系统命令或启动程序（而不是传统的`os.system()`）并可选择与它们交互的推荐方法。

使用子进程运行子进程很简单。在这里，**Popen**构造函数**启动进程**。您还可以将数据从 Python 程序传输到子进程并检索其输出。使用**help(subprocess)**命令，我们可以看到相关信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/5cb9d517-d7b9-4466-80cc-23aadaf26abc.png)

执行命令或调用进程的最简单方法是通过`call()`函数（从 Python 2.4 到 3.4）或`run()`（对于 Python 3.5+）。例如，以下代码执行列出当前路径中文件的命令。

您可以在`subprocess`子文件夹中的**`SystemCalls.py`**文件中找到此代码：

```py
import os
import subprocess
# using system
os.system("ls -la")
# using subprocess
subprocess.call(["ls", "-la"])
```

为了能够使用终端命令（例如清除或 cls 清理控制台，cd 移动到目录树中等），需要指定 shell = True 参数：

```py
>> subprocess.call("cls", shell=True)
```

在这个例子中，它要求用户写下他们的名字，然后在屏幕上打印一个问候语。通过子进程，我们可以使用 Popen 方法调用它，以编程方式输入一个名字，并将问候语作为 Python 字符串获取。

`Popen()`实例包括`terminate()`和`kill()`方法，分别用于终止或杀死进程。Linux 的发行版区分 SIGTERM 和 SIGKILL 信号：

```py
>>> p = subprocess.Popen(["python", "--version"])
>>> p.terminate()
```

与调用函数相比，Popen 函数提供了更多的灵活性，因为它在新进程中执行命令作为子程序。例如，在 Unix 系统上，该类使用`os.execvp()`。在 Windows 上，它使用 Windows `CreateProcess()`函数。

您可以在官方文档中找到有关 Popen 构造函数和 Popen 类提供的方法的更多信息：[`docs.python.org/2/library/subprocess.html#popen-constructor`](https://docs.python.org/3.5/library/subprocess.html#popen-constructor)。

在这个例子中，我们使用`subprocess`模块调用`ping`命令，并获取该命令的输出，以评估特定 IP 地址是否响应`ECHO_REPLY`。此外，我们使用`sys`模块来检查我们执行脚本的操作系统。

您可以在`PingScanNetWork.py`文件的 subprocess 子文件夹中找到以下代码：

```py
#!/usr/bin/env python
from subprocess import Popen, PIPE
import sys
import argparse
parser = argparse.ArgumentParser(description='Ping Scan Network')

# Main arguments
parser.add_argument("-network", dest="network", help="NetWork segment[For example 192.168.56]", required=True)
parser.add_argument("-machines", dest="machines", help="Machines number",type=int, required=True)

parsed_args = parser.parse_args()    
for ip in range(1,parsed_args.machines+1):
    ipAddress = parsed_args.network +'.' + str(ip)
    print "Scanning %s " %(ipAddress)
    if sys.platform.startswith('linux'):
    # Linux
        subprocess = Popen(['/bin/ping', '-c 1 ', ipAddress], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    elif sys.platform.startswith('win'):
    # Windows
        subprocess = Popen(['ping', ipAddress], stdin=PIPE, stdout=PIPE, stderr=PIPE)
stdout, stderr= subprocess.communicate(input=None)
print stdout
if "Lost = 0" in stdout or "bytes from " in stdout:
    print "The Ip Address %s has responded with a ECHO_REPLY!" %(stdout.split()[1])
```

要执行此脚本，我们需要将我们正在分析的网络和我们想要检查的机器编号作为参数传递：

```py
python PingScanNetWork.py -network 192.168.56 -machines 1
```

以下是扫描 129.168.56 网络和一个机器的结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/6b324c6f-76c0-4706-88dc-bd48a61849d2.png)

# 在 Python 中处理文件系统

在本节中，我们解释了 Python 中用于处理文件系统、访问文件和目录、读取和创建文件以及使用和不使用上下文管理器的主要模块。

# 访问文件和目录

在本节中，我们将回顾如何处理文件系统并执行诸如浏览目录或逐个读取每个文件的任务。

# 递归浏览目录

在某些情况下，需要递归迭代主目录以发现新目录。在这个例子中，我们看到如何递归浏览目录并检索该目录中所有文件的名称：

```py
import os
 # you can change the "/" to a directory of your choice
 for file in os.walk("/"):
    print(file)
```

# 检查特定路径是否为文件或目录

我们可以检查某个字符串是否为文件或目录。为此，我们可以使用`os.path.isfile()`方法，如果是文件则返回`True`，如果是目录则返回`False`：

```py
 >>> import os
 >>> os.path.isfile("/")
 False
 >>> os.path.isfile("./main.py")
 True
```

# 检查文件或目录是否存在

如果您想要检查当前工作路径目录中是否存在文件，可以使用`os.path.exists()`函数，将要检查的文件或目录作为参数传递：

```py
 >>> import os
 >>> os.path.exists("./main.py")
 True
 >>> os.path.exists("./not_exists.py")
 False
```

# 在 Python 中创建目录

您可以使用`os.makedirs()`函数创建自己的目录：

```py
 >>> if not os.path.exists('my_dir'):
 >>>    os.makedirs('my_dir')
```

此代码检查`my_dir`目录是否存在；如果不存在，它将调用`os.makedirs` **('**`my_dir`**')**来创建该目录。

如果您在验证目录不存在后创建目录，在执行对`os.makedirs`('`my_dir`')的调用之前，可能会生成错误或异常。

如果您想要更加小心并捕获任何潜在的异常，您可以将对`os.makedirs('`my_dir`')`的调用包装在**try...except**块中：

```py
if not os.path.exists('my_dir'):
    try:
        os.makedirs('my_dir')
    except OSError as e:
       print e
```

# 在 Python 中读写文件

现在我们将回顾读取和写入文件的方法。

# 文件方法

这些是可以在文件对象上使用的函数。

+   **file.write(string)**：将字符串打印到文件，没有返回。

+   **file.read([bufsize])**：从文件中读取最多“bufsize”字节数。如果没有缓冲区大小选项运行，则读取整个文件。

+   **file.readline([bufsize])**：从文件中读取一行（保留换行符）。

+   **file.close()**：关闭文件并销毁文件对象。Python 会自动执行这个操作，但当您完成一个文件时，这仍然是一个好习惯。

# 打开文件

处理文件的经典方法是使用`open()`方法。这种方法允许您打开一个文件，返回一个文件类型的对象：

**open(name[, mode[, buffering]])**

文件的打开模式可以是 r（读取）、w（写入）和 a（追加）。我们可以在这些模式中添加 b（二进制）、t（文本）和+（打开读写）模式。例如，您可以在选项中添加“+”，这允许使用同一个对象进行读/写：

```py
>>> my_file=open("file.txt","r”)
```

要读取文件，我们有几种可能性：

+   `readlines()`方法读取文件的所有行并将它们连接成一个序列。如果您想一次读取整个文件，这个方法非常有用：` >>> allLines = file.readlines()`。

+   如果我们想逐行读取文件，我们可以使用`readline()`方法。这样，如果我们想逐行读取文件的所有行，我们可以将文件对象用作迭代器：

```py
>>> for line in file:
>>>  print line
```

# 使用上下文管理器

在 Python 中创建文件的多种方法，但最干净的方法是使用**with**关键字，这种情况下我们使用**上下文管理器方法**。

最初，Python 提供了 open 语句来打开文件。当我们使用 open 语句时，Python 将开发者的责任委托给开发者，当不再需要使用文件时关闭文件。这种做法会导致错误，因为开发者有时会忘记关闭文件。自 Python 2.5 以来，开发者可以使用 with 语句安全地处理这种情况。**with 语句**会自动关闭文件，即使发生异常也是如此。

with 命令允许对文件进行多种操作：

```py
>>> with open("somefile.txt", "r") as file:
>>> for line in file:
>>> print line
```

这样，我们就有了优势：文件会自动关闭，我们不需要调用`close()`方法。

您可以在文件名为`**create_file.py**`的文件中找到下面的代码

```py
def main():
    with open('test.txt', 'w') as file:
        file.write("this is a test file")

 if __name__ == '__main__':
    main()
```

上面的脚本使用上下文管理器打开一个文件，并将其作为文件对象返回。在这个块中，我们调用 file.write("this is a test file")，将其写入我们创建的文件。在这种情况下，with 语句会自动处理文件的关闭，我们不需要担心它。

有关 with 语句的更多信息，您可以查看官方文档[`docs.python.org/2/reference/compound_stmts.html#the-with-statement`](https://docs.python.org/2/reference/compound_stmts.html#the-with-statement)。

# 逐行读取文件

我们可以逐行迭代文件：

```py
>>> with open('test.txt', 'r') as file:
>>>    for line in file:
>>>        print(line)
```

在这个例子中，当我们处理文件时，我们将所有这些功能与异常管理结合起来。

您可以在**`create_file_exceptions.py`**文件中找到以下代码：

```py
def main():
    try:
        with open('test.txt', 'w') as file:
            file.write("this is a test file")
    except IOError as e:
        print("Exception caught: Unable to write to file", e)
    except Exception as e:
        print("Another error occurred ", e)
    else:
        print("File written to successfully")

if __name__ == '__main__':
    main()
```

# Python 中的线程

在本节中，我们将介绍线程的概念以及如何使用`Python`模块管理它们。

# 线程介绍

线程是可以由操作系统调度并在单个核心上以并发方式或在多个核心上以并行方式执行的流。线程可以与共享资源（如内存）交互，并且它们也可以同时或甚至并行地修改事物。

# 线程类型

有两种不同类型的线程：

+   **内核级线程**：低级线程，用户无法直接与它们交互。

+   **用户级线程**：高级线程，我们可以在我们的代码中与它们交互。

# 进程与线程

进程是完整的程序。它们有自己的 PID（进程 ID）和 PEB（进程环境块）。这些是进程的主要特点：

+   进程可以包含多个线程。

+   如果一个进程终止，相关的线程也会终止。

线程是一个类似于进程的概念：它们也是正在执行的代码。然而，线程是在一个进程内执行的，并且进程的线程之间共享资源，比如内存。这些是线程的主要特点：

+   线程只能与一个进程关联。

+   进程可以在线程终止后继续（只要还有至少一个线程）。

# 创建一个简单的线程

线程是程序在并行执行任务的机制。因此，在脚本中，我们可以在单个处理器上多次启动相同的任务。

在 Python 中处理线程有两种选择：

+   线程模块提供了编写多线程程序的原始操作。

+   线程模块提供了更方便的接口。

`thread`模块将允许我们使用多个线程：

在这个例子中，我们创建了四个线程，每个线程在屏幕上打印不同的消息，这些消息作为参数传递给`thread_message(message)`方法。

您可以在 threads 子文件夹中的**`threads_init.py`**文件中找到以下代码：

```py
import thread
import time

num_threads = 4

def thread_message(message):
  global num_threads
  num_threads -= 1
  print('Message from thread %s\n' %message)

while num_threads > 0:
  print "I am the %s thread" %num_threads
  thread.start_new_thread(thread_message,("I am the %s thread" %num_threads,))
  time.sleep(0.1)
```

如果我们调用 help(thread)命令，可以查看更多关于`start_new_thread()`方法的信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/9fa9be64-d35f-47de-a4fb-d15a493af04b.png)

# 线程模块

除了`thread`模块，我们还有另一种使用`threading`模块的方法。线程模块依赖于`thread`模块为我们提供更高级、更完整和面向对象的 API。线程模块在某种程度上基于 Java 线程模型。

线程模块包含一个 Thread 类，我们必须扩展它以创建自己的执行线程。run 方法将包含我们希望线程执行的代码。如果我们想要指定自己的构造函数，它必须调用 threading.`Thread .__ init __ (self)`来正确初始化对象。

在 Python 中创建新线程之前，我们要检查 Python Thread 类的 init 方法构造函数，并查看需要传递的参数：

```py
# Python Thread class Constructor
 def __init__(self, group=None, target=None, name=None, args=(), kwargs=None, verbose=None):
```

Thread 类构造函数接受五个参数作为参数：

+   **group**：保留给未来扩展的特殊参数。

+   **target**：要由 run 方法()调用的可调用对象。

+   **name**：我们线程的名称。

+   **args**：用于目标调用的参数元组。

+   **kwargs**：调用基类构造函数的字典关键字参数。

如果我们在 Python 解释器控制台中调用**help(threading)**命令，可以获取有关`init()`方法的更多信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/f0c2a3d8-c36e-4ec1-9e17-1c6c8ab60a9d.png)

让我们创建一个简单的脚本，然后用它来创建我们的第一个线程：

在 threads 子文件夹中的**`threading_init.py`**文件中，您可以找到以下代码：

```py
import threading

def myTask():
    print("Hello World: {}".format(threading.current_thread()))

 # We create our first thread and pass in our myTask function
 myFirstThread = threading.Thread(target=myTask)
 # We start out thread
 myFirstThread.start()
```

为了使线程开始执行其代码，只需创建我们刚刚定义的类的实例并调用其 start 方法即可。主线程的代码和我们刚刚创建的线程的代码将同时执行。

我们必须实例化一个 Thread 对象并调用`start()`方法。Run 是我们希望在每个线程内并行运行的逻辑，因此我们可以使用`run()`方法启动一个新线程。此方法将包含我们希望并行执行的代码。

在此脚本中，我们正在创建四个线程。

在 threads 子文件夹中的**`threading_example.py`**文件中，您可以找到以下代码：

```py
import threading

class MyThread(threading.Thread):

    def __init__ (self, message):
        threading.Thread.__init__(self)
        self.message = message

    def run(self):
        print self.message

threads = []
for num in range(0, 5):
    thread = MyThread("I am the "+str(num)+" thread")
    thread.name = num
    thread.start()
```

我们还可以使用`thread.join()`方法等待线程终止。join 方法用于使执行调用的线程在被调用的线程结束之前被阻塞。在这种情况下，它用于使主线程在子线程之前不结束其执行，否则可能导致某些平台在子线程结束执行之前终止子线程。join 方法可以接受浮点数作为参数，表示等待的最大秒数。

在 threads 子文件夹中的**`threading_join.py`**文件中，您可以找到以下代码：

```py
import threading

class thread_message(threading.Thread):
    def __init__ (self, message):
         threading.Thread.__init__(self)
         self.message = message

    def run(self):
         print self.message

threads = []
for num in range(0, 10):
 thread = thread_message("I am the "+str(num)+" thread")
 thread.start()
 threads.append(thread)

# wait for all threads to complete by entering them
for thread in threads:
 thread.join()
```

# Python 中的多线程和并发

在本节中，我们将介绍多线程和并发的概念，以及如何使用 Python 模块来管理它们。

# 多线程简介

多线程应用程序的理念是允许我们在额外的线程上有代码的副本并执行它们。这允许程序同时执行多个操作。此外，当一个进程被阻塞时，例如等待输入/输出操作，操作系统可以将计算时间分配给其他进程。

当我们提到多处理器时，我们指的是可以同时执行多个线程的处理器。这些处理器通常有两个或更多个线程，在内核中积极竞争执行时间，当一个线程停止时，处理内核开始执行另一个线程。

这些子进程之间的上下文变化非常快，给人一种计算机在并行运行进程的印象，这使我们能够进行多任务处理。

# Python 中的多线程

Python 有一个 API，允许我们使用多个线程编写应用程序。为了开始多线程，我们将在`python`类内部创建一个新线程，并将其命名为**`ThreadWorker.py`**。这个类继承自`threading.Thread`，并包含管理一个线程的代码：

```py
import threading
class ThreadWorker(threading.Thread):
    # Our workers constructor
    def __init__(self):
        super(ThreadWorker, self).__init__()
    def run(self):
        for i in range(10):
           print(i)
```

现在我们有了我们的线程工作类，我们可以开始在我们的主类上工作了。创建一个新的 python 文件，命名为`main.py`，并放入以下代码：

```py
import threading
from ThreadWorker import ThreadWorker 
def main():
    # This initializes ''thread'' as an instance of our Worker Thread
   thread = ThreadWorker()
    # This is the code needed to run our thread
    thread.start()

if __name__ == "__main__":  
    main()
```

有关线程模块的文档可在[`docs.python.org/3/library/threading.html`](https://docs.python.org/3/library/threading.html)找到。

# 经典 Python 线程的限制

Python 经典线程的一个主要问题是它们的执行并不完全是异步的。众所周知，Python 线程的执行并不完全是并行的，**添加多个线程**通常会使执行时间加倍。因此，执行这些任务会减少执行时间。

Python 中线程的执行受 GIL（全局解释器锁）控制，因此一次只能执行一个线程，无论机器有多少个处理器。

这样可以更容易地为 Python 编写 C 扩展，但它的缺点是会大大限制性能，因此尽管如此，在 Python 中，有时我们可能更有兴趣使用进程而不是线程，后者不会受到这种限制的影响。

默认情况下，线程更改是在每 10 个字节码指令执行时进行的，尽管可以使用 sys.setcheckinterval 函数进行修改。它还在线程使用 time.sleep 休眠或开始输入/输出操作时进行更改，这可能需要很长时间才能完成，因此，如果不进行更改，CPU 将长时间没有执行代码，等待 I/O 操作完成。

为了最小化 GIL 对我们应用程序性能的影响，最好使用-O 标志调用解释器，这将生成一个优化的字节码，指令更少，因此上下文更改更少。我们还可以考虑使用进程而不是线程，正如我们讨论的那样，比如`ProcessPoolExecutors`模块。

有关**GIL**的更多信息，请参阅[`wiki.python.org/moin/GlobalInterpreterLock`](https://wiki.python.org/moin/GlobalInterpreterLock)。

# 使用 ThreadPoolExecutor 在 Python 中进行并发

在这一部分，我们回顾了提供执行任务异步的接口的**ThreadPoolExecutor**类。

# 创建 ThreadPoolExecutor

我们可以用 init 构造函数定义我们的**ThreadPoolExecutor**对象：

```py
executor = ThreadPoolExecutor(max_workers=5)
```

如果我们将最大工作线程数作为参数传递给构造函数，我们就可以创建 ThreadPoolExecutor。在这个例子中，我们已经将最大线程数定义为五，这意味着这组子进程只会同时有五个线程在工作。

为了使用我们的`ThreadPoolExecutor`，我们可以调用`submit()`方法，该方法以一个函数作为参数，以异步方式执行该代码：

`executor.submit(myFunction())`

# ThreadPoolExecutor 实践

在这个例子中，我们分析了`ThreadPoolExecutor`类的对象的创建。我们定义了一个`view_thread()`函数，允许我们使用`threading.get_ident()`方法显示当前线程标识符。

我们定义了我们的主函数，其中 executor 对象被初始化为 ThreadPoolExecutor 类的一个实例，并在这个对象上执行一组新的线程。然后我们使用`threading.current_thread()`方法获得已执行的线程。

您可以在 concurrency 子文件夹中的**threadPoolConcurrency.py**文件中找到以下代码：

```py
#python 3
from concurrent.futures import ThreadPoolExecutor
import threading
import random

def view_thread():
 print("Executing Thread")
 print("Accesing thread : {}".format(threading.get_ident()))
 print("Thread Executed {}".format(threading.current_thread()))

def main():
 executor = ThreadPoolExecutor(max_workers=3)
 thread1 = executor.submit(view_thread)
 thread1 = executor.submit(view_thread)
 thread3 = executor.submit(view_thread)

if __name__ == '__main__':
 main()

```

我们看到脚本输出中的三个不同值是三个不同的线程标识符，我们获得了三个不同的守护线程：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/459803de-3951-439d-8852-1c26a2480765.png)

# 使用上下文管理器执行 ThreadPoolExecutor

另一种实例化 ThreadPoolExecutor 的方法是使用`with`语句作为上下文管理器：

`with ThreadPoolExecutor(max_workers=2) as executor:`

在这个例子中，在我们的主函数中，我们将 ThreadPoolExecutor 作为上下文管理器使用，然后两次调用`future = executor.submit(message, (message))`来在线程池中处理每条消息。

你可以在 concurrency 子文件夹的`threadPoolConcurrency2.py`文件中找到以下代码：

```py
from concurrent.futures import ThreadPoolExecutor

def message(message):
 print("Processing {}".format(message))

def main():
 print("Starting ThreadPoolExecutor")
 with ThreadPoolExecutor(max_workers=2) as executor:
   future = executor.submit(message, ("message 1"))
   future = executor.submit(message, ("message 2"))
 print("All messages complete")

if __name__ == '__main__':
 main()
```

# Python Socket.io

在本节中，我们将回顾如何使用 socket.io 模块来创建基于 Python 的 Web 服务器。

# 介绍 WebSockets

WebSockets 是一种技术，通过 TCP 连接在客户端和服务器之间提供实时通信，并消除了客户端不断检查 API 端点是否有更新或新内容的需要。客户端创建到 WebSocket 服务器的单个连接，并保持等待以监听来自服务器的新事件或消息。

Websockets 的主要优势在于它们更有效，因为它们减少了网络负载，并以消息的形式向大量客户端发送信息。

# aiohttp 和 asyncio

aiohttp 是一个在 asyncio 中构建服务器和客户端应用程序的库。该库原生使用 websockets 的优势来异步通信应用程序的不同部分。

文档可以在[`aiohttp.readthedocs.io/en/stable`](http://aiohttp.readthedocs.io/en/stable/)找到。

asyncio 是一个帮助在 Python 中进行并发编程的模块。在 Python 3.6 中，文档可以在[`docs.python.org/3/library/asyncio.html`](https://docs.python.org/3/library/asyncio.html)找到。

# 使用 socket.io 实现服务器

Socket.IO 服务器可以在官方 Python 存储库中找到，并且可以通过 pip 安装：`pip install python-socketio.`

完整的文档可以在[`python-socketio.readthedocs.io/en/latest/`](https://python-socketio.readthedocs.io/en/latest/)找到。

以下是一个在 Python 3.5 中工作的示例，我们在其中使用 aiohttp 框架实现了一个 Socket.IO 服务器：

```py
from aiohttp import web
import socketio

socket_io = socketio.AsyncServer()
app = web.Application()
socket_io.attach(app)

async def index(request):
        return web.Response(text='Hello world from socketio' content_type='text/html')

# You will receive the new messages and send them by socket
@socket_io.on('message')
def print_message(sid, message):
    print("Socket ID: " , sid)
    print(message)

app.router.add_get('/', index)

if __name__ == '__main__':
    web.run_app(app)
```

在上面的代码中，我们实现了一个基于 socket.io 的服务器，该服务器使用了 aiohttp 模块。正如你在代码中看到的，我们定义了两种方法，`index()`方法，它将在“/”根端点接收到请求时返回一个响应消息，以及一个`print_message()`方法，其中包含`@socketio.on('message')`注释。这个注释使函数监听消息类型的事件，当这些事件发生时，它将对这些事件进行操作。

# 总结

在本章中，我们学习了 Python 编程的主要系统模块，如用于操作系统的 os 模块，用于文件系统的 sys 模块，以及用于执行命令的 sub-proccess 模块。我们还回顾了如何处理文件系统，读取和创建文件，管理线程和并发。

在下一章中，我们将探讨用于解析 IP 地址和域的 socket 包，并使用 TCP 和 UDP 协议实现客户端和服务器。

# 问题

1.  允许我们与 Python 解释器交互的主要模块是什么？

1.  允许我们与操作系统环境、文件系统和权限交互的主要模块是什么？

1.  用于列出当前工作目录内容的模块和方法是什么？

1.  执行命令或通过 call()函数调用进程的模块是什么？

1.  在 Python 中处理文件和管理异常的简单和安全方法是什么？

1.  进程和线程之间的区别是什么？

1.  Python 中用于创建和管理线程的主要模块是什么？

1.  Python 在处理线程时存在的限制是什么？

1.  哪个类提供了一个高级接口，用于以异步方式执行输入/输出任务？

1.  线程模块中的哪个函数确定了哪个线程执行了？

# 进一步阅读

在这些链接中，您将找到有关提到的工具的更多信息，以及我们讨论的一些模块的官方 Python 文档：

+   [`docs.python.org/3/tutorial/inputoutput.html`](https://docs.python.org/3/tutorial/inputoutput.html)

+   [`docs.python.org/3/library/threading.html`](https://docs.python.org/3/library/threading.html)

+   [`wiki.python.org/moin/GlobalInterpreterLock`](https://wiki.python.org/moin/GlobalInterpreterLock)

+   [`docs.python.org/3/library/concurrent.futures.html`](https://docs.python.org/3/library/concurrent.futures.html)

对于对使用 aiohttp 和 asyncio 等技术进行 Web 服务器编程感兴趣的读者，应该查看诸如 Flask（[`flask.pocoo.org`](http://flask.pocoo.org)）和 Django（[`www.djangoproject.com`](https://www.djangoproject.com)）等框架。


# 第三章：套接字编程

本章将介绍使用`socket`模块进行 Python 网络编程的一些基础知识。在此过程中，我们将使用 TCP 和**用户数据报** **协议**（**UDP**）协议构建客户端和服务器。套接字编程涵盖了使用 Python 编写低级网络应用程序的 TCP 和 UDP 套接字。我们还将介绍 HTTPS 和 TLS 以进行安全数据传输。

本章将涵盖以下主题：

+   了解套接字及如何在 Python 中实现它们

+   了解 Python 中 TCP 编程客户端和服务器

+   了解 Python 中 UDP 编程客户端和服务器

+   了解解析 IP 地址和域的套接字方法

+   将所有概念应用于实际用例，如端口扫描和异常处理

# 技术要求

本章的示例和源代码可在 GitHub 存储库的`第三章`文件夹中找到：[`github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security`](https://github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security)。

您需要在本地计算机上安装一个至少有 2GB 内存的 Python 发行版，并具有一些关于网络协议的基本知识。

# 套接字介绍

套接字是允许我们利用操作系统与网络进行交互的主要组件。您可以将套接字视为客户端和服务器之间的点对点通信通道。

网络套接字是在同一台或不同机器上的进程之间建立通信的一种简单方式。套接字的概念与 UNIX 文件描述符非常相似。诸如`read()`和`write()`（用于处理文件系统）的命令以类似的方式工作于套接字。

网络套接字地址由 IP 地址和端口号组成。套接字的目标是通过网络通信进程。

# Python 中的网络套接字

网络中不同实体之间的通信基于 Python 的套接字经典概念。套接字由机器的 IP 地址、它监听的端口和它使用的协议定义。

在 Python 中创建套接字是通过`socket.socket()`方法完成的。套接字方法的一般语法如下：

```py
s = socket.socket (socket_family, socket_type, protocol=0)
```

这些**参数**代表传输层的地址族和协议。

根据套接字类型，套接字根据是否使用 TCP 或 UDP 服务，被分类为流套接字（`socket.SOCK_STREAM`）或数据报套接字（`socket.SOCK_DGRAM`）。`socket.SOCK_DGRAM`用于 UDP 通信，`socket.SOCK_STREAM`用于 TCP 连接。

套接字还可以根据家族进行分类。我们有 UNIX 套接字（`socket.AF_UNIX`），它是在网络概念之前创建的，基于文件；我们感兴趣的是`socket.AF_INET`套接字；`socket.AF_INET6 用于 IPv6`套接字，等等：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/8617f5df-4575-4951-ab3a-1d6add4a165a.png)

# 套接字模块

在 Python 中，可以在`socket`模块中找到用于处理套接字的类型和函数。`socket`模块公开了快速编写 TCP 和 UDP 客户端和服务器所需的所有必要部分。`socket`模块几乎包含了构建套接字服务器或客户端所需的一切。在 Python 的情况下，套接字返回一个对象，可以对其应用套接字方法。

当您安装 Python 发行版时，默认情况下会安装此模块。

要检查它，我们可以在 Python 解释器中这样做：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/51894bae-8aea-48b5-baf5-676c2046591f.png)

在此屏幕截图中，我们看到此模块中可用的所有常量和方法。我们首先在返回的结构中看到的常量。在最常用的常量中，我们可以突出显示以下内容：

```py
socket.AF_INET
socket.SOCK_STREAM
```

构建在 TCP 级别工作的套接字的典型调用如下：

```py
socket.socket(socket.AF_INET,socket.SOCK_STREAM)
```

# 套接字方法

这些是我们可以在客户端和服务器中使用的一般套接字方法：

+   `socket.recv(buflen)`: 这个方法从套接字接收数据。方法参数指示它可以接收的最大数据量。

+   `socket.recvfrom(buflen)`: 这个方法接收数据和发送者的地址。

+   `socket.recv_into(buffer)`: 这个方法将数据接收到缓冲区中。

+   `socket.recvfrom_into(buffer)`: 这个方法将数据接收到缓冲区中。

+   `socket.send(bytes)`: 这个方法将字节数据发送到指定的目标。

+   `socket.sendto(data, address)`: 这个方法将数据发送到给定的地址。

+   `socket.sendall(data)`: 这个方法将缓冲区中的所有数据发送到套接字。

+   `socket.close()`: 这个方法释放内存并结束连接。

# 服务器套接字方法

在**客户端-服务器架构**中，有一个提供服务给一组连接的机器的中央服务器。这些是我们可以从服务器的角度使用的主要方法：

+   `socket.bind(address)`: 这个方法允许我们将地址与套接字连接起来，要求在与地址建立连接之前套接字必须是打开的

+   `socket.listen(count)`: 这个方法接受客户端的最大连接数作为参数，并启动用于传入连接的 TCP 监听器

+   `socket.accept()`: 这个方法允许我们接受来自客户端的连接。这个方法返回两个值：`client_socket` 和客户端地址。`client_socket` 是一个用于发送和接收数据的新套接字对象。在使用这个方法之前，必须调用`socket.bind(address)`和`socket.listen(q)`方法。

# 客户端套接字方法

这是我们可以在套接字客户端中用于与服务器连接的套接字方法：

+   `socket.connect(ip_address)`: 这个方法将客户端连接到服务器 IP 地址

我们可以使用`help(socket)`命令获取有关这个方法的更多信息。我们了解到这个方法与`connect_ex`方法相同，并且在无法连接到该地址时还提供了返回错误的可能性。

我们可以使用`help(socket)`命令获取有关这些方法的更多信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/6d26def8-753b-4270-8ae2-909cb98b0051.png)

# 使用套接字模块的基本客户端

在这个例子中，我们正在测试如何从网站发送和接收数据。一旦建立连接，我们就可以发送和接收数据。通过两个函数`send()`和`recv()`，可以非常容易地与套接字通信，用于 TCP 通信。对于 UDP 通信，我们使用`sendto()`和`recvfrom()`

在这个`socket_data.py`脚本中，我们使用`AF_INET`和`SOCK_STREAM`参数创建了一个套接字对象。然后将客户端连接到远程主机并发送一些数据。最后一步是接收一些数据并打印出响应。我们使用一个无限循环（while `True`）并检查数据变量是否为空。如果发生这种情况，我们结束循环。

您可以在`socket_data.py`文件中找到以下代码：

```py
import socket
print 'creating socket ...'
# create a socket object
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print 'socket created'
print "connection with remote host"
s.connect(('www.google.com',80))
print 'connection ok'
s.send( 'GET /index.html HTML/1.1\r\n\r\n')
while 1:
   data=s.recv(128)
    print data
    if data== "":
        break
print 'closing the socket'
s.close()
```

# 创建一个简单的 TCP 客户端和 TCP 服务器

创建这个应用的想法是，套接字客户端可以针对给定的主机、端口和协议建立连接。套接字服务器负责在特定端口和协议上接收来自客户端的连接。

# 使用套接字创建服务器和客户端

要创建一个套接字，使用`socket.socket()`构造函数，可以将家族、类型和协议作为可选参数。默认情况下，使用`AF_INET`家族和`SOCK_STREAM`类型。

在本节中，我们将看到如何创建一对客户端和服务器脚本作为示例。

我们必须做的第一件事是为服务器创建一个套接字对象：

```py
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
```

现在，我们必须使用 bind 方法指示服务器将监听哪个端口。对于 IP 套接字，就像我们的情况一样，bind 参数是一个包含主机和端口的元组。主机可以留空，表示可以使用任何可用的名称。

`bind(IP,PORT)`方法允许将主机和端口与特定套接字关联起来，考虑到`1-1024`端口保留用于标准协议：

```py
server.bind(("localhost", 9999))
```

最后，我们使用 listen 方法使套接字接受传入的连接并开始监听。listen 方法需要一个参数，指示我们要接受的最大连接数。

`accept`方法继续等待传入连接，阻塞执行直到消息到达。

要接受来自客户端套接字的请求，应该使用`accept()`方法。这样，服务器套接字等待接收来自另一台主机的输入连接：

```py
server.listen(10)
socket_client, (host, port) = server.accept()
```

我们可以使用`help(socket)`命令获取有关这些方法的更多信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/d1606fe2-424f-4112-9426-0d1abf78022c.png)

一旦我们有了这个套接字对象，我们就可以通过它与客户端进行通信，使用`recv`和`send`方法（或 UDP 中的`recvfrom`和`sendfrom`）来接收或发送消息。send 方法的参数是要发送的数据，而`recv`方法的参数是要接受的最大字节数：

```py
received = socket_client.recv(1024)
print "Received: ", received
socket_client.send(received)
```

要创建客户端，我们必须创建套接字对象，使用 connect 方法连接到服务器，并使用之前看到的 send 和 recv 方法。connect 参数是一个包含主机和端口的元组，与 bind 完全相同：

```py
socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket_client.connect(("localhost", 9999))
socket_client.send("message")
```

让我们看一个完整的例子。在这个例子中，客户端向服务器发送用户写的任何消息，服务器重复接收到的消息。

# 实现 TCP 服务器在本例中，我们将创建一个多线程 TCP 服务器。

服务器套接字在`localhost:9999`上打开一个 TCP 套接字，并在无限循环中监听请求。当您从客户端套接字接收到请求时，它将返回一条消息，指示已从另一台机器建立连接。

while 循环使服务器程序保持活动状态，并且不允许代码结束。`server.listen(5)`语句监听连接并等待客户端。此指令告诉服务器以最大连接数设置为`5`开始监听。

您可以在`tcp_server.py`文件中的`tcp_client_server`文件夹中找到以下代码：

```py
import socket
import threading

bind_ip = "localhost"
bind_port = 9999

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)server.bind((bind_ip,bind_port))
server.listen(5)
print "[*] Listening on %s:%d" % (bind_ip,bind_port)

# this is our client-handling thread
def handle_client(client_socket):
# print out what the client sends
    request = client_socket.recv(1024)
    print "[*] Received: %s" % request
    # send back a packet
    client_socket.send("Message received")
    client_socket.close()

while True:
    client,addr = server.accept()
    print "[*] Accepted connection from: %s:%d" % (addr[0],addr[1])
    # spin up our client thread to handle incoming data
    client_handler = threading.Thread(target=handle_client,args=(client,))
    client_handler.start()
```

# 实现 TCP 客户端

客户端套接字打开与服务器正在侦听的套接字相同类型的套接字并发送消息。服务器做出响应并结束执行，关闭客户端套接字。

您可以在`tcp_client.py`文件中的`tcp_client_server`文件夹中找到以下代码：

```py
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "127.0.0.1" # server address
port =9999 #server port
s.connect((host,port))
print s.recv(1024)
while True:
    message = raw_input("> ")
    s.send(message)
    if message== "quit":
        break
s.close()
```

在上述代码中，`new: s.connect((host,port))`方法将客户端连接到服务器，`s.recv(1024)`方法接收服务器发送的字符串。

# 创建一个简单的 UDP 客户端和 UDP 服务器

在本节中，我们将介绍如何使用 Python 的`Socket`模块设置自己的 UDP 客户端服务器应用程序。该应用程序将是一个服务器，它监听特定端口上的所有连接和消息，并将任何消息打印到控制台。

# UDP 协议简介

UDP 是与 TCP 处于同一级别的协议，即在 IP 层之上。它为使用它的应用程序提供了一种断开连接模式的服务。该协议适用于需要高效通信且无需担心数据包丢失的应用程序。UDP 的典型应用包括互联网电话和视频流。UDP 帧的标头由四个字段组成：

+   UDP 源端口

+   UDP 目的端口

+   UDP 消息的长度

+   检查和校验和作为错误控制字段

在 Python 中使用 TCP 的唯一区别是，在创建套接字时，必须使用`SOCK_DGRAM`而不是`SOCK_STREAM`。

TCP 和 UDP 之间的主要区别在于 UDP 不是面向连接的，这意味着我们的数据包不一定会到达目的地，并且如果传输失败，也不会收到错误通知。

# 使用 socket 模块的 UDP 客户端和服务器

在这个例子中，我们将创建一个同步 UDP 服务器，这意味着每个请求必须等待前一个请求的过程结束。`bind()`方法将用于将端口与 IP 地址关联起来。对于消息的接收，我们使用`recvfrom()`和`sendto()`方法进行发送。

# 实现 UDP 服务器

与 TCP 的主要区别在于 UDP 不控制发送的数据包的错误。TCP 套接字和 UDP 套接字之间的唯一区别是在创建套接字对象时必须指定`SOCK_DGRAM`而不是`SOCK_STREAM`。使用以下代码创建 UDP 服务器：

你可以在`udp_client_server`文件夹中的`udp_server.py`文件中找到以下代码：

```py
import socket,sys
buffer=4096
host = "127.0.0.1"
port = 6789
socket_server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
socket_server.bind((host,port))

while True:
    data,addr = socket_server.recvfrom(buffer)
    data = data.strip()
    print "received from: ",addr
    print "message: ", data
    try:
        response = "Hi %s" % sys.platform
    except Exception,e:
        response = "%s" % sys.exc_info()[0]
    print "Response",response
    socket_server.sendto("%s "% response,addr)

socket_server.close()
```

在上面的代码中，我们看到`socket.SOCK_DGRAM`创建了一个 UDP 套接字，而`data，**`addr = s.recvfrom(buffer)`**返回了数据和源地址。

现在我们已经完成了服务器，需要实现我们的客户端程序。服务器将持续监听我们定义的 IP 地址和端口号，以接收任何 UDP 消息。在执行 Python 客户端脚本之前，必须先运行该服务器，否则客户端脚本将失败。

# 实现 UDP 客户端

要开始实现客户端，我们需要声明要尝试发送 UDP 消息的 IP 地址，以及端口号。这个端口号是任意的，但你必须确保你没有使用已经被占用的套接字：

```py
UDP_IP_ADDRESS = "127.0.0.1"
 UDP_PORT = 6789
 message = "Hello, Server"
```

现在是时候创建我们将用来向服务器发送 UDP 消息的套接字了：

```py
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
```

最后，一旦我们构建了新的套接字，就该编写发送 UDP 消息的代码了：

```py
clientSocket.sendto(Message, (UDP_IP_ADDRESS, UDP_PORT))
```

你可以在`udp_client_server`文件夹中的`udp_client.py`文件中找到以下代码：

```py
import socket
UDP_IP_ADDRESS = "127.0.0.1"
UDP_PORT = 6789
buffer=4096
address = (UDP_IP_ADDRESS ,UDP_PORT)
socket_client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
while True:
    message = raw_input('?: ').strip()
    if message=="quit":
        break
    socket_client.sendto("%s" % message,address)
    response,addr = socket_client.recvfrom(buffer)
    print "=> %s" % response

socket_client.close()
```

如果我们尝试在 UDP 套接字中使用`SOCK_STREAM`，我们会得到`error: Traceback (most recent call last): File ".\udp_server.py", line 15, in <module> data,addr = socket_server.recvfrom(buffer)socket.error: [Errno 10057] A request to send or receive data was disallowed because the socket is not connected and no address was supplied`。

# 解析 IP 地址和域名

在本章中，我们已经学习了如何在 Python 中构建套接字，包括面向 TCP 连接和不面向连接的 UDP。在本节中，我们将回顾一些有用的方法，以获取有关 IP 地址或域名的更多信息。

# 使用套接字收集信息

收集更多信息的有用方法包括：

+   `gethostbyaddr(address)`:允许我们从 IP 地址获取域名

+   `gethostbyname(hostname)`:允许我们从域名获取 IP 地址

我们可以使用`help(socket)`命令获取有关这些方法的更多信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/dcfa6c52-52f4-4d99-95c6-fe9fcf06dd81.png)

现在我们将详细介绍一些与主机、IP 地址和域名解析相关的方法。对于每个方法，我们将展示一个简单的例子：

+   `socket.gethostbyname(hostname)`:该方法将主机名转换为 IPv4 地址格式。IPv4 地址以字符串形式返回。这个方法相当于我们在许多操作系统中找到的`nslookup`命令：

```py
>>> import socket
> socket.gethostbyname('packtpub.com')
'83.166.169.231'
>> socket.gethostbyname('google.com')
'216.58.210.142'
```

+   `socket.gethostbyname_ex(name)`:该方法返回单个域名的多个 IP 地址。这意味着一个域名运行在多个 IP 上：

```py
>> socket.gethostbyname_ex('packtpub.com')
 ('packtpub.com', [], ['83.166.169.231'])
>>> socket.gethostbyname_ex('google.com')
 ('google.com', [], ['216.58.211.46'])
```

+   `socket.getfqdn([domain])`:用于查找域的完全限定名称：

```py
>> socket.getfqdn('google.com')
```

+   `socket.gethostbyaddr(ip_address)`:该方法返回一个元组（`hostname`，`name`，`ip_address_list`），其中`hostname`是响应给定 IP 地址的主机名，`name`是与同一地址关联的名称列表，`ip_address_list`是同一主机上同一网络接口的 IP 地址列表：

```py
>>> socket.gethostbyaddr('8.8.8.8')
('google-public-dns-a.google.com', [], ['8.8.8.8'])
```

+   `socket.getservbyname(servicename[, protocol_name])`：此方法允许您从端口名称获取端口号：

```py
>>> import socket
>>> socket.getservbyname('http')
80
>>> socket.getservbyname('smtp','tcp')
25
```

+   `socket.getservbyport(port[, protocol_name])`：此方法执行与前一个方法相反的操作，允许您从端口号获取端口名称：

```py
>>> socket.getservbyport(80)
'http'
>>> socket.getservbyport(23)
'telnet'
```

以下脚本是一个示例，演示了如何使用这些方法从 Google 服务器获取信息。

您可以在`socket_methods.py`文件中找到以下代码：

```py
import socket
import sys
try:
    print "gethostbyname"
    print socket.gethostbyname_ex('www.google.com')
    print "\ngethostbyaddr"
    print socket.gethostbyaddr('8.8.8.8')
    print "\ngetfqdn"
    print socket.getfqdn('www.google.com')
    print "\ngetaddrinfo"
    print socket.getaddrinfo('www.google.com',socket.SOCK_STREAM)
except socket.error as error:
    print (str(error))
    print ("Connection error")
    sys.exit()
```

`socket.connect_ex(address)`方法用于使用套接字实现端口扫描。此脚本显示了在本地主机上使用回环 IP 地址接口`127.0.0.1`的打开端口。

您可以在`socket_ports_open.py`文件中找到以下代码：

```py
import socket
ip ='127.0.0.1'
portlist = [22,23,80,912,135,445,20]
for port in portlist:
    sock= socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    result = sock.connect_ex((ip,port))
    print port,":", result
    sock.close()
```

# 反向查找

此命令从 IP 地址获取主机名。为此任务，我们可以使用`gethostbyaddr()`函数。在此脚本中，我们从`8.8.8.8`的 IP 地址获取主机名。

您可以在`socket_reverse_lookup.py`文件中找到以下代码：

```py
import sys, socket
try :
    result=socket.gethostbyaddr("8.8.8.8")
    print "The host name is:"
    print " "+result[0]
    print "\nAddress:"
    for item in result[2]:
        print " "+item
except socket.herror,e:
    print "error for resolving ip address:",e
```

# 套接字的实际用例

在本节中，我们将讨论如何使用套接字实现端口扫描以及在使用套接字时如何处理异常。

# 使用套接字进行端口扫描

套接字是网络通信的基本构建模块，我们可以通过调用`connect_ex`方法来轻松地检查特定端口是打开、关闭还是被过滤。

例如，我们可以编写一个函数，该函数接受 IP 和端口列表作为参数，并针对每个端口返回该端口是打开还是关闭。

在此示例中，我们需要导入 socket 和`sys`模块。如果我们从主程序执行该函数，我们可以看到它如何检查每个端口，并返回特定 IP 地址的端口是打开还是关闭。第一个参数可以是 IP 地址，也可以是域名，因为该模块能够从 IP 解析名称，反之亦然。

您可以在`port_scan`文件夹中的`check_ports_socket.py`文件中找到以下代码：

```py
import socket
import sys

def checkPortsSocket(ip,portlist):
    try:
        for port in portlist:
            sock= socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((ip,port))
            if result == 0:
                print ("Port {}: \t Open".format(port))
            else:
                print ("Port {}: \t Closed".format(port))
            sock.close()
    except socket.error as error:
        print (str(error))
        print ("Connection error")
        sys.exit()

checkPortsSocket('localhost',[80,8080,443])
```

以下 Python 代码将允许您扫描本地或远程主机的开放端口。该程序会扫描用户输入的特定 IP 地址上的选定端口，并将开放的端口反馈给用户。如果端口关闭，它还会显示有关关闭原因的信息，例如超时连接。

您可以在`port_scan`文件夹中的`socket_port_scanner.py`文件中找到以下代码。

脚本从用户输入的 IP 地址和端口相关信息开始：

```py
#!/usr/bin/env python
#--*--coding:UTF-8--*--
# Import modules
import socket
import sys
from datetime import datetime
import errno

# RAW_INPUT IP / HOST
remoteServer    = raw_input("Enter a remote host to scan: ")
remoteServerIP  = socket.gethostbyname(remoteServer)

# RAW_INPUT START PORT / END PORT
print "Please enter the range of ports you would like to scan on the machine"
startPort    = raw_input("Enter a start port: ")
endPort    = raw_input("Enter a end port: ")

print "Please wait, scanning remote host", remoteServerIP
#get Current Time as T1
t1 = datetime.now()

```

我们继续脚本，使用从`startPort`到`endPort`的 for 循环来分析每个端口。最后，我们显示完成端口扫描所需的总时间：

```py
#Specify Range - From startPort to startPort
try:
    for port in range(int(startPort),int(endPort)):
    print ("Checking port {} ...".format(port))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((remoteServerIP, port))
    if result == 0:
        print "Port {}: Open".format(port)
    else:
        print "Port {}: Closed".format(port)
        print "Reason:",errno.errorcode[result]
    sock.close()
# If interrupted
except KeyboardInterrupt:
    print "You pressed Ctrl+C"
    sys.exit()
# If Host is wrong
except socket.gaierror:
    print 'Hostname could not be resolved. Exiting'
    sys.exit()
# If server is down
except socket.error:
    print "Couldn't connect to server"
    sys.exit()
#get current Time as t2
t2 = datetime.now()
#total Time required to Scan
total =  t2 - t1
# Time for port scanning
print 'Port Scanning Completed in: ', total
```

在执行上一个脚本时，我们可以看到打开的端口以及完成端口扫描所需的时间（以秒为单位）：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/4cd90073-6b11-4d10-bc57-cf996c26d4db.png)

以下 Python 脚本将允许我们使用`portScanning`和`socketScan`函数扫描 IP 地址。该程序会扫描用户输入的 IP 地址解析出的特定域上的选定端口。

在此脚本中，用户必须输入主机和端口作为必填参数，用逗号分隔：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/fb2d53e2-8076-426f-a13f-c52a0c3148e9.png)

您可以在`port_scan`文件夹中的`socket_portScan.py`文件中找到以下代码：

```py
#!/usr/bin/python
# -*- coding: utf-8 -*-
import optparse
from socket import *
from threading import *

def socketScan(host, port):
    try:
        socket_connect = socket(AF_INET, SOCK_STREAM)
        socket_connect.connect((host, port))
        results = socket_connect.recv(100)
        print '[+] %d/tcp open \n' % port
        print '[+] ' + str(results)
    except:
        print '[-] %d/tcp closed \n' % port
    finally:
        socket_connect.close()

def portScanning(host, ports):
    try:
        ip = gethostbyname(host)
    except:
        print "[-] Cannot resolve '%s': Unknown host" %host
        return
    try:
        name = gethostbyaddr(ip)
        print '\n[+] Scan Results for: ' + name[0]
    except:
        print '\n[+] Scan Results for: ' + ip

    for port in ports:
        t = Thread(target=socketScan,args=(host,int(port)))
        t.start()
```

这是我们的主程序，当我们获取脚本执行的必填参数主机和端口时。一旦我们获得这些参数，我们调用`portScanning`函数，该函数将解析 IP 地址和主机名，并调用`socketScan`函数，该函数将使用`socket`模块确定端口状态：

```py
def main():
    parser = optparse.OptionParser('socket_portScan '+ '-H <Host> -P <Port>')
    parser.add_option('-H', dest='host', type='string', help='specify host')                parser.add_option('-P', dest='port', type='string', help='specify port[s] separated by comma')

(options, args) = parser.parse_args()
host = options.host
ports = str(options.port).split(',')

if (host == None) | (ports[0] == None):
    print parser.usage
    exit(0)

portScanning(host, ports)

if __name__ == '__main__':
    main()
python .\socket_portScan.py -H 8.8.8.8 -P 80,21,22,23
```

在执行上一个脚本时，我们可以看到`google-public-dns-a.google.com`域中的所有端口都已关闭。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/45a671e7-9e5a-47e5-84df-0880e69b1ec8.png)

# 处理套接字异常

为了处理异常，我们将使用 try 和 except 块。Python 的套接字库为不同的错误定义了不同类型的异常。这些异常在这里描述：

+   `exception socket.timeout`：此块捕获与等待时间到期相关的异常。

+   `exception socket.gaierror`：此块捕获在搜索有关 IP 地址的信息时发生的错误，例如当我们使用`getaddrinfo()`和`getnameinfo()`方法时。

+   `exception socket.error`：此块捕获通用输入和输出错误以及通信。这是一个通用块，您可以捕获任何类型的异常。

下一个示例向您展示如何处理异常。

您可以在`manage_socket_errors.py`文件中找到以下代码：

```py
import socket,sys
host = "127.0.0.1"
port = 9999
try:
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
except socket.error,e:
    print "socket create error: %s" %e
    sys.exit(1)

try:
    s.connect((host,port))
except socket.timeout,e :
    print "Timeout %s" %e
    sys.exit(1)
except socket.gaierror, e:
    print "connection error to the server:%s" %e
    sys.exit(1)
except socket.error, e:
    print "Connection error: %s" %e
    sys.exit(1)
```

在上一个脚本中，当与 IP 地址的连接超时时，它会抛出与服务器的套接字连接相关的异常。如果尝试获取不存在的特定域或 IP 地址的信息，它可能会抛出`socket.gaierror`异常，并显示`连接到服务器的错误：[Errno 11001] getaddrinfo failed`消息。如果与目标的连接不可能，它将抛出`socket.error`异常，并显示`连接错误：[Errno 10061] 由于目标计算机积极拒绝，无法建立连接`消息。

# 摘要

在本章中，我们回顾了`socket`模块，用于在 Python 中实现客户端-服务器架构的 TCP 和 UDP 协议。我们还回顾了从域解析 IP 地址和反之的主要功能和方法。最后，我们实现了端口扫描和如何在产生错误时处理异常等实际用例。

在下一个*章节*中，我们将探讨用 Python 处理 http 请求包、REST API 和服务器身份验证。

# 问题

1.  `sockets`模块的哪种方法允许从 IP 地址解析域名？

1.  `socket`模块的哪种方法允许服务器套接字接受来自另一台主机的客户端套接字的请求？

1.  `socket`模块的哪种方法允许您向特定地址发送数据？

1.  `socket`模块的哪种方法允许您将主机和端口与特定套接字关联起来？

1.  TCP 和 UDP 协议之间的区别是什么，以及如何在 Python 中使用`socket`模块实现它们？

1.  `socket`模块的哪种方法允许您将主机名转换为 IPv4 地址格式？

1.  `socket`模块的哪种方法允许您使用套接字实现端口扫描并检查端口状态？

1.  `socket`模块的哪个异常允许您捕获与等待时间到期相关的异常？

1.  `socket`模块的哪个异常允许您捕获在搜索有关 IP 地址的信息时发生的错误？

1.  `socket`模块的哪个异常允许您捕获通用输入和输出错误以及通信？

# 进一步阅读

在这些链接中，您将找到有关提到的工具和一些评论模块的官方 Python 文档的更多信息：

+   [`wiki.python.org/moin/HowTo/Sockets`](https://wiki.python.org/moin/HowTo/Sockets)

+   [`docs.python.org/2/library/socket.html`](https://docs.python.org/2/library/socket.html)

+   [`docs.python.org/3/library/socket.html`](https://docs.python.org/3/library/socket.html)

+   [`www.geeksforgeeks.org/socket-programming-python/`](https://www.geeksforgeeks.org/socket-programming-python/)

+   [`realpython.com/python-sockets/`](https://realpython.com/python-sockets/)

Python 3.7 中套接字的新功能：[`www.agnosticdev.com/blog-entry/python/whats-new-sockets-python-37`](https://www.agnosticdev.com/blog-entry/python/whats-new-sockets-python-37)
