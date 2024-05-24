# Python 渗透测试实用指南（一）

> 原文：[`annas-archive.org/md5/4B796839472BFAAEE214CCEDB240AE18`](https://annas-archive.org/md5/4B796839472BFAAEE214CCEDB240AE18)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

在网络安全和 Python 编程领域有这么多优秀的书籍，都是由聪明的人写成的，那么这本书有什么不同的特点呢？这是一个非常合理的问题，现在让我们来试着回答一下。

这本书试图捕捉我在过去几年中使用 Python 和渗透测试领域所积累的实践经验。它是 Python、渗透测试/攻击性安全、防御性安全和机器学习在渗透测试生态系统中独特的融合。本书以温和的方式开始，涵盖了 Python 的所有关键概念，使读者在前四章结束时能够对 Python 有相当不错的掌握，然后深入研究渗透测试和网络安全用例的自动化。读者将了解如何从头开始开发符合行业标准的漏洞扫描器，与 Nessus 和 Qualys 相同。本书还探讨了有关 Web 应用程序漏洞、它们的利用以及如何使用定制的利用程序自动化 Web 利用的概念。它还深入探讨了反向工程、模糊测试和在 Windows 和 Linux 环境中的缓冲区溢出漏洞，以 Python 作为核心。书中有一个专门讨论自定义利用程序开发的部分，重点是规避反病毒检测。本书还有一个专门讨论开发网络爬虫及其在网络安全领域中的利用的章节。本书还对防御性安全概念提供了相当深入的见解，讨论了网络威胁情报，以及如何开发自定义威胁评分算法。本书最后还介绍了 Python 的许多其他有益用例，比如开发自定义键盘记录器。

# 这本书适合谁

如果你是一名安全顾问、开发人员或者对 Python 知之甚少的网络安全爱好者，并且需要深入了解渗透测试生态系统和 Python 如何结合创建攻击工具、利用漏洞、自动化网络安全用例等等，那么这本书适合你。《Python 实战渗透测试》指导你深入了解 Python 在网络安全和渗透测试中的高级用法，帮助你更好地了解基础设施中的安全漏洞。

# 这本书涵盖了什么

第一章，*Python 简介*，介绍了 Python 的基础知识，主要关注 Python 使用的数据类型、变量、表达式和程序结构。其目标是让读者熟悉 Python 编程语言的基础知识，以便在接下来的章节中使用和利用它。

第二章，*构建 Python 脚本*，涵盖了 Python 的进一步概念，这些概念构成了编写 Python 脚本的基础，同时探讨了函数、模块、循环、包和导入等概念。

第三章，*概念处理*，向读者介绍了其他与 Python 相关的概念，包括类、对象、IO 和目录访问、正则表达式、异常处理以及 CSV、JSON 和 XML 文件的解析。

第四章，*高级 Python 模块*，将学习过程提升到一个高级水平，探索了 Python 的强大之处，理解了多进程和多线程概念，以及套接字编程。

第五章，“漏洞扫描器 Python-第 1 部分”，探讨了制作迷你漏洞扫描引擎所需的高级概念，该引擎将使用自定义端口扫描程序构建在 Nmap 上的端口扫描结果，并应用各种开源脚本和 Metasploit 模块，以及 Python、Ruby 和 NSE 脚本。结果将被汇总，最终将为分析师起草报告。这一章在复杂性和代码行数方面非常庞大，分为两部分。本部分侧重于使用 Python 自动化端口扫描。

第六章，“漏洞扫描器 Python-第 2 部分”，探讨了制作迷你漏洞扫描引擎所需的高级概念。这一章是前一章的延续，读者将学习如何协调各种 Kali Linux 工具，以便自动化服务枚举阶段的漏洞评估，从而完成定制漏洞扫描器的开发。

第七章，“机器学习和网络安全”，试图将网络安全领域与数据科学联系起来，并阐明我们如何使用机器学习和自然语言处理来自动化渗透测试的手动报告分析阶段。本章还将把之前的所有部分联系在一起，基于我们迄今所学的知识，制作一个迷你渗透测试工具包。

第八章，“自动化 Web 应用程序扫描-第 1 部分”，向读者解释了他们如何使用 Python 自动化各种 Web 应用程序攻击类型，其中一些最知名的包括 SQL 注入、XSS、CSRF 和点击劫持。

第九章，“自动化 Web 应用程序扫描-第 2 部分”，是前一章的延续。在这里，读者将了解如何使用 Python 开发自定义利用程序，利用 Web 应用程序最终为用户提供使用 Python 的 shell 访问权限。

第十章，“构建自定义爬虫”，解释了如何使用 Python 构建自定义爬虫，以便在应用程序中进行爬取，无论是否有身份验证，同时列出被测试应用程序的注入点和网页。爬虫的功能可以根据需求进行扩展和定制。

第十一章，“逆向工程 Linux 应用程序和缓冲区溢出”，解释了如何对 Linux 应用程序进行逆向工程。读者还将了解 Python 如何在帮助 Linux 环境中的缓冲区溢出漏洞方面发挥作用。该章还指导读者针对缓冲区溢出漏洞进行自定义利用程序开发。

第十二章，“逆向工程 Windows 应用程序”，解释了如何对 Windows 应用程序进行逆向工程，以及 Python 如何在帮助 Windows 环境中的缓冲区溢出漏洞方面发挥作用。该章还指导读者针对缓冲区溢出漏洞进行自定义利用程序开发。

第十三章，“利用开发”，解释了读者如何使用 Python 编写自己的利用程序，这些利用程序可以作为 Metasploit 模块进行扩展，并且还涵盖了编码 shell 以避免检测。

第十四章，*网络威胁情报*，指导读者如何使用 Python 进行网络威胁情报和威胁信息的收集、威胁评分，最后，如何利用获得的信息，使 SIEM、IPS 和 IDS 系统能够利用最新的威胁信息进行早期检测。

第十五章，*Python 的其他奇迹*，介绍了如何使用 Python 提取 Google 浏览器保存的密码，开发自定义键盘记录器，解析 Nessus 和 Nmap 报告文件等。

# 为了充分利用本书

为了充分利用本书，只需要有一个继续前进并详细理解每个概念的愿望。

# 下载示例代码文件

您可以从您在[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册。

1.  选择支持选项卡。

1.  点击代码下载和勘误。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保您使用最新版本的解压或提取文件夹：

+   Windows 的 WinRAR/7-Zip

+   Mac 的 Zipeg/iZip/UnRarX

+   Linux 的 7-Zip/PeaZip

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Penetration-Testing-with-Python`](https://github.com/PacktPublishing/Hands-On-Penetration-Testing-with-Python)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还提供了来自我们丰富书籍和视频目录的其他代码包，可以在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。请查看！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781788990820_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/9781788990820_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如："要使用 Python 终端，只需在终端提示符中键入`python3`命令。"

代码块设置如下：

```py
a=44
b=33
if a > b:
    print("a is greater")
print("End") 

```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```py
my_list=[1,"a",[1,2,3],{"k1":"v1"}]
my_list[0] -> 1
my_List[1] -> "a"
my_list[2] -> [1,2,3]
my_list[2][0] -> 1
my_list[2][2] -> 3
my_list[3] -> {"k1":"v1"}
my_list[3]["k1"] -> "v1"
my_list[3].get("k1") -> "v1 

```

任何命令行输入或输出都以以下方式编写：

```py
import threading
>>> class a(threading.Thread):
... def __init__(self):
... threading.Thread.__init__(self)
... def run(self):
... print("Thread started")
... 
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中出现。例如："点击**开始爬取**按钮。"

警告或重要说明会出现在这样。

技巧和窍门会出现在这样。


# 第一章：Python 简介

本章将介绍 Python，主要关注 Python 编程语言遵循的数据类型，变量，表达式和程序结构。本章的目标是使读者熟悉 Python 的基础知识，以便他们可以在接下来的章节中使用它。本章将涵盖 Python 的安装及其依赖管理器。我们还将开始研究 Python 脚本。

在本章中，我们将涵盖以下主题：

+   Python 简介（包括安装和设置）

+   基本数据类型

+   序列数据类型 - 列表，字典，元组

+   变量和关键字

+   操作和表达式

# 技术要求

在继续本章之前，请确保您已准备好以下设置：

+   一台工作的计算机或笔记本电脑

+   Ubuntu 操作系统，最好是 16.04 版本

+   Python 3.x

+   一个可用的互联网连接

# 为什么选择 Python？

当我们考虑探索一种新的编程语言或技术时，我们经常会想到新技术的范围以及它可能给我们带来的好处。让我们从思考为什么我们可能想要使用 Python 以及它可能给我们带来的优势开始这一章。

为了回答这个问题，我们将考虑当前的技术趋势，而不会涉及更多的语言特定功能，比如它是面向对象的，功能性的，可移植的和解释性的。我们以前听过这些术语。让我们试着思考为什么我们可能会从严格的工业角度使用 Python，这种语言的现在和未来的景观可能是什么样的，以及这种语言如何为我们服务。我们将首先提到一些计算机科学相关人员可能选择的职业选项：

+   程序员或软件开发人员

+   Web 开发人员

+   数据库工程师

+   网络安全专业人员（渗透测试员，事件响应者，SOC 分析师，恶意软件分析师，安全研究员等）

+   数据科学家

+   网络工程师

还有许多其他角色，但我们暂时只关注最通用的选项，看看 Python 如何适用于它们。让我们从程序员或软件开发人员的角色开始。截至 2018 年，Python 被记录为招聘广告中列出的第二受欢迎的语言（[`www.codingdojo.com/blog/7-most-in-demand-programming-languages-of-2018/`](https://www.codingdojo.com/blog/7-most-in-demand-programming-languages-of-2018/)）。程序员的角色可能因公司而异，但作为 Python 程序员，您可能会编写 Python 软件产品，开发用 Python 编写的网络安全工具（已经存在大量这样的工具可以在 GitHub 和网络安全社区的其他地方找到），原型设计一个可以模仿人类的机器人，设计智能家居自动化产品或实用工具等。Python 的范围涵盖了软件开发的各个方面，从典型的软件应用到强大的硬件产品。这是因为这种语言易于理解，具有出色的库支持，由庞大的社区支持，并且当然，它是开源的美丽之处。

让我们转向网络。近年来，Python 在成熟作为 Web 开发语言方面表现出色。最受欢迎的全栈基于 Web 的框架，如 Django、Flask 和 CherryPy，使得使用 Python 进行 Web 开发成为一种无缝和清晰的体验，学习、定制和灵活性都很强。我个人最喜欢 Django，因为它提供了非常清晰的 MVC 架构，业务逻辑和表示层完全隔离，使得开发代码更加清晰和易于管理。Django 装备齐全，支持 ORM 和使用 celery 进行后台任务处理，实现了其他任何 Web 框架能够做到的一切，同时保持了 Python 的本地代码。Flask 和 CherryPy 也是 Web 开发的绝佳选择，可以对数据流和定制性进行大量控制。

**网络安全**是一个离开 Python 就不完整的领域。网络安全领域的每个行业都与 Python 有一定的关联，大多数网络安全工具都是用 Python 编写的。从渗透测试到监控安全运营中心，Python 被广泛使用和需要。Python 通过为渗透测试人员提供出色的工具和自动化支持，使他们能够为各种渗透测试活动编写快速而强大的脚本，从侦察到利用都可以。我们将在本书的课程中详细学习这一点。

**机器学习**（**ML**）和**人工智能**（**AI**）是科技行业中我们经常遇到的热门词汇。Python 对所有 ML 和 AI 模型都有出色的支持。在大多数情况下，Python 是任何想学习 ML 和 AI 的人的首选。这个领域中另一个著名的语言是 R，但由于 Python 在其他技术和软件开发领域的出色覆盖，将用 Python 编写的机器学习解决方案与现有或新产品结合起来比用 R 编写的解决方案更容易。Python 拥有惊人的机器学习库和 API，如 sciket-learn、NumPy、Pandas、matplotlib、NLTK 和 TensorFlow。Pandas 和 NumPy 使得科学计算变得非常容易，给用户提供了在内存中处理大型数据集的灵活性，具有出色的抽象层，使开发人员可以忘记背景细节，干净高效地完成工作。

几年前，一个典型的数据库工程师可能会被期望了解关系型数据库，比如**MySQL**、**SQL Server**、**Oracle**、**PostgreSQL**等等。然而，在过去的几年里，技术领域已经完全改变。虽然一个典型的数据库工程师仍然应该了解并熟练掌握这些数据库技术栈，但这已经不够了。随着数据量的增加，当我们进入大数据时代时，传统数据库必须与 Hadoop 或 Spark 等大数据解决方案配合工作。话虽如此，数据库工程师的角色已经演变成包括数据分析师的技能集。现在，数据不再需要从本地数据库服务器中获取和处理 - 它需要从异构来源收集，预处理，跨分布式集群或并行核心进行处理，然后再存储回分布式节点集群中。我们在这里谈论的是大数据分析和分布式计算。我们之前提到了 Hadoop 这个词。如果你对它不熟悉，Hadoop 是一个引擎，能够通过在计算机集群中生成文件块来处理大文件，然后对处理结果集进行聚合，这在业界被称为 map-reduce 操作。Apache Spark 是分析领域的一个新热词，它声称比 Hadoop 生态系统快 100 倍。Apache Spark 有一个名为`pyspark`的 Python API，使用它我们可以用本地 Python 代码运行 Apache Spark。它非常强大，熟悉 Python 使得设置变得简单和无缝。

提到前面的几点的目的是为了突出 Python 在当前技术领域和未来的重要性。机器学习和人工智能很可能会成为主导产业，而这两者都主要由 Python 驱动。因此，现在开始阅读和探索 Python 和机器学习的网络安全将是一个更好的时机。让我们通过了解一些基础知识来开始我们的 Python 之旅。

# 关于 Python - 编译还是解释

编译器通过将用高级编程语言编写的人类可读的代码转换为机器代码，然后由底层架构或机器运行。如果你不想运行代码，编译后的版本可以保存并以后执行。值得注意的是，编译器首先检查语法错误，只有在没有发现错误的情况下才会创建程序的编译版本。如果你使用过 C 语言，你可能会遇到`.out`文件，这些是编译后的文件的例子。

然而，在解释器的情况下，程序的每一行都是在运行时从源代码中解释并转换为机器代码进行执行。Python 属于解释的字节码类别。这意味着 Python 代码首先被翻译成中间字节码（一个`.pyc`文件）。然后，这个字节码由解释器逐行解释并在底层架构上执行。

# 安装 Python

在本书的过程中，所有的练习都将在 Linux 操作系统上展示。在我的情况下，我使用的是 Ubuntu 16.04。你可以选择任何你喜欢的变种。我们将使用`python3`来进行练习，可以按照以下方式安装：

```py
sudo apt-get install python3
sudo apt-get install python3-pip
```

第二个命令安装了**pip**，它是 Python 的包管理器。所有不包括在标准安装中的开源 Python 库都可以通过`pip`来安装。我们将在接下来的部分中探讨如何使用 pip。

# 开始

在本书的过程中，我们将致力于涵盖 Python、网络安全、渗透测试和数据科学领域的先进和著名的行业标准。然而，正如他们所说，每段非凡的旅程都始于小步。让我们开始我们的旅程，先了解 Python 的基础知识。

# 变量和关键字

**变量**，顾名思义，是保存值的占位符。Python 变量只是在 Python 程序或脚本的范围内保存用户定义值的名称。如果我们将 Python 变量与其他传统语言（如 C、C++、Java 等）进行比较，我们会发现它们有些不同。在其他语言中，我们必须将数据类型与变量的名称关联起来。例如，在 C 或 Java 中声明整数，我们必须声明为`int a=2`，编译器将立即在 C 中保留两个字节的内存，在 Java 中保留四个字节。然后将内存位置命名为`a`，程序将引用其中存储的值`2`。然而，Python 是一种动态类型语言，这意味着我们不需要将数据类型与我们在程序中声明或使用的变量关联起来。

整数的典型 Python 声明可能如`a=20`。这只是创建一个名为`a`的变量，并将值`20`放入其中。即使我们在下一行将值更改为`a="hello world"`，它也会将字符串`hello world`与变量`a`关联起来。让我们在 Python 终端上看看它的运行情况：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/c64e1eab-6ced-40a7-afd9-f52a540dabe8.png)

使用 Python 终端，只需在终端提示符中键入`python3`命令。让我们思考一下这是如何工作的。看一下下面的图表，比较静态类型语言和动态类型语言：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/0d42b878-542f-4972-a1d6-a5650b1921bc.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/36132ef2-42f9-4f37-8d0c-18089f559fd2.png)

正如您在前面的图表中看到的，在 Python 的情况下，变量实际上保存对实际对象的引用。每次更改值时，都会在内存中创建一个新对象，并且变量指向这个新对象。以前的对象由垃圾收集器声明。

在讨论 Python 是一种动态类型语言之后，我们不应该将其与弱类型语言混淆。尽管 Python 是动态类型的，但它也是一种强类型语言，就像 Java、C 或 C++一样。

在下面的示例中，我们声明一个字符串类型的变量`a`和一个整数类型的变量`b`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/991cd824-ffd9-4193-8d3e-31654ea761e5.png)

当我们执行操作`c=a+b`时，在弱类型语言中可能发生的是将`b`的整数值转换为字符串，并将存储在变量`c`中的结果为`hello world22`。然而，由于 Python 是强类型的，该函数遵循与变量关联的类型。我们需要显式进行转换才能执行这种操作。

让我们看看下面的示例，以了解强类型语言的含义；我们在运行时明确更改变量`b`的类型并将其转换为字符串类型：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/5b8991ee-cd92-44ad-abfe-d0534491ef7e.png)

# 变量命名约定

在了解了如何声明和使用变量的基础知识之后，让我们尝试了解它们遵循的命名约定。变量，也称为标识符，可以以 A-Z、a-z 或下划线之间的任何字母开头命名。然后可以跟随任意数量的数字或字母数字字符。

必须注意的是，某些特殊字符，如%，@，#，-和!在 Python 中是保留的，不能与变量一起使用。

# Python 关键字

**关键字**，顾名思义，是某种语言实现中具有预定义含义的特定保留字。在其他语言中，我们通常不能使用与关键字相同的名称来命名我们的变量，但 Python 是一个略有不同的情况。尽管我们不应该使用与关键字保留相同的名称来命名变量或标识符，即使我们这样做，程序也不会抛出任何错误，我们仍然会得到一个输出。让我们尝试通过传统的 C 程序和等效的 Python 脚本来理解这一点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/e3862155-a723-4571-abb9-4c60f2a57f5c.png)

应该注意的是，这是一个简单的 C 程序，我们在其中声明了一个整数，并使用`int`标识符来标识它，随后我们简单地打印`hello world`。

然而，当我们尝试编译程序时，它会抛出编译错误，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/334cc30b-eb1a-4cb2-a891-6614441abc6a.png)

让我们尝试在 Python shell 中做同样的事情，看看会发生什么：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/975e7b89-e7e4-4874-89ea-4c1768baf01c.png)

可以看到，当我们用名称`int`和`str`声明变量时，程序没有抛出任何错误。尽管`int`和`str`都是 Python 关键字，在前面的情况下，我们看到用名称`int`声明的变量保存了一个字符串值，而用`str`类型声明的变量保存了一个`int`值。我们还看到了一个普通变量`a`，它是从`int`类型转换为`string`类型。由此可以确定，我们可以在 Python 中使用保留字作为变量。这样做的缺点是，如果我们要使用关键字作为变量或标识符，我们将覆盖这些保留字所具有的实际功能。当我们在程序范围内覆盖它们的实际行为时，它们将遵循更新或覆盖的功能，这是非常危险的，因为这将使我们的代码违反 Python 的约定。这应该始终被避免。

让我们扩展前面的例子。我们知道`str()`是一个内置的 Python 函数，其目的是将数值数据类型转换为字符串类型，就像我们对变量`a`所看到的那样。然而，后来我们重写了它的功能，并且在我们的程序范围内，我们将其分配给了一个整数类型。现在，在程序范围内的任何时间点，如果我们尝试使用`str`函数将数值类型转换为`string`，解释器将抛出一个错误，说`int`类型变量不能用作方法，或者它们不可调用，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/88a7a2cd-885c-4dc5-ae8e-0865c9ca544b.png)

对于`int`方法也是如此，我们将不再能够使用它将字符串转换为其等效的整数。

现在，让我们看看 Python 中还有哪些类型的关键字，我们应该尽量避免将它们用作我们的变量名。有一种很酷的方法可以通过 Python 代码本身来做到这一点，这让我们可以在终端窗口中打印 Python 关键字：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/6e6f151e-b64d-4871-a95a-ab0b78b4869c.png)

`import`语句用于在 Python 中导入库，就像我们在 Java 中导入包时一样。我们将在以后的章节中详细介绍使用导入和循环。现在，我们将看看不同的 Python 关键字的含义：

+   `false`: 布尔`false`运算符。

+   `none`: 这相当于其他语言中的`Null`。

+   `true`: 布尔`true`运算符。

+   `and`: 逻辑`and`，可以与条件和循环一起使用。

+   `as`: 这用于为我们导入的模块分配别名。

+   `assert`: 这用于调试代码的目的。

+   `break`: 这会退出循环。

+   `class`: 这用于声明一个类。

+   `continue`: 这是传统的`continue`语句，用于循环，可以用于继续执行循环。

+   `def`：用于定义函数。每个 Python 函数都需要在`def`关键字之前。

+   `del`：用于删除对象

+   `elif`：条件`else...if`语句。

+   `else`：条件`else`语句。

+   `except`：用于捕获异常。

+   `finally`：与异常处理一起使用，作为我们清理资源的最终代码块的一部分。

+   `for`：传统的 for 循环声明关键字。

+   `global`：用于声明和使用全局变量。

+   `if`：条件`if`语句。

+   `import`：用于导入 Python 库、包和模块。

+   `in`：用于在 Python 字符串、列表和其他对象之间进行搜索。

+   `is`：用于测试对象的标识。

+   `lambda`：与 Lambda 函数一起使用。

+   `nonlocal`：用于声明嵌套函数中不是其本地变量的变量。

+   `not`：条件运算符。

+   `or`：另一个条件运算符。

+   `pass`：在 Python 中用作占位符。

+   `raise`：用于在 Python 中引发异常。

+   `return`：用于从函数返回。

+   `try`：与异常处理一起使用的传统`try`关键字。

+   `while`：与`while`循环一起使用。

+   `with`：用于文件打开等。

+   `yield`：与生成器一起使用。

+   `from`：与相对导入一起使用。

在本书中，我们将学习此列表中提到的所有关键字。

# Python 数据类型

像任何其他编程语言一样，Python 也有标准数据类型。在本节中，我们将探讨 Python 提供给我们使用的各种强大的数据类型。

# 数字

**数字**，顾名思义，涵盖了所有数字数据类型，包括整数和浮点数据类型。在本章的前面，我们看到要使用整数或浮点数，我们可以简单地声明变量并赋予整数或浮点值。现在，让我们编写一个适当的 Python 脚本，并探索如何使用数字。将脚本命名为`numbers.py`，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/8126ea5f-c958-432d-a21e-e104ab71827f.png)

前面的屏幕截图显示了一个简单的 Python 脚本，该脚本将整数与浮点数相加，然后打印总和。要运行脚本，我们可以输入`python3 numbers.py`命令，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/050cfa73-4361-4b66-9354-5975f58a6faa.png)

您可能已经注意到脚本开头的命令是`#! /usr/bin/python`。这行的作用是使您的代码可执行。在脚本的权限已更改并且已被设置为可执行之后，命令表示如果尝试执行此脚本，则我们应该继续使用`/usr/bin/python3`路径中放置的`python3`来执行它。可以在以下示例中看到这一点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/56bba27d-5bf8-4bab-a6e5-cefbbbc32293.png)

如果我们观察`print`命令，我们可以看到字符串格式化程序是`%s`。要用实际值填充它，需要将第二个参数传递给`print`函数：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/c97aee4e-553c-4f0a-a5ca-adfad91fdb6d.png)

要将字符串转换为其等效的整数或浮点值，我们可以使用内置的`int()`和`float()`函数。

# 字符串类型

我们知道字符串是字符的集合。在 Python 中，字符串类型属于序列类别。字符串非常强大，有许多方法可用于执行字符串操作。让我们看一下下面的代码片段，它向我们介绍了 Python 中的字符串。在 Python 中，字符串可以在单引号和双引号中声明：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/22c427ea-efbe-4418-9cff-bc1b0a78118e.png)

在上面的代码中，我们只是声明了一个名为`my_str`的字符串，并将其打印在控制台窗口上。

# 字符串索引

必须注意的是，在 Python 中可以将字符串视为字符序列。字符串可以被视为字符列表。让我们尝试打印字符串的各个索引处的字符，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d5ec70ee-4290-461e-b965-01c74a3164cc.png)

在索引 `0` 处，字符 `0` 被打印。在索引 `10` 处，我们有一个空格，而在索引 `5` 处，我们有字母 `m`。需要注意的是，序列在 Python 中以起始索引 `0` 存储，字符串类型也是如此。

# 通过方法和内置函数进行字符串操作

在本节中，我们将看看如何比较两个字符串，连接字符串，将一个字符串复制到另一个字符串，并使用一些方法执行各种字符串操作。

# replace( ) 方法

`replace` 方法用于执行字符串替换。它返回一个带有适当替换的新字符串。`replace` 方法的第一个参数是要在字符串中替换的字符串或字符，而第二个参数是要替换的字符串或字符：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/1fc71b45-8d4d-4b3f-a0a5-3457356c2a6c.png)

在前面的例子中，我们可以看到原始字符串中的 `!` 被 `@` 替换，并返回一个带有替换的新字符串。需要注意的是，这些更改实际上并没有应用到原始字符串上，而是返回了一个带有适当更改的新字符串。这可以在下一行中验证，我们打印原始字符串，旧的未更改值 `Welcome to python strings !` 被打印出来。这背后的原因是 Python 中的字符串是不可变的，就像在 Java 中一样。这意味着一旦声明了一个字符串，通常就不能修改。然而，并非总是如此。让我们尝试更改字符串，并这次尝试捕获最初声明的字符串 `my_str` 中的修改，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/149b832c-b606-4089-8a7d-eec5ae01da93.png)

在前面的代码中，我们能够修改原始字符串，因为我们从我们之前声明的字符串 `my_str` 中的 `replace` 方法中得到了新返回的字符串。这可能与我们之前说的相矛盾。让我们看看在调用 `replace` 方法之前和之后发生了什么：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/b3244b6c-200a-4d48-951b-4fda8b1b2d53.png)

将 `!` 替换为 `@` 后，结果如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/35b0c002-e5b1-4fd5-9ed7-bfc0ae446d32.png)

在前面的两个示例中可以看到，在调用 `replace` 方法之前，`my_str` 字符串引用指向包含 `!` 的实际对象。一旦 `replace()` 方法返回一个新字符串，并且我们用新返回的对象更新了现有的字符串变量，旧的内存对象并没有被覆盖，而是创建了一个新的对象。程序引用现在指向新创建的对象。早期的对象在内存中，并没有任何引用指向它。这将在以后的阶段由垃圾收集器清理。

另一件我们可以做的事情是尝试改变原始字符串中任何位置的任何字符。我们已经看到字符串字符可以通过它们的索引访问，但是如果我们尝试在任何特定索引处更新或更改字符，就会抛出异常，并且不允许进行操作，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/13e222d0-bd51-47f4-92e8-e8c83e701e31.png)

默认情况下，`replace()` 方法会替换目标字符串中替换字符串的所有出现。然而，如果我们只想替换目标字符串中的一个或两个出现，我们可以向 `replace()` 方法传递第三个参数，并指定我们想要进行的替换次数。假设我们有以下字符串：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/f75a0ce4-c66a-4cce-b046-9fdf34154f94.png)

如果我们只想要`!`字符的第一个出现变成`@`，并且我们希望其余部分保持不变，可以按照以下方式实现：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/c3588b54-8a51-4fd7-aef9-019c3524b426.png)

# 子字符串或字符串切片

获取字符串的一部分是我们在日常字符串操作中经常遇到的常见练习。诸如 C 或 Java 之类的语言为我们提供了专用方法，如`substr(st_index,end_index)`或`subString(st_index,end_index)`。在 Python 中执行子字符串操作时，没有专用方法，但我们可以使用切片。例如，如果我们希望获得原始`my_str`字符串的前四个字符，我们可以通过使用`my_str[0:4]`等操作来实现，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/c6aeed0e-02f3-469e-b7ce-9294498e9ca3.png)

同样，切片操作返回一个新的字符串，而不会对原始字符串进行更改。此外，值得在这里理解的是，切片发生在 n-1 个字符上，其中`n`是作为第二个参数指定的上限，即在我们的例子中是四。因此，实际的子字符串操作将从索引`0`开始，到索引`3`结束，从而返回字符串`Welc`。

让我们看一些切片的更多例子：

+   要从索引`4`获取整个字符串，按照以下方式操作：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/265fb596-8570-4a43-a5bd-ac71c3cede1c.png)

+   要从开头获取到索引`4`的字符串，请执行以下操作：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/e980939e-4bac-4535-80d2-61117ec28703.png)

+   要使用切片打印整个字符串，请执行以下操作：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/8663fe94-e20c-4356-bed8-c2368b4f43f3.png)

+   要打印步长为`2`的字符，按照以下方式操作：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/6f045c64-fcec-4fac-a464-6b0d2851675d.png)

+   要打印字符串的反向，请执行以下操作：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/8320ea2f-87aa-493d-90df-6ca0ac460748.png)

+   打印字符串的一部分以相反的顺序，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/a9f35a75-da29-4ce9-88b6-d2abb5ab707f.png)

# 字符串连接和复制

`+`是 Python 中用于连接两个字符串的连接运算符。与往常一样，连接的结果是一个新的字符串，除非我们获得更新后的字符串，否则更新将不会反映在原始字符串对象上。`+`运算符在用于字符串类型时内部被重载以执行对象的连接。当它用于数值数据类型时，也用于两个数字的加法，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/9bbe9d09-0f6f-4be5-8b84-293154494d00.png)

有趣的是，Python 还支持另一个操作符，当与字符串数据类型一起使用时会被重载。它不是执行常规操作，而是执行原始操作的变体，以便可以在字符串数据类型之间复制功能。在这里，我们谈论的是乘法操作符`*`。它通常用于执行数值数据类型的乘法，但当它用于字符串数据类型时，它执行的是复制操作。这在以下代码片段中显示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/0dc12321-1ec0-449b-b40e-d18c32ed580e.png)

在前面的情况下，乘法运算符实际上将存储在变量`c`中的`Hello world`字符串复制了五次，正如我们在表达式中指定的那样。这是一个非常方便的操作，可以用来生成模糊负载，我们将在本书的后面章节中看到。

# strip()，lstrip()和 rstrip()方法

`strip`方法实际上是用于从输入字符串中去除空格。默认情况下，`strip`方法将从字符串的左右两侧去除空格，并返回一个新的字符串，其中前导和尾随两侧都没有空格，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/521462f8-9528-4dd3-8432-3c961ce9e0b1.png)

然而，如果我们只想去掉左边的空格，我们可以使用`lstrip()`方法。同样，如果我们只想去掉右边的空格，我们可以使用`rstrip()`方法。如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/48b30334-a5c3-422f-a28e-dddd1dc5e34a.png)

# split()方法

`split`方法，顾名思义，用于在特定分隔符上拆分输入字符串，并返回包含已拆分单词的列表。我们将很快更详细地了解列表。现在，让我们看一下以下示例，其中我们有员工的姓名、年龄和工资，用逗号分隔在一个字符串中。如果我们希望分别获取这些信息，我们可以在`,`上执行拆分。`split`函数将第一个参数作为要执行`split`操作的分隔符：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/54ee7d41-e315-4acf-9ef5-30f8a364999c.png)

默认情况下，`split`操作是在空格上执行的，即，如果未指定分隔符。可以如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/3b721965-73f1-443e-ad86-80eb51ad3af0.png)

# find()、index()、upper()、lower()、len()和 count()方法

`find()`函数用于在目标字符串中搜索字符或字符串。如果找到匹配，此函数返回字符串的第一个索引。如果找不到匹配，则返回`-1`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/ac610f73-f88d-4f46-bd14-e0e7ca7c9db6.png)

`index()`方法与`find()`方法相同。如果找到匹配，它返回字符串的第一个索引，并在找不到匹配时引发异常：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/bacda854-0567-4485-b282-0fdab63f915a.png)

`upper()`方法用于将输入字符串转换为大写字母，`lower()`方法用于将给定字符串转换为小写字母：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/1d9cd7e7-9c5c-46da-8404-ced350f2a170.png)

`len()`方法返回给定字符串的长度：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/76a2b0cf-b6c7-4672-ae1a-eb1414843544.png)

`count()`方法返回我们希望在目标字符串中计算的任何字符或字符串的出现次数：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/6d5e9730-57b1-4b13-b8dd-4ab28b9a0255.png)

# `in`和`not in`方法

`in`和`not in`方法非常方便，因为它们让我们可以快速在序列上进行搜索。如果我们希望检查目标字符串中是否存在或不存在某个字符或单词，我们可以使用`in`和`not in`方法。这将返回`True`（如果单词存在）和`False`（如果不存在）：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/13b72441-6e6c-4f4e-8558-7a125dfe3a87.png)

# endswith()、isdigit()、isalpha()、islower()、isupper()和 capitalize()方法

`endswith()`方法检查给定字符串是否以我们传递的特定字符或单词结尾：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/3c680da9-5f9b-4341-8687-c510267c9191.png)

`isdigit()`方法检查给定的字符串是否为数字类型：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/a1b64dd8-ef60-4a1a-bdc3-3b060d1a3fc4.png)

`isalpha()`方法检查给定的字符串是否为字母字符类型：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/588ee101-e6b4-4c46-8893-7fb5184b26e6.png)

`islower()`方法检查字符串是否为小写，而`isupper()`方法检查字符串是否为大写。`capitalize()`方法将给定字符串转换为句子大小写：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/4b918755-df2c-4319-ba79-94af07d7cd07.png)

# 列表类型

Python 没有数组类型，而是提供了列表数据类型。Python 列表也属于序列类，并提供了广泛的功能。如果你来自 Java、C 或 C++背景，你可能会发现 Python 列表与这些语言提供的数组和列表类型略有不同。在 C、C++或 Java 中，数组是相似数据类型的元素集合，Java 数组列表也是如此。但在 Python 中情况不同。在 Python 中，列表是可以是同质和异质数据类型的元素集合。这是使 Python 列表强大、健壮且易于使用的特点之一。在声明时，我们也不需要指定 Python 列表的大小。它可以动态增长以匹配它包含的元素数量。让我们看一个使用列表的基本示例：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/80849a5f-d291-4d12-baf5-f3968064f41f.png)

Python 中的列表从索引`0`开始，可以根据索引访问任何项，如前面的屏幕截图所示。前面的列表是同质的，因为所有元素都是字符串类型。我们也可以有一个异质列表，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/98d236da-817a-4518-803a-e59395b2c770.png)

目前，我们正在手动打印列表元素。我们可以很容易地用循环迭代它们，稍后我们将探讨这一点。现在，让我们试着理解 Python 中可以对列表结构执行哪些操作。

# 切片列表

**切片**是一种允许我们从序列和列表中提取元素的操作。我们可以对列表进行切片，以提取我们感兴趣的部分。需要再次注意的是，切片的索引是基于 0 的，并且最后一个索引始终被视为`n-1`，其中 n 是指定的最后一个索引值。要从列表中切片出前五个和后五个元素，我们可以执行以下操作：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/f71326a4-1b4c-4fe4-a8a6-2ffabe019d33.png)

让我们看一些列表切片的示例及其结果：

+   要获取从索引`4`开始的列表，请执行以下操作：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/46a125ca-dab4-473c-8796-8b0fe756da1c.png)

+   要获取从开头到索引`4`的列表元素，请执行以下操作：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/3c3ea6df-f4f2-4278-b6ea-6b775b7969bf.png)

+   要使用切片打印整个列表，请执行以下操作：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d7bf51a3-9ed3-4f24-a1a0-8890dfba879d.png)

+   要打印步长为`2`的列表元素，请执行以下操作：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/8fd8c671-7792-46f7-93e6-b3a979605b0f.png)

+   要打印列表的反向，请执行以下操作：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/69c36743-6554-4c54-91b7-395d2a5d1e10.png)

+   要以相反的顺序打印列表的一部分，请执行以下操作：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/b490c167-0ab4-4ed5-bb00-1751307d7b46.png)

+   向`list-append()`添加新元素：`append()`方法用于向列表添加元素，要添加的元素作为参数传递给`append()`方法。要添加的这些元素可以是任何类型。除了数字或字符串之外，元素本身可以是一个列表：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/6cf0eaa7-81d0-43f2-b4e6-bd9c147ac5f0.png)

我们可以看到在前面的例子中，我们使用`append()`方法向原始列表添加了三个元素`6`、`7`和`8`。然后，我们实际上添加了另一个包含三个字符的列表，这个列表会完整地存储在原始列表中。可以通过指定`my_list[8]`索引来访问它们。在前面的例子中，新列表完整地添加到原始列表中，但没有合并。

# 合并和更新列表

在 Python 中，可以通过两种方式进行列表合并。首先，我们可以使用传统的`+`运算符，之前我们用来连接两个字符串。当用于列表对象类型时，它也是一样的。另一种方法是使用`extend`方法，它将新列表作为要与现有列表合并的参数。这在以下示例中显示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/6bc7138d-5445-493a-b429-ad348042890f.png)

要更新列表中的元素，我们可以访问其索引，并为我们希望更新的任何元素添加更新后的值。例如，如果我们希望将字符串`Hello`作为列表的第 0 个元素，可以通过将第 0 个元素分配给`Hello`值来实现`merged[0]="hello"`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/81dc9bf3-7d05-4dc5-a2fe-7669da40f460.png)

# 复制列表

我们已经看到 Python 变量只是对实际对象的引用。对于列表也是如此。因此，操作列表会有点棘手。默认情况下，如果我们通过简单地使用`=`运算符将一个列表变量复制到另一个列表变量，它实际上不会创建列表的副本或本地副本 - 相反，它只会创建另一个引用，并将新创建的引用指向相同的内存位置。因此，当我们对复制的变量进行更改时，原始列表中也会反映相同的更改。在下面的示例中，我们将创建新的隔离副本，其中对复制的变量的更改不会反映在原始列表中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/a0c195ed-49bc-4dec-9772-0f94c573644a.png)

现在，让我们看看如何创建现有列表的新副本，以便对新列表的更改不会对现有列表造成任何更改：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/fd4396e7-54fa-4227-b771-f9708b988c64.png)

创建原始列表的隔离副本的另一种方法是利用 Python 中提供的`copy`和`deepcopy`函数。浅复制构造一个新对象，然后将该对象的*引用*插入到原始列表中找到的对象中。另一方面，*深复制*构造一个新的复合对象，然后递归地插入到原始列表中找到的对象的*副本*：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/cfa57b95-bd7f-4fdd-8f97-37431ba47755.png)

# 从列表中删除元素

我们可以使用`del`命令删除列表中的元素或整个列表。`del`命令不返回任何内容。我们也可以使用`pop`方法从列表中删除元素。`pop`方法将要删除的元素的索引作为参数：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/41be39ab-2b4f-4483-acdd-7e1a929a6dae.png)

整个列表结构可以被删除如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/52929047-d566-4cd2-b9de-96626a871fa0.png)

# 使用 len()、max()和 min()进行复制

乘法运算符`*`，当应用于列表时，会导致列表元素的复制效果。列表的内容将根据传递给复制运算符的数字重复多次：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/aa5f4c95-bef4-46f8-b4c7-d54df712d39f.png)

`len()`方法给出了 Python 列表的长度。`max()`方法返回列表的最大元素，而`min()`方法返回列表的最小元素：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/cb322b31-3b37-4f10-a95c-49e17ea5ce9c.png)

我们也可以在字符类型上使用`max`和`min`方法，但是不能在包含混合或异构类型的列表上使用它们。如果这样做，将会得到一个异常，说明我们正在尝试比较数字和字符：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/edea29fb-7ba5-4650-918a-97c0eaf37001.png)

# in 和 not in

`in`和`not in`方法是 Python 中的基本操作，可以用于任何序列类型。我们之前看到了它们如何与字符串一起使用，我们用它们来搜索目标字符串中的字符串或字符。`in`方法返回`true`，如果搜索成功则返回`false`。`not in`方法则相反。执行如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/50142294-3c9d-4e79-b4f8-70ca12912977.png)

# Python 中的元组

Python 元组与 Python 列表非常相似。不同之处在于它是一个只读结构，因此一旦声明，就不能对元组的元素进行修改。Python 元组可以用如下方式使用：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/deb53b7e-f5fc-4639-9413-03355effa0d6.png)

在前面的代码中，我们可以看到我们可以像访问列表一样访问元组，但是当我们尝试更改元组的任何元素时，它会抛出一个异常，因为元组是只读结构。如果我们执行我们在列表上执行的操作，我们会发现它们与元组的工作方式完全相同：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/f4f04740-11d2-47d7-b642-86bded48a6b3.png)

如果元组中只有一个元素，则必须使用尾随逗号声明。如果在声明时不添加逗号，则将根据元组的元素将其解释为数字或字符串数据类型。以下示例更好地解释了这一点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/aadff71a-28ef-4377-803c-3790e9c065a0.png)

元组可以转换为列表，然后可以进行如下操作：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d2a752cc-1c18-412a-9de8-483ee1ba9b8e.png)

# Python 中的字典

**字典**是非常强大的结构，在 Python 中被广泛使用。字典是一种键值对结构。字典键可以是唯一的数字或字符串，值可以是任何 Python 对象。字典是可变的，可以就地更改。以下示例演示了 Python 中字典的基础知识：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/026f5772-da80-4c06-b866-5ffa45f665af.png)

Python 字典可以在花括号内声明。每个键值对之间用逗号分隔。应该注意，键必须是唯一的；如果我们尝试重复键，旧的键值对将被新的键值对覆盖。从前面的例子中，我们可以确定字典键可以是字符串或数字类型。让我们尝试在 Python 中对字典进行各种操作：

+   **使用键检索字典值**：可以通过字典键的名称访问字典值。如果不知道键的名称，可以使用循环来遍历整个字典结构。我们将在本书的下一章中介绍这一点： 

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/3800b1fd-c087-4497-9eb2-70d32b55f8b2.png)

这是打印字典值的许多方法之一。但是，如果我们要打印值的键在字典中不存在，我们将收到一个找不到键的异常，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/9be2648e-13c9-4097-b0ce-04c7dcbf929d.png)

有一种更好的方法来处理这个问题，避免这种类型的异常。我们可以使用字典类提供的`get()`方法。`get()`方法将键名作为第一个参数，如果键不存在，则将默认值作为第二个参数。然后，如果找不到键，将返回默认值，而不是抛出异常。如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/5884c24f-f3c4-44dc-9b79-ca9f0e412392.png)

在前面的例子中，当实际字典`dict1`中存在`k1`键时，将返回`k1`键的值，即`v1`。然后，搜索了`k0`键，但最初不存在。在这种情况下，不会引发异常，而是返回`False`值，表明实际上不存在这样的键`K0`。请记住，我们可以将任何占位符作为`get()`方法的第二个参数，以指示我们要搜索的键的缺失。

+   **向字典添加键和值**：一旦声明了字典，在代码的过程中可能会有许多情况，我们希望修改字典键或添加新的字典键和值。可以通过以下方式实现。如前所述，字典值可以是任何 Python 对象，因此我们可以在字典中的值中有元组、列表和字典类型：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/425afb59-cd2f-4d18-966d-8fa9b01a11a8.png)

现在，让我们将更复杂的类型添加为值：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/228b2391-23bd-460f-85e0-6e045e2b03ed.png)

可以通过它们的键正常检索这些值，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/a68a6a98-a518-4c70-a02f-c8d7171aa4f4.png)

+   **扩展字典内容**: 在前面的例子中，我们将一个字典添加为现有字典的值。我们现在将看到如何将两个字典合并为一个公共或新字典。可以使用`update()`方法来实现这一点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/7474e4c8-1dc5-4086-a8df-f911e871d9c0.png)

+   **`Keys()`**：要获取所有字典键，我们可以使用`keys()`方法。这将返回字典键的类实例：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/85740215-8770-4e17-b499-4f91cae8fbb8.png)

我们可以看到，keys 方法返回一个`dict_keys`类的实例，它保存了字典键的列表。我们可以将其强制转换为列表类型，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/86da945a-0ecb-44f2-a367-d6e6fe617918.png)

+   **`values()`**：`values()`方法返回字典中存在的所有值：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/3c4ba243-4241-4d6c-b0c8-9bccbe80de5d.png)

+   **`Items()`**：这个方法实际上是用来遍历字典键值对的，因为它返回一个包含元组列表的列表类实例。每个元组有两个条目，第一个是键，第二个是值：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/6c4ee05b-2d21-4c19-b018-492110271041.png)

我们也可以将返回的类实例转换为元组、列表元组或列表类型。这样做的理想方式是遍历项目，我们稍后将在循环时看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/b526057b-5f0d-471b-9256-da3477b45944.png)

+   **`in`**和**`not in`**：`in`和`not in`方法用于查看字典中是否存在键。默认情况下，`in`和`not in`子句将搜索字典键，而不是值。看下面的例子：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/8423b4f3-adbc-448d-a657-4ba3d67e5264.png)

+   **存储顺序**：默认情况下，Python 字典是无序的，这意味着它们在内部存储的顺序与我们定义的顺序不同。这是因为字典存储在称为**哈希表**的动态表中。由于这些表是动态的，它们的大小可以增加和缩小。内部发生的情况是计算键的哈希值并将其存储在表中。键进入第一列，而第二列保存实际值。让我们看下面的例子来更好地解释这一点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/5df607af-fdcd-462d-bfe9-23375ad29fd9.png)

在前面的例子中，我们声明了一个名为`a`的字典，第一个键为`abc`，第二个键为`abcd`。然而，当我们打印值时，我们可以看到`abcd`在`abc`之前存储。为了解释这一点，让我们假设字典内部存储的动态表或哈希表的大小为`8`。

正如我们之前提到的，键将被存储为哈希值。当我们计算`abc`字符串的哈希并以模 8 的方式进行除法时，即表大小为`8`，我们得到结果`7`。如果我们对`abcd`做同样的操作，我们得到结果`4`。这意味着哈希`abcd`将被存储在索引`4`，而哈希`abc`将被存储在索引`7`。因此，在列表中，我们得到`abcd`在`abc`之前列出的原因是这样的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/e5c7a7d8-19a0-47de-85ee-17aa4f778632.png)

在`hash(key)%table_size`操作后，可能会出现两个键到达相同值的情况，这称为**冲突**。在这种情况下，首先插槽的键是先存储的键。

+   **`sorted()`**：如果我们希望字典根据键排序，可以使用内置的 sorted 方法。这可以调整为返回一个元组列表，每个元组在第 0 个索引处有一个键，第 1 个索引处有一个值：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/ccb9d9fc-f6fc-4fe5-98d0-95e24576990c.png)

+   **删除元素**：我们可以使用传统的`del`语句来删除任何字典项。当我们说删除时，我们指的是删除键和值。字典项成对工作，因此删除键也会删除值。删除条目的另一种方法是使用`pop()`方法并将键作为参数传递。这在以下代码片段中显示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/b723bc4c-f7de-45c6-87d3-8bc7252f83b7.png)

# Python 运算符

Python 中的运算符是可以对表达式进行算术或逻辑操作的东西。运算符操作的变量称为**操作数**。让我们试着了解 Python 中提供的各种运算符： 

+   **算术**：

| **函数** | **示例** |
| --- | --- |
| 加法 | `a + b` |
| 减法 | `a - b` |
| 否定 | `-a` |
| 乘法 | `a * b` |
| 除法 | `a / b` |
| 取模 | `a % b` |
| 指数 | `a ** b` |
| 地板除法 | `a // b` |

+   **赋值**：

+   `a = 0`评估为`a=0`

+   `a +=1`评估为`a = a + 1`

+   `a -= 1`评估为`a = a + 1`

+   `a *= 2`评估为`a = a * 2`

+   `a /= 5`评估为`a = a / 5`

+   `a **= 3`评估为`a = a ** 3`

+   `a //= 2`评估为`a= a // 2`（地板除法 2）

+   `a %= 5`评估为`a= a % 5`

+   **逻辑运算符**：

+   **`and`**：`True`：如果两个操作数都为`true`，则条件变为`true`。例如，`(a and b)`为`true`。

+   **`or`**：`True`：如果两个操作数中有任何一个非零，则条件变为`true`。例如，`(a or b)`为`true`。

+   **`not`**：`True`：用于颠倒其操作数的逻辑状态。例如，`not (a and b)`为`false`。

+   **位运算符**：

| **函数** | **示例** |
| --- | --- |
| `and` | `a & b` |
| `or` | `a &#124; b` |
| `xor` | `a ^ b` |
| `反转` | `~ a` |
| `右移` | `a >> b` |
| `左移` | `a << b` |

# 总结

在本章中，我们讨论了 Python 的基础知识，并探索了该语言的语法。这与您以往可能学过的语言并没有太大不同，例如 C、C++或 Java。但是，与同行相比，它更容易使用，并且在网络安全领域非常强大。本章阐述了 Python 的基础知识，并将帮助我们进步，因为一些数据类型，如列表、字典、元组和字符串在本书的整个过程中都被大量使用。

在下一章中，我们将学习条件和循环，并看看循环如何与我们迄今为止学习的数据类型一起使用。

# 问题

1.  Python 是开源的吗？如果是，它与其他开源语言有何不同？

1.  谁管理 Python 并致力于进一步的功能增强？

1.  Python 比 Java 快吗？

1.  Python 是面向对象的还是函数式的？

1.  如果我对任何编程语言几乎没有经验，我能快速学会 Python 吗？

1.  Python 对我有什么好处，作为一名网络安全工程师？

1.  我是一名渗透测试员-为什么我需要了解人工智能和机器学习？


# 第二章：构建 Python 脚本

本章将涵盖所有编程语言的核心概念。这包括条件语句、循环、函数和包。我们将看到这些概念在 Python 中与其他编程语言中基本相同，只是在一些语法上有所不同。但语法只需要练习；其他一切都会自动顺利进行。本章我们将要涵盖的主题如下：

+   条件语句

+   循环

+   函数

+   模块和包

+   理解和生成器

# 技术要求

确保你具备以下继续学习所需的先决条件：

+   一台工作的计算机或笔记本电脑

+   Ubuntu 操作系统（最好是 16.04）

+   Python 3.x

+   一个工作的互联网连接

# 缩进

如果你来自 Java、C 或 C++等语言的背景，你可能熟悉使用花括号来分组逻辑连接语句的概念。然而，在 Python 中情况并非如此。相反，逻辑连接的语句，包括类、函数、条件语句和循环，都是使用缩进来分组的。缩进可以使代码保持清晰易读。我们将在接下来的部分中更详细地探讨这一点。但现在，让我们和花括号说再见。我建议你使用制表符进行缩进，因为在每一行输入相同数量的空格会非常耗时。

# 条件语句

与所有其他语言一样，Python 使用条件语句来执行条件操作。Python 支持的条件语句如下：

+   `if`条件

+   `if...else`条件

+   `else...if`条件梯，在 Python 中称为`elif`

Python 不支持`switch`语句。

# if 条件

`if`条件或`if`语句接受一个语句，并在评估该语句后返回布尔值`True`或`False`。如果条件返回`True`，则执行`if`语句后面的代码（同样缩进）。如果语句/条件评估为`False`，那么如果有`else`代码块，则执行`else`代码块，否则执行`if`块后面的代码，因此`if`块实际上被跳过。让我们看看`if`代码的运行情况。

从现在开始，我们将看一下脚本是如何工作的。我们将要么创建脚本文件，要么进行练习。因此，请继续在 gedit 或你选择的任何编辑器上创建一个名为`if_condition.py`的文件。或者，我们可以在终端中输入`gedit if_condition.py`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/aa9f2b2d-6c1e-4a9c-9f32-6256eeea1e66.png)

然后我们输入以下代码：

```py
a=44
b=33
if a > b:
    print("a is greater") 
print("End")
```

现在，为了运行这个脚本，我们可以在终端中简单地输入`python3.5 if_condition.py`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/1312d095-dbf5-4364-b1b7-5b7579c8056e.png)

Python 的`print`方法默认会在要打印的字符串后添加`\n`，这样我们可以看到两个不同行的输出。请注意`if`语句的语法如下：

`if <条件>：然后缩进的代码`

我们是否使用括号与条件是由我们决定的。正如你所看到的，条件评估为`True`，所以打印了`a is greater`。对于 Python 中的`if`条件，任何不评估为零（`0`）、`False`、`None`或`空`的东西都会被视为`True`，并且执行`if`语句后面的代码。

让我们看一个`if`条件与`and...or`和`and...not`逻辑运算符结合的另一个例子。

让我们创建另一个名为`if_detailed.py`的文件，并输入以下代码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/7c54677b-14e2-455c-9d44-5ca468c56ff8.png)

你可能已经注意到，在文件的开头，我们有一个语句，写着`#! /usr/bin/python3.5`。这意味着我们不必每次执行代码时都输入`python3.5`。它指示代码使用位于`/usr/bin/python3.5`的程序来执行它，每次作为可执行文件执行时。我们需要改变文件的权限使其可执行。这样做，然后按照以下方式执行代码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/7e5e11fc-3482-487e-bb75-e91fda5623a7.png)

产生的输出是不言自明的。正如我之前提到的，任何不等于`0`、`False`、`None`或`empty`的东西都被视为`True`，并且执行`if`块。这解释了为什么前三个`if`条件被评估为`True`并且消息被打印出来，但第四个消息没有被打印。从第 19 行开始，我们使用了逻辑运算符。在 Python 中，合取操作由`and`运算符执行，这与我们在 C、C++和 Java 中使用的`&&`相同。对于短路布尔运算符，在 Python 中我们有`or`关键字，它与 C、C++和 Java 中的`||`相同。最后，`not`关键字在 Python 中提供否定，就像其他语言中的`!`一样。

应该注意，在 Python 中，`null`字节字符由保留关键字`None`表示，这与 Java 或 C#等语言中的`null`相同。

# `if...else`条件

`if...else`条件在任何其他语言中基本上是一样的。如果`if`条件评估为`True`值，那么缩进在`if`下面的代码块将被执行。否则，缩进在`else`块下面的代码块将被执行：

```py
a=44
b=66
if a > b:
    print("a is Greater") 
else:
    print("B is either Greater or Equal")
print("End")
```

让我们创建一个名为`if_else.py`的文件，并看看如何使用它：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/5599335c-aa75-4ca0-84cb-e3fc8080ee70.png)

这里的输出也是不言自明的。在这段代码中，我们探讨了一些位运算符与`if...else`代码结构一起使用的情况。我们还使用了变量，这些变量将被打印出来。`%s`是一个占位符，并指定`%s`的值应该被字符串变量替换，其值将在字符串结束后立即出现。如果我们有多个值要替换，它们可以作为一个元组传递，如`%(val1,val2,val3)`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/adaa4be6-332d-470f-8ae1-b6d99a3a6bac.png)

# `if...elif`条件

`if...elif`梯，在其他编程语言中如 C、C++和 Java 中被称为**if...else if**，在 Python 中具有相同的功能。`if`条件让我们在代码的`else`部分旁边指定一个条件。只有条件为`true`时，才会执行条件语句后面的部分：

```py
a=44
b=66
if a > b:
    print("a is Greater") 
elif b > a:
    print("B is either Greater or Equal")
else:
    print("A and B are equal")
print("End")
```

必须注意的是，前面代码片段中的第三个`else`是可选的。即使我们不指定它，代码也能正常工作：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/ee775bc5-f579-4818-b1b7-e52d557c3560.png)

让我们创建一个名为`if_el_if.py`的文件，并看看它如何使用：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/2676e133-5cb3-4a20-85c9-3a22b38122d7.png)

# 循环

**循环**是每种编程语言都具有的实用工具。借助循环，我们可以执行重复性的任务或语句，如果没有循环，将需要大量的代码行。这在某种程度上违背了首先拥有编程语言的目的。如果你熟悉 Java、C 或 C++，你可能已经遇到了`while`、`for`和`do...while`循环。Python 基本上是一样的，只是它不支持`do...while`循环。因此，我们将在下一节中学习的 Python 中的循环是以下的：

+   `while`循环

+   `for`循环

# while 循环

请记住，当我们在书的第一章讨论列表时，我们提到在 Python 中列表实际上可以包含异构数据类型。列表可以包含整数、字符串、字典、元组，甚至是嵌套列表。这个特性使得列表非常强大，非常容易和直观地使用。让我们看下面的例子：

```py
my_list=[1,"a",[1,2,3],{"k1":"v1"}]
my_list[0] -> 1
my_List[1] -> "a"
my_list[2] -> [1,2,3]
my_list[2][0] -> 1
my_list[2][2] -> 3
my_list[3] -> {"k1":"v1"}
my_list[3]["k1"] -> "v1"
my_list[3].get("k1") -> "v1
```

让我们通过以下代码更仔细地了解`while`循环，我们将其称为`while_loops.py`。我们还将看到如何使用`while`循环迭代列表：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/0e68bc32-414c-496d-adc4-3b226d86b136.png)

代码的第一部分，第 2 到 6 行，描述了`while`循环的简单用法，我们在其中打印了一个语句五次。请注意，为了执行循环指定的条件可以放在括号内或括号外，如第 7 到 10 行所示。

在第 12 行，我们声明了一个包含数字、字符串、浮点数和嵌套列表的列表。然后，在从第 14 行开始的最后一个`while`循环中，我们通过将循环控制变量设置为小于列表长度来迭代列表的元素。在循环中，我们检查列表变量的类型。`if`类型(`1`)返回一个整数类，类型(`a`)返回一个字符串类，类型(`[]`)返回一个列表类。当类型是列表时，我们再次在嵌套的`while`循环中迭代它的元素，并打印每一个，如第 19 到 24 行所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/10ea76e3-b448-4f3b-83b1-94ab2fb0b198.png)

# for 循环

`for`循环在 Python 中被广泛使用，每当我们需要迭代不可改变的列表时，它都是默认选择。在继续使用`for`循环之前，让我们更仔细地了解 Python 中的**迭代**、**可迭代**和**迭代器**这些术语的含义。

# 迭代、可迭代和迭代器

**迭代**：迭代是一个过程，其中一组指令或结构按顺序重复指定次数，或直到满足条件。每次循环体执行时，都称为完成一次迭代。

**可迭代**：可迭代是一个具有`__iter__`方法的对象，它返回一个迭代器。迭代器是任何包含可以迭代的元素序列的对象，然后可以执行操作。Python 字符串、列表、元组、字典和集合都是可迭代的，因为它们实现了`__iter__`方法。看下面的代码片段，看一个例子：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/519d23b0-3a68-4990-8bdc-a9ab679251bb.png)

在上面的代码片段中，我们声明了一个字符串`a`，并将值`hello`放入其中。要查看 Python 中任何对象的所有内置方法，我们可以使用`dir(<object>)`方法。对于字符串，这将返回可以在字符串类型上执行的所有操作和方法。在第二行，第 5 个操作是我们之前提到的`iter`方法。可以看到`iter(a)`返回一个字符串迭代器。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/a0a1f01f-e979-4f87-978e-bad863fc3fa3.png)

同样，列表对象的`iter`方法将返回一个列表迭代器，如前所示。

**迭代器**：迭代器是一个具有`__next__`方法的对象。`next`方法始终返回调用原始`iter()`方法的序列的`next`元素，从索引 0 开始。下面的代码片段中展示了这一点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/56b3b03d-3e4d-46ed-9c14-5e7635670261.png)

正如在字符串和列表的示例中所看到的，迭代器上的`next`方法总是返回我们迭代的序列或对象中的`next`元素。必须注意的是，迭代器只能向前移动，如果我们想让`iter_a`或`list_itr`返回到任何元素，我们必须重新将迭代器初始化为原始对象或序列：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/debc073b-944c-415d-8025-4aad8c31828f.png)

# 更仔细地看一下 for 循环

Python 中的`for`循环超出了其他编程语言中`for`循环的能力。当调用诸如字符串、元组、列表、集合或字典等可迭代对象时，`for`循环内部调用`iter`来获取迭代器。然后，它调用`next`方法来获取可迭代对象中的实际元素。然后，它重复调用 next 直到引发`StopIteration`异常，然后它会在内部处理并将我们从循环中取出。`for`循环的语法如下所示：

```py
for var in iterable:
    statement 1
    statement 2
    statement n
```

让我们创建一个名为`for_loops.py`的文件，它将解释`for`循环的基本用法：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/21f3c53c-8026-4eb0-89c2-584610aaf3bd.png)

在前面的示例中，我们使用了 Python 的 range 函数/方法，它帮助我们实现了传统的`for`循环，我们在其他编程语言（如 C、C++或 Java）中学到的。这可能看起来像`for i =0 ;i < 5 ;i ++`。Python 中的 range 函数需要一个必需参数和两个默认参数。必需参数指定迭代的限制，并且从索引`0`开始，返回数字，直到达到限制，就像代码的第 3 和第 4 行所示的那样。当使用两个参数调用时，第一个参数作为范围的起点，最后一个作为终点，就像我们代码的第 7 和第 8 行所示的那样。最后，当使用三个参数调用`range`函数时，第三个参数作为步长，默认为 1。这在下面的输出和示例代码的第 12 和第 13 行中显示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/52eaf92b-b027-400f-ad61-adc8931dae46.png)

让我们看看另一个`for`循环的例子，我们将用它来迭代 Python 定义的所有可迭代对象。这将使我们能够探索`for`循环的真正威力。让我们创建一个名为`for_loops_ad.py`的文件：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/5899a34e-3c43-477a-b13b-b2fe50d1e557.png)

之前，我们看到了如何从列表、字符串和元组中读取值。在前面的示例中，我们使用`for`循环枚举字符串、列表和字典。我们之前了解到，`for`循环实际上调用可迭代对象的`iter`方法，然后为每次迭代调用`next`方法。这在下面的示例中显示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/c6c41da0-de0e-4976-9ac5-55a9dea1ab52.png)

当我们使用`for`循环迭代 Python 字典时，默认情况下会将字典键返回给我们。当我们在字典上使用`.items()`时，每次迭代都会返回一个元组，其中键在元组的第 0 个索引处，值在第一个索引处。

# Python 中的函数和方法

函数和方法用于设计或制作可以在脚本或其他脚本的整个过程中重复使用的逻辑代码单元。函数实际上构成了代码重用的基础，并为代码结构带来了模块化。它们使代码更清晰，更容易修改。

建议我们总是尝试将逻辑分解为小的代码单元，每个单元都是一个函数。我们应该尽量保持方法的大小在代码行方面尽可能小。

以下代码代表了在 Python 中定义方法的基本语法：

```py
def print_message(message):
    print(message)
    statement 2
    statement 
```

Python 方法在其定义中没有返回类型，就像您在 C、C++或 Java 中看到的那样，例如`void`、`in`、`float`等。Python 方法可能返回值，也可能不返回值，但我们不需要明确指定。方法在 Python 中非常强大和灵活。

应该注意到每个 Python 脚本的默认名称是`main`，并且它被放置在一个全局变量中，可以在整个 Python 上下文中访问，称为`__name__`。我们将在接下来的示例中使用它。

让我们探索使用我们的`method_basics.py`脚本调用方法的各种方式：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/6433781e-b3c0-4444-ac77-972cb6a9b54e.png)

现在让我们将其分解成更小的部分，并尝试理解发生了什么：

+   `print_msg1()`: 这是一个基本的方法，只是在控制台上打印一个字符串。它在第 2 行定义，在第 19 行调用。

+   `print_msg2()`: 这是一个方法，接受变量消息作为参数，然后在屏幕上打印该变量的值。请记住，Python 变量不需要指定类型，因此我们可以将任何数据传递给`message`变量。这是一个接受单个参数的 Python 方法的示例。请记住，参数的类型是 Python 对象，它可以接受传递给它的任何值。输出可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/f707b6e8-aff7-4cf9-99f6-05cf4084806f.png)

+   `print_msg3()`: 这是一个 Python 方法，接受两个参数。它类似于我们之前看到的`print_msg2()`方法。不同之处在于它有时可能会返回一个值。它的调用方式也不同。请注意，在第 22 行，我们通过将第二个参数传递为`True`来调用此方法。这意味着它返回一个值为`True`，但是我们在第 26 行不使用`True`作为第二个参数调用它，因此它不返回任何值。因此，我们在屏幕上得到`None`。在其他编程语言中，如 C、C++或 Java，调用方法时参数的顺序非常重要。这是因为我们传递参数的顺序应该与传递给方法的顺序相同。然而，在 Python 中，我们可以调用方法并在调用过程中传递命名参数。这意味着顺序并不重要，只要名称与方法参数的名称匹配即可。这在第 29 行中得到了体现，我们将消息作为第二个参数传递，即使它在方法定义中是第一个参数。这样做完全有效，如输出所示。

+   `print_msg4()`: 这是我们熟悉 Python 默认参数以及它们如何与方法一起使用的地方。默认参数是在声明方法时分配默认值的变量。如果调用者为此参数或变量传递了一个值，则默认值将被调用者传递的值覆盖。如果在调用过程中没有为默认参数传递值，则变量将保持其初始化的默认值。`print_msg4()`方法有一个必填参数`m`，和两个可选参数`op1`和`op2`。

+   `print_msg4('Test Mandatory')`: 这在第 31 行被调用。这表示必填参数应传递`Test mandatory`字符串，另外两个`op1`和`op2`变量将被初始化为默认值，如输出所示。

+   `print_msg4(1,2)`: 这在第 32 行被调用。这表示必填参数应传递一个带有`value=1`的整数，另一个带有`value=2`的整数应传递给`op1`。因此，`op1`的默认值将被覆盖。`op2`将保留默认值，因为没有传递值。

+   `print_msg4(2,3,2)`: 这在第 33 行被调用。这表示必填参数应传递一个带有`value=2`的整数，另一个带有`value=3`的整数应传递给`op1`，因此`op1`和`op2`的默认值将被覆盖。

+   `print_msg4(1,op2='Test')`: 这在第 34 行被调用。必填参数接收一个带有`value=1`的整数。对于第二个参数，在调用过程中我们指定了一个命名参数，因此`Test`的顺序对`op2`不重要，它将被复制到调用者的`op2`。

+   `print_msg4(1,op2=33,op1=44)`: 这在第 35 行被调用。必填参数接收`value=1`。对于第二个参数，我们指定了一个命名参数`op2`，对于第三个参数，我们传递了`op1`。同样，我们可以在输出中看到顺序并不重要。

+   `print_msg5()`: 通常，在其他编程语言中，函数或方法总是可以返回一个值。如果需要返回多个值，必须将这些值放入数组或另一个结构中，然后返回它们。Python 为我们抽象地处理了这种情况。如果你阅读代码，你可能会认为该方法返回了多个值，而实际上它返回的是一个元组，其中每个值都乘以了二。这可以从输出中验证。

让我们现在探索一些更进一步的方法和传递参数的方式，使用以下示例`methods_adv.py`。以下代码片段表示 Python 中的可变参数类型方法。从输出中可以验证，`method_1`接受任意大小的普通序列作为输入，这意味着我们可以向方法传递任意数量的参数。当方法声明为由`*`符号前缀的参数时，所有传递的参数都被转换为序列，并且一个元组对象被放置在`args`中。另一方面，当在调用方法时使用`*`与参数一起使用时，参数类型从序列中更改，内部将每个元素`if`序列作为单个参数传递给调用者，如`method_1_rev`中所示。

此外，当在方法声明中使用`if`与参数一起使用时，它会将所有命名参数内部转换为 Python 字典，键为名称，值为`=`运算符后的值。这可以在`method_2`中看到。最后，当`**`与调用者参数一起使用时，该参数会从 Python 字典内部转换为命名参数。这可以通过`method_2_rev`进行验证：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/a143bc5f-0fdd-4a93-a9ff-650b65748d8b.png)

# 模块和包

每个 Python 脚本都被称为一个模块。Python 被设计为可重用和易于编码。因此，我们创建的每个 Python 文件都成为 Python 模块，并有资格在任何其他文件或脚本中被调用或使用。你可能已经学过在 Java 中如何导入类并与其他类一起重用。这里的想法基本上是一样的，只是我们将整个文件作为模块导入，我们可以重用导入文件的任何方法、类或变量。让我们看一个例子。我们将创建两个文件`child.py`和`parent.py`，并在每个文件中放置以下代码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/4978a91f-a963-4631-9d09-6704e427d4f0.png)

前五行属于`child.py`，最后八行属于`parent.py`。我们将运行父文件，如输出所示。应该注意的是，导入的文件可以被赋予别名。在我们的例子中，我们导入了 child 并给它起了别名 C。最后，我们从父 Python 脚本中调用了该模块的`child_method()`类。

让我们现在尝试探索 Python 包以及它们如何被使用。在 Java 中，包只是收集 Java 中逻辑连接的类文件的文件夹或目录。包在 Python 中也是如此；它们收集逻辑连接的 Python 模块。始终建议使用包，因为这样可以保持代码整洁，使其可重用和模块化。

如前所述，Python 包是一个普通的目录。唯一的区别是，为了使普通目录像 Python 包一样运行，我们必须在目录中放置一个空的`__init__.py`文件。这告诉 Python 应该使用哪些目录作为包。让我们继续创建一个名为`shapes`的包。我们将放置一个空的 Python 文件`__init__.py`和另一个名为`area_finder.py`的文件在其中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/3f51903f-9f5e-4c09-a2d4-51e0ab61bd4c.png)

让我们现在把以下代码放在`area_finder.py`文件中。我们还要创建另一个名为`invoker.py`的文件，并将其放在我们创建的 shapes 文件夹之外。调用者的代码在下图的右侧，而`area_finder`的代码在左侧：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d04e78e6-484e-4d8b-a142-751caf7ca5ce.png)

上面的代码是 Python 中如何使用包的一个简单示例。我们创建了一个名为`shapes`的包，并在其中放置了一个名为`area_finder`的文件，用于计算形状的面积。然后，我们继续创建了一个名为`invoker.py`的文件，放在`shapes`文件夹外，并以多种方式导入了包中的`area_finder`脚本（仅用于演示目的）。最后，我们使用其中一个别名来调用`find_area()`方法。

# 生成器和推导式

**生成器**是 Python 中一种特殊的迭代器。换句话说，Python 生成器是通过发出`yield`命令返回生成器迭代器的函数，可以进行迭代。可能会有一些情况，我们希望一个方法或函数返回一系列值，而不仅仅是一个值。例如，我们可能希望我们的方法部分执行任务，将部分结果返回给调用者，然后从上次返回最后一个值的地方恢复工作。通常，当方法终止或返回一个值时，它的执行会从头开始。这就是生成器试图解决的问题。生成器方法返回一个值和一个控制给调用者，然后从离开的地方继续执行。生成器方法是一个带有 yield 语句的普通 Python 方法。以下代码片段`generators.py`解释了如何使用生成器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/602efafc-01fe-4ce4-99db-0d946dea3d9e.png)

请注意，由于`genMethod`中有一个 yield 语句，它变成了一个生成器。每次执行 yield 语句时，"a"的值都会作为控制返回给调用者（记住生成器返回一系列值）。每次对生成器方法进行`next()`调用时，它都会从之前离开的地方恢复执行。

我们知道，每次执行 yield 时，生成器方法都会返回一个生成器迭代器。因此，与任何迭代器一样，我们可以使用`for`循环来迭代生成器方法。这个`for`循环会一直持续，直到它到达方法中的 yield 操作。使用`for`循环的相同示例如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/8f445fb5-837c-4f90-af71-da0d2bebab28.png)

你可能会想为什么我们要使用生成器，当相同的结果可以通过列表实现。生成器非常节省内存和空间。如果需要大量处理来生成值，使用生成器是有意义的，因为我们只根据需求生成值。

生成器表达式是可以产生生成器对象的一行表达式，可以进行迭代。这意味着可以实现相同的内存和处理优化。以下代码片段显示了如何使用生成器表达式：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/2d06b188-024e-4928-b650-aa02d5d0f302.png)

# 推导式

**Python 推导式**，通常称为**列表推导式**，是 Python 中非常强大的实用工具，如果我们需要对列表的所有或部分元素执行一些操作，它会很方便。列表推导式将返回一个带有应用修改的新列表。假设我们有一个数字列表，我们想要对列表中的每个数字进行平方。

让我们看看解决这个问题的两种不同方法：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/eaed9af8-43f0-40e1-86df-0076c101d8d4.png)

左侧的代码片段是更传统的方法，需要九行。使用推导式的相同代码只需要三行。列表推导式在方括号内声明，并对列表的每个元素执行任何操作。然后返回带有修改的新列表。让我们看另一个推导式的例子。这次，我们将使用一个`if`条件（称为推导式过滤器），以及带有推导式的嵌套循环。我们将命名文件为`list_comp_adv.py`，并输入以下代码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/5a1a5b89-0434-4f19-b6c6-60d05a1c1ca1.png)

前面的代码片段是不言自明的。它向我们展示了如何在推导式中使用`if`条件（第 4 行）。它还向我们展示了如何使用嵌套循环来累加两个列表（第 5 行）。最后，它向我们展示了如何在推导式中使用字典（第 6 行）。

# Map、Lambda、zip 和 filters

在本节中，我们将了解一些非常方便的 Python 函数。这些函数允许我们对 Python 可迭代对象（如列表）进行快速处理操作。

+   `Map()`: 正如我们之前看到的，当我们需要对列表中的所有或部分元素执行操作时，列表推导式非常方便。同样的操作也可以通过`map`函数实现。它接受两个参数，第一个是将对列表元素执行操作的函数，第二个是列表本身。以下示例`map_usage.py`演示了这一点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/77878f15-4172-4891-8b59-225dce87a415.png)

+   `Lambda()`: Lambda 函数是小巧但功能强大的内联函数，可用于数据操作。它们对于小的操作非常有用，因为实现它们所需的代码很少。让我们再次看同一个示例，但这次我们将使用 Lambda 函数代替普通的 Python 函数：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/cb16e80b-43d7-4c23-bfef-9aebe43b2889.png)

+   `Zip()`: `zip`方法接受两个列表或可迭代对象，并在多个可迭代对象之间聚合元素。最后，它返回一个包含聚合的元组迭代器。让我们使用一个简单的代码`zip_.py`来演示这个函数：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/3b2d1050-84aa-4988-8977-1da910a5f0f7.png)

+   `Filter()`: `filter`方法用于过滤出列表中满足特定条件的元素。`filter`方法接受两个参数，第一个是返回特定元素为`true`或`false`的方法或 Lambda 函数，第二个是该元素所属的列表或可迭代对象。它返回一个包含条件评估为`true`的元素的列表。让我们创建一个名为`filter_usage.py`的文件，并添加以下内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/5281cba6-6154-46fd-a92d-b7b1edbd98ad.png)

# 摘要

在本章中，我们讨论了条件、循环、方法、迭代器、包、生成器和推导式。所有这些在 Python 中被广泛使用。我们之所以涵盖这些主题，是因为当我们进入后面的自动化渗透测试和网络安全测试用例时，我们将看到这些概念在我们的代码文件中被广泛使用。在下一章中，我们将探讨 Python 的面向对象特性。我们将探讨如何在 Python 中处理 XML、CSV 和 JSON 数据。我们还将了解有关文件、IO 和正则表达式的内容。

# 问题

1.  举一个现实生活中使用生成器的用例。 

1.  我们可以将函数名称存储在变量中，然后通过变量调用它吗？

1.  我们可以将模块名称存储在变量中吗？

# 进一步阅读

+   生成器和推导式：[`jpt-pynotes.readthedocs.io/en/latest/generators-comprehensions.html`](http://jpt-pynotes.readthedocs.io/en/latest/generators-comprehensions.html)

+   模块：[`docs.python.org/3/tutorial/modules.html`](https://docs.python.org/3/tutorial/modules.html)


# 第三章：概念处理

这一章将使我们熟悉 Python 中的各种面向对象的概念。我们将看到 Python 不仅可以用作脚本语言，而且还支持各种面向对象的原则，并且因此可以用来设计可重用和可扩展的软件组件。此外，我们还将探讨正则表达式、文件和其他基于 I/O 的访问，包括 JSON、CSV 和 XML。最后，我们将讨论异常处理。在本章中，我们将涵盖以下主题：

+   Python 中的面向对象编程

+   文件、目录和其他基于 I/O 的访问类型

+   Python 中的正则表达式

+   使用 XML、JSON 和 CSV 数据进行数据操作和解析

+   异常处理

# Python 中的面向对象编程

任何编程语言的面向对象特性都教会我们如何处理类和对象。对于 Python 也是如此。我们将要涵盖的一般面向对象特性包括：

+   类和对象

+   类关系：继承、组合、关联和聚合

+   抽象类

+   多态

+   静态、实例和类方法和变量

# 类和对象

**类**可以被认为是一个包含了方法和变量定义的模板或蓝图，用于与该类的对象一起使用。**对象**只是类的一个实例，其中包含实际值而不是变量。一个类也可以被定义为对象的集合。

简单来说，一个类是变量和方法的集合。方法实际上定义了类执行的行为或操作，而变量是操作所针对的实体。在 Python 中，使用 class 关键字声明类，后跟类名。以下示例显示了如何声明一个基本的员工类，以及一些方法和操作。让我们创建一个名为`Classes.py`的 Python 脚本：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/88a7d85c-8830-450b-8ebc-e800e20456cd.png)

以下项目符号解释了前面的代码及其结构：

+   `class Id_Generator()`：为了在 Python 中声明一个类，我们需要将其与 class 关键字关联起来，这就是我们在代码的第 2 行所做的。在等同缩进的情况下，`Id_Generator`类的内容是类的一部分。这个类的目的是为每个新创建的员工生成一个员工 ID。它使用`generate()`方法来实现这一点。

+   每个 Python 或任何其他编程语言中的类都有一个构造函数。这要么是显式声明的，要么没有声明，隐式地采用默认构造函数。如果你来自使用 Java 或 C++的背景，你可能习惯于构造函数的名称与类名相同，但这并不总是这样。在 Python 中，类构造方法是使用`__init__`单词定义的，并且它总是以`self`作为参数。

+   `self`：`self`类似于关键字。在 Python 中，`self`表示类的当前实例，并且在 Python 中，每个类方法都必须将`self`作为其第一个参数。这也适用于构造函数。值得注意的是，在调用实例方法时，我们不需要显式地将类的实例作为参数传递；Python 会隐式地为我们处理这个问题。任何实例级变量都必须使用`self`关键字声明。这可以在构造函数中看到——我们已经声明了一个实例变量 ID 为`self.id`并将其初始化为`0`。

+   `def generate(self)`：`generate`是一个实例方法，它递增 ID 并返回递增的 ID。

+   `class Employee()`：`employee`类是一个用于创建员工的类，它具有构造函数。它使用`printDetails`方法打印员工的详细信息。

+   **`def __init__(self,Name,id_gen)`**：构造函数有两种类型——带参数和不带参数。任何带参数的构造函数都是带参数的构造函数。在这里，`employee`类的构造函数是带参数的，因为它接受两个参数：要创建的员工的姓名和`Id_Generator`类的实例。在这个方法中，我们只是调用了`Id_Generator`类的`generate`方法，它会返回员工 ID。构造函数还将传递给`self`类实例变量的员工姓名`name`进行初始化。它还将其他变量`D_id`和`Salary`初始化为`None`。

+   **`def printDetails(self)`**：这是一个打印员工详细信息的方法。

+   24-32 行：在代码的这一部分，我们首先创建了`Id_Generator`类的实例并命名为`Id_gen`。然后，我们创建了`Employee`类的一个实例。请记住，类的构造函数在我们创建类的实例时被调用。由于在这种情况下构造函数是带参数的，我们必须创建一个带两个参数的实例，第一个参数是员工姓名，第二个参数是`Id_Generator`类的实例。这就是我们在第 25 行所做的：`emp1=Employee('Emp1',Id_gen)`。正如前面提到的，我们不需要显式传递`self`；Python 会隐式处理这个问题。之后，我们为`Emp1`实例的`Salary`和`D_id`实例变量赋一些值。我们还创建了另一个名为`Emp2`的员工，如第 28 行所示。最后，我们通过调用`emp1.printDetails()`和`emp2.printDetails()`来打印两个员工的详细信息。

# 类关系

面向对象编程语言最大的优势之一是代码重用。这种可重用性是由类之间存在的关系所支持的。面向对象编程通常支持四种关系：继承、关联、组合和聚合。所有这些关系都基于**is-a**、**has-a**和**part-of**关系。

# 继承

类继承是一个功能，我们可以使用它来扩展类的功能，通过重用另一个类的能力。继承强烈促进了代码的重用。举个简单的继承例子，假设我们有一个`Car`类。车辆类的一般属性包括`category`（如 SUV、运动型、轿车或掀背车）、`mileage`、`capacity`和`brand`。现在假设我们有另一个名为`Ferrari`的类，除了普通汽车的特征外，还具有特定于跑车的额外特征，如`Horsepower`、`Topspeed`、`Acceleration`和`PowerOutput`。在这种情况下，我们在两个类之间建立了继承关系。这种关系是子类和基类之间的**is-a**关系。我们知道 Ferrari 是一辆车。在这种情况下，汽车是基类，Ferrari 是子类，它从父类继承了通用汽车属性，并具有自己的扩展特征。让我们扩展我们之前讨论的例子，我们创建了一个`Employee`类。现在我们将创建另一个名为`Programmer`的类，并看看如何在两者之间建立继承关系：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/ba8e64e6-daad-48cb-9f20-f5361846cbc3.png)

以下几点解释了前面的代码及其结构：

+   `Class Programmer(Employee)`：在前面的情况下，我们创建了另一个名为`Programmer`的类，它继承自`Employee`基类。`Programmer`和`Employee`之间存在**is a**关系。除了`Employee`类的所有变量和方法外，`Programmer`类还定义了一些自己的变量和方法，如语言、数据库、项目和其他技能。

+   **`def __init__(self,name,id_gen,lang,db,projects,**add_skills)`**：`Programmer`类的`init`方法接受一些自解释的参数。请注意(`Employee`类) `super().__init__()` 超类构造函数的调用，位于第 32 行。在其他高级语言如 Java 和 C++中，我们知道基类或超类构造函数会自动从子类构造函数中调用，当没有指定时，这是隐式从子类构造函数中执行的第一个语句。但在 Python 中并非如此。基类构造函数不会从子类构造函数中隐式调用，我们必须使用 super 关键字显式调用它，就像在第 32 行中看到的那样。

+   **`def printSkillDetails(self)`**：这是帮助我们探索继承力量的方法。我们在这个方法中使用了基类的变量（`iD`，`name`和`salary`），以及一些特定于`Programmer`类的变量。这显示了如何使用继承来重用代码并得到一个**是一个**关系。

+   第 52-62 行：最后，我们创建了`Programmer`类的一个实例并调用了`printSkillDetails`方法。

# Python 中的访问修饰符

在 Python 中，我们没有像 Java 和 C++中那样的访问修饰符。然而，有一种部分解决方法可以用来指示哪些变量是`公共的`，`受保护的`和`私有的`。这里的**指示**一词很重要；Python 并不阻止使用受保护或私有成员，它只是指示成员是哪个。让我们看一个例子。创建一个名为`AccessSpecifiers.py`的类：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/e9df90c1-868b-4c3a-8195-4fc53ec92820.png)

上面的例子向我们展示了如何在 Python 中使用访问限定符。在类中简单声明的任何变量默认为公共，就像我们声明的`self.public`一样。Python 中的受保护变量是通过在它们前面加下划线(`_`)来声明的，就像第 5 行中看到的`self._protected`一样。但必须注意的是，这并不能阻止任何人使用它们，就像在第 23 行中看到的那样，我们在类外部使用了受保护成员。Python 中的私有成员是通过在它们前面加双下划线(`__`)来声明的，就像第 6 行中看到的`self.__private`一样。然而，同样地，没有任何东西可以阻止这个成员在类外部被使用。然而，访问它们的方式有点不同；对于私有成员，如果它们要在类外部被访问，会遵循一个特定的约定：`instance._<className><memberName>`。这被称为**名称修饰**。

我们在这里学到的关于 Python 中访问修饰符的知识是，Python 确实有符号来表示类的公共、私有和受保护成员，但它没有任何方式让成员在其范围之外被使用，因此这仅仅是用于标识目的。

# 组合

面向对象编程中的**组合**表示类之间的**部分**关系。在这种关系中，一个类是另一个类的一部分。让我们考虑以下示例`Composition.py`，以了解类之间的组合关系：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/de3e8ad9-955c-4e15-ab91-a7a3579209c9.png)

在上面的例子中，法拉利汽车和发动机之间的关系是组合类型。这是因为发动机是汽车的一部分，而汽车是法拉利类型的。

# 关联

关联关系维护了类的对象之间的**拥有**关系。**拥有**关系可以是一对一，也可以是一对多。在下面的例子中，我们可以看到`Employee`和`Manager`类之间存在一对一的关联关系，因为一个`Employee`只会有一个`Manager`类。我们还有一个`Employee`和`Department`之间的一对一关联关系。这些关系的反向将是一对多的关系，因为一个`Department`类可能有很多员工，一个经理可能有很多员工报告给他们。以下代码片段描述了关联关系：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/beea7cf0-1d8d-4bbe-9cda-18414b49672a.png)

# 聚合

聚合关系是一种特殊的**拥有**关系，它总是单向的。它也被称为单向关联关系。例如，`Employee`和`Address`之间的关系是单向关联，因为员工总是有地址，但反过来并不总是成立。以下示例描述了`Employee`和`Address`之间的聚合关系：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/994d4a59-bbb2-46e8-9235-d904530cc5c0.png)

# 抽象类

有许多情况下，我们可能希望部分实现一个类，使得该类通过模板定义其目标，并且还定义了它必须如何通过一些已实现的方法获取其目标的一部分。类目标的剩余部分可以留给子类来实现，这是强制性的。为了实现这样的用例，我们使用抽象类。抽象基类，通常称为`abc`类，是一个包含抽象方法的类。抽象方法是一种没有实现的方法。它只包含声明，并且应该在实现或继承抽象类的类中实现。

关于抽象类的一些重要要点包括以下内容：

+   在 Python 中，抽象方法是使用`@abstractmethod`装饰器声明的。

+   虽然抽象类可以包含抽象方法，但没有任何阻止抽象类同时拥有普通或非抽象方法的限制。

+   抽象类不能被实例化。

+   抽象类的子类必须实现基类的所有抽象方法。如果没有这样做，它就无法被实例化。

+   如果抽象类的子类没有实现抽象方法，它将自动成为一个抽象类，然后可以由另一个类进一步扩展。

+   Python 中的抽象类是使用`abc`模块实现的。

让我们创建一个名为`Abstract.py`的类，并看看如何在 Python 中使用抽象类：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/5e68c2ad-439d-46e2-91d2-94023f36707a.png)

在上面的例子中，我们创建了一个名为`QueueAbs`的抽象类，它继承自名为`ABC`的抽象基类。该类有两个抽象方法，`enqueue`和`dequeue`，还有一个名为`printItems()`的具体方法。然后，我们创建了一个名为`Queue`的类，它是`QueueAbs`抽象基类的子类，并实现了`enqueue`和`dequeue`方法。最后，我们创建了`Queue`类的实例并调用了方法，如前所示。

值得记住的一件事是，在 Java 和 C#中，抽象类不能实现抽象方法。但在 Python 中不是这样。在 Python 中，抽象方法可能有默认实现，也可能没有，但这并不妨碍子类对其进行重写。无论抽象类方法是否有实现，子类都必须对其进行重写。

# 多态

多态性是指一个实体可以存在多种形式的属性。在编程方面，它指的是创建一个可以与多个对象或实体一起使用的结构或方法。在 Python 中，多态性可以通过以下方式实现：

+   函数多态性

+   类多态性（抽象类）

# 函数多态性

让我们考虑两个类，`Ferrari`和`McLaren`。假设两者都有一个返回汽车最高速度的`Speed()`方法。让我们思考在这种情况下如何使用函数多态性。让我们创建一个名为`Poly_functions.py`的文件：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d69fa450-747f-44ce-9130-f010f91b2cea.png)

我们可以看到我们有两个类，`Ferrari`和`McLaren`。两者都有一个打印两辆车速度的共同速度方法。一种方法是创建两个类的实例，并使用每个实例调用打印速度方法。另一种方法是创建一个接受类实例并在接收到的实例上调用速度方法的公共方法。这就是我们在第 10 行定义的多态`printSpeed(carType)`函数。

# 类多态性（抽象类）

也许有时我们希望根据类必须做什么来定义类的模板，而不是如何做到这一点 - 我们希望将这留给类的实现。这就是我们可以使用抽象类的地方。让我们创建一个名为`Poly_class.py`的脚本，并添加以下代码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/ced77fe9-81c9-462f-bd46-c25fc2873fdb.png)

可以看到我们有一个名为`Shape`的抽象类，它有一个`area`方法。`area`方法在这个类中没有实现，但会在子类中实现。`Square`和`Circle`子类重写了`area`方法。`area`方法是多态的，这意味着如果一个正方形重写它，它实现了正方形的面积，当`Circle`类重写它时，它实现了圆的面积。

# Python 中的静态、实例和类方法

在 Python 类中可以定义三种方法。到目前为止，我们大部分时间都在处理实例方法，我们已经使用我们的 Python 类实例调用了它们：

+   **实例方法和变量：** 在 Python 类中定义的任何方法，使用类的实例调用，以 self 作为其第一个位置参数，被称为实例方法。实例方法能够访问类的实例变量和其他实例方法。使用`self.__class__`构造，它也能够访问类级别的变量和方法。另一方面，实例变量是在 Python 类中使用`self`关键字声明的任何变量。

+   **类方法和变量：** 使用`@classmethod` Python 装饰器声明的任何方法都被称为类方法。类方法也可以在没有`@classmethod`装饰器的情况下声明。如果是这种情况，必须使用类名调用它。类方法只能访问在类级别标记或声明的变量，并且不能访问对象或实例级别的类变量。另一方面，类变量可以在任何方法之外声明。在类内部，我们必须在不使用 self 关键字的情况下声明变量。因此，类变量和方法在某种程度上类似于我们在 Java 中学习的静态方法和变量，但有一个陷阱，如下所述：

在 Java 和 C#中，我们知道静态变量不能通过类的实例访问。在 Python 中，静态变量是类级变量，实际上可以通过类的实例访问。但是访问是只读访问，这意味着每当使用类的实例访问类级变量并且实例尝试修改或更新它时，Python 会自动创建一个同名的变量副本并将其分配给类的这个实例。这意味着下次使用相同实例访问变量时，它将隐藏类级变量，并提供对新创建的实例级副本的访问。

+   **静态方法：** 在 Python 类中使用`@staticmethod`装饰器声明的任何方法都被称为静态方法。Python 中的静态方法与我们在 Java 和 C#中看到的不同。静态级别的方法无法访问实例或对象级别的变量，也无法访问类级别的变量。

让我们以一个名为`Class_methods.py`的示例来进一步解释：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/c8c50950-2aae-4a6e-be1c-75f27fbe8e39.png)

以下是前面代码的延续：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/b8a6e8d2-3dbd-44e0-85c0-8c6346735d93.png)

前面的代码片段解释了静态、实例和类方法的用法。每当类方法由类的实例调用时，Python 会在内部自动将实例类型转换为类类型，这可以在第 42 行看到。

输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d0b7fefc-0f6d-44e8-8bf2-6c63bb93ff62.png)

# 文件、目录和 I/O 访问

与其他编程语言一样，Python 提供了一个强大且易于使用的接口来处理 I/O、文件和目录。我们将在接下来的章节中更详细地探讨这些内容。

# 文件访问和操作

我们可以在 Python 中读取、写入和更新文件。Python 有一个`open`结构，可以用来提供文件操作。当我们打开一个文件时，可以以各种模式打开该文件，如下所示：

+   `r`：读取模式，这以文本模式读取文件（默认）。

+   `rb`：这以二进制模式读取文件。

+   `r+`：这以读取和写入模式读取文件。

+   `rb`：这以二进制模式打开文件进行读取和写入。

+   `w`：这仅以写入模式打开文件。它会覆盖现有文件。

+   `wb`：这以二进制模式打开文件进行写入。它会覆盖现有文件。

+   `w+`：这以写入和读取模式打开文件。它会覆盖现有文件。

+   `wb+`：这以二进制模式打开文件进行读取和写入。它会覆盖现有文件。

+   `a`：这以追加模式打开文件，并在文件不存在时创建文件。

+   `ab`：这以追加二进制模式打开文件，并在文件不存在时创建文件。

+   `a+`：这以追加和读取模式打开文件，并在文件不存在时创建文件。

+   `ab+`：这以追加读取二进制模式打开文件，并在文件不存在时创建文件。

在以下代码块中，`open`方法调用的第一个参数是要打开的文件的路径。第二个参数是文件打开的`mode`，第三个是可选的缓冲参数，指定文件的期望`buffer`大小：`0`表示无缓冲，`1`表示行缓冲，任何其他正值表示使用大约该大小的缓冲（以字节为单位）。负缓冲表示应使用系统默认值。对于 tty 设备，通常是行缓冲，对于其他文件，通常是完全缓冲。如果省略，将使用系统默认值。

```py
open("filepath","mode",buffer)
```

通过缓冲，我们不是直接从操作系统的原始文件表示中读取（这样会有很高的延迟），而是将文件读入操作系统缓冲区，然后从那里读取。这样做的好处是，如果我们有一个文件存在于共享网络上，并且我们的目标是每 10 毫秒读取一次文件。我们可以将其加载到缓冲区中，然后从那里读取，而不是每次都从网络中读取，这将是昂贵的。

看一下`File_access.py`文件中的以下片段以了解更多：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/72c27a66-405c-4bff-8007-6fce75c0dea8.png)

前面截图中的代码片段来自`File_access.py`文件，解释了如何在 Python 中使用文件。`File`类的`read()`方法接受文件路径，如果没有给出整个路径，则假定当前工作目录是起始路径。在文件实例上调用的`read()`方法将整个文件读入程序变量。`read(20)`将从当前文件指针位置加载 20 个字节的文件。当我们处理大文件时，这非常方便。

`readlines()`方法返回一个列表，每个条目都指向文件的一行。`readline()`方法返回文件的当前行。`seek()`方法将文件指针移到参数中指定的位置。因此，每当我们执行`seek(0)`时，文件指针都会指向文件的开头：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d982737e-10d6-4d76-9cf5-750bcf84a5c1.png)

# 重命名和删除文件以及访问目录

在 Python 中，对文件目录和各种其他操作系统命令的系统级访问是由`os`模块提供的。`os`模块是一个非常强大的实用程序。在本节中，我们将看到它在重命名、删除、创建和访问目录方面的一些用法，借助`os_directories.py`文件中的以下片段：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/510246cb-685b-46a6-8e83-c58199e98da4.png)

前面截图中的代码片段展示了在 Python 中使用`os`模块与文件和目录一起使用的各种方式，以重命名和删除文件以及创建和更改目录。它还向我们展示了如何重命名和遍历所有文件（包括嵌套文件）从一个子文件夹。需要注意的是，如果我们想要删除一个文件夹，我们可以使用`os.rmdir()`方法，但是文件夹中的所有文件都应该被显式删除才能使其工作：

+   以下输出显示了文件在创建前后的变化：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d27dec94-d550-47f0-a800-82356b636b19.png)

+   以下输出显示了文件名的更改：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d00304ad-2c46-4020-908e-aeaf748b38af.png)

+   以下输出显示了文件被删除后的变化：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/ac7c3bda-3308-4ea5-8b4f-2da84ba8b947.png)

# 控制台 I/O

到目前为止，我们已经处理了大部分以硬编码数据作为输入的 Python 程序。让我们看看如何在 Python 中从用户那里获取输入并在我们的代码中使用。我们将创建一个名为`user_input.py`的文件：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/2737bd23-9fff-48d2-a9ef-9f03d0d1a749.png)

这是相当不言自明的。为了获取用户输入，我们使用`input()`方法，它会暂停屏幕，直到用户提供输入。它总是返回一个字符串：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/ee4a3968-eabd-4d31-a6aa-36744383f1ea.png)

# Python 中的正则表达式

**正则表达式**非常强大，在网络安全领域被广泛用于模式匹配，无论是处理解析日志文件、Qualys 或 Nessus 报告，还是 Metasploit、NSE 或任何其他服务扫描或利用脚本生成的输出。Python 中提供对正则表达式支持的模块是`re`。我们将使用 Python 正则表达式（`re`模块）的一些重要方法，如下所述：

| `match()` | 这确定正则表达式是否在字符串开头找到匹配项`re.match(pattern,string,Flag=0)`。标志可以用`&#124;`或操作符指定。最常用的标志是`re.Ignore-Case`，`re.Multiline`和`re.DOTALL`。这些标志可以用或操作符指定为(`re.M&#124; re.I`)。 |
| --- | --- |
| `search()` | 与 match 不同，search 不仅在字符串开头寻找匹配项，而是在整个字符串中搜索或遍历以寻找给定的搜索字符串/正则表达式，可以指定为`re.search(pattern,string,Flag=0)`。 |
| `findall()` | 这在字符串中搜索正则表达式匹配项，并返回所有子字符串作为列表，无论它在哪里找到匹配项。 |
| `group()` | 如果找到匹配项，则`group()`返回正则表达式匹配的字符串。 |
| `start()` | 如果找到匹配项，则`start()`返回匹配项的起始位置。 |
| `end()` | 如果找到匹配项，则`end()`返回匹配项的结束位置。 |
| `span()` | 如果找到匹配项，则`span()`返回一个包含匹配项的起始和结束位置的元组。 |
| `split()` | 这根据正则表达式匹配来拆分字符串，并返回一个列表。 |
| `sub()` | 这用于字符串替换。它会替换所有子字符串的匹配项。如果找不到匹配项，则返回一个新字符串。 |
| `subn()` | 这用于字符串替换。它会替换所有子字符串的匹配项。返回类型是一个元组，新字符串在索引 0 处，替换的数量在索引 1 处。 |

现在我们将尝试通过`regular_expressions.py`脚本中的以下片段来理解正则表达式：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/e8004fd3-a4ef-4d0e-900a-174774490875.png)

`match`和`search`之间的区别在于，`match`只在字符串开头搜索模式，而`search`则在整个输入字符串中搜索。代码行 42 和 50 产生的输出将说明这一点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/5febd3bf-641a-4918-9857-f09a0961ee8f.png)

在前面的屏幕中，可以看到当输入`Hello`时，`match`和`search`都能够定位到字符串。然而，当输入为`\d`时，表示任何十进制数，`match`无法定位，但`search`可以。这是因为`search`方法在整个字符串中搜索，而不仅仅是开头。

同样，可以从以下截图中看到，`match`没有返回数字和非数字的分组，但`search`有。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/103f9502-7e14-446b-9540-612b790ee6d0.png)

在以下输出中，搜索了`Reg`关键字，因此`match`和`search`都返回了结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d53c255f-370b-4e6a-bba4-133b4012e11c.png)

注意，在下面的截图中，`findall()`与`match`和`search`不同：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/bcb6ea48-da84-4f3c-9bfe-ed19b1fdbca4.png)

这些例子已经展示了`match()`和`search()`的不同操作方式，以及`search()`在执行搜索操作时更加强大：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/4fac2b11-551e-472e-af98-da7102068a6a.png)

让我们来看一下 Python 中一些重要的正则表达式：

| **正则表达式** | **描述** |
| --- | --- |
| `\d` | 这匹配字符串中的零到九的数字。 |
| `(\D\d)` | 这匹配了`\D`非数字和`\d`数字，它们被分组在一起。括号(`()`)用于分组。 |
| `.*string.*` | 如果在字符串中找到一个单词，不管它前面和后面是什么，都会返回一个匹配项。`.*`符号表示任何东西。 |
| `^` | 尖号符号表示它匹配字符串的开头。 |
| `[a-zA-Z0-9]` | `[...]`用于匹配放在大括号内的任何内容。例如，`[12345]`表示应该找到介于一和五之间的任何数字的匹配项。`[a-zA-Z0-9]`表示应该将所有字母数字字符视为匹配项。 |
| `\w` | `\w`与`[a-zA-Z0-9_]`相同，匹配所有字母数字字符。 |
| `\W` | `\W`是`\w`的否定形式，匹配所有非字母数字字符。 |
| `\D` | `\D`是`\d`的否定形式，匹配所有不是数字的字符。 |
| `[^a-z]` | `^`，当放置在`[]`内时，作为否定形式。在这种情况下，它意味着匹配除了`a`到`z`之间的字母以外的任何内容。 |
| `re{n}` | 这意味着精确匹配前面表达式的`n`次出现。 |
| `re{n ,}` | 这意味着匹配前面表达式的`n`次或更多次出现。 |
| `re {n,m}` | 这意味着匹配前面表达式的最少`n`次和最多`m`次出现。 |
| `\s` | 这意味着匹配空格字符。 |
| `[T&#124;t]est` | 这意味着匹配`Test`和`test`。 |
| `re*` | 这意味着匹配`*`后面的表达式的任何出现。 |
| `re?` | 这意味着匹配`?`后面的表达式的任何出现。 |
| `re+` | 这意味着匹配`+`后面的表达式的任何出现。 |

# 使用 XML、JSON 和 CSV 数据进行数据操作和解析

在本节中，我们将首先看看如何在 Python 中操作 XML 数据，然后看看如何操作 JSON 数据。之后，我们将重点介绍 CSV 的 pandas Python 实用程序。

# XML 数据操作

在本节中，我们将看看如何在 Python 中操作 XML 数据。虽然有许多方法可以解析 Python 中的 XML 文档，但简单且最常用的方法是使用`XML.etree`模块。让我们看看以下示例，它将说明在 Python 中解析 XML 文档和字符串是多么简单和容易。创建一个名为`xml_parser.py`的脚本。我们将使用一个名为`exmployees.xml`的 XML 文档：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/2af0e0e4-8682-4da6-bbda-ce278188c0b1.png)

正如前面的例子中所示，我们简单地使用`xml.etree.ElementTree`模块，并将其别名为 ET。在类的解析方法中，我们通过调用`parse`方法（在前一种情况下）或`fromstring`方法（在后一种情况下）来提取 XML 文档或 XML 字符串的根。这将返回`<class 'xml.etree.ElementTree.Element'>` ET 元素类的实例。我们可以遍历它以获取所有子节点，如从第 21 行到第 26 行所示。如果我们不知道节点的属性名称，类的`attrib`属性返回一个字典，其中包含属性名称和其值的键值映射。如果我们知道子节点的名称，我们可以遵循第二种方法，如从第 29 行到第 36 行所示，其中我们指定节点的名称。

如果我们传递的是 XML 字符串而不是文件，则唯一的变化在于初始化根元素的方式；其余部分保持不变。关于此脚本的另一点要注意的是，我们使用了命令行参数。`sys.argv[]`用于访问这些命令行参数，文件的 0 索引具有脚本本身的名称，从索引 1 开始是参数。在我们的示例中，XML 文件的名称作为命令行参数传递给脚本，并使用`sys.argv[1]`属性进行访问。如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/c1c97fa6-d348-4d0b-ae92-e7cedbf8724a.png)

# JSON 数据操作

现在让我们看看如何使用 Python 操作 JSON 数据。 JSON（JavaScript 对象表示）是一种非常广泛使用的数据存储和交换格式。随着互联网的成熟，它变得越来越受欢迎，并成为基于 REST 的 API 或服务中信息交换的标准。

Python 为我们提供了一个用于 JSON 数据操作的 JSON 模块。让我们创建一个名为`employees.json`的 JSON 文件，并查看如何使用 JSON 模块访问 JSON 内容。假设我们的目标是读取员工数据，然后找出工资超过 30,000 的员工，并用`A`级标记他们。然后我们将那些工资低于 30,000 的员工标记为`B`级：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/4eaf8647-2b2b-441e-8317-7bc715e5cce7.png)

获得的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/b699e6c9-04e1-45ef-b33e-598ac06ead4d.png)

从前面的代码可以推断出，JSON 文件被加载为 Python 字典，可以通过`json.load()`命令实现。`load()`方法期望提供 JSON 文件路径作为参数。如果 JSON 数据不是作为外部文件而是作为 Python 字符串存在，我们可以使用`json.loads()`方法，并将 JSON 字符串作为参数传递。这将再次将字符串转换为 Python 本机类型，可能是列表或字典。如下所示：

```py
>>> a='{"k1":"v1"}'
>>> d=json.loads(a)
>>> type(d)
<class 'dict'
```

在`json_parse.py`文件中，第 10 到 20 行简单地迭代 Python 字典和内部列表，并显示员工详细信息。这是我们之前见过的。脚本的目标实际上是更新员工的工资档次，这是在`process()`方法中实现的。我们再次打开并加载 JSON 文件到 Python 本机类型（第 23 行）。然后，我们迭代 Python 字典。在第 27 行，我们检查员工的工资是否大于或等于 30,000。如果是，我们修改员工的档次，通过修改加载所有详细信息的原始`json_data`对象。`json_data["employees"]["data"][index]["slab"]`语句将指向当前员工的档次，确定他们的工资是多还是少于 30,000，并将其设置为`A`或`B`。最后，我们将在`json_data`对象中得到修改后的员工详细信息，并使用`json.dump()方法`覆盖原始 JSON 文件的内容。这将把 Python 本机对象（列表、字典或元组）转换为其 JSON 等效形式。它将`file_object`作为第二个参数，指示 JSON 数据必须放在哪里。它还接受格式选项，如`indent`、`sort_keys`等。同样，我们还有一个`json.dumps()`方法，它将 Python 本机类型转换为其 JSON 字符串等效形式。如下所示：

```py
>>> json.dumps({"k1":"v1"})
'{"k1": "v1"}'
```

应该记住，外部 JSON 文件不能在原地修改。换句话说，我们不能修改外部 JSON 文件的一部分，然后保持其余部分不变。在这种情况下，我们需要用新内容覆盖整个文件。

# CSV

**CSV 数据**在网络安全和数据科学领域被广泛使用，无论是作为日志文件的形式，作为 Nessus 或 Qualys 报告的输出（以 Excel 格式），还是用于机器学习的大型数据集。Python 提供了内置的 CSV 模块对 CSV 文件提供了出色的支持。在本节中，我们将探讨这个模块，并关注 CSV 的 pandas Python 实用程序。

让我们首先看一下 Python 提供的内置 CSV 模块。下面的代码片段，名为`csv_parser.py`，演示了这个模块：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/4749f061-9e48-4237-bae7-4b9f61412218.png)

前面的代码帮助我们了解如何使用 CSV 模块在 Python 中读取 CSV 文件。建议始终使用 CSV 模块，因为它内部处理分隔符、换行符和字符。有两种从 CSV 文件中读取数据的方法，第一种是使用`csv.reader()`方法（第 10-25 行），它返回一个 CSV 字符串列表。列表的每一行或项将是表示 CSV 文件一行的字符串列表，可以通过索引访问每个项。另一种读取 CSV 文件的方法是使用`csv.DictReader()`（第 29-38 行），它返回一个字典列表。每个字典将具有一个键值对，键表示 CSV 列，值是实际的行值。

产生的输出如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/6b9cd6c3-59ac-4e64-b0a5-91f72d0db0c2.png)

为了写入 CSV 文件，有两种不同的方法。一种方法是使用`csv.DictWriter()`指令，它返回一个 writer 对象，并且具有将 Python 列表或字典直接推送到 CSV 文件的能力。当我们在列表或字典上调用`writerows()`方法时，这将在内部将 Python 列表或字典转换为 CSV 格式。这在第 40-53 行中展示：我们检查员工的薪水，将适当的分级与之关联，最后使用`writerows()`方法覆盖修改后的 CSV 文件。`csv.DictWriter()`支持`writerows()`和`write row()`方法。`writerows()`方法将简单地获取一个字典并将其写入 CSV 文件。

写入 CSV 文件的第二种方法是使用`csv.Writer()`方法。这将返回一个 writer 对象，该对象将以列表的形式作为`writerows()`方法的参数，并将结构写入外部 CSV 文件。这两种方法的示例如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/fcffdd28-fda0-48fa-ad18-cc52eb3bf1e6.png)

虽然前面介绍的访问和处理 CSV 文件的方法很好，但如果 CSV 文件非常大，这些方法就不适用了。如果 CSV 文件大小为 10GB，系统的 RAM 只有 4GB，那么`csv.reader()`或`csv.DictReader()`都无法很好地工作。这是因为`reader()`和`DictReader()`都会将外部 CSV 文件完全读入变量程序内存中，也就是 RAM。对于一个巨大的文件，直接使用 CSV 模块是不可取的。

另一种方法是使用迭代器或按字节块读取文件，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/422f0beb-263e-4baa-b4bf-36c2b024054b.png)

前面的代码片段不会将整个文件加载到内存中，而是一次读取一行。这样，我们可以处理和存储该行到数据库中，或执行任何相关操作。由于文件是逐行读取的，如果我们有多行的 CSV 数据，这将会造成麻烦。正如我们在前面的示例中看到的，`Emp1`的第一条记录没有完全读取；它被分成两行，第二行只包含`Description`字段的一部分。这意味着以前的方法对于大型或多行的 CSV 文件是行不通的。

如果我们试图按块或字节来读取，就像我们之前看到的那样，我们将不知道多少块或字节对应于一行，因此这也会导致不一致的结果。为了解决这个问题，我们将使用 Pandas，这是一个强大的 Python 数据分析工具包。

有关 Pandas 的详细信息，请参阅以下链接：[`pandas.pydata.org/pandas-docs/stable/`](http://pandas.pydata.org/pandas-docs/stable/)。

首先，我们需要安装 pandas，可以按照以下步骤进行：

```py
pip3.5 install pandas
```

以下代码片段解释了如何使用 pandas 以小块读取巨大的 CSV 文件，从而减少内存使用：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/29a040bd-0403-468a-929c-b1b11e816f89.png)

如前面的代码片段所示，我们声明块大小为 100,000 条记录，假设我们有一个非常大的 CSV 文件要处理。块大小是上限；如果实际记录少于块大小，程序将只获取两者中较小的值。然后，我们使用`pd.read_csv()`加载 CSV 文件，指定块大小作为参数。`chunk.rename()`方法实际上会从列名中删除换行符（如果有的话），`chunk.fillna('')`将填充 CSV 文件返回的空值。最后，我们使用`iterrows()`方法迭代行，该方法返回一个元组，然后按照所示打印值。应该注意的是，`pd.read_csv()`返回一个 pandas DataFrame，可以被视为内存中的关系表。

# 异常处理

异常，我们都知道，是意想不到的条件。它们可能在运行时出现并导致程序崩溃。因此，建议将可疑代码（可能导致异常）放在异常处理代码块中。然后，即使发生异常，我们的代码也会适当地处理它并采取所需的操作。与 Java 和 C#一样，Python 也支持用于处理异常的传统 try 和 catch 块。然而，有一个小改变，就是 Python 中的 catch 块被称为 except。

以下代码片段显示了我们如何在 Python 中进行基本的异常处理：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/a860a901-891c-44c5-949d-287fa7267489.png)

前面的代码是不言自明的。Python 使用`try`和`except`，而不是`try`和`catch`。我们使用`raise`命令来手动抛出异常。最终块的工作方式与其他语言相同，核心条件是无论异常是否发生，最终块都应该被执行。

应该注意，在前面的例子中，我们在 except 块中处理异常时使用了一个通用的 Exception 类。如果我们确定代码可能引发什么样的异常，我们可以使用特定的异常处理程序，比如`IOError`、`ImportError`、`ValueError`、`KeyboardINterupt`和`EOFError`。最后，还应该记住，在 Python 中，我们可以在`try`块旁边使用一个 else 块。

# 摘要

在本章中，我们讨论了 Python 的 OOP、文件、目录、IO、XML、JSON、CSV 和异常处理。这些是 Python 的核心构造，被广泛使用。当我们转向使用 Python 实现渗透测试和网络安全时，我们将经常使用所有这些结构和概念，因此我们对它们有很好的理解是很重要的。在下一章中，我们将讨论更高级的概念，如 Python 中的多线程、多进程、子进程和套接字编程。通过那一章，我们将完成对 Python 先决条件的探索，这将进而引导我们学习有关 Python 的渗透测试和网络安全生态系统。

# 问题

1.  我们经常听说 Python 是一种脚本语言。将其用作面向对象的语言的典型优势是什么？你能想到任何特定的产品或用例吗？

1.  列举一些解析 XML 和 CSV 文件的方法。

1.  我们能否在不看类结构的情况下检测到类的所有属性？

1.  什么是方法装饰器？

# 进一步阅读

+   pandas: [`pandas.pydata.org/`](https://pandas.pydata.org/)

+   NumPy: [`www.numpy.org/`](http://www.numpy.org/)

+   Python GUI 编程：[`www.python-course.eu/python_tkinter.php`](https://www.python-course.eu/python_tkinter.php)


# 第四章：高级 Python 模块

本章将使我们熟悉一些高级 Python 模块，当涉及到响应时间、处理速度、互操作性和通过网络发送数据等参数时非常有用。我们将研究如何使用线程和进程在 Python 中进行并行处理。我们还将了解如何使用 IPC 和子进程在进程之间建立通信。之后，我们将探讨 Python 中的套接字编程，并通过实现反向 TCP shell 进入网络安全领域。本章将涵盖以下主题：

+   使用线程进行多任务处理

+   使用进程进行多任务处理

+   子进程

+   套接字编程的基础

+   使用 Python 实现反向 TCP shell

# 使用线程进行多任务处理

**线程**是一个轻量级的进程，与其父进程共享相同的地址和内存空间。它在处理器核心上并行运行，从而为我们提供了并行性和多任务处理能力。它与父进程共享相同的地址和内存空间的事实使得整个多任务处理操作非常轻量级，因为没有涉及上下文切换开销。在上下文切换中，当调度新进程以执行时，操作系统需要保存前一个进程的状态，包括进程 ID、指令指针、返回地址等。

这是一个耗时的活动。由于使用线程进行多任务处理不涉及创建新进程来实现并行性，线程在多任务处理活动中提供了非常好的性能。就像在 Java 中我们有`Thread`类或可运行接口来实现线程一样，在 Python 中我们可以使用`Thread`模块来实现线程。通常有两种在 Python 中实现线程的方法：一种是 Java 风格的，另一种更符合 Python 的风格。让我们一起来看看这两种方法。

以下代码显示了类似于 Java 的实现，我们在其中对线程类进行子类化并覆盖`run()`方法。我们将希望与线程并行运行的逻辑或任务放在`run()`方法内：

```py
import threading
>>> class a(threading.Thread):
... def __init__(self):
... threading.Thread.__init__(self)
... def run(self):
... print("Thread started")
... 
>>> obj=a()
>>> obj.start()
Thread started
```

在这里，我们有一个方法（`run()`），在这种情况下，它被设计为并行执行。这就是 Python 探索的另一种线程方法，在这种方法中，我们可以使用线程使任何方法并行执行。我们可以使用我们选择的任何方法，该方法可以接受任何参数。

以下代码片段显示了使用线程的另一种方式。在这里，我们可以看到我们通常定义了一个`add(num1,num2)`方法，然后在线程中使用它：

```py
>>> import threading
>>> def add(num1,num2):
...     print(num1 + num2)
... 
>>> for i in range(5):
...     t=threading.Thread(target=add,args=(i,i+1))
...     t.start()
... 
1
3
5
7
9
```

`for`循环创建了一个线程对象`t`。在调用`start()`方法时，会调用在创建线程对象时指定的目标参数中的方法。在前面的例子中，我们将`add()`方法传递给了线程实例。要传递给使用线程调用的方法的参数作为元组传递给`args`参数。`add()`方法通过线程调用了五次，并且输出显示在屏幕上，如前面的例子所示。

# 恶魔线程和非恶魔线程

必须注意的是，线程是从主程序中调用的，主程序不会退出（默认情况下）直到线程完全执行。原因是主程序默认以非恶魔模式调用线程，这使得线程在前台运行，而不是等待它在后台运行。因此，非恶魔线程是在前台运行的，导致主程序等待运行线程完成执行。另一方面，恶魔线程是在后台运行的，因此不会导致主程序等待其完成执行。请看下面的例子：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/6e397ca8-b18b-4f3c-8ba6-924d43fa7c65.png)

从前面的代码片段可以看出，当我们创建和执行一个非恶魔线程（默认情况下）时，在打印`Main Ended`后，终端窗口会暂停 4 秒，等待`ND`线程完成执行。当它完成时，我们会得到一个`Exit Non Demonic`的消息，这时主程序退出。在此之前，主程序不会退出。

让我们看看这在恶魔线程中如何改变，它在后台运行：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/1282d560-dbce-4a16-afca-418123f2620f.png)

在前面的代码片段中，我们看到了如何使用一个恶魔线程。有趣的是，主程序并没有等待恶魔线程完成执行。恶魔线程在后台运行，当它完成时，主线程已经从内存中退出，因此我们没有在屏幕上看到`Exit: Daemonic`的消息。在这种情况下，我们正在使用日志记录模块。默认情况下，日志记录模块将记录到`stdout`，在我们的情况下，这是终端。

# 线程加入和枚举

正如我们在前一节中看到的，主线程默认情况下会等待线程执行。尽管如此，主方法的代码仍将被执行，因为主线程将在不同的处理器核心上运行，与子线程不同。有时我们可能希望控制主线程的执行，与子线程的执行周期一致。假设我们希望在子线程执行后仅执行主线程的一部分代码。这可以通过`join()`方法实现。如果我们在主线程 M 的第 X 行调用线程 T 上的`join()`，那么主线程的 X+1 行将在 T 线程完成执行之前不会被执行。换句话说，我们将主线程的尾部与线程 T 连接起来，因此主线程的执行将在 T 完成之前暂停。让我们看下面的例子，我们在其中使用线程枚举和`join()`来批量执行线程。

主程序必须在退出之前验证所有线程是否已执行：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d55f6fa9-2ca8-4942-a604-9df8396064a2.png)

以下截图描述了前面代码的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/bcdb3300-4256-4c30-8704-458809e8c604.png)

# 线程之间的互通

尽管线程应该独立执行，但有许多情况下需要线程之间进行通信，例如如果一个线程需要在另一个线程达到某个特定点时才开始任务。假设我们正在处理生产者和消费者问题，其中一个线程（生产者）负责将项目放入队列。生产者线程需要向消费者线程发送消息，以便它知道可以从队列中消费数据。这可以通过 Python 中的线程事件来实现。调用`threading.event()`返回一个事件实例，可以使用`set()`方法设置，使用`clear()`方法重置。

在下面的代码块中，我们将看到一个示例，其中一个线程将递增一个计数器。另一个线程需要在计数器值达到 5 时执行一个动作。必须注意，事件还有一个`wait()`方法，它会等待事件被阻塞或设置。事件可以等待一个超时间隔，或者可以无限期等待，但一旦设置标志为`true`，`wait()`方法将不会实际阻塞线程的执行。这在下面的代码中有所体现：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/1032f145-f810-4804-85e9-895ad8059ce6.png)

# 线程并发控制

有许多情况下，多个线程需要共享资源。我们希望确保如果一个线程正在改变对象的状态，另一个线程必须等待。为了避免不一致的结果，在改变其状态之前必须锁定共享资源。状态改变后，应释放锁。Python 提供了线程锁来做到这一点。看一下下面的代码片段`Thread_locking.py`，它演示了线程锁定和并发控制：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/f5d301dc-49fd-4ef6-a601-f7f981c008b7.png)

前面的代码片段显示了线程锁定。在这里，`count`是一个多个线程尝试更新的共享变量。第一个输出没有锁定机制（第 16 行和第 22 行被注释掉）。当没有锁定时，可以看到`thread_3`在获取锁时将值读为 1，`thread_4`也是一样。每个线程将计数的值增加 1，但到`thread_4`结束时，计数的值为 3。当我们使用锁定时，可以从第二个输出中看到，当共享资源`counter`被更新时，没有其他线程实际上可以读取它，因此获得的结果是一致的。

# 使用进程进行多任务处理

与线程模块一样，多进程模块也用于提供多任务处理能力。线程模块实际上有点误导：它在 Python 中的实现实际上不是用于并行处理，而是用于在单个核心上进行时间共享的处理。默认的 Python 实现**CPython**在解释器级别上不是线程安全的。每当使用线程时，都会在 Python 线程中访问的对象上放置一个**全局解释器锁**（**GIL**）。这个锁以时间共享的方式执行线程，给每个线程一小部分时间，因此我们的程序中没有性能增益。因此，多进程模块被开发出来，以提供并行处理给 Python 生态系统。这通过将负载分布到多个处理器核心上来减少执行时间。看一下下面的代码，它使用了多进程：

```py
>>> import multiprocessing
>>> def process_me(id):
... print("Process " +str(id))
... 
>>> for i in range(5):
... p=multiprocessing.Process(target=process_me,args=(i,))
... p.start()
>>> Process 0
>>> Process 1
>>> Process 2
>>> Process 3
>>> Process 4
import multiprocessing as mp
>>> class a(mp.Process):
... def __init__(self):
... threading.Thread.__init__(self)
... def run(self):
... print("Process started")
... 
>>> obj=a()
>>> obj.start()
Process started
```

前面的代码片段表示了两种多进程的实现：一种简单的方法和一种基于类的方法。

# 恶魔和非恶魔进程

我们已经学习了什么是恶魔和非恶魔线程。同样的原则也适用于进程。恶魔进程在后台运行而不阻塞主进程，而非恶魔进程在前台运行。这在下面的示例中显示出来：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/75c7a70a-38f0-4f46-b35e-17593e3f939a.png)

可以从前面的代码片段中看到，当我们创建和执行一个非恶魔进程（默认选项）时，如输出 1 和第 20 行所示，在打印`Main Ended`后，终端窗口会在等待非恶魔进程完成执行时停顿 4 秒。当它完成时，我们会得到`Exit Non Daemonic`的消息，这时主程序退出。在第二种情况下（如输出 2 所示），主程序不会等待恶魔进程完成执行。恶魔进程在后台运行，当它完成时，主线程已经从内存中退出。因此，我们没有在屏幕上看到`Exit :Daemonic`的消息打印出来。

# 进程连接、枚举和终止

关于线程连接和枚举的相同理论也可以应用于进程。进程可以连接到主线程或另一个进程，以便另一个线程在连接的进程完成之前不会退出。除了连接和枚举之外，我们还可以在 Python 中显式终止进程。

看一下以下代码片段，演示了上述概念。以下代码的目标是生成一些进程，并使主进程等待 10 秒，以便生成的进程完成执行。如果它们没有完成，那些仍在运行的进程将在退出之前被终止：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/b26127f3-7bd5-4c9c-a991-e4171692dab8.png)

上述代码`Join_enumerate_terminate.py`非常简单；我们所做的与之前的线程相同。这里唯一的区别是我们仅应用了 3 秒的加入操作，以便故意获得一些仍在运行的进程。然后我们通过对它们应用`terminate()`来终止这些进程。

# 多进程池

多进程库中最酷的功能之一是**池化**。这让我们可以将任务均匀分配到所有处理器核心上，而不必担心同时运行的进程数量。这意味着该模块有能力批量生成一组进程。假设我们将批处理大小定义为 4，这是我们可能拥有的处理器核心数量。这意味着，任何时候，可以执行的最大进程数量为四个，如果其中一个进程完成执行，也就是说现在有三个正在运行的进程，模块会自动选择下一组进程，使批处理大小再次等于四。该过程将持续进行，直到我们完成分布式任务或明确定义条件。

看一下以下示例，我们需要在八个不同的文件中写入 800 万条记录（每个文件中有 100 万条记录）。我们有一个四核处理器来执行此任务。理想情况下，我们需要两次生成一个批处理大小为四的进程，以便每个进程在文件中写入 100 万条记录。由于我们有四个核心，我们希望每个核心执行我们任务的不同部分。如果我们选择一次生成八个进程，我们将在上下文切换中浪费一些时间，因此我们需要明智地使用我们的处理器和处理能力，以获得最大的吞吐量：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/7fc29816-ce6c-46a5-ab31-5a75a7b60de3.png)

在上述代码`Multiprocess_pool.py`中，我们在第 30 行创建了一个多进程池。我们将池的大小定义为`size=mp.cpu_count()`，在我们的情况下是`4`，因此我们定义了一个大小为四的池。我们需要创建八个文件，每个文件包含 100 万条记录。我们使用`for`循环来定义八个进程，这些进程将通过在创建的池对象上调用`apply_async()`来发送到池对象。`apply_async()`方法期望我们希望使用多进程模块作为参数执行的方法的名称。第二个参数是传递给我们希望执行的方法的参数。请注意，当使用池模块执行进程时，进程还具有从方法返回数据的能力。

从输出中可以看到，没有同时执行的进程超过四个。还可以验证，第一个完成的进程是`Forkpoolworker4`。当批处理大小为 3 时，模块会立即生成另一个进程。这可以通过输出来验证，输出中在第一部分的第六行中声明了`Started process Poolworker4`。

请注意，两个批次是并行执行的。每个进程花费了 13 到 14 秒，但由于它们是并行执行的，每个批次的整体执行时间为 14 秒。因此，两个批次的总时间为 28 秒。很明显，通过使用并行处理，我们在短短 28 秒内解决了问题。如果我们选择顺序或线程方法，总时间将接近*(13*8) = 104*秒。作为练习，您可以自己尝试。

现在让我们举另一个例子，展示池模块的另一个强大功能。假设作为我们的要求的一部分，我们需要解析创建的 800 万个文件中的四个文件，其 ID`％1700`的结果为零。然后我们必须将所有四个文件的结果合并到另一个文件中。这是分布式处理和结果聚合的一个很好的例子：这些进程不仅应该并行读取文件，还必须聚合结果。这与 Hadoop 的映射-减少问题有些类似。在典型的映射-减少问题中，有两组操作：

+   **映射**：这涉及将一个巨大的数据集分布在分布式系统的各个节点上。每个节点处理它接收到的数据块。

+   **减少**：这是聚合操作，其中来自每个节点的映射阶段的输出被返回，并且根据逻辑，最终聚合并返回结果。

我们在这里做的是相同的事情，唯一的区别是我们使用处理器核心代替节点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/ba23f995-6aaf-4f2f-ae31-75806d6206f2.png)

如前面的代码片段所示，借助`Pool`模块的`map()`方法，我们可以让多个进程并行处理不同的文件，然后将所有结果组合并作为单个结构发送。这些进程是并行执行的，对于`record_id％1700`返回零的记录将被返回。最后，我们将聚合结果保存在`Modulo_1700_agg`文件中。这是多进程模块的一个非常强大的特性，如果使用正确，可以大大减少处理时间和聚合时间。

# 子进程

从另一个进程调用外部进程称为**子处理**。在这种情况下，进程之间的通信是通过操作系统管道进行的。换句话说，如果进程 A 被进程 B 作为子进程调用，那么进程 B 可以通过操作系统管道向其传递输入，也可以通过操作系统管道从中读取输出。在自动化渗透测试和使用 Python 调用其他工具和实用程序时，该模块至关重要。Python 提供了一个非常强大的模块，称为`subprocess`来处理子处理。看一下下面的代码片段`Subprocessing.py`，它展示了如何使用子处理来调用一个名为`ls`的系统命令：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/efe81042-63ce-4ee0-a4ea-6fe512989192.png)

在前面的代码片段中，我们使用了`subprocess.Popen()`方法来调用`subprocess`。还有一些其他调用或调用`subprocess`的方法，比如`call()`，但我们在这里讨论的是`Popen`。这是因为`Popen`方法返回将要生成的进程的进程 ID，从而使我们对该进程有很好的控制。`Popen`方法接受许多参数，其中第一个实际上是要在操作系统级别执行的命令。命名参数包括`stderr=subprocess.PIPE`，这意味着如果外部程序或脚本产生错误，该错误必须重定向到操作系统管道，父进程必须从中读取错误。`stdout=subprocess.PIPE`表示子进程产生的输出也必须发送到管道到父进程。`shell=True`表示无论给出什么命令，第一个参数都必须被视为`shell`命令，如果有一些参数，它们必须作为要调用的进程的参数传递。最后，如果我们希望父进程读取子进程产生的输出和错误，我们必须在调用的`subprocess`上调用`communicate()`方法。`communicate()`方法打开`subprocess`管道，通信从子进程向管道的一端写入开始，父进程从另一端读取。必须注意`communicate()`方法将使父进程等待子进程完成。该方法返回一个元组，其中 0 号索引处是输出，1 号索引处是标准错误。

应该注意的是，我们在现实世界的示例中不应该使用`shell=True`，因为这会使应用程序容易受到 shell 注入的攻击。避免使用以下行：

`>>> subprocess.Popen(command, shell=True) #这将删除所有内容！！`

看一下以下示例，我们将使用`shell=False`。使用`shell=False`，我们调用的进程/命令的命令和参数必须作为列表分开传递。让我们尝试使用`shell=False`执行`ls -l`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/2b25936f-6483-4e7e-b78d-28918afffe3b.png)

这就是我们如何使用 Python 执行外部进程的方式，借助于 subprocess 模块。

# 套接字编程基础

当我们谈论套接字时，我们指的是 TCP 套接字和 UDP 套接字。**套接字**连接只是 IP 地址和端口号的组合。我们可以想到的每个在端口上运行的服务都在内部实现和使用套接字。

例如，我们的 Web 服务器总是在端口`80`（默认情况下）上监听，它打开一个套接字连接到外部世界，并绑定到具有 IP 地址和端口`80`的套接字。套接字连接可以以以下两种模式使用：

+   服务器

+   客户端

当套接字用作服务器时，服务器执行的步骤顺序如下：

1.  创建一个套接字。

1.  绑定到套接字。

1.  在套接字上监听。

1.  接受连接。

1.  接收和发送数据。

另一方面，当套接字连接用作客户端连接到服务器套接字时，步骤顺序如下：

1.  创建一个套接字。

1.  连接到套接字。

1.  接收和发送数据。

看一下以下代码片段`server_socket.py`，它在端口`80`实现了一个 TCP 服务器套接字：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/c22814d3-51d0-4002-90b1-323f1a762121.png)

在前面的案例中，我们使用`socket.socket`语句创建了一个套接字。在这里，`socket.AF_INET`表示 IPv4 协议，`socket.SOCK_STREAM`表示使用基于流的套接字数据包，这些数据包仅是 TCP 流。`bind()`方法以元组作为参数，第一个参数是本地 IP 地址。您应该将其替换为您的个人 IP，或`127.0.0.1`。传递给元组的第二个参数是端口，然后调用`bind()`方法。然后我们开始监听套接字，最后开始一个循环，我们接受客户端连接。请注意，该方法创建了一个单线程服务器，这意味着如果任何其他客户端连接，它必须等到活动客户端断开连接。`send()`和`recv()`方法是不言自明的。

现在让我们创建一个基本的客户端套接字代码`client_socket.py`，连接到之前创建的服务器并向其传递消息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/8a85859c-469a-48c9-a9ea-bfa613bc246f.png)

客户端和服务器套接字产生的输出如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/4f357662-4615-410d-8204-25603f3bd866.png)

这是我们如何使用 UDP 进行套接字连接的方式：

```py
sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

```

# 使用 Python 进行反向 TCP shell

现在我们已经了解了子进程、多进程等基础知识，使用 Python 实现基本的 TCP 反向 shell 非常简单。在这个例子`rev_tcp.py`中，我们将使用基于 bash 的反向 TCP shell。在本书的后面章节中，我们将看到如何完全使用 Python 传递反向 shell：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/91cc6614-9d64-417f-b396-ff81b57f0271.png)

需要注意的是，`OS.dup2`用于在 Python 中创建文件描述符的副本。`stdin`被定义为文件描述符`0`，`stdout`被定义为文件描述符`1`，`stderr`被定义为文件描述符`2`。代码行`OS.dup2(s.fileno(),0)`表示我们应该创建`stdin`的副本并将流量重定向到套接字文件，该套接字文件恰好位于本地主机和端口`1234`（Netcat 正在监听的地方）。最后，我们以交互模式调用 shell，由于我们没有指定`stderr`、`stdin`和`stdout`参数，默认情况下，这些参数将被发送到系统级的`stdin`和`stdout`，再次映射到程序的范围内的套接字。因此，前面的代码片段将以交互模式打开 shell，并将其传递给套接字。所有输入都从套接字作为`stdin`接收，所有输出都通过`stdout`传递到套接字。可以通过查看生成的输出来验证这一点。

# 总结

在本章中，我们讨论了一些更高级的 Python 概念，这些概念可以帮助我们增加吞吐量。我们讨论了多进程 Python 模块以及它们如何用于减少所需时间并增加我们的处理能力。通过本章，我们基本上涵盖了我们进入渗透测试、自动化和各种网络安全用例所需的 Python 的一切。需要注意的是，从现在开始，我们的重点将是应用我们到目前为止所学的概念，而不是解释它们的工作原理。因此，如果您有任何疑问，我强烈建议您在继续之前澄清这些疑问。在下一章中，我们将讨论如何使用 Python 解析 PCAP 文件，自动化 Nmap 扫描等等。对于所有的安全爱好者，让我们开始吧。

# 问题

1.  我们可以使用 Python 的其他多进程库吗？

1.  在 Python 中，线程在哪些情况下会变得有用，考虑到它们实际上在同一个核心上执行？

# 进一步阅读

+   多进程：[`docs.python.org/2/library/multiprocessing.html`](https://docs.python.org/2/library/multiprocessing.html)

+   子进程：[`docs.python.org/2/library/subprocess.html`](https://docs.python.org/2/library/subprocess.html)


# 第五章：漏洞扫描器 Python - 第 1 部分

当我们谈论端口扫描时，自动想到的工具就是 Nmap。Nmap 有良好的声誉，可以说是最好的开源端口扫描器。它具有大量功能，允许您在网络上执行各种扫描，以发现哪些主机是活动的，哪些端口是开放的，以及主机上运行的服务和服务版本。它还有一个引擎（Nmap 扫描引擎），可以扫描用于发现运行服务的常见漏洞的 NSE 脚本。在本章中，我们将使用 Python 来自动执行端口扫描的过程。本章将为我们的自动化漏洞扫描器奠定基础，并将补充下一章，该章将专注于自动化服务扫描和枚举。

本章涵盖以下主题：

+   介绍 Nmap

+   使用 Python 构建网络扫描器

# 介绍 Nmap

我们的端口扫描器将基于 Nmap 构建，具有额外的功能和能力，例如并行端口扫描目标，暂停和恢复扫描。它还将具有一个 Web GUI，我们可以用来进行扫描。

让我们来看看 Nmap 的各种属性：

+   以下截图显示了 Nmap 可用的不同扫描技术：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/bc202233-ec7a-4cf2-9f45-f460cbf1989f.png)

+   以下截图显示了主机发现和端口规范，以及一些示例：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/6d0cc2a1-1a99-4b91-a955-7c716b98e2b4.png)

+   以下截图显示了服务和版本检测以及操作系统检测，以及一些示例：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/0916b622-58df-43d6-8352-47abde235a89.png)

+   以下截图显示了时间和性能，以及一些示例：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/2c977b22-4f6f-4759-a377-2f524a871ce2.png)

+   以下截图显示了 NSE 脚本以及一些示例：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/65ff3c58-e849-4150-adf9-d23d42e34175.png)

+   以下截图显示了防火墙/IDS 回避和欺骗，以及一些示例：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/73d765cb-3e08-4f16-8897-5b8e5440adb1.png)

+   以下截图显示了一些有用的 Nmap 输出示例：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d133fd74-18da-4b31-931c-965053f0e6fb.png)

前面的截图提供了我们在日常操作中经常使用的 Nmap 命令的全面列表。我们将不会涵盖如何在终端上运行 Nmap 命令，因为这被认为是直接的。

需要注意的是，从现在开始，我们将使用 Kali Linux 作为我们的渗透测试实验室操作系统。因此，我们将在 Kali Linux 上实施所有 Python 自动化。要安装 Kali Linux VM/VirtualBox 镜像，请参考[`www.osboxes.org/Kali-linux/`](https://www.osboxes.org/Kali-linux/)。要下载 VirtualBox，请参考[`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads)。下载后，执行以下截图中显示的步骤。

首先，输入新虚拟机的名称，类型和版本；在我们的案例中，这是 Linux 和 Debian（64 位）。之后，分配内存大小：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/8660a60c-33a3-4bbd-a4ae-89f264016990.png)

接下来，选择虚拟硬盘文件，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/fb56c950-1a2e-40aa-b206-c3316e593f3e.png)

# 使用 Python 构建网络扫描器

现在我们已经设置好了 VirtualBox 镜像，让我们来看一个简单的 Python 脚本，它将帮助我们调用 Nmap 并启动扫描。稍后，我们将优化此脚本以使其更好。最后，我们将使其成为一个功能齐全的端口扫描 Python 引擎，具有暂停，恢复和多进程能力：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/f39d287f-fe41-46e2-9472-e1905e658275.png)

前面脚本产生的信息对 Python 代码来说很难过滤和存储。如果我们想要将所有打开的端口和服务存储在字典中，使用前面的方法会很困难。让我们考虑另一种方法，可以解析并处理脚本产生的信息。我们知道`oX`标志用于以 XML 格式生成输出。我们将使用`oX`标志将 XML 字符串转换为 Python 字典，如下节所示。

# 使用脚本控制 Nmap 输出

在下面的示例中，我们重复使用了之前学习的相同概念。我们将 Nmap 输出重定向为 XML 格式显示在屏幕上。然后，我们将产生的输出作为字符串收集起来，并使用`import xml.Etree.elementTree` Python 模块作为`ET`，以将 XML 输出转换为 Python 字典。使用以下代码，我们可以使用我们的程序控制 Nmap 并过滤出所有有用的信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/642b97d5-7cb5-4089-aaa2-186d75977dbc.png)

然后，我们可以将这些信息存储在数据库表中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/18f9a7f3-34e3-4fe4-a586-cca99832a8a4.png)

接下来，运行以下命令：

```py
Nmap=NmapPy(["Nmap","-Pn","-sV","-oX","-","127.0.0.1"])
Nmap.scan()
```

虽然前面的方法很好，并且让我们对 Nmap 输出有细粒度的控制，但它涉及处理和解析代码，这可能是我们每次使用 Nmap 进行扫描时都不想编写的。另一种更好的方法是使用 Python 内置的 Nmap 包装模块。我们可以使用`pip install`安装 Python 的 Nmap 模块，它几乎与我们之前做的事情一样，但允许我们避免编写所有处理和子处理逻辑。这使得代码更清晰、更可读。每当我们希望有更细粒度的控制时，我们总是可以回到前面的方法。

# 使用 Nmap 模块进行 Nmap 端口扫描

现在让我们继续安装 Python Nmap 模块，如下所示：

```py
pip install Nmap
```

上述命令将安装`Nmap`实用程序。以下部分提供了有关如何使用该库的概述：

```py
import Nmap # import Nmap.py module
 Nmap_obj = Nmap.PortScanner() # instantiate Nmap.PortScanner object
 Nmap_obj.scan('192.168.0.143', '1-1024') # scan host 192.1680.143, ports from 1-1024
 Nmap_obj.command_line() # get command line used for the scan : Nmap -oX - -p 1-1024 192.1680.143
 Nmap_obj.scaninfo() # get Nmap scan informations {'tcp': {'services': '1-1024', 'method': 'connect'}}
 Nmap_obj.all_hosts() # get all hosts that were scanned
 Nmap_obj['192.1680.143'].hostname() # get one hostname for host 192.1680.143, usualy the user record
 Nmap_obj['192.1680.143'].hostnames() # get list of hostnames for host 192.1680.143 as a list of dict
 # [{'name':'hostname1', 'type':'PTR'}, {'name':'hostname2', 'type':'user'}]
 Nmap_obj['192.1680.143'].hostname() # get hostname for host 192.1680.143
 Nmap_obj['192.1680.143'].state() # get state of host 192.1680.143 (up|down|unknown|skipped)
 Nmap_obj['192.1680.143'].all_protocols() # get all scanned protocols ['tcp', 'udp'] in (ip|tcp|udp|sctp)
 Nmap_obj['192.1680.143']['tcp'].keys() # get all ports for tcp protocol
 Nmap_obj['192.1680.143'].all_tcp() # get all ports for tcp protocol (sorted version)
 Nmap_obj['192.1680.143'].all_udp() # get all ports for udp protocol (sorted version)
 Nmap_obj['192.1680.143'].all_ip() # get all ports for ip protocol (sorted version)
 Nmap_obj['192.1680.143'].all_sctp() # get all ports for sctp protocol (sorted version)
 Nmap_obj['192.1680.143'].has_tcp(22) # is there any information for port 22/tcp on host 192.1680.143
 Nmap_obj['192.1680.143']['tcp'][22] # get infos about port 22 in tcp on host 192.1680.143
 Nmap_obj['192.1680.143'].tcp(22) # get infos about port 22 in tcp on host 192.1680.143
 Nmap_obj['192.1680.143']['tcp'][22]['state'] # get state of port 22/tcp on host 192.1680.143
```

这为 Alexandre Norman 编写的出色实用程序提供了一个快速入门。有关此模块的更多详细信息，请访问[`pypi.org/project/python-Nmap/`](https://pypi.org/project/python-nmap/)。我们将使用相同的模块来进行 Nmap 的并行端口扫描，并具有暂停和恢复扫描的附加功能。

# 目标和架构概述

在深入了解代码细节之前，重要的是我们理解我们在做什么以及为什么这样做。默认情况下，Nmap 非常强大并且具有大量功能。在使用操作系统工具进行典型的网络渗透测试时，采用的方法是使用 Nmap 进行端口扫描以获取打开的端口、运行的服务和服务版本。根据端口扫描结果，测试人员通常使用各种服务扫描脚本来获取服务版本和相关的 CVE ID（如果有的话），然后再根据这些，测试人员可以使用 Metasploit 来利用这些漏洞。对于服务扫描，测试人员使用各种开源技术，如 NSE、Ruby、Python、Java、bash 脚本，或者诸如 Metasploit、w3af、nikto、Wireshark 等工具。整个周期形成了一个需要每次遵循的流程，但它非常分散。我们在这里尝试提出的想法是，在接下来的部分中，我们将编排渗透测试人员需要执行的所有活动，并使用 Python 自动化所有这些活动，以便所有需要运行的工具和脚本都可以预先配置并一次性运行。我们不仅仅是编排和自动化活动，还使代码优化以利用多进程和多线程来减少扫描时间。

代码的架构可以分为以下几部分：

+   端口扫描（服务/端口发现）

+   服务扫描

# 端口扫描

端口扫描部分是指我们将如何在 Python 代码中实现它。想法是使用线程和多进程的组合。如果我们想要扫描 10 个主机，我们将把它分成 5 个批次。每个批次有两个主机（批次大小可以根据实验室机器的 RAM 和处理器能力增加）。对于四核处理器和 2GB RAM，批次大小应为 2。在任何时候，我们将处理一个批次，并为每个主机分配一个单独的线程。因此，将有两个线程并行运行，扫描两个主机。一旦一个主机被分配给一个线程，线程将选择要扫描该主机的端口范围（假设在 1 到 65535 之间）。逻辑不是顺序扫描端口，而是将整个范围分成三个大小为 21,845 的块。现在，单个主机的三个块并行扫描。如果处理器核心数量更多，块大小可以增加。对于四核处理器和 2GB RAM，建议使用三个块：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/43439e13-237b-41cd-9532-19de6878b022.png)

总之，主机被分成大小为 2 的批次，并专门用于单个主机。进一步的端口被分成块，并且一个多进程过程被专门用于扫描每个块，使得端口扫描可以并行进行。因此，在任何时候，将有两个线程和六个进程用于端口扫描活动。如果用户想要暂停扫描，他们可以在终端窗口使用*Ctrl* + *C*来暂停。当他们重新运行代码时，他们将被提示选择启动新的扫描或恢复先前暂停的扫描。

# 服务扫描

当端口扫描活动结束时，我们将所有结果保存在我们的 MySQL 数据库表中。根据发现的服务，我们有一个配置好的脚本列表，如果找到特定的服务，我们需要执行这些脚本。我们使用 JSON 文件来映射服务和相应的脚本以执行。用户将得到端口扫描结果，并有选择重新配置或更改结果的选项，以减少误报。一旦最终配置完成，服务扫描就开始了。我们从数据库中逐个选择一个主机，并根据发现的服务，从 JSON 文件中读取适当的脚本，为这个特定的主机执行它们，并将结果保存在数据库中。这将持续到所有主机的服务都被扫描。最后，生成一个包含格式化结果和屏幕截图的 HTML 报告，以附加到概念验证（POC）报告中。

服务扫描的架构图如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d773d881-a6d1-49a6-8553-07c81a5aed82.png)

以下屏幕截图显示了 JSON 文件如何配置以执行脚本：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/0c8f1abe-7e5b-4057-a877-13af911e8717.png)

如前面的屏幕截图所示，JSON 文件中有各种类别的命令。Metasploit 模板显示了用于执行 Metasploit 模块的命令。单行命令用于执行 NSE 脚本和所有非交互式的模块或脚本。其他类别包括`interactive_commands`和`single_line_sniffing`，在这里我们需要嗅探流量并执行脚本。JSON 文件的一般模板如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/705fd705-0c7b-48aa-b505-cf34c0fb0b9d.png)

键是服务的名称。标题有文件描述。`method_id`是应调用的实际 Python 方法，以调用要执行的外部脚本。请注意，对于单行命令，我们还在`args`参数下的第一个参数中指定了以秒为单位的超时参数。

# 代码的更详细查看

让我们来看一下我们将使用 Python 构建网络扫描器所需的基本文件和方法的概述：

+   `Driver_main_class.py`：这是提示用户输入信息的 Python 类、文件或模块，例如项目名称、要扫描的 IP 地址、要扫描的端口范围、要使用的扫描开关和扫描类型。

+   `main_class_based_backup.py`：这是包含我们之前讨论的所有端口扫描主要逻辑的 Python 类、文件或模块。它从`Driver_main_class.py`获取输入并将输入存储在数据库中。最后，它使用线程和多进程在我们的目标上启动端口扫描。

+   `Driver_scanner.py`：端口扫描结束后，下一步是执行服务扫描，这个 Python 类调用另一个类`driver_meta.py`，该类获取要执行服务扫描的项目名称或 ID。

+   `driver_meta.py`：这个类显示端口扫描的默认结果，并给用户重新配置结果的选项。重新配置后，该类从数据库表中读取当前项目的主机，为其执行服务扫描。对于每个主机，它然后读取 JSON 文件以获取要执行的命令，并对于要执行的每个命令，它将控制传递给另一个文件`auto_comamnds.py`。

+   `auto_commands.py`：这个文件从`driver_meta.py`获取参数，并调用外部技术，如 NSE、Ruby、Python、Java、bash 脚本，或者工具，如 Metasploit、Wireshark 和 Nikto。然后用于执行所选服务、主机和端口的服务扫描。命令执行结束后，它将结果返回给`driver_meta.py`以保存在数据库中。

+   `IPtable.py`：这是将端口扫描结果存储在数据库表中的类。它代表了我们的漏洞扫描器的数据层。

+   `IPexploits.py`：这是将服务扫描结果存储在数据库表中的类。它还代表了我们的漏洞扫描器的数据层。

# 入门

整个代码库可以在以下 GitHub 存储库中找到。安装说明在主页上指定。我们将查看代码部分和具有实现扫描器的中心逻辑的文件。请随时从存储库下载代码并按照执行部分中指定的方式执行。或者，我创建了一个即插即用的 Kali VM 映像，其中包含所有先决条件安装和开箱即用的代码库。可以从 URL[<https://drive.google.com/file/d/1e0Wwc1r_7XtL0uCLJXeLstMgJR68wNLF/view?usp=sharing>](http://%3Chttps://drive.google.com/file/d/1e0Wwc1r_7XtL0uCLJXeLstMgJR68wNLF/view?usp=sharing%3E)下载并无忧地执行。默认用户名为：`PTO_root`，密码为：`PTO_root`

如前所述，我们将讨论代码的中心逻辑，该逻辑由以下代码片段表示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/906ee2de-700c-48dc-aa75-c98131399c4e.png)

整个类可以在 URL[<https://github.com/FurqanKhan1/Dictator/blob/master/Dictator_service/Driver_main_class.py>](http://%3Chttps://github.com/FurqanKhan1/Dictator/blob/master/Dictator_service/Driver_main_class.py%3E)找到`Driver_main_class.py`。该类的构造函数声明了在`main_class_based_backup.py`中找到的`NmapScan`类的对象。**（1）**和**（2）**标记的行是在收集所有输入后触发实际逻辑的地方，包括项目名称、IP、端口范围、扫描开关和扫描类型。扫描类型 1 表示新扫描，而扫描类型 2 表示恢复先前暂停的现有扫描。`self.scanbanner()`方法提示用户输入用户希望使用的 Nmap 扫描开关。有七种开关类型在日常扫描中最常用。以下截图显示了配置文件`Nmap.cfg`中配置的扫描开关：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/db825a7f-52ec-40d7-a2d2-76923a5600b8.png)

以下代码片段代表了`main_class_based_backup.py`类的流程：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/4f7219c0-f153-451e-aa10-0381f5441da9.png)

这个截图代表了主要的`NmapScan`类。该类的构造函数包含了我们将在整个类的执行流程中使用的各种变量。如前所述，`IPtable`是一个用于将数据推送到后端数据库的 Python 类。数据库的结构将在`db_structure`部分讨论。目前，我们应该理解，通过使用 MySQLdb db 连接器/Python 模块，我们将通过`IPtable`类将所有端口扫描的详细信息推送到后端表中。此外，`textable`是一个用于在终端窗口上绘制表格以表示数据的 Python 模块。`Simple_Logger`是一个用于在文件中记录调试和错误消息的 Python 模块。

正如我们之前所看到的，当我们查看`Driver_main_class.py`时，实际执行流程始于`NmapScan`类的`driver_main`方法（在`Driver_main_class.py`类的代码片段**(1)**和**(2)**中突出显示）。以下截图更详细地显示了这个方法：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/5bfc3fe2-0ae7-4311-9419-1ed0006c3c4a.png)

前面的代码片段很简单。该方法接收来自调用者的所有参数。我们将扫描的开始时间保存在一个名为`start`的变量中。突出显示的代码片段**(1)**调用了同一类的另一个`main`方法，并将所有接收到的参数传递给它。这是启动所有主机的端口扫描的方法。一旦调用的`self.main`方法完成执行，如代码片段(2)所示，我们需要检查所有主机是否成功扫描。这可以从一个后台表中推断出，该表维护了所有正在扫描的主机的`status_code`，由当前项目 ID 引用。如果主机成功扫描，状态将是 complete，否则将是 processing 或 incomplete。如果当前项目不处于暂停状态，并且仍有一些主机的状态是 incomplete 或 processing，我们需要再次处理这些主机，这是代码片段(3)所突出显示的内容。如果所有主机的处理状态都是 complete，我们将最终项目状态更新为 complete，由`self.IPtable.clearLogs`方法指定。最后，我们显示执行时间（以秒为单位）。在下一个代码片段中，我们将看一下`NmapScan`类的`main`方法，让事情开始运行：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/e985decc-f655-423b-a6ae-6099dce2091b.png)

`main`方法开始检查`scan_type`。必须注意`scan_type="1"`表示新扫描，`scan_type="2"`表示恢复先前暂停的扫描。代码还检查扫描模式。注意`c`代表命令行模式。我们正在制作的漏洞扫描器在 GUI 模式和命令行模式下都可以操作，我们稍后会讨论。我们现在可以忽略`g-init`和`g-start`模式。

在第 6 行，代码将当前项目名称存储在后端数据库中。代码的逻辑由`self.db_projectname`方法处理。该方法接受项目名称，将其存储在数据库表中，返回一个唯一的项目 ID，并将其存储在名为`self.CURRENT_PROJECT_ID`的类变量中。它还在父项目文件夹的根目录下的`Results`文件夹下创建一个名为`Results_project_id`的文件夹。该方法的完整细节可以在以下路径找到：[<https://github.com/FurqanKhan1/Dictator/blob/master/Dictator_service/main_class_based_backup.py>](http://%3Chttps://github.com/FurqanKhan1/Dictator/blob/master/Dictator_service/main_class_based_backup.py%3E)。

高亮显示的代码片段**(2)**调用了一个名为`self.numofips(targethosts)`的方法，该方法返回要扫描的主机数量。如果有多个主机，它们应该被输入为逗号分隔（例如`192.168.250.143`，`192.168.250.144`）或 CIDR 表示法（例如`192.168.250.140/16`）。如果它们是逗号分隔的，那么`targethosts.split(',')`将分割输入并返回 IP 列表给`listip`变量。如果是 CIDR 表示法，代码片段**(3)**将把 CIDR IP 列表转换为本机 Python IP 列表并返回结果，结果将再次存储在`listip`变量中。

高亮显示的代码片段**(4)**负责将端口分成小块并将它们存储在数据库中，与之前讨论的当前项目 ID 相关。假设我们有两个要扫描的主机，`192.168.250.143`和`192.168.250.136`，并且我们想要扫描主机的整个端口范围（从 1 到 65,535）。在这种情况下，方法的调用将是`self.makeBulkEntries([192.168.250.143,192.168.250.136], "1-65535")`。该方法处理输入并将其转换为以下内容：

`[[192.168.250.143,"1-21845"],[192.168.250.143,"21845-43690"],[192.168.250.143,"43690-65535"],[192.168.250.144,"1-21845"],[192.168.250.144,"21845-43690"],[192.168.250.144,"43690-65535"]]`。

前面的列表被插入到数据库表中，共有六行，每行的扫描状态为不完整。

在下一行，`threading.enumurate()`返回当前运行线程的数量。它应该返回一个值为 1，因为只有主线程在运行。

高亮显示的代码片段**(5)**调用了`startProcessing`方法。这个方法从后端数据库表中读取一批不完整状态的不同主机，然后为这些主机分配一个线程进行扫描。必须注意的是，`self.N`表示批处理大小，我们已经讨论过它是 2，并且在类的构造函数中初始化。我们可以增加这个数字以获得更高的处理器数量。

`startProcessing`方法会生成线程并为每个未扫描的主机分配一个线程，但必须有一些逻辑来检查主机何时完全扫描，例如，如果批处理大小为`2`，并且扫描了 1 个主机，它会提取另一个未扫描的主机并为其分配一个线程。该方法还需要检查所有主机是否完全扫描。如果是这种情况，扫描必须结束。这段逻辑由`start_Polling()`方法处理，如标有**(6)**的代码片段所示。

高亮显示的代码片段**(7)**将调用一个方法来恢复暂停的扫描。因此，它将加载所有处于暂停状态的扫描的项目 ID。用户可以选择任何有效的项目 ID 来恢复扫描。

最后，代码片段**(8)**提到了`Start_Polling()`，它具有与之前讨论的相同功能，但在这种情况下是为恢复的扫描。

在下面的代码片段中，`startProcessing()`方法简单地从数据库表中提取所有不完整状态的不同主机，并将它们放入本机 Python 列表`All_hosts`中。对于当前示例，它将返回以下列表：[`192.168.250.143`, `192.168.250.144`]。之后，高亮显示的代码片段**(1)**将调用`startThreads`方法，其中一个线程将被分配给一个主机：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/9c9a7de3-73d9-40fe-b127-81948237195c.png)

`startThreads()`方法很简单。我们遍历主机列表并为每个主机分配一个线程，通过调用`obj.simplescanner`方法并将当前 IP 列表传递给它。对于我们当前的示例，`simplescanner`方法将被调用两次。首先，它将为线程 1 调用，该线程具有 IP 地址`192.168.250.143`，然后它将为线程 2 调用，该线程具有 IP 地址`192.168.250.144`。这由代码片段**(1)**突出显示。

`simpleScanner（）`方法也很简单，使用了我们之前学习的多进程概念。首先，它读取调用它的当前主机的所有记录或端口块。例如，当它针对主机`192.168.250.143`调用时，它会读取数据库行[`[192.168.250.143，"1-21845"]，[192.168.250.143，"21845-43690"]和[192.168.250.143，"43690-65535"]`]。之后，它将更新所有这些记录的状态，并将它们标记为：处理中，因为我们将要专门处理端口块的进程。最后，我们遍历端口列表，并为当前 IP 和当前端口块调用多进程进程，如**（1）**部分所示。根据当前示例，我们将为 Thread 1 运行三个并行进程，为 Thread 2 运行三个并行进程：

+   进程 1（方法=端口扫描器（），IP=192.168.250.143，portx=1-21845，rec_id=100）

+   进程 2（方法=端口扫描器（），IP=192.168.250.143，portx=21845-43690，rec_id=101）

+   进程 3（方法=端口扫描器（），IP=192.168.250.143，portx=43690-65535，rec_id=102）

+   进程 4（方法=端口扫描器（），IP=192.168.250.144，portx=1-21845，rec_id=103）

+   进程 5（方法=端口扫描器（），IP=192.168.250.144，portx=21845-43690，rec_id=104）

+   进程 6（方法=端口扫描器（），IP=192.168.250.144，portx=43690-65535，rec_id=105）

理想情况下，每个进程将在处理器核心上执行。拥有七个核心的处理器将是很棒的。在这种情况下，主程序将利用一个核心，其余六个核心将在前面的六个进程之间并行分配。然而，在我们的情况下，我们有一个四核处理器，其中一个核心被主线程使用，其余三个核心被生成的六个进程共享。这将涉及由于上下文切换而产生一定的延迟。还要注意，我们正在使用多进程库的 mp.Process 实用程序。请随时使用批处理模块，如我们在前几章中讨论的，批处理大小为 3，看看扫描时间是否有任何差异。最后，我们希望 Thread 1 线程保持活动状态，直到所有主机块都被扫描，因为我们的轮询逻辑表明，如果一个线程完成，那么主机扫描就结束了。因此，我们在当前线程上调用`join（）`方法。这确保了 Thread 1 和 Thread 2 在所有进程完成之前都保持活动状态；换句话说，所有块都被扫描。

以下代码是不言自明的。我们使用 Python 的内置 Nmap 实用程序来扫描主机和端口块。如果扫描成功，我们只需解析结果并分别提取 TCP 和 UDP 结果。提取结果后，我们只需使用`self.IPtable .Update（）`方法将结果保存在后端数据库表中。我们将状态标记为完成，并保存发现为开放的端口和服务的结果。另一方面，如果端口扫描结果和 IP 返回任何异常，我们将尝试进行三次重复扫描：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/6c69fb2c-a863-4c03-9951-d6587f0e30d8.png)

经过三次重试，如果扫描不成功，那么对于该记录（`I`，`port-chunk`，`project_id`），我们将更新状态为错误完成，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/07daa4ad-28c8-4ce9-ab0e-368f1d2b1577.png)

`start_Polling`方法不断监视活动线程的数量，如**(1)**和**(2)**所示。如果发现只有一个正在运行的线程，然后它检查后端表，看是否所有主机都标记为`complete`状态。如果只有一个正在运行的线程（`main`）并且所有主机都标记为 complete，则它会跳出无限轮询循环。另一方面，如果发现当前运行的线程数量小于最大允许的批处理大小，并且数据库表中还有一些未扫描的主机，它会选择一个未扫描的主机，并通过调用`startProcessing()`方法为其分配一个线程。这在以下代码片段的**(3)**和**(4)**部分中得到了突出显示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/474536d9-0239-4bd0-b419-d93f3e97063f.png)

以下代码处理了如何恢复暂停的扫描。`self.IPtable.MakeUpdate`方法将未扫描主机的状态更新为`incomplete`。当有主机的状态从`processing`更改为`incomplete`时，返回 1。如果在将主机放入数据库表之前扫描被暂停，则返回状态`2`。在这种情况下，我们需要重新进行批量输入。其余代码很简单；我们调用`startProcessing()`方法来委派一个线程来扫描主机：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d998a5dc-be7b-4796-a2a5-4b3f0a3a9275.png)

必须注意的是，为了暂停扫描，我们只需在控制台或终端窗口上按下*Ctrl* + *C*。当前扫描将被暂停，并在后端数据库中针对当前项目 ID 适当地更新状态。还应该注意，正如前面提到的，上述方法构成了我们漏洞扫描器的端口扫描部分的核心逻辑。确切的代码还有一些其他功能，详细信息可以在 GitHub 存储库[<https://github.com/FurqanKhan1/Dictator>](http://%3Chttps://github.com/FurqanKhan1/Dictator%3E)中找到。

# 执行代码

在执行代码之前，请参考 GitHub URL [<https://github.com/FurqanKhan1/Dictator/wiki>](http://%3Chttps://github.com/FurqanKhan1/Dictator/wiki%3E)上的安装和设置说明。安装指南还介绍了如何设置后端数据库和表。或者，您可以下载预先安装和预配置了所有内容的即插即用的虚拟机。

要运行代码，请转到`/root/Django_project/Dictator/Dictator_Servicepath`并运行`driver_main_class.py`代码文件，命令为`python Driver_main_class.py`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/0ef89bf7-bfcd-495b-814e-a5402aff164e.png)

以下屏幕截图显示了程序正在进行扫描的过程：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/7db4c409-3d62-48d3-aec5-1bdeb4057460.png)

以下屏幕截图显示了日志详情：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/4feca97b-57a3-40ba-8ee2-04c02ff0ead0.png)

可以看到在前面的屏幕截图中，为一个主机生成了三个子进程并创建了一个线程。

# 漏洞扫描器端口扫描部分的数据库架构

让我们试着了解我们正在使用的后端数据库以及数据库中各种表的结构。使用`show databases`命令列出 MySQL 中存在的所有数据库：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/33fbdd85-907e-4b6c-81b8-3713c8e0c79c.png) ![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/6b682cfd-471e-4e60-ba2e-16e9734fd478.png)

为了使用当前数据库，也就是我们的漏洞扫描器相关的数据库，我们使用`nmapscan`命令。此外，要查看当前数据库中的所有表，我们使用`show tables`命令：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/34d0290a-b420-42ed-8d8e-db7f49cd82a2.png)

为了查看将保存所有扫描项目的表的结构或模式，我们使用`desc project`命令。要查看我们扫描的项目的数据，我们发出以下 SQL 查询：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/bf85b82b-b7bb-41c8-ac59-d63bb1a430e7.png)

`IPtable` 是保存我们目标端口扫描结果的表。以下命令 `desc IPtable` 显示了表的模式：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/f4848d35-8c04-4c37-8534-a8d613ca6661.png)

以下截图显示了当前项目`744`中`IPtable`中的数据。我们可以看到所有的服务扫描结果都以 CSV 格式放在表中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/19ce5118-42ad-4cdb-b976-1d46ee553d09.png)

一旦项目的端口扫描成功完成，项目的所有细节都将从 `IPtable` 移动到 `IPtable_history`。这是为了在 `IPtable` 上快速进行查找操作。因此，`IPtable_history` 表的模式将与 IPtable 完全相同。这可以在以下截图中验证：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/ee50a4d2-fe36-4dcd-85d8-978e85dd336f.png)

# 总结

在本章中，我们讨论了如何使用 Python 内置的 Nmap 实用程序来进行和自动化端口扫描，同时具有暂停和恢复扫描的附加功能，并使用线程和多进程添加了优化层。在下一章中，我们将继续使用我们的漏洞扫描程序，了解如何现在可以使用端口扫描结果来进一步自动化和编排服务扫描。我们还将讨论我们的漏洞扫描程序的 GUI 版本，它具有大量功能和非常直观的仪表板。

# 问题

1.  为什么我们要使用线程和多进程的组合来自动化端口扫描？

1.  我们可能如何进一步优化吞吐量？

1.  是否有其他 Python 模块或库可以用来自动化 Nmap？

1.  我们可以使用其他扫描程序，如 Angry-IP 或 Mass Scan，使用相同的方法吗？

# 进一步阅读

+   关于如何使用 Nmap 和从`python3`访问扫描结果的 Python 课程：[`pypi.org/project/python-Nmap/`](https://pypi.org/project/python-Nmap/)

+   Nmap 教程：[ https://hackertarget.com/Nmap-tutorial/](https://hackertarget.com/Nmap-tutorial/)

+   Python MySQL：[`www.w3schools.com/python/python_mysql_getstarted.asp`](https://www.w3schools.com/python/python_mysql_getstarted.asp) 和 [`dev.mysql.com/doc/connector-python/en/`](https://dev.mysql.com/doc/connector-python/en/)
