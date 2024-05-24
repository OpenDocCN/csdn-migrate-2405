# 精通 Python（一）

> 原文：[`zh.annas-archive.org/md5/37ba6447e713c9bd5373842650e2e5f3`](https://zh.annas-archive.org/md5/37ba6447e713c9bd5373842650e2e5f3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Python 是一种易于学习的语言，从一开始就非常强大和方便。然而，精通 Python 是一个完全不同的问题。

你将遇到的每个编程问题都至少有几种可能的解决方案和/或范式可以应用于 Python 的广泛可能性之内。本书不仅将说明一系列不同和新的技术，还将解释何时何地应该应用某种方法。

这本书不是 Python 3 的初学者指南。它是一本可以教你 Python 中更高级技术的书。具体针对 Python 3.5 及以上版本，还演示了一些 Python 3.5 独有的特性，比如 async def 和 await 语句。

作为一名有多年经验的 Python 程序员，我将尝试用相关背景信息来理性地解释本书中所做的选择。然而，这些理性化并不是严格的指导方针。其中几个案例归根结底是个人风格的问题。只需知道它们源自经验，并且在许多情况下是 Python 社区推荐的解决方案。

本书中的一些参考对你来说可能不明显，如果你不是蒙提·派森的粉丝。本书在代码示例中广泛使用 spam 和 eggs 而不是 foo 和 bar。为了提供一些背景信息，我建议观看蒙提·派森的“垃圾食品”小品。它非常愚蠢！

# 本书涵盖内容

《第一章》《入门-每个项目一个环境》介绍了使用 virtualenv 或 venv 来隔离 Python 项目中的包的虚拟 Python 环境。

《第二章》《Pythonic 语法，常见陷阱和风格指南》解释了 Pythonic 代码是什么，以及如何编写符合 Python 哲学的 Pythonic 代码。

《第三章》《容器和集合-正确存储数据》是我们使用 Python 捆绑的许多容器和集合来创建快速且可读的代码的地方。

《第四章》《函数式编程-可读性与简洁性》涵盖了 Python 中可用的列表/字典/集合推导和 lambda 语句等函数式编程技术。此外，它还说明了它们与涉及的数学原理的相似之处。

《第五章》《装饰器-通过装饰实现代码重用》不仅解释了如何创建自己的函数/类装饰器，还解释了内部装饰器（如 property，staticmethod 和 classmethod）的工作原理。

《第六章》《生成器和协程-无限，一步一步》展示了生成器和协程如何用于惰性评估无限大小的结构。

《第七章》《异步 IO-无需线程的多线程》演示了使用 async def 和 await 的异步函数的用法，以便外部资源不再阻塞 Python 进程。

《第八章》《元类-使类（而不是实例）更智能》深入探讨了类的创建以及如何完全修改类的行为。

第九章，“文档-如何使用 Sphinx 和 reStructuredText”，展示了如何使用 Sphinx 自动记录你的代码，几乎不费吹灰之力。此外，它还展示了如何使用 Napoleon 语法来记录函数参数，这种方式在代码和文档中都很清晰。

第十章，“测试和日志-为错误做准备”，解释了如何测试代码以及如何添加日志以便在以后出现错误时进行轻松调试。

第十一章，“调试-解决错误”，演示了使用跟踪、日志和交互式调试来追踪错误的几种方法。

第十二章，“性能-跟踪和减少内存和 CPU 使用”，展示了几种测量和改进 CPU 和内存使用的方法。

第十三章，“多处理-当单个 CPU 核心不够用时”，说明了多处理库可以用于执行代码，不仅可以在多个处理器上执行，甚至可以在多台机器上执行。

第十四章，“C/C++扩展、系统调用和 C/C++库”，涵盖了调用 C/C++函数以实现互操作性和性能的方法，使用 Ctypes、CFFI 和本地 C/C++。

第十五章，“打包-创建自己的库或应用程序”，演示了使用 setuptools 和 setup.py 在 Python 包索引（PyPI）上构建和部署软件包。

# 你需要这本书

这本书的唯一硬性要求是 Python 解释器。建议使用 Python 3.5 或更新的解释器，但许多代码示例也可以在旧版本的 Python 中运行，比如 2.7，在文件顶部添加一个简单的 from __future__ import print_statement。

此外，第十四章，“C/C++扩展、系统调用和 C/C++库”需要 C/C++编译器，如 GCC、Visual Studio 或 XCode。Linux 机器是执行 C/C++示例最简单的机器，但在 Windows 和 OS X 机器上也应该可以轻松执行。

# 这本书是为谁准备的

如果你已经超越了绝对的 Python 初学者水平，那么这本书适合你。即使你已经是一名专业的 Python 程序员，我保证你会在这本书中找到一些有用的技巧和见解。

至少，它将允许 Python 2 程序员更多地了解 Python 3 中引入的新功能，特别是 Python 3.5。

需要基本的 Python 熟练，因为 Python 解释器的安装和基本的 Python 语法没有涵盖。

# 约定

在这本书中，你会发现许多文本样式，用来区分不同类型的信息。以下是一些这些样式的例子和它们的含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“应该注意，`type()`函数还有另一个用途。”

代码块设置如下：

```py
import abc
import importlib

class Plugins(abc.ABCMeta):
    plugins = dict()

    def __new__(metaclass, name, bases, namespace):
        cls = abc.ABCMeta.__new__(
            metaclass, name, bases, namespace)
```

任何命令行输入或输出都写成如下形式，其中>>>表示 Python 控制台，#表示常规的 Linux/Unix shell：

```py
>>> class Spam(object):
…     eggs = 'my eggs'

>>> Spam = type('Spam', (object,), dict(eggs='my eggs'))

```

### 注意

警告或重要提示以这样的方式出现在一个框中。

### 提示

提示和技巧看起来像这样。


# 第一章：入门-每个项目一个环境

Python 哲学的一个方面一直以来都是最重要的，也将永远如此——可读性，或者说 Pythonic 代码。这本书将帮助你掌握编写 Python 的方式：可读、美观、明确，尽可能简单。简而言之，它将是 Pythonic 代码。这并不是说复杂的主题不会被涵盖。当然会，但每当 Python 的哲学受到影响时，你将被警告何时何地使用这种技术是合理的。

本书中的大部分代码将在 Python 2 和 Python 3 上运行，但主要目标是 Python 3。这样做有三个原因：

1.  Python 3 于 2008 年发布，这在快速变化的软件世界中已经是很长的时间了。它不再是新鲜事物，而是稳定的、可用的，最重要的是，它是未来。

1.  Python 2 的开发在 2009 年基本停止了。某些功能已经从 Python 3 回溯到 Python 2，但任何新的开发都将首先针对 Python 3。

1.  Python 3 已经成熟。我必须承认，Python 3.2 和更早版本仍存在一些小问题，这使得很难编写能在 Python 2 和 3 上运行的代码，但 Python 3.3 在这方面有了很大的改进，我认为它已经成熟。这一点可以从 Python 3.4 和 3.5 中略有修改的语法以及许多非常有用的功能得到证实，这些都在本书中有所涵盖。

总之，Python 3 是对 Python 2 的改进。我自己也是长期的怀疑论者，但我没有看到不使用 Python 3 进行新项目的理由，甚至将现有项目迁移到 Python 3 通常只需要进行一些小的更改。有了 Python 3.5 中的`async with`等新功能，你会想要升级来尝试一下。

这一章将向你展示如何正确设置环境，创建一个新的隔离环境，并确保在不同的机器上运行相同代码时获得类似的结果。大多数 Python 程序员已经在使用`virtualenv`创建虚拟 Python 环境，但在 Python 3.3 中引入的`venv`命令是一个非常好的替代方案。它本质上是`virtualenv`包的一个克隆，但稍微简单一些，并且与 Python 捆绑在一起。虽然它的使用方法大部分类似于`virtualenv`，但有一些有趣的变化值得知道。

其次，我们将讨论`pip`命令。使用`ensurepip`包通过`venv`自动安装`pip`命令，这是在 Python 3.4 中引入的一个包。这个包会在现有的 Python 库中自动引导`pip`，同时保持独立的 Python 和`pip`版本。在 Python 3.4 之前，`venv`没有`pip`，需要手动安装。

最后，我们将讨论如何安装使用`distutils`创建的包。纯 Python 包通常很容易安装，但涉及 C 模块时可能会有挑战。

在本章中，将涵盖以下主题：

+   使用`venv`创建虚拟 Python 环境

+   使用`ensurepip`引导 pip 的引导

+   使用`pip`基于`distutils`（C/C++）安装包

# 使用 venv 创建虚拟 Python 环境

大多数 Python 程序员可能已经熟悉`venv`或`virtualenv`，但即使你不熟悉，现在开始使用也不算晚。`venv`模块旨在隔离你的 Python 环境，这样你就可以安装特定于当前项目的包，而不会污染全局命名空间。此外，由于包是本地安装的，你不需要系统（root/administrator）访问权限来安装它们。

结果是，您可以确保在本地开发机器和生产机器上具有完全相同版本的软件包，而不会干扰其他软件包。例如，有许多 Django 软件包需要 Django 项目的特定版本。使用`venv`，您可以轻松地为项目 A 安装 Django 1.4，为项目 B 安装 Django 1.8，而它们永远不会知道其他环境中安装了不同的版本。默认情况下，甚至配置了这样的环境，以便全局软件包不可见。这样做的好处是，要获得环境中安装的所有软件包的确切列表，只需`pip freeze`即可。缺点是，一些较重的软件包（例如`numpy`）将必须在每个单独的环境中安装。不用说，哪种选择对您的项目最好取决于项目。对于大多数项目，我会保持默认设置，即不具有全局软件包，但是在处理具有大量 C/C++扩展的项目时，简单地启用全局站点软件包会很方便。原因很简单；如果您没有编译器可用，安装软件包可能会很困难，而全局安装对于 Windows 有可执行文件，对于 Linux/Unix 有可安装软件包可用。

### 注意

`venv`模块（[`docs.python.org/3/library/venv.html`](https://docs.python.org/3/library/venv.html)）可以看作是`virtualenv`工具（[`virtualenv.pypa.io/`](https://virtualenv.pypa.io/)）的一个略微简化的版本，自 Python 3.3 版本以来已经捆绑在一起（参见 PEP 0405 -- Python 虚拟环境：[`www.python.org/dev/peps/pep-0405/`](https://www.python.org/dev/peps/pep-0405/)）。

`virtualenv`包通常可以用作`venv`的替代品，特别是对于不捆绑`venv`的较旧的 Python 版本（3.3 以下）来说，这一点尤为重要。

## 创建您的第一个 venv

创建环境非常容易。基本命令是`pyvenv PATH_TO_THE_NEW_VIRTUAL_ENVIRONMENT`，所以让我们试一试。请注意，此命令适用于 Linux、Unix 和 Mac；Windows 命令将很快跟进：

```py
# pyvenv test_venv
# . ./test_venv/bin/activate
(test_venv) #

```

### 注意

一些 Ubuntu 版本（特别是 14.04 LTS）通过不在`ensurepip`中包含完整的`pyvenv`包来削弱 Python 安装。标准的解决方法是调用`pyvenv --without-pip test_env`，这需要通过`pip`主页上提供的`get_pip.py`文件手动安装`pip`。

这将创建一个名为`test_venv`的环境，第二行激活该环境。

在 Windows 上，一切都略有不同，但总体上是相似的。默认情况下，`pyvenv`命令不会在您的 PATH 中，因此运行该命令略有不同。三个选项如下：

+   将`Python\Tools\Scripts\`目录添加到您的 PATH

+   运行模块：

```py
python -m venv test_venv

```

+   直接运行脚本：

```py
python Python\Tools\Scripts\pyvenv.py test_venv

```

为了方便起见，我建议您无论如何将`Scripts`目录添加到您的 PATH，因为许多其他应用程序/脚本（如`pip`）也将安装在那里。

以下是 Windows 的完整示例：

```py
C:\envs>python -m venv test_venv
C:\envs>test_venv\Scripts\activate.bat
(test_venv) C:\envs>

```

### 提示

在使用 Windows PowerShell 时，可以通过使用`test_venv\Scripts\Activate.ps1`来激活环境。请注意，这里确实需要反斜杠。

## venv 参数

到目前为止，我们只是创建了一个普通的和常规的`venv`，但是有一些非常有用的标志可以根据您的需求定制您的`venv`。

首先，让我们看一下`venv`的帮助：

| 参数 | 描述 |
| --- | --- |
| `--system-site-packages` | 它使虚拟环境可以访问`system-site-packages`目录 |
| `--symlinks` | 尝试在平台不默认使用符号链接时使用`symlinks`而不是副本 |
| `--copies` | 尝试使用副本而不是符号链接，即使符号链接是平台的默认值 |
| `--clear` | 在环境创建之前删除环境目录的内容，如果存在的话 |
| `--upgrade` | 升级环境目录以使用 Python 的这个版本，假设 Python 已经被原地升级 |
| `--without-pip` | 这将跳过在虚拟环境中安装或升级 pip（pip 默认情况下是引导的） |

要注意的最重要的参数是`--system-site-packages`，它可以在环境中启用全局站点包。这意味着如果你在全局 Python 版本中安装了一个包，它也将在你的环境中可用。但是，如果你尝试将其更新到不同的版本，它将被安装在本地。在可能的情况下，我建议禁用`--system-site-packages`标志，因为它可以为你提供一个简单的环境，而不会有太多的变量。否则，简单地更新系统包可能会破坏你的虚拟环境，更糟糕的是，没有办法知道哪些包是本地需要的，哪些只是为其他目的安装的。

要为现有环境启用这个功能，你可以简单地再次运行环境创建命令，但这次加上`--system-site-packages`标志以启用全局站点包。

要再次禁用它，你可以简单地运行环境创建命令，不带标志。这将保留在环境中安装的本地包，但会从你的 Python 范围中删除全局包。

### 提示

在使用`virtualenvwrapper`时，也可以通过在激活的环境中使用`toggleglobalsitepackages`命令来完成这个操作。

`--symlinks`和`--copies`参数通常可以忽略，但了解它们的区别很重要。这些参数决定文件是从基本 Python 目录复制还是创建符号链接。

### 注意

符号链接是 Linux/Unix/Mac 的东西；它不是复制文件，而是创建一个符号链接，告诉系统在哪里找到实际的文件。

默认情况下，`venv`会尝试创建符号链接，如果失败，它会退而使用复制。自从 Windows Vista 和 Python 3.2 以来，这在 Windows 上也得到支持，所以除非你使用的是一个非常旧的系统，你很可能会在你的环境中使用符号链接。符号链接的好处是它节省了磁盘空间，并且与你的 Python 安装保持同步。缺点是，如果你的系统的 Python 版本升级了，它可能会破坏你的环境中安装的包，但这可以通过使用`pip`重新安装包来轻松解决。

最后，`--upgrade`参数在系统 Python 版本被原地升级后非常有用。这个参数的最常见用法是在使用复制（而不是符号链接）环境后修复损坏的环境。

## virtualenv 和 venv 之间的区别

由于`venv`模块本质上是`virtualenv`的一个简化版本，它们大部分是相同的，但有些地方是不同的。此外，由于`virtualenv`是一个与 Python 分开分发的包，它确实有一些优势。

以下是`venv`相对于`virtualenv`的优势：

+   `venv`随 Python 3.3 及以上版本一起分发，因此不需要单独安装

+   `venv`简单直接，除了基本必需品之外没有其他功能

`virtualenv`相对于`venv`的优势：

+   `virtualenv`是在 Python 之外分发的，因此可以单独更新。

+   `virtualenv`适用于旧的 Python 版本，但建议使用 Python 2.6 或更高版本。然而，使用较旧版本（1.9.x 或更低版本）可以支持 Python 2.5。

+   它支持方便的包装器，比如`virtualenvwrapper` ([`virtualenvwrapper.readthedocs.org/`](http://virtualenvwrapper.readthedocs.org/))

简而言之，如果`venv`对您足够了，就使用它。如果您使用的是旧版本的 Python 或需要一些额外的便利，比如`virtualenvwrapper`，则使用`virtualenv`。这两个项目本质上是做同样的事情，并且已经努力使它们之间易于切换。两者之间最大和最显著的区别是`virtualenv`支持的 Python 版本的种类。

# 使用 ensurepip 引导 pip

自 2008 年推出以来，`pip`软件包管理器一直在逐渐取代`easy_install`。自 Python 3.4 以来，它甚至已成为默认选项，并与 Python 捆绑在一起。从 Python 3.4 开始，它默认安装在常规 Python 环境和`pyvenv`中；在此之前，需要手动安装。要在 Python 3.4 及以上版本自动安装`pip`，需要使用`ensurepip`库。这是一个处理`pip`的自动安装和/或升级的库，因此至少与`ensurepip`捆绑的版本一样新。

## ensurepip 用法

使用`ensurepip`非常简单。只需运行 python `-m ensurepip`来保证`pip`的版本，或者运行 python `-m ensurepip --upgrade`来确保`pip`至少是与`ensurepip`捆绑的版本一样新。

除了安装常规的`pip`快捷方式外，这还将安装`pipX`和`pipX.Y`链接，允许您选择特定的 Python 版本。当同时使用 Python 2 和 Python 3 时，这允许您使用`pip2`和`pip3`在 Python 2 和 Python 3 中安装软件包。这意味着如果您在 Python 3.5 上使用 python `-m ensurepip`，您将在您的环境中安装`pip`、`pip3`和`pip3.5`命令。

## 手动 pip 安装

如果您使用的是 Python 3.4 或更高版本，`ensurepip`软件包非常好。然而，在此之下，您需要手动安装`pip`。实际上，这非常容易。只需要两个步骤：

1.  下载`get-pip.py`文件：[`bootstrap.pypa.io/get-pip.py`](https://bootstrap.pypa.io/get-pip.py)。

1.  执行`get-pip.py`文件：python `get-pip.py`。

### 提示

如果`ensurepip`命令由于权限错误而失败，提供`--user`参数可能会有用。这允许您在用户特定的站点包目录中安装`pip`，因此不需要 root/admin 访问权限。

# 安装 C/C++软件包

大多数 Python 软件包纯粹是 Python，并且安装起来非常容易，只需简单的`pip install packagename`就可以了。然而，有些情况涉及到编译，安装不再是简单的 pip install，而是需要搜索几个小时以查看安装某个软件包所需的依赖关系。

特定的错误消息会根据项目和环境而异，但这些错误中有一个共同的模式，了解您所看到的内容可以在寻找解决方案时提供很大帮助。

例如，在标准的 Ubuntu 机器上安装`pillow`时，您会得到几页错误、警告和其他消息，最后是这样的：

```py
 **x86_64-linux-gnu-gcc: error: build/temp.linux-x86_64-3.4/libImaging/Jpeg2KDecode.o: No such file or directory
 **x86_64-linux-gnu-gcc: error: build/temp.linux-x86_64-3.4/libImaging/Jpeg2KEncode.o: No such file or directory
 **x86_64-linux-gnu-gcc: error: build/temp.linux-x86_64-3.4/libImaging/BoxBlur.o: No such file or directory
 **error: command 'x86_64-linux-gnu-gcc' failed with exit status 1

 **----------------------------------------
Command "python3 -c "import setuptools, tokenize;__file__='/tmp/pip-build-_f0ryusw/pillow/setup.py';exec(compile(getattr(tokenize, 'open', open)(__file__).read().replace('\r\n', '\n'), __file__, 'exec'))" install --record /tmp/pip-kmmobum2-record/install-record.txt --single-version-externally-managed --compile --install-headers include/site/python3.4/pillow" failed with error code 1 in /tmp/pip-build-_f0ryusw/pillow

```

看到这样的消息后，您可能会想要搜索其中的一行，比如`x86_64-linux-gnu-gcc: error: build/temp.linux-x86_64-3.4/libImaging/Jpeg2KDecode.o: No such file or directory`。虽然这可能会给您一些相关的结果，但很可能不会。在这种安装中的技巧是向上滚动，直到看到有关缺少头文件的消息。这是一个例子：

```py
 **In file included from libImaging/Imaging.h:14:0,
 **from libImaging/Resample.c:16:
 **libImaging/ImPlatform.h:10:20: fatal error: Python.h: No such file or directory
 **#include "Python.h"
 **^
 **compilation terminated.

```

这里的关键消息是缺少`Python.h`。这些是 Python 头文件的一部分，需要用于 Python 中大多数 C/C++软件包的编译。根据操作系统的不同，解决方案也会有所不同，不幸的是。因此，我建议您跳过本段中与您的情况无关的部分。

## Debian 和 Ubuntu

在 Debian 和 Ubuntu 中，要安装的软件包是`python3-dev`或`python2-dev`（如果您仍在使用 Python 2）。要执行的命令如下：

```py
# sudo apt-get install python3-dev

```

但是，这只安装了开发头文件。如果您希望编译器和其他头文件与安装捆绑在一起，那么`build-dep`命令也非常有用。以下是一个示例：

```py
# sudo apt-get build-dep python3

```

## Red Hat、CentOS 和 Fedora

Red Hat、CentOS 和 Fedora 是基于 rpm 的发行版，它们使用`yum`软件包管理器来安装所需的软件。大多数开发头文件都可以通过`<package-name>-devel`获得，并且可以轻松安装。要安装 Python 3 开发头文件，请使用以下命令：

```py
# sudo apt-get install python3-devel

```

为了确保您具有构建软件包（如 Python）所需的所有要求，例如开发头文件和编译器，`yum-builddep`命令是可用的：

```py
# yum-builddep python3

```

## OS X

在实际安装软件包之前，OS X 上的安装过程包括三个步骤。

首先，您需要安装 Xcode。这可以通过 OS X App Store 完成，网址为[`itunes.apple.com/en/app/xcode/id497799835?mt=12`](https://itunes.apple.com/en/app/xcode/id497799835?mt=12)。

然后，您需要安装 Xcode 命令行工具：

```py
# xcode-select --install

```

最后，您需要安装**Homebrew**软件包管理器。步骤可在[`brew.sh/`](http://brew.sh/)找到，但安装命令如下：

```py
# /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"

```

### 注意

其他软件包管理器，如`Macports`，也是可能的，但`Homebrew`目前是 OS X 上开发和社区最活跃的软件包管理器。

完成所有这些步骤后，您应该有一个可用的 Homebrew 安装。可以使用`brew doctor`命令验证`Homebrew`的工作情况。如果输出中没有主要错误，那么您应该准备通过 brew 安装您的第一个软件包。现在我们只需要安装 Python，就完成了：

```py
# brew install python3

```

## Windows

在 Windows 上，手动编译 C Python 软件包通常是一个非常不容易的任务。大多数软件包都是针对 Linux/Unix 系统编写的（OS X 属于 Unix 类别），而 Windows 对开发人员来说只是一个附带的功能。结果是，由于测试软件包的人很少，许多库需要手动安装，因此在 Windows 上编译软件包非常繁琐。因此，除非您确实必须这样做，否则请尽量避免在 Windows 上手动编译 Python 软件包。大多数软件包都可以通过一些搜索获得可安装的二进制下载，并且还有诸如 Anaconda 之类的替代方案，其中包括大多数重要的 C Python 软件包的二进制软件包。

如果您仍然倾向于手动编译 C Python 软件包，那么还有另一种选择，通常是更简单的替代方案。Cygwin 项目（[`cygwin.com/`](http://cygwin.com/)）试图使 Linux 应用程序在 Windows 上原生运行。这通常是一个比让软件包与 Visual Studio 配合工作更容易的解决方案。

如果您确实希望选择 Visual Studio 路径，我想指向第十四章，*C/C++扩展、系统调用和 C/C++库*，其中涵盖了手动编写 C/C++扩展以及有关您的 Python 版本所需的 Visual Studio 版本的一些信息。

# 摘要

随着`pip`和`venv`等包的加入，我觉得 Python 3 已经成为一个完整的包，应该适合大多数人。除了遗留应用程序外，再也没有理由不选择 Python 3 了。2008 年初版的 Python 3 相比于同年发布的成熟的 Python 2.6 版本确实有些粗糙，但在这方面已经发生了很多变化。最后一个重要的 Python 2 版本是 Python 2.7，发布于 2010 年；在软件世界中，这是非常非常长的时间。虽然 Python 2.7 仍然在接受维护，但它将不会获得 Python 3 正在获得的任何惊人的新功能——比如默认的 Unicode 字符串、`dict`生成器（第六章，*生成器和协程-无限，一步一步*）以及`async`方法（第七章，*异步 IO-无需线程的多线程*）。

完成本章后，您应该能够创建一个干净且可重现的虚拟环境，并知道如果 C/C++包的安装失败应该去哪里查找。

这一章最重要的笔记如下：

+   为了创建一个干净简洁的环境，请使用`venv`。如果需要与 Python 2 兼容，请使用`virtualenv`。

+   如果 C/C++包安装失败，请查找有关缺少包含文件的错误。

下一章将介绍 Python 风格指南，重要的规则以及它们的重要性。可读性是 Python 哲学中最重要的方面之一，您将学习编写更干净、更易读的 Python 代码的方法和风格。


# 第二章：Pythonic 语法，常见陷阱和风格指南

Python 编程语言的设计和开发一直由其原始作者 Guido van Rossum 掌握，他常常被亲切地称为**终身仁慈独裁者**（**BDFL**）。尽管 van Rossum 被认为拥有一台时光机（他曾多次回答功能请求说“我昨晚刚实现了这个”：[`www.catb.org/jargon/html/G/Guido.html`](http://www.catb.org/jargon/html/G/Guido.html)），但他仍然只是一个人，需要帮助来维护和发展 Python。为了方便这一点，**Python Enhancement Proposal**（**PEP**）流程已经被开发出来。这个流程允许任何人提交一个带有功能技术规范和为其有用性辩护的理由的 PEP。在 Python 邮件列表上进行讨论并可能进行一些改进后，BDFL 将做出接受或拒绝提案的决定。

Python 风格指南（`PEP 8`：[`www.python.org/dev/peps/pep-0008/`](https://www.python.org/dev/peps/pep-0008/)）曾经作为其中一个 PEP 提交，自那以后它一直被接受和不断改进。它有很多伟大和广泛接受的惯例，也有一些有争议的。特别是，79 个字符的最大行长度是许多讨论的话题。然而，将一行限制在 79 个字符确实有一些优点。除此之外，虽然风格指南本身并不能使代码成为 Pythonic，正如“Python 之禅”（`PEP 20`：[`www.python.org/dev/peps/pep-0020/`](https://www.python.org/dev/peps/pep-0020/)）所说的那样：“美丽胜过丑陋。” `PEP 8`定义了代码应该以确切的方式进行格式化，而`PEP 20`更多的是一种哲学和心态。

常见的陷阱是一系列常见的错误，从初学者的错误到高级错误不等。它们范围广泛，从将列表或字典（可变的）作为参数传递到闭包中的延迟绑定问题。更重要的问题是如何以一种清晰的方式解决循环导入的问题。

本章中使用的一些技术可能对于这样一个早期的章节来说有点过于先进，但请不要担心。本章是关于风格和常见陷阱的。使用的技术的内部工作将在后面的章节中介绍。

我们将在本章中涵盖以下主题：

+   代码风格（`PEP 8`，`pyflakes`，`flake8`等）

+   常见陷阱（列表作为函数参数，按值传递与按引用传递，以及继承行为）

### 注意

Pythonic 代码的定义是非常主观的，主要反映了本作者的观点。在项目中工作时，与该项目的编码风格保持一致比遵循 Python 或本书给出的编码指南更重要。

# 代码风格 - 或者什么是 Pythonic 代码？

Pythonic code - 当你第一次听到它时，你可能会认为它是一种编程范式，类似于面向对象或函数式编程。虽然有些地方可以被认为是这样，但实际上它更多的是一种设计哲学。Python 让你可以自由选择以面向对象，过程式，函数式，面向方面甚至逻辑导向的方式进行编程。这些自由使 Python 成为一个很好的编程语言，但是，自由总是需要很多纪律来保持代码的清晰和可读性。`PEP8`标准告诉我们如何格式化代码，但 Pythonic 代码不仅仅是语法。这就是 Pythonic 哲学（`PEP20`）的全部内容，即代码应该是：

+   清晰

+   简单

+   美丽

+   显式

+   可读性

大多数听起来都像是常识，我认为它们应该是。然而，也有一些情况，没有一个明显的方法来做（除非你是荷兰人，当然，你将在本章后面读到）。这就是本章的目标 - 学习什么样的代码是美丽的，以及为什么在 Python 风格指南中做出了某些决定。

### 注意

有些程序员曾经问过 Guido van Rossum，Python 是否会支持大括号。从那天起，大括号就可以通过`__future__`导入使用了：

```py
>>> from __future__ import braces
 **File "<stdin>", line 1
SyntaxError: not a chance

```

## 格式化字符串 - `printf-style`还是`str.format`？

Python 长期以来一直支持`printf-style`（`%`）和`str.format`，所以你很可能已经对两者都很熟悉了。

在本书中，`printf-style`格式将被用于一些原因：

+   最重要的原因是这对我来说很自然。我已经在许多不同的编程语言中使用`printf`大约 20 年了。

+   大多数编程语言都支持`printf`语法，这使得它对很多人来说很熟悉。

+   尽管这只与本书中的示例有关，但它占用的空间稍微少一些，需要较少的格式更改。与显示器相反，书籍多年来并没有变得更宽。

一般来说，大多数人现在推荐使用`str.format`，但这主要取决于个人偏好。`printf-style`更简单，而`str.format`方法更强大。

如果你想了解更多关于如何用`str.format`替换`printf-style`格式（或者反过来，当然也可以），我推荐访问 PyFormat 网站[`pyformat.info/`](https://pyformat.info/)。

## PEP20，Python 之禅

大部分 Python 哲学可以通过 PEP20 来解释。Python 有一个小彩蛋，可以始终提醒你`PEP20`。只需在 Python 控制台中键入`import this`，就会得到`PEP20`的内容。引用`PEP20`：

> *"长期的 Python 程序员 Tim Peters 简洁地表达了 BDFL 对 Python 设计的指导原则，总共有 20 条格言，其中只有 19 条被记录下来。"*

接下来的几段将解释这 19 行的意图。

### 注意

PEP20 部分的示例在工作上并不完全相同，但它们确实有相同的目的。这里的许多示例都是虚构的，除了解释段落的理由外，没有其他目的。

为了清晰起见，在我们开始之前，让我们看一下`import this`的输出：

```py
>>> import this
The Zen of Python, by Tim Peters

Beautiful is better than ugly.
Explicit is better than implicit.
Simple is better than complex.
Complex is better than complicated.
Flat is better than nested.
Sparse is better than dense.
Readability counts.
Special cases aren't special enough to break the rules.
Although practicality beats purity.
Errors should never pass silently.
Unless explicitly silenced.
In the face of ambiguity, refuse the temptation to guess.
There should be one-- and preferably only one --obvious way to do it.
Although that way may not be obvious at first unless you're Dutch.
Now is better than never.
Although never is often better than *right* now.
If the implementation is hard to explain, it's a bad idea.
If the implementation is easy to explain, it may be a good idea.
Namespaces are one honking great idea -- let's do more of those!

```

### 美丽胜过丑陋

尽管美是相当主观的，但有一些 Python 风格规则需要遵守：限制行长度，保持语句在单独的行上，将导入拆分为单独的行等等。

简而言之，与这样一个相当复杂的函数相比：

```py
 def filter_modulo(items, modulo):
    output_items = []
    for i in range(len(items)):
        if items[i] % modulo:
            output_items.append(items[i])
    return output_items
```

或者这样：

```py
filter_modulo = lambda i, m: [i[j] for i in range(len(i))
                              if i[j] % m]
```

只需执行以下操作：

```py
def filter_modulo(items, modulo):
    for item in items:
        if item % modulo:
            yield item
```

更简单，更易读，更美丽一些！

### 注意

这些示例的结果并不相同。前两个返回列表，而最后一个返回生成器。生成器将在第六章中更详细地讨论，*生成器和协程-无限，一步一次*。

### 显式胜过隐式

导入、参数和变量名只是许多情况中的一些，显式代码更容易阅读，但编写代码时需要付出更多的努力和/或冗长。

这是一个例子：

```py
from spam import *
from eggs import *

some_function()
```

虽然这样可以节省一些输入，但很难看出`some_function`是在哪里定义的。它是在`foo`中定义的吗？在`bar`中定义的吗？也许在两个模块中都定义了？有一些具有高级内省功能的编辑器可以帮助你，但为什么不明确地保持，这样每个人（即使只是在线查看代码）都能看到它在做什么呢？

```py
import spam
import eggs

spam.some_function()
eggs.some_function()
```

额外的好处是我们可以明确地从`spam`或`eggs`中调用函数，每个人都会更清楚代码的作用。

对于具有`*args`和`**kwargs`的函数也是一样。它们有时可能非常有用，但它们的缺点是很难确定哪些参数对于函数是有效的：

```py
def spam(egg, *args, **kwargs):
    processed_egg = process_egg(egg, *args, **kwargs)
    return Spam(processed_egg)
```

文档显然对这样的情况有所帮助，我并不反对一般情况下使用`*args`和`**kwargs`，但至少保留最常见的参数是个好主意。即使这需要你重复父类的参数，这样代码会更清晰。在未来重构父类时，你会知道是否还有子类使用了一些参数。

### 简单胜于复杂

> *"简单胜于复杂。复杂胜于混乱。"*

在开始一个新项目时，问自己最重要的问题是：它需要多复杂？

例如，假设我们已经编写了一个小程序，现在我们需要存储一些数据。我们有哪些选择？

+   完整的数据库服务器，比如 PostgreSQL 或 MySQL

+   简单的文件系统数据库，比如 SQLite 或 AnyDBM

+   平面文件存储，比如 CSV 和 TSV

+   结构化存储，比如 JSON、YAML 或 XML

+   序列化的 Python，比如 Pickle 或 Marshal

所有这些选项都有自己的用例以及根据用例的优势和劣势：

+   你存储了大量数据吗？那么完整的数据库服务器和平面文件存储通常是最方便的选择。

+   它是否能够轻松地在不需要任何包安装的不同系统上移植？这使得除了完整的数据库服务器之外的任何选项都很方便。

+   我们需要搜索数据吗？这在使用其中一个数据库系统时要容易得多，无论是文件系统还是完整的服务器。

+   是否有其他应用需要能够编辑数据？这使得像平面文件存储和结构化存储这样的通用格式成为方便的选择，但排除了序列化的 Python。

很多问题！但最重要的一个是：它需要多复杂？在`pickle`文件中存储数据是可以在三行内完成的，而连接到数据库（即使是 SQLite）将会更复杂，并且在许多情况下是不需要的：

```py
import pickle  # Or json/yaml
With open('data.pickle', 'wb') as fh:
    pickle.dump(data, fh, pickle.HIGHEST_PROTOCOL)
```

对比：

```py
import sqlite3
connection = sqlite3.connect('database.sqlite')
cursor = connection.cursor()
cursor.execute('CREATE TABLE data (key text, value text)')
cursor.execute('''INSERT INTO data VALUES ('key', 'value')''')
connection.commit()
connection.close()
```

当然，这些例子远非相同，一个存储了完整的数据对象，而另一个只是在 SQLite 数据库中存储了一些键值对。然而，重点不在于此。重点是，尽管使用适当的库可以简化这个过程，但在许多情况下，代码更加复杂，而实际上却不够灵活。简单胜于复杂，如果不需要复杂性，最好避免它。

### 扁平胜于嵌套

嵌套的代码很快变得难以阅读和理解。这里没有严格的规则，但通常当你有三层嵌套循环时，就是重构的时候了。

只需看下面的例子，它打印了一个二维矩阵的列表。虽然这里没有明显的错误，但将其拆分为更多的函数可能会使目的更容易理解，也更容易测试：

```py
def print_matrices():
    for matrix in matrices:
        print('Matrix:')
        for row in matrix:
            for col in row:
                print(col, end='')
            print()
        print()
```

稍微扁平化的版本如下：

```py
def print_row(row):
    for col in row:
        print(col, end='')

def print_matrix(matrix):
    for row in matrix:
        print_row(row)
        print()

def print_matrices(matrices):
    for matrix in matrices:
        print('Matrix:')
        print_matrix(matrix)
        print()
```

这个例子可能有点复杂，但思路是正确的。深度嵌套的代码很容易变得难以阅读。

### 稀疏胜于密集

空白通常是件好事。是的，它会使你的文件变得更长，你的代码会占用更多的空间，但如果你按逻辑拆分你的代码，它可以帮助很多可读性：

```py
>>> def make_eggs(a,b):'while',['technically'];print('correct');\
...     {'this':'is','highly':'unreadable'};print(1-a+b**4/2**2)
...
>>> make_eggs(1,2)
correct
4.0
```

虽然从技术上讲是正确的，但这并不是所有人都能读懂的。我相信这需要一些努力才能找出代码实际在做什么，以及它会打印出什么数字，而不是尝试它。

```py
>>> def make_eggs(a, b):
...     'while', ['technically']
...     print('correct')
...     {'this': 'is', 'highly': 'unreadable'}
...     print(1 - a + ((b ** 4) / (2 ** 2)))
...
>>> make_eggs(1, 2)
correct
4.0
```

不过，这还不是最佳代码，但至少在代码中发生了什么更加明显了一些。

### 可读性很重要

更短并不总是意味着更容易阅读：

```py
fib=lambda n:reduce(lambda x,y:(x[0]+x[1],x[0]),[(1,1)]*(n-2))[0]
```

虽然简短的版本在简洁上有一定的美感，但我个人觉得下面的更美观：

```py
def fib(n):
    a, b = 0, 1
    while True:
        yield a
        a, b = b, a + b
```

### 实用性胜过纯粹

> *"特殊情况并不足以打破规则。尽管实用性胜过纯粹。"*

违反规则有时会很诱人，但往往会导致一连串的问题。当然，这适用于所有规则。如果你的快速修复会违反规则，你应该立即尝试重构它。很可能你以后没有时间来修复它，并会后悔。

不需要过分。如果解决方案已经足够好，而重构会更费力，那么选择有效的方法可能更好。尽管所有这些例子都涉及导入，但这个指导原则几乎适用于所有情况。

为了防止行过长，可以通过几种方法使导入变得更短，比如添加反斜杠、添加括号，或者只是缩短导入：

```py
from spam.eggs.foo.bar import spam, eggs, extra_spam, extra_eggs, extra_stuff  from spam.eggs.foo.bar import spam, eggs, extra_spam, extra_eggs
```

这种情况可以很容易地避免，只需遵循`PEP8`（每行一个导入）：

```py
from spam.eggs.foo.bar import spam from spam.eggs.foo.bar import eggs from spam.eggs.foo.bar import extra_spam from spam.eggs.foo.bar import extra_eggs from spam.eggs.foo.bar import extra_stuff  from spam.eggs.foo.bar import spam
from spam.eggs.foo.bar import eggs
from spam.eggs.foo.bar import extra_spam
from spam.eggs.foo.bar import extra_eggs
```

但是长导入怎么办？

```py
from spam_eggs_and_some_extra_spam_stuff import my_spam_and_eggs_stuff_which_is_too_long_for_a_line
```

是的…即使通常不建议为导入添加反斜杠，但在某些情况下这仍然是最佳选择：

```py
from spam_eggs_and_some_extra_spam_stuff \
    import my_spam_and_eggs_stuff_which_is_too_long_for_a_line
```

### 错误不应该悄悄地传递

> *“错误不应该悄悄地传递。除非明确地被压制。”

用 Jamie Zawinsky 的话来说：有些人在遇到错误时，会想“我知道了，我会使用`try`/`except`/`pass`块。”现在他们有了两个问题。

裸露或过于宽泛的异常捕获已经是一个坏主意了。不传递它们会让你（或者其他人在处理代码时）长时间猜测发生了什么：

```py
try:
    value = int(user_input)
except:
    pass
```

如果你真的需要捕获所有错误，就要非常明确地表达出来：

```py
try:
    value = int(user_input)
except Exception as e:
    logging.warn('Uncaught exception %r', e)
```

或者更好的是，明确捕获并添加一个合理的默认值：

```py
try:
    value = int(user_input)
except ValueError:
    value = 0
```

问题实际上更加复杂。对于依赖异常内部发生情况的代码块怎么办？例如，考虑以下代码块：

```py
try:
    value = int(user_input)
    value = do_some_processing(value)
    value = do_some_other_processing(value)
except ValueError:
    value = 0
```

如果引发了`ValueError`，是哪一行导致的？是`int(user_input)`，`do_some_processing(value)`，还是`do_some_other_processing(value)`？如果错误被悄悄地捕获，那么在正常执行代码时就无法知道，这可能非常危险。如果由于某种原因其他函数的处理发生了变化，那么以这种方式处理异常就会成为一个问题。所以，除非确实打算这样做，否则请使用这种方式：

```py
try:
    value = int(user_input)
except ValueError:
    value = 0
else:
    value = do_some_processing(value)
    value = do_some_other_processing(value)
```

### 面对模棱两可，拒绝猜测

虽然猜测在许多情况下都有效，但如果不小心就会出问题。正如在“明确胜于含糊”一段中已经展示的，当有一些`from ... import *`时，你并不能总是确定哪个模块提供了你期望的变量。

通常应该避免模棱两可，以避免猜测。清晰明了的代码会产生更少的错误。模棱两可可能出现的一个有用情况是函数调用。比如，以下两个函数调用：

```py
spam(1, 2, 3, 4, 5)
spam(spam=1, eggs=2, a=3, b=4, c=5)
```

它们可能是相同的，但也可能不是。没有看到函数的情况下是无法说的。如果函数是以以下方式实现的，那么两者之间的结果将会大不相同：

```py
def spam(a=0, b=0, c=0, d=0, e=0, spam=1, eggs=2):
    pass
```

我并不是说你应该在所有情况下使用关键字参数，但如果涉及许多参数和/或难以识别的参数（比如数字），那么这是个好主意。你可以选择逻辑变量名来传递参数，只要从代码中清楚地传达了含义。

举个例子，以下是一个类似的调用，使用自定义变量名来传达意图：

```py
a = 3
b = 4
c = 5
spam(a, b, c)
```

### 一种明显的方法

> *“应该有一种——最好只有一种——明显的方法来做。虽然一开始可能不明显，除非你是荷兰人。”

一般来说，经过一段时间思考一个困难的问题后，你会发现有一种解决方案明显优于其他选择。当然也有例外情况，这时如果你是荷兰人就会很有用。这里的笑话是指 Python 的 BDFL 和原始作者 Guido van Rossum 是荷兰人（就像我一样）。

### 现在总比永远好

> *“现在比不做要好。尽管不做通常比*立刻*做要好。”*

最好立即解决问题，而不是将问题推到未来。然而，有些情况下，立即解决问题并不是一个选择。在这些情况下，一个很好的选择可能是将一个函数标记为已弃用，这样就不会有意外忘记问题的机会：

```py
import warnings
warnings.warn('Something deprecated', DeprecationWarning)
```

### 难以解释，易于解释

> *“如果实现很难解释，那就是一个坏主意。如果实现很容易解释，那可能是一个好主意。”*

一如既往，尽量保持简单。虽然复杂的代码可能很好测试，但更容易出现错误。你能保持事情简单，就越好。

### 命名空间是一个非常棒的想法

> *“命名空间是一个非常棒的想法——让我们做更多这样的事情！”*

命名空间可以使代码更加清晰易用。正确命名它们会让它们变得更好。例如，下面这行代码是做什么的？

```py
load(fh)
```

不太清楚，对吧？

带有命名空间的版本怎么样？

```py
pickle.load(fh)
```

现在我们明白了。

举一个命名空间的例子，其完整长度使其难以使用，我们将看一下 Django 中的`User`类。在 Django 框架中，`User`类存储在`django.contrib.auth.models.User`中。许多项目以以下方式使用该对象：

```py
from django.contrib.auth.models import User
# Use it as: User
```

虽然这相当清晰，但可能会让人认为`User`类是当前类的本地类。而以下做法让人们知道它在另一个模块中：

```py
from django.contrib.auth import models
# Use it as: models.User
```

然而，这很快就会与其他模块的导入发生冲突，所以我个人建议改用以下方式：

```py
from django.contrib.auth import models as auth_models
# Use it as auth_models.User
```

这里有另一种选择：

```py
import django.contrib.auth as auth_models
# Use it as auth_models.User
```

### 结论

现在我们应该对 Python 的思想有了一些了解。创建代码：

+   美观

+   可读

+   明确的

+   足够明确

+   并非完全没有空格

所以让我们继续看一些使用 Python 风格指南创建美观、可读和简单代码的更多例子。

## 解释 PEP8

前面的段落已经展示了很多使用`PEP20`作为参考的例子，但还有一些其他重要的指南需要注意。PEP8 风格指南规定了标准的 Python 编码约定。简单地遵循 PEP8 标准并不能使你的代码变得 Pythonic，但这绝对是一个很好的开始。你使用哪种风格并不是那么重要，只要你保持一致。没有比不使用适当的风格指南更糟糕的事情了，不一致地使用更糟糕。

### 鸭子类型

鸭子类型是一种通过行为处理变量的方法。引用 Alex Martelli（我的 Python 英雄之一，也被许多人称为 MartelliBot）的话：

> *“不要检查它是否是一只鸭子：检查它是否像一只鸭子一样嘎嘎叫，像一只鸭子一样走路，等等，根据你需要玩语言游戏的鸭子行为子集。如果参数未通过这个特定的鸭子测试，那么你可以耸耸肩，问一句‘为什么是一只鸭子？’”*

在许多情况下，当人们进行比较，比如`if spam != '':`，他们实际上只是在寻找任何被认为是真值的东西。虽然你可以将值与字符串值`''`进行比较，但你通常不必这么具体。在许多情况下，只需使用`if spam:`就足够了，而且实际上功能更好。

例如，以下代码行使用`timestamp`的值生成文件名：

```py
filename = '%s.csv' % timestamp

```

因为它被命名为`timestamp`，有人可能会想要检查它实际上是一个`date`或`datetime`对象，像这样：

```py
import datetime
if isinstance(timestamp, (datetime.date, datetime.datetime)):
    filename = '%s.csv' % timestamp
else:
    raise TypeError(
        'Timestamp %r should be date(time) object, got %s'
        % (timestamp, type(timestamp))) 
```

虽然这并不是本质上错误的，但在 Python 中，比较类型被认为是一种不好的做法，因为通常情况下并不需要。在 Python 中，更倾向于鸭子类型。只需尝试将其转换为字符串，不必在乎它实际上是什么。为了说明这对最终结果几乎没有什么影响，看下面的代码：

```py
import datetime
timestamp = datetime.date(2000, 10, 5)
filename = '%s.csv' % timestamp
print('Filename from date: %s' % filename)

timestamp = '2000-10-05'
filename = '%s.csv' % timestamp
print('Filename from str: %s' % filename)
```

正如你所期望的那样，结果是相同的：

```py
Filename from date: 2000-10-05.csv
Filename from str: 2000-10-05.csv
```

同样适用于将数字转换为浮点数或整数；而不是强制执行某种类型，只需要求某些特性。需要一个可以作为数字传递的东西？只需尝试转换为`int`或`float`。需要一个`file`对象？为什么不只是检查是否有一个带有`hasattr`的`read`方法呢？

所以，不要这样做：

```py
if isinstance(value, int):
```

相反，只需使用以下内容：

```py
value = int(value)
```

而不是这样：

```py
import io

if isinstance(fh, io.IOBase):
```

只需使用以下行：

```py
if hasattr(fh, 'read'):
```

### 值和身份比较之间的差异

在 Python 中有几种比较对象的方法，标准的大于和小于，等于和不等于。但实际上还有一些其他方法，其中一个有点特殊。那就是身份比较运算符：不是使用`if spam == eggs`，而是使用`if spam is eggs`。最大的区别在于一个比较值，另一个比较身份。这听起来有点模糊，但实际上相当简单。至少在 CPython 实现中，比较的是内存地址，这意味着这是你可以得到的最轻量级的查找之一。而值需要确保类型是可比较的，也许需要检查子值，身份检查只是检查唯一标识符是否相同。

### 注意

如果你曾经写过 Java，你应该对这个原则很熟悉。在 Java 中，普通的字符串比较（`spam == eggs`）将使用身份而不是值。要比较值，你需要使用`spam.equals(eggs)`来获得正确的结果。

看看这个例子：

```py
a = 200 + 56
b = 256
c = 200 + 57
d = 257

print('%r == %r: %r' % (a, b, a == b))
print('%r is %r: %r' % (a, b, a is b))
print('%r == %r: %r' % (c, d, c == d))
print('%r is %r: %r' % (c, d, c is d))
```

虽然值是相同的，但身份是不同的。这段代码的实际结果如下：

```py
256 == 256: True
256 is 256: True
257 == 257: True
257 is 257: False
```

问题在于 Python 为所有介于`-5`和`256`之间的整数保留了一个内部整数对象数组；这就是为什么对`256`有效但对`257`无效的原因。

你可能会想知道为什么有人会想要使用`is`而不是`==`。有多个有效的答案；取决于情况，一个是正确的，另一个不是。但性能也可以是一个非常重要的考虑因素。基本准则是，当比较 Python 的单例对象，如`True`、`False`和`None`时，总是使用`is`进行比较。

至于性能考虑，考虑以下例子：

```py
spam = range(1000000)
eggs = range(1000000)
```

当执行`spam == eggs`时，这将比较两个列表中的每个项目，因此在内部实际上进行了 100 万次比较。将其与使用`spam is eggs`时的简单身份检查进行比较。

要查看 Python 在内部实际上使用`is`运算符时的操作，可以使用`id`函数。当执行`if spam is eggs`时，Python 实际上会在内部执行`if id(spam) == id(eggs)`。

### 循环

对于来自其他语言的人来说，可能会倾向于使用`for`循环或甚至`while`循环来处理`list`、`tuple`、`str`等的项目。虽然有效，但比必要的复杂。例如，考虑这段代码：

```py
i = 0
while i < len(my_list):
    item = my_list[i]
    i += 1
    do_something(i, item)
```

而不是你可以这样做：

```py
for i, item in enumerate(my_list):
    do_something(i, item)
```

虽然这可以写得更短，但通常不建议这样做，因为它不会提高可读性：

```py
[do_something(i, item) for i, item in enumerate(my_list)]
```

最后一个选项对一些人可能是清晰的，但对一些人可能不是。我个人更倾向于在实际存储结果时才使用列表推导、字典推导和 map 和 filter 语句。

例如：

```py
spam_items = [x for x in items if x.startswith('spam_')]
```

但前提是不会影响代码的可读性。

考虑一下这段代码：

```py
eggs = [is_egg(item) or create_egg(item) for item in list_of_items if egg and hasattr(egg, 'egg_property') and isinstance(egg, Egg)]  eggs = [is_egg(item) or create_egg(item) for item in list_of_items
        if egg and hasattr(egg, 'egg_property')
        and isinstance(egg, Egg)]
```

不要把所有东西都放在列表推导中，为什么不把它分成几个函数呢？

```py
def to_egg(item):
    return is_egg(item) or create_egg(item)

def can_be_egg(item):
    has_egg_property = hasattr(egg, 'egg_property')
    is_egg_instance = isinstance(egg, Egg)
    return egg and has_egg_property and is_egg_instance

eggs = [to_egg(item) for item in list_of_items if can_be_egg(item)]  eggs = [to_egg(item) for item in list_of_items if
        can_be_egg(item)]
```

虽然这段代码有点长，但我个人认为这样更易读。

### 最大行长度

许多 Python 程序员认为 79 个字符太过约束，只是保持行长。虽然我不会特别为 79 个字符辩论，但设置一个低且固定的限制，比如 79 或 99 是一个好主意。虽然显示器变得越来越宽，限制你的行仍然可以帮助你提高可读性，并且允许你将多个文件放在一起。我经常会打开四个 Python 文件并排放在一起。如果行宽超过 79 个字符，那就根本放不下了。

PEP8 指南告诉我们在行变得太长的情况下使用反斜杠。虽然我同意反斜杠比长行更可取，但我仍然认为应尽量避免使用。以下是 PEP8 的一个例子：

```py
with open('/path/to/some/file/you/want/to/read') as file_1, \
        open('/path/to/some/file/being/written', 'w') as file_2:
    file_2.write(file_1.read())
```

我会重新格式化它，而不是使用反斜杠：

```py
filename_1 = '/path/to/some/file/you/want/to/read'
filename_2 = '/path/to/some/file/being/written'
with open(filename_1) as file_1, open(filename_2, 'w') as file_2:
    file_2.write(file_1.read())
```

或者可能是以下内容：

```py
filename_1 = '/path/to/some/file/you/want/to/read'
filename_2 = '/path/to/some/file/being/written'
with open(filename_1) as file_1:
    with open(filename_2, 'w') as file_2:
        file_2.write(file_1.read())
```

当然并非总是一个选择，但保持代码简洁和可读是一个很好的考虑。它实际上为代码添加了更多信息的奖励。如果您使用传达文件名目标的名称，而不是`filename_1`，那么您正在尝试做什么就立即变得更清晰。

## 验证代码质量，pep8，pyflakes 等

有许多用于检查 Python 代码质量的工具。最简单的工具，比如`pep8`，只验证一些简单的`PEP8`错误。更先进的工具，比如`pylint`，进行高级内省，以检测潜在的错误在其他情况下工作的代码。`pylint`提供的大部分内容对许多项目来说有点过头，但仍然值得一看。

### flake8

`flake8`工具将 pep8、pyflakes 和 McCabe 结合起来，为代码设置了一个质量标准。`flake8`工具是我维护代码质量中最重要的包之一。我维护的所有包都要求 100%的`flake8`兼容性。它并不承诺可读的代码，但至少要求一定程度的一致性，这在与多个程序员一起编写项目时非常重要。

#### Pep8

用于检查 Python 代码质量的最简单的工具之一是`pep8`包。它并不检查 PEP8 标准中的所有内容，但它走了很长一段路，并且仍然定期更新以添加新的检查。`pep8`检查的一些最重要的事情如下：

+   缩进，虽然 Python 不会检查你用多少空格缩进，但这并不有助于你的代码可读性

+   缺少空格，比如`spam=123`

+   太多的空格，比如`def eggs(spam = 123):`

+   太多或太少的空行

+   行太长

+   语法和缩进错误

+   不正确和/或多余的比较（`not in`，`is not`，`if spam is True`，以及没有`isinstance`的类型比较）

结论是，`pep8`工具在测试空格和一些常见的样式问题方面帮助很大，但仍然相当有限。

#### pyflakes

这就是 pyflakes 的用武之地。pyflakes 比`pep8`更智能，它会警告你一些风格问题，比如：

+   未使用的导入

+   通配符导入（`from module import *`）

+   不正确的`__future__`导入（在其他导入之后）

但更重要的是，它会警告潜在的错误，比如以下内容：

+   重新定义已导入的名称

+   使用未定义的变量

+   在赋值之前引用变量

+   重复的参数名称

+   未使用的局部变量

PEP8 的最后一部分由 pep8-naming 包涵盖。它确保您的命名接近 PEP8 规定的标准：

+   类名为*CapWord*

+   函数、变量和参数名称全部小写

+   常量全大写并被视为常量

+   实例方法和类方法的第一个参数分别为*self*和*cls*

#### McCabe

最后，还有 McCabe 复杂性。它通过查看**抽象语法树**（**AST**）来检查代码的复杂性。它会找出有多少行、级别和语句，并在您的代码比预先配置的阈值更复杂时警告您。通常，您将通过`flake8`使用 McCabe，但也可以手动调用。使用以下代码：

```py
def spam():
    pass

def eggs(matrix):
    for x in matrix:
        for y in x:
            for z in y:
                print(z, end='')
            print()
        print()
```

McCabe 将给我们以下输出：

```py
# pip install mccabe
...
# python -m mccabe cabe_test.py 1:1: 'spam' 1
5:1: 'eggs' 4

```

当然，您的最大阈值是可配置的，但默认值为 10。 McCabe 测试返回一个受函数大小、嵌套深度和其他一些参数影响的数字。如果您的函数达到 10，可能是时候重构代码了。

#### flake8

所有这些组合在一起就是`flake8`，这是一个将这些工具结合起来并输出单个报告的工具。`flake8`生成的一些警告可能不符合您的口味，因此如果需要，每一项检查都可以在文件级别和整个项目级别上禁用。例如，我个人在所有项目中都禁用`W391`，它会警告文件末尾的空行。这是我在编写代码时发现很有用的，这样我就可以轻松地跳到文件末尾并开始编写代码，而不必先添加几行。

一般来说，在提交代码和/或将其放在网上之前，只需从源目录运行`flake8`以递归检查所有内容。

以下是一些格式不佳的代码演示：

```py
def spam(a,b,c):
    print(a,b+c)

def eggs():
    pass
```

它的结果如下：

```py
# pip install flake8
...
# flake8 flake8_test.py
flake8_test.py:1:11: E231 missing whitespace after ','
flake8_test.py:1:13: E231 missing whitespace after ','
flake8_test.py:2:12: E231 missing whitespace after ','
flake8_test.py:2:14: E226 missing whitespace around arithmetic operator
flake8_test.py:4:1: E302 expected 2 blank lines, found 1

```

### Pylint

`pylint`是一个更先进的——在某些情况下更好的——代码质量检查器。然而，`pylint`的强大功能也带来了一些缺点。而`flake8`是一个非常快速、轻量级和安全的质量检查工具，`pylint`具有更先进的内省，因此速度要慢得多。此外，`pylint`很可能会给出大量无关或甚至错误的警告。这可能被视为`pylint`的缺陷，但实际上更多的是被动代码分析的限制。诸如`pychecker`之类的工具实际上会加载和执行您的代码。在许多情况下，这是安全的，但也有一些情况是不安全的。想象一下执行一个删除文件的命令可能会发生什么。

虽然我对`pylint`没有意见，但一般来说，我发现大多数重要的问题都可以通过`flake8`来处理，其他问题也可以通过一些适当的编码标准轻松避免。如果配置正确，它可能是一个非常有用的工具，但如果没有配置，它会非常冗长。

# 常见陷阱

Python 是一种旨在清晰可读且没有任何歧义和意外行为的语言。不幸的是，这些目标并非在所有情况下都能实现，这就是为什么 Python 确实有一些特殊情况，它可能会做一些与您期望的不同的事情。

本节将向您展示编写 Python 代码时可能遇到的一些问题。

## 范围很重要！

在 Python 中有一些情况，您可能没有使用您实际期望的范围。一些例子是在声明类和使用函数参数时。

### 函数参数

以下示例显示了由于默认参数的粗心选择而导致的一个案例：

```py
def spam(key, value, list_=[], dict_={}):
    list_.append(value)
    dict_[key] = value

    print('List: %r' % list_)
    print('Dict: %r' % dict_)

spam('key 1', 'value 1')
spam('key 2', 'value 2')
```

您可能会期望以下输出：

```py
List: ['value 1']
Dict: {'key 1': 'value 1'}
List: ['value 2']
Dict: {'key 2': 'value 2'}
```

但实际上是这样的：

```py
List: ['value 1']
Dict: {'key 1': 'value 1'}
List: ['value 1', 'value 2']
Dict: {'key 1': 'value 1', 'key 2': 'value 2'}
```

原因是`list_`和`dict_`实际上是在多次调用之间共享的。唯一有用的情况是在做一些巧妙的事情时，所以请避免在函数中使用可变对象作为默认参数。

相同示例的安全替代如下：

```py
def spam(key, value, list_=None, dict_=None):
    if list_ is None:
        list_ = []

    if dict_ is None:
        dict_ {}

    list_.append(value)
    dict_[key] = value
```

### 类属性

在定义类时也会出现问题。很容易混淆类属性和实例属性。特别是对于从其他语言（如 C#）转过来的人来说，这可能会令人困惑。让我们来举个例子：

```py
class Spam(object):
    list_ = []
    dict_ = {}

    def __init__(self, key, value):
        self.list_.append(value)
        self.dict_[key] = value

        print('List: %r' % self.list_)
        print('Dict: %r' % self.dict_)

Spam('key 1', 'value 1')
Spam('key 2', 'value 2')
```

与函数参数一样，列表和字典是共享的。因此，输出如下：

```py
List: ['value 1']
Dict: {'key 1': 'value 1'}
List: ['value 1', 'value 2']
Dict: {'key 1': 'value 1', 'key 2': 'value 2'}
```

更好的选择是在类的`__init__`方法中初始化可变对象。这样，它们不会在实例之间共享：

```py
class Spam(object):
    def __init__(self, key, value):
        self.list_ = [key]
        self.dict_ = {key: value}

        print('List: %r' % self.list_)
        print('Dict: %r' % self.dict_)
```

处理类时需要注意的另一件重要事情是，类属性将被继承，这可能会让事情变得混乱。在继承时，原始属性将保留（除非被覆盖），即使在子类中也是如此：

```py
 **>>> class A(object):
...     spam = 1

>>> class B(A):
...     pass

Regular inheritance, the spam attribute of both A and B are 1 as
you would expect.
>>> A.spam
1
>>> B.spam
1

Assigning 2 to A.spam now modifies B.spam as well
>>> A.spam = 2

>>> A.spam
2
>>> B.spam
2

```

虽然由于继承而可以预料到这一点，但使用类的其他人可能不会怀疑变量在此期间发生变化。毕竟，我们修改了`A.spam`，而不是`B.spam`。

有两种简单的方法可以避免这种情况。显然，可以简单地为每个类单独设置`spam`。但更好的解决方案是永远不要修改类属性。很容易忘记属性将在多个位置更改，如果它必须是可修改的，通常最好将其放在实例变量中。

### 修改全局范围的变量

从全局范围访问变量时的一个常见问题是，设置变量会使其成为局部变量，即使访问全局变量也是如此。

这样可以工作：

```py
 **>>> def eggs():
...     print('Spam: %r' % spam)

>>> eggs()
Spam: 1

```

但以下内容不是：

```py
 **>>> spam = 1

>>> def eggs():
...     spam += 1
...     print('Spam: %r' % spam)

>>> eggs()
Traceback (most recent call last):
 **...
UnboundLocalError: local variable 'spam' referenced before assignment

```

问题在于`spam += 1`实际上转换为`spam = spam + 1`，而包含`spam =`的任何内容都会使变量成为您的范围内的局部变量。由于在那一点上正在分配局部变量，它还没有值，您正在尝试使用它。对于这些情况，有`global`语句，尽管我真的建议您完全避免使用全局变量。

## 覆盖和/或创建额外的内置函数

虽然在某些情况下可能有用，但通常您会希望避免覆盖全局函数。命名函数的`PEP8`约定-类似于内置语句、函数和变量-是使用尾随下划线。

因此，不要使用这个：

```py
list = [1, 2, 3]
```

而是使用以下方法：

```py
list_ = [1, 2, 3]
```

对于列表等，这只是一个很好的约定。对于`from`、`import`和`with`等语句，这是一个要求。忘记这一点可能会导致非常令人困惑的错误：

```py
>>> list = list((1, 2, 3))
>>> list
[1, 2, 3]

>>> list((4, 5, 6))
Traceback (most recent call last):
 **...
TypeError: 'list' object is not callable

>>> import = 'Some import'
Traceback (most recent call last):
 **...
SyntaxError: invalid syntax

```

如果您确实想要定义一个在任何地方都可用的内置函数，是可能的。出于调试目的，我已经知道在开发项目时向项目中添加此代码：

```py
import builtins
import inspect
import pprint
import re

def pp(*args, **kwargs):
    '''PrettyPrint function that prints the variable name when
    available and pprints the data'''
    name = None
    # Fetch the current frame from the stack
    frame = inspect.currentframe().f_back
    # Prepare the frame info
    frame_info = inspect.getframeinfo(frame)

    # Walk through the lines of the function
    for line in frame_info[3]:
        # Search for the pp() function call with a fancy regexp
        m = re.search(r'\bpp\s*\(\s*([^)]*)\s*\)', line)
        if m:
            print('# %s:' % m.group(1), end=' ')
            break

    pprint.pprint(*args, **kwargs)

builtins.pf = pprint.pformat
builtins.pp = pp
```

对于生产代码来说太过狡猾，但在需要打印语句进行调试的大型项目中仍然很有用。替代（更好的）调试解决方案可以在第十一章“调试-解决错误”中找到。

使用起来非常简单：

```py
x = 10
pp(x)
```

以下是输出：

```py
# x: 10
```

## 在迭代时修改

在某个时候，您将遇到这个问题：在迭代可变对象（如列表、字典或集合）时，您不能修改它们。所有这些都会导致`RuntimeError`告诉您在迭代期间不能修改对象：

```py
dict_ = {'spam': 'eggs'}
list_ = ['spam']
set_ = {'spam', 'eggs'}

for key in dict_:
    del dict_[key]

for item in list_:
    list_.remove(item)

for item in set_:
    set_.remove(item)
```

这可以通过复制对象来避免。最方便的选项是使用`list`函数：

```py
dict_ = {'spam': 'eggs'}
list_ = ['spam']
set_ = {'spam', 'eggs'}

for key in list(dict_):
    del dict_[key]

for item in list(list_):
    list_.remove(item)

for item in list(set_):
    set_.remove(item)
```

## 捕获异常- Python 2 和 3 之间的区别

使用 Python 3，捕获异常并存储它已经变得更加明显，使用`as`语句。问题在于许多人仍然习惯于`except Exception, variable`语法，这种语法已经不再起作用。幸运的是，Python 3 的语法已经回溯到 Python 2，所以现在您可以在任何地方使用以下语法：

```py
try:
    ... # do something here
except (ValueError, TypeError) as e:
    print('Exception: %r' % e)
```

另一个重要的区别是，Python 3 使这个变量局限于异常范围。结果是，如果您想要在`try`/`except`块之后使用它，您需要在之前声明异常变量：

```py
def spam(value):
    try:
        value = int(value)
    except ValueError as exception:
        print('We caught an exception: %r' % exception)

    return exception

spam('a')
```

您可能期望由于我们在这里得到一个异常，这样可以工作；但实际上，它不起作用，因为在`return`语句的那一点上`exception`不存在。

实际输出如下：

```py
We caught an exception: ValueError("invalid literal for int() with base 10: 'a'",)
Traceback (most recent call last):
  File "test.py", line 14, in <module>
    spam('a')
  File "test.py", line 11, in spam
    return exception
UnboundLocalError: local variable 'exception' referenced before assignment
```

就个人而言，我会认为前面的代码在任何情况下都是错误的：如果没有异常怎么办？它会引发相同的错误。幸运的是，修复很简单；只需将值写入到作用域之外的变量中。这里需要注意的一点是，你需要明确保存变量到父作用域。这段代码也不起作用：

```py
def spam(value):
    exception = None
    try:
        value = int(value)
    except ValueError as exception:
        print('We caught an exception: %r' % exception)

    return exception
```

我们真的需要明确保存它，因为 Python 3 会自动删除在`except`语句结束时使用`as variable`保存的任何内容。这样做的原因是 Python 3 的异常包含一个`__traceback__`属性。拥有这个属性会让垃圾收集器更难处理，因为它引入了一个递归的自引用循环（*exception -> traceback -> exception -> traceback… ad nauseum*）。为了解决这个问题，Python 基本上执行以下操作：

```py
exception = None
try:
    value = int(value)
except ValueError as exception:
    try:
        print('We caught an exception: %r' % exception)
    finally:
        del exception
```

解决方案非常简单 - 幸运的是 - 但你应该记住，这可能会在程序中引入内存泄漏。Python 的垃圾收集器足够聪明，可以理解这些变量不再可见，并最终会删除它，但这可能需要更长的时间。垃圾收集实际上是如何工作的在第十二章中有介绍，*性能 - 跟踪和减少内存和 CPU 使用情况*。这是代码的工作版本：

```py
def spam(value):
    exception = None
    try:
        value = int(value)
    except ValueError as e:
        exception = e
        print('We caught an exception: %r' % exception)

    return exception
```

## 延迟绑定 - 要小心闭包

闭包是在代码中实现局部作用域的一种方法。它使得可以在本地定义变量，而不会覆盖父（或全局）作用域中的变量，并且稍后将变量隐藏在外部作用域中。Python 中闭包的问题在于出于性能原因，Python 尝试尽可能晚地绑定其变量。虽然通常很有用，但它确实具有一些意想不到的副作用：

```py
eggs = [lambda a: i * a for i in range(3)]

for egg in eggs:
    print(egg(5))
```

预期结果？应该是这样的，对吧？

```py
0
5
10
```

不，不幸的是。这类似于类继承与属性的工作方式。由于延迟绑定，变量`i`在调用时从周围的作用域中调用，而不是在实际定义时调用。

实际结果如下：

```py
10
10
10
```

那么应该怎么做呢？与前面提到的情况一样，需要将变量设为局部变量。一种替代方法是通过使用`partial`对函数进行柯里化来强制立即绑定。

```py
import functools

eggs = [functools.partial(lambda i, a: i * a, i) for i in range(3)]

for egg in eggs:
    print(egg(5))
```

更好的解决方案是通过不引入额外的作用域（`lambda`）来避免绑定问题，这些作用域使用外部变量。如果`i`和`a`都被指定为`lambda`的参数，这将不是一个问题。

## 循环导入

尽管 Python 对循环导入相当宽容，但也有一些情况会出现错误。

假设我们有两个文件。

`eggs.py`：

```py
from spam import spam

def eggs():
    print('This is eggs')
    spam()
```

`spam.py`：

```py
from eggs import eggs

def spam():
    print('This is spam')

if __name__ == '__main__':
    eggs()
```

运行`spam.py`将导致循环`import`错误：

```py
Traceback (most recent call last):
  File "spam.py", line 1, in <module>
    from eggs import eggs
  File "eggs.py", line 1, in <module>
    from spam import spam
  File "spam.py", line 1, in <module>
    from eggs import eggs
ImportError: cannot import name 'eggs'
```

有几种方法可以解决这个问题。重新构造代码通常是最好的方法，但最佳解决方案取决于问题。在前面的情况下，可以很容易地解决。只需使用模块导入而不是函数导入（无论是否存在循环导入，我都建议这样做）。

`eggs.py`：

```py
import spam

def eggs():
    print('This is eggs')
    spam.spam()
```

`spam.py`：

```py
import eggs

def spam():
    print('This is spam')

if __name__ == '__main__':
    eggs.eggs()
```

另一种解决方案是将导入语句移到函数内部，以便在运行时发生。这不是最漂亮的解决方案，但在许多情况下都能解决问题。

`eggs.py`：

```py
def eggs():
    from spam import spam
    print('This is eggs')
    spam()
```

`spam.py`：

```py
def spam():
    from eggs import eggs
    print('This is spam')

if __name__ == '__main__':
    eggs()
```

最后还有一种解决方案，即将导入移到实际使用它们的代码下面。这通常不被推荐，因为它可能会使导入的位置不明显，但我仍然认为这比在函数调用中使用`import`更可取。

`eggs.py`：

```py
def eggs():
    print('This is eggs')
    spam()

from spam import spam
```

`spam.py`：

```py
def spam():
    print('This is spam')

from eggs import eggs

if __name__ == '__main__':
    eggs()
```

是的，还有其他解决方案，比如动态导入。其中一个例子是 Django 的`ForeignKey`字段支持字符串而不是实际类。但这些通常是一个非常糟糕的想法，因为它们只会在运行时进行检查。因此，错误只会在执行使用它的任何代码时引入，而不是在修改代码时引入。因此，请尽量避免这些情况，或者确保添加适当的自动化测试以防止意外错误。特别是当它们在内部引起循环导入时，它们将成为一个巨大的调试痛点。

## 导入冲突

一个极其令人困惑的问题是导入冲突——多个具有相同名称的包/模块。我在我的包上收到了不少 bug 报告，例如，有人试图使用我的`numpy-stl`项目，它位于名为`stl`的包中的一个名为`stl.py`的测试文件。结果是：它导入了自身而不是`stl`包。虽然这种情况很难避免，至少在包内部，相对导入通常是一个更好的选择。这是因为它还告诉其他程序员，导入来自本地范围而不是另一个包。因此，不要写`import spam`，而是写`from . import spam`。这样，代码将始终从当前包加载，而不是任何偶然具有相同名称的全局包。

除此之外，还存在包之间不兼容的问题。常见名称可能被几个包使用，因此在安装这些包时要小心。如果有疑问，只需创建一个新的虚拟环境，然后再试一次。这样做可以节省大量的调试时间。

# 摘要

本章向我们展示了 Python 哲学的全部内容，并向我们解释了 Python 之禅的含义。虽然代码风格是非常个人化的，但 Python 至少有一些非常有帮助的指导方针，至少能让人们大致保持在同一页面和风格上。最后，我们都是成年人；每个人都有权利按照自己的意愿编写代码。但我请求您。请阅读风格指南，并尽量遵守它们，除非您有一个真正充分的理由不这样做。

随着这种力量而来的是巨大的责任，也有一些陷阱，尽管并不多。有些陷阱足够棘手，以至于经常会让我困惑，而我已经写了很长时间的 Python 了！Python 不断改进。自 Python 2 以来，许多陷阱已经得到解决，但有些将永远存在。例如，递归导入和定义在大多数支持它们的语言中很容易让你掉进陷阱，但这并不意味着我们会停止努力改进 Python。

Python 多年来的改进的一个很好的例子是 collections 模块。它包含了许多有用的集合，这些集合是由用户添加的，因为有这样的需求。其中大多数实际上是用纯 Python 实现的，因此它们很容易被任何人阅读。理解可能需要更多的努力，但我真的相信，如果你能读完这本书，你将没有问题理解这些集合的作用。但我不能保证完全理解内部工作；其中一些部分更多地涉及通用计算机科学而不是 Python 掌握。

下一章将向您展示 Python 中可用的一些集合以及它们的内部构造。尽管您无疑熟悉列表和字典等集合，但您可能不清楚某些操作涉及的性能特征。如果本章中的一些示例不够清晰，您不必担心。下一章将至少重新讨论其中一些，并且更多内容将在后续章节中介绍。


# 第三章：容器和集合-正确存储数据

Python 捆绑了几个非常有用的集合，其中一些是基本的 Python 集合数据类型。其余的是这些类型的高级组合。在本章中，我们将解释其中一些集合的使用方法，以及它们各自的优缺点。

在我们正式讨论数据结构和相关性能之前，需要对时间复杂度（特别是大 O 符号）有基本的了解。不用担心！这个概念非常简单，但没有它，我们无法轻松地解释操作的性能特征。

一旦大 O 符号清晰，我们将讨论基本数据结构：

+   `list`

+   `dict`

+   `set`

+   `tuple`

在基本数据结构的基础上，我们将继续介绍更高级的集合，例如以下内容：

+   类似字典的类型：

+   `ChainMap`

+   `Counter`

+   `Defaultdict`

+   `OrderedDict`

+   列表类型：

+   `Deque`

+   `Heapq`

+   元组类型：

+   `NamedTuple`

+   其他类型：

+   `Enum`

# 时间复杂度-大 O 符号

在开始本章之前，您需要了解一个简单的符号。本章大量使用大 O 符号来指示操作的时间复杂度。如果您已经熟悉这个符号，可以跳过这一段。虽然这个符号听起来很复杂，但实际概念非常简单。

当我们说一个函数需要`O(1)`的时间时，这意味着通常只需要`1`步来执行。同样，一个具有`O(n)`的函数将需要`n`步来执行，其中`n`通常是对象的大小。这种时间复杂度只是对执行代码时可以预期的基本指示，因为这通常是最重要的。

该系统的目的是指示操作的大致性能；这与代码速度无关，但仍然相关。执行单个步骤的代码`1000`次更快，但需要执行`O(2**n)`步骤的代码仍然比另一个版本慢，因为对于 n 等于`10`或更高的值，它只需要`O(n)`步骤。这是因为`n=10`时`2**n`为`2**10=1024`，也就是说，执行相同代码需要 1,024 步。这使得选择正确的算法非常重要。即使`C`代码通常比 Python 快，如果使用错误的算法，也毫无帮助。

例如，假设您有一个包含`1000`个项目的列表，并且您遍历它们。这将花费`O(n)`的时间，因为有`n=1000`个项目。检查项目是否存在于列表中需要`O(n)`的时间，因此需要 1,000 步。这样做 100 次将花费`100*O(n) = 100 * 1000 = 100,000`步。当您将其与`dict`进行比较时，检查项目是否存在只需要`O(1)`的时间，差异是巨大的。使用`dict`，将是`100*O(1) = 100 * 1 = 100`步。因此，对于包含 1000 个项目的对象，使用`dict`而不是`list`将大约快 1,000 倍：

```py
n = 1000
a = list(range(n))
b = dict.fromkeys(range(n))
for i in range(100):
    i in a  # takes n=1000 steps
    i in b  # takes 1 step
```

为了说明`O(1)`，`O(n)`和`O(n**2)`函数：

```py
def o_one(items):
    return 1  # 1 operation so O(1)

def o_n(items):
    total = 0
    # Walks through all items once so O(n)
    for item in items:
        total += item
    return total

def o_n_squared(items):
    total = 0
    # Walks through all items n*n times so O(n**2)
    for a in items:
        for b in items:
            total += a * b
    return total

n = 10
items = range(n)
o_one(items)  # 1 operation
o_n(items)  # n = 10 operations
o_n_squared(items)  # n*n = 10*10 = 100 operations
```

应该注意，本章中的大 O 是关于平均情况，而不是最坏情况。在某些情况下，它们可能更糟，但这些情况很少，可以忽略不计。

# 核心集合

在本章稍后讨论更高级的组合集合之前，您需要了解核心 Python 集合的工作原理。这不仅仅是关于使用，还涉及到时间复杂度，这会对应用程序随着增长而产生强烈影响。如果您熟悉这些对象的时间复杂度，并且熟记 Python 3 的元组打包和解包的可能性，那么可以直接跳到*高级集合*部分。

## list - 一个可变的项目列表

`list`很可能是您在 Python 中最常用的容器结构。它的使用简单，对于大多数情况，性能很好。

虽然你可能已经熟悉了列表的使用，但你可能不知道`list`对象的时间复杂度。幸运的是，`list`的许多时间复杂度非常低；`append`，`get`，`set`和`len`都需要`O(1)`的时间-这是最好的可能性。但是，你可能不知道`remove`和`insert`的时间复杂度是`O(n)`。因此，要从 1000 个项目中删除一个项目，Python 将不得不遍历 1000 个项目。在内部，`remove`和`insert`操作执行类似于这样的操作：

```py
>>> def remove(items, value):
...     new_items = []
...     found = False
...     for item in items:
...         # Skip the first item which is equal to value
...         if not found and item == value:
...             found = True
...             continue
...         new_items.append(item)
...
...     if not found:
...         raise ValueError('list.remove(x): x not in list')
...
...     return new_items

>>> def insert(items, index, value):
...     new_items = []
...     for i, item in enumerate(items):
...         if i == index:
...             new_items.append(value)
...         new_items.append(item)
...     return new_items

>>> items = list(range(10))
>>> items
[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

>>> items = remove(items, 5)
>>> items
[0, 1, 2, 3, 4, 6, 7, 8, 9]

>>> items = insert(items, 2, 5)
>>> items
[0, 1, 5, 2, 3, 4, 6, 7, 8, 9]

```

要从列表中删除或插入单个项目，Python 需要复制整个列表，这在列表较大时特别耗费资源。当执行一次时，当然不是那么糟糕。但是当执行大量删除时，`filter`或`list`推导是一个更快的解决方案，因为如果结构良好，它只需要复制列表一次。例如，假设我们希望从列表中删除一组特定的数字。我们有很多选项。第一个是使用`remove`，然后是列表推导，然后是`filter`语句。第四章, *功能编程-可读性与简洁性*，将更详细地解释`list`推导和`filter`语句。但首先，让我们看看这个例子：

```py
>>> primes = set((1, 2, 3, 5, 7))

# Classic solution
>>> items = list(range(10))
>>> for prime in primes:
...     items.remove(prime)
>>> items
[0, 4, 6, 8, 9]

# List comprehension
>>> items = list(range(10))
>>> [item for item in items if item not in primes]
[0, 4, 6, 8, 9]

# Filter
>>> items = list(range(10))
>>> list(filter(lambda item: item not in primes, items))
[0, 4, 6, 8, 9]

```

后两种对于大量项目的列表要快得多。这是因为操作要快得多。比较使用`n=len(items)`和`m=len(primes)`，第一个需要`O(m*n)=5*10=50`次操作，而后两个需要`O(n*1)=10*1=10`次操作。

### 注意

第一种方法实际上比这更好一些，因为`n`在循环过程中减少。所以，实际上是`10+9+8+7+6=40`，但这是一个可以忽略的效果。在`n=1000`的情况下，这将是`1000+999+998+997+996=4990`和`5*1000=5000`之间的差异，在大多数情况下是可以忽略的。

当然，`min`，`max`和`in`都需要`O(n)`，但这对于一个不是为这些类型的查找进行优化的结构来说是可以预料的。

它们可以这样实现：

```py
>>> def in_(items, value):
...     for item in items:
...         if item == value:
...             return True
...     return False

>>> def min_(items):
...     current_min = items[0]
...     for item in items[1:]:
...         if current_min > item:
...             current_min = item
...     return current_min

>>> def max_(items):
...     current_max = items[0]
...     for item in items[1:]:
...         if current_max < item:
...             current_max = item
...     return current_max

>>> items = range(5)
>>> in_(items, 3)
True
>>> min_(items)
0
>>> max_(items)
4

```

通过这些例子，很明显`in`运算符如果你幸运的话可以工作`O(1)`，但我们将其视为`O(n)`，因为它可能不存在，如果不存在，那么所有的值都需要被检查。

## dict-无序但快速的项目映射

`dict`必须至少是你在 Python 中使用的前三种容器结构之一。它快速，易于使用，非常有效。平均时间复杂度正如你所期望的那样-`O(1)`对于`get`，`set`和`del`-但也有一些例外。`dict`的工作方式是通过使用`hash`函数（调用对象的`__hash__`函数）将键转换为哈希并将其存储在哈希表中。然而，哈希表有两个问题。第一个和最明显的问题是，项目将按哈希排序，这在大多数情况下是随机的。哈希表的第二个问题是它们可能会发生哈希冲突，哈希冲突的结果是在最坏的情况下，所有先前的操作可能需要`O(n)`。哈希冲突并不太可能发生，但它们可能发生，如果一个大的`dict`表现不佳，那就是需要查看的地方。

让我们看看这在实践中是如何工作的。为了举例说明，我将使用我能想到的最简单的哈希算法，即数字的最高位。所以，对于`12345`，它将返回`1`，对于`56789`，它将返回`5`：

```py
>>> def most_significant(value):
...     while value >= 10:
...         value //= 10
...     return value

>>> most_significant(12345)
1
>>> most_significant(99)
9
>>> most_significant(0)
0

```

现在我们将使用这种哈希方法使用一个列表的列表来模拟一个`dict`。我们知道我们的哈希方法只能返回`0`到`9`之间的数字，所以我们在列表中只需要 10 个桶。现在我们将添加一些值，并展示 spam in eggs 可能如何工作：

```py
>>> def add(collection, key, value):
...     index = most_significant(key)
...     collection[index].append((key, value))

>>> def contains(collection, key):
...     index = most_significant(key)
...     for k, v in collection[index]:
...         if k == key:
...             return True
...     return False

# Create the collection of 10 lists
>>> collection = [[], [], [], [], [], [], [], [], [], []]

# Add some items, using key/value pairs
>>> add(collection, 123, 'a')
>>> add(collection, 456, 'b')
>>> add(collection, 789, 'c')
>>> add(collection, 101, 'c')

# Look at the collection
>>> collection
[[], [(123, 'a'), (101, 'c')], [], [],
 **[(456, 'b')], [], [], [(789, 'c')], [], []]

# Check if the contains works correctly
>>> contains(collection, 123)
True
>>> contains(collection, 1)
False

```

这段代码显然与`dict`的实现不同，但在内部实际上非常相似。因为我们可以通过简单的索引获取值为`123`的项`1`，所以在一般情况下，我们只有`O(1)`的查找成本。然而，由于`123`和`101`两个键都在`1`桶中，运行时实际上可能增加到`O(n)`，在最坏的情况下，所有键都具有相同的散列。这就是我们所说的散列冲突。

### 提示

要调试散列冲突，可以使用`hash()`函数与计数集合配对，这在*counter – keeping track of the most occurring elements*部分有讨论。

除了散列冲突性能问题，还有另一种可能让你感到惊讶的行为。当从字典中删除项时，它实际上不会立即调整内存中的字典大小。结果是复制和迭代整个字典都需要`O(m)`时间（其中 m 是字典的最大大小）；当前项数 n 不会被使用。因此，如果向`dict`中添加 1000 个项并删除 999 个项，迭代和复制仍将需要 1000 步。解决此问题的唯一方法是重新创建字典，这是`copy`和`insert`操作都会在内部执行的操作。请注意，`insert`操作期间的重新创建不是保证的，而是取决于内部可用的空闲插槽数量。

## set - 没有值的字典

`set`是一种使用散列方法获取唯一值集合的结构。在内部，它与`dict`非常相似，具有相同的散列冲突问题，但`set`有一些方便的功能需要展示：

```py
# All output in the table below is generated using this function
>>> def print_set(expression, set_):
...     'Print set as a string sorted by letters'
...     print(expression, ''.join(sorted(set_)))

>>> spam = set('spam')
>>> print_set('spam:', spam)
spam: amps

>>> eggs = set('eggs')
>>> print_set('eggs:', spam)
eggs: amps

```

前几个基本上都是预期的。在操作符处，它变得有趣起来。

| 表达式 | 输出 | 解释 |
| --- | --- | --- |
| `spam` | `amps` | 所有唯一的项。`set` 不允许重复。 |
| `eggs` | `egs` |
| `spam & eggs` | `s` | 两者中的每一项。 |
| `spam &#124; eggs` | `aegmps` | 两者中的任一项或两者都有的。 |
| `spam ^ eggs` | `aegmp` | 两者中的任一项，但不是两者都有的。 |
| `spam - eggs` | `amp` | 第一个中的每一项，但不是后者中的。 |
| `eggs - spam` | `eg` |
| `spam > eggs` | `False` | 如果后者中的每一项都在前者中，则为真。 |
| `eggs > spam` | `False` |
| `spam > sp` | `True` |
| `spam < sp` | `False` | 如果第一个中的每一项都包含在后者中，则为真。 |

`set`操作的一个有用示例是计算两个对象之间的差异。例如，假设我们有两个列表：

+   `current_users`: 组中的当前用户

+   `new_users`: 组中的新用户列表

在权限系统中，这是一个非常常见的场景——从组中批量添加和/或删除用户。在许多权限数据库中，不容易一次设置整个列表，因此你需要一个要插入的列表和一个要删除的列表。这就是`set`真正方便的地方：

```py
The set function takes a sequence as argument so the double ( is
required.
>>> current_users = set((
...     'a',
...     'b',
...     'd',
... ))

>>> new_users = set((
...     'b',
...     'c',
...     'd',
...     'e',
... ))

>>> to_insert = new_users - current_users
>>> sorted(to_insert)
['c', 'e']
>>> to_delete = current_users - new_users
>>> sorted(to_delete)
['a']
>>> unchanged = new_users & current_users
>>> sorted(unchanged)
['b', 'd']

```

现在我们有了所有被添加、删除和未更改的用户列表。请注意，`sorted`仅用于一致的输出，因为`set`与`dict`类似，没有预定义的排序顺序。

## 元组 - 不可变列表

`tuple`是一个你经常使用而甚至都没有注意到的对象。当你最初看到它时，它似乎是一个无用的数据结构。它就像一个你无法修改的列表，那么为什么不只使用`list`呢？有一些情况下，`tuple`提供了一些`list`没有的非常有用的功能。

首先，它们是可散列的。这意味着你可以将`tuple`用作`dict`中的键，这是`list`无法做到的：

```py
>>> spam = 1, 2, 3
>>> eggs = 4, 5, 6

>>> data = dict()
>>> data[spam] = 'spam'
>>> data[eggs] = 'eggs'

>>> import pprint  # Using pprint for consistent and sorted output
>>> pprint.pprint(data)
{(1, 2, 3): 'spam', (4, 5, 6): 'eggs'}

```

然而，它实际上可以比简单的数字更复杂。只要`tuple`的所有元素都是可散列的，它就可以工作。这意味着你可以使用嵌套的元组、字符串、数字和任何其他`hash()`函数返回一致结果的东西：

```py
>>> spam = 1, 'abc', (2, 3, (4, 5)), 'def'
>>> eggs = 4, (spam, 5), 6

>>> data = dict()
>>> data[spam] = 'spam'
>>> data[eggs] = 'eggs'
>>> import pprint  # Using pprint for consistent and sorted output
>>> pprint.pprint(data)
{(1, 'abc', (2, 3, (4, 5)), 'def'): 'spam',
 **(4, ((1, 'abc', (2, 3, (4, 5)), 'def'), 5), 6): 'eggs'}

```

你可以使它们变得如你所需的那样复杂。只要所有部分都是可散列的，它就会按预期运行。

也许更有用的是元组也支持元组打包和解包：

```py
# Assign using tuples on both sides
>>> a, b, c = 1, 2, 3
>>> a
1

# Assign a tuple to a single variable
>>> spam = a, (b, c)
>>> spam
(1, (2, 3))

# Unpack a tuple to two variables
>>> a, b = spam
>>> a
1
>>> b
(2, 3)

```

除了常规的打包和解包外，从 Python 3 开始，我们实际上可以使用可变数量的项目打包和解包对象：

```py
# Unpack with variable length objects which actually assigns as a
list, not a tuple
>>> spam, *eggs = 1, 2, 3, 4
>>> spam
1
>>> eggs
[2, 3, 4]

# Which can be unpacked as well of course
>>> a, b, c = eggs
>>> c
4

# This works for ranges as well
>>> spam, *eggs = range(10)
>>> spam
0
>>> eggs
[1, 2, 3, 4, 5, 6, 7, 8, 9]

# Which works both ways
>>> a
2
>>> a, b, *c = a, *eggs
>>> a, b
(2, 1)
>>> c
[2, 3, 4, 5, 6, 7, 8, 9]

```

这种方法在许多情况下都可以应用，甚至用于函数参数：

```py
>>> def eggs(*args):
...     print('args:', args)

>>> eggs(1, 2, 3)
args: (1, 2, 3)

```

同样，从函数返回多个参数也很有用：

```py
>>> def spam_eggs():
...     return 'spam', 'eggs'

>>> spam, eggs = spam_eggs()
>>> print('spam: %s, eggs: %s' % (spam, eggs))
spam: spam, eggs: eggs

```

# 高级集合

以下集合大多只是基本集合的扩展，其中一些非常简单，另一些则稍微复杂一些。不过，对于所有这些集合，了解底层结构的特性是很重要的。如果不了解它们，将很难理解这些集合的特性。

出于性能原因，有一些集合是用本机 C 代码实现的，但所有这些集合也可以很容易地在纯 Python 中实现。

## ChainMap - 字典列表

在 Python 3.3 中引入的`ChainMap`允许您将多个映射（例如字典）合并为一个。这在合并多个上下文时特别有用。例如，在查找当前作用域中的变量时，默认情况下，Python 会在`locals()`，`globals()`，最后是`builtins`中搜索。

通常，您会这样做：

```py
import builtins

builtin_vars = vars(builtins)
if key in locals():
    value = locals()[key]
elif key in globals():
    value = globals()[key]
elif key in builtin_vars:
    value = builtin_vars[key]
else:
    raise NameError('name %r is not defined' % key)
```

这样做是有效的，但至少可以说很丑陋。当然，我们可以让它更漂亮：

```py
import builtins

mappings = globals(), locals(), vars(builtins)
for mapping in mappings:
    if key in mapping:
        value = mapping[key]
        break
else:
    raise NameError('name %r is not defined' % key)
```

好多了！而且，这实际上可以被认为是一个不错的解决方案。但自从 Python 3.3 以来，它变得更容易了。现在我们可以简单地使用以下代码：

```py
import builtins
import collections

mappings = collections.ChainMap(globals(), locals(), vars(builtins))
value = mappings[key]
```

`ChainMap`集合对于命令行应用程序非常有用。最重要的配置是通过命令行参数进行的，然后是目录本地配置文件，然后是全局配置文件，最后是默认配置：

```py
import argparse
import collections

defaults = {
    'spam': 'default spam value',
    'eggs': 'default eggs value',
}

parser = argparse.ArgumentParser()
parser.add_argument('--spam')
parser.add_argument('--eggs')

args = vars(parser.parse_args())
# We need to check for empty/default values so we can't simply use vars(args)
filtered_args = {k: v for k, v in args.items() if v}

combined = collections.ChainMap(filtered_args, defaults)

print(combined ['spam'])
```

请注意，仍然可以访问特定的映射：

```py
print(combined.maps[1]['spam'])

for map_ in combined.maps:
    print(map_.get('spam'))
```

## counter - 跟踪最常出现的元素

`counter`是一个用于跟踪元素出现次数的类。它的基本用法如您所期望的那样：

```py
>>> import collections

>>> counter = collections.Counter('eggs')
>>> for k in 'eggs':
...     print('Count for %s: %d' % (k, counter[k]))
Count for e: 1
Count for g: 2
Count for g: 2
Count for s: 1

```

但是，`counter`不仅仅可以返回计数。它还有一些非常有用且快速（它使用`heapq`）的方法来获取最常见的元素。即使向计数器添加了一百万个元素，它仍然在一秒内执行：

```py
>>> import math
>>> import collections

>>> counter = collections.Counter()
>>> for i in range(0, 100000):
...    counter[math.sqrt(i) // 25] += 1

>>> for key, count in counter.most_common(5):
...     print('%s: %d' % (key, count))
11.0: 14375
10.0: 13125
9.0: 11875
8.0: 10625
12.0: 10000

```

但等等，还有更多！除了获取最频繁的元素之外，还可以像我们之前看到的`set`操作一样添加、减去、交集和"联合"计数器。那么添加两个计数器和对它们进行联合有什么区别呢？正如您所期望的那样，它们是相似的，但有一点不同。让我们看看它的工作原理：

```py
>>> import collections

>>> def print_counter(expression, counter):
...     sorted_characters = sorted(counter.elements())
...     print(expression, ''.join(sorted_characters))

>>> eggs = collections.Counter('eggs')
>>> spam = collections.Counter('spam')
>>> print_counter('eggs:', eggs)
eggs: eggs
>>> print_counter('spam:', spam)
spam: amps
>>> print_counter('eggs & spam:', eggs & spam)
eggs & spam: s
>>> print_counter('spam & eggs:', spam & eggs)
spam & eggs: s
>>> print_counter('eggs - spam:', eggs - spam)
eggs - spam: egg
>>> print_counter('spam - eggs:', spam - eggs)
spam - eggs: amp
>>> print_counter('eggs + spam:', eggs + spam)
eggs + spam: aeggmpss
>>> print_counter('spam + eggs:', spam + eggs)
spam + eggs: aeggmpss
>>> print_counter('eggs | spam:', eggs | spam)
eggs | spam: aeggmps
>>> print_counter('spam | eggs:', spam | eggs)
spam | eggs: aeggmps

```

前两个是显而易见的。`eggs`字符串只是一个包含两个"`g`"，一个"`s`"和一个"`e`"的字符序列，spam 几乎相同，但字母不同。

`spam & eggs`的结果（以及反向）也是非常可预测的。spam 和 eggs 之间唯一共享的字母是`s`，因此这就是结果。在计数方面，它只是对来自两者的共享元素执行`min(element_a, element_b)`，并得到最低值。

从 eggs 中减去字母`s`，`p`，`a`和`m`，剩下`e`和`g`。同样，从 spam 中删除`e`，`g`和`s`，剩下`p`，`a`和`m`。

现在，添加就像您所期望的那样 - 只是对两个计数器的每个元素进行逐个相加。

那么联合（OR）有什么不同呢？它获取每个计数器中元素的`max(element_a, element_b)`，而不是将它们相加；与添加的情况一样。

最后，正如前面的代码所示，elements 方法返回一个由计数重复的所有元素扩展列表。

### 注意

`Counter`对象将在执行数学运算期间自动删除零或更少的元素。

## deque - 双端队列

`deque`（双端队列）对象是最古老的集合之一。它是在 Python 2.4 中引入的，所以到目前为止已经有 10 多年的历史了。一般来说，这个对象对于大多数目的来说现在都太低级了，因为许多操作本来会使用它，现在有很好的支持库可用，但这并不使它变得不那么有用。

在内部，`deque`被创建为一个双向链表，这意味着每个项目都指向下一个和上一个项目。由于`deque`是双端的，列表本身指向第一个和最后一个元素。这使得从列表的开头/结尾添加和删除项目都是非常轻松的`O(1)`操作，因为只需要改变指向列表开头/结尾的指针，并且需要添加指针到第一个/最后一个项目，具体取决于是在开头还是结尾添加项目。

对于简单的堆栈/队列目的，使用双端队列似乎是浪费的，但性能足够好，我们不必担心产生的开销。`deque`类是完全在 C 中实现的（使用 CPython）。

它作为队列的使用非常简单：

```py
>>> import collections

>>> queue = collections.deque()
>>> queue.append(1)
>>> queue.append(2)
>>> queue
deque([1, 2])
>>> queue.popleft()
1
>>> queue.popleft()
2
>>> queue.popleft()
Traceback (most recent call last):
 **...
IndexError: pop from an empty deque

```

正如预期的那样，由于只有两个项目，我们尝试获取三个项目，所以会出现`IndexError`。

作为堆栈的使用几乎相同，但我们必须使用`pop`而不是`popleft`（或者使用`appendleft`而不是`append`）：

```py
>>> import collections

>>> queue = collections.deque()
>>> queue.append(1)
>>> queue.append(2)
>>> queue
deque([1, 2])
>>> queue.pop()
2
>>> queue.pop()
1
>>> queue.pop()
Traceback (most recent call last):
 **...
IndexError: pop from an empty deque

```

另一个非常有用的功能是`deque`可以使用`maxlen`参数作为循环队列。通过使用这个参数，它可以用来保留最后的`n`个状态消息或类似的东西：

```py
>>> import collections

>>> circular = collections.deque(maxlen=2)
>>> for i in range(5):
...     circular.append(i)
...     circular
deque([0], maxlen=2)
deque([0, 1], maxlen=2)
deque([1, 2], maxlen=2)
deque([2, 3], maxlen=2)
deque([3, 4], maxlen=2)
>>> circular
deque([3, 4], maxlen=2)

```

每当您需要单线程应用程序中的队列或堆栈类时，`deque`是一个非常方便的选择。如果您需要将对象同步到多线程操作，则`queue.Queue`类更适合。在内部，它包装了`deque`，但它是一个线程安全的替代方案。在同一类别中，还有一个用于异步操作的`asyncio.Queue`和一个用于多进程操作的`multiprocessing.Queue`。`asyncio`和多进程的示例分别可以在第七章和第十三章中找到。

## defaultdict - 具有默认值的字典

`defaultdict`绝对是我在 collections 包中最喜欢的对象。我仍然记得在它被添加到核心之前写过自己的版本。虽然它是一个相当简单的对象，但它对各种设计模式非常有用。您只需从一开始声明默认值，而不必每次都检查键的存在并添加值，这使得它非常有用。

例如，假设我们正在从连接的节点列表构建一个非常基本的图结构。

这是我们的连接节点列表（单向）：

```py
nodes = [
    ('a', 'b'),
    ('a', 'c'),
    ('b', 'a'),
    ('b', 'd'),
    ('c', 'a'),
    ('d', 'a'),
    ('d', 'b'),
    ('d', 'c'),
]
```

现在让我们将这个图放入一个普通的字典中：

```py
>>> graph = dict()
>>> for from_, to in nodes:
...     if from_ not in graph:
...         graph[from_] = []
...     graph[from_].append(to)

>>> import pprint
>>> pprint.pprint(graph)
{'a': ['b', 'c'],
 **'b': ['a', 'd'],
 **'c': ['a'],
 **'d': ['a', 'b', 'c']}

```

当然，也有一些变化，例如使用`setdefault`。但它们比必要的复杂。

真正的 Python 版本使用`defaultdict`代替：

```py
>>> import collections

>>> graph = collections.defaultdict(list)
>>> for from_, to in nodes:
...     graph[from_].append(to)

>>> import pprint
>>> pprint.pprint(graph)
defaultdict(<class 'list'>,
 **{'a': ['b', 'c'],
 **'b': ['a', 'd'],
 **'c': ['a'],
 **'d': ['a', 'b', 'c']})

```

这是一段美妙的代码吗？`defaultdict`实际上可以被看作是`counter`对象的前身。它没有`counter`那么花哨，也没有所有`counter`的功能，但在许多情况下它可以胜任：

```py
>>> counter = collections.defaultdict(int)
>>> counter['spam'] += 5
>>> counter
defaultdict(<class 'int'>, {'spam': 5})

```

`defaultdict`的默认值需要是一个可调用对象。在前面的例子中，这些是`int`和`list`，但您可以轻松地定义自己的函数来用作默认值。下面的例子就是这样做的，尽管我不建议在生产中使用，因为它缺乏一些可读性。然而，我相信这是 Python 强大之处的一个美好例子。

这是我们如何在一行 Python 中创建一个`tree`：

```py
import collections
def tree(): return collections.defaultdict(tree)
```

太棒了，不是吗？这是我们实际上如何使用它的方式：

```py
>>> import json
>>> import collections

>>> def tree():
...     return collections.defaultdict(tree)

>>> colours = tree()
>>> colours['other']['black'] = 0x000000
>>> colours['other']['white'] = 0xFFFFFF
>>> colours['primary']['red'] = 0xFF0000
>>> colours['primary']['green'] = 0x00FF00
>>> colours['primary']['blue'] = 0x0000FF
>>> colours['secondary']['yellow'] = 0xFFFF00
>>> colours['secondary']['aqua'] = 0x00FFFF
>>> colours['secondary']['fuchsia'] = 0xFF00FF

>>> print(json.dumps(colours, sort_keys=True, indent=4))
{
 **"other": {
 **"black": 0,
 **"white": 16777215
 **},
 **"primary": {
 **"blue": 255,
 **"green": 65280,
 **"red": 16711680
 **},
 **"secondary": {
 **"aqua": 65535,
 **"fuchsia": 16711935,
 **"yellow": 16776960
 **}
}

```

这个好处是你可以让它变得更深。由于`defaultdict`的基础，它会递归生成自己。

## namedtuple - 带有字段名称的元组

`namedtuple`对象确实就像名字暗示的那样 - 一个带有名称的元组。它有一些有用的用例，尽管我必须承认我在实际中并没有找到太多用例，除了一些 Python 模块，比如 inspect 和`urllib.parse`。2D 或 3D 空间中的点是它明显有用的一个很好的例子：

```py
>>> import collections

>>> Point = collections.namedtuple('Point', ['x', 'y', 'z'])
>>> point_a = Point(1, 2, 3)
>>> point_a
Point(x=1, y=2, z=3)

>>> point_b = Point(x=4, z=5, y=6)
>>> point_b
Point(x=4, y=6, z=5)

```

关于`namedtuple`，并没有太多可以说的；它做你期望的事情，最大的优势是属性可以通过名称和索引执行，这使得元组解包非常容易：

```py
>>> x, y, z = point_a
>>> print('X: %d, Y: %d, Z: %d' % (x, y, z))
X: 1, Y: 2, Z: 3
>>> print('X: %d, Y: %d, Z: %d' % point_b)
X: 4, Y: 6, Z: 5
>>> print('X: %d' % point_a.x)

```

## enum - 一组常量

`enum`包与`namedtuple`非常相似，但目标和接口完全不同。基本的`enum`对象使得在模块中拥有常量变得非常容易，同时避免了魔术数字。这是一个基本的例子：

```py
>>> import enum

>>> class Color(enum.Enum):
...     red = 1
...     green = 2
...     blue = 3

>>> Color.red
<Color.red: 1>
>>> Color['red']
<Color.red: 1>
>>> Color(1)
<Color.red: 1>
>>> Color.red.name
'red'
>>> Color.red.value
1
>>> isinstance(Color.red, Color)
True
>>> Color.red is Color['red']
True
>>> Color.red is Color(1)
True

```

`enum`包的一些方便功能是，对象是可迭代的，可以通过值的数字和文本表示进行访问，并且，通过适当的继承，甚至可以与其他类进行比较。

以下代码展示了基本 API 的使用：

```py
>>> for color in Color:
...     color
<Color.red: 1>
<Color.green: 2>
<Color.blue: 3>

>>> colors = dict()
>>> colors[Color.green] = 0x00FF00
>>> colors
{<Color.green: 2>: 65280}

```

还有更多。`enum`包中较少为人知的可能性之一是，你可以通过特定类型的继承使值比较起作用，这对于任何类型都有效，不仅仅是整数，还包括（你自己的）自定义类型。

这是常规的`enum`：

```py
>>> import enum

>>> class Spam(enum.Enum):
...     EGGS = 'eggs'

>>> Spam.EGGS == 'eggs'
False

```

以下是带有`str`继承的`enum`：

```py
>>> import enum

>>> class Spam(str, enum.Enum):
...     EGGS = 'eggs'

>>> Spam.EGGS == 'eggs'
True

```

## OrderedDict - 插入顺序很重要的字典

`OrderdDict`是一个跟踪插入顺序的`dict`。而普通的`dict`会按照哈希的顺序返回键，`OrderedDict`会按照插入的顺序返回键。所以，它不是按键或值排序的，但这也很容易实现：

```py
>>> import collections

>>> spam = collections.OrderedDict()
>>> spam['b'] = 2
>>> spam['c'] = 3
>>> spam['a'] = 1
>>> spam
OrderedDict([('b', 2), ('c', 3), ('a', 1)])

>>> for key, value in spam.items():
...     key, value
('b', 2)
('c', 3)
('a', 1)

>>> eggs = collections.OrderedDict(sorted(spam.items()))
>>> eggs
OrderedDict([('a', 1), ('b', 2), ('c', 3)])

```

虽然你可能猜到了它是如何工作的，但内部可能会让你有点惊讶。我知道我原本期望的实现方式是不同的。

在内部，`OrderedDict`使用普通的`dict`来存储键/值，并且除此之外，它还使用一个双向链表来跟踪下一个/上一个项目。为了跟踪反向关系（从双向链表返回到键），还有一个额外的`dict`存储在内部。

简而言之，`OrderedDict`可以是一个非常方便的工具，用来保持你的`dict`排序，但它是有代价的。这个系统的结构使得`set`和`get`非常快速（O(1)），但是与普通的`dict`相比，这个对象仍然更加沉重（内存使用量增加一倍或更多）。当然，在许多情况下，内部对象的内存使用量将超过`dict`本身的内存使用量，但这是需要记住的一点。

## heapq - 有序列表

`heapq`模块是一个非常好的小模块，它可以非常容易地在 Python 中创建一个优先队列。这种结构总是可以在最小的（或最大的，取决于实现）项目上进行最小的努力。API 非常简单，它的使用最好的例子之一可以在`OrderedDict`对象中看到。你可能不想直接使用`heapq`，但了解内部工作原理对于分析诸如`OrderedDict`之类的类是很重要的。

### 提示

如果你正在寻找一个结构来保持你的列表始终排序，可以尝试使用`bisect`模块。

基本用法非常简单：

```py
>>> import heapq

>>> heap = [1, 3, 5, 7, 2, 4, 3]
>>> heapq.heapify(heap)
>>> heap
[1, 2, 3, 7, 3, 4, 5]

>>> while heap:
...     heapq.heappop(heap), heap
(1, [2, 3, 3, 7, 5, 4])
(2, [3, 3, 4, 7, 5])
(3, [3, 5, 4, 7])
(3, [4, 5, 7])
(4, [5, 7])
(5, [7])
(7, [])

```

这里有一件重要的事情需要注意 - 你可能已经从前面的例子中理解了 - `heapq`模块并不创建一个特殊的对象。它只是一堆方法，用于将常规列表视为`heap`。这并不使它变得不那么有用，但这是需要考虑的一点。你可能也会想为什么`heap`没有排序。实际上，它是排序的，但不是你期望的方式。如果你将`heap`视为一棵树，它就会变得更加明显：

```py
   1
 2   3
7 3 4 5
```

最小的数字总是在顶部，最大的数字总是在树的底部。因此，找到最小的数字非常容易，但找到最大的数字就不那么容易了。要获得堆的排序版本，我们只需要不断地删除树的顶部，直到所有项目都消失。

## bisect - 排序列表

我们在前一段中看到了`heapq`模块，它使得从列表中始终获取最小的数字变得非常简单，因此也很容易对对象列表进行排序。`heapq`模块将项目附加到形成类似树的结构，而`bisect`模块以使它们保持排序的方式插入项目。一个很大的区别是，使用`heapq`模块添加/删除项目非常轻便，而使用`bisect`模块查找项目非常轻便。如果您的主要目的是搜索，那么`bisect`应该是您的选择。

与`heapq`一样，`bisect`并不真正创建一个特殊的数据结构。它只是在一个标准的`list`上操作，并期望该`list`始终保持排序。重要的是要理解这一点的性能影响；仅仅使用`bisect`算法向列表添加项目可能会非常慢，因为在列表上插入需要`O(n)`的时间。实际上，使用 bisect 创建一个排序列表需要`O(n*n)`的时间，这相当慢，特别是因为使用`heapq`或 sorted 创建相同的排序列表只需要`O(n * log(n))`的时间。

### 注意

`log(n)`是指以 2 为底的对数函数。要计算这个值，可以使用`math.log2()`函数。这意味着每当数字的大小加倍时，值就会增加 1。对于`n=2`，`log(n)`的值为`1`，因此对于`n=4`和`n=8`，对数值分别为`2`和`3`。

这意味着 32 位数字，即`2**32 = 4294967296`，具有`32`的对数。

如果您有一个排序的结构，并且只需要添加一个单个项目，那么可以使用`bisect`算法进行插入。否则，通常更快的方法是简单地附加项目，然后调用`.sort()`。

为了说明，我们有这些行：

```py
>>> import bisect

Using the regular sort:
>>> sorted_list = []
>>> sorted_list.append(5)  # O(1)
>>> sorted_list.append(3)  # O(1)
>>> sorted_list.append(1)  # O(1)
>>> sorted_list.append(2)  # O(1)
>>> sorted_list.sort()  # O(n * log(n)) = O(4 * log(4)) = O(8)
>>> sorted_list
[1, 2, 3, 5]

Using bisect:
>>> sorted_list = []
>>> bisect.insort(sorted_list, 5)  # O(n) = O(1)
>>> bisect.insort(sorted_list, 3)  # O(n) = O(2)
>>> bisect.insort(sorted_list, 1)  # O(n) = O(3)
>>> bisect.insort(sorted_list, 2)  # O(n) = O(4)
>>> sorted_list
[1, 2, 3, 5]

```

对于少量项目，差异是可以忽略的，但它很快就会增长到一个差异很大的程度。对于`n=4`，差异只是`4 * 1 + 8 = 12`和`1 + 2 + 3 + 4 = 10`之间，使得 bisect 解决方案更快。但是，如果我们要插入 1,000 个项目，那么结果将是`1000 + 1000 * log(1000) = 10966`与`1 + 2 + … 1000 = 1000 * (1000 + 1) / 2 = 500500`。因此，在插入许多项目时要非常小心。

不过，在列表中进行搜索非常快；因为它是排序的，我们可以使用一个非常简单的二分搜索算法。例如，如果我们想要检查列表中是否存在一些数字呢？

```py
>>> import bisect

>>> sorted_list = [1, 2, 3, 5]
>>> def contains(sorted_list, value):
...     i = bisect.bisect_left(sorted_list, value)
...     return i < len(sorted_list) and sorted_list[i] == value

>>> contains(sorted_list, 2)
True
>>> contains(sorted_list, 4)
False
>>> contains(sorted_list, 6)
False

```

如您所见，`bisect_left`函数找到了数字应该在的位置。这实际上也是`insort`函数所做的；它通过搜索数字的位置来将数字插入到正确的位置。

那么这与`sorted_list`中的常规值有什么不同呢？最大的区别在于`bisect`在内部执行二分搜索，这意味着它从中间开始，根据值是大还是小而向左或向右跳转。为了说明，我们将在从`0`到`14`的数字列表中搜索`4`：

```py
sorted_list = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
Step 1: 4 > 7                       ^
Step 2: 4 > 3           ^
Step 3: 4 > 5                 ^
Step 4: 4 > 5              ^
```

如您所见，经过仅四步（实际上是三步；第四步只是为了说明），我们已经找到了我们搜索的数字。根据数字（例如`7`），可能会更快，但是找到一个数字永远不会超过`O(log(n))`步。

使用常规列表，搜索将简单地遍历所有项目，直到找到所需的项目。如果你幸运的话，它可能是你遇到的第一个数字，但如果你不幸的话，它可能是最后一个项目。对于 1,000 个项目来说，这将是 1000 步和`log(1000) = 10`步之间的差异。

# 总结

Python 内置了一些非常有用的集合。由于越来越多的集合定期添加，最好的做法就是简单地跟踪集合手册。你是否曾经想过任何结构是如何工作的，或者为什么会这样？只需在这里查看源代码：

[`hg.python.org/cpython/file/default/Lib/collections/__init__.py`](https://hg.python.org/cpython/file/default/Lib/collections/__init__.py)

完成本章后，你应该了解核心集合和集合模块中最重要的集合，更重要的是这些集合在几种情景下的性能特征。在应用程序中选择正确的数据结构是你的代码将经历的最重要的性能因素，这对于任何程序员来说都是必不可少的知识。

接下来，我们将继续讨论函数式编程，其中包括`lambda`函数、`list`推导、`dict`推导、`set`推导以及一系列相关主题。这包括一些涉及的数学背景信息，可能会很有趣，但可以安全地跳过。
