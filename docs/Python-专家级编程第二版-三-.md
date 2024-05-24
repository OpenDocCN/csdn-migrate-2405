# Python 专家级编程第二版（三）

> 原文：[`zh.annas-archive.org/md5/4CC2EF9A4469C814CC3EEBD966D2E707`](https://zh.annas-archive.org/md5/4CC2EF9A4469C814CC3EEBD966D2E707)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：编写包

本章重点介绍了编写和发布 Python 包的可重复过程。其意图是：

+   在开始真正工作之前缩短设置所需的时间

+   提供一种标准化的编写包的方式

+   简化测试驱动开发方法的使用

+   促进发布过程

它分为以下四个部分：

+   所有包的**常见模式**，描述了所有 Python 包之间的相似之处，以及`distutils`和`setuptools`如何发挥核心作用

+   什么是**命名空间包**以及它们为何有用

+   如何在**Python 包索引**（**PyPI**）中注册和上传包，重点放在安全性和常见陷阱上

+   独立可执行文件作为打包和分发 Python 应用程序的替代方式

# 创建一个包

Python 打包一开始可能有点令人不知所措。这主要是因为对于创建 Python 包的适当工具的混乱。不管怎样，一旦您创建了第一个包，您会发现这并不像看起来那么困难。此外，了解适当的、最新的打包工具也会有很大帮助。

即使您不打算将代码作为开源分发，您也应该知道如何创建包。了解如何制作自己的包将使您更深入地了解打包生态系统，并有助于您使用 PyPI 上可用的第三方代码。

此外，将您的闭源项目或其组件作为源分发包可用，可以帮助您在不同环境中部署代码。利用 Python 打包生态系统在代码部署中的优势将在下一章中更详细地描述。在这里，我们将专注于创建这样的分发的适当工具和技术。

## Python 打包工具的混乱状态

很长一段时间以来，Python 打包的状态非常混乱，花了很多年时间才将这个话题组织起来。一切都始于 1998 年引入的`distutils`包，后来在 2003 年由`setuptools`进行了增强。这两个项目开启了一个漫长而复杂的分叉、替代项目和完全重写的故事，试图一劳永逸地修复 Python 的打包生态系统。不幸的是，大多数尝试都没有成功。效果恰恰相反。每个旨在取代`setuptools`或`distutils`的新项目都增加了已经围绕打包工具的巨大混乱。一些这样的分叉被合并回它们的祖先（比如`distribute`是`setuptools`的一个分叉），但有些被遗弃了（比如`distutils2`）。

幸运的是，这种状态正在逐渐改变。一个名为**Python 打包管理机构**（**PyPA**）的组织成立，旨在恢复打包生态系统的秩序和组织。由 PyPA 维护的**Python 打包用户指南**（[`packaging.python.org`](https://packaging.python.org)）是关于最新打包工具和最佳实践的权威信息来源。把它视为关于打包的最佳信息来源，以及本章的补充阅读。该指南还包含了与打包相关的更改和新项目的详细历史，因此如果您已经了解一些内容但想确保仍在使用适当的工具，它将非常有用。

远离其他流行的互联网资源，比如**打包者指南**。它已经过时，没有维护，大部分已经过时。它可能只是出于历史原因有趣，而 Python 打包用户指南实际上是这个旧资源的一个分支。

### 由于 PyPA，Python 打包的当前格局

除了为打包提供权威指南外，PyPA 还维护打包项目和新官方打包方面的标准化过程。PyPA 的所有项目都可以在 GitHub 的一个组织下找到：[`github.com/pypa`](https://github.com/pypa)。

其中一些在书中已经提到。最显著的是：

+   `pip`

+   `virtualenv`

+   `twine`

+   `warehouse`

请注意，其中大多数是在该组织之外启动的，并且只有在成熟和广泛使用的解决方案下才移至 PyPA 赞助下。

由于 PyPA 的参与，逐渐放弃鸡蛋格式，转而使用 wheels 进行构建分发已经在进行中。未来可能会带来更多新的变化。PyPA 正在积极开发`warehouse`，旨在完全取代当前的 PyPI 实现。这将是包装历史上的一大步，因为`pypi`是一个如此古老和被忽视的项目，只有少数人能够想象在没有完全重写的情况下逐渐改进它。

### 工具推荐

Python Packaging User Guide 给出了一些建议，推荐使用一些工具来处理软件包。它们通常可以分为两组：用于安装软件包的工具和用于创建和分发软件包的工具。

PyPA 推荐的第一组工具已经在第一章中提到过，但为了保持一致，让我们在这里重复一下：

+   使用`pip`从 PyPI 安装软件包

+   使用`virtualenv`或`venv`来实现 Python 环境的应用级隔离

Python Packaging User Guide 给出了一些建议，推荐用于创建和分发软件包的工具如下：

+   使用`setuptools`来定义项目并创建**源分发**

+   使用**wheels**而不是**eggs**来创建**构建分发**

+   使用`twine`将软件包分发上传到 PyPI

## 项目配置

显而易见，组织大型应用程序代码的最简单方法是将其拆分为几个软件包。这使得代码更简单，更易于理解，维护和更改。它还最大化了每个软件包的可重用性。它们就像组件一样。

### setup.py

必须分发的软件包的根目录包含一个`setup.py`脚本。它定义了`distutils`模块中描述的所有元数据，作为对标准`setup()`函数的参数的组合。尽管`distutils`是一个标准库模块，但建议您使用`setuptools`包，它对标准`distutils`提供了几个增强功能。

因此，此文件的最小内容是：

```py
from setuptools import setup

setup(
    name='mypackage',
)
```

`name`给出了软件包的完整名称。从那里，脚本提供了几个命令，可以使用`--help-commands`选项列出：

```py
$ python3 setup.py --help-commands
Standard commands:
 **build             build everything needed to install
 **clean             clean up temporary files from 'build' command
 **install           install everything from build directory
 **sdist             create a source distribution (tarball, zip file)
 **register          register the distribution with the PyP
 **bdist             create a built (binary) distribution
 **check             perform some checks on the package
 **upload            upload binary package to PyPI

Extra commands:
 **develop           install package in 'development mode'
 **alias             define a shortcut to invoke one or more commands
 **test              run unit tests after in-place build
 **bdist_wheel       create a wheel distribution

usage: setup.py [global_opts] cmd1 [cmd1_opts] [cmd2 [cmd2_opts] ...]
 **or: setup.py --help [cmd1 cmd2 ...]
 **or: setup.py --help-commands
 **or: setup.py cmd --help

```

实际的命令列表更长，可以根据可用的`setuptools`扩展而变化。它被截断以仅显示对本章最重要和相关的命令。**标准** **命令**是`distutils`提供的内置命令，而**额外** **命令**是由第三方软件包创建的命令，例如`setuptools`或定义和注册新命令的任何其他软件包。另一个软件包注册的额外命令是由`wheel`软件包提供的`bdist_wheel`。

### setup.cfg

`setup.cfg`文件包含`setup.py`脚本命令的默认选项。如果构建和分发软件包的过程更复杂，并且需要传递许多可选参数给`setup.py`命令，这将非常有用。这允许您在每个项目的代码中存储这些默认参数。这将使您的分发流程独立于项目，并且还可以提供关于如何构建和分发软件包给用户和其他团队成员的透明度。

`setup.cfg`文件的语法与内置的`configparser`模块提供的语法相同，因此类似于流行的 Microsoft Windows INI 文件。以下是一个设置配置文件的示例，其中提供了一些`global`，`sdist`和`bdist_wheel`命令的默认值：

```py
[global]
quiet=1

[sdist]
formats=zip,tar

[bdist_wheel]
universal=1
```

此示例配置将确保始终使用两种格式（ZIP 和 TAR）创建源分发，并且将创建通用轮（与 Python 版本无关）的构建轮分发。此外，通过全局`quiet`开关，每个命令的大部分输出都将被抑制。请注意，这仅用于演示目的，可能不是默认情况下抑制每个命令的输出的合理选择。

### MANIFEST.in

使用`sdist`命令构建分发时，`distutils`浏览包目录，寻找要包含在存档中的文件。`distutils`将包括：

+   由`py_modules`，`packages`和`scripts`选项隐含的所有 Python 源文件

+   `ext_modules`选项中列出的所有 C 源文件

与 glob 模式`test/test*.py`匹配的文件是：`README`，`README.txt`，`setup.py`和`setup.cfg`。

此外，如果您的包处于子版本或 CVS 下，`sdist`将浏览文件夹，如`.svn`，以寻找要包含的文件。还可以通过扩展与其他版本控制系统集成。`sdist`构建一个列出所有文件并将它们包含到存档中的`MANIFEST`文件。

假设您不使用这些版本控制系统，并且需要包含更多文件。现在，您可以在与`setup.py`相同的目录中定义一个名为`MANIFEST.in`的模板，用于`MANIFEST`文件，其中您指示`sdist`包含哪些文件。

此模板每行定义一个包含或排除规则，例如：

```py
include HISTORY.txt
include README.txt
include CHANGES.txt
include CONTRIBUTORS.txt
include LICENSE
recursive-include *.txt *.py
```

`MANIFEST.in`的完整命令列表可以在官方`distutils`文档中找到。

### 最重要的元数据

除了要分发的软件包的名称和版本外，`setup`可以接收的最重要的参数是：

+   `description`: 这包括几句话来描述该包

+   `long_description`: 这包括一个可以使用 reStructuredText 的完整描述

+   `keywords`: 这是定义该包的关键字列表

+   `author`: 这是作者的姓名或组织

+   `author_email`: 这是联系电子邮件地址

+   `url`: 这是项目的 URL

+   `license`: 这是许可证（GPL，LGPL 等）

+   `packages`: 这是包中所有名称的列表；`setuptools`提供了一个称为`find_packages`的小函数来计算这个列表

+   `namespace_packages`: 这是命名空间包的列表

### Trove classifiers

PyPI 和`distutils`提供了一组分类应用程序的解决方案，称为**trove classifiers**。所有分类器形成一个类似树状的结构。每个分类器都是一种字符串形式，其中每个命名空间都由`::`子字符串分隔。它们的列表作为`classifiers`参数提供给`setup()`函数的包定义。以下是 PyPI 上某个项目（这里是`solrq`）的分类器示例列表：

```py
from setuptools import setup

setup(
    name="solrq",
    # (...)

    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Internet :: WWW/HTTP :: Indexing/Search',
    ],
)
```

它们在包定义中是完全可选的，但为`setup()`接口中可用的基本元数据提供了有用的扩展。除其他外，trove classifiers 可能提供有关支持的 Python 版本或系统、项目的开发阶段或代码发布的许可证的信息。许多 PyPI 用户通过分类搜索和浏览可用的软件包，因此适当的分类有助于软件包达到其目标。

Trove classifiers 在整个打包生态系统中起着重要作用，不应被忽视。没有组织验证软件包的分类，因此您有责任为您的软件包提供适当的分类器，并且不要给整个软件包索引引入混乱。

撰写本书时，PyPI 上有 608 个分类器，分为九个主要类别：

+   开发状态

+   环境

+   框架

+   预期受众

+   许可证

+   自然语言

+   操作系统

+   编程语言

+   主题

新的分类器会不时地被添加，因此在您阅读时这些数字可能会有所不同。当前可用的所有 trove 分类器的完整列表可通过`setup.py register --list-classifiers`命令获得。

### 常见模式

为了分发而创建一个包对于经验不足的开发人员来说可能是一项繁琐的任务。`setuptools`或`distuitls`在它们的`setup()`函数调用中接受的大部分元数据可以手动提供，忽略了这些可能在项目的其他部分中可用的事实：

```py
from setuptools import setup

setup(
    name="myproject",
    version="0.0.1",
    description="mypackage project short description",
    long_description="""
        Longer description of mypackage project
        possibly with some documentation and/or
        usage examples
    """,
    install_requires=[
        'dependency1',
        'dependency2',
        'etc',
    ]
)
```

虽然这肯定会起作用，但在长期内很难维护，并且留下了未来错误和不一致的可能性。`setuptools`和`distutils`都无法自动从项目源中提取各种元数据信息，因此您需要自己提供它们。在 Python 社区中有一些常见的模式用于解决最常见的问题，如依赖管理、版本/自述文件的包含等。至少了解其中一些是值得的，因为它们如此受欢迎，以至于它们可以被视为包装习语。

#### 从包中自动包含版本字符串

**PEP 440（版本标识和依赖规范）**文档规定了版本和依赖规范的标准。这是一个长篇文档，涵盖了接受的版本规范方案以及 Python 包装工具中版本匹配和比较应该如何工作。如果您正在使用或计划使用复杂的项目版本编号方案，那么阅读这个文档是义不容辞的。如果您使用的是由点分隔的一个、两个、三个或更多数字组成的简单方案，那么您可以放弃阅读 PEP 440。如果您不知道如何选择适当的版本方案，我强烈建议遵循语义化版本控制，这已经在第一章中提到过了。

另一个问题是在包或模块中包含版本说明符的位置。有 PEP 396（模块版本号），它正好处理这个问题。请注意，它只是信息性的，并且具有*延迟*状态，因此它不是标准跟踪的一部分。无论如何，它描述了现在似乎是*事实*标准。根据 PEP 396，如果包或模块有指定的版本，它应该被包含为包根（`__init__.py`）或模块文件的`__version__`属性。另一个*事实*标准是还包括包含版本部分的`VERSION`属性的元组。这有助于用户编写兼容性代码，因为如果版本方案足够简单，这样的版本元组可以很容易地进行比较。

PyPI 上有很多包都遵循这两个标准。它们的`__init__.py`文件包含如下所示的版本属性：

```py
# version as tuple for simple comparisons
VERSION = (0, 1, 1)
# string created from tuple to avoid inconsistency
__version__ = ".".join([str(x) for x in VERSION])
```

延迟 PEP 396 的另一个建议是，distutils 的`setup()`函数中提供的版本应该从`__version__`派生，或者反之亦然。Python 包装用户指南提供了单一源项目版本的多种模式，每种模式都有其自己的优点和局限性。我个人比较喜欢的是比较长的模式，它没有包含在 PyPA 的指南中，但它的优点是将复杂性限制在`setup.py`脚本中。这个样板假设版本说明符由包的`__init__`模块的`VERSION`属性提供，并提取这些数据以包含在`setup()`调用中。以下是一些虚构包的`setup.py`脚本的摘录，展示了这种方法：

```py
from setuptools import setup
import os

def get_version(version_tuple):
    # additional handling of a,b,rc tags, this can
    # be simpler depending on your versioning scheme
    if not isinstance(version_tuple[-1], int):
        return '.'.join(
            map(str, version_tuple[:-1])
        ) + version_tuple[-1]

    return '.'.join(map(str, version_tuple))

# path to the packages __init__ module in project
# source tree
init = os.path.join(
    os.path.dirname(__file__), 'src', 'some_package', '__init__.py'
)

version_line = list(
    filter(lambda l: l.startswith('VERSION'), open(init))
)[0]

# VERSION is a tuple so we need to eval its line of code.
# We could simply import it from the package but we
# cannot be sure that this package is importable before
# finishing its installation
VERSION = get_version(eval(version_line.split('=')[-1]))

setup(
    name='some-package',
    version=VERSION,
    # ...
)
```

#### 自述文件

Python Packaging Index 可以在 PyPI 门户网站的软件包页面上显示项目的 readme 或`long_description`的值。你可以使用 reStructuredText ([`docutils.sourceforge.net/rst.html`](http://docutils.sourceforge.net/rst.html))标记编写这个描述，因此在上传时它将被格式化为 HTML。不幸的是，目前只有 reStructuredText 作为 PyPI 上的文档标记可用。在不久的将来，这种情况不太可能改变。更有可能的是，当我们看到`warehouse`项目完全取代当前的 PyPI 实现时，将支持更多的标记语言。不幸的是，`warehouse`的最终发布日期仍然未知。

然而，许多开发人员出于各种原因希望使用不同的标记语言。最受欢迎的选择是 Markdown，这是 GitHub 上默认的标记语言——大多数开源 Python 开发目前都在这里进行。因此，通常，GitHub 和 Markdown 爱好者要么忽视这个问题，要么提供两个独立的文档文本。提供给 PyPI 的描述要么是项目 GitHub 页面上可用的简短版本，要么是在 PyPI 上呈现不佳的纯 Markdown 格式。

如果你想为你的项目的 README 使用不同于 reStructuredText 标记语言的东西，你仍然可以以可读的形式在 PyPI 页面上提供它作为项目描述。诀窍在于使用`pypandoc`软件包将你的其他标记语言转换为 reStructuredText，同时上传到 Python Package Index 时要有一个回退到你的 readme 文件的纯内容，这样如果用户没有安装`pypandoc`，安装就不会失败：

```py
try:
    from pypandoc import convert

    def read_md(f):
        return convert(f, 'rst')

except ImportError:
    convert = None
    print(
        "warning: pypandoc module not found, could not convert Markdown to RST"
    )

    def read_md(f):
        return open(f, 'r').read()  # noqa

README = os.path.join(os.path.dirname(__file__), 'README.md')

setup(
    name='some-package',
    long_description=read_md(README),
    # ...
)
```

#### 管理依赖

许多项目需要安装和/或使用一些外部软件包。当依赖列表非常长时，就会出现如何管理的问题。在大多数情况下，答案非常简单。不要过度设计问题。保持简单，并在你的`setup.py`脚本中明确提供依赖列表：

```py
from setuptools import setup
setup(
    name='some-package',
    install_requires=['falcon', 'requests', 'delorean']
    # ...
)
```

一些 Python 开发人员喜欢使用`requirements.txt`文件来跟踪他们软件包的依赖列表。在某些情况下，你可能会找到理由这样做，但在大多数情况下，这是该项目代码未正确打包的遗留物。无论如何，即使像 Celery 这样的知名项目仍然坚持这种约定。因此，如果你不愿意改变你的习惯，或者你在某种程度上被迫使用要求文件，那么至少要做到正确。以下是从`requirements.txt`文件中读取依赖列表的一种流行习语：

```py
from setuptools import setup
import os

def strip_comments(l):
    return l.split('#', 1)[0].strip()

def reqs(*f):
    return list(filter(None, [strip_comments(l) for l in open(
        os.path.join(os.getcwd(), *f)).readlines()]))

setup(
    name='some-package',
    install_requires=reqs('requirements.txt')
    # ...
)
```

## 自定义设置命令

`distutils`允许你创建新的命令。新的命令可以通过入口点进行注册，这是由`setuptools`引入的一种将软件包定义为插件的简单方法。

入口点是通过`setuptools`提供的一种通过一些 API 公开的类或函数的命名链接。任何应用程序都可以扫描所有已注册的软件包，并将链接的代码用作插件。

要链接新的命令，可以在设置调用中使用`entry_points`元数据：

```py
setup(
    name="my.command",
    entry_points="""
        [distutils.commands]
        my_command  = my.command.module.Class
    """
)
```

所有命名链接都被收集在命名部分中。当`distutils`被加载时，它会扫描在`distutils.commands`下注册的链接。

这种机制被许多提供可扩展性的 Python 应用程序使用。

## 在开发过程中使用软件包

使用`setuptools`主要是关于构建和分发软件包。然而，你仍然需要知道如何使用它们直接从项目源安装软件包。原因很简单。在提交软件包到 PyPI 之前，测试包装代码是否正常工作是很重要的。测试的最简单方法是安装它。如果你将一个有问题的软件包发送到存储库，那么为了重新上传它，你需要增加版本号。

在最终分发之前测试代码是否打包正确可以避免不必要的版本号膨胀，显然也可以节省时间。此外，在同时处理多个相关包时，直接从自己的源代码使用`setuptools`进行安装可能是必不可少的。

### setup.py install

`install`命令将包安装到 Python 环境中。如果之前没有进行构建，它将尝试构建包，然后将结果注入 Python 树中。当提供源分发时，可以将其解压缩到临时文件夹，然后使用此命令安装。`install`命令还将安装在`install_requires`元数据中定义的依赖项。这是通过查看 Python 包索引中的包来完成的。

在安装包时，除了使用裸`setup.py`脚本之外，还可以使用`pip`。由于它是 PyPA 推荐的工具，即使在本地环境中安装包用于开发目的时，也应该使用它。为了从本地源安装包，请运行以下命令：

```py
pip install <project-path>

```

### 卸载包

令人惊讶的是，`setuptools`和`distutils`缺乏`uninstall`命令。幸运的是，可以使用`pip`卸载任何 Python 包：

```py
pip uninstall <package-name>

```

在系统范围的包上尝试卸载可能是一种危险的操作。这是为什么对于任何开发都使用虚拟环境如此重要的另一个原因。

### setup.py develop 或 pip -e

使用`setup.py install`安装的包将被复制到当前环境的 site-packages 目录中。这意味着每当您对该包的源代码进行更改时，都需要重新安装它。这在密集开发过程中经常是一个问题，因为很容易忘记需要再次进行安装。这就是为什么`setuptools`提供了额外的`develop`命令，允许我们以**开发模式**安装包。此命令在部署目录（site-packages）中创建对项目源代码的特殊链接，而不是将整个包复制到那里。包源代码可以在不需要重新安装的情况下进行编辑，并且可以像正常安装一样在`sys.path`中使用。

`pip`还允许以这种模式安装包。这种安装选项称为*可编辑模式*，可以在`install`命令中使用`-e`参数启用：

```py
pip install -e <project-path>

```

# 命名空间包

*Python 之禅*，您可以通过在解释器会话中编写`import this`来阅读，关于命名空间说了以下内容：

> *命名空间是一个了不起的想法——让我们做更多这样的事情！*

这可以以至少两种方式理解。第一种是在语言环境中的命名空间。我们都在不知不觉中使用命名空间：

+   模块的全局命名空间

+   函数或方法调用的本地命名空间

+   内置名称的命名空间

另一种命名空间可以在打包级别提供。这些是**命名空间包**。这通常是一个被忽视的功能，可以在组织的包生态系统或非常庞大的项目中非常有用。

## 这有什么用呢？

命名空间包可以被理解为一种在元包级别以上对相关包或模块进行分组的方式，其中每个包都可以独立安装。

如果您的应用程序组件是独立开发、打包和版本化的，但您仍希望从相同的命名空间访问它们，命名空间包尤其有用。这有助于明确每个包属于哪个组织或项目。例如，对于一些虚构的 Acme 公司，通用命名空间可以是`acme`。结果可能会导致创建一个通用的`acme`命名空间包，用于容纳该组织的其他包。例如，如果 Acme 的某人想要贡献一个与 SQL 相关的库，他可以创建一个新的`acme.sql`包，并将其注册到`acme`中。

重要的是要了解普通包和命名空间包之间的区别以及它们解决的问题。通常（没有命名空间包），您将创建一个带有以下文件结构的`acme`包和`sql`子包/子模块：

```py
$ tree acme/
acme/
├── acme
│   ├── __init__.py
│   └── sql
│       └── __init__.py
└── setup.py

2 directories, 3 files

```

每当您想要添加一个新的子包，比如`templating`，您都被迫将其包含在`acme`的源树中：

```py
$ tree acme/
acme/
├── acme
│   ├── __init__.py
│   ├── sql
│   │   └── __init__.py
│   └── templating
│       └── __init__.py
└── setup.py

3 directories, 4 files

```

这种方法使得独立开发`acme.sql`和`acme.templating`几乎不可能。`setup.py`脚本还必须为每个子包指定所有的依赖关系，因此不可能（或者至少非常困难）只安装一些`acme`组件。而且，如果一些子包有冲突的要求，这是一个无法解决的问题。

使用命名空间包，您可以独立存储每个子包的源树：

```py
$ tree acme.sql/
acme.sql/
├── acme
│   └── sql
│       └── __init__.py
└── setup.py

2 directories, 2 files

$ tree acme.templating/
acme.templating/
├── acme
│   └── templating
│       └── __init__.py
└── setup.py

2 directories, 2 files

```

您还可以在 PyPI 或您使用的任何包索引中独立注册它们。用户可以选择从`acme`命名空间安装哪些子包，但他们永远不会安装通用的`acme`包（它不存在）：

```py
$ pip install acme.sql acme.templating

```

请注意，独立的源树不足以在 Python 中创建命名空间包。如果您不希望您的包互相覆盖，您需要做一些额外的工作。此外，根据您的 Python 语言版本目标，正确的处理可能会有所不同。这方面的细节在接下来的两节中描述。

## PEP 420 - 隐式命名空间包

如果您只使用和针对 Python 3，那么对您来说有个好消息。**PEP 420（隐式命名空间包）**引入了一种新的定义命名空间包的方法。它是标准跟踪的一部分，并且自 3.3 版本以来成为语言的官方部分。简而言之，如果一个目录包含 Python 包或模块（包括命名空间包），并且不包含`__init__.py`文件，则被视为命名空间包。因此，以下是在上一节中介绍的文件结构示例：

```py
$ tree acme.sql/
acme.sql/
├── acme
│   └── sql
│       └── __init__.py
└── setup.py

2 directories, 2 files

$ tree acme.templating/
acme.templating/
├── acme
│   └── templating
│       └── __init__.py
└── setup.py

2 directories, 2 files

```

它们足以定义`acme`是 Python 3.3 及更高版本中的命名空间包。使用设置工具的最小`setup.py`脚本将如下所示：

```py
from setuptools import setup

setup(
 **name='acme.templating',
 **packages=['acme.templating'],
)

```

不幸的是，在撰写本书时，`setuptools.find_packages()`不支持 PEP 420。无论如何，这在将来可能会改变。此外，明确定义包列表的要求似乎是易于集成命名空间包的一个非常小的代价。

## 在以前的 Python 版本中的命名空间包

PEP 420 布局中的命名空间包在 Python 3.3 之前的版本中无法工作。然而，这个概念非常古老，在像 Zope 这样的成熟项目中经常被使用，因此肯定可以使用它们，但不能进行隐式定义。在 Python 的旧版本中，有几种方法可以定义包应该被视为命名空间。

最简单的方法是为每个组件创建一个文件结构，类似于普通包布局而不是命名空间包，并将一切交给`setuptools`。因此，`acme.sql`和`acme.templating`的示例布局可能如下所示：

```py
$ tree acme.sql/
acme.sql/
├── acme
│   ├── __init__.py
│   └── sql
│       └── __init__.py
└── setup.py

2 directories, 3 files

$ tree acme.templating/
acme.templating/
├── acme
│   ├── __init__.py
│   └── templating
│       └── __init__.py
└── setup.py

2 directories, 3 files

```

请注意，对于`acme.sql`和`acme.templating`，还有一个额外的源文件`acme/__init__.py`。这个文件必须保持空白。如果我们将这个名称作为`setuptools.setup()`函数的`namespace_packages`关键字参数的值提供，`acme`命名空间包将被创建：

```py
from setuptools import setup

setup(
    name='acme.templating',
    packages=['acme.templating'],
    namespace_packages=['acme'],
)
```

最简单并不意味着最好。为了注册一个新的命名空间，`setuptools`将在您的`__init__.py`文件中调用`pkg_resources.declare_namespace()`函数。即使`__init__.py`文件是空的，也会发生这种情况。无论如何，正如官方文档所说，声明命名空间在`__init__.py`文件中是您自己的责任，`setuptools`的这种隐式行为可能会在将来被取消。为了安全和"未来证明"，您需要在文件`acme/__init__.py`中添加以下行：

```py
__import__('pkg_resources').declare_namespace(__name__)
```

# 上传软件包

没有组织的方式存储、上传和下载软件包将是无用的。Python 软件包索引是 Python 社区中开源软件包的主要来源。任何人都可以自由上传新软件包，唯一的要求是在 PyPI 网站上注册-[`pypi.python.org/pypi`](https://pypi.python.org/pypi)。

当然，您不仅限于这个索引，所有打包工具都支持使用替代软件包存储库。这对于在内部组织中分发闭源代码或用于部署目的尤其有用。如何使用这样的打包工具以及如何创建自己的软件包索引的说明将在下一章中解释。在这里，我们只关注向 PyPI 上传开源软件，只简要提及如何指定替代存储库。

## PyPI- Python 软件包索引

Python 软件包索引，如前所述，是开源软件包分发的官方来源。从中下载不需要任何帐户或权限。您唯一需要的是一个可以从 PyPI 下载新分发包的软件包管理器。您应该首选`pip`。

### 上传到 PyPI-或其他软件包索引

任何人都可以注册并上传软件包到 PyPI，只要他或她已经注册了帐户。软件包与用户绑定，因此，默认情况下，只有注册软件包名称的用户是其管理员，并且可以上传新的分发包。这可能对于更大的项目来说是一个问题，因此有一个选项可以将其他用户设计为软件包维护者，以便他们能够上传新的分发包。

上传软件包的最简单方法是使用`setup.py`脚本的`upload`命令：

```py
$ python setup.py <dist-commands> upload

```

在这里，`<dist-commands>`是一个创建要上传的分发包的命令列表。只有在同一次`setup.py`执行期间创建的分发包才会上传到存储库。因此，如果您要同时上传源分发包、构建分发包和 wheel 软件包，那么您需要发出以下命令：

```py
$ python setup.py sdist bdist bdist_wheel upload

```

在使用`setup.py`上传时，您不能重复使用已构建的分发包，并且被迫在每次上传时重新构建它们。这可能有些合理，但对于大型或复杂的项目来说可能不方便，因为创建分发包可能需要相当长的时间。`setup.py upload`的另一个问题是，它可能在某些 Python 版本上使用明文 HTTP 或未经验证的 HTTPS 连接。这就是为什么建议使用`twine`作为`setup.py upload`的安全替代品。

Twine 是与 PyPI 交互的实用程序，目前只提供一个功能-安全地上传软件包到存储库。它支持任何打包格式，并始终确保连接是安全的。它还允许您上传已经创建的文件，因此您可以在发布之前测试分发包。`twine`的一个示例用法仍然需要调用`setup.py`来构建分发包：

```py
$ python setup.py sdist bdist_wheel
$ twine upload dist/*

```

如果您尚未注册此软件包，则上传将失败，因为您需要先注册它。这也可以使用`twine`来完成：

```py
$ twine register dist/*

```

### .pypirc

`.pypirc`是一个存储有关 Python 软件包存储库信息的配置文件。它应该位于您的主目录中。该文件的格式如下：

```py
[distutils]
index-servers =
    pypi
    other

[pypi]
repository: <repository-url>
username: <username>
password: <password>

[other]
repository: https://example.com/pypi
username: <username>
password: <password>
```

`distutils`部分应该有`index-servers`变量，列出所有描述所有可用存储库和其凭据的部分。对于每个存储库部分，只有三个变量可以修改：

+   `存储库`：这是软件包存储库的 URL（默认为[`www.python.org/pypi`](https://www.python.org/pypi)）

+   `用户名`：这是在给定存储库中进行授权的用户名

+   `密码`：这是用于授权的用户密码，以明文形式

请注意，以明文形式存储存储库密码可能不是明智的安全选择。您可以始终将其留空，并在必要时提示输入密码。

`.pypirc`文件应该受到为 Python 构建的每个打包工具的尊重。虽然这对于每个与打包相关的实用程序来说可能并不正确，但它得到了最重要的工具的支持，如`pip`、`twine`、`distutils`和`setuptools`。

## 源包与构建包

Python 软件包通常有两种类型的分发：

+   源分发

+   构建（二进制）分发

源分发是最简单和最独立于平台的。对于纯 Python 软件包，这是毫无疑问的。这种分发只包含 Python 源代码，这些源代码应该已经非常易于移植。

更复杂的情况是，当您的软件包引入一些扩展时，例如用 C 编写的扩展。只要软件包用户在其环境中具有适当的开发工具链，源分发仍将起作用。这主要包括编译器和适当的 C 头文件。对于这种情况，构建的分发格式可能更适合，因为它可能已经为特定平台提供了构建好的扩展。

### sdist

`sdist`命令是最简单的可用命令。它创建一个发布树，其中复制了运行软件包所需的一切。然后将此树存档在一个或多个存档文件中（通常只创建一个 tarball）。存档基本上是源树的副本。

这个命令是从目标系统独立地分发软件包的最简单方法。它创建一个包含存档的`dist`文件夹，可以进行分发。为了使用它，必须向`setup`传递一个额外的参数来提供版本号。如果不给它一个`version`值，它将使用`version = 0.0.0`：

```py
from setuptools import setup

setup(name='acme.sql', version='0.1.1')
```

这个数字对于升级安装是有用的。每次发布软件包时，都会提高这个数字，以便目标系统知道它已经更改。

让我们使用这个额外的参数运行`sdist`命令：

```py
$ python setup.py sdist
running sdist
...
creating dist
tar -cf dist/acme.sql-0.1.1.tar acme.sql-0.1.1
gzip -f9 dist/acme.sql-0.1.1.tar
removing 'acme.sql-0.1.1' (and everything under it)
$ ls dist/
acme.sql-0.1.1.tar.gz

```

### 注意

在 Windows 下，归档将是一个 ZIP 文件。

版本用于标记存档的名称，可以在任何安装了 Python 的系统上分发和安装。在`sdist`分发中，如果软件包包含 C 库或扩展，目标系统负责编译它们。这在基于 Linux 的系统或 Mac OS 中非常常见，因为它们通常提供编译器，但在 Windows 下很少见。这就是为什么当软件包打算在多个平台上运行时，应该始终使用预构建的分发进行分发。

### bdist 和 wheels

为了能够分发预构建的分发，`distutils`提供了`build`命令，它在四个步骤中编译软件包：

+   `build_py`：这将通过对其进行字节编译并将其复制到构建文件夹中来构建纯 Python 模块。

+   `build_clib`：当软件包包含任何 C 库时，使用 C 编译器构建 C 库并在构建文件夹中创建一个静态库。

+   `build_ext`：这将构建 C 扩展并将结果放在构建文件夹中，如`build_clib`。

+   `build_scripts`：这将构建标记为脚本的模块。当第一行被设置为（`!#`）时，它还会更改解释器路径，并修复文件模式，使其可执行。

这些步骤中的每一步都是可以独立调用的命令。编译过程的结果是一个包含了安装软件包所需的一切的构建文件夹。`distutils`包中还没有交叉编译器选项。这意味着命令的结果始终特定于它所构建的系统。

当需要创建一些 C 扩展时，构建过程使用系统编译器和 Python 头文件（`Python.h`）。这个**include**文件是从 Python 构建源代码时就可用的。对于打包的发行版，可能需要额外的系统发行版包。至少在流行的 Linux 发行版中，通常被命名为`python-dev`。它包含了构建 Python 扩展所需的所有必要的头文件。

使用的 C 编译器是系统编译器。对于基于 Linux 的系统或 Mac OS X，分别是**gcc**或**clang**。对于 Windows，可以使用 Microsoft Visual C++（有免费的命令行版本可用），也可以使用开源项目 MinGW。这可以在`distutils`中配置。

`build`命令由`bdist`命令用于构建二进制分发。它调用`build`和所有依赖的命令，然后以与`sdist`相同的方式创建存档。

让我们在 Mac OS X 下为`acme.sql`创建一个二进制发行版：

```py
$ python setup.py bdist
running bdist
running bdist_dumb
running build
...
running install_scripts
tar -cf dist/acme.sql-0.1.1.macosx-10.3-fat.tar .
gzip -f9 acme.sql-0.1.1.macosx-10.3-fat.tar
removing 'build/bdist.macosx-10.3-fat/dumb' (and everything under it)
$ ls dist/
acme.sql-0.1.1.macosx-10.3-fat.tar.gz    acme.sql-0.1.1.tar.gz

```

请注意，新创建的存档名称包含了系统名称和它构建的发行版名称（*Mac OS X 10.3*）。

在 Windows 下调用相同的命令将创建一个特定的分发存档：

```py
C:\acme.sql> python.exe setup.py bdist
...
C:\acme.sql> dir dist
25/02/2008  08:18    <DIR>          .
25/02/2008  08:18    <DIR>          ..
25/02/2008  08:24            16 055 acme.sql-0.1.win32.zip
 **1 File(s)         16 055 bytes
 **2 Dir(s)  22 239 752 192 bytes free

```

如果软件包包含 C 代码，除了源分发外，释放尽可能多的不同二进制分发是很重要的。至少，对于那些没有安装 C 编译器的人来说，Windows 二进制分发是很重要的。

二进制发行版包含一个可以直接复制到 Python 树中的树。它主要包含一个文件夹，该文件夹被复制到 Python 的`site-packages`文件夹中。它还可能包含缓存的字节码文件（在 Python 2 上为`*.pyc`文件，在 Python 3 上为`__pycache__/*.pyc`）。

另一种构建分发是由`wheel`包提供的“wheels”。当安装（例如，使用`pip`）时，`wheel`会向`distutils`添加一个新的`bdist_wheel`命令。它允许创建特定于平台的分发（目前仅适用于 Windows 和 Mac OS X），为普通的`bdist`分发提供了替代方案。它旨在取代`setuptools`早期引入的另一种分发——eggs。Eggs 现在已经过时，因此不会在这里介绍。使用 wheels 的优势列表非常长。以下是 Python Wheels 页面（[`pythonwheels.com/`](http://pythonwheels.com/)）中提到的优势：

+   纯 Python 和本地 C 扩展包的更快安装

+   避免安装时的任意代码执行。（避免`setup.py`）

+   在 Windows 或 OS X 上安装 C 扩展不需要编译器

+   允许更好的缓存用于测试和持续集成

+   创建`.pyc`文件作为安装的一部分，以确保它们与使用的 Python 解释器匹配

+   跨平台和机器上的安装更一致

根据 PyPA 的建议，wheels 应该是您的默认分发格式。不幸的是，Linux 的特定平台 wheels 目前还不可用，因此如果您必须分发带有 C 扩展的软件包，那么您需要为 Linux 用户创建`sdist`分发。

# 独立可执行文件

创建独立的可执行文件是 Python 代码打包材料中常常被忽视的一个话题。这主要是因为 Python 在其标准库中缺乏适当的工具，允许程序员创建简单的可执行文件，用户可以在不需要安装 Python 解释器的情况下运行。

编译语言在一个重要方面比 Python 具有优势，那就是它们允许为给定的系统架构创建可执行应用程序，用户可以以一种不需要了解底层技术的方式运行。Python 代码在作为包分发时需要 Python 解释器才能运行。这给没有足够技术能力的用户带来了很大的不便。

开发人员友好的操作系统，比如 Mac OS X 或大多数 Linux 发行版，都预装了 Python。因此，对于他们的用户，基于 Python 的应用程序仍然可以作为依赖于主脚本文件中特定**解释器指令**的源代码包进行分发，这通常被称为**shebang**。对于大多数 Python 应用程序，这采用以下形式：

```py
#!/usr/bin/env python
```

这样的指令，当作为脚本的第一行使用时，将默认标记为由给定环境的 Python 版本解释。当然，这可以更详细地表达，需要特定的 Python 版本，比如`python3.4`、`python3`或`python2`。请注意，这将在大多数流行的 POSIX 系统中工作，但根据定义，这在任何情况下都不具备可移植性。这个解决方案依赖于特定的 Python 版本的存在，以及`env`可执行文件确切地位于`/usr/bin/env`。这些假设都可能在某些操作系统上失败。另外，shebang 在 Windows 上根本不起作用。此外，即使对于经验丰富的开发人员，在 Windows 上启动 Python 环境也可能是一个挑战，因此你不能指望非技术用户能够自己做到这一点。

另一件要考虑的事情是在桌面环境中的简单用户体验。用户通常希望可以通过简单点击桌面上的应用程序来运行它们。并非每个桌面环境都支持将 Python 应用程序作为源代码分发后以这种方式运行。

因此，最好能够创建一个二进制分发，它可以像任何其他编译的可执行文件一样工作。幸运的是，可以创建一个既包含 Python 解释器又包含我们项目的可执行文件。这允许用户打开我们的应用程序，而不必关心 Python 或任何其他依赖项。

## 独立的可执行文件何时有用？

独立的可执行文件在用户体验的简单性比用户能够干预应用程序代码更重要的情况下是有用的。请注意，仅仅将应用程序作为可执行文件分发只会使代码阅读或修改变得更加困难，而不是不可能。这不是保护应用程序代码的方法，应该只用作使与应用程序交互的方式更简单的方法。

独立的可执行文件应该是为非技术终端用户分发应用程序的首选方式，似乎也是为 Windows 分发 Python 应用程序的唯一合理方式。

独立的可执行文件通常是一个不错的选择：

+   依赖于目标操作系统上可能不容易获得的特定 Python 版本的应用程序

+   依赖于修改后的预编译的 CPython 源代码的应用程序

+   具有图形界面的应用程序

+   具有许多用不同语言编写的二进制扩展的项目

+   游戏

## 流行的工具

Python 没有任何内置支持来构建独立的可执行文件。幸运的是，有一些社区项目在解决这个问题，取得了不同程度的成功。最值得注意的四个是：

+   PyInstaller

+   cx_Freeze

+   py2exe

+   py2app

它们每一个在使用上都略有不同，而且每一个都有略微不同的限制。在选择工具之前，您需要决定要针对哪个平台，因为每个打包工具只能支持特定的操作系统集。

最好的情况是在项目的早期阶段就做出这样的决定。当然，这些工具都不需要在您的代码中进行深入的交互，但是如果您早期开始构建独立的软件包，您可以自动化整个过程，并节省未来的集成时间和成本。如果您把这个留到以后，您可能会发现项目构建得非常复杂，以至于没有任何可用的工具可以使用。为这样的项目提供一个独立的可执行文件将是困难的，并且会花费大量的时间。

### PyInstaller

PyInstaller（[`www.pyinstaller.org/`](http://www.pyinstaller.org/)）是目前将 Python 软件包冻结为独立可执行文件的最先进的程序。它在目前所有可用的解决方案中提供了最广泛的多平台兼容性，因此是最推荐的。PyInstaller 支持的平台有：

+   Windows（32 位和 64 位）

+   Linux（32 位和 64 位）

+   Mac OS X（32 位和 64 位）

+   FreeBSD、Solaris 和 AIX

支持的 Python 版本是 Python 2.7 和 Python 3.3、3.4 和 3.5。它可以在 PyPI 上找到，因此可以使用`pip`在您的工作环境中安装它。如果您在安装时遇到问题，您可以随时从项目页面下载安装程序。

不幸的是，不支持跨平台构建（交叉编译），因此如果您想为特定平台构建独立的可执行文件，那么您需要在该平台上执行构建。随着许多虚拟化工具的出现，这在今天并不是一个大问题。如果您的计算机上没有安装特定的系统，您可以随时使用 Vagrant，它将为您提供所需的操作系统作为虚拟机。

简单应用程序的使用很容易。假设我们的应用程序包含在名为`myscript.py`的脚本中。这是一个简单的“Hello world！”应用程序。我们想为 Windows 用户创建一个独立的可执行文件，并且我们的源代码位于文件系统中的`D://dev/app`下。我们的应用程序可以使用以下简短的命令进行打包：

```py
$ pyinstaller myscript.py

2121 INFO: PyInstaller: 3.1
2121 INFO: Python: 2.7.10
2121 INFO: Platform: Windows-7-6.1.7601-SP1
2121 INFO: wrote D:\dev\app\myscript.spec
2137 INFO: UPX is not available.
2138 INFO: Extending PYTHONPATH with paths
['D:\\dev\\app', 'D:\\dev\\app']
2138 INFO: checking Analysis
2138 INFO: Building Analysis because out00-Analysis.toc is non existent
2138 INFO: Initializing module dependency graph...
2154 INFO: Initializing module graph hooks...
2325 INFO: running Analysis out00-Analysis.toc
(...)
25884 INFO: Updating resource type 24 name 2 language 1033

```

PyInstaller 的标准输出即使对于简单的应用程序也非常长，因此为了简洁起见，在前面的示例中进行了截断。如果在 Windows 上运行，目录和文件的结果结构将如下所示：

```py
$ tree /0066
│   myscript.py
│   myscript.spec
│
├───build
│   └───myscript
│           myscript.exe
│           myscript.exe.manifest
│           out00-Analysis.toc
│           out00-COLLECT.toc
│           out00-EXE.toc
│           out00-PKG.pkg
│           out00-PKG.toc
│           out00-PYZ.pyz
│           out00-PYZ.toc
│           warnmyscript.txt
│
└───dist
 **└───myscript
 **bz2.pyd
 **Microsoft.VC90.CRT.manifest
 **msvcm90.dll
 **msvcp90.dll
 **msvcr90.dll
 **myscript.exe
 **myscript.exe.manifest
 **python27.dll
 **select.pyd
 **unicodedata.pyd
 **_hashlib.pyd

```

`dist/myscript`目录包含了可以分发给用户的构建应用程序。请注意，整个目录必须被分发。它包含了运行我们的应用程序所需的所有附加文件（DLL、编译的扩展库等）。可以使用`pyinstaller`命令的`--onefile`开关获得更紧凑的分发：

```py
$ pyinstaller --onefile myscript.py
(...)
$ tree /f
├───build
│   └───myscript
│           myscript.exe.manifest
│           out00-Analysis.toc
│           out00-EXE.toc
│           out00-PKG.pkg
│           out00-PKG.toc
│           out00-PYZ.pyz
│           out00-PYZ.toc
│           warnmyscript.txt
│
└───dist
 **myscript.exe

```

使用`--onefile`选项构建时，您需要分发给其他用户的唯一文件是`dist`目录中找到的单个可执行文件（这里是`myscript.exe`）。对于小型应用程序，这可能是首选选项。

运行`pyinstaller`命令的一个副作用是创建`*.spec`文件。这是一个自动生成的 Python 模块，包含了如何从您的源代码创建可执行文件的规范。例如，我们已经在以下代码中使用了这个：

```py
# -*- mode: python -*-

block_cipher = None

a = Analysis(['myscript.py'],
             pathex=['D:\\dev\\app'],
             binaries=None,
             datas=None,
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='myscript',
          debug=False,
          strip=False,
          upx=True,
          console=True )
```

这个`.spec`文件包含了之前指定的所有`pyinstaller`参数。如果您对构建进行了大量的自定义，这将非常有用，因为这可以代替必须存储您的配置的构建脚本。创建后，您可以将其用作`pyinstaller`命令的参数，而不是您的 Python 脚本：

```py
$ pyinstaller.exe myscript.spec

```

请注意，这是一个真正的 Python 模块，因此您可以使用自己已经了解的语言对其进行扩展并对构建过程进行更复杂的自定义。当您针对许多不同的平台时，自定义`.spec`文件尤其有用。此外，并非所有的`pyinstaller`选项都可以通过命令行参数使用，只有在修改`.spec`文件时才能使用。

PyInstaller 是一个功能强大的工具，使用起来对于大多数程序来说非常简单。无论如何，如果您有兴趣将其作为分发应用程序的工具，建议仔细阅读其文档。

### cx_Freeze

cx_Freeze ([`cx-freeze.sourceforge.net/`](http://cx-freeze.sourceforge.net/))是另一个用于创建独立可执行文件的工具。它比 PyInstaller 更简单，但也支持三个主要平台：

+   Windows

+   Linux

+   Mac OS X

与 PyInstaller 一样，它不允许我们执行跨平台构建，因此您需要在分发到的相同操作系统上创建您的可执行文件。cx_Freeze 的主要缺点是它不允许我们创建真正的单文件可执行文件。使用它构建的应用程序需要与相关的 DLL 文件和库一起分发。假设我们有与*PyInstaller*部分中的相同应用程序，那么示例用法也非常简单：

```py
$ cxfreeze myscript.py

copying C:\Python27\lib\site-packages\cx_Freeze\bases\Console.exe -> D:\dev\app\dist\myscript.exe
copying C:\Windows\system32\python27.dll -> D:\dev\app\dist\python27.dll
writing zip file D:\dev\app\dist\myscript.exe
(...)
copying C:\Python27\DLLs\bz2.pyd -> D:\dev\app\dist\bz2.pyd
copying C:\Python27\DLLs\unicodedata.pyd -> D:\dev\app\dist\unicodedata.pyd

```

生成的文件结构如下：

```py
$ tree /f
│   myscript.py
│
└───dist
 **bz2.pyd
 **myscript.exe
 **python27.dll
 **unicodedata.pyd

```

cx_Freeze 不是提供自己的构建规范格式（就像 PyInstaller 一样），而是扩展了`distutils`包。这意味着您可以使用熟悉的`setup.py`脚本配置独立可执行文件的构建方式。如果您已经使用`setuptools`或`distutils`来分发软件包，那么 cx_Freeze 非常方便，因为额外的集成只需要对`setup.py`脚本进行小的更改。以下是一个使用`cx_Freeze.setup()`创建 Windows 独立可执行文件的`setup.py`脚本示例：

```py
import sys
from cx_Freeze import setup, Executable

# Dependencies are automatically detected, but it might need fine tuning.
build_exe_options = {"packages": ["os"], "excludes": ["tkinter"]}

setup(
    name="myscript",
    version="0.0.1",
    description="My Hello World application!",
    options={
        "build_exe": build_exe_options
    },
    executables=[Executable("myscript.py")]
)
```

有了这样一个文件，可以使用添加到`setup.py`脚本的新`build_exe`命令来创建新的可执行文件：

```py
$ python setup.py build_exe

```

cx_Freeze 的使用似乎比 PyInstaller 和`distutils`集成更容易一些，这是一个非常有用的功能。不幸的是，这个项目可能会给经验不足的开发人员带来一些麻烦：

+   在 Windows 下使用`pip`进行安装可能会有问题

+   官方文档非常简短，某些地方缺乏说明

### py2exe 和 py2app

py2exe ([`www.py2exe.org/`](http://www.py2exe.org/))和 py2app ([`pythonhosted.org/py2app/`](https://pythonhosted.org/py2app/))是另外两个集成到 Python 打包中的程序，可以通过`distutils`或`setuptools`创建独立可执行文件。它们被一起提到，因为它们在使用和限制方面非常相似。py2exe 和 py2app 的主要缺点是它们只针对单个平台：

+   py2exe 允许构建 Windows 可执行文件

+   py2app 允许构建 Mac OS X 应用程序

由于使用方法非常相似，只需要修改`setup.py`脚本，这些软件包似乎互补。py2app 项目的官方文档提供了以下`setup.py`脚本示例，可以根据所使用的平台使用正确的工具（py2exe 或 py2app）构建独立可执行文件：

```py
import sys
from setuptools import setup

mainscript = 'MyApplication.py'

if sys.platform == 'darwin':
    extra_options = dict(
        setup_requires=['py2app'],
        app=[mainscript],
        # Cross-platform applications generally expect sys.argv to
        # be used for opening files.
        options=dict(py2app=dict(argv_emulation=True)),
    )
elif sys.platform == 'win32':
    extra_options = dict(
        setup_requires=['py2exe'],
        app=[mainscript],
    )
else:
    extra_options = dict(
        # Normally unix-like platforms will use "setup.py install"
        # and install the main script as such
        scripts=[mainscript],
    )

setup(
    name="MyApplication",
    **extra_options
)
```

使用这样的脚本，您可以使用`python setup.py py2exe`命令构建 Windows 可执行文件，并使用`python setup.py py2app`构建 Mac OS X 应用程序。当然，跨编译是不可能的。

尽管 cx_Freeze 的一些限制和弹性不如 PyInstaller 或 cx_Freeze，但了解总是有 py2exe 和 py2app 项目。在某些情况下，PyInstaller 或 cx_Freeze 可能无法正确地构建项目的可执行文件。在这种情况下，值得检查其他解决方案是否能够处理我们的代码。

## 可执行软件包中 Python 代码的安全性

重要的是要知道，独立可执行文件并不以任何方式使应用程序代码安全。从这种可执行文件中反编译嵌入的代码并不是一件容易的任务，但肯定是可行的。更重要的是，这种反编译的结果（如果使用适当的工具进行）可能看起来与原始源代码非常相似。

这个事实使得独立的 Python 可执行文件对于泄漏应用程序代码可能会损害组织的闭源项目来说并不是一个可行的解决方案。因此，如果你的整个业务可以通过简单地复制应用程序的源代码来复制，那么你应该考虑其他分发应用程序的方式。也许提供软件作为服务对你来说会是更好的选择。

### 使反编译变得更加困难

正如已经说过的，目前没有可靠的方法可以防止应用程序被反编译。但是，有一些方法可以使这个过程变得更加困难。但更困难并不意味着不太可能。对于我们中的一些人来说，最具诱惑力的挑战是最困难的挑战。我们都知道，这个挑战的最终奖励是非常高的：您试图保护的代码。

通常，反编译的过程包括几个步骤：

1.  从独立可执行文件中提取项目的字节码的二进制表示。

1.  将二进制表示映射到特定 Python 版本的字节码。

1.  将字节码转换为 AST。

1.  直接从 AST 重新创建源代码。

提供确切的解决方案来阻止开发人员对独立可执行文件进行逆向工程将是毫无意义的，因为这是显而易见的原因。因此，这里只提供了一些阻碍反编译过程或贬值其结果的想法：

+   删除运行时可用的任何代码元数据（文档字符串），因此最终结果会变得不太可读

+   修改 CPython 解释器使用的字节码值，以便从二进制转换为字节码，然后再转换为 AST 需要更多的工作

+   使用经过复杂修改的 CPython 源代码版本，即使可用应用程序的反编译源代码也无法在没有反编译修改后的 CPython 二进制文件的情况下使用

+   在将源代码捆绑成可执行文件之前，使用混淆脚本对源代码进行混淆，这样在反编译后源代码的价值就会降低

这些解决方案使开发过程变得更加困难。上述一些想法需要对 Python 运行时有很深的理解，但它们每一个都充满了许多陷阱和缺点。大多数情况下，它们只是推迟了不可避免的结果。一旦你的技巧被破解，所有额外的努力都将成为时间和资源的浪费。

不允许您的闭源代码以任何形式直接发货给用户是唯一可靠的方法。只有在您组织的其他方面保持严密的安全性时，这才是真实的。

# 摘要

本章描述了 Python 的打包生态系统的细节。现在，在阅读完本章之后，您应该知道哪些工具适合您的打包需求，以及您的项目需要哪些类型的分发。您还应该知道常见问题的流行技术以及如何为您的项目提供有用的元数据。

我们还讨论了独立可执行文件的话题，这些文件非常有用，特别是在分发桌面应用程序时。

下一章将广泛依赖我们在这里学到的知识，展示如何以可靠和自动化的方式有效处理代码部署。


# 第六章：部署代码

即使完美的代码（如果存在的话）如果不被运行，也是无用的。因此，为了发挥作用，我们的代码需要安装到目标机器（计算机）并执行。将特定版本的应用程序或服务提供给最终用户的过程称为部署。

对于桌面应用程序来说，这似乎很简单——你的工作就是提供一个可下载的包，并在必要时提供可选的安装程序。用户有责任在自己的环境中下载并安装它。你的责任是尽可能地使这个过程简单和方便。适当的打包仍然不是一项简单的任务，但一些工具已经在上一章中进行了解释。

令人惊讶的是，当你的代码不是产品本身时，情况会变得更加复杂。如果你的应用程序只提供向用户出售的服务，那么你有责任在自己的基础设施上运行它。这种情况对于 Web 应用程序或任何“X 作为服务”产品都很典型。在这种情况下，代码被部署到远程机器上，通常开发人员几乎无法物理接触到这些机器。如果你已经是云计算服务的用户，比如亚马逊网络服务（AWS）或 Heroku，这一点尤其真实。

在本章中，我们将集中讨论代码部署到远程主机的方面，因为 Python 在构建各种与网络相关的服务和产品领域非常受欢迎。尽管这种语言具有很高的可移植性，但它没有特定的特性，可以使其代码易于部署。最重要的是你的应用程序是如何构建的，以及你用什么流程将其部署到目标环境中。因此，本章将重点讨论以下主题：

+   部署代码到远程环境的主要挑战是什么

+   如何构建易于部署的 Python 应用程序

+   如何在没有停机的情况下重新加载 Web 服务

+   如何利用 Python 打包生态系统进行代码部署

+   如何正确监控和调试远程运行的代码

# 十二要素应用

无痛部署的主要要求是以确保这个过程简单和尽可能流畅的方式构建你的应用程序。这主要是关于消除障碍和鼓励良好的做法。在只有特定人员负责开发（开发团队或简称为 Dev）的组织中，以及不同的人负责部署和维护执行环境（运维团队或简称为 Ops）的组织中，遵循这样的常见做法尤为重要。

与服务器维护、监控、部署、配置等相关的所有任务通常被放在一个袋子里，称为运维。即使在没有专门的运维团队的组织中，通常也只有一些开发人员被授权执行部署任务和维护远程服务器。这种职位的通用名称是 DevOps。此外，每个开发团队成员都负责运维并不是一种不寻常的情况，因此在这样的团队中，每个人都可以被称为 DevOps。无论你的组织结构如何，每个开发人员都应该知道运维工作以及代码如何部署到远程服务器，因为最终，执行环境及其配置是你正在构建的产品的隐藏部分。

以下的常见做法和约定主要是出于以下原因：

+   在每家公司，员工会离职，新员工会入职。通过使用最佳方法，你可以让新团队成员更容易地加入项目。你永远无法确定新员工是否已经熟悉了系统配置和可靠运行应用程序的常见做法，但你至少可以让他们更有可能快速适应。

+   在只有一些人负责部署的组织中，它简单地减少了运维和开发团队之间的摩擦。

鼓励构建易于部署应用程序的实践的一个很好的来源是一个名为**十二要素应用**的宣言。它是一个通用的、与语言无关的构建软件即服务应用程序的方法论。它的目的之一是使应用程序更容易部署，但它也强调了其他主题，比如可维护性和使应用程序更容易扩展。

正如其名称所示，十二要素应用由 12 条规则组成：

+   **代码库**：一个代码库在版本控制中跟踪，多次部署

+   **依赖关系**：明确声明和隔离依赖关系

+   **配置**：将配置存储在环境中

+   **后端服务**：将后端服务视为附加资源

+   **构建、发布、运行**：严格区分构建和运行阶段

+   **进程**：将应用程序作为一个或多个无状态进程执行

+   **端口绑定**：通过端口绑定导出服务

+   **并发**：通过进程模型进行扩展

+   **可处置性**：通过快速启动和优雅关闭来最大化健壮性

+   **开发/生产一致性**：尽量使开发、演示和生产环境尽可能相似

+   **日志**：将日志视为事件流

+   **管理进程**：将管理任务作为一次性进程运行

在这里扩展每个规则有点无意义，因为十二要素应用方法论的官方页面（[`12factor.net/`](http://12factor.net/)）包含了每个应用要素的广泛原理，以及不同框架和环境的工具示例。

本章试图与上述宣言保持一致，因此我们将在必要时详细讨论其中一些。所呈现的技术和示例有时可能略微偏离这 12 个要素，但请记住，这些规则并非铁板一块。只要能达到目的，它们就是好的。最终，重要的是工作的应用程序（产品），而不是与某种任意方法论兼容。

# 使用 Fabric 进行部署自动化

对于非常小的项目，可能可以手动部署代码，也就是通过远程 shell 手动输入必要的命令序列来安装新版本的代码并在远程 shell 上执行。然而，即使对于一个中等大小的项目，这种方法容易出错，繁琐，并且应该被视为浪费你最宝贵的资源，也就是你自己的时间。

解决这个问题的方法是自动化。一个简单的经验法则是，如果你需要手动执行相同的任务至少两次，你应该自动化它，这样你就不需要第三次手动执行了。有各种工具可以让你自动化不同的事情：

+   远程执行工具如 Fabric 用于按需在多个远程主机上自动执行代码。

+   诸如 Chef、Puppet、CFEngine、Salt 和 Ansible 等配置管理工具旨在自动配置远程主机（执行环境）。它们可以用于设置后端服务（数据库、缓存等）、系统权限、用户等。它们大多也可以用作像 Fabric 这样的远程执行工具，但根据它们的架构，这可能更容易或更困难。

配置管理解决方案是一个复杂的话题，值得单独写一本书。事实上，最简单的远程执行框架具有最低的入门门槛，并且是最受欢迎的选择，至少对于小型项目来说是这样。事实上，每个配置管理工具都提供了一种声明性地指定机器配置的方式，深层内部都实现了远程执行层。

此外，根据某些工具的设计，由于它们的设计，它可能不适合实际的自动化代码部署。一个这样的例子是 Puppet，它确实不鼓励显式运行任何 shell 命令。这就是为什么许多人选择同时使用这两种类型的解决方案来相互补充：配置管理用于设置系统级环境，按需远程执行用于应用程序部署。

Fabric ([`www.fabfile.org/`](http://www.fabfile.org/))到目前为止是 Python 开发人员用来自动化远程执行的最流行的解决方案。它是一个用于简化使用 SSH 进行应用程序部署或系统管理任务的 Python 库和命令行工具。我们将重点关注它，因为它相对容易上手。请注意，根据您的需求，它可能不是解决问题的最佳方案。无论如何，它是一个很好的工具，可以为您的操作添加一些自动化，如果您还没有的话。

### 提示

**Fabric 和 Python 3**

本书鼓励您只在 Python 3 中开发（如果可能的话），并提供有关旧语法特性和兼容性注意事项的注释，只是为了使最终版本切换更加轻松。不幸的是，在撰写本书时，Fabric 仍未正式移植到 Python 3。这个工具的爱好者们被告知至少有几年的时间正在开发 Fabric 2，将带来一个兼容性更新。据说这是一个完全重写，带有许多新功能，但目前还没有 Fabric 2 的官方开放存储库，几乎没有人看到过它的代码。核心 Fabric 开发人员不接受当前项目的 Python 3 兼容性的任何拉取请求，并关闭对其的每个功能请求。这种对流行开源项目的开发方式至少是令人不安的。这个问题的历史并不让我们看到 Fabric 2 的官方发布的机会很高。这种秘密开发新 Fabric 版本的做法引发了许多问题。

不管任何人的观点，这个事实并不会减少 Fabric 在当前状态下的实用性。因此，如果您已经决定坚持使用 Python 3，有两个选择：使用一个完全兼容且独立的分支（[`github.com/mathiasertl/fabric/`](https://github.com/mathiasertl/fabric/)）或者在 Python 3 中编写您的应用程序，并在 Python 2 中维护 Fabric 脚本。最好的方法是在一个单独的代码存储库中进行。

当然，您可以只使用 Bash 脚本来自动化所有工作，但这非常繁琐且容易出错。Python 有更方便的字符串处理方式，并鼓励代码模块化。事实上，Fabric 只是一个通过 SSH 粘合命令执行的工具，因此仍然需要一些关于命令行界面及其实用程序在您的环境中如何工作的知识。

使用 Fabric 开始工作，您需要安装`fabric`包（使用`pip`），并创建一个名为`fabfile.py`的脚本，通常位于项目的根目录中。请注意，`fabfile`可以被视为项目配置的一部分。因此，如果您想严格遵循十二要素应用程序方法论，您不应该在部署的应用程序源树中维护其代码。事实上，复杂的项目通常是由维护为单独代码库的各种组件构建而成，因此，将所有项目组件配置和 Fabric 脚本放在一个单独的存储库中是一个很好的方法。这样可以使不同服务的部署更加一致，并鼓励良好的代码重用。

一个定义了简单部署过程的示例`fabfile`将如下所示：

```py
# -*- coding: utf-8 -*-
import os

from fabric.api import *  # noqa
from fabric.contrib.files import exists

# Let's assume we have private package repository created
# using 'devpi' project
PYPI_URL = 'http://devpi.webxample.example.com'

# This is arbitrary location for storing installed releases.
# Each release is a separate virtual environment directory
# which is named after project version. There is also a
# symbolic link 'current' that points to recently deployed
# version. This symlink is an actual path that will be used
# for configuring the process supervision tool e.g.:
# .
# ├── 0.0.1
# ├── 0.0.2
# ├── 0.0.3
# ├── 0.1.0
# └── current -> 0.1.0/

REMOTE_PROJECT_LOCATION = "/var/projects/webxample"

env.project_location = REMOTE_PROJECT_LOCATION

# roledefs map out environment types (staging/production)
env.roledefs = {
    'staging': [
        'staging.webxample.example.com',
    ],
    'production': [
        'prod1.webxample.example.com',
        'prod2.webxample.example.com',
    ],
}

def prepare_release():
    """ Prepare a new release by creating source distribution and uploading to out private package repository
    """
    local('python setup.py build sdist upload -r {}'.format(
        PYPI_URL
    ))

def get_version():
    """ Get current project version from setuptools """
    return local(
        'python setup.py --version', capture=True
    ).stdout.strip()

def switch_versions(version):
    """ Switch versions by replacing symlinks atomically """
    new_version_path = os.path.join(REMOTE_PROJECT_LOCATION, version)
    temporary = os.path.join(REMOTE_PROJECT_LOCATION, 'next')
    desired = os.path.join(REMOTE_PROJECT_LOCATION, 'current')

    # force symlink (-f) since probably there is a one already
    run(
        "ln -fsT {target} {symlink}"
        "".format(target=new_version_path, symlink=temporary)
    )
    # mv -T ensures atomicity of this operation
    run("mv -Tf {source} {destination}"
        "".format(source=temporary, destination=desired))

@task
def uptime():
    """
    Run uptime command on remote host - for testing connection.
    """
    run("uptime")

@task
def deploy():
    """ Deploy application with packaging in mind """
    version = get_version()
    pip_path = os.path.join(
        REMOTE_PROJECT_LOCATION, version, 'bin', 'pip'
    )

    prepare_release()

    if not exists(REMOTE_PROJECT_LOCATION):
        # it may not exist for initial deployment on fresh host
        run("mkdir -p {}".format(REMOTE_PROJECT_LOCATION))

    with cd(REMOTE_PROJECT_LOCATION):
        # create new virtual environment using venv
        run('python3 -m venv {}'.format(version))

        run("{} install webxample=={} --index-url {}".format(
            pip_path, version, PYPI_URL
        ))

    switch_versions(version)
    # let's assume that Circus is our process supervision tool
    # of choice.
    run('circusctl restart webxample')
```

每个使用`@task`装饰的函数都被视为`fabric`包提供的`fab`实用程序的可用子命令。您可以使用`-l`或`--list`开关列出所有可用的子命令：

```py
$ fab --list
Available commands:

 **deploy  Deploy application with packaging in mind
 **uptime  Run uptime command on remote host - for testing connection.

```

现在，您可以只需一个 shell 命令将应用程序部署到给定的环境类型：

```py
$ fab –R production deploy

```

请注意，前面的`fabfile`仅用于举例说明。在您自己的代码中，您可能希望提供全面的故障处理，并尝试重新加载应用程序，而无需重新启动 Web 工作进程。此外，此处介绍的一些技术现在可能很明显，但稍后将在本章中进行解释。这些是：

+   使用私有软件包存储库部署应用程序

+   在远程主机上使用 Circus 进行进程监控

# 您自己的软件包索引或索引镜像

有三个主要原因您可能希望运行自己的 Python 软件包索引：

+   官方 Python 软件包索引没有任何可用性保证。它由 Python 软件基金会运行，感谢众多捐赠。因此，这往往意味着该站点可能会关闭。您不希望由于 PyPI 中断而在中途停止部署或打包过程。

+   即使对于永远不会公开发布的闭源代码，也有用处，因为它可以使用 Python 编写的可重用组件得到适当打包。这简化了代码库，因为公司中用于不同项目的软件包不需要被打包。您可以直接从存储库安装它们。这简化了这些共享代码的维护，并且如果公司有许多团队在不同项目上工作，可能会减少整个公司的开发成本。

+   使用`setuptools`对整个项目进行打包是非常好的做法。然后，部署新应用程序版本通常只需运行`pip install --update my-application`。

### 提示

**代码打包**

代码打包是将外部软件包的源代码包含在其他项目的源代码（存储库）中的做法。当项目的代码依赖于某个特定版本的外部软件包时，通常会这样做，该软件包也可能被其他软件包（以完全不同的版本）所需。例如，流行的`requests`软件包在其源代码树中打包了`urllib3`的某个版本，因为它与之紧密耦合，并且几乎不太可能与`urllib3`的其他版本一起使用。一些特别经常被其他人打包的模块的例子是`six`。它可以在许多流行项目的源代码中找到，例如 Django（`django.utils.six`），Boto（`boto.vedored.six`）或 Matplotlib（`matplotlib.externals.six`）。

尽管一些大型和成功的开源项目甚至也会使用打包，但如果可能的话应该避免。这只在某些情况下才有合理的用途，并且不应被视为软件包依赖管理的替代品。

## PyPI 镜像

PyPI 中断的问题可以通过允许安装工具从其镜像之一下载软件包来在一定程度上得到缓解。事实上，官方 Python 软件包索引已经通过**CDN**（**内容传送网络**）提供服务，因此它本质上是镜像的。这并不改变这样的事实，即它似乎偶尔会出现一些糟糕的日子，当任何尝试下载软件包失败时。在这里使用非官方镜像不是一个解决方案，因为这可能会引发一些安全顾虑。

最好的解决方案是拥有自己的 PyPI 镜像，其中包含您需要的所有软件包。唯一使用它的一方是您自己，因此更容易确保适当的可用性。另一个优势是，每当此服务关闭时，您无需依赖其他人来重新启动它。PyPA 维护和推荐的镜像工具是**bandersnatch**（[`pypi.python.org/pypi/bandersnatch`](https://pypi.python.org/pypi/bandersnatch)）。它允许您镜像 Python Package Index 的全部内容，并且可以作为`.pypirc`文件中存储库部分的`index-url`选项提供（如前一章中所述）。此镜像不接受上传，也没有 PyPI 的 Web 部分。无论如何，要小心！完整的镜像可能需要数百千兆字节的存储空间，并且其大小将随着时间的推移而继续增长。

但是，为什么要停留在一个简单的镜像上，而我们有一个更好的选择呢？您几乎不太可能需要整个软件包索引的镜像。即使是具有数百个依赖项的项目，它也只是所有可用软件包的一小部分。此外，无法上传自己的私有软件包是这种简单镜像的巨大局限性。似乎使用 bandersnatch 的附加价值与其高昂的价格相比非常低。在大多数情况下，这是正确的。如果软件包镜像仅用于单个或少数项目，那么使用**devpi**（[`doc.devpi.net/`](http://doc.devpi.net/)）将是一个更好的方法。它是一个与 PyPI 兼容的软件包索引实现，提供以下两种功能：

+   上传非公共软件包的私有索引

+   索引镜像

devpi 相对于 bandersnatch 的主要优势在于它如何处理镜像。它当然可以像 bandersnatch 一样对其他索引进行完整的通用镜像，但这不是它的默认行为。它不是对整个存储库进行昂贵的备份，而是为已被客户端请求的软件包维护镜像。因此，每当安装工具（`pip`、`setuptools`和`easyinstall`）请求软件包时，如果在本地镜像中不存在，devpi 服务器将尝试从镜像索引（通常是 PyPI）下载并提供。软件包下载后，devpi 将定期检查其更新，以保持镜像的新鲜状态。

镜像方法在您请求尚未被镜像的新软件包并且上游软件包索引中断时留下了轻微的失败风险。无论如何，由于在大多数部署中，您将仅依赖于已在索引中镜像的软件包，因此这种风险得到了减少。对于已经请求的软件包，镜像状态与 PyPI 具有最终一致性，并且新版本将自动下载。这似乎是一个非常合理的权衡。

## 使用软件包进行部署

现代 Web 应用程序有很多依赖项，并且通常需要许多步骤才能在远程主机上正确安装。例如，对于远程主机上的应用程序的新版本的典型引导过程包括以下步骤：

+   为隔离创建新的虚拟环境

+   将项目代码移动到执行环境

+   安装最新的项目要求（通常来自`requirements.txt`文件）

+   同步或迁移数据库架构

+   从项目源和外部软件包收集静态文件到所需位置

+   为可用于不同语言的应用程序编译本地化文件

对于更复杂的网站，可能会有许多与前端代码相关的附加任务：

+   使用预处理器（如 SASS 或 LESS）生成 CSS 文件

+   对静态文件（JavaScript 和 CSS 文件）进行缩小、混淆和/或合并

+   编译用 JavaScript 超集语言（CoffeeScript、TypeScript 等）编写的代码到本机 JS

+   预处理响应模板文件（缩小、内联样式等）

所有这些步骤都可以使用诸如 Bash、Fabric 或 Ansible 之类的工具轻松自动化，但在安装应用程序的远程主机上做所有事情并不是一个好主意。原因如下：

+   一些用于处理静态资产的流行工具可能是 CPU 密集型或内存密集型。在生产环境中运行它们可能会使应用程序执行不稳定。

+   这些工具通常需要额外的系统依赖项，这些依赖项可能不是项目的正常运行所必需的。这些主要是额外的运行时环境，如 JVM、Node 或 Ruby。这增加了配置管理的复杂性，并增加了整体维护成本。

+   如果您将应用程序部署到多个服务器（十个、百个、千个），那么您只是在重复很多工作，这些工作本来可以只做一次。如果您有自己的基础设施，那么您可能不会经历巨大的成本增加，特别是如果您在低流量时段进行部署。但如果您在计费模型中运行云计算服务，该模型会额外收费用于负载峰值或一般执行时间，那么这些额外成本可能在适当的规模上是相当可观的。

+   大多数这些步骤只是花费了很多时间。您正在将代码安装到远程服务器上，所以您最不希望的是在部署过程中由于某些网络问题而中断连接。通过保持部署过程快速，您可以降低部署中断的几率。

出于明显的原因，上述部署步骤的结果不能包含在应用程序代码存储库中。简单地说，有些事情必须在每个发布中完成，你无法改变这一点。显然这是一个适当自动化的地方，但关键是在正确的地方和正确的时间做。

大部分静态收集和代码/资产预处理等工作可以在本地或专用环境中完成，因此部署到远程服务器的实际代码只需要进行最少量的现场处理。在构建分发或安装包的过程中，最显著的部署步骤是：

+   安装 Python 依赖项和传输静态资产（CSS 文件和 JavaScript）到所需位置可以作为`setup.py`脚本的`install`命令的一部分来处理

+   预处理代码（处理 JavaScript 超集、资产的缩小/混淆/合并，以及运行 SASS 或 LESS）和诸如本地化文本编译（例如 Django 中的`compilemessages`）等工作可以作为`setup.py`脚本的`sdist`/`bdist`命令的一部分

包括除 Python 以外的预处理代码可以很容易地通过适当的`MANIFEST.in`文件处理。依赖项当然最好作为`setuptools`包的`setup()`函数调用的`install_requires`参数提供。

当然，打包整个应用程序将需要您进行一些额外的工作，比如提供自己的自定义`setuptools`命令或覆盖现有的命令，但这将为您带来许多优势，并使项目部署更快速和可靠。

让我们以一个基于 Django 的项目（在 Django 1.9 版本中）为例。我选择这个框架是因为它似乎是这种类型的最受欢迎的 Python 项目，所以你很有可能已经对它有所了解。这样的项目中文件的典型结构可能如下所示：

```py
$ tree . -I __pycache__ --dirsfirst
.
├── webxample
│   ├── conf
│   │   ├── __init__.py
│   │   ├── settings.py
│   │   ├── urls.py
│   │   └── wsgi.py
│   ├── locale
│   │   ├── de
│   │   │   └── LC_MESSAGES
│   │   │       └── django.po
│   │   ├── en
│   │   │   └── LC_MESSAGES
│   │   │       └── django.po
│   │   └── pl
│   │       └── LC_MESSAGES
│   │           └── django.po
│   ├── myapp
│   │   ├── migrations
│   │   │   └── __init__.py
│   │   ├── static
│   │   │   ├── js
│   │   │   │   └── myapp.js
│   │   │   └── sass
│   │   │       └── myapp.scss
│   │   ├── templates
│   │   │   ├── index.html
│   │   │   └── some_view.html
│   │   ├── __init__.py
│   │   ├── admin.py
│   │   ├── apps.py
│   │   ├── models.py
│   │   ├── tests.py
│   │   └── views.py
│   ├── __init__.py
│   └── manage.py
├── MANIFEST.in
├── README.md
└── setup.py

15 directories, 23 files

```

请注意，这与通常的 Django 项目模板略有不同。默认情况下，包含 WSGI 应用程序、设置模块和 URL 配置的包与项目名称相同。因为我们决定采用打包的方法，这将被命名为`webxample`。这可能会引起一些混淆，所以最好将其重命名为`conf`。

不要深入可能的实现细节，让我们只做一些简单的假设：

+   我们的示例应用程序有一些外部依赖。在这里，将是两个流行的 Django 软件包：`djangorestframework` 和 `django-allauth`，以及一个非 Django 软件包：`gunicorn`。

+   `djangorestframework` 和 `django-allauth` 被提供为 `webexample.webexample.settings` 模块中的 `INSTALLED_APPS`。

+   该应用程序在三种语言（德语、英语和波兰语）中进行了本地化，但我们不希望将编译的 `gettext` 消息存储在存储库中。

+   我们厌倦了普通的 CSS 语法，所以我们决定使用更强大的 SCSS 语言，我们使用 SASS 将其转换为 CSS。

了解项目的结构后，我们可以编写我们的 `setup.py` 脚本，使 `setuptools` 处理：

+   在 `webxample/myapp/static/scss` 下编译 SCSS 文件

+   从 `.po` 格式编译 `webexample/locale` 下的 `gettext` 消息到 `.mo` 格式

+   安装要求

+   提供软件包的入口点的新脚本，这样我们将有自定义命令而不是 `manage.py` 脚本

我们在这里有点运气。 `libsass` 的 Python 绑定是 SASS 引擎的 C/C++端口，它与 `setuptools` 和 `distutils` 提供了很好的集成。只需进行少量配置，它就可以为运行 SASS 编译提供自定义的 `setup.py` 命令：

```py
from setuptools import setup

setup(
    name='webxample',
    setup_requires=['libsass >= 0.6.0'],
    sass_manifests={
        'webxample.myapp': ('static/sass', 'static/css')
    },
)
```

因此，我们可以通过键入 `python setup.py build_scss` 来将我们的 SCSS 文件编译为 CSS，而不是手动运行 `sass` 命令或在 `setup.py` 脚本中执行子进程。这还不够。这让我们的生活变得更容易，但我们希望整个分发过程完全自动化，因此只需一个步骤即可创建新版本。为了实现这个目标，我们不得不稍微覆盖一些现有的 `setuptools` 分发命令。

处理一些项目准备步骤的 `setup.py` 文件示例可能如下所示：

```py
import os

from setuptools import setup
from setuptools import find_packages
from distutils.cmd import Command
from distutils.command.build import build as _build

try:
    from django.core.management.commands.compilemessages \
        import Command as CompileCommand
except ImportError:
    # note: during installation django may not be available
    CompileCommand = None

# this environment is requires
os.environ.setdefault(
    "DJANGO_SETTINGS_MODULE", "webxample.conf.settings"
)

class build_messages(Command):
    """ Custom command for building gettext messages in Django
    """
    description = """compile gettext messages"""
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):

        pass

    def run(self):
        if CompileCommand:
            CompileCommand().handle(
                verbosity=2, locales=[], exclude=[]
            )
        else:
            raise RuntimeError("could not build translations")

class build(_build):
    """ Overriden build command that adds additional build steps
    """
    sub_commands = [
        ('build_messages', None),
        ('build_sass', None),
    ] + _build.sub_commands

setup(
    name='webxample',
    setup_requires=[
        'libsass >= 0.6.0',
        'django >= 1.9.2',
    ],
    install_requires=[
        'django >= 1.9.2',
        'gunicorn == 19.4.5',
        'djangorestframework == 3.3.2',
        'django-allauth == 0.24.1',
    ],
    packages=find_packages('.'),
    sass_manifests={
        'webxample.myapp': ('static/sass', 'static/css')
    },
    cmdclass={
        'build_messages': build_messages,
        'build': build,
    },
    entry_points={
        'console_scripts': {
            'webxample = webxample.manage:main',
        }
    }
)
```

通过这种实现，我们可以使用这个单一的终端命令构建所有资产并为 `webxample` 项目创建源分发的软件包：

```py
$ python setup.py build sdist

```

如果您已经拥有自己的软件包索引（使用 `devpi` 创建），则可以添加 `install` 子命令或使用 `twine`，这样该软件包将可以在您的组织中使用 `pip` 进行安装。如果我们查看使用我们的 `setup.py` 脚本创建的源分发结构，我们可以看到它包含了从 SCSS 文件生成的编译的 `gettext` 消息和 CSS 样式表：

```py
$ tar -xvzf dist/webxample-0.0.0.tar.gz 2> /dev/null
$ tree webxample-0.0.0/ -I __pycache__ --dirsfirst
webxample-0.0.0/
├── webxample
│   ├── conf
│   │   ├── __init__.py
│   │   ├── settings.py
│   │   ├── urls.py
│   │   └── wsgi.py
│   ├── locale
│   │   ├── de
│   │   │   └── LC_MESSAGES
│   │   │       ├── django.mo
│   │   │       └── django.po
│   │   ├── en
│   │   │   └── LC_MESSAGES
│   │   │       ├── django.mo
│   │   │       └── django.po
│   │   └── pl
│   │       └── LC_MESSAGES
│   │           ├── django.mo
│   │           └── django.po
│   ├── myapp
│   │   ├── migrations
│   │   │   └── __init__.py
│   │   ├── static
│   │   │   ├── css
│   │   │   │   └── myapp.scss.css
│   │   │   └── js
│   │   │       └── myapp.js
│   │   ├── templates
│   │   │   ├── index.html
│   │   │   └── some_view.html
│   │   ├── __init__.py
│   │   ├── admin.py
│   │   ├── apps.py
│   │   ├── models.py
│   │   ├── tests.py
│   │   └── views.py
│   ├── __init__.py
│   └── manage.py
├── webxample.egg-info
│   ├── PKG-INFO
│   ├── SOURCES.txt
│   ├── dependency_links.txt
│   ├── requires.txt
│   └── top_level.txt
├── MANIFEST.in
├── PKG-INFO
├── README.md
├── setup.cfg
└── setup.py

16 directories, 33 files

```

使用这种方法的额外好处是，我们能够在 Django 的默认 `manage.py` 脚本的位置提供我们自己的项目入口点。现在我们可以使用这个入口点运行任何 Django 管理命令，例如：

```py
$ webxample migrate
$ webxample collectstatic
$ webxample runserver

```

这需要在 `manage.py` 脚本中进行一些小的更改，以便与 `setup()` 中的 `entry_points` 参数兼容，因此它的主要部分的代码被包装在 `main()` 函数调用中：

```py
#!/usr/bin/env python3
import os
import sys

def main():
    os.environ.setdefault(
        "DJANGO_SETTINGS_MODULE", "webxample.conf.settings"
    )

    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)

if __name__ == "__main__":
    main()
```

不幸的是，许多框架（包括 Django）并不是以打包项目的方式设计的。这意味着根据应用程序的进展，将其转换为包可能需要进行许多更改。在 Django 中，这通常意味着重写许多隐式导入并更新设置文件中的许多配置变量。

另一个问题是使用 Python 打包创建的发布的一致性。如果不同的团队成员被授权创建应用程序分发，那么在相同可复制的环境中进行此过程至关重要，特别是当您进行大量资产预处理时；即使从相同的代码库创建，可能在两个不同的环境中创建的软件包看起来也不一样。这可能是由于在构建过程中使用了不同版本的工具。最佳实践是将分发责任移交给持续集成/交付系统，如 Jenkins 或 Buildbot。额外的好处是您可以断言软件包在分发之前通过了所有必需的测试。您甚至可以将自动部署作为这种持续交付系统的一部分。

尽管如此，使用`setuptools`将您的代码分发为 Python 软件包并不简单和轻松；它将极大简化您的部署，因此绝对值得一试。请注意，这也符合十二要素应用程序的第六条详细建议：将应用程序执行为一个或多个无状态进程（[`12factor.net/processes`](http://12factor.net/processes)）。

# 常见的惯例和做法

有一套部署的常见惯例和做法，不是每个开发人员都可能知道，但对于任何曾经进行过一些操作的人来说都是显而易见的。正如在章节介绍中所解释的那样，即使您不负责代码部署和操作，至少了解其中一些对于在开发过程中做出更好的设计决策是至关重要的。

## 文件系统层次结构

您可能会想到的最明显的惯例可能是关于文件系统层次结构和用户命名的。如果您在这里寻找建议，那么您会感到失望。当然有一个**文件系统层次结构标准**，它定义了 Unix 和类 Unix 操作系统中的目录结构和目录内容，但真的很难找到一个完全符合 FHS 的实际操作系统发行版。如果系统设计师和程序员不能遵守这样的标准，那么很难期望管理员也能做到。根据我的经验，我几乎在可能的任何地方看到应用程序代码部署，包括在根文件系统级别的非标准自定义目录。几乎总是，做出这样决定的人都有非常充分的理由。在这方面我能给你的唯一建议是：

+   明智选择，避免惊喜

+   在项目的所有可用基础设施中保持一致

+   尽量在您的组织（您所在的公司）中保持一致

真正有帮助的是为您的项目记录惯例。只需确保这些文件对每个感兴趣的团队成员都是可访问的，并且每个人都知道这样的文件存在。

## 隔离

隔离的原因以及推荐的工具已经在第一章中讨论过，*Python 的当前状态*。对于部署，只有一件重要的事情要补充。您应该始终为应用程序的每个发布版本隔离项目依赖关系。在实践中，这意味着每当您部署应用程序的新版本时，您应该为此版本创建一个新的隔离环境（使用`virtualenv`或`venv`）。旧环境应该在您的主机上保留一段时间，以便在出现问题时可以轻松地回滚到旧版本之一。

为每个发布创建新的环境有助于管理其干净状态并符合提供的依赖项列表。通过新环境，我们指的是在文件系统中创建一个新的目录树，而不是更新已经存在的文件。不幸的是，这可能会使一些事情变得更加困难，比如优雅地重新加载服务，如果环境是就地更新的话，这将更容易实现。

## 使用进程监控工具

远程服务器上的应用程序通常不会意外退出。如果是 Web 应用程序，其 HTTP 服务器进程将无限期地等待新的连接和请求，并且只有在发生一些无法恢复的错误时才会退出。

当然，无法在 shell 中手动运行它并保持一个永久的 SSH 连接。使用`nohup`、`screen`或`tmux`来半守护化进程也不是一个选择。这样做就像是在设计您的服务注定要失败。

您需要的是一些进程监控工具，可以启动和管理您的应用程序进程。在选择合适的工具之前，您需要确保它：

+   如果服务退出，则重新启动服务

+   可靠地跟踪其状态

+   捕获其`stdout`/`stderr`流以进行日志记录

+   以特定用户/组权限运行进程

+   配置系统环境变量

大多数 Unix 和 Linux 发行版都有一些内置的进程监控工具/子系统，比如`initd`脚本、`upstart`和`runit`。不幸的是，在大多数情况下，它们不适合运行用户级应用程序代码，并且非常难以维护。特别是编写可靠的`init.d`脚本是一个真正的挑战，因为它需要大量的 Bash 脚本编写，这很难做到正确。一些 Linux 发行版，比如 Gentoo，对`init.d`脚本有了重新设计的方法，因此编写它们变得更容易。无论如何，为了一个单一的进程监控工具而将自己锁定到特定的操作系统发行版并不是一个好主意。

Python 社区中管理应用程序进程的两种流行工具是 Supervisor ([`supervisord.org`](http://supervisord.org))和 Circus ([`circus.readthedocs.org/en/latest/`](https://circus.readthedocs.org/en/latest/))。它们在配置和使用上都非常相似。Circus 比 Supervisor 稍微年轻一些，因为它是为了解决后者的一些弱点而创建的。它们都可以使用简单的 INI 格式进行配置。它们不仅限于运行 Python 进程，还可以配置为管理任何应用程序。很难说哪一个更好，因为它们都提供非常相似的功能。

无论如何，Supervisor 不支持 Python 3，因此我们不会推荐它。虽然在 Supervisor 的控制下运行 Python 3 进程不是问题，但我将以此为借口，只展示 Circus 配置的示例。

假设我们想要在 Circus 控制下使用`gunicorn` web 服务器运行 webxample 应用程序（在本章前面介绍过）。在生产环境中，我们可能会在适用的系统级进程监控工具（`initd`、`upstart`和`runit`）下运行 Circus，特别是如果它是从系统软件包存储库安装的。为了简单起见，我们将在虚拟环境内本地运行。允许我们在 Circus 中运行应用程序的最小配置文件（这里命名为`circus.ini`）如下所示：

```py
[watcher:webxample]
cmd = /path/to/venv/dir/bin/gunicorn webxample.conf.wsgi:application
numprocesses = 1
```

现在，`circus`进程可以使用这个配置文件作为执行参数来运行：

```py
$ circusd circus.ini
2016-02-15 08:34:34 circus[1776] [INFO] Starting master on pid 1776
2016-02-15 08:34:34 circus[1776] [INFO] Arbiter now waiting for commands
2016-02-15 08:34:34 circus[1776] [INFO] webxample started
[2016-02-15 08:34:34 +0100] [1778] [INFO] Starting gunicorn 19.4.5
[2016-02-15 08:34:34 +0100] [1778] [INFO] Listening at: http://127.0.0.1:8000 (1778)
[2016-02-15 08:34:34 +0100] [1778] [INFO] Using worker: sync
[2016-02-15 08:34:34 +0100] [1781] [INFO] Booting worker with pid: 1781

```

现在，您可以使用`circusctl`命令来运行一个交互式会话，并使用简单的命令来控制所有受管进程。以下是这样一个会话的示例：

```py
$ circusctl
circusctl 0.13.0
webxample: active
(circusctl) stop webxample
ok
(circusctl) status
webxample: stopped
(circusctl) start webxample
ok
(circusctl) status
webxample: active

```

当然，上述两种工具都有更多功能可用。它们的所有功能都在它们的文档中有解释，因此在做出选择之前，您应该仔细阅读它们。

## 应用代码应该在用户空间中运行

您的应用程序代码应始终在用户空间中运行。这意味着它不得以超级用户权限执行。如果您按照 Twelve-Factor App 设计应用程序，可以在几乎没有特权的用户下运行应用程序。拥有文件并且不属于特权组的用户的传统名称是`nobody`，但实际建议是为每个应用程序守护进程创建一个单独的用户。原因是系统安全性。这是为了限制恶意用户在控制应用程序进程后可能造成的损害。在 Linux 中，同一用户的进程可以相互交互，因此在用户级别上将不同的应用程序分开是很重要的。

## 使用反向 HTTP 代理

多个 Python 符合 WSGI 标准的 Web 服务器可以轻松地自行提供 HTTP 流量，无需在其上方使用任何其他 Web 服务器。然而，通常还是很常见将它们隐藏在 Nginx 等反向代理后面，原因有很多：

+   TLS/SSL 终止通常最好由顶级 Web 服务器（如 Nginx 和 Apache）处理。然后，Python 应用程序只能使用简单的 HTTP 协议（而不是 HTTPS），因此安全通信通道的复杂性和配置留给了反向代理。

+   非特权用户无法绑定低端口（0-1000 范围内），但 HTTP 协议应该在端口 80 上为用户提供服务，HTTPS 应该在端口 443 上提供服务。为此，必须以超级用户权限运行进程。通常，更安全的做法是让应用程序在高端口上提供服务，或者在 Unix 域套接字上提供服务，并将其用作在更特权用户下运行的反向代理的上游。

+   通常，Nginx 可以比 Python 代码更有效地提供静态资产（图像、JS、CSS 和其他媒体）。如果将其配置为反向代理，那么只需几行配置就可以通过它提供静态文件。

+   当单个主机需要从不同域中的多个应用程序提供服务时，Apache 或 Nginx 是不可或缺的，用于为在同一端口上提供服务的不同域创建虚拟主机。

+   反向代理可以通过添加额外的缓存层来提高性能，也可以配置为简单的负载均衡器。

一些 Web 服务器实际上建议在代理后运行，例如 Nginx。例如，`gunicorn`是一个非常强大的基于 WSGI 的服务器，如果其客户端速度很快，可以提供出色的性能结果。另一方面，它不能很好地处理慢速客户端，因此很容易受到基于慢速客户端连接的拒绝服务攻击的影响。使用能够缓冲慢速客户端的代理服务器是解决这个问题的最佳方法。

## 优雅地重新加载进程

Twelve-Factor App 方法论的第九条规则涉及进程的可处置性，并指出您应该通过快速启动时间和优雅的关闭来最大程度地提高鲁棒性。虽然快速启动时间相当不言自明，但优雅的关闭需要一些额外的讨论。

在 Web 应用程序范围内，如果以非优雅的方式终止服务器进程，它将立即退出，没有时间完成处理请求并向连接的客户端回复适当的响应。在最佳情况下，如果使用某种反向代理，那么代理可能会向连接的客户端回复一些通用的错误响应（例如 502 Bad Gateway），即使这并不是通知用户您已重新启动应用程序并部署新版本的正确方式。

根据 Twelve-Factor App，Web 服务器进程应能够在接收到 Unix `SIGTERM`信号（例如`kill -TERM <process-id>`）时优雅地退出。这意味着服务器应停止接受新连接，完成处理所有挂起的请求，然后在没有其他事情可做时以某种退出代码退出。

显然，当所有服务进程退出或开始其关闭过程时，您将无法再处理新请求。这意味着您的服务仍然会经历停机，因此您需要执行额外的步骤-启动新的工作进程，这些工作进程将能够在旧的工作进程优雅退出时接受新的连接。各种 Python WSGI 兼容的 Web 服务器实现允许在没有任何停机时间的情况下优雅地重新加载服务。最流行的是 Gunicorn 和 uWSGI：

+   Gunicorn 的主进程在接收到`SIGHUP`信号（`kill -HUP <process-pid>`）后，将启动新的工作进程（带有新的代码和配置），并尝试在旧的工作进程上进行优雅的关闭。

+   uWSGI 至少有三种独立的方案来进行优雅的重新加载。每一种都太复杂，无法简要解释，但它的官方文档提供了所有可能选项的完整信息。

优雅的重新加载在部署 Web 应用程序中已经成为标准。Gunicorn 似乎有一种最容易使用但也给您留下最少灵活性的方法。另一方面，uWSGI 中的优雅重新加载允许更好地控制重新加载，但需要更多的努力来自动化和设置。此外，您如何处理自动部署中的优雅重新加载也受到您使用的监视工具以及其配置方式的影响。例如，在 Gunicorn 中，优雅的重新加载就像这样简单：

```py
kill -HUP <gunicorn-master-process-pid>

```

但是，如果您想通过为每个发布分离虚拟环境并使用符号链接配置进程监视来正确隔离项目分发（如之前在`fabfile`示例中提出的），您很快会注意到这并不像预期的那样工作。对于更复杂的部署，目前还没有可用的解决方案可以直接为您解决问题。您总是需要进行一些黑客攻击，有时这将需要对低级系统实现细节有相当高的了解。

# 代码仪器和监控

我们的工作并不仅仅是编写应用程序并将其部署到目标执行环境。可能编写一个应用程序后，部署后将不需要任何进一步的维护，尽管这是非常不太可能的。实际上，我们需要确保它被正确地观察以发现错误和性能问题。

为了确保我们的产品按预期工作，我们需要正确处理应用程序日志并监视必要的应用程序指标。这通常包括：

+   监控 Web 应用程序访问日志以获取各种 HTTP 状态代码

+   可能包含有关运行时错误和各种警告的进程日志的收集

+   监控远程主机上的系统资源（CPU 负载、内存和网络流量），应用程序运行的地方

+   监控业务绩效和指标的应用级性能（客户获取、收入等）

幸运的是，有很多免费的工具可用于仪器化您的代码并监视其性能。其中大多数都很容易集成。

## 记录错误-哨兵/乌鸦

无论您的应用程序经过多么精确的测试，事实是痛苦的。您的代码最终会在某个时候失败。这可能是任何事情-意外的异常、资源耗尽、某些后台服务崩溃、网络中断，或者只是外部库中的问题。一些可能的问题，如资源耗尽，可以通过适当的监控来预测和防止，但无论您如何努力，总会有一些事情会越过您的防线。

您可以做的是为这种情况做好充分准备，并确保没有错误被忽视。在大多数情况下，应用程序引发的任何意外故障场景都会导致异常，并通过日志系统记录。这可以是`stdout`、`sderr`、“文件”或您为日志记录配置的任何输出。根据您的实现，这可能会导致应用程序退出并带有一些系统退出代码，也可能不会。

当然，您可以仅依赖于存储在文件中的这些日志来查找和监视应用程序错误。不幸的是，观察文本日志中的错误非常痛苦，并且在除了在开发中运行代码之外的任何更复杂的情况下都无法很好地扩展。您最终将被迫使用一些专为日志收集和分析而设计的服务。适当的日志处理对于稍后将要解释的其他原因非常重要，但对于跟踪和调试生产错误并不起作用。原因很简单。错误日志的最常见形式只是 Python 堆栈跟踪。如果您仅停留在那里，您很快就会意识到这不足以找到问题的根本原因-特别是当错误以未知模式或在某些负载条件下发生时。

您真正需要的是尽可能多的关于错误发生的上下文信息。拥有在生产环境中发生的错误的完整历史记录，并且可以以某种便捷的方式浏览和搜索，也非常有用。提供这种功能的最常见工具之一是 Sentry（[`getsentry.com`](https://getsentry.com)）。它是一个经过实战考验的用于跟踪异常和收集崩溃报告的服务。它作为开源软件提供，是用 Python 编写的，并起源于用于后端 Web 开发人员的工具。现在它已经超出了最初的野心，并支持了许多其他语言，包括 PHP、Ruby 和 JavaScript，但仍然是大多数 Python Web 开发人员的首选工具。

### 提示

**Web 应用程序中的异常堆栈跟踪**

通常，Web 应用程序不会在未处理的异常上退出，因为 HTTP 服务器有义务在发生任何服务器错误时返回一个 5XX 组的状态代码的错误响应。大多数 Python Web 框架默认情况下都会这样做。在这种情况下，实际上是在较低的框架级别处理异常。无论如何，在大多数情况下，这仍将导致异常堆栈跟踪被打印（通常在标准输出上）。

Sentry 以付费软件即服务模式提供，但它是开源的，因此可以免费托管在您自己的基础设施上。提供与 Sentry 集成的库是`raven`（可在 PyPI 上获得）。如果您尚未使用过它，想要测试它但无法访问自己的 Sentry 服务器，那么您可以轻松在 Sentry 的本地服务站点上注册免费试用。一旦您可以访问 Sentry 服务器并创建了一个新项目，您将获得一个称为 DSN 或数据源名称的字符串。这个 DSN 字符串是集成应用程序与 sentry 所需的最小配置设置。它以以下形式包含协议、凭据、服务器位置和您的组织/项目标识符：

```py
'{PROTOCOL}://{PUBLIC_KEY}:{SECRET_KEY}@{HOST}/{PATH}{PROJECT_ID}'
```

一旦您获得了 DSN，集成就非常简单：

```py
from raven import Client

client = Client('https://<key>:<secret>@app.getsentry.com/<project>')

try:
    1 / 0
except ZeroDivisionError:
    client.captureException()
```

Raven 与最流行的 Python 框架（如 Django，Flask，Celery 和 Pyramid）有许多集成，以使集成更容易。这些集成将自动提供特定于给定框架的附加上下文。如果您选择的 Web 框架没有专门的支持，`raven`软件包提供了通用的 WSGI 中间件，使其与任何基于 WSGI 的 Web 服务器兼容：

```py
from raven import Client
from raven.middleware import Sentry

# note: application is some WSGI application object defined earlier
application = Sentry(
    application,
    Client('https://<key>:<secret>@app.getsentry.com/<project>')
)
```

另一个值得注意的集成是跟踪通过 Python 内置的`logging`模块记录的消息的能力。启用此类支持仅需要几行额外的代码：

```py
from raven.handlers.logging import SentryHandler
from raven.conf import setup_logging

client = Client('https://<key>:<secret>@app.getsentry.com/<project>')
handler = SentryHandler(client)
setup_logging(handler)
```

捕获`logging`消息可能会有一些不明显的注意事项，因此，如果您对此功能感兴趣，请确保阅读官方文档。这应该可以避免令人不快的惊喜。

最后一点是关于运行自己的 Sentry 以节省一些钱的方法。 "没有免费的午餐。"最终，您将支付额外的基础设施成本，而 Sentry 将只是另一个需要维护的服务。*维护=额外工作=成本*！随着您的应用程序增长，异常的数量也会增长，因此您将被迫在扩展产品的同时扩展 Sentry。幸运的是，这是一个非常强大的项目，但如果负载过重，它将无法为您提供任何价值。此外，保持 Sentry 准备好应对灾难性故障场景，其中可能会发送数千个崩溃报告，是一个真正的挑战。因此，您必须决定哪个选项对您来说真正更便宜，以及您是否有足够的资源和智慧来自己完成所有这些。当然，如果您的组织的安全政策禁止向第三方发送任何数据，那么就在自己的基础设施上托管它。当然会有成本，但这绝对是值得支付的成本。

## 监控系统和应用程序指标

在监控性能方面，可供选择的工具数量可能令人不知所措。如果您期望很高，那么可能需要同时使用其中的几个。

Munin（[`munin-monitoring.org`](http://munin-monitoring.org)）是许多组织使用的热门选择之一，无论它们使用什么技术栈。它是一个很好的工具，用于分析资源趋势，并且即使在默认安装时也提供了许多有用的信息，而无需额外配置。它的安装包括两个主要组件：

+   Munin 主机从其他节点收集指标并提供指标图

+   Munin 节点安装在受监视的主机上，它收集本地指标并将其发送到 Munin 主机

主机、节点和大多数插件都是用 Perl 编写的。还有其他语言的节点实现：`munin-node-c`是用 C 编写的（[`github.com/munin-monitoring/munin-c`](https://github.com/munin-monitoring/munin-c)），`munin-node-python`是用 Python 编写的（[`github.com/agroszer/munin-node-python`](https://github.com/agroszer/munin-node-python)）。Munin 附带了大量插件，可在其`contrib`存储库中使用。这意味着它提供了对大多数流行的数据库和系统服务的开箱即用支持。甚至还有用于监视流行的 Python Web 服务器（如 uWSGI 和 Gunicorn）的插件。

Munin 的主要缺点是它将图形呈现为静态图像，并且实际的绘图配置包含在特定插件配置中。这并不利于创建灵活的监控仪表板，并在同一图表中比较来自不同来源的度量值。但这是我们为简单安装和多功能性所付出的代价。编写自己的插件非常简单。有一个`munin-python`包（[`python-munin.readthedocs.org/en/latest/`](http://python-munin.readthedocs.org/en/latest/)），它可以帮助用 Python 编写 Munin 插件。

很遗憾，Munin 的架构假设每个主机上都有一个单独的监控守护进程负责收集指标，这可能不是监控自定义应用程序性能指标的最佳解决方案。编写自己的 Munin 插件确实非常容易，但前提是监控进程已经以某种方式报告其性能统计数据。如果您想收集一些自定义应用程序级别的指标，可能需要将它们聚合并存储在某些临时存储中，直到报告给自定义的 Munin 插件。这使得创建自定义指标变得更加复杂，因此您可能需要考虑其他解决方案。

另一个特别容易收集自定义指标的流行解决方案是 StatsD（[`github.com/etsy/statsd`](https://github.com/etsy/statsd)）。它是一个用 Node.js 编写的网络守护程序，监听各种统计数据，如计数器、计时器和量规。由于基于 UDP 的简单协议，它非常容易集成。还可以使用名为`statsd`的 Python 包将指标发送到 StatsD 守护程序：

```py
>>> import statsd
>>> c = statsd.StatsClient('localhost', 8125)
>>> c.incr('foo')  # Increment the 'foo' counter.
>>> c.timing('stats.timed', 320)  # Record a 320ms 'stats.timed'.

```

由于 UDP 是无连接的，它对应用程序代码的性能开销非常低，因此非常适合跟踪和测量应用程序代码内的自定义事件。

不幸的是，StatsD 是唯一的指标收集守护程序，因此它不提供任何报告功能。您需要其他进程能够处理来自 StatsD 的数据，以查看实际的指标图。最受欢迎的选择是 Graphite（[`graphite.readthedocs.org`](http://graphite.readthedocs.org)）。它主要做两件事：

+   存储数字时间序列数据

+   根据需要呈现此数据的图形

Graphite 提供了保存高度可定制的图形预设的功能。您还可以将许多图形分组到主题仪表板中。与 Munin 类似，图形呈现为静态图像，但还有 JSON API 允许其他前端读取图形数据并以其他方式呈现。与 Graphite 集成的一个很棒的仪表板插件是 Grafana（[`grafana.org`](http://grafana.org)）。它真的值得一试，因为它比普通的 Graphite 仪表板具有更好的可用性。Grafana 提供的图形是完全交互式的，更容易管理。

不幸的是，Graphite 是一个有点复杂的项目。它不是一个单一的服务，而是由三个独立的组件组成：

+   **Carbon**：这是一个使用 Twisted 编写的守护程序，用于监听时间序列数据

+   **whisper**：这是一个简单的数据库库，用于存储时间序列数据

+   **graphite webapp**：这是一个 Django Web 应用程序，根据需要呈现静态图像（使用 Cairo 库）或 JSON 数据

当与 StatsD 项目一起使用时，`statsd`守护程序将其数据发送到`carbon`守护程序。这使得整个解决方案成为一个相当复杂的各种应用程序堆栈，每个应用程序都是使用完全不同的技术编写的。此外，没有预配置的图形、插件和仪表板可用，因此您需要自己配置所有内容。这在开始时需要很多工作，很容易忽略一些重要的东西。这就是为什么即使决定将 Graphite 作为核心监控服务，使用 Munin 作为监控备份也可能是一个好主意。

## 处理应用程序日志

虽然像 Sentry 这样的解决方案通常比存储在文件中的普通文本输出更强大，但日志永远不会消失。向标准输出或文件写入一些信息是应用程序可以做的最简单的事情之一，这绝对不应被低估。有可能 raven 发送到 Sentry 的消息不会被传递。网络可能会失败。Sentry 的存储可能会耗尽，或者可能无法处理传入的负载。在任何消息被发送之前，您的应用程序可能会崩溃（例如，出现分段错误）。这只是可能的情况之一。不太可能的是您的应用程序无法记录将要写入文件系统的消息。这仍然是可能的，但让我们诚实一点。如果您面临日志记录失败的情况，可能您有更多紧迫的问题，而不仅仅是一些丢失的日志消息。

记住，日志不仅仅是关于错误。许多开发人员过去认为日志只是在调试问题时有用的数据来源，或者可以用来进行某种取证。肯定有更少的人尝试将其用作生成应用程序指标的来源或进行一些统计分析。但是日志可能比这更有用。它们甚至可以成为产品实现的核心。一个很好的例子是亚马逊的一篇文章，介绍了一个实时竞价服务的示例架构，其中一切都围绕访问日志收集和处理。请参阅[`aws.amazon.com/blogs/aws/real-time-ad-impression-bids-using-dynamodb/`](https://aws.amazon.com/blogs/aws/real-time-ad-impression-bids-using-dynamodb/)。

### 基本的低级日志实践

十二要素应用程序表示日志应被视为事件流。因此，日志文件本身并不是日志，而只是一种输出格式。它们是流的事实意味着它们代表按时间顺序排列的事件。在原始状态下，它们通常以文本格式呈现，每个事件一行，尽管在某些情况下它们可能跨越多行。这对于与运行时错误相关的任何回溯都是典型的。

根据十二要素应用程序方法论，应用程序不应知道日志存储的格式。这意味着写入文件，或者日志轮换和保留不应由应用程序代码维护。这些是应用程序运行的环境的责任。这可能令人困惑，因为许多框架提供了用于管理日志文件以及轮换、压缩和保留实用程序的函数和类。诱人的是使用它们，因为一切都可以包含在应用程序代码库中，但实际上这是一个应该真正避免的反模式。

处理日志的最佳约定可以归结为几条规则：

+   应用程序应始终将日志无缓冲地写入标准输出（`stdout`）

+   执行环境应负责将日志收集和路由到最终目的地

所提到的执行环境的主要部分通常是某种进程监控工具。流行的 Python 解决方案，如 Supervisor 或 Circus，是处理日志收集和路由的第一责任方。如果日志要存储在本地文件系统中，那么只有它们应该写入实际的日志文件。

Supervisor 和 Circus 也能够处理受管进程的日志轮换和保留，但您确实应该考虑是否要走这条路。成功的操作大多是关于简单性和一致性。您自己应用程序的日志可能不是您想要处理和存档的唯一日志。如果您使用 Apache 或 Nginx 作为反向代理，您可能希望收集它们的访问日志。您可能还希望存储和处理缓存和数据库的日志。如果您正在运行一些流行的 Linux 发行版，那么每个这些服务都有它们自己的日志文件被名为`logrotate`的流行实用程序处理（轮换、压缩等）。我强烈建议您忘记 Supervisor 和 Circus 的日志轮换能力，以便与其他系统服务保持一致。`logrotate`更加可配置，还支持压缩。

### 提示

**logrotate 和 Supervisor/Circus**

在使用`logrotate`与 Supervisor 或 Circus 时，有一件重要的事情需要知道。日志的轮换将始终发生在 Supervisor 仍然具有对已轮换日志的打开描述符时。如果您不采取适当的对策，那么新事件仍将被写入已被`logrotate`删除的文件描述符。结果，文件系统中将不再存储任何内容。解决这个问题的方法非常简单。使用`copytruncate`选项为 Supervisor 或 Circus 管理的进程的日志文件配置`logrotate`。在旋转后，它将复制日志文件并在原地将原始文件截断为零大小。这种方法不会使任何现有的文件描述符无效，已经运行的进程可以不间断地写入日志文件。Supervisor 还可以接受`SIGUSR2`信号，这将使其重新打开所有文件描述符。它可以作为`logrotate`配置中的`postrotate`脚本包含在内。这种第二种方法在 I/O 操作方面更经济，但也更不可靠，更难维护。

### 日志处理工具

如果您没有处理大量日志的经验，那么当使用具有实质负载的产品时，您最终会获得这种经验。您很快会注意到，基于将它们存储在文件中并在某些持久存储中备份的简单方法是不够的。没有适当的工具，这将变得粗糙和昂贵。像`logrotate`这样的简单实用程序只能确保硬盘不会被不断增加的新事件所溢出，但是拆分和压缩日志文件只有在数据归档过程中才有帮助，但并不会使数据检索或分析变得更简单。

在处理跨多个节点的分布式系统时，很好地拥有一个单一的中心点，从中可以检索和分析所有日志。这需要一个远远超出简单压缩和备份的日志处理流程。幸运的是，这是一个众所周知的问题，因此有许多可用的工具旨在解决它。

许多开发人员中的一个受欢迎的选择是**Logstash**。这是一个日志收集守护程序，可以观察活动日志文件，解析日志条目并以结构化形式将它们发送到后端服务。后端的选择几乎总是相同的——**Elasticsearch**。Elasticsearch 是建立在 Lucene 之上的搜索引擎。除了文本搜索功能外，它还具有一个独特的数据聚合框架，非常适合用于日志分析的目的。

这对工具的另一个补充是**Kibana**。它是一个非常多才多艺的监控、分析和可视化平台，适用于 Elasticsearch。这三种工具如何相互补充的方式，是它们几乎总是作为单一堆栈一起用于日志处理的原因。

现有服务与 Logstash 的集成非常简单，因为它可以监听现有日志文件的更改，以便通过最小的日志配置更改获取新事件。它以文本形式解析日志，并且预先配置了对一些流行日志格式（如 Apache/Nginx 访问日志）的支持。Logstash 唯一的问题是它不能很好地处理日志轮换，这有点令人惊讶。通过发送已定义的 Unix 信号（通常是`SIGHUP`或`SIGUSR1`）来强制进程重新打开其文件描述符是一个非常成熟的模式。似乎每个处理日志的应用程序都应该知道这一点，并且能够处理各种日志文件轮换场景。遗憾的是，Logstash 不是其中之一，因此如果您想使用`logrotate`实用程序管理日志保留，请记住要大量依赖其`copytruncate`选项。Logstash 进程无法处理原始日志文件被移动或删除的情况，因此在没有`copytruncate`选项的情况下，它将无法在日志轮换后接收新事件。当然，Logstash 可以处理不同的日志流输入，例如 UDP 数据包、TCP 连接或 HTTP 请求。

另一个似乎填补了一些 Logstash 空白的解决方案是 Fluentd。它是一种替代的日志收集守护程序，可以与 Logstash 在提到的日志监控堆栈中互换使用。它还有一个选项，可以直接监听和解析日志事件，所以最小的集成只需要一点点努力。与 Logstash 相比，它处理重新加载非常出色，甚至在日志文件轮换时也不需要信号。无论如何，最大的优势来自于使用其替代的日志收集选项，这将需要对应用程序中的日志配置进行一些重大更改。

Fluentd 真的将日志视为事件流（正如《十二要素应用程序》所推荐的）。基于文件的集成仍然是可能的，但它只是对将日志主要视为文件的传统应用程序的向后兼容性。每个日志条目都是一个事件，应该是结构化的。Fluentd 可以解析文本日志，并具有多个插件选项来处理：

+   常见格式（Apache、Nginx 和 syslog）

+   使用正则表达式指定的任意格式，或者使用自定义解析插件处理

+   结构化消息的通用格式，例如 JSON

Fluentd 的最佳事件格式是 JSON，因为它增加的开销最少。 JSON 中的消息也可以几乎不经过任何更改地传递到 Elasticsearch 或数据库等后端服务。

Fluentd 的另一个非常有用的功能是能够使用除了写入磁盘的日志文件之外的其他传输方式传递事件流。最值得注意的内置输入插件有：

+   `in_udp`：使用此插件，每个日志事件都作为 UDP 数据包发送

+   `in_tcp`：使用此插件，事件通过 TCP 连接发送

+   `in_unix`：使用此插件，事件通过 Unix 域套接字（命名套接字）发送

+   `in_http`：使用此插件，事件作为 HTTP POST 请求发送

+   `in_exec`：使用此插件，Fluentd 进程会定期执行外部命令，以 JSON 或 MessagePack 格式获取事件

+   `in_tail`：使用此插件，Fluentd 进程会监听文本文件中的事件

对于日志事件的替代传输可能在需要处理机器存储的 I/O 性能较差的情况下特别有用。在云计算服务中，通常默认磁盘存储的 IOPS（每秒输入/输出操作次数）非常低，您需要花费大量资金以获得更好的磁盘性能。如果您的应用程序输出大量日志消息，即使数据量不是很大，也可能轻松饱和您的 I/O 能力。通过替代传输，您可以更有效地使用硬件，因为您只需将数据缓冲的责任留给单个进程——日志收集器。当配置为在内存中缓冲消息而不是磁盘时，甚至可以完全摆脱日志的磁盘写入，尽管这可能会大大降低收集日志的一致性保证。

使用不同的传输方式似乎略微违反了十二要素应用程序方法的第 11 条规则。详细解释时，将日志视为事件流表明应用程序应始终仅通过单个标准输出流（`stdout`）记录日志。仍然可以在不违反此规则的情况下使用替代传输方式。写入`stdout`并不一定意味着必须将此流写入文件。您可以保留应用程序以这种方式记录日志，并使用外部进程将其捕获并直接传递给 Logstash 或 Fluentd，而无需涉及文件系统。这是一种高级模式，可能并不适用于每个项目。它具有更高复杂性的明显缺点，因此您需要自行考虑是否真的值得这样做。

# 总结

代码部署并不是一个简单的话题，阅读本章后您应该已经知道这一点。对这个问题的广泛讨论很容易占据几本书。即使我们的范围仅限于 Web 应用程序，我们也只是触及了表面。本章以十二要素应用程序方法为基础。我们只详细讨论了其中的一些内容：日志处理、管理依赖关系和分离构建/运行阶段。

阅读本章后，您应该知道如何正确自动化部署过程，考虑最佳实践，并能够为在远程主机上运行的代码添加适当的仪器和监视。
