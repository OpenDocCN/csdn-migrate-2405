# 精通 Django（一）

> 原文：[`zh.annas-archive.org/md5/0D7AA9BDBF4A402F69CD832FB5D17FA6`](https://zh.annas-archive.org/md5/0D7AA9BDBF4A402F69CD832FB5D17FA6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

# 您需要为本书做好准备

**所需的编程知识**

本书的读者应该了解过程化和面向对象编程的基础知识：控制结构（如 if、while 或 for）、数据结构（列表、哈希/字典）、变量、类和对象。网页开发经验，正如您可能期望的那样，非常有帮助，但不是阅读本书的必要条件。在整本书中，我试图为缺乏这方面经验的读者推广网页开发的最佳实践。

**所需的 Python 知识**

在其核心，Django 只是用 Python 编写的一组库。要使用 Django 开发网站，您需要编写使用这些库的 Python 代码。因此，学习 Django 实际上就是学习如何在 Python 中编程以及理解 Django 库的工作原理。如果您有 Python 编程经验，那么您应该可以轻松上手。总的来说，Django 代码并不执行很多*魔术*（即，编程技巧，其实现很难解释或理解）。对您来说，学习 Django 将是学习 Django 的惯例和 API 的问题。

如果您没有 Python 编程经验，您将会有所收获。它很容易学习，也很愉快使用！尽管本书不包括完整的 Python 教程，但它会在适当的时候突出 Python 的特性和功能，特别是当代码不立即让人明白时。不过，我建议您阅读官方的 Python 教程（有关更多信息，请访问[`docs.python.org/tut/`](http://docs.python.org/tut/)）。我还推荐 Mark Pilgrim 的免费书籍*Dive Into Python*，可在线获取[`www.diveintopython.net/`](http://www.diveintopython.net/)，并由 Apress 出版。

**所需的 Django 版本**

本书涵盖 Django 1.8 LTS。这是 Django 的长期支持版本，将至少在 2018 年 4 月之前得到全面支持。

如果您使用的是 Django 的早期版本，建议您升级到最新版本的 Django 1.8 LTS。在印刷时（2016 年 7 月），Django 1.8 LTS 的最新生产版本是 1.8.13。

如果您安装了 Django 的较新版本，请注意，尽管 Django 的开发人员尽可能保持向后兼容性，但偶尔会引入一些向后不兼容的更改。每个版本的更改都总是在发布说明中进行了解，您可以在[`docs.djangoproject.com/en/dev/releases/`](https://docs.djangoproject.com/en/dev/releases)找到。

有任何疑问，请访问：[`masteringdjango.com`](http://masteringdjango.com)。

# 这本书是为谁准备的

本书假设您对互联网和编程有基本的了解。有 Python 或 Django 的经验会是一个优势，但不是必需的。这本书非常适合初学者和中级程序员，他们正在寻找一个快速、安全、可扩展和可维护的替代网页开发平台，而不是基于 PHP、Java 和 dotNET 的平台。

# 惯例

在本书中，您会发现一些区分不同信息类型的文本样式。以下是一些这些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“在命令提示符（或在`Applications/Utilities/Terminal`中，OS X 中）键入`python`。”

代码块设置如下：

```py
from django.http import HttpResponse
def hello(request):
return HttpResponse("Hello world")
```

任何命令行输入或输出都以以下方式编写：

```py
Python 2.7.5 (default, June 27 2015, 13:20:20)
[GCC x.x.x] on xxx
Type "help", "copyright", "credits" or "license" for more information.
>>>

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这样的方式显示在文本中：“您应该看到文本**Hello world**-这是您的 Django 视图的输出（图 2-1）。”

### 注意

警告或重要说明会以这样的方式显示在框中。

### 提示

提示和技巧是这样显示的。


# 第一章：Django 简介和入门

# 介绍 Django

几乎所有优秀的开源软件都是因为一个或多个聪明的开发人员有问题需要解决，而没有可行或成本效益的解决方案。Django 也不例外。Adrian 和 Jacob 早已从项目中*退休*，但是驱使他们创建 Django 的基本原因仍然存在。正是这种扎实的实际经验基础使 Django 如此成功。为了表彰他们的贡献，我认为最好让他们用自己的话（从原书中编辑和重新格式化）介绍 Django。

*Adrian Holovaty 和 Jacob Kaplan-Moss-2009 年 12 月*

在早期，网页开发人员手工编写每个页面。更新网站意味着编辑 HTML；*重新设计*涉及逐个重新制作每个页面。随着网站的增长和变得更加雄心勃勃，很快就显而易见，这种方法是乏味、耗时且最终是不可持续的。

**国家超级计算应用中心**（**NCSA**，开发了第一个图形化网页浏览器 Mosaic 的地方）的一群有进取心的黑客解决了这个问题，让 Web 服务器生成可以动态生成 HTML 的外部程序。他们称这个协议为**通用网关接口**（**CGI**），它彻底改变了 Web。现在很难想象 CGI 必须是多么大的突破：CGI 允许你将 HTML 页面视为根据需要动态生成的资源，而不是简单的磁盘文件。

CGI 的发展开创了动态网站的第一代。然而，CGI 也有它的问题：CGI 脚本需要包含大量重复的**样板**代码，它们使代码重用变得困难，对于初学者来说编写和理解也很困难。

PHP 解决了许多这些问题，并风靡全球——它现在是用于创建动态网站的最流行工具，并且有数十种类似的语言（如 ASP、JSP 等）都紧随 PHP 的设计。PHP 的主要创新在于它的易用性：PHP 代码简单地嵌入到普通 HTML 中；对于已经了解 HTML 的人来说，学习曲线极其浅。

但是 PHP 也有自己的问题；它非常容易使用，鼓励编写松散、重复、考虑不周的代码。更糟糕的是，PHP 几乎没有保护程序员免受安全漏洞的影响，因此许多 PHP 开发人员发现自己只有在为时已晚时才学习安全知识。

这些和类似的挫折直接导致了当前一批*第三代*Web 开发框架的发展。随着这一新的 Web 开发潮流的兴起，人们对 Web 开发人员的期望也在不断增加。

Django 的发展是为了满足这些新的期望。

## Django 的历史

Django 是在美国堪萨斯州劳伦斯的 Web 开发团队编写的真实应用程序的基础上有机地发展起来的。它诞生于 2003 年秋天，当时《劳伦斯日报》报纸的 Web 程序员 Adrian Holovaty 和 Simon Willison 开始使用 Python 构建应用程序。

负责制作和维护几个本地新闻网站的 World Online 团队在由新闻截止日期决定的开发环境中蓬勃发展。对于包括 LJWorld.com、Lawrence.com 和 KUsports.com 在内的网站，记者（和管理层）要求在非常紧迫的时间表下添加功能和构建整个应用程序，通常只有一天或一小时的通知时间。因此，Simon 和 Adrian 出于必要性开发了一个节省时间的 Web 开发框架——这是他们在极端截止日期下构建可维护应用程序的唯一方法。

在 2005 年夏天，经过将这个框架开发到能够有效地为 World Online 的大部分网站提供动力的程度后，包括 Jacob Kaplan-Moss 在内的团队决定将该框架作为开源软件发布。他们于 2005 年 7 月发布了它，并将其命名为 Django，以纪念爵士吉他手 Django Reinhardt。

这段历史很重要，因为它有助于解释两个关键问题。首先是 Django 的“甜蜜点”。因为 Django 诞生于新闻环境中，它提供了一些功能（比如它的管理站点，在第五章中介绍的*The* * Django * Admin * Site*），特别适合像[Amazon.com](http://www.amazon.com)、[craigslist.org](http://www.craigslist.org)和[washingtonpost.com](http://www.washingtonpost.com)这样提供动态和数据库驱动信息的“内容”网站。

不要让这使你失去兴趣，尽管 Django 特别适合开发这类网站，但这并不排除它成为构建任何类型动态网站的有效工具。（在某些方面特别有效和在其他方面无效之间存在区别。）

第二个需要注意的事情是 Django 的起源如何塑造了其开源社区的文化。因为 Django 是从现实世界的代码中提取出来的，而不是学术练习或商业产品，它专注于解决 Django 开发人员自己曾经面对过的问题，而且仍在面对。因此，Django 本身几乎每天都在积极改进。该框架的维护者有兴趣确保 Django 节省开发人员的时间，生成易于维护并在负载下表现良好的应用程序。

Django 可以让您在极短的时间内构建深度、动态、有趣的网站。Django 旨在让您专注于工作中有趣的部分，同时减轻重复部分的痛苦。通过这样做，它提供了常见 Web 开发模式的高级抽象，频繁编程任务的快捷方式，并明确了解决问题的约定。与此同时，Django 试图不干扰您的工作，让您根据需要在框架范围之外工作。

我们写这本书是因为我们坚信 Django 可以使 Web 开发变得更好。它旨在快速让您开始自己的 Django 项目，然后最终教会您成功设计、开发和部署一个令您自豪的网站所需的一切知识。

入门

要开始使用 Django，您需要做两件非常重要的事情：

1.  安装 Django（显然）；和

1.  深入了解**模型-视图-控制器**（**MVC**）设计模式。

首先，安装 Django 非常简单，并且在本章的第一部分中有详细介绍。其次同样重要，特别是如果您是新程序员或者从使用不清晰地将网站的数据和逻辑与其显示方式分离的编程语言转换而来。Django 的理念基于*松耦合*，这是 MVC 的基本理念。随着我们的学习，我们将更详细地讨论松耦合和 MVC，但如果您对 MVC 了解不多，最好不要跳过本章的后半部分，因为了解 MVC 将使理解 Django 变得更加容易。

## 安装 Django

在学习如何使用 Django 之前，您必须先在计算机上安装一些软件。幸运的是，这是一个简单的三个步骤过程：

1.  安装 Python。

1.  安装 Python 虚拟环境。

1.  安装 Django。

如果这对您来说不熟悉，不用担心，在本章中，让我们假设您以前从未从命令行安装过软件，并将逐步引导您完成。

我为那些使用 Windows 的人编写了这一部分。虽然 Django 在*nix 和 OSX 用户群体中有很强的基础，但大多数新用户都在 Windows 上。如果您使用 Mac 或 Linux，互联网上有大量资源；最好的起点是 Django 自己的安装说明。有关更多信息，请访问[`docs.djangoproject.com/en/1.8/topics/install/`](https://docs.djangoproject.com/en/1.8/topics/install/)。

对于 Windows 用户，您的计算机可以运行任何最近的 Windows 版本（Vista，7，8.1 或 10）。本章还假设您正在桌面或笔记本电脑上安装 Django，并将使用开发服务器和 SQLite 来运行本书中的所有示例代码。这绝对是您刚开始时设置 Django 的最简单和最好的方法。

如果您确实想要进行更高级的 Django 安装，您的选项在第十三章*，部署 Django*，第二十章*，更多关于安装 Django*和第二十一章*，高级数据库管理*中都有涵盖。

### 注意

如果您使用的是 Windows，我建议您尝试使用 Visual Studio 进行所有 Django 开发。微软已经在为 Python 和 Django 程序员提供支持方面进行了重大投资。这包括对 Python/Django 的完整 IntelliSense 支持，并将 Django 的所有命令行工具整合到 VS IDE 中。

最重要的是，这完全免费。我知道，谁会想到 M$会提供免费服务？？但这是真的！

有关 Visual Studio Community 2015 的完整安装指南，请参阅附录 G*，使用 Visual Studio 开发 Django*，以及在 Windows 中开发 Django 的一些建议。

## 安装 Python

Django 本身纯粹是用 Python 编写的，因此安装框架的第一步是确保您已安装 Python。

### Python 版本

Django 1.8 LTS 版本与 Python 2.7、3.3、3.4 和 3.5 兼容。对于每个 Python 版本，只支持最新的微版本（A.B.C）。

如果您只是试用 Django，无论您使用 Python 2 还是 Python 3 都无所谓。但是，如果您打算最终将代码部署到实时网站，Python 3 应该是您的首选。Python 维基（有关更多信息，请访问[`wiki.python.org/moin/Python2orPython3`](https://wiki.python.org/moin/Python2orPython3)）非常简洁地解释了这背后的原因：

> *简短版本：Python 2.x 是遗留版本，Python 3.x 是语言的现在和未来*

除非您有非常好的理由使用 Python 2（例如，遗留库），否则 Python 3 是最佳选择。

### 提示

注意：本书中的所有代码示例都是用 Python 3 编写的

### 安装

如果您使用的是 Linux 或 Mac OS X，您可能已经安装了 Python。在命令提示符（或在 OS X 中的`Applications/Utilities/Terminal`）中输入`python`。如果看到类似以下内容，则表示已安装 Python：

```py
Python 2.7.5 (default, June 27 2015, 13:20:20)
[GCC x.x.x] on xxx
Type "help", "copyright", "credits" or "license" for more 
    information.

```

### 注意

您可以看到，在前面的示例中，Python 交互模式正在运行 Python 2.7。这是对经验不足的用户的陷阱。在 Linux 和 Mac OS X 机器上，通常会安装 Python 2 和 Python 3。如果您的系统是这样的，您需要在所有命令前面输入`python3`，而不是 python 来运行 Python 3 的 Django。

假设您的系统尚未安装 Python，我们首先需要获取安装程序。转到[`www.python.org/downloads/`](https://www.python.org/downloads/)，并单击大黄色按钮，上面写着**下载 Python 3.x.x**。

在撰写本文时，最新版本的 Python 是 3.5.1，但在您阅读本文时可能已经更新，因此数字可能略有不同。

**不要**下载 2.7.x 版本，因为这是 Python 的旧版本。本书中的所有代码都是用 Python 3 编写的，因此如果尝试在 Python 2 上运行代码，将会出现编译错误。

下载 Python 安装程序后，转到您的`Downloads`文件夹，双击文件`python-3.x.x.msi`运行安装程序。安装过程与任何其他 Windows 程序相同，因此如果您之前安装过软件，这里应该没有问题，但是，有一个非常重要的自定义您必须进行。

### 注意

不要忘记下一步，因为它将解决由于在 Windows 中不正确映射`pythonpath`（Python 安装的重要变量）而引起的大多数问题。

默认情况下，Python 可执行文件不会添加到 Windows PATH 语句中。为了使 Django 正常工作，Python 必须在 PATH 语句中列出。幸运的是，这很容易纠正：

+   在 Python 3.4.x 中，当安装程序打开自定义窗口时，选项**将 python.exe 添加到 Path**未被选中，您必须将其更改为**将安装在本地硬盘上**，如*图 1.1*所示。![安装](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_01_001.jpg)

图 1.1：将 Python 添加到 PATH（版本 3.4.x）。

+   在 Python 3.5.x 中，确保在安装之前选中**将 Python 3.5 添加到 PATH**（*图 1.2*）。![安装](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_01_002.jpg)

图 1.2：将 Python 添加到 PATH（版本 3.5.x）。

安装 Python 后，您应该能够重新打开命令窗口并在命令提示符下键入 python，然后会得到类似于这样的输出：

```py
Python 3.5.1 (v3.5.1:37a07cee5969, Dec  6 2015, 01:38:48) 
    [MSC v.1900 32 bit (Intel)] on win32
Type "help", "copyright", "credits" or "license" for more 
    information.
>>>

```

在此期间，还有一件重要的事情要做。使用*CTRL*+*C*退出 Python。在命令提示符下键入以下内容并按 Enter：

```py
python-m pip install-U pip

```

输出将类似于这样：

```py
C:\Users\nigel>python -m pip install -U pip
Collecting pip
 Downloading pip-8.1.2-py2.py3-none-any.whl (1.2MB)
 100% |################################| 1.2MB 198kB/s
Installing collected packages: pip
Found existing installation: pip 7.1.2
Uninstalling pip-7.1.2:
Successfully uninstalled pip-7.1.2
Successfully installed pip-8.1.2

```

您现在不需要完全了解这个命令的作用；简而言之，`pip`是 Python 软件包管理器。它用于安装 Python 软件包：`pip`实际上是 Pip Installs Packages 的递归缩写。Pip 对我们安装过程的下一阶段非常重要，但首先，我们需要确保我们正在运行最新版本的 pip（在撰写本文时为 8.1.2），这正是这个命令所做的。

## 安装 Python 虚拟环境

### 注意

如果您要使用 Microsoft Visual Studio（VS），您可以在这里停下来并跳转到附录 G，*使用 Visual Studio 开发 Django*。VS 只需要您安装 Python，其他所有操作都可以在集成开发环境（IDE）内完成。

计算机上的所有软件都是相互依存的 - 每个程序都有其他软件依赖的软件部分（称为**依赖项**）和需要找到文件和其他软件运行所需的设置（称为**环境变量**）。

当您编写新的软件程序时，可能（并且经常）会修改其他软件依赖的依赖项和环境变量。这可能会导致许多问题，因此应该避免。

Python 虚拟环境通过将新软件所需的所有依赖项和环境变量包装到与计算机上其余软件分开的文件系统中来解决此问题。

### 注意

一些查看其他教程的人可能会注意到，这一步通常被描述为可选的。这不是我支持的观点，也不是一些 Django 核心开发人员支持的观点。

### 注意

在虚拟环境中开发 Python 应用程序（其中包括 Django）的优势是显而易见的，这里不值得一提。作为初学者，您只需要相信我 - 运行 Django 开发的虚拟环境是不可选的。

Python 中的虚拟环境工具称为`virtualenv`，我们使用`pip`从命令行安装它：

```py
pip install virtualenv

```

您的命令窗口的输出应该类似于这样：

```py
C:\Users\nigel>pip install virtualenv
 Collecting virtualenv
 Downloading virtualenv-15.0.2-py2.py3-none-any.whl (1.8MB)
100% |################################| 1.8MB 323kB/s
Installing collected packages: virtualenv
Successfully installed virtualenv-15.0.2

```

一旦安装了`virtualenv`，您需要通过输入以下命令为您的项目创建一个虚拟环境：

```py
virtualenv env_mysite

```

### 注意

互联网上的大多数示例使用`env`作为您的环境名称。这是不好的；主要是因为通常会安装几个虚拟环境来测试不同的配置，而`env`并不是非常描述性的。例如，您可能正在开发一个必须在 Python 2.7 和 Python 3.4 上运行的应用程序。命名为`env_someapp_python27`和`env_someapp_python34`的环境将比如果您将它们命名为`env`和`env1`更容易区分。

在这个例子中，我保持了简单，因为我们只会使用一个虚拟环境来进行我们的项目，所以我使用了`env_mysite`。您的命令的输出应该看起来像这样：

```py
C:\Users\nigel>virtualenv env_mysite
Using base prefix 
 'c:\\users\\nigel\\appdata\\local\\programs\\python\\python35-32'
New python executable in 
    C:\Users\nigel\env_mysite\Scripts\python.exe
Installing setuptools, pip, wheel...done.

```

一旦`virtualenv`完成设置新虚拟环境的工作，打开 Windows 资源管理器，看看`virtualenv`为您创建了什么。在您的主目录中，现在会看到一个名为`\env_mysite`的文件夹（或者您给虚拟环境的任何名称）。如果您打开文件夹，您会看到以下内容：

```py
\Include 
\Lib 
\Scripts 
\src 

```

`virtualenv`为您创建了一个完整的 Python 安装，与您的其他软件分开，因此您可以在不影响系统上的任何其他软件的情况下工作。

要使用这个新的 Python 虚拟环境，我们必须激活它，所以让我们回到命令提示符并输入以下内容：

```py
 env_mysite\scripts\activate

```

这将在您的虚拟环境的`\scripts`文件夹中运行激活脚本。您会注意到您的命令提示现在已经改变：

```py
 (env_mysite) C:\Users\nigel>

```

命令提示符开头的`(env_mysite)`让您知道您正在虚拟环境中运行。我们的下一步是安装 Django。

## 安装 Django

既然我们已经安装了 Python 并运行了一个虚拟环境，安装 Django 就非常容易了，只需输入以下命令：

```py
 pip install django==1.8.13

```

这将指示 pip 将 Django 安装到您的虚拟环境中。您的命令输出应该如下所示：

```py
 (env_mysite) C:\Users\nigel>pip install django==1.8.13
 Collecting django==1.8.13
 Downloading Django-1.8.13-py2.py3-none-any.whl (6.2MB)
 100% |################################| 6.2MB 107kB/s
 Installing collected packages: django
 Successfully installed django-1.8.13

```

在这种情况下，我们明确告诉 pip 安装 Django 1.8.13，这是撰写本文时 Django 1.8 LTS 的最新版本。如果要安装 Django，最好查看 Django 项目网站以获取 Django 1.8 LTS 的最新版本。

### 注意

如果您想知道，输入`pip install django`将安装 Django 的最新稳定版本。如果您想获取有关安装 Django 最新开发版本的信息，请参阅第二十章, *更多* * 关于安装 * *Django*。

为了获得一些安装后的积极反馈，请花点时间测试安装是否成功。在您的虚拟环境命令提示符下，输入`python`并按回车键启动 Python 交互解释器。如果安装成功，您应该能够导入模块`django`：

```py
 (env_mysite) C:\Users\nigel>python
 Python 3.5.1 (v3.5.1:37a07cee5969, Dec  6 2015, 01:38:48) 
 [MSC v.1900 32 bit (Intel)] on win32
 Type "help", "copyright", "credits" or "license" for more 
    information.
 >>> import django
 >>> django.get_version()
 1.8.13'

```

## 设置数据库

这一步并不是为了完成本书中的任何示例而必需的。Django 默认安装了 SQLite。SQLite 无需您进行任何配置。如果您想使用像 PostgreSQL、MySQL 或 Oracle 这样的大型数据库引擎，请参阅第二十一章, *高级数据库管理*。

## 开始一个项目

一旦安装了 Python、Django 和（可选）数据库`server/library`，您可以通过创建一个*项目*来开始开发 Django 应用程序。

项目是 Django 实例的一组设置。如果这是您第一次使用 Django，您需要进行一些初始设置。换句话说，您需要自动生成一些代码来建立一个 Django 项目：Django 实例的一组设置，包括数据库配置、Django 特定选项和应用程序特定设置。

我假设在这个阶段，您仍然在运行上一个安装步骤中的虚拟环境。如果没有，您将不得不重新开始：

```py
 env_mysite\scripts\activate\

```

从您的虚拟环境命令行中，运行以下命令：

```py
 django-admin startproject mysite

```

这将在当前目录（在本例中为`\env_mysite\`）中创建一个`mysite`目录。如果您想要在根目录之外的其他目录中创建项目，您可以创建一个新目录，切换到该目录并从那里运行`startproject`命令。

### 注意

**警告！**

您需要避免将项目命名为内置的 Python 或 Django 组件。特别是，这意味着您应该避免使用诸如"django"（这将与 Django 本身冲突）或"test"（这与内置的 Python 包冲突）等名称。

让我们看看`startproject`创建了什么：

```py
mysite/ 
  manage.py 
  mysite/ 
    __init__.py 
    settings.py 
    urls.py 
    wsgi.py 

```

这些文件是：

+   外部的`mysite/`根目录。这只是您项目的一个容器。对 Django 来说，它的名称并不重要；您可以将其重命名为任何您喜欢的名称。

+   `manage.py`，一个命令行实用程序，让您以各种方式与您的 Django 项目进行交互。您可以在 Django 项目网站上阅读有关`manage.py`的所有详细信息（有关更多信息，请访问[`docs.djangoproject.com/en/1.8/ref/django-admin/`](https://docs.djangoproject.com/en/1.8/ref/django-admin/)）。

+   内部的`mysite/`目录。这是您项目的 Python 包。这是您用来导入其中任何内容的名称（例如，`mysite.urls`）。

+   `mysite/__init__.py`，一个空文件，告诉 Python 这个目录应该被视为 Python 包。 （如果你是 Python 初学者，请阅读官方 Python 文档中关于包的更多信息[`docs.python.org/tutorial/modules.html#packages`](https://docs.python.org/tutorial/modules.html#packages)。）

+   `mysite/settings.py`，这个 Django 项目的设置/配置。附录 D*设置*将告诉您有关设置如何工作的所有信息。

+   `mysite/urls.py`，这个 Django 项目的 URL 声明；你的 Django 网站的目录。您可以在第二章*视图和 URLconfs*和第七章*高级视图和 URLconfs*中了解更多关于 URL 的信息。

+   `mysite/wsgi.py`，WSGI 兼容的 Web 服务器为您的项目提供服务的入口点。有关更多详细信息，请参阅第十三章*部署 Django*。

### Django 设置

现在，编辑`mysite/settings.py`。这是一个普通的 Python 模块，其中包含表示 Django 设置的模块级变量。在编辑`settings.py`时的第一步是将`TIME_ZONE`设置为您的时区。请注意文件顶部的`INSTALLED_APPS`设置。它包含了在此 Django 实例中激活的所有 Django 应用程序的名称。应用程序可以在多个项目中使用，并且您可以将它们打包和分发给其他人在他们的项目中使用。默认情况下，`INSTALLED_APPS`包含以下应用程序，这些应用程序都是 Django 自带的：

+   `django.contrib.admin`：管理站点。

+   `django.contrib.auth`：身份验证系统。

+   `django.contrib.contenttypes`：内容类型框架。

+   `django.contrib.sessions`：会话框架。

+   `django.contrib.messages`：消息框架。

+   `django.contrib.staticfiles`：用于管理静态文件的框架。

这些应用程序默认包含，以方便常见情况。其中一些应用程序至少使用了一个数据库表，因此我们需要在使用它们之前在数据库中创建这些表。要做到这一点，请运行以下命令：

```py
 python manage.py migrate 

```

`migrate`命令查看`INSTALLED_APPS`设置，并根据`settings.py`文件中的数据库设置和应用程序附带的数据库迁移创建任何必要的数据库表（我们稍后会涵盖这些）。它将为每个应用程序应用的每个迁移显示一条消息。

### 开发服务器

让我们验证一下你的 Django 项目是否正常工作。如果还没有，请切换到外部的`mysite`目录，并运行以下命令：

```py
python manage.py runserver

```

您将在命令行上看到以下输出：

```py
Performing system checks... 0 errors found
June 12, 2016-08:48:58
Django version 1.8.13, using settings 'mysite.settings'
Starting development server at http://127.0.0.1:8000/
Quit the server with CTRL-BREAK.

```

您已经启动了 Django 开发服务器，这是一个纯粹用 Python 编写的轻量级 Web 服务器。我们已经将其与 Django 一起提供，这样您就可以在准备投入生产之前快速开发，而无需处理配置生产服务器（如 Apache）的问题。

现在是一个很好的时机来注意：不要在任何类似生产环境的地方使用这个服务器。它只用于开发时使用。

现在服务器正在运行，请使用您的 Web 浏览器访问`http://127.0.0.1:8000/`。您将在愉快的浅蓝色（*图 1.3*）中看到一个“欢迎来到 Django”的页面。它成功了！

### 注意

**runserver 的自动重新加载**

开发服务器会根据需要自动重新加载每个请求的 Python 代码。您无需重新启动服务器即可使代码更改生效。但是，某些操作（例如添加文件）不会触发重新启动，因此在这些情况下，您将不得不重新启动服务器。

![开发服务器](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_01_003.jpg)

Django 的欢迎页面

## 模型-视图-控制器（MVC）设计模式

MVC 作为一个概念已经存在很长时间，但自从互联网出现以来，它已经呈指数级增长，因为它是设计客户端-服务器应用程序的最佳方式。所有最好的 Web 框架都是围绕 MVC 概念构建的。冒着引发战争的风险，我认为如果你不使用 MVC 来设计 Web 应用程序，那么你就错了。作为一个概念，MVC 设计模式真的很容易理解：

+   **模型（M）**是您的数据的模型或表示。它不是实际数据，而是数据的接口。模型允许您从数据库中提取数据，而无需了解底层数据库的复杂性。模型通常还提供了一个*抽象*层与您的数据库，以便您可以在多个数据库中使用相同的模型。

+   **视图（V）**是你所看到的。它是模型的表示层。在你的计算机上，视图是 Web 应用程序中浏览器中所看到的内容，或者是桌面应用程序的用户界面。视图还提供了一个接口来收集用户输入。

+   **控制器（C）**控制信息在模型和视图之间的流动。它使用编程逻辑来决定从模型中提取哪些信息，并将哪些信息传递给视图。它还通过视图从用户那里获取信息，并实现业务逻辑：通过更改视图，或通过模型修改数据，或两者兼而有之。

在每一层发生的事情的不同解释是困难的地方-不同的框架以不同的方式实现相同的功能。一个框架**专家**可能会说某个函数属于视图，而另一个可能会坚决地主张它应该在控制器上。

作为一个有远见的程序员，你不必关心这一点，因为最终这并不重要。只要你理解 Django 如何实现 MVC 模式，你就可以自由地继续并完成一些真正的工作。尽管在评论线程中观看战争可能是一种极具娱乐性的分心……

Django 紧密遵循 MVC 模式，但它在实现中使用了自己的逻辑。因为`C`由框架本身处理，而 Django 中的大部分工作发生在模型、模板和视图中，因此 Django 通常被称为*MTV 框架*。在 MTV 开发模式中：

+   **M 代表“模型”，**数据访问层。这一层包含关于数据的一切：如何访问它，如何验证它，它具有哪些行为，以及数据之间的关系。我们将在第四章中仔细研究 Django 的模型，*模型*。

+   T 代表“模板”，表示层。这一层包含与表示相关的决策：在网页或其他类型的文档上如何显示某些内容。我们将在第三章中探讨 Django 的模板，“模板”。

+   V 代表“视图”，业务逻辑层。这一层包含访问模型并转到适当模板的逻辑。你可以把它看作是模型和模板之间的桥梁。我们将在下一章中查看 Django 的视图。

这可能是 Django 中唯一不太幸运的命名，因为 Django 的视图更像是 MVC 中的控制器，而 MVC 的视图实际上在 Django 中是一个模板。起初可能有点混淆，但作为一个完成工作的程序员，你真的不会长时间在意。这只是对于我们这些需要教授它的人来说是个问题。哦，当然还有那些喷子。

# 接下来呢？

现在你已经安装了所有东西并且开发服务器正在运行，你已经准备好继续学习 Django 的视图，并学习使用 Django 提供网页的基础知识。


# 第二章：视图和 URLconfs

在上一章中，我解释了如何设置 Django 项目并运行 Django 开发服务器。在本章中，你将学习使用 Django 创建动态网页的基础知识。

# 你的第一个 Django 网页：Hello World

作为我们的第一个目标，让我们创建一个网页，输出那个著名的例子消息：**Hello World**。如果你要发布一个简单的**Hello World**网页而没有使用 Web 框架，你只需在一个文本文件中输入 `Hello world`，将其命名为 `hello.html`，然后上传到 Web 服务器的某个目录中。请注意，在这个过程中，你已经指定了关于该网页的两个关键信息：它的内容（字符串 `Hello world`）和它的 URL（例如 `http://www.example.com/hello.html`）。使用 Django，你以不同的方式指定相同的两个内容。页面的内容由**视图函数**生成，URL 在**URLconf**中指定。首先，让我们编写我们的 Hello World 视图函数。

## 你的第一个视图

在我们在上一章中创建的`mysite`目录中，创建一个名为`views.py`的空文件。这个 Python 模块将包含本章的视图。我们的 Hello World 视图很简单。以下是整个函数以及导入语句，你应该将其输入到`views.py`文件中：

```py
from django.http import HttpResponse 

def hello(request): 
    return HttpResponse("Hello world") 

```

让我们逐行分析这段代码：

+   首先，我们导入了`django.http`模块中的`HttpResponse`类。我们需要导入这个类，因为它在我们的代码中稍后会用到。

+   接下来，我们定义一个名为 `hello` 的函数-视图函数。

每个视图函数至少需要一个参数，按照惯例称为`request`。这是一个包含有关触发此视图的当前 Web 请求的信息的对象，是`django.http.HttpRequest`类的实例。

在这个例子中，我们并没有对 `request` 做任何操作，但它仍然必须是视图的第一个参数。请注意，视图函数的名称并不重要；它不必以某种方式命名，以便 Django 识别它。我们在这里称它为 `hello`，因为这个名称清楚地表示了视图的要点，但它也可以被命名为 `hello_wonderful_beautiful_world`，或者其他同样令人讨厌的名称。接下来的部分，“你的第一个 URLconf”，将解释 Django 如何找到这个函数。

这个函数是一个简单的一行代码：它只是返回一个用文本 `Hello world` 实例化的 `HttpResponse` 对象。

这里的主要教训是：视图只是一个以`HttpRequest`作为第一个参数并返回`HttpResponse`实例的 Python 函数。为了使 Python 函数成为 Django 视图，它必须做这两件事。（有例外情况，但我们稍后会讨论。）

## 你的第一个 URLconf

如果此时再次运行 `python manage.py runserver`，你仍然会看到**欢迎使用 Django**的消息，但没有我们的 Hello World 视图的任何痕迹。这是因为我们的`mysite`项目还不知道`hello`视图；我们需要明确告诉 Django 我们正在激活这个视图的特定 URL。继续我们之前关于发布静态 HTML 文件的类比，此时我们已经创建了 HTML 文件，但还没有将其上传到服务器上的目录中。

要将视图函数与 Django 中的特定 URL 挂钩，我们使用 URLconf。URLconf 就像是 Django 网站的目录。基本上，它是 URL 和应该为这些 URL 调用的视图函数之间的映射。这是告诉 Django 的方式，*对于这个 URL，调用这段代码，对于那个 URL，调用那段代码*。

例如，当有人访问 URL `/foo/` 时，调用视图函数 `foo_view()`，它位于 Python 模块 `views.py` 中。在上一章中执行 `django-admin startproject` 时，脚本会自动为您创建一个 URLconf：文件 `urls.py`。

默认情况下，它看起来像这样：

```py
"""mysite URL Configuration 
 The urlpatterns list routes URLs to views. For more information please 
 see:
     https://docs.djangoproject.com/en/1.8/topics/http/urls/ 
Examples:
Function views
     1\. Add an import:  from my_app import views
     2\. Add a URL to urlpatterns:  url(r'^$', views.home, name='home') Class-based views
     1\. Add an import:  from other_app.views import Home
     2\. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
     1\. Add an import:  from blog import urls as blog_urls
     2\. Add a URL to urlpatterns:  url(r'^blog/', include(blog_urls)) 
""" 
from django.conf.urls import include, url
from django.contrib import admin

 urlpatterns = [
     url(r'^admin/', include(admin.site.urls)),
 ] 

```

如果我们忽略文件顶部的文档注释，这就是一个 URLconf 的本质：

```py
from django.conf.urls import include, url
from django.contrib import admin 

urlpatterns = [
     url(r'^admin/', include(admin.site.urls)),
 ] 

```

让我们逐行分析这段代码：

+   第一行从`django.conf.urls`模块中导入了两个函数：`include`允许你包含另一个 URLconf 模块的完整 Python 导入路径，`url`使用正则表达式将浏览器中的 URL 模式匹配到 Django 项目中的模块。

+   第二行调用了`django.contrib`模块中的`admin`函数。这个函数是由`include`函数调用的，用于加载 Django 管理站点的 URL。

+   第三行是`urlpatterns`-一个简单的`url()`实例列表。

这里需要注意的主要是变量`urlpatterns`，Django 希望在你的 URLconf 模块中找到它。这个变量定义了 URL 和处理这些 URL 的代码之间的映射关系。要向 URLconf 添加 URL 和视图，只需在 URL 模式和视图函数之间添加映射。下面是如何连接我们的`hello`视图：

```py
from django.conf.urls import include, url 
from django.contrib import admin 
from mysite.views import hello 

urlpatterns = [
     url(r'^admin/', include(admin.site.urls)),
     url(r'^hello/$', hello), 
] 

```

我们在这里做了两个更改：

+   首先，我们从模块`mysite/views.py`中导入了`hello`视图，这在 Python 导入语法中转换为`mysite.views`。（这假设`mysite/views.py`在你的 Python 路径上。）

+   接下来，我们在`urlpatterns`中添加了一行`url(r'^hello/$', hello),`。这行被称为 URLpattern。`url()`函数告诉 Django 如何处理你正在配置的 URL。第一个参数是一个模式匹配字符串（一个正则表达式；稍后会详细介绍），第二个参数是用于该模式的视图函数。`url()`还可以接受其他可选参数，我们将在第七章中更深入地介绍，*高级视图和 URLconfs*。

我们在这里引入的另一个重要细节是正则表达式字符串前面的`r`字符。这告诉 Python 该字符串是一个**原始字符串**-它的内容不应解释反斜杠。

在普通的 Python 字符串中，反斜杠用于转义特殊字符，比如字符串`\n`，它是一个包含换行符的单字符字符串。当你添加`r`使其成为原始字符串时，Python 不会应用反斜杠转义，因此`r'\n'`是一个包含字面反斜杠和小写`n`的两个字符字符串。

Python 的反斜杠用法与正则表达式中的反斜杠之间存在自然冲突，因此最好在 Django 中定义正则表达式时始终使用原始字符串。

简而言之，我们只是告诉 Django，任何对 URL`/hello/`的请求都应该由`hello`视图函数处理。

值得讨论的是这个 URLpattern 的语法，因为它可能不是立即显而易见的。虽然我们想匹配 URL`/hello/`，但模式看起来与此有些不同。原因如下：

+   Django 在检查 URLpatterns 之前会从每个传入的 URL 中删除斜杠。这意味着我们的 URLpattern 不包括`/hello/`中的前导斜杠。起初，这可能看起来有点不直观，但这个要求简化了一些事情，比如在其他 URLconfs 中包含 URLconfs，我们将在第七章中介绍，*高级视图和 URLconfs*。

+   模式包括插入符（^）和美元符号（$）。这些是具有特殊含义的正则表达式字符：插入符表示*要求模式与字符串的开头匹配*，美元符号表示*要求模式与字符串的结尾匹配*。

这个概念最好通过例子来解释。如果我们使用的是模式`^hello/`（末尾没有美元符号），那么任何以`/hello/`开头的 URL 都会匹配，比如`/hello/foo`和`/hello/bar`，而不仅仅是`/hello/`。

同样，如果我们省略了初始的插入符号（即`hello/$`），Django 将匹配任何以`hello/`结尾的 URL，比如`/foo/bar/hello/`。

如果我们只是使用了`hello/`，没有插入符号或美元符号，那么包含`hello/`的任何 URL 都会匹配，比如`/foo/hello/bar`。

因此，我们同时使用插入符号和美元符号来确保只有 URL`/hello/`匹配-没有多余，也没有少了。大多数 URLpatterns 将以插入符号开头，并以美元符号结尾，但具有执行更复杂匹配的灵活性也是很好的。

也许你会想知道如果有人请求 URL`/hello`（即没有尾随斜杠），会发生什么。因为我们的 URLpattern 需要一个尾随斜杠，那个 URL 就不会匹配。然而，默认情况下，任何不匹配 URLpattern 并且不以斜杠结尾的 URL 请求都会被重定向到相同的 URL，但是以斜杠结尾（这由`APPEND_SLASH` Django 设置规定，详见附录 D，*设置*）。

关于这个 URLconf 的另一件事是，我们将`hello`视图函数作为对象传递而不调用函数。这是 Python（和其他动态语言）的一个关键特性：函数是一级对象，这意味着你可以像任何其他变量一样传递它们。很酷，对吧？

为了测试我们对 URLconf 的更改，启动 Django 开发服务器，就像你在第一章 *Django 简介和入门*中所做的那样，通过运行命令`python manage.py runserver`。（如果你让它保持运行状态，也没关系。开发服务器会自动检测 Python 代码的更改并在必要时重新加载，因此你不必在更改之间重新启动服务器。）服务器正在运行在地址`http://127.0.0.1:8000/`，所以打开一个网络浏览器，转到`http://127.0.0.1:8000/hello/`。你应该会看到文本**Hello World**-这是你的 Django 视图的输出（*图 2.1*）。

![你的第一个 URLconf](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_02_001.jpg)

图 2.1：耶！你的第一个 Django 视图

## 正则表达式

正则表达式（或 regexes）是一种在文本中指定模式的简洁方式。虽然 Django 的 URLconfs 允许任意的正则表达式进行强大的 URL 匹配，但实际上你可能只会使用一些正则表达式符号。*表 2.1*列出了一些常见符号。

表 2.1：常见的正则表达式符号

| **符号** | **匹配** |
| --- | --- |
| `.`（点） | 任意单个字符 |
| `\d` | 任意单个数字 |
| `[A-Z]` | `A`和`Z`之间的任何字符（大写） |
| `[a-z]` | `a`和`z`之间的任何字符（小写） |
| `[A-Za-z]` | `a`和`z`之间的任何字符（不区分大小写） |
| `+` | 前一个表达式的一个或多个（例如，`\d+`匹配一个或多个数字） |
| `[^/]+` | 一个或多个字符，直到（但不包括）斜杠 |
| `?` | 前一个表达式的零个或一个（例如，`\d?`匹配零个或一个数字） |
| `*` | 前一个表达式的零个或多个（例如，`\d*`匹配零个、一个或多个数字） |
| `{1,3}` | 前一个表达式的一个到三个（包括）（例如，`\d{1,3}`匹配一个、两个或三个数字） |

有关正则表达式的更多信息，请参阅 Python 正则表达式文档，访问[`docs.python.org/3.4/library/re.html`](https://docs.python.org/3.4/library/re.html)。

## 关于 404 错误的快速说明

此时，我们的 URLconf 只定义了一个 URLpattern：处理 URL`/hello/`的 URLpattern。当你请求不同的 URL 时会发生什么？要找出来，尝试运行 Django 开发服务器，并访问诸如`http://127.0.0.1:8000/goodbye/`之类的页面。

你应该会看到一个**页面未找到**的消息（*图 2.2*）。Django 显示这个消息是因为你请求了一个在你的 URLconf 中没有定义的 URL。

![关于 404 错误的快速说明](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_02_002.jpg)

图 2.2：Django 的 404 页面

这个页面的实用性不仅仅体现在基本的 404 错误消息上。它还会告诉您 Django 使用了哪个 URLconf 以及该 URLconf 中的每个模式。通过这些信息，您应该能够知道为什么请求的 URL 会引发 404 错误。

当您首次创建 Django 项目时，每个 Django 项目都处于调试模式。如果项目不处于调试模式，Django 会输出不同的 404 响应。这是敏感信息，仅供您作为 Web 开发人员使用。如果这是一个部署在互联网上的生产站点，您不希望将这些信息暴露给公众。因此，只有在您的 Django 项目处于**调试模式**时才会显示**Page not found**页面。

我将在后面解释如何关闭调试模式。现在只需知道每个 Django 项目在创建时都处于调试模式，如果项目不处于调试模式，Django 会输出不同的 404 响应。

## 关于站点根目录的一点说明

在上一节中已经解释过，如果您查看站点根目录`http://127.0.0.1:8000/`，您将看到一个 404 错误消息。Django 不会在站点根目录自动添加任何内容；该 URL 并没有特殊处理。

这取决于您将其分配给一个 URL 模式，就像 URLconf 中的每个其他条目一样。匹配站点根目录的 URL 模式有点不直观，因此值得一提。

当您准备为站点根目录实现一个视图时，使用 URL 模式`^$`，它匹配空字符串。例如：

```py
from mysite.views import hello, my_homepage_view

 urlpatterns = [
     url(r'^$', my_homepage_view),
     # ... 

```

## Django 如何处理请求

在继续我们的第二个视图函数之前，让我们暂停一下，了解一下 Django 是如何工作的。具体来说，当您在 Web 浏览器中访问`http://127.0.0.1:8000/hello/`以查看您的**Hello World**消息时，Django 在幕后做了什么？一切都始于**settings 文件**。

当您运行`python manage.py runserver`时，脚本会在内部`mysite`目录中查找名为`settings.py`的文件。该文件包含了这个特定 Django 项目的各种配置，全部都是大写的：`TEMPLATE_DIRS`、`DATABASES`等等。最重要的设置叫做`ROOT_URLCONF`。`ROOT_URLCONF`告诉 Django 应该使用哪个 Python 模块作为这个网站的 URLconf。

记得`django-admin startproject`创建了`settings.py`和`urls.py`文件吗？自动生成的`settings.py`包含一个指向自动生成的`urls.py`的`ROOT_URLCONF`设置。打开`settings.py`文件，您会看到它应该是这样的。

```py
ROOT_URLCONF = 'mysite.urls'
```

这对应于文件`mysite/urls.py`。当请求特定 URL（比如请求`/hello/`）时，Django 加载`ROOT_URLCONF`设置指向的 URLconf。然后，它按顺序检查该 URLconf 中的每个 URL 模式，逐个将请求的 URL 与模式进行比较，直到找到一个匹配的模式。

当找到匹配的 URL 模式时，它调用与该模式相关联的视图函数，并将`HttpRequest`对象作为第一个参数传递给它（我们将在后面介绍`HttpRequest`的具体内容）。正如我们在第一个视图示例中看到的，视图函数必须返回一个`HttpResponse`。

一旦这样做，Django 就会完成剩下的工作，将 Python 对象转换为适当的 Web 响应，包括适当的 HTTP 标头和正文（即网页内容）。总之：

+   一个请求进入`/hello/`。

+   Django 通过查看`ROOT_URLCONF`设置来确定根 URLconf。

+   Django 查看 URLconf 中的所有 URL 模式，找到第一个与`/hello/`匹配的模式。

+   如果找到匹配项，它会调用相关的视图函数。

+   视图函数返回一个`HttpResponse`。

+   Django 将`HttpResponse`转换为适当的 HTTP 响应，从而生成一个网页。

现在您已经了解了如何制作 Django 网页的基础知识。实际上很简单，只需编写视图函数并通过 URLconf 将其映射到 URL。

# 您的第二个视图：动态内容

我们的 Hello World 视图在演示 Django 工作基础方面很有启发性，但它并不是动态网页的一个例子，因为页面的内容始终相同。每次查看`/hello/`时，您都会看到相同的内容；它可能就像是一个静态 HTML 文件。

对于我们的第二个视图，让我们创建一个更加动态的东西-一个显示当前日期和时间的网页。这是一个不错的、简单的下一步，因为它不涉及数据库或任何用户输入-只涉及服务器内部时钟的输出。它只比 Hello World 有点更有趣，但它将演示一些新概念。这个视图需要做两件事：计算当前日期和时间，并返回包含该值的`HttpResponse`。如果您有 Python 经验，您就会知道 Python 包括一个用于计算日期的`datetime`模块。以下是如何使用它：

```py
>>> import datetime 
>>> now = datetime.datetime.now() 
>>> now 
datetime.datetime(2015, 7, 15, 18, 12, 39, 2731) 
>>> print (now) 
2015-07-15 18:12:39.002731 

```

这很简单，与 Django 无关。这只是 Python 代码。（我们想强调的是，您应该知道哪些代码只是 Python 代码，哪些是特定于 Django 的代码。当您学习 Django 时，我们希望您能够将您的知识应用到其他不一定使用 Django 的 Python 项目中。）要创建一个显示当前日期和时间的 Django 视图，我们只需要将`datetime.datetime.now()`语句连接到一个视图并返回一个`HttpResponse`。更新后的`views.py`如下所示：

```py
from django.http import HttpResponse 
import datetime 

def hello(request):
     return HttpResponse("Hello world") 

def current_datetime(request):
     now = datetime.datetime.now()
     html = "<html><body>It is now %s.</body></html>" % now
     return HttpResponse(html) 

```

让我们逐步了解我们对`views.py`所做的更改，以适应`current_datetime`视图。

+   我们在模块顶部添加了`import datetime`，这样我们就可以计算日期了。

+   新的`current_datetime`函数计算当前日期和时间，作为`datetime.datetime`对象，并将其存储为本地变量`now`。

+   视图中的第二行代码使用 Python 的**格式化字符串**功能构造了一个 HTML 响应。字符串中的`%s`是一个占位符，字符串后面的百分号表示用变量`now`的值替换后面字符串中的`%s`。`now`变量在技术上是一个`datetime.datetime`对象，而不是一个字符串，但`%s`格式字符将其转换为其字符串表示形式，类似于`"2015-07-15 18:12:39.002731"`。这将导致一个 HTML 字符串，如`"<html><body>现在是 2015-07-15 18:12:39.002731。</body></html>"`。

+   最后，视图返回一个包含生成的响应的`HttpResponse`对象-就像我们在`hello`中做的那样。

在`views.py`中添加了这个之后，将 URL 模式添加到`urls.py`中，告诉 Django 哪个 URL 应该处理这个视图。类似`/time/`这样的东西会有意义：

```py
from django.conf.urls import include, url 
from django.contrib import admin 
from mysite.views import hello, current_datetime

     urlpatterns = [
         url(r'^admin/', include(admin.site.urls)),
         url(r'^hello/$', hello),
         url(r'^time/$', current_datetime),
     ] 

```

我们在这里做了两个更改。首先，在顶部导入了`current_datetime`函数。其次，更重要的是，我们添加了一个 URL 模式，将 URL`/time/`映射到这个新视图。掌握了吗？视图编写和 URLconf 更新后，启动`runserver`并在浏览器中访问`http://127.0.0.1:8000/time/`。您应该看到当前的日期和时间。如果您没有看到本地时间，很可能是因为您的`settings.py`中的默认时区设置为`UTC`。

# URLconfs 和松散耦合

现在是时候强调 URLconfs 和 Django 背后的一个关键理念了：松散耦合的原则。简单地说，松散耦合是一种软件开发方法，它重视使各个部分可互换的重要性。如果两个代码片段松散耦合，那么对其中一个片段的更改对另一个片段几乎没有影响。

Django 的 URLconfs 是这个原则在实践中的一个很好的例子。在 Django Web 应用程序中，URL 定义和它们调用的视图函数是松散耦合的；也就是说，对于给定函数的 URL 应该是什么的决定，以及函数本身的实现，存在于两个不同的地方。

例如，考虑我们的`current_datetime`视图。如果我们想要更改应用程序的 URL——比如，将其从`/time/`移动到`/current-time/`——我们可以快速更改 URLconf，而不必担心视图本身。同样，如果我们想要更改视图函数——以某种方式改变其逻辑——我们可以这样做，而不会影响函数绑定的 URL。此外，如果我们想要在几个 URL 上公开当前日期功能，我们可以通过编辑 URLconf 轻松处理，而不必触及视图代码。

在这个例子中，我们的`current_datetime`可以通过两个 URL 访问。这是一个刻意制造的例子，但这种技术可能会派上用场：

```py
urlpatterns = [
       url(r'^admin/', include(admin.site.urls)),
       url(r'^hello/$', hello),
       url(r'^time/$', current_datetime),
       url(r'^another-time-page/$', current_datetime),
 ] 

```

URLconfs 和视图是松散耦合的实践。我将在整本书中继续指出这一重要的哲学。

# 你的第三个视图：动态 URL

在我们的`current_datetime`视图中，页面的内容——当前日期/时间——是动态的，但 URL（`/time/`）是静态的。然而，在大多数动态网络应用中，URL 包含影响页面输出的参数。例如，一个在线书店可能为每本书提供自己的 URL，如`/books/243/`和`/books/81196/`。让我们创建一个第三个视图，显示当前日期和时间偏移了一定数量的小时。目标是以这样的方式设计网站，使得页面`/time/plus/1/`显示未来一小时的日期/时间，页面`/time/plus/2/`显示未来两小时的日期/时间，页面`/time/plus/3/`显示未来三小时的日期/时间，依此类推。一个新手可能会想要为每个小时偏移编写一个单独的视图函数，这可能会导致这样的 URLconf：

```py
urlpatterns = [
     url(r'^time/$', current_datetime),
     url(r'^time/plus/1/$', one_hour_ahead),
     url(r'^time/plus/2/$', two_hours_ahead),
     url(r'^time/plus/3/$', three_hours_ahead),
] 

```

显然，这种想法是有缺陷的。这不仅会导致冗余的视图函数，而且应用程序基本上只能支持预定义的小时范围——一、两或三个小时。

如果我们决定创建一个显示未来四小时时间的页面，我们将不得不为此创建一个单独的视图和 URLconf 行，进一步增加了重复。

那么，我们如何设计我们的应用程序来处理任意小时偏移？关键是使用通配符 URLpatterns。正如我之前提到的，URLpattern 是一个正则表达式；因此，我们可以使用正则表达式模式`\d+`来匹配一个或多个数字：

```py
urlpatterns = [
     # ...
     url(r'^time/plus/\d+/$', hours_ahead),
     # ... 
] 

```

（我使用`# ...`来暗示可能已经从这个例子中删除了其他 URLpatterns。）这个新的 URLpattern 将匹配任何 URL，比如`/time/plus/2/`、`/time/plus/25/`，甚至`/time/plus/100000000000/`。想想看，让我们限制一下，使得最大允许的偏移量是合理的。

在这个例子中，我们将通过只允许一位或两位数字来设置最大的 99 小时——在正则表达式语法中，这相当于`\d{1,2}`：

```py
url(r'^time/plus/\d{1,2}/$', hours_ahead), 

```

既然我们已经为 URL 指定了一个通配符，我们需要一种方法将通配符数据传递给视图函数，这样我们就可以对任意小时偏移使用一个视图函数。我们通过在 URLpattern 中希望保存的数据周围放置括号来实现这一点。在我们的例子中，我们希望保存在 URL 中输入的任何数字，所以让我们在`\d{1,2}`周围放上括号，就像这样：

```py
url(r'^time/plus/(\d{1,2})/$', hours_ahead), 

```

如果你熟悉正则表达式，你会在这里感到很舒适；我们使用括号来从匹配的文本中捕获数据。最终的 URLconf，包括我们之前的两个视图，看起来像这样：

```py
from django.conf.urls import include, url from django.contrib import admin from mysite.views import hello, current_datetime, hours_ahead 

urlpatterns = [
     url(r'^admin/', include(admin.site.urls)),
     url(r'^hello/$', hello),
     url(r'^time/$', current_datetime),
     url(r'^time/plus/(\d{1,2})/$', hours_ahead),
 ] 

```

### 注意

如果您在其他 Web 开发平台上有经验，您可能会想：“嘿，让我们使用查询字符串参数！”-类似于`/time/plus?hours=3`，其中小时将由 URL 查询字符串（'?'后面的部分）中的`hours`参数指定。您可以在 Django 中这样做（我将在第七章中告诉您如何做），但 Django 的核心理念之一是 URL 应该是美观的。URL`/time/plus/3/`比其查询字符串对应项更清晰、更简单、更可读、更容易大声朗读，而且更漂亮。美观的 URL 是高质量 Web 应用的特征。

Django 的 URLconf 系统鼓励使用美观的 URL，因为使用美观的 URL 比不使用更容易。

处理完这些后，让我们编写`hours_ahead`视图。`hours_ahead`与我们之前编写的`current_datetime`视图非常相似，但有一个关键区别：它接受一个额外的参数，即偏移的小时数。以下是视图代码：

```py
from django.http import Http404, HttpResponse 
import datetime 

def hours_ahead(request, offset):
     try:
         offset = int(offset)
     except ValueError:
         raise Http404()
     dt = datetime.datetime.now() + datetime.timedelta(hours=offset)
     html = "<html><body>In %s hour(s), it will be  %s.
             </body></html>" % (offset, dt)
     return HttpResponse(html) 

```

让我们仔细看看这段代码。

视图函数`hours_ahead`接受两个参数：`request`和`offset`。

+   `request`是一个`HttpRequest`对象，就像`hello`和`current_datetime`中一样。我再说一遍：每个视图总是以`HttpRequest`对象作为其第一个参数。

+   `offset`是 URLpattern 中括号捕获的字符串。例如，如果请求的 URL 是`/time/plus/3/`，那么`offset`将是字符串'3'。如果请求的 URL 是`/time/plus/21/`，那么`offset`将是字符串'21'。请注意，捕获的值将始终是 Unicode 对象，而不是整数，即使字符串只由数字组成，比如'21'。

我决定将变量称为`offset`，但只要它是有效的 Python 标识符，您可以将其命名为任何您喜欢的名称。变量名并不重要；重要的是它是`request`之后的函数的第二个参数。（在 URLconf 中也可以使用关键字参数，而不是位置参数。我将在第七章中介绍这一点。）

在函数内部，我们首先对`offset`调用`int()`。这将把 Unicode 字符串值转换为整数。

请注意，如果您对无法转换为整数的值（如字符串`foo`）调用`int()`，Python 将引发`ValueError`异常。在这个例子中，如果我们遇到`ValueError`，我们会引发异常`django.http.Http404`，这将导致**404**页面未找到错误。

敏锐的读者会想：无论如何，我们怎么会到达`ValueError`的情况呢？因为我们 URLpattern-`(\d{1,2})`中的正则表达式只捕获数字，因此`offset`将始终是由数字组成的字符串？答案是，我们不会，因为 URLpattern 提供了适度但有用的输入验证级别，但我们仍然检查`ValueError`，以防这个视图函数以其他方式被调用。

实现视图函数时最好不要对其参数做任何假设。记住松耦合。

在函数的下一行中，我们计算当前的日期/时间，并添加适当数量的小时。我们已经从`current_datetime`视图中看到了`datetime.datetime.now()`；这里的新概念是，您可以通过创建`datetime.timedelta`对象并添加到`datetime.datetime`对象来执行日期/时间算术。我们的结果存储在变量`dt`中。

这行还显示了为什么我们对`offset`调用了`int()`-`datetime.timedelta`函数要求`hours`参数是一个整数。

接下来，我们构建这个视图函数的 HTML 输出，就像我们在`current_datetime`中所做的那样。这一行与上一行的一个小区别是，它使用了 Python 的格式化字符串功能，而不仅仅是一个。因此，在字符串中有两个`%s`符号和一个要插入的值的元组：`(offset, dt)`。

最后，我们返回一个 HTML 的`HttpResponse`。

有了这个视图函数和 URLconf 的编写，启动 Django 开发服务器（如果尚未运行），并访问`http://127.0.0.1:8000/time/plus/3/`来验证它是否正常工作。

然后尝试`http://127.0.0.1:8000/time/plus/5/`。

然后访问`http://127.0.0.1:8000/time/plus/24/`。

最后，访问`http://127.0.0.1:8000/time/plus/100/`来验证您的 URLconf 中的模式只接受一位或两位数字；在这种情况下，Django 应该显示**Page not found**错误，就像我们在*关于 404 错误的快速说明*部分中看到的那样。

URL `http://127.0.0.1:8000/time/plus/`（没有小时指定）也应该会引发 404 错误。

# Django 的漂亮错误页面

花点时间来欣赏我们迄今为止制作的精美 Web 应用程序-现在让我们打破它！让我们故意在我们的`views.py`文件中引入一个 Python 错误，方法是注释掉`hours_ahead`视图中的`offset = int(offset)`行：

```py
def hours_ahead(request, offset):
     # try:
 #     offset = int(offset)
 # except ValueError:
 #     raise Http404()
     dt = datetime.datetime.now() + datetime.timedelta(hours=offset)
     html = "<html><body>In %s hour(s), it will be %s.
               </body></html>" % (offset, dt)
     return HttpResponse(html) 

```

加载开发服务器并导航到`/time/plus/3/`。您将看到一个错误页面，其中包含大量信息，包括在顶部显示的**TypeError**消息：**unsupported type for timedelta hours component: str (** *图 2.3*).

![Django 的漂亮错误页面](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_02_003.jpg)

图 2.3：Django 的错误页面

发生了什么？嗯，`datetime.timedelta`函数期望`hours`参数是一个整数，而我们注释掉了将`offset`转换为整数的代码。这导致`datetime.timedelta`引发了**TypeError**。这是每个程序员在某个时候都会遇到的典型小错误。这个例子的目的是演示 Django 的错误页面。花点时间来探索错误页面，并了解它提供的各种信息。以下是一些需要注意的事项：

+   在页面顶部，您将获得有关异常的关键信息：异常的类型，异常的任何参数（在这种情况下是**unsupported type**消息），引发异常的文件以及有问题的行号。

+   在关键异常信息下面，页面显示了此异常的完整 Python 回溯。这类似于您在 Python 命令行解释器中获得的标准回溯，只是更加交互式。对于堆栈中的每个级别（帧），Django 显示文件的名称，函数/方法名称，行号以及该行的源代码。

+   单击源代码行（深灰色），您将看到错误行之前和之后的几行代码，以便为您提供上下文。单击堆栈中任何帧下的**Local vars**，以查看该帧中所有局部变量及其值的表，即在引发异常的代码的确切点上。这些调试信息可以提供很大的帮助。

+   注意**切换到复制和粘贴视图**文本下的**Traceback**标题。单击这些单词，回溯将切换到一个可以轻松复制和粘贴的备用版本。当您想与其他人分享您的异常回溯以获得技术支持时，可以使用此功能-例如 Django IRC 聊天室中的友好人士或 Django 用户邮件列表中的人士。

+   在下面，**在公共网站上分享此回溯**按钮将在单击一次后为您完成此工作。单击它以将回溯发布到 dpaste（有关更多信息，请访问[`www.dpaste.com/`](http://www.dpaste.com/)），在那里您将获得一个独特的 URL，可以与其他人分享。

+   接下来，**请求信息**部分包括关于产生错误的传入 web 请求的丰富信息：`GET`和`POST`信息，cookie 值和元信息，比如 CGI 头。附录 F，*请求和响应对象*，包含了请求对象包含的所有信息的完整参考。

+   在**请求信息**部分之后，**设置**部分列出了此特定 Django 安装的所有设置。所有可用的设置都在附录 D，*设置*中有详细介绍。

在某些特殊情况下，Django 错误页面能够显示更多信息，比如模板语法错误的情况。我们稍后会讨论 Django 模板系统时再谈论这些。现在，取消注释`offset = int(offset)`行，以使视图函数再次正常工作。

如果您是那种喜欢通过精心放置`print`语句来调试的程序员，Django 错误页面也非常有用。

在视图的任何位置，临时插入`assert False`来触发错误页面。然后，您可以查看程序的本地变量和状态。以下是一个示例，使用`hours_ahead`视图：

```py
def hours_ahead(request, offset):
     try:
         offset = int(offset)
     except ValueError:
         raise Http404()
     dt = datetime.datetime.now() + datetime.timedelta(hours=offset)
     assert False
     html = "<html><body>In %s hour(s), it will be %s.
              </body></html>" % (offset, dt)
     return HttpResponse(html) 

```

最后，显而易见，这些信息中的大部分都是敏感的-它暴露了您的 Python 代码和 Django 配置的内部，并且在公共互联网上显示这些信息是愚蠢的。恶意人士可以利用它来尝试反向工程您的 Web 应用程序并做坏事。因此，只有当您的 Django 项目处于调试模式时，才会显示 Django 错误页面。我将在第十三章 *部署 Django*中解释如何停用调试模式。现在，只需知道每个 Django 项目在启动时都会自动处于调试模式即可。（听起来很熟悉吗？本章前面描述的**页面未找到**错误也是同样的工作方式。）

# 接下来呢？

到目前为止，我们一直在 Python 代码中直接编写 HTML 硬编码的视图函数。我这样做是为了在演示核心概念时保持简单，但在现实世界中，这几乎总是一个坏主意。Django 附带了一个简单而强大的模板引擎，允许您将页面的设计与底层代码分离。我们将在下一章深入探讨 Django 的模板引擎。


# 第三章：模板

在上一章中，您可能已经注意到我们在示例视图中返回文本的方式有些奇怪。换句话说，HTML 直接硬编码在我们的 Python 代码中，就像这样：

```py
def current_datetime(request): 
    now = datetime.datetime.now() 
    html = "It is now %s." % now 
    return HttpResponse(html) 

```

尽管这种技术对于解释视图如何工作的目的很方便，但直接在视图中硬编码 HTML 并不是一个好主意。原因如下：

+   对页面设计的任何更改都需要对 Python 代码进行更改。网站的设计往往比底层 Python 代码更频繁地发生变化，因此如果设计可以在不需要修改 Python 代码的情况下进行更改，那将是很方便的。

+   这只是一个非常简单的例子。一个常见的网页模板有数百行 HTML 和脚本。从这个混乱中解开和排除程序代码是一场噩梦（*咳嗽-PHP-咳嗽*）。

+   编写 Python 代码和设计 HTML 是两种不同的学科，大多数专业的 Web 开发环境将这些责任分开给不同的人（甚至是不同的部门）。设计师和 HTML/CSS 编码人员不应该被要求编辑 Python 代码来完成他们的工作。

+   如果程序员和设计师可以同时工作在 Python 代码和模板上，而不是一个人等待另一个人完成编辑包含 Python 和 HTML 的单个文件，那将是最有效的。

出于这些原因，将页面的设计与 Python 代码本身分开会更加清晰和易于维护。我们可以通过 Django 的*模板系统*来实现这一点，这是我们在本章中讨论的内容。

# 模板系统基础知识

Django 模板是一串文本，旨在将文档的呈现与其数据分离。模板定义了占位符和各种基本逻辑（模板标签），规定文档应该如何显示。通常，模板用于生成 HTML，但 Django 模板同样能够生成任何基于文本的格式。

### 注意

**Django 模板背后的哲学**

如果您有编程背景，或者习惯于将编程代码直接嵌入 HTML 的语言，您需要记住 Django 模板系统不仅仅是 Python 嵌入到 HTML 中。

这是有意设计的：模板系统旨在表达演示，而不是程序逻辑。

让我们从一个简单的示例模板开始。这个 Django 模板描述了一个 HTML 页面，感谢一个人向公司下订单。把它想象成一封表格信：

```py
<html> 
<head><title>Ordering notice</title></head> 
<body> 

<h1>Ordering notice</h1> 

<p>Dear {{ person_name }},</p> 

<p>Thanks for placing an order from {{ company }}. It's scheduled to ship on {{ ship_date|date:"F j, Y" }}.</p> 
<p>Here are the items you've ordered:</p> 
<ul> 
{% for item in item_list %}<li>{{ item }}</li>{% endfor %} 
</ul> 

{% if ordered_warranty %} 
    <p>Your warranty information will be included in the packaging.</p> 
{% else %} 
    <p>You didn't order a warranty, so you're on your own when 
    the products inevitably stop working.</p> 
{% endif %} 

<p>Sincerely,<br />{{ company }}</p> 

</body> 
</html> 

```

这个模板是基本的 HTML，其中包含一些变量和模板标签。让我们逐步进行：

+   任何被一对大括号包围的文本（例如，`{{ person_name }}`）都是*变量*。这意味着“*插入具有给定名称的变量的值*”。我们如何指定变量的值？我们马上就会讨论到。任何被大括号和百分号包围的文本（例如，`{% if ordered_warranty %}`）都是*模板标签*。标签的定义非常广泛：标签只是告诉模板系统“*做某事*”。

+   这个示例模板包含一个`for`标签（`{% for item in item_list %}`）和一个`if`标签（`{% if ordered_warranty %}`）。`for`标签的工作方式与 Python 中的`for`语句非常相似，让您可以循环遍历序列中的每个项目。

+   一个`if`标签，正如您可能期望的那样，充当逻辑 if 语句。在这种特殊情况下，标签检查`ordered_warranty`变量的值是否评估为`True`。如果是，模板系统将显示`{% if ordered_warranty %}`和`{% else %}`之间的所有内容。如果不是，模板系统将显示`{% else %}`和`{% endif %}`之间的所有内容。请注意，`{% else %}`是可选的。

+   最后，这个模板的第二段包含了一个*filter*的例子，这是改变变量格式的最方便的方法。在这个例子中，`{{ ship_date|date:"F j, Y" }}`，我们将`ship_date`变量传递给`date`过滤器，并给`date`过滤器传递参数`"F j, Y"`。`date`过滤器根据该参数指定的格式格式化日期。过滤器使用管道字符（`|`）进行连接，作为对 Unix 管道的引用。

每个 Django 模板都可以访问多个内置标签和过滤器，其中许多在接下来的章节中讨论。附录 E，*内置模板标签和过滤器*，包含了标签和过滤器的完整列表，熟悉该列表是一个好主意，这样您就知道可能发生什么。还可以创建自己的过滤器和标签；我们将在第八章，*高级模板*中进行介绍。

# 使用模板系统

Django 项目可以配置一个或多个模板引擎（甚至可以不使用模板）。Django 自带了一个用于其自己模板系统的内置后端-**Django 模板语言**（**DTL**）。Django 1.8 还包括对流行的替代品 Jinja2 的支持（有关更多信息，请访问[`jinja.pocoo.org/`](http://jinja.pocoo.org/)）。如果没有紧迫的理由选择其他后端，应该使用 DTL-特别是如果您正在编写可插拔应用程序并且打算分发模板。Django 的`contrib`应用程序包括模板，如`django.contrib.admin`，使用 DTL。本章中的所有示例都将使用 DTL。有关更高级的模板主题，包括配置第三方模板引擎，请参阅第八章，*高级模板*。在您的视图中实现 Django 模板之前，让我们先深入了解 DTL，以便您了解其工作原理。以下是您可以在 Python 代码中使用 Django 模板系统的最基本方式：

1.  通过提供原始模板代码作为字符串来创建`Template`对象。

1.  使用给定的一组变量（上下文）调用`Template`对象的`render()`方法。这将根据上下文返回一个完全呈现的模板字符串，其中所有变量和模板标签都根据上下文进行评估。

在代码中，它看起来像这样：

```py
>>> from django import template 
>>> t = template.Template('My name is {{ name }}.') 
>>> c = template.Context({'name': 'Nige'}) 
>>> print (t.render(c)) 
My name is Nige. 
>>> c = template.Context({'name': 'Barry'}) 
>>> print (t.render(c)) 
My name is Barry. 

```

以下各节将更详细地描述每个步骤。

## 创建模板对象

创建`Template`对象的最简单方法是直接实例化它。`Template`类位于`django.template`模块中，构造函数接受一个参数，即原始模板代码。让我们进入 Python 交互式解释器，看看这在代码中是如何工作的。从您在第一章中创建的`mysite`项目目录中，键入`python manage.py shell`以启动交互式解释器。

让我们来看一些模板系统的基础知识：

```py
>>> from django.template import Template 
>>> t = Template('My name is {{ name }}.') 
>>> print (t) 

```

如果您正在交互式地跟随，您会看到类似于这样的内容：

```py
<django.template.base.Template object at 0x030396B0> 

```

`0x030396B0`每次都会不同，这并不重要；这是一个 Python 的东西（如果你一定要知道的话，这是`Template`对象的 Python“标识”）。

当您创建一个`Template`对象时，模板系统会将原始模板代码编译成内部优化形式，准备好进行呈现。但是，如果您的模板代码包含任何语法错误，对`Template()`的调用将引发`TemplateSyntaxError`异常：

```py
>>> from django.template import Template 
>>> t = Template('{% notatag %}') 
Traceback (most recent call last): 
  File "", line 1, in ? 
  ... 
django.template.base.TemplateSyntaxError: Invalid block tag: 'notatag' 

```

这里的“块标签”是指`{% notatag %}`。 “块标签”和“模板标签”是同义词。系统对以下任何情况都会引发`TemplateSyntaxError`异常：

+   无效标签

+   对有效标签的无效参数

+   无效的过滤器

+   对有效过滤器的无效参数

+   无效的模板语法

+   未关闭的标签（对于需要关闭标签的标签）

## 呈现模板

一旦你有了`Template`对象，你可以通过给它*上下文*来传递数据。上下文只是一组模板变量名及其关联的值。模板使用这个来填充它的变量并评估它的标记。在 Django 中，上下文由`Context`类表示，它位于`django.template`模块中。它的构造函数接受一个可选参数：将变量名映射到变量值的字典。

使用上下文调用`Template`对象的`render()`方法来*填充*模板：

```py
>>> from django.template import Context, Template 
>>> t = Template('My name is {{ name }}.') 
>>> c = Context({'name': 'Stephane'}) 
>>> t.render(c) 
'My name is Stephane.' 

```

### 注意

**一个特殊的 Python 提示**

如果你以前使用过 Python，你可能会想知道为什么我们要运行 python manage.py shell 而不是只运行 python（或 python3）。这两个命令都会启动交互式解释器，但`manage.py` shell 命令有一个关键的区别：在启动解释器之前，它会告诉 Django 要使用哪个设置文件。Django 的许多部分，包括模板系统，都依赖于你的设置，除非框架知道要使用哪些设置，否则你将无法使用它们。

如果你感兴趣，这是它在幕后是如何工作的。Django 会查找一个名为 DJANGO_SETTINGS_MODULE 的环境变量，它应该设置为你的 settings.py 的导入路径。例如，DJANGO_SETTINGS_MODULE 可能设置为'mysite.settings'，假设 mysite 在你的 Python 路径上。

当你运行 python manage.py shell 时，该命令会为你设置 DJANGO_SETTINGS_MODULE。在这些示例中，你需要使用 python manage.py shell，否则 Django 会抛出异常。

# 字典和上下文

Python 字典是已知键和变量值之间的映射。`Context`类似于字典，但`Context`提供了额外的功能，如第八章中所述的*高级模板*。

变量名必须以字母（A-Z 或 a-z）开头，可以包含更多的字母、数字、下划线和点。（点是一个我们马上会讨论的特殊情况。）变量名是区分大小写的。以下是使用类似本章开头示例的模板进行编译和渲染的示例：

```py
>>> from django.template import Template, Context 
>>> raw_template = """<p>Dear {{ person_name }},</p> 
... 
... <p>Thanks for placing an order from {{ company }}. It's scheduled to 
... ship on {{ ship_date|date:"F j, Y" }}.</p> 
... 
... {% if ordered_warranty %} 
... <p>Your warranty information will be included in the packaging.</p> 
... {% else %} 
... <p>You didn't order a warranty, so you're on your own when 
... the products inevitably stop working.</p> 
... {% endif %} 
... 
... <p>Sincerely,<br />{{ company }}</p>""" 
>>> t = Template(raw_template) 
>>> import datetime 
>>> c = Context({'person_name': 'John Smith', 
...     'company': 'Outdoor Equipment', 
...     'ship_date': datetime.date(2015, 7, 2), 
...     'ordered_warranty': False}) 
>>> t.render(c) 
u"<p>Dear John Smith,</p>\n\n<p>Thanks for placing an order from Outdoor 
Equipment. It's scheduled to\nship on July 2, 2015.</p>\n\n\n<p>You 
didn't order a warranty, so you're on your own when\nthe products 
inevitably stop working.</p>\n\n\n<p>Sincerely,<br />Outdoor Equipment 
</p>" 

```

+   首先，我们导入`Template`和`Context`类，它们都位于`django.template`模块中。

+   我们将模板的原始文本保存到变量`raw_template`中。请注意，我们使用三引号来指定字符串，因为它跨越多行；相比之下，单引号内的字符串不能跨越多行。

+   接下来，我们通过将`raw_template`传递给`Template`类的构造函数来创建一个模板对象`t`。

+   我们从 Python 的标准库中导入`datetime`模块，因为我们在下面的语句中会用到它。

+   然后，我们创建一个`Context`对象`c`。`Context`构造函数接受一个 Python 字典，它将变量名映射到值。在这里，例如，我们指定`person_name`是"`John Smith`"，`company`是"`Outdoor Equipment`"，等等。

+   最后，我们在模板对象上调用`render()`方法，将上下文传递给它。这将返回渲染后的模板-也就是说，它用变量的实际值替换模板变量，并执行任何模板标记。

请注意，*您没有订购保修*段落被显示，因为`ordered_warranty`变量评估为`False`。还请注意日期`2015 年 7 月 2 日`，它根据格式字符串"`F j, Y`"显示。（我们稍后会解释`date`过滤器的格式字符串。）

如果你是 Python 的新手，你可能会想为什么这个输出包含换行符（"`\n`"）而不是显示换行。这是因为 Python 交互式解释器中的一个微妙之处：对 `t.render(c)` 的调用返回一个字符串，默认情况下交互式解释器显示字符串的表示形式，而不是字符串的打印值。如果你想看到带有换行符的字符串显示为真正的换行而不是 "`\n`" 字符，使用 print 函数：`print (t.render(c))`。

这些是使用 Django 模板系统的基础知识：只需编写一个模板字符串，创建一个 `Template` 对象，创建一个 `Context`，然后调用 `render()` 方法。

## 多个上下文，同一个模板

一旦你有了一个 `Template` 对象，你可以通过它渲染多个上下文。例如：

```py
>>> from django.template import Template, Context 
>>> t = Template('Hello, {{ name }}') 
>>> print (t.render(Context({'name': 'John'}))) 
Hello, John 
>>> print (t.render(Context({'name': 'Julie'}))) 
Hello, Julie 
>>> print (t.render(Context({'name': 'Pat'}))) 
Hello, Pat 

```

当你使用相同的模板源来渲染多个上下文时，最好只创建一次 `Template` 对象，然后多次调用 `render()` 方法：

```py
# Bad 
for name in ('John', 'Julie', 'Pat'): 
    t = Template('Hello, {{ name }}') 
    print (t.render(Context({'name': name}))) 

# Good 
t = Template('Hello, {{ name }}') 
for name in ('John', 'Julie', 'Pat'): 
    print (t.render(Context({'name': name}))) 

```

Django 的模板解析非常快。在幕后，大部分解析是通过对单个正则表达式的调用来完成的。这与基于 XML 的模板引擎形成鲜明对比，后者需要 XML 解析器的开销，而且往往比 Django 的模板渲染引擎慢几个数量级。

## 上下文变量查找

到目前为止的例子中，我们在上下文中传递了简单的值-大多是字符串，还有一个 `datetime.date` 的例子。然而，模板系统优雅地处理了更复杂的数据结构，如列表、字典和自定义对象。在 Django 模板中遍历复杂数据结构的关键是点字符（“`.`”）。

使用点来访问对象的字典键、属性、方法或索引。这最好通过一些例子来说明。例如，假设你要将一个 Python 字典传递给模板。要通过字典键访问该字典的值，使用一个点：

```py
>>> from django.template import Template, Context 
>>> person = {'name': 'Sally', 'age': '43'} 
>>> t = Template('{{ person.name }} is {{ person.age }} years old.') 
>>> c = Context({'person': person}) 
>>> t.render(c) 
'Sally is 43 years old.' 

```

同样，点也允许访问对象的属性。例如，Python 的 `datetime.date` 对象具有 `year`、`month` 和 `day` 属性，你可以使用点来在 Django 模板中访问这些属性：

```py
>>> from django.template import Template, Context 
>>> import datetime 
>>> d = datetime.date(1993, 5, 2) 
>>> d.year 
1993 
>>> d.month 
5 
>>> d.day 
2 
>>> t = Template('The month is {{ date.month }} and the year is {{ date.year }}.') 
>>> c = Context({'date': d}) 
>>> t.render(c) 
'The month is 5 and the year is 1993.' 

```

这个例子使用了一个自定义类，演示了变量点也允许在任意对象上进行属性访问：

```py
>>> from django.template import Template, Context 
>>> class Person(object): 
...     def __init__(self, first_name, last_name): 
...         self.first_name, self.last_name = first_name, last_name 
>>> t = Template('Hello, {{ person.first_name }} {{ person.last_name }}.') 
>>> c = Context({'person': Person('John', 'Smith')}) 
>>> t.render(c) 
'Hello, John Smith.' 

```

点也可以指代对象的方法。例如，每个 Python 字符串都有 `upper()` 和 `isdigit()` 方法，你可以在 Django 模板中使用相同的点语法调用这些方法：

```py
>>> from django.template import Template, Context 
>>> t = Template('{{ var }} -- {{ var.upper }} -- {{ var.isdigit }}') 
>>> t.render(Context({'var': 'hello'})) 
'hello -- HELLO -- False' 
>>> t.render(Context({'var': '123'})) 
'123 -- 123 -- True' 

```

请注意，在方法调用中不要包括括号。而且，不可能向方法传递参数；你只能调用没有必需参数的方法（我们稍后在本章中解释这个理念）。最后，点也用于访问列表索引，例如：

```py
>>> from django.template import Template, Context 
>>> t = Template('Item 2 is {{ items.2 }}.') 
>>> c = Context({'items': ['apples', 'bananas', 'carrots']}) 
>>> t.render(c) 
'Item 2 is carrots.' 

```

不允许负列表索引。例如，模板变量

`{{ items.-1 }}` 会导致 `TemplateSyntaxError`。

### 注意

**Python 列表**

提醒：Python 列表是从 0 开始的索引。第一个项目在索引 0 处，第二个在索引 1 处，依此类推。

点查找可以总结如下：当模板系统在变量名称中遇到一个点时，它按照以下顺序尝试以下查找：

+   字典查找（例如，`foo["bar"]`）

+   属性查找（例如，`foo.bar`）

+   方法调用（例如，`foo.bar()`）

+   列表索引查找（例如，`foo[2]`）

系统使用第一个有效的查找类型。这是短路逻辑。点查找可以嵌套多层深。例如，以下示例使用 `{{ person.name.upper }}`，它转换为字典查找 (`person['name']`)，然后是方法调用 (`upper()`)：

```py
>>> from django.template import Template, Context 
>>> person = {'name': 'Sally', 'age': '43'} 
>>> t = Template('{{ person.name.upper }} is {{ person.age }} years old.') 
>>> c = Context({'person': person}) 
>>> t.render(c) 
'SALLY is 43 years old.' 

```

## 方法调用行为

方法调用比其他查找类型稍微复杂一些。以下是一些需要记住的事项：

+   如果在方法查找期间，方法引发异常，异常将被传播，除非异常具有一个值为 `True` 的 `silent_variable_failure` 属性。如果异常确实具有 `silent_variable_failure` 属性，则变量将呈现为引擎的 `string_if_invalid` 配置选项的值（默认情况下为空字符串）。例如：

```py
        >>> t = Template("My name is {{ person.first_name }}.") 
        >>> class PersonClass3: 
        ...     def first_name(self): 
        ...         raise AssertionError("foo") 
        >>> p = PersonClass3() 
        >>> t.render(Context({"person": p})) 
        Traceback (most recent call last): 
        ... 
        AssertionError: foo 

        >>> class SilentAssertionError(Exception): 
        ...     silent_variable_failure = True 
        >>> class PersonClass4: 
        ...     def first_name(self): 
        ...         raise SilentAssertionError 
        >>> p = PersonClass4() 
        >>> t.render(Context({"person": p})) 
        'My name is .' 

```

+   只有当方法没有必需的参数时，方法调用才能正常工作。否则，系统将转到下一个查找类型（列表索引查找）。

+   按设计，Django 有意限制了模板中可用的逻辑处理的数量，因此无法向从模板中访问的方法调用传递参数。数据应该在视图中计算，然后传递给模板进行显示。

+   显然，一些方法具有副作用，允许模板系统访问它们将是愚蠢的，甚至可能是一个安全漏洞。

+   比如，你有一个 `BankAccount` 对象，它有一个 `delete()` 方法。如果模板包含类似 `{{ account.delete }}` 的内容，其中 `account` 是一个 `BankAccount` 对象，那么当模板被渲染时，对象将被删除！为了防止这种情况发生，在方法上设置函数属性 `alters_data`：

```py
        def delete(self): 
        # Delete the account 
        delete.alters_data = True 

```

+   模板系统不会执行以这种方式标记的任何方法。继续上面的例子，如果模板包含 `{{ account.delete }}`，并且 `delete()` 方法具有 `alters_data=True`，那么在模板被渲染时，`delete()` 方法将不会被执行，引擎将用 `string_if_invalid` 替换变量。

+   **注意：** Django 模型对象上动态生成的 `delete()` 和 `save()` 方法会自动设置 `alters_data=true`。

## 如何处理无效变量

通常，如果变量不存在，模板系统会插入引擎的 `string_if_invalid` 配置选项的值，默认情况下为空字符串。例如：

```py
>>> from django.template import Template, Context 
>>> t = Template('Your name is {{ name }}.') 
>>> t.render(Context()) 
'Your name is .' 
>>> t.render(Context({'var': 'hello'})) 
'Your name is .' 
>>> t.render(Context({'NAME': 'hello'})) 
'Your name is .' 
>>> t.render(Context({'Name': 'hello'})) 
'Your name is .' 

```

这种行为比引发异常更好，因为它旨在对人为错误具有弹性。在这种情况下，所有的查找都失败了，因为变量名的大小写或名称错误。在现实世界中，由于小的模板语法错误导致网站无法访问是不可接受的。

# 基本模板标签和过滤器

正如我们已经提到的，模板系统附带了内置的标签和过滤器。接下来的部分将介绍最常见的标签和过滤器。

## 标签

### if/else

`{% if %}` 标签评估一个变量，如果该变量为 `True`（即存在，不为空，并且不是 `false` 布尔值），系统将显示 `{% if %}` 和 `{% endif %}` 之间的所有内容，例如：

```py
{% if today_is_weekend %} 
    <p>Welcome to the weekend!</p> 
{% endif %} 

```

`{% else %}` 标签是可选的：

```py
{% if today_is_weekend %} 
    <p>Welcome to the weekend!</p> 
{% else %} 
    <p>Get back to work.</p> 
{% endif %} 

```

`if` 标签也可以接受一个或多个 `{% elif %}` 子句：

```py
{% if athlete_list %} 
    Number of athletes: {{ athlete_list|length }} 
{% elif athlete_in_locker_room_list %} 
    <p>Athletes should be out of the locker room soon! </p> 
{% elif ... 
    ... 
{% else %} 
    <p>No athletes. </p> 
{% endif %} 

```

`{% if %}` 标签接受 and、or 或 not 用于测试多个变量，或者对给定变量取反。例如：

```py
{% if athlete_list and coach_list %} 
    <p>Both athletes and coaches are available. </p> 
{% endif %} 

{% if not athlete_list %} 
    <p>There are no athletes. </p> 
{% endif %} 

{% if athlete_list or coach_list %} 
    <p>There are some athletes or some coaches. </p> 
{% endif %} 

{% if not athlete_list or coach_list %} 
    <p>There are no athletes or there are some coaches. </p> 
{% endif %} 

{% if athlete_list and not coach_list %} 
    <p>There are some athletes and absolutely no coaches. </p> 
{% endif %} 

```

在同一个标签中使用 `and` 和 `or` 子句是允许的，其中 `and` 的优先级高于 `or`，例如：

```py
{% if athlete_list and coach_list or cheerleader_list %} 

```

将被解释为：

```py
if (athlete_list and coach_list) or cheerleader_list 

```

### 提示

注意：在 if 标签中使用实际括号是无效的语法。

如果需要使用括号表示优先级，应该使用嵌套的 if 标签。不支持使用括号来控制操作的顺序。如果发现自己需要括号，考虑在模板外执行逻辑，并将结果作为专用模板变量传递。或者，只需使用嵌套的 `{% if %}` 标签，就像这样：

```py
 {% if athlete_list %} 
     {% if coach_list or cheerleader_list %} 
         <p>We have athletes, and either coaches or cheerleaders! </p> 
     {% endif %} 
 {% endif %} 

```

同一个逻辑运算符的多次使用是可以的，但不能组合不同的运算符。例如，这是有效的：

```py
{% if athlete_list or coach_list or parent_list or teacher_list %} 

```

确保用 `{% endif %}` 来关闭每个 `{% if %}`。否则，Django 将抛出 `TemplateSyntaxError`。

### for

`{% for %}`标签允许您循环遍历序列中的每个项目。 与 Python 的`for`语句一样，语法是`for X in Y`，其中`Y`是要循环遍历的序列，`X`是用于循环的特定周期的变量的名称。 每次循环时，模板系统将呈现`{% for %}`和`{% endfor %}`之间的所有内容。 例如，您可以使用以下内容显示给定变量`athlete_list`的运动员列表：

```py
<ul> 
{% for athlete in athlete_list %} 
    <li>{{ athlete.name }}</li> 
{% endfor %} 
</ul> 

```

在标签中添加`reversed`以以相反的顺序循环遍历列表：

```py
{% for athlete in athlete_list reversed %} 
... 
{% endfor %} 

```

可以嵌套`{% for %}`标签：

```py
{% for athlete in athlete_list %} 
    <h1>{{ athlete.name }}</h1> 
    <ul> 
    {% for sport in athlete.sports_played %} 
        <li>{{ sport }}</li> 
    {% endfor %} 
    </ul> 
{% endfor %} 

```

如果需要循环遍历一个列表的列表，可以将每个子列表中的值解压缩为单独的变量。

例如，如果您的上下文包含一个名为`points`的（x，y）坐标列表，则可以使用以下内容输出点列表：

```py
{% for x, y in points %} 
    <p>There is a point at {{ x }},{{ y }}</p> 
{% endfor %} 

```

如果需要访问字典中的项目，则这也可能很有用。 例如，如果您的上下文包含一个名为`data`的字典，则以下内容将显示字典的键和值：

```py
{% for key, value in data.items %} 
    {{ key }}: {{ value }} 
{% endfor %} 

```

在循环之前检查列表的大小并在列表为空时输出一些特殊文本是一种常见模式：

```py
{% if athlete_list %} 

  {% for athlete in athlete_list %} 
      <p>{{ athlete.name }}</p> 
  {% endfor %} 

{% else %} 
    <p>There are no athletes. Only computer programmers.</p> 
{% endif %} 

```

由于这种模式很常见，`for`标签支持一个可选的`{% empty %}`子句，让您定义列表为空时要输出的内容。 此示例等效于上一个示例：

```py
{% for athlete in athlete_list %} 
    <p>{{ athlete.name }}</p> 
{% empty %} 
    <p>There are no athletes. Only computer programmers.</p> 
{% endfor %} 

```

没有支持在循环完成之前中断循环。 如果要实现此目的，请更改要循环遍历的变量，以便仅包括要循环遍历的值。

同样，不支持`continue`语句，该语句将指示循环处理器立即返回到循环的开头。 （有关此设计决定背后的原因，请参见本章后面的*哲学和限制*部分。）

在每个`{% for %}`循环中，您可以访问名为`forloop`的模板变量。 此变量具有一些属性，可为您提供有关循环进度的信息：

+   `forloop.counter`始终设置为表示循环已输入的次数的整数。 这是从 1 开始索引的，因此第一次循环时，`forloop.counter`将设置为`1`。 以下是一个示例：

```py
        {% for item in todo_list %} 
            <p>{{ forloop.counter }}: {{ item }}</p> 
        {% endfor %} 

```

+   `forloop.counter0`类似于`forloop.counter`，只是它是从零开始索引的。 它的值将在第一次循环时设置为`0`。

+   `forloop.revcounter`始终设置为表示循环中剩余项目数的整数。 第一次循环时，`forloop.revcounter`将设置为您正在遍历的序列中项目的总数。 最后一次循环时，`forloop.revcounter`将设置为`1`。

+   `forloop.revcounter0`类似于`forloop.revcounter`，只是它是从零开始索引的。 第一次循环时，`forloop.revcounter0`将设置为序列中的元素数减去`1`。 最后一次循环时，它将设置为`0`。

+   `forloop.first`是一个布尔值，如果这是第一次循环，则设置为`True`。 这对于特殊情况很方便：

```py
        {% for object in objects %} 
            {% if forloop.first %}<li class="first">
{% else %}<li>{% endif %} 
            {{ object }} 
            </li> 
        {% endfor %} 

```

+   `forloop.last`是一个布尔值，如果这是最后一次循环，则设置为`True`。 这的一个常见用法是在链接列表之间放置管道字符：

```py
        {% for link in links %} 
            {{ link }}{% if not forloop.last %} | {% endif %} 
        {% endfor %} 

```

+   前面的模板代码可能会输出类似于以下内容：

```py
        Link1 | Link2 | Link3 | Link4 

```

+   这种模式的另一个常见用法是在列表中的单词之间放置逗号：

```py
        Favorite places: 
        {% for p in places %}{{ p }}{% if not forloop.last %}, 
          {% endif %} 
        {% endfor %} 

```

+   `forloop.parentloop`是对父循环的`forloop`对象的引用，以防嵌套循环。 以下是一个示例：

```py
        {% for country in countries %} 
            <table> 
            {% for city in country.city_list %} 
                <tr> 
                <td>Country #{{ forloop.parentloop.counter }}</td> 
                <td>City #{{ forloop.counter }}</td> 
                <td>{{ city }}</td> 
                </tr> 
            {% endfor %} 
            </table> 
        {% endfor %} 

```

`forloop`变量仅在循环内部可用。 模板解析器达到`{% endfor %}`后，`forloop`将消失。

### 注意

上下文和 forloop 变量

在{% for %}块内，现有的变量被移出以避免覆盖`forloop`变量。Django 在`forloop.parentloop`中公开了这个移动的上下文。通常情况下，您不需要担心这一点，但如果您提供了一个名为`forloop`的模板变量（尽管我们建议不要这样做），它将在`{% for %}`块内被命名为`forloop.parentloop`。

### ifequal/ifnotequal

Django 模板系统不是一个完整的编程语言，因此不允许执行任意的 Python 语句。（有关这个想法的更多信息，请参见*哲学和限制*部分）。

但是，比较两个值并在它们相等时显示某些内容是一个常见的模板要求，Django 提供了一个`{% ifequal %}`标签来实现这个目的。

`{% ifequal %}`标签比较两个值，并显示两者之间的所有内容

`{% ifequal %}`和`{% endifequal %}`如果值相等。此示例比较模板变量`user`和`currentuser`：

```py
{% ifequal user currentuser %} 
    <h1>Welcome!</h1> 
{% endifequal %} 

```

参数可以是硬编码的字符串，可以是单引号或双引号，因此以下是有效的：

```py
{% ifequal section 'sitenews' %} 
    <h1>Site News</h1> 
{% endifequal %} 

{% ifequal section "community" %} 
    <h1>Community</h1> 
{% endifequal %} 

```

就像`{% if %}`一样，`{% ifequal %}`标签支持可选的`{% else %}`：

```py
{% ifequal section 'sitenews' %} 
    <h1>Site News</h1> 
{% else %} 
    <h1>No News Here</h1> 
{% endifequal %} 

```

只允许将模板变量、字符串、整数和十进制数作为`{% ifequal %}`的参数。这些是有效的示例：

```py
{% ifequal variable 1 %} 
{% ifequal variable 1.23 %} 
{% ifequal variable 'foo' %} 
{% ifequal variable "foo" %} 

```

任何其他类型的变量，例如 Python 字典、列表或布尔值，都不能在`{% ifequal %}`中进行硬编码。这些是无效的示例：

```py
{% ifequal variable True %} 
{% ifequal variable [1, 2, 3] %} 
{% ifequal variable {'key': 'value'} %} 

```

如果需要测试某些东西是真还是假，请使用`{% if %}`标签，而不是`{% ifequal %}`。

`ifequal`标签的替代方法是使用`if`标签和"`==`"运算符。

`{% ifnotequal %}`标签与`ifequal`标签相同，只是它测试两个参数是否不相等。`ifnotequal`标签的替代方法是使用`if`标签和"`!=`"运算符。

### 评论

就像在 HTML 或 Python 中一样，Django 模板语言允许使用注释。要指定注释，请使用`{# #}`：

```py
{# This is a comment #} 

```

当模板呈现时，注释不会被输出。使用这种语法的注释不能跨越多行。这种限制提高了模板解析的性能。

在下面的模板中，呈现的输出将与模板完全相同（即，注释标签不会被解析为注释）：

```py
This is a {# this is not 
a comment #} 
test. 

```

如果要使用多行注释，请使用`{% comment %}`模板标签，如下所示：

```py
{% comment %} 
This is a 
multi-line comment. 
{% endcomment %} 

```

评论标签不能嵌套。

## 过滤器

正如本章前面所解释的，模板过滤器是在显示变量值之前修改变量值的简单方法。过滤器使用管道字符，如下所示：

```py
 {{ name|lower }} 

```

这将显示经过`lower`过滤器过滤后的`{{ name }}`变量的值，该过滤器将文本转换为小写。过滤器可以链接-也就是说，它们可以串联使用，以便将一个过滤器的输出应用于下一个过滤器。

以下是一个示例，它获取列表中的第一个元素并将其转换为大写：

```py
 {{ my_list|first|upper }} 

```

一些过滤器需要参数。过滤器参数在冒号后面，总是用双引号括起来。例如：

```py
 {{ bio|truncatewords:"30" }} 

```

这将显示`bio`变量的前 30 个单词。

以下是一些最重要的过滤器。附录 E，*内置模板标签和过滤器*涵盖了其余部分。

+   `addslashes`：在任何反斜杠、单引号或双引号之前添加一个反斜杠。这对于转义字符串很有用。例如：

```py
        {{ value|addslashes }} 

```

+   `date`：根据参数中给定的格式字符串格式化`date`或`datetime`对象，例如：

```py
        {{ pub_date|date:"F j, Y" }} 

```

+   格式字符串在附录 E 中定义，*内置模板标签和过滤器*。

+   `length`：返回值的长度。对于列表，这将返回元素的数量。对于字符串，这将返回字符的数量。如果变量未定义，`length`返回`0`。

# 哲学和限制

现在你对**Django 模板语言**（DTL）有了一定的了解，现在可能是时候解释 DTL 背后的基本设计理念了。首先，**DTL 的限制是有意的。**

Django 是在在线新闻编辑室这样一个高频率、不断变化的环境中开发的。Django 的原始创作者在创建 DTL 时有一套非常明确的哲学。

这些理念至今仍然是 Django 的核心。它们是：

1.  将逻辑与呈现分开

1.  防止冗余

1.  与 HTML 解耦

1.  XML 很糟糕

1.  假设设计师有能力

1.  显而易见地处理空格

1.  不要发明一种编程语言

1.  确保安全性

1.  可扩展

以下是对此的解释：

1.  **将逻辑与呈现分开**

模板系统是控制呈现和与呈现相关逻辑的工具——仅此而已。模板系统不应该支持超出这一基本目标的功能。

1.  **防止冗余**

大多数动态网站使用某种常见的站点范围设计——共同的页眉、页脚、导航栏等等。Django 模板系统应该能够轻松地将这些元素存储在一个地方，消除重复的代码。这就是模板继承背后的哲学。

1.  **与 HTML 解耦**

模板系统不应该被设计成只输出 HTML。它应该同样擅长生成其他基于文本的格式，或者纯文本。

1.  **不应该使用 XML 作为模板语言**

使用 XML 引擎解析模板会在编辑模板时引入一整套新的人为错误，并且在模板处理中产生不可接受的开销。

1.  **假设设计师有能力**

模板系统不应该设计成模板必须在诸如 Dreamweaver 之类的所见即所得编辑器中显示得很好。这太严重了，不会允许语法像现在这样好。

Django 期望模板作者能够舒适地直接编辑 HTML。

1.  **显而易见地处理空格**

模板系统不应该对空格做魔术。如果模板包含空格，系统应该像对待文本一样对待空格——只是显示它。任何不在模板标记中的空格都应该显示出来。

1.  **不要发明一种编程语言**

模板系统有意不允许以下情况：

+   变量赋值

+   高级逻辑

目标不是发明一种编程语言。目标是提供足够的编程式功能，如分支和循环，这对于做出与呈现相关的决策至关重要。

Django 模板系统认识到模板通常是由设计师而不是程序员编写的，因此不应假设有 Python 知识。

1.  **安全性**

模板系统应该默认禁止包含恶意代码，比如删除数据库记录的命令。这也是模板系统不允许任意 Python 代码的另一个原因。

1.  **可扩展性**

模板系统应该认识到高级模板作者可能想要扩展其技术。这就是自定义模板标记和过滤器背后的哲学。

多年来我使用过许多不同的模板系统，我完全支持这种方法——DTL 及其设计方式是 Django 框架的主要优点之一。

当压力来临，需要完成任务时，你既有设计师又有程序员试图沟通并完成所有最后一分钟的任务时，Django 只是让每个团队专注于他们擅长的事情。

一旦你通过实际实践发现了这一点，你会很快发现为什么 Django 真的是*完美主义者的截止日期框架*。

考虑到这一切，Django 是灵活的——它不要求你使用 DTL。与 Web 应用程序的任何其他组件相比，模板语法是高度主观的，程序员的观点差异很大。Python 本身有数十，甚至数百个开源模板语言实现，这一点得到了支持。每一个可能都是因为其开发者认为所有现有的模板语言都不够好而创建的。

因为 Django 旨在成为一个提供所有必要组件的全栈 Web 框架，以使 Web 开发人员能够高效工作，所以大多数情况下更方便使用 DTL，但这并不是严格的要求。

# 在视图中使用模板

你已经学会了使用模板系统的基础知识；现在让我们利用这些知识来创建一个视图。

回想一下`mysite.views`中的`current_datetime`视图，我们在上一章中开始了。它看起来是这样的：

```py
from django.http import HttpResponse 
import datetime 

def current_datetime(request): 

    now = datetime.datetime.now() 
    html = "<html><body>It is now %s.</body></html>" % now 
    return HttpResponse(html) 

```

让我们更改这个视图以使用 Django 的模板系统。起初，你可能会想要做类似这样的事情：

```py
from django.template import Template, Context 
from django.http import HttpResponse 
import datetime 

def current_datetime(request): 

    now = datetime.datetime.now() 
    t = Template("<html><body>It is now {{ current_date }}. 
         </body></html>") 
    html = t.render(Context({'current_date': now})) 
    return HttpResponse(html) 

```

当然，这使用了模板系统，但它并没有解决我们在本章开头指出的问题。也就是说，模板仍然嵌入在 Python 代码中，因此没有真正实现数据和呈现的分离。让我们通过将模板放在一个单独的文件中来解决这个问题，这个视图将会加载。

你可能首先考虑将模板保存在文件系统的某个位置，并使用 Python 的内置文件打开功能来读取模板的内容。假设模板保存为文件`/home/djangouser/templates/mytemplate.html`，那么可能会是这样：

```py
from django.template import Template, Context 
from django.http import HttpResponse 
import datetime 

def current_datetime(request): 

    now = datetime.datetime.now() 
    # Simple way of using templates from the filesystem. 
    # This is BAD because it doesn't account for missing files! 
    fp = open('/home/djangouser/templates/mytemplate.html') 
    t = Template(fp.read()) 
    fp.close() 

    html = t.render(Context({'current_date': now})) 
    return HttpResponse(html) 

```

然而，这种方法是不够优雅的，原因如下：

+   它没有处理文件丢失的情况。如果文件`mytemplate.html`不存在或不可读，`open()`调用将引发`IOError`异常。

+   它会将模板位置硬编码。如果你要为每个视图函数使用这种技术，你将会重复模板位置。更不用说这需要大量的输入！

+   它包含了大量乏味的样板代码。你有更好的事情要做，而不是每次加载模板时都写`open()`、`fp.read()`和`fp.close()`的调用。

为了解决这些问题，我们将使用模板加载和模板目录。

# 模板加载

Django 提供了一个方便而强大的 API，用于从文件系统加载模板，目的是消除模板加载调用和模板本身中的冗余。为了使用这个模板加载 API，首先你需要告诉框架你存储模板的位置。这个地方就是你的设置文件——我在上一章中提到的`settings.py`文件。如果你在跟着做，打开你的`settings.py`文件，找到`TEMPLATES`设置。这是一个配置列表，每个引擎一个：

```py
TEMPLATES = [ 
    { 
        'BACKEND': 'django.template.backends.django.DjangoTemplates', 
        'DIRS': [], 
        'APP_DIRS': True, 
        'OPTIONS': { 
            # ... some options here ... 
        }, 
    }, 
] 

```

`BACKEND`是一个点分隔的 Python 路径，指向实现 Django 模板后端 API 的模板引擎类。内置的后端是`django.template.backends.django.DjangoTemplates`和`django.template.backends.jinja2.Jinja2`。由于大多数引擎从文件加载模板，每个引擎的顶级配置包含三个常见的设置：

+   `DIRS`定义了引擎应该在其中查找模板源文件的目录列表，按搜索顺序排列。

+   `APP_DIRS`告诉引擎是否应该在已安装的应用程序内查找模板。按照惯例，当`APPS_DIRS`设置为`True`时，`DjangoTemplates`会在每个`INSTALLED_APPS`的"templates"子目录中查找。这允许模板引擎即使`DIRS`为空也能找到应用程序模板。

+   `OPTIONS`包含特定于后端的设置。

虽然不常见，但是可以配置多个具有不同选项的相同后端实例。在这种情况下，你应该为每个引擎定义一个唯一的`NAME`。

## 模板目录

默认情况下，`DIRS`是一个空列表。要告诉 Django 的模板加载机制在哪里查找模板，选择一个您想要存储模板的目录，并将其添加到`DIRS`中，如下所示：

```py
'DIRS': [ 
           '/home/html/example.com', 
           '/home/html/default', 
       ], 

```

有几件事情需要注意：

+   除非您正在构建一个没有应用程序的非常简单的程序，否则最好将`DIRS`留空。默认设置文件将`APP_DIRS`配置为`True`，因此最好在 Django 应用程序中有一个`templates`子目录。

+   如果您想在项目根目录下拥有一组主模板，例如`mysite/templates`，您确实需要设置`DIRS`，如下所示：

+   'DIRS': [os.path.join(BASE_DIR, 'templates')],

+   顺便说一句，您的模板目录不一定要被称为`'templates'`，Django 对您使用的名称没有任何限制，但是如果您遵循惯例，您的项目结构会更容易理解。

+   如果您不想使用默认设置，或者由于某些原因无法使用默认设置，您可以指定任何您想要的目录，只要该目录和该目录中的模板可被您的 Web 服务器运行的用户帐户读取。

+   如果您使用 Windows，请包括您的驱动器号，并使用 Unix 风格的正斜杠而不是反斜杠，如下所示：

```py
        'DIRS': [
        'C:/www/django/templates',
        ]
```

由于我们还没有创建 Django 应用程序，因此您必须根据上面的示例将`DIRS`设置为`[os.path.join(BASE_DIR, 'templates')]`，以使下面的代码按预期工作。设置了`DIRS`之后，下一步是更改视图代码，使用 Django 的模板加载功能而不是硬编码模板路径。回到我们的`current_datetime`视图，让我们像这样进行更改：

```py
from django.template.loader import get_template 
from django.template import Context 
from django.http import HttpResponse 
import datetime 

def current_datetime(request): 
    now = datetime.datetime.now() 
    t = get_template('current_datetime.html') 
    html = t.render(Context({'current_date': now})) 
    return HttpResponse(html) 

```

在这个例子中，我们使用了函数`django.template.loader.get_template()`而不是手动从文件系统加载模板。`get_template()`函数以模板名称作为参数，找出模板在文件系统上的位置，打开该文件，并返回一个编译的`Template`对象。在这个例子中，我们的模板是`current_datetime.html`，但`.html`扩展名并没有什么特别之处。您可以为您的应用程序指定任何扩展名，或者完全不使用扩展名。为了确定模板在文件系统上的位置，`get_template()`将按顺序查找：

+   如果`APP_DIRS`设置为`True`，并且假设您正在使用 DTL，它将在当前应用程序中查找`templates`目录。

+   如果它在当前应用程序中找不到您的模板，`get_template()`将从`DIRS`中组合您传递给`get_template()`的模板名称，并按顺序逐个查找，直到找到您的模板。例如，如果您的`DIRS`中的第一个条目设置为`'/home/django/mysite/templates'`，那么前面的`get_template()`调用将查找模板`/home/django/mysite/templates/current_datetime.html`。

+   如果`get_template()`找不到给定名称的模板，它会引发`TemplateDoesNotExist`异常。

要查看模板异常的样子，再次启动 Django 开发服务器，方法是在 Django 项目目录中运行`python manage.py runserver`。然后，将浏览器指向激活`current_datetime`视图的页面（例如`http://127.0.0.1:8000/time/`）。假设您的`DEBUG`设置为`True`，并且您还没有创建`current_datetime.html`模板，您应该会看到一个 Django 错误页面，突出显示`TemplateDoesNotExist`错误（*图 3.1*）。

![模板目录](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_03_001.jpg)

图 3.1：缺少模板错误页面。

这个错误页面与我在第二章中解释的类似，*视图和 URLconfs*，只是增加了一个额外的调试信息部分：*模板加载器事后调查*部分。该部分告诉您 Django 尝试加载的模板，以及每次尝试失败的原因（例如，**文件不存在**）。当您尝试调试模板加载错误时，这些信息是非常宝贵的。接下来，使用以下模板代码创建`current_datetime.html`文件：

```py
It is now {{ current_date }}. 

```

将此文件保存到`mysite/templates`（如果尚未创建`templates`目录，则创建该目录）。刷新您的网络浏览器页面，您应该看到完全呈现的页面。

# render()

到目前为止，我们已经向您展示了如何加载模板，填充`Context`并返回一个包含呈现模板结果的`HttpResponse`对象。下一步是优化它，使用`get_template()`代替硬编码模板和模板路径。我带您通过这个过程是为了确保您了解 Django 模板是如何加载和呈现到您的浏览器的。

实际上，Django 提供了一个更简单的方法来做到这一点。Django 的开发人员意识到，因为这是一个常见的习语，Django 需要一个快捷方式，可以在一行代码中完成所有这些。这个快捷方式是一个名为`render()`的函数，它位于模块`django.shortcuts`中。

大多数情况下，您将使用`render()`而不是手动加载模板和创建`Context`和`HttpResponse`对象-除非您的雇主根据编写的代码总行数来评判您的工作。

以下是使用`render()`重写的持续`current_datetime`示例：

```py
from django.shortcuts import render 
import datetime 

def current_datetime(request): 
    now = datetime.datetime.now() 
    return render(request, 'current_datetime.html',  
                  {'current_date': now}) 

```

有何不同！让我们逐步了解代码更改：

+   我们不再需要导入`get_template`，`Template`，`Context`或`HttpResponse`。相反，我们导入`django.shortcuts.render`。`import datetime`保持不变。

+   在`current_datetime`函数中，我们仍然计算`now`，但模板加载、上下文创建、模板渲染和`HttpResponse`创建都由`render()`调用处理。因为`render()`返回一个`HttpResponse`对象，所以我们可以在视图中简单地`return`该值。

`render()`的第一个参数是请求，第二个是要使用的模板的名称。如果给出第三个参数，应该是用于为该模板创建`Context`的字典。如果不提供第三个参数，`render()`将使用一个空字典。

# 模板子目录

将所有模板存储在单个目录中可能会变得难以管理。您可能希望将模板存储在模板目录的子目录中，这也是可以的。

事实上，我建议这样做；一些更高级的 Django 功能（例如通用视图系统，我们在第十章中介绍，*通用视图*）期望这种模板布局作为默认约定。

在模板目录的子目录中存储模板很容易。在对`get_template()`的调用中，只需包括子目录名称和模板名称之前的斜杠，就像这样：

```py
t = get_template('dateapp/current_datetime.html') 

```

因为`render()`是围绕`get_template()`的一个小包装器，你可以用`render()`的第二个参数做同样的事情，就像这样：

```py
return render(request, 'dateapp/current_datetime.html',  
              {'current_date': now}) 

```

您的子目录树的深度没有限制。随意使用尽可能多的子目录。

### 注意

Windows 用户，请确保使用正斜杠而不是反斜杠。`get_template()`假定 Unix 风格的文件名指定。

# 包含模板标签

现在我们已经介绍了模板加载机制，我们可以介绍一个利用它的内置模板标签：`{% include %}`。此标签允许您包含另一个模板的内容。标签的参数应该是要包含的模板的名称，模板名称可以是变量，也可以是硬编码（带引号）的字符串，可以是单引号或双引号。

每当您在多个模板中有相同的代码时，请考虑使用`{% include %}`来消除重复。这两个示例包括模板`nav.html`的内容。这两个示例是等效的，并且说明单引号和双引号都是允许的：

```py
{% include 'nav.html' %} 
{% include "nav.html" %} 

```

此示例包括模板`includes/nav.html`的内容：

```py
{% include 'includes/nav.html' %} 

```

此示例包括变量`template_name`中包含的模板的内容：

```py
{% include template_name %} 

```

与`get_template()`一样，模板的文件名是通过将当前 Django 应用程序中的`templates`目录的路径添加到模板名称（如果`APPS_DIR`为`True`）或将`DIRS`中的模板目录添加到请求的模板名称来确定的。包含的模板将使用包含它们的模板的上下文进行评估。

例如，考虑这两个模板：

```py
# mypage.html 

<html><body> 

{% include "includes/nav.html" %} 

<h1>{{ title }}</h1> 
</body></html> 

# includes/nav.html 

<div id="nav"> 
    You are in: {{ current_section }} 
</div> 

```

如果您使用包含`current_section`的上下文渲染`mypage.html`，那么该变量将在`included`模板中可用，就像您期望的那样。

如果在`{% include %}`标记中找不到给定名称的模板，Django 将执行以下两种操作之一：

+   如果`DEBUG`设置为`True`，您将在 Django 错误页面上看到`TemplateDoesNotExist`异常。

+   如果`DEBUG`设置为`False`，标记将会静默失败，在标记的位置显示空白。

### 注意

包含的模板之间没有共享状态-每个包含都是完全独立的渲染过程。

块在被包含之前被评估。这意味着包含另一个模板的模板将包含已经被评估和渲染的块，而不是可以被另一个扩展模板覆盖的块。

# 模板继承

到目前为止，我们的模板示例都是小型的 HTML 片段，但在现实世界中，您将使用 Django 的模板系统来创建整个 HTML 页面。这导致了一个常见的 Web 开发问题：在整个网站中，如何减少常见页面区域的重复和冗余，比如整个站点的导航？

解决这个问题的经典方法是使用服务器端包含，您可以在 HTML 页面中嵌入的指令来包含一个网页在另一个网页中。事实上，Django 支持这种方法，刚刚描述的`{% include %}`模板标记。

但是，使用 Django 解决这个问题的首选方法是使用一种更优雅的策略，称为模板继承。实质上，模板继承允许您构建一个包含站点所有常见部分并定义子模板可以覆盖的“块”的基本“骨架”模板。让我们通过编辑`current_datetime.html`文件来看一个更完整的模板示例，为我们的`current_datetime`视图创建一个更完整的模板：

```py
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"> 
<html lang="en"> 
<head> 
    <title>The current time</title> 
</head> 
<body> 
    <h1>My helpful timestamp site</h1> 
    <p>It is now {{ current_date }}.</p> 

    <hr> 
    <p>Thanks for visiting my site.</p> 
</body> 
</html> 

```

看起来很好，但是当我们想要为另一个视图创建一个模板时会发生什么-比如，来自第二章的`hours_ahead`视图，*视图和 URLconfs*？如果我们再次想要创建一个漂亮的有效的完整 HTML 模板，我们会创建类似于以下内容：

```py
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"> 
<html lang="en"> 

<head> 
    <title>Future time</title> 
</head> 

<body> 
    <h1>My helpful timestamp site</h1> 
    <p>In {{ hour_offset }} hour(s), it will be {{ next_time }}.</p> 

    <hr> 
    <p>Thanks for visiting my site.</p> 
</body> 
</html> 

```

显然，我们刚刚复制了大量的 HTML。想象一下，如果我们有一个更典型的网站，包括导航栏、一些样式表，也许还有一些 JavaScript-我们最终会在每个模板中放入各种冗余的 HTML。

解决这个问题的服务器端包含解决方案是将两个模板中的共同部分分解出来，并将它们保存在单独的模板片段中，然后在每个模板中包含它们。也许您会将模板的顶部部分存储在名为`header.html`的文件中：

```py
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"> 
<html lang="en"> 
<head> 

```

也许您会将底部部分存储在名为`footer.html`的文件中：

```py
    <hr> 
    <p>Thanks for visiting my site.</p> 
</body> 
</html> 

```

使用基于包含的策略，标题和页脚很容易。中间部分很混乱。在这个示例中，两个页面都有一个标题-*我的有用的时间戳站*-但是这个标题无法放入`header.html`，因为两个页面上的标题是不同的。如果我们在头部包含 h1，我们就必须包含标题，这样就无法根据页面自定义它。

Django 的模板继承系统解决了这些问题。您可以将其视为服务器端包含的内部版本。您不是定义常见的片段，而是定义不同的片段。

第一步是定义一个基本模板-稍后子模板将填写的页面骨架。以下是我们正在进行的示例的基本模板：

```py
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"> 
<html lang="en"> 

<head> 
    <title>{% block title %}{% endblock %}</title> 
</head> 

<body> 
    <h1>My helpful timestamp site</h1> 
    {% block content %}{% endblock %} 
    {% block footer %} 
    <hr> 
    <p>Thanks for visiting my site.</p> 
    {% endblock %} 
</body> 
</html> 

```

这个模板，我们将其称为`base.html`，定义了一个简单的 HTML 骨架文档，我们将用于站点上的所有页面。

子模板的工作是覆盖、添加或保留块的内容。 （如果您在跟踪，请将此文件保存到模板目录中，命名为`base.html`。）

我们在这里使用了一个您以前没有见过的模板标记：`{% block %}`标记。所有`{% block %}`标记所做的就是告诉模板引擎，子模板可以覆盖模板的这些部分。

现在我们有了这个基本模板，我们可以修改我们现有的`current_datetime.html`模板来使用它：

```py
{% extends "base.html" %} 

{% block title %}The current time{% endblock %} 

{% block content %} 
<p>It is now {{ current_date }}.</p> 
{% endblock %} 

```

趁热打铁，让我们为本章的`hours_ahead`视图创建一个模板。（如果您正在使用代码进行跟踪，我将让您自己决定将`hours_ahead`更改为使用模板系统而不是硬编码的 HTML。）以下是可能的样子：

```py
{% extends "base.html" %} 

{% block title %}Future time{% endblock %} 

{% block content %} 

<p>In {{ hour_offset }} hour(s), it will be {{ next_time }}.</p> 
{% endblock %} 

```

这不是很美吗？每个模板只包含该模板独有的代码。不需要冗余。如果您需要对整个站点进行设计更改，只需对`base.html`进行更改，所有其他模板将立即反映出更改。

这就是它的工作原理。当您加载模板`current_datetime.html`时，模板引擎会看到`{% extends %}`标记，并注意到这个模板是一个子模板。引擎立即加载父模板-在这种情况下是`base.html`。

此时，模板引擎注意到`base.html`中的三个`{% block %}`标记，并用子模板的内容替换这些块。因此，我们在`{% block title %}`中定义的标题将被使用，`{% block content %}`也将被使用。

请注意，由于子模板未定义页脚块，模板系统将使用父模板中的值。在

父模板中的`{% block %}`标记始终用作备用。

继承不会影响模板上下文。换句话说，继承树中的任何模板都可以访问上下文中的每个模板变量。您可以使用所需的任意级别的继承。使用继承的一种常见方式是以下三级方法：

1.  创建一个包含站点主要外观和感觉的`base.html`模板。这通常是很少或几乎不会更改的东西。

1.  为站点的每个部分创建一个`base_SECTION.html`模板（例如，`base_photos.html`和`base_forum.html`）。这些模板扩展`base.html`并包括特定于部分的样式/设计。

1.  为每种类型的页面创建单独的模板，例如论坛页面或照片库。这些模板扩展适当的部分模板。

这种方法最大程度地提高了代码的重用性，并使向共享区域添加项目变得容易，比如整个部分的导航。以下是一些使用模板继承的指导方针：

+   如果您在模板中使用`{% extends %}`，它必须是该模板中的第一个模板标记。否则，模板继承将无法工作。

+   通常，基本模板中有更多的`{% block %}`标记，越好。请记住，子模板不必定义所有父块，因此您可以在许多块中填写合理的默认值，然后仅在子模板中定义您需要的块。拥有更多的钩子比拥有更少的钩子更好。

+   如果您发现自己在许多模板中重复使用代码，这可能意味着您应该将该代码移动到父模板中的`{% block %}`中。

+   如果您需要从父模板获取块的内容，请使用 `{{ block.super }}`，这是一个提供父模板呈现文本的 "魔术" 变量。如果您想要添加到父块的内容而不是完全覆盖它，这将非常有用。

+   您可能不会在同一个模板中定义多个具有相同名称的 `{% block %}` 标签。这种限制存在是因为块标签在 "两个" 方向上起作用。也就是说，块标签不仅提供要填充的空白，还定义了填充父级空白的内容。如果模板中有两个类似命名的 `{% block %}` 标签，那么该模板的父级将不知道使用哪个块的内容。

+   您传递给 `{% extends %}` 的模板名称是使用 `get_template()` 使用的相同方法加载的。也就是说，模板名称将附加到您的 `DIRS` 设置，或者当前 Django 应用程序中的 "templates" 文件夹。

+   在大多数情况下，`{% extends %}` 的参数将是一个字符串，但它也可以是一个变量，如果您直到运行时才知道父模板的名称。这让您可以做一些很酷的、动态的事情。

# 接下来是什么？

现在您已经掌握了 Django 模板系统的基础知识。接下来呢？大多数现代网站都是数据库驱动的：网站的内容存储在关系数据库中。这允许对数据和逻辑进行清晰的分离（就像视图和模板允许逻辑和显示的分离一样）。下一章介绍了 Django 提供的与数据库交互的工具。
