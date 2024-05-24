# Flask 蓝图（一）

> 原文：[`zh.annas-archive.org/md5/53AA49F14B72D97DBF009B5C4214AEF0`](https://zh.annas-archive.org/md5/53AA49F14B72D97DBF009B5C4214AEF0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

情景很熟悉：你是一名网页开发者，已经使用过几种编程语言、框架和环境，决定学习足够的 Python 来制作一些玩具网页应用程序。也许你已经使用过一些 Python 网页框架来构建一个或两个应用程序，并且想探索一些你一直听说过的替代选项。

这通常是人们了解 Flask 的方式。

作为一个微框架，Flask 旨在帮助你，然后不再干涉你。与大多数其他通用网页框架采取非常不同的方法，Flask 由一个非常小的核心组成，处理和规范化 HTTP 和 WSGI 规范（通过 Werkzeug），并提供一个非常好的模板语言（通过 Jinja2）。Flask 的美妙之处在于其固有的可扩展性：由于它从一开始就被设计为做得很少，因此也很容易扩展。这样做的一个愉快的结果是，你不必受制于特定的数据库抽象层、身份验证协议或缓存机制。

学习一个新的框架不仅仅是学习提供给你的基本功能和对象：同样重要的是学习如何调整框架以帮助你构建应用程序的特定要求。

本书将演示如何使用 Python 网页微框架开发一系列网页应用程序项目，并利用扩展和外部 Python 库/API 来扩展各种更大更复杂的网页应用程序的开发。

# 本书内容

第一章，“从正确的角度开始-使用 Virtualenv”，开始了我们对 Python 网页应用程序开发的深入探讨，介绍了使用和管理虚拟环境来隔离应用程序依赖关系的基础知识。我们将研究安装和分发可重用的 Python 代码包的设置工具、pip、库和实用程序，以及 virtualenv，这是一个用于创建项目的基于 Python 软件要求的隔离环境的工具。我们还将讨论这些工具无法做到的事情，并研究 virtualenvwrapper 抽象，以增强 virtualenv 提供的功能。

第二章，“从小到大-扩展 Flask 应用程序结构”，探讨了你可能考虑为 Flask 应用程序考虑的各种基线布局和配置。随着我们从最简单的单文件应用程序结构逐渐进展到更复杂的多包蓝图架构，我们概述了每种方法的利弊。

第三章，“Snap-代码片段共享应用程序”，构建了我们的第一个简单的 Flask 应用程序，重点是学习最流行的关系数据库抽象之一，SQLAlchemy，以及一些最流行的 Flask 扩展：Flask-Login 用于处理经过身份验证的用户登录会话，Flask-Bcrypt 确保帐户密码以安全方式存储，Flask-WTF 用于创建和处理基于表单的输入数据。

第四章，“Socializer-可测试的时间轴”，为社交网页应用程序构建了一个非常简单的数据模型，主要关注使用 pytest，Python 测试框架和工具进行单元和功能测试。我们还将探讨应用程序工厂模式的使用，该模式允许我们为简化测试目的实例化我们应用程序的不同版本。此外，详细描述了 Blinker 库提供的常常被省略（和遗忘）的信号的使用和创建。

第五章，*Shutterbug，Photo Stream API*，围绕基于 JSON 的 API 构建了一个应用程序的框架，这是当今任何现代 Web 应用程序的要求。我们使用了许多基于 API 的 Flask 扩展之一，Flask-RESTful，用于原型设计 API，我们还深入研究了无状态系统的简单身份验证机制，并在此过程中编写了一些测试。我们还短暂地进入了 Werkzeug 的世界，这是 Flask 构建的 WSGI 工具包，用于构建自定义 WSGI 中间件，允许无缝处理基于 URI 的版本号，以适应我们新生 API 的需求。

第六章，*Hublot – Flask CLI Tools*，涵盖了大多数 Web 应用程序框架讨论中经常省略的一个主题：命令行工具。解释了 Flask-Script 的使用，并创建了几个基于 CLI 的工具，以与我们应用程序的数据模型进行交互。此外，我们将构建我们自己的自定义 Flask 扩展，用于包装现有的 Python 库，以从 GitHub API 获取存储库和问题信息。

第七章，*Dinnerly – Recipe Sharing*，介绍了 OAuth 授权流程的概念，这是许多大型 Web 应用程序（如 Twitter、Facebook 和 GitHub）实施的，以允许第三方应用程序代表帐户所有者行事，而不会损害基本帐户安全凭据。为食谱共享应用程序构建了一个简单的数据模型，允许所谓的社交登录以及将数据从我们的应用程序跨发布到用户连接的服务的 feeds 或 streams。最后，我们将介绍使用 Alembic 的数据库迁移的概念，它允许您以可靠的方式将 SQLAlchemy 模型元数据与基础关系数据库表的模式同步。

# 本书需要什么

要完成本书中大多数示例的操作，您只需要您喜欢的文本编辑器或 IDE，访问互联网（以安装各种 Flask 扩展，更不用说 Flask 本身了），一个关系数据库（SQLite、MySQL 或 PostgreSQL 之一），一个浏览器，以及对命令行的一些熟悉。我们已经注意到了在每一章中完成示例所需的额外软件包或库。

# 本书适合谁

本书是为希望深入了解 Web 应用程序开发世界的新 Python 开发人员，或者对学习 Flask 及其背后的基于扩展的生态系统感兴趣的经验丰富的 Python Web 应用程序专业人士而创建的。要充分利用每一章，您应该对 Python 编程语言有扎实的了解，对关系数据库系统有基本的了解，并且熟练掌握命令行。

# 约定

本书中，您将找到许多不同类型信息的文本样式。以下是一些样式的示例，以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："这将创建一个空的`app1`环境并激活它。您应该在 shell 提示符中看到一个（app1）标签。"

代码块设置如下：

```py
[default]
  <div>{{ form.password.label }}: {{ form.password }}</div>
  {% if form.password.errors %}
  <ul class="errors">{% for error in form.password.errors %}<li>{{ error }}</li>{% endfor %}</ul>
  {% endif %}

  <div><input type="submit" value="Sign up!"></div>
</form>

{% endblock %}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目以粗体显示：

```py
    from application.users.views import users
    app.register_blueprint(users, url_prefix='/users')

 from application.posts.views import posts
 app.register_blueprint(posts, url_prefix='/posts')

        # …
```

任何命令行输入或输出都以以下方式编写：

```py
$ source ~/envs/testing/bin/activate
(testing)$ pip uninstall numpy

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这样的方式出现在文本中："然后它断言返回的 HTML 中出现了**注册！**按钮文本"。

### 注意

警告或重要说明显示在这样的框中。

### 提示

提示和技巧显示如下。


# 第一章：正确开始——使用 Virtualenv

现代软件开发中的一个巨大困难是依赖管理。一般来说，软件项目的依赖关系包括所需的库或组件，以使项目能够正确运行。对于 Flask 应用程序（更一般地说，对于 Python 应用程序），大多数依赖关系由特别组织和注释的源文件组成。创建后，这些源文件包可以包含在其他项目中，依此类推。对于一些人来说，这种依赖链可能变得难以管理，当链中的任何库发生细微变化时，可能会导致一系列不兼容性，从而使进一步的开发陷入停滞。在 Python 世界中，正如您可能已经知道的那样，可重用的源文件的基本单元是 Python 模块（包含定义和语句的文件）。一旦您在本地文件系统上创建了一个模块，并确保它在系统的 PYTHONPATH 中，将其包含在新创建的项目中就像指定导入一样简单，如下所示：

```py
import the_custom_module

```

其中`the_custom_module.py`是一个存在于执行程序系统的`$PYTHONPATH`中的文件。

### 注意：

`$PYTHONPATH`可以包括对压缩存档（`.zip`文件夹）的路径，除了正常的文件路径。

当然，故事并不会在这里结束。虽然最初在本地文件系统中散布模块可能很方便，但当您想要与他人共享一些您编写的代码时会发生什么？通常，这将涉及通过电子邮件/Dropbox 发送相关文件，然而，这显然是一个非常繁琐且容易出错的解决方案。幸运的是，这是一个已经被考虑过并且已经在缓解常见问题方面取得了一些进展的问题。其中最重要的进展之一是本章的主题，以及如何利用以下创建可重用的、隔离的代码包的技术来简化 Flask 应用程序的开发：

+   使用 pip 和 setuptools 进行 Python 打包

+   使用 virtualenv 封装虚拟环境

各种 Python 打包范例/库提出的解决方案远非完美；与热情的 Python 开发者争论的一种肯定方式是宣称*打包问题*已经解决！我们在这方面还有很长的路要走，但通过改进 setuptools 和其他用于构建、维护和分发可重用 Python 代码的库，我们正在逐步取得进展。

在本章中，当我们提到一个包时，我们实际上要谈论的是一个分发——一个从远程源安装的软件包——而不是一个使用`the__init__.py`约定来划分包含我们想要导入的模块的文件夹结构的集合。

# Setuptools 和 pip

当开发人员希望使他们的代码更广泛可用时，首要步骤之一将是创建一个与 setuptools 兼容的包。

现代 Python 版本的大多数发行版将已经安装了 setuptools。如果您的系统上没有安装它，那么获取它相对简单，官方文档中还提供了额外的说明：

```py
wget https://bootstrap.pypa.io/ez_setup.py -O - | python

```

安装了 setuptools 之后，创建兼容包的基本要求是在项目的根目录创建一个`setup.py`文件。该文件的主要内容应该是调用`setup()`函数，并带有一些强制（和许多可选）参数，如下所示：

```py
from setuptools import setup

setup(
 name="My Great Project",
 version="0.0.1",
 author="Jane Doe",
 author_email="jane@example.com",
 description= "A brief summary of the project.",
 license="BSD",
 keywords="example tutorial flask",
 url="http://example.com/my-great-project",
 packages=['foobar','tests'],
 long_description="A much longer project description.",
 classifiers=[
 "Development Status :: 3 - Alpha",
 "Topic :: Utilities",
 "License :: OSI Approved :: BSD License",
 ],
)

```

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt Publishing 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

一旦软件包被创建，大多数开发人员将选择使用 setuptools 本身提供的内置工具将他们新创建的软件包上传到 PyPI——几乎所有 Python 软件包的官方来源。虽然使用特定的公共 PyPI 存储库并不是必需的（甚至可以设置自己的个人软件包索引），但大多数 Python 开发人员都希望在这里找到他们的软件包。

这将引出拼图中另一个至关重要的部分——`pip` Python 软件包安装程序。如果您已安装 Python 2.7.9 或更高版本，则`pip`将已经存在。某些发行版可能已经为您预安装了它，或者它可能存在于系统级软件包中。对于类似 Debian 的 Linux 发行版，可以通过以下命令安装它：

```py
apt-get install python-pip

```

同样，其他基于 Linux 的发行版将有他们自己推荐的软件包管理器。如果您更愿意获取源代码并手动安装，只需获取文件并使用 Python 解释器运行即可：

```py
$ curl -o get-pip.py https://bootstrap.pypa.io/get-pip.py
$ python get-pip.py

```

Pip 是一个用于安装 Python 软件包的工具（本身也是一个 Python 软件包）。虽然它不是唯一的选择，但`pip`是迄今为止使用最广泛的。

### 注意

`pip`的前身是`easy_install`，在 Python 社区中已经大部分被后者取代。`easy_install`模块存在一些相当严重的问题，比如允许部分安装、无法卸载软件包而需要用户手动删除相关的`.egg`文件，以及包含有用的成功和错误消息的控制台输出，允许开发人员在出现问题时确定最佳操作方式。

可以在命令行中调用 pip 来在本地文件系统上安装科学计算软件包，比如说：

```py
$ pip install numpy

```

上述命令将查询默认的 PyPI 索引，寻找名为`numpy`的软件包，并将最新版本下载到系统的特定位置，通常是`/usr/local/lib/pythonX.Y/site-packages`（`X`和`Y`是`pip`指向的 Python 版本的主/次版本）。此操作可能需要 root 权限，因此需要`sudo`或类似的操作来完成。

虚拟环境的许多好处之一是，它们通常避免了对已安装软件包进行系统级更改时可能出现的权限提升要求。

一旦此操作成功完成，您现在可以将`numpy`软件包导入新模块，并使用它提供的所有功能：

```py
import numpy

x = numpy.array([1, 2, 3])
sum = numpy.sum(x)
print sum  # prints 6

```

一旦我们安装了这个软件包（或者其他任何软件包），就没有什么可以阻止我们以通常的方式获取其他软件包。此外，我们可以通过将它们的名称作为`install`命令的附加参数来一次安装多个软件包：

```py
$ pip install scipy pandas # etc.

```

# 避免依赖地狱，Python 的方式

新开发人员可能会想要安装他们遇到的每个有趣的软件包。这样做的话，他们可能会意识到这很快就会变成一个卡夫卡式的情况，先前安装的软件包可能会停止工作，新安装的软件包可能会表现得不可预测，如果它们成功安装的话。前述方法的问题，正如你们中的一些人可能已经猜到的那样，就是冲突的软件包依赖关系。例如，假设我们安装了软件包`A`；它依赖于软件包`Q`的版本 1 和软件包`R`的版本 1。软件包`B`依赖于软件包`R`的版本 2（其中版本 1 和 2 不兼容）。Pip 将愉快地为您安装软件包`B`，这将升级软件包`R`到版本 2。这将使软件包`A`在最好的情况下完全无法使用，或者在最坏的情况下，使其以未记录和不可预测的方式行为。

Python 生态系统已经提出了一个解决从俗称为**依赖地狱**中产生的基本问题的解决方案。虽然远非完美，但它允许开发人员规避在 Web 应用程序开发中可能出现的许多最简单的软件包版本依赖冲突。

`virtualenv`工具（Python 3.3 中的默认模块`venv`）是必不可少的，以确保最大限度地减少陷入依赖地狱的机会。以下引用来自`virtualenv`官方文档的介绍部分：

> *它创建一个具有自己安装目录的环境，不与其他 virtualenv 环境共享库（也可以选择不访问全局安装的库）。*

更简洁地说，`virtualenv`允许您为每个 Python 应用程序（或任何 Python 代码）创建隔离的环境。

### 注意

`virtualenv`工具不会帮助您管理 Python 基于 C 的扩展的依赖关系。例如，如果您从`pip`安装`lxml`软件包，它将需要您拥有正确的`libxml2`和`libxslt`系统库和头文件（它将链接到）。`virtualenv`工具将无法帮助您隔离这些系统级库。

# 使用 virtualenv

首先，我们需要确保在本地系统中安装了`virtualenv`工具。这只是从 PyPI 存储库中获取它的简单事情：

```py
$ pip install virtualenv

```

### 注意

出于明显的原因，应该在可能已经存在的任何虚拟环境之外安装这个软件包。

## 创建新的虚拟环境

创建新的虚拟环境很简单。以下命令将在指定路径创建一个新文件夹，其中包含必要的结构和脚本，包括默认 Python 二进制文件的完整副本：

```py
$ virtualenv <path/to/env/directory>

```

如果我们想创建一个位于`~/envs/testing`的环境，我们首先要确保父目录存在，然后调用以下命令：

```py
$ mkdir -p ~/envs
$ virtualenv ~/envs/testing

```

在 Python 3.3+中，一个大部分与 API 兼容的`virtualenv`工具被添加到默认语言包中。模块的名称是`venv`，然而，允许您创建虚拟环境的脚本的名称是`pyvenv`，可以以与先前讨论的`virtualenv`工具类似的方式调用：

```py
$ mkdir -p ~/envs
$ pyvenv ~/envs/testing

```

## 激活和停用虚拟环境

创建虚拟环境不会自动激活它。环境创建后，我们需要激活它，以便对 Python 环境进行任何修改（例如安装软件包）将发生在隔离的环境中，而不是我们系统的全局环境中。默认情况下，激活虚拟环境将更改当前活动用户的提示字符串（`$PS1`），以便显示所引用的虚拟环境的名称：

```py
$ source ~/envs/testing/bin/activate
(testing) $ # Command prompt modified to display current virtualenv

```

Python 3.3+的命令是相同的：

```py
$ source ~/envs/testing/bin/activate
(testing) $ # Command prompt modified to display current virtualenv

```

当您运行上述命令时，将发生以下一系列步骤：

1.  停用任何已激活的环境。

1.  使用`virtualenv bin/`目录的位置在您的`$PATH`变量之前添加，例如`~/envs/testing/bin:$PATH`。

1.  如果存在，则取消设置`$PYTHONHOME`。

1.  修改您的交互式 shell 提示，以包括当前活动的`virtualenv`的名称。

由于`$PATH`环境变量的操作，通过激活环境的 shell 调用的 Python 和`pip`二进制文件（以及通过`pip`安装的其他二进制文件）将包含在`~/envs/testing/bin`中。

## 向现有环境添加包

我们可以通过简单激活它，然后以以下方式调用`pip`来轻松向虚拟环境添加包：

```py
$ source ~/envs/testing/bin/activate
(testing)$ pip install numpy

```

这将把`numpy`包安装到测试环境中，只有测试环境。您的全局系统包不受影响，以及任何其他现有环境。

## 从现有环境中卸载包

卸载`pip`包也很简单：

```py
$ source ~/envs/testing/bin/activate
(testing)$ pip uninstall numpy

```

这将仅从测试环境中删除`numpy`包。

这是 Python 软件包管理存在相对重要的一个地方：卸载一个包不会卸载它的依赖项。例如，如果安装包`A`并安装依赖包`B`和`C`，则以后卸载包`A`将不会卸载`B`和`C`。

# 简化常见操作-使用 virtualenvwrapper 工具

我经常使用的一个工具是`virtualenvwrapper`，它是一组非常智能的默认值和命令别名，使得使用虚拟环境更直观。现在让我们将其安装到我们的全局系统中：

```py
$ pip install virtualenvwrapper

```

### 注意

这也将安装`virtualenv`包，以防它尚未存在。

接下来，您需要将以下行添加到您的 shell 启动文件的末尾。这很可能是`~/.bashrc`，但是如果您已将默认 shell 更改为其他内容，例如`zsh`，那么它可能会有所不同（例如`~/.zshrc`）：

```py
export WORKON_HOME=$HOME/.virtualenvs
source /usr/local/bin/virtualenvwrapper.sh

```

在上述代码块的第一行指示使用`virtualenvwrapper`创建的新虚拟环境应存储在`$HOME/.virtualenvs`中。您可以根据需要修改此设置，但我通常将其保留为一个很好的默认值。我发现将所有虚拟环境放在我的主目录中的同一个隐藏文件夹中可以减少个别项目中的混乱，并使误将整个虚拟环境添加到版本控制变得更加困难。

### 注意

将整个虚拟环境添加到版本控制可能看起来像一个好主意，但事情从来不像看起来那么简单。一旦运行稍微（或完全）不同的操作系统的人决定下载您的项目，其中包括可能包含针对您自己的架构编译的`C`模块的包的完整`virtualenv`文件夹，他们将很难使事情正常工作。

相反，pip 支持并且许多开发人员使用的常见模式是在虚拟环境中冻结已安装包的当前状态，并将其保存到`requirements.txt`文件中：

```py
(testing) $ pip freeze > requirements.txt

```

然后，该文件可以添加到**版本控制系统**（**VCS**）中。由于该文件的目的是声明应用程序所需的依赖关系，而不是提供它们或指示如何构建它们，因此您的项目的用户可以自由选择以任何方式获取所需的包。通常，他们会通过`pip`安装它们，`pip`可以很好地处理要求文件：

```py
(testing) $ pip install –r  requirements.txt

```

第二行在当前 shell 环境中添加了一些方便的别名，以创建、激活、切换和删除环境：

+   `mkvirtualenv test`：这将创建一个名为 test 的环境并自动激活它。

+   `mktmpenv test`：这将创建一个名为 test 的临时环境并自动激活它。一旦调用停用脚本，此环境将被销毁。

+   `workon app`：这将切换到 app 环境（已经创建）。

+   `workon`（`alias lsvirtualenv`）：当您不指定环境时，这将打印所有可用的现有环境。

+   `deactivate`：如果有的话，这将禁用当前活动的环境。

+   `rmvirtualenv app`：这将完全删除 app 环境。

我们将使用以下命令创建一个环境来安装我们的应用程序包：

```py
$ mkvirtualenv app1

```

这将创建一个空的`app1`环境并激活它。您应该在 shell 提示符中看到一个（`app1`）标签。

### 注意

如果您使用的是 Bash 或 ZSH 之外的 shell，此环境标签可能会出现也可能不会出现。这样的工作方式是，用于激活虚拟环境的脚本还会修改当前的提示字符串（`PS1`环境变量），以便指示当前活动的`virtualenv`。因此，如果您使用非常特殊或非标准的 shell 配置，则有可能无法正常工作。

# 摘要

在本章中，我们看到了任何非平凡的 Python 应用程序都面临的最基本的问题之一：库依赖管理。值得庆幸的是，Python 生态系统已经开发了被广泛采用的`virtualenv`工具，用于解决开发人员可能遇到的最常见的依赖问题子集。

此外，我们还介绍了一个工具`virtualenvwrapper`，它抽象了一些使用`virtualenv`执行的最常见操作。虽然我们列出了这个软件包提供的一些功能，但`virtualenvwrapper`可以做的事情更加广泛。我们只是在这里介绍了基础知识，但如果您整天都在使用 Python 虚拟环境，深入了解这个工具能做什么是不可或缺的。


# 第二章：从小到大-扩展 Flask 应用程序结构

Flask 是一个很棒的框架，适合想要编写一个非常快速的单文件应用程序以原型化 API 或构建一个非常简单的网站的人。然而，不那么明显的是，Flask 在更大、更模块化的应用程序结构中的灵活性和能力，这在单模块布局变得更加繁琐而不再方便时是必不可少的。本章我们将涵盖的主要要点如下：

+   如何将基于模块的 Flask 应用程序转换为基于包的布局

+   如何在基于包的应用程序结构上实现 Flask 蓝图

+   如何确保我们的结果应用程序可以使用内置的 Werkzeug 开发服务器运行

# 你的第一个 Flask 应用程序结构

在官方网站上找到的典型的 Flask 入门应用程序是简单的典范，这是你很可能以前就遇到过的：

```py
# app.py 
from flask import Flask
app = Flask(__name__)

@app.route("/")
def hello():
 return "Hello World!"

if __name__ == "__main__":
app.run()

```

首先通过从`pip`安装`Flask`包（当然是在虚拟环境中），然后在 Python 解释器下执行脚本来运行前面的应用程序：

```py
$ pip install Flask
$ python app.py

```

这将启动 Werkzeug 开发 Web 服务器，默认情况下会在`http://localhost:5000`上为`Flask`通过`pip`获取时安装的应用程序提供服务。

人们启动新的`Flask`应用程序的典型方式是向我们在前一节中展示的非常简单的模块添加各种端点：

```py
from flask import Flask, request
app = Flask(__name__)

@app.route("/")
def hello():
 return "Hello World!"

@app.route("/contact")
def contact():
 return "You can contact me at 555-5555, or "
 " email me at test@example.com"

@app.route('/login', methods=['GET', 'POST'])
def login():
 if request.method == 'POST':
 # Logic for handling login
 pass
 else:
 # Display login form
 pass

if __name__ == "__main__":
 app.run()

```

虽然直观，但是一旦应用程序的复杂性增加，这种方法的缺点就变得明显起来：

+   模块中的函数定义数量几乎与我们想要路由到的 URL 数量成线性增长。虽然这不是一个固有的缺点，但开发人员应该更喜欢将功能拆分成更容易理解的小包。

+   路由所需的模板和静态文件积累在同一子文件夹位置，因此使它们的组织更加复杂和容易出错。

+   某些操作（例如日志记录）在按包配置而不是在一个庞大的模块中配置时会变得更简单。

# 从模块到包

可以对基于模块的 Flask 应用程序应用的最简单的结构变化是将其转换为典型的 Python 包，并特别考虑静态和模板文件夹。

```py
application
└──application
    ├──__init__.py
    ├──static
    │  ├──app.js
    │  └──styles.css
    └──templates
         ├──index.html
         └──layout.html
```

在这里，我们创建了一个顶级应用程序包，将`app.py`模块以及`static`和`template`文件夹放入其中，并将其重命名为`__init__.py`。

### 注意

`__init__.py`文件是一个文件夹被视为有效的 Python 包所必需的。

此时应该处理的一个细节是用于运行开发服务器的代码。如果你还记得，单模块应用程序包含以下条件语句：

```py
if __name__ == "__main__":
 app.run()

```

这使我们能够直接用 Python 解释器执行模块文件，如下所示：

```py
$ python app.py
* Running on http://localhost:5000/

```

出于各种原因，这不再是一个可行的选择。然而，我们仍然希望以简单的方式运行开发服务器。为此，我们将创建一个`run.py`文件，作为内部`application`包文件夹的同级：

```py
├──application
│  ├──__init__.py
│  ├──static
│  │  ├──app.js
│  │  └──styles.css
│  └──templates
│  ├──index.html
│  └──layout.html
└──run.py
```

在`run.py`文件中，我们将添加以下片段：

```py
from application import app
app.run()

```

这使我们能够通过 CLI 调用以下命令以通常的方式运行开发服务器：

```py
$ python run.py

```

### 注意

通常情况下，在`__init__.py`包中包含修改状态的代码（例如创建 Flask 应用程序对象）被认为是一种不好的做法。我们现在只是为了说明目的而这样做。

我们的 Flask 应用程序对象的`run`方法可以接受一些可选参数。以下是最有用的几个：

+   `host`：要绑定的主机 IP。默认为任何端口，用`0.0.0.0`表示。

+   `port`：应用程序将绑定到的端口。默认为`5000`。

+   `debug`：如果设置为`True`，Werkzeug 开发服务器在检测到代码更改时将重新加载，并在发生未处理的异常时在 HTML 页面中提供一个交互式调试器。

在我们在前一节中概述的新应用程序结构中，很容易看到功能，比如路由处理程序定义，可以从`__init__.py`中拆分成类似`views.py`模块的东西。同样，我们的数据模型可以被分解成一个`models.py`模块，如下所示：

```py
application
├──application
│  ├──__init__.py
│  ├──models.py
│  ├──static
│  │  ├──app.js
│  │  └──styles.css
│  ├──templates
│  │  ├──index.html
│  │  └──layout.html
│  └──views.py
└──run.py

```

我们只需要在`__init__.py`中导入这些模块，以确保在运行应用程序时它们被加载：

```py
from flask import Flask
app = Flask(__name__)

import application.models
import application.views

```

### 注意

请注意，我们需要在实例化应用程序对象后导入视图，否则将创建循环导入。一旦我们开始使用蓝图开发应用程序，我们通常会尽量避免循环导入，确保一个蓝图不从另一个蓝图中导入。

同样，我们必须在`views.py`模块中导入 Flask 应用程序对象，以便我们可以使用`@app.route`装饰器来定义我们的路由处理程序：

```py
from application import app

@app.route("/")
def hello():
 return "Hello World!"

@app.route("/contact")
def contact():
 return "You can contact me at 555-5555, or "
 " email me at test@example.com"

@app.route('/login', methods=['GET', 'POST'])
def login():
 if request.method == 'POST':
 # Logic for handling login
 pass
 else:
 # Display login form
 pass

```

如预期的那样，应用程序仍然可以像以前一样使用内置的 Werkzeug 应用程序服务器从**命令行界面**（**CLI**）运行；唯一改变的是我们文件的组织。我们获得的优势（以额外文件的代价和可能出现循环导入的可能性）是功能分离和组织：我们的视图处理程序可以根据其感兴趣的领域在单个或多个模块中分组，我们的数据层和实用函数可以存在于应用程序结构的其他位置。

# 从包到蓝图

我们刚刚探讨的基于包的应用程序结构可能适用于大量的应用程序。然而，Flask 为我们提供了一种抽象级别**即蓝图**，它在视图层面上规范和强制实施了关注点的分离。

### 注意

不要将 Flask 中的蓝图概念与同名的 Packt 图书系列的概念混淆！

一个变得过于笨重的 Flask 应用程序可以被分解成一组离散的蓝图——每个蓝图都有自己的 URI 映射和视图函数、静态资源（例如 JavaScript 和 CSS 文件）、Jinja 模板，甚至 Flask 扩展。在许多方面，蓝图与 Flask 应用程序本身非常相似。但是，蓝图不是独立的 Flask 应用程序，不能作为独立的应用程序运行，如官方 Flask 文档中所述：

> *在 Flask 中，蓝图不是可插拔应用程序，因为它实际上不是一个应用程序——它是一组可以在应用程序上注册的操作，甚至可以多次注册。—官方 Flask 文档，[`flask.pocoo.org/docs/0.10/blueprints/`](http://flask.pocoo.org/docs/0.10/blueprints/)*

因此，应用程序中的所有蓝图将共享相同的主应用程序对象和配置，并且它们必须在 URI 分发之前向主 Flask 对象注册。

## 我们的第一个蓝图

以前基于包的应用程序布局可以通过首先添加一个新的包来包含我们的蓝图来扩展为基于蓝图的架构，我们将简单地称之为`users`：

```py
├──application
│  ├──__init__.py
│  └──users
│  ├──__init__.py
│  └──views.py
└──run.py

```

`users`包的内容包括必需的`__init__.py`和另一个模块`views.py`。我们（现在只是简单的）`users`蓝图的视图函数将放在`views.py`模块中：

```py
from flask import Blueprint

users = Blueprint('users', __name__)

@users.route('/me')
def me():
 return "This is my page.", 200

```

### 注意

我们本可以将这段代码放在`users/__init__.py`文件中，而不是将其分离成自己的`views.py`模块；但这样做的话，我们将会在包初始化中放置一个产生副作用的代码（即，实例化用户蓝图对象），这通常是不被赞同的。将其分离成一个不同的模块会带来一些额外的复杂性，但将会在以后避免一些麻烦。

在这个新模块中，我们从 Flask 中导入了`Blueprint`类，并用它来实例化了一个`users`蓝图对象。`Blueprint`类有两个必需的参数，`name`和`import_name`，我们提供的是`users`和`__name__`，这是所有 Python 模块和脚本都可以使用的全局魔术属性。前者可以是我们所需的所有注册蓝图中的任何唯一标识符，后者应该是实例化蓝图对象的模块的名称。

一旦我们完成了这一步，我们必须修改我们在`application/__init__.py`中的应用程序初始化，以便将蓝图绑定到 Flask 应用程序对象：

```py
from flask import Flask
from application.users.views import users

app = Flask(__name__)
app.register_blueprint(users, url_prefix='/users')

```

在将蓝图对象注册到应用程序实例时，可以指定几个可选参数。其中一个参数是`url_prefix`，它将自动为所讨论的蓝图中定义的所有路由添加给定字符串的前缀。这使得封装所有视图和路由变得非常简单，这些视图和路由用于处理以`/users/*` URI 段开头的任何端点的请求，这是我们在本书中经常使用的一种模式。

完成后，我们可以通过我们的`run.py`脚本以通常的方式使用内置的 Werkzeug 应用程序服务器来运行我们的应用程序：

```py
$ python run.py

```

打开我们选择的浏览器并导航到`http://localhost:5000/users/me`会产生以下渲染结果：

![我们的第一个蓝图](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-bp/img/3965_02_01.jpg)

# 总结

在本章中，我们从最常见的简单 Flask 应用程序架构开始，并探讨了一些扩展它的方法，以实现更模块化的方法。我们首先从基于模块的布局转向基于包的布局，然后升级到使用 Flask 蓝图，为我们在接下来的章节中使用的基本应用程序结构铺平了道路。

在下一章中，我们将利用在这里获得的知识，通过使用蓝图模式和几个众所周知的 Flask 扩展来创建我们的第一个功能性 Flask 应用程序。


# 第三章：Snap - 代码片段共享应用程序

在本章中，我们将构建我们的第一个完全功能的、基于数据库的应用程序。这个应用程序，代号 Snap，将允许用户使用用户名和密码创建帐户。用户将被允许登录、注销、添加和列出所谓的半私密*snaps*文本，这些文本可以与其他人分享。

本章中，您应该熟悉以下至少一种关系数据库系统：PostgreSQL、MySQL 或 SQLite。此外，对 SQLAlchemy Python 库的一些了解将是一个优势，它充当这些（以及其他几个）数据库的抽象层和对象关系映射器。如果您对 SQLAlchemy 的使用不熟悉，不用担心。我们将对该库进行简要介绍，以帮助新开发人员迅速上手，并为经验丰富的开发人员提供复习。

从现在开始，在本书中，SQLite 数据库将是我们选择的关系数据库。我们列出的其他数据库系统都是基于客户端/服务器的，具有多种配置选项，可能需要根据安装的系统进行调整，而 SQLite 的默认操作模式是独立、无服务器和零配置。

我们建议您使用 SQLite 来处理这个项目和接下来的章节中的项目，但 SQLAlchemy 支持的任何主要关系数据库都可以。

# 入门

为了确保我们正确开始，让我们创建一个项目存在的文件夹和一个虚拟环境来封装我们将需要的任何依赖项：

```py
$ mkdir -p ~/src/snap && cd ~/src/snap
$ mkvirtualenv snap -i flask

```

这将在给定路径创建一个名为`snap`的文件夹，并带我们到这个新创建的文件夹。然后它将在这个环境中创建 snap 虚拟环境并安装 Flask。

### 注意

请记住，`mkvirtualenv`工具将创建虚拟环境，这将是从`pip`安装软件包的默认位置集，但`mkvirtualenv`命令不会为您创建项目文件夹。这就是为什么我们将首先运行一个命令来创建项目文件夹，然后再创建虚拟环境。虚拟环境通过激活环境后执行的`$PATH`操作完全独立于文件系统中项目文件的位置。

然后，我们将使用基本的基于蓝图的项目布局创建一个空的用户蓝图。所有文件的内容几乎与我们在上一章末尾描述的内容相同，布局应该如下所示：

```py
application
├── __init__.py
├── run.py
└── users
    ├── __init__.py
    ├── models.py
    └── views.py

```

## Flask-SQLAlchemy

一旦上述文件和文件夹被创建，我们需要安装下一个重要的一组依赖项：SQLAlchemy 和使与该库交互更类似于 Flask 的 Flask 扩展，Flask-SQLAlchemy：

```py
$ pip install flask-sqlalchemy

```

这将安装 Flask 扩展到 SQLAlchemy 以及后者的基本分发和其他几个必要的依赖项，以防它们尚未存在。

现在，如果我们使用的是除 SQLite 之外的关系数据库系统，这就是我们将在其中创建数据库实体的时刻，比如在 PostgreSQL 中，以及创建适当的用户和权限，以便我们的应用程序可以创建表并修改这些表的内容。然而，SQLite 不需要任何这些。相反，它假设任何可以访问数据库文件系统位置的用户也应该有权限修改该数据库的内容。

在本章的后面，我们将看到如何通过 SQLAlchemy 自动创建 SQLite 数据库文件。然而，为了完整起见，这里是如何在文件系统的当前文件夹中创建一个空数据库：

```py
$ sqlite3 snap.db  # hit control-D to escape out of the interactive SQL console if necessary.

```

### 注意

如前所述，我们将使用 SQLite 作为示例应用程序的数据库，并且给出的指示将假定正在使用 SQLite；二进制文件的确切名称可能在您的系统上有所不同。如果使用的不是 SQLite，您可以替换等效的命令来创建和管理您选择的数据库。

现在，我们可以开始对 Flask-SQLAlchemy 扩展进行基本配置。

### 配置 Flask-SQLAlchemy

首先，我们必须在`application/__init__.py`文件中将 Flask-SQLAlchemy 扩展注册到`application`对象中：

```py
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../snap.db'
db = SQLAlchemy(app)

```

`app.config['SQLALCHEMY_DATABASE_URI']`的值是我们之前创建的`snap.db SQLite`数据库的转义相对路径。一旦这个简单的配置就位，我们就能够通过`db.create_all()`方法自动创建 SQLite 数据库，这可以在交互式 Python shell 中调用：

```py
$  python
>>>from application import db
>>>db.create_all()

```

这是一个幂等操作，这意味着即使数据库已经存在，也不会发生任何变化。然而，如果本地数据库文件不存在，它将被创建。这也适用于添加新的数据模型：运行`db.create_all()`将它们的定义添加到数据库，确保相关表已被创建并且可访问。然而，它并不考虑已经存在于数据库中的现有模型/表定义的修改。为此，您需要使用相关工具（例如 sqlite CLI，或者迁移工具如 Alembic，我们将在后面的章节中讨论）来修改相应的表定义，以匹配您模型中已更新的定义。

### SQLAlchemy 基础知识

SQLAlchemy 首先是一个与 Python 中的关系数据库进行交互的工具包。

虽然它提供了令人难以置信的多种功能，包括各种数据库引擎的 SQL 连接处理和连接池、处理自定义数据类型的能力以及全面的 SQL 表达式 API，但大多数开发人员熟悉的功能是对象关系映射器。这个映射器允许开发人员将 Python 对象定义与他们选择的数据库中的 SQL 表连接起来，从而使他们能够灵活地控制自己应用程序中的领域模型，并且只需要最小的耦合到数据库产品和引擎特定的 SQL 特性。

虽然在本章讨论对象关系映射器的有用性（或缺乏有用性）超出了范围，但对于那些不熟悉 SQLAlchemy 的人，我们将提供使用这个工具带来的好处清单，如下所示：

+   您的领域模型是为了与最受尊敬、经过测试和部署的 Python 包之一——SQLAlchemy 进行交互而编写的。

+   由于有关使用 SQLAlchemy 的广泛文档、教程、书籍和文章，将新开发人员引入项目变得更加容易。

+   查询的验证是在模块导入时使用 SQLAlchemy 表达式语言完成的，而不是针对数据库执行每个查询字符串以确定是否存在语法错误。表达式语言是用 Python 编写的，因此可以使用您通常的一套工具和 IDE 进行验证。

+   由于实现了设计模式，如工作单元、身份映射和各种延迟加载特性，开发人员通常可以避免执行比必要更多的数据库/网络往返。考虑到典型 Web 应用程序中请求/响应周期的大部分很容易归因于各种类型的网络延迟，最小化典型响应中的数据库查询数量在多个方面都是性能上的胜利。

+   虽然许多成功的高性能应用程序可以完全建立在 ORM 上，但 SQLAlchemy 并不强制要求这样做。如果出于某种原因，更倾向于编写原始的 SQL 查询字符串或直接使用 SQLAlchemy 表达语言，那么您可以这样做，并仍然从 SQLAlchemy 本身的连接池和 Python DBAPI 抽象功能中受益。

既然我们已经给出了几个理由，说明为什么应该使用这个数据库查询和领域数据抽象层，让我们看看如何定义一个基本的数据模型。

#### 声明式映射和 Flask-SQLAlchemy

SQLAlchemy 实现了一种称为**数据映射器**的设计模式。基本上，这个数据映射器的工作是在代码中桥接数据模型的定义和操作（在我们的情况下，Python 类定义）以及数据库中这个数据模型的表示。映射器应该知道代码相关的操作（例如，对象构造、属性修改等）如何与我们选择的数据库中的 SQL 特定语句相关联，确保在我们映射的 Python 对象上执行的操作与它们关联的数据库表正确同步。

我们可以通过两种方式将 SQLAlchemy 集成到我们的应用程序中：通过使用提供表、Python 对象和数据映射一致集成的声明式映射，或者通过手动指定这些关系。此外，还可以使用所谓的 SQLAlchemy“核心”，它摒弃了基于数据域的方法，而是基于 SQL 表达语言构造，这些构造包含在 SQLAlchemy 中。

在本章（以及将来的章节）中，我们将使用声明式方法。

要使用声明式映射功能，我们需要确保我们定义的任何模型类都将继承自 Flask-SQLAlchemy 提供给我们的声明基类`Model`类（一旦我们初始化了扩展）：

```py
from application import db

class User(db.Model):
 # model attributes
 pass

```

这个`Model`类本质上是`sqlalchemy.ext.declarative.declarative_base`类的一个实例（带有一些额外的默认值和有用的功能），它为对象提供了一个元类，该元类将处理适当的映射构造。

一旦我们在适当的位置定义了我们的模型类定义，我们将通过使用`Column`对象实例来定义通过类级属性映射的相关 SQL 表的详细信息。Column 调用的第一个参数是我们想要对属性施加的类型约束（对应于数据库支持的特定模式数据类型），以及类型支持的任何可选参数，例如字段的大小。还可以提供其他参数来指示对生成的表字段定义的约束：

```py
class User(db.Model):

 id = db.Column(db.Integer, primary_key=True)
 email = db.Column(db.String(255), unique=True)
 username = db.Column(db.String(40), unique=True)

```

### 注意

如前所述，仅仅定义属性并不会自动转换为数据库中的新表和列。为此，我们需要调用`db.create_all()`来初始化表和列的定义。

我们可以轻松地创建此模型的实例，并为我们在类定义中声明的属性分配一些值：

```py
$ (snap) python
>>>from application.users.models import User
>>>new_user = User(email="me@example.com", username="me")
>>>new_user.email
'me@example.com'
>>>new_user.username
'me'

```

### 注意

您可能已经注意到，我们的用户模型没有定义`__init__`方法，但当实例化上面的示例时，我们能够将`email`和`username`参数传递给对象构造函数。这是 SQLAlchemy 声明基类的一个特性，它会自动将命名参数在对象构造时分配给它们的对象属性对应项。因此，通常不需要为数据模型定义一个具体的构造方法。

模型对象的实例化并不意味着它已经持久化到数据库中。为此，我们需要通知 SQLAlchemy 会话，我们希望添加一个新对象以进行跟踪，并将其提交到数据库中：

```py
>>>from application import db
>>>db.session.add(new_user)
>>>db.session.commit()

```

一旦对象被提交，`id`属性将获得底层数据库引擎分配给它的主键值：

```py
>>>print(new_user.id)
1

```

如果我们想修改属性的值，例如，更改特定用户的电子邮件地址，我们只需要分配新值，然后提交更改：

```py
>>>new_user.email = 'new@example.com'
>>>db.session.add(new_user)
>>>db.session.commit()
>>>print(new_user.email)
u'new@example.com'

```

此时，您可能已经注意到在任何以前的操作中都没有编写过一行 SQL，并且可能有点担心您创建的对象中嵌入的信息没有持久保存到数据库中。对数据库的粗略检查应该让您放心：

```py
$ sqlite3 snap.db
SQLite version 3.8.5 2014-08-15 22:37:57
Enter ".help" for usage hints.
sqlite> .tables
user
sqlite> .schema user
CREATE TABLE user (
 id INTEGER NOT NULL,
 email VARCHAR(255),
 username VARCHAR(40),
 PRIMARY KEY (id),
 UNIQUE (email),
 UNIQUE (username)
);
sqlite> select * from user;
1|new@example.com|me

```

### 注意

请记住，SQLite 二进制文件的确切名称可能会因您选择的操作系统而异。此外，如果您选择了除 SQLite 之外的数据库引擎来跟随这些示例，相关的命令和结果可能会大相径庭。

就是这样：SQLAlchemy 成功地在幕后管理了相关的 SQL INSERT 和 UPDATE 语句，让我们可以使用本机 Python 对象，并在准备将数据持久保存到数据库时通知会话。

当然，我们不仅限于定义类属性。在许多情况下，声明模型上的实例方法可能会证明很有用，以便我们可以执行更复杂的数据操作。例如，想象一下，我们需要获取给定用户的主键 ID，并确定它是偶数还是奇数。方法声明将如你所期望的那样：

```py
class User(db.Model):

 id = db.Column(db.Integer, primary_key=True)
 email = db.Column(db.String(255), unique=True)
 username = db.Column(db.String(40), unique=True)

def is_odd_id(self):
 return (self.id % 2 != 0)

```

实例方法调用可以像往常一样执行，但在将对象提交到会话之前，主键值将为 none：

```py
$ (snap)  python
Python 2.7.10 (default, Jul 13 2015, 23:27:37)
[GCC 4.2.1 Compatible Apple LLVM 6.1.0 (clang-602.0.53)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>>fromapplication.users.models import User
>>>test = User(email='method@example.com', username='method_test')
>>>from application import db
>>>db.session.add(test)
>>>db.session.commit()
>>> test.id
2
>>>test.is_odd_id()
False

```

当然，在大多数 Web 应用程序的上下文中，前面的实现是微不足道且有些毫无意义的。然而，定义模型实例方法以编码业务逻辑的能力非常方便，我们将在本章后面看到 Flask-Login 扩展中的一些内容。

### 快照数据模型

现在我们已经探索了 SQLAlchemy 声明基础和 Flask-SQLAlchemy 扩展的基础知识，使用了一个简化的模型，我们的下一步是完善一个用户数据模型，这是几乎任何 Web 应用程序的基石。我们将在用户蓝图中创建这个模型，在一个新的`users/models.py`模块中利用我们对 SQLAlchemy 模型的知识，为用户`password`和`created_on`字段添加字段，以存储记录创建的时间。此外，我们将定义一些实例方法：

```py
import datetime
from application import db

class User(db.Model):

 # The primary key for each user record.
 id = db.Column(db.Integer, primary_key=True)

 # The unique email for each user record.
 email = db.Column(db.String(255), unique=True)

 # The unique username for each record.
 username = db.Column(db.String(40), unique=True)

 # The hashed password for the user
 password = db.Column(db.String(60))

#  The date/time that the user account was created on.
 created_on = db.Column(db.DateTime, 
 default=datetime.datetime.utcnow)

 def __repr__(self):
 return '<User {!r}>'.format(self.username)

 def is_authenticated(self):
 """All our registered users are authenticated."""
 return True

 def is_active(self):
 """All our users are active."""
 return True

 def is_anonymous(self):
 """We don)::f):lf):"""users are authenticated."""
 return False

 def get_id(self):
 """Get the user ID as a Unicode string."""
 return unicode(self.id)

```

`is_authenticated`、`is_active`、`is_anonymous`和`get_id`方法目前可能看起来是任意的，但它们是下一步所需的，即安装和设置 Flask-Login 扩展，以帮助我们管理用户身份验证系统。

## Flask-Login 和 Flask-Bcrypt 用于身份验证

我们已经多次使用其他库进行了安装扩展，我们将在当前项目的虚拟环境中安装这些扩展：

```py
$ (snap) pip install flask-login flask-bcrypt

```

第一个是一个特定于 Flask 的库，用于规范几乎每个 Web 应用程序都需要的标准用户登录过程，后者将允许我们确保我们在数据库中存储的用户密码使用行业标准算法进行哈希处理。

安装后，我们需要以通常的方式实例化和配置扩展。为此，我们将添加到`application/__init__.py`模块中：

```py
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager
from flask.ext.bcrypt import Bcrypt

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../snap.db'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
flask_bcrypt = Bcrypt(app)

from application.users import models as user_models
from application.users.views import users

```

为了正确运行，Flask-Login 扩展还必须知道如何仅通过用户的 ID 从数据库中加载用户。我们必须装饰一个函数来完成这个任务，并为简单起见，我们将它插入到`application/__init__.py`模块的最后：

```py
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login LoginManager
from flask.ext.bcrypt import Bcrypt

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../snap.db'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
flask_bcrypt = Bcrypt(app)

from application.users import models as user_models
from application.users.views import users

@login_manager.user_loader
def load_user(user_id):
 return application.user_models.query.get(int(user_id))

```

现在我们已经设置了模型和所需的方法/函数，以便 Flask-Login 可以正确运行，我们的下一步将是允许用户像几乎任何 Web 应用程序一样登录使用表单。

## Flask-WTF - 表单验证和呈现

Flask-WTF（https://flask-wtf.readthedocs.org/en/latest/）扩展包装了 WTForms 库，这是一个非常灵活的管理和验证表单的工具，并且可以在 Flask 应用程序中方便地使用。让我们现在安装它，然后我们将定义我们的第一个表单来处理用户登录：

```py
$ pip install flask-wtf

```

接下来，我们将在我们的`users/views.py`模块中定义我们的第一个表单：

```py
from flask import Blueprint

from flask.ext.wtf import Form
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length

users = Blueprint('users', __name__, template_folder='templates')

classLoginForm(Form):
 """
 Represents the basic Login form elements & validators.
 """

 username = StringField('username', validators=[DataRequired()])
 password = PasswordField('password', validators=[DataRequired(),
 Length(min=6)])

```

在这里，我们定义了`LoginForm`，它是`Form`的子类，具有`username`和`password`的类属性。这些属性的值分别是`StringField`和`PasswordField`，每个都有自己的验证器集，指示这两个字段的表单数据都需要非空，并且密码字段本身应至少为六个字符长才能被视为有效。

我们的`LoginForm`类将以两种不同的方式被使用，如下所示：

+   它将在我们的`login.html`模板中呈现所需的表单字段

+   它将验证我们需要完成用户成功登录所需的 POST 表单数据

为了实现第一个，我们需要在`application/templates/layout.html`中定义我们的 HTML 布局，使用 Jinja2 模板语言。请注意使用`current_user`对象代理，它通过 Flask-Login 扩展在所有 Jinja 模板中提供，这使我们能够确定正在浏览的人是否已经认证，如果是，则应该向这个人呈现略有不同的页面内容：

```py
<!doctype html>
<html>
  <head>
    <title>Snaps</title>
  </head>

  <body>
    <h1>Snaps</h1>

    {% for message in get_flashed_messages() %}
    <div class="flash">{{ message }}</div>
    {% endfor %}

    {% if not current_user.is_authenticated() %}
    <a href="{{ url_for('users.login') }}">login</a>
    {% else %}
    <a href="{{ url_for('users.logout') }}">logout</a>
    {% endif %}

    <div class="content">
    {% block content %}{% endblock %}
    </div>
  </body>
</html>
```

现在我们已经有了极其基本的布局，我们需要在`application/users/templates/users/login.html`中创建我们的`login.html`页面：

### 注意

当使用蓝图时，`application/users/templates/users/index.html`的相对复杂路径是必需的，因为默认模板加载程序搜索注册的模板路径的方式，它允许相对简单地在主应用程序模板文件夹中覆盖蓝图模板，但会增加一些额外的文件树复杂性。

```py
{% extends "layout.html" %}

{% block content %}

<form action="{{ url_for('users.login')}}" method="post">
  {{ form.hidden_tag() }}
  {{ form.id }}
  <div>{{ form.username.label }}: {{ form.username }}</div>
  {% if form.username.errors %}
  <ul class="errors">{% for error in form.username.errors %}<li>{{ error }}</li>{% endfor %}</ul>
  {% endif %}

  <div>{{ form.password.label }}: {{ form.password }}</div>
  {% if form.password.errors %}
  <ul class="errors">{% for error in form.password.errors %}<li>{{ error }}</li>{% endfor %}</ul>
  {% endif %}

  <div><input type="submit" value="Login"></div>
</form>

{% endblock %}
```

前面的代码将扩展我们之前定义的基本应用程序级`layout.html`，并插入隐藏的表单字段（Flask-WTF 提供的内置 CSRF 保护所需），表单标签，表单输入和提交按钮。我们还将显示 WTForms 返回的内联错误，以防我们提交的数据未通过相关字段的表单验证器。

> **跨站请求伪造**（**CSRF**）*是一种攻击类型，当恶意网站、电子邮件、博客、即时消息或程序导致用户的网络浏览器在用户当前已认证的受信任站点上执行不需要的操作时发生。OWASP 对 CSRF 的定义*

### 注意

防止跨站请求伪造最常见的方法是在发送给用户的每个 HTML 表单中包含一个令牌，然后可以针对已认证用户的会话中的匹配令牌进行验证。如果令牌无法验证，那么表单数据将被拒绝，因为当前认证用户可能并不是自愿提交相关表单数据。

现在我们已经创建了`login.html`模板，接下来我们可以在`application/users/views.py`中挂接一个路由视图处理程序来处理登录和表单逻辑：

```py
from flask import (Blueprint, flash, render_template, url_for, redirect, g)
from flask.ext.login import login_user, logout_user, current_user

from flask.ext.wtf import Form
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length

from models import User
from application import flask_bcrypt

users = Blueprint('users', __name__, template_folder='templates')

class LoginForm(Form):
 """
 Represents the basic Login form elements & validators.
 """

 username = StringField('username', 
validators=[DataRequired()])
password = PasswordField('password', 
validators=[DataRequired(),Length(min=6)])

@users.route('/login', methods=['GET', 'POST'])
def login():
 """
Basic user login functionality.

 If the user is already logged in, we
redirect the user to the default snaps index page.

 If the user is not already logged in and we have
form data that was submitted via POST request, we
call the validate_on_submit() method of the Flask-WTF
 Form object to ensure that the POST data matches what
we are expecting. If the data validates, we login the
user given the form data that was provided and then
redirect them to the default snaps index page.

 Note: Some of this may be simplified by moving the actual User
loading and password checking into a custom Flask-WTF validator
for the LoginForm, but we avoid that for the moment, here.
 """

current_user.is_authenticated():
 return redirect(url_for('snaps.listing))

 form = LoginForm()
 if form.validate_on_submit():

 user = User.query.filter_by(
 username=form.username.data).first()

 if not user:
 flash("No such user exists.")
 returnrender_template('users/login.html', form=form)

 if(not flask_bcrypt.check_password_hash(user.password,
 form.password.data)):

 flash("Invalid password.")
 returnrender_template('users/login.html', form=form)

 login_user(user, remember=True)
 flash("Success!  You're logged in.")
 returnredirect(url_for("snaps.listing"))

 return render_template('users/login.html', form=form)

@users.route('/logout', methods=['GET'])
def logout():
 logout_user()
 return redirect(url_for(('snaps.listing'))

```

### 哈希用户密码

我们将更新我们的用户模型，以确保密码在更新“密码”字段时由 Flask-Bcrypt 加密。为了实现这一点，我们将使用 SQLAlchemy 的一个功能，它类似于 Python 的@property 装饰器（以及相关的 property.setter 方法），名为混合属性。

### 注意

混合属性之所以被命名为混合属性，是因为当在类级别或实例级别调用时，它们可以提供完全不同的行为。SQLAlchemy 文档是了解它们在领域建模中可以扮演的各种角色的好地方。

我们将简单地将密码类级属性重命名为`_password`，以便我们的混合属性方法不会发生冲突。随后，我们添加了封装了密码哈希逻辑的混合属性方法，以在属性分配时使用：

### 注意

除了混合属性方法之外，我们对分配密码哈希的要求也可以通过使用 SQLAlchemy TypeDecorator 来满足，这允许我们增加现有类型（例如，String 列类型）的附加行为。

```py
import datetime
from application import db, flask_bcrypt
from sqlalchemy.ext.hybrid import hybrid_property

class User(db.Model):

 # …

 # The hashed password for the user
 _password = db.Column('password', db.String(60))

 # …
 @hybrid_property
 def password(self):
 """The bcrypt'ed password of the given user."""

return self._password

 @password.setter
 def password(self, password):
 """Bcrypt the password on assignment."""

 self._password = flask_bcrypt.generate_password_hash(
 password)

 # …

```

为了生成一个用于测试目的的用户（并验证我们的密码是否在实例构造/属性分配时被哈希），让我们加载 Python 控制台，并使用我们定义的模型和我们创建的 SQLAlchemy 数据库连接自己创建一个用户实例：

### 提示

如果您还没有，不要忘记使用`db.create_all()`来初始化数据库。

```py
>>>from application.users.models import User
>>>user = User(username='test', password='mypassword', email='test@example.com')
>>>user.password
'$2a$12$O6oHgytOVz1hrUyoknlgqeG7TiVS7M.ogRPv4YJgAJyVeUIV8ad2i'
>>>from application import db
>>>db.session.add(user)
>>>db.session.commit()

```

### 配置应用程序 SECRET_KEY

我们需要的最后一点是定义一个应用程序范围的`SECRET_KEY`，Flask-WTF 将使用它来签署用于防止 CSRF 攻击的令牌。我们将在`application/__init__.py`中的应用程序配置中添加此密钥：

```py
from flask import Flask
fromflask.ext.sqlalchemy import SQLAlchemy
fromflask.ext.login import LoginManager
fromflask.ext.bcrypt import Bcrypt

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../snap.db'
app.config['SECRET_KEY'] = "-80:,bPrVzTXp*zXZ0[9T/ZT=1ej08"
# …

```

### 注意

当然，您会想要使用您自己的唯一密钥；最简单的方法是通过`/dev/urandom`来使用您系统内核的随机数设备，对于大多数 Linux 发行版都是可用的。在 Python 中，您可以使用`os.urandom`方法来获得一个具有*n*字节熵的随机字符串。

### 连接蓝图

在我们运行应用程序之前，我们需要使用 Flask 应用程序对象注册我们新创建的用户蓝图。这需要对`application/__init__.py`进行轻微修改：

```py
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager
from flask.ext.bcrypt import Bcrypt

app = Flask(__name__)

# …
from application.users.views import users
app.register_blueprint(users, url_prefix='/users')

# …

```

## 让我们运行这个东西

既然我们已经把所有小部件放在一起，让我们运行应用程序并让事情发生。我们将使用一个类似于我们在上一章中使用的`run.py`文件，它已经适应了我们的应用程序工厂的工作方式：

```py
from application import create_app

app = create_app(config='settings')
app.run(debug=True)

```

该文件被放置在`application`文件夹的同级目录下，然后以通常的方式调用：

```py
$ python run.py

```

访问`http://localhost:5000/users/login`，您应该会看到我们创建的`username`和`password`输入字段。如果您尝试输入无效字段（例如，不存在的用户名），页面将显示相关的错误消息。如果您尝试使用我们在交互提示中创建的用户凭据登录，那么您应该会看到文本：`Success! You logged in`。

## 快照的数据模型

既然我们已经创建了我们的基本用户模型、视图函数，并连接了我们的身份验证系统，让我们创建一个新的蓝图来存储我们的快照所需的模型，在`application/snaps/models.py`下。

### 提示

不要忘记创建`application/snaps/__init__.py`，否则该文件夹将无法被识别为一个包！

这个模型将与我们的用户模型非常相似，但将包含有关用户和他们的快照之间关系的附加信息。在 SQLAlchemy 中，我们将通过使用`ForeignKey`对象和`relationship`方法来描述表中记录之间的关系：

```py
import datetime
import hashlib
from application import db

class Snap(db.Model):

 # The primary key for each snap record.
 id = db.Column(db.Integer, primary_key=True)

 # The name of the file; does not need to be unique.
 name = db.Column(db.String(128))

 # The extension of the file; used for proper syntax 
 # highlighting
 extension = db.Column(db.String(12))

 # The actual content of the snap
 content = db.Column(db.Text())

 # The unique, un-guessable ID of the file
 hash_key = db.Column(db.String(40), unique=True)

 #  The date/time that the snap was created on.
 created_on = db.Column(db.DateTime, 
 default=datetime.datetime.utcnow,index=True)

 # The user this snap belongs to
 user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

 user = db.relationship('User', backref=db.backref(
 'snaps', lazy='dynamic'))

 def __init__(self, user_id, name, content, extension):
 """
 Initialize the snap object with the required attributes.
 """

 self.user_id = user_id
 self.name = name
 self.content = content
 self.extension = extension

self.created_on = datetime.datetime.utcnow()

 # This could be made more secure by combining the 
 # application SECRET_KEYin the hash as a salt.
 self.hash_key = hashlib.sha1(self.content + str(self.created_on)).hexdigest()

 def __repr__(self):
 return '<Snap {!r}>'.format(self.id)

```

这个模型大部分应该是相对熟悉的；它与我们之前为用户模式构建的模型并没有太大的不同。对于我们的快照，我们将需要一些强制属性，如下所示：

+   `user_id`：这是创建快照的用户的 ID。由于我们当前的实现将要求用户进行身份验证才能创建快照，所有生成的快照都将与发布它们的用户相关联。这也将使我们在以后轻松扩展系统，以包括用户个人资料、个人快照统计信息和删除快照的能力。

+   `created_on`：这在构造函数中设置为当前的 UTC 时间戳，并将用于按降序排序以在我们的首页上以列表形式显示它们。

+   `hash_key`：这个属性也在构造函数中设置，是快照内容与创建时间戳的加密哈希。这给了我们一个不容易猜测的唯一安全 ID，我们可以用它来在以后引用快照。

### 注意

尽管我们为前面的`hash_key`描述的条件并不保证该值是唯一的，快照哈希键的唯一性也通过数据库级别的唯一索引约束得到了强制。

+   `content`：这是快照本身的内容——模型的主要部分。

+   `extension`：这是快照的文件扩展名，这样我们就可以包含简单的语法高亮。

+   `name`：这是快照的名称，不需要是唯一的。

+   `user`：这是一个特殊属性，声明每个快照实例都与一个用户实例相关联，并允许我们访问创建快照的用户的数据。`backref`选项还指定了反向应该是可能的：也就是说，通过用户实例上的快照属性访问用户创建的所有快照。

### 使用内容敏感的默认函数更好的默认值

对前面的模型可以进行的一个改进是删除显式的`__init__`方法。最初定义它的唯一原因是确保可以从内容字段的值构造`hash_key`字段。虽然在大多数情况下，定义的显式对象构造函数已经足够好了，但 SQLAlchemy 提供了功能，允许我们根据另一个字段的内容设置一个字段的默认值。这被称为**上下文敏感的默认函数**，可以在`application/snaps/models.py`模块的顶部声明为这样：

```py
defcontent_hash(context):
 # This could be made more secure by combining the
 # application SECRET_KEY in the hash as a salt.
 content = context.current_parameters['content']
 created_on = context.current_parameters['created_on']
 return hashlib.sha1(content + str(created_on)).hexdigest()

```

一旦存在这个方法，我们就可以将`hash_key`列的默认参数定义为我们的`content_hash`内容敏感的默认值：

```py
# The unique, un-guessable ID of the file
hash_key = db.Column(db.String(40), unique=True, 
 default=content_hash)

```

## 快照视图处理程序

接下来，我们将创建所需的视图和模板，以列出和添加快照。为此，我们将在`application/snaps/views.py`中实例化一个`Blueprint`对象，并声明我们的路由处理程序：

```py
from flask import Blueprint
from flask.ext.login import login_required

from .models import Snap

snaps = Blueprint('snaps', __name__, template_folder='templates')

@snaps.route('/', methods=['GET'])
def listing():
"""List all snaps; most recent first."""

@snaps.route('/add', methods=['GET', 'POST'])
@login_required
def add():
 """Add a new snap."""

```

请注意，我们已经用`@login_required`装饰器包装了我们的`add()`路由处理程序，这将阻止未经身份验证的用户访问此端点的所有定义的 HTTP 动词（在本例中为 GET 和 POST），并返回 401。

### 注意

与其让服务器返回 HTTP 401 未经授权，不如配置 Flask-Login 将未经身份验证的用户重定向到登录页面，方法是将`login_manager.login_view`属性设置为登录页面本身的`url_for`兼容位置，而在我们的情况下将是`users.login`。

现在，让我们创建 WTForm 对象来表示一个快照，并将其放在`application/snaps/views.py`模块中：

```py
from flask.ext.wtf import Form
from wtforms import StringField
from wtforms.widgets import TextArea
from wtforms.validators import DataRequired

class SnapForm(Form):
 """Form for creating new snaps."""

 name = StringField('name', validators=[DataRequired()])
 extension = StringField('extension', 
 validators=[DataRequired()])
 content = StringField('content', widget=TextArea(),
 validators=[DataRequired()])

```

### 提示

虽然这在某种程度上是个人偏好的问题，但使用 WTForms（或任何其他类似的抽象）创建的表单可以放在模型旁边，而不是视图。或者，更进一步地，如果您有许多不同的表单与复杂的数据关系，也许将所有声明的表单放在应用程序的自己的模块中也是明智的。

我们的快照需要一个名称、一个扩展名和快照本身的内容，我们已经在前面的表单声明中封装了这些基本要求。让我们实现我们的`add()`路由处理程序：

```py
from flask import Blueprint, render_template, url_for, redirect, current_app, flash
from flask.ext.login import login_required, current_user
from sqlalchemy import exc

from .models import Snap
from application import db

# …

@snaps.route('/add', methods=['GET', 'POST'])
@login_required
def add():
 """Add a new snap."""

 form = SnapForm()

 if form.validate_on_submit():
 user_id = current_user.id

 snap = Snap(user_id=user_id, name=form.name.data,
 content=form.content.data, 
 extension=form.extension.data)
 db.session.add(snap)

try:
 db.session.commit()
 except exc.SQLAlchemyError:
 current_app.exception("Could not save new snap!")
 flash("Something went wrong while posting your snap!")

 else:
 return render_template('snaps/add.html', form=form)

 return redirect(url_for('snaps.listing'))

```

简而言之，我们将验证提交的 POST 数据，以确保它满足我们在`SnapForm`类声明中指定的验证器，然后继续使用提供的表单数据和当前认证用户的 ID 来实例化一个`Snap`对象。构建完成后，我们将将此对象添加到当前的 SQLAlchemy 会话中，然后尝试将其提交到数据库。如果发生 SQLAlchemy 异常（所有 SQLAlchemy 异常都继承自`salalchemy.exc.SQLALchemyError`），我们将记录异常到默认的应用程序日志处理程序，并设置一个闪存消息，以便提醒用户发生了意外情况。

为了完整起见，我们将在这里包括极其简单的`application/snaps/templates/snaps/add.html` Jinja 模板：

```py
{% extends "layout.html" %}

{% block content %}
<form action="{{ url_for('snaps.add')}}" method="post">

  {{ form.hidden_tag() }}
  {{ form.id }}

  <div class="row">
    <div>{{ form.name.label() }}: {{ form.name }}</div>
    {% if form.name.errors %}
    <ul class="errors">{% for error in form.name.errors %}<li>{{ error }}</li>{% endfor %}</ul>
    {% endif %}

    <div>{{ form.extension.label() }}: {{ form.extension }}</div>
    {% if form.extension.errors %}
    <ul class="errors">{% for error in form.extension.errors %}<li>{{ error }}</li>{% endfor %}</ul>
    {% endif %}
  </div>

  <div class="row">
    <div>{{ form.content.label() }}: {{ form.content }}</div>
    {% if form.content.errors %}
    <ul class="errors">{% for error in form.content.errors %}<li>{{ error }}</li>{% endfor %}</ul>
    {% endif %}
  </div>

  <div><input type="submit" value="Snap"></div>
</form>

{% endblock %}
```

完成了`add()`处理程序和相关模板后，现在是时候转向`listing()`处理程序了，这将偶然成为我们应用程序的登陆页面。列表页面将以相反的时间顺序显示最近发布的 20 个快照：

```py
@snaps.route('/', methods=['GET'])
def listing():
 """List all snaps; most recent first."""
 snaps = Snap.query.order_by(
 Snap.created_on.desc()).limit(20).all()
 return render_template('snaps/index.html', snaps=snaps)

```

`application/snaps/templates/snaps/add.html` Jinja 模板呈现了我们从数据库中查询到的快照：

```py
{% extends "layout.html" %}

{% block content %}
<div class="new-snap">
  <p><a href="{{url_for('snaps.add')}}">New Snap</a></p>
</div>

{% for snap in snaps %}
<div class="snap">
  <span class="author">{{snap.user.username}}</span>, published on <span class="date">{{snap.created_on}}</span>
  <pre><code>{{snap.content}}</code></pre>
</div>
{% endfor %}

{% endblock %}
```

接下来，我们必须确保我们创建的快照蓝图已加载到应用程序中，并通过将其添加到`application/__init__.py`模块来添加到根/URI 路径：

```py
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager
from flask.ext.bcrypt import Bcrypt

# …

from application.users import models as user_models
from application.users.views import users
from application.snaps.views import snaps

app.register_blueprint(users, url_prefix='/users')
app.register_blueprint(snaps, url_prefix='')

@login_manager.user_loader
de fload_user(user_id):
 return user_models.User.query.get(int(user_id))

```

为了测试我们的新功能，我们需要将新创建的快照模型添加到我们的数据库中。我们可以通过执行我们在本章前面描述的`db.create_all()`函数来实现这一点。由于我们经常运行这个命令，让我们将其放在与我们的主应用程序包文件同级的脚本中，并将文件命名为`database.py`：

```py
from application import db
db.create_all()

```

一旦就位，我们可以简单地使用 Python 解释器执行脚本，以在我们的数据库中创建新的快照模型：

```py
$ python database.py

```

现在，我们的数据库应该已经根据我们的模型定义更新了，让我们确保应用程序按预期运行：

```py
$ python run.py

```

假设没有错误，您应该能够访问显示的 URL，并使用我们在本章早些时候创建的用户之一的凭据登录。当然，您可以通过交互式 Python 解释器创建一个新用户，然后使用这些凭据来测试应用程序的身份验证功能：

```py
$ python
>>>from application import db
>>>from application.users.models import User
>>>user = User(name='test', email='test@example.com', password='foobar')
>>>db.session.add(user)
>>>db.session.commit(user)

```

# 总结

通过阅读本章并构建 Snap 应用程序，我们已经看到了 Flask 如何通过使用扩展来增强，例如 Flask-WTF（用于 Web 表单创建和验证）、Flask-SQLAlchemy（用于与 SQLAlchemy 数据库抽象库的简单集成）、Flask-Bcrypt（用于密码哈希）和 Flask-Login（用于简单用户登录系统的标准实现要求的抽象）。虽然 Flask 本身相对简洁，但可用的扩展生态系统使得构建一个完全成熟的用户认证应用程序可以快速且相对轻松地完成。

我们探讨了上述扩展及其有用性，包括 Flask-WTF 和 Flask-SQLAlchemy，并设计了一个基于蓝图的简单应用程序，集成了上述所有组件。虽然 Snap 应用程序本身非常简单，还有很多功能需要实现，但它非常容易更新和添加其他功能。

在下一章中，我们将构建一个具有更复杂数据模型的应用程序，并包含一些在今天的 Web 应用程序中常见的社交功能。此外，它将被构建和设置为单元和功能测试，这是任何微不足道的应用程序都不应该缺少的功能。


# 第四章：Socializer-可测试的时间线

在本章中，我们将使用代号“Socializer”构建我们的下一个应用程序。这个应用程序将为您提供一个非常典型的*时间线*信息流，其变体出现在许多知名的现代网络应用程序中。

这个应用程序将允许经过身份验证的用户关注其他用户，并被其他用户关注，并以时间顺序显示被关注用户发布的内容。除了构建基于时间线的应用程序所需的基本功能之外，我们还将使用优秀的`Blinker`库来实现其他行为，以进行进程内发布/订阅信号，这将使我们能够将应用程序解耦为更可组合、可重用的部分。

此外，Socializer 将在构建过程中考虑单元测试和功能测试，使我们能够对各种模型和视图进行严格测试，以确保其按照我们的期望进行功能。

# 开始

就像我们在上一章中所做的那样，让我们为这个应用程序创建一个全新的目录，另外创建一个虚拟环境，并安装我们将要使用的一些基本包：

```py
$ mkdir -p ~/src/socializer && cd ~/src/socializer
$ mkvirtualenv socializer
$ pip install flask flask-sqlalchemy flask-bcrypt flask-login flask-wtf blinker pytest-flask

```

我们的应用程序布局暂时将与上一章中使用的布局非常相似：

```py
├── application
│   ├── __init__.py
│   └── users
│       ├── __init__.py
│       ├── models.py
│       └── views.py
└── run.py
└── database.py

```

# 应用程序工厂

单元测试和功能测试的一个主要好处是能够在各种不同条件和配置下确保应用程序以已知和可预测的方式运行。为此，在我们的测试套件中构建所有 Flask 应用程序对象将是一个巨大的优势。然后，我们可以轻松地为这些对象提供不同的配置，并确保它们表现出我们期望的行为。

值得庆幸的是，这完全可以通过应用程序工厂模式来实现，而 Flask 对此提供了很好的支持。让我们在`application/__init__.py`模块中添加一个`create_app`方法：

```py
from flask import Flask

def create_app(config=None):
 app = Flask(__name__)

 if config is not None:
 app.config.from_object(config)

 return app

```

这个方法的作用相对简单：给定一个可选的`config`参数，构建一个 Flask 应用程序对象，可选地应用这个自定义配置，最后将新创建的 Flask 应用程序对象返回给调用者。

以前，我们只是在模块本身中实例化一个 Flask 对象，这意味着在导入此包或模块时，应用程序对象将立即可用。然而，这也意味着没有简单的方法来做以下事情：

+   将应用程序对象的构建延迟到模块导入到本地命名空间之后的某个时间。这一开始可能看起来很琐碎，但对于可以从这种惰性实例化中受益的大型应用程序来说，这是非常有用和强大的。正如我们之前提到的，应尽可能避免产生副作用的包导入。

+   替换不同的应用程序配置值，例如在运行测试时可能需要的配置值。例如，我们可能希望在运行测试套件时避免向真实用户发送电子邮件通知。

+   在同一进程中运行多个 Flask 应用程序。虽然本书中没有明确讨论这个概念，但在各种情况下这可能是有用的，比如拥有为公共 API 的不同版本提供服务的单独应用程序实例，或者为不同内容类型（JSON、XML 等）提供服务的单独应用程序对象。关于这个主题的更多信息可以从官方 Flask 在线文档的*应用程序调度*部分中获取[`flask.pocoo.org/docs/0.10/patterns/appdispatch/`](http://flask.pocoo.org/docs/0.10/patterns/appdispatch/)。

有了应用程序工厂，我们现在在何时以及如何构建我们的主应用程序对象方面有了更多的灵活性。当然，缺点（或者优点，如果你打算在同一个进程中运行多个应用程序！）是，我们不再可以访问一个准全局的`app`对象，我们可以导入到我们的模块中，以便注册路由处理程序或访问`app`对象的日志记录器。

## 应用程序上下文

Flask 的主要设计目标之一是确保您可以在同一个 Python 进程中运行多个应用程序。那么，一个应用程序如何确保被导入到模块中的`app`对象是正确的，而不是在同一个进程中运行的其他应用程序的对象？

在支持单进程/多应用程序范式的其他框架中，有时可以通过强制显式依赖注入来实现：需要`app`对象的代码应明确要求将 app 对象传递给需要它的函数或方法。从架构设计的角度来看，这听起来很棒，但如果第三方库或扩展不遵循相同的设计原则，这很快就会变得繁琐。最好的情况是，您最终将需要编写大量的样板包装函数，最坏的情况是，您最终将不得不诉诸于在模块和类中进行猴子补丁，这将最终导致比您最初预期的麻烦更多的脆弱性和不必要的复杂性。

### 注意

当然，显式依赖注入样板包装函数本身并没有什么不对。Flask 只是选择了一种不同的方法，过去曾因此受到批评，但已经证明是灵活、可测试和有弹性的。

Flask，不管好坏，都是建立在基于代理对象的替代方法之上的。这些代理对象本质上是容器对象，它们在所有线程之间共享，并且知道如何分派到在幕后绑定到特定线程的*真实*对象。

### 注意

一个常见的误解是，在多线程应用程序中，根据 WSGI 规范，每个请求将被分配一个新的线程：这根本不是事实。新请求可能会重用现有但当前未使用的线程，并且这个旧线程可能仍然存在局部作用域的变量，可能会干扰您的新请求处理。

其中一个代理对象`current_app`被创建并绑定到当前请求。这意味着，我们不再导入一个已经构建好的 Flask 应用程序对象（或者更糟糕的是，在同一个请求中创建额外的应用程序对象），而是用以下内容替换它：

```py
from flask import current_app as app

```

### 提示

当然，导入的`current_app`对象的别名是完全可选的。有时最好将其命名为`current_app`，以提醒自己它不是真正的应用程序对象，而是一个代理对象。

使用这个代理对象，我们可以规避在实现应用程序工厂模式时，在导入时没有可用的实例化 Flask 应用程序对象的问题。

### 实例化一个应用程序对象

当然，我们需要在某个时候实际创建一个应用程序对象，以便代理有东西可以代理。通常，我们希望创建对象一次，然后确保调用`run`方法以启动 Werkzeug 开发服务器。

为此，我们可以修改上一章中的`run.py`脚本，从我们的工厂实例化 app 对象，并调用新创建的实例的`run`方法，如下所示：

```py
from application import create_app

app = create_app()
app.run(debug=True)

```

现在，我们应该能够像以前一样运行这个极其简陋的应用程序：

```py
$ python run.py

```

### 提示

还可以调用 Python 解释器，以便为您导入并立即执行模块、包或脚本。这是通过`-m`标志实现的，我们之前对`run.py`的调用可以修改为更简洁的版本，如下所示：

```py
$ python –m run

```

# 单元和功能测试

实现应用程序工厂以分发 Flask 应用程序实例的主要好处之一是，我们可以更有效地测试应用程序。我们可以为不同的测试用例构建不同的应用程序实例，并确保它们尽可能地相互隔离（或者尽可能地与 Flask/Werkzeug 允许的隔离）。

Python 生态系统中测试库的主要组成部分是 unittest，它包含在标准库中，并包括了 xUnit 框架所期望的许多功能。虽然本书不会详细介绍 unittest，但一个典型的基于类的测试用例将遵循以下基本结构，假设我们仍然使用工厂模式来将应用程序配置与实例化分离：

```py
from myapp import create_app
import unittest

class AppTestCase(unittest.TestCase):

 def setUp(self):
 app = create_app()  # Could also pass custom settings.
 app.config['TESTING'] = True
 self.app = app

 # Whatever DB initialization is required

 def tearDown(self):
 # If anything needs to be cleaned up after a test.
 Pass

 def test_app_configuration(self):
 self.assertTrue(self.app.config['TESTING'])
 # Other relevant assertions

if __name__ == '__main__':
 unittest.main()

```

使用 unittest 测试格式/样式的优点如下：

+   不需要外部依赖；unittest 是 Python 标准库的一部分。

+   入门相对容易。大多数 xUnit 测试框架遵循类似的命名约定来声明测试类和测试方法，并包含几个典型断言的辅助函数，如`assertTrue`或`assertEqual`等。

然而，它并不是唯一的选择；我们将使用`pytest`和包装方便功能的相关 Flask 扩展`pytest-flask`。

除了作为一个稍微现代化和简洁的测试框架外，`pytest`相对于许多其他测试工具提供的另一个主要优势是能够为测试定义固定装置，这在它们自己的文档中描述得非常简洁，如下所示：

+   固定装置具有明确的名称，并通过声明其在测试函数、模块、类或整个项目中的使用来激活它们

+   固定装置以模块化的方式实现，因为每个固定装置名称都会触发一个固定装置函数，该函数本身可以使用其他固定装置

+   固定装置管理从简单单元到复杂功能测试的规模，允许您根据配置和组件选项对固定装置和测试进行参数化，或者在类、模块或整个测试会话范围内重用固定装置

在测试 Flask 应用程序的情况下，这意味着我们可以在`fixture`中定义对象（例如我们的应用程序对象），然后通过使用与定义的固定装置函数相同名称的参数，将该对象自动注入到测试函数中。

如果上一段文字有点难以理解，那么一个简单的例子就足以澄清问题。让我们创建以下的`conftest.py`文件，其中将包含任何测试套件范围的固定装置和辅助工具，供其他测试使用：

```py
import pytest
from application import create_app

@pytest.fixture
def app():
 app = create_app()
 return app

```

我们将在`tests/test_application.py`中创建我们的第一个测试模块，如下所示：

### 提示

请注意`tests_*`前缀对于测试文件名是重要的——它允许`pytest`自动发现哪些文件包含需要运行的测试函数和断言。如果您的 tests/folder 中的文件名没有上述前缀，那么测试运行器将放弃加载它，并将其视为包含具有测试断言的函数的文件。

```py
import flask

def test_app(app):
 assert isinstance(app, flask.Flask)

```

### 请注意

请注意`test_app`函数签名中的`app`参数与`conftest.py`中定义的`app`固定装置函数的名称相匹配，传递给`test_app`的值是`app`固定装置函数的返回值。

我们将使用安装到我们的虚拟环境中的`py.test`可执行文件来运行测试套件（当我们添加了`pytest-flask`和`pytest`库时），在包含`conftest.py`和我们的 tests/文件夹的目录中运行，输出将指示我们的测试模块已被发现并运行：

```py
$ py.test
=============== test session starts ================
platform darwin -- Python 2.7.8 -- py-1.4.26 -- pytest-2.7.0
rootdir: /path/to/socializer, inifile:
plugins: flask
collected 1 items

tests/test_application.py .

============= 1 passed in 0.02 seconds =============

```

就是这样！我们已经编写并运行了我们的第一个应用程序测试，尽管不是很有趣。如果你还不太明白发生了什么，不要担心；本章中将进行大量具体的测试，还会有更多的例子。

# 社交功能-朋友和关注者

许多现代网络应用程序允许用户*添加朋友*或*关注*其他用户，并且自己也可以被添加朋友或关注。虽然这个概念在文字上可能很简单，但有许多实现和变体，所有这些都针对它们特定的用例进行了优化。

在这种情况下，我们想要实现一个类似新闻订阅的服务，该服务会显示来自选定用户池的信息，并在每个经过身份验证的用户中显示独特的聚合时间线，以下是可能使用的三种方法类别：

+   **写入时的扇出**：每个用户的新闻订阅都存储在一个单独的逻辑容器中，旨在使读取非常简单、快速和直接，但代价是去规范化和较低的写入吞吐量。逻辑容器可以是每个用户的数据库表（尽管对于大量用户来说效率非常低），也可以是列式数据库（如 Cassandra）中的列，或者更专门的存储解决方案，如 Redis 列表，可以以原子方式向其中添加元素。

+   **读取时的扇出**：当新闻订阅需要额外的定制或处理来确定诸如可见性或相关性之类的事情时，通常最好使用读取时的扇出方法。这允许更精细地控制哪些项目将出现在动态信息中，以及以哪种顺序（假设需要比时间顺序更复杂的东西），但这会增加加载用户特定动态信息的计算时间。通过将最近的项目保存在 RAM 中（这是 Facebook™新闻订阅背后的基本方法，也是 Facebook 在世界上部署最大的 Memcache 的原因），但这会引入几层复杂性和间接性。

+   **天真的规范化**：这是方法中最不可扩展的，但实现起来最简单。对于许多小规模应用程序来说，这是最好的起点：一个包含所有用户创建的项目的帖子表（带有对创建该特定项目的用户的外键约束）和一个跟踪哪些用户正在关注谁的关注者表。可以使用各种缓存解决方案来加速请求的部分，但这会增加额外的复杂性，并且只有在必要时才能引入。

对于我们的 Socializer 应用程序，第三种方法，所谓的天真规范化，将是我们实现的方法。其他方法也是有效的，你可以根据自己的目标选择其中任何一条路线，但出于简单和阐述的目的，我们将选择需要最少工作量的方法。

有了这个想法，让我们开始实现所需的基本 SQLAlchemy 模型和关系。首先，让我们使用我们新创建的应用程序工厂来初始化和配置 Flask-SQLAlchemy 扩展，以及使用相同的混合属性方法来哈希我们的用户密码，这是我们在上一章中探讨过的方法。我们的`application/__init__.py`如下：

```py
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.bcrypt import Bcrypt

# Initialize the db extension, but without configuring
# it with an application instance.
db = SQLAlchemy()

# The same for the Bcrypt extension
flask_bcrypt = Bcrypt()

def create_app(config=None):
 app = Flask(__name__)

 if config is not None:
 app.config.from_object(config)

 # Initialize any extensions and bind blueprints to the
 # application instance here.
 db.init_app(app)
 flask_bcrypt.init_app(app)

 return app

```

由于应用程序工厂的使用，我们将扩展（`db`和`flask_bcrypt`）的实例化与它们的配置分开。前者发生在导入时，后者需要在构建 Flask 应用对象时发生。幸运的是，大多数现代的 Flask 扩展都允许发生这种确切的分离，正如我们在前面的片段中所演示的那样。

现在，我们将通过创建`application/users/__init__.py`来创建我们的用户包，然后我们将创建`application/users/models.py`，其中包含我们用于 Flask-Login 扩展的标准部分（稍后我们将使用），就像我们在上一章中所做的那样。此外，我们将为我们的关注者表和用户模型上的关联关系添加一个显式的 SQLAlchemy 映射：

```py
import datetime
from application import db, flask_bcrypt
from sqlalchemy.ext.hybrid import hybrid_property

__all__ = ['followers', 'User']

# We use the explicit SQLAlchemy mappers for declaring the
# followers table, since it does not require any of the features
# that the declarative base model brings to the table.
#
# The `follower_id` is the entry that represents a user who
# *follows* a `user_id`.
followers = db.Table(
 'followers',
 db.Column('follower_id', db.Integer, db.ForeignKey('user.id'),
 primary_key=True),
 db.Column('user_id', db.Integer, db.ForeignKey('user.id'),
 primary_key=True))

class User(db.Model):

 # The primary key for each user record.
 id = db.Column(db.Integer, primary_key=True)

 # The unique email for each user record.
 email = db.Column(db.String(255), unique=True)

 # The unique username for each record.
 username = db.Column(db.String(40), unique=True)

 # The hashed password for the user
 _password = db.Column('password', db.String(60))
 #  The date/time that the user account was created on.
 created_on = db.Column(db.DateTime,
 default=datetime.datetime.utcnow)

 followed = db.relationship('User',
 secondary=followers,
 primaryjoin=(id==followers.c.follower_id ),
 secondaryjoin=(id==followers.c.user_id),
 backref=db.backref('followers', lazy='dynamic'),
 lazy='dynamic')

 @hybrid_property
 def password(self):
 """The bcrypt'ed password of the given user."""

 return self._password

 @password.setter
 def password(self, password):
 """Bcrypt the password on assignment."""

 self._password = flask_bcrypt.generate_password_hash(
 password)

 def __repr__(self):
 return '<User %r>' % self.username

 def is_authenticated(self):
 """All our registered users are authenticated."""
 return True

 def is_active(self):
 """All our users are active."""
 return True

 def is_anonymous(self):
 """We don't have anonymous users; always False"""
 return False
 def get_id(self):
 """Get the user ID."""
 return unicode(self.id)

```

用户模型的`followed`属性是一个 SQLAlchemy 关系，它通过中间的关注者表将用户表映射到自身。由于社交连接需要隐式的多对多关系，中间表是必要的。仔细看一下`followed`属性，如下所示的代码：

```py
 followed = db.relationship('User',
 secondary=followers,
 primaryjoin=(id==followers.c.follower_id ),
 secondaryjoin=(id==followers.c.user_id),
 backref=db.backref('followers', lazy='dynamic'),
 lazy='dynamic')

```

我们可以看到，与本章和以前章节中使用的常规列定义相比，声明有些复杂。然而，`relationship`函数的每个参数都有一个非常明确的目的，如下列表所示：

+   `User`：这是目标关系类的基于字符串的名称。这也可以是映射类本身，但是那样你可能会陷入循环导入问题的泥潭。

+   `primaryjoin`：这个参数的值将被评估，然后用作主表（`user`）到关联表（`follower`）的`join`条件。

+   `secondaryjoin`：这个参数的值，类似于`primaryjoin`，在关联表（`follower`）到子表（`user`）的`join`条件中被评估并使用。由于我们的主表和子表是一样的（用户关注其他用户），这个条件几乎与`primaryjoin`参数中产生的条件相同，只是在关联表中映射的键方面有所不同。

+   `backref`：这是将插入到实例上的属性的名称，该属性将处理关系的反向方向。这意味着一旦我们有了一个用户实例，我们就可以访问`user.followers`来获取关注给定用户实例的人的列表，而不是`user.followed`属性，其中我们明确定义了当前用户正在关注的用户列表。

+   `lazy`：这是任何基于关系的属性最常被误用的属性。有各种可用的值，包括`select`、`immediate`、`joined`、`subquery`、`noload`和`dynamic`。这些确定了相关数据的加载方式或时间。对于我们的应用程序，我们选择使用`dynamic`的值，它不返回一个可迭代的集合，而是返回一个可以进一步细化和操作的`Query`对象。例如，我们可以做一些像`user.followed.filter(User.username == 'example')`这样的事情。虽然在这种特定情况下并不是非常有用，但它提供了巨大的灵活性，有时以生成效率较低的 SQL 查询为代价。

我们将设置各种属性，以确保生成的查询使用正确的列来创建自引用的多对多连接，并且只有在需要时才执行获取关注者列表的查询。关于这些特定模式的更多信息可以在官方的 SQLAlchemy 文档中找到：[`docs.sqlalchemy.org/en/latest/`](http://docs.sqlalchemy.org/en/latest/)。

现在，我们将为我们的用户模型添加一些方法，以便便于关注/取消关注其他用户。由于 SQLAlchemy 的一些内部技巧，为用户添加和移除关注者可以表达为对本地 Python 列表的操作，如下所示：

```py
def unfollow(self, user):
 """
 Unfollow the given user.

 Return `False` if the user was not already following the user.
 Otherwise, remove the user from the followed list and return
 the current object so that it may then be committed to the 
 session.
 """

 if not self.is_following(user):
 return False

 self.followed.remove(user)
 return self

def follow(self, user):
 """
 Follow the given user.
 Return `False` if the user was already following the user.
 """

 if self.is_following(user):
 return False

 self.followed.append(user)
 return self

def is_following(self, user):
 """
 Returns boolean `True` if the current user is following the
 given `user`, and `False` otherwise.
 """
 followed = self.followed.filter(followers.c.user_id == user.id)
 return followed.count() > 0

```

### 注意

实际上，您并不是在原生的 Python 列表上操作，而是在 SQLAlchemy 知道如何跟踪删除和添加的数据结构上操作，然后通过工作单元模式将这些同步到数据库。

接下来，我们将在`application/posts/models.py`的蓝图模块中创建`Post`模型。像往常一样，不要忘记创建`application/posts/__init__.py`文件，以便将文件夹声明为有效的 Python 包，否则在尝试运行应用程序时将出现一些非常令人困惑的导入错误。

目前，这个特定的模型将是一个简单的典范。以下是该项目的用户模型的当前实现：

```py
from application import db
import datetime

__all__ = ['Post']

class Post(db.Model):

 # The unique primary key for each post created.
 id = db.Column(db.Integer, primary_key=True)
 # The free-form text-based content of each post.
 content = db.Column(db.Text())

 #  The date/time that the post was created on.
 created_on = db.Column(db.DateTime(),
 default=datetime.datetime.utcnow, index=True)

 # The user ID that created this post.
 user_id = db.Column(db.Integer(), db.ForeignKey('user.id'))

 def __repr__(self):
 return '<Post %r>' % self.body

```

一旦我们定义了`Post`模型，我们现在可以为用户模型添加一个方法，该方法允许我们获取与当前实例链接的用户的新闻源。我们将该方法命名为`newsfeed`，其实现如下：

```py
def newsfeed(self):
 """
 Return all posts from users followed by the current user,
 in descending chronological order.

 """

 join_condition = followers.c.user_id == Post.user_id
 filter_condition = followers.c.follower_id == self.id
 ordering = Post.created_on.desc()

 return Post.query.join(followers,
 (join_condition)).filter(
 filter_condition).order_by(ordering)

```

### 注意

请注意，为了实现上述方法，我们必须将`Post`模型导入到`application/users/models.py`模块中。虽然这种特定的情况将正常运行，但必须始终注意可能会有一些难以诊断的潜在循环导入问题。

# 功能和集成测试

在大多数单元、功能和集成测试的处理中，通常建议在编写相应的代码之前编写测试。虽然这通常被认为是一个良好的实践，出于各种原因（主要是允许您确保正在编写的代码解决了已定义的问题），但为了简单起见，我们等到现在才涉及这个主题。

首先，让我们创建一个新的`test_settings.py`文件，它与我们现有的`settings.py`同级。这个新文件将包含我们在运行测试套件时想要使用的应用程序配置常量。最重要的是，它将包含一个指向不是我们应用程序数据库的数据库的 URI，如下所示：

```py
SQLALCHEMY_DATABASE_URI = 'sqlite:////tmp/test_app.db'
DEBUG = True
TESTING = True

```

### 注意

前面的`SQLALCHEMY_DATABASE_URI`字符串指向`/tmp/test_app.db`作为测试数据库的位置。当然，您可以选择与系统范围的`tmp`目录不同的路径。

我们还将对`conftest.py`文件进行一些添加，以添加额外的装置，用于初始化测试数据库，并确保我们有一个 SQLAlchemy 数据库会话对象可用于可能需要它的任何测试函数：

```py
import pytest
import os
from application import create_app, db as database

DB_LOCATION = '/tmp/test_app.db'

@pytest.fixture(scope='session')
def app():
 app = create_app(config='test_settings')
 return app

@pytest.fixture(scope='session')
def db(app, request):
 """Session-wide test database."""
 if os.path.exists(DB_LOCATION):
 os.unlink(DB_LOCATION)

 database.app = app
 database.create_all()

 def teardown():
 database.drop_all()
 os.unlink(DB_LOCATION)
 request.addfinalizer(teardown)
 return database

@pytest.fixture(scope='function')
def session(db, request):

 session = db.create_scoped_session()
 db.session = session

 def teardown():
 session.remove()

 request.addfinalizer(teardown)
 return session

```

### 注意

会话装置可以通过显式事务进行增强，确保在拆卸时开始并提交事务。这个（简单）实现留给读者作为一个练习。

`scope`参数指示了创建的装置对象的生命周期。在前面的例子中，我们为会话装置指定了`function`，这意味着为每个作为参数调用的测试函数创建一个新的装置对象。如果我们使用`module`作为我们的作用域值，我们将为每个包含该装置的`module`创建一个新的装置：一个装置将用于模块中的所有测试。这不应与`session`作用域值混淆，后者表示为整个测试套件运行的整个持续时间创建一个装置对象。会话范围可以在某些情况下非常有用，例如，创建数据库连接是一个非常昂贵的操作。如果我们只需要创建一次数据库连接，那么测试套件的总运行时间可能会大大缩短。

有关`py.test`装置装饰器的`scope`参数以及使用内置的`request`对象添加拆卸终结器回调函数的更多信息，可以查看在线文档：[`pytest.org/latest/contents.html`](https://pytest.org/latest/contents.html)。

我们可以编写一个简单的测试，从我们的声明性用户模型中创建一个新用户，在`tests/test_user_model.py`中：

```py
from application.users import models

def test_create_user_instance(session):
 """Create and save a user instance."""

 email = 'test@example.com'
 username = 'test_user'
 password = 'foobarbaz'

 user = models.User(email, username, password)
 session.add(user)
 session.commit()

 # We clear out the database after every run of the test suite
 # but the order of tests may affect which ID is assigned.
 # Let's not depend on magic numbers if we can avoid it.
 assert user.id is not None

 assert user.followed.count() == 0
 assert user.newsfeed().count() == 0

```

在使用`py.test`运行测试套件后，我们应该看到我们新创建的测试文件出现在列出的输出中，并且我们的测试应该无错误地运行。我们将断言我们新创建的用户应该有一个 ID（由数据库分配），并且不应该关注任何其他用户。因此，我们创建的用户的新闻源也不应该有任何元素。

让我们为用户数据模型的非平凡部分添加一些更多的测试，这将确保我们的关注/关注关系按预期工作：

```py
def test_user_relationships(session):
 """User following relationships."""

 user_1 = models.User(
 email='test1@example.com', username='test1',
 password='foobarbaz')
 user_2 = models.User(
 email='test2@example.com', username='test2',
 password='bingbarboo')

 session.add(user_1)
 session.add(user_2)

 session.commit()

 assert user_1.followed.count() == 0
 assert user_2.followed.count() == 0

 user_1.follow(user_2)

 assert user_1.is_following(user_2) is True
 assert user_2.is_following(user_1) is False
 assert user_1.followed.count() == 1

 user_1.unfollow(user_2)

 assert user_1.is_following(user_2) is False
 assert user_1.followed.count() == 0

```

# 使用 Blinker 发布/订阅事件

在任何非平凡应用程序的生命周期中，一个困难是确保代码库中存在正确的模块化水平。

存在各种方法来创建接口、对象和服务，并实现设计模式，帮助我们管理不断增加的复杂性，这是不可避免地为现实世界的应用程序所创建的。一个经常被忽视的方法是 Web 应用程序中的进程内`发布-订阅`设计模式。

通常，`发布-订阅`，或者更通俗地称为 pub/sub，是一种消息模式，其中存在两类参与者：**发布者**和**订阅者**。发布者发送消息，订阅者订阅通过主题（命名通道）或消息内容本身产生的消息的子集。

在大型分布式系统中，pub/sub 通常由一个消息总线或代理来中介，它与所有各种发布者和订阅者通信，并确保发布的消息被路由到感兴趣的订阅者。

然而，为了我们的目的，我们可以使用一些更简单的东西：使用非常简单的`Blinker`包支持的进程内发布/订阅系统，如果安装了 Flask。

## 来自 Flask 和扩展的信号

当存在`Blinker`包时，Flask 允许您订阅发布的各种信号（主题）。此外，Flask 扩展可以实现自己的自定义信号。您可以订阅应用程序中的任意数量的信号，但是信号订阅者接收消息的顺序是未定义的。

Flask 发布的一些更有趣的信号在以下列表中描述：

+   `request_started`: 这是在请求上下文创建后立即发送的，但在任何请求处理发生之前

+   `request_finished`: 这是在响应构造后发送的，但在发送回客户端之前立即发送

Flask-SQLAlchemy 扩展本身发布了以下两个信号：

+   `models_committed`: 这是在任何修改的模型实例提交到数据库后发送的

+   `before_models_committed`: 这是在模型实例提交到数据库之前发送的

Flask-Login 发布了半打信号，其中许多可以用于模块化认证问题。以下列出了一些有用的信号：

+   `user_logged_in`: 当用户登录时发送

+   `user_logged_out`: 当用户注销时发送

+   `user_unauthorized`: 当未经认证的用户尝试访问需要认证的资源时发送

## 创建自定义信号

除了订阅由 Flask 和各种 Flask 扩展发布的信号主题之外，还可以（有时非常有用！）创建自己的自定义信号，然后在自己的应用程序中使用。虽然这可能看起来像是一个绕圈子的方法，简单的函数或方法调用就足够了，但是将应用程序的各个部分中的正交关注点分离出来的能力是一个吸引人的建议。

例如，假设你有一个用户模型，其中有一个`update_password`方法，允许更改给定用户实例的密码为新的值。当密码被更改时，我们希望向用户发送一封邮件，通知他们发生了这个动作。

现在，这个功能的简单实现就是在`update_password`方法中发送邮件，这本身并不是一个坏主意。然而，想象一下，我们还有另外十几个实例需要发送邮件给用户：当他们被新用户关注时，当他们被用户取消关注时，当他们达到一定的关注者数量时，等等。

然后问题就显而易见了：我们在应用程序的各个部分混合了发送邮件给用户的逻辑和功能，这使得越来越难以理解、调试和重构。

虽然有几种方法可以管理这种复杂性，但当实现发布/订阅模式时，可以明显地看到可能的关注点的明确分离。在我们的 Flask 应用程序中使用自定义信号，我们可以创建一个添加关注者的信号，在动作发生后发布一个事件，任何数量的订阅者都可以监听该特定事件。此外，我们可以组织我们的应用程序，使得类似事件的信号订阅者（例如，发送电子邮件通知）在代码库中的同一位置。

让我们创建一个信号，每当一个用户关注另一个用户时就发布一个事件。首先，我们需要创建我们的`Namespace`信号容器对象，以便我们可以声明我们的信号主题。让我们在`application/__init__.py`模块中做这件事：

```py
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.bcrypt import Bcrypt
from blinker import Namespace

# Initialize the db extension, but without configuring
# it with an application instance.
db = SQLAlchemy()
flask_bcrypt = Bcrypt()

socializer_signals = Namespace()
user_followed = socializer_signals.signal('user-followed')

# …

```

一旦这个功能就位，我们在`User.follow()`方法中发出`user-followed`事件就很简单了，如下所示：

```py
def follow(self, user):
 """
 Follow the given user.

 Return `False` if the user was already following the user.
 """

 if self.is_following(user):
 return False
 self.followed.append(user)

 # Publish the signal event using the current model (self) as sender.
 user_followed.send(self)

 return self

```

### 注意

记得在`application/users/models.py`模块顶部添加`from the application import user_followed`导入行。

一旦发布了事件，订阅者可能会连接。让我们在`application/signal_handlers.py`中实现信号处理程序：

```py
__all__ = ['user_followed_email']

import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
def user_followed_email(user, **kwargs):
 logger.debug(
 "Send an email to {user}".format(user=user.username))

from application import user_followed

def connect_handlers():
 user_followed.connect(user_followed_email)

```

最后，我们需要确保我们的信号处理程序通过将函数导入到`application/__init__.py`模块来注册：

```py
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.bcrypt import Bcrypt
from blinker import Namespace

# Initialize the db extension, but without configuring
# it with an application instance.
db = SQLAlchemy()
flask_bcrypt = Bcrypt()

socializer_signals = Namespace()
user_followed = socializer_signals.signal('user-followed')

from signal_handlers import connect_handlers
connect_handlers()

# …
# …

```

添加此功能后，每当用户关注其他用户时，我们都将在配置的日志输出中打印一条调试消息。实际向用户发送电子邮件的功能留给读者作为练习；一个好的起点是使用`Flask-Mail`扩展。

# 异常的优雅处理

无论我们多么努力，有时我们使用和编写的代码会引发异常。

通常，这些异常是在特殊情况下抛出的，但这并不减少我们应该了解应用程序的哪些部分可能引发异常，以及我们是否希望在调用点处理异常，还是简单地让它冒泡到调用堆栈的另一个帧。

对于我们当前的应用程序，有几种异常类型我们希望以一种优雅的方式处理，而不是让整个 Python 进程崩溃，导致一切戛然而止，变得丑陋不堪。

在上一章中，我们简要提到了大多数基于 Flask 和 SQLAlchemy 的应用程序（或几乎任何其他数据库抽象）中需要存在的必要异常处理，但当这些异常确实出现时，处理它们的重要性怎么强调都不为过。考虑到这一点，让我们创建一些视图、表单和模板，让我们作为新用户注册到我们的应用程序，并查看一些异常出现时处理它们的示例。

首先，让我们在`application/users/views.py`中创建基本的用户视图处理程序：

```py
from flask import Blueprint, render_template, url_for, redirect, flash, g
from flask.ext.login import login_user, logout_user

from flask.ext.wtf import Form
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length

from models import User
from application import db, flask_bcrypt

users = Blueprint('users', __name__, template_folder='templates')

class Login	Form(Form):
 """
Represents the basic Login form elements & validators.
 """

username = StringField('username',
 validators=[DataRequired()])
password = PasswordField('password',
 validators=[DataRequired(),Length(min=6)])

class CreateUserForm(Form):
 """
 Encapsulate the necessary information required for creating a new user.
 """

 username = StringField('username', validators=[DataRequired(), Length(min=3, max=40)])
 email = StringField('email', validators=[DataRequired(), Length(max=255)])
 password = PasswordField('password', validators=[DataRequired(),
 Length(min=8)])

 @users.route('/signup', methods=['GET', 'POST'])
 def signup():
 """
Basic user creation functionality.

 """

form = CreateUserForm()

if form.validate_on_submit():

 user = User( username=form.username.data,
 email=form.email.data,
 password=form.password.data)

 # add the user to the database
 db.session.add(user)
 db.session.commit()
 # Once we have persisted the user to the database successfully,
 # authenticate that user for the current session
login_user(user, remember=True)
return redirect(url_for('users.index'))

return render_template('users/signup.html', form=form)

@users.route('/', methods=['GET'])
def index():
return "User index page!", 200

@users.route('/login', methods=['GET', 'POST'])
def login():
 """
Basic user login functionality.

 """

if hasattr(g, 'user') and g.user.is_authenticated():
return redirect(url_for('users.index'))

form = LoginForm()

if form.validate_on_submit():

 # We use one() here instead of first()
 user = User.query.filter_by(username=form.username.data).one()
 if not user or not flask_bcrypt.check_password_hash(user.password, form.password.data):

 flash("No such user exists.")
 return render_template('users/login.html', form=form)

 login_user(user, remember=True)
 return redirect(url_for('users.index'))
 return render_template('users/login.html', form=form)

@users.route('/logout', methods=['GET'])
def logout():
logout_user()
return redirect(url_for('users.login'))

```

你会发现，登录和注销功能与我们在上一章使用 Flask-Login 扩展创建的功能非常相似。因此，我们将简单地包含这些功能和定义的路由（以及相关的 Jinja 模板），而不加评论，并专注于新的注册路由，该路由封装了创建新用户所需的逻辑。此视图利用了新的`application/users/templates/users/signup.html`视图，该视图仅包含允许用户输入其期望的用户名、电子邮件地址和密码的相关表单控件：

```py
{% extends "layout.html" %}

{% block content %}

<form action="{{ url_for('users.signup')}}" method="post">
  {{ form.hidden_tag() }}
  {{ form.id }}
  <div>{{ form.username.label }}: {{ form.username }}</div>
  {% if form.username.errors %}
  <ul class="errors">{% for error in form.username.errors %}<li>{{ error }}</li>{% endfor %}</ul>
  {% endif %}

  <div>{{ form.email.label }}: {{ form.email }}</div>
  {% if form.email.errors %}
  <ul class="errors">{% for error in form.email.errors %}<li>{{ error }}</li>{% endfor %}</ul>
  {% endif %}

  <div>{{ form.password.label }}: {{ form.password }}</div>
  {% if form.password.errors %}
  <ul class="errors">{% for error in form.password.errors %}<li>{{ error }}</li>{% endfor %}</ul>
  {% endif %}

  <div><input type="submit" value="Sign up!"></div>
</form>

{% endblock %}
```

一旦我们有了前面的模板，我们将更新我们的应用程序工厂，将用户视图绑定到应用程序对象。我们还将初始化 Flask-Login 扩展，就像我们在上一章所做的那样：

```py
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.bcrypt import Bcrypt
from blinker import Namespace
from flask.ext.login import LoginManager

# Initialize the db extension, but without configuring
# it with an application instance.
db = SQLAlchemy()
flask_bcrypt = Bcrypt()
login_manager = LoginManager()

socializer_signals = Namespace()
user_followed = socializer_signals.signal('user-followed')

from signal_handlers import *

def create_app(config=None):
app = Flask(__name__)

if config is not None:
 app.config.from_object(config)

 # Initialize any extensions and bind blueprints to the
 # application instance here.
 db.init_app(app)
 flask_bcrypt.init_app(app)
 login_manager.init_app(app)

 from application.users.views import users
 app.register_blueprint(users, url_prefix='/users')

 from application.users import models as user_models
 @login_manager.user_loader
 de fload_user(user_id):
 return user_models.User.query.get(int(user_id))

 return app

```

别忘了在我们的`application/settings.py`模块中添加一个`SECRET_KEY`配置值：

```py
SQLALCHEMY_DATABASE_URI = 'sqlite:///socializer.db'
SECRET_KEY = 'BpRvzXZ800[-t:=z1eZtx9t/,P*'

```

现在，我们应该能够运行应用程序并访问`http://localhost:5000/users/signup`，在那里我们将看到一系列用于创建新用户账户的表单输入。在成功创建新用户后，我们将自动使用 Flask-Login 扩展的`login_user()`方法进行身份验证。

然而，我们尚未考虑到的是，由于与我们的 SQLAlchemy 模型和数据库期望不匹配，用户创建失败的情况。这可能由于多种原因发生：

+   现有用户已经声明了提交的电子邮件或用户名值，这两者在我们用户模型中都被标记为唯一

+   某个字段需要数据库指定的额外验证标准，而这些标准未被满足

+   数据库不可用（例如，由于网络分区）

为了确保这些事件以尽可能优雅的方式处理，我们必须封装可能引发相关异常的代码部分，这些异常表明了这些条件之一。因此，在我们的`application/users/views.py`模块中的注册路由中，我们将修改将用户持久化到数据库的代码部分：

```py
# place with other imports…
from sqlalchemy import exc

# …

try:
 db.session.add(user)
 db.session.commit()
 except exc.IntegrityError as e:
 # A unique column constraint was violated
 current_app.exception("User unique constraint violated.")
 return render_template('users/signup.html', form=form)
 except exc.SQLAlchemyError:
 current_app.exception("Could not save new user!")
 flash("Something went wrong while creating this user!")
 return render_template('users/signup.html', form=form)

```

此外，我们将在登录路由中使用 try/except 块包装`User.query.filter_by(username=form.username.data).one()`，以确保我们处理登录表单中提交的用户名在数据库中根本不存在的情况：

```py
try:
    # We use one() here instead of first()
    user = User.query.filter_by(
           username=form.username.data).one()s
except NoResultFound:
    flash("User {username} does not exist.".format(
        username=form.username.data))
    return render_template('users/login.html', form=form)

# …
```

# 功能测试

既然我们已经创建了一些处理用户注册和登录的路由和模板，让我们利用本章早些时候获得的`py.test`知识来编写一些事后的集成测试，以确保我们的视图按预期行为。首先，让我们在`application/tests/test_user_views.py`中创建一个新的测试模块，并编写我们的第一个使用客户端固定装置的测试，以便通过内置的 Werkzeug 测试客户端模拟对应用程序的请求。这将确保已构建适当的请求上下文，以便上下文绑定对象（例如，`url_for`，`g`）可用，如下所示：

```py
def test_get_user_signup_page(client):
 """Ensure signup page is available."""
 response = client.get('/users/signup')
 assert response.status_code == 200
 assert 'Sign up!' in response.data

```

前面的测试首先向`/users/signup`路由发出请求，然后断言该路由的 HTTP 响应代码为`200`（任何成功返回`render_template()`函数的默认值）。然后它断言**注册！**按钮文本出现在返回的 HTML 中，这是一个相对安全的保证，即所讨论的页面在没有任何重大错误的情况下被渲染。

接下来，让我们添加一个成功用户注册的测试，如下所示：

```py
from flask import session, get_flashed_messages
from application.users.models import User
from application import flask_bcrypt

def test_signup_new_user(client):
 """Successfully sign up a new user."""
 data = {'username': 'test_username', 'email': 'test@example.com',
 'password': 'my test password'}

 response = client.post('/users/signup', data=data)

 # On successful creation we redirect.
 assert response.status_code == 302

 # Assert that a session was created due to successful login
 assert '_id' in session

 # Ensure that we have no stored flash messages indicating an error
 # occurred.
 assert get_flashed_messages() == []

 user = User.query.filter_by(username=data['username']).one()

 assert user.email == data['email']
 assert user.password
 assert flask_bcrypt.check_password_hash(
 user.password, data['password'])

```

如果我们立即运行测试套件，它会失败。这是由于 Flask-WTF 引入的一个微妙效果，它期望为任何提交的表单数据提供 CSRF 令牌。以下是我们修复此问题的两种方法：

+   我们可以在模拟的 POST 数据字典中手动生成 CSRF 令牌；`WTForms`库提供了实现此功能的方法

+   我们可以在`test_settings.py`模块中将`WTF_CSRF_ENABLED`配置布尔值设置为`False`，这样测试套件中发生的所有表单验证将不需要 CSRF 令牌即可被视为有效。

第一种方法的优势在于，请求/响应周期中发送的数据将紧密反映生产场景中发生的情况，缺点是我们必须为想要测试的每个表单生成（或程序化抽象）所需的 CSRF 令牌。第二种方法允许我们在测试套件中完全停止关心 CSRF 令牌，这也是一个缺点。本章中，我们将采用第二种方法所述的方式。

在前面的测试中，我们将首先创建一个包含我们希望 POST 到注册端点的模拟表单数据的字典，然后将此数据传递给`client.post('/users/signup')`方法。在新用户成功注册后，我们应该期望被重定向到不同的页面（我们也可以检查响应中*Location*头的存在和值），此外，Flask-Login 将创建一个会话 ID 来处理我们的用户会话。此外，对于我们当前的应用程序，成功的注册尝试意味着我们不应该有任何存储以供显示的闪现消息，并且应该有一个新用户记录，其中包含在 POST 中提供的数据，并且该数据应该可用并填充。

虽然大多数开发者非常热衷于测试请求的成功路径，但测试最常见的失败路径同样重要，甚至更为重要。为此，让我们为最典型的失败场景添加以下几个测试，首先是使用无效用户名的情况：

```py
import pytest
import sqlalchemy

def test_signup_invalid_user(client):
 """Try to sign up with invalid data."""

 data = {'username': 'x', 'email': 'short@example.com',
 'password': 'a great password'}

 response = client.post('/users/signup', data=data)

 # With a form error, we still return a 200 to the client since
 # browsers are not always the best at handling proper 4xx response codes.
 assert response.status_code == 200
 assert 'must be between 3 and 40 characters long.' in response.data

```

### 注意

记住，我们在`application.users.views.CreateUserForm`类中定义了用户注册的表单验证规则；用户名必须介于 3 到 40 个字符之间。

```py
def test_signup_invalid_user_missing_fields(client):
 """Try to sign up with missing email."""

 data = {'username': 'no_email', 'password': 'a great password'}
 response = client.post('/users/signup', data=data)

 assert response.status_code == 200
 assert 'This field is required' in response.data

 with pytest.raises(sqlalchemy.orm.exc.NoResultFound):
 User.query.filter_by(username=data['username']).one()

 data = {'username': 'no_password', 'email': 'test@example.com'}
 response = client.post('/users/signup', data=data)

 assert response.status_code == 200
 assert 'This field is required' in response.data

 with pytest.raises(sqlalchemy.orm.exc.NoResultFound):
 User.query.filter_by(username=data['username']).one()

```

### 注意

在前面的测试中，我们使用了`py.test`（及其他测试库）中一个经常被忽视的便利函数，即`raises(exc)`上下文管理器。这允许我们将一个函数调用包裹起来，在其中我们期望抛出异常，如果预期的异常类型（或派生类型）未被抛出，它本身将导致测试套件中的失败。

# 你的新闻动态

尽管我们已经构建了大部分支持架构，为我们的 Socializer 应用程序提供功能，但我们仍缺少拼图中更基本的一块：能够按时间顺序查看你关注的人的帖子。

为了使显示帖子所有者的信息更简单一些，让我们在我们的`Post`模型中添加一个关系定义：

```py
class Post(db.Model):
 # …
 user = db.relationship('User',
 backref=db.backref('posts', lazy='dynamic'))

```

这将允许我们使用`post.user`访问与给定帖子关联的任何用户信息，这在显示单个帖子或帖子列表的任何视图中都将非常有用。

让我们在`application/users/views.py`中为此添加一条路由：

```py
@users.route('/feed', methods=['GET'])
@login_required
def feed():
 """
 List all posts for the authenticated user; most recent first.
 """
 posts = current_user.newsfeed()
 return render_template('users/feed.html', posts=posts)

```

请注意，前面的代码片段使用了`current_user`代理（您应该将其导入到模块中），该代理由 Flask-Login 扩展提供。由于 Flask-Login 扩展在代理中存储了经过身份验证的用户对象，因此我们可以像在普通`user`对象上一样调用其方法和属性。

由于之前的 feed 端点已经运行，我们需要在`application/users/templates/users/feed.html`中提供支持模板，以便我们实际上可以渲染响应：

```py
{% extends "layout.html" %}

{% block content %}
<div class="new-post">
  <p><a href="{{url_for('posts.add')}}">New Post</a></p>
</div>

{% for post in posts %}
<div class="post">
  <span class="author">{{post.user.username}}</span>, published on <span class="date">{{post.created_on}}</span>
  <pre><code>{{post.content}}</code></pre>
</div>
{% endfor %}

{% endblock %}
```

我们需要的最后一部分是添加新帖子的视图处理程序。由于我们尚未创建`application/posts/views.py`模块，让我们来创建它。我们将需要一个`Flask-WTForm`类来处理/验证新帖子，以及一个路由处理程序来发送和处理所需的字段，所有这些都连接到一个新的蓝图上：

```py
from flask import Blueprint, render_template, url_for, redirect, flash, current_app

from flask.ext.login import login_required, current_user
from flask.ext.wtf import Form
from wtforms import StringField
from wtforms.widgets import TextArea
from wtforms.validators import DataRequired
from sqlalchemy import exc

from models import Post
from application import db

posts = Blueprint('posts', __name__, template_folder='templates')

class CreatePostForm(Form):
 """Form for creating new posts."""

 content = StringField('content', widget=TextArea(),
 validators=[DataRequired()])

@posts.route('/add', methods=['GET', 'POST'])
@login_required
def add():
 """Add a new post."""

 form = CreatePostForm()
 if form.validate_on_submit():
 user_id = current_user.id

 post = Post(user_id=user_id, content=form.content.data)
 db.session.add(post)

 try:
 db.session.commit()
 except exc.SQLAlchemyError:
 current_app.exception("Could not save new post!")
 flash("Something went wrong while creating your post!")
 else:
 return render_template('posts/add.html', form=form)

 return redirect(url_for('users.feed'))

```

相应的`application/posts/templates/posts/add.html`文件正如预期的那样相对简单，并且让人想起上一章中使用的视图模板。这里是：

```py
{% extends "layout.html" %}

{% block content %}
<form action="{{ url_for('posts.add')}}" method="post">

  {{ form.hidden_tag() }}
  {{ form.id }}

  <div class="row">
    <div>{{ form.content.label }}: {{ form.content }}</div>
    {% if form.content.errors %}
    <ul class="errors">{% for error in form.content.errors %}<li>{{ error }}</li>{% endfor %}</ul>
    {% endif %}
  </div>

  <div><input type="submit" value="Post"></div>
</form>

{% endblock %}
```

最后，我们需要通过在我们的应用程序工厂中将其绑定到我们的应用程序对象，使应用程序意识到这个新创建的帖子蓝图，位于`application/__init__.py`中：

```py
def create_app(config=None):
    app = Flask(__name__)

    # …
    from application.users.views import users
    app.register_blueprint(users, url_prefix='/users')

 from application.posts.views import posts
 app.register_blueprint(posts, url_prefix='/posts')

        # …
```

一旦上述代码就位，我们可以通过在`/users/signup`端点的 Web 界面上创建用户帐户，然后在`/posts/add`上为用户创建帖子来为这些用户生成一些测试用户和帖子。否则，我们可以创建一个小的 CLI 脚本来为我们执行此操作，我们将在下一章中学习如何实现。我们还可以编写一些测试用例来确保新闻源按预期工作。实际上，我们可以做这三件事！

# 摘要

我们通过首先介绍应用程序工厂的概念，并描述了这种方法的一些好处和权衡来开始本章。接下来，我们使用我们新创建的应用程序工厂来使用`py.test`设置我们的第一个测试套件，这需要对我们的应用程序对象的创建方式进行一些修改，以确保我们获得一个适合的实例，配置为测试场景。 

然后，我们迅速着手实现了典型 Web 应用程序背后的基本数据模型，其中包含了*社交*功能，包括关注其他用户以及被其他用户关注的能力。我们简要涉及了所谓新闻源应用程序的几种主要实现模式，并为我们自己的数据模型使用了最简单的版本。

这随后导致我们讨论和探索了发布/订阅设计模式的概念，Flask 和各种 Flask 扩展集成了`Blinker`包中的一个进程内实现。利用这些新知识，我们创建了自己的发布者和订阅者，使我们能够解决许多现代 Web 应用程序中存在的一些常见横切关注点。

对于我们的下一个项目，我们将从创建过去几章中使用的基于 HTML 的表单和视图切换到另一个非常重要的现代 Web 应用程序部分：提供一个有用的 JSON API 来进行交互。
