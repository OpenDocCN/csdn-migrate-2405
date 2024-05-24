# Flask 框架学习手册（一）

> 原文：[`zh.annas-archive.org/md5/A6963809F66F360038656FE5292ADA55`](https://zh.annas-archive.org/md5/A6963809F66F360038656FE5292ADA55)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

欢迎阅读《学习 Flask》，这本书将教会您使用 Flask 构建 Web 应用程序所需的必要技能，这是一个轻量级的 Python Web 框架。本书采用了一个以示例驱动的方法，旨在让您快速入门。实际示例与适量的背景信息相结合，以确保您不仅了解 Flask 开发的如何，还了解为什么。

Flask 最初是由 Armin Ronacher 在 2010 年作为复杂的愚人节恶作剧的一部分发布的。该项目吹嘘自己是“下一代 Python 微型 Web 框架”，并讽刺了类似微框架所流行的功能。尽管 Flask 原本是一个恶作剧，但作者们对该项目引起了许多人的严肃兴趣感到意外。

Flask 是一个建立在两个优秀库之上的微框架：Jinja2 模板引擎和 Werkzeug WSGI 工具包。尽管与其他框架（如 Django 和 Pylons）相比，Flask 是一个相对较新的框架，但它已经获得了大量忠实的追随者。Flask 为常见的 Web 开发任务提供了强大的工具，并鼓励采用自己的库来处理其他一切，使程序员有灵活性来选择最佳组件来构建他们的应用程序。每个 Flask 应用程序都是不同的，正如项目的文档所述，“Flask 很有趣”。

Flask 微框架在设计和 API 方面代表了与大多数其他流行的 Python Web 框架的不同，这导致许多新手开发人员问：“构建应用程序的正确方法是什么？” Flask 对于我们开发者应该如何构建应用程序并没有提供强烈的意见。相反，它提供了关于构建应用程序所需的意见。Flask 可以被认为是一组对象和函数，用于处理常见的 Web 任务，如将 URL 路由到代码、处理请求数据和渲染模板。虽然 Flask 提供的灵活性令人振奋，但它也可能导致混乱和糟糕的设计。

本书的目的是帮助您将这种灵活性视为机会。在本书的过程中，我们将构建并逐步增强一个由 Flask 驱动的博客网站。通过向网站添加新功能来介绍新概念。到本书结束时，我们将创建一个功能齐全的网站，您将对 Flask 及其常用扩展和库生态系统有着扎实的工作知识。

# 本书涵盖的内容

《第一章》《创建您的第一个 Flask 应用程序》以大胆宣言“Flask 很有趣”开始，这是当您查看官方 Flask 文档时看到的第一件事情之一，在本章中，您将了解为什么许多 Python 开发人员都同意这一观点。

《第二章》《使用 SQLAlchemy 的关系数据库》指出，关系数据库是几乎所有现代 Web 应用程序构建的基石。我们将使用 SQLAlchemy，这是一个强大的对象关系映射器，可以让我们抽象出多个数据库引擎的复杂性。在本章中，您将了解您早期选择的数据模型将影响随后代码的几乎每个方面。

《第三章》《模板和视图》涵盖了框架中最具代表性的两个组件：Jinja2 模板语言和 URL 路由框架。我们将完全沉浸在 Flask 中，看到我们的应用程序最终开始成形。随着我们在本章的进展，我们的应用程序将开始看起来像一个真正的网站。

第四章 *表单和验证*，向您展示如何使用表单直接通过由流行的 WTForms 库处理的网站修改博客内容。这是一个有趣的章节，因为我们将添加各种与网站交互的新方式。我们将创建与我们的数据模型一起工作的表单，并学习如何接收和验证用户数据。

第五章 *用户认证*，解释了如何向您的网站添加用户认证。能够区分一个用户和另一个用户使我们能够开发一整套新的功能。例如，我们将看到如何限制对创建、编辑和删除视图的访问，防止匿名用户篡改网站内容。我们还可以向用户显示他们的草稿帖子，但对其他人隐藏。

第六章 *建立管理仪表板*，向您展示如何为您的网站构建一个管理仪表板，使用优秀的 Flask-Admin。我们的管理仪表板将使特定选定的用户能够管理整个网站上的所有内容。实质上，管理站点将是数据库的图形前端，支持创建、编辑和删除应用程序表中的行的操作。

第七章 *AJAX 和 RESTful API*，使用 Flask-Restless 为博客应用程序创建 RESTful API。RESTful API 是一种强大的访问应用程序的方式，通过提供高度结构化的数据来表示它。Flask-Restless 与我们的 SQLAlchemy 模型非常配合，它还处理复杂的任务，如序列化和结果过滤。

第八章 *测试 Flask 应用*，介绍了如何编写覆盖博客应用程序所有部分的单元测试。我们将利用 Flask 的测试客户端来模拟“实时”请求。我们还将看到 Mock 库如何简化测试复杂的交互，如调用数据库等第三方服务。

第九章 *优秀的扩展*，教您如何使用流行的第三方扩展增强您的 Flask 安装。我们在整本书中都使用了扩展，但现在我们可以探索额外的安全性或功能，而几乎不费吹灰之力，可以很好地完善您的应用程序。

第十章 *部署您的应用程序*，教您如何安全地以自动化、可重复的方式部署您的 Flask 应用程序。我们将看看如何配置常用的 WSGI 能力服务器，如 Apache 和 Nginx，以及 Python Web 服务器 Gunicorn，为您提供多种选择。然后，我们将看到如何使用 SSL 安全地部分或整个网站，最后使用配置管理工具来自动化我们的部署。

# 本书所需内容

虽然 Python 在大多数操作系统上都能很好地运行，而且我们在本书中尽量保持了与操作系统无关的方法，但建议在使用本书时使用运行 Linux 发行版或 OS X 的计算机，因为 Python 已经安装并运行。Linux 发行版可以安装在计算机上或虚拟机中。几乎任何 Linux 发行版都可以，任何最新版本的 Ubuntu 都可以。

# 这本书适合谁

这本书适合任何想要将他们对 Python 的知识发展成可以在 Web 上使用的人。Flask 遵循 Python 的设计原则，任何了解 Python 甚至不了解 Python 的人都可以轻松理解。

# 约定

在本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是这些样式的一些示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下：“我们可以通过使用`include`指令来包含其他上下文。”

代码块设置如下：

```py
from app import api
from models import Comment

api.create_api(Comment, methods=['GET', 'POST'])
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目会以粗体显示：

```py
{% block content %}
  {{ entry.body }}

  <h4 id="comment-form">Submit a comment</h4>
 {% include "entries/includes/comment_form.html" %}
{% endblock %}
```

任何命令行输入或输出都以以下方式书写：

```py
(blog) $ python manage.py db upgrade
INFO  [alembic.migration] Context impl SQLiteImpl.
INFO  [alembic.migration] Will assume non-transactional DDL.
INFO  [alembic.migration] Running upgrade 594ebac9ef0c -> 490b6bc5f73c, empty message

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这样的方式出现在文本中：“您应该在空白白色页面上看到消息**Hello, Flask**显示。”

### 注意

警告或重要提示会出现在这样的框中。

### 提示

提示和技巧会以这样的方式出现。


# 第一章：创建您的第一个 Flask 应用程序

*Flask 很有趣*。这是您在查看官方 Flask 文档时看到的第一件事情之一，而在本书的过程中，您将了解为什么这么多 Python 开发人员同意这一观点。

在本章中，我们将：

+   简要讨论 Flask 框架的特点

+   设置开发环境并安装 Flask

+   实现一个最小的 Flask 应用程序并分析其工作原理

+   尝试常用 API 和交互式调试器

+   开始着手博客项目，该项目将在本书的过程中逐步增强

# 什么是 Flask？

Flask 是一个用 Python 编写的轻量级 Web 框架。Flask 最初是一个愚人节玩笑，后来成为 Python Web 框架世界中备受欢迎的黑马。它现在是创业公司中最广泛使用的 Python Web 框架之一，并且正在成为大多数企业快速简单解决方案的完美工具。在其核心，它提供了一组强大的库，用于处理最常见的 Web 开发任务，例如：

+   URL 路由，使 URL 映射到您的代码变得容易

+   使用 Jinja2 进行模板渲染，这是最强大的 Python 模板引擎之一。

+   会话管理和保护 Cookie

+   HTTP 请求解析和灵活的响应处理

+   交互式基于 Web 的调试器

+   易于使用的灵活应用程序配置管理

本书将通过实际的实例教您如何使用这些工具。我们还将讨论 Flask 中未包含的常用第三方库，例如数据库访问和表单验证。通过本书的学习，您将准备好使用 Flask 处理下一个大型项目。

## 自由伴随着责任

正如文档所述，*Flask 很有趣*，但在构建大型应用程序时可能会具有挑战性。与 Django 等其他流行的 Python Web 框架不同，Flask 不强制规定模块或代码的结构方式。如果您有其他 Web 框架的经验，您可能会惊讶于在 Flask 中编写应用程序感觉像编写 Python 而不是框架样板。

本书将教您使用 Flask 编写清晰、表达力强的应用程序。随着本书的学习，您不仅将成为熟练的 Flask 开发人员，还将成为更强大的 Python 开发人员。

# 设置开发环境

Flask 是用 Python 编写的，因此在我们开始编写 Flask 应用程序之前，我们必须确保已安装 Python。大多数 Linux 发行版和最新版本的 OSX 都预装了 Python。本书中的示例将需要 Python 2.6 或 2.7。有关安装 Python 的说明，请访问[`www.python.org`](http://www.python.org)。

如果这是您第一次使用 Python，网上有许多优秀的免费资源可供使用。我建议阅读*Learn Python The Hard Way*，作者是*Zed Shaw*，可在[`learnpythonthehardway.org`](http://learnpythonthehardway.org)免费在线阅读。还想了解更多？您可以在[`resrc.io/list/10/list-of-free-programming-books/#python`](http://resrc.io/list/10/list-of-free-programming-books/#python)找到大量免费的 Python 资源。

您可以通过从命令提示符运行 Python 交互解释器来验证 Python 是否已安装并且您拥有正确的版本：

```py
$ python
Python 2.7.6 (default, Nov 26 2013, 12:52:49)
[GCC 4.8.2] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>>

```

在提示符（`>>>`）中键入`exit()`并按*Enter*离开解释器。

## 支持 Python 3

本书将包含兼容 Python 2 和 Python 3 的代码。不幸的是，由于 Python 3 相对于 Python 2 仍然相对较新，本书中使用的并非所有第三方包都保证与 Python 3 无缝工作。许多人正在努力使流行的开源库与两个版本兼容，但在撰写本文时，仍有一些库尚未移植。为了获得最佳结果，请确保您在系统上安装的 Python 版本为 2.6 或更高。

# 安装 Python 包

现在您已经确保 Python 正确安装，我们将安装一些流行的 Python 包，这些包将在本书的过程中使用。

我们将系统范围内安装这些包，但一旦它们安装完成，我们将专门在虚拟环境中工作。

## 安装 pip

事实上，Python 包安装程序是`pip`。我们将在整本书中使用它来安装 Flask 和其他第三方库。

如果您已经安装了`setuptools`，您可以通过运行以下命令来安装`pip`：

```py
$ sudo easy_install pip

```

安装完成后，请验证`pip`是否正确安装：

```py
$ pip --version
pip 1.2.1 from /usr/lib/python2.7/site-packages/pip-1.2.1-py2.7.egg (python 2.7)

```

版本号可能会发生变化，因此请参考官方说明，网址为[`www.pip-installer.org/en/latest/installing.html`](http://www.pip-installer.org/en/latest/installing.html)。

## 安装 virtualenv

安装了 pip 之后，我们可以继续安装任何 Python 开发人员工具包中最重要的工具：`virtualenv`。Virtualenv 可以轻松创建隔离的 Python 环境，其中包括它们自己的系统和第三方包的副本。

### 为什么使用 virtualenv？

Virtualenv 解决了与包管理相关的许多问题。想象一下，您有一个使用非常早期版本的 Flask 构建的旧应用程序，您想使用最新版本的 Flask 构建一个新项目。如果 Flask 是系统范围内安装的，您将被迫要么升级旧项目，要么针对旧的 Flask 编写新项目。如果两个项目都使用 virtualenv，那么每个项目都可以运行自己的 Flask 版本，而不会有冲突或问题。

Virtualenv 可以轻松控制项目使用的第三方包的版本。

另一个考虑因素是，通常需要提升权限（`sudo pip install foo`）才能在系统范围内安装包。通过使用 virtualenv，您可以创建 Python 环境并像普通用户一样安装包。如果您正在部署到共享托管环境或者在没有管理员权限的情况下，这将非常有用。

### 使用 pip 安装 virtualenv

我们将使用 pip 来安装`virtualenv`；因为它是一个标准的 Python 包，所以可以像安装其他 Python 包一样安装。为了确保`virtualenv`被系统范围内安装，运行以下命令（需要提升的权限）：

```py
$ sudo pip install virtualenv
$ virtualenv --version
1.10.1

```

版本号可能会发生变化，因此请参考[`virtualenv.org`](http://virtualenv.org)上的官方说明。

# 创建您的第一个 Flask 应用程序

现在我们已经安装了适当的工具，我们准备创建我们的第一个 Flask 应用程序。首先，在一个方便的地方创建一个目录，用于保存所有的 Python 项目。在命令提示符或终端中，导航到您的项目目录；我的是`/home/charles/projects`，或者在基于 Unix 的系统中简写为`~/projects`。

```py
$ mkdir ~/projects
$ cd ~/projects

```

现在我们将创建一个`virtualenv`。下面的命令将在您的项目文件夹中创建一个名为`hello_flask`的新目录，其中包含一个完整的、隔离的 Python 环境。

```py
$ virtualenv hello_flask

New python executable in hello_flask/bin/python2.
Also creating executable in hello_flask/bin/python
Installing setuptools............done.
Installing pip...............done.
$ cd hello_flask

```

如果列出`hello_flask`目录的内容，您将看到它创建了几个子目录，包括一个包含 Python 和 pip 副本的`bin`文件夹（在 Windows 上是`Scripts`）。下一步是激活您的新 virtualenv。具体的说明因使用 Windows 还是 Mac OS/Linux 而有所不同。要激活您的 virtualenv，请参考以下截图：

![创建您的第一个 Flask 应用](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_01_01.jpg)

创建 hello_flask virtualenv

当您`激活`一个`virtualenv`时，您的 PATH 环境变量会被临时修改，以确保您安装或使用的任何软件包都受限于您的`virtualenv`。

## 在您的 virtualenv 中安装 Flask

现在我们已经验证了我们的`virtualenv`设置正确，我们可以安装 Flask 了。

当您在虚拟环境中时，永远不应该使用管理员权限安装软件包。如果在尝试安装 Flask 时收到权限错误，请仔细检查您是否正确激活了您的`virtualenv`（您的命令提示符中应该看到(`hello_flask`)）。

```py
(hello_flask) $ pip install Flask

```

当 pip 下载 Flask 包及其相关依赖项并将其安装到您的 virtualenv 时，您将看到一些文本滚动。Flask 依赖于一些额外的第三方库，pip 将自动为您下载和安装这些库。让我们验证一下是否一切都安装正确：

```py
(hello_flask) $ python
>>> import flask
>>> flask.__version__
'0.10.1'
>>> flask
<module 'flask' from '/home/charles/projects/hello_flask/lib/python2.7/site-packages/flask/__init__.pyc'>

```

恭喜！您已经安装了 Flask，现在我们准备开始编码。

## Hello, Flask!

在`hello_flask` virtualenv 中创建一个名为`app.py`的新文件。使用您喜欢的文本编辑器或 IDE，输入以下代码：

```py
from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    return 'Hello, Flask!'

if __name__ == '__main__':
    app.run(debug=True)
```

保存文件，然后通过命令行运行`app.py`来执行它。您需要确保已激活`hello_flask` virtualenv：

```py
$ cd ~/projects/hello_flask
(hello_flask) $ python app.py
* Running on http://127.0.0.1:5000/

```

打开您喜欢的 Web 浏览器，导航到显示的 URL（`http://127.0.0.1:5000`）。您应该在一个空白的白色页面上看到消息**Hello, Flask!**。默认情况下，Flask 开发服务器在本地运行在`127.0.0.1`，绑定到端口`5000`。

![Hello, Flask!](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_01_02.jpg)

您的第一个 Flask 应用程序。

## 理解代码

我们刚刚创建了一个非常基本的 Flask 应用程序。要理解发生了什么，让我们逐行分解这段代码。

`from flask import Flask`

我们的应用程序通过导入`Flask`类开始。这个类代表一个单独的 WSGI 应用程序，是任何 Flask 项目中的核心对象。

WSGI 是 Python 标准的 Web 服务器接口，在 PEP 333 中定义。您可以将 WSGI 视为一组行为和方法，当实现时，允许您的 Web 应用程序与大量的 Web 服务器一起工作。Flask 为您处理所有实现细节，因此您可以专注于编写 Web 应用程序。

`app = Flask(__name__)`

在这一行中，我们在变量`app`中创建了一个应用程序实例，并将其传递给我们模块的名称。变量`app`当然可以是任何东西，但是对于大多数 Flask 应用程序来说，`app`是一个常见的约定。应用程序实例是诸如视图、URL 路由、模板配置等的中央注册表。我们提供当前模块的名称，以便应用程序能够通过查看当前文件夹内部找到资源。这在以后当我们想要渲染模板或提供静态文件时将会很重要。

```py
@app.route('/')
def index():
 return 'Hello, Flask!'

```

在前面的几行中，我们指示我们的 Flask 应用程序将所有对`/`（根 URL）的请求路由到这个视图函数（`index`）。视图只是一个返回某种响应的函数或方法。每当您打开浏览器并导航到我们应用程序的根 URL 时，Flask 将调用这个视图函数并将返回值发送到浏览器。

关于这些代码行有一些需要注意的事项：

+   `@app.route`是上面定义的`app`变量的 Python 装饰器。这个装饰器(`app.route`)包装了下面的函数，这种情况下是`index`，以便将特定 URL 的请求路由到特定视图。这里选择`index`作为函数的名称，因为它是 Web 服务器使用的第一个页面的通用名称。其他示例可能是主页或主要。装饰器是 Python 开发人员丰富且有趣的主题，所以如果您对它们不熟悉，我建议使用您喜欢的搜索引擎找到一个好的教程。

+   `index`函数不带任何参数。如果您来自其他 Web 框架，并且期望有一个请求对象或类似的东西，这可能看起来有点奇怪。在接下来的示例中，我们将看到如何从请求中访问值。

+   `index`函数返回一个普通的字符串对象。在后面的示例中，我们将看到如何渲染模板以返回 HTML。

+   以下行使用调试模式下内置的开发服务器执行我们的应用程序。`if`语句是一个常见的 Python 约定，确保只有在通过 python `app.py`运行脚本时才会运行应用程序，如果我们尝试从另一个 Python 文件导入此应用程序，则不会运行。

```py
if __name__ == '__main__':
    app.run(debug=True)
```

## 路由和请求

现在我们的 Flask 应用程序并不那么有趣，所以让我们看看我们可以以不同方式为我们的 Web 应用程序添加更有趣的行为。一种常见的方法是添加响应式行为，以便我们的应用程序将查看 URL 中的值并处理它们。让我们为我们的 Hello Flask 应用程序添加一个名为`hello`的新路由。这个新路由将向出现在 URL 中的人显示问候语：

```py
from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    return 'Hello, Flask!'

@app.route('/hello/<name>')
def hello(name):
    return 'Hello, %s' % name

if __name__ == '__main__':
    app.run(debug=True)
```

再次运行我们的应用程序并在 Web 浏览器中打开它。现在我们可以导航到 URL，比如`http://127.0.0.1/hello/Charlie`，并看到我们的自定义消息：

![路由和请求](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_01_03.jpg)

我们的 Flask 应用程序显示自定义消息

在前面的示例中，我们添加的路由指定了一个参数：`name`。这个参数也出现在函数声明中作为唯一的参数。Flask 自动将 URL`/hello/Charlie`与`hello`视图进行匹配；这被称为映射。然后将字符串`Charlie`作为参数传递给我们的视图函数。

如果我们导航到`http://127.0.0.1:5000/hello/`而没有指定名称会发生什么？正如您所看到的，Flask 开发服务器将返回`404`响应，表示 URL 与任何已知路由不匹配。

![路由和请求](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_01_04.jpg)

Flask 404 页面

### 从请求中读取值

除了 URL 之外，值可以通过查询字符串传递给您的应用程序。查询字符串由任意键和值组成，这些键和值被附加到 URL 上，使用问号：

| URL | 参数值 |
| --- | --- |
| `/hello/?name=Charlie` | name: Charlie |
| `/hello/?name=Charlie&favorite_color=green` | name: Charliefavorite_color: green |

为了在视图函数中访问这些值，Flask 提供了一个请求对象，该对象封装了关于当前 HTTP 请求的各种信息。在下面的示例中，我们将修改我们的`hello`视图，以便通过查询字符串传递的名称也能得到响应。如果在查询字符串或 URL 中未指定名称，我们将返回 404。

```py
from flask import Flask, abort, request

app = Flask(__name__)

@app.route('/')
def index():
    return 'Hello, Flask!'

@app.route('/hello/<name>')
@app.route('/hello/')
def hello(name=None):
    if name is None:
        # If no name is specified in the URL, attempt to retrieve it
        # from the query string.
        name = request.args.get('name')
        if name:
            return 'Hello, %s' % name
    else:
        # No name was specified in the URL or the query string.
        abort(404)

if __name__ == '__main__':
    app.run(debug=True)
```

正如您所看到的，我们已经为我们的`hello`视图添加了另一个路由装饰器：Flask 允许您将多个 URL 路由映射到同一个视图。因为我们的新路由不包含名称参数，我们需要修改视图函数的参数签名，使`name`成为可选参数，我们通过提供默认值`None`来实现这一点。

我们视图的函数体也已经修改为检查 URL 中是否存在名称。如果未指定名称，我们将中止并返回`404`页面未找到状态码。

![从请求中读取值](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_01_05.jpg)

使用查询字符串问候某人

## 调试 Flask 应用程序

不可避免的是，迟早我们会在我们的代码中引入一个 bug。由于 bug 是不可避免的，作为开发人员，我们所能希望的最好的事情就是有助于我们快速诊断和修复 bug 的好工具。幸运的是，Flask 自带了一个非常强大的基于 Web 的调试器。Flask 调试器使得在错误发生的瞬间内省应用程序的状态成为可能，消除了需要添加打印语句或断点的必要。

这可以通过在运行时告诉 Flask 应用程序以`debug`模式运行来启用。我们可以通过几种方式来做到这一点，但实际上我们已经通过以下代码做到了这一点：

```py
if __name__ == '__main__':
    app.run(debug=True)
```

为了尝试它，让我们通过制造一个拼写错误来引入`hello_flask`应用程序中的一个 bug。在这里，我只是从变量`name`中简单地删除了末尾的 e：

```py
@app.route('/hello/<name>')
@app.route('/hello/')
def hello(name=None):
    if nam is None:
        # No name was specified in the URL or the query string.
        abort(404)
```

当我们启动开发服务器并尝试访问我们的视图时，现在会出现调试页面：

![调试 Flask 应用程序](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_01_06.jpg)

在 Web 浏览器中运行的 Flask 交互式调试器

这个代码列表被称为**Traceback**，它由调用堆栈组成，即在实际错误之前的嵌套函数调用列表。Traceback 通常提供了一个很好的线索，可以解释发生了什么。在底部我们看到了我们有意打错的代码行，以及实际的 Python 错误，这是一个**NameError**异常，告诉我们**nam**未定义。

![调试 Flask 应用程序](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_01_07.jpg)

Traceback 详细显示了我们的拼写错误和错误的描述。

真正的魔力发生在你把鼠标放在高亮的行上时。在右侧，你会看到两个小图标，代表终端和源代码文件。点击**Source Code**图标将展开包含错误行的源代码。这对于解释错误时建立一些上下文非常有用。

终端图标最有趣。当你点击**Terminal**图标时，一个小控制台会出现，带有标准的 Python 提示符。这个提示符允许你实时检查异常发生时本地变量的值。尝试输入`name`并按*Enter*——它应该显示在 URL 中指定的值（如果有的话）。我们还可以通过以下方式检查当前请求参数：

![调试 Flask 应用程序](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_01_08.jpg)

使用调试控制台内省变量

当你在章节中工作并进行实验时，能够快速诊断和纠正任何 bug 将是一项非常有价值的技能。我们将在第八章中回到交互式调试器，*测试 Flask 应用程序*，但现在要知道它的存在，并且可以在代码中断时和地方使用它进行内省。

# 介绍博客项目

在本书的其余部分，我们将构建、增强和部署一个对程序员友好的博客站点。这个项目将介绍你最常见的 Web 开发任务，比如使用关系数据库、处理和验证表单数据，以及（每个人都喜欢的）测试。在每一章中，你将通过实际的、动手编码的项目学习一个新的技能。在下表中，我列出了核心技能的简要描述，以及博客相应的功能：

| 技能 | 博客站点功能 |
| --- | --- |
| 使用 SQLAlchemy 的关系数据库 Flask-SQLAlchemy | 在关系数据库中存储条目和标签。执行各种查询，包括分页、日期范围、全文搜索、内连接和外连接等。 |
| 表单处理和验证 Flask-WTF | 使用表单创建和编辑博客条目。在后面的章节中，我们还将使用表单来让用户登录站点并允许访问者发表评论。 |
| 使用 Jinja2 模板渲染 Jinja2 | 创建一个干净、可扩展的模板集，适当时使用继承和包含。 |
| 用户认证和管理仪表板 Flask-Login | 将用户帐户存储在数据库中，并将帖子管理页面限制为注册用户。构建一个管理面板，用于管理帖子、用户帐户，并显示页面浏览量、IP 地理位置等统计信息。 |
| Ajax 和 RESTful APIsFlask-API | 构建一个 Ajax 驱动的评论系统，该系统将显示在每个条目上。使用 RESTful API 公开博客条目，并构建一个简单的命令行客户端，用于使用 API 发布条目。 |
| 单元测试 unittest | 我们将为博客构建一个完整的测试套件，并学习如何模拟真实请求并使用模拟简化复杂的交互。 |
| 其他 | **跨站点请求伪造**（**CSRF**）保护，Atom feeds，垃圾邮件检测，异步任务执行，部署，**安全套接字层**（**SSL**），托管提供商等等。 |

## 规范

当开始一个大型项目时，拥有一个功能规范是个好主意。对于博客网站，我们的规范将简单地是我们希望博客具有的功能列表。这些功能是基于我在构建个人博客时的经验：

+   条目应该使用基于 web 的界面输入。对于格式，作者可以使用**Markdown**，这是一种轻量级、外观吸引人的标记语言。

+   图片可以上传到网站，并轻松地嵌入到博客条目中。

+   条目可以使用任意数量的标签进行组织。

+   该网站应支持多个作者。

+   条目可以按发布顺序显示，也可以按月份、标签或作者列出。条目的长列表将被分页。

+   条目可以保存为*草稿*，并由其作者查看，但在*发布*之前其他人无法查看。

+   访问者可以在条目上发表评论，评论将被检查是否为垃圾邮件，然后由作者自行决定是否应该保持可见。

+   所有帖子都将提供 Atom feeds，包括每个作者和标签的单独 feeds。

+   可以使用 RESTful API 访问条目。作者将获得一个 API 令牌，允许他们使用 API 修改条目。

虽然这个列表并不详尽，但它涵盖了我们博客网站的核心功能，你将有希望发现它既有趣又具有挑战性。在本书的最后，我将提出一些你可能添加的其他功能的想法，但首先你需要熟悉使用 Flask。我相信你迫不及待地想要开始，所以让我们设置我们的博客项目。

## 创建博客项目

让我们从在我们的工作目录中创建一个新项目开始；在我的笔记本电脑上是`/home/charles/projects`，或者在 Unix 系统中是`~/projects`，简称为。这正是我们创建`hello_flask`应用程序时所做的事情：

```py
$ cd ~/projects
$ mkdir blog
$ cd blog

```

然后，我们需要设置我们的`virtualenv`环境。这与我们之前所做的不同，因为这是一种更有结构的使用虚拟环境的方式：

```py
$ virtualenv blog

```

下一步将是将 Flask 安装到我们的虚拟环境中。为此，我们将`激活`虚拟环境，并使用`pip`安装 Flask：

```py
$ source blog/bin/activate
(blog) $ pip install Flask

```

到目前为止，所有这些对你来说应该都有些熟悉。但是，我们可以创建一个名为`app`的新文件夹，而不是为我们的应用程序创建单个文件，这是完全可以的，对于非常小的应用程序来说是有意义的，这样可以使我们的应用程序模块化和更加合乎逻辑。在该文件夹内，我们将创建五个空文件，分别命名为`__init__.py`、`app.py`、`config.py`、`main.py`和`views.py`，如下所示：

```py
mkdir app
touch app/{__init__,app,config,main,views}.py

```

这个最后的命令使用了你的 shell 的一个小技巧，来创建括号内的多个文件名。如果你使用版本控制，你会希望将`app`目录视为你的代码库的根目录。app 目录将包含博客应用的源代码、模板和静态资源。如果你还没有使用版本控制，现在是一个很好的时机来尝试一下。*Pro Git*是一个很好的资源，可以免费在[`git-scm.com/book`](http://git-scm.com/book)上获取。

我们刚刚创建的这些文件是什么？正如你将看到的，每个文件都有重要的作用。希望它们的名称能够提供关于它们作用的线索，但这里是每个模块责任的简要概述：

| `__init__.py` | 告诉 Python 将 app/目录作为 Python 包使用 |
| --- | --- |
| `app.py` | Flask 应用 |
| `config.py` | 我们的 Flask 应用的配置变量 |
| `main.py` | 执行我们应用的入口点 |
| `views.py` | 应用的 URL 路由和视图 |

### 一个简单的 Flask 应用

让我们用最少量的代码填充这些文件，以创建一个可运行的 Flask 应用程序。这将使我们的项目在第二章中处于良好的状态，我们将开始编写代码来存储和检索数据库中的博客条目。

我们将从`config.py`模块开始。这个模块将包含一个`Configuration`类，指示 Flask 我们想要在`DEBUG`模式下运行我们的应用。将以下两行代码添加到`config.py`模块中：

```py
class Configuration(object):
    DEBUG = True
```

接下来我们将创建我们的 Flask 应用，并指示它使用`config`模块中指定的配置值。将以下代码添加到`app.py`模块中：

```py
from flask import Flask

from config import Configuration  # import our configuration data.

app = Flask(__name__)
app.config.from_object(Configuration)  # use values from our Configuration object.
```

视图模块将包含一个映射到站点根 URL 的单个视图。将以下代码添加到`views.py`中：

```py
from app import app

@app.route('/')
def homepage():
    return 'Home page'
```

你可能注意到，我们仍然缺少对`app.run()`的调用。我们将把这段代码放在`main.py`中，这将作为我们应用的入口点。将以下代码添加到`main.py`模块中：

```py
from app import app  # import our Flask app
import views

if __name__ == '__main__':
    app.run()
```

我们不调用`app.run(debug=True)`，因为我们已经指示 Flask 在`Configuration`对象中以调试模式运行我们的应用。

你可以通过执行以下命令行来运行应用程序：

```py
$ python main.py
 * Running on http://127.0.0.1:5000/
* Restarting with reloader

```

![一个简单的 Flask 应用](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_01_09.jpg)

从小小的开始...

### 放大

除了`Configuration`类之外，大部分代码对你来说应该很熟悉。我们基本上是将`hello_flask`示例中的代码分离成了几个模块。可能每个文件只写两三行代码看起来有些愚蠢，但随着我们项目的增长，你会看到这种早期组织的承诺是如何得到回报的。

你可能已经注意到，这些文件有一个内部的优先级，根据它们被导入的顺序—这是为了减轻循环导入的可能性。循环导入发生在两个模块相互导入并且因此根本无法被导入时。在使用 Flask 框架时，很容易创建循环导入，因为很多不同的东西依赖于中心应用对象。为了避免问题，有些人只是把所有东西放到一个单一的模块中。这对于较小的应用程序来说是可以的，但在一定规模或复杂性之后就无法维护了。这就是为什么我们将我们的应用程序分成几个模块，并创建一个单一的入口点来控制导入的顺序。

### 导入流程

当你从命令行运行 python `main.py`时，执行就开始了。Python 解释器运行的第一行代码是从`app`模块导入`app`对象。现在我们在`app.py`内部，它导入了 Flask 和我们的`Configuration`对象。`app.py`模块的其余部分被读取和解释，然后我们又回到了`main.py`。`main.py`的第二行导入了`views`模块。现在我们在`views.py`内部，它依赖于`app.py`的`@app.route`，实际上已经从`main.py`中可用。随着`views`模块的解释，URL 路由和视图被注册，然后我们又回到了`main.py`。由于我们直接运行`main.py`，'if'检查将评估为`True`，我们的应用程序将运行。

![导入流程](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_01_10.jpg)

执行 main.py 时的导入流程

# 摘要

到目前为止，你应该已经熟悉了为 Python 项目设置新的虚拟环境的过程，能够安装 Flask，并创建了一个简单的应用程序。在本章中，我们讨论了如何为项目创建虚拟环境，并使用`pip`安装第三方包。我们还学习了如何编写基本的 Flask 应用程序，将请求路由到视图，并读取请求参数。我们熟悉了交互式调试器以及 Python 解释器如何处理导入语句。

如果你已经熟悉本章大部分内容，不用担心；很快事情会变得更具挑战性。

在下一章中，你将了解如何使用关系数据库来存储和检索博客条目。我们将为项目添加一个新模块来存储我们的数据库特定代码，并创建一些模型来表示博客条目和标签。一旦我们能够存储这些条目，我们将学习如何以各种方式通过过滤、排序和聚合来读取它们。更多信息，请参考以下链接：

+   [`www.python.org/dev/peps/pep-0333/`](https://www.python.org/dev/peps/pep-0333/)

+   [`wiki.python.org/moin/PythonDecorators`](https://wiki.python.org/moin/PythonDecorators)

+   [`charlesleifer.com`](http://charlesleifer.com)


# 第二章：使用 SQLAlchemy 的关系数据库

关系数据库是几乎每个现代 Web 应用程序构建的基石。学会以表和关系的方式思考你的应用程序是一个干净、设计良好的项目的关键之一。正如你将在本章中看到的，你早期选择的数据模型将影响代码的几乎每个方面。我们将使用 SQLAlchemy，一个强大的对象关系映射器，允许我们在 Python 内部直接与数据库交互，抽象出多个数据库引擎的复杂性。

在本章中，我们将：

+   简要概述使用关系数据库的好处

+   介绍 SQLAlchemy，Python SQL 工具包和对象关系映射器

+   配置我们的 Flask 应用程序使用 SQLAlchemy

+   编写一个模型类来表示博客条目

+   学习如何从数据库保存和检索博客条目

+   执行查询-排序、过滤和聚合

+   为博客条目构建标记系统

+   使用 Alembic 创建模式迁移

# 为什么使用关系数据库？

我们应用程序的数据库远不止是我们需要保存以备将来检索的东西的简单记录。如果我们只需要保存和检索数据，我们可以轻松地使用纯文本文件。事实上，我们希望能够对我们的数据执行有趣的查询。而且，我们希望能够高效地做到这一点，而不需要重新发明轮子。虽然非关系数据库（有时被称为 NoSQL 数据库）非常受欢迎，并且在 Web 世界中有其位置，但关系数据库早就解决了过滤、排序、聚合和连接表格数据的常见问题。关系数据库允许我们以结构化的方式定义数据集，从而保持数据的一致性。使用关系数据库还赋予我们开发人员自由，可以专注于我们应用程序中重要的部分。

除了高效执行特别查询外，关系数据库服务器还会执行以下操作：

+   确保我们的数据符合模式中规定的规则

+   允许多人同时访问数据库，同时保证底层数据的一致性

+   确保数据一旦保存，即使应用程序崩溃也不会丢失

关系数据库和 SQL，与关系数据库一起使用的编程语言，是值得一整本书来讨论的话题。因为这本书致力于教你如何使用 Flask 构建应用程序，我将向你展示如何使用一个被 Python 社区广泛采用的用于处理数据库的工具，即 SQLAlchemy。

### 注意

SQLAlchemy 抽象了许多编写 SQL 查询的复杂性，但深入理解 SQL 和关系模型是无法替代的。因此，如果你是 SQL 的新手，我建议你查看在线免费提供的色彩丰富的书籍*Learn SQL the Hard Way*，*Zed Shaw*，网址为[`sql.learncodethehardway.org/`](http://sql.learncodethehardway.org/)。

# 介绍 SQLAlchemy

SQLAlchemy 是一个在 Python 中处理关系数据库非常强大的库。我们可以使用普通的 Python 对象来表示数据库表并执行查询，而不是手动编写 SQL 查询。这种方法有许多好处，如下所示：

+   你的应用程序可以完全使用 Python 开发。

+   数据库引擎之间的微小差异被抽象掉了。这使你可以像使用轻量级数据库一样做事情，例如，在本地开发和测试时使用 SQLite，然后在生产环境中切换到为高负载设计的数据库（如 PostgreSQL）。

+   数据库错误更少，因为现在在你的应用程序和数据库服务器之间有两层：Python 解释器本身（这将捕捉明显的语法错误）和 SQLAlchemy，它有明确定义的 API 和自己的错误检查层。

+   由于 SQLAlchemy 的工作单元模型有助于减少不必要的数据库往返，所以您的数据库代码可能会变得更加高效。SQLAlchemy 还有用于高效预取相关对象的设施，称为急加载。

+   **对象关系映射**（**ORM**）使您的代码更易于维护，这是一种被称为**不要重复自己**（**DRY**）的愿望。假设您向模型添加了一个列。使用 SQLAlchemy，每当您使用该模型时，该列都将可用。另一方面，如果您在整个应用程序中手写 SQL 查询，您将需要逐个更新每个查询，以确保包含新列。

+   SQLAlchemy 可以帮助您避免 SQL 注入漏洞。

+   出色的库支持：正如您将在后面的章节中看到的，有许多有用的库可以直接与您的 SQLAlchemy 模型一起工作，提供诸如维护界面和 RESTful API 之类的功能。

希望您在阅读完这个列表后感到兴奋。如果这个列表中的所有项目现在对您来说都没有意义，不要担心。当您阅读本章和后续章节时，这些好处将变得更加明显和有意义。

现在我们已经讨论了使用 SQLAlchemy 的一些好处，让我们安装它并开始编码。

### 注意

如果您想了解更多关于 SQLAlchemy 的信息，在*开源应用程序的架构*中有一整章专门讨论了它的设计，可以免费在线阅读，网址是[`aosabook.org/en/sqlalchemy.html`](http://aosabook.org/en/sqlalchemy.html)。

## 安装 SQLAlchemy

我们将使用`pip`将 SQLAlchemy 安装到博客应用的虚拟环境中。正如您在上一章中所记得的，要激活您的虚拟环境，只需切换到`source`并执行`activate`脚本：

```py
$ cd ~/projects/blog
$ source blog/bin/activate
(blog) $ pip install sqlalchemy
Downloading/unpacking sqlalchemy
…
Successfully installed sqlalchemy
Cleaning up...

```

您可以通过打开 Python 解释器并检查 SQLAlchemy 版本来检查您的安装是否成功；请注意，您的确切版本号可能会有所不同。

```py
$ python
>>> import sqlalchemy
>>> sqlalchemy.__version__
'0.9.0b2'

```

## 在我们的 Flask 应用中使用 SQLAlchemy

SQLAlchemy 在 Flask 上运行得非常好，但 Flask 的作者发布了一个名为**Flask-SQLAlchemy**的特殊 Flask 扩展，它提供了许多常见任务的辅助功能，并可以避免我们以后不得不重新发明轮子。让我们使用`pip`来安装这个扩展：

```py
(blog) $ pip install flask-sqlalchemy
…
Successfully installed flask-sqlalchemy

```

Flask 为对构建扩展感兴趣的开发人员提供了一个标准接口。随着这个框架的流行，高质量的扩展数量也在增加。如果您想查看一些更受欢迎的扩展，可以在 Flask 项目网站上找到一个精选列表，网址是[`flask.pocoo.org/extensions/`](http://flask.pocoo.org/extensions/)。

## 选择数据库引擎

SQLAlchemy 支持多种流行的数据库方言，包括 SQLite、MySQL 和 PostgreSQL。根据您想要使用的数据库，您可能需要安装一个包含数据库驱动程序的额外 Python 包。下面列出了 SQLAlchemy 支持的一些流行数据库以及相应的 pip-installable 驱动程序。一些数据库有多个驱动程序选项，所以我首先列出了最流行的一个。

| 数据库 | 驱动程序包 |
| --- | --- |
| SQLite | 不需要，自 Python 2.5 版本起已包含在 Python 标准库中 |
| MySQL | MySQL-python, PyMySQL（纯 Python），OurSQL |
| PostgreSQL | psycopg2 |
| Firebird | fdb |
| Microsoft SQL Server | pymssql, PyODBC |
| Oracle | cx-Oracle |

SQLite 与 Python 一起标准提供，并且不需要单独的服务器进程，因此非常适合快速启动。在接下来的示例中，为了简单起见，我将演示如何配置博客应用以使用 SQLite。如果您有其他数据库想法，并且希望在博客项目中使用它，请随时使用`pip`在此时安装必要的驱动程序包。

## 连接到数据库

使用您喜欢的文本编辑器，打开我们博客项目（`~/projects/blog/app/config.py`）的`config.py`模块。我们将添加一个特定于 SQLAlchemy 的设置，以指示 Flask-SQLAlchemy 如何连接到我们的数据库。以下是新的行：

```py
import os
class Configuration(object):
 APPLICATION_DIR = os.path.dirname(os.path.realpath(__file__))
    DEBUG = True
 SQLALCHEMY_DATABASE_URI = 'sqlite:///%s/blog.db' % APPLICATION_DIR

```

`SQLALCHEMY_DATABASE_URI`包括以下部分：

`dialect+driver://username:password@host:port/database`

因为 SQLite 数据库存储在本地文件中，我们需要提供的唯一信息是数据库文件的路径。另一方面，如果您想连接到本地运行的 PostgreSQL，您的 URI 可能看起来像这样：

`postgresql://postgres:secretpassword@localhost:5432/blog_db`

### 注意

如果您在连接到数据库时遇到问题，请尝试查阅 SQLAlchemy 关于数据库 URI 的文档：[`docs.sqlalchemy.org/en/rel_0_9/core/engines.html`](http://docs.sqlalchemy.org/en/rel_0_9/core/engines.html)。

现在我们已经指定了如何连接到数据库，让我们创建一个负责实际管理我们数据库连接的对象。这个对象由 Flask-SQLAlchemy 扩展提供，并且方便地命名为`SQLAlchemy`。打开`app.py`并进行以下添加：

```py
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy

from config import Configuration

app = Flask(__name__)
app.config.from_object(Configuration)
db = SQLAlchemy(app)

```

这些更改指示我们的 Flask 应用程序，进而指示 SQLAlchemy 如何与我们应用程序的数据库通信。下一步将是创建一个用于存储博客条目的表，为此，我们将创建我们的第一个模型。

# 创建 Entry 模型

**模型**是我们想要存储在数据库中的数据表的数据表示。这些模型具有称为**列**的属性，表示数据中的数据项。因此，如果我们要创建一个`Person`模型，我们可能会有用于存储名字、姓氏、出生日期、家庭地址、头发颜色等的列。由于我们有兴趣创建一个模型来表示博客条目，我们将为标题和正文内容等内容创建列。

### 注意

请注意，我们不说`People`模型或`Entries`模型 - 即使它们通常代表许多不同的对象，模型是单数。

使用 SQLAlchemy，创建模型就像定义一个类并指定分配给该类的多个属性一样简单。让我们从我们博客条目的一个非常基本的模型开始。在博客项目的`app/`目录中创建一个名为`models.py`的新文件，并输入以下代码：

```py
import datetime, re
from app import db

def slugify(s):
    return re.sub('[^\w]+', '-', s).lower()

class Entry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    slug = db.Column(db.String(100), unique=True)
    body = db.Column(db.Text)
    created_timestamp = db.Column(db.DateTime, default=datetime.datetime.now)
    modified_timestamp = db.Column(
        db.DateTime,
        default=datetime.datetime.now, 
        onupdate=datetime.datetime.now)

    def __init__(self, *args, **kwargs):
        super(Entry, self).__init__(*args, **kwargs)  # Call parent constructor.
        self.generate_slug()

    def generate_slug(self):
        self.slug = ''
        if self.title:
            self.slug = slugify(self.title)

    def __repr__(self):
        return '<Entry: %s>' % self.title
```

有很多事情要做，所以让我们从导入开始，然后逐步进行。我们首先导入标准库`datetime`和`re`模块。我们将使用`datetime`获取当前日期和时间，使用`re`进行一些字符串操作。接下来的导入语句引入了我们在`app.py`中创建的`db`对象。您可能还记得，`db`对象是`SQLAlchemy`类的一个实例，它是 Flask-SQLAlchemy 扩展的一部分。`db`对象提供了访问我们需要构建`Entry`模型的类的功能，这只是前面几行。

在`Entry`模型之前，我们定义了一个辅助函数`slugify`，我们将使用它为我们的博客条目提供一些漂亮的 URL（在第三章中使用，*模板和视图*）。`slugify`函数接受一个字符串，比如*关于 Flask 的帖子*，并使用正则表达式将可读的字符串转换为 URL，因此返回*a-post-about-flask*。

接下来是`Entry`模型。我们的`Entry`模型是一个普通的类，扩展了`db.Model`。通过扩展`db.Model`，我们的`Entry`类将继承各种我们将用于查询数据库的帮助程序。

`Entry`模型的属性是我们希望存储在数据库中的名称和数据的简单映射，并列在下面：

+   `id`：这是我们数据库表的主键。当我们创建一个新的博客条目时，数据库会自动为我们设置这个值，通常是每个新条目的自增编号。虽然我们不会明确设置这个值，但当你想要引用一个模型到另一个模型时，主键会派上用场，这一点你将在本章后面看到。

+   `title`：博客条目的标题，存储为具有最大长度为 100 的`String`列。

+   `slug`：标题的 URL 友好表示，存储为具有最大长度为 100 的`String`列。该列还指定了`unique=True`，因此没有两个条目可以共享相同的 slug。

+   `body`：帖子的实际内容，存储在`Text`列中。这与`Title`和`Slug`的`String`类型不同，因为你可以在这个字段中存储任意多的文本。

+   `created_timestamp`：博客条目创建的时间，存储在`DateTime`列中。我们指示 SQLAlchemy 在首次保存条目时自动填充这一列的当前时间。

+   `modified_timestamp`：博客条目上次更新的时间。当我们保存一个条目时，SQLAlchemy 会自动使用当前时间更新这个列。

### 注意

对于标题或事物名称等短字符串，`String`列是合适的，但当文本可能特别长时，最好使用`Text`列，就像我们为条目正文所做的那样。

我们已经重写了类的构造函数（`__init__`），这样，当创建一个新模型时，它会根据标题自动为我们设置 slug。

最后一部分是`__repr__`方法，用于生成我们的`Entry`类实例的有用表示。`__repr__`的具体含义并不重要，但允许你在调试时引用程序正在处理的对象。

最后需要添加一小段代码到 main.py，这是我们应用程序的入口点，以确保模型被导入。将以下突出显示的更改添加到 main.py 中：

```py
from app import app, db
import models
import views

if __name__ == '__main__':
    app.run()
```

## 创建 Entry 表

为了开始使用`Entry`模型，我们首先需要在我们的数据库中为它创建一个表。幸运的是，Flask-SQLAlchemy 带有一个很好的辅助程序来做这件事。在博客项目的`app`目录中创建一个名为`scripts`的新子文件夹。然后创建一个名为`create_db.py`的文件：

```py
(blog) $ cd app/
(blog) $ mkdir scripts
(blog) $ touch scripts/create_db.py

```

将以下代码添加到`create_db.py`模块中。这个函数将自动查看我们编写的所有代码，并根据我们的模型在数据库中为`Entry`模型创建一个新表：

```py
import os, sys
sys.path.append(os.getcwd())
from main import db

if __name__ == '__main__':
    db.create_all()
```

从`app/`目录内执行脚本。确保虚拟环境是激活的。如果一切顺利，你应该看不到任何输出。

```py
(blog) $ python create_db.py 
(blog) $

```

### 注意

如果在创建数据库表时遇到错误，请确保你在 app 目录中，并且在运行脚本时虚拟环境是激活的。接下来，确保你的`SQLALCHEMY_DATABASE_URI`设置中没有拼写错误。

## 使用 Entry 模型

让我们通过保存一些博客条目来尝试我们的新`Entry`模型。我们将在 Python 交互式 shell 中进行此操作。在这个阶段，让我们安装**IPython**，这是一个功能强大的 shell，具有诸如制表符补全（默认的 Python shell 没有的功能）。

```py
(blog) $ pip install ipython

```

现在检查我们是否在`app`目录中，让我们启动 shell 并创建一些条目，如下所示：

```py
(blog) $ ipython

In []: from models import *  # First things first, import our Entry model and db object.
In []: db  # What is db?
Out[]: <SQLAlchemy engine='sqlite:////home/charles/projects/blog/app/blog.db'>

```

### 注意

如果你熟悉普通的 Python shell 但不熟悉 IPython，一开始可能会有点不同。要注意的主要事情是`In[]`指的是你输入的代码，`Out[]`是你放入 shell 的命令的输出。

IPython 有一个很棒的功能，允许你打印关于对象的详细信息。这是通过输入对象的名称后跟一个问号（?）来完成的。内省`Entry`模型提供了一些信息，包括参数签名和表示该对象的字符串（称为`docstring`）的构造函数。

```py
In []: Entry?  # What is Entry and how do we create it?
Type:       _BoundDeclarativeMeta
String Form:<class 'models.Entry'>
File:       /home/charles/projects/blog/app/models.py
Docstring:  <no docstring>
Constructor information:
 Definition:Entry(self, *args, **kwargs)

```

我们可以通过将列值作为关键字参数传递来创建`Entry`对象。在前面的示例中，它使用了`**kwargs`；这是一个快捷方式，用于将`dict`对象作为定义对象的值，如下所示：

```py
In []: first_entry = Entry(title='First entry', body='This is the body of my first entry.')

```

为了保存我们的第一个条目，我们将其添加到数据库会话中。会话只是表示我们在数据库上的操作的对象。即使将其添加到会话中，它也不会立即保存到数据库中。为了将条目保存到数据库中，我们需要提交我们的会话：

```py
In []: db.session.add(first_entry)
In []: first_entry.id is None  # No primary key, the entry has not been saved.
Out[]: True
In []: db.session.commit()
In []: first_entry.id
Out[]: 1
In []: first_entry.created_timestamp
Out[]: datetime.datetime(2014, 1, 25, 9, 49, 53, 1337)

```

从前面的代码示例中可以看出，一旦我们提交了会话，将为我们的第一个条目分配一个唯一的 id，并将`created_timestamp`设置为当前时间。恭喜，您已创建了您的第一个博客条目！

尝试自己添加几个。在提交之前，您可以将多个条目对象添加到同一个会话中，因此也可以尝试一下。

### 注意

在您进行实验的任何时候，都可以随时删除`blog.db`文件，并重新运行`create_db.py`脚本，以便使用全新的数据库重新开始。

## 对现有条目进行更改

修改现有的`Entry`时，只需进行编辑，然后提交。让我们使用之前返回给我们的 id 检索我们的`Entry`，进行一些更改，然后提交。SQLAlchemy 将知道需要更新它。以下是您可能对第一个条目进行编辑的方式：

```py
In []: first_entry = Entry.query.get(1)
In []: first_entry.body = 'This is the first entry, and I have made some edits.'
In []: db.session.commit()

```

就像那样，您的更改已保存。

## 删除条目

删除条目与创建条目一样简单。我们将调用`db.session.delete`而不是调用`db.session.add`，并传入我们希望删除的`Entry`实例。

```py
In []: bad_entry = Entry(title='bad entry', body='This is a lousy entry.')
In []: db.session.add(bad_entry)
In []: db.session.commit()  # Save the bad entry to the database.
In []: db.session.delete(bad_entry)
In []: db.session.commit()  # The bad entry is now deleted from the database.

```

# 检索博客条目

虽然创建、更新和删除操作相当简单，但当我们查看检索条目的方法时，真正有趣的部分开始了。我们将从基础知识开始，然后逐渐深入到更有趣的查询。

我们将使用模型类上的特殊属性进行查询：`Entry.query`。该属性公开了各种 API，用于处理数据库中条目的集合。

让我们简单地检索`Entry`表中所有条目的列表：

```py
In []: entries = Entry.query.all()
In []: entries  # What are our entries?
Out[]: [<Entry u'First entry'>, <Entry u'Second entry'>, <Entry u'Third entry'>, <Entry u'Fourth entry'>]

```

如您所见，在此示例中，查询返回了我们创建的`Entry`实例的列表。当未指定显式排序时，条目将以数据库选择的任意顺序返回给我们。让我们指定我们希望以标题的字母顺序返回给我们条目：

```py
In []: Entry.query.order_by(Entry.title.asc()).all()
Out []:
[<Entry u'First entry'>,
 <Entry u'Fourth entry'>,
 <Entry u'Second entry'>,
 <Entry u'Third entry'>]

```

接下来是如何按照最后更新时间的逆序列出您的条目：

```py
In []: oldest_to_newest = Entry.query.order_by(Entry.modified_timestamp.desc()).all()
Out []:
[<Entry: Fourth entry>,
 <Entry: Third entry>,
 <Entry: Second entry>,
 <Entry: First entry>]

```

## 过滤条目列表

能够检索整个博客条目集合非常有用，但是如果我们想要过滤列表怎么办？我们可以始终检索整个集合，然后在 Python 中使用循环进行过滤，但那将非常低效。相反，我们将依赖数据库为我们进行过滤，并简单地指定应返回哪些条目的条件。在以下示例中，我们将指定要按标题等于`'First entry'`进行过滤的条目。

```py
In []: Entry.query.filter(Entry.title == 'First entry').all()
Out[]: [<Entry u'First entry'>]

```

如果这对您来说似乎有些神奇，那是因为它确实如此！SQLAlchemy 使用操作符重载将诸如`<Model>.<column> == <some value>`的表达式转换为称为`BinaryExpression`的抽象对象。当您准备执行查询时，这些数据结构然后被转换为 SQL。

### 注意

`BinaryExpression`只是一个表示逻辑比较的对象，并且是通过重写通常在 Python 中比较值时调用的标准方法而生成的。

为了检索单个条目，您有两个选项：`.first()`和`.one()`。它们的区别和相似之处总结在以下表中：

| 匹配行的数量 | first()行为 | one()行为 |
| --- | --- | --- |
| 1 | 返回对象 | 返回对象 |
| 0 | 返回`None` | 引发`sqlalchemy.orm.exc.NoResultFound` |
| 2+ | 返回第一个对象（基于显式排序或数据库选择的排序） | 引发`sqlalchemy.orm.exc.MultipleResultsFound` |

让我们尝试与之前相同的查询，但是，而不是调用`.all()`，我们将调用`.first()`来检索单个`Entry`实例：

```py
In []: Entry.query.filter(Entry.title == 'First entry').first()
Out[]: <Entry u'First entry'>

```

请注意，以前的`.all()`返回包含对象的列表，而`.first()`只返回对象本身。

## 特殊查找

在前面的示例中，我们测试了相等性，但还有许多其他类型的查找可能。在下表中，我们列出了一些您可能会发现有用的查找。完整列表可以在 SQLAlchemy 文档中找到。

| 示例 | 意义 |
| --- | --- |
| Entry.title == 'The title' | 标题为“The title”的条目，区分大小写。 |
| Entry.title != 'The title' | 标题不是“The title”的条目。 |
| Entry.created_timestamp < datetime.date(2014, 1, 25) | 2014 年 1 月 25 日之前创建的条目。要使用小于或等于，使用<=。 |
| Entry.created_timestamp > datetime.date(2014, 1, 25) | 2014 年 1 月 25 日之后创建的条目。要使用大于或等于，使用>=。 |
| Entry.body.contains('Python') | 正文包含单词“Python”的条目，区分大小写。 |
| Entry.title.endswith('Python') | 标题以字符串“Python”结尾的条目，区分大小写。请注意，这也将匹配以单词“CPython”结尾的标题，例如。 |
| Entry.title.startswith('Python') | 标题以字符串“Python”开头的条目，区分大小写。请注意，这也将匹配标题如“Pythonistas”。 |
| Entry.body.ilike('%python%') | 正文包含单词“python”的条目，文本中任何位置，不区分大小写。百分号“%”是通配符。 |
| Entry.title.in_(['Title one', 'Title two']) | 标题在给定列表中的条目，要么是'Title one'要么是'Title two'。 |

## 组合表达式

前面表格中列出的表达式可以使用位运算符组合，以生成任意复杂的表达式。假设我们想要检索所有博客条目中标题包含`Python`或`Flask`的条目。为了实现这一点，我们将创建两个`contains`表达式，然后使用 Python 的位`OR`运算符进行组合，这是一个管道`|`字符，不像其他许多使用双管`||`字符的语言：

```py
Entry.query.filter(Entry.title.contains('Python') | Entry.title.contains('Flask'))
```

使用位运算符，我们可以得到一些非常复杂的表达式。试着弄清楚以下示例在询问什么：

```py
Entry.query.filter(
    (Entry.title.contains('Python') | Entry.title.contains('Flask')) &
    (Entry.created_timestamp > (datetime.date.today() - datetime.timedelta(days=30)))
)
```

您可能已经猜到，此查询返回所有标题包含`Python`或`Flask`的条目，并且在过去 30 天内创建。我们使用 Python 的位`OR`和`AND`运算符来组合子表达式。对于您生成的任何查询，可以通过打印查询来查看生成的 SQL，如下所示：

```py
In []: query = Entry.query.filter(
 (Entry.title.contains('Python') | Entry.title.contains('Flask')) &
 (Entry.created_timestamp > (datetime.date.today() - datetime.timedelta(days=30)))
)
In []: print str(query)

SELECT entry.id AS entry_id, ...
FROM entry 
WHERE (
 (entry.title LIKE '%%' || :title_1 || '%%') OR (entry.title LIKE '%%' || :title_2 || '%%')
) AND entry.created_timestamp > :created_timestamp_1

```

### 否定

还有一点要讨论，那就是**否定**。如果我们想要获取所有标题中不包含`Python`或`Flask`的博客条目列表，我们该怎么做呢？SQLAlchemy 提供了两种方法来创建这些类型的表达式，一种是使用 Python 的一元否定运算符（`~`），另一种是调用`db.not_()`。以下是如何使用 SQLAlchemy 构建此查询的方法：

使用一元否定：

```py
In []: Entry.query.filter(~(Entry.title.contains('Python') | Entry.title.contains('Flask')))

```

使用`db.not_()`：

```py
In []: Entry.query.filter(db.not_(Entry.title.contains('Python') | Entry.title.contains('Flask')))

```

### 运算符优先级

并非所有操作都被 Python 解释器视为相等。这就像在数学课上学习的那样，我们学到类似*2 + 3 * 4*的表达式等于*14*而不是*20*，因为乘法运算首先发生。在 Python 中，位运算符的优先级都高于诸如相等性测试之类的东西，这意味着在构建查询表达式时，您必须注意括号。让我们看一些示例 Python 表达式，并查看相应的查询：

| 表达式 | 结果 |
| --- | --- |
| (Entry.title == 'Python' &#124; Entry.title == 'Flask') | 错误！SQLAlchemy 会抛出错误，因为首先要评估的实际上是'Python' &#124; Entry.title! |
| (Entry.title == 'Python') &#124; (Entry.title == 'Flask') | 正确。返回标题为“Python”或“Flask”的条目。 |
| ~Entry.title == 'Python' | 错误！SQLAlchemy 会将其转换为有效的 SQL 查询，但结果将没有意义。 |
| ~(Entry.title == 'Python') | 正确。返回标题不等于“Python”的条目。 |

如果您发现自己在操作符优先级方面有困难，最好在使用`==`、`!=`、`<`、`<=`、`>`和`>=`的任何比较周围加上括号。

# 构建标记系统

标签是一个轻量级的分类系统，非常适合博客。标签允许您将多个类别应用于博客文章，并允许多篇文章在其类别之外相互关联。在我的博客上，我使用标签来组织帖子，这样对于想阅读我关于 Flask 的帖子的人，只需在“Flask”标签下查找即可找到所有相关的帖子。根据我们在第一章中讨论的规范，*创建您的第一个 Flask 应用程序*，每个博客条目可以有多少个标签都可以，因此关于 Flask 的帖子可能会被标记为 Flask 和 Python。同样，每个标签（例如 Python）可以与多个条目相关联。在数据库术语中，这称为多对多关系。

为了对此进行建模，我们必须首先创建一个模型来存储标签。这个模型将存储我们使用的标签名称，因此在我们添加了一些标签之后，表可能看起来像下面这样：

| id | tag |
| --- | --- |
| 1 | Python |
| 2 | Flask |
| 3 | Django |
| 4 | random-thoughts |

让我们打开`models.py`并为`Tag`模型添加一个定义。在文件末尾添加以下类，位于`Entry`类下方：

```py
class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    slug = db.Column(db.String(64), unique=True)

    def __init__(self, *args, **kwargs):
        super(Tag, self).__init__(*args, **kwargs)
        self.slug = slugify(self.name)

    def __repr__(self):
        return '<Tag %s>' % self.name
```

您以前见过所有这些。我们添加了一个主键，这将由数据库管理，并添加了一个列来存储标签的名称。`name`列被标记为唯一，因此每个标签在这个表中只会被一行表示，无论它出现在多少个博客条目中。

现在我们既有博客条目模型，也有标签模型，我们需要一个第三个模型来存储两者之间的关系。当我们希望表示博客条目被标记为特定标签时，我们将在这个表中存储一个引用。以下是数据库表级别上正在发生的事情的图示：

![构建标记系统](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_02_01.jpg)

由于我们永远不会直接访问这个中间表（SQLAlchemy 会透明地处理它），我们不会为它创建一个模型，而是简单地指定一个表来存储映射。打开`models.py`并添加以下突出显示的代码：

```py
import datetime, re

from app import db

def slugify(s):
    return re.sub('[^\w]+', '-', s).lower()

entry_tags = db.Table('entry_tags',
 db.Column('tag_id', db.Integer, db.ForeignKey('tag.id')),
 db.Column('entry_id', db.Integer, db.ForeignKey('entry.id'))
)

class Entry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    slug = db.Column(db.String(100), unique=True)
    body = db.Column(db.Text)
    created_timestamp = db.Column(db.DateTime, default=datetime.datetime.now)
    modified_timestamp = db.Column(
        db.DateTime,
        default=datetime.datetime.now,
        onupdate=datetime.datetime.now)

 tags = db.relationship('Tag', secondary=entry_tags,
 backref=db.backref('entries', lazy='dynamic'))

    def __init__(self, *args, **kwargs):
        super(Entry, self).__init__(*args, **kwargs)
        self.generate_slug()

    def generate_slug(self):
        self.slug = ''
        if self.title:
            self.slug = slugify(self.title)

    def __repr__(self):
        return '<Entry %s>' % self.title

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    slug = db.Column(db.String(64), unique=True)

    def __init__(self, *args, **kwargs):
        super(Tag, self).__init__(*args, **kwargs)
        self.slug = slugify(self.name)

    def __repr__(self):
        return '<Tag %s>' % self.name
```

通过创建`entry_tags`表，我们已经建立了`Entry`和`Tag`模型之间的链接。SQLAlchemy 提供了一个高级 API 来处理这种关系，名为`db.relationship`函数。这个函数在`Entry`模型上创建了一个新属性，允许我们轻松地读取和写入给定博客条目的标签。这两行代码中有很多内容，让我们仔细看一下：

```py
tags = db.relationship('Tag', secondary=entry_tags,
    backref=db.backref('entries', lazy='dynamic'))
```

我们将`Entry`类的标签属性设置为`db.relationship`函数的返回值。前两个参数`'Tag'`和`secondary=entry_tags`指示 SQLAlchemy 我们将通过`entry_tags`表查询`Tag`模型。第三个参数创建了一个反向引用，允许我们从`Tag`模型返回到相关的博客条目列表。通过指定`lazy='dynamic'`，我们指示 SQLAlchemy，我们不希望它为我们加载所有相关的条目，而是想要一个查询对象。

## 向条目添加和删除标签

让我们使用 IPython shell 来看看这是如何工作的。关闭当前的 shell 并重新运行`scripts/create_db.py`脚本。由于我们添加了两个新表，这一步是必要的。现在重新打开 IPython：

```py
(blog) $ python scripts/create_db.py
(blog) $ ipython
In []: from models import *
In []: Tag.query.all()
Out[]: []

```

目前数据库中没有标签，所以让我们创建一些标签：

```py
In []: python = Tag(name='python')
In []: flask = Tag(name='flask')
In []: db.session.add_all([python, flask])
In []: db.session.commit()

```

现在让我们加载一些示例条目。在我的数据库中有四个：

```py
In []: Entry.query.all()
Out[]:
[<Entry Py
thon entry>,
 <Entry Flask entry>,
 <Entry More flask>,
 <Entry Django entry>]
In []: python_entry, flask_entry, more_flask, django_entry = _

```

### 注意

在 IPython 中，您可以使用下划线(`_`)来引用上一行的返回值。

要向条目添加标签，只需将它们分配给条目的`tags`属性。就是这么简单！

```py
In []: python_entry.tags = [python]
In []: flask_entry.tags = [python, flask]
In []: db.session.commit()

```

我们可以像处理普通的 Python 列表一样处理条目的标签列表，因此通常的`.append()`和`.remove()`方法也可以使用：

```py
In []: kittens = Tag(name='kittens')
In []: python_entry.tags.append(kittens)
In []: db.session.commit()
In []: python_entry.tags
Out[]: [<Tag python>, <Tag kittens>]
In []: python_entry.tags.remove(kittens)
In []: db.session.commit()
In []: python_entry.tags
Out[]: [<Tag python>]

```

## 使用 backrefs

创建`Entry`模型上的`tags`属性时，您会回忆起我们传入了`backref`参数。让我们使用 IPython 来看看后向引用是如何使用的。

```py
In []: python  # The python variable is just a tag.
Out[]: <Tag python>
In []: python.entries
Out[]: <sqlalchemy.orm.dynamic.AppenderBaseQuery at 0x332ff90>
In []: python.entries.all()
Out[]: [<Entry Flask entry>, <Entry Python entry>]

```

与`Entry.tags`引用不同，后向引用被指定为`lazy='dynamic'`。这意味着，与给出标签列表的`entry.tags`不同，我们每次访问`tag.entries`时都不会收到条目列表。为什么呢？通常，当结果集大于几个项目时，将`backref`参数视为查询更有用，可以进行过滤、排序等操作。例如，如果我们想显示最新的标记为`python`的条目会怎样？

```py
In []: python.entries.order_by(Entry.created_timestamp.desc()).first()
Out[]: <Entry Flask entry>

```

### 注意

SQLAlchemy 文档包含了可以用于 lazy 参数的各种值的优秀概述。您可以在[`docs.sqlalchemy.org/en/rel_0_9/orm/relationships.html#sqlalchemy.orm.relationship.params.lazy`](http://docs.sqlalchemy.org/en/rel_0_9/orm/relationships.html#sqlalchemy.orm.relationship.params.lazy)上找到它们。

# 对模式进行更改

本章最后要讨论的主题是如何对现有的模型定义进行修改。根据项目规范，我们希望能够保存博客条目的草稿。现在我们没有办法知道一个条目是否是草稿，所以我们需要添加一个列来存储条目的状态。不幸的是，虽然`db.create_all()`用于创建表非常完美，但它不会自动修改现有的表；为了做到这一点，我们需要使用迁移。

## 将 Flask-Migrate 添加到我们的项目中

我们将使用 Flask-Migrate 来帮助我们在更改模式时自动更新数据库。在博客虚拟环境中，使用`pip`安装 Flask-Migrate：

```py
(blog) $ pip install flask-migrate

```

### 注意

SQLAlchemy 的作者有一个名为 alembic 的项目；Flask-Migrate 使用它并直接将其与 Flask 集成，使事情变得更容易。

接下来，我们将向我们的应用程序添加一个`Migrate`助手。我们还将为我们的应用程序创建一个脚本管理器。脚本管理器允许我们在应用程序的上下文中直接从命令行执行特殊命令。我们将使用脚本管理器来执行`migrate`命令。打开`app.py`并进行以下添加：

```py
from flask import Flask
from flask.ext.migrate import Migrate, MigrateCommand
from flask.ext.script import Manager
from flask.ext.sqlalchemy import SQLAlchemy

from config import Configuration

app = Flask(__name__)
app.config.from_object(Configuration)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

manager = Manager(app)
manager.add_command('db', MigrateCommand)

```

为了使用管理器，我们将在`app.py`旁边添加一个名为`manage.py`的新文件。将以下代码添加到`manage.py`中：

```py
from app import manager
from main import *

if __name__ == '__main__':
    manager.run()
```

这看起来与`main.py`非常相似，关键区别在于，我们不是调用`app.run()`，而是调用`manager.run()`。

### 注意

Django 有一个类似的，尽管是自动生成的`manage.py`文件，起着类似的功能。

## 创建初始迁移

在我们开始更改模式之前，我们需要创建其当前状态的记录。为此，请从博客的`app`目录内运行以下命令。第一个命令将在`app`文件夹内创建一个迁移目录，用于跟踪我们对模式所做的更改。第二个命令`db migrate`将创建我们当前模式的快照，以便将来的更改可以与之进行比较。

```py
(blog) $ python manage.py db init

 Creating directory /home/charles/projects/blog/app/migrations ... done
 ...
(blog) $ python manage.py db migrate
INFO  [alembic.migration] Context impl SQLiteImpl.
INFO  [alembic.migration] Will assume non-transactional DDL.
 Generating /home/charles/projects/blog/app/migrations/versions/535133f91f00_.py ... done

```

最后，我们将运行`db upgrade`来运行迁移，以指示迁移系统一切都是最新的：

```py
(blog) $ python manage.py db upgrade
INFO  [alembic.migration] Context impl SQLiteImpl.
INFO  [alembic.migration] Will assume non-transactional DDL.
INFO  [alembic.migration] Running upgrade None -> 535133f91f00, empty message

```

## 添加状态列

现在我们已经有了当前模式的快照，我们可以开始进行更改。我们将添加一个名为`status`的新列，该列将存储与特定状态对应的整数值。尽管目前只有两种状态（`PUBLIC`和`DRAFT`），但使用整数而不是布尔值使我们有可能在将来轻松添加更多状态。打开`models.py`并对`Entry`模型进行以下添加：

```py
class Entry(db.Model):
 STATUS_PUBLIC = 0
 STATUS_DRAFT = 1

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    slug = db.Column(db.String(100), unique=True)
    body = db.Column(db.Text)
 status = db.Column(db.SmallInteger, default=STATUS_PUBLIC)
    created_timestamp = db.Column(db.DateTime, default=datetime.datetime.now)
    ...
```

从命令行，我们将再次运行`db migrate`来生成迁移脚本。您可以从命令的输出中看到它找到了我们的新列！

```py
(blog) $ python manage.py db migrate
INFO  [alembic.migration] Context impl SQLiteImpl.
INFO  [alembic.migration] Will assume non-transactional DDL.
INFO  [alembic.autogenerate.compare] Detected added column 'entry.status'
 Generating /home/charl
es/projects/blog/app/migrations/versions/2c8e81936cad_.py ... done

```

因为我们在数据库中有博客条目，所以我们需要对自动生成的迁移进行小修改，以确保现有条目的状态被初始化为正确的值。为此，打开迁移文件（我的是`migrations/versions/2c8e81936cad_.py`）并更改以下行：

```py
op.add_column('entry', sa.Column('status', sa.SmallInteger(), nullable=True))
```

将`nullable=True`替换为`server_default='0'`告诉迁移脚本不要将列默认设置为 null，而是使用`0`。

```py
op.add_column('entry', sa.Column('status', sa.SmallInteger(), server_default='0'))
```

最后，运行`db upgrade`来运行迁移并创建状态列。

```py
(blog) $ python manage.py db upgrade
INFO  [alembic.migration] Context impl SQLiteImpl.
INFO  [alembic.migration] Will assume non-transactional DDL.
INFO  [alembic.migration] Running upgrade 535133f91f00 -> 2c8e81936cad, empty message

```

恭喜，您的`Entry`模型现在有了一个状态字段！

# 总结

到目前为止，您应该熟悉使用 SQLAlchemy 来处理关系数据库。我们介绍了使用关系数据库和 ORM 的好处，配置了一个 Flask 应用程序来连接到关系数据库，并创建了 SQLAlchemy 模型。所有这些都使我们能够在数据之间创建关系并执行查询。最重要的是，我们还使用了迁移工具来处理未来的数据库模式更改。

在第三章中，*模板和视图*，我们将搁置交互式解释器，开始创建视图以在 Web 浏览器中显示博客条目。我们将利用我们所有的 SQLAlchemy 知识创建有趣的博客条目列表，以及一个简单的搜索功能。我们将构建一组模板，使博客网站在视觉上更具吸引力，并学习如何使用 Jinja2 模板语言来消除重复的 HTML 编码。这将是一个有趣的章节！


# 第三章：模板和视图

这一章也可以被称为*Flask 章节*，因为我们将涵盖框架中最具代表性的两个组件：Jinja2 模板语言和 URL 路由框架。到目前为止，我们一直在为博客应用奠定基础，但实际上我们几乎没有涉及到 Flask 的开发。在这一章中，我们将深入了解 Flask，并看到我们的应用最终开始成形。我们将把单调的数据库模型转换为动态呈现的 HTML 页面，使用模板。我们将设计一个 URL 方案，反映我们希望组织博客条目的方式。随着我们在本章的进展，我们的博客应用将开始看起来像一个真正的网站。

在本章中，我们将：

+   学习如何使用 Jinja2 呈现 HTML 模板

+   学习如何使用 Jinja2 模板语言提供的循环、控制结构和过滤器

+   使用模板继承来消除重复的编码

+   为我们的博客应用创建一个清晰的 URL 方案，并设置从 URL 到视图的路由

+   使用 Jinja2 模板呈现博客条目列表

+   为网站添加全文搜索

# 介绍 Jinja2

Jinja2 是一个快速、灵活和安全的模板引擎。它允许您将网站定义为小块，这些小块被拼凑在一起形成完整的页面。例如，在我们的博客中，我们将为标题、侧边栏、页脚以及用于呈现博客文章的模板创建块。这种方法是 DRY（不要重复自己），这意味着每个块中包含的标记不应该被复制或粘贴到其他地方。由于站点的每个部分的 HTML 只存在于一个地方，因此更改和修复错误变得更容易。Jinja2 还允许您在模板中嵌入显示逻辑。例如，我们可能希望向已登录的用户显示注销按钮，但向匿名浏览的用户显示登录表单。正如您将看到的，使用一些模板逻辑来实现这些类型的事情非常容易。

从一开始，Flask 就是以 Jinja2 为核心构建的，因此在 Flask 应用中使用模板非常容易。由于 Jinja2 是 Flask 框架的要求，它已经安装在我们的虚拟环境中，所以我们可以立即开始使用。

在博客项目的`app`目录中创建一个名为`templates`的新文件夹。在模板文件夹中创建一个名为`homepage.html`的单个文件，并添加以下 HTML 代码：

```py
<!doctype html>
<html>
  <head>
    <title>Blog</title>
  </head>
  <body>
    <h1>Welcome to my blog</h1>
  </body>
</html>
```

现在在博客项目的`app`目录中打开`views.py`。我们将修改我们的`homepage`视图以呈现新的`homepage.html`模板。为此，我们将使用 Flask 的`render_template()`函数，将我们的模板名称作为第一个参数传递进去。呈现模板是一个非常常见的操作，所以 Flask 尽可能地简化了这部分内容：

```py
from flask import render_template

from app import app

@app.route('/')
def homepage():
    return render_template('homepage.html')
```

使用我们在上一章中创建的`manage.py`助手，启动开发服务器并导航到`http://127.0.0.1:5000/`以查看呈现的模板，如下面的屏幕截图所示：

```py
(blog) $ python manage.py runserver
* Running on http://127.0.0.1:5000/
* Restarting with reloader

```

![介绍 Jinja2](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_03_01.jpg)

## 基本的模板操作

前面的例子可能看起来并不那么令人印象深刻，因为我们所做的不过是提供一个简单的 HTML 文档。为了使事情变得有趣，我们需要给我们的模板提供上下文。让我们修改我们的主页，显示一个简单的问候语来说明这一点。打开`views.py`并进行以下修改：

```py
from flask import render_template, request

from app import app

@app.route('/')
def homepage():
    name = request.args.get('name')
 if not name:
 name = '<unknown>'
    return render_template('homepage.html', name=name)
```

在视图代码中，我们将`name`传递到模板上下文中。下一步是在实际模板中对`name`做一些操作。在这个例子中，我们将简单地打印`name`的值。打开`homepage.html`并进行以下添加：

```py
<!doctype html>
<html>
  <head>
    <title>Blog</title>
  </head>
  <body>
    <h1>Welcome to my blog</h1>
    <p>Your name is {{ name }}.</p>
  </body>
</html>
```

启动开发服务器并导航到根 URL。你应该看到类似下面图片的东西：

![基本的模板操作](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_03_02.jpg)

传递给`render_template`函数的任何关键字参数都可以在模板上下文中使用。在 Jinja2 的模板语言中，双大括号类似于`print`语句。我们使用`{{ name }}`操作来输出`name`的值，该值设置为`<unknown>`。

### 提示

注重安全的读者可能已经注意到，当我们在浏览器中查看我们的模板时，括号被转义了。通常，括号被浏览器视为 HTML 标记，但是如您所见，Jinja2 已经自动转义了括号，用`&lt;`和`&gt;`替换了它们。

尝试导航到诸如`http://127.0.0.1:5000/?name=Charlie`之类的 URL。无论您指定什么值，Jinja2 都会自动为我们呈现，如下图所示

基本模板操作

假设有人恶意访问您的网站并想要制造一些麻烦。注意到查询字符串中的值直接传递到模板中，这个人决定尝试注入一个脚本标记来玩一些恶作剧。幸运的是，Jinja2 在将值插入渲染页面之前会自动转义这些值。

基本模板操作

## 循环、控制结构和模板编程

Jinja2 支持一种微型编程语言，可用于在上下文中对数据执行操作。如果我们只能将值打印到上下文中，那么实际上就没有太多令人兴奋的事情了。当我们将上下文数据与循环和控制结构等内容结合在一起时，事情就变得有趣起来了。

让我们再次修改我们的主页视图。这次我们将从`request.args`中接受一个数字，以及一个名称，并显示 0 到该数字之间的所有偶数。好处是我们几乎可以在模板中完成所有这些工作。对`views.py`进行以下更改：

```py
from flask import render_template, request

from app import app

@app.route('/')
def homepage():
    name = request.args.get('name')
 number = request.args.get('number')
 return render_template('homepage.html', name=name, number=number)

```

现在打开`hompage.html`模板并添加以下代码。如果看起来奇怪，不用担心。我们将逐行讲解。

```py
<!doctype html>
<html>
  <head>
    <title>Blog</title>
  </head>
  <body>
    <h1>Welcome to my blog</h1>
    {% if number %}
 <p>Your number is {{ number|int }}</p>
 <ul>
 {% for i in range(number|int) %}
 {% if i is divisibleby 2 %}
 <li>{{ i }}</li>
 {% endif %}
 {% endfor %}
 </ul>
 {% else %}
 <p>No number specified.</p>
 {% endif %}

    <p>Your name is {{ name|default('<unknown>', True) }}.</p>
  </body>
</html>
```

启动 runserver 并通过查询字符串传递一些值进行实验。还要注意当传递非数字值或负值时会发生什么。

循环、控制结构和模板编程

让我们逐行讲解我们的新模板代码，从`{% if number %}`语句开始。与使用双大括号的打印标记不同，逻辑标记使用`{%`和`%}`。我们只是检查上下文中是否传递了一个数字。如果数字是`None`或空字符串，则此测试将失败，就像在 Python 中一样。

下一行打印了我们数字的整数表示，并使用了一个新的语法`|int`。竖线符号（`|`）在 Jinja2 中用于表示对过滤器的调用。**过滤器**对位于竖线符号左侧的值执行某种操作，并返回一个新值。在这种情况下，我们使用了内置的`int`过滤器，将字符串转换为整数，在无法确定数字时默认为`0`。Jinja2 内置了许多过滤器；我们将在本章后面讨论它们。

`{% for %}`语句用于创建一个*for*循环，看起来非常接近 Python。我们使用 Jinja2 的`range`辅助函数生成一个数字序列`[0，number)`。请注意，我们再次通过`int`过滤器在调用`range`时将`number`上下文值传递给`range`。还要注意，我们将一个值赋给一个新的上下文变量`i`。在循环体内，我们可以像使用任何其他上下文变量一样使用`i`。

### 提示

当然，就像在普通的 Python 中一样，我们也可以在 for 循环上使用`{% else %}`语句，用于在没有要执行的循环时运行一些代码。

现在我们正在循环遍历数字，我们需要检查`i`是否为偶数，如果是，则打印出来。Jinja2 提供了几种方法可以做到这一点，但我选择展示了一种名为**tests**的 Jinja2 特性的使用。与过滤器和控制结构一样，Jinja2 还提供了许多有用的工具来测试上下文值的属性。测试与`{% if %}`语句一起使用，并通过关键字`is`表示。因此，我们有`{% if i is divisibleby 2 %}`，这非常容易阅读。如果`if`语句评估为`True`，那么我们将使用双大括号打印`i`的值：`{{ i }}`。

### 提示

Jinja2 提供了许多有用的测试；要了解更多，请查阅项目文档[`jinja.pocoo.org/docs/templates/#tests`](http://jinja.pocoo.org/docs/templates/#tests)。

由于 Jinja2 不知道重要的空格，我们需要明确关闭所有逻辑标记。这就是为什么您看到了一个`{% endif %}`标记，表示`divisibleby 2`检查的关闭，以及一个`{% endfor %}`标记，表示`for i in range`循环的关闭。在`for`循环之后，我们现在处于最外层的`if`语句中，该语句测试是否将数字传递到上下文中。如果没有数字存在，我们希望向用户显示一条消息，因此在调用`{% endif %}`之前，我们将使用`{% else %}`标记来显示此消息。

最后，我们已将打印向用户问候语的行更改为`{{ name|default('<unknown>', True) }}`。在视图代码中，我们删除了将其设置为默认值`<unknown>`的逻辑。相反，我们将该逻辑移到了模板中。在这里，我们看到了`default`过滤器（由`|`字符表示），但与`int`不同的是，我们传递了多个参数。在 Jinja2 中，过滤器可以接受多个参数。按照惯例，第一个参数出现在管道符号的左侧，因为过滤器经常操作单个值。如果有多个参数，则这些参数在过滤器名称之后的括号中指定。在`default`过滤器的情况下，我们已指定在未指定名称时使用的值。

## Jinja2 内置过滤器

在前面的示例中，我们看到了如何使用`int`过滤器将上下文值强制转换为整数。除了`int`之外，Jinja2 还提供了大量有用的内置过滤器。出于空间原因（列表非常长），我只包含了我经验中最常用的过滤器，但整个列表可以在网上找到[`jinja.pocoo.org/docs/templates/#list-of-builtin-filters`](http://jinja.pocoo.org/docs/templates/#list-of-builtin-filters)。

### 提示

在以下示例中，参数列表中的第一个参数将出现在管道符号的左侧。因此，即使我写了`abs(number)`，使用的过滤器将是`number|abs`。当过滤器接受多个参数时，剩余的参数将在过滤器名称后的括号中显示。

| 过滤器和参数 | 描述和返回值 |
| --- | --- |
| abs(number) | 返回数字的绝对值。 |

| default(value, default_value='', boolean=False) | 如果`value`未定义（即上下文中不存在该名称），则使用提供的`default_value`。如果您只想测试`value`是否评估为布尔值`True`（即不是空字符串，数字零，None 等），则将第三个参数传递为`True`：

```py
{{ not_in_context&#124;default:"The value was not in the context" }}

{{ ''&#124;default('An empty string.', True) }}
```

|

| dictsort(value, case_sensitive=False, by='key') | 按键对字典进行排序，产生`(key, value)`对。但您也可以按值排序。

```py
<p>Alphabetically by name.</p>
{% for name, age in people&#124;dictsort %}
    {{ name }} is {{ age }} years old.
{% endfor %}

<p>Youngest to oldest.</p>
{% for name, age in people&#124;dictsort(by='value') %}
    {{ name }} is {{ age }} years old.
{% endfor %}
```

|

| int(value, default=0) | 将`value`转换为整数。如果无法转换该值，则使用指定的默认值。 |
| --- | --- |
| length(object) | 返回集合中的项目数。 |
| reverse(sequence) | 反转序列。 |

| safe(value) | 输出未转义的值。当您有信任的 HTML 希望打印时，此过滤器非常有用。例如，如果 `value = "<b>"`：

```py
{{ value }} --> outputs &lt;b&gt;

{{ value&#124;safe }} --> outputs <b>
```

|

| sort(value, reverse=False, case_sensitive=False, attribute=None) | 对可迭代的值进行排序。如果指定了 `reverse`，则项目将以相反顺序排序。如果使用了 `attribute` 参数，该属性将被视为排序的值。 |
| --- | --- |
| striptags(value) | 删除任何 HTML 标签，用于清理和输出不受信任的用户输入。 |
| truncate(value, length=255, killwords=False, end='...') | 返回字符串的截断副本。长度参数指定要保留多少个字符。如果`killwords`为`False`，则一个单词可能会被切成一半；如果为`True`，则 Jinja2 将在前一个单词边界截断。如果值超过长度并且需要被截断，将自动附加`end`中的值。 |
| urlize(value, trim_url_limit=None, nofollow=False, target=None) | 将纯文本中的 URL 转换为可点击的链接。 |

### 提示

过滤器可以链接在一起，所以`{{ number|int|abs }}`首先将数字变量转换为整数，然后返回其绝对值。

# 为博客创建一个基础模板

Jinja2 的继承和包含功能使得定义一个基础模板成为站点上每个页面的架构基础非常容易。基础模板包含一些基本结构，如`<html>`、`<head>`和`<body>`标签，以及 body 的基本结构。它还可以用于包含样式表或脚本，这些样式表或脚本将在每个页面上提供。最重要的是，基础模板负责定义可覆盖的块，我们将在其中放置特定于页面的内容，如页面标题和正文内容。

为了快速启动，我们将使用 Twitter 的 Bootstrap 库（版本 3）。这将使我们能够专注于模板的结构，并且只需进行最少的额外工作就能拥有一个看起来不错的网站。当然，如果您愿意，也可以使用自己的 CSS，但示例代码将使用特定于 bootstrap 的结构。

在`templates`目录中创建一个名为`base.html`的新文件，并添加以下内容：

```py
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>{% block title %}{% endblock %} | My Blog</title>
    <link rel="stylesheet" href="//netdna.bootstrapcdn.com/bootstrap/3.1.0/css/bootstrap.min.css">
    <style type="text/css">
      body { padding-top: 60px; }
    </style>
    {% block extra_styles %}{% endblock %}

    <script src="img/jquery-1.10.2.min.js"></script>
    <script src="img/bootstrap.min.js"></script>
    {% block extra_scripts %}{% endblock %}
  </head>

  <body class="{% block body_class %}{% endblock %}">
    <div class="navbar navbar-inverse navbar-fixed-top" role="navigation">
      <div class="container">
        <div class="navbar-header">
          <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-collapse">
            <span class="sr-only">Toggle navigation</span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
          </button>
          <a class="navbar-brand" href="#">{% block branding %}My Blog{% endblock %}</a>
        </div>
        <div class="collapse navbar-collapse">
          <ul class="nav navbar-nav">
            <li><a href="/">Home</a></li>
            {% block extra_nav %}{% endblock %}
          </ul>
        </div>
      </div>
    </div>
    <div class="container">
      <div class="row">
        <div class="col-md-9">
          <h1>{% block content_title %}{% endblock %}</h1>
          {% block content %}
          {% endblock %}
        </div>
        <div class="col-md-3">
          {% block sidebar %}
          <ul class="well nav nav-stacked">
            <li><a href="#">Sidebar item</a></li>
          </ul>
          {% endblock %}
        </div>
      </div>
      <div class="row">
        <hr />
        <footer>
          <p>&copy; your name</p>
        </footer>
      </div>
    </div>
  </body>
</html>
```

在标记中夹杂着一个新的 Jinja2 标签`block`。`block`标签用于指示页面的可覆盖区域。

您可能已经注意到我们正在从公开可用的 URL 中提供 jQuery 和 Bootstrap。在下一章中，我们将讨论如何提供存储在本地磁盘上的静态文件。现在我们可以修改我们的主页模板，并利用新的基础模板。我们可以通过扩展基础模板并覆盖某些块来实现这一点。这与大多数语言中的类继承非常相似。只要继承页面的部分被很好地分成块，我们就可以只覆盖需要更改的部分。让我们打开`homepage.html`，并用以下内容替换当前内容的一部分：

```py
{% extends "base.html" %}

{% block content_title %}Welcome to my blog{% endblock %}

{% block content %}
  {% if number %}
    <p>Your number is {{ number|int }}</p>
    <ul>
      {% for i in range(number|int) %}
        {% if i is divisibleby 2 %}
          <li>{{ i }}</li>
        {% endif %}
      {% endfor %}
    </ul>
  {% else %}
    <p>No number specified.</p>
  {% endif %}

  <p>Your name is {{ name|default('<unknown>', True) }}.</p>
{% endblock %}
```

通过扩展原始页面，我们已经删除了所有 HTML 样板和大量复杂性，只关注于使这个页面，我们的主页视图，独特的部分。启动服务器并导航到`http://127.0.0.1:5000/`，您会看到我们的主页已经改变了。

![为博客创建基础模板](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_03_06.jpg)

恭喜！您现在已经学会了 Jinja2 最常用的一些功能。还有许多更高级的功能我们没有在时间允许的情况下涵盖，我建议阅读项目的文档，以了解 Jinja2 的全部可能性。文档可以在[`jinja.pocoo.org/docs/`](http://jinja.pocoo.org/docs/)找到。

我们仍然需要构建模板来显示我们的博客条目。但在继续构建模板之前，我们首先必须创建一些视图函数，这些函数将生成博客条目的列表。然后我们将条目传递到上下文中，就像我们在主页中所做的那样。

# 创建 URL 方案

URL 是给人看的，因此它们应该易于记忆。当 URL 方案准确反映网站的隐含结构时，良好的 URL 方案易于记忆。我们的目标是创建一个 URL 方案，使我们网站上的访问者能够轻松找到他们感兴趣的主题的博客条目。

参考我们在第一章中创建的规范，*创建您的第一个 Flask 应用程序*，我们知道我们希望我们的博客条目按标签和日期进行组织。按标签和日期组织的条目必然是所有条目的子集，因此给我们提供了这样的结构：

| URL | 目的 |
| --- | --- |
| `/entries/` | 这显示了我们所有的博客条目，按最近的顺序排列 |
| `/entries/tags/` | 这包含用于组织我们的博客条目的所有标签 |
| `/entries/tags/python/` | 这包含所有标记为`python`的条目 |
| `/entries/learning-the-flask-framework/` | 这是显示博客条目标题为*学习 Flask 框架*的正文内容的详细页面 |

由于单个博客条目可能与多个标签相关联，我们如何决定将其用作规范 URL？如果我写了一篇名为*学习 Flask 框架*的博客条目，我可以将其嵌套在`/entries/`，`/entries/tags/python/`，`/entries/tags/flask/`等下。这将违反有关良好 URL 的规则之一，即唯一资源应该有一个且仅有一个 URL。因此，我将主张将单个博客条目放在层次结构的顶部：

`/entries/learning-the-flask-framework/`

通常，具有大量时间敏感内容的新闻网站和博客将使用发布日期嵌套单个内容片段。这可以防止当两篇文章可能具有相同的标题但是在不同时间编写时发生冲突。当每天产生大量内容时，这种方案通常更有意义：

`/entries/2014/jan/18/learning-the-flask-framework/`

尽管我们在本章中不会涵盖这种类型的 URL 方案，但代码可以在[`www.packtpub.com/support`](http://www.packtpub.com/support)上找到。

## 定义 URL 路由

让我们将之前描述的结构转换为 Flask 将理解的一些 URL 路由。在博客项目的`app`目录中创建一个名为`entries`的新目录。在`entries`目录内，创建两个文件，`__init__.py`和`blueprint.py`如下：

```py
(blog) $ mkdir entries
(blog) $ touch entries/{__init__,blueprint}.py

```

**Blueprints**提供了一个很好的 API，用于封装一组相关的路由和模板。在较小的应用程序中，通常所有内容都会在应用程序对象上注册（即`app.route`）。当应用程序具有不同的组件时，如我们的应用程序，可以使用 blueprints 来分离各种移动部分。由于`/entries/` URL 将完全用于我们的博客条目，我们将创建一个 blueprint，然后定义视图来处理我们之前描述的路由。打开`blueprint.py`并添加以下代码：

```py
from flask import Blueprint

from models import Entry, Tag

entries = Blueprint('entries', __name__, template_folder='templates')

@entries.route('/')
def index():
    return 'Entries index'

@entries.route('/tags/')
def tag_index():
    pass

@entries.route('/tags/<slug>/')
def tag_detail(slug):
    pass

@entries.route('/<slug>/')
def detail(slug):
    pass
```

这些 URL 路由是我们将很快填充的占位符，但我想向您展示如何将一组 URL 模式清晰简单地转换为一组路由和视图。

为了访问这些新视图，我们需要使用我们的主要 Flask `app`对象注册我们的 blueprint。我们还将指示我们的应用程序，我们希望我们的条目的 URL 位于前缀`/entries`。打开`main.py`并进行以下添加：

```py
from app import app, db
import models
import views

from entries.blueprint import entries
app.register_blueprint(entries, url_prefix='/entries')

if __name__ == '__main__':
    app.run()
```

如果您想测试一下，请启动调试服务器（`python manage.py runserver`）并导航到`http://127.0.0.1:5000/entries/`。您应该会看到以下消息：

![定义 URL 路由](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_03_07.jpg)

## 构建索引视图

`index`视图是我们`/entries/`层次结构中最顶层的 URL，因此将包含所有的条目。随着时间的推移，我们可能会有数十甚至数百个博客条目，因此我们希望对这个列表进行分页，以免压倒我们的访问者（或我们的服务器！）。因为我们经常需要显示对象列表，让我们创建一个助手模块，以便轻松地显示对象的分页列表。在`app`目录中，创建一个名为`helpers.py`的新模块，并添加以下代码：

```py
from flask import render_template, request

def object_list(template_name, query, paginate_by=20, **context):
    page = request.args.get('page')
    if page and page.isdigit():
        page = int(page)
    else:
        page = 1
    object_list = query.paginate(page, paginate_by)
    return render_template(template_name, object_list=object_list, **context)
```

现在，我们将打开`entries/blueprint.py`并修改`index`视图以返回分页列表条目：

```py
from flask import Blueprint

from helpers import object_list
from models import Entry, Tag

entries = Blueprint('entries', __name__, template_folder='templates')

@entries.route('/')
def index():
    entries = Entry.query.order_by(Entry.created_timestamp.desc())
 return object_list('entries/index.html', entries)

```

我们正在导入`object_list`辅助函数，并将其传递给模板的名称和表示我们希望显示的条目的查询。随着我们构建这些视图的其余部分，您将看到诸如`object_list`这样的小辅助函数如何使 Flask 开发变得非常容易。

最后一部分是`entries/index.html`模板。在`entries`目录中，创建一个名为`templates`的目录，和一个名为`entries`的子目录。创建`index.html`，使得从`app`目录到`entries/templates/entries/index.html`的完整路径，并添加以下代码：

```py
{% extends "base.html" %}

{% block title %}Entries{% endblock %}

{% block content_title %}Entries{% endblock %}

{% block content %}
  {% include "includes/list.html" %}
{% endblock %}
```

这个模板非常简单，所有的工作都将在`includes/list.html`中进行。`{% include %}`标签是新的，对于可重用的模板片段非常有用。创建文件`includes/list.html`并添加以下代码：

```py
{% for entry in object_list.items %}
  <p><a href="{{ url_for('entries.detail', slug=entry.slug) }}">{{ entry.title }}</a></p>
{% endfor %}
```

`url_for`函数非常有用。`url_for()`允许我们提供视图函数的名称或任何参数，然后生成 URL。由于我们希望引用的 URL 是 entries blueprint 的`detail`视图，视图的名称是`entries.detail`。详细视图接受一个参数，即条目标题的 slug。

在构建详细视图之前，重新打开基本模板，并在导航部分添加一个链接到条目：

```py
<ul class="nav navbar-nav">
  <li><a href="{{ url_for('homepage') }}">Home</a></li>
  <li><a href="{{ url_for('entries.index') }}">Blog</a></li>
  {% block extra_nav %}{% endblock %}
</ul>
```

下面的屏幕截图显示了更新后的导航标题，以及博客条目的列表：

![构建索引视图](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_03_08.jpg)

## 构建详细视图

让我们创建一个简单的视图，用于呈现单个博客条目的内容。条目的 slug 将作为 URL 的一部分传递进来。我们将尝试将其与现有的`Entry`匹配，如果没有匹配项，则返回 404 响应。更新 entries blueprint 中的`detail`视图的以下代码：

```py
from flask import render_template
@entries.route('/<slug>/')
def detail(slug):
 entry = Entry.query.filter(Entry.slug == slug).first_or_404()
 return render_template('entries/detail.html', entry=entry)

```

在`entries`模板目录中创建一个名为`detail.html`的模板，并添加以下代码。我们将在主内容区域显示条目的标题和正文，但在侧边栏中，我们将显示一个标签列表和条目创建日期：

```py
{% extends "base.html" %}

{% block title %}{{ entry.title }}{% endblock %}

{% block content_title %}{{ entry.title }}{% endblock %}

{% block sidebar %}
  <ul class="well nav nav-list">
    <li><h4>Tags</h4></li>
    {% for tag in entry.tags %}
      <li><a href="{{ url_for('entries.tag_detail', slug=tag.slug) }}">{{ tag.name }}</a></li>
    {% endfor %}
  </ul>

  <p>Published {{ entry.created_timestamp.strftime('%m/%d/%Y') }}</p>
{% endblock %}

{% block content %}
  {{ entry.body }}
{% endblock %}
```

现在应该可以在索引页面上查看条目，并转到详细视图的链接。正如你可能猜到的，我们需要解决的下一个问题是标签详细页面。

![构建详细视图](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_03_09.jpg)

## 列出与给定标签匹配的条目

列出与给定标签匹配的条目将结合两个先前视图的逻辑。首先，我们需要使用 URL 中提供的`tag` slug 查找`Tag`，然后我们将显示一个`object_list`，其中包含使用指定标签标记的`Entry`对象。在`tag_detail`视图中，添加以下代码：

```py
@entries.route('/tags/<slug>/')
def tag_detail(slug):
 tag = Tag.query.filter(Tag.slug == slug).first_or_404()
 entries = tag.entries.order_by(Entry.created_timestamp.desc())
 return object_list('entries/tag_detail.html', entries, tag=tag)

```

`entries`查询将获取与标签相关的所有条目，然后按最近的顺序返回它们。我们还将标签传递到上下文中，以便在模板中显示它。创建`tag_detail.html`模板并添加以下代码。由于我们将显示一个条目列表，我们将重用我们的`list.html`包含：

```py
{% extends "base.html" %}

{% block title %}{{ tag.name }} entries{% endblock %}

{% block content_title %}{{ tag.name }} entries{% endblock %}

{% block content %}
  {% include "includes/list.html" %}
{% endblock %}
```

在下面的屏幕截图中，我已经导航到`/entries/tags/python/`。这个页面只包含已经被标记为*Python*的条目：

![列出与给定标签匹配的条目](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_03_10.jpg)

## 列出所有标签

最后缺失的部分是显示所有标签列表的视图。这个视图将与`index`条目非常相似，只是我们将查询`Tag`模型而不是`Entry`对象。更新以下代码到`tag_index`视图：

```py
@entries.route('/tags/')
def tag_index():
 tags = Tag.query.order_by(Tag.name)
 return object_list('entries/tag_index.html', tags)

```

在模板中，我们将每个标签显示为指向相应标签详情页面的链接。创建文件`entries/tag_index.html`并添加以下代码：

```py
{% extends "base.html" %}

{% block title %}Tags{% endblock %}

{% block content_title %}Tags{% endblock %}

{% block content %}
  <ul>
    {% for tag in object_list.items %}
      <li><a href="{{ url_for('entries.tag_detail', slug=tag.slug) }}">{{ tag.name }}</a></li>
    {% endfor %}
  </ul>
{% endblock %}
```

如果你愿意，你可以在基础模板的导航中添加一个到标签列表的链接。

## 全文搜索

为了让用户能够找到包含特定单词或短语的帖子，我们将在包含博客条目列表的页面上添加简单的全文搜索。为了实现这一点，我们将进行一些重构。我们将在所有包含博客条目列表的页面的侧边栏中添加一个搜索表单。虽然我们可以将相同的代码复制粘贴到`entries/index.html`和`entries/tag_detail.html`中，但我们将创建另一个包含搜索小部件的基础模板。创建一个名为`entries/base_entries.html`的新模板，并添加以下代码：

```py
{% extends "base.html" %}

{% block sidebar %}
  <form class="form-inline well" method="get" role="form">
    <div class="input-group">
      <input class="form-control input-xs" name="q" placeholder="Search..." value="{{ request.args.get('q', '') }}" />
      <span class="input-group-btn">
        <button class="btn btn-default" type="submit">Go</button>
      </span>
    </div>
  </form>
{% endblock %}

{% block content %}
  {% include "includes/list.html" %}
{% endblock %}
```

### 提示

尽管我们不会明确地将`request`传递到上下文中，Flask 会使其可访问。你可以在 Flask 文档的[`flask.pocoo.org/docs/templating/#standard-context`](http://flask.pocoo.org/docs/templating/#standard-context)中找到标准上下文变量的列表。

现在我们将更新`entries/index.html`和`entries/tag_detail.html`以利用这个新的基础模板。由于`content`块包含条目列表，我们可以从这两个模板中删除它：

```py
{% extends "entries/base_entries.html" %}

{% block title %}Entries{% endblock %}

{% block content_title %}Entries{% endblock %}
```

这是在更改基础模板并删除上下文块后的`entries/index.html`的样子。对`entries/tag_detail.html`做同样的操作。

```py
{% extends "entries/base_entries.html" %}
{% block title %}Tags{% endblock %}
{% block content_title %}Tags{% endblock %}
```

现在我们需要更新我们的视图代码来实际执行搜索。为此，我们将在蓝图中创建一个名为`entry_list`的新辅助函数。这个辅助函数将类似于`object_list`辅助函数，但会执行额外的逻辑来根据我们的搜索查询过滤结果。将`entry_list`函数添加到`blueprint.py`中。注意它如何检查请求查询字符串是否包含名为`q`的参数。如果`q`存在，我们将只返回标题或正文中包含搜索短语的条目：

```py
from flask import request
def entry_list(template, query, **context):
    search = request.args.get('q')
    if search:
        query = query.filter(
            (Entry.body.contains(search)) |
            (Entry.title.contains(search)))
    return object_list(template, query, **context)
```

为了利用这个功能，修改`index`和`tag_detail`视图，调用`entry_list`而不是`object_list`。更新后的`index`视图如下：

```py
@entries.route('/')
def index():
    entries = Entry.query.order_by(Entry.created_timestamp.desc())
    return entry_list('entries/index.html', entries)
```

恭喜！现在你可以导航到条目列表并使用搜索表单进行搜索。

![全文搜索](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_03_11.jpg)

# 添加分页链接

正如我们之前讨论的，我们希望对条目的长列表进行分页，以便用户不会被极长的列表所压倒。我们实际上已经在`object_list`函数中完成了所有工作；唯一剩下的任务是添加链接，让用户可以从一个条目页面跳转到下一个页面。

因为分页链接是我们将在多个地方使用的一个功能，我们将在应用程序的模板目录中创建分页`include`（而不是条目模板目录）。在`app/templates/`中创建一个名为`includes`的新目录，并创建一个名为`page_links.html`的文件。由于`object_list`返回一个`PaginatedQuery`对象，我们可以在模板中利用这个对象来确定我们所在的页面以及总共有多少页。为了使分页链接看起来漂亮，我们将使用 Bootstrap 提供的 CSS 类。将以下内容添加到`page_links.html`中：

```py
<ul class="pagination">
  <li{% if not object_list.has_prev %} class="disabled"{% endif %}>
    {% if not object_list.has_prev %}
      <a href="./?page={{ object_list.prev_num }}">&laquo;</a>
    {% else %}
      <a href="#">&laquo;</a>
    {% endif %}
  </li>
  {% for page in object_list.iter_pages() %}
    <li>
      {% if page %}
        <a {% if page == object_list.page %}class="active" {% endif %}href="./?page={{ page }}">{{ page }}</a>
      {% else %}
        <a class="disabled">...</a>
      {% endif %}
    </li>
  {% endfor %}
  <li{% if not object_list.has_next %} class="disabled"{% endif %}>
    {% if object_list.has_next %}
      <a href="./?page={{ object_list.next_num }}">&raquo;</a>
    {% else %}
      <a href="#">&raquo;</a>
    {% endif %}
  </li>
</ul>
```

现在，无论我们在哪里显示一个对象列表，让我们在页面底部包含`page_links.html`模板。目前，我们需要更新的模板只有`entries/base_entries.html`和`entries/tag_index.html`。`base_entries.html`的`content`块如下：

```py
{% block content %}
  {% include "includes/list.html" %}
  {% include "includes/page_links.html" %}
{% endblock %}
```

![添加分页链接](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_03_12.jpg)

# 增强博客应用

在继续下一章之前，我建议花一些时间来实验我们在本章中创建的视图和模板。以下是一些您可以考虑的想法：

+   在条目详细视图上对标签列表进行排序（提示：使用标签的`name`属性上的`sort`过滤器）。

+   从主页模板中删除示例代码，并添加您自己的内容。

+   您可能已经注意到，我们正在显示所有条目，而不考虑它们的状态。修改`entry_list`函数和条目`detail`视图，只显示状态为`STATUS_PUBLIC`的`Entry`对象。

+   尝试不同的 Bootstrap 主题- [`bootswatch.com`](http://bootswatch.com)有许多免费的主题可供选择。

+   高级：允许指定多个标签。例如，`/entries/tags/flask+python/`只会显示标记有*flask*和*python*的条目。

# 总结

在本章中，我们涵盖了大量信息，到目前为止，您应该熟悉创建视图和模板的过程。我们学会了如何呈现 Jinja2 模板以及如何将数据从视图传递到模板上下文中。我们还学会了如何在模板中修改上下文数据，使用 Jinja2 标签和过滤器。在本章的后半部分，我们为网站设计了 URL 结构，并将其转换为 Flask 视图。我们为网站添加了一个简单的全文搜索功能，并通过为条目和标签列表添加分页链接来结束。

在下一章中，我们将学习如何通过网站使用**表单**创建和编辑博客条目。我们将学习如何处理和验证用户输入，然后将更改保存到数据库中。我们还将添加一个上传照片的功能，以便在博客条目中嵌入图像。
