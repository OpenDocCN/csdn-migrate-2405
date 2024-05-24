# 精通 Flask（一）

> 原文：[`zh.annas-archive.org/md5/3704FA7246A3AC34DE99A41EE212E530`](https://zh.annas-archive.org/md5/3704FA7246A3AC34DE99A41EE212E530)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Flask 是 Python 的一个 Web 框架，专门设计为提供创建 Web 应用程序所需的最少功能。与其他 Web 框架不同，特别是其他语言中的框架，Flask 没有整个与其捆绑的库生态系统，用于诸如数据库查询或表单处理之类的功能。相反，Flask 更喜欢是一个实现不可知的框架。

这种设置的主要特点是它允许程序员以任何他们想要的方式设计他们的应用程序和工具。不提供常见抽象的自己版本也意味着标准库可以比其他框架更常用，这保证了它们的稳定性和其他 Python 程序员的可读性。由于 Flask 社区相当庞大，也有许多不同的社区提供的添加常见功能的方式。本书的主要重点之一是介绍这些扩展，并找出它们如何帮助避免重复造轮子。这些扩展的最大优点是，如果您不需要它们的额外功能，您不需要包含它们，您的应用程序将保持较小。

这种设置的主要缺点是，绝大多数新的 Flask 用户不知道如何正确地构建大型应用程序，最终创建了难以理解和难以维护的代码混乱。这就是本书的另一个主要重点，即如何在 Flask 应用程序中创建模型视图控制器（MVC）架构。

最初是为设计桌面用户界面而发明的 MVC 设置允许数据处理（模型）、用户交互（控制器）和用户界面（视图）分离为三个不同的组件。

![前言](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_Preface.jpg)

将这三个不同的组件分开允许程序员重用代码，而不是为每个网页重新实现相同的功能。例如，如果数据处理代码没有分割成自己独立的函数，我们将不得不在渲染网页的每个函数中编写相同的数据库连接代码和 SQL 查询。

大量的研究和大量的痛苦的第一手经验使本书成为最全面的 Flask 资源，因此我真诚地希望您会喜欢阅读它。

# 本书涵盖内容

第一章，“入门”，帮助读者使用 Python 项目的最佳实践设置 Flask 开发环境。读者将获得一个非常基本的 Flask 应用程序框架，该框架将贯穿整本书。

第二章，“使用 SQLAlchemy 创建模型”，展示了如何使用 Python 数据库库 SQLAlchemy 与 Flask 一起创建面向对象的数据库 API。

第三章，“使用模板创建视图”，展示了如何使用 Flask 的模板系统 Jinja，通过利用 SQLAlchemy 模型动态创建 HTML。

第四章，“使用蓝图创建控制器”，介绍了如何使用 Flask 的蓝图功能来组织您的视图代码，同时避免重复。

第五章，“高级应用程序结构”，利用前四章所学的知识，解释了如何重新组织代码文件，以创建更易维护和可测试的应用程序结构。

第六章，“保护您的应用程序”，解释了如何使用各种 Flask 扩展来添加具有基于权限的访问权限的登录系统。

第七章，“在 Flask 中使用 NoSQL”，展示了 NoSQL 数据库是什么，以及如何在允许更强大功能时将其集成到您的应用程序中。

第八章，“构建 RESTful API”，展示了如何以安全且易于使用的方式向第三方提供应用程序数据库中存储的数据。

第九章，“使用 Celery 创建异步任务”，解释了如何将昂贵或耗时的程序移到后台，以便应用程序不会变慢。

第十章，“有用的 Flask 扩展”，解释了如何利用流行的 Flask 扩展，以使您的应用程序更快，添加更多功能，并使调试更容易。

第十一章，“构建您自己的扩展”，教您 Flask 扩展的工作原理以及如何创建您自己的扩展。

第十二章，“测试 Flask 应用”，解释了如何为您的应用程序添加单元测试和用户界面测试，以确保质量并减少错误代码的数量。

第十三章，“部署 Flask 应用”，解释了如何将您完成的应用程序从开发转移到托管在实时服务器上。

# 您需要为本书做好准备

要开始阅读本书，您只需要选择一个文本编辑器，一个网络浏览器，并在您的计算机上安装 Python。

Windows，Mac OS X 和 Linux 用户都应该能够轻松地跟上本书的内容。

# 这本书是为谁写的

这本书是为已经对 Flask 有一定了解并希望将他们的 Flask 理解从入门到精通的 Web 开发人员编写的。

# 约定

在本书中，您将找到一些区分不同类型信息的文本样式。以下是这些样式的一些示例及其含义的解释。

文本中的代码单词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄显示如下：“`first()`和`all()`方法返回一个值，因此结束链。”

代码块设置如下：

```py
class User(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(255))
    password = db.Column(db.String(255))
    posts = db.relationship(
        'Post',
        backref='user',
        lazy='dynamic'
    )
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```py
from flask.ext.sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config.from_object(DevConfig)
db = SQLAlchemy(app)

```

任何命令行输入或输出都以以下方式编写：

```py
$ python manage.py db init

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这样的方式出现在文本中：“点击另一个按钮，上面写着**下载 Bootstrap**，然后您将开始下载一个 Zip 文件。”

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：入门

**Python**是一种灵活的语言，给程序员自由构建他们的编程环境。然而，这种自由的危险后果是从一开始就不设置一个新的 Python 项目，以避免未来出现问题。

例如，你可能已经进行了一半的项目，意识到你五天前删除了一个你现在需要使用的文件或代码。再举一个例子，你希望使用的两个包需要同一个基础包的不同版本。除了本章介绍的工具之外，修复已经有解决方案的问题将需要大量额外的工作。在开始时多做一点额外的工作可以节省未来数天的工作。

为此，我们需要安装三个程序：**Git**、**pip**和**virtualenv**。

# 使用 Git 进行版本控制

为了防止人为错误，我们将使用一个名为 Git 的版本控制系统。**版本控制**是一种记录文件随时间变化的工具。这使得程序员可以看到代码如何从以前的修订版变化，并甚至将代码恢复到以前的状态。版本控制系统还使得合作比以往更容易，因为更改可以在许多不同的程序员之间共享，并自动合并到项目的当前版本中，而无需复制和粘贴数百行代码。

简而言之，版本控制就像是你的代码的备份，只是更强大。

## 安装 Git

安装 Git 非常简单。只需转到[`www.git-scm.com/downloads`](http://www.git-scm.com/downloads)，然后点击正在运行的**操作系统**（**OS**）。一个程序将开始下载，它将引导您完成基本的安装过程。

### Windows 上的 Git

Git 最初仅为 Unix 操作系统（例如 Linux、Mac OS X）开发。因此，在 Windows 上使用 Git 并不是无缝的。在安装过程中，安装程序会询问您是否要在普通的 Windows 命令提示符旁边安装 Git。不要选择此选项。选择默认选项，将在系统上安装一个名为**Bash**的新类型的命令行，这是 Unix 系统使用的相同命令行。Bash 比默认的 Windows 命令行更强大，本书中的所有示例都将使用它。

### 注意

初学者的 Bash 入门教程位于[`linuxcommand.org/learning_the_shell.php#contents`](http://linuxcommand.org/learning_the_shell.php#contents)。

## Git 基础知识

Git 是一个非常复杂的工具；这里只会涵盖本书所需的基础知识。

### 注意

要了解更多，请参阅 Git 文档[`www.git-scm.com/doc`](http://www.git-scm.com/doc)。

Git 不会自动跟踪你的更改。为了让 Git 正常运行，我们必须提供以下信息：

+   要跟踪哪些文件夹

+   何时保存代码的状态

+   要跟踪什么，不要跟踪什么

在我们做任何事情之前，我们告诉 Git 在我们的目录中创建一个`git`实例。在你的项目目录中，在终端中运行以下命令：

```py
$ git init

```

Git 现在将开始跟踪我们项目中的更改。当`git`跟踪我们的文件时，我们可以通过输入以下命令来查看我们跟踪文件的状态，以及任何未跟踪的文件：

```py
$ git status

```

现在我们可以保存我们的第一个**提交**，这是在运行`commit`命令时代码的快照。

```py
# In Bash, comments are marked with a #, just like Python
# Add any files that have changes and you wish to save in this commit
$ git add main.py
# Commit the changes, add in your commit message with -m
$ git commit -m"Our first commit"

```

在将来的任何时候，我们都可以返回到项目的这一点。将要提交的文件称为 Git 中的**暂存**文件。记住只有在准备好提交它们时才添加暂存文件。一旦文件被暂存，任何进一步的更改也不会被暂存。对于更高级的 Git 使用示例，请向你的`main.py`文件添加任何文本，然后运行以下命令：

```py
# To see the changes from the last commit
$ git diff
# To see the history of your changes
$ git log
# As an example, we will stage main.py
# and then remove any added files from the stage
$ git add main.py
$ git status
$ git reset HEAD main.py
# After any complicated changes, be sure to run status
# to make sure everything went well
$ git status
# lets delete the changes to main.py, reverting to its state at the last commit
# This can only be run on files that aren't staged
$ git checkout -- main.py

```

你的终端应该看起来像这样：

![Git 基础知识](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_01_01.jpg)

Git 系统的 `checkout` 命令对于这个简单的介绍来说相当高级，但它用于改变 Git 系统的 `HEAD` 指针的当前状态，也就是我们代码在项目历史中的当前位置。这将在下一个示例中展示。

现在，要查看以前提交的代码，请先运行此命令：

```py
$ git log
Fri Jan 23 19:16:43 2015 -0500 f01d1e2 Our first commit  [Jack Stouffer]

```

紧挨着我们提交消息的字符串 `f01d1e2`，被称为我们提交的 **哈希**。它是该提交的唯一标识符，我们可以使用它返回到保存的状态。现在，要将项目恢复到该状态，请运行此命令：

```py
$ git checkout f01d1e2

```

您的 Git 项目现在处于一种特殊状态，任何更改或提交都不会被保存，也不会影响您检出后进行的任何提交。这种状态只用于查看旧代码。要返回到 Git 的正常模式，请运行此命令：

```py
$ git checkout master

```

# 使用 pip 进行 Python 包管理

在 Python 中，程序员可以从其他程序员那里下载库，以扩展标准 Python 库的功能。就像您从 Flask 中了解到的那样，Python 的很多功能来自于其大量的社区创建的库。

然而，安装第三方库可能会非常麻烦。假设有一个名为 X 的包需要安装。很简单，下载 Zip 文件并运行 `setup.py`，对吗？并不完全是这样。包 X 依赖于包 Y，而包 Y 又依赖于 Z 和 Q。这些信息都没有在包 X 的网站上列出，但它们需要被安装才能让 X 正常工作。然后，您必须逐个找到所有的包并安装它们，希望您安装的包不需要额外的包。

为了自动化这个过程，我们使用 **pip**，即 Python 包管理器。

## 在 Windows 上安装 pip Python 包管理器

如果您使用的是 Windows，并且已安装了当前版本的 Python，那么您已经有了 pip！如果您的 Python 安装不是最新的，最简单的方法就是重新安装它。在 [`www.python.org/downloads/`](https://www.python.org/downloads/) 下载 Python Windows 安装程序。

在 Windows 上，控制从命令行访问哪些程序的变量是 **path**。要修改您的路径以包括 Python 和 pip，我们必须添加 `C:\Python27` 和 `C:\Python27\Tools`。通过打开 Windows 菜单，右键单击 **计算机**，然后单击 **属性** 来编辑 Windows 路径。在 **高级系统设置** 下，单击 **环境变量...**。向下滚动直到找到 **Path**，双击它，并在末尾添加 `;C:\Python27;C:\Python27\Tools`。

确保您已正确修改了路径，请关闭并重新打开终端，并在命令行中输入以下内容：

```py
pip --help

```

### 提示

**下载示例代码**

您可以从 [`www.packtpub.com`](http://www.packtpub.com) 的帐户中下载您购买的所有 Packt Publishing 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问 [`www.packtpub.com/support`](http://www.packtpub.com/support) 并注册，以便直接通过电子邮件接收文件。

`pip` 应该已经打印出其使用消息，如下面的屏幕截图所示：

![在 Windows 上安装 pip Python 包管理器](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_01_02.jpg)

## 在 Mac OS X 和 Linux 上安装 pip Python 包管理器

一些 Linux 上的 Python 安装不带有 pip，Mac OS X 上的安装默认也不带有 pip。要安装它，请从 [`raw.githubusercontent.com/pypa/pip/master/contrib/get-pip.py`](https://raw.githubusercontent.com/pypa/pip/master/contrib/get-pip.py) 下载 `get-pip.py` 文件。

下载后，使用以下命令以提升的权限运行它：

```py
$ sudo python get-pip.py

```

然后 pip 将被自动安装。

## pip 基础知识

要使用 `pip` 安装一个包，请按照以下简单步骤进行：

```py
$ pip install [package-name]

```

在 Mac 和 Linux 上，因为你在用户拥有的文件夹之外安装程序，你可能需要在安装命令前加上`sudo`。要安装 Flask，只需运行这个命令：

```py
$ pip install flask

```

然后，Flask 的所有要求将被安装。

如果你想要移除一个不再使用的包，运行这个命令：

```py
$ pip uninstall [package-name]

```

如果你想探索或找到一个包，但不知道它的确切名称，你可以使用搜索命令：

```py
$ pip search [search-term]

```

现在我们安装了一些包，在 Python 社区中，通常习惯创建一个运行项目所需的包的列表，这样其他人可以快速安装所有所需的东西。这也有一个额外的好处，即你项目的任何新成员都能够快速运行你的代码。

这个列表可以通过 pip 运行这个命令来创建：

```py
$ pip freeze > requirements.txt

```

这个命令到底做了什么？`pip freeze`单独运行会打印出安装的包及其版本的列表，如下所示：

```py
Flask==0.10.1
itsdangerous==0.24
Jinja2==2.7.3
MarkupSafe==0.23
Werkzeug==0.10.4
wheel==0.24.0
```

`>`操作符告诉 Bash 获取上一个命令打印的所有内容并将其写入这个文件。如果你查看你的项目目录，你会看到一个名为`requirements.txt`的新文件，其中包含了`pip freeze`的输出。

要安装这个文件中的所有包，新的项目维护者将不得不运行这个命令：

```py
$ pip install -r requirements.txt

```

这告诉`pip`读取`requirements.txt`中列出的所有包并安装它们。

# 使用 virtualenv 进行依赖隔离

所以你已经安装了你的新项目所需的所有包。太好了！但是，当我们在以后开发第二个项目时，会使用这些包的更新版本会发生什么？当你希望使用的库依赖于你为第一个项目安装的库的旧版本时会发生什么？当更新的包包含破坏性更改时，升级它们将需要在旧项目上进行额外的开发工作，这可能是你无法承受的。

幸运的是，有一个名为 virtualenv 的工具，它可以为你的 Python 项目提供隔离。virtualenv 的秘密在于欺骗你的计算机，让它在项目目录中查找并安装包，而不是在主 Python 目录中，这样你可以完全隔离它们。

现在我们有了 pip，要安装 virtualenv 只需运行这个命令：

```py
$ pip install virtualenv

```

## virtualenv 基础

让我们按照以下方式为我们的项目初始化 virtualenv：

```py
$ virtualenv env

```

额外的`env`告诉`virtualenv`将所有的包存储到一个名为`env`的文件夹中。virtualenv 要求你在对项目进行隔离之前启动它：

```py
$ source env/bin/activate
# Your prompt should now look like
(env) $

```

`source`命令告诉 Bash 在当前目录的上下文中运行脚本`env/bin/activate`。让我们在我们的新隔离环境中重新安装 Flask：

```py
# you won't need sudo anymore
(env) $ pip install flask
# To return to the global Python
(env) $ deactivate

```

然而，跟踪你不拥有的东西违反了 Git 的最佳实践，所以我们应该避免跟踪第三方包的更改。要忽略项目中的特定文件，需要`gitignore`文件。

```py
$ touch .gitignore

```

`touch`是 Bash 创建文件的命令，文件名开头的点告诉 Bash 不要列出它的存在，除非特别告诉它显示隐藏文件。我们现在将创建一个简单的`gitignore`文件：

```py
env/
*.pyc
```

这告诉 Git 忽略整个`env`目录和所有以`.pyc`结尾的文件（一个*编译*的 Python 文件）。在这种用法中，`*`字符被称为**通配符**。

# 我们项目的开始

最后，我们可以开始我们的第一个 Flask 项目了。为了在本书结束时拥有一个复杂的项目，我们需要一个简单的 Flask 项目来开始。

在名为`config.py`的文件中，添加以下内容：

```py
class Config(object):
    pass

class ProdConfig(Config):
    pass

class DevConfig(Config):
    DEBUG = True
```

现在，在另一个名为`main.py`的文件中，添加以下内容：

```py
from flask import Flask
from config import DevConfig

app = Flask(__name__)
app.config.from_object(DevConfig)

@app.route('/')
def home():
    return '<h1>Hello World!</h1>'

if __name__ == '__main__':
    app.run()
```

对于熟悉基本 Flask API 的人来说，这个程序非常基础。如果我们导航到`http://127.0.0.1:5000/`，它只会在浏览器上显示`Hello World!`。对于 Flask 用户可能不熟悉的一点是`config.from_object`，而不是`app.config['DEBUG']`。我们使用`from_object`是因为将来会使用多个配置，并且在需要在配置之间切换时手动更改每个变量是很繁琐的。

记得在 Git 中提交这些更改：

```py
# The --all flag will tell git to stage all changes you have made
# including deletions and new files
$ git add --all
$ git commit -m "created the base application"

```

### 注意

不再提醒何时将更改提交到 Git。读者需要养成在达到一个停顿点时提交的习惯。还假定您将在虚拟环境中操作，因此所有命令行提示都不会以`(env)`为前缀。

## 使用 Flask Script

为了使读者更容易理解接下来的章节，我们将使用第一个**Flask 扩展**（扩展 Flask 功能的软件包）之一，名为**Flask Script**。Flask Script 允许程序员创建在 Flask 的**应用上下文**中操作的命令，即 Flask 中允许修改`Flask`对象的状态。Flask Script 带有一些默认命令来在应用上下文中运行服务器和 Python shell。要使用`pip`安装 Flask Script，请运行以下命令：

```py
$ pip install flask-script

```

我们将在第十章中涵盖 Flask Script 的更高级用法；现在，让我们从一个名为`manage.py`的简单脚本开始。首先按照以下方式导入 Flask Script 的对象和你的应用程序：

```py
from flask.ext.script import Manager, Server
from main import app
```

然后，将您的应用程序传递给`Manager`对象，它将初始化 Flask Script：

```py
manager = Manager(app)
```

现在我们添加我们的命令。服务器与通过`main.py`运行的普通开发服务器相同。`make_shell_context`函数将创建一个可以在应用上下文中运行的 Python shell。返回的字典将告诉 Flask Script 默认要导入什么：

```py
manager.add_command("server", Server())

@manager.shell
def make_shell_context():
    return dict(app=app)
```

### 注意

通过`manage.py`运行 shell 将在稍后变得必要，因为当 Flask 扩展只有在创建 Flask 应用程序时才会初始化时。运行默认的 Python shell 会导致这些扩展返回错误。

然后，以 Python 标准的方式结束文件，只有当用户运行了这个文件时才会运行：

```py
if __name__ == "__main__":
    manager.run()
```

现在您可以使用以下命令运行开发服务器：

```py
$ python manage.py server

```

使用以下命令运行 shell：

```py
$ python manage.py shell
# Lets check if our app imported correctly
>>> app
<Flask 'main'>

```

# 摘要

现在我们已经设置好了开发环境，我们可以继续在 Flask 中实现高级应用程序功能。在我们可以做任何可视化之前，我们需要有东西来显示。在下一章中，您将被介绍并掌握在 Flask 中使用数据库。


# 第二章：使用 SQLAlchemy 创建模型

如前所述，**模型**是一种抽象和给数据提供一个通用接口的方式。在大多数 Web 应用程序中，数据存储和检索是通过**关系数据库管理系统**（**RDBMS**）进行的，这是一个以行和列的表格格式存储数据并能够在表格之间比较数据的数据库。一些例子包括 MySQL，Postgres，Oracle 和 MSSQL。

为了在我们的数据库上创建模型，我们将使用一个名为**SQLAlchemy**的 Python 包。SQLAlchemy 在其最低级别是一个数据库 API，并在其最高级别执行**对象关系映射**（**ORM**）。ORM 是一种在不同类型的系统和数据结构之间传递和转换数据的技术。在这种情况下，它将数据库中大量类型的数据转换为 Python 中类型和对象的混合。此外，像 Python 这样的编程语言允许您拥有不同的对象，这些对象相互引用，并获取和设置它们的属性。ORM，如 SQLAlchemy，有助于将其转换为传统数据库。

为了将 SQLAlchemy 与我们的应用程序上下文联系起来，我们将使用 Flask SQLAlchemy。Flask SQLAlchemy 是 SQLAlchemy 的一个便利层，提供了有用的默认值和特定于 Flask 的函数。如果您已经熟悉 SQLAlchemy，那么您可以在没有 Flask SQLAlchemy 的情况下自由使用它。

在本章结束时，我们将拥有一个完整的博客应用程序的数据库架构，以及与该架构交互的模型。

# 设置 SQLAlchemy

为了在本章中跟进，如果您还没有运行的数据库，您将需要一个。如果您从未安装过数据库，或者您没有偏好，SQLite 是初学者的最佳选择。

**SQLite**是一种快速的 SQL，无需服务器即可工作，并且完全包含在一个文件中。此外，SQLite 在 Python 中有原生支持。如果您选择使用 SQLite，将在*我们的第一个模型*部分为您创建一个 SQLite 数据库。

## Python 包

要使用`pip`安装 Flask SQLAlchemy，请运行以下命令：

```py
$ pip install flask-sqlalchemy

```

我们还需要安装特定的数据库包，用于作为 SQLAlchemy 的连接器。SQLite 用户可以跳过此步骤：

```py
# MySQL
$ pip install PyMySQL
# Postgres
$ pip install psycopg2
# MSSQL
$ pip install pyodbc
# Oracle
$ pip install cx_Oracle

```

## Flask SQLAlchemy

在我们可以抽象化我们的数据之前，我们需要设置 Flask SQLAlchemy。SQLAlchemy 通过特殊的数据库 URI 创建其数据库连接。这是一个看起来像 URL 的字符串，包含 SQLAlchemy 连接所需的所有信息。它的一般形式如下：

```py
databasetype+driver://user:password@ip:port/db_name
```

对于您之前安装的每个驱动程序，URI 将是：

```py
# SQLite
sqlite:///database.db
# MySQL
mysql+pymysql://user:password@ip:port/db_name
# Postgres
postgresql+psycopg2://user:password@ip:port/db_name
# MSSQL
mssql+pyodbc://user:password@dsn_name
# Oracle
oracle+cx_oracle://user:password@ip:port/db_name
```

在我们的`config.py`文件中，使用以下方式将 URI 添加到`DevConfig`文件中：

```py
class DevConfig(Config):
    debug = True
    SQLALCHEMY_DATABASE_URI = "YOUR URI"
```

# 我们的第一个模型

您可能已经注意到，我们实际上没有在我们的数据库中创建任何表来进行抽象。这是因为 SQLAlchemy 允许我们从表中创建模型，也可以从我们的模型中创建表。这将在我们创建第一个模型后进行介绍。

在我们的`main.py`文件中，必须首先使用以下方式初始化 SQLAlchemy：

```py
from flask.ext.sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config.from_object(DevConfig)
db = SQLAlchemy(app)

```

SQLAlchemy 将读取我们应用程序的配置，并自动连接到我们的数据库。让我们在`main.py`文件中创建一个`User`模型，以与用户表进行交互：

```py
class User(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(255))
    password = db.Column(db.String(255))

    def __init__(self, username):
        self.username = username

    def __repr__(self):
        return "<User '{}'>".format(self.username)
```

我们取得了什么成就？我们现在有一个基于用户表的模型，有三列。当我们从`db.Model`继承时，与数据库的整个连接和通信将已经为我们处理。

每个`db.Column`实例的类变量代表数据库中的一列。`db.Column`实例中有一个可选的第一个参数，允许我们指定数据库中列的名称。如果没有，SQLAlchemy 会假定变量的名称与列的名称相同。使用这个可选变量会看起来像这样：

```py
username = db.Column('user_name', db.String(255))
```

`db.Column`的第二个参数告诉 SQLAlchemy 应将该列视为什么类型。本书中我们将使用的主要类型是：

+   `db.String`

+   `db.Text`

+   `db.Integer`

+   `db.Float`

+   `db.Boolean`

+   `db.Date`

+   `db.DateTime`

+   `db.Time`

每种类型代表的含义都相当简单。`String`和`Text`类型接受 Python 字符串并将它们分别转换为`varchar`和`text`类型的列。`Integer`和`Float`类型接受任何 Python 数字并在将它们插入数据库之前将它们转换为正确的类型。布尔类型接受 Python 的`True`或`False`语句，并且如果数据库有`boolean`类型，则将布尔值插入数据库。如果数据库中没有`boolean`类型，SQLAlchemy 会自动在 Python 布尔值和数据库中的 0 或 1 之间进行转换。`Date`、`DateTime`和`Time`类型使用`datetime`本地库中同名的 Python 类型，并将它们转换为数据库中的类型。`String`、`Integer`和`Float`类型接受一个额外的参数，告诉 SQLAlchemy 我们列的长度限制。

### 注意

如果您希望真正了解 SQLAlchemy 如何将您的代码转换为 SQL 查询，请将以下内容添加到`DevConfig`文件中：

```py
SQLALCHMEY_ECHO = True
```

这将在终端上打印出创建的查询。随着您在本书中的进展，您可能希望关闭此功能，因为每次加载页面时可能会打印出数十个查询。

参数`primary_key`告诉 SQLAlchemy 该列具有**主键索引**。每个 SQLAlchemy 模型*都需要*一个主键才能正常工作。

SQLAlchemy 将假定您的表名是模型类名的小写版本。但是，如果我们希望我们的表被称为除了*users*之外的其他名称呢？要告诉 SQLAlchemy 使用什么名称，请添加`__tablename__`类变量。这也是连接到已经存在于数据库中的表的方法。只需将表的名称放在字符串中。

```py
class User(db.Model):
    __tablename__ = 'user_table_name'

    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(255))
    password = db.Column(db.String(255))
```

我们不必包含`__init__`或`__repr__`函数。如果不包含，那么 SQLAlchemy 将自动创建一个接受列的名称和值作为关键字参数的`__init__`函数。

## 创建用户表

使用 SQLAlchemy 来完成繁重的工作，我们现在将在数据库中创建用户表。更新`manage.py`为：

```py
from main import app, db, User
...
@manager.shell
def make_shell_context():
    return dict(app=app, db=db, User=User)

Style - "db","User" in first line as Code Highlight
```

### 提示

从现在开始，每当我们创建一个新模型时，导入它并将其添加到返回的`dict`中。

这将允许我们在 shell 中使用我们的模型。现在运行 shell 并使用`db.create_all()`来创建所有表：

```py
$ python manage.py shell
>>> db.create_all()

```

现在您应该在数据库中看到一个名为`users`的表以及指定的列。此外，如果您使用 SQLite，您现在应该在文件结构中看到一个名为`database.db`的文件。

# CRUD

对于数据的每种存储机制，都有四种基本类型的函数：**创建、读取、更新和删除**（**CRUD**）。这些允许我们使用的所有基本方式来操作和查看我们的 Web 应用程序所需的数据。要使用这些函数，我们将在数据库上使用一个名为**session**的对象。会话将在本章后面进行解释，但现在，将其视为我们对数据库的所有更改的存储位置。

## 创建模型

要使用我们的模型在数据库中创建新行，请将模型添加到`session`和`commit`对象中。将对象添加到会话中标记其更改以进行保存，并且提交是将会话保存到数据库中的时候：

```py
>>> user = User(username='fake_name')
>>> db.session.add(user)
>>> db.session.commit()

```

向我们的表中添加新行非常简单。

## 读取模型

在向数据库添加数据后，可以使用`Model.query`来查询数据。对于使用 SQLAlchemy 的人来说，这是`db.session.query(Model)`的简写。

对于我们的第一个示例，使用`all()`来获取数据库中的所有行作为列表。

```py
>>> users = User.query.all()
>>> users
[<User 'fake_name'>]

```

当数据库中的项目数量增加时，此查询过程变得更慢。在 SQLAlchmey 中，与 SQL 一样，我们有限制功能来指定我们希望处理的总行数。

```py
>>> users = User.query.limit(10).all()

```

默认情况下，SQLAlchemy 返回按其主键排序的记录。要控制这一点，我们有 `order_by` 函数，它的用法是：

```py
# asending
>>> users = User.query.order_by(User.username).all()
# desending
>>> users = User.query.order_by(User.username.desc()).all()

```

要返回一个模型，我们使用 `first()` 而不是 `all()`：

```py
>>> user = User.query.first()
>>> user.username
fake_name

```

要通过其主键返回一个模型，使用 `query.get()`：

```py
>>> user = User.query.get(1)
>>> user.username
fake_name

```

所有这些函数都是可链式调用的，这意味着它们可以附加到彼此以修改返回结果。精通 JavaScript 的人会发现这种语法很熟悉。

```py
>>> users = User.query.order_by(
 User.username.desc()
 ).limit(10).first()

```

`first()` 和 `all()` 方法返回一个值，因此结束了链式调用。

还有一个特定于 Flask SQLAlchemy 的方法叫做 **pagination**，可以用来代替 `first()` 或 `all()`。这是一个方便的方法，旨在启用大多数网站在显示长列表项目时使用的分页功能。第一个参数定义了查询应该返回到哪一页，第二个参数是每页的项目数。因此，如果我们传递 1 和 10 作为参数，将返回前 10 个对象。如果我们传递 2 和 10，将返回对象 11-20，依此类推。

分页方法与 `first()` 和 `all()` 方法不同，因为它返回一个分页对象而不是模型列表。例如，如果我们想要获取博客中虚构的 `Post` 对象的第一页的前 10 个项目：

```py
>>> Post.query.paginate(1, 10)
<flask_sqlalchemy.Pagination at 0x105118f50>

```

这个对象有几个有用的属性：

```py
>>> page = User.query.paginate(1, 10)
# return the models in the page
>>> page.items
[<User 'fake_name'>]
# what page does this object represent
>>> page.page
1
# How many pages are there
>>> page.pages
1
# are there enough models to make the next or previous page
>>> page.has_prev, page.has_next
(False, False)
# return the next or previous page pagination object
# if one does not exist returns the current page
>>> page.prev(), page.next()
(<flask_sqlalchemy.Pagination at 0x10812da50>,
 <flask_sqlalchemy.Pagination at 0x1081985d0>)

```

### 过滤查询

现在我们来到了 SQL 的真正威力，即通过一组规则过滤结果。要获取满足一组相等条件的模型列表，我们使用 `query.filter_by` 过滤器。`query.filter_by` 过滤器接受命名参数，这些参数代表我们在数据库中每一列中寻找的值。要获取所有用户名为 `fake_name` 的用户列表：

```py
>>> users = User.query.filter_by(username='fake_name').all()

```

这个例子是在一个值上进行过滤，但多个值可以传递给 `filter_by` 过滤器。就像我们之前的函数一样，`filter_by` 是可链式调用的：

```py
>>> users = User.query.order_by(User.username.desc())
 .filter_by(username='fake_name')
 .limit(2)
 .all()

```

`query.filter_by` 只有在你知道你要查找的确切值时才有效。这可以通过将 Python 比较语句传递给 `query.filter` 来避免：

```py
>>> user = User.query.filter(
 User.id > 1
 ).all()

```

这是一个简单的例子，但 `query.filter` 接受任何 Python 比较。对于常见的 Python 类型，比如 `整数`、`字符串` 和 `日期`，可以使用 `==` 运算符进行相等比较。如果有一个 `整数`、`浮点数` 或 `日期` 列，也可以使用 `>`、`<`、`<=` 和 `>=` 运算符传递不等式语句。

我们还可以使用 SQLAlchemy 函数来转换复杂的 SQL 查询。例如，使用 `IN`、`OR` 或 `NOT` SQL 比较：

```py
>>> from sqlalchemy.sql.expression import not_, or_
>>> user = User.query.filter(
 User.username.in_(['fake_name']),
 User.password == None
 ).first()
# find all of the users with a password
>>> user = User.query.filter(
 not_(User.password == None)
 ).first()
# all of these methods are able to be combined
>>> user = User.query.filter(
 or_(not_(User.password == None), User.id >= 1)
 ).first()

```

在 SQLAlchemy 中，与 `None` 的比较会被转换为与 `NULL` 的比较。

## 更新模型

要更新已经存在的模型的值，将 `update` 方法应用到查询对象上，也就是说，在你使用 `first()` 或 `all()` 等方法返回模型之前：

```py
>>> User.query.filter_by(username='fake_name').update({
 'password': 'test'
 })
# The updated models have already been added to the session
>>> db.session.commit()

```

## 删除模型

如果我们希望从数据库中删除一个模型：

```py
>>> user = User.query.filter_by(username='fake_name').first()
>>> db.session.delete(user)
>>> db.session.commit()

```

# 模型之间的关系

SQLAlchemy 中模型之间的关系是两个或多个模型之间的链接，允许模型自动引用彼此。这允许自然相关的数据，比如 *评论到帖子*，可以轻松地从数据库中检索其相关数据。这就是关系型数据库管理系统中的 *R*，它赋予了这种类型的数据库大量的能力。

让我们创建我们的第一个关系。我们的博客网站将需要一些博客文章。每篇博客文章将由一个用户撰写，因此将博客文章链接回撰写它们的用户是很有意义的，可以轻松地获取某个用户的所有博客文章。这是一个 **一对多** 关系的例子。

## 一对多

让我们添加一个模型来代表我们网站上的博客文章：

```py
class Post(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    title = db.Column(db.String(255))
    text = db.Column(db.Text())
    publish_date = db.Column(db.DateTime())
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'))

    def __init__(self, title):
        self.title = title

    def __repr__(self):
        return "<Post '{}'>".format(self.title)
```

请注意`user_id`列。熟悉 RDBMS 的人会知道这代表**外键约束**。外键约束是数据库中的一条规则，强制`user_id`的值存在于用户表中的`id`列中。这是数据库中的一个检查，以确保`Post`始终引用现有用户。`db.ForeignKey`的参数是`user_id`字段的字符串表示。如果决定用`__table_name__`来命名用户表，必须更改此字符串。在初始化 SQLAlchemy 时，使用此字符串而不是直接引用`User.id`，因为`User`对象可能尚不存在。

`user_id`列本身不足以告诉 SQLAlchemy 我们有一个关系。我们必须修改我们的`User`模型如下：

```py
class User(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(255))
    password = db.Column(db.String(255))
    posts = db.relationship(
        'Post',
        backref='user',
        lazy='dynamic'
    )
```

`db.relationship`函数在 SQLAlchemy 中创建一个虚拟列，与我们的`Post`模型中的`db.ForeignKey`相连接。第一个参数是我们引用的类的名称。我们很快就会介绍`backref`的作用，但`lazy`参数是什么？`lazy`参数控制 SQLAlchemy 如何加载我们的相关对象。`subquery`会在加载我们的`Post`对象时立即加载我们的关系。这减少了查询的数量，但当返回的项目数量增加时，速度会变慢。相比之下，使用`dynamic`选项，相关对象将在访问时加载，并且可以在返回之前进行筛选。如果返回的对象数量很大或将变得很大，这是最好的选择。

我们现在可以访问`User.posts`变量，它将返回所有`user_id`字段等于我们的`User.id`的帖子的列表。让我们在 shell 中尝试一下：

```py
>>> user = User.query.get(1)
>>> new_post = Post('Post Title')
>>> new_post.user_id = user.id
>>> user.posts
[]
>>> db.session.add(new_post)
>>> db.session.commit()
>>> user.posts
[<Post 'Post Title'>]

```

请注意，如果没有将更改提交到数据库，我们将无法访问我们的关系中的帖子。

`backref`参数使我们能够通过`Post.user`访问和设置我们的`User`类。这是由以下给出的：

```py
>>> second_post = Post('Second Title')
>>> second_post.user = user
>>> db.session.add(second_post)
>>> db.session.commit()
>>> user.posts
[<Post 'Post Title'>, <Post 'Second Title'>]

```

因为`user.posts`是一个列表，我们也可以将我们的`Post`模型添加到列表中以自动保存它：

```py
>>> second_post = Post('Second Title')
>>> user.posts.append(second_post)
>>> db.session.add(user)
>>> db.session.commit()
>>> user.posts
[<Post 'Post Title'>, <Post 'Second Title'>]

```

使用`backref`选项作为 dynamic，我们可以将我们的关系列视为查询以及列表：

```py
>>> user.posts
[<Post 'Post Title'>, <Post 'Second Title'>]
>>> user.posts.order_by(Post.publish_date.desc()).all()
[<Post 'Second Title'>, <Post 'Post Title'>]

```

在我们继续下一个关系类型之前，让我们为用户评论添加另一个模型，它具有一对多的关系，稍后将在书中使用：

```py
class Post(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    title = db.Column(db.String(255))
    text = db.Column(db.Text())
    publish_date = db.Column(db.DateTime())
    comments = db.relationship(
        'Comment',
        backref='post',
        lazy='dynamic'
    )
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'))

    def __init__(self, title):
        self.title = title

    def __repr__(self):
        return "<Post '{}'>".format(self.title)

class Comment(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(255))
    text = db.Column(db.Text())
    date = db.Column(db.DateTime())
    post_id = db.Column(db.Integer(), db.ForeignKey('post.id'))

    def __repr__(self):
        return "<Comment '{}'>".format(self.text[:15])
```

## 多对多

如果我们有两个可以相互引用的模型，但每个模型都需要引用每种类型的多个模型，该怎么办？例如，我们的博客帖子将需要标签，以便我们的用户可以轻松地将相似的帖子分组。每个标签可以指向多个帖子，但每个帖子可以有多个标签。这种类型的关系称为**多对多**关系。考虑以下示例：

```py
tags = db.Table('post_tags',
    db.Column('post_id', db.Integer, db.ForeignKey('post.id')),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'))
)

class Post(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    title = db.Column(db.String(255))
    text = db.Column(db.Text())
    publish_date = db.Column(db.DateTime())
    comments = db.relationship(
        'Comment',
        backref='post',
        lazy='dynamic'
    )
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'))
    tags = db.relationship(
        'Tag',
        secondary=tags,
        backref=db.backref('posts', lazy='dynamic')
    )

    def __init__(self, title):
        self.title = title

    def __repr__(self):
        return "<Post '{}'>".format(self.title)

class Tag(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    title = db.Column(db.String(255))

    def __init__(self, title):
        self.title = title

    def __repr__(self):
        return "<Tag '{}'>".format(self.title)
```

`db.Table`对象是对数据库的低级访问，比`db.Model`的抽象更低。`db.Model`对象建立在`db.Table`之上，并提供了表中特定行的表示。使用`db.Table`对象是因为不需要访问表的单个行。

`tags`变量用于表示`post_tags`表，其中包含两行：一行表示帖子的 id，另一行表示标签的 id。为了说明这是如何工作的，如果表中有以下数据：

```py
post_id   tag_id
1         1
1         3
2         3
2         4
2         5
3         1
3         2
```

SQLAlchemy 会将其转换为：

+   id 为`1`的帖子具有 id 为`1`和`3`的标签

+   id 为`2`的帖子具有 id 为`3`、`4`和`5`的标签

+   id 为`3`的帖子具有 id 为`1`和`2`的标签

您可以将这些数据描述为与帖子相关的标签。

在`db.relationship`函数设置我们的关系之前，但这次它有 secondary 参数。secondary 参数告诉 SQLAlchemy 这个关系存储在 tags 表中。让我们看看下面的代码：

```py
>>> post_one = Post.query.filter_by(title='Post Title').first()
>>> post_two = Post.query.filter_by(title='Second Title').first()
>>> tag_one = Tag('Python')
>>> tag_two = Tag('SQLAlchemy')
>>> tag_three = Tag('Flask')
>>> post_one.tags = [tag_two]
>>> post_two.tags = [tag_one, tag_two, tag_three]
>>> tag_two.posts
[<Post 'Post Title'>, <Post 'Second Title'>]
>>> db.session.add(post_one)
>>> db.session.add(post_two)
>>> db.session.commit()

```

在一对多关系中，主关系列只是一个列表。主要区别在于`backref`选项现在也是一个列表。因为它是一个列表，我们可以从`tag`对象中向标签添加帖子，如下所示：

```py
>>> tag_one.posts.append(post_one)
[<Post 'Post Title'>, <Post 'Second Title'>]
>>> post_one.tags
[<Tag 'SQLAlchemy'>, <Tag 'Python'>]
>>> db.session.add(tag_one)
>>> db.session.commit()

```

# SQLAlchemy 会话的便利性

现在您了解了 SQLAlchemy 的强大之处，也可以理解 SQLAlchemy 会话对象是什么，以及为什么 Web 应用程序不应该没有它们。正如之前所述，会话可以简单地描述为一个跟踪我们模型更改并在我们告诉它时将它们提交到数据库的对象。但是，它比这更复杂一些。

首先，会话是**事务**的处理程序。事务是在提交时刷新到数据库的一组更改。事务提供了许多隐藏的功能。例如，当对象具有关系时，事务会自动确定哪些对象将首先保存。您可能已经注意到了，在上一节中保存标签时。当我们将标签添加到帖子中时，会话自动知道首先保存标签，尽管我们没有将其添加到提交。如果我们使用原始 SQL 查询和数据库连接，我们将不得不跟踪哪些行与其他行相关，以避免保存对不存在的对象的外键引用。

事务还会在将对象的更改保存到数据库时自动将数据标记为陈旧。当我们下次访问对象时，将向数据库发出查询以更新数据，但所有这些都是在后台进行的。如果我们不使用 SQLAlchemy，我们还需要手动跟踪需要更新的行。如果我们想要资源高效，我们只需要查询和更新那些行。

其次，会话使得不可能存在对数据库中同一行的两个不同引用。这是通过所有查询都经过会话来实现的（`Model.query`实际上是`db.session.query(Model)`），如果在此事务中已经查询了该行，则将返回指向该对象的指针，而不是一个新对象。如果没有这个检查，表示同一行的两个对象可能会以不同的更改保存到数据库中。这会产生微妙的错误，可能不会立即被发现。

请记住，Flask SQLAlchemy 为每个请求创建一个新会话，并在请求结束时丢弃未提交的任何更改，因此请记住保存您的工作。

### 注意

要深入了解会话，SQLAlchemy 的创建者 Mike Bayer 在 2012 年加拿大 PyCon 上发表了一次演讲。请参阅*SQLAlchemy 会话-深入*，链接在这里-[`www.youtube.com/watch?v=PKAdehPHOMo`](https://www.youtube.com/watch?v=PKAdehPHOMo)。

# 使用 Alembic 进行数据库迁移

Web 应用程序的功能性不断变化，随着新功能的增加，我们需要改变数据库的结构。无论是添加或删除新列，还是创建新表，我们的模型都会在应用程序的生命周期中发生变化。然而，当数据库经常发生变化时，问题很快就会出现。在将我们的更改从开发环境移动到生产环境时，如何确保您在没有手动比较每个模型及其相应表的情况下携带了每个更改？假设您希望回到 Git 历史记录中查看您的应用程序的早期版本是否存在与您现在在生产环境中遇到的相同错误。在没有大量额外工作的情况下，您将如何将数据库更改回正确的模式？

作为程序员，我们讨厌额外的工作。幸运的是，有一个名为**Alembic**的工具，它可以根据我们的 SQLAlchemy 模型的更改自动创建和跟踪数据库迁移。**数据库迁移**是我们模式的所有更改的记录。Alembic 允许我们将数据库升级或降级到特定的保存版本。通过几个版本的升级或降级将执行两个选定版本之间的所有文件。Alembic 最好的部分是它的历史文件只是 Python 文件。当我们创建我们的第一个迁移时，我们可以看到 Alembic 语法是多么简单。

### 注意

Alembic 并不捕获每一个可能的变化。例如，它不记录 SQL 索引的更改。在每次迁移之后，建议读者查看迁移文件并进行任何必要的更正。

我们不会直接使用 Alembic；相反，我们将使用**Flask-Migrate**，这是专门为 SQLAlchemy 创建的扩展，并与 Flask Script 一起使用。要使用`pip`安装它：

```py
$ pip install Flask-Migrate

```

要开始，我们需要将命令添加到我们的`manage.py`文件中，如下所示：

```py
from flask.ext.script import Manager, Server
from flask.ext.migrate import Migrate, MigrateCommand

from main import app, db, User, Post, Tag

migrate = Migrate(app, db)

manager = Manager(app)
manager.add_command("server", Server())
manager.add_command('db', MigrateCommand)

@manager.shell
def make_shell_context():
    return dict(app=app, db=db, User=User, Post=Post, Tag=Tag)

if __name__ == "__main__":
    manager.run()
```

我们使用我们的应用程序和我们的 SQLAlchemy 实例初始化了`Migrate`对象，并且通过`manage.py db`使迁移命令可调用。要查看可能的命令列表，请运行此命令：

```py
$ python manage.py db

```

要开始跟踪我们的更改，我们使用`init`命令如下：

```py
$ python manage.py db init

```

这将在我们的目录中创建一个名为`migrations`的新文件夹，其中将保存我们的所有历史记录。现在我们开始进行我们的第一个迁移：

```py
$ python manage.py  db migrate -m"initial migration"

```

这个命令将导致 Alembic 扫描我们的 SQLAlchemy 对象，并找到所有在此提交之前不存在的表和列。由于这是我们的第一个提交，迁移文件会相当长。一定要使用`-m`指定迁移消息，因为这是识别每个迁移在做什么的最简单方法。每个迁移文件都存储在`migrations/versions/`文件夹中。

要将迁移应用到您的数据库并更改模式，请运行以下命令：

```py
$ python manage.py db upgrade

```

要返回到以前的版本，使用`history`命令找到版本号，并将其传递给`downgrade`命令：

```py
$ python manage.py db history
<base> -> 7ded34bc4fb (head), initial migration
$ python manage.py db downgrade 7ded34bc4fb

```

就像 Git 一样，每个迁移都有一个哈希标记。这是 Alembic 的主要功能，但这只是表面层次。尝试将您的迁移与 Git 提交对齐，以便在还原提交时更容易降级或升级。

# 总结

现在我们已经掌握了数据控制，我们现在可以继续在我们的应用程序中显示我们的数据。下一章，第三章 *使用模板创建视图*，将动态地涵盖根据我们的模型创建基于 HTML 的视图，并从我们的 Web 界面添加模型。


# 第三章：使用模板创建视图

现在我们的数据以一种方便访问的格式呈现，将信息显示在网页上变得更加容易。在本章中，我们将使用 Flask Jinja 的包含模板语言，从我们的 SQLAlchemy 模型动态创建 HTML。我们还将研究 Jinja 的方法，自动创建 HTML 并修改数据以在模板内进行呈现。然后，本章将以使用 Jinja 自动创建和验证 HTML 表单结束。

# Jinja 的语法

**Jinja**是用 Python 编写的模板语言。**模板语言**是一种旨在帮助自动创建文档的简单格式。在任何模板语言中，传递给模板的变量将替换模板中预定义的位置。在 Jinja 中，变量替换由`{{}}`定义。`{{}}`语法称为**变量块**。还有由`{% %}`定义的**控制块**，它声明语言函数，如**循环**或`if`语句。例如，当从上一章传递给它的`Post`模型时，我们有以下 Jinja 代码：

```py
<h1>{{ post.title }}</h1>
```

这将产生以下结果：

```py
<h1>First Post</h1>
```

在 Jinja 模板中显示的变量可以是任何 Python 类型或对象，只要它们可以通过 Python 函数`str（）`转换为字符串。例如，传递给模板的字典或列表可以通过其属性显示：

```py
{{ your_dict['key'] }}
{{ your_list[0] }}
```

许多程序员更喜欢使用 JavaScript 来模板化和动态创建他们的 HTML 文档，以减轻服务器的 HTML 渲染负载。本章不会涵盖这个话题，因为这是一个高级的 JavaScript 话题。然而，许多 JavaScript 模板引擎也使用`{{}}`语法。如果您选择将 Jinja 和在 HTML 文件中定义的 JavaScript 模板结合在一起，则将 JavaScript 模板包装在`raw`控制块中，以告诉 Jinja 忽略它们：

```py
{% raw %}
<script id="template" type="text/x-handlebars-template">
    <h1>{{title}}</h1>
    <div class="body">
        {{body}}
    </div>
</script>
{% endraw %}
```

## 过滤器

认为 Jinja 和 Python 的语法是相同的是一个常见的错误，因为它们相似。然而，它们之间有很多不同之处。正如您将在本节中看到的，普通的 Python 函数实际上并不存在。相反，在 Jinja 中，变量可以传递给修改变量以供显示目的的内置函数。这些函数，称为过滤器，使用管道字符`|`在变量块中调用：

```py
{{ variable | filter_name(*args) }}
```

否则，如果没有向过滤器传递参数，则可以省略括号，如下所示：

```py
{{ variable | filter_name }}
```

过滤器也可以被称为控制块，以将它们应用于文本块：

```py
{% filter filter_name %}
    A bunch of text
{% endfilter %}
```

Jinja 中有许多过滤器；本书将仅涵盖最有用的过滤器。为了简洁起见，在每个示例中，每个过滤器的输出将直接列在过滤器本身下面。

### 注意

有关 Jinja 中所有默认过滤器的完整列表，请访问[`jinja.pocoo.org/docs/dev/templates/#list-of-builtin-filters`](http://jinja.pocoo.org/docs/dev/templates/#list-of-builtin-filters)。

### 默认

如果传递的变量是`None`，则将其替换为默认值，如下所示：

```py
{{ post.date | default('2015-01-01') }}
2015-01-01
```

如果您希望用默认值替换变量，并且如果变量求值为`False`，则将可选的第二个参数传递给`True`：

```py
{{ '' | default('An empty string', True) }}
An empty string
```

### 逃脱

如果传递的变量是 HTML 字符串，则将打印`&`，`<`，`>`，`'`和`"`字符作为 HTML 转义序列：

```py
{{ "<h1>Title</h1>" | escape }}
&#60;h1&#62;Title&#60;/h1&#62;
```

### float

这将使用 Python 的`float（）`函数将传递的值转换为浮点数，如下所示：

```py
{{ 75 | float }}
75.0
```

### 整数

这将使用 Python 的`int（）`函数将传递的值转换为整数，如下所示：

```py
{{ 75.7 | int }}
75
```

### 连接

这是一个使用字符串和字符串列表的元素连接的过滤器，与相同名称的`list`方法完全相同。它被给定为：

```py
{{ ['Python', 'SQLAlchemy'] | join(',') }}
Python, SQLAlchemy
```

### 长度

这是一个填充与 Python `len（）`函数相同作用的过滤器。它被给定为：

```py
Tag Count: {{ post.tags | length }}
Tag Count: 2
```

### 圆

这将四舍五入浮点数到指定的精度：

```py
{{ 3.141592653589793238462 | round(1) }}
3.1
```

您还可以指定要将数字舍入到的方式：

```py
{{ 4.7 | round(1, "common") }}
5
{{ 4.2 | round(1, "common") }}
4
{{ 4.7 | round(1, "floor") }}
4
{{ 4.2 | round(1, "ceil") }}
5
```

`common`选项像人一样四舍五入：大于或等于 0.5 的四舍五入，小于 0.5 的舍去。`floor`选项总是向下舍入数字，`ceil`选项总是向上舍入，不考虑小数。

### safe

如果你尝试从变量插入 HTML 到你的页面中，例如，当你希望显示一个博客文章时，Jinja 将自动尝试向输出添加 HTML 转义序列。看下面的例子：

```py
{{ "<h1>Post Title</h1>" }}
&lt;h1&gt;Post Title&lt;/h1&gt;
```

这是一个必要的安全功能。当应用程序具有允许用户提交任意文本的输入时，它允许恶意用户输入 HTML 代码。例如，如果用户提交一个脚本标签作为评论，而 Jinja 没有这个功能，该脚本将在访问页面的所有浏览器上执行。

然而，我们仍然需要一种方法来显示我们知道是安全的 HTML，比如我们博客文章的 HTML。我们可以使用`safe`过滤器来实现这一点，如下所示：

```py
{{ "<h1>Post Title</h1>" | safe }}
<h1>Post Title</h1>
```

### title

我们使用标题格式来大写字符串，如下所示：

```py
{{ "post title" | title }}
Post Title
```

### tojson

我们可以将变量传递给 Python 的`json.dumps`函数。请记住，你传递的对象必须是`json`模块可序列化的。

```py
{{ {'key': False, 'key2': None, 'key3': 45} | tojson }}
{key: false, key2: null, key3: 45}
```

这个功能最常用于在页面加载时将 SQLAlchemy 模型传递给 JavaScript MVC 框架，而不是等待 AJAX 请求。如果你以这种方式使用`tojson`，请记住也将结果传递给`safe`过滤器，以确保你的 JavaScript 中不会出现 HTML 转义序列。以下是一个使用`Backbone.js`的示例，这是一个流行的 JavaScript MVC 框架，包含了一系列模型：

```py
var collection = new PostCollection({{ posts | tojson | safe }});
```

### truncate

这将获取一个长字符串，并返回指定长度的字符串，并附加省略号：

```py
{{ "A Longer Post Body Than We Want" | truncate(10) }}
A Longer...
```

默认情况下，任何在中间被截断的单词都会被丢弃。要禁用这一点，作为额外参数传递`True`：

```py
{{ "A Longer Post Body Than We Want" | truncate(10, True) }}
A Longer P...
```

### 自定义过滤器

将自己的过滤器添加到 Jinja 中就像编写 Python 函数一样简单。为了理解自定义过滤器，我们将看一个例子。我们的简单过滤器将计算字符串中子字符串的出现次数并返回它。看下面的调用：

```py
{{ variable | filter_name("string") }}
```

这将被更改为：

```py
filter_name(variable, "string")
```

我们可以定义我们的过滤器如下：

```py
def count_substring(string, sub):
    return string.count(sub)
```

要将此功能添加到可用过滤器列表中，我们必须手动将其添加到`main.py`文件中`jinja_env`对象的`filters`字典中：

```py
app.jinja_env.filters['count_substring'] = count_substring
```

## 注释

模板中的注释由`{# #}`定义，将被 Jinja 忽略，并不会出现在返回的 HTML 代码中：

```py
{# Note to the maintainers of this code #}
```

## if 语句

Jinja 中的`if`语句类似于 Python 的`if`语句。任何返回或是布尔值的东西决定了代码的流程：

```py
{%if user.is_logged_in() %} 
    <a href='/logout'>Logout</a>
{% else %}
    <a href='/login'>Login</a>
{% endif %}
```

过滤器也可以用在`if`语句中：

```py
{% if comments | length > 0 %} 
    There are {{ comments | length }} comments
{% else %}
    There are no comments
{% endif %}
```

## 循环

我们可以在 Jinja 中使用循环来迭代任何列表或生成器函数：

```py
{% for post in posts %}
    <div>
        <h1>{{ post.title }}</h1>
        <p>{{ post.text | safe }}</p>
    </div>
{% endfor %}
```

循环和`if`语句可以结合使用，以模仿 Python 循环中的`break`功能。在这个例子中，只有当`post.text`不是`None`时，循环才会使用`post`：

```py
{% for post in posts if post.text %}
    <div>
        <h1>{{ post.title }}</h1>
        <p>{{ post.text | safe }}</p>
    </div>
{% endfor %}
```

在循环内，你可以访问一个名为`loop`的特殊变量，它可以让你访问有关`for`循环的信息。例如，如果我们想知道当前循环的当前索引以模拟 Python 中的`enumerate`函数，我们可以使用循环变量的索引变量，如下所示：

```py
{% for post in posts %}
    {{ loop.index }}. {{ post.title }}
{% endfor %}
```

这将产生以下输出：

```py
1\. Post Title
2\. Second Post
```

`loop`对象公开的所有变量和函数在下表中列出：

| 变量 | 描述 |
| --- | --- |
| `loop.index` | 循环的当前迭代（从 1 开始索引） |
| `loop.index0` | 循环的当前迭代（从 0 开始索引） |
| `loop.revindex` | 距离循环末尾的迭代次数（从 1 开始索引） |
| `loop.revindex0` | 距离循环末尾的迭代次数（从 0 开始索引） |
| `loop.first` | 如果当前项目是迭代器中的第一个，则为 True |
| `loop.last` | 如果当前项目是迭代器中的最后一个，则为 True |
| `loop.length` | 迭代器中的项目数 |
| `loop.cycle` | 用于在迭代器中循环的辅助函数，稍后会解释 |
| `loop.depth` | 表示递归循环中当前循环的深度（从级别 1 开始） |
| `loop.depth0` | 表示递归循环中当前循环的深度（从级别 0 开始） |

`cycle`函数是一个在每次循环时逐个遍历迭代器的函数。我们可以使用前面的示例来演示： 

```py
{% for post in posts %}
    {{ loop.cycle('odd', 'even') }} {{ post.title }} 
{% endfor %}
```

这将输出：

```py
odd Post Title
even Second Post
```

## 宏

**宏**最好理解为 Jinja 中返回模板或 HTML 字符串的函数。这用于避免重复的代码，并将其减少到一个函数调用。例如，以下是一个用于在模板中添加 Bootstrap CSS 输入和标签的宏：

```py
{% macro input(name, label, value='', type='text') %}
    <div class="form-group">
        <label for"{{ name }}">{{ label }}</label>
        <input type="{{ type }}" name="{{ name }}"
            value="{{ value | escape }}" class="form-control">
    </div>
{% endmacro %}
```

现在，要在任何模板中快速添加输入到表单，使用以下方式调用您的宏：

```py
{{ input('name', 'Name') }}
```

这将输出：

```py
<div class="form-group">
    <label for"name">Name</label>
    <input type="text" name="name" value="" class="form-control">
</div>
```

## Flask 特定的变量和函数

Flask 在模板中默认提供了几个函数和对象。

### config

Flask 在模板中提供了当前的`config`对象：

```py
{{ config.SQLALCHEMY_DATABASE_URI }}
sqlite:///database.db
```

### request

这是 Flask 的`request`对象，用于当前请求。

```py
{{ request.url }}
http://127.0.0.1/
```

### session

Flask 的`session`对象是：

```py
{{ session.new }}
True
```

### url_for()

`url_for`函数通过将路由函数名称作为参数返回路由的 URL。这允许更改 URL 而不必担心链接会断开。

```py
{{ url_for('home') }}
/
```

如果我们有一个在 URL 中有位置参数的路由，我们将它们作为`kwargs`传递。它们将在生成的 URL 中为我们填充：

```py
{{ url_for('post', post_id=1) }}
/post/1
```

### get_flashed_messages()

这将返回通过 Flask 中的`flash()`函数传递的所有消息的列表。`flash`函数是一个简单的函数，用于排队消息，这些消息只是 Python 字符串，供`get_flashed_messages`函数消耗。

```py
{% for message in get_flashed_messages() %}
    {{ message }}
{% endfor %}
```

# 创建我们的视图

要开始，我们需要在项目目录中创建一个名为`templates`的新文件夹。该文件夹将存储所有的 Jinja 文件，这些文件只是带有 Jinja 语法的 HTML 文件。我们的第一个模板将是我们的主页，它将是前 10 篇帖子的摘要列表。还将有一个用于显示帖子内容、页面上的评论、作者用户页面的链接和标签页面的链接的帖子视图。还将有用户和标签页面，显示用户的所有帖子和具有特定标签的所有帖子。每个页面还将有一个侧边栏，显示最近的五篇帖子和使用最多的五个标签。

## 视图函数

因为每个页面都会有相同的侧边栏信息，我们可以将其拆分为一个单独的函数，以简化我们的代码。在`main.py`文件中，添加以下代码：

```py
from sqlalchemy import func
...
def sidebar_data():
    recent = Post.query.order_by(
        Post.publish_date.desc()
    ).limit(5).all()
    top_tags = db.session.query(
        Tag, func.count(tags.c.post_id).label('total')
    ).join(
        tags
    ).group_by(Tag).order_by('total DESC').limit(5).all()

    return recent, top_tags
```

最近的帖子查询很直接，但最受欢迎的标签查询看起来有些熟悉，但有点奇怪。这有点超出了本书的范围，但使用 SQLAlchemy 的`func`库返回计数，我们可以按最常用的标签对标签进行排序。`func`函数在[`docs.sqlalchemy.org/en/rel_1_0/core/sqlelement.html#sqlalchemy.sql.expression.func`](http://docs.sqlalchemy.org/en/rel_1_0/core/sqlelement.html#sqlalchemy.sql.expression.func)中有详细说明。

`main.py`中的主页函数将需要一个分页对象中的所有帖子和侧边栏信息：

```py
from flask import Flask, render_template 
...
@app.route('/')
@app.route('/<int:page>')
def home(page=1):
    posts = Post.query.order_by(
        Post.publish_date.desc()
    ).paginate(page, 10)
    recent, top_tags = sidebar_data()

    return render_template(
        'home.html',
        posts=posts,
        recent=recent,
        top_tags=top_tags
    )
```

在这里，我们终于看到了 Flask 和 Jinja 是如何联系在一起的。Flask 函数`render_template`接受模板文件夹中的文件名，并将所有`kwargs`作为变量传递给模板。另外，我们的`home`函数现在有多个路由来处理分页，并且如果斜杠后面没有内容，将默认显示第一页。

现在您已经掌握了编写视图函数所需的所有知识，我挑战您尝试根据前面的描述编写其余的视图函数。尝试后，将您的结果与以下内容进行比较：

```py
@app.route('/post/<int:post_id>')
def post(post_id):
    post = Post.query.get_or_404(post_id)
    tags = post.tags
    comments = post.comments.order_by(Comment.date.desc()).all()
    recent, top_tags = sidebar_data()

    return render_template(
        'post.html',
        post=post,
        tags=tags,
        comments=comments,
        recent=recent,
        top_tags=top_tags
    )

@app.route('/tag/<string:tag_name>')
def tag(tag_name):
    tag = Tag.query.filter_by(title=tag_name).first_or_404()
    posts = tag.posts.order_by(Post.publish_date.desc()).all()
    recent, top_tags = sidebar_data()

    return render_template(
        'tag.html',
        tag=tag,
        posts=posts,
        recent=recent,
        top_tags=top_tags
    )

@app.route('/user/<string:username>')
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = user.posts.order_by(Post.publish_date.desc()).all()
    recent, top_tags = sidebar_data()
    return render_template(
        'user.html',
        user=user,
        posts=posts,
        recent=recent,
        top_tags=top_tags
    )
```

在编写所有视图之后，唯一剩下的事情就是编写模板。

## 编写模板和继承

因为本书不专注于界面设计，我们将使用 CSS 库 Bootstrap，并避免编写自定义 CSS。如果你以前没有使用过，**Bootstrap**是一组默认的 CSS 规则，可以使你的网站在所有浏览器上运行良好，并具有工具，可以轻松控制网站的布局。要下载 Bootstrap，转到[`getbootstrap.com/`](http://getbootstrap.com/)，点击**下载 Bootstrap**按钮。再点击另一个按钮**下载 Bootstrap**，你将开始下载一个 Zip 文件。将此文件解压缩到你的项目目录，并将文件夹重命名为`static`。`static`文件夹必须与`main.py`文件在同一目录级别，Flask 才能自动找到这些文件。从现在开始，我们将在这里保存我们的 CSS、字体、图像和 JavaScript 文件。

因为每个路由都将有一个分配给它的模板，每个模板都需要具有我们的元信息、样式表、常用 JavaScript 库等的必需 HTML **样板**代码。为了保持我们的模板**DRY**（**不要重复自己**），我们将使用 Jinja 最强大的功能之一，模板继承。**模板继承**是指子模板可以导入基础模板作为起点，并只替换基础模板中标记的部分。要开始我们的基础模板，我们需要一个基本的 HTML 骨架如下：

```py
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial- scale=1">
  <title>{% block title %}Blog{% endblock %}</title>
  <link rel="stylesheet" href="{{ url_for('static', filename='css/bootstrap.min.css') }}">
</head>
<body>
  <div class="container">
    <div class="jumbotron">
      <h1><a href="{{ url_for('home') }}">My Blog</a></h1>
        <p>Welcome to the blog!</p>
    </div>
    {% block body %}
    {% endblock %}
  </div>

  <script src="img/jquery.min.js') }}">></script>
  <script src="img/bootstrap.min.js') }}">></script>
</body>
</html>
```

将其保存为`base.html`在你的`templates`目录中。`block`控制块在继承中用于标记可以由子模板替换的部分。因为我们将在几个不同的页面中使用分页，让我们创建一个宏来渲染一个分页小部件：

```py
{% macro render_pagination(pagination, endpoint) %}
  <nav>
    <ul class="pagination">
      <li>
        <a href="{{ url_for('home', page=pagination.prev().page) }}" aria-label="Previous">
          <span aria-hidden="true">&laquo;</span>
        </a>
      </li>
      {% for page in pagination.iter_pages() %}
        {% if page %}
          {% if page != pagination.page %}
            <li>
              <a href="{{ url_for(endpoint, page=page) }}">
                {{ page }}
              </a>
            </li>
          {% else %}
            <li><a href="">{{ page }}</a></li>
          {% endif %}
        {% else %}
          <li><a>…</a><li>
        {% endif %}
      {% endfor %}
      <li>
        <a href="{{ url_for('home', page=pagination.next().page) }}" aria-label="Next">
          <span aria-hidden="true">&raquo;</span>
        </a>
      </li>
    </ul>
  </nav>
{% endmacro %}
```

这个宏接受一个 Flask SQLAlchemy 分页对象和一个视图函数名称，并构建一个 Bootstrap 页面链接列表。将其添加到`base.html`的顶部，以便所有从中继承的页面都可以访问它。

### 主页模板

要继承一个模板，使用`extends`控制块：

```py
{% extends "base.html" %}
{% block title %}Home{% endblock %}
```

这个模板将使用所有 HTML `base.html`，但替换`title`块中的数据。如果我们不声明一个`title`块，`base.html`中的内容将保持不变。将此模板保存为`index.html`。现在我们可以看到它的效果。在浏览器中打开`http://127.0.0.1:5000/`，你应该会看到以下内容：

![主页模板](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_03_01.jpg)

在这一点上，如果你有代表性的假数据，开发和模拟 UI 会更容易。因为我们只有两篇文章，手动从命令行添加大量模型是繁琐的（我们将在第十章中解决这个问题，*有用的 Flask 扩展*），让我们使用以下脚本添加 100 个示例文章：

```py
import random
import datetime

user = User.query.get(1)

tag_one = Tag('Python')
tag_two = Tag('Flask')
tag_three = Tag('SQLAlechemy')
tag_four = Tag('Jinja')
tag_list = [tag_one, tag_two, tag_three, tag_four]

s = "Example text"

for i in xrange(100):
    new_post = Post("Post " + str(i))
    new_post.user = user
    new_post.publish_date = datetime.datetime.now()
    new_post.text = s
    new_post.tags = random.sample(tag_list, random.randint(1, 3))
    db.session.add(new_post)

db.session.commit()
```

这个脚本是一个简单的循环，设置一个新文章的所有属性，并随机确定文章的标签。现在，为了认真地开发我们的模板，我们将从主页开始添加以下内容：博客文章的摘要和链接，最近的博客文章，以及最常用的标签。

现在，让我们将内容添加到`home.html`中：

```py
{% block body %}
<div class="row">
  <div class="col-lg-9">
    {% for post in posts.items %}
    <div class="row">
      <div class="col-lg-12">
        <h1>{{ post.title }}</h1>
      </div>
    </div>
    <div class="row">
      <div class="col-lg-12">
        {{ post.text | truncate(255) | safe }}
        <a href="{{
          url_for('posts', post_id=post.id)
          }}">Read More</a>
      </div>
    </div>
    {% endfor %}
  </div>
  <div class="col-lg-3">
    <div class="row">
      <h5>Recent Posts</h5>
      <ul>
        {% for post in recent %}
        <li><a href="{{
          url_for('post', post_id=post.id)
          }}">{{ post.title }}</a></li>
        {% endfor %}
      </ul>
    </div>
    <div class="row">
      <h5>Popular Tags</h5>
      <ul>
        {% for tag in top_tags %}
        <li><a href="{{ url_for('tag', tag_name=tag[0].title) }}">{{ tag[0].title }}</a></li>
        {% endfor %}
      </ul>
    </div>
  </div>
</div>
{% endblock %}
```

所有其他页面将采用这种中间内容一般形式，侧边栏链接到热门内容。

### 编写其他模板

现在你已经了解了继承的各个方面，也知道了哪些数据将会放到每个模板中，我将提出与上一节相同的挑战。尝试编写剩余模板的内容部分。完成后，你应该能够自由地浏览你的博客，点击文章并查看用户页面。在本章中还有一个最后的功能要添加——读者添加评论的能力。

# Flask WTForms

在应用程序中添加表单似乎是一项简单的任务，但当您开始编写服务器端代码时，随着表单变得更加复杂，验证用户输入的任务变得越来越大。安全性至关重要，因为数据来自不可信任的来源，并将被输入到数据库中。**WTForms**是一个库，通过检查输入与常见表单类型进行验证，来处理服务器端表单验证。Flask WTForms 是在 WTForms 之上的 Flask 扩展，它添加了功能，如 Jinja HTML 渲染，并保护您免受**SQL 注入**和**跨站请求伪造**等攻击。要安装 Flask WTForms 和 WTForms，我们有：

```py
$ pip install Flask-WTF

```

### 注意

保护自己免受 SQL 注入和跨站请求伪造是非常重要的，因为这些是您的网站将接收到的最常见的攻击形式。要了解更多关于这些攻击的信息，请访问[`en.wikipedia.org/wiki/SQL_injection`](https://en.wikipedia.org/wiki/SQL_injection)和[`en.wikipedia.org/wiki/Cross-site_request_forgery`](https://en.wikipedia.org/wiki/Cross-site_request_forgery)分别了解 SQL 注入和跨站请求伪造。

为了使 Flask WTForms 的安全措施正常工作，我们需要一个秘钥。**秘钥**是一个随机的字符串，将用于对需要进行真实性测试的任何内容进行加密签名。这不能是任何字符串；它必须是随机的，以避免削弱安全保护的强度。要生成一个随机字符串，请在 Bash 中输入以下内容：

```py
$ cat /dev/urandom | tr -cd 'a-f0-9' | head -c 32

```

如果您使用 Mac，请输入以下内容：

```py
cat /dev/urandom | env LC_CTYPE=C tr -cd 'a-f0-9' | head -c 32

```

在`Config`对象的`config.py`中添加输出：

```py
class Config(object):
    SECRET_KEY = 'Your key here'
```

## WTForms 基础

WTForms 有三个主要部分——**表单**、**字段**和**验证器**。字段是输入字段的表示，并进行基本的类型检查，验证器是附加到字段的函数，确保表单中提交的数据在我们的约束范围内。表单是一个包含字段和验证器的类，并在`POST`请求时对自身进行验证。让我们看看这个过程，以便更好地理解。在`main.py`文件中添加以下内容：

```py
from flask_wtf import Form
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired, Length
…
class CommentForm(Form):
    name = StringField(
        'Name',
        validators=[DataRequired(), Length(max=255)]
    )
    text = TextAreaField(u'Comment', validators=[DataRequired()])
```

这里我们有一个从 Flask WTForm 的`Form`对象继承的类，并使用等于 WTForm 字段的类变量定义输入。字段接受一个可选参数`validators`，这是一个将应用于我们数据的 WTForm 验证器列表。最常用的字段有：

+   `fields.DateField`

这代表了一个 Python `Date`对象，并接受一个可选参数格式，该格式采用`stftime`格式字符串来翻译数据。

+   `fields.IntegerField`

这尝试将传递的数据强制转换为整数，并在模板中呈现为数字输入。

+   `fields.FloatField`

这尝试将传递的数据强制转换为浮点数，并在模板中呈现为数字输入。

+   `fields.RadioField`

这代表了一组单选输入，并接受一个`choices`参数，即一个元组列表，作为显示值和返回值。

+   `fields.SelectField`

与`SelectMultipleField`一起，它代表一组单选输入。接受一个`choices`参数，即一个元组列表，作为显示值和返回值。

+   `fields.StringField`

这代表了一个普通的文本输入，并将尝试将返回的数据强制转换为字符串。

### 注意

有关验证器和字段的完整列表，请访问 WTForms 文档[`wtforms.readthedocs.org`](http://wtforms.readthedocs.org)。

最常用的验证器如下：

+   `validators.DataRequired()`

+   `validators.Email()`

+   `validators.Length(min=-1, max=-1)`

+   `validators.NumberRange(min=None, max=None)`

+   `validators.Optional()`

+   `validators.Regexp(regex)`

+   `validators.URL()`

这些验证都遵循 Python 的命名方案。因此，它们对于它们的功能是相当直接的。所有验证器都接受一个名为`message`的可选参数，这是验证器失败时将返回的错误消息。如果未设置消息，则使用相同的默认值。

## 自定义验证器

编写自定义验证函数非常简单。所需的只是编写一个函数，该函数以`form`对象和`field`对象作为参数，并在数据未通过测试时引发 WTForm.`ValidationError`。以下是一个自定义电子邮件验证器的示例：

```py
import re
import wtforms
def custom_email(form, field):
  if not re.match(r"[^@]+@[^@]+\.[^@]+", field.data):
    raise wtforms.ValidationError('Field must be a valid email address.')
```

要使用此函数，只需将其添加到字段的验证器列表中。

## 发布评论

现在我们有了评论表单，并且了解了如何构建它，我们需要将其添加到我们的帖子视图的开头：

```py
@app.route('/post/<int:post_id>', methods=('GET', 'POST'))
def post(post_id):
form = CommentForm()
if form.validate_on_submit():
        new_comment = Comment()
    new_comment.name = form.name.data
    new_comment.text = form.text.data
    new_comment.post_id = post_id
    new_comment.date = datetime.datetime.now()

    db.session.add(new_comment)
    db.session.commit()
    post = Post.query.get_or_404(post_id)
    tags = post.tags
    comments = post.comments.order_by(Comment.date.desc()).all()
    recent, top_tags = sidebar_data()

    return render_template(
        'post.html',
        post=post,
        tags=tags,
        comments=comments,
        recent=recent,
        top_tags=top_tags,
        form=form
    )
```

首先，我们将`POST`方法添加到视图的允许方法列表中。然后，创建一个新的表单对象实例。然后，“validate_on_submit（）”方法检查 Flask 请求是否为`POST`请求。如果是`POST`请求，则将请求表单数据发送到表单对象。如果数据经过验证，那么“validate_on_submit（）”将返回`True`并将数据添加到`form`对象中。然后，我们从每个字段中获取数据，填充一个新的评论，并将其添加到数据库中。最后，我们将表单添加到要发送到模板的变量中，以便将表单添加到我们的`post.html`文件中：

```py
<div class="col-lg-12">
  <h3>New Comment:</h3>
  <form method="POST" action="{{ url_for('post', post_id=post.id) }}">
    {{ form.hidden_tag() }}
    <div class="form-group">
      {{ form.name.label }}
      {% if form.name.errors %}
        {% for e in form.name.errors %}
          <p class="help-block">{{ e }}</p>
        {% endfor %}
      {% endif %}
      {{ form.name(class_='form-control') }}
    </div>
    <div class="form-group">
      {{ form.text.label }}
      {% if form.text.errors %}
        {% for e in form.text.errors %}
          <p class="help-block">{{ e }}</p>
        {% endfor %}
      {% endif %}
      {{ form.text(class_='form-control') }}
    </div>
    <input class="btn btn-primary" type="submit" value="Add Comment">
  </form>
</div>
```

这里发生了几件新事情。首先，“form.hidden_tag（）”方法会自动添加一个反跨站请求伪造措施。其次，`field.errors`列表用于呈现我们的验证器在验证失败时发送的任何消息。第三，调用字段本身作为方法将呈现该字段的 HTML 代码。最后，调用`field.label`将自动为我们的输入创建一个 HTML 标签。现在，向字段添加信息并按下提交按钮应该会添加您的评论！

这将看起来像以下的屏幕截图：

![发布评论](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_03_02.jpg)

读者的最后一个挑战是制作一个宏，该宏接受一个`form`对象和一个要发送`POST`请求的端点，并自动生成整个表单标记的 HTML。如果遇到困难，请参考 WTForms 文档。这有点棘手，但不是太难。

# 摘要

现在，仅仅三章之后，您已经拥有了一个完全功能的博客。这是很多关于 Web 开发技术的书籍会结束的地方。然而，还有 10 章要去将您的实用博客转变为用户实际用于其网站的东西。在下一章中，我们将专注于构建 Flask 应用程序以适应长期开发和更大规模的项目。
