# Flask Web 应用构建指南（一）

> 原文：[`zh.annas-archive.org/md5/5AC5010B2FEF93C4B37A69C597C8617D`](https://zh.annas-archive.org/md5/5AC5010B2FEF93C4B37A69C597C8617D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

在我们“现在的世界”中，人们几乎无法开发新的应用程序而不将许多技术粘合在一起，无论是新趋势数据库，消息系统还是各种语言。 谈到 Web 开发，事情可能会变得稍微复杂，因为你不仅必须将许多技术混合在一起，而且它们还必须与访问它们的应用程序（也称为 Web 浏览器）良好地配合。 它们还应与您的部署服务器兼容，这本身又是另一回事！

在 Python 世界中，人们遵循 Python 之禅和 PEP8 等伟大准则，交付令人惊叹的桌面软件，我们可以利用各种库和框架来创建出色的 Web 应用程序，每个都有其自己的哲学。 例如，Django 是一个捆绑解决方案； 它为您做出了关于项目应该如何看起来，应该有什么，以及应该如何完成事情的选择。 Web2py 是另一个框架解决方案，甚至将 IDE 与其捆绑在一起。 这些都是很好的概念，但如果您想创建一些简单的东西，我建议您在其他地方做。 它们通常是很好的选择，但有时它们只是太多了（最新的 Django 版本似乎决定改变这一点； 让我们密切关注进一步的发展）。

Flask 定位自己不是像 Django 和 Web2py 那样的开箱即用的解决方案，而是一个最简解决方案，你只得到最基本的东西，然后选择其他所有的东西。 当你想要对应用程序进行细粒度控制时，当你想要精确选择你的组件时，或者当你的解决方案很简单时（不是简化的，好吗？）。

这本书是对 Web 世界中美丽代码和许多选择的情景的回应。 它试图解决与 Web 开发相关的主要问题，从安全性到内容交付，从会话管理到 REST 服务和 CRUD。 还涵盖了重要的现代概念，如过度工程，质量和开发过程，以便从第一天起获得更好的结果。 为了使学习过程顺利进行，主题都是在不着急的情况下呈现，并附有注释示例。 该书还旨在为读者提供有关如何预防代码常见问题的现实建议。

来学习如何创建出色的 Flask 应用程序，为您的项目和客户提供价值！

# 本书涵盖的内容

第一章《Flask in a Flask, I Mean, Book》向你介绍了 Flask，解释了它是什么，它不是什么，以及它在 Web 框架世界中的定位。

第二章《First App, How Hard Could it Be?》涵盖了通往 Flask 开发的第一步，包括环境设置，你自己的“Hello World”应用程序，以及模板如何进入这个方程式。 这是一个轻松的章节！

第三章《Man, Do I Like Templates!》介绍了面部标签和过滤器在 Jinja2 模板引擎中的进展，以及它如何与 Flask 集成。 从这里开始事情开始变得有点严肃！

第四章《Please Fill in This Form, Madam》讨论了如何处理表单（因为表单是 Web 开发生活中的一个事实），并使用 WTForms 以其全部荣耀来对待它们！

第五章《Where Do You Store Your Stuff?》介绍了关系型和非关系型数据库的概念，涵盖了如何处理这两种情况，以及何时处理。

第六章《But I Wanna REST Mom, Now!》是关于创建 REST 服务的一章（因为 REST 的热情必须得到满足），手动创建和使用令人惊叹的 Flask-Restless。

第七章，“如果没有经过测试，就不是游戏，兄弟！”，是我们以质量为中心的章节，您将学习通过适当的测试、TDD 和 BDD 方式提供质量！

第八章，“技巧和窍门或 Flask 魔法 101”，是一个密集的章节，涵盖了良好的实践、架构、蓝图、调试和会话管理。

第九章，“扩展，我是如何爱你”，涵盖了到目前为止尚未涉及的所有伟大的 Flask 扩展，这些扩展将帮助您实现现实世界对您的生产力要求。

第十章，“现在怎么办？”，结束了我们的开发之旅，涵盖了健康部署的所有基础知识，并指引您在 Flask 世界中迈出下一步。

# 您需要为本书做好准备

为了充分利用阅读体验，读者应该准备一台安装了 Ubuntu 14.x 或更高版本的机器，因为示例是为这种设置设计的，还需要对 Python 有基本的了解（如果您没有，请先参考[`learnxinyminutes.com/docs/python/`](http://learnxinyminutes.com/docs/python/)），以及一个带有您喜欢的高亮显示的文本编辑器（LightTable，Sublime，Atom）。其他所需软件将在各章讨论中介绍。

# 这本书是为谁准备的

本书面向 Python 开发人员，无论是有一些或没有 Web 开发经验的人，都希望创建简约的 Web 应用程序。它专注于那些希望成为 Web 开发人员的人，因为所有基础知识都在一定程度上得到了涵盖，也专注于那些已经熟悉使用其他框架进行 Web 开发的人，无论是基于 Python 的框架，如 Django、Bottle 或 Pyramid，还是其他语言的框架。 

同样重要的是，您要对用于构建网页的 Web 技术有基本的了解，比如 CSS、JavaScript 和 HTML。如果这不是您的背景，请查看 W3Schools 网站（[`w3schools.com/`](http://w3schools.com/)），因为它涵盖了使用这些技术的基础知识。此外，如果您熟悉 Linux 终端，整本书的学习将会更加轻松；如果不是这种情况，请尝试链接[`help.ubuntu.com/community/UsingTheTerminal`](https://help.ubuntu.com/community/UsingTheTerminal)。

尽管如此，请放心，如果您对 Python 有基本的了解，您完全有能力理解示例和章节；在本书结束时，您将创建出表现良好且易于维护的令人惊叹的 Web 应用程序。

# 约定

在本书中，您将找到一些区分不同信息类型的文本样式。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“进入新项目文件夹并创建`main.py`文件”。

代码块设置如下：

```py
# coding:utf-8
from flask import Flask
app = Flask(__name__)

@app.route("/")
def hello():
    return "Hello World!"

if __name__ == "__main__":
    app.run()
```

任何命令行输入或输出都以以下形式编写：

```py
sudo pip install virtualenvwrapper

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，比如菜单或对话框中的单词，会以这样的形式出现在文本中：“您有没有想象过在网站上填写表单并在末尾点击那个花哨的**发送**按钮时会发生什么？”。

### 注意

警告或重要说明会以这样的方式出现在框中。

### 提示

提示和技巧会以这样的方式出现。


# 第一章：Flask 中的 Flask，我的意思是，书

Flask 是什么？这是一个人类几千年来一直在思考的问题……嗯，实际上是自 2010 年 Armin Ronacher 首次承诺该项目以来。Flask 是一个 Web 框架，与大多数人习惯使用的方式非常不同。它对你的应用程序应该是什么样子或者你应该使用什么来使其可用并不那么自以为是。这个 BSD 许可的软件包就是这样！

# Flask 及其特性简介

Flask 框架实际上是一个非常好的胶水，它将令人惊叹的 Werkzeug 和 Jinja2 框架粘合在一起，负责响应请求和呈现输出（HTML，也许）。在 MVC 架构中，也被称为模型-视图-控制器，Flask 涵盖了 C 和 V。但 M 在哪里？Flask 并没有为你提供集成的模型层，因为对于 Web 应用程序实际上并不需要。如果你确实需要使用数据库，只需从众多可用的数据库解决方案中选择一个并创建自己的模型层，这并不难，而且会让你很开心！微框架的概念，怀着良好的意图，专门为 Flask 而设计，就是要给你提供你所需要的最小（但也是最有用的）功能集，而且不会妨碍你。

框架中必须具备哪些特性？

+   开发服务器和调试器（健全友好）

+   Unicode 支持（拉丁语言友好）

+   WSGI 兼容（uWsgi 友好）

+   单元测试客户端（质量代码）

+   URL 路由（它让我感动得流泪，它太美了！）

+   请求分发

+   安全的 cookies

+   会话

+   Jinja2 模板（标签、过滤器、宏等）

有了这些，你可以处理 Ajax 请求、浏览器请求和请求之间的用户会话；将 HTTP 请求路由到你的控制器；评估表单数据；响应 HTML 和 JSON 等等。

这很好，但 Flask 不是一个 MVC 框架吗？嗯，这是值得讨论的。如果一个 Web 框架不实现 MVC 反模式，比如在视图中处理请求或混合模型和控制器，它可能有助于实现 MVC，这在我看来是最好的，因为它不会强制你的应用程序结构。

### 注意

Flask 不是一个 MVC 框架，因为它没有实现模型层，尽管如果你希望创建自己的模型层，它不会限制你。

如果你需要一个简单的、单文件的 Web 应用程序，接收一个表单并返回一个答案，无论是 HTML 还是其他，Flask 都可以帮助你轻松实现。如果你需要一个多层、高深度模块化的 Facebook 克隆，Flask 也可以为你提供帮助。

那么，我们到目前为止学到了什么？

+   Flask 诞生于 2010 年

+   Flask 是一个基于 Jinja2 和 Werkzeug 的极简主义 Web 框架

+   Flask 不强制执行特定的项目架构

### 注意

请参考 Flask 许可证的详细信息[`flask.pocoo.org/docs/0.10/license/`](http://flask.pocoo.org/docs/0.10/license/)。

现在，你可能想知道你的哪些好点子可以用 Flask 来实现。这就对了！我们一起来想想这个问题吧？

Flask 在数据库集成、表单库、管理界面或迁移工具方面没有捆绑功能。你可以通过扩展来实现这些功能，这些扩展很快就会讨论到，但它们都是外部的 Flask。如果你需要这些扩展，而且不想在项目开始时设置它们（或者没有时间），你可能更适合使用一个功能齐全的 MVC 一体化、低内聚、高耦合的框架，比如 Django。

现在，想象一下你需要建立一个网站，只有一个表单，比如[`cashcash.cc/`](http://cashcash.cc/)的克隆，它接收一个表单并返回当前的货币交易价值；Flask 可以帮助你快速完成项目。

让我们再深入思考一下。如果你需要一组特定的库在你的项目中一起工作，而你又不希望 Web 框架妨碍你；这对于 Flask 来说是另一个非常好的场景，因为它给你提供了最基本的东西，让你自己组合其他你可能需要的一切。一些框架对它们自己的组件有如此高的耦合（读作**依赖性**），以至于如果你想使用特定的替代方案，你可能会遇到严重的问题。

例如，你可能想在项目中使用 NoSQL 数据库；然而，如果这样做，你的项目的一些组件可能会停止工作（例如：管理组件）。

基本上，如果你有时间可以抽出来，如果你正在做一些简单的事情，如果你想要实现自己的架构解决方案，或者如果你需要对项目中使用的组件进行细粒度控制，Flask 就是适合你的 Web 框架。

# 总结

现在，让我们谈谈令人敬畏的事情，在读完这本书后，你将能够处理 HTTP 和 Ajax 请求；创建具有数据库集成（SQL 和 NoSQL）和 REST 服务的完整功能的 Web 应用程序；使用 Flask 扩展（表单、缓存、日志、调试、认证、权限等）；以及模块化和对应用程序进行单元和功能测试。

希望你喜欢这本书，并能用所学的知识做出很棒的东西


# 第二章：第一个应用程序，有多难？

在一个完整的章节中没有一行代码，你需要这个，对吧？在这一章中，我们将逐行解释我们的第一个应用程序；我们还将介绍如何设置我们的环境，开发时使用什么工具，以及如何在我们的应用程序中使用 HTML。

# Hello World

当学习新技术时，人们通常会写一个 Hello World 应用程序，这个应用程序包含启动一个简单应用程序并显示文本"Hello World!"所需的最小可能代码。让我们使用 Flask 来做到这一点。

本书针对**Python 2.x**进行了优化，所以我建议你从现在开始使用这个版本。所有的示例和代码都针对这个 Python 版本，这也是大多数 Linux 发行版的默认版本。

# 先决条件和工具

首先，让我们确保我们的环境已经正确配置。在本课程中，我假设你使用的是类似 Debian 的 Linux 发行版，比如 Mint（[`www.linuxmint.com/`](http://www.linuxmint.com/)）或 Ubuntu（[`ubuntu.com/`](http://ubuntu.com/)）。所有的说明都将针对这些系统。

让我们从以下方式开始安装所需的 Debian 软件包：

```py
sudo apt-get install python-dev python-pip

```

这将安装 Python 开发工具和编译 Python 包所需的库，以及 pip：一个方便的工具，你可以用它来从命令行安装 Python 包。继续吧！让我们安装我们的虚拟环境管理工具：

```py
sudo pip install virtualenvwrapper
echo "source /usr/local/bin/virtualenvwrapper.sh" >> ~/.bashrc

```

解释一下我们刚刚做的事情：`sudo`告诉我们的操作系统，我们想要以管理员权限运行下一个命令，`pip`是默认的 Python 包管理工具，帮助我们安装`virtualenvwrapper`包。第二个命令语句添加了一个命令，将`virtualenvwrapper.sh`脚本与控制台一起加载，以便命令在你的 shell 内工作（顺便说一下，我们将使用它）。

# 设置虚拟环境

虚拟环境是 Python 将完整的包环境与其他环境隔离开来的方式。这意味着你可以轻松地管理依赖关系。想象一下，你想为一个项目定义最小必需的包；虚拟环境将非常适合让你测试和导出所需包的列表。我们稍后会讨论这个问题。现在，按下键盘上的*Ctrl* + *Shift* + *T*创建一个新的终端，并像这样创建我们的*hello world*环境：

```py
mkvirtualenv hello
pip install flask

```

第一行创建了一个名为"hello"的环境。你也可以通过输入`deactivate`来停用你的虚拟环境，然后可以使用以下命令再次加载它：

```py
workon hello  # substitute hello with the desired environment name if needed

```

第二行告诉 pip 在当前虚拟环境`hello`中安装 Flask 包。

# 理解"Hello World"应用程序

在设置好环境之后，我们应该使用什么来编写我们美丽的代码呢？编辑器还是集成开发环境？如果你的预算有限，可以尝试使用 Light Table 编辑器（[`lighttable.com/`](http://lighttable.com/)）。免费、快速、易于使用（*Ctrl* + *Spacebar* 可以访问所有可用选项），它还支持工作区！对于这个价钱来说，已经很难找到更好的了。如果你有 200 美元可以花（或者有免费许可证[`www.jetbrains.com/pycharm/buy/`](https://www.jetbrains.com/pycharm/buy/)），那就花钱购买 PyCharm 集成开发环境吧，这几乎是最适合 Python Web 开发的最佳 IDE。现在让我们继续。

创建一个文件夹来保存你的项目文件（你不需要，但如果你这样做，人们会更喜欢你），如下所示：

```py
mkdir hello_world

```

进入新的项目文件夹并创建`main.py`文件：

```py
cd hello_world
touch main.py

```

`main.py`文件将包含整个"Hello World"应用程序。我们的`main.py`内容应该像这样：

```py
# coding:utf-8
from flask import Flask
app = Flask(__name__)

@app.route("/")
def hello():
    return "Hello World!"

if __name__ == "__main__":
    app.run()
```

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便将文件直接发送到您的电子邮件。

哇！那需要一些打字，对吧？不是吗？是的，我知道。那么，我们刚刚做了什么？

第一行说明我们的`main.py`文件应该使用`utf-8`编码。所有酷孩子都这样做，所以不要对您的非英语朋友不友好，并在所有 Python 文件中使用它（这样做可能有助于您避免在大型项目中出现一些讨厌的错误）。

在第二行和第三行，我们导入我们的 Flask 类并对其进行实例化。我们应用程序的名称是“app”。几乎所有与它相关的东西都与它有关：视图、蓝图、配置等等。参数`__name__`是必需的，并且用于告诉应用程序在哪里查找静态内容或模板等资源。

为了创建我们的“Hello World”，我们需要告诉我们的 Flask 实例在用户尝试访问我们的 Web 应用程序（使用浏览器或其他方式）时如何响应。为此，Flask 有路由。

路由是 Flask 读取请求头并决定哪个视图应该响应该请求的方式。它通过分析请求的 URL 的路径部分，并找到注册了该路径的路由来实现这一点。

在*hello world*示例中，在第 5 行，我们使用路由装饰器将`hello`函数注册到`"/"`路径。每当应用程序接收到路径为`"/"`的请求时，`hello`都会响应该请求。以下代码片段显示了如何检查 URL 的路径部分：

```py
from urlparse import urlparse
parsed = urlparse("https://www.google.com/")
assert parsed.path == "/"
```

您还可以将多个路由映射到同一个函数，如下所示：

```py
@app.route("/")
@app.route("/index")
def hello():
    return "Hello World!"
```

在这种情况下，`"/"`和`"/index"`路径都将映射到`hello`。

在第 6 和第 7 行，我们有一个将响应请求的函数。请注意，它不接收任何参数并且以熟悉的字符串作出响应。它不接收任何参数，因为请求数据（如提交的表单）是通过一个名为**request**的线程安全变量访问的，我们将在接下来的章节中更多地了解它。

关于响应，Flask 可以以多种格式响应请求。在我们的示例中，我们以纯字符串作出响应，但我们也可以以 JSON 或 HTML 字符串作出响应。

第 9 和第 10 行很简单。它们检查`main.py`是作为脚本还是作为模块被调用。如果是作为脚本，它将运行与 Flask 捆绑在一起的内置开发服务器。让我们试试看：

```py
python main.py

```

您的终端控制台将输出类似以下内容：

```py
Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)

```

只需在浏览器中打开`http://127.0.0.1:5000/`，即可查看您的应用程序运行情况。

将`main.py`作为脚本运行通常是一个非常简单和方便的设置。通常，您可以使用 Flask-Script 来处理为您调用开发服务器和其他设置。

如果您将`main.py`作为模块使用，只需按以下方式导入它：

```py
from main import what_I_want
```

通常，您会在测试代码中执行类似以下操作来导入应用工厂函数。

这基本上就是关于我们的“Hello World”应用程序的所有内容。我们的世界应用程序缺少的一件事是乐趣因素。所以让我们添加一些；让我们让您的应用程序有趣！也许一些 HTML、CSS 和 JavaScript 可以在这里起作用。让我们试试看！

# 提供 HTML 页面

首先，要使我们的`hello`函数以 HTML 响应，我们只需将其更改为以下内容：

```py
def hello():
    return "<html><head><title>Hi there!</title></head><body>Hello World!</body></html>", 200
```

在上面的示例中，`hello`返回一个 HTML 格式的字符串和一个数字。字符串将默认解析为 HTML，而`200`是一个可选的 HTTP 代码，表示成功的响应。默认情况下返回`200`。

如果您使用*F5*刷新浏览器，您会注意到没有任何变化。这就是为什么当源代码更改时，Flask 开发服务器不会重新加载。只有在调试模式下运行应用程序时才会发生这种情况。所以让我们这样做：

```py
app = Flask(__name__)
app.debug=True
```

现在去你的应用程序正在运行的终端，输入`Ctrl + C`然后重新启动服务器。你会注意到除了你的服务器正在运行的 URL 之外有一个新的输出——关于“stat”的内容。这表示你的服务器将在源代码修改时重新加载代码。这很好，但你注意到我们刚刚犯下的罪行了吗：在处理响应的函数内部定义我们的模板？小心，MVC 之神可能在看着你。让我们把我们定义视图的地方和定义控制器的地方分开。创建一个名为 templates 的文件夹，并在其中创建一个名为`index.html`的文件。`index.html`文件的内容应该像这样：

```py
<html>
<head><title>Hi there!</title></head>
<body>Hello World!</body>
</html>
```

现在改变你的代码像这样：

```py
from flask import Flask, render_response
@app.route("/")
def hello():
    return render_template("index.html")
```

你看到我们做了什么了吗？`render_response`能够从`templates/`文件夹（Flask 的默认文件夹）中加载模板，并且你可以通过返回输出来渲染它。

现在让我们添加一些 JavaScript 和 CSS 样式。默认情况下，Flask 内置的开发服务器会提供`project`文件夹中名为`static`的子文件夹中的所有文件。让我们创建我们自己的文件夹并向其中添加一些文件。你的项目树应该是这样的：

```py
project/
-main.py
-templates/
--index.html
-static/
--js
---jquery.min.js
---foundation.min.js
---modernizr.js
--css
---styles.css
---foundation.min.css
```

注意我从`foundation.zurb`框架中添加了文件，这是一个在[`foundation.zurb.com/`](http://foundation.zurb.com/)上可用的不错的 CSS 框架。我建议你也这样做，以便拥有一个现代、漂亮的网站。你模板中的静态文件路径应该是这样的：

```py
<script src='/static/js/modernizr.js'></script>
```

在真实文件路径之前的`/static`文件夹是 Flask 默认提供的路由，只在调试模式下起作用。在生产环境中，你将需要 HTTP 服务器为你提供静态文件。查看本章附带的代码以获取完整示例。

尝试用一些漂亮的 CSS 样式来改进“hello world”示例！

# 总结

建立开发环境是一项非常重要的任务，我们刚刚完成了这个任务！创建一个“Hello World”应用程序是向某人介绍新技术的好方法。我们也做到了。最后，我们学会了如何提供 HTML 页面和静态文件，这基本上是大多数 Web 应用程序所做的。你在本章中掌握了所有这些技能，我希望这个过程既简单又充实！

在下一章中，我们将通过更加冒险的模板来为我们的挑战增添一些调味。我们将学习如何使用 Jinja2 组件来创建强大的模板，从而让我们在输入更少的情况下做更多的事情。到时见！


# 第三章：天哪，我喜欢模板！

如前所述，Flask 为您提供了 MVC 中的 VC。在本章中，我们将讨论 Jinja2 是什么，以及 Flask 如何使用 Jinja2 来实现视图层并让您感到敬畏。做好准备！

# Jinja2 是什么，它如何与 Flask 耦合在一起？

Jinja2 是一个库，可以在[`jinja.pocoo.org/`](http://jinja.pocoo.org/)找到；您可以使用它来生成带有捆绑逻辑的格式化文本。与 Python 格式函数不同，Python 格式函数只允许您用变量内容替换标记，您可以在模板字符串中使用控制结构（例如`for`循环），并使用 Jinja2 进行解析。让我们考虑这个例子：

```py
from jinja2 import Template
x = """
<p>Uncle Scrooge nephews</p>
<ul>
{% for i in my_list %}
<li>{{ i }}</li>
{% endfor %}
</ul>
"""
template = Template(x)
# output is an unicode string
print template.render(my_list=['Huey', 'Dewey', 'Louie'])
```

在上面的代码中，我们有一个非常简单的例子，其中我们创建了一个模板字符串，其中包含一个`for`循环控制结构（简称“for 标签”），该结构遍历名为`my_list`的列表变量，并使用大括号`{{ }}`符号打印“li HTML 标签”中的元素。

请注意，您可以在模板实例中调用`render`多次，并使用不同的键值参数，也称为模板上下文。上下文变量可以有任何有效的 Python 变量名——也就是说，任何符合正则表达式*[a-zA-Z_][a-zA-Z0-9_]*格式的内容。

### 提示

有关 Python 正则表达式（**Regex**简称）的完整概述，请访问[`docs.python.org/2/library/re.html`](https://docs.python.org/2/library/re.html)。还可以查看这个用于正则表达式测试的在线工具[`pythex.org/`](http://pythex.org/)。

一个更复杂的例子将使用环境类实例，这是一个中央、可配置、可扩展的类，可以以更有组织的方式加载模板。

您明白我们要说什么了吗？这是 Jinja2 和 Flask 背后的基本原理：它为您准备了一个环境，具有一些响应式默认设置，并让您的轮子转起来。

# 您可以用 Jinja2 做什么？

Jinja2 非常灵活。您可以将其与模板文件或字符串一起使用；您可以使用它来创建格式化文本，例如 HTML、XML、Markdown 和电子邮件内容；您可以组合模板、重用模板和扩展模板；甚至可以使用扩展。可能性是无穷无尽的，并且结合了良好的调试功能、自动转义和完整的 Unicode 支持。

### 注意

自动转义是 Jinja2 的一种配置，其中模板中打印的所有内容都被解释为纯文本，除非另有明确要求。想象一个变量*x*的值设置为`<b>b</b>`。如果启用了自动转义，模板中的`{{ x }}`将打印给定的字符串。如果关闭了自动转义，这是 Jinja2 的默认设置（Flask 的默认设置是开启的），则生成的文本将是`b`。

在介绍 Jinja2 允许我们进行编码之前，让我们先了解一些概念。

首先，我们有前面提到的大括号。双大括号是一个分隔符，允许您从提供的上下文中评估变量或函数，并将其打印到模板中：

```py
from jinja2 import Template
# create the template
t = Template("{{ variable }}")
# – Built-in Types –
t.render(variable='hello you')
>> u"hello you"
t.render(variable=100)
>> u"100"
# you can evaluate custom classes instances
class A(object):
  def __str__(self):
    return "__str__"
  def __unicode__(self):
    return u"__unicode__"
  def __repr__(self):
    return u"__repr__"
# – Custom Objects Evaluation –
# __unicode__ has the highest precedence in evaluation
# followed by __str__ and __repr__
t.render(variable=A())
>> u"__unicode__"
```

在上面的例子中，我们看到如何使用大括号来评估模板中的变量。首先，我们评估一个字符串，然后是一个整数。两者都会产生 Unicode 字符串。如果我们评估我们自己的类，我们必须确保定义了`__unicode__`方法，因为在评估过程中会调用它。如果没有定义`__unicode__`方法，则评估将退回到`__str__`和`__repr__`，依次进行。这很简单。此外，如果我们想评估一个函数怎么办？好吧，只需调用它：

```py
from jinja2 import Template
# create the template
t = Template("{{ fnc() }}")
t.render(fnc=lambda: 10)
>> u"10"
# evaluating a function with argument
t = Template("{{ fnc(x) }}")
t.render(fnc=lambda v: v, x='20')
>> u"20"
t = Template("{{ fnc(v=30) }}")
t.render(fnc=lambda v: v)
>> u"30"
```

要在模板中输出函数的结果，只需像调用任何常规 Python 函数一样调用该函数。函数返回值将被正常评估。如果您熟悉 Django，您可能会注意到这里有一点不同。在 Django 中，您不需要使用括号来调用函数，甚至不需要向其传递参数。在 Flask 中，如果要对函数返回值进行评估，则*始终*需要使用括号。

以下两个示例展示了 Jinja2 和 Django 在模板中函数调用之间的区别：

```py
{# flask syntax #}
{{ some_function() }}

{# django syntax #}
{{ some_function }}
```

您还可以评估 Python 数学运算。看一下：

```py
from jinja2 import Template
# no context provided / needed
Template("{{ 3 + 3 }}").render()
>> u"6"
Template("{{ 3 - 3 }}").render()
>> u"0"
Template("{{ 3 * 3 }}").render()
>> u"9"
Template("{{ 3 / 3 }}").render()
>> u"1"
```

其他数学运算符也可以使用。您可以使用花括号分隔符来访问和评估列表和字典：

```py
from jinja2 import Template
Template("{{ my_list[0] }}").render(my_list=[1, 2, 3])
>> u'1'
Template("{{ my_list['foo'] }}").render(my_list={'foo': 'bar'})
>> u'bar'
# and here's some magic
Template("{{ my_list.foo }}").render(my_list={'foo': 'bar'})
>> u'bar'
```

要访问列表或字典值，只需使用普通的 Python 表示法。对于字典，您还可以使用变量访问表示法访问键值，这非常方便。

除了花括号分隔符，Jinja2 还有花括号/百分比分隔符，它使用`{% stmt %}`的表示法，用于执行语句，这可能是控制语句，也可能不是。它的使用取决于语句，其中控制语句具有以下表示法：

```py
{% stmt %}
{% endstmt %}
```

第一个标签具有语句名称，而第二个是闭合标签，其名称在开头附加了`end`。您必须意识到非控制语句*可能*没有闭合标签。让我们看一些例子：

```py
{% block content %}
{% for i in items %}
{{ i }} - {{ i.price }}
{% endfor %}
{% endblock %}
```

前面的例子比我们之前看到的要复杂一些。它在块语句中使用了控制语句`for`循环（您可以在另一个语句中有一个语句），这不是控制语句，因为它不控制模板中的执行流程。在`for`循环中，您可以看到`i`变量与关联的价格（在其他地方定义）一起打印出来。

您应该知道的最后一个分隔符是`{# comments go here #}`。这是一个多行分隔符，用于声明注释。让我们看两个具有相同结果的例子：

```py
{# first example #}
{#
second example
#}
```

两种注释分隔符都隐藏了`{#`和`#}`之间的内容。可以看到，这个分隔符适用于单行注释和多行注释，非常方便。

## 控制结构

Jinja2 中默认定义了一组不错的内置控制结构。让我们从`if`语句开始学习它。

```py
{% if true %}Too easy{% endif %}
{% if true == true == True %}True and true are the same{% endif %}
{% if false == false == False %}False and false also are the same{% endif %}
{% if none == none == None %}There's also a lowercase None{% endif %}
{% if 1 >= 1 %}Compare objects like in plain python{% endif %}
{% if 1 == 2 %}This won't be printed{% else %}This will{% endif %}
{% if "apples" != "oranges" %}All comparison operators work = ]{% endif %}
{% if something %}elif is also supported{% elif something_else %}^_^{% endif %}
```

`if`控制语句很美妙！它的行为就像`python if`语句一样。如前面的代码所示，您可以使用它以非常简单的方式比较对象。"`else`"和"`elif`"也得到了充分支持。

您可能还注意到了`true`和`false`，非大写，与普通的 Python 布尔值`True`和`False`一起使用。为了避免混淆的设计决策，所有 Jinja2 模板都有`True`、`False`和`None`的小写别名。顺便说一句，小写语法是首选的方式。

如果需要的话，您应该避免这种情况，可以将比较组合在一起以改变优先级评估。请参阅以下示例：

```py
{% if  5 < 10 < 15 %}true{%else%}false{% endif %}
{% if  (5 < 10) < 15 %}true{%else%}false{% endif %}
{% if  5 < (10 < 15) %}true{%else%}false{% endif %}
```

前面示例的预期输出是`true`、`true`和`false`。前两行非常直接。在第三行中，首先，`(10<15)`被评估为`True`，它是`int`的子类，其中`True == 1`。然后评估`5` < `True`，这显然是假的。

`for`语句非常重要。几乎无法想象一个严肃的 Web 应用程序不必在某个时候显示某种列表。`for`语句可以迭代任何可迭代实例，并且具有非常简单的、类似 Python 的语法：

```py
{% for item in my_list %}
{{ item }}{# print evaluate item #}
{% endfor %}
{# or #}
{% for key, value in my_dictionary.items() %}
{{ key }}: {{ value }}
{% endfor %}
```

在第一个语句中，我们有一个开放标签，指示我们将遍历`my_list`项，每个项将被名称`item`引用。名称`item`仅在`for`循环上下文中可用。

在第二个语句中，我们对形成`my_dictionary`的键值元组进行迭代，这应该是一个字典（如果变量名不够具有启发性的话）。相当简单，对吧？`for`循环也为您准备了一些技巧。

在构建 HTML 列表时，通常需要以交替颜色标记每个列表项，以改善可读性，或者使用一些特殊标记标记第一个和/或最后一个项目。这些行为可以通过在 Jinja2 for 循环中访问块上下文中可用的循环变量来实现。让我们看一些例子：

```py
{% for i in ['a', 'b', 'c', 'd'] %}
{% if loop.first %}This is the first iteration{% endif %}
{% if loop.last %}This is the last iteration{% endif %}
{{ loop.cycle('red', 'blue') }}{# print red or blue alternating #}
{{ loop.index }} - {{ loop.index0 }} {# 1 indexed index – 0 indexed index #}
{# reverse 1 indexed index – reverse 0 indexed index #}
{{ loop.revindex }} - {{ loop.revindex0 }} 
{% endfor %}
```

`for`循环语句，就像 Python 一样，也允许使用`else`，但意义略有不同。在 Python 中，当您在`for`中使用`else`时，只有在没有通过`break`命令到达`else`块时才会执行`else`块，就像这样：

```py
for i in [1, 2, 3]:
  pass
else:
  print "this will be printed"
for i in [1, 2, 3]:
  if i == 3:
    break
else:
  print "this will never not be printed"
```

如前面的代码片段所示，`else`块只有在`for`循环中从未被`break`命令中断执行时才会执行。使用 Jinja2 时，当`for`可迭代对象为空时，将执行`else`块。例如：

```py
{% for i in [] %}
{{ i }}
{% else %}I'll be printed{% endfor %}
{% for i in ['a'] %}
{{ i }}
{% else %}I won't{% endfor %}
```

由于我们正在讨论循环和中断，有两件重要的事情要知道：Jinja2 的`for`循环不支持`break`或`continue`。相反，为了实现预期的行为，您应该使用循环过滤，如下所示：

```py
{% for i in [1, 2, 3, 4, 5] if i > 2 %}
value: {{ i }}; loop.index: {{ loop.index }}
{%- endfor %}
```

在第一个标签中，您会看到一个普通的`for`循环和一个`if`条件。您应该将该条件视为一个真正的列表过滤器，因为索引本身只是在每次迭代中计数。运行前面的示例，输出将如下所示：

```py
value:3; index: 1
value:4; index: 2
value:5; index: 3
```

看看前面示例中的最后一个观察——在第二个标签中，您看到`{%-`中的破折号吗？它告诉渲染器在每次迭代之前不应该有空的新行。尝试我们之前的示例，不带破折号，并比较结果以查看有何变化。

现在我们将看看用于从不同文件构建模板的三个非常重要的语句：`block`、`extends`和`include`。

`block`和`extends`总是一起使用。第一个用于定义模板中的“可覆盖”块，而第二个定义了具有块的当前模板的父模板。让我们看一个例子：

```py
# coding:utf-8
with open('parent.txt', 'w') as file:
    file.write("""
{% block template %}parent.txt{% endblock %}
===========
I am a powerful psychic and will tell you your past

{#- "past" is the block identifier #}
{% block past %}
You had pimples by the age of 12.
{%- endblock %}

Tremble before my power!!!""".strip())

with open('child.txt', 'w') as file:
    file.write("""
{% extends "parent.txt" %}

{# overwriting the block called template from parent.txt #}
{% block template %}child.txt{% endblock %}

{#- overwriting the block called past from parent.txt #}
{% block past %}
You've bought an ebook recently.
{%- endblock %}""".strip())
with open('other.txt', 'w') as file:
	file.write("""
{% extends "child.txt" %}
{% block template %}other.txt{% endblock %}""".strip())

from jinja2 import Environment, FileSystemLoader

env = Environment()
# tell the environment how to load templates
env.loader = FileSystemLoader('.')
# look up our template
tmpl = env.get_template('parent.txt')
# render it to default output
print tmpl.render()
print ""
# loads child.html and its parent
tmpl = env.get_template('child.txt')
print tmpl.render()
# loads other.html and its parent
env.get_template('other.txt').render()
```

您是否看到了`child.txt`和`parent.txt`之间的继承？`parent.txt`是一个简单的模板，有两个名为`template`和`past`的`block`语句。当您直接呈现`parent.txt`时，它的块会“原样”打印，因为它们没有被覆盖。在`child.txt`中，我们扩展`parent.txt`模板并覆盖所有其块。通过这样做，我们可以在模板的特定部分中具有不同的信息，而无需重写整个内容。

例如，使用`other.txt`，我们扩展`child.txt`模板并仅覆盖命名为 block 的模板。您可以从直接父模板或任何父模板覆盖块。

如果您正在定义一个`index.txt`页面，您可以在其中有默认块，需要时进行覆盖，从而节省大量输入。

解释最后一个示例，就 Python 而言，非常简单。首先，我们创建了一个 Jinja2 环境（我们之前谈到过这个），并告诉它如何加载我们的模板，然后直接加载所需的模板。我们不必费心告诉环境如何找到父模板，也不必预加载它们。

`include`语句可能是迄今为止最简单的语句。它允许您以非常简单的方式在另一个模板中呈现模板。让我们看一个例子：

```py
with open('base.txt', 'w') as file:
  file.write("""
{{ myvar }}
You wanna hear a dirty joke?
{% include 'joke.txt' %}
""".strip())
with open('joke.txt', 'w') as file:
  file.write("""
A boy fell in a mud puddle. {{ myvar }} 
""".strip())

from jinja2 import Environment, FileSystemLoader

env = Environment()
# tell the environment how to load templates
env.loader = FileSystemLoader('.')
print env.get_template('base.txt').render(myvar='Ha ha!')
```

在前面的示例中，我们在`base.txt`中呈现`joke.txt`模板。由于`joke.txt`在`base.txt`中呈现，它也可以完全访问`base.txt`上下文，因此`myvar`会正常打印。

最后，我们有`set`语句。它允许您在模板上下文中定义变量。它的使用非常简单：

```py
{% set x = 10 %}
{{ x }}
{% set x, y, z = 10, 5+5, "home" %}
{{ x }} - {{ y }} - {{ z }}
```

在前面的示例中，如果`x`是通过复杂计算或数据库查询给出的，如果要在模板中重复使用它，将其*缓存*在一个变量中会更有意义。如示例中所示，您还可以一次为多个变量分配一个值。

## 宏

宏是您在 Jinja2 模板中最接近编码的地方。宏的定义和使用类似于普通的 Python 函数，因此非常容易。让我们尝试一个例子：

```py
with open('formfield.html', 'w') as file:
  file.write('''
{% macro input(name, value='', label='') %}
{% if label %}
<label for='{{ name }}'>{{ label }}</label>
{% endif %}
<input id='{{ name }}' name='{{ name }}' value='{{ value }}'></input>
{% endmacro %}'''.strip())
with open('index.html', 'w') as file:
  file.write('''
{% from 'formfield.html' import input %}
<form method='get' action='.'>
{{ input('name', label='Name:') }}
<input type='submit' value='Send'></input>
</form>
'''.strip())

from jinja2 import Environment, FileSystemLoader

env = Environment()
env.loader = FileSystemLoader('.')
print env.get_template('index.html').render()
```

在前面的例子中，我们创建了一个宏，接受一个`name`参数和两个可选参数：`value`和`label`。在`macro`块内，我们定义了应该输出的内容。请注意，我们可以在宏中使用其他语句，就像在模板中一样。在`index.html`中，我们从`formfield.html`中导入输入宏，就好像`formfield`是一个模块，输入是一个使用`import`语句的 Python 函数。如果需要，我们甚至可以像这样重命名我们的输入宏：

```py
{% from 'formfield.html' import input as field_input %}
```

您还可以将`formfield`作为模块导入并按以下方式使用它：

```py
{% import 'formfield.html' as formfield %}
```

在使用宏时，有一种特殊情况，您希望允许任何命名参数传递到宏中，就像在 Python 函数中一样（例如，`**kwargs`）。使用 Jinja2 宏，默认情况下，这些值在`kwargs`字典中可用，不需要在宏签名中显式定义。例如：

```py
# coding:utf-8
with open('formfield.html', 'w') as file:
    file.write('''
{% macro input(name) -%}
<input id='{{ name }}' name='{{ name }}' {% for k,v in kwargs.items() -%}{{ k }}='{{ v }}' {% endfor %}></input>
{%- endmacro %}
'''.strip())with open('index.html', 'w') as file:
    file.write('''
{% from 'formfield.html' import input %}
{# use method='post' whenever sending sensitive data over HTTP #}
<form method='post' action='.'>
{{ input('name', type='text') }}
{{ input('passwd', type='password') }}
<input type='submit' value='Send'></input>
</form>
'''.strip())

from jinja2 import Environment, FileSystemLoader

env = Environment()
env.loader = FileSystemLoader('.')
print env.get_template('index.html').render()
```

如您所见，即使您没有在宏签名中定义`kwargs`参数，`kwargs`也是可用的。

宏在纯模板上具有一些明显的优势，您可以通过`include`语句注意到：

+   使用宏时，您不必担心模板中的变量名称

+   您可以通过宏签名定义宏块的确切所需上下文

+   您可以在模板中定义一个宏库，并仅导入所需的内容

Web 应用程序中常用的宏包括用于呈现分页的宏，用于呈现字段的宏，以及用于呈现表单的宏。您可能还有其他用例，但这些是相当常见的用例。

### 提示

关于我们之前的例子，使用 HTTPS（也称为安全 HTTP）发送敏感信息，如密码，通过互联网是一个良好的做法。要小心！

## 扩展

扩展是 Jinja2 允许您扩展其词汇的方式。扩展默认情况下未启用，因此只有在需要时才能启用扩展，并且可以在不太麻烦的情况下开始使用它：

```py
env = Environment(extensions=['jinja2.ext.do', 'jinja2.ext.with_'])
```

在前面的代码中，我们有一个示例，其中您创建了一个启用了两个扩展的环境：`do`和`with`。这些是我们将在本章中学习的扩展。

正如其名称所示，`do`扩展允许您“做一些事情”。在`do`标记内，您可以执行 Python 表达式，并完全访问模板上下文。Flask-Empty 是一个流行的 Flask 样板，可在[`github.com/italomaia/flask-empty`](https://github.com/italomaia/flask-empty)上找到，它使用`do`扩展来更新其宏之一中的字典。让我们看看我们如何做到这一点：

```py
{% set x = {1:'home', '2':'boat'} %}
{% do x.update({3: 'bar'}) %}
{%- for key,value in x.items() %}
{{ key }} - {{ value }}
{%- endfor %}
```

在前面的例子中，我们使用一个字典创建了`x`变量，然后用`{3: 'bar'}`更新了它。通常情况下，您不需要使用`do`扩展，但是当您需要时，可以节省大量编码。

`with`扩展也非常简单。每当您需要创建块作用域变量时，都可以使用它。想象一下，您有一个需要在变量中缓存一小段时间的值；这将是一个很好的用例。让我们看一个例子：

```py
{% with age = user.get_age() %}
My age: {{ age }}
{% endwith %}
My age: {{ age }}{# no value here #}
```

如示例所示，`age`仅存在于`with`块内。此外，在`with`块内设置的变量将仅在其中存在。例如：

```py
{% with %}
{% set count = query.count() %}
Current Stock: {{ count }}
Diff: {{ prev_count - count }}
{% endwith %}
{{ count }} {# empty value #}
```

## 过滤器

过滤器是 Jinja2 的一个奇妙之处！这个工具允许您在将常量或变量打印到模板之前对其进行处理。目标是在模板中严格实现您想要的格式。

要使用过滤器，只需使用管道运算符调用它，就像这样：

```py
{% set name = 'junior' %}
{{ name|capitalize }} {# output is Junior #}
```

它的名称被传递给**capitalize**过滤器进行处理，并返回大写的值。要将参数传递给过滤器，只需像调用函数一样调用它，就像这样：

```py
{{ ['Adam', 'West']|join(' ') }} {# output is Adam West #}
```

`join`过滤器将连接传递的可迭代值，将提供的参数放在它们之间。

Jinja2 默认提供了大量可用的过滤器。这意味着我们无法在这里覆盖它们所有，但我们当然可以覆盖一些。`capitalize`和`lower`已经看到了。让我们看一些进一步的例子：

```py
{# prints default value if input is undefined #}
{{ x|default('no opinion') }}
{# prints default value if input evaluates to false #}
{{ none|default('no opinion', true) }}
{# prints input as it was provided #}
{{ 'some opinion'|default('no opinion') }}

{# you can use a filter inside a control statement #}
{# sort by key case-insensitive #}
{% for key in {'A':3, 'b':2, 'C':1}|dictsort %}{{ key }}{% endfor %}
{# sort by key case-sensitive #}
{% for key in {'A':3, 'b':2, 'C':1}|dictsort(true) %}{{ key }}{% endfor %}
{# sort by value #}
{% for key in {'A':3, 'b':2, 'C':1}|dictsort(false, 'value') %}{{ key }}{% endfor %}
{{ [3, 2, 1]|first }} - {{ [3, 2, 1]|last }}
{{ [3, 2, 1]|length }} {# prints input length #}
{# same as in python #}
{{ '%s, =D'|format("I'm John") }}
{{ "He has two daughters"|replace('two', 'three') }}
{# safe prints the input without escaping it first#}
{{ '<input name="stuff" />'|safe }}
{{ "there are five words here"|wordcount }}
```

尝试前面的例子，以确切了解每个过滤器的作用。

阅读了这么多关于 Jinja2 的内容，您可能会想：“Jinja2 很酷，但这是一本关于 Flask 的书。给我看看 Flask 的东西！”好的，好的，我可以做到！

根据我们迄今所见，几乎一切都可以在 Flask 中使用而无需修改。由于 Flask 为您管理 Jinja2 环境，因此您不必担心创建文件加载程序之类的事情。但是，您应该知道的一件事是，由于您不是自己实例化 Jinja2 环境，因此您实际上无法将要激活的扩展传递给类构造函数。

要激活扩展程序，请在应用程序设置期间将其添加到 Flask 中，如下所示：

```py
from flask import Flask
app = Flask(__name__)
app.jinja_env.add_extension('jinja2.ext.do')  # or jinja2.ext.with_
if __name__ == '__main__':
  app.run()
```

## 搞乱模板上下文

在第二章中所见，*第一个应用，有多难？*，您可以使用`render_template`方法从`templates`文件夹加载模板，然后将其呈现为响应。

```py
from flask import Flask, render_template
app = Flask(__name__)

@app.route("/")
def hello():
    return render_template("index.html")
```

如果您想向模板上下文添加值，就像本章中的一些示例中所示，您将不得不向`render_template`添加非位置参数：

```py
from flask import Flask, render_template
app = Flask(__name__)

@app.route("/")
def hello():
    return render_template("index.html", my_age=28)
```

在上面的示例中，`my_age`将在`index.html`上下文中可用，其中`{{ my_age }}`将被翻译为 28。`my_age`实际上可以具有您想要展示的任何值。

现在，如果您希望*所有*视图在其上下文中具有特定值，例如版本值-一些特殊代码或函数；您该怎么做？Flask 为您提供了`context_processor`装饰器来实现这一点。您只需注释一个返回字典的函数，然后就可以开始了。例如：

```py
from flask import Flask, render_response
app = Flask(__name__)

@app.context_processor
def luck_processor():
  from random import randint
  def lucky_number():
    return randint(1, 10)
  return dict(lucky_number=lucky_number)

@app.route("/")
def hello():
  # lucky_number will be available in the index.html context by default
  return render_template("index.html")
```

# 总结

在本章中，我们看到了如何仅使用 Jinja2 呈现模板，控制语句的外观以及如何使用它们，如何编写注释，如何在模板中打印变量，如何编写和使用宏，如何加载和使用扩展，以及如何注册上下文处理器。我不知道您怎么看，但这一章节感觉像是大量的信息！我强烈建议您运行示例进行实验。熟悉 Jinja2 将为您节省大量麻烦。

下一章，我们将学习使用 Flask 的表单。期待许多示例和补充代码，因为表单是您从 Web 应用程序打开到 Web 的大门。大多数问题都来自 Web，您的大多数数据也是如此。


# 第四章：请填写这张表格，夫人

你有没有想象过当你在网站上填写表单并点击最后的漂亮的**发送**按钮时会发生什么？好吧，你写的所有数据——评论、名称、复选框或其他任何东西——都会被编码并通过协议发送到服务器，然后服务器将这些信息路由到 Web 应用程序。Web 应用程序将验证数据的来源，读取表单，验证数据的语法和语义，然后决定如何处理它。你看到了吗？那里有一长串事件，每个链接都可能是问题的原因？这就是表单。

无论如何，没有什么可害怕的！Flask 可以帮助你完成这些步骤，但也有专门为此目的设计的工具。在本章中，我们将学习：

+   如何使用 Flask 编写和处理表单

+   如何验证表单数据

+   如何使用 WTForms 验证 Flask 中的表单

+   如何实现跨站点请求伪造保护

这实际上将是一个相当顺利的章节，有很多新信息，但没有复杂的东西。希望你喜欢！

# HTML 表单对于胆小的人

HTML 基本上是 Web 编写的语言。借助称为**标签**的特殊标记，可以为纯文本添加含义和上下文，将其转换为 HTML。对我们来说，HTML 是达到目的的手段。因此，如果你想了解更多，请在你喜欢的浏览器中打开[`www.w3schools.com/html/`](http://www.w3schools.com/html/)。我们没有完全覆盖 HTML 语法，也没有涉及到整个过程中的所有美妙魔法。

虽然我们不会详细介绍 HTML，但我们会专门介绍 HTML；我指的是`<form>`标签。事实是：每当你打开一个网页，有一些空白字段需要填写时，你很可能在填写 HTML 表单。这是从浏览器向服务器传输数据的最简单方式。这是如何工作的？让我们看一个例子：

```py
<!-- example 1 -->
<form method='post' action='.'>
<input type='text' name='username' />
<input type='password' name='passwd' />
<input type='submit' />
</form>
```

在上面的例子中，我们有一个完整的登录表单。它的开始由`<form>`标签定义，具有两个非必需的属性：`method`和`action`。`method`属性定义了当发送表单数据时你希望数据如何发送到服务器。它的值可以是`get`或`post`。只有当表单数据很小（几百个字符）、不敏感（如果其他人看到它并不重要）且表单中没有文件时，才应该使用`get`，这是默认值。这些要求存在的原因是，当使用`get`时，所有表单数据将被编码为参数附加到当前 URL 之后再发送。在我们的例子中，选择的方法是`post`，因为我们的输入字段之一是密码，我们不希望其他人查看我们的密码。使用`get`方法的一个很好的用例是搜索表单。例如：

```py
<!-- example 2 -->
<form action='.'>
<input type='search' name='search' />
</form>
```

在`示例 2`中，我们有一个简单的搜索表单。如果我们在`name`输入中填写搜索词`SearchItem`并点击*Enter*，URL 将如下所示：

[`mydomain.com/?search=SearchItem`](http://mydomain.com/?search=SearchItem)

然后，前面的 URL 将保存到浏览器历史记录中，任何有权访问它的人都可以看到上一个用户在搜索什么。对于敏感数据来说，这是不好的。

无论如何，回到*示例 1*。第二个属性`action`对于告诉浏览器应该接收和响应表单数据的 URL 非常有用。我们使用`'.'`作为它的值，因为我们希望表单数据被发送到当前 URL。

接下来的两行是我们的输入字段。输入字段用于收集用户数据，与名称可能暗示的相反，输入字段可以是`input`、`textarea`或`select`元素。在使用输入字段时，始终记得使用属性`name`对它们进行命名，因为这有助于在 Web 应用程序中处理它们。

在第三行，我们有一个特殊的输入字段，它不一定有任何要发送的数据，即提交输入按钮。默认情况下，如果在`input`元素具有焦点时按下*Enter*，或者按下提交按钮，表单将被发送。我们的*示例 1*是后者。

哇！终于，我们的表单已经编写和解释完毕。有关输入字段可能类型的详尽列表，请查看[`www.w3schools.com/tags/tag_input.asp`](http://www.w3schools.com/tags/tag_input.asp)。

# 处理表单

现在让我们看看如何将*示例 1*中的表单与应用程序集成：

```py
# coding:utf-8

from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/', methods=['get', 'post'])
def login_view():
    # the methods that handle requests are called views, in flask
    msg = ''

    # form is a dictionary like attribute that holds the form data
    if request.method == 'POST':
      username = request.form["username"]
        passwd = request.form["passwd"]

        # static useless validation
        if username == 'you' and passwd == 'flask':
            msg = 'Username and password are correct'
        else:
            msg = 'Username or password are incorrect'
    return render_template('form.html', message=msg)

if __name__=='__main__':
    app.run()
```

在前面的例子中，我们定义了一个名为`login_view`的视图，该视图接受`get`或`post`请求；当请求为`post`时（如果是由`get`请求发送的表单，则我们忽略该表单），我们获取`username`和`passwd`的值；然后我们运行一个非常简单的验证，并相应地更改`msg`的值。

### 提示

注意：在 Flask 中，视图不同于 MVC 中的视图。在 Flask 中，视图是接收请求并返回响应的组件，可以是函数或类。

您看到我们在示例中处理的`request`变量了吗？这是当前活动`request`上下文的代理。这就是为什么`request.form`指向发送的表单数据。

现在，如果您收到一个编码在 URL 中的参数，您将如何获取它，考虑到请求 URL 是`http://localhost:5000/?page=10`？

```py
# inside a flask view
def some_view():
    try:
        page = int(request.args.get('page', 1))
        assert page == 10
    except ValueError:
        page = 1
    ...
```

在分页时，前面的例子是非常常见的。与以前一样，`request.args`只与当前用户请求相关。很简单！

到目前为止，我们用内联验证处理表单验证非常糟糕。不再这样做了！让我们从现在开始尝试一些更花哨的东西。

# WTForms 和你

WTForms（[`github.com/wtforms/wtforms`](https://github.com/wtforms/wtforms)）是一个独立的强大的表单处理库，允许您从类似表单的类生成 HTML 表单，实现字段和表单验证，并包括跨源伪造保护（黑客可能尝试在您的 Web 应用程序中利用的一个恶意漏洞）。我们当然不希望发生这种情况！

首先，要安装 WTForms 库，请使用以下命令：

```py
pip install wtforms

```

现在让我们编写一些表单。WTForms 表单是扩展`Form`类的类。就是这么简单！让我们创建一个登录表单，可以与我们之前的登录示例一起使用：

```py
from wtforms import Form, StringField, PasswordField
class LoginForm(Form):
    username = StringField(u'Username:')
    passwd = PasswordField(u'Password:')
```

在前面的代码中，我们有一个带有两个字段`username`和`passwd`的表单，没有验证。只需在模板中构建一个表单就足够了，就像这样：

```py
<form method='post'>
{% for field in form %}
    {{ field.label }}
    {{ field }}
    {% if field.errors %}
        {% for error in field.errors %}
            <div class="field_error">{{ error }}</div>
        {% endfor %}
    {% endif %}
{% endfor %}
</form>
```

如前面的代码所示，您可以迭代 WTForms 表单的字段，每个字段都有一些有用的属性，您可以使用这些属性使您的 HTML 看起来很好，比如`label`和`errors`。`{{ field }}`将为您呈现一个普通的 HTML 输入元素。有些情况下，您可能希望为输入元素设置特殊属性，例如`required`，告诉浏览器如果为空，则不应提交给定字段。为了实现这一点，调用`field`作为一个函数，就像这样：

```py
{% if field.flags.required %}
{{ field(required='required') }}
{% endif %}
```

您可以根据示例传递任何所需的参数，如`placeholder`或`alt`。Flask-Empty（[`github.com/italomaia/flask-empty`](https://github.com/italomaia/flask-empty)）在其宏中有一个很好的示例。

WTForms 使用标志系统，以允许您检查何时对字段应用了一些验证。如果字段有一个`required`验证规则，`fields.flags`属性中的`required`标志将设置为 true。但是 WTForms 验证是如何工作的呢？

在 Flask 中，验证器是您添加到`validators`字段的可调用对象，或者是格式为`validate_<field>(form, field)`的类方法。它允许您验证字段数据是否符合要求，否则会引发`ValidationError`，解释出了什么问题。让我们看看我们漂亮的登录表单示例如何进行一些验证：

```py
# coding:utf-8
from wtforms import Form, ValidationError
from wtforms import StringField, PasswordField
from wtforms.validators import Length, InputRequired
from werkzeug.datastructures import MultiDict

import re

def is_proper_username(form, field):
    if not re.match(r"^\w+$", field.data):
        msg = '%s should have any of these characters only: a-z0-9_' % field.name
        raise ValidationError(msg)

class LoginForm(Form):
    username = StringField(
        u'Username:', [InputRequired(), is_proper_username, Length(min=3, max=40)])
    password = PasswordField(
        u'Password:', [InputRequired(), Length(min=5, max=12)])

    @staticmethod
    def validate_password(form, field):
        data = field.data
        if not re.findall('.*[a-z].*', data):
            msg = '%s should have at least one lowercase character' % field.name
            raise ValidationError(msg)
        # has at least one uppercase character
        if not re.findall('.*[A-Z].*', data):
            msg = '%s should have at least one uppercase character' % field.name
            raise ValidationError(msg)
        # has at least one number
        if not re.findall('.*[0-9].*', data):
            msg = '%s should have at least one number' % field.name
            raise ValidationError(msg)
        # has at least one special character
        if not re.findall('.*[^ a-zA-Z0-9].*', data):
            msg = '%s should have at least one special character' % field.name
            raise ValidationError(msg)

# testing our form
form = LoginForm(MultiDict([('username', 'italomaia'), ('password', 'lL2m@msbb')]))
print form.validate()
print form.errors
```

在上述代码中，我们有一个完整的表单示例，带有验证，使用类、方法和函数作为验证器以及一个简单的测试。我们的每个字段的第一个参数是字段标签。第二个参数是在调用`form.validate`方法时要运行的验证器列表（这基本上就是`form.validate`做的事情）。每个字段验证器都会按顺序运行，如果发现错误，则会引发`ValidationError`（并停止验证链调用）。

每个验证器都接收表单和字段作为参数，并必须使用它们进行验证。如`validate_password`所示，它是因为命名约定而为字段`password`调用的。`field.data`保存字段输入，因此您通常可以只验证它。

让我们了解每个验证器：

+   `Length`：验证输入值的长度是否在给定范围内（最小、最大）。

+   `InputRequired`：验证字段是否接收到值，任何值。

+   `is_proper_username`：验证字段值是否与给定的正则表达式匹配。（还有一个内置验证器，用于将正则表达式与给定值匹配，称为**Regexp**。您应该尝试一下。）

+   `validate_password`：验证字段值是否符合给定的正则表达式规则组。

在我们的示例测试中，您可能已经注意到了使用`werkzeug`库中称为`MultiDict`的特殊类似字典的类。它被使用是因为`formdata`参数，它可能接收您的`request.form`或`request.args`，必须是`multidict-type`。这基本上意味着您不能在这里使用普通字典。

调用`form.validate`时，将调用所有验证器。首先是字段验证器，然后是`class`方法字段验证器；`form.errors`是一个字典，其中包含在调用 validate 后找到的所有字段错误。然后您可以对其进行迭代，以在模板、控制台等中显示您找到的内容。

# Flask-WTF

Flask 使用扩展以便与第三方库透明集成。WTForms 与 Flask-WTF 是这样的一个很好的例子，我们很快就会看到。顺便说一句，Flask 扩展是一段代码，以可预测的方式与 Flask 集成其配置、上下文和使用。这意味着扩展的使用方式非常相似。现在确保在继续之前在您的虚拟环境中安装了 Flask-WTF：

```py
# oh god, so hard... not!
pip flask-wtf

```

从[`flask-wtf.readthedocs.org/`](http://flask-wtf.readthedocs.org/)，项目网站，我们得到了 Flask-WTF 提供的以下功能列表：

+   与 WTForms 集成

+   使用 CSRF 令牌保护表单

+   与 Flask-Uploads 一起工作的文件上传

+   全局 CSRF 保护

+   Recaptcha 支持

+   国际化集成

我们将在本章中看到前两个功能，而第三个将在第十章中讨论，*现在怎么办？*。最后三个功能将不在本书中涵盖。我们建议您将它们作为作业进行探索。

## 与 WTForms 集成

Flask-WTF 在集成时使用了关于`request`的小技巧。由于`request`实现了对当前请求和请求数据的代理，并且在`request`上下文中可用，扩展`Form`默认会获取`request.form`数据，节省了一些输入。

我们的`login_view`示例可以根据迄今为止讨论的内容进行重写，如下所示：

```py
# make sure you're importing Form from flask_wtf and not wtforms
from flask_wtf import Form

# --//--
@app.route('/', methods=['get', 'post'])
def login_view():
    # the methods that handle requests are called views, in flask
    msg = ''
    # request.form is passed implicitly; implies POST
    form = LoginForm()
    # if the form should also deal with form.args, do it like this:
    # form = LoginForm(request.form or request.args)

    # checks that the submit method is POST and form is valid
    if form.validate_on_submit():
        msg = 'Username and password are correct'
    else:
        msg = 'Username or password are incorrect'
    return render_template('form.html', message=msg)
```

我们甚至可以更进一步，因为我们显然是完美主义者：

```py
# flash allows us to send messages to the user template without
# altering the returned context
from flask import flash
from flask import redirect
@app.route('/', methods=['get', 'post'])
def login_view():
    # msg is no longer necessary. We will use flash, instead
    form = LoginForm()

    if form.validate_on_submit():
        flash(request, 'Username and password are correct')
        # it's good practice to redirect after a successful form submit
        return redirect('/')
    return render_template('form.html', form=form)
```

在模板中，将`{{ message }}`替换为：

```py
{# 
beautiful example from 
http://flask.pocoo.org/docs/0.10/patterns/flashing/#simple-flashing 
#}
{% with messages = get_flashed_messages() %}
  {% if messages %}
    <ul class='messages'>
    {% for message in messages %}
      <li>{{ message }}</li>
    {% endfor %}
    </ul>
  {% endif %}
{% endwith %}
```

`get_flashed_messages`默认在模板上下文中可用，并为当前用户提供尚未显示的所有闪现消息。然后我们使用`with`缓存它，检查它是否不为空，然后对其进行迭代。

### 提示

闪现消息在重定向时特别有用，因为它们不受响应上下文的限制。

## 使用 CSRF 令牌保护表单

**跨站点请求伪造**（**CSRF**）发生在一个网站试图利用另一个网站对你的浏览器的信任（假设你是用户）时。基本上，你正在访问的网站会尝试获取或更改你已经访问并进行身份验证的网站的信息。想象一下，你正在访问一个网站，该网站有一张图片，加载了你已经进行身份验证的另一个网站的 URL；想象一下，给定的 URL 请求了前一个网站的一个动作，并且该动作改变了你的账户的某些内容——例如，它的状态被修改为非活动状态。嗯，这就是 CSRF 攻击的一个简单案例。另一个常见的情况是发送 JSONP 请求。如果被攻击的网站，也就是你没有访问的那个网站，接受 JSONP 表单替换（JSONP 用于跨域请求）并且没有 CRSF 保护，那么你将面临更加恶劣的攻击。

WTForms 自带 CSRF 保护；Flask-WTF 将整个过程与 Flask 粘合在一起，使你的生活更轻松。为了在使用该扩展时具有 CSRF 保护，你需要设置`secret_key`，就是这样：

```py
app.secret_key = 'some secret string value' # ex: import os; os.urandom(24)
```

然后，每当你编写一个应该具有 CSRF 保护的表单时，只需确保向其中添加 CSRF 令牌，就像这样：

```py
<form method='post'>{{ form.csrf_token }}
{% for field in form if field.name != 'csrf_token' %}
    <div class="field">
    {{ field.label }} {{ field }}
    </div>
    {% if field.errors %}
        {% for error in field.errors %}
        <div class="field_error">{{ error }}</div>
        {% endfor %}
    {% endif %}
{% endfor %}
<input type='submit' />
</form>
```

当表单被接收时，CSRF 令牌会与用户会话中注册的内容进行检查。如果它们匹配，表单的来源就是安全的。这是一种安全的方法，因为一个网站无法读取另一个网站设置的 cookie。

在不希望表单受到 CSRF 保护的情况下，不要添加令牌。如果希望取消对表单的保护，必须关闭表单的 CSRF 保护，就像这样：

```py
form = Form(csrf_enabled=False)
```

在使用`get`方法但同时又使用表单进行验证的搜索字段的情况下，*可能*需要取消对表单的保护。

## 挑战

创建一个 Web 应用程序，接收一个名字，然后回答：“你好，<NAME>”。如果表单为空发送，应显示错误消息。如果给定的名字是“查克·诺里斯”，答案应该是“旋风踢！”。

创建一个 Web 应用程序，显示一张图片，并询问用户看到了什么。然后应用程序应验证答案是否正确。如果不正确，向用户显示错误消息。否则，祝贺用户并显示一张新图片。使用 Flask-WTF。

创建一个具有四种运算的计算器。它应该有用户可以点击的所有数字和运算符。确保它看起来像一个计算器（因为我们是完美主义者！），并且在用户尝试一些恶意操作时进行投诉，比如将 0 除以 0。

# 总结

学到了这么多...我能说什么呢！试试看也没什么坏处，对吧？嗯，我们已经学会了如何编写 HTML 表单；使用 Flask 读取表单；编写 WTForms 表单；使用纯 Python 和表单验证器验证表单数据；以及编写自定义验证器。我们还看到了如何使用 Flask-WTF 来编写和验证我们的表单，以及如何保护我们的应用程序免受 CSRF 攻击。

在下一章中，我们将看看如何使用出色、易于使用的库将 Web 应用程序数据存储在关系型和非关系型数据库中，并如何将它们与 Flask 集成。还将进行数据库的简要概述，以便更顺畅地吸收知识。


# 第五章：你把东西放在哪里？

我就像一只松鼠。我偶尔会在家里的秘密藏匿处留下一些钱，以防我被抢劫，或者在一个月里花费太多。我真的忘记了我所有的藏匿处在哪里，这有点有趣也有点悲哀（对我来说）。

现在，想象一下，你正在存储一些同样重要甚至更重要的东西，比如客户数据或者甚至你公司的数据。你能允许自己将它存储在以后可能会丢失或者可以被某人干扰的地方吗？我们正处于信息时代；信息就是力量！

在网络应用程序世界中，我们有两个大的数据存储玩家：**关系数据库**和**NoSQL 数据库**。第一种是传统的方式，其中您的数据存储在表和列中，事务很重要，期望有 ACID，规范化是关键（双关语）！它使用**SQL**来存储和检索数据。在第二种方式中，情况变得有点疯狂。您的数据可能存储在不同的结构中，如文档、图形、键值映射等。写入和查询语言是特定于供应商的，您可能不得不放弃 ACID 以换取速度，大量的速度！

你可能已经猜到了！这一章是关于**MVC**中的**M**层，也就是如何以透明的方式存储和访问数据的章节！我们将看一下如何使用查询和写入两种数据库类型的示例，以及何时选择使用哪种。

### 提示

ACID 是原子性、一致性、隔离性和持久性的缩写。请参考[`en.wikipedia.org/wiki/ACID`](http://en.wikipedia.org/wiki/ACID)了解一个舒适的定义和概述。

# SQLAlchemy

SQLAlchemy 是一个与关系数据库一起工作的惊人库。它是由 Pocoo 团队制作的，他们也是 Flask 的创始人，被认为是“事实上”的 Python SQL 库。它可以与 SQLite、Postgres、MySQL、Oracle 和所有 SQL 数据库一起使用，这些数据库都有兼容的驱动程序。

SQLite 自称为一个自包含、无服务器、零配置和事务性 SQL 数据库引擎（[`sqlite.org/about.html`](https://sqlite.org/about.html)）。其主要目标之一是成为应用程序和小型设备的嵌入式数据库解决方案，它已经做到了！它也非常容易使用，这使得它非常适合我们的学习目的。

尽管所有的例子都将以 SQLite 为主要考虑对象进行给出和测试，但它们应该在其他数据库中也能够以很少或没有改动的方式工作。在适当的时候，将会不时地给出特定于数据库的提示。

### 注意

请参考[`www.w3schools.com/sql/default.asp`](http://www.w3schools.com/sql/default.asp)了解广泛的 SQL 参考。

在我们的第一个例子之前，我们是否应该复习一下几个关系数据库的概念？

## 概念

**表**是低级抽象结构，用于存储数据。它由**列**和**行**组成，其中每一列代表数据的一部分，每一行代表一个完整的记录。通常，每个表代表一个类模型的低级抽象。

**行**是给定类模型的单个记录。您可能需要将多个行记录分散到不同的表中，以记录完整的信息。一个很好的例子是**MxN 关系**。

**列**代表存储的数据本身。每一列都有一个特定的类型，并且只接受该类型的输入数据。您可以将其视为类模型属性的抽象。

**事务**是用来将要执行的操作分组的方式。它主要用于实现原子性。这样，没有操作是半途而废的。

**主键**是一个数据库概念，记录的一部分数据用于标识数据库表中的给定记录。通常由数据库通过约束来实现。

**外键**是一个数据库概念，用于在不同表之间标识给定记录的一组数据。它的主要用途是在不同表的行之间构建关系。通常由数据库通过约束来实现。

在使用关系数据库时的一个主要关注点是数据规范化。在关系数据库中，相关数据存储在不同的表中。您可能有一个表来保存一个人的数据，一个表来保存这个人的地址，另一个表来保存他/她的汽车，等等。

每个表都与其他表隔离，通过外键建立的关系可以检索相关数据！数据规范化技术是一组规则，用于允许数据在表之间适当分散，以便轻松获取相关表，并将冗余保持最小。

### 提示

请参考[`en.wikipedia.org/wiki/Database_normalization`](http://en.wikipedia.org/wiki/Database_normalization)了解数据库规范化的概述。

有关规范形式的概述，请参阅以下链接：

[`en.wikipedia.org/wiki/First_normal_form`](http://en.wikipedia.org/wiki/First_normal_form)

[`en.wikipedia.org/wiki/Second_normal_form`](http://en.wikipedia.org/wiki/Second_normal_form)

[`en.wikipedia.org/wiki/Third_normal_form`](http://en.wikipedia.org/wiki/Third_normal_form)

我们现在可以继续了！

## 实际操作

让我们开始将库安装到我们的环境中，并尝试一些示例：

```py
pip install sqlalchemy

```

我们的第一个示例！让我们为一家公司（也许是你的公司？）创建一个简单的员工数据库：

```py
from sqlalchemy import create_engine
db = create_engine('sqlite:///employees.sqlite')
# echo output to console
db.echo = True

conn = db.connect()

conn.execute("""
CREATE TABLE employee (
  id          INTEGER PRIMARY KEY,
  name        STRING(100) NOT NULL,
  birthday    DATE NOT NULL
)""")

conn.execute("INSERT INTO employee VALUES (NULL, 'marcos mango', date('1990-09-06') );")
conn.execute("INSERT INTO employee VALUES (NULL, 'rosie rinn', date('1980-09-06') );")
conn.execute("INSERT INTO employee VALUES (NULL, 'mannie moon', date('1970-07-06') );")
for row in conn.execute("SELECT * FROM employee"):
    print row
# give connection back to the connection pool
conn.close()
```

前面的例子非常简单。我们创建了一个 SQLAlchemy 引擎，从**连接池**中获取连接（引擎会为您处理），然后执行 SQL 命令来创建表，插入几行数据并查询是否一切都如预期发生。

### 提示

访问[`en.wikipedia.org/wiki/Connection_pool`](http://en.wikipedia.org/wiki/Connection_pool)了解连接池模式概述。（这很重要！）

在我们的插入中，我们为主键`id`提供了值`NULL`。请注意，SQLite 不会使用`NULL`填充主键；相反，它会忽略`NULL`值，并将列设置为新的、唯一的整数。这是 SQLite 特有的行为。例如，**Oracle**将要求您显式插入序列的下一个值，以便为主键设置一个新的唯一列值。

我们之前的示例使用了一个名为**autocommit**的功能。这意味着每次执行方法调用都会立即提交到数据库。这样，您无法一次执行多个语句，这在现实世界的应用程序中是常见的情况。

要一次执行多个语句，我们应该使用**事务**。我们可以通过事务重写我们之前的示例，以确保所有三个插入要么一起提交，要么根本不提交（严肃的表情...）。

```py
# we start our transaction here
# all actions now are executed within the transaction context
trans = conn.begin()

try:
    # we are using a slightly different insertion syntax for convenience, here; 
    # id value is not explicitly provided
    conn.execute("INSERT INTO employee (name, birthday) VALUES ('marcos mango', date('1990-09-06') );")
    conn.execute("INSERT INTO employee (name, birthday) VALUES ('rosie rinn', date('1980-09-06') );")
    conn.execute("INSERT INTO employee (name, birthday) VALUES ('mannie moon', date('1970-07-06') );")
    # commit all
    trans.commit()
except:
    # all or nothing. Undo what was executed within the transaction
    trans.rollback()
    raise
```

到目前为止还没有什么花哨的。在我们的例子中，我们从连接创建了一个事务，执行了一些语句，然后提交以完成事务。如果在事务开始和结束之间发生错误，`except`块将被执行，并且在事务中执行的所有语句将被回滚或“撤消”。

我们可以通过在表之间创建关系来完善我们的示例。想象一下，我们的员工在公司档案中注册了一个或多个地址。我们将创建一个 1xN 关系，其中一个员工可以拥有一个或多个地址。

```py
# coding:utf-8
from sqlalchemy import create_engine

engine = create_engine('sqlite:///employees.sqlite')
engine.echo = True

conn = engine.connect()

conn.execute("""
CREATE TABLE employee (
  id          INTEGER PRIMARY KEY,
  name        STRING(100) NOT NULL,
  birthday    DATE NOT NULL
)""")

conn.execute("""
CREATE TABLE address(
  id      INTEGER PRIMARY KEY,
  street  STRING(100) NOT NULL,
  number  INTEGER,
  google_maps STRING(255),
  id_employee INTEGER NOT NULL,
  FOREIGN KEY(id_employee) REFERENCES employee(id)
)""")

trans = conn.begin()
try:
    conn.execute("INSERT INTO employee (name, birthday) VALUES ('marcos mango', date('1990-09-06') );")
    conn.execute("INSERT INTO employee (name, birthday) VALUES ('rosie rinn', date('1980-09-06') );")
    conn.execute("INSERT INTO employee (name, birthday) VALUES ('mannie moon', date('1970-07-06') );")
    # insert addresses for each employee
    conn.execute(
        "INSERT INTO address (street, number, google_maps, id_employee) "
        "VALUES ('Oak', 399, '', 1)")
    conn.execute(
        "INSERT INTO address (street, number, google_maps, id_employee) "
        "VALUES ('First Boulevard', 1070, '', 1)")
    conn.execute(
        "INSERT INTO address (street, number, google_maps, id_employee) "
        "VALUES ('Cleveland, OH', 10, 'Cleveland,+OH,+USA/@41.4949426,-81.70586,11z', 2)")
    trans.commit()
except:
    trans.rollback()
    raise

# get marcos mango addresses
for row in conn.execute("""
  SELECT a.street, a.number FROM employee e
  LEFT OUTER JOIN address a
  ON e.id = a.id_employee
  WHERE e.name like '%marcos%';
  """):
    print "address:", row
conn.close()
```

在我们新的和更新的示例中，我们记录了一些员工的地址，确保使用正确的外键值（`id_employee`），然后我们使用`LEFT JOIN`查找名为`'marcos mango'`的员工的地址。

我们已经看到了如何创建表和关系，运行语句来查询和插入数据，并使用 SQLAlchemy 进行事务处理；我们还没有完全探索 SQLAlchemy 库的强大功能。

SQLAlchemy 具有内置的 ORM，允许您像使用本机对象实例一样使用数据库表。想象一下，读取列值就像读取实例属性一样，或者通过方法查询复杂的表关系，这就是 SQLAlchemy 的 ORM。

让我们看看使用内置 ORM 的示例会是什么样子：

```py
# coding:utf-8

from sqlalchemy import create_engine
from sqlalchemy import Column, Integer, String, Date, ForeignKey
from sqlalchemy.orm import sessionmaker, relationship, backref
from sqlalchemy.ext.declarative import declarative_base

from datetime import datetime

engine = create_engine('sqlite:///employees.sqlite')
engine.echo = True

# base class for our models
Base = declarative_base()

# we create a session binded to our engine
Session = sessionmaker(bind=engine)

# and then the session itself
session = Session()

# our first model
class Address(Base):
    # the table name we want in the database
    __tablename__ = 'address'

    # our primary key
    id = Column(Integer, primary_key=True)
    street = Column(String(100))
    number = Column(Integer)
    google_maps = Column(String(255))
    # our foreign key to employee
    id_employee = Column(Integer, ForeignKey('employee.id'))

    def __repr__(self):
         return u"%s, %d" % (self.street, self.number)

class Employee(Base):
    __tablename__ = 'employee'

    id = Column(Integer, primary_key=True)
    name = Column(String(100))
    birthday = Column(Date)
    # we map 
    addresses = relationship("Address", backref="employee")

    def __repr__(self):
         return self.name

# create our database from our classes
Base.metadata.create_all(engine)

# execute everything inside a transaction
session.add_all([
        Employee(name='marcos mango', birthday=datetime.strptime('1990-09-06', '%Y-%m-%d')), 
        Employee(name='rosie rinn', birthday=datetime.strptime('1980-09-06', '%Y-%m-%d')),
        Employee(name='mannie moon', birthday=datetime.strptime('1970-07-06', '%Y-%m-%d'))
    ])
session.commit()

session.add_all([
    Address(street='Oak', number=399, google_maps='', id_employee=1),
    Address(street='First Boulevard', number=1070, google_maps='', id_employee=1),
    Address(street='Cleveland, OH', number=10, 
             google_maps='Cleveland,+OH,+USA/@41.4949426,-81.70586,11z', id_employee=2)
])
session.commit()

# get marcos, then his addresses
marcos = session.query(Employee).filter(Employee.name.like(r"%marcos%")).first()
for address in marcos.addresses:
    print 'Address:', address
```

前面的示例介绍了相当多的概念。首先，我们创建了我们的引擎，即第一个示例中使用的 SQLAlchemy 引擎，然后我们创建了我们的基本模型类。虽然`Employee`将被`create_all`映射到一个名为`employee`的表中，但每个定义的`Column`属性都将被映射到数据库中给定表的列中，并具有适当的约束。例如，对于`id`字段，它被定义为主键，因此将为其创建主键约束。`id_employee`是一个外键，它是对另一个表的主键的引用，因此它将具有外键约束，依此类推。

我们所有的类模型都应该从中继承。然后我们创建一个`session`。会话是您使用 SQLAlchemy ORM 模型的方式。

会话具有内部正在进行的事务，因此它非常容易具有类似事务的行为。它还将您的模型映射到正确的引擎，以防您使用多个引擎；但等等，还有更多！它还跟踪从中加载的所有模型实例。例如，如果您将模型实例添加到其中，然后修改该实例，会话足够聪明，能够意识到其对象的更改。因此，它会将自身标记为脏（内容已更改），直到调用提交或回滚。

在示例中，在找到 marcos 之后，我们可以将"Marcos Mango's"的名字更改为其他内容，比如`"marcos tangerine"`，就像这样：

```py
marcos.name = "marcos tangerine"
session.commit()
```

现在，在`Base.metadata`之后注释掉整个代码，并添加以下内容：

```py
marcos = session.query(Employee).filter(Employee.name.like(r"%marcos%")).first()
marcos_last_name = marcos.name.split(' ')[-1]
print marcos_last_name
```

现在，重新执行示例。Marcos 的新姓氏现在是"tangerine"。神奇！

### 提示

有关使用 SQLAlchemy ORM 进行查询的惊人、超级、强大的参考，请访问[`docs.sqlalchemy.org/en/rel_0_9/orm/tutorial.html#querying`](http://docs.sqlalchemy.org/en/rel_0_9/orm/tutorial.html#querying)。

在谈论了这么多关于 SQLAlchemy 之后，您能否请醒来，因为我们将谈论 Flask-SQLAlchemy，这个扩展将库与 Flask 集成在一起。

## Flask-SQLAlchemy

Flask-SQLAlchemy 是一个轻量级的扩展，它将 SQLAlchemy 封装在 Flask 周围。它允许您通过配置文件配置 SQLAlchemy 引擎，并为每个请求绑定一个会话，为您提供了一种透明的处理事务的方式。让我们看看如何做到这一点。首先，确保我们已经安装了所有必要的软件包。加载虚拟环境后，运行：

```py
pip install flask-wtf flask-sqlalchemy

```

我们的代码应该是这样的：

```py
# coding:utf-8
from flask import Flask, render_template, redirect, flash
from flask_wtf import Form
from flask.ext.sqlalchemy import SQLAlchemy

from wtforms.ext.sqlalchemy.orm import model_form

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/employees.sqlite'
app.config['SQLALCHEMY_ECHO'] = True

# initiate the extension
db = SQLAlchemy(app)

# define our model
class Employee(db.Model):
    __tablename__ = 'employee'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    birthday = db.Column(db.Date, nullable=False)

    def __repr__(self):
        return 'employee %s' % self.name

# create the database
db.create_all()

# auto-generate form for our model
EmployeeForm = model_form(Employee, base_class=Form, field_args={
    'name': {
    'class': 'employee'
  }
})

@app.route("/", methods=['GET', 'POST'])
def index():
    # as you remember, request.POST is implicitly provided as argument
    form = EmployeeForm()

    try:
        if form.validate_on_submit():
            employee = Employee()
            form.populate_obj(employee)
            db.session.add(employee)
            db.session.commit()
            flash('New employee add to database')
            return redirect('/')
    except Exception, e:
        # log e
        db.session.rollback()
        flash('An error occurred accessing the database. Please, contact administration.')

    employee_list=Employee.query.all()
    return render_template('index.html', form=form, employee_list=employee_list)

if __name__ == '__main__':
    app.debug = True
    app.run()
```

前面的示例非常完整。它具有表单验证、CSRF 保护、从模型自动生成的表单以及数据库集成。让我们只关注到目前为止我们还没有提到的内容。

自动生成表单非常方便。使用`model_form`，您可以自省定义的模型类并生成适合该模型的表单类。您还可以通过`model_form`参数`field_args`为字段提供参数，这对于添加元素类或额外验证器非常有用。

您可能还注意到`Employee`扩展了`db.Model`，这是您的 ORM 模型基类。所有您的模型都应该扩展它，以便被`db`所知，它封装了我们的引擎并保存我们的请求感知会话。

在 index 函数内部，我们实例化表单，然后检查它是否通过 POST 提交并且有效。在`if`块内部，我们实例化我们的员工模型，并使用`populate_obj`将表单的值放入模型实例中。我们也可以逐个字段地进行操作，就像这样：

```py
employee.name = form.name.data
employee. birthday = form.birthday.data
```

`populate_obj`只是更方便。在填充模型后，我们将其添加到会话中以跟踪它，并提交会话。在此块中发生任何异常时，我们将其放在一个带有准备回滚的 try/except 块中。

请注意，我们使用`Employee.query`来查询存储在我们数据库中的员工。每个模型类都带有一个`query`属性，允许您从数据库中获取和过滤结果。对`query`的每个过滤调用将返回一个`BaseQuery`实例，允许您堆叠过滤器，就像这样：

```py
queryset = Employee.query.filter_by(name='marcos mango')
queryset = queryset.filter_by(birthday=datetime.strptime('1990-09-06', '%Y-%m-%d'))
queryset.all()  # <= returns the result of both filters applied together
```

这里有很多可能性。为什么不现在就尝试一些例子呢？

### 注意

与 Web 应用程序和数据库相关的最常见的安全问题是**SQL 注入攻击**，攻击者将 SQL 指令注入到您的数据库查询中，获取他/她不应该拥有的权限。SQLAlchemy 的引擎对象“自动”转义您的查询中的特殊字符；因此，除非您明确绕过其引用机制，否则您应该是安全的。

# MongoDB

MongoDB 是一个广泛使用的强大的 NoSQL 数据库。它允许您将数据存储在文档中；一个可变的、类似字典的、类似对象的结构，您可以在其中存储数据，而无需担心诸如“我的数据是否规范化到第三范式？”或“我是否必须创建另一个表来存储我的关系？”等问题。

MongoDB 文档实际上是 BSON 文档，是 JSON 的超集，支持扩展的数据类型。如果您知道如何处理 JSON 文档，您应该不会有问题。

### 提示

如果 JSON 对您毫无意义，只需查看[`www.w3schools.com/json/`](http://www.w3schools.com/json/)。

让我们在本地安装 MongoDB，以便尝试一些例子：

```py
sudo apt-get install mongodb

```

现在，从控制台输入：

```py
mongo

```

您将进入 MongoDB 交互式控制台。从中，您可以执行命令，向数据库添加文档，查询、更新或删除。您可以通过控制台实现的任何语法，也可以通过控制台实现。现在，让我们了解两个重要的 MongoDB 概念：数据库和集合。

在 MongoDB 中，您的文档被分组在集合内，而集合被分组在数据库内。因此，在连接到 MongoDB 后，您应该做的第一件事是选择要使用的数据库。您不需要创建数据库，连接到它就足以创建数据库。对于集合也是一样。您也不需要在使用文档之前定义其结构，也不需要实现复杂的更改命令，如果您决定文档结构应该更改。这里有一个例子：

```py
> use example
switched to db example
> db.employees.insert({name: 'marcos mango', birthday: new Date('Sep 06, 1990')})
WriteResult({ "nInserted" : 1 })
> db.employees.find({'name': {$regex: /marcos/}})
```

在上述代码中，我们切换到示例数据库，然后将一个新文档插入到员工集合中（我们不需要在使用之前创建它），最后，我们使用正则表达式搜索它。MongoDB 控制台实际上是一个 JavaScript 控制台，因此新的`Date`实际上是 JavaScript 类`Date`的实例化。非常简单。

### 提示

如果您不熟悉 JavaScript，请访问[`www.w3schools.com/js/default.asp`](http://www.w3schools.com/js/default.asp)了解一个很好的概述。

我们可以存储任何 JSON 类型的文档，还有其他一些类型。访问[`docs.mongodb.org/manual/reference/bson-types/`](http://docs.mongodb.org/manual/reference/bson-types/)获取完整列表。

关于正确使用 MongoDB，只需记住几个黄金规则：

+   避免将数据从一个集合保留到另一个集合，因为 MongoDB 不喜欢*连接*

+   在 MongoDB 中，将文档值作为列表是可以的，甚至是预期的

+   在 MongoDB 中，适当的文档索引（本书未涉及）对性能至关重要

+   写入比读取慢得多，可能会影响整体性能

## MongoEngine

MongoEngine 是一个非常棒的 Python 库，用于访问和操作 MongoDB 文档，并使用**PyMongo**，MongoDB 推荐的 Python 库。

### 提示

由于 PyMongo 没有**文档对象映射器**（**DOM**），我们不直接使用它。尽管如此，有些情况下 MongoEngine API 将不够用，您需要使用 PyMongo 来实现您的目标。

它有自己的咨询 API 和文档到类映射器，允许您以与使用 SQLAlchemy ORM 类似的方式处理文档。这是一个好事，因为 MongoDB 是无模式的。它不像关系数据库那样强制执行模式。这样，您在使用之前不必声明文档应该是什么样子。MongoDB 根本不在乎！

在实际的日常开发中，确切地知道您应该在文档中存储什么样的信息是一个很好的反疯狂功能，MongoEngine 可以直接为您提供。

由于您的机器上已经安装了 MongoDB，只需安装 MongoEngine 库即可开始使用它编码：

```py
pip install mongoengine pymongo==2.8

```

让我们使用我们的新库将“Rosie Rinn”添加到数据库中：

```py
# coding:utf-8

from mongoengine import *
from datetime import datetime

# as the mongo daemon, mongod, is running locally, we just need the database name to connect
connect('example')

class Employee(Document):
    name = StringField()
    birthday = DateTimeField()

    def __unicode__(self):
        return u'employee %s' % self.name

employee = Employee()
employee.name = 'rosie rinn'
employee.birthday = datetime.strptime('1980-09-06', '%Y-%m-%d')
employee.save()

for e in Employee.objects(name__contains='rosie'):
    print e
```

理解我们的示例：首先，我们使用`example`数据库创建了一个 MongoDB 连接，然后像使用 SQLAlchemy 一样定义了我们的员工文档，最后，我们插入了我们的员工“Rosie”并查询是否一切正常。

在声明我们的`Employee`类时，您可能已经注意到我们必须使用适当的字段类型定义每个字段。如果 MongoDB 是无模式的，为什么会这样？MongoEngine 强制执行每个模型字段的类型。如果您为模型定义了`IntField`并为其提供了字符串值，MongoEngine 将引发验证错误，因为那不是适当的字段值。此外，我们为`Employee`定义了一个`__unicode__`方法，以便在循环中打印员工的姓名。`__repr__`在这里不起作用。

由于 MongoDB 不支持事务（MongoDB 不是 ACID，记住？），MongoEngine 也不支持，我们进行的每个操作都是原子的。当我们创建我们的“Rosie”并调用`save`方法时，“Rosie”立即插入数据库；不需要提交更改或其他任何操作。

最后，我们有数据库查询，我们搜索“Rosie”。要查询所选集合，应使用每个 MongoEngine 文档中可用的`objects`处理程序。它提供了类似 Django 的界面，支持操作，如`contains`，`icontains`，`ne`，`lte`等。有关查询运算符的完整列表，请访问[`mongoengine-odm.readthedocs.org/guide/querying.html#query-operators`](https://mongoengine-odm.readthedocs.org/guide/querying.html#query-operators)。

## Flask-MongoEngine

MongoEngine 本身非常容易，但有人认为事情可以变得更好，于是我们有了 Flask-MongoEngine。它为您提供了三个主要功能：

+   Flask-DebugToolbar 集成（嘿嘿！）

+   类似 Django 的查询集（`get_or_404`，`first_or_404`，`paginate`，`paginate_field`）

+   连接管理

Flask-DebugToolbar 是一个漂亮的 Flask 扩展，受到 Django-DebugToolbar 扩展的启发，它跟踪应用程序在幕后发生的事情，例如请求中使用的 HTTP 标头，CPU 时间，活动 MongoDB 连接的数量等。

类似 Django 的查询是一个很有用的功能，因为它们可以帮助你避免一些无聊的编码。`get_or_404(*args, **kwargs)`查询方法会在未找到要查找的文档时引发 404 HTTP 页面（它在内部使用`get`）。如果你正在构建一个博客，你可能会喜欢在加载特定的文章条目时使用这个小家伙。`first_or_404()`查询方法类似，但适用于集合。如果集合为空，它会引发 404 HTTP 页面。`paginate(page, per_page)`查询实际上是一个非常有用的查询方法。它为你提供了一个开箱即用的分页界面。它在处理大型集合时效果不佳，因为在这些情况下 MongoDB 需要不同的策略，但大多数情况下，它就是你所需要的。`paginate_field(field_name, doc_id, page, per_page)`是 paginate 的更具体版本，因为你将对单个文档字段进行分页，而不是对集合进行分页。当你有一个文档，其中一个字段是一个巨大的列表时，它非常有用。

现在，让我们看一个完整的`flask-mongoengine`示例。首先，在我们的虚拟环境中安装这个库：

```py
pip install flask-mongoengine

```

现在开始编码：

```py
# coding:utf-8

from flask import Flask, flash, redirect, render_template
from flask.ext.mongoengine import MongoEngine
from flask.ext.mongoengine.wtf import model_form
from flask_wtf import Form

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['MONGODB_SETTINGS'] = {
    # 'replicaset': '',
    'db': 'example',
    # 'host': '',
    # 'username': '',
    # 'password': ''
}
db = MongoEngine(app)

class Employee(db.Document):
    name = db.StringField()
    # mongoengine does not support datefield
    birthday = db.DateTimeField()

    def __unicode__(self):
        return u'employee %s' % self.name

# auto-generate form for our model
EmployeeForm = model_form(Employee, base_class=Form, field_args={
    'birthday': {
        # we want to use date format, not datetime
        'format': '%Y-%m-%d'
    }
})

@app.route("/", methods=['GET', 'POST'])
def index():
    # as you remember, request.POST is implicitly provided as argument
    form = EmployeeForm()

    try:
        if form.validate_on_submit():
            employee = Employee()
            form.populate_obj(employee)
            employee.save()
            flash('New employee add to database')
            return redirect('/')
    except:
        # log e
        flash('An error occurred accessing the database. Please, contact administration.')

    employee_list=Employee.objects()
    return render_template('index.html', form=form, employee_list=employee_list)

if __name__ == '__main__':
    app.debug = True
    app.run()
```

我们的 Flask-MongoEngine 示例与 Flask-SQLAlchemy 示例非常相似。除了导入的差异之外，还有 MongoDB 的配置，因为 MongoDB 需要不同的参数；我们有`birthday`字段类型，因为 MongoEngine 不支持`DateField`；有生日格式的覆盖，因为`datetimefield`的默认字符串格式与我们想要的不同；还有`index`方法的更改。

由于我们不需要使用 Flask-MongoEngine 处理会话，我们只需删除所有与它相关的引用。我们还改变了`employee_list`的构建方式。

### 提示

由于 MongoDB 不会解析你发送给它的数据以尝试弄清楚查询的内容，所以你不会遇到 SQL 注入的问题。

# 关系型与 NoSQL

你可能会想知道何时使用关系型数据库，何时使用 NoSQL。嗯，鉴于今天存在的技术和技术，我建议你选择你感觉更适合的类型来工作。NoSQL 吹嘘自己是无模式、可扩展、快速等，但关系型数据库对于大多数需求也是相当快速的。一些关系型数据库，比如 Postgres，甚至支持文档。那么扩展呢？嗯，大多数项目不需要扩展，因为它们永远不会变得足够大。其他一些项目，只需与它们的关系型数据库一起扩展。

如果没有*重要*的原因来选择原生无模式支持或完整的 ACID 支持，它们中的任何一个都足够好。甚至在安全方面，也没有值得一提的大差异。MongoDB 有自己的授权方案，就像大多数关系型数据库一样，如果配置正确，它们都是一样安全的。通常，应用层在这方面更加麻烦。

# 摘要

这一章非常紧凑！我们对关系型和 NoSQL 数据库进行了概述，学习了 MongoDB 和 MongoEngine，SQLite 和 SQLAlchemy，以及如何使用扩展来将 Flask 与它们集成。知识积累得很快！现在你能够创建更复杂的带有数据库支持、自定义验证、CSRF 保护和用户通信的网络应用程序了。

在下一章中，我们将学习关于 REST 的知识，它的优势，以及如何创建服务供应用程序消费。


# 第六章：但是我现在想休息妈妈！

REST 是一种架构风格，由于其许多特性和架构约束（如可缓存性、无状态行为和其接口要求），近年来一直在获得动力。

### 提示

有关 REST 架构的概述，请参阅[`www.drdobbs.com/Web-development/restful-Web-services-a-tutorial/240169069`](http://www.drdobbs.com/Web-development/restful-Web-services-a-tutorial/240169069)和[`en.wikipedia.org/wiki/Representational_state_transfer`](http://en.wikipedia.org/wiki/Representational_state_transfer)。

本章我们将专注于 RESTful Web 服务和 API——即遵循 REST 架构的 Web 服务和 Web API。让我们从开始说起：什么是 Web 服务？

Web 服务是一个可以被你的应用程序查询的 Web 应用程序，就像它是一个 API 一样，提高了用户体验。如果你的 RESTful Web 服务不需要从传统的 UI 界面调用，并且可以独立使用，那么你拥有的是一个**RESTful Web 服务 API**，简称“RESTful API”，它的工作方式就像一个常规 API，但通过 Web 服务器。

对 Web 服务的调用可能会启动批处理过程、更新数据库或只是检索一些数据。对服务可能执行的操作没有限制。

RESTful Web 服务应该通过**URI**（类似于 URL）访问，并且可以通过任何 Web 协议访问，尽管**HTTP**在这里是王者。因此，我们将专注于**HTTP**。我们的 Web 服务响应，也称为资源，可以具有任何所需的格式；如 TXT、XML 或 JSON，但最常见的格式是 JSON，因为它非常简单易用。我们还将专注于 JSON。在使用 HTTP 与 Web 服务时，一种常见的做法是使用 HTTP 默认方法（`GET`、`POST`、`PUT`、`DELETE`和`OPTIONS`）向服务器提供关于我们想要实现的更多信息。这种技术允许我们在同一个服务中拥有不同的功能。

对`http://localhost:5000/age`的服务调用可以通过`GET`请求返回用户的年龄，或通过`DELETE`请求删除其值。

让我们看看每个*通常使用*的方法通常用于什么：

+   `GET`：这用于检索资源。你想要信息？不需要更新数据库？使用 GET！

+   `POST`：这用于将新数据插入服务器，比如在数据库中添加新员工。

+   `PUT`：这用于更新服务器上的数据。你有一个员工决定在系统中更改他的昵称？使用`PUT`来做到这一点！

+   `DELETE`：这是你在服务器上删除数据的最佳方法！

+   `OPTIONS`：这用于询问服务支持哪些方法。

到目前为止，有很多理论；让我们通过一个基于 Flask 的 REST Web 服务示例来实践。

首先，安装示例所需的库：

```py
pip install marshmallow

```

现在，让我们来看一个例子：

```py
# coding:utf-8

from flask import Flask, jsonify
from flask.ext.sqlalchemy import SQLAlchemy

from marshmallow import Schema

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/articles.sqlite'

db = SQLAlchemy(app)

class Article(db.Model):
    __tablename__ = 'articles'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text(), nullable=False)

    def __unicode__(self):
        return self.content

# we use marshmallow Schema to serialize our articles
class ArticleSchema(Schema):
    """
    Article dict serializer
    """
    class Meta:
        # which fields should be serialized?
        fields = ('id', 'title', 'content')

article_schema = ArticleSchema()
# many -> allow for object list dump
articles_schema = ArticleSchema(many=True)

@app.route("/articles/", methods=["GET"])
@app.route("/articles/<article_id>", methods=["GET"])
def articles(article_id=None):
    if article_id:
        article = Article.query.get(article_id)

        if article is None:
            return jsonify({"msgs": ["the article you're looking for could not be found"]}), 404

        result = article_schema.dump(article)
        return jsonify({'article': result})
    else:
        # never return the whole set! As it would be very slow
        queryset = Article.query.limit(10)
        result = articles_schema.dump(queryset)

        # jsonify serializes our dict into a proper flask response
        return jsonify({"articles": result.data})

db.create_all()

# let's populate our database with some data; empty examples are not that cool
if Article.query.count() == 0:
    article_a = Article(title='some title', content='some content')
    article_b = Article(title='other title', content='other content')

    db.session.add(article_a)
    db.session.add(article_b)
    db.session.commit()

if __name__ == '__main__':
    # we define the debug environment only if running through command line
    app.config['SQLALCHEMY_ECHO'] = True
    app.debug = True
    app.run()
```

在前面的示例中，我们创建了一个 Web 服务，使用 GET 请求来查询文章。引入了`jsonify`函数，因为它用于将 Python 对象序列化为 Flask JSON 响应。我们还使用 marshmallow 库将 SQLAlchemy 结果序列化为 Python 字典，因为没有原生 API 可以做到这一点。

让我们逐步讨论这个例子：

首先，我们创建我们的应用程序并配置我们的 SQLAlchemy 扩展。然后定义`Article`模型，它将保存我们的文章数据，以及一个 ArticleSchema，它允许 marshmallow 将我们的文章序列化。我们必须在 Schema Meta 中定义应该序列化的字段。`article_schema`是我们用于序列化单篇文章的模式实例，而`articles_schema`序列化文章集合。

我们的文章视图有两个定义的路由，一个用于文章列表，另一个用于文章详情，返回单篇文章。

在其中，如果提供了`article_id`，我们将序列化并返回请求的文章。如果数据库中没有与`article_id`对应的记录，我们将返回一个带有给定错误和 HTTP 代码 404 的消息，表示“未找到”状态。如果`article_id`为`None`，我们将序列化并返回 10 篇文章。您可能会问，为什么不返回数据库中的所有文章？如果我们在数据库中有 10,000 篇文章并尝试返回那么多，我们的服务器肯定会出问题；因此，避免返回数据库中的所有内容。

这种类型的服务通常由使用 JavaScript（如 jQuery 或 PrototypeJS）的 Ajax 请求来消耗。在发送 Ajax 请求时，这些库会添加一个特殊的标头，使我们能够识别给定请求是否实际上是 Ajax 请求。在我们的前面的例子中，我们为所有 GET 请求提供 JSON 响应。

### 提示

不懂 Ajax？访问[`www.w3schools.com/Ajax/ajax_intro.asp`](http://www.w3schools.com/Ajax/ajax_intro.asp)。

我们可以更加选择性，只对 Ajax 请求发送 JSON 响应。常规请求将收到纯 HTML 响应。要做到这一点，我们需要对视图进行轻微更改，如下所示：

```py
from flask import request
…

@app.route("/articles/", methods=["GET"])
@app.route("/articles/<article_id>", methods=["GET"])
def articles(article_id=None):
    if article_id:
        article = Article.query.get(article_id)

        if request.is_xhr:
            if article is None:
                return jsonify({"msgs": ["the article you're looking for could not be found"]}), 404

            result = article_schema.dump(article)
            return jsonify({'article': result})
        else:
            if article is None:
                abort(404)

            return render_template('article.html', article=article)
    else:
        queryset = Article.query.limit(10)

        if request.is_xhr:
            # never return the whole set! As it would be very slow
            result = articles_schema.dump(queryset)

            # jsonify serializes our dict into a proper flask response
            return jsonify({"articles": result.data})
        else:
            return render_template('articles.html', articles=queryset)
```

`request`对象有一个名为`is_xhr`的属性，您可以检查该属性以查看请求是否实际上是 Ajax 请求。如果我们将前面的代码拆分成几个函数，例如一个用于响应 Ajax 请求，另一个用于响应纯 HTTP 请求，那么我们的前面的代码可能会更好。为什么不尝试重构代码呢？

我们的最后一个示例也可以采用不同的方法；我们可以通过 Ajax 请求加载所有数据，而不向其添加上下文变量来呈现 HTML 模板。在这种情况下，需要对代码进行以下更改：

```py
from marshmallow import Schema, fields
class ArticleSchema(Schema):
    """
      Article dict serializer
      """
      url = fields.Method("article_url")
      def article_url(self, article):
          return article.url()

      class Meta:
          # which fields should be serialized?
          fields = ('id', 'title', 'content', 'url')

@app.route("/articles/", methods=["GET"])
@app.route("/articles/<article_id>", methods=["GET"])
def articles(article_id=None):
    if article_id:
        if request.is_xhr:
            article = Article.query.get(article_id)
            if article is None:
                return jsonify({"msgs": ["the article you're looking for could not be found"]}), 404

            result = article_schema.dump(article)
            return jsonify({'article': result})
        else:
            return render_template('article.html')
    else:
        if request.is_xhr:
            queryset = Article.query.limit(10)
            # never return the whole set! As it would be very slow
            result = articles_schema.dump(queryset)

            # jsonify serializes our dict into a proper flask response
            return jsonify({"articles": result.data})
        else:
            return render_template('articles.html')
```

我们在模式中添加了一个新字段`url`，以便从 JavaScript 代码中访问文章页面的路径，因为我们返回的是一个 JSON 文档而不是 SQLAlchemy 对象，因此无法访问模型方法。

`articles.html`文件将如下所示：

```py
<!doctype html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Articles</title>
</head>
<body>
<ul id="articles">
</ul>

<script type="text/javascript" src="img/jquery-2.1.3.min.js"></script>
<script type="text/javascript">
  // only execute after loading the whole HTML
  $(document).ready(function(){
    $.ajax({
      url:"{{ url_for('.articles') }}",
      success: function(data, textStatus, xhr){
        $(data['articles']).each(function(i, el){
          var link = "<a href='"+ el['url'] +"'>" + el['title'] + "</a>";
          $("#articles").append("<li>" + link + "</li>");
        });}});}); // don't do this in live code
</script>
</body>
</html>
```

在我们的模板中，文章列表是空的；然后在使用 Ajax 调用我们的服务后进行填充。如果您测试完整的示例，Ajax 请求非常快，您甚至可能都没有注意到页面在填充 Ajax 之前是空的。

# 超越 GET

到目前为止，我们已经有了一些舒适的 Ajax 和 RESTful Web 服务的示例，但我们还没有使用服务将数据记录到我们的数据库中。现在试试吧？

使用 Web 服务记录到数据库与我们在上一章中所做的并没有太大的不同。我们将从 Ajax 请求中接收数据，然后检查使用了哪种 HTTP 方法以决定要做什么，然后我们将验证发送的数据并保存所有数据（如果没有发现错误）。在第四章*请填写这张表格，夫人*中，我们谈到了 CSRF 保护及其重要性。我们将继续使用我们的 Web 服务对数据进行 CSRF 验证。诀窍是将 CSRF 令牌添加到要提交的表单数据中。有关示例 HTML，请参见随附的电子书代码。

这是我们的视图支持`POST`，`PUT`和`REMOVE`方法：

```py
@app.route("/articles/", methods=["GET", "POST"])
@app.route("/articles/<int:article_id>", methods=["GET", "PUT", "DELETE"])
def articles(article_id=None):
    if request.method == "GET":
        if article_id:
            article = Article.query.get(article_id)

            if request.is_xhr:
                if article is None:
                    return jsonify({"msgs": ["the article you're looking for could not be found"]}), 404

                result = article_schema.dump(article)
                return jsonify({': result.data})

            return render_template('article.html', article=article, form=ArticleForm(obj=article))
        else:
            if request.is_xhr:
                # never return the whole set! As it would be very slow
                queryset = Article.query.limit(10)
                result = articles_schema.dump(queryset)

                # jsonify serializes our dict into a proper flask response
                return jsonify({"articles": result.data})
    elif request.method == "POST" and request.is_xhr:
        form = ArticleForm(request.form)

        if form.validate():
            article = Article()
            form.populate_obj(article)
            db.session.add(article)
            db.session.commit()
            return jsonify({"msgs": ["article created"]})
        else:
            return jsonify({"msgs": ["the sent data is not valid"]}), 400

    elif request.method == "PUT" and request.is_xhr:
        article = Article.query.get(article_id)

        if article is None:
            return jsonify({"msgs": ["the article you're looking for could not be found"]}), 404

        form = ArticleForm(request.form, obj=article)

        if form.validate():
            form.populate_obj(article)
            db.session.add(article)
            db.session.commit()
            return jsonify({"msgs": ["article updated"]})
        else:
            return jsonify({"msgs": ["the sent data was not valid"]}), 400
    elif request.method == "DELETE" and request.is_xhr:
        article = Article.query.get(article_id)

        if article is None:
            return jsonify({"msgs": ["the article you're looking for could not be found"]}), 404

        db.session.delete(article)
        db.session.commit()
        return jsonify({"msgs": ["article removed"]})

    return render_template('articles.html', form=ArticleForm())
```

好吧，事实就是这样，我们再也不能隐藏了；在同一页中处理 Web 服务和纯 HTML 渲染可能有点混乱，就像前面的例子所示。即使您将函数按方法分割到其他函数中，事情可能看起来也不那么好。通常的模式是有一个视图用于处理 Ajax 请求，另一个用于处理“正常”请求。只有在方便的情况下才会混合使用两者。

# Flask-Restless

Flask-Restless 是一个扩展，能够自动生成整个 RESTful API，支持`GET`、`POST`、`PUT`和`DELETE`，用于你的 SQLAlchemy 模型。大多数 Web 服务不需要更多。使用 Flask-Restless 的另一个优势是可以扩展自动生成的方法，进行身份验证验证、自定义行为和自定义查询。这是一个必学的扩展！

让我们看看我们的 Web 服务在 Flask-Restless 下会是什么样子。我们还需要为这个示例安装一个新的库：

```py
pip install Flask-Restless

```

然后：

```py
# coding:utf-8

from flask import Flask, url_for
from flask.ext.restless import APIManager
from flask.ext.sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/employees.sqlite'

db = SQLAlchemy(app)

class Article(db.Model):
    __tablename__ = 'articles'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.String(255), nullable=False)

    def __unicode__(self):
        return self.content

    def url(self):
        return url_for('.articles', article_id=self.id)

# create the Flask-Restless API manager
manager = APIManager(app, flask_sqlalchemy_db=db)

# create our Article API at /api/articles
manager.create_api(Article, collection_name='articles', methods=['GET', 'POST', 'PUT', 'DELETE'])

db.create_all()

if __name__ == '__main__':
    # we define the debug environment only if running through command line
    app.config['SQLALCHEMY_ECHO'] = True
    app.debug = True
    app.run()
```

在前面的示例中，我们创建了我们的模型，然后创建了一个 Flask-Restless API 来保存所有我们的模型 API；然后我们为`Article`创建了一个带有前缀`articles`的 Web 服务 API，并支持`GET`、`POST`、`PUT`和`DELETE`方法，每个方法都有预期的行为：`GET`用于查询，`POST`用于新记录，`PUT`用于更新，`DELETE`用于删除。

在控制台中，输入以下命令发送 GET 请求到 API，并测试您的示例是否正常工作：

```py
curl http://127.0.0.1:5000/api/articles

```

由于 Flask-Restless API 非常广泛，我们将简要讨论一些对大多数项目非常有用的常见选项。

`create_api`的`serializer`/`deserializer`参数在您需要为模型进行自定义序列化/反序列化时非常有用。使用方法很简单：

```py
manager.create_api(Model, methods=METHODS,
                   serializer=my_serializer,
                   deserializer=my_deserializer)
def my_serializer(instance):
    return some_schema.dump(instance).data

def my_deserializer(data):
    return some_schema.load(data).data
```

您可以使用 marshmallow 生成模式，就像前面的示例一样。

`create_api`的另一个有用的选项是`include_columns`和`exclude_columns`。它们允许您控制 API 返回多少数据，并防止返回敏感数据。当设置`include_columns`时，只有其中定义的字段才会被 GET 请求返回。当设置`exclude_columns`时，只有其中未定义的字段才会被 GET 请求返回。例如：

```py
# both the statements below are equivalents
manager.create_api(Article, methods=['GET'], include_columns=['id', 'title'])
manager.create_api(Article, methods=['GET'], exclude_columns=['content'])
```

# 总结

在本章中，我们学习了 REST 是什么，它的优势，如何创建 Flask RESTful Web 服务和 API，以及如何使用 Flask-Restless 使整个过程顺利运行。我们还概述了 jQuery 是什么，以及如何使用它发送 Ajax 请求来查询我们的服务。这些章节示例非常深入。尝试自己编写示例代码，以更好地吸收它们。

在下一章中，我们将讨论确保软件质量的一种方式：测试！我们将学习如何以各种方式测试我们的 Web 应用程序，以及如何将这些测试集成到我们的编码例程中。到时见！
