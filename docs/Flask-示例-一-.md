# Flask 示例（一）

> 原文：[`zh.annas-archive.org/md5/93A989EF421129FF1EAE9C80E14340DD`](https://zh.annas-archive.org/md5/93A989EF421129FF1EAE9C80E14340DD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

理论上，没有什么是有效的，但每个人都知道为什么。实践中，一切都有效，但没有人知道为什么。在这里，我们结合理论和实践；没有什么有效，也没有人知道为什么！

学习计算机科学必须始终是理论和实践的结合；你需要知道你在做什么（理论），但你也需要知道如何去做（实践）。我学习如何创建 Web 应用程序的经验是，很少有老师找到了这种平衡的甜蜜点；要么我读了很多关于继承、虚拟环境和测试驱动开发的页面，想知道它们如何适用于我，要么我安装了一堆工具、框架和库，看着魔术发生，却不知道它是如何工作的。

接下来的内容，我希望是一个很好的平衡。从第一章开始，你将拥有一个 Flask Web 应用程序，全世界都可以访问，即使它只是用“你好，世界！”来欢迎访客，这也是相当实用的。在接下来的章节中，我们将一起构建三个有趣且有用的项目。总的来说，我们会尽可能地自己构建东西。虽然重新发明轮子不是好事，但在接触解决方案之前接触问题是很好的。在你写一行 CSS 之前学习 CSS 框架会让你感到困惑，你会想，“但我真的需要这个吗？”，对于许多其他框架和工具也是如此。因此，我们将从零开始，看看为什么这很困难，然后介绍工具来让我们的生活变得更容易。我认为这是理论和实践之间的理想平衡。

当我告诉别人我正在写一本关于 Flask 的书时，常见的回答是“为什么？已经有很多关于 Flask 的书和教程了。”这是一个合理的问题，对它的回答为这本书提供了一个很好的概述。《Flask 实例》与其他 Flask 教育材料不同，原因如下。

**我们不会让你陷入困境**

许多 Flask 教程向您展示如何开发一个 Flask 应用程序并在本地计算机上运行它，然后就结束了。这作为第一步是很好的，但如果您有兴趣构建 Web 应用程序，您可能希望它们能够在网络上访问，这样您的朋友、家人、同事和客户就可以在不经过您家的情况下欣赏到您的手工艺品。从我们的第一个项目开始，我们的应用程序将在虚拟专用服务器（VPS）上运行，并且可以被全世界访问。

**我们不会构建博客应用程序**

如果你读过任何 Web 应用程序开发教程，你一定会注意到几乎每一个教程都是关于如何使用 x 和 y 构建一个博客。我对博客示例感到相当厌倦（实际上，我再也不想看到有人告诉我如何构建博客了）。相反，你将学习如何使用 Flask 开发一些有趣、原创，甚至可能有用的项目。

**我们将专注于安全**

最近，网络犯罪已经成为一个热门词汇。可以说，我们几乎每天都会读到关于主要 Web 应用程序被黑客攻击的消息，这是因为很多开发人员不了解 SQL 注入、CSRF、XSS、如何存储密码等许多应该被视为基本知识的东西。在本书中，当我们开发这三个项目时，我们将花时间详细解释一些核心安全概念，并向您展示如何加固我们的应用程序，以防潜在的恶意攻击者。

**我们将提供深入的解释**

我们不仅会给你一些代码然后告诉你去运行它。在任何可能的情况下，我们都会解释我们在做什么，为什么这样做，以及我们是如何做的。这意味着你将能够从所有项目中汲取灵感，将它们与你自己的想法结合起来，在阅读完本书后立即开始构建原创内容。

因此，我希望这本书对你有所帮助，无论你是刚开始涉足计算机科学和编程世界，还是拥有著名大学的计算机科学学位，耳朵里充满了编译器理论，但现在想要构建一些实用和有趣的东西。希望你在完成这些项目时和我在组织它们时一样开心！

# 本书涵盖的内容

第一章，“你好，世界！”，教你如何设置我们的开发环境和 Web 服务器，并编写我们的第一个 Flask 应用程序。

第二章，“开始我们的头条新闻项目”，向您展示了当用户访问 URL 时如何运行 Python 代码以及如何向用户返回基本数据。我们还将看看如何使用 RSS 订阅自动获取最新的头条新闻。

第三章，“在我们的头条新闻项目中使用模板”，介绍了 Jinja 模板，并将它们整合到我们的头条新闻项目中。我们将展示如何通过从 Python 代码传递数据到模板文件来提供动态 HTML 内容。

第四章，“我们头条新闻项目的用户输入”，展示了如何从互联网上获取用户输入，并使用这些输入来定制我们将向用户展示的内容。我们将看看如何通过 JSON API 访问当前天气信息，并将这些信息包含在我们的头条新闻项目中。

第五章，“改善我们的头条新闻项目的用户体验”，指导您向我们的头条新闻项目添加 cookie，以便我们的应用程序可以记住我们用户的选择。我们还将通过添加一些基本的 CSS 来为我们的应用程序添加样式。

第六章，“构建交互式犯罪地图”，介绍了我们的新项目，即犯罪地图。我们将介绍关系数据库，在服务器上安装 MySQL，并了解如何从我们的 Flask 应用程序与我们的数据库交互。

第七章，“向我们的犯罪地图项目添加谷歌地图”，指导您添加谷歌地图小部件，并演示如何根据我们的数据库添加和删除地图上的标记。我们将添加一个带有各种输入的 HTML 表单，供用户提交新的犯罪信息，并显示现有的犯罪信息。

第八章，“在我们的犯罪地图项目中验证用户输入”，通过确保用户不能意外地或通过恶意制作的输入来破坏它，完善了我们的第二个项目。

第九章，“构建服务员呼叫应用程序”，介绍了我们的最终项目，这是一个在餐厅呼叫服务员到餐桌的应用程序。我们将介绍 Bootstrap，并设置一个使用 Bootstrap 作为前端的基本用户账户控制系统。

第十章，“在服务员呼叫项目中使用模板继承和 WTForms”，介绍了 Jinja 的模板继承功能，以便我们可以添加类似的页面而不重复代码。我们将使用 WTForms 库使我们的 Web 表单更容易构建和验证。

第十一章，“在我们的服务员呼叫项目中使用 MongoDB”，讨论了如何在服务器上安装和配置 MongoDB，并将其链接到我们的服务员呼叫项目。我们将通过向我们的数据库添加索引和向我们的应用程序添加一个网站图标来完成我们的最终项目。

附录，*未来的一瞥*，概述了一些重要的主题和技术，我们无法详细介绍，并指出了更多关于这些内容的学习指引。

# 本书需要什么

我们将使用的所有示例都假定您在开发机器上使用 Ubuntu 操作系统，并且可以访问运行 Ubuntu Server 的服务器（我们将在第一章讨论如何设置后者）。如果您强烈偏好另一个操作系统，并且已经设置了 Python 环境（包括 Python 包管理器 pip），那么这些示例将很容易转换。

本书中使用的所有其他软件和库都是免费提供的，我们将在需要时详细演示如何安装和配置它们。

# 本书适合谁

您是否看过 PHP 并讨厌那笨重的语法？或者，您是否看过.Net 并希望它更加开放和灵活？您是否尝试过 Python 中的 GUI 库，并发现它们难以使用？如果您对这些问题的任何一个答案是肯定的，那么这本书就是为您而写的。

本书还适用于那些了解 Python 基础知识并希望学习如何使用它构建具有 Web 前端的强大解决方案的人。

# 约定

在本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是一些这些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："我们可以通过使用`include`指令来包含其他上下文。"

代码块设置如下：

```py
@app.route("/")
def get_news():
return "no news is good news"
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项将以粗体显示：

```py
import feedparserfrom flask import Flask
app = Flask(__name__)BBC_FEED = "http://feeds.bbci.co.uk/news/rss.xml"
```

任何命令行输入或输出都以以下方式书写：

```py
sudo apt-get update
sudo apt-get install git

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，例如菜单或对话框中的单词，会以这样的方式出现在文本中："单击**下一步**按钮将您移至下一个屏幕。"

### 注意

警告或重要说明显示在这样的框中。

### 提示

提示和技巧显示如下。


# 第一章：你好，世界！

你好，读者！让我们开始构建一些 Flask 应用程序。Flask 足够简约，以便为您提供选择和灵活性；与较大的框架不同，您可以选择要做什么，然后操纵 Flask 来完成您的要求，它足够完整，可以直接使用。

我们将一起开发三个 Web 应用程序；第一个很简单，将允许您在构建一个非平凡的 Web 应用程序时熟悉 Flask 和新技术和术语；第二个将让您开始构建一个使用传统 SQL 数据库的 Web 应用程序；最后一个将使用**NoSQL**数据库和前端框架来创建一个有用且外观良好的 Web 应用程序。

在本章中，我们将简要介绍 Flask 是什么，也许更重要的是，它不是什么。我们将继续设置我们的基本开发环境以及 Web 服务器，并安装 Python 包管理器以及 Flask 本身。到本章结束时，我们将有我们第一个应用程序的轮廓，并且按照古老的传统，我们将使用我们的新技能来显示文本“Hello, World!”。

简而言之，我们将涵盖以下主题：

+   介绍 Flask

+   创建我们的开发环境

+   编写“Hello, World！”

+   部署我们的应用程序到生产环境

# 介绍 Flask

Flask 是 Python Web 开发的微框架。框架，简单来说，是一个库或一组库，旨在解决通用问题的一部分，而不是完全特定的问题。在构建 Web 应用程序时，总会有一些问题需要解决，例如从 URL 到资源的路由，将动态数据插入 HTML，以及与最终用户交互。

Flask 是微框架，因为它只实现了核心功能（包括路由），但将更高级的功能（包括身份验证和数据库 ORM）留给了扩展。这样做的结果是对于第一次使用者来说初始设置更少，对于有经验的用户来说有更多的选择和灵活性。这与“更完整”的框架形成对比，例如**Django**，后者规定了自己的 ORM 和身份验证技术。

正如我们将讨论的那样，在 Flask 中，我们的 Hello World 应用程序只需要七行代码就可以编写，整个应用程序只包含一个文件。听起来不错吗？让我们开始吧！

# 创建我们的开发环境

开发环境包括开发人员在构建软件时使用的所有软件。首先，我们将安装 Python 包管理器（**pip**）和 Flask 包。在本书中，我们将展示在**Ubuntu 14.04**的干净安装上使用**Python 2.7**进行开发的详细步骤，但是一切都应该很容易转换到 Windows 或 OS X。

## 安装 pip

对于我们的 Hello World 应用程序，我们只需要 Python Flask 包，但在我们的三个应用程序的开发过程中，我们将安装几个 Python 包。为了管理这些包，我们将使用 Python 包管理器 pip。如果您到目前为止一直在 Python 中开发而没有使用包管理器，您会喜欢使用 pip 下载、安装、删除和更新包的简便性。如果您已经使用它，那么跳到下一步，我们将使用它来安装 Flask。

pip 管理器包含在 Python 的 3.4+和 2.7.9+版本中。对于较旧版本的 Python，需要安装 pip。要在 Ubuntu 上安装 pip，请打开终端并运行以下命令：

```py
sudo apt-get update
sudo apt-get install python-pip

```

### 注意

要在 Windows 或 OS X 上安装 pip，您可以从 pip 主页[`pip.pypa.io/en/latest/installing/#install-or-upgrade-pip`](https://pip.pypa.io/en/latest/installing/#install-or-upgrade-pip)下载并运行`get-pip.py`文件。

就是这样！现在您可以通过 pip 轻松安装任何 Python 包。

## 安装 Flask

通过 pip 安装 Flask 再简单不过了。只需运行以下命令：

```py
pip install –-user flask

```

您可能会在终端中看到一些警告，但最后，您也应该看到**成功安装了 Flask**。现在，您可以像导入其他库一样将 Flask 导入 Python 程序中。

### 注意

如果您习惯于在 Python 开发中使用 VirtualEnv，您可以在 VirtualEnv 环境中安装 Flask。我们将在附录 A.未来的一瞥中进一步讨论这个问题。

# 编写“你好，世界！”

现在，我们将创建一个基本的网页，并使用 Flask 的内置服务器将其提供给`localhost`。这意味着我们将在本地机器上运行一个 Web 服务器，我们可以轻松地从本地机器上发出请求。这对开发非常有用，但不适用于生产应用程序。稍后，我们将看看如何使用流行的 Apache Web 服务器来提供 Flask Web 应用程序。 

## 编写代码

我们的应用程序将是一个单独的 Python 文件。在您的主目录中创建一个名为`firstapp`的目录，然后在其中创建一个名为`hello.py`的文件。在`hello.py`文件中，我们将编写代码来提供一个包含静态字符串“Hello, World!”的网页。代码如下所示：

```py
from flask import Flask

app = Flask(__name__)

@app.route("/")
def index():
    return "Hello, World!"

if __name__ == '__main__':
    app.run(port=5000, debug=True)
```

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接将文件发送到您的电子邮件。

您可以按照以下步骤下载代码文件：

+   使用您的电子邮件地址和密码登录或注册我们的网站。

+   将鼠标指针悬停在顶部的 SUPPORT 标签上。

+   单击“代码下载和勘误”。

+   在搜索框中输入书名。

+   选择您要下载代码文件的书籍。

+   从下拉菜单中选择您购买此书的地方。

+   单击“下载代码”。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR / 7-Zip for Windows

+   Zipeg / iZip / UnRarX for Mac

+   7-Zip / PeaZip for Linux

让我们来分解一下这段代码。第一行应该很熟悉；它只是从`flask`包中导入 Flask。第二行使用我们模块的名称作为参数创建了一个 Flask 对象的实例。Flask 使用这个来解析资源，在复杂的情况下，可以在这里使用其他东西而不是`__name__`。对于我们的目的，我们将始终使用`__name__`，这将我们的模块链接到 Flask 对象。

第 3 行是一个 Python 装饰器。Flask 使用装饰器进行 URL 路由，因此这行代码意味着直接下面的函数应该在用户访问我们网页应用程序的主*根*页面时被调用（由单个斜杠定义）。如果您不熟悉装饰器，这些是美丽的 Python 快捷方式，起初似乎有点像黑魔法。实质上，它们调用一个函数，该函数接受在装饰器下定义的函数（在我们的情况下是`index()`）并返回一个修改后的函数。

接下来的两行也应该很熟悉。它们定义了一个非常简单的函数，返回我们的消息。由于这个函数是由 Flask 在用户访问我们的应用程序时调用的，因此这个返回值将是对请求我们的着陆页面的用户发送的响应。

第 6 行是您可能熟悉的 Python 习语。这是一个简单的条件语句，如果我们的应用程序直接运行，则评估为`True`。它用于防止 Python 脚本在被导入其他 Python 文件时意外运行。

最后一行在我们的本地机器上启动了 Flask 的开发服务器。我们将其设置为在`端口 5000`上运行（我们将在生产中使用`端口 80`），并将调试设置为`True`，这将帮助我们在网页浏览器中直接查看详细的错误。

## 运行代码

要运行我们的开发 Web 服务器，只需打开一个终端并运行`hello.py`文件。如果你使用了前一节中概述的相同结构，命令将如下所示：

```py
cd firstapp/hello
python hello.py

```

你应该得到类似下面截图中的输出：

![运行代码](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_01_01.jpg)

此外，你应该看到进程继续运行。这是我们的网络服务器在等待请求。所以，让我们发出一个请求！

打开一个网络浏览器——我使用的是 Ubuntu 自带的 Firefox——并导航到`localhost:5000`。

URL 中的`localhost`部分是指向回环地址的快捷方式，通常是`127.0.0.1`，它要求你的计算机向自己发出网络请求。冒号后面的数字（`5000`）是它应该发出请求的端口。默认情况下，所有 HTTP（网络）流量都通过`端口 80`进行传输。现在，我们将使用`5000`，因为它不太可能与任何现有服务冲突，但在生产环境中我们将切换到`端口 80`，这是常规的，这样你就不必担心冒号了。

你应该在浏览器中看到“Hello, World!”字符串显示，就像下面的截图一样。恭喜，你已经使用 Flask 构建了你的第一个网络应用！

![运行代码](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_01_02.jpg)

# 将我们的应用部署到生产环境

拥有一个运行的应用程序是很棒的，但作为网络应用程序的概念固有的是我们希望其他人能够使用它。由于我们的应用程序是基于 Python 的，我们在如何在 Web 服务器上运行我们的应用程序方面有一些限制（许多传统的 Web 主机只配置为运行 PHP 和/或.NET 应用程序）。让我们考虑如何使用运行 Ubuntu 服务器、Apache 和 WSGI 的**虚拟专用服务器**（**VPS**）来提供 Flask 应用程序。

从这一点开始，我们将维护*两个*环境。第一个是我们的**开发**环境，我们刚刚设置好，在这里我们将编写代码并使用在`localhost`上运行的 Flask 服务器查看其结果（就像我们刚刚做的那样）。第二个将是**生产**环境。这将是一个服务器，我们可以在其中部署我们的网络应用程序，并使它们对世界可访问。当我们在开发环境安装新的 Python 库或其他软件时，我们通常希望在生产环境中复制我们的操作。

## 设置虚拟专用服务器

尽管理论上你可以在本地主机上托管你的网络应用并允许其他人使用，但这有一些严重的限制。首先，每次关闭电脑时，你的应用都将不可用。此外，你的电脑可能通过互联网服务提供商（ISP）和可能的无线路由器连接到互联网。这意味着你的 IP 地址是动态的，经常会变化，这使得你的应用程序的用户难以跟上！最后，很可能你的互联网连接是不对称的，这意味着你的上传速度比下载速度慢。

在服务器上托管你的应用程序可以解决所有这些问题。在“云”变得流行之前，托管网络应用的传统方式是购买一台物理服务器并找到一个数据中心来托管它。如今，情况简单得多。在几分钟内，你可以启动一个虚拟服务器，对你来说它看起来就像一台物理服务器——你可以登录、配置它，并完全控制它——但实际上它只是云提供商拥有和控制的一台虚拟“片”。

在撰写本文时，云服务提供商领域的主要参与者包括亚马逊网络服务、微软 Azure、谷歌云计算和 Digital Ocean。所有这些公司都允许你按小时支付来租用一个虚拟服务器或多台虚拟服务器。如果你是作为爱好学习 Flask，并且不愿意支付任何人来托管你的网络应用程序，你可能会很容易地在这些提供商中找到一个免费试用。任何提供商的最小服务都足以托管我们将运行的所有应用程序。

选择前述提供商之一或您选择的其他提供商。如果您以前从未做过类似的事情，Digital Ocean 通常被认为是注册并创建新机器的最简单过程。选择提供商后，您应该能够按照其各自的说明启动运行 Ubuntu Server 14.04 并通过 SSH 连接到它的 VPS。您将完全控制该机器，只有一个细微的区别：您将没有显示器或鼠标。

您将在本地终端上输入命令，实际上将在远程机器上运行。有关如何连接到您的 VPS 的详细说明将由提供商提供，但如果您使用 Ubuntu，只需运行以下命令即可：

```py
ssh user@123.456.789.000

```

或者，如果您使用公共-私有密钥身份验证进行设置，其中`yourkey.pem`是您的私钥文件的完整路径，以下是要运行的命令：

```py
ssh user@123.456.78.000 –i yourkey.pem

```

这里，`user`是 VPS 上的默认用户，`yourkey`是您的私钥文件的名称。

**其他操作系统的 SSH：**

### 提示

从 OS X 进行 SSH 应该与 Ubuntu 相同，但如果您使用 Windows，您将需要下载 PuTTY。请参阅[`www.putty.org/`](http://www.putty.org/)进行下载和完整的使用说明。请注意，如果您使用密钥文件进行身份验证，您将需要将其转换为与 PuTTY 兼容的格式。在 PuTTY 网站上也可以找到转换工具。

一旦我们连接到 VPS，安装 Flask 的过程与以前相同：

```py
sudo apt-get update
sudo apt-get install python-pip
pip install --user Flask

```

要安装我们的 Web 服务器 Apache 和 WSGI，我们将运行以下命令：

```py
sudo apt-get install apache2
sudo apt-get install libapache2-mod-wsgi

```

Apache 是我们的 Web 服务器。它将监听 Web 请求（由我们的用户使用他们的浏览器访问我们的 Web 应用程序生成）并将这些请求交给我们的 Flask 应用程序。由于我们的应用程序是用 Python 编写的，我们还需要**WSGI（Web 服务器网关接口）**。

这是 Web 服务器和 Python 应用程序之间的常见接口，它允许 Apache 与 Flask 进行通信，反之亦然。架构概述可以在以下图表中看到：

![设置虚拟专用服务器](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_01_03.jpg)

## 配置我们的服务器

现在我们已经安装了 Apache，我们可以看到我们的第一个结果。您可能习惯于使用 URL 访问网站，例如`http://example.com`。我们将直接使用 VPS 的 IP 地址访问我们的 Web 应用程序。您的 VPS 应该有一个静态的公共地址。静态意味着它不会定期更改，公共意味着它是全局唯一的。当您通过 SSH 连接到 VPS 时，您可能使用了公共 IP 地址。如果找不到它，请在 VPS 上运行以下命令，您应该会在输出中看到一个包含您的公共 IP 的`inet addr`部分：

```py
ifconfig

```

IP 地址应该类似于`123.456.78.9`。将您的 IP 地址输入到浏览器的地址栏中，您应该会看到一个页面，上面写着“**Apache2 Ubuntu 默认页面：It Works!**”或类似的内容，如下面的屏幕截图所示：

![配置我们的服务器](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_01_04.jpg)

这意味着我们现在可以向任何有互联网连接的人提供 Web 内容！但是，我们仍然需要：

+   将我们的代码复制到 VPS

+   连接 Apache 和 Flask

+   配置 Apache 以提供我们的 Flask 应用程序

在第一步中，我们将在本地机器上设置一个 Git 存储库，并将存储库克隆到 VPS。在第二步中，我们将使用与 Apache 一起安装的 WSGI 模块。最后，我们将看一下如何编写虚拟主机，使 Apache 默认提供我们的 Flask 应用程序。

## 安装和使用 Git

Git 是一个版本控制系统。版本控制系统除其他功能外，还会自动保存我们代码库的多个版本。这对于撤消意外更改甚至删除非常有用；我们可以简单地恢复到我们代码的以前版本。它还包括许多分布式开发的功能，即许多开发人员在一个项目上工作。然而，我们主要将其用于备份和部署功能。

要在本地计算机和 VPS 上安装 Git，请在每台计算机上运行以下命令：

```py
sudo apt-get update
sudo apt-get install git

```

### 注意

确保您对使用终端在自己的计算机上运行命令和通过 SSH 连接在服务器上运行命令之间的区别感到满意。在许多情况下，我们需要两次运行相同的命令 - 分别针对每个环境运行一次。

现在您已经拥有了软件，您需要一个托管 Git 存储库或“repos”的地方。两个受欢迎且免费的 Git 托管服务是 GitHub（[`github.com`](http://github.com)）和 Bitbucket（[`bitbucket.org`](http://bitbucket.org)）。前往其中一个，创建一个帐户，并按照提供的说明创建一个新存储库。在给存储库命名的选项时，将其命名为`firstapp`，以匹配我们将用于代码库的目录的名称。创建新存储库后，您应该会得到一个唯一的存储库 URL。请记下这一点，因为我们将使用它来使用`git`推送我们的**Hello, World!**应用程序，然后部署到我们的 VPS。

在本地计算机上，打开终端并将目录更改为 Flask 应用程序。通过以下命令初始化一个新存储库，并将其链接到您的远程 Git 存储库：

```py
cd firstapp
git init
git remote add origin <your-git-url>

```

告诉`git`您是谁，以便它可以自动向您的代码更改添加元数据，如下所示：

```py
git config --global user.email "you@example.com"
git config --global user.name "Your Name"

```

Git 允许您完全控制哪些文件是存储库的一部分，哪些不是。即使我们在`firstapp`目录中初始化了 Git 存储库，我们的存储库目前不包含任何文件。按照以下步骤将我们的应用程序添加到存储库中，提交，然后推送：

```py
git add hello.py
git commit -m "Initial commit"
git push -u origin master

```

这些是我们将在本书中使用的主要 Git 命令，因此让我们简要了解每个命令的作用。`add`命令将新文件或修改的文件添加到我们的存储库中。这告诉 Git 哪些文件实际上是我们项目的一部分。将`commit`命令视为对我们项目当前状态的快照。此快照保存在我们的本地计算机上。对代码库进行重大更改时，最好进行新的`commit`，因为我们可以轻松地恢复到以前的`commits`，如果后来的`commit`破坏了我们的应用程序。最后，`push`命令将我们的本地更改推送到远程 Git 服务器。这对备份很有用，并且还将允许我们在我们的 VPS 上获取更改，从而使我们的本地计算机上的代码库与我们的 VPS 上的代码库保持同步。

现在，再次 SSH 到您的 VPS 并获取我们的代码，如下所示：

```py
cd /var/www
git clone <your-git-url>

```

### 注意

上述命令中的`<your-git-url>`部分实际上是对 Git 存储库的 URL 的占位符。

如果尝试克隆 Git 存储库时出现`permission denied`错误，则可能需要为您正在使用的 Linux 用户的`/var/www`目录所有权。如果您使用`tom@123.456.789.123`登录到服务器，可以运行以下命令，这将使您的用户拥有`/var/www`的所有权，并允许您将 Git 存储库克隆到其中。再次，`tom`是以下情况中使用的占位符：

```py
sudo chown -R tom /var/www

```

如果您将`firstapp`用作远程存储库的名称，则应创建一个名为`firstapp`的新目录。使用以下命令验证我们的代码是否存在：

```py
cd firstapp
ls

```

您应该看到您的`hello.py`文件。现在，我们需要配置 Apache 以使用 WSGI。

## 使用 WSGI 为我们的 Flask 应用提供服务

首先，在我们的应用程序目录中创建一个非常简单的`.wsgi`文件。然后，在 Apache 查找可用站点的目录中创建一个 Apache 配置文件。

这两个步骤中唯一稍微棘手的部分是，我们将直接在我们的 VPS 上创建文件，而我们的 VPS 没有显示器，这意味着我们必须使用命令行界面文本编辑器。当然，我们可以像为我们的代码库做的那样，将文件本地创建然后传输到我们的 VPS，但是对于对配置文件进行小的更改，这往往比值得的努力更多。使用没有鼠标的文本编辑器需要一点时间来适应，但这是一个很好的技能。Ubuntu 上的默认文本编辑器是 Nano，其他流行的选择是 vi 或 Vim。有些人使用 Emacs。如果您已经有喜欢的，就用它。如果没有，我们将在本书的示例中使用 Nano（它已经安装并且可以说是最简单的）。但是，如果您想要更上一层楼，我建议学习使用 Vim。

假设您仍然连接到您的 VPS，并已经像最近的步骤一样导航到`/var/www/firstapp`目录，运行以下命令：

```py
nano hello.wsgi

```

这将创建`hello.wsgi`文件，您现在可以通过 Nano 进行编辑。输入以下内容：

```py
import sys
sys.path.insert(0, "/var/www/firstapp")
from hello import app as application

```

这只是 Python 语法，它将我们的应用程序补丁到 PATH 系统中，以便 Apache 可以通过 WSGI 找到它。然后我们将`app`（我们在`hello.py`应用程序中使用`app = Flask(__name__)`行命名）导入命名空间。

按*Ctrl* + *X*退出 Nano，并在提示时输入*Y*以保存更改。

现在，我们将创建一个 Apache 配置文件，指向我们刚刚创建的`.wsgi`文件，如下所示：

```py
cd /etc/apache2/sites-available
nano hello.conf

```

### 注意

如果您在编辑或保存文件时遇到权限问题，您可能还需要取得`apache2`目录的所有权。运行以下命令，将用户名替换为您的 Linux 用户：

`sudo chown –R tom /etc/apache2`

在这个文件中，我们将为 Apache 虚拟主机创建一个配置。这将允许我们从单个服务器上提供多个站点，这在以后想要使用我们的单个 VPS 来提供其他应用程序时将非常有用。在 Nano 中，输入以下配置：

```py
<VirtualHost *>
    ServerName example.com

    WSGIScriptAlias / /var/www/firstapp/hello.wsgi
    WSGIDaemonProcess hello
    <Directory /var/www/firstapp>
       WSGIProcessGroup hello
       WSGIApplicationGroup %{GLOBAL}
        Order deny,allow
        Allow from all
    </Directory>
</VirtualHost>
```

这可能看起来很复杂，但实际上非常简单。我们将创建一个`virtualhost`并指定我们的域名，我们的`.wsgi`脚本所在的位置，我们的应用程序的名称以及谁被允许访问它。我们将在最后一章讨论域名，但现在，您可以将其保留为`example.com`，因为我们将通过其 IP 地址访问我们的应用程序。

### 注意

如果您在这一步遇到问题，Flask 网站上有一个关于配置和故障排除 Apache 配置的很好的资源。您可以在[`flask.pocoo.org/docs/0.10/deploying/mod_wsgi/`](http://flask.pocoo.org/docs/0.10/deploying/mod_wsgi/)找到它。

按*Ctrl* + *X*，然后在再次提示时输入*Y*以保存并退出文件。现在，我们需要启用配置并将其设置为我们的默认站点。

### 配置 Apache 以提供我们的 Flask 应用程序

Apache 站点的工作方式如下：有一个`sites-available`目录（我们在其中创建了新的虚拟主机配置文件）和一个`sites-enabled`目录，其中包含我们希望处于活动状态的所有配置文件的快捷方式。默认情况下，您会在`sites-available`目录中看到一个名为`000-default.conf`的文件。这就是我们第一次安装 Apache 时看到默认的**It works** Apache 页面的原因。我们不再想要这个了；相反，我们希望使用我们的应用程序作为默认站点。因此，我们将禁用默认的 Apache 站点，启用我们自己的站点，然后重新启动 Apache 以使更改生效。运行以下命令来执行此操作：

```py
sudo a2dissite 000-default.conf
sudo a2ensite hello.conf
sudo service apache2 reload

```

### 注意

所需的 Apache 配置和命令可能会根据您使用的平台而有所不同。如果您使用推荐的 Ubuntu 服务器，上述内容应该都能顺利工作。如果不是，您可能需要稍微了解一下如何为您的特定平台配置 Apache。

您应该注意输出中的`重新加载 web 服务器 apache2`。如果显示错误，则可能在前面的命令中配置错误。如果是这种情况，请仔细阅读错误消息，并返回查看之前的步骤，看看为什么事情没有按预期工作。

为了测试一切是否正常工作，请在本地机器上的 Web 浏览器中打开并再次在地址栏中键入您的 IP 地址。您应该在浏览器中看到**Hello, World!**而不是之前看到的默认 Apache 页面。

如果您收到**错误 500**，这意味着我们的应用程序出现了一些问题。不要担心；最好现在就习惯处理这个错误，因为修复可能会很简单，而不是以后，当我们添加了更多可能出错或配置错误的组件时。要找出出了什么问题，运行以下命令在您的 VPS 上：

```py
sudo tail –f /var/log/apache2/error.log

```

`tail`命令只是输出作为参数传递的文件的最后几行。`-f`是用于跟踪，这意味着如果文件更改，输出将被更新。如果您无法立即确定哪些行是我们正在寻找的错误的指示，再次在本地机器上的 Web 浏览器中访问该站点，您将看到`tail`命令的输出相应地更新。以下截图显示了`tail`命令在没有错误时的输出；但是，如果出了任何问题，您将看到错误输出打印在所有信息消息中。

![配置 Apache 以提供我们的 Flask 应用程序](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_01_05.jpg)

一些可能的绊脚石是错误配置的 WSGI 和 Apache 文件（例如，确保您的`WSGIDaemonProcess`和`daemon name`匹配）或错误配置的 Python（您可能忘记在 VPS 上安装 Flask）。如果您无法弄清楚错误消息的含义，互联网搜索消息（删除应用程序的错误特定部分，如名称和路径）通常会指引您朝正确的方向。如果失败，Stack Overflow 和 Google Groups 上有强大而友好的 Flask 和 WSGI 社区，通常会有人愿意帮助初学者。请记住，如果您遇到问题并且找不到现有的解决方案，请不要感到难过；您将帮助无数面临类似问题的人。

# 摘要

在本章中，我们涉及了相当多的材料！我们进行了一些初始设置和日常工作，然后使用 Flask 编写了我们的第一个 Web 应用程序。我们看到这在本地运行，然后讨论了如何使用 Git 将我们的代码复制到服务器。我们配置了服务器以向公众提供我们的应用程序；但是，我们的应用程序只是一个静态页面，向访问我们页面的人打印“Hello, World!”字符串。这对许多人来说并不有用，并且可以使用静态 HTML 页面更简单地实现。但是，通过我们付出的额外努力，现在我们的应用程序背后拥有 Python 的所有功能；我们只是还没有使用它！

在下一章中，我们将发现如何利用 Python 使我们的 Web 应用程序更有用！


# 第二章：开始我们的头条项目

现在我们的 Hello World 应用程序已经启动运行，我们已经完成了所有必要的工作，可以创建一个更有用的应用程序。在接下来的几章中，我们将创建一个头条应用程序，向用户显示最新的新闻头条，天气信息和货币汇率。

在本章中，我们将介绍 RSS 订阅，并展示如何使用它们自动检索特定出版物的最新新闻文章。在下一章中，我们将讨论如何使用模板向用户显示检索到的文章的标题和摘要。第四章，*我们头条项目的用户输入*，将向您展示如何从用户那里获取输入，以便他们可以自定义他们的体验，并且还将讨论如何向我们的应用程序添加天气和货币数据。我们将在第五章中完成项目，*改善我们头条项目的用户体验*，通过添加一些 CSS 样式，并研究如何在用户的下一次访问中记住他们的偏好。

在本章结束时，您将学会如何创建一个更复杂的 Flask 应用程序。我们将从真实世界的新闻故事中提取原始数据，并构建 HTML 格式以向用户显示这些内容。您还将了解更多关于路由的知识，即不同的 URL 触发应用程序代码的不同部分。

在这一章中，我们将涵盖以下主题：

+   搭建我们的项目和 Git 仓库

+   创建一个新的 Flask 应用程序

+   介绍 RSS 和 RSS 订阅

# 设置我们的项目和 Git 仓库

我们可以简单地编辑我们的 Hello World 应用程序以添加所需的功能，但更干净的做法是开始一个新项目。我们将为每个项目创建一个新的 Git 仓库，一个新的 Python 文件，一个新的`.wsgi`文件和一个新的 Apache 配置文件。这意味着书中的所有三个项目以及原始的 Hello World 应用程序都可以从我们的 Web 服务器访问。

设置与我们在第一章中为我们的 Hello World 应用程序所做的非常相似，但我们将再次简要地介绍这些步骤，因为我们不必重复大部分配置和安装，如下所示：

1.  登录到您的 GitHub 或 BitBucket 帐户，并创建一个名为`headlines`的新存储库。记下您获得的此空存储库的 URL。

1.  在您的本地计算机上，在您的主目录或者您放置`firstapp`目录的任何地方创建一个名为`headlines`的新目录。

1.  在此目录中创建一个名为`headlines.py`的新文件。

1.  在您的终端中，将目录更改为`headlines`目录，并通过执行以下命令初始化 Git 存储库：

```py
cd headlines
git init
git remote add origin <your headlines git URL>
git add headlines.py
git commit -m "initial commit"
git push –u origin master

```

现在，我们几乎准备好将代码推送到我们的新仓库；我们只需要先编写它。

# 创建一个新的 Flask 应用程序

首先，我们将创建新的 Flask 应用程序的框架，这与我们的 Hello World 应用程序几乎相同。在编辑器中打开`headlines.py`并写入以下代码：

```py
from flask import Flask

app = Flask(__name__)

@app.route("/")
def get_news():
  return "no news is good news"

if __name__ == '__main__':
  app.run(port=5000, debug=True)
```

这与以前完全一样。您可以在终端中使用`python headlines.py`运行它。打开浏览器并导航到`localhost:5000`，以查看显示的**没有新闻就是好消息**字符串。然而，尽管这句古话可能是真的，但糟糕的消息是我们的应用程序除了这个之外没有做任何更有用的事情。让我们让它向用户显示实际的新闻。

# 介绍 RSS 和 RSS 订阅

RSS 是一种古老但仍然广泛使用的技术，用于管理内容订阅。它已经存在了很长时间，以至于有人争论 RSS 这几个字母实际上代表什么，有人说是真正简单的聚合，有人说是丰富的站点摘要。这有点无关紧要，因为每个人都只是称它为 RSS。

RSS 使用 XML 以有序和结构化的格式呈现内容。它有几种用途，其中较常见的用途之一是供人们消费新闻文章。在新闻网站上，新闻通常以类似于印刷报纸的方式布局，重要的文章会占用更多的空间，并且会在页面上停留更长的时间。这意味着经常访问页面的用户会重复看到一些内容，并且必须寻找新内容。另一方面，有些网页更新非常不频繁，比如一些作者的博客。用户必须继续检查这些页面，看它们是否有更新，即使它们大部分时间都没有变化。RSS 源解决了这两个问题。如果网站配置为使用 RSS 源，所有新内容都会发布到一个源中。用户可以订阅他或她选择的源，并使用 RSS 阅读器来消费这些内容。他或她订阅的所有源的新故事将出现在阅读器中，并在标记为已读后消失。

由于 RSS 源具有正式的结构，它们允许我们在 Python 中以编程方式轻松解析标题、文章文本和日期。我们将使用一些主要新闻出版物的 RSS 源来向我们应用程序的用户显示新闻。

尽管 RSS 遵循严格的格式，我们可以不费太多力气地编写逻辑来解析源，但我们将使用 Python 库来完成这项工作。该库将抽象出诸如不同版本的 RSS 之类的东西，并允许我们以完全一致的方式访问所需的数据。

有几个 Python 库可以用来实现这一点。我们将选择`feedparser`。要安装它，打开你的终端并输入以下内容：

```py
pip install --user feedparser

```

现在，让我们去找一个要解析的 RSS 源！大多数主要出版物都提供 RSS 源，而建立在流行平台上的较小网站，如 WordPress 和 Blogger，通常也会默认包含 RSS。有时需要一点努力才能找到 RSS 源；然而，由于没有关于它应该位于何处的标准，你经常会在主页的某个地方看到 RSS 图标（查看页眉和页脚），它看起来类似于这样：

![RSS 和 RSS 源简介](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_02_01.jpg)

此外，寻找标有**RSS**或**Feed**的链接。如果这种方法失败，尝试访问[site.com/rss](http://site.com/rss)或[site.com/feed](http://site.com/feed)，其中`site.com`是你正在寻找 RSS 源的网站的根 URL。

我们将使用主要 BBC 新闻页面的 RSS 源。在撰写本文时，它位于[`feeds.bbci.co.uk/news/rss.xml`](http://feeds.bbci.co.uk/news/rss.xml)。如果你感兴趣，你可以在浏览器中打开这个 URL，在页面的某个地方右键单击，然后点击**查看源代码**或等效选项。你应该会看到一些结构化的 XML，格式类似于以下内容：

```py
<?xml version="1.0" encoding="UTF-8"?>
  <channel>
    <title>FooBar publishing</title>
    <link>http://dwyer.co.za</link>
    <description>A mock RSS feed</description> 
    <language>en-gb</language>  
    <item> 
      <title>Flask by Example sells out</title>
      <description>Gareth Dwyer's new book, Flask by Example sells out in minutes</description>
      <link>http://dwyer.co.za/book/news/flask-by-example</link>
      <guid isPermalink="false">http://dwyer.co.za/book/news/flask-by-example</guid>
      <pubDate>Sat, 07 Mar 2015 09:09:19 GMT</pubDate>
    </item>
  </channel>
</rss>
```

在源的顶部，你会看到一两行描述源本身的内容，比如它使用的 RSS 版本以及可能一些关于样式的信息。之后，你会看到与源的发布者相关的信息，然后是一系列`<item>`标签。其中每个代表一个*故事*——在我们的情况下，是一篇新闻文章。这些项目包含诸如标题、摘要、发布日期和完整故事的链接等信息。让我们开始解析吧！

## 使用 Python 从 RSS 获取信息

在我们的`headlines.py`文件中，我们将进行修改以导入我们安装的`feedparser`库，解析 feed，并获取第一篇文章。我们将围绕第一篇文章构建 HTML 格式，并在我们的应用程序中显示这个。如果你对 HTML 不熟悉，它代表**超文本标记语言**，用于定义网页中文本的外观和布局。它非常简单，但如果对你来说完全是新的，你应该花一点时间去学习一下初学者教程，以熟悉它的最基本用法。有许多免费的在线教程，快速搜索应该能找到几十个。一个受欢迎且非常适合初学者的教程可以在[`www.w3schools.com/html/`](http://www.w3schools.com/html/)找到。

我们的新代码添加了新库的导入，定义了一个新的全局变量用于 RSS feed URL，并进一步添加了一些逻辑来解析 feed，获取我们感兴趣的数据，并将其插入到一些非常基本的 HTML 中。它看起来类似于这样：

```py
import feedparser
from flask import Flask

app = Flask(__name__)

BBC_FEED = "http://feeds.bbci.co.uk/news/rss.xml"

@app.route("/")
def get_news():
 feed = feedparser.parse(BBC_FEED)
 first_article = feed['entries'][0]
 return """<html>
 <body>
 <h1> BBC Headlines </h1>
 <b>{0}</b> <br/>
 <i>{1}</i> <br/>
 <p>{2}</p> <br/>
 </body>
</html>""".format(first_article.get("title"), first_article.get("published"), first_article.get("summary"))

if __name__ == "__main__":
  app.run(port=5000, debug=True)
```

这个函数的第一行将 BBC 的 feed URL 传递给我们的`feedparser`库，该库下载 feed，解析它，并返回一个 Python 字典。在第二行，我们仅从 feed 中获取了第一篇文章并将其分配给一个变量。`feedparser`返回的字典中的`entries`条目包含了包括我们之前提到的新闻故事的所有项目的列表，因此我们从中取出了第一个，并从中获取了标题或`title`，日期或`published`字段以及文章的摘要（即`summary`）。在`return`语句中，我们在一个三引号的 Python 字符串中构建了一个基本的 HTML 页面，其中包括所有 HTML 页面都有的`<html>`和`<body>`标签，以及描述我们页面的`<h1>`标题；`<b>`，这是一个*加粗*标签，显示新闻标题；`<i>`，代表*斜体*标签，显示文章的日期；和`<p>`，这是一个段落标签，用于显示文章的摘要。由于 RSS feed 中几乎所有项目都是可选的，我们使用了`python.get()`运算符而不是使用索引表示法（方括号），这意味着如果有任何信息缺失，它将简单地从我们最终的 HTML 中省略，而不会导致运行时错误。

为了清晰起见，我们在这个例子中没有进行任何异常处理；但是请注意，`feedparser`在尝试解析 BBC URL 时可能会抛出异常。如果你的本地互联网连接不可用，BBC 服务器宕机，或者提供的 feed 格式不正确，那么`feedparser`将无法将 feed 转换为 Python 字典。在一个真实的应用程序中，我们会添加一些异常处理并在这里重试逻辑。在一个真实的应用程序中，我们也绝不会在 Python 字符串中构建 HTML。我们将在下一章中看看如何正确处理 HTML。打开你的网络浏览器，看看结果。你应该看到一个非常基本的页面，看起来类似于以下内容（尽管你的新闻故事将是不同的）：

![使用 Python 的 RSS](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_02_02.jpg)

这是一个很好的开始，我们现在为我们应用程序的假设用户提供了动态内容（即根据用户或外部事件自动更改的内容）。然而，最终，它并不比静态字符串更有用。谁想要看到来自他们无法控制的单一出版物的单一新闻故事呢？

为了完成本章，我们将看看如何根据 URL 路由从不同的出版物中显示文章。也就是说，我们的用户将能够在我们的网站上导航到不同的 URL，并查看来自几种出版物中的文章。在此之前，让我们稍微详细地看一下 Flask 如何处理 URL 路由。

## Flask 中的 URL 路由

你还记得我们在上一章中简要提到了 Python 装饰器吗？它们由我们主要函数上面的有趣的`@app.route("/")`行表示，它们指示 Flask 应用程序的哪些部分应该由哪些 URL 触发。我们的基本 URL 通常类似于`site.com`，但在我们的情况下是我们 VPS 的 IP 地址，它被省略了，我们将在装饰器中指定剩下的 URL（即路径）。之前，我们使用了一个斜杠，表示当我们的基本 URL 被访问时，没有指定路径时应该触发该函数。现在，我们将设置我们的应用程序，以便用户可以访问类似[site.com/bbc](http://site.com/bbc)或[site.com/cnn](http://site.com/cnn)的 URL，选择他们想要看到文章的出版物。

我们需要做的第一件事是收集一些 RSS URL。在撰写本文时，以下所有内容都是有效的：

+   CNN: [`rss.cnn.com/rss/edition.rss`](http://rss.cnn.com/rss/edition.rss)

+   Fox News: [`feeds.foxnews.com/foxnews/latest`](http://feeds.foxnews.com/foxnews/latest)

+   IOL: [`www.iol.co.za/cmlink/1.640`](http://www.iol.co.za/cmlink/1.640)

首先，我们将考虑如何使用静态路由来实现我们的目标。这绝不是最好的解决方案，因此我们将仅为我们的两个出版物实现静态路由。一旦我们完成这项工作，我们将考虑如何改用动态路由，这是许多问题的更简单和更通用的解决方案。

我们将建立一个 Python 字典，封装所有的 RSS 订阅，而不是为每个 RSS 订阅声明一个全局变量。我们将使我们的`get_news()`方法通用化，并让我们装饰的方法使用相关的出版物调用它。我们修改后的代码如下：

```py
import feedparser
from flask import Flask

app = Flask(__name__)

RSS_FEEDS = {'bbc': 'http://feeds.bbci.co.uk/news/rss.xml',
             'cnn': 'http://rss.cnn.com/rss/edition.rss',
             'fox': 'http://feeds.foxnews.com/foxnews/latest',
             'iol': 'http://www.iol.co.za/cmlink/1.640'}

@app.route("/")
@app.route("/bbc")
def bbc():
    return get_news('bbc')

@app.route("/cnn")
def cnn():
    return get_news('cnn')

def get_news(publication):
  feed = feedparser.parse(RSS_FEEDS[publication])
  first_article = feed['entries'][0]
  return """<html>
    <body>
        <h1>Headlines </h1>
        <b>{0}</b> </ br>
        <i>{1}</i> </ br>
        <p>{2}</p> </ br>
    </body>
</html>""".format(first_article.get("title"), first_article.get("published"), first_article.get("summary"))

if __name__ == "__main__":
  app.run(port=5000, debug=True)
```

Common mistakes:

### 提示

如果您复制或粘贴函数并编辑`@app.route`装饰器，很容易忘记编辑函数名。虽然我们的函数名在很大程度上是无关紧要的，因为我们不直接调用它们，但我们不能让不同的函数共享与最新定义相同的名称，因为最新的定义将始终覆盖任何先前的定义。

我们仍然默认返回 BBC 新闻订阅，但如果用户访问 CNN 或 BBC 路由，我们将明确从各自的出版物中获取头条新闻。请注意，我们可以在一个函数中有多个装饰器，这样我们的`bbc()`函数就会在访问我们的基本 URL 或`/bbc`路径时触发。另外，请注意函数名不需要与路径相同，但在前面的例子中我们遵循了这个常见的约定。

接下来，当用户访问`/cnn`页面时，我们可以看到我们应用程序的输出。显示的标题现在来自 CNN 订阅。

![Flask 中的 URL 路由](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_02_03.jpg)

现在我们知道了 Flask 中路由的工作原理，如果能更简单就好了，不是吗？我们不想为我们的每个订阅定义一个新的函数。我们需要的是函数根据路径动态获取正确的 URL。这正是动态路由所做的事情。

在 Flask 中，如果我们在 URL 路径的一部分中使用尖括号`<` `>`，那么它将被视为一个变量，并传递给我们的应用程序代码。因此，我们可以重新使用单个`get_news()`函数，并传入一个`<publication>`变量，该变量可用于从我们的字典中进行选择。装饰器指定的任何变量都必须在我们函数的定义中考虑到。更新后的`get_news()`函数的前几行如下所示：

```py
@app.route("/")
@app.route("/<publication>")
def get_news(publication="bbc"):
    # rest of code unchanged  
```

在前面显示的代码中，我们将`<publication>`添加到路由定义中。这将创建一个名为`publication`的参数，我们需要将其作为函数的参数直接添加到路由下面。因此，我们可以保留出版物参数的默认值为`bbc`，但如果用户访问 CNN，Flask 将传递`cnn`值作为出版物参数。

代码的其余部分保持不变，但是删除现在未使用的`bbc()`和`cnn()`函数定义非常重要，因为我们需要默认路由来激活我们的`get_news()`函数。

很容易忘记在函数定义中*catch* URL 变量。路由的任何动态部分都必须在函数中包含同名的参数才能使用该值，因此要注意这一点。请注意，我们给我们的 publication 变量一个默认值`bbc`，这样当用户访问我们的基本 URL 时，我们就不需要担心它未定义。但是，再次强调，如果用户访问我们字典中没有的任何 URL，我们的代码将抛出异常。在真实的 Web 应用程序中，我们会捕获这种情况并向用户显示错误，但我们将把错误处理留到以后的章节。

## 发布我们的头条应用程序

这是我们在本章中将应用的最远程度。让我们将结果推送到我们的服务器，并配置 Apache 默认显示我们的头条新闻应用程序，而不是我们的 Hello World 应用程序。

首先，将更改添加到 Git 存储库中，对其进行提交，并将其推送到远程。您可以通过运行以下命令来完成此操作（在打开终端并切换到头条目录后）：

```py
git add headlines.py
git commit –m "dynamic routing"
git push origin master

```

然后，使用以下命令通过 SSH 连接到 VPS 并在那里克隆新项目：

```py
ssh –i yourkey.pem root@123.456.789.123
cd /var/www
git clone https://<yourgitrepo>

```

不要忘记安装我们现在依赖的新库。在服务器上忘记安装依赖关系是一个常见的错误，可能会导致令人沮丧的调试。请记住这一点。以下是此命令：

```py
pip install --user feedparser

```

现在，创建`.wsgi`文件。我假设您在创建远程存储库时将 Git 项目命名为`headlines`，并且在执行前面的 Git 克隆命令时，在您的`/var/www`目录中创建了一个名为`headlines`的目录。如果您将项目命名为其他名称，并且现在有一个具有不同名称的目录，请将其重命名为 headlines（否则，您将不得不相应地调整我们即将进行的大部分配置）。在 Linux 中重命名目录，请使用以下命令：

```py
mv myflaskproject headlines

```

之前使用的命令将目录称为`myflaskproject`重命名为`headlines`，这将确保接下来的所有配置都能正常工作。现在，运行以下命令：

```py
cd headlines
nano headlines.wsgi

```

然后，插入以下内容：

```py
import sys
sys.path.insert(0, "/var/www/headlines")
from headlines import app as application
```

通过按下*Ctrl* + *X*键组合退出 Nano，并在提示保存更改时输入*Y*。

现在，转到 Apache 中的`sites-available`目录，并使用以下命令创建新的`.conf`文件：

```py
cd /etc/apache2/sites-available
nano headlines.conf

```

接下来，输入以下内容：

```py
<VirtualHost *>
    ServerName example.com

    WSGIScriptAlias / /var/www/headlines/headlines.wsgi
    WSGIDaemonProcess headlines
    <Directory /var/www/headlines>
       WSGIProcessGroup headlines
       WSGIApplicationGroup %{GLOBAL}
        Order deny,allow
        Allow from all
    </Directory>
</VirtualHost>
```

保存文件并退出 nano。现在，通过运行以下命令禁用我们的旧站点，启用新站点，并重新启动 Apache：

```py
sudo a2dissite hello.conf
sudo a2enssite headlines.conf
sudo service apache2 reload

```

尝试从本地机器访问 VPS 的 IP 地址，如果一切如预期般进行，您应该像以前一样看到新闻标题！如果没有，不要担心。在某些配置中犯错误是很容易的。最有可能的是您的`headlines.wsgi`或`headlines.conf`文件有一个小错误。找到这个最简单的方法是查看 Apache 错误日志中的最近错误，这些错误在您尝试访问站点时会触发。使用以下命令再次查看：

```py
sudo tail –fn 20 /var/log/apache2/error.log

```

# 摘要

这就是本章的全部内容。本章的主要要点是看一下 Flask 如何处理静态和动态路由。您还学会了一种相当混乱的使用 HTML 格式化数据并将其返回给用户的方法。

在下一章中，我们将看一下使用 Jinja 模板更清晰地分离 HTML 代码和 Python 代码的方法。我们还将让我们的应用程序显示不止一个新闻故事。


# 第三章：在我们的头条项目中使用模板

在上一章中，我们看到了一种将静态 HTML 与动态内容结合起来创建网页的方法。但这很混乱，我们不想在 Python 字符串中构建我们的网页。混合 HTML 和 Python 并不理想，原因有几个：首先，这意味着如果我们想要更改静态文本，比如出现在标题中的文本，我们必须编辑我们的 Python 文件，这也涉及重新加载这些文件到 Apache。如果我们雇佣前端开发人员来处理 HTML，他们有可能会不小心破坏陌生的 Python 代码，并且更难以正确地构建任何其他前端代码，比如 JavaScript 和 CSS。理想情况下，我们应该在前端和后端组件之间实现完全的隔离。我们可以在很大程度上使用 Jinja 来实现这一点，但与生活的大多数方面一样，一些妥协是必要的。

在本章结束时，我们将扩展我们的应用程序，以显示所选出版物的不止一个头条新闻。我们将为每个出版物显示多篇文章，每篇文章都有一个指向原始文章的链接，我们的逻辑和视图组件将在很大程度上分离。在本章中，我们将涵盖以下主题：

+   介绍 Jinja

+   Jinja 模板的基本用法

+   Jinja 模板的高级用法

# 介绍 Jinja

Jinja 是一个 Python 模板引擎。它允许我们轻松地定义由 Python 填充的动态 HTML 块。HTML 模板即使对于具有多个页面的静态网站也是有用的。通常，每个页面都有一些共同的元素，比如标题和页脚。虽然对于静态网站来说，可以维护每个页面，但如果对共享部分进行更改，则需要在多个位置进行单个更改。Flask 是建立在 Jinja 之上的，因此虽然可以在没有 Flask 的情况下使用 Jinja，但 Jinja 仍然是 Flask 的固有部分，并且 Flask 提供了几种直接与 Jinja 一起工作的方法。一般来说，Flask 对于应用程序的结构假设没有任何东西，除了你告诉它的内容，并且更喜欢通过可选插件提供功能。Jinja 在某种程度上是一个例外。Flask 默认为您提供 Jinja，并假设您将所有 Jinja 模板存储在名为`templates`的应用程序子目录中。

创建模板后，我们将从我们的 Flask 应用程序中调用渲染这些模板。渲染涉及解析 Jinja 代码，插入任何动态数据，并创建纯 HTML 以返回给用户的浏览器。尽管所有这些都是在幕后完成的，但可能会让人有点困惑，不知道在哪里完成了什么。我们将一步一步地进行。

# Jinja 模板的基本用法

使用 Jinja 模板的第一步是在我们的应用程序中创建一个目录来包含我们的模板文件，所以导航到您的`headlines`目录，并创建一个名为`templates`的目录。与之前的步骤不同，这个名称是应用程序的其他部分所期望的，并且区分大小写，因此在创建时要小心。在最基本的级别上，Jinja 模板可以只是一个 HTML 文件，我们将为所有的 Jinja 模板使用`.html`扩展名。在`templates`目录中创建一个名为`home.html`的新文件。这将是我们的用户访问我们的应用程序时看到的页面，并且将包含我们以前在 Python 字符串中的所有 HTML。

### 注意

在本书中，我们只会使用 Jinja 来构建 HTML 文件，但 Jinja 足够灵活，可以用于生成任何基于文本的格式。虽然我们使用`.html`扩展名来命名我们的 Jinja 模板，但这些文件本身并不总是纯 HTML。

现在，将以下静态 HTML 代码放入此文件中。我们将在下一步中看如何在 Python 和我们的模板之间传递动态数据。

```py
<html>
    <head>
        <title>Headlines</title>
    </head>
    <body>
        <h1>Headlines</h1>
        <b>title</b><br />
        <i>published</i><br />
        <p>summary</p>
    </body>
</html>
```

现在在我们的 Python 代码中，我们将渲染这个模板并返回它，而不是在我们的路由函数中构建字符串并返回它。在`headlines.py`中，在顶部添加一个导入：

```py
from flask import render_template
```

`render_template`函数是一个魔术，它以 Jinja 模板作为输入，并产生纯 HTML 作为输出，可以被任何浏览器读取。目前，一些魔术已经失去了，因为我们将纯 HTML 作为输入，并在浏览器中查看相同的输出。

## 渲染基本模板

在你的`get_news()`函数中，删除包含我们三引号 HTML 字符串的`return`语句。保留之前从`feedparser`获取数据的行，因为我们很快会再次使用它。

更新`return`语句，使得`get_news()`函数现在如下所示：

```py
@app.route("/")
@app.route("/<publication>"
def get_news(publication="bbc"):
  feed = feedparser.parse(RSS_FEEDS[publication])
  first_article = feed['entries'][0]
 return render_template("home.html")

```

尽管我们当前的 HTML 文件是纯 HTML，还没有使用我们稍后将看到的 Jinja 语法，但实际上我们已经做了相当多的魔术。这个调用在我们的`templates`目录中查找名为`home.html`的文件，读取它，解析任何 Jinja 逻辑，并创建一个 HTML 字符串返回给用户。一旦你做了以上两个更改，再次用`python headlines.py`运行你的应用程序，并在浏览器中导航到`localhost:5000`。

再次，我们为了前进而后退了一步。如果你现在运行应用程序并在浏览器中查看结果，你应该会看到与我们原始页面类似的东西，只是现在你会看到字符串**title**，**published**和**summary**，如下图所示：

![渲染基本模板](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_03_01.jpg)

让我们看看如何在`render_template`调用中填充这些字段，以便我们可以再次看到真实的新闻内容。

## 将动态数据传递给我们的模板

首先，在我们的 Python 文件中，我们将把每个作为命名变量传递。再次更新`get_news()`函数，并将所有需要显示给用户的数据作为参数传递给`render_template()`，如下所示：

```py
@app.route("/")
@app.route("/<publication>"
def get_news(publication="bbc"):
  feed = feedparser.parse(RSS_FEEDS[publication])
  first_article = feed['entries'][0]
 render_template("home.html",title=first_article.get("title"),published=first_article.get("published"),summary=first_article.get("summary"))

```

`render_template`函数以模板的文件名作为第一个参数，然后可以接受任意数量的命名变量作为后续参数。每个变量中的数据将在模板中使用变量名可用。

## 在我们的模板中显示动态数据

在我们的`home.html`文件中，我们只需要在占位符的两侧放上两个大括号。更改后的样子如下：

```py
<html>
    <head>
        <title>Headlines</title>
    </head>
    <body>
        <h1>Headlines</h1>
        <b>{{title}}</b><br />
        <i>{{published}}</i><br />
        <p>{{summary}}</p>
    </body>
</html>
```

双大括号，{{ }}, 表示对 Jinja 来说，它们内部的任何内容都不应被视为字面 HTML 代码。因为我们的*占位符*，*title*，*published*和*summary*与我们传递给`render_template`调用的 Python 变量名相同，只需添加周围的大括号，`render_template`调用将用真实数据替换这些，返回一个纯 HTML 页面。试一下，确保我们可以再次看到真实的新闻数据，如下图所示：

![在我们的模板中显示动态数据](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_03_02.jpg)

# Jinja 模板的高级用法

现在我们完全分离了后端和前端组件，但我们的应用程序并没有比以前做更多的事情。让我们看看如何从所选出版物中显示多个新闻文章。我们不想为每篇文章的`render_template`调用添加三个新参数（或者如果我们决定要显示的不仅仅是文章的标题、日期和摘要，那么可能会添加几十个额外的参数）。

幸运的是，Jinja 可以接管 Python 的一些逻辑。这就是我们需要小心的地方：我们花了很多精力来分离逻辑和视图组件，当我们发现 Jinja 语言实际上有多么强大时，很容易将大部分逻辑移到我们的模板文件中。这将使我们回到最初的状态，代码难以维护。然而，在某些情况下，我们的前端代码需要处理一些逻辑，比如现在我们不想用太多重复的参数来污染我们的后端代码。

## 使用 Jinja 对象

首先要学习的是 Jinja 如何处理对象。所有基本的 Python 数据结构，如变量、对象、列表和字典，Jinja 都能理解，并且可以以与 Python 非常相似的方式进行处理。例如，我们可以将`first_article`对象传递给模板，而不是将文章的三个组件分别传递给模板，然后在 Jinja 中处理分离。让我们看看如何做到这一点。将 Python 代码更改为向`render_template`传递单个命名参数，即`first_article`，并将前端代码更改为从中提取所需的部分。

`render_template`调用现在应该是这样的：

```py
render_template("home.html", article=first_article)
```

模板现在有一个名为`article`的引用，我们可以使用它来获得与之前相同的结果。更改 home.html 中相关部分如下：

```py
<b>{{article.title}}</b><br />
<i>{{article.published</i><br />
<p>{{article.summary}}</p>
```

请注意，在 Jinja 中访问字典中的项与 Python 中略有不同。我们使用句点来访问属性，因此要访问文章的标题，我们使用`{{article.title}}`，而不是 Python 中的`article["title"]`或`article.get("title")`。我们的代码再次更整洁，但没有额外的功能。

## 向我们的模板添加循环逻辑

几乎没有额外的努力，我们可以使所有文章列表可用于 Jinja。在 Python 代码中，更改`render_template`调用如下：

```py
render_template("home.html", articles=feed['entries'])
```

您可以删除代码中直接在前一行上定义`first_article`变量的行，因为我们不再需要它。我们的模板现在可以访问我们通过`feedparser`获取的完整文章列表。

在我们的 Jinja 模板中，我们现在可以`添加{{articles}}`或`{{articles[0]}}`来查看我们现在传递的所有信息的完整转储，或者仅查看第一篇文章的转储。如果您感兴趣，可以尝试这个中间步骤，但在下一步中，我们将循环遍历所有文章并显示我们想要的信息。

通过向模板提供更多数据，我们传递了一些理想情况下应该由 Python 代码处理的逻辑责任，但我们也可以在 Jinja 中处理得非常干净。类似于我们使用双大括号`{{` `}}`表示变量的方式，我们使用大括号和百分号的组合`{% %}`表示控制逻辑。通过示例来看会更清楚。更改模板代码中的`<body>`部分如下：

```py
<body>
    <h1>Headlines</h1>
    {% for article in articles %}
        <b>{{article.title}}</b><br />
        <i>{{article.published}}</i><br />
        <p>{{article.summary}}</p>
        <hr />
    {% endfor %}
</body>
```

我们可以看到 Jinja 的 for 循环与 Python 类似。它循环遍历我们从 Python 代码传递进来的*articles*列表，并为循环的每次迭代创建一个新变量`article`，每次引用列表中的下一个项目。然后可以像其他 Jinja 变量一样使用`article`变量（使用双大括号）。因为 Jinja 中的空格是无关紧要的，不像 Python，我们必须用`{% endfor %}`行定义循环的结束位置。最后，在 HTML 中的`<hr />`创建一个作为每篇文章之间分隔符的水平线。

使用新的模板文件在本地运行应用程序，并在浏览器中查看结果。您应该看到类似以下图片的东西：

![向我们的模板添加循环逻辑](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_03_03.jpg)

## 向我们的模板添加超链接

现在我们想要将每个标题链接到原始文章。我们的用户可能会发现这很有用 - 如果一个标题看起来有趣，他或她可以轻松地获取文章的全文来阅读。RSS 订阅的所有者通常也会要求或要求使用该订阅的任何人链接回原始文章。（再次检查大多数大型订阅发布的条款和条件。）因为我们已经将整个`article`对象传递给我们的模板，所以我们不需要对我们的 Python 代码进行进一步的更改来实现这一点；我们只需要利用我们已经可用的额外数据。

在模板文件中，搜索以下内容：

```py
<b>{{article.title}}</b><br />
```

将此行更改为以下内容：

```py
<b><a href="{{article.link}}">{{article.title}}</a></b><br />
```

如果您对 HTML 不熟悉，那么这里有很多事情要做。让我们分解一下：HTML 中的`<a>`标签表示超链接（通常在大多数浏览器中默认显示为蓝色并带有下划线），`href`属性指定链接的目的地或 URL，并且链接以`</a>`标签结束。也就是说，`<a>`和`</a>`之间的任何文本都将是可点击的，并且将由我们用户的浏览器以不同的方式显示。请注意，我们可以在双引号中使用双大括号来指示变量，即使在用于定义目标属性的双引号内也可以。

如果您在浏览器中刷新页面，现在应该看到标题是粗体链接，如下图所示，并且点击其中一个链接应该会带您到原始文章。

![向我们的模板添加超链接](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_03_04.jpg)

## 将我们的代码推送到服务器

现在是将代码推送到我们的 VPS 的好时机。这是我们将分解如何做这件事的最后一次，但希望你现在对 Git 和 Apache 已经很熟悉，不会有任何意外发生。在本地机器上，从`headlines`目录运行：

```py
git add headlines.py
git add templates
git commit -m "with Jinja templates"
git push origin master

```

然后在您的 VPS 上（像往常一样通过 SSH 登录），切换到适当的目录，从 Git 存储库中拉取更新，并重新启动 Apache 以重新加载代码：

```py
cd /var/www/headlines
git pull
sudo service apache2 reload

```

确保一切都已经通过从本地机器的网络浏览器访问 VPS 的 IP 地址并检查是否看到与我们在本地看到的相同的输出来运行，如下图所示：

![将我们的代码推送到服务器](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_03_05.jpg)

# 摘要

现在我们有了一个基本的新闻摘要网站！您可以从许多不同的网站显示最近的新闻，查看每篇最近文章的标题，日期和摘要，并且可以点击任何标题访问原始文章。不过，您只看到了 Jinja 语言的一小部分功能 - 随着我们扩展这个项目和将来章节中的其他项目，您将看到它如何用于继承、条件语句等等。

在下一章中，我们将向我们的应用程序添加天气和货币信息，并探讨与用户互动的方式。


# 第四章：我们 Headlines 项目的用户输入

还记得我们是如何允许用户使用 URL 中的`<variable>`部分指定要查看的出版物的吗？尽管我们实际上是在从用户那里获取输入，但这种检索输入的方式有一些相当严重的限制。让我们看看与用户交互的更强大的方法，并向我们的应用程序添加一些更有用的信息。从现在开始，我们将对我们的代码文件进行相当多的增量更改，因此请记住，如果您需要概述，您可以随时参考附带的代码包。

在本章中，我们将看一些更灵活和强大的获取输入的方法。我们还将在这个过程中遇到一些更高级的 Git 功能，并花点时间解释如何使用它们。

在本章中，我们将讨论以下主题：

+   使用 HTTP GET 获取用户输入

+   使用 HTTP POST 获取用户输入

+   添加天气和货币数据

# 使用 HTTP GET 获取用户输入

HTTP GET 请求是从用户那里检索输入的最简单方式。在浏览网页时，您可能已经注意到 URL 中的问号。在网站的搜索框中提交一个术语时，您的搜索术语通常会出现在 URL 中，看起来像这样：

`example.com/search?query=weather`

问号后面的部分表示一个命名的 GET 参数。名称是`query`，值是`weather`。尽管这些参数通常是通过 HTML 输入框自动生成的，但用户也可以手动将它们插入到 URL 中，或者它们可以是发送给用户的可点击链接的一部分。HTTP GET 旨在从用户那里获取有限的、非敏感的信息，以便服务器根据 GET 参数返回所请求的页面。按照惯例，GET 请求不应该以产生副作用的方式修改服务器状态，也就是说，用户应该能够多次发出完全相同的请求，并始终得到完全相同的结果。

因此，GET 请求非常适合让用户指定要查看的出版物。让我们扩展我们的 Headlines 项目，以根据 GET 请求选择一个标题。首先，让我们修改 Python 代码以执行以下操作：

+   从 Flask 导入请求上下文

+   删除动态 URL 变量

+   检查用户是否已输入有效的出版物作为 GET 参数

+   将用户查询和出版物传递给模板

按照以下方式更新`headlines.py`文件：

```py
import feedparser
from flask import Flask
from flask import render_template
from flask import request

app = Flask(__name__)

RSS_FEEDS = {'bbc': 'http://feeds.bbci.co.uk/news/rss.xml',
             'cnn': 'http://rss.cnn.com/rss/edition.rss',
             'fox': 'http://feeds.foxnews.com/foxnews/latest',
             'iol': 'http://www.iol.co.za/cmlink/1.640'}

@app.route("/")
def get_news():
 query = request.args.get("publication")
 if not query or query.lower() not in RSS_FEEDS:
 publication = "bbc"
 else:
 publication = query.lower()
        feed = feedparser.parse(RSS_FEEDS[publication])
 return render_template("home.html",articles=feed['entries']

if __name__ == "__main__":
    app.run(port=5000, debug=True)
```

第一个新变化是 Flask 请求上下文的新导入。这是 Flask 魔法的另一部分，使我们的生活更轻松。它提供了一个全局上下文，我们的代码可以使用它来访问关于最新请求的信息。这对我们很有用，因为用户作为请求的一部分传递的 GET 参数会自动在`request.args`中可用，我们可以像使用 Python 字典一样访问键值对（尽管它是不可变的）。请求上下文还简化了请求处理的其他部分，这意味着我们不必担心线程或请求的顺序。您可以在以下网站上阅读有关请求上下文工作原理及其功能的更多信息：

[`flask-cn.readthedocs.org/en/latest/reqcontext/`](http://flask-cn.readthedocs.org/en/latest/reqcontext/)

我们使用`get()`方法来检查是否已设置出版物键，如果键不存在，则返回`None`。如果参数存在，我们确保值是有效的（即它在我们的`RSS_FEEDS`映射中），如果是，则返回匹配的出版物。

我们可以通过访问我们的 URL 后跟 `get` 参数来测试代码，例如：`localhost:5000/?publication=bbc`。不幸的是，从我们的用户体验来看，我们使应用程序变得不太用户友好，而不是更加用户友好。为什么我们要这样做呢？原来我们的用户不必手动修改 URL——通过一个非常小的更改，我们可以自动填充 URL 参数，这样用户根本不必触摸 URL。修改 `home.html` 模板，并在标题下方添加以下 HTML： 

```py
<form>
  <input type="text" name="publication" placeholder="search" />
  <input type="submit" value="Submit" />
</form>
```

这很简单，但让我们分解一下看看它是如何工作的。首先，我们创建了一个 HTML 表单元素。默认情况下，当提交时，这将创建一个 HTTP GET 请求，通过将任何输入作为 GET 参数传递到 URL 中。我们有一个名为 `publication` 的单个文本输入。这个名称很重要，因为 GET 参数将使用它。`placeholder` 是可选的，但它会让我们的用户有更好的体验，因为浏览器会用它来指示文本字段的用途。最后，我们有另一个类型为 `submit` 的输入。这将自动为我们的表单创建一个漂亮的**提交**按钮，当按下时，它将获取输入框中的任何文本并将其提交到我们的 Python 后端。

保存模板，重新加载页面以查看它现在的工作方式。您应该在页面顶部看到输入表单，如下面的截图所示。我们为四行 HTML 获得了很多功能，现在我们可以看到，尽管 GET 参数最初看起来像是在创建更多的任务和管理员，但实际上它们使我们的 Web 应用程序更简单、更用户友好。

![使用 HTTP GET 获取用户输入](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_04_01.jpg)

# 使用 HTTP POST 获取用户输入

HTTP GET 的替代方法是 HTTP POST，并不总是立即明显应该使用哪一个。HTTP POST 用于向服务器发布更大的数据块或更敏感的数据。通过 POST 请求发送的数据在 URL 中不可见，尽管这并不使其本质上更安全（它默认不提供加密或验证），但它确实提供了一些安全优势。URL 经常被浏览器缓存，并通过自动完成功能建议下次用户输入类似的 URL 时。

因此，通过 GET 请求发送的数据可能会被保留。使用 POST 还可以防止他人通过窥视用户的肩膀（肩部冲浪）来查看数据。特别是密码通常在输入时通过使用 HTML 密码字段而被遮蔽，使其在浏览器中显示为星号（********）或点（••••••••）。然而，如果使用 GET 发送，数据仍然会在 URL 中清晰可见，因此应始终使用 POST。

虽然我们的搜索查询并不是机密的或过长的，但我们现在要花点时间来看看如何使用 POST 而不是 GET 来实现相同的功能。如果您只想继续完成我们的 Headlines 应用程序，可以跳过本节，但请记住，我们将在后续项目中使用 POST 请求而不进行详细解释。完成 POST 示例后，我们将把我们的应用程序恢复到当前状态（使用 GET 请求），因为这更适合我们的用例。

## 在 Git 中创建分支

对我们的代码库进行更改，我们不确定是否想要，我们将使用 Git 的分支功能。把分支想象成是路上的岔路口，除了我们随时可以改变主意并返回决策点。首先，我们需要确保我们当前的分支（master）是最新的——即所有本地更改都已提交。打开终端，从 headlines 目录运行以下命令：

```py
git add headlines.py
git add templates/home.html
git commit -m "Using GET"
git push origin master

```

我们不严格需要将其推送到服务器——Git 在本地保留完整的修订历史，即使没有推送，我们的更改理论上仍然是安全的。然而，我们的代码处于工作状态，因此进行远程备份也没有坏处。现在我们将创建新的分支并切换到使用它来进行下一组更改：

```py
git branch post-requests
git checkout post-requests

```

我们现在正在我们代码库的一个新分支上工作。通常，我们最终会将此分支合并回主分支，但在我们的情况下，一旦我们完成所需的工作，我们将放弃它。由于 Git 大多数操作都是在后台进行，很难将发生的事情可视化，因此如果您感兴趣并且可能会在将来的项目中使用 Git，那么值得阅读有关 Git 的内容。否则，只需将其视为一个检查点，以便我们可以自由地进行实验，而不必担心搞乱我们的代码。

## 在 Flask 中添加 POST 路由

要使用 POST 请求，我们需要对 Python 和 HTML 代码进行一些小的更改。在`headlines.py`文件中，进行以下更改：

+   将`request.args.get`更改为`request.form.get`

+   将`@app.route("/")`更改为`@app.route("/", methods=['GET', 'POST'])`

第一个更改的原因是我们现在从表单中获取用户数据，因此 Flask 会自动将其提供给我们的`request.form`。这与`request.get`的工作方式相同，只是它从 POST 请求而不是从 GET 请求中收集数据。第二个更改并不那么明显。我们之前没有提到的是，所有路由装饰器都可以指定函数如何被访问：通过 GET 请求、POST 请求或两者兼有。默认情况下，只允许 GET，但我们现在希望我们的默认页面可以通过 GET（当我们只是访问主页并且默认给出 BBC 时）或 POST（当我们通过带有额外查询数据的表单请求页面时）来访问。`methods`参数接受一个 HTTP 方法的列表，这些方法应该被允许访问我们应用程序的特定路由。

## 使我们的 HTML 表单使用 POST

我们的模板需要进行类似的更改。将`home.html`文件中的开头`<form>`标签更改为：

```py
<form action="/" method="POST">
```

与 Flask 一样，HTML 表单默认使用 GET，因此我们必须明确定义我们要使用 POST 而不是 GET。`action`属性并不是绝对必要的，但通常当我们使用 POST 时，我们会将用户重定向到确认页面或类似的页面，接下来的页面的 URL 将出现在这里。在这种情况下，我们明确表示我们希望在提交表单后重定向到同一个页面。

保存 Python 和 HTML 文件的更改，并在浏览器中刷新页面以查看更改生效。功能应该完全相同，只是我们在 URL 中看不到任何数据。对于许多应用程序来说，这可能更清晰，但在我们的情况下，这不是我们想要的。首先，我们希望用户的浏览器可以缓存搜索词。如果用户习惯性地查询 FOX，我们希望浏览器在他开始在我们的应用程序的 URL 中输入时能够自动完成这一点。此外，我们希望我们的用户能够轻松地分享包括查询的链接。

如果用户（让我们称之为鲍勃）在将**cnn**输入到我们的应用程序后看到一堆有趣的标题，并希望与另一个用户（简）分享所有这些标题，我们不希望鲍勃不得不给简发消息，告诉她访问我们的网站，并在搜索表单中输入特定的查询。相反，鲍勃应该能够分享一个 URL，让简直接访问页面，就像他看到的那样（例如，`example.com/?publication=cnn`）。简只需点击鲍勃发送的链接，就可以查看相同的标题（假设她在 RSS 订阅更新之前访问我们的页面）。

## 恢复我们的 Git 存储库

我们需要将代码恢复到之前的状态。因为上一节中的所有更改都是在我们的实验性 post 请求分支中进行的，所以我们不需要手动重新编辑我们更改的行。相反，我们将提交我们的更改到这个分支，然后切换回我们的主分支，在那里我们会发现一切都和我们离开时一样。在您的终端中运行以下命令：

```py
git add headlines.py
git add templates/home.html
git commit –m "POST requests"
git checkout master

```

打开`headlines.py`和`templates/home.html`文件，确保它们与我们在进行 POST 实验之前保持一致！

# 添加天气和货币数据

现在让我们添加一些更多功能。我们正在显示来自三个不同来源的媒体头条，但我们的用户可能对更多内容感兴趣。我们将看看在页面顶部显示当前天气和一些汇率有多容易。对于天气数据，我们将使用 OpenWeatherMap API，对于货币数据，我们将使用 Open Exchange Rates。在撰写本文时，这些 API 是免费提供的，尽管它们都需要注册。

## 介绍 OpenWeatherMap API

在您的网络浏览器中，访问 URL [`api.openweathermap.org/data/2.5/weather?q=London,uk&units=metric&appid=cb932829eacb6a0e9ee4f38bfbf112ed`](http://api.openweathermap.org/data/2.5/weather?q=London,uk&units=metric&appid=cb932829eacb6a0e9ee4f38bfbf112ed)。您应该看到类似以下截图的内容：

![介绍 OpenWeatherMap API](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_04_02.jpg)

这是伦敦的 JSON 天气数据，设计成自动读取而不是人工读取。在看如何将这些数据读入我们的 Headlines 应用程序之前，请注意我们访问的 URL 有一个`appid`参数。尽管天气数据是免费提供的，但每个访问数据的开发人员都需要在 OpenWeatherMap 注册一个免费账户，并获取一个唯一的 API 密钥作为`appid`参数的值。这是为了防止人们滥用 API，进行过多的请求，并占用可用的带宽。在撰写本文时，OpenWeatherMap 允许每分钟对 API 进行 60 次调用，每天 50000 次作为他们的免费访问计划的一部分，因此我们的项目不太可能达到这些限制。

### 注册 OpenWeatherMap

您应该注册自己的 API 密钥，而不是使用本书中发布的密钥。通常，您的 API 密钥应保持秘密，并且应避免共享它（尤其是避免在书中发布它）。要获取您自己的 API 密钥，请转到[www.openweathermap.org](http://www.openweathermap.org)，并通过单击页面顶部的注册链接完成他们的注册流程。填写电子邮件地址，用户名和密码。注册页面应该类似于以下截图：

![注册 OpenWeatherMap](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_04_03.jpg)

## 检索您的 OpenWeatherMap API 密钥

注册后，您将能够登录 OpenWeatherMap。您可以通过导航到[home.openweathermap.org](http://home.openweathermap.org)并向下滚动到**API 密钥**文本框找到您的个人 API 密钥。您应该在以下图像中看到您的 API 密钥，如红色矩形所示：

![检索您的 OpenWeatherMap API 密钥](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_04_04.jpg)

将密钥复制到剪贴板，因为我们很快将在我们的 Python 代码中使用它。

## 使用 Python 解析 JSON

现在我们可以通过使用 URL 在 HTTP 上访问结构化的天气数据。但是在浏览器中这样做并没有太大用处，因为我们希望从我们的 Python 代码自动读取这些数据。幸运的是，Python 有一堆有用的标准库，正好适用于这种用例！

## 介绍 JSON

JSON 是一种结构化数据格式，非常类似于 Python 字典，从前面的示例中应该很明显。实际上，在这种情况下，它是相同的，我们可以非常简单地将其转换为 Python 字典，以便在我们的 Flask 应用程序中使用，方法是将其加载为字符串，然后在其上运行内置的 Python `eval`函数。然而，JSON 并不总是与 Python 字典相同。例如，它使用`true`和`false`而不是`True`和`False`（注意大小写的区别）-将任何我们无法完全控制的东西传递给`eval()`通常是一个坏主意。因此，我们将使用`Python json`库来安全地解析它。我们还将使用 Python `urllib2`库从网络上下载数据，并使用 Python `urllib`库正确编码 URL 参数。

## 在 Python 中检索和解析 JSON

对于在 Python 中检索和解析 JSON，第一步是向我们的`headlines.py`文件添加我们需要的三个新导入：

```py
import json
import urllib2
import urllib
```

**风格提示：**

### 提示

为了良好的 Python 风格，保持导入按字母顺序排列。您可以在以下网站阅读有关导入排序约定的更多信息：[`www.python.org/dev/peps/pep-0008/#imports`](https://www.python.org/dev/peps/pep-0008/#imports)

现在添加一个新函数`get_weather()`，它将使用特定查询调用天气 API。这很简单，代码如下。用你从 OpenWeatherMap 页面复制的 API 密钥替换`<your-api-key-here>`占位符。

```py
def get_weather(query):
    api_url = http://api.openweathermap.org/data/2.5/weather?q={}&units=metric&appid=<your-api-key-here>
    query = urllib.quote(query)
    url = api_url.format(query)
    data = urllib2.urlopen(url).read()
    parsed = json.loads(data)
    weather = None
    if parsed.get("weather"):
        weather = {"description":parsed["weather"][0]["description"],"temperature":parsed["main"]["temp"],"city":parsed["name"]
                  }
    return weather
```

我们在浏览器中使用与之前相同的 URL，但是我们使查询部分可配置，以便检索天气数据的城市是动态的。我们在查询变量上使用`urllib.quote()`，因为 URL 中不能有空格，但是我们想要检索天气的城市的名称可能包含空格。`quote()`函数通过将空格转换为"`%20`"（这是 URL 中表示空格的方式）来处理这个问题。然后我们使用`urllib2`库将数据通过 HTTP 加载到 Python 字符串中。与我们的 feedparsing 示例一样，通过互联网下载数据总是潜在不稳定的，对于真实的应用程序，我们需要在这里添加一些异常处理和重试逻辑。

然后我们使用 json 库的`loads()`函数（加载字符串）将我们下载的 JSON 字符串转换为 Python 字典。最后，我们根据 API 返回的 JSON 构建一个更简单的 Python 字典，因为 OpenWeatherMap 提供了一大堆我们不需要的属性。

## 使用我们的天气代码

现在对`get_news()`函数进行两个小改动，以便使用我们的`get_weather()`函数。我们需要调用`get_weather()`函数（现在我们只会传入伦敦作为常量），然后将天气数据传递给我们的模板。`get_news()`函数现在应该如下所示：

```py
@app.route("/")
def get_news():
        query = request.args.get("publication")
        if not query or query.lower() not in RSS_FEEDS:
                publication = "bbc"
        else:
                publication = query.lower()
        feed = feedparser.parse(RSS_FEEDS[publication])
        weather = get_weather("London,UK")
        return render_template("home.html",articles=feed["entries"],weather=weather)

```

现在将伦敦的简化数据加载到天气变量中，并将其传递给我们的模板文件，以便我们可以向用户显示数据。

## 显示天气数据

现在我们只需要调整我们的模板来适应额外的数据。我们将在新闻标题上方显示天气数据，并添加一些二级标题以保持我们应用程序的不同部分有序。

在开头的`<h1>`标签后面，向 home.html 模板添加以下三行：

```py
<body>
  <h1>Headlines</h1>
  <h2>Current weather</h2>
  <p>City: <b>{{weather.city}}</b></p>
  <p>{{weather.description}} |{{weather.temperature}}℃</p>
  <h2>Headlines</h2>

```

这里没有我们之前没有见过的东西。我们只需使用大括号从我们的天气变量中获取我们想要的部分。有趣的`&#8451;`部分是为了显示摄氏度符号。如果你是那些能够理解华氏度概念的人之一，那么从 API URL 中删除`&units=metric`（这将告诉 OpenWeatherData 以华氏度给我们温度），并在模板中使用`&#8457;`代替*F*符号来显示给我们的用户。

## 允许用户自定义城市

如前所述，我们并不总是想显示伦敦的天气。让我们为城市添加第二个搜索框！搜索通常很困难，因为用户输入的数据从来都不一致，而计算机喜欢一致。幸运的是，我们正在使用的 API 非常灵活，因此我们将直接传递用户的输入，并将困难的部分留给其他人处理。

### 在我们的模板中添加另一个搜索框

我们将搜索框添加到我们的模板中，就像以前一样。这个表单直接放在`home.html`文件中“当前天气”标题下面。

```py
<form>
  <input type="text" name="city" placeholder="weather search">
  <input type="submit" value="Submit">
</form>
```

在前面的代码片段中定义的表单简单地使用了一个命名文本输入和一个提交按钮，就像我们为出版物输入添加的那样。

### 在我们的 Python 代码中使用用户的城市搜索

在我们的 Python 代码中，我们需要在 GET 请求中查找`city`参数。我们的“get_news（）”函数不再命名良好，因为它不仅仅是获取新闻。让我们进行一些重构。之后，我们将有一个“home（）”函数，该函数调用获取新闻和天气数据（以及以后的货币数据），我们的“get_news（）”函数将再次只负责获取新闻。我们还将有很多不同事物的默认值，因此我们将添加一个`DEFAULTS`字典作为全局变量，每当我们的代码无法在 GET 参数中找到信息时，它将返回到那里获取所需的信息。我们代码的更改部分（不包括导入、全局 URL 和最后的主要部分）现在看起来像这样：

```py
# ...

DEFAULTS = {'publication':'bbc',
            'city': 'London,UK'}

@app.route("/")
def home():
    # get customized headlines, based on user input or default
    publication = request.args.get('publication')
    if not publication:
        publication = DEFAULTS['publication']
    articles = get_news(publication)
    # get customized weather based on user input or default
    city = request.args.get('city')
    if not city:
        city = DEFAULTS['city']
    weather = get_weather(city)
return render_template("home.html", articles=articles,weather=weather)

def get_news(query):
    if not query or query.lower() not in RSS_FEEDS:
        publication = DEFAULTS["publication"]
    else:
        publication = query.lower()
    feed = feedparser.parse(RSS_FEEDS[publication])
    return feed['entries']

def get_weather(query):
    query = urllib.quote(query)
    url = WEATHER_URL.format(query)
    data = urllib2.urlopen(url).read()
    parsed = json.loads(data)
    weather = None
    if parsed.get('weather'):
        weather = {'description':parsed['weather'][0]['description'],'temperature':parsed['main']['temp'],'city':parsed['name']}
    return weather
```

现在我们有了良好的关注点分离-我们的“get_weather（）”函数获取天气数据，我们的“get_news（）”函数获取新闻，我们的“home（）”函数将两者结合起来，并处理用户的输入，向我们的访问者显示定制数据。

## 检查我们的新功能

如果一切顺利，我们现在应该有一个显示可定制新闻和天气数据的网站。如前所述，天气搜索非常灵活。尝试一些不同的输入-您应该会看到一个类似以下图像的页面：

![检查我们的新功能](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_04_05.jpg)

## 处理重复的城市名称

OpenWeatherMap API 很好地处理了重复的城市名称，尽管默认值有时有点反直觉。例如，如果我们搜索伯明翰，我们将得到美国的那个。如果我们想要查找英国的伯明翰，我们可以搜索伯明翰，英国。为了不让观众感到困惑，我们将对显示城市旁边的国家进行小修改。然后他们将立即能够看到是否得到了与他们预期的城市不同的结果。如果您检查我们的天气调用的完整 API 响应，您会发现国家代码列在`sys`下-我们将获取它，添加到我们的自定义字典中，然后在我们的模板中显示它。

在`get_weather`函数中，修改我们构建字典的行：

```py
weather = {'description': parsed['weather'][0]['description'],
           'temperature': parsed['main']['temp'],
           'city': parsed['name'],
 'country': parsed['sys']['country']
          }
```

并在我们的模板中修改显示城市的行如下：

```py
<p>City: <b>{{weather.city}}, {{weather.country}}</b></p>
```

检查它是否工作-如果您重新启动应用程序并重新加载页面，您应该会看到在“当前天气”搜索框中键入“伯明翰”现在显示城市名称旁边的国家代码。

![处理重复的城市名称](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_04_06.jpg)

## 货币

货币数据被认为比天气数据更有价值。许多商业服务提供经常更新且非常可靠的 API。但是，免费的 API 有点罕见。一个提供有限免费 API 的服务是 Open Exchange Rates-再次，我们需要注册一个免费帐户以获得 API 密钥。

### 获取 Open Exchange Rates API 的 API 密钥

转到[openexchangerates.com](http://openexchangerates.com)，并完成他们的注册流程。 点击**注册**链接后，它可能看起来他们只有付费计划，因为这些更加突出显示。 但是，在大型付费计划选项下方，有一行描述其免费提供的单行文本，并附有选择它的链接。 点击这个链接，并输入您的详细信息。

如果您没有自动重定向，请转到他们网站上的仪表板，您会看到您的**API 密钥**（应用程序 ID）显示出来。 复制这个，因为我们需要将其添加到我们的 Python 代码中。 您可以在以下截图中看到如何找到您的 API 密钥的示例：

![获取 Open Exchange Rates API 的 API 密钥](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_04_07.jpg)

### 使用 Open Exchange Rates API

`currency` API 返回的 JSON 与`weather` API 一样，因此我们可以非常容易地将其集成到我们的 Headlines 应用程序中。 我们需要将 URL 添加为全局变量，然后添加一个新函数来计算汇率。 不幸的是，API 的免费版本受限于返回所有主要货币相对于美元的汇率，因此我们将不得不为不涉及美元的转换计算我们自己的近似汇率，并依赖于一个完美的市场尽可能地保持我们的信息准确（参见[`en.wikipedia.org/wiki/Triangular_arbitrage`](http://en.wikipedia.org/wiki/Triangular_arbitrage)）。

在现有的`WEATHER_URL`下面的全局变量中添加变量`CURRENCY_URL`，如下面的代码片段所示。 您需要替换自己的 App ID。

```py
WEATHER_URL = "http://api.openweathermap.org/data/2.5/weather?q={}&units=metric&APPID=<your-api-key-here>"
CURRENCY_URL = "https://openexchangerates.org//api/latest.json?app_id=<your-api-key-here>"
```

添加`get_rates()`函数如下：

```py
def get_rate(frm, to):
        all_currency = urllib2.urlopen(CURRENCY_URL).read()

        parsed = json.loads(all_currency).get('rates')
        frm_rate = parsed.get(frm.upper())
        to_rate = parsed.get(to.upper())
        return to_rate/frm_rate
```

请注意我们在最后进行的计算。 如果请求是从美元到其他任何货币，我们可以简单地从返回的 JSON 中获取正确的数字。 但在这种情况下，计算是足够简单的，因此不值得添加额外的逻辑步骤来判断我们是否需要进行计算。

### 使用我们的货币功能

现在我们需要从我们的`home()`函数中调用`get_rates()`函数，并将数据传递给我们的模板。 我们还需要向我们的`DEFAULTS`字典添加默认货币。 根据以下突出显示的代码进行更改：

```py
DEFAULTS = {'publication':'bbc',
            'city': 'London,UK',
 'currency_from':'GBP',
 'currency_to':'USD'
}

@app.route("/")
def home():
    # get customized headlines, based on user input or default
    publication = request.args.get('publication')
    if not publication:
        publication = DEFAULTS['publication']
    articles = get_news(publication)
    # get customized weather based on user input or default
    city = request.args.get('city')
    if not city:
        city = DEFAULTS['city']
    weather = get_weather(city)
    # get customized currency based on user input or default
    currency_from = request.args.get("currency_from")
    if not currency_from:
        currency_from = DEFAULTS['currency_from']
    currency_to = request.args.get("currency_to")
    if not currency_to:
        currency_to = DEFAULTS['currency_to']
    rate = get_rate(currency_from, currency_to)
    return render_template("home.html", articles=articles,weather=weather,
                           currency_from=currency_from, currency_to=currency_to, rate=rate)
```

### 在我们的模板中显示货币数据

最后，我们需要修改我们的模板以显示新数据。 在`home.html`中的天气部分下面添加：

```py
<h2>Currency</h2>
1 {{currency_from}} = {{currency_to}} {{rate}}
```

像往常一样，在浏览器中检查一切是否正常运行。 您应该看到英镑兑美元的默认货币数据，如下图所示：

![在我们的模板中显示货币数据](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_04_08.jpg)

### 为用户选择货币添加输入

现在我们需要添加另一个用户输入来自定义要显示的货币。 我们可以像之前两个一样轻松地添加另一个文本搜索，但这会变得混乱。 我们需要用户的两个输入：*从*货币和*到*货币。 我们可以添加两个输入，或者我们可以要求用户将两者输入到同一个输入中，但前者会使我们的页面变得非常凌乱，而后者意味着我们需要担心正确地拆分用户输入数据（这几乎肯定不一致）。 相反，让我们看看另一个输入元素，HTML `select`。 您几乎肯定在其他网页上看到过这些——它们是带有用户可以选择的值列表的下拉菜单。 让我们看看如何在 HTML 中构建它们，以及如何在 Flask 中抓取它们的数据。

### 创建 HTML 选择下拉元素

首先，在每个下拉菜单中硬编码四种货币。 代码应该插入在`home.html`模板中**货币**标题的下方，代码如下：

```py
<form>
    from: <select name="currency_from">
            <option value="USD">USD</option>
            <option value="GBP">GBP</option>
            <option value="EUR">EUR</option>
            <option value="ZAR">ZAR</option>
          </select>

     to: <select name="currency_to">
           <option value="USD">USD</option>
           <option value="GBP">GBP</option>
           <option value="EUR">EUR</option>
           <option value="ZAR">ZAR</option>
         </select>
         <input type="submit" value="Submit">
</form>
```

用于 GET 请求参数的名称是选择标签本身的属性（类似于我们在`<input type="text">`标签中使用的名称属性）。在我们的情况下，这些是`currency_from`和`currency_to`，这些是我们之前在 Python 代码中指定的。值稍微有些棘手——我们有在 GET 请求中传递的值（例如`currency_from=EUR`），然后是显示给用户的值。在这种情况下，我们将两者都使用相同的——货币代码——但这不是强制的。例如，我们可以在显示值中使用货币的全名，如美元，在请求中传递代码。参数值被指定为`<option>`标签的属性，每个都是`<select>`的子元素。显示值插入在开放和关闭的`<option>`和`</option>`标签之间。

测试一下，确保它能正常工作，保存模板并重新加载页面。您应该会看到下拉输入框出现，如下图所示：

![创建 HTML 选择下拉元素](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_04_09.jpg)

### 将所有货币添加到选择输入中

当然，我们可以像前一节那样对完整列表进行操作。但是我们是程序员，不是数据捕捉者，所以我们将使列表动态化，使用`for`循环插入选项，并保持我们的模板更新和清晰。为了获取货币列表，我们可以简单地获取 JSON `all_currency`对象的键，以便使我们的`get_rate()`函数返回一个元组——计算出的汇率和货币列表。然后我们可以将（排序后的）列表传递给我们的模板，模板可以循环遍历它们并用它们构建下拉列表。更改如下所示：

在`home()`函数中进行以下更改：

```py
        if not currency_to:
          currency_to=DEFAULTS['currency_to']
 rate, currencies = get_rate(currency_from, currency_to)
 return render_template("home.html", articles=articles,weather=weather, currency_from=currency_from, currency_to=currency_to,    rate=rate,currencies=sorted(currencies))
```

在`get_rate()`函数中：

```py
frm_rate = parsed.get(frm.upper())
to_rate = parsed.get(to.upper())
return (to_rate / frm_rate, parsed.keys())

```

在`home.html`模板中：

```py
        <h2>Currency</h2>
        <form>
                from: <select name="currency_from">
 {% for currency in currencies %}
 <optionvalue="{{currency}}">{{currency}}</option>
 {% endfor %}
                      </select>

                to: <select name="currency_to">
 {% for currency in currencies %}
 <option value="{{currency}}">{{currency}}</option>
 {% endfor %}

                    </select>
                <input type="submit" value="Submit">
        </form>
        1 {{currency_from}} = {{currency_to}} {{rate}}
```

### 在下拉输入中显示所选货币

之后，我们应该能够轻松地查看任何我们想要的货币的汇率。一个小小的烦恼是下拉框总是默认显示顶部项目。如果它们显示当前选定的值会更直观。我们可以通过在我们的选择标签中设置`selected="selected"`属性和一个简单的一行 Jinja `if`语句来实现这一点。更改我们`home.html`模板中货币输入的`for`循环如下：

对于`currency_from`循环：

```py
{% for currency in currencies %}
    <option value="{{currency}}" {{'selected="selected"' if currency_from==currency}}>{{currency}}</option>
{% endfor %}
```

对于`currency_to`循环：

```py
{% for currency in currencies %}
    <option value="{{currency}}" {{'selected="selected"' if currency_to==currency}}>{{currency}}</option>
{% endfor %}
```

重新加载应用程序和页面，现在您应该能够从两个选择输入中选择任何可用的货币，并且在页面加载所需的货币数据后，选择输入应该自动显示当前货币，如下图所示。单击选择输入后，您还应该能够在键盘上输入并根据您输入的首字母选择选项。

![在下拉输入中显示所选货币](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_04_10.jpg)

现在我们可以同时看到新闻、天气和货币数据！您可以从本章的代码包中参考完整的代码。

# 总结

在本章中，我们看了一下 HTTP GET 和 POST 请求之间的区别，并讨论了在何时使用哪种请求。虽然目前我们没有好的用途来使用 HTTP POST，但在未来的项目中，我们将从用户那里获取登录数据时使用它。幸运的是，我们对 HTTP POST 的解释工作并没有白费——我们还看了一些 Git 可以帮助我们进行版本控制的更高级的方法，我们未使用的代码安全地存储在代码库的不同分支中，以防以后需要参考。最后但并非最不重要的是，我们将天气和货币数据添加到了我们的应用程序中，并研究了一些不同的选项，以允许用户向我们的应用程序输入数据。我们的第一个项目快要完成了！

在下一章中，我们将进行一些修饰性的润色，并考虑如何记住我们的用户，这样他们就不必每次访问我们的网站时都执行完全相同的操作。


# 第五章：改进我们的头条项目的用户体验

富有的商人们为了不断给人留下良好印象以保持有利可图的关系，有时会雇佣个人助理来研究他们的熟人。然后，个人助理会站在社交活动中富有的人的身后，对即将接触的人耳语几句关键的话。这些话必须简洁但具有信息量，比如“保罗·史密斯。一个孩子，吉尔。最近去了毛里求斯”。现在，我们的商人可以假装接近的人是一个亲密的朋友，并且长篇大论地谈论他的孩子和旅行，而实际上并不知道这个人是谁。这会让其他人觉得重要和受欢迎，这有助于我们假设的百万富翁变得更加富有。

为什么这与 Web 应用程序相关呢？好吧，我们想做的就是这样。我们网站的用户觉得重要和被记住，更有可能回来，所以我们需要一个数字助理，让用户觉得我们花了时间和精力来记住他们是谁以及他们喜欢什么。我们可以建立一个用户数据库，存储他们通常计算的货币转换和他们感兴趣的城市天气，然后默认显示给他们。这种策略的问题在于我们需要他们在每次访问时进行身份识别，而大多数用户会觉得输入用户名，可能还有密码，这一额外步骤很烦人。

输入 HTTP cookie。这些狡猾的小东西将潜伏在我们用户的计算机上，在用户第二次访问我们的网站时，充当我们的数字助理，给我们提供我们以前获得但没有记住的信息。这听起来相当不光彩。有一段时间，欧盟也是这么认为的，并试图对 cookie 的使用进行监管，但它们无处不在，简单而有用，监管尝试有点令人失望（请看[`silktide.com/the-stupid-cookie-law-is-dead-at-last/`](http://silktide.com/the-stupid-cookie-law-is-dead-at-last/)）。

在最简单的形式中，cookie 只是我们存储在用户计算机上的键值对，并要求他们的浏览器在访问我们的网站时自动发送给我们。这样做的好处是我们不必保留和维护数据库，也不必明确要求用户告诉我们他们是谁。然而，缺点是我们无法控制这些信息，如果用户更换计算机、Web 浏览器，甚至只是删除我们的 cookie，我们将无法再识别他或她。因此，cookie 非常适合我们构建的应用程序；如果用户不得不点击几次才能回到上次搜索的媒体、货币和天气信息，这并不是世界末日，但如果我们能记住以前的选择并自动显示这些信息，那就很好。

当我们谈论用户体验（通常称为 UX）时，我们的网站看起来好像是上世纪 80 年代制作的。我们将在后面的章节中更加注重美学，但现在我们也将看看如何向我们的网站添加一些基本的布局和颜色。因为我们专注于功能和简单性，所以它仍然远非“现代化”，但我们将向我们的工具包添加一些基本组件，以便以后更加谨慎地使用。我们将使用层叠样式表（通常简称为 CSS）来实现这一点。CSS 是一个很好的工具，可以进一步分离关注点；我们已经主要将逻辑（即我们的 Python 脚本）与内容（即我们的 HTML 模板）分开。现在，我们将看看 CSS 如何帮助我们将格式（颜色、字体、布局等）与我们的其他内容（例如模板文件中的静态文本）分开。

现在我们已经概述了 cookies 和 CSS，我们将开始研究如何在 Flask 中实现它们。这是我们第一个项目的最后一章，到最后，我们将拥有一个包括 cookies 和 CSS 的 Headlines 应用程序。

在本章中，我们将研究以下主题：

+   向我们的 Headlines 应用程序添加 cookies

+   向我们的 Headlines 应用程序添加 CSS

# 向我们的 Headlines 应用程序添加 cookies

在这一点上，我们的应用程序有一些问题。让我们想象一个名叫鲍勃的用户，他住在西雅图。鲍勃访问我们的网站，看到了 BBC，伦敦和将 GBP 转换为 USD 的默认值。鲍勃想要看到西雅图的天气，所以他在**天气搜索**栏中输入`西雅图`并按下回车键。他浏览返回的天气，感到很沮丧，因为天气一如既往地寒冷和下雨，所以他从页面底部的天气中看向 BBC 的头条新闻。他更喜欢 CNN 的头条新闻，所以他从下拉菜单中选择了这个出版物并点击**提交**。他读了几条头条新闻后意识到时事新闻甚至比天气更沉闷和令人沮丧。所以，他的眼睛再次移回页面顶部来振作自己。他感到困惑；自从更改了他的出版物偏好后，天气又默认回到了伦敦，那里的天气甚至更糟糕！他关闭了我们的应用程序，不再回来。如果他回来，一切都会再次显示默认值。

两个直接问题是：

+   即使用户在我们的网站上停留，也不记住用户的选择

+   用户关闭我们的网站并在以后重新访问时不记住用户的选择

让我们解决这两个问题。

## 使用 Flask 处理 cookies

如前所述，cookies 可以被视为我们可能或可能不会从返回访客那里收到的键值对。我们需要改变我们的应用程序，这样当用户做出选择时，我们创建或更新他们的 cookie 以反映这些更改，当用户请求我们的网站时，我们检查是否存在 cookie，并尽可能多地从中读取未指定的信息。首先，我们将看看如何设置 cookies 并让用户的浏览器自动记住信息，然后我们将看看如何检索我们以前使用 cookies 存储的信息。

### 在 Flask 中设置 cookies

Flask 使处理 cookies 变得非常容易。首先，我们需要更多的导入；我们将使用 Python 的`datetime`库来设置即将存在的 cookies 的寿命，我们将使用 Flask 的`make_response()`函数来创建一个响应对象，我们可以在其上设置 cookies。在`headlines.py`文件的导入部分中添加以下两行：

```py
import datetime
from flask import make_response
```

之前，我们只是用自定义参数渲染我们的模板，然后将其返回给用户的网络浏览器。为了设置 cookies，我们需要额外的步骤。首先，我们将使用新的`make_response()`函数创建一个响应对象，然后使用这个对象设置我们的 cookie。最后，我们将返回整个响应，其中包括渲染的模板和 cookies。

用以下行替换`headlines.py`中`home()`函数的最后一行：

```py
response = make_response(render_template("home.html",
  articles=articles,
  weather=weather,
  currency_from=currency_from,
  currency_to=currency_to,
  rate=rate,
  currencies=sorted(currencies)))
expires = datetime.datetime.now() + datetime.timedelta(days=365)
response.set_cookie("publication", publication, expires=expires)
response.set_cookie("city", city, expires=expires)
response.set_cookie("currency_from",
  currency_from, expires=expires)
response.set_cookie("currency_to", currency_to, expires=expires)
return response
```

这与我们之前简单的返回语句相比是一个相当大的改变，所以让我们来详细分析一下。首先，我们将在我们的`render_template()`调用周围包装一个`make_response()`调用，而不是直接返回渲染的模板。这意味着我们的 Jinja 模板将被渲染，所有的占位符将被替换为正确的值，但是我们不会直接将这个响应返回给用户，而是将它加载到一个变量中，以便我们可以对它进行一些更多的添加。一旦我们有了这个响应对象，我们将创建一个值为今天日期后 365 天的`datetime`对象。然后，我们将在我们的`response`对象上进行一系列的`set_cookie()`调用，保存所有用户的选择（或刷新以前的默认值），并将到期时间设置为从设置 cookie 的时间开始的一年，使用我们的`datetime`对象。

最后，我们将返回包含渲染模板的 HTML 和我们的四个 cookie 值的`response`对象。在加载页面时，用户的浏览器将保存这四个 cookies，如果同一用户再次访问我们的应用程序，我们将能够检索这些值。

### 在 Flask 中检索 cookies

如果我们不对信息进行任何处理，那么记住这些信息也没有太大的意义。在向用户发送响应之前，我们现在将 cookies 设置为最后一步。然而，当用户向我们发送请求时，我们需要检查保存的 cookies。如果你还记得我们如何从 Flask 的请求对象中获取命名参数，你可能猜到如何获取保存的 cookies。如果存在，以下行将获取名为`publication`的 cookie：

```py
request.cookies.get("publication")
```

这很简单，对吧？唯一棘手的部分是正确获取我们的回退逻辑。我们仍然希望显式请求具有最高优先级；也就是说，如果用户输入文本或从下拉菜单中选择一个值，这将是他或她想要的，而不管我们对以前的访问期望如何。如果没有显式请求，我们将查看 cookies，以检查是否可以从中获取默认值。最后，如果我们仍然没有任何内容，我们将使用我们硬编码的默认值。

#### 编写回退逻辑以检查 cookies

首先，让我们只为`publication`实现这个逻辑。在`headlines.py`的`home()`函数中的 publication 逻辑中添加一个新的`if`块，使其匹配以下内容：

```py
# get customised headlines, based on user input or default
publication = request.args.get("publication")
if not publication:
 publication = request.cookies.get("publication")
    if not publication:
        publication = DEFAULTS["publication"]
```

现在，我们将查看 GET 参数，必要时回退到保存的 cookies，最后回退到我们的默认值。让我们看看这个工作。打开你的网络浏览器，导航到`localhost:5000`。在**Publication**搜索栏中搜索`Fox`，等待页面重新加载，显示 Fox News 的头条新闻。现在，关闭你的浏览器，重新打开它，再次加载`localhost:5000`。这次，你应该看到 Fox 的头条新闻，而不需要再搜索它们，就像下面的截图一样。

请注意，URL 中没有`publication`参数，但是头条新闻现在是来自 Fox News。

![编写回退逻辑以检查 cookies](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_05_01.jpg)

#### 检索其他数据的 cookies

我们的 publication 有基本的 cookies 工作，但我们仍然希望读取我们可能为天气和货币选项保存的 cookies。我们可以简单地在代码的每个部分添加相同的 if 语句，将`city`、`currency_from`和`currency_to`替换为相关的`publication`，但是在代码的许多部分进行相同的更改是我们需要进行一些重构的明显迹象。

让我们创建一个`get_value_with_fallback()`函数，它在更抽象的层面上实现了我们的回退逻辑。将新函数添加到`headlines.py`文件中，并从`home()`函数中调用它，如下所示：

```py
def get_value_with_fallback(key):
    if request.args.get(key):
        return request.args.get(key)
    if request.cookies.get(key):
        return request.cookies.get(key)
    return DEFAULTS[key]

@app.route("/")
def home():
    # get customised headlines, based on user input or default
    publication = get_value_with_fallback("publication")
    articles = get_news(publication)

    # get customised weather based on user input or default
    city = get_value_with_fallback("city")
    weather = get_weather (city)

    # get customised currency based on user input or default
    currency_from = get_value_with_fallback("currency_from")
    currency_to = get_value_with_fallback("currency_to")
    rate, currencies = get_rate(currency_from, currency_to)

    # save cookies and return template
    response = make_response(render_template("home.html", articles=articles, weather=weather, currency_from=currency_from, currency_to=currency_to, rate=rate, currencies=sorted(currencies)))
    expires = datetime.datetime.now() + datetime.timedelta(days=365)
    response.set_cookie("publication", publication, expires=expires)
    response.set_cookie("city", city, expires=expires)
    response.set_cookie("currency_from", currency_from, expires=expires)
    response.set_cookie("currency_to", currency_to, expires=expires)
    return response
```

现在，我们应该能够以任何顺序提交表单，并且所有的选项都能被记住，就像我们期望的那样。此外，每当我们访问我们的网站时，它都会自动配置为我们最近使用的选项。试一试吧！您应该能够搜索货币、天气和头条新闻；然后关闭浏览器；再次访问网站。您最近使用的输入应该默认显示出来。

在下面的截图中，我们可以看到 URL 中没有传递任何参数，但我们正在显示南非伊丽莎白港的天气数据；从**人民币**（**CNY**）到**圣赫勒拿镑**（**SHP**）的货币数据；以及来自福克斯新闻的头条新闻。

![检索其他数据的 cookies](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_05_02.jpg)

# 向我们的 Headlines 应用程序添加 CSS

我们的网站仍然相当简陋。有很多白色和一些黑色。大多数用户更喜欢颜色、动画、边框、边距等。如前所述，我们现在不会真正关注美学，但我们会添加一些基本的颜色和样式。

## 外部、内部和内联 CSS

CSS 可以以几种方式添加到网页中。最好的方法是将其与 HTML 完全分开，并将其保存在一个外部文件中，该文件在 HTML 中通过`<link>`元素包含。这有时被称为*外部 CSS*。最糟糕的方法被称为*内联 CSS*。使用内联方法，CSS 是根据每个元素定义的；这被认为是不好的做法，因为对样式的任何更改都需要在 HTML 中查找相关部分。

此外，页面上的许多元素通常具有相同或至少相关的样式，以保持整个站点的颜色方案和样式。因此，使用内联样式通常会导致大量的代码重复，我们知道要避免这种情况。

对于这个项目，我们将采取一个折中的方法。我们将保持我们在`.html`模板文件中定义的 CSS，但我们将把它们都定义在一个地方。这是因为我们还没有看过 Flask 如何按照惯例处理文件，所以现在把所有的代码放在一个地方更简单。

## 添加我们的第一个 CSS

CSS 非常简单；我们将通过类型、ID、类等描述页面的元素，并为这些元素定义许多属性，如颜色、布局、填充、字体等。CSS 被设计为*级联*，也就是说，如果我们没有为更具体的元素指定属性，它将自动继承为更一般的元素定义的属性。我们将快速浏览 CSS 本身，所以如果您以前从未听说过它，并且想了解更多关于它的信息，现在是一个适当的时机休息一下，查看一些特定于 CSS 的资源。在线有很多这样的资源，一个快速搜索就会揭示出来；如果您喜欢我们之前提到的 W3Schools HTML 教程，您可以在这里找到类似的 CSS 教程[`www.w3schools.com/css/`](http://www.w3schools.com/css)。或者，通过接下来的示例和简要解释来深入了解！

首先，让我们为我们的网站添加一个更好的标题。我们将在顶级标题下方添加一个标语，并用一个新的`<div>`标签将其包围起来，以便我们可以在即将到来的 CSS 中修改整个标题。修改`home.html`模板的开头如下所示：

```py
<div id="header">
    <h1>Headlines</h1>
 <p>Headlines. Currency. Weather.</p>
 <hr />
</div>

```

`<div>`标签本身并没有做任何事情，您可以将其视为一个容器。我们可以使用它将逻辑相关的元素分组到同一个元素中，这对于 CSS 非常有用，因为我们可以一次性地为`<div>`标签中的所有元素设置样式。

CSS 应该添加到我们模板的`<head>`部分中的`<style>`标签中。在我们的`home.html`模板中的`<title>`标签下面，添加以下代码：

```py
<style>
html {
    font-family: "Helvetica";
    background: white;
}

body {
    background: lightgrey;
    max-width: 900px;
    margin: 0 auto;
}

#header {
    background: lightsteelblue;
}
</style>
```

我们明确定义了三个元素的样式：外部`<html>`元素，`<body>`元素和具有`id="header"`属性的任何元素。由于我们所有的元素都在`<html>`元素内部，字体会自动向下级元素级联（尽管仍然可以被子元素显式覆盖）。我们将页面中所有可见项包含在`<body>`元素中，并将其最大宽度设置为 900 像素。`margin: 0 auto;`表示`<body>`顶部和底部没有边距，左右两侧有自动边距。这会使页面上的所有内容居中。`background: white;`和`background: lightgrey;`表示我们将在较大的窗口内有一个居中的主要元素，其背景为浅灰色，而窗口本身为白色。最后，我们定义的头部`div`将具有浅钢蓝色的背景。保存添加样式的页面并刷新以查看效果。它应该看起来类似于以下图片：

![添加我们的第一个 CSS](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_05_03.jpg)

让我们看看如何在下一节中改善美学。

**浏览器和缓存**

### 提示

浏览器通常会在本地缓存不经常更改的内容，以便在下次访问页面时更快地显示页面。这对开发来说并不理想，因为您希望在进行更改时看到更改。如果您的样式似乎没有达到您的预期，请清除浏览器的缓存，然后重试。在大多数浏览器上，可以通过按下*Ctrl* + *Shift* + *ESC*并从弹出的菜单中选择相关选项来完成此操作。

## 向我们的 CSS 添加填充

这比白色背景上的黑色略有趣，但仍然相当丑陋。一个问题是文本紧贴着颜色的边缘，没有任何空间。我们可以使用*CSS 填充*来解决这个问题，它可以通过指定的数量从顶部、右侧、底部、左侧或任何组合移动所有内容。

我们可以直接向我们的`<body>`标签添加填充，因为我们希望所有文本都有一个漂亮的左侧缓冲区。如果您尝试这样做，您会看到一个直接的问题；填充会影响所有内容，包括我们的`<div>`头部和将其与其余内容分隔开的`<hr>`标签，这意味着会有一条我们不想要的奇怪的灰色条纹。我们将以一种您很快会用于几乎所有与 CSS 相关的事情的方式来解决这个问题——只需添加更多的 div！我们需要一个*main*`<div>`头部，围绕所有的子标题和一个内部头部 div，这样我们就可以填充头部的文本，而不填充背景颜色或分隔符。

### 在我们的 CSS 中添加更多样式

将以下部分添加到您的 CSS 中，为我们的主要和内部头部 div 定义左侧填充，并更新`#header`部分以包括一些顶部填充：

```py
#header {
  padding-top: 5;
  background: lightsteelblue;
}
#inner-header {
  padding-left: 10;
}
#main{
  padding-left: 10;
}
```

### 将 div 标签添加到模板文件

现在，让我们添加 div 本身；`home.html`中的模板代码应更新为如下所示：

```py
    <body>
        <div id="header">
            <div id="inner-header">
                <h1>Headlines</h1>
                <p>Headlines. Currency. Weather.</p>
             </div>
           <hr />
        </div>
        <div id="main">
            <h2>Current weather</h2>

... [ rest of the content code here ] ...

            {% endfor %}
        </div>
    </body>
```

## 为我们的输入添加样式

这使得布局看起来更加愉悦，因为文本看起来不像是试图溜走。接下来的一个主要问题是我们的输入元素，它们非常无聊。让我们也为它们添加一些样式。在我们迄今为止的 CSS 底部，添加以下文本：

```py
input[type="text"], select {
    color: grey;
    border: 1px solid lightsteelblue;
    height: 30px;
    line-height:15px;
    margin: 2px 6px 16px 0px;
}
input[type="submit"] {
    padding: 5px 10px 5px 10px;
    color: black;
    background: lightsteelblue;
    border: none;
    box-shadow: 1px 1px 1px #4C6E91;
}
input[type="submit"]:hover{
    background: steelblue;
}
```

第一部分样式化了我们的文本输入和选择（即下拉）元素。文本颜色是灰色，它有一个与我们标题相同颜色的边框，我们将通过高度和行高使它们比以前的默认值稍微大一点。我们还需要调整边距，使文本更自然地适应新的大小（如果你感兴趣，可以在第一部分的底部留出边距行，看看结果）。第二和第三部分是为了美化我们的**提交**按钮；一个是定义它们通常的外观，另一个是定义当鼠标移动到它们上面时的外观。再次保存这些更改并刷新页面，看看它们的外观。你应该看到类似以下截图的东西。

![美化我们的输入](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_05_04.jpg)

最终结果仍然不会赢得任何设计奖，但至少你已经学会了 CSS 的基础知识。设计网页最令人沮丧的部分之一是，每个浏览器对 CSS 的解释略有不同（或在某些情况下，差异很大）。跨浏览器测试和验证是每个网页开发人员的死敌，在后面的章节中，我们将看一些工具和框架，可以用来减轻由于潜在的不一致性而引起的问题。

# 摘要

在本章中，我们使我们的网站在功能上更加用户友好（通过使用 cookie 记住用户的选择）和美观（使用 CSS）。在以后的项目中，我们将回到这两个主题，其中我们将使用 cookie 允许用户登录和一些更高级的 CSS。这是我们 Headlines 项目的结束；我们有一个可以显示新闻、天气和货币信息的 Headlines 应用程序。

在下一章中，我们将开始建立一个新项目：一个交互式犯罪地图。


# 第六章：构建交互式犯罪地图

我们的第一个项目明显缺乏任何形式的长期存储。虽然我们通过使用 cookie 来模拟长期存储来解决问题，但我们也看到了这些方法的局限性。在这个项目中，我们将构建一个交互式犯罪地图，允许用户标记见证或经历的犯罪活动的位置细节。由于我们希望长期保留数据并使其对许多用户可用，我们不能依赖于用户的本地和临时存储。

因此，我们项目的第一步将是在我们的 VPS 上设置一个 MySQL 数据库，并将其与一个新的 Flask Web 应用程序进行链接。我们将使用 Google Maps API 允许用户查看我们的地图并向其添加新的标记（其中每个标记代表一种犯罪）。

我们的新项目将具有比我们以前的项目更高级的用户输入，允许用户过滤他们对地图的视图，并向地图添加相当复杂的数据。因此，我们将更加关注输入验证和净化。

我们项目的目标是创建一个包含交互地图的网页。用户应该能够通过选择地图上的位置并输入犯罪的日期、类别和描述来提交新的犯罪。用户还应该能够查看地图上以图标形式记录的所有先前记录的犯罪，并通过选择地图上相关图标来查看任何特定犯罪的更多细节。地图的目的是能够轻松查看犯罪率高的地区，以及帮助调查人员发现犯罪的模式和趋势。

本章的相当大一部分内容都是关于在我们的 VPS 上设置 MySQL 数据库并为犯罪数据创建数据库。接下来我们将设置一个包含地图和文本框的基本页面。我们将看到如何通过将输入到文本框中的数据存储到我们的数据库中，将 Flask 与 MySQL 进行链接。

与上一个项目一样，我们将避免在“现实世界”项目中几乎肯定会使用的框架和自动化工具。由于我们将专注于学习，较低级别的抽象是有用的。因此，我们不会为我们的数据库查询使用对象关系映射（ORM），也不会为用户输入和交互使用 JavaScript 框架。这意味着会有一些繁琐的 SQL 和纯 JavaScript 编写，但在盲目使用这些工具和框架之前，充分理解它们存在的原因以及它们解决的问题是非常重要的。

在本章中，我们将涵盖：

+   设置一个新的 Git 存储库

+   理解关系数据库

+   在我们的 VPS 上安装和配置 MySQL

+   在 MySQL 中创建我们的犯罪地图数据库

+   创建一个基本的数据库 Web 应用程序

# 设置一个新的 Git 存储库

我们将为我们的新代码库创建一个新的 Git 存储库，因为尽管一些设置将是相似的，但我们的新项目应该与我们的第一个项目完全无关。如果您需要更多关于此步骤的帮助，请返回到第一章，“你好，世界！”并按照“安装和使用 Git”部分中的详细说明进行操作。如果您感到自信，请检查您是否可以仅使用以下摘要完成此操作：

+   前往 Bitbucket、GitHub 或您用于第一个项目的任何托管平台的网站。登录并创建一个新的存储库

+   将您的存储库命名为`crimemap`并记下您收到的 URL

+   在您的本地计算机上，打开终端并运行以下命令：

```py
mkdir crimemap
cd crimemap
git init
git remote add origin <git repository URL>

```

我们将暂时将此存储库保留为空，因为我们需要在我们的 VPS 上设置一个数据库。一旦我们安装了数据库，我们将回到这里设置我们的 Flask 项目。

# 理解关系数据库

在其最简单的形式中，关系数据库管理系统，如 MySQL，就是一个类似于 Microsoft Excel 的高级电子表格程序。我们用它来以行和列的形式存储数据。每一行都是一个“*thing*”，每一列都是有关相关行中“*thing*”的特定信息。我在“*thing*”中加了引号，因为我们不仅仅局限于存储对象。事实上，在现实世界和解释数据库中，关于人的数据是最常见的“*thing*”。一个关于电子商务网站客户信息的基本数据库可能看起来类似于以下内容：

| ID | 名 | 姓 | 电子邮件地址 | 电话 |
| --- | --- | --- | --- | --- |
| 1 | 弗罗多 | 巴金斯 | `fbaggins@example.com` | +1 111 111 1111 |
| 2 | 比尔博 | 巴金斯 | `bbaggins@example.com` | +1 111 111 1010 |
| 3 | 山姆怀斯 | 甘吉 | `sgamgee@example.com` | +1 111 111 1001 |

如果我们从左到右查看单行，我们将得到有关一个人的所有信息。如果我们从上到下查看单列，我们将得到每个人的一条信息（例如，电子邮件地址）。这两种方式都很有用；如果我们想要添加一个新的人或联系特定的人，我们可能会对特定行感兴趣。如果我们想向所有客户发送通讯，我们只对电子邮件列感兴趣。

那么，为什么我们不能只使用电子表格而不是数据库呢？嗯，如果我们进一步考虑电子商务店的例子，我们很快就会看到限制。如果我们想要存储我们提供的所有物品的清单，我们可以创建另一个类似于前面的表，其中包含`Item name`、`Description`、`Price`和`Quantity in stock`等列。我们的模型仍然很有用；然而，现在，如果我们想要存储弗罗多曾经购买的所有物品的清单，就没有一个合适的地方来存放这些数据。我们可以在我们的客户表中添加 1000 列（如前所示），比如`Purchase 1`、`Purchase 2`，一直到`Purchase 1000`，并希望弗罗多永远不会购买超过 1000 件物品。这既不可扩展，也不容易处理。我们如何获取弗罗多上周二购买的物品的描述？我们只是将`name`项存储在我们的新列中吗？那些没有唯一名称的物品会发生什么？

很快，我们会意识到我们需要反向思考。我们需要创建一个名为`Orders`的新表，将每个订单中购买的物品存储在`Customers`表中，同时在每个订单中存储对客户的引用。因此，一个订单“知道”它属于哪个客户，但客户本身并不知道属于他/她的订单。

尽管我们的模型仍然可以勉强放入电子表格中，但随着我们的数据模型和规模的增长，我们的电子表格变得更加繁琐。我们需要进行复杂的查询，比如“我想看到所有库存中的物品，过去六个月至少被订购一次，并且价格超过 10 美元的物品”。

进入**关系数据库管理系统**（**RDBMS**）。它们已经存在了几十年，是一种经过验证的解决常见问题的方法（例如以有组织和可访问的方式存储具有复杂关系的数据）。我们不会在我们的犯罪地图中涉及它们的全部功能（事实上，如果需要，我们可能可以将我们的数据存储在文本文件中），但如果你有兴趣构建 Web 应用程序，你将在某个时候需要一个数据库。因此，让我们从小处着手，将强大的 MySQL 工具添加到我们不断增长的工具箱中。

我强烈建议您了解更多关于数据库的知识！如果您对构建我们当前项目的经验感兴趣，那就去阅读和学习关于数据库的知识吧。关系数据库管理系统的历史很有趣，而规范化和数据库种类的复杂性和微妙性（包括我们下一个项目中将会看到的 NoSQL 数据库）值得更多的学习时间，而这本书专注于 Python web 开发，我们无法花太多时间在这方面。

# 在我们的 VPS 上安装和配置 MySQL

安装和配置 MySQL 是一个非常常见的任务。因此，您可以在预构建的镜像或为您构建整个*stacks*的脚本中找到它。一个常见的 stack 被称为**LAMP stack**，代表**Linux**，**Apache**，**MySQL**和**PHP**，许多 VPS 提供商提供一键式的 LAMP stack 镜像。

由于我们将使用 Linux 并且已经手动安装了 Apache，在安装 MySQL 后，我们将非常接近传统的 LAMP stack；我们只是使用 P 代替 PHP。为了符合我们“教育第一”的目标，我们将手动安装 MySQL，并通过命令行进行配置，而不是安装 GUI 控制面板。如果您以前使用过 MySQL，请随意按照您的意愿进行设置。

MySQL 和 Git

### 注意

请记住，我们的 MySQL 设置和我们存储在其中的数据都不是我们 Git 存储库的一部分。任何在数据库级别上的错误，包括错误配置或删除数据，都将更难以撤消。

## 在我们的 VPS 上安装 MySQL

在我们的服务器上安装 MySQL 非常简单。通过 SSH 登录到您的 VPS 并运行以下命令：

```py
sudo apt-get update
sudo apt-get install mysql-server

```

您应该看到一个界面提示您输入 MySQL 的 root 密码。在提示时输入密码并重复输入。安装完成后，您可以通过输入以下内容获得一个实时的 SQL shell：

```py
mysql –p

```

然后，在提示时输入您之前选择的密码。我们可以使用这个 shell 创建数据库和模式，但我们宁愿通过 Python 来做这件事；所以，如果您打开了 MySQL shell，请输入`quit`并按下*Enter*键来终止它。

## 为 MySQL 安装 Python 驱动程序

由于我们想要使用 Python 来访问我们的数据库，我们需要安装另一个软件包。Python 有两个主要的 MySQL 连接器：*PyMySQL*和*MySQLdb*。从简单性和易用性的角度来看，第一个更可取。它是一个纯 Python 库，这意味着它没有依赖性。MySQLdb 是一个 C 扩展，因此有一些依赖性，但理论上它会更快一些。一旦安装，它们的工作方式非常相似。在本章的示例中，我们将使用 PyMySQL。

要安装它，请在您的 VPS 上运行以下命令：

```py
pip install --user pymysql

```

# 在 MySQL 中创建我们的犯罪地图数据库

对 SQL 语法的一些了解将对本章的其余部分有所帮助，但您应该能够跟上。我们需要做的第一件事是为我们的 Web 应用程序创建一个数据库。如果您习惯使用命令行编辑器，您可以直接在 VPS 上创建以下脚本，这样可以更容易调试，而且我们不会在本地运行它们。然而，在 SSH 会话中进行开发远非理想；因此，我建议您在本地编写它们，并使用 Git 在运行之前将它们传输到服务器上。

这可能会使调试有点令人沮丧，因此在编写这些脚本时要特别小心。如果您愿意，您可以直接从本书附带的代码包中获取它们。在这种情况下，您只需要正确填写`dbconfig.py`文件中的用户和密码字段，一切都应该正常工作。

## 创建一个数据库设置脚本

在本章开始时我们初始化 Git 存储库的`crimemap`目录中，创建一个名为`db_setup.py`的 Python 文件，其中包含以下代码：

```py
import pymysql
import dbconfig
connection = pymysql.connect(host='localhost',
                             user=dbconfig.db_user,
                             passwd=dbconfig.db_password)

try:
        with connection.cursor() as cursor:
                sql = "CREATE DATABASE IF NOT EXISTS crimemap"
                cursor.execute(sql)
                sql = """CREATE TABLE IF NOT EXISTS crimemap.crimes (
id int NOT NULL AUTO_INCREMENT,
latitude FLOAT(10,6),
longitude FLOAT(10,6),
date DATETIME,
category VARCHAR(50),
description VARCHAR(1000),
updated_at TIMESTAMP,
PRIMARY KEY (id)
)"""
                cursor.execute(sql);
        connection.commit()
finally:
        connection.close()
```

让我们看看这段代码做了什么。首先，我们导入了刚刚安装的`PyMySQL`库。我们还导入了`dbconfig`，稍后我们将在本地创建并填充数据库凭据（我们不希望将这些凭据存储在我们的存储库中）。然后，我们将使用`localhost`（因为我们的数据库安装在与我们的代码相同的机器上）和尚不存在的凭据创建到我们的数据库的连接。

现在我们已经连接到我们的数据库，我们可以获取一个游标。您可以将游标想象成文字处理器中的闪烁对象，指示当您开始输入时文本将出现的位置。数据库游标是一个指向数据库中我们想要创建、读取、更新或删除数据的位置的对象。一旦我们开始处理数据库操作，就会出现各种异常。我们始终希望关闭与数据库的连接，因此我们将在`try`块中创建一个游标（并执行所有后续操作），并在`finally`块中使用`connection.close()`（`finally`块将在`try`块成功与否时执行）。

游标也是一个资源，所以我们将获取一个并在`with:`块中使用它，这样当我们完成后它将自动关闭。设置完成后，我们可以开始执行 SQL 代码。

当我们调用`cursor.execute()`函数时，我们将传入的 SQL 代码将使用数据库引擎运行，并且如果适当的话，游标将被填充结果。我们将在后面讨论如何使用游标和`execute()`函数读取和写入数据。

### 创建数据库

SQL 读起来与英语类似，因此通常很容易弄清楚现有的 SQL 代码的作用，即使编写新代码可能有点棘手。我们的第一个 SQL 语句将创建一个`crimemap`数据库（如果尚不存在），这意味着如果我们回到这个脚本，我们可以保留这行而不必每次删除整个数据库。我们将把我们的第一个 SQL 语句作为一个字符串创建，并使用`sql`变量来存储它。然后，我们将使用我们创建的游标执行该语句。

### 查看我们的表列

现在我们知道我们有一个数据库，我们可以创建一个表。该表将存储我们记录的所有犯罪的数据，每起犯罪在表的一行中。因此，我们需要几列。我们的`create table`语句中可以看到每列以及将存储在该列中的数据类型。为了解释这些，我们有：

+   **id**：这是一个唯一的数字，对于我们记录的每一起犯罪都会自动记录。我们不需要太担心这个字段，因为 MySQL 会在我们每次添加新的犯罪数据时自动插入它，从 1 开始递增。

+   **纬度和经度**：这些字段将用于存储每起犯罪的位置。在浮点数后面我们将指定`(10, 6)`，这意味着每个浮点数最多可以有 10 位数字，小数点后最多可以有 6 位数字。

+   **日期**：这是犯罪的日期和时间。

+   **类别**：我们将定义几个类别来对不同类型的犯罪进行分类。这将有助于以后过滤犯罪。`VARCHAR(50)`表示这将是可变长度的数据，最长为 50 个字符。

+   **描述**：这类似于`类别`，但最多为 1000 个字符。

+   **Updated_at**：这是另一个我们不需要担心的字段。当我们插入数据或编辑数据时，MySQL 会将其设置为当前时间。例如，如果我们想要删除特定时间错误插入的一堆数据，这可能会很有用。

### 索引和提交

我们`create table`查询的最后一行指定了我们的`id`列为*主键*。这意味着它将被索引（因此，如果我们在查询我们的数据库时使用它，我们将能够非常有效地找到数据），并且将具有各种其他有用的属性，比如强制存在和唯一性。

一旦我们定义了这个更复杂的 SQL 片段，我们将在下一行执行它。然后，我们将提交我们对数据库的更改。把这看作是保存我们的更改；如果我们在没有提交的情况下关闭连接，我们的更改将被丢弃。

**SQL 提交**：

### 提示

忘记提交更改是 SQL 初学者的常见错误。如果您到达一个点，您的数据库表现不如预期，并且您无法弄清楚原因，检查一下您的代码中是否忘记了提交。

## 使用数据库设置脚本

将我们的脚本保存在本地并推送到存储库。请参考以下命令的顺序：

```py
git add db_setup.py
git commit –m "database setup script"
git push origin master

```

通过以下命令 SSH 到您的 VPS，并将新存储库克隆到您的/var/www 目录：

```py
ssh user@123.456.789.123
cd /var/www
git clone <your-git-url>
cd crimemap

```

### 向我们的设置脚本添加凭据

现在，我们仍然没有我们的脚本依赖的凭据。在使用设置脚本之前，我们将做两件事：

+   创建`dbconfig.py`文件，其中包含数据库和密码

+   将此文件添加到`.gitignore`中，以防止它被添加到我们的存储库中

使用以下命令在您的 VPS 上直接创建和编辑`dbconfig.py`文件：

```py
nano dbconfig.py

```

然后，使用您在安装 MySQL 时选择的密码输入以下内容：

```py
db_user = "root"
db_password = "<your-mysql-password>"
```

按下*Ctrl* + *X*保存，并在提示时输入*Y*。

现在，使用类似的`nano`命令来创建、编辑和保存`.gitignore`，其中应包含以下内容：

```py
dbconfig.py
*.pyc

```

第一行防止我们的`dbconfig`文件被添加到 Git 存储库中，这有助于防止未经授权使用我们的数据库密码。第二行防止编译的 Python 文件被添加到存储库中，因为这些只是运行时优化，并且与我们的项目相关。

### 运行我们的数据库设置脚本

完成后，您可以运行：

```py
python db_setup.py

```

假设一切顺利，现在你应该有一个用于存储犯罪的表的数据库。Python 将输出任何 SQL 错误，允许您在必要时进行调试。如果您从服务器对脚本进行更改，请运行与您从本地机器运行的相同的`git add`、`git commit`和`git push`命令。

git 状态：

### 提示

您可以从终端运行`git status`（确保您在存储库目录中）来查看已提交文件的摘要。您现在可以使用这个（在`git push`之前）来确保您没有提交`dbconfig`文件。

这就结束了我们的初步数据库设置！现在，我们可以创建一个使用我们的数据库的基本 Flask 项目。

# 创建一个基本的数据库 Web 应用程序

我们将首先构建我们的犯罪地图应用程序的框架。它将是一个基本的 Flask 应用程序，只有一个页面：

+   显示我们的数据库中`crimes`表中的所有数据

+   允许用户输入数据并将这些数据存储在数据库中

+   有一个**清除**按钮，可以删除之前输入的所有数据

尽管我们将存储和显示的内容现在还不能真正被描述为*犯罪数据*，但我们将把它存储在我们之前创建的`crimes`表中。我们现在只使用`description`字段，忽略所有其他字段。

设置 Flask 应用程序的过程与我们之前所做的非常相似。我们将把数据库逻辑分离到一个单独的文件中，留下我们的主要`crimemap.py`文件用于 Flask 设置和路由。

## 设置我们的目录结构

在您的本地机器上，切换到`crimemap`目录。如果您在服务器上创建了数据库设置脚本或对其进行了任何更改，请确保将更改同步到本地。然后，通过运行以下命令（或者如果您愿意，使用 GUI 文件浏览器）创建`templates`目录并触摸我们将使用的文件：

```py
cd crimemap
git pull origin master
mkdir templates
touch templates/home.html
touch crimemap.py
touch dbhelper.py

```

## 查看我们的应用程序代码

将以下代码添加到`crimemap.py`文件中。这里没有什么意外的内容，应该都是我们在 Headlines 项目中熟悉的。唯一需要指出的是`DBHelper()`类，我们将在下一步考虑它的代码。我们将在初始化应用程序后简单地创建一个全局的`DBHelper`实例，然后在相关方法中使用它来从数据库中获取数据，将数据插入数据库，或者从数据库中删除所有数据：

```py
from dbhelper import DBHelper
from flask import Flask
from flask import render_template
from flask import request

app = Flask(__name__)
DB = DBHelper()

@app.route("/")
def home():
    try:
        data = DB.get_all_inputs()
    except Exception as e:
        print e
        data = None
    return render_template("home.html", data=data)

@app.route("/add", methods=["POST"])
def add():
  try:
    data = request.form.get("userinput")
    DB.add_input(data)
  except Exception as e:
    print e
  return home()

@app.route("/clear")
def clear():
  try:
    DB.clear_all()
  except Exception as e:
    print e
  return home()

if __name__ == '__main__':
  app.run(port=5000, debug=True)
```

## 查看我们的 SQL 代码

从我们的数据库辅助代码中还有一些 SQL 需要学习。将以下代码添加到`dbhelper.py`文件中：

```py
import pymysql
import dbconfig

class DBHelper:

  def connect(self, database="crimemap"):
    return pymysql.connect(host='localhost',
              user=dbconfig.db_user,
              passwd=dbconfig.db_password,
              db=database)

  def get_all_inputs(self):
  connection = self.connect()
    try:
      query = "SELECT description FROM crimes;"
      with connection.cursor() as cursor:
        cursor.execute(query)
      return cursor.fetchall()
    finally:
      connection.close()

  def add_input(self, data):
    connection = self.connect()
    try:
      # The following introduces a deliberate security flaw. See section on SQL injection below
      query = "INSERT INTO crimes (description) VALUES ('{}');".format(data)
      with connection.cursor() as cursor:
        cursor.execute(query)
        connection.commit()
    finally:
      connection.close()

  def clear_all(self):
    connection = self.connect()
    try:
      query = "DELETE FROM crimes;"
      with connection.cursor() as cursor:
        cursor.execute(query)
        connection.commit()
    finally:
      connection.close()
```

就像在我们的设置脚本中一样，我们需要与数据库建立连接，然后从连接中获取一个游标以执行有意义的操作。同样，我们将在`try:` `finally:`块中执行所有操作，以确保连接被关闭。

在我们的辅助程序中，我们将考虑四个主要数据库操作中的三个。**CRUD**（**创建，读取，更新**和**删除**）描述了基本的数据库操作。我们要么创建和插入新数据，读取现有数据，修改现有数据，或者删除现有数据。在我们的基本应用程序中，我们不需要更新数据，但创建，读取和删除肯定是有用的。

### 读取数据

让我们从阅读开始，假设我们的数据库中已经有一些数据了。在 SQL 中，这是使用`SELECT`语句来完成的；我们将根据一组条件选择要检索的数据。在我们的情况下，`get_all_inputs`函数中的查询是`SELECT description FROM crimes;`。稍后我们会看一下如何完善`SELECT`查询，但这个查询只是获取我们`crimes`表中每一行的`description`字段。这类似于我们在本章开头讨论的例子，那时我们想要发送一封新闻简报，需要每个客户的电子邮件地址。在这里，我们想要每个犯罪的描述。

一旦游标执行了查询，它将指向一个包含结果的数据结构的开头。我们将在游标上执行`fetchall()`，将我们的结果集转换为列表，以便我们可以将它们传回我们的应用程序代码。（如果你在 Python 中使用了生成器，可能会觉得数据库游标就像一个生成器。它知道如何遍历数据，但它本身并不包含所有数据）。

### 插入数据

接下来是我们的`add_input()`函数。这个函数会获取用户输入的数据，并将其插入数据库中。在 SQL 中，使用`INSERT`关键字来创建数据。我们的查询（假设`foobar`是我们传入的数据）是`INSERT into crimes (description) VALUES ('foobar')`。

这可能看起来比实际做的事情要复杂，但请记住，我们仍然只处理一个字段（描述）。我们稍后会讨论`INSERT`是如何设计来接受多个但是任意列的，这些列可以在第一组括号中命名，然后为每个列提供匹配的值，在`VALUES`之后的第二组括号中给出。

由于我们对数据库进行了更改，我们需要*提交*我们的连接以使这些更改永久化。

### 删除数据

最后，我们将看一下 SQL 中`DELETE`语句有多简洁。`DELETE FROM crimes`会清除我们`crimes`数据库中的所有数据。稍后我们会考虑如何通过指定条件来删除部分数据，使这个关键字的行为不那么像核武器。

同样，这会对我们的数据库进行更改，所以我们需要提交这些更改。

如果所有新的 SQL 命令似乎太多了，那就去在线沙盒或者我们之前讨论过如何访问的实时 SQL shell 中玩一下。你会发现，SQL 在一段时间后会变得非常自然，因为它的大部分关键词都来自自然语言，而且它使用的符号非常少。

最后，让我们来看一下我们的 HTML 模板。

## 创建我们的视图代码

Python 和 SQL 编写起来很有趣，它们确实是我们应用程序的主要部分。但是，目前我们有一个没有门或窗户的房子；困难和令人印象深刻的部分已经完成，但它是不可用的。让我们添加一些 HTML 代码，以便世界可以与我们编写的代码进行交互。

在`templates/home.html`中，添加以下内容：

```py
<html>
<body>
  <head>
    <title>Crime Map</title>
  </head>

  <h1>Crime Map</h1>
  <form action="/add" method="POST">
    <input type="text" name="userinput">
    <input type="submit" value="Submit">
    </form>
  <a href="/clear">clear</a>
  {% for userinput in data %}
    <p>{{userinput}}</p>
    {% endfor %}
</body>
</html>
```

这里没有我们以前没有见过的东西。在这里，我们有一个带有单个文本输入的表单，通过调用我们应用程序的`/add`函数向我们的数据库添加数据，并且直接在其下面，我们循环遍历所有现有数据，并在`<p>`标签中显示每个片段。

## 在我们的 VPS 上运行代码

最后，我们需要使我们的代码对世界可访问。这意味着将其推送到我们的`git`存储库，将其拉到 VPS 上，并配置 Apache 进行服务。在本地运行以下命令：

```py
git add .
git commit –m "Skeleton CrimeMap"
git push origin master
ssh <username>@<vps-ip-address>

```

现在，在您的 VPS 上运行以下命令：

```py
cd /var/www/crimemap
git pull origin master

```

现在，我们需要一个`.wsgi`文件将 Python 链接到 Apache，可以通过运行以下命令创建：

```py
nano crimemap.wsgi

```

`.wsgi`文件应包含以下内容：

```py
import sys
sys.path.insert(0, "/var/www/crimemap")
from crimemap import app as application
```

现在，按下*Ctrl* + *X*，然后在提示保存时输入*Y*。

我们还需要创建一个新的 Apache`.conf`文件，并将其设置为默认文件（而不是`headlines`，即我们当前默认的`.conf`文件）。运行以下命令创建文件：

```py
cd /etc/apache2/sites-available
nano crimemap.conf

```

接下来，添加以下代码：

```py
<VirtualHost *>
    ServerName example.com

 WSGIScriptAlias / /var/www/crimemap/crimemap.wsgi
 WSGIDaemonProcess crimemap
 <Directory /var/www/crimemap>
 WSGIProcessGroup crimemap
       WSGIApplicationGroup %{GLOBAL}
        Order deny,allow
        Allow from all
    </Directory>
</VirtualHost>
```

这与我们为以前的项目创建的`headlines.conf`文件非常相似，您可能会发现最好只需复制以前的文件并根据需要进行替换。

最后，我们需要停用旧站点并激活新站点，如下所示：

```py
sudo a2dissite headlines.conf
sudo a2ensite crimemap.conf
sudo service apache2 reload

```

现在，一切应该都正常工作。如果您手动复制了代码，几乎可以肯定会有一两个 bug 需要处理。不要因此而感到沮丧；记住调试预计将成为开发的一个重要部分！如有必要，运行`tail –f /var/log/apache2/error.log`，同时加载站点以注意任何错误。如果失败，请在`crimemap.py`和`dbhelper.py`中添加一些打印语句，以缩小故障位置。

一切都正常工作后，您应该能够看到一个带有单个文本输入的网页。当您通过输入提交文本时，您应该能够在页面上看到文本显示，就像以下示例一样：

![在我们的 VPS 上运行代码](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_06_01.jpg)

请注意，我们从数据库获取的数据是一个元组，因此它被括号括起来，并且有一个尾随逗号。这是因为我们只从我们的`crimes`表中选择了一个字段，`'description'`，而在理论上，我们可能会处理每个犯罪的许多列（很快我们将这样做）。

## 减轻 SQL 注入

我们的应用程序存在一个致命缺陷。我们从用户那里获取输入，并使用 Python 字符串格式化将其插入到我们的 SQL 语句中。当用户输入正常的字母数字字符串时，这样做效果很好，但是如果用户是恶意的，他们实际上可以注入自己的 SQL 代码并控制我们的数据库。尽管 SQL 注入是一种古老的攻击方式，大多数现代技术都会自动减轻其影响，但每年仍然有数十起针对主要公司的攻击，其中由于 SQL 注入漏洞而泄漏了密码或财务数据。我们将花一点时间讨论什么是 SQL 注入以及如何防止它。

### 向我们的数据库应用程序注入 SQL

转到我们的 Web 应用程序，点击**清除**链接以删除任何保存的输入。现在，在输入框中输入`Bobby`，然后点击**提交**按钮。页面现在应该类似于以下图片：

![向我们的数据库应用程序注入 SQL](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_06_02.jpg)

在此输入中，现在键入：

`'); DELETE FROM crimes; --`

所有字符在这里都很重要。

输入需要以单引号开头，后跟一个闭括号，然后是一个分号，然后是删除语句，另一个分号，一个空格，最后是两个破折号。当页面刷新时，您可能期望看到第二行，列出这个看起来奇怪的字符串，位于**Bobby**输出下面，但实际上，您将看到一个空白页面，看起来类似于下面的屏幕截图：

![向我们的数据库应用程序注入 SQL](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_06_03.jpg)

这很奇怪，对吧？让我们看看发生了什么。在我们的`DBHelper`类中，我们的插入语句有以下行：

```py
query = "INSERT INTO crimes (description) VALUES ('{}');".format(data)
```

这意味着用户的输入会在我们运行代码之前添加到 SQL 代码中。当我们将之前使用的看起来奇怪的输入放入 SQL 语句的占位符中时，我们将得到以下字符串：

```py
"INSERT INTO crimes (description) VALUES (''); DELETE FROM crimes; -- ');"
```

这是两个 SQL 语句而不是一个。我们用一个空值关闭了`INSERT`语句，然后用`DELETE`语句删除了`crimes`表中的所有内容。末尾的两个破折号形成了一个 SQL 注释，这样额外的闭引号和括号就不会引起任何语法错误。当我们输入我们的数据时，我们向数据库插入了一个空行，然后删除了`crimes`表中的所有数据！

当然，一个有创造力的攻击者可以在我们选择的`DELETE`语句的位置运行任何 SQL 语句。他们可以删除整个表（参考[`xkcd.com/327/`](https://xkcd.com/327/)中的一个幽默的例子），或者他们可以运行一个选择语句来绕过数据库登录功能。或者，如果您存储信用卡信息，类似的攻击可以用来获取数据并将其显示给攻击者。总的来说，我们不希望我们的 Web 应用程序的用户能够在我们的数据库上运行任意代码！

### 防止 SQL 注入

防范 SQL 注入涉及对用户输入进行消毒，并确保如果用户输入可能被解释为 SQL 语法的特殊字符，则忽略这些字符。有不同的方法可以做到这一点，我们将使用我们的 Python SQL 库自动提供的一个简单方法。有关此主题的更全面信息，请参阅[`www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet`](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)。

在`dbhelper.py`文件中，将`add_input()`方法更改为以下内容：

```py
def add_input(self, data):
    connection = self.connect()
  try:
      query = "INSERT INTO crimes (description) VALUES (%s);"
      with connection.cursor() as cursor:
          cursor.execute(query, data)
          connection.commit()
      finally:
          connection.close()
```

我们在这里使用的`%s`标记是一个字符串占位符，类似于`%d`，它在普通 Python 字符串中用作占位符，也是大括号的旧替代方法。但是，我们不会使用 Python 的`str.format()`函数，而是将要插入到占位符中的字符串和值传递给 PyMySQL 的`cursor.execute()`函数。这将自动转义所有对 SQL 有意义的字符，这样我们就不必担心它们被执行。

现在，如果您再次尝试输入，您将看到它们按预期显示-包括特殊字符-如下面的屏幕截图所示：

![防范 SQL 注入](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_06_04.jpg)

在本书的最后一章中，我们将简要讨论可以提供更强大防范 SQL 注入攻击的 ORM 技术。虽然似乎我们通过转义一些特殊字符解决了一个简单的问题，但实际上可能会变得相当微妙。诸如**sqlmap**（[`sqlmap.org/`](http://sqlmap.org/)）之类的工具可以尝试对相同的想法（即输入特殊字符针对数据库）进行数百种不同的变体，直到找到意外的结果并发现漏洞。请记住，为了使您的应用程序安全，它必须受到对每种可能的漏洞的保护；而要使其不安全，它只需要对一个漏洞进行攻击。

# 摘要

这就是我们犯罪地图项目介绍的全部内容。我们讨论了如何在我们的 VPS 上安装 MySQL 数据库以及如何将其连接到 Flask。我们看了看如何创建、读取、更新和删除数据，并创建了一个基本的数据库 Web 应用程序，可以接受用户输入并再次显示出来。最后，我们看了看 SQL 注入漏洞以及如何保护自己免受其影响。

接下来，我们将添加一个谷歌地图小部件和一些更好的美学设计。
