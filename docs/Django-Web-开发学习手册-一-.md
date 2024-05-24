# Django Web 开发学习手册（一）

> 原文：[`zh.annas-archive.org/md5/C7E16835D8AC71A567CF7E772213E9F7`](https://zh.annas-archive.org/md5/C7E16835D8AC71A567CF7E772213E9F7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Django 是用 Python 编写的，是一个旨在快速构建复杂 Web 应用程序的 Web 应用程序框架，无需任何麻烦。它松散地遵循 MVC 模式，并遵循不重复原则，使数据库驱动的应用程序高效且高度可扩展，并且是迄今为止最受欢迎和成熟的 Python Web 框架。

这本书是一本手册，将帮助您构建一个简单而有效的 Django Web 应用程序。它首先向您介绍 Django，并教您如何设置它并编写简单的程序。然后，您将学习构建您的第一个类似 Twitter 的应用程序。随后，您将介绍标签、Ajax（以增强用户界面）和推文。然后，您将继续创建管理界面，学习数据库连接，并使用第三方库。然后，您将学习调试和部署 Django 项目，并且还将一窥 Django 与 AngularJS 和 Elasticsearch。通过本书的最后，您将能够利用 Django 框架轻松开发出一个功能齐全的 Web 应用程序。

# 本书内容

第一章《Django 简介》向您介绍了 MVC Web 开发框架的历史，并解释了为什么 Python 和 Django 是实现本书目标的最佳工具。

第二章《入门》向您展示如何在 Unix/Linux、Windows 和 Mac OS X 上设置开发环境。我们还将看到如何创建我们的第一个项目并将其连接到数据库。

第三章《Django 中的代码风格》涵盖了构建网站所需的所有基本主题，例如更好的 Django Web 开发的编码实践，应该使用哪种 IDE 和版本控制。

第四章《构建类似 Twitter 的应用程序》带您了解主要的 Django 组件，并为您的 Twitter 应用程序开发一个工作原型。

第五章《引入标签》教您设计算法来构建标签模型以及在帖子中使用标签的机制。

第六章《使用 AJAX 增强用户界面》将帮助您使用 Django 的 Ajax 增强 UI 体验。

第七章《关注和评论》向您展示如何创建登录、注销和注册页面模板。它还将向您展示如何允许另一个用户关注您以及如何显示最受关注的用户。

第八章《创建管理界面》向您展示了使用 Django 的内置功能的管理员界面的功能，以及如何以自定义方式显示带有侧边栏或启用分页的推文。

第九章《扩展和部署》通过利用 Django 框架的各种功能，为您的应用程序准备部署到生产环境。它还向您展示如何添加对多种语言的支持，通过缓存提高性能，自动化测试，并配置项目以适用于生产环境。

第十章《扩展 Django》讨论了如何改进应用程序的各个方面，主要是性能和本地化。它还教您如何在生产服务器上部署项目。

第十一章《数据库连接》涵盖了各种数据库连接形式，如 MySQL，NoSQL，PostgreSQL 等，这是任何基于数据库的应用程序所需的。

第十二章《使用第三方包》讨论了开源以及如何在项目中使用和实现开源第三方包。

第十三章《调试的艺术》向您展示如何记录和调试代码，以实现更好和更高效的编码实践。

第十四章《部署 Django 项目》向您展示如何将 Django 项目从开发环境移动到生产环境，以及在上线之前需要注意的事项。

第十五章《接下来做什么？》将带您进入下一个级别，介绍 Django 项目中使用的两个最重要和首选组件 AngularJS 和 Elasticsearch。

# 您需要为本书做好准备

对于本书，您需要在 PC/笔记本电脑上运行最新（最好是）Ubuntu/Windows/Mac 操作系统，并安装 Python 2.7.X 版本。

除此之外，您需要 Django 1.7.x 和您喜欢的任何一个文本编辑器，如 Sublime Text 编辑器，Notepad++，Vim，Eclipse 等。

# 这本书适合谁

这本书适合想要开始使用 Django 进行 Web 开发的 Web 开发人员。需要基本的 Python 编程知识，但不需要了解 Django。

# 约定

在本书中，您会发现许多文本样式，用于区分不同类型的信息。以下是一些这些样式的示例及其含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“`username`变量是我们想要查看的推文的所有者。”

代码块设置如下：

```py
#!/usr/bin/env python
import os
import sys
if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_mytweets.settings")
    from django.core.management import execute_from_command_line
    execute_from_command_line(sys.argv)
```

任何命令行输入或输出都写成如下形式：

```py
Python 2.7.6 (default, Mar 22 2014, 22:59:56) 
[GCC 4.8.2] on linux2 
Type "help", "copyright", "credits" or "license" for more information.

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中以这种方式出现：“在那个链接中，我们会找到下载按钮，点击下载后，点击**下载 Bootstrap**。”

### 注意

警告或重要说明出现在这样的框中。

### 提示

提示和技巧看起来像这样。


# 第一章：Django 简介

欢迎来到 Django 开发 2.0 版本！

Django 是一个网页开发框架，网页开发是一种技能。要掌握任何技能，可以遵循著名的"1 万小时"规则，即如果你练习任何东西达到那么长时间，你肯定会成为专家。但那是很长的时间，没有合适的计划，这可能会出错。非常出错。

那么，有没有更好的方法来实现你的目标？有！将你想学习的技能分解成更小的子技能，然后逐个掌握它们。 （程序员称之为"分而治之"规则。）你需要通过研究来确定最重要的子技能。子技能被频繁提及的次数越多，掌握它就越重要。

作为本书的作者，我请求您做出承诺，即在最初令人沮丧的时刻坚持学习本书。学习新技能时会感到沮丧，相信我：当你觉得太简单时，你是在做对的。

在本章中，我们将涵盖以下主题：

+   首先为什么要进行网页开发？

+   网页开发中的变化

+   网页开发中的 MVC 模式

+   为什么选择 Django

+   Django 内部

# 首先为什么要进行网页开发？

网站直接在全球观众面前给公司或产品留下第一印象。现在每个初创公司都有一个网站，这有助于向潜在客户或投资者推销他们的想法。

现在一切都在线，所以与其坐视变化，为什么不参与并学习编码呢？学习网页开发是你可以用时间做出的最有价值的投资之一。它不仅会通过让你找到更好的工作来使你受益，而且你还可以以非常简单和直接的方式将你的想法编码成原型。

网页开发必备的要素包括用户界面和用户体验，但遗憾的是这超出了本书的范围。

# 网页开发中的变化

网页开发在过去几年取得了巨大进步。一些改进列举如下：

+   **JavaScript**：从编写复杂的选择器到操作**文档对象模型**（**DOM**）。像**jQuery**和**AngularJs**这样的库使前端动态变得更简单。JavaScript 甚至发展出了构建生产就绪的服务器端框架**node.js**。

+   **浏览器**：从在各种浏览器上简单地打破页面发展到智能地恢复连接，告诉你哪个标签正在播放音乐，或者无缝地渲染实时游戏。

+   **开源**：使用他人编写的代码现在比编写自己的代码更可取。这帮助许多项目停止重复造轮子，**Django**就是最好的例子之一。

+   **API 作为脊柱**：今天的网络技术可能明天就不一样，或者数据可能不会以相同的方式或在相同的位置表示。换句话说，更多的设备将带有不同的屏幕尺寸。因此，最好将文本与视觉分开。

+   **用户界面**：过去，开发团队的宝贵时间被用户界面设计消耗。但是像**Bootstrap**和**Foundation**这样的框架使网页开发变得更加容易。

+   **敏捷开发**：在开发周期中快速前进对大多数初创公司是可以接受的。在软件开发周期开始时从未要求完整的需求。因此，持续的客户或利益相关者参与非常重要。Django 框架是这种开发的最合适的框架。正如 Django 的口号所说，"*完美主义者的网络框架，有截止日期*"

+   云计算的演变：这在 Web 应用程序的托管端发挥了重要作用，并为上线提供了更快、更可靠和更便宜的解决方案。

+   NoSQL 的诞生：大大降低成本，NoSQL 为开发人员提供了诸如“立即存储，稍后查找价值”和“一起存储任何东西”的自由，使其更适合云环境并具有更强的容错性。

# Web 开发中的 MVC 模式

在本书中，您将了解如何使用一个名为 Django 的 Model-View-Controller（MVC）Web 框架，它是用强大而流行的编程语言 Python 编写的。

MVC 基于分离表示的概念。分离表示的理念是在领域对象（模拟我们对真实世界的看法）和表示对象（我们在屏幕上看到的用户界面（UI）元素）之间进行清晰的划分。领域对象应完全独立，并且应该能够支持多个演示，可能同时进行。

这种模式的好处是显而易见的。有了它，设计师可以在不担心数据存储或管理的情况下工作在界面上。开发人员能够编写数据处理的逻辑，而不必深入了解演示细节。因此，MVC 模式迅速进入了 Web 语言，并且严肃的 Web 开发人员开始接受它而不是以前的技术。

本书强调利用 Django 和 Python 创建一个具有今天 Web 2.0 网站常见功能的微型博客 Web 应用程序。本书采用教程风格介绍概念并解释问题的解决方案。它不是 Python 或 Django 的参考手册，因为两者已经有很多资源。本书只假设对标准 Web 技术（HTML 和 CSS）和 Python 编程语言有工作知识。另一方面，Django 将在我们在各章节中构建功能时进行解释，直到我们实现拥有一个可工作的 Web 2.0 应用程序的目标。

## 多语言支持

Django 通过其内置的国际化系统支持多语言网站。对于那些在拥有多种语言的网站上工作的人来说，这可能非常有价值。该系统使翻译界面变得非常简单。

因此，总之，Django 提供了一组集成和成熟的组件，具有出色的文档，网址为[`www.djangoproject.com/documentation/`](http://www.djangoproject.com/documentation/)。

由于其庞大的开发人员和用户社区，现在学习 Web 开发框架的时机是最好的！

# 为什么选择 Django？

自 MVC 模式传播到 Web 开发以来，与大多数其他语言不同，Python 在 Web 框架方面有了相当多的选择。尽管一开始从众多选择中选择一个可能会令人困惑，但有几个竞争框架只能对 Python 社区有利。

Django 是 Python 的一个可用框架，所以问题是：它有什么特别之处，以至于成为本书的主题？

首先，Django 提供了一组紧密集成的组件。所有这些组件都是由 Django 团队自己开发的。Django 最初是作为一个内部框架开发的，用于管理一系列面向新闻的网站。后来，它的代码在互联网上发布，Django 团队继续使用开源模型进行开发。由于其根源，Django 的组件从一开始就被设计用于集成、可重用性和速度。

Django 的数据库组件，对象关系映射器（ORM），提供了数据模型和数据库引擎之间的桥梁。它支持大量的数据库系统，从一个引擎切换到另一个引擎只是改变一个配置文件的事情。如果决定从一个数据库引擎切换到另一个数据库引擎，这给开发人员带来了很大的灵活性。如果遇到问题，可以在这里找到驱动程序（二进制 Python 包）：[`www.lfd.uci.edu/~gohlke/pythonlibs/`](http://www.lfd.uci.edu/~gohlke/pythonlibs/)。

此外，Django 提供了一个整洁的开发环境。它带有一个轻量级的 Web 服务器用于开发和测试。当启用调试模式时，Django 提供非常彻底和详细的错误消息，包含大量的调试信息。所有这些都使得隔离和修复错误变得非常容易。

Django 通过其内置的国际化系统支持多语言网站。对于那些在拥有多种语言的网站上工作的人来说，这可能非常有价值。该系统使得翻译界面变得非常简单。

Django 具备一个 Web 框架所期望的标准功能。这些功能包括以下内容：

+   一个具有简单但可扩展语法的模板和文本过滤引擎

+   表单生成和验证 API

+   可扩展的身份验证系统

+   用于加速应用程序性能的缓存系统

+   一个用于生成 RSS 订阅的饲料框架

尽管 Django 没有提供简化使用 Ajax 的 JavaScript 库，但选择一个库并将其与 Django 集成是一件简单的事情，我们将在后面的章节中看到。

因此，总之，Django 提供了一套集成和成熟的组件，并拥有出色的文档，这要归功于其庞大的开发人员和用户社区。有了 Django，现在是学习 Web 开发框架的最佳时机！

## Django 内部

我们将提到一些使用 Django 进行更好的 Web 开发的重要原因。以下小节解释了一些最重要的功能。

### Django 是成熟的

许多公司直接在生产中使用 Django，并得到了来自世界各地开发人员的持续贡献。一些著名的网站包括**Pinterest**和**Quora**。它已经成为完美的 Web 开发框架。

### 电池包含

Django 遵循 Python 的**电池包含**哲学，这意味着 Django 带有许多在 Web 开发过程中解决常见问题的重要额外功能和选项。

### 组件和模块化框架之间紧密集成

Django 在与第三方模块集成方面非常灵活。存在一个流行的项目（例如数据库领域的**mongoDB**或**OpenID**主要的**SocialAuth**），它没有一个用于 Django 集成的**应用程序编程接口**（**API**）或完整的插件的可能性非常小。

### 对象关系映射器

这是 Django 项目中最重要的部分之一。Django 的数据库组件，ORM，为 Django 的**模态类**提供了封装、可移植性、安全性和表现力等功能，这些功能映射到配置的选择数据库。

### 清晰的 URL 设计

Django 中的 URL 系统非常灵活和强大。它允许您为应用程序中的 URL 定义模式，并定义 Python 函数来处理每个模式。

这使开发人员能够创建既人性化（避免 URL 以`.php`、`.aspx`等结尾的模式）又搜索引擎友好的 URL。

### 自动管理界面

Django 带有一个准备好使用的管理界面。这个界面使得管理应用程序数据变得轻而易举。它也非常灵活和可定制。

### 高级开发环境

此外，Django 提供了一个整洁的开发环境。它配备了一个轻量级的 Web 服务器用于开发和测试。当启用调试模式时，Django 提供非常彻底和详细的错误消息，带有大量的调试信息。所有这些都使得隔离和修复错误变得非常容易。

### Django 1.6 和 1.7 中的新功能

在最新版本 1.6 中，Django 带来了一些重大变化，其中一些如下：

+   Python 3 在此版本中得到了官方支持，这意味着它是稳定的，可以用于生产。

+   布局简单。添加了新的默认值，默认情况下添加了 Django 管理模板，并删除了 Sites 包。

+   添加了点击劫持防护。

+   默认数据库是 SQLite3。

+   随着旧的 API 被弃用，最大的变化是事务得到了改进。DB 层的自动提交默认已启用。

+   此版本中的 DB 连接是持久的。在 Django 1.5 之前，每个 HTTP 请求都会建立一个新连接，但从 1.6 开始，相同的连接将在请求之间重复使用。

+   时区默认为 UTC。

+   简单的应用集成。

+   可扩展的。

+   强大的配置机制。

+   如果没有模型，就不需要`models.py`文件。

+   为其子类添加了一个新方法。

+   允许将游标用作上下文管理器。

+   为国际化、表单和文件上传添加了许多功能。

+   它具有更好的功能来避免 CSRF。

+   除此之外，还引入了一个二进制字段，以及 HTML 5 输入字段（电子邮件、URL 和数字）。

您可以在此处详细阅读新添加的功能：[`docs.djangoproject.com/en/1.7/releases/1.7/`](https://docs.djangoproject.com/en/1.7/releases/1.7/)。

# 支持的数据库

Django 对数据有着很好和强大的尊重。正确地对数据进行建模，站点的其余部分就会顺理成章。尽管 Django 是为关系数据库设计的，但非官方的 NoSQL 实现也存在于 Django 中。以下是 Django 支持的关系数据库列表：

+   SQL：SQLite，MySQL 和 PostgreSQL。

+   SQLite：这是 Django 应用程序的默认数据库，主要用于测试目的。

+   PostgreSQL：这是一个广泛使用的开源关系型数据库。我们将基于此构建我们的微博示例。

### 注意

MySQL 和 PostgreSQL 是 Django 社区中最常用的两种数据库，而 PostgreSQL 是 Django 社区中最受欢迎的。

+   NoSQL：你的数据是否只需要一个表，无论是用户信息还是他们的评论等等？换句话说，是否可以没有插入数据的结构规则或嵌套数据，比如带有评论子文档数组的文章？听起来奇怪吗？是的，它是。在早期，人们使用的是唯一的关系数据库概念，但自从云计算时代开始，程序员们喜欢为每个可能的项目实现 NoSQL 架构。它不存储也不遵循任何正常形式。你不能使用连接，但使用它有许多其他优点。

App Engine、MongoDB、Elasticsearch、Cassandra 和 Redis 是 Django 支持的一些著名的 NoSQL 数据库。MongoDB 在 Django 社区中变得越来越受欢迎。

+   MongoDB：这是一个广泛使用的开源 NoSQL 文档型数据库。我们将用它来创建我们的第二个小型应用程序，用于 URL 缩短。

在本书中，我们将主要处理前述列表中的三个数据库，但其他数据库的实现几乎可以通过最小的配置更改来实现。

有许多由 Django 提供支持的知名网站。其中一些如下：

+   Pinterest：一个内容分享服务，特别是图片和视频

+   Disqus：一个博客评论托管服务

+   Quora：一个基于问题和答案的网站

+   Bitbucket：一个免费的 Git 和 mercurial 代码托管站点

+   **Mozilla Firefox**：**Mozilla**支持页面

# 使用本书您将学到的内容

本书侧重于构建微博网站应用程序，并向其添加常见的 Web 2.0 功能。其中一些功能如下：

+   创建 Django 视图、模型和控制器：这主要涉及学习 Django 框架，即如何在控制器上处理请求，在对存储在数据库中的模型进行必要的操作后呈现视图。

+   **标签和标签云**：在微博网站项目中，每条消息都将有一个带有**#**的标签。这些标签的映射将在本节中处理。

+   **内容定制和搜索**：根据关键词或标签搜索消息。

+   **Ajax 增强**：在搜索或标记期间使用 Ajax 进行自动完成，并对保存的消息或标记进行就地编辑。

+   **朋友网络**：列出个人资料的所有朋友并计算其他重要统计数据。

本书不是专注于教授各种 Django 功能，而是使用教程风格来教授如何使用 Django 实现这些功能。因此，它作为官方 Django 文档的补充资源，该文档可以在网上免费获取。

感兴趣吗？太棒了！准备好了吗？我保证这将既有趣又有意思。

# 总结

在本章中，我们了解了为什么网页开发正在获得优势以及 Web 技术领域发生了什么变化；如何利用 Python 和 Django 框架来利用新的 Web 技术；Django 实际上是什么以及我们可以用它实现什么；最后，支持 Django 的不同类型的数据库。

在下一章中，我们将介绍如何在各种操作系统上（如 Windows、Linux 和 Mac）安装 Python 和 Django，并使用 Django 平台设置我们的第一个项目。


# 第二章：入门

Python 和 Django 适用于多个平台。在本章中，我们将看到如何在 UNIX/Linux、Windows 和 Mac OS X 上设置我们的开发环境。我们还将看到如何创建我们的第一个项目并将其连接到数据库。

在本章中，我们将涵盖以下主题：

+   安装 Python

+   安装 Django

+   安装数据库系统

+   创建您的第一个项目

+   设置数据库

+   启动开发服务器

# 安装所需的软件

我们的开发环境包括 Python、Django 和数据库系统。在接下来的章节中，我们将看到如何安装这些软件包。

## 安装 Python

Django 是用 Python 编写的，因此在设置我们的开发环境的第一步自然是安装 Python。Python 适用于各种操作系统，安装 Python 与安装其他软件包没有什么不同。但是，具体的步骤取决于您的操作系统。

安装时，您需要确保获得 Python 的最新版本。Django 需要 Python 2.7 或更高版本。Python 的最新版本是 3.x 的 3.4.2 和 2.x 版本的 2.7.9。

请阅读与您的操作系统相关的部分以获取安装说明。

### 在 Windows 上安装 Python

Python 有一个标准的 Windows 用户安装程序。只需前往[`www.python.org/download/`](https://www.python.org/download/)并下载最新版本。接下来，双击`.exe`或`.msi`文件，按照安装说明逐步进行安装。图形安装程序将指导您完成安装过程，并在“开始”菜单中创建 Python 可执行文件的快捷方式。

安装完成后，我们需要将 Python 目录添加到系统路径中，以便在使用命令提示符时可以访问 Python。要做到这一点，请按照以下步骤操作：

1.  打开控制面板。

1.  双击**系统和安全**图标或文本，然后查找**系统**（如在 Windows 7 中所示），如下截图所示：![在 Windows 上安装 Python](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00266.jpeg)

1.  单击**高级系统设置**，将弹出一个窗口。

1.  单击**环境变量**按钮，将打开一个新的对话框。

1.  选择**Path**系统变量并编辑它。

1.  将 Python 安装路径追加为其值（默认路径通常为`c:\PythonXX`，其中`XX`是您的 Python 版本），如下截图所示：![在 Windows 上安装 Python](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00267.jpeg)

如果要测试安装，请打开**运行**对话框，输入`python`，然后按*Enter*按钮。Python 交互式 shell 应该会打开。

### 注意

不要忘记使用分号(`;`)将新路径与之前的路径分隔开。

### 在 Unix/Linux 上安装 Python

如果您使用 Linux 或其他 Unix 版本，您可能已经安装了 Python。要检查，请打开终端，输入`python`，然后按*Enter*按钮。如果您看到 Python 交互式 shell，则已安装 Python。在终端中输入`python`后，您应该会得到以下输出：

```py
Python 2.7.6 (default, Mar 22 2014, 22:59:56) 
[GCC 4.8.2] on linux2 
Type "help", "copyright", "credits" or "license" for more information.

```

![在 Unix/Linux 上安装 Python](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00268.jpeg)

输出的第一行指示您系统上安装的版本（此处为 2.7.6）。

如果您看到错误消息而不是前面的输出，或者安装了旧版本的 Python，请继续阅读。

建议 Unix/Linux 用户通过系统的软件包管理器安装和更新 Python。尽管实际细节因系统而异，但与安装其他软件包没有什么不同。

对于基于 APT 的 Linux 发行版，如**Debian**和**Ubuntu**，打开终端并输入以下内容：

```py
$ sudo apt-get update
$ sudo apt-get install python

```

如果您有**Synaptic Package Manager**，只需搜索 Python，标记其安装包，并单击**应用**按钮。

其他 Linux 发行版的用户应查阅其系统文档，了解如何使用软件包管理器安装软件包。

### 在 Mac OS X 上安装 Python

Mac OS X 预装了 Python。但是，由于苹果的发布周期，通常是一个旧版本。如果您启动 Python 交互式 shell 并发现版本旧于 2.3，请访问[`www.python.org/download/mac/`](http://www.python.org/download/mac/)并下载适用于您的 Mac OS X 版本的新安装程序。

现在 Python 已经准备就绪，我们几乎可以开始了。接下来，我们将安装**virtualenv**。

## 安装 virtualenv

使用 virtualenv 可以创建一个隔离的 Python 环境。在开始阶段并不是很需要，但对于依赖管理来说是一个救命稻草（例如，如果您的一个 Web 应用程序需要库的一个版本，而另一个应用程序由于一些遗留或兼容性问题需要同一库的另一个版本，或者如果对一个库或应用程序所做的更改破坏了其他应用程序）。

Virtualenv 可以用来避免这种问题。它将创建自己的环境，这样就不会影响全局设置。它通常会创建自己的目录和共享库，以使 virtualenv 在没有任何外部干扰的情况下工作。如果你有**pip 1.3**或更高版本，请在全局安装。您可以使用以下命令安装 virtualenv：

```py
$ [sudo] pip install virtualenv

```

![安装 virtualenv](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00269.jpeg)

一旦完全下载，virtualenv 将如下所示：

![安装 virtualenv](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00270.jpeg)

### 注意

如果您尚未安装 pip，可以使用`sudo apt-get install python-pip`进行安装。

就这些了！现在您可以使用以下命令创建您的虚拟环境：

```py
$ virtualenv ENV

```

![安装 virtualenv](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00271.jpeg)

Virtualenv 有非常详细的在线文档，您在使用 virtualenv 时遇到任何问题都必须遵循。以下内容摘自在线文档：

> *这将创建`ENV/lib/pythonX.X/site-packages`，您安装的任何库都将放在这里。它还会创建`ENV/bin/python`，这是一个使用此环境的 Python 解释器。每次使用该解释器（包括当脚本中有`#!/path/to/ENV/bin/python`时），都将使用该环境中的库。*

我们可以在[`pypi.python.org/pypi/virtualenv/1.8.2`](https://pypi.python.org/pypi/virtualenv/1.8.2)找到 virtualenv 在线文档。

新的`virtualenv`文件夹还包括 pip 安装程序，因此您可以使用`ENV/bin/pip`命令将其他软件包安装到环境中。

### 注意

**激活脚本**：在新创建的虚拟环境中将有一个`bin/activate` shell 脚本。对于 Windows 系统，提供了**CMD**和**Powershell**的激活脚本。

您可以在以下网址阅读更多信息：

[`virtualenv.readthedocs.org/en/latest/virtualenv.html`](http://virtualenv.readthedocs.org/en/latest/virtualenv.html)

在 Unix 系统上，我们可以使用以下命令激活`virtualenv`脚本：

```py
$ source bin/activate

```

![安装 virtualenv](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00272.jpeg)

在 Windows 上，我们可以使用以下命令在命令提示符上激活`virtualenv`脚本：

```py
: > \path\to\env\Scripts\activate

```

输入`deactivate`来撤消更改，如下图所示：

![安装 virtualenv](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00273.jpeg)

这将更改您的`$PATH`变量。

要了解有关激活脚本的更多信息，例如您正在使用哪个环境或是否需要激活脚本，请访问以下链接：

[`virtualenv.readthedocs.org/en/latest/virtualenv.html`](http://virtualenv.readthedocs.org/en/latest/virtualenv.html)

## 安装 Django

安装 Django 非常简单，但在某种程度上取决于您的操作系统。由于 Python 是一种平台无关的语言，Django 有一个包可以在任何操作系统上使用。

要下载 Django，请访问[`www.djangoproject.com/download/`](http://www.djangoproject.com/download/)并获取最新的官方版本。本书中的代码是在 Django 1.7（本文撰写时的最新版本）上开发的，但大部分代码应该可以在以后的官方版本上运行。接下来，按照与您的平台相关的说明进行操作。

### Django 与操作系统的兼容性- Windows 与 Linux

在处理操作系统时，有一些要注意的地方。在运行 Django 之前，许多软件包和设置需要进行调整，以确保没有任何问题。让我们来看看它们：

+   一些 Python 软件包在 Windows 上无法正确安装，或者根本无法安装；如果可以安装，当您运行 Django 时会带来很多麻烦

+   如果您需要部署 Django 应用程序，最好使用类 Unix 系统，因为 99%的情况下，您的部署环境是相同的

+   如果您的应用程序很复杂，获取所需的依赖项会更容易，无论是 Linux 中的扩展，库等等

### 在 Windows 上安装 Django

在下载了 Django 存档之后，将其解压到 C 驱动器，并打开命令提示符（从**开始** | **附件**）。现在，通过发出以下命令，将当前目录更改为您从中提取 Django 的位置：

```py
c:\>cd c:\Django-x.xx

```

这里，`x.xx`是您的 Django 版本。

接下来，通过运行以下命令来安装 Django（您需要管理员权限）：

### 注意

如果您的系统没有处理`.tar.gz`文件的程序，我建议使用**7-Zip**，它是免费的，可以在[`www.7-zip.org/`](http://www.7-zip.org/)上获得。

```py
c:\Django-x.xx>python setup.py install

```

如果由于某种原因前面的说明没有起作用，您可以手动将存档中的`django`文件夹复制到 Python 安装目录中的`Lib\site-packages`文件夹中。这将执行`setup.py`安装命令的工作。

最后一步是将`Django-x.xx\django\bin`中的`django-admin.py`文件复制到系统路径的某个位置，例如`c:\windows`或您安装 Python 的文件夹。

完成后，您可以安全地删除`c:\Django-x.xx`文件夹，因为它不再需要了。

就是这样！要测试您的安装，请打开命令提示符并输入以下命令：

```py
c:\>django-admin.py --version

```

如果您在屏幕上看到 Django 的当前版本，则一切都已设置好。

### 在 Unix/Linux 和 Mac OS X 上安装 Django

所有 Unix 和 Linux 系统的安装说明都是相同的。您需要在`Django-x.xx.tar.gz`存档所在的目录中运行以下命令。这些命令将为您提取存档并安装 Django：

```py
$ tar xfz Django-x.xx.tar.gz
$ cd Django-x.xx
$ sudo python setup.py install

```

前面的说明应该适用于任何 Unix/Linux 系统，以及 Mac OS X。但是，如果您的系统有 Django 的软件包，通过系统的软件包管理器安装 Django 可能会更容易。Ubuntu 有一个；因此，要在 Ubuntu 上安装 Django，只需在 Synaptic 中查找一个名为`python-django`的软件包，或者运行以下命令：

```py
$ sudo apt-get install python-django

```

您可以通过运行以下命令来测试您的安装：

```py
$ django-admin.py --version

```

如果您在屏幕上看到 Django 的当前版本，则一切都已设置好。

## 安装数据库系统

虽然 Django 不需要数据库来运行，但我们将要开发的应用程序需要。因此，在软件安装的最后一步，我们将确保我们有一个数据库系统来处理我们的数据。

值得注意的是，Django 支持多种数据库引擎：**MySQL**、**PostgreSQL**、**MS SQL Server**、**Oracle**和**SQLite**。然而，有趣的是，您只需要学习一个 API 就可以使用任何这些数据库系统。这是可能的，因为 Django 的数据库层抽象了对数据库系统的访问。我们稍后会学习这一点，但是现在，您只需要知道，无论您选择哪种数据库系统，您都可以运行本书（或其他地方）开发的 Django 应用程序而无需修改。

如果您使用 Python 2.7 或更高版本，则无需安装任何内容。Python 2.7 带有名为`sqlite3`的 SQLite 数据库管理系统模块。与客户端-服务器数据库系统不同，SQLite 不需要内存中的常驻进程，并且它将数据库存储在单个文件中，这使其非常适合我们的开发环境。

如果您没有 Python 2.7，您可以通过在[`www.pysqlite.org/`](http://www.pysqlite.org/)（Windows 用户）下载或通过您的软件包管理器（Unix/Linux）手动安装 SQLite 的 Python 模块。

另一方面，如果您的系统上已经安装了另一个受 Django 支持的数据库服务器，您也可以使用它。我们将在后面的部分中看到，通过编辑配置文件，我们可以告诉 Django 使用哪个数据库系统。

### 提示

**我不需要 Apache 或其他网络服务器吗？**

Django 自带自己的网络服务器，在开发阶段我们将使用它，因为它轻量级且预先配置了 Django。但是，Django 也支持 Apache 和其他流行的网络服务器，如 lighttpd、nginx 等。我们将在本书后面的部分中看到，当我们准备部署应用程序时，如何配置 Django 以适用于 Apache。

数据库管理器也是一样。在开发阶段，我们将使用 SQLite，因为它易于设置，但是当我们部署应用程序时，我们将切换到诸如 MySQL 之类的数据库服务器。

正如我之前所说的，无论我们使用什么组件，我们的代码都将保持不变；Django 会处理与网络和数据库服务器的所有通信。

# 创建您的第一个项目

现在，我们已经准备好了所需的软件，是时候进行有趣的部分了——创建我们的第一个 Django 项目了！

如果您还记得 Django 安装部分，我们使用了一个名为`django-admin.py`的命令来测试我们的安装。这个实用程序是 Django 项目管理设施的核心，因为它使用户能够执行一系列项目管理任务，包括以下内容：

+   创建一个新项目

+   创建和管理项目的数据库

+   验证当前项目并测试错误

+   启动开发网络服务器

我们将在本章的其余部分看到如何使用这些任务。

## 创建一个空项目

要创建您的第一个 Django 项目，请打开终端（或 Windows 用户的命令提示符；即**开始** | **运行** | **cmd**），然后输入以下命令。然后，按*Enter*。

```py
$ django-admin.py startproject django_bookmarks

```

这个命令将在当前目录中创建一个名为`django_bookmarks`的文件夹，并在其中创建初始目录结构。让我们看看创建了哪些类型的文件：

```py
django_bookmarks/
|-- django_bookmarks
|   |-- __init__.py
|   |-- settings.py
|   |-- urls.py
|   `-- wsgi.py
`-- manage.py
```

以下是这些文件的快速解释：

+   `__init__.py`：Django 项目是 Python 包，这个文件是必需的，用于告诉 Python 这个文件夹应该被视为一个包。

Python 术语中的包是模块的集合，它们用于将类似的文件分组在一起，以防止命名冲突。

+   `manage.py`：这是另一个用于管理我们项目的实用脚本。您可以将其视为项目版本的`django-admin.py`文件。实际上，`django-admin.py`和`manage.py`共享相同的后端代码。

+   `settings.py`：这是您的 Django 项目的主要配置文件。在其中，您可以指定各种选项，包括数据库设置、站点语言、需要启用的 Django 功能等。在接下来的章节中，我们将解释此文件的各个部分，但在本章中，我们只会看到如何输入数据库设置。

+   `url.py`：这是另一个配置文件。您可以将其视为 URL 和处理它们的 Python 函数之间的映射。这个文件是 Django 的强大功能之一，我们将在下一章中看到如何利用它。

当我们开始为应用程序编写代码时，我们将在项目文件夹内创建新文件；因此该文件夹也用作我们代码的容器。

现在您已经对 Django 项目的结构有了一个大致的了解，让我们配置我们的数据库系统。

## 设置数据库

在本节中，我们将开始使用各种选项和配置文件设置数据库。

好了，现在我们已经准备好了源代码编辑器，让我们打开项目文件夹中的`settings.py`文件并查看其内容：

```py
"""
Django settings for django_bookmarks project.

For more information on this file, see
https://docs.djangoproject.com/en/1.7/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.7/ref/settings/
"""

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import os
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.7/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = ')9c8g--=vo2*rh$9f%=)=e+@%7e%xe8jptgpfe+(90t7uurfy0'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

TEMPLATE_DEBUG = True

ALLOWED_HOSTS = []

# Application definition

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
)

MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
)

ROOT_URLCONF = 'django_bookmarks.urls'

WSGI_APPLICATION = 'django_bookmarks.wsgi.application'

# Database
# https://docs.djangoproject.com/en/1.7/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}

# Internationalization
# https://docs.djangoproject.com/en/1.7/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.7/howto/static-files/

STATIC_URL = '/static/'
```

您可能已经注意到，该文件包含许多控制应用程序各个方面的变量。输入变量的新值就像执行 Python 赋值语句一样简单。此外，该文件有大量注释，注释详细解释了变量的控制内容。

现在让我们关注配置数据库。如前所述，Django 支持多个数据库系统，因此首先，我们必须指定我们将要使用的数据库系统。这由`DATABASE_ENGINE`变量控制。如果您已安装 SQLite，请将该变量设置为`'sqlite3'`。否则，请从变量名称旁边的注释中选择与您的数据库引擎匹配的值。

接下来是数据库名称。保持数据库名称默认即可。另一方面，如果您正在使用数据库服务器，您需要执行以下操作：

+   输入数据库的相关信息：用户名、密码、主机和端口。（SQLite 不需要这些。）

+   在数据库服务器内创建实际数据库，因为 Django 不会自行执行此操作。例如，在 MySQL 中，可以通过`mysql`命令行实用程序或 phpMyAdmin 来执行此操作。

最后，我们将告诉 Django 使用表填充已配置的数据库。虽然我们尚未为我们的数据创建任何表（并且在下一章之前也不会这样做），但 Django 需要数据库中的一些表才能正常运行一些功能。创建这些表就像发出以下命令一样简单：

```py
$ python manage.py syncdb

```

如果一切正确，状态消息将在屏幕上滚动，指示正在创建表。在提示输入超级用户帐户时，请输入您首选的用户名、电子邮件和密码。另一方面，如果数据库配置错误，将打印错误消息以帮助您排除问题。

完成这些操作后，我们就可以启动我们的应用程序了。

### 提示

**使用 python manage.py**

运行以`python manage.py`开头的命令时，请确保您当前位于项目的目录中，其中包含`manage.py`。

## 启动开发服务器

如前所述，Django 带有一个轻量级的 Web 服务器，用于开发和测试应用程序。该服务器预先配置为与 Django 一起工作，并且更重要的是，每当您修改代码时，它都会重新启动。

要启动服务器，请运行以下命令：

```py
$ python manage.py runserver

```

接下来，打开浏览器，导航至以下 URL：`http://localhost:8000/`。您应该会看到欢迎消息，如下截图所示：

![启动开发服务器](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00274.jpeg)

恭喜！您已经创建并配置了您的第一个 Django 项目。这个项目将是我们构建书签应用程序的基础。在下一章中，我们将开始开发我们的应用程序，网页服务器显示的页面将被我们自己编写的内容替换！

### 注意

您可能已经注意到，默认情况下，Web 服务器在端口 8000 上运行。如果要更改端口，可以使用以下命令在命令行上指定：

```py
$ python manage.py runserver <port number>

```

此外，默认情况下，开发服务器只能从本地机器访问。如果您想从网络上的另一台机器访问开发服务器，请使用以下命令行参数：

```py
$ python manage.py runserver 0.0.0.0:<port number>

```

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

# 总结

在这一章中，我们已经准备好了我们的开发环境，创建了我们的第一个项目，并学会了如何启动 Django 开发服务器。我们学会了如何在 Windows 和 Linux 中安装 Django 和 virtualenv。我们学习了 Django 设置的基本机制，甚至学会了如何安装数据库。

现在我们准备开始构建我们的社交书签应用程序！下一章将带您了解主要的 Django 组件，并为我们的书签分享应用程序开发一个工作原型。这将是一个有趣的章节，有很多新东西要学习，所以请继续阅读！


# 第三章：Django 中的代码风格

由于您来自 Python 背景，您可能已经编写了大量的代码，并且当然也享受过。

Python 代码易于维护，并且适用于小型项目或解决任何竞争性编程比赛；您可以通过将 Python 代码存储在本地或存储在公共文件夹中来实现。但是，如果您正在进行协作项目，特别是 Web 开发，那么这将使一切与传统编码不同。这不仅需要纪律，比如遵循项目的代码语法，还可能需要为您的代码编写大量的文档。在使用任何版本控制工具，比如 GIT 时，您的提交消息（在让其他开发人员更容易理解您正在做什么或已经完成的工作方面起着重要作用）也会广播项目的当前进展。

本章将涵盖您需要遵循的所有基本主题，比如更好的 Django Web 开发的编码实践，使用哪个 IDE，版本控制等等。

我们将在本章学习以下主题：

+   Django 编码风格

+   使用 IDE 进行 Django Web 开发

+   Django 项目结构

+   最佳实践——使用版本控制

+   Django 救援团队（在哪里提问 Django 问题）

+   更快的 Web 开发——使用 Twitter-Bootstrap

### 注意

本章基于一个重要事实，即代码被阅读的次数远远多于被编写的次数。因此，在您真正开始构建项目之前，我们建议您熟悉 Django 社区为 Web 开发采用的所有标准实践。

# Django 编码风格

Django 的大部分重要实践都是基于 Python 的。虽然您可能已经知道它们，但我们仍然会停下来写出所有记录的实践，以便您在开始之前就了解这些概念。当然，在构建项目时，您可以回到本章快速查看。

为了使标准实践成为主流，Python 增强提案被提出，其中一个被广泛采用的开发标准实践是 PEP8，Python 代码的风格指南——Guido van Rossum 编写的 Python 代码的最佳风格。

文档中说道，“PEP8 处理与 Python 文档字符串相关的语义和约定。”更多阅读，请访问[`legacy.python.org/dev/peps/pep-0008/`](http://legacy.python.org/dev/peps/pep-0008/)。

## 理解 Python 中的缩进

当你编写 Python 代码时，缩进起着非常重要的作用。它就像其他语言中的块，比如 C 或 Perl。但是程序员们总是在讨论是否应该使用制表符还是空格，以及如果使用空格，应该使用多少——两个、四个还是八个。使用四个空格进行缩进比使用八个更好，如果有更多的嵌套块，使用八个空格进行每次缩进可能会占用更多字符，无法在单行中显示。但是，这又是程序员的选择。

以下是错误的缩进实践导致的结果：

```py
>>> def a():
...   print "foo"
...     print "bar"
IndentationError: unexpected indent

```

那么，我们应该使用哪个：制表符还是空格？

选择其中一个，但在同一个项目中不要混合使用制表符和空格，否则维护起来会是一场噩梦。Python 中最流行的缩进方式是使用空格；制表符排在第二位。如果你遇到了混合使用制表符和空格的代码，你应该将其转换为只使用空格。

### 正确的缩进——我们是否需要每次缩进级别四个空格？

关于这个问题已经有很多混淆，当然，Python 的语法都是关于缩进的。坦率地说：在大多数情况下，确实是这样。因此，强烈建议每个缩进级别使用四个空格，如果你一直使用两个空格的方法，就停止使用它。这没有错，但是当你处理多个第三方库时，你可能最终会得到一个不同版本的代码混乱，最终会变得难以调试。

现在是缩进的问题。当你的代码在一个连续的行中时，你应该垂直对齐，或者你可以选择悬挂缩进。当你使用悬挂缩进时，第一行不应包含任何参数，进一步的缩进应该用来清楚地区分它作为一个连续的行。

### 注意

悬挂缩进（也称为负缩进）是一种缩进风格，其中所有行都缩进，除了段落的第一行。前面的段落就是悬挂缩进的例子。

以下示例说明了在编写代码时应该如何使用适当的缩进方法：

```py
bar = some_function_name(var_first, var_second,
 var_third, var_fourth) 
# Here indentation of arguments makes them grouped, and stand clear from others.
def some_function_name(
 var_first, var_second, var_third,
 var_fourth):
 print(var_first)
# This example shows the hanging intent.

```

我们不鼓励以下编码风格，而且在 Python 中也不起作用：

```py
# When vertical alignment is not used, Arguments on the first line are forbidden
foo = some_function_name(var_first, var_second,
 var_third, var_fourth)
# Further indentation is required as indentation is not distinguishable between arguments and source code.
def some_function_name(
 var_first, var_second, var_third,
 var_fourth):
 print(var_first)

```

虽然不需要额外的缩进，但如果你想使用额外的缩进来确保代码能够工作，你可以使用以下编码风格：

```py
# Extra indentation is not necessary.
if (this
 and that):
 do_something()

```

### 提示

理想情况下，你应该将每行限制在最多 79 个字符。这允许使用`+`或`–`字符来查看使用版本控制的差异。为了编辑器的统一性，最好将行限制在 79 个字符。你可以利用剩余的空间做其他用途。

### 空行的重要性

两个空行和单个空行的重要性如下：

+   **两个空行**：双空行可以用于分隔顶层函数和类定义，从而增强代码的可读性。

+   **单个空行**：单个空行可以用于以下用例--例如，类中的每个函数可以用单个空行分隔，相关函数可以用单个空行分组。你也可以用单个空行分隔源代码的逻辑部分。

## 导入一个包

导入一个包是代码可重用的直接影响。因此，总是将导入放在源文件的顶部，紧跟在任何模块注释和文档字符串之后，在模块的全局和常量变量之前。每个导入通常应该在单独的行上。

导入包的最佳方式如下：

```py
import os
import sys

```

不建议在同一行中导入多个包，例如：

```py
import sys, os

```

你可以按照以下方式导入包，尽管这是可选的：

```py
from django.http import Http404, HttpResponse

```

如果你的导入变得更长，你可以使用以下方法来声明它们：

```py
from django.http import (
Http404, HttpResponse, HttpResponsePermanentRedirect
)

```

### 分组导入的包

包的导入可以按以下方式分组：

+   **标准库导入**：比如`sys`，os，`subprocess`等。

```py
import re
import simplejson

```

+   **相关的第三方导入**：这些通常是从 Python 奶酪商店下载的，也就是**PyPy**（使用 pip install）。这里有一个例子：

```py
from decimal import *

```

+   **本地应用/特定库的导入**：这包括你项目的本地模块，比如模型，视图等。

```py
from models import ModelFoo
from models import ModelBar

```

## Python/Django 的命名约定

每种编程语言和框架都有自己的命名约定。Python/Django 中的命名约定大体上是一样的，但是值得在这里提一下。在创建变量名或全局变量名以及命名类、包、模块等时，你需要遵循这个约定。

这是我们应该遵循的常见命名约定：

+   **正确命名变量**：永远不要使用单个字符，例如，'x'或'X'作为变量名。这在你平常的 Python 脚本中可能没问题，但是当你构建一个 web 应用程序时，你必须适当地命名变量，因为它决定了整个项目的可读性。

+   **包和模块的命名**：建议模块使用小写和短名称。如果使用下划线可以提高可读性，则可以使用下划线。Python 包也应具有短小写名称，尽管不鼓励使用下划线。

+   由于模块名称映射到文件名（`models.py`，`urls.py`等），因此选择模块名称要相当简短是很重要的，因为一些文件系统不区分大小写并且会截断长名称。

+   **命名类**：类名应遵循**CamelCase**命名约定，内部使用的类可以在其名称中加上下划线。

+   **全局变量名称**：首先，应避免使用全局变量，但如果需要使用它们，可以通过`__all__`来防止全局变量被导出，或者通过在名称中定义带有前缀下划线的方式（旧的传统方式）。

+   **函数名称和方法参数**：函数名称应为小写，并用下划线分隔，`self`作为实例化方法的第一个参数。对于类或方法，使用 CLS 或对象进行初始化。

+   **方法名称和实例变量**：使用函数命名规则，必要时使用下划线分隔单词以提高可读性。仅对非公共方法和实例变量使用一个前导下划线。

# 使用 IDE 进行更快的开发

在源代码编辑器方面市场上有很多选择。有些人喜欢全功能的集成开发环境（IDE），而其他人喜欢简单的文本编辑器。选择完全取决于您；选择您感觉更舒适的。如果您已经使用某个程序来处理 Python 源文件，我建议您继续使用，因为它将与 Django 一起很好地工作。否则，我可以提出一些建议，比如这些：

+   **SublimeText**：这个编辑器非常轻巧而功能强大。它适用于所有主要平台，支持语法高亮和代码补全，并且与 Python 兼容。该编辑器是开源的，您可以在[`www.sublimetext.com/`](http://www.sublimetext.com/)找到它

+   **PyCharm**：我要说，这是最智能的代码编辑器，具有高级功能，如代码重构和代码分析，使开发更清洁。Django 的功能包括模板调试（这是一个赢家），还有快速文档，因此这种查找对于初学者来说是必不可少的。社区版是免费的，您可以在购买专业版之前试用 30 天。

# 使用 Sublime 文本编辑器设置您的项目

本书中大多数示例将使用**Sublime 文本编辑器**编写。在本节中，我们将展示如何安装和设置 Django 项目。

1.  **下载和安装**：您可以从网站[www.sublimetext.com](http://www.sublimetext.com)的下载选项卡下载 Sublime。单击下载文件选项进行安装。

1.  **为 Django 设置**：Sublime 拥有非常庞大的插件生态系统，这意味着一旦您下载了编辑器，就可以安装插件以添加更多功能。

安装成功后，它将如下所示：

![使用 Sublime 文本编辑器设置项目](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00275.jpeg)

### 注意

最重要的是**Package Control**，它是在 Sublime 内直接安装附加插件的管理器。这将是您唯一手动安装的软件包。它将处理其余的软件包安装。

![使用 Sublime 文本编辑器设置项目](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00276.jpeg)

使用 Sublime 进行 Python 开发的一些建议如下：

+   **Sublime Linter**：在您编写 Python 代码时，它会立即提供有关代码的反馈。它还支持 PEP8；此插件将实时突出显示我们在前一节中讨论的有关更好编码的内容，以便您可以修复它们。![使用 Sublime 文本编辑器设置项目](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00277.jpeg)

+   **Sublime CodeIntel**：这是由**SublimeLint**的开发人员维护的。Sublime CodeIntel 具有一些高级功能，例如直接跳转到定义，智能代码完成和导入建议。![使用 Sublime 文本编辑器设置项目](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00278.jpeg)

您还可以探索其他 Sublime 插件，以提高您的生产力。

# 设置 PyCharm IDE

您可以使用任何您喜欢的 IDE 进行 Django 项目开发。我们将在本书中使用 pycharm IDE。建议使用此 IDE，因为它将在调试时帮助您使用断点，这将节省您大量时间弄清楚实际出了什么问题。

以下是如何安装和设置**pycharm** IDE 用于 Django：

1.  **下载和安装**：您可以从以下链接检查功能并下载 pycharm IDE：

[`www.jetbrains.com/pycharm/`](http://www.jetbrains.com/pycharm/)

![设置 PyCharm IDE](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00279.jpeg)

1.  **为 Django 设置**：为 Django 设置 pycharm 非常容易。您只需导入项目文件夹并提供`manage.py`路径，如下图所示：![设置 PyCharm IDE](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00280.jpeg)

# Django 项目结构

Django 项目结构在 1.6 版本中已更改。Django（`django-admin.py`）还有一个`startapp`命令来创建一个应用程序，因此现在是时候告诉您 Django 中应用程序和项目之间的区别了。

**项目**是一个完整的网站或应用程序，而**应用程序**是一个小型的、独立的 Django 应用程序。应用程序基于这样一个原则，即它应该做一件事，并且做得正确。

为了简化从头开始构建 Django 项目的痛苦，Django 通过自动生成基本项目结构文件来为您提供优势，从而可以将任何项目推进到其开发和功能添加阶段。

因此，总之，我们可以说项目是应用程序的集合，应用程序可以作为一个独立实体编写，并且可以轻松地导出到其他应用程序以供重用。

要创建您的第一个 Django 项目，请打开终端（或 Windows 用户的命令提示符），输入以下命令，然后按*Enter*：

```py
$ django-admin.py startproject django_mytweets

```

此命令将在当前目录中创建一个名为`django_mytweets`的文件夹，并在其中创建初始目录结构。让我们看看创建了哪些类型的文件。

新结构如下：

```py
django_mytweets///
django_mytweets/
manage.py
```

这是`django_mytweets/`的内容：

```py
django_mytweets/
__init__.py
settings.py
urls.py
wsgi.py
```

以下是这些文件的快速解释：

+   `django_mytweets`（外部文件夹）：此文件夹是项目文件夹。与以前的项目结构相反，在以前的项目结构中，整个项目都保存在一个文件夹中，新的 Django 项目结构在某种程度上暗示着每个项目都是 Django 中的一个应用程序。

这意味着您可以在与 Django 项目相同的级别上导入其他第三方应用程序。此文件夹还包含`manage.py`文件，其中包括所有项目管理设置。

+   `manage.py`：这是用于管理我们的项目的实用程序脚本。您可以将其视为项目版本的`django-admin.py`。实际上，`django-admin.py`和`manage.py`共享相同的后端代码。

### 注意

当我们要调整更改时，将提供有关设置的进一步澄清。

让我们看看`manage.py`文件：

```py
#!/usr/bin/env python
import os
import sys
if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_mytweets.settings")
    from django.core.management import execute_from_command_line
    execute_from_command_line(sys.argv)
```

一旦阅读以下代码解释，`manage.py`文件的源代码将不言自明。

```py
#!/usr/bin/env python

```

第一行只是声明接下来的文件是一个 Python 文件，然后是导入部分，其中导入了`os`和`sys`模块。这些模块主要包含与系统相关的操作。

```py
import os
import sys
```

下一段代码检查文件是否由主函数执行，这是要执行的第一个函数，然后将 Django 设置模块加载到当前路径。由于您已经在运行虚拟环境，这将为所有模块设置路径为当前运行虚拟环境的路径。

```py
if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_mytweets.settings")
django_mytweets/ ( Inner folder)
__init__.py
```

Django 项目是 Python 包，这个文件是必需的，用于告诉 Python 这个文件夹应该被视为一个包。在 Python 的术语中，包是模块的集合，它们用于将类似的文件分组在一起，并防止命名冲突。

+   `settings.py`：这是 Django 项目的主要配置文件。在其中，您可以指定各种选项，包括数据库设置、站点语言、需要启用的 Django 功能等。在接下来的章节中，随着我们构建应用程序的进展，将解释该文件的各个部分。

默认情况下，数据库配置为使用 SQLite 数据库，这是用于测试目的的建议使用。在这里，我们将只看到如何在设置文件中输入数据库；它还包含基本的设置配置，并且在`manage.py`文件中稍作修改，它可以被移动到另一个文件夹，比如`config`或`conf`。

要使每个其他第三方应用程序成为项目的一部分，我们需要在`settings.py`文件中注册它。`INSTALLED_APPS`是一个包含所有已安装应用程序条目的变量。随着项目的增长，管理起来变得困难；因此，`INSTALLED_APPS`变量有三个逻辑分区，如下所示：

+   `DEFAULT_APPS`：此参数包含默认的 Django 已安装应用程序（如管理员）

+   `THIRD_PARTY_APPS`：此参数包含其他应用程序，比如**SocialAuth**，用于社交认证

+   `LOCAL_APPS`：此参数包含您创建的应用程序

+   `url.py`：这是另一个配置文件。您可以将其视为 URL 和 Django 视图函数之间的映射。这个文件是 Django 更强大的功能之一，我们将在下一章中看到如何利用它。

当我们开始为我们的应用程序编写代码时，我们将在项目文件夹内创建新文件。因此，该文件夹也作为我们代码的容器。

现在您对 Django 项目的结构有了一个大致的了解，让我们配置我们的数据库系统。

# 最佳实践 - 使用版本控制

版本控制是一个系统，它会记住您在项目中所做的所有更改，随着您的不断进展。在任何时间点，您都可以查看对特定文件所做的更改；随着时间的推移，您可以还原它或进一步编辑它。

对于具有多个贡献者的项目，特别是那些同时在同一文件上工作的项目，版本控制更有意义。版本控制是一个救命稻草，因为它记录了文件的各个版本，并允许选项，比如通过合并或丢弃任一副本来保存两个版本。

我们将使用分布式版本控制，也就是说，每个开发人员都有项目的完整副本（与子版本控制相反，其中存储库托管在系统服务器上）。

## Git - 最新和最流行的版本控制工具

**Git**是我们将用于项目的版本控制工具。它是目前最好的版本控制工具，也是开源的。Git 除了源代码文件外，还可以很好地处理其他类型的文件，比如图像、PDF 等。您可以从以下网址下载 Git：

[`git-scm.com/downloads`](http://git-scm.com/downloads)

大多数现代集成开发环境已经内置了版本控制系统支持；像 PyCharm、Sublime 这样的 IDE 已经有了可以将 Git 集成到工作目录中的插件。Git 可以使用`git`命令从终端初始化，并且您可以使用`git --help`命令查看它提供的更多选项。

### Git 的工作原理

作为开发人员，我们有一个与远程服务器（通常称为存储库）同步的本地项目副本，并且可以将其发送到远程存储库。当其他开发人员想要将更改推送到远程存储库时，他们必须首先拉取您的更改。这最大程度地减少了中央存储库上的冲突机会，其中每个开发人员都是同步的。整个工作流程在下一节中显示。

### 设置您的 Git

任何项目都可以添加到 Git 进行版本控制，将文件夹创建为 Git 存储库。要做到这一点，使用以下命令：

+   `$git init`：如果要复制现有的 Git 存储库，这可能是您的朋友已经在**GitHub**或**Bitbucket**上托管了它的情况，请使用以下命令：

+   `$git clone URL`：远程存储库的 URL，如[`github.com/AlienCoders/web-development.git`](https://github.com/AlienCoders/web-development.git)。

**暂存区**：暂存区是您在提交文件之前必须首先列出所有文件的地方。简而言之，暂存是需要作为中间步骤而不是直接提交的，因为当发生冲突时，它们会在暂存区中标记。只有在冲突解决后才能提交文件。

让我们看看以下命令及其用途：

+   `$git add <file-name>`或`$git add`：用于批量将所有文件添加到暂存区。

+   `$git status`：了解您的工作目录的状态，已添加哪些文件，哪些文件尚未添加。

+   `$git diff`：获取已修改和已暂存的状态，或者获取已修改但尚未暂存的状态。

+   `$ git commit -m`：要提交所做的更改，首先必须将它们添加到暂存区；然后，您必须使用此命令提交它们。

+   `$ git rm <file-name>`：如果您错误地将任何文件添加到暂存区，可以使用此命令从暂存区中删除它。

+   `$git stash`: Git 不跟踪重命名的文件。换句话说，如果您已经重命名了已经暂存的文件，您将不得不再次将它们添加到暂存区，然后提交。您可以通过使用以下命令将更改保存到存储库而不实际提交。

+   `$git stash apply`：它将所有当前更改保存到堆栈中。然后，您可以继续使用您的更改。一旦您有能力获取您保存的更改，您可以使用此命令。

### Git 中的分支

版本控制的另一个概念是**分支**（Git）。分支就像您的提交路径，默认情况下，所有提交都在主分支上进行。分支主要用于跟踪项目中的功能。每个功能都可以作为分支进行工作；一旦功能完成，就可以将其合并回主分支。

分支的基本工作流程是这样的：您最初有一个主分支，并为每个新功能创建一个新分支。更改将提交到新分支，一旦完成功能，您可以将其合并回主分支。这可以用以下方式直观表示：

+   `$git branch`：要列出使用 Git 的现有分支，我们需要使用此命令。![Git 中的分支](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00281.jpeg)

+   `git checkout -b <new-branch-name>`：使用此命令可以在现有存储库中创建一个新分支。我们可以通过以下块图逻辑地看到它的外观：![Git 中的分支](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00282.jpeg)

您将收到一条消息，通知您已切换到新分支。如果要切换回旧分支，可以使用以下命令：

+   `$git checkout <old-branch-name>`：您将看到消息`切换到分支<old-branch-name>`。

+   `$git merge <branch-name>`：功能完成后，您可以使用此命令将其合并到您选择的分支。这将分支`<branch-name>`合并到当前分支。要将更改同步回`<branch-name>`，您可以从当前分支切换到分支`<branch-name>`并再次合并。您还可以使用标签在提交历史中标记重要的点。

+   提交后，您可以使用`$git tag -a v1.0`命令标记重要的提交。

+   要从远程服务器获取新更改，您可以使用`$git fetch`命令从 Git 中获取更改。

+   将更改直接合并到当前分支，您可以使用`$git pull`命令。

+   完成更改后，您可以使用`$git push`命令将其提交并推送到远程存储库。

# 设置数据库

在本节中，我们将首次开始使用代码。因此，我们将不得不选择一个源代码编辑器来输入和编辑代码。您可以使用任何您喜欢的源代码编辑器。如前所述，我们已经使用 Sublime 文本编辑器来编写本书的代码。

好了，现在您已经准备好一个源代码编辑器，让我们打开项目文件夹中的`settings.py`并查看其中包含的内容：

```py
# Django settings for django_mytweets project.
DEBUG = True
TEMPLATE_DEBUG = DEBUG
ADMINS = (
    # ('Your Name', 'your_email@domain.com'),
)
MANAGERS = ADMINS
DATABASE_ENGINE = ''   # 'postgresql_psycopg2', 'postgresql',
                       # 'mysql', 'sqlite3' or 'ado_mssql'.
DATABASE_NAME = ''     # Or path to database file 
                       # if using sqlite3.
DATABASE_USER = ''     # Not used with sqlite3.
DATABASE_PASSWORD = '' # Not used with sqlite3.
DATABASE_HOST = ''     # Set to empty string for localhost.
                       # Not used with sqlite3.
DATABASE_PORT = ''     # Set to empty string for default.
                       # Not used with sqlite3.
```

`settings.py`文件中还有许多行，但我们已经削减了此文件的其余内容。

您可能已经注意到，该文件包含许多控制应用程序各个方面的变量。输入变量的新值就像执行 Python 赋值语句一样简单。此外，该文件有大量注释，并且注释详细解释了变量控制的内容。

现在让我们关注配置数据库。如前所述，Django 支持多个数据库系统，因此，首先，我们必须指定要使用的数据库系统。这由`DATABASE_ENGINE`变量控制。如果安装了 SQLite，请将变量设置为`sqlite3`。否则，从变量名称旁边的注释中选择与您的数据库引擎匹配的值。

接下来是数据库名称。我们将为您的数据库选择一个描述性名称；编辑`DATABASE_NAME`并将其设置为`django_mytweetsdb`。如果您使用 SQLite，这就是您需要做的。另一方面，如果您使用数据库服务器，请按照以下说明操作：

+   输入数据库的相关信息-用户名、密码、主机和端口（SQLite 不需要这些）。

+   在数据库服务器中创建实际数据库，因为 Django 不会自行执行此操作。例如，在 MySQL 中，可以通过`mysql`命令行实用程序或`phpMyAdmin`来完成此操作。

进行这些简单的编辑后，`settings.py`中的数据库部分现在如下所示：

```py
DATABASE_ENGINE = 'sqlite3'
DATABASE_NAME = 'django_mytweetsdb'
DATABASE_USER = ''
DATABASE_PASSWORD = ''
DATABASE_HOST = ''
DATABASE_PORT = ''
```

最后，我们将告诉 Django 使用表填充配置的数据库。尽管我们尚未为我们的数据创建任何表（直到下一章我们才会这样做），但 Django 需要数据库中的一些表才能正常运行一些功能。创建这些表就像发出以下命令一样简单：

```py
$ python manage.py syncdb

```

如果一切正确，状态消息将在屏幕上滚动，指示正在创建表。在提示超级用户帐户时，请输入您首选的用户名、电子邮件和密码。另一方面，如果数据库配置错误，将打印错误消息以帮助您排除故障。

完成后，我们准备启动我们的应用程序。

### 注意

**使用 python manage.py**

运行以`python manage.py`开头的命令时，请确保您当前位于项目的目录中，其中包含`manage.py`文件。

# 启动开发服务器

如前所述，Django 带有一个轻量级的 Web 服务器，用于开发和测试应用程序。该服务器预先配置为与 Django 一起工作，更重要的是，每当您修改代码时，它都会重新启动。

要启动服务器，请运行以下命令：

```py
$ python manage.py runserver

```

接下来，打开浏览器并导航到此 URL：`http://localhost:8000/`。您应该会看到欢迎消息，如下面的截图所示：

![启动开发服务器](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00283.jpeg)

恭喜！您已经创建并配置了您的第一个 Django 项目。这个项目将是我们构建书签应用程序的基础。在下一章中，我们将开始开发我们的应用程序，Web 服务器显示的页面将被我们自己编写的内容替换！

正如您可能已经注意到的，Web 服务器默认在端口`8000`上运行。如果要更改端口，可以使用以下命令在命令行上指定：

```py
$ python manage.py runserver <port number>

```

此外，默认情况下，开发服务器只能从本地机器访问。如果要从网络上的另一台机器访问开发服务器，请使用以下命令行参数：

```py
$ python manage.py runserver 0.0.0.0:<port number>

```

# 更快的 Web 开发

在 Web 开发中，对 Web 项目成功起到重要帮助的一件事是其用户界面和用户体验。尽管 Django 在后端处理所有业务逻辑，但无疑需要一个令人敬畏的前端设计框架，不仅可以在编码时简化开发人员的生活，而且还可以增强整个 Web 项目的用户体验。因此，我们选择在这里解释**Twitter Bootstrap**。

## 最小化的 Bootstrap

**Bootstrap**是一个完整的前端框架，超出了本书的范围，无法让您熟悉它的每个方面。您一定会想知道为什么我们会在 Django 书中讨论 Bootstrap。您被告知了一个前端框架。这里的想法是帮助您构建一个可以直接用于生产的 Web 应用程序，并且您将部署到**AWS**和**Heroku**等云中。一旦您完成本书，您需要您的项目达到生产级别。因此，通过尽可能简化 Bootstrap，您仍然可以构建一个外观出色的 Django Web 应用程序。

有许多种方法可以根据排列和组合来布置您的网页。为了帮助您了解这一点，我们将看一些例子。

**线框**是 Web 开发的第一步，这意味着它必须处理页面上内容的位置。如果您已经了解了 Web 设计的基础知识，那么这一部分对您来说将更有意义。如果没有，请先阅读一些内容，以对 Web 开发有一个基本的了解。查找`div`和`span`之间的区别，然后一切都会对您有意义。您可以从这里了解更多信息：[`developer.mozilla.org/en-US/Learn/HTML`](https://developer.mozilla.org/en-US/Learn/HTML)。Bootstrap 基本页面线框分为行和列；每列进一步分为 12 个部分。通过这些子部分，您可以使用排列来设计您的布局。

当我们从开发人员的角度看网站时，我们注意到的第一件事是使用的线框。例如，当您访问[www.facebook.com](http://www.facebook.com)时，您会在页面中央看到您的新闻订阅，左侧是其他重要链接（例如消息、页面和群组的链接）。在右侧，您会看到可以聊天的朋友。

在 Bootstrap 中可以想象相同的布局为 2-8-2。左侧链接的列将是“2 列”，新闻订阅将是“8 列”，聊天部分将是“2 列”。这是一个基本的线框。

### 提示

请记住，总和始终必须为 12，因为 Bootstrap 中的活动流体网格系统是基于 12 列网格原则的，以获得更好和更灵活的布局。

现在，Bootstrap 不仅用于使网页响应式-它还有许多其他组件可以使网页看起来更好，更清洁。

要在 Django 中使用 Bootstrap，有两种方式：

+   **Django 方式**：`pip install django-bootstrap3`

+   **手动方式**：下载 Bootstrap 资源并将其复制到静态位置

### Django 方式

如果您想使用命令安装 Bootstrap，则必须将`settings.py`文件中的`INSTALLED_APPS`变量附加到`bootstrap3`。

以下是使用此方法的简单 HTML 表单的示例 Django 模板：

```py
{% load bootstrap3 %}
{%# simple HTML form #%}
<form action="action_url">
    {% csrf_token %}
    {% bootstrap_form sample_form %}
    {% buttons %}
        <button type="submit" class="btn btn-primary">
            {% bootstrap_icon "heart" %} SUBMIT
        </button>
    {% endbuttons %}
</form>
```

### 提示

要了解更多并进行探索，您可以参考以下链接：

[`django-bootstrap3.readthedocs.org/`](http://django-bootstrap3.readthedocs.org/)

### 手动安装 Bootstrap

这种方法适合初学者，但一旦你有信心，你可以通过遵循命令方法来快捷操作。

在这里，我们将学习项目文件的基本包含，并且其余内容将在即将到来的章节中涵盖。一旦您从在线来源（[`getbootstrap.com`](http://getbootstrap.com)）下载了 Bootstrap，解压后的文件夹结构看起来像这样：

```py
|-- css 
|   |-- bootstrap.css 
|   |-- bootstrap.css.map 
|   |-- bootstrap.min.css 
|   |-- bootstrap-theme.css 
|   |-- bootstrap-theme.css.map 
|   `-- bootstrap-theme.min.css 
|-- fonts 
|   |-- glyphicons-halflings-regular.eot 
|   |-- glyphicons-halflings-regular.svg 
|   |-- glyphicons-halflings-regular.ttf 
|   `-- glyphicons-halflings-regular.woff 
`-- js 
 |-- bootstrap.js 
 `-- bootstrap.min.js 

```

Django 中使用的本地文件约定有两种类型：一种是“静态”，另一种是“媒体”。静态文件指的是项目的资产，如 CSS，JavaScript 等。媒体文件是项目中上传的文件，主要包括图片，用于显示或下载的视频等。

通过将以下行添加到`setting.py`文件中，可以将静态文件添加到您的项目中：

```py
STATICFILES_DIRS = (
    # put absolute path here as string not relative path.
    # forward slash to be used even in windows.
    os.path.join(
        os.path.dirname(__file__),
        'static',
    ),
)
```

现在，您只需要在项目目录中创建一个文件夹，并复制所有 Bootstrap 资源。

# 总结

在本章中，我们准备了开发环境，创建了我们的第一个项目，设置了数据库，并学会了如何启动 Django 开发服务器。我们学习了为我们的 Django 项目编写代码的最佳方式，并了解了默认的 Django 项目结构。我们学习了命名约定，空行的重要性，以及我们应该使用哪种导入风格以及在哪里使用。

我们看到了哪种编辑器和哪种 IDE 更适合基于 Python 和 Django 的 Web 开发。我们学会了如何使用 Git 来保持我们的代码在存储库中更新。我们学习了一些关于 Bootstrap 来进行前端开发。

下一章将带您了解主要的 Django 组件，并帮助开发我们的 Twitter 应用程序的工作原型。这将是一个有趣的章节，有许多新东西要学习，所以请继续阅读！


# 第四章：构建类似 Twitter 的应用程序

在之前的章节中，我们学习了编写代码的更好方法。牢记这些要点，现在是时候开始真正的 Django 项目开发，并了解视图、模型和模板。

本章中每个部分的第一部分将介绍基础知识以及特定主题中的工作原理。这将包括适当的实践、标准方法和重要术语。

每个部分的第二部分将是我们的 mytweets Django 应用程序开发中该概念的应用。第一部分可以被视为主题的章节描述，第二部分可以被视为我们的 Django 项目形式的练习，这将是一个独特的学习体验。

本章涵盖以下主题：

+   关于 Django 术语的说明

+   设置基本模板应用程序

+   创建 Django 项目的模板结构

+   设置应用程序的基本引导

+   创建主页

+   介绍基于类的视图

+   我们的 mytweets 项目的 Django 设置

+   生成用户页面

+   设计初始数据库模式

+   用户注册和账户管理

+   为主页创建模板

# 关于 Django 术语的说明

Django 是一个 MVC 框架。但是，在整个代码中，控制器被称为**视图**，视图被称为**模板**。Django 中的视图是检索和操作数据的组件，而模板是向用户呈现数据的组件。因此，有时称 Django 为**模型模板视图**（**MTV**）框架。这种不同的术语既不改变 Django 是一个 MVC 框架的事实，也不影响应用程序的开发方式，但请记住这些术语，以避免可能的混淆，如果您以前使用过其他 MVC 框架。

您可以将本章视为主要 Django 组件的深入介绍。您将学习如何使用视图创建动态页面，如何使用模型存储和管理数据库中的数据，以及如何使用模板简化页面生成。

在学习这些功能的同时，您将对 Django 组件如何工作和相互交互形成一个坚实的理解。随后的章节将更深入地探讨这些组件，因为我们开发更多功能并将它们添加到我们的应用程序中。

# 设置基本模板应用程序

我们的项目将是一个微博网站，每个用户都将有一个公共页面，其中将显示他们发布的时间轴。

在看到开发服务器的欢迎页面后，首先想到的是如何更改它。要创建我们自己的欢迎页面，我们需要定义一个 URL 形式的应用程序入口点，并告诉 Django 在访问此 URL 时调用特定的 Python 函数。我们将自己编写这个 Python 函数，并让它显示我们自己的欢迎消息。

本节基本上是对我们在上一章中进行的配置的重做，但意图是将所有说明放在一起，以便项目引导需要更少的页面查找。

## 创建虚拟环境

我们将使用以下命令设置 Django 的虚拟环境，以使其正常工作：

```py
$ virtualenv django_env

```

输出如下：

```py
New python executable in django_env/bin/python
Installing setuptools, pip...done.

```

我们现在需要激活虚拟环境并设置所有环境变量，以便所有 Python 安装都将被路由到此环境目录，而不会影响其他设置：

```py
$ source django_env/bin/activate

```

输出如下：

```py
(django_env)ratan@lenovo:~/code$

```

# 安装 Django

虽然您已经安装了 Django，但我们将再次进行安装，因为 Django 将由`virtualenv`管理，其他项目或用户（或您自己）在其他地方工作时不会被搞乱。

```py
$pip install django

```

您可能会收到以下错误：

```py
bad interpreter: No such file or directory

```

如果是这样，请在不带空格的路径中创建您的虚拟环境。很可能，在您创建虚拟环境的位置存在一个包含空格的目录，例如，`/home/ratan/folder name with space$virtualenv django_env`。

如果是这样，请将目录名称更改为以下内容：

`/home/ratan/folder_name_with_no_space$virtualenv django_env`

我们可以使用命令`pip install django`继续进行 Django 安装。

输出将如下所示：

```py
Downloading/unpacking django
Downloading Django-1.6.5-py2.py3-none-any.whl (6.7MB): 6.7MB downloaded
Installing collected packages: django
Successfully installed django
Cleaning up...

```

现在，在我们开始创建 Django 应用程序之前，我们将确保 Git 已安装。使用以下命令查找我们安装的 Git 版本：

```py
$git --version

```

输出将如下所示：

```py
git version 1.9.1

```

这证实了我们已安装了 Git。当然，你一定想知道我们是否会在这个项目中使用版本控制。答案是肯定的：随着项目的进行，我们将对大部分项目文件进行版本控制。

## 创建 Django 项目的模板结构

在本节中，我们将为项目创建结构，例如，为我们的项目创建一个名为`mytweets`的文件夹，安装所需的包等。运行以下命令：

```py
$django-admin.py startproject mytweets

```

这将创建名为`mytweets`的文件夹，我们将使用它作为我们的项目目录。在当前文件夹中，我们看到两个子文件夹：`environment`和`mytweets`。现在的问题是我们是否要对我们的环境文件夹进行版本控制。我们不会，因为这些文件非常特定于您当前的系统。它们不会帮助任何人设置与我们相同的环境。然而，在 Python 中还有另一种方法：使用`pip freeze`命令。这实际上会拍摄您的 Django 应用程序中当前安装的所有库的快照，然后您可以将该列表保存在文本文件中并进行版本控制。因此，您的同事开发人员可以下载相同版本的库。这真的是一种 Pythonic 的做法，不是吗？

您安装新包的最常见方法是使用`pip`命令。`pip install`命令有三个版本，如下所示：

```py
$ pip install PackageName

```

这是默认设置，并安装包的最新版本：

```py
$ pip install PackageName==1.0.4

```

使用`==`参数，您可以安装特定版本的包。在这种情况下，即 1.0.4。使用以下命令安装带有版本号的包：

```py
$ pip install 'PackageName>=1.0.4' # minimum version

```

当您不确定要安装的包版本但有一个想法需要库的最低版本时，请使用上述命令。

使用`pip`命令安装库非常容易。您只需在命令行中输入以下内容即可：

```py
$pip install -r requirements.txt

```

现在我们需要冻结当前项目的库：

```py
$pip freeze > requirements.txt

```

此命令会冻结项目中当前安装的库以及版本号（如果指定），并将它们存储在名为`requirements.txt`的文件中。

在我们项目的这个阶段，`pip freeze`命令将看起来像这样。

```py
Django==1.6.5
argparse==1.2.1
wsgiref==0.1.2
```

要将这些库与项目一起安装回您的新环境中，我们可以运行以下命令：

```py
$pip install -r requirements.txt

```

因此，我们可以继续初始化我们的代码目录作为 Git 仓库，并将当前路径更改为`$cd mytweets`。执行以下命令在项目文件夹中构建 Git 仓库：

```py
$git init

```

输出将如下所示：

```py
Initialized empty Git repository in /home/ratan/code/mytweets/.git/

```

如果我们在基于 Linux 的系统上运行所有命令以获取详细的目录列表，我们可以看到以下输出：

```py
...
drwxrwxr-x 7 ratan ratan 4096 Aug 2 16:07 .git/
...
```

这是`.git`文件夹，根据其命名约定（以点开头），它在目录的正常列表中是隐藏的，即存储所有 Git 相关文件（如分支、提交、日志等）的目录。删除该特定目录将使您的目录无 Git（无版本控制）并且与您当前系统中的任何其他目录一样正常。

我们可以使用以下命令将当前目录中的所有文件添加到暂存区：

```py
$git add .

```

使用以下命令进行项目的第一次提交：

```py
$git commit -m "initial commit of the project."

```

输出将如下所示：

```py
[master (root-commit) 597b6ec] initial commit of the project.
5 files changed, 118 insertions(+)
create mode 100755 manage.py
create mode 100644 mytweets/__init__.py
create mode 100644 mytweets/settings.py
create mode 100644 mytweets/urls.py
create mode 100644 mytweets/wsgi.py
```

第一行（这里是主分支）表示我们在主分支中，接下来的是被提交的文件。

到目前为止，我们已经设置了基本的 Django 模板并将其添加到了版本控制中。可以使用以下命令验证相同的事情：

```py
$git log

```

输出将如下所示：

```py
commit 597b6ec86c54584a758f482aa5a0f5781ff4b682
Author: ratan <mail@ratankumar.org>
Date: Sat Aug 2 16:50:37 2014 +0530
initial commit of the project.

```

有关设置作者和为远程存储库推送生成`SSH`密钥的说明，请参阅以下链接：

[`help.github.com/articles/set-up-git`](https://help.github.com/articles/set-up-git)

[`help.github.com/articles/generating-ssh-keys`](https://help.github.com/articles/generating-ssh-keys)

# 为应用程序设置基本的 Twitter Bootstrap

如前一章介绍的，bootstrap 是用户界面设计的基本框架。我们将继续使用前面提到的第二种方法，即手动下载 bootstrap 文件并将其链接到静态文件夹中。

我们跳过的方法意味着我们不会执行以下命令：

```py
$pip install django-bootstrap3

```

有关此实现的详细文档，请参阅[`django-bootstrap3.readthedocs.org/`](http://django-bootstrap3.readthedocs.org/)。

我们将要遵循的方法是下载 bootstrap 文件并将其放置在项目的静态文件夹中。

要开始使用 bootstrap，我们必须从以下官方 bootstrap 网址下载静态文件：

[`getbootstrap.com/`](http://getbootstrap.com/)

当您访问此链接时，您将找到一个下载按钮。单击**下载**，然后单击**下载 Bootstrap**。这将以压缩格式提供 bootstrap 资源文件。下载的文件将具有类似`bootstrap-3.2.0-dist.zip`的名称。解压此 zip 文件的内容。解压后，文件夹`bootstrap-3.2.0-dist`的结构如下：

```py
|-- css
| |-- bootstrap.css
| |-- bootstrap.css.map
| |-- bootstrap.min.css
| |-- bootstrap-theme.css
| |-- bootstrap-theme.css.map
| |-- bootstrap-theme.min.css
|-- fonts
| |-- glyphicons-halflings-regular.eot
| |-- glyphicons-halflings-regular.svg
| |-- glyphicons-halflings-regular.ttf
| |-- glyphicons-halflings-regular.woff
|-- js
|-- bootstrap.js
|-- bootstrap.min.js
```

特定于应用程序的静态文件存储在应用程序的`static`子目录中。

Django 还会查找`STATICFILES_DIRS`设置中列出的任何目录。让我们更新项目设置，指定`settings.py`文件中的静态文件目录。

我们可以更新项目的`setting.py`文件如下以使用 Twitter bootstrap：

```py
STATICFILES_DIRS = (
os.path.join(
os.path.dirname(__file__),
'static',
),
)
```

这里，`static`变量将是我们将保存 bootstrap 文件的文件夹。我们将在当前项目目录内创建`static`文件夹，并将所有解压缩的 bootstrap 文件复制到该文件夹中。

出于开发目的，我们将保持大多数设置不变，例如默认数据库 SQLite；稍后在部署测试应用程序到 MySQL 或我们选择的任何其他数据库时，我们可以将其移动。

在我们实际在项目中使用 bootstrap 之前，我们必须了解一些基本概念，以理解 bootstrap 作为前端框架。

Bootstrap 基于网格系统设计网页，该网格有三个主要组件，如下：

+   **容器**：容器用于为整个网页提供基础，通常，bootstrap 的所有组件将是容器的直接或嵌套子对象。换句话说，容器为响应式宽度提供宽度约束。当屏幕分辨率更改时，容器会在设备屏幕上改变其宽度。行和列是基于百分比的，因此它们会自动修改。

容器还为内容提供了来自浏览器边缘的填充，以便它们不会触及视图区域的边缘。默认填充为 15 像素。您永远不需要在容器内部放置另一个容器。以下图片显示了容器的结构：

![为应用程序设置基本的 Twitter Bootstrap](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00284.jpeg)

+   **行**：行放置在容器内并包含列。Bootstrap 的基本设计层次结构是`容器` | `行` | `列`。行也像列的包装器一样，因此在列由于默认的左浮动属性而变得奇怪的情况下，保持它们分开分组，以便这个问题不会反映在行外部。

行两侧有 15 像素的负边距，这将它们推出容器的 15 像素填充之上。因此，它们被否定，行与容器的边缘相接触，负边距被填充所覆盖。因此，行不会受到容器填充的推动。永远不要在容器外使用行。

![为应用程序设置基本的 Twitter Bootstrap](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00285.jpeg)

+   **列**：列有 15 像素的填充。这意味着列实际上与行的边缘相接触，行已经与容器的边缘相接触，因为在前一段讨论的容器的否定属性。

列再次有 15 像素的填充，因此列的内容与容器的视图边缘相距 15 像素。

因此，我们不需要特殊的第一列和最后一列，左右都有填充。现在所有列之间都有一个一致的 15 像素间隙。

列内的内容被推送到列的位置，并且它们之间也被 30 像素的间距分隔。我们可以在列内部使用行进行嵌套布局。

![为应用程序设置基本的 Twitter Bootstrap](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00286.jpeg)

永远不要在行外使用列。

牢记这些要点，我们可以继续设计我们的第一个布局。

# URL 和视图 - 创建主页

在 Django 术语中，视图是一个普通的 Python 函数，通过生成相应的页面来响应页面请求。要为主页编写我们的第一个 Django 视图，我们首先需要在项目内创建一个 Django 应用程序。您可以将应用程序视为视图和数据模型的容器。要创建它，请在我们的`django_mytweets`文件夹内发出以下命令：

```py
$ python manage.py startapp tweets

```

应用程序创建的语法与项目创建的语法非常相似。我们使用`startapp`命令作为`python manage.py`命令的第一个参数，并提供`tweets`作为我们应用程序的名称。

运行此命令后，Django 将在项目文件夹内创建一个名为`tweets`的文件夹，其中包含这三个文件：

+   `__init__.py`：这个文件告诉 Python`tweets`是一个 Python 包

+   `views.py`：这个文件将包含我们的视图

+   `models.py`：这个文件将包含我们的数据模型

现在让我们创建主页视图。我们将首先在项目内创建一个`template`文件夹，以保存所有 HTML 文件：

```py
$mkdir templates

```

现在在其中创建一个名为`base.html`的基本 HTML 文件，内容如下：

```py
{% load staticfiles %}
<html>
<head>
<link href="{% static 'bootstrap/css/bootstrap.min.css' %}"
rel="stylesheet" media="screen" />">
</head>

<body>
{% block content %}
<h1 class="text-info">">HELLO DJANGO!</h1>
{% endblock %}

<script src="img/bootstrap.min.js' %}"></script>
</body>
</html>
```

我们的目录结构现在看起来像这样（如果您使用 Linux 操作系统，请使用`tree`命令）：

```py
mytweets/
|-- manage.py
|-- mytweets
| |-- __init__.py
| |-- __init__.pyc
| |-- settings.py
| |-- settings.pyc
| |-- urls.py
| |-- urls.pyc
| |-- wsgi.py
| `-- wsgi.pyc
|-- static
| |-- css
| | |-- bootstrap.css
| | |-- bootstrap.css.map
| | |-- bootstrap.min.css
| | |-- bootstrap-theme.css
| | |-- bootstrap-theme.css.map
| | `-- bootstrap-theme.min.css
| |-- fonts
| | |-- glyphicons-halflings-regular.eot
| | |-- glyphicons-halflings-regular.svg
| | |-- glyphicons-halflings-regular.ttf
| | `-- glyphicons-halflings-regular.woff
| `-- js
| |-- bootstrap.js
| `-- bootstrap.min.js
|-- templates
| `-- base.html
`-- tweets
|-- admin.py
|-- __init__.py
|-- models.py
|-- tests.py
`-- views.py
```

# 介绍基于类的视图

基于类的视图是在 Django 中定义视图的新方法。它们不取代基于函数的视图。它们只是一种以 Python 对象而不是函数实现视图的替代方法。它们有两个优点，优于基于函数的视图。使用基于类的视图，不同的 HTTP 请求可以映射到不同的函数，而不是基于`request.method`参数进行分支的函数视图。可以使用面向对象的技术来重用代码组件，例如**混入**（多重继承）。

虽然我们将在项目中使用基于类的视图，但为了了解两者之间的确切区别，我们将在这里呈现两者的代码。

我们将不得不更新我们项目的`url.py`文件，以便在用户请求网站时提供`base.html`文件。

**基于函数的视图**：

按照以下方式更新`view.py`文件：

```py
from django.http import HttpResponse

def index(request):
if request.method == 'GET': 
return HttpResponse('I am called from a get Request')
elif request.method == 'POST':
return HttpResponse('I am called from a post Request')
```

按照以下方式更新`urls.py`文件：

```py
from django.conf.urls import patterns, include, url
from django.contrib import admin
from tweets import views
admin.autodiscover()

urlpatterns = patterns('',
url(r'^$', views.index, name='index'),
url(r'^admin/', include(admin.site.urls)),
)
```

使用以下命令运行开发服务器：

```py
$python manage.py runserver

```

我们将看到一个响应，显示**我是从 get 请求中调用的**。

**基于类的视图**：

更新`views.py`文件如下：

```py
from django.http import HttpResponse
from django.views.generic import View

class Index(ViewV iew):
def get(self, request): 
return HttpResponse('I am called from a get Request')
def post(self, request): 
return HttpResponse('I am called from a post Request')

urls.py
from django.conf.urls import patterns, include, url
from django.contrib import admin
from tweets.views import Index
admin.autodiscover()

urlpatterns = patterns('',
url(r'^$', Index.as_view()),
url(r'^admin/', include(admin.site.urls)),
)
```

在开发服务器被访问后，它也会在浏览器上生成相同的结果。我们将在整个项目中使用基于类的视图。

我们所呈现的只是一个字符串，这有点简单。我们在模板文件夹中创建了一个`base.html`文件，现在将继续使用我们的基于类的视图并呈现我们的`base.html`文件。

在 Django 中，有多种方法可以呈现我们的页面。我们可以使用这三个函数中的任何一个来呈现我们的页面：`render()`，`render_to_response()`或`direct_to_template()`。但是，让我们首先看看它们之间的区别以及我们应该使用哪一个：

+   `render_to_response(template[, dictionary][, context_instance][, mimetype])`：`render_to_response`命令是标准的呈现函数，要使用`RequestContext`，我们必须指定`context_instance=RequestContext(request)`。

+   `render(request, template[, dictionary][, context_instance][, content_type][, status][, current_app])`。这是`render_to_response`命令的新快捷方式，从 Django 的 1.3 版本开始可用。这将自动使用`RequestContext`。

+   `direct_to_template()`: 这是一个通用视图。它自动使用`RequestContext`和所有它的`context_processor`参数。

但是，应该避免使用`direct_to_template`命令，因为基于函数的通用视图已被弃用。

我们将选择第二个，`render()`函数，来呈现我们的`base.html`模板。

下一步是在我们的 Django 应用程序中包含模板文件夹（我们已经创建的带有名为`base.html`的基本文件的模板文件夹）。为了包含模板，我们将以以下方式更新`settings.py`文件：

```py
TEMPLATE_DIRS = (
BASE_DIR + '/templates/'
)
TEMPLATE_LOADERS = (
'django.template.loaders.filesystem.Loader',
'django.template.loaders.app_directories.Loader', 
)
```

这定义了模板目录并初始化了基本的`TEMPLATE_LOADER`参数。

# mytweets 项目的 Django 设置

让我们使用我们`mytweets`项目所需的最小设置更新`settings.py`文件。在启动我们的 mytweets 应用程序之前，我们将添加许多设置，我们将在以下更改中看到。有关此文件的更多信息，请访问[`docs.djangoproject.com/en/1.6/topics/settings/`](https://docs.djangoproject.com/en/1.6/topics/settings/)。

有关设置及其值的完整列表，请访问[`docs.djangoproject.com/en/1.6/ref/settings/`](https://docs.djangoproject.com/en/1.6/ref/settings/)。

使用以下内容更新我们项目的`settings.py`文件：

```py
# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import os
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.6/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'XXXXXXXXXXXXXXXXXXXXXXXXXX'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True
TEMPLATE_DEBUG = True
ALLOWED_HOSTS = []

# Application definition
INSTALLED_APPS = (
'django.contrib.admin',
'django.contrib.auth',
'django.contrib.contenttypes',
'django.contrib.sessions',
'django.contrib.messages',
'django.contrib.staticfiles',
)

MIDDLEWARE_CLASSES = (
'django.contrib.sessions.middleware.SessionMiddleware',
'django.middleware.common.CommonMiddleware',
'django.middleware.csrf.CsrfViewMiddleware',
'django.contrib.auth.middleware.AuthenticationMiddleware',
'django.contrib.messages.middleware.MessageMiddleware',
'django.middleware.clickjacking.XFrameOptionsMiddleware',
)

ROOT_URLCONF = 'mytweets.urls'
WSGI_APPLICATION = 'mytweets.wsgi.application'

# Database
# https://docs.djangoproject.com/en/1.6/ref/settings/#databases

DATABASES = {
'default': {
'ENGINE': 'django.db.backends.sqlite3',
'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
}
}

#static file directory inclusion
STATICFILES_DIRS = ( 
os.path.join(
os.path.dirname(__file__),
'static',
),
)

TEMPLATE_DIRS = (
BASE_DIR + '/templates/'
)

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
'django.template.loaders.filesystem.Loader',
'django.template.loaders.app_directories.Loader',
# 'django.template.loaders.eggs.Loader',
)

# Internationalization
# https://docs.djangoproject.com/en/1.6/topics/i18n/

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.6/howto/static-files/

STATIC_URL = '/static/'
```

现在，如果我们启动开发服务器，我们的屏幕将如下截图所示：

![mytweets 项目的 Django 设置](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00287.jpeg)

### 注意

在我们的`base.html`文件中，我们写了`class="h1"`而不是`<h1></h1>`。这是故意为了在运行时检查是否加载了引导文件，即`Header 1`属性。

正如您可能已经注意到的，我们没有向模板传递任何变量，这大致区分了静态页面和动态页面。让我们继续做这个。我们只需要对`views.py`和`base.html`文件进行一些更改，如下所示：

+   `views.py`文件中的更改：

```py
from django.views.generic import View
from django.shortcuts import render 
class Index(View):
def get(self, request): 
params = {}
params["name"] = "Django"
return render(request, 'base.html', params)
```

+   `base.html`文件中的更改

```py
{% load staticfiles %}
<html>
<head>
<link href="{% static 'bootstrap/css/bootstrap.min.css' %}"
rel="stylesheet" media="screen">
</head>

<body>
{% block content %}
<h1>Hello {{name}}!</h1>
{% endblock %}

<script src="img/bootstrap.min.js' %}"></script>
</body>
</html>
```

我们可以看到它有多简单。我们所做的只是创建一个映射（在 Python 中称为**字典**）并将`name`属性分配给它作为 Django，并将其添加到`render()`函数中作为新参数。它被呈现到 HTML 的基础上，并且可以轻松地调用`{{name}}`。当它被呈现时，它会用 Django 替换自己。

我们将提交我们到目前为止所做的所有更改。在这之前，让我们创建一个`.gitignore`文件。它的作用是，无论这个文件中有什么内容（或者我们在`.gitignore`文件中写入的文件的通配符），它都会阻止所有这些内容提交，并将它们发送到存储库服务器。

它如何帮助？它在许多重要的用例中都有帮助。假设我们不想将任何本地配置文件放到生产服务器上。在这种情况下，`.gitignore`文件可以成为救世主，也可以在`.py`文件生成它们的`.pyc`文件时使用，这些文件在运行时被编译。我们不需要在服务器上存储这些二进制文件，因为它们每次代码更改时都会单独生成。

在 Linux 命令行中，只需在项目目录的根文件夹中键入`$vim .gitignore`命令，然后写入`*.pyc`。然后，以通常的方式保存并退出。

现在，如果我们执行`$git status`命令，我们将看不到任何扩展名为`.pyc`的文件，这意味着 Git 已经忽略了以`.pyc`结尾的文件进行跟踪。

`$git status`命令的结果如下：

```py
Changes not staged for commit:
(use "git add <file>..." to update what will be committed)
(use "git checkout -- <file>..." to discard changes in working directory)

modified: mytweets/settings.py
modified: mytweets/urls.py

Untracked files:
(use "git add <file>..." to include in what will be committed)

.gitignore
static/
templates/
tweets/
```

这是相当清楚的，正如应该的。我们之前已经提交了`settings.py`和`urls.py`文件，现在我们对它们进行了一些更改，而提到的未跟踪文件甚至没有被添加到 Git 进行跟踪。

我们可以使用`git add .`命令将所有更改添加到目录中。但是，为了避免将任何不需要的文件推送到 Git 跟踪，建议在开发的高级阶段逐个添加文件。对于当前的情况，一次性添加文件是可以的。要将所需的文件添加到我们的项目中，请使用以下命令：

```py
$git add .

```

输出将如下所示：

```py
On branch master
Changes to be committed:
(use "git reset HEAD <file>..." to unstage)

new file: .gitignore
modified: mytweets/settings.py
modified: mytweets/urls.py
new file: static/css/bootstrap-theme.css
new file: static/css/bootstrap-theme.css.map
new file: static/css/bootstrap-theme.min.css
new file: static/css/bootstrap.css
new file: static/css/bootstrap.css.map
new file: static/css/bootstrap.min.css
new file: static/fonts/glyphicons-halflings-regular.eot
new file: static/fonts/glyphicons-halflings-regular.svg
new file: static/fonts/glyphicons-halflings-regular.ttf
new file: static/fonts/glyphicons-halflings-regular.woff
new file: static/js/bootstrap.js
new file: static/js/bootstrap.min.js
new file: templates/base.html
new file: tweets/__init__.py
new file: tweets/admin.py
new file: tweets/models.py
new file: tweets/tests.py
new file: tweets/views.py

```

提交更改并附上适当的消息，比如“*添加基本的引导模板*”：

```py
$git commit -m "basic bootstap template added"

```

输出将如下所示：

```py
[master 195230b] basic bootstap template added
21 files changed, 9062 insertions(+), 1 deletion(-)
create mode 100644 .gitignore
create mode 100644 static/css/bootstrap-theme.css
create mode 100644 static/css/bootstrap-theme.css.map
create mode 100644 static/css/bootstrap-theme.min.css
create mode 100644 static/css/bootstrap.css
create mode 100644 static/css/bootstrap.css.map
create mode 100644 static/css/bootstrap.min.css
create mode 100644 static/fonts/glyphicons-halflings-regular.eot
create mode 100644 static/fonts/glyphicons-halflings-regular.svg
create mode 100644 static/fonts/glyphicons-halflings-regular.ttf
create mode 100644 static/fonts/glyphicons-halflings-regular.woff
create mode 100644 static/js/bootstrap.js
create mode 100644 static/js/bootstrap.min.js
create mode 100644 templates/base.html
create mode 100644 tweets/__init__.py
create mode 100644 tweets/admin.py
create mode 100644 tweets/models.py
create mode 100644 tweets/tests.py
create mode 100644 tweets/views.py

```

# 将所有内容放在一起 - 生成用户页面

到目前为止，我们已经涵盖了很多材料，比如介绍了视图和模板的概念。在最后一节中，我们将编写另一个视图，并利用到目前为止学到的所有信息。这个视图将显示属于某个用户的所有推文的列表。

## 熟悉 Django 模型

模型是标准的 Python 类，具有一些附加功能。它们是`django.db.models.Model`的子类。在后台，**对象关系映射器**（**ORM**）与这些类及其对象绑定在一起。这使它们与底层数据库进行通信。ORM 是 Django 的一个重要特性，没有它，我们将不得不编写自己的查询（如果是 MySQL，则为 SQL）来访问数据库内容。模型的每个属性都由数据库字段表示。没有字段，模型将只是一个空容器，毫无意义。

以下是 Django 的模型属性及其预期用途的解释。完整的字段列表可以在[`docs.djangoproject.com/en/dev/ref/models/fields/`](https://docs.djangoproject.com/en/dev/ref/models/fields/)的标准文档中找到。

以下是这些类型的部分表：

| 字段类型 | 描述 |
| --- | --- |
| `IntegerField` | 一个整数 |
| `TextField` | 一个大文本字段 |
| `DateTimeField` | 一个日期和时间字段 |
| `EmailField` | 一个最大长度为 75 个字符的电子邮件字段 |
| `URLField` | 一个最大长度为 200 个字符的 URL 字段 |
| `FileField` | 一个文件上传字段 |

每个模型字段都带有一组特定于字段的参数。例如，如果我们想要一个字段是`CharField`字段，我们必须将其`max_length`参数作为其参数传递，该参数映射到数据库中`varchar`的字段大小。

以下是可以应用于所有字段类型的参数（它们是可选的）：

+   `null`：默认情况下，它设置为`false`。当设置为`true`时，允许将`null`的关联字段的值存储在数据库中。

+   `blank`：默认情况下，它设置为`false`。当设置为`true`时，允许将`blank`的关联字段的值存储在数据库中。

### 注意

`null`和`blank`参数之间的区别在于，`null`参数主要与数据库相关，而`blank`参数用于验证字段。换句话说，如果属性设置为`false`，则属性的空值（`blank`）将不会被保存。

+   `choices`：这可以是一个列表或元组，并且必须是可迭代的。如果这是一个元组，第一个元素是将存储到数据库中的值，第二个值用于在小部件形式或`ModelChoiceField`中显示。

例如：

```py
USER_ROLE = ( 
('U', 'USER'), 
('S', 'STAFF'), 
('A', 'ADMIN')
)
user_role = models.CharField(max_length=1, choices=USER_ROLE)
```

+   `default`：每次实例化类的对象时分配给属性的值。

+   `help_text`：以小部件形式显示的帮助文本。

+   `primary_key`：如果设置为`True`，则该字段将成为模型的主键。如果模型中没有主键，Django 将创建一个整数字段并将其标记为主键。

## 模型中的关系

有三种主要类型的关系：多对一，多对多和一对一。

### 多对一关系

在 Django 中，`django.db.models.ForeignKey`参数用于将一个模型定义为另一个模型属性的外键，从而产生多对多的关系。

它被用作模型类的任何其他属性，包括它所在的类。例如，如果学生在特定学校学习，那么学校有很多学生，但学生只去一个学校，这是一个多对一的关系。让我们看一下以下代码片段：

```py
from django.db import models
class School(models.Model):
# ...
ass
class Student(models.Model):
school = models.ForeignKey(School)
# …
```

### 一对一关系

一对一关系与多对一关系非常相似。唯一的区别是，反向映射在一对一关系的情况下会导致单个对象，而不是多对一关系。

例如：

```py
class EntryDetail(models.Model):
entry = models.OneToOneField(Entry)
details = models.TextField()
```

在前面的示例中，`EntryDetail()`类有一个名为`entry`的属性，它与`Entry`模型一对一映射。这意味着每个`Entry`对象都映射到`EntryDetail`模型。

### 多对多关系

正如名称本身所示，具有多对多关系的模型属性提供对其指向的两个模型的访问（例如向后的一对多关系）。属性命名是这两种关系之间唯一的重要区别。

如果我们通过以下示例来说明，这将更清楚：

```py
class Product(models.Model):
name = models.CharField(_(u"Name"), max_length=50)
class Category(models.Model):
name = models.CharField(_(u"Name"), max_length=50)
products = models.ManyToManyField("Product", blank=True, null=True)
```

有了属性和主要关系的想法，我们现在可以直接创建我们的项目模型，在接下来的部分中我们将很快做到这一点。

如果我们要为应用程序设计模型，如果模型太多，我们应该拆分应用程序。如果我们的应用程序中有超过大约 15 个模型，我们应该考虑如何将我们的应用程序拆分成更小的应用程序。这是因为，对于现有的 15 个模型应用程序，我们可能正在做太多事情。这与 Django 的哲学不符，即*应用程序应该只做一件事，并且做得正确*。

# 模型-设计初始数据库模式

回到我们的项目，我们在初始阶段将需要两个模型：`user`模型和`tweet`模型。`user`模型将用于存储在我们的项目中拥有帐户的用户的基本用户详细信息。

接下来是`tweet`模型，它将存储与推文相关的数据，例如推文文本，创建该推文的用户，以及推文发布的时间戳等其他重要细节。

要列出用户的推文，最好是创建一个专门针对项目中所有用户的用户应用程序。我们的用户模型将通过扩展 Django 的`AbstractBaseUser`用户模型类来创建。

### 注意

永远不建议更改 Django 源树中的实际`user`类和/或复制和修改`auth`模块。

这将是使用框架进行 Web 开发的第一个应用程序，而不是自己编写整个身份验证，这对所有 Web 开发场景都是非常普遍的。Django 带有预定义的库，因此我们不必重新发明轮子。它同时提供了认证和授权，并称为认证系统。

## Django 的用户对象

Django 1.5 附带了一个可配置的用户模型，这是在应用程序中存储特定于用户的数据的更简单的方法。

我们将创建一个用户应用程序，然后将 Django 的默认用户模型导入其中：

```py
$python manage.py startapp user_profile

```

我们将根据当前项目的需要扩展 Django 用户模型，通过创建一个继承自`AbstractBaseUser`类的自定义`User()`类。因此，我们的`models.py`文件将如下所示：

```py
from django.db import models
from django.contrib.auth.models import AbstractBaseUser

class User(AbstractBaseUser):

Custom user class.
```

现在我们已经为项目创建了自定义的`user`类，我们可以向这个`user`类添加所有我们希望在用户模型中的基本属性。

现在`models.py`看起来是这样的：

```py
from django.db import models
from django.contrib.auth.models import AbstractBaseUser

class User(AbstractBaseUser):

Custom user class.

username = models.CharField('username', max_length=10, unique=True, db_index=True)
email = models.EmailField('email address', unique=True)
joined = models.DateTimeField(auto_now_add=True)
is_active = models.BooleanField(default=True)
is_admin = models.BooleanField(default=False)
```

在上述代码片段中，自定义用户模型`email`字段具有一个设置为`True`的`unique`属性。这意味着用户只能使用给定的电子邮件地址注册一次，验证可以在注册页面上完成。您还将在`username`属性中看到一个`db_index`选项，其值为`True`，这将在`username`属性上为用户表建立索引。

`joined`是`dateTimeField`参数，当创建新用户配置文件时会自动填充；当创建新用户帐户时，默认情况下`is_active`字段设置为`True`，同时`is_admin`字段初始化为`False`。

还需要一个字段，使其几乎与默认的 Django 用户模型相同，即`username`字段。

在`models.py`文件中添加`USERNAME_FIELD`字段如下：

```py
USERNAME_FIELD = 'username' 
def __unicode__(self):
return self.username
```

`USERNAME_FIELD`也作为 Django 中用户模型的唯一标识符。我们已经将我们的`username`参数映射到 Django 的`username`字段。这个字段在定义时必须是唯一的（`unique=True`），而我们的`username`字段已经是唯一的。

`__unicode__()`方法也被添加为显示用户模型对象的人类可读表示的定义。

因此，最终的`models.py`文件将如下所示：

```py
from django.db import models
from django.contrib.auth.models import AbstractBaseUser

class User(AbstractBaseUser):
"""
Custom user class.
"""
username = models.CharField( 'username', max_length=10, unique=True, db_index=True)
email = models.EmailField('email address', unique=True)
joined = models.DateTimeField(auto_now_add=True)
is_active = models.BooleanField(default=True)
is_admin = models.BooleanField(default=False)

USERNAME_FIELD = 'username'
def __unicode__(self):
return self.username
```

现在，在定义了我们的用户模型之后，我们可以继续设计推文模型。这是我们创建的同一个应用程序，用于查看基本的基于类的视图。我们将向其`models.py`文件添加内容，如下所示：

```py
from django.db import models
from user_profile import User
class Tweet(models.Model):
"""
Tweet model
"""
user = models.ForeignKey(User)
text = models.CharField(max_length=160)
created_date = models.DateTimeField(auto_now_add=True)
country = models.CharField(max_length=30)
is_active = models.BooleanField(default=True)
```

推文模型的设计尽可能简单，`attribute`参数是对我们已经创建的`User`对象的外键。`text`属性是推文内容，它将主要由纯文本组成。`created_Date`属性是在未初始化`tweet`对象时自动添加到数据库中的，它存储了实际发布推文的国家名称。在大多数情况下，它将与用户的国家相同。`is_active`标志用于表示推文的当前状态，即它是否处于活动状态并且可以显示，或者已被用户删除。

我们需要在数据库中为我们刚刚创建的两个模型`user_profile`和`tweet`创建表。我们将不得不更新项目的`settings.py`文件中的`INSTALLED_APPS`变量，以告诉 Django 在 Django 项目中包括这两个应用程序。

我们更新后的`INSTALLED_APPS`变量将如下所示：

```py
INSTALLED_APPS = (
'django.contrib.admin',
'django.contrib.auth',
'django.contrib.contenttypes',
'django.contrib.sessions',
'django.contrib.messages',
'django.contrib.staticfiles',
'user_profile',
'tweet'
)
```

您可以看到我们添加的最后两个条目以添加我们的模型。

现在，为了为我们的项目创建数据库表，我们将在终端中从根项目文件夹运行以下命令：

```py
$python manage.py syncdb

```

输出将如下所示：

```py
Creating tables ...
Creating table django_admin_log
Creating table auth_permission
Creating table auth_group_permissions
Creating table auth_group
Creating table auth_user_groups
Creating table auth_user_user_permissions
Creating table auth_user
Creating table django_content_type
Creating table django_session
Creating table user_profile_user
Creating table tweet_tweet
```

您刚刚安装了 Django 的 auth 系统，这意味着您没有定义任何超级用户。您可以在终端上看到以下内容：

```py
Would you like to create one now? (yes/no): yes
Username (leave blank to use 'ratan'):
Email address: mail@ratankumar.org
Password: XXXX
Password (again): XXXX
Superuser created successfully.
Installing custom SQL ...
Installing indexes ...
Installed 0 object(s) from 0 fixture(s)
```

因此，我们的数据库已填充了一个表。我们的项目中将出现一个名为`db.sqlite3`的数据库文件。

与 Django 1.6 一样，默认情况下会出现管理员面板。我们的模型要在 Django 的管理面板中可用，只需为两个应用程序的模型名称添加`admin.site.register`参数作为参数。

因此，在`admin.py`文件中添加`admin.site.register(parameter)`到`mytweets`和`user_profile`文件下将如下所示：

+   `tweet`应用程序的`admin.py`文件如下所示：

```py
from django.contrib import admin
from models import Tweet

admin.site.register(Tweet)
```

+   `user_profile`应用程序的`admin.py`文件如下所示：

```py
from django.contrib import admin
from models import User
admin.site.register(User)
```

使用以下命令启动服务器：

```py
$python manage.py runserver

```

然后访问 URL`http://127.0.0.1:8000/admin`；它会要求登录信息。您可能还记得，我们在运行`$python manage.py syncdb`命令时创建了默认用户；使用相同的用户名和密码。

成功登录后，管理面板看起来像以下截图：

![Django 的用户对象](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00288.jpeg)

让我们在管理面板中玩耍，并创建一个我们将在首页视图中使用的`user`和`tweet`对象。要向项目添加新用户，只需点击用户模型框前面的**添加**按钮，如下截图所示：

![Django 的用户对象](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00289.jpeg)

然后填写详细信息并保存。您将看到如下截图中显示的**"用户创建成功"**消息：

![Django 的用户对象](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00290.jpeg)

我们将按照类似的流程创建一条推文。首先返回到`http://127.0.0.1:8000/admin/`。然后，在推文框前面点击**添加**按钮。

![Django 的用户对象](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00291.jpeg)

通过填写框并从下拉菜单中选择用户来撰写新推文。由于我们已将用户映射到用户对象，因此此用户列表已经填充。随着我们不断添加用户，下拉菜单将填充所有用户对象。

![Django 的用户对象](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00292.jpeg)

最后，在撰写推文后，点击**保存**按钮。您将看到以下截图中显示的相同屏幕：

![Django 的用户对象](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00293.jpeg)

如果您仔细观察，管理员列表页面会显示每条推文都是一个`tweet`对象，这不太友好。实际上，对于 Django 管理视图中或任何其他地方显示的所有模型基础表示，都适用相同的规则。

在我们的项目的`admin.py`文件中添加以下代码片段：

```py
def __unicode__(self): 
return self.text
```

我们的管理视图现在将显示确切的文本，而不是写入推文对象。

![Django 的用户对象](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00294.jpeg)

## 创建 URL

我们项目中的每个用户都将具有以下格式的唯一 URL 的个人资料：`http://127.0.0.1:8000/user/<username>`。这里，`username`变量是我们想要查看推文的所有者。这个 URL 与我们之前添加的第一个 URL 不同，因为它包含一个动态部分，所以我们必须利用正则表达式的能力来表示这个 URL。打开`urls.py`文件并编辑它，使 URL 表格如下所示：

```py
url(r'^user/(\w+)/$', Profile.as_view()), urls.py
from django.conf.urls import patterns, include, url
from django.contrib import admin
from tweet.views import Index,Profile
admin.autodiscover()

urlpatterns = patterns('',
url(r'^$', Index.as_view()),
url(r'^user/(\w+)/$', Profile.as_view()),
url(r'^admin/', include(admin.site.urls)),
)
```

这里的模式看起来比第一个更复杂。注释`\w`表示字母数字字符或下划线。其后的`+`符号会导致正则表达式匹配前面的内容的一个或多个重复。因此，实际上，`\w+`表示由字母数字字符和可能的下划线组成的任何字符串。我们用括号括起了正则表达式的这部分。这将导致 Django 捕获与这部分匹配的字符串并将其传递给视图。

在我们看到视图生效之前，还有一件事需要解释。如果您以前没有使用过正则表达式，我们使用的正则表达式看起来可能有点奇怪。这是一个包含两个字符`^`和`$`的原始字符串。注释`r''`是 Python 定义原始字符串的语法。如果 Python 遇到这样的原始字符串，反斜杠和其他转义序列将保留在字符串中，而不会以任何方式解释。在这种语法中，反斜杠保留在字符串中而不会改变，转义序列不会被解释。这在处理正则表达式时非常有用，因为它们经常包含反斜杠。

在正则表达式中，`^`表示字符串的开头，`$`表示字符串的结尾。因此，`^$`基本上表示一个不包含任何内容的字符串，即空字符串。鉴于我们正在编写主页的视图，页面的 URL 是根 URL，确实应该是空的。

`re`模块的 Python 文档详细介绍了正则表达式。如果您想对正则表达式进行彻底的处理，我建议阅读它。您可以在[`docs.python.org/lib/module-re.html`](http://docs.python.org/lib/module-re.html)上找到在线文档。以下是一个总结正则表达式语法的表格，供那些想要快速复习的人使用：

| 符号/表达式 | 匹配的字符串 |
| --- | --- |
| `. (Dot)` | 任何字符 |
| `^ (Caret)` | 字符串的开头 |
| `$` | 字符串的结尾 |
| `*` | 0 次或多次重复 |
| `+` | 1 次或多次重复 |
| `?` | 0 或 1 次重复 |
| `&#124;` | A &#124; B 表示 A 或 B |
| `[a-z]` | 任何小写字符 |
| `\w` | 任何字母数字字符或 _ |
| `\d` | 任何数字 |

我们现在将在我们的推文应用程序的`view.py`文件中创建一个带有`GET`函数的`Profile()`类。这里需要学习的重要事情是`get()`函数如何处理通过 URL 传递的动态参数，即`username`变量。

我们的推文应用程序的`view.py`将如下所示：

```py
class Profile(View):
"""User Profile page reachable from /user/<username> URL"""
def get(self, request, username):
params = dict()()()
user = User.objects.get(username=username)
tweets = Tweet.objects.filter(user=user)
params["tweets"] = tweets
params["user"] = user
return render(request, 'profile.html', params)
```

## 模板 - 为主页创建模板

我们几乎完成了项目的模型创建。现在我们将继续创建视图页面。

我们要创建的第一个页面是基本页面，它将列出用户发布的所有推文。这可以是一个所谓的公共个人资料页面，可以在没有任何身份验证的情况下访问。

正如你可能已经注意到的，我们在`views.py`文件的`Profile`类中使用了`profile.html`文件，它属于我们的推文应用程序。

我们项目的`views.py`文件将如下所示：

```py
class Profile(View):
"""User Profile page reachable from /user/<username> URL"""
def get(self, request, username):
params = dict()
user = User.objects.get(username=username)
tweets = Tweet.objects.filter(user=user)
params["tweets"] = tweets
params["user"] = user
return render(request, 'profile.html', params)
```

我们将使用已经在我们的`base.html`文件中导入的 Bootstrap 框架来设计`Profile.html`文件。

我们将首先重构我们为应用程序创建的`base.html`文件。现在这个`base.html`文件将被用作我们项目的模板或主题。我们将在整个项目中导入此文件，这将导致项目中的用户界面保持一致。

我们将从我们的`base.html`文件中删除我们放在块内容中的`div`标签。

我们还需要 jQuery，这是一个用于完全实现 bootstrap 功能的 JavaScript 库。可以从[`jquery.com/download/`](http://jquery.com/download/)下载。对于我们当前的项目，我们将在生产就绪阶段下载最新版本的 jQuery。我们将在 bootstrap 的 JavaScript 导入之前添加它。

现在`base.html`文件应该是这样的：

```py
{% load staticfiles %}
<html>
<head>
<link href="{% static 'bootstrap/css/bootstrap.min.css' %}"
rel="stylesheet" media="screen">
</head>

<body>
{% block content %}
{% endblock %}

<script src="img/jquery-2.1.1.min.js' %}"></script>
<script src="img/bootstrap.min.js' %}"></script>
</body>
</html>
```

在这种情况下，块如下所示：

```py
{% block content %}
{% endblock %}
```

这意味着，无论我们要扩展哪个模板`base.html`文件，当前在`profile.html`文件中，`profile.html`文件的内容将在这些块引用之间呈现。为了更好地理解这一点，考虑这样做：每个页面都有页眉（在某些情况下是导航栏）和页脚，页面内容根据视图而变化。通过前面的模板，我们通常需要在块内容之前放置页眉代码，并在块内容下方放置页脚内容。

现在使用页眉要容易得多，因为我们有前端框架的优势。我们将首先选择项目的布局。为简单起见，我们将整个页面分为三个部分。第一个将是页眉，随着我们在整个项目中导航，它将是恒定的。同样的情况也适用于页面底部，即我们的页脚。

![模板-为主页创建模板](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00295.jpeg)

为了实现前面的布局，我们的 bootstrap 代码将以这种方式构建：我们将使用 bootstrap 的`navbar`作为页眉部分以及页脚部分。然后我们将放置容器`div`标签。我们的`base.html`文件的更新代码将更改为以下内容：

```py
{% load staticfiles %}
<html>
<head>
<link href="{% static 'css/bootstrap.min.css' %}"
rel="stylesheet" media="screen">
</head>
<body>
<nav class="navbar navbar-default navbar-fixed-top" role="navigation">
<a class="navbar-brand" href="#">MyTweets</a>
<p class="navbar-text navbar-right">User Profile Page</p>
</nav>
<div class="container">
{% block content %}

{% endblock %}
</div>
<nav class="navbar navbar-default navbar-fixed-bottom" role="navigation">
<p class="navbar-text navbar-right">Footer </p>

</nav>
<script src="img/bootstrap.min.js' %}"></script>
</body>
</html>
```

`navbar`参数将在主体中启动，但在容器之前，以便它可以包裹整个容器。我们使用 Django 块内容来呈现我们将在扩展模板中定义的行，在这种情况下是`profile.html`文件。页脚部分最后出现，这是在`endblock`语句之后。

这将呈现以下页面：

![模板-为主页创建模板](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00296.jpeg)

### 提示

请注意，如果您没有包含静态文件，请在您的`settings.py`文件中用以下内容替换`STATICFILES_DIRS`变量：

```py
STATICFILES_DIRS = (
BASE_DIR + '/static/',
)
```

个人资料页面的设计如下：

![模板-为主页创建模板](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00297.jpeg)

这可以很容易地再次设计，借助名为`well`的 bootstrap 组件。`well`或`wellbox`组件与元素一起使用，以产生内嵌效果。`profile.html`文件将只扩展`base.html`文件，并且只包含行和进一步的元素。

我们项目的`profile.html`文件如下所示：

```py
{% extends "base.html" %}
{% block content %}
<div class="row clearfix">
<div class="col-md-12 column">
{% for tweet in tweets %}
<div class="well">
<span>{{ tweet.text }}</span>
</div>
{% endfor %}
</div>
</div>
{% endblock %}
```

这将显示我们通过 URL 参数传递的用户的推文。我们采用的示例是用户`ratancs`，我们在初始设置期间创建的用户。您可以在以下截图中看到他们的推文：

![模板-为主页创建模板](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00298.jpeg)

# 总结

我们学习了与我们的 Django 项目相关的基本术语，我们需要设置项目的基本模板结构，以及如何为我们的类似推文的应用程序设置 bootstrap。我们还看到了 MVC 在这里的工作方式以及在创建主页时 URL 和视图的作用。

然后，我们介绍了基于类的视图来生成用户页面。我们看到了模型在 Django 中的工作方式，以及如何为项目设计数据库模式。我们还学会了构建用户注册页面、帐户管理页面和主页模板。

我们将学习设计构建标签模型的算法，以及在接下来的章节中如何在您的帖子中使用标签的机制。
