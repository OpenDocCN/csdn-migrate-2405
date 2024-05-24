# Go Web 爬虫快速启动指南（一）

> 原文：[`zh.annas-archive.org/md5/5F4220C3B6C0AD580CCD346802D7B1C0`](https://zh.annas-archive.org/md5/5F4220C3B6C0AD580CCD346802D7B1C0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

互联网是一个充满有趣信息和见解的地方，等待被获取。就像金块一样，这些零散的数据片段可以被收集、过滤、组合和精炼，从而产生极具价值的产品。凭借正确的知识、技能和一点创造力，您可以构建一个能够支撑数十亿美元公司的网络爬虫。为了支持这一点，您需要使用最适合工作的工具，首先是一种专为速度、简单和安全性而构建的编程语言。

Go 编程语言结合了前辈的最佳理念和前沿思想，摒弃了不必要的废话，产生了一套锋利的工具和清晰的架构。通过 Go 标准库和开源贡献者的项目，您拥有构建任何规模的网络爬虫所需的一切。

# 这本书适合谁

这本书适合有一点编码经验的人，对如何构建快速高效的网络爬虫感兴趣。

# 本书涵盖的内容

第一章《介绍网络爬虫和 Go》解释了什么是网络爬虫，以及如何安装 Go 编程语言和工具。

第二章《请求/响应周期》概述了 HTTP 请求和响应的结构，并解释了如何使用 Go 进行制作和处理。

第三章《网络爬虫礼仪》解释了如何构建一个遵循最佳实践和推荐的网络爬虫，以有效地爬取网络，同时尊重他人。

第四章《解析 HTML》展示了如何使用各种工具从 HTML 页面中解析信息。

第五章《网络爬虫导航》演示了有效浏览网站的最佳方法。

第六章《保护您的网络爬虫》解释了如何使用各种工具安全、可靠地浏览互联网。

第七章《并发爬取》介绍了 Go 并发模型，并解释了如何构建高效的网络爬虫。

第八章《100 倍速爬取》提供了构建大规模网络爬虫的蓝图，并提供了一些来自开源社区的示例。

# 为了充分利用本书

为了充分利用本书，您应该熟悉您的终端或命令提示符，确保您有良好的互联网连接，并阅读每一章，即使您认为您已经知道了。本书的读者应该以开放的心态思考网络爬虫应该如何行动，并学习当前的最佳实践和适当的礼仪。本书还专注于 Go 编程语言，涵盖了安装、基本命令、标准库和包管理，因此对 Go 的一些熟悉将有所帮助，因为本书对语言进行了广泛的涵盖，只深入到了进行网络爬取所需的深度。为了能够运行本书中的大部分代码，读者应该熟悉他们的终端或命令提示符，以便运行示例等其他任务。

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)登录或注册

1.  选择“支持”选项卡

1.  点击“代码下载和勘误”

1.  在搜索框中输入书名，然后按照屏幕上的说明操作

一旦文件下载完成，请确保使用以下最新版本的软件解压缩或提取文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Go-Web-Scraping-Quick-Start-Guide`](https://github.com/PacktPublishing/Go-Web-Scraping-Quick-Start-Guide)。如果代码有更新，将在现有的 GitHub 存储库中更新。

我们还有其他代码包，来自我们丰富的书籍和视频目录，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如："这是使用`net/http`包的默认 HTTP 客户端请求`index.html`资源。"

代码块设置如下：

```go
POST /login HTTP/1.1
Host: myprotectedsite.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 38

username=myuser&password=supersecretpw
```

任何命令行输入或输出都以以下方式书写：

```go
go run main.go
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中以这种方式出现。例如："在这种情况下，您将收到 500 内部服务器错误的状态码。"

警告或重要说明显示为这样。

提示和技巧显示为这样。


# 第一章：介绍网络爬虫和 Go

收集、解析、存储和处理数据是几乎每个人在软件开发职业生涯中都需要做的基本任务。跟上大大提高应用程序开发的稳定性、速度和效率的新兴技术是另一个挑战。为了提供如何实现这两个目标的见解，我写了这本书。在这里，您将找到一个在 Go 中执行网络爬虫的指南。本书涵盖了网络爬虫的广泛视角，从**超文本传输协议**（**HTTP**）和**超文本标记语言**（**HTML**）的基础知识到构建高度并发的分布式系统。

在本章中，您将找到以下主题的解释：

+   什么是网络爬虫？

+   为什么您需要一个网络爬虫？

+   什么是 Go？

+   为什么 Go 非常适合网络爬虫？

+   您如何设置 Go 开发环境？

# 什么是网络爬虫？

网络爬虫在本质上是为了特定目的从互联网上收集公开可用的信息。它以许多不同的名称出现，比如以下：

+   蜘蛛

+   爬虫

+   机器人

尽管这个名字可能带有负面含义，但网络爬虫的实践自互联网诞生以来就存在，并发展成了各种技术和技巧。事实上，一些公司甚至建立了他们整个业务模式在网络爬虫上！

# 为什么您需要一个网络爬虫？

有许多不同的用例，您可能需要构建一个网络爬虫。所有这些用例都围绕着互联网上的信息通常是分散的，但当收集到一个单一的包中时，可能非常有价值。在这些情况下，收集信息的人通常与数据的生产者没有工作或商业关系，这意味着他们无法要求将信息打包并交付给他们。由于缺乏这种关系，需要数据的人必须依靠自己的手段来收集信息。

# 搜索引擎

网络爬虫的一个众所周知的用例是为了构建搜索引擎而对网站进行索引。在这种情况下，网络爬虫会访问不同的网站，并跟踪其他网站的引用，以便发现互联网上所有可用的内容。通过收集页面上的一些内容，您可以通过将术语与您收集的页面的内容进行匹配来响应搜索查询。如果您跟踪页面如何链接在一起，并根据它们与其他站点的连接数量对最重要的页面进行排名，您还可以建议类似的页面。

Googlebot 是用于构建搜索引擎的网络爬虫的最著名的例子。它是构建搜索引擎的第一步，因为它会下载、索引和对网站上的每个页面进行排名。它还会跟踪到其他网站的链接，这就是它能够索引互联网上大部分内容的原因。根据 Googlebot 的文档，网络爬虫试图每隔几秒钟到达每个网页，这需要它们每天达到数十亿页的估计！

如果您的目标是构建一个搜索引擎，尽管规模要小得多，您将在本书中找到足够的工具来收集您需要的信息。但是，本书不会涵盖索引和排名页面以提供相关的搜索结果。

# 价格比较

另一个已知的用例是查找通过各种网站销售的特定产品或服务，并跟踪它们的价格。您可以看到谁在销售该商品，谁的价格最低，或者它最有可能何时有货。您甚至可能对来自不同来源的类似产品感兴趣。定期让网络爬虫访问网站以监视这些产品和服务将很容易解决这个问题。这与跟踪航班、酒店和租车价格非常相似。

像 camelcamelcamel（[`camelcamelcamel.com/`](https://camelcamelcamel.com/)）这样的网站就是围绕这种情况构建其商业模式的。根据他们解释他们系统如何工作的博客文章，他们每隔半小时到几个小时主动收集来自多个零售商的定价信息，涵盖数百万种产品。这使用户可以查看多个平台上的价格差异，并在物品价格下降时收到通知。

您可以在[`camelcamelcamel.com/blog/how-our-price-checking-system-works`](https://camelcamelcamel.com/blog/how-our-price-checking-system-works)阅读他们的文章。

这种类型的网络爬虫需要非常仔细地解析网页，以提取只与相关的内容。在后面的章节中，您将学习如何从 HTML 页面中提取信息，以收集这些信息。

# 构建数据集

数据科学家通常需要数十万个数据点来构建、训练和测试机器学习模型。在某些情况下，这些数据已经预打包并准备好供使用。大多数情况下，科学家需要自己去构建一个定制的数据集。这通常是通过构建一个网络爬虫来收集来自各种感兴趣来源的原始数据，并对其进行精炼，以便以后进行处理。这些网络爬虫还需要定期收集新鲜数据，以使用最相关的信息更新其预测模型。

数据科学家经常遇到的一个常见用例是确定人们对特定主题的感受，即所谓的情感分析。通过这个过程，公司可以寻找围绕其产品或整体存在的讨论，并收集一个普遍的共识。为了做到这一点，模型必须在什么是积极评论和消极评论上进行训练，这可能需要成千上万的个别评论才能构建一个平衡的训练集。构建一个网络爬虫来收集相关论坛、评论和社交媒体网站上的评论，对于构建这样的数据集将是有帮助的。

这些只是一些驱动谷歌、Mozenda 和[Cheapflights.com](http://Cheapflights.com)等大型企业的网络爬虫的例子。还有一些公司会按费用为您从网络上爬取所需的任何可用数据。为了以如此大规模运行爬虫，您需要使用一种快速、可扩展且易于维护的语言。

# 什么是 Go？

Go 是由谷歌员工于 2007 年创建的一种编程语言。在创建时，目标是构建一种快速、安全和简单的语言。Go 于 2012 年首次正式发布 1.0 版本，是当今增长最快的编程语言之一。根据*Stack Overflow 2018 开发者调查*，Go 在最受喜爱语言中排名前五，在最想要语言中排名前三。

Go 支持许多大规模网络基础架构平台和工具，如 Docker、Kubernetes 和 Terraform。这些平台使公司能够构建支持财富 500 强公司的生产规模产品。这主要是由于 Go 语言的设计，使其易于直接清晰地使用。许多其他使用 Go 进行开发的公司经常吹嘘其性能优于其他语言。

# 为什么 Go 很适合网络爬虫？

Go 编程语言的架构以及其标准库使其成为构建快速、可扩展和易于维护的网络爬虫的绝佳选择。Go 是一种静态类型、垃圾回收的语言，其语法更接近于 C/C++。对于从面向对象编程语言转过来的开发人员来说，该语言的语法会感觉非常熟悉。Go 还具有一些函数式编程元素，例如高阶函数。总的来说，有三个主要原因使得 Go 非常适合网络爬虫：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-web-scr-qk-st-gd/img/667ca4d5-2860-442a-8550-acb3a8a5ab52.png)

# Go 很快

速度是 Go 编程语言的主要目标之一。许多基准测试将 Go 的速度与 C++、Java 和 Rust 相提并论，并远远领先于 Python 和 Ruby 等语言。基准测试应该始终带有一些怀疑态度，但 Go 始终以极高的性能数字脱颖而出。这种速度通常与低资源占用量相结合，因为运行时非常轻量级，不占用太多内存。其中一个隐藏的好处是能够在较小的机器上运行 Go 程序，或者在同一台机器上运行多个实例，而不会有显著的开销。这降低了在更大规模上运行网络爬虫的成本。

这种速度在构建网络爬虫中非常重要，并且在更大的规模下变得更加明显。例如，一个需要两分钟来爬取一个页面的网络爬虫；理论上你可以在一天内处理 720 页。如果你能将处理时间减少到每页一分钟，你就可以将每天的页面数量翻倍到 1440 页！更好的是，这将以相同的成本完成。Go 的速度和效率使你能够用更少的资源做更多的事情。

# Go 是安全的

导致其速度的一个因素是 Go 是静态类型的。这使得该语言非常适合在大规模构建系统，并且对程序在生产环境中的运行非常有信心。此外，由于 Go 程序是通过编译器构建而不是通过解释器运行的，它允许你在编译时捕获更多的错误，并大大减少了可怕的运行时错误。

这种安全保障也延伸到了 Go 的垃圾收集器。垃圾收集意味着你不需要手动分配和释放内存。这有助于防止由于代码中对象处理不当而可能导致的内存泄漏。有人可能会认为垃圾收集会影响应用程序的性能，然而，Go 的垃圾收集器在干扰代码执行方面几乎没有什么额外开销。许多来源报告说，Go 的垃圾收集器引起的暂停时间不到一毫秒。在大多数情况下，这是为了避免未来追踪内存泄漏而付出的非常小的代价。对于网络爬虫来说，这当然是正确的。

随着网络爬虫在规模和复杂性上的增长，跟踪处理过程中可能发生的所有错误可能会变得困难。考虑到每天处理成千上万个网页，一个小错误可能会显著影响数据的收集。在一天结束时，错过的数据就是失去的金钱，因此在系统运行之前尽可能地防止尽可能多的已知错误对你的系统至关重要。

# Go 是简单的

除了 Go 编程语言本身的架构之外，标准库提供了所有你需要使网络爬虫变得简单的正确包。Go 在`net/http`包中提供了一个内置的 HTTP 客户端，它在开箱即用的同时也允许进行大量的定制。发起 HTTP 请求就像下面这样简单：

```go
http.Get("http://example.com")
```

`net/http`包的一部分还包括结构化 HTTP 请求、HTTP 响应以及所有 HTTP 状态码的实用程序，我们将在本书的后面进行深入讨论。你很少需要任何第三方包来处理与 Web 服务器的通信。Go 标准库还提供了工具来帮助分析 HTTP 请求，快速消耗 HTTP 响应主体，并调试你的网络爬虫中的请求和响应。`net/http`包中的 HTTP 客户端也是非常可配置的，让你调整特殊参数和方法以满足你的特定需求。通常情况下不需要这样做，但如果你遇到这样的情况，这个选项是存在的。

这种简单性将有助于消除编写代码时的一些猜测。您不需要确定进行 HTTP 请求的最佳方式；Go 已经解决了这个问题，并为您提供了完成工作所需的最佳工具。即使您需要的不仅仅是标准库，Go 社区也构建了遵循相同简单文化的工具。这无疑使集成第三方库变得容易。

# 如何设置 Go 开发环境

在开始构建网络爬虫之前，您需要适当的工具。为编写 Go 代码设置开发环境相对简单。您不需要安装很多外部工具，并且所有主要计算平台都得到支持。对于本章中列出的所有工具，您将找到适用于 Windows、Mac 和 Linux 系统的单独说明。此外，由于我们将使用的所有工具都是开源的，因此如果需要，您将能够访问源代码并根据自己的需求构建它们。

# Go 语言和工具

首先，您需要在计算机上安装 Go 编程语言和工具。安装过程因不同操作系统而异，请按照[`golang.org/doc/install`](https://golang.org/doc/install)上的说明进行操作。在安装页面上，您将找到适用于您的平台的 Go 下载说明，以及最低操作系统要求。

您最好花一些额外的时间浏览 Go 编程语言网站，了解更多关于该语言的信息，阅读教程，并查找标准库文档。

这是来自 Go 网站安装页面的截图，包含了在计算机上安装 Go 所需的所有说明：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-web-scr-qk-st-gd/img/e6a2e038-6896-4b07-8235-3f26f1ae1c5c.png)

如果您愿意，也可以从源代码构建该语言。安装结束时，您应该拥有所有 Go 库、Go 命令行以及一个简单的 hello world 项目，以确保一切都安装正确。

非常重要的是要按照说明一直测试您的安装。有时候，Go 在`$GOPATH`方面可能有点棘手。设置好`$GOPATH`后，您必须确保完成以下操作：

+   您有所需的`src`、`bin`和`pkg`目录

+   所有源代码都包含在`src`目录中

+   `src`目录中的文件夹结构模仿了您希望包名称的结构。

通过完成测试部分，您将节省将来很多的烦恼。

自从 1.11 版本发布以来，Go 团队宣布支持 Go 模块，这允许您在`$GOPATH`之外进行开发。由于这个功能仍然被认为是实验性的，本书将继续使用经典的 Go 开发方法。

# Git

您还需要安装 Git 版本控制软件。这将用于在计算机上下载第三方库。`go get`命令依赖于系统上安装了 Git，以便直接将库下载并安装到您的`$GOPATH`中。您也可以随意使用 Git 下载每个章节的示例。本书中的所有示例都将使用在 GitHub 上可用的开源库。您可以按照[`git-scm.com/download`](https://git-scm.com/download)上的说明为您的系统安装 Git。

Git 命令行工具是一组广泛的命令，用于对源代码进行版本控制、存储和检索。这些命令是支持 GitHub 网站的基础。强烈建议您学习如何使用该工具与 GitHub 网站进行交互，而不是通过用户界面进行操作。

以下是 Git 下载页面的截图，包含了适用于您操作系统的链接：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-web-scr-qk-st-gd/img/00d36271-bc01-4df6-8708-08b962b1feb8.png)

# 编辑器

你将需要的第二个工具是一个好的文本编辑器或**集成开发环境**（**IDE**）。如果你对 IDE 不熟悉，它们基本上是为特定编程语言编写应用程序而定制的文本编辑器。JetBrains 的 GoLand 是一个著名的 Go 语言 IDE。它具有内置的语法高亮显示、运行和调试模式、内置版本控制和包管理支持。

GoLand 提供 30 天的试用期，之后您必须购买许可证才能继续使用。

以下是 GoLand IDE 显示标准`Hello World`程序的截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-web-scr-qk-st-gd/img/06e4e699-c1a8-49b6-986e-c6b99e221464.png)

如果您更喜欢使用文本编辑器，那么有许多可用的编辑器，它们通常都有适用于 Go 的插件，使开发更加容易。如今最好的两个文本编辑器是微软的 Visual Studio Code 和 GitHub 的 Atom。这两者都是通用编辑器，也有用于语法高亮显示、构建和运行 Go 代码的插件。这样您就可以添加所需的功能而不会增加太多开销。

这个截图显示的是在 Visual Studio Code 中显示的相同`Hello World`程序：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-web-scr-qk-st-gd/img/a51cc645-d1ad-4c44-bd16-341e7667c80d.png)

最后，Atom 版本的`Hello World`程序如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-web-scr-qk-st-gd/img/8f6a50f0-a5ba-43b0-bc3b-fe29e3db11bf.png)

由于插件的社区支持水平很高，Visual Studio Code 和 Atom 都是构建 Go 应用程序的绝佳选择，我强烈建议安装。或者，您可以在任何文本编辑器中编写 Go 程序，并使用标准的 Go 命令在终端或命令提示符中运行代码。

您将需要一个稳定的互联网连接。良好的互联网连接将消除连接到不同网站时出现的错误。如果您正在构建一个位于网络防火墙后面的网络爬虫，或者您的网络连接较弱，您可能会遇到访问本书示例中使用的一些网站时出现困难。

# 摘要

在本章中，您学习了构建网络爬虫的一些用例以及与之相关的企业示例。您还学习了 Go 编程语言的一些优势，并创建了一个适合构建网络爬虫的开发环境。这些步骤应该可以帮助您开始这条道路。

在第二章中，*请求/响应循环*，我们将学习如何在 Go 中与 Web 服务器通信。我们将学习您的网络爬虫如何与 Web 服务器通信的基础知识。


# 第二章：请求/响应循环

在构建网络爬虫之前，您必须花一点时间思考互联网是如何工作的。在其核心，互联网是一组通过**域名查找系统**（**DNS**）服务器连接在一起的计算机网络。当您想访问一个网站时，您的浏览器将网站 URL 发送到 DNS 服务器，URL 被翻译成 IP 地址，然后您的浏览器发送请求到该 IP 地址的机器。这台机器称为 Web 服务器，接收并检查请求，并决定发送什么内容回到您的浏览器。然后您的浏览器解析服务器发送的信息，并根据数据的格式在屏幕上显示内容。Web 服务器和浏览器之间能够通信是因为它们遵守了一套全球规则，称为 HTTP。在本章中，您将学习 HTTP 请求和响应循环的一些关键点。

本章涵盖以下主题：

+   HTTP 请求是什么样子的？

+   HTTP 响应是什么样子的？

+   HTTP 状态码是什么？

+   Go 中的 HTTP 请求/响应是什么样子的？

# HTTP 请求是什么样子的？

当客户端（如浏览器）从服务器请求网页时，它发送一个 HTTP 请求。这种请求的格式定义了一个操作、一个资源和 HTTP 协议的版本。一些 HTTP 请求包括额外的信息供服务器处理，如查询或特定的元数据。根据操作，您还可能向服务器发送新信息供服务器处理。

# HTTP 请求方法

目前有九种 HTTP 请求方法，它们定义了客户端期望的一般操作。每种方法都带有特定的含义，告诉服务器应该如何处理请求。这九种请求方法如下：

+   `GET`

+   `POST`

+   `PUT`

+   `DELETE`

+   `HEAD`

+   `CONNECT`

+   `TRACE`

+   `OPTIONS`

+   `PATCH`

您将需要的最常见的请求方法是`GET`、`POST`和`PUT`。`GET`请求用于从网站检索信息。`POST`和`PUT`请求用于向网站发送信息，例如用户登录数据。这些类型的请求通常只在提交某种形式的表单数据时发送，我们将在本书的后面章节中介绍这些内容。

在构建网络爬虫时，您将大部分时间向服务器发送 HTTP `GET`请求以获取网页。对于[`example.com/index.html`](http://example.com/index.html)的最简单的`GET`请求示例如下：

```go
GET /index.html HTTP/1.1
Host: example.com
```

客户端使用`GET`操作将此消息发送到服务器，以使用 HTTP 协议的`1.1`版本获取`index.html`资源。HTTP 请求的第一行称为请求行，是 HTTP 请求的核心。

# HTTP 头

在请求行下面是一系列键值对，提供了描述请求应该如何处理的元数据。这些元数据字段称为 HTTP 头。在我们之前的简单请求中，我们有一个单独的 HTTP 头，定义了我们要到达的目标主机。这些信息并不是 HTTP 协议要求的，但几乎总是发送以提供关于谁应该接收请求的澄清。

如果您检查您的 Web 浏览器发送的 HTTP 请求，您将看到更多的 HTTP 头。以下是 Google Chrome 浏览器发送给相同的[example.com](http://example.com)网站的示例：

```go
GET /index.html HTTP/1.1
Host: example.com
Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
If-None-Match: "1541025663+gzip"
If-Modified-Since: Fri, 09 Aug 2013 23:54:35 GMT
```

HTTP 请求的基础是相同的，但是您的浏览器提供了更多的请求头，主要与如何处理缓存的 HTML 页面有关。我们将在接下来的章节中更详细地讨论其中一些头部。

服务器读取请求并处理所有头部，以决定如何响应您的请求。在最基本的情况下，服务器将回复说您的请求是 OK，并传送`index.html`的内容。

# 查询参数

对于一些 HTTP 请求，客户端需要提供额外的信息以便细化请求。这通常有两种不同的方式。对于 HTTP `GET`请求，有一种定义的方式来在请求中包含额外的信息。在 URL 的末尾放置一个`?`定义了 URL 资源的末尾，接下来的部分定义了查询参数。这些参数是键值对，定义了发送到服务器的额外信息。键值对的书写格式如下：

```go
key1=value1&key2=value2&key3 ...
```

在执行搜索时，您会经常看到这种情况。举个假设的例子，如果您在一个网站上搜索鞋子，您可能会遇到一个分页的结果页面，URL 可能看起来像这样：

```go
https://buystuff.com/product_search?keyword=shoes&page=1
```

注意资源是`product_search`，后面是`keyword`和`page`的查询参数。这样，您可以通过调整查询来收集所有页面的产品。

查询参数由网站定义。并没有所有网站都必须具有的标准参数，因此根据您正在抓取的网站的不同，您需要进行一些调查。

# 请求主体

查询参数通常只用于 HTTP `GET`请求。对于您向服务器发送数据的请求，比如`POST`和`PUT`请求，您将发送一个包含所有额外信息的请求主体。请求主体放置在 HTTP 请求的头部之后，它们之间有一行空格。以下是一个假设的用于登录到一个虚构网站的`POST`请求：

```go
POST /login HTTP/1.1
Host: myprotectedsite.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 38

username=myuser&password=supersecretpw
```

在这个请求中，我们将我们的`username`和`password`发送到`myprotectedsite.com/login`。这个请求的头部必须描述请求主体，以便服务器能够处理它。在这种情况下，我们声明请求主体以`x-www-form-urlencoded`格式，这是*查询参数*部分中使用的相同格式。我们可以使用其他格式，比如`JSON`或`XML`甚至纯文本，但前提是服务器支持。`x-www-form-urlencoded`格式是最广泛支持的，通常是一个安全的选择。我们在头部中定义的第二个参数是请求主体的字节长度。这允许服务器有效地准备处理数据，或者如果请求太大，则完全拒绝请求。

如果您熟悉结构，Go 标准库对构建 HTTP 请求有很好的支持。我们将在本章后面重新讨论如何做到这一点。

# HTTP 响应是什么样子的？

当服务器响应您的请求时，它通常会提供一个状态码、一些响应头和资源的内容。继续使用我们之前对[`www.example.com/index.html`](http://www.example.com/index.html)的请求，您将能够逐节看到典型响应的样子。

# 状态行

HTTP 响应的第一行称为状态行，通常看起来像这样：

```go
HTTP/1.1 200 OK
```

首先，它告诉您服务器正在使用的 HTTP 协议的版本。这应该始终与客户端 HTTP 请求发送的版本匹配。在这种情况下，我们的服务器正在使用版本`1.1`。接下来是 HTTP 状态码。这是用来指示响应状态的代码。大多数情况下，您应该看到状态码为 200，表示请求成功，并且会有一个响应主体跟随。这并不总是这样，我们将在下一节更深入地了解 HTTP 状态码。OK 是状态码的可读描述，仅供您参考使用。

# 响应头

HTTP 响应头跟随状态行，看起来与 HTTP 请求头非常相似。它们也提供了特定于响应的元数据，就像请求头一样。以下是我们[example.com](http://example.com)响应的头部：

```go
Accept-Ranges: bytes
Cache-Control: max-age=604800
Content-Type: text/html; charset=UTF-8
Date: Mon, 29 Oct 2018 13:31:23 GMT
Etag: "1541025663"
Expires: Mon, 05 Nov 2018 13:31:23 GMT
Last-Modified: Fri, 09 Aug 2013 23:54:35 GMT
Server: ECS (dca/53DB)
Vary: Accept-Encoding
X-Cache: HIT
Content-Length: 1270
```

在此响应中，您可以看到一些描述页面内容、如何缓存以及剩余数据大小的标头。在接收到数据后，这些信息对于处理数据是有用的。

# 响应主体

响应的其余部分是实际呈现`index.html`的网页。您的浏览器将使用此内容绘制网页本身的文本、图像和样式，但是对于爬取的目的，这并非必要。响应主体的缩写版本类似于这样：

```go
<!doctype html>
<html>
<head>
 <title>Example Domain</title>
 <meta charset="utf-8" />
 <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
 <meta name="viewport" content="width=device-width, initial-scale=1" />
 <!-- The <style> section was removed for brevity -->
</head>
<body>
 <div>
  <h1>Example Domain</h1>
<p>This domain is established to be used for illustrative examples in
   documents. You may use this domain in examples without prior 
   coordination or asking for permission.</p>
<p><a href="http://www.iana.org/domains/example">More information...</a></p>
 </div>
</body>
</html>
```

大多数情况下，您将处理具有状态码 200 的 Web 服务器的响应，表示请求正常。但是，偶尔您会遇到其他状态代码，您的网络爬虫应该知道。

# HTTP 状态码是什么？

HTTP 状态码用于通知 HTTP 客户端 HTTP 请求的状态。在某些情况下，HTTP 服务器需要通知客户端请求未被理解，或者需要采取额外的操作才能获得完整的响应。HTTP 状态码分为四个独立的范围，每个范围覆盖特定类型的响应。

# 100–199 范围

这些代码用于向 HTTP 客户端提供关于如何传递请求的信息。这些代码通常由 HTTP 客户端自己处理，在您的网络爬虫需要担心它们之前就会被处理。

例如，客户端可能希望使用 HTTP 2.0 协议发送请求，并请求服务器进行更改。如果服务器支持 HTTP 2.0，它将以 101 状态代码响应，表示切换协议。这样的情况将由客户端在后台处理，因此您无需担心。

# 200–299 范围

`200-299`范围的状态代码表示请求已成功处理，没有问题。在这里需要注意的最重要的代码是 200 状态代码。这意味着您将收到一个响应主体，并且一切都很完美！

在某些情况下，您可能正在下载大文件的块（考虑到几十亿字节的规模），在这种情况下，成功的响应应该是 206，表示服务器正在返回原始文件的部分内容。

此范围内的其他代码表示请求成功，但服务器正在后台处理信息，或者根本没有内容。这些通常不会在网络爬取中看到。

# 300–399 范围

如果您遇到此范围内的状态代码，这意味着请求已被理解，但需要采取额外步骤才能获得实际内容。您在这里遇到的最常见情况是重定向。

301、302、307 和 308 状态代码都表示您正在寻找的资源可以在另一个位置找到。在此响应的标头中，服务器应指示响应标头中的最终位置在哪里。例如，301 响应可能如下所示：

```go
HTTP/1.1 301 Moved Permanently
Location: /blogs/index.html
Content-Length: 190

<html>
<head><title>301 Moved Permanently</title></head>
<body bgcolor="white">
<h1>301 Moved Permanently</h1>
Please go to <a href="/blogs/index.html">/blogs/index.html</a>
</body>
</html>
```

服务器包括一个`Location`标头，告诉客户端资源的位置已移动，并且客户端应该将下一个请求发送到该位置。在大多数情况下，这里的内容可以被忽略。

此范围内的其他状态代码与代理和缓存信息的使用有关，这两者我们将在未来的章节中讨论。

# 400–499 范围

当您遇到此范围内的状态代码时，您应该关注。`400`范围表示您的请求出了问题。许多不同的问题可能触发这些响应，例如格式不佳、身份验证问题或异常请求。服务器将这些代码发送回给它们的客户端，告诉它们不会满足请求，因为某些东西看起来可疑。

您可能已经熟悉的一个状态码是 404 Not Found。当您请求服务器似乎找不到的资源时就会出现这种情况。这可能是由于资源拼写错误或页面根本不存在。有时，网站会在服务器上更新文件，可能忘记更新网页中与新位置的链接。这可能导致**损坏的链接**，尤其是当页面链接到外部网站时，这种情况特别常见。

在这个范围内，您可能会遇到的其他常见状态码是 401 Unauthorized 和 403 Forbidden。在这两种情况下，这意味着您正在尝试访问需要适当身份验证凭据的页面。网络上有许多不同形式的身份验证，本书将在未来的章节中仅涵盖基础知识。

我想要在这个范围内强调的最后一个状态码是 429 Too Many Requests。一些 Web 服务器配置了速率限制，这意味着您在一定时间内只能维持一定数量的请求。如果您超过了这个速率，那么不仅会对 Web 服务器造成不合理的压力，而且还会暴露您的网络爬虫，使其有被列入黑名单的风险。遵守适当的网络爬取礼仪对您和目标网站都有益处。

# 500-599 范围

这个范围内的状态码通常表示与服务器本身相关的错误。尽管这些错误通常不是您的错，但您仍需要意识到它们并适应情况。

状态码 502 Bad Gateway 和 503 Service Temporarily Unavailable 表示服务器由于服务器内部问题而无法生成资源。这并不一定意味着资源不存在，或者您无权访问它。当遇到这些代码时，最好将请求搁置，稍后再试。如果您经常看到这些代码，您可能希望停止所有请求，让服务器解决其问题。

有时候网页服务器会因为没有特定的原因而出现故障。在这种情况下，您将收到 500 Internal Server Error 状态码。这些错误是通用的，通常是服务器代码崩溃的原因。在这种情况下，重试您的请求或让您的抓取器暂时停止也是相关的建议。

# 在 Go 中，HTTP 请求/响应是什么样子的？

现在您已经熟悉了 HTTP 请求和响应的基础知识，是时候看看在 Go 中是什么样子了。Go 中的标准库提供了一个名为`net/http`的包，其中包含了构建客户端所需的所有工具，可以从 Web 服务器请求页面并以极少的努力处理响应。

让我们看一下本章开头的示例，我们在访问[`www.example.com/index.html`](http://www.example.com/index.html)的网页。底层的 HTTP 请求指示[example.com](http://example.com)的 Web 服务器`GET` `index.html`资源：

```go
GET /index.html HTTP/1.1
Host: example.com
```

使用 Go 的`net/http`包，您可以使用以下代码行：

```go
r, err := http.Get("http://www.example.com/index.html")
```

Go 编程语言允许从单个函数返回多个变量。这也是通常抛出和处理错误的方式。

这是使用`net/http`包的默认 HTTP 客户端请求`index.html`资源，返回两个对象：HTTP 响应（`r`）和错误（`err`）。在 Go 中，错误是作为值返回的，而不是被其他代码抛出和捕获。如果`err`等于`nil`，那么我们知道与 Web 服务器通信没有问题。

让我们看一下本章开头的响应。如果请求成功，服务器将返回类似以下内容：

```go
HTTP/1.1 200 OK
Accept-Ranges: bytes
Cache-Control: max-age=604800
Content-Type: text/html; charset=UTF-8
Date: Mon, 29 Oct 2018 13:31:23 GMT
Etag: "1541025663"
Expires: Mon, 05 Nov 2018 13:31:23 GMT
Last-Modified: Fri, 09 Aug 2013 23:54:35 GMT
Server: ECS (dca/53DB)
Vary: Accept-Encoding
X-Cache: HIT
Content-Length: 1270

<!doctype html>
<html>
<head>
 <title>Example Domain</title>
 <meta charset="utf-8" />
 <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
 <meta name="viewport" content="width=device-width, initial-scale=1" />
 <!-- The <style> section was removed for brevity -->
</head>
<body>
 <div>
 <h1>Example Domain</h1>
 <p>This domain is established to be used for illustrative examples in
    documents. You may use this
    domain in examples without prior coordination or asking for
    permission.</p>
 <p><a href="http://www.iana.org/domains/example">More information...</a></p>
 </div>
</body>
</html>
```

所有这些信息都包含在`r`变量中，这是从`http.Get()`函数返回的`*http.Response`。让我们来看看 Go 中`http.Response`对象的定义。以下`struct`在 Go 标准库中定义：

```go
type Response struct {
    Status string
    StatusCode int
    Proto string
    ProtoMajor int
    ProtoMinor int
    Header Header
    Body io.ReadCloser
    ContentLength int64
    TransferEncoding []string
    Close bool
    Uncompressed bool
    Trailer Header
    Request *Request
    TLS *tls.ConnectionState
}
```

`http.Response`对象包含处理 HTTP 响应所需的所有字段。特别是，`StatusCode`，`Header`和`Body`在爬取中会很有用。让我们在一个简单的例子中将请求和响应放在一起，将`index.html`文件保存到您的计算机上。

# 一个简单的请求示例

在您设置的`$GOPATH/src`文件夹中，创建一个名为`simplerequest`的文件夹。在`simplerequest`中，创建一个名为`main.go`的文件。将`main.go`的内容设置为以下代码：

```go
package main

import (
 "log"
 "net/http"
 "os"
)

func main() {
 // Create the variables for the response and error
 var r *http.Response
 var err error

 // Request index.html from example.com
 r, err = http.Get("http://www.example.com/index.html")

 // If there is a problem accessing the server, kill the program and print the error the console
 if err != nil {
  panic(err)
 }

 // Check the status code returned by the server
 if r.StatusCode == 200 {
  // The request was successful!
  var webPageContent []byte

  // We know the size of the response is 1270 from the previous example
  var bodyLength int = 1270

  // Initialize the byte array to the size of the data
  webPageContent = make([]byte, bodyLength)

  // Read the data from the server
  r.Body.Read(webPageContent)

  // Open a writable file on your computer (create if it does not 
     exist)
  var out *os.File
  out, err = os.OpenFile("index.html", os.O_CREATE|os.O_WRONLY, 0664)

  if err != nil {
   panic(err)
  }

  // Write the contents to a file
  out.Write(webPageContent)
  out.Close()
 } else {
  log.Fatal("Failed to retrieve the webpage. Received status code", 
  r.Status)
 }
}
```

这里给出的示例有点冗长，以便向您展示 Go 编程的基础知识。随着您在本书中的进展，您将了解到一些技巧，使您的代码更加简洁。

您可以在`terminal`窗口中输入以下命令来从`simplerequest`文件夹内运行此代码：

```go
go run main.go 
```

如果一切顺利，您不应该看到打印的消息，应该有一个名为`index.html`的新文件，其中包含响应主体的内容。您甚至可以用 Web 浏览器打开该文件！

有了这些基础知识，您应该可以创建一个在 Go 中可以使用几行代码创建 HTTP 请求和读取 HTTP 响应的网络爬虫。

# 摘要

在本章中，我们介绍了 HTTP 请求和响应的基本格式。我们还看到了如何在 Go 中进行 HTTP 请求，以及`http.Response`结构如何与真实的 HTTP 响应相关联。最后，我们创建了一个小程序，向[`www.example.com/index.html`](http://www.example.com/index.html)发送了一个 HTTP 响应，并处理了 HTTP 响应。有关完整的 HTTP 规范，我鼓励您访问[`www.w3.org/Protocols/`](https://www.w3.org/Protocols/)。

在第三章中，*网络爬虫礼仪*，我们将看到成为网络良好公民的最佳实践。


# 第三章：网络爬取礼仪

在深入了解太多代码之前，你需要记住一些要点，当你开始运行网络爬虫时。重要的是要记住，为了让每个人都和睦相处，我们都必须成为互联网的良好公民。牢记这一点，有许多工具和最佳实践可供遵循，以确保在向外部网络服务器添加负载时，你是公平和尊重的。违反这些准则可能会使你的网络爬虫面临被网络服务器屏蔽的风险，或者在极端情况下，你可能会陷入法律纠纷。

在本章中，我们将涵盖以下主题：

+   什么是 robots.txt 文件？

+   什么是用户代理字符串？

+   你如何限制你的网络爬虫？

+   你如何使用缓存？

# 什么是 robots.txt 文件？

大多数网站页面都可以被网络爬虫和机器人访问。允许这样做的原因之一是为了被搜索引擎索引，或者允许内容策展人发现页面。Googlebot 是大多数网站都很乐意让其访问其内容的工具之一。然而，有些网站可能不希望所有内容都出现在谷歌搜索结果中。想象一下，如果你可以谷歌一个人，立即获得他们所有的社交媒体资料，包括联系信息和地址。这对这个人来说是个坏消息，对于托管网站的公司来说也不是一个好的隐私政策。为了控制网站不同部分的访问权限，你需要配置一个`robots.txt`文件。

`robots.txt`文件通常托管在网站的根目录下的`/robots.txt`资源中。这个文件包含了谁可以访问网站中的哪些页面的定义。这是通过描述与`User-Agent`字符串匹配的机器人，并指定允许和不允许的路径来完成的。通配符也支持在`Allow`和`Disallow`语句中。以下是 Twitter 的一个例子`robots.txt`文件：

```go
User-agent: *
Disallow: /
```

这是你可能会遇到的最严格的`robots.txt`文件。它声明没有网络爬虫可以访问[twitter.com](http://twitter.com)的任何部分。违反这一规定将使你的网络爬虫面临被 Twitter 服务器列入黑名单的风险。另一方面，像 Medium 这样的网站则更加宽容。以下是他们的`robots.txt`文件：

```go
User-Agent: *
Disallow: /m/
Disallow: /me/
Disallow: /@me$
Disallow: /@me/
Disallow: /*/edit$
Disallow: /*/*/edit$
Allow: /_/
Allow: /_/api/users/*/meta
Allow: /_/api/users/*/profile/stream
Allow: /_/api/posts/*/responses
Allow: /_/api/posts/*/responsesStream
Allow: /_/api/posts/*/related
Sitemap: https://medium.com/sitemap/sitemap.xml
```

通过查看这些，你可以看到编辑配置文件是被以下指令禁止的：

+   `Disallow: /*/edit$`

+   `Disallow: /*/*/edit$`

与登录和注册相关的页面，这可能被用于自动帐户创建，也被`Disallow: /m/`禁止访问。

如果你重视你的网络爬虫，不要访问这些页面。`Allow`语句明确允许`/_/`路径中的路径，以及一些`api`相关资源。除了这里定义的内容，如果没有明确的`Disallow`语句，那么你的网络爬虫有权限访问这些信息。在 Medium 的情况下，这包括所有公开可用的文章，以及关于作者和出版物的公开信息。这个`robots.txt`文件还包括一个`sitemap`，这是一个列出网站上所有页面的 XML 编码文件。你可以把它想象成一个巨大的索引，非常有用。

`robots.txt`文件的另一个例子显示了一个网站为不同的`User-Agent`实例定义规则。以下`robots.txt`文件来自 Adidas：

```go
User-agent: *
Disallow: /*null*
Disallow: /*Cart-MiniAddProduct
Disallow: /jp/apps/shoplocator*
Disallow: /com/apps/claimfreedom*
Disallow: /us/help-topics-affiliates.html
Disallow: /on/Demandware.store/Sites-adidas-US-Site/en_US/
User-Agent: bingbot
Crawl-delay: 1
Sitemap: https://www.adidas.com/on/demandware.static/-/Sites-CustomerFileStore/default/adidas-US/en_US/sitemaps/adidas-US-sitemap.xml
Sitemap: https://www.adidas.com/on/demandware.static/-/Sites-CustomerFileStore/default/adidas-MLT/en_PT/sitemaps/adidas-MLT-sitemap.xml
```

这个例子明确禁止所有网络爬虫访问一些路径，以及对`bingbot`的特殊说明。`bingbot`必须遵守`Crawl-delay`为`1`秒的规定，这意味着它不能每秒访问超过一次的页面。要注意`Crawl-delays`非常重要，因为它们将定义你可以多快地进行网络请求。违反这一规定可能会为你的网络爬虫产生更多的错误，或者它可能会被永久屏蔽。

# 什么是用户代理字符串？

当 HTTP 客户端向 Web 服务器发出请求时，它们会标识自己的身份。这对于网络爬虫和普通浏览器都是成立的。你是否曾经想过为什么一个网站知道你是 Windows 用户还是 Mac 用户？这些信息包含在你的`User-Agent`字符串中。以下是 Linux 计算机上 Firefox 浏览器的`User-Agent`字符串示例：

```go
Mozilla/5.0 (X11; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0
```

你可以看到这个字符串标识了 Web 浏览器的系列、名称和版本，以及操作系统。这个字符串将随着每个来自该浏览器的请求一起发送到请求头，例如以下内容：

```go
GET /index.html HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:57.0) Gecko/20100101 Firefox/57.0
```

并非所有的`User-Agent`字符串都包含这么多信息。非网页浏览器的 HTTP 客户端通常要小得多。以下是一些示例：

+   cURL: `curl/7.47.0`

+   Go: `Go-http-client/1.1`

+   Java: `Apache-HttpClient/4.5.2`

+   Googlebot（用于图像）：`Googlebot-Image/1.0`

`User-Agent`字符串是介绍你的机器人并对遵循`robots.txt`文件中设置的规则负责的一种好方法。通过使用这种机制，你将对任何违规行为负责。

# 示例

有一些开源工具可用于解析`robots.txt`文件并根据其验证网站 URL，以查看你是否有访问权限。我推荐的一个项目在 GitHub 上叫做`temoto`的`robotstxt`。为了下载这个库，在你的终端中运行以下命令：

```go
go get github.com/temoto/robotstxt
```

这里提到的`$GOPATH`是你在 Go 编程语言安装中设置的路径，见第一章，*介绍 Web 爬虫和 Go*。这是带有`src/ bin/`和`pkg/`目录的目录。

这将在你的机器上安装库到`$GOPATH/src/github/temoto/robotstxt`。如果愿意，你可以阅读代码以了解其工作原理。为了本书的目的，我们将只在我们自己的项目中使用该库。在你的`$GOPATH/src`文件夹中，创建一个名为`robotsexample`的新文件夹。在`robotsexample`文件夹中创建一个`main.go`文件。以下是`main.go`的代码，展示了如何使用`temoto/robotstxt`包的简单示例：

```go
package main

import (
  "net/http"

  "github.com/temoto/robotstxt"
)

func main() {
  // Get the contents of robots.txt from packtpub.com
  resp, err := http.Get("https://www.packtpub.com/robots.txt")
  if err != nil {
    panic(err)
  }
  // Process the response using temoto/robotstxt
  data, err := robotstxt.FromResponse(resp)
  if err != nil {
    panic(err)
  }
  // Look for the definition in the robots.txt file that matches the default Go User-Agent string
  grp := data.FindGroup("Go-http-client/1.1")
  if grp != nil {
    testUrls := []string{
      // These paths are all permissable
      "/all",
      "/all?search=Go",
      "/bundles",

      // These paths are not
      "/contact/",
      "/search/",
      "/user/password/",
    }

    for _, url := range testUrls {
      print("checking " + url + "...")

      // Test the path against the User-Agent group
      if grp.Test(url) == true {
        println("OK")
      } else {
        println("X")
      }
    }
  }
}
```

本示例使用 Go 语言的`range`操作符进行每个循环。`range`操作符返回两个变量，第一个是`迭代`的`索引`（我们通过将其分配给`_`来忽略），第二个是该索引处的值。

这段代码对[`www.packtpub.com/`](https://www.packtpub.com/)的`robots.txt`文件检查了六条不同的路径，使用了 Go HTTP 客户端的默认`User-Agent`字符串。如果`User-Agent`被允许访问页面，则`Test()`方法返回`true`。如果返回`false`，则你的爬虫不应该访问网站的这一部分。

# 如何限制你的爬虫速度

良好的网络爬取礼仪的一部分是确保你不会对目标 Web 服务器施加太大的负载。这意味着限制你在一定时间内发出的请求数量。对于较小的服务器，这一点尤为重要，因为它们的资源池更有限。一个很好的经验法则是，你应该只在你认为页面会发生变化的时候访问相同的网页。例如，如果你正在查看每日优惠，你可能只需要每天爬取一次。至于从同一个网站爬取多个页面，你应该首先遵循`robots.txt`文件中的`Crawl-Delay`。如果没有指定`Crawl-Delay`，那么你应该在每个页面后手动延迟一秒钟。

有许多不同的方法可以将延迟纳入你的爬虫中，从手动让程序休眠到使用外部队列和工作线程。本节将解释一些基本技术。当我们讨论 Go 编程语言并发模型时，我们将重新讨论更复杂的示例。

向您的网络爬虫添加节流的最简单方法是跟踪发出的请求的时间戳，并确保经过的时间大于您期望的速率。例如，如果您要以每 5 秒一个页面的速率抓取，它可能是这样的：

```go
package main

import (
  "fmt"
  "net/http"
  "time"
)

func main() {
  // Tracks the timestamp of the last request to the webserver
  var lastRequestTime time.Time

  // The maximum number of requests we will make to the webserver
  maximumNumberOfRequests := 5

  // Our scrape rate at 1 page per 5 seconds
  pageDelay := 5 * time.Second

  for i := 0; i < maximumNumberOfRequests; i++ {
    // Calculate the time difference since our last request
    elapsedTime := time.Now().Sub(lastRequestTime)
    fmt.Printf("Elapsed Time: %.2f (s)\n", elapsedTime.Seconds())
    //Check if there has been enough time
    if elapsedTime < pageDelay {
      // Sleep the difference between the pageDelay and elapsedTime
      var timeDiff time.Duration = pageDelay - elapsedTime
      fmt.Printf("Sleeping for %.2f (s)\n", timeDiff.Seconds())
      time.Sleep(pageDelay - elapsedTime)
    }

    // Just for this example, we are not processing the response
    println("GET example.com/index.html")
    _, err := http.Get("http://www.example.com/index.html")
    if err != nil {
      panic(err)
    }

    // Update the last request time
    lastRequestTime = time.Now()
  }
}
```

此示例在定义变量时有许多`:=`的实例。这是 Go 中同时声明和实例化变量的简写方式。它取代了需要说以下内容：

`var a string`

a = "value"

相反，它变成了：

`a := "value"`

在此示例中，我们每隔五秒向[`www.example.com/index.html`](http://www.example.com/index.html)发出一次请求。我们知道自上次请求以来的时间有多长，因为我们更新`lastRequestTime`变量并在进行每个请求之前检查它。这就是您抓取单个网站所需的全部内容，即使您要抓取多个页面。

如果您要从多个网站抓取数据，您需要将`lastRequestTime`分成每个网站一个变量。最简单的方法是使用`map`，Go 的键值结构，其中键将是主机名，值将是上次请求的时间戳。这将替换定义为以下内容：

```go
var lastRequestMap map[string]time.Time = map[string]time.Time{
  "example.com": time.Time{},
  "packtpub.com": time.Time{},
}
```

我们的`for`循环也会稍微改变，并将地图的值设置为当前抓取时间，但仅适用于我们正在抓取的网站。例如，如果我们要交替抓取页面，可能会是这样的：

```go
// Check if "i" is an even number
if i%2 == 0 {
  // Use the Packt Publishing site and elapsed time
  webpage = packtPage
  elapsedTime = time.Now().Sub(lastRequestMap["packtpub.com"])
} else {
  // Use the example.com elapsed time
  elapsedTime = time.Now().Sub(lastRequestMap["example.com"])
}
```

最后，要更新地图的最后已知请求时间，我们将使用类似的块：

```go
// Update the last request time
if i%2 == 0 {
  // Use the Packt Publishing elapsed time
  lastRequestMap["packtpub.com"] = time.Now()
} else {
  // Use the example.com elapsed time
  lastRequestMap["example.com"] = time.Now()
}
```

您可以在 GitHub 上找到此示例的完整源代码。

如果您查看终端中的输出，您将看到对任一站点的第一个请求没有延迟，每个休眠期略少于五秒。这表明爬虫正在独立地尊重每个站点的速率。

# 如何使用缓存

最后一个可以使您的爬虫受益并减少网站负载的技术是仅在内容更改时请求新内容。如果您的爬虫从 Web 服务器下载相同的旧内容，那么您将不会获得任何新信息，而 Web 服务器则会做不必要的工作。因此，大多数 Web 服务器实施技术以向客户端提供有关缓存的指令。

支持缓存的网站将向客户端提供有关可以存储什么以及存储多长时间的信息。这是通过响应头，如`Cache-Control`，`Etag`，`Date`，`Expires`和`Vary`来完成的。您的网络爬虫应该了解这些指令，以避免向网络服务器发出不必要的请求，从而节省您和服务器的时间和计算资源。让我们再次看看我们的[`www.example.com/index.html`](http://www.example.com/index.html)响应，如下所示：

```go
HTTP/1.1 200 OK
Accept-Ranges: bytes
Cache-Control: max-age=604800
Content-Type: text/html; charset=UTF-8
Date: Mon, 29 Oct 2018 13:31:23 GMT
Etag: "1541025663"
Expires: Mon, 05 Nov 2018 13:31:23 GMT
Last-Modified: Fri, 09 Aug 2013 23:54:35 GMT
Server: ECS (dca/53DB)
Vary: Accept-Encoding
X-Cache: HIT
Content-Length: 1270
...
```

响应的正文在此示例中未包含。

有一些响应头用于传达缓存指令，您应该遵循这些指令以增加网络爬虫的效率。这些头部将告诉您应缓存什么信息，以及多长时间，以及其他一些有用的信息，以使生活更轻松。

# Cache-Control

`Cache-Control`头用于指示此内容是否可缓存以及缓存多长时间。此头的常见值如下：

+   `no-cache`

+   `no-store`

+   `must-revalidated`

+   `max-age=<seconds>`

+   `public`

缓存指令，如`no-cache`，`no-store`和`must-revalidate`存在是为了防止客户端缓存响应。有时，服务器知道此页面上的内容经常更改，或者依赖于其控制范围之外的来源。如果没有发送这些指令中的任何一个，您应该能够使用提供的`max-age`指令缓存响应。这定义了您应将此内容视为新鲜的秒数。此时间后，响应被认为是陈旧的，并且应向服务器发出新请求。

在上一个示例的响应中，服务器发送了一个`Cache-Control`标头：

```go
Cache-Control: max-age=604800
```

这表示您应该将此页面缓存长达`604880`秒（七天）。

# Expires

`Expires`标头是另一种定义保留缓存信息时间的方法。此标头定义了确切的日期和时间，从该日期和时间开始，内容将被视为过时并应该被刷新。如果提供了`Cache-Control`标头的`max-age`指令，这个时间应该与之相符。

在我们的示例中，`Expires`标头与`Date`标头匹配，根据`Date`标头定义了请求何时被服务器接收，从而定义了 7 天的到期时间：

```go
Date: Mon, 29 Oct 2018 13:31:23 GMT
Expires: Mon, 05 Nov 2018 13:31:23 GMT
```

# Etag

`Etag`也是保持缓存信息的重要内容。这是此页面的唯一密钥，只有在页面内容更改时才会更改。在缓存过期后，您可以使用此标记与服务器检查是否实际上有新内容，而无需下载新副本。这通过发送包含`Etag`值的`If-None-Match`标头来实现。当发生这种情况时，服务器将检查当前资源上的`Etag`是否与`If-None-Match`标头中的`Etag`匹配。如果匹配，则表示没有更新，服务器将以 304 Not Modified 的状态代码响应，并附加一些标头以扩展您的缓存。以下是`304`响应的示例：

```go
HTTP/1.1 304 Not Modified
Accept-Ranges: bytes
Cache-Control: max-age=604800
Date: Fri, 02 Nov 2018 14:37:16 GMT
Etag: "1541025663"
Expires: Fri, 09 Nov 2018 14:37:16 GMT
Last-Modified: Fri, 09 Aug 2013 23:54:35 GMT
Server: ECS (dca/53DB)
Vary: Accept-Encoding
X-Cache: HIT
```

在这种情况下，服务器验证`Etag`并提供一个新的`Expires`时间，仍然与`max-age`匹配，从第二次请求被满足的时间开始。这样，您仍然可以节省时间，而无需通过网络读取更多数据。您仍然可以使用缓存的页面来满足您的需求。

# 在 Go 中缓存内容

缓存页面的存储和检索可以通过手动使用本地文件系统来实现，也可以通过数据库来保存数据和缓存信息。还有一些开源工具可用于简化这种技术。其中一个项目是 GitHub 用户`gregjones`的`httpcache`。

`httpcache`遵循**互联网工程任务组**（**IETF**）制定的缓存要求，这是互联网标准的管理机构。该库提供了一个模块，可以从本地机器存储和检索网页，以及一个用于 Go HTTP 客户端的插件，自动处理所有与缓存相关的 HTTP 请求和响应标头。它还提供多个存储后端，您可以在其中存储缓存信息，如 Redis、Memcached 和 LevelDB。这将允许您在不同的机器上运行网络爬虫，但连接到相同的缓存信息。

随着您的爬虫规模的增长，您需要设计分布式架构，像这样的功能将是至关重要的，以确保时间和资源不会浪费在重复的工作上。所有爬虫之间的稳定通信至关重要！

让我们来看一个使用`httpcache`的示例。首先，通过在终端中输入以下命令来安装`httpcache`，如下所示：

+   `go get github.com/gregjones/httpcache`

+   `go get github.com/peterbourgon/diskv`

`diskv`项目被`httpcache`用于在本地机器上存储网页。

在您的`$GOPATH/src`中，创建一个名为`cache`的文件夹，并在其中创建一个`main.go`。使用以下代码作为您的`main.go`文件：

```go
package main

import (
  "io/ioutil"

  "github.com/gregjones/httpcache"
  "github.com/gregjones/httpcache/diskcache"
)

func main() {
  // Set up the local disk cache
  storage := diskcache.New("./cache")
  cache := httpcache.NewTransport(storage)

  // Set this to true to inform us if the responses are being read from a cache
  cache.MarkCachedResponses = true
  cachedClient := cache.Client()

  // Make the initial request
  println("Caching: http://www.example.com/index.html")
  resp, err := cachedClient.Get("http://www.example.com/index.html")
  if err != nil {
    panic(err)
  }

  // httpcache requires you to read the body in order to cache the response
  ioutil.ReadAll(resp.Body)
  resp.Body.Close()

  // Request index.html again
  println("Requesting: http://www.example.com/index.html")
  resp, err = cachedClient.Get("http://www.example.com/index.html")
  if err != nil {
    panic(err)
  }

  // Look for the flag added by httpcache to show the result is read from the cache
  _, ok = resp.Header["X-From-Cache"]
  if ok {
    println("Result was pulled from the cache!")
  }
}
```

该程序使用本地磁盘缓存来存储来自[`www.example.com/index.html`](http://www.example.com/index.html)的响应。在底层，它读取所有与缓存相关的标头，以确定是否可以存储页面，并将到期日期与数据一起包括在内。在第二次请求时，`httpcache`检查内容是否已过期，并返回缓存的数据，而不是进行另一个 HTTP 请求。它还添加了一个额外的标头`X-From-Cache`，以指示这是从缓存中读取的。如果页面已过期，它将使用`If-None-Match`标头进行 HTTP 请求，并处理响应，包括在 304 Not Modified 响应的情况下更新缓存。

使用自动设置好处理缓存内容的客户端将使您的爬虫运行更快，同时减少您的网络爬虫被标记为不良公民的可能性。当这与尊重网站的`robots.txt`文件和适当节流请求结合使用时，您可以自信地进行爬取，知道自己是网络社区中值得尊敬的成员。

# 总结

在本章中，您学会了尊重地爬取网络的基本礼仪。您了解了什么是`robots.txt`文件，以及遵守它的重要性。您还学会了如何使用`User-Agent`字符串来正确表示自己。还介绍了通过节流和缓存来控制您的爬虫。有了这些技能，您离构建一个完全功能的网络爬虫又近了一步。

在第四章中，*解析 HTML*，我们将学习如何使用各种技术从 HTML 页面中提取信息。


# 第四章：解析 HTML

在之前的章节中，我们处理了整个网页，这对大多数网络爬虫来说并不是很实用。虽然从网页中获取所有内容很好，但大多数情况下，你只需要从每个页面中获取一小部分信息。为了提取这些信息，你必须学会解析网络的标准格式，其中最常见的是 HTML。

本章将涵盖以下主题：

+   HTML 格式是什么

+   使用字符串包进行搜索

+   使用正则表达式包进行搜索

+   使用 XPath 查询进行搜索

+   使用层叠样式表选择器进行搜索

# HTML 格式是什么？

HTML 是用于提供网页上下文的标准格式。HTML 页面定义了浏览器应该绘制哪些元素，元素的内容和样式，以及页面应该如何响应用户的交互。回顾我们的[`example.com/index.html`](http://example.com/index.html)响应，你可以看到以下内容，这就是 HTML 文档的样子：

```go
<!doctype html>
<html>
<head>
  <title>Example Domain</title>
  <meta charset="utf-8" />
  <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <!-- The <style> section was removed for brevity -->
</head>
<body>
  <div>
    <h1>Example Domain</h1>
    <p>This domain is established to be used for illustrative examples 
       in documents. You may use this domain in examples without prior
       coordination or asking for permission.</p>
    <p><a href="http://www.iana.org/domains/example">More 
        information...</a></p>
  </div>
</body>
</html>
```

遵循 HTML 规范的文件遵循一套严格的规则，定义了文档的语法和结构。通过学习这些规则，你可以快速轻松地从任何网页中检索任何信息。

# 语法

HTML 文档通过使用带有元素名称的标签来定义网页的元素。标签总是被尖括号包围，比如`<body>`标签。每个元素通过在标签名称之前使用斜杠来定义标签集的结束，比如`</body>`。元素的内容位于一对开放和关闭标签之间。例如，`<body>`和匹配的`</body>`标签之间的所有内容定义了 body 元素的内容。

一些标签还有额外的属性，以键值对的形式定义，称为属性。这些属性用于描述元素的额外信息。在所示的示例中，有一个带有名为`href`的属性的`<a>`标签，其值为[`www.iana.org/domains/example`](https://www.iana.org/domains/example)。在这种情况下，`href`是`<a>`标签的一个属性，并告诉浏览器这个元素链接到提供的 URL。我们将在后面的章节中更深入地了解如何导航这些链接。

# 结构

每个 HTML 文档都有一个特定的布局，从`<!doctype>`标签开始。这个标签用于定义用于验证特定文档的 HTML 规范的版本。在我们的情况下，`<!doctype html>`指的是 HTML 5 规范。有时你可能会看到这样的标签：

```go
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
```

这将描述一个遵循提供的 URL 提供的定义的`HTML 4.01`（严格）网页。我们不会在本书中使用提供的定义来验证页面，因为通常不需要这样做。

在`<!doctype>`标签之后是`<html>`标签，其中包含网页的实际内容。在`<html>`标签内，你会找到文档的`<head>`和`<body>`标签。`<head>`标签包含有关页面本身的元数据，比如标题，以及用于构建网页的外部文件。这些文件可能是用于样式，或者用于描述元素如何对用户交互做出反应。

在实际网页[`example.com/index.html`](http://example.com/index.html)上，你可以看到`<style>`标签用于描述网页上各种类型元素的大小、颜色、字体和间距。为了节省空间，本书中删除了 HTML 文档中的这些信息。

`<body>`标签包含了你感兴趣的大部分数据。在`<body>`元素内，你会找到所有文本、图片、视频和包含你网页抓取需求信息的链接。从网页中收集你需要的数据可以通过许多不同的方式完成；你将在接下来的章节中看到一些常见的方法。

# 使用字符串包进行搜索

搜索内容的最基本方法是使用 Go 标准库中的`strings`包。`strings`包允许您对 String 对象执行各种操作，包括搜索匹配项，计算出现次数以及将字符串拆分为数组。此包的实用性可以涵盖您可能遇到的一些用例。

# 示例-计算链接

我们可以使用`strings`包提取的一条快速且简单的信息是计算网页中包含的链接数量。`strings`包有一个名为`Count()`的函数，它返回字符串中子字符串出现的次数。正如我们之前所见，链接包含在`<a>`标记中。通过计算`"<a"`的出现次数，我们可以大致了解页面中链接的数量。示例如下所示：

```go
package main

import (
  "fmt"
  "io/ioutil"
  "net/http"
  "strings"
)

func main() {
  resp, err := http.Get("https://www.packtpub.com/")
  if err != nil {
    panic(err)
  }

  data, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    panic(err)
  }

  stringBody := string(data)

  numLinks := strings.Count(stringBody, "<a")
  fmt.Printf("Packt Publishing homepage has %d links!\n", numLinks)
}
```

在此示例中，`Count()`函数用于查找 Packt Publishing 网站主页中`"<a"`的出现次数。

# 示例-Doctype 检查

`strings`包中的另一个有用方法是`Contains()`方法。这用于检查字符串中子字符串的存在。例如，您可以检查用于构建网页的 HTML 版本，类似于此处给出的示例：

```go
package main

import (
  "io/ioutil"
  "net/http"
  "strings"
)

func main() {
  resp, err := http.Get("https://www.packtpub.com/")
  if err != nil {
    panic(err)
  }

  data, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    panic(err)
  }

  stringBody := strings.ToLower(string(data))

  if strings.Contains(stringBody, "<!doctype html>") {
    println("This webpage is HTML5")
  } else if strings.Contains(stringBody, "html/strict.dtd") {
    println("This webpage is HTML4 (Strict)")
  } else if strings.Contains(stringBody, "html/loose.dtd") {
    println("This webpage is HTML4 (Tranistional)")
  } else if strings.Contains(stringBody, "html/frameset.dtd") {
    println("This webpage is HTML4 (Frameset)")
  } else {
    println("Could not determine doctype!")
  }
}
```

此示例查找包含在`<!doctype>`标记中的信息，以检查它是否包含 HTML 版本的特定指示符。运行此代码将向您显示 Packt Publishing 的主页是按照 HTML 5 规范构建的。

依赖`strings`包可以揭示有关网页的一些非常轻的信息，但它也有其缺点。在前面的两个示例中，如果文档中包含字符串的句子出现在意想不到的位置，匹配可能会误导。过于概括的字符串搜索可能导致误导，可以通过使用更健壮的工具避免。

# 使用 regexp 包进行搜索

Go 标准库中的`regexp`包通过使用正则表达式提供了更深层次的搜索。这定义了一种语法，允许您以更复杂的术语搜索字符串，并从文档中检索字符串。通过在正则表达式中使用捕获组，您可以从网页中提取与查询匹配的数据。以下是`regexp`包可以帮助您实现的一些有用任务。

# 示例-查找链接

在上一节中，我们使用了`strings`包来计算页面上链接的数量。通过使用`regexp`包，我们可以进一步使用以下正则表达式检索实际链接：

```go
 <a.*href\s*=\s*"'["'].*>
```

此查询应匹配任何看起来像 URL 的字符串，位于`<a>`标记内的`href`属性内。

以下程序打印 Packt Publishing 主页上的所有链接。使用相同的技术可以用于收集所有图像，通过查询`<img>`标记的`src`属性：

```go
package main

import (
  "fmt"
  "io/ioutil"
  "net/http"
        "regexp"
)

func main() {
  resp, err := http.Get("https://www.packtpub.com/")
  if err != nil {
    panic(err)
  }

  data, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    panic(err)
  }

  stringBody := string(data)

        re := regexp.MustCompile(`<a.*href\s*=\s*"'["'].*>`)
        linkMatches := re.FindAllStringSubmatch(stringBody, -1)

        fmt.Printf("Found %d links:\n", len(linkMatches))
        for _,linkGroup := range(linkMatches){
            println(linkGroup[1])
        }
}
```

# 示例-查找价格

正则表达式也可以用于查找网页本身显示的内容。例如，您可能正在尝试查找物品的价格。让我们看一下以下示例，显示了 Packt Publishing 网站上*Hands-On Go Programming*书的价格：

```go
package main

import (
  "fmt"
  "io/ioutil"
  "net/http"
        "regexp"
)

func main() {
  resp, err := http.Get("https://www.packtpub.com/application-development/hands-go-programming")
  if err != nil {
    panic(err)
  }

  data, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    panic(err)
  }

  stringBody := string(data)

  re := regexp.MustCompile(`.*main-book-price.*\n.*(\$[0-9]*\.[0-9]{0,2})`)
  priceMatches := re.FindStringSubmatch(stringBody)

  fmt.Printf("Book Price: %s\n", priceMatches[1])
}
```

该程序查找与`main-book-price`匹配的文本字符串，然后查找以下行中的 USD 格式的小数。

您可以看到，正则表达式可用于提取文档中的字符串，而`strings`包主要用于发现字符串。这两种技术都存在同样的问题：您可能会在意想不到的地方匹配字符串。为了更细粒度地进行搜索，搜索需要更加结构化。

# 使用 XPath 查询进行搜索

在以前的解析 HTML 文档的示例中，我们将 HTML 简单地视为可搜索的文本，您可以通过查找特定字符串来发现信息。幸运的是，HTML 文档实际上是有结构的。您可以看到每组标签可以被视为某个对象，称为节点，它又可以包含更多的节点。这创建了一个根节点、父节点和子节点的层次结构，提供了一个结构化的文档。特别是，HTML 文档与 XML 文档非常相似，尽管它们并非完全符合 XML 标准。由于这种类似 XML 的结构，我们可以使用 XPath 查询在页面中搜索内容。

XPath 查询定义了在 XML 文档中遍历节点层次结构并返回匹配元素的方法。在我们之前的示例中，我们需要搜索字符串来查找`<a>`标签以计算和检索链接。如果在 HTML 文档的意外位置（如代码注释或转义文本）中找到类似的匹配字符串，这种方法可能会有问题。如果我们使用 XPath 查询，如`//a/@href`，我们可以遍历 HTML 文档结构以找到实际的`<a>`标签节点并检索`href`属性。

# 示例 - 每日优惠

使用结构化查询语言如 XPath，您也可以轻松收集未格式化的数据。在我们之前的示例中，我们主要关注产品的价格。价格更容易处理，因为它们通常遵循特定的格式。例如，您可以使用正则表达式来查找美元符号，后跟一个或多个数字，一个句点和两个更多数字。另一方面，如果您想要检索没有格式的文本块或多个文本块，那么使用基本的字符串搜索将变得更加困难。XPath 通过允许您检索节点内的所有文本内容来简化此过程。

Go 标准库对 XML 文档和元素的处理有基本支持；不幸的是，它不支持 XPath。然而，开源社区已经为 Go 构建了各种 XPath 库。我推荐的是 GitHub 用户`antchfx`的`htmlquery`。

您可以使用以下命令获取此库：

```go
go get github.com/antchfx/htmlquery
```

以下示例演示了如何使用 XPath 查询来获取一些基本产品信息来抓取每日优惠：

```go
package main

import (
  "regexp"
  "strings"

  "github.com/antchfx/htmlquery"
)

func main() {
  doc, err := htmlquery.LoadURL("https://www.packtpub.com/packt/offers/free-learning")
  if err != nil {
    panic(err)
  }

  dealTextNodes := htmlquery.Find(doc, `//div[@class="dotd-main-book-summary float-left"]//text()`)

  if err != nil {
    panic(err)
  }

  println("Here is the free book of the day!")
  println("----------------------------------")

  for _, node := range dealTextNodes {
    text := strings.TrimSpace(node.Data)
    matchTagNames, _ := regexp.Compile("^(div|span|h2|br|ul|li)$")
    text = matchTagNames.ReplaceAllString(text,"")
    if text != "" {
      println(text)
    }
  }
}
```

该程序选择包含`class`属性的`div`元素中找到的任何`text()`。此查询还返回目标`div`元素的子节点的名称，例如`div`和`h2`，以及空文本节点。因此，我们放弃任何已知的 HTML 标签（使用正则表达式），并且只打印不是空字符串的剩余文本节点。

# 示例 - 收集产品

在这个示例中，我们将使用 XPath 查询来从 Packt Publishing 网站检索最新的发布信息。在这个网页上，有一系列包含更多`<div>`标签的`<div>`标签，最终会导致我们的信息。这些`<div>`标签中的每一个都有一个称为`class`的属性，描述了节点的用途。特别是，我们关注`landing-page-row`类。`landing-page-row`类中与书籍相关的`<div>`标签有一个称为`itemtype`的属性，告诉我们这个`div`是用于书籍的，并且应该包含其他包含名称和价格的属性。使用`strings`包无法实现这一点，而使用正则表达式将非常费力。

让我们看看以下示例：

```go
package main

import (
  "fmt"
  "strconv"

  "github.com/antchfx/htmlquery"
)

func main() {
  doc, err := htmlquery.LoadURL("https://www.packtpub.com/latest-
  releases")
  if err != nil {
    panic(err)
  }

  nodes := htmlquery.Find(doc, `//div[@class="landing-page-row 
  cf"]/div[@itemtype="http://schema.org/Product"]`)
  if err != nil {
    panic(err)
  }

  println("Here are the latest releases!")
  println("-----------------------------")

  for _, node := range nodes {
    var title string
    var price float64

    for _, attribute := range node.Attr {
      switch attribute.Key {
      case "data-product-title":
        title = attribute.Val
      case "data-product-price":
        price, err = strconv.ParseFloat(attribute.Val, 64)
        if err != nil {
          println("Failed to parse price")
        }
      }
    }
    fmt.Printf("%s ($%0.2f)\n", title, price)
  }
}
```

通过使用直接针对文档中的元素的 XPath 查询，我们能够导航到确切节点的确切属性，以检索每本书的名称和价格。

# 使用层叠样式表选择器进行搜索

您可以看到，使用结构化查询语言比基本字符串搜索更容易搜索和检索信息。但是，XPath 是为通用 XML 文档设计的，而不是 HTML。还有一种专门用于 HTML 的结构化查询语言。**层叠样式表**（**CSS**）是为 HTML 页面添加样式元素的一种方法。在 CSS 文件中，您可以定义到一个元素或多个元素的路径，以及描述外观。元素路径的定义称为 CSS 选择器，专门为 HTML 文档编写。

CSS 选择器了解我们可以在搜索 HTML 文档中使用的常见属性。在以前的 XPath 示例中，我们经常使用这样的查询`div[@class="some-class"]`来搜索具有类名`some-class`的元素。CSS 选择器通过简单地使用`.`为`class`属性提供了一种简写。相同的 XPath 查询在 CSS 查询中看起来像`div.some-class`。这里使用的另一个常见简写是搜索具有`id`属性的元素，这在 CSS 中表示为`#`符号。为了找到具有`main-body` id 的元素，您将使用`div#main-body`作为 CSS 选择器。CSS 选择器规范中还有许多其他便利之处，可以扩展 XPath 的功能，同时简化常见查询。

尽管 Go 标准库中不支持 CSS 选择器，但再次，开源社区有许多工具提供了这种功能，其中最好的是 GitHub 用户`PuerkitoBio`的`goquery`。

您可以使用以下命令获取该库：

```go
go get github.com/PuerkitoBio/goquery
```

# 示例-每日优惠

以下示例将使用`goquery`代替`htmlquery`来完善 XPath 示例：

```go
package main

import (
  "fmt"
  "strconv"

  "github.com/PuerkitoBio/goquery"
)

func main() {
  doc, err := goquery.NewDocument("https://www.packtpub.com/latest-
  releases")
  if err != nil {
    panic(err)
  }

  println("Here are the latest releases!")
  println("-----------------------------")
  doc.Find(`div.landing-page-row div[itemtype$="/Product"]`).
    Each(func(i int, e *goquery.Selection) {
      var title string
      var price float64

      title,_ = e.Attr("data-product-title")
      priceString, _ := e.Attr("data-product-price")
      price, err = strconv.ParseFloat(priceString, 64)
      if err != nil {
        println("Failed to parse price")
      }
      fmt.Printf("%s ($%0.2f)\n", title, price)
    })
}
```

使用`goquery`，搜索每日优惠变得更加简洁。在此查询中，我们使用 CSS 选择器提供的一个辅助功能，即使用`$=`运算符。我们不再寻找`itemtype`属性，匹配确切的字符串`http://schema.org/Product`，而是简单地匹配以`/Product`结尾的字符串。我们还使用`.`运算符来查找`landing-page-row`类。需要注意的一个关键区别是，与 XPath 示例之间的一个关键区别是，您不需要匹配类属性的整个值。当我们使用 XPath 搜索时，我们必须使用`@class="landing-page-row cf"`作为查询。在 CSS 中，不需要对类进行精确匹配。只要元素包含`landing-page-row`类，它就匹配。

# 示例-收集产品

在此提供的代码中，您可以看到收集产品示例的 CSS 选择器版本：

```go
package main

import (
  "bufio"
  "strings"

  "github.com/PuerkitoBio/goquery"
)

func main() {
  doc, err := goquery.NewDocument("https://www.packtpub.com/packt/offers/free-learning")
  if err != nil {
    panic(err)
  }

  println("Here is the free book of the day!")
  println("----------------------------------")
  rawText := doc.Find(`div.dotd-main-book-summary div:not(.eighteen-days-countdown-bar)`).Text()
  reader := bufio.NewReader(strings.NewReader(rawText))

  var line []byte
  for err == nil{
    line, _, err = reader.ReadLine()
    trimmedLine := strings.TrimSpace(string(line))
    if trimmedLine != "" {
      println(trimmedLine)
    }
  }
}
```

在这个例子中，您可以使用 CSS 查询来返回所有子元素的所有文本。我们使用`:not()`运算符来排除倒计时器，并最终处理文本行以忽略空格和空行。

# 总结

您可以看到有各种方法可以使用不同的工具从 HTML 页面中提取数据。基本字符串搜索和`regex`搜索可以使用非常简单的技术收集信息，但也有需要更多结构化查询语言的情况。XPath 通过假设文档是 XML 格式并可以进行通用搜索，提供了出色的搜索功能。CSS 选择器是搜索和提取 HTML 文档中数据的最简单方法，并提供了许多有用的 HTML 特定功能。

在第五章中，*网络爬虫导航*，我们将探讨高效和安全地爬取互联网的最佳方法。


# 第五章：网络爬取导航

到目前为止，本书侧重于为单个网页检索信息。虽然这是网络爬取的基础，但并不涵盖大多数用例。很可能，你需要访问多个网页或网站，以收集满足你需求的所有信息。这可能涉及直接通过 URL 列表访问许多已知网站，或者跟踪在某些页面上发现的链接到更多未知的地方。有许多不同的方式来引导你的网络爬虫浏览网页。

在本章中，我们将涵盖以下主题：

+   如何跟踪链接

+   如何使用`POST`请求提交表单

+   如何跟踪你的历史记录以避免循环

+   广度优先和深度优先爬取的区别

# 跟踪链接

正如你在本书中许多示例中所看到的，有一些由`<a>`标签表示的 HTML 元素，其中包含`href`属性，引用不同的 URL。这些标签称为锚标签，是网页上生成链接的方式。在网页浏览器中，这些链接通常会有不同的字体颜色，通常是蓝色，带有下划线。作为网页浏览器中的用户，如果你想要跟踪一个链接，通常只需点击它，你就会被重定向到 URL。作为一个网络爬虫，点击操作通常是不必要的。相反，你可以向`href`属性本身发送一个`GET`请求。

如果你发现`href`属性缺少`http://`或`https://`前缀和主机名，你必须使用当前网页的前缀和主机名。

# 示例-每日特惠

在第四章中，*解析 HTML*，我们使用了一个示例，从 Packt Publishing 网站上检索了最新发布的书籍的标题和价格。你可以通过跟踪每个链接到书籍的主要网页来收集更多关于每本书的信息。在下面的代码示例中，我们将添加导航以实现这一点：

```go
package main

import (
  "fmt"
  "strings"
  "time"
  "github.com/PuerkitoBio/goquery"
)

func main() {
  doc, err := goquery.NewDocument("https://www.packtpub.com/latest-releases")
  if err != nil {
    panic(err)
  }

  println("Here are the latest releases!")
  println("-----------------------------")
  time.Sleep(1 * time.Second)
  doc.Find(`div.landing-page-row div[itemtype$="/Product"] a`).
    Each(func(i int, e *goquery.Selection) {
      var title, description, author, price string
      link, _ := e.Attr("href")
      link = "https://www.packtpub.com" + link

      bookPage, err := goquery.NewDocument(link)
      if err != nil {
        panic(err)
      }
      title = bookPage.Find("div.book-top-block-info h1").Text()
      description = strings.TrimSpace(bookPage.Find("div.book-top-
      block-info div.book-top-block-info-one-liner").Text())
      price = strings.TrimSpace(bookPage.Find("div.book-top-block-info 
      div.onlyDesktop div.book-top-pricing-main-ebook-price").Text())
      authorNodes := bookPage.Find("div.book-top-block-info div.book-
      top-block-info-authors")
       if len(authorNodes.Nodes) < 1 {
        return
      } 
      author = strings.TrimSpace(authorNodes.Nodes[0].FirstChild.Data)
      fmt.Printf("%s\nby: %s\n%s\n%s\n---------------------\n\n", 
      title, author, price, description)
      time.Sleep(1 * time.Second)
    })
}
```

正如你所看到的，我们已经修改了`Each()`循环，以提取网页中列出的每个产品的链接。每个链接只包含到书籍的相对路径，所以我们在每个链接前缀中加入了[`www.packtpub.com`](https://www.packtpub.com)字符串。接下来，我们使用我们构建的链接导航到页面本身，并抓取所需的信息。在每页的末尾，我们休眠`1`秒，以便我们的网络爬虫不会过度负担服务器，遵守我们在第三章中学到的良好礼仪，*网络爬取礼仪*。

# 提交表单

到目前为止，我们已经能够使用 HTTP `GET`请求从服务器请求信息。这些请求涵盖了你在构建自己的网络爬虫时会遇到的绝大多数网络爬取任务。然而，总会有一些时候，你可能需要提交某种表单数据，以便检索你正在寻找的信息。这些表单数据可能包括搜索查询，或者登录界面，或者任何需要你在框中输入并点击提交按钮的页面。

对于简单的网站，这是通过一个包含一个或多个`<input>`元素和一个提交按钮的 HTML `<form>`元素来完成的。这个`<form>`元素通常具有定义`action`（发送`<form>`数据的位置）和`method`（要使用的 HTTP 方法）的属性。默认情况下，网页将使用 HTTP `GET`请求发送表单数据，但也很常见看到 HTTP `POST`请求。

# 示例-提交搜索

在下面的示例中，您将看到如何通过使用 HTML 表单的属性和元素来模拟表单提交。我们将使用位于[`hub.packtpub.com/`](https://hub.packtpub.com/)网站上的表单来发现有关 Go 编程语言（通常称为 GoLang）的文章。在[`hub.packtpub.com`](https://hub.packtpub.com)的主页上，有一个搜索框位于页面的左上角，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-web-scr-qk-st-gd/img/f8262a4d-c832-4b8e-80eb-b112ee0eeb3f.png)

通过右键单击搜索框，您应该能够使用浏览器的开发者工具检查元素。这会显示页面的 HTML 源代码，显示该框位于 HTML 表单中。在 Google Chrome 中，它看起来类似于下面的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-web-scr-qk-st-gd/img/aab70a2c-d612-4f8d-80eb-1911f3711ce1.png)

这个表单使用 HTTP `GET`方法，并提交到[`hub.packtpub.com/`](https://hub.packtpub.com/)端点。这个表单的值是从`<input>`标签中使用`name`属性作为键，搜索框中的文本作为值。因为这个表单使用`GET`作为方法，键值对被发送到服务器作为 URL 的查询部分。在我们的例子中，我们想要提交 GoLang 作为我们的搜索查询。为了做到这一点，当您点击按钮提交您的查询时，您的浏览器将发送一个`GET`请求到[`hub.packtpub.com/?s=Golang`](https://hub.packtpub.com/?s=Golang)。

结果页面将包含所有与 Go 相关的文章。您可以爬取标题、日期、作者等，以便保持 Go 文章的索引。通过定期提交此查询，您可以在发布时立即发现新文章。

# 示例-POST 方法

在前面的例子中使用的表单使用`GET`作为方法。假设，如果它使用`POST`方法，表单提交的方式将有所不同。您需要构建一个请求主体，而不是将值放在 URL 中。在下面的例子中，相同的表单和搜索查询将被构造为`POST`请求：

```go
package main

import (
  "net/http"
  "net/url"
)

func main() {
  data := url.Values{}
  data.Set("s", "Golang")

  response, err := http.PostForm("https://hub.packtpub.com/", data)

  // ... Continue processing the response ...
}
```

在 Go 中，您可以使用`url.Values`结构构建表单提交。您可以使用此功能设置表单的输入——在我们的例子中是`s=Golang`——并使用`http.Post()`函数提交它。如果表单使用`POST`作为其方法，这种技术将只有帮助。

# 避免循环

如果您正在构建一个遵循链接的网络爬虫，您可能需要知道您已经访问过哪些页面。您正在访问的页面很可能包含一个指向您已经访问过的页面的链接，将您带入一个无限循环。因此，非常重要的是在您的爬虫中构建一个跟踪系统，记录其历史。

存储唯一项目集合的最简单数据结构将是一个集合。Go 标准库没有集合数据结构，但可以通过使用`map[string]interface{}]`来模拟。

在 Go 中，`interface{}`是一个通用对象，类似于`java.lang.Object`。

在 Go 中，您可以定义一个地图如下：

```go
visitedMap := map[string]interface{}{}
```

在这种情况下，我们将使用访问的 URL 作为键，以及您想要的任何值。我们将只使用`nil`，因为只要键存在，我们就知道我们已经访问了该站点。添加我们已经访问的站点将简单地将 URL 插入为键，`nil`作为值，如下面的代码块所示：

```go
visitedMap["http://example.com/index.html"] = nil
```

当您尝试从地图中检索一个值时，Go 将返回两个值：如果存在，键的值和一个布尔值，说明键是否存在于地图中。在我们的例子中，我们只关心后者。

我们将检查类似于以下代码块中演示的站点访问：

```go
_, ok := visitedMap["http://example.com/index.html"]

if ok {
  // ok == true, meaning the URL exists in the visitedMap
  // Skip this URL
} else {
  // ok == false, meaning the URL does not exist in the visitedMap
  // Make the HTTP Request and continue processing this page
  // ...
} 
```

# 广度优先与深度优先爬行

现在，您可以导航到不同的页面，并且可以避免陷入循环，当爬行网站时，您还有一个重要的选择要做。一般来说，有两种主要方法可以通过跟随链接来覆盖所有页面：广度优先和深度优先。想象一下，您正在爬取一个包含 20 个链接的单个网页。自然地，您会跟随页面上的第一个链接。在第二页上，还有十个链接。在这里就是您的决定：跟随第二页上的第一个链接，还是返回到第一页上的第二个链接。

# 深度优先

如果您选择在第二页上跟随第一个链接，这将被视为深度优先爬行：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-web-scr-qk-st-gd/img/da7a1fd2-dfee-4cd0-9c7d-ce7f8233b4ca.png)

您的爬虫将继续尽可能深入地跟随链接以收集所有页面。在产品的情况下，您可能会跟随推荐或类似项目的路径。这可能会将您带到远离爬虫的原始起点的产品。另一方面，它也可能帮助快速构建相关项目的更紧密网络。在包含文章的网站上，深度优先爬行将迅速将您带回到过去，因为链接的页面很可能是对先前撰写的文章的引用。这将帮助您迅速到达许多链接路径的起源。

在第六章中，*保护您的网络爬虫*，我们将学习如何通过确保我们有适当的边界来避免深度优先爬行的一些陷阱。

# 广度优先

如果您选择在第一页上跟随第二个链接，这将被视为广度优先爬行：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-web-scr-qk-st-gd/img/f9a154db-834e-47a8-af96-2dddb69ced25.png)

使用这种技术，您很可能会在原始搜索域内停留更长时间。例如，如果您在一个包含产品的网站上搜索鞋子，页面上大多数链接都与鞋子相关。您将首先收集同一域内的链接。随着您在网站内部的深入，推荐项目可能会将您带到其他类型的服装。广度优先爬行将帮助您更快地收集完整的页面集群。

如何导航您的爬虫没有对错之分；这完全取决于您的具体需求。深度优先爬行将揭示特定主题的起源，而广度优先爬行将在发现新内容之前完成整个集群。如果这符合您的要求，您甚至可以使用多种技术的组合。

# 使用 JavaScript 导航

到目前为止，我们已经专注于简单的网页，所有所需的信息都只在 HTML 文件中。对于更现代的网站来说，情况并非总是如此，它们包含负责在初始页面加载后加载额外信息的 JavaScript 代码。在许多网站上，当您执行搜索时，初始页面可能会显示一个空表，并在后台发出第二个请求以收集要显示的实际结果。为了做到这一点，您的 Web 浏览器会运行 JavaScript 中编写的自定义代码。在这种情况下，使用标准的 HTTP 客户端是不够的，您需要使用支持 JavaScript 执行的外部浏览器。

在 Go 中，由于几个标准协议的存在，有许多选项可以将爬虫代码与 Web 浏览器集成。WebDriver 协议是由 Selenium 开发的最初的标准，并得到大多数主要浏览器的支持。该协议允许程序发送浏览器的命令，例如加载网页，等待元素，点击按钮和捕获 HTML。这些命令对于从通过 JavaScript 加载项目的网页收集结果是必要的。支持 WebDriver 客户端协议的一个库是 GitHub 用户`tebeka`的`selenium`。

# 示例 - 书评

在 Packt Publishing 网站上，书评是通过 JavaScript 加载的，在页面首次加载时是不可见的。此示例演示了如何使用`selenium`包从 Packt Publishing 网站上的书目录中爬取评论。

`selenium`包依赖于四个外部依赖项才能正常运行：

+   Google Chrome 或 Mozilla Firefox 网络浏览器

+   与 Chrome 或 Firefox 兼容的 WebDriver

+   Selenium 服务器二进制文件

+   Java

所有这些依赖项都将在安装期间由`selenium`脚本下载，除了 Java。

请确保您的计算机上已安装 Java。如果没有，请从[`www.java.com/en/download/help/download_options.xml`](https://www.java.com/en/download/help/download_options.xml)下载并安装官方版本。

首先，通过以下方式安装软件包：

```go
go get github.com/tebeka/selenium
```

这将在您的`GOPATH`中的`$GOPATH/src/github.com/tebeka/selenium`内安装`selenium`。此安装脚本依赖于其他一些软件包才能运行。您可以使用以下命令安装它们：

```go
go get cloud.google.com/go/storage
go get github.com/golang/glog
go get google.golang.org/api/option
```

接下来，我们安装代码示例需要的浏览器、驱动程序和`selenium`二进制文件。转到`selenium`目录内的`Vendor`文件夹，并通过运行以下命令完成安装：

```go
go run init.go
```

现在`selenium`及其所有依赖项都已设置好，您可以在`$GOPATH/src`中创建一个带有`main.go`文件的新文件夹。让我们逐步了解您需要编写的代码，以便收集一本书的评论。首先，让我们看一下`import`语句：

```go
package main

import (
  "github.com/tebeka/selenium"
)
```

正如您所看到的，我们的程序只依赖于`selenium`包来运行示例！接下来，我们可以看到`main`函数的开始，并定义一些重要的变量：

```go
func main() {

 // The paths to these binaries will be different on your machine!

  const (
    seleniumPath = "/home/vincent/Documents/workspace/Go/src/github.com/tebeka/selenium/vendor/selenium-server-standalone-3.14.0.jar"

  geckoDriverPath = "/home/vincent/Documents/workspace/Go/src/github.com/tebeka/selenium/vendor/geckodriver-v0.23.0-linux64"
  )
```

在这里，我们为`selenium`服务器可执行文件的路径和 Firefox WebDriver 的路径（称为`geckodriver`）渲染常量。如果您要使用 Chrome 运行此示例，您将提供路径到您的`chromedriver`。所有这些文件都是由之前运行的`init.go`程序安装的，您的路径将与此处写的路径不同。请确保更改这些以适应您的环境。函数的下一部分初始化了`selenium`驱动程序：

```go
  service, err := selenium.NewSeleniumService(
    seleniumPath, 
    8080, 
    selenium.GeckoDriver(geckoDriverPath))

  if err != nil {
    panic(err)
  }
  defer service.Stop()

  caps := selenium.Capabilities{"browserName": "firefox"}
  wd, err := selenium.NewRemote(caps, "http://localhost:8080/wd/hub")
  if err != nil {
    panic(err)
  }
  defer wd.Quit()
```

`defer`语句告诉 Go 在函数结束时运行以下命令。推迟清理语句是一个好习惯，这样您就不会忘记将它们放在函数的末尾！

在这里，我们通过提供它所需的可执行文件的路径以及我们的代码将与`selenium`服务器通信的端口来创建`selenium`驱动程序。我们还通过调用`NewRemote()`来获取与 WebDriver 的连接。`wd`对象是我们将用于向 Firefox 浏览器发送命令的 WebDriver 连接，如下面的代码片段所示：

```go
  err = wd.Get("https://www.packtpub.com/networking-and-servers/mastering-go")
  if err != nil {
    panic(err)
  }

  var elems []selenium.WebElement
  wd.Wait(func(wd2 selenium.WebDriver) (bool, error) {
    elems, err = wd.FindElements(selenium.ByCSSSelector, "div.product-reviews-review div.review-body")
    if err != nil {
      return false, err
    } else {
      return len(elems) > 0, nil
    }
  })

  for _, review := range elems {
    body, err := review.Text()
    if err != nil {
      panic(err)
    }
    println(body)
  }
}
```

我们告诉浏览器加载*Mihalis Tsoukalos*的*Mastering Go*网页，并等待我们的产品评论的 CSS 查询返回多于一个结果。这将一直循环，直到评论出现。一旦我们发现评论，我们就打印每一个评论的文本。

# 摘要

在本章中，我们介绍了如何通过网站导航您的网络爬虫的基础知识。我们研究了网页链接的结构，以及如何使用 HTTP `GET`请求来模拟跟踪链接。我们研究了 HTTP 表单（如搜索框）如何生成 HTTP 请求。我们还看到了 HTTP `GET`和`POST`请求之间的区别，以及如何在 Go 中发送`POST`请求。我们还介绍了如何通过跟踪历史记录来避免循环。最后，我们介绍了广度优先和深度优先网络爬行之间的差异，以及它们各自的权衡。

在第六章中，*保护您的网络爬虫*，我们将探讨在爬取网络时如何确保您的安全。


# 第六章：保护您的网络爬虫

现在您已经构建了一个能够自主从各种网站收集信息的网络爬虫，有一些事情您应该做以确保它的安全运行。应该采取一些重要措施来保护您的网络爬虫。正如您应该知道的，如果您没有完全拥有它，互联网上的任何东西都不应该完全信任。

在本章中，我们将讨论以下工具和技术，这些工具和技术将确保您的网络爬虫的安全：

+   虚拟私人服务器

+   代理

+   虚拟私人网络

+   白名单和黑名单

# 虚拟私人服务器

当您对网站发出 HTTP 请求时，您正在在您的计算机和目标服务器之间建立直接连接。通过这样做，您向他们提供了您计算机的公共 IP 地址，这可以用来确定您的大致位置和您的**互联网服务提供商**（**ISP**）。尽管这不能直接追溯到您的确切位置，但如果它落入错误的手中，它可能被恶意使用。考虑到这一点，最好不要将您的任何个人资产暴露给不受信任的服务器。

在远离您物理位置的计算机上运行您的网络爬虫，并具有某种远程访问，是将您的网络爬虫与个人电脑解耦的好方法。您可以从网络上的各种提供商租用**虚拟私人服务器**（**VPS**）实例。

一些更值得注意的公司包括以下内容：

+   **亚马逊网络服务**（**AWS**）

+   微软 Azure

+   谷歌云

+   DigitalOcean

+   Linode

这些公司将允许您创建一个虚拟机，并为您提供访问实例的凭据。它们有各种不同的产品，取决于您需要的机器大小，并且如果它们在某个特定大小以下，大多数公司都提供一些免费资源。

您需要将您的网络爬虫代码部署到这些机器上，并从 VPS 内运行程序。本书不会详细介绍 Go 应用程序的打包和部署，但以下是一些让您开始的技术：

+   **安全复制协议**（**SCP**）

+   Git

+   Ansible

+   木偶

+   Docker

+   Kubernetes

通过在 VPS 上操作网络爬虫，您可以放心，如果您的机器暴露了，它可以被安全地销毁，而不会危及您的个人电脑。此外，在 VPS 上运行爬虫可以让您轻松扩展以满足您在开始爬取更多网站时的需求。您可以启动多个 VPS 实例并并行运行您的爬虫。

# 代理

代理的作用是在您的系统之上提供额外的保护层。在其核心，代理是一个位于您的网络爬虫和目标网络服务器之间的服务器，并在两者之间传递通信。您的网络爬虫向代理服务器发送请求，然后代理服务器将请求转发到网站。从网站的角度来看，请求只来自代理服务器，而不知道请求的来源。有许多类型的代理可用，每种都有其优缺点。

# 公共和共享代理

一些代理是对公众开放的。然而，它们可以被许多不同的人共享。这会危及您的可靠性，因为如果其他用户通过滥用来危害代理，它可能会危及您的网络爬虫。对于公共代理，速度是另一个问题：通过代理的流量越多，可用带宽就越少。另一方面，这些代理是免费使用的，在测试和调试阶段可能会有用。

以下是一些列出公共代理的网站：

+   [`free-proxy-list.net`](https://free-proxy-list.net)

+   [`hidemyna.me`](https://hidemyna.me)

+   [`proxy-list.download`](https://proxy-list.download)

由于公共代理的成功率不同，您需要确保在生产中尝试之前进行研究。您需要考虑这些代理是否可靠，并且能否访问您的目标网站。您还需要确保在通过它们连接时您的信息得到保护。

# 专用代理

专用代理是确保只有您控制通过代理服务器流动的流量的绝佳方式。有许多公司提供按需和批量销售专用代理。一些值得考虑的公司包括以下内容：

+   风暴代理

+   炽热 SEO

+   Ghost 代理

+   Oxylabs

在选择公司时有一些要考虑的事项。

# 价格

专用代理的定价模型因公司而异。在大多数情况下，您按使用的 IP 地址付费，并且可以随意使用该 IP 地址。有许多公司拥有 IP 地址池，并将根据您的带宽收费。在这种定价模型中，您需要确保尽可能有效地进行调用。

每个 IP 代理的成本可能在每月 1 美元至 6 美元之间。通常，批量购买会获得更大的折扣。一些公司还可能限制您的带宽。

# 位置

偶尔，代理的位置对您可能很重要。许多代理公司在世界各地分布其服务器，以实现更广泛的覆盖范围。如果您在不同国家的网站上爬取数据，可能有必要通过该国家的代理来运行您的爬虫，以避免防火墙或异常流量签名。不同的国家也可能对该国家通过互联网允许的内容有不同的法律，因此在选择此路线之前，您应始终咨询当地法律。

# 类型

您应该了解的两种主要类型的代理是：住宅和数据中心代理。住宅代理具有由注册在住宅区域的 ISP 分配的 IP 地址。这些 IP 地址直接与特定地区相关，许多网站可以根据这些 IP 地址估计您的位置。这就是 Google Analytics 知道网站流量来自何处的方式。从网络爬取的角度来看，如果网站流量来自旧金山而不是伦敦，可能会有所不同。如果您的内容根据您的位置而变化，您可能需要在正确的位置使用住宅代理。

第二种类型的代理是数据中心代理。这些代理由与数据中心相关的 ISP 分配，例如 VSP 提供商。当您创建新的虚拟机时，分配给该机器的 IP 地址很可能是数据中心 IP。这些地址可能会被网站有意地阻止，以防止非住宅访客访问。

# 匿名性

在选择代理提供程序时，匿名性应被视为相当重要。并非所有代理在将数据传递给目标服务器时完全隐藏请求的来源源。

透明代理向目标服务器提供有关您身份的信息，在大多数情况下应该避免使用。这些代理将 HTTP 头传递给目标服务器，例如`X-Forwarded-For`：`<your_ip_address>`，以识别请求的来源源，以及`Via`：`<proxy_server>`以识别代理本身。

匿名代理提供与透明代理相同的头信息，但它们可能提供错误信息以隐藏您的真实身份。在这种情况下，目标服务器将意识到连接是通过代理进行的，但请求的真实来源是未知的。

精英代理是您可以从代理中获得的最高匿名级别。精英代理不会转发有关原始来源的任何信息，也不会透露请求来自代理的事实。相反，该请求对 Web 服务器来说看起来是来自代理的 IP 地址的正常请求。

# Go 中的代理

一旦您收到要使用的代理地址列表，配置 Go HTTP 客户端非常简单。Go HTTP 客户端包含一个称为**传输**的对象。传输负责与 Web 服务器进行低级通信，包括打开和关闭连接，发送和接收数据以及处理 HTTP 1XX 响应代码。您可以通过设置接受`*http.Request`并将代理地址返回为`*url.URL`的函数来设置传输的`Proxy()`方法。

以下是设置`Proxy()`函数的示例：

```go
package main

import (
  "math/rand"
  "net/http"
  "net/url"
)

// Public proxies from https://hidemyna.me
// These proxies are subject to frequent change.
// Please replace them if necessary.
var proxies []string = []string{
 "http://207.154.231.208:8080",
 "http://138.68.230.88:8080",
 "http://162.243.107.45:8080",
}

func GetProxy(_ *http.Request) (*url.URL, error) {
  randomIndex := rand.Int31n(int32(len(proxies)) - int32(1))
  randomProxy := proxies[randomIndex]
  return url.Parse(randomProxy)
}

func main() {
  http.DefaultTransport.(*http.Transport).Proxy = GetProxy
  // Continue with your HTTP requests ...
}
```

`GetProxy()`函数在三个配置的代理之间随机选择，并将字符串转换为`*url.URL`。通过配置`http.DefaultTransport.Proxy`函数，每次使用`http.DefaultClient`时，`GetProxy`将确定使用哪个随机代理。您还可以通过检查`*http.Request`并根据提供的主机名返回所需的代理，为不同的主机使用不同的代理。

# 虚拟私人网络

根据您的需求，您可能需要连接到**虚拟私人网络**（**VPN**）以确保您的网络爬虫流量全部隐藏。代理通过掩盖网络爬虫的 IP 地址提供了一层保护，而 VPN 还通过加密隧道掩盖了网络爬虫和目标站点之间流动的数据。这将使您正在抓取的内容对 ISP 和任何其他访问您网络的人都是不可见的。

并非所有国家都允许使用 VPN。请遵守当地法律。

有许多公司提供 VPN 访问，成本通常在每月 5 美元至 15 美元之间。

以下是一些推荐的公司：

+   Vypr VPN

+   Express VPN

+   IPVanish VPN

+   Nord VPN

配置您的网络爬虫使用 VPN 与代理不同。VPN 通常需要一个特定的客户端将您的机器连接到它们的网络，这不是通过代码完成的。优点是您使用网络爬虫编写的代码将独立于任何网络配置工作。不幸的是，您将无法在代码中使用 shell 命令进行网络的即时更改。

按照 VPN 提供商提供的说明连接到 VPN 网络。

# 边界

当您爬取网站时，您可能并不总是知道自己将去哪里。网页中的许多链接会带您前往您可能不太信任的外部网站。这些链接的页面可能包含无关的信息，也可能被用于恶意目的。重要的是为您的网络爬虫定义边界，以安全地浏览未知来源。

# 白名单

**白名单**域是一种明确允许您的网络爬虫访问某些网站的过程。白名单上列出的任何站点都可以让网络爬虫访问，而未列出的任何站点都将自动跳过。这是一种简单的方法，可以确保您的网络爬虫只访问一小组特定站点的页面，有助于收集非常专注的信息。您甚至可以通过仅允许访问网站的路径来进一步扩展。

使用 Go 构建白名单非常简单，可以使用 URL 和 path 包。让我们以在 Packt Hub 网站（[`hub.packtpub.com/`](https://hub.packtpub.com/)）上索引文章为例。这里发布的许多文章包含指向外部网站的链接，用于注明信息来源。但是，如果我们只对在 Packt Hub 上找到其他文章感兴趣，我们将只列出[hub.packtpub.com](http://hub.packtpub.com)的 URL。

您可能遇到的示例文章链接看起来可能是这样的：[`hub.packtpub.com/8-programming-languages-to-learn-in-2019/`](https://hub.packtpub.com/8-programming-languages-to-learn-in-2019/)。

使用 GoLang URL 包，我们可以查看主机名，以确定是否值得跟踪链接：

```go
parsedUrl, err := url.Parse("https://hub.packtpub.com/8-programming-languages-to-learn-in-2019")

if err != nil {
  panic(err)
}

site := parsedUrl.Host + parsedUrl.Path
```

然后，您可以使用`path.Match()`函数来验证是否匹配，如下所示：

```go
doesMatch, err := path.Match("hub.packtpub.com/*", site)
if err != nil {
  panic(err)
}
if doesMatch {
// Continue scraping …
}
```

# 黑名单

与白名单相反，**黑名单**定义了您的爬虫绝对不应该访问的网站。您可能希望在此处包括一些您知道不包含任何相关信息的地方，或者您对其内容不感兴趣的地方。您还可以暂时将正在遇到性能问题的站点列入黑名单，例如大量的 5XX 错误，如第二章中所讨论的*请求/响应循环*。您可以像前面的示例一样将链接 URL 与其主机名进行匹配。

所需的唯一更改是修改最后的`if`块，如下所示，以便仅在`doesMatch`为 false 时运行：

```go
if !doesMatch {
// Continue scraping …
}
```

# 总结

在本章中，我们回顾了许多不同的技术，以确保我们和我们的网络爬虫在浏览互联网时受到保护。通过使用 VPS，我们可以保护我们的个人资产免受恶意活动和在互联网上的可发现性。代理还有助于限制有关互联网流量来源的信息，提供了一层匿名性。VPN 通过为我们的数据创建加密隧道来增加了代理的额外安全层。最后，创建白名单和黑名单确保您的爬虫不会深入未知和不受欢迎的地方。

在第七章中，*并发爬取*，我们将看看如何使用并发来增加我们的网络爬虫的规模，而无需增加额外的资源成本。
