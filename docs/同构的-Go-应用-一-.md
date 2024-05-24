# 同构的 Go 应用（一）

> 原文：[`zh.annas-archive.org/md5/70B74CAEBE24AE2747234EE512BCFA98`](https://zh.annas-archive.org/md5/70B74CAEBE24AE2747234EE512BCFA98)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

2017 年 2 月，我在 GopherCon India 上做了一个关于同构 Go 的演讲。同构 Go 是使用 Go 编程语言创建同构 Web 应用程序的方法论。同构 Web 应用程序架构提升了用户体验，同时也提高了搜索引擎的可发现性。我的同构 Go 演讲受到了好评，一群全栈工程师在演讲后联系了我。

我会见的工程师们对于维护全栈 Web 应用程序代码库的复杂性表示了不满。他们抱怨不得不在后端使用 Go 和在前端使用 JavaScript 这两种截然不同的编程语言之间来回切换。每当他们不得不用 JavaScript 开发解决方案时，他们渴望 Go 语言的语法简洁、强大的标准库、并发构造以及开箱即用的类型安全性。

他们传达给我的信息是清楚明了的。他们渴望能够完全使用 Go 创建全栈 Web 应用程序。能够在一个统一的 Go 代码库中编写前端和后端的 Go 代码，这的确是一个诱人的提议。

由于我从会议上收集到的反馈，我为自己制定了两个行动项。首先，需要演示同构 Go Web 应用程序的能力。其次，需要详细解释同构 Go 背后的所有主要概念。

第一个行动项，演示同构 Go，成为了同构 Go 和 UX 工具包开源项目的起源——在撰写本文时，这些是创建 Go 同构 Web 应用程序最先进的技术。第一个在 Go 中创建的同构 Web 应用程序是 IGWEB 演示（可在[`igweb.kamesh.com`](http://igweb.kamesh.com)找到），这也是本书中展示的 Web 应用程序。

第二个行动项，解释主要的同构 Go 概念，最终成为了这本书。在观看了我的同构 Go 演讲后，Packt Publishing 联系我，给了我写这本书的机会，我很高兴地接受了。能够写一本关于我非常热衷的新兴技术的书，真是一次令人振奋的经历。

写这本书给了我一个机会，可以提出之前在 Go 编程领域从未涉及的想法和概念，比如内存模板集、端到端路由、同构交接、同构 Web 表单、实时 Web 应用功能、使用 Go 的可重用组件、编写端到端自动化测试来测试客户端功能，以及使用 Go 编写的同构 Web 应用程序的部署。

这本书的广泛深度确保我履行了对你这位读者的重要责任，为你的投资提供了高价值。这尤为重要，因为这恰好是关于同构 Go 的第一本也是唯一一本书。

这本书的重点是教会你如何从零开始创建一个同构 Go Web 应用程序。这本书是一次旅程，从介绍使用 Go 创建同构 Web 应用程序的优势开始，到将多容器同构 Go Web 应用程序部署到云端结束。

我希望你喜欢阅读这本书，并且它将成为你多年来的宝贵资源。

# 你需要为这本书做好准备

要编译本书附带的代码，你需要一台安装了 Go 发行版的操作系统的计算机。支持的操作系统列表以及系统要求可以在[`golang.org/doc/install#requirements`](https://golang.org/doc/install#requirements)找到。

# 这本书是为谁写的

本书面向具有 Go 编程语言先前经验并了解语言基本概念的读者。还假定读者具有基本网络开发的先前经验。不需要先前对等同构网络应用程序开发的知识。由于本书采用 Go 的成语化方法，因此读者不必具有使用 JavaScript 或 JavaScript 生态系统中的任何工具或库的先前经验。

# 约定

在本书中，您将找到一些区分不同信息类型的文本样式。以下是一些示例及其含义的解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："让我们检查`products_page.tmpl`源文件。"

代码块设置如下：

```go
{{ define "pagecontent" }}
{{template "products_content" . }}
{{end}}
{{template "layouts/webpage_layout" . }}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```go
func NewWidget() *Widget {
  w := &Widget{}
  w.SetCogType(cogType)
  return f
}
```

任何命令行输入或输出都以以下方式编写：

```go
$ go get -u github.com/uxtoolkit/cog
```

**新术语**和**重要单词**以粗体显示。例如，屏幕上显示的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中："这将向网页上的第一个“添加到购物车”按钮发送鼠标点击事件。"

警告或重要说明会以这种方式出现。

提示和技巧会以这种方式出现。


# 第一章：使用 Go 创建同构 Web 应用程序

同构 Web 应用程序是指 Web 服务器和 Web 浏览器（客户端）可能共享 Web 应用程序代码的全部或部分。同构 Web 应用程序允许我们从传统 Web 应用程序架构中获得最大的好处。它们提供了更好的用户体验，通过搜索引擎增强了可发现性，并通过在不同环境中共享 Web 应用程序代码的部分来降低运营成本。

成熟的企业，如 Airbnb、彭博社、Capital One、Facebook、谷歌、Netflix 和沃尔玛已经接受了同构 Web 应用程序开发，并且有充分的理由——财务底线。

沃尔玛的一项研究发现，他们每提高 1 秒的速度，就会增加 2%的转化率。此外，他们还发现，每提高 100 毫秒的速度，就会增加 1%的增量收入。来源：网站速度如何影响转化率（http://www.globaldots.com/how-website-speed-affects-conversion-rates/）。

同构 Go 是使用 Go 编程语言创建同构 Web 应用程序的方法论。在本书中，我们将深入探讨使用 Go 创建同构 Web 应用程序的过程。

本章将涵盖以下主题：

+   为什么你应该考虑使用同构 Go 来开发现代 Web 应用程序

+   传统 Web 应用程序架构概述

+   同构 Web 应用程序架构简介

+   何时实现同构 Web 应用程序

+   在学习同构 Go 之前你应该知道的事情

# 为什么选择同构 Go？

毫无疑问，JavaScript 是当前领先的技术，就市场份额和思想份额而言，用于创建同构 Web 应用程序。在客户端，JavaScript 已经包含在所有主要的 Web 浏览器中。由于 Node.js 的出现，JavaScript 现在也可以存在于服务器端。

如果是这样的话，那么为什么我们应该把注意力集中在使用 Go 来创建同构 Web 应用程序呢？这个问题的答案是多方面的。将这里提供的答案列表视为一个初始列表，这是我们讨论的起点：

+   Go 具有类型检查

+   即使是科技巨头也避免使用纯 JavaScript

+   将代码转换为纯 JavaScript 已经被广泛接受

+   Go 对前端 Web 开发有很多好处

# Go 具有类型检查

Go 是一种包含内置静态类型检查的语言。这个事实的直接影响是，许多错误可以在编译时被捕获。

对许多 JavaScript 开发人员来说，最大的痛点是 JavaScript 缺乏静态类型检查。我个人曾在跨越数十万行代码的 JavaScript 代码库中工作过，亲眼看到最微不足道的错误是如何由于缺乏静态类型检查而产生的。

# 通过转换器避免纯 JavaScript

为了避免编写纯 JavaScript，科技巨头微软和谷歌分别创建了 TypeScript 和 Dart 作为语言和转换器。**转换器**是一种源代码到源代码的编译器。

编译器将人类可读的代码，写成一种编程语言，转换成机器代码。转换器用于将源代码从一种编程语言转换为另一种语言。输出可能或可能不可读取，这取决于转换器的意图。

诸如 TypeScript 和 Dart 之类的语言被转换为纯 JavaScript 代码，以便在支持 JavaScript 的 Web 浏览器中运行。在 TypeScript 的情况下，它本质上是 JavaScript 的超集，引入了静态类型检查。AngularJS 框架的创建者选择了 TypeScript 而不是纯 JavaScript 作为开发其框架下一个主要版本的语言。

通过使用另一种编程语言和转译器来规避 JavaScript，为开发人员创造了双赢局面。开发人员可以使用对他们最有效的编程语言进行编程，而最终，开发人员创建的代码将得以在 Web 浏览器中运行——这要归功于转译器。

# 转译代码

将代码转译为 JavaScript 已经成为一种被广泛接受的做法，甚至在 JavaScript 社区内部也是如此。例如，Babel 转译器允许开发人员编写尚未发布的 JavaScript 语言未来标准，将其转译为目前在主要 Web 浏览器中支持的标准 JavaScript 代码。

在这种情况下，在 Web 浏览器中运行被转译为 JavaScript 代码的 Go 程序并不奇怪或牵强。事实上，除了静态类型检查之外，还有许多其他好处可以从能够在前端运行 Go 中获得。

# Go 在前端的好处

在前端使用 Go 具有许多优势，包括以下内容：

+   一个稳健的标准库

+   使用 Go 包进行代码模块化很容易

+   Go 附带了一个隐式构建系统

+   Go 的并发构造允许我们避免回调地狱

+   并发概念内置于 Go 中

+   Go 可用于同构 Web 应用程序开发

# 稳健的标准库

Go 附带了一个稳健的标准库，提供了许多强大的功能。例如，在 Go 中，我们可以渲染内联客户端模板，而无需包含任何第三方模板库或框架。我们将在第三章中考虑如何做到这一点，*使用 GopherJS 在前端上使用 Go*。

# 使用 Go 包促进模块化

Go 具有强大的包实现，促进了模块化，允许更大程度的代码重用和可维护性。此外，Go 工具链包括`go get`命令，允许我们轻松获取官方和第三方 Go 包。

如果你来自 JavaScript 世界，把`go get`想象成一个更简单、更轻量级的`npm`（`npm`是 Node 包管理器，一个第三方 JavaScript 包的存储库）。

# 隐式构建系统

在 JavaScript 生态系统中，现代开发人员仍然流行手动创建和维护项目构建文件。作为一种现代编程语言，Go 附带了一个隐式构建系统。

只要遵循 Go 的约定，并且一旦为 Go 应用程序发出`go build`命令，隐式构建系统就会启动。它将通过检查应用程序 Go 源代码中找到的依赖项，自动构建和编译 Go 项目。这为开发人员提供了重大的生产力提升。

# 避免回调地狱

也许考虑使用 Go 进行同构 Web 开发最具吸引力的原因是避免*回调地狱*。JavaScript 是一种单线程编程语言。当我们想要在异步调用之后延迟执行特定任务时，我们会将这些任务的代码放在回调函数中。

很快，我们要延迟执行的任务列表将增长，嵌套回调函数的数量也将随之增长。这种情况被称为*回调地狱*。

我们可以使用 Go 的内置并发构造来避免回调地狱。

# 并发

Go 是一种现代编程语言，旨在在多核处理器和分布式系统的时代保持相关性。它的设计并不是将并发的重要性作为事后的想法。

事实上，并发对于 Go 的创建者来说非常重要，以至于他们将并发直接构建到语言本身中。在 Go 中，我们可以避免回调地狱，使用 Go 的内置并发构造：goroutines 和 channels。**Goroutines**是廉价、轻量级的线程。**Channels**是允许 goroutines 之间通信的通道。

# 使用 Go 进行等同于 Web 应用程序开发

在等同于 Web 应用程序开发方面，JavaScript 不再是唯一的选择。由于最近的技术进步，特别是**GopherJS**的创建，我们现在可以在前端使用 Go 编程语言；这使我们能够在 Go 中创建等同于 Web 应用程序。

**等同于 Go**是一种新兴技术，它为我们提供了创建等同于 Web 应用程序所需的基本要素，利用了 Go 编程语言提供的强大和高效的功能。在本书中，我们将使用 Go 标准库的功能和 Go 社区的第三方库来实现等同于 Web 应用程序。

# Web 应用程序架构概述

为了理解和充分欣赏等同于 Web 应用程序的架构，有必要了解其前身的 Web 应用程序架构。我们将介绍过去 25 年在行业中流行的主要 Web 应用程序架构。

毕竟，直到我们完全承认我们所在的位置，我们才能真正欣赏到我们所到达的地方。随着多年来 Web 应用程序架构领域发生的重大变化，有很多值得承认的地方。

在介绍等同于 Web 应用程序架构之前，让我们花些时间回顾它之前的三种传统 Web 应用程序架构：

+   经典 Web 应用程序架构

+   AJAX Web 应用程序架构

+   **单页应用程序**（**SPA**）架构

我们将确定考虑的三种架构的优缺点。我们将根据我们为给定架构确定的每个缺点开始一个需求愿望清单。毕竟，缺点实际上是改进的机会。

# 经典 Web 应用程序架构

**经典 Web 应用程序架构**可以追溯到上世纪 90 年代初，当图形 Web 浏览器开始流行起来。当用户使用 Web 浏览器与 Web 服务器进行交互时，每个用户交互都会使用 HTTP 向 Web 服务器发出请求。*图 1.1*描述了经典 Web 应用程序架构。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/2864d216-af37-499e-9c57-18db57a61689.png)

图 1.1：经典 Web 应用程序架构

该图还描述了一个 HTTP 事务，其中包括用户的 Web 浏览器发送到 Web 服务器的请求。一旦 Web 服务器接受了请求，它将返回相应的响应。

通常，响应是一个 HTML 网页，它可能包含内联 CSS 和/或 JavaScript，或者调用外部 CSS 样式表和/或 JavaScript 源文件。

Web 服务器可以以响应的形式返回两种类型的资源：静态资源和动态资源。

**静态资源**是一个文件。例如，它可以是存储在 Web 服务器上的 HTML、JPEG、PDF 或 MP4 文件。服务器将在其响应主体中返回请求指定的文档。

**动态资源**是服务器动态生成的资源。动态资源的一个例子是搜索引擎的搜索结果页面。通常，动态请求的响应主体将以 HTML 格式进行格式化。

当涉及到 Web 应用程序时，我们处理动态资源。Web 服务器正在提供 Web 应用程序，通常 Web 应用程序包含一个控制器，该控制器包含将用户请求路由到服务器上执行的特定操作的逻辑。一旦 Web 服务器处理完用户的请求，服务器会以 Web 页面响应的形式将响应发送回客户端。

服务器端编程语言（如 Go、Perl、PHP、Python、Ruby 和 Java）用于处理从 Web 浏览器发送的请求。例如，让我们考虑一个用于电子商务网站的服务器端 Web 应用程序。

Web 应用程序可以通过使用服务器端的**路由处理程序**（如*图 1.1*所示）路由请求；`/product-detail/swiss-army-knife`路由可以与产品详细信息控制器相关联，该控制器将提供包含瑞士军刀产品概要页面的 HTML 网页响应。

在经典的 Web 应用程序架构中，用于呈现 Web 页面的代码位于服务器端，通常整合到模板文件中。从一组模板呈现 Web 页面响应是由驻留在服务器上的**模板渲染器**执行的（如*图 1.1*所示）。

通常在这种范式中，JavaScript 可能会包含在呈现的 Web 页面中以增强用户体验。在这种 Web 应用程序架构中，实施 Web 应用程序的责任主要放在服务器端语言上，JavaScript 主要用于用户界面控件或网站的增强用户交互，放在次要位置。

# 优势

经典 Web 应用程序架构具有两个主要优势：

+   更快的初始页面加载

+   更好的搜索引擎可发现性

# 更好的搜索引擎可发现性

经典 Web 应用程序架构的第二个主要优势是这种架构对搜索引擎友好，因为 Web 应用程序提供了可以被搜索引擎机器人轻松消化的 HTML 网页响应。除此之外，服务器端路由处理程序允许创建与特定服务器端控制器相关联的搜索引擎友好的 URL。

使网站对搜索引擎友好的关键因素是可发现性。除了拥有优质内容外，搜索引擎友好的网站还需要永久链接 - 旨在永久保持服务的网页链接。描述性良好的 URL 可以在服务器端的路由器中注册为路由。这些路由最终成为永久链接，搜索引擎机器人爬虫可以在浏览网站时轻松索引。

目标是拥有美观的网站 URL，其中包含有意义的信息，可以轻松被搜索引擎的机器人爬虫索引，例如：`http://igweb.kamesh.com/product-detail/swiss-army-knife`。

上述永久链接比以下链接更容易被搜索引擎索引和人类理解：`http://igweb.kamesh.com/webapp?section=product-detail&amp;product_id=052486`。

# 更快的初始页面加载

经典 Web 应用程序架构的第一个主要优势是用户认为页面加载速度快，因为整个页面一次性呈现。这是由于 Web 服务器在服务器端使用模板渲染器呈现 Web 页面响应的结果。

用户不会感知到缓慢，因为他们立即从服务器接收到呈现的页面。

请记住，如果服务器的响应时间延迟很高，那么用户交互将停滞不前。在这种情况下，快速的初始页面加载优势将丧失，因为用户必须盯着空白屏幕等待服务器完成处理。这种等待将以 Web 页面响应被交付给用户或 HTTP 请求超时而结束，以先到者为准。

# 主要的缺点

我们将在本章中考虑的传统 Web 应用程序架构中检查每种传统 Web 应用程序架构的主要缺点。本章的*同构 Web 应用程序架构*部分将向我们展示同构 Web 应用程序架构如何为每个提出的缺点提供解决方案，并收集每种传统 Web 应用程序架构提供的好处。

经典 Web 应用程序架构的主要缺点是，所有用户交互，甚至最微不足道的交互，都需要完整的页面重新加载。

这意味着**文档对象模型**（**DOM**），表示当前网页状态的树形数据结构以及组成它的元素，在每次用户交互时都会被完全清除，并重新创建：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/607435db-ddc5-4849-9eea-0ae2f645f355.png)

图 1.2：新闻网站的布局图和评论部分的线框图

例如，让我们假设我们正在阅读新闻网站上的一篇文章。*图 1.2*描述了新闻网站的布局图（左侧的插图），网页底部是网站的评论部分。其他部分可能存在于布局中的负（空）空间中。

*图 1.2*还包括新闻评论部分的线框设计（右侧的插图），其中包含一些示例评论。省略号（...）表示出于简洁起见未列出的多个网站评论。

让我们考虑这样一个情景，这篇特定的新闻文章已经变得非常火爆，包含超过 10,000 条评论。评论是分页的，每页显示 50 条评论：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/0687777b-b22a-4e9c-980f-b407a6a171c2.png)

图 1.3：查看下一组评论需要整个网页刷新

*图 1.3*描述了新闻网站的网页被刷新（左侧的插图）。请注意，用户会感觉刷新很快，因为页面会立即加载（考虑到网络延迟很低）。*图 1.3*还描述了点击下一个链接后（右侧的插图）下一批 50 篇文章。

如果我们点击分页导航控件上的下一个链接，将导致整个页面重新加载，这将销毁 DOM 并重新创建。由于评论位于屏幕底部，在整个页面重新加载时，滚动位置也可能会回到网页顶部，导致用户体验不佳。

我们只想在页面底部看到下一组评论。我们并不打算整个网页重新加载，但它确实重新加载了，这就是经典 Web 应用程序架构的主要局限性。

**愿望清单项目＃1：**为了增强用户体验，点击网站上的链接不应导致整个页面重新加载。

# AJAX Web 应用程序架构

随着**XMLHttpRequest**（**XHR**）对象的出现，**异步 JavaScript 和 XML**（**AJAX**）时代开始了。*图 1.4*说明了 AJAX Web 应用程序架构。

客户端的初始请求后，服务器发送回一个包含 HTML、CSS 和 JavaScript 的网页响应。一旦网页加载完成，客户端的 JavaScript 应用程序可以通过 XHR 对象发起 HTTP 异步请求回到 Web 服务器。

一些观察者将 AJAX 的出现描述为*Web 2.0 时代*，在这个时代，网站变得更加互动，用户体验更加丰富，JavaScript 库的使用开始获得关注。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/5b063664-99ed-44f9-aa20-ea8a800ec367.png)

图 1.4：AJAX Web 应用程序架构

由于 XHR 调用是异步的，它们不会阻塞在 Web 浏览器中运行的单线程 JavaScript 应用程序。一旦从服务器收到给定 XHR 请求的响应，就可以对从服务器返回的数据采取行动。

# 主要优势

AJAX Web 应用程序架构的主要优势是它消除了执行完整页面重新加载的需要。

在我们考虑的新闻文章网页有 10,000 多条评论的情况下，我们可以编写 Web 应用程序，在按下“下一页”按钮时发起 XHR 调用，然后服务器可以发送包含要显示的下一组评论的 HTML 片段。一旦我们收到下一组评论，我们可以使用 JavaScript 动态更新 DOM，完全避免执行完整的页面重新加载！

*图 1.5*说明了这种方法。最左边的插图描述了评论部分中的评论。中间的插图只描述了更新的评论部分。最后，右边的插图描述了加载到评论部分的下一批评论：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/58d8dbdc-911a-4e7a-bc69-a59cc3202fd2.png)

图 1.5：当单击“下一页”链接时，只更新新闻网站的评论部分，避免了完整的页面刷新

正如您所看到的，这种方法的主要优势是我们避免了完整的页面重新加载，从而增强了用户体验。请记住，在某些情况下，例如浏览网站的不同部分，仍然可能发生完整的页面重新加载。

# 缺点

AJAX Web 应用程序架构具有以下缺点：

+   处理两种编程语言之间的心理上下文转换

+   通过逐步客户端渲染引入的复杂性

+   工作重复

# 心理上下文转换

当涉及到开发人员的生产力时，我们现在引入了一种心理上下文转换（也称为认知转换），假设后端服务器端语言不是 JavaScript。例如，让我们假设我们的后端应用程序是用 Go 实现的，前端应用程序是用 JavaScript 实现的。现在，开发人员将不得不精通服务器端语言（Go）和客户端语言（JavaScript），除了语法上的差异之外，它们可能具有不同的指导理念和习惯用法。

这对于负责维护代码库的全栈开发人员来说是一种心理上下文转换。组织立即解决心理上下文转换问题的一种方法是动用资金。如果组织有能力这样做，它可以承担增加的运营成本，并至少指定一个开发人员负责前端，一个开发人员负责后端。

**愿望清单项目＃2：**为了增加可维护性，应该有一个单一的、统一的项目代码库，使用单一的编程语言实现。

# 增加的渲染复杂性

除了引入处理两种不同编程语言的心理上下文转换之外，我们现在增加了渲染复杂性的级别。在经典的 Web 应用程序架构中，从服务器响应接收到的渲染的网页从未被改变。事实上，一旦发起新的页面请求，它就被清除了。

现在，我们以逐步方式从客户端重新渲染网页的部分，这要求我们实现更多的逻辑来进行（并跟踪）对网页的后续更新。

**愿望清单项目＃3：**为了增加效率，应该有一种机制来执行分布式模板渲染。

# 工作重复

AJAX Web 应用程序架构在服务器端和客户端之间引入了工作重复。比如，我们想要在新闻文章中添加新评论。填写表单后，为了添加新评论，我们可以发起一个 XHR 调用，将要添加的新评论发送到服务器。服务器端 Web 应用程序随后可以将新评论持久保存到数据库中，其中存储了所有评论。我们可以立即更新评论部分，以包括刚刚添加的新评论，而不是刷新整个网页。

计算机编程的一个基本原则，特别是在 Web 编程中，就是不要相信用户输入。让我们考虑一种情况，用户可能在评论框中输入了一组无效字符。我们将不得不实现一些类型的验证，既在客户端又在服务器端检查用户的评论。这意味着我们将不得不在 JavaScript 中实现客户端表单验证，并在 Go 中实现服务器端表单验证。

在这一点上，我们在两种不同的操作环境中引入了两种编程语言的工作重复。除了我们刚刚考虑的例子，可能还有其他需要在这种架构路径上进行工作重复的情况。这恰好是 AJAX Web 应用程序架构的一个主要缺点。

**愿望清单项目＃4：**为了提高生产力，应该有一种方法在不同环境之间共享和重用代码，以避免工作重复。

# 单页应用程序（SPA）架构

2004 年，**万维网联盟**（**W3C**）开始制定新的 HTML 标准，这将是 HTML5 的前身。2010 年，HTML5 开始加速发展，规范中的功能开始进入主要的 Web 浏览器，HTML5 功能变得非常流行。

HTML5 的主要卖点是引入功能，使 Web 应用程序能够更像本机应用程序。通过 JavaScript 可以访问一组新的 API。这些 API 包括在用户设备上本地存储数据的功能，更好地控制前进和后退按钮（使用 Web 浏览器的历史 API），用于呈现图形的 2D 画布，以及包括比其前身更强大功能的 XHR 对象的第二个版本。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/afac4340-c6a5-4165-b267-2b883bea71cc.png)

图 1.6：单页应用程序（SPA）架构

在 2010 年代初，开始出现了 JavaScript 框架，这有助于开发一种新型架构，即 SPA 架构。这种架构，如*图 1.6*所示，专注于*fat client*和*thin server*策略。其思想是从服务器端删除任何类型的模板渲染的责任，并将所有**用户界面**（**UI**）渲染分配给客户端。在这种架构中，服务器和客户端的职责有明确的分离。

SPA 架构消除了用户界面责任的工作重复。它通过将所有 UI 代码整合到客户端来实现这一点。这样做消除了服务器端在用户界面方面的工作重复。如*图 1.6*所示，用户界面的责任完全由客户端承担。

服务器最初返回一个包含 JavaScript 和客户端模板的有效负载。JavaScript 有效负载可能会被*聚合*，这意味着组成 Web 应用程序的所有 JavaScript 源文件可以合并成一个 JavaScript 源文件。除此之外，JavaScript 有效负载还可能被**缩小**。

**缩小**是从源代码中删除任何不必要字符的过程，这可能包括在不改变源代码功能的情况下重命名源代码中的标识符，以减少其存储占用空间。

一旦 Web 浏览器完全下载了 JavaScript 负载，JavaScript 代码的首要任务是在客户端上引导 JavaScript 应用程序，渲染用户界面。

# 搜索引擎可发现性降低

使用 SPA 架构可能会降低搜索引擎的可发现性。由于在客户端动态渲染内容的性质，一些 SPA 实现可能无法生成易于搜索引擎爬虫消费的格式良好的 HTML 内容，这些爬虫通常只用于消费初始网页响应。

搜索引擎爬虫可能无法渲染网页，因为它可能没有配备 JavaScript 运行时。没有完全渲染的网页内容，爬虫无法有效地执行其消费网页内容的职责。

除此之外，SPA 实现使用片段标识符处理路由，这种方法对搜索引擎不友好。

让我们回到我们的电子商务 Web 应用程序示例。在经典和 AJAX Web 应用程序架构中，我们的 Web 应用程序可能具有以下 URL：`http://igweb.kamesh.com/product-detail/swiss-army-knife`。

在 SPA 实现的情况下，带有片段标识符的 URL 可能如下所示：

`http://igweb.kamesh.com/#section=product_detail&amp;product=swiss-army-knife`

这个 URL 对于搜索引擎爬虫来说很难索引，因为片段标识符（#符号后面的字符）是用来指定给定网页内的位置的。

片段标识符旨在提供单个网页部分内的链接。片段标识符影响 Web 浏览器的历史，因为我们可以在 URL 上附加唯一标识符。这有效地防止用户遇到完整的页面重新加载。

这种方法的缺点是 HTTP 请求中不包括片段标识符，因此从 Web 服务器的角度来看，URL `http://igweb.kamesh.com/webapp#orange`和 URL `http://igweb.kamesh.com/webapp#apple`指向相同的资源：`http://igweb.kamesh.com/webapp`。

搜索引擎爬虫必须以更复杂的方式实现，以处理包含片段标识符的网站的索引复杂性。尽管谷歌在解决这个问题上取得了相当大的进展，但实现不带片段标识符的 URL 仍然是推荐的最佳实践，以确保网站能够被搜索引擎轻松索引。

值得注意的是，在某些情况下，SPA 架构可能会通过使用更现代的实践来克服这一劣势。例如，更近期的 SPA 实现完全避免了片段标识符，而是使用 Web 浏览器的 History API 来拥有更友好的搜索引擎 URL。

**愿望清单项目＃6：**为了促进可发现性，网站应提供易于搜索引擎爬虫消费的格式良好的 HTML 内容。网站还应包含易于搜索引擎爬虫索引的链接。

# 主要优势

SPA 架构的主要优势在于它提供了客户端路由，防止了整个页面的重新加载。客户端路由涉及拦截给定网页上超链接的点击事件，以便它们不会发起新的 HTTP 请求到 Web 服务器。客户端路由器将给定路由与负责处理路由的客户端路由处理程序相关联。

例如，让我们考虑一个实现了客户端路由的电子商务网站。当用户点击链接到瑞士军刀产品详情页面时，不会启动完全重新加载页面，而是向 Web 服务器的 REST API 端点发出 XHR 调用。端点以 JavaScript 对象表示法（JSON）格式返回有关瑞士军刀的配置数据，客户端应用程序用于呈现瑞士军刀产品详情页面的内容。

从用户的角度来看，体验是无缝的，因为用户不会经历在完全重新加载页面时遇到的突然的白屏。

# 缺点

SPA 架构具有以下缺点：

+   最初的页面加载被认为是较慢的

+   降低搜索引擎的可发现性

# 较慢的初始页面加载

基于 SPA 的 Web 应用程序的初始页面加载可能被认为是缓慢的。这种缓慢可能是由于初始下载聚合 JavaScript 有效载荷所需的时间而导致的。

传输控制协议（TCP）具有缓慢启动机制，其中数据以段的形式发送。JavaScript 有效载荷在完全传递到 Web 浏览器之前，需要在服务器和客户端之间进行多次往返：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/f4bc0017-3e81-4ff6-9c82-31dea3279a3d.png)

图 1.7：由于用户被加载指示器所招呼，初始页面加载被认为是缓慢的，而不是呈现的网页

这导致用户必须等待 JavaScript 有效载荷完全获取，然后网页才能完全呈现。使用加载指示器（如旋转的轮子）是一种常见的用户体验（UX）实践，让用户知道用户界面仍在加载中。

*图 1.7*包括一个插图（左侧）显示加载指示器，以及一个插图（右侧）显示加载的网页布局。重要的是要注意，根据 SPA 的实现方式，可能会在构成网页的各个部分中分布多个加载指示器。

我相信，在您自己的网络浏览中，您可能已经使用过包含这些加载旋转器的 Web 应用程序。从用户的角度来看，我们可以同意，理想情况下，我们宁愿看到呈现的输出，而不是旋转的轮子。

**愿望清单项目＃5：**为了给用户留下最好的第一印象，网站应该能够立即向用户显示内容。

# 同构 Web 应用程序架构

**同构 Web 应用程序架构**包括在服务器端和客户端分别实现两个 Web 应用程序，使用相同的编程语言并在两个环境中重用代码：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/6567eb2b-b96e-46d8-b63a-a8718516213c.png)

图 1.8：同构 Web 应用程序架构

如图 1.8 所示，业务逻辑可以在不同环境中共享。例如，如果我们定义了一个“产品”结构来模拟我们电子商务网站上的产品，服务器端和客户端应用程序都可以知道它。

除此之外，模板渲染器存在于服务器端和客户端，因此模板也可以在不同环境中进行渲染，使模板成为“同构”。

“同构”一词可用于描述可以在不同环境之间共享的任何内容（业务逻辑、模板、模板函数和验证逻辑）。

服务器端路由处理程序负责在服务器端服务路由，客户端路由处理程序负责在客户端服务路由。当用户最初访问使用同构 Web 应用程序架构实现的网站时，服务器端路由处理程序启动并使用服务器端模板渲染器生成网页响应。

网站的后续用户交互是在 SPA 模式下使用客户端路由进行的。客户端路由处理程序负责为给定的客户端路由提供服务，并使用客户端模板渲染器将内容呈现到网页（用户界面）上。

客户端应用程序可以发起 XHR 请求到 Web 服务器上的 Rest API 端点，从服务器的响应中检索数据，并使用客户端模板渲染器在网页上呈现内容。

同构的 Go Web 应用程序可以选择使用 WebSocket 连接，如*图 1.8*所示，用于 Web 服务器和 Web 浏览器之间的持久、双向通信。同构的 Go Web 应用程序还具有以`gob`格式发送和接收数据的额外好处——`gob`是 Go 的二进制编码数据格式。可以使用标准库中的`encoding/gob`包对数据进行编码和解码为`gob`格式。

Gob 编码的数据比 JSON 具有更小的数据存储占用空间。

`gob`格式的主要优势是其较小的存储占用空间。JSON 数据是文本格式，众所周知，文本格式的数据在与二进制编码格式相比需要更大的存储占用空间。通过在客户端和服务器之间交换较小的数据负载，Web 应用程序在传输数据时可以获得更快的响应时间。

# 愿望清单已实现

同构的 Web 应用架构为三种传统 Web 应用架构中发现的所有缺点提供了解决方案。让我们盘点一下我们在愿望清单上放置的项目：

1.  为了**增强用户体验**，在网站上点击链接不应导致全页重新加载。

1.  为了**增加可维护性**，应该有一个单一、统一的项目代码库，使用单一编程语言实现。

1.  为了**提高效率**，应该有一种分布式模板渲染的机制。

1.  为了**提高生产力**，应该有一种方式在不同环境中共享和重用代码，以避免重复劳动。

1.  为了**给出最好的第一印象**，网站应该能够迅速向用户显示内容。

1.  为了**提高可发现性**，网站应提供易于搜索引擎机器人消费的格式良好的 HTML 内容。网站还应包含易于搜索引擎机器人索引的链接。

现在，是时候检查同构的 Web 应用架构如何满足我们愿望清单上的每一项了。

# 1. 提升用户体验

在初始服务器端呈现的网页响应之后，同构的 Web 应用架构通过以 SPA 模式运行来增强用户体验。客户端路由用于网站的后续用户交互，防止全页重新加载，并增强网站的用户体验。

# 2. 增加可维护性

由于同构的 Web 应用架构使用单一编程语言来实现客户端和服务器端的 Web 应用程序，因此项目代码库的可维护性得到了加强。这可以避免在不同环境中处理两种不同编程语言时发生的心理上下文转换。

# 3. 增加效率

同构的 Web 应用架构通过提供分布式模板渲染机制——同构模板渲染器，增加了呈现内容的效率。如*图 1.8*所示，由于服务器端和客户端都有模板渲染器，模板可以在不同环境中轻松重用。

# 4. 增加生产力

同构 Web 应用程序架构的标志是单一统一的代码库，提供了许多机会在不同环境之间共享代码。例如，表单验证逻辑可以在不同环境之间共享，允许在客户端和服务器端使用相同的验证逻辑验证 Web 表单。还可以在客户端和服务器端之间共享模型和模板。

# 6. 促进可发现性

同构 Web 应用程序架构促进了可发现性，因为它可以轻松提供格式良好的 HTML 内容。请记住，Go 模板的渲染输出是 HTML。

使用同构模板渲染器，HTML 内容可以在客户端和服务器端轻松渲染。这意味着我们可以为传统搜索引擎爬虫提供格式良好的 HTML 内容，这些爬虫只是简单地抓取网页内容，以及为可能配备 JavaScript 运行时的现代搜索引擎爬虫提供格式良好的 HTML 内容。

同构 Web 应用程序架构促进可发现性的另一种方式是应用程序的路由处理程序（服务器端和客户端）可以定义格式良好的 URL，并且这些 URL 可以轻松被搜索引擎爬虫索引。

这是可能的，因为客户端实现的路由处理程序利用 Web 浏览器的 History API 来匹配服务器端定义的相同路由。例如，瑞士军刀产品详情页面的`/product-detail/swiss-army-knife`路由可以由服务器端和客户端路由器注册。

# 5. 给出最好的第一印象

同构 Web 应用程序架构使用服务器端渲染初始网页响应，确保用户在访问网站时立即看到内容。对于与用户的第一次接触，同构 Web 应用程序架构借鉴了经典 Web 应用程序架构的方法，提供初始网页响应。

这对用户来说是一个受欢迎的好处，因为内容会立即显示给他们，用户会感知到快速加载页面的结果。这与 SPA 架构形成鲜明对比，因为在 SPA 架构中，用户必须等待客户端应用程序引导完成后才能在屏幕上看到网页内容出现。

# 实时演示

现在是时候看同构 Web 应用程序架构的实际效果了。我们将在本书的过程中实施的网站 IGWEB 的实时演示可在[`igweb.kamesh.com`](http://igweb.kamesh.com)上找到。*图 1.9*是网站首页的截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/d9a58ed0-9559-4676-8e20-b2a24c4f5a11.png)

图 1.9：IGWEB：使用同构 Go 实现的网站

请注意，在*以上折叠*区域（在浏览器窗口中可见的区域）中的内容会立即显示。此外，当通过导航菜单中的链接导航到网站的不同部分时，请注意网站的响应性。我们将在下一章为您详细介绍 IGWEB 项目。

在撰写本文时，IGWEB 已经验证可以在以下 Web 浏览器中运行：Google Chrome 版本 62.0，Apple Safari 版本 9.1.1，Mozilla Firefox 57.0 和 Microsoft Edge 15.0。建议您使用与此列表中提供的版本相同或更高版本的 Web 浏览器。

# 可衡量的好处

本书介绍的使用 Go 开发同构 Web 应用程序的方法已经被证明在提供增强用户体验方面具有可衡量的好处。

我们可以使用 Google PageSpeed Insights 工具（[`developers.google.com/speed/pagespeed/insights/`](https://developers.google.com/speed/pagespeed/insights/)）来评估 IGWEB 首页的性能。该工具根据网页内容的组织、静态资产的大小和呈现网页所需的时间等各种标准，评估网页提供良好用户体验的程度，评分从 0 到 100。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/f6b3afb1-039b-482c-9787-c9b62c27d754.png)

图 1.10：通过 Google PageSpeed Insights 工具运行 IGWEB 首页的结果

*图 1.10*是一个屏幕截图，显示了评估 IGWEB 桌面版的结果。在撰写本文时，IGWEB 在桌面浏览体验方面得分为 97/100，在移动浏览体验方面得分为 91/100。根据该工具，桌面和移动版均达到 90+分，表明 IGWEB 首页*应用了大多数性能最佳实践，并应该提供良好的用户体验*。

# 命名

我在**GopherCon India**上的开场演讲中使用了“等同 Go”作为标题，主题是在 Go 中开发等同 Web 应用程序。我的演讲标题是受到“等同 JavaScript”一词的启发。术语“等同 JavaScript”是由 Charlie Robbins 在他 2011 年的博客文章中创造的（[`blog.nodejitsu.com/scaling-isomorphic-javascript-code/`](https://blog.nodejitsu.com/scaling-isomorphic-javascript-code/)），*Scaling Isomorphic JavaScript Code*。

“等同”一词源自数学。在希腊语中，iso 意为相等，morphosis 意为形成或塑造。

JavaScript 社区内存在关于使用术语“等同”的辩论，用来描述一个包含可以在客户端或服务器上运行的代码的 Web 应用程序。JavaScript 社区的一些成员更喜欢使用术语“universal”。

在我看来，术语“等同”更合适，而术语“universal”引入了歧义。这种歧义源于“universal”一词带有一些附加含义。

苹果广泛使用术语“通用二进制”来描述包含多个处理器架构的机器代码的 fat 二进制文件。现代 JavaScript 代码通过即时编译器编译为机器代码。

因此，使用术语“universal”是模棱两可的，并且需要额外的细节来确定其使用的上下文。因此，本书中将使用的首选术语是“等同”。

# 先决条件

本书侧重于教授如何使用 Go 编程语言创建等同 Web 应用程序。由于我们将采用一种以 Go 为重点的成语化方法，因此不需要事先熟悉 JavaScript 生态系统中的库和工具。

我们假设读者在 Go 或其他服务器端编程语言方面具有一定的先前编程经验。

如果您以前从未在 Go 中编程，我建议您参考[`tour.golang.org`](https://tour.golang.org)上提供的《Go 之旅》。

要更深入地学习基本的 Go 概念，我建议您观看我的视频课程《全栈 Web 开发的 Go 基础》，*Packt Publishing*，可在[`www.packtpub.com/web-development/go-essentials-full-stack-web-development-video`](https://www.packtpub.com/web-development/go-essentials-full-stack-web-development-video)上找到。

# 总结

在本章中，我们介绍了等同 Go。我们介绍了 Go 编程语言提供的许多优势，以及为什么它是创建等同 Web 应用程序的一个引人注目的选择。

我们回顾了传统的 Web 应用程序架构，包括经典的 Web 应用程序架构、AJAX 应用程序架构和 SPA 架构。我们确定了每种传统架构的优缺点。我们介绍了同构 Web 应用程序架构，并展示了它是如何解决传统架构的所有缺点的。

我们展示了 IGWEB 的现场演示，这是一个同构 Go 网站，并向您介绍了 Google PageSpeed Insight 工具，用于衡量网页性能。最后，我们为您提供了一些关于术语“同构”以及您需要了解的内容，以便充分理解本书涵盖的材料。

在第二章中，“同构 Go 工具链”，我们将向您介绍开发同构 Go Web 应用程序所使用的关键技术。我们还将向您介绍 IGWEB，这是一个同构 Go 网站，我们将在本书的过程中构建。


# 第二章：同构 Go 工具链

在上一章中，我们确定了同构网络应用架构提供的许多好处，以及使用 Go 编程语言构建同构网络应用的优势。现在，是时候探索使同构 Go 网络应用成为可能的基本要素了。

在本章中，我们将向您介绍*同构 Go*工具链。我们将研究构成工具链的关键技术——Go、GopherJS、同构 Go 工具包和 UX 工具包。一旦我们确定了如何获取和准备这些工具，我们将安装 IGWEB 演示——本书中将要实现的同构 Go 网络应用。随后，我们将深入研究 IGWEB 演示的解剖，检查项目结构和代码组织。

我们还将向您介绍一些有用和高效的技术，这些技术将贯穿整本书的使用，比如在服务器端实现自定义数据存储来满足我们的网络应用数据持久性需求，并利用依赖注入来提供常用功能。最后，我们将为 IGWEB 应用提供一个项目路线图，以规划我们在构建 Isomorphic Go 网络应用中的旅程。

在本章中，我们将涵盖以下主题：

+   安装同构 Go 工具链

+   设置 IGWEB 演示

+   IGWEB 演示简介

+   项目结构和代码组织

# 安装同构 Go 工具链

在本节中，我们将指导您完成安装和配置同构 Go 工具链的过程，这是一组技术，允许我们创建同构 Go 网络应用。以下是我们将要涵盖的关键技术：

+   Go

+   GopherJS

+   同构 Go 工具包

+   UX 工具包

我们将利用**Go**作为服务器端和客户端的编程语言来创建我们的网络应用。Go 允许我们使用简单易懂的语法创建可靠和高效的软件。它是一种现代的编程语言，设计用于多核处理器、网络系统、大规模计算集群和万维网的时代。由于 Go 是一种通用编程语言，它非常适合创建同构网络应用的理想技术。

**GopherJS**允许我们通过将 Go 代码转译为纯 JavaScript 代码，将 Go 引入客户端，这样可以在所有主要的 Web 浏览器中运行。GopherJS 提供了常见 JavaScript 功能的绑定，包括 DOM API、XHR、内置 JavaScript 函数/操作符和 WebSocket API。

**同构 Go 工具包**为我们提供了构建同构 Go 网络应用所需的技术。使用该项目提供的工具，我们可以实现同构网络应用所需的常见功能，如客户端路由、同构模板渲染和创建同构网络表单。

**UX 工具包**为我们提供了在 Go 中创建可重用组件的能力，这些组件被称为**cogs**。您可以将它们视为自包含的用户界面小部件，促进了可重用性。Cogs 可以作为纯 Go cogs 或混合 cogs 实现，可以利用现有的 JavaScript 功能。Cogs 在服务器端注册，并在客户端部署。

*图 2.1*展示了我们将作为 Venn 图使用的技术堆栈，清楚地指示了技术组件将驻留在哪个环境（或多个环境）中：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/c24101d5-08b4-4f83-848a-44a9e1df48a1.png)

图 2.1：同构 Go 工具链：Go、GopherJS、同构 Go 工具包和 UX 工具包

既然我们已经确定了构成我们技术堆栈的关键组件，让我们继续安装/配置它们。

# Go

如果您对 Go 不熟悉，值得花些时间参加 Go 之旅，网址为[`tour.golang.org`](https://tour.golang.org)。

在继续之前，您需要在系统上安装 Go。在本节中，我们将提供安装 Go 和设置 Go 工作区的高级概述。如果您需要进一步帮助，可以访问[`golang.org/doc/install`](https://golang.org/doc/install)获取安装 Go 的详细说明。

让我们前往 Go 网站，网址为[`golang.org`](https://golang.org)：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/fdfe9bb6-f4b6-45b6-a392-a3bee77ce753.png)

图 2.2：Go 网站

单击*图 2.2*中显示的下载 Go 链接，以进入下载页面（[`golang.org/dl/`](https://golang.org/dl/)），如*图 2.3*所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/f6c2a836-5f4d-427c-8eec-068b4964b5a0.png)

图 2.3：Go 网站上的下载页面

如您所见，Go 适用于所有主要操作系统。我们将在 Mac 上进行安装和配置过程。有关在其他操作系统上安装 Go 的信息可以在 Go 网站的*入门*文档中找到，网址为[`golang.org/doc/install`](https://golang.org/doc/install)。

在下载页面上，单击链接以下载适用于您操作系统的 Go 分发。我单击了下载 Apple macOS 安装程序的链接。

使您的系统能够运行 Go 将包括以下步骤：

1.  安装 Go

1.  设置您的 Go 工作区

1.  构建和运行程序

# 安装 Go

下载完成后，继续启动安装程序。Go 安装程序显示在*图 2.4*中：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/1b97ddd2-2222-446e-a370-c67411f187da.png)

图 2.4：Go 安装程序

按照安装程序的屏幕提示操作，如果安装程序要求您使 Go 对系统上的所有用户可用，请确保选择为系统的所有用户安装 Go。您可能还需要输入系统凭据（以便您可以为系统上的所有用户安装 Go）。再次，继续并提供您的系统凭据。

安装程序完成后，您应该从 Go 安装程序获得以下确认：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/bad5b5a6-fd6d-441c-87a4-8f6bc1efd6cc.png)

图 2.5：Go 安装程序报告安装成功

安装程序完成后，让我们打开命令提示符并检查安装程序安装文件的位置：

```go
$ which go
/usr/local/go/bin/go
```

在 macOS 系统上，Go 分发安装到`/usr/local/go`目录中，Go 分发附带的二进制文件安装在`/usr/local/go/bin`目录中。

如果您是 Go 工具链的新手，您应该使用`go help`命令来熟悉 Go 附带的各种命令：

```go
$ go help
Go is a tool for managing Go source code.

Usage:

 go command [arguments]

The commands are:

 build      compile packages and dependencies
 clean      remove object files
 doc        show documentation for package or symbol
 env        print Go environment information
 bug        start a bug report
 fix        run go tool fix on packages
 fmt        run gofmt on package sources
 generate   generate Go files by processing source
 get        download and install packages and dependencies
 install    compile and install packages and dependencies
 list       list packages
 run        compile and run Go program
 test       test packages
 tool       run specified go tool
 version    print Go version
 vet        run go tool vet on packages

Use "go help [command]" for more information about a command.

Additional help topics:
 c           calling between Go and C
 buildmode   description of build modes
 filetype    file types
 gopath      GOPATH environment variable
 environment environment variables
 importpath  import path syntax
 packages    description of package lists
 testflag    description of testing flags
 testfunc    description of testing functions
Use "go help [topic]" for more information about that topic.
```

要确定系统上安装的 Go 版本，您可以使用`go version`命令：

```go
$ go version
go version go1.9.1 darwin/amd64
```

您应该在系统上安装最新版本的 Go，并且在继续之前，您需要有一个正确配置的 Go 工作区。

# 设置您的 Go 工作区

现在您已成功在系统上安装了 Go，您需要在继续之前拥有一个正确配置的 Go 工作区。我们将提供设置 Go 工作区的高级概述，如果您需要进一步帮助，可以阅读 Go 网站上提供的设置 Go 工作区的详细说明：[`golang.org/doc/code.html`](https://golang.org/doc/code.html)。

使用您喜欢的文本编辑器打开您的主目录中的`.profile`文件。如果您使用 Linux，您需要打开主目录中找到的`.bashrc`文件。

我们将在文件中添加以下行以添加一些非常重要的环境变量：

```go
export GOROOT=/usr/local/go
export GOPATH=/Users/kamesh/go
export GOBIN=${GOPATH}/bin
export PATH=${PATH}:/usr/local/bin:${GOROOT}/bin:${GOBIN}
```

我的用户名是`kamesh`，您显然需要用您的用户名替换它。

`$GOROOT`是一个环境变量，用于指定 Go 分发在系统上的安装位置。

`$GOPATH`是一个环境变量，用于指定包含所有 Go 项目源代码的顶级目录。这个目录被称为我们的 Go 工作空间。我已经在我的家目录的`go`文件夹中创建了我的工作空间：`/Users/kamesh/go`。

让我们继续创建我们的 Go 工作空间，以及其中的三个重要目录：

```go
$ mkdir go
$ mkdir go/src
$ mkdir go/pkg
$ mkdir go/bin
```

`go/src`目录将包含 Go 源文件。`go/pkg`目录将包含编译后的 Go 包。最后，`go/bin`目录将包含编译后的 Go 二进制文件。

`$GOBIN`是一个环境变量，用于指定 Go 应该安装编译后的二进制文件的位置。当我们运行`go install`命令时，Go 会编译我们的源代码，并将新创建的二进制文件存储在`$GOBIN`指定的目录中。

我们向**`$PATH`**环境变量添加了两个额外的条目——`$GOROOT/bin`和`$GOBIN`目录。这告诉我们的 shell 环境在哪里找到与 Go 相关的二进制文件。将`$GOROOT/bin`添加到`$PATH`中，让 shell 环境知道 Go 分发的二进制文件位于何处。添加`$GOBIN`告诉 shell 环境我们创建的 Go 程序的二进制文件位于何处。

# 构建和运行 Go 程序

让我们创建一个简单的“hello world”程序来检查我们的 Go 设置。

我们首先在 Go 工作空间的`src`目录中创建一个新程序的目录，如下所示：

```go
$ cd $GOPATH/src
$ mkdir hellogopher
```

现在，使用您喜欢的文本编辑器，在`hellogopher`目录中创建一个`hellogopher.go`源文件，内容如下：

```go
package main

import "fmt"

func main() {

  fmt.Println("Hello Gopher!")
}
```

要一步构建和运行此程序，您可以发出`go run`命令：

```go
$ go run hellogopher.go
Hello Gopher!
```

要生成一个存在于当前目录中的二进制可执行文件，您可以发出`go build`命令：

```go
$ go build
```

要构建一个二进制可执行文件并自动将其移动到您的`$GOBIN`目录，您可以发出`go install`命令：

```go
$ go install
```

发出`go install`命令后，您只需输入以下命令来运行它（假设`$GOBIN`在您的`$PATH`中已经指定）：

```go
$ hellogopher
Hello Gopher!
```

此时，我们已经成功安装、配置和验证了 Go 安装。现在是时候启动其他工具了，首先是 GopherJS。

# GopherJS

GopherJS 是一个将 Go 代码转换为纯 JavaScript 代码的转换器。使用 GopherJS，我们可以用 Go 编写前端代码，这些代码将在支持 JavaScript 的所有主要 Web 浏览器上运行。这项技术使我们能够在 Web 浏览器中释放 Go 的力量，没有它，同构 Go 将是不可能的。

在本章中，我们将向您展示如何安装 GopherJS。我们将在第三章中更详细地介绍 GopherJS，*使用 GopherJS 进行前端开发*。

开始使用 GopherJS 包括以下步骤：

1.  安装 GopherJS

1.  安装必要的 GopherJS 绑定

1.  在命令行上熟悉 GopherJS

# 安装 GopherJS

我们可以通过发出以下`go get`命令来安装 GopherJS：

```go
$ go get -u github.com/gopherjs/gopherjs
```

要查找系统上安装的`gopherjs`的当前版本，使用`gopherjs version`命令：

```go
$ gopherjs version
GopherJS 1.9-1</strong>
```

Go 和 GopherJS 的主要版本必须在您的系统上匹配。在本书中，我们将使用 Go 的 1.9.1 版本和 GopherJS 的 1.9-1 版本。

您可以输入`gopherjs help`来熟悉 GopherJS 提供的各种命令：

```go
$ gopherjs
GopherJS is a tool for compiling Go source code to JavaScript.

Usage:
 gopherjs [command]

Available Commands:
 build compile packages and dependencies
 doc display documentation for the requested, package, method or symbol
 get download and install packages and dependencies
 install compile and install packages and dependencies
 run compile and run Go program
 serve compile on-the-fly and serve
 test test packages
 version print GopherJS compiler version

Flags:
 --color colored output (default true)
 --localmap use local paths for sourcemap
 -m, --minify minify generated code
 -q, --quiet suppress non-fatal warnings
 --tags string a list of build tags to consider satisfied during the build
 -v, --verbose print the names of packages as they are compiled
 -w, --watch watch for changes to the source files

Use "gopherjs [command] --help" for more information about a command.
```

# 安装必要的 GopherJS 绑定

现在我们已经安装了 GopherJS 并确认它可以工作，我们需要获取以下 GopherJS 绑定，这些绑定是我们前端网页应用开发所需的：

+   dom

+   jsbuiltin

+   xhr

+   websocket

# dom

`dom`包为我们提供了 JavaScript 的 DOM API 的 GopherJS 绑定。

我们可以通过发出以下命令来安装`dom`包：

```go
$ go get honnef.co/go/js/dom
```

# jsbuiltin

`jsbuiltin`包为常见的 JavaScript 运算符和函数提供了绑定。我们可以通过发出以下命令来安装`jsbuiltin`包：

```go
$ go get -u -d -tags=js github.com/gopherjs/jsbuiltin
```

# xhr

`xhr`包为`XMLHttpRequest`对象提供了绑定。我们可以通过以下命令安装`xhr`包：

```go
$ go get -u honnef.co/go/js/xhr
```

# websocket

`websocket`包为 Web 浏览器的 WebSocket API 提供了绑定。我们可以通过以下命令安装`websocket`包：

```go
$ go get -u github.com/gopherjs/websocket
```

# 熟悉命令行上的 GopherJS

`gopherjs`命令与`go`命令非常相似。例如，要将 Go 程序转译为其 JavaScript 表示形式，我们发出以下`gopherjs build`命令：

```go
$ gopherjs build
```

要构建一个 GopherJS 项目并缩小生成的 JavaScript 源文件，我们需要在`gopherjs build`命令中指定`-m`标志：

```go
$ gopherjs build -m
```

当我们执行构建操作时，GopherJS 将创建一个`.js`源文件和一个`.js.map`源文件。

`.js.map`文件称为源映射。当我们使用 Web 浏览器控制台追踪错误时，此功能非常有用，可以将缩小的 JavaScript 源文件映射回其未构建状态。

由 GopherJS 生成的 JavaScript 源文件可以作为外部 JavaScript 源文件导入到 Web 页面中，使用`script`标签。

# 等同 Go 工具包

等同 Go 工具包（[`isomorphicgo.org`](http://isomorphicgo.org)）为我们提供了实现等同 Go Web 应用程序所需的技术。我们将使用等同 Go 工具包中的`isokit`包来实现等同 Web 应用程序：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/316a1087-f70e-41f0-9d18-e8ba031b35ae.png)

图 2.6：等同 Go 网站

# 安装 isokit

Isomorphic Go 工具包的`isokit`包提供了通用的等同功能，可以在服务器端或客户端上使用。该软件包提供的一些显着优点包括等同模板渲染、客户端应用程序路由、自动静态资产捆绑以及创建等同 Web 表单的能力。

我们可以通过以下`go get`命令安装`isokit`包：

```go
$ go get -u github.com/isomorphicgo/isokit
```

# UX 工具包

UX 工具包（[`uxtoolkit.io`](http://uxtoolkit.io)）允许我们实现*齿轮*，这些齿轮是用 Go 实现的可重用组件，可以在组成 IGWEB 的网页中使用。我们将在第九章中介绍可重用组件，*齿轮-可重用组件*。

# 安装齿轮包

我们可以通过以下`go get`命令安装`cog`包：

```go
$ go get -u github.com/uxtoolkit/cog
```

现在我们已经安装了等同 Go 工具链，是时候设置 IGWEB 演示了，这是本书中我们将构建的等同 Web 应用程序。

# 设置 IGWEB 演示

您可以通过以下`go get`命令获取本书的源代码示例：

```go
$ go get -u github.com/EngineerKamesh/igb
```

IGWEB 演示网站的完成实现源代码位于`igb/igweb`文件夹中。各章节的源代码清单可以在`igb/individual`文件夹中找到。

# 设置应用程序根环境变量

IGWEB 演示依赖于应用程序根环境变量`$IGWEB_APP_ROOT`的定义。Web 应用程序使用此环境变量来声明其所在位置。通过这样做，Web 应用程序可以确定其他资源的位置，例如静态资产（图像、css 和 javascript）。

您应该通过在 bash 配置文件中添加以下条目来设置`$IGWEB_APP_ROOT`环境变量：

```go
export IGWEB_APP_ROOT=${GOPATH}/src/github.com/EngineerKamesh/igb/igweb
```

要验证环境中是否存在`$IGWEB_APP_ROOT`环境变量，可以使用`echo`命令：

```go
$ echo $IGWEB_APP_ROOT
/Users/kamesh/go/src/github.com/EngineerKamesh/igb/igweb
```

# 转译客户端应用程序

现在我们已经设置了`$IGWEB_APP_ROOT`环境变量，我们可以访问`client`目录，其中包含客户端 Web 应用程序：

```go
$ cd $IGWEB_APP_ROOT/client
```

我们发出以下`go get`命令来安装可能需要的任何其他依赖项，以确保我们的客户端应用程序正常运行：

```go
$ go get ./..
```

最后，我们发出`gopherjs build`命令来转译 IGWEB 客户端 Web 应用程序：

```go
$ gopherjs build
```

运行命令后，应该生成两个文件——`client.js`和`client.js.map`。`client.js`源文件是 IGWEB 客户端 Go 程序的 JavaScript 表示。`client.js.map`文件是源映射文件，将与`client.js`一起在 Web 浏览器中使用，以在 Web 控制台中提供详细信息，这在调试问题时非常方便。

现在我们已经转译了 IGWEB 客户端应用程序的代码，下一个逻辑步骤将是构建和运行 IGWEB 服务器端应用程序。在我们这样做之前，我们必须安装并运行本地 Redis 实例，这是我们将在下一节中做的事情。

# 设置 Redis

Redis 是一种流行的 NoSQL 内存数据库。由于整个数据库都存在于内存中，数据库查询非常快速。Redis 也以支持多种数据类型而闻名，它是一个多用途工具，可以用作数据库、内存缓存，甚至作为消息代理。

在本书中，我们将使用 Redis 来满足 IGWEB 的数据持久化需求。我们将在默认端口 6379 上运行我们的 Redis 实例。

我们发出以下命令来下载和安装 Redis：

```go
$ wget http://download.redis.io/releases/redis-4.0.2.tar.gz
$ tar xzf redis-4.0.2.tar.gz
$ cd redis-4.0.2
$ make
$ sudo make install
```

使用`wget`命令获取 Redis 的替代方法是从 Redis 下载页面获取，如*图 2.7*所示，网址为[`redis.io/download`](https://redis.io/download)：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/f96ccb37-2b11-437a-bd38-bfc1cfdae2ff.png)

图 2.7：Redis 网站上的下载部分

下载并安装 Redis 后，您可以通过发出`redis-server`命令启动服务器：

```go
$ redis-server
```

在另一个终端窗口中，我们可以打开 Redis 的**命令行界面**（**CLI**），使用`redis-cli`命令连接到 Redis 服务器实例：

```go
$ redis-cli
```

我们可以使用`set`命令设置`foo`键的`bar`值：

```go
127.0.0.1:6379> set foo bar
OK
```

我们可以使用`get`命令获取`foo`键的值：

```go
127.0.0.1:6379> get foo
"bar"
```

您可以通过访问 Redis 网站的文档部分了解更多关于 Redis 的信息，网址为[`redis.io/documentation.`](https://redis.io/documentation)。阅读 Redis 快速入门文档，网址为[`redis.io/topics/quickstart`](https://redis.io/topics/quickstart)，也是有帮助的。现在我们已经安装了本地 Redis 实例，是时候构建和运行 IGWEB 演示了。

# 运行 IGWEB 演示

您可以通过首先将目录更改为`$IGWEB_APP_ROOT`目录，然后发出`go run`命令来运行 IGWEB Web 服务器实例：

```go
$ cd $IGWEB_APP_ROOT
```

```go
$ go run igweb.go
```

您可以通过访问`http://localhost:8080/index`链接从您的 Web 浏览器访问 IGWEB 网站。您应该能够看到网站的主页，如*图 2.8*所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/e85914c0-73d8-41eb-a9fa-4d7bcf532bff.png)

图 2.8：IGWEB 主页

我们安装过程的最后一步是使用示例数据集加载本地 Redis 实例。

# 加载示例数据集

提供的示例数据集用于填充产品列表和关于页面的数据。您可以通过访问`http://localhost:8080/products`在浏览器中查看产品列表页面，您应该会看到*图 2.9*中显示的屏幕：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/628a6b67-8ec5-4f25-a637-fdc14036d7ad.png)

图 2.9：空产品部分，显示加载示例数据集的消息

继续点击网页上显示的链接以加载示例数据集。当您点击链接时，您应该会看到*图 2.10*中显示的屏幕：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/c3620722-69e4-4d0e-8a82-09e758657896.png)

图 2.10：确认已加载示例数据集

现在，如果您返回产品列表页面，您应该会看到页面上显示的产品，如*图 2.11*所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/8ae4bf3f-f652-4877-9ae2-fe1bcf497c29.png)

图 2.11：填充了产品的产品部分

现在我们已经启动并运行了 IGWEB 演示！

每当我们想要对服务器端的 Go 应用程序进行更改时，我们需要发出 `go build` 命令并重新启动 web 服务器实例。同样，每当我们对客户端的 Go 应用程序进行更改时，我们必须发出 `gopherjs build` 命令。在开发过程中不断发出这些命令可能会很烦人和低效。`kick` 命令为我们提供了一种更高效的方式。

# 使用 kick

`kick` 命令是一种轻量级机制，为 Go web 服务器实例提供了*即时启动*。当应用程序项目目录（或其任何子目录）中的 Go 源文件发生更改时，*即时启动*就会发生。

`kick` 命令为我们提供了一种自动化开发工作流程的手段，通过重新编译我们的 Go 代码并重新启动 web 服务器，每当我们对 Go 源文件进行更改时。

`kick` 提供的工作流程类似于使用动态脚本语言（如 PHP）开发 web 应用程序，每当对 PHP 源文件进行更改时，刷新浏览器中的网页会立即反映出更改。

在这个问题空间中，`kick` 与其他基于 Go 的解决方案的不同之处在于，在执行*即时启动*时，它考虑了 `go` 和 `gopherjs` 命令。它还考虑了对模板文件的更改，使其成为同构 web 应用程序开发的便捷工具。

# 安装 kick

要安装 `kick`，我们只需发出以下 `go get` 命令：

```go
$ go get -u github.com/isomorphicgo/kick
```

# 运行 kick

要了解如何使用 `kick`，可以像这样发出 `help` 命令行标志：

```go
$ kick --help
```

`--appPath` 标志指定 Go 应用程序项目的路径。`--gopherjsAppPath` 标志指定 GopherJS 项目的路径。`--mainSourceFile` 标志指定包含 Go 应用程序项目目录中 `main` 函数实现的 Go 源文件的名称。如果你仍然在终端窗口中使用 `go run` 命令运行 IGWEB，现在是退出程序并使用 `kick` 运行它的时候了。

要使用 `kick` 运行 IGWEB 演示，我们发出以下命令：

```go
$ kick --appPath=$IGWEB_APP_ROOT --gopherjsAppPath=$IGWEB_APP_ROOT/client --mainSourceFile=igweb.go
```

# 验证 kick 是否正常工作

让我们打开关于页面（`http://localhost:8080/about`）以及网络检查器。注意在网络控制台中显示的 IGWEB 客户端应用程序的消息，如 *图 2.12* 所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/9b32d07a-f409-4f16-9a47-31cbeab0b4ed.png)

图 2.12：在网络控制台中打印的消息

让我们打开位于 `client` 目录中的 `client.go` 源文件。让我们用以下内容替换 `run` 函数中的第一行：

```go
println("IGWEB Client Application - Kamesh just made an update.")
```

保存文件并查看终端窗口，在那里你正在运行 `kick`，你应该能够看到以下消息出现：

```go
Instant KickStart Applied! (Recompiling and restarting project.)
```

这是来自 `kick` 的确认，它已经检测到文件的更改，并执行了*即时启动*。现在，让我们重新加载网页，你应该能够看到更新后的消息，如 *图 2.13* 所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/bab89060-bee6-4416-bb79-48eba369ce46.png)

图 2.13：修改后的消息在网络控制台中打印出来

现在你已经成功使用 `kick` 在你的机器上运行 IGWEB 演示，现在是介绍项目的时候了。

# IGWEB 演示简介

IGWEB 是由三个想要使用同构 Go 在网上构建简单商店演示的虚构科技初创公司。这些有进取心的 gopher 的想法是将在车库/庭院销售的常见二手产品在线销售。这个 gopher 团队选择在同构 Go 中实现 IGWEB 演示，不仅提供增强的用户体验，还能获得更大的搜索引擎可发现性。如果你还没有猜到，IGWEB 简单地代表*同构 Go web 应用程序*。

# 从头开始构建 IGWEB

为了理解构建同构 Web 应用程序涉及的基本概念，我们将在创建 IGWEB 时遵循惯用的 Go 方法。我们将利用标准库中的功能以及第三方包中发现的功能。

如果您有使用 Web 框架开发 Web 应用程序的经验，您可能会想知道为什么我们采取这种方法。在撰写本文时，没有基于 Go 的 Web 框架可以提供开箱即用的功能，用于创建符合上一章中介绍的同构 Web 应用程序架构的 Web 应用程序。

此外，Web 框架通常涉及遵循特定的规则和约定，这可能是特定于框架的。我们的重点是概念性的，不与特定的 Web 框架绑定。因此，我们的注意力将集中在创建同构 Web 应用程序涉及的基本概念上。

# IGWEB 路线图

在构建 IGWEB 演示网站的每个部分和功能的过程中，我们将学习更多关于同构 Go 的知识。以下是 IGWEB 主要部分/功能的路线图，以及在书中实现该特定部分或功能的相应章节。

# 首页

除了包含精选产品的图像轮播和多个实时时钟之外，IGWEB 首页还包含一个链接到独立前端编码示例的部分。

独立示例包括各种前端编程示例，使用 GopherJS 进行内联模板渲染的示例，以及本地存储检查器的示例。这些示例将在第三章中进行介绍，*使用 GopherJS 进行前端开发*。图像轮播和实时时钟将在第九章中进行介绍，*齿轮-可重用组件*。

首页的位置：`http://localhost:8080/index`。

# 关于页面

我们的 gopher 团队希望通过在 IGWEB 的关于页面上亮相来向世界展示自己。在实现这一目标的过程中，我们将学习同构模板渲染以及在不同环境中共享模板、模板数据和模板函数的能力。

关于页面将在第四章中进行介绍，*同构模板*。

关于页面的位置：`http://localhost:8080/about`。

# 产品页面

产品列表页面展示了 IGWEB 网站上可供销售的产品。每个产品都有产品标题、图像缩略图预览、产品价格和简短描述。单击产品图像将带用户转到产品详细页面，在那里用户可以了解更多关于该特定产品的信息。通过实现产品列表和产品详细页面，我们将了解同构 Go 中的端到端应用程序路由。

产品页面将在第五章中进行介绍，*端到端路由*。

产品页面的位置：`http://localhost:8080/products`。

# 购物车功能

产品页面中显示的每个产品卡都将包含一个“添加到购物车”按钮。该按钮也将出现在产品的详细页面上。我们将学习如何在执行购物车上的添加和删除操作时维护购物车的状态。

购物车功能将在第六章中进行介绍，*同构交接*。

位置：`http://localhost:8080/shopping-cart`。

# 联系页面

联系页面将提供与 IGWEB 的 gopher 团队联系的方式。在实施联系表单的过程中，我们将了解如何实现一个同构 Web 表单，它在不同环境中共享验证逻辑。此外，我们还将学习 Web 表单如何在 Web 浏览器中禁用 JavaScript 的情况下保持弹性工作。

联系页面将在第七章中介绍，*同构 Web 表单*。联系表单的日期选择器`cog`将在第九章中介绍，*Cogs – 可重复使用的组件*。

联系页面的位置：`http://localhost:8080/contact`。

# 实时聊天功能

在需要更大的用户交互性的情况下，网站用户可以与实时聊天机器人进行交互。在构建实时聊天功能的过程中，我们将了解实时 Web 应用程序功能。实时聊天功能将在第八章中介绍，*实时 Web 应用程序功能*。

单击位于网页右上角的实时聊天图标即可激活实时聊天功能。

# 可重复使用的组件

通过实现各种可重复使用的组件，例如实时时钟和产品轮播图，我们将返回到主页，这些产品在 IGWEB 上可用。我们还将为联系页面构建日期选择器`cog`，以及关于页面的时间组件。时间组件将以人类可读的格式表示时间。我们还将研究实现通知组件，用于向用户显示通知消息。

可重复使用的组件将在第九章中介绍，*Cogs – 可重复使用的组件*。

# 项目结构和代码组织

IGWEB 项目的代码可以在`igweb`文件夹中找到，并且按照以下文件夹进行组织（按字母顺序列出）：

```go
  ⁃ bot

  ⁃ chat

  ⁃ client
    ⁃ carsdemo
    ⁃ chat
    ⁃ common
    ⁃ gopherjsprimer
    ⁃ handlers
    ⁃ localstoragedemo
    ⁃ tests

  ⁃ common
    ⁃ datastore

  ⁃ endpoints

  ⁃ handlers

  ⁃ scripts  

  ⁃ shared
    ⁃ cogs
    ⁃ forms
    ⁃ models
    ⁃ templates
    ⁃ templatedata
    ⁃ templatefuncs
    ⁃ validate

  ⁃ static
    ⁃ css
    ⁃ fonts
    ⁃ images
    ⁃ js
    ⁃ templates

  ⁃ submissions

  ⁃ tests
```

`bot`文件夹包含实现实时聊天功能的聊天机器人的源文件。

`chat`文件夹包含实现实时聊天功能的聊天服务器的服务器端代码。

`client`文件夹包含将使用 GopherJS 转译为 JavaScript 的客户端 Go 程序。

`client/carsdemo`包含一个独立示例，演示使用 GopherJS 进行内联模板渲染。此示例将在第三章中介绍，*使用 GopherJS 进行前端开发*。

`client/chat`文件夹包含实现聊天客户端的客户端代码。

`client/common`文件夹包含实现客户端应用程序中使用的通用功能的客户端代码。

`client/gopherjsprimer`包含独立的 GopherJS 示例，将在第三章中介绍，*使用 GopherJS 进行前端开发*。

`client/handlers`文件夹包含客户端路由/页面处理程序。这些处理程序负责处理客户端页面的路由，防止完整页面重新加载。它们还负责处理给定网页的所有客户端用户交互。

`client/localstoragedemo`包含本地存储检查器的实现，将在第三章中介绍，*使用 GopherJS 进行前端开发*。

`client/tests`文件夹包含对客户端功能进行端到端测试的测试。该文件夹包括这三个文件夹：`client/tests/go`，`client/tests/js`和`client/tests/screenshots`。`go`子文件夹包含 CasperJS 测试，这些测试是模拟用户与使用 Go 实现的网站进行交互的自动化测试。运行`scripts`文件夹中的`build_casper_tests.sh` bash 脚本将每个 Go 源文件转译为其等效的 JavaScript 表示形式，并存储在`js`子文件夹中。运行 CasperJS 测试时，将生成并保存截图在`screenshots`子文件夹中。

`common`文件夹包含实现服务器端应用程序中使用的通用功能的服务器端代码。

`common/datastore`文件夹包含了实现 Redis 数据存储的服务器端代码，以满足应用程序的数据持久化需求。

`endpoints`文件夹包含了负责为 Web 客户端发出的 XHR 调用提供服务的 Rest API 端点的服务器端代码。

`handlers`文件夹包含了服务器端路由处理函数的服务器端代码，负责为特定路由提供服务。这些处理函数的主要责任是向客户端发送网页响应。它们用于初始网页加载，其中网页响应是使用经典的 Web 应用程序架构在服务器端呈现的。

`scripts`文件夹包含了在命令行上运行的方便的 bash shell 脚本。

`shared`文件夹包含了在服务器端和客户端之间共享的等同代码。查看这个文件夹可以让我们了解所有可以在各个环境中共享的 Go 代码。

`shared/cogs`文件夹包含了可重复使用的组件（cogs），这些组件在服务器端注册并在客户端部署。

`shared/forms`文件夹包含了等同 Web 表单。

`shared/models`文件夹包含了我们用来模拟数据的等同类型（结构）在我们的等同 Web 应用程序中使用。

`shared/templates`文件夹包含了可以在各个环境中渲染的等同模板。

`shared/templatedata`文件夹包含了在渲染时要提供给等同模板的等同数据对象。

`shared/templatefuncs`文件夹包含了可以在各个环境中使用的等同模板函数。

`shared/validate`文件夹包含了通用的等同验证逻辑，可以被各个环境中的 Web 表单利用。

`static`文件夹包含了等同 Web 应用程序的所有静态资产。

`static/css`文件夹包含了 CSS 样式表源文件。

`static/fonts`文件夹包含了 Web 应用程序使用的自定义字体。

`static/images`文件夹包含了 Web 应用程序使用的图像。

`static/js`文件夹包含了 Web 应用程序的 JavaScript 源代码。

`submissions`文件夹存在于举例说明的目的。该文件夹包含了`submissions`包，其中包含了在 Web 表单成功通过 Web 表单验证过程后要调用的逻辑。

`tests`文件夹包含了对服务器端功能进行端到端测试的测试。

# MVC 模式

IGWEB 的项目代码库可以被概念化为遵循**模型-视图-控制**（MVC）模式。MVC 模式在 Web 应用程序的创建中被广泛使用，并在*图 2.14*中描述：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/09af5bf1-3a2f-4fe2-9070-96b8a1e7b260.png)

图 2.14：模型视图控制器模式

在基于 MVC 的应用程序中有三个主要组件——模型、视图和控制器。模型的主要目的是为应用程序提供数据和业务规则。把模型想象成应用程序数据需求的守门人。IGWEB 的模型可以在`shared/models`文件夹中找到。

视图负责用户所见的输出。视图的重点在于呈现和将模型渲染到用户界面中，以一种对用户有意义的方式。IGWEB 中的视图存在于`shared/templates`文件夹中找到的模板中。

控制器实现系统的应用逻辑，它们基本上告诉应用程序应该如何行为。您可以将控制器概念化为应用程序模型和视图之间的代理。控制器接受来自视图的用户输入，并可以访问或改变模型的状态。控制器还可以改变视图当前呈现的内容。IGWEB 中的服务器端控制器是`handlers`文件夹中的路由处理程序。IGWEB 中的客户端控制器是`client/handlers`目录中的路由/页面处理程序。

当您阅读本书中的示例时，请注意相对提到的所有文件夹都是相对于`igweb`文件夹的。

现在我们已经确定了 IGWEB 项目的代码是如何组织的，我们可以开始实现构成我们 Isomorphic Go web 应用程序的各个部分和功能的旅程。

# 自定义数据存储

为 IGWEB 演示网站实现了自定义数据存储。尽管我们将在本书中仅使用 Redis 作为独占数据库，但事实上，只要您创建一个实现`Datastore`接口的自定义数据存储，您就可以自由地使用几乎任何数据库。

让我们来看看在`common/datastore`文件夹中的`datastore.go`源文件中定义`Datastore`接口的部分：

```go
type Datastore interface {
  CreateGopherTeam(team []*models.Gopher) error
  GetGopherTeam() []*models.Gopher
  CreateProduct(product *models.Product) error
  CreateProductRegistry(products []string) error
  GetProducts() []*models.Product
  GetProductDetail(productTitle string) *models.Product
  GetProductsInShoppingCart(cart *models.ShoppingCart) []*models.Product
  CreateContactRequest(contactRrequest *models.ContactRequest) error
  Close()
}
```

我们将在各自处理特定部分或功能的章节中讨论`Datastore`接口的各个方法，其中使用了该方法。请注意，实现`Datastore`接口所需的最终方法是`Close`方法（以粗体显示）。`Close`方法确定数据存储如何关闭其连接（或清空其连接池）。

在`common/datastore`文件夹中的`redis.go`源文件中检查`RedisDatastore`的实现，将会提供一个创建实现`Datastore`接口的自定义数据存储所需的内容。

在`datastore.go`源文件中进一步定义了`NewDatastore`函数，该函数负责返回一个新的数据存储：

```go
const (
  REDIS = iota
)

func NewDatastore(datastoreType int, dbConnectionString string) (Datastore, error) {

  switch datastoreType {

 case REDIS:
 return NewRedisDatastore(dbConnectionString)

  default:
    return nil, errors.New("Unrecognized Datastore!")

  }
}
```

我们的数据存储解决方案是灵活的，因为我们可以用任何其他数据库替换 Redis 数据存储，只要我们的新自定义数据存储实现了`Datastore`接口。请注意，我们在常量分组中使用`iota`枚举器定义了`REDIS`常量（以粗体显示）。检查`NewDatastore`函数，并注意当在`datastoreType`的`switch`块中遇到`REDIS`情况时，会返回一个新的`RedisDatastore`实例（以粗体显示）。

如果我们想为另一个数据库添加支持，比如 MongoDB，我们只需在常量分组中添加一个新的常量条目`MONGODB`。除此之外，我们还将在`NewDatastore`函数的`switch`块中为 MongoDB 添加一个额外的`case`语句，该语句返回一个`NewMongoDataStore`实例，并将连接字符串作为输入参数传递给该函数。`NewMongoDBDatastore`函数将返回我们自定义数据存储类型`MongoDBDataStore`的实例，该类型将实现`Datastore`接口。

以这种方式实现自定义数据存储的一个巨大好处是，我们可以防止在特定数据库的情况下使我们的 Web 应用程序充斥着数据库驱动程序特定的调用。通过自定义数据存储，我们的 Web 应用程序变得对数据库不可知，并为我们提供了更大的灵活性来处理我们的数据访问和数据存储需求。

GopherFace 网络应用程序，来自使用 Go 视频系列的网络编程，实现了针对 MySQL、MongoDB 和 Redis 的自定义数据存储。使用这些数据库的自定义数据存储的示例可在[`github.com/EngineerKamesh/gofullstack/tree/master/volume2/section5/gopherfacedb/common/datastore`](https://github.com/EngineerKamesh/gofullstack/tree/master/volume2/section5/gopherfacedb/common/datastore)找到。

# 依赖注入

服务器端应用程序的主要入口点是`igweb.go`源文件中定义的`main`函数。客户端应用程序的主要入口点是`client/client.go`源文件中定义的`main`函数。在这两个主要入口点中，我们利用依赖注入技术在整个 Web 应用程序中共享通用功能。通过这样做，我们避免了使用包级全局变量。

在服务器端和客户端，我们在`common`包中实现了自定义的`Env`类型。您可以考虑`Env`代表了从*应用环境*中访问的通用功能。

以下是在服务器端`common/common.go`源文件中找到的`Env`结构的声明：

```go
package common

import (
  "github.com/EngineerKamesh/igb/igweb/common/datastore"
  "github.com/gorilla/sessions"
  "github.com/isomorphicgo/isokit"
)

type Env struct {
 DB datastore.Datastore
 TemplateSet *isokit.TemplateSet
}
```

`DB`字段将用于存储自定义数据存储对象。

`TemplateSet`字段是指向`TemplateSet`对象的指针。模板集允许我们以灵活的方式在各种环境中呈现模板，我们将在第四章中详细介绍它们，*同构模板*。

`Store`字段是指向`sessions.FilesystemStore`对象的指针。我们将使用 Gorilla 工具包中的`sessions`包进行会话管理。

在`igweb.go`源文件的`main`函数中，我们将声明一个`env`变量，一个`common.Env`类型的对象：

```go
  env := common.Env{}
```

我们使用新创建的`RedisDatastore`实例和新创建的`TemplateSet`实例分别为`env`对象的`DB`和`TemplateSet`字段赋值（赋值以粗体显示）。出于说明目的，我们省略了一些代码，并在此处显示了部分代码清单：

```go
  db, err := datastore.NewDatastore(datastore.REDIS, "localhost:6379")
  ts := isokit.NewTemplateSet()

 env.TemplateSet = ts
 env.DB = db
```

我们将使用 Gorilla Mux 路由器来满足我们的服务器端路由需求。注意，我们将`env`对象的引用作为输入参数（以粗体显示）传递给`registerRoutes`函数：

```go
func registerRoutes(env *common.Env, r *mux.Router) {
```

我们通过将`env`对象作为输入参数包含在我们为特定路由注册的路由处理函数中，将`env`对象传播给我们的请求处理程序函数，如下所示：

```go
r.Handle("/index", handlers.IndexHandler(env)).Methods("GET")
```

通过调用 Gorilla Mux 路由器的`Handle`方法，我们已经注册了`/index`路由，并将`handlers`包中的`IndexHandler`函数关联为将为此路由提供服务的函数。我们将`env`对象的引用作为此函数的唯一输入参数提供（以粗体显示）。此时，我们已成功传播了`RedisDatastore`和`TemplateSet`实例，并使它们可用于`IndexHandler`函数。

让我们来检查`handlers/index.go`源文件中定义的`IndexHandler`函数的源代码：

```go
package handlers

import (
  "net/http"

  "github.com/EngineerKamesh/igb/igweb/common"
  "github.com/EngineerKamesh/igb/igweb/shared/templatedata"
  "github.com/isomorphicgo/isokit"
)

func IndexHandler(env *common.Env) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    templateData := templatedata.Index{PageTitle: "IGWEB"}
    env.TemplateSet.Render("index_page", &isokit.RenderParams{Writer: w, Data: templateData})
  })
}
```

注意，`handler`函数的处理逻辑被放置在一个闭包中，我们已经闭包了`env`变量。这使我们能够满足`handler`函数应该返回`http.Handler`的要求，同时，我们可以提供对`env`对象的访问权限给`handler`函数。

这种方法的好处是，与使用包级全局变量相比，我们可以明确地看到这个处理程序函数需要`env`对象才能正常工作，方法是检查函数的输入参数（以粗体显示）。

我们在客户端也采用类似的依赖注入策略。以下是在`client/common/common.go`源文件中找到的客户端侧`Env`类型的声明：

```go
package common

import (
 "github.com/isomorphicgo/isokit"
 "honnef.co/go/js/dom"
)

type Env struct {
 TemplateSet *isokit.TemplateSet
 Router *isokit.Router
 Window dom.Window
 Document dom.Document
 PrimaryContent dom.Element
 Location *dom.Location
}
```

我们在客户端声明的`Env`类型与我们在服务器端声明的不同。这是可以理解的，因为我们希望在客户端访问一组不同的通用功能。例如，客户端没有`RedisDatastore`。

我们以与服务器端相同的方式声明了`TemplateSet`字段。因为`*isokit.TemplateSet`类型是同构的，它可以存在于服务器端和客户端。

`Router`字段是指向客户端`isokit.Router`实例的指针。

`Window`字段是`Window`对象，`Document`字段是`Document`对象。

`PrimaryContent`字段表示我们将在客户端渲染页面内容的`div`容器。我们将在第四章 *同构模板*中更详细地介绍这些字段的作用。

`Location`字段是`Window`对象的`Location`对象。

在`client.go`源文件中定义的`registerRoutes`函数内部，我们使用`isokit.Router`来处理客户端路由需求。我们将`env`对象传递给客户端处理函数，如下所示：

```go
  r := isokit.NewRouter()
  r.Handle("/index", handlers.IndexHandler(env))
```

让我们来检查在`client/handlers/index.go`源文件中定义的客户端端`IndexHandler`函数的源代码：

```go
func IndexHandler(env *common.Env) isokit.Handler {
  return isokit.HandlerFunc(func(ctx context.Context) {
    templateData := templatedata.Index{PageTitle: "IGWEB"}
    env.TemplateSet.Render("index_content", &isokit.RenderParams{Data: templateData, Disposition: isokit.PlacementReplaceInnerContents, Element: env.PrimaryContent, PageTitle: templateData.PageTitle})
  })
}
```

我们向这个处理函数提供`env`对象的访问方式（以粗体显示）的方式与我们在服务器端所做的方式完全相同。处理函数的处理逻辑被放入闭包中，并且我们已经关闭了`env`变量。这使我们能够满足客户端处理函数应返回`isokit.Handler`的要求，同时我们可以为处理函数提供对`env`对象的访问。

我们在这里使用的依赖注入技术是受 Alex Edwards 在组织数据库访问方面的博客文章的启发：[`www.alexedwards.net/blog/organising-database-access`](http://www.alexedwards.net/blog/organising-database-access)。

# 总结

在本章中，我们向您介绍了安装同构 Go 工具链的过程。我们向您介绍了 IGWEB 项目，这是一个同构 Web 应用程序，我们将在本书中实现。我们还检查了 IGWEB 代码库的项目结构和代码组织。

我们向您展示了如何设置数据存储并将样本数据集加载到 Redis 实例中。我们演示了如何使用`kick`来执行*即时启动*，以加快 Web 应用程序开发周期。我们还为 IGWEB 项目的功能和功能实现提供了路线图，并包括它们将被覆盖的各自章节。最后，我们演示了依赖注入技术，以在服务器端和客户端共享通用功能。

现在我们已经准备就绪，我们需要对在 Web 浏览器中使用 Go 有一个良好的理解。在第三章 *使用 GopherJS 在前端使用 Go*中，我们将更详细地探索 GopherJS，并学习如何使用 GopherJS 执行常见的 DOM 操作。


# 第三章：使用 GopherJS 在前端进行 Go 编程

自创建以来，JavaScript 一直是 Web 浏览器的事实标准编程语言。因此，它在前端 Web 开发领域长期占据主导地位。它一直是唯一具备操纵网页的**文档对象模型**（**DOM**）和访问现代 Web 浏览器中实现的各种**应用程序编程接口**（**API**）能力的工具。

由于这种独占性，JavaScript 一直是同构 Web 应用程序开发的唯一可行选项。随着 GopherJS 的推出，我们现在可以在 Web 浏览器中创建 Go 程序，这也使得使用 Go 开发同构 Web 应用程序成为可能。

GopherJS 允许我们使用 Go 编写程序，这些程序会转换为等效的 JavaScript 表示形式，适合在任何支持 JavaScript 的 Web 浏览器中运行。特别是在服务器端使用 Go 时，GopherJS 为我们提供了一种可行且有吸引力的替代方案，尤其是如果我们在前端和后端都使用 Go。有了 Go 覆盖前后端的情况，我们有了新的机会来共享代码，并消除在不同环境中使用不同编程语言时产生的心理上下文转换。

在本章中，我们将涵盖以下主题：

+   文档对象模型

+   基本的 DOM 操作

+   GopherJS 概述

+   GopherJS 示例

+   内联模板渲染

+   本地存储

# 文档对象模型

在我们深入研究 GopherJS 之前，重要的是让我们了解 JavaScript 以及扩展—GopherJS 为我们做了什么。JavaScript 具有的主要功能之一是其能够访问和操作**DOM**（**文档对象模型**的缩写）。DOM 是表示 Web 页面结构及其中存在的所有节点（元素）的树形数据结构。

DOM 的重要性在于它充当 HTML 文档的编程接口，具有访问 Web 页面样式、结构和内容的能力。由于 DOM 树中的每个节点都是一个对象，因此 DOM 可以被视为给定 Web 页面的面向对象表示。因此，可以使用 JavaScript 访问和更改对象及其属性。

*图 3.1*描述了给定 Web 页面的 DOM 层次结构。Web 页面上的所有元素都是**html**节点的子节点，由 Web 页面的 HTML 源代码中的`<html>`标签表示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/8cae7934-c0ad-4bab-96d3-ff260b9d3422.png)

图 3.1：Web 页面的 DOM 层次结构

**head**节点是**html**节点的子节点，包含两个子节点—meta（在 HTML 中使用`<meta>`标签定义）和一个脚本节点（用于外部 CSS 或 JavaScript 源文件）。与 head 节点处于同一级别的是 body 节点，使用`<body>`标签定义。

body 节点包含要在 Web 页面上呈现的所有元素。在 body 节点下面，我们有一个子节点，即标题节点（使用`<h1>`标签定义），即 Web 页面的标题。此节点没有子元素。

在标题节点的同一级别，我们还有一个 div 节点（使用`<div>`标签定义）。此节点包含一个 div 子节点，其有两个子节点—一个段落节点（使用`<p>`标签定义），在此节点的同一级别存在一个图像节点（使用`<img>`标签定义）。

图像节点没有子元素，段落节点有一个子元素—一个 span 节点（使用`<span>`标签定义）。

Web 浏览器中包含的 JavaScript 运行时为我们提供了访问 DOM 树中各个节点及其相应值的功能。使用 JavaScript 运行时，我们可以访问单个节点，如果给定节点包含子节点，我们还可以访问所有父节点的子节点集合。

由于网页被表示为一组对象，使用 DOM，我们可以访问任何给定 DOM 对象的事件、方法和属性。事实上，`document`对象代表了网页文档本身。

这是 MDN 网站上关于 DOM 的有用介绍：

[`developer.mozilla.org/en-US/docs/Web/API/Document_Object_Model/Introduction`](https://developer.mozilla.org/en-US/docs/Web/API/Document_Object_Model/Introduction)。

# 访问和操作 DOM

如前所述，我们可以使用 JavaScript 来访问和操作给定网页的 DOM。由于 GopherJS 转译为 JavaScript，我们现在有能力在 Go 的范围内访问和操作 DOM。*图 3.2*描述了一个 JavaScript 程序访问/操作 DOM 以及一个 Go 程序也访问/操作 DOM：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/0b73a589-0ac3-48df-9410-e1418404e5b1.png)

图 3.2：DOM 可以被 JavaScript 程序和/或 Go 程序（使用 GopherJS）访问和操作

现在，让我们看一些简单的编程片段，我们可以使用 Go 访问 JavaScript 功能，然后使用 JavaScript 进行一些基本的 DOM 操作，以及它们在 GopherJS 中的等效指令。暂时让我们预览一下使用 GopherJS 编码的样子。这些概念将在本章后面作为完整的例子进行进一步详细解释。

# 基本的 DOM 操作

在本节中，我们将看一些基本的 DOM 操作集合。每个呈现的 DOM 操作都包括在 JavaScript、GopherJS 和使用 DOM 绑定中执行的等效操作。

# 显示警报消息

**JavaScript**

```go
alert("Hello Isomorphic Go!");
```

**GopherJS**

```go
js.Global.Call("alert", "Hello Isomorphic Go!")
```

**DOM 绑定**

```go
dom.GetWindow().Alert("Hello Isomorphic Go!")
```

我们可以执行的最基本的操作之一是在模态对话框中显示`alert`消息。在 JavaScript 中，我们可以使用内置的`alert`函数显示`alert`消息：

```go
alert("Hello Isomorphic Go!");
```

这行代码将在模态窗口对话框中打印出消息`Hello Isomorphic Go!`。`alert`函数会阻止进一步执行，直到用户关闭`alert`对话框。

当我们调用`alert`方法时，实际上是这样调用的：

```go
window.alert("Hello Isomorphic Go!");
```

`window`对象是一个全局对象，代表浏览器中打开的窗口。JavaScript 实现允许我们直接调用`alert`函数以及其他内置函数，而不需要将它们显式地引用为窗口对象的方法，这是一种方便的方式。

我们使用`js`包通过 GopherJS 访问 JavaScript 功能。我们可以将包导入到我们的 Go 程序中，如下所示：

```go
import "github.com/gopherjs/gopherjs/js"
```

`js`包为我们提供了与原生 JavaScript API 交互的功能。对`js`包中的函数的调用直接转换为它们等效的 JavaScript 语法。

我们可以使用 GopherJS 在 Go 中以以下方式显示`alert`消息对话框：

```go
js.Global.Call("alert", "Hello Isomorphic Go!")
```

在前面的代码片段中，我们使用了`js.Global`对象可用的`Call`方法。`js.Global`对象为我们提供了 JavaScript 的全局对象（`window`对象）。

这是`Call`方法的签名：

```go
func (o *Object) Call(name string, args ...interface{}) *Object
```

`Call`方法将调用全局对象的方法，并提供名称。提供给方法的第一个参数是要调用的方法的名称。第二个参数是要传递给全局对象方法的参数列表。`Call`方法被称为可变函数，因为它可以接受`interface{}`类型的可变数量的参数。

您可以通过查看 GopherJS 文档了解更多关于`Call`方法的信息[`godoc.org/github.com/gopherjs/gopherjs/js#Object.Call`](https://godoc.org/github.com/gopherjs/gopherjs/js#Object.Call)。

现在我们已经看到了如何使用`js.Global`对象的`Call`方法来显示`alert`对话框窗口，让我们来看看 DOM 绑定。

`dom`包为我们提供了方便的 GopherJS 绑定到 JavaScript DOM API。使用这个包的想法是，与使用`js.Global`对象执行所有操作相比，DOM 绑定为我们提供了一种惯用的方式来调用常见的 DOM API 功能。

如果您已经熟悉用于访问和操作 DOM 的 JavaScript API，那么使用`dom`包将对您来说感觉自然。我们可以使用`GetWindow`函数访问全局窗口对象，就像这样：

```go
dom.GetWindow()
```

使用`dom`包，我们可以使用以下代码显示警报对话框消息：

```go
dom.GetWindow().Alert("Hello Isomorphic Go!")
```

对这段代码片段的粗略观察表明，这更接近于调用`alert`对话框的 JavaScript 方式：

```go
window.alert("Hello Isomorphic Go!")
```

由于这种相似性，熟悉 JavaScript DOM API 是一个好主意，因为它将使您能够熟悉等效的函数调用，使用`dom`包。

您可以通过查看包的文档来了解更多关于`dom`包的信息</span>[`godoc.org/honnef.co/go/js/dom`](https://godoc.org/honnef.co/go/js/dom)。

# 通过 ID 获取 DOM 元素

我们可以使用`document`对象的`getElementById`方法来访问给定`id`的元素。在这些例子中，我们访问了具有`id`为`"primaryContent"`的主要内容`div`容器。

JavaScript

```go
element = document.getElementById("primaryContent");
```

GopherJS

```go
element := js.Global.Get("document").Call("getElementById", "primaryContent")
```

DOM 绑定

```go
element := dom.GetWindow().Document().GetElementByID("primaryContent")
```

尽管`dom`包的方法调用与 JavaScript 的方法调用非常相似，但可能会出现细微的差异。

例如，注意在 JavaScript 中使用`document`对象的`getElementById`方法调用时的大写，以及使用 DOM 绑定时使用`GetElementByID`方法调用时的大写。

为了在 Go 中导出`GetElementByID`方法，我们必须大写第一个字母，这里是*G*。此外，注意在使用 JavaScript 方式时，*Id*的大小写的微妙差异，与使用 DOM 绑定时*ID*的大小写的微妙差异。

# 查询选择器

`document`对象的`querySelector`方法为我们提供了一种使用 CSS 查询选择器访问 DOM 元素的方法，类似于 jQuery 库。我们可以使用文档对象的`querySelector`方法访问包含欢迎消息的`h2`元素，在 IGWEB 主页上。

JavaScript

```go
element = document.querySelector(".welcomeHeading");
```

GopherJS

```go
element := js.Global.Get("document").Call("querySelector", ".welcomeHeading")
```

DOM 绑定

```go
element := dom.GetWindow().Document().QuerySelector(".welcomeHeading")
```

# 更改元素的 CSS 样式属性

在我们之前涵盖的代码片段中，我们只考虑了访问 DOM 元素的例子。现在，让我们考虑一个例子，我们将改变一个元素的 CSS 样式属性。我们将通过改变`div`元素的`display`属性来隐藏主要内容`div`容器中的内容。

我们可以通过给`js.Global`和`dom`包的调用起别名来节省一些输入，就像这样：

对于 GopherJS：

`JS := js.Global`

对于`dom`包：

`D := dom.GetWindow().Document()`

为了改变主要内容 div 容器的显示属性，我们首先需要访问`div`元素，然后将其`display`属性更改为`none`值。

JavaScript

```go
element = document.GetElementById("primaryContent");
element.style.display = "none"
```

GopherJS

```go
js := js.Global
element := js.Get("document").Call("getElementById"), "primaryContent")
element.Get("style").Set("display", "none")
```

DOM 绑定

```go
d := dom.GetWindow().Document()
element := d.GetElementByID("welcomeMessage")
element.Style().SetProperty("display", "none", "")
```

您可以通过使用 GopherJS Playground 来体验使用 GopherJS，网址为[`gopherjs.github.io/playground/`](https://gopherjs.github.io/playground/)。

# GopherJS 概述

现在我们已经预览了使用 GopherJS，让我们来考虑一下 GopherJS 的工作原理的高级概述。*图 3.3*描述了一个同构的 Go 应用程序，其中包括一个使用 GopherJS 的 Go 前端 Web 应用程序和一个 Go 后端 Web 应用程序：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/20fc07f2-fb79-454b-a515-00ad25513e50.png)

图 3.3：同构的 Go Web 应用程序包括一个使用 GopherJS 的 Go 前端 Web 应用程序和一个 Go 后端 Web 应用程序

在图 3.3 中，我们将通信方式描述为 HTTP 事务，但重要的是要注意，这不是客户端和 Web 服务器进行通信的唯一方式。我们还可以使用 Web 浏览器的 WebSocket API 建立持久连接，这将在第八章中介绍，即*实时 Web 应用程序功能*。

在前一节中，我们介绍了 GopherJS DOM 绑定的微例子，它们为我们提供了对 DOM API 的访问，这是在 Web 浏览器中实现的 JavaScript API。除了 DOM API 之外，还有其他 API，如 XHR（用于创建和发送 XMLHttpRequests）API 和 WebSocket API（用于与 Web 服务器创建双向持久连接）。XHR 和 WebSocket API 也有 GopherJS 绑定可用。

图 3.4 显示了左侧的常见 JavaScript API，右侧是它们对应的 GopherJS 绑定。有了 GopherJS 绑定，我们可以从 Go 编程语言中访问 JavaScript API 功能：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/4f3bdd37-00ad-44a5-90ba-567cdcdebe49.png)

图 3.4：常见的 JavaScript API 及其等效的 GopherJS 绑定

# GopherJS 转译器

我们使用 GopherJS 转译器将 Go 程序转换为 JavaScript 程序。图 3.5 描述了一个 Go 程序，不仅使用了 Go 标准库的功能，还使用了各种 JavaScript API 的功能，使用了等效的 GopherJS 绑定包：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/03e2e6dc-3294-4428-896f-ac16c157496a.png)

图 3.5：使用标准库和 GopherJS 绑定转译为等效 JavaScript 程序的 Go 程序

我们使用`gopherjs build`命令将 Go 程序转译为其等效的 JavaScript 表示。生成的 JavaScript 源代码不是供人类修改的。JavaScript 程序可以访问嵌入在 Web 浏览器中的 JavaScript 运行时，以及常见的 JavaScript API。

要了解类型是如何从 Go 转换为 JavaScript 的，请查看[`godoc.org/github.com/gopherjs/gopherjs/js`](https://godoc.org/github.com/gopherjs/gopherjs/js)上的表格。

关于 IGWEB，我们将前端 Go Web 应用程序项目代码组织在`client`文件夹中。这使我们可以将前端 Web 应用程序与后端 Web 应用程序清晰地分开。

图 3.6 显示了包含许多 Go 源文件的客户端项目文件夹：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/4758a86b-a357-4112-b9f0-c6040844c343.png)

图 3.6：客户端文件夹包含组成前端 Go Web 应用程序的 Go 源文件。GopherJS 转译器生成一个 JavaScript 程序（client.js）和一个源映射（client.js.map）

在`client`文件夹中运行 GopherJS 转译器对 Go 源文件进行处理时，通过发出`gopherjs build`命令，将创建两个输出文件。第一个输出文件是`client.js`文件，代表等效的 JavaScript 程序。第二个输出文件是`client.js.map`文件，这是用于调试目的的源映射。这个源映射在我们使用 Web 浏览器的控制台追踪错误时，通过提供详细的错误信息来帮助我们。

附录：调试同构 Go 包含了有关调试使用 Go 实现的同构 Web 应用程序的指导和建议。

`gopherjs build`命令在行为上与其`go build`对应命令相同。客户端项目文件夹可以包含任意数量的子文件夹，这些子文件夹也可能包含 Go 源文件。当我们执行`gopherjs build`命令时，将创建一个 JavaScript 源程序和一个源`map`文件。这类似于在发出`go build`命令时创建的单个静态二进制文件。

在`client`文件夹之外，服务器和客户端之间共享的代码可以通过在`import`语句中指定共享包的正确路径来共享。`shared`文件夹将包含要在各个环境中共享的代码，例如模型和模板。

我们可以使用`<script>`标签将 GopherJS 生成的 JavaScript 源文件作为外部`javascript`源文件包含在我们的 Web 页面中，如下所示：

```go
<script type="text/javascript" src="img/client.js"></script>
```

请记住，当我们发出`gopherjs build`命令时，我们不仅创建了我们正在编写的程序的 JavaScript 等效程序，还带来了我们的程序依赖的标准库或第三方包。因此，除了包含我们的前端 Go 程序外，GopherJS 还包括我们的程序依赖的任何依赖包。

并非所有来自 Go 标准库的包都可以在 Web 浏览器中使用。您可以参考 GopherJS 兼容性表，查看 Go 标准库中受支持的包的列表，网址为[`github.com/gopherjs/gopherjs/blob/master/doc/packages.md`](https://github.com/gopherjs/gopherjs/blob/master/doc/packages.md)。

这一事实的后果是，生成的 JavaScript 源代码文件大小将与我们在 Go 程序中引入的依赖关系数量成比例增长。这一事实的另一个后果是，如*图 3.7*所示，在同一个 Web 页面中包含多个 GopherJS 生成的 JavaScript 文件是没有意义的，因为依赖包（例如标准库中的常见包）将被多次包含，不必要地增加我们的总脚本负载，并且没有任何回报价值：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/c50fbfc9-8ffa-41b3-94bf-91fd6243c09e.png)

图 3.7：不要在单个 Web 页面中导入多个 GopherJS 生成的源文件

因此，一个 Web 页面最多应包含一个 GopherJS 生成的源文件，如*图 3.8*所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/99c52275-0f7c-4958-9f46-6168436a2eb6.png)

图 3.8：Web 页面中应包含一个 GopherJS 生成的源文件

# GopherJS 示例

在本章的前面，我们预览了使用 GopherJS 编码的样子。现在我们将看一些完全充实的示例，以巩固我们对一些基本概念的理解。

如前所述，前端 Web 应用程序的源代码可以在`client`文件夹中找到。

如果要手动转换客户端目录中的 Go 代码，可以在`client`文件夹中发出`gopherjs build`命令：

```go
$ gopherjs build
```

如前所述，将生成两个源文件——`client.js` JavaScript 源文件和`client.js.map`源映射文件。

要手动运行 Web 服务器，可以进入`igweb`文件夹并运行以下命令：

```go
$ go run igweb.go
```

更方便的替代方法是使用`kick`编译 Go 代码和 GopherJS 代码，命令如下：

```go
$ kick --appPath=$IGWEB_APP_ROOT --gopherjsAppPath=$IGWEB_APP_ROOT/client --mainSourceFile=igweb.go
```

使用`kick`的优势在于它将自动监视对 Go 后端 Web 应用程序或 GopherJS 前端 Web 应用程序所做的更改。如前一章所述，当检测到更改时，`kick`将执行*instant kickstart*，这将加快您的迭代开发周期。

一旦您运行了`igweb`程序，可以在以下网址访问 GopherJS 示例：[](http://localhost:8080/front-end-examples-demo) `http://localhost:8080/front-end-examples-demo`

前端示例演示将包含一些基本的 GopherJS 示例。让我们打开`igweb`文件夹中的`igweb.go`源文件，看看一切是如何工作的。

在`registerRoutes`函数中，我们注册以下路由：

```go
r.Handle("/front-end-examples-demo", handlers.FrontEndExamplesHandler(env)).Methods("GET")
r.Handle("/lowercase-text", handlers.LowercaseTextTransformHandler(env)).Methods("POST")
```

`/front-end-examples-demo`路由用于显示我们的前端示例网页。`/lowercase-text`路由用于将文本转换为小写。我们将在稍后更详细地介绍第二个路由；首先，让我们看一下处理`/front-end-examples-demo`路由的处理程序函数（位于`handlers/frontendexamples.go`源文件中）：

```go
package handlers

import (
  "net/http"
  "github.com/EngineerKamesh/igb/igweb/common"
  "github.com/isomorphicgo/isokit"
)

func FrontEndExamplesHandler(env *common.Env) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    env.TemplateSet.Render("frontend_examples_page", &isokit.RenderParams{Writer: w, Data: nil})
  })
}
```

在这里，我们已经定义了我们的处理程序函数`FrontEndExamplesHandler`，它接受一个`env`对象的指针作为输入参数，并返回一个`http.Handler`函数。我们已经定义了一个闭包来返回`http.HandlerFunc`，它接受`http.ResponseWriter`和`*http.Request`作为输入参数。

我们在`TemplateSet`对象上调用`Render`方法来渲染前端示例页面。方法的第一个输入参数是模板的名称，即`frontend_examples_page`。第二个输入参数是要使用的渲染参数。由于我们是从服务器端渲染模板，我们传递`w`，即`http.ResponseWriter`，负责写出网页响应（渲染的模板）。由于我们没有向模板传递任何数据，我们将`RenderParams`结构体的`Data`字段赋值为`nil`。

在第四章中，*同构模板*，我们将解释模板集是如何工作的，以及我们如何使用`isokit`包提供的同构模板渲染器在服务器端和客户端渲染模板。

在`client.go`源文件中的`initializePage`函数的部分源代码列表中，我们包含了以下代码行来初始化 GopherJS 代码示例（以粗体显示）：

```go
func initializePage(env *common.Env) {

  l := strings.Split(env.Window.Location().Pathname, "/")
  routeName := l[1]

  if routeName == "" {
    routeName = "index"
  }

  if strings.Contains(routeName, "-demo") == false {
    handlers.InitializePageLayoutControls(env)
  }

  switch routeName {

  case "front-end-examples-demo":
    gopherjsprimer.InitializePage()
```

`gopherjsprimer.InitializePage`函数负责向前端示例网页中的元素添加事件侦听器。在注册任何事件之前，我们首先检查页面是否已经访问了`/front-end-examples`路由。如果用户正在访问不同路由的页面，例如`/index`，则无需为前端示例页面设置事件处理程序。如果用户已经访问了`/front-end-examples`路由，那么控制流将到达指定值为`"front-end-examples-demo"`的`case`语句，并且我们将通过调用`gopherjsprimer.InitializePage`函数为网页上的 UI 元素设置所有事件处理程序。

让我们仔细看看`client/gopherjsprimer/initpage.go`源文件中的`InitializePage`函数：

```go
func InitializePage() {

  d := dom.GetWindow().Document()

  messageInput := d.GetElementByID("messageInput").(*dom.HTMLInputElement)

  alertButtonJS := d.GetElementByID("alertMessageJSGlobal").(*dom.HTMLButtonElement)
  alertButtonJS.AddEventListener("click", false, func(event dom.Event) {
 DisplayAlertMessageJSGlobal(messageInput.Value)
 })

  alertButtonDOM := d.GetElementByID("alertMessageDOM").(*dom.HTMLButtonElement)
 alertButtonDOM.AddEventListener("click", false, func(event dom.Event) {
 DisplayAlertMessageDOM(messageInput.Value)
 })

  showGopherButton := d.GetElementByID("showGopher").(*dom.HTMLButtonElement)
 showGopherButton.AddEventListener("click", false, func(event dom.Event) {
 ShowIsomorphicGopher()
 })

  hideGopherButton := d.GetElementByID("hideGopher").(*dom.HTMLButtonElement)
 hideGopherButton.AddEventListener("click", false, func(event dom.Event) {
 HideIsomorphicGopher()
 })

  builtinDemoButton := d.GetElementByID("builtinDemoButton").(*dom.HTMLButtonElement)
 builtinDemoButton.AddEventListener("click", false, func(event dom.Event) {
 builtinDemo(event.Target())
 })

  lowercaseTransformButton := d.GetElementByID("lowercaseTransformButton").(*dom.HTMLButtonElement)
 lowercaseTransformButton.AddEventListener("click", false, func(event dom.Event) {
 go lowercaseTextTransformer()
 })

}
```

`InitializePage`函数负责使用元素的`AddEventListener`方法（以粗体显示）向前端示例网页中的元素添加事件侦听器。

# 显示警报消息

让我们从一个例子开始，显示一个警报对话框。在本章的前面，我们看到了如何使用`js.Global`对象的`Call`方法和 GopherJS DOM 绑定来显示警报对话框。*图 3.9*描述了我们第一个例子的用户界面：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/740dc41d-898d-425d-9898-8ee2959e019c.png)

图 3.9：显示警报消息示例

用户界面包括一个输入文本字段，用户可以在其中输入要显示在警报对话框中的自定义消息。文本字段后面是两个按钮：

+   第一个按钮将使用`js.Global`对象上的`Call`方法显示警报对话框

+   第二个按钮将使用 GopherJS DOM 绑定显示警报对话框

前端示例的 HTML 标记可以在位于`shared/templates/frontend_examples_page.tmpl`的模板文件中找到。

以下是警报消息示例的 HTML 标记：

```go
<div class="example">
<form class="pure-form">
  <fieldset class="pure-group">
  <h2>Example: Display Alert Message</h2>
  </fieldset>
  <fieldset class="pure-control-group">
  <label for="messageInput">Alert Message: </label>
  <input id="messageInput" type="text" value="Hello Gopher!" />
  </fieldset>
  <fieldset class="pure-group">
 <button id="alertMessageJSGlobal" type="button" class="pure-button pure-button-primary">Display Alert Message using js.Global</button>
 <button id="alertMessageDOM" type="button" class="pure-button pure-button-primary">Display Alert Message using dom package</button>
</fieldset>
</form>
</div>
```

在这里，我们声明了两个按钮（用粗体显示）并为它们分配了唯一的 id。使用`js.Global.Call`功能显示警报对话框的按钮具有`alertMessageJSGlobal`的 id。使用 GopherJS DOM 绑定显示警报对话框的按钮具有`alertMessageDOM`的 id。

在`initpage.go`源文件中定义的`InitializePage`函数中的以下代码片段负责为在示例中显示的`Display Alert Message`按钮设置事件处理程序：

```go
  alertButtonJS := d.GetElementByID("alertMessageJSGlobal").(*dom.HTMLButtonElement)
  alertButtonJS.AddEventListener("click", false, func(event dom.Event) {
    DisplayAlertMessageJSGlobal(messageInput.Value)
  })

  alertButtonDOM := d.GetElementByID("alertMessageDOM").(*dom.HTMLButtonElement)
  alertButtonDOM.AddEventListener("click", false, func(event dom.Event) {
    DisplayAlertMessageDOM(messageInput.Value)
  })
```

我们通过在`document`对象上调用`GetElementByID`函数来获取第一个按钮，将按钮的`id`作为函数的输入参数传递。然后，我们调用按钮上的`AddEventListener`方法来创建一个新的事件监听器，该监听器将监听点击事件。当第一个按钮被点击时，我们调用`DisplayAlertMessagesJSGlobal`函数，并传递`messageInput`文本字段的值，其中包含用户可以输入的自定义警报消息。

我们以类似的方式为第二个按钮设置了事件监听器，只是当检测到按钮上的点击事件时，我们调用`DisplayAlertMessageDOM`函数，该函数调用使用 GopherJS DOM 绑定显示警报对话框的函数。同样，我们将`messageInput`文本字段的值传递给函数。

现在，如果你点击任何一个按钮，你应该能够看到警报对话框。将警报消息更改为不同的内容，并注意你对警报消息文本字段所做的更改将反映在警报对话框中。*图 3.10*描述了具有自定义消息 Hello Isomorphic Gopher!的警报对话框：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/8ce236ca-e89a-45e5-b86d-0ef86cca8a95.png)

图 3.10：显示具有自定义警报消息的示例

# 更改元素的 CSS 样式属性

现在我们将看一个例子，其中我们实际上通过改变元素的 CSS 样式属性来操作 DOM。这个例子的用户界面由等距地图鼹鼠的图像组成，正下方是两个按钮，如*图 3.11*所示。第一个按钮被点击时，如果它被隐藏，将显示等距地图鼹鼠图像。第二个按钮被点击时，如果它被显示，将隐藏等距地图鼹鼠图像。*图 3.11*显示了等距地图鼹鼠可见时的情况：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/08a48cf6-fa7c-4848-a09b-a8981a2fb0c7.png)

图 3.11：当等距地图鼹鼠图像可见时的用户界面

*图 3.12*描述了当等距地图鼹鼠图像不可见时的用户界面：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/14bd6b99-7a09-41af-b4cd-815616e2a4a6.png)

图 3.12：当等距地图鼹鼠图像不可见时的用户界面

以下是为此示例生成用户界面的 HTML 标记：

```go
<div class="example">
  <form class="pure-form">
  <fieldset class="pure-group">
    <h2>Example: Change An Element's CSS Style Property</h2>
  </fieldset>
  <fieldset class="pure-group">
    <div id="igRacer">
      <img id="isomorphicGopher" border="0" src="img/isomorphic_go_logo.png">
    </div>
  </fieldset>
  <fieldset class="pure-group">
 <button id="showGopher" type="button" class="pure-button pure-button-primary">Show Isomorphic Gopher</button>
 <button id="hideGopher" type="button" class="pure-button pure-button-primary">Hide Isomorphic Gopher</button>
  </fieldset>
  </form>
</div>
```

在这里，我们声明了代表等距地图鼹鼠图像的图像标签，并为其分配了`isomorphicGopher`的 id。我们声明了两个按钮（用粗体显示）：

+   第一个按钮，具有`showGopher`的 id，将在点击时显示等距地图鼹鼠图像

+   第二个按钮，具有`hideGopher`的 id，将在点击时隐藏等距地图鼹鼠图像

`InitializePage`函数中的以下代码片段负责为显示和隐藏等距地图鼹鼠图像的两个按钮设置事件处理程序：

```go
  showGopherButton := d.GetElementByID("showGopher").(*dom.HTMLButtonElement)
  showGopherButton.AddEventListener("click", false, func(event dom.Event) {
    ShowIsomorphicGopher()
  })

  hideGopherButton := d.GetElementByID("hideGopher").(*dom.HTMLButtonElement)
  hideGopherButton.AddEventListener("click", false, func(event dom.Event) {
    HideIsomorphicGopher()
  })
```

如果点击显示等距地图鼹鼠按钮，我们调用`ShowIsomorphicGopher`函数。如果点击隐藏等距地图鼹鼠按钮，我们调用`HideIsomorphicGopher`函数。

让我们来看一下`client/gopherjsprimer/cssexample.go`源文件中定义的`ShowIsomorphicGopher`和`HideIsomorphicGopher`函数：

```go
package gopherjsprimer

import "honnef.co/go/js/dom"

func toggleIsomorphicGopher(isVisible bool) {

  d := dom.GetWindow().Document()
  isomorphicGopherImage := d.GetElementByID("isomorphicGopher").(*dom.HTMLImageElement)

  if isVisible == true {
    isomorphicGopherImage.Style().SetProperty("display", "inline", "")
  } else {
    isomorphicGopherImage.Style().SetProperty("display", "none", "")
  }

}

func ShowIsomorphicGopher() {
  toggleIsomorphicGopher(true)
}

func HideIsomorphicGopher() {
  toggleIsomorphicGopher(false)
}
```

`ShowIsomorphicGopher`和`HideIsomorphicGopher`函数都调用`toggleIsomorphicGopher`函数。唯一的区别是，`ShowIsomorphicGopher`函数调用`toggleIsomorphicGopher`函数并传入`true`的输入参数，而`HideIsomorphicGopher`函数调用`toggleIsomorphicGopher`函数并传入`false`的输入参数。

`toggleIsomorphicGopher`函数接受一个布尔变量作为参数，指示是否应显示`IsomorphicGopher`图像。

如果我们向函数传递`true`的值，那么等距地图像将被显示，如*图 3.11*所示。如果我们向函数传递`false`的值，那么等距地图像将不会被显示，如*图 3.12*所示。我们将`Document`对象的值赋给`d`变量。我们调用`Document`对象的`GetElementByID`方法来获取等距地图像。请注意，我们已经执行了类型断言（粗体显示），以断言`d.GetElementByID("isomorphicGopher")`返回的值具有`*dom.HTMLImageElement`的具体类型。

我们声明了一个`if`条件块，检查`isVisible`布尔变量的值是否为`true`，如果是，我们将图像元素的`Style`对象的`display`属性设置为`inline`。这将导致等距地图像出现，如*图 3.11*所示。

如果`isVisible`布尔变量的值为`false`，我们进入`else`块，并将图像元素的`Style`对象的`display`属性设置为`none`，这将防止等距地图像显示，如*图 3.12*所示。

# JavaScript typeof 运算符功能

JavaScript 的`typeof`运算符用于返回给定操作数的类型。例如，让我们考虑以下 JavaScript 代码：

```go
typeof 108 === "number"
```

这个表达式将求值为布尔值`true`。同样，现在考虑这段 JavaScript 代码：

```go
typeof "JavaScript" === "string"
```

这个表达式也将求值为布尔值`true`。

所以你可能会想，我们如何使用 Go 来使用 JavaScript 的`typeof`运算符？答案是，我们将需要`jsbuiltin`包，GopherJS 对内置 JavaScript 功能的绑定，其中包括`typeof`运算符。

在这个例子中，我们将使用`jsbuiltin`包使用 JavaScript 的`typeof`运算符。*图 3.13*展示了这个例子的用户界面：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/12865f98-0842-417e-8e3d-b5b7ea66b13a.png)

图 3.13：JavaScript typeof 示例的用户界面

以下是实现此示例用户界面的 HTML 标记：

```go
<div class="example">
  <h2>Example: JavaScript Builtin Functionality for typeof operation</h2>
  <p>Note: The message should appear in the web console after clicking the button below.</p>
 <button id="builtinDemoButton" type="button" class="pure-button pure-button-primary">Builtin Demo</button>
</div>
```

我们声明了一个`id`为`bultinDemoButton`的按钮。现在，让我们在`InitializePage`函数中为内置演示按钮设置一个事件侦听器，以处理点击事件：

```go
  builtinDemoButton := d.GetElementByID("builtinDemoButton").(*dom.HTMLButtonElement)
  builtinDemoButton.AddEventListener("click", false, func(event dom.Event) {
    builtinDemo(event.Target())
  })
```

我们通过在`Document`对象`d`上调用`GetElementID`方法来获取`button`元素。我们将返回的`button`元素赋给`builtinDemoButton`变量。然后我们向`button`元素添加事件侦听器以检测其是否被点击。如果检测到点击事件，我们调用`builtinDemo`函数并传入`button`元素的值，这恰好是事件目标。

让我们检查`client/gopherjsprimer`文件夹中的`builtindemo.go`源文件：

```go
package gopherjsprimer

import (
  "github.com/gopherjs/jsbuiltin"
  "honnef.co/go/js/dom"
)

func builtinDemo(element dom.Element) {

  if jsbuiltin.TypeOf(element) == "object" {
    println("Using the typeof operator, we can see that the element that was clicked, is an object.")
  }

}
```

`bulitindemo`函数接受`dom.Element`类型的输入参数。在这个函数内部，我们通过调用`jsbuiltin`包的`TypeOf`函数（粗体显示）对传入函数的元素执行 JavaScript 的`typeof`操作。我们检查传入的元素是否是对象。如果是对象，我们会在 Web 控制台上打印出一条消息，确认传入函数的元素是一个对象。*图 3.14*展示了在 Web 控制台上打印的消息：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/668122f7-9980-4234-b3b0-50af070d483f.png)

图 3.14：在内置演示按钮被点击后在 Web 控制台上打印的消息

从表面上看，这是一个相当琐碎的例子。然而，它突出了一个非常重要的概念——在 Go 的范围内，我们仍然可以访问内置的 JavaScript 功能。

# 使用 XHR post 将文本转换为小写

现在我们将创建一个简单的小写文本转换器。用户输入的任何文本都将转换为小写。我们的小写文本转换器解决方案的用户界面如*图 3.15*所示。在图像中，输入文本为 GopherJS。当用户点击 Lowercase It!按钮时，文本字段中的文本将被转换为其小写等价物，即 gopherjs：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/c9618da7-a56b-498f-b10c-74e41aa50f38.png)

图 3.15：小写文本转换器示例

实际上，我们可以在客户端上应用文本转换；然而，看到一个示例，我们将输入文本以`XHR Post`的形式发送到 Web 服务器，然后在服务器端执行小写转换会更有趣。一旦服务器完成将文本转换为小写，输入将被发送回客户端，并且文本字段将使用输入文本的小写版本进行更新。

这是用户界面的 HTML 标记：

```go
<div class="example">
  <form class="pure-form">
  <fieldset class="pure-group">
    <h2>Example: XHR Post</h2>
  </fieldset>
  <fieldset class="pure-control-group">
    <label for="textToLowercase">Enter Text to Lowercase: </label>
    <input id="textToLowercase" type="text" placeholder="Enter some text here to lowercase." value="GopherJS" />
  </fieldset>
  <fieldset class="pure-group">
    <button id="lowercaseTransformButton" type="button" class="pure-button pure-button-primary">Lowercase It!</button>
  </fieldset>
  </form>
</div>
```

我们声明一个`input`文本字段，用户可以在其中输入他们想要转换为小写的文本。我们为`input`文本字段分配了一个`id`为`textToLowercase`。然后我们声明一个带有`id`为`lowercaseTransformButton`的按钮。当点击此按钮时，我们将启动一个`XHR Post`到服务器。服务器将转换文本为小写并发送回输入文本的小写版本。

这是`InitializePage`函数中的代码，用于设置按钮的事件监听器：

```go
  lowercaseTransformButton := d.GetElementByID("lowercaseTransformButton").(*dom.HTMLButtonElement)
  lowercaseTransformButton.AddEventListener("click", false, func(event dom.Event) {
    go lowercaseTextTransformer()
  })
```

我们将`button`元素分配给`lowercaseTransformButton`变量。然后我们调用`button`元素上的`AddEventListener`方法来检测点击事件。当检测到点击事件时，我们调用`lowercaseTextTransformer`函数。

这是在`client/gopherjsprimer/xhrpost.go`源文件中定义的`lowercaseTextTransformer`函数：

```go
func lowercaseTextTransformer() {
  d := dom.GetWindow().Document()
  textToLowercase := d.GetElementByID("textToLowercase").(*dom.HTMLInputElement)

  textBytes, err := json.Marshal(textToLowercase.Value)
  if err != nil {
    println("Encountered error while attempting to marshal JSON: ", err)
    println(err)
  }

  data, err := xhr.Send("POST", "/lowercase-text", textBytes)
  if err != nil {
    println("Encountered error while attempting to submit POST request via XHR: ", err)
    println(err)
  }

  var s string
  err = json.Unmarshal(data, &s)

  if err != nil {
    println("Encountered error while attempting to umarshal JSON data: ", err)
  }
  textToLowercase.Set("value", s)
}
```

我们首先通过获取文本输入元素并将其分配给`textToLowercase`变量来开始。然后，我们使用`json`包中的`Marshal`函数将输入到文本输入元素中的文本值编组为其 JSON 表示形式。我们将编组的值分配给`textBytes`变量。

我们使用 GopherJS XHR 绑定来发送`XHR Post`到 Web 服务器。XHR 绑定是通过`xhr`包提供给我们的。我们调用`xhr`包中的`Send`函数来提交`XHR Post`。函数的第一个参数是我们将用于提交数据的 HTTP 方法。这里我们指定`POST`作为 HTTP 方法。第二个输入参数是要将数据提交到的路径。这里我们指定了`/lowercase-text`路由，这是我们在`igweb.go`源文件中设置的。第三个也是最后一个参数是要通过`XHR Post`发送的数据，即`textBytes`——JSON 编组的数据。

来自`XHR Post`的服务器响应将存储在`data`变量中。我们调用`json`包中的`Unmarshal`函数来解组服务器的响应，并将解组的值分配给`string`类型的`s`变量。然后我们使用`textToLowercase`对象的`Set`方法将文本输入元素的值设置为`s`变量的值。

现在，让我们来看看负责在`handlers/lowercasetext.go`源文件中进行小写转换的服务器端处理程序：

```go
package handlers

import (
  "encoding/json"
  "fmt"
  "io/ioutil"
  "log"
  "net/http"
  "strings"

  "github.com/EngineerKamesh/igb/igweb/common"
)

func LowercaseTextTransformHandler(env *common.Env) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    var s string

    reqBody, err := ioutil.ReadAll(r.Body)
    if err != nil {
      log.Print("Encountered error when attempting to read the request body: ", err)
    }

    reqBodyString := string(reqBody)

    err = json.Unmarshal([]byte(reqBodyString), &s)
    if err != nil {
      log.Print("Encountered error when attempting to unmarshal JSON: ", err)
    }

    textBytes, err := json.Marshal(strings.ToLower(s))
    if err != nil {
      log.Print("Encountered error when attempting ot marshal JSON: ", err)
    }
    fmt.Println("textBytes string: ", string(textBytes))
    w.Write(textBytes)

  })

}
```

在`LowercaseTextTransformHandler`函数中，我们调用`ioutil`包中的`ReadAll`函数来读取请求体。我们将`reqBody`的字符串值保存到`reqBodyString`变量中。然后我们对这个字符串进行 JSON 解组，并将解组后的值存储到`string`类型的`s`变量中。

我们使用`strings`包中的`ToLower`函数将`s`字符串变量的值转换为小写，并将该值编组成 JSON 表示。然后我们在`http.ResponseWriter`的`w`上调用`Write`方法，将字符串的 JSON 编组值写出为小写。

当我们在用户界面中点击 Lowercase It!按钮时，字符串 GopherJS 会被转换为其小写表示 gopherjs，如*图 3.16*所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/51fee22d-c095-4427-aeee-15ef890c2179.png)

图 3.16：当按钮被点击时，文本“GopherJS”被转换为小写的“gopherjs”

# 内联模板渲染

在这一部分，您将学习如何使用 GopherJS 在 Go 中执行客户端模板渲染。我们可以直接在 Web 浏览器中使用`html/template`包来渲染模板。我们将使用内联模板来渲染汽车表格的各行。

# 汽车列表演示

在汽车列表演示中，我们将使用内联客户端端 Go 模板填充一张表格的行。在我们的示例中，表格将是汽车列表，我们将从汽车切片中获取要显示在表格中的汽车。然后我们使用`gob`编码对汽车切片进行编码，并通过 XHR 调用将数据传输到 Web 服务器实例。

客户端模板渲染有很多好处：

+   Web 服务器上的 CPU 使用率是由服务器端模板渲染引起的

+   不需要完整页面重新加载来渲染客户端模板

+   通过在客户端端渲染模板来减少带宽消耗

让我们在`shared/templates/carsdemo_page.tmpl`目录中打开`cars.html`源文件：

```go
{{ define "pagecontent" }}
<table class="mdl-data-table mdl-js-data-table mdl-shadow--2dp">
  <thead>
    <tr>
      <th class="mdl-data-table__cell--non-numeric">Model Name</th>
      <th class="mdl-data-table__cell--non-numeric">Color</th>
      <th class="mdl-data-table__cell--non-numeric">Manufacturer</th>
    </tr>
  </thead>
 <tbody id="autoTableBody">
 </tbody>
</table>
{{end}}
{{template "layouts/carsdemolayout" . }}
```

这个 HTML 源文件包含了我们示例的网页内容，一个汽车表格，我们将使用内联模板来渲染表格的每一行。

我们使用`table`标签声明了将在网页上显示的表格。我们声明了每一列的标题。由于我们将显示一张汽车表格，每辆车有三列；我们有一个列用于车型名称，一个列用于颜色，一个列用于制造商。

我们将要添加到表格中的每一行都将被追加到`tbody`元素中（以粗体显示）。

请注意，我们使用`carsdemolayout.tmpl`布局模板来布局汽车演示页面。让我们打开位于`shared/templates/layouts`目录中的这个文件：

```go
<html>
  {{ template "partials/carsdemoheader" }}
<body>
    <div class="pageContent" id="primaryContent">
      {{ template "pagecontent" . }}
    </div>
<script src="img/client.js"></script>
</body>
</html>
```

布局模板不仅负责渲染`pagecontent`模板，还负责渲染位于`templates/shared/partials`目录中的头部模板`carsdemoheader.tmpl`。布局模板还负责导入由 GopherJS 生成的`client.js`外部 JavaScript 源文件。

让我们来看一下`carsdemoheader.tmpl`源文件：

```go
<head>
  <link rel="icon" type="image/png" href="/static/images/isomorphic_go_icon.png">
  <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons">
  <link rel="stylesheet" href="https://code.getmdl.io/1.3.0/material.indigo-pink.min.css">
  <script defer src="img/material.min.js"></script>
</head>
```

在这个头部模板文件中，我们导入了 CSS 样式表和 Material Design Library 的 JavaScript 源文件。我们将使用 Material Design Library 来使用默认的材料设计样式使我们的表格看起来漂亮。

在`client.go`源文件的`initializePage`函数中，我们包含了以下代码行来初始化汽车演示代码示例，当着陆在汽车演示网页上时：

```go
carsdemo.InitializePage()
```

在`client/carsdemo`目录中的`cars.go`源文件中，我们声明了用于渲染给定汽车信息的内联模板：

```go
const CarItemTemplate = `
  <td class="mdl-data-table__cell--non-numeric">{{.ModelName}}</td>
  <td class="mdl-data-table__cell--non-numeric">{{.Color}}</td>
  <td class="mdl-data-table__cell--non-numeric">{{.Manufacturer}}</td>
`
```

我们声明了`CarItemTemplate`常量，这是一个多行字符串，包括我们的内联模板。在模板的第一行中，我们渲染包含型号名称的列。在模板的第二行中，我们渲染汽车的颜色。最后，在模板的第三行中，我们渲染汽车的制造商。

我们声明并初始化了`D`变量，使用了`Document`对象，如下所示：

```go
var D = dom.GetWindow().Document()
```

`InitializePage`函数（在`client/carsdemo/cars.go`源文件中找到）负责调用`cars`函数：

```go
func InitializePage() {
  cars()
}
```

在`cars`函数内部，我们创建了`nano`，`ambassador`和`omni`——`Car`类型的三个实例。就在这之后，我们使用汽车对象来填充`cars`切片：

```go
nano := models.Car{ModelName: "Nano", Color: "Yellow", Manufacturer: "Tata"}
ambassador := models.Car{ModelName: "Ambassador", Color: "White", Manufacturer: "HM"}
omni := models.Car{ModelName: "Omni", Color: "Red", Manufacturer: "Maruti Suzuki"}
cars := []models.Car{nano, ambassador, omni}
```

现在我们有了一个`cars`切片来填充表格，是时候用以下代码生成表格的每一行了：

```go
  autoTableBody := D.GetElementByID("autoTableBody")
  for i := 0; i < len(cars); i++ {
    trElement := D.CreateElement("tr")
    tpl := template.New("template")
    tpl.Parse(CarItemTemplate)
    var buff bytes.Buffer
    tpl.Execute(&buff, cars[i])
    trElement.SetInnerHTML(buff.String())
    autoTableBody.AppendChild(trElement)
  }
```

在这里，我们声明并初始化了`autoTableBody`变量，这是表格的`tbody`元素。这是我们将用来向表格追加新行的元素。我们遍历`cars`切片，对于每个`Car`结构，我们使用`Document`对象的`CreateElement`方法动态创建一个`tr`元素。然后我们创建一个新模板，并解析汽车项目模板的内容。

我们声明了一个名为`buff`的缓冲变量，用于保存执行模板的结果。我们在模板对象`tpl`上调用`Execute`函数，传入`buff`和`cars`切片的`i`索引处的当前`Car`记录，这将是传递给内联模板的数据对象。

然后我们在`tr`元素对象上调用`SetInnerHTML`方法，并传入`buff`变量的字符串值，其中包含我们渲染的模板内容。

这是所有行都填充的汽车表的样子：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/a5cb151a-e871-42ea-9bd8-f2ebbe2f98d9.png)

图 3.17：汽车表

这个例子对于说明目的是有用的，但在实际情况下并不是很实用。在 Go 源文件中混合使用 HTML 编写的内联模板可能会变得难以维护，因为项目代码库规模扩大。除此之外，如果我们有一种方法可以在客户端访问服务器端所有用户界面的模板，那将是很好的。事实上，我们可以做到，这将是我们在第四章中的重点，*同构模板*。

现在我们已经看到了如何渲染内联模板，让我们考虑如何将`cars`切片作为二进制数据以`gob`格式编码传输到服务器。

# 传输 gob 编码数据

`encoding/gob`包为我们提供了管理 gob 流的功能，这些流是在编码器和解码器之间交换的二进制值。您可以使用编码器将值编码为`gob`编码数据，然后使用解码器解码`gob`编码数据。

通过在服务器端和客户端上使用 Go，我们创建了一个 Go 特定的环境，如*图 3.18*所示。这是使用`encoding/gob`包进行客户端和服务器之间数据交换的理想环境：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/948fb981-58cf-4b2a-b0ff-e74256d19245.png)

图 3.18：Go 特定的环境

我们将要传输的数据包括`cars`切片。`Car`结构可以被认为是同构的，因为我们可以在客户端和服务器端都使用`Car`结构。

请注意，在`cars.go`源文件中，我们已经包含了`encoding/gob`包（以粗体显示）在我们的导入分组中：

```go
import (
  "bytes"
  "encoding/gob"
  "html/template"

  "github.com/EngineerKamesh/igb/igweb/shared/models"

  "honnef.co/go/js/dom"
  "honnef.co/go/js/xhr"
)
```

我们使用以下代码将`cars`切片编码为`gob`格式：

```go
  var carsDataBuffer bytes.Buffer
  enc := gob.NewEncoder(&carsDataBuffer)
  enc.Encode(cars)
```

在这里，我们声明了一个名为`carsDataBuffer`的字节缓冲区，它将包含`gob`编码的数据。我们创建了一个新的`gob`编码器，并指定我们要将编码后的数据存储到`carsDataBuffer`中。然后我们调用了`gob`编码器对象上的`Encode`方法，并传入了`cars`切片。到这一步，我们已经将`cars`切片编码到了`carsDataBuffer`中。

现在我们已经将`cars`切片编码成`gob`格式，我们可以使用`HTTP POST`方法通过 XHR 调用将`gob`编码的数据传输到服务器：

```go
  xhrResponse, err := xhr.Send("POST", "/cars-data", carsDataBuffer.Bytes())

  if err != nil {
    println(err)
  }

  println("xhrResponse: ", string(xhrResponse))
```

我们在`xhr`包中调用`Send`函数，并指定我们要使用`POST`方法，并将数据发送到`/cars-data`URL。我们调用`carsDataBuffer`上的`Bytes`方法，以获取缓冲区的字节切片表示。正是这个字节切片，我们将发送到服务器，并且它是`gob`编码的`car`切片。

服务器的响应将存储在`xhrResponse`变量中，并且我们将在网络控制台中打印出这个变量。

现在我们已经看到了程序的客户端部分，是时候来看看服务端处理程序函数了，它服务于`/cars-data`路由。让我们来看看`carsdata.go`源文件中定义的`CarsDataHandler`函数，它位于 handlers 目录中：

```go
func CarsDataHandler(env *common.Env) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

    var cars []models.Car
    var carsDataBuffer bytes.Buffer

    dec := gob.NewDecoder(&carsDataBuffer)
    body, err := ioutil.ReadAll(r.Body)
    carsDataBuffer = *bytes.NewBuffer(body)
    err = dec.Decode(&cars)

    w.Header().Set("Content-Type", "text/plain")

    if err != nil {
      log.Println(err)
      w.Write([]byte("Something went wrong, look into it"))

    } else {
      fmt.Printf("Cars Data: %#v\n", cars)
      w.Write([]byte("Thanks, I got the slice of cars you sent me!"))
    }

  })
}
```

在`CarsDataHandler`函数内部，我们声明了一个`cars`变量，它是一个`Car`对象的切片。在这之下，我们有`carsDataBuffer`，它将包含从客户端网页应用程序发送的 XHR 调用中接收到的`gob`编码数据。

我们创建了一个新的`gob`解码器，并指定`gob`数据将存储在`carsDataBuffer`中。然后我们使用`ioutil`包中的`ReadAll`函数来读取请求体并将所有内容保存到`body`变量中。

然后我们创建一个新的字节缓冲区，并将`body`变量作为输入参数传递给`NewBuffer`函数。`carsDataBuffer`现在包含了通过 XHR 调用传输的`gob`编码数据。最后，我们调用`dec`对象的`Decode`函数，将`gob`编码的数据转换回`Car`对象的切片。

如果我们没有收到任何错误，我们将`cars`切片打印到标准输出：

```go
Cars Data: []models.Car{models.Car{ModelName:"Nano", Color:"Yellow", Manufacturer:"Tata"}, models.Car{ModelName:"Ambassador", Color:"White", Manufacturer:"HM"}, models.Car{ModelName:"Omni", Color:"Red", Manufacturer:"Maruti Suzuki"}}
```

除了将`cars`切片打印到标准输出之外，我们还向网络客户端发送了一个响应，指示`cars`切片已成功接收。我们可以在网络浏览器控制台中查看这条消息：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/24b9fade-eb63-4b23-a704-55d075d06f03.png)

图 3.19：服务器对网络客户端的响应

# 本地存储

你知道吗，网络浏览器自带了一个内置的键值数据库吗？这个数据库的名字叫本地存储，在 JavaScript 中，我们可以将`localStorage`对象作为`window`对象的属性来访问。本地存储允许我们在网络浏览器中本地存储数据。本地存储是按域和协议划分的，这意味着来自相同来源的页面可以访问和修改共享数据。

以下是本地存储的一些好处：

+   它提供安全的数据存储

+   它的存储限制比 cookie 大得多（至少 5MB）

+   它提供低延迟的数据访问

+   对于不需要联网的网络应用程序非常有帮助

+   它可以用作本地缓存

# 常见的本地存储操作

我们将向您展示如何使用 JavaScript 代码对`localStorage`对象执行一些常见操作。这些操作包括以下内容：

1.  设置键值对

1.  获取给定键的值

1.  获取所有键值对

1.  清除所有条目

在下一节中，我们将向您展示如何使用 GopherJS 执行相同的操作，以一个完全充实的示例。

# 设置键值对

要将项目存储到本地存储中，我们调用`localStorage`对象的`setItem`方法，并将键和值作为参数传递给该方法：

```go
localStorage.setItem("foo", "bar"); 
```

在这里，我们提供了一个`"foo"`键，带有一个`"bar"`值。

# 获取给定键的值

要从本地存储中获取项目，我们调用`localStorage`对象的`getItem`方法，并将键作为该方法的单个参数传递：

```go
var x = localStorage.getItem("foo");
```

在这里，我们提供了`"foo"`键，并且我们期望`x`变量的值将等于`"bar"`。

# 获取所有键值对

我们可以使用`for`循环从本地存储中检索所有键值对，并使用`localStorage`对象的`key`和`getItem`方法访问键和值的值：

```go
for (var i = 0; i < localStorage.length; i++) {
  console.log(localStorage.key(i)); // prints the key
  console.log(localStorage.getItem(localStorage.key(i))); // prints the value
}
```

我们在`localStorage`对象上使用`key`方法，传入数字索引`i`，以获取存储中的第 i 个键。类似地，我们将`i`数字索引传递给`localStorage`对象的`key`方法，以获取存储中第 i 个位置的键的名称。请注意，键的名称是通过`localStorage.key(i)`方法调用获得的，并传递给`getItem`方法以检索给定键的值。

# 清除所有条目

我们可以通过在`localStorage`对象上调用`clear`方法轻松地删除本地存储中的所有条目：

```go
localStorage.clear();
```

# 构建本地存储检查器

根据上一节中关于如何利用`localStorage`对象的信息，让我们继续构建本地存储检查器。本地存储检查器将允许我们执行以下操作：

+   查看当前存储在本地存储中的所有键值对

+   向本地存储添加新的键值对

+   清除本地存储中的所有键值对

*图 3.20*描述了本地存储检查器的用户界面：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/f23ed4be-f436-4afe-b71f-7ced3274cf8c.png)

图 3.20：本地存储演示用户界面

直接位于 LocalStorage Demo 标题下方的框是一个`div`容器，负责保存当前存储在本地存储中的键值对列表。键输入文本字段是用户输入键的地方。值输入文本字段是用户输入键值对的值的地方。单击保存按钮将新的键值对条目保存到本地存储中。单击清除所有按钮将清除本地存储中的所有键值对条目。

# 创建用户界面

我们在`shared/templates/layouts`文件夹中找到的`localstorage_layout.tmpl`源文件中定义了本地存储演示页面的布局：

```go
<!doctype html>
<html>
  {{ template "partials/localstorageheader_partial" }}
  <body>
    <div class="pageContent" id="primaryContent">
      {{ template "pagecontent" . }}
    </div>

  <script type="text/javascript" src="img/client.js"></script>

  </body>
</html>
```

此布局模板定义了本地存储演示网页的布局。我们使用模板操作（以粗体显示）来呈现`partials/localstorageheader_partial`头部模板和`pagecontent`页面内容模板。

请注意，在网页底部，我们包含了 JavaScript 源文件`client.js`，这是由 GopherJS 生成的，使用`script`标签（以粗体显示）。

我们在`shared/templates/partials`文件夹中找到的`localstorageheader_partial.tmpl`源文件中定义了本地存储演示页面的头部模板。

```go
<head>
  <title>LocalStorage Demo</title> 
  <link rel="icon" type="image/png" href="/static/images/isomorphic_go_icon.png">
 <link rel="stylesheet" href="https://unpkg.com/purecss@1.0.0/build/pure-min.css" integrity="sha384-nn4HPE8lTHyVtfCBi5yW9d20FjT8BJwUXyWZT9InLYax14RDjBj46LmSztkmNP9w" crossorigin="anonymous">
 <link rel="stylesheet" type="text/css" href="/static/css/igweb.css">
 <link rel="stylesheet" type="text/css" href="/static/css/localstoragedemo.css">
</head>
```

此标题模板旨在呈现`head`标签，我们在其中使用`link`标签（以粗体显示）包含外部 CSS 样式表。

我们在`shared/templates`文件夹中找到的`localstorage_example_page.tmpl`源文件中定义了本地存储演示的用户界面的 HTML 标记：

```go
{{ define "pagecontent" }}

<h1>LocalStorage Demo</h1>

    <div id="inputFormContainer">
      <form class="pure-form">
      <fieldset class="pure-group" style="min-height: 272px">
      <div id="storageContents">
 <dl id="itemList">
 </dl>
 </div>
      </fieldset>

      <fieldset class="pure-control-group">
      <label for="messageInput">Key: </label>
      <input id="itemKey" type="text" value="" />
      <label for="messageInput">Value: </label>
      <input id="itemValue" type="text" value="" />

      </fieldset>

      <fieldset class="pure-control-group">
      </fieldset>

      <fieldset class="pure-group">
        <button id="saveButton" type="button" class="pure-button pure-button-primary">Save</button>
 <button id="clearAllButton" type="button" class="pure-button pure-button-primary">Clear All</button>
      </fieldset>
      </form>
    </div>

{{end}}
{{template "layouts/localstorage_layout" . }}
```

具有`"storageContents"`id 的`div`元素将用于存储本地存储数据库中的项目条目列表。实际上，我们将使用具有`"itemList"`id 的 dl（描述列表）元素来显示所有键值对。

我们为用户定义了一个输入文本字段以输入键，并且我们还为用户定义了一个输入文本字段以输入值。我们还为`Save`按钮定义了标记，并且直接在其下方，我们定义了`Clear All`按钮的标记。

# 设置服务器端路由

我们在`igweb.go`源文件中的`registerRoutes`函数中注册了`/localstorage-demo`路由：

```go
r.Handle("/localstorage-demo", handlers.LocalStorageDemoHandler(env)).Methods("GET")
```

我们已经定义了`LocalStorageDemoHandler`服务器端处理程序函数，用于服务于`localstorage-demo`服务器端路由，在`handlers`文件夹中找到的`localstoragedemo.go`源文件中：

```go
package handlers

import (
  "net/http"

  "github.com/EngineerKamesh/igb/igweb/common"
  "github.com/isomorphicgo/isokit"
)

func LocalStorageDemoHandler(env *common.Env) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    env.TemplateSet.Render("localstorage_example_page", &isokit.RenderParams{Writer: w, Data: nil})
  })
}
```

`LocalStorageDemoHandler`函数负责向客户端写入网页响应。它调用应用程序的`TemplateSet`对象的`Render`方法，以渲染`localstorage_example_page`模板。您将在第四章中了解更多关于渲染同构模板的内容，*同构模板*。

# 实现客户端功能

实现本地存储检查器的客户端功能包括以下步骤：

1.  初始化本地存储检查器网页

1.  实现本地存储检查器

# 初始化本地存储检查器网页

为了初始化本地存储检查器网页上的事件处理程序，我们需要在`client.go`源文件中的`initializePage`函数内的`localstorage-demo`情况下添加以下代码行：

```go
localstoragedemo.InitializePage()
```

调用`localstoragedemo`包中定义的`InitializePage`函数将为保存和清除所有按钮添加事件监听器。

# 实现本地存储检查器

本地存储检查器的实现可以在`client/localstoragedemo`目录中的`localstorage.go`源文件中找到。

在`import`分组中，我们包括了`js`和`dom`包（以粗体显示）：

```go
package localstoragedemo

import (
 "github.com/gopherjs/gopherjs/js"
 "honnef.co/go/js/dom"
)
```

我们已经定义了`localStorage`变量，并将其赋值为附加到`window`对象的`localStorage`对象的值：

```go
var localStorage = js.Global.Get("localStorage")
```

像往常一样，我们使用`D`变量将`Document`对象进行了别名，以节省一些输入。

```go
var D = dom.GetWindow().Document().(dom.HTMLDocument)
```

`InitializePage`函数负责为保存和清除所有按钮设置事件监听器：

```go
func InitializePage() {
 saveButton := D.GetElementByID("saveButton").(*dom.HTMLButtonElement)
 saveButton.AddEventListener("click", false, func(event dom.Event) {
 Save()
 })

 clearAllButton := D.GetElementByID("clearAllButton").(*dom.HTMLButtonElement)
 clearAllButton.AddEventListener("click", false, func(event dom.Event) {
 ClearAll()
 })

 DisplayStorageContents()
}
```

我们通过调用`Document`对象的`GetElementByID`方法并将`id``saveButton`作为该方法的唯一输入参数来获取`saveButton`元素。紧接着，我们在点击事件上添加一个事件监听器来调用`Save`函数。调用`Save`函数将保存一个新的键值对条目。

我们还通过调用`Document`对象的`GetElementByID`方法并将`id``clearAllButton`作为该方法的唯一输入参数来获取`clearAllButton`元素。紧接着，我们在点击事件上添加一个事件监听器来调用`ClearAll`函数。调用`ClearAll`函数将清除本地存储中当前存储的所有键值对。

`Save`函数负责将键值对保存到 Web 浏览器的本地存储中：

```go
func Save() {

 itemKey := D.GetElementByID("itemKey").(*dom.HTMLInputElement)
 itemValue := D.GetElementByID("itemValue").(*dom.HTMLInputElement)

  if itemKey.Value == "" {
    return
  }

  SetKeyValuePair(itemKey.Value, itemValue.Value)
  itemKey.Value = ""
  itemValue.Value = ""
  DisplayStorageContents()
}
```

我们使用`Document`对象的`GetElementByID`方法获取键和值的文本输入字段（以粗体显示）。在`if`条件块中，我们检查用户是否未为键输入文本字段输入值。如果他们没有输入值，我们就从函数中返回。

如果用户已经在键输入文本字段中输入了值，我们将继续。我们调用`SetKeyValuePair`函数，并将`itemKey`和`itemValue`的值作为输入参数传递给函数。

然后，我们将`itemKey`和`itemValue`的`Value`属性都设置为空字符串，以清除输入文本字段，这样用户可以轻松地在以后添加新条目而无需手动清除这些字段中的文本。

最后，我们调用`DisplayStorageContents`函数，该函数负责显示本地存储中的所有当前条目。

让我们来看看`SetKeyValuePair`函数：

```go
func SetKeyValuePair(itemKey string, itemValue string) {
  localStorage.Call("setItem", itemKey, itemValue)
}
```

在这个函数内部，我们只需调用`localStorage`对象的`setItem`方法，将`itemKey`和`itemValue`作为输入参数传递给函数。此时，键值对条目将保存到 Web 浏览器的本地存储中。

`DisplayStorageContents`函数负责在`itemList`元素（一个`dl`（描述列表）元素）中显示所有本地存储中的键值对。

```go
func DisplayStorageContents() {

  itemList := D.GetElementByID("itemList")
  itemList.SetInnerHTML("")

  for i := 0; i < localStorage.Length(); i++ {

    itemKey := localStorage.Call("key", i)
    itemValue := localStorage.Call("getItem", itemKey)

    dtElement := D.CreateElement("dt")
    dtElement.SetInnerHTML(itemKey.String())

    ddElement := D.CreateElement("dd")
    ddElement.SetInnerHTML(itemValue.String())

    itemList.AppendChild(dtElement)
    itemList.AppendChild(ddElement)
  }

}
```

我们调用`SetInnerHTML`方法并输入空字符串来清除列表的内容。

我们使用`for`循环遍历本地存储中的所有条目。对于每个键值对，我们通过调用`localStorage`对象的`key`和`getItem`方法分别获取`itemKey`和`itemValue`。

我们使用`dt`元素（`dtElement`）来显示键。`dt`元素用于定义描述列表中的术语。我们使用`dd`元素（`ddElement`）来显示值。`dd`元素用于描述描述列表中的术语。使用描述列表及其相关元素来显示键值对，我们使用了一种语义友好的方法来在网页上显示键值对。我们通过调用其`AppendChild`方法将`dt`和`dd`元素附加到`itemList`对象上。

`ClearAll`函数用于删除本地存储中保存的所有键值对：

```go
func ClearAll() {
  localStorage.Call("clear")
  DisplayStorageContents()
}
```

我们调用`localStorage`对象的`clear`方法，然后调用`DisplayStorageContents`函数。如果一切正常，所有项目应该被清除，一旦单击了清除所有按钮，我们应该看不到`itemList`元素中出现任何值。

# 运行本地存储演示

您可以在`http://localhost:8080/localstorage-demo`访问本地存储演示。

让我们向本地存储添加一个新的键值对。在键输入文本字段中，让我们添加`"foo"`键，在值输入文本字段中，让我们添加`"bar"`值。单击保存按钮将新的键值对添加到本地存储中。

图 3.21 显示了单击保存按钮后出现的新创建的键值对：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/923f5dd7-6b4b-42d9-b8bd-d739bf695dfd.png)

图 3.21：本地存储检查器显示了一个新添加的键值对

尝试刷新网页，然后尝试重新启动 Web 浏览器并返回网页。请注意，在这些情况下，本地存储仍然保留了保存的键值对。单击清除所有按钮后，您会注意到`itemList`已被清除，如图 3.20 所示，因为本地存储已清空所有键值对。

我们刚刚创建的本地存储检查器特别方便，可以检查由第三方 JavaScript 解决方案填充的键值对，这些解决方案被我们的客户端 Web 应用程序使用。如果您在 IGWEB 主页上查看图像轮播后登陆本地存储演示页面，您会注意到 itemList 中填充了图 3.22 中显示的键值对：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/b7232412-3b7a-4b72-873e-9f60e2b7fd6f.png)

图 3.22：本地存储演示显示了由图像轮播填充的键值对

这些键值对是由图像轮播填充的，我们将在第九章中实现为可重用组件。

# 总结

在本章中，我们向您介绍了使用 GopherJS 在前端进行 Go 编程。我们向您介绍了 DOM，并展示了如何使用 GopherJS 访问和操作 DOM。我们通过几个微例子来让您熟悉使用 GopherJS 编码的样子。然后我们继续展示了完全成熟的例子。

我们向您展示了如何显示警报对话框并显示自定义消息。我们还向您展示了如何更改元素的 CSS 样式属性。我们继续向您展示了如何在 Go 的限制范围内使用`jsbuiltin`包调用 JavaScript 的`typeof`运算符。我们向您展示了如何创建一个简单的小写文本转换器，并演示了如何使用`xhr`包发送`XHR Post`。我们还向您展示了如何渲染内联 Go 模板，最后，我们向您展示了如何构建本地存储检查器。

在第四章中，*同构模板*，我们将介绍同构模板，这些模板可以在服务器端或客户端上进行渲染。
