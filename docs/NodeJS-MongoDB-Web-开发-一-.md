# NodeJS MongoDB Web 开发（一）

> 原文：[`zh.annas-archive.org/md5/2FC862C6AE287FE2ADCD470958CE8295`](https://zh.annas-archive.org/md5/2FC862C6AE287FE2ADCD470958CE8295)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

随着 ECMAscript 6 的出现，Node.JS 的可用性在未来有很大的发展空间，并且已经在今天得到了实现。学习 es6 语法糖的需求以及包含大多数跨技术特性的需求，激励了不同的技术社区学习 JavaScript。

Node.js 的高性能和可扩展性以及名为 MongoDB 的开源 NoSQL 数据库解决方案适用于轻松构建快速、可扩展的网络应用程序。这种组合使得管理任何形式的数据变得简单，并确保其交付速度。

本书旨在提供使用 Node.JS 和 MongoDB 构建等同服务器端渲染 Web 应用程序的不同方面。本书还指导我们使用 hapi.js 创建可配置的 Node.JS 服务器，并学习使用 Angular 4 开发单页前端应用程序。

本书将首先介绍您建立开发环境所需的基础知识，并对新的 ECMAscript 与传统 JavaScript 的不同进行比较研究。一旦基础就绪，我们将快速浏览必要的步骤，使主要应用程序服务器运行起来，并学习 Node.JS 核心。

此外，我们将通过使用控制器和 ViewModels 来生成可重用代码，从而减少开发时间。开发以学习适当的测试概念以及如何自动化测试以实现可重用性和可维护性而结束。

在本书结束时，您将与 JavaScript 生态系统连接，并了解流行的 JavaScript 前端和后端框架。

# 本书涵盖内容

第一章，*欢迎来到全栈 JavaScript*，介绍了 Node.js 和 MongoDB。除此之外，它还将解释您将使用本书构建的应用程序的整体架构。

第二章，*启动和运行*，解释了如何为 Node.js 和 MongoDB 设置开发环境。您还将通过编写一个示例应用程序并运行它来验证一切是否设置正确。

第三章，*Node 和 MongoDB 基础*，是关于学习 JavaScript 的基础知识。此外，还介绍了 NodeJS 的需要了解的概念以及 MongoDB 上的基本 CRUD 操作。

第四章，*介绍 Express*，向您介绍了 Express 框架及其各个组件。它还指导您如何组织使用该框架构建的基本应用程序。它还将详细介绍 Express 的 MVC 组件。

第五章，*使用 Handlebars 进行模板化*，向您介绍了使用模板引擎和 handlebars 的概念。此外，它还向您展示了如何在应用程序中使用 handlebars 作为模板引擎。

第六章，*控制器和视图模型*，向您展示了如何将构建的示例应用程序的代码组织到 Express 框架的控制器和视图中。它将通过介绍将代码分离到各种模块并利用 Express 框架来间接介绍 MVS 概念。

第七章，*使用 MongoDB 持久化数据*，向您展示了如何从正在构建的 Node.js 应用程序连接到 MongoDB 服务器。它还将向您介绍 ODM 的概念，最流行的是 Mongoose。

第八章，*创建 RESTful API*，向您介绍了 RESTful API。它还向您展示了 RESTful 包装器对应用程序的重要性。然后，它将教您如何将当前应用程序更改为基于 REST API 的应用程序。

第九章，*测试您的代码*，向您展示为什么需要将测试与应用程序结合，并且还会提到您在本章编写的代码的可测试性需要注意的事项。

第十章，*使用基于云的服务部署*，讨论了托管您正在构建的 Node.js MongoDB 应用程序的选项。它还比较了市场上可用的各种 PaaS 解决方案。

第十一章，*流行的 Node.js Web 框架*，介绍了除了 Express 之外在 Node.js 上可用的各种 Web 框架，您将在本书中用于构建应用程序。您将分析各种 Web 框架，如 Meteor、Sails、Koa、Hapi 和 Flatiron。您还将通过创建 API 服务器更详细地学习一种独特类型的框架，即 hapi.js。

第十二章，*使用流行的前端框架创建单页应用程序*，提供了单页应用程序与流行的前端框架（如 backbone.js、ember.js、react.js 和 Angular）的比较研究。您将详细了解一种流行的框架--Angular4。此外，您还将分析流行的前端方面，如可用的自动化工具和转译器。

# 您需要为本书做好准备

本书只需要对 JavaScript 和 HTML 有基本的了解。然而，本书的设计也有助于具有基本编程知识和跨平台开发人员学习 JavaScript 及其框架的初学者。

# 本书适合对象

本书适用于具有以下标准的 JavaScript 开发人员：

+   那些想要学习后端 JavaScript 的人

+   那些了解 es5 并希望从新的 ECMAscript 开始的人

+   那些具有 JavaScript 中级知识并希望探索新框架，如 Angular 2、hapi 和 Express 的人

最后，本书适用于任何渴望学习 JavaScript 并希望在 Node.js 和 MongoDB 中构建交互式 Web 应用程序的跨平台开发人员。

# 约定

在本书中，您将找到许多文本样式，用以区分不同类型的信息。以下是一些示例以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下：

"在上述情况中，`setTimeout()`方法由 JavaScript（Node.js）API 提供。"

代码块设置如下：

```js
var http = require('http');
http.createServer(function(req, res) {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Hello World\n');
}).listen(8080, 'localhost');
console.log('Server running at http://localhost:8080'); 
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```js
app.engine('Handlebars', exphbs.create({ 
    defaultLayout: 'main', 
    layoutsDir: app.get('views') + '/layouts', 
    partialsDir: [app.get('views') + '/partials'], 
 helpers: { 
        timeago: (timestamp)=> { 
            return moment(timestamp).startOf('minute').fromNow(); 
        } 
    } 
}).engine); 
```

任何命令行输入或输出都以以下方式书写：

```js
$ sudo apt-get install python-software-properties $ sudo curl -sL https://deb.nodesource.com/setup_8.x | sudo -E bash - $ sudo apt-get install nodejs
```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如

例如，在菜单或对话框中出现的文本如下所示：

Mac 上一个很好的替代品是 iTerm2。

警告或重要提示以此框出现。

提示和技巧显示如下。


# 第一章：欢迎来到全栈 JavaScript

曾经只被认为是为网页添加增强功能和小部件的语言，现在已经发展成了一个完整的生态系统。截至 2017 年的调查（[`insights.stackoverflow.com/survey/2017`](https://insights.stackoverflow.com/survey/2017)），它是 stackoverflow 上使用量最大的语言，有大约一百万个与之相关的问题标签。有大量的框架和环境可以让 JavaScript 几乎在任何地方运行。我相信阿特伍德定律说得最好：

“任何可以用 JavaScript 编写的应用程序最终都将用 JavaScript 编写！”

尽管这句话可以追溯到 2007 年，但它在今天仍然是真实的。你不仅可以使用 JavaScript 开发完整的单页应用程序，比如 Gmail，还可以看到我们如何在本书的后续章节中使用它来实现以下项目：

+   完全使用 Node.js 和 Express.js 来支持后端

+   使用诸如 MongoDB 之类的强大的文档导向数据库来持久化数据

+   使用 Handlebars.js 编写动态 HTML 页面

+   使用 Heroku 和 Amazon Web Services（AWS）等服务将整个项目部署到云端

有了 Node.js 的引入，JavaScript 正式进入了以前甚至不可能的方向。现在，你可以在服务器上使用 JavaScript，也可以用它来开发完整的企业级应用程序。当你将这一点与 MongoDB 及其基于 JSON 的数据的强大功能结合起来时，你可以在应用程序的每一层中使用 JavaScript。

让我们快速了解一些 Node.js 和 MongoDB 的基本概念，这将有助于你理解本书后续章节的内容。

# Node.js 简介

人们在初次接触 Node.js 时最容易混淆的一件事是，要理解它究竟是什么。它是一个完全不同的语言吗，它只是 JavaScript 的一个框架，还是其他什么东西？Node.js 绝对不是一种新语言，它也不仅仅是 JavaScript 的一个框架。它可以被看作是建立在 Google 的 V8 引擎之上的 JavaScript 运行环境。因此，它为我们提供了一个上下文，我们可以在任何可以安装 Node.js 的平台上编写 JavaScript 代码。任何地方！

现在，稍微了解一下它的历史！2009 年，Ryan Dahl 在 JSConf 上做了一个演讲，彻底改变了 JavaScript。在他的演讲中，他向 JavaScript 社区介绍了 Node.js。在大约 45 分钟的演讲后，他得到了观众的起立鼓掌。他在 Flickr 上看到了一个简单的文件上传进度条后，受到启发，决定写 Node.js。他意识到该网站正在以错误的方式处理整个过程，他决定必须有更好的解决方案。

现在让我们快速了解一下 Node.js 的特点，看看它与其他服务器端编程语言有何不同。

# V8 引擎带来的优势

V8 引擎是由 Google 开发的，并于 2008 年开源。众所周知，JavaScript 是一种解释性语言，它不像编译语言那样高效，因为代码的每一行在执行时都会被逐行解释。V8 引擎带来了一个高效的模型，其中 JavaScript 代码首先被解释，然后编译成机器级代码。

新的 V8 5.9 发布了一个稳定版本，引入了 TurboFan 编译器，提供了性能和大规模优化的好处。它还推出了 Ignition 解释器，对于所有大小的设备如服务器或 IOT 设备等，它都非常高效，因为它的内存占用范围不同。由于内存占用低，它可以快速启动应用程序。我们可以在以下链接中研究基准测试：[`goo.gl/B15xB2`](https://goo.gl/B15xB2)

通过两个强大的更新，v8 团队还在开发 Orinoco，这是一个基于并行和并发压缩机制的垃圾收集器。

这样的高性能和有希望的结果是将 node 8(LTS)的发布日期从 2018 年 5 月推迟到 2018 年 10 月的原因。目前我们正在使用非 LTS 版本的 node 8。它为使用 node v4.x.x 及以上版本的用户提供了干净的替代，没有破损的库。版本 8 还具有各种内置功能，如缓冲区改进和内置的 promisify 方法等。我们可以在以下链接中学习它们：[`goo.gl/kMySCS`](https://goo.gl/kMySCS)

# Node.js 是单线程的！

随着 Web 的出现，传统的 JavaScript 旨在在浏览器中添加简单的功能和最小的运行时。因此，JavaScript 被保持为单线程脚本语言。现在，为了对单线程模型有一个简要的了解，让我们考虑以下图表：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/fac07705-b3fd-4128-88db-7c5cd27c1d22.jpg)

单线程模型在执行上下文中创建一个单一的调用栈。在前面的代码中，当函数`getData()`被调用时，该函数被推入堆栈以便按顺序执行。

在 Node.js 的上下文中，JavaScript 是基础脚本语言，因此 Node.js 是单线程的。您可能会问，单线程模型如何帮助？典型的 PHP、ASP.NET、Ruby 或基于 Java 的服务器遵循的模型是每个客户端请求都会导致实例化一个新的线程甚至一个进程。

当涉及到 Node.js 时，请求在同一个线程上运行，共享资源。一个经常被问到的问题是，使用这样的模型会有什么优势？要理解这一点，我们应该了解 Node.js 试图解决的问题。它试图在单个线程上进行异步处理，以提供更高的性能和可伸缩性，以处理太多的网络流量的应用程序。想象一下处理数百万并发请求的 Web 应用程序；如果服务器为每个进来的请求创建一个新的线程，它将消耗大量资源，我们最终将不得不添加更多的服务器来增加应用程序的可伸缩性。

单线程的异步处理模型在先前的上下文中有其优势，您可以使用更少的服务器端资源处理更多的并发请求。然而，这种方法也有其缺点；Node（默认情况下）不会利用服务器上可用的 CPU 核心数量，而不使用额外的模块，如`pm2`。

Node.js 是单线程的这一点并不意味着它在内部不使用线程。只是开发人员和代码的执行上下文对 Node.js 内部使用的线程模型没有控制权。

如果您对线程和进程的概念不熟悉，我建议您阅读一些关于这些主题的初步文章。还有很多 YouTube 视频也是关于同样的主题。

以下参考资料可以作为一个起点：

[`www.cs.ucsb.edu/~rich/class/cs170/notes/IntroThreads/`](http://www.cs.ucsb.edu/~rich/class/cs170/notes/IntroThreads/)

# 非阻塞异步执行

Node.js 最强大的特性之一是它既是事件驱动的，又是异步的。那么，异步模型是如何工作的呢？想象一下你有一段代码，在第 n 行有一个耗时的操作。当这段代码被执行时，后面的行会发生什么？在正常的同步编程模型中，后面的行将不得不等到该行的操作完成。异步模型会以不同的方式处理这种情况。

让我们通过以下代码和图表来可视化这种情况：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/5d3b673d-680b-4465-9fb5-f39e91ffc1a9.jpg)

在前面的情况下，`setTimeout()`方法由 JavaScript（Node.js）API 提供。因此，这个方法被认为是同步的，并在不同的执行上下文中执行。根据`setTimeout()`的功能，它在指定的持续时间后执行回调函数，在我们的例子中是三秒后。

此外，当前的执行永远不会被阻塞以完成一个进程。当 Node.js API 确定事件的完成已被触发时，它将立即执行你的回调函数。

在典型的同步编程语言中，执行前面的代码将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/52bd7604-513e-4e81-9d83-8619af93c648.jpg)

如果你仍然对学习 JavaScript 中的异步模型和回调概念感兴趣，**Mozilla 开发者网络**（**MDN**）有许多文章详细解释了这些概念。

# npm - Node 包管理器

使用 Node.js 编写应用程序真的很愉快，当你意识到你可以随时使用的大量信息和工具时！使用 Node.js 内置的包管理器 npm，你可以找到成千上万的模块，只需几次按键就可以安装和在应用程序中使用！Node.js 成功的最大原因之一是 npm，它是最好的包管理器之一，学习曲线非常小。如果这是你第一次接触的包管理器，你应该觉得自己很幸运！

在一个普通的月份，npm 处理的下载量超过 10 亿次，目前有大约 15 万个包可供下载。你可以通过访问[www.npmjs.com](https://www.npmjs.com/)来查看可用模块的库。在你的应用程序中下载和安装任何模块就像执行以下命令一样简单：

```js
npm install package 
```

你写了一个想要与世界分享的模块吗？你可以使用 npm 打包并将其轻松上传到[www.npmjs.org](https://www.npmjs.com/)的公共注册表中！如果你不确定安装的模块如何工作，源代码就在你的项目的`node_modules/`文件夹中等待探索！

npm 中的模块版本遵循语义化版本控制，例如`major.minor.patch`的顺序。

# 分享和重用 JavaScript

在开发 Web 应用程序时，你总是需要对 UI 进行验证，客户端和服务器两端都需要进行验证，因为客户端验证对于更好的 UI 体验是必需的，而服务器端验证则是为了更好地保护应用程序的安全。想想两种不同的语言在行动：你将在服务器和客户端两端实现相同的逻辑。使用 Node.js，你可以考虑在服务器和客户端之间共享通用函数，大大减少代码重复。

曾经尝试过优化从模板引擎（如 Underscore）加载的**单页应用程序**（**SPA**）的客户端组件的加载时间吗？你会考虑一种方法，可以同时在服务器和客户端共享模板的渲染；有些人称之为混合模板。

Node.js 比其他任何服务器端技术更好地解决了客户端模板重复的问题，只是因为我们可以在服务器和客户端同时使用相同的 JS 模板框架和模板。

如果你对这一点持轻视态度，它解决的问题不仅仅是在服务器和客户端重用验证或模板的问题。想想正在构建的 SPA；你将需要在客户端 MV*框架中实现服务器端模型的子集。现在，想想在客户端和服务器上共享模板、模型和控制器子集。我们正在解决更高级别的代码冗余情景。

# 不仅仅用于构建 Web 服务器！

Node.js 不仅仅是用于在服务器端编写 JavaScript。是的，我们之前已经讨论过这一点。Node.js 为 JavaScript 代码在任何可以安装的地方工作设置了环境。它可以是创建命令行工具的强大解决方案，也可以是完全功能的本地运行应用程序，与 Web 或浏览器无关。Grunt.js 就是一个由 Node 驱动的命令行工具的很好例子，许多 Web 开发人员每天都在使用它来自动化任务，如构建过程、编译 CoffeeScript、启动 Node.js 服务器、运行测试等。

除了命令行工具，Node.js 在硬件领域也越来越受欢迎，尤其是 Node.js 机器人运动。`Johnny-Five`和`Cylon.js`是两个流行的 Node.js 库，用于提供与机器人工作的框架。只需在 YouTube 上搜索 Node.js 机器人，你就会看到很多例子。此外，你可能正在使用一个基于 Node.js 开发的文本编辑器。GitHub 的开源编辑器 Atom 就是一个很好的例子。

# 使用 Socket.io 进行实时 Web 应用程序

Node.js 产生的一个重要原因是支持实时 Web 应用程序。Node.js 有几个专为实时 Web 应用程序构建的框架非常受欢迎：`Socket.io`和`Sock.JS`。这些框架使构建即时协作应用程序（如 Google Drive 和 Mozilla 的 together.js）变得非常简单。在现代浏览器引入 WebSockets 之前，这是通过长轮询实现的，这对于实时体验来说并不是一个很好的解决方案。虽然 WebSockets 是现代浏览器中支持的功能，但`Socket.io`充当了一个框架，还为旧版浏览器提供了无缝的回退实现。

如果您需要了解更多关于在应用程序中使用 WebSockets 的信息，这是 MDN 上一个很好的资源，您可以探索一下：

[`developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_client_applications`](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_client_applications)。

# 网络和文件 IO

除了 Node.js 强大的非阻塞异步特性之外，它还通过核心模块提供了强大的网络和文件系统工具。使用 Node.js 的网络模块，您可以创建接受网络连接并通过流和管道进行通信的服务器和客户端应用程序。Node 包含一个名为**fs**或文件系统的模块，它完全负责对文件执行的所有读写操作。它还利用了 Node 的流特性来执行这些操作。

# 微服务

根据功能单元划分应用程序称为**微服务**。每个微服务都成为自包含的部署单元。Node.js 基于通用 JS 模块模式，提供了应用程序结构的模块化。这种模式用于创建微服务。随着功能的增加，微服务的数量也在增加。为了管理这些服务，Node.js 生态系统提供了强大的库，如`pm2`。因此，它使应用程序的元素能够单独更新和扩展。

# 物联网（IoT）

随着**物联网**（**IoT**）的出现，Node.js 生态系统为各种设备（如传感器、信标、可穿戴设备等）提供了惊人的库支持。Node.js 被认为是管理这些设备发出的请求的理想技术，通过其强大的流和非阻塞 I/O 支撑。像 Arduino、Raspberry Pi 等流行的物联网板变种有 300 多个 Node.js 包。构建数据密集型、实时应用程序的开发人员通常会发现 Node.js 是一个自然的选择。

# 使用 Node.js 创建一个简单的服务器

要看轻量级 Node.js 可以做到什么，让我们看一下启动 HTTP 服务器并向浏览器发送 Hello World 的示例代码：

```js
var http = require('http');
http.createServer(function(req, res) {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Hello World\n');
}).listen(8080, 'localhost');
console.log('Server running at http://localhost:8080'); 
```

只需几行基本的代码就可以编写一个完整的 Node.js 应用程序。使用简单的 Node.js `app.js`命令运行它将启动一个监听端口 8080 的 HTTP 服务器。将任何浏览器指向`http://localhost:8080`，您将在屏幕上看到简单的输出 Hello World！虽然这个示例应用程序实际上并没有做任何有用的事情，但它应该让您一窥使用 Node.js 编写 Web 应用程序时所拥有的强大功能。如果您还没有设置初始的 Node.js 开发环境，我们将在下一章中讨论它。

# 何时使用 Node.js

您可能听说过美国心理学家亚伯拉罕·马斯洛的这句谚语：

“如果你手中只有一把锤子，那么任何东西看起来都像钉子！”

在这种情况下，这是有道理的。Node.js 不是一种可以依赖解决您打算解决的所有应用程序问题的技术，如果选择不明智，使用它的决定将适得其反。Node.js 非常适合预期处理大量并发连接的应用程序。此外，应该注意，它最适合每个传入请求需要非常少的 CPU 周期的应用程序。这意味着，如果您打算在请求时执行计算密集型任务，它将阻塞事件循环，从而影响 Web 服务器同时处理的其他请求。Node.js 非常适合实时 Web 应用程序，如聊天室、协作工具、在线游戏等。因此，在决定是否使用 Node.js 时，我们应该认真分析应用程序的上下文，并弄清楚 Node.js 是否真的适合应用程序的上下文。

很难详细讨论 Node.js 的用例。然而，以下 Stack Overflow 主题有效地做到了这一点，我强烈建议您阅读这篇帖子上的答案，如果您对 Node.js 的用例更感兴趣：[`stackoverflow.com/questions/5062614/how-to-decide-when-to-use-node-js.`](http://stackoverflow.com/questions/5062614/how-to-decide-when-to-use-node-js)

由于我们已经简要介绍了 Node.js 的概念和特性，现在让我们来看看 NoSQL 和 MongoDB 方面。

# NoSQL 运动

让我们从探讨一个问题的答案开始：什么是 NoSQL 数据库？NoSQL 是数据库技术的常见术语，它偏离了传统的关系数据库管理系统（RDBMS）概念。这些数据库解决方案偏离 RDBMS 数据库标准的常见原因是为了实现和设定比传统 RDBMS 解决方案更好的可用性和分区能力标准。

为了向您介绍这个概念，我们应该看一下布鲁尔定理，也就是 CAP 定理：

分布式计算系统不可能同时提供以下三项保证：一致性、可用性和分区容错性。

传统的 RDBMS 解决方案在一致性方面表现良好，但在提供更好的可用性（数据读取）和分区能力方面会有所妥协。大多数 NoSQL 解决方案已经朝着这个方向发展，以实现更好的数据可用性和分区。

由于这是任何偏离 RDBMS 解决方案（如 MySQL、PostgreSQL 等）概念的数据库技术的常见术语，NoSQL 数据库有各种子集。最流行的 NoSQL 子集包括文档存储、键值存储和基于图的数据库解决方案。我们将要尝试的 MongoDB 属于文档存储类别。除了 MongoDB 之外，市场上还有许多其他 NoSQL 解决方案，如 Cassandra、Redis、Neo4j、HBase 等。

# MongoDB 简介

正如我们在前面的段落中讨论的，MongoDB 属于 NoSQL 数据库的文档存储类别。MongoDB 由 10gen 积极开发，该公司已更名为 MongoDB Inc. MongoDB 是开源的，其源代码可在 GitHub 等各种平台上获得。

我们将看一下 MongoDB 的以下各种特性：

+   JSON 友好的数据库

+   无模式化设计

+   各种性能方面

# JSON 友好的数据库

MongoDB 之所以如此受欢迎的一个最重要的原因是它是一个 JSON 友好的数据库。这意味着文档以 JavaScript 对象的形式存储和检索。在内部，这些 JSON 数据在持久化到系统时会转换为 BSON 格式。因此，这提供了极大的灵活性，我们可以在客户端、服务器和最终数据库中使用相同的数据格式。

MongoDB 集合（表）中的典型文档（记录）可能如下所示：

```js
$ mongo 
> db.contacts.find({email: 'jason@kroltech.com'}).pretty() 
{ 
   "email" : "jason@kroltech.com", 
   "phone" : "123-456-7890", 
   "gravatar" : "751e957d48e31841ff15d8fa0f1b0acf", 
   "_id" : ObjectId("52fad824392f58ac2452c992"), 
   "name" : { 
      "first" : "Jason", 
      "last" : "Krol" 
   }, 
   "__v" : 0 
} 
```

在检查前面的输出后，我们可以看到一个名为`_id`的关键字。这是一个必须被编码为二进制 JSON `objectID`(BSON)的 MongoDB ID。如果编码失败，MongoDB 将无法检索或更新对象。

# 无模式化设计

MongoDB 的另一个重要特性是其无模式化的特性。在关系型数据库中，您需要提前定义存储的数据的确切结构，这被称为模式。这意味着您必须定义表中每个字段的确切列数、长度和数据类型，并且每个字段必须始终符合该确切的一组标准。Mongo 提供了一种灵活的特性，使得您存储到数据库中的文档不需要遵循任何模式，除非开发人员通过应用程序级别强制执行它。这使得 MongoDB 非常适合基于敏捷开发，因为您可以在应用程序模式上进行即时修改。

# 各种性能方面

除了友好的 JavaScript 特性之外，MongoDB 和 Node.js 之间的另一个相似之处是，MongoDB 也是为高并发应用程序和大量读操作而设计的。

MongoDB 还引入了*分片*的概念，这使得可以水平和垂直扩展数据库。如果应用程序所有者需要增加数据库的能力，他们可以在堆栈中添加更多的机器。这是一个相对于投资于单台机器的 RAM 来说更便宜的选择，而这将是关系型数据库解决方案的情况。

索引化的过程创建了一个称为索引的值列表，用于选择的字段。这些索引用于查询更大的数据块。使用索引可以加快数据检索速度和性能。MongoDB 客户端提供了各种方法，比如`ensureIndex`，只有在索引不存在时才创建索引。

此外，MongoDB 还有各种命令来允许对数据进行*聚合*，比如分组、计数和返回不同的值。

我们讨论的所有优点都会对一致性产生一定影响，因为 MongoDB 不严格遵守 ACID 事务等关系型数据库标准。此外，如果您最终创建了一个可能需要太多 JOIN 操作的数据模型，那么 MongoDB 可能不适合，因为它并不是设计用于太多的聚合，尽管聚合是可能通过 MongoDB 聚合框架实现的。MongoDB 可能适合也可能不适合您的应用程序。在做出决定之前，您应该真正权衡每种技术的利弊，以确定哪种技术适合您。

# Node.js 和 MongoDB 在实际中

Node.js 和 MongoDB 在开发社区中都非常受欢迎和活跃。这对企业也是如此。财富 500 强中一些最大的公司已经完全采用 Node.js 来支持他们的 Web 应用程序。

这在很大程度上是由于 Node.js 的异步特性，使其成为高流量、高 I/O 应用程序的绝佳选择，例如电子商务网站和移动应用程序。

以下是一些正在使用 Node.js 的大公司的小列表：

+   贝宝

+   领英

+   eBay

+   沃尔玛

+   雅虎！

+   微软

+   道琼斯

+   优步

+   纽约时报

MongoDB 在企业领域的使用同样令人印象深刻和广泛，越来越多的公司采用这一领先的 NoSQL 数据库服务器。以下是一些正在使用 MongoDB 的大公司的小列表：

+   思科

+   Craigslist 公司

+   福布斯

+   FourSquare

+   财捷通

+   麦克菲

+   MTV

+   大都会人寿

+   旭通飞

+   安德玛

# 本书的预期内容

本书的其余部分将是一次引导之旅，带领您完成一个完整的数据驱动网站的创建过程。我们创建的网站将涵盖典型大型 Web 开发项目的几乎所有方面。该应用程序将使用一种名为 Express 的流行 Node.js 框架进行开发，并将使用 MongoDB 持久化数据。在最初的几章中，我们将涵盖涉及启动服务器核心并提供内容所涉及的基础工作。这包括配置您的环境，以便您可以使用 Node.js 和 MongoDB，并对这两种技术的核心概念进行基本介绍。然后，我们将从头开始编写一个由 ExpressJS 驱动的 Web 服务器，该服务器将处理为网站提供所有必要文件。然后，我们将使用 Handlebars 模板引擎来提供静态和动态 HTML 网页。更深入地进行，我们将通过添加数据层使应用程序持久化，网站的记录将通过 MongoDB 服务器保存和检索。

我们将介绍如何编写 RESTful API，以便其他人可以与您的应用程序进行交互。最后，我们将深入了解如何为您的所有代码编写和执行测试。以下部分提供了摘要。

最后，我们将进行一个简短的旁观，检查一些越来越受欢迎的前端技术，这些技术在编写单页应用程序时变得越来越受欢迎。这些技术包括 Backbone.js、Angular 和 Ember.js。

最后但同样重要的是，我们将详细介绍如何使用 Heroku 和亚马逊 Web 服务等流行的基于云的托管服务将您的新网站部署到互联网上。

# 摘要

在本章中，我们回顾了本书其余部分可以期待的内容。我们讨论了 JavaScript 目前令人惊叹的状态，以及它如何可以用于支持 Web 应用程序的整个堆栈。虽然您一开始就不需要任何说服，但我希望您对开始使用 Node.js 和 MongoDB 编写 Web 应用程序感到兴奋并准备好了！

接下来，我们将设置您的开发环境，并让您使用 Node.js、MongoDB 和 npm，并编写并启动一个使用 MongoDB 的快速 Node.js 应用程序！


# 第二章：启动和运行

在本章中，我们将介绍设置开发环境所需的必要步骤。这些步骤包括以下内容：

+   在您的计算机上安装 Node.js

+   在您的计算机上安装 MongoDB

+   验证一切是否设置正确

仔细遵循这些部分，因为我们需要在跳转到实际编码的章节之前，开发环境已经准备就绪。在本书的其余部分中，我们将假定您使用的是 Mac OS X、Linux 或 Windows 7/Windows 8。您还需要在计算机上拥有超级用户和/或管理员权限，因为您将安装 Node 和 MongoDB 服务器。本章之后的代码和示例将是与操作系统无关的，并且应该在任何环境中工作，只要您提前采取了我概述的准备步骤。

您需要一个合适的文本编辑器来编写和编辑代码。虽然您选择的任何文本编辑器都可以满足此目的，但选择一个更好的文本编辑器将极大地提高您的生产力。Sublime Text 3 似乎是目前最受欢迎的文本编辑器，无论在哪个平台上。这是一个简单、轻量级的编辑器，由全球开发人员提供了无限的插件。如果您使用的是 Windows 机器，那么*Notepad++*也是一个不错的选择。此外，还有基于 JavaScript 的开源编辑器，如 Atom 和 Brackets，也值得一试。

最后，您需要访问命令行。Linux 和 Mac 可以通过终端程序访问命令行。Mac 上一个很好的替代品是 iTerm2 ([`iterm2.com`](http://iterm2.com))。对于 Windows，默认的命令行程序可以工作，但不是最好的。那里一个很好的替代品是 ConEmu ([`conemu.codeplex.com`](http://conemu.codeplex.com))。

在本书的其余部分，每当我提到命令行或命令提示符时，它看起来像下面这样：

```js
$ command -parameters -etc
```

# 安装 Node.js

可以通过访问官方 Node 网站并访问下载部分轻松获取 Node.js 安装程序。一旦进入那里，请确保根据您的操作系统和 CPU（32 位或 64 位）下载正确的版本。作为替代方案，您还可以使用特定于操作系统的软件包管理器进行安装。根据您使用的操作系统，只需跳转到特定的子部分，以获取有关要遵循的步骤的更多详细信息。

您可以通过以下链接跳转到 Node.js 下载部分：[`nodejs.org/en/download`](https://nodejs.org/en/download)。

# Mac OS X

Node 网站上有一个专门为 OS X 设计的通用安装程序。

我们需要按照以下步骤在 Mac 上安装 Node.js：

1.  访问 Node.js 官方网站的下载页面，如前所述，单击 Mac OS X 安装程序，这与处理器类型（32 位或 64 位）无关。

1.  下载完成后，双击`.pkg`文件，这将启动 Node 安装程序。

1.  按照向导的每一步进行操作，这应该是相当简单易懂的。

此外，如果您已安装了 OS X 软件包管理器之一，则无需手动下载安装程序。

您可以通过各自的软件包管理器安装 Node.js。

+   使用 Homebrew 进行安装：

```js
    brew install node
```

+   使用 Mac ports 进行安装：

```js
    port install nodejs
```

通过安装程序或软件包管理器安装 Node.js 时，将包括 npm。因此，我们不需要单独安装它。

# Windows

在 Windows 上安装 Node.js，我们将按照以下步骤进行：

1.  我们需要确定您的处理器类型，32 位还是 64 位。您可以通过在命令提示符下执行以下命令来执行此操作：

```js
    $ wmic os get osarchitecture
```

输出如下：

```js
      OSArchiecture
      64-bit
```

1.  根据此命令的结果下载安装程序。

1.  下载完成后，双击`.msi`文件，这将启动 Node 安装程序。

1.  按照向导的每一步进行操作。

1.  当您到达自定义设置屏幕时，您应该注意安装向导不仅会安装 Node.js 运行时，还会安装 npm 软件包管理器，并配置路径变量。

1.  因此，一旦安装完成，Node 和 npm 可以在任何文件夹中通过命令行执行。

此外，如果您安装了任何 Windows 软件包管理器，则无需手动下载安装程序。您可以通过相应的软件包管理器安装 Node.js：

+   使用 chocolatey：

```js
    cinst nodejs.install
```

+   使用`scoop`：

```js
    scoop install nodejs
```

# Linux

由于 Linux 有许多不同的版本和发行版，安装 Node 并不那么简单。但是，如果您一开始就在运行 Linux，那么您很清楚这一点，并且可能对一些额外的步骤感到满意。

Joyent 在如何使用许多不同的软件包管理器选项在 Linux 上安装 Node 的出色 wiki。这涵盖了几乎所有流行的`deb`和`rpm`-based 软件包管理器。您可以通过访问[`github.com/joyent/node/wiki/Installing-Node.js-via-package-manager`](https://github.com/joyent/node/wiki/Installing-Node.js-via-package-manager)阅读该 wiki。

以 Ubuntu 14.04 和之前版本为例，安装 Node 的步骤如下：

```js
$ sudo apt-get install python-software-properties $ sudo curl -sL https://deb.nodesource.com/setup_8.x | sudo -E bash - $ sudo apt-get install nodejs
```

完成这些步骤后，Node 和 npm 应该已安装在您的系统上。

# 测试 Node.js 是否正确安装

现在 Node 已经安装在您的系统上，让我们运行一个快速测试，以确保一切正常运行。

通过终端程序访问命令行并执行以下命令：

```js
    $ node --version
    v8.4.3
    $ npm --version
    5.3.0
```

假设您的 Node 安装成功，您应该在屏幕上看到安装的版本号作为输出，就在您执行的命令下面。

您的版本号很可能比之前打印的要新。

您还可以启动 Node `repl`，这是一个命令行 shell，可以让您直接执行 JavaScript：

```js
    $ node
    > console.log('Hello world!')
    Hello World!
    Undefined
    [press Ctrl-C twice to exit]  
```

# 在线文档

您需要确保将浏览器指向 Node 的在线文档并将其加为书签，因为它无疑会成为您经常访问的资源。您不一定要逐个阅读每个部分，但一旦开始在 Node.js 中编写代码，您将需要经常参考此文档，以更多地了解 Node.js 公开的 API。该文档可在[`nodejs.org/api/`](http://nodejs.org/api/)上找到。

还可以查看 npm 注册表，网址为[`npmjs.com`](http://npmjs.com)，在那里您可以找到数以万计的 Node 开发人员可用的模块。

# 安装 MongoDB

MongoDB 也可以通过访问官方 MongoDB 网站并从[`www.MongoDB.org/downloads`](http://www.mongodb.org/downloads)访问下载部分轻松下载。在那里，请务必根据您的操作系统和 CPU（32 位或 64 位）下载正确的版本。

对于 Windows 用户，您可以选择下载 MSI 安装程序文件，这将使安装更简单。

根据您下载的 MongoDB 版本，您将需要在以下部分中用适当的版本号替换`<version>`。

# Mac OS X 安装说明

如果您使用 Homebrew 软件包管理器，可以使用以下两个命令安装 MongoDB：

```js
    $ brew update
    $ brew install MongoDB
```

本章的其余部分假设您没有使用 Homebrew，并且需要手动安装 MongoDB。如果您通过 Homebrew 安装 MongoDB，可以直接转到*确认成功安装 MongoDB*部分。

下载完成后，打开并提取`.tgz`文件的内容。您需要将提取的内容移动到目标文件夹`/MongoDB`。您可以通过查找器或命令行执行此操作，具体取决于您的喜好，如下所示：

```js
    $ mkdir -p /MongoDB
    $ cd ~/Downloads
    $ cp -R -n MongoDB-osx-x86_64-2.4.9/ MongoDB 
```

您需要确保 MongoDB 二进制文件的位置已配置在您的环境路径中，以便您可以从任何工作目录执行`MongoDB`和 Mongo。要做到这一点，编辑您家目录（`~/`）中的`.profile`文件，并将 MongoDB 的位置追加到其中。您的`.profile`文件应该看起来像以下内容：

```js
export PATH=~/bin:/some/of/my/stuff:/more/stuff:/MongoDB/bin:$PATH
```

如果您没有这行或完全缺少`.bash_profile`，您可以通过执行以下命令轻松创建一个：

```js
    $ touch .bash_profile
    $ [edit] .bash_profile
    export PATH=$PATH:/MongoDB/bin
```

您很可能在前面的代码行中有比我更多的内容。重要的是在最后的`$PATH`之前添加`:/MongoDB/bin`。`:`是不同路径之间的分隔符（因此您可能会将您的路径添加到现有列表的末尾，但在结尾的`$PATH`之前）。

在这里，`mongod`指的是您需要调用的 MongoDB 服务器实例，`mongo`指的是 Mongo shell，它将是您与数据库交互的控制台。

接下来，您需要创建一个默认的`data`文件夹，MongoDB 将用它来存储所有数据文档。从命令行执行以下操作：

```js
    $ mkdir -p /data/db
    $ chown `id -u` /data/db
```

一旦文件已经正确解压到`/MongoDB`文件夹并且数据文件夹已创建，您可以通过从命令行执行以下命令来启动 MongoDB 数据库服务器：

```js
    $ mongod
```

这应该会在服务器启动时输出一大堆日志语句，但最终会以以下结束：

```js
2017-08-04T10:10:47.853+0530 I NETWORK [thread1] waiting for connections on port 27017
```

就是这样！您的 MongoDB 服务器已经启动并运行。您可以输入*Ctrl-C*来取消并关闭服务器。

# Windows 7/Windows 8 安装说明

完成下载后，MongoDB 网站将自动将您重定向到一个带有 Windows *快速入门*指南链接的页面：

[`docs.MongoDB.org/manual/tutorial/install-MongoDB-on-windows/`](http://docs.mongodb.org/manual/tutorial/install-mongodb-on-windows/)。

强烈建议您遵循该指南，因为它将是最新的，并且通常会比我在这里提供的更详细。

解压已下载的 ZIP 文件到根目录`c:\`。默认情况下，这应该会解压一个名为`MongoDB-osx-x86_64-2.4.9`的文件夹。根据您用于解压的工具，您可以保持原样，也可以将目标文件夹更改为`MongoDB`。如果在解压过程中没有更改目标文件夹，完成后应该将文件夹重命名。无论哪种方式，确保解压出的文件位于名为`c:\MongoDB`的文件夹中。

接下来，您需要创建一个默认的`data`文件夹，MongoDB 将用它来存储所有数据文档。使用 Windows 资源管理器或命令提示符，您最熟悉的方式创建`c:\data`文件夹，然后使用以下命令创建`c:\data\db`：

```js
    $ md data
    $ md data\db
```

一旦文件已经正确解压到`c:\MongoDB`文件夹，并且数据文件夹随后创建，您可以通过从提示符执行以下命令来启动 MongoDB 数据库服务器：

```js
$ c:\MongoDB\bin\mongod.exe
```

这应该会在服务器启动时输出一大堆日志语句，但最终会以以下结束：

```js
2017-08-04T10:10:47.853+0530 I NETWORK [thread1] waiting for connections on port 27017
```

就是这样！您的 MongoDB 服务器已经启动并运行。您可以输入*Ctrl*-*C*来取消并关闭服务器。

# Linux 安装说明

再次，与 Windows 或 Mac 相比，我们将面临稍微更具挑战性的 Linux 安装过程。官方网站[`docs.MongoDB.org/manual/administration/install-on-linux/`](http://docs.mongodb.org/manual/administration/install-on-linux/)上有关于如何在许多不同的 Linux 发行版上安装 MongoDB 的详细说明。

我们将继续使用 Ubuntu 作为我们的首选版本，并使用 APT 软件包管理器进行安装：

```js
    $ sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 
      7F0CEB10
    $ echo 'deb http://downloads-distro.MongoDB.org/repo/ubuntu-upstart 
     dist 10gen' | sudo tee /etc/apt/sources.list.d/MongoDB.list
    $ sudo apt-get update
    $ sudo apt-get install MongoDB-10gen
```

完成这些步骤后，MongoDB 应该已经安装并准备在您的系统上运行。在终端中执行以下命令以确保。这会启动 MongoDB 守护程序，并监听连接：

```js
    $ mongod
 2017-08-04T10:10:47.853+0530 I NETWORK [thread1] waiting for   
 connections on port 27017
```

成功！您的 MongoDB 服务器已经运行。您可以输入*Ctrl*-*C*来取消并关闭服务器。

由于您正在开发本地开发机器而不是生产服务器，您不需要 MongoDB 服务器始终运行。这将是对您的机器不必要的负担，因为大部分时间您不会与服务器进行开发。因此，在本书的其余部分，每次启动期望连接到 MongoDB 服务器的代码时，您都需要手动启动服务器。如果您愿意，您当然可以配置 MongoDB 在本地作为服务运行并始终运行，但是如何配置超出了本章的范围。

# 确认 MongoDB 安装成功

现在 MongoDB 已经安装在您的系统上，让我们运行一个快速测试，确保一切正常运行。

通过终端程序访问命令行并执行以下命令：

```js
    $ mongod --version
    db version v3.4.4
    $ mongo --version
    MongoDB shell version v3.4.4  
```

假设您的 MongoDB 安装成功，您应该在屏幕上看到安装的版本号作为输出。

您的版本号很可能比之前打印的要更新。

# 将在线文档加为书签

您需要确保将浏览器指向 MongoDB 的在线文档，网址为[`docs.MongoDB.org/manual/`](http://docs.mongodb.org/manual/)，并将其加为书签，因为它无疑将成为您经常访问的资源。

# 编写您的第一个应用程序

现在您已经安装了所有内容并确认一切正常运行，您可以编写您的第一个快速应用程序，该应用程序将同时使用 Node 和 MongoDB。这将证明您的环境已经准备就绪，并且您已经准备好开始。此外，这将让您简单了解 Node 和 MongoDB 开发的世界！如果以下内容让您感到困惑或不合理，不要担心，本书的其余部分将会澄清一切！

首先，我们需要为我们的应用程序创建一个文件夹，该文件夹将包含此应用程序的特定代码，如下所示：

```js
    $ mkdir testapp
    $ cd testapp
```

# 创建示例应用程序

我们刚刚创建的`testapp`文件夹将是我们示例 Node 应用程序的根目录。虽然这不是必需的，但是创建`package.json`文件对我们的 Node 应用程序非常重要，这将包含有关应用程序的必要数据，如版本、名称、描述、开发和运行时依赖项。可以通过从`testapp`文件夹根目录发出以下命令来完成：

```js
    $ npm init 
```

这个命令将会询问您一些问题，比如您新创建的应用的名称和版本号。您不需要一次填写所有细节，可以通过按下*Enter*跳过步骤，系统将使用默认值，稍后您可以更新。

# 准备依赖模块

在我们开始编写任何 Node.js 代码之前，我们需要使用`npm`安装我们的依赖项。由于这是一个基本应用程序，我们将使用它来测试我们的 Node.js 与 MongoDB 服务器的连接。因此，我们唯一需要的依赖模块是 Node.js 的原生 MongoDB 客户端。我们可以通过执行以下命令轻松安装：

```js
    $ npm install MongoDB --save
```

在`npm`安装 MongoDB 驱动程序后，您可以列出目录的内容，您会注意到一个新文件夹被创建，名为`node_modules`。这是所有 Node 模块的存储位置，当您从`npm`安装它们时，它们会存储在这里。在`node_modules`文件夹中，应该有一个名为`MongoDB`的单个文件夹。此外，您会注意到我们示例应用程序的`package.json`文件将被此新依赖项条目更新。

# 添加应用程序代码

现在，让我们编写简单的应用程序代码来测试一下。这个应用程序基本上会连接到我们本地运行的 MongoDB 服务器，插入一些记录作为种子数据，然后提供输出，告诉我们数据是否被正确插入到 MongoDB 中。你可以通过以下 URL 下载代码的 Gist：[`bit.ly/1JpT8QL`](http://bit.ly/1JpT8QL)。

使用你喜欢的编辑器，创建一个名为`app.js`的新文件，并将其保存到应用程序根目录，即`testapp`文件夹。只需将上面 Gist 的内容复制到`app.js`文件中。

# 理解代码

现在，让我们逐个解释代码的每个部分在做什么。

```js
    //require the mongoClient from MongoDB module 
    var MongoClient = require('MongoDB').MongoClient;  
```

上面的一行需要我们通过`npm`安装的 MongoDB Node 驱动程序。这是 Node.js 中用于将外部文件依赖项引入当前上下文文件的必需约定。

我们将在接下来的章节中更详细地解释这一点。

```js
//MongoDB configs  
var connectionUrl = 'MongoDB://localhost:27017/myproject',  
    sampleCollection = 'chapters'; 
```

在上面的代码中，我们声明了要使用的数据库服务器信息和集合的变量。在这里，`myproject`是我们想要使用的数据库，`chapters`是集合。在 MongoDB 中，如果你引用并尝试使用一个不存在的集合，它将自动被创建。

下一步将是定义一些数据，我们可以将其插入到 MongoDB 中以验证一切是否正常。因此，我们在这里创建了一个章节的数组，可以将其插入到我们在前面步骤中设置的数据库和集合中：

```js
//We need to insert these chapters into MongoDB 
var chapters = [{  
    'Title': 'Snow Crash',  
    'Author': 'Neal Stephenson'  
},{  
    'Title': 'Snow Crash',  
    'Author': 'Neal Stephenson'  
}]; 
```

现在，我们可以看一下其余的代码，我们将这些数据插入到 MongoDB 数据库中：

```js
MongoClient.connect(connectionUrl, function(err, db) {    
  console.log("Connected correctly to server");     
  // Get some collection  
  var collection = db.collection(sampleCollection);   
  collection.insert(chapters,function(error,result){     
    //here result will contain an array of records inserted  
    if(!error) {  
      console.log("Success :"+result.ops.length+" chapters 
 inserted!");  
    } else {  
      console.log("Some error was encountered!");  
    }     
    db.close();    
  });    
}); 
```

在这里，我们与 MongoDB 服务器建立连接，如果连接正常，`db`变量将拥有我们可以用于进一步操作的`connection`对象：

```js
MongoClient.connect(url, function(err, db) {   
```

仔细看一下上面的代码-你还记得我们在第一章中学到的内容吗？我们在这里为我们进行的`connection`调用使用了一个`callback`。正如在第一章中讨论的，这个函数将被注册为一个`callback`，一旦连接尝试完成，就会被触发。连接完成后，这将由`error`或`db`对象触发，具体取决于我们是否能够建立正确的连接。因此，如果你看一下`callback`函数中的代码，我们在记录正确连接到服务器之前并没有检查是否有任何错误。现在，这就是你要在我们尝试运行这个应用程序时添加和检查的任务！看一下本节中以下代码块：

```js
var collection = db.collection(sampleCollection); 
collection.insert(chapters,function(error,result){ 
```

这只是使用我们在连接调用中得到的`db`对象，并获取名为`chapters`的`collection`。记住，我们在代码开头将该值设置为`sampleCollection`。一旦我们获得了`collection`，我们就会进行`insert`调用，将我们在数组`chapters`中定义的章节放入其中。正如你所看到的，这个`insert`调用也是通过附加`callback`函数来进行的，这是一个异步调用。一旦 MongoDB 原生客户端中的代码完成了`insert`操作，这个`callback`函数就会被触发，而我们将其作为一个依赖项来使用。

接下来，我们将看一下我们传递给`insert`函数调用的`callback`函数中的代码：

```js
if(!error) {  
  console.log("Success :"+result.ops.length+" chapters 
               inserted!");  
} else {  
  console.log("Some error was encountered!");  
}     
db.close(); 
```

在这里，我们处理通过`callback`传递的值，以找出`insert`操作是否成功，以及已插入记录相关的数据。因此，我们检查是否有错误，如果没有，就继续打印插入的记录数。在这里，如果操作成功，结果数组将包含我们插入到 MongoDB 中的记录。

现在我们可以继续尝试运行这段代码，因为我们已经理解了它的作用。

# 启动示例应用程序

一旦您将完整的代码保存到`app.js`中，就可以执行它并查看发生了什么。但是，在启动明显依赖于与 MongoDB 的连接的应用程序之前，您需要首先启动 MongoDB 守护程序实例：

```js
    $ mongod
```

在 Windows 中，如果您尚未为`mongod`设置`PATH`变量，则在执行 MongoDB 时可能需要使用完整路径，即`c:\MongoDB\bin\mongod.exe`。对于您的需求，本书的其余部分将引用`mongod`命令，但您可能始终需要在每个实例中执行完整路径。

现在，要启动应用程序本身，请在`app.js`所在的`root`文件夹中执行以下命令：

```js
    $ node app.js
```

当应用程序首次执行时，您应该会看到以下内容：

```js
    Connected correctly to server
    Success :2 chapters inserted!  
```

# 检查实际数据库

让我们快速查看一下数据库本身，看看在应用程序执行过程中发生了什么。由于服务器目前正在运行，我们可以使用 Mongo shell 连接到它-这是 MongoDB 服务器的命令行界面。执行以下命令以使用 Mongo 连接到服务器并针对章节集合运行查询。正如您在即将看到的代码中，Mongo shell 最初连接到名为`test`的默认数据库。如果要切换到其他数据库，我们需要手动指定数据库名称：

```js
    $ mongo
    MongoDB shell version: 2.4.8
    connecting to: test
    > use myproject
    > show collections
    chapters
    system.indexes
    > db.chapters.find().pretty()  
```

在这里，`pretty`被用作命令的一部分，用于格式化`find`命令的结果。这仅在 shell 上下文中使用。它对 JSON 执行更多的美化任务。

您应该会看到类似以下输出的内容：

```js
{  
    'id' : ObjectId("5547e734cdf16a5ca59531a7"), 
    'Title': 'Snow Crash',  
    'Author': 'Neal Stephenson'  
}, 
{  
    'id' : ObjectId("5547e734cdf16a5ca59531a7"), 
    'Title': 'Snow Crash',  
    'Author': 'Neal Stephenson' 
} 
```

如果再次运行 Node 应用程序，记录将再次插入 Mongo 服务器。因此，如果重复执行命令多次，输出中将有更多的记录。在本章中，我们没有处理这种情况，因为我们打算只有特定的代码，这将足够简单易懂。

# 摘要

在本章中，我们花时间确保您的开发环境正确配置了 Node 运行环境和 MongoDB 服务器。在确保两者都正确安装后，我们编写了一个利用了这两种技术的基本应用程序。该应用程序连接到本地运行的 MongoDB 服务器，并插入了示例记录。

现在，繁琐但必要的设置和安装任务已经完成，我们可以继续一些有趣的事情并开始学习了！

在下一章中，我们将回顾 JavaScript 语言的入门知识，并了解 Node 的基础知识。然后，我们将使用 Mongo shell 回顾 MongoDB 的基本**CRUD**（`create`，`read`，`update`，`delete`）操作。


# 第三章：Node 和 MongoDB 基础知识

在我们深入研究并开始使用 Node 和 MongoDB 构建一个完整的 Web 应用程序之前，重温一些基础知识是很重要的。本章将为你提供一个关于语法和重要主题的速成课程。它分为两部分，前半部分侧重于 JavaScript 或 Node，后半部分涵盖 MongoDB。你将深入了解一些常见和强大的可用工具，并将回顾大量的示例代码，以便让你快速上手。

在本章中，我们将涵盖以下主题：

+   JavaScript 语言的基础知识

+   Node.js 的基础知识

+   Node 的包管理器 npm

+   MongoDB 的基础知识

在本章结束时，你应该对语法以及如何使用 Node 和 MongoDB 有扎实的理解。有很多内容需要涵盖，所以让我们开始吧。

# JavaScript 入门指南

正如我们所知，Node.js 不仅仅是另一种语言，而是 JavaScript。在编写浏览器上的 JavaScript 时使用的语言语法和工具将完全适用于服务器端。Node.js 具有一些仅在服务器上可用的附加工具，但语言和语法再次与 JavaScript 相同。我假设你对基本的 JavaScript 语法有一般的了解，但我会简要介绍一下 JavaScript 的语言，以防万一。

一般来说，JavaScript 在语法方面是一个相当简单的语言，你只需要了解一些重要的元素。

# 介绍 es6

es6，或者 ECMAScript 2015，是 JavaScript 语言的更新，适用于所有类型、值、对象文字、属性、函数和程序语法。es6 的全新语义（类似于其他语言如 Java、C#等）使跨平台开发人员能够轻松学习 JavaScript。它不仅改进了语言的语法方面，还提供了新的内置工具，如 promises、proper tail calls、destructuring、modules 等。由于我们已经安装了 Node 版本 8，所有 ECMAScript 6 功能或 es2017 直至今都是包括在内的。如果你使用的是低于 4.3.2 版本的 Node，你将需要安装类似 babel.js 的转译工具。我们将通过逐步在代码中实现和进行比较研究来学习 es6。

# 语法基础

在几乎任何编程语言中，你可以做的最基本的事情就是声明一个变量。与大多数其他语言不同，JavaScript 是一种动态类型的语言，这意味着当你声明一个变量时，它的值可以是任何类型，并且在其生命周期内可以改变。然而，相反，强类型语言规定，定义为`string`类型的变量必须始终是一个字符串，并且必须始终具有字符串的值。强类型特性包含在我们接下来要学习的 es6 中。目前，在 JavaScript 中声明一个变量，只需在变量名之前使用`var`关键字：

```js
var myVariable;    // declaring a variable with no value 
var myFirstName = "Jason";   
var myLastName = "Krol"; 
var myFullName = myFirstName + ' ' + myLastName;  
// => Jason Krol 
```

前面的代码片段显示了我们如何声明变量并在声明时定义它们的初始值。`+`运算符用于字符串连接。

此外，我们使用**驼峰**命名法来命名变量。使用驼峰命名法并不是强制性的，但在面向对象的语言中，遵循驼峰命名法比基于下划线的方法更常见。

JavaScript 不会因为你忘记在每个语句的末尾加上分号而抱怨。相反，如果缺少适当的语句终止，它会尝试为你添加分号。这可能导致意想不到的结果。关于分号插入的规则在这篇文章中有解释：[`bclary.com/2004/11/07/#a-7.9.1`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Introduction_to_Object-Oriented_JavaScript)。

自 es6 引入了两个更多的变量声明关键字，即`let`和`const`，使 JavaScript 变得更加优雅。首先，让我们通过以下示例学习`const`：

```js
const loopOver = [1,2,3];
```

`const`的用法与`var`相同。用`const`声明变量会使其不可变，并且不能用于重新分配新的内容。

关于`const`关键字的另一个区别是，它并不意味着某物是常量，而是强调一次赋值。

通过添加以下行来测试它：

```js
loopOver = [4,5,6];
```

它会抛出以下错误：

```js
Uncaught TypeError: Assignment to constant variable
```

那么，为什么需要呢？对于程序员来说，推荐的做法是保持简单，这意味着使用一个变量来表示一个值。然而，我们之前讨论过变量的动态性，它有自己的优点，有时需要表示一个不可变的数据。比如存储一些服务器配置的凭据或 Node 包本身。用法可能有所不同，但都会遵循一次赋值的单一规则。

要学习`let`关键字，我们首先需要了解变量的作用域，这在下一节中有所涉及。

# 理解变量的作用域

在 JavaScript 中理解变量的作用域非常重要，以更好地掌握这门语言。作用域可以被称为您的变量或函数存在的一个容器。与 Java 和其他流行的语言不同，JavaScript 遵循函数级作用域，而不是块级作用域（这在 es6 中引入）。这意味着您定义的变量将受限于其父函数绑定的作用域。

考虑以下代码片段：

```js
var outer = 10; 
function myFunction() { 
   var inner = 2; 
   console.log(inner);// 2 
   console.log(outer);// 10 
}myFunction();console.log(inner); 
```

当运行前述代码时，我们可以看到`inner`变量的作用域仅限于名为`myFunction`的父函数。它在外部是不可访问的，并且会提供一个`referenceError`通知。此外，外部作用域中的变量在函数作用域中是可用的，您无需额外的努力来访问它们，就像在前面的示例中看到的名为`outer`的变量一样。

在这种情况下需要讨论的一个重要事情是`var`关键字的使用。如果在声明新变量时漏掉了`var`，JavaScript 不会抱怨。但如果发生这种情况，情况可能会变得非常糟糕。请看以下例子：

```js
(function (){   
    (function (){  
          a = 10;   
    })();  
})();  
console.log(a);// 10 
```

在这里，由于在内部函数中跳过了`var`关键字和变量声明，JavaScript 认为应该在其父作用域中搜索该变量，然后将其附加到全局作用域，并最终使其在任何地方都可用。因此，为了避免代码中出现此类问题，通过 JSHint 等代码质量工具对代码进行检查总是很有用的。前面的代码结构可能会让你感到困惑，因为它使用了自调用函数来引入作用域。

现在，随着 es6 的到来，您可以在块级作用域中声明变量，而不仅仅是函数作用域。要理解块级作用域，让我们看下面的例子：

|

```js
for(let i=0;i<loopOver.length;i++){
console.log(`Iteration : ", i)
}
Console.log(`Let value of ${ i}`)
```

|

```js
for(var i=0;i<loopOver.length;i++){
console.log(`Iteration : ", i)
}
Console.log(`Let value of ${ i}`)
```

|

前述代码片段的唯一区别是变量`i`的声明。`i`变量在`for`循环块之外是不可访问的。

有关`let`的更多详细信息，请参考链接：[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Statements/let`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Statements/let)

这就是关于变量作用域的全部内容。JavaScript 支持多种数据类型。让我们来看看它们。

# 数据类型

数据类型是任何语言的基础。JavaScript 中可用的数据类型有

如下：

+   数字

+   字符串

+   布尔

+   对象

+   空值

+   未定义

+   符号（es6 中新增）

在我们的代码中，我们声明的每个变量都包含属于前述类型的值。数字、字符串和布尔类型都很容易理解。这些属于语言支持的原始数据类型。在这里，一个重要的要点是要注意，JavaScript 在类型级别上没有整数或浮点数之间的区别。

数组、函数、正则表达式和日期等类型属于对象数据类型。

它们被认为是复合数据类型。因此，您定义的函数

在您的代码中也只是对象。

Null 和 undefined 是 JavaScript 支持的两种特殊类型。Null 指向

指向故意的非值，而 undefined 指向未初始化的值。因此，当您只声明变量并尚未使用值对其进行初始化时，变量将是未定义类型。最后但同样重要的是，es6 引入了一种新的原始数据类型符号。它们用于唯一的属性键和代表概念的常量。

我们没有在我们的书中使用它们，但是您可以访问以下链接以获取更多详细信息[`exploringjs.com/es6/ch_symbols.html`](http://exploringjs.com/es6/ch_symbols.html)。

因此，在我们了解定义函数、数组和对象的各种方法之前，让我们先了解运算符和流程。

# 运算符和流程

JavaScript 支持与 C 语言系列中的其他语言类似的控制结构。条件语句使用`if`和`else`编写，并且可以使用`else-if`梯级将语句链接在一起。

```js
var a = "some value"; 
if(a === "other value") { 
  //do something 
} else if (a === "another value") { 
  //do something 
} else { 
  //do something 
} 
```

可以使用`while`、`do-while`、`for`和`switch`语句编写控制语句。在编写 JavaScript 条件时，需要考虑的一个重要事项是了解什么等于`true`和/或`false`。大于或小于零的任何值，非 null 和非 undefined 都等于`true`。诸如`0`、`null`、`undefined`或`空`字符串的字符串等于`false`。

使用`while`、`do-while`、`for`和`switch`语句的一些示例如下：

```js
// for loop example 

var myVar = 0; 
for(let i = 0; i < 100; i += 1) {  
  myVar = i; 
  console.log(myVar); // => 0 1 ... 99 
} 

// do while example 
var x = 0; 
do { 
  x += 1; 
  console.log(x); // => 1 2 ... 100 
} while (x < 100); 

// while example 
while (x > 90) { 
  x -= 1; 
  console.log(x); // => 99 98 ... 90 
} 
//switch example 

var x = 0; 
switch(x) { 
  case 1 :  
console.log(""one""); 
break; 
  case 2 :  
console.log("two""); 
break; 
  default: 
console.log("none"); 

} // => "none" 
```

另一个重要的事情是要理解

使用`==`和`===`进行比较。应该在何处使用`==`比较

变量的类型不是你关心的问题；如果还应该比较变量的数据类型，那么你应该选择`===`比较符号，如下面的代码所示：

```js
const a = '5'; 
const b = 5; 
if(a == b) { 
  //do something 
} 
if(a === b) { 
  //do something 
} 
```

在代码片段中，第一个条件评估为 true，而第二个条件不是。因此，在编写代码时，始终更安全地依赖严格的（`===`）相等检查作为最佳实践。

在批准应用程序之前，建议始终通过诸如 JSHint 之类的代码质量工具运行代码。您可以通过诸如 Grunt 之类的任务运行器自动运行代码质量检查，以便每次我们更改代码时，代码质量工具都会运行并显示代码编写中是否存在任何潜在问题。

# 理解对象

在 JavaScript 对象中，我们创建的数组甚至函数都属于相同的数据类型：`Object`。声明对象是一个非常简单的过程：

```js
var myObject = {};    // that's it! 
```

您可以向此对象添加任何类型的属性或属性。这意味着您可以将数组、函数甚至其他对象添加为此对象的属性。向此对象添加新属性可以通过以下两种方式之一完成：

```js
var person = {}; 
person.firstName = 'Jason';    // via dot operator 
person['lastName'] = 'Krol';   // via square brackets 
```

让我们看一个例子，我们将数组和函数添加为此对象的属性：

```js
var person = {}; 
person.firstName = 'Jason';    // properties 
person.lastName = 'Krol'; 
person.fullName = function() {  // methods 
  return this.firstName + ' ' + this.lastName; 
}; 
person.colors = ['red', 'blue', 'green'];  // array property 
```

您可以在前面的代码中看到，我们定义了一个名为`person`的基本对象，并为其分配了一些属性和一个函数。重要的是要注意在`fullName`函数中使用了`this`关键字。`this`关键字指的是函数所属的对象。因此，通过`this`关键字，函数将能够访问其所属对象的其他属性。

除了在对象创建后添加属性的方法之外，我们还可以在创建对象时将初始对象属性附加为其一部分，如下所示：

```js
// define properties during declaration 
var book = { 
  title: 'Web Development with MongoDB and NodeJS', 
  author: 'Jason Krol', 
  publisher: 'Packt Publishing' 
}; 
console.log(book.title); 
// => Web Development with MongoDB and NodeJS 
book.pageCount = 150;    // add new properties 
```

在前面的示例中，我们创建对象时没有指定它们应该由哪个类创建，而是使用`{}`。因此，这将导致从`Object`基类创建此新对象，其他复合类型（如数组和函数）都是从该基类扩展的。因此，当您使用`{}`时，它等同于一个新的`Object()`。

在这里，我们通过使用对象字面量`{}`创建的对象是`Object`类的实例。要为我们的应用程序定义自定义类，我们需要使用函数和原型。Mozilla 在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Introduction_to_Object-Oriented_JavaScript`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Introduction_to_Object-Oriented_JavaScript)上提供了一个相当不错的教程，介绍了整个要点。es6 通过添加各种功能增强了对象属性：

首先，最重要的是**属性简写**。现在，使用 es6，我们可以使用变量分配属性。让我们使用以下示例来理解这一点：

```js
let publisher = 'Packt Publishing';
let book = { publisher };
console.log(book.publisher);
```

在前面的片段中，变量值隐式分配给对象属性，声明对象时无需指定属性。

下一个令人惊叹的功能是计算对象字面量中属性键的属性。要了解此功能，让我们向前面的对象添加一个名为`book`的属性。

```js
let edition = 3;
let book = {publisher,[ `Whats new in ${edition} ? `] : "es6 and other improvisation"}
```

es6 向我们介绍了一个最期待的功能之一，称为**模板文字**。您可能已经注意到在前面的片段中使用了`${}`占位符的一种插值操作。这只是一个字符串中变量的连接，而不使用任何运算符，例如`+`。模板文字增强了 JavaScript 中的可读性功能，这是非常重要的。有关更多信息，请访问链接[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Template_literals`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Template_literals)。

运行前面的代码后，我们注意到 es6 使我们能够使用方括号计算属性名称的任何计算。最后，我们可以遵循`object`属性中所有函数的方法表示的优雅特性。这可以在以下示例中看到：

```js
var person = { 
        firstName : 'Jason', 
        lastName : 'Krol', // properties 
       fullName() {  // method notation 
                      return this.firstName + ' ' + this.lastName; 
} 
}; 
```

始终记住，对象只是内存位置的地址，而不是实际存储。例如，`firstName: 'Jason'`存储在内存位置`person.firstName`的地址中。到目前为止，我们已经了解了称为变量的单个存储点，让我们进一步学习多个存储点。

# 理解数组

在 JavaScript 中，数组的工作方式与几乎任何其他语言中的工作方式相同。它们是从零开始索引的，您可以将变量声明为空数组或预填充数组。您可以操作数组中的项目，并且数组的长度不固定：

```js
var favFoods = ['pizza', 'cheeseburgers', 'french fries']; 
var stuff = [];        // empty array 
var moreStuff = new Array();       // empty array 
var firstFood = favFoods[0];    // => pizza

// array functions: 
favFoods.push('salad');    // add new item

// => ['pizza', 'cheeseburgers', 'french fries', 'salad'] 
favFoods.pop();        // remove the last item 
// => ['pizza', 'cheeseburgers', 'french fries'] 
var first = favFoods.shift();     // remove the first item 
// => first = 'pizza';  
// => favFoods = ['cheeseburgers', 'french fries'] 
```

更准确地说，您可以将数组视为基本`Object`类的扩展子类，具有`Array`函数的额外实现。

# 理解函数

在 JavaScript 中，函数是头等公民。这意味着`function`本身是一个对象，因此可以将其视为对象，并将其与基本`Object`类扩展为具有属性和附加函数。我们将看到许多情况下，我们将函数作为参数传递给其他函数，并从其他函数调用中返回函数。

在这里，我们将采用标准函数（在本例中为`myFunction`）。我们将为此函数分配一个`timesRun`属性，就像在执行任何其他对象时一样，并查看如何稍后引用该属性：

```js
var myFunction = function() { 
  if(this.timesRun) 
    this.timesRun += 1; 
  else 
    this.timesRun = 1; 
  // do some actual work 

  console.log(this.timesRun); 
}; 
myFunction(); 
// => 1; 
myFunction(); 
// => 2; 
myFunction(); 
// => 3;  
```

正如我们在前面的示例中所看到的，使用 var 关键字，我们可以以与变量相同的方式定义函数：

```js
function sayHello() {
 console.log('Hello!');
}
// or 
var sayHello = function() {
 console.log('Hello!');
};
```

在前面的示例代码中，两种方法几乎是相同的。第一种方法是定义函数的最常见方式，称为**命名函数方法**。这里讨论的第二种方法是函数表达式方法，其中您将未命名函数分配为变量的引用并保持其未命名。

这两种方法之间最重要的区别与一个叫做 JavaScript hoisting 的概念有关。基本上，不同之处在于当你采用函数表达式策略时，函数在其定义语句执行之前将不会在其包含的范围内可用。在命名函数方法中，无论你在哪个位置定义它，该函数都将在其包含的范围内可用，如下面的代码所示：

```js
one();//will display Hello  
two();//will trigger error as its definition is yet to happen. 

function one() { 
    console.log('Hello!'); 
} 

var two = function() { 
  console.log('Hello!'); 
}; 
two ();//will display Hello 
```

在前面的示例代码片段中，`function one`可以从其父范围的任何地方调用。但是在其表达式被评估之前，`function two`将不可用。

JavaScript hoisting 是指在脚本执行之前，JS 解释器将函数定义和变量声明移动到包含范围的顶部的过程。因此，在命名函数的前一个案例中，定义被移动到了范围的顶部。然而，对于函数表达式，只有变量的声明移动到了范围的顶部，将其设置为未定义，直到脚本中实际执行的那一点。你可以在[`code.tutsplus.com/tutorials/JavaScript-hoisting-explained--net-15092`](http://code.tutsplus.com/tutorials/javascript-hoisting-explained--net-15092)上阅读更多关于 hoisting 的概念。

# 匿名函数和回调

通常，你需要使用一个临时函数，你不一定想提前声明。在这种情况下，你可以使用匿名函数，它只是在需要时声明的函数。这类似于我们之前探讨的函数表达式上下文，唯一的区别是该函数没有分配给一个变量，因此没有办法在以后引用它。匿名函数最常见的用法是当它们被定义为另一个函数的参数时（尤其是当用作*回调*时）。

使用匿名函数（即使你没有意识到它）的最常见的地方之一是与`setTimeout`或`setInterval`一起使用。这两个标准的 JavaScript 函数将在指定的延迟时间（以毫秒为单位）后执行代码，或者在指定的延迟时间后重复执行代码。以下是其中一个`setTimeout`的示例，使用了内联的匿名函数：

```js
console.log('Hello...'); 
setTimeout(function() { 
  console.log('World!'); 
}, 5000); 
// => Hello... 
// (5000 milliseconds i.e. 5 second delay) 
// => World! 
```

你可以看到匿名函数作为第一个参数传递给了`setTimeout`，因为`setTimeout`需要一个函数。如果你愿意，你可以提前声明函数作为变量，并将其传递给`setTimeout`，而不是内联的匿名函数：

```js
var sayWorld = function() { 
  console.log('World!'); 
} 
setTimeout(sayWorld, 5000); 
// (5 second delay) 
// => World! 
```

匿名函数只是作为一个干净的内联一次性函数。

回调很重要，因为 JavaScript 最强大（也最令人困惑）的特性之一是它是异步的。这意味着每一行都是按顺序执行的，但它不会等待可能需要更长时间的代码（即使是按设计）。我们在第一章中通过一个例子探讨了这一点，当时我们正在研究 Node.js 的异步特性。

Mozilla 有一个关于 JavaScript 概念的详细教程，我们建议你在完成本章后阅读一次。该教程包括高级概念，比如闭包，这些概念由于主题的深度而没有在本章中涵盖。因此，请参考 Mozilla 开发网络文章[`developer.mozilla.org/en-US/docs/Web/JavaScript/A_re-introduction_to_JavaScript`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/A_re-introduction_to_JavaScript)。

# JSON

**JavaScript 对象表示法**（**JSON**）是处理 JavaScript 以及大多数其他语言和网络服务中的数据时使用的标准语法。JSON 的基本原则是它看起来与标准的 JavaScript 对象完全相同，只有一些严格的例外：

+   JSON 是纯文本。没有带属性的数据类型；也就是说，日期值被存储为字符串等等

+   所有名称和字符串值必须用双引号括起来

+   属性中不能包含函数

让我们快速看一下一个标准的 JSON 对象：

```js
{ 
  "title": "This is the title", 
  "description": "Here is where the description would be", 
  "page-count": 150, 
  "authors": [ 
    { "name": "John Smith" }, 
    { "name": "Jane Doe" }, 
    { "name": "Andrea Johnson" } 
  ], 
  "id": "1234-567-89012345" 
} 
```

如果您对 XML 有所了解，JSON 有些类似，只是它更容易阅读和理解。正如 ECMA 所描述的那样，“*JSON 是一种文本格式，可以促进所有编程语言之间的结构化数据交换*”。

# Node.js 的基础知识

在了解 JavaScript 的基础知识之后，让我们专注于 Node 的一些基础知识。我们将从理解 node.js 核心架构开始。不同的 node 特性的重要性在于它的架构和工作方式。让我们在下一节仔细研究它。

# Node.js 架构

Web 应用程序通常遵循由客户端、Web 服务器和数据源组成的三层 Web 架构。在我们的上下文中，我们使用 Node.js 创建了一个 Web 应用服务器。正如我们在第一章中讨论的那样，*欢迎来到全栈 JavaScript 中*，Node.js 遵循单线程的架构模型。为了减少内存泄漏并在编写代码时理解异步性，我们需要了解 Node.js 的工作原理。

以下图表描述了代码的可视化表示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/adb24843-8871-4455-9c64-88a3da79ef3d.jpg)

每个处理组件按以下顺序进行排列：

1.  客户端发送请求（考虑一个 HTTP 请求）。

1.  Chrome 的 v8 引擎是一个**即时**（**JIT**）编译器。一旦服务器接收到请求，v8 将 JavaScript 代码转换为机器代码。

1.  Node.js 核心中的 C++ API 为其他系统级组件提供了绑定。绑定基本上是一个包装库，使得用一种语言编写的代码可以与用另一种语言编写的代码进行通信。这个 API 负责发出一个事件。

1.  一旦事件被触发，它就被存储在**事件队列**中。

1.  **事件循环**负责从队列中获取事件并在调用堆栈中执行它。

1.  如果一个事件需要执行异步操作，比如使用数据库文件，它会切换执行上下文到另一个工作线程并执行。这是由 libuv 完成的。libuv 库负责处理系统中事件生命周期的异步行为。它是用 C 编写的。它维护一个线程池来处理诸如 I/O 和网络相关操作的异步请求。

1.  一旦异步操作完成，它返回回调。回调保持在事件队列中，直到调用堆栈为空。

1.  一旦调用堆栈为空，事件循环就会从事件队列中提取回调并在调用堆栈中执行它。

1.  最终，事件将数据返回给 Node API。

1.  在每个循环中，它执行单个操作。虽然操作是顺序执行的，但这个单线程的机械化事件循环非常快，以至于提供了并发的错觉。单个线程可以利用系统的单个核心；因此，它提供了更好的性能和最小的响应时间给客户端。

# 事件驱动

在其核心，Node 最强大的功能之一是它是事件驱动的。这意味着你在 Node 中编写的几乎所有代码都是以响应事件的方式编写的，或者是自身触发事件（进而触发其他代码监听该事件）。

让我们来看一下我们将在后面的章节中编写的处理使用 Mongoose 连接到 MongoDB 服务器的代码，Mongoose 是一个流行的 Node.js MongoDB **对象文档映射**（**ODM**）模块：

```js
mongoose.connect('); 
mongoose.connection.on('open', function() { 
console.log("Connected to Mongoose..."); 
}); 
```

首先，我们告诉我们的 `mongoose` 对象连接到作为参数传递给函数的服务器。连接可能需要一段时间，但我们无法知道需要多长时间。因此，我们绑定了一个监听器到 `mongoose.connection` 对象的 `open` 事件上。通过使用 on 关键字，我们指示当 `mongoose.connection` 对象触发 `open` 事件时，执行作为参数传递的匿名函数。

# 异步执行

早些时候，我们在浏览器中使用 `setTimeout` 来回顾异步 JavaScript 代码的概念；这些原则在 Node 的世界中更为强大。由于您可能会对不同的 REST API 服务、数据库服务器和其他任何内容进行许多网络相关的连接，因此很重要的是，您的代码可以平稳执行，并且在每个服务响应时都有适当的回调使用。

# 模块系统

为了使代码尽可能模块化和可重用，Node 使用了一个模块系统，允许您更好地组织代码。基本前提是，您编写一个满足单一关注点的代码，并使用 `module.exports`（或简单地 `exports`）将此代码导出为服务于该单一目的的模块。每当您需要在代码库的其他地方使用该代码时，您将需要该模块：

```js
// ** file: dowork.js 
module.exports = { 
  doWork: function(param1, param2) { 
    return param1 + param2; 
  }   
} 

// ** file: testing.js 
var worker = require('./dowork'); // note: no .js in the file 

var something = 1; 
var somethingElse = 2; 

var newVal = worker.doWork(something, somethingElse); 
console.log(newVal); 
// => 3 
```

使用这个系统，可以简单地在许多其他文件中重用模块（在本例中是 `dowork` 模块）中的功能。此外，模块的各个文件充当私有命名空间，这意味着每个文件定义一个模块并且被单独执行。在模块文件中声明和使用的任何变量都是私有的，不会暴露给通过 `require()` 使用模块的任何代码。开发人员可以控制模块的哪一部分将被导出。这种模块的实现被称为**commonJs**模块模式。

在我们总结 Node.js 中的模块系统之前，我们需要了解 `require` 关键字。`require` 关键字接受文件地址作为字符串，并将其提供给 JavaScript 引擎编译为 `Module._load` 方法。`Module._load` 方法首次执行时，实际上是从导出的文件中加载，并且进一步进行缓存。缓存是为了减少文件读取次数，可以显著加快应用程序的速度。此外，当下次加载模块时，它会从缓存中提供已加载模块的实例。这允许在项目中共享模块，并保持单例状态。最后，`Module._load` 方法返回所述文件的 `module.exports` 属性在其各自的执行中。

模块系统也可以无限扩展。在您的模块中，您可以要求其他模块，依此类推。在导入时要确保不会导致所谓的**循环**依赖。

循环依赖是指模块直接或间接地要求自身的情况。我们可以从以下链接的讨论中了解更多：

[`stackoverflow.com/questions/10869276/how-to-deal-with-cyclic-dependencies-in-node-js`](https://stackoverflow.com/questions/10869276/how-to-deal-with-cyclic-dependencies-in-node-js)。

# Node.js 核心

Node.js 核心实际上有数百个模块可供您在编写应用程序时使用。这些模块已经编译成二进制，并在 Node.js 源代码中定义。其中包括以下内容：

+   事件

+   文件系统

与其他语言一样，Node.js 核心还提供了使用`fs`模块与文件系统交互的能力。该模块配备了不同的方法，用于同步和异步地执行文件的不同操作。参考第一章。*欢迎来到全栈 JavaScript*，了解更多关于同步和异步的区别。`fs`的同步方法以关键字 Sync 结尾，例如`readFileSync`。要深入了解模块，请参考以下链接：[`nodejs.org/api/fs.html`](https://nodejs.org/api/fs.html)。

# HTTP

HTTP 模块是 Node.js 核心中最重要的模块之一。HTTP 模块提供了实现 HTTP 客户端和服务器的功能。

以下是创建基本服务器和客户端所需的最小代码：

| **HTTP 服务器** | **HTTP 客户端** |
| --- | --- |

|

```js
const http = require('http');
//create a server object
http.createServer((req, res)=>{
  res.write('Hello Readers!'); //write a response to the client
  res.end(); //end the response
}).listen(3000); //the server object listens on port 3000
```

|

```js
const http = require('http');
http.get({
 hostname: 'localhost',
 port: 3000,
 path: '/'
}, (res) => {
 res.setEncoding('utf8');
 res.on('data', (chunk)=>{
 console.log(`BODY: ${chunk}`);
 });
});
```

|

考虑到前面的代码，一旦模块被引入，我们就可以使用 HTTP 对象的实例来创建服务器或请求另一端的服务器。`createServer`方法需要一个回调作为参数。每当服务器受到 HTTP 请求时，都会调用这个`callback`。此外，它还提供一个响应对象作为参数，以便相应地处理返回的响应。

# Net

前面的 HTTP 模块是使用 net 模块连接的。根据 node.js api 的文档，net 模块提供了用于创建基于流的 TCP 或 IPC 服务器的异步网络 API。这是 Node 的核心编译二进制库之一，它与内部 C 库 libuv 交互。libuv 库负责处理异步请求，如 I/O 和网络相关操作。最好的参考文档是 Node 自己的文档：[`nodejs.org/api/net.html`](https://nodejs.org/api/fs.html)。

# 流

流是核心模块中最重要的模块之一。简单来说，流是从特定来源接收的数据流的小数据块。在接收端，它可能既没有所有的流数据，也不必一次性将其全部放入内存。这使我们能够使用有限的资源处理大量数据。我们可以通过 Dominic Denicola 提供的类比来形象地描述流。根据他的说法：

"流是异步可迭代对象，就像数组是同步可迭代对象一样"。

考虑到我们需要在进行多次读写操作的环境中读取大文件数据。在这种情况下，流提供了一个强大的抽象来处理低级 I/O 系统调用，同时提供性能优势。

内部流模块不应直接使用，以避免在 Node 版本之间发生行为变化。但是，我们可以在 npm 上使用可读流等包装模块。

尽管在我们的书的上下文中并未广泛使用流，但它是 Node.js 核心的一个支柱特性，被其内部模块使用，并一直是 Node.js 生态系统的重要组成部分。要了解更多关于流的信息，请访问以下链接：[`community.risingstack.com/the-definitive-guide-to-object-streams-in-node-js/`](https://community.risingstack.com/the-definitive-guide-to-object-streams-in-node-js/)。

一定要查看 Node 的在线文档：[`nodejs.org/api`](http://nodejs.org/api)，以查看 Node 核心中可用模块的完整列表，并查看大量示例代码和解释。

# 使用 npm 安装模块

Node 中的模块系统非常强大，使用其他开发者编写的第三方模块非常简单。Node 包含了自己的包管理器**npm**，它是一个注册表，目前包含了超过 475,000 个用 Node 编写的模块。这些模块完全开源，并且可以通过几个简短的命令让你使用。此外，你也可以通过 npm 发布你自己的个人模块，并允许世界上的任何人使用你的功能！

假设你想要在你的项目中（我们在本书后面会使用的）包含一个流行的 web 框架`express`。下载一个模块并在你的代码中使用它只需要两个简单的步骤：

```js
    $ npm install express
    // ** file: usingnpm.js
    var express = require('express');  
```

就是这样！真的，就是这么简单！从你的项目所在的文件夹的命令行中，只需要执行`npm install package-name`，这个包就会从 npm 下载并存储在你的项目中的一个叫做`node_modules`的文件夹中。如果你浏览`node_modules`文件夹，你会发现一个你安装的包的文件夹，在这个文件夹中，你会找到这个包本身的原始源代码。一旦这个包被下载，使用`require()`在你的代码中就会变得非常简单。

有时候你可能想要全局安装一个 Node 包，比如说，当你使用一个叫做 Grunt.js 的流行命令行构建工具的时候。要全局安装一个 npm 包，只需要包含`-g`或者`--global`标志，这个模块就会被安装为一个全局可执行文件。当全局安装 npm 包时，这个包的源文件并不会存储在特定项目的`node_modules`文件夹中，而是存储在你机器的系统目录下的`node_modules`文件夹中。

npm 的一个非常强大的特性是它允许其他开发者快速、简单、一致地在他们的本地环境中启动你的代码。Node 项目通常包括一个特殊的文件叫做`package.json`，其中包含了关于项目的信息以及项目依赖的所有 npm 包的列表。拥有你本地代码副本的开发者只需要执行`npm install`就可以通过这个文件下载并在本地安装每个依赖。

如果你想要安装的依赖被保存到`package.json`文件中，`npm install`标志`--save`或者`--save-dev`是必需的。如果你正在开始一个新项目，不想手动创建一个`package.json`文件，你可以简单地执行`npm init`并回答几个快速的问题来快速设置一个默认的`package.json`文件。在`init`期间，如果你想的话可以留空每个问题并接受默认值：

```js
    $ npm init

    $ npm install express --save
    $ npm install grunt --save-dev
    $ cat package.json
    {
     "name": "chapter3",
     "version": "0.0.0",
     "description": "",
     "main": "index.js",
     "scripts": {
       "test": "echo \"Error: no test specified\" && exit 1"
     },
     "author": "",
     "license": "ISC",
     "dependencies": {
       "express": "³.5.1"
     },
     "devDependencies": {
       "grunt": "⁰.4.4"
     }
    }

```

`dependencies`和`devDependencies`部分列出了`express`和`grunt`。这两个部分的区别在于，`dependencies`部分对于应用程序的正常运行是绝对关键的，而`devDependencies`部分只包含了在项目开发过程中需要安装的包（比如 Grunt 用于各种构建步骤、测试框架等）。如果你对包版本中的`^`符号的使用感到困惑，它用于更新依赖到最新的次要版本或者补丁版本（第二个或第三个数字）。`¹.2.3`将匹配任何 1.x.x 版本，包括 1.3.0，但不会包括 2.0.0。所以，在我们的例子中，`³.5.1`的 Express.js 将寻找最新的 express.js 的次要版本，但不会接受 4.0.0，因为这是一个主要版本。

# MongoDB 的基础知识

由于 MongoDB 主要由 JavaScript 驱动，Mongo shell 充当了一个 JavaScript 环境。除了能够执行常规的 Mongo 查询之外，你还可以执行标准的 JavaScript 语句。在 JavaScript 入门中提到的大部分内容同样适用于 Mongo shell。

在这一节中，我们将主要关注通过 Mongo shell 执行标准 CRUD 操作的各种方法。

# Mongo shell

要访问 Mongo shell，只需从任何终端执行`mongo`。Mongo shell 需要`mongod`服务器当前正在运行并且可用于机器，因为它的第一件事就是连接到服务器。使用以下命令访问 Mongo shell：

```js
    $ mongo
    MongoDB shell version: 2.4.5
    connecting to: test
    >
```

默认情况下，当您首次启动 Mongo 时，您会连接到本地服务器，并设置为使用`test`数据库。要显示服务器上所有数据库的列表，请使用以下命令：

```js
    > show dbs
```

要切换到`show dbs`输出中列出的任何数据库，请使用以下命令：

```js
    > use chapter3
    switched to db chapter3
```

值得注意的是，如果您在一个不存在的数据库上使用`use`，

将自动创建一个。如果您正在使用现有数据库，并且想要查看数据库中的集合列表，请执行以下命令：

```js
    > show collections
```

在我`chapter3`数据库的情况下，由于它是自动生成的新数据库，我没有现有的集合。MongoDB 中的集合类似于关系数据库中的表。

# 插入数据

由于我们正在使用`chapter3`数据库，这是一个全新的数据库，目前里面没有集合。您可以通过简单地引用一个新的集合名称和`db`对象来使用任何集合（表）：

```js
> db.newCollection.find() 
> 
```

在空集合上执行`find`操作只会返回空。让我们插入一些数据，这样我们就可以尝试一些查询：

```js
> db.newCollection.insert({ name: 'Jason Krol', website: 
 'http://kroltech.com' }) 
> db.newCollection.find().pretty() 
{ 
  "_id" : ObjectId("5338b749dc8738babbb5a45a"), 
  "name" : "Jason Krol", 
  "website" : "http://kroltech.com" 
} 
```

在我们执行简单的插入（基本上是一个 JavaScript JSON 对象）之后，我们将在集合上执行另一个`find`操作，并且返回我们的新记录，这次还添加了一个额外的`_id`字段。`_id`字段是 Mongo 用来跟踪每个文档（记录）的唯一标识符的方法。我们还在`find()`的末尾链接了`pretty()`函数，这样可以更好地输出结果。

继续插入一些记录，这样您就有一些数据可以在下一节进行查询时使用。

# 查询

在 MongoDB 集合中查询和搜索文档非常简单。仅使用没有参数的`find()`函数将返回集合中的每个文档。为了缩小搜索结果，您可以提供一个`JSON`对象作为第一个参数，其中包含尽可能多或尽可能少的特定信息以匹配，如下面的代码所示：

```js
> db.newCollection.find({ name: 'Jason Krol' }) 
{ "_id" : ObjectId("533dfb9433519b9339d3d9e1"), "name" : "Jason 
 Krol", "website" : "http://kroltech.com" }
```

您可以包含额外的参数来使搜索更精确：

```js
> db.newCollection.find({ name: 'Jason Krol', website: 
 'http://kroltech.com'}){ "_id" : ObjectId("533dfb9433519b9339d3d9e1"), "name" : "Jason 
 Krol", "website" : "http://kroltech.com" }
```

对于每个结果集，每个字段都包含在内。如果您只想返回特定的一组字段，您可以将`map`作为`find()`的第二个参数包括：

```js
> db.newCollection.find({ name: 'Jason Krol' }, { name: true }) 
{ "_id" : ObjectId("533dfb9433519b9339d3d9e1"), "name" : "Jason Krol" 
 }> db.newCollection.find({ name: 'Jason Krol' }, { name: true, _id: 
 false }) 
{ "name" : "Jason Krol" } 
```

`_id`字段将始终默认包含，除非您明确声明不想包含它。

此外，您可以使用查询运算符来搜索范围内的内容。这些包括大于（或等于）和小于（或等于）。如果您想对作业集合执行搜索，并且想要找到每个分数在 B 范围内（80-89）的文档，您可以执行以下搜索：

```js
> db.homework_scores.find({ score: { $gte: 80, $lt: 90 } }) 
```

最后，您可以在执行搜索时使用`regex`来返回多个匹配的文档：

```js
> db.newCollection.find({ name: { $regex: 'Krol'} }) 
```

前面的查询将返回包含单词`Krol`的每个文档。您可以使用`regex`语句进行高级查询。

如果您知道您将在查询中返回多个文档，并且只想要第一个结果，请使用`findOne()`代替常规的`find()`操作。

# 更新数据

要更新记录，请使用`update()`函数，但将查找查询作为第一个参数包括：

```js
> db.newCollection.update({ name: 'Jason Krol' }, { website: 
                           'http://jasonkrol.com' })
```

这里有一个小问题。如果你执行一个新的`find({ name: 'Jason Krol' })`操作，会发生一些奇怪的事情。没有返回数据。发生了什么？好吧，`update()`函数的第二个参数实际上是完整文档的新版本。因此，你只想要更新`website`字段，实际发生的是找到的文档被新版本替换，新版本只包含`website`字段。重申一下，之所以会发生这种情况，是因为在 NoSQL（如 MongoDB）中，文档没有固定数量的字段（如关系数据库）。要解决这个问题，你应该使用`$set`运算符。

```js
> db.newCollection.update({ name: 'Jason Krol' }, { $set: { website: 
 'http://jasonkrol.com'} })
```

也许有一天你想要更新一个文档，但文档本身可能存在，也可能不存在。当文档不存在时，如果你想根据提供的更新值立即创建一个新文档，会发生什么？好吧，有一个很方便的函数专门用于这个目的。将`{upsert: true}`作为`update()`函数的第三个参数传递：

```js
> db.newCollection.update({ name: 'Joe Smith' }, { name: 'Joe Smith', 
                     website: 'http://google.com' }, { upsert: true })
```

如果我们有一个`name`字段匹配`Joe Smith`的文档，`website`

字段将被更新（并且`name`字段将被保留）。但是，如果我们没有

匹配的文档，将自动创建一个新文档。

# 删除数据

删除文档的工作方式几乎与`find()`完全相同，只是不是查找和返回结果，而是删除与搜索条件匹配的文档：

```js
> db.newCollection.remove({ name: 'Jason Krol' }) 
```

如果你想要核心选项，你可以使用`drop()`函数，它将删除集合中的每个文档：

```js
> db.newCollection.drop() 
```

# 额外资源

对于 JavaScript 的进一步学习，我建议你查看以下一些资源：

+   Mozilla 开发者网络位于[`developer.mozilla.org/en-US/docs/Web/JavaScript`](https://developer.mozilla.org/en-US/docs/Web/JavaScript)

+   *Secrets of the JavaScript Ninja*，*John Resig*，*Bear Bibeault*，*Manning*

+   *Learning JavaScript Design Patterns*，*Addy Osmani*，*O'Reilly*

+   *JavaScript: The Good Parts*，*Douglas Crockford*，*O'Reilly*

Node API 在线文档将是你全面了解 Node 核心模块中所有可用内容的最佳选择。Node API 文档可以在[`nodejs.org/api`](http://nodejs.org/api)找到。

此外，有一个很棒的网站，教你使用实际的编程问题来学习 Node。这些练习的重点是理解 Node 的工作原理，并深入了解流、异步 I/O、promises 等基本知识。Node school 可以在[`nodeschool.io`](http://nodeschool.io)找到。

最后，MongoDB 的创建者提供了一个令人惊叹的 7-8 周在线培训和认证计划，完全免费，你将学到成为真正的 MongoDB 大师所需的一切。这可以在 MongoDB 大学的[`university.mongodb.com`](https://university.mongodb.com)找到。

现在是时候深入进入并开始编写一些真正的代码了！

# 总结

在本章中，你快速学习了 JavaScript、Node.js 和 MongoDB 的基础知识。此外，你还了解了 Node 的包管理器 npm。为了进一步学习，提供了 JavaScript、Node.js 和 MongoDB 的额外资源。

在下一章中，你将使用 Express.js 编写你的第一个 Node web 服务器，并开始创建一个完整的 Web 应用程序。


# 第四章：介绍 Express

当我们需要构建一个完整的 Web 应用程序时，从头开始编写整个应用程序并不是最佳的方法。我们可以使用一个维护良好、编写良好的 Web 应用程序框架来构建我们的应用程序，以减少开发工作量并提高可维护性。

在本章中，我们将涵盖以下主题：

+   探索 Express.js Web 应用程序框架

+   探索 Express.js 的各种元素

+   使用 Express 开发必要的代码来引导 Web 应用程序

# Web 应用程序框架

简而言之，Web 框架使得开发 Web 应用程序变得更容易。考虑将常用功能分解为可重用模块的方面。这正是框架所做的。它们带有许多可重用模块，并强制执行代码的标准结构，以便全世界的开发人员更容易地浏览和理解应用程序。

除了所有这些优点之外，Web 框架大多由全世界的开发人员维护。因此，开发人员将新的 bug 修复和底层语言的功能整合到框架版本中的工作量最小化，我们只需要升级应用程序使用的框架版本。因此，使用 Web 框架构建 Web 应用程序为开发和维护阶段带来了许多优势。

我们将在整本书中使用的 Express.js 框架是基于**模型-视图-控制器**（**MVC**）的 Web 应用程序框架。MVC 只是一种架构设计模式：

+   模型：模型用于表示 Web 应用程序的数据或实体。

它更接近实例，这些实例存储应用程序的数据，通常是数据库或 Web 服务。

+   视图：视图负责将应用程序呈现给最终用户。因此，视图可以被视为应用程序的呈现层。

+   控制器：现在，你可能想知道控制器在 Web 应用程序中的作用。控制器的作用就是将模型与相应的视图粘合在一起，并负责处理用户对应用程序中特定 Web 页面的请求。

如果你第一次听到这个概念，可能会有点难以理解。但是在阅读完本章之后，我们会向你展示各种例子，让你逐渐熟悉这些概念。

# 什么是 Express.js？

正如它在主页上完美描述的那样，Express 是一个最小化和灵活的 Node.js

Web 应用程序框架，提供了一套强大的功能，用于构建单页、多页和混合 Web 应用程序。换句话说，它提供了所有你需要的工具和基本构建块，只需编写很少的代码就可以让 Web 服务器运行起来。它让你专注于编写你的应用程序，而不用担心基本功能的细节。

Express 框架是最流行的基于 Node 的 Web 框架之一，也是`npm`中最流行的包之一。它是基于 Sinatra Web 框架构建的，在 Ruby 世界中非常流行。有很多跨语言的框架都受到 Sinatra 简单性的启发，比如 PHP 的 Laravel 框架。因此，Express 是 Node.js 世界中基于 Sinatra 的 Web 框架。

如果你看一段代码示例，Express 的最基本实现之一，你会发现启动 Web 服务器是多么容易，例如：

```js
const express = require('express'); 
const app = express(); 
app.get('/', (req, res)=>{ 
   res.send('Hello World'); 
}); 
app.listen(3300); 
```

Express 的美妙之处在于它使得构建和维护网站的服务器代码变得简单。

# 构建完整的 Web 应用程序

从本章开始，我们将构建一个完整的 Web 应用程序。

我们将要构建的 Web 应用程序将是一个流行的社交图片分享网站[imgur.com](http://imgur.com)的克隆。我们将称我们的网站为`imgPloadr.io`。

# 设计 Web 应用程序

网站的要求如下：

+   主页将允许访问者上传图片，并浏览已上传的图片，这些图片将按从新到旧的顺序进行排序。

+   每个上传的图片将通过自己的页面呈现，显示其标题、描述和大图像。访问者将能够喜欢图片并发表评论。

+   一个一致共享的侧边栏将在两个页面上可见，并展示有关网站的一般统计信息，最受欢迎的图片和最近的评论。

该网站将使用 Bootstrap，以便具有漂亮的专业设计，并且在任何设备上都能响应。

以下屏幕截图是完成网站的主页：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/03b442bd-b85f-4b44-b678-59376c2e67dc.png)

以下屏幕截图是网站上图片的详细页面：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/583645f2-a488-46a8-91cd-ae0421631c8e.png)

# 组织文件

在编写任何代码之前，我们希望确保您已经正确设置了项目文件夹，并具有正确的文件夹结构来存放您将要创建的各种文件。首先创建一个新的项目文件夹，并为其命名。然后，在该文件夹内，创建额外的文件夹以匹配以下结构：

```js
/(project root) 
---/helpers 
---/controllers 
---/public 
------/css 
------/img 
------/js 
------/upload 
---/server 
---/Views 
------/layouts 
------/partials 
```

这些文件夹中的每一个都将包含我们在本章和本书的其余部分中编写的重要模块。

如果您通过 Yeoman 使用基于 Express 的生成器，您将获得必要的文件夹结构和依赖项与样板代码导入。然而，由于我们的意图是了解这个框架，我们将跳过这一步。访问[`yeoman.io/`](http://yeoman.io/)了解更多关于`Yeoman`功能的信息。

您需要一个`package.json`文件用于这个项目，创建这个文件的最简单方法是从项目文件夹的根目录执行以下命令：

```js
$ npm init  
```

在提示时回答每个问题，或者简单地重复按*Enter*接受默认值。现在，让我们通过`npm`安装 Express 及其必要的依赖项：

```js
$ npm install express morgan body-parser cookie-parser method-
override errorhandler express-handlebars --save  
```

这将在`node_modules`文件夹中安装 Express 框架，并且还将在`package.json`文件的依赖项部分中添加 Express。请注意，在撰写本书时，Express.js 处于其 4.x.x 版本。在这里，您可以看到，Express 是一个完全解耦的框架，它本身并不带有很多打包的模块。相反，您可以找出应用程序的依赖关系，并随时插入和拔出应用程序。如果您从一开始就一直关注 Express 的发展，您一定会注意到这些变化是作为 Express 4.x.x 版本的一部分引入的。在此版本之前，Express 通常会随附许多内置模块。在这里，我们与 Express 一起安装的模块是我们在构建完整 Web 应用程序时应用程序具有的各种依赖项。我们将在本章的后面部分讨论每个模块的使用。

# 创建应用程序的入口点

安装 Express 和必要的依赖项之后，开发应用程序的下一步将是创建一个文件，该文件将作为应用程序的默认入口点。我们将执行此文件来启动我们的 Web 应用程序，并且它将包含必要的代码来要求依赖模块，并在开发服务器上监听指定的端口。

我们暂时将入口点文件命名为`server.js`，并且保持它非常简洁，以便内容相当自解释。在这个文件中执行的任何主要逻辑实际上将被延迟到其他文件中托管的外部模块中。

在`server.js`中我们无法做任何事情之前，我们需要引入一些我们将要使用的模块，特别是 Express：

```js
const express = require('express'); 
// config = require('./server/configure'); 
let app = express(); 
```

在前面的代码中，我们将`express`模块分配给`express`变量。`config`模块实际上将是我们自己编写的模块，但目前由于它不存在，我们将保留该行的注释。最后，我们将声明一个名为`app`的变量，这实际上是 Express 框架在执行时返回的内容。这个`app`对象驱动我们整个`app`应用程序，这就是它如此巧妙地命名的原因。

在本章和本书的其余部分中，我可能会在示例中包含已注释的代码（以`//`开头的代码）。这样，当我们使用已注释的行作为参考点时，或者当我们通过简单取消注释代码来启用这些功能时，跟随将会更容易。

接下来，我们将通过`app.set()`函数在`app`对象中设置一些简单的设置。这些设置实际上只是为了定义一些我们可以在代码的其余部分中使用的应用级常量，以便我们可以方便地使用它们作为快捷方式：

```js
app.set('port', process.env.PORT || 3300); 
app.set('Views', `${__dirname}/Views`); 
// app = config(app); 
```

代码解释如下：

+   前面代码的前两行使用了 Node 中的内置常量。`process.env.PORT`常量是设置在实际机器上的环境设置，用于服务器的默认端口值。如果在机器上没有设置端口值，我们将硬编码一个默认值`3300`来代替使用。

+   之后，我们将我们的 Views（HTML 模板）的位置设置为

`${__dirname}'/Views`，或者使用另一个 Node 常量，`/Views`

在当前工作目录中的文件夹。

+   代码的第三行引用了尚未编写的`config`模块，因此该行被注释掉了。

+   最后但并非最不重要的是，我们将使用我们的`app`对象创建一个 HTTP 服务器，并告诉它监听连接：

```js
app.get('/', (req, res) => {
  res.send('Hello World');
});
app.listen(app.get('port'), () => {
  console.log(`Server up: http://localhost:${app.get('port')}`);
});
```

在这里，我们在我们的应用程序中设置了一个路由，以响应`Hello World`消息。如果任何用户请求我们应用程序的根目录，它将会响应一个`Hello World`消息。代码的最后部分是在我们的应用程序上调用`listen()`函数，告诉它要监听哪个端口，并传入一个简单的匿名回调函数，一旦服务器启动并监听，就会执行一个简单的`console.log()`消息。就是这样！再次确保将此文件保存为项目根目录下的`server.js`。您已经准备好运行您的服务器，看看它是否正常工作。

# 启动应用程序

让我们来测试一下您的服务器的运行情况：

```js
$ node server.js
Server up: http://localhost:3300  
```

太棒了！到目前为止，您的服务器实际上并没有做任何伟大的事情。尝试将浏览器指向`http://localhost:3300`。您应该会收到一个非常基本的消息，上面写着`Hello World`！如果您请求端口上的任何其他路由，例如`http://localhost:3300/`，它将会响应一个无法获取的响应。这是因为您还没有配置任何路由或任何实际逻辑在您的服务器中，来处理特定的请求，只有一个对`/`默认路由的`GET`请求。

在设置路由之前，我们应该了解 Express 中间件的概念，这对于理解我们应用程序的自定义依赖模块如何与我们的正常应用程序流集成是至关重要的。

您可以在运行服务器之前，直接从命令行设置任意数量的环境变量，执行类似以下命令的操作：

```js
$   PORT=5500 node server.js
Server   up: http://localhost:5500   
```

您还可以在环境设置中永久设置环境变量。通常可以通过编辑您的`.profile`文件或等效文件来完成此操作。

# 中间件

Express 提供的最强大的功能之一是中间件的概念。中间件背后的思想是，它就像一个过滤器堆栈，每个对服务器的请求都会通过。每个请求都会经过每个过滤器，并且每个过滤器可以对请求执行特定任务，然后再传递到下一个过滤器。

为了更好地理解，这里是中间件的图解视图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/webdev-mongo-node/img/21df5552-efca-45c1-9090-21550c23cac5.png)

通常，这些过滤器用于诸如 cookie 解析、表单字段处理、会话处理、身份验证、错误处理和日志记录等任务。清单不胜枚举。您可以使用数百个第三方模块，也可以简单地编写自己的自定义中间件。

# 创建自定义中间件

毫无疑问，总有一天你会想要编写自己的自定义中间件，除了*Connect*或任何其他第三方提供的现有中间件。在 Node 中编写自定义中间件之前，习惯性地首先搜索[`www.npmjs.org/`](https://www.npmjs.org/)，因为很有可能其他人已经完成了这项工作。

编写自定义中间件非常简单。在使用 Express 框架时，它记录了各种类型的中间件，我们可以简单地将其分类为两种类型，即应用程序级和基于路由的中间件。

以下是应用程序级中间件的超级基本示例：

```js
app.use((err, req, res, next)=> { 
    // do whatever you want here, alter req, alter res, throw err etc. 
    return next(); 
});
```

`app.use`函数允许我们注册为中间件。在基本级别上，它是一个在`http.createServer`方法中接收请求时调用的函数。此外，我们需要编写一个接受四个参数的函数：`err`，`req`，`res`和`next`。

+   第一个参数是一个错误对象，如果在您的中间件运行之前有任何堆栈错误，该错误将被传递给您的中间件，以便您可以相应地处理它。这是一个可选参数；因此，如果对特定功能的实现不需要错误处理，我们可以跳过它。

+   你已经熟悉了`req`和`res`参数，已经编写了你的路由。

+   第四个参数实际上是一个回调的引用。这个`next`参数是中间件堆栈能够像堆栈一样运行的方式，每个执行并确保管道中的下一个中间件通过`next`返回和调用。

`app.use`方法还接受第一个参数作为路由或端点。这形成了之前提到的第二种中间件类型，称为**基于路由的中间件**。以下是语法：

```js
app.use('/get_data', (err, req, res, next)=>{ 
    console.log('Hello world!')     
    return next(); 
}, (err, req, res, next)=>{ 
    console.log('Hello world Again!')     
    return next();
});
```

因此，这表明我们不是将中间件应用于所有传入的请求，而是将其特定于一个路由并调用路由匹配。

在编写自定义中间件时唯一要记住的重要事情是你有正确的参数并且返回`next()`。其余完全取决于你！

# 中间件的顺序

中间件被调用的顺序非常重要。再次使用过滤器的概念，作为通过每个过滤器的请求，您要确保它们按正确的顺序执行其职责。一个很好的例子是在会话处理程序之前实现 cookie 解析器，因为会话通常依赖于 cookie 来在请求之间维护与用户的状态。

中间件顺序重要的另一个很好的例子涉及错误处理。如果你的任何中间件遇到错误，它们将简单地将该错误传递给堆栈中的下一个中间件。如果最后一个中间件，无论是什么，都不能优雅地处理该错误，它基本上会显示在你的应用程序中作为堆栈跟踪（这是不好的）。将错误处理程序配置为最后一个中间件之一就像是在说“*如果一切都失败，并且在以前的中间件的任何时候发生故障，请优雅地处理它*。”

我们已经安装的各种依赖项将被集成到我们的代码中作为中间件。我们将通过`config`模块来执行这个集成各种中间件的任务，因为它将帮助我们使`server.js`文件更加精简，并增加代码的可读性。

# 配置模块

由于我们保持`server.js`文件非常简洁，因此在配置服务器时仍需要相当多的逻辑。为此，我们将使用一个名为`configure`的自定义模块。首先，在`server`文件夹中创建一个`configure.js`文件。当我们首次安装 Express 时，我们已经安装了自定义依赖项。

现在模块已安装并准备好使用，让我们开始编写`configure.js`文件。首先，像我们的任何模块一样，我们将声明我们的依赖项：

```js
const path = require('path'), 
    routes = require('./routes'), 
    exphbs = require('express-handlebars'),), 
    express = require('express'), 
    bodyParser = require('body-parser'), 
    cookieParser = require('cookie-parser'), 
    morgan = require('morgan'), 
    methodOverride = require('method-override'), 
    errorHandler = require('errorhandler'); 

module.exports = (app)=>{ 
   app.use(morgan('dev')); 
   app.use(bodyParser.urlencoded({'extended':true})); 
   app.use(bodyparser.json()); 
   app.use(methodOverride()); 
   app.use(cookieParser('some-secret-value-here')); 
   routes(app);//moving the routes to routes folder. 

   app.use('/public/', express.static(path.join(__dirname, 
            '../public'))); 

if ('development' === app.get('env')) { 
   app.use(errorHandler()); 
} 
    return app; 
}; 
```

在前面的代码中，我们为我们自定义的`configure`模块中将要使用的每个模块声明了`const`。然后，我们定义了实际将由此代码文件导出的模块，更具体地说是一个接受我们的`app`对象作为参数的函数，并返回相同对象（在我们对其进行一些配置修改后）。

您应该看到我们需要 Connect，它实际上是 Express.js 的核心依赖项之一，默认安装。Connect 是一个流行的第三方中间件框架，我们将在本章后面更多地了解它。

让我们来看看我们在前面的代码中使用的每个 Connect 中间件：

+   `morgan`：这是负责记录日志的模块。这对调试您的 Node 服务器非常有帮助。

+   `bodyParser`：这有助于方便打包通过浏览器的 HTML 表单提交的任何表单字段。通过`POST`请求提交的表单字段将通过`req.body`属性可用。

+   `methodOverride`：对于不正确支持 REST HTTP 动词的旧浏览器，如`UPDATE`和`PUT`，`methodOverride`中间件允许使用特殊的隐藏输入字段来伪造它。

+   `cookieParser`：这允许发送和接收 cookie。

+   `errorHandler`：这处理整个中间件过程中发生的任何错误。通常，您会编写自己的自定义`errorHandler`，可能会呈现默认的 404 HTML 页面，将错误记录到数据存储中，等等。

+   `handlebars`：这是我们将与视图一起使用的模板引擎。我们将在接下来的部分中更多地解释如何集成它。

`routes(app)`行是 Express 的一个特殊组件，表示您实际上正在使用路由器与服务器，您可以响应`GET`、`POST`、`PUT`和`UPDATE`等请求。由于您正在使用 Express 路由器作为最后一个中间件之一，我们还将在下一节中定义实际的路由。

最后，`express.static()`中间件用于从预定义的静态资源目录向浏览器呈现静态内容文件。这很重要，这样服务器可以提供静态文件，如`.js`、`.css`、`图像`和`regular.html`，以及您可能需要提供的任何其他文件。静态中间件将从 public 目录提供任何静态文件，就像以下代码一样：

```js
http://localhost:3300/public/js/somescript.js
http://localhost:3300/public/img/main_logo.jpg
```

重要的是，您的静态中间件在`app.router()`之后定义，这样静态资产不会意外地优先于您可能已定义的匹配路由。

# 激活配置模块

现在您的`configure.js`文件已经完成，您可以从主`server.js`文件中调用它了。如果您还记得，我们在`configure`模块中包含了两行被注释掉的代码。现在是时候取消注释这两行了，这样当您运行服务器时，您的`configure`模块将发挥作用。这两行现在应该是这样的：

```js
config = require('./server/configure'), 
app = config(app); 
```

通过执行`server.js`节点再次启动服务器，一切应该仍然运行顺利。现在，是时候在我们的应用程序中加入更多路由了，除了我们之前添加的`Hello World`路由。

# 路由和控制器

到目前为止，你有你的`server.js`文件和一个`configure`模块，用于连接应用程序所需的所有中间件。下一步是实现适当的路由器和必要的控制器。

路由将是应用程序中每个可用 URL 路径的映射。服务器上的每个路由都对应于控制器中的一个函数。这是我们正在编写的特定应用程序的路由表：

```js
GET  /(index) - home.index (render the homepage of the site) 
GET  /images/image_id - image.index (render the page for a specific 
                                     image)
POST /images - image.create (when a user submits and uploads a new 
                              image)
POST /images/image_id/like - image.like (when a user clicks the Like 
                                          button)
POST /images/image_id/comment - image.comment (when a user posts a 
                                                comment)
```

你可以看到我们处理了两个不同的`GET`请求和三个不同的`POST`请求。此外，我们有两个主要的控制器：`home`和`image`。控制器实际上只是具有不同函数定义的模块，这些函数与相应的路由相匹配。正如前面指出的，它们在 MVC 设计模式中被称为控制器。通常，每个路由都对应一个控制器。这个控制器很可能会渲染一个视图，而这个视图很可能会有自己的模型（在视图中显示的任何数据）。

让我们将我们的路由写成一个与所述表格匹配的模块。首先，在`server`文件夹中创建一个`routes.js`文件。`routes`文件将会非常简单，它所需的唯一依赖将是我们定义的控制器：

```js
const express = require('express'), 
    router = express.Router(), 
    home = require('../controllers/home'), 
    image = require('../controllers/image'); 
module.exports = (app)=>{ 
    router.get('/', home.index); 
    router.get('/images/:image_id', image.index); 
    router.post('/images', image.create); 
    router.post('/images/:image_id/like', image.like); 
    router.post('/images/:image_id/comment', image.comment); 
    app.use(router); 
}; 
```

我们立即声明一个`router`变量，并要求`controllers`文件夹来分配每个应用程序路由（我们还没有创建这些文件，但接下来就要创建了）。在这里，我们将每个路由分配给控制器中的相应函数。然后，我们导出一个模块，当单独调用时，将所有这些路由附加到`app`实例上。

路由的第一个参数是路由本身的字符串值，它可以包含变量值作为子路径。你可以看到第二个`router.get`，我们分配了一个路由值`/images/:image_id`，它基本上等同于浏览器地址栏中的`/image/ANYVALUE`。当我们编写`image.index`控制器时，你将看到如何检索`:image_id`的值并在`controller`函数内部使用它。

路由的第二个参数是一个回调函数。你可以完全忽略使用控制器的想法，只需将回调定义为内联匿名函数；然而，随着你的路由增长，这个文件会变得越来越大，代码会开始变得混乱。将代码分解成尽可能多的小而可管理的模块总是一个很好的做法，以保持自己的理智！

前两个`router.get`路由是典型的路由，当访问者将他们的浏览器指向`yourdomain.com/routepath`时会被调用——浏览器默认发送`GET`请求到服务器。另外三个`router.post`路由被定义为处理浏览器向服务器发出的请求，通常通过 HTML 表单提交完成。

有了所有我们定义的路由，现在让我们创建匹配的控制器。在`controllers`文件夹中，创建`home.js`和`image.js`文件。`home.js`文件非常基本：

```js
module.exports = { 
    index(req, res){ 
        res.send('The home:index controller'); 
    } 
}; 
```

使用这个模块，我们实际上是在导出一个对象，该对象具有一个名为`index`的单个函数。`index`的`function`签名是使用 Express 的每个路由所需的签名。第一个参数是一个请求对象，第二个参数是一个响应对象。浏览器发送到服务器的请求的每个具体细节都可以通过请求对象获得。

此外，请求对象将使用之前声明的所有中间件进行修改。你将使用响应对象向客户端发送响应——这可能是一个渲染的 HTML 页面、静态资产、JSON 数据、错误，或者你确定的任何内容。目前，我们的控制器只是简单地响应一个简单的文本，这样你就可以看到它们都在工作。

让我们创建一个图像控制器，其中有更多的函数。编辑`/controllers/image.js`文件并插入以下代码：

```js
module.exports = { 
    index(req, res) { 
        res.send(`The image:index controller ${req.params.image_id}`); 
    }, 
    create(req, res) { 
        res.send('The image:create POST controller'); 
    }, 
    like (req, res) { 
        res.send('The image:like POST controller'); 
    }, 
    comment(req, res) { 
        res.send('The image:comment POST controller'); 
    } 
}; 
```

在这里，我们定义了`index`函数，就像我们在主控制器中所做的那样，只是我们还将显示`image_id`，这是在执行此控制器函数时在路由中设置的。`params`属性是通过`urlencoded`功能添加到`request`对象中的，这是 body parser 模块的一部分！

请注意，控制器目前不需要任何依赖项（文件顶部没有定义`require`声明）。随着我们实际完善控制器函数并开始执行诸如将记录插入我们的 MongoDB 数据库和使用其他第三方`npm`模块等操作，这将发生改变。

现在你的控制器已经创建并准备好使用，你只需要激活你的路由。为了做到这一点，我们将在我们的`configure.js`文件中插入最后一行代码，就在`return app;`行的上方：

```js
routes(app);  
```

不要忘记在文件顶部取消注释`routes = require('./routes')`这一行。我们在这里做的是使用我们定义的`routes`模块，并执行`initialize`函数，这将通过我们的`app`对象实际连接我们的路由。我们需要注释掉我们刚刚移动到`routes`中的冗余代码，它仍然存在于`server.js`中。

作为迄今为止你已经创建的每个文件的总结，这里列出了不间断的文件，这样你就可以查看完整的代码：

首先，我们需要用`server.js`启动

```js
const express = require('express'); 
const config = require('./server/configure'); 
let app = express(); 
app.set('port', process.env.PORT || 3300); 
app.set('Views', `${ __dirname }/Views`); 
app = config(app); 

//commenting out following snippet that is not required 
// app.get('/', function(req, res){ 
//    res.send('Hello World'); 
// }); 

const server = app.listen(app.get('port'), ()=>{ 
    console.log(`Server up: http://localhost:${ app.get('port')}`); 
}); 
```

接下来，我们将使用`server/configure.js`配置服务器：

```js
const path = require('path'), 
    routes = require('./routes'), 
    exphbs = require('express-handlebars'), 
    express = require('express'), 
    bodyParser = require('body-parser'), 
    cookieParser = require('cookie-parser'), 
    morgan = require('morgan'), 
    methodOverride = require('method-override'), 
    errorHandler = require('errorhandler'); 

module.exports = (app)=>{ 
  app.use(morgan('dev'));
  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({
  extended: true
}));
  app.use(methodOverride()); 
  app.use(cookieParser('some-secret-value-here')); 
  routes(app); 
  app.use('/public/', express.static(path.join(__dirname,  
          '../public'))); 

  if ('development' === app.get('env')) { 
    app.use(errorHandler()); 
  } 
  return app; 
}; 
```

然后，我们在`server/routes.js`中定义了我们的路由：

```js
const express = require('express'), 
    router = express.Router(), 
    home = require('../controllers/home'), 
    image = require('../controllers/image'); 
module.exports = (app)=>{ 
    router.get('/', home.index); 
    router.get('/images/:image_id', image.index); 
    router.post('/images', image.create); 
    router.post('/images/:image_id/like', image.like); 
    router.post('/images/:image_id/comment', image.comment); 
    app.use(router); 
}; 
```

最后，我们将使用`controllers/home.js`定义我们的控制器：

```js
module.exports = { 
    index(req, res) { 
        res.send('The home:index controller'); 
    } 
}; 
```

此外，我们还将使用`controllers/image.js`来定义我们的控制器：

```js
module.exports = { 
    index(req, res) { 
        res.send(`The image:index controller ${req.params.image_id}`); 
    }, 
    create(req, res) { 
        res.send('The image:create POST controller'); 
    }, 
    like (req, res) { 
        res.send('The image:like POST controller'); 
    }, 
    comment(req, res) { 
        res.send('The image:comment POST controller'); 
    } 
}; 
```

让我们最后一次启动服务器并检查是否一切正常。

执行`server.js`节点，并且这次将浏览器指向`http://localhost:3300`。现在，你应该在浏览器中看到一些响应。转到`http://localhost:3300/images/testing123`。你应该在屏幕上看到以下消息：

```js
 The image:index controller testing123 
```

# Handlebars 作为视图引擎

默认情况下，Express 可以愉快地呈现静态 HTML 文档并将其返回给客户端。但是，除非你正在构建一个纯静态的、内容驱动的网站，这是可疑的，否则你很可能希望动态地呈现你的 HTML。也就是说，你希望在页面被请求时动态生成 HTML 的部分，也许使用循环、条件语句、数据驱动的内容等等。为了呈现动态 HTML 页面，你需要使用一个渲染引擎。

这就是 Handlebars 的用武之地。这个渲染引擎得名是因为它用于显示数据的语法，即双大括号`{{`和`}}`。使用 Handlebars，你可以在你的 HTML 页面中有根据传递给它的数据在运行时确定的部分。考虑以下例子：

```js
<div> 
    <p>Hello there {{ name }}!  Todays date is {{ timestamp }}</p> 
</div> 
```

访问者浏览器上实际的 HTML 将是：

```js
<div> 
    <p>Hello there Jason!  Todays date is Sun Apr 13</p> 
</div> 
```

我们在`configure`模块中要处理的第一件事是将 Handlebars 注册为默认的视图渲染引擎。在`configure.js`文件中，在`return(app);`行的上方，你应该插入以下代码：

```js
app.engine('handlebars', exphbs.create({ 
    defaultLayout: 'main', 
    layoutsDir: `${app.get('Views')}/layouts`, 
    partialsDir: [`${app.get('Views') }/partials`] 
}).engine); 
app.set('View engine', 'handlebars'); 
```

首先，使用传入`configure`函数的 Express `app`对象，通过调用`app`的`engine`函数来定义我们选择的渲染引擎。`engine`函数的第一个参数是渲染引擎应该寻找的文件扩展名，即`handlebars`。

第二个参数通过调用`express-hbs`模块的`create`函数来构建引擎。这个`create`函数以一个`options`对象作为参数，这个`options`对象为我们的服务器定义了许多常量。最重要的是，我们将定义哪个布局是我们的默认布局，以及我们的布局将存储在哪里。如果您还记得，在`server.js`中，我们使用`app.set`来设置我们的`app`的`Views`属性，指向当前工作目录`+/Views`。当我们配置渲染引擎的选项时，就会使用这个设置。您会注意到`partialsDir`属性使用了一个数组（只有一个项）和一个`layoutsDir`的单个字符串值。这两种方法是可以互换的，我只是想演示您可以有多个部分目录，它可以只是一个字符串值的数组。

有了这个设置，我们的服务器现在知道，每当我们尝试呈现具有`handlebars`文件扩展名的 HTML 页面时，它将使用 Handlebars 引擎执行呈现。这意味着我们需要确保在我们的动态 HTML 页面中使用 Handlebars 特定的语法。

在下一章中，我们将学习更多关于 Handlebars 以及如何编写动态 HTML 页面的知识。

使用`.handlebars`作为文件扩展名纯粹是个人选择。有些人更喜欢`.hbs`，如果你愿意，你可以使用任何你喜欢的东西。只需确保`app.engine()`函数中的第一个参数和`app.set('View engine')`函数中的第二个参数是相同的。

要了解 Express.js 提供的许多模板引擎，请查看此链接[`github.com/expressjs/express/wiki#template-engines`](https://github.com/expressjs/express/wiki#template-engines)。

# 摘要

在本章中，我们学习了 Node 的 Express Web 框架，并使用 Express 编写了一个基本的 Web 服务器，这将成为我们在本书的其余部分中构建的图片上传网站的基础。

您编写的 Web 服务器处理特定路由的请求，使用控制器处理这些路由的逻辑，并支持典型 Web 服务器应具备的所有标准要求。

在下一章中，我们将介绍 Handlebars 模板引擎，以编写网站所需的每个动态 HTML 页面。此外，我们将更新图像和主页控制器，以包含必要的逻辑，以正确呈现这些 HTML 页面。
