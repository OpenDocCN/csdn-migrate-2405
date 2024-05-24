# Deno Web 开发（一）

> 原文：[`zh.annas-archive.org/md5/05CD4283AEDF57F3F0FCDC18A95F489E`](https://zh.annas-archive.org/md5/05CD4283AEDF57F3F0FCDC18A95F489E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

Deno 是一个具有安全默认设置和优秀开发者体验的 JavaScript/TypeScript 运行时。

《Deno Web Development》介绍了 Deno 的原生对象、其原则，以及开发者如何使用它们来构建真实世界的应用程序。本书分为三个主要部分：介绍 Deno，从头构建 API，以及测试和部署 Deno 应用程序。到了本书的最后，读者将能够熟练使用 Deno 来创建、维护和部署安全和可靠的 Web 应用程序。

# 本书适合谁阅读

本书面向所有级别的开发者，他们希望在自己的 JavaScript 和 TypeScript 技能中利用一个安全、简单和现代化的运行时，用于 Web 开发。

# 本书涵盖内容

第一章，《什么是 Deno？》，提供了关于 Node.js 的历史背景和导致 Deno 诞生的动机，展示了运行时架构和原则。

第二章，《工具链》，介绍了如何安装 Deno，并探索了包含在运行时二进制文件中的工具。

第三章，《运行时和标准库》，解释了如何使用 Deno 的运行时和标准库函数编写简单的脚本和应用程序。

第四章，《构建 Web 应用程序》，展示了如何使用标准库 HTTP 模块为 Web 应用程序设置基础。

第五章，《添加用户并迁移到 Oak》，讨论了使用流行的 HTTP 库 oak 来构建 REST API，并向应用程序添加持久性和用户。

第六章，《添加身份验证并连接数据库》，讨论了添加对身份验证的支持以及经过身份验证的端点，并连接到 MongoDB 数据库。

第七章，《HTTPS，提取配置和 Deno 在浏览器中》，讨论了启用 HTTPS，基于文件和环境处理配置，以及在浏览器中使用 Deno 代码。

第八章，《测试 – 单元和集成》，涵盖了为前面章节中编写的模块编写和运行单元和集成测试。

第九章，《部署 Deno 应用程序》，介绍了配置容器环境以及自动化部署 Deno 应用程序，使其在云环境中运行。

第十章，《接下来是什么？》，概述了我们在本书中学到的内容，介绍了 Deno 的路线图，解释了如何将模块发布到 Deno 的官方注册表，并带你了解 Deno 的未来和社区。

# 为了最大化本书的收益

本书中的所有代码示例都是在 macOS 上的 Deno 1.7.5 上测试的，但它们应该在 Deno 的未来版本中工作。在本书的过程中还使用了几个第三方包。使用它们的示例也适用于软件的新版本。

本书将为所有使用的软件提供安装说明。

![](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/deno-web-dev/img/01.jpg)

本书的代码是使用 VS Code（[`code.visualstudio.com/`](https://code.visualstudio.com/)）编写的，以便在使用官方 Deno 扩展时获得最佳体验。这不是一个要求，任何代码编辑器都可以跟随本书。

**如果您使用本书的数字版本，我们建议您亲自输入代码或通过 GitHub 存储库访问代码（下一节中有链接）。这样做可以帮助您避免与复制和粘贴代码相关的潜在错误。**

您应该熟悉使用 JavaScript 并具有 TypeScript 的基本知识。不需要 Node.js 知识，但可能会有所帮助。

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)您的账户上下载本书的示例代码文件。如果您在其他地方购买了此书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便将文件直接发送给您。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packt.com](http://www.packt.com)。

1.  选择**支持**标签。

1.  点击**代码下载**。

1.  在**搜索**框中输入书籍名称，并按照屏幕上的指示操作。

下载文件后，请确保使用最新版本解压缩或提取文件夹：

+   对于 Windows，请使用 WinRAR/7-Zip

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

本书的代码包也托管在 GitHub 上，地址为[`github.com/PacktPublishing/Deno-Web-Development`](https://github.com/PacktPublishing/Deno-Web-Development)。如果代码有更新，它将在现有的 GitHub 存储库上进行更新。

我们还有其他来自我们丰富的书籍和视频目录的代码包，地址为[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)。查看它们！

# 使用的约定

本书中使用了多种文本约定。

`文本中的代码`：表示文本中的代码单词，数据库表名，文件夹名，文件名，文件扩展名，路径名，假 URL，用户输入和 Twitter 处理程序。例如："在`deps.ts`文件中添加`oak-middleware-jwt`并导出`jwtMiddleware`函数。"

代码块如下所示设置：

```js
const apiRouter = new Router({ prefix: "/api" })
apiRouter.use(async (_, next) => {
  console.log("Request was made to API Router");
  await next();
}))
…
app.use(apiRouter.routes());
app.use(apiRouter.allowedMethods());
```

当我们希望引起您对代码块中的特定部分的关注时，相关的行或项目将被加粗：

```js
const app = new Application();
app.use(async (ctx, next) => {
  const start = Date.now();
  await next();
  const ms = Date.now() - start;
  ctx.response.headers.set("X-Response-Time", `${ms}ms`);
});
…
app.use(apiRouter.routes());
app.use(apiRouter.allowedMethods());
```

以下写出命令行输入或输出：

```js
$ deno --version 
deno 1.7.5 (release, x86_64-apple-darwin) 
v8 9.0.123 
typescript 4.1.4
```

**粗体**：表示新术语、重要词汇或您在屏幕上看到的词汇。例如，菜单或对话框中的词汇在文本中会以这种方式出现。这是一个示例：“如果您使用过 MongoDB，您可以在 Atlas 界面上通过访问**集合**菜单来查看您创建的用户。”

提示或重要注释

像这样出现。

# 联系我们

读者反馈总是受欢迎的。

**一般反馈**：如果您对本书的任何方面有疑问，请在消息的主题中提及书名，并通过 customercare@packtpub.com 向我们发送电子邮件。

**勘误**：尽管我们已经竭尽全力确保内容的准确性，但错误仍然可能发生。如果您在这本书中发现了错误，我们将非常感激如果您能向我们报告。请访问[www.packtpub.com/support/errata](http://www.packtpub.com/support/errata)，选择您的书籍，点击“勘误表提交表单”链接，并输入详细信息。

**盗版**：如果您在互联网上以任何形式遇到我们作品的非法副本，我们将非常感激如果您能提供位置地址或网站名称。请通过 copyright@packt.com 与我们联系，并提供材料的链接。

**如果您有兴趣成为作者**：如果您在某个主题上有专业知识，并且您有兴趣撰写或贡献一本书，请访问[authors.packtpub.com](http://authors.packtpub.com)。

# 评论

请留下评论。一旦您阅读并使用了这本书，为什么不在这本书购买的网站上留下评论呢？潜在的读者可以看到并使用您公正的意见来做出购买决策，我们 Packt 可以了解您对我们产品的看法，我们的作者可以看到您对他们书籍的反馈。谢谢！

关于 Packt 的更多信息，请访问[packt.com](http://packt.com)。


# 第一部分：熟悉 Deno

在本节中，你将了解 Deno 是什么，它为何被创建，以及它是如何被创建的。本节将帮助你设置环境并熟悉生态系统的相关工具。

本部分包含以下章节：

+   第一章，[Deno 是什么？](https://epic.packtpub.com/index.php?module=oss_Chapters&action=DetailView&record=9acbdeda-16ff-b77c-78da-5f32428f1e3c)

+   第二章，[工具链](https://epic.packtpub.com/index.php?module=oss_Chapters&action=DetailView&record=28007db8-c7cd-f7e7-f001-5f32420421d8)

+   第三章，[运行时](https://epic.packtpub.com/index.php?module=oss_Chapters&action=DetailView&record=543934d7-4ca4-7b9f-4311-5f32428a2967)与标准库


# 第一章：Deno 是什么？

Deno 是一个安全的 JavaScript 和 TypeScript 运行时。我猜你可能对这个实验新工具感到兴奋。你已经使用过 JavaScript 或 TypeScript，至少听说过 Node.js。Deno 对你来说将感觉 novelty 正好合适，同时对于在生态系统中工作的人来说，有些东西听起来会很熟悉。

在我们开始动手之前，我们将了解 Deno 是如何创建的以及它的动机。这样做将帮助我们更好地学习和理解它。

在这本书中，我们将重点关注实际示例。我们将编写代码，然后解释我们做出的一些决策背后的原因。如果你来自 Node.js 背景，有些概念可能对你来说很熟悉。我们还将解释 Deno 并与它的祖先 Node.js 进行比较。

一旦基础知识确立，我们将深入研究 Deno，并通过构建小型工具和实际应用程序来探索其运行时功能。

没有 Node，就没有 Deno。要深入了解后者，我们不能忽视它的 10 多年的祖先，这就是我们将在本章中要探讨的。我们将解释它在 2009 年创建的原因以及在使用十年后检测到的痛点。

之后，我们将介绍 Deno 及其解决的基本差异和挑战。我们将查看其架构、一些运行时的原则和影响以及它擅长的用例。

在了解 Deno 是如何诞生的之后，我们将探讨它的生态系统、标准库以及 Deno 可以发挥重要作用的一些用例。

阅读完这一章后，您将了解 Deno 是什么，它不是什么，为什么它不是 Node.js 的下一个版本，以及当您考虑将 Deno 用于下一个项目时应该考虑什么。

在本章中，我们将涵盖以下主题：

+   一点历史

+   为什么是 Deno？

+   支持 Deno 的架构和技术

+   掌握 Deno 的限制

+   探索 Deno 的使用案例

让我们开始吧！

# 一点历史

Deno 的第一个稳定版本，v1.0.0，于 2020 年 5 月 13 日发布。

瑞安·达尔（Ryan Dahl）--Node.js 的创建者--第一次提到它是在他著名的演讲《关于 node.js 我后悔的 10 件事》中（[`youtu.be/M3BM9TB-8yA`](https://youtu.be/M3BM9TB-8yA)）。除了它展示了 Deno 的第一个非常原始版本之外，这个演讲也是值得一看的，因为它是一堂关于软件如何衰老的课。它很好地反映了决策是如何随着时间演变，即使它们是由开源社区中最聪明的人做出的，并且最终可能会走向与最初计划不同的方向。

在 2020 年 5 月发布后，由于其历史背景、核心团队以及吸引 JavaScript 社区的事实，Deno 受到了很多关注。这可能是你听说的其中一种方式，无论是通过博客文章、推文还是会议演讲。

这种热情对其运行时产生了积极影响，许多人想要贡献和使用它。由于其 Discord 频道（[`discord.gg/deno`](https://discord.gg/deno)）和 Deno 存储库的拉取请求数量（[`github.com/denoland`](https://github.com/denoland)），社区正在增长。目前，它以每月一个次要版本的速度发展，交付了大量修复和改进。路线图展示了一个未来，这同样令人兴奋。凭借明确定义的路径和原则，Deno 拥有发展成为越来越重要角色的所有条件。

让我们回溯一点，回到 2009 年 Node.js 的创建。

当时，Ryan 开始质疑大多数后端语言和框架是如何处理 I/O（输入/输出）的。大多数工具将 I/O 视为一个同步操作，阻塞进程直到完成，然后继续执行代码。

从根本上说，正是这种同步阻塞操作引起了 Ryan 的质疑。

## 处理 I/O

当你编写必须处理每秒数千个请求的服务器时，资源消耗和速度是两个重要的因素。

对于这样的资源关键项目，重要的是基本工具——原语——具有考虑这一点的架构。当扩展时间到来时，最初做出的基本决策支持这一点是有帮助的。

Web 服务器就是这种情况之一。Web 是当今世界的一个重要平台。它从未停止增长，每天都有更多设备和新技术上网，使更多人可以访问它。Web 是世界各地人民的共同、民主、去中心化的基础。有了这个目标，这些应用程序和网站背后的服务器需要处理巨大的负载。像 Twitter、Facebook 和 Reddit 这样的 Web 应用程序以及其他许多应用程序，每分钟处理数千个请求。因此，扩展是必不可少的。

为了激发关于性能和资源效率的讨论，让我们来看看以下图表，该图表比较了最常用的两个开源 Web 服务器：Apache 和 Nginx：

![图 1.1 – 每秒请求数与并发连接数 – Nginx 对 Apache](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/deno-web-dev/img/Figure_1.1_B16380.jpg)

图 1.1 – 每秒请求数与并发连接数 – Nginx 对 Apache

乍一看，这告诉我们 Nginx 几乎每次都能名列前茅。我们还可以理解，随着并发连接数目的增加，Apache 每秒请求数会下降。相比之下，Nginx 每秒请求数保持相对稳定，尽管随着连接数目的增加，每秒请求数也显示出预期的下降。达到一千个并发连接后，Nginx 的每秒请求数几乎达到 Apache 的两倍。

让我们看看 RAM 内存消耗的比较：

![图 1.2 – 内存消耗与并发连接数——Nginx 与 Apache 的对比](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/deno-web-dev/img/Figure_1.2_B16380.jpg)

图 1.2 – 内存消耗与并发连接数——Nginx 与 Apache 的对比

Apache 的内存消耗随着并发连接数的*线性*增长，而 Nginx 的内存占用是恒定的。

你可能已经在好奇这是为什么。

之所以这样，是因为 Apache 和 Nginx 在处理并发连接的方式上有很大的不同。Apache 每个请求都会创建一个新的线程，而 Nginx 则使用事件循环。

在*每个请求一个线程*架构中，每当有一个新请求进来时，它就会创建一个线程。那个线程负责处理请求直到完成。如果另一个请求在之前的请求还在处理时到来，将会创建一个新的线程。

此外，在多线程环境中处理网络编程并不被认为是特别容易的事情。你可能会遇到文件和资源锁定、线程通信问题以及常见的死锁等问题。对于开发者来说，已经够棘手了，使用线程也不是免费的，因为线程本身就有资源开销。

相比之下，在事件循环架构中，一切都在单个线程上发生。这个决定极大地简化了开发人员的生活。你不需要考虑前面提到的因素，这意味着你可以有更多的时间来处理用户的问题。

通过使用这种模式，Web 服务器只需将事件发送到事件循环。它是一个异步队列，当有可用资源时执行操作，在操作完成后异步返回代码。为了让这工作，所有操作都需要是非阻塞的，意味着它们不应该等待完成，只是发送一个事件并稍后等待响应。

### 阻塞与非阻塞

以读取文件为例。在一个阻塞环境中，你会读取文件，并让进程等待它完成直到执行下一行代码。当操作系统读取文件内容时，程序处于空闲状态，浪费了宝贵的 CPU 周期：

```js
const result = readFile('./README.md');
// Use result
```

程序会等待文件被读取，然后继续执行代码。

使用事件循环执行相同操作的是触发“读取文件”事件并执行其他任务（例如，处理其他请求）。当文件读取操作完成后，事件循环将调用回调函数并返回结果。这次，运行时在操作系统检索文件内容时处理其他请求，更好地利用资源：

```js
const result = readFileAsync('./README.md', function(result) {
  // Use result
});
```

在这个例子中，任务被分配了一个回调。当任务完成（这可能需要几秒或几毫秒）时，它会调用回调函数并返回结果。当这个函数被调用时，里面的代码是线性运行的。

### 为什么事件循环没有被更广泛地使用呢？

既然我们已经理解了事件循环的优势，这是一个非常合理的疑问。尽管在 Python 和 Ruby 中有一些实现，事件循环没有被更广泛地使用的原因之一是，它们需要所有基础架构和代码都是非阻塞的。非阻塞意味着不要同步执行代码。它意味着触发事件，并在稍后的某个时间点处理结果。

除此之外，许多常用的语言和库并不提供异步 API。许多语言中没有回调，像 C 这样的编程语言中也不存在匿名函数。当今软件的至关重要部分，例如 `libmysqlclient`，即使其内部部分可能使用异步任务执行，也不支持异步操作。异步 DNS 解析也是许多系统并非标准的另一个例子。作为另一个例子，你可能认为操作系统的手动页面就是如此。其中大多数甚至不提供了解特定函数是否执行 I/O 的方法。这些都是当今许多基础软件组件中不存在异步 I/O 能力的证据。

甚至提供这些功能的现有工具也要求开发者对异步 I/O 模式有深入的了解才能使用事件循环。像 `libmysqlclient` 示例中那样绕过技术限制来让某物工作是一项艰巨的任务。

### JavaScript 前来救援

JavaScript 是由布兰登·艾 ich（Brendan Eich）在 1995 年为网景工作时创建的。起初它只在浏览器中运行，并允许开发者在网页中添加交互式功能。它由一些揭示为非常适合事件循环的元素组成：

+   它有匿名函数和闭包。

+   它一次只执行一个回调。

+   I/O 通过回调（例如，`addEventListener`）在 DOM 上进行。

结合了语言这三个基本方面使得事件循环对于任何习惯了在浏览器中使用 JavaScript 的人来说都是自然而然的事情。

语言特性最终使得其开发者倾向于事件驱动编程。

## Node.js 登上舞台

在所有关于 I/O 以及应该如何处理它的思考和问题之后，瑞恩·达尔（Ryan Dahl）在 2009 年提出了 Node.js。它是一个基于谷歌 V8 的 JavaScript 运行时 - 一个将 JavaScript 带到服务器的 JavaScript 引擎。

Node.js 设计上是异步和单线程的。它有一个事件循环作为其核心，并以一种可扩展的方式呈现，用于开发可以处理成千上万个并发请求的后端应用程序。

事件循环为我们提供了一种干净的方式来处理并发问题，在这方面 Node.js 与 PHP 或 Ruby 等工具不同，后者使用每个请求一个线程的模型。这个单线程环境让 Node.js 用户可以不必关心线程安全问题。它非常成功地抽象了事件循环以及所有同步工具的问题，用户几乎不需要了解事件循环本身。Node.js 通过利用回调和最近承诺（promises）的运用实现了这一点。

Node.js 将自己定位为为用户提供一个低级别的、纯粹的事件驱动的、非阻塞的基础设施，让他们编程自己的应用程序。

### Node.js 的崛起

告诉公司和开发者们他们可以利用已有的 JavaScript 知识迅速地编写服务器，这导致了 Node.js 的流行度上升。

自从它被发布并开始被不同规模的公司在生产环境中使用以来，这种语言很快地发展进化。

在 2011 年 Node.js 创建后的仅仅两年，Uber 和 LinkedIn 就已经在服务器上运行 JavaScript 了。2012 年，Ryan Dahl 辞去了 Node.js 社区的日常运营工作，以便致力于研究和其它项目。

据估计，到 2017 年，运行 Node.js 的实例超过 880 万个（来源：[`blog.risingstack.com/history-of-node-js/`](https://blog.risingstack.com/history-of-node-js/)）。今天，从**Node 包管理器**（**npm**）下载的包已经超过 1030 亿个，发布的包大约有 146 万 7527 个。

Node.js 是一个很好的平台，这一点毫无疑问。基本上任何使用过它的人都会体验到它的许多优点。流行度和社区在其中扮演了重要的角色。有很多不同经验水平和背景的人一起协作开发某项技术，这只能推动它向前发展。这就是 Node.js 所发生的，并且仍然在发生的事情。

Node.js 让开发者们可以用 JavaScript 去实现很多之前不可能的用途。这从机器人技术，到加密货币，到代码打包器，API 等等都有涉及。它是一个稳定的环境，让开发者们感到高效且速度快。它将继续它的使命，在未来很多年里支持不同规模的公司和企业。

但既然你买了这本书，那说明你相信 Deno 有一些值得探索的东西，我可以保证它确实如此。

你可能会想，既然之前的解决方案已经足够令人满意，为什么还要提出一个新的解决方案呢？我们接下来就会发现答案。

# 为什么是 Deno？

自从 Node.js 创建以来，许多事情已经改变。十多年过去了，JavaScript 也发生了变化，软件基础设施社区也是如此。像 Rust 和 golang 这样的语言诞生了，它们在软件社区中是非常重要的发展。这些语言使得生产本地机器代码变得容易，同时为开发者提供一个严格和可靠的环境。

然而，这种严格性是以生产率为代价的。并不是说开发者写这些语言时不觉得生产率低，因为他们确实觉得有生产力，但你可以很容易地争论，生产率是动态语言明显占优势的领域。

动态语言的开发便捷和速度使它们在脚本和原型设计方面成为非常强劲的竞争者。而当考虑到动态语言时，JavaScript 立刻浮现在脑海中。

JavaScript 是最常用的动态语言，它可以在任何装有网络浏览器的设备上运行。由于它的广泛使用和庞大的社区，人们对它进行了许多优化工作。诸如 ECMA International 等组织的创建确保了该语言稳定而谨慎地发展。

正如我们在上一节所看到的，Node.js 在将 JavaScript 带到服务器上扮演了非常成功的角色，为大量不同的用例打开了大门。它目前用于许多不同的任务，包括网络开发工具、创建网络服务器和脚本，等等。在其创建之初，为了启用这些用例，Node.js 必须为 JavaScript 发明之前不存在概念。后来，这些概念由标准化组织讨论，并以不同的方式添加到语言中，使得 Node.js 的部分内容与其母语言 ECMAScript 不兼容。十年过去了，ECMAScript 也发生了变化，围绕它的生态系统也是如此。

**CommonJS**模块不再是标准；JavaScript 现在有 ES 模块。**TypedArrays**现在已经存在，最终，JavaScript 可以直接处理二进制数据。Promises 和 async/await 是处理异步操作的首选方法。

这些功能在 Node.js 上是可用的，但它们必须与 2009 年创建的非标准功能共存，这些功能仍然需要维护。这些功能以及 Node.js 的大量用户使得系统的发展变得困难且缓慢。

为了解决这些问题，并跟上 JavaScript 语言的发展，许多社区项目被创建出来。这些项目使我们能够使用该语言的最新特性，但在许多 Node.js 项目中加入了诸如构建系统的东西，使得它们变得非常复杂。引用 Dahl 的话，“*夺走了动态语言脚本的美好*。”

超过 10 年的广泛使用也清楚地表明，运行时的一些基本构建设需要改进。缺乏安全沙箱是主要问题之一。在创建 Node.js 的时候，JavaScript 可以通过在 V8（它背后的 JavaScript 引擎）中创建绑定来访问“外部世界”。尽管这些绑定使 JavaScript 能够实现诸如从文件系统读取、访问网络等 I/O 功能，但它们也打破了 JavaScript 沙箱的目的。这个决定使得让开发者控制 Node.js 脚本可以访问的内容变得非常困难。例如，在当前状态下，没有办法阻止 Node.js 脚本中的第三方包读取用户可以访问的所有文件，以及其他恶意行为。

十年后，Ryan Dahl 和 Deno 背后的团队怀念一个既有趣又高效的脚本环境，可以用于执行各种任务。团队还觉得 JavaScript 景观已经发生了足够大的变化，简化是有价值的，因此他们决定创建 Deno。

## 介绍 Deno

"Deno 是一个简单、现代且安全的 JavaScript 和 TypeScript 运行时，它使用了 V8 引擎，并内置了 Rust 构建。" – [`deno.land/`](https://deno.land/)

Deno 的名称是通过反转其前身 no-de 的音节而构成的，即 de-no。从它的前身那里学到了很多教训，Deno 提出了以下主要特性：

+   默认情况下是安全的

+   一等 TypeScript 支持

+   单一的可执行文件

+   提供编写应用程序的基本工具

+   完整且经过审计的标准库

+   与 ECMAScript 和浏览器环境的兼容性

默认情况下，Deno 是安全的，并且是按照设计来创建的。它最终利用了 V8 沙箱，并提供了一个严格的权限模型，使开发者能够精确控制代码可以访问的内容。

TypeScript 也得到了一等支持，这意味着开发者可以选择不进行任何额外配置就使用 TypeScript。Deno 的所有 API 也都是用 TypeScript 编写的，因此具有正确和精确的类型和文档。标准库也是如此。

Deno 带有一个单一的可执行文件，其中包含了编写应用程序所需的所有基本工具；它总是这样。团队努力保持可执行文件的小巧（约 15 MB），以便我们可以在各种情况和环境中使用它，从简单的脚本到完整的应用程序。

不仅仅是执行代码，Deno 二进制文件提供了一整套开发者工具，具体包括一个代码检查器、一个格式化工具和一个测试运行器。

Go 语言精心打磨的标准库激发了 Deno 标准库的灵感。与 Node.js 的标准库相比，Deno 的标准库故意设计得更大、更完整。这个决定是为了应对一些 Node.js 项目中曾经出现的庞大的依赖树。Deno 的核心团队认为，通过提供一个稳定且完整的标准库，可以帮助解决这个问题。通过移除创建第三方包来处理常见用例的需求，该平台默认提供了这些功能，从而旨在减少使用大量第三方包的必要性。

为了与 ES6 和浏览器保持兼容，Deno 努力模仿浏览器 API。执行 HTTP 请求、处理 URL 或编码文本等工作，可以通过使用你在浏览器中会使用的相同 API 来完成。Deno 团队故意努力保持这些 API 与浏览器同步。

旨在提供三者的最佳特性，Deno 提供了 JavaScript 的原型能力和开发者体验，TypeScript 的类型安全和安全性，以及 Rust 的性能和简洁性。

理想情况下，正如 Dahl 在他的一次谈话中提到的，代码应该遵循从原型到生产的以下流程：开发者可以开始写 JavaScript，迁移到 TypeScript，最终得到 Rust 代码。

在撰写本文时，只能运行 JavaScript 和 TypeScript。Rust 只能通过一个（仍然不稳定的）插件 API 来使用，这可能在不太遥远的将来可能会变得稳定。

## 命令行脚本的网络浏览器。

随着时间的推移，Node.js 模块系统演变成现在过于复杂且维护痛苦的东西。它考虑了诸如导入文件夹、搜索依赖项、导入相对文件、搜索 index.js、第三方包和读取`package.json`文件等边缘情况。

它也与**npm**（**Node 包管理器**）紧密耦合，后者最初是 Node.js 的一部分，但在 2014 年分离出来。

拥有一个集中式的包管理器并不非常符合网络化，借用 Dahl 的话来说。数百万应用程序依赖于一个单一的注册表来生存，这是一个负担。

Deno 通过使用 URL 来解决这个问题。它采取了一种与浏览器非常相似的方法，只需要一个到文件的绝对 URL 就可以执行或导入代码。这个绝对 URL 可以是本地、远程或基于 HTTP 的，并包括以下文件扩展名：

```js
import { serve } from 'https://deno.land/std@0.83.0/http/server.ts'
```

前面的代码碰巧就是你在浏览器中在`<script>`标签内想要引入 ES 模块时会写的相同代码。

关于安装和离线使用，Deno 通过使用本地缓存确保用户不必为此担心。当程序运行时，它会安装所有必需的依赖项，从而消除了安装步骤。我们稍后会在第二章更深入地探讨这一点，*工具链*。

现在我们已经熟悉了 Deno 是什么以及它解决的问题，我们就可以深入了解。通过了解幕后发生的事情，我们可以更好地理解 Deno 本身。

在下一节中，我们将探讨支持 Deno 的技术以及它们是如何连接的。

# 支持 Deno 的架构和技术

从架构上讲，Deno 考虑了诸如安全等各种主题，如与底层操作系统通信的干净且高效的通信方式，而不会泄露细节给 JavaScript 端。为了实现这一点，Deno 使用消息传递从 V8 内部与 Deno 后端通信。后端是用 Rust 编写的组件，与事件循环交互，进而与操作系统交互。

Deno 是由四项技术实现的：

+   V8

+   TypeScript

+   Tokio (事件循环)

+   Rust

正是这四个部分的结合，使得它能够在保证代码安全和沙盒化的同时，为开发者提供出色的体验和开发速度。如果你不熟悉这些技术，我会留下一个简短的定义：

**V8** 是谷歌开发的 JavaScript 引擎。它用 C++编写，可以在所有主流操作系统上运行。它还是 Chrome、Node.js 等浏览器的引擎。

**TypeScript** 是微软开发的一种超集 JavaScript，它为语言添加了可选的静态类型，并*编译*成 JavaScript。

**Tokio** 是为 Rust 提供编写任何规模网络应用程序的异步运行时。

**Rust** 是 Mozilla 设计的专注于性能和安全的服务器端语言。

使用快速发展语言 Rust 编写 Deno 的核心，使其比 Node.js 更受开发者欢迎。Node.js 的核心是用 C++编写的，这并不以特别容易处理著称。由于许多陷阱和不太好的开发者体验，C++在 Node.js 核心的发展中显示出是一个小障碍。

`Deno_core`作为 Rust crate（包）分发。Rust 与 Rust 之间的这种联系并非巧合。Rust 提供了许多功能，使与 JavaScript 的连接变得容易，并增加了 Deno 本身的 capabilities. Asynchronous operations in Rust typically use Futures that map very well with JavaScript Promises. Rust is also an embeddable language, and that provides direct embedding capabilities to Deno. This added to Rust being one of the first languages to create a compiler for *WebAssembly*, made the Deno team choose it for its core.

## 来自 POSIX 系统的灵感

POSIX 系统对 Deno 有很大的启发。在他的一次演讲中，Dahl 甚至提到 Deno 处理某些任务*“就像一个操作系统”*。

下面的表格显示了来自 POSIX/Linux 系统的标准术语以及它们如何映射到 Deno 概念：

![](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/deno-web-dev/img/Table_1.1_B16380.jpg)

一些来自 Linux 世界的概念你可能很熟悉。比如说进程。它们代表了一个正在运行的程序的实例，该程序可能使用一个或多个线程执行。Deno 使用 WebWorker 在运行时完成同样的任务。

在第二行，我们有系统调用。如果你不熟悉它们，它们是程序向内核发出请求的方式。在 Deno 中，这些请求并不直接发送到内核；相反，它们从 Rust 核心发送到底层操作系统，但它们的工作方式相似。我们接下来有机会在即将到来的架构图中看到这一点。

这些都是如果你熟悉 Linux/POSIX 系统你可能认出的几个例子。

我们将在本书的剩余部分解释和使用上述大部分 Deno 概念。

## 架构

Deno 的核心最初是用 *golang* 编写的，但后来改用 Rust。这个决定是为了摆脱 *golang*，因为它是一个垃圾收集语言。它与 V8 的垃圾收集器的组合可能会导致未来的问题。

为了了解底层技术如何相互作用形成 Deno 核心，让我们看一下以下架构图：

![图 1.3 – Deno 架构](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/deno-web-dev/img/Figure_1.3_B16380.jpg)

图 1.3 – Deno 架构

Deno 使用消息传递与 Rust 后端进行通信。作为一个关于权限隔离的决策，Deno 从不向 Rust 暴露 JavaScript 对象句柄。V8 内部和外部的所有通信都使用 `Uint8Array` 实例。

对于事件循环，Deno 使用 Tokio，一个 Rust 线程池。Tokio 负责处理 I/O 工作和回调 Rust 后端，使其能够异步处理所有操作。**操作**（**ops**）是 Rust 和事件循环之间来回传递的消息的名称。

所有从 Deno 代码发送到其核心（用 Rust 编写）的异步消息都会返回**承诺**给 Deno。更准确地说，Rust 中的异步操作通常返回**未来**，Deno 将它们映射到 JavaScript 承诺。每当这些**未来**被解决，JavaScript 的**承诺**也同样被解决。

为了使 V8 能够向 Rust 后端发送消息，Deno 使用 `rusty_v8`，这是由 Deno 团队创建的 Rust 库，它提供了 V8 到 Rust 的绑定。

Deno 还将在 V8 内部包含 TypeScript 编译器。它使用 V8 快照进行启动时间优化。快照用于在特定的执行时间保存 JavaScript 堆，并在需要时恢复它。

自从它首次提出以来，Deno 一直受到迭代、进化过程的制约。如果你好奇它变化了多少，你可以查看 2018 年由 Ryan Dahl 写的最初路线图文档([`github.com/ry/deno/blob/a836c493f30323e7b40e988140ed2603f0e3d10f/Roadmap.md`](https://github.com/ry/deno/blob/a836c493f30323e7b40e988140ed2603f0e3d10f/Roadmap.md))。

现在，我们不仅知道 Deno 是什么，也知道它背后的幕后工作。这些知识将帮助我们在将来运行和调试我们的应用程序。Deno 的创造者做出了许多技术和架构决策，将 Deno 带到今天这个状态。这些决策推动了运行时的进步，并确保 Deno 在几种情况下都能表现出色，其中一些我们稍后会探讨。然而，为了使其在某些用例中表现良好，必须做出一些权衡。这些权衡导致了我们接下来要探讨的限制。

# 掌握 Deno 的限制

正如所有事情一样，选择解决方案是处理权衡的问题。那些最适合我们正在编写的项目和应用程序的解决方案是我们最终会使用的。目前，Deno 有一些限制；有些是由于它短暂的寿命，其他则是因为设计决策。像大多数解决方案一样，Deno 也不是一个万能的工具。在接下来的几页中，我们将探讨 Deno 当前的一些限制以及背后的动机。

## 不如 Node.js 稳定

在当前状态下，Deno 在稳定性方面无法与 Node.js 相提并论，这是显而易见的原因。Node.js 有超过 10 年的发展，而 Deno 只剩下接近两年的寿命。

尽管本书中介绍的大部分核心功能已经被认为是稳定且版本正确的，但仍然有一些功能可能会发生变化，并且标有不稳定标志。

Node.js 多年的经验确保了它经过了实战考验，并且可以在最多样化的环境中工作。这是我们希望 Deno 能够获得的，但时间和采用是关键因素。

## 更好的 HTTP 延迟，但吞吐量更差

Deno 从一开始就保持性能。然而，如基准页面所示（[`deno.land/benchmarks`](https://deno.land/benchmarks)），在某些主题上，它仍然不是 Node.js 的水平。

它的祖先利用了直接与 C++绑定在 HTTP 服务器上，从而提高这个性能分数。由于 Deno 抵制添加本地的 HTTP 绑定并在本地的 TCP 套接字之上构建，它仍然承受着性能上的惩罚。这个决定是团队计划在优化 TCP 套接字通信之后解决的问题。

Deno HTTP 服务器每秒处理大约 25k 个请求，最大延迟为 1.3 毫秒，而 Node.js 处理 34k 个请求，但延迟在 2 到 300 毫秒之间变化。

我们无法说每秒 25k 请求不够，尤其是当我们使用 JavaScript 时。如果你的应用/网站需要的请求量超过这个数字，那么 JavaScript，以及因此 Deno，可能不是这个工作的正确工具。

## 与 Node.js 的兼容性

由于许多已经引入的更改，Deno 不提供与现有 JavaScript 包和工具的兼容性。一个兼容层正在标准库上创建，但它仍然远远没有完成。

由于 Node.js 和 Deno 是两个非常相似的系统，有着共同的目标，我们预计随着时间的推移，Deno 将能够默认执行越来越多的 Node.js 程序。然而，尽管目前有些 Node.js 代码是可以运行的，但目前并非如此。

## TypeScript 编译器速度

如我们之前提到的，Deno 使用 TypeScript 编译器。它作为运行时最慢的部分表现出来，尤其是与 V8 解释 JavaScript 的时间相比。快照在这方面有所帮助，但这还不够。Deno 的核心团队认为他们可能需要将 TypeScript 编译器迁移到 Rust 来解决这个问题。

由于完成这项任务需要做大量的工作，这可能不会很快实现，尽管这应该是使其启动时间快得多的事情之一。

## 缺乏插件/扩展

尽管 Deno 有一个插件系统来支持自定义操作，但它还没有完成，被认为是不稳定的。这意味着将本地功能扩展到比 Deno 提供的更多是几乎不可能的。

到目前为止，我们应该理解 Deno 目前的限制以及这些限制存在的原因。其中一些可能随着 Deno 的成熟和演变而很快得到解决。其他的则是设计决策或路线图优先级的结果。理解这些限制在决定是否在项目中使用 Deno 时至关重要。在下一节中，我们将看看我们认为 Deno 非常适合的用例。

# 探索用例

正如您可能已经意识到的，Deno 本身与 Node.js 有许多共同的用例。大多数所做的更改都是为了确保运行时更安全、更简单，但随着它利用了大多数相同的技术，拥有相同的引擎，以及许多相同的目标，用例之间的差异不会太大。

然而，尽管差异并不大，可能存在一些微小的细微差别，这使得在特定情况下其中一个比另一个稍微更适合。在本节中，我们将探讨一些 Deno 的用例。

## 灵活的脚本语言

脚本编程是那些解释型语言总是闪耀光芒的功能之一。当我们想要快速原型化某件事时，JavaScript 是完美的。这可以包括重命名文件、迁移数据、从 API 中消费内容等等。它似乎是这些用例的正确工具。

Deno 对脚本编程给予了深思熟虑。运行时本身让用户用它来写脚本变得非常容易，从而在这方面的使用场景中提供了许多好处，特别是与 Node.js 相比。这些好处包括仅用一个 URL 就能执行代码，无需管理依赖项，以及基于 Deno 创建可执行文件的能力。

在此之上，你现在可以导入远程代码，同时控制它使用的权限，这在信任和安全方面是一个重大的步骤。

Deno 的**读取-评估-打印循环** (**REPL**) 是进行实验工作的好地方。在我们之前提到的基础上，二进制文件的小巧以及它包含所有所需工具的事实是蛋糕上的樱桃。

## 更安全的桌面应用程序

尽管插件系统还不稳定，允许开发者创建桌面应用程序的包很大程度上依赖于它，但它非常有前景。

在过去的几年里，我们见证了桌面网络应用程序的兴起。Electron 框架的兴起（[`www.electronjs.org/`](https://www.electronjs.org/)）使可以创建像 VS Code 或 Slack 这样的应用程序。这些是运行在 WebView 中的网页，可以访问本地功能，是许多人日常生活的一部分。

然而，对于用户来说安装这些应用程序，他们必须盲目地信任它们。之前，我们讨论了安全性以及 JavaScript 代码曾经可以访问它运行的所有系统。Deno 在这里从根本上不同，因为由于其沙盒和所有的安全特性，这要安全得多，并且解锁的潜力巨大。

在本书中，我们将探讨如何使用 JavaScript 在 Deno 中构建桌面应用程序的大量进展。

## 编写工具的快速而完整的环境

Deno 的功能使它成为一个非常完整、简单且快速的编写工具的环境。当我们说工具时，这不仅仅是针对 JavaScript 或 TypeScript 项目的工具。由于单一的二进制文件包含了开发应用程序所需的所有内容，我们可以将 Deno 用于 JavaScript 世界之外的生态系统。

它的清晰性、通过 TypeScript 自动生成文档、易于运行以及 JavaScript 的普及性，使 Deno 成为编写工具（如代码生成器、自动化脚本或其他开发工具）的正确组合。

## 在嵌入式设备上运行

通过使用 Rust 并将核心作为 Rust crate 分发，Deno 自动启用了在嵌入式设备上的使用，从 IoT 设备到可穿戴设备和 ARM 设备。再次，它的小巧以及包含所有工具的二进制文件可能是一个巨大的胜利。

箱子可以独立提供的事实允许人们在不同地方嵌入 Deno。例如，当用 Rust 编写数据库并且想要添加 Map-Reduce 逻辑时，我们可以使用 JavaScript 和 Deno 来实现。

## 生成浏览器兼容代码

如果你之前没有看过 Deno，那么这可能是个惊喜。我们不是在谈论服务器端运行时吗？是的。但这个服务器端运行时一直在努力保持 API 的浏览器兼容性。它在工具链中提供了特性，使代码可以写在 Deno 中并在浏览器中执行，这将在第七章 *HTTPS、提取配置和 Deno 在浏览器中* 中探索。

所有的这些工作都由 Deno 团队负责，他们使自己的 API 保持与浏览器兼容，并生成可以在浏览器中打开新可能性集的浏览器代码。浏览器兼容性是我们在本书后面将会使用到的内容，在第七章 *HTTPS、提取配置和 Deno 在浏览器中* 中，通过编写一个完整的应用程序、客户端和服务器来构建一个 Deno 应用程序。（注：这里原文中的“in this book”翻译为“在本书后面”，以保持上下文的连贯性。）

## 全面的 API

Deno 和 Node.js 一样，在处理 HTTP 服务器方面投入了大量精力。拥有一个完整的标准库，为框架提供伟大的基础，毫无疑问，API 是 Deno 最强大的用例之一。TypeScript 在文档、代码生成和静态类型检查方面是一个很好的补充，帮助成熟的代码库扩展。

我们将在本书的剩余部分更多地关注这个具体的用例，因为我相信这是最重要的用例之一——Deno 发挥光彩的地方。

这些都是我们认为 Deno 非常适合的用例的几个例子。与 Node.js 一样，我们也知道还有许多新的用途等待发现。我们很高兴能陪伴这个冒险，并看到它还将揭示什么。

# 总结

在本书这一章中，我们穿越回 2009 年，以理解 Node.js 的创建。在那之后，我们意识到与线程模型相比，为什么要使用事件驱动的方法，以及它带来的优势。我们了解到事件驱动、异步代码是什么，以及 JavaScript 如何帮助 Node.js 和 Deno 充分利用服务器的资源。

在那之后，我们快速浏览了 Node.js 的 10 多年的历史、它的演变以及它的采用开始的情况。我们观察到运行时如何与它的基础语言 JavaScript 一起增长，同时帮助数百万企业将其伟大的产品带给客户。

然后，我们用今天的眼光来看 Node.js，生态和语言发生了什么变化？开发者遇到了哪些痛点？我们深入这些痛点，探讨为什么改变 Node.js 来解决这些问题既困难又缓慢。

随着这一章的进展，Deno 的动机变得越来越明显。在查看了 JavaScript 在服务器端的历史之后，出现一些新东西是合理的——一些可以解决以前经历的痛苦同时保留开发者所喜爱的东西的东西。

最后，我们了解了 Deno，它将成为我们这本书的朋友。我们学习了它的愿景、原则以及它如何解决某些问题。在简要介绍了使其成为可能的基础架构和组件之后，我们不禁要谈论一些权衡和当前的限制。

我们通过列举 Deno 适用的一些用例来结束这一章。稍后在本书中，当我们开始编程时，我们会回到这些用例。从这一章开始，我们的方法将更加具体和实用，始终朝着编写可以运行和探索的代码和示例前进。

既然我们已经了解了 Deno 是什么，我们就有了开始使用它的所有必要条件。在下一章中，我们将设置相应的环境并编写一个 Hello World 应用程序，同时做许多其他令人兴奋的事情。

就是这样，激动人心的冒险开始了，对吧？让我们出发吧！


# 第二章：工具链

如今我们熟悉了事件驱动语言，了解了 Node 的历史以及导致 Deno 产生的原因，我们就可以开始写一些代码了。

在本章中，我们首先要做的是设置环境和代码编辑器。我们将通过编写我们的第一个 Deno 程序和使用 REPL 实验运行时 API 来继续。然后，我们将探讨模块系统以及 Deno 缓存和模块解析如何通过实际示例工作。我们将了解版本控制，并将学习如何处理第三方依赖。然后，我们将使用 CLI 探索包及其文档，以及如何安装和重复使用 Deno 脚本。

在运行和安装几个脚本之后，我们将深入研究权限，学习权限系统是如何工作的以及我们如何可以保障我们运行的代码的安全。

在我们了解工具链的过程中，我们不能忽略代码格式化和验尸，所以我们在本章中也将探讨这些主题。我们将通过编写和运行一些简单的测试来探索 Deno 的测试套件，最后介绍 Deno 如何将代码打包成一个自给自足的二进制文件或单个 JavaScript 文件。

在本章中，我们将涵盖以下主题：

+   设置环境

+   安装 VS Code

+   Hello World

+   模块系统和第三方依赖

+   运行和安装脚本

+   使用测试命令

+   使用权限

+   格式化和验尸代码

+   代码打包

+   编译成二进制

+   使用升级命令

让我们开始吧！

# 技术要求

本章中出现的所有代码都可以在 [`github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter02`](https://github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter02) 找到。

# 设置环境

Deno 的一个原则是使其单一的可执行文件尽可能完整。这个决定，以及其他决策，大大简化了安装步骤。在本节中，我们将安装 VS Code 和推荐插件，并学习如何在不同的系统上安装 Deno。

## 安装 Deno

在接下来的几页中，我们将学习如何安装 Deno。为了确保本书中写的所有内容都能顺利运行，我们将使用版本 1.7.5。

这是本书中为数不多的部分，根据您的操作系统，事情可能会有所不同。安装完成后，无论您如何安装 Deno，都没有区别。

让我们实际操作并在我们的机器上安装 Deno。下面的子弹点展示了如何在不同的操作系统上安装运行时：

+   **Shell (Mac, Linux)**:

    ```js
    $ curl -fsSL https://deno.land/x/install/install.sh | sh -s v1.7.5
    ```

+   **PowerShell (Windows)**:

    ```js
    $v="1.7.5"; iwr https://deno.land/x/install/install.ps1 -useb | iex
    ```

然后，为了确保一切正常工作，让我们通过运行以下命令来获取当前的 Deno 版本：

```js
$ deno --version
```

我们应该得到以下输出：

```js
$ deno --version 
deno 1.7.5 (release, x86_64-apple-darwin) 
v8 9.0.123 
typescript 4.1.4
```

现在我们已经安装了正确版本的 Deno，我们可以开始编写和执行我们的程序了。然而，为了使我们的体验更加顺畅，我们将安装并配置我们选择的编辑器。

# 安装 VS Code

VS Code 是我们将在这本书中使用的编辑器。这主要是因为它有一个官方的 Deno 插件。还有其他提供 JavaScript 和 TypeScript 愉悦体验的编辑器，所以您可以自由使用它们。

这些步骤不是遵循本书剩余内容的必要步骤，所以请随意跳过它们。要安装它，请按照以下步骤操作：

1.  访问 [`code.visualstudio.com/`](https://code.visualstudio.com/) 并点击 **下载** 按钮。

1.  下载完成后，在您的系统上安装它。

1.  安装 VS Code 后，最后一步是安装 Deno 的 VS Code 插件。

1.  在 `Deno` 上下文中，安装由 Denoland 编写的 Deno 插件，这是官方插件：

![图 2.1 – VS Code 左侧栏的插件图标](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/deno-web-dev/img/Figure_2.1_B16380.jpg)

](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/deno-web-dev/img/Figure_2.1_B16380.jpg)

图 2.1 – VS Code 左侧栏的插件图标

这就是 Deno 的 VS Code 插件的样子：

![图 2.2 – Deno 在 VS Code 市场中的扩展](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/deno-web-dev/img/Figure_2.2_B16380.jpg)

图 2.2 – Deno 在 VS Code 市场中的扩展

要在你项目中启用 Deno 插件，你必须创建一个本地 VS Code 文件夹，该文件夹将包含工作区配置文件。为此，我们将创建一个名为 `.vscode` 的文件夹，并在其中创建一个名为 `settings.json` 的文件，并在该文件中写入以下内容：

```js
{
 "deno.enable": true
}
```

这将使 VS Code 激活当前文件夹内的扩展。在使用不稳定特性时，我们还可以启用 `deno.unstable` 设置，这也在插件文档中提到。

## 壳牌补全

Deno 还为我们提供了一种生成壳牌补全的方法。这样，在终端中编写 Deno 命令时，我们将获得自动完成建议。我们可以通过运行以下命令来实现：

```js
$ deno completions <shell>
```

`shell` 的可能值有 `zsh`、`bash`、`fish`、`powershell` 和 `elvish`。确保你选择你正在使用的那个。此命令将输出补全内容到标准输出。然后你可以将内容粘贴到你的 shell 配置文件中([`deno.land/manual@v1.7.5/getting_started/setup_your_environment#shell-autocomplete`](https://deno.land/manual@v1.6.0/getting_started/setup_your_environment#shell-autocomplete))。

有了这些，我们已经完成了如何安装 Deno 的步骤。我们还安装并配置了运行时和编辑器。现在，让我们用 Deno 编写一个 Hello World 程序！

# Hello World

一切准备就绪后，让我们编写我们的第一个程序！

首先，我们需要创建一个名为 `my-first-deno-program.js` 的文件，并写一些我们熟悉的内容。我们将使用 `console` API 将消息写入控制台：

```js
console.log('Hello from deno');
```

要执行此操作，让我们使用前面章节中安装的 CLI。我们必须使用名为 `run` 的命令来执行程序：

```js
$ deno run my-first-deno-program.js
Hello from deno
```

提示

所有 Deno CLI 命令都可以使用 `--help` 标志执行，这将详细说明命令的所有可能行为。

至此，我们实际上并没有做任何我们不知道该做什么的事情。我们只是用我们熟悉的 JavaScript 语言编写了一个 `console.log` 文件。

有趣的是，我们已经学会了使用`run`命令来执行程序。我们稍后在本书中详细探讨这个。

### 重新加载

**阅读-评估-打印循环**，也称为**REPL**，是在解释型语言中常用的工具。它允许用户运行代码行并获得即时输出。Node.js、Ruby 和 Python 是几个大量使用它的语言例子。Deno 也不例外。

要打开它，你只需要运行以下命令：

```js
$ deno
```

你现在可以花些时间去探索这门语言（提示：有标签完成功能）。如果你好奇有哪些 API 可以使用，这里是尝试它们的好地方。我们稍后会深入那些内容，但为了给你一些建议，你可以看看*Deno*命名空间，与 Web API 兼容的函数如`fetch`，或者如`Math`或`window`的对象，这些都在 Deno 的文档中列出（[`doc.deno.land/builtin/stable`](https://doc.deno.land/builtin/stable)）。

试试它们吧！

### 评估

另一种执行不在文件中的代码的方法是使用`eval`命令：

```js
$ deno eval "console.log('Hello from eval')"
Hello from eval
```

`eval`命令可以用来运行简单的内联脚本。

到目前为止，我们所编写的程序相当简单。我们只是以几种不同的方式将值输出到控制台。然而，当我们开始接近现实世界时，我们知道我们将编写更复杂的逻辑。更复杂的逻辑意味着更多的错误，因此需要调试我们的代码。这是我们接下来要学习的内容。

# 在 Deno 中调试代码

即使在我们遵循最佳实践并尽力编写简单、干净的代码时，任何相关的程序都很有可能会偶尔需要调试。

掌握快速运行和调试代码的能力是提高任何技术学习曲线的最佳方法之一。这项技能使得通过尝试和错误以及快速实验来测试和理解事物变得容易。

让我们学习一下如何调试我们的代码。

第一步是创建一个第二个程序。让我们添加几个变量，稍后可以检查。这个程序的主要目标是返回当前时间。我们将使用已知的`Date`对象来完成这个任务。让我们将这个文件命名为`get-current-time.js`，像这样：

```js
const now = new Date();
console.log(`${now.getHours()}:${now.getMinutes()}:  ${now.getSeconds()}`);
```

如果我们想在它打印到控制台之前调试`now`变量的值，这就是调试发挥作用的地方。让我们用`--inspect-brk`标志运行同一个程序：

```js
$ deno run --inspect-brk get-current-time.js
Debugger listening on ws://127.0.0.1:9229/ws/32e48d8a-5c9c-4300-8e09-ee700ab79648
```

我们现在可以打开 Google Chrome 浏览器，输入`chrome://inspect/`。在 localhost 上运行的远程目标 called `deno` 将会列出。点击`inspect`后，Chrome DevTools 检查器窗口将打开，并且执行将暂停在第一行：

![图 2.3 – Chrome 在要调试的第一行停止](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/deno-web-dev/img/Figure_2.3_B16380.jpg)

图 2.3 – Chrome 在要调试的第一行停止

在此阶段，我们可以添加断点、记录某些值、检查变量等等。它使得我们可以像在 Node 上或浏览器中调试时做的那样做相同的事情。

其实也可以使用`--inspect`标志来进行这个操作。然而，我们在这里使用了`--inspect-brk`以方便起见。这两个选项行为相似，但`inspect`需要在代码中存在一个*调试器*。当代码执行并解释*调试器*关键字时，它会尝试连接到一个已经运行的检查器实例。

既然我们已经了解了如何运行和调试代码，我们就可以开始编写自己的程序了。还有很多要学的，但我们已经熟悉了最基本的内容。

当我们开始编写程序并随着代码库的增长，我们很可能会开始将逻辑提取到不同的模块中。当这些模块变得可重用时，我们可能会将它们提取成包，以便它们可以在项目之间共享。这就是为什么我们需要了解 Deno 如何处理模块解析，我们将在下一节中进行了解。

# 模块和第三方依赖

Deno 使用与浏览器完全兼容的 ECMAScript 模块和导入。模块的路径是绝对的，所以它包括文件扩展名，这也是浏览器世界中的一个标准。

Deno 非常认真地采取了作为一个为脚本提供*浏览器*的方法。它与网络浏览器共有的一个特点是它深刻地利用了 URL。它们是分享资源最灵活的方式，在网络上表现得很美丽。为什么不用它们进行模块解析呢？浏览器就是这么做的。

模块路径是绝对的这个事实使得我们不需要依赖像 npm 这样的第三方实体，或者复杂的模块解析策略。有了绝对导入，我们可以直接从 GitHub、私有服务器，甚至从一个 gist 导入代码。唯一的要求是它有一个 URL。

这个决定使得可以采用完全去中心化的模块分布，并使得 Deno 内部的模块解析简单且与浏览器兼容。这是在 Node 上不会发生的事情。

Deno 甚至利用 URL 进行版本控制。例如，要导入标准库中 0.83.0 版本的 HTTP 服务器，我们将使用以下代码：

```js
import { serve } from 
'https://deno.land/std@0.83.0/http/server.ts'
```

这就是导入一个模块有多么简单。在这里，代码是从[`deno.land/`](https://deno.land/)加载的，但模块可以从任何其他地方加载。唯一的要求是有一个链接指向它。

例如，如果您有自己的服务器，文件可以通过 URL 访问，您可以在 Deno 中直接使用它们。之前，我们了解到 Deno 会自动安装并缓存依赖项，那么让我们了解更多关于它是如何工作的。

## 本地缓存的依赖项

我们已经了解到 Deno 没有像`node_modules`这样的约定。对于来自 Node 的人来说，这可能听起来很奇怪。这意味着你的代码总是从互联网上获取模块吗？不是。你仍然可以离线工作吗？可以。

让我们在实践中看看这个。

创建一个名为`hello-http-server.js`的文件，并添加以下代码：

```js
import { serve } from
"https://deno.land/std@0.84.0/http/server.ts";
for await (const req of serve(":8080")) {
  req.respond({ body: "Hello deno" });
}
```

正如你可能猜到的那样，这个程序在端口`8080`上启动一个 HTTP 服务器，并对每个请求响应`Hello deno`。

如果你觉得这仍然很奇怪，不用担心——我们将在下一章更深入地介绍标准库。

让我们运行程序，并注意 Deno 在执行代码之前做了什么：

```js
$ deno run hello-http-server.js
Download https://deno.land/std@0.83.0/http/server.ts
Download https://deno.land/std@0.83.0/encoding/utf8.ts
Download https://deno.land/std@0.83.0/io/bufio.ts
Download https://deno.land/std@0.83.0/_util/assert.ts
Download https://deno.land/std@0.83.0/async/mod.ts
Download https://deno.land/std@0.83.0/http/_io.ts
Download https://deno.land/std@0.83.0/textproto/mod.ts
Download https://deno.land/std@0.83.0/http/http_status.ts
Download https://deno.land/std@0.83.0/async/deferred.ts
Download https://deno.land/std@0.83.0/async/delay.ts
Download https://deno.land/std@0.83.0/async/mux_async_iterator.ts
Download https://deno.land/std@0.83.0/async/pool.ts
Download https://deno.land/std@0.83.0/bytes/mod.ts
error: Uncaught PermissionDenied: network access to "0.0.0.0:8080", run again with the --allow-net flag
```

发生了什么事？在运行代码之前，Deno 查看代码的导入，下载任何依赖项，编译它们，并将它们存储在本地缓存中。最后仍然有一个错误，但我们稍后再解决这个问题。

为了了解 Deno 如何处理下载的文件，我们将使用另一个名为`info`的命令：

```js
$ deno info
DENO_DIR location: "/Users/alexandre/Library/Caches/deno"
Remote modules cache: "/Users/alexandre/Library/Caches/deno/deps"
TypeScript compiler cache: "/Users/alexandre/Library/Caches/deno/gen"
```

这会打印有关 Deno 安装的信息。注意`DENO_DIR`，这是 Deno 存储其本地缓存的路径。如果我们导航到那里，我们可以访问`.js`文件和相应的源映射。

在第一次下载并缓存模块之后，Deno 将不会重新下载它们，并将一直使用本地缓存，直到明确要求它不要这样做。

### 不运行代码的缓存

为了确保你有一个本地副本，而不必运行你的代码的依赖项，你可以使用以下命令：

```js
$ deno cache hello-http-server.js
```

这将做与 Deno 在运行你的代码之前完全相同的事情；唯一的区别是它不会运行。由于这个原因，我们可以建立`deno cache`命令和 Node 上`npm install`所做的操作之间的并行性。

### 重新加载缓存

`cache`和`run`命令可以使用`--reload`标志来强制下载依赖项。可以使用`--reload`标志的参数发送需要重新加载的模块的逗号分隔列表：

```js
$ deno cache hello-http-server.js --reload=https://deno.land/std@0.83.0/http/server.ts
Download https://deno.land/std@0.83.0/http/server.ts
```

在前面的示例中，只有来自[`deno.land/std@0.83.0/http/server.ts`](https://deno.land/std@0.83.0/http/server.ts)的模块会被重新下载，正如我们可以通过查看命令的输出确认的那样。

### 最后运行服务器

既然依赖项已经下载，那么阻止我们运行服务器的东西就是一个`PermissionDenied`错误：

```js
error: Uncaught PermissionDenied: network access to "0.0.0.0:8080", run again with the --allow-net flag
```

现在，让我们遵循建议并添加`--allow-net`标志，这将授予我们的程序完全的网络访问权限。我们将在本章后面讨论权限：

```js
$ deno run --allow-net hello-http-server.js
```

提示（Windows）

请注意，如果你使用的是 Windows，你可能会遇到 Windows 本地的网络授权弹窗，通知你有一个程序（Deno）正在尝试访问网络。如果你想让这个 Web 服务器能够运行，你应该点击**允许访问**。

现在，我们的服务器应该正在运行。如果我们用`curl`访问端口`8080`，它会显示`Hello` `Deno`：

```js
$ curl localhost:8080
Hello deno
```

这是我们最简单的 Web 服务器的结束；我们将在几页后回到这个话题。

## 管理依赖项

如果你曾经使用过其他工具，甚至是 Node.js 本身，你可能会觉得代码中到处都是 URL 不太直观。我们也可以争论说，通过直接在代码中写入 URL，我们可能会造成一些问题，比如同一个依赖项有两个不同的版本，或者 URL 有拼写错误。

Deno 通过摒弃复杂的模块解析策略，使用 plain JavaScript 和绝对导入来解决这个问题。

跟踪依赖项的提议解决方案，不过就是一个建议，那就是使用一个导出所有所需依赖项的文件，并将其放在一个包含 URL 的单一文件中。让我们看看它是如何工作的。

创建一个名为`deps.js`的文件，并在其中添加我们的依赖项，导出我们需要的那些：

```js
export { serve } from 
"https://deno.land/std@0.83.0/http/server.ts";
```

使用前面的语法，我们从标准库的 HTTP 服务器中导入了`serve`方法。

回到我们的`hello-http-server.js`文件，我们现在可以更改导入，以便我们可以从`deps.js`文件中使用导出的函数：

```js
import { serve } from "./deps.js";
for await (const req of serve(":8080")) {
  req.respond({ body: "Hello deno" });
}
```

现在，每当我们添加一个依赖项时，我们可以运行`deno cache deps.js`来保证我们有一个模块的本地副本。

这是 Deno 管理依赖项的方式。就是这么简单——没有魔法，没有复杂的标准，只是一个导入和导出符号的文件。

### 完整性检查

既然你知道了如何导入和管理第三方依赖项，你可能觉得还缺少了一些东西。

*怎样才能保证下次我们、同事，甚至是 CI 在尝试安装项目时，我们的依赖项没有发生变化呢？*

这是一个公平的问题，而且因为这是一个 URL，这可能会发生。

我们可以通过使用完整性检查来解决这个问题。

#### 生成锁文件

Deno 具有一种可以通过使用 JSON 文件存储和检查子资源完整性的特性，这与使用锁文件方法的其他技术类似。

要创建我们的第一个锁文件，请运行以下命令：

```js
$ deno cache --lock=lock.json --lock-write deps.js 
```

使用`--lock`标志，我们选择文件的名称，通过使用`--lock-write`，我们正在给 Deno 创建或更新该文件的权限。

查看生成的`lock.json`文件，我们会在那里找到以下内容：

```js
{
    "https://deno.land/std@0.83.0/_util/assert.ts":    "e1f76e77c5ccb5a8e0dbbbe6cce3a56d2556c8cb5a9a8802fc9565 af72462149",
    "https://deno.land/std@0.83.0/async/deferred.ts":    "ac95025f46580cf5197928ba90995d87f26e202c19ad961bc4e317 7310894cdc",
    "https://deno.land/std@0.83.0/async/delay.ts":    "35957d585a6e3dd87706858fb1d6b551cb278271b03f52c5a2cb70 e65e00c26a",
```

它生成一个 JSON 对象，其中键是依赖项的路径，值是 Deno 用来保证资源完整性的哈希值。

这个文件应该随后被提交到你的版本控制系统。

在下一节中，我们将学习如何安装依赖项，并确保每个人都运行着完全相同的代码版本。

#### 使用锁文件安装依赖项

一旦锁文件被创建，任何想要下载代码的人都可以运行带有`--lock`标志的 cache 命令。这在你下载依赖项时启用完整性检查：

```js
$ deno cache --reload --lock=lock.json deps.js
```

还可以使用`run`命令的`--lock`标志来启用运行时验证：

```js
$ deno run --lock=lock.json --allow-net hello-http-server.js
```

重要提示

当使用`run`命令的锁标志时，包含尚未缓存的依赖关系的代码将不会与锁文件进行核对。

为了确保在运行时检查新的依赖关系，我们可以使用`--cached-only`标志。

这样，如果任何不在`lock.json`文件中的依赖关系被我们的代码使用，Deno 将会抛出一个错误。

这就是我们确保运行我们想要的依赖关系的确切版本，消除可能由于版本更改而出现的问题的所有工作。

## 导入映射

Deno 支持导入映射（[`github.com/WICG/import-maps`](https://github.com/WICG/import-maps)）。

如果你不熟悉它们是什么，我会为你简要解释一下：它们用于控制 JavaScript 导入。如果你之前用过像 webpack 这样的 JavaScript 代码打包工具，那么这是一个类似于你所知的“别名”的功能。

重要提示

这个特性目前是不稳定的，因此必须使用`--unstable`标志来启用。

让我们创建一个 JSON 文件。这里文件的名字无关紧要，但为了简单起见，我们将它命名为`import-maps.json`。

在这个文件中，我们将创建一个带有`imports`键的 JavaScript 对象。在这个对象中，任何键将是模块名称，任何值将是真实的导入路径。我们第一个*导入映射*将是将`http`单词映射到标准库 HTTP 模块的根部的映射：

```js
{
  "imports": {
    "http/": "https://deno.land/std@0.83.0/http/"
  }
}
```

这样做后，我们现在可以在我们的`deps.js`文件中导入标准库的 HTTP 模块，像这样：

```js
export { serve } from "http/server.ts"; 
```

运行它时，我们将使用`--import-map`标志。这样做时，我们可以选择包含导入映射的文件。然后，因为这个特性仍然不稳定，我们必须使用`--unstable`标志：

```js
$ deno run --allow-net --import-map=import-maps.json --unstable hello-http-server.js
```

正如我们所看到的，我们的代码运行得非常完美。

这是一个轻松定制模块解析，且不依赖于任何外部工具的方法。它也已经被提议作为添加到浏览器中的内容。希望这个功能能在不久的将来被接受。

## 检查模块

我们刚刚使用了标准库的 HTTP 模块来创建一个服务器。如果你还不是非常熟悉标准库，不用担心；我们将在下一章更详细地解释它。现在，我们只需要知道我们可以在其网站上探索它的模块（[`deno.land/std`](https://deno.land/std)）。

让我们看看前一个脚本中使用的模块，HTTP 模块，并使用 Deno 了解更多关于它的信息。

我们可以使用`info`命令来完成这个：

```js
$ deno info https://deno.land/std@0.83.0/http/server.ts
local:/Users/alexandre/Library/Caches/deno/deps/https/deno.land/2d926cfeece184c4e5686c4a94b44c9d9a3ee01c98bdb4b5e546dea4 e0b25e49
type: TypeScript
compiled: /Users/alexandre/Library/Caches/deno/gen/https/deno.land/2d926cfeece184c4e5686c4a94b44c9d9a3ee01c98bdb4b5e546dea4 e0b25e49.js
deps: 12 unique (total 63.31KB)
https://deno.land/std@0.83.0/http/server.ts (10.23KB)
├── https://deno.land/std@0.83.0/_util/assert.ts *
├─┬ https://deno.land/std@0.83.0/async/mod.ts (202B)
│ ├── https://deno.land/std@0.83.0/async/deferred.ts *
│ ├── https://deno.land/std@0.83.0/async/delay.ts (279B)
│ ├─┬ 
…
│    └── https://deno.land/std@0.83.0/encoding/utf8.ts *
└─┬ https://deno.land/std@0.83.0/io/bufio.ts (21.15KB)
    https://deno.land/std@0.83.0/_util/assert.ts (405B)
    https://deno.land/std@0.83.0/bytes/mod.ts (4.34KB)
```

这个命令列出了关于 HTTP 模块的大量信息。让我们逐一分析。

在第一行，我们获取脚本的缓存版本的路径。在那之后的一行，我们看到文件的类型。我们已经知道标准库是用 TypeScript 编写的，所以这应该不会让我们感到惊讶。下一行也是一个路径，这次是模块的编译版本的路径，因为 TypeScript 模块在下载步骤中编译为 JavaScript。

命令输出的最后部分是依赖树。通过查看它，我们可以快速识别它只是链接到标准库中的其他模块。

提示

我们可以使用`--unstable`和`--json`标志与`deno info`一起使用，以获得一个可以通过编程方式访问的 JSON 输出。

当使用第三方模块时，我们不仅需要知道它们依赖什么，还需要知道模块提供了哪些函数和对象。我们将在下一节学习这一点。

# 探索文档

文档是任何软件项目的一个重要方面。Deno 在这方面做得很好，所有 API 的文档都维护得很好，TypeScript 在这方面提供了很大的帮助。由于标准库和运行时函数都是用 TypeScript 编写的，因此大部分文档都是自动生成的。

文档可在[`doc.deno.land/`](https://doc.deno.land/)找到。

如果你不能访问互联网并且想要访问你本地安装模块的文档，Deno 可以为你提供帮助。

许多编辑器，尤其是 VS Code，允许你这样做，著名的*Cmd/Ctrl* + 点击就是一个例子。然而，Deno 不依赖编辑器特性来实现这一点，因为`doc`命令提供了你将需要的所有基本功能。

让我们来看看标准库的 HTTP 模块的文档：

```js
$ deno doc https://deno.land/std@0.83.0/http/server.ts
function _parseAddrFromStr(addr: string): HTTPOptions
    Parse addr from string
async function listenAndServe(addr: string | HTTPOptions, handler: (req: ServerRequest) => void): Promise<void>
    Start an HTTP server with given options and request handler
async function listenAndServeTLS(options: HTTPSOptions, handler: (req: ServerRequest) => void): Promise<void>
    Start an HTTPS server with given options and request 
      handler
function serve(addr: string | HTTPOptions): Server
    Create a HTTP server
...
```

我们现在可以看到暴露的方法和类型。

在我们之前的某个程序中，我们使用了`serve`方法。为了了解更多关于这个特定方法的信息，我们可以将方法（或任何其他符号）名称作为第二个参数发送：

```js
$ deno doc https://deno.land/std@0.83.0/http/server.ts serve
Defined in https://deno.land/std@0.83.0/http/server.ts:282:0
function serve(addr: string | HTTPOptions): Server
    Create a HTTP server
        import { serve } from         "https://deno.land/std/http/server.ts";
        const body = "Hello World\n";
        const server = serve({ port: 8000 });
        for await (const req of server) {
          req.respond({ body }); add 
        }
```

这是一个非常有用的功能，它使开发者能够在不依赖编辑器的情况下浏览本地安装模块的文档。

正如我们在下一章将要学习的那样，通过使用 REPL，你可能会注意到 Deno 有一个内置的 API。要查看其文档，我们可以运行以下命令：

```js
$ deno doc --builtin
```

输出的内容将会非常庞大，因为它列出了所有的公共方法和类型。

在*nix 系统中，这可以很容易地通过管道传送到像`less`这样的应用程序：

```js
$ deno doc --builtin | less
```

与远程模块类似，也可以通过方法名进行过滤。例如，Deno 命名空间中存在的`writeFile`函数：

```js
$ deno doc --builtin Deno.writeFile
Defined in lib.deno.d.ts:1558:2
function writeFile(path: string | URL, data: Uint8Array, options?: WriteFileOptions): Promise<void>
  Write `data` to the given `path`, by default creating a new file if needed,
  else overwriting.
  ```ts

const encoder = new TextEncoder();

const data = encoder.encode("Hello world\n");

await Deno.writeFile("hello1.txt", data);  // 覆盖"hello1.txt"或创建它

await Deno.writeFile("hello2.txt", data, {create: false});  // 只有当"hello2.txt"存在时才有效

await Deno.writeFile("hello3.txt", data, {mode: 0o777});  // 设置新文件的权限

await Deno.writeFile("hello4.txt", data, {append: true});  // 将数据添加到文件的末尾

```js
 Requires `allow-write` permission, and `allow-read` if `options.create` is `false`.
```

`doc`命令是开发工作流程中的一个有用部分。然而，如果你能访问互联网并且想要以更易消化和视觉化的方式访问它，应该去[`doc.deno.land/`](https://doc.deno.land/)。

你可以使用文档网站了解更多关于内置 API 或标准库模块的信息。此外，它还允许你显示任何可用的模块的文档。为此，我们只需将模块 URL 的`://`部分替换为一个反斜杠`\`，并在 URL 前加上[`doc.deno.land/`](https://doc.deno.land/)。

例如，要访问 HTTP 模块的文档，URL 将是 [`doc.deno.land/https/deno.land/std@0.83.0/http/server.ts`](https://doc.deno.land/https/deno.land/std@0.83.0/http/server.ts)。

如果你导航到那个 URL，将显示一个干净的界面，包含模块的文档。

现在我们知道如何使用和探索第三方模块。然而，当我们开始编写我们的应用程序时，可能有一些工具我们要在各个项目中共享。我们可能还想让那个特定的包在我们系统的每个地方都可用。下一节将帮助我们做到这一点。

# 运行和安装脚本

在他最早的几次演讲中，在 Deno 的第一个版本发布说明中（[`deno.land/posts/v1#a-web-browser-for-command-line-scripts`](https://deno.land/posts/v1#a-web-browser-for-command-line-scripts)），Dahl 使用了我非常喜欢的一句话：

“Deno 是命令行脚本的网络浏览器。”

每当我使用 Deno 时，这句话变得越来越有意义。我确信随着本书的进行，它也会对你有意义。让我们更深入地探索一下。

在浏览器中，当你访问一个 URL 时，它会运行那里的代码。它解释 HTML 和 CSS，然后执行一些 JavaScript。

Deno，遵循其作为脚本浏览器的前提，只需要一个 URL 来运行代码。让我们看看它是如何工作的。

老实说，这与我们之前已经做过的事情并没有太大区别。作为复习，上次我们执行简单的 Web 服务器时，我们做了以下事情：

```js
$ deno run --allow-net --import-map=import-maps.json --unstable hello-http-server.js
```

在这里，`hello-http-server.js`只是一个当前文件夹中的文件。

让我们尝试用一个远程文件来做同样的事情——一个通过 HTTP 提供服务的文件。

我们将从 Deno 标准库的示例集中执行一个“回声服务器”。你可以在这里查看这个代码([`deno.land/std@0.83.0/examples/echo_server.ts`](https://deno.land/std@0.83.0/examples/echo_server.ts))。这是一个回声服务器，无论发送给它什么都会回显：

```js
$ deno run --allow-net https://deno.land/std@0.83.0/examples/ echo_server.ts
Download https://deno.land/std@0.83.0/examples/echo_server.ts
Check https://deno.land/std@0.83.0/examples/echo_server.ts
Listening on 0.0.0.0:8080
```

重要提示

如果你使用的是 Windows 系统，可能无法访问`0.0.0.0:8080`；你应该访问`localhost:8080` instead. 它们都指的是你本地机器上的同一件事。然而，当`0.0.0.0`出现在本书的其他部分时，如果你正在运行 Windows，你应该尝试访问`localhost`。

碰巧的是，每次文件没有被缓存时，Deno 都会下载并执行它们。

它与网络浏览器区别有多大？我认为没有太大区别。我们给了它一个 URL，它运行了代码。

为了确保它正常工作，我们可以建立一个 Telnet 连接（[`en.wikipedia.org/wiki/Telnet`](https://en.wikipedia.org/wiki/Telnet)）并发送服务器回显的消息：

```js
$ telnet 0.0.0.0 8080
Trying 0.0.0.0...
Connected to 0.0.0.0.
Escape character is '^]'.
hello buddy
hello buddy
```

您可以使用任何可用的 Telnet 客户端；在这里，我们使用了一个通过 Homebrew（[`brew.sh/`](https://brew.sh/)）安装的 macOS 客户端。第一个“hello buddy”是我们发送的消息，而后一个是回显的消息。通过这个，我们可以验证回显服务器是否正常工作。

重要说明

如果您使用任何其他的 telnet 客户端，请确保您启用了“本地行编辑”设置。一些客户端默认不启用此设置，并且在你输入字符时发送字符，导致消息中出现重复的字符。下面的图片展示了如何在 Windows 上的 PuTTY 中配置这个设置。

![图 2.4 – PuTTY 本地行编辑设置](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/deno-web-dev/img/Figure_2.4_B16380.jpg)

图 2.4 – PuTTY 本地行编辑设置

这证实了我们之前所说的，即 Deno 用相同的方法运行代码和解决模块：它以类似的方式处理本地和远程代码。

## 安装实用脚本

有些实用程序我们写一次，而有些我们多次使用。有时，为了方便重用，我们只是将那些脚本从一个项目复制到另一个项目。对于其他的，我们保存在一个 GitHub 仓库中，并且一直去那里获取它们。我们最常使用的可能需要被包装在 shell 脚本中，添加到`/usr/local/bin`（在*nix 系统上）并在我们的系统上使其可用。

为此，Deno 提供了`install`命令。

这个命令将一个程序包装在一个薄的壳脚本中，并将其放入安装的 bin 目录中。脚本的权限在安装时设置，此后不再询问：

```js
$ deno install --allow-net --allow-read https://deno.land/std@0.83.0/http/file_server.ts
```

在这里，我们使用了标准库中的另一个模块叫做`file_server`。它创建了一个 HTTP 服务器来服务当前目录。您可以通过访问导入 URL（[`deno.land/std@0.83.0/http/file_server.ts`](https://deno.land/std@0.83.0/http/file_server.ts)）看到它的代码。

安装命令将在您的系统上使`file_server`脚本可用。

为了给它一个除了`file_server`之外的名称，我们可以使用`-n`标志，如下所示：

```js
$ deno install --allow-net --allow-read -n serve https://deno.land/std@0.83.0/http/file_server.ts 
```

现在，让我们服务当前目录：

```js
$ serve
HTTP server listening on http://0.0.0.0:4507/
```

如果我们访问`http://localhost:4507`，我们会得到以下内容：

![图 2.5 – Deno 文件服务器网页](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/deno-web-dev/img/Figure_2.5_B16380.jpg)

图 2.5 – Deno 文件服务器网页

这适用于远程 URL，但也可以用于本地 URL。如果您有一个用 Deno 编写的程序，您想要将其转换为可执行文件，您也可以使用`install`命令来完成。

我们可以用我们简单的 Web 服务器来做这件事，例如：

```js
$ deno install --allow-net --unstable hello-http-server.js
```

通过运行前面的代码，创建了一个名为`hello-http-server`的脚本，并在我们的系统中可用。

这就是我们执行本地和远程脚本所需的一切。Deno 使这非常容易，因为它以非常直接的方式处理导入和模块，非常类似于浏览器。

以前，我们使用权限允许脚本访问网络或文件系统等资源。在本节中，我们使用权限与`install`命令一起使用，但我们之前也这样使用过`run`命令。

到现在，你可能已经理解了它们是如何工作的，但我们在下一节会更详细地了解它们。

# 权限

当我们几页前编写我们的第一个 HTTP 服务器时，我们第一次遇到了 Deno 的权限。当时，我们必须给我们的脚本授予访问网络的权限。从那时起，我们多次使用它们，但并不太了解它们是如何工作的。

在本节中，我们将探讨权限是如何工作的。我们将了解存在哪些权限以及如何配置它们。

如果我们运行`deno run --help`，我们将获得`run`命令的帮助输出，其中列出了某些权限。为了使这更方便您，我们将列出所有现有的权限并提供每个的简要说明。

### -A, --allow-all

这关闭了所有权限检查。带有此标志运行代码意味着它将拥有用户所有的访问权限，与 Node.js 默认行为非常相似。

在运行此代码时请小心，尤其是当代码不是你自己的时候。

### --allow-env

这赋予了访问环境的能力。它用于程序可以访问环境变量。

### --allow-hrtime

这赋予了访问高分辨率时间管理的能力。它可以用于精确的基准测试。给予错误的脚本这个权限可能会允许指纹识别和时序攻击。

### --allow-net=<域名>

这赋予了访问网络的能力。如果没有参数，它允许所有的网络访问。如果有参数，它允许我们传递一个由逗号分隔的列表的域名，其中网络通信将被允许。

### --allow-plugin

这允许加载插件。请注意，这仍然是一个不稳定的特性。

### --allow-read=<路径>

这赋予了文件系统的读取权限。如果没有参数，它授予用户可以访问的一切。如果有参数，这只允许访问由逗号分隔的列表提供的文件夹。

### --allow-run

这赋予了运行子进程的能力（例如，使用`Deno.run`）。请记住，子进程不是沙盒化的，应该谨慎使用。

### --allow-write=<路径>

这赋予了文件系统的写入权限。如果没有参数，它授予用户可以访问的一切。如果有参数，它只允许访问由逗号分隔的列表提供的文件夹。

每次程序运行且没有正确的权限时，都会抛出一个`PermissionError`。

权限在`run`和`install`命令中使用。它们之间的唯一区别是授予权限的时刻。对于`run`，您必须在运行时授予权限，而对于`install`，您在安装脚本时授予权限。

对于 Deno 程序，还有一种获取权限的方式。它不需要预先授予权限，而是会在需要时请求它们。我们将在下一章中探讨这一特性，届时我们将学习 Deno 的命名空间。

就这样！除了权限之外，真的没有太多可以添加的内容，因为它是 Deno 中的一个非常重要的功能，它默认沙盒化我们的代码，并让我们决定我们的代码应该具有哪些访问权限。我们将在本书中编写应用程序时继续使用权限。

到目前为止，我们已经学习了如何运行、安装和缓存模块，以及如何使用权限。随着我们编写和运行更复杂的程序，开始需要对它们进行测试。我们可以使用`test`命令来实现，正如我们将在下一节中学到的。

# 使用测试命令

作为主二进制文件的一部分，Deno 还提供了一个测试运行器。这个命令的名字意料之中地叫做`test`。在本节中，我们将探索它并运行几个测试。

在本节中，我们将主要探索命令本身，而不是测试语法。我们将更详细地探讨该语法的语法和最佳实践，这将是在本书后面的一个专章中进行。

`test`命令根据`{*_,*.,}test.{js,mjs,ts,jsx,tsx}`通配符表达式查找要运行的文件。

由于通配符表达式可能不太直观，我们将简要解释它们。

它匹配任何具有`js`、`mjs`、`ts`、`jsx`和`tsx`扩展名的文件，并且文件名中包含`test`，前面有一个下划线（`_`）或点（`.`）

以下是一些将匹配表达式并被认为是要测试的文件示例：

+   `example.test.ts`

+   `example_test.js`

+   `example.test.jsx`

+   `example_test.mjs`

Deno 测试也在沙盒环境中运行，因此它们需要权限。查看上一节以了解更多关于如何做到这一点的信息。

在运行测试时，也可以使用我们在本章前面学到的调试命令。

## 过滤测试

当你有一个完整的测试套件时，一个常见的需求是只运行其中的特定部分。为此，`test`命令提供了`--filter`标志。

想象我们有一个以下文件，其中定义了两个测试：

```js
Deno.test("first test", () => {});
Deno.test("second test", () => {});
```

如果我们只想运行其中的一个，我们可以使用`--filter`标志，并通过传递一个字符串或模式来匹配测试名称：

```js
$ deno test --filter second
running 1 tests
test second test ... ok (3ms)
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out (3ms)
```

前面的代码只是运行了与过滤器匹配的测试。当我们在开发代码库的小部分测试时，这个特性非常有用，我们希望能够快速反馈关于这个过程的信息。

## 快速失败

在诸如持续集成服务器等环境中，如果真的不关心有多少测试失败，我们可能希望快速失败，只要测试阶段结束即可。

要做到这一点，我们可以使用 `--fail-fast` 标志。

这就是我们现在所需要了解的所有关于测试的内容。正如我们之前提到的，我们将在第八章*，测试 - 单元和集成*中回到测试主题。我们只是想在这里熟悉一下 CLI 命令。

我们认为测试是一个保证我们的代码正在运行的工具，同时也是记录我们代码行为的手段。测试是任何正在运行和发展的代码库的基础，Deno 通过在其二进制文件中包含一个测试运行器，使它们成为一等公民。然而，测试只是更大工具集的一部分——一个包括诸如代码审查和格式化等开发者需求的部分。

在下一节中，我们将了解 Deno 如何解决这些问题。

# 代码审查和格式化

代码审查和格式化是维护代码一致性和强制执行良好实践的两个被认为至关重要的能力。怀着这样的想法，Deno 在其 CLI 中集成了这两个工具。我们将在这一节中了解它们。

## 格式化

要格式化 Deno 的代码，CLI 提供了 `fmt` 命令。这是一个有观点的格式化器，旨在解决任何关于代码格式化的疑问。主要目标是让开发者在编写代码时不必关心代码的格式，在审查拉取请求时也不必关心。

运行以下命令（无参数）将格式化当前目录中的所有文件：

```js
$ deno fmt
/Users/alexandre/Deno-Web-Development/Chapter02/my-first-deno-program.js
/Users/alexandre/Deno-Web-Development/Chapter02/bundle.js
```

如果我们想要格式化一个单独的文件，我们可以把它作为一个参数发送。

要检查文件的格式化错误，我们可以使用这个与 `--check` 标志一起，它将把我们文件中找到的错误输出到 stdout。

### 忽略行和文件

要使格式化器忽略一行或整个文件，我们可以使用 `ignore` 注释：

```js
// deno-fmt-ignore
const book = 'Deno 1.x – Web Development'; 
```

使用 `deno-fmt-ignore` 忽略了注释后面的行：

```js
// deno-fmt-ignore-file
const book = 'Deno 1.x – Web Development';
const editor = 'PacktPub'
```

使用`deno-fmt-ignore-file`将忽略整个文件。

## 代码审查

仍然在 unstable 标志下，`lint` 命令将我们在代码中找到的警告和错误打印到 stdout。

让我们通过运行名为 `to-lint.js` 的脚本的代码审查器来实际看看它。你可以对任何你想要的东西运行它。在这里，我们只是用一个会抛出错误的文件，因为它包含了一个 `debugger`:

```js
$ deno lint --unstable to-lint.js
(no-debugger) `debugger` statement is not allowed
  debugger;
    ~~~~~~~~~
    at /Users/alexandre/dev/personal/Deno-Web-Development/Chapter02/to-lint.js:4:2
Found 1 problems
```

在这一节中，我们学习了如何使用 `fmt` 和 `lint` 命令来维护代码一致性和最佳实践。

这些是 Deno CLI 提供的命令之一，在我们编写 Deno 程序的日常生活中将会使用到。它们两个都碰巧是非常有观点的，所以没有空间支持不同的标准。这应该不足为奇，因为 Deno 深受*golang*的启发，这种方法与*gofmt*等工具所能做到的相一致。

有了这个，我们知道如何格式化和检查我们的代码以遵循最佳实践。将这个添加到我们前几部分所学习的内容，没有什么能阻止我们在生产环境中运行我们的代码。

当我们进入生产环境时，我们显然希望我们的服务器尽可能快。在前一章节中，我们了解到 Deno 最慢的部分之一是 TypeScript 解析。当我们编写 TypeScript 代码时，我们不希望每次服务器启动时都牺牲时间去解析它。同时，由于我们编写干净、独立的模块，我们不希望将它们分别发送到生产环境。

这就是为什么 Deno 提供了一个允许我们将代码捆绑到单个文件的功能。我们将在下一节了解这个功能。

# 捆绑代码

在前一章节中，当我们介绍 Deno 时，我们选择了捆绑代码作为一个激动人心的特性，原因有很多。这个特性有巨大的潜力，我们将在第七章中更详细地探索这个特性，*HTTPS、提取配置和 Deno 在浏览器中*。但由于我们现在正在探索 CLI，我们将了解适当的命令。

它被称为`bundle`，它将代码捆绑成单个、自包含的 ES 模块。

不依赖于 Deno 命名空间的捆绑代码也可以在浏览器中使用`<script type="module">`和在 Node.js 中运行。

让我们用它来构建我们的`get-current-time.js`脚本：

```js
$ deno bundle get-current-time.js bundle.js
Bundle file:///Users/alexandre/dev/deno-web-development/Chapter02/2-hello-world/get-current-time.js
Emit "bundle.js" (2.33 KB)
```

现在，我们可以运行生成的`bundle.js`：

```js
$ deno run bundle.js
0:11:4
```

这将打印当前时间。

由于它兼容 ES6 的 JavaScript（你需要安装 Node.js 才能运行下面的命令），我们也可以用 Node.js 来执行它：

```js
$ node bundle.js
0:11:4
```

为了在浏览器中使用同样的代码，我们可以创建一个名为`index-bundle.html`的文件，并导入我们生成的捆绑包：

```js
<!DOCTYPE html>
<html>
  <head>
    <title>Deno bundle</title>
  </head>
  <body>
    <script type="module" src="img/bundle.js"></script>
  </body>
</html>
```

有了前一部分所获得的知识，我们可以在当前文件夹中运行标准库的文件服务器：

```js
$ deno run --allow-net --allow-read https://deno.land/std@0.83.0/http/file_server.ts
HTTP server listening on http://0.0.0.0:4507/ 
```

现在，如果你导航到`http://localhost:4507/index-bundle.html`，并打开浏览器控制台，你会发现当前时间已经被打印出来了。

捆绑是一个非常有前途的功能，我们将在第七章、*HTTPS、提取配置和 Deno 在浏览器中*中进一步探索。它允许我们将应用程序创建成单个 JavaScript 文件。

我们稍后会回到这个问题，并在本书的后面部分向你展示它所启发的功能。捆绑是一个很好的分发你的 Deno 应用程序的方式，正如我们在这个章节所看到的。但是如果你想要将你的应用程序分发到可以运行在非你的电脑上呢？`bundle`命令是否为我们实现了这个功能？

嗯，实际上并不是。如果代码将要执行的地方安装了 Node、Deno 或一个浏览器，它就会这样做。

但如果它没有呢？这就是我们接下来要学习的内容。

# 编译成二进制

当 Deno 最初推出时，Dahl 表示其目标之一是能够将 Deno 代码作为单个二进制文件发货，类似于 golang 的做法，从第一天开始。这与 nexe ([`github.com/nexe/nexe`](https://github.com/nexe/nexe)) 或 pkg ([`github.com/vercel/pkg`](https://github.com/vercel/pkg)) 的工作非常相似，后者为 Node 提供服务。

这与捆绑功能不同，后者会生成一个 JavaScript 文件。当你将 Deno 代码编译成二进制文件时，所有的运行时和代码都包含在那个二进制文件中，使其自给自足。一旦你编译好了，你就可以把这个二进制文件发送到任何地方，然后就能执行它。

重要提示

在撰写本文时，这仍然是一个具有许多限制的不稳定功能，如其在 https://deno.land/posts/v1.7#improvements-to-codedeno-compilecode 中所述。

这个过程非常简单。让我们看看我们是如何做到的。

我们只需要使用`compile`命令。对于这个例子，我们将使用前面章节中使用的脚本，即`get-current-time.js`：

```js
$ deno compile --unstable get-current-time.js
Bundle file:///Users/alexandre/dev/Deno-Web-Development/Chapter02/get-current-time.js
Compile file:///Users/alexandre/dev/Deno-Web-Development/Chapter02/get-current-time.js
Emit get-current-time
```

这会生成一个名为`get-current-time`的二进制文件，我们可以现在执行它：

```js
$ ./get-current-time
16:10:8
```

这正在工作！这个功能使我们能够轻松地分发应用程序。这是可能的，因为它包括了代码及其所有依赖项，包括 Deno 运行时，使其自给自足。

随着 Deno 的不断发展，新的功能、bug 修复和改进将会被添加。以每个季度发布几个版本的速度，你可能会想要升级我们使用的 Deno 版本是非常常见的。CLI 也提供了这个命令。我们将在下一节学习这个。

# 使用升级命令

我们开始这一章的学习是如何安装 Deno，我们安装了运行时的单个版本。但 Deno 在不断地发布 bug 修复和改进——尤其是在这些早期版本中。

当有新的更新时，我们可以使用安装 Deno 时使用的相同包管理器来升级它。然而，Deno CLI 提供了一个命令，它可以用来升级自己。该命令称为`upgrade`，可以与`--version`标志一起使用，以选择我们要升级到的版本：

```js
$ deno upgrade --version=1.7.4
```

如果没有提供版本，默认为最新版本。要在另一个位置安装新版本，而不是替换当前安装，可以使用`--output`标志，如下所示：

```js
$ deno upgrade --output $HOME/my_deno
```

就是这样——`upgrade`是遵循 Deno 哲学提供编写和维护应用程序所需的一切的另一个工具，而那个周期中肯定包括更新我们的运行时。

# 总结

在本章中，我们的主要焦点是了解 Deno 提供的工具，包括其主二进制文件中的那些工具。这些工具将在我们的日常生活中和本书的其余部分被大量使用。

我们首先安排了我们的环境和编辑器，然后深入了解了工具链。

然后，我们编写了并执行了一个`eval`命令，作为启用实验和无需文件运行代码的方式。之后，我们查看了模块系统。我们不仅导入了并使用了模块，还深入了解了 Deno 如何下载并在本地缓存依赖。

在熟悉了模块系统之后，我们学习了如何管理外部依赖，即锁文件和完整性检查。我们不得不在这个部分稍微提一下一个仍然不稳定但很有前景的功能：导入映射。

之后，我们利用`info`命令的帮助，探索了一些第三方模块及其代码和依赖。Deno 没有忽视文档，我们还学会了如何使用`documentation`命令和相应的网站查看第三方代码文档。

由于脚本在 Deno 中是第一公民，我们探索了允许我们从 URL 直接运行代码并全局安装实用脚本的命令。

整本书中，我们都提到了权限是 Deno 的一大特色。在这一章，我们学习了如何在运行代码时使用权限来微调其权限。

接下来，我们学习了测试运行器，以及如何运行和筛选测试。我们还了解了一个功能，即如何根据 Deno 的标准格式化和校对我们的代码。我们了解了`fmt`和`lint`命令，这两个带有观点的工具确保开发者不必担心格式化和校验，因为它们是自动处理的。

最后，我们介绍了`bundle`和`compile`命令。我们学会了如何将我们的代码打包成一个 JavaScript 文件，以及如何生成一个包含我们的代码和 Deno 运行时的二进制文件，使其自给自足。

这一章涵盖了大量的有趣内容。我保证接下来会更令人兴奋。在下一章，我们将了解标准库，并学会使用它来编写简单的应用程序，同时了解 Deno 的 API。

兴奋吗？让我们开始吧！


# 第三章：运行时和标准库

既然我们已经足够了解 Deno，那么我们就可以用它来编写一些真正的应用程序。在本章中，我们将不使用任何库，因为其主要目的是介绍运行时 API 和标准库。

我们将编写小型 CLI 工具、Web 服务器等，始终利用官方 Deno 团队创建的力量，没有外部依赖。

我们将从 Deno 命名空间开始，因为我们认为首先探索运行时包含的内容是有意义的。按照这个想法，我们还将查看 Deno 与浏览器共享的 Web API。我们将使用`setTimeout`到`addEventListener`、`fetch`等。

仍然在 Deno 命名空间中，我们将了解程序的生命周期，与文件系统交互，并构建小型命令行程序。后来，我们将了解缓冲区，并理解它们如何用于异步读写。

我们将简要介绍标准库，并浏览一些有用的模块。这一章并不旨在取代标准库的文档；它将展示标准库的一些功能和用例。在编写小型程序的过程中，我们将了解它。

在穿越标准库的旅程中，我们将使用与文件系统、ID 生成、文本格式化和 HTTP 通信相关的模块。其中一部分将是我们稍后深入探索的介绍。您将通过编写您的第一个 JSON API 并连接到它来完成本章。

以下是我们将在本章中涵盖的主题：

+   **Deno 运行时**

+   探索 Deno 命名空间

+   使用标准库

+   使用 HTTP 模块构建 Web 服务器

## 技术要求

本章的所有代码文件可以在以下 GitHub 链接找到：[`github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter03`](https://github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter03)。

# **Deno 运行时**

Deno 提供了一组函数，这些函数作为全局变量包含在`Deno`命名空间中。运行时 API 在[`doc.deno.land/`](https://doc.deno.land/)上进行文档化，可以用来做最基本的、底层的事情。

在 Deno 中，无需导入即可使用两种类型的函数：Web API 和`Deno`命名空间。每当 Deno 中存在与浏览器中相同的行为时，Deno 会模仿浏览器 API——这些是 Web API。由于您来自 JavaScript 世界，您可能对这些大部分都很熟悉。我们谈论的是诸如`fetch`、`addEventListener`、`setTimeout`等函数，以及`window`、`Event`、`console`等对象 among others.

使用 Web API 编写的代码可以捆绑并在浏览器中运行，无需任何转换。

运行时暴露的 API 的大部分位于一个名为`Deno`的全局命名空间中。你可以使用 REPL 和文档，这两者我们在第二章中探讨过，*工具链*，来探索它并快速了解它包括哪些函数。在本章后面，我们还将尝试一些最常用的函数。

如果你想要访问 Deno 中包含的所有符号的文档，你可以使用带有`--builtin`标志的`doc`命令。

## 稳定性

`Deno`命名空间内的函数从版本 1.0.0 开始被认为是稳定的。这意味着 Deno 团队将努力在 newer versions 中支持它们，并将尽最大努力使它们与未来的变化保持兼容。

仍不稳定 features live under the `--unstable` flag，正如你可能会想到的那样，因为我们已经在之前的示例中使用过它们。

不稳定模块的文档可以通过使用`doc`命令的`--unstable`标志或通过访问[`doc.deno.land/builtin/unstable`](https://doc.deno.land/builtin/unstable)来获取。

标准库尚未被 Deno 团队认为是稳定的，因此它们的版本与 CLI 不同（在撰写本文时，它是版本 0.83.0）。

与`Deno`命名空间函数相比，标准库通常不需要`--unstable`标志来运行，除非标准库中的任何模块正在使用来自`Deno`命名空间的 unstable functions。

## 程序生命周期

Deno 支持浏览器兼容的`load`和`unload`事件，可以用来运行设置和清理代码。

处理器可以以两种不同的方式编写：使用`addEventListener`和通过重写`window.onload`和`window.onunload`函数。`load`事件可以是异步的，但`unload`事件却不能取消，因此这是不正确的。

使用`addEventListener`可以注册无限数量的处理器；例如：

```js
addEventListener("load", () => {
  console.log("loaded 1");
});
addEventListener("unload", () => {
  console.log("unloaded 1");
});
addEventListener("load", () => {
  console.log("loaded 2");
});
addEventListener("unload", () => {
  console.log("unloaded 2");
});
console.log("Exiting...");
```

如果我们运行前面的代码，我们得到以下输出：

```js
$ deno run program-lifecycle/add-event-listener.js
Exiting...
loaded 1
loaded 2
unloaded 1
unloaded 2
```

另一种在设置和拆除阶段安排代码运行的方法是重写`window`对象的`onload`和`onunload`函数。这些函数的特点是只有最后一个分配的运行。这是因为它们互相覆盖；例如，请参见以下代码：

```js
window.onload = () => {
  console.log("onload 1");
};
window.onunload = () => {
  console.log("onunload 1");
};
window.onload = () => {
  console.log("onload 2");
};
window.onunload = () => {
  console.log("onunload 2");
};
console.log("Exiting");
```

运行前面的程序后，我们得到了以下输出：

```js
$ deno run program-lifecycle/window-on-load.js
Exiting
onload 2
onunload 2
```

如果我们然后查看我们最初编写的代码，我们可以理解前两个声明被跟在它们后面的两个声明覆盖了。当我们覆盖`onunload`和`onload`时，就会发生这种情况。

## 网络 API

为了展示我们可以像在浏览器中一样使用 Web API，我们将编写一个简单的程序，获取 Deno 网站的标志，将其转换为 base64，并在控制台打印一个包含图像 base64 的 HTML 页面。让我们按照以下步骤进行操作：

1.  从[`deno.land/logo.svg`](https://deno.land/logo.svg)开始请求：

    ```js
    fetch("https://deno.land/logo.svg")
    ```

1.  将其转换为`blob`：

    ```js
    fetch("https://deno.land/logo.svg")
      .then(r =>r.blob())
    ```

1.  从`blob`对象中获取文本并将其转换为`base64`：

    ```js
    fetch("https://deno.land/logo.svg ")
      .then(r =>r.blob())
      .then(async (img) => {
        const base64 = btoa(
          await img.text()
        )
    });
    ```

1.  向控制台打印一个包含图片标签的 HTML 页面，使用 Base64 图片：

    ```js
    fetch("https://deno.land/logo.svg ")
      .then(r =>r.blob())
      .then(async (img) => {
    const base64 = btoa(
          await img.text()
        )
        console.log(`<html>
    <img src="img/svg+xml;base64,${base64}" />
    </html>
        `
        )
      })
    ```

    当我们运行这个时，我们得到了预期的输出：

    ```js
    $ deno run --allow-net web-apis/fetch-deno-logo.js
    <html>
      <img src="data:image/svg+xml;base64,PHN2ZyBoZWlnaHQ9Ijgx My4xODQiIHdpZHRoPSI4MTMuMTUiIHhtbG5zPSJodHRwOi8vd3d3Lncz Lm9yZy8yMDAwL3N2ZyI+PGcgZmlsbD0iIzIyMiI+PHBhdGggZD0ibTM3 NC41NzUuMjA5Yy0xLjkuMi04IC45LTEzLjUgMS40LTc4LjIgOC4yLTE1 NS4yIDQxLjMtMjE4IDkzLjktMTEuNiA5LjYtMzggMzYtNDcuNiA0Ny42 LTUyIDYyLjEtODIuNCAxMzEuOC05My42IDIxNC4zLTIuNSAxOC4z
    …
    ```

现在，借助*nix 的输出重定向功能，我们可以用我们脚本的输出创建一个 HTML 文件：

```js
$ deno run --allow-net web-apis/fetch-deno-logo.js > web-apis/deno-logo.html
```

你现在可以检查这个文件，或者直接在浏览器中打开它来测试它是否有效。

你也可以运用前一章的知识，直接从 Deno 标准库运行一个脚本来服务当前文件夹：

```js
$ deno run --allow-net --allow-read https://deno.land/std@0.83.0/http/file_server.ts web-apis
Check https://deno.land/std@0.65.0/http/file_server.ts
HTTP server listening on http://0.0.0.0:4507
```

然后，通过导航到`http://localhost:4507/deno-logo.html`，我们可以检查图像是否在那里并且有效：

![图 3.1 - 使用 Base64 图像的 Deno.land 网页](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/deno-web-dev/img/Figure_3.1_B16380.jpg)

图 3.1 - 使用 Base64 图像的 Deno.land 网页

这些都是 Deno 支持的 Web API 的例子。在这个特定例子中，我们使用了`fetch`和`btoa`，但本章还将使用更多。

请随意实验这些熟悉的 API， either by writing simple scripts or by using the REPL。在本书的其余部分，我们将使用来自 Web APIs 的已知函数。在下一节中，我们将了解 Deno 命名空间，那些只在内置 Deno 中工作的函数，以及通常提供更多低级行为的功能。

# 探索 Deno 命名空间

所有未通过 Web API 覆盖的功能都位于 Deno 命名空间下。这些功能是 Deno 独有的，例如，不能被捆绑以在 Node 或浏览器中运行。

在本节中，我们将探索一些这个功能。我们将构建一些小工具，模仿你每天使用的程序。

如果你想在我们动手之前探索一下可用的函数，它们可以在[`doc.deno.land/builtin/stable`](https://doc.deno.land/builtin/stable)找到。

## 构建一个简单的 ls 命令

如果你曾经使用过*nix 系统的终端或者 Windows PowerShell，你可能对`ls`命令不陌生。简而言之，它列出了一个目录内的文件和文件夹。我们将要做的就是创建一个 Deno 工具，模仿`ls`的一些功能，也就是列出目录中的文件，并显示它们的一些详细信息。

原始命令有无数的标志，出于简洁原因，我们在这里不会实现。

我们决定显示的文件信息包括文件名、大小和最后修改日期。让我们开始动手：

1.  创建一个名为`list-file-names.js`的文件，并使用`Deno.readDir`获取当前目录中的所有文件和文件夹的列表：

    ```js
    for await (const dir of Deno.readDir(".")) {
      console.log(dir.name)
    }
    ```

    这将把当前目录中的文件打印在不同行上：

    ```js
    readDir (https://doc.deno.land/builtin/stable#Deno.readDir) from the Deno namespace.As is mentioned in the documentation, it returns `AsyncInterable`, which we're looping through and printing the name of the file. As the runtime is written in TypeScript, we have very useful type completion and we know exactly what properties are present in every `dir` entry.Now, we want to get the current directory as a command-line argument.
    ```

1.  使用`Deno.args`（https://doc.deno.land/builtin/stable#Deno.args）来获取命令行参数。如果没有发送参数，使用当前目录作为默认值：

    ```js
    const [path = "."] = Deno.args;
    for await (const dir of Deno.readDir(path)) {
      console.log(dir.name)
    }
    ```

    我们利用数组解构来获取`Deno.args`的第一个值，同时使用默认属性来设置`path`变量的默认值。

1.  导航到`demo-files`文件夹（[`github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter03/ls/demo-files`](https://github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter03/ls/demo-files)）并运行以下命令：

    ```js
    $ deno run --allow-read ../list-file-names.ts            
    file-with-no-content.txt
    .hidden-file
    lorem-ipsum.txt
    ```

    看起来它正在工作。它正在获取当前所在的文件夹中的文件并列出它们。

    现在我们需要获取文件信息以便显示它。

1.  使用`Deno.stat`（[`doc.deno.land/builtin/stable#Deno.stat`](https://doc.deno.land/builtin/stable#Deno.stat)）来获取有关文件的信息：

    ```js
    padEnd so that the output is aligned. By running the program we just wrote, while in the Chapter03/Is folder (https://github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter03/ls/demo-files), we get the following output:

    ```

    `deno run --allow-read index.ts ./demo-files`

    12   7/4  .hidden

    96   7/4  folder

    96   7/4  second-folder

    5    7/4  my-best-file

    20   7/4  .file1

    0    7/4  .hidden-file

    ```js

    ```

我们得到了作为参数发送的`deno-files`目录中的文件和文件夹列表，以及字节大小和创建的月份和日期。

在这里，我们使用已经知的必需的`--allow-read`标志来赋予 Deno 访问文件系统的权限。然而，在上一章中，我们提到了 Deno 程序请求权限的不同方式，我们称之为“动态权限”。接下来我们将学习这方面的内容。

## 使用动态权限

当我们自己编写 Deno 程序时，我们通常事先知道所需的权限。然而，当编写可能需要或不需要的权限的代码，或者编写交互式 CLI 工具时，一次性请求所有权限可能没有意义。这就是动态权限的目的。

动态权限允许程序在需要时请求权限，从而使得执行代码的人可以交互式地给予或拒绝特定的权限。

这是一个仍然不稳定的功能，因此其 API 可能会发生变化，但由于它所启用的潜在可能性，我认为它仍然值得提及。

您可以在[`doc.deno.land/builtin/unstable#Deno.permissions`](https://doc.deno.land/builtin/unstable#Deno.permissions)查看 Deno 的权限 API。

接下来我们要确保我们的`ls`程序请求文件系统的读取权限。让我们按照以下步骤进行：

1.  在使用程序之前，使用`Deno.permissions.request`来请求读取权限：

    ```js
    …
    const [path = "."] = Deno.args;
    await Deno.permissions.request({
      name: "read",
      path,
    });
    for await (const dir of Deno.readDir(path)) {
    …
    ```

    这请求了对程序将要运行的目录的权限。

1.  在当前目录下运行程序并授予权限：

    ```js
    g to the permission request command, we're granting it access to the current directory (.).We can now try to run the same program but denying the permissions this time.
    ```

1.  运行程序并在当前目录下拒绝读取权限：

    ```js
    $ deno run --unstable list-file-names-interactive-permissions.ts .
    Deno requests read access to ".". Grant? [g/d (g = grant, d = deny)] d
    error: Uncaught (in promise) PermissionDenied: read access to ".", run again with the --allow-read flag
        at processResponse (deno:core/core.js:223:11)
        at Object.jsonOpAsync (deno:core/core.js:240:12)
        at async Object.[Symbol.asyncIterator] (deno:cli/rt/30_fs.js:125:16)
        at async list-file-names-interactive-permissions.ts:10:18
    ```

    这就是动态权限的工作方式！

在这里，我们使用它们来控制文件系统的读取权限，但它们也可以用来请求运行时所有可用的权限（如第二章 *工具链*中所述）。在编写 CLI 应用程序时，它们非常有用，允许您交互式地调整正在运行的程序可以访问的权限。

## 使用文件系统 API

访问文件系统是我们编写程序时所需的基本需求之一。正如您在文档中可能已经看到的那样，Deno 提供了执行这些常见任务的 API。

决定与 Rust 核心标准化通信后，所有这些 API 都返回`Uint8Array`，解码和编码应由其消费者完成。这与 Node.js 有很大的不同，在 Node.js 中，一些函数返回转换后的格式，而其他函数则返回 blob、缓冲区等。

让我们探索这些文件系统 API 并读取一个文件的内容。

我们将使用`TextDecoder`和`Deno.readFile` API 读取位于[`github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter03/file-system/sentence.txt`](https://github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter03/file-system/sentence.txt)的示例文件，如下脚本所示：

```js
const decoder = new TextDecoder()
const content = await Deno.readFile('./sentence.txt');
console.log(decoder.decode(content))
```

您可以注意到我们使用了`TextDecoder`类，这是浏览器中存在的另一个 API。

不要忘记在运行脚本时使用`--allow-read`权限，以便它可以从文件系统中读取。

如果我们想将这个文件的内容写入另一个文件，我们可以使用`writeFile`：

```js
const content = await Deno.readFile("./sentence.txt");
await Deno.writeFile("./copied-sentence.txt", content)
```

请注意，由于我们使用从`readFile`获得的`Uint8Array`直接发送到`writeFile`方法，所以我们不再需要`TextEncoder`。记住在运行时使用`--allow-write`标志，因为它现在正在向文件系统写入。

正如你可能猜到的或在文档中读到的，Deno 正好提供了这样一个 API，即`copyFile`：

```js
await Deno.copyFile("./copied-sentence.txt", 
  "./using-copy-command.txt");
```

现在，你可能注意到了，我们在调用 Deno 命名空间函数时总是使用`await`。

Deno 上的所有异步操作都返回一个承诺，这是我们这样做的主要原因。我们本可以使用等效的`then`语法在那里处理结果，但我们认为这样更易读。

其他用于删除、重命名、更改权限等的 API 也包含在 Deno 命名空间中，您可以在文档中找到它们。

重要提示

Deno 中的许多异步 API 都有一个等效的*同步*API，可以用于特定用例，在这些用例中，您希望阻塞进程并获取结果（例如，`readFileSync`、`writeFileSync`等）。

## 使用缓冲区

缓冲区代表用于存储临时二进制数据的内存区域。它们通常用于处理 I/O 和网络操作。由于异步操作是 Deno 的优势之一，因此我们将在本节中探索缓冲区。

Deno 缓冲区与 Node 缓冲区不同。这是因为当 Node 被创建时，直到版本 4，JavaScript 中都没有对`ArrayBuffers`的支持。由于 Node 针对异步操作进行了优化（缓冲区真正闪耀的地方），其背后的团队不得不创建一个 Node 缓冲区来模拟本地缓冲区的行为。后来，`ArrayBuffers`被添加到语言中，Node 团队将现有的缓冲区迁移到利用它。目前它只是一个`ArrayBuffers`的子类。这个相同的缓冲区然后在 Node v10 中被弃用。由于 Deno 是最近创建的，它的缓冲区深度利用了`ArrayBuffer`。

## 从 Deno.Buffer 读写

Deno 提供了一个动态长度的缓冲区，它是基于`ArrayBuffer`的固定内存分配实现的。缓冲区提供了类似队列的功能，其中数据可以被不同的消费者写入和读取。正如我们最初提到的，它们在网络和 I/O 等任务中得到了广泛应用，因为它们允许异步读写。

举个例子，假设你有一个正在写一些日志的应用程序，你想处理这些日志。你可以同步地处理它们，也可以让这个应用程序将日志写入一个缓冲区，然后有一个消费者异步地处理这些日志。

让我们为那种情况写一个小的程序。我们将写两个简短的程序。第一个将模拟一个产生日志的应用程序；第二个将使用缓冲区来消费这些日志。

我们首先编写模拟应用程序产生日志的代码。在[`github.com/PacktPublishing/Deno-Web-Development/blob/master/Chapter03/buffers/logs/example-log.txt`](https://github.com/PacktPublishing/Deno-Web-Development/blob/master/Chapter03/buffers/logs/example-log.txt)，有一个文件，里面有一些示例日志我们将使用：

```js
const encoder = new TextEncoder();
const fileContents = await Deno.readFile("./example-log.txt ");
const decoder = new TextDecoder();
const logLines = decoder.decode(fileContents).split("\n");
export default function start(buffer: Deno.Buffer) {
  setInterval(() => {
     const randomLine = Math.floor(Math.min(Math.random() *        1000, logLines.length));
     buffer.write(encoder.encode(logLines[randomLine]));
  },   100)
}
```

这段代码从示例文件中读取内容并将其分割成行。然后，它获取一个随机的行号，每 100 毫秒将那一行写入一个缓冲区。这个文件然后导出一个函数，我们可以调用它来开始“生成随机日志”。我们将在下一个脚本中使用这个功能来模拟一个产生日志的应用程序。

现在来到了有趣的部分：我们将按照这些步骤编写一个基本的*日志处理器*：

1.  创建一个缓冲区，并将其发送给我们刚刚编写的日志生产者的`start`函数：

    ```js
    import start from "./logCreator.ts";
    const buffer = new Deno.Buffer();
    start(buffer);
    ```

1.  调用`processLogs`函数来开始处理缓冲区中的日志条目：

    ```js
    …
    start(buffer);
    processLogs();
    async function processLogs() {}
    ```

    正如你所看到的，`processLogs`函数会被调用，但是什么也不会发生，因为我们还没有实现一个程序来执行它。

1.  在`processLogs`函数内部创建一个`Uint8Array`对象类型，并在那里读取缓冲区的内容：

    ```js
    …
    async function processLogs() {
      const destination = new Uint8Array(100);
      const readBytes = await buffer.read(destination);
      if (readBytes) {
        // Something was read from the buffer
      }
    }
    ```

    文档（[`doc.deno.land/builtin/stable#Deno.Buffer`](https://doc.deno.land/builtin/stable#Deno.Buffer)）指出，当有东西要读取时，`Deno.Buffer`的`read`函数返回读取的字节数。当没有东西可读时，缓冲区为空，它返回 null。

1.  现在，在`if`内部，我们可以直接解码读取的内容，因为我们都知道它以`Uint8Array`格式存在：

    ```js
    const decoder = new TextDecoder();
    …  
    if (readBytes) {
      const read = decoder.decode(destination);
    }
    ```

1.  要在控制台上打印解码值，我们可以使用已知的`console.log`。我们还可以用不同的方式来实现，通过使用`Deno.stdout`（[`doc.deno.land/builtin/stable#Deno.stdout`](https://doc.deno.land/builtin/stable#Deno.stdout)）向标准输出写入。

    `Deno.stdout`是 Deno 中的一个`writer`对象([`doc.deno.land/builtin/stable#Deno.Writer`](https://doc.deno.land/builtin/stable#Deno.Writer))。我们可以使用它的`write`方法将文本发送到那里：

    ```js
    const decoder = new TextDecoder();
    const encoder = new TextEncoder();
    …  
    if (readBytes) {
      const read = decoder.decode(destination);
      await Deno.stdout.write(encoder.encode(`${read}\n`));
    }
    ```

    通过这样做，我们正在向`Deno.stdout`写入刚刚读取的值，并且在末尾添加一个换行符（`\n`），以便在控制台上更具可读性。

    如果我们保持这种方式，这个`processLogs`函数将只运行一次。由于我们希望在稍后再次运行此函数以检查`buffer`中是否还有更多日志，我们需要安排它稍后再次运行。

1.  使用`setTimeout`在 100 毫秒后调用相同的`processLogs`函数：

    ```js
    async function processLogs() {
      const destination = new Uint8Array(100);
      const readBytes = await buffer.read(destination);
      if (readBytes) {
        …
      }
      setTimeout(processLogs, 10);
    }
    ```

例如，如果我们打开`example-log.txt`文件，我们可以看到包含以下格式的日期的行：`Thu Aug 20 22:14:31 WEST 2020`。

让我们想象我们只是想打印出带有`Tue`的日志。让我们来写一下实现这个功能的逻辑：

```js
async function processLogs() {
  const destination = new Uint8Array(100);
  const readBytes = await buffer.read(destination);
  if (readBytes) {
    const read = decoder.decode(destination);
    if (read.includes("Tue")) {
      await Deno.stdout.write(encoder.encode(`${read}\n`));
    }
  }
  setTimeout(processLogs, 10);
}  
```

然后，我们在包含`example-logs.txt`文件的文件夹内执行程序：

```js
$ deno run --allow-read index.ts
Tue Aug 20 17:12:05 WEST 2019
Tue Sep 17 02:19:56 WEST 2019
Tue Dec  3 14:02:01 CET 2019
Tue Jul 21 10:37:26 WEST 2020
```

带有日期的日志行如实地从缓冲区中读取并符合我们的条件。

这是一个关于缓冲区可以做什么的简短演示。我们能够异步地从缓冲区读取和写入。这种方法允许，例如，消费者在应用程序读取其他部分的同时处理文件的一部分。

Deno 命名空间提供了比这里尝试的更多功能。在本节中，我们决定挑选几个部分给你一个启示，看看它启用了多少功能。

在*第四章*，*构建 Web 应用程序*及以后，我们将使用这些函数，以及第三方模块和标准库来编写我们的 Web 服务器。

# 使用标准库

在本节中，我们将探讨由 Deno 的标准库提供的行为。目前，这个标准库不被运行时认为是稳定的，因此模块是单独版本化的。在我们撰写本文时，标准库处于*版本 0.83.0*。

如我们之前提到的，Deno 在向标准库添加内容方面非常慎重。核心团队希望它提供足够的行为，这样人们就不需要依赖数百万个外部包来完成某些事情，但同时也不想添加过多的 API 表面。这是一个难以达到的微妙平衡。

受到 golang 的启发，Deno 标准库的大部分函数模仿了谷歌创建的语言。这是因为 Deno 团队真心相信*golang*如何发展其标准库，一个以打磨得非常好而闻名的库。作为一个有趣的注解，Ryan Dahl（Deno 和 Node 的创建者）在他的某次演讲中提到，当拉取请求向标准库添加新的 API 时，会要求提供相应的*golang*实现。

我们不会遍历整个库，原因与我们没有遍历整个 Deno 命名空间一样。我们将通过构建一些有用的程序来学习它所能提供的功能。我们将从生成 ID、日志记录、HTTP 通信等知名用例开始。

## 为我们的简单 ls 添加颜色

几页之前，我们在*nix 系统中构建了一个非常粗糙简单的`ls`命令的“克隆”。当时我们列出了文件，以及它们的大小和修改日期。

为了开始探索标准库，我们打算给该程序的终端输出添加一些着色。让我们使文件夹名称以红色打印，这样我们就可以轻松地区分它们。

我们将创建一个名为`list-file-names-color.ts`的文件。这次我们将使用 TypeScript，因为我们将得到更好的补全功能，因为标准库和 Deno 命名空间函数都是为了这个目的而编写的。

让我们探索一下标准库函数，它们允许我们给文本着色（https://deno.land/std@0.83.0/fmt/colors.ts）。

如果我们想查看一个模块的文档，我们可以直接查看代码，但我们也可以使用`doc`命令或文档网站。我们将使用后者。

导航到 https://doc.deno.land/https/deno.land/std@0.83.0/fmt/colors.ts。屏幕上列出了所有可用的方法：

1.  从标准库的格式化库中导入打印红色文本的方法：

    ```js
    import { red } from "https://deno.land/std@0.83.0/fmt/colors.ts";
    ```

1.  在我们的`async`迭代器中使用它，该迭代器正在遍历当前目录中的文件：

    ```js
    const [path = "."] = Deno.args;
    for await (const item of Deno.readDir(path)) {
      if (item.isDirectory) {
        console.log(red(item.name));
      } else {
        console.log(item.name);
      }
    }
    ```

1.  在`demo-files`文件夹内运行它（[`github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter03/ls`](https://github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter03/ls)），我们得到的文件夹以红色显示（这在打印的书里看不到，但你可以本地运行它）：

    ```js
    $ deno run –allow-read list-file-names-color.ts
    file-with-no-content.txt
    demo-folder
    .hidden-file
    lorem-ipsum.txt
    ```

现在我们有一个更好的`ls`命令，它让我们能够通过标准库的着色函数区分文件夹和文件。在本书的过程中，我们将查看标准库提供的许多其他模块。其中一些将在我们开始编写自己的应用程序时使用。

我们将特别关注的一个模块是 HTTP 模块，从下一节开始我们将大量使用它。

# 使用 HTTP 模块构建 Web 服务器

本书的主要内容，以及介绍 Deno 以及如何使用它，是学习如何使用它来构建 Web 应用程序。在这里，我们将创建一个简单的 JSON API 来向您介绍 HTTP 模块。

我们将构建一个 API，用于保存和列出便签。我们将这些便签称为 post-its。想象一下，这个 API 将喂养你的 post-its 板。

我们将使用 Web API 和 Deno 标准库 HTTP 模块中的函数创建一个非常简单的路由系统。记住，我们这样做是为了探索 API 本身，所以这并不是生产就绪的代码。

让我们先创建一个名为`post-it-api`的文件夹和一个名为`index.ts`的文件。再次，我们将使用 TypeScript，因为我们相信自动完成和类型检查功能可以大大提高我们的体验并减少可能的错误数量。

本节最终的代码可以在[`github.com/PacktPublishing/Deno-Web-Development/blob/master/Chapter03/post-it-api/steps/7.ts`](https://github.com/PacktPublishing/Deno-Web-Development/blob/master/Chapter03/post-it-api/steps/7.ts)找到：

1.  首先，将标准库 HTTP 模块导入我们的文件中：

    ```js
    import { serve } from
      "https://deno.land/std@0.83.0/http/server.ts";
    ```

1.  使用`AsyncIterator`编写处理请求的逻辑，就像我们之前的例子中所做的那样：

    ```js
    console.log("Server running at port 8080");
    for await (const req of serve({ port: 8080 })) {
      req.respond({ body: "post-it api", status: 200 });
    }
    ```

    如果我们现在运行它，这就是我们会得到的。记住，为了让它具有网络访问权限，我们需要使用在权限部分提到的`--allow-net`标志：

    ```js
    deno run --allow-net index.ts
    Server running at port 8080
    ```

1.  为了清晰起见，我们可以将端口和服务器实例提取到单独的变量中：

    ```js
    const PORT = 8080;
    const server = serve({ port: PORT });
    console.log("Server running at port", PORT);
    for await (const req of serve({ port: PORT })) {
    …
    ```

我们现在有了一个运行中的服务器，和之前一样，唯一的区别是现在代码（可以说）因为将配置变量放在文件顶部而更加可读。我们稍后会学习如何从代码中提取这些变量。

### 返回便签列表

我们的第一个要求是我们有一个返回便签列表的 API。这些便签将包括名称、标题和创建日期。在我们到达那里之前，为了使我们能够有多个路由，我们需要一个路由系统。

为了进行这个练习，我们将自己构建一个。这是我们了解 Deno 中一些内置 API 的方式。稍后我们会同意，在编写生产应用程序时，有时最好重用经过测试和广泛使用的软件，而不是不断重新发明轮子。然而，为了学习目的，完全重新发明轮子是可以的。

为了创建我们的基本路由系统，我们将使用一些您可能在浏览器中知道的 API。例如`URL`、`UrlSearchParams`等对象。

我们的目标是能够通过其 URL 和路径定义一个路由。类似`GET /api/post-its`这样的东西会很好。让我们这样做！

1.  首先，创建一个`URL`对象（[`developer.mozilla.org/en-US/docs/Web/API/URL`](https://developer.mozilla.org/en-US/docs/Web/API/URL)）来帮助我们解析 URL 和其参数。我们将`HOST`和`PROTOCOL`提取到另一个变量中，这样我们就不用重复了：

    ```js
    const PORT = 8080;
    const HOST = "localhost";
    const PROTOCOL = "http";
    const server = serve({ port: PORT, hostname: HOST });
    console.log(`Server running at ${HOST}:${PORT}`);
    for await (const req of server) {
      const url = new
        URL(`${PROTOCOL}://${HOST}${req.url}`);
      req.respond({ body: "post-it api", status: 200 });
    }
    ```

1.  使用创建的`URL`对象进行一些路由。我们将使用`switch case`来实现。当没有匹配的路由时，应该向客户端发送`404`：

    ```js
      const pathWithMethod = `${req.method} ${url.pathname}`;
      switch (pathWithMethod) {
        case "GET /api/post-its":
          req.respond({ body: "list of all the post-its",
            status: 200 });
          continue;
        default:
          req.respond({ status: 404 });
      } 
    ```

    提示

    您可以同时在运行脚本时使用`--unstable`和`--watch`标志，以在文件更改时重新启动它：`deno run --allow-net --watch --unstable index.ts`。

1.  访问`http://localhost:8080/api/post-its`，并确认我们得到了正确的响应。其他任何路由都会得到 404 响应。

    请注意，我们使用`continue`关键字让 Deno 在响应请求后跳出当前迭代（记住我们正在`for`循环内）。

    您可能已经注意到，目前我们只是按路径路由，而不是按方法路由。这意味着对`/api/post-its`的任何请求，无论是`POST`还是`GET`，都会得到相同的响应。让我们通过前进来解决这个问题。

1.  创建一个包含请求方法和路径名的变量：

    ```js
      const pathWithMethod = `${req.method} ${url.pathname}`
      switch (pathWithMethod) {
    ```

    现在我们可以定义我们想要的路线，`GET /api/post-its`。现在我们已经有了我们路由系统的基本知识，我们将编写返回便签的逻辑。

1.  创建一个 TypeScript 接口，以帮助我们保持便签的结构：

    ```js
    interface PostIt {
      title: string,
      id: string,
      body: string,
      createdAt: Date
    }
    ```

1.  创建一个变量，作为我们这次练习的*内存数据库*。

    我们将使用一个 JavaScript 对象，其中键是 ID，值是刚刚定义的`PostIt`类型的对象：

    ```js
    let postIts: Record<PostIt["id"], PostIt> = {}
    ```

1.  向我们的数据库添加几个测试数据：

    ```js
    let postIts: Record<PostIt["id"], PostIt> = {
      '3209ebc7-b3b4-4555-88b1-b64b33d507ab': { title: 'Read more', body: 'PacktPub books', id: 3209ebc7-b3b4-4555-88b1-b64b33d507ab ', createdAt: new Date() },
      'a1afee4a-b078-4eff-8ca6-06b3722eee2c': { title: 'Finish book', body: 'Deno Web Development', id: '3209ebc7-b3b4-4555-88b1-b64b33d507ab ', createdAt: new Date() }
    }
    ```

    请注意，我们目前是*手动生成*ID 的。稍后，我们将使用标准库的另一个模块来完成。让我们回到我们的 API，并更改处理路由的`case`。

1.  更改返回所有便签的`case`，而不是硬编码的消息。

    由于我们的数据库是一个键/值存储，我们需要使用`reduce`来构建一个包含所有便签的数组（删除代码块中高亮的行）：

    ```js
    case GET "/api/post-its":
      req.respond({ body: "list of all the post-its", status:     200 });
      const allPostIts = Object.keys(postIts).
        reduce((allPostIts: PostIt[], postItId) => {
            return allPostIts.concat(postIts[postItId]);
          }, []);
      req.respond({ body: JSON.stringify({ postIts:     allPostIts }) });
      continue;
    ```

1.  运行代码并访问`/api/post-its`。我们应该在那里看到我们的便签列表！

    您可能已经注意到，这仍然不是 100%正确的，因为我们的 API 返回的是 JSON，而其头部与载荷不匹配。

1.  我们将通过使用我们来自浏览器的 API——`Headers`对象——来添加`content-type`（https://developer.mozilla.org/en-US/docs/Web/API/Headers）。删除以下代码块中高亮的行：

    ```js
    const headers = new Headers();
    headers.set("content-type", "application/json");
    const pathWithMethod = `${req.method} ${url.pathname}`
    switch (pathWithMethod) {
      case "GET /api/post-its":
    …
        req.respond({ body: JSON.stringify({ postIts: 
          allPostIts }) });
        req.respond({ headers, body: JSON.stringify({ 
          postIts: allPostIts }) });
        continue;
    ```

我们已经创建了一个`Headers`对象的实例，然后我们在`req.respond`上使用了它。这样，我们的 API 现在变得更加一致、易消化，并遵循标准。

### 向数据库添加一个便签

现在我们已经有了读取便签的方法，我们还需要一种添加新便签的方法，因为拥有一个完全静态内容的 API 并没有多大意义。这就是我们将要做的。

我们将使用我们创建的*路由基础设施*来添加一个允许我们*插入*记录到我们数据库的路由。由于我们遵循 REST 指南，该路由将位于列出`post-its`的路径上，但方法不同：

1.  定义一个总是返回`201`状态码的路由：

    ```js
        case "POST /api/post-its":
          req.respond({ status: 201 });
          continue
    ```

1.  使用`curl`的帮助，测试它，我们可以看到它返回了正确的状态码：

    ```js
    curl but feel free to use your favorite HTTP requests tool, you can even use a graphical client such as Postman (https://www.postman.com/).Let's make the new route do what it is supposed to. It should get a JSON payload and use that to create a new post-it.We know, by looking at the documentation of the standard library's HTTP module (`doc.deno.land/https/deno.land/std@0.83.0/http/server.ts#ServerRequest`) that the body of the request is a *Reader* object. The documentation includes an example on how to read from it.
    ```

1.  按照建议，读取值并打印出来以更好地理解它：

    ```js
    case "POST /api/post-its":
          const body = await Deno.readAll(req.body);
          console.log(body) 
    ```

1.  使用`curl`的帮助，用`body`发送请求：

    ```js
    201 status code. If we look at our running server though, something like this is printed to the console:

    ```

    Uint8Array(25) [

    123,  34, 116, 105, 116, 108, 101,

    34,58,32,34,84,   101, 115,

    116,  32, 112, 111, 115, 116,  45,

    105, 116,  34, 125

    ]

    ```js

    We previously learned that Deno uses `Uint8Array` to do all its communications with the Rust backend, and this is not an exception. However, `Uint8Array` is not what we currently want, we want the actual text of the request body. 
    ```

1.  使用`TextDecoder`将请求体作为可读值获取。这样做之后，我们再次记录输出，然后我们将发送一个新的请求：

    ```js
    $ deno -X POST -d "{\"title\": \"Buy milk\"}" 
    http://localhost:8080/api/post-its
    ```

    这次服务器在控制台打印的内容如下：

    ```js
    {"title": "Buy milk "}
    ```

    我们正在取得进展！

1.  由于主体是一个字符串，我们需要将其解析为 JavaScript 对象。我们将使用我们的一位老朋友，`JSON.parse`：

    ```js
    const decoded = JSON.parse(new 
      TextDecoder().decode(body));
    ```

    现在我们的请求体以一种我们可以操作的格式存在，这就是我们创建新数据库记录所需要做的全部工作。让我们按照以下步骤创建一个：

1.  使用标准库中的`uuid`模块（[`deno.land/std@0.83.0/uuid`](https://deno.land/std@0.83.0/uuid)）为我们的记录生成一个随机的 UUID：

    ```js
    import { v4 } from 
      "https://deno.land/std/uuid/mod.ts";
    ```

1.  在我们的路由的 switch case 中，我们将使用`generate`方法创建一个`id`并将其插入到*数据库*中，在用户在请求负载中发送的内容顶部添加`createdAt`日期。为了这个例子，我们省略了验证：

    ```js
    case "POST /api/post-its":
    …
        const decoded = JSON.parse(new 
          TextDecoder().decode(body));
        const id = v4.generate();
        postIts[id] = {
          ...decoded,
          id,
          createdAt: new Date()
        }
        req.respond({ status: 201, body:
          JSON.stringify(postIts[id]), headers });
    ```

    注意我们在这里使用的是之前定义的同一个`headers`对象（在`GET`路由中），这样我们的 API 就会返回`Content-Type: application/json`。

    然后，再次遵循*REST*指南，我们返回`201` `Created`代码和创建的记录。

1.  保存代码，重新启动服务器，再次运行它：

    ```js
    GET request to the route that lists all the post-its to check if the record was actually inserted into the database:

    ```

    $ curl http://localhost:8080/api/post-its

    {"postIts":[{"title":"Read more","body":"PacktPub books","id":"3209ebc7-b3b4-4555-88b1-b64b33d507ab","createdAt":"2021-01-10T16:28:52.210Z"},{"title":"Finish book","body":"Deno Web Development","id":"a1afee4a-b078-4eff-8ca6-06b3722eee2c","createdAt":"2021-01-10T16:28:52.210Z"},{"title":"Buy groceries","body":"1 x Milk","id":"b35b0a62-4519-4491-9ba9-b5809b4810d5","createdAt":"2021-01-10T16:29:05.519Z"}]}

    ```js

    ```

而且它奏效了！现在我们有一个 API 可以返回并添加 post-its 到列表中。

这基本上结束了我们在这个章节中使用 HTTP 模块进行 API 所做的工作。像我们写的这个 API 一样，大多数 API 都是为了被前端应用程序消费而创建的，我们来做这件事来结束这个章节。

### 服务于前端

由于这超出了本书的范围，我们不会编写与该 API 交互的前端代码。然而，如果你想用它来获取便签并显示在一个单页应用程序上，我在书中的文件中包含了一个（[`github.com/PacktPublishing/Deno-Web-Development/blob/master/Chapter03/post-it-api/index.html`](https://github.com/PacktPublishing/Deno-Web-Development/blob/master/Chapter03/post-it-api/index.html)）。

我们将学习如何使用我们刚刚构建的 Web 服务器来提供 HTML 文件：

1.  首先，我们需要在服务器的根目录下创建一个路由。然后，我们需要设置正确的`Content-Type`，并使用已知的文件系统 API 返回文件内容。

    为了获取当前文件相对于 HTML 文件的路径，我们将使用 URL 对象和 JavaScript 的`import.meta`声明（[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/import.meta`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/import.meta)），其中包含当前文件的路径：

    ```js
    resolve, and fromFileUrl methods from Deno's standard-library to get a URL that is relative to the current file.Note that we now need to run this with the `--allow-read` flag since our code is reading from the filesystem. 
    ```

1.  为了让我们更安全，我们将指定程序可以读取的确切文件夹，通过将其传递给`--allow-read`标志：

    ```js
    $ deno run --allow-net --allow-read=. index.ts
    Server running at http://0.0.0.0:8080 
    ```

    这将防止任何可能允许恶意人士读取我们文件系统的错误。

1.  用浏览器访问该 URL，你应该会来到一个可以看到我们添加的便签`post-its`的页面。要添加一个新的，你也可以点击**添加新便签**文字并填写表单：

![图 3.2 – 前端消费便签 API](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/deno-web-dev/img/Figure_3.2_B16380.jpg)

](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/deno-web-dev/img/Figure_3.2_B16380.jpg)

图 3.2 – 前端消费便签 API

重要提示

请记住，在许多生产环境中，不推荐 API 为前端代码提供服务。在这里，我们这样做是为了学习目的，这样我们才能理解标准库 HTTP 模块的一些可能性。

在本节中，我们学习了如何利用标准库提供的模块。我们制作了一个`ls`命令的简单版本，并使用标准库的输出格式化函数给它添加了一些颜色。为了结束这一节，我们制作了一个具有几个端点的 HTTP API，用于列出和持久化记录。我们讨论了不同的需求，并学习了 Deno 如何实现它们。

# 总结

随着我们对本书的阅读，我们对 Deno 的了解变得更加实用，我们开始用它来处理更接近现实世界的用例。这一章就是关于这个的。

我们首先学习了运行时的基本特性，即程序生命周期，以及 Deno 如何看待模块稳定性和版本控制。我们很快转向了 Deno 提供的 Web API，通过编写一个简单的程序，从网站上获取 Deno 徽标，将其转换为 base64，并将其放入 HTML 页面中。

然后，我们进入了`Deno`命名空间，探索了一些其底层功能。我们使用文件系统 API 构建了几个示例，并最终用它构建了一个`ls`命令的简化版。

缓冲区是在 Node.js 世界中大量使用的东西，它们能够执行异步读写行为。正如我们所知，Deno 与 Node.js 有很多相同的用例，这使得在这一章节中不谈论缓冲区变得不可能。我们首先解释了 Deno 缓冲区与 Node.js 的区别，然后构建了一个小应用程序，它能够异步地从它们中读取和写入。

为了结束这一章节，我们更接近了这本书的主要目标之一，即使用 Deno 进行网络开发。我们使用 Deno 创建了第一个 JSON API。在这个过程中，我们了解了多个 Deno API，甚至构建了我们的基本路由系统。然后，我们创建了几个路由，列出并创建了我们的*数据存储*中的记录。在本章即将结束时，我们学习了如何处理 API 中的头部，并将其添加到我们的端点中。

我们结束了这一章节，通过我们的网络服务器直接提供了一个单页应用程序；这个单页应用程序消费并与我们 API 进行了交互。

这一章我们覆盖了很多内容。我们开始构建 API，这些 API 现在比我们之前所做的更接近现实。我们还更清楚地了解了使用 Deno 开发、使用权限和文档的感觉。

当前章节结束了我们的入门之旅，希望它让你对接下来的内容感到好奇。

在接下来的四章中，我们将构建一个网络应用程序，并探索在这一过程中所做的所有决定。到目前为止你所学的的大部分知识将在后面用到，但也有很多新的、令人兴奋的内容。在下一章，我们将开始创建一个 API，随着章节的进行，我们将继续为其添加功能。

我希望你能加入我们！
