# NodeJS Web 开发第五版（一）

> 原文：[`zh.annas-archive.org/md5/E4F616CD5ADA487AF57868CB589CA6CA`](https://zh.annas-archive.org/md5/E4F616CD5ADA487AF57868CB589CA6CA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

前言

Node.js 是一个服务器端的 JavaScript 平台，允许开发人员在网页浏览器之外使用 JavaScript 构建快速可扩展的应用程序。它在软件开发世界中扮演着越来越重要的角色，最初作为服务器应用程序的平台，但现在在命令行开发工具甚至 GUI 应用程序中得到广泛应用，这要归功于 Electron 等工具包。Node.js 已经将 JavaScript 从浏览器中解放出来。

它运行在谷歌 Chrome 浏览器核心的超快 JavaScript 引擎 V8 之上。Node.js 运行时遵循一个巧妙的事件驱动模型，尽管使用单线程模型，但在并发处理能力方面被广泛使用。

Node.js 的主要重点是高性能、高可扩展性的 Web 应用程序，但它也在其他领域得到了应用。例如，基于 Node.js 的 Electron 包装了 Chrome 引擎，让 Node.js 开发人员可以创建桌面 GUI 应用程序，并成为许多热门应用程序的基础，包括 Atom 和 Visual Studio Code 编辑器、GitKraken、Postman、Etcher 和桌面版 Slack 客户端。Node.js 在物联网设备上很受欢迎。它的架构特别适合微服务开发，并经常帮助构建全栈应用程序的服务器端。

在单线程系统上提供高吞吐量的关键是 Node.js 的异步执行模型。这与依赖线程进行并发编程的平台非常不同，因为这些系统通常具有很高的开销和复杂性。相比之下，Node.js 使用一个简单的事件分发模型，最初依赖回调函数，但今天依赖 JavaScript Promise 对象和 async 函数。

由于 Node.js 建立在 Chrome 的 V8 引擎之上，该平台能够快速采用 JavaScript 语言的最新进展。Node.js 核心团队与 V8 团队密切合作，让它能够快速采用 V8 中实现的新 JavaScript 语言特性。Node.js 14.x 是当前版本，本书是针对该版本编写的。

# 第一章：这本书适合谁

服务器端工程师可能会发现 JavaScript 是一种优秀的替代编程语言。由于语言的进步，JavaScript 早就不再是一种只适用于在浏览器中为按钮添加动画效果的简单玩具语言。我们现在可以使用这种语言构建大型系统，而 Node.js 具有许多内置功能，比如一流的模块系统，可以帮助开发更大的项目。

有经验的浏览器端 JavaScript 开发人员可能会发现通过本书扩展视野，包括使用服务器端开发。

# 本书内容

《第一章》《关于 Node.js》介绍了 Node.js 平台。它涵盖了 Node.js 的用途、技术架构选择、历史、服务器端 JavaScript 的历史、JavaScript 应该从浏览器中解放出来以及 JavaScript 领域的重要最新进展。

《第二章》《设置 Node.js》介绍了如何设置 Node.js 开发环境。这包括在 Windows、macOS 和 Linux 上安装 Node.js。还介绍了一些重要的工具，包括`npm`和`yarn`包管理系统，以及用于将现代 JavaScript 转译为在旧 JavaScript 实现上可运行形式的 Babel。

《第三章》《探索 Node.js 模块》深入探讨了模块作为 Node.js 应用程序中的模块化单元。我们将深入了解和开发 Node.js 模块，并使用`npm`来维护依赖关系。我们将了解新的模块格式 ES6 模块，以及如何在 Node.js 中使用它，因为它现在得到了原生支持。

第四章，“HTTP 服务器和客户端”，开始探索 Node.js 的 Web 开发。我们将在 Node.js 中开发几个小型 Web 服务器和客户端应用程序。我们将使用斐波那契算法来探索重型、长时间运行计算对 Node.js 应用程序的影响。我们还将学习几种缓解策略，并获得我们开发 REST 服务的第一次经验。

第五章，“你的第一个 Express 应用程序”，开始了本书的主要旅程，即开发一个用于创建和编辑笔记的应用程序。在本章中，我们运行了一个基本的笔记应用程序，并开始使用 Express 框架。

第六章，“实现移动优先范式”，使用 Bootstrap V4 框架在笔记应用程序中实现响应式 Web 设计。这包括集成流行的图标集以及自定义 Bootstrap 所需的步骤。

第七章，“数据存储和检索”，探索了几种数据库引擎和一种可以轻松切换数据库的方法。目标是将数据稳健地持久化到磁盘。

第八章，“使用微服务对用户进行身份验证”，为笔记应用程序添加了用户身份验证。我们将学习使用 PassportJS 处理登录和注销。身份验证既支持本地存储的用户凭据，也支持使用 Twitter 的 OAuth。

第九章，“使用 Socket.IO 进行动态客户端/服务器交互”，让我们看看如何让用户实时交流。我们将使用 Socket.IO 这个流行的框架来支持内容的动态更新和简单的评论系统。所有内容都是由用户在伪实时中动态更新的，这给了我们学习实时动态更新的机会。

第十章，“将 Node.js 应用部署到 Linux 服务器”，是我们开始部署旅程的地方。在本章中，我们将使用传统的方法在 Ubuntu 上使用 Systemd 部署后台服务。

第十一章，“使用 Docker 部署 Node.js 微服务”，让我们开始探索使用 Docker 进行基于云的部署，将笔记应用程序视为一组微服务的集群。

第十二章，“使用 Terraform 在 AWS EC2 上部署 Docker Swarm”，让我们看看如何构建一个使用 AWS EC2 系统的云托管系统。我们将使用流行的工具 Terraform 来创建和管理 EC2 集群，并学习如何几乎完全自动化使用 Terraform 功能部署 Docker Swarm 集群。

第十三章，“单元测试和功能测试”，让我们探索三种测试模式：单元测试、REST 测试和功能测试。我们将使用流行的测试框架 Mocha 和 Chai 来驱动这三种模式的测试用例。对于功能测试，我们将使用 Puppeteer，这是一个在 Chrome 实例中自动化测试执行的流行框架。

第十四章，“Node.js 应用程序中的安全性”，是我们集成安全技术和工具以减轻安全入侵的地方。我们将首先在 AWS EC2 部署中使用 Let's Encrypt 实现 HTTPS。然后，我们将讨论 Node.js 中的几种工具来实现安全设置，并讨论 Docker 和 AWS 环境的最佳安全实践。

# 为了充分利用本书

基本要求是安装 Node.js 并拥有面向程序员的文本编辑器。编辑器不必太复杂；即使是 vi/vim 也可以。我们将向您展示如何安装所需的一切，而且这些都是开源的，因此没有任何准入障碍。

最重要的工具是您的大脑，我们指的不是耳屎。

| **书中涵盖的软件/硬件** **操作系统要求** |
| --- |
| Node.js 及相关框架，如 Express、Sequelize 和 Socket.IO |
| 使用`npm`/`yarn`软件包管理工具 |
| Python 和 C/C++编译器 |
| MySQL、SQLite3 和 MongoDB 数据库 |
| Docker |
| Multipass |
| Terraform |
| Mocha 和 Chai |

每个涉及的软件都是 readily available。对于 Windows 和 macOS 上的 C/C++编译器，您需要获取 Visual Studio（Windows）或 Xcode（macOS），但两者都是免费提供的。

如果您已经有一些 JavaScript 编程经验，这将会很有帮助。如果您已经有其他编程语言的经验，学习它会相当容易。

## 下载示例代码文件

尽管我们希望书中和存储库中的代码片段是相同的，但在某些地方可能会有细微差异。存储库中可能包含书中未显示的注释、调试语句或替代实现（已注释掉）。

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](https://www.packtpub.com/support)并注册，文件将直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)登录或注册。

1.  选择支持选项卡。

1.  单击代码下载。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用以下最新版本的软件解压或提取文件夹：

+   Windows 上的 WinRAR/7-Zip

+   Mac 上的 Zipeg/iZip/UnRarX

+   Linux 上的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Node.js-Web-Development-Fifth-Edition`](https://github.com/PacktPublishing/Node.js-Web-Development-Fifth-Edition)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自丰富书籍和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。快去看看吧！

## 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码字、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。例如："首先更改`package.json`，使其具有以下`scripts`部分。"

代码块设置如下：

```

When we wish to draw your attention to a particular part of a code block, the relevant lines or items are set in bold:

```

任何命令行输入或输出都以以下形式编写：

```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中以这种方式出现。例如："单击提交按钮。"

警告或重要说明看起来像这样。

提示和技巧看起来像这样。


# 第二章

第一部分：Node.js 简介

这是对 Node.js 领域的高层概述。读者将已经迈出了使用 Node.js 的第一步。

本节包括以下章节：

+   第一章，*关于 Node.js*

+   第二章，*设置 Node.js*

+   第三章，*探索 Node.js 模块*

+   第四章，*HTTP 服务器和客户端*


关于 Node.js

JavaScript 是每个前端 Web 开发人员的得心应手，使其成为一种非常流行的编程语言，以至于被刻板地认为是用于 Web 页面中的客户端代码。有可能，拿起这本书的时候，你已经听说过 Node.js，这是一个用于在 Web 浏览器之外编写 JavaScript 代码的编程平台。现在大约有十年的历史，Node.js 正在成为一个成熟的编程平台，在大大小小的项目中被广泛使用。

本书将为您介绍 Node.js。通过本书，您将学习使用 Node.js 开发服务器端 Web 应用程序的完整生命周期，从概念到部署和安全性。在撰写本书时，我们假设以下内容：

+   你已经知道如何编写软件。

+   你熟悉 JavaScript。

+   你对其他语言中开发 Web 应用程序有所了解。

当我们评估一个新的编程工具时，我们是因为它是流行的新工具而抓住它吗？也许我们中的一些人会这样做，但成熟的方法是将一个工具与另一个工具进行比较。这就是本章的内容，介绍使用 Node.js 的技术基础。在着手编写代码之前，我们必须考虑 Node.js 是什么，以及它如何适应软件开发工具的整体市场。然后我们将立即着手开发工作应用程序，并认识到通常学习的最佳方式是通过在工作代码中进行搜索。

我们将在本章中涵盖以下主题：

+   Node.js 简介

+   Node.js 可以做什么

+   为什么你应该使用 Node.js

+   Node.js 的架构

+   使用 Node.js 的性能、利用率和可扩展性

+   Node.js、微服务架构和测试

+   使用 Node.js 实现十二要素应用程序模型

# 第三章：Node.js 概述

Node.js 是一个令人兴奋的新平台，用于开发 Web 应用程序、应用服务器、任何类型的网络服务器或客户端以及通用编程。它旨在通过服务器端 JavaScript、异步 I/O 和异步编程的巧妙组合，在网络应用程序中实现极端可扩展性。

尽管只有十年的历史，Node.js 迅速崭露头角，现在正发挥着重要作用。无论是大公司还是小公司，都在大规模和小规模项目中使用它。例如，PayPal 已经将许多服务从 Java 转换为 Node.js。

Node.js 的架构与其他应用平台通常选择的方式有所不同。在其他应用平台中，线程被广泛使用来扩展应用程序以填充 CPU，而 Node.js 则避免使用线程，因为线程具有固有的复杂性。据称，采用单线程事件驱动架构，内存占用低，吞吐量高，负载下的延迟配置文件更好，并且编程模型更简单。Node.js 平台正处于快速增长阶段，许多人认为它是传统的使用 Java、PHP、Python 或 Ruby on Rails 的 Web 应用程序架构的一个引人注目的替代方案。

在其核心，它是一个独立的 JavaScript 引擎，具有适用于通用编程的扩展，并且专注于应用服务器开发。尽管我们正在将 Node.js 与应用服务器平台进行比较，但它并不是一个应用服务器。相反，Node.js 是一个类似于 Python、Go 或 Java SE 的编程运行时。虽然有一些用 Node.js 编写的 Web 应用程序框架和应用服务器，但它只是一个执行 JavaScript 程序的系统。

关键的架构选择是 Node.js 是事件驱动的，而不是多线程的。Node.js 架构基于将阻塞操作分派到单线程事件循环，结果以调用事件处理程序的事件返回给调用者。在大多数情况下，事件被转换为由`async`函数处理的 promise。由于 Node.js 基于 Chrome 的 V8 JavaScript 引擎，Chrome 中实现的性能和功能改进很快就会流入 Node.js 平台。

Node.js 核心模块足够通用，可以实现执行任何 TCP 或 UDP 协议的服务器，无论是 DNS、HTTP、互联网中继聊天（IRC）还是 FTP。虽然它支持互联网服务器或客户端的开发，但它最大的用例是常规网站开发，取代了像 Apache/PHP 或 Rails 堆栈这样的技术，或者作为现有网站的补充，例如，使用 Node.js 的 Socket.IO 库可以轻松地添加实时聊天或监控现有网站。它的轻量级、高性能的特性经常被用作 Node.js 的“胶水”服务。

特别有趣的组合是在现代云基础设施上部署小型服务，使用诸如 Docker 和 Kubernetes 之类的工具，或者像 AWS Lambda 这样的函数即服务平台。将大型应用程序划分为易于部署的微服务时，Node.js 在规模上表现良好。

掌握了 Node.js 的高级理解后，让我们深入一点。

# Node.js 的能力

Node.js 是一个在 Web 浏览器之外编写 JavaScript 应用程序的平台。这不是我们在 Web 浏览器中熟悉的 JavaScript 环境！虽然 Node.js 执行与我们在浏览器中使用的相同的 JavaScript 语言，但它没有一些与浏览器相关的功能。例如，Node.js 中没有内置 HTML DOM。

除了其本身执行 JavaScript 的能力外，内置模块提供了以下类型的功能：

+   命令行工具（以 shell 脚本风格）

+   交互式终端风格的程序，即 REPL

+   优秀的进程控制功能来监督子进程

+   处理二进制数据的缓冲对象

+   TCP 或 UDP 套接字与全面的事件驱动回调

+   DNS 查找

+   HTTP、HTTPS 和 HTTP/2 客户端服务器在 TCP 库文件系统访问之上

+   内置的基本单元测试支持通过断言

Node.js 的网络层是低级的，同时使用起来很简单，例如，HTTP 模块允许您使用几行代码编写 HTTP 服务器（或客户端）。这很强大，但它让您，程序员，非常接近协议请求，并让您实现应该在请求响应中返回的那些 HTTP 头部。

典型的 Web 应用程序开发人员不需要在 HTTP 或其他协议的低级别上工作；相反，我们倾向于使用更高级别的接口更加高效，例如，PHP 程序员假设 Apache/Nginx 等已经提供了 HTTP，并且他们不必实现堆栈的 HTTP 服务器部分。相比之下，Node.js 程序员确实实现了一个 HTTP 服务器，他们的应用代码附加到其中。

为了简化情况，Node.js 社区有几个 Web 应用程序框架，比如 Express，提供了典型程序员所需的更高级别的接口。您可以快速配置一个具有内置功能的 HTTP 服务器，比如会话、cookie、提供静态文件和日志记录，让开发人员专注于业务逻辑。其他框架提供 OAuth 2 支持或专注于 REST API 等等。

使用 Node.js 的社区在这个基础上构建了各种令人惊叹的东西。

## 人们如何使用 Node.js？

Node.js 不仅限于 Web 服务应用程序开发；Node.js 周围的社区已经将其引向了许多其他方向：

+   构建工具：Node.js 已经成为开发命令行工具的热门选择，这些工具用于软件开发或与服务基础设施通信。Grunt、Gulp 和 Webpack 被广泛用于前端开发人员构建网站资产。Babel 被广泛用于将现代 ES-2016 代码转译为在旧版浏览器上运行。流行的 CSS 优化器和处理器，如 PostCSS，都是用 Node.js 编写的。静态网站生成系统，如 Metalsmith、Punch 和 AkashaCMS，在命令行上运行，并生成您上传到 Web 服务器的网站内容。

+   Web UI 测试：Puppeteer 让您控制一个无头 Chrome 浏览器实例。借助它，您可以通过控制现代、功能齐全的 Web 浏览器来开发 Node.js 脚本。一些典型的用例是 Web 抓取和 Web 应用程序测试。

+   桌面应用程序：Electron 和 node-webkit（NW.js）都是用于开发 Windows、macOS 和 Linux 桌面应用程序的框架。这些框架利用大量的 Chrome，由 Node.js 库包装，使用 Web UI 技术开发桌面应用程序。应用程序使用现代的 HTML5、CSS3 和 JavaScript 编写，并可以利用领先的 Web 框架，如 Bootstrap、React、VueJS 和 AngularJS。许多流行的应用程序都是使用 Electron 构建的，包括 Slack 桌面客户端应用程序、Atom、Microsoft Visual Code 编程编辑器、Postman REST 客户端、GitKraken GIT 客户端和 Etcher 等。

+   移动应用程序：Node.js for Mobile Systems 项目允许您使用 Node.js 开发 iOS 和 Android 的智能手机或平板电脑应用程序。苹果的 App Store 规定不允许将具有 JIT 功能的 JavaScript 引擎纳入其中，这意味着普通的 Node.js 不能在 iOS 应用程序中使用。对于 iOS 应用程序开发，该项目使用 Node.js-on-ChakraCore 来规避 App Store 规定。对于 Android 应用程序开发，该项目使用常规的 Node.js 在 Android 上运行。在撰写本文时，该项目处于早期开发阶段，但看起来很有前景。

+   物联网（IoT）：Node.js 是物联网项目中非常流行的语言，Node.js 可以在大多数基于 ARM 的单板计算机上运行。最明显的例子是 NodeRED 项目。它提供了一个图形化的编程环境，让您通过连接块来绘制程序。它具有面向硬件的输入和输出机制，例如与树莓派或 Beaglebone 单板计算机上的通用 I/O（GPIO）引脚进行交互。

您可能已经在使用 Node.js 应用程序而没有意识到！JavaScript 在 Web 浏览器之外也有用武之地，这不仅仅是因为 Node.js。

## 服务器端 JavaScript

别再挠头了！当然，您正在这样做，挠头并自言自语地说：“浏览器语言在服务器上做什么？”事实上，JavaScript 在浏览器之外有着悠久而鲜为人知的历史。JavaScript 是一种编程语言，就像任何其他语言一样，更好的问题是“为什么 JavaScript 应该被困在 Web 浏览器内部？”

回到网络时代的黎明，编写 Web 应用程序的工具处于萌芽阶段。一些开发人员尝试使用 Perl 或 TCL 编写 CGI 脚本，PHP 和 Java 语言刚刚被开发出来。即便那时，JavaScript 也在服务器端使用。早期的 Web 应用程序服务器之一是网景的 LiveWire 服务器，它使用了 JavaScript。微软的 ASP 的一些版本使用了 JScript，他们的 JavaScript 版本。一个更近期的服务器端 JavaScript 项目是 Java 领域的 RingoJS 应用程序框架。Java 6 和 Java 7 都附带了 Rhino JavaScript 引擎。在 Java 8 中，Rhino 被新的 Nashorn JavaScript 引擎所取代。

换句话说，JavaScript 在浏览器之外并不是一件新事物，尽管它并不常见。

您已经了解到 Node.js 是一个用于在 Web 浏览器之外编写 JavaScript 应用程序的平台。Node.js 社区使用这个平台进行各种类型的应用程序开发，远远超出了最初为该平台构思的范围。这证明了 Node.js 的受欢迎程度，但我们仍然必须考虑使用它的技术原因。

# 为什么要使用 Node.js？

在众多可用的 Web 应用程序开发平台中，为什么应该选择 Node.js？有很多选择，那么 Node.js 有什么特点使其脱颖而出呢？我们将在接下来的部分中找到答案。

## 流行度

Node.js 迅速成为一种受欢迎的开发平台，并被许多大大小小的参与者所采用。其中之一是 PayPal，他们正在用 Node.js 替换其现有的基于 Java 的系统。其他大型 Node.js 采用者包括沃尔玛的在线电子商务平台、LinkedIn 和 eBay。

有关 PayPal 关于此的博客文章，请访问[`www.paypal-engineering.com/2013/11/22/node-js-at-paypal/`](https://www.paypal-engineering.com/2013/11/22/node-js-at-paypal/)。

根据 NodeSource 的说法，Node.js 的使用量正在迅速增长（有关更多信息，请访问[`nodesource.com/node-by-numbers`](https://nodesource.com/node-by-numbers)）。这种增长的证据包括下载 Node.js 版本的带宽增加，与 Node.js 相关的 GitHub 项目的活动增加等。

对 JavaScript 本身的兴趣仍然非常强烈，但在搜索量（Google Insights）和作为编程技能的使用方面（Dice Skills Center）已经停滞多年。Node.js 的兴趣一直在迅速增长，但正在显示出停滞的迹象。

有关更多信息，请参阅[`itnext.io/choosing-typescript-vs-javascript-technology-popularity-ea978afd6b5f`](https://itnext.io/choosing-typescript-vs-javascript-technology-popularity-ea978afd6b5f)或[`bit.ly/2q5cu0w`](http://bit.ly/2q5cu0w)。

最好不要只是跟随潮流，因为有不同的潮流，每一个都声称他们的软件平台有很酷的功能。Node.js 确实有一些很酷的功能，但更重要的是它的技术价值。

## JavaScript 无处不在

在服务器和客户端上使用相同的编程语言一直是网络上的一个长期梦想。这个梦想可以追溯到早期的 Java 时代，当时 Java 小程序在浏览器中被视为用于 Java 编写的服务器应用程序的前端，而 JavaScript 最初被设想为这些小程序的轻量级脚本语言。然而，Java 从未实现其作为客户端编程语言的炒作，甚至“Java 小程序”这个词组也正在逐渐消失，成为被放弃的客户端应用程序模型的模糊记忆。最终，我们选择了 JavaScript 作为浏览器中的主要客户端语言，而不是 Java。通常情况下，前端 JavaScript 开发人员使用的是与服务器端团队不同的语言，后者可能是 PHP、Java、Ruby 或 Python。

随着时间的推移，在浏览器中的 JavaScript 引擎变得非常强大，让我们能够编写越来越复杂的浏览器端应用程序。有了 Node.js，我们终于能够使用相同的编程语言在客户端和服务器上实现应用程序，因为 JavaScript 在网络的两端，即浏览器和服务器上。

前端和后端使用相同的编程语言具有几个潜在的好处：

+   同一编程人员可以在网络两端工作。

+   代码可以更轻松地在服务器和客户端之间迁移。

+   服务器和客户端之间的常见数据格式（JSON）。

+   服务器和客户端存在常见的软件工具。

+   服务器和客户端的常见测试或质量报告工具。

+   在编写 Web 应用程序时，视图模板可以在两端使用。

JavaScript 语言非常受欢迎，因为它在 Web 浏览器中非常普遍。它与其他语言相比具有许多现代、先进的语言概念。由于其受欢迎程度，有许多经验丰富的 JavaScript 程序员。

## 利用谷歌对 V8 的投资

为了使 Chrome 成为一款受欢迎且出色的 Web 浏览器，谷歌投资于使 V8 成为一个超快的 JavaScript 引擎。因此，谷歌有巨大的动力继续改进 V8。V8 是 Chrome 的 JavaScript 引擎，也可以独立执行。

Node.js 建立在 V8 JavaScript 引擎之上，使其能够利用 V8 的所有工作。因此，Node.js 能够在 V8 实现新的 JavaScript 语言特性时迅速采用，并因此获得性能优势。

## 更精简、异步、事件驱动的模型

Node.js 架构建立在单个执行线程上，具有巧妙的事件驱动、异步编程模型和快速的 JavaScript 引擎，据称比基于线程的架构具有更少的开销。其他使用线程进行并发的系统往往具有内存开销和复杂性，而 Node.js 没有。我们稍后会更深入地讨论这一点。

## 微服务架构

软件开发中的一个新感觉是微服务的概念。微服务专注于将大型 Web 应用程序拆分为小型、紧密专注的服务，可以由小团队轻松开发。虽然它们并不是一个全新的想法，它们更像是对旧的客户端-服务器计算模型的重新构架，但是微服务模式与敏捷项目管理技术很匹配，并且为我们提供了更精细的应用部署。

Node.js 是实现微服务的优秀平台。我们稍后会详细介绍。

## Node.js 在一次重大分裂和敌对分支之后变得更加强大

在 2014 年和 2015 年，Node.js 社区因政策、方向和控制而发生了重大分裂。**io.js**项目是一个敌对的分支，由一群人驱动，他们希望合并几个功能并改变决策过程中的人员。最终的结果是合并了 Node.js 和 io.js 存储库，成立了独立的 Node.js 基金会来运作，并且社区共同努力朝着共同的方向前进。

弥合这一分歧的一个具体结果是快速采用新的 ECMAScript 语言特性。V8 引擎迅速采用这些新特性来推进 Web 开发的状态。Node.js 团队也在 V8 中尽快采用这些特性，这意味着承诺和`async`函数很快就会成为 Node.js 程序员的现实。

总之，Node.js 社区不仅在 io.js 分支和后来的 ayo.js 分支中幸存下来，而且社区和它培育的平台因此变得更加强大。

在本节中，您已经了解了使用 Node.js 的几个原因。它不仅是一个受欢迎的平台，有一个强大的社区支持，而且还有一些严肃的技术原因可以使用它。它的架构具有一些关键的技术优势，让我们更深入地了解一下这些优势。

# Node.js 事件驱动架构

据说 Node.js 的出色性能是因为其异步事件驱动架构和使用 V8 JavaScript 引擎。这使其能够同时处理多个任务，例如在多个 Web 浏览器的请求之间进行协调。Node.js 的原始创始人 Ryan Dahl 遵循了这些关键点：

+   单线程、事件驱动的编程模型比依赖线程处理多个并发任务的应用服务器更简单，复杂性更低，开销更小。

+   通过将阻塞函数调用转换为异步代码执行，可以配置系统以在满足阻塞请求时发出事件。

+   您可以利用来自 Chrome 浏览器的 V8 JavaScript 引擎，并且所有工作都用于改进 V8；所有性能增强都进入 V8，因此也有益于 Node.js。

在大多数应用服务器中，并发或处理多个并发请求的能力是通过多线程架构实现的。在这样的系统中，对数据的任何请求或任何其他阻塞函数调用都会导致当前执行线程暂停并等待结果。处理并发请求需要有多个执行线程。当一个线程被暂停时，另一个线程可以执行。这会导致应用服务器启动和停止线程来处理请求。每个暂停的线程（通常在输入/输出操作完成时等待）都会消耗完整的内存调用堆栈，增加开销。线程会给应用服务器增加复杂性和服务器开销。

为了帮助我们理解为什么会这样，Node.js 的创始人 Ryan Dahl 在 2010 年 5 月的 Cinco de NodeJS 演示中提供了以下示例。([`www.youtube.com/watch?v=M-sc73Y-zQA`](https://www.youtube.com/watch?v=M-sc73Y-zQA)) Dahl 问我们当我们执行这样的代码行时会发生什么：

```

Of course, the program pauses at this point while the database layer sends the query to the database and waits for the result or the error. This is an example of a blocking function call. Depending on the query, this pause can be quite long (well, a few milliseconds, which is ages in computer time). This pause is bad because the execution thread can do nothing while it waits for the result to arrive. If your software is running on a single-threaded platform, the entire server would be blocked and unresponsive. If instead your application is running on a thread-based server platform, a thread-context switch is required to satisfy any other requests that arrive. The greater the number of outstanding connections to the server, the greater the number of thread-context switches. Context switching is not free because more threads require more memory per thread state and more time for the CPU to spend on thread management overheads.

The key inspiration guiding the original development of Node.js was the simplicity of a single-threaded system. A single execution thread means that the server doesn't have the complexity of multithreaded systems. This choice meant that Node.js required an event-driven model for handling concurrent tasks. Instead of the code waiting for results from a blocking request, such as retrieving data from a database, an event is instead dispatched to an event handler.

Using threads to implement concurrency often comes with admonitions, such as *expensive and error-prone*, *the error-prone synchronization primitives of Java*, or *designing concurrent software can be complex and error-prone*. The complexity comes from access to shared variables and various strategies to avoid deadlock and competition between threads. The *synchronization primitives of Java* are an example of such a strategy, and obviously many programmers find them difficult to use. There's a tendency to create frameworks such as `java.util.concurrent` to tame the complexity of threaded concurrency, but some argue that papering over complexity only makes things more complex. 

A typical Java programmer might object at this point. Perhaps their application code is written against a framework such as Spring, or maybe they're directly using Java EE. In either case, their application code does not use concurrency features or deal with threads, and therefore where is the complexity that we just described? Just because that complexity is hidden within Spring and Java EE does not mean that there is no complexity and overhead.

Okay, we get it: while multithreaded systems can do amazing things, there is inherent complexity. What does Node.js offer?

## The Node.js answer to complexity

Node.js asks us to think differently about concurrency. Callbacks fired asynchronously from an event loop are a much simpler concurrency model—simpler to understand, simpler to implement, simpler to reason about, and simpler to debug and maintain. 

Node.js has a single execution thread with no waiting on I/O or context switching. Instead, there is an event loop that dispatches events to handler functions as things happen. A request that would have blocked the execution thread instead executes asynchronously, with the results or errors triggering an event. Any operation that would block or otherwise take time to complete must use the asynchronous model. 

The original Node.js paradigm delivered the dispatched event to an anonymous function. Now that JavaScript has `async` functions, the Node.js paradigm is shifting to deliver results and errors via a promise that is handled by the `await` keyword. When an asynchronous function is called, control quickly passes to the event loop rather than causing Node.js to block. The event loop continues handling the variety of events while recording where to send each result or error.

By using an asynchronous event-driven I/O, Node.js removes most of this overhead while introducing very little of its own.

One of the points Ryan Dahl made in the Cinco de Node presentation is a hierarchy of execution time for different requests. Objects in memory are more quickly accessed (in the order of nanoseconds) than objects on disk or objects retrieved over the network (milliseconds or seconds). The longer access time for external objects is measured in zillions of clock cycles, which can be an eternity when your customer is sitting at their web browser ready to move on if it takes longer than two seconds to load the page. 

Therefore, concurrent request handling means using a strategy to handle the requests that take longer to satisfy. If the goal is to avoid the complexity of a multithreaded system, then the system must use asynchronous operations as Node.js does.

What do these asynchronous function calls look like?

## Asynchronous requests in Node.js

In Node.js, the query that we looked at previously will read as follows:

```

程序员提供一个在结果（或错误）可用时被调用的函数（因此称为*回调函数*）。`query`函数仍然需要相同的时间。它不会阻塞执行线程，而是返回到事件循环，然后可以处理其他请求。Node.js 最终会触发一个事件，导致调用此回调函数并返回结果或错误指示。

在客户端 JavaScript 中使用类似的范例，我们经常编写事件处理程序函数。

JavaScript 语言的进步为我们提供了新的选择。与 ES2015 promises 一起使用时，等效的代码如下：

```

This is a little better, especially in instances of deeply nested event handling.

The big advance came with the ES-2017 `async` function:

```

除了`async`和`await`关键字之外，这看起来像我们在其他语言中编写的代码，并且更容易阅读。由于`await`的作用，它仍然是异步代码执行。

这三个代码片段都执行了我们之前编写的相同查询。`query`不再是阻塞函数调用，而是异步的，不会阻塞执行线程。

使用回调函数和 promise 的异步编码，Node.js 也存在自己的复杂性问题。我们经常在一个异步函数之后调用另一个异步函数。使用回调函数意味着深度嵌套的回调函数，而使用 promise 则意味着长长的`.then`处理程序函数链。除了编码的复杂性，我们还有错误和结果出现在不自然的位置。异步执行的回调函数被调用时，不会落在下一行代码上。执行顺序不是像同步编程语言中一行接一行的，而是由回调函数执行的顺序决定的。

`async`函数的方法解决了这种编码复杂性。编码风格更自然，因为结果和错误出现在自然的位置，即下一行代码。`await`关键字集成了异步结果处理，而不会阻塞执行线程。`async/await`功能的背后有很多东西，我们将在本书中广泛涵盖这个模型。

但是 Node.js 的异步架构实际上改善了性能吗？

## 性能和利用率

Node.js 引起了一些兴奋是因为它的吞吐量（每秒请求量）。对比类似应用的基准测试，比如 Apache，显示出 Node.js 有巨大的性能提升。

一个流传的基准是以下简单的 HTTP 服务器（从[`nodejs.org/en/`](https://nodejs.org/en/)借来的），它直接从内存中返回一个`Hello World`消息：

```

This is one of the simpler web servers that you can build with Node.js. The `http` object encapsulates the HTTP protocol, and its `http.createServer` method creates a whole web server, listening on the port specified in the `listen` method. Every request (whether a `GET` or `POST` on any URL) on that web server calls the provided function. It is very simple and lightweight. In this case, regardless of the URL, it returns a simple `text/plain` that is the `Hello World` response.

Ryan Dahl showed a simple benchmark in a video titled *Ryan Dahl: Introduction to Node.js* (on the YUI Library channel on YouTube, [`www.youtube.com/watch?v=M-sc73Y-zQA`](https://www.youtube.com/watch?v=M-sc73Y-zQA)). It used a similar HTTP server to this, but that returned a one-megabyte binary buffer; Node.js gave 822 req/sec, while Nginx gave 708 req/sec, for a 15% improvement over Nginx. He also noted that Nginx peaked at four megabytes of memory, while Node.js peaked at 64 megabytes. 

The key observation was that Node.js, running an interpreted, JIT-compiled, high-level language, was about as fast as Nginx, built of highly optimized C code, while running similar tasks. That presentation was in May 2010, and Node.js has improved hugely since then, as shown in Chris Bailey's talk that we referenced earlier.

Yahoo! search engineer Fabian Frank published a performance case study of a real-world search query suggestion widget implemented with Apache/PHP and two variants of Node.js stacks ([`www.slideshare.net/FabianFrankDe/nodejs-performance-case-study`](http://www.slideshare.net/FabianFrankDe/nodejs-performance-case-study)). The application is a pop-up panel showing search suggestions as the user types in phrases using a JSON-based HTTP query. The Node.js version could handle eight times the number of requests per second with the same request latency. Fabian Frank said both Node.js stacks scaled linearly until CPU usage hit 100%. 

LinkedIn did a massive overhaul of their mobile app using Node.js for the server-side to replace an old Ruby on Rails app. The switch lets them move from 30 servers down to 3, and allowed them to merge the frontend and backend team because everything was written in JavaScript. Before choosing Node.js, they'd evaluated Rails with Event Machine, Python with Twisted, and Node.js, chose Node.js for the reasons that we just discussed. For a look at what LinkedIn did, see [`arstechnica.com/information-technology/2012/10/a-behind-the-scenes-look-at-linkedins-mobile-engineering/`](http://arstechnica.com/information-technology/2012/10/a-behind-the-scenes-look-at-linkedins-mobile-engineering/).

Most existing Node.js performance tips tend to have been written for older V8 versions that used the CrankShaft optimizer. The V8 team has completely dumped CrankShaft, and it has a new optimizer called TurboFan—for example, under CrankShaft, it was slower to use `try/catch`, `let/const`, generator functions, and so on. Therefore, common wisdom said to not use those features, which is depressing because we want to use the new JavaScript features because of how much it has improved the JavaScript language. Peter Marshall, an engineer on the V8 team at Google, gave a talk at Node.js Interactive 2017 claiming that, using TurboFan, you should just write natural JavaScript. With TurboFan, the goal is for across-the-board performance improvements in V8\. To view the presentation, see the video titled *High Performance JS* in V8 at [`www.youtube.com/watch?v=YqOhBezMx1o`](https://www.youtube.com/watch?v=YqOhBezMx1o).

A truism about JavaScript is that it's no good for heavy computation work because of the nature of JavaScript. We'll go over some ideas that are related to this in the next section. A talk by Mikola Lysenko at Node.js Interactive 2016 went over some issues with numerical computing in JavaScript, and some possible solutions. Common numerical computing involves large numerical arrays processed by numerical algorithms that you might have learned in calculus or linear algebra classes. What JavaScript lacks is multidimensional arrays and access to certain CPU instructions. The solution that he presented is a library to implement multidimensional arrays in JavaScript, along with another library full of numerical computing algorithms. To view the presentation, see the video titled *Numerical Computing in JavaScript* by Mikola Lysenko at [`www.youtube.com/watch?v=1ORaKEzlnys`](https://www.youtube.com/watch?v=1ORaKEzlnys)[. ](https://www.youtube.com/watch?v=1ORaKEzlnys)

At the Node.js Interactive conference in 2017, IBM's Chris Bailey made a case for Node.js being an excellent choice for highly scalable microservices. Key performance characteristics are I/O performance (measured in transactions per second), startup time (because that limits how quickly your service can scale up to meet demand), and memory footprint (because that determines how many application instances can be deployed per server). Node.js excels on all those measures; with every subsequent release, it either improves on each measure or remains fairly steady. Bailey presented figures comparing Node.js to a similar benchmark written in Spring Boot showing Node.js to perform much better. To view his talk, see the video titled *Node.js Performance and Highly Scalable Micro-Services - Chris Bailey, IBM* at [`www.youtube.com/watch?v=Fbhhc4jtGW4`](https://www.youtube.com/watch?v=Fbhhc4jtGW4).

The bottom line is that Node.js excels at event-driven I/O throughput. Whether a Node.js program can excel at computational programs depends on your ingenuity in working around some limitations in the JavaScript language.

A big problem with computational programming is that it prevents the event loop from executing. As we will see in the next section, that can make Node.js look like a poor candidate for anything.

### Is Node.js a cancerous scalability disaster?

In October 2011, a blog post (since pulled from the blog where it was published) titled *Node.js is a cancer* called Node.js a scalability disaster. The example shown for proof was a CPU-bound implementation of the Fibonacci sequence algorithm. While the argument was flawed—since nobody implements Fibonacci that way—it made the valid point that Node.js application developers have to consider the following: where do you put the heavy computational tasks?

A key to maintaining high throughput of Node.js applications is by ensuring that events are handled quickly. Because it uses a single execution thread, if that thread is bogged down with a big calculation, Node.js cannot handle events, and event throughput will suffer.

The Fibonacci sequence, serving as a stand-in for heavy computational tasks, quickly becomes computationally expensive to calculate for a naïve implementation such as this:

```

这是一个特别简单的方法来计算斐波那契数。是的，有很多更快的计算斐波那契数的方法。我们展示这个作为 Node.js 在事件处理程序缓慢时会发生什么的一个一般性例子，而不是讨论计算数学函数的最佳方法。考虑以下服务器：

```

This is an extension of the simple web server shown earlier. It looks in the request URL for an argument, `n`, for which to calculate the Fibonacci number. When it's calculated, the result is returned to the caller.

For sufficiently large values of `n` (for example, `40`), the server becomes completely unresponsive because the event loop is not running. Instead, this function has blocked event processing because the event loop cannot dispatch events while the function is grinding through the calculation.

In other words, the Fibonacci function is a stand-in for any blocking operation.

Does this mean that Node.js is a flawed platform? No, it just means that the programmer must take care to identify code with long-running computations and develop solutions. These include rewriting the algorithm to work with the event loop, rewriting the algorithm for efficiency, integrating a native code library, or foisting computationally expensive calculations to a backend server.

A simple rewrite dispatches the computations through the event loop, letting the server continue to handle requests on the event loop. Using callbacks and closures (anonymous functions), we're able to maintain asynchronous I/O and concurrency promises, as shown in the following code:

```

这是一个同样愚蠢的计算斐波那契数的方法，但是通过使用`process.nextTick`，事件循环有机会执行。

因为这是一个需要回调函数的异步函数，它需要对服务器进行小的重构：

```

We've added a callback function to receive the result. In this case, the server is able to handle multiple Fibonacci number requests. But there is still a performance issue because of the inefficient algorithm.

Later in this book, we'll explore this example a little more deeply to explore alternative approaches.

In the meantime, we can discuss why it's important to use efficient software stacks.

## Server utilization, overhead costs, and environmental impact

The striving for optimal efficiency (handling more requests per second) is not just about the geeky satisfaction that comes from optimization. There are real business and environmental benefits. Handling more requests per second, as Node.js servers can do, means the difference between buying lots of servers and buying only a few servers. Node.js potentially lets your organization do more with less.

Roughly speaking, the more servers you buy, the greater the monetary cost and the greater the environmental cost. There's a whole field of expertise around reducing costs and the environmental impact of running web-server facilities to which that rough guideline doesn't do justice. The goal is fairly obvious—fewer servers, lower costs, and a lower environmental impact by using more efficient software.

Intel's paper, *Increasing Data Center Efficiency with Server Power Measurements* ([`www.intel.com/content/dam/doc/white-paper/intel-it-data-center-efficiency-server-power-paper.pdf`](https://www.intel.com/content/dam/doc/white-paper/intel-it-data-center-efficiency-server-power-paper.pdf)), gives an objective framework for understanding efficiency and data center costs. There are many factors, such as buildings, cooling systems, and computer system designs. Efficient building design, efficient cooling systems, and efficient computer systems (data center efficiency, data center density, and storage density) can lower costs and environmental impact. But you can destroy these gains by deploying an inefficient software stack, compelling you to buy more servers than you would if you had an efficient software stack. Alternatively, you can amplify gains from data center efficiency with an efficient software stack that lets you decrease the number of servers required.

This talk about efficient software stacks isn't just for altruistic environmental purposes. This is one of those cases where being green can help your business bottom line.

In this section, we have learned a lot about how Node.js architecture differs from other programming platforms. The choice to eschew threads to implement concurrency simplifies away the complexity and overhead that comes from using threads. This seems to have fulfilled the promise of being more efficient. Efficiency has a number of benefits to many aspects of a business.

# Embracing advances in the JavaScript language

The last couple of years have been an exciting time for JavaScript programmers. The TC-39 committee that oversees the ECMAScript standard has added many new features, some of which are syntactic sugar, but several of which have propelled us into a whole new era of JavaScript programming. By itself, the `async/await` feature promises us a way out of what's called callback fell, the situation that we find ourselves in when nesting callbacks within callbacks. It's such an important feature that it should necessitate a broad rethinking of the prevailing callback-oriented paradigm in Node.js and the rest of the JavaScript ecosystem.

A few pages ago, you saw this:

```

这是 Ryan Dahl 的一个重要洞察，也是推动 Node.js 流行的原因。某些操作需要很长时间才能运行，比如数据库查询，不应该和快速从内存中检索数据的操作一样对待。由于 JavaScript 语言的特性，Node.js 必须以一种不自然的方式表达这种异步编码结构。结果不会出现在下一行代码，而是出现在这个回调函数中。此外，错误必须以一种不自然的方式处理，出现在那个回调函数中。

在 Node.js 中的约定是回调函数的第一个参数是一个错误指示器，随后的参数是结果。这是一个有用的约定，你会在整个 Node.js 领域找到它；然而，它使得处理结果和错误变得复杂，因为两者都出现在一个不方便的位置——那个回调函数。错误和结果自然地应该出现在随后的代码行上。

随着每一层回调函数嵌套，我们陷入了回调地狱。第七层回调嵌套比第六层回调嵌套更复杂。为什么？至少有一点是因为随着回调的嵌套更深，错误处理的特殊考虑变得更加复杂。

但正如我们之前所看到的，这是在 Node.js 中编写异步代码的新首选方式：

```

相反，ES2017 的`async`函数使我们回到了这种非常自然的编程意图表达。结果和错误会在正确的位置上，同时保持了使 Node.js 变得伟大的出色的事件驱动的异步编程模型。我们将在本书的后面看到这是如何工作的。

TC-39 委员会为 JavaScript 添加了许多新功能，比如以下的：

+   改进的类声明语法，使对象继承和 getter/setter 函数非常自然。

+   一个在浏览器和 Node.js 中标准化的新模块格式。

+   字符串的新方法，比如模板字符串表示法。

+   集合和数组的新方法，例如`map`/`reduce`/`filter`的操作。

+   使用`const`关键字来定义不能被改变的变量，使用`let`关键字来定义变量的作用域仅限于它们声明的块，而不是被提升到函数的前面。

+   新的循环结构和与这些新循环配合使用的迭代协议。

+   一种新类型的函数，箭头函数，它更轻量，意味着更少的内存和执行时间影响。

+   `Promise`对象表示将来承诺交付的结果。单独使用，承诺可以缓解回调地狱问题，并且它们构成了`async`函数的一部分基础。

+   生成器函数是一种有趣的方式，用于表示一组值的异步迭代。更重要的是，它们构成了异步函数的基础的另一半。

你可能会看到新的 JavaScript 被描述为 ES6 或 ES2017。描述正在使用的 JavaScript 版本的首选名称是什么？

ES1 到 ES5 标志着 JavaScript 发展的各个阶段。ES5 于 2009 年发布，并在现代浏览器中得到广泛实现。从 ES6 开始，TC-39 委员会决定改变命名约定，因为他们打算每年添加新的语言特性。因此，语言版本现在包括年份，例如，ES2015 于 2015 年发布，ES2016 于 2016 年发布，ES2017 于 2017 年发布。

## 部署 ES2015/2016/2017/2018 JavaScript 代码

问题在于，通常 JavaScript 开发人员无法使用最新的功能。前端 JavaScript 开发人员受到部署的网络浏览器和大量旧浏览器的限制，这些浏览器在长时间未更新操作系统的计算机上使用。幸运的是，Internet Explorer 6 版本几乎已经完全退出使用，但仍然有大量旧浏览器安装在老旧计算机上，仍然为其所有者提供有效的角色。旧浏览器意味着旧的 JavaScript 实现，如果我们希望我们的代码能够运行，我们需要它与旧浏览器兼容。

Babel 和其他代码重写工具的一个用途是处理这个问题。许多产品必须能够被使用旧浏览器的人使用。开发人员仍然可以使用最新的 JavaScript 或 TypeScript 功能编写他们的代码，然后使用 Babel 重写他们的代码，以便在旧浏览器上运行。这样，前端 JavaScript 程序员可以采用（部分）新功能，但需要更复杂的构建工具链，并且代码重写过程可能引入错误的风险。

Node.js 世界没有这个问题。Node.js 迅速采用了 ES2015/2016/2017 功能，就像它们在 V8 引擎中实现一样。从 Node.js 8 开始，我们可以自由地使用`async`函数作为一种原生功能。新的模块格式首次在 Node.js 版本 10 中得到支持。

换句话说，虽然前端 JavaScript 程序员可以主张他们必须等待几年才能采用 ES2015/2016/2017 功能，但 Node.js 程序员无需等待。我们可以简单地使用新功能，而无需任何代码重写工具，除非我们的管理人员坚持支持早于这些功能采用的旧 Node.js 版本。在这种情况下，建议您使用 Babel。

JavaScript 世界的一些进步是在 TC-39 社区之外发生的。

## TypeScript 和 Node.js

TypeScript 语言是 JavaScript 环境的一个有趣的分支。因为 JavaScript 越来越能够用于复杂的应用程序，编译器帮助捕捉编程错误变得越来越有用。其他语言的企业程序员，如 Java，习惯于强类型检查作为防止某些类别的错误的一种方式。

强类型检查在某种程度上与 JavaScript 程序员相悖，但它确实很有用。TypeScript 项目旨在从 Java 和 C#等语言中引入足够的严谨性，同时保留 JavaScript 的松散性。结果是编译时类型检查，而不会像其他语言中的程序员那样承载沉重的负担。

虽然我们在本书中不会使用 TypeScript，但它的工具链在 Node.js 应用程序中非常容易采用。

在本节中，我们了解到随着 JavaScript 语言的变化，Node.js 平台也跟上了这些变化。

# 使用 Node.js 开发微服务或最大服务

新的功能，如云部署系统和 Docker，使得实现一种新的服务架构成为可能。Docker 使得可以在可重复部署到云托管系统中的数百万个容器中定义服务器进程配置。它最适合小型、单一用途的服务实例，可以连接在一起组成一个完整的系统。Docker 并不是唯一可以帮助简化云部署的工具；然而，它的特性非常适合现代应用部署需求。

一些人将微服务概念作为描述这种系统的一种方式。根据[microservices.io](http://microservices.io/)网站，微服务由一组狭义、独立可部署的服务组成。他们将其与单片应用部署模式进行对比，单片应用将系统的每个方面集成到一个捆绑包中（例如 Java EE 应用服务器的单个 WAR 文件）。微服务模型为开发人员提供了非常需要的灵活性。

微服务的一些优势如下：

+   每个微服务可以由一个小团队管理。

+   每个团队可以按照自己的时间表工作，只要保持服务 API 的兼容性。

+   微服务可以独立部署，如果需要的话，比如为了更容易进行测试。

+   更容易切换技术栈选择。

Node.js 在这方面的定位如何？它的设计与微服务模型非常契合：

+   Node.js 鼓励小型、紧密专注、单一用途的模块。

+   这些模块由出色的 npm 包管理系统组成应用程序。

+   发布模块非常简单，无论是通过 NPM 仓库还是 Git URL。

+   虽然 Express 等应用框架可以用于大型服务，但它非常适用于小型轻量级服务，并支持简单易用的部署。

简而言之，使用 Node.js 以精益和敏捷的方式非常容易，可以根据您的架构偏好构建大型或小型服务。

# 总结

在本章中，您学到了很多东西。特别是，您看到了 JavaScript 在 Web 浏览器之外的生活，以及 Node.js 是一个具有许多有趣特性的优秀编程平台。虽然它是一个相对年轻的项目，但 Node.js 已经变得非常流行，不仅广泛用于 Web 应用程序，还用于命令行开发工具等。由于 Node.js 平台基于 Chrome 的 V8 JavaScript 引擎，该项目已经能够跟上 JavaScript 语言的快速改进。

Node.js 架构由事件循环触发回调函数管理的异步函数组成，而不是使用线程和阻塞 I/O。这种架构声称具有性能优势，似乎提供了许多好处，包括能够在更少的硬件上完成更多的工作。但我们也了解到低效的算法可能会抵消任何性能优势。

本书的重点是开发和部署 Node.js 应用程序的现实考虑。我们将尽可能涵盖开发、完善、测试和部署 Node.js 应用程序的许多方面。

既然我们已经对 Node.js 有了介绍，我们准备好开始使用它了。在第二章 *设置 Node.js*中，我们将介绍如何在 Mac、Linux 或 Windows 上设置 Node.js 开发环境，甚至编写一些代码。让我们开始吧。


设置 Node.js

在开始使用 Node.js 之前，您必须设置好开发环境。虽然设置非常简单，但有许多考虑因素，包括是否使用包管理系统安装 Node.js，满足安装本地代码 Node.js 包的要求，以及决定使用什么编辑器最好与 Node.js 一起使用。在接下来的章节中，我们将使用这个环境进行开发和非生产部署。

在本章中，我们将涵盖以下主题：

+   如何在 Linux、macOS 或 Windows 上从源代码和预打包的二进制文件安装 Node.js

+   如何安装**node 包管理器**（**npm**）和其他一些流行的工具

+   Node.js 模块系统

+   Node.js 和 ECMAScript 委员会的 JavaScript 语言改进

# 第四章：系统要求

Node.js 可以在类似 POSIX 的操作系统、各种 UNIX 衍生系统（例如 Solaris）和 UNIX 兼容的操作系统（如 Linux、macOS 等），以及 Microsoft Windows 上运行。它可以在各种大小的计算机上运行，包括像树莓派这样的微型 ARM 设备，树莓派是一个用于 DIY 软件/硬件项目的微型嵌入式计算机。

Node.js 现在可以通过包管理系统获得，无需从源代码编译和安装。

由于许多 Node.js 包是用 C 或 C++编写的，您必须有 C 编译器（如 GCC）、Python 2.7（或更高版本）和`node-gyp`包。由于 Python 2 将在 2019 年底停止维护，Node.js 社区正在为 Python 3 兼容性重写其工具。如果您计划在网络编码中使用加密，还需要 OpenSSL 加密库。现代 UNIX 衍生系统几乎肯定会自带这些内容，Node.js 的配置脚本（在从源代码安装时使用）将检测它们的存在。如果您需要安装它，Python 可以在[`python.org`](http://python.org)获取，OpenSSL 可以在[`openssl.org`](http://openssl.org)获取。

现在我们已经了解了运行 Node.js 的要求，让我们学习如何安装它。

# 使用包管理器安装 Node.js

安装 Node.js 的首选方法是使用包管理器中提供的版本，比如`apt-get`或 MacPorts。包管理器通过输入简单的命令，如`apt-get update`，来帮助您在计算机上维护软件的当前版本，并确保更新依赖包，从而让您的生活更加轻松。让我们首先来看一下如何从包管理系统进行安装。

有关从包管理器安装的官方说明，请访问[`nodejs.org/en/download/package-manager/.`](https://nodejs.org/en/download/package-manager/)

## 在 macOS 上使用 MacPorts 安装 Node.js

MacPorts 项目（[`www.macports.org/`](http://www.macports.org/)）多年来一直在为 macOS 打包大量开源软件包，他们已经打包了 Node.js。它默认管理的命令安装在`/opt/local/bin`上。安装 MacPorts 后，安装 Node.js 非常简单，可以在 MacPorts 安装命令的目录中找到 Node.js 二进制文件：

```

If you have followed the directions for setting up MacPorts, the MacPorts directory is already in your PATH environment variable. Running the `node`, `npm`, or `npx` commands is then simple. This proves Node.js has been installed and the installed version matched what you asked for.

MacPorts isn't the only tool for managing open source software packages on macOS.

## Installing Node.js on macOS with Homebrew

Homebrew is another open source software package manager for macOS, which some say is the perfect replacement for MacPorts. It is available through their home page at [`brew.sh/`](http://brew.sh/). After installing Homebrew using the instructions on their website and ensuring that it is correctly set up, use the following code:

```

然后，像这样安装：

```

Like MacPorts, Homebrew installs commands on a public directory, which defaults to `/usr/local/bin`. If you have followed the Homebrew instructions to add that directory to your `PATH` variable, run the Node.js command as follows:

```

这证明 Node.js 已经安装，并且安装的版本与您要求的版本相匹配。

当然，macOS 只是我们可能使用的众多操作系统之一。

## 从包管理系统在 Linux、*BSD 或 Windows 上安装 Node.js

Node.js 现在可以通过大多数包管理系统获得。Node.js 网站上的说明目前列出了 Node.js 的打包版本，适用于长列表的 Linux，以及 FreeBSD，OpenBSD，NetBSD，macOS，甚至 Windows。访问[`nodejs.org/en/download/package-manager/`](https://nodejs.org/en/download/package-manager/)获取更多信息。

例如，在 Debian 和其他基于 Debian 的 Linux 发行版（如 Ubuntu）上，使用以下命令：

```

This adds the NodeSource APT repository to the system, updates the package data, and prepares the system so that you can install Node.js packages. It also instructs us on how to install Node.js and the required compiler and developer tools.

To download other Node.js versions (this example shows version 14.x), modify the URL to suit you:

```

命令将安装在`/usr/bin`中，我们可以测试下载的版本是否符合我们的要求。

由于一种名为**Windows 子系统 Linux**（**WSL**）的新工具，Windows 正开始成为 Unix/Linux 极客可以工作的地方。

### 在 WSL 中安装 Node.js

**WSL**允许您在 Windows 上安装 Ubuntu、openSUSE 或 SUSE Linux Enterprise。所有这三个都可以通过内置到 Windows 10 中的商店获得。您可能需要更新 Windows 设备才能进行安装。为了获得最佳体验，请安装 WSL2，这是 WSL 的一次重大改进，提供了 Windows 和 Linux 之间更好的集成。

安装完成后，Linux 特定的说明将在 Linux 子系统中安装 Node.js。

要安装 WSL，请参阅[`msdn.microsoft.com/en-us/commandline/wsl/install-win10`](https://msdn.microsoft.com/en-us/commandline/wsl/install-win10)。

要了解并安装 WSL2，请参阅[`docs.microsoft.com/en-us/windows/wsl/wsl2-index`](https://docs.microsoft.com/en-us/windows/wsl/wsl2-index)。

在 Windows 上，该过程可能需要提升的权限。

### 在 Windows 上打开具有管理员特权的 PowerShell

在 Windows 上安装工具时，您将运行一些命令需要在具有提升权限的 PowerShell 窗口中执行。我们提到这一点是因为在启用 WSL 的过程中，需要在 PowerShell 窗口中运行一个命令。

该过程很简单：

1.  在“开始”菜单中，在应用程序的搜索框中输入`PowerShell`。生成的菜单将列出 PowerShell。

1.  右键单击 PowerShell 条目。

1.  弹出的上下文菜单将有一个名为“以管理员身份运行”的条目。点击它。

生成的命令窗口将具有管理员特权，并且标题栏将显示管理员：Windows PowerShell。

在某些情况下，您将无法使用软件包管理系统中的 Node.js。

## 从 nodejs.org 安装 Node.js 发行版

[`nodejs.org/en/`](https://nodejs.org/en/)网站提供了 Windows、macOS、Linux 和 Solaris 的内置二进制文件。我们只需转到该网站，单击安装按钮，然后运行安装程序。对于具有软件包管理器的系统，例如我们刚刚讨论的系统，最好使用软件包管理系统。这是因为您会发现更容易保持最新版本。但是，由于以下原因，这并不适用于所有人：

+   有些人更喜欢安装二进制文件，而不是使用软件包管理器。

+   他们选择的系统没有软件包管理系统。

+   他们的软件包管理系统中的 Node.js 实现已经过时。

只需转到 Node.js 网站，您将看到以下屏幕截图中的内容。该页面会尽力确定您的操作系统并提供适当的下载。如果您需要其他内容，请单击标题中的 DOWNLOADS 链接以获取所有可能的下载：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/63b156b2-8046-4789-a277-04a59cc77f3f.png)

对于 macOS，安装程序是一个`PKG`文件，提供了典型的安装过程。对于 Windows，安装程序只需按照典型的安装向导过程进行。

安装程序完成后，您将拥有命令行工具，例如`node`和`npm`，您可以使用它们来运行 Node.js 程序。在 Windows 上，您将获得一个预配置为与 Node.js 良好配合工作的 Windows 命令外壳版本。

正如您刚刚了解的，我们大多数人将完全满意于安装预构建的软件包。但是，有时我们必须从源代码安装 Node.js。

# 在类似 POSIX 的系统上从源代码安装

安装预打包的 Node.js 发行版是首选的安装方法。但是，在一些情况下，从源代码安装 Node.js 是可取的：

+   它可以让您根据需要优化编译器设置。

+   它可以让您交叉编译，比如为嵌入式 ARM 系统。

+   您可能需要保留多个 Node.js 版本进行测试。

+   您可能正在处理 Node.js 本身。

现在您已经有了一个高层次的视图，让我们通过一些构建脚本来动手。一般的过程遵循您可能已经用其他开源软件包执行过的`configure`、`make`和`make install`例程。如果没有，不用担心，我们会指导您完成这个过程。

官方安装说明在源分发的`README.md`中，位于[`github.com/nodejs/node/blob/master/README.md`](https://github.com/nodejs/node/blob/master/README.md)。

## 安装先决条件

有三个先决条件：C 编译器、Python 和 OpenSSL 库。Node.js 编译过程会检查它们的存在，如果 C 编译器或 Python 不存在，将会失败。这些命令将检查它们的存在：

```

Go to [`github.com/nodejs/node/blob/master/BUILDING.md`](https://github.com/nodejs/node/blob/master/BUILDING.md) for details on the requirements.

The specific method for installing these depends on your OS.

The Node.js build tools are in the process of being updated to support Python 3.x. Python 2.x is in an end-of-life process, slated for the end of 2019, so it is therefore recommended that you update to Python 3.x.

Before we can compile the Node.js source, we must have the correct tools installed and on macOS, there are a couple of special considerations.

## Installing developer tools on macOS

Developer tools (such as GCC) are an optional installation on macOS. Fortunately, they're easy to acquire.

You start with Xcode, which is available for free through the Macintosh app store. Simply search for `Xcode` and click on the Get button. Once you have Xcode installed, open a Terminal window and type the following:

```

这将安装 Xcode 命令行工具：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/d8c5d5a8-8f7e-40e0-8f9d-3e8e892f2204.png)

有关更多信息，请访问[`osxdaily.com/2014/02/12/install-command-line-tools-mac-os-x/`](http://osxdaily.com/2014/02/12/install-command-line-tools-mac-os-x/)。

现在我们已经安装了所需的工具，我们可以继续编译 Node.js 源代码。

## 为所有类 POSIX 系统从源代码安装

从源代码编译 Node.js 遵循以下熟悉的过程：

1.  从[`nodejs.org/download.`](http://nodejs.org/download)下载源代码。

1.  使用`./configure`配置源代码进行构建。

1.  运行`make`，然后运行`make install`。

源代码包可以通过浏览器下载，或者按照以下步骤进行替换您喜欢的版本：

```

Now, we configure the source so that it can be built. This is just like with many other open source packages and there is a long list of options to customize the build:

```

要使安装到您的`home`目录中，以这种方式运行它：

```

If you're going to install multiple Node.js versions side by side, it's useful to put the version number in the path like this. That way, each version will sit in a separate directory. It will then be a simple matter of switching between Node.js versions by changing the `PATH` variable appropriately:

```

安装多个 Node.js 版本的更简单方法是使用`nvm`脚本，稍后将进行描述。

如果你想在系统范围的目录中安装 Node.js，只需省略`--prefix`选项，它将默认安装在`/usr/local`中。

过一会儿，它会停止，并且很可能已经成功地配置了源树，以便在您选择的目录中进行安装。如果这不成功，打印出的错误消息将描述需要修复的内容。一旦配置脚本满意，您就可以继续下一步。

配置脚本满意后，您可以编译软件：

```

If you are installing on a system-wide directory, perform the last step this way instead:

```

安装完成后，您应该确保将安装目录添加到您的`PATH`变量中，如下所示：

```

Alternatively, for `csh` users, use this syntax to make an exported environment variable:

```

安装完成后，它会创建一个目录结构，如下所示：

```

Now that we've learned how to install Node.js from the source on UNIX-like systems, we get to do the same on Windows.

## Installing from the source on Windows

The `BUILDING.md` document referenced previously has instructions. You can use the build tools from Visual Studio or the full Visual Studio 2017 or 2019 product: 

*   Visual Studio 2019: [`www.visualstudio.com/downloads/`](https://www.visualstudio.com/downloads/)
*   The build tools: [`visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2019`](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2019)

Three additional tools are required:

*   Git for Windows: [`git-scm.com/download/win`](http://git-scm.com/download/win)  
*   Python: [`www.python.org/`](https://www.python.org/)
*   OpenSSL: [`www.openssl.org/source/`](https://www.openssl.org/source/) and [`wiki.openssl.org/index.php/Binaries`](https://wiki.openssl.org/index.php/Binaries)
*   The **Netwide Assembler** (**NASM**) for OpenSSL: [`www.nasm.us/`](https://www.nasm.us/)

Then, run the included `.\vcbuild` script to perform the build. 

We've learned how to install one Node.js instance, so let's now take it to the next level by installing multiple instances.

# Installing multiple Node.js instances with nvm

Normally, you wouldn't install multiple versions of Node.js—doing so adds complexity to your system. But if you are hacking on Node.js itself or testing your software against different Node.js releases, you may want to have multiple Node.js installations. The method to do so is a simple variation on what we've already discussed.

Earlier, while discussing building Node.js from the source, we noted that you can install multiple Node.js instances in separate directories. It's only necessary to build from the source if you need a customized Node.js build but most folks would be satisfied with pre-built Node.js binaries. They, too, can be installed on separate directories.

Switching between Node.js versions is simply a matter of changing the `PATH` variable (on POSIX systems), as in the following code, using the directory where you installed Node.js:

```

在一段时间后，维护这个变得有点乏味。对于每个发布，您都必须在 Node.js 安装中设置 Node.js、npm 和任何第三方模块。此外，显示更改`PATH`的命令并不是最佳的。富有创造力的程序员已经创建了几个版本管理器，以简化管理多个 Node.js/npm 版本，并提供智能更改`PATH`的命令：

+   Node 版本管理器：[`github.com/tj/n`](https://github.com/tj/n)

+   Node 版本管理器：[`github.com/creationix/nvm`](https://github.com/creationix/nvm)

两者都维护多个同时版本的 Node.js，并且让你可以轻松切换版本。安装说明可以在它们各自的网站上找到。

例如，使用`nvm`，您可以运行这样的命令：

```

In this example, we first listed the available versions. Then, we demonstrated how to switch between Node.js versions, verifying the version changed each time. We also installed and used a new version using `nvm`. Finally, we showed the directory where nvm installs Node.js packages versus Node.js versions that are installed using MacPorts or Homebrew.

This demonstrates that you can have Node.js installed system-wide, keep multiple private Node.js versions managed by `nvm`, and switch between them as needed. When new Node.js versions are released, they are simple to install with `nvm`, even if the official package manager for your OS hasn't yet updated its packages.

## Installing nvm on Windows

Unfortunately, `nvm` doesn't support Windows. Fortunately, a couple of Windows-specific clones of the `nvm` concept exist:

*   Node.js version management utility for Windows: [`github.com/coreybutler/nvm-windows`](https://github.com/coreybutler/nvm-windows)
*   Natural Node.js and npm version manager for Windows: [`github.com/marcelklehr/nodist`](https://github.com/marcelklehr/nodist)

Another route is to use WSL. Because in WSL you're interacting with a Linux command line, you can use `nvm` itself. But let's stay focused on what you can do in Windows.

Many of the examples in this book were tested using the `nvm-windows` application. There are slight behavior differences but it acts largely the same as `nvm` for Linux and macOS. The biggest change is the version number specifier in the `nvm use` and `nvm install` commands.

With `nvm` for Linux and macOS, you can type a simple version number, such as `nvm use 8`, and it will automatically substitute the latest release of the named Node.js version. With `nvm-windows`, the same command acts as if you typed `nvm use 8.0.0`. In other words, with `nvm-windows`, you must use the exact version number. Fortunately, the list of supported versions is easily available using the `nvm list available` command.

Using a tool such as `nvm` simplifies the process of testing a Node.js application against multiple Node.js versions.

Now that we can install Node.js, we need to make sure we are installing any Node.js module that we want to use. This requires having build tools installed on our computer.

# Requirements for installing native code modules

While we won't discuss native code module development in this book, we do need to make sure that they can be built. Some modules in the npm repository are native code and they must be compiled with a C or C++ compiler to build the corresponding `.node` files (the `.node` extension is used for binary native code modules).

The module will often describe itself as a wrapper for some other library. For example, the `libxslt` and `libxmljs` modules are wrappers around the C/C++ libraries of the same name. The module includes the C/C++ source code and when installed, a script is automatically run to do the compilation with `node-gyp`.

The `node-gyp` tool is a cross-platform command-line tool written in Node.js for compiling native add-on modules for Node.js. We've mentioned native code modules several times and it is this tool that compiles them for use with Node.js.

You can easily see this in action by running these commands:

```

这是在临时目录中完成的，所以之后可以删除它。如果您的系统没有安装编译本地代码模块的工具，您将看到错误消息。否则，您将看到`node-gyp`的执行输出，然后是许多明显与编译 C/C++文件相关的文本行。

`node-gyp`工具具有与从源代码编译 Node.js 相似的先决条件，即 C/C++编译器、Python 环境和其他构建工具，如 Git。对于 Unix、macOS 和 Linux 系统，这些都很容易获得。对于 Windows，您应该安装以下内容：

+   Visual Studio 构建工具：[`www.visualstudio.com/downloads/#build-tools-for-visual-studio-2017`](https://www.visualstudio.com/downloads/#build-tools-for-visual-studio-2017)

+   Windows 的 Git：[`git-scm.com/download/win`](http://git-scm.com/download/win)

+   Windows 的 Python：[`www.python.org/`](https://www.python.org/)

通常，您不需要担心安装`node-gyp`。这是因为它作为 npm 的一部分在后台安装。这样做是为了让 npm 可以自动构建本地代码模块。

它的 GitHub 存储库包含文档；转到[`github.com/nodejs/node-gyp`](https://github.com/nodejs/node-gyp)。

阅读`node-gyp`存储库中的文档将让您更清楚地了解之前讨论的编译先决条件和开发本地代码模块。

这是一个非显式依赖的示例。最好明确声明软件包依赖的所有内容。在 Node.js 中，依赖关系在`package.json`中声明，以便包管理器（`npm`或`yarn`）可以下载和设置所有内容。但是这些编译器工具是由操作系统包管理系统设置的，这是`npm`或`yarn`无法控制的。因此，我们无法明确声明这些依赖关系。

我们刚刚了解到 Node.js 不仅支持用 JavaScript 编写的模块，还支持其他编程语言。我们还学会了如何支持这些模块的安装。接下来，我们将了解 Node.js 版本号。

# 选择要使用的 Node.js 版本和版本策略

在上一节中，我们提到了许多不同的 Node.js 版本号，您可能会对要使用哪个版本感到困惑。本书针对的是 Node.js 版本 14.x，并且预计我们将涵盖的所有内容都与 Node.js 10.x 和任何后续版本兼容。

从 Node.js 4.x 开始，Node.js 团队采用了双轨道方法。偶数版本（4.x、6.x、8.x 等）被称为**长期支持**（**LTS**），而奇数版本（5.x、7.x、9.x 等）是当前新功能开发的地方。虽然开发分支保持稳定，但 LTS 版本被定位为用于生产使用，并将在几年内接收更新。

在撰写本文时，Node.js 12.x 是当前的 LTS 版本；Node.js 14.x 已发布，最终将成为 LTS 版本。

每个新的 Node.js 发布的主要影响，除了通常的性能改进和错误修复之外，还包括引入最新的 V8 JavaScript 引擎发布。反过来，这意味着引入更多的 ES2015/2016/2017 功能，因为 V8 团队正在实现它们。在 Node.js 8.x 中，`async/await`函数到达，在 Node.js 10.x 中，支持标准的 ES6 模块格式到达。在 Node.js 14.x 中，该模块格式将得到完全支持。

一个实际的考虑是新的 Node.js 发布是否会破坏您的代码。新的语言功能总是在 V8 赶上 ECMAScript 的过程中添加，Node.js 团队有时会对 Node.js API 进行重大更改。如果您在一个 Node.js 版本上进行了测试，它是否会在较早的版本上工作？Node.js 的更改是否会破坏我们的一些假设？

npm 的作用是确保我们的软件包在正确的 Node.js 版本上执行。这意味着我们可以在`package.json`文件中指定软件包的兼容 Node.js 版本（我们将在第三章，*探索 Node.js 模块*中探讨）。

我们可以在`package.json`中添加条目如下：

```

This means exactly what it implies—that the given package is compatible with Node.js version 8.x or later.

Of course, your development environment(s) could have several Node.js versions installed. You'll need the version your software is declared to support, plus any later versions you wish to evaluate.

We have just learned how the Node.js community manages releases and version numbers. Our next step is to discuss which editor to use.

# Choosing editors and debuggers for Node.js

Since Node.js code is JavaScript, any JavaScript-aware editor will be useful. Unlike some other languages that are so complex that an IDE with code completion is a necessity, a simple programming editor is perfectly sufficient for Node.js development.

Two editors are worth shouting out because they are written in Node.js: Atom and Microsoft Visual Studio Code. 

Atom ([`atom.io/`](https://atom.io/)) describes itself as a hackable editor for the 21st century. It is extendable by writing Node.js modules using the Atom API and the configuration files are easily editable. In other words, it's hackable in the same way plenty of other editors have been—going back to Emacs, meaning you write a software module to add capabilities to the editor. The Electron framework was invented in order to build Atom and it is is a super-easy way of building desktop applications using Node.js.

Microsoft Visual Studio Code ([`code.visualstudio.com/`](https://code.visualstudio.com/)) is a hackable editor (well, the home page says extensible and customizable, which means the same thing) that is also open source and implemented in Electron. However, it's not a hollow me-too editor, copying Atom while adding nothing of its own. Instead, Visual Studio Code is a solid programmer's editor in its own right, bringing interesting functionality to the table.

As for debuggers, there are several interesting choices. Starting with Node.js 6.3, the `inspector` protocol has made it possible to use the Google Chrome debugger. Visual Studio Code has a built-in debugger that also uses the `inspector` protocol.

For a full list of debugging options and tools, see [`nodejs.org/en/docs/guides/debugging-getting-started/`](https://nodejs.org/en/docs/guides/debugging-getting-started/).

Another task related to the editor is adding extensions to help with the editing experience. Most programmer-oriented editors allow you to extend the behavior and assist with writing the code. A trivial example is syntax coloring for JavaScript, CSS, HTML, and so on. Code completion extensions are where the editor helps you write the code. Some extensions scan code for common errors; often these extensions use the word *lint*. Some extensions help to run unit test frameworks. Since there are so many editors available, we cannot provide specific suggestions.  

For some, the choice of programming editor is a serious matter defended with fervor, so we carefully recommend that you use whatever editor you prefer, as long as it helps you edit JavaScript code. Next, we will learn about the Node.js commands and a little about running Node.js scripts.

# Running and testing commands

Now that you've installed Node.js, we want to do two things—verify that the installation was successful and familiarize ourselves with the Node.js command-line tools and running simple scripts with Node.js. We'll also touch again on `async` functions and look at a simple example HTTP server. We'll finish off with the `npm` and `npx` command-line tools.

## Using Node.js's command-line tools

The basic installation of Node.js includes two commands: `node` and `npm`. We've already seen the `node` command in action. It's used either for running command-line scripts or server processes. The other, `npm`, is a package manager for Node.js.

The easiest way to verify that your Node.js installation works is also the best way to get help with Node.js. Type the following command:

```

输出很多，但不要过于仔细研究。关键是`node --help`提供了很多有用的信息。

请注意，Node.js 和 V8 都有选项（在上一个命令行中未显示）。请记住 Node.js 是建立在 V8 之上的；它有自己的选项宇宙，主要关注字节码编译、垃圾回收和堆算法的细节。输入`node --v8-options`以查看这些选项的完整列表。

在命令行上，您可以指定选项、单个脚本文件和该脚本的参数列表。我们将在下一节*使用 Node.js 运行简单脚本*中进一步讨论脚本参数。

在没有参数的情况下运行 Node.js 会将您放在一个交互式 JavaScript shell 中：

```

Any code you can write in a Node.js script can be written here. The command interpreter gives a good terminal-oriented user experience and is useful for interactively playing with your code. You do play with your code, don't you? Good!

## Running a simple script with Node.js

Now, let's look at how to run scripts with Node.js. It's quite simple; let's start by referring to the help message shown previously. The command-line pattern is just a script filename and some script arguments, which should be familiar to anyone who has written scripts in other languages.

Creating and editing Node.js scripts can be done with any text editor that deals with plain text files, such as VI/VIM, Emacs, Notepad++, Atom, Visual Studio Code, Jedit, BB Edit, TextMate, or Komodo. It's helpful if it's a programmer-oriented editor, if only for the syntax coloring.

For this and other examples in this book, it doesn't truly matter where you put the files. However, for the sake of neatness, you can start by making a directory named `node-web-dev` in the `home` directory of your computer and inside that, creating one directory per chapter (for example, `chap02` and `chap03`).

First, create a text file named `ls.js` with the following content:

```

接下来，通过输入以下命令来运行它：

```

This is a pale and cheap imitation of the Unix `ls` command (as if you couldn't figure that out from the name!). The `readdir` function is a close analog to the Unix `readdir` system call used to list the files in a directory. On Unix/Linux systems, we can run the following command to learn more:

```

当然，`man`命令让你阅读手册页，第`3`节涵盖了 C 库。

在函数体内，我们读取目录并打印其内容。使用`require('fs').promises`给我们提供了一个返回 Promise 的`fs`模块（文件系统函数）的版本；因此，在异步函数中它可以很好地工作。同样，ES2015 的`for..of`循环构造让我们能够以一种适合在`async`函数中工作的方式循环遍历数组中的条目。

默认情况下，`fs`模块函数使用最初为 Node.js 创建的回调范式。因此，大多数 Node.js 模块使用回调范式。在`async`函数中，如果函数返回 Promise，那么更方便使用`await`关键字。`util`模块提供了一个函数，`util.promisify`，它为旧式的面向回调的函数生成一个包装函数，因此它返回一个 Promise。

这个脚本是硬编码为列出当前目录中的文件。真正的`ls`命令需要一个目录名，所以让我们稍微修改一下脚本。

命令行参数会落入一个名为`process.argv`的全局数组中。因此，我们可以修改`ls.js`，将其复制为`ls2.js`（如下所示）来看看这个数组是如何工作的：

```

You can run it as follows:

```

我们只是检查了命令行参数是否存在，`if (process.argv[2])`。如果存在，我们会覆盖`dir`变量的值，`dir = process.argv[2]`，然后将其用作`readdir`的参数：

```

If you give it a non-existent directory pathname, an error will be thrown and printed using the `catch` clause. 

### Writing inline async arrow functions

There is a different way to write these examples that some feel is more concise. These examples were written as a regular function—with the `function` keyword—but with the `async` keyword in front. One of the features that came with ES2015 is the arrow function, which lets us streamline the code a little bit.

Combined with the `async` keyword, an async arrow function looks like this:

```

你可以在任何地方使用这个；例如，该函数可以被分配给一个变量，或者它可以作为回调传递给另一个函数。当与`async`关键字一起使用时，箭头函数的主体具有所有`async`函数的行为。

为了这些示例的目的，可以将异步箭头函数包装为立即执行：

```

The final parenthesis causes the inline function to immediately be invoked.

Then, because `async` functions return a Promise, it is necessary to add a `.catch` block to catch errors. With all that, the example looks as follows:

```

也许这种风格或者之前的风格更可取。然而，你会发现这两种风格都在使用中，了解这两种风格的工作方式是必要的。

在脚本的顶层调用异步函数时，有必要捕获任何错误并报告它们。未能捕获和报告错误可能导致难以解决的神秘问题。在这个示例的原始版本中，错误是通过`try/catch`块明确捕获的。在这个版本中，我们使用`.catch`块捕获错误。

在我们拥有异步函数之前，我们有 Promise 对象，而在那之前，我们有回调范式。所有三种范式在 Node.js 中仍在使用，这意味着你需要理解每一种。

## 转换为异步函数和 Promise 范式

在上一节中，我们讨论了`util.promisify`及其将面向回调的函数转换为返回 Promise 的能力。后者与异步函数很好地配合，因此，最好让函数返回一个 Promise。

更准确地说，`util.promisify`应该给出一个使用错误优先回调范式的函数。这些函数的最后一个参数是一个回调函数，其第一个参数被解释为错误指示器，因此有了错误优先回调这个短语。`util.promisify`返回的是另一个返回 Promise 的函数。

Promise 的作用与错误优先回调相同。如果指示了错误，则 Promise 解析为拒绝状态，而如果指示了成功，则 Promise 解析为成功状态。正如我们在这些示例中看到的那样，Promise 在`async`函数中处理得非常好。

Node.js 生态系统拥有大量使用错误优先回调的函数。社区已经开始了一个转换过程，其中函数将返回一个 Promise，并可能还会接受一个错误优先回调以实现 API 兼容性。

Node.js 10 中的一个新功能就是这样的转换的一个例子。在`fs`模块中有一个名为`fs.promises`的子模块，具有相同的 API，但产生 Promise 对象。我们使用该 API 编写了前面的示例。

另一个选择是第三方模块`fs-extra`。该模块具有超出标准`fs`模块的扩展 API。一方面，如果没有提供回调函数，它的函数会返回一个 Promise，否则会调用回调函数。此外，它还包括几个有用的函数。

在本书的其余部分，我们经常使用`fs-extra`，因为它具有额外的功能。有关该模块的文档，请访问[`www.npmjs.com/package/fs-extra`](https://www.npmjs.com/package/fs-extra)。

`util`模块还有另一个函数`util.callbackify`，它的功能与其名称暗示的一样——它将返回 Promise 的函数转换为使用回调函数的函数。

现在我们已经看到如何运行一个简单的脚本，让我们来看一个简单的 HTTP 服务器。

## 使用 Node.js 启动服务器

你将运行许多服务器进程的脚本；我们稍后将运行许多这样的脚本。由于我们仍在尝试验证安装并让你熟悉使用 Node.js，我们想要运行一个简单的 HTTP 服务器。让我们借用 Node.js 首页上的简单服务器脚本([`nodejs.org`](http://nodejs.org))。

创建一个名为`app.js`的文件，其中包含以下内容：

```

Run it as follows:

```

这是你可以用 Node.js 构建的最简单的网络服务器。如果你对它的工作原理感兴趣，请翻到第四章，*HTTP 服务器和客户端*，第五章，*你的第一个 Express 应用程序*，和第六章，*实现移动优先范式*。但现在，只需在浏览器中键入`http://127.0.0.1:8124`，就可以看到 Hello, World!的消息：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/fec4c888-fe02-4660-b3a3-ed7810a88ef1.png)

一个值得思考的问题是为什么这个脚本在`ls.js`退出时没有退出。在两种情况下，脚本的执行都到达了文件的末尾；Node.js 进程在`app.js`中没有退出，而在`ls.js`中退出了。

这是因为存在活动事件监听器。Node.js 始终启动一个事件循环，在`app.js`中，`listen`函数创建了一个实现 HTTP 协议的事件`listener`。这个`listener`事件会一直保持`app.js`运行，直到你做一些事情，比如在终端窗口中按下*Ctrl* + *C*。在`ls.js`中，没有任何内容来创建一个长时间运行的`listener`事件，所以当`ls.js`到达脚本的末尾时，`node`进程将退出。

要使用 Node.js 执行更复杂的任务，我们必须使用第三方模块。npm 存储库是去的地方。

## 使用 npm，Node.js 包管理器

Node.js 作为一个具有一些有趣的异步 I/O 库的 JavaScript 解释器，本身就是一个相当基本的系统。使 Node.js 有趣的事情之一是不断增长的用于 Node.js 的第三方模块生态系统。

在这个生态系统的中心是 npm 模块存储库。虽然 Node.js 模块可以作为源代码下载并手动组装以供 Node.js 程序使用，但这样做很麻烦，而且很难实现可重复的构建过程。npm 为我们提供了一个更简单的方法；npm 是 Node.js 的事实标准包管理器，它极大地简化了下载和使用这些模块。我们将在下一章详细讨论 npm。

你们中的敏锐者可能已经注意到，npm 已经通过之前讨论的所有安装方法安装了。过去，npm 是单独安装的，但今天它与 Node.js 捆绑在一起。

现在我们已经安装了`npm`，让我们快速试一下。**hexy**程序是一个用于打印文件的十六进制转储的实用程序。这是一个非常 70 年代的事情，但它仍然非常有用。它现在正好符合我们的目的，因为它可以让我们快速安装和尝试：

```

Adding the `-g` flag makes the module available globally, irrespective of the present working directory of your command shell. A global install is most useful when the module provides a command-line interface. When a package provides a command-line script, `npm` sets that up. For a global install, the command is installed correctly for use by all users of the computer.

Depending on how Node.js is installed for you, it may need to be run with `sudo`:

```

安装完成后，您可以以以下方式运行新安装的程序：

```

The `hexy` command was installed as a global command, making it easy to run.

Again, we'll be doing a deep dive into npm in the next chapter. The `hexy` utility is both a Node.js library and a script for printing out these old-style hex dumps.

In the open source world, a perceived need often leads to creating an open source project. The folks who launched the Yarn project saw needs that weren't being addressed by npm and created an alternative package manager tool. They claim a number of advantages over npm, primarily in the area of performance. To learn more about Yarn, go to [`yarnpkg.com/`](https://yarnpkg.com/).

For every example in this book that uses npm, there is a close equivalent command that uses Yarn.

For npm-packaged command-line tools, there is another, simpler way to use the tool.

## Using npx to execute Node.js packaged binaries

Some packages in the npm repository are command-line tools, such as the `hexy` program we looked at earlier. Having to first install such a program before using it is a small hurdle. The sharp-eyed among you will have noticed that `npx` is installed alongside the `node` and `npm` commands when installing Node.js. This tool is meant to simplify running command-line tools from the npm repository by removing the need to first install the package.

The previous example could have been run this way:

```

在底层，`npx`使用`npm`将包下载到缓存目录，除非包已经安装在当前项目目录中。因为包然后在缓存目录中，所以只下载一次。

这个工具有很多有趣的选项；要了解更多，请访问[`www.npmjs.com/package/npx`](https://www.npmjs.com/package/npx)。

在本节中，我们已经学到了有关 Node.js 提供的命令行工具，以及运行简单脚本和 HTTP 服务器的知识。接下来，我们将学习 JavaScript 语言的进步如何影响 Node.js 平台。

# 用 ECMAScript 2015、2016、2017 和以后推进 Node.js

2015 年，ECMAScript 委员会发布了 JavaScript 语言的一个期待已久的重大更新。更新为 JavaScript 带来了许多新功能，如 Promises、箭头函数和类对象。这个语言更新为改进奠定了基础，因为它应该大大提高我们编写清晰、易懂的 JavaScript 代码的能力。

浏览器制造商正在添加这些非常需要的功能，这意味着 V8 引擎也在添加这些功能。这些功能正在以 Node.js 的方式进入，从 4.x 版本开始。

要了解 Node.js 中 ES2015/2016/2017 等的当前状态，请访问[`nodejs.org/en/docs/es6/`](https://nodejs.org/en/docs/es6/)。

默认情况下，Node.js 启用 V8 认为稳定的 ES2015、2016 和 2017 功能。其他功能可以通过命令行选项启用。几乎完整的功能可以通过`--es_staging`选项启用。网站文档提供了更多信息。

Node green 网站([`node.green/`](http://node.green/))有一张表格列出了 Node.js 版本中许多功能的状态。

ES2019 语言规范发布在[`www.ecma-international.org/publications/standards/Ecma-262.htm`](https://www.ecma-international.org/publications/standards/Ecma-262.htm)。

TC-39 委员会在 GitHub 上进行工作，网址为[`github.com/tc39`](https://github.com/tc39)。

ES2015（以及之后）的功能对 JavaScript 语言有很大的改进。其中一个功能，`Promise`类，应该意味着 Node.js 编程中常见习语的根本性重新思考。在 ES2017 中，一对新关键字，`async`和`await`，简化了在 Node.js 中编写异步代码，这应该鼓励 Node.js 社区进一步重新思考平台的常见习语。

JavaScript 有很多新功能，但让我们快速浏览其中两个我们将大量使用的功能。

第一个是称为箭头函数的轻量级函数语法：

```

This is more than the syntactic sugar of replacing the `function` keyword with the fat arrow. Arrow functions are lighter weight as well as being easier to read. The lighter weight comes at the cost of changing the value of `this` inside the arrow function. In regular functions, `this` has a unique value inside the function. In an arrow function, `this` has the same value as the scope containing the arrow function. This means that, when using an arrow function, we don't have to jump through hoops to bring `this` into the callback function because `this` is the same at both levels of the code.

The next feature is the `Promise` class, which is used for deferred and asynchronous computations. Deferred code execution to implement asynchronous behavior is a key paradigm for Node.js and it requires two idiomatic conventions:

*   The last argument to an asynchronous function is a callback function, which is called when an asynchronous execution is to be performed.
*   The first argument to the callback function is an error indicator.

While convenient, these conventions have resulted in multilayer code pyramids that can be difficult to understand and maintain:

```

您不需要理解代码；这只是实践中发生的概述，因为我们使用回调。根据特定任务所需的步骤数量，代码金字塔可能会变得非常深。Promise 将让我们解开代码金字塔，并提高可靠性，因为错误处理更直接，可以轻松捕获所有错误。

`Promise`类的创建如下：

```

Rather than passing in a callback function, the caller receives a `Promise` object. When properly utilized, the preceding pyramid can be coded as follows:

```

这是因为`Promise`类支持链接，如果`then`函数返回一个`Promise`对象。

`async/await`功能实现了`Promise`类的承诺，简化了异步编码。这个功能在`async`函数中变得活跃：

```

An `async` arrow function is as follows: 

```

为了看到`async`函数范式给我们带来了多大的改进，让我们将之前的示例重新编码如下：

```

Again, we don't need to understand the code but just look at its shape. Isn't this a breath of fresh air compared to the nested structure we started with?

The `await` keyword is used with a Promise. It automatically waits for the Promise to resolve. If the Promise resolves successfully, then the value is returned and if it resolves with an error, then that error is thrown. Both handling results and throwing errors are handled in the usual manner.

This example also shows another ES2015 feature: destructuring. The fields of an object can be extracted using the following code:

```

这演示了一个具有三个字段的对象，但只提取了两个字段。

为了继续探索 JavaScript 的进步，让我们来看看 Babel。

## 使用 Babel 使用实验性 JavaScript 功能

Babel 转译器是使用尖端 JavaScript 功能或尝试新 JavaScript 功能的主要工具。由于您可能从未见过**转译器**这个词，它的意思是将源代码从一种语言重写为另一种语言。它类似于**编译器**，Babel 将计算机源代码转换为另一种形式，但是 Babel 生成的是 JavaScript，而不是直接可执行代码。也就是说，它将 JavaScript 代码转换为 JavaScript 代码，这可能看起来没有用，直到您意识到 Babel 的输出可以针对旧的 JavaScript 版本。

更简单地说，Babel 可以配置为将具有 ES2015、ES2016、ES2017（等等）功能的代码重写为符合 ES5 版本 JavaScript 的代码。由于 ES5 JavaScript 与几乎所有旧计算机上的网络浏览器兼容，开发人员可以使用现代 JavaScript 编写其前端代码，然后使用 Babel 将其转换为在旧浏览器上执行。

要了解更多关于 Babel 的信息，请访问[`babeljs.io`](https://%20babeljs.io)。

Node Green 网站明确表示 Node.js 支持几乎所有的 ES2015、2016 和 2017 功能。因此，实际上，我们不再需要为 Node.js 项目使用 Babel。您可能需要支持旧版本的 Node.js，可以使用 Babel 来实现。

对于网络浏览器来说，一组 ECMAScript 功能和我们可以在浏览器端代码中可靠使用这些功能之间存在着更长的时间延迟。并不是网络浏览器制造商在采用新功能方面速度慢，因为谷歌、Mozilla 和微软团队都积极采用最新功能。不幸的是，苹果的 Safari 团队似乎在采用新功能方面较慢。然而，更慢的是新浏览器在现场计算机中的渗透。

因此，现代 JavaScript 程序员需要熟悉 Babel。

我们还没有准备好展示这些功能的示例代码，但我们可以继续记录 Babel 工具的设置。有关设置文档的更多信息，请访问[`babeljs.io/docs/setup/`](http://babeljs.io/docs/setup/)并单击 CLI 按钮。

为了简要介绍 Babel，我们将使用它来转译我们之前看到的脚本，以在 Node.js 6.x 上运行。在这些脚本中，我们使用了异步函数，这是 Node.js 6.x 不支持的功能。

在包含`ls.js`和`ls2.js`的目录中，输入以下命令：

```

This installs the Babel software, along with a couple of transformation plugins. Babel has a plugin system so that you can enable the transformations required by your project. Our primary goal in this example is converting the `async` functions shown earlier into Generator functions. Generators are a new sort of function introduced with ES2015 that form the foundation for the implementation of `async` functions.

Because Node.js 6.x does not have either the `fs.promises` function or `util.promisify`, we need to make some substitutions to create a file named `ls2-old-school.js`:

```

我们有之前看过的相同示例，但有一些更改。`fs_readdir`函数创建一个 Promise 对象，然后调用`fs.readdir`，确保根据我们得到的结果要么`reject`要么`resolve`Promise。这基本上是`util.promisify`函数所做的。

因为`fs_readdir`返回一个 Promise，所以`await`关键字可以做正确的事情，并等待请求成功或失败。这段代码应该在支持`async`函数的 Node.js 版本上运行。但我们感兴趣的是，也是我们添加`fs_readdir`函数的原因是它在旧的 Node.js 版本上是如何工作的。

`fs_readdir`中使用的模式是在`async`函数上下文中使用基于回调的函数所需的。

接下来，创建一个名为`.babelrc`的文件，其中包含以下内容：

```

This file instructs Babel to use the named transformation plugins that we installed earlier. As the name implies, it will transform the `async` functions to `generator` functions.

Because we installed `babel-cli`, a `babel` command is installed, such that we can type the following:

```

要转译您的代码，请运行以下命令：

```

This command transpiles the named file, producing a new file. The new file is as follows:

```

这段代码并不是为了人类易读。相反，它意味着你编辑原始源文件，然后将其转换为目标 JavaScript 引擎。要注意的主要事情是转译后的代码使用了生成器函数（`function*`表示生成器函数）代替`async`函数，使用`yield`关键字代替`await`关键字。生成器函数是什么，以及`yield`关键字的确切作用并不重要；唯一需要注意的是`yield`大致相当于`await`，而`_asyncToGenerator`函数实现了类似于 async 函数的功能。否则，转译后的代码相当清晰，看起来与原始代码相似。

转译后的脚本运行如下：

```

换句话说，它在旧的 Node.js 版本上运行与`async`版本相同。使用类似的过程，您可以转译使用现代 ES2015（等等）构造编写的代码，以便在旧的 Web 浏览器中运行。

在本节中，我们了解了 JavaScript 语言的进展，特别是 async 函数，然后学习了如何使用 Babel 在旧的 Node.js 版本或旧的 Web 浏览器上使用这些功能。

# 摘要

在本章中，您学到了使用 Node.js 的命令行工具安装 Node.js 并运行 Node.js 服务器。我们也匆匆忽略了很多细节，这些细节将在本书的后面进行详细介绍，所以请耐心等待。

具体来说，我们涵盖了下载和编译 Node.js 源代码，安装 Node.js（无论是在家目录中用于开发还是在系统目录中用于部署），以及安装 npm，这是与 Node.js 一起使用的事实上的标准包管理器。我们还看到了如何运行 Node.js 脚本或 Node.js 服务器。然后我们看了 ES2015、2016 和 2017 的新功能。最后，我们看了如何使用 Babel 在您的代码中实现这些功能。

现在我们已经看到如何设置开发环境，我们准备开始使用 Node.js 实现应用程序。第一步是学习 Node.js 应用程序和模块的基本构建模块，即更仔细地查看 Node.js 模块，它们是如何使用的，以及如何使用 npm 来管理应用程序的依赖关系。我们将在下一章中涵盖所有这些内容。


探索 Node.js 模块

模块和包是将应用程序拆分为较小部分的基本构建模块。模块封装了一些功能，主要是 JavaScript 函数，同时隐藏实现细节并为模块公开 API。模块可以由第三方分发并安装供我们的模块使用。已安装的模块称为包。

npm 包存储库是一个庞大的模块库，供所有 Node.js 开发人员使用。在该库中有数十万个包，可以加速您的应用程序开发。

由于模块和包是应用程序的构建模块，了解它们的工作原理对于您在 Node.js 中取得成功至关重要。在本章结束时，您将对 CommonJS 和 ES6 模块有扎实的基础，了解如何在应用程序中构建模块，如何管理第三方包的依赖关系，以及如何发布自己的包。

在本章中，我们将涵盖以下主题：

+   所有类型的 Node.js 模块的定义以及如何构建简单和复杂的模块

+   使用 CommonJS 和 ES2015/ES6 模块以及何时使用每种模块

+   了解 Node.js 如何找到模块和已安装的包，以便更好地构建您的应用程序

+   使用 npm 包管理系统（以及 Yarn）来管理应用程序的依赖关系，发布包，并记录项目的管理脚本

所以，让我们开始吧。

# 第五章：定义 Node.js 模块

模块是构建 Node.js 应用程序的基本构建模块。Node.js 模块封装了函数，将细节隐藏在一个受保护的容器内，并公开明确定义的 API。

当 Node.js 创建时，当然还不存在 ES6 模块系统。因此，Ryan Dahl 基于 CommonJS 标准创建了 Node.js 模块系统。到目前为止，我们看到的示例都是按照该格式编写的模块。随着 ES2015/ES2016，为所有 JavaScript 实现创建了一个新的模块格式。这种新的模块格式被前端工程师用于其浏览器 JavaScript 代码，也被 Node.js 工程师和其他 JavaScript 实现使用。

由于 ES6 模块现在是标准模块格式，Node.js **技术指导委员会**（**TSC**）承诺支持 ES6 模块与 CommonJS 格式的一流支持。从 Node.js 14.x 开始，Node.js TSC 兑现了这一承诺。

在 Node.js 平台上应用程序中使用的每个源文件都是一个*模块*。在接下来的几节中，我们将检查不同类型的模块，从 CommonJS 模块格式开始。

在本书中，我们将传统的 Node.js 模块标识为 CommonJS 模块，新的模块格式标识为 ES6 模块。

要开始探索 Node.js 模块，当然要从头开始。

## 检查传统的 Node.js 模块格式

我们已经在上一章中看到了 CommonJS 模块的实际应用。现在是时候看看它们是什么以及它们是如何工作的了。

在第二章中的`ls.js`示例中，*设置 Node.js*，我们编写了以下代码来引入`fs`模块，从而可以访问其函数：

```

The `require` function is given a *module identifier,* and it searches for the module named by that identifier. If found, it loads the module definition into the Node.js runtime and making its functions available. In this case, the `fs` object contains the code (and data) exported by the `fs` module. The `fs` module is part of the Node.js core and provides filesystem functions.

By declaring `fs` as `const`, we have a little bit of assurance against making coding mistakes. We could mistakenly assign a value to `fs`, and then the program would fail, but as a `const` we know the reference to the `fs` module will not be changed.

The file, `ls.js`, is itself a module because every source file we use on Node.js is a module. In this case, it does not export anything but is instead a script that consumes other modules.

What does it mean to say the `fs` object contains the code exported by the `fs` module? In a CommonJS module, there is an object, `module`, provided by Node.js, with which the module's author describes the module. Within this object is a field, `module.exports`, containing the functions and data exported by the module. The return value of the `require` function is the object. The object is the interface provided by the module to other modules. Anything added to the `module.exports` object is available to other pieces of code, and everything else is hidden. As a convenience, the `module.exports` object is also available as `exports`. 

The `module` object contains several fields that you might find useful. Refer to the online Node.js documentation for details.

Because `exports` is an alias of `module.exports`, the following two lines of code are equivalent:

```

您可以选择使用`module.exports`还是`exports`。但是，绝对不要做以下类似的事情：

```

Any assignment to `exports` will break the alias, and it will no longer be equivalent to `module.exports`. Assignments to `exports.something` are okay, but assigning to `exports` will cause failure. If your intent is to assign a single object or function to be returned by `require`, do this instead:

```

有些模块导出单个函数，因为这是模块作者设想提供所需功能的方式。

当我们说`ls.js`没有导出任何内容时，我们的意思是`ls.js`没有将任何内容分配给`module.exports`。

为了给我们一个简单的例子，让我们创建一个简单的模块，名为`simple.js`：

```

We have one variable, `count`, which is not attached to the `exports` object, and a function, `next`, which is attached. Because `count` is not attached to `exports`, it is private to the module. 

Any module can have private implementation details that are not exported and are therefore not available to any other code.

Now, let's use the module we just wrote:

```

模块中的`exports`对象是由`require('./simple')`返回的对象。因此，每次调用`s.next`都会调用`simple.js`中的`next`函数。每次返回（并递增）局部变量`count`的值。试图访问私有字段`count`会显示它在模块外部不可用。

这就是 Node.js 解决基于浏览器的 JavaScript 的全局对象问题的方式。看起来像全局变量的变量只对包含该变量的模块是全局的。这些变量对任何其他代码都不可见。

Node.js 包格式源自 CommonJS 模块系统（[`commonjs.org`](http://commonjs.org)）。在开发时，CommonJS 团队的目标是填补 JavaScript 生态系统中的空白。当时，没有标准的模块系统，使得打包 JavaScript 应用程序变得更加棘手。`require`函数、`exports`对象和 Node.js 模块的其他方面直接来自 CommonJS `Modules/1.0`规范。

`module`对象是由 Node.js 注入的全局模块对象。它还注入了另外两个变量：`__dirname`和`__filename`。这些对于帮助模块中的代码知道其在文件系统中的位置非常有用。主要用于使用相对于模块位置的路径加载其他文件。

例如，可以将像 CSS 或图像文件这样的资源存储在相对于模块的目录中。然后应用框架可以通过 HTTP 服务器提供这些文件。在 Express 中，我们可以使用以下代码片段来实现：

```

This says that HTTP requests on the `/assets/vendor/jquery` URL are to be handled by the static handler in Express, from the contents of a directory relative to the directory containing the module. Don't worry about the details because we'll discuss this more carefully in a later chapter. Just notice that `__dirname` is useful to calculate a filename relative to the location of the module source code.

To see it in action, create a file named `dirname.js` containing the following:

```

这让我们看到我们收到的值：

```

Simple enough, but as we'll see later these values are not directly available in ES6 modules.

Now that we've got a taste for CommonJS modules, let's take a look at ES2015 modules.

## Examining the ES6/ES2015 module format

ES6 modules are a new module format designed for all JavaScript environments. While Node.js has always had a good module system, browser-side JavaScript has not. That meant the browser-side community had to use non-standardized solutions. The CommonJS module format was one of those non-standard solutions, which was borrowed for use in Node.js. Therefore, ES6 modules are a big improvement for the entire JavaScript world, by getting everyone on the same page with a common module format and mechanisms.

An issue we have to deal with is the file extension to use for ES6 modules. Node.js needs to know whether to parse using the CommonJS or ES6 module syntax. To distinguish between them, Node.js uses the file extension `.mjs` to denote ES6 modules, and `.js` to denote CommonJS modules. However, that's not the entire story since Node.js can be configured to recognize the `.js` files as ES6 modules. We'll give the exact particulars later in this chapter.

The ES6 and CommonJS modules are conceptually similar. Both support exporting data and functions from a module, and both support hiding implementation inside a module. But they are very different in many practical ways.

Let's start with defining an ES6 module. Create a file named `simple2.mjs` in the same directory as the `simple.js` example that we looked at earlier:

```

这与`simple.js`类似，但添加了一些内容以演示更多功能。与以前一样，`count`是一个未导出的私有变量，`next`是一个导出的函数，用于递增`count`。

`export`关键字声明了从 ES6 模块中导出的内容。在这种情况下，我们有几个导出的函数和两个导出的变量。`export`关键字可以放在任何顶层声明的前面，比如变量、函数或类声明：

```

The effect of this is similar to the following:

```

两者的目的本质上是相同的：使函数或其他对象可供模块外部的代码使用。但是，我们不是显式地创建一个对象`module.exports`，而是简单地声明要导出的内容。例如`export function next()`这样的语句是一个命名导出，意味着导出的函数（就像这里）或对象有一个名称，模块外部的代码使用该名称来访问对象。正如我们在这里看到的，命名导出可以是函数或对象，也可以是类定义。

模块的*默认导出*是使用`export default`定义的，每个模块只能导出一次。默认导出是模块外部代码在使用模块对象本身时访问的内容，而不是使用模块中的导出之一。

你也可以先声明一些东西，比如`squared`函数，然后再导出它。

现在让我们看看如何使用 ES2015 模块。创建一个名为`simpledemo.mjs`的文件，内容如下：

```

The `import` statement does what it says: it imports objects exported from a module. Because it uses the `import * as foo` syntax, it imports everything from the module, attaching everything to an object, in this case named `simple2`. This version of the `import` statement is most similar to a traditional Node.js `require` statement because it creates an object with fields containing the objects exported from the module.

This is how the code executes:

```

过去，ES6 模块格式是隐藏在一个选项标志`--experimental-module`后面的，但是从 Node.js 13.2 开始，不再需要该标志。访问`default`导出是通过访问名为`default`的字段来实现的。访问导出的值，比如`meaning`字段，是不需要括号的，因为它是一个值而不是一个函数。

现在来看一种从模块中导入对象的不同方法，创建另一个文件，名为`simpledemo2.mjs`，内容如下：

```

In this case, the import is treated similarly to an ES2015 destructuring assignment. With this style of import, we specify exactly what is to be imported, rather than importing everything. Furthermore, instead of attaching the imported things to a common object, and therefore executing `simple2.next()`, the imported things are executed using their simple name, as in `next()`.

The import for `default as simple` is the way to declare an alias of an imported thing. In this case, it is necessary so that the default export has a name other than *default*. 

Node.js modules can be used from the ES2015 `.mjs` code. Create a file named `ls.mjs` containing the following:

```

这是第二章中`ls.js`示例的重新实现，*设置 Node.js*。在这两种情况下，我们都使用了`fs`包的`promises`子模块。要使用`import`语句，我们访问`fs`模块中的`promises`导出，并使用`as`子句将`fs.promises`重命名为`fs`。这样我们就可以使用异步函数而不是处理回调。

否则，我们有一个`async`函数`listFiles`，它执行文件系统操作以从目录中读取文件名。因为`listFiles`是`async`，它返回一个 Promise，我们必须使用`.catch`子句捕获任何错误。

执行脚本会得到以下结果：

```

The last thing to note about ES2015 module code is that the `import` and `export` statements must be top-level code. Try putting an `export` inside a simple block like this:

```

这个无辜的代码导致了一个错误：

```

While there are a few more details about the ES2015 modules, these are their most important attributes.

Remember that the objects injected into CommonJS modules are not available to ES6 modules. The `__dirname` and `__filename` objects are the most important, since there are many cases where we compute a filename relative to the currently executing module. Let us explore how to handle that issue.

### Injected objects in ES6 modules

Just as for CommonJS modules, certain objects are injected into ES6 modules. Furthermore, ES6 modules do not receive the `__dirname`, and `__filename` objects or other objects that are injected into CommonJS modules.

The `import.meta` meta-property is the only value injected into ES6 modules. In Node.js it contains a single field, `url`. This is the URL from which the currently executing module was loaded.

Using `import.meta.url`, we can compute `__dirname` and `__filename`.

### Computing the missing __dirname variable in ES6 modules

If we make a duplicate of `dirname.js` as `dirname.mjs`, so it will be interpreted as an ES6 module, we get the following:

```

由于`__dirname`和`__filename`不是 JavaScript 规范的一部分，它们在 ES6 模块中不可用。输入`import.meta.url`对象，我们可以计算`__dirname`和`__filename`。要看它的运行情况，创建一个包含以下内容的`dirname-fixed.mjs`文件：

```

We are importing a couple of useful functions from the `url` and `path` core packages. While we could take the `import.meta.url` object and do our own computations, these functions already exist. The computation is to extract the pathname portion of the module URL, to compute `__filename`, and then use `dirname` to compute `__dirname`.

```

我们看到模块的`file://` URL，以及使用内置核心函数计算的`__dirname`和`__filename`的值。

我们已经讨论了 CommonJS 和 ES6 模块格式，现在是时候讨论在应用程序中同时使用它们了。

## 同时使用 CommonJS 和 ES6 模块

Node.js 支持 JavaScript 代码的两种模块格式：最初为 Node.js 开发的 CommonJS 格式，以及新的 ES6 模块格式。这两种格式在概念上是相似的，但在实际上有许多不同之处。因此，我们将面临在同一个应用程序中同时使用两种格式的情况，并需要知道如何进行操作。

首先是文件扩展名的问题，以及识别要使用哪种模块格式。以下情况下使用 ES6 模块格式：

+   文件名以`.mjs`结尾的文件。

+   如果`package.json`有一个名为`type`且值为`module`的字段，则以`.js`结尾的文件。

+   如果`node`二进制文件使用`--input-type=module`标志执行，则通过`--eval`或`--print`参数传递的任何代码，或者通过 STDIN（标准输入）传入的代码，都将被解释为 ES6 模块代码。

这是相当直截了当的。ES6 模块在以`.mjs`扩展名命名的文件中，除非你在`package.json`中声明包默认使用 ES6 模块，这样以`.js`扩展名命名的文件也会被解释为 ES6 模块。

以下情况下使用 CommonJS 模块格式：

+   文件名以`.cjs`结尾的文件。

+   如果`package.json`不包含`type`字段，或者包含一个值为`commonjs`的`type`字段，则文件名将以`.js`结尾。

+   如果`node`二进制文件使用`--input-type`标志或`--type-type=commonjs`标志执行，则通过`--eval`或`--print`参数传递的任何代码，或者通过 STDIN（标准输入）传入的代码，都将被解释为 CommonJS 模块代码。

再次，这是直截了当的，Node.js 默认使用 CommonJS 模块来处理`.js`文件。如果包明确声明为默认使用 CommonJS 模块，则 Node.js 将把`.js`文件解释为 CommonJS。

Node.js 团队强烈建议包作者在`package.json`中包含一个`type`字段，即使类型是`commonjs`。

考虑一个具有这个声明的`package.json`：

```

This, of course, informs Node.js that the package defaults to ES6 modules. Therefore, this command interprets the module as an ES6 module:

```

这个命令将执行相同的操作，即使没有`package.json`条目：

```

If instead, the `type` field had the `commonjs`, or the `--input-type` flag specified as `commonjs`, or if both those were completely missing, then `my-module.js` would be interpreted as a CommonJS module.

These rules also apply to the `import` statement, the `import()` function, and the `require()` function. We will cover those commands in more depth in a later section. In the meantime, let's learn how the `import()` function partly resolves the inability to use ES6 modules in a CommonJS module. 

### Using ES6 modules from CommonJS using import()

The `import` statement in ES6 modules is a statement, and not a function like `require()`. This means that `import` can only be given a static string, and you cannot compute the module identifier to import. Another limitation is that `import` only works in ES6 modules, and therefore a CommonJS module cannot load an ES6 module. Or, can it?

Since the `import()` function is available in both CommonJS and ES6 modules, that means we should be able to use it to import ES6 modules in a CommonJS module. 

To see how this works, create a file named `simple-dynamic-import.js` containing the following:

```

这是一个使用我们之前创建的 ES6 模块的 CommonJS 模块。它只是调用了一些函数，除了它在我们之前说过的只有 ES6 模块中才能使用`import`之外，没有什么激动人心的地方。让我们看看这个模块的运行情况：

```

This is a CommonJS module successfully executing code contained in an ES6 module simply by using `import()`.

Notice that `import()` was called not in the global scope of the module, but inside an async function. As we saw earlier, the ES6 module keyword statements like `export` and `import` must be called in the global scope. However, `import()` is an asynchronous function, limiting our ability to use it in the global scope.

The `import` statement is itself an asynchronous process, and by extension the `import()` function is asynchronous, while the Node.js `require()` function is synchronous. 

In this case, we executed `import()` inside an `async` function using the `await` keyword. Therefore, even if `import()` were used in the global scope, it would be tricky getting a global-scope variable to hold the reference to that module. To see, why let's rewrite that example as `simple-dynamic-import-fail.js`:

```

这是相同的代码，但在全局范围内运行。在全局范围内，我们不能使用`await`关键字，所以我们应该期望`simple2`将包含一个挂起的 Promise。运行脚本会导致失败：

```

We see that `simple2` does indeed contain a pending Promise, meaning that `import()` has not yet finished. Since `simple2` does not contain a reference to the module, attempts to call the exported function fail.

The best we could do in the global scope is to attach the `.then` and `.catch` handlers to the `import()` function call. That would wait until the Promise transitions to either a success or failure state, but the loaded module would be inside the callback function. We'll see this example later in the chapter.

Let's now see how modules hide implementation details.

## Hiding implementation details with encapsulation in CommonJS and ES6 modules

We've already seen a couple of examples of how modules hide implementation details with the `simple.js` example and the programs we examined in Chapter 2, *Setting up Node.js*. Let's take a closer look.

Node.js modules provide a simple encapsulation mechanism to hide implementation details while exposing an API. To review, in CommonJS modules the exposed API is assigned to the `module.exports` object, while in ES6 modules the exposed API is declared with the `export` keyword. Everything else inside a module is not available to code outside the module.

In practice, CommonJS modules are treated as if they were written as follows:

```

因此，模块内的一切都包含在一个匿名的私有命名空间上下文中。这就解决了全局对象问题：模块中看起来全局的一切实际上都包含在一个私有上下文中。这也解释了注入的变量实际上是如何注入到模块中的。它们是创建模块的函数的参数。

另一个优势是代码安全性。因为模块中的私有代码被隐藏在私有命名空间中，所以模块外部的代码或数据无法访问私有代码。

让我们来看一个封装的实际演示。创建一个名为`module1.js`的文件，其中包含以下内容：

```

Then, create a file named `module2.js`, containing the following:

```

使用这两个模块，我们可以看到每个模块都是其自己受保护的泡泡。

然后按照以下方式运行它：

```

This artificial example demonstrates encapsulation of the values in `module1.js` from those in `module2.js`. The `A` and `B` values in `module1.js` don't overwrite `A` and `B` in `module2.js` because they're encapsulated within `module1.js`. The `values` function in `module1.js` does allow code in `module2.js` access to the values; however, `module2.js` cannot directly access those values. We can modify the object `module2.js` received from `module1.js`. But doing so does not change the values within `module1.js`.

In Node.js modules can also be data, not just code.

## Using JSON modules

Node.js supports using `require('./path/to/file-name.json')` to import a JSON file in a CommonJS module. It is equivalent to the following code:

```

也就是说，JSON 文件是同步读取的，文本被解析为 JSON。生成的对象作为模块导出的对象可用。创建一个名为`data.json`的文件，其中包含以下内容：

```

Now create a file named `showdata.js` containing the following:

```

它将执行如下：

```

The `console.log` function outputs information to the Terminal. When it receives an object, it prints out the object content like this. And this demonstrates that `require` correctly read the JSON file since the resulting object matched the JSON.

In an ES6 module, this is done with the `import` statement and requires a special flag. Create a file named `showdata-es6.mjs` containing the following:

```

到目前为止，这相当于该脚本的 CommonJS 版本，但使用`import`而不是`require`。

```

Currently using `import` to load a JSON file is an experimental feature. Enabling the feature requires these command-line arguments, causing this warning to be printed. We also see that instead of `data` being an anonymous object, it is an object with the type `Module`.

Now let's look at how to use ES6 modules on some older Node.js releases.

## Supporting ES6 modules on older Node.js versions

Initially, ES6 module support was an experimental feature in Node.js 8.5 and became a fully supported feature in Node.js 14\. With the right tools, we can use it on earlier Node.js implementations. 

For an example of using Babel to transpile ES6 code for older Node.js versions, see [`blog.revillweb.com/using-es2015-es6-modules-with-babel-6-3ffc0870095b`](https://blog.revillweb.com/using-es2015-es6-modules-with-babel-6-3ffc0870095b).

The better method of using ES6 modules on Node.js 6.x is the `esm` package. Simply do the following:

```

有两种方法可以使用这个模块：

+   在 CommonJS 模块中，调用`require('esm')`。

+   在命令行中使用`--require esm`，如下所示。

在这两种情况下，效果是一样的，即加载`esm`模块。这个模块只需要加载一次，我们不必调用它的任何方法。相反，`esm`将 ES6 模块支持改装到 Node.js 运行时中，并且与 6.x 版本及更高版本兼容。

因此，我们可以使用这个模块来改装 ES6 模块支持；它不改装其他功能，比如`async`函数。成功执行`ls.mjs`示例需要对`async`函数和箭头函数的支持。由于 Node.js 6.x 不支持任何一个，`ls.mjs`示例将能够正确加载，但仍将失败，因为它使用了其他不受支持的功能。

```

It is, of course, possible to use Babel in such cases to convert the full set of ES2015+ features to run on older Node.js releases.

For more information about esm, see: 
[`medium.com/web-on-the-edge/es-modules-in-node-today-32cff914e4b`](https://medium.com/web-on-the-edge/es-modules-in-node-today-32cff914e4b). The article describes an older release of the `esm` module, at the time named `@std/esm`.

Th current documentation for the esm package is available at: [`www.npmjs.com/package/esm`](https://www.npmjs.com/package/esm).

In this section, we've learned about how to define a Node.js module and various ways to use both CommonJS and ES6 modules. But we've left out some very important things: what is the module identifier and all the ways to locate and use modules. In the next section, we cover these topics.

# Finding and loading modules using require and import

In the course of learning about modules for Node.js, we've used the `require` and `import` features without going into detail about how modules are found and all the options available. The algorithm for finding Node.js modules is very flexible. It supports finding modules that are siblings of the currently executing module, or have been installed local to the current project, or have been installed globally.

For both `require` and `import`, the command takes a *module identifier*. The algorithm Node.js uses is in charge of resolving the module identifier into a file containing the module, so that Node.js can load the module.

The official documentation for this is in the Node.js documentation, at [`nodejs.org/api/modules.html`](https://nodejs.org/api/modules.html). [The official documentation for ES6 modules also discusses how the algorithm differs, at](https://nodejs.org/api/modules.html)[`nodejs.org/api/esm.html`](https://nodejs.org/api/esm.html)[.](https://nodejs.org/api/modules.html)

Understanding the module resolution algorithm is one key to success with Node.js. This algorithm determines how best to structure the code in a Node.js application. While debugging problems with loading the correct version of a given package, we need to know how Node.js finds packages.

First, we must consider several types of modules, starting with the simple file modules we've already used.

## Understanding File modules

The CommonJS and ES6 modules we've just looked at are what the Node.js documentation describes as a **file module**. Such modules are contained within a single file, whose filename ends with `.js`, `.cjs`, `.mjs`, `.json`, or `.node`. The latter are compiled from C or C++ source code, or even other languages such as Rust, while the former are, of course, written in JavaScript or JSON. 

The *module identifier* of a file module must start with `./` or `../`. This signals Node.js that the module identifier refers to a local file. As should already be clear, this module identifier refers to a pathname relative to the currently executing module.

It is also possible to use an absolute pathname as the module identifier. In a CommonJS module, such an identifier might be `/path/to/some/directory/my-module.js`. In an ES6 module, since the module identifier is actually a URL, then we must use a `file://` URL like `file:///path/to/some/directory/my-module.mjs`. There are not many cases where we would use an absolute module identifier, but the capability does exist.

One difference between CommonJS and ES6 modules is the ability to use extensionless module identifiers. The CommonJS module loader allows us to do this, which you should save as `extensionless.js`:

```

这使用了一个无扩展名的模块标识符来加载我们已经讨论过的模块`simple.js`：

```

And we can run it with the `node` command using an extension-less module identifier.

But if we specify an extension-less identifier for an ES6 module:

```

我们收到了错误消息，清楚地表明 Node.js 无法解析文件名。同样，在 ES6 模块中，给`import`语句的文件名必须带有文件扩展名。

接下来，让我们讨论 ES6 模块标识符的另一个副作用。

### ES6 的 import 语句采用 URL

ES6 `import`语句中的模块标识符是一个 URL。有几个重要的考虑因素。

由于 Node.js 只支持`file://`URL，我们不允许从 Web 服务器检索模块。这涉及明显的安全问题，如果模块可以从`http://`URL 加载，企业安全团队将会感到焦虑。

引用具有绝对路径名的文件必须使用`file:///path/to/file.ext`语法，如前面所述。这与`require`不同，我们将使用`/path/to/file.ext`。

由于`?`和`#`在 URL 中具有特殊意义，它们对`import`语句也具有特殊意义，如下例所示：

```

This loads the module named `module-name.mjs` with a query string containing `query=1`. By default, this is ignored by the Node.js module loader, but there is an experimental loader hook feature by which you can do something with the module identifier URL.

The next type of module to consider is those baked into Node.js, the core modules.

## Understanding the Node.js core modules

Some modules are pre-compiled into the Node.js binary. These are the core Node.js modules documented on the Node.js website at [`nodejs.org/api/index.html`](https://nodejs.org/api/index.html).

They start out as source code within the Node.js build tree. The build process compiles them into the binary so that the modules are always available.

We've already seen how the core modules are used. In a CommonJS module, we might use the following:

```

在 ES6 模块中的等效代码如下：

```

In both cases, we're loading the `http` and `fs` core modules that would then be used by other code in the module.

Moving on, we will next talk about more complex module structures.

## Using a directory as a module

We commonly organize stuff into a directory structure. The stuff here is a technical term referring to internal file modules, data files, template files, documentation, tests, assets, and more. Node.js allows us to create an entry-point module into such a directory structure.

For example, with a module identifier like `./some-library` that refers to a directory, then there must be a file named `index.js`, `index.cjs`, `index.mjs`, or `index.node` in the directory. In such a case, the module loader loads the appropriate `index` module even though the module identifier did not reference a full pathname. The pathname is computed by appending the file it finds in the directory.

One common use for this is that the `index` module provides an API for a library stored in the directory and that other modules in the directory contain what's meant to be private implement details.

This may be a little confusing because the word *module* is being overloaded with two meanings. In some cases, a module is a file, and in other cases, a module is a directory containing one or more file modules.

While overloading the word *module* this way might be a little confusing, it's going to get even more so as we consider the packages we install from other sources.

## Comparing installed packages and modules

Every programming platform supports the distribution of libraries or packages that are meant to be used in a wide array of applications. For example, where the Perl community has CPAN, the Node.js community has the `npm` registry. A Node.js *installed package* is the same as we just described as a *folder as a module*, in that the package format is simply a directory containing a `package.json` file along with the code and other files comprising the package.

There is the same risk of confusion caused by overloading the word *module* since an installed package is typically the same as the *directories as modules* concept just described. Therefore, it's useful to refer to an installed package with the word *package*.

The `package.json` file describes the package. A minimal set of fields are defined by Node.js, specifically as follows:

```

`name`字段给出了包的名称。如果存在`main`字段，它将命名要在加载包时使用的 JavaScript 文件，而不是`index.js`。像 npm 和 Yarn 这样的包管理应用程序支持`package.json`中的更多字段，它们用来管理依赖关系、版本和其他一切。

如果没有`package.json`，那么 Node.js 将寻找`index.js`或`index.node`。在这种情况下，`require('some-library')`将加载`/path/to/some-library/index.js`中的文件模块。

安装的包保存在一个名为`node_modules`的目录中。当 JavaScript 源代码有`require('some-library')`或`import 'some-library'`时，Node.js 会在一个或多个`node_modules`目录中搜索以找到命名的包。

请注意，在这种情况下，模块标识符只是包名。这与我们之前学习的文件和目录模块标识符不同，因为这两者都是路径名。在这种情况下，模块标识符有点抽象，这是因为 Node.js 有一个算法来在嵌套的`node_modules`目录中找到包。

要理解这是如何工作的，我们需要深入了解算法。

## 在文件系统中找到安装的包

Node.js 包系统如此灵活的关键之一是用于搜索包的算法。

对于给定的`require`、`import()`或`import`语句，Node.js 会在包含该语句的目录中向上搜索文件系统。它正在寻找一个名为`node_modules`的目录，其中包含满足模块标识符的模块。

例如，对于名为`/home/david/projects/notes/foo.js`的源文件和请求模块标识符`bar.js`的`require`或`import`语句，Node.js 尝试以下选项：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/b20040f4-8a85-4f12-b445-b49a673a904a.png)

正如刚才所说，搜索从`foo.js`所在的文件系统级别开始。Node.js 会查找名为`bar.js`的文件模块，或者包含模块的名为`bar.js`的目录，如*使用目录作为模块*中所述。Node.js 将在`foo.js`旁边的`node_modules`目录以及该文件上方的每个目录中检查这个包。但是，它不会进入任何目录，比如`express`或`express/node_modules`。遍历只会向文件系统上方移动，而不会向下移动。

虽然一些第三方包的名称以`.js`结尾，但绝大多数不是。因此，我们通常会使用`require('bar')`。通常，第三方安装的包是作为一个包含`package.json`文件和一些 JavaScript 文件的目录交付的。因此，在典型情况下，包模块标识符将是`bar`，Node.js 将在一个`node_modules`目录中找到一个名为`bar`的目录，并从该目录访问包。

在文件系统中向上搜索的这种行为意味着 Node.js 支持包的嵌套安装。一个 Node.js 包可能依赖于其他模块，这些模块将有自己的`node_modules`目录；也就是说，`bar`包可能依赖于`fred`包。包管理应用程序可能会将`fred`安装为`/home/david/projects/notes/node_modules/bar/node_modules/fred`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/0d84888b-cc4d-4f3c-881e-dd3dc6c71008.png)

在这种情况下，当`bar`包中的 JavaScript 文件使用`require('fred')`时，它的模块搜索从`/home/david/projects/notes/node_modules/bar/node_modules`开始，在那里它会找到`fred`包。但是，如果包管理器检测到`notes`中使用的其他包也使用`fred`包，包管理器将把它安装为`/home/david/projects/notes/node_modules/fred`。

因为搜索算法会在文件系统中向上查找，它会在任一位置找到`fred`。

最后要注意的是，这种`node_modules`目录的嵌套可以任意深。虽然包管理应用程序尝试在一个平面层次结构中安装包，但可能需要将它们深度嵌套。

这样做的一个原因是为了能够使用两个或更多版本的同一个包。

### 处理同一安装包的多个版本

Node.js 包标识符解析算法允许我们安装两个或更多版本的同一个包。回到假设的*notes*项目，注意`fred`包不仅为`bar`包安装，也为`express`包安装。

查看算法，我们知道`bar`软件包和`express`软件包中的`require('fred')`将分别满足于本地安装的相应`fred`软件包。

通常，软件包管理应用程序将检测`fred`软件包的两个实例并仅安装一个。但是，假设`bar`软件包需要`fred`版本 1.2，而`express`软件包需要`fred`版本 2.1。

在这种情况下，软件包管理应用程序将检测不兼容性，并安装两个版本的`fred`软件包，如下所示：

+   在`/home/david/projects/notes/node_modules/bar/node_modules`中，它将安装`fred`版本 1.2。

+   在`/home/david/projects/notes/node_modules/express/node_modules`中，它将安装`fred`版本 2.1。

当`express`软件包执行`require('fred')`或`import 'fred'`时，它将满足于`/home/david/projects/notes/node_modules/express/node_modules/fred`中的软件包。同样，`bar`软件包将满足于`/home/david/projects/notes/node_modules/bar/node_modules/fred`中的软件包。在这两种情况下，`bar`和`express`软件包都有`fred`软件包的正确版本可用。它们都不知道已安装另一个版本的`fred`。

`node_modules`目录用于应用程序所需的软件包。Node.js 还支持在全局位置安装软件包，以便它们可以被多个应用程序使用。

## 搜索全局安装的软件包

我们已经看到，使用 npm 可以执行*全局安装*软件包。例如，如果全局安装了`hexy`或`babel`等命令行工具，那么很方便。在这种情况下，软件包将安装在项目目录之外的另一个文件夹中。Node.js 有两种策略来查找全局安装的软件包。

与`PATH`变量类似，`NODE_PATH`环境变量可用于列出额外的目录，以便在其中搜索软件包。在类 Unix 操作系统上，`NODE_PATH`是一个由冒号分隔的目录列表，在 Windows 上是用分号分隔的。在这两种情况下，它类似于`PATH`变量的解释，这意味着`NODE_PATH`有一个目录名称列表，用于查找已安装的模块。

不建议使用`NODE_PATH`方法，因为如果人们不知道必须设置这个变量，可能会发生令人惊讶的行为。如果需要特定目录中的特定模块以正确运行，并且未设置该变量，应用程序可能会失败。最佳做法是明确声明所有依赖关系，对于 Node.js 来说，这意味着在`package.json`文件中列出所有依赖项，以便`npm`或`yarn`可以管理依赖项。

在刚刚描述的模块解析算法之前，已经实现了这个变量。由于该算法，`NODE_PATH`基本上是不必要的。

有三个额外的位置可以存放模块：

+   `$HOME/.node_modules`

+   `$HOME/.node_libraries`

+   `$PREFIX/lib/node`

在这种情况下，`$HOME`是您期望的（用户的主目录），而`$PREFIX`是安装 Node.js 的目录。

有人建议不要使用全局软件包。理由是希望实现可重复性和可部署性。如果您已经测试了一个应用程序，并且所有代码都方便地位于一个目录树中，您可以将该目录树复制到其他机器上进行部署。但是，如果应用程序依赖于系统其他位置神奇安装的某些其他文件，该怎么办？您会记得部署这些文件吗？应用程序的作者可能会编写文档，说明在运行*npm install*之前*安装这个*，然后*安装那个*，以及*安装其他东西*，但是应用程序的用户是否会正确地遵循所有这些步骤？

最好的安装说明是简单地运行*npm install*或*yarn install*。为了使其工作，所有依赖项必须在`package.json`中列出。

在继续之前，让我们回顾一下不同类型的模块标识符。

## 审查模块标识符和路径名

这是分布在几个部分的许多细节。因此，当使用`require`、`import()`或`import`语句时，快速回顾一下模块标识符是如何解释的是很有用的：

+   **相对模块标识符**：这些以 `./` 或 `../` 开头，绝对标识符以 `/` 开头。模块名称与 POSIX 文件系统语义相同。结果路径名是相对于正在执行的文件的位置进行解释的。也就是说，以 `./` 开头的模块标识符在当前目录中查找，而以 `../` 开头的模块标识符在父目录中查找。

+   **绝对模块标识符**：这些以 `/` （或 `file://` 用于 ES6 模块）开头，当然，会在文件系统的根目录中查找。这不是推荐的做法。

+   **顶级模块标识符**：这些不以这些字符串开头，只是模块名称。这些必须存储在`node_modules`目录中，Node.js 运行时有一个非常灵活的算法来定位正确的`node_modules`目录。

+   **核心模块**：这些与*顶级模块标识符*相同，即没有前缀，但核心模块已经预先嵌入到 Node.js 二进制文件中。

在所有情况下，除了核心模块，模块标识符都会解析为包含实际模块的文件，并由 Node.js 加载。因此，Node.js 所做的是计算模块标识符和实际文件名之间的映射关系。

不需要使用包管理器应用程序。Node.js 模块解析算法不依赖于包管理器，如 npm 或 Yarn，来设置`node_modules`目录。这些目录并没有什么神奇之处，可以使用其他方法构建包含已安装包的`node_modules`目录。但最简单的机制是使用包管理器应用程序。

一些包提供了我们可以称之为主包的子包，让我们看看如何使用它们。

## 使用深度导入模块标识符

除了像 `require('bar')` 这样的简单模块标识符外，Node.js 还允许我们直接访问包中包含的模块。使用不同的模块标识符，以模块名称开头，添加所谓的*深度导入*路径。举个具体的例子，让我们看一下 `mime` 模块（[`www.npmjs.com/package/mime`](https://www.npmjs.com/package/mime)），它处理将文件名映射到相应的 MIME 类型。

在正常情况下，你使用 `require('mime')` 来使用该包。然而，该包的作者开发了一个精简版本，省略了许多特定供应商的 MIME 类型。对于该版本，你使用 `require('mime/lite')`。当然，在 ES6 模块中，你会相应地使用 `import 'mime'` 和 `import 'mime/lite'`。

`mime/lite`是深度导入模块标识符的一个例子。

使用这样的模块标识符，Node.js 首先定位包含主要包的`node_modules`目录。在这种情况下，就是 `mime` 包。默认情况下，深度导入模块只是相对于包目录的路径名，例如，`/path/to/node_modules/mime/lite`。根据我们已经检查过的规则，它将被满足为一个名为 `lite.js` 的文件，或者一个名为 `lite` 的目录，其中包含一个名为 `index.js` 或 `index.mjs` 的文件。

但是可以覆盖默认行为，使深度导入标识符指向模块中的不同文件。

### 覆盖深度导入模块标识符

使用该包的代码所使用的深度导入模块标识符不必是包源内部使用的路径名。我们可以在 `package.json` 中放置声明，描述每个深度导入标识符的实际路径名。例如，具有内部模块命名为 `./src/cjs-module.js` 和 `./src/es6-module.mjs` 的包可以在 `package.json` 中使用此声明进行重新映射：

```

With this, code using such a package can load the inner module using `require('module-name/cjsmodule')` or `import 'module-name/es6module'`. Notice that the filenames do not have to match what's exported.

In a `package.json` file using this `exports` feature, a request for an inner module not listed in `exports` will fail. Supposing the package has a `./src/hidden-module.js` file, calling `require('module-name/src/hidden-module.js')` will fail.

All these modules and packages are meant to be used in the context of a Node.js project. Let's take a brief look at a typical project.

## Studying an example project directory structure

A typical Node.js project is a directory containing a `package.json` file declaring the characteristics of the package, especially its dependencies. That, of course, describes a directory module, meaning that each module is its own project. At the end of the day, we create applications, for example, an Express application, and these applications depend on one or more (possibly thousands of) packages that are to be installed:

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/cf27a654-d58c-4078-b716-46e60c3cc2d2.png)

This is an Express application (we'll start using Express in Chapter 5, *Your First Express Application*) containing a few modules installed in the `node_modules` directory. A typical Express application uses `app.js` as the main module for the application, and has code and asset files distributed in the `public`, `routes`, and `views` directories. Of course, the project dependencies are installed in the `node_modules` directory.

But let's focus on the content of the `node_modules` directory versus the actual project files. In this screenshot, we've selected the `express` package. Notice it has a `package.json` file and there is an `index.js` file. Between those two files, Node.js will recognize the `express` directory as a module, and calling `require('express')` or `import 'express'` will be satisfied by this directory.

The `express` directory has its own `node_modules` directory, in which are installed two packages. The question is, why are those packages installed in `express/node_modules` rather than as a sibling of the `express` package?

Earlier we discussed what happens if two modules (modules A and B) list a dependency on different versions of the same module (C). In such a case, the package manager application will install two versions of C, one as `A/node_modules/C` and the other as `B/node_modules/C`. The two copies of C are thus located such that the module search algorithm will cause module A and module B to have the correct version of module C.

That's the situation we see with `express/node_modules/cookie`. To verify this, we can use an `npm` command to query for all references to the module:

```

这表示 `cookie-parser` 模块依赖于 `cookie` 的 0.1.3 版本，而 Express 依赖于 0.1.5 版本。

现在我们可以认识到模块是什么，以及它们如何在文件系统中找到，让我们讨论何时可以使用每种方法来加载模块。

## 使用 require、import 和 import() 加载模块

显然，CommonJS 模块中使用 `require`，ES6 模块中使用 `import`，但有一些细节需要讨论。我们已经讨论了 CommonJS 和 ES6 模块之间的格式和文件名差异，所以让我们在这里专注于加载模块。

`require` 函数仅在 CommonJS 模块中可用，用于加载 CommonJS 模块。该模块是同步加载的，也就是说当 `require` 函数返回时，模块已完全加载。

默认情况下，CommonJS 模块无法加载 ES6 模块。但正如我们在 `simple-dynamic-import.js` 示例中看到的，CommonJS 模块可以使用 `import()` 加载 ES6 模块。由于 `import()` 函数是一个异步操作，它返回一个 Promise，因此我们不能将结果模块用作顶级对象。但我们可以在函数内部使用它：

```

And at the top-level of a Node.js script, the best we can do is the following:

```

这与 `simple-dynamic-import.js` 示例相同，但我们明确处理了 `import()` 返回的 Promise，而不是使用异步函数。虽然我们可以将 `simple2` 赋给全局变量，但使用该变量的其他代码必须适应赋值可能尚未完成的可能性。

`import()` 提供的模块对象包含在 ES6 模块中使用 `export` 语句导出的字段和函数。正如我们在这里看到的，默认导出具有 `default` 名称。

换句话说，在 CommonJS 模块中使用 ES6 模块是可能的，只要我们等待模块完成加载后再使用它。

`import` 语句用于加载 ES6 模块，仅在 ES6 模块内部有效。您传递给 `import` 语句的模块说明符被解释为 URL。

ES6 模块可以有多个命名导出。在我们之前使用的 `simple2.mjs` 中，这些是函数 `next`、`squared` 和 `hello`，以及值 `meaning` 和 `nocount`。ES6 模块可以有单个默认导出，就像我们在 `simple2.mjs` 中看到的那样。

通过 `simpledemo2.mjs`，我们看到可以只从模块中导入所需的内容：

```

In this case, we use the exports as just the name, without referring to the module: `simple()`, `hello()`, and `next()`.

It is possible to import just the default export:

```

在这种情况下，我们可以调用函数为 `simple()`。我们还可以使用所谓的命名空间导入；这类似于我们导入 CommonJS 模块的方式：

```

In this case, each property exported from the module is a property of the named object in the `import` statement. 

An ES6 module can also use `import` to load a CommonJS module. Loading the `simple.js` module we used earlier is accomplished as follows:

```

这类似于 ES6 模块所示的 *默认导出* 方法，我们可以将 CommonJS 模块内的 `module.exports` 对象视为默认导出。实际上，`import` 可以重写为以下形式：

```

This demonstrates that the CommonJS `module.exports` object is surfaced as `default` when imported.

We've learned a lot about using modules in Node.js. This included the different types of modules, and how to find them in the file system. Our next step is to learn about package management applications and the npm package repository.

# Using npm – the Node.js package management system

As described in Chapter 2, *Setting **up **Node.js*, npm is a package management and distribution system for Node.js. It has become the de facto standard for distributing modules (packages) for use with Node.js. Conceptually, it's similar to tools such as `apt-get` (Debian), `rpm`/`yum` (Red Hat/Fedora), MacPorts/Homebrew (macOS), CPAN (Perl), or PEAR (PHP). Its purpose is to publish and distributing Node.js packages over the internet using a simple command-line interface. In recent years, it has also become widely used for distributing front-end libraries like jQuery and Bootstrap that are not Node.js modules. With npm, you can quickly find packages to serve specific purposes, download them, install them, and manage packages you've already installed.

The `npm` application extends on the package format for Node.js, which in turn is largely based on the CommonJS package specification. It uses the same `package.json` file that's supported natively by Node.js, but with additional fields for additional functionality.

## The npm package format

An npm package is a directory structure with a `package.json` file describing the package. This is exactly what was referred to earlier as a directory module, except that npm recognizes many more `package.json` tags than Node.js does. The starting point for npm's `package.json` file is the CommonJS Packages/1.0 specification. The documentation for the npm `package.json` implementation is accessed using the following command:

```

一个基本的 `package.json` 文件如下：

```

Npm recognizes many more fields than this, and we'll go over some of them in the coming sections. The file is in JSON format, which, as a JavaScript programmer, you should be familiar with.

There is a lot to cover concerning the npm `package.json` format, and we'll do so over the following sections.

## Accessing npm helpful documentation

The main `npm` command has a long list of subcommands for specific package management operations. These cover every aspect of the life cycle of publishing packages (as a package author), and downloading, using, or removing packages (as an npm consumer).

You can view the list of these commands just by typing `npm` (with no arguments). If you see one you want to learn more about, view the help information:

```

帮助文本将显示在您的屏幕上。

npm 网站上也提供了帮助信息：[`docs.npmjs.com/cli-documentation/`](https://docs.npmjs.com/cli-documentation/)。

在查找和安装 Node.js 包之前，我们必须初始化项目目录。

## 使用 npm init 初始化 Node.js 包或项目

npm 工具使得初始化 Node.js 项目目录变得容易。这样的目录包含至少一个 `package.json` 文件和一个或多个 Node.js JavaScript 文件。

因此，所有 Node.js 项目目录都是模块，根据我们之前学到的定义。然而，在许多情况下，Node.js 项目并不打算导出任何功能，而是一个应用程序。这样的项目可能需要其他 Node.js 包，并且这些包将在`package.json`文件中声明，以便使用 npm 轻松安装。Node.js 项目的另一个常见用例是一个旨在供其他 Node.js 包或应用程序使用的功能包。这些包也包括一个`package.json`文件和一个或多个 Node.js JavaScript 文件，但在这种情况下，它们是导出函数的 Node.js 模块，可以使用`require`、`import()`或`import`加载。

这意味着初始化 Node.js 项目目录的关键是创建`package.json`文件。

`package.json`文件可以手动创建 - 毕竟它只是一个 JSON 文件 - npm 工具提供了一个方便的方法：

```

In a blank directory, run `npm init`, answer the questions, and as quick as that you have the starting point for a Node.js project.

This is, of course, a starting point, and as you write the code for your project it will often be necessary to use other packages.

## Finding npm packages

By default, `npm` packages are retrieved over the internet from the public package registry maintained on [`npmjs.com`](http://npmjs.com). If you know the module name, it can be installed simply by typing the following:

```

但是如果您不知道模块名称怎么办？如何发现有趣的模块？网站[`npmjs.com`](http://npmjs.com)发布了一个可搜索的模块注册表索引。npm 包还具有命令行搜索功能，可以查询相同的索引：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/de2ec86a-0e7d-4a98-ad55-6ee68f3e0d15.png)

当然，在找到一个模块后，它会被安装如下：

```

The npm repository uses a few `package.json` fields to aid in finding packages.

### The package.json fields that help finding packages

For a package to be easily found in the npm repository requires a good package name, package description, and keywords. The npm search function scans those package attributes and presents them in search results.

The relevant `package.json` fields are as follows:

```

`npm view`命令向我们显示了给定包的`package.json`文件中的信息，并且使用`--json`标志，我们可以看到原始的 JSON 数据。

`name`标签当然是包名，它在 URL 和命令名称中使用，因此选择一个对两者都安全的名称。如果您希望在公共`npm`存储库中发布一个包，最好通过在[`npmjs.com`](https://npmjs.com)上搜索或使用`npm search`命令来检查特定名称是否已被使用。

`description`标签是一个简短的描述，旨在作为包的简要描述。

在 npm 搜索结果中显示的是名称和描述标签。

`keywords`标签是我们列出包的属性的地方。npm 网站包含列出使用特定关键字的所有包的页面。当搜索包时，这些关键字索引非常有用，因为它们将相关的包列在一个地方，因此在发布包时，着陆在正确的关键字页面上是很有用的。

另一个来源是`README.md`文件的内容。这个文件应该被添加到包中，以提供基本的包文档。这个文件显示在`npmjs.com`上的包页面上，因此对于这个文件来说，说服潜在用户实际使用它是很重要的。正如文件名所示，这是一个 Markdown 文件。

一旦找到要使用的包，您必须安装它才能使用该包。

## 安装 npm 包

`npm install`命令使得在找到梦寐以求的包后安装变得容易，如下所示：

```

The named module is installed in `node_modules` in the current directory. During the installation process, the package is set up. This includes installing any packages it depends on and running the `preinstall` and `postinstall` scripts. Of course, installing the dependent packages also involves the same installation process of installing dependencies and executing pre-install and post-install scripts. 

Some packages in the npm repository have a package *scope* prepended to the package name. The package name in such cases is presented as `@scope-name/package-name`, or, for example, `@akashacms/plugins-footnotes`. In such a package, the `name` field in `package.json` contains the full package name with its `@scope`.

We'll discuss dependencies and scripts later. In the meantime, we notice that a version number was printed in the output, so let's discuss package version numbers.

## Installing a package by version number

Version number matching in npm is powerful and flexible. With it, we can target a specific release of a given package or any version number range. By default, npm installs the latest version of the named package, as we did in the previous section. Whether you take the default or specify a version number, npm will determine what to install.

The package version is declared in the `package.json` file, so let's look at the relevant fields:

```

`version`字段显然声明了当前包的版本。`dist-tags`字段列出了包维护者可以使用的符号标签，以帮助用户选择正确的版本。这个字段由`npm dist-tag`命令维护。

`npm install`命令支持这些变体：

```

The last two are what they sound like. You can specify `express@4.16.2` to target a precise version, or `express@">4.1.0 < 5.0"` to target a range of Express V4 versions. We might use that specific expression because Express 5.0 might include breaking changes.

The version match specifiers include the following choices:

*   **Exact version match**: 1.2.3
*   **At least version N**: >1.2.3
*   **Up to version N**: <1.2.3
*   **Between two releases**: >=1.2.3 <1.3.0

The `@tag` attribute is a symbolic name such as `@latest`, `@stable`, or `@canary`. The package owner assigns these symbolic names to specific version numbers and can reassign them as desired. The exception is `@latest`, which is updated whenever a new release of the package is published.

For more documentation, run these commands: `npm help json` and `npm help npm-dist-tag`.

In selecting the correct package to use, sometimes we want to use packages that are not in the npm repository.

## Installing packages from outside the npm repository

As awesome as the npm repository is, we don't want to push everything we do through their service. This is especially true for internal development teams who cannot publish their code for all the world to see. Fortunately, Node.js packages can be installed from other locations. Details about this are in `npm help package.json` in the `dependencies` section. Some examples are as follows:

*   **URL**: You can specify any URL that downloads a tarball, that is, a `.tar.gz` file. For example, GitHub or GitLab repositories can easily export a tarball URL. Simply go to the Releases tab to find them.
*   **Git URL**: Similarly, any Git repository can be accessed with the right URL, for example:

```

+   **GitHub 快捷方式**：对于 GitHub 存储库，您可以只列出存储库标识符，例如`expressjs/express`。可以使用`expressjs/express#tag-name`引用标签或提交。

+   **GitLab、BitBucket 和 GitHub URL 快捷方式**：除了 GitHub 快捷方式外，npm 还支持特定 Git 服务的特殊 URL 格式，如`github:user/repo`、`bitbucket:user/repo`和`gitlab:user/repo`。

+   **本地文件系统**：您可以使用 URL 从本地目录安装，格式为：`file:../../path/to/dir`。

有时，我们需要安装一个包，以供多个项目使用，而不需要每个项目都安装该包。

## 全局包安装

在某些情况下，您可能希望全局安装一个模块，以便可以从任何目录中使用它。例如，Grunt 或 Babel 构建工具非常有用，您可能会发现如果这些工具全局安装会很有用。只需添加`-g`选项：

```

If you get an error, and you're on a Unix-like system (Linux/Mac), you may need to run this with `sudo`:

```

当然，这种变体会以提升的权限运行`npm install`。

npm 网站提供了更多信息的指南，网址为[`docs.npmjs.com/resolving-eacces-permissions-errors-when-installing-packages-globally`](https://docs.npmjs.com/resolving-eacces-permissions-errors-when-installing-packages-globally)。

如果本地软件包安装到`node_modules`中，全局软件包安装会在哪里？在类 Unix 系统上，它会安装到`PREFIX/lib/node_modules`中，在 Windows 上，它会安装到`PREFIX/node_modules`中。在这种情况下，`PREFIX`表示安装 Node.js 的目录。您可以按以下方式检查目录的位置：

```

The algorithm used by Node.js for the `require` function automatically searches the directory for packages if the package is not found elsewhere.

ES6 modules do not support global packages.

Many believe it is not a good idea to install packages globally, which we will look at next.

### Avoiding global module installation

Some in the Node.js community now frown on installing packages globally. One rationale is that a software project is more reliable if all its dependencies are explicitly declared. If a build tool such as Grunt is required but is not explicitly declared in `package.json`, the users of the application would have to receive instructions to install Grunt, and they would have to follow those instructions. 

Users being users, they might skip over the instructions, fail to install the dependency, and then complain the application doesn't work. Surely, most of us have done that once or twice.

It's recommended to avoid this potential problem by installing everything locally via one mechanism—the `npm install` command.

There are two strategies we use to avoid using globally installed Node.js packages. For the packages that install commands, we can configure the `PATH` variable, or use `npx` to run the command. In some cases, a package is used only during development and can be declared as such in `package.json`.

## Maintaining package dependencies with npm

The `npm install` command by itself, with no package name specified, installs the packages listed in the `dependencies` section of `package.json`. Likewise, the `npm update` command compares the installed packages against the dependencies and against what's available in the npm repository and updates any package that is out of date in regards to the repository. 

These two commands make it easy and convenient to set up a project, and to keep it up to date as dependencies are updated. The package author simply lists all the dependencies, and npm installs or updates the dependencies required for using the package. What happens is npm looks in `package.json` for the `dependencies` or `devDependencies` fields, and it works out what to do from there.

You can manage the dependencies manually by editing `package.json`. Or you can use npm to assist you with editing the dependencies. You can add a new dependency like so:

```

使用`--save`标志，npm 将在`package.json`中添加一个`dependencies`标签：

```

With the added dependency, when your application is installed, `npm` will now install the package along with any other `dependencies` listed in `package.json` file.

The `devDependencies` lists modules used during development and testing. The field is initialized the same as the preceding one, but with the `--save-dev` flag. The `devDependencies` can be used to avoid some cases where one might instead perform a global package install.

By default, when `npm install` is run, modules listed in both `dependencies` and `devDependencies` are installed. Of course, the purpose of having two dependency lists is to control when each set of dependencies is installed.

```

这将安装“生产”版本，这意味着只安装`dependencies`中列出的模块，而不安装`devDependencies`中的任何模块。例如，如果我们在开发中使用像 Babel 这样的构建工具，该工具就不应该在生产环境中安装。

虽然我们可以在`package.json`中手动维护依赖关系，但 npm 可以为我们处理这些。

### 自动更新 package.json 的依赖关系

使用 npm@5（也称为 npm 版本 5），一个变化是不再需要向`npm install`命令添加`--save`。相反，`npm`默认会像您使用了`--save`命令一样操作，并会自动将依赖项添加到`package.json`中。这旨在简化使用`npm`，可以说`npm`现在更方便了。与此同时，`npm`自动修改`package.json`对您来说可能会非常令人惊讶和不便。可以使用`--no-save`标志来禁用此行为，或者可以使用以下方法永久禁用：

```

The `npm config` command supports a long list of settable options for tuning the behavior of npm. See `npm help config` for the documentation and `npm help 7 config` for the list of options.

Now let's talk about the one big use for package dependencies: to fix or avoid bugs.

### Fixing bugs by updating package dependencies

Bugs exist in every piece of software. An update to the Node.js platform may break an existing package, as might an upgrade to packages used by the application. Your application may trigger a bug in a package it uses. In these and other cases, fixing the problem might be as simple as updating a package dependency to a later (or earlier) version.

First, identify whether the problem exists in the package or in your code. After determining it's a problem in another package, investigate whether the package maintainers have already fixed the bug. Is the package hosted on GitHub or another service with a public issue queue? Look for an open issue on this problem. That investigation will tell you whether to update the package dependency to a later version. Sometimes, it will tell you to revert to an earlier version; for example, if the package maintainer introduced a bug that doesn't exist in an earlier version.

Sometimes, you will find that the package maintainers are unprepared to issue a new release. In such a case, you can fork their repository and create a patched version of their package. In such a case, your package might use a Github URL referencing your patched package.

One approach to fixing this problem is **pinning** the package version number to one that's known to work. You might know that version 6.1.2 was the last release against which your application functioned and that starting with version 6.2.0 your application breaks. Hence, in `package.json`:

```

这将冻结您对特定版本号的依赖。然后，您可以自由地花时间更新您的代码以适应模块的后续版本。一旦您的代码更新了，或者上游项目更新了，就相应地更改依赖关系。

在`package.json`中列出依赖项时，很容易变懒，但这会导致麻烦。

## 明确指定软件包依赖版本号

正如我们在本章中已经说过多次的那样，明确声明您的依赖关系是一件好事。我们已经提到过这一点，但值得重申并看看 npm 如何简化这一点。

第一步是确保您的应用程序代码已经检入源代码存储库。您可能已经知道这一点，并且甚至打算确保所有内容都已检入。对于 Node.js，每个模块应该有自己的存储库，而不是将每一个代码片段都放在一个存储库中。

然后，每个模块可以按照自己的时间表进行进展。一个模块的故障很容易通过在`package.json`中更改版本依赖来撤消。

下一步是明确声明每个模块的所有依赖关系。目标是简化和自动化设置每个模块的过程。理想情况下，在 Node.js 平台上，模块设置就像运行`npm install`一样简单。

任何额外所需的步骤都可能被遗忘或执行不正确。自动设置过程消除了几种潜在的错误。

通过`package.json`的`dependencies`和`devDependencies`部分，我们不仅可以明确声明依赖关系，还可以指定版本号。

懒惰地声明依赖关系的方法是在版本字段中放入`*`。这将使用 npm 存储库中的最新版本。这似乎有效，直到有一天，该软件包的维护者引入了一个 bug。你会输入`npm update`，突然间你的代码就无法工作了。你会跳转到软件包的 GitHub 网站，查看问题队列，可能会看到其他人已经报告了你所看到的问题。其中一些人会说他们已经固定在之前的版本上，直到这个 bug 被修复。这意味着他们的`package.json`文件不依赖于最新版本的`*`，而是依赖于在 bug 产生之前的特定版本号。

不要做懒惰的事情，做明智的事情。

明确声明依赖关系的另一个方面是不隐式依赖全局软件包。之前，我们说过 Node.js 社区中有些人警告不要在全局目录中安装模块。这可能看起来像在应用程序之间共享代码的一种简便方法。只需全局安装，你就不必在每个应用程序中安装代码。

但是，这会让部署变得更加困难吗？新的团队成员会被指示安装这里和那里的所有特殊文件来使应用程序运行吗？你会记得在所有目标机器上安装那个全局模块吗？

对于 Node.js 来说，这意味着列出`package.json`中的所有模块依赖项，然后安装指令就是简单的`npm install`，然后可能是编辑配置文件。

尽管 npm 存储库中的大多数软件包都是带有 API 的库，但有些是我们可以从命令行运行的工具。

## 安装命令的软件包

有些软件包安装命令行程序。安装这些软件包的一个副作用是，你可以在 shell 提示符下输入新的命令，或者在 shell 脚本中使用。一个例子是我们在第二章中简要使用过的`hexy`程序，*设置 Node.js*。另一个例子是广泛使用的 Grunt 或 Babel 构建工具。

明确声明所有依赖关系在`package.json`中的建议适用于命令行工具以及任何其他软件包。因此，这些软件包通常会被本地安装。这需要特别注意正确设置`PATH`环境变量。正如你可能已经知道的那样，`PATH`变量在类 Unix 系统和 Windows 上都用于列出命令行 shell 搜索命令的目录。

命令可以安装到两个地方之一：

+   **全局安装**：它安装到一个目录，比如`/usr/local`，或者 Node.js 安装的`bin`目录。`npm bin -g`命令告诉你这个目录的绝对路径名。在这种情况下，你不太可能需要修改 PATH 环境变量。

+   **本地安装**：安装到正在安装模块的`package`中的`node_modules/.bin`，`npm bin`命令告诉你该目录的绝对路径名。因为该目录不方便运行命令，所以改变 PATH 变量是有用的。

要运行命令，只需在 shell 提示符下输入命令名称。如果命令安装的目录恰好在 PATH 变量中，这样就能正确运行。让我们看看如何配置 PATH 变量以处理本地安装的命令。

### 配置 PATH 变量以处理本地安装的命令

假设我们已经安装了`hexy`命令，如下所示：

```

As a local install, this creates a command as `node_modules/.bin/hexy`. We can attempt to use it as follows:

```

但这会出错，因为命令不在`PATH`中列出的目录中。解决方法是使用完整路径名或相对路径名：

```

But obviously typing the full or partial pathname is not a user-friendly way to execute the command. We want to use the commands installed by modules, and we want a simple process for doing so. This means, we must add an appropriate value in the `PATH` variable, but what is it?

For global package installations, the executable lands in a directory that is probably already in your `PATH` variable, like `/usr/bin` or `/usr/local/bin`. Local package installations require special handling. The full path for the `node_modules/.bin` directory varies for each project, and obviously it won't work to add the full path for every `node_modules/.bin` directory to your `PATH`.

Adding `./node_modules/.bin` to the `PATH` variable (or, on Windows, `.\node_modules\.bin`) works great. Any time your shell is in the root of a Node.js project, it will automatically find locally installed commands from Node.js packages.

How we do this depends on the command shell you use and your operating system.

On a Unix-like system, the command shells are `bash` and `csh`. Your `PATH` variable would be set up in one of these ways:

```

下一步是将命令添加到你的登录脚本中，这样变量就会一直设置。在`bash`上，添加相应的行到`~/.bashrc`，在`csh`上，添加到`~/.cshrc`。

一旦完成了这一步，命令行工具就能正确执行。

### 在 Windows 上配置 PATH 变量

在 Windows 上，这个任务是通过系统范围的设置面板来处理的：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/4e178c1e-2d36-4402-8e8e-713142886014.png)

在 Windows 设置屏幕中搜索`PATH`，可以找到`系统属性`面板的这个窗格。点击`环境变量`按钮，然后选择`Path`变量，最后点击`编辑`按钮。在这个屏幕上，点击`新建`按钮添加一个条目到这个变量中，并输入`.\node_modules\.bin`如图所示。你必须重新启动任何打开的命令行窗口。一旦你这样做了，效果就会如前所示。

尽管修改 PATH 变量很容易，但我们不希望在所有情况下都这样做。

### 避免修改 PATH 变量

如果你不想始终将这些变量添加到你的`PATH`中怎么办？`npm-path`模块可能会引起你的兴趣。这是一个小程序，可以计算出适合你的 shell 和操作系统的正确`PATH`变量。查看[`www.npmjs.com/package/npm-path`](https://www.npmjs.com/package/npm-path)上的包。

另一个选择是使用`npx`命令来执行这些命令。这个工具会自动安装在`npm`命令旁边。这个命令要么执行来自本地安装包的命令，要么在全局缓存中静默安装命令：

```

Using `npx` is this easy.

Of course, once you've installed some packages, they'll go out of date and need to be updated.

## Updating packages you've installed when they're outdated

The coder codes, updating their package, leaving you in the dust unless you keep up.

To find out whether your installed packages are out of date, use the following command:

```

报告显示了当前的 npm 包、当前安装的版本，以及`npm`仓库中的当前版本。更新过时的包非常简单：

```

Specifying a package name updates just the named package. Otherwise, it updates every package that would be printed by `npm outdated`.

Npm handles more than package management, it has a decent built-in task automation system.

## Automating tasks with scripts in package.json

The `npm` command handles not just installing packages, it can also be used to automate running tasks related to the project. In `package.json`, we can add a field, `scripts`, containing one or more command strings. Originally scripts were meant to handle tasks related to installing an application, such as compiling native code, but they can be used for much more. For example, you might have a deployment task using `rsync` to copy files to a server. In `package.json`, you can add this:

```

重要的是，我们可以添加任何我们喜欢的脚本，`scripts`条目记录了要运行的命令：

```

Once it has been recorded in `scripts`, running the command is this easy.

There is a long list of "lifecycle events" for which npm has defined script names. These include the following:

*   `install`, for when the package is installed
*   `uninstall`, for when it is uninstalled
*   `test`, for running a test suite
*   `start` and `stop`, for controlling a server defined by the package

Package authors are free to define any other script they like. 

For the full list of predefined script names, see the documentation: [`docs.npmjs.com/misc/scripts`](https://docs.npmjs.com/misc/scripts)

Npm also defines a pattern for scripts that run before or after another script, namely to prepend `pre` or `post` to the script name. Therefore the `pretest` script runs before the `test` script, and the `posttest` script runs afterward.

A practical example is to run a test script in a `prepublish` script to ensure the package is tested before publishing it to the npm repository:

```

有了这个组合，如果测试作者输入`npm publish`，`prepublish`脚本将导致`test`脚本运行，然后使用`mocha`运行测试套件。

自动化所有管理任务是一个众所周知的最佳实践，即使只是为了你永远不会忘记如何运行这些任务。为每个这样的任务创建`scripts`条目不仅可以防止你忘记如何做事，还可以为他人记录管理任务。

接下来，让我们谈谈如何确保执行包的 Node.js 平台支持所需的功能。

## 声明 Node.js 版本兼容性

重要的是，你的 Node.js 软件必须在正确的 Node.js 版本上运行。主要原因是你的包运行时需要的 Node.js 平台功能必须可用。因此，包的作者必须知道哪些 Node.js 版本与包兼容，然后在`package.json`中描述这种兼容性。

这个依赖在`package.json`中使用`engines`标签声明：

```

版本字符串类似于我们可以在`dependencies`和`devDependencies`中使用的。在这种情况下，我们定义了该包与 Node.js 8.x、9.x 和 10.x 兼容。

现在我们知道如何构建一个包，让我们谈谈发布包。

## 发布 npm 包

npm 仓库中的所有这些包都来自像你一样有更好的做事方式的人。发布包非常容易入门。

关于发布包的在线文档可以在[`docs.npmjs.com/getting-started/publishing-npm-packages`](https://docs.npmjs.com/getting-started/publishing-npm-packages)找到。

还要考虑这个：[`xkcd.com/927/`](https://xkcd.com/927/)。

首先使用`npm adduser`命令在 npm 仓库中注册。你也可以在网站上注册。接下来，使用`npm login`命令登录。

最后，在包的根目录中使用`npm publish`命令。然后，退后一步，以免被涌入的粉丝踩到，或者可能不会。仓库中有数以亿计的包，每天都有数百个包被添加。要使你的包脱颖而出，你需要一些营销技巧，这是本书范围之外的另一个话题。

建议你的第一个包是一个作用域包，例如`@my-user-name/my-great-package`。

在本节中，我们学到了很多关于使用 npm 来管理和发布包。但是 npm 并不是管理 Node.js 包的唯一选择。

# Yarn 包管理系统

尽管 npm 非常强大，但它并不是 Node.js 的唯一包管理系统。因为 Node.js 核心团队并没有规定一个包管理系统，Node.js 社区可以自由地开发他们认为最好的任何系统。我们绝大多数人使用 npm 是对其价值和有用性的证明。但是，还有一个重要的竞争对手。

Yarn（参见[`yarnpkg.com/en/`](https://yarnpkg.com/en/)）是 Facebook、Google 和其他几家公司的工程师合作开发的。他们宣称 Yarn 是超快、超安全（通过使用所有内容的校验和）和超可靠（通过使用`yarn-lock.json`文件记录精确的依赖关系）。

Yarn 不是运行自己的包存储库，而是在`npmjs.com`的 npm 包存储库上运行。这意味着 Node.js 社区并没有被 Yarn 分叉，而是通过一个改进的包管理工具得到了增强。

npm 团队在 npm@5（也称为 npm 版本 5）中对 Yarn 做出了回应，通过提高性能和引入`package-lock.json`文件来提高可靠性。npm 团队在 npm@6 中实施了额外的改进。

Yarn 已经变得非常流行，并且被广泛推荐用于 npm。它们执行非常相似的功能，性能与 npm@5 并没有太大的不同。命令行选项的表述方式也有所不同。我们讨论过的 npm 的一切功能 Yarn 也都支持，尽管命令语法略有不同。Yarn 给 Node.js 社区带来的一个重要好处是，Yarn 和 npm 之间的竞争似乎正在促使 Node.js 包管理的更快进步。

为了让你开始，这些是最重要的命令：

+   `yarn add`：将一个包添加到当前包中使用

+   `yarn init`：初始化一个包的开发

+   `yarn install`：安装`package.json`文件中定义的所有依赖项

+   `yarn publish`：将包发布到包管理器

+   `yarn remove`：从当前包中移除一个未使用的包

运行`yarn`本身就会执行`yarn install`的行为。Yarn 还有其他几个命令，`yarn help`会列出它们所有。

# 总结

在本章中，你学到了很多关于 Node.js 的模块和包。具体来说，我们涵盖了为 Node.js 实现模块和包，我们可以使用的不同模块结构，CommonJS 和 ES6 模块之间的区别，管理已安装的模块和包，Node.js 如何定位模块，不同类型的模块和包，如何以及为什么声明对特定包版本的依赖关系，如何找到第三方包，以及我们如何使用 npm 或 Yarn 来管理我们使用的包并发布我们自己的包。

现在你已经学习了关于模块和包，我们准备使用它们来构建应用程序，在下一章中我们将看到。
