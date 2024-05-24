# React 全栈项目（一）

> 原文：[`zh.annas-archive.org/md5/05F04F9004AE49378ED0525C32CB85EB`](https://zh.annas-archive.org/md5/05F04F9004AE49378ED0525C32CB85EB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书探讨了通过将 React 的力量与经过行业测试的服务器端技术（如 Node、Express 和 MongoDB）相结合，开发全栈 JavaScript Web 应用的潜力。JavaScript 领域已经快速增长了一段时间。在这个主题上有大量的选择和资源可用，当你需要从这些经常变化的部分中进行选择、了解它们并使它们一起工作来构建自己的 Web 应用时，很容易迷失。为了解决这一痛点，本书采用了一种实用的方法，帮助您设置和构建使用这种流行的 JavaScript 堆栈的各种工作应用程序。

# 本书适合的读者

本书面向有一些 React 经验但没有涉及 Node、Express 和 MongoDB 的全栈开发经验的 JavaScript 开发人员，他们希望获得实用的指南，以开始使用这种堆栈构建不同类型的 Web 应用程序。

# 本书涵盖的内容

第一章，《使用 MERN 释放 React 应用程序》，介绍了 MERN 堆栈技术和本书中开发的应用程序。我们将讨论使用 React、Node、Express 和 MongoDB 开发 Web 应用程序的背景和相关性。

第二章，《准备开发环境》，帮助设置 MERN 堆栈技术以进行开发。我们将探索必要的开发工具，安装 Node、MongoDB、Express、React 和其他所需的库，然后运行代码来检查设置。

第三章，《使用 MongoDB、Express 和 Node 构建后端》，实现了一个骨架 MERN 应用的后端。我们将构建一个独立的服务器端应用程序，其中包括 MongoDB、Express 和 Node，用于存储用户详细信息，并具有用于用户身份验证和 CRUD 操作的 API。

第四章，《添加 React 前端以完成 MERN》，通过集成 React 前端完成了 MERN 骨架应用程序。我们将使用 React 视图实现一个可与服务器上的用户 CRUD 和 auth API 进行交互的工作前端。

第五章，“从简单的社交媒体应用开始”，通过扩展骨架应用程序构建了一个社交媒体应用程序。我们将通过实现社交媒体功能来探索 MERN 堆栈的能力，例如帖子分享、点赞和评论；关注朋友；以及聚合新闻源。

第六章，“通过在线市场锻炼新的 MERN 技能”，在在线市场应用程序中实现了基本功能。我们将实现与买卖相关的功能，支持卖家账户、产品列表和按类别搜索产品。

第七章，“扩展订单和支付的市场”，进一步构建了市场应用程序，包括购物车、订单管理和支付处理。我们将添加购物车功能，允许用户使用购物车中的商品下订单。我们还将集成 Stripe 以收集和处理付款。

第八章，“构建媒体流应用程序”，使用 MongoDB GridFS 实现媒体上传和流媒体。我们将开始构建一个基本的媒体流应用程序，允许注册用户上传视频文件，这些文件将存储在 MongoDB 上并流回，以便观众可以在简单的 React 媒体播放器中播放每个视频。

第九章，“定制媒体播放器和改善 SEO”，通过定制媒体播放器和自动播放媒体列表来升级媒体查看功能。我们将在默认的 React 媒体播放器上实现定制控件，添加可以自动播放的播放列表，并通过为媒体详细信息添加有选择的服务器端渲染和数据来改善 SEO。

第十章，“开发基于 Web 的 VR 游戏”，使用 React 360 开发了一个用于 Web 的 3D 虚拟现实游戏。我们将探索 React 360 的 3D 和 VR 功能，并构建一个简单的基于 Web 的 VR 游戏。

第十一章，*使用 MERN 使 VR 游戏动态化*，通过扩展 MERN 骨架应用程序并集成 React 360，构建了一个动态的 VR 游戏应用程序。我们将实现一个游戏数据模型，允许用户创建自己的 VR 游戏，并将动态游戏数据与使用 React 360 开发的游戏相结合。

第十二章，*遵循最佳实践并进一步开发 MERN*，反思了前几章的教训，并提出了进一步基于 MERN 的应用程序开发的改进建议。我们将扩展一些已经应用的最佳实践，比如应用程序结构中的模块化，其他应该应用的实践，比如编写测试代码，以及可能的改进，比如优化捆绑大小。

# 为了充分利用本书

本书的内容组织假定您熟悉基本的基于 Web 的技术，了解 JavaScript 中的编程构造，并对 React 应用程序的工作原理有一般了解。在阅读本书时，您将了解这些概念在使用 React、Node、Express 和 MongoDB 构建完整的 Web 应用程序时是如何结合在一起的。

为了在阅读各章节时最大限度地提高学习体验，建议您并行运行相关应用程序代码的关联版本，并使用每章提供的相关说明。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用以下最新版本的解压缩或提取文件夹：

+   Windows 上的 WinRAR/7-Zip

+   Mac 上的 Zipeg/iZip/UnRarX

+   Linux 上的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Full-Stack-React-Projects`](https://github.com/PacktPublishing/Full-Stack-React-Projects)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自我们丰富书籍和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如："将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。"

代码块设置如下：

```jsx
import path from 'path'
const CURRENT_WORKING_DIR = process.cwd()
app.use('/dist', express.static(path.join(CURRENT_WORKING_DIR, 'dist')))
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项将以粗体显示：

```jsx
{
    "presets": [
      "env",
      "stage-2",
      "react"
    ],
    "plugins": [
 "react-hot-loader/babel"
 ]
}
```

任何命令行输入或输出都将按照以下方式书写：

```jsx
npm install babel-preset-react --save-dev
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中以这种方式出现。例如："从管理面板中选择系统信息。"

警告或重要说明会以这种方式出现。提示和技巧会以这种方式出现。


# 第一章：使用 MERN 释放 React 应用程序

React 可能已经为前端 Web 开发开辟了新的领域，并改变了我们编写 JavaScript 用户界面的方式，但我们仍然需要一个坚实的后端来构建完整的 Web 应用程序。尽管在选择后端技术时有很多选择，但使用完整的 JavaScript 堆栈的好处和吸引力是不可否认的，特别是当有像 Node、Express 和 MongoDB 这样强大且被广泛采用的后端技术时。将 React 的潜力与这些经过行业测试的服务器端技术相结合，可以在开发现实世界 Web 应用程序时创造多样的可能性。

本书将指导您进行基于 MERN 的 Web 开发设置，以构建不同复杂性的实际 Web 应用程序。

在深入开发这些 Web 应用程序之前，我们将在本章中回答以下问题，以便为使用 MERN 设置背景：

+   什么是 MERN 堆栈？

+   为什么 MERN 如今仍然相关？

+   MERN 何时适合开发 Web 应用程序？

+   这本书如何组织以帮助掌握 MERN？

# MERN 堆栈

MongoDB、Express、React 和 Node 一起被用来构建 Web 应用程序，并组成了 MERN 堆栈。在这个组合中，Node 和 Express 将 Web 后端绑在一起，MongoDB 作为 NoSQL 数据库，React 构建用户看到并与之交互的前端。

这四种技术都是免费的、开源的、跨平台的，基于 JavaScript，并得到了广泛的社区和行业支持。每种技术都有一套独特的属性，当它们集成在一起时，就可以构建一个简单但有效的完整 JavaScript 堆栈，用于 Web 开发。

# Node

Node 是建立在 Chrome 的 V8 JavaScript 引擎上的 JavaScript 运行时环境。Node 使得在服务器端使用 JavaScript 来构建各种工具和应用成为可能，而不再局限于浏览器内的先前用例。

Node 具有事件驱动的架构，能够进行异步、非阻塞的 I/O。它独特的非阻塞 I/O 模型消除了等待请求的方式。这使得构建可扩展和轻量级的实时 Web 应用程序成为可能，可以高效地处理许多请求。

Node 的默认包管理系统，Node 包管理器或 npm，已捆绑在 Node 安装中。Npm 提供了数十万个由世界各地的开发人员构建的可重用 Node 包，并自称目前是世界上最大的开源库生态系统。

在[`nodejs.org/en/`](https://nodejs.org/en/)了解更多关于 Node，并浏览可用的 npm 模块在[`www.npmjs.com/`](https://www.npmjs.com/)。

# Express

Express 是一个用于构建带有 Node 服务器的 Web 应用程序和 API 的基本框架。它提供了一层简单的基本 Web 应用程序功能，可以补充 Node。

在使用 Node 开发的任何 Web 应用程序中，Express 可以用作路由和中间件 Web 框架，具有自己的最小功能-Express 应用程序本质上是一系列中间件函数调用。

**中间件**函数是具有对 HTTP 请求和响应对象的访问权限，以及 Web 应用程序请求-响应周期中的下一个中间件函数的访问权限的函数。

可以将几乎任何兼容的中间件插入到请求处理链中，几乎可以按任何顺序进行，使 Express 非常灵活易用。

在[expressjs.com](http://expressjs.com)上了解 Express.js 的可能性。

# MongoDB

在决定用于任何应用程序的 NoSQL 数据库时，MongoDB 是首选。它是一个面向文档的数据库，可以将数据存储在灵活的类 JSON 文档中。这意味着字段可以在文档之间变化，并且数据模型可以随着应用程序要求的变化而随时间演变。

将高可用性和可扩展性放在首位的应用程序受益于 MongoDB 的分布式架构功能。它内置支持高可用性，使用分片进行水平扩展，并且可以跨地理分布进行多数据中心的可扩展性。

MongoDB 具有表达丰富的查询语言，可以进行即席查询，索引以实现快速查找，并提供实时聚合，从而提供了强大的访问和分析数据的方式，即使数据量呈指数级增长，也能保持性能。

在[`www.mongodb.com/`](https://www.mongodb.com/)上探索 MongoDB 的功能和服务。

# React

React 是一个声明式的、基于组件的 JavaScript 库，用于构建用户界面。它的声明式和模块化特性使开发人员能够轻松创建和维护可重用、交互式和复杂的用户界面。

如果使用 React 构建，显示大量变化数据的大型应用程序可以快速响应，因为它会在特定数据更改时高效地更新和渲染正确的 UI 组件。React 通过其对虚拟 DOM 的显著实现进行高效渲染，这使其与其他处理页面更新的 Web UI 库有所区别，后者直接在浏览器的 DOM 中进行昂贵的操作。

使用 React 开发用户界面也迫使前端程序员编写合理和模块化的代码，这些代码是可重用的，更容易调试、测试和扩展。

在[`reactjs.org/`](https://reactjs.org/)上查看有关 React 的资源。

由于所有四种技术都是基于 JavaScript 的，它们本质上都是为集成进行了优化。然而，实际上如何将它们组合在一起形成 MERN 堆栈可能会根据应用程序要求和开发者偏好而有所不同，使 MERN 可以根据特定需求进行定制和扩展。

# MERN 的相关性

自 JavaScript 诞生以来，它已经走过了很长的路，而且它还在不断发展。MERN 堆栈技术挑战了现状，并为 JavaScript 的可能性开辟了新的领域。但是，当涉及到开发需要可持续的真实应用程序时，选择 MERN 是否是一个值得的选择呢？以下简要概述了选择 MERN 作为下一个 Web 应用程序的强有力理由。

# 技术堆栈的一致性

由于 JavaScript 一直在使用，开发人员不需要频繁学习和切换到使用非常不同的技术。这也促进了在不同部分的 Web 应用程序上工作的团队之间更好的沟通和理解。

# 学习、开发、部署和扩展所需的时间更少

技术堆栈的一致性也使学习和使用 MERN 变得更加容易，减少了采用新堆栈的开销和开发工作的时间。一旦建立了 MERN 应用程序的工作基础并建立了工作流程，复制、进一步开发和扩展任何应用程序就需要更少的工作量。

# 在行业中被广泛采用

基于其需求，各种规模的组织一直在采用此堆栈中的技术，因为他们可以更快地构建应用程序，处理高度多样化的需求，并在规模上更有效地管理应用程序。

# 社区支持和增长

围绕非常流行的 MERN 堆栈技术的开发者社区非常多样化，并且定期增长。由于有很多人不断使用、修复、更新，并愿意帮助发展这些技术，支持系统在可预见的未来将保持强大。这些技术将继续得到维护，并且在文档、附加库和技术支持方面很可能会提供资源。

使用这些技术的便利性和好处已经被广泛认可。由于继续采用和适应的知名公司，以及不断增加的为代码库做出贡献、提供支持和创建资源的人数，MERN 堆栈中的技术将在很长一段时间内继续保持相关性。

# MERN 应用范围

考虑到每种技术的独特特性，以及通过集成其他技术来扩展此堆栈的功能的便利性，可以使用此堆栈构建的应用程序范围实际上非常广泛。

如今，网络应用程序默认应该是丰富的客户端应用程序，具有沉浸式、互动性，并且在性能和可用性上不会逊色。MERN 的优势组合使其非常适合开发满足这些方面和需求的网络应用程序。

此外，一些技术的新颖和即将推出的特性，例如使用 Node 进行低级操作操作、使用 MongoDB GridFS 进行大文件流传输功能，以及使用 React 360 在网络上实现虚拟现实功能，使得可以使用 MERN 构建更复杂和独特的应用程序。

挑选 MERN 技术中的特定功能，并论述为什么这些功能不适用于某些应用可能看起来是合理的。但考虑到 MERN 堆栈如何灵活地组合和扩展，这些问题可以在 MERN 中逐案解决。在本书中，我们将演示在构建应用程序时如何考虑特定要求和需求。

# 本书中开发的 MERN 应用程序

为了展示 MERN 的广泛可能性以及如何轻松开始构建具有不同功能的 Web 应用程序，本书将展示日常使用的 Web 应用程序以及复杂和罕见的 Web 体验：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/32a3447c-a28e-46f0-8a79-13201edf6fb5.jpg)上述截图展示了本书其余部分开发的四个不同的 MERN 应用程序

# 社交媒体平台

对于第一个 MERN 应用程序，我们将构建一个受 Twitter 和 Facebook 启发的基本社交媒体应用程序。这个社交媒体平台将实现诸如帖子分享、点赞和评论、关注朋友以及聚合新闻源等简单功能。

# 在线市场

各种类型的电子商务 Web 应用程序在互联网上随处可见，而且这些应用程序在短期内不会过时。使用 MERN，我们将构建一个在线市场应用程序，涵盖核心方面，如支持卖家账户、产品列表、顾客购物车和支付处理。

# 媒体流应用程序

为了测试一些高级的 MERN 功能，下一个选择是更加沉浸式的应用程序，比如媒体流应用程序。受 Netflix 和 YouTube 的功能启发，该应用程序将实现内容上传和查看功能，为内容提供者提供媒体内容上传功能，并为观众提供实时内容流。

# Web 的 VR 游戏

React 360 的发布使得将 Web VR 功能应用于 React 用户界面成为可能。我们将探索如何在 MERN 中使用 React 360 创建罕见的 Web 体验，通过组合基本的虚拟现实游戏应用程序。用户将能够制作和玩 VR 游戏，每个游戏都将有动画的 VR 对象，玩家可以收集以完成游戏。

# 书的结构

这本书旨在帮助那些对 MERN 堆栈有零到一些经验的 JavaScript 开发人员，设置并开始开发不同复杂性的 Web 应用程序。它包括构建和运行不同应用程序的指南，以及代码片段和关键概念的解释。

这本书分为五个部分，从基础到高级主题逐步展开，带领你一路构建 MERN，然后利用它开发具有简单到复杂功能的不同应用程序，同时演示如何根据应用程序要求扩展 MERN 堆栈的功能。

# 开始使用 MERN

*第一章*，*释放 MERN 的 React 应用程序*和*第二章*，*准备开发环境*为在 MERN 堆栈中开发 Web 应用程序设定了背景，并指导您设置开发环境。

# 从头开始构建 MERN——一个骨架应用程序

*第三章*，*使用 MongoDB、Express 和 Node 构建后端*和*第四章*，*添加 React 前端以完成 MERN*展示了如何将 MERN 堆栈技术结合起来形成一个具有最少和基本功能的骨架 Web 应用程序。这个骨架 MERN 应用程序作为本书其余部分开发的四个主要应用程序的基础。

# 使用 MERN 开发基本 Web 应用程序

在这一部分，您将通过构建两个真实世界的应用程序——一个简单的社交媒体平台（第五章）*，从一个简单的社交媒体应用开始*，和一个在线市场（第六章）*，通过在线市场锻炼新的 MERN 技能*和*第七章*，*扩展订单和支付的市场*来熟悉 MERN 堆栈 Web 应用程序的核心属性。

# 深入复杂的 MERN 应用

*第八章*，*构建媒体流应用程序*，*第九章*，*自定义媒体播放器和改善 SEO*，*第十章*，*开发基于 Web 的 VR 游戏*和*第十一章*，*使用 MERN 使 VR 游戏动态*展示了这个堆栈如何用于开发具有更复杂和沉浸式功能的应用程序，例如使用 React 360 进行媒体流和虚拟现实。

# 继续前进与 MERN

最后*第十二章*，*遵循最佳实践并进一步开发 MERN*总结了前面的章节和应用程序，通过扩展最佳实践来开发成功的 MERN 应用程序，提出改进建议和进一步发展。

您可以根据自己的经验水平和偏好，选择是否按照规定的顺序使用本书。对于一个对 MERN 非常陌生的开发人员，可以按照本书中的路径进行。对于更有经验的 JS 开发人员，*从零开始构建 MERN* - *一个骨架应用程序* 部分的章节将是开始设置基础应用程序的好地方，然后选择任何四个应用程序进行构建和扩展。

# 充分利用本书

这本书的内容是以实践为导向的，涵盖了构建每个 MERN 应用程序所需的实施步骤、代码和相关概念。建议您不要仅仅试图通读章节，而是应该并行运行相关代码，并在阅读书中的解释时浏览应用程序的功能。

讨论代码实现的章节将指向包含完整代码及其运行说明的 GitHub 存储库。您可以在阅读章节之前拉取代码、安装并运行它：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/0758a73f-e9a3-4256-94f9-ba1e653e30a4.png)

您可以考虑按照本书中概述的推荐步骤来实施：

+   在深入讨论章节中的实施细节之前，从相关的 GitHub 存储库中拉取代码

+   按照代码的说明安装和运行应用程序

+   在阅读相关章节中的功能描述时，浏览正在运行的应用程序的功能

+   在开发模式下运行代码并在编辑器中打开后，参考书中的步骤和解释，以更深入地理解实施细节

本书旨在为每个应用程序提供快速的入门指南和工作代码。您可以根据需要对此代码进行实验、改进和扩展。为了获得积极的学习体验，鼓励您在遵循本书的同时重构和修改代码。在一些示例中，本书选择冗长的代码而不是简洁和更清晰的代码，因为对于新手来说更容易理解。在一些其他实现中，本书坚持使用更广泛使用的传统约定，而不是现代和即将到来的 JavaScript 约定。这样做是为了在您自行研究讨论的技术和概念时，最小化参考在线资源和文档时的差异。本书中代码可以更新的这些实例，是探索和发展超出本书涵盖范围的技能的好机会。

# 摘要

在本章中，我们了解了在 MERN 堆栈中开发 Web 应用程序的背景，以及本书将如何帮助您使用该堆栈进行开发。

MERN 堆栈项目集成了 MongoDB、Express、React 和 Node，用于构建 Web 应用程序。该堆栈中的每种技术在 Web 开发领域都取得了相关进展。这些技术被广泛采用，并在不断壮大的社区支持下不断改进。可以开发具有不同需求的 MERN 应用程序，从日常使用的应用程序到更复杂的 Web 体验。本书中的实用导向方法可用于从基础到高级的 MERN 技能成长，或者直接开始构建更复杂的应用程序。

在下一章中，我们将开始为 MERN 应用程序开发做准备，通过设置开发环境。


# 第二章：准备开发环境

在使用 MERN 堆栈构建应用程序之前，我们首先需要准备每种技术的开发环境，以及用于辅助开发和调试的工具。本章将指导您了解工作空间选项、基本开发工具、如何在工作空间中设置 MERN 技术以及检查此设置的实际代码步骤。

我们将涵盖以下主题：

+   工作空间选项

+   代码编辑器

+   Chrome 开发者工具

+   Git 设置

+   MongoDB 设置

+   Node 设置

+   npm 模块以完成 MERN 堆栈

+   用于检查 MERN 设置的代码

# 选择开发工具

在选择基本开发工具（如文本编辑器或 IDE、版本控制软件甚至开发工作空间本身）时有很多选择。在本节中，我们将介绍与 MERN Web 开发相关的选项和建议，以便您可以根据个人偏好做出明智的决定。

# 工作空间选项

在本地计算机上开发是程序员中最常见的做法，但随着诸如 Cloud9（[`aws.amazon.com/cloud9/?origin=c9io`](https://aws.amazon.com/cloud9/?origin=c9io)）等优秀的云开发服务的出现，现在可以同时使用本地和云端。您可以使用 MERN 技术设置本地工作空间，并且在本书的其余部分将假定为这种情况，但您也可以选择在配备了 Node 开发的云服务中运行和开发代码。

# 本地和云开发

您可以选择同时使用这两种类型的工作空间，以享受在本地工作的好处，而不必担心带宽/互联网问题，并在没有您喜爱的本地计算机时远程工作。为此，您可以使用 Git 对代码进行版本控制，将最新代码存储在 GitHub 或 BitBucket 等远程 Git 托管服务上，然后在所有工作空间中共享相同的代码。

# IDE 或文本编辑器

大多数云开发环境都将集成源代码编辑器。但是对于您的本地工作空间，您可以根据自己作为程序员的偏好选择任何编辑器，然后为 MERN 开发进行自定义。例如，以下流行选项都可以根据需要进行自定义：

+   **Atom**（[`atom.io/`](https://atom.io/)）：GitHub 的免费开源文本编辑器，有许多其他开发人员提供的与 MERN 堆栈相关的包可用

+   SublimeText（https://www.sublimetext.com/）：一款专有的跨平台文本编辑器，还有许多与 MERN 堆栈相关的软件包可用，支持 JavaScript 开发

+   Visual Studio Code（https://code.visualstudio.com/）：微软开发的功能丰富的源代码编辑器，广泛支持现代 Web 应用程序开发工作流程，包括对 MERN 堆栈技术的支持

+   WebStorm（https://www.jetbrains.com/webstorm/）：由 JetBrains 开发的全功能 JavaScript IDE，支持基于 MERN 堆栈的开发

# Chrome 开发者工具

加载、查看和调试前端是 Web 开发过程中非常关键的一部分。Chrome 开发者工具是 Chrome 浏览器的一部分，具有许多出色的功能，允许调试、测试和实验前端代码，以及 UI 的外观、响应和性能。此外，React 开发者工具扩展可作为 Chrome 插件使用，并将 React 调试工具添加到 Chrome 开发者工具中。

# Git

任何开发工作流程都不完整，如果没有版本控制系统来跟踪代码更改、共享代码和协作。多年来，Git 已成为许多开发人员的事实标准版本控制系统，并且是最广泛使用的分布式源代码管理工具。在本书中，Git 将主要帮助跟踪进度，因为我们逐步构建每个应用程序。

# 安装

要开始使用 Git，首先根据您的系统规格在本地计算机或基于云的开发环境上安装它。有关下载和安装最新 Git 的相关说明，以及使用 Git 命令的文档，可在以下网址找到：https://git-scm.com/downloads。

# 远程 Git 托管服务

基于云的 Git 存储库托管服务，如 GitHub 和 BitBucket，有助于在工作空间和部署环境之间共享最新的代码，并备份代码。这些服务提供了许多有用的功能，以帮助代码管理和开发工作流程。要开始使用，您可以创建一个帐户，并为您的代码库设置远程存储库。

所有这些基本工具将丰富您的 Web 开发工作流程，并在您完成工作区的必要设置并开始构建 MERN 应用程序后提高生产力。

# 设置 MERN 技术栈

MERN 技术栈正在开发和升级，因此在撰写本书时，我们使用的是最新的稳定版本。大多数这些技术的安装指南取决于工作区的系统环境，因此本节指向所有相关的安装资源，并且也作为设置完全功能的 MERN 技术栈的指南。

# MongoDB

在向 MERN 应用程序添加任何数据库功能之前，必须在开发环境中设置并运行 MongoDB。在撰写本文时，MongoDB 的当前稳定版本是 3.6.3，本书中用于开发应用程序的是 MongoDB Community Edition 的这个版本。本节的其余部分提供了有关如何安装和运行 MongoDB 的资源。

# 安装

您需要在工作区安装并启动 MongoDB，以便在开发中使用它。MongoDB 的安装和启动过程取决于工作区的规格：

+   云开发服务将有其自己的安装和设置 MongoDB 的说明。例如，Cloud9 的操作步骤可以在此找到：[`community.c9.io/t/setting-up-mongodb/1717`](https://community.c9.io/t/setting-up-mongodb/1717)。

+   在本地机器上安装的指南详见：[`docs.mongodb.com/manual/installation/`](https://docs.mongodb.com/manual/installation/)。

# 运行 mongo shell

*mongo* shell 是 MongoDB 的交互式工具，是熟悉 MongoDB 操作的好地方。一旦安装并运行了 MongoDB，您可以在命令行上运行 *mongo* shell。在 *mongo* shell 中，您可以尝试查询和更新数据以及执行管理操作的命令。

# Node

MERN 应用程序的后端服务器实现依赖于 Node 和 npm。在撰写本文时，8.11.1 是最新的稳定 Node 版本，并且附带 npm 版本 5.6.0。然而，npm 的最新版本是 5.8.0，因此在安装 Node 后，需要根据下一节的讨论升级 npm。

# 安装

Node 可以通过直接下载、安装程序或 Node 版本管理器进行安装。

+   您可以通过直接下载源代码或针对您的工作平台特定的预构建安装程序来安装 Node。下载地址为[nodejs.org/en/download](https://nodejs.org/en/download/)。

+   云开发服务可能已经预装了 Node，比如 Cloud9，或者会有特定的添加和更新 Node 的说明。

要测试安装是否成功，可以打开命令行并运行`node -v`来查看它是否正确返回版本号。

# 升级 npm 版本

为了安装 npm 版本 5.8.0，可以从命令行运行以下安装命令，并使用**`npm -v`**检查版本：

```jsx
npm install -g npm@5.8.0 
npm -v
```

# 使用 nvm 进行 Node 版本管理

如果您需要为不同的项目维护多个 Node 和 npm 版本，nvm 是一个有用的命令行工具，可以在同一工作空间中安装和管理不同的版本。您必须单独安装 nvm。设置说明可以在[github.com/creationix/nvm](https://github.com/creationix/nvm)找到。

# MERN 的 npm 模块

其余的 MERN 堆栈技术都可以作为 npm 模块使用，并且可以通过`npm install`添加到每个项目中。这些包括关键模块，如 React 和 Express，这些模块是运行每个 MERN 应用程序所必需的，还有在开发过程中将需要的模块。在本节中，我们列出并讨论这些模块，然后在下一节中看如何在一个工作项目中使用这些模块。

# 关键模块

为了集成 MERN 堆栈技术并运行您的应用程序，我们将需要以下 npm 模块：

+   **React**：要开始使用 React，我们将需要两个模块：

+   `react`

+   `react-dom`

+   **Express**：要在代码中使用 Express，您需要`express`模块

+   **MongoDB**：要在 Node 应用程序中使用 MongoDB，还需要添加驱动程序，该驱动程序可作为名为`mongodb`的 npm 模块使用

# devDependency 模块

为了在 MERN 应用程序的开发过程中保持一致性，我们将在整个堆栈中使用 JavaScript ES6。因此，为了辅助开发过程，我们将使用以下额外的 npm 模块来编译和捆绑代码，并在开发过程中更新代码时自动重新加载服务器和浏览器应用程序：

+   Babel 模块用于将 ES6 和 JSX 转换为适合所有浏览器的 JavaScript。需要的模块来使 Babel 工作的有：

+   `babel-core`

+   `babel-loader`用于使用 Webpack 转换 JavaScript 文件

+   `babel-preset-env`，`babel-preset-react`和`babel-preset-stage-2`用于支持 React，最新的 JS 功能以及一些 stage-x 功能，例如声明目前未在`babel-preset-env`下覆盖的类字段

+   Webpack 模块将帮助捆绑编译后的 JavaScript，用于客户端和服务器端代码。需要使 Webpack 工作的模块有：

+   `webpack`

+   `webpack-cli`用于运行 Webpack 命令

+   `webpack-node-externals`在 Webpack 打包时忽略外部 Node 模块文件

+   `webpack-dev-middleware`在开发过程中通过连接的服务器提供从 Webpack 发出的文件

+   `webpack-hot-middleware`将热模块重新加载添加到现有服务器中，通过将浏览器客户端连接到 Webpack 服务器，并在开发过程中接收代码更改的更新

+   `nodemon`在开发过程中监视服务器端的更改，以便重新加载服务器以使更改生效。

+   `react-hot-loader`用于加快客户端的开发。每当 React 前端中的文件更改时，`react-hot-loader`使浏览器应用程序能够在不重新捆绑整个前端代码的情况下更新。

尽管`react-hot-loader`旨在帮助开发流程，但安装此模块作为常规依赖项而不是 devDependency 是安全的。它会自动确保在生产中禁用热重新加载，并且占用空间很小。

# 检查您的开发设置

在这一部分，我们将逐步进行开发工作流程，并编写代码，以确保环境正确设置以开始开发和运行 MERN 应用程序。

我们将在以下文件夹结构中生成这些项目文件以运行一个简单的设置项目：

```jsx
| mern-simplesetup/
  | -- client/
    | --- HelloWorld.js
    | --- main.js
  | -- server/
    | --- devBundle.js
    | --- server.js
  | -- .babelrc
  | -- nodemon.json
  | -- package.json
  | -- template.js
  | -- webpack.config.client.js
  | -- webpack.config.client.production.js
  | -- webpack.config.server.js
```

本节讨论的代码可在 GitHub 的存储库中找到：[github.com/shamahoque/mern-simplesetup](https://github.com/shamahoque/mern-simplesetup)。您可以克隆此代码，并在本章的其余部分中阅读代码解释时运行它。

# 初始化 package.json 并安装 npm 模块

我们将首先使用 npm 安装所有必需的模块。在每个项目文件夹中添加`package.json`文件以维护、记录和共享 MERN 应用程序中使用的 npm 模块是最佳实践。`package.json`文件将包含有关应用程序的元信息，以及列出模块依赖项。

按照以下步骤生成`package.json`文件，修改它，并用它来安装 npm 模块：

+   `npm init`: 从命令行进入项目文件夹，运行`npm init`。您将被问及一系列问题，然后将自动生成一个`package.json`文件，其中包含您的答案。

+   `dependencies`: 在编辑器中打开`package.json`，修改 JSON 对象，添加关键模块和`react-hot-loader`作为常规的`dependencies`。

在代码块之前提到的文件路径表示项目目录中代码的位置。本书始终遵循这一约定，以提供更好的上下文和指导，让您能够跟着代码进行学习。

`mern-simplesetup/package.json`:

```jsx
"dependencies": {
   "express": "⁴.16.3",
    "mongodb": "³.0.7",
    "react": "¹⁶.3.2",
    "react-dom": "¹⁶.3.2",
    "react-hot-loader": "⁴.1.2"
}
```

+   `devDependencies`: 进一步修改`package.json`，添加以下在开发过程中所需的 npm 模块作为`devDependencies`。

`mern-simplesetup/package.json`:

```jsx
"devDependencies": {
    "babel-core": "⁶.26.2",
    "babel-loader": "⁷.1.4",
    "babel-preset-env": "¹.6.1",
    "babel-preset-react": "⁶.24.1",
    "babel-preset-stage-2": "⁶.24.1",
    "nodemon": "¹.17.3",
    "webpack": "⁴.6.0",
    "webpack-cli": "².0.15",
    "webpack-dev-middleware": "³.1.2",
    "webpack-hot-middleware": "².22.1",
    "webpack-node-externals": "¹.7.2"
}
```

+   `npm install`: 保存`package.json`，然后从命令行运行`npm install`，以获取并添加所有这些模块到您的项目中。

# 配置 Babel、Webpack 和 Nodemon

在我们开始编写 Web 应用程序之前，我们需要配置 Babel、Webpack 和 Nodemon，在开发过程中编译、打包和自动重新加载代码更改。

# Babel

在项目文件夹中创建一个`.babelrc`文件，并添加以下 JSON，其中指定了`presets`和`plugins`。

`mern-simplesetup/.babelrc`:

```jsx
{
    "presets": [
      "env",
      "stage-2"
      "react"
    ],
    "plugins": [
      "react-hot-loader/babel"
    ]
}
```

`react-hot-loader/babel`插件是由`react-hot-loader`模块需要编译`React`组件。

# Webpack

我们将不得不为捆绑客户端和服务器端代码以及生产代码分别配置 Webpack。在项目文件夹中创建`webpack.config.client.js`、`webpack.config.server.js`和`webpack.config.client.production.js`文件。所有三个文件都将具有以下代码结构：

```jsx
const path = require('path')
const webpack = require('webpack')
const CURRENT_WORKING_DIR = process.cwd()

const config = { ... }

module.exports = config
```

`config` JSON 对象的值将根据客户端或服务器端代码以及开发与生产代码而有所不同。

# 用于开发的客户端 Webpack 配置

在您的`webpack.config.client.js`文件中更新`config`对象如下，以配置 Webpack 在开发过程中捆绑和热加载 React 代码。

`mern-simplesetup/webpack.config.client.js`:

```jsx
const config = {
    name: "browser",
    mode: "development",
    devtool: 'eval-source-map',
    entry: [
        'react-hot-loader/patch',
        'webpack-hot-middleware/client?reload=true',
        path.join(CURRENT_WORKING_DIR, 'client/main.js')
    ],
    output: {
        path: path.join(CURRENT_WORKING_DIR , '/dist'),
        filename: 'bundle.js',
        publicPath: '/dist/'
    },
    module: {
        rules: [
            {
                test: /\.jsx?$/,
                exclude: /node_modules/,
                use: [
                    'babel-loader'
                ]
            }
        ]
    }, plugins: [
          new webpack.HotModuleReplacementPlugin(),
          new webpack.NoEmitOnErrorsPlugin()
      ]
}
```

+   `mode`将`process.env.NODE_ENV`设置为给定值，并告诉 Webpack 相应地使用其内置的优化。如果没有明确设置，它默认为值`'production'`。也可以通过命令行通过将值作为 CLI 参数传递来设置。

+   `devtool`指定了如何生成源映射，如果有的话。通常，源映射提供了一种将压缩文件中的代码映射回源文件中的原始位置以帮助调试的方法。

+   `entry`指定了 Webpack 开始打包的入口文件，在这种情况下是`client`文件夹中的`main.js`文件。

+   `output`指定了打包代码的输出路径，在这种情况下设置为`dist/bundle.js`。

+   `publicPath`允许指定应用程序中所有资产的基本路径。

+   `module`设置了用于转译的文件扩展名的正则规则，以及要排除的文件夹。这里要使用的转译工具是`babel-loader`。

+   `HotModuleReplacementPlugin`启用了`react-hot-loader`的热模块替换。

+   `NoEmitOnErrorsPlugin`允许在编译错误时跳过输出。

# 服务器端 Webpack 配置

修改代码以要求`nodeExternals`，并在`webpack.config.server.js`文件中更新`config`对象以配置 Webpack 用于打包服务器端代码。

`mern-simplesetup/webpack.config.server.js`：

```jsx
const config = {
    name: "server",
    entry: [ path.join(CURRENT_WORKING_DIR , './server/server.js') ],
    target: "node",
    output: {
        path: path.join(CURRENT_WORKING_DIR , '/dist/'),
        filename: "server.generated.js",
        publicPath: '/dist/',
        libraryTarget: "commonjs2"
    },
    externals: [nodeExternals()],
    module: {
        rules: [
            {
                test: /\.js$/,
                exclude: /node_modules/,
                use: [ 'babel-loader' ]
            }
        ]
    }
}
```

`mode`选项在这里没有明确设置，但在运行 Webpack 命令时，将根据开发或生产的需要进行传递。

Webpack 从`server.js`文件夹开始打包，然后将打包后的代码输出到`dist`文件夹中的`server.generated.js`文件中。

# 用于生产的客户端 Webpack 配置

为了准备客户端代码用于生产，更新`webpack.config.client.production.js`文件中的`config`对象与以下代码。

`mern-simplesetup/webpack.config.client.production.js`：

```jsx
const config = {
    mode: "production",
    entry: [
        path.join(CURRENT_WORKING_DIR, 'client/main.js')
    ],
    output: {
        path: path.join(CURRENT_WORKING_DIR , '/dist'),
        filename: 'bundle.js',
        publicPath: "/dist/"
    },
    module: {
        rules: [
            {
                test: /\.jsx?$/,
                exclude: /node_modules/,
                use: [
                    'babel-loader'
                ]
            }
        ]
    }
}
```

这将配置 Webpack 用于打包用于生产模式的 React 代码，其中将不再需要热重载插件或调试配置。

# Nodemon

在项目文件夹中创建一个`nodemon.js`文件，并添加以下配置。

`mern-simplesetup/nodemon.js`

```jsx
{
    "verbose": false,
    "watch": [ "./server" ],
    "exec": "webpack --mode=development --config 
    webpack.config.server.js 
                && node ./dist/server.generated.js"
}
```

这个配置将设置`nodemon`在开发过程中监视服务器文件的更改，然后根据需要执行编译和构建命令。

# 使用 React 的前端视图

为了开始开发前端，首先在项目文件夹中创建一个名为`template.js`的根模板文件，它将使用`React`组件来渲染 HTML。

`mern-simplesetup/template.js`:

```jsx
export default () => {
    return `<!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8">
          <title>MERN Kickstart</title>
        </head>
        <body>
          <div id="root"></div>
          <script type="text/javascript" src="/dist/bundle.js"> 
       </script>
        </body>
      </html>` 
} 
```

当服务器收到对根 URL 的请求时，这个 HTML 模板将在浏览器中被渲染，ID 为`"root"`的`div`元素将包含我们的`React`组件。

接下来，创建一个`client`文件夹，我们将在其中添加两个 React 文件，`main.js`和`HelloWorld.js`。

`main.js`文件简单地在 HTML 文档的`div`元素中渲染顶层入口`React`组件。

`mern-simplesetup/client/main.js`:

```jsx
import React from 'react'
import { render } from 'react-dom'
import HelloWorld from './HelloWorld'

render(<HelloWorld/>, document.getElementById('root'))
```

在这种情况下，入口`React`组件是从`HelloWorld.js`导入的`HelloWorld`组件。

`HelloWorld.js`包含一个基本的`HelloWorld`组件，它被热导出以在开发过程中使用`react-hot-loader`进行热重载。

`mern-simplesetup/client/HelloWorld.js`:

```jsx
import React, { Component } from 'react'
import { hot } from 'react-hot-loader'

class HelloWorld extends Component {
   render() {
     return (
         <div>
             <h1>Hello World!</h1>
         </div>
     ) 
   }
}

export default hot(module)(HelloWorld)
```

为了在服务器收到对根 URL 的请求时在浏览器中看到`React`组件被渲染，我们需要使用 Webpack 和 Babel 设置来编译和打包这段代码，并添加服务器端代码来响应根路由请求并返回打包后的代码。

# 使用 Express 和 Node 构建服务器

在项目文件夹中，创建一个名为`server`的文件夹，并添加一个名为`server.js`的文件来设置服务器。然后，添加另一个名为`devBundle.js`的文件，它将在开发模式下使用 Webpack 配置来编译 React 代码。

# Express 应用程序

在`server.js`中，我们首先将添加代码来导入`express`模块，以初始化一个 Express 应用程序。

`mern-simplesetup/server/server.js`:

```jsx
import express from 'express'

const app = express()
```

然后我们将使用这个 Express 应用程序来构建出 Node 服务器应用程序的其余部分。

# 在开发过程中打包 React 应用程序

为了保持开发流程简单，我们将初始化 Webpack 来在运行服务器时编译客户端代码。在`devBundle.js`中，我们将设置一个编译方法，它接受 Express 应用程序并配置它来使用 Webpack 中间件来编译、打包和提供代码，以及在开发模式下启用热重载。

`mern-simplesetup/server/devBundle.js`:

```jsx
import webpack from 'webpack'
import webpackMiddleware from 'webpack-dev-middleware'
import webpackHotMiddleware from 'webpack-hot-middleware'
import webpackConfig from './../webpack.config.client.js'

const compile = (app) => {
  if(process.env.NODE_ENV == "development"){
    const compiler = webpack(webpackConfig)
    const middleware = webpackMiddleware(compiler, {
      publicPath: webpackConfig.output.publicPath
    })
    app.use(middleware)
    app.use(webpackHotMiddleware(compiler))
  }
}

export default {
  compile
}
```

我们将在开发模式下通过在`server.js`中添加以下行来调用这个编译方法。

`mern-simplesetup/server/server.js`:

```jsx
**import devBundle from './devBundle'**
const app = express()
**devBundle.compile(app)** 
```

这两行突出显示的代码仅用于开发模式，在构建应用程序代码以进行生产时应将其注释掉。在开发模式下，当执行这些行时，Webpack 将编译和捆绑 React 代码并将其放置在`dist/bundle.js`中。

# 从 dist 文件夹中提供静态文件

Webpack 将在开发模式和生产模式下编译客户端代码，然后将捆绑文件放置在`dist`文件夹中。为了使这些静态文件在客户端请求时可用，我们将在`server.js`中添加以下代码来从`dist/folder`中提供静态文件。

`mern-simplesetup/server/server.js`：

```jsx
import path from 'path'
const CURRENT_WORKING_DIR = process.cwd()
app.use('/dist', express.static(path.join(CURRENT_WORKING_DIR, 'dist')))
```

# 在根目录渲染模板

当服务器在根 URL `/` 处收到请求时，我们将在浏览器中呈现`template.js`。在`server.js`中，向 Express 应用程序添加以下路由处理代码，以接收在`/`处的 GET 请求。

`mern-simplesetup/server/server.js`：

```jsx
import template from './../template'
app.get('/', (req, res) => {
     res.status(200).send(template())
})
```

最后，添加服务器代码以侦听指定端口的传入请求。

`mern-simplesetup/server/server.js`：

```jsx
let port = process.env.PORT || 3000
app.listen(port, function onStart(err) {
  if (err) {
    console.log(err) 
  }
  console.info('Server started on port %s.', port)
})
```

# 将服务器连接到 MongoDB

要将 Node 服务器连接到 MongoDB，请在`server.js`中添加以下代码，并确保您的工作区中正在运行 MongoDB。

`mern-simplesetup/server/server.js`：

```jsx
import { MongoClient } from 'mongodb'
const url = process.env.MONGODB_URI || 'mongodb://localhost:27017/mernSimpleSetup'
MongoClient.connect(url, (err, db)=>{
  console.log("Connected successfully to mongodb server")
  db.close()
})
```

在此代码示例中，`MongoClient`是连接到运行中的`MongoDB`实例的驱动程序，使用其`url`，并允许我们在后端实现与数据库相关的代码。

# 运行 npm 脚本

更新`package.json`文件，添加以下 npm 运行脚本以进行开发和生产。

`mern-simplesetup/package.json`：

```jsx
"scripts": {
    "development": "nodemon",
    "build": "webpack --config webpack.config.client.production.js 
```

```jsx
                 && webpack --mode=production --config 
     webpack.config.server.js",
    "start": "NODE_ENV=production node ./dist/server.generated.js"
}
```

+   `npm run development`：此命令将启动 Nodemon、Webpack 和服务器以进行开发

+   `npm run build`：这将为生产模式生成客户端和服务器代码包（在运行此脚本之前，请确保从`server.js`中删除`devBundle.compile`代码）

+   `npm run start`：此命令将在生产环境中运行捆绑代码

# 实时开发和调试

要运行到目前为止开发的代码，并确保一切正常运行，可以按照以下步骤进行：

1.  **从命令行运行应用程序**：`npm run development`。

1.  **在浏览器中加载**：在浏览器中打开根 URL，即`http://localhost:3000`，如果您正在使用本地机器设置。您应该看到一个标题为 MERN Kickstart 的页面，上面只显示 Hello World!。

1.  开发代码并调试实时更改：将`HelloWorld.js`组件文本中的`'Hello World!'`更改为`'hello'`。保存更改以在浏览器中看到即时更新，并检查命令行输出以查看`bundle.js`是否未重新创建。类似地，当您更改服务器端代码时，您也可以看到即时更新，从而提高开发效率。

如果您已经走到了这一步，恭喜您，您已经准备好开始开发令人兴奋的 MERN 应用程序了。

# 总结

在本章中，我们讨论了开发工具选项以及如何安装 MERN 技术，然后编写了代码来检查开发环境是否设置正确。

我们首先看了推荐的工作区、IDE、版本控制软件和适用于 Web 开发的浏览器选项。您可以根据自己作为开发人员的偏好从这些选项中进行选择。

接下来，我们首先安装 MongoDB、Node 和 npm，然后使用 npm 添加其余所需的库，从而设置了 MERN 堆栈技术。

在继续编写代码以检查此设置之前，我们配置了 Webpack 和 Babel 以在开发期间编译和捆绑代码，并构建生产就绪的代码。我们了解到，在在浏览器上打开 MERN 应用程序之前，有必要编译用于开发 MERN 应用程序的 ES6 和 JSX 代码。

此外，我们通过为前端开发包括 React Hot Loader，为后端开发配置 Nodemon，并在开发期间运行服务器时编译客户端和服务器端代码的方式，使开发流程更加高效。

在下一章中，我们将使用此设置开始构建一个骨架 MERN 应用程序，该应用程序将作为功能齐全应用程序的基础。


# 第三章：使用 MongoDB、Express 和 Node 构建后端

在大多数 Web 应用程序的开发过程中，存在常见任务、基本功能和实现代码的重复。这本书中开发的 MERN 应用程序也是如此。考虑到这些相似之处，我们将首先为一个骨架 MERN 应用程序奠定基础，该应用程序可以轻松修改和扩展，以实现各种 MERN 应用程序。

在本章中，我们将涵盖以下主题，并从 MERN 骨架的后端实现开始，使用 Node、Express 和 MongoDB：

+   MERN 应用程序中的用户 CRUD 和 auth

+   使用 Express 服务器处理 HTTP 请求

+   使用 Mongoose 模式进行用户模型

+   用户 CRUD 和 auth 的 API

+   用 JWT 进行受保护路由的身份验证

+   运行后端代码并检查 API

# 骨架应用程序概述

骨架应用程序将封装基本功能和一个在大多数 MERN 应用程序中重复的工作流程。我们将构建骨架本质上作为一个基本但完全功能的 MERN Web 应用程序，具有用户创建（CRUD）和身份验证-授权（auth）功能，这也将展示如何开发、组织和运行使用这个堆栈构建的一般 Web 应用程序的代码。目标是保持骨架尽可能简单，以便易于扩展，并可用作开发不同 MERN 应用程序的基础应用程序。

# 功能分解

在骨架应用程序中，我们将添加以下用例，其中包括用户 CRUD 和 auth 功能的实现：

+   **注册**：用户可以通过使用电子邮件地址注册创建新帐户

+   **用户列表**：任何访问者都可以看到所有注册用户的列表

+   **身份验证**：注册用户可以登录和退出

+   **受保护的用户资料**：只有注册用户可以在登录后查看个人用户详细信息

+   **授权用户编辑和删除**：只有注册和经过身份验证的用户才能编辑或删除自己的用户帐户详细信息

# 本章重点-后端

在本章中，我们将专注于使用 Node、Express 和 MongoDB 构建骨架应用程序的工作后端。完成的后端将是一个独立的服务器端应用程序，可以处理 HTTP 请求以创建用户、列出所有用户，并在考虑用户身份验证和授权的情况下查看、更新或删除数据库中的用户。

# 用户模型

用户模型将定义要存储在 MongoDB 数据库中的用户详细信息，并处理与用户相关的业务逻辑，如密码加密和用户数据验证。这个骨架版本的用户模型将是基本的，支持以下属性：

| **字段名称** | **类型** | **描述** |
| --- | --- | --- |
| `name` | String | 存储用户姓名的必需字段 |
| `email` | String | 必需的唯一字段，用于存储用户的电子邮件并标识每个帐户（每个唯一电子邮件只允许一个帐户） |
| `password` | String | 用于身份验证的必需字段，数据库将存储加密后的密码而不是实际字符串，以确保安全性 |
| `created` | Date | 当创建新用户帐户时自动生成的时间戳 |
| `updated` | Date | 当现有用户详细信息更新时自动生成的时间戳 |

# 用户 CRUD 的 API 端点

为了在用户数据库上启用和处理用户 CRUD 操作，后端将实现并公开 API 端点，供前端在视图中使用，如下所示：

| **操作** | **API 路由** | **HTTP 方法** |
| --- | --- | --- |
| 创建用户 | `/api/users` | `POST` |
| 列出所有用户 | `/api/users` | `GET` |
| 获取用户 | `/api/users/:userId` | `GET` |
| 更新用户 | `/api/users/:userId` | `PUT` |
| 删除用户 | `/api/users/:userId` | `DELETE` |
| 用户登录 | `/auth/signin` | `POST` |
| 用户退出登录（可选） | `/auth/signout` | `GET` |

其中一些用户 CRUD 操作将具有受保护的访问权限，这将要求请求的客户端进行身份验证、授权或两者都要求。最后两个路由用于身份验证，将允许用户登录和退出登录。

# 使用 JSON Web Tokens 进行身份验证

为了根据骨架特性限制和保护对用户 API 端点的访问，后端需要整合身份验证和授权机制。在实现 Web 应用程序的用户身份验证时有许多选择。最常见和经过时间考验的选项是使用会话在客户端和服务器端存储用户状态。但是，一种较新的方法是使用**JSON Web Token**（**JWT**）作为无状态身份验证机制，不需要在服务器端存储用户状态。

这两种方法在相关的真实用例中都有优势。然而，为了简化本书中的代码，并且因为它与 MERN 堆栈和我们的示例应用程序配合得很好，我们将使用 JWT 进行身份验证实现。此外，本书还将在未来章节中提出安全增强选项。

# JWT 的工作原理

当用户成功使用其凭据登录时，服务器端会生成一个使用秘钥和唯一用户详细信息签名的 JWT。然后，将此令牌返回给请求的客户端，以便在本地保存，可以保存在`localStorage`、`sessionStorage`或浏览器的 cookie 中，从根本上将维护用户状态的责任交给客户端：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/fd35db0d-22fd-4aa9-8206-3e51089ada4d.png)

对于成功登录后进行的 HTTP 请求，特别是对受保护且具有受限访问权限的 API 端点的请求，客户端必须将此令牌附加到请求中。更具体地说，`JSON Web Token`必须包含在请求的`Authorization`头部中作为`Bearer`：

```jsx
Authorization: Bearer <JSON Web Token>
```

当服务器收到对受保护的 API 端点的请求时，它会检查请求的`Authorization`头部是否包含有效的 JWT，然后验证签名以识别发送者，并确保请求数据未被损坏。如果令牌有效，则请求的客户端将被授予对关联操作或资源的访问权限，否则将返回授权错误。

在骨架应用程序中，当用户使用电子邮件和密码登录时，后端将使用仅在服务器上可用的秘钥生成带有用户 ID 的签名 JWT。然后，当用户尝试查看任何用户配置文件、更新其帐户详细信息或删除其用户帐户时，将需要此令牌进行验证。

实现用户模型来存储和验证用户数据，然后将其与 API 集成以基于 JWT 执行 CRUD 操作，将产生一个功能齐全的独立后端。在本章的其余部分，我们将看看如何在 MERN 堆栈和设置中实现这一点。

# 实现骨架后端

为了开始开发 MERN 骨架的后端部分，我们将首先设置项目文件夹，安装和配置必要的 npm 模块，然后准备运行脚本以帮助开发和运行代码。然后，我们将逐步通过代码实现用户模型、API 端点和基于 JWT 的身份验证，以满足我们之前为面向用户的功能定义的规范。

本章讨论的代码以及完整的骨架应用程序的代码可在 GitHub 的存储库[github.com/shamahoque/mern-skeleton](https://github.com/shamahoque/mern-skeleton)中找到。仅后端的代码可在同一存储库的名为`mern-skeleton-backend`的分支中找到。您可以克隆此代码，并在阅读本章其余部分的代码解释时运行应用程序。

# 文件夹和文件结构

以下文件夹结构仅显示与 MERN 骨架后端相关的文件。有了这些文件，我们将生成一个功能齐全的独立服务器端应用程序：

```jsx
| mern_skeleton/
   | -- config/
      | --- config.js
   | -- server/
      | --- controllers/
         | ---- auth.controller.js
         | ---- user.controller.js
      | --- helpers/
         | ---- dbErrorHandler.js
      | --- models/
         | ---- user.model.js
      | --- routes/
         | ---- auth.routes.js
         | ---- user.routes.js
      | --- express.js
      | --- server.js
  | -- .babelrc
  | -- nodemon.json
  | -- package.json
  | -- template.js
  | -- webpack.config.server.js
```

这个结构将在下一章进一步扩展，在那里我们通过添加`React`前端来完成骨架应用程序。

# 项目设置

如果开发环境已经设置好，我们可以初始化 MERN 项目以开始开发后端。首先，我们将在项目文件夹中初始化`package.json`，配置和安装开发依赖项，设置用于代码的配置变量，并更新`package.json`以帮助开发和运行代码的运行脚本。

# 初始化`package.json`

我们需要一个`package.json`文件来存储有关项目的元信息，列出模块依赖项及其版本号，并定义运行脚本。要在项目文件夹中初始化`package.json`文件，请从命令行转到项目文件夹并运行`npm init`，然后按照说明添加必要的细节。有了`package.json`文件后，我们可以继续设置和开发，并在代码实现过程中根据需要更新文件。

# 开发依赖项

为了开始开发并运行后端服务器代码，我们将配置和安装 Babel、Webpack 和 Nodemon，如第二章中所讨论的那样，对于仅后端，进行一些微小的调整。

# Babel

由于我们将使用 ES6 编写后端代码，我们将配置和安装 Babel 模块来转换 ES6。

首先，在`.babelrc`文件中配置 Babel，使用最新 JS 特性的预设和一些目前未在`babel-preset-env`下覆盖的 stage-x 特性。

`mern-skeleton/.babelrc`：

```jsx
{
    "presets": [
      "env",
      "stage-2"
    ]
}
```

接下来，我们从命令行安装 Babel 模块作为`devDependencies`：

```jsx
npm install --save-dev babel-core babel-loader babel-preset-env babel-preset-stage-2
```

一旦模块安装完成，您会注意到`package.json`文件中的`devDependencies`列表已更新。

# Webpack

我们需要 Webpack 使用 Babel 编译和捆绑服务器端代码，并且对于配置，我们可以使用在第二章中讨论的相同的`webpack.config.server.js`。

从命令行运行以下命令来安装`webpack`，`webpack-cli`和`webpack-node-externals`模块：

```jsx
npm install --save-dev webpack webpack-cli webpack-node-externals
```

这将安装 Webpack 模块并更新`package.json`文件。

# Nodemon

为了在开发过程中更新代码时自动重新启动 Node 服务器，我们将使用 Nodemon 来监视服务器代码的更改。我们可以使用与第二章中讨论的相同的安装和配置指南，*准备开发环境*。

# 配置变量

在`config/config.js`文件中，我们将定义一些与服务器端配置相关的变量，这些变量将在代码中使用，但不应作为最佳实践硬编码，也是出于安全目的。

`mern-skeleton/config/config.js`：

```jsx
const config = {
  env: process.env.NODE_ENV || 'development',
  port: process.env.PORT || 3000,
  jwtSecret: process.env.JWT_SECRET || "YOUR_secret_key",
  mongoUri: process.env.MONGODB_URI ||
    process.env.MONGO_HOST ||
    'mongodb://' + (process.env.IP || 'localhost') + ':' +
    (process.env.MONGO_PORT || '27017') +
    '/mernproject'
}

export default config
```

定义的配置变量有：

+   `env`：区分开发和生产模式

+   `端口`：定义服务器的监听端口

+   `jwtSecret`：用于签署 JWT 的秘钥

+   `mongoUri`：项目的 MongoDB 数据库位置

# 运行脚本

为了在开发后端代码时运行服务器，我们可以从`package.json`文件中的`npm run development`脚本开始。对于完整的骨架应用程序，我们将使用第二章中定义的相同的运行脚本，*准备开发环境*。

`mern-skeleton/package.json`：

```jsx
"scripts": {
    "development": "nodemon"
 }
```

`npm run development`：从项目文件夹的命令行中运行此命令基本上会根据`nodemon.js`中的配置启动 Nodemon。配置指示 Nodemon 监视服务器文件的更新，并在更新时重新构建文件，然后重新启动服务器，以便立即使用更改。

# 准备服务器

在本节中，我们将集成 Express、Node 和 MongoDB，以在开始实现特定于用户的功能之前运行完全配置的服务器。

# 配置 Express

要使用 Express，我们将首先安装 Express，然后在`server/express.js`文件中添加和配置它。

从命令行运行以下命令来安装带有`--save`标志的`express`模块，以便`package.json`文件会自动更新：

```jsx
npm install express --save
```

一旦 Express 安装完成，我们可以将其导入到`express.js`文件中，并根据需要进行配置，并使其对整个应用程序可用。

`mern-skeleton/server/express.js`：

```jsx
import express from 'express'
const app = express()
  /*... configure express ... */
export default app
```

为了正确处理 HTTP 请求并提供响应，我们将使用以下模块来配置 Express：

+   `body-parser`：用于处理流式请求对象解析复杂性的主体解析中间件，以便我们可以通过在请求主体中交换 JSON 来简化浏览器-服务器通信：

+   安装`body-parser`模块：`npm install body-parser --save`

+   配置 Express：`bodyParser.json()`和`bodyParser.urlencoded({ extended: true })`

+   `cookie-parser`：用于解析和设置请求对象中的 cookie 的 cookie 解析中间件：

安装`cookie-parser`模块：`npm install cookie-parser --save`

+   `压缩`：压缩中间件，将尝试压缩所有通过中间件传递的请求的响应主体：

安装`compression`模块：`npm install compression --save`

+   `头盔`：一组中间件函数，通过设置各种 HTTP 头部来帮助保护 Express 应用程序：

安装`头盔`模块：`npm install helmet --save`

+   `cors`：中间件以启用**CORS**（**跨源资源共享**）：

安装`cors`模块：`npm install cors --save`

在安装了上述模块之后，我们可以更新`express.js`来导入这些模块并在导出到服务器其余代码中使用之前配置 Express 应用程序。

更新后的`mern-skeleton/server/express.js`代码应该如下所示：

```jsx
import express from 'express'
import bodyParser from 'body-parser'
import cookieParser from 'cookie-parser'
import compress from 'compression'
import cors from 'cors'
import helmet from 'helmet'

const app = express()

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))
```

```jsx
app.use(cookieParser())
app.use(compress())
app.use(helmet())
app.use(cors())

export default app
```

# 启动服务器

通过配置 Express 应用程序来接受 HTTP 请求，我们可以继续使用它来实现服务器以监听传入的请求。

在`mern-skeleton/server/server.js`文件中，添加以下代码来实现服务器：

```jsx
import config from './../config/config'
import app from './express'

app.listen(config.port, (err) => {
  if (err) {
    console.log(err)
  }
  console.info('Server started on port %s.', config.port)
})
```

我们首先导入配置变量来设置服务器将监听的端口号，然后配置 Express 应用程序以启动服务器。

要使此代码运行并继续开发，现在可以从命令行运行`npm run development`。如果代码没有错误，服务器应该开始运行，并且 Nodemon 会监视代码更改。

# 设置 Mongoose 并连接到 MongoDB

我们将使用`Mongoose`模块来在此骨架中实现用户模型，以及我们 MERN 应用程序的所有未来数据模型。在这里，我们将首先配置 Mongoose，并利用它来定义与 MongoDB 数据库的连接。

首先，要安装`mongoose`模块，请运行以下命令：

```jsx
npm install mongoose --save
```

然后，更新`server.js`文件以导入`mongoose`模块，配置它以使用原生的 ES6 promises，并最终使用它来处理与项目的 MongoDB 数据库的连接。

`mern-skeleton/server/server.js`：

```jsx
import mongoose from 'mongoose'

mongoose.Promise = global.Promise
mongoose.connect(config.mongoUri)

mongoose.connection.on('error', () => {
  throw new Error(`unable to connect to database: ${mongoUri}`)
})
```

如果您在开发中运行代码，则保存此更新应重新启动现在已集成了 Mongoose 和 MongoDB 的服务器。

Mongoose 是一个 MongoDB 对象建模工具，它提供了基于模式的解决方案来对应用程序数据进行建模。它包括内置的类型转换、验证、查询构建和业务逻辑钩子。在此后端堆栈中使用 Mongoose 提供了对 MongoDB 的更高层次的功能，包括将对象模型映射到数据库文档。因此，使用 Node 和 MongoDB 后端进行开发变得更简单和更高效。要了解有关 Mongoose 的更多信息，请访问[mongoosejs.com](http://mongoosejs.com)。

# 在根 URL 上提供 HTML 模板

现在，具有 Node、Express 和 MongoDB 功能的服务器正在运行，我们可以扩展它以响应根 URL`/`的传入请求并提供 HTML 模板。

在`template.js`文件中，添加一个 JS 函数，该函数返回一个简单的 HTML 文档，该文档将在浏览器屏幕上呈现`Hello World`。

`mern-skeleton/template.js`：

```jsx
export default () => {
    return `<!doctype html>
      <html lang="en">
          <head>
             <meta charset="utf-8">
             <title>MERN Skeleton</title>
          </head>
          <body>
            <div id="root">Hello World</div>
          </body>
      </html>`
}
```

要在根 URL 上提供此模板，请更新`express.js`文件以导入此模板，并在对`'/'`路由的 GET 请求的响应中发送它。

`mern-skeleton/server/express.js`：

```jsx
import Template from './../template'
...
app.get('/', (req, res) => {
  res.status(200).send(Template())
})
...
```

通过这个更新，在浏览器中打开根 URL 应该显示“Hello World”在页面上呈现。

如果您在本地机器上运行代码，根 URL 将是`http://localhost:3000/`。

# 用户模型

我们将在`server/models/user.model.js`文件中实现用户模型，使用 Mongoose 来定义包含必要用户数据字段的模式，为字段添加内置验证，并整合密码加密、认证和自定义验证等业务逻辑。

我们将首先导入`mongoose`模块，并使用它来生成一个`UserSchema`。

`mern-skeleton/server/models/user.model.js`:

```jsx
import mongoose from 'mongoose'

const UserSchema = new mongoose.Schema({ … })
```

`mongoose.Schema()`函数以模式定义对象作为参数，生成一个新的 Mongoose 模式对象，可以在后端代码的其余部分中使用。

# 用户模式定义

生成新的 Mongoose 模式所需的用户模式定义对象将声明所有用户数据字段和相关属性。

# 名称

`name`字段是一个必填字段，类型为`String`。

`mern-skeleton/server/models/user.model.js`:

```jsx
name: {
   type: String,
   trim: true,
   required: 'Name is required'
 },
```

# 电子邮件

`email`字段是一个必填字段，类型为`String`，必须匹配有效的电子邮件格式，并且在用户集合中也必须是“唯一”的。

`mern-skeleton/server/models/user.model.js`:

```jsx
email: {
  type: String,
  trim: true,
  unique: 'Email already exists',
  match: [/.+\@.+\..+/, 'Please fill a valid email address'],
  required: 'Email is required'
},
```

# 创建和更新时间戳

`created`和`updated`字段是`Date`值，将被程序生成以记录用户创建和更新的时间戳。

`mern-skeleton/server/models/user.model.js`:

```jsx
created: {
  type: Date,
  default: Date.now
},
updated: Date,
```

# 哈希密码和盐

`hashed_password`和`salt`字段代表我们将用于认证的加密用户密码。

`mern-skeleton/server/models/user.model.js`:

```jsx
hashed_password: {
    type: String,
    required: "Password is required"
},
salt: String
```

出于安全目的，实际密码字符串不会直接存储在数据库中，而是单独处理。

# 用于认证的密码

密码字段对于在任何应用程序中提供安全用户认证非常重要，它需要作为用户模型的一部分进行加密、验证和安全认证。

# 作为虚拟字段

用户提供的`password`字符串不会直接存储在用户文档中。相反，它被处理为一个“虚拟”字段。

`mern-skeleton/server/models/user.model.js`:

```jsx
UserSchema
  .virtual('password')
  .set(function(password) {
    this._password = password
    this.salt = this.makeSalt()
    this.hashed_password = this.encryptPassword(password)
  })
  .get(function() {
    return this._password
  })
```

当在用户创建或更新时接收到`password`值时，它将被加密为一个新的哈希值，并设置为`hashed_password`字段，以及在`salt`字段中设置`salt`值。

# 加密和认证

加密逻辑和盐生成逻辑，用于生成代表`password`值的`hashed_password`和`salt`值，被定义为`UserSchema`方法。

`mern-skeleton/server/models/user.model.js`：

```jsx
UserSchema.methods = {
  authenticate: function(plainText) {
    return this.encryptPassword(plainText) === this.hashed_password
  },
  encryptPassword: function(password) {
    if (!password) return ''
    try {
      return crypto
        .createHmac('sha1', this.salt)
        .update(password)
        .digest('hex')
    } catch (err) {
      return ''
    }
  },
  makeSalt: function() {
    return Math.round((new Date().valueOf() * Math.random())) + ''
  }
}
```

此外，`authenticate`方法也被定义为`UserSchema`方法，用于在用户提供的密码必须进行验证以进行登录时使用。

Node 中的`crypto`模块用于将用户提供的密码字符串加密为带有随机生成的`salt`值的`hashed_password`。当用户详细信息在创建或更新时保存到数据库中，`hashed_password`和 salt 将存储在用户文档中。在用户登录时，需要`hashed_password`和 salt 值来匹配和验证提供的密码字符串，使用之前定义的`authenticate`方法。

# 密码字段验证

为了在最终用户选择的实际密码字符串上添加验证约束，我们需要添加自定义验证逻辑并将其与模式中的`hashed_password`字段关联起来。

`mern-skeleton/server/models/user.model.js`：

```jsx
UserSchema.path('hashed_password').validate(function(v) {
  if (this._password && this._password.length < 6) {
    this.invalidate('password', 'Password must be at least 6 characters.')
  }
  if (this.isNew && !this._password) {
    this.invalidate('password', 'Password is required')
  }
}, null)
```

为了确保在创建新用户或更新现有密码时确实提供了密码值，并且长度至少为六个字符，我们添加了自定义验证以在 Mongoose 尝试存储`hashed_password`值之前检查密码值。如果验证失败，逻辑将返回相关的错误消息。

一旦`UserSchema`被定义，并且所有与密码相关的业务逻辑都像之前讨论的那样被添加，我们最终可以在`user.model.js`文件的底部导出模式，以便在后端代码的其他部分中使用它。

`mern-skeleton/server/models/user.model.js`：

```jsx
export default mongoose.model('User', UserSchema) 
```

# Mongoose 错误处理

向用户模式字段添加的验证约束将在将用户数据保存到数据库时引发错误消息。为了处理这些验证错误以及我们向数据库查询时可能引发的其他错误，我们将定义一个辅助方法来返回相关的错误消息，以便在请求-响应周期中适当地传播。

我们将在`server/helpers/dbErrorHandler.js`文件中添加`getErrorMessage`辅助方法。该方法将解析并返回与使用 Mongoose 查询 MongoDB 时发生的特定验证错误或其他错误相关联的错误消息。

`mern-skeleton/server/helpers/dbErrorHandler.js`：

```jsx
const getErrorMessage = (err) => {
  let message = ''
  if (err.code) {
      switch (err.code) {
          case 11000:
          case 11001:
              message = getUniqueErrorMessage(err)
              break
          default:
              message = 'Something went wrong'
      }
  } else {
      for (let errName in err.errors) {
          if (err.errors[errName].message)
          message = err.errors[errName].message
      }
  }
  return message
}

export default {getErrorMessage}
```

不是因为 Mongoose 验证器违规而抛出的错误将包含错误代码，并且在某些情况下需要以不同方式处理。例如，由于违反唯一约束而导致的错误将返回一个与 Mongoose 验证错误不同的错误对象。唯一选项不是验证器，而是用于构建 MongoDB 唯一索引的便捷助手，因此我们将添加另一个`getUniqueErrorMessage`方法来解析与唯一约束相关的错误对象，并构造适当的错误消息。

`mern-skeleton/server/helpers/dbErrorHandler.js`：

```jsx
const getUniqueErrorMessage = (err) => {
  let output
  try {
      let fieldName =   
      err.message.substring(err.message.lastIndexOf('.$') + 2,                                             
      err.message.lastIndexOf('_1'))
      output = fieldName.charAt(0).toUpperCase() + fieldName.slice(1) +   
      ' already exists'
  } catch (ex) {
      output = 'Unique field already exists'
  }
  return output
}
```

通过使用从此辅助文件导出的`getErrorMessage`函数，我们将在处理 Mongoose 执行的用户 CRUD 操作引发的错误时添加有意义的错误消息。

# 用户 CRUD API

Express 应用程序公开的用户 API 端点将允许前端对根据用户模型生成的文档执行 CRUD 操作。为了实现这些工作端点，我们将编写 Express 路由和相应的控制器回调函数，当这些声明的路由收到 HTTP 请求时应该执行这些函数。在本节中，我们将看看这些端点在没有任何身份验证限制的情况下如何工作。

用户 API 路由将在`server/routes/user.routes.js`中使用 Express 路由器声明，然后挂载到我们在`server/express.js`中配置的 Express 应用程序上。

`mern-skeleton/server/express.js`：

```jsx
import userRoutes from './routes/user.routes'
...
app.use('/', userRoutes)
...
```

# 用户路由

`user.routes.js`文件中定义的用户路由将使用`express.Router()`来声明具有相关 HTTP 方法的路由路径，并分配应该在服务器接收到这些请求时调用的相应控制器函数。

我们将通过以下方式保持用户路由简单：

+   `/api/users`用于：

+   使用 GET 列出用户

+   使用 POST 创建新用户

+   `/api/users/:userId`用于：

+   使用 GET 获取用户

+   使用 PUT 更新用户

+   使用 DELETE 删除用户

生成的`user.routes.js`代码将如下所示（不包括需要为受保护的路由添加的身份验证考虑）。

`mern-skeleton/server/routes/user.routes.js`：

```jsx
import express from 'express'
import userCtrl from '../controllers/user.controller'

const router = express.Router()

router.route('/api/users')
  .get(userCtrl.list)
  .post(userCtrl.create)

router.route('/api/users/:userId')
  .get(userCtrl.read)
  .put(userCtrl.update)
  .delete(userCtrl.remove)

router.param('userId', userCtrl.userByID)

export default router
```

# 用户控制器

`server/controllers/user.controller.js`文件将包含在前面的用户路由声明中使用的控制器方法，作为服务器接收到路由请求时的回调。

`user.controller.js`文件将具有以下结构：

```jsx
import User from '../models/user.model'
import _ from 'lodash'
import errorHandler from './error.controller'

const create = (req, res, next) => { … }
const list = (req, res) => { … }
const userByID = (req, res, next, id) => { … }
const read = (req, res) => { … }
const update = (req, res, next) => { … }
const remove = (req, res, next) => { … }

export default { create, userByID, read, list, remove, update }
```

控制器将使用`errorHandler`助手来在 Mongoose 发生错误时响应路由请求并提供有意义的消息。在更新具有更改值的现有用户时，它还将使用一个名为`lodash`的模块。

`lodash`是一个 JavaScript 库，提供常见编程任务的实用函数，包括对数组和对象的操作。要安装`lodash`，请从命令行运行`npm install lodash --save`。

先前定义的每个控制器函数都与路由请求相关，并将根据每个 API 用例进行详细说明。

# 创建新用户

创建新用户的 API 端点在以下路由中声明。

`mern-skeleton/server/routes/user.routes.js`：

```jsx
router.route('/api/users').post(userCtrl.create)
```

当 Express 应用程序在`'/api/users'`处收到 POST 请求时，它会调用控制器中定义的`create`函数。

`mern-skeleton/server/controllers/user.controller.js`：

```jsx
const create = (req, res, next) => {
  const user = new User(req.body)
  user.save((err, result) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.status(200).json({
      message: "Successfully signed up!"
    })
  })
}
```

此函数使用从前端收到的用户 JSON 对象在`req.body`中创建新用户。`user.save`尝试在 Mongoose 对数据进行验证检查后将新用户保存到数据库中，因此将向请求的客户端返回错误或成功响应。

# 列出所有用户

获取所有用户的 API 端点在以下路由中声明。

`mern-skeleton/server/routes/user.routes.js`：

```jsx
router.route('/api/users').get(userCtrl.list)
```

当 Express 应用程序在`'/api/users'`处收到 GET 请求时，它会执行`list`控制器函数。

`mern-skeleton/server/controllers/user.controller.js`：

```jsx
const list = (req, res) => {
  User.find((err, users) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.json(users)
  }).select('name email updated created')
}
```

`list`控制器函数从数据库中找到所有用户，仅填充结果用户列表中的名称、电子邮件、创建和更新字段，然后将这些用户列表作为 JSON 对象数组返回给请求的客户端。

# 按 ID 加载用户以进行读取、更新或删除

读取、更新和删除的所有三个 API 端点都需要根据正在访问的用户的用户 ID 从数据库中检索用户。在响应特定的读取、更新或删除请求之前，我们将编程 Express 路由器执行此操作。

# 加载

每当 Express 应用程序收到与路径中包含`:userId`参数匹配的路由的请求时，该应用程序将首先执行`userByID`控制器函数，然后传播到传入请求特定的`next`函数。

`mern-skeleton/server/routes/user.routes.js`：

```jsx
router.param('userId', userCtrl.userByID)
```

`userByID`控制器函数使用`:userId`参数中的值来查询数据库的`_id`，并加载匹配用户的详细信息。

`mern-skeleton/server/controllers/user.controller.js`：

```jsx
const userByID = (req, res, next, id) => {
  User.findById(id).exec((err, user) => {
    if (err || !user)
      return res.status('400').json({
        error: "User not found"
      })
    req.profile = user
    next()
  })
}
```

如果在数据库中找到匹配的用户，则用户对象将附加到请求对象的`profile`键中。然后，使用`next()`中间件将控制传播到下一个相关的控制器函数。例如，如果原始请求是读取用户配置文件，则`userById`中的`next()`调用将转到`read`控制器函数。

# 阅读

声明了读取单个用户数据的 API 端点在以下路由中。

`mern-skeleton/server/routes/user.routes.js`：

```jsx
router.route('/api/users/:userId').get(userCtrl.read)
```

当 Express 应用程序在`'/api/users/:userId'`接收到 GET 请求时，它执行`userByID`控制器函数，通过参数中的`userId`值加载用户，然后执行`read`控制器函数。

`mern-skeleton/server/controllers/user.controller.js`：

```jsx
const read = (req, res) => {
  req.profile.hashed_password = undefined
  req.profile.salt = undefined
  return res.json(req.profile)
}
```

`read`函数从`req.profile`中检索用户详细信息，并在将用户对象发送到请求客户端的响应之前删除敏感信息，如`hashed_password`和`salt`值。

# 更新

声明了更新单个用户的 API 端点在以下路由中。

`mern-skeleton/server/routes/user.routes.js`：

```jsx
router.route('/api/users/:userId').put(userCtrl.update)
```

当 Express 应用程序在`'/api/users/:userId'`接收到 PUT 请求时，类似于`read`，它首先加载具有`:userId`参数值的用户，然后执行`update`控制器函数。

`mern-skeleton/server/controllers/user.controller.js`：

```jsx
const update = (req, res, next) => {
  let user = req.profile
  user = _.extend(user, req.body)
  user.updated = Date.now()
  user.save((err) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    user.hashed_password = undefined
    user.salt = undefined
    res.json(user)
  })
}
```

`update`函数从`req.profile`中检索用户详细信息，然后使用`lodash`模块来扩展和合并请求体中的更改以更新用户数据。在将此更新后的用户保存到数据库之前，`updated`字段将填充为当前日期以反映最后更新的时间戳。成功保存此更新后，更新后的用户对象将通过删除敏感数据，如`hashed_password`和`salt`，然后将用户对象发送到请求客户端的响应中。

# 删除

声明了删除用户的 API 端点在以下路由中。

`mern-skeleton/server/routes/user.routes.js`：

```jsx
router.route('/api/users/:userId').delete(userCtrl.remove)
```

当 Express 应用程序在`'/api/users/:userId'`接收到 DELETE 请求时，类似于读取和更新，它首先通过 ID 加载用户，然后执行`remove`控制器函数。

`mern-skeleton/server/controllers/user.controller.js`：

```jsx
const remove = (req, res, next) => {
  let user = req.profile
  user.remove((err, deletedUser) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    deletedUser.hashed_password = undefined
    deletedUser.salt = undefined
    res.json(deletedUser)
  })
}
```

`remove`函数从`req.profile`中检索用户，并使用`remove()`查询从数据库中删除用户。成功删除后，将在响应中返回已删除的用户对象。

到目前为止，通过实现 API 端点，任何客户端都可以对用户模型执行 CRUD 操作，但我们希望通过认证和授权来限制对其中一些操作的访问。

# 用户认证和受保护的路由

为了限制用户操作（如用户资料查看、用户更新和用户删除），我们将实现 JWT 的登录认证，然后保护和授权读取、更新和删除路由。

登录和登出的认证相关 API 端点将在`server/routes/auth.routes.js`中声明，然后挂载到`server/express.js`中的 Express 应用程序上。

`mern-skeleton/server/express.js`：

```jsx
import authRoutes from './routes/auth.routes'
  ...
  app.use('/', authRoutes)
  ...
```

# 认证路由

使用`express.Router()`在`auth.routes.js`文件中定义了两个认证 API，以声明具有相关 HTTP 方法的路由路径，并分配了应在收到这些路由的请求时调用的相应认证控制器函数。

认证路由如下：

+   `'/auth/signin'`：使用电子邮件和密码进行用户认证的 POST 请求

+   `'/auth/signout'`：GET 请求以清除包含在登录后设置在响应对象上的 JWT 的 cookie

生成的`mern-skeleton/server/routes/auth.routes.js`文件将如下所示：

```jsx
import express from 'express'
import authCtrl from '../controllers/auth.controller'

const router = express.Router()

router.route('/auth/signin')
  .post(authCtrl.signin)
router.route('/auth/signout')
  .get(authCtrl.signout)

export default router
```

# 认证控制器

`server/controllers/auth.controller.js`中的认证控制器函数不仅处理登录和登出路由的请求，还提供 JWT 和`express-jwt`功能，以启用受保护的用户 API 端点的认证和授权。

`auth.controller.js`文件将具有以下结构：

```jsx
import User from '../models/user.model'
import jwt from 'jsonwebtoken'
import expressJwt from 'express-jwt'
import config from './../../config/config'

const signin = (req, res) => { … }
const signout = (req, res) => { … }
const requireSignin = … 
const hasAuthorization = (req, res) => { … }

export default { signin, signout, requireSignin, hasAuthorization }
```

以下详细说明了四个控制器函数，以展示后端如何使用 JSON Web Tokens 实现用户认证。

# 登录

在以下路由中声明了用于登录用户的 API 端点。

`mern-skeleton/server/routes/auth.routes.js`：

```jsx
router.route('/auth/signin').post(authCtrl.signin)
```

当 Express 应用程序在`'/auth/signin'`收到 POST 请求时，它会执行`signin`控制器函数。

`mern-skeleton/server/controllers/auth.controller.js`：

```jsx
const signin = (req, res) => {
  User.findOne({
    "email": req.body.email
  }, (err, user) => {
    if (err || !user)
      return res.status('401').json({
        error: "User not found"
      })

    if (!user.authenticate(req.body.password)) {
      return res.status('401').send({
        error: "Email and password don't match."
      })
    }

    const token = jwt.sign({
      _id: user._id
    }, config.jwtSecret)

    res.cookie("t", token, {
      expire: new Date() + 9999
    })

    return res.json({
      token,
      user: {_id: user._id, name: user.name, email: user.email}
    })
  })
}
```

`POST`请求对象在`req.body`中接收电子邮件和密码。该电子邮件用于从数据库中检索匹配的用户。然后，`UserSchema`中定义的密码验证方法用于验证从客户端`req.body`中接收的密码。

如果密码成功验证，JWT 模块将用秘密密钥和用户的`_id`值生成一个签名的 JWT。

安装`jsonwebtoken`模块，通过在命令行中运行`npm install jsonwebtoken --save`来使其在导入此控制器时可用。

然后，签名的 JWT 将与用户详细信息一起返回给经过身份验证的客户端。可选地，我们还可以将令牌设置为响应对象中的 cookie，以便在客户端选择 JWT 存储的情况下可用。在客户端，当从服务器请求受保护的路由时，必须将此令牌附加为`Authorization`头。

# 登出

在以下路由中声明了用于登出用户的 API 端点。

`mern-skeleton/server/routes/auth.routes.js`:

```jsx
router.route('/auth/signout').get(authCtrl.signout)
```

当 Express 应用程序在`'/auth/signout'`处收到 GET 请求时，它会执行`signout`控制器函数。

`mern-skeleton/server/controllers/auth.controller.js`:

```jsx
const signout = (req, res) => {
  res.clearCookie("t")
  return res.status('200').json({
    message: "signed out"
  })
}
```

`signout`函数清除包含签名 JWT 的响应 cookie。这是一个可选的端点，如果前端根本不使用 cookie，则对身份验证没有真正必要。使用 JWT，用户状态存储是客户端的责任，并且除了 cookie 之外，客户端存储的选择有多种选项。在登出时，客户端需要在客户端删除令牌，以确立用户不再经过身份验证。

# 使用 express-jwt 保护路由

为了保护对读取、更新和删除路由的访问，服务器需要检查请求的客户端是否真的是经过身份验证和授权的用户。

在访问受保护的路由时，我们将使用`express-jwt`模块来检查请求用户是否已登录并具有有效的 JWT。

`express-jwt`模块是验证 JSON Web 令牌的中间件。运行`npm install express-jwt --save`来安装`express-jwt`。

# 要求登录

`auth.controller.js`中的`requireSignin`方法使用`express-jwt`来验证传入请求的`Authorization`头中是否有有效的 JWT。如果令牌有效，它会将经过验证的用户 ID 附加在请求对象的`'auth'`键中，否则会抛出身份验证错误。

`mern-skeleton/server/controllers/auth.controller.js`：

```jsx
const requireSignin = expressJwt({
  secret: config.jwtSecret,
  userProperty: 'auth'
})
```

我们可以将`requireSignin`添加到任何应受保护免受未经身份验证访问的路由。

# 授权已登录用户

对于一些受保护的路由，如更新和删除，除了检查身份验证外，我们还希望确保请求的用户只能更新或删除自己的用户信息。为了实现这一点，在`auth.controller.js`中定义的`hasAuthorization`函数在允许相应的 CRUD 控制器函数继续之前，检查经过身份验证的用户是否与正在更新或删除的用户相同。

`mern-skeleton/server/controllers/auth.controller.js`：

```jsx
const hasAuthorization = (req, res, next) => {
  const authorized = req.profile && req.auth && req.profile._id == 
  req.auth._id
  if (!(authorized)) {
    return res.status('403').json({
      error: "User is not authorized"
    })
  }
  next()
}
```

`req.auth`对象由`express-jwt`在身份验证验证后的`requireSignin`中填充，而`req.profile`由`user.controller.js`中的`userByID`函数填充。我们将在需要身份验证和授权的路由中添加`hasAuthorization`函数。

# 保护用户路由

我们将在需要受到身份验证和授权保护的用户路由声明中添加`requireSignin`和`hasAuthorization`。

更新`user.routes.js`中的读取、更新和删除路由如下。

`mern-skeleton/server/routes/user.routes.js`：

```jsx
import authCtrl from '../controllers/auth.controller'
...
router.route('/api/users/:userId')
    .get(authCtrl.requireSignin, userCtrl.read)
    .put(authCtrl.requireSignin, authCtrl.hasAuthorization, 
     userCtrl.update)
    .delete(authCtrl.requireSignin, authCtrl.hasAuthorization, 
     userCtrl.remove)
...
```

只需要身份验证验证的用户信息读取路由，而更新和删除路由在执行这些 CRUD 操作之前应检查身份验证和授权。

# 对于 express-jwt 的身份验证错误处理

处理由`express-jwt`抛出的与验证传入请求中的 JWT 令牌相关的错误时，我们需要在 Express 应用程序配置中添加以下错误捕获代码，该配置位于`mern-skeleton/server/express.js`中的代码末尾，在挂载路由之后并在导出应用程序之前：

```jsx
app.use((err, req, res, next) => {
  if (err.name === 'UnauthorizedError') {
    res.status(401).json({"error" : err.name + ": " + err.message})
  }
})
```

当令牌由于某种原因无法验证时，`express-jwt`会抛出一个名为`UnauthorizedError`的错误。我们在这里捕获此错误，以便向请求的客户端返回`401`状态。

通过实施用户身份验证来保护路由，我们已经涵盖了骨架 MERN 应用程序的所有期望功能。在下一节中，我们将看看如何在不实施前端的情况下检查这个独立后端是否按预期运行。

# 检查独立后端

在选择用于检查后端 API 的工具时，有许多选项，从命令行工具 curl（[`github.com/curl/curl`](https://github.com/curl/curl)）到 Advanced REST Client（[`chrome.google.com/webstore/detail/advanced-rest-client/hgmloofddffdnphfgcellkdfbfbjeloo`](https://chrome.google.com/webstore/detail/advanced-rest-client/hgmloofddffdnphfgcellkdfbfbjeloo)）—一个具有交互式用户界面的 Chrome 扩展程序应用。

要检查本章实现的 API，首先从命令行运行服务器，并使用这些工具之一请求路由。如果您在本地计算机上运行代码，则根 URL 为`http://localhost:3000/`。

使用 ARC，我们将展示检查实现的 API 端点的五个用例的预期行为。

# 创建新用户

首先，我们将使用`/api/users`的 POST 请求创建一个新用户，并在请求体中传递名称、电子邮件和密码值。当用户在数据库中成功创建且没有任何验证错误时，我们将看到一个 200 OK 的成功消息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/a33bc049-08a1-4fc9-b5ae-33f3f08a4ce1.png)

# 获取用户列表

我们可以通过对`/api/users`进行`GET`请求来查看数据库中是否有新用户。响应应包含存储在数据库中的所有用户对象的数组：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/a9f44f9e-5f75-4c8e-875b-0c9eeedf7308.png)

# 尝试获取单个用户

接下来，我们将尝试在未登录的情况下访问受保护的 API。对任何一个用户进行`GET`请求将返回 401 未经授权，例如，在以下示例中，对`/api/users/5a1c7ead1a692aa19c3e7b33`的`GET`请求将返回 401：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/6d089bdf-7f14-480c-97b3-4217eeac894b.png)

# 登录

为了能够访问受保护的路由，我们将使用第一个示例中创建的用户的凭据进行登录。要登录，需要在`/auth/signin`发送带有电子邮件和密码的 POST 请求。成功登录后，服务器将返回一个签名的 JWT 和用户详细信息。我们将需要这个令牌来访问获取单个用户的受保护路由：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/6f5444db-3e39-4a3f-8f8e-fd0ef0976303.png)

# 成功获取单个用户

使用登录后收到的令牌，我们现在可以访问之前失败的受保护路由。在向`/api/users/5a1c7ead1a692aa19c3e7b33`发出 GET 请求时，令牌以 Bearer 方案设置在`Authorization`标头中，这次用户对象成功返回。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/93af55fd-9288-4870-9250-549a0df79e08.png)

# 总结

在本章中，我们使用 Node、Express 和 MongoDB 开发了一个完全独立的服务器端应用程序，涵盖了 MERN 骨架应用程序的第一部分。在后端，我们实现了以下功能：

+   用 Mongoose 实现的用于存储用户数据的用户模型

+   使用 Express 实现的用户 API 端点执行 CRUD 操作

+   使用 JWT 和`express-jwt`实现受保护路由的用户认证

我们还通过配置 Webpack 编译 ES6 代码和 Nodemon 在代码更改时重新启动服务器来设置开发流程。最后，我们使用 Chrome 的高级 Rest API 客户端扩展应用程序检查了 API 的实现。

我们现在准备在下一章中扩展这个后端应用程序代码，添加 React 前端，并完成 MERN 骨架应用程序。
