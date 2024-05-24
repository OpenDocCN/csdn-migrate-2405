# 使用 Meteor 构建单页 Web 应用（一）

> 原文：[`zh.annas-archive.org/md5/54FF21F0AC5E9648A2B99A8900626FC1`](https://zh.annas-archive.org/md5/54FF21F0AC5E9648A2B99A8900626FC1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

感谢您购买这本书。您为前端和 JavaScript 技术的新一步做出了明智的选择。Meteor 框架不仅仅是为了简化事情而出现的另一个库。它为 Web 服务器、客户端逻辑和模板提供了一个完整的解决方案。此外，它还包含了一个完整的构建过程，这将使通过块状方式为 Web 工作变得更快。多亏了 Meteor，链接您的脚本和样式已经成为过去，因为自动构建过程会为您处理所有事情。这确实是一个很大的改变，但您很快就会喜欢上它，因为它使扩展应用程序的速度与创建新文件一样快。

Meteor 旨在创建单页应用程序，其中实时是默认值。它负责数据同步和 DOM 的更新。如果数据发生变化，您的屏幕将进行更新。这两个基本概念构成了我们作为网页开发者所做的很多工作，而 Meteor 则无需编写任何额外的代码即可实现。

在我看来，Meteor 在现代网页开发中是一个完整的游戏改变者。它将以下模式作为默认值引入：

+   胖客户端：所有的逻辑都存在于客户端。HTML 仅在初始页面加载时发送

+   在客户端和服务器上使用相同的 JavaScript 和 API

+   实时：数据自动同步到所有客户端

+   一种“无处不在的数据库”方法，允许在客户端进行数据库查询

+   作为 Web 服务器通信默认的发布/订阅模式

一旦你使用了我所介绍的所有这些新概念，你很难回到过去那种只花费时间准备应用程序结构，而链接文件或将它们封装为 Require.js 模块，编写端点以及编写请求和发送数据上下的代码的老方法。

在阅读这本书的过程中，您将逐步介绍这些概念以及它们是如何相互连接的。我们将建立一个带有后端编辑帖子的博客。博客是一个很好的例子，因为它使用了帖子列表、每个帖子的不同路由以及一个管理界面来添加新帖子，为我们提供了全面理解 Meteor 所需的所有内容。

# 本书涵盖内容

第一章，*Meteor 入门*，描述了安装和运行 Meteor 所需的步骤，同时还详细介绍了 Meteor 项目的文件结构，特别是我们将要构建的 Meteor 项目。

第二章，*构建 HTML 模板*，展示了如何使用 handlebar 这样的语法构建反应式模板，以及如何在其中显示数据是多么简单。

第三章，*存储数据和处理集合*，涵盖了服务器和客户端的数据库使用。

第四章, *数据流控制*, 介绍了 Meteor 的发布/订阅模式，该模式用于在服务器和客户端之间同步数据。

第五章, *使用路由使我们的应用具有多样性*, 教我们如何设置路由，以及如何让我们的应用表现得像一个真正的网站。

第六章, *使用会话保持状态*, 讨论了响应式会话对象及其使用方法。

第七章, *用户和权限*, 描述了用户的创建以及登录过程是如何工作的。此时，我们将为我们的博客创建后端部分。

第八章, *使用 Allow 和 Deny 规则进行安全控制*, 介绍了如何限制数据流仅对某些用户开放，以防止所有人对我们的数据库进行更改。

第九章, *高级响应性*, 展示了如何构建我们自己的自定义响应式对象，该对象可以根据时间间隔重新运行一个函数。

第十章, *部署我们的应用*, 介绍了如何使用 Meteor 自己的部署服务以及在自己的基础设施上部署应用。

第十一章, *构建我们自己的包*, 描述了如何编写一个包并将其发布到 Atmosphere，供所有人使用。

第十二章, *Meteor 中的测试*, 展示了如何使用 Meteor 自带的 tinytest 包进行包测试，以及如何使用第三方工具测试 Meteor 应用程序本身。

附录, 包含 Meteor 命令列表以及 iron:router 钩子及其描述。

# 本书需要的软件

为了跟随章节中的示例，你需要一个文本编辑器来编写代码。我强烈推荐 Sublime Text 作为你的集成开发环境，因为它有几乎涵盖每个任务的可扩展插件。

你还需要一个现代浏览器来查看你的结果。由于许多示例使用浏览器控制台来更改数据库以及查看代码片段的结果，我推荐使用 Google Chrome。其开发者工具网络检查器拥有一个 web 开发者需要的所有工具，以便轻松地工作和服务器调试网站。

此外，你可以使用 Git 和 GitHub 来存储你每一步的成功，以及为了回到代码的先前版本。

每个章节的代码示例也将发布在 GitHub 上，地址为[`github.com/frozeman/book-building-single-page-web-apps-with-meteor`](https://github.com/frozeman/book-building-single-page-web-apps-with-meteor)，该仓库中的每个提交都与书中的一个章节相对应，为你提供了一种直观的方式来查看在每个步骤中添加和移除了哪些内容。

# 本书适合对象

这本书适合希望进入单页、实时应用新范式的 Web 开发者。你不需要成为 JavaScript 专业人士就能跟随书中的内容，但扎实的基本知识会让你发现这本书是个宝贵的伴侣。

如果你听说过 Meteor 但还没有使用过，这本书绝对适合你。它会教你所有你需要理解并成功使用 Meteor 的知识。如果你之前使用过 Meteor 但想要更深入的了解，那么最后一章将帮助你提高对自定义反应式对象和编写包的理解。目前 Meteor 社区中涉及最少的主题可能是测试，因此通过阅读最后一章，你将很容易理解如何使用自动化测试使你的应用更加健壮。

# 约定

在这本书中，你会发现多种用于区分不同信息类型的文本样式。以下是这些样式的几个示例及其含义解释。

文本中的代码词汇、数据库表名、文件夹名、文件名、文件扩展名、路径名、假 URL、用户输入和 Twitter 处理显示如下："With Meteor, we never have to link files with the `<script>` tags in HTML."

一段代码如下所示：

```js
<head>
  <title>My Meteor Blog</title>
</head>
<body>
  Hello World
</body>
```

当我们希望引起你对代码块中特定部分的关注时，相关行或项目以粗体显示：

```js
<div class="footer">
  <time datetime="{{formatTime timeCreated "iso"}}">Posted {{formatTime timeCreated "fromNow"}} by {{author}}</time>
</div>
```

任何命令行输入或输出如下所示：

```js
$ cd my/developer/folder
$ meteor create my-meteor-blog

```

**新术语**和**重要词汇**以粗体显示。例如，你在屏幕上看到的、在菜单或对话框中出现的词汇，在文本中显示为这样："However, now when we go to our browser, we will still see **Hello World**."

### 注意

警告或重要说明以这样的盒子形式出现。

### 提示

技巧和建议以这样的形式出现。

# 读者反馈

我们的读者的反馈总是受欢迎的。告诉我们你对这本书的看法——你喜欢或可能不喜欢的地方。读者反馈对我们开发您真正能从中获得最大收益的书很重要。

发送一般反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在消息主题中提到书名。

如果你需要我们出版某本书，并希望看到它，请在[www.packtpub.com](http://www.packtpub.com)上的**建议书名**表单中给我们留言，或者发送电子邮件至`<suggest@packtpub.com>`。

如果您在某个主题上有专业知识，并且您有兴趣撰写或为书籍做出贡献，请查看我们在[www.packtpub.com/authors](http://www.packtpub.com/authors)上的作者指南。

# 客户支持

既然您已经成为 Packt 书籍的自豪拥有者，我们有很多东西可以帮助您充分利用您的购买。

## 下载示例代码

您可以通过您在[`www.packtpub.com`](http://www.packtpub.com)的账户下载您购买的所有 Packt 书籍的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便我们将文件直接通过电子邮件发送给您。

## 错误更正

尽管我们已经尽一切努力确保我们的内容的准确性，但错误确实会发生。如果您在我们的书中发现一个错误——也许是在文本或代码中——我们将非常感谢您能向我们报告。这样做可以节省其他读者的挫折感，并帮助我们改进本书的后续版本。如果您发现任何错误，请通过访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书籍，点击**错误提交表单**链接，并输入您错误的详细信息。一旦您的错误得到验证，您的提交将被接受，错误将被上传到我们的网站，或添加到该标题的错误部分现有的错误列表中。

要查看之前提交的错误更正，请前往[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)并在搜索字段中输入书籍的名称。所需信息将在**错误更正**部分下出现。

## 盗版

互联网上的版权材料盗版是一个持续存在的问题，所有媒体都受到影响。在 Packt，我们非常重视我们版权和许可证的保护。如果您在互联网上以任何形式发现我们作品的非法副本，请立即提供给我们地址或网站名称，以便我们可以寻求解决方案。

请通过`<copyright@packtpub.com>`联系我们，并提供疑似被盗材料的链接。

我们感谢您在保护我们的作者和我们提供有价值内容的能力方面所提供的帮助。

## 问题

如果您在这本书的任何一个方面遇到问题，可以通过`<questions@packtpub.com>`联系我们，我们会尽力解决问题。


# 第一章：开始使用 Meteor

欢迎来到关于 Meteor 的这本书。Meteor 是一个令人兴奋的新 JavaScript 框架，我们将很快看到如何用更少的代码实现真实且令人印象深刻的结果。

在本章中，我们将学习系统要求以及我们开始需要使用哪些额外的工具。我们将了解如何轻松地运行我们的第一个 Meteor 应用程序，以及一个 Meteor 应用程序可能的良好基本文件夹结构。我们还将了解 Meteor 的自动构建过程及其特定的文件加载方式。

我们还将了解如何使用 Meteor 官方的包管理系统添加包。在本章末尾，我们将简要查看 Meteor 的命令行工具及其一些功能。

为了总结，我们将涵盖以下主题：

+   Meteor 的全栈框架

+   Meteor 的系统要求

+   安装 Meteor

+   添加基本包

+   Meteor 的文件夹约定和加载顺序

+   Meteor 的命令行工具

# Meteor 的全栈框架

Meteor 不仅仅是一个像 jQuery 或 AngularJS 这样的 JavaScript 库。它是一个包含前端库、基于 Node.js 的服务器和命令行工具的全栈解决方案。所有这些加在一起让我们可以用 JavaScript 编写大规模的网络应用程序，无论是在服务器端还是客户端，都可以使用一致的 API。

尽管 Meteor 还相当年轻，但已经有几家公司，如[`lookback.io`](https://lookback.io)、[`respond.ly`](https://respond.ly)和[`madeye.io`](https://madeye.io)，在其生产环境中使用 Meteor。

如果你想亲自看看用 Meteor 制作的东西，请查看[`madewith.meteor.com`](http://madewith.meteor.com)。

Meteor 使我们能够快速构建网络应用程序，并处理诸如文件链接、文件压缩和文件合并等无聊的过程。

以下是在 Meteor 下可以实现的一些亮点：

+   我们可以使用模板来构建复杂的网络应用程序，这些模板在数据更改时会自动更新，从而大大提高速度。

+   在我们应用程序运行的同时，我们可以将新代码推送到所有客户端。

+   Meteor 的核心包带有一个完整的账户解决方案，允许与 Facebook、Twitter 等无缝集成。

+   数据将自动在客户端之间同步，几乎实时地保持每个客户端在相同的状态。

+   延迟补偿将使我们的界面在服务器响应后台进行时看起来超级快速。

使用 Meteor 时，我们永远不需要在 HTML 的`<script>`标签中链接文件。Meteor 的命令行工具会自动收集我们应用程序文件夹中的 JavaScript 或 CSS 文件，并在初始页面加载时将它们链接到`index.html`文件中。这使得将我们的代码结构化到单独的文件中变得像创建它们一样简单。

Meteor 的命令行工具还会监控我们应用程序文件夹内的所有文件，如有更改，就会在文件更改时实时重建它们。

此外，它还会启动一个 Meteor 服务器，为客户端提供应用文件。当文件发生变化时，Meteor 会重新加载每个客户端的网站，同时保留其状态。这被称为**热代码重载**。

在生产环境中，构建过程还会对我们的 CSS 和 JavaScript 文件进行合并和压缩。

仅仅通过添加`less`和`coffee`核心包，我们甚至可以不费吹灰之力地用 LESS 写所有样式和用 CoffeeScript 写代码。

命令行工具也是用于部署和捆绑我们的应用的工具，这样我们就可以在远程服务器上运行它。

听起来很棒吗？让我们看看使用 Meteor 需要什么。

# Meteor 的要求

Meteor 不仅仅是 JavaScript 框架和服务器。正如我们之前所看到的，它也是一个命令行工具，为我们整个构建过程做好准备。

目前，官方支持的操作系统如下：

+   Mac OS X 10.6 及以上

+   Linux x86 和 x86_64 系统

+   Windows

    ### 注意

    在撰写本书时，Windows 安装程序仍在开发中。请关注[`github.com/meteor/meteor/wiki/Preview-of-Meteor-on-Windows`](https://github.com/meteor/meteor/wiki/Preview-of-Meteor-on-Windows)的 wiki 页面。

本书和所有示例都使用*Meteor 1.0*。

## 使用 Chrome 的开发者工具

我们还需要安装了 Firebug 插件的 Google Chrome 或 Firefox 来跟随需要控制台的示例。本书中的示例、屏幕截图和解释将使用 Google Chrome 的开发者工具。

## 使用 Git 和 GitHub

我强烈推荐在使用我们将在本书中工作的网页项目时使用**GitHub**。Git 和 GitHub 帮助我们备份我们的进度，并让我们总能回到之前的阶段，同时看到我们的更改。

Git 是一个版本控制系统，由 Linux 的发明者、Linus Torvalds 于 2005 年创建。

使用 Git，我们可以*提交*我们代码的任何状态，并稍后回到那个确切的状态。它还允许多个开发者在同一代码库上工作，并通过自动化过程合并他们的结果。如果在合并过程中出现冲突，合并开发者可以通过删除不需要的代码行来解决这些*合并冲突*。

我还建议在[`github.com`](http://github.com)注册一个账户，这是浏览我们代码历史的最简单方式。他们有一个易于使用的界面，以及一个很棒的 Windows 和 Mac 应用。

要跟随本书中的代码示例，你可以从本书的网页[`www.packtpub.com/books/content/support/17713`](https://www.packtpub.com/books/content/support/17713)下载每个章节的全部代码示例。

此外，您将能够从[`github.com/frozeman/book-building-single-page-web-apps-with-meteor`](http://github.com/frozeman/book-building-single-page-web-apps-with-meteor)克隆本书的代码。这个仓库中的每个标签等于书中的一个章节，提交历史将帮助您查看每个章节所做的更改。

# 安装 Meteor

安装 Meteor 就像在终端中运行以下命令一样简单：

```js
$ curl https://install.meteor.com/ | sh

```

就这样！这将安装 Meteor 命令行工具（`$ meteor`），Meteor 服务器，MongoDB 数据库和 Meteor 核心包（库）。

### 注意

所有命令行示例都在 Mac OS X 上运行和测试，可能会在 Linux 或 Windows 系统上有所不同。

## 安装 Git

要安装 Git，我建议从[`mac.github.com`](https://mac.github.com)或[`windows.github.com`](https://windows.github.com)安装 GitHub 应用程序。然后我们只需进入应用程序，点击**首选项**，并在**高级**选项卡内点击**安装命令行工具**按钮。

如果我们想手动安装 Git 并通过命令行进行设置，我们可以从[`git-scm.com`](http://git-scm.com)下载 Git 安装程序，并遵循[`help.github.com/articles/set-up-git`](https://help.github.com/articles/set-up-git)这个很好的指南。

现在，我们可以通过打开终端并运行以下命令来检查一切是否成功安装：

```js
$ git

```

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)账户中购买的所有 Packt 书籍的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便将文件直接通过电子邮件发送给您。

这将返回 Git 选项的列表。如果我们得到`command not found: git`，我们需要检查`git`二进制文件是否已正确添加到我们的`PATH`环境变量中。

如果一切顺利，我们就可以准备创建我们的第一个 Meteor 应用了。

# 创建我们的第一个应用

为了创建我们的第一个应用程序，我们打开终端，前往我们希望创建新项目的文件夹，并输入以下命令：

```js
$ cd my/developer/folder
$ meteor create my-meteor-blog

```

Meteor 现在将创建一个名为`my-meteor-blog`的文件夹。Meteor 为我们在这个文件夹内创建的 HTML、CSS 和 JavaScript 文件已经是一个完整的 Meteor 应用程序。为了看到它的实际效果，运行以下命令：

```js
$ cd my-meteor-blog
$ meteor

```

Meteor 现在将在端口`3000`上为我们启动一个本地服务器。现在，我们可以打开我们的网页浏览器，导航到`http://localhost:3000`。我们将看到应用程序正在运行。

这个应用程序除了显示一个简单的反应式示例外，没有什么作用。如果你点击**点击我**按钮，它会增加计数器：

![创建我们的第一个应用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00003.jpeg)

对于后面的示例，我们将需要 Google Chrome 的开发者工具。要打开控制台，我们可以在 Mac OS X 上按*Alt* + *command* + *I*，或者在 Chrome 的右上角点击菜单按钮，选择**更多工具**，然后选择**开发者工具**。

**开发者工具**允许我们查看我们网站的 DOM 和 CSS，以及有一个控制台，我们可以在其中与我们的网站的 JavaScript 进行交互。

## 创建一个好的文件夹结构

对于这本书，我们将从头开始构建自己的应用程序。这也意味着我们必须建立一个可持续的文件夹结构，这有助于我们保持代码的整洁。

在使用 Meteor 时，我们对文件夹结构非常灵活。这意味着我们可以把我们的文件放在任何我们想要的地方，只要它们在应用程序的文件夹内。Meteor 以不同的方式处理特定的文件夹，允许我们只在外部客户端、服务器或两者上都暴露文件。我们稍后会看看这些特定的文件夹。

但是，首先让我们通过删除我们新创建的应用程序文件夹中所有的预添加文件，并创建以下的文件夹结构：

```js
- my-meteor-blog
  - server
  - client
    - styles
    - templates
```

## 预添加样式文件

为了能完全专注于 Meteor 代码但仍然拥有一个漂亮的博客，我强烈建议从书籍的网页上下载本章伴随的代码，网址为[`packtpub.com/books/content/support/17713`](http://packtpub.com/books/content/support/17713)。它们将包含两个已经可以替换的样式文件（`lesshat.import.less`和`styles.less`），这将使你在接下来的章节中的示例博客看起来很漂亮。

你也可以直接从 GitHub 下载这些文件，网址为[`github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter1/my-meteor-blog/client/styles`](https://github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter1/my-meteor-blog/client/styles)，然后手动将它们复制到`my-meteor-blog/client/styles`文件夹中。

接下来，我们需要添加一些基本包，这样我们就可以开始构建我们的应用程序了。

# 添加基本包

Meteor 中的包是可以在我们的项目中添加的库。Meteor 包的好处是它们是开箱即用的自包含单元。它们主要提供一些模板功能，或者在项目的全局命名空间中提供额外的对象。

包还可以为 Meteor 的构建过程添加功能，比如`stylus`包，它让我们可以使用`stylus`预处理器语法来编写我们应用程序的样式文件。

对于我们的博客，我们首先需要两个包：

`less`：这是一个 Meteor 核心包，它将我们的样式文件实时编译成 CSS。

`jeeeyul:moment-with-langs`：这是一个用于日期解析和格式化的第三方库。

## 添加一个核心包

要添加`less`包，我们只需打开终端，前往我们的项目文件夹，并输入以下命令：

```js
$ meteor add less

```

现在，我们可以在我们的项目中使用任何`*.less`文件，Meteor 将在其构建过程中自动将它们编译为我们。

## 添加第三方包

要添加第三方包，我们可以在[`atmospherejs.com`](https://atmospherejs.com)上搜索包，这是 Meteor 打包系统的前端，或者使用命令行工具`$ meteor search <package name>`。

对于我们的博客，我们将需要`jeeeyul:moment-with-langs`包，它允许我们稍后简单地操作和格式化日期。

包使用作者名加上冒号进行命名空间。

要添加`moment`包，我们只需输入以下命令：

```js
$ meteor add jeeeyul:moment-with-langs

```

进程完成后，我们使用`$ meteor`重新启动应用程序，我们将在应用程序的全局命名空间中拥有`moment`对象，我们可以在接下来的章节中使用它。

如果我们想要添加某个包的特定版本，我们可以使用以下命令：

```js
$ meteor add jeeeyul:moment-with-langs@=2.8.2

```

如果您想要 1.0.0 范围内的版本（而不是 2.0.0），请使用以下命令：

```js
$ meteor add jeeeyul:moment-with-langs@1.0.0

```

要仅更新包，我们可以简单地运行以下命令：

```js
$ meteor update –-packages-only

```

此外，我们可以使用以下命令仅更新特定的包：

```js
$ meteor update jeeeyul:moment-with-langs

```

就是这样！现在我们完全准备好开始创建我们的第一个模板。您可以直接进入下一章，但请确保您回来阅读，因为我们将详细讨论 Meteor 的构建过程。

# 变量作用域

为了理解 Meteor 的构建过程及其文件夹约定，我们需要快速了解一下变量作用域。

Meteor 在提供代码之前，将每个代码文件包裹在匿名函数中。因此，使用`var`关键字声明的变量将仅在该文件的作用域内可用，这意味着这些变量无法被您应用程序中的其他任何文件访问。然而，当我们不使用这个关键字声明一个变量时，我们将其变成了一个全局可用的变量，这意味着它可以从我们应用程序中的任何文件访问。为了理解这一点，我们可以看一下以下示例：

```js
// The following files content
var myLocalVariable = 'test';
myGlobalVariable = 'test';
```

在 Meteor 的构建过程之后，前面的代码行将如下所示：

```js
(function(){
  var myLocalVariable = 'test';
  myGlobalVariable = 'test';
})();
```

这样，使用*var*创建的变量是匿名函数的局部变量，而另一个变量可以全局访问，因为它可能是在此之前在其他地方创建的。

# Meteor 的文件夹约定和加载顺序

虽然 Meteor 没有对我们的文件夹名称或结构施加限制，但是有一些命名约定可以帮助 Meteor 的构建过程确定文件需要加载的顺序。

以下表格描述了文件夹及其特定的加载顺序：

| 文件夹名称 | 加载行为 |
| --- | --- |
| `client` | 此文件仅在客户端加载。 |
| `client/compatibility` | 此文件不会被包裹在匿名函数中。这是为使用`var`声明顶级变量的库设计的。此外，这个文件夹中的文件将在客户端上的其他文件之前加载。 |
| `server` | 此文件夹中的文件仅在服务器上提供。 |
| `public` | 这个文件夹可以包含在客户端上使用的资产，例如图片、`favicon.ico` 或 `robots.txt`。公共文件夹内的文件夹和文件可以从根目录 `/` 在客户端上直接访问。 |
| `private` | 这个文件夹可以包含只有服务器上可用的资产。这些文件可以通过 `Assets` API 访问。 |
| `lib` | `lib` 文件夹内的文件和子文件夹将在其他文件之前加载，其中更深层次的 `lib` 文件夹将在其父文件夹的 `lib` 文件夹之前加载。 |
| `tests` | 此文件夹内的文件将完全不被 Meteor 触摸或加载。 |
| `packages` | 当我们想要使用本地包时，我们可以将它们添加到这个文件夹中，Meteor 将使用这些包，即使有一个与之一样的名字存在于 Meteor 的官方包系统中。（然而，我们仍然需要使用 `$ meteor add ....` 添加包） |

下面的表格描述了创建特定加载顺序的文件名：

| 文件名 | 加载行为 |
| --- | --- |
| `main.*` | 具有此名称的文件最后加载，而更深层次的文件夹则在它们的父文件夹的文件之前加载 |
| `*.*` | 表中提到的前面文件夹之外的文件将在客户端和服务器上一起加载 |

因此，我们看到 Meteor 收集了所有文件，除了 `public`、`private` 和 `tests` 中的文件。

此外，文件总是按照字母顺序加载，子文件夹中的文件会在父文件夹中的文件之前加载。

如果我们有位于 `client` 或 `server` 文件夹之外的文件，并希望确定代码应该在哪里执行，我们可以使用以下变量：

```js
if(Meteor.isClient) {
  // Some code executed on the client
}

if(Meteor.isServer) {
  // Some code executed on the server. 
}
```

我们还看到，`main.*` 文件中的代码是最后加载的。为了确保特定代码只在所有文件加载完毕且客户端的 DOM 准备就绪后加载，我们可以使用 Meteor 的 `startup()` 函数：

```js
Meteor.startup(function(){
  /*
  This code runs on the client when the DOM is ready,
  and on the server when the server process is finished starting.
  */
});
```

## 服务器上加载资产

要从服务器上的 `private` 文件夹加载文件，我们可以如下使用 `Assets` API：

```js
Assets.getText(assetPath, [asyncCallback]);
// or
Assets.getBinary(assetPath, [asyncCallback])
```

在这里，`assetPath` 是相对于 `private` 文件夹的文件路径，例如，'`subfolder/data.txt'`。

如果我们提供一个回调函数作为第二个参数，`Assets()` 方法将异步运行。因此，我们有两种获取资产文件内容的方法：

```js
// Synchronously
var myData = Assets.getText('data.txt');

// Or asynchronously
Assets.getText('data.txt', function(error, result){
  // Do somthing with the result.
  // If the error parameter is not NULL, something went wrong
});
```

### 注意

如果第一个例子返回一个错误，我们当前的服务器代码将会失败。在第二个例子中，我们的代码仍然可以工作，因为错误包含在 `error` 参数中。

既然我们已经了解了 Meteor 的基本文件夹结构，那么现在让我们简要地看看 Meteor 的命令行工具。

# Meteor 的命令行工具

既然我们已经了解了 Meteor 的构建过程和文件夹结构，我们将更详细地看看 Meteor 提供命令行工具能做什么。

正如我们在使用 `meteor` 命令时所见，我们需要在 Meteor 项目中才能执行所有操作。例如，当我们运行 `meteor add xxx`，我们就会向当前所在的项目中添加一个包。

## 更新 Meteor

如果 Meteor 发布了一个新版本，我们可以通过运行以下命令简单地更新我们的项目：

```js
$ meteor update

```

如果我们想要回到之前的版本，我们可以通过运行以下命令来实现：

```js
$ meteor update –-release 0.9.1

```

这将使我们的项目回退到发布版本 0.9.1。

## 部署 Meteor

将我们的 Meteor 应用程序部署到公共服务器，只需运行以下命令即可：

```js
$ meteor deploy my-app-name

```

这将要求我们注册一个 Meteor 开发者账户，并在[](http://my-app-name.meteor.com)部署我们的应用程序。

要了解如何部署一个 Meteor 应用程序的完整介绍，请参考第十章，*部署我们的应用程序*。

在附录中，你可以找到 Meteor 命令及其解释的完整列表。

# 总结

在本章中，我们学习了 Meteor 运行所需要的内容、如何创建一个 Meteor 应用程序，以及构建过程是如何工作的。

我们知道 Meteor 的文件结构相当灵活，但有一些特殊的文件夹，如`client`、`server`和`lib`文件夹，它们在不同的位置和顺序被加载。我们还了解了如何添加包以及如何使用 Meteor 命令行工具。

如果你想更深入地了解我们迄今为止学到的内容，请查看 Meteor 文档的以下部分：

+   [](https://www.meteor.com/projects)

+   [](https://www.meteor.com/tool)

+   [](https://docs.meteor.com/#/full/whatismeteor)

+   [](https://docs.meteor.com/#/full/structuringyourapp)

+   [](https://docs.meteor.com/#/full/usingpackages)

+   [](https://docs.meteor.com/#/full/assets)

+   [](https://docs.meteor.com/#/full/commandline)

你可以在[](https://www.packtpub.com/books/content/support/17713)找到本章的代码示例，或者在 GitHub 上找到[](https://github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter1)。

现在我们已经设置了我们项目的基本文件夹结构，我们准备开始 Meteor 的有趣部分——模板。


# 第二章： 构建 HTML 模板

在我们成功安装 Meteor 并设置好我们的文件夹结构之后，我们现在可以开始为我们的博客构建基本模板了。

在本章中，我们将学习如何构建模板。我们将了解如何显示数据以及如何使用助手函数更改某些部分。我们将查看如何添加事件、使用条件以及理解数据上下文，都在模板中。

以下是对本章将涵盖内容的概述：

+   基本模板结构

+   显示数据

+   编写模板助手函数

+   在模板中使用条件

+   数据上下文以及如何设置它们

+   嵌套模板和数据上下文继承

+   添加事件

+   构建块助手

    ### 注意

    如果你跳过第一章*Meteor 入门*直接进入本章，请从以下任一位置下载前一章的代码示例：书籍网页在[`www.packtpub.com/books/content/support/17713`](https://www.packtpub.com/books/content/support/17713)或 GitHub 仓库在[`github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter1`](https://github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter1)。

    这些代码示例还将包含所有样式文件，因此我们不必担心在过程中添加 CSS 代码。

# 在 Meteor 中编写模板

通常当我们构建网站时，我们在服务器端构建完整的 HTML。这很简单；每个页面都是在服务器上构建的，然后发送到客户端，最后 JavaScript 添加了一些额外的动画或动态行为。

这在单页应用中不是这样，因为在单页应用中，每个页面都需要已经存在于客户端浏览器中，以便可以随时显示。Meteor 通过提供存在于 JavaScript 中的模板来解决这个问题，可以在某个时刻将它们放置在 DOM 中。这些模板可以包含嵌套模板，使得轻松重用和结构化应用的 HTML 布局变得容易。

由于 Meteor 在文件和文件夹结构方面非常灵活，任何`*.html`页面都可以包含一个模板，并在 Meteor 的构建过程中进行解析。这允许我们将所有模板放在我们在第第一章*Meteor 入门*中创建的`my-meteor-blog/client/templates`文件夹中，这种文件夹结构的选择是因为它帮助我们组织模板，当应用增长时。

Meteor 的模板引擎称为**Spacebars**，它是 handlebars 模板引擎的派生。Spacebars 建立在**Blaze**之上，后者是 Meteor 的响应式 DOM 更新引擎。

### 注意

Blaze 可以使用其 API 直接生成反应式 HTML，尽管使用 Meteor 的 Spacebars 或建立在 Blaze 之上的第三方模板语言（如为 Meteor 设计的 Jade）更为方便。

有关 Blaze 的更多详细信息，请访问[`docs.meteor.com/#/full/blaze`](https://docs.meteor.com/#/full/blaze)和[`github.com/mquandalle/meteor-jade`](https://github.com/mquandalle/meteor-jade)。

使 Spacebars 如此激动人心的是它的简单性和反应性。反应式模板意味着模板的某些部分可以在底层数据变化时自动更改。无需手动操作 DOM，不一致的界面已成为过去。为了更好地了解 Meteor，我们将从为我们的应用创建的基本 HTML 文件开始：

1.  让我们在我们`my-meteor-blog/client`文件夹中创建一个`index.html`文件，并输入以下代码行：

    ```js
    <head>
      <title>My Meteor Blog</title>
    </head>
    <body>
      Hello World
    </body>
    ```

    ### 注意

    请注意，我们的`index.html`文件不包含`<html>...</html>`标签，因为 Meteor 会收集任何文件中的`<head>`和`<body>`标签，并构建自己的`index.html`文件，该文件将交付给用户。实际上，我们还可以将此文件命名为`myapp.html`。

1.  接下来，我们通过在命令行中输入以下命令来运行我们的 Meteor 应用：

    ```js
    $ cd my-meteor-blog
    $ meteor

    ```

    这将启动一个带有我们应用的 Meteor 服务器。

1.  就这样！现在我们可以打开浏览器，导航到`http://localhost:3000`，我们应该能看到**Hello World**。

这里发生的是，Meteor 将查看我们应用文件夹中可用的所有 HTML 文件，合并所有找到的`<head>`和`<body>`标签的内容，并将其作为索引文件提供给客户端。

如果我们查看我们应用的源代码，我们会看到`<body>`标签是空的。这是因为 Meteor 将`<body>`标签的内容视为自己的模板，在 DOM 加载时，将与相应的 JavaScript 模板一起注入。

### 注意

要查看源代码，不要使用开发者工具的**元素面板**，因为这将显示 JavaScript 执行后的源代码。在 Chrome 中，右键单击网站，而选择**查看页面源代码**。

我们还会看到 Meteor 已经在我们的`<head>`标签中链接了各种各样的 JavaScript 文件。这些都是 Meteor 的核心包和我们的第三方包。在生产环境中，这些文件将被合并成一体。为了看到这个效果，打开终端，使用*Ctrl* + *C*退出我们运行中的 Meteor 服务器，并运行以下命令：

```js
$ meteor --production

```

如果我们现在查看源代码，我们会看到只有一个神秘的 JavaScript 文件被链接。

接下来，最好是通过简单地退出 Meteor 并再次运行`meteor`命令回到我们的开发者模式，因为这样在文件发生变化时可以更快地重新加载应用。

# 构建基本模板

现在，让我们通过在我们`my-meteor-blog/client/templates`文件夹中创建一个名为`layout.html`的文件，将基本模板添加到我们的博客中。这个模板将作为我们博客布局的包装模板。要构建基本模板，请执行以下步骤：

1.  在刚刚创建的`layout.html`中添加以下代码行：

    ```js
    <template name="layout">
      <header>
        <div class="container">
          <h1>My Meteor Single Page App</h1>
          <ul>
            <li>
              <a href="/">Home</a>
            </li>
            <li>
              <a href="/about">About</a>
            </li>
          </ul>
        </div>
      </header>

      <div class="container">
        <main>
        </main>
      </div>
    </template>
    ```

1.  接下来，我们将创建主页模板，稍后列出我们所有的博客文章。在`layout.html`相同的模板文件夹中，我们将创建一个名为`home.html`的文件，并包含以下代码行：

    ```js
    <template name="home">
    {{#markdown}}
    ## Welcome to my Blog
    Here I'm talking about my latest discoveries from the world of JavaScript.
    {{/markdown}}
    </template>
    ```

1.  下一个文件将是一个简单的**关于**页面，我们将其保存为`about.html`，并包含以下代码片段：

    ```js
    <template name="about">
    {{#markdown}}
    ## About me
    Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod
    tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam,
    quis nostrud **exercitation ullamco** laboris nisi ut aliquip ex ea commodo
    consequat.

    Link to my facebook: [facebook.com][1]

    [1]: http://facebook.com
    {{/markdown}}
    </template>
    ```

    正如您所见，我们使用了一个`{{#markdown}}`块助手来包装我们的文本。大括号是 Blaze 用来将逻辑带到 HTML 的处理程序语法。`{{#markdown}}...{{/markdown}}`块在模板渲染时将所有的 Markdown 语法转换成 HTML。

    ### 注意

    由于 Markdown 语法将缩进解释为代码，因此 Markdown 文本不能像我们对 HTML 标签那样进行缩进。

1.  为了能够使用`{{#markdown}}`块助手，我们首先需要将`markdown`核心包添加到我们的应用程序中。为此，我们使用*Ctrl* + *C*在终端中停止正在运行的应用程序，并输入以下命令：

    ```js
    $ meteor add markdown

    ```

1.  现在我们可以再次运行`meteor`命令来启动我们的服务器。

然而，当我们现在打开浏览器时，我们仍然会看到**Hello World**。那么我们如何使我们的模板现在变得可见呢？

# 添加模板和部分

为了在应用程序中显示主页模板，我们需要打开之前创建的`index.html`，并执行以下步骤：

1.  我们将`Hello World`替换为以下模板包含助手：

    ```js
    {{> layout}}
    ```

1.  如果我们现在回到浏览器，我们会看到文本消失了，而我们之前创建的`layout`模板以及其标题和菜单出现了。

1.  为了完成页面，我们需要在`layout`模板中显示`home`模板。我们只需在`layout`模板的`main`部分添加另一个模板包含助手，如下所示：

    ```js
    <main>
      {{> home}}
    </main>
    ```

1.  如果我们回到浏览器，我们应该看到以下截图：![Adding templates and partials](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00004.jpeg)

如果我们现在将`{{> home}}`替换为`{{> about}}`，我们将会看到我们的`about`模板。

# 使用模板助手显示数据

每个模板都可以有函数，这些函数被称为`template`助手，它们可以在模板及其子模板中使用。

除了我们自定义的助手函数外，还有三个回调函数在模板创建、渲染和销毁时被调用。要使用模板助手显示数据，请执行以下步骤：

1.  为了看到这三个回调函数的作用，让我们创建一个名为`home.js`的文件，并将其保存到我们的`my-meteor-blog/client/templates/`文件夹中，并包含以下代码片段：

    ```js
    Template.home.created = function(){
      console.log('Created the home template');
    };
    Template.home.rendered = function(){
      console.log('Rendered the home template');
    };

    Template.home.destroyed = function(){
      console.log('Destroyed the home template');
    };
    ```

    如果我们现在打开浏览器的控制台，我们会看到前两个回调被触发。最后一个只有在动态移除模板时才会触发。

1.  为了在`home`模板中显示数据，我们将创建一个助手函数，该函数将返回一个简单的字符串，如下所示：

    ```js
    Template.home.helpers({
      exampleHelper: function(){
        return 'This text came from a helper with some <strong>HTML</strong>.';
      }
    });
    ```

1.  现在如果我们去我们的`home.html`文件，在`{{markdown}}`块助手之后添加`{{exampleHelper}}`助手，并保存文件，我们将在浏览器中看到出现的字符串，但我们注意到 HTML 被转义了。

1.  为了使 Meteor 正确渲染 HTML，我们可以简单地将双花括号替换为三花括号，如下代码行所示，Blaze 不会让 HTML 转义：

    ```js
    {{{exampleHelper}}}
    ```

    ### 注意

    注意，在我们的大多数模板助手中，我们*不应该*使用三花括号`{{{...}}}`，因为这将打开 XSS 和其他攻击的大门。只有当返回的 HTML 安全可渲染时才使用它。

1.  此外，我们可以使用双花括号返回未转义的 HTML，但我们需要返回通过`SpaceBars.SafeString`函数传递的字符串，如下例所示：

    ```js
    Template.home.helpers({
      exampleHelper: function(){
        return new Spacebars.SafeString('This text came from a helper with some <strong>HTML</strong>.');
      }
    });
    ```

# 为模板设置数据上下文

+   现在我们已经有了`contextExample`模板，我们可以通过传递一些数据将其添加到我们的`home`模板中，如下所示：

    ```js
    {{> contextExample someText="I was set in the parent template's helper, as an argument."}}
    ```

    这将在`contextExample`模板中显示文本，因为我们使用`{{someText}}`来显示它。

    ### 提示

    记住，文件名实际上并不重要，因为 Meteor 会无论如何收集并连接它们；然而，模板名称很重要，因为我们用这个来引用模板。

    在 HTML 中设置上下文不是非常动态，因为它是有硬编码的。为了能够动态地改变上下文，最好使用`template`助手函数来设置它。

    +   为此，我们必须首先将助手添加到我们的`home`模板助手中，该助手返回数据上下文，如下所示：

    ```js
    Template.home.helpers({
      // other helpers ...
      dataContextHelper: function(){
        return {
          someText: 'This text was set using a helper of the parent template.',
          someNested: {
            text: 'That comes from "someNested.text"'
          }
        };
      }
    });
    ```

    +   现在我们可以将此助手作为数据上下文添加到我们的`contextExample`模板包含助手中，如下所示：

    ```js
    {{> contextExample dataContextHelper}}
    ```

    +   另外，为了显示我们返回的嵌套数据对象，我们可以在`contextExample`模板中使用 Blaze 点语法，通过在模板中添加以下代码行来实现：

    ```js
    <p>{{someNested.text}}</p>
    ```

这现在将显示`someText`和`someNested.text`，后者是由我们的助手函数返回的。

## 使用`{{#with}}`块助手

设置数据上下文的一种另一种方法是使用`{{#with}}`块助手。以下代码片段与之前使用助手函数的包含助手具有相同的结果：

```js
{{#with dataContextHelper}}
  {{> contextExample}}
{{/with}}
```

我们甚至在浏览器中得到同样的结果，当我们不使用子模板，只是将`contextExample`模板的内容添加到`{{#with}}`块助手中，如下所示：

```js
{{#with dataContextHelper}}
  <p>{{someText}}</p>
  <p>{{someNested.text}}</p>
{{/with}}
```

# 模板助手和模板回调中的"this"

在 Meteor 中，模板助手中的`this`在模板回调（如`created()`、`rendered()`和`destroyed()`）中的使用方式不同。

如前所述，模板有三个回调函数，在模板的不同状态下触发：

+   `created`：当模板初始化但尚未插入 DOM 时触发

+   `rendered`：当模板及其所有子模板附加到 DOM 时触发

+   `destroyed`：当模板从 DOM 中移除并在模板实例被销毁之前触发

在这些回调函数中，`this` 指的是当前模板实例。实例对象可以访问模板的 DOM 并带有以下方法：

+   `this.$(selectorString)`：这个方法找到所有匹配 `selectorString` 的元素，并返回这些元素的 jQuery 对象。

+   `this.findAll(selectorString)`：这个方法找到所有匹配 `selectorString` 的元素，但返回普通的 DOM 元素。

+   `this.find(selectorString)`：这个方法找到匹配 `selectorString` 的第一个元素，并返回一个普通的 DOM 元素。

+   `this.firstNode`：这个对象包含模板中的第一个元素。

+   `this.lastNode`：这个对象包含模板中的最后一个元素。

+   `this.data`：这个对象包含模板的数据上下文

+   `this.autorun(runFunc)`：一个在模板实例被销毁时停止的反应式 `Tracker.autorun()` 函数。

+   `this.view`：这个对象包含这个模板的 `Blaze.View` 实例。`Blaze.View` 是反应式模板的构建块。

在辅助函数内部，`this` 仅指向当前的数据上下文。

为了使这些不同的行为变得可见，我们将查看一些示例：

+   当我们想要访问模板的 DOM 时，我们必须在渲染回调中进行，因为只有在这一点上，模板元素才会出现在 DOM 中。为了看到它的工作原理，我们按照以下方式编辑我们的 `home.js` 文件：

    ```js
    Template.home.rendered = function(){
      console.log('Rendered the home template');

     this.$('p').html('We just replaced that text!');
    };
    ```

    这将用我们设置的字符串替换由 `{{#markdown}}` 块辅助函数创建的第一个 `<p>` 标签。现在当我们检查浏览器时，我们会发现包含我们博客介绍文本的第一个 `<p>` 标签已经被替换。

+   对于下一个示例，我们需要为我们的 `contextExample` 模板创建一个额外的模板 JavaScript 文件。为此，我们在 `templates` 文件夹中创建一个名为 `examples.js` 的新文件，并使用以下代码片段保存它：

    ```js
    Template.contextExample.rendered = function(){
      console.log('Rendered Context Example', this.data);
    };

    Template.contextExample.helpers({
      logContext: function(){
        console.log('Context Log Helper', this);
      }
    });
    ```

    这将把渲染回调以及一个名为 `logContext` 的辅助函数添加到我们的 `contextExample` 模板辅助函数中。为了使这个辅助函数运行，我们还需要将其添加到我们的 `contextExample` 模板中，如下所示：

    ```js
    <p>{{logContext}}</p>
    ```

当我们现在回到浏览器的控制台时，我们会发现数据上下文对象已经被返回给所有我们的已渲染的 `contextTemplates` 模板的 `rendered` 回调和辅助函数。我们还可以看到辅助函数将在渲染回调之前运行。

### 注意

如果您需要从模板辅助函数内部访问模板的实例，您可以使用 `Template.instance()` 来获取它。

现在让我们使用事件使我们的模板变得交互式。

# 添加事件

为了使我们的模板更具动态性，我们将添加一个简单的事件，这将使之前创建的 `logContext` 辅助函数重新反应式地运行。

首先，然而，我们需要在我们的 `contextExample` 模板中添加一个按钮：

```js
<button>Get some random number</button>
```

为了捕获点击事件，打开 `examples.js` 并添加以下 `event` 函数：

```js
Template.contextExample.events({
  'click button': function(e, template){
    Session.set('randomNumber', Math.random(0,99));
  }
});
```

这将设置一个名为 `randomNumber` 的会话变量到一个随机数。

### 注意

在下一章中，我们将深入讨论会话。现在，我们只需要知道当会话变量发生变化时，所有使用`Session.get('myVariable')`获取该会话变量的函数将重新运行。

为了看到这个效果，我们将向`logContext`助手添加一个`Session.get()`调用，并像以下方式返回先前设置的随机数：

```js
Template.contextExample.helpers({
  logContext: function(){
    console.log('Context Log Helper',this);

    return Session.get('randomNumber');
  }
});
```

如果我们打开浏览器，我们会看到**获取一些随机数**按钮。当我们点击它时，我们会看到一个随机数出现在按钮上方。

### 注意

当我们在我们`home`模板中多次使用`contextTemplates`模板时，我们会发现该模板助手每次都会显示相同的随机数。这是因为会话对象将重新运行其所有依赖项，其中所有依赖项都是`logHelper`助手的实例。

既然我们已经介绍了模板助手，那么让我们创建一个自定义的块助手。

# 块助手

```js
example.html file:
```

```js
<template name="blockHelperExample">
  <div>
    <h1>My Block Helper</h1>
    {{#if this}}
      <p>Content goes here: {{> Template.contentBlock}}</p>
    {{else}}
      <p>Else content here: {{> Template.elseBlock}}</p>
    {{/if}}
  </div>
</template>
```

`{{> Template.contentBlock}}`是为块内容预定义的占位符。同样适用于`{{> Template.elseBlock}}`。

当`this`（在这个例子中，我们使用模板的上下文作为一个简单的布尔值）为`true`时，它将显示给定的`Template.contentBlock`。否则，它将显示`Template.elseBlock`的内容。

为了看到我们可以如何将最近创建的模板作为块助手使用，请查看以下示例，我们可以将其添加到`home`模板中：

```js
{{#blockHelperExample true}}
  <span>Some Content</span>
{{else}}
  <span>Some Warning</span>
{{/blockHelperExample}}
```

现在我们应该看到以下截图：

![块助手](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00005.jpeg)

现在我们将`true`更改为`false`，我们传递给`{{#blockHelperExample}}`，我们应该看到`{{else}}`之后的内容。

我们还可以使用助手函数来替换布尔值，这样我们就可以动态地切换块助手。此外，我们可以传递键值对参数，并通过它们的键在块助手模板内部访问它们，如下面的代码示例所示：

```js
{{#blockHelperExample myValue=true}}
...
{{/blockHelperExample}}
```

我们还可以按照以下方式通过其名称访问给定参数：

```js
<template name="blockHelperExample">
  <div>
    <h1>My Block Helper</h1>
    {{#if myValue}}
    ...
    {{/if}}
  </div>
</template>
```

### 注意

请注意，块内容的上下文将是出现块的模板的上下文，而不是块助手模板本身的上下文。

块助手是一种强大的工具，因为它们允许我们编写自包含组件，当打包成包时，其他可以使用它们作为即插即用的功能。这个特性有潜力允许一个充满活力的市场，就像我们在 jQuery 插件市场中看到的那样。

# 列出帖子

此模板将用于在主页上显示每个帖子。

+   为了使其出现，我们需要在`home`模板中添加一个`{{#each}}`助手，如下所示：

    ```js
    {{#each postsList}}
      {{> postInList}}
    {{/each}}
    ```

    当我们传递给`{{#each}}`块助手时，如果`postsList`助手返回一个数组，`{{#each}}`的内容将针对数组中的每个项目重复，将数组项目设置为数据上下文。

    +   为了看到这个效果，我们在`home.js`文件中添加了`postsList`助手，如下所示：

    ```js
    Template.home.helpers({
      // other helpers ...
      postsList: function(){
        return [
          {
            title: 'My Second entry',
            description: 'Borem sodum color sit amet, consetetur sadipscing elitr.',
            author: 'Fabian Vogelsteller',
            timeCreated: moment().subtract(3, 'days').unix()
          },
          {
            title: 'My First entry',
            description: 'Lorem ipsum dolor sit amet, consetetur sadipscing elitr.',
            author: 'Fabian Vogelsteller',
            timeCreated: moment().subtract(7, 'days').unix()
          }
        ];
      }
    });
    ```

    +   正如我们可以看到的，我们返回一个数组，每个项目都是一个包含我们文章数据上下文的对象。对于 `timeCreated`，我们使用我们之前添加的第三方包的 `moment` 函数。这将生成过去几天的时间戳。如果我们现在去浏览器，我们会看到列出的两篇文章，如下截图所示：![列出文章](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00006.jpeg)*   为了以正确的格式显示我们的文章项中的 `timeCreated`，我们需要创建一个助手函数来格式化时间戳。然而，因为我们想要在后面的其他模板中使用这个助手，我们需要让它成为一个全局助手，任何模板都可以访问。为此，我们创建一个名为 `template-helpers.js` 的文件，并将其保存到我们的 `my-meteor-blog/client` 文件夹中，因为它不属于任何特定的模板.*   为了注册一个全局助手，我们可以使用 Meteor 的 `Template.registerHelper` 函数：

    ```js
    Template.registerHelper('formatTime', function(time, type){
      switch(type){
        case 'fromNow': 
          return moment.unix(time).fromNow();
        case 'iso':
          return moment.unix(time).toISOString();
        default:
          return moment.unix(time).format('LLLL');
      }
    });
    ```

    +   现在，我们只需通过用以下代码段替换 `postInList` 模板的底部内容来添加助手：

    ```js
    <div class="footer">
      <time datetime="{{formatTime timeCreated "iso"}}">Posted {{formatTime timeCreated "fromNow"}} by {{author}}</time>
    </div>
    ```

现在，如果我们保存这两个文件并回到浏览器，我们会看到博客文章底部添加了一个相对日期。这之所以有效，是因为我们把时间和一个类型字符串传递给助手，如下所示：

```js
{{formatTime timeCreated "fromNow"}}
```

助手然后使用一个 `moment` 函数返回格式化的日期。

有了这个全局助手，我们现在可以格式化任何 Unix 时间戳，在任何模板中将时间转换为相对时间、ISO 时间字符串和标准日期格式（使用 LLLL 格式，转换为 1986 年 9 月 4 日星期四晚上 8:30）。

既然我们已经使用了 `{{#with}}` 和 `{{#each}}` 块助手，让我们来看看 Blaze 使用的其他默认助手和语法。

# Spacebars 语法

来总结一下 Spacebars 的语法：

| 助手 | 描述 |
| --- | --- |
| `{{myProperty}}` | 模板助手可以是模板数据上下文中的属性或模板助手函数。如果存在具有相同名称的助手函数和属性，模板助手将使用助手函数。 |
| `{{> myTemplate}}` | 包含助手用于模板，并且总是期待一个模板对象或者 null。 |
| `{{> Template.dynamic template=templateName [data=dataContext]}}` | 使用 `{{> Template.dynamic ...}}` 助手，你可以通过提供返回模板名称的模板助手来动态渲染模板。当助手重新运行并返回不同的模板名称时，它将用新模板替换此位置的模板。 |
| `{{#myBlockHelper}}`...`{{/myBlockHelper}}` | 包含 HTML 和 Spacebars 语法的块助手。 |

默认情况下，Spacebars 带有以下四个默认块助手：

+   `{{#if}}..{{/if}}`

+   `{{#unless}}..{{/unless}}`

+   `{{#with}}..{{/with}}`

+   `{{#each}}..{{/each}}`

`{{#if}}` 块助手允许我们创建简单的条件，如下所示：

```js
{{#if myHelperWhichReturnsABoolean}}
  <h1>Show me this</h1>
{{else}}
  <strong>If not<strong> show this.
{{/if}}
```

`{{#unless}}` 块助手的工作方式与 `{{#if}}` 相同，但逻辑相反。

如前所见，`{{#with}}`块将为其内容和包含的模板设置新的数据上下文，而`{{#each}}`块帮助器将多次渲染，为每次迭代设置不同的数据上下文。

## 访问父数据上下文

为了完成对 Spacebars 语法的探索，让我们更仔细地看看我们用来显示数据的模板帮助器语法。正如我们已经在前面看到的，我们可以使用双花括号语法显示数据，如下所示：

```js
{{myData}}
```

在此帮助器内部，我们可以使用点语法访问对象属性：

```js
{{myObject.myString}}
```

我们还可以使用路径样式的语法访问父数据上下文：

```js
{{../myParentsTemplateProperty}}
```

此外，我们可以移动更多的上下文：

```js
{{../../someParentProperty}}
```

这一特性使我们能够非常灵活地设置数据上下文。

### 注意

如果我们想从一个模板帮助器内部做同样的事情，我们可以使用模板 API 的`Template.parentData(n)`，其中`n`是要访问父模板数据上下文所需的步骤数。

`Template.parentData(0)`与`Template.currentData()`相同，或者如果我们处于模板帮助器中，则为`this`。

## 向帮助器传递数据

向帮助器传递数据可以通过两种不同的方式完成。我们可以如下向帮助器传递参数：

```js
{{myHelper "A String" aContextProperty}}
```

然后，我们可以在帮助器中按照以下方式访问它：

```js
Template.myTemplate.helpers({
   myHelper: function(myString, myObject){
     // And we get:
     // myString = 'aString'
     // myObject = aContextProperty
   }
});
```

除了这个，我们还可以以键值的形式传递数据：

```js
{{myHelper myString="A String" myObject=aDataProperty}}
```

然而，这次我们需要按照以下方式访问它们：

```js
Template.myTemplate.helpers({
   myHelper: function(Parameters){
     // And we can access them:
     // Parameters.hash.myString = 'aString'
     // Parameters.hash.myObject = aDataProperty
   }
});
```

请注意，块帮助器和包含帮助器的行为不同，因为它们总是期望对象或键值作为参数：

```js
{{> myTemplate someString="I will be available inside the template"}}

// Or

{{> myTemplate objectWithData}}
```

如果我们想在帮助器函数中使用它，那么我们需要对传递的参数进行类型转换，如下所示：

```js
Template.myBlock.helpers({
   doSomethingWithTheString: function(){
     // Use String(this), to get the string
     return this;
   }
});
```

此外，我们还可以在我们的块帮助器模板中简单地显示字符串，使用`{{Template.contentBlock}}`如下所示：

```js
<template name="myBlock">
  <h1>{{this}}</h1>
  {{Template.contentBlock}}
</template>
```

我们还可以将另一个模板帮助器作为参数传递给包含或块帮助器，如下例所示：

```js
{{> myTemplate myHelperWhichReturnsAnObject "we pass a string and a number" 300}}
```

尽管向模板帮助器传递数据和向包含/块帮助器传递数据略有不同，但在生成帮助器时参数可以非常灵活。

# 总结

反应式模板是 Meteor 最令人印象深刻的功能之一，一旦我们习惯了它们，我们可能就不会再回到手动操作 DOM 了。

阅读这一章之后，我们应该知道如何在 Meteor 中编写和使用模板。我们还应该理解其基本语法以及如何添加模板。

我们看到了如何在模板中访问和设置数据，以及如何使用帮助器。我们学习了不同类型的帮助器，例如包含帮助器和块帮助器。我们还构建了我们自己的自定义块帮助器并使用了 Meteor 的默认帮助器。

我们了解到模板有三种不同的回调，分别用于模板创建、渲染和销毁时。

我们学习了如何向帮助器传递数据，以及这在普通帮助器和块帮助器之间的区别。

为了深入了解，请查看以下文档：

+   [`docs.meteor.com/#/full/templates_api`](https://docs.meteor.com/#/full/templates_api)

+   [`www.meteor.com/blaze`](https://www.meteor.com/blaze)

+   [`docs.meteor.com/#/full/blaze`](https://docs.meteor.com/#/full/blaze)

+   [`atmospherejs.com/meteor/spacebars`](https://atmospherejs.com/meteor/spacebars)

+   [`momentjs.com`](http://momentjs.com)

你可以在这个章节找到代码示例，网址为[`www.packtpub.com/books/content/support/17713`](https://www.packtpub.com/books/content/support/17713)，或者在 GitHub 上查看[`github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter2`](https://github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter2)。

关于模板的新知识让我们准备好向我们的数据库添加数据，并看看我们如何在主页上显示它。


# 第三章：存储数据和处理集合

在上一章中，我们学习了如何构建模板并在其中显示数据。我们建立了我们应用程序的基本布局并在首页列出了一些后续示例。

在本章中，我们将持续向服务器上的数据库添加后续示例。我们将学习如何稍后在客户端访问这些数据，以及 Meteor 如何在客户端和服务器之间同步数据。

在本章中，我们将涵盖以下主题：

+   在 Meteor 中存储数据

+   创建集合

+   向集合中添加数据

+   从集合中查询数据

+   在集合中更新数据

+   “无处不在的数据库”意味着什么

+   服务器数据库与客户端数据库的区别

    ### 注意

    如果你直接跳到这一章并想跟随示例，请从以下任一位置下载上一章的代码示例：[`www.packtpub.com/books/content/support/17713`](https://www.packtpub.com/books/content/support/17713) 或 [`github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter2`](https://github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter2)。

    这些代码示例还将包含所有样式文件，因此我们无需担心在过程中添加 CSS 代码。

# Meteor 和数据库

Meteor 目前默认使用 MongoDB 在服务器上存储数据，尽管还计划有用于关系型数据库的驱动程序。

### 注意

如果你有冒险精神，可以尝试一下社区构建的 SQL 驱动程序，例如来自 [`atmospherejs.com/numtel/mysql`](https://atmospherejs.com/numtel/mysql) 的 `numtel:mysql` 包。

MongoDB 是一个**NoSQL** 数据库。这意味着它基于平面文档结构，而不是关系表结构。它对文档的处理方式使它成为 JavaScript 的理想选择，因为文档是用 BJSON 编写的，这与 JSON 格式非常相似。

Meteor 采用了一种*无处不在的数据库*的方法，这意味着我们有一个相同的 API 来在客户端和服务器上查询数据库。然而，当我们在客户端查询数据库时，我们只能访问我们*发布*给客户端的数据。

**MongoDB** 使用一种称为**集合**的数据结构，这在 SQL 数据库中相当于一个表。集合包含文档，每个文档都有自己的唯一 ID。这些文档是类似 JSON 的结构，可以包含具有值的属性，甚至是多维属性，如下所示：

```js
{
  "_id": "W7sBzpBbov48rR7jW",
  "myName": "My Document Name",
  "someProperty": 123456,
  "aNestedProperty": {
    "anotherOne": "With another string"
  }
}
```

这些集合用于在服务器上的 MongoDB 以及客户端的`minimongo`集合中存储数据，后者是一个模仿真实 MongoDB 行为的内存数据库。

### 注意

我们将在本章末尾更多地讨论`minimongo`。

MongoDB API 允许我们使用简单的基于 JSON 的查询语言从集合中获取文档。我们可以传递其他选项，只询问*特定字段*或*对返回的文档进行排序*。这些功能在客户端尤其强大，可以以各种方式显示数据。

# 设置集合

为了亲眼看到这一切，让我们通过创建我们的第一个集合来开始。

我们在`my-meteor-blog`文件夹内创建一个名为`collections.js`的文件。我们需要在根目录中创建它，这样它才能在客户端和服务器上都可用。现在让我们将以下代码行添加到`collections.js`文件中：

```js
Posts = new Mongo.Collection('posts');
```

这将使`Posts`变量在全球范围内可用，因为我们没有使用`var`关键字，这会将它们限制为该文件的范围。

`Mongo.Collection`是查询数据库的 API，它带有以下基本方法：

+   `insert`：此方法用于将文档插入数据库

+   `update`：此方法用于更新文档或它们的部分内容

+   `upsert`：此方法用于插入或更新文档或它们的部分内容

+   `remove`：此方法用于从数据库中删除文档

+   `find`：此方法用于查询数据库中的文档

+   `findOne`：此方法用于只返回第一个匹配的文档

# 添加帖子示例

要查询数据库中的帖子，我们需要添加一些帖子示例。这必须在服务器上完成，因为我们希望它们持久存在。要添加一个示例帖子，请执行以下步骤：

1.  我们在`my-meteor-blog/server`文件夹内创建一个名为`main.js`的文件。在这个文件中，我们将使用`Meteor.startup()`函数在服务器启动时执行代码。

1.  我们然后添加帖子示例，但只有在集合为空时。为了防止这种情况，我们每次重启服务器时都添加它们，如下所示：

    ```js
    Meteor.startup(function(){

      console.log('Server started');

      // #Storing Data -> Adding post examples
      if(Posts.find().count() === 0) {

        console.log('Adding dummy posts');
        var dummyPosts = [
          {
            title: 'My First entry',
            slug: 'my-first-entry',
            description: 'Lorem ipsum dolor sit amet.',
            text: 'Lorem ipsum dolor sit amet...',
            timeCreated: moment().subtract(7,'days').unix(),
            author: 'John Doe'
          },
          {
            title: 'My Second entry',
            slug: 'my-second-entry',
            description: 'Borem ipsum dolor sit.',
            text: 'Lorem ipsum dolor sit amet...',
            timeCreated: moment().subtract(5,'days').unix(),
            author: 'John Doe'
          },
          {
            title: 'My Third entry',
            slug: 'my-third-entry',
            description: 'Dorem ipsum dolor sit amet.',
            text: 'Lorem ipsum dolor sit amet...',
            timeCreated: moment().subtract(3,'days').unix(),
            author: 'John Doe'
          },
          {
            title: 'My Fourth entry',
            slug: 'my-fourth-entry',
            description: 'Sorem ipsum dolor sit amet.',
            text: 'Lorem ipsum dolor sit amet...',
            timeCreated: moment().subtract(2,'days').unix(),
            author: 'John Doe'
          },
          {
            title: 'My Fifth entry',
            slug: 'my-fifth-entry',
            description: 'Korem ipsum dolor sit amet.',
            text: 'Lorem ipsum dolor sit amet...',
            timeCreated: moment().subtract(1,'days').unix(),
            author: 'John Doe'
          }
        ];
        // we add the dummyPosts to our database
        _.each(dummyPosts, function(post){
          Posts.insert(post);
        });
      }
    });
    ```

现在，当我们检查终端时，我们应该看到与以下屏幕截图类似的某些内容：

![添加帖子示例](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00007.jpeg)

### 注意

我们还可以使用 Mongo 控制台添加虚拟数据，而不是在代码中编写它们。

要使用 Mongo 控制台，我们首先使用`$ meteor`启动 Meteor 服务器，然后在第二个终端运行`$ meteor mongo`，这将我们带到 Mongo shell。

在这里，我们可以简单地使用 MongoDB 的语法添加文档：

```js
db.posts.insert({title: 'My First entry',
 slug: 'my-first-entry',
 description: 'Lorem ipsum dolor sit amet.',
 text: 'Lorem ipsum dolor sit amet...',
 timeCreated: 1405065868,
 author: 'John Doe'
}
)

```

# 查询集合

当我们保存我们的更改时，服务器确实重新启动了。在此阶段，Meteor 在我们的数据库中添加了五个帖子示例。

### 注意

如果服务器没有重新启动，这意味着我们在代码中的某个地方犯了语法错误。当我们手动重新加载浏览器或检查终端时，我们会看到 Meteor 给出的错误，然后我们可以进行修复。

如果我们数据库中出了什么问题，我们总是可以使用终端中的`$ meteor reset`命令来重置它。

我们只需在浏览器中打开控制台并输入以下命令即可查看这些帖子：

```js
Posts.find().fetch();

```

这将返回一个包含五个项目的数组，每个项目都是我们的示例帖子之一。

为了在我们前端页面上列出这些新插入的帖子，我们需要在 `home.js` 文件中替换我们 `postsList` 帮助器的內容，如下面的代码行所示：

```js
Template.home.helpers({
  postsList: function(){
    return Posts.find({}, {sort: {timeCreated: -1}});
  }
});
```

正如我们所看到的，我们直接在帮助器中返回了集合游标。这个返回值然后传递到我们的 `home` 模板中的 `{{#each}}` 块帮助器，该帮助器将在渲染 `postInList` 模板时遍历每个帖子。

### 注意

请注意，`Posts.find()` 返回一个游标，在 `{{#each}}` 块帮助器中使用时效率更高，而 `Posts.find().fetch()` 将返回一个包含文档对象的数组。使用 `fetch()`，我们可以在返回之前操纵文档。

我们将一个选项对象作为 `find()` 函数的第二个参数。我们传递的选项将根据 `timeCreated` 进行排序，并使用 `-1`。`-1` 的值意味着它将按降序排序（`1` 表示升序）。

现在，当我们查看我们的浏览器时，我们会看到我们的五篇帖子全部列出，如下面的截图所示：

![查询集合](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00008.jpeg)

# 更新集合

现在我们已经知道如何插入和获取数据，让我们来看看如何在我们的数据库中更新数据。

正如我们之前所见，我们可以使用浏览器的光标来玩转数据库。对于我们接下来的例子，我们将只使用控制台来了解当我们在数据更改时，Meteor 如何反应性地改变模板。

为了能够在我们的数据库中编辑一篇帖子，我们首先需要知道其条目的 `_id` 字段。为了找出这个，我们需要输入以下命令：

```js
Posts.find().fetch();

```

这将返回 `Posts` 集合中的所有文档，因为我们没有传递任何特定的查询对象。

在返回的数组中，我们需要查看最后一个项目，标题为 **My Fifth entry** 的项目，并使用 *Cmd* + *C*（或者如果我们在 Windows 或 Linux 上，使用 *Ctrl* + *C*）将 `_id` 字段复制到剪贴板。

### 注意

我们也可以简单地使用 `Posts.findOne()`，这将给我们找到的第一个文档。

现在我们已经有了 `_id`，我们可以通过输入以下命令简单地更新我们第五篇帖子的标题：

```js
Posts.update('theCopied_Id', {$set: {title: 'Wow the title changed!'}});

```

一旦我们执行这个命令，我们就会注意到第五篇帖子的标题已经变成了我们新的标题，如果我们现在重新加载页面，我们会看到标题保持不变。这意味着更改已经持久地保存到了数据库中。

为了看到 Meteor 的响应性跨客户端，打开另一个浏览器窗口，导航到 `http://localhost:3000`。现在我们再次通过执行以下命令更改我们的标题，我们会看到所有客户端实时更新：

```js
Posts.update('theCopied_Id', {$set: {title: 'Changed the title again'}});

```

# 数据库无处不在

在 Meteor 中，我们可以使用浏览器的控制台来更新数据，这意味着我们可以从客户端更新数据库。这之所以有效，是因为 Meteor 会自动将这些更改同步到服务器，并相应地更新数据库。

这之所以发生，是因为我们的项目默认添加了 `autopublish` 和 `insecure` 核心包。`autopublish` 包会自动将所有文档发布给每个客户端，而 `insecure` 包允许每个客户端通过其 `_id` 字段更新数据库记录。显然，这对于原型设计来说很好，但对于生产环境来说是不切实际的，因为每个客户端都可以操作我们的数据库。

如果我们移除了 `insecure` 包，我们将需要添加“允许和拒绝”规则来确定客户端可以更新哪些内容以及不可以更新哪些内容；否则，所有更新都将被拒绝。我们将在后面的章节中查看这些规则的设置，但现在这个包对我们很有用，因为我们可以立即操作数据库。

在下一章中，我们将了解如何手动将某些文档发布给客户端。我们将从移除 `autopublish` 包开始。

# 客户端与服务器集合之间的差异

Meteor 采用了一种*无处不在的数据库*方法。这意味着它为客户端和服务器端提供了相同的 API。数据流动是通过发布订阅模型来控制的。

服务器上运行着真正的 MongoDB 数据库，它负责持久化存储数据。在客户端，Meteor 包含一个名为 `minimongo` 的包，它是一个纯内存数据库，模仿了 MongoDB 的大部分查询和更新功能。

每次客户端连接到其 Meteor 服务器时，Meteor 都会下载客户端订阅的文档并将它们存储在其本地的 `minimongo` 数据库中。从这里，它们可以在模板中显示，或者由函数处理。

当客户端更新一个文档时，Meteor 会将其同步回服务器，在那里它将穿过任何允许/拒绝函数，然后被永久存储在数据库中。这也适用于反向操作；当服务器端数据库中的文档发生变化时，它将自动同步到所有订阅它的客户端，使每个连接的客户端保持最新。

# 概要

在本章中，我们学习了如何在 Meteor 的 MongoDB 数据库中持久化存储数据。我们还看到了如何查询集合和更新文档。我们理解了“无处不在的数据库”方法意味着什么，以及 Meteor 如何使每个客户端保持最新。

为了更深入地了解 MongoDB 以及如何查询和更新集合，请查看以下资源：

+   [Meteor 完整栈数据库驱动](https://www.meteor.com/full-stack-db-drivers)

+   [Meteor 迷你数据库](https://www.meteor.com/mini-databases)

+   [Meteor 文档：集合](https://docs.meteor.com/#/full/collections)

+   [MongoDB 手册：CRUD 简介](http://docs.mongodb.org/manual/core/crud-introduction/)

+   [MongoDB 手册：查询操作符](http://docs.mongodb.org/manual/reference/operator/query/)

你可以在这个章节找到代码示例，网址为[`www.packtpub.com/books/content/support/17713`](https://www.packtpub.com/books/content/support/17713)，或者在 GitHub 上查看[`github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter3`](https://github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter3)。

在下一章中，我们将了解如何使用发布和订阅控制数据流，从而只将必要的文档发送给客户端。


# 第四章：控制数据流

在前一章节中，我们学习了如何将数据持久化地存储在我们的数据库中。在本章中，我们将了解如何告诉 Meteor 应该向客户端发送什么数据。

到目前为止，所有这些都是因为使用了`autopublish`包而神奇地工作的，该包将与每个客户端同步所有数据。现在，我们将手动控制这个流程，只向客户端发送必要的数据。

在本章中，我们将介绍以下主题：

+   与服务器同步数据

+   向客户端发布数据

+   发布部分集合

+   只发布文档的特定字段

+   延迟加载更多帖子

    ### 注意

    如果你想要直接进入章节并跟随示例，可以从书籍的网页 [`www.packtpub.com/books/content/support/17713`](https://www.packtpub.com/books/content/support/17713) 或者从 GitHub 仓库 [`github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter3`](https://github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter3) 下载前一章节的代码示例。

    这些代码示例还将包含所有样式文件，因此我们不需要在过程中担心添加 CSS 代码。

# 数据同步 – 当前的 Web 与新的 Web

在当前的 Web 中，大多数页面要么是托管在服务器上的静态文件，要么是由服务器在请求时生成的动态页面。这对于大多数服务器端渲染的网站来说是真的，例如用 PHP、Rails 或 Django 编写的网站。这两种技术除了被客户端显示外不需要任何努力；因此，它们被称为*薄*客户端。

在现代网络应用程序中，浏览器的概念已经从薄客户端转移到*厚*客户端。这意味着网站的大部分逻辑都存在于客户端，并且客户端请求它需要的数据。

目前，这主要是通过调用 API 服务器实现的。这个 API 服务器然后返回数据，通常以 JSON 格式返回，给客户端一个轻松处理和使用数据的方式。

大多数现代网站都是薄客户端和厚客户端的混合体。普通页面是服务器端渲染的，只有如聊天框或新闻提要等功能通过 API 调用进行更新。

Meteor，然而，建立在这样一个理念上，即使用所有客户端的计算能力比使用一个单一服务器的计算能力要好。一个纯厚客户端或者一个单页应用包含了一个网站前端的所有逻辑，在初始页面加载时发送下来。

服务器随后仅仅作为数据源，只向客户端发送数据。这可以通过连接到 API 并利用 AJAX 调用实现，或者像 Meteor 一样，使用一种名为**发布/订阅**的模型。在这个模型中，服务器提供一系列发布物，每个客户端决定它想订阅哪个数据集。

与 AJAX 调用相比，开发者无需处理任何下载或上传逻辑。Meteor 客户端在订阅特定数据集后自动后台同步所有数据。当服务器上的数据发生变化时，服务器将更新后的文档发送给客户端，反之亦然，如下面的图表所示：

![同步数据 - 当前的网络与新的网络](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00009.jpeg)

### 注意

如果这听起来确实不安全，请放心，我们可以设置规则，在服务器端过滤更改。我们将在第八章，*使用允许和拒绝规则进行安全设置*中查看这些可能性。

# 移除 autopublish 包

为了使用 Meteor 的发布/订阅，我们需要移除`autopublish`包，这个包是我们项目默认添加的。

这个包适用于快速原型设计，但在生产环境中不可行，因为我们的数据库中的所有数据都将同步到所有客户端。这不仅不安全，而且还会减慢数据加载过程。

我们只需在我们`my-meteor-blog`文件夹内的终端上运行以下命令：

```js
$ meteor remove autopublish

```

现在我们可以再次运行`meteor`来启动我们的服务器。当我们检查网站时，我们会发现我们上一章的所有帖子都消失了。

然而，它们实际上并没有消失。当前的服务器只是还没有发布任何内容，客户端也只是没有订阅任何内容；因此，我们看不到它们。

# 发布数据

为了在客户端再次访问帖子，我们需要告诉服务器将其发布给订阅的客户端。

为此，我们将在`my-meteor-blog/server`文件夹中创建一个名为`publications.js`的文件，并添加以下代码行：

```js
Meteor.publish('all-posts', function () {
  return Posts.find();
});
```

`Meteor.publish`函数将创建一个名为`all-posts`的发布，并返回一个包含`Post`集合中所有帖子的游标。

现在，我们只需告诉客户端订阅这个发布，我们就会再次看到我们的帖子。

我们在`my-meteor-blog/client`文件夹中创建一个名为`subscriptions.js`的文件，内容如下：

```js
Meteor.subscribe('all-posts');
```

现在，当我们检查我们的网站时，我们可以看到我们的博客文章已经重新出现。

这是因为当执行`subsciptions.js`文件时，客户端会订阅`all-posts`发布，这发生在页面完全加载之前，因为 Meteor 自动将`subsciptions.js`文件添加到文档的头部为我们。

这意味着 Meteor 服务器首先发送网站，然后 JavaScript 在客户端构建 HTML；随后，所有订阅都会同步，填充客户端的集合，并且模板引擎**Blaze**能够显示帖子。

现在我们已经恢复了我们的帖子，让我们看看我们如何告诉 Meteor 只发送集合中的一部分文档。

# 只发布数据的一部分

为了使我们的首页更具未来感，我们需要限制在上面显示的文章数量，因为随着时间的推移，我们可能会添加很多文章。

为此，我们将创建一个名为`limited-posts`的新发布，其中我们可以向文章的`find()`函数传递一个`limit`选项，并将其添加到我们的`publications.js`文件中，如下所示：

```js
Meteor.publish('limited-posts', function () {
  return Posts.find({}, {
    limit: 2,
    sort: {timeCreated: -1}
  });
});
```

我们添加一个`sort`选项，通过它按`timeCreated`字段降序排列文章。这是必要的，以确保我们获取最新的文章并然后限制输出。如果我们只在客户端上对数据进行排序，可能会发生我们省略了较新的文章，因为服务器发布只会发送它找到的第一个文档，不管它们是否是最新的。

现在我们只需去到`subscriptions.js`文件，将订阅更改为以下代码行：

```js
Meteor.subscribe('limited-posts');
```

如果我们现在查看我们的浏览器，我们会看到只有最后两篇文章出现在我们的首页上，因为我们只订阅了两个，如下面的屏幕截图所示：

![只发布数据的部分](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00010.jpeg)

### 注意

我们必须意识到，如果我们保留旧订阅的代码并与新订阅的代码并列，我们将同时订阅两个。这意味着 Meteor 合并了两个订阅，因此在我们客户端集合中保留了所有订阅的文档。

在添加新订阅之前，我们必须注释掉旧的订阅或删除它。

# 发布特定字段

为了优化发布，我们还可以确定要从文档中发布哪些字段。例如，我们只要求`title`和`text`属性，而不是其他所有属性。

这样做可以加快我们订阅的同步速度，因为我们不需要整个文章，只需要在首页上列出文章时必要的数据和简短描述。

让我们在`publications.js`文件中添加另一个发布：

```js
Meteor.publish('specificfields-posts', function () {
  return Posts.find({}, {
    fields: {
      title: 1
    }
  });
});
```

由于这只是一个示例，我们传递一个空对象作为一个查询来查找所有文档，作为`find()`的第二个参数，我们传递一个包含`fields`对象的选项对象。

我们给每个字段一个值为`1`的属性，该属性将被包含在返回的文档中。如果我们想通过排除字段来工作，我们可以使用字段名称并将值设置为`0`。然而，我们不能同时包含和排除字段，因此我们需要根据文档大小选择哪个更适合。

现在我们可以在`subscriptions.js`文件中简单地将订阅更改为以下代码行：

```js
Meteor.subscribe('specificfields-posts');
```

现在，当我们打开浏览器时，它将向我们展示一个文章列表。只有标题存在，而描述、时间和作者字段为空：

![发布特定字段](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00011.jpeg)

# 懒加载文章

既然我们已经浏览了这些简单的示例，那么现在让我们将它们结合起来，并为首页上的文章列表添加一个优美的懒加载功能。

懒加载是一种技术，只有在用户需要或滚动到末尾时才加载附加数据。这可以用来增加页面加载，因为要加载的数据是有限的。为此，让我们执行以下步骤：

1.  我们需要向首页文章列表的底部添加一个懒加载按钮。我们打开我们的`home.html`文件，在`home`模板的末尾，在我们`{{#each postsList}}`块助手下面添加以下按钮：

    ```js
    <button class="lazyload">Load more</button>
    ```

1.  接下来，我们将向我们的`publications.js`文件中添加一个发布，以发送灵活数量的文章，如下所示：

    ```js
    Meteor.publish('lazyload-posts', function (limit) {
      return Posts.find({}, {
        limit: limit,
        fields: {
          text: 0
        },
        sort: {timeCreated: -1}
      });
    });
    ```

基本上，这是我们之前学到的内容的组合。

+   我们使用了`limit`选项，但不是设置一个固定的数字，而是使用了`limit`参数，我们稍后将其传递给这个发布函数。

+   以前，我们使用了`fields`选项并排除了`text`字段。

+   我们可以只包含`fields`来获得相同的结果。这将更安全，因为它确保我们在文档扩展时不会获取任何额外的字段：

    ```js
    fields: {
      title: 1,
      slug: 1,
      timeCreated: 1,
      description: 1,
      author: 1
    }
    ```

+   我们对输出进行了排序，以确保我们总是返回最新的文章。

现在我们已经设置了我们的发布，让我们添加一个订阅，这样我们就可以接收其数据。

### 注意

请注意，我们需要先删除任何其他订阅，这样我们就不会订阅任何其他发布。

为此，我们需要利用 Meteor 的`session`对象。这个对象可以在客户端用来设置反应性的变量。这意味着每次我们改变这个会话变量时，它都会再次运行使用它的每个函数。在下面的示例中，我们将使用会话来在点击懒加载按钮时增加文章列表的数量：

1.  首先，在`subscription.js`文件中，我们添加以下代码行：

    ```js
    Session.setDefault('lazyloadLimit', 2);
    Tracker.autorun(function(){
    Meteor.subscribe('lazyload-posts', Session.get('lazyloadLimit'));
    });
    ```

1.  然后我们将`lazyloadLimit`会话变量设置为`2`，这将是我们前端页面最初显示的文章数量。

1.  接下来，我们创建一个`Tracker.autorun()`函数。这个函数将在开始时运行，后来在我们改变`lazyloadLimit`会话变量到另一个值时随时运行。

1.  在这个函数内部，我们订阅了`lazyload-posts`，将`lazyloadLimit`值作为第二个参数。这样，每次会话变量改变时，我们都用一个新的值改变我们的订阅。

1.  现在，我们只需要通过点击懒加载按钮来增加会话值，订阅就会改变，发送给我们额外的文章。为此，我们在`home.js`文件的末尾添加以下代码行：

    ```js
    Template.home.events({
      'click button.lazyload': function(e, template){
      var currentLimit = Session.get('lazyloadLimit');

      Session.set('lazyloadLimit', currentLimit + 2);
      }
    });
    ```

    这段代码将为懒加载按钮附加一个`click`事件。每次我们点击这个按钮时，我们都会获取`lazyloadLimit`会话，并增加两倍。

1.  当我们检查浏览器时，我们应该能够点击文章列表底部的懒加载按钮，它应该再添加两篇文章。每次我们点击按钮时，都应该发生这种情况，直到我们达到五个示例文章。

当我们只有五篇文章时，这看起来并不太有意义，但当文章超过 50 篇时，将最初显示的文章限制为 10 篇将显著提高页面加载时间。

然后我们只需要将会话的默认值更改为 10 并增加 10，就可以实现一个很好的懒加载效果。

# 切换订阅

现在我们已经有了很好的懒加载逻辑，让我们来看看这里的底层发生了什么。

我们之前创建的`.autorun()`函数将在代码首次执行时运行，订阅`lazyload-posts`发布。Meteor 然后发送`Posts`集合的最初两个文档，因为我们的第一个`limit`值是`2`。

下次我们更改`lazyloadLimit`会话时，它通过更改发布函数中的限制值来更改订阅。

Meteor 然后在后台检查我们客户端数据库中存在的文档，并请求下载缺失的文档。

当我们减少会话值时，这个方法也会起作用。Meteor 会删除与当前订阅/订阅不匹配的文档。

因此，我们可以尝试这样做；我们打开浏览器控制台，将会话限制设置为`5`：

```js
Session.set('lazyloadLimit', 5);
```

这将立即在我们的列表中显示所有五个示例文章。现在如果我们将其设置为更小的值，我们将看到它们是如何被移除的：

```js
Session.set('lazyloadLimit', 2);
```

为了确保它们已经消失，我们可以查询我们本地数据库，如下所示：

```js
Posts.find().fetch();
```

这将返回一个包含两个项目的数组，显示 Meteor 已经删除了我们不再订阅的文章，如下图所示：

![切换订阅](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00012.jpeg)

# 关于数据发布的一些说明

```js
Posts collection changes:
```

```js
Meteor.publish('comments', function (postId) {
    var post = Posts.find({_id: postId});

    return Comments.find({_id: {$in: post.comments}});
});
```

为了解决这个问题，你可以将文章和评论分开发布并在客户端连接它们，或者使用第三方包，如在[`atmospherejs.com/reywood/publish-composite`](https://atmospherejs.com/reywood/publish-composite)提供的允许有反应性发布的`reywood:publish-composite`包。

### 注意

请注意，`Meteor.publish()`函数重新运行的唯一情况是当前用户发生变化，使得`this.userId`在函数中可访问。

# 总结

在本章中，我们创建了几篇发布文章并订阅了它们。我们使用了`fields`和`limit`选项来修改发布的文档数量，并为博客首页实现了一个简单的懒加载逻辑。

为了更深入地了解我们学到的内容，我们可以查看第三章, *存储数据和处理集合*。以下 Meteor 文档将详细介绍我们可以在集合`find()`函数中使用的选项：

+   [`www.meteor.com/livequery`](https://www.meteor.com/livequery)

+   [`www.meteor.com/ddp`](https://www.meteor.com/ddp)

+   [`docs.meteor.com/#/full/publishandsubscribe`](https://docs.meteor.com/#/full/publishandsubscribe)

+   关于 Meteor 的集合，可以参考[`docs.meteor.com/#/full/collections`](https://docs.meteor.com/#/full/collections)。

你可以在这个章节代码示例的[`www.packtpub.com/books/content/support/17713`](https://www.packtpub.com/books/content/support/17713)找到，或者在 GitHub 上找到[`github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter4`](https://github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter4)。

在下一章节，我们将给我们的应用添加一个真正应用的元素——不同的页面和路由。


# 第五章：使用路由使我们的应用具有灵活性

既然我们已经到了这一章节，我们应该已经对 Meteor 的模板系统有一个很好的理解，并且了解服务器与客户端之间数据同步的工作原理。在消化了这些知识后，让我们回到有趣的部分，把我们的博客变成一个具有不同页面的真正网站。

你可能会问，“在单页应用中页面做什么？” “单页”这个术语有点令人困惑，因为它并不意味着我们的应用只由一个页面组成。它更是一个从当前做事方式衍生出来的术语，因为只有一页是从服务器发送下来的。在那之后，所有的路由和分页都在浏览器中完成。再也不需要从服务器本身请求任何页面了。在这里更好的术语应该是“客户端 web 应用程序”，尽管**单页**是目前使用的名称。

在本章中，我们将涵盖以下主题：

+   为我们的静态和动态页面编写路由。

+   根据路由更改订阅

+   为每个页面更改网站的标题。

那么，我们不要浪费时间，先添加`iron:router`包。

### 注意

如果你直接跳到这一章节并且想跟随示例，从以下网址下载前一章节的代码示例：书的网页[`www.packtpub.com/books/content/support/17713`](https://www.packtpub.com/books/content/support/17713) 或 GitHub 仓库[`github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter4`](https://github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter4)。

这些代码示例还将包含所有样式文件，因此我们不必担心在过程中添加 CSS 代码。

# 添加 iron:router 包

路由是应用中特定页面的 URL。在服务器端渲染的应用中，路由要么由服务器的/框架配置定义，要么由服务器上的文件夹结构定义。

在客户端应用中，路由仅仅是应用将用来确定要渲染哪些页面的路径。

客户端内要执行的步骤如下：

1.  网站被发送到客户端。

1.  JavaScript 文件（或文件）被加载并解析。

1.  路由器代码将检查当前它是哪个 URL，并运行正确的路由函数，然后渲染正确的模板。

    ### 提示

    为了在我们的应用中使用路由，我们将使用`iron:router`包，这是一个为 Meteor 编写的路由器，它使得设置路由和将它们与订阅结合变得容易。

1.  要添加包，我们取消任何正在运行的 Meteor 实例，前往我们的`my-meteor-blog`文件夹，并输入以下命令：

    ```js
    $ meteor add iron:router

    ```

1.  如果我们完成了这些，我们可以通过运行`$ meteor`命令再次启动 Meteor。

当我们回到浏览器的控制台时，我们会看到一个错误，说：`Error: Oh no! No route found for path: "/"`。不用担心；我们将在下一节处理这个问题。

# 设置路由器

为了使用路由器，我们需要对其进行设置。为了保持我们的代码组织有序，我们将在`my-meteor-blog`文件夹的根目录下创建一个名为`routes.js`的文件，并输入以下代码：

```js
Router.configure({
    layoutTemplate: 'layout'
});
```

路由配置允许您定义以下默认模板：

| ` | layoutTemplate` | 布局模板将作为主包装器。在这里，子模板将在`{{> yield}}`占位符中渲染，该占位符必须放在模板的某个位置。 |
| --- | --- | --- |
| ` | notFoundTemplate` | 如果当前 URL 没有定义路由，将渲染此模板。 |
| ` | loadingTemplate` | 当当前路由的订阅正在加载时，将显示此模板。 |

对于我们的博客，我们现在只需定义`layoutTemplate`属性。

执行以下步骤以设置路由器：

1.  要创建我们的第一个路由，我们需要在`route.js`文件中添加以下代码行：

    ```js
    Router.map(function() {

        this.route('Home', {
            path: '/',
            template: 'home'
        });

    });
    ```

    ### 注意

    您还可以将`Home`路由命名为`home`（小写）。然后我们可以省略手动模板定义，因为`iron:router`将自动查找名为`home`的模板。

    为了简单起见，我们手动定义模板，以保持全书中的所有路由一致。

1.  如果我们现在保存这个文件并回到浏览器，我们将看到`layout`模板被渲染两次。这并不是因为`iron:router`默认将`layoutTemplate`添加到我们应用程序的正文中，而是因为我们手动添加了它，以及在`index.html`中使用了`{{> layout}}`，所以它被渲染了两次。

为了防止`layout`模板的重复出现，我们需要从`index.html`文件中的`<body>`标签中删除`{{> layout}}`助手。

当我们检查浏览器时，现在只会看到`layout`模板被渲染一次。

# 切换到布局模板

尽管我们通过`template: home`向我们的`Home`路由传递了一个模板，但我们并没有动态地渲染这个模板；我们只是显示了带有其*硬编码*子模板的布局模板。

为了改变这一点，我们需要将布局模板内的`{{> home}}`包含助手替换为`{{> yield}}`。

`{{> yield}}`助手是`iron:router`提供的占位符助手，在此处渲染路由模板。

完成此操作后，当我们检查浏览器时，我们不应该看到任何变化，因为我们仍然在渲染`home`模板，但这次是动态的。然后我们按照以下步骤进行操作：

1.  为了验证这一点，我们将向我们的应用程序添加一个未找到的模板，通过在`layout.html`文件中的布局模板之后添加以下模板：

    ```js
    <template name="notFound">
      <div class="center">
        <h1>Nothing here</h1><br>
        <h2>You hit a page which doesn't exist!</h2>
      </div>
    </template>
    ```

1.  现在我们需要向`route.js`中的`Router.configure()`函数添加`notFoundTemplate`属性：

    ```js
    Router.configure({
        layoutTemplate: 'layout',
        notFoundTemplate: 'notFound'
    });
    ```

现在，当我们导航到`http://localhost:3000/doesntexist`时，我们将看到`notFound`模板被渲染，而不是我们的`home`模板：

![切换到布局模板](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00013.jpeg)

如果我们点击主菜单中的**首页**链接，我们会回到我们的首页，因为此链接导航到"``/``"。我们已经成功添加了我们的第一个路由。现在让我们继续创建第二个路由。

# 添加另一个路由

拥有一个首页并不意味着是一个真正的网站。让我们添加一个到我们的**关于**页面的链接，该页面自从第二章 *构建 HTML 模板*以来就在我们的抽屉里。

要这样做，只需复制`Home`路由，并将值更改为创建一个`About`路由，如下所示：

```js
Router.map(function() {

    this.route('Home', {
        path: '/',
        template: 'home'
    });
    this.route('About', {
        path: '/about',
        template: 'about'
    });
});
```

完成！

现在，当我们回到浏览器时，我们可以点击主菜单中的两个链接来切换我们的**首页**和**关于**页面，甚至输入`http://localhost:3000/about`也会直接带我们到相应的页面，如下截图所示：

![添加另一个路由](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00014.jpeg)

# 将帖子订阅移动到首页路由

为了为每个页面加载正确的数据，我们需要在路由中拥有订阅，而不是将其保存在单独的`subscriptions.js`文件中。

`iron:router`有一个特殊的函数叫做`subscriptions()`，这正是我们需要的。使用这个函数，我们可以反应性地更新特定路由的订阅。

为了看到它的实际应用，将`subscriptions()`函数添加到我们的`Home`路由中：

```js
this.route('Home', {
    path: '/',
    template: 'home',
    subscriptions
: function(){
 return Meteor.subscribe("lazyload-posts", Session.get('lazyloadLimit'));
 }
});
```

`subscriptions.js`文件中的**Session.setDefault('lazyloadLimit', 2)**行需要在`routes.js`文件的开头，并在`Router.configure()`函数之前：

```js
if(Meteor.isClient) {
    Session.setDefault('lazyloadLimit', 2);
}
```

这必须包裹在`if(Meteor.isClient){}`条件内，因为会话对象仅在客户端可用。

`subscriptions()`函数和之前使用的`Tracker.autorun()`函数一样是*响应式的*。这意味着当`lazyloadLimit`会话变量发生变化时，它会重新运行并更改订阅。

为了看到它的工作情况，我们需要删除`my-meteor-blog/client/subscriptions.js`文件，这样我们就不会有两个订阅相同发布物的点。

当我们现在检查浏览器并刷新页面时，我们会看到`home`模板仍然显示所有示例帖子。点击懒加载按钮会增加列出的帖子数量，但这次一切都是在我们的反应式`subscriptions()`函数中完成的。

### 注意

`iron:router`带有更多的钩子，您可以在附录中找到简短的列表。

为了完成我们的路由，我们只需要添加帖子路由，这样我们就可以点击一个帖子并详细阅读。

# 设置帖子路由

为了能够显示一个完整的帖子页面，我们需要创建一个帖子模板，当用户点击一个帖子时可以加载。

我们在`my-meteor-blog/client/templates`文件夹中创建一个名为`post.html`的文件，并使用以下模板代码：

```js
<template name="post">
  <h1>{{title}}</h1>
  <h2>{{description}}</h2>

  <small>
    Posted {{formatTime timeCreated "fromNow"}} by {{author}}
  </small>

  <div class="postContent">
    {{#markdown}}
{{text}}
    {{/markdown}}
  </div>
</template>
```

这个简单的模板显示了博客文章的所有信息，甚至重用了我们在这本书中早些时候从`template-helper.js`文件创建的`{{formatTime}}`助手。我们用这个助手来格式化文章创建的时间。

我们暂时还看不到这个模板，因为我们必须先为这个页面创建发布和路由。

## 创建一个单篇博文发布

为了在这个模板中显示完整文章的数据，我们需要创建另一个发布，该发布将完整的文章文档发送到客户端。

为了实现这一点，我们打开`my-meteor-blog/server/publication.js`文件，并添加以下发布内容：

```js
Meteor.publish("single-post", function(slug) {
  return Posts.find({slug: slug});
});
```

这里使用的`slug`参数将在稍后的订阅方法中提供，以便我们可以使用`slug`参数来引用正确的文章。

### 注意

缩略词是文档标题，以一种适合 URL 使用的方式格式化。缩略词比简单地在 URL 后附加文档 ID 更好，因为它们可读性强，易于访问者理解，也是良好 SEO 的重要组成部分。

为了使用缩略词，每个缩略词都必须是唯一的。我们在创建文章时会照顾到这一点。

假设我们传递了正确的斜杠，比如`my-first-entry`，这个发布将发送包含此斜杠的文章。

## 添加博文路由

为了让这个路由工作，它必须是动态的，因为每个链接的 URL 对于每篇文章都必须是不同的。

我们还将渲染一个加载模板，直到文章被加载。首先，我们在`my-meteor-blog/client/templates/layout.html`中添加以下模板：

```js
<template name="loading">
  <div class="center">
    <h1>Loading</h1>
  </div>
</template>
```

此外，我们还需要将此模板作为默认加载模板添加到`routes.js`中的`Router.configure()`调用中：

```js
Router.configure({
    layoutTemplate: 'layout',
    notFoundTemplate: 'notFound',
    loadingTemplate: 'loading',
    ...
```

然后，我们将以下代码行添加到我们的`Router.map()`函数中，以创建一个动态路由：

```js
this.route('Post', {
    path: '/posts/:slug',
    template: 'post',

    waitOn: function() {
        return Meteor.subscribe('single-post', this.params.slug);
    },
    data: function() {
        return Posts.findOne({slug: this.params.slug});
    }
});
```

`'/posts/:slug'`路径是一个动态路由，其中`:slug`可以是任何内容，并将传递给路由函数作为`this.params.slug`。这样我们只需将给定的 slug 传递给`single-post`订阅，并检索与这个 slug 匹配的文章的正确文档。

`waitOn()`函数的工作方式类似于`subscriptions()`函数，不过它会自动渲染我们在`Router.configure()`中设置的`loadingTemplate`，直到订阅准备好。

这个路由的`data()`函数将设置`post`模板的数据上下文。我们基本上在我们的本地数据库中查找包含来自 URL 的给定 slug 的文章。

### 注意

`Posts`集合的`findOne()`方法与`find()`方法类似，但只返回找到的第一个结果作为 JavaScript 对象。

让我们总结一下这里发生的事情：

1.  路由被调用（通过点击链接或页面重新加载）。

1.  然后`waitOn()`函数将订阅由给定的`slug`参数标识的正确文章，该参数是 URL 的一部分。

1.  由于`waitOn()`函数，`loadingTemplate`将在订阅准备好之前渲染。由于这在我们的本地机器上会非常快，所以我们可能根本看不到加载模板。

1.  一旦订阅同步，模板就会渲染。

1.  然后`data()`函数将重新运行，设置模板的数据上下文为当前文章文档。

现在发布和路由都准备好了，我们只需导航到`http://localhost:3000/posts/my-first-entry`，我们应该看到`post`模板出现。

## 文章链接

虽然我们已经设置了路由和订阅，但我们看不到它工作，因为我们需要正确的文章链接。由于我们之前添加的每个示例文章都包含一个`slug`属性，所以我们只需将它们添加到`postInList`模板中的文章链接。打开`my-meteor-blog/client/templates/postInList.html`文件，按照以下方式更改链接：

```js
<h2><a href="posts/{{slug}}">{{title}}</a></h2>
```

最后，当我们打开浏览器并点击博客文章的标题时，我们会被重定向到一个显示完整文章条目的页面，如下面的屏幕截图所示：

![文章链接](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00015.jpeg)

# 更改网站标题

如今我们的文章路由已经运行，我们只缺少为每个页面显示正确的标题。

遗憾的是，`<head></head>`在 Meteor 中不是一个响应式模板，我们本可以让 Meteor 自动更改标题和元标签。

### 注

计划将`head`标签变成一个响应式模板，但可能在 1.0 版本之前不会实现。

为了更改文档标题，我们需要找到一种基于当前路由来更改它的不同方法。

幸运的是，`iron:router`有一个`onAfterAction()`函数，也可以在`Router.configure()`函数中用于每个路由之前运行。在这个函数中，我们有权访问当前路由的数据上下文，所以我们可以简单地使用原生 JavaScript 设置标题：

```js
Router.configure({
    layoutTemplate: 'layout',
    notFoundTemplate: 'notFound',

    onAfterAction: function() {
 var data = Posts.findOne({slug: this.params.slug});

 if(_.isObject(data) && !_.isArray(data))
 document.title = 'My Meteor Blog - '+ data.title;
 else
 document.title = 'My Meteor Blog - '+ this.route.getName();
 }
});
```

使用**Posts.findOne({slug: this.params.slug})**，我们获取当前路由的文章。然后我们检查它是否是一个对象；如果是，我们将文章标题添加到`title`元标签。否则，我们只取路由名称。

在`Router.configure()`中这样做将为每个路由调用**onAfterAction**。

现在如果我们看看我们浏览器的标签页，我们会发现当我们浏览网站时，我们网站的标题会发生变化：

![更改网站标题](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/bd-sgl-pg-webapp-mtr/img/00016.jpeg)

### 提示

如果我们想要让我们的博客更酷，我们可以添加`mrt:iron-router-progress`包。这将在切换路由时在页面的顶部添加一个进度条。我们只需从我们的应用程序文件夹中运行以下命令：

```js
$ meteor add mrt:iron-router-progress

```

# 摘要

就这样！现在我们的应用程序是一个功能完整的网站，有不同的页面和 URL。

在本章中，我们学习了如何设置静态和动态路由。我们将我们的订阅移到了路由中，这样它们就可以根据路由的需要自动更改。我们还使用了 slugs 来订阅正确的文章，并在`post`模板中显示它们。最后，我们更改了网站的标题，使其与当前路由相匹配。

要了解更多关于`iron:router`的信息，请查看其文档在[`github.com/EventedMind/iron-router`](https://github.com/EventedMind/iron-router)。

你可以在这个章节的代码示例在[`www.packtpub.com/books/content/support/17713`](https://www.packtpub.com/books/content/support/17713)找到，或者在 GitHub 上找到[`github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter5`](https://github.com/frozeman/book-building-single-page-web-apps-with-meteor/tree/chapter5)。

在下一章中，我们将深入探讨 Meteor 的会话对象。
