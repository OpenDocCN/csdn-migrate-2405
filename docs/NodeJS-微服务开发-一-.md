# NodeJS 微服务开发（一）

> 原文：[`zh.annas-archive.org/md5/4F011ED53DB2D88764152F518B13B69D`](https://zh.annas-archive.org/md5/4F011ED53DB2D88764152F518B13B69D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

JavaScript 已成为当今和未来最重要的语言之一。

过去几年中 JavaScript 的崛起是如此迅猛，以至于它已成为开发现代 Web 应用程序的强大语言。

MEVN 是用于开发现代 Web 应用程序的堆栈之一，除了 MEAN 和 MERN。本书提供了使用 MEVN 技术逐步构建全栈 Web 应用程序的方法，其中包括 MongoDB、Express.js、Vue.js 和 Node.js。

本书将介绍 Node.js 和 MongoDB 的基本概念，继续构建 Express.js 应用程序并实现 Vue.js。

在本书中，我们将涵盖以下内容：

+   学习技术堆栈- MongoDB、Node.js、Express.js 和 Vue.js

+   构建 Express.js 应用程序

+   学习什么是 REST API 以及如何实现它们

+   学习在 Express.js 应用程序中使用 Vue.js 作为前端层

+   在应用程序中添加身份验证层

+   添加自动化脚本和测试

# 本书适合对象

本书旨在帮助对使用 Mongo DB、Express.js、Vue.js 和 Node.js 技术堆栈构建全栈应用程序感兴趣的 Web 开发人员学习。

本书适合具有 HTML、CSS 和 JavaScript 基本知识的初学者和中级开发人员。如果您是 Web 或全栈 JavaScript 开发人员，并且已经尝试过传统的堆栈，如 LAMP、MEAN 或 MERN，并希望探索具有现代 Web 技术的新堆栈，那么本书适合您。

# 本书涵盖的内容

第一章，“MEVN 简介”，介绍了 MEVN 堆栈以及构建应用程序所需的不同工具的安装。

第二章，“构建 Express 应用程序”，介绍了 Express.js，MVC 结构的概念，并向您展示如何使用 Express.js 和 MVC 结构设置应用程序。

第三章，“MongoDB 简介”，重点介绍了 Mongo 和其查询，介绍了 Mongoose 以及使用 Mongoose 执行 CRUD 操作的性能。

第四章，“REST API”，介绍了 REST 架构以及 RESTful API 是什么。本章还介绍了不同的 HTTP 动词和开发 REST API 的方法。

第五章，“构建真实应用程序”，介绍了 Vue.js，并向您展示如何使用 MEVN 中的所有技术构建一个完全工作的动态应用程序。

第六章，“使用 Passport.js 进行身份验证”，介绍了 Passport.js 是什么，并描述了如何实现 JWT 和本地策略以在应用程序中添加身份验证层。

第七章，“Passport.js OAuth 策略”，介绍了 OAuth 策略是什么，并指导您实现 Facebook、Twitter、Google 和 LinkedIn 的 Passport.js 策略。

第八章，“Vuex 简介”，介绍了 Vuex 的核心概念-状态、获取器、突变和操作。它还描述了如何在应用程序中实现它们。

第九章，“测试 MEVN 应用程序”，解释了单元测试和端到端测试是什么，并指导您编写应用程序不同方面的单元测试和自动化测试。

第十章，*Go Live*，解释了什么是持续集成，指导您如何设置一个持续集成服务，并在 Heroku 上部署应用程序。

# 充分利用本书

如果您具备以下技能，本书将对您最有益处：

+   了解 HTML、CSS 和 JavaScript

+   了解 Vue.js 和 Node.js 是一个加分项

+   了解如何使用 MEAN 和 MERN 堆栈构建 Web 应用程序是一个加分项

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)上登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Full-Stack-Web-Development-with-Vue.js-and-Node`](https://github.com/PacktPublishing/Full-Stack-Web-Development-with-Vue.js-and-Node)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自丰富图书和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。以下是一个例子：“模块是可以通过 Node.js 的`require`命令加载并具有命名空间的东西。模块有一个与之关联的`package.json`文件。”

代码块设置如下：

```js
extends layout

block content
  h1= title
  p Welcome to #{title}
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目将以粗体显示：

```js
var index = require('./routes/index');
var users = require('./routes/users');

var app = express();

// Require file system module
var fs = require('file-system');
```

任何命令行输入或输出都将按照以下方式编写：

```js
$ mkdir css
$ cd css
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中以这种方式出现。以下是一个例子：“只需点击“继续”，直到安装完成。”

警告或重要说明会出现在这样。

技巧和窍门会出现在这样。


# 第一章：介绍 MEVN

**Mongo, Express, Vue.js 和 Node.js**（**MEVN**）是一组 JavaScript 技术，就像**MongoDB**，**Express**，**Angular**和**Node.js**（**MEAN**）一样，以及**MongoDB**，**Express**，**React**和**Node.js**（**MERN**）一样。这是一个全栈解决方案，用于构建使用 MongoDB 作为数据存储的基于 Web 的应用程序，Express.js 作为后端框架（构建在 Node.js 之上），Vue.js 作为前端的 JavaScript 框架，Node.js 作为后端的主要引擎。

本书适用于有兴趣学习使用 MongoDB，Express.js，Vue.js 和 Node.js 构建全栈 JavaScript 应用程序的 Web 开发人员。适合具有 HTML，CSS 和 JavaScript 基础知识的初学者和中级开发人员。

MEVN 可能是一个新名词，但其中使用的技术并不新。这里介绍的唯一新技术是 Vue.js。Vue.js 是一个开源的 JavaScript 框架，其受欢迎程度正在迅速增长。学习 Vue.js 并不需要太多的学习曲线，它也是 AngularJS 和 ReactJS 等其他 JavaScript 框架的激烈竞争对手。

现代 Web 应用程序需要快速且易于扩展。过去，JavaScript 仅在 Web 应用程序中用于添加一些常规 HTML 和 CSS 无法实现的视觉效果或动画。但今天，JavaScript 已经改变。今天，JavaScript 几乎在每个基于 Web 的应用程序中使用，从小型到大型应用程序。当应用程序需要更快速和更具交互性时，会选择 JavaScript。

使用 JavaScript 作为唯一编程语言构建全栈应用有其自身的好处：

+   如果您刚开始学习编程，您只需要掌握一种语言：JavaScript。

+   全栈工程师需求量大。成为全栈开发人员意味着您了解数据库的工作原理，知道如何构建后端和前端，并且还具备 UI/UX 技能。

在本书中，我们将使用这些技术栈构建应用程序。

本章将涵盖以下主题：

+   MEVN 技术栈介绍

+   Node.js 及其在 Windows，Linux 和 macOS 上的安装介绍

+   `npm`及其安装概述

+   介绍 MongoDB 及其安装以及 MongoDB 中使用的一些基本命令

+   介绍 GitHub 版本控制以及它如何帮助软件工程师轻松访问代码历史和协作

# JavaScript 技术栈的演变

JavaScript 是当今最重要的编程语言之一。由 Brendan Eich 于 1995 年创建，它不仅在保持其地位方面表现出色，而且在超越所有其他编程语言方面也表现出色。

JavaScript 的受欢迎程度不断增长，没有止境。使用 JavaScript 作为唯一编程语言构建 Web 应用程序一直很受欢迎。随着这种快速增长的步伐，软件工程师需要了解 JavaScript 的需求也在不断增加。无论您选择擅长哪种编程语言，JavaScript 总是以某种方式介入并与其他编程语言一起参与。

在开发应用程序时，前端和后端有很多技术可供选择。虽然本书使用 Express.js 作为后端，但也有其他框架可供学习。

其他可用的后端框架包括**Meteor.js**，**Sails.js**，**Hapi.js**，**Mojito**，**Koa.js**等。

同样，对于前端，技术包括**Vue.js**，**React**，**Angular**，**Backbone**等。

除了 MongoDB 之外，数据库的选项还有 MySQL，PostgreSQL，Cassandra 等。

# 介绍 MEVN

JavaScript 框架每天都在增长，无论是数量还是使用率。 JavaScript 过去只用于客户端逻辑，但多年来它已经有了显着增长，现在它在前端和后端都有使用。

在 MEVN 堆栈中，Express.js 用于管理所有与后端相关的内容，而 Vue.js 处理所有与视图相关的内容。使用 MEVN 堆栈的优点如下：

+   整个应用程序都使用一种语言，这意味着您需要了解的唯一语言是 JavaScript

+   使用一种语言很容易理解客户端和服务器端

+   它是一个非常快速和可靠的应用程序，具有 Node.js 的非阻塞 I/O

+   这是一个了解 JavaScript 不断增长的生态系统的好方法

# 安装 Node.js

要开始，我们需要添加 MEVN 堆栈应用程序所需的所有依赖项。我们还可以参考官方网站（[`nodejs.org/`](https://nodejs.org/)）上有关如何在任何操作系统中安装 Node.js 的详细文档。

# 在 macOS 上安装 Node.js

在 macOS 上安装 Node.js 有两种方法：使用安装程序或使用 bash。

# 使用安装程序安装 Node.js

要使用安装程序安装 Node.js，请执行以下步骤：

1.  安装程序：我们可以从官方网站的下载页面（[`nodejs.org/en/#download`](https://nodejs.org/en/#download)）下载 macOS 的安装程序。我们将安装最新的`node`版本，即`10.0.0`。您可以安装任何您想要的`node`版本，但是我们在本书中将构建的应用程序将需要`node`版本`>= 6.0.0`。运行安装程序并按照给定的说明进行操作。当我们下载并运行安装程序时，将提示我们出现以下对话框：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/a6868792-7dc7-4c0f-b1b6-2c5ae9bcf818.png)

1.  只需点击继续，直到安装完成。安装完成后，我们将能够看到以下对话框：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/72da9af1-2959-4f12-93d2-cadf6a8edce8.png)

只需点击关闭，我们就完成了。

# 使用 bash 安装 Node.js

Node.js 可以在 macOS 中使用 Homebrew 轻松安装。Homebrew 是一个免费的开源软件包管理器，用于在 macOS 上安装软件。我个人更喜欢 Homebrew，因为它使在 Mac 上安装不同的软件变得非常容易：

1.  要安装`Homebrew`，请输入以下命令：

```js
$ /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

1.  现在，使用`Homebrew`来安装 Node.js，使用以下命令：

```js
$ brew install node
```

# 在 Linux 上安装 Node.js

对于 Linux，我们可以安装 Node.js 的默认发行版，或者可以从 NodeSource 下载最新版本。

# 从默认发行版安装 Node.js

要从默认发行版安装，我们可以使用以下命令在 Linux 上安装 Node.js：

```js
$ sudo apt-get install -y nodejs
```

# 从 NodeSource 安装 Node.js

要从 NodeSource 安装 Node.js，请执行以下步骤：

1.  首先从 NodeSource 下载最新版本的 Node.js：

```js
$ curl -sL https://deb.nodesource.com/setup_9.x | sudo -E bash 
```

1.  然后，使用以下命令安装 Node.js：

```js
$ sudo apt-get install -y nodejs
```

`apt`是 Advanced Package Tool 的缩写，用于在 Debian 和 Linux 发行版上安装软件。基本上，这相当于 macOS 中的 Homebrew 命令。

# 在 Windows 上安装 Node.js

我们可以通过以下步骤在 Windows 上安装 Node.js：

1.  从官方网站（[`nodejs.org/en/download/`](https://nodejs.org/en/download/)）下载 Node.js 安装程序。

1.  运行安装程序并按照给定的说明进行操作。

1.  单击关闭/完成按钮。

通过安装程序在 Windows 上安装 Node.js 几乎与在 macOS 上相同。下载并运行安装程序后，将提示我们出现对话框。只需点击继续，直到安装完成。当我们最终看到确认对话框时，点击关闭。Node.js 将被安装！

# 介绍 NVM

**NVM** 代表 **Node Version Manager**。NVM 跟踪我们安装的所有 `node` 版本，并允许我们在不同版本之间切换。当我们为一个 Node.js 版本构建的应用程序与其他版本不兼容时，我们需要特定的 `node` 版本来使事情正常运行时，这就非常方便了。NVM 允许我们轻松管理这些版本。当我们需要升级或降级 `node` 版本时，这也非常有帮助。

# 从 NVM 安装 Node.js

1.  要下载 NVM，请使用以下命令：

```js
$ curl -o- https://raw.githubusercontent.com/creationix/nvm/v0.33.0/install.sh | bash
```

1.  我们也可以使用以下命令：

```js
$ wget -qO- https://raw.githubusercontent.com/creationix/nvm/v0.33.6/install.sh | bash
```

1.  使用以下命令检查 `nvm` 是否已成功安装：

```js
$ nvm --version 
```

1.  现在，要通过 `nvm` 安装 `node`，请使用此命令：

```js
$ nvm install node
```

# 介绍 npm

npm 是 **Node Package Manager** 的缩写。基本上，它是一个工具，负责我们为 Node.js 安装的所有包。我们可以在官方网站 ([`www.npmjs.com/`](https://www.npmjs.com/)) 上找到所有现有的包。`npm` 使开发人员能够轻松地保持其代码更新，并重用许多其他开发人员共享的代码。

开发人员经常对包和模块这两个术语感到困惑。然而，这两者之间有明显的区别。

# 模块

模块是可以通过 `require` 命令由 Node.js 加载并具有命名空间的东西。一个模块有一个与之关联的 `package.json` 文件。

# 包

一个 `package` 只是一个文件，或者一组文件，它能够独立运行。每个包还有一个包含描述该包的所有元数据信息的 `package.json` 文件。一组模块组成了一个 `node` 包。

# 安装 npm

当我们从安装程序安装 Node.js 时，`npm` 作为 `node` 的一部分被安装。我们可以使用以下命令来检查 `npm` 是否已安装：

```js
$ npm --version
```

如果 `npm` 未安装，该命令会显示错误，而如果已安装，它只会打印出已安装的 `npm` 的版本。

# 使用 npm

`npm` 用于在我们的应用程序中安装不同的包。有两种安装包的方式：本地和全局。当我们想要安装特定于我们的应用程序的某个包时，我们希望将该包安装在本地。然而，如果我们想要将某个包用作命令行工具或者能够在应用程序之外访问它，我们将希望将其安装为全局包。

# 本地安装 npm 包

要仅安装特定于我们的应用程序的包，我们可以使用以下命令：

```js
$ npm install <package_name> --save
```

# 全局安装 npm 包

要全局安装一个包，我们可以使用以下命令：

```js
 $ npm install -g <package_name>
```

# 介绍 package.json

所有的 `node` 包和模块都包括一个名为 `package.json` 的文件。这个文件的主要功能是携带与该包或模块相关的所有元信息。`package.json` 文件需要内容是一个 JSON 对象。

作为最低要求，一个 `package.json` 文件包括以下内容：

+   **name**：包的名称。这是一个 `package.json` 文件的重要部分，因为它是区分它与其他包的主要内容，因此它是一个必填字段。

+   **version**：包的版本。这也是一个必填字段。为了能够安装我们的包，需要给出 `name` 和 `version` 字段。

+   **description**：包的简短摘要。

+   **main**：这是用于查找包的主要入口点。基本上，它是一个文件路径，因此当用户安装此包时，它知道从哪里开始查找模块。

+   **scripts**：这个字段包含可以在应用程序的各种状态下运行的命令。它是一个键值对。`key` 是应该运行命令的事件，`value` 是实际命令。

+   **author/contributors**：作者和贡献者是人。它包含一个人的标识符。作者是一个人，而贡献者可以是一组人。

+   **license**：当提供许可字段时，用户可以轻松使用我们的软件包。这有助于确定在使用软件包时的权限和限制。

# 创建一个 package.json 文件

我们可以手动创建一个`package.json`文件并自己指定选项，或者我们可以使用命令从命令提示符交互式地创建它。

让我们继续使用`npm`初始化一个带有`package.json`的示例应用程序。

首先，在项目目录中使用以下命令创建一个文件夹：

```js
$ mkdir testproject
```

要创建一个`package.json`文件，在我们创建的应用程序中运行以下命令：

```js
$ npm init
```

运行此命令将询问我们一系列问题，我们可以从命令行交互式地回答这些问题：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/9242cbf3-4880-4130-897e-cbd9b258a49b.png)

最后，它将创建一个`package.json`文件，其中将包含以下内容：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/703c36f8-ede0-4290-bd40-25d0788cd7d4.png)

# 安装 MongoDB

MongoDB 是 MEVN 堆栈中技术的第一部分。MongoDB 是一个免费的开源文档数据库，发布在 GNU 许可下。它是一个 NoSQL 数据库，意味着它是一个非关系数据库。与关系数据库不同，关系数据库使用表和行来表示数据，MongoDB 使用集合和文档。MongoDB 将数据表示为 JSON 文档的集合。它为我们提供了灵活性，可以以任何方式添加字段。单个集合中的每个文档可以具有完全不同的结构。除了添加字段，它还提供了在文档之间以任何方式更改字段的灵活性，这在关系数据库中是一项繁琐的任务。

# 与关系数据库管理系统（RDBMS）相比，MongoDB 的优势

MongoDB 相比关系数据库管理系统提供了许多优势：

+   无模式架构：MongoDB 不要求我们为其集合设计特定的模式。一个文档的模式可以不同，另一个文档可以完全不同。

+   每个文档都以 JSON 结构格式存储。

+   查询和索引 MongoDB 非常容易。

+   MongoDB 是一个免费的开源程序。

# 在 macOS 上安装 MongoDB

安装 MongoDB 有两种方法。我们可以从官方 MongoDB 网站([`www.mongodb.org/downloads#production`](https://www.mongodb.org/downloads#production))下载，或者我们可以使用 Homebrew 进行安装。

# 通过下载安装 MongoDB

1.  从[`www.mongodb.com/download-center#production.`](https://www.mongodb.com/download-center#production)下载您想要的 MongoDB 版本

1.  将下载的 gzipped 复制到根文件夹。将其添加到根文件夹将允许我们全局使用它：

```js
 $ cd Downloads $ mv mongodb-osx-x86_64-3.0.7.tgz ~/
```

1.  解压缩 gzipped 文件：

```js
 $ tar -zxvf mongodb-osx-x86_64-3.0.7.tgz
```

1.  创建一个目录，Mongo 将用来保存数据：

```js
 $ mkdir -p /data/db
```

1.  现在，要检查安装是否成功，请启动 Mongo 服务器：

```js
 $ ~/mongodb/bin/mongod
```

在这里，我们已成功安装并启动了`mongo`服务器。

# 通过 Homebrew 安装 MongoDB

要从 Homebrew 在 macOS 上安装 MongoDB，请按照以下步骤：

1.  使用 Homebrew，我们只需要一个命令来安装 MongoDB：

```js
$ brew install mongodb
```

1.  创建一个目录，Mongo 将用来保存数据：

```js
 $ sudo mkdir -p /data/db
```

1.  启动 Mongo 服务器：

```js
 $ ~/mongodb/bin/mongod 
```

因此，MongoDB 最终安装完成。

# 在 Linux 上安装 MongoDB

在 Linux 上安装 MongoDB 也有两种方法：我们可以使用`apt-get`命令，或者我们可以下载 tarball 并解压缩它。

# 使用 apt-get 安装 MongoDB

要使用`apt-get`安装 MongoDB，请执行以下步骤：

1.  运行以下命令安装最新版本的 MongoDB：

```js
 $ sudo apt-get install -y mongodb-org
```

1.  通过运行命令验证`mongod`是否已成功安装：

```js
 $ cd /var/log/mongodb/mongod.log
```

1.  要启动`mongod`进程，请在终端中执行以下命令：

```js
 $ sudo service mongod start
```

1.  查看日志文件是否有一行表示 MongoDB 连接成功建立：

```js
 $ [initandlisten] waiting for connections on port<port>
```

1.  停止`mongod`进程：

```js
 $ sudo service mongod stop
```

1.  重新启动`mongod`进程：

```js
 $ sudo service mongod restart
```

# 使用 tarball 安装 MongoDB

1.  从[`www.mongodb.com/download-center?_ga=2.230171226.752000573.1511359743-2029118384.1508567417`](https://www.mongodb.com/download-center?_ga=2.230171226.752000573.1511359743-2029118384.1508567417)下载二进制文件。使用这个命令：

```js
 $ curl -O https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-
 3.4.10.tgz
```

1.  提取下载的文件：

```js
 $ tar -zxvf mongodb-linux-x86_64-3.4.10.tgz
```

1.  复制并提取到目标目录：

```js
 $ mkdir -p mongodb $ cp -R -n mongodb-linux-x86_64-3.4.10/ mongodb
```

1.  设置二进制文件的位置到 PATH 变量：

```js
 $ export PATH=<mongodb-install-directory>/bin:$PATH
```

1.  创建一个目录供 Mongo 使用来存储所有与数据库相关的数据：

```js
 $ mkdir -p /data/db
```

1.  启动`mongod`进程：

```js
 $ mongod
```

# 在 Windows 上安装 MongoDB

从安装程序安装 MongoDB 在 Windows 上和安装其他软件一样简单。就像我们为 Node.js 做的那样，我们可以从官方网站([`www.mongodb.com/download-center#atlas`](https://www.mongodb.com/download-center#atlas))下载 Windows 的 MongoDB 安装程序。这将下载一个可执行文件。

一旦可执行文件下载完成，运行安装程序并按照说明进行操作。仔细阅读对话框中的说明。安装完成后，只需点击“关闭”按钮，你就完成了。

# 使用 MongoDB

让我们深入了解一下 MongoDB。正如之前提到的，Mongo 由一个包含集合（表/数据组）和文档（行/条目/记录）的数据库组成。我们将使用 MongoDB 提供的一些命令来创建、更新和删除文档：

首先，使用这个命令启动 Mongo 服务器：

```js
$ mongod
```

然后，使用这个命令打开 Mongo shell：

```js
$ mongo
```

# 创建或使用 MongoDB 数据库

这是我们可以看到所有数据库、集合和文档的地方。

要显示我们拥有的数据库列表，我们可以使用以下命令：

```js
> show dbs
```

现在，这个命令应该列出所有现有的数据库。要使用我们想要的数据库，我们可以简单地运行这个命令：

```js
> use <database_name>
```

但是如果没有列出数据库，不要担心。MongoDB 为我们提供了一个功能，当我们运行前面的命令时，即使该数据库不存在，它也会自动为我们创建一个具有给定名称的数据库。

因此，如果我们已经有一个要使用的数据库，我们只需运行该命令，如果还没有数据库，我们可以使用这个命令创建一个：

```js
> use posts
```

当我们运行这个命令时，将创建一个名为`posts`的数据库。

# 创建文档

现在，让我们快速回顾一下在 MongoDB 中使用的命令。`insert`命令用于在 MongoDB 的集合中创建新文档。让我们向我们刚刚创建的名为`posts`的数据库添加一条新记录。

同样，在向集合添加文档之前，我们首先需要一个集合，但我们目前还没有。但是 MongoDB 允许我们通过运行`insert`命令轻松创建一个集合。同样，如果集合存在，它将把文档添加到给定的集合中，如果集合不存在，它将简单地创建一个新的集合。

现在，在 Mongo shell 中运行以下命令：

```js
> db.posts.insertOne({
 title: 'MEVN',
 description: 'Yet another Javascript full stack technology'
});
```

这个命令将在`posts`数据库中创建一个名为`posts`的新集合。这个命令的输出是：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/b8a7bc64-056f-4843-ad70-fa136b03b44e.png)

它将返回一个 JSON 对象，其中包含我们刚刚在`insertedId`键中创建的文档的 ID，以及事件被接收为`acknowledged`的标志。

# 获取文档

当我们想要从集合中获取记录时，就会使用这个命令。我们可以获取所有记录，也可以通过传递参数来获取特定文档。我们可以向`posts`数据库添加一些文档，以更好地学习这个命令。

# 获取所有文档

要从`posts`集合中获取所有记录，请运行以下命令：

```js
> db.posts.find()
```

这将返回我们在`posts`集合中拥有的所有文档：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/ace2e83f-51d0-47e3-acb3-5fbdf1882add.png)

# 获取特定文档

让我们找到一个标题为`MEVN`的帖子。为了做到这一点，我们可以运行：

```js
> db.posts.find({ 'title': 'MEVN' }) 
```

这个命令将只返回标题为`MEVN`的文档：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/d46f10fd-7826-4822-94c0-7ca9dcd84c9c.png)

# 更新文档

当我们想要更新集合中的某个部分时，可以使用这个命令。比如说我们想要更新标题为`Vue.js`的帖子的描述，我们可以运行以下命令：

```js
> db.posts.updateOne(
 { "title" : "MEVN" },
 { $set: { "description" : "A frontend framework for Javascript programming language" } }
 )
```

这个命令的输出将是：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/c5873c55-7a64-47ee-9b04-999a1ba0b4f2.png)

我们可以看到`matchedCount`是`1`，这意味着关于我们发送的参数来更新标题为`MEVN`的记录，`posts`集合中有一个匹配查询的文档。

另一个关键称为`modifiedCount`，它给出了更新的文档数量。

# 删除文档

`delete`命令用于从集合中删除文档。有几种方法可以从 MongoDB 中删除文档。

# 删除符合给定条件的文档

要删除所有带有特定条件的文档，我们可以运行：

```js
> db.posts.remove({ title: 'MEVN' })
```

这个命令将从`posts`集合中删除所有标题为`MEVN`的文档。

# 删除符合给定条件的单个文档

要仅删除满足给定条件的第一条记录，我们可以使用：

```js
> db.posts.deleteOne({ title: 'Expressjs' })
```

# 删除所有记录

要从集合中删除所有记录，我们可以使用：

```js
> db.posts.remove({})
```

# 介绍 Git

Git 是用于跟踪应用程序中代码更改的版本控制系统。它是一个免费的开源软件，用于在构建应用程序时跟踪和协调多个用户。

要开始使用这个软件，我们需要先安装它。在每个操作系统上都有一种非常简单的安装方法。

# 在 Windows 上安装 Git

我们可以在[`gitforwindows.org/.`](https://gitforwindows.org/)找到 Windows 版 Git 的安装程序。

下载 Windows 的可执行安装程序文件，并按照逐步说明进行操作。

# 在 Mac 上安装 Git

我们可以通过 Homebrew 轻松在 Mac 上安装 Git。只需在命令行中输入以下命令即可在 Mac 上安装 Git：

```js
$ brew install git 
```

# 在 Linux 上安装 Git

在 Linux 上安装 Git 就像在 macOS 上安装 Git 一样容易。只需输入以下命令并按 Enter 键在 Linux 上安装 Git：

```js
$ sudo apt-get install git
```

# 介绍 GitHub

GitHub 是一个版本控制服务。它是一个专门设计用于跟踪代码更改的源代码管理工具。GitHub 还提供了社交网络功能，如添加评论和显示动态，这使得它更加强大，因为多个开发人员可以同时在一个应用程序中进行协作。

# 为什么要使用 GitHub？

GitHub 对软件工程师来说是救星。GitHub 提供了几个优势，使得使用它非常值得。GitHub 提供的一些好处列在这里：

+   **跟踪代码更改**：GitHub 帮助跟踪代码的更改，这意味着它维护了我们代码的历史。这使我们能够查看在任何时间段内对我们代码库所做的修订。

+   **文档**：GitHub 提供了添加文档、维基等功能，这些可以使用简单的 Markdown 语言编写。

+   **图表和报告**：GitHub 提供了对各种指标的洞察，包括对代码进行了多少次添加和删除，谁是最大的贡献者，谁有最多的提交。

+   **Bug 跟踪**：由于 GitHub 跟踪了每个时间点的所有活动，当出现问题时，我们可以轻松地回溯到导致代码出错的时间点。我们还可以集成第三方工具，如 Travis 进行持续集成，这有助于我们轻松跟踪和识别错误。

+   **合作很容易**：GitHub 跟踪每个合作者在项目上的每一个活动，并发送电子邮件通知。它还提供社交媒体功能，如动态、评论、表情符号和提及。

+   **托管我们自己的网站**：我们还可以使用 GitHub 的一个名为 GitHub Pages 的功能来托管我们自己的网站。我们只需要为我们自己的项目创建一个仓库，并使用 Github Pages 进行托管，然后网站就可以适用于 URL：`https://<username>.github.io`。

# 使用 GitHub

GitHub 非常易于使用。但是，要开始使用 GitHub，我们需要至少了解一些 GitHub 中使用的术语：

+   **Repository/Repo**：存储库是存储我们所有代码库的地方。存储库可以是私有的或公共的。

+   **ssh-key**：ssh-key 是在 GitHub 中授权的一种方式。它存储了我们的身份。

+   **Branch**：分支可以被定义为存储库的多个状态。任何存储库的主要分支都是`master`分支。多个用户可以并行在不同的分支上工作。

+   **Commit**：提交使得很容易区分文件在给定时间的不同状态。当我们进行提交时，会为该提交分配一个唯一的标识符，以便轻松检查在该提交中进行了哪些更改。提交需要一个消息作为参数，以描述正在进行的更改的类型。

+   **Push**：推送将我们所做的提交发送回我们的存储库。

+   **Pull**：与推送相反，拉取是从远程存储库到我们的本地项目获取提交的过程。

+   **Merge**：合并基本上是在多个分支之间进行的。它用于将一个分支的更改应用到另一个分支。

+   **Pull requests**：创建`pull request`基本上是将我们对代码库所做的更改发送给其他开发人员进行批准。我们可以开始讨论一个`pull request`来检查代码的质量，并确保更改不会破坏任何东西。

要了解 GitHub 中使用的词汇，请访问[`help.github.com/articles/github-glossary/`](https://help.github.com/articles/github-glossary/)。

# 设置 GitHub 存储库

现在我们知道了 GitHub 的基础知识，让我们开始为我们想要构建的项目创建一个 GitHub 存储库：

1.  首先，在根文件夹中为应用程序创建一个文件夹。让我们将这个应用程序命名为`blog`：

```js
 $ mkdir blog
```

1.  在 GitHub 上创建一个帐户[`github.com/`](https://github.com/)。

1.  转到您的个人资料。在存储库选项卡下，单击新建，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/a167a04d-7d3a-48e7-a0f0-c5cb1553e087.png)

1.  将此存储库命名为`blog`。

1.  现在，在终端上，转到此应用程序的位置，并使用此命令初始化一个空存储库：

```js
 $ cd blog $ git init
```

1.  现在，让我们创建一个名为`README.md`的文件，并为应用程序编写描述，然后保存它：

```js
 $ echo 'Blog' > README.md 
```

1.  将此文件添加到 GitHub：

```js
 $ git add README.md
```

1.  添加一个`commit`，以便我们有这个代码更改的历史记录：

```js
 $ git commit -m 'Initial Commit'
```

1.  现在，要将本地应用程序与 GitHub 中的`remote`存储库链接起来，请使用以下命令：

```js
$ git remote add origin https://github.com/{github_username}/blog.git
```

1.  最后，我们需要将这个`commit`推送到 GitHub：

```js
 $ git push -u origin master
```

当完成后，访问 GitHub 存储库，在那里您将找到对我们存储库所做的提交的历史，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/95a1bce9-e60d-484a-a21c-f435eb23d0fb.png)

就是这样。现在，当我们想要进行更改时，我们将首先创建一个分支并将更改推送到该分支。

# 总结

在本章中，我们学习了什么是 MEVN 堆栈。我们了解了 Node.js、npm 和 MongoDB，以及对 GitHub 的简要概述以及它如何帮助软件工程师轻松访问代码历史和协作。

在下一章中，我们将更多地了解 Node.js 和 Node.js 模块。我们将学习 MVC 架构以及如何通过使用 Express.js 构建应用程序来实现它。


# 第二章：构建 Express 应用程序

Express.js 是一个 Node.js Web 应用程序框架。Express.js 使得使用 Node.js 更加容易并发挥其能力。在本章中，我们将仅使用 Express.js 创建一个应用程序。Express.js 也是一个`node`包。我们可以使用应用程序生成器工具，让我们轻松地创建一个 Express 应用程序的框架，或者我们可以从头开始自己创建一个。

在上一章中，我们了解了`npm`是什么，什么是包，以及如何安装包。在本章中，我们将涵盖以下元素：

+   Node.js 是什么以及它能做什么

+   它所增加的好处

+   Node.js 的基本编程

+   Node.js 核心和自定义模块

+   Express.js 简介

+   使用 Express.js 创建应用程序

+   Express.js 中的路由

+   MVC 架构：它是什么，以及在应用程序中实现时增加了什么价值

+   应用程序的文件命名约定

+   文件夹重新组织以整合 MVC

+   为 Express.js 应用程序创建视图

有很多`npm`包可以让我们为 Express.js 应用程序创建一个框架。其中一个包是`express-generator`。这让我们可以在几秒钟内创建整个应用程序的框架。它会以模块化结构创建所有必要的文件和文件夹。它以非常易于理解的方式生成文件结构。我们唯一需要做的就是定义模板视图和路由。

我们也可以根据自己的需求修改这个结构。当我们时间紧迫，想在一天内构建一个应用程序时，这非常方便。这个过程非常简单。

`express-generator`只是许多可用于创建 Express 应用程序的脚手架或模块化结构的工具之一。每个生成器工具可能都有自己的构建文件结构的方式，可以很容易地定制。

如果你是初学者，并且想了解文件夹结构是如何工作的，我建议你从头开始构建应用程序。我们将在本章中进一步讨论这一点。

要开始，首先我们需要在深入 Express.js 之前更多地了解 Node.js。

# Node.js 简介

Node.js 是建立在 JavaScript 引擎上的 JavaScript 运行时。它是用于服务器端管理的开源框架。Node.js 轻量高效，并在各种平台上运行，如 Windows、Linux 和 macOS。

Node.js 是由 Ryan Dahl 于 2009 年创建的。JavaScript 过去主要用于客户端脚本编程，但 Node.js 使得 JavaScript 也可以用于服务器端。Node.js 的发明引入了在 Web 应用程序中使用单一编程语言的概念。Node.js 带来了许多好处，其中一些如下：

+   事件驱动编程：它意味着将对象的状态从一个状态改变为另一个状态。Node.js 使用事件驱动编程，这意味着它使用用户的交互操作，如鼠标点击和按键按下，来改变对象的状态。

+   非阻塞 I/O：非阻塞 I/O，或者非同步 I/O，意味着异步 I/O。同步进程会等待当前运行的进程完成，因此会阻塞进程。另一方面，异步进程不需要等待该进程完成，这使得它快速且可靠。

+   单线程：单线程意味着 JavaScript 只在一个事件循环中运行。由于异步进程允许我们同时拥有多个进程，似乎所有这些进程都在自己的特定线程中运行。但是 Node.js 处理异步的方式有些不同。Node.js 中的事件循环在相应事件发生后触发下一个被安排执行的回调函数。

# 理解 Node.js

在深入研究 Node.js 编程之前，让我们先了解一些 Node.js 的基础知识。Node.js 在 JavaScript V8 引擎上运行。JavaScript V8 引擎是由*Chromium 项目*为 Google Chrome 和 Chromium 网络浏览器构建的。它是一个用 C++编写的开源项目。该引擎用于客户端和服务器端的 JavaScript Web 应用程序。

# Node.js 编程

让我们首先运行一个`node`进程。打开终端并输入以下命令：

```js
$ node
```

这将启动一个新的`node`进程。我们可以在这里编写普通的 JavaScript。

例如，我们可以在新的 Node shell 中写入以下 JavaScript 命令：

```js
> var a = 1;
```

当我们输入`a`并按回车时，它返回`1`。

我们也可以在`node`进程中运行带有`.js`扩展名的文件。让我们在根目录中创建一个名为`tutorial`的文件夹，命令是`mkdir tutorial`，并在其中创建一个名为`tutorial.js`的文件。

现在，在终端中，让我们用以下命令进入该目录：

```js
$ cd tutorial $ node tutorial.js
```

我们应该看到类似以下的东西：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/db7d6f63-3df3-4fd9-842e-fc4f6177ef4b.png)

这不会返回任何东西，因为我们还没有为`tutorial.js`编写任何内容。

现在，让我们在`tutorial.js`中添加一些代码：

```js
console.log('Hello World');
```

现在，用以下命令运行文件：

```js
$ node tutorial.js
```

我们将看到一个输出，上面写着`Hello World`。这就是我们在 Node.js 中执行文件的方式。

除了在 V8 引擎上运行并在 Web 浏览器中执行 JavaScript 代码之外，Node.js 还提供了一个服务器运行环境。这是 Node.js 最强大的功能。Node.js 提供了自己的 HTTP 模块，可以实现非阻塞的 HTTP。让我们构建一个简单的 Web 服务器来理解这一点。

在同一个文件中，在`tutorial.js`中，用以下代码覆盖文件：

```js
const http = require('http');

http.createServer(function (req, res) {
 res.writeHead(200, { 'Content-Type': 'text/plain' });
 res.end('Hello World\n');
}).listen(8080, '127.0.0.1');

console.log('Server running at http://127.0.0.1:8080/');
```

在这里，`var http = require('http');`的代码将 HTTP 模块引入了我们的应用程序。这意味着现在我们可以通过`http`变量访问 HTTP 库中定义的函数。现在我们需要创建一个 Web 服务器。前面的代码告诉 Node.js 在 8080 端口运行 Web 服务器。`createServer`方法中的`function`参数接受两个参数，`req`和`res`，它们分别是请求和响应的简写。在该函数内部，我们需要做的第一件事是设置 HTTP 头。这基本上是定义我们希望从该请求中得到的响应类型。然后，我们通过`res.send`定义我们想要在响应中获取的内容。最后，我们要求 Web 服务器监听 8080 端口。

当我们用`$ node tutorial.js`运行这段代码时，输出看起来像这样：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/154a4a5f-59e2-4837-b2c7-7962c1eb24ed.png)

当我们在浏览器中输入该 URL 时，我们应该能够看到这个：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/d553340f-ee2f-4961-af8b-28c4b6269826.png)

这就是 Node.js 作为服务器程序的工作方式。

要退出`node`控制台，请按两次*Ctrl* *+* *C*。

# Node.js 模块

一个 Node.js 模块只是一个包含可重用代码的普通 JavaScript 文件。每个模块都有其特定的功能。我们可以将其视为一个库。

例如，如果我们想在我们的应用程序中将所有与用户相关的活动分隔开，我们可以为其创建一个模块，该模块将处理有关用户的所有数据库。

我们在 Node.js 中使用模块的方式是通过`require`。我们刚刚展示的创建 Web 服务器的示例也是一个 Node.js 模块。

# Node.js 核心模块

Node.js 有两种类型的模块。核心模块是内置在 Node.js 中的模块。它们在我们安装 Node.js 时就存在了。这些也被称为内置模块。Node.js 中有很多核心模块：

+   调试器

+   文件系统

+   HTTP

+   路径

+   进程

+   事件

如果您想了解每个核心模块的更多细节，可以访问文档：

[`nodejs.org/api/.`](https://nodejs.org/api/)

# 自定义模块

这些是我们在 Node.js 之上自己创建的模块。由于 Node.js 拥有一个非常庞大的生态系统，有大量不同的模块可以根据我们的需求免费获取。我们可以自己构建一个，也可以使用别人的模块。这是 Node.js 强大的另一个方面。它给了我们使用社区模块的灵活性，或者我们可以自己构建它们。

我们可以在[`www.npmjs.com/browse/depended`](https://www.npmjs.com/browse/depended)上查看所有现有可用模块的列表：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/72db803d-bbff-45a8-8283-f529bfecf3a4.png)

# 介绍 Express.js

Express.js 是一个用于 Node.js 的极简的服务器端 Web 框架。它是建立在 Node.js 之上的，以便轻松管理 Node.js 服务器。Express.js 最重要的优势是它使路由非常非常容易。它提供的强大 API 非常容易配置。它很容易接收来自前端的请求，也很容易连接到数据库。Express.js 也是 Node.js 最流行的 Web 框架。它使用**模型视图控制器**（**MVC**）设计模式，我们将在本章后面讨论。

# 安装 Express.js

我们已经介绍了如何通过`npm`安装`node`模块。同样，我们可以使用以下命令通过 NPM 安装 Express.js：

```js
$ npm install express
```

这是安装`node`模块的一种简单方式。但是，在构建应用程序时，我们将需要许多不同类型的模块。我们还希望在多个应用程序之间共享这些模块。因此，为了使模块全局可用，我们必须全局安装它。为此，`npm`在安装`node`模块时提供了添加`-g`的选项。所以，现在我们可以使用：

```js
$ npm install -g express
```

这将全局安装 Express.js，这允许我们在多个应用程序中使用`express`命令。

# 创建 Express.js 应用程序

现在我们已经安装了 Express.js，让我们开始使用 Express.js 创建应用程序。

我们将把我们的应用程序命名为`express_app`。使用`express`命令非常简单地构建一个 Express 应用程序的大纲。我们可以简单地使用：

```js
$ express express_app
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/5ed5de2e-8500-4b09-bdeb-7eb0ee523acf.png)

该命令会在我们的应用程序中创建许多文件和文件夹。让我们快速看一下这些：

+   `package.json`：这个文件包含了我们在应用程序中安装的所有`node`包的列表和应用程序的介绍。

+   `app.js`：这个文件是 Express 应用程序的主入口页面。Web 服务器代码驻留在这个文件中。

+   `public`：我们可以使用这个文件夹来插入我们的资产，如图像、样式表或自定义 JavaScript 代码。

+   `views`：这个文件夹包含了所有将在浏览器中呈现的视图文件。它有一个主布局文件（包含视图文件的基本 HTML 模板），一个`index.jade`文件（扩展布局文件，只包含可变或动态的内容），以及一个`error.jade`文件（在需要向前端显示某种错误消息时显示）。

+   `routes`：这个文件夹包含了我们将要构建的访问应用程序不同页面的所有路由的完整列表。我们将在后续章节中更多地讨论这个问题。

+   `bin`：这个文件夹包含了 Node.js 的可执行文件。

所以，这些是我们需要知道的基本事情。现在，使用你喜欢的文本编辑器来处理应用程序，让我们开始吧。现在，如果我们查看`package.json`，会发现有一些包我们没有安装，但在依赖项中列出了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/e44f9b6c-a3d5-47be-b601-fb8687b29f77.png)

这是因为这些是任何应用程序的 Express.js 依赖项。这意味着，当我们使用`express`命令创建应用程序时，它将自动安装所有需要的依赖项。例如，前面`package.json`文件中列出的依赖项做了以下事情：

+   **body-parser**：用于解析我们在发出 HTTP 请求时提供的 body 参数

+   **debug**：这是一个 JavaScript 实用程序包，可以对`console.log`返回的内容进行漂亮的格式化

我们也可以通过`package.json`文件安装或删除包。只需在`package.json`文件中添加或删除包的名称以安装或删除它。然后运行`$ npm install`。

+   **express**：这是一个 Node.js JavaScript 框架，用于构建可扩展的 Web 应用程序。

+   **jade**：如前所述，这是 Node.js 的默认模板引擎。在使用`express`命令创建应用程序时，应该会看到一个警告，指出默认视图引擎在将来的版本中将不再是 jade。这是因为`jade`将被`pug`取代；`jade`曾经是一家公司拥有的，后来更名为`pug`。

express 生成器使用过时的`jade`模板引擎。要更改模板引擎，请执行以下步骤：

1.  在`package.json`文件中，删除`"jade": "~1.11.0"`一行，并运行：

```js
$ cd express_app
$ npm install
```

1.  现在，要安装新的`pug`模板引擎，请运行：

```js
$ npm install pug --save
```

1.  如果我们查看`package.json`文件，应该会看到类似于以下内容的一行：

`"pug": "².0.0-rc.4"`.

1.  重命名`views`文件夹中的文件：

+   `error.jade` to `error.pug`

+   `index.jade` to `index.pug`

+   `layout.jade` to `layout.pug`

1.  最后，在`app.js`中删除以下行：

```js
app.set('view engine', 'jade');
```

1.  添加以下行以使用`pug`作为视图引擎：

```js
app.set('view engine', 'pug');
```

+   **morgan**：这是用于记录 HTTP 请求的中间件

+   **serve-favicon**：用于在浏览器中显示一个 favicon 以识别我们的应用程序

对于我们的应用程序来说，并不需要所有这些依赖项。它们来自安装 Express.js。只需查找您想要的内容，然后根据应用程序的需要添加或删除包。

现在，我们将保持原样。`express`命令只是将依赖项添加到我们的`package.json`文件中，并为我们的应用程序创建一个框架。为了实际安装`package.json`文件中列出的这些模块和包，我们需要运行：

```js
$ npm install
```

这个命令将实际安装所有的依赖项。现在，如果我们查看文件结构，我们会看到一个名为`node_modules`的新文件夹被添加。这是我们在该应用程序中安装的所有包的所在地。

现在，我们要做的第一件事是设置一个 Web 服务器。为此，在`app.js`文件中添加以下行：

```js
// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

app.listen(3000, function() { console.log('listening on 3000') })

module.exports = app;

```

现在，运行以下命令：

```js
$ node app.js
```

这将启动我们的应用程序服务器。现在，当我们访问`http://localhost:3000/`URL 时，我们应该能够得到这个：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/e5dbd016-ed59-4dbf-8aeb-ba560d247a0b.png)

就是这样。我们已经成功创建了一个 Express 应用程序。

# Express 路由器

让我们继续学习 Express 路由器。正如本章前面提到的，Express.js 最重要的一个方面之一是为应用程序提供了简单的路由。路由是应用程序的 URL 的定义。如果我们查看`app.js`，我们会看到类似于以下内容的部分：

```js
...
app.use('/', index);
app.use('/users', users);
...
```

这意味着当我们访问一个网页，并且当请求发送到主页时，express 路由器会将其重定向到一个名为`index`的路由器。现在，查看`routes/index.js`，其中包含以下代码：

```js
var express = require('express');
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Express' });
});

module.exports = router;
```

这意味着当我们访问主页时，它会渲染一个名为`index`的页面，该页面位于`views/index.pug`中，并传递一个`title`参数以在页面上显示。现在，查看`views`文件夹中的`index.pug`文件，其中包含以下代码：

```js
extends layout

block content
  h1= title
  p Welcome to #{title}
```

这意味着它使用了`layout.pug`文件的布局，并显示了一个`h1`标题以及一个渲染我们从路由文件传递的标题的段落。因此，输出如下：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/79f3e138-a5bb-4c1b-81e3-bde7992002d1.png)

非常简单和直接了当，对吧？

# 请求对象

请求对象是一个包含有关 HTTP 请求信息的对象。请求的属性有：

+   **query: **这包含有关解析查询字符串的信息。通过`req.query`访问。

+   **params: **这包含有关解析路由参数的信息。通过`req.params`访问。

+   **body: **这包含有关解析请求体的信息。通过`req.body`访问。

# 响应对象

在`req`变量上接收到`request`后，`res`对象是我们作为`response`发送回去的东西。

响应的属性包括：

+   **send: **用于向视图发送响应。通过`res.send`访问。它接受两个参数，状态码和响应体。

+   **status: **如果我们想要发送应用程序的成功或失败，使用`res.status`。这是 HTTP 状态码。

+   **redirect: **当我们想要重定向到特定页面而不是以其他格式发送响应时，使用`res.redirect`。

# MVC 介绍

无论使用何种编程语言，构建应用程序时 MVC 模型都是必不可少的。MVC 架构使得组织应用程序的结构和分离逻辑部分和视图部分变得容易。我们可以随时引入这种 MVC 结构，即使我们已经完成了应用程序的一半。最好的实施时间是在任何应用程序开始时。

顾名思义，它有三个部分：

+   **Model: **应用程序的所有业务逻辑都驻留在这些`models`下。它们处理数据库。它们处理应用程序的所有逻辑部分。

+   **View: **浏览器渲染的一切——用户所见的一切——都由这些视图文件处理。它处理我们发送给客户端的任何内容。

+   **Controller: **`Controllers`基本上连接这些`models`和视图。它负责将在`models`中进行的逻辑计算传递到`views`部分：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/ed9038d2-b132-4c49-abd4-ca54af97f786.png)

在我们构建的应用程序中，不需要实现 MVC 平台。JavaScript 是一种模式不可知的语言，这意味着我们可以创建自己的文件夹结构。与其他编程语言不同，我们可以选择最适合我们的结构。

# 为什么要使用 MVC？

将 MVC 架构应用到我们的应用程序中时，会增加很多好处：

+   清晰地分离业务逻辑和视图。这种分离允许我们在整个应用程序中重用业务逻辑。

+   开发过程变得更快。这是显而易见的，因为各部分被清晰地分离出来。我们只需将视图添加到我们的视图文件夹中，并在`models`文件夹中添加逻辑。

+   修改现有代码变得容易。当多个开发人员在同一个项目上工作时，这非常方便。任何人都可以从任何地方接手应用程序并开始对其进行更改。

# 改变文件夹结构以包含 MVC

现在我们已经了解了足够多关于 MVC 的知识，让我们修改我们创建的应用程序`express_app`的文件结构。首先，我们需要在根目录中创建这三个文件夹。已经有一个视图文件夹，所以我们可以跳过它。让我们继续创建`models`和`controllers`文件夹。

在我们的`app.js`中，我们需要包含我们的控制器文件。为了做到这一点，我们首先要引入一个叫做文件系统的新包。这个模块使得执行与文件相关的操作变得容易，比如读取/写入文件。

因此，要将这个包添加到我们的应用程序中，运行：

```js
$ npm install file-system --save 
```

当我们只想要将一个`node`模块安装到我们的应用程序中时，使用`--save`参数。此外，在安装后，这个包将自动包含在我们的`package.json`中。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/e78d5486-a74d-46e8-8cba-51a0992af1e4.png)

现在，我们需要引入这个模块并使用它来包含控制器中的所有文件。为此，在我们的`app.js`中添加这些代码行。确保在我们的 web 服务器运行代码之前添加这些行：

```js
var index = require('./routes/index');
var users = require('./routes/users');

var app = express();

// Require file system module
var fs = require('file-system');

// Include controllers
fs.readdirSync('controllers').forEach(function (file) {
 if(file.substr(-3) == '.js') {
 const route = require('./controllers/' + file)
 route.controller(app)
 }
})

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');
```

让我们继续添加一个路由到我们的控制器。让我们在应用程序的根目录中创建一个名为`controllers`的文件夹，并在`controllers`文件夹中添加一个名为`index.js`的文件，并粘贴以下代码：

```js
module.exports.controller = (app) => {
 // get homepage
 app.get('/', (req, res) => {
 res.render('index', { title: 'Express' });
 })
}
```

现在，我们所有的路由都将由控制器文件处理，这意味着我们不需要在控制路由的`app.js`中的代码。因此，我们可以从文件中删除这些行：

```js
var index = require('./routes/index');
var users = require('./routes/users');

app.use('/', index);
app.use('/users', users);
```

实际上，我们不再需要`routes`文件夹。让我们也删除`routes`文件夹。

同样，让我们添加一个新的路由来控制所有与用户相关的操作。为此，在`controllers`文件夹中添加一个名为`users.js`的新文件，并在其中粘贴以下代码：

```js
module.exports.controller = (app) => {
 // get users page
 app.get('/users', (req, res) => {
 res.render('index', { title: 'Users' });
 })
}
```

现在，让我们重新启动我们的应用程序的 node 服务器： 

```js
$ node app.js
```

有了这个，当我们访问`http://localhost:3000/users`时，我们将能够看到以下内容：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/f1e95c69-0473-449b-952c-2451add9a98e.png)

我们已经成功设置了 MVC 架构的`controllers`和`views`部分。我们将在后续章节中更多地涵盖`models`部分。

在上一章中，我们谈到了 GitHub 以及如何使用它来通过进行小的提交来制作代码历史。不要忘记设置一个 repo 并持续将代码推送到 GitHub。

npm 软件包存储在`node_modules`目录中，我们不应该将其推送到 GitHub。为了忽略这些文件，我们可以添加一个名为`.gitignore`的文件，并指定我们不想推送到 GitHub 的文件。

让我们在我们的应用程序中创建一个名为`.gitignore`的文件，并添加以下内容：

```js
node_modules/
```

这样，当我们安装任何软件包时，它不会显示为提交到 GitHub 时的代码差异。

每次我们对代码进行更改时，都必须重新启动我们的`node`服务器，这非常耗时。为了简化这个过程，`node`提供了一个名为`nodemon`的软件包，它会在我们对代码进行更改时自动重新启动服务器。

要安装软件包，请运行：

```js
$ npm install nodemon --save
```

要运行服务器，请使用以下命令：

```js
$ nodemon app.js
```

# 文件命名约定

在开发应用程序时，我们需要遵循一定的命名约定来命名文件。随着应用程序的构建，我们将拥有大量文件，这可能会变得混乱。MVC 允许在不同文件夹中具有并行命名约定，这可能导致不同文件夹中具有相同的文件名。

如果这是我们发现易于维护的方式，我们也可以处理这样的文件名。否则，我们可以只向每个文件附加文件类型，如以下示例中所示；对于处理与用户相关的活动的控制器文件，我们可以将其保留为`controllers/users.js`，或者将其重命名为`controllers/users_controller.js`。我们将在我们的应用程序中使用`controllers/users`。

对于`models`、`services`或任何其他需要在应用程序中不同区域之间共享的文件夹，情况也是如此。对于这个应用程序，我们将使用以下命名约定：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/2ecb07df-3666-4060-b1af-b197789c09df.png)

记住，在 Node.js 中没有官方的命名约定。我们绝对可以自定义我们发现更简单的方式。我们将在后续章节中讨论更多关于创建`models`的内容。这将要求我们与 Mongo 建立连接，我们将在后续章节中描述。

# 为 Express.js 应用程序创建视图文件

在上一节中，我们学习了如何创建`controllers`。在本节中，我们将讨论如何添加和自定义视图文件。如果你记得，我们在`controllers/users.js`中有这段代码：

```js
module.exports.controller = (app) => {
  // get users page
  app.get('/users', (req, res) => {
    res.render('index', { title: 'Users' });
  })
}
```

让我们更改渲染`index`文件的一行为：

```js
module.exports.controller = (app) => {
  // get users page
  app.get('/users', (req, res) => {
    res.render('users', { title: 'Users' });
  })
}
```

这意味着控制器想要加载`users`文件，该文件位于`views`文件夹中。让我们继续在`views`文件夹中创建一个`users.pug`文件。

创建文件后，粘贴以下代码；这与我们`views`文件夹中的`index.pug`文件中的代码相同：

```js
extends layout

block content
 h1= title
 p Welcome to #{title}
```

现在，如果我们使用`nodemon`，我们不必重新启动服务器；只需重新加载位置为`http://localhost:3000/users`的浏览器。这应该呈现如下内容：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/bd386ef4-752b-4a54-9206-abf4b85a3bd4.png)

现在我们知道如何连接`controllers`和`views`以及如何创建视图文件，让我们对文件的代码有更多了解。

第一行说：

```js
extends layout
```

这意味着它要求扩展已经在`layout.pug`文件中的视图。现在，看看`layout.pug`：

```js
doctype html
html
  head
    title= title
    link(rel='stylesheet', href='/stylesheets/style.css')
  body
    block content
```

这是一个简单的 HTML 文件，包括`doctype`，`HTML`，`head`和`body`标签。在`body`标签内，它说要阻止内容，这意味着它会产生在此`block content`语句下编写的任何其他文件的内容。如果我们看`users.jade`，我们可以看到内容是在`block content`语句下编写的。现在，这非常有用，因为我们不必在创建的每个视图文件中重复整个 HTML 标签。

另外，如果我们查看控制器内的`users.js`，会有一行说：

```js
res.render('users', { title: 'Users' });
```

render 方法有两个参数：它想要加载的视图和要传递给该视图的变量。在这个例子中，`Users`被传递给了 title 变量。在`views`文件夹中的`users.jade`中，我们有：

```js
block content
  h1= title
  p Welcome to #{title}
```

这将在`h1`标签和`p`标签内呈现该变量。这样，我们可以从`controllers`传递任何我们想要的内容到视图中。让我们在`users.js`控制器的`render`方法中添加一个名为`description`的新变量：

```js
module.exports.controller = (app) => {
  // get homepage
  app.get('/users', (req, res) => {
    res.render('users', { title: 'Users', description: 'This is the description of all the users' });
  })
}
```

另外，让我们创建一个在`users.pug`中呈现的地方：

```js
extends layout

block content
  h1= title
  p Welcome to #{title}
  p #{description}
```

如果我们重新加载浏览器，我们会得到：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/cbaf19b7-8457-426c-b195-65b17ac8dd2b.png)

这就是我们为 express 应用程序创建视图的方式。现在，继续根据我们应用程序的需要添加视图。

始终确保将更改提交并推送到 GitHub。提交越小，代码就越易维护。

# 总结

在本章中，我们学习了 Node.js 是什么，Express.js 是什么。我们学习了如何使用 Express.js 创建应用程序，并了解了 MVC 架构。

在下一章中，我们将讨论 MongoDB 及其查询。我们还将讨论使用 Mongoose 进行快速开发以及 Mongoose 查询和验证。


# 第三章：介绍 MongoDB

MongoDB 的名称来源于 huMONGOus 数据一词，意思是它可以处理大量数据。MongoDB 是一种面向文档的数据库架构。它使我们能够更快地开发和扩展。在关系数据库设计中，我们通过创建表和行来存储数据，但是使用 MongoDB，我们可以将数据建模为 JSON 文档，这与关系数据库相比要简单得多。如果我们灵活并且需求经常变化，并且需要进行持续部署，那么 MongoDB 就是我们的选择。作为基于文档的数据模型，MongoDB 也非常灵活。

使用 MongoDB 的最大优势是数据是非结构化的。我们可以按任何格式自定义我们的数据。在关系数据库管理系统中，我们必须精确定义表可以拥有的字段数量，但是使用 MongoDB，每个文档可以拥有自己的字段数量。我们甚至可以添加新数据，而不必担心更改模式，这就是为什么 Mongo 对数据库采用了**无模式设计模型**。

如果我们的业务增长迅速，我们需要更快地扩展，我们需要以更灵活的方式访问数据，如果我们需要对数据进行更改而不必担心更新应用程序的数据库模式，那么 MongoDB 是我们的最佳选择。在关系数据库管理系统中添加新列也会导致一些性能问题。但是，由于 MongoDB 是无模式的，添加新字段可以立即完成，而不会影响我们应用程序的性能。

在关系数据库中，我们使用的术语是**数据库**、**表**和**行**，而在 MongoDB 中，我们分别使用**数据库**、**集合**和**文档**。

以下是本章节将涵盖的内容的简要总结：

+   介绍 MongoDB 以及使用 MongoDB 的好处

+   理解 MongoDB 数据库、集合和文档

+   介绍 Mongoose，创建与 Mongoose 的连接，理解 Mongoose 以及使用 Mongoose 进行 CRUD 操作

+   使用 Mongoose 添加默认和自定义验证

# 为什么选择 MongoDB？

MongoDB 提供了许多优势，其中一些是：

+   **灵活的文档**：MongoDB 集合包含多个文档。每个集合下的文档可以具有可变的字段名称，也可以具有不同的大小，这意味着我们不必定义模式。

+   **没有复杂的关系**：MongoDB 中的文档存储为 JSON 文档，这意味着我们不再需要费心学习应用程序各个组件之间的关系。

+   **易于扩展**：MongoDB 易于扩展，因为它通过使用一种称为分片的分区方法来最小化数据库大小。分片是一种数据库分区方法，允许我们将大型数据库分隔成较小的部分。

# MongoDB 查询

我们在第一章中快速回顾了 Mongo 查询的外观。在这里，我们将深入研究这些查询。

我们需要做的第一件事是启动 MongoDB 服务器。我们可以使用以下命令来做到这一点：

```js
$ mongod
```

现在，让我们通过在终端中输入`mongo`来打开 mongo shell。当我们进入 mongo shell 时，要显示数据库列表，我们输入`show dbs`。

如果在列表中看到数据库，请输入`use {database_name}`来开始使用该数据库。如果我们还没有创建我们的数据库，只需使用`use {database_name}`就会为我们创建一个数据库。就是这么简单。在这个练习中，让我们创建一个名为`mongo_test_queries`的数据库。为此，我们需要使用：

```js
> use mongo_test_queries
```

这应该在终端中输出以下内容：

```js
# switched to db mongo_test_queries
```

现在，一旦我们进入数据库，我们需要的第一件事是一个集合。我们有一个数据库，但没有集合。在 MongoDB 中创建集合的最佳方法是通过插入文档。这不仅初始化了一个集合，还将文档添加到该集合中。就是这么简单。现在，让我们继续进行 Mongo 查询。

# 创建文档

在 MongoDB 中有不同的查询来创建文档，例如`insertOne()`，`insertMany()`和`insert()`。

# insertOne()

`insertOne()`命令将单个文档添加到我们的集合中。例如：

```js
> db.users.insertOne(
 {
 name: "Brooke",
 email: "brooke@app.com",
 address: 'Kathmandu'
 }
)
```

此命令仅接受一个参数，即对象，我们可以传递我们想要的`users`集合的字段名称和值。当我们在 Mongo shell 中的终端中运行上述代码时，我们应该得到以下输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/91f27147-b1ee-4f8f-9121-a09b3d2a3c84.png)

它返回刚刚创建的文档的`_id`。我们已成功在`users`集合中创建了一个集合和一个文档。

`insertOne()`和`insertMany()`命令仅适用于 Mongo 版本 3.2 或更高版本。

# insertMany()

此命令用于将多个文档插入到集合中。在前面的示例中，我们看到`insertOne()`命令接受一个对象作为参数。`insertMany()`命令接受一个数组作为参数，以便我们可以在其中传递多个对象并在集合中插入多个文档。让我们看一个例子：

```js
> db.users.insertMany(
 [
 { name: "Jack", email: "jack@mongo.com" },
 { name: "John", email: "john@mongo.com" },
 { name: "Peter", email: "peter@mongo.com" }
 ]
)
```

此片段在`users`集合中创建了三个文档。当我们运行命令时，输出应该是：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/2a0b35a8-6ce9-4aea-a11d-92c82bda78cf.png)

# insert() 

此命令将单个文档以及多个文档插入到集合中。它可以执行`insertOne()`和`insertMany()`命令的工作。要插入单个文档，我们可以使用：

```js
> db.users.insert(
    { name: "Mike", email: "mike@mongo.com" }
)
```

如果命令成功执行，我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/8a719b2a-0ff8-40a6-aa1a-f68d30c60f64.png)

现在，如果我们要插入多个文档，我们可以简单地使用：

```js
> db.users.insert(
  [
    { name: "Josh", email: "josh@mongo.com" },
    { name: "Ross", email: "ross@mongo.com" },
  ]
)
```

输出应该如下：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/e9a066be-5a9a-49cb-b34e-7d57f8edb430.png)

# 检索文档

在 MongoDB 中检索集合中的文档是使用`find()`命令完成的。有许多使用此命令的方法。

# 查找所有文档

要从集合中检索所有文档，我们可以使用：

```js
> db.users.find()
```

我们也可以使用以下内容：

```js
> db.users.find({})
```

这将输出以下内容：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/493ba105-c15e-4001-bec1-5c33c473e5e8.png)

# 通过过滤器查找文档

我们也可以向`find()`命令添加过滤器。让我们检索名称为`Mike`的文档。为此，我们可以使用：

```js
> db.users.find({ name: 'Mike' })
```

它应该返回以下文档：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/48f4dda2-bd2a-4452-9a6c-6900e11ff9f5.png)

我们还可以使用`AND`或`OR`查询指定多个条件。

要查找名称为`Mike`且电子邮件为`mike@mongo.com`的集合，我们可以简单地使用：

```js
> db.users.find({ name: 'Mike', email: 'mike@mongo.com' })
```

逗号运算符表示`AND`运算符。我们可以使用逗号分隔的值指定尽可能多的条件。前面的命令应该输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/5c263d37-43b8-433c-9a47-ff92862d4fe0.png)

现在，使用`AND`或逗号运算符指定条件很简单。如果要使用 OR 运算符，则应使用：

```js
> db.users.find(
 {
 $or: [ { email: "josh@mongo.com" }, { name: "Mike" } ]
 }
)
```

在这里，我们说：检索那些名称为 Mike 的用户的文档，电子邮件也可以是`josh@mongo.com`。输出如下：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/2fae1443-b58a-48ea-af6a-95deda33f5f3.png)

# 更新文档

就像`insert()`一样，在 MongoDB 中使用`update()`命令有三种方法：`updateOne()`，`updateMany()`和`update()`。

# updateOne()

此命令仅在集合中更新单个文档。在这里，我们插入了一对具有不正确电子邮件的用户条目。对于名称为`Peter`的用户，电子邮件是`jack@mongo.com`。让我们使用`updateOne()`更新此文档：

```js
> db.users.updateOne(
 { "name": "Peter" },
 {
 $set: { "email": "peter@mongo.com" }
 }
 )
```

此命令将更新 Peter 的电子邮件为`peter@mongo.com`。输出为：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/a7c5fd07-4a23-4cad-9dcf-f086003367ba.png)

正如输出所说，`modifiedCount`是`1`，`matchedCount`是`1`，这意味着找到并更新了具有给定条件的文档。

# updateMany()

此命令用于更新集合中的多个文档。使用`updateOne()`和`updateMany()`更新文档的命令相同。要更新多条记录，我们指定条件，然后设置所需的值：

```js
> db.users.updateOne(
 { "name": "Peter" },
 {
 $set: { "email": "peter@mongo.com" }
 }
 )
```

`updateOne()`和`updateMany()`之间的唯一区别是，`updateOne()`只更新匹配的第一个文档，而`updateMany()`更新所有匹配的文档。

# update()

就像插入一样，`update()`命令可以为`updateOne()`和`updateMany()`执行任务。为了避免混淆，我们可以使用`update()`命令而不是`updateOne()`和`updateMany()`：

```js
> db.users.update(
 { "name": "John" },
 {
 $set: { "email": "john@mongo.com" }
 }
 )
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/acd38c2b-330c-44af-bfe4-d799032d7288.png)

# 删除文档

MongoDB 提供了多个命令来从集合中删除和移除文档。

# deleteOne()

`deleteOne()`只从集合中删除单个文档：

```js
> db.users.deleteOne( { name: "John" } )
```

这将删除名为`John`的用户的条目。输出如下：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/4a229e2e-ac94-4654-bb52-3e0fc52b7cf8.png)

正如您在输出中所看到的，`deletedCount`是`1`，这意味着记录已被删除。

# deleteMany()

`deleteMany()`的命令与`deleteOne()`相同。唯一的区别是，`deleteOne()`只删除与匹配过滤器匹配的单个条目，而`deleteMany()`删除所有符合给定条件的文档：

```js
> db.users.deleteMany( { name: "Jack" } )
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/f45587d2-a32a-44c1-88b3-e3a6f6b71bf6.png)

# remove()

`remove()`命令用于从集合中删除单个条目，以及多个条目。如果我们只想删除符合某些条件的单个文档，那么我们可以传递我们希望删除的条目计数。例如，让我们首先创建一个条目：

```js
> db.users.insertOne({ name: 'Mike', email: 'mike@mike.com' })
```

有了这个，现在我们有了两个`Mike`的条目。现在，如果我们想要使用`remove()`来删除一个条目，我们可以这样做：

```js
> db.users.remove({ name: 'Mike' }, 1)
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/9c069d94-4b75-4853-855d-d584cbb13044.png)

如您所见，我们有两个名为`Mike`的条目，但只删除了一个。同样，如果我们想要删除所有文档，我们可以使用：

```js
> db.users.remove({})
```

所有文档将被删除。

我们谈到了如何在 Mongo 中查询文档的基本思想。要了解更多详细信息，请访问[`docs.mongodb.com/v3.2/tutorial/query-documents/`](https://docs.mongodb.com/v3.2/tutorial/query-documents/)。

# 介绍 Mongoose

Mongoose 是一个优雅的 MongoDB 对象建模库，适用于 Node.js。正如我之前提到的，MongoDB 是一个无模式的数据库设计。虽然这有其优点，但有时我们也需要添加一些验证，这意味着为我们的文档定义模式。Mongoose 提供了一种简单的方法来添加这些验证，并对文档中的字段进行类型转换。

例如，要将数据插入 MongoDB 文档，我们可以使用：

```js
> db.posts.insert({ title : 'test title', description : 'test description'})
```

现在，如果我们想要添加另一个文档，并且我们想在该文档中添加一个额外的字段，我们可以使用：

```js
> db.posts.insert({ title : 'test title', description : 'test description', category: 'News'})
```

这在 MongoDB 中是可能的，因为没有定义模式。构建应用程序时也需要这些类型的文档。MongoDB 将默默接受任何类型的文档。但是，有时我们需要让文档看起来相似，以便在某些验证中表现出特定的数据类型。在这种情况下，Mongoose 就派上用场了。我们也可以利用这些功能与原始的 MongoDB 一起使用，但是在 MongoDB 中编写验证是一项极其痛苦的任务。这就是为什么创建了 Mongoose。

Mongoose 是用 Node.js 编写的 Mongo 的数据建模技术。Mongoose 集合中的每个文档都需要固定数量的字段。我们必须明确定义`Schema`并遵守它。Mongoose 模式的一个示例是：

```js
const UserSchema = new Schema({
 name: String,
 bio: String,
 extras: {}
})
```

这意味着名称和描述字段必须是字符串，而额外的字段可以接受一个完整的 JSON 对象，其中我们还可以存储嵌套值。

# 安装 Mongoose

像任何其他包一样，Mongoose 可以通过 NPM 在我们的项目中安装。在我们的终端中运行以下命令，进入我们在上一章中创建的`express_app`文件夹，以在该应用程序中安装 Mongoose：

```js
$ npm install mongoose --save
```

如果成功安装，我们应该在我们的`package.json`文件中添加一行：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/cd4d9ce0-ceaf-45cf-80ca-181b578da24d.png)

# 将 Mongoose 连接到 MongoDB

安装 Mongoose 后，我们必须将其连接到 MongoDB 才能开始使用它。这在 Mongoose 中非常简单；我们只需在`app.js`文件中添加一行代码来`require` Mongoose，并使用`mongoose.connect`方法将其连接到数据库。让我们继续做这件事。在`app.js`文件中，添加以下代码：

```js
var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var mongoose = require('mongoose');
```

这将把 Mongoose 模块导入到我们的代码库中。

要连接到 MongoDB 数据库，将以下代码添加到我们的`app.js`中：

```js
var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var mongoose = require('mongoose');

var app = express();

//connect to mongodb
mongoose.connect('mongodb://localhost:27017/express_app', function() {
 console.log('Connection has been made');
})
.catch(err => {
 console.error('App starting error:', err.stack);
 process.exit(1);
});

// Require file system module
var fs = require('file-system');
```

这样就创建了与我们的 Mongoose 数据库的连接。现在，让我们用以下命令运行应用程序：

```js
$ nodemon app.js
```

并在我们的终端中显示成功或失败的消息：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-dev-vue-node/img/a9f674f8-65fb-4746-9de9-b5347303decc.png)

就是这样！我们已经成功地连接到了我们的 MongoDB 数据库。这里的 URL 是本地托管的数据库 URL。

# 在 Mongoose 中创建记录

让我们从在我们应用的`express_app`中创建一个新的模型开始。在项目的根目录下创建一个名为`models`的文件夹，命名为`User.js`。

我们在文件名的开头字母使用大写字母。此外，我们在`models`中使用单数形式。与此相反，在`controllers`中，我们使用复数形式和小写字母，比如`users.js`。

创建文件后，将以下代码粘贴到其中：

```js
const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const UserSchema = new Schema({
 name: String,
 email: String
})

const User = mongoose.model("User", UserSchema)
module.exports = User
```

这里的第一行只是导入了 Mongoose 模块。这个 Mongoose 包为我们提供了几个属性，其中之一是定义`Schema`。现在，这里的原始`Schema`定义是这个高亮部分：

```js
const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const UserSchema = new Schema({
 name: String,
 email: String
})

const User = mongoose.model("User", UserSchema)
module.exports = User
```

这样做的作用是向我们的`User`数据模型添加验证，其中规定总共必须有两个字段。在创建 Mongoose 集合的文档时，它不会接受一个或两个以上的数据字段。此外，它还向这个`Schema`添加了一个验证层，规定这两个字段，即`name`和`email`都应该是有效的字符串。它不会接受整数、布尔值或其他任何非字符串类型的数据。这是我们如何定义`Schema`的方式：

```js
const mongoose = require("mongoose")
const Schema = mongoose.Schema

const UserSchema = new Schema({
  name: String,
  email: String
})

const User = mongoose.model("User", UserSchema)
module.exports = User
```

代码的高亮部分表示创建模型的方式。方法的第一个参数是我们的模型名称，它映射到集合名称的相应复数版本。因此，当我们创建一个`User`模型时，这自动映射到我们数据库中的`user`集合。

现在，要创建一个用户，首先要做的是创建一个资源：

```js
const user_resource = new User({
  name: 'John Doe',
  email: 'john@doe.com'
})
```

现在，最终创建`user`的部分是：

```js
user_resource.save((error) => {
  if(error)
 console.log(error);

  res.send({
    success: true,
    code: 200,
    msg: "User added!"
  })
})
```

上面的代码使用了一个名为`save`的 Mongoose 函数。`save`方法有一个回调函数，用于错误处理。当我们在保存资源到数据库时遇到错误时，我们可以在那里做任何我们想做的事情：

```js
user_resource.save((error) => {
  if(error)
    console.log(error);

  res.send({
 success: true,
 code: 200,
 msg: "User added!"
 })
})
```

`res.send`方法允许我们设置当资源成功保存到数据库时要发送给客户端的内容。对象的第一个元素是`success: true`，表示执行是否成功。第二个元素是状态码或响应码。`200`响应码表示执行成功。我们在后面的章节中也会讨论这个。最后一个元素是发送给客户端的消息；用户在前端看到这个消息。

这就是我们在 Mongoose 中创建资源的方式。

# 从 Mongoose 中获取记录

现在我们已经成功创建了一个用户，在数据库的`users`集合中有一条记录。有两种方法可以在我们的客户端中获取这条记录：获取我们拥有的所有用户的记录，或者获取特定的用户。

# 获取所有记录

Mongoose 模型中有很多方法可以让我们的生活变得更轻松。其中两种方法是`find()`和`findById()`。在 MongoDB 中，我们看到了如何通过原始的 MongoDB 查询检索集合的记录数据。这是类似的，唯一的区别是 Mongoose 有一种非常简单的方法来做到这一点。我建议你先学习 MongoDB 而不是 Mongoose，因为 MongoDB 可以让你对数据库有一个整体的了解，你将学习数据库的基本知识和查询。Mongoose 只是在 MongoDB 的基础上添加了一层，使其看起来更容易进行快速开发。

有了这个，让我们看一下这里的代码片段：

```js
User.find({}, 'name email', function (error, users) {
  if (error) { console.error(error); }
  res.send({
    users: users
  })
})
```

Mongoose 模型`User`调用了一个名为`find()`的方法。第一个参数是我们的查询字符串，在前面的查询中为空：`{}`。因此，如果我们想要检索所有与相同姓名的用户，比如 Peter，那么我们可以将空的`{}`替换为`{ name: 'Peter'}`。

第二个参数表示我们想要从数据库中检索哪些字段。如果我们想要检索所有字段，可以将其留空，或者在这里指定。在这个例子中，我们只检索用户的姓名和电子邮件。

第三个参数附加了一个回调函数。这个函数有两个参数，不像`create`方法。第一个参数处理错误。如果一些原因，执行没有成功完成，它会返回一个错误，我们可以按照我们的意愿进行自定义。第二个参数在这里很重要；当执行成功完成时，它返回响应。在这种情况下，`users`参数是从`users`集合中检索到的对象数组。这个调用的输出将是：

```js
users: [
  {
    name: 'John Doe',
    email: 'john@doe.com'
  }
]
```

现在我们有了`users`集合中的所有记录。

# 获取特定记录

这也和从集合中获取所有记录一样简单。我们在上一节讨论了使用`find()`。要获取单个记录，我们必须使用`findById()`或`findOne()`，或者我们也可以使用`where`查询。`where`查询与我们之前讨论的相同，当我们需要传递参数以获取属于同一类别的记录时。

让我们继续使用以下查询：

```js
User.findById(1, 'name email', function (error, user) {
  if (error) { console.error(error); }
  res.send(user)
}) 
```

正如你所看到的，`find()`和`findById()`的语法是相似的。它们都接受相同数量的参数并且行为相同。这两者之间唯一的区别是，前者`find()`方法返回一个记录数组作为响应，而`findById()`返回一个单一对象。因此，前面查询的响应将是：

```js
{
    name: 'John Doe',
    email 'john@doe.com'
}
```

就是这样 - 简单！

# 在 Mongoose 中更新记录

让我们继续更新集合中的记录。更新集合记录的方法有多种，就像从集合中检索数据一样。在 Mongoose 中更新文档是`read`和`create`(save)方法的组合。要更新文档，我们首先需要使用 Mongoose 的读取查询找到该文档，修改该文档，然后保存更改。

# findById()和 save()

让我们看一个例子如下：

```js
User.findById(1, 'name email', function (error, user) {
  if (error) { console.error(error); }

  user.name = 'Peter'
  user.email = 'peter@gmail.com'
  user.save(function (error) {
    if (error) {
      console.log(error)
    }
    res.send({
      success: true
    })
  })
})
```

所以，我们需要做的第一件事是找到用户文档，我们通过`findById()`来实现。这个方法返回具有给定 ID 的用户。现在我们有了这个用户，我们可以随意更改这个用户的任何内容。在前面的例子中，我们正在更改该人的姓名和电子邮件。

现在重要的部分。更新这个用户文档的工作是由`save()`方法完成的。我们已经通过以下方式更改了用户的姓名和电子邮件：

```js
user.name = 'Peter'
user.email = 'peter@gmail.com'
```

我们直接更改了通过`findById()`返回的对象。现在，当我们使用`user.save()`时，这个方法会用新的姓名和电子邮件覆盖之前的值。

我们可以使用其他方法来更新 Mongoose 中的文档。

# findOneAndUpdate()

当我们想要更新单个条目时，可以使用这种方法。例如：

```js
User.findOneAndUpdate({name: 'Peter'}, { $set: { name: "Sara" } },   function(err){
  if(err){
    console.log(err);
  }
});
```

正如你所看到的，第一个参数定义了描述我们想要更新的记录的条件，这种情况下是名字为 Peter 的用户。第二个参数是我们定义要更新的`user`的属性的对象，由`{ $set: { name: "Sara" }`定义。这将`Peter`的`name`设置为`Sara`。

现在，让我们对上述代码进行一些小的修改：

```js
User.findOneAndUpdate({name: 'Peter'}, { $set: { name: "Sara" } },   function(err, user){
  if(err){
    console.log(err);
  }
  res.send(user);
});
```

在这里，请注意我向回调函数添加了一个名为`user`的第二个参数。这样做的作用是，当 Mongoose 完成对数据库中文档的更新时，它会返回该对象。当我们想要在更新记录后做出一些决定并且想要使用新更新的文档时，这非常有用。

# findByIdAndUpdate()

这与`findOneAndUpdate()`有些相似。这个方法接受一个 ID 作为参数，不像`findOneAndUpdate()`，在那里我们可以添加自己的条件，并更新该文档：

```js
User.findByIdAndUpdate(1, { $set: { name: "Sara" } },   function(err){
  if(err){
    console.log(err);
  }
});
```

这里唯一的区别是第一个参数接受一个单一的整数值，即文档的 ID，而不是一个对象。这个方法也返回正在更新的对象。所以我们可以使用：

```js
User.findByIdAndUpdate(1, { $set: { name: "Sara" } }, function(err){
  if(err, user){
    console.log(err);
  }
 res.send(user);
});
```

# 在 Mongoose 中删除记录

就像在 Mongoose 中有许多方法来创建、获取和更新记录一样，它也提供了几种方法来从集合中删除记录，比如`remove()`、`findOneAndRemove()`和`findByIdAndRemove()`。我们可以使用`remove()`来删除一个或多个文档。我们也可以先找到我们想要删除的文档，然后使用`remove()`命令只删除这些文档。如果我们想要根据一些条件找到特定的文档，我们可以使用`findOneAndRemove()`。当我们知道要删除的文档的 ID 时，我们可以使用`findByIdAndRemove()`。

# remove()

让我们看一个使用这种方法的示例：

```js
User.remove({
  _id: 1
}, function(err){
  if (err)
    res.send(err)
  res.send({
    success: true
  })
})
```

`remove()`方法的第一个参数是过滤我们想要删除的用户的条件。它接受一个 ID 作为参数。它找到具有给定 ID 的用户并从集合中删除文档。第二个参数是我们之前讨论过的回调函数。如果上述操作出现问题，它会返回一个错误，我们可以用来更好地处理应用程序中发生的异常或错误。在成功的情况下，我们可以定义自己的逻辑来返回什么。在上述情况下，我们返回`{ success: true }`。

# findOneAndRemove

`findOneAndRemove()`的行为方式与`remove()`相同，并且需要相同数量的参数：

```js
User.findOneAndRemove({
  _id: 1
}, function(err){
  if (err)
    res.send(err)
  res.send({
    success: true
  })
})
```

我们只需要定义要删除的文档的条件。

现在，我们也可以修改上述代码：

```js
User.findOneAndRemove({
  _id: 1
}, function(err, user){
  if (err)
    res.send(err)
  res.send({
    success: true,
    user: user
  })
})
```

在这里，我突出显示了添加的代码片段。我们还可以将第二个参数传递给回调函数，该回调函数返回被删除的`user`对象。如果我们想要向前端显示某个消息并添加一些用户属性，比如`user`的`name`或`email`，那么这将非常有用。例如，如果我们想要在前端显示一个消息，说用户{name}已被删除。然后我们可以传递`user`或`user`的其他属性；在这种情况下，它是要在前端显示的名字。

`remove()`和`findOneAndRemove()`之间的主要区别是`remove()`不返回被删除的文档，但`findOneAndRemove()`会。现在我们知道何时使用这两种方法了。

# findByIdAndRemove()

这与`findOneAndRemove()`相同，只是这总是需要一个`id`作为参数传递：

```js
User.findByIdAndRemove(1, function(err){
  if (err)
    res.send(err)
  res.send({
    success: true
  })
})
```

你在`findOneAndRemove()`和前面的`findByIdAndRemove()`的代码之间找到了什么不同吗？如果我们看一下这个方法的第一个参数，它只接受一个简单的整数值，即文档 ID。现在，如果我们看一下前面的`findOneAndRemove()`代码，我们会注意到我们在第一个参数中传递了一个对象。这是因为对于`findOneAndRemove()`，我们可以传递除 ID 之外的不同参数。例如，我们还可以在`findOneAndRemove()`的参数中传递`{ name: 'Anita' }`。但是对于`findByIdAndRemove()`，从方法名称显而易见，我们不需要传递一个对象，而只需要一个表示文档 ID 的整数。

它在参数中查找具有指定 ID 的文档，并从集合中删除该文档。与`findOneAndRemove()`一样，它也返回被删除的文档。

# 使用 Mongoose 添加验证

Mongoose 中的验证是在模式级别定义的。验证可以在字符串和数字中设置。Mongoose 为字符串和数字提供了内置的验证技术。此外，我们也可以根据需要自定义这些验证。由于验证是在模式中定义的，因此当我们对任何文档执行`save()`方法时，它们会被触发。如果我们只想测试这些验证，我们也可以通过`{doc}.validate()`方法执行验证方法。

`validate()`也是中间件，这意味着当我们以异步方式执行某些方法时，它具有控制权。

# 默认验证

让我们谈谈 Mongoose 提供给我们的一些默认验证。这些也被称为内置验证器。

# required()

`required()`验证器检查我们在其上添加了此验证的字段是否有一些值。以前，在`User`模型中，我们有这样的代码：

```js
var mongoose = require("mongoose");
var Schema = mongoose.Schema;

var UserSchema = new Schema({
  name: String,
  email: String
});

var User = mongoose.model("User", UserSchema);
module.exports = User;
```

这段代码也与用户的字段相关联了验证。它要求用户的姓名和电子邮件必须是字符串，而不是数字、布尔值或其他任何东西。但是这段代码并不确保用户的姓名和电子邮件字段已设置。

因此，如果我们想添加`required()`验证，代码应该修改为这样：

```js
var mongoose = require("mongoose");
var Schema = mongoose.Schema;

var UserSchema = new Schema({
  name: {
 required: true
 },
  email: {
 required: true
 }
});

var User = mongoose.model("User", UserSchema);
module.exports = User;
```

如您所见，我们已将 name 键的值更改为对象，而不仅仅是一个字符串。在这里，我们可以添加任意多的验证。因此，添加的验证`required: true`在将该文档保存到集合之前检查用户的姓名和电子邮件是否设置了某些值。如果验证未满足，它将返回错误。

当验证返回错误时，我们还可以传递消息。例如：

```js
var mongoose = require("mongoose");
var Schema = mongoose.Schema;

var UserSchema = new Schema({
  name: {
 required: [true, 'Let us know you by adding your name!']
 },
  email: {
 required: [true, 'Please add your email as well.']
 }
});

var User = mongoose.model("User", UserSchema);
module.exports = User;
```

通过这种方式，我们还可以根据需要自定义消息。很酷，对吧？

# 类型验证

类型验证方法定义了文档中字段的类型。类型的不同变体可以是`String`、`boolean`和`number`。

# 字符串

字符串本身有几个验证器，如`enum`、`match`、`maxlength`和`minlength`。

`maxlength`和`minlength`定义了字符串的长度。

# 数字

数字有两个验证器：`min`和`max`。`min`和`max`的值定义了集合中字段的值范围。

# 自定义验证

如果默认的内置验证不够用，我们还可以添加自定义验证。我们可以传递一个`validate`函数，并在该函数中编写我们的自定义代码。让我们看一个例子：

```js
var userSchema = new Schema({
  phone: {
    type: String,
    validate: {
 validator: function(v) {
 return /\d{3}-\d{3}-\d{4}/.test(v);
 },
 message: '{VALUE} is not a valid phone number!'
 }
  }
});
```

在这里，我们向`Schema`传递了一个`validate`方法。它接受一个验证函数，我们可以在其中添加自己的验证代码。前面的方法检查用户的电话号码字段是否符合正确的格式。如果未通过验证，则显示消息`{value} is not a valid phone number`。

我们还可以在 Mongoose 中添加嵌套验证：例如，如果我们的用户集合中的名称保存为`{ name: { first_name: 'Anita', last_name: 'Sharma' } }`，我们将需要为`first_name`和`last_name`都添加验证。为了做到这一点，我们可以使用：

```js
var nameSchema = new Schema({
  first_name: String,
  last_name: String
});

userSchema = new Schema({
  name: {
    type: nameSchema,
    required: true
  }
});
```

首先，我们为低级对象定义`Schema`，即`first_name`和`last_name`。然后，对于`userSchema`，我们将`nameSchema`传递给名称字段。

请记住，我们不能像这样在单个`Schema`中添加嵌套验证：

```js
var nameSchema = new Schema({
  first_name: String,
  last_name: String
});

personSchema = new Schema({
  name: {
    type: {
      first_name: String,
      last_name: String
    },
    required: true
  }
});
```

您可以在这里查看 Mongoose 验证：[`mongoosejs.com/docs/validation.html`](http://mongoosejs.com/docs/validation.html)。

# 总结

在本章中，我们介绍了关于 MongoDB 及其优势的基本信息，如何在 MongoDB 中进行 CRUD 操作和查询，以及 Mongoose 中的基本验证。

在接下来的章节中，我们将更多地讨论关于 REST API 和我们应用程序中的 RESTful 架构设计。
