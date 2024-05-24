# NodeJS 高级开发（一）

> 原文：[`zh.annas-archive.org/md5/b716b694adad5a9e5b2b3ff42950695d`](https://zh.annas-archive.org/md5/b716b694adad5a9e5b2b3ff42950695d)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

欢迎来到*高级 Node.js 开发*。本书充满了大量的内容、项目、挑战和真实世界的例子，所有这些都旨在通过*实践*来教您 Node。这意味着在接下来的章节中，您将很早就开始动手写一些代码，并且您将为每个项目编写代码。您将编写支持我们应用程序的每一行代码。现在，我们需要一个文本编辑器。

本书中的所有项目都很有趣，旨在教会您启动自己的 Node 应用程序所需的一切，从规划到开发，再到测试和部署。现在，当您启动这些不同的 Node 应用程序并在书中前进时，您将遇到错误，这是不可避免的。也许某些东西没有按预期安装，或者您尝试运行一个应用程序，而不是获得预期的输出，您得到了一个非常长的晦涩错误消息。别担心，我会帮助您。我将在各章节中向您展示通过这些错误的技巧和诀窍。让我们继续并开始吧。

# 这本书适合谁

本书面向任何希望启动自己的 Node 应用程序、转行或作为 Node 开发人员自由职业的人。您应该对 JavaScript 有基本的了解才能跟上本书。

# 本书涵盖内容

第一章，*设置*，将是您本地环境的非常基本的设置。我们将学习安装 MongoDB 和 Robomongo。

第二章，*MongoDB，Mongoose 和 REST API-第一部分*，将帮助您学习如何将您的 Node 应用程序连接到您在本地计算机上运行的 MongoDB 数据库。

第三章，*MongoDB，Mongoose 和 REST API-第二部分*，将帮助您开始使用 Mongoose 并连接到我们的 MongoDB 数据库。

第四章，*MongoDB，Mongoose 和 REST API-第三部分*，在与 Mongoose 玩耍后，将解决查询和 ID 验证问题。

第五章，*使用 Socket.io 创建实时 Web 应用程序*，将帮助您详细了解 Socket.io 和 WebSockets，帮助您创建实时 Web 应用程序。

第六章，*生成 newMessage 和 newLocationMessage*，讨论如何生成文本和地理位置消息。

第七章，*将我们的聊天页面样式化为 Web 应用程序*，继续我们关于样式化我们的聊天页面的讨论，并使其看起来更像一个真正的 Web 应用程序。

第八章，*加入页面和传递房间数据*，继续我们关于聊天页面的讨论，并研究加入页面和传递房间数据。

第九章，*ES7 类*，将帮助您学习 ES6 类语法，并使用它创建用户类和其他一些方法。

第十章，*Async/Await 项目设置*，将带您了解 async/await 的工作过程。

# 为了充分利用本书

要运行本书中的项目，您将需要以下内容：

+   Node.js 的最新版本（在撰写本书时为 9.x.x）

+   Express

+   MongoDB

+   Mongoose

+   Atom

我们将在书的过程中看到其他要求。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)登录或注册。

1.  选择 SUPPORT 选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

文件下载后，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Advanced-Node.js-Development`](https://github.com/PacktPublishing/Advanced-Node.js-Development)。我们还有其他书籍和视频的代码包可供下载，网址为**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**。快去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含了本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/AdvancedNode.jsDevelopment_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/Bookname_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。这里有一个例子：“将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。”

代码块设置如下：

```js
html, body, #map {
 height: 100%; 
 margin: 0;
 padding: 0
}
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目会以粗体显示：

```js
[default]
exten => s,1,Dial(Zap/1|30)
exten => s,2,Voicemail(u100)
exten => s,102,Voicemail(b100)
exten => i,1,Voicemail(s0)
```

任何命令行输入或输出都是这样写的：

```js
$ cd css
```

**粗体**：表示一个新术语，一个重要单词，或者您在屏幕上看到的单词。例如，菜单或对话框中的单词会以这种形式出现在文本中。这里有一个例子：“从管理面板中选择系统信息。”

警告或重要提示会显示在这样的形式下。

提示和技巧会显示在这样的形式下。


# 第一章：设置

在本章中，您将为本书的其余部分设置本地环境。无论您使用的是 macOS、Linux 还是 Windows，我们都将安装 MongoDB 和 Robomongo。

更具体地，我们将涵盖以下主题：

+   Linux 和 macOS 上的 MongoDB 和 Robomongo 安装

+   Windows 上的 MongoDB 和 Robomongo 安装

# 为 Linux 和 macOS 安装 MongoDB 和 Robomongo

这一部分是为 macOS 和 Linux 用户准备的。如果你使用的是 Windows，我已经为你写了一个单独的部分。

我们将首先下载并设置 MongoDB，因为这将是我们将使用的数据库。当我们最终将其部署到 Heroku 时，我们将使用第三方服务来托管我们的数据库，但在我们的本地机器上，我们需要下载 MongoDB，以便我们可以启动数据库服务器。这将让我们通过我们的 Node 应用程序连接到它，以读取和写入数据。

为了获取数据库，我们将前往[mongodb.com](https://www.mongodb.com/)。然后我们可以转到下载页面并下载适当的版本。

在这个页面上，向下滚动并选择 Community Server；这是我们将要使用的。此外，还有不同操作系统的选项，无论是 Windows、Linux、macOS 还是 Solaris。我使用的是 macOS，所以我会使用这个下载：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/a102bcde-1204-422d-a5f9-89241b83256a.png)

如果你在 Linux 上，点击 Linux；然后转到版本下拉菜单并选择适当的版本。例如，如果你在 Ubuntu 14.04 上，你可以从 Linux 选项卡下载正确的版本。然后，你只需点击下载按钮并跟随操作。

接下来你可以打开它。我们将只需提取目录，创建一个全新的文件夹在`Downloads`文件夹中。如果你在 Linux 上，你可能需要手动将该存档的内容解压到`Downloads`文件夹中。

现在这个文件夹包含一个`bin`文件夹，在那里我们有所有需要的可执行文件，以便做一些事情，比如连接到数据库和启动数据库服务器：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/cf592d91-c40c-4267-9e8c-d10d17441e55.png)

在我们继续运行任何命令之前。我们将把这个目录重命名为`mongo`，然后将它移动到`user`目录中。你可以看到现在在`user`目录中，我有`mongo`文件夹。我们还将在`mongo`旁边创建一个全新的目录，名为`mongo-data`，这将存储数据库中的实际数据：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/a5a2c607-ba1b-492f-ba54-8883c2181d75.png)

所以当我们向`Todos`表中插入新记录时，例如，它将存储在`mongo-data`文件夹中。一旦你将`mongo`文件夹移动到`user`目录中，并且你有了新的`mongo-data`文件夹，你就可以准备从终端实际运行数据库服务器了。我将进入终端并导航到`user`目录中的全新`mongo`文件夹，我当前所在的位置，所以我可以`cd`到`mongo`，然后我将通过在那里添加`bin`目录来`cd`进入`bin`目录：

```js
cd mongo/bin
```

从这里，我们有一堆可执行文件可以运行：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/b7f1e04d-e598-4cda-9f34-5567fcbfc0ef.png)

我们有一些东西，比如 bisondump 和 mongodump。在这一部分，我们将专注于：mongod，它将启动数据库服务器，以及 mongo，它将让我们连接到服务器并运行一些命令。就像当我们输入`node`时，我们可以在终端中运行一些 JavaScript 命令一样，当我们输入`mongo`时，我们将能够运行一些 Mongo 命令来插入、获取或对数据进行任何我们喜欢的操作。

不过首先，让我们启动数据库服务器。我将使用`./`来运行当前目录中的文件。我们将要运行的文件名为`mongod`；此外，我们需要提供一个参数：`dbpath`参数。`dbpath`参数将被设置为刚刚创建的目录的路径，即`mongo-data`目录。我将使用`~`（波浪号）来导航到用户目录，然后到`/mongo-data`，如下所示：

```js
./mongod --dbpath ~/mongo-data
```

运行这个命令将启动服务器。这将创建一个活动连接，我们可以连接到这个连接来操作我们的数据。当你运行命令时，你看到的最后一行应该是，等待在端口 27017 上连接：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/6ae32fca-e76e-440c-b799-8e0a4dc89e28.png)

如果你看到这个，这意味着你的服务器已经启动了。

接下来，让我们打开一个新标签，它会在完全相同的目录中启动，这一次，不是运行`mongod`，而是运行`mongo`文件：

```js
./mongo
```

当我们运行`mongo`时，我们打开了一个控制台。它连接到我们刚刚启动的数据库服务器，从这里，我们可以开始运行一些命令。这些命令只是为了测试一切是否按预期工作。我们稍后将详细介绍所有这些内容。不过现在，我们可以访问`db.Todos`，然后我们将调用`.insert`来创建一个全新的 Todo 记录。我会像调用函数一样调用它：

```js
db.Todos.insert({})
```

接下来，在`insert`里，我们将传入我们的文档。这将是我们想要创建的 MongoDB 文档。现在，我们将保持事情非常简单。在我们的对象上，我们将指定一个属性，`text`，将其设置为一个字符串。在引号内，输入任何你想做的事情。我会说`Film new node course`：

```js
db.Todos.insert({text: 'Film new node course'})
```

只要你的命令看起来像这样，你可以按*enter*，然后你应该得到一个带有 nInserted 属性的 WriteResult 对象，这个属性是插入的数量的缩写：一个值设置为 1。这意味着创建了一个新的记录，这太棒了！

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/8386e144-0b90-406d-b53e-74d0b1a6fc5c.png)

现在我们已经插入了一条记录，让我们获取一下记录，以确保一切都按预期工作。

我们将调用`find`而不带任何参数。我们想返回`Todos`集合中的每一个项目：

```js
db.Todos.find()
```

当我运行这个时，我们会得到什么？我们得到一个看起来像对象的东西：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/0010a250-81ef-4691-81e9-47bd8947a807.png)

我们的`text`属性设置为我们提供的文本，我们有一个`_id`属性。这是每条记录的唯一标识符，我们稍后会讨论。只要你看到文本属性回到你设置的内容，你就可以放心了。

我们可以关闭`mongo`命令。但是，我们仍然会让`mongod`命令继续运行，因为我还想安装一件东西。它叫做 Robomongo，它是一个用于管理 Mongo 数据库的图形用户界面。当你开始玩 Mongo 时，这将非常有用。你将能够查看数据库中保存的确切数据；你可以操纵它并做各种各样的事情。

在**Finder**中，我们有我们的`mongo-data`目录，你可以看到这里有很多东西。这意味着我们的数据已经成功保存。所有的数据都在这个`mongo-data`目录中。要下载和安装 Robomongo，它适用于 Linux、Windows 和 macOS，我们将前往[robomongo.org](https://robomongo.org/)并获取适合我们操作系统的安装程序：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/2ae29fa9-116a-4c8e-958a-3e54f5af15ac.png)

我们可以点击下载 Robo 3T 并下载最新版本；它应该会自动检测你的操作系统。下载适用于 Linux 或 macOS 的安装程序。macOS 的安装程序非常简单。这是其中一种你将图标拖到`Applications`文件夹中的安装程序。对于 Linux，你需要解压存档并在`bin`目录中运行程序。这将在你的 Linux 发行版上启动 Robomongo。

由于我使用的是 macOS，我只需快速将图标拖到 Applications 中，然后我们可以玩一下程序本身。接下来，我会在 Finder 中打开它。当你第一次打开 Robomongo 时，你可能会在 macOS 上收到如下警告，因为它是一个我们下载的程序，不是来自已识别的 macOS 开发者：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/86211a5f-5bf6-4de6-ac3a-67ed46de358f.png)

这没问题；大多数从网上下载的程序都不是官方的，因为它们不是来自应用商店。您可以右键单击下载的软件包，选择“打开”，然后再次点击“打开”来运行该程序。当您第一次打开它时，您会看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/0373d4b1-8e34-40fd-b3e6-54fd39c9bd9c.png)

我们有一个小屏幕在后台和一个连接列表；目前该列表为空。我们需要做的是为我们的本地 MongoDB 数据库创建一个连接，以便我们可以连接到它并操作那些数据。我们有创建。我会点击这个，我们唯一需要更新的是名称。我会给它一个更具描述性的名称，比如`本地 Mongo 数据库`。我会将地址设置为`localhost`，`27017`端口是正确的；没有必要更改这些。所以，我会点击“保存”：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/81030b36-1414-4923-aa5d-4b4ff8eebef5.png)

接下来，我将双击数据库以连接到它。在小窗口内，我们有我们的数据库。我们已经连接到它；我们可以做各种事情来管理它。

我们可以打开`test`数据库，在那里，我们应该看到一个`Collections`文件夹。如果我们展开这个文件夹，我们有我们的`Todos`集合，然后，我们可以右键单击该集合。接下来，点击“查看文档”，我们应该会看到我们的一个 Todo 项目，就是我们在 Mongo 控制台中创建的那个：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/b61e0458-1436-4e0a-8e5d-d7f9720297ee.png)

我可以展开它以查看文本属性。电影新节点课程出现了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/923fd0bf-e61a-4b96-ba04-23fce7844409.png)

如果您看到这个，那么您已经完成了。

下一节是给 Windows 用户的。

# 为 Windows 安装 MongoDB 和 Robomongo

如果您使用的是 Windows，这是适合您的安装部分。如果您使用的是 Linux 或 macOS，前一节适合您；您可以跳过这一部分。我们的目标是在我们的计算机上安装 MongoDB，这将让我们创建一个本地 MongoDB 数据库服务器。我们将能够使用 Node.js 连接到该服务器，并且我们将能够读取和写入数据库中的数据。这对于 Todo API 来说将是非常棒的，它将负责读取和写入各种与 Todo 相关的信息。

要开始，我们将通过访问[mongodb.com](https://www.mongodb.com/)来获取 MongoDB 安装程序。在这里，我们可以点击大绿色的下载按钮；此外，我们还可以在此页面上看到几个选项：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/f0efad4b-ffae-4687-8d4d-fc58c0b4dedb.png)

我们将使用 Community Server 和 Windows。如果您转到版本下拉菜单，那里的版本都不适合您。顶部的是我们想要的：Windows Server 08 R2 64 位及更高版本，支持 SSL。让我们开始下载这个。它稍微大一点；稍微超过 100 MB，所以下载需要一些时间才能开始。

我会启动它。这是一个基本的安装程序，您需要点击几次“下一步”并同意许可协议。点击“自定义”选项一会儿，尽管我们将继续选择“完整”选项。当您点击“自定义”时，它会显示您的计算机上将安装在哪里，这很重要。在这里，您可以看到对我来说它在`C:\Program Files\MongoDB\Server`，然后在`3.2`目录中：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/72c4a18a-cc75-4ca9-a154-4f86957e7b0a.jpg)

这将很重要，因为我们需要进入这个目录才能启动 MongoDB 服务器。我会返回，然后我将使用“完整”选项，这将安装我们需要的一切。现在我们实际上可以开始安装过程。通常，您需要点击“是”，以确认您要安装该软件。我会继续这样做，然后我们就完成了。

现在一旦它安装好了，我们将进入命令提示符并启动服务器。我们需要做的第一件事是进入`Program Files`目录。我在命令提示符中。我建议你使用命令提示符而不是 Git Bash。Git Bash 不能用来启动 MongoDB 服务器。我将使用`cd/`来导航到我的机器的根目录，然后我们可以使用以下命令来导航到那个路径：

```js
cd Program Files/MongoDB/Server/3.2
```

这是安装 MongoDB 的目录。我可以使用`dir`来打印出这个目录的内容，我们关心的是`bin`目录：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/db65d9da-c05d-4a66-b6d0-daff0be8ad26.jpg)

我们可以使用`cd bin`进入`bin`，并使用`dir`打印出它的内容。此外，这个目录包含了一大堆我们将用来启动服务器和连接到服务器的可执行文件：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/4b41a0e3-2ab4-4082-9f85-ec32f2e4008f.jpg)

我们将运行的第一个可执行文件是`mongod.exe`。这将启动我们的本地 MongoDB 数据库。在我们继续运行这个`EXE`之前，我们还需要做一件事。在通用文件资源管理器中，我们需要创建一个目录，用来存储我们所有的数据。为了做到这一点，我将把我的放在我的用户目录下，通过转到`C:/Users/Andrew`目录。我将创建一个新文件夹，我会把这个文件夹叫做`mongo-data`。现在，`mongo-data`目录是我们所有数据实际存储的地方。这就是我们在运行`mongod.exe`命令时需要指定的路径；我们需要告诉 Mongo 数据存储在哪里。

在命令提示符中，我们现在可以启动这个命令。我将运行`mongod.exe`，作为`dbpath`参数传入，传入我们刚刚创建的文件夹的路径。在我的情况下，它是`/Users/Andrew/mongo-data`。现在如果你的用户名不同，显然是不同的，或者你把文件夹放在不同的目录中，你需要指定`mongo-data`文件夹的绝对路径。不过，一旦你有了这个，你就可以通过运行以下命令启动服务器：

```js
mongod.exe --dbpath /Users/Andrew/mongo-data
```

你会得到一个很长的输出列表：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/b4e63a72-9dca-452f-93d7-089f0c14db1a.jpg)

你需要关心的唯一一件事是，在最底部，你应该看到等待在端口 27017 上连接。如果你看到这个，那么你就可以开始了。但是现在服务器已经启动，让我们连接到它并发出一些命令来创建和读取一些数据。

# 创建和读取数据

为了做到这一点，我们将打开第二个命令提示符窗口，并使用`cd/Program Files/MongoDB/Server/3.2/bin`进入相同的`bin`目录。从这里，我们将运行`mongo.exe`。请注意，我们不是运行`mongod`命令；我们运行的是`mongo.exe`。这将连接到我们的本地 MongoDB 数据库，并且会让我们进入数据库的命令提示符视图。我们将能够发出各种 Mongo 命令来操作数据，有点像我们可以从命令提示符中运行 Node 来运行各种 JavaScript 语句一样。当我们运行这个命令时，我们将连接到数据库。在第一个控制台窗口中，你可以看到连接被接受的显示。我们确实有了一个新的连接。现在在第一个控制台窗口中，我们可以运行一些命令来创建和读取数据。现在我不指望你从这些命令中得到任何东西。我们暂时不讨论 MongoDB 的细节。我只是想确保当你运行它们时，它能按预期工作。

首先，让我们从控制台创建一个新的 Todo。这可以通过`db.Todos`来完成，在这个 Todos 集合上，我们将调用`.insert`方法。此外，我们将使用一个参数调用`insert`，一个对象；这个对象可以有我们想要添加到记录中的任何属性。例如，我想设置一个`text`属性。这是我实际需要做的事情。在引号内，我可以放一些东西。我会选择`创建新的 Node 课程`。

```js
db.Todos.insert({text: 'Create new Node course'})
```

现在当我运行这个命令时，它将实际地将数据插入到我们的数据库中，我们应该会得到一个`writeResult`对象，其中`nInserted`属性设置为`1`。这意味着插入了一条记录。

现在我们的数据库中有一个 Todo，我们可以尝试再次使用`db.Todos`来获取它。这一次，我们不会调用`insert`来添加记录，而是调用`find`，不提供任何参数。这将返回我们数据库中的每一个 Todo：

```js
db.Todos.find()
```

当我运行这个命令时，我们得到一个看起来像对象的东西，其中有一个`text`属性设置为`Create new Node course`。我们还有一个`_id`属性。`_id`属性是 MongoDB 的唯一标识符，这是他们用来给您的文档，比如说一个 Todo，在这种情况下，一个唯一的标识符。稍后我们会更多地讨论`_id`和我们刚刚运行的所有命令。现在，我们可以使用*Ctrl* + *C*来关闭它。我们已经成功断开了与 Mongo 的连接，现在我们也可以关闭第二个命令提示窗口。

在我们继续之前，我还想做一件事。我们将安装一个名为 Robomongo 的程序——一个用于 MongoDB 的图形用户界面。它将让您连接到本地数据库以及真实数据库，我们稍后会详细介绍。此外，它还可以让您查看所有数据，操纵它，并执行数据库 GUI 中可以执行的任何操作。这非常有用；有时您只需要深入数据库，看看数据的确切样子。

为了开始这个过程，我们将转到一个新的标签页，然后转到[robomongo.org](https://robomongo.org/)。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/08f5d2c2-ca66-4850-94f6-57dd4171d0d6.jpg)

在这里，我们可以通过转到下载来获取安装程序。我们将下载最新版本，我使用的是 Windows。我需要安装程序，而不是便携式版本，所以我会点击这里的第一个链接：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/1939e6e2-86d8-4f12-a51d-48178d002060.jpg)

这将开始一个非常小的下载，只有 17MB，我们可以通过点击“下一步”几次来在我们的机器上安装 Robomongo。

我将开始这个过程，确认安装并点击“下一步”几次。在设置内没有必要进行任何自定义操作。我们将使用所有默认设置运行安装程序。现在我们可以通过完成安装程序中的所有步骤来实际运行程序。当您运行 Robomongo 时，您将会看到一个 MongoDB 连接屏幕：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/d449e05c-b3da-4a11-8460-44fa1f27adc4.jpg)

这个屏幕让您配置 Robomongo 的所有连接。您可能有一个用于本地数据库的本地连接，也可能有一个连接到实际生产数据存储的真实 URL。我们稍后会详细介绍这一切。

现在，我们将点击“创建”。默认情况下，您的`localhost`地址和`27017`端口不需要更改：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/6a98e947-9493-464c-b5ac-f5480792bd9a.jpg)

我要做的就是更改名称，使其更容易识别。我会选择`Local Mongo Database`。现在，我们可以保存我们的新连接，并通过双击连接到数据库。当我们这样做时，我们会得到一个数据库的树形视图。我们有这个`test`数据库；这是默认创建的一个，我们可以展开它。然后我们可以展开我们的`Collections`文件夹，看到`Todos`集合。这是我们在控制台内创建的集合。我会右键单击它，然后转到“查看文档”。当我查看文档时，我实际上可以查看到单独的记录：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/cc419081-dcaf-4f7a-a631-4623a539008b.jpg)

在这里，我看到了我的 _id 和 text 属性，它们在上面的图像中显示为 Create new Node course。

如果您看到这个，那么这意味着您有一个本地的 Mongo 服务器在运行，并且这也意味着您已经成功地向其中插入了数据。

# 总结

在这一章中，你下载并运行了 MongoDB 数据库服务器。这意味着我们有一个本地数据库服务器，可以从我们的 Node 应用程序连接到它。我们还安装了 Robomongo，它让我们连接到本地数据库，这样我们就可以查看和操作数据。当你调试或管理数据，或者对你的 Mongo 数据库进行其他操作时，这将非常方便。我们将在整本书中使用它，你将在后面的章节中开始看到它为什么是有价值的。不过，现在你已经准备好了。你可以继续开始构建 Todo API 了。


# 第二章：MongoDB、Mongoose 和 REST API – 第一部分

在本章中，您将学习如何将您的 Node 应用程序连接到您在本地计算机上运行的 MongoDB 数据库。这意味着我们将能够在我们的 Node 应用程序内部发出数据库命令，执行诸如插入、更新、删除或读取数据等操作。如果我们要制作 Todo REST API，这将是至关重要的。当有人访问我们的 API 端点时，我们希望操作数据库，无论是读取所有的 Todos 还是添加一个新的。然而，在我们做任何这些之前，我们必须先学习基础知识。

# 连接到 MongoDB 并写入数据

要从 Node.js 内部连接到我们的 MongoDB 数据库，我们将使用 MongoDB 团队创建的一个 npm 模块。它被称为 node-mongodb-native，但它包括了你需要连接和与数据库交互的所有功能。要找到它，我们将谷歌搜索`node-mongodb-native`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/d2d25ad4-75ae-45ac-ba0e-26abbda50968.png)

GitHub 仓库，应该是第一个链接，是我们想要的——node-mongodb-native 仓库——如果我们向下滚动，我们可以看一下一些重要的链接：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/c02996e6-da4d-4ffa-8612-721523ea48e4.png)

首先是文档，还有我们的 api-docs；当我们开始探索这个库内部的功能时，这些将是至关重要的。如果我们在这个页面上继续向下滚动，我们会发现大量关于如何入门的示例。我们将在本章中讨论很多这些内容，但我想让你知道你可以在哪里找到其他资源，因为 mongodb-native 库有很多功能。有整个课程专门致力于 MongoDB，甚至都没有涵盖这个库内置的所有功能。

我们将专注于 Node.js 应用程序所需的 MongoDB 的重要和常见子集。要开始，让我们打开上图中显示的文档。当你进入文档页面时，你必须选择你的版本。我们将使用 3.0 版本的驱动程序，有两个重要的链接：

+   **参考链接：** 这包括类似指南的文章，入门指南和其他各种参考资料。

+   **API 链接：** 这包括您在使用该库时可用的每个单独方法的详细信息。当我们开始创建我们的 Node Todo API 时，我们将在此链接上探索一些方法。

不过，现在我们可以开始为这个项目创建一个新目录，然后我们将安装 MongoDB 库并连接到我们正在运行的数据库。我假设您在本章的所有部分中都已经运行了您的数据库。我在我的终端中的一个单独标签页中运行它。

如果您使用的是 Windows，请参考 Windows 安装部分的说明来启动您的数据库，如果您忘记了。如果您使用的是 Linux 或 macOS 操作系统，请使用我已经提到的说明，并且不要忘记也包括`dbpath`参数，这对于启动 MongoDB 服务器至关重要。

# 为项目创建一个目录

首先，我要在桌面上为 Node API 创建一个新文件夹。我将使用`mkdir`创建一个名为`node-todo-api`的新文件夹。然后，我可以使用`cd`进入该目录，`cd node-todo-api`。从这里，我们将运行`npm init`，这将创建我们的`package.json`文件，并允许我们安装我们的 MongoDB 库。再次，我们将使用回车键跳过所有选项，使用每个默认值：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/08418c55-f4af-4d52-8f3c-239701eb5c9f.png)

一旦我们到达结尾，我们可以确认我们的选择，现在我们的`package.json`文件已经创建。接下来我们要做的是在 Atom 中打开这个目录。它在桌面上，`node-todo-api`。接下来，在项目的根目录中，我们将创建一个新文件夹，我将称这个文件夹为`playground`。在这个文件夹里，我们将存储各种脚本。它们不会是与 Todo API 相关的脚本；它们将是与 MongoDB 相关的脚本，所以我希望将它们放在文件夹中，但我不一定希望它们成为应用的一部分。我们将像以前一样使用`playground`文件夹。

在`playground`文件夹中，让我们继续创建一个新文件，我们将称这个文件为`mongodb-connect.js`。在这个文件中，我们将通过加载库并连接到数据库来开始。现在，为了做到这一点，我们必须安装库。从终端，我们可以运行`npm install`来完成这项工作。新的库名称是`mongodb`；全部小写，没有连字符。然后，我们将继续指定版本，以确保我们都使用相同的功能，`@3.0.2`。这是写作时的最新版本。在版本号之后，我将使用`--save`标志。这将把它保存为常规依赖项，它已经是：

```js
npm install mongodb@3.0.2 --save
```

我们需要这个来运行 Todo API 应用程序。

# 将`mongodb-connect`文件连接到数据库。

现在安装了 MongoDB，我们可以将其移动到我们的`mongodb-connect`文件并开始连接到数据库。我们需要做的第一件事是从我们刚刚安装的库中提取一些东西，那就是`mongodb`库。我们要找的是一个叫做`MongoClient`的构造函数。`MongoClient`构造函数允许您连接到 Mongo 服务器并发出命令来操作数据库。让我们继续创建一个名为`MongoClient`的常量。我们将把它设置为`require`，并且我们将要求我们刚刚安装的库`mongodb`。从那个库中，我们将取出`MongoClient`：

```js
const MongoClient = require('mongodb').MongoClient; 
```

现在`MongoClient`已经就位，我们可以调用`MongoClient.connect`来连接到数据库。这是一个方法，它接受两个参数：

+   第一个参数是一个字符串，这将是您的数据库所在的 URL。现在在生产示例中，这可能是 Amazon Web Services URL 或 Heroku URL。在我们的情况下，它将是本地主机 URL。我们稍后会谈论这个。

+   第二个参数将是一个回调函数。回调函数将在连接成功或失败后触发，然后我们可以适当地处理事情。如果连接失败，我们将打印一条消息并停止程序。如果成功，我们可以开始操作数据库。

# 将字符串添加为第一个参数

对于我们的第一个参数，我们将从`mongodb://`开始。当我们连接到 MongoDB 数据库时，我们要使用像这样的 mongodb 协议：

```js
MongoClient.connect('mongodb://')
```

接下来，它将在本地主机上，因为我们在本地机器上运行它，并且我们已经探索了端口：`27017`。在端口之后，我们需要使用`/`来指定我们要连接的数据库。现在，在上一章中，我们使用了测试数据库。这是 MongoDB 给你的默认数据库，但我们可以继续创建一个新的。在`/`之后，我将称数据库为`TodoApp`，就像这样：

```js
MongoClient.connect('mongodb://localhost:27017/TodoApp'); 
```

# 将回调函数添加为第二个参数

接下来，我们可以继续提供回调函数。我将使用 ES6 箭头（`=>`）函数，并且我们将通过两个参数。第一个将是一个错误参数。这可能存在，也可能不存在；就像我们过去看到的那样，如果实际发生了错误，它就会存在；否则就不会存在。第二个参数将是`client`对象。这是我们可以用来发出读写数据命令的对象：

```js
MongoClient.connect('mongodb://localhost:27017/TodoApp', (err, client) => { 

});
```

# mongodb-connect 中的错误处理

现在，在写入任何数据之前，我将继续处理可能出现的任何错误。我将使用一个`if`语句来做到这一点。如果有错误，我们将在控制台上打印一条消息，让查看日志的人知道我们无法连接到数据库服务器，`console.log`，然后在引号内放上类似`Unable to connect to MongoDB server`的内容。在`if`语句之后，我们可以继续记录一个成功的消息，类似于`console.log`。然后，在引号内，我们将使用`Connected to MongoDB server`：

```js
MongoClient.connect('mongodb://localhost:27017/TodoApp', (err, client) => {
  if(err){
    console.log('Unable to connect to MongoDB server');
  }
  console.log('Connected to MongoDB server');
});
```

现在，当你处理这样的错误时，即使错误块运行，成功代码也会运行。我们要做的是在`console.log('Unable to connect to MongoDB server');`行之前添加一个`return`语句。

这个`return`语句并没有做什么花哨的事情。我们所做的只是使用它来阻止函数的其余部分执行。一旦从函数返回，程序就会停止，这意味着如果发生错误，消息将被记录，函数将停止，我们将永远看不到这条`Connected to MongoDB server`消息：

```js
if(err) { 
    return console.log('Unable to connect to MongoDB server'); 
  } 
```

使用`return`关键字的替代方法是添加一个`else`子句，并将我们的成功代码放在`else`子句中，但这是不必要的。我们可以只使用我更喜欢的`return`语法。

现在，在运行这个文件之前，我还想做一件事。在我们的回调函数的最底部，我们将在 db 上调用一个方法。它叫做`client.close`：

```js
MongoClient.connect('mongodb://localhost:27017/TodoApp', (err, client) => {
  if(err) { 
    return console.log('Unable to connect to MongoDB server'); 
  } 
  console.log('Connected to MongoDB server');
  const db = client.db('TodoApp');
  client.close(); 
}); 
```

这关闭了与 MongoDB 服务器的连接。现在我们已经有了这个设置，我们实际上可以保存`mongodb-connect`文件并在终端内运行它。它现在还没有做太多事情，但它确实会工作。

# 在终端中运行文件

在终端中，我们可以使用`node playground`作为目录运行文件，文件本身是`mongodb-connect.js`：

```js
node playground/mongodb-connect.js
```

当我们运行这个文件时，我们会得到`Connected to MongoDB server`打印到屏幕上：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/9407d5a3-011f-4cbe-90eb-9c4a31b55d58.png)

如果我们进入我们拥有 MongoDB 服务器的选项卡，我们可以看到我们有一个新的连接：连接已接受。正如你在下面的截图中所看到的，该连接已关闭，这太棒了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/6f1192b4-66da-47e3-bde5-7f094bbc762f.png)

使用 Mongo 库，我们能够连接，打印一条消息，并从服务器断开连接。

现在，你可能已经注意到我们在 Atom 中的`MongoClient.connect`行中更改了数据库名称，但我们实际上并没有做任何事情来创建它。在 MongoDB 中，与其他数据库程序不同，你不需要在开始使用之前创建数据库。如果我想启动一个新的数据库，我只需给它一个名称，比如`Users`。

现在我有一个`Users`数据库，我可以连接到它并对其进行操作。没有必要先创建该数据库。我将继续将数据库名称更改回`TodoApp`。如果我们进入 Robomongo 程序并连接到我们的本地数据库，你还会看到我们唯一拥有的数据库是`test`。`TodoApp`数据库甚至从未被创建过，即使我们连接到它。Mongo 不会创建数据库，直到我们开始向其中添加数据。我们现在可以继续做到这一点。

# 向数据库添加数据

在 Atom 中，在我们调用`db.close`之前，我们将向集合中插入一条新记录。这将是 Todo 应用程序。在这个应用程序中，我们将有两个集合：

+   一个`Todos`集合

+   一个`Users`集合

我们可以继续通过调用`db.collection`向`Todos`集合添加一些数据。`db.collection`方法以要插入的集合的字符串名称作为其唯一参数。现在，就像实际数据库本身一样，您不需要首先创建此集合。您只需给它一个名称，比如`Todos`，然后可以开始插入。无需运行任何命令来创建它：

```js
db.collection('Todos')
```

接下来，我们将使用集合中可用的一个方法`insertOne`。`insertOne`方法允许您将新文档插入到集合中。它需要两个参数：

+   第一个将是一个对象。这将存储我们希望在文档中拥有的各种键值对。

+   第二个将是一个回调函数。当事情失败或顺利进行时，将触发此回调函数。

您将获得一个错误参数，可能存在，也可能不存在，您还将获得结果参数，如果一切顺利，将会提供：

```js
const MongoClient = require('mongodb').MongoClient;

MongoClient.connect('mongodb://localhost:27017/TodoApp', (err, client) => {
  if(err){
    console.log('Unable to connect to MongoDB server');
  }
  console.log('Connected to MongoDB server');
  const db = client.db('TodoApp');
  db.collection('Todos').insertOne({
    text: 'Something to do',
    completed: false
  }, (err, result) => {

  });
  client.close();
});
```

在错误回调函数本身内部，我们可以添加一些代码来处理错误，然后我们将添加一些代码来在成功添加时将对象打印到屏幕上。首先，让我们添加一个错误处理程序。就像我们之前做的那样，我们将检查错误参数是否存在。如果存在，那么我们将简单地使用`return`关键字打印一条消息，以阻止函数继续执行。接下来，我们可以使用`console.log`打印`无法插入 todo`。我将传递给`console.log`的第二个参数将是实际的`err`对象本身，这样如果有人查看日志，他们可以看到出了什么问题：

```js
db.collection('Todos').insertOne({ 
  text: 'Something to do', 
  completed: false 
}, (err, result) => { 
  if(err){ 
    return console.log('Unable to insert todo', err); 
  }
```

在我们的`if`语句旁边，我们可以添加我们的成功代码。在这种情况下，我们要做的只是将一些内容漂亮地打印到`console.log`屏幕上，然后我将调用`JSON.stringify`，我们将继续传入`result.ops`。`ops`属性将存储所有插入的文档。在这种情况下，我们使用了`insertOne`，所以它只会是我们的一个文档。然后，我可以添加另外两个参数，对于筛选函数是`undefined`，对于缩进是`2`：

```js
db.collection('Todos').insertOne({ 
  text: 'Something to do', 
  completed: false 
}, (err, result) => { 
  if(err){ 
    return console.log('Unable to insert todo', err); 
  }

  console.log(JSON.stringify(result.ops, undefined, 2)); 
}); 
```

有了这个，我们现在可以继续执行我们的文件，看看会发生什么。在终端中，我将运行以下命令：

```js
node playground/ mongodb-connect.js
```

当我执行命令时，我们会收到成功消息：`已连接到 MongoDB 服务器`。然后，我们会得到一个插入的文档数组：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/bc451fb0-aae9-404f-9d73-cb56589083ef.png)

现在正如我所提到的，在这种情况下，我们只插入了一个文档，如前面的屏幕截图所示。我们有`text`属性，由我们创建；我们有`completed`属性，由我们创建；我们有`_id`属性，由 Mongo 自动添加。`_id`属性将是接下来部分的主题。我们将深入讨论它是什么，为什么存在以及为什么它很棒。

目前，我们将继续注意它是一个唯一标识符。这是一个仅分配给此文档的 ID。这就是使用 Node.js 将文档插入到您的 MongoDB 数据库中所需的全部内容。我们可以在 Robomongo 中查看此文档。我将右键单击连接，然后单击刷新：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/3618889d-f9e2-4b28-9548-d34f9e2f0315.png)

这显示了我们全新的`TodoApp`数据库。如果我们打开它，我们会得到我们的`Collections`列表。然后我们可以进入`Collections`，查看文档，我们得到了什么？我们得到了我们的一个 Todo 项目。如果我们展开它，我们可以看到我们有我们的 _id，我们有我们的文本属性，我们有我们的完成布尔值：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/952d1c7e-fe2e-40e3-a249-8ac9ca3e4b68.png)

在这种情况下，Todo 未完成，因此`completed`值为`false`。现在，我希望您将一个新记录添加到集合中。这将是本节的挑战。

# 向集合中添加新记录

在 Atom 中，我希望您从`db.collection`一直到回调的底部，将代码注释掉。然后，我们将继续添加一些内容。在`db.close()`之前，您将输入`Insert new doc into the Users collection`。这个文档将有一些属性。我希望您给它一个`name`属性；将其设置为您的名字。然后，我们将给它一个`age`属性，最后但并非最不重要的是我们可以给它一个`location`字符串。我希望您使用`insertOne`插入该文档。您需要将新的集合名称传递给集合方法。然后，再往下，您将添加一些错误处理代码，并将操作打印到屏幕上。重新运行文件后，您应该能够在终端中查看您的记录，并且应该能够刷新。在 Robomongo 中，您应该看到新的 Users 集合，并且应该看到您指定的用户的名称、年龄和位置。

希望您能够成功将一个新文档插入到 Users 集合中。为了完成这个任务，您需要调用`db.collection`，这样我们就可以访问我们想要插入的集合，这种情况下是`Users`：

```js
//Insert new doc into Users(name, age, location)
db.collection('Users')
```

接下来，我们需要调用一个方法来操作`Users`集合。我们想要插入一个新文档，所以我们将使用`insertOne`，就像我们在上一小节中所做的那样。我们将把两个参数传递给`insertOne`。第一个是要插入的文档。我们将给它一个`name`属性；我将把它设置为`Andrew`。然后，我们可以设置`age`等于`25`。最后，我们将`location`设置为我的当前位置，`Philadelphia`：

```js
//Insert new doc into Users(name, age, location)
db.collection('Users').insertOne({
  name: 'Andrew',
  age: 25,
  location: 'Philadelphia'
}
```

我们要传入的下一个参数是我们的回调函数，它将在错误对象和结果一起被调用。在回调函数内部，我们将首先处理错误。如果有错误，我们将继续将其记录到屏幕上。我将返回`console.log`，然后我们可以放置消息：`Unable to insert user`。然后，我将添加错误参数作为`console.log`的第二个参数。接下来，我们可以添加我们的成功案例代码。如果一切顺利，我将使用`console.log`将`result.ops`打印到屏幕上。这将显示我们插入的所有记录：

```js
//Insert new doc into Users(name, age, location)
db.collection('Users').insertOne({
  name: 'Andrew',
  age: 25,
  location: 'Philadelphia'
}, (err, result) => {
  if(err) {
    return console.log('Unable to insert user', err);
  }
  console.log(result.ops);
});
```

现在我们可以继续使用*向上*箭头键和*回车*键在终端内重新运行文件：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/1efe9b45-0509-4625-9bcf-cf85ef2e1968.png)

我们得到了我们插入的文档数组，只有一个。`name`、`age`和`location`属性都来自我们，`_id`属性来自 MongoDB。

接下来，我希望您验证它是否确实被插入到 Robomongo 中。通常，当您添加一个新的集合或新的数据库时，您可以右键单击连接本身，单击刷新，然后您应该能够看到添加的所有内容：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/029bbfea-6826-4ece-ac25-f10f834c5966.png)

如前面的屏幕截图所示，我们有我们的 Users 集合。我可以查看 Users 的文档。我们得到了一个文档，其中名称设置为 Andrew，年龄设置为 25，位置设置为 Philadelphia。有了这个，我们现在完成了。我们已经能够使用 Node.js 连接到我们的 MongoDB 数据库，还学会了如何使用这个 mongo-native 库插入文档。在下一节中，我们将深入研究 ObjectIds，探讨它们究竟是什么，以及它们为什么有用。

# ObjectId

现在您已经将一些文档插入到 MongoDB 集合中，我想花一点时间谈谈 MongoDB 中的`_id`属性，因为它与您可能已经使用过的其他数据库系统（如 Postgres 或 MySQL）中的 ID 有些不同。

# MongoDB 中的 _id 属性

为了开始我们对`_id`属性的讨论，让我们继续重新运行`mongodb-connect`文件。这将向 Users 集合中插入一个新的文档，就像我们在`db.collection`行中定义的那样。我将通过在节点中运行文件来做到这一点。它在`playground`文件夹中，文件本身叫做`mongodb-connect.js`：

```js
node playground/mongodb-connect.js
```

我将运行命令，然后我们将打印出插入的文档：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/dc75c923-aecb-4897-9cde-e6938420c025.png)

正如我们过去所看到的，我们得到了我们的三个属性，以及 Mongo 添加的一个属性。

关于这个的第一件事是，它不是一个自动递增的整数，就像对于 Postgres 或 MySQL 一样，第一条记录的 ID 是 1，第二条记录的 ID 是 2。Mongo 不使用这种方法。Mongo 被设计为非常容易扩展。扩展意味着你可以添加更多的数据库服务器来处理额外的负载。

想象一下，你有一个每天大约有 200 个用户的 Web 应用程序，你当前的服务器已经准备好处理这个流量。然后，你被某个新闻媒体选中，有 1 万人涌入你的网站。使用 MongoDB，很容易启动新的数据库服务器来处理额外的负载。当我们使用随机生成的 ID 时，我们不需要不断地与其他数据库服务器通信，以检查最高递增值是多少。是 7 吗？是 17 吗？这并不重要；我们只是简单地生成一个新的随机 ObjectId，并将其用于文档的唯一标识符。

现在，ObjectId 本身由几个不同的部分组成。它是一个 12 字节的值。前四个字节是时间戳；我们稍后会谈论这个。这意味着我们在数据中有一个内置的时间戳，指的是 ID 创建时刻的时间。这意味着在我们的文档中，我们不需要有一个`createdAt`字段；它已经编码在 ID 中了。

接下来的三个字节是机器标识符。这意味着如果两台计算机生成 ObjectId，它们的机器 ID 将是不同的，这将确保 ID 是唯一的。接下来，我们有两个字节，进程 ID，这只是另一种创建唯一标识符的方式。最后，我们有一个 3 字节的计数器。这类似于 MySQL 会做的。这只是 ID 的 3 个字节。正如我们已经提到的，我们有一个时间戳，它将是唯一的；一个机器标识符；一个进程 ID；最后，只是一个随机值。这就是 ObjectId 的组成部分。

ObjectId 是`_id`的默认值。如果没有提供任何内容，你确实可以对该属性做任何你喜欢的事情。例如，在`mongodb-connect`文件中，我可以指定一个`_id`属性。我将给它一个值，所以让我们用`123`；在末尾加上逗号；这是完全合法的：

```js
db.collection('Users').insertOne({
  _id: 123,
  name: 'Andrew',
  age: 25,
  location: 'Philadelphia'
}
```

我们可以保存文件，并使用*上*箭头键和*回车*键重新运行脚本：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/dfbb1afb-2704-4061-b756-9cdefb890c9e.png)

我们得到了我们的记录，其中`_id`属性是`123`。`ObjectId`是 MongoDB 创建 ID 的默认方式，但你可以为 ID 创建做任何你喜欢的事情。在 Robomongo 中，我们可以刷新我们的 Users 集合，然后得到我们的文档：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/201195b7-8371-478d-a7a1-988e81213e14.png)

我们有我们在上一节中创建的一个，以及我们刚刚创建的两个，都有一个唯一的标识符。这就是为什么唯一的 ID 非常重要。在这个例子中，我们有三个属性：名称、年龄和位置，它们对所有记录都是相同的。这是一个合理的做法。想象两个人需要做同样的事情，比如买东西。仅仅那个字符串是不够唯一标识一个 Todo 的。另一方面，ObjectId 是唯一的，这就是我们将用来将诸如 Todos 之类的事物与诸如`Users`之类的事物关联起来的东西。

接下来，我想看一下我们在代码中可以做的一些事情。正如我之前提到的，时间戳被嵌入在这里，我们实际上可以将其提取出来。在 Atom 中，我们要做的是移除`_id`属性。时间戳只有在使用`ObjectId`时才可用。然后，在我们的回调函数中，我们可以继续将时间戳打印到屏幕上。

```js
db.collection('Users').insertOne({
  name: 'Andrew',
  age: 25,
  location: 'Philadelphia'
}, (err, result) => {
  if(err) {
    return console.log('Unable to insert user', err);
  }

  console.log(result.ops);
});
```

如果你记得，`result.ops`是一个包含所有插入的文档的数组。我们只插入一个，所以我将访问数组中的第一个项目，然后我们将访问`_id`属性。这将正如你所想的那样：

```js
console.log(result.ops[0]._id);
```

如果我们保存文件并从终端重新运行脚本，我们只会得到`ObjectId`打印到屏幕上：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/288d7028-2bd9-4e7e-8fc1-fab1a9e60a0c.png)

现在，我们可以在`_id`属性上调用一个方法。

# 调用`.getTimestamp`函数

我们要调用的是`.getTimestamp`。`getTimestamp`是一个函数，但它不需要任何参数。它只是返回 ObjectId 创建的时间戳：

```js
console.log(result.ops[0]._id.getTimestamp()); 
```

现在，如果我们继续重新运行我们的程序，我们会得到一个时间戳：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/7d48f1c5-d083-463a-859e-3c4a91749924.png)

在前面的截图中，我可以看到 ObjectId 是在 2016 年 2 月 16 日 08:41 Z 创建的，所以这个时间戳确实是正确的。这是一个绝妙的方法，可以准确地确定文档是何时创建的。

现在，我们不必依赖 MongoDB 来创建我们的 ObjectIds。在 MongoDB 库中，他们实际上给了我们一个可以随时运行的函数来创建一个 ObjectId。暂时，让我们继续注释掉我们插入的调用。

在文件的顶部，我们将改变我们的导入语句，加载 MongoDB 的新内容，并且我们将使用 ES6 的对象解构来实现这一点。在我们实际使用它之前，让我们花一点时间来谈谈它。

# 使用对象解构 ES6

对象解构允许你从对象中提取属性以创建变量。这意味着如果我们有一个名为`user`的对象，并且它等于一个具有`name`属性设置为`andrew`和一个年龄属性设置为`25`的对象，如下面的代码所示：

```js
const MongoClient = require('mongodb').MongoClient;

var user = {name: 'andrew', age: 25};
```

我们可以很容易地将其中一个提取到一个变量中。比如说，我们想要获取名字并创建一个`name`变量。要在 ES6 中使用对象解构，我们将创建一个变量，然后将其包裹在花括号中。我们将提供我们想要提取的名字；这也将是变量名。然后，我们将把它设置为我们想要解构的对象。在这种情况下，那就是`user`对象：

```js
var user = {name: 'andrew', age: 25};
var {name} = user;
```

我们已经成功解构了`user`对象，取出了`name`属性，创建了一个新的`name`变量，并将其设置为任何值。这意味着我可以使用`console.log`语句将`name`打印到屏幕上：

```js
var user = {name: 'andrew', age: 25};
var {name} = user;
console.log(name);
```

我将重新运行脚本，我们得到`andrew`，这正是你所期望的，因为这是`name`属性的值：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/724333b0-a6d8-4e53-b09d-2266f7b30fdc.png)

ES6 解构是从对象的属性中创建新变量的一种绝妙方式。我将继续删除这个例子，并且在代码顶部，我们将改变我们的`require`语句，以便使用解构。

在添加任何新内容之前，让我们继续并将 MongoClient 语句切换到解构；然后，我们将担心抓取那个新东西，让我们能够创建 ObjectIds。我将复制并粘贴该行，并注释掉旧的，这样我们就可以参考它。

```js
// const MongoClient = require('mongodb').MongoClient;
const MongoClient = require('mongodb').MongoClient;
```

我们要做的是在`require`之后删除我们的`.MongoClient`调用。没有必要去掉那个属性，因为我们将使用解构代替。这意味着在这里我们可以使用解构，这需要我们添加花括号，并且我们可以从 MongoDB 库中取出任何属性。

```js
const {MongoClient} = require('mongodb');
```

在这种情况下，我们唯一拥有的属性是`MongoClient`。这创建了一个名为`MongoClient`的变量，将其设置为`require('mongodb')`的`MongoClient`属性，这正是我们在之前的`require`语句中所做的。

# 创建 objectID 的新实例

现在我们有了一些解构，我们可以很容易地从 MongoDB 中取出更多的东西。我们可以添加一个逗号并指定我们想要取出的其他东西。在这种情况下，我们将取出大写的`ObjectID`。

```js
const {MongoClient, ObjectID} = require('mongodb');
```

这个`ObjectID`构造函数让我们可以随时创建新的 ObjectIds。我们可以随心所欲地使用它们。即使我们不使用 MongoDB 作为我们的数据库，创建和使用 ObjectIds 来唯一标识事物也是有价值的。接下来，我们可以通过首先创建一个变量来创建一个新的 ObjectId。我会称它为`obj`，并将其设置为`new ObjectID`，将其作为一个函数调用：

```js
const {MongoClient, ObjectID} = require('mongodb');

var obj = new ObjectID(); 
```

使用`new`关键字，我们可以创建`ObjectID`的一个新实例。接下来，我们可以使用`console.log(obj)`将其记录到屏幕上。这是一个普通的 ObjectId：

```js
console.log(obj); 
```

如果我们从终端重新运行文件，我们会得到你期望的结果：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/f429516c-25b3-4fae-8689-052b7c4c1ceb.png)

我们得到了一个看起来像 ObjectId 的东西。如果我再次运行它，我们会得到一个新的；它们都是唯一的：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/b2b1feb5-0446-44b9-b276-e57ae9a9279e.png)

使用这种技术，我们可以在任何地方都使用 ObjectIds。我们甚至可以生成我们自己的 ObjectIds，将它们设置为我们文档的`_id`属性，尽管我发现让 MongoDB 为我们处理这些繁重的工作要容易得多。我将继续删除以下两行，因为我们实际上不会在脚本中使用这段代码：

```js
var obj = new ObjectID();
console.log(obj);
```

我们已经了解了一些关于 ObjectIds 的知识，它们是什么，以及它们为什么有用。在接下来的章节中，我们将看看我们可以如何与 MongoDB 一起工作的其他方式。我们将学习如何读取、删除和更新我们的文档。

# 获取数据

现在你知道如何向数据库插入数据了，让我们继续讨论如何从中获取数据。我们将在 Todo API 中使用这种技术。人们会想要填充一个他们需要的所有 Todo 项目的列表，并且他们可能想要获取有关单个 Todo 项目的详细信息。所有这些都需要我们能够查询 MongoDB 数据库。

# 在 Robomongo 文件中获取 todos

现在，我们将基于`mongodb-connect`创建一个新文件。在这个新文件中，我们将从数据库中获取记录，而不是插入记录。我将创建一个副本，将这个新文件称为`mongodb-find`，因为`find`是我们将用来查询数据库的方法。接下来，我们可以开始删除当前插入记录的所有注释掉的代码。让我们开始尝试从我们的 Todos 集合中获取所有的 Todos。现在，如果我转到 Robomongo 并打开`Todos`集合，我们只有一条记录：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/c2f51586-1c3b-4789-bdef-5628eaa6ce3a.png)

为了使这个查询更有趣一些，我们将继续添加第二个。在 Robomongo 窗口中，我可以点击插入文档。Robomongo 可以删除、插入、更新和读取所有的文档，这使它成为一个很棒的调试工具。我们可以随时添加一个新的文档，其中`text`属性等于`Walk the dog`，我们还可以附加一个`completed`值。我将`completed`设置为`false`：

```js
{
  text : "Walk the dog",
  completed : false
}
```

现在，默认情况下，我们不会提供`_id`属性。这将让 MongoDB 自动生成那个 ObjectId，而在这里我们有我们的两个 Todos：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/98401436-3619-4b3e-ade6-1924c766d1fe.png)

有了这个，让我们继续在 Atom 中运行我们的第一个查询。

# find 方法

在 Atom 中，我们要做的是访问集合，就像我们在`mongodb-connect`文件中使用`db.collection`一样，将集合名称作为字符串传递。这个集合将是`Todos`集合。现在，我们将继续使用集合上可用的一个叫做`find`的方法。默认情况下，我们可以不带参数地调用`find`：

```js
db.collection('Todos').find();
```

这意味着我们没有提供查询，所以我们没有说我们想要获取所有已完成或未完成的`Todos`。我们只是说我们想获取所有`Todos`：无论其值如何，一切。现在，调用 find 只是第一步。`find`返回一个 MongoDB 游标，而这个游标并不是实际的文档本身。可能有几千个，那将非常低效。它实际上是指向这些文档的指针，并且游标有大量的方法。我们可以使用这些方法来获取我们的文档。

我们将要使用的最常见的游标方法之一是`.toArray.`它确切地做了你认为它会做的事情。我们不再有游标，而是有一个文档的数组。这意味着我们有一个对象的数组。它们有 ID 属性，文本属性和完成属性。这个`toArray`方法恰好得到了我们想要的东西，也就是文档。`toArray`返回一个 promise。这意味着我们可以添加一个`then`调用，我们可以添加我们的回调，当一切顺利时，我们可以做一些像将这些文档打印到屏幕上的事情。

```js
db.collection('Todos').find().toArray().then((docs) => {

});
```

我们将得到文档作为第一个和唯一的参数，我们还可以添加一个错误处理程序。我们将传递一个错误参数，我们可以简单地打印一些像`console.log(无法获取 todos)`的东西到屏幕上；作为第二个参数，我们将传递`err`对象：

```js
db.collection('Todos').find().toArray().then((docs) => {

}, (err) => { 
  console.log('Unable to fetch todos', err); 
}); 
```

现在，对于成功的情况，我们要做的是将文档打印到屏幕上。我将继续使用`console.log`来打印一条小消息，`Todos`，然后我将再次调用`console.log`。这次，我们将使用`JSON.stringify`技术。我将传递文档，`undefined`作为我们的过滤函数和`2`作为我们的间距。

```js
  db.collection('Todos').find().toArray().then((docs) => {
    console.log('Todos');
    console.log(JSON.stringify(docs, undefined, 2));
  }, (err) => {
    console.log('Unable to fetch todos', err);
  });
```

我们现在有一个能够获取文档，将其转换为数组并将其打印到屏幕上的脚本。现在，暂时地，我将注释掉`db.close`方法。目前，那会干扰我们之前的代码。我们的最终代码将如下所示：

```js
//const MongoClient = require('mongodb').MongoClient;
const {MongoClient, ObjectID} = require('mongodb');

MongoClient.connect('mongodb://localhost:27017/TodoApp', (err, client) => {
  if(err){ 
    console.log('Unable to connect to MongoDB server');
  } 
  console.log('Connected to MongoDB server');
  const db = client.db('TodoApp');

  db.collection('Todos').find().toArray().then((docs) => {
    console.log('Todos');
    console.log(JSON.stringify(docs, undefined, 2));
  }, (err) => {
    console.log('Unable to fetch todos', err);
  });
  //client.close();
});
```

保存文件并从终端运行它。在终端中，我将继续运行我们的脚本。显然，由于我们用 Robomongo 连接到了数据库，它正在某个地方运行；它正在另一个标签页中运行。在另一个标签页中，我可以运行脚本。我们将通过`node`运行它；它在`playground`文件夹中，文件本身叫做`mongodb-find.js`：

```js
node playground/mongodb-find.js
```

当我执行这个文件时，我们将得到我们的结果：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/3c47a41b-466f-4f2a-8554-d765a66781ee.png)

我们有我们的`Todos`数组和我们的两个文档。我们有我们的`_id`，我们的`text`属性和我们的`completed`布尔值。现在，我们有一种在 Node.js 中查询我们的数据的方法。现在，这是一个非常基本的查询。我们获取`Todos`数组中的所有内容，无论它是否具有某些值。

# 编写一个查询以获取特定值

为了基于某些值进行查询，让我们继续切换我们的`Todos`。目前，它们两个的`completed`值都等于`false`。让我们继续将`Walk the dog`的完成值更改为`true`，这样我们就可以尝试只查询未完成的项目。在 Robomongo 中，我将右键单击文档，然后单击编辑文档，然后我们可以编辑值。我将把`completed`值从`false`更改为`true`，然后我可以保存记录：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/b3502cf4-287e-423b-bd7e-91e512b9dc29.png)

在终端内，我可以重新运行脚本来证明它已经改变。我将通过运行*control* + *C*关闭脚本，然后可以重新运行它：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/b94e60a9-afce-4a1a-b615-bc1a35291560.png)

如前面的屏幕截图所示，我们有两个`Todos`，一个`completed`值为`false`，另一个`completed`值为`true`。默认情况下，待办事项应用程序可能只会显示您尚未完成的`Todos`集合。您已经完成的待办事项，比如`Walk the dog`，可能会被隐藏，尽管如果您点击了一个按钮，比如显示所有待办事项，它们可能是可访问的。让我们继续编写一个查询，只获取`completed`状态设置为`false`的`Todos`集合。

# 编写一个查询以获取已完成的待办事项

为了完成这个目标，在 Atom 中，我们将更改调用 find 的方式。我们不再传递`0`个参数，而是传递`1`个参数。这就是我们所谓的查询。我们可以开始指定我们想要查询`Todos`集合的方式。例如，也许我们只想查询`completed`值等于`false`的`Todos`。我们只需设置键值对来按值查询，如下所示：

```js
db.collection('Todos').find({completed: false}).toArray().then((docs) => {
```

如果我在终端中关闭脚本后重新运行我们的脚本，我们只会得到我们的一个待办事项：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/2c632bdf-9012-4b71-acf5-fdccbb9420ad.png)

我们的项目有一个`text`等于`Something to do`。它的`completed`状态为`false`，所以它显示出来。我们的另一个待办事项，`Walk the dog`的`text`属性没有显示出来，因为它已经完成。它不匹配查询，所以 MongoDB 不会返回它。当我们开始根据已完成的值、文本属性或 ID 查询我们的文档时，这将会很有用。让我们花点时间来看看我们如何可以通过 ID 查询我们的`Todos`中的一个。

# 按 ID 查询待办事项

我们需要做的第一件事是从我们的查询对象中删除所有内容；我们不再想要按`completed`值查询。相反，我们将按`_id`属性查询。

现在，为了说明这一点，我将从终端获取`completed`值为`false`的待办事项的 ID。我将使用*command* + *C*进行复制。如果您使用的是 Windows 或 Linux，您可能需要在突出显示 ID 后右键单击，并单击复制文本。现在我已经将文本放入剪贴板，我可以转到查询本身。现在，如果我们尝试像这样添加 ID：

```js
db.collection('Todos').find({_id: ''}).toArray().then((docs) => {
```

它不会按预期工作，因为我们在 ID 属性中拥有的不是一个字符串。它是一个 ObjectId，这意味着我们需要使用之前导入的`ObjectID`构造函数来为查询创建一个 ObjectId。

为了说明这将如何发生，我将继续缩进我们的对象。这将使它更容易阅读和编辑。

```js
db.collection('Todos').find({
  _id: '5a867e78c3a2d60bef433b06'
}).toArray().then((docs) => {
```

现在，我要删除字符串并调用`new ObjectID`。`new ObjectID`构造函数确实需要一个参数：ID，在这种情况下，我们将其存储为字符串。这将按预期工作。

```js
db.collection('Todos').find({
  _id: new ObjectID('5a867e78c3a2d60bef433b06');
})
```

我们在这里所做的是查询`Todos`集合，寻找任何具有与我们拥有的 ID 相等的`_id`属性的记录。现在，我可以保存这个文件，通过重新运行脚本来刷新一下，我们将得到完全相同的待办事项：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/c40589de-95cc-48bc-bcfd-25d7c72ee229.png)

我可以继续将其更改为`Walk the dog`的待办事项，通过复制字符串值，将其粘贴到 ObjectID 构造函数中，并重新运行脚本。当我这样做时，我得到了`Walk the dog`的待办事项，因为那是我查询的 ObjectId。

现在，以这种方式查询是我们将使用 find 的方式之一，但除了`toArray`之外，我们的光标上还有其他方法可用。我们可以通过转到原生驱动程序的文档来探索其他方法。在 Chrome 中，打开 MongoDB 文档-这些是我在上一章中向您展示如何访问的文档-在左侧，我们有光标部分。

如果您点击，我们可以查看光标上可用的所有方法的列表：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/fd2e42a1-88bf-4fc0-a885-e024cf5e2cc4.png)

这是从 find 返回的内容。在列表的最底部，我们有我们的`toArray`方法。我们现在要看的是称为 count 的方法。从以前的内容，您可以继续并点击 count；它将带您到文档；原生驱动程序的文档实际上非常好。这里有您可以提供的所有参数的完整列表。其中一些是可选的，一些是必需的，通常有一个真实世界的例子。接下来，我们可以确切地找出如何使用`count`。

# 实现计数方法

现在，我们将继续在 Atom 中实现`count`。我要做的是将当前查询复制到剪贴板，然后将其注释掉。我将用一个调用`count`替换我们对`toArray`的调用。让我们继续删除我们传递给 find 的查询。我们要做的是计算`Todos`集合中的所有 Todos。我们将不再调用`toArray`，而是调用 count。

```js
db.collection('Todos').find({}).count().then((count) => {
```

正如您在 count 的示例中看到的那样，他们这样调用 count：调用 count，传递一个回调函数，该函数在出现错误或实际计数时调用。您还可以将 promise 作为访问数据的一种方式，这正是我们使用`toArray`的方式。在我们的情况下，我们将使用 promise 而不是传递回调函数。我们已经设置好了 promise。我们需要做的就是将`docs`更改为`count`，然后我们将删除打印 docs 到屏幕的`console.log`调用者。在我们打印 Todos 之后，我们将打印`Todos count`，并传入值。

```js
db.collection('Todos').find({}).count().then((count) => {
   console.log('Todos count:');
}, (err) => {
   console.log('Unable to fetch todos', err);
});
```

这不是一个模板字符串，但我将继续并用一个替换它，用`` ` ``替换引号。现在，我可以传入`count`。

```js
db.collection('Todos').find({}).count().then((count) => {
   console.log(`Todos count: ${count}`);
}, (err) => {
   console.log('Unable to fetch todos', err);
});
```

现在我们已经完成了这一步，我们有一个方法来计算`Todos`集合中的所有`Todos`的数量。 在终端中，我将关闭之前的脚本并重新运行它：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/9fd9155b-32b9-4c22-9771-82a526d89065.png)

我们也得到了`Todos count`，这是正确的。 我们有一个调用 find 返回`Todos`集合中的所有内容的游标。 如果您将所有这些加起来，您将得到这两个 Todo 项目。

再次强调，这些是`count`和`toArray`；它们只是您可以使用的所有出色方法的一个子集。 我们将使用其他方法，无论是 MongoDB 本机驱动程序还是稍后将看到的 Mongoose 库，但现在让我们继续进行挑战，根据您的了解。

# 查询用户集合

要开始，让我们进入 Robomongo，打开`Users`集合，并查看我们在其中的所有文档。 目前我们有五个。 如果您的数量不完全相同，或者您的有点不同，也没关系。 我将突出显示它们，右键单击它们，并单击递归展开。 这将显示我每个文档的所有键值对：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/389ebd7e-0161-4c1b-a31d-bab563cc5621.png)

目前，除了 ID 之外，它们都是相同的。 名字都是 Andrew，年龄是 25，位置是费城。 我将调整其中两个的姓名属性。 我将右键单击第一个文档，并将名称更改为类似`Jen`的内容。 然后，我将继续对第二个文档执行相同的操作。 我将编辑该文档并将名称从`Andrew`更改为`Mike`。 现在我有一个名称为`Jen`的文档，一个名称为`Mike`的文档，还有三个名称为`Andrew`的文档。

我们将查询我们的用户，寻找所有名称等于您在脚本中提供的名称的用户。 在这种情况下，我将尝试查询`Users`集合中名称为`Andrew`的所有文档。 然后，我将它们打印到屏幕上，并且我期望会得到三个回来。 名称为`Jen`和`Mike`的两个不应该出现。

我们需要做的第一件事是从集合中获取。 这将是`Users`集合，而不是本章中使用的`Todos`集合。 在`db.collection`中，我们正在寻找`Users`集合，现在我们将继续调用`find`，传入我们的查询。 我们希望查询所有文档，其中`name`等于字符串`Andrew`。

```js
db.collection('Users').find({name: 'Andrew'})
```

这将返回游标。为了真正地获取这些文档，我们必须调用`toArray`。现在我们有一个 promise；我们可以将`then`调用附加到`toArray`上来对`docs`做一些事情。文档将作为我们成功处理程序的第一个参数返回，并且在函数本身内部，我们可以将文档打印到屏幕上。我将继续使用`console.log(JSON.stringify())`，传入我们的三个经典参数：对象本身，`docs`，`undefined`和`2`来进行格式化：

```js
db.collection('Users').find({name: 'Andrew'}).toArray().then((docs) => {
  console.log(JSON.stringify(docs, undefined, 2));
});
```

有了这个，我们现在就完成了。我们有一个查询，并且它应该可以工作。我们可以通过从终端运行它来进行测试。在终端中，我将关闭之前的连接，然后重新运行脚本：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/4fd344a9-de63-45ff-a7b0-fd5353c06e3b.png)

当我这样做时，我得到了三份文件。它们都有一个`name`等于`Andrew`，这是正确的，因为我们设置的查询。请注意，具有名称等于`Mike`或`Jen`的文档找不到了。

我们现在知道如何向数据库中插入和查询数据。接下来，我们将看看如何删除和更新文档。

# 设置存储库

在我们继续之前，我确实想为这个项目添加版本控制。在这一节中，我们将在本地创建一个新的存储库，创建一个新的 GitHub 存储库，并将我们的代码推送到该 GitHub 存储库中。如果你已经熟悉 Git 或 GitHub，你可以自行操作；你不需要通过这一节。如果你对 Git 还不明白，那也没关系。只需跟着进行，我们将一起完成整个过程。

这一部分将非常简单；这里涉及的内容与 MongoDB 无关。要开始，我将从终端使用`git init`初始化一个新的 Git 存储库。这将初始化一个新的仓库，我随时可以像这样运行`git status`来查看未跟踪的文件：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/8c2070ea-2d27-43e3-b609-f3a4948be5bc.png)

这里有我们的`playground`文件夹，我们希望将其添加到版本控制下，并且有`package.json`。我们还有`node_modules`。我们不想跟踪这个目录。这里包含了我们所有的 npm 库。要忽略`node_modules`，在 Atom 中我们将在项目的根目录下创建`.gitignore`文件。如果你记得的话，这可以让你指定你想要在版本控制之外的文件和文件夹。我将创建一个名为`.gitignore`的新文件。为了忽略`node_modules`目录，我们只需要像这里显示的那样输入它：

```js
node_modules/
```

我将保存文件并从终端重新运行`git status`。我们看到`.gitignore`文件出现了，而`node_modules`文件夹却不见了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/ce67bd02-10cd-4cf0-b6ba-6754e2b5a4aa.png)

接下来，我们要做的是使用两个命令进行第一次提交。首先，我要使用 `git add .` 将所有内容添加到下一个提交中。然后，我可以使用带有 `-m` 标志的 `git commit` 进行提交。这次提交的一个好消息是 `初始提交`：

```js
git add .
git commit -m 'Init commit'
```

在我们离开之前，我想要创建一个 GitHub 仓库并将这段代码上传到上面。这将需要我打开浏览器并转到 [github.com](http://www.github.com)。一旦您登录，我们就可以创建一个新的仓库。我要创建一个新的仓库并给它一个名称：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/e42875c4-0a3d-41cb-8ee9-f150f3c02dcf.png)

我将使用 `node-course-2-todo-api`。如果您愿意，您可以选择其他名称。我要选择这个来保持课程文件的组织。现在我可以继续创建这个仓库，并且正如您可能还记得的，GitHub 实际上给了我们一些有用的命令：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/77b896c2-0987-4c37-a6d7-7fe02ea00204.png)

在这种情况下，我们正在从命令行推送一个现有仓库。我们已经经历了初始化仓库、添加文件和进行第一次提交的步骤。这意味着我可以复制以下两行，然后前往终端并将它们粘贴进去：

```js
git remote add origin https://github.com/garygreig/node-course-2-todo-api.git
git push -u origin master
```

取决于您的操作系统，您可能需要逐个执行这些命令。在 Mac 上，当我尝试粘贴多个命令时，它会运行所有命令，除了最后一个，然后我只需按回车键运行最后一个命令。花点时间为您的操作系统执行这些操作。您可能需要将它们作为一个命令运行，或者您可以粘贴所有内容并按*回车*键。无论哪种方式，我们的代码都被推送到了 GitHub。我可以通过刷新仓库页面来证明它已经推送上去了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/1bd89ea4-3f8b-4cb0-9ff0-194e62d0d9e0.png)

这里我们有所有的源代码、`.gitignore` 文件、`package.json`，还有我们的`playground`目录和我们的 MongoDB 脚本。

到此为止了。下一节我们将探讨如何从 MongoDB 集合中删除数据。

# 删除文档

在本节中，您将学习如何从 MongoDB 集合中删除文档。在深入探讨可以删除多个文档或只删除一个文档的方法之前，我们需要创建几个更多的 Todos。当前，`Todos` 集合仅有两个条目，我们需要更多的条目来演示这些涉及删除的方法。

现在，我有两个。我将继续创建第三个，可以通过右键单击然后转到插入文档...来完成。我们将使用 `text` 属性等于诸如 `吃午饭` 的新文档，并将 `completed` 设置为 `false`：

```js
{
   text: 'Eat lunch',
   completed: false
}
```

现在在保存之前，我会将它复制到剪贴板上。我们将创建一些重复的 Todos，这样我们就可以看到如何基于特定条件删除项目。在这种情况下，我们将删除具有相同文本值的多个 Todos。我将把它复制到剪贴板上，点击保存，然后我将创建两个具有完全相同结构的副本。现在我们有三个除了 ID 不同之外都相同的 Todos，以及两个具有唯一文本属性的 Todos：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/8fc55286-909e-408d-8951-e315c454287f.png)

让我们继续进入 Atom 并开始编写一些代码。

# 探索删除数据的方法

我要复制`mongodb-find`文件，创建一个名为`mongodb-delete.js`的全新文件。在这里，我们将探索删除数据的方法。我还将删除我们在上一部分设置的所有查询。我将保留`db.close`方法的注释，因为我们不想立即关闭连接；这将干扰我们即将编写的这些语句。

现在，我们将使用三种方法来删除数据。

+   第一个将使用的是`deleteMany`。`deleteMany`方法让我们可以针对多个文档并将它们删除。

+   我们还将使用`deleteOne`，它可以定位一个文档并删除它。

+   最后，我们将使用`findOneAndDelete`。`findOneAndDelete`方法让您删除单个项目，并返回这些值。想象一下，我想删除一个 Todo。我删除了 Todo，但我也得到了 Todo 对象，所以我可以告诉用户确切地删除了哪一个。这是一个非常有用的方法。

# `deleteMany`方法

现在，我们将从`deleteMany`开始，并将针对我们刚刚创建的重复项。这一部分的目标是删除 Todos 集合中每一个`text`属性等于`吃午餐`的 Todo。目前，有五个中的三个符合这个条件。

在 Atom 中，我们可以通过执行`db.collection`来开始`db.collection`。这将让我们定位到我们的 Todos 集合。现在，我们可以继续使用`deleteMany`集合方法，传入参数。在这种情况下，我们只需要一个参数，就是我们的对象，这个对象就像我们传递给 find 的对象一样。有了这个，我们可以定位到我们的 Todos。在这种情况下，我们将删除所有`text`等于`吃午餐`的 Todo。

```js
//deleteMany 
db.collection('Todos').deleteMany({text: 'Eat lunch'});
```

在 RoboMongo 中我们没有使用任何标点符号，因此在 Atom 中我们也将避免使用标点符号；它需要完全相同。

现在我们可以添加`then`调用，当成功或失败时执行一些操作。现在，我们将只添加一个成功案例。我们将得到一个返回到回调的结果参数，并且我们可以将其打印到`console.log(result)`屏幕上，稍后我们将看一下这个结果对象的具体内容。

```js
//deleteMany 
db.collection('Todos').deleteMany({text: 'Eat lunch'}).then((result) => {
  console.log(result); 
});
```

有了这个，我们现在有一个可以删除所有`吃午饭`文本值的脚本。让我们继续运行它，看看发生了什么。在终端中，我将运行这个文件。它在`playground`文件夹中，我们刚刚称它为`mongodb-delete.js`：

```js
node playground/mongodb-delete.js
```

现在当我运行它时，我们会得到很多输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/7744c074-3a75-4b6b-8dc0-2d5f890da471.png)

一个真正重要的输出部分，事实上是唯一重要的部分，就在顶部。如果你滚动到顶部，你会看到这个`result`对象。我们将`ok`设置为`1`，表示事情如预期般发生了，我们将`n`设置为`3`。`n`是已删除的记录数。在这种情况下，有三个符合条件的 Todos 被删除了。这就是你如何可以定位和删除许多 Todos。

# `deleteOne`方法

现在，除了`deleteMany`，我们还有`deleteOne`，`deleteOne`的工作方式与`deleteMany`完全相同，只是它删除它看到与条件匹配的第一项，然后停止。

为了确切地说明这是如何工作的，我们将创建两个项目并存放到我们的集合中。如果我刷新一下，你会看到我们现在只有两个文档：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/9a571ad9-8625-46c8-813d-118afc431db6.png)

这些是我们开始的内容。我将再次使用剪贴板中的相同数据插入文档。这次我们只创建两个重复的文档。

# `deleteOne`方法

这里的目标是使用`deleteOne`删除文本等于`吃午饭`的文档，但因为我们使用的是`deleteOne`而不是`deleteMany`，其中一个应该保留，另一个应该被删除。

回到 Atom 中，我们可以通过调用`db.collection`并指定目标集合的名称开始工作。这次又是`Todos`，我们将使用`deleteOne`。`deleteOne`方法需要相同的条件。我们会对`text`等于`吃午饭`的文档进行操作。

这一次，我们只是要删除一个文档，而且我们依然会得到完全相同的结果。为了证明这一点，我会像之前用`console.log(result)`一样打印到屏幕上：

```js
//deleteOne 
db.collection('Todos').deleteOne({text: 'Eat lunch'}).then((result) => {
  console.log(result); 
});
```

有了这个，我们现在重新运行我们的脚本，看看发生了什么。在终端中，我将关闭当前的连接并重新运行它：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/30033a3b-581d-4d26-9540-f20270b17f0a.png)

我们得到一个看起来类似的对象，一堆我们并不关心的无用东西，但是再次滚动到顶部，我们有一个`result`对象，其中`ok`为`1`，被删除的文档数量也是`1`。尽管有多个文档满足了这个条件，但它只删除了第一个，并且我们可以通过转到 Robomongo，右键单击上方，再次查看文档来证明这一点。这次，我们有三个 Todos。

我们仍然有一个带有`吃午饭`文本的 Todos:

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/d13d8b43-2602-4ce3-9343-ca45bc01c592.png)

现在我们知道了如何使用这两种方法，我想来看看我最喜欢的方法。这就是`findOneAndDelete`。

# findOneAndDelete 方法

大多数时候，当我要删除文档时，我只有 ID。这意味着我不知道文本是什么或完成状态是什么，这取决于你的用户界面，这可能非常有用。例如，如果我删除了一个待办事项，也许我想显示，接着说*您删除了说吃午饭的待办事项*，并配备一个小的撤销按钮，以防他们不小心执行了该操作。获取数据以及删除它可以是非常有用的。

为了探索`findOneAndDelete`，我们将再次针对`text`等于`吃午饭`的待办事项进行操作。我将注释掉`deleteOne`，接下来我们可以通过访问适当的集合来开始。方法名为`findOneAndDelete`。`findOneAndDelete`方法接受一组非常相似的参数。我们唯一需要传递的是查询。这将与我们在上一屏幕截图中使用的相同。不过，这一次，让我们直接针对`completed`值设置为`false`的待办事项。

现在有两个符合此查询的待办事项，但再次使用的是`findOne`方法，这意味着它只会定位到它看到的第一个，即带有`text`属性为`有事情要做`的。回到 Atom 中，我们可以通过目标`completed`等于`false`的待办事项完成这个操作。现在，我们不再得到一个带有`ok`属性和`n`属性的结果对象，而是`findOneAndDelete`方法实际上获取了该文档。这意味着我们可以连接一个`then`调用，获取我们的结果，并再次使用`console.log(result)`打印到屏幕上：

```js
//findOneAndDelete
db.collection('Todos').findOneAndDelete({completed: false}).then((result) => {
  console.log(result);
});
```

现在我们有了这个方法，让我们在终端中测试一下。在终端中，我将关闭脚本，然后再次启动它：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/c21e6884-fda6-41aa-aa79-316cdfcf9085.png)

我们可以在结果对象中得到几种不同的东西。我们得到一个设置为`1`的`ok`，让我们知道事情进行得如计划。我们有一个`lastErrorObject`；我们马上就会讨论它；还有我们的`value`对象。这就是我们删除的实际文档。这就是为什么`findOneAndDelete`方法非常方便。它不仅得到了该文档，还删除了它。

现在在这种特殊情况下，`lastErrorObject`中再次只有我们的`n`属性，并且我们可以查看删除的待办事项数。`lastErrorObject`可能还包含其他信息，但只有在使用其他方法时才会发生，所以到时候我们再看。现在，当你删除待办事项时，我们只会得到一个数字。

有了这个方法，我们现在有三种不同的方法可以针对我们的 MongoDB 文档进行定位并删除它们。

# 使用 deleteMany 和 findOneAndDelete 方法

我们将进行一项快速挑战，以测试你的能力。在 Robomongo 中，我们可以查看`Users`集合中的数据。我将打开它，突出显示所有数据，并递归展开，以便我们可以查看：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/93f0f8e8-ab68-4b27-a89e-83c04cd39268.png)

我们有 Jen 的名字；我们有 Mike；我们有 Andrew，Andrew 和 Andrew。这是完美的数据。你的数据可能看起来有些不同，但目标是使用两种方法。首先，查找任何重复项，任何具有与另一个文档名称相同的名称的文档。在这种情况下，我有三个名称为 Andrew 的文档。我想要使用`deleteMany`来定位并删除所有这些文档。我还想使用`findOneAndDelete`来删除另一个文档；无论哪一个都可以。而且我希望你通过 ID 来删除它。

最终，这两个语句都应该在 Robomongo 内显示它们的效果。当完成时，我希望看到这三个文档被删除。它们全部都叫 Andrew，我希望看到名为 Mike 的文档被删除，因为我打算用`findOneAndDelete`方法调用来定位它。

首先，我要编写我的脚本，一个用于删除名称为`Andrew`的用户，一个用于删除 ID 的文档。为了获取 ID，我将继续编辑，并简单地抓取引号内的文本，然后取消更新并移动到 Atom。

# 删除重复文档

首先，我们将尝试去除重复用户，我将使用`db.collection`来实现这一点。我们将针对`Users`集合进行操作，在这种特殊情况下，我们将使用`deleteMany`方法。在这里，我们将尝试删除所有`name`属性等于`Andrew`的用户。

```js
db.collection('Users').deleteMany({name: 'Andrew'});
```

现在我可以追加一个 then 调用来检查成功或错误，或者我可以像这样离开它，这就是我要做的。如果你使用回调或 promise 的 then 方法，那是完全可以的。只要删除发生了，你就可以继续。

# 使用 ID 定位文档

接下来，我将写另一个语句。我们再次针对`Users`集合进行操作。现在，我们将使用`findOneAndDelete`方法。在这种特殊情况下，我将删除`_id`等于我已复制到剪贴板的 ObjectId 的 Todo，这意味着我需要创建一个`new ObjectID`，并且我还需要在引号内传入剪贴板中的值。

```js
db.collection('Users').deleteMany({name: 'Andrew'});

db.collection('Users').findOneAndDelete({
  _id: new ObjectID("5a86978929ed740ca87e5c31")
})
```

单引号或双引号都可以。确保`ObjectID`的大写与你定义的内容完全相同，否则此创建将不会发生。

现在我们创建了`ID`并将其作为`_id`属性传递，我们可以继续添加`then`回调。因为我正在使用`findOneAndDelete`，我打算将那个文档打印到屏幕上。在这里，我将获得我的参数`results`，然后我将使用我们的漂亮打印方法将其打印到屏幕上，`console.log(JSON.stringify())`，传入这三个参数，`results`，`undefined`和间距，我将使用`2`。

```js
db.collection('Users').deleteMany({name: 'Andrew'});

db.collection('Users').findOneAndDelete({
  _id: new ObjectID("5a86978929ed740ca87e5c31")
}).then((results) => {
  console.log(JSON.stringify(results, undefined, 2));
});
```

有了这个，我们现在可以继续了。

# 运行 findOneAndDelete 和 deleteMany 语句

让我们首先注释掉`findOneAndDelete`。我们将运行`deleteMany`语句。在终端中，我可以关闭当前连接，然后再次启动它，如果我们进入 Robomongo，我们应该看到那三个文档已被删除。我将右键单击`Users`并查看文档：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/f0a3f3dc-cabf-4503-bc29-7152fe580144.png)

我们刚刚得到了两个文档。任何名为`Andrew`的都已被删除，这意味着我们的语句按预期运行了，这太棒了。

接下来，我们可以运行我们的`findOneAndDelete`语句。在这种情况下，我们期望那个`name`等于`Mike`的文档被删除。我将确保保存文件。一旦保存，我就可以进入终端并重新运行脚本。这一次，我们获得了`name`为`Mike`的文档。我们确实针对了正确的文档，并且似乎已经删除了一个项目：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/b3fb5a61-5cdd-45ea-85fc-52ebca362ae0.png)

我可以随时通过刷新 Robomongo 中的集合来验证这一点：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/84ba63a2-1cd9-48ff-90df-833865eb2282.png)

我得到了只有一个文档的集合。我们现在结束了。我们知道如何从我们的 MongoDB 集合中删除文档；我们可以删除多个文档；我们可以只针对一个，或者我们可以针对一个并获取其值。

# 为删除文档方法进行提交

在我们离开之前，让我们进行提交并将其推送到 GitHub。在终端中，我可以关闭脚本并运行`git status`以查看我们有未跟踪的文件。这里，我们有我们的`mongodb-delete`文件。我可以使用`git add .`添加它，然后我可以提交，使用带有`-m`标志的`git commit`。在这里，我可以提供提交消息，即`Add delete script`：

```js
git commit -m 'Add delete script'
```

我将进行提交并使用`git push`将其推送到 GitHub，默认情况下将使用 origin 远程仓库。当你只有一个远程仓库时，第一个将被称为 origin。这是默认名称，就像 master 是默认分支一样。有了这个，我们现在就结束了。我们的代码已经上传到 GitHub。下一节的主题是更新，你将学习如何更新集合中的文档。

# 更新数据

你知道如何向 MongoDB 中插入、删除和获取文档。在本节中，你将学习如何更新 MongoDB 集合中的文档。和往常一样，开始之前，我们将复制我们上次写的最后一个脚本，并将其更新用于本节。

我将复制`mongodb-delete`文件，重命名为`mongodb-update.js`，这就是我们将编写更新语句的地方。我还将删除我们写的所有语句，也就是被删除的数据。现在我们已经准备好了，接下来我们将探索本节将要学习的一个方法。这个方法叫做`findOneAndUpdate`。它有点类似于`findOneAndDelete`。它允许我们更新一项内容并获得新文档。所以，如果我更新一个待办事项，将其`completed`设置为`true`，我将在响应中得到那个文档。现在，为了开始，我们将更新我们 Todos 集合中的一项内容。如果查看文档，我们目前有两个。这里的目标将是更新第二项内容，即`text`等于`Eat lunch`的内容。我们将尝试将`completed`值设置为`true`，这将是一个很常见的操作。

如果我勾选一个待办事项，我们希望切换完成的布尔值。回到 Atom 中，我们将通过访问适当的集合来启动事情。那将是`db.collection`。集合名称是`Todos`，我们将使用的方法是`findOneAndUpdate`。现在，`findOneAndUpdate`将使用到目前为止我们使用过的最多参数，所以让我们去查找它的文档以备将来参考。

在 Chrome 中，我们目前打开了“Cursor”选项卡。这是我们定义`count`方法的地方。如果我们滚动到“Cursor”选项卡旁边，我们还有其他选项卡。我们正在寻找的是`Collection`。现在，在`Collection`部分，我们有我们的 typedefs 和方法。我们在这里看的是方法，所以如果我往下滚动，应该能找到`findOneAndUpdate`并单击它。现在，`findOneAndUpdate`需要传入一些参数。第一个是`filter`。`update`参数让我们可以指定要更新的文档。也许我们有文本，或者更有可能的是我们有文档的 ID。接下来是我们想要进行的实际更新。我们不想更新 ID，只想通过 ID 进行筛选。在这种情况下，更新的目标是更新“completed”布尔值。然后我们有一些选项，我们将对其进行定义。我们将仅使用其中之一。我们还有我们的`callback`。我们将继续遵循迄今为止的方式，忽略掉回调，而是使用 promises。正如您在文档页面上所看到的，如果没有传入回调，它会返回一个 promise，这正是我们所期望的。让我们开始填写适当的`findOneAndUpdate`参数，从`filter`开始。我要做的是通过 ID 进行筛选。在 Robomongo 中，我可以获取此文档的 ID。我将编辑它并将 ID 复制到剪贴板中。现在，在 Atom 中，我们可以开始查询第一个对象`filter`。我们只需要查找`_id`等于我们复制到剪贴板中的值的文档。这就是我们需要的`filter`参数。接下来要做的是要应用的实际更新，并且这并不是很直接。我们在这里要做的是了解 MongoDB 的更新操作符。

通过谷歌搜索`mongodb update operators`，我们可以查看完整的这些操作符列表以及它们的确切含义。当我这样做时，我们在寻找[mongodb.com](http://www.mongodb.com)文档：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/6f97eb20-78fa-402b-a775-9cfc27409e28.png)

现在这个文档是专门针对 MongoDB 的，这意味着它适用于所有驱动程序。在这种情况下，它将与我们的 Node.js 驱动程序配合使用。如果我们继续向下滚动，我们可以查看我们可以访问的所有更新操作符。最重要的，也是我们要开始使用的是`$set`操作符。这让我们在更新中设置字段的值，这正是我们想要做的。还有其他操作符，比如增量。这个`$inc`让你增加字段的值，就像我们的`Users`集合中的`age`字段一样。虽然这些操作符非常有用，但我们要开始使用`$set`。要使用这些操作符之一，我们需要将其输入，并将其设置为一个对象。在这个对象中，这些就是我们实际要设置的东西。例如，我们想将`completed`设置为`true`。如果我们尝试像这样在对象的根目录下将`completed`设置为`true`，那么它不会按预期工作。我们必须使用这些更新操作符，这意味着我们需要这个。现在我们已经使用了设置更新操作符来更新我们的更新，我们可以继续提供我们的第三个和最后一个参数。如果你前往`findOneAndUpdate`的文档，我们可以快速查看一下`options`。我们关心的是`returnOriginal`。

`returnOriginal`方法默认为`true`，这意味着它返回原始文档，而不是更新后的文档，我们不希望如此。当我们更新文档时，我们希望得到更新后的文档。我们要做的就是将`returnOriginal`设置为`false`，这将在我们的第三个和最后一个参数中发生。这也将是一个对象，`returnOriginal`将被设置为`false`。

有了这个，我们就完成了。我们可以添加一个`then`调用来对结果进行操作。我将得到我的结果，并可以简单地将其打印到屏幕上，我们可以看一下具体返回了什么：

```js
db.collection('Todos').findOneAndUpdate({ 
  _id: new ObjectID('5a86c378baa6685dd161da6e') 
}, { 
  $set: { 
    completed:true 
  } 
}, { 
  returnOriginal: false 
}).then((result) => { 
  console.log(result); 
}); 
```

现在，让我们从终端运行这个。我将在终端中保存我的文件。我们将运行`node`。文件在`playground`文件夹中，我们将称它为`mongodb-update.js`。我将运行以下脚本：

```js
node playground/mongodb-update.js
```

我们得到了值属性，就像我们使用`findOneAndDelete`时一样，这里有我们的文档，其中`completed`值设置为`true`，这就是我们刚刚设置的全新值，这太棒了。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/6ea4eeaf-5eb6-4035-be14-aa56c0efb3c1.png)

如果我们前往 Robomongo，我们可以确认值确实已经更新。我们可以在旧文档中看到这一点，在那里值为 false。我将为 Todos 打开一个新的视图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/936011e3-b25f-4701-ac2d-f15393c3216f.png)

我们有一个包含值为 true 的吃午餐任务。既然我们已经完成了这一步，我们知道如何在 MongoDB 集合中插入、删除、更新和读取文档了。为了结束这一节，我想给你提供一个快速挑战。在 `Users` 集合中，你应该有一个文档。它应该有一个姓名。它可能不是 `Jen`；它可能是你设置的其他东西。我想让你把这个名字更新为你的名字。如果它已经是你的名字，那就没问题；你可以将它改为其他的东西。我还希望你使用 `$inc`，我们谈论过的增加运算符，将这个值增加 1。现在我不会告诉你增加运算符究竟是如何工作的。我希望你前往文档，点击 `运算符`，然后向下滚动查看示例。每个运算符都有示例。学会如何阅读文档对你变得非常有用。现在，各种库的文档并不总是一样的；每个人都有点不一样的做法；但是一旦你学会了如何阅读一个库的文档，那么阅读其他库的文档就会变得容易得多，而我在这门课程中只能教授一部分知识。这门课程的真正目的是让你编写自己的代码，进行自己的研究，并查阅自己的文档，所以你的目标再次是更新这个文档，将姓名设置为当前设置的其他名称，并将年龄增加 1。

要开始工作，我打算在 Robomongo 中获取文档的 ID，因为这是我想要更新的文档。我会将 ID 复制到剪贴板上，现在我们可以专注于在 Atom 中编写该语句了。首先，我们将更新姓名，因为我们已经知道如何做了。在 Atom 中，我将继续复制该语句：

```js
db.collection('Todos').findOneAndUpdate({
  _id: new ObjectID('57bc4b15b3b6a3801d8c47a2')
}, {
  $set: {
    completed:true
  }
}, {
  returnOriginal: false
}).then((result) => {
  console.log(result);
});
```

我会复制并粘贴它。回到 Atom 中，我们可以开始替换内容。首先，我们将使用新的 ID 替换旧的 ID，并更改我们传递给设置的内容。我们不想更新 `completed`，而是想要更新 `name`。我会将 `name` 设置为除了 `Jen` 之外的其他名称。我将使用我的名字 `Andrew`。现在，我们将保持 `returnOriginal` 设置为 `false`。我们想要拿回新文档，而不是原始文档。现在，我们需要做的另一件事是增加年龄。这将通过增加运算符来完成，你应该已经通过 Chrome 中的文档进行了探索。如果你点击 `$inc`，它会带你到文档的 `$inc` 部分，如果向下滚动，你应该能够看到一个示例。在这里，我们有一个增加的示例：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/ea8c2677-365e-4533-80bb-e53952b498a4.png)

我们像设置 `set` 一样设置 `$inc`。然后，在对象内部，我们指定要递增的内容，以及要递增的程度。可以是`-2`，或者在我们的情况下，它将是正数，`1`。在 Atom 中，我们可以实现这一点，如下所示的代码：

```js
db.collection('Users').findOneAndUpdate({ 
  _id: new ObjectID('57abbcf4fd13a094e481cf2c') 
}, { 
  $set: { 
    name: 'Andrew' 
  }, 
  $inc: { 
    age: 1 
  } 
}, { 
  returnOriginal: false 
}).then((result) => { 
  console.log(result); 
}); 
```

我将 `$inc` 等于一个对象，并在其中，我们将 `age` 递增 `1`。有了这一点，我们现在完成了。在运行这个文件之前，我将把其他对 `findOneAndUpdate` 的调用注释掉，只留下新的。我还需要交换集合。我们不再更新 Todos 集合；我们正在更新`Users` 集合。现在，我们可以开始了。我们将 `name` 设置为 `Andrew`，并将 `age` 递增 `1`，这意味着我们期望 Robomongo 中的年龄为 26 而不是 25。让我们重启终端中的脚本来运行它：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/92d5c78a-7d25-4e19-aad4-155256400d0a.png)

我们可以看到我们的新文档，其中名称确实为 `Andrew`，年龄确实为`26`，这太棒了。既然你知道如何使用递增运算符，你也可以去学习你在更新调用中可用的所有其他运算符。我可以在 Robomongo 中再次检查一切是否按预期工作。我将刷新`Users`集合：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/4bce35a0-d75f-4431-8e26-93dbc12f7e02.png)

我们在这里有我们的更新文档。好了，让我们通过提交更改来结束本节。在终端中，我将运行 `git status` 以查看存储库的所有更改：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/a0f74cdc-051d-4c3b-9a02-3539a35a2383.png)

在这里，我们只有一个未跟踪的文件，我们的`mongodb-update`脚本。我将使用 `git add .` 将其添加到下一次提交中，然后使用 `git commit` 实际进行提交。我将为 `message` 提供 `-m` 参数，以便我们可以指定消息，这将是 `Add update script`：

```js
git add .
git commit -m 'Add update script'
```

现在我们可以运行提交命令并将其推送到 GitHub，这样我们的代码就备份到了 GitHub 存储库中：

```js
git push
```

更新完成后，我们现在已经掌握了所有基本的 CRUD（创建、读取、更新和删除）操作。接下来，我们将讨论一个叫做 Mongoose 的东西，我们将在 Todo API 中使用它。

# 总结

在本章中，我们从连接到 MongoDB 并写入数据开始。然后，我们继续了解了在 MongoDB 上下文中的`id`属性。在学习更多关于获取数据之后，我们探索了在文档中删除数据的不同方法。

在下一章中，我们将继续与 Mongoose、MongoDB 和 REST API 进行更多的操作。


# 第三章：MongoDB，Mongoose 和 REST API - 第二部分

在本章中，您最终将离开`playground`文件夹，并且我们将开始使用 Mongoose。我们将连接到我们的 MongoDB 数据库，创建一个模型，讨论模型的确切含义，最后，我们将使用 Mongoose 向数据库保存一些数据。

# 设置 Mongoose

我们不需要在`playground`目录中打开的任何文件，所以我们可以关闭它们。我们还将使用 Robomongo 清除`TodoApp`数据库。Robomongo 中的数据将与我们将来使用的数据有些不同，最好从头开始。在删除数据库后，无需创建数据库，因为如果您记得，一旦开始向数据库写入数据，MongoDB 将自动创建数据库。有了这个准备，我们现在可以探索 Mongoose，我总是喜欢做的第一件事是查看网站。

你可以通过访问[mongoosejs.com](http://mongoosejs.com/)来查看网站：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/882fe839-f4d9-4eee-8119-1169fcfc4185.png)

在这里，您可以找到示例，指南，插件的完整列表以及大量的优秀资源。我最常使用的是阅读文档资源。它包括类似教程的指南，具有示例，以及覆盖库的每个功能的文档。这真的是一个很棒的资源。

如果您想了解某些内容或者想使用书中未涵盖的功能，我强烈建议您来到这个页面，获取一些例子，复制和粘贴一些代码，玩弄一下，并弄清楚它是如何工作的。我们现在将介绍大部分基本的 Mongoose 功能。

# 设置项目的根目录

在我们实际在项目中使用 Mongoose 之前，我们需要做的第一件事是安装它。在终端中，我将使用`npm i`来安装它，这是`npm install`的缩写。模块名称本身称为`mongoose`，我们将安装最新版本，即`5.0.6`版本。我们将添加`--save`标志，因为我们将需要 Mongoose 用于生产和测试目的。

```js
**npm i mongoose@5.0.6 --save**
```

一旦我们运行这个命令，它就会开始执行。我们可以进入 Atom 并开始创建我们运行应用程序所需的文件。

首先，让我们在项目的根目录中创建一个文件夹。这个文件夹将被称为`server`，与我们的服务器相关的所有内容都将存储在`server`文件夹中。我们将创建的第一个文件将被称为`server.js`。这将是我们应用程序的根。当您想启动您的 Node 应用程序时，您将运行这个文件。这个文件将准备好一切。

我们在`server.js`中需要做的第一件事是加载 Mongoose。我们将创建一个名为`mongoose`的变量，并从`mongoose`库中获取它。

```js
var mongoose = require('mongoose');
```

现在我们已经有了`mongoose`变量，我们需要继续连接到数据库，因为在 Mongoose 知道如何连接之前，我们无法开始向数据库写入数据。

# 连接 mongoose 到数据库

连接的过程将与我们在 MongoDB 脚本中所做的非常相似；例如，`mongodb-connect`脚本。在这里，我们调用了`MongoClient.connect`，传入了一个 URL。对于 Mongoose，我们要做的是调用`mongoose.connect`，传入完全相同的 URL；`mongodb`是协议，调用`//`。我们将连接到我们的`localhost`数据库，端口为`27017`。接下来是我们的`/`，然后是数据库名称，我们将继续使用`TodoApp`数据库，这是我们在`mongodb-connect`脚本中使用的。

```js
var mongoose = require('mongoose');

mongoose.connect('mongodb://localhost:27017/TodoApp');
```

这就是这两个函数的不同之处。`MongoClient.connect`方法接受一个回调函数，那时我们就可以访问数据库。Mongoose 要复杂得多。这是好事，因为这意味着我们的代码可以简单得多。Mongoose 会随着时间维护连接。想象一下，我尝试保存一些东西，`save new something`。现在显然，当这个保存语句运行时，`mongoose.connect`还没有时间去发出数据库请求来连接。那至少需要几毫秒。这个语句几乎会立即运行。

在幕后，Mongoose 将等待连接，然后才会尝试进行查询，这是 Mongoose 的一个巨大优势之一。我们不需要微观管理事情发生的顺序；Mongoose 会为我们处理。

我还想在`mongoose.connect`的上面配置一件事。在这门课程中，我们一直在使用 promises，并且我们将继续使用它们。Mongoose 默认支持回调，但回调并不是我喜欢编程的方式。我更喜欢 promises，因为它们更容易链式、管理和扩展。在`mongoose.connect`语句的上面，我们将告诉 Mongoose 我们想要使用哪个 promise 库。如果你不熟悉 promise 的历史，它并不一定总是内置在 JavaScript 中的。Promise 最初来自像 Bluebird 这样的库。这是一个开发者的想法，他们创建了一个库。人们开始使用它，以至于他们将其添加到了语言中。

在我们的情况下，我们需要告诉 Mongoose 我们想要使用内置的 promise 库，而不是一些第三方的库。我们将把`mongoose.Promise`设置为`global.Promise`，这是我们只需要做一次的事情：

```js
var mongoose = require('mongoose');

mongoose.Promise = global.Promise;
mongoose.connect('mongodb://localhost:27017/TodoApp');
```

我们只需要把这两行放在`server.js`中；我们不需要在其他地方添加它们。有了这个配置，Mongoose 现在已经配置好了。我们已经连接到了我们的数据库，并设置它使用 promises，这正是我们想要的。接下来我们要做的是创建一个模型。

# 创建待办事项模型

现在，正如我们已经讨论过的，MongoDB 中，你的集合可以存储任何东西。我可以有一个具有年龄属性的文档的集合，就是这样。我可以在同一个集合中有一个不同的文档，具有一个名字属性；就是这样。这两个文档是不同的，但它们都在同一个集合中。Mongoose 喜欢保持事情比那更有组织性一些。我们要做的是为我们想要存储的每样东西创建一个模型。在这个例子中，我们将创建一个待办事项模型。

现在，待办事项将具有某些属性。它将有一个`text`属性，我们知道它是一个字符串；它将有一个`completed`属性，我们知道它是一个布尔值。这些是我们可以定义的。我们要做的是创建一个 Mongoose 模型，这样 Mongoose 就知道如何存储我们的数据。

在`mongoose.connect`语句的下面，让我们创建一个名为`Todo`的变量，并将其设置为`mongoose.model`。`model`是我们将用来创建新模型的方法。它接受两个参数。第一个是字符串名称。我将匹配左边的变量名`Todo`，第二个参数将是一个对象。

```js
mongoose.connect('mongodb://localhost:27017/TodoApp');
var Todo = mongoose.model('Todo', {

});
```

这个对象将定义模型的各种属性。例如，待办事项模型将有一个`text`属性，所以我们可以设置它。然后，我们可以将 text 设置为一个对象，并且可以配置 text 的具体内容。我们也可以为`completed`做同样的事情。我们将有一个 completed 属性，并且我们将要指定某些内容。也许它是必需的；也许我们有自定义验证器；也许我们想设置类型。我们还将添加一个最终的属性`completedApp`，这将让我们知道何时完成了一个待办事项：

```js
var Todo = mongoose.model('Todo', {
  text: {

  },
  completed: {

  },
  completedAt: {

  }
});
```

`createdApp`属性可能听起来有用，但如果你记得 MongoDB 的`ObjectId`，它已经内置了`createdAt`时间戳，所以在这里没有理由添加`createdApp`属性。另一方面，`completedAt`将增加价值。它让你确切地知道你何时完成了一个 Todo。

从这里开始，我们可以开始指定每个属性的细节，Mongoose 文档中有大量不同的选项可用。但现在，我们将通过为每个属性指定类型来保持简单，例如`text`。我们可以将`type`设置为`String`。它始终将是一个字符串；如果它是布尔值或数字就没有意义了。

```js
var Todo = mongoose.model('Todo', {
  text: {
    type: String
  },
```

接下来，我们可以为`completed`设置一个类型。它需要是一个布尔值；没有其他办法。我们将把`type`设置为`Boolean`。

```js
  completed: {
    type: Boolean
  },
```

我们最后一个属性是`completedAt`。这将是一个普通的 Unix 时间戳，这意味着它只是一个数字，所以我们可以将`completedAt`的`type`设置为`Number`。

```js
  completedAt: {
    type: Number
  }
});
```

有了这个，我们现在有一个可用的 Mongoose 模型。这是一个具有几个属性的 Todo 模型：`text`，`completed`和`completedAt`。

为了准确说明我们如何创建这些实例，我们将继续添加一个 Todo。我们不会担心获取数据、更新数据或删除数据，尽管这是 Mongoose 支持的功能。我们将在接下来的部分中担心这些问题，因为我们将开始为 API 的各个路由构建。现在，我们将简要介绍如何创建一个全新的 Todo 的示例。

# 创建一个全新的 Todo

我将创建一个名为`newTodo`的变量，尽管你可以给它取任何你喜欢的名字；这里的名字并不重要。但重要的是你运行 Todo 函数。这是从`mongoose.model`返回的构造函数。我们要在它前面加上`new`关键字，因为我们正在创建`Todo`的一个新实例。

现在，`Todo`构造函数确实需要一个参数。它将是一个对象，我们可以在其中指定一些这些属性。也许我们知道我们希望`text`等于`Cook dinner`之类的东西。在函数中，我们可以指定。`text`等于一个字符串，`Cook dinner`：

```js
var newTodo = new Todo({
  text: 'Cook dinner'
});
```

我们还没有要求任何属性，所以我们可以到此为止。我们有一个`text`属性；这已经足够了。让我们继续探讨如何将其保存到数据库。

# 将实例保存到数据库

仅仅创建一个新实例并不会实际更新 MongoDB 数据库。我们需要在`newTodo`上调用一个方法。这将是`newTodo.save`。`newTodo.save`方法将负责将`text`实际保存到 MongoDB 数据库中。现在，`save`返回一个 promise，这意味着我们可以添加一个`then`调用并添加一些回调。

```js
newTodo.save().then((doc) => {

}, (e) => {

});
```

我们将为数据保存成功或出现错误时添加回调。也许连接失败了，或者模型无效。无论如何，现在我们只是打印一个小字符串，`console.log(Unable to save todo)`。在上面的成功回调中，我们实际上将得到那个 Todo。我可以将参数称为`doc`，并将其打印到屏幕上，`console.log`。我将首先打印一条小消息：`Saved todo`，第二个参数将是实际的文档：

```js
newTodo.save().then((doc) => {
  console.log('Saved todo', doc);
}, (e) => {
  console.log('Unable to save todo');
});
```

我们已经配置了 Mongoose，连接到了 MongoDB 数据库；我们创建了一个模型，指定了我们希望 Todos 具有的属性；我们创建了一个新的 Todo；最后，我们将其保存到了数据库中。

# 运行 Todos 脚本

我们将从终端运行脚本。我将通过运行`node`来启动，我们要运行的文件位于`server`目录中，名为`server.js`：

```js
**node server/server.js** 
```

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/ed659d0a-1b42-4d15-a9ad-630e16843426.png)

当我们运行文件时，我们得到`Saved todo`，这意味着事情进行得很顺利。我们在这里有一个对象，有一个预期的`_id`属性；我们指定的`text`属性；和`__v`属性。`__v`属性表示版本，它来自 mongoose。我们稍后会谈论它，但基本上它会跟踪随时间的各种模型更改。

如果我们打开 Robomongo，我们会看到完全相同的数据。我要右键单击连接并刷新它。在这里，我们有我们的`TodoApp`。在`TodoApp`数据库中，我们有我们的`todos`集合：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/b21da561-c5a1-4a56-8a79-7b8f11564915.png)

mongoose 自动将 Todo 转换为小写并复数形式。我要查看文档：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/992de390-402a-4e3b-8587-0738a485e9d1.png)

我们有一个文档，文本等于 Cook dinner，就是我们在 Atom 中创建的。

# 创建第二个 Todo 模型

我们使用我们的 mongoose 模型创建了一个 Todo。我希望你做的是创建第二个，填写所有三个值。这意味着你要创建一个新的 Todo，有一个`text`值，一个`completed`布尔值；继续设置为`true`；和一个`completedAt`时间戳，你可以设置为任何你喜欢的数字。然后，我希望你继续保存它；如果保存成功，将其打印到屏幕上；如果保存不好，打印一个错误。最后，运行它。

我首先要做的是在下面创建一个新变量。我要创建一个名为`otherTodo`的变量，将其设置为`Todo`模型的一个`new`实例。

```js
var otherTodo = new Todo ({

});
```

从这里，我们可以传入我们的一个参数，这将是对象，并且我们可以指定所有这些值。我可以将`text`设置为任何我喜欢的值，例如`Feed the cat`。我可以将`completed`值设置为`true`，我可以将`completedAt`设置为任何数字。任何小于 0 的值，比如-1，都会从 1970 年开始倒数。任何正数都将是我们所在的位置，我们稍后会更多地讨论时间戳。现在，我要选择类似`123`的东西，基本上是 1970 年的两分钟。

```js
var otherTodo = new Todo ({
  text: 'Feed the cat',
  completed: true,
  completedAt: 123
});
```

有了这个，我们现在只需要调用`save`。我要调用`otherTodo.save`。这实际上是要写入到 MongoDB 数据库的。我要添加一个`then`回调，因为我确实想在保存完成后做一些事情。如果`save`方法成功，我们将得到我们的`doc`，我要将其打印到屏幕上。我要使用我们之前谈到的漂亮打印系统，`JSON.stringify`，传入实际对象，`undefined`和`2`。

```js
var otherTodo = new Todo ({
  text: 'Feed the cat',
  completed: true,
  completedAt: 123
});

otherTodo.save().then((doc) => {
  console.log(JSON.stringify(doc, undefined, 2));
})
```

你不需要这样做；你可以以任何你喜欢的方式打印它。接下来，如果事情进行得不好，我要打印一条小消息：`console.log('Unable to save', e)`。它会传递那个错误对象，所以如果有人在阅读日志，他们可以看到调用失败的原因。

```js
otherTodo.save().then((doc) => {
  console.log(JSON.stringify(doc, undefined, 2));
}, (e) => {
  console.log('Unable to save', e);
});
```

有了这个，我们现在可以注释掉那个第一个 Todo。这将阻止创建另一个，我们可以重新运行脚本，运行我们全新的 Todo 创建调用。在终端中，我要关闭旧连接并启动一个新连接。这将创建一个全新的 Todo，我们就在这里：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/b3fac07c-6fb7-4586-8126-aaf2bec1881b.png)

`text`属性等于`Feed the cat`。`completed`属性设置为布尔值`true`；注意它周围没有引号。`completedAt`等于数字`123`；再次，没有引号。我也可以进入 Robomongo 来确认这一点。我要重新获取 Todos 集合，现在我们有两个 Todos：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/13ecf179-7f79-4fc2-b3ff-3f9d73ba92bc.png)

在值列的右侧，你还会注意到类型列。在这里，我们有 int32 用于 completedAt 和 __v 属性。completed 属性是一个布尔值，text 是一个字符串，_id 是一个 ObjectId 类型。

Robomongo 中隐藏了很多有用的信息。如果你想要什么，他们很可能已经内置了。就是这样。我们现在知道如何使用 Mongoose 建立连接，创建模型，最终将该模型保存到数据库中。

# 验证器、类型和默认值

在本节中，你将学习如何改进你的 Mongoose 模型。这将让你添加诸如验证之类的东西。你可以使某些属性成为必需项，并设置智能默认值。因此，如果没有提供类似已完成的东西，你可以设置一个默认值。所有这些功能都内置在 Mongoose 中；我们只需要学会如何使用它。

为了说明为什么我们要设置这些东西，让我们滚动到我们的`server`文件的底部，删除我们创建的`new Todo`上的所有属性。然后，我们将保存文件并进入终端，运行脚本。这将是在`server`目录中的`node`，文件将被称为`server.js`：

```js
**node server/server.js** 
```

当我们运行它时，我们得到了我们的新 Todo，但它只有版本和 ID 属性：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/a2ac5284-4e03-4f07-a75f-b419eaad74f6.png)

我们在模型中指定的所有属性，`text`，`completed`和`completedAt`，都找不到。这是一个相当大的问题。如果它们没有`text`属性，我们不应该将 Todo 添加到数据库中，`completed`之类的东西应该有智能默认值。如果没有人会创建一个已经完成的 Todo 项目，那么`completed`应该默认为`false`。

# Mongoose 验证器

现在，为了开始，我们将在 Mongoose 文档中打开两个页面，这样你就知道这些东西的位置，如果将来想深入了解的话。首先，我们将查找验证器。我将搜索“mongoose 验证器”，这将显示我们内置的所有默认验证属性：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/7a3739ae-5156-4ac0-b21a-7a9f721ba7a7.png)

例如，我们可以将某些东西设置为“必需的”，所以如果没有提供，当我们尝试保存该模型时，它将抛出错误。我们还可以为数字和字符串设置验证器，为字符串设置`minlength`/`maxlength`值。

我们要查看的另一个页面是模式页面。要进入这个页面，我们将搜索“mongoose 模式”。这是第一个页面，`guide.html`文件：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/212abfaf-82d2-4a8f-bbaf-957f2b7b764b.png)

在这个页面上，你将看到与我们迄今为止所做的略有不同的东西。他们称之为“新模式”，设置所有属性。这不是我们到目前为止所做的事情，但将来我们会做。现在，你可以将这个对象，即“模式”对象，视为我们在 Atom 中拥有的对象，作为我们的`mongoose.model`调用的第二个参数传递过去。

# 自定义 Todo 文本属性

为了开始，让我们自定义 Mongoose 如何处理我们的`text`属性。目前，我们告诉 Mongoose 我们希望它是一个字符串，但我们没有任何验证器。我们可以为`text`属性做的第一件事是将`required`设置为`true`。

```js
var Todo = mongoose.model('Todo', {
  text: {
    type: String,
    required: true
  },
```

当你将`required`设置为`true`时，值必须存在，所以如果我尝试保存这个 Todo，它会失败。我们可以证明这一点。我们可以保存文件，转到终端，关闭一切，然后重新启动它：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/c5664fc4-40e1-47a2-baff-0973a8305dc2.png)

我们得到了一个难以理解的错误消息。我们将在一会儿深入研究这个问题，但现在你只需要知道的是，我们得到了一个验证错误：Todo 验证失败，这太棒了。

现在，除了确保`text`属性存在之外，我们还可以设置一些自定义验证器。例如，对于字符串，我们有一个`minlength`验证器，这很棒。你不应该能够创建一个文本为空字符串的 Todo。我们可以将`minlength`设置为最小长度，在这种情况下将是`1`：

```js
var Todo = mongoose.model('Todo', {
  text: {
    type: String,
    required: true,
    minlength: 1
  },
```

现在，即使我们在`otherTodo`函数中提供了一个`text`属性，假设我们将`text`设置为空字符串：

```js
var otherTodo = new Todo ({
  text: ''
});
```

它仍然会失败。它确实存在，但它没有通过`minlength`验证器，其中`minlength`验证器必须是`1`。我可以保存`server`文件，在终端重新启动，我们仍然会失败。

现在，除了`required`和`minlength`之外，文档中还有一些其他实用程序。一个很好的例子是称为`trim`的东西。它对字符串非常有用。基本上，`trim`会修剪掉值的开头或结尾的任何空格。如果我将`trim`设置为`true`，就像这样：

```js
var Todo = mongoose.model('Todo', {
  text: {
    type: String,
    required: true,
    minlength: 1,
    trim: true
  },
```

它将删除任何前导或尾随空格。因此，如果我尝试创建一个`text`属性只是一堆空格的 Todo，它仍然会失败：

```js
var otherTodo = new Todo ({
  text: '      '
});
```

`trim`属性将删除所有前导和尾随空格，留下一个空字符串，如果我重新运行，我们仍然会失败。文本字段无效。如果我们提供有效的值，事情将按预期工作。在`otherTodo`的所有空格中间，我将提供一个真正的 Todo 值，它将是`Edit this video`：

```js
var otherTodo = new Todo ({
  text: '    Edit this video    '
});
```

当我们尝试保存这个 Todo 时，首先会发生的是字符串开头和结尾的空格会被修剪。然后，它会验证这个字符串的最小长度为 1，它确实是，最后，它会将 Todo 保存到数据库。我将保存`server.js`，重新启动我们的脚本，这一次我们得到了我们的 Todo：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/85a25e58-55ab-40e6-b209-73bbca30dd1e.png)

`Edit this video`文本显示为`text`属性。那些前导和尾随空格已经被移除，这太棒了。只使用三个属性，我们就能够配置我们的`text`属性，设置一些验证。现在，我们可以为`completed`做类似的事情。

# Mongoose 默认值

对于`completed`，我们不会`require`它，因为完成值很可能默认为`false`。相反，我们可以设置`default`属性，为这个`completed`字段设置一个默认值。

```js
  completed: {
    type: Boolean,
    default: false
  },
```

现在`completed`，正如我们在本节中讨论的那样，应该默认为`false`。如果 Todo 已经完成，就没有理由创建一个 Todo。我们也可以为`completedAt`做同样的事情。如果一个 Todo 开始时没有完成，那么`completedAt`就不会存在。只有当 Todo 完成时，它才会存在；它将是时间戳。我要做的是将`default`设置为`null`：

```js
  completed: {
    type: Boolean,
    default: false
  },
  completedAt: {
    type: Number,
    default: null
  }
```

太棒了。现在，我们为我们的 Todo 有一个相当不错的模式。我们将验证用户是否正确设置了文本，并且我们将自己设置`completed`和`completedAt`的值，因为我们可以使用默认值。有了这个设置，我现在可以重新运行我们的`server`文件，这样我们就可以得到一个更好的默认 Todo：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/676dd86c-d8d0-4581-80c2-fbeac54bba33.png)

我们有用户提供的`text`属性，已经经过验证和修剪。接下来，我们将`completed`设置为`false`，`completedAt`设置为`null`；这太棒了。我们现在有一个无懈可击的模式，具有良好的默认值和验证。

# Mongoose 类型

如果您一直在玩各种类型，您可能已经注意到，如果您将`type`设置为除了您指定的类型之外的其他类型，在某些情况下它仍然可以工作。例如，如果我尝试将`text`设置为一个对象，我会得到一个错误。它会说，嘿，你试图使用一个字符串，但实际上出现了一个对象。但是，如果我尝试将`text`设置为一个数字，我会选择`23`：

```js
var otherTodo = new Todo ({
  text: 23
});
```

这将起作用。这是因为 Mongoose 会将您的数字转换为字符串，实质上是用引号包裹它。对于布尔值也是一样的。如果我传入一个布尔值，就像这样：

```js
var otherTodo = new Todo ({
  text: true
});
```

生成的字符串将是`"true"`。我将在将`text`设置为`true`后保存文件，并运行脚本：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/495fb8a4-dddd-40ae-b13a-667020db4ba5.png)

当我这样做时，我得到了`text`等于`true`，如前面的截图所示。请注意，它确实被引号包裹。重要的是要意识到，在 Mongoose 内部确实存在类型转换。它很容易让你犯错并导致一些意外的错误。但现在，我将把`text`设置为一个合适的字符串：

```js
var otherTodo = new Todo ({
  text: 'Something to do'
});
```

# 为身份验证创建 Mongoose 用户模型

现在，我们将创建一个全新的 Mongoose 模型。首先，你将创建一个新的`User`模型。最终，我们将用它进行身份验证。它将存储诸如电子邮件和密码之类的东西，而 Todos 将与该`User`关联，因此当我创建一个时，只有我可以编辑它。

我们将研究所有这些，但现在，我们将保持事情非常简单。在`User`模型上，你需要设置的唯一属性是`email`属性。我们以后会设置其他属性，比如`password`，但它将以稍有不同的方式完成，因为它需要是安全的。现在，我们只需坚持`email`。我希望你对其进行`require`。我也希望你对其进行`trim`，所以如果有人在之前或之后添加了空格，那些空格就会消失。最后但并非最不重要的是，继续将`type`设置为`String`，设置类型，并将`minlength`设置为`1`。现在，显然，你可以传入一个不是电子邮件的字符串。我们以后会探索自定义验证。这将让我们验证电子邮件是否为电子邮件，但现在这将让我们走上正确的轨道。

创建了你的 Mongoose 模型后，我希望你继续尝试创建一个新的`User`。创建一个没有`email`属性的`User`，然后创建一个具有`email`属性的`User`，确保当你运行脚本时，数据会如预期般显示在 Robomongo 中。这些数据应该显示在新的`Users`集合中。

# 设置电子邮件属性

首先，我要做的是创建一个变量来存储这个新模型，一个名为`User`的变量，并将其设置为`mongoose.model`，这是我们可以创建新的`User`模型的方法。第一个参数，你知道，需要是字符串模型名称。我将使用与我在变量中指定的完全相同的名称，尽管它可能会有所不同。我只是喜欢保持使用这种模式，其中变量等于模型名称。接下来，作为第二个参数，我们可以指定一个对象，其中我们配置`User`应该具有的所有属性。

```js
var User = mongoose.model('User', {

});
```

现在，正如我之前提到的，我们以后会添加其他属性，但是现在，添加对`email`属性的支持就足够了。有几件事我想在这封电子邮件上做。首先，我想设置`type`。电子邮件始终是一个字符串，因此我们可以将`type`设置为`String`。

```js
var User = mongoose.model('User', {
  email: {
    type: String,

  }
});
```

接下来，我们将对其进行`require`。你不能创建一个没有电子邮件的用户，所以我将把`required`设置为`true`。在`required`之后，我们将继续对该电子邮件进行`trim`。如果有人在它之前或之后添加了空格，显然是一个错误，所以我们将继续删除`User`模型中的那些空格，使我们的应用程序变得更加用户友好。最后但并非最不重要的是，我们要做的是设置一个`minlength`验证器。我们以后将设置自定义验证，但现在`minlength`为`1`就足够了。

```js
var User = mongoose.model('User', {
  email: {
    type: String,
    required: true,
    trim: true,
    minlength: 1
  }
});
```

现在，我将继续创建这个`User`的新实例并保存它。在运行脚本之前，我将注释掉我们的新 Todo。现在，我们可以创建这个`User`模型的新实例。我将创建一个名为`user`的变量，并将其设置为`new User`，传入我们想要在该用户上设置的任何值。

```js
var User = mongoose.model('User', {
  email: {
    type: String,
    required: true,
    trim: true,
    minlength: 1
  }
});

var user = new User({

});
```

我将首先不运行它，只是为了确保验证有效。现在，在用户变量旁边，我现在可以调用`user.save`。`save`方法返回一个 promise，因此我可以附加一个`then`回调。我将为此添加一个成功案例和一个错误处理程序。错误处理程序将获得该错误参数，成功案例将获得 doc。如果一切顺利，我将使用`console.log('User saved', doc)`打印一条消息，然后是`doc`参数。对于此示例，不需要为其进行格式化。对于错误处理程序，我将使用`console.log('无法保存用户')`，然后是错误对象。

```js
var user = new User({

});

user.save().then((doc) => {
  console.log('User saved', doc);
}, (e) => {
  console.log('Unable to save user', e);
});
```

由于我们正在创建一个没有属性的用户，我们希望错误会打印出来。我将保存`server.js`并重新启动文件：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/16d912d6-c907-453e-8235-935e68105d61.png)

我们得到了错误。这是一个名为“路径'email'是必需的”验证错误。 Mongoose 让我们知道我们确实有一个错误。由于我们将`required`设置为`true`，因此电子邮件确实需要存在。我将继续放一个值，将`email`设置为我的电子邮件`andrew@example.com`，然后我会在后面放几个空格：

```js
var user = new User({
  email: 'andrew@example.com '
});
```

这一次，事情应该如预期那样进行，`trim`应该修剪该电子邮件的末尾，删除所有空格，这正是我们得到的结果：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/dd0d3bfd-cd05-4808-b38d-b3fa153e95d7.png)

`User`确实已保存，这很好，`email`已经被正确格式化。显然，我也可以输入像`123`这样的字符串，它也可以工作，因为我们还没有设置自定义验证，但我们有一个相当不错的起点。我们有`User`模型，并且我们已经设置好并准备好使用`email`属性。

有了这个，我们现在要开始创建 API。在下一节中，您将安装一个名为**Postman**的工具，它将帮助我们测试我们的 HTTP 请求，然后我们将为我们的 Todo REST API 创建我们的第一个路由。

# 安装 Postman

在本节中，您将学习如何使用 Postman。如果您正在构建 REST API，Postman 是一种必不可少的工具。我从未与团队合作或在项目中使用 Postman 不是每个开发人员都大量使用的情况。Postman 允许您创建 HTTP 请求并将其发送。这使得测试您编写的所有内容是否按预期工作变得非常容易。显然，我们还将编写自动化测试，但使用 Postman 可以让您玩弄数据并在移动 API 时查看事物是如何工作的。这真的是一个很棒的工具。

我们将转到浏览器并转到[getpostman.com](https://www.getpostman.com/)，在这里我们可以获取他们的应用程序：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/835b7f36-2f52-4f8f-933e-ae187b98caf2.png)

现在我将使用 Chrome 应用程序。要安装它，您只需从 Chrome 商店安装 Chrome 应用程序，单击“添加到 Chrome”，它应该会将您带到可以打开应用程序的页面。现在，要打开 Chrome 应用程序，您必须转到这种奇怪的 URL。它是`chrome://apps`。在这里，您可以查看所有应用程序，我们只需单击即可打开 Postman。

现在正如我之前提到的，Postman 允许您发出 HTTP 请求，因此我们将继续并进行一些操作以玩弄用户界面。您无需创建帐户，也无需注册付费计划。付费计划面向需要高级功能的开发团队。我们只是在我们的机器上进行基本请求；我们不需要云存储或类似的东西。我将跳过帐户创建，我们可以直接进入应用程序。

在这里，我们可以设置我们的请求；这是面板中发生的事情：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/d92b060a-975c-4a9b-a969-974129f1781e.png)

而且，在白色空间中，我们将能够查看结果。让我们继续向谷歌发出请求。

# 向谷歌发出 HTTP 请求

在 URL 栏中，我将输入`http://google.com`。我们可以点击发送来发送该请求。确保你选择了 GET 作为你的 HTTP 方法。当我发送请求时，它会返回，所有的返回数据都显示在白色空间中：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/30fd6a5f-765a-4304-b3fe-1d288de8d437.png)

我们有一些状态码；我们有一个 200，表示一切顺利；我们有时间，大约花了四分之一秒；我们有来自 Google 的头部；我们有 Cookie，但在这种情况下没有；我们有我们的 Body 数据。`google.com`的 body 是一个 HTML 网站。在大多数情况下，我们在 Postman 中发送和接收的 body 将是 JSON，因为我们正在构建 REST API。

# 说明 JSON 数据的工作方式

所以为了说明 JSON 数据是如何工作的，我们将向我们在课程中早些时候使用过的地理编码 URL 发出请求。如果你还记得，我们能够传入一个位置，然后得到一些 JSON 数据，描述了诸如纬度和经度以及格式化地址之类的东西。现在这些应该还在你的 Chrome 历史记录中。

如果你删除了你的历史记录，你可以在地址栏中输入[`maps.googleapis.com/maps/api/geocode/json?address=1301+lombard+st+philadelphia`](https://maps.googleapis.com/maps/api/geocode/json?address=1301+lombard+st+philadelphia)。这是我将要使用的 URL；你可以简单地复制它，或者你可以获取任何 JSON API 的 URL。我将它复制到剪贴板中，然后返回到 Postman，用刚刚复制的 URL 替换掉原来的 URL：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/51563b05-4b16-4b54-b205-919769dc5aca.png)

现在，我可以继续发送请求。我们得到了我们的 JSON 数据，这太棒了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/071bf0f7-f6a7-435e-8579-509ed52a4808.png)

当我们发出这个请求时，我们能够看到确切的返回内容，这就是我们将要使用 Postman 的方式。

我们将使用 Postman 来发送请求，添加 Todos，删除 Todos，获取所有的 Todos，并登录；所有这些都将在这里发生。记住，API 不一定有前端。也许它是一个 Android 应用程序；也许它是一个 iPhone 应用程序或 Web 应用程序；也许它是另一个服务器。Postman 让我们能够与我们的 API 进行交互，确保它按预期工作。我们有所有的 JSON 数据返回。在 Body 下的 Raw 视图中，我们有原始数据响应。基本上，它只是未经美化的；没有格式化，没有着色。我们还有一个预览选项卡。预览选项卡对于 JSON 来说是相当无用的。当涉及到 JSON 数据时，我总是坚持使用漂亮的选项卡，这应该是默认的。

现在我们已经安装了 Postman 并且知道了一些如何使用它的知识，我们将继续进行下一部分，我们将实际创建我们的第一个请求。我们将发送一个 Postman 请求来访问我们将要创建的 URL。这将让我们可以直接从 Postman 或任何其他应用程序（无论是 Web 应用程序、移动应用程序还是另一个服务器）中创建新的 Todos。接下来就是这些内容，所以请确保你已经安装了 Postman。如果你能够完成本节的所有内容，那么你已经准备好继续了。

# 资源创建端点 - POST /todos

在本节中，你将为添加新的 Todos 创建你的`HTTP POST`路由。在我们深入讨论之前，我们首先要重构`server.js`中的所有内容。我们有数据库配置的东西，应该放在其他地方，我们有我们的模型，也应该放在单独的文件中。我们在`server.js`中想要的唯一的东西就是我们的 Express 路由处理程序。

# 重构 server.js 文件以创建 POST todos 路由

首先，在`server`文件夹中，我们将创建一个名为`db`的新文件夹，在`db`文件夹中，我们将创建一个文件，所有的 Mongoose 配置都将在其中进行。我将把那个文件命名为`mongoose.js`，我们需要做的就是将我们的 Mongoose 配置代码放在这里：

```js
var mongoose = require('mongoose');
mongoose.Promise = global.Promise;
mongoose.connect('mongodb://localhost:27017/TodoApp');
```

删除它，并将其移动到`mongoose.js`中。现在，我们需要导出一些东西。我们要导出的是`mongoose`变量。因此，当有人需要 mongoose.js 文件时，他们将得到配置好的 Mongoose，并且他们将得到它——他们将从库中得到的`mongoose`变量。我将设置`module.exports`等于一个对象，并且在该对象上，我们将`mongoose`设置为`mongoose`：

```js
mongoose.connect('mongodb://localhost:27017/TodoApp');

module.exports = {
  mongoose: mongoose
};
```

现在我们知道，在 ES6 中，这可以简化。如果你有一个属性和一个同名的变量，你可以缩短它，我们可以进一步将其放在一行上：

```js
module.exports = {mongoose};
```

现在我们有了一个单独的文件中的 Mongoose 配置，该文件可以在`server.js`文件中被引用。我将使用 ES6 解构来获取 mongoose 属性。基本上，我们正在创建一个名为`mongoose`的本地变量，该变量等于对象上的 mongoose 属性，并且该对象将是从我们刚刚创建的文件中获取的返回结果。它在`db`目录中，名为`mongoose.js`，我们可以省略扩展名：

```js
var mongoose = require('./db/mongoose');
```

现在 Mongoose 已经有了自己的位置，让我们对`Todo`和`User`做同样的事情。这将发生在服务器中的一个名为`models`的新文件夹中。

# 配置 Todo 和 Users 文件

在`models`文件夹中，我们将创建两个文件，一个用于每个模型。我将创建两个新文件，名为`todo.js`和`user.js`。我们可以从`server.js`文件中获取 todos 和 Users 模型，然后将它们简单地复制粘贴到相应的文件中。一旦模型被复制，我们可以从`server.js`中删除它。Todos 模型将如下所示：

```js
var Todo = mongoose.model('Todo', {
  text: {
    type: String,
    required: true,
    minlength: 1,
    trim: true
  },
  completed: {
    type: Boolean,
    default: false
  },
  completedAt: {
    type: Number,
    default: null
  }
});
```

`user.js`模型将如下所示。

```js
var User = mongoose.model('User', {
  email: {
    type: String,
    required: true,
    trim: true,
    minlength: 1
  }
});
```

我还将删除到目前为止我们所拥有的一切，因为`server.js`中的这些示例不再必要。我们可以简单地将我们的 mongoose 导入语句留在顶部。

在这些模型文件中，有一些事情我们需要做。首先，我们将在 Todos 和 Users 文件中调用`mongoose.model`，因此我们仍然需要加载 Mongoose。现在，我们不必加载我们创建的`mongoose.js`文件；我们可以加载普通的库。让我们创建一个变量。我们将称这个变量为`mongoose`，然后我们将`require('mongoose')`：

```js
var mongoose = require('mongoose');

var Todo = mongoose.model('Todo', {
```

我们需要做的最后一件事是导出模型，否则我们无法在需要这个文件的文件中使用它。我将设置`module.exports`等于一个对象，并且我们将`Todo`属性设置为`Todo`变量；这正是我们在`mongoose.js`中所做的：

```js
module.exports = {Todo};
```

我们将在`user.js`中做完全相同的事情。在`user.js`中，我们将在顶部创建一个名为`mongoose`的变量，需要`mongoose`，然后在底部导出`User`模型，`module.exports`，将其设置为一个对象，其中`User`等于`User`：

```js
Var mongoose = require('mongoose');

var User = mongoose.model('User', {
  email: {
    type: String,
    required: true,
    trim: true,
    minlength: 1
  }
});

module.exports = {User};
```

现在，我们的三个文件都已经格式化。我们有三个新文件和一个旧文件。剩下要做的就是加载`Todo`和`User`。

# 在`server.js`文件中加载 Todo 和 User 文件

在`server.js`文件中，让我们使用解构创建一个变量`Todo`，将其设置为`require('./models/todo')`，我们可以对`User`做完全相同的事情。使用 ES6 解构，我们将获取`User`变量，并且我们将从调用`require`返回的对象中获取它，需要`models/user`：

```js
var {mongoose} = require('./db/mongoose');
var {Todo} = require('./models/todo');
var {User} = require('./models/user');
```

有了这个设置，我们现在准备开始。我们有完全相同的设置，只是已经重构，这将使测试、更新和管理变得更加容易。`server.js`文件只负责我们的路由。

# 配置 Express 应用程序

现在，让我们开始，我们需要安装 Express。我们已经在过去做过了，所以在终端中，我们只需要运行`npm i`，然后是模块名称，即`express`。我们将使用最新版本，`4.16.2`。

我们还将安装第二个模块，实际上我们可以在第一个模块之后立即输入。没有必要两次运行`npm install`。这个叫做`body-parser`。`body-parser`将允许我们向服务器发送 JSON。服务器然后可以接收该 JSON 并对其进行处理。`body-parser`本质上解析主体。它获取该字符串主体并将其转换为 JavaScript 对象。现在，使用`body-parser`，我们将安装最新版本`1.18.2`。我还将提供`--save`标志，这将把 Express 和`body-parser`添加到`package.json`的依赖项部分：

```js
**npm i express@4.16.2 body-parser@1.18.2 --save** 
```

现在，我可以继续发送这个请求，安装这两个模块，并在`server.js`中开始配置我们的应用程序。

首先，我们必须加载刚刚安装的这两个模块。正如我之前提到的，我喜欢在本地导入和库导入之间保留一个空格。我将使用一个名为`express`的变量来存储 Express 库，即`require('express')`。我们将对`body-parser`做同样的事情，使用一个名为`bodyParser`的变量，将其设置为从`body-parser`中获取的返回结果：

```js
var express = require('express');
var bodyParser = require('body-parser');

var {mongoose} = require('./db/mongoose');
var {Todo} = require('./models/todo');
var {User} = require('./models/user');
```

现在我们可以设置一个非常基本的应用程序。我们将创建一个名为`app`的变量；这将存储我们的 Express 应用程序。我将把它设置为调用`express`：

```js
var {User} = require('./models/user');

var app = express();
```

我们还将调用`app.listen`，监听一个端口。我们最终将部署到 Heroku。不过，现在我们将有一个本地端口，端口`3000`，并且我们将提供一个回调函数，一旦应用程序启动，它就会触发。我们将使用`console.log`来打印`Started on port 3000`：

```js
var app = express();

app.listen(3000, () => {
  console.log('Started on port 3000');
});
```

# 配置 POST 路由

现在，我们有一个非常基本的服务器。我们只需要开始配置我们的路由，正如我承诺的那样，我们将在本节中专注于 POST 路由。这将让我们创建新的 Todos。现在，在您的 REST API 中，有基本的 CRUD 操作，CRUD 代表创建、读取、更新和删除。

当您想要创建一个资源时，您使用`POST HTTP`方法，并将该资源作为主体发送。这意味着当我们想要创建一个新的 Todo 时，我们将向服务器发送一个 JSON 对象。它将具有一个`text`属性，服务器将获取该`text`属性，创建新模型，并将带有 ID、completed 属性和`completedAt`的完整模型发送回客户端。

要设置路由，我们需要调用`app.post`，传入我们用于每个 Express 路由的两个参数，即我们的 URL 和我们的回调函数，该函数将使用`req`和`res`对象进行调用。现在，REST API 的 URL 非常重要，关于正确的结构有很多讨论。对于资源，我喜欢使用`/todos`：

```js
app.post('/todos', (req, res) => {

});
```

这是用于资源创建的，这是一个非常标准的设置。`/todos`用于创建新的 Todo。稍后，当我们想要读取 Todos 时，我们将使用`GET`方法，并且我们将使用`GET`从`/todos`获取所有 Todos 或`/todos`，一些疯狂的数字，以根据其 ID 获取单个 Todo。这是一个非常常见的模式，也是我们将要使用的模式。不过，现在我们可以专注于获取从客户端发送的主体数据。

# 从客户端获取主体数据

为此，我们必须使用`body-parser`模块。正如我之前提到的，`body-parser`将获取您的 JSON 并将其转换为一个对象，将其附加到此`request`对象上。我们将使用`app.use`配置中间件。`app.use`使用中间件。如果我们正在编写自定义中间件，它将是一个函数；如果我们正在使用第三方中间件，我们通常只是从库中访问某些内容。在这种情况下，它将作为函数调用`bodyParser.json`。这个 JSON 方法的返回值是一个函数，这就是我们需要给 Express 的中间件：

```js
var app = express();

app.use(bodyParser.json());
```

有了这个设置，我们现在可以向我们的 Express 应用程序发送 JSON。在`post`回调中，我想要做的就是简单地`console.log` `req.body`的值，其中`bodyParser`存储了 body。

```js
app.use(bodyParser.json());

app.post('/todos', (req, res) => {
  console.log(req.body);
});
```

现在我们可以启动服务器并在 Postman 中测试一下。

在 Postman 中测试 POST 路由

在终端中，我将使用`clear`清除终端输出，然后运行应用程序：

```js
**node server/server.js** 
```

服务器在端口 3000 上运行，这意味着我们现在可以进入 Postman：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/6a953c9e-1aaa-46b5-9fbe-b41a776ebcf2.png)

在 Postman 中，我们不会像在上一节中那样进行`GET`请求。这次，我们要做的是进行 POST 请求，这意味着我们需要将 HTTP 方法更改为 POST，并输入 URL。端口将是`localhost:3000`，路径将是`/todos`。这是我们要发送数据的 URL：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/4febabfd-5ae5-42f9-9a10-fc88a754d192.png)

现在，为了向应用程序发送一些数据，我们必须转到 Body 选项卡。我们要发送 JSON 数据，所以我们将转到原始并从右侧的下拉列表中选择 JSON（application/json）：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/6a0475dd-eab4-40a1-add7-f4e0db4de205.png)

现在我们已经设置了头部。这是 Content-Type 头部，让服务器知道正在发送 JSON。所有这些都是由 Postman 自动完成的。在 Body 中，我要附加到我的 JSON 的唯一信息是一个`text`属性：

```js
{
  "text": "This is from postman"
}
```

现在我们可以点击发送来发送我们的请求。我们永远不会收到响应，因为我们还没有在`server.js`中回应它，但是如果我转到终端，你会看到我们有我们的数据：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/f9371b46-fd66-4a0d-939f-fe21b9551ad7.png)

这是我们在 Postman 中创建的数据。现在它显示在我们的 Node 应用程序中，这太棒了。我们离实际创建 Todo 只差一步。在 post 处理程序中，唯一剩下的事情就是实际使用来自“用户”的信息创建 Todo。

# 创建 Mongoose 模型的实例

在`server.js`中，让我们创建一个名为`todo`的变量，以执行之前所做的操作，创建 Mongoose 模型的实例。我们将其设置为`new Todo`，传入我们的对象和要设置的值。在这种情况下，我们只想设置`text`。我们将文本设置为`req.body`，这是我们拥有的对象，然后我们将访问`text`属性，就像这样：

```js
app.post('/todos', (req, res) => {
  var todo = new Todo({
    text: req.body.text
  });
```

接下来，我们将调用`todo.save`。这将实际将模型保存到数据库，并且我们将为成功和错误情况提供回调。

```js
app.post('/todos', (req, res) => {
  var todo = new Todo({
    text: req.body.text
  });

todo.save().then((doc) => {

}, (e) => {

});
```

现在，如果一切顺利，我们将发送回实际的 Todo，它将显示在 then 回调中。我将获取`doc`，并在回调函数中使用`res.send`发送`doc`回去。这将为`User`提供非常重要的信息，例如 ID 和`completed`和`completedAt`属性，这些属性不是由`User`设置的。如果事情进展不顺利并且我们遇到错误，那也没关系。我们要做的就是使用`res.send`发送错误回去：

```js
todo.save().then((doc) => {
  res.send(doc);
}, (e) => {
  res.send(e);
});
```

稍后我们将修改如何发送错误。目前，这段代码将运行得很好。我们还可以设置 HTTP 状态。

# 设置 HTTP 状态码

如果你记得，HTTP 状态可以让你给别人一些关于请求进展情况的信息。它进行得顺利吗？它进行得不好吗？这种情况。你可以通过访问[httpstatuses.com](https://httpstatuses.com/)来获取所有可用的 HTTP 状态列表。在这里，你可以查看所有你可以设置的状态：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/6da92bd6-eedd-4b4d-b992-f2aae3128ab9.png)

Express 默认设置的一个是`200`。这意味着事情进行得很顺利。我们将用于错误的是`400`。`400`状态意味着有一些错误的输入，如果模型无法保存，就会出现这种情况。也许`User`没有提供`text`属性，或者文本字符串为空。无论哪种情况，我们都希望返回`400`，这将会发生。在我们调用`send`之前，我们要做的就是调用`status`，传入`400`的状态：

```js
todo.save().then((doc) => {
  res.send(doc);
}, (e) => {
  res.status(400).send(e);
});
```

有了这个，我们现在准备在 Postman 中测试我们的`POST /todos`请求。

# 在 Postman 中测试 POST /todos

我将在终端中重新启动服务器。如果你喜欢，你可以用`nodemon`启动它。目前，我将手动重新启动它：

```js
**nodemon server/server.js** 
```

我们现在在本地主机 3000 上，进入 Postman，我们可以进行与之前完全相同的请求。我将点击发送：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/776c1611-1339-44e4-b558-bc348e3afa13.png)

我们得到了一个 200 的状态。这太棒了；这是默认状态，意味着事情进行得很顺利。JSON 响应正是我们所期望的。我们有我们设置的`text`；我们有生成的`_id`属性；我们有`completedAt`，它被设置为`null`，默认值；以及我们有`completed`被设置为`false`，默认值。

我们还可以测试当我们尝试创建一个没有正确信息的 Todo 时会发生什么。例如，也许我将`text`属性设置为空字符串。如果我发送这个请求，我们现在会得到一个 400 Bad Request：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/cb3f9133-cfef-4f45-932b-624493eef4f1.png)

现在，我们有一堆验证代码说`Todo 验证失败`。然后，我们可以进入`errors`对象来获取具体的错误。在这里，我们可以看到`text`字段失败了，`message`是`Path 'text' is required`。所有这些信息都可以帮助某人修复他们的请求并做出正确的请求。

现在，如果我进入 Robomongo，我将刷新`todos`集合。看看最后一个，它确实是我们在 Postman 中创建的：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/bbc69aa2-e621-4fe9-8387-10ac561c4a4d.png)

文本等于这是来自 Postman 的。有了这个，我们现在为 Todo REST API 设置了我们的第一个 HTTP 端点。

现在我还没有详细讨论 REST 是什么。我们稍后会谈论这个。现在，我们将专注于创建这些端点。当我们开始添加认证时，REST 版本将稍后出现。

# 向数据库添加更多的 Todos

在 Postman 中，我们可以添加更多的 Todos，这就是我要做的。`Charge my phone`—我想我从来没有需要被提醒过这个—我们将添加`Take a break for lunch`。在 Pretty 部分，我们看到`Charge my phone` Todo 已经创建了一个唯一的 ID。我将发送第二个，我们会看到`Take a break for lunch` Todo 已经创建：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/a4b7b887-ce27-47db-9bc9-12faf509399a.png)

在 Robomongo 中，我们可以给`todos`集合进行最后一次刷新。我将展开最后三个项目，它们确实是我们在 Postman 中创建的三个项目：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/e9e6b7a1-ffa1-4d96-83d3-f4cc1172b560.png)

现在我们的项目中已经完成了一些有意义的工作，让我们继续提交我们的更改。你可以在 Atom 中看到，`server`目录是绿色的，意味着它还没有添加到 Git 中，`package.json`文件是橙色的，这意味着它已经被修改，尽管 Git 正在跟踪它。在终端中，我们可以关闭服务器，我总是喜欢运行`git status`来进行一次理智检查：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/ccbaae0a-9862-411f-a8b5-5bd8aa2ac2b3.png)

在这里，一切看起来都如预期。我可以使用`git add .`添加所有内容，然后再进行一次检查：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/b349702a-b07e-406a-a056-911068914b44.png)

在这里，我们在`server`文件夹中有四个新文件，以及我们的`package.json`文件。

现在，是时候提交了。我要创建一个快速提交。我使用`-am`标志，通常会添加修改后的文件。由于我已经使用了 add，我可以简单地使用`-m`标志，就像我们在整个课程中一直在做的那样。对于这个，一个好的消息可能是`添加 POST /todos 路由和重构 mongoose`：

```js
**git commit -m 'Add POST /todos route and refractor mongoose'** 
```

有了提交，我们现在可以通过将其推送到 GitHub 来结束这些工作，确保它得到备份，并确保它对任何其他在项目上合作的人都可用。记住，仅仅创建一个提交并不能将其上传到 GitHub；您必须使用另一个命令`git push`将其推送上去。有了这个，现在是时候进入下一部分了，您将在那里测试您刚刚创建的路由。

# 测试 POST /todos

在这一部分，您将学习如何为 Todo API 设置测试套件，类似于我们在“测试”部分所做的，我们将为`/todos`编写两个测试用例。我们将验证当我们发送正确的数据作为主体时，我们会得到一个包括 ID 在内的`200`完成文档；如果我们发送错误的数据，我们期望得到一个包含错误对象的`400`。

# 为测试 POST /todos 路由安装 npm 模块

现在，在我们做任何这些之前，我们必须安装在“测试”部分中安装的所有模块，`expect`用于断言，`mocha`用于整个测试套件，`supertest`用于测试我们的 Express 路由，以及`nodemon`。`nodemon`模块将让我们创建`test-watch`脚本，这样我们就可以自动重新启动测试套件。现在我知道您已经全局安装了`nodemon`，但由于我们在`package.json`脚本中使用它，所以在本地安装它也是一个好主意。

我们将使用`npm i`安装`expect`版本`22.3.0`，最新版本。接下来是`mocha`。最新版本是`5.0.1`。之后是`nodemon`版本`1.15.0`，最后但并非最不重要的是`supertest`版本`3.0.0`。有了这些，我们只需要加上`--save-dev`标志。我们想要保存这些，但不作为常规依赖项。它们仅用于测试，因此我们将它们保存为`devDependencies`：

```js
**npm i expect@22.3.0 mocha@5.0.1 nodemon@1.15.0 supertest@3.0.0 --save-dev** 
```

现在，我们可以运行这个命令，一旦完成，我们就可以开始在 Atom 中设置测试文件。

# 设置测试文件

在 Atom 中，我现在在我的`package.json`文件中列出了我的`devDependencies`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/17f9d742-f3d4-4e21-870d-edcfd2448fc6.png)

现在，我的命令输出可能与您的有些不同。npm 正在缓存我最近安装的一些模块，所以正如您在前面的截图中所看到的，它只是获取本地副本。它们确实被安装了，我可以通过打开`node_modules`文件夹来证明。

我们现在将在`server`中创建一个文件夹，用于存储所有测试文件，这个文件夹将被称为`tests`。我们要担心创建的唯一文件是`server.js`的测试文件。我将在 tests 中创建一个名为`server.test.js`的新文件。这是我们将在本章中使用的测试文件的扩展名。在`server.test`文件中，我们现在可以通过要求很多这些模块来启动事情。我们将要求`supertest`模块和`expect`。`mocha`和`nodemon`模块不需要被要求；这不是它们的使用方式。

我们将得到的`const expect`变量将等于`require('expect')`，我们将对`supertest`做同样的事情，使用`const`：

```js
const expect = require('expect');
const request = require('supertest');
```

既然我们已经准备好了，我们需要加载一些本地文件。我们需要加载`server.js`，这样我们就可以访问 Express 应用程序，因为我们需要它来进行超级测试，我们还想加载我们的 Todo 模型。正如您稍后将看到的，我们将查询数据库，并且访问此模型将是必要的。现在模型已经导出了一些东西，但`server.js`目前没有导出任何东西。我们可以通过在`server.js`文件的最底部添加`module.exports`并将其设置为一个对象来解决这个问题。在该对象上，我们要做的就是将`app`属性设置为`app`变量，使用 ES6 对象语法。

```js
module.exports = {app};
```

现在，我们已经准备好加载这两个文件了。

# 加载测试文件

首先，让我们创建一个名为`app`的本地变量，并且我们将使用 ES6 解构从服务器文件的返回结果中取出它。在这里，我们将从相对路径开始。然后，我们将从`tests`返回到`server`的上一级目录。文件名只是`server`，没有扩展名。我们也可以对 Todo 模型做同样的操作。

我们将创建一个名为`Todo`的常量。我们使用 ES6 解构从导出中取出它，文件来自相对路径，返回到上一级目录。然后我们必须进入`models`目录，最后，文件名为`todo`：

```js
const expect = require('expect');
const request = require('supertest');

const {app} = require('./../server');
const {Todo} = require('./../models/todo');
```

既然我们已经加载了所有这些，我们准备创建我们的`describe`块并添加我们的测试用例。

# 为测试用例添加描述块

我将使用`describe`来对所有路由进行分组。对于一些路由，我将有多个测试用例，添加一个`describe`块是很好的，这样您可以在终端中快速查看测试输出。POST Todos 的`describe`块将简单地称为`POST /todos`。然后，我们可以添加箭头函数(`=>`)，在其中我们可以开始列出我们的测试用例。第一个测试将验证当我们发送适当的数据时，一切都如预期般进行：

```js
const {Todo} = require('./../models/todo');

describe('POST /todos', () => {
  it('should create a new todo')
});
```

现在，我们可以添加我们的回调函数，这个函数将接受`done`参数，因为这将是一个异步测试。您必须指定`done`，否则这个测试将无法按预期工作。在回调函数中，我们将创建一个名为`text`的变量。这是我们真正需要的唯一设置数据。我们只需要一个字符串，并且我们将在整个过程中使用该字符串。随意给它任何值。我将使用`Test todo text`。

```js
describe('POST /todos', () => {
  it('should create a new todo',(done) => {
    var text = 'Test todo text';
  });
});
```

现在是时候开始通过`supertest`发出请求了。我们之前只发出了`GET`请求，但`POST`请求同样简单。

# 通过 supertest 进行 POST 请求

我们将调用请求，传入我们要发出请求的应用程序。接下来，我们将调用`.post`，这将设置一个`POST`请求。我们将前往`/todos`，新的事情是我们实际上要发送数据。为了随请求发送数据作为主体，我们必须调用`send`，并且我们将传入一个对象。这个对象将被`supertest`转换为 JSON，所以我们不需要担心这一点——这只是使用`supertest`库的另一个很好的理由。我们将把`text`设置为之前显示的`text`变量，并且我们可以使用 ES6 语法来完成这个操作：

```js
describe('POST /todos', () => {
  it('should create a new todo',(done) => {
    var text = 'Test todo text';

    request(app)
    .post('/todos')
    .send({text})
  })
});
```

现在我们已经发送了请求，我们可以开始对请求进行断言。

# 对 POST 请求进行断言

我们将从状态开始。我将`expect`状态等于`200`，当我们发送有效数据时，这应该是情况。之后，我们可以对返回的主体进行断言。我们希望确保主体是一个对象，并且它的`text`属性等于我们之前指定的属性。这正是它在发送主体时应该做的事情。

在`server.test.js`中，我们可以通过创建一个自定义的`expect`断言来完成这个操作。如果你还记得，我们的自定义`expect`调用确实传递了响应，并且我们可以在函数内部使用该响应。我们要`expect`响应体有一个`text`属性，并且`text`属性等于使用`toBe`定义的`text`字符串：

```js
    request(app)
    .post('/todos')
    .send({text})
    .expect(200)
    .expect((res) => {
      expect(res.body.text).toBe(text);
    })
```

如果是这样，很好，测试通过了。如果不是，也没关系。我们只需要抛出一个错误，测试就会失败。接下来我们需要做的是调用`end`来结束一切，但我们还没有完成。我们要做的是实际检查 MongoDB 集合中存储了什么，这就是我们加载模型的原因。与之前一样，我们不再像之前那样将`done`传递给 end，而是传递一个函数。这个函数将在有错误时被调用，并传递一个错误和响应：

```js
  request(app)
  .post('/todos')
  .send({text})
  .expect(200)
  .expect((res) => {
    expect(res.body.text).toBe(text);
  })
  .end((err, res) => {

});
```

这个回调函数将允许我们做一些事情。首先，让我们处理可能发生的任何错误。如果状态不是`200`，或者`body`没有一个等于我们发送的`text`属性的`text`属性，那么就会出现错误。我们只需要检查错误是否存在。如果存在错误，我们将把它传递给`done`。这将结束测试，将错误打印到屏幕上，因此测试确实会失败。我也会`return`这个结果。

```js
.end((err, res) => {
  if(err) {
    return done(err);
  }
});
```

现在，返回它并没有做任何特别的事情。它只是停止函数的执行。现在，我们将向数据库发出请求，获取所有的 Todos，并验证我们添加的一个`Todo`是否确实被添加了。

# 发出请求从数据库中获取 Todos

为此，我们必须调用`Todo.find`。现在，`Todo.find`与我们使用的 MongoDB 原生`find`方法非常相似。我们可以不带参数地调用它来获取集合中的所有内容。在这种情况下，我们将获取所有的 Todos。接下来，我们可以附加一个`then`回调。我们将使用这个函数调用所有的`todos`，并对其进行一些断言。

```js
.end((err, res) => {
  if(err) {
    return done(err);
  }

Todo.find().then((todos) => {

})
```

在这种情况下，我们要断言我们创建的 Todo 确实存在。我们将从期望`todos.length`等于数字`1`开始，因为我们添加了一个 Todo 项目。我们还要做一个断言。我们要`expect`这一个唯一的项目有一个`text`属性等于使用`toBe`在 server.test.js 中定义的`text`变量。

```js
Todo.find().then((todos) => {
  expect(todos.length).toBe(1);
  expect(todos[0].text).toBe(text);
})
```

如果这两个都通过了，那么我们可以相当肯定一切都按预期工作了。状态码是正确的，响应也是正确的，数据库看起来也是正确的。现在是时候调用`done`，结束测试用例了：

```js
Todo.find().then((todos) => {
  expect(todos.length).toBe(1);
  expect(todos[0].text).toBe(text);
  done();
})
```

我们还没有完成。如果其中任何一个失败，测试仍然会通过。我们必须添加一个`catch`调用。

# 为错误处理添加 catch 调用

`catch`将获取我们回调中可能发生的任何错误。然后，我们将能够获取到错误参数，并使用箭头函数将其传递给`done`，就像这样：

```js
Todo.find().then((todos) => {
  expect(todos.length).toBe(1);
  expect(todos[0].text).toBe(text);
  done();
}).catch((e) => done(e));
```

请注意，这里我使用的是语句语法，而不是箭头函数表达式语法。有了这个，我们的测试用例现在可以运行了。我们有一个很好的测试用例，我们需要做的就是在`package.json`中设置`scripts`来实际运行它。

# 在`package.json`中设置测试脚本

在运行测试之前，我们要设置`scripts`，就像我们在测试部分做的那样。我们将有两个：`test`，只运行测试；和`test-watch`，通过`nodemon`运行测试脚本。这意味着每当我们更改应用程序时，测试都会重新运行。

就在`test`中，我们将运行`mocha`，我们需要提供的唯一其他参数是测试文件的 globbing 模式。我们将获取`server`目录中的所有内容，这可能在一个子目录中（稍后会有），所以我们将使用两个星号（`**`）。它可以有任何文件名，只要以`.test.js`扩展名结尾。

```js
"scripts": {
  "test": "mocha server/**/*.test.js",
  "test-watch":
},
```

现在对于`test-watch`，我们要做的就是运行`nodemon`。我们将使用`--exec`标志来指定一个在单引号内运行的自定义命令。我们要运行的命令是`npm test`。单独的`test`脚本是有用的，`test-watch`只是在每次更改时重新运行`test`脚本：

```js
"scripts": {
  "test": "mocha server/**/*.test.js",
  "test-watch": "nodemon --exec 'npm test'"
},
```

在我们继续之前，我们需要修复一个重大缺陷。正如你可能已经注意到的，在`server.test`文件中，我们做出了一个非常大的假设。我们假设数据库中没有任何内容。我们之所以这样假设，是因为我们期望在添加 1 个待办事项后，待办事项的长度为 1，这意味着我们假设它从 0 开始。现在这个假设是不正确的。如果我现在运行测试套件，它会失败。我已经在数据库中有了待办事项。我们要做的是在`server.test`文件中添加一个测试生命周期方法。这个方法叫做`beforeEach`。

# 在 server.test.js 文件中添加测试生命周期方法

`beforeEach`方法将允许我们在每个测试用例之前运行一些代码。我们将使用`beforeEach`来设置数据库的有用方式。现在，我们要做的只是确保数据库是空的。我们将传入一个函数，该函数将使用`done`参数调用，就像我们的单独测试用例一样。

```js
const {Todo} = require('./../models/todo');    

beforeEach((done) => {

});
```

这个函数将在每个测试用例之前运行，只有在我们调用`done`后才会继续进行测试用例，这意味着我们可以在这个函数中做一些异步的事情。我要做的是调用`Todo.remove`，这类似于 MongoDB 的原生方法。我们只需要传入一个空对象；这将清除所有的待办事项。然后，我们可以添加一个`then`回调，在`then`回调中，我们将调用`done`，就像这样：

```js
beforeEach((done) => {
  Todo.remove({}).then(() => {
    done();
  })
});
```

现在，我们也可以使用表达式语法来缩短这个：

```js
beforeEach((done) => {
  Todo.remove({}).then(() => done());
});
```

有了这个，我们的数据库在每次请求之前都将是空的，现在我们的假设是正确的。我们假设我们从 0 个待办事项开始，并且确实从 0 个待办事项开始，因为我们刚刚删除了所有内容。

# 运行测试套件

我将继续进入终端，清除终端输出，现在我们可以通过以下命令开始运行测试套件：

```js
**npm run test-watch** 
```

这将启动`nodemon`，它将启动测试套件，然后我们得到一个通过的测试，应该创建一个新的待办事项：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/f0070bec-b83e-418e-9b90-edf39bd6f374.png)

我们可以通过调整一些值来验证一切是否按预期工作。我可以添加`1`如下：

```js
request(app)
  .post('/todos')
  .send({text})
  .expect(200)
  .expect((res) => {
    expect(res.body.text).toBe(text + '1');
})
```

只是为了证明它实际上正在做它所说的。你可以看到我们得到了一个错误，因为这两个不相等。

对于我们的状态也是一样的。如果我将状态更改为其他值，比如`201`，测试套件将重新运行并失败。最后但并非最不重要的是，如果我将`toBe`更改为`3`，如下所示：

```js
expect(todos.length).toBe(3); 
```

这将失败，因为我们总是在清除数据库，因此这里唯一正确的值将是`1`。现在我们已经有了这个，我们可以添加我们的第二个测试用例。这将是验证当我们发送错误数据时，待办事项不会被创建的测试用例。

# 测试用例：不应该使用无效的主体数据创建待办事项

要开始使用这个，我们将使用`it`来创建一个全新的测试用例。这个测试用例的文本可能是`should not create todo with invalid body data`。我们可以传入带有`done`参数的回调函数，并开始进行超级测试请求。

这一次，不需要创建一个`text`变量，因为我们不会将文本传递进去。我们要做的是什么都不传递：

```js
it('should not create todo with invalid body data', (done) => {

});
```

现在，我想让你做的是，像之前一样发出一个请求。你将向相同的 URL 发出一个`POST`请求，但是你将发送一个空对象作为`send`。这个空对象会导致测试失败，因为我们无法保存模型。然后，你会期望我们得到一个`400`，这将是情况，我们在`server.js`文件中发送了一个 400。你不需要对返回的主体做出任何假设。

最后，你将使用以下格式；我们将传递一个回调给`end`，检查是否有任何错误，然后对数据库做出一些假设。你要做的假设是`todos`的长度是`0`。由于前面的代码块没有创建`Todo`，所以不应该有`Todo`存在。`beforeEach`函数将在每个测试用例运行之前运行，所以在我们的用例运行之前，`should create a new todo`中创建的`Todo`将被删除。继续设置。发出请求并验证长度是否为 0。你不需要在前一个测试用例中进行断言，因为这个断言是关于数组的某些内容，而数组将是空的。你也可以不使用以下断言：

```js
.expect((res) => {
  expect(res.body.text).toBe(text);
})
```

因为我们不会对主体做出任何断言。完成后，保存测试文件。确保你的两个测试都通过了。

我要做的第一件事是调用`request`，传入我们的`app`。我们想再次发出一个`post`请求，所以我会再次调用`.post`，URL 也将是相同的。现在，在这一点上，我们将调用`.send`，但我们不会传递无效的数据。这个测试用例的整个重点是看当我们传入无效数据时会发生什么。应该发生的是我们应该得到一个`400`，所以我期望从服务器得到一个`400`的响应。现在我们不需要对主体做出任何断言，所以我们可以继续进行`.end`，在那里我们将传递我们的函数，该函数将被调用并传入`err`参数，如果有的话，以及`res`，就像这样：

```js
it('should not create todo with invalid body data', (done) => {
  request(app)
  .post('/todos')
  .send({})
  .expect(400)
  .end((err, res) => {

  });
});
```

现在，我们要做的是处理任何潜在的错误。如果有错误，我们将`return`，这将停止函数的执行，然后我们将调用`done`，传入错误，以便测试正确地失败：

```js
.end((err, res) => {
  if(err) {
    return done(err);
  }
});
```

# 对`Todos`集合的长度做出断言

现在，我们可以从数据库中获取数据，并对`Todos`集合的长度做出一些断言。我将使用`Todo.find`来获取集合中的每一个`Todo`。然后，我将添加一个`then`回调，这样我就可以对数据做一些操作。在这种情况下，我将得到`todos`，并对其长度做出断言。我们将期望`todos.length`等于数字`0`。

```js
Todo.find().then((todos) => {
  expect(todos.length).toBe(0);
});
```

在这个测试用例运行之前，数据库中不应该有`Todo`，因为我们发送了错误的数据，所以这个测试用例不应该创建任何`Todo`。现在我们可以调用`done`，并且我们也可以添加我们的`catch`回调，就像之前一样。我们将调用`catch`，获取错误参数并将其传递给`done`：

```js
Todo.find().then((todos) => {
  expect(todos.length).toBe(0);
  done();
}).catch((e) => done(e));
```

现在，我们完成了。我可以保存文件了。这将重新启动`nodemon`，这将重新启动我们的测试套件。我们应该看到的是我们的两个测试用例，它们都通过了。在终端中，我们确实看到了这一点。我们有两个`POST /todos`的测试用例，两者都确实通过了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/9b7eb6b6-3f5b-4b0d-a3a5-3dec02aac70a.png)

在这一节中，设置基本的测试套件花了一些时间，但是在将来，随着我们添加更多的路由，测试将会更容易。我们不需要设置基础设施；我们也不需要创建测试脚本或安装新的模块。

# 为`POST /todos`路由做出提交

最后要做的就是提交。我们添加了一些有意义的代码，所以我们要保存这项工作。如果我运行`git status`，您可以看到我们有一些更改的文件以及一些未跟踪的文件，所以我将使用`git add .`将所有这些添加到下一个提交中。现在，我可以使用`git commit`和`-m`标志来实际进行提交。对于这个提交，一个好的提交消息将是`测试 POST /todos 路由`。

```js
**git commit -m 'Test POST /todos route'** 
```

我将进行提交，最后，我将使用`git push`将其推送到 GitHub。您可以在这种特殊情况下使用`git push`。我需要使用`git push --force`，这将覆盖 GitHub 上的所有内容。这只是我在这种特定情况下需要做的事情。您应该只运行`git push`。运行后，您的代码应该被推送到 GitHub，然后就完成了。我们的路由有两个测试案例，现在是时候继续添加新的路由了。下一个路由将是一个`GET`请求，用于获取所有 Todos。

# 列出资源 - GET /todos

现在我们的测试套件已经就位，是时候创建我们的第二个路由了，即`GET /todos`路由，它将负责返回所有的 Todos。这对于任何 Todo 应用程序都是有用的。

# 创建 GET /todos 路由

您可能要向用户显示的第一个屏幕是他们所有的 Todos 列表。这是您用来获取信息的路由。这将是一个`GET`请求，所以我将使用`app.get`来注册路由处理程序，URL 本身将与我们的 URL 匹配，`/todos`，因为我们想要获取所有的 Todos。稍后当我们获取单个 Todo 时，URL 将看起来像`/todos/123`，但现在我们将其与 POST URL 匹配。接下来，我们可以在`server.js`中的`app.listen`上面添加我们的回调；这将给我们我们的请求和响应对象：

```js
app.get('/todos', (req, res) => {

});
```

我们所需要做的就是获取集合中的所有 Todos，这一步我们已经在测试文件中完成了。在`server.test.js`中，我们使用`Todo.find`来获取所有的 Todos。我们将在这里使用相同的技术，但是我们不会传入查询；我们想要返回所有内容。

```js
app.get('/todos', (req, res) => {
  Todo.find()
});
```

稍后当我们添加身份验证时，您将只获取您创建的`Todos`，但是现在，没有身份验证，您将获取`Todos`集合中的所有内容。

接下来，我们将添加一个`then`调用。这个`then`调用将使用两个函数，一个是成功案例函数，当承诺被解决时调用，另一个是当承诺被拒绝时调用的函数。成功案例将使用所有的`todos`调用，并且我们要做的就是使用`res.send`将这些信息发送回去。

```js
app.get('/todos', (req, res) => {
  Todo.find().then((todos) => {
    res.send()
  }, (e) => {

  })
});
```

我们可以传入`todos`数组，但这不是完成任务的最佳方式。当您返回一个数组时，您有点束缚自己。如果您想添加另一个属性，无论是自定义状态代码还是其他数据，您都不能，因为您有一个数组。更好的解决方案是创建一个对象，并在该对象上指定`todos`，使用 ES6 将其设置为`todos`数组：

```js
app.get('/todos', (req, res) => {
  Todo.find().then((todos) => {
    res.send({todos});
  }, (e) => {

  })
});
```

这将让您以后添加其他属性。例如，我可以添加某种自定义状态代码，将其设置为我喜欢的任何值。通过使用对象而不是发送一个数组回来，我们为更灵活的未来打开了可能性。有了这个，我们的成功案例就可以运行了。我们唯一需要做的就是处理错误，错误处理程序将与我们之前使用的一样，`res.status`。我们将发送一个`400`，并将发送回传入函数的错误对象：

```js
app.get('/todos', (req, res) => {
  Todo.find().then((todos) => {
    res.send({todos});
  }, (e) => {
    res.status(400).send(e);
  });
});
```

既然我们已经完成了这一步，我们可以启动服务器并在 Postman 中测试一下。

# 测试 GET /todos 路由

我将使用以下命令启动服务器：

```js
**node server/server.js** 
```

在 Postman 中，我们可以开始创建一些待办事项。目前，我们的应用程序和应用程序的测试使用相同的数据库。在上一节中我们运行的`beforeEach`方法调用不幸地擦除了一切，这意味着我们没有数据可获取。我在 Postman 中要做的第一件事是尝试获取我们应该得到的数据，我们应该得到一个空数组，这仍然可以工作。URL 将是`localhost:3000/todos`，确实将是一个 GET 请求。我可以点击发送，这将触发请求，然后我们得到我们的数据：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/34dbc53f-5ac8-4bcd-87f9-143839ddf738.png)

我们有一个对象，我们有我们的`todos`属性，我们有我们的空数组，这是预期的。

现在，您可能已经注意到，每次想要使用它时手动配置路由变得非常乏味，我们将一遍又一遍地使用相同的路由。通过 Postman，我们实际上可以创建一个路由集合，这样我们就可以重新发送请求，而不必手动输入所有信息。在右侧，我可以单击保存旁边的下拉箭头，然后单击另存为。在这里，我可以给我的请求一些详细信息：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/ac4b8cb6-153b-417c-96cd-269e9679134e.png)

我将请求名称更改为`GET /todos`；这是我喜欢使用的命名约定，HTTP 方法后跟 URL。我们现在可以暂时将描述留空，并且我们可以创建一个新的集合，因为我们没有任何集合。Postman Echo 集合是 Postman 提供给您探索此功能的示例集合。我们将创建一个名为`Todo App`的集合。现在，每当我们想要运行该命令时，我们只需转到集合，点击 GET /todos，点击发送，请求就会触发。

让我们继续设置一个`POST`请求来创建一个待办事项，然后我们将运行它，保存它，并重新运行`GET`以确保返回新创建的待办事项。

# 设置 Post 请求以创建待办事项

要创建`POST`请求，如果您还记得，我们必须将方法更改为 POST，URL 将保持不变，`localhost:3000/todos`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/49eb0feb-7dd5-4958-9e2c-01e98e4a4b11.png)

现在，为了使这个请求成功，我们还必须传递一个 Body 标签。这个标签将是一个原始的 JSON 主体。在这里，我们可以指定我们想要发送的数据。在这种情况下，我们要发送的唯一数据属性是`text`，我将其设置为`从 Postman 做的一些事情`：

```js
{ 
  "text": "Something to do from postman"
}
```

现在，我们可以继续执行此操作，然后在下面，我们得到了我们新创建的带有 200 状态代码的 Todo：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/e5588bc3-06ee-437a-8df9-f71995efcf4a.png)

这意味着一切都进行得很顺利。我们可以将其保存到我们的集合中，以便稍后可以轻松地重新运行此操作。我将请求名称更改为`POST /todos`，遵循相同的语法。然后，我可以选择现有的集合，Todo App 集合，并保存它：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/8c148816-7449-49fd-9c48-d2b819286d1c.png)

现在，我只需点击请求，使用*command* + *enter*，或单击发送按钮，即可发送请求，然后我得到了我的`todos`数组，一切看起来都很好。

我总是可以点击 POST，添加第二个，如果我喜欢，可以进行微调，添加数字`2`，然后我可以使用*command* + *enter*来发送它。我可以重新运行`GET`请求，然后在数据库中有两个`todos`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/e15ee861-0822-44b8-8e3a-9006edc40d0e.png)

有了这个，我们的`GET /todos`请求现在已经完成。我们还在 Postman 中设置了我们的集合，这样就可以更快地触发任何这些 HTTP 请求。

我将通过在终端中进行提交来结束本节。我将关闭服务器并运行`git status`。这一次，你会看到我们只有一个文件被修改，这意味着我们可以简单地使用`git commit`和`-a`标志，而不是使用`git add`。`-a`标志将所有修改的文件添加到下一个提交中。它不适用于新的、未跟踪的文件，但修改的文件是完全可以的。然后，我可以添加`-m`标志来指定我的提交消息。对于这个来说，一个好的提交消息将是`Add GET /todos route`：

```js
**git commit -a -m 'Add GET /todos route'** 
```

最后，我们将使用`git push`将其推送到 GitHub，现在我们完成了。在下一节中，我们将为`GET /todos`编写测试用例。

# 测试 GET /todos

现在我们的`GET /todos`路由已经就位，是时候为它添加一个测试用例了。现在，我们实际上可以编写测试用例之前，我们必须处理一个不同的问题。我们在`server.test`文件中的第一件事是删除所有的 Todos，这发生在每个测试之前。`GET /todos`路由基本上依赖于数据库中有它可以返回的 Todos。它将处理 Node Todos，但对于我们的测试用例，我们希望数据库中有一些数据。

为了添加这些数据，我们要做的是修改`beforeEach`，添加一些种子数据。这意味着我们的数据库仍然是可预测的；当它启动时，它总是看起来完全一样，但它会有一些项目。

# 为 GET /todos 测试用例添加种子数据

现在，为了做到这一点，我们要做的第一件事是制作一个虚拟 Todos 数组。这些 Todos 只需要`text`属性，因为其他所有内容都将由 Mongoose 填充。我可以创建一个名为`todos`的常量，将其设置为一个数组，我们将有一个对象数组，其中每个对象都有一个`text`属性。例如，这个可以有一个文本为`First test todo`，然后我可以在数组的第二个项目中添加第二个对象，其`text`属性等于`Second test todo`：

```js
const todos = [{
  text: 'First test todo'
},{
  text: 'Second test todo'
}];
```

现在，我们实际上可以编写测试用例之前，我们必须使用一个全新的 Mongoose 方法`insertMany`修改`beforeEach`，它接受一个数组，如前面的代码块所示，并将所有这些文档插入集合中。这意味着我们需要快速调整代码。

不是使用一个简单的箭头函数调用`done`，我要加上一些花括号，在回调函数内部，我们将调用`Todo.insertMany`，并且我们将使用在前面的代码块中定义的数组调用`insertMany`。这将插入数组中的所有 Todos，我们的两个 Todos，然后我们可以做一些像调用`done`的事情。我将返回响应，这将让我们链接回调，然后我可以添加一个`then`方法，在那里我可以使用一个非常简单的基于表达式的箭头函数。我要做的就是使用表达式语法调用`done`：

```js
beforeEach((done) => {
  Todo.remove({}).then(() => {
    return Todo.insertMany(todos);
  }).then(() => done());
});
```

现在，让我们继续运行测试套件。我现在警告你，其他测试会出问题，因为它们断言的数字现在将不正确。在终端中，我将使用以下命令启动测试套件：

```js
**npm run test-watch** 
```

一旦测试套件启动，我将回到 Atom，正如承诺的那样，两个测试用例都失败了。我们期望`3`是`1`，我们期望`2`是`0`。现在所有的都错了`2`。

为了解决这个问题，我们将使用两种不同的技术。在 server.test.js 文件中，在 Post todos 测试中，对于第一个测试，我们要做的是只查找`text`属性等于`Test todo text`的 Todos：

```js
Todo.find({text}).then((todos) => {
  expect(todos.length).toBe(1);
  expect(todos[0].text).toBe(text);
  done();
}).catch((e) => done(e));
```

这意味着结果的长度仍然是`1`，第一项仍然应该有一个`text`属性等于上面的文本。对于第二个测试，我们将保持`find`调用不变；相反，我们将确保数据库的长度为`2`：

```js
Todo.find().then((todos) => {
  expect(todos.length).toBe(2);
  done();
}).catch((e) => done(e));
```

Todos 集合中应该只有两个文档，因为这是我们添加的所有内容，这是一个失败的测试，所以不应该添加第三个。有了这个设置，你可以看到我们的两个测试用例现在通过了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/5938a07e-7023-4bbc-8d15-0354b7666740.png)

我们现在准备继续并在测试用例中添加一个新的`describe`块。

# 在测试用例中添加一个描述块

我将添加一个`describe`块，描述`GET /todos`路由，传入我们的箭头函数，然后我们可以添加我们的单个测试用例，`it('should get all todos', )`。现在，在这种情况下，所有的`todos`都指的是我们之前添加的两个 Todos。我将传入一个带有`done`参数的箭头函数，我们准备好了。我们所要做的就是开始 super test 请求——我将在 express 应用程序上`request`一些东西——这将是一个 GET 请求，所以我们将调用`.get`，传入 URL`/todos`：

```js
describe('GET /todos', () => { 
  it('should get all todos', (done) => { 
    request(app) 
    .get('/todos') 
  )}; 
});
```

有了这个设置，我们现在准备做出我们的断言；我们没有在请求体中发送任何数据，但我们将对返回的内容做出一些断言。

# 在测试用例中添加断言

我们期望返回`200`，并且我们还将创建一个自定义断言，期望关于 body 的一些内容。我们将使用响应提供我们的回调函数，并期望`res.body.todos`的长度为`2`，`.toBe(2)`。现在我们有了这个设置，我们所要做的就是添加一个`end`调用，并将`done`作为参数传递。

```js
describe('GET /todos', () => {
  it('should get all todos', (done) => {
    request(app)
    .get('/todos')
    .expect(200)
    .expect((res) => {
      expect(res.body.todos.length).toBe(2);
    })
    .end(done);
  )};
});
```

不需要提供一个结束函数，因为我们不是异步地做任何事情。

有了这个设置，我们现在可以继续了。我们可以保存`server.test`文件。这将使用`nodemon`重新运行测试套件；我们应该看到我们的新测试，并且它应该通过。在终端中，我们就是这样得到的：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/adv-node-dev/img/d04de850-8dd9-43c5-8f4b-f04d8d8571ea.png)

我们有`POST /todos`部分；这两个测试都通过了，我们有`GET /todos`部分，一个测试确实通过了。现在，如果我将状态更改为`201`，测试将失败，因为这不是返回的状态。如果我将长度更改为`3`，它将失败，因为我们只添加了 2 个 Todos 作为种子数据。

现在我们完成了，让我们继续提交，保存这段代码。我将关闭`test-watch`脚本，运行`git status`命令，我们有两个修改过的文件，这意味着我可以使用`git commit`与`-a`标志和`-m`标志。记住，`-a`标志将修改的文件添加到下一个提交。这次提交的好消息是`Add tests for GET /todos`：

```js
**git commit -a -m 'Add tests for GET /todos'**
```

我要提交，将其推送到 GitHub，然后我们就完成了。

# 总结

在本章中，我们致力于设置 mongoose，将 mongoose 连接到数据库。我们创建了一些 Todos 模型并运行了测试脚本。接下来，我们研究了 mongoose 验证器、默认值和类型，并自定义了 todo 模型的属性，如测试、完成和完成时间。然后，我们了解了 Postman 的基础知识，并向 Google 发出了 HTTP 请求。我们还研究了配置一些 todo 路由，主要是 POST /todos 和 GET /todos。我们还研究了创建测试用例和测试这些路由。

有了这个设置，我们现在准备继续添加一个全新的路由，这将在下一章中进行。
