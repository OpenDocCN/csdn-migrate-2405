# NodeJS 开发学习手册（一）

> 原文：[`zh.annas-archive.org/md5/551AEEE166502AE00C0784F70639ECDF`](https://zh.annas-archive.org/md5/551AEEE166502AE00C0784F70639ECDF)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

欢迎阅读《学习 Node.js 开发》。本书充满了大量的内容、项目、挑战和真实世界的例子，所有这些都旨在通过实践教授 Node。这意味着在接下来的章节中，您将很早就开始动手写一些代码，并且您将为每个项目编写代码。您将编写支持我们应用程序的每一行代码。现在，我们需要一个文本编辑器。我们有各种文本编辑器选项可供选择。我始终建议使用 Atom，您可以在[atom.io](http://atom.io)找到它。它是免费的、开源的，并且适用于所有操作系统，即 Linux、macOS 和 Windows。它是由 GitHub 背后的人员创建的。

本书中的所有项目都很有趣，并且它们旨在教会您启动自己的 Node 应用程序所需的一切，从规划到开发、测试到部署。现在，当您启动这些不同的 Node 应用程序并阅读本书时，您将遇到错误，这是不可避免的。也许某些东西没有按预期安装，或者您尝试运行一个应用程序，而不是得到预期的输出，您得到了一个非常长的晦涩的错误消息。不要担心，我会在章节中向您展示通过这些错误的技巧和窍门。让我们继续并开始吧。

# 本书适合对象

本书面向希望启动自己的 Node 应用程序、转行或作为 Node 开发人员自由职业的任何人。您应该对 JavaScript 有基本的了解才能跟上本书的内容。

# 本书涵盖的内容

第一章《设置》，讨论了 Node 是什么以及为什么要使用它。在本章中，您将学习 Node 的安装，到本章结束时，您将能够运行您的第一个 Node 应用程序。

第二章《Node 基础知识-第一部分》讨论了构建 Node 应用程序。《Node 基础知识》主题已分为 3 部分。本主题的第一部分包括模块基础知识、需要自己的文件以及第三方 NPM 模块。

第三章《Node 基础知识-第二部分》继续讨论一些更多的 Node 基础知识。本章探讨了 yargs、JSON、addNote 函数和重构，将功能移入单独的函数并测试功能。

第四章《Node 基础知识-第三部分》包括从文件系统中读取和写入内容等内容。我们将深入研究高级 yargs 配置、调试故障应用程序以及一些新的 ES6 函数。

第五章《Node.js 异步编程基础》涵盖了与异步编程相关的基本概念、术语和技术，使其在我们的天气应用程序中变得非常实用。

第六章《异步编程中的回调》是 Node 中异步编程的第二部分。我们将研究回调、HTTPS 请求以及在回调函数中的错误处理。我们还将研究天气预报 API，并获取我们地址的实时天气数据。

第七章《异步编程中的 Promise》是 Node 中异步编程的第三部分，也是最后一部分。本章重点介绍 Promise，它的工作原理，为什么它们有用等等。在本章结束时，我们将在我们的天气应用程序中使用 Promise。

第八章《Node 中的 Web 服务器》讨论了 Node Web 服务器以及将版本控制集成到 Node 应用程序中。我们还将介绍一个名为 Express 的框架，这是最重要的 NPM 库之一。

第九章，*将应用部署到 Web*，讨论了将应用部署到 Web。我们将使用 Git、GitHub，并使用这两项服务将我们的实时应用程序部署到 Web。

第十章，*测试 Node 应用程序-第一部分*，讨论了我们如何测试代码以确保其按预期工作。我们将开始设置测试，然后编写我们的测试用例。我们将研究基本的测试框架和异步测试。

第十一章，*测试 Node 应用程序-第二部分*，继续我们测试 Node 应用程序的旅程。在本章中，我们将测试 Express 应用程序，并研究一些高级的测试方法。

# 为了充分利用本书

Web 浏览器，我们将在整本书中使用 Chrome，但任何浏览器都可以，以及终端，有时在 Linux 上称为命令行，Windows 上称为命令提示符。Atom 作为文本编辑器。以下模块列表将在本书的整个过程中使用：

+   lodash

+   nodemon

+   yargs

+   请求

+   axios

+   express

+   hbs

+   heroku

+   rewire

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

文件下载后，请确保使用最新版本的以下软件解压或提取文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

本书的代码捆绑包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Learning-Node.js-Development`](https://github.com/PacktPublishing/Learning-Node.js-Development)。我们还有来自丰富书籍和视频目录的其他代码捆绑包可用于**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如："将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。"

代码块设置如下：

```js
console.log('Starting app.js');

const fs = require('fs');
const _ = require('lodash');
const yargs = require('yargs');
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```js
const argv = yargs.argv;
var command = process.argv[2];
console.log('Command:', command);
console.log('Process', process.argv); console.log('Yargs', argv);
```

任何命令行输入或输出都以以下方式编写：

```js
cd hello-world node app.js
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中出现。例如："从管理面板中选择系统信息。"

警告或重要说明看起来像这样。

提示和技巧看起来像这样。


# 第一章：设置

在本章中，您将为本书的其余部分设置本地环境。无论您使用的是 macOS、Linux 还是 Windows，我们都将安装 Node，并查看我们如何运行 Node 应用程序。

我们将讨论 Node 是什么，为什么您会想要使用它，以及为什么您会想要使用 Node 而不是像 Rails、C++、Java 或任何其他可以完成类似任务的语言。在本章结束时，您将运行您的第一个 Node 应用程序。这将是简单的，但它将使我们走上创建真实生产 Node 应用程序的道路，这是本书的目标。

更具体地，我们将涵盖以下主题：

+   Node.js 安装

+   Node 是什么

+   为什么使用 Node

+   Atom

+   Hello World

# Node.js 安装

在我们开始讨论 Node 是什么以及它为什么有用之前，您需要先在您的计算机上安装 Node，因为在接下来的几节中，我们将想要运行一些 Node 代码。

现在，要开始，我们只需要两个程序-一个浏览器，我将在整本书中都使用 Chrome，但任何浏览器都可以，还有终端。我将使用**Spotlight**打开终端，在我的操作系统中它就是这个名字。

如果您使用 Windows，寻找命令提示符，您可以使用 Windows 键搜索，然后输入`command prompt`，在 Linux 上，您要寻找命令行，尽管根据您的发行版，它可能被称为终端或命令提示符。

现在，一旦您打开了该程序，您将看到一个屏幕，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/a4d7162c-aef9-40d4-98a9-ec1ea68fbca0.png)

基本上，它在等待您运行一个命令。在整本书中，我们将从终端运行相当多的命令。我将在几节后讨论它，所以如果您以前从未使用过这个，您可以开始舒适地进行导航。

# Node.js 版本确认

在浏览器中，我们可以转到[nodejs.org](http://nodejs.org)下载最新版本的 Node 安装程序（如下所示）。在本书中，我们将使用最新版本 9.3.0：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/01739796-c861-4e5e-a192-0e22f6a8c399.png)

重要的是安装 Node.js 的 V8 版本。它不一定要是 4.0，可以是 1.0，但重要的是它在 V8 分支上，因为 V8 带来了大量新功能，包括您可能在浏览器中使用 ES6 喜欢的所有功能。

ES6 是 JavaScript 的下一个版本，它带来了很多我们将在整本书中使用的优秀增强功能。如果您查看下面的图片，Node.js 长期支持发布计划([`github.com/nodejs/LTS`](https://github.com/nodejs/LTS))，您会看到当前的 Node 版本是 V8，发布于 2017 年 4 月：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/0386ded3-18cb-4911-a3fe-8efd5908b708.png)

在继续之前，我想谈谈 Node 的发布周期。我在上面的图片中所看到的是官方发布周期，这是由 Node 发布的。您会注意到，只有在偶数 Node 版本旁边才会找到活跃的 LTS，蓝色条和维护条。现在，LTS 代表长期支持，这是推荐大多数用户使用的版本。我建议您坚持当前提供的 LTS 选项（Node v 8.9.4 LTS），尽管左侧的任何内容都可以，这显示在[nodejs.org](http://nodejs.org)上的两个绿色按钮上。

现在，您可以看到，主要版本号每六个月增加一次。无论有任何大的全面性变化，这都会像钟表一样发生，即使没有发生任何重大变化。这不像 Angular，从 1.0 跳到 2.0 几乎就像使用完全不同的库一样。这在 Node 中并不是这种情况，您从本书中得到的是 Node 所提供的最新和最好的东西。

# 安装 Node

一旦确认并选择了版本，我们所要做的就是在 Node 网站([nodejs.org](http://nodejs.org))上点击所需版本按钮并下载安装程序。安装程序是那种基本的*点击几次下一步就完成*类型的安装程序，不需要运行任何花哨的命令。我将启动安装程序。如下截图所示，它只会问几个问题，然后让我们通过所有问题点击下一步或继续：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/9d793ed5-bdc8-43e9-80af-9c6e539d4a72.png)

您可能想要指定自定义目标，但如果您不知道这意味着什么，并且通常在安装程序时不这样做，请跳过该步骤。在下一个截图中，您可以看到我只使用了 58.6 MB，没有问题。

我将通过输入我的密码来运行安装程序。一旦我输入密码，安装 Node 应该只需要几秒钟：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/83317cab-1d71-4aaf-ba99-43b150100919.png)

如下截图所示，我们有一条消息，说安装已成功完成，这意味着我们可以开始了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/17dde6f1-27e8-43e8-b7ba-d3f342d8261b.png)

# 验证安装

现在 Node 已经成功安装，我们可以通过在终端中运行 Node 来验证。在终端中，我将通过退出终端并重新打开来关闭它：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/ef346e4a-2e45-4758-9eac-3c7d3a12bada.png)

我之所以打开它是因为我们安装了一个新的命令，有些终端需要在运行新命令之前重新启动。

在我们的情况下，我们重新启动了一些东西，我们可以运行我们全新的命令，所以我们会输入它：

```js
node -v
```

在这个命令中，我们正在运行 Node 命令，并传入所谓的**标志**，即连字符后跟一个字母。它可以是`a`，可以是`j`，或者在我们的情况下是`v`。这个命令将打印当前安装的 Node 版本。

我们可能会遇到这样的错误：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/624d0bbe-8758-48a9-a8d5-667582827385.png)

如果您尝试运行一个不存在的命令，比如`nodeasdf`，您将看到命令未找到。如果您看到这个，通常意味着 Node 安装程序没有正确工作，或者您根本没有运行它。

然而，在我们的情况下，使用`v`标志运行 Node 应该会得到一个数字。在我们的情况下，它是版本 9.3.0。如果您已经安装了 Node，并且看到类似下一个截图的东西，那么您已经完成了。在下一节中，我们将开始探索 Node 到底是什么。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/c6ad6c47-19b7-41ae-b798-a6cd09c51270.png)

# 什么是 Node？

Node 诞生于原始开发人员将 JavaScript 带到了您的机器上作为一个独立的进程，而不仅仅是在浏览器中运行。这意味着我们可以在浏览器之外使用 JavaScript 创建应用程序。

现在，JavaScript 以前的功能集是有限的。当我在浏览器中使用它时，我可以做一些事情，比如更新 URL 和删除 Node 标志，添加点击事件或其他任何东西，但我实际上不能做更多。

有了 Node，我们现在有了一个看起来更类似于其他语言（如 Java、Python 或 PHP）的功能集。其中一些如下：

+   我们可以使用 JavaScript 语法编写 Node 应用程序

+   您可以操纵您的文件系统，创建和删除文件夹

+   您可以直接创建查询数据库

+   您甚至可以使用 Node 创建 Web 服务器

这些是过去不可能的事情，现在却因为 Node 而成为可能。

现在，Node 和在浏览器中执行的 JavaScript 都在完全相同的引擎上运行。它被称为 V8 JavaScript 运行时引擎。这是一个将 JavaScript 代码编译成更快的机器代码的开源引擎。这是 Node.js 如此快速的一个重要部分。

机器码是低级代码，你的计算机可以直接运行它，而无需解释。你的计算机只知道如何运行某些类型的代码，例如，你的计算机不能直接运行 JavaScript 代码或 PHP 代码，而是需要先将其转换为低级代码。

使用这个 V8 引擎，我们可以将我们的 JavaScript 代码编译成更快的机器码，并执行它。这就是所有这些新功能的来源。V8 引擎是用一种叫做 C++的语言编写的。因此，如果你想扩展 Node 语言，你不会编写 Node 代码，而是编写建立在 V8 已有基础上的 C++代码。

现在，我们不会在这本书中编写任何 C++代码。这本书不是关于扩展 Node，而是关于使用 Node。因此，我们只会编写 JavaScript 代码。

说到 JavaScript 代码，让我们开始在终端内编写一些。在整本书中，我们将创建文件并执行这些文件，但我们实际上可以通过运行`node`命令来创建一个全新的 Node 进程。

参考下面的截图，我有一个小的右尖括号，它正在等待 JavaScript Node 代码，而不是一个新的命令提示符命令：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/c5947e1b-5bd5-472e-993d-6c281a8324d0.png)

这意味着我可以运行像`console.log`这样的东西，你可能已经知道，它会将消息记录到屏幕上。`log`是一个函数，所以我会像这样调用它，打开和关闭括号，并在两个单引号内传递一个字符串，一个消息`Hello world!`，就像下面的命令行中所示：

```js
console.log('Hello world!');
```

这将在屏幕上打印出 Hello world。如果我按下*enter*，Hello world！就会像你期望的那样打印出来，就像下面的代码输出中所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/baf96c0b-f956-42f2-9fd4-1ae1d93d86c1.png)

现在，在幕后实际发生了什么？这就是 Node 的工作原理。它接受你的 JavaScript 代码，将其编译成机器码，然后执行它。在上面的代码中，你可以看到它执行了我们的代码，打印出了 Hello world！现在，当我们执行这个命令时，V8 引擎在幕后运行，并且也在 Chrome 浏览器内运行。

如果我在 Chrome 中打开开发者工具，可以通过设置 | 更多工具 | 开发者工具来实现：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/c50b749f-f331-445c-a2cf-a4e5effb477a.png)

我可以忽略大部分的东西。我只是在寻找控制台选项卡，就像下面的截图中所示的那样：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/46808206-8003-411c-8dca-2745900d99a3.png)

上面的截图显示了控制台，这是一个可以运行一些 JavaScript 代码的地方。我可以输入完全相同的命令`console.log('Hello world!');`并运行它：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/608f3133-f3d0-4562-9a9b-65c76466c07a.png)

正如你在上面的截图中所看到的，Hello world！打印到了屏幕上，这与我们之前在终端中运行时得到的完全相同的结果。在这两种情况下，我们都是通过 V8 引擎运行它，输出也是相同的。

现在，我们已经知道这两者是不同的。Node 具有文件系统操作等功能，而浏览器具有操作窗口内显示内容的功能。让我们花点时间来探索它们的区别。

# 使用 Node 和浏览器进行 JavaScript 编码的区别

在浏览器中，如果你进行过任何 JavaScript 开发，你可能已经使用过`window`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/c86d2ba0-91d4-4829-81fc-5471adbb8604.png)

Window 是全局对象，它基本上存储了你可以访问的一切。在下面的截图中，你可以看到诸如数组、各种 CSS 操作和 Google Analytics 关键字等内容；基本上你创建的每个变量都存在于 Window 内：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/29a97655-4da3-4dd9-b5ae-fdafb9a1f4dd.png)

在 Node 内部，我们有一个类似的东西叫做`global`，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/1cb4f89c-3e2f-4e20-bdfd-2d67697b1e46.png)

它不叫`window`，因为在 Node 中没有浏览器窗口，因此它被称为`global`。`global`对象存储了许多与`window`相同的东西。在下面的截图中，你可以看到一些可能很熟悉的方法，比如`setTimeout`和`setInterval`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/586f7689-f17e-430e-8b70-a9c8c0f411c8.png)

如果我们看一下这段代码的截图，我们会发现大部分东西都是在 window 中定义的，只有一些例外，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/ddde7001-804c-4a88-a11f-b0c14722b083.png)

现在，在 Chrome 浏览器中，我也可以访问`document`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/c9ca1af3-26a5-41f2-8d40-a0c092e1d6e4.png)

`document`对象在 Node 网站中存储了对**文档对象模型**（**DOM**）的引用。`document`对象显示了我在浏览器视口中的内容，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/4f4e6fb3-b941-4b3a-b829-06187cf3fef4.png)

我可以更改文档以更新在浏览器视口中显示的内容。当然，在 Node 中我们没有这个 HTML `document`，但我们有类似的东西，叫做`process`。你可以通过从 Node 运行 process 来查看它，在下面的截图中，我们有关于正在执行的特定 Node 进程的大量信息：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/dafb06f4-45b7-4327-95e0-ce6f3ac2900f.png)

这里还有一些方法可以关闭当前的 Node 进程。我想让你运行`process.exit`命令，并将数字零作为参数传入，表示退出时没有错误：

```js
process.exit(0);
```

当我运行这个命令时，你可以看到我现在回到了命令提示符，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/07a39364-2899-4019-a0b4-3900fcd8b12e.png)

我已经离开了 Node，现在可以运行任何常规的命令提示符命令，比如检查我的 Node 版本。我可以通过运行`node`随时重新进入 Node，并且可以通过两次按下*control* + *C*来离开，而不使用`process.exit`命令。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/eb2936f8-a6d8-4880-9ca1-e3232ac78ae1.png)

现在，我又回到了我的常规命令提示符。所以，这些是显而易见的差异，在浏览器中你有可视区域，window 变成了 global，而 document 基本上变成了 process。当然，这是一个概括，但这些是一些大的变化。我们将在整本书中探索所有细微之处。

现在，当有人问你什么是 Node 时，你可以说*Node 是一个使用 V8 引擎的 JavaScript 运行时*。当他们问你 V8 引擎是什么时，你可以说*V8 引擎是一个用 C++编写的开源 JavaScript 引擎，它接受 JavaScript 代码并将其编译成机器代码。它被用在 Node.js 内部，也被用在 Chrome 浏览器中*。

# 为什么使用 Node

在本节中，我们将探讨 Node.js 背后的原因。为什么它在创建后端应用方面如此出色？为什么像 Netflix、Uber 和 Walmart 这样的公司正在越来越多地使用 Node.js 在生产中？

正如你可能已经注意到的，由于你正在学习这门课程，当人们想要学习一门新的后端语言时，他们越来越多地转向 Node 作为他们想要学习的语言。Node 技能组合需求很高，无论是需要每天使用 Node 来编译他们的应用程序的前端开发人员，还是使用 Node.js 创建应用程序和实用程序的工程师。所有这些都使 Node 成为了首选的后端语言。

现在，如果我们看一下 Node 的主页，我们会发现三个句子，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/b3212c22-2924-411a-ac57-d8e8db1d71b7.png)

在上一节中，我们解释了第一个句子。我们看了 Node.js 是什么。图片中只有三个句子，所以在本节中，我们将看一下后面的两个句子。我们现在来读一下，然后我们将分解它，学习 Node 为什么如此出色。

第一句话，Node.js 使用事件驱动的、非阻塞 I/O 模型，使其轻量高效；我们现在将探索所有这些。第二句话，我们将在本节结束时探讨——Node.js 的打包生态系统 npm 是世界上最大的开源库生态系统。现在，这两句话中包含了大量的信息。

我们将介绍一些代码示例，深入研究一些图表和图形，探讨 Node 的不同之处以及它的优点。

Node 是一个事件驱动的、非阻塞的语言。那么，什么是 I/O？I/O 是您的应用程序一直在做的事情。当您读取或写入数据库时，这就是 I/O，它是输入/输出的缩写。

这是您的 Node 应用程序与物联网中其他事物的通信。这可能是数据库读写请求，您可能正在更改文件系统中的一些文件，或者您可能正在向单独的 Web 服务器发出 HTTP 请求，例如 Google API，以获取用户当前位置的地图。所有这些都使用 I/O，而 I/O 需要时间。

非阻塞 I/O 非常好。这意味着当一个用户从 Google 请求 URL 时，其他用户可以请求数据库文件读写访问，他们可以请求各种各样的事情，而不会阻止其他人完成一些工作。

# 阻塞和非阻塞软件开发

让我们继续看看阻塞和非阻塞软件开发之间的区别：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/d98b8e36-15cf-4a2e-8a6f-74ae6d3a7f03.png)

在前面的截图中，我有两个将要执行的文件。但在进行之前，首先让我们探索每个文件的操作方式，以及完成程序所需的步骤。 

这将帮助我们了解阻塞和非阻塞之间的重大差异，我在图像的左侧显示了阻塞，这不是 Node 使用的方式，而非阻塞在右侧，这正是我们书中所有 Node 应用程序的运行方式。

您不必了解诸如 require 之类的具体细节，才能理解这个代码示例中发生了什么。我们将以非常一般的方式来分解事物。每个代码的第一行负责获取一个被调用的函数。这个函数将是我们模拟的 I/O 函数，它将去数据库，获取一些用户数据并将其打印到屏幕上。

请参考前面的代码图像。在我们加载函数之后，两个文件都尝试使用 ID 为`123`的用户。当它获取到该用户时，首先打印`user1`字符串到屏幕上，然后继续获取 ID 为`321`的用户，并将其打印到屏幕上。最后，两个文件都将`1 + 2`相加，将结果 3 存储在`sum`变量中，并将其打印到屏幕上。

尽管它们都做同样的事情，但它们的方式却大不相同。让我们逐步分解各个步骤。在下面的代码图像中，我们将介绍 Node 执行的内容以及所需的时间：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/cbf26905-e195-4d79-be4f-e6fd874a2483.png)

您可以考虑前面截图中显示的秒数；这并不重要，只是为了显示两个文件之间的相对操作速度。

# 阻塞 I/O 的工作方式

阻塞示例可以如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/edacad6f-9299-41ce-a728-a6172afbd4b1.png)

在我们的阻塞示例中，首先发生的事情是我们在代码的第 3 行获取用户：

```js
var user1 = getUserSync('123');
```

现在，这个请求需要我们去数据库，这是一个 I/O 操作，需要一点时间。在我们的例子中，我们将说它需要三秒。

接下来，在代码的第 4 行，我们将用户打印到屏幕上，这不是一个 I/O 操作，它会立即运行，将`user1`打印到屏幕上，如下图所示：

```js
console.log('user1', user1); 
```

正如你在下面的屏幕截图中所看到的，这几乎不需要时间：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/400cbd6b-099e-48ab-81f4-291cf7d055f2.png)

接下来，我们等待获取`user2`：

```js
var user2 = getUserSync('321');
```

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/0888c6f8-da6d-4320-aafa-4f6692b70f96.png)

当`user2`返回时，正如你所期望的那样，我们将其打印到屏幕上，这正是第 7 行发生的事情：

```js
console.log('user2', user2);
```

最后，我们将数字相加并将其打印到屏幕上：

```js
var sum = 1 + 2; 
console.log('The sum is ' + sum); 
```

这些都不是 I/O 操作，所以在这里，我们的总和几乎立即打印到屏幕上。

这就是阻塞的工作原理。它被称为阻塞，因为当我们从数据库获取数据时，也就是进行 I/O 操作时，我们的应用程序无法做其他任何事情。这意味着我们的机器会空闲地等待数据库的响应，甚至不能做一些简单的事情，比如将两个数字相加并将它们打印到屏幕上。在阻塞系统中这是不可能的。

# 工作中的非阻塞 I/O

在我们的非阻塞示例中，这就是我们将构建我们的 Node 应用程序的方式。

让我们逐行分解这个代码示例。首先，事情的开始方式与我们在阻塞示例中讨论的方式非常相似。我们将为`user1`启动`getUser`函数，这正是我们之前所做的：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/9c170d20-73ec-417b-a51a-62f13963b8de.png)

但我们并没有等待，我们只是启动了那个事件。这都是 Node.js 内部事件循环的一部分，我们将会详细探讨这个问题。

请注意，这需要一点时间；我们只是开始请求，我们并没有等待数据。我们接下来要做的可能会让你感到惊讶。我们没有将`user1`打印到屏幕上，因为我们仍在等待该请求返回，而是开始获取 ID 为`321`的`user2`的过程：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/e6e86e00-25f0-453b-89f5-063adbfef43e.png)

在代码的这一部分中，我们启动了另一个事件，这需要一点时间来完成-这不是一个 I/O 操作。现在，在幕后，数据库的获取是 I/O 操作，但启动事件，调用这个函数并不是，所以它会非常快速地发生。

接下来，我们打印总和。总和与这两个用户对象无关。它们基本上没有关联，所以在打印`sum`变量之前，我们不需要等待用户返回，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/989ab9b8-023d-4e73-acd5-ebf2d460f179.png)

打印总和之后会发生什么？嗯，我们有点线框，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/47d4fbae-786a-469b-ba5d-eff9d7b767dd.png)

这个框表示我们的事件得到响应所需的模拟时间。现在，这个框的宽度与阻塞示例的第一部分（等待 user1）中的框完全相同，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/7b946502-ff7c-4c2e-8fe8-2be5a4ae7a62.png)

使用非阻塞并不会使我们的 I/O 操作变得更快，但它可以让我们同时运行多个操作。

在非阻塞的例子中，我们在半秒钟之前启动了两个 I/O 操作，在三秒半之间，两者都返回，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/88a19684-fd14-41b8-89d3-9feeee9f4591.png)

现在，结果是整个应用程序完成得更快。如果比较执行这两个文件所花费的时间，非阻塞版本在三秒多一点结束，而阻塞版本则需要六秒多一点。相差 50%。这 50%来自于阻塞中我们有两个请求，每个请求需要三秒，而在非阻塞中，我们有两个请求，每个请求需要三秒，但它们同时运行。

使用非阻塞模式，我们仍然可以做一些事情，比如打印总和，而不必等待数据库回应。现在，这就是两者之间的重大区别；阻塞，一切按顺序发生，在非阻塞中，我们启动事件，附加回调，这些回调稍后被触发。我们仍然打印出`user1`和`user2`，只是当数据返回时才这样做，因为数据不会立即返回。

在 Node.js 中，事件循环会为事件附加一个监听器，比如数据库回应完成。当它完成时，在非阻塞情况下调用你传递的回调函数，然后我们将其打印到屏幕上。

现在，想象一下这是一个网页服务器，而不是前面的例子。这意味着如果一个网页服务器来查询数据库，我们不能处理其他用户的请求而不启动一个单独的线程。现在，Node.js 是单线程的，这意味着你的应用程序在一个单一的线程上运行，但由于我们有非阻塞 I/O，这不是一个问题。

在阻塞的情况下，我们可以在两个单独的线程上处理两个请求，但这并不是很好扩展，因为对于每个请求，我们都必须增加应用程序使用的 CPU 和 RAM 资源的数量，而且这很糟糕，因为这些线程仍然处于空闲状态。仅仅因为我们可以启动其他线程并不意味着我们应该这样做，我们正在浪费没有做任何事情的资源。

在非阻塞的情况下，我们不是通过创建多个线程来浪费资源，而是在一个线程上做所有事情。当一个请求进来时，I/O 是非阻塞的，所以我们不会占用比根本没有发生更多的资源。

# 使用终端的阻塞和非阻塞示例

让我们实时运行这些示例，看看我们得到什么。我们有两个文件（`blocking`和`non-blocking`文件），我们在上一节中看到了。

我们将运行这两个文件，我正在使用 Atom 编辑器来编辑我的文本文件。这些是我们将在本节后面设置的东西，这只是为了让你看看，你不需要运行这些文件。

现在，`blocking`和`non-blocking`文件，都将被运行，并且它们将以不同的方式做与我们在上一节中所做的类似的事情。两者都使用 I/O 操作，`getUserSync`和`getUser`，每个操作需要 5 秒。时间没有区别，只是它们执行的顺序使非阻塞版本快得多。

现在，为了模拟和展示工作原理，我将添加一些`console.log`语句，如下面的代码示例所示，`console.log('starting user1')`，`console.log('starting user2')`。

这将让我们看到终端内部的工作原理。通过运行`node blocking.js`，这就是我们运行文件的方式。我们输入`node`，然后指定文件名，如下面的代码所示：

```js
 node blocking.js 
```

当我运行文件时，我们会得到一些输出。开始用户 1 打印到屏幕上，然后停在那里：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/20b59ccb-f0e6-489a-bfcb-4d12c123e78c.png)

现在，我们有用户 1 对象打印到屏幕上，名字是 Andrew，并且开始用户 2 打印到屏幕上，如下面的代码输出所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/1042e6f6-cea0-4939-a0a6-f5ae5687895d.png)

之后，大约 5 秒后，用户 2 对象带着名字 Jen 回来。

如前面的屏幕截图所示，我们的两个用户已经打印到屏幕上，最后我们的总和，即 3，打印到屏幕上；一切都很顺利。

请注意，开始用户 1 立即后面就是用户 1 的完成，开始用户 2 立即后面就是用户 2 的完成，因为这是一个阻塞应用程序。

现在，我们将运行非阻塞文件，我称之为`non-blocking.js`。当我运行这个文件时，开始用户 1 打印，开始用户 2 打印，然后总和连续打印：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/b2645e90-ed2b-47f9-bc54-0f86d99d7392.png)

大约 5 秒后，基本上在同一时间，用户 1 和用户 2 都在屏幕上打印出来。

这就是非阻塞的工作原理。仅仅因为我们启动了一个 I/O 操作，并不意味着我们不能做其他事情，比如启动另一个操作并将一些数据打印到屏幕上，在这种情况下只是一个数字。这就是重大的区别，也是非阻塞应用程序如此出色的地方。它们可以在完全相同的时间做很多事情，而不必担心多线程应用程序的混乱。

让我们回到浏览器，再次查看 Node 网站上的那些句子：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/5362f1ab-d1ae-4a24-805f-0c29032f702f.png)

Node.js 使用事件驱动的、非阻塞的 I/O 模型，使其轻量级和高效，我们在实际操作中看到了这一点。

因为 Node 是非阻塞的，我们能够将应用程序所需的时间减少了一半。这种非阻塞 I/O 使我们的应用程序非常快速，这就是轻量级和高效的作用所在。

# Node 社区-解决问题的开源库

现在，让我们去看 Node 网站上的最后一句话，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/77e0d3cd-2131-4e2b-9e51-24548fa6adaa.png)

Node.js 的软件包生态系统 npm 是世界上最大的开源库生态系统。这正是使 Node 如此出色的地方。这是锦上添花-社区，每天都有人开发新的库，解决 Node.js 应用程序中的常见问题。

诸如验证对象、创建服务器以及使用套接字实时提供内容等事情。所有这些都已经有库构建好了，所以你不必担心这些。这意味着你可以专注于与你的应用程序相关的特定事物，而不必在你甚至写真正的代码之前创建所有这些基础设施，这些代码是针对你应用程序的特定用例的。

现在，npm 可以在[npmjs.org](http://npmjs.org)上找到，这是我们将寻求许多第三方模块的网站：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/8b3348a0-e931-4ece-a38d-7fbee074a008.png)

如果你试图在 Node 中解决一个通用的问题，很有可能已经有人解决了。例如，如果我想验证一些对象，比如我想验证一个名字属性是否存在，以及是否有一个长度为三的 ID。我可以去谷歌或者去 npm；我通常选择谷歌，然后搜索`npm validate object`。

当我谷歌搜索时，我只会寻找[npmjs.com](http://npmjs.com)的结果，你可以发现前三个结果都来自那里：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/83bd9ccc-dcdd-4f5f-aff2-b74cc3b8c031.png)

我可以点击第一个，这将让我探索文档，看看它是否适合我：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/c77764e8-64dc-4c68-947c-e4e74dbb858a.png)

这个看起来很不错，所以我可以毫不费力地将它添加到我的应用程序中。

现在，我们将通过这个过程。别担心，我不会让你不知所措地如何添加第三方模块。我们将在书中使用大量的第三方模块，因为这才是真正的 Node 开发者所做的。他们利用了出色的开发者社区，这也是使 Node 如此出色的最后一点。

这就是为什么 Node 能够达到当前的强大地位，因为它是非阻塞的，这意味着它非常适合 I/O 应用程序，并且有一个出色的开发者社区。因此，如果你想要完成任何事情，有可能已经有人编写了代码来完成它。

这并不是说你永远不应该再次使用 Rails 或 Python 或任何其他阻塞语言，这不是我的意思。我真正想向你展示的是 Node.js 的强大之处，以及你如何使你的应用程序变得更好。像 Python 这样的语言有一些库，比如旨在为 Python 添加非阻塞特性的 Twisted。尽管存在一个大问题，那就是所有的第三方库仍然是以阻塞方式编写的，所以你在使用哪些库方面受到了很大的限制。

由于 Node 是从头开始构建的非阻塞式，[npmjs.com](http://npmjs.com)上的每个库都是非阻塞式的。所以你不必担心找到一个是非阻塞式的还是阻塞式的；你可以安装一个模块，知道它是从头开始使用非阻塞式思想构建的。

在接下来的几节中，你将编写你的第一个应用程序，并从终端运行它。

# 不同的文本编辑器用于节点应用程序

在这一节中，我想给你介绍一下你可以用来阅读本书的各种文本编辑器。如果你已经有一个你喜欢使用的，你可以继续使用你已经有的。在本书中，没有必要更换编辑器来完成任何工作。

现在，如果你没有一个，并且正在寻找一些选择，我总是建议使用**Atom**，你可以在[atom.io](http://atom.io)找到它。它是免费的，开源的，并且可以在所有操作系统上使用，包括 Linux、macOS 和 Windows。它是由 GitHub 背后的人创建的，这是我在本书中将要使用的编辑器。有一个很棒的主题和插件开发社区，所以你真的可以根据自己的喜好进行定制。

除了 Atom 之外，还有一些其他选择。我听到很多人在谈论**Visual Studio Code**。它也是开源的，免费的，并且可以在所有操作系统上使用。如果你不喜欢 Atom，我强烈建议你试试这个，因为我听到很多好评。

接下来，我们总是有**Sublime Text**，你可以在[sublimetext.com](http://sublimetext.com)找到。现在，Sublime Text 并不是免费的，也不是开源的，但是很多人确实喜欢使用它。我更喜欢 Atom，因为它与 Sublime Text 非常相似，但我觉得它更快速、更容易使用，而且它是免费和开源的。

现在，如果你正在寻找一个更高级的编辑器，拥有所有 IDE 的功能，而不是一个文本编辑器，我总是推荐**JetBrains**。他们的产品都不是免费的，尽管它们都有 30 天的免费试用期，但它们确实是最好的工具。如果你发现自己处于公司环境中，或者你在一家公司愿意为编辑器付费的工作中，我总是建议你选择 JetBrains。他们的所有编辑器都配备了你所期望的所有工具，比如版本控制集成、调试工具和内置的部署工具。

所以，请花点时间，下载你想要使用的，玩弄一下，确保它符合你的需求，如果不符合，再尝试另一个。

# Hello World - 创建和运行第一个 Node 应用程序

在这一节中，你将创建并运行你的第一个 Node 应用程序。嗯，它将是一个简单的应用程序。它将演示整个过程，从创建文件到从终端运行它们。

# 创建 Node 应用程序

第一步是创建一个文件夹。我们创建的每个项目都将放在自己的文件夹中。我将在 macOS 上打开**Finder**并导航到我的桌面。我希望你也能在你的操作系统上打开桌面，无论你是在 Linux、Windows 还是 macOS 上，并创建一个名为`hello-world`的全新文件夹。

我不建议在项目文件或文件夹名称中使用空格，因为这只会使在终端内导航变得更加混乱。现在，我们有了这个`hello-world`文件夹，我们可以在编辑器中打开它。

现在我将使用 c*ommand* + *O*（Windows 用户为*Ctrl* + *O*）来打开，然后我将导航到桌面并双击我的 hello-world 文件夹，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/0f41597b-8ced-4bd1-a43f-84b71697a3d6.png)

在左边，我有我的文件，没有。所以，让我们创建一个新的。我将在项目的根目录中创建一个新文件，我们将把它命名为`app.js`，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/1f21ffe8-49cf-414a-bfa2-e0cab5682fa0.png)

这将是我们在 Node 应用程序中唯一的文件，而且在这个文件中，我们可以编写一些代码，当我们启动应用程序时，它将被执行。

在未来，我们将做一些疯狂的事情，比如初始化数据库和启动 Web 服务器，但现在我们将简单地使用`console.log`，这意味着我们正在访问控制台对象上的日志属性。这是一个函数，所以我们可以用括号调用它，然后我们将一个字符串作为一个参数传递进去，`Hello world!`。我会在末尾加上一个分号并保存文件，如下所示的代码：

```js
console.log('Hello world!');
```

这将是我们运行的第一个应用程序。

现在，请记住，这门课程有一个基本的 JavaScript 要求，所以这里的任何东西对你来说都不应该太陌生。我将在这门课程中涵盖所有新鲜的内容，但基础知识，比如创建变量，调用函数，这些应该是你已经熟悉的。

# 运行 Node 应用程序

现在我们有了`app.js`文件，唯一剩下的事情就是运行它，我们将在终端中进行。现在，要运行这个程序，我们必须导航到我们的项目文件夹中。如果你对终端不熟悉，我会给你一个快速的复习。

你可以随时使用`pwd`在 Linux 或 macOS 上，或者在 Windows 上使用`dir`命令来查看你所在的位置。当你运行它时，你会看到类似于以下截图的内容：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/d60c2c2f-132e-4e91-9502-3ac7e918147c.png)

我在`Users`文件夹中，然后我在我的用户文件夹中，我的用户名恰好是`Gary`。

当你打开终端或命令提示符时，你将会在你的用户目录中开始。

我们可以使用`cd`进入桌面，就像这样：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/8f231b7e-2265-4f50-8652-6f360e5727ee.png)

现在我们坐在桌面上。你可以从计算机的任何地方运行另一个命令`cd /users/Gary/desktop`。这将导航到你的桌面，无论你位于哪个文件夹。命令`cd desktop`要求你在用户目录中才能正确工作。

现在我们可以通过 cd 进入我们的项目目录，我们称之为`hello-world`，如下命令所示：

```js
cd hello-world
```

通过以下截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/3490414c-477f-42bf-a6b8-59748150c574.png)

一旦我们在这个目录中，我们可以在 Linux 或 Mac 上运行`ls`命令（在 Windows 上是`dir`命令）来查看我们所有的文件，而在这种情况下，我们只有一个，我们有`app.js`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/533e8079-8292-4d97-a74d-ddb45f680e25.png)

这是我们将要运行的文件。

现在，在你做任何其他事情之前，请确保你在`hello-world`文件夹中，并且你应该有`app.js`文件。如果有的话，我们要做的就是运行`node`命令，后面跟一个空格，这样我们就可以传入一个参数，那个参数就是文件名`app.js`，如下所示：

```js
node app.js
```

一旦你准备好了，按下*enter*，然后我们就可以看到，Hello world!打印到屏幕上，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/dcd99b26-6948-473b-a370-a873bf676c13.png)

这就是创建和运行一个非常基本的 Node 应用程序所需的全部步骤。虽然我们的应用程序没有做任何酷炫的事情，但我们将在整本书中使用这个创建文件夹/文件并在终端中运行它们的过程，所以这是我们开始制作真实世界 Node 应用程序的一个很好的开始。

# 总结

在本章中，我们接触了 Node.js 的概念。我们看了一下 Node 是什么，我们了解到它是建立在 V8 JavaScript 引擎之上的。然后我们探讨了为什么 Node 变得如此流行，它的优势和劣势。我们看了一下我们可以选择的不同文本编辑器，最后，你创建了你的第一个 Node 应用程序。

在下一章中，我们将深入并创建我们的第一个应用程序。我真的很兴奋开始编写真实世界的应用程序。


# 第二章：Node 基础-第一部分

在本章中，你将学到很多关于构建 Node 应用的知识，你将实际上构建你的第一个 Node 应用程序。这将是真正有趣的开始。

我们将开始学习所有内置到 Node 中的模块。这些是让你能够以前从未能够做到的 JavaScript 的对象和函数。我们将学习如何做一些事情，比如读写文件系统，这将在 Node 应用程序中用来持久化我们的数据。

我们还将研究第三方 npm 模块；这是 Node 变得如此受欢迎的一个重要原因。npm 模块为你提供了一个很好的第三方库集合，你可以使用它们，它们也有非常常见的问题。因此，你不必一遍又一遍地重写那些样板代码。在本章中，我们将使用第三方模块来帮助获取用户输入。

本章将专门涵盖以下主题：

+   模块基础

+   引入自己的文件

+   第三方模块

+   全局模块

+   获取输入

# 模块基础

在本节中，你将最终学习一些 Node.js 代码，我们将以讨论 Node 中的模块开始。模块是功能单元，所以想象一下，我创建了一些做类似事情的函数，比如一些帮助解决数学问题的函数，例如加法、减法和除法。我可以将它们捆绑成一个模块，称之为 Andrew-math，其他人可以利用它。

现在，我们不会讨论如何制作我们自己的模块；事实上，我们将讨论如何使用模块，这将使用 Node 中的一个函数`require()`来实现。`require()`函数将让我们做三件事：

+   首先，它让我们加载 Node.js 捆绑的模块。这些包括 HTTP 模块，它让我们创建一个 Web 服务器，以及`fs`模块，它让我们访问机器的文件系统。

我们还将在后面的部分中使用`require()`来加载第三方库，比如 Express 和 Sequelize，这将让我们编写更少的代码。

+   我们将能够使用预先编写的库来处理复杂的问题，我们所需要做的就是通过调用一些方法来实现`require()`。

+   我们将使用`require()`来引入我们自己的文件。它将让我们将应用程序分解为多个较小的文件，这对于构建真实世界的应用程序至关重要。

如果你的所有代码都在一个文件中，测试、维护和更新将会非常困难。现在，`require()`并不那么糟糕。在本节中，我们将探讨`require()`的第一个用例。

# 使用`require()`的情况

我们将看一下两个内置模块；我们将弄清楚如何引入它们和如何使用它们，然后我们将继续开始构建那个 Node 应用程序的过程。

# 应用程序的初始化

我们在终端中的第一步是创建一个目录来存储所有这些文件。我们将使用`cd Desktop`命令从我们的主目录导航到桌面：

```js
cd Desktop
```

然后，我们将创建一个文件夹来存储这个项目的所有课程文件。

现在，这些课程文件将在每个部分的资源部分中提供，因此如果你遇到困难，或者你的代码出了问题，你可以下载课程文件，比较你的文件，找出问题所在。

现在，我们将使用`mkdir`命令来创建那个文件夹，这是**make directory**的缩写。让我们将文件夹命名为`notes-node`，如下所示：

```js
mkdir notes-node
```

我们将在 Node 中制作一个笔记应用，所以`notes-node`似乎很合适。然后我们将`cd`进入`notes-node`，然后我们可以开始玩一些内置模块：

```js
cd notes-node
```

这些模块是内置的，所以不需要在终端中安装任何东西。我们可以直接在我们的 Node 文件中引入它们。

在这个过程中的下一步是打开 Atom 文本编辑器中的那个目录。所以打开我们刚刚在桌面上创建的目录，你会在那里找到它，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/0c1f5e61-9318-4a46-8fb2-994408a8d2d1.png)

现在，我们需要创建一个文件，并将该文件放在项目的根目录中：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/9ef115c8-64d7-428a-b25d-28f3441d2057.png)

我们将把这个文件命名为`app.js`，这是我们应用程序的起点：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/9fdc5112-279d-4049-8f40-c7a820d516d2.png)

我们将编写其他在整个应用程序中使用的文件，但这是我们唯一会从终端运行的文件。这是我们应用程序的初始化文件。

# 使用 require()的内置模块

现在，为了开始，我将首先使用`console.log`打印`Starting app`，如下面的代码所示：

```js
console.log('Starting app');
```

我们这样做的唯一原因是为了跟踪我们的文件如何执行，我们只会在第一个项目中这样做。在以后，一旦你熟悉了文件的加载和运行方式，我们就可以删除这些`console.log`语句，因为它们将不再必要。

在调用`console.log`开始应用程序之后，我们将使用`require()`加载一个内置模块。

我们可以在 Node.js API 文档中获得所有内置模块的完整列表。

要查看 Node.js API 文档，请转到[nodejs.org/api](http://nodejs.org/api)。当你访问这个 URL 时，你会看到一个很长的内置模块列表。使用**文件系统**模块，我们将创建一个新文件和**OS**模块。OS 模块将让我们获取当前登录用户的用户名等信息。 

# 在文件系统模块中创建和追加文件

不过，首先我们将从文件系统模块开始。我们将逐步介绍如何创建文件并追加内容：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/5b1f68c0-b22d-4a77-b215-07276083f00c.png)

当你查看内置模块的文档页面时，无论是文件系统还是其他模块，你都会看到一个很长的列表，列出了你可以使用的所有不同函数和属性。在本节中，我们将使用的是`fs.appendFile`。

如果你点击它，它会带你到具体的文档页面，这是我们可以找出如何使用`appendFile`的地方，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/83a4ce04-2434-462b-a603-e6a46de862b6.png)

现在，`appendFile`非常简单。我们将向它传递两个字符串参数（如前面的截图所示）：

+   一个是文件名

+   另一个是我们想要追加到文件中的数据

这是我们调用`fs.appendFile`所需要提供的全部内容。在我们调用`fs.appendFile`之前，我们需要先引入它。引入的整个目的是让我们加载其他模块。在这种情况下，我们将从`app.js`中加载`fs`模块。

让我们创建一个变量，使用`const`来定义它。

由于我们不会操纵模块返回的代码，所以不需要使用`var`关键字；我们将使用`const`关键字。

然后我们会给它一个名字，`fs`，并将其设置为`require()`，如下面的代码所示：

```js
const fs = require()
```

在这里，`require()`是一个可以在任何 Node.js 文件中使用的函数。你不需要做任何特殊的事情来调用它，只需要像前面的代码中所示的那样调用它。在参数列表中，我们只需要传入一个字符串。

现在，每次调用`require()`时，无论是加载内置模块、第三方模块还是你自己的文件，你只需要传入一个字符串。

在我们的例子中，我们将传入模块名`fs`，并在末尾加上一个分号，如下面的代码所示：

```js
const fs = require('fs');
```

这将告诉 Node，你想要获取`fs`模块的所有内容，并将它们存储在`fs`变量中。此时，我们可以访问`fs`模块上的所有可用函数，包括`fs.appendFile`，我们在文档中探索过。

回到 Atom，我们可以通过调用 `fs.appendFile` 来调用 `appendFile`，传入我们将使用的两个参数；第一个将是文件名，所以我们添加 `greetings.txt`，第二个将是你想要追加到文件中的文本。在我们的例子中，我们将追加 `Hello world!`，如下面的代码所示：

```js
fs.appendFile('greetings.txt', 'Hello world!');
```

让我们保存文件，如上面的命令所示，并从终端运行它，看看会发生什么。

**在 Node v7 上运行程序时的警告** 如果你在 Node v7 或更高版本上运行，当你在终端内运行程序时会收到一个小警告。现在，在 v7 上，它仍然可以工作，只是一个警告，但你可以使用以下代码来摆脱它：

```js
// Orignal line 
fs.appendFile('greetings.txt', 'Hello world!');

// Option one
fs.appendFile('greetings.txt', 'Hello world!', function (err){
  if (err) { 
    console.log('Unable to write to file');
  }
});

// Option two
fs.appendFileSync('greetings.txt', 'Hello world!');
```

在上面的代码中，我们有我们程序中的原始行。

在这里的 `Option one` 是将回调添加为追加文件的第三个参数。当发生错误或文件成功写入时，此回调将被执行。在选项一中，我们有一个 `if` 语句；如果有错误，我们只是在屏幕上打印一条消息 `Unable to write to file`。

现在，在上面的代码中，我们的第二个选项 `Option two` 是调用 `appendFileSync`，这是一个同步方法（我们稍后会详细讨论）；这个函数不需要第三个参数。你可以像上面的代码中所示那样输入它，你就不会收到警告。

因此，如果你看到警告，选择其中一种选项，两者都可以工作得差不多。

如果你使用的是 v6，你可以坚持使用上面代码中的原始行，尽管你可能会使用下面这两个选项之一来使你的代码更具未来性。

不要担心，我们将在整本书中广泛讨论异步和同步函数，以及回调函数。我在代码中给你的只是一个模板，你可以在你的文件中写下来以消除错误。在几章中，你将准确理解这两种方法是什么，以及它们是如何工作的。

如果我们在终端中进行追加，`node app.js`，我们会看到一些很酷的东西：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/2ec51c4b-ece3-4ce3-bb59-73b569219a36.png)

如前面的代码所示，我们得到了我们的一个 `console.log` 语句，`Starting app.`。所以我们知道应用程序已经正确启动了。此外，如果我们转到 Atom，我们实际上会看到一个全新的 `greetings.txt` 文件，如下面的代码所示。这是由 `fs.appendFile` 创建的文本文件：

```js
console.log('Starting app.');

const fs = require('fs');

fs.appendFile('greetings.txt', 'Hello world!');
```

在这里，`fs.appendFile` 尝试将 `greetings.txt` 追加到一个文件中；如果文件不存在，它就会简单地创建它：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/91fe0afc-82be-45e7-8cf1-71ab8ac7e2c8.png)

你可以看到我们的消息 `Hello world!` 在 `greetings.txt` 文件中打印到屏幕上。在短短几分钟内，我们就能够加载一个内置的 Node 模块并调用一个函数，让我们创建一个全新的文件。

如果我们再次调用它，通过使用上箭头键和回车键重新运行命令，并回到 `greetings.txt` 的内容，你会看到这一次我们有两次 `Hello world!`，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/e87eb337-f0a8-4c89-b798-9b58b7a5739d.png)

它每次运行程序都会追加 `Hello world!` 一次。我们有一个应用程序，在我们的文件系统上创建一个全新的文件，如果文件已经存在，它就会简单地添加到它。

# 在 require()中的 OS 模块

一旦我们创建并追加了 `greetings.txt` 文件，我们将自定义这个 `greeting.txt` 文件。为了做到这一点，我们将探索另一个内置模块。我们将在未来使用不仅仅是 `appendFile`。我们将探索其他方法。对于本节，真正的目标是理解 `require()`。`require()` 函数让我们加载模块的功能，以便我们可以调用它。

我们将使用的第二个模块是 OS，我们可以在文档中查看它。在 OS 模块中，我们将使用在最底部定义的方法，os.userInfo([options])：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/4701cb5a-ce45-40d1-8cbe-10c9dcdff9b4.png)

os.userInfo([options])方法被调用并返回有关当前登录用户的各种信息，例如用户名，这就是我们要提取的信息：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/dfff1585-133a-45cb-b109-74c1c8c9b000.png)

使用来自操作系统的用户名，我们可以自定义`greeting.txt`文件，以便它可以说`Hello Gary!`而不是`Hello world!`。

要开始，我们必须要求 OS。这意味着我们将回到 Atom 内部。现在，在我创建`fs`常量的下面，我将创建一个名为`os`的新常量，将其设置为`require()`; 这作为一个函数调用，并传递一个参数，模块名称`os`，如下所示：

```js
console.log('Starting app.');

const fs = require('fs');
const os = require('os');

fs.appendFile('greetings.txt', 'Hello world!');
```

从这里开始，我们可以开始调用 OS 模块上可用的方法，例如 os.userInfo([optional])。

让我们创建一个名为`user`的新变量来存储结果。变量 user 将被设置为`os.userInfo`，我们可以调用`userInfo`而不带任何参数：

```js
console.log('Starting app.');

const fs = require('fs');
const os = require('os');

var user = os.userInfo();

fs.appendFile('greetings.txt', 'Hello world!');
```

现在，在我们对`fs.appendFile`行执行任何操作之前，我将对其进行注释，并使用`console.log`打印用户变量的内容：

```js
console.log('Starting app.');

const fs = require('fs');
const os = require('os');

var user = os.userInfo();
console.log(user);
// fs.appendFile('greetings.txt', 'Hello world!');
```

这将让我们准确地探究我们得到了什么。在终端中，我们可以使用上箭头键和回车键重新运行我们的程序，并且在下面的代码中，你可以看到我们有一个带有一些属性的对象：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/e8e6025d-09b3-4c9e-9e0d-5d65e2a43a74.png)

我们有`uid`，`gid`，`username`，`homedir`和`shell`。根据您的操作系统，您可能不会拥有所有这些，但您应该始终拥有`username`属性。这是我们关心的。

这意味着回到 Atom 内部，我们可以在`appendFile`中使用`user.username`。我将删除`console.log`语句并取消注释我们对`fs.appendFile`的调用：

```js
console.log('Starting app.');

const fs = require('fs');
const os = require('os');

var user = os.userInfo();

fs.appendFile('greetings.txt', 'Hello world!');
```

现在，在`fs.appendFile`中的`world`处，我们将其与`user.username`交换。我们可以以两种方式做到这一点。

# 连接用户.username

第一种方法是删除`world!`并连接`user.username`。然后我们可以使用`+`（加号）运算符连接另一个字符串，如下面的代码所示：

```js
console.log('Starting app.');

const fs = require('fs');
const os = require('os');

var user = os.userInfo();

fs.appendFile('greetings.txt', 'Hello' + user.username + '!');
```

现在，如果我们运行这个，一切都会按预期工作。在终端中，我们可以重新运行我们的应用程序。它会打印`Starting app`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/eeb699b5-0250-46f4-b4f4-45f16076b0c1.png)

在`greetings.txt`文件中，你应该看到类似`Hello Gary!`的东西打印到屏幕上，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/48ca995f-4076-461a-8e60-c817922f81d8.png)

使用`fs`模块和`os`模块，我们能够获取用户的用户名，创建一个新文件并存储它。

# 使用模板字符串

第二种方法是使用 ES6 功能模板字符串来交换`fs.appendFile`中的`world`与`user.username`。模板字符串以`` ` ``（对勾）运算符开头和结尾，位于键盘上*1*键的左侧。然后你像平常一样打字。

这意味着我们首先输入`hello`，然后我们会用`!`（感叹号）标记添加一个空格，在`!`之前，我们会放置名字：

```js
console.log('Starting app.');

const fs = require('fs');
const os = require('os');

var user = os.userInfo();

fs.appendFile('greetings.txt', `Hello !`);
```

要在模板字符串中插入 JavaScript 变量，你需要使用`$`（美元）符号，后面跟上大括号。然后我们将引用一个变量，比如`user.username`：

```js
console.log('Starting app.');

const fs = require('fs');
const os = require('os');

var user = os.userInfo();

fs.appendFile('greetings.txt', `Hello ${user.username}!`);
```

请注意，Atom 编辑器实际上可以识别出大括号的语法。

这就是使用模板字符串所需要的。它是一个 ES6 功能，因为你使用的是 Node v6。这种语法比我们先前看到的字符串/串联版本容易理解和更新。

如果你运行这段代码，它将产生完全相同的输出。我们可以运行它，查看文本文件，这一次我们有两次`Hello Gary!`，这正是我们想要的：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/3f725d56-9605-46bb-84cb-dd044a1308d7.png)

有了这个配置，我们现在已经完成了我们非常基础的示例，并准备在下一节中开始创建我们的笔记应用程序的文件并在`app.js`中要求它们。

首先，你已经学到了我们可以使用`require`来加载模块。这让我们可以使用 Node 开发者、第三方库或者自己编写的现有功能，并将其加载到文件中，以便可以重复使用。创建可重复使用的代码对于构建大型应用程序至关重要。如果每次都必须在应用程序中构建所有内容，那么没有人会有所作为，因为他们会被困在构建基础设施上，比如 HTTP 服务器和 Web 服务器等。这些东西已经有模块了，我们将利用 npm 社区的伟大作用。在这种情况下，我们使用了两个内置模块，`fs`和`os`。我们使用`require`将它们加载进来，并将模块结果存储在两个变量中。这些变量存储了模块中提供给我们的所有内容；在`fs`的情况下，我们使用`appendFile`方法，而在 OS 的情况下，我们使用`userInfo`方法。一起，我们能够获取用户名并将其保存到文件中，这太棒了。

# 要求自己的文件

在本节中，你将学习如何使用`require()`来加载项目中创建的其他文件。这将让你将函数从`app.js`移到更具体的文件中；这将使你的应用程序更容易扩展、测试和更新。要开始，我们要做的第一件事就是创建一个新文件。

# 创建一个新文件来加载其他文件

在我们的笔记应用程序的上下文中，新文件将存储各种用于编写和阅读笔记的函数。目前，你不需要担心该功能，因为我们稍后将详细介绍，但我们将创建文件，它最终将存放在那里。这个文件将是`notes.js`，我们将把它保存在应用程序的根目录下，就在`app.js`和`greetings.txt`旁边，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/37116f0e-f983-4ff1-a0b8-54ff1f419b0a.png)

目前，我们在`notes`中所做的就是使用`console.log`打印一小段日志，显示文件已经被执行，使用以下代码：

```js
console.log('Starting notes.js');
```

现在，我们在`notes`的顶部和`app.js`的顶部都有了`console.log`。我将把`app.js`中的`console.log`从`Starting app.`更改为`Starting app.js`。有了这个配置，我们现在可以 require notes 文件。它没有导出任何功能，但没关系。

顺便说一下，当我说导出时，我指的是 notes 文件没有任何其他文件可以利用的函数或属性。

我们将在后面的部分讨论如何导出东西。不过，目前我们将以与加载内置 Node 模块相同的方式加载我们的模块。

让我们创建`const`；我会将其命名为 notes，将其设置为从`require()`返回的结果：

```js
console.log('Starting app.js');

const fs = require('fs');
const os = require('os');
const notes = require('');

var user = os.userInfo();

fs.appendFile('greetings.txt', `Hello ${user.username}!`);
```

在括号内，我们将传入一个参数，这个参数将是一个字符串，但它会有一点不同。在之前的部分中，我们键入了模块名称，但在这种情况下，我们拥有的不是一个模块，而是一个文件，`notes.js`。我们需要做的是告诉 Node 文件的位置，使用相对路径。

现在，相对路径以`./`（点斜杠）开头，指向文件所在的当前目录。在这种情况下，这将指向我们的项目根目录`notes-node`的`app.js`目录。从这里开始，我们不必进入任何其他文件夹来访问`notes.js`，它就在我们项目的根目录中，所以我们可以输入它的名称，如下面的代码所示：

```js
console.log('Starting app.js');

const fs = require('fs');
const os = require('os');
const notes = require('./notes.js');

var user = os.userInfo();

fs.appendFile('greetings.txt', `Hello ${user.username}!`);
```

有了这个配置，当我们保存`app.js`并运行我们的应用程序时，我们就可以看到发生了什么。我将使用`node app.js`命令运行应用程序：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/037c3e53-2739-4a42-ae40-953bee14a3ca.png)

如前面的代码输出所示，我们得到了两个日志。首先，我们得到了`Starting app.js`，然后我们得到了`Starting notes.js`。现在，`Starting notes.js`来自于`note.js`文件，并且它只能执行，因为我们在`app.js`内部需要了这个文件。

从`app.js`文件中注释掉这条命令行，如下所示：

```js
console.log('Starting app.js');

const fs = require('fs');
const os = require('os');
// const notes = require('./notes.js');

var user = os.userInfo();

fs.appendFile('greetings.txt', `Hello ${user.username}!`);
```

保存文件，并从终端重新运行它；您可以看到`notes.js`文件从未被执行，因为我们从未明确地触摸它。

我们从来没有像前面的示例那样在终端中调用它，并且我们也从未 require 过。

目前，我们将需要 require 它，所以我将取消注释。

顺便说一下，我使用命令/（斜线）来快速注释和取消注释行。这是大多数文本编辑器中可用的键盘快捷键；如果您使用的是 Windows 或 Linux，它可能不是*command*，可能是*Ctrl*或其他内容。

# 从 notes.js 中导出文件以在 app.js 中使用

现在，焦点将是从`notes.js`中导出东西，我们可以在`app.js`中使用。在`notes.js`内部（实际上，在我们所有的 Node 文件中），我们可以访问一个名为`module`的变量。我会用`console.log`来将`module`打印到屏幕上，这样我们就可以在终端中探索它，如下所示：

```js
console.log('Starting notes.js');

console.log(module);
```

让我们重新运行文件来探索它。如下截图所示，我们得到了一个相当大的对象，即与`notes.js`文件相关的不同属性：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/a98531ef-4b8b-4456-99b1-5c2e44de387a.png)

现在，说实话，我们将不会使用大部分这些属性。我们有诸如`id`、`exports`、`parent`和`filename`之类的东西。在本书中，我们唯一会使用的属性是`exports`。

`exports`对象位于`module`属性上，该对象上的一切都会被导出。此对象会被设置为`const`变量`notes`。这意味着我们可以在其上设置属性，它们将被设置在 notes 上，并且我们可以在`app.js`内部使用它们。

# exports 对象工作的一个简单示例

让我们快速看看它是如何工作的。我们将定义一个`age`属性使用`module.exports`，刚刚在终端中探索过的对象。我们知道这是一个对象，因为我们在之前的截图中可以看到（`exports: {}`）；这意味着我可以添加一个属性`age`，并将其设置为我的年龄`25`，如下所示：

```js
console.log('Starting notes.js');

module.exports.age = 25;
```

然后我可以保存这个文件并移动到`app.js`利用这个新的`age`属性。在当前情况下，`const`变量 notes 将存储我所有的输出，现在只有 age。

在`fs.appendFile`中，`greeting.txt`文件后面，我将添加`You are`，然后是年龄。在模板字符串内，我们将使用`$`和花括号，`notes.age`，以及末尾的句号，如下所示：

```js
console.log('Starting app.js');

const fs = require('fs');
const os = require('os');
const notes = require('./notes.js');

var user = os.userInfo();

fs.appendFile('greetings.txt', `Hello ${user.username}! You are ${notes.age}.`);
```

现在我们的问候应该是`Hello Gary! You are 25`。它得到了我们单独文件（即`note.js`）中的`25`值，这太棒了。

让我们花点时间使用上箭头键和回车键在终端重新运行程序：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/093236f1-6c23-40e7-8649-618d90932157.png)

回到应用程序内部，我们可以打开`greetings.txt`，如下截图所示，我们有`Hello Gary! You are 25`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/087ca523-8167-4c0d-8ae4-0617bed2c9a0.png)

使用`require()`，我们能够引入一个我们创建的文件，这个文件存储了对项目其他部分有利的一些属性。

# 导出函数

很明显，上面的例子是相当刻意的。我们不会导出静态数字；导出的真正目的是能够导出在`app.js`内部使用的函数。让我们花点时间导出两个函数。在`notes.js`文件中，我将设置`module.exports.addnote`等于一个函数；`function`关键字后跟随圆括号，然后是花括号：

```js
console.log('Starting notes.js');

module.exports.addNote = function () {

} 
```

现在，在整个课程中，我将尽可能使用箭头函数，如前面的代码所示。要将常规的 ES5 函数转换为箭头函数，你只需删除`function`关键字，然后在括号和开放花括号之间用`=>`符号替换，如下所示：

```js
console.log('Starting notes.js');

module.exports.addNote = () => {

} 
```

现在，箭头函数还有一些更微妙的地方需要在整本书中讨论，但如果你有一个匿名函数，你可以毫不费力地用箭头函数代替。主要区别在于箭头函数不会绑定`() => {}`关键字或参数数组，这是我们将在整本书中探讨的。所以如果你遇到一些错误，知道箭头函数可能是引起错误的原因是很好的。

不过目前，我们将保持事情非常简单，使用`console.log`来打印`addNote`。这将让我们知道`addNote`函数已被调用。我们将返回一个字符串，`'New note'`，如下所示：

```js
console.log('Starting notes.js');

module.exports.addNote = () => {
  console.log('addNote');
  return 'New note';
};
```

现在，`addNote`函数在`notes.js`中被定义了，但我们可以在`app.js`中利用它。

让我们快速地注释掉`app.js`中的`appendFile`和用户行：

```js
console.log('Starting app.js');

const fs = require('fs');
const os = require('os');
const notes = require('./notes.js');

// var user = os.userInfo();
//
// fs.appendFile('greetings.txt', `Hello ${user.username}! You are ${notes.age}.`);
```

我将添加一个变量，称为结果，（简称`res`），并将其设置为`notes.addNote`的返回结果：

```js
console.log('Starting app.js');

const fs = require('fs');
const os = require('os');
const notes = require('./notes.js');

var res = notes.addNote();

// var user = os.userInfo();
//
// fs.appendFile('greetings.txt', `Hello ${user.username}! You are ${notes.age}.`);
```

现在，`addNote`函数目前只是一个虚拟函数。它不需要任何参数，也实际上什么也不做，所以我们可以无需任何参数地调用它。

然后我们将打印结果变量，如下面的代码所示，我们期望结果变量等于字符串`New note`：

```js
console.log('Starting app.js');

const fs = require('fs');
const os = require('os');
const notes = require('./notes.js');

var res = notes.addNote();
console.log(res);

// var user = os.userInfo();
//
// fs.appendFile('greetings.txt', `Hello ${user.username}! You are ${notes.age}.`);
```

如果我保存我的两个文件（`app.js`和`notes.js`），然后在终端重新运行，你会看到`New note`打印到屏幕最后并在`addNote`之前打印：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/effc1e66-5430-4eda-a5b0-9c0496ffcaa5.png)

这意味着我们成功地引入了我们称为`addNote`的笔记文件，并且它的返回结果成功地返回给了`app.js`。

使用这个确切的模式，我们将能够在我们的`notes.js`文件中定义添加和删除笔记的函数，但我们将能够在我们的应用程序内的任何地方调用它们，包括在`app.js`中。

# 练习 - 在导出对象中添加一个新函数

现在是时候进行一个快速的挑战了。我想让你在`notes.js`中创建一个名为`add`的新函数。这个`add`函数将被设置在`exports`对象上。

记住，`exports`是一个对象，所以你可以设置多个属性。

这个`add`函数将接受两个参数`a`和`b`；它会将它们相加并返回结果。然后在`app.js`中，我想让你调用`add`函数，传入两个你喜欢的数字，比如`9`和`-2`，然后将结果打印到屏幕上并确保它正常工作。

你可以开始移除对`addNote`的调用，因为在这个挑战中将不再需要它。

所以，请花一点时间，在`notes.js`内创建`add`函数，在`app.js`内调用它，并确保正确的结果打印到屏幕上。进行得如何？希望你能够创建该函数并从`app.js`中调用它。

# 练习的解决方案

过程中的第一步是定义新函数。在`notes.js`中，我将`module.exports.add`设置为该函数，如下所示：

```js
console.log('Starting notes.js');

module.exports.addNote = () => {
  console.log('addNote');
  return 'New note';
}; 

module.exports.add =
```

让我们将其等于箭头函数。如果你使用普通函数，那完全没问题，我只是更喜欢在我可以的时候使用箭头函数。此外，在括号内，我们将会有两个参数，我们将得到`a`和`b`，就像这里展示的一样：

```js
console.log('Starting notes.js');

module.exports.addNote = () => {
  console.log('addNote');
  return 'New note';
}; 

module.exports.add = (a, b) => {

};
```

我们需要做的只是返回结果，这非常简单。所以我们将输入`return a + b`：

```js
console.log('Starting notes.js');

module.exports.addNote = () => {
  console.log('addNote');
  return 'New note';
}; 

module.exports.add = (a, b) => {
  return a + b;
};
```

现在，这是你的挑战的第一部分，在`notes.js`中定义一个实用函数；第二部分是实际在`app.js`中使用它。

在`app.js`中，我们可以通过打印带有冒号`:`的`console.log`结果来使用我们的函数（这只是为了格式化）。作为第二个参数，我们将打印实际结果，`notes.add`。然后，我们将两个数字相加；我们将加上`9`和`-2`，就像这段代码展示的那样：

```js
console.log('Starting app.js');

const fs = require('fs');
const os = require('os');
const notes = require('./notes.js');

console.log('Result:', notes.add(9, -2));

// var user = os.userInfo();
//
// fs.appendFile('greetings.txt', `Hello ${user.username}! You are ${notes.age}.`);
```

在这种情况下，结果应该是`7`。如果我们运行程序，你可以看到，我们得到了`7`，它打印到屏幕上：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/2d99dcfd-a8d3-4bee-9ed0-3cb9376d14e6.png)

如果你能理解这个，恭喜你，你成功完成了你的第一个挑战。这些挑战将分布在整本书中，并且会变得越来越复杂。但不要担心，我们会将挑战描述得很明确；我会告诉你我想要什么，以及我想要它如何完成。现在，你可以尝试不同的方法去做，真正的目标是让你能够独立编写代码，而不是跟随他人的步伐。这才是真正的学习过程。

在下一节中，我们将探讨如何使用第三方模块。从那里开始，我们将开始构建笔记应用程序。

# 第三方模块

你现在已经知道了使用`require()`的三种方式中的两种，在本节中，我们将探索最后一种方式，即要求你从 npm 安装的软件包中获取。正如我在第一章中提到的，npm 是 Node 变得如此奇妙的重要部分。有一个庞大的开发者社区已经创建了成千上万的软件包，已经解决了 Node 应用程序中一些最常见的问题。我们将在整本书中利用相当多的软件包。

# 使用 npm 模块创建项目

现在，在 npm 软件包中，没有什么神奇的，这是普通的 Node 代码，旨在解决特定的问题。你想要使用它的原因是，这样你就不必花费所有时间编写这些已经存在的实用函数；它们不仅存在，而且已经经过测试，已经被证明有效，而且其他人已经使用它们并记录了它们。

现在，这么多话说了，我们应该如何开始呢？好吧，要开始，我们实际上必须从终端运行一个命令，告诉我们的应用程序我们想要使用 npm 模块。这个命令将在终端上运行。确保你已经进入了你的项目文件夹，并且在`notes-node`目录中。当你安装了 Node 时，你也安装了一个叫做 npm 的东西。

有一段时间，npm 代表**Node 包管理器**，但那现在是一个笑话，因为有很多东西在 npm 上并不特定于 Node。许多前端框架，如 jQuery 和 react，现在也存在于 npm 上，所以他们几乎抛弃了 Node 包管理器的解释，在他们的网站上，现在他们循环播放一堆与 npm 相匹配的滑稽事情。

我们将运行一些 npm 命令，你可以通过运行`npm`，一个空格，和`-v`（我们正在用`v`标志运行 npm）。这将打印版本，如下面的代码所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/2fbd827c-06bf-47f8-b0cd-c92078d62e5d.png)

如果你的版本略有不同，也没有关系；重要的是你已经安装了 npm。

现在，我们将在终端中运行一个名为`npm init`的命令。这个命令将提示我们回答关于我们的 npm 项目的一些问题。我们可以运行这个命令，并且可以按照下面的截图循环回答问题：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/fa3bdede-390d-4877-b36f-fab82a4d2bbb.png)

在上述截图中，顶部是正在发生的事情的快速描述，下面将开始提出一些问题，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/8d36696c-4caf-408a-b352-db86a16cf7e7.png)

这些问题包括以下内容：

+   名称：你的名称不能包含大写字符或空格；你可以使用`notes-node`，例如。你可以按“回车”使用默认值，括号中就是默认值。

+   版本：1.0.0 也可以正常工作；我们将大多数设置保留在默认值。

+   描述：我们暂时可以将其保留为空。

+   入口点：这将是`app.js`，确保它正确显示。

+   测试命令：我们将在本书的后面探索测试，所以现在可以将其保留为空。

+   git 仓库：我们现在也将其保留为空。

+   关键词：这些用于搜索模块。我们不会发布这个模块，所以可以将其保留为空。

+   作者：你可能会输入你的名字。

+   许可证：对于许可证，我们暂时将使用 ISC；因为我们不打算发布它，所以这并不重要。

回答了这些问题后，如果我们按“回车”，我们将在屏幕上看到以下内容和一个最终问题：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/e71f1d89-0400-4a57-8405-8cbfceead0f6.png)

现在，我想驱散这个命令有任何神奇的谣言。这个命令所做的就是在你的项目内创建一个单个文件。它将位于项目的根目录，并且被称为`package.json`，该文件将与上述截图完全一样。

对于最后一个问题，如上面截图下面所示，你可以按“回车”或者输入`yes`来确认这是你想要做的事情：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/9be2c9e8-b3f9-4a8b-a116-058652e2f3e7.jpg)

现在我们已经创建了文件，我们可以实际在项目内查看它。如下面的代码所示，我们有`package.json`文件：

```js
{
  "name": "notes-node",
  "version": "1.0.0",
  "description": "",
  "main": "app.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "",
  "license": "ISC"
}
```

并且这就是它，这是对你的应用程序的简单描述。就像我提到的，我们不打算将我们的应用程序发布到 npm 上，所以很多这些信息对我们来说并不重要。然而，重要的是，`package.json`是我们定义要在应用程序中安装的第三方模块的地方。

# 在我们的应用程序中安装 lodash 模块

要在应用程序中安装模块，我们将在终端中运行一个命令。在本章中，我们将安装一个名为`lodash`的模块。`lodash`模块附带了大量的实用方法和函数，使得在 Node 或 JavaScript 中开发变得更加容易。让我们看看我们到底要接触到什么，让我们进入浏览器。

我们将前往[`www.npmjs.com`](https://www.npmjs.com)。然后我们将搜索`lodash`包，你会看到它出现在下面的截图中：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/76628499-5b5d-48cd-af2b-adbb78842b1a.png)

当你点击它时，你应该会进入到包页面，包页面将向你展示有关该模块的很多统计信息和文档，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/3d77137e-bdad-4eb0-a259-d73aedbdbe5f.png)

现在，我在寻找新模块时使用`lodash`包页面；我喜欢看看它有多少下载量以及上次更新是什么时候。在包页面上，你可以看到它最近更新过，这很棒，这意味着该包很可能与 Node 的最新版本兼容，如果你向页面下方看，你会看到这实际上是一个最受欢迎的 npm 包之一，每天有超过一百万次的下载。我们将使用这个模块来探索如何安装 npm 模块以及如何在项目中实际使用它们。

# 安装 lodash

要安装`lodash`，你需要的第一件事就是获取一个模块名，就是`lodash`。一旦你有了这个信息，你就可以开始安装了。

进入终端，我们将运行`npm install`命令。在安装后，我们将指定模块`lodash`。单独运行这个命令也可以；但我们还会提供`save`标志。

`npm install lodash`命令将安装该模块，`save`标志，即`--`（两个）破折号后跟单词`save`，将更新`package.json`文件的内容。让我们运行这个命令：

```js
npm install loadsh --save
```

上述命令将前往 npm 服务器并获取代码，然后将其安装到你的项目中，每当你安装一个 npm 模块时，它都将存放在`node_modules`文件夹中。

现在，如果你打开`node_modules`文件夹，你会看到下面的代码所示的`lodash`文件夹。这就是我们刚刚安装的模块：

```js
{
  "name": "notes-node",
  "version": "1.0.0",
  "description": "",
  "main": "app.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "",
  "license": "ISC",
  "dependencies": {
    "lodash": "^4.17.4"
  }
}
```

就像您在上图的`package.json`中所看到的那样，我们还进行了一些自动更新。有一个新的`dependencies`属性，其中有一个键值对对象，其中键是我们想在项目中使用的模块，值是版本号，本例中是最新版本，版本`4.17.4`。有了这个，我们现在可以在项目中引入我们的模块了。

在`app.js`内部，我们可以通过相同的要求过程利用`lodash`中的所有内容。我们将创建一个`const`，我们将把这个`const`命名为`_`（这是`lodash`实用程序库的常见名称），并将其设置为`require()`。在 require 括号内，我们将传入与`package.json`文件中完全相同的模块名称。这是您在运行`npm install`时所使用的相同模块名称。然后，我们会输入`lodash`，如下所示：

```js
console.log('Starting app.js');

const fs = require('fs');
const os = require('os');
const _ = require('lodash');
const notes = require('./notes.js');

console.log('Result:', notes.add(9, -2));

// var user = os.userInfo();
//
// fs.appendFile('greetings.txt', `Hello ${user.username}! You are ${notes.age}.`);
```

现在，操作的顺序非常重要。Node 首先会查找`lodash`的核心模块。它找不到核心模块，所以下一个地方它会查找是`node_modules`文件夹。如下代码所示，它会找到`lodash`并加载该模块，返回任何它提供的输出：

```js
console.log('Starting app.js');

const fs = require('fs');
const os = require('os');
const _ = require('lodash');
const notes = require('./notes.js');

console.log('Result:', notes.add(9, -2));

// var user = os.userInfo();
//
// fs.appendFile('greetings.txt', `Hello ${user.username}! You are ${notes.age}.`);
```

# 使用 Lodash 的实用工具

现在，有了输出，我们可以利用 Lodash 带来的一些实用工具。我们将在本节快速探讨其中的两个，并且在整本书中将更多地探索，因为 Lodash 基本上就是一组非常实用的工具。在我们开始之前，我们应该先看一下文档，这样我们才知道我们要做什么。

当您使用 npm 模块时，这是一个非常常见的步骤：首先安装它；第二，你必须查看那些文档，并确保你能做你想做的事情。

在 npm 页面上，点击那里给出的 lodash 链接，或者前往[lodash.com](https://lodash.com)，点击 API 文档页面，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/7e1fe429-f974-4343-b6d8-c522192df5d9.png)

您可以查看您可用的各种方法，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/1396d946-2797-48fe-ba6a-877176597a7f.png)

在我们的情况下，我们将使用*command* + *F*（Windows 用户为*Ctrl* + *F*）来搜索`_.isString`。然后在文档中，我们可以点击它，将其在主页面打开，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/cb9b613b-b3cf-438e-94c1-2e3cef5ad7af.png)

`_.isString`是与 `lodash` 一起的一个实用工具，如果您传入的变量是字符串，它将返回`true`，如果您传入的值不是字符串，它将返回`false`。我们可以在 Atom 中使用它来验证。让我们来试一试。

# 使用 _.isString 实用工具

要使用`_.isString`实用程序，我们将在`app.js`中添加`console.log`以显示结果并且我们将使用`_.isString`，传入一些值。首先让我们传入`true`，然后我们可以复制这行，并传入一个字符串，比如`Gary`，如下所示：

```js
console.log('Starting app.js');

const fs = require('fs');
const os = require('os');
const _ = require('lodash');
const notes = require('./notes.js');

console.log(_.isString(true));
console.log(_.isString('Gary'));

// console.log('Result:', notes.add(9, -2));

// var user = os.userInfo();
//
// fs.appendFile('greetings.txt', `Hello ${user.username}! You are ${notes.age}.`);
```

我们可以在终端中使用先前使用的相同命令`node app.js`来运行我们的文件：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/9561c991-5646-4e82-a72e-3ccbb9a76eb6.png)

当我们运行文件时，我们会得到两个提示，一个是我们已经开始了两个文件，一个是`false`，然后是`true`。 `false` 是因为布尔值不是字符串，`true` 是因为 `Gary` 确实是一个字符串，所以它通过了`_.isString`的测试。这是`lodash`捆绑的许多实用函数中的一个。

现在，`lodash`可以做的远不止简单的类型检查。它附带了一堆其他我们可以利用的实用方法。让我们探索另一个实用程序。

# 使用 _.uniq

回到浏览器中，我们可以再次使用`command + F`来搜索一个新的实用程序，即`_.uniq`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/d4ce4612-1d7d-40cb-8d7e-67113d61f06b.png)

这个唯一的方法，简单地获取一个数组，并返回删除所有重复项的数组。这意味着如果我有好几次相同的数字或相同的字符串，它将删除任何重复内容。让我们运行一下。

回到 Atom 中，我们可以将这个实用工具添加到我们的项目中，我们将注释掉`_.isString`的调用，并且我们将创建一个名为`filteredArray`的变量。这将是没有重复项的数组，我们将调用`_.uniq`。

现在，正如我们所知，这需要一个数组。由于我们正在尝试使用唯一功能，我们将传入一个具有一些重复项的数组。将你的名字作为字符串用两次；我将使用一次我的名字，然后跟着数字`1`，然后再用一次我的名字。然后我可以使用`1`，`2`，`3`和`4`，如下所示：

```js
console.log('Starting app.js');

const fs = require('fs');
const os = require('os');
const _ = require('lodash');
const notes = require('./notes.js');

// console.log(_.isString(true));
// console.log(_.isString('Gary'));
var filteredArray = _.uniq(['Gary', 1, 'Gary', 1, 2, 3, 4]);
console.log();

// console.log('Result:', notes.add(9, -2));

// var user = os.userInfo();
//
// fs.appendFile('greetings.txt', `Hello ${user.username}! You are ${notes.age}.`);
```

现在，如果一切按计划进行，我们应该得到一个删除了所有重复项的数组，这意味着我们将有一个`Gary`的实例，一个`1`的实例，然后没有重复的`2`，`3`和`4`。

最后要做的事情是用`console.log`打印出来，这样我们就可以在终端中查看了。我将把这个`filteredArray`变量传递给我们的`console.log`语句，如下面的代码所示：

```js
console.log('Starting app.js');

const fs = require('fs');
const os = require('os');
const _ = require('lodash');
const notes = require('./notes.js');

// console.log(_.isString(true));
// console.log(_.isString('Gary'));
var filteredArray = _.uniq(['Gary', 1, 'Gary', 1, 2, 3, 4]);
console.log(filteredArray);

// console.log('Result:', notes.add(9, -2));

// var user = os.userInfo();
//
// fs.appendFile('greetings.txt', `Hello ${user.username}! You are ${notes.age}.`);
```

从这里，我们可以在 Node 中运行我们的项目。我将使用上次的命令，然后我可以按下回车键，你会看到我们得到了一个删除了所有重复项的数组，如下代码输出所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/36269bde-30dd-40e0-83e2-54aeaaba939a.png)

我们有一个字符串`Gary`的实例，一个数字`1`的实例，然后有`2`，`3`，`4`，正是我们所期望的。

`lodash`工具确实是无穷无尽的。有很多函数，一开始探索起来可能有点压倒，但当你开始创建更多的 JavaScript 和 Node 项目时，你会发现自己在排序、过滤或类型检查方面一遍又一遍地解决许多相同的问题，在这种情况下，最好使用`lodash`这样的工具来完成这一工作。`lodash`工具之所以如此优秀，有以下几个原因：

+   你不必不断地重写你的方法

+   经过充分测试，已在生产环境中使用过

如果有任何问题，现在已经解决了。

# `node_modules`文件夹

现在你知道如何使用第三方模块了，我还想讨论一件事。那就是`node_modules`文件夹的一般情况。当你将你的 Node 项目放在 GitHub 上，或者你在拷贝它或发送给朋友时，`node_modules`文件夹实际上不应该跟着一起走。

`node_modules`文件夹包含生成的代码。这不是你编写的代码，你不应该对 Node 模块内部的文件进行任何更新，因为很有可能下次安装一些模块时它们会被覆盖。

在我们的情况下，我们已经在`package.json`文件中定义了模块和版本，如下面的代码所示，因为我们使用了方便的`save`标志：

```js
{
  "name": "notes-node",
  "version": "1.0.0",
  "description": "",
  "main": "app.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "",
  "license": "ISC",
  "dependencies": {
    "lodash": "^4.17.4"
  }
}
```

这实际上意味着我们可以彻底删除`node_modules`文件夹。现在，我们可以拷贝这个文件夹并给朋友，可以放在 GitHub 上，或者任何我们想做的事情。当我们想要恢复`node_modules`文件夹时，我们只需在终端内运行`npm install`命令，而不带任何模块名或任何标志。

当不带任何名称或标志运行此命令时，它将加载你的`package.json`文件，抓取所有的依赖项并安装它们。运行完这个命令后，`node_modules`文件夹将看起来和我们删除它之前一模一样。现在，当你使用 Git 和 GitHub 时，你只需忽略`node_modules`文件夹，而不是删除它。

现在，到目前为止我们所探索的内容是我们将在整本书中经常进行的过程。因此，如果 npm 看起来还很陌生，或者你不太确定它到底有什么用，当我们与第三方模块做更多事情时，它将变得清晰明了，而不仅仅是进行类型检查或在数组中查找唯一的项目。npm 社区背后有着巨大的力量，我们将充分利用这一点，以便我们创建真实世界的应用。

# 全局模块

我得到的一个主要的抱怨是学生们每次想要在文本编辑器内看到他们刚刚做出的更改时，都必须从终端重新启动应用。因此，在这一部分，我们将学习如何在文件更改时自动重新启动应用程序。这意味着，如果我从`Gary`更改为`Mike`并保存，它将在终端上自动重新启动。

# 安装 nodemon 模块

现在，为了在我们对文件进行更改时自动重新启动我们的应用程序，我们必须安装一个命令行实用程序，并且我们将使用 npm 来完成这个步骤。要开始，请打开 Google Chrome（或您使用的浏览器）并转到[`www.npmjs.com`](https://www.npmjs.com)，就像我们在*I*nstalling the* *lodash* *module in our app*部分以及我们正在寻找的模块之前所做的一样，这个模块叫做**nodemon**。

nodemon 将负责监视我们应用程序的更改，并在这些更改发生时重新启动应用程序。正如我们在下面截图中所见，我们还可以查看`nodemon`的文档，以及其他各种内容，比如当前版本号等：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/a70450e3-59e6-400c-9696-682c4daebf72.png)

您还将注意到它是一个非常受欢迎的模块，每天有超过 30,000 次下载。现在，这个模块与我们上一节使用的`lodash`有些不同。`lodash`会被安装并添加到我们项目的`package.json`文件中，如下所示： 

```js
{
 "name": "notes-node",
 "version": "1.0.0",
 "description": "",
 "main": "app.js",
 "scripts": {
 "test": "echo \"Error: no test specified\" && exit 1"
 },
 "author": "",
 "license": "ISC",
 "dependencies": {
 "lodash": "^4.17.4"
 }
}
```

这意味着它进入我们的`node_modules`文件夹，我们可以在我们的`app.js`文件中引用它（更多细节请参考前面的部分）。但是，Nodemon 的工作方式有些不同。这是一个从终端执行的命令行实用程序。这将是启动我们应用程序的一个全新方式，并且要安装模块以在命令行中运行，我们必须调整上一节中使用的`install`命令。

现在，我们可以以类似的方式开始，但是稍微不同。我们将使用`npm install`并输入名字，就像我们在*Installing the* *lodash* *module in our app*部分所做的那样，但是我们将使用`g`标志而不是使用`save`标志，`g`标志代表全局，如下所示：

```js
npm install nodemon -g
```

该命令会在您的机器上将`nodemon`安装为全局实用程序，这意味着它不会添加到您具体的项目中，你也不会需要`nodemon`。相反，你将在终端中运行`nodemon`命令，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/55de7da7-2315-4ef3-90fa-9d1258a72b46.png)

当我们使用前面的命令安装`nodemon`时，它将去 npm 中获取与`nodemon`一起的所有代码。

它会将其添加到 Node 和 npm 位于您机器上的安装位置，而不是添加到您正在工作的项目之外。

`npm install nodemon -g`命令可以在您机器上的任何地方执行；它不需要在项目文件夹中执行，因为它实际上并不更新项目。不过，这样一来，我们现在在我们的机器上有了一个全新的命令，`nodemon`。

# 执行 nodemon

Nodemon 将像 Node 一样执行，我们键入命令，然后键入我们要启动的文件。在我们的案例中，`app.js`是我们项目的根。运行时，您将会看到一些东西，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/3b8e4ff2-fdf4-40f5-9937-ef2c3f108cc8.png)

我们将看到我们应用程序的输出，以及显示发生了什么的`nodemon`日志。如前面的代码所示，您可以看到`nodemon`正在使用的版本，它监视的文件以及它实际运行的命令。此时，已经等待进行更多更改；它已经运行完整个应用程序，并将继续运行，直到发生另一个更改或直到您关闭它。

在 Atom 中，我们将对我们的应用程序进行一些更改。让我们开始通过在`app.js`中将`Gary`更改为`Mike`，然后将`filteredArray`变量更改为`var filteredArray = _.uniq(['Mike'])`，如下所示的代码：

```js
console.log('Starting app.js');

const fs = require('fs');
const os = require('os');
const _ = require('lodash');
const notes = require('./notes.js');

// console.log(_.isString(true));
// console.log(_.isString('Gary'));
var filteredArray = _.uniq(['Mike']);
console.log(filteredArray);
```

现在，我将保存文件。在终端窗口中，您可以看到应用程序已自动重新启动，并且在瞬间屏幕上显示了新的输出：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/278c0e02-c056-47a8-9076-9c52309dd3fb.png)

如前面的截图所示，我们现在有一个包含一个字符串`Mike`的数组。这就是`nodemon`的真正威力。

您可以创建您的应用程序，并它们将在终端中自动重启，这非常有用。这将节省您大量时间和许多头痛。每次进行小修改时，您都不必来回切换。这还可以防止很多错误，比如当您正在运行 Web 服务器时，您进行了更改，但忘记重新启动 Web 服务器。您可能认为您的更改与预期不同，因为应用程序不按预期工作，但实际上，您只是从未重新启动应用程序。

在大部分情况下，我们将在整本书中使用`nodemon`，因为它非常有用。它仅用于开发目的，这正是我们在本地机器上正在进行的操作。现在，我们将继续并开始探索如何从用户那里获取输入来创建我们的笔记应用程序。这将是接下来几节的主题。

在开始之前，我们应该清理本节中已经编写的大部分代码。我将删除`app.js`中所有被注释掉的代码。然后，我将简单地删除`os`，因为在整个项目中我们将不再使用它，而我们已经有了`fs`、`os`和`lodash`。我还将在第三方和 Node 模块与我编写的文件之间添加一个空格，这些文件如下：

```js
console.log('Starting app.js');

const fs = require('fs');
const _ = require('lodash');

const notes = require('./notes.js');
```

我发现这是一个很好的语法，让人很容易快速浏览第三方模块或 Node 模块，或者我创建和需要的模块。

接下来，在`notes.js`中，我们将移除`add`函数；这仅用于示范目的，如下图所示。然后我们可以保存`notes.js`和`app.js`文件，`nodemon`将自动重新启动：

```js
console.log('Starting notes.js');

module.exports.addNote = () => {
  console.log('addNote');
  return 'New note';
};

module.exports.add = (a, b) => {
  return a + b;
};
```

现在我们可以删除`greetings.txt`文件。这是用来演示`fs`模块如何工作的，既然我们已经知道它是如何工作的，我们可以删除那个文件。最后但并非最不重要的，我们总是可以使用 C*trl* + *C*关闭`nodemon`。现在我们回到了常规的终端。

有了这个，现在我们应该继续，弄清楚如何从用户那里获取输入，因为这是用户可以创建笔记、删除笔记和获取他们的笔记的方式。

# 获取输入

如果用户想要添加一条笔记，我们需要知道笔记的标题以及笔记的内容。如果他们想要获取一条笔记，我们需要知道他们想要获取的笔记的标题，所有这些信息都需要输入我们的应用程序。而且笔记应用程序在获取动态用户输入之前不会有什么特别之处。这就是使您的脚本变得有用和令人敬畏的原因。

现在，在本书中，我们将创建多种不同方式从用户那里获取输入的笔记应用程序。我们将使用套接字 I/O 从网络应用程序中实时获取信息，我们将创建我们自己的 API，以便其他网站和服务器可以向我们的应用程序发出 Ajax 请求，但在本节中，我们将以一个非常基本的示例开始解释如何获取用户输入。

我们将在命令行内从用户那里获取输入。这意味着当您在命令行中运行应用程序时，您将能够传入一些参数。这些参数将在 Node 内部可用，然后我们可以对它们进行其他操作，例如创建一个笔记、删除一个笔记或返回一个笔记。

# 在命令行内获取用户输入

要开始，让我们从终端运行我们的应用程序。我们将类似于我们在较早的章节中运行它的方式运行它：我们将以`node`开头（我不使用`nodemon`，因为我们将更改输入），然后我们将使用`app.js`，这是我们想要运行的文件，但是我们仍然可以输入其他变量。

我们可以传递各种命令行参数。我们可以有一个命令，这将告诉应用程序要做什么，无论您想要添加一个笔记，删除一个笔记，还是列出一个笔记。

如果我们想要添加一条笔记，可能看起来像下面的命令：

```js
node app.js add
```

这条命令会添加一条笔记；我们可以使用`remove`命令来移除一条笔记，如下所示：

```js
node app.js remove
```

我们可以使用`list`命令列出所有的笔记：

```js
node app.js list
```

现在，当我们运行这条命令时，应用程序仍然会按预期工作。只是因为我们传入了一个新的参数，并不意味着我们的应用程序会崩溃：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/de190e41-6194-4b7e-ae63-0b7adc259456.png)

实际上，我们已经可以访问`list`参数了，只是我们没有在应用程序中使用它。

要访问应用程序初始化时使用的命令行参数，您需要使用我们在第一章中探讨过的`process`对象。

我们可以使用`console.log`将所有的参数打印到屏幕上以输出它们；它在进程对象上，我们要寻找的属性是`argv`。

`argv`对象简称为参数向量，或者在 JavaScript 的情况下更像是参数数组。这将是传入的所有命令行参数的数组，我们可以使用它们开始创建我们的应用程序。

现在保存`app.js`文件，它将如下所示：

```js
console.log('Starting app.js');

const fs = require('fs');
const _ = require('lodash');

const notes = require('./notes.js');

console.log(process.argv);
```

然后我们将重新运行这个文件：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/d3077eb1-454a-4b2e-ab74-c7c0c8324ce5.png)

现在，正如前面的命令输出所示，我们有以下三个条目：

+   第一个指向所使用的 Node 的可执行文件。

+   第二个指向启动的应用程序文件；在这种情况下，它是`app.js`。

+   第三个就是我们的命令行参数开始发挥作用的地方。在其中，我们有我们的`list`显示为字符串。

这意味着我们可以访问数组中的第三个项目，那将是我们笔记应用程序的命令。

# 访问笔记应用程序的命令行参数

现在，让我们来访问数组中的命令行参数。我们将创建一个名为`command`的变量，并将其设置为`process.argv`，然后我们将获取第三个位置上的项目（就像前面的命令输出中所示的`list`一样），这在这里显示为了 2：

```js
var command = process.argv[2];
```

然后我们可以通过记录`command`字符串来将其输出到屏幕上。然后，作为第二个参数，我将传入实际使用的命令：

```js
console.log('Command: ' , command);
```

这只是一个简单的日志，用于跟踪应用程序的执行情况。酷的东西将在我们添加根据该命令执行不同操作的 if 语句时出现。

# 添加 if/else 语句

让我们在`console.log('Command: ', command);`下面创建一个 if/else 块。我们将添加`if (command === 'add')`，如下所示：

```js
console.log('Starting app.js');

const fs = require('fs');
const _ = require('lodash');

const notes = require('./notes.js');

var command = process.argv[2];
console.log('Command: ', command);

if (command === 'add') 
```

在这种情况下，我们将通过添加`new note`的过程来添加一个新的笔记。现在，我们在这里没有指定其他参数，比如标题或正文（我们将在后面的部分中讨论这个问题）。目前，如果命令确实等于`add`，我们将使用`console.log`打印`Adding new note`，如下面的代码所示：

```js
console.log('Starting app.js');

const fs = require('fs');
const _ = require('lodash');

const notes = require('./notes.js');

var command = process.argv[2];
console.log('Command: ', command);

if (command === 'add') {
  console.log('Adding new note');
}
```

我们可以使用`list`这样的命令做同样的事情。我们将添加`else if (command === 'list')`，如下所示：

```js
console.log('Starting app.js');

const fs = require('fs');
const _ = require('lodash');

const notes = require('./notes.js');

var command = process.argv[2];
console.log('Command: ', command);

if (command === 'add') {
  console.log('Adding new note');
} else if (command === 'list')
```

如果命令确实等于字符串`list`，我们将使用`console.log`运行以下代码块打印`Listing all notes`。我们还可以添加一个 else 子句，如果没有命令的话，打印`Command not recognized`，如下所示：

```js
console.log('Starting app.js');

const fs = require('fs');
const _ = require('lodash');

const notes = require('./notes.js');

var command = process.argv[2];
console.log('Command: ', command);

if (command === 'add') {
  console.log('Adding new note');
} else if (command === 'list') {
  console.log('Listing all notes');
} else {
  console.log('Command not recognized');
}
```

有了这个设置，我们现在可以第三次运行我们的应用程序，在这一次中，你将会看到我们的命令等于列表，并且所有的笔记都会显示出来，如下面的代码所示：

```js
if (command === 'add') {
  console.log('Adding new note');
} else if (command === 'list') {
  console.log('Listing all notes');
} else {
  console.log('Command not recognized');
}
```

这意味着我们能够使用我们的参数来运行不同的代码。请注意，我们并没有运行`Adding new note`和`Command not recognized`。但是，我们可以将`node app.js`命令从`list`切换到`add`，在这种情况下，我们将会得到`Adding new note`的打印，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/475401cc-84e9-4785-a2b0-f676f103fba5.png)

如果我们运行一个不存在的命令，比如`read`，你会看到`Command not recognized`被打印出来，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/e9b6a001-067d-4224-aac3-449a3cdcbd07.png)

# 练习 - 在 if 块中添加两个 else if 子句

现在，我想让你在我们的 if 块中添加另外两个`else if`子句，如下所示：

+   其中一个将用于`read`命令，负责获取个别的笔记

+   另一个叫做`remove`的命令将负责删除笔记

你需要做的就是为它们都添加`else if`语句，然后快速地用`console.log`打印出`Fetching note`或`Removing note`之类的东西。

花点时间来解决这个挑战。当您添加了这两个`else if`子句后，从终端运行它们并确保您的日志显示出来。如果显示出来，您就完成了，可以继续进行下一步。

# 练习的解决方案

对于解决方案，我首先要做的是为`read`添加一个`else if`。我将打开和关闭我的大括号，然后在中间按下*enter*，以便所有内容都被格式化正确。

在`else if`语句中，我将检查`command`变量是否等于字符串`read`，如下所示：

```js
console.log('Starting app.js');

const fs = require('fs');
const _ = require('lodash');

const notes = require('./notes.js');

var command = process.argv[2];
console.log('Command: ', command);

if (command === 'add') {
  console.log('Adding new note');
} else if (command === 'list') {
  console.log('Listing all notes');
} else if () {

} else {
  console.log('Command not recognized');
}
```

在未来，我们将调用更新本地数据库的方法以更新笔记。

目前，我们将使用`console.log`来打印`Reading note`：

```js
console.log('Starting app.js');

const fs = require('fs');
const _ = require('lodash');

const notes = require('./notes.js');

var command = process.argv[2];
console.log('Command: ', command);

if (command === 'add') {
  console.log('Adding new note');
} else if (command === 'list') {
  console.log('Listing all notes');
} else if (command === 'read') {

} else {
  console.log('Command not recognized');
}
```

您需要做的下一件事是添加一个`else if`子句，检查`command`是否等于`remove`。在`else if`中，我将打开和关闭我的条件，并按下*enter*，就像我在前一个`else if`子句中所做的那样；这一次，我将添加`if` `command`等于`remove`，我们想要删除笔记。在那种情况下，我们只需使用`console.log`来打印`Reading note`，如下面的代码所示：

```js
console.log('Starting app.js');

const fs = require('fs');
const _ = require('lodash');

const notes = require('./notes.js');

var command = process.argv[2];
console.log('Command: ', command);

if (command === 'add') {
  console.log('Adding new note');
} else if (command === 'list') {
  console.log('Listing all notes');
} else if (command === 'read') {
  console.log('Reading note');
} else {
  console.log('Command not recognized');
}
```

有了这个，我们就完成了。如果我们参考代码块，我们已经添加了可以在终端上运行的两个新命令，并且我们可以测试这些命令：

```js
if (command === 'add') {
  console.log('Adding new note');
} else if (command === 'list') {
  console.log('Listing all notes');
} else if (command === 'read') {
  console.log('Reading note');
} else {
  console.log('Command not recognized');
}
```

首先，我将用`read`命令运行`node app.js`，然后`Reading note`显示出来：

```js
console.log('Starting app.js');

const fs = require('fs');
const _ = require('lodash');

const notes = require('./notes.js');

var command = process.argv[2];
console.log('Command: ', command);

if (command === 'add') {
  console.log('Adding new note');
} else if (command === 'list') {
  console.log('Listing all notes');
} else if (command === 'read') {
  console.log('Reading note');
} else if (command == 'remove') {
  console.log('Removing note');
} else {
  console.log('Command not recognized');
}
```

然后我会重新运行命令；这一次，我将使用`remove`。当我这样做时，屏幕上会打印出`Removing note`，就像这个屏幕截图中显示的那样：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/3f7acc58-ae65-4865-9d47-413e64f16ece.png)

我将用一个不存在的命令结束我的测试，当我运行它时，您可以看到`Command not recognized`出现了。

# 获取特定的笔记信息

现在，我们在前面的小节中所做的是第 1 步。我们现在支持各种命令。我们需要弄清楚的下一件事是如何获取更具体的信息。例如，您想删除哪个笔记？您想读哪个笔记？在添加笔记时，您希望笔记文本是什么？我们都需要从终端获取这些信息。

现在，获取它将与我们早些时候所做的非常相似，为了向您展示它是什么样子，我们将再次使用以下命令打印整个`argv`对象：

```js
console.log(process.argv);
```

接下来，我们可以在终端运行一个更复杂的命令。假设我们要使用`node app.js remove`命令来删除一个笔记，我们可以通过它的标题来做到这一点。我们可能会使用`title`参数，它看起来像下面的代码：

```js
node app.js remove --title
```

在这个`title`参数中，我们有`--`（两个）破折号，后面是参数名`title`，然后是`=`（等号）。然后我们可以输入我们的笔记标题。也许笔记标题是`secrets`。这样就可以将标题参数传递到我们的应用程序中。

现在，你可以以以下方式格式化`title`参数：

+   你可以像前面的命令一样拥有标题`secrets`。

+   你可以将标题等于引号内的`secrets`，这样可以让我们在标题中使用空格：

```js
 node app.js remove --title=secrets
```

+   你可以完全去掉`=`（等号），只需留下一个空格：

```js
 node app.js remove --title="secrets 2"
```

无论你选择如何格式化你的参数，这都是传递标题的有效方式。

正如你在前面的截图中看到的那样，当我包装我的字符串时，我使用双引号。现在，如果你切换到单引号，它不会在 Linux 或 OS X 上断开，但在 Windows 上会断开。这意味着当你传递命令行参数，如标题或笔记正文时，如果存在空格，你会想要用双引号而不是单引号。所以，如果你正在使用 Windows，并且在参数方面遇到了一些意外的行为，请确保你使用的是双引号而不是单引号；这应该解决问题。

目前，我将保留`=`（等号）和引号，并重新运行命令:

```js
node app.js remove --title="secrets 2"
```

当我运行命令时，您可以在以下代码输出中看到我们有两个参数：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/1cb82daa-4c24-4774-873c-9a3f6872e51d.png)

这些是我们不需要的参数，然后我们有我们的`删除`命令，这是第三个，现在我们有一个新的第四个字符串，标题等于`secrets 2`。我们的参数已成功传递到应用程序中。问题是它不太容易使用。在第四个字符串中，我们必须解析出键`title`和值`secrets 2`。

当我们使用命令时，它是前一节中的第三个参数，它在我们的应用程序内使用起来更容易。我们只需从参数数组中取出它，并通过使用命令变量引用它，并检查它是否等于`添加`，`列表`，`读取`或`删除`。

随着我们使用不同的样式传递参数，事情变得更加复杂。如果我们使用空格而不是`=`（等号）重新运行上一个命令，如下面的代码所示，这是完全有效的，我们的参数数组现在看起来完全不同：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/lrn-node-dev/img/d2a28fa2-df33-4c71-a401-b391ddc66626.png)

在上面的代码输出中，您可以看到标题作为第四项，值作为第五项，这意味着我们必须添加其他条件来解析。这很快就会变得痛苦，这就是为什么我们不会这样做。

在下一章中，我们将使用一个名为 yargs 的第三方模块来使解析命令行参数变得轻松。与我们之前展示的字符串不同，我们将得到一个对象，其中 title 属性等于`secrets 2`字符串。这将使实现其余笔记应用程序变得非常容易。

现在，解析某些类型的命令行参数，例如键值对，变得更加复杂，这就是为什么在下一章中，我们将使用 yargs 来做到这一点。

# 摘要

在本章中，我们学会了如何使用 require 加载 Node.js 提供的模块。我们为笔记应用程序创建了我们的文件，并在`app.js`中引入它们。我们探索了如何使用内置模块，以及如何使用我们定义的模块。我们发现了如何要求我们创建的其他文件，并如何从这些文件中导出属性和函数等东西。

我们稍微探索了 npm，我们如何使用`npm init`生成`package.json`文件，以及我们如何安装和使用第三方模块。接下来，我们探索了`nodemon`模块，使用它在我们对文件进行更改时自动重新启动我们的应用程序。最后，我们学会了如何从用户那里获取输入，这对创建笔记应用程序是必要的。我们了解到我们可以使用命令行参数将数据传递给我们的应用程序。

在下一章中，我们将探索一些更有趣的 Node 基本概念，包括 yargs，JSON 和重构。
