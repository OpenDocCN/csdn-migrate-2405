# Vue CLI3 快速启动指南（一）

> 原文：[`zh.annas-archive.org/md5/31ebad88f7990ce0d7b13055dbe49dcf`](https://zh.annas-archive.org/md5/31ebad88f7990ce0d7b13055dbe49dcf)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Vue 最初是由一个人 Evan You 发起的项目。令人惊讶的是，它已经发展到今天这个地步：成为最受欢迎的前端框架之一，与由公司支持的 React 和 Angular 竞争。

当然，这些并不是唯一的前端框架，但 Vue、React 和 Angular 这三者似乎是最受欢迎的，互联网上充斥着这些框架的比较和使用经验。比如，很常见的是看到一篇比较 Vue 和 React 的文章，或者一篇关于 Vue 比 Angular 更好的博客文章。无论这些文章是某人的观点，还是标题党，或者是事实陈述，这些说法肯定有一些真实性。

Vue 成功的原因是什么？是奉献、努力工作还是运气？可能都有一点。但 Vue 成功的另一个关键是 Evan 明显地优先考虑了为开发人员简化事情。Vue 不再是由一个人开发，但它仍然非常易于接近。社区一直保持着 Vue 从一开始就具有的要点：一个易于使用的框架，让你自由编码。

Vue CLI 就是这一成功的又一个例子。除了一个与其他现代前端框架相匹敌的命令行界面外，Vue CLI 3 还在前端 JavaScript 框架中树立了新的标准，并配备了图形用户界面（GUI）。这个界面使得设置、扩展、运行和服务一个 Vue 项目变得轻而易举。

当你将这个 GUI 的添加与成功地试图通过提供一个经过深思熟虑的设置过程来减轻工具链疲劳的尝试相结合时，你会得到一个非常强大的组合，开发人员也会因此而感到高兴。

# 这本书是为谁准备的

这本书是为网页开发人员和 JavaScript 开发人员准备的，他们想要更多地了解 Vue CLI 3。读者必须具备 HTML/CSS 和 JavaScript 的基本知识。基本上，读者还应该熟悉基本的操作系统工作流程，比如使用类 UNIX 命令行界面，包括 Git Bash、Windows PowerShell 或任何相关的命令行工具。

这本书深入探讨了 Vue CLI 3 的技术构建模块。这不是一本关于在 Vue 中编写应用程序的书。这更像是一本基础性的书，将帮助您了解 Vue CLI 内部工作原理。如果您从未完全确定 NPM 的工作原理以及如何正确使用它，这本书将通过 Vue CLI 3 的视角来解释。同样，我们将研究 webpack，HMR，使用单文件`.vue`组件，SCSS，ECMAScript，使用 Jest 进行单元测试以及使用 Cypress 进行端到端测试。

# 本书涵盖的内容包括：

第一章《介绍 Vue CLI 3》解释了如何使用 Vue CLI 3 以及为什么应该使用它。它涵盖了最佳实践以及使用 Vue CLI 3 会得到什么。我们将设置 Node 版本管理器和 NPM，安装 Vue CLI 3，并展示如何通过命令行或 GUI 启动新应用程序。

第二章《Vue CLI 3 中的 Webpack》带领读者回顾了过去几年 JavaScript 的发展概况，这导致了 webpack 的出现。它解释了一些背景概念：NPM 和 NPM 脚本，CommonJS，JS 和 Node.js 中的模块，以及模块捆绑器以及它们在浏览器中的使用。此外，我们介绍了 webpack 的工作原理以及如何运行它。最后，我们逐步解释了如何通过 NPM 添加 Vue 项目并使用 webpack。基本上，我们正在手动设置 Vue 工具链，以便我们可以欣赏 Vue CLI 3 自动为我们做了什么。

第三章《Vue CLI 3 中的 Babel》探讨了如何使用 Babel 以及使用它的好处。我们检查了 Vue 核心 Babel 插件的构建模块，包括`Babel 7`，`babel-loader`和`@vue/babel-preset-app`。我们还研究了使用 ES5 和 ES6 运行 webpack 的区别，并更新了我们的 webpack 配置，以便它能理解 Babel。

第四章《Vue CLI 3 中的测试》介绍了使用 Vue 插件，重点介绍了用于测试的插件。我们向 Vue 应用程序添加了 Jest 插件，使用 Jest 运行单元测试，并在 Vue CLI 3 GUI 中展示了一些额外的技术和工作流程，包括从项目任务页面运行任务以及在 GUI 中运行单元测试。我们讨论了**测试驱动开发**（TDD）以及使用断言，并在章节末尾概述了 Cypress。

第五章《Vue CLI 3 和路由》讨论了使用 vue-router 和 vuex 添加 Vue 项目，配置预设选项以及理解 vue-router 主题。这些包括命名路由、动态路由、使用 Vue 实例中的方法导航到路由、使用子路由以及延迟加载路由。

第六章《在 Vue CLI 3 中使用 ESlint 和 Prettier》向我们展示了 ESlint 是什么以及它的用处。我们还看了 Prettier，一个方便的代码格式化程序，可以在每次保存时格式化您的代码。我们讨论了通用的代码检查器以及它们的用途。

第七章《使用 SCSS 改进 CSS》描述了 SCSS 的基础知识，展示了它与 CSS 的不同之处以及可用的附加功能。我们使用了在第五章《Vue CLI 3 和路由》中构建的简单应用程序，并看到如何通过向应用程序添加 boostrap-vue 插件来改进其样式。在 VDOM 库中使用 SCSS 有时会令人困惑，在本章中，我们看到了一种实际的工作流选项。

第八章《在 GitHub Pages 上部署 Vue CLI 3 应用程序》解释了 Git 是什么以及如何设置它。我们讨论了一些基础知识，包括使用 Git 跟踪更改和提交应用程序中的更改。我们继续讨论了三棵树概念、分支和合并分支。我们注册了 GitHub 帐户，使用 GitHub Desktop 添加了 origin/master，并了解了如何发布本地存储库。最后，我们讨论了如何使用*subtree*功能在 GitHub 页面上部署 Vue 应用程序。

# 要充分利用本书

要充分利用本书，您应该对使用 Windows、HTML、CSS、JavaScript 的基础知识以及使用 Git Bash 等命令行工具有一定的了解。熟悉 Node、NPM 和一些基本的命令行实用程序将是有益的，但这并非强制要求。

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packt.com](http://www.packt.com)。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

文件下载后，请确保使用最新版本解压或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Vue-CLI-3-Quick-Start-Guide`](https://github.com/PacktPublishing/Vue-CLI-3-Quick-Start-Guide)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载它：[`www.packtpub.com/sites/default/files/downloads/9781789950342_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/9781789950342_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄。这是一个例子：“将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。”

代码块设置如下：

```js
{
  "name": "vue-from-npm",
  "version": "1.0.0",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```js
let CustomArticle = Vue.component('custom-article', {
    template: `
      <article>
        Our own custom article component!
      </article>`
  })
```

任何命令行输入或输出都以以下方式编写：

```js
mkdir new-project-with-webpack && cd new-project-with-webpack
```

**粗体**：表示一个新术语，一个重要的词，或者你在屏幕上看到的词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“从管理面板中选择系统信息。”

警告或重要说明会以这种方式出现。提示和技巧会以这种方式出现。


# 第一章：介绍 Vue CLI 3

本书介绍了**Vue CLI 3**，并回答了诸如如何使用它，为什么使用它，最佳实践以及您将从中获得什么等问题。

在本章中，我们将看看如何在我们的系统上设置 Vue CLI 3。我们将首先检查 Vue CLI 3 是否已经可用，然后我们将看到如果我们需要进行全新安装或从先前版本进行更新的确切步骤。

然后我们将看看如何安装**Node 版本管理器**（**NVM**），以及为什么这比简单安装 Node 更好。我们将看到在 VS Code 中如何轻松开始使用 Vue CLI 3，以及如何通过使用命令行来集成所有这些工具。

我们还将讨论为什么使用 Vue CLI 3 非常好，并且我们将通过从命令行和使用内置的 Vue CLI 3 UI 功能来运行默认的 Vue CLI 3 应用程序来实践这一点。

我们将在本章中涵盖以下主题：

+   在您的系统上设置 Vue CLI 3

+   安装 Vue CLI 3

+   安装 VS Code

+   使用无配置的 Vue CLI

+   使用 Vue CLI 3 的好处

+   通过默认工具链避免 JavaScript 疲劳

我们将从设置 Vue CLI 3 开始本章。

# 技术要求

我们只需要一些技术要求；它们如下：

+   Windows 安装（Windows 7 或更高版本）

+   为 Windows 安装 NVM（安装的具体步骤在本章中描述）

+   安装 VS Code（代码编辑器）

让我们开始在我们的系统上设置 Vue CLI 3。

# 在我们的系统上设置 Vue CLI 3

使用 Vue CLI 3 的常见方式是通过一个名为**命令行界面**（**CLI**）的命令行应用程序，在那里我们运行我们的 Vue CLI 3 命令。另一个先决条件是在我们的计算机上安装 Node.js。

如果您在共享计算机上工作，比如在您的开发团队中，很有可能您已经具备了所有的先决条件。在这种情况下，您可以通过运行一些检查来验证您是否可以立即开始使用 Vue CLI 3。

# Vue CLI 3 已经可用吗？

要快速检查您是否可以立即运行 Vue CLI 3 并跳过所有安装步骤，请在命令行应用程序中运行以下命令：

```js
node --version
```

还可以使用此命令检查 Vue CLI 3：

```js
vue -V
```

如果您得到任何高于 8.9 的 Node 版本（理想情况下，高于 8.11.0），您就可以开始了。显然，对于 Vue CLI，您希望得到任何高于 3.0.0 的版本。

此外，如果您的 Vue CLI 版本低于 V3，或者您想更新到最新的 Vue CLI，例如 3.3.0，只需运行此命令：

```js
npm install @vue/cli
```

如果您没有安装 Node.js 或 Vue CLI 怎么办？

我们将使用`nvm`或`nvm-windows`来安装 Node，然后安装 Vue CLI 3。

# 使用 Node 版本管理器安装 Node.js

我们应该使用推荐的 Node.js 版本是多少？此信息可在以下链接找到：[`cli.vuejs.org/guide/installation.html`](https://cli.vuejs.org/guide/installation.html)。

目前，截至 2019 年初，要在 Vue CLI 中获得最佳结果，所需的 Node 的最低版本是 8.11.0+，但如果确实需要，您也可以使用 8.9。

这带我们来到另一个重要的决定：安装 NVM。

# 为什么要安装 NVM？

虽然不绝对需要安装 NVM 才能在系统上运行 Vue CLI 3，但出于几个原因，安装 NVM 是可取的。

首先，您永远不知道 Node 何时会推荐更新以修复安全问题，这通常意味着最好在您的计算机上安装更新。

其次，如果您需要运行除 Vue 之外的其他技术，这些其他技术可能还需要不同版本的 Node。要在系统上轻松切换这些所需的 Node 安装，您可以简单地安装 NVM。

# 在 Windows 上安装 NVM

您可以从此地址下载 Windows 的 NVM：

```js
https://github.com/coreybutler/nvm-windows/releases
```

找到`nvm-setup.zip`文件，下载并从中提取`nvm-setup.exe`，然后按照以下安装步骤进行安装：

1.  按下 Windows + *R*打开运行提示。在提示符中键入`cmd`。

1.  在提示符内部，按下*Ctrl* + *Shift* + *Enter*。这将以管理员权限运行命令提示符，这是下一步所需的。

1.  访问[`nodejs.org`](https://nodejs.org)，查看当前的**长期支持**（**LTS**）版本号。例如，目前在 64 位 Windows 上，LTS 版本是 10.15.1。

1.  要安装它，请在具有管理员权限的命令提示符中运行以下命令：

```js
nvm install 10.15.1
```

1.  命令提示符将记录以下消息：

```js
Downloading node.js version 10.15.1 (64-bit) ...
```

1.  下载完成后，我们可以使用下载的 Node 版本。我们用以下命令来做：

```js
nvm use 10.15.1
```

1.  最后，您可以通过运行以下命令来验证安装是否成功：

```js
node --version
```

1.  如果您想了解与您的 Node 安装一起提供的`npm`的版本，只需运行以下命令：

```js
npm --version
```

接下来，我们将安装 Vue CLI 3。

# 安装 Vue CLI 3

我们可以使用`npm`或`yarn`来安装 Vue CLI 3。由于`npm`与 Node.js 安装捆绑在一起，我们将使用`npm`：

```js
npm install -g @vue/cli --loglevel verbose
```

上述命令会全局安装 Vue CLI 3。这就是`-g`标志的作用。`@vue/cli`的语法是我们在 Vue CLI 3 中使用的，`--loglevel verbose`将记录我们安装的细节，这非常有用，特别是在较慢的连接和较慢的机器上，有时我们可能会开始怀疑我们的控制台是否冻结。使用`--loglevel verbose`，就会更清晰，这总是好的。

完成后，让我们通过运行此命令来双重检查安装的 Vue CLI 版本：

```js
vue --version
```

以下是一些其他有用的命令，您应该在控制台中尝试：

```js
vue -h
```

请注意，`vue -h`是`vue --help`的别名。我使用前者是因为它更容易输入。

还要注意，您可以在每个单独的`vue`命令上运行`-h`标志，例如：

```js
vue create -h
vue add -h
vue invoke -h
vue inspect -h
vue serve -h
vue build -h
vue ui -h
vue init -h
vue config -h
vue upgrade -h
vue info -h
```

运行任何上述命令将返回特定命令的用法说明，描述其功能以及要附加到每个单独命令的选项（标志）。显然，`-h`标志是探索 Vue CLI 功能的好方法，并且在需要时即时刷新您的记忆。

接下来，我们将安装我们选择的代码编辑器 VS Code。

# 安装 VS Code

要安装 VS Code，只需转到[`code.visualstudio.com`](https://code.visualstudio.com)，然后下载适合您操作系统的版本。

如果您不确定自己使用的是 32 位还是 64 位计算机，您可以通过在命令提示符（具有管理员权限）中运行以下命令来快速检查 Windows 上的情况：

`wmic os get osarchitecture`

输出将是`OSArchitecture`，在下一行，要么是`32 位`，要么是`64 位`。

一旦 VS Code 被下载，只需运行下载的安装文件并按照安装说明进行安装。

安装完 VS Code 后，您将在命令行中获得一个额外的命令，`code`。

`code`命令非常有用，我们将在下一节中看到。

# 在没有配置的情况下使用 Vue CLI

在本节中，我们将看到使用 Vue CLI 的最快最简单的方法。它完全不需要任何配置！使用 Vue CLI 无需配置的原因是为了进行一些快速实验，而不必回答关于项目配置的提示，这是 Vue CLI 在运行包含配置步骤的项目时通常会询问的（这是使用 Vue CLI 构建应用程序的默认方法）。

首先，按住*Shift*键，在桌面的空白区域右键单击。从弹出的上下文菜单中，单击“在此处打开命令窗口”命令。

打开后，输入以下命令：

```js
mkdir noConfig
```

这将创建一个名为`noConfig`的新目录。接下来，让我们使用`cd`命令切换到该目录：

```js
cd noConfig
```

最后，使用以下命令从命令提示符启动 VS Code：

```js
code .
```

前面命令中的点表示在当前文件夹中打开 VS Code。可以关闭欢迎标签页。

接下来，使用*Alt* + *F*键盘快捷键打开文件菜单，并按下*N*键打开一个全新的文件。

在新文件中，打开标签页，输入以下代码：

```js
<template>
  <h1>What's up, Vue CLI 3?</h1>
  <hr>
</template>
```

接下来，按下*Ctrl* + *S*键盘快捷键，将文件保存为`App.vue`。

VS Code 将保存文件。它将给出一个新的图标，Vue 标志图标，这是一个视觉提示，刚刚保存的文件确实是一个 Vue 文件。

VS Code 也可能提示您安装一个名为`Vetur`的扩展，具体提示如下：

```js
The 'Vetur' extension is recommended for this file type.
```

通过单击弹出窗口底部的安装按钮来安装扩展。

请注意，安装`Vetur`扩展与使用没有配置的 Vue CLI 3 无关，但与我们在 VS Code 中使用 Vue 时更加高效有关。

现在我们可以通过运行`vue serve`来为我们的 Vue 应用程序提供服务。但是，在实际运行命令之前，让我们使用`-h`标志来查看我们有哪些可用选项：

```js
vue serve -h
```

这就是我们将得到的内容：

```js
Usage: serve [options] [entry]

serve a .js or .vue file in development mode with zero config

Options:
 -o, --open Open browser
 -c, --copy Copy local url to clipboard
 -h, --help Output usage information
```

现在我们知道可以期待什么，让我们使用以下命令为我们的 Vue 应用程序提供服务：

```js
vue serve -o -c
```

因此，正如之前提到的，这个命令将为我们的 Vue 应用程序提供服务，并在浏览器中打开它。它还将复制提供的 URL 到剪贴板。这使我们可以，例如，打开一个不同的非默认浏览器，并轻松地粘贴 URL 到浏览器的地址栏中，这样我们也可以在那里预览我们的应用程序。

然而，我们将遇到一个小问题。

我们将在命令中得到这个通知，而不是我们的 Vue 应用程序被提供服务：

```js
Command vue serve requires a global addon to be installed.
Please run npm install -g @vue/cli-service-global and try again.
```

这是一个简单的修复。更好的是，我们将使用`--loglevel verbose`扩展前面的命令：

```js
npm install -g @vue/cli-service-global --loglevel verbose
```

一段时间后，根据你的下载速度，你会收到`npm info ok`的消息。

这意味着你现在可以再次运行`vue serve`命令：

```js
vue serve -o -c
```

这次它成功了！有点...

现在我们收到一个错误，上面写着`编译失败，有 1 个错误`。然后，更进一步地，我们看到了根本原因：

```js
Component template should contain exactly one root element.
```

有几种方法可以解决这个问题，但它基本上是说我们可以将我们的`h1`和`hr`标签包裹在一个`div`标签中，然后我们就可以了。所以，让我们在 VS Code 中更新`App.vue`文件为这样：

```js
<template>
  <div>
    <h1>What's up, Vue CLI 3?</h1>
    <hr>
  </div>
</template>
```

确保保存你的更改，现在，最后，让我们再次提供服务：

```js
vue serve -o -c
```

你可能会有点惊讶，因为一个新的标签页会自动打开，加载应用程序，显示在你的默认浏览器中。

假设你的默认浏览器是 Chrome。让我们打开另一个浏览器（例如 Firefox），点击管理栏内部，并按下*Ctrl* + *V*快捷键粘贴剪贴板的内容。当然，它将是`http://localhost:8080/`。

通过使用`-o`和`-c`标志，我们以非常简单的方式执行了打开应用程序并复制其 URL 的重复任务只是冰山一角。Vue CLI 3 还有更多功能，可以帮助我们更快更轻松地编写我们的应用程序。

例如，让我们回到我们的代码，删除带有`hr`标签的行，然后保存文件。看看你的浏览器标签，打开我们的 Vue 应用程序的标签。它将自动刷新，反映代码的更改。这就是 webpack 在 Vue CLI 3 的内部运行，监视我们的 Vue 文件的更改，并相应地在浏览器中热重新加载应用程序。

如果你已经编码超过几年，你会欣赏到这种工作流的便利。过去，我们要么必须设置我们的工具，使它们在我们保存文件时自动刷新浏览器中的应用程序，要么我们必须设置我们的 IDE 或代码编辑器，或者两者兼而有之。甚至直到最近，我们仍然不得不调整 webpack 来自动化这种工作流程，而且像任何与编码相关的事情一样，有时并不像我们希望的那样顺利。

使用 Vue CLI 3，所有这些都是自动化的，非常简单。

让我们看看 Vue CLI 3 如何帮助我们更好地编码并提高生产力的其他方式。

# 使用 Vue CLI 3 的好处

当 Vue CLI 3 推出时，Vue 的创始人 Evan You 列出了它的这些目标：

+   通过简化设置来避免前端开发的工具链疲劳

+   遵循工具的最佳实践

+   使这些最佳实践成为 Vue 应用的默认设置

除了这些伟大的目标，Vue CLI 还带来了许多更新，比如以下内容：

+   预设的 webpack 配置

+   ES2017 和 Babel 7 支持开箱即用

+   出色的 CSS 支持，包括**Sassy CSS**（**SCSS**）和**PostCSS**支持

+   许多集成选项（TypeScript，PWA，Web 组件，端到端测试，Jest 等）

这是很多功能。本书的目的是遍历所有选项，并让您熟悉它们的内部工作原理。

现在，让我们来看看使用默认选项设置默认应用有多么容易，来结束本章。

# 默认工具链，疲劳程度为零

在本节中，我们将创建一个默认的 Vue 应用程序模板。与上一节相反，在本节中，我们将真正构建一个完整的应用程序。我们将使用两种方法：命令行上的 Vue CLI 3 和带有 GUI 的 Vue CLI 3。

您可能会问为什么我们首先没有配置运行 Vue CLI 3？答案是，这可能对快速实验和开始使用一些基本命令很有用。

# 通过命令行创建 Vue CLI 3 默认应用

我们使用`vue create`命令创建 Vue CLI 3 应用程序。让我们看看我们有哪些选项可用：

```js
vue create -h
```

这就是将返回的内容：

```js
Usage: create [options] <app-name>

create a new project powered by vue-cli-service

Options:
-p, --preset <presetName> Skip prompts and use saved or remote preset
-d, --default Skip prompts and use default preset
-i, --inlinePreset <json> Skip prompts and use inline JSON string as preset
-m, --packageManager <command> Use specified npm client when installing dependencies
-r, --registry <rul> Use specified npm registry when installing dependencies (only for npm)
-g, --git [message] Force git initialization with initial commit message
-n, --no-git Skip git initialization
-f, --force Overwrite target directory if it exists
-c, --clone Use git clone when fetching remote preset
-x, --proxy Use specified proxy when creating project
-b, --bare Scaffold project without beginner instructions
-h, --help output usage information
```

让我们首先跳过所有提示，使用默认选项：

```js
vue create -d first-default-app
```

您的控制台将显示以下输出：

```js
Vue CLI v3.3.0
? Creating project in C:\...
? Initializing git repository...
? Installing CLI plugins. This might take a while...
```

确实需要一段时间。幸运的是，有一个进度条，让我们知道我们在设置项目时进行到了哪个阶段。

准备好后，我们只需运行以下命令：

```js
cd first-default-app
```

一旦我们的控制台指向正确的目录，我们可以使用以下命令运行应用：

```js
npm run serve
```

现在我们可以在浏览器中查看默认应用程序：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/af6f9b7b-eeff-470e-82f2-de62aec3af1b.png)

正如我们所看到的，我们有一个欢迎消息，然后页面列出了安装的 CLI 插件。显然，`babel`和`eslint`插件是默认的。每个链接都指向 GitHub 上`vue-cli`存储库中的各自部分。

接下来，我们看到一些基本链接和一些链接，以了解更大的`Vue.js`生态系统（即，`vue-router`，`vuex`，`vue-devtools`，`vue-loader`和`awesome-vue`的链接）。

# 通过 UI 创建 Vue CLI 3 默认应用

要开始使用 Vue CLI GUI，让我们首先使用*Ctrl* + *C*快捷键停止在上一节中运行的服务器。控制台将会回应以下消息：

```js
Terminate batch job (Y/N)?
```

输入`Y`（大小写不重要）并按下*Enter*键。

这将使我们重新获得当前控制台窗口的控制，并允许我们输入新命令。

让我们首先在控制台中从当前目录向上一级：

```js
cd ..
```

接下来，让我们运行这个命令：

```js
vue ui -h
```

然后我们将得到以下输出：

```js
Usage: ui [options]

start and open the vue-cli ui

Options:
-H, --host <host> Host used for the UI server (default: localhost)
-p, --port <port> Port used for the UI server (by default search for available port)
-D, --dev Run in dev mode
--quiet Don't output starting messages
--headless Don't open browser on start and output port
-h, --help output usage information
```

这次，我们将不使用任何标志运行该命令：

```js
vue ui
```

我们将在控制台中看到以下输出：

```js
? Starting GUI...
? Ready on http://localhost:8000
```

这次，我们可以通过可视化方式创建一个项目。最初，我们看到当前文件夹中没有 Vue 项目：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/6671f159-471f-4888-84d1-aba11a94dcfa.png)

让我们点击“创建”选项卡来创建一个项目。

将打开一个新窗口，有一个大按钮，上面写着在这里创建一个新项目：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/0d1f4896-c050-4335-a9b2-a90bee7ba022.png)

正如我们在前面的截图中看到的，还有许多其他按钮和选项可以使用。我们将在接下来的章节中进行详细讨论；目前，我们只是熟悉我们正在使用的工具：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/897416f9-bd44-411e-ae62-13cf57e973b6.png)

正如我们从前面的截图中看到的，页面底部的“下一步”按钮当前是禁用的。要启用它，只需在最顶部的输入框中输入项目文件夹名称。我们将文件夹命名为`second-vue-project`。现在点击“下一步”。

在下一个窗口中，您可以选择一个预设。让我们将其设置为默认预设：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/32858460-03b1-496a-bc52-9b73d275b560.png)

选择一个预设将使“创建项目”按钮可点击。您将在屏幕中央看到一个加载图标，并显示以下消息：

```js
Installing Vue CLI plugins. This might take a while...
```

在安装过程中，您将看到一些其他消息。最后，当完成时，您将会看到以下窗口：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/c4e6ddb2-6ac3-4593-b8ee-3d9c27dbb9df.png)

我们的项目现在已经准备好进行工作了，我们将在下一章中进行。

# 摘要

在本章中，我们看了如何使用 Vue CLI 3 开始，既可以使用命令行，也可以使用 Vue CLI UI。

我们已经看到如何安装所有先决条件，并且我们看到了建议的工作流程和一些基本指针，以便轻松入门。由于了解如何在命令行和 UI 上使用 Vue CLI，我们现在可以轻松初始化 Vue 应用程序。我们知道在启动新项目时有哪些选项可供我们选择。然而，还有许多其他事情我们需要了解 Vue CLI 的内部工作原理。

在下一章中，我们将通过专注于 webpack 来进一步改进我们的工作流程，webpack 是 Vue CLI 3 核心的模块捆绑器。


# 第二章：Vue CLI 3 中的 Webpack

在上一章中，我们看到了如何通过命令行和 UI 开始使用 Vue CLI。在本章中，我们将从 Vue CLI 3 的角度介绍 webpack 的基础知识。我们将首先概述 webpack 是什么。我们将研究模块捆绑、摇树、webpack 加载器和输出、webpack 插件、**热模块替换**（**HMR**）、代码覆盖和代码拆分的概念，然后我们将看看这些概念如何与 Vue CLI 3 配合，如下所示：

+   从脚本标签到模块捆绑器的 JavaScript（JS）语言的演变

+   脚本标签

+   **立即调用函数表达式**（**IIFEs**），它们解决了什么问题，以及它们没有解决的问题

+   **Node Package Manager** (**NPM**)如何帮助团队在他们的代码中共享第三方库

+   JS 任务运行器和 NPM 脚本的作用

+   CommonJS 规范是什么，以及它如何在 JavaScript 和 Node.js 中工作

+   模块捆绑器是什么，以及它们如何弥合 Node.js 和浏览器之间的差距

+   webpack 是什么，以及它是如何工作的

+   如何在项目中运行 webpack

+   使用生产和开发模式使用 webpack 捆绑资产

+   通过 NPM 添加 Vue 项目并使用 webpack

准确理解 webpack 的工作原理对于理解 Vue CLI 3 的魔力至关重要。如果您熟悉 webpack，您可能仍然会发现本章的某些部分有用。如果您觉得自己是 webpack 专家，您可能可以直接跳过本章。

在深入了解 webpack 是什么以及正确理解 webpack 解决的问题之前，我们需要回顾一下过去十年中 JS 语言发生的一些变化。

# JS 语言的演变

从 webpack 的角度来看，以下是 JS 生态系统中添加的方法、技术、最佳实践和模式的时间顺序列表，这些方法、技术、最佳实践和模式导致了当前的状态：

+   `script`标签作为向网页添加交互性的答案

+   立即调用函数表达式作为模块化库和避免代码冲突的答案

+   IIFEs 的问题

+   使用 NPM 在团队环境中共享第三方库

+   JS 任务运行器和 NPM 脚本

+   JS 中的模块

让我们更详细地看看这些解决方案中的每一个。

# 脚本标签

最初，将 JS 添加到您的网页意味着您需要直接在 HTML 中添加一些`script`标签。对于快速原型，这仍然是一种有效的做法，甚至到今天。很多时候，第三方库是通过`script`标签内的`src`属性添加的（通常放在我们的 HTML 中关闭`body`标签的正上方）。

不幸的是，您通常需要在 HTML 中添加多个`script`标签。而不管您是直接将 JS 代码添加到页面中，还是从项目中的另一个文件添加，或者从远程位置添加（例如从**内容传送网络**（**CDN**）使用`src`属性），最终，所有这些脚本都被添加到全局 JS 范围内。这意味着一件事，冲突。

为了避免冲突，采取了一个巧妙的方法，即使用 IIFE。

# 立即调用的函数表达式

IIFE 到底是什么？IIFE 简单地利用了 JS 中*括号不能包含语句*的事实。这个事实本身允许 JS 开发人员放入匿名函数，他们可以立即调用，而不会因为简单地将它们包装在括号中而从解析器中得到任何错误。

IIFE 本质上是 JS 语言的一个怪癖，但是非常有用；通过 IIFE，所有的代码都被限定在函数范围内，因此您的代码不会受到外部任何其他东西的影响。换句话说，使用 IIFE 是避免冲突的一种简单方法，即意外覆盖变量或函数。因此，有一段时间，许多流行的库开始将它们自己的代码包装成 IIFE。例如，如果您打开 jQuery 库的代码（[`code.jquery.com`](https://code.jquery.com)），或 Chart.js 库的代码（[`cdnjs.cloudflare.com/ajax/libs/Chart.js/2.7.3/Chart.bundle.js`](https://cdnjs.cloudflare.com/ajax/libs/Chart.js/2.7.3/Chart.bundle.js)），或许多其他流行的 JS 库的代码，您会发现它们使用了 IIFE 模式。

因此，通过 IIFE，我们可以向页面添加不同的脚本，而不必担心代码冲突可能发生。

# IIFE 的问题

不幸的是，仅仅使用 IIFE 并不能解决我们所有的问题。为了说明手头的问题，让我们引用 Erlang 的创始人 Joe Armstrong 的话：

“你想要香蕉，但你得到的是拿着香蕉的大猩猩，整个丛林。”

请记住，在这段引用中，阿姆斯特朗先生讨论的是面向对象语言的问题，但根本问题在 JS 代码模块化中也适用。

基本上，我们对 IIFEs 的问题在于我们无法从 JS 库中精选出我们想要使用的特定功能。使用 IIFE 模式，我们*必须*使用 IIFE 中包含的所有内容，即使我们只是使用特定库代码库的一小部分。当然，老实说，IIFEs 并不是这个问题的罪魁祸首。长期以来，JS 语言根本没有能力精选任何类型的代码功能，因为在 JS 中，将代码拆分成模块是不可能的。

JS 的另一个主要痛点是在团队之间重复使用第三方代码的问题。

# 使用 NPM 在团队环境中共享第三方库

IIFEs 解决了代码冲突的问题，但并没有解决代码重用的问题。如果我的团队中的开发人员有一个不同的、更新的库版本，其中有破坏性的更改，该怎么办？如果我决定在我的计算机上更新依赖关系，我的其他团队成员将如何处理？除了使用源代码版本控制，还有其他更快的协作选项吗？

**Node Package Manager**（**NPM**）是这些问题的答案。Node 只是一个可以在服务器上运行的 Google V8 JS 引擎。NPM 允许开发人员将新库安装到项目中，无论是用于应用程序的前端还是后端。因此，NPM 实际上是 JS 包管理器，类似于 Ruby（gems ([`rubygems.org/`](https://rubygems.org/)））、C#（NuGet ([`www.nuget.org/`](https://www.nuget.org/)））或 Linux 中的`apt-get`、`yum`。

例如，假设我们想通过 NPM 安装 Vue。如果我们的计算机上安装了 Node，那么我们也会有 NPM，因为 NPM 随 Node 一起捆绑安装。

接下来，我们需要创建一个新目录。让我们将此目录的名称更改为`vue-from-npm`，并将命令行控制台指向它。然后我们可以跟随这个命令：

```js
npm init -y
```

运行上述命令将创建一个`package.json`文件。`-y`标志接受控制台中提示的所有默认答案。

如果我们查看项目目录中新创建的`package.json`文件，我们会看到以下内容：

```js
{
  "name": "vue-from-npm",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "keywords": [],
  "author": "",
  "license": "ISC"
}
```

请注意，`npm init`命令只会将`package.json`文件添加到空目录中。就是这样！

然后，添加 Vue 就像运行这个命令一样简单：

```js
npm install vue --save --verbose
```

上述命令将执行一些操作，即：

+   它将添加`node_modules`目录。

+   它将整个 Vue 库放在`node_modules`目录中。

+   它将在我们项目的根目录中创建`package-lock.json`文件。

+   它将更新我们项目的根目录中的`package.json`文件。

更新后的`package.json`文件现在看起来是这样的：

```js
{
  "name": "vue-from-npm",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "keywords": [],
  "author": "",
  "license": "ISC",
  "dependencies": {
    "vue": "².6.7"
  }
}
```

如果不明显的话，文件已经更新了一个新条目：`dependencies`。这个条目列出了项目中包含的所有依赖项。具体来说，我们已经将 Vue（版本 2.6.7 或以上）添加到了我们的项目中。

NPM 的一个很棒的地方是，我们可以像添加 Vue 一样轻松地向我们的项目添加任何其他库。例如，要使用 accounting.js 更新我们的项目，我们只需运行这个命令：

```js
npm install accounting-js --save --verbose
```

安装完成后，让我们再次检查`node_modules`目录：

```js
vue-npm/node_modules/
 ├── accounting-js/
 │ ├── dist/
 │ ├── lib/
 │ ├── CHANGELOG.md
 │ ├── package.json
 │ └── README.md
 ├── is-string/
 ├── object-assign/
 └── vue/
```

请注意，为了简洁起见，我们只显示了`accounting-js`文件夹内的第二级文件夹和文件。`is-string`，`object-assign`和`vue`文件夹都被折叠显示。

这向我们展示了有时其他 NPM 模块会捆绑实际安装的库。在`accounting-js`的情况下，我们还得到了`is-string`和`object-assign` NPM 模块。让我们也检查一下我们目录根目录中更新的`package.json`文件：

```js
{
  "name": "vue-from-npm",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "keywords": [],
  "author": "",
  "license": "ISC",
  "dependencies": {
    "accounting-js": "¹.1.1",
    "vue": "².6.7"
  }
}
```

正如我们所看到的，根`package.json`文件已经更新为正确的`accounting-js`版本。让我们找到另一个`package.json`文件，这次是在`node_modules/accounting-js`文件夹中。如果你打开了那个文件，它包含了更多信息，仅仅超过 100 行代码。这些信息是特定于实际的 NPM 模块`accounting-js`。

好的，现在我们的项目已经准备好进行协作了。怎么做呢？让我们看看我们的一个同事，让我们称他为“约翰”，如何在他自己的电脑上添加我们刚刚创建的项目和所有项目依赖项。

为此，我们将创建一个新文件夹，让我们称之为`johns-computer`，然后我们只需将`vue-from-npm`文件夹中的根级`package.json`复制到我们的`johns-computer`文件夹中。

接下来，让我们简单地运行这个命令：

```js
npm install --verbose
```

运行上述命令将安装我们在`vue-from-npm`文件夹中的所有项目和依赖项。

# JavaScript 任务运行器和 NPM 脚本

大约在 NPM 变得流行的同时，另一种前端技术也在崛起：任务运行器。任务运行器是简单的工具；它们运行重复的任务。有时，任务运行器被称为构建工具，因为它们充当开发人员对代码库进行更新和最终生成的生产就绪代码之间的中介。这就是所谓的*构建步骤*，这是软件开发过程中的一部分，在这个过程中，你的代码在你编写完之后会发生一些事情。

例如，CSS3 中添加的新功能通常以*供应商前缀*（也称为*浏览器前缀*）的形式开始。换句话说，在新的 CSS 功能在所有浏览器中可用之前，它会在各个浏览器中以实验阶段实现，使用浏览器特定的前缀，如下所示：

```js
-ms-
-moz-
-o-
-webkit-
```

在这个按字母顺序排列的浏览器前缀列表中，我们可以看到微软浏览器、Mozilla、旧版本的 Opera，最后是所有基于 webkit 的浏览器（Chrome、Safari、新版 Opera 等）的浏览器前缀。

跟踪浏览器前缀的更新是有点困难的。开发人员的时间可能不是最好的用法，去监视 CSS 实现的变化，然后相应地更新他们的代码。例如，在过去的某个时间点，有必要在 CSS 的`transition`属性上使用以下浏览器前缀：

```js
-webkit-transition: background-color 1s;
-moz-transition: background-color 1s;
-o-transition: background-color 1s;
-ms-transition: background-color 1s;
```

显然，今天我们在 CSS 声明中简单地使用`transition`属性，而不需要任何浏览器前缀，因为`transition`属性在所有现代浏览器中得到了广泛支持。

不得不应对不断变化的 CSS 规范和各种浏览器中的实现带来的不断变化的情况，导致了任务运行器这种解决方案的出现。前端开发人员现在不再需要手动向他们的 CSS 代码中添加供应商前缀，而是可以简单地向他们的任务运行器添加一个插件，它会为他们做这些繁重的工作：在需要时添加供应商前缀。

当然，我们之前看到的只是任务运行器用于的一个例子。其他一些例子包括：压缩 CSS 和 JS 文件，从 ES6 转译为 ES5，从 SASS 编译 CSS，删除未使用的 CSS，在项目中保存文件时重新加载浏览器，等等。

今天，有许多不同的工具帮助我们有效地自动化开发过程中的一些任务。三个工具脱颖而出：Grunt、Gulp 和 NPM 脚本。

虽然 Grunt 和 Gulp 是独立的任务运行器，可以通过 NPM 安装，但基于 NPM 的脚本是一个有趣的替代方案，原因如下：

+   您已经在使用 NPM，为什么不更熟悉一下您已经在使用的工具呢？

+   使用 NPM 脚本而不是前面提到的任务运行器将进一步简化您的开发流程。

+   通过使用 NPM，您可以避免使用任务运行器插件来自动化 NPM 中可以自动化的任务的复杂性。

直到这一点，我们已经回顾了 JS 生态系统的历史和演变。我们已经看到了 IIFE 如何用来处理意外的作用域泄漏。我们还看到了 NPM 如何处理代码共享。我们进一步看到了如何使用任务运行器自动化一些重复的任务，以及如何使用 NPM 来通过将任务保留在 NPM 脚本中来消除不必要的抽象层。

然而，我们还没有看到解决 JS 中代码模块化问题的方法。所以，让我们接着看看。

# JavaScript 中的模块

在任何编程语言中，模块都是一个独立的功能块。您可以将它们视为电视节目的不同集数。它们可以独立查看。它们可以独立存在，尽管它们是整体的一部分。

就像电视节目中的一集有一个季节和一个编号，这样我们就知道*它在*更大情节中的位置一样，一个模块也包含了告诉我们它依赖的其他模块（*模块依赖*）以及它为整个应用程序添加了什么功能的信息；这就是所谓的*模块接口*，对其他模块公开的 API。

我们已经看到，在开始时，JS 根本没有模块。这在 Node.js 的引入后发生了变化。Node.js 实际上是 CommonJS 的一种实现，这是由 Mozilla 的 Kevin Dangoor 在 2009 年发起的一个项目。

CommonJS 项目的目的是定义一个标准库，提供供在浏览器之外使用的 JS API。这包括一个模块规范，这导致开发人员能够在 Node.js 中使用这样的代码：

```js
var bootstrap = require('bootstrap');
```

# 在 Node.js 中使用模块

让我们在 Node.js 中要求并使用一些模块：

1.  首先，我们将创建一个新目录。让我们称之为`module-practice`。让我们将 Git Bash 指向这个文件夹。

1.  一旦进入其中，让我们创建两个新文件。让我们将这些文件命名为`main.js`和`whatever.js`，如下所示：

```js
touch main.js whatever.js
```

1.  接下来，让我们按照以下步骤在 VS Code 中打开整个文件夹：

```js
code .
```

1.  现在，让我们向`whatever.js`添加一些代码如下：

```js
console.log('whatever');
```

这就是 JS 中代码的简单形式。

1.  现在让我们看看如何使它在我们的`main.js`文件中可用。我们只需要像下面这样要求`whatever.js`：

```js
let whatever = require('./whatever');
```

1.  现在它被要求了，我们可以使用它，所以让我们将`main.js`更新为这样：

```js
let whatever = require('./whatever');

whatever.returnWhatever();
```

1.  现在让我们用以下方式运行这段代码：

```js
node main.js
```

现在会发生的是，我们将在 Git Bash 中看到单词`whatever`被打印出来。

让我们进一步进行我们的实验。这是我们更新后的`whatever.js`：

```js
module.exports = {
    returnWhatever: function() {
        console.log('whatever');
    }
}
```

因此，我们需要更新`main.js`如下：

```js

whatever.returnWhatever();
```

正如我们已经看到的，`require`关键字导入了一个模块的代码，并使其在另一个文件中可用；在我们的例子中，就是`main.js`文件。

`exports`关键字让我们可以将代码提供给其他文件，但有一个注意事项。它还允许我们选择我们想要向其他文件提供的模块的哪些部分。正如我们所看到的，`module.exports`是一个对象。这个对象的内容在我们的`main.js`要求`whatever`模块时将被返回。这使我们能够仅暴露代码的某些部分，并且使模块接口的设置成为可能。换句话说，`module.exports`是使我们能够保持代码的部分私有的东西。考虑对`whatever.js`的这个更新：

```js
module.exports = {
    returnWhatever: function() {
        returnSomething();
    }
}

let returnSomething = () => {
    console.log('whatever');
}
```

我们不需要对`main.js`进行任何更改。如果我们从 Git Bash 运行它，仍然会在控制台输出单词`whatever`。但是我们已经使`whatever.js`的部分内容不直接可访问。

作为一个旁注，注意在前面的代码中，ES3 和 ES5 的函数语法一起使用。定义`returnSomething`函数的代码部分使用了更新的语法，这使我们能够在不使用`function`关键字的情况下编写函数定义。

# 模块捆绑器，一种在浏览器中使用模块的方法

不幸的是，你不能直接在浏览器中使用`require`关键字，正如我们刚才看到的那样。`require`关键字不是 JS 浏览器 API 的一部分。这里需要注意的是，Node.js 有能力读取和写入计算机文件系统。因此，如果你在项目中使用 Node.js 安装了任何 NPM 包，你就可以像之前解释的那样要求这样一个模块。

然而，浏览器中的 JS 无法访问你的操作系统文件系统，因此这给我们留下了一个难题：我们如何在浏览器中使用 JS 模块语法？

答案是：我们有一个工具可以做到这一点，它被称为**模块捆绑器**。

今天，在 2019 年，有许多不同的模块打包工具可用，比如 webpack（[`webpack.github.io/`](http://webpack.github.io/)）、FuseBox（[`fuse-box.org/`](https://fuse-box.org/)）、Parcel（[`parceljs.org/`](https://parceljs.org/)）、rollup.js（[`rollupjs.org/guide/en`](https://rollupjs.org/guide/en)）或 Browserify（[`browserify.org/`](http://browserify.org/)）。

什么是模块打包工具？以下是 Browserify 主页上的一句话，简洁地表达了它：

“Browserify 让你可以在浏览器中使用 require('modules')来捆绑所有你的依赖项。”

除了打包项目中通过模块所需的所有依赖项，模块打包工具还解决了循环依赖等问题；也就是说，它们使用算法来解析项目中所有依赖项应该在项目中捆绑的顺序。

我们几乎完成了对 JS 生态系统的概述。接下来，我们将看一种特定的模块打包工具，那就是 webpack。

一旦我们知道 webpack 究竟是什么，以及它在幕后是如何工作的，我们就能完全理解它在 Vue CLI 中的位置。

# 什么是 webpack？

Webpack 是 Web 的模块打包工具。有些人也把它称为 Web 应用程序的资产编译器。

根据 webpack 的 GitHub 页面：

“它将许多模块打包成少量的捆绑资产等等。模块可以是 CommonJs、AMD、ES6 模块、CSS、图片、JSON、CoffeeScript、LESS 等等，还有你自定义的东西。”

在本章的前面，标题为*在 Node.js 中使用模块*的部分中，我们只是浅尝辄止地介绍了模块在 Node 应用程序中的导出和引入。我们没有提到的是，我们可以使用各种不同的模块语法。正如前面提到的，Node.js 使用 CommonJS 模块语法。除了 CommonJS，还有**异步模块定义**（**AMD**）。除了 AMD，你还可以使用 ESM 模块。使用 ESM 模块时，语法与我们之前看到的有些不同。

让我们按照以下步骤使用 ESM 语法重写`whatever`模块，并在`main.js`中使用它：

1.  为了简化事情，让我们创建一个新的文件夹如下：

```js
mkdir es6-module-practice;
```

1.  让我们使用`cd`命令（*更改目录*命令）指向我们的 Git Bash 如下：

```js
cd es6-module-practice
```

1.  让我们按照以下方式添加我们的两个文件：

```js
touch whatever2.mjs main2.mjs
```

1.  现在，让我们按照以下方式打开我们的文件夹与 VS Code：

```js
code .
```

1.  接下来，让我们添加`main2.mjs`的代码如下：

```js
import returnWhatever from './whatever2';

returnWhatever();
```

1.  最后，让我们按照以下方式编写`whatever2.mjs`的代码：

```js
let returnWhatever = () => {
    returnSomething();
}

let returnSomething = () => {
    console.log('whatever');
}

export default returnWhatever;
```

1.  正如我们所看到的，我们需要将文件保存为 ESM 模块，使用`mjs`文件扩展名。Node.js 实验性地支持 ESM 模块，因此您需要在 Git Bash 中运行以下命令：

```js
node --experimental-modules main2.mjs
```

1.  运行上述命令后，您将在控制台中看到以下输出：

```js
(node:12528) ExperimentalWarning: The ESM module loader is experimental.
whatever
```

正如我们所看到的，除了在控制台中收到预期的输出之外，我们还收到了`ExperimentalWarning`消息。希望这个演示两种不同模块语法的示例能帮助我们理解 webpack 将为我们做什么。除其他事项外，它将*平衡竞争环境*，这样我们就可以在项目中使用各种标准和非标准的模块工作方式。

基本上，webpack 所做的是，它接受具有依赖项的模块（包括我们项目的资产，如`.png`、`.jpeg`和`.scss`文件），并输出静态资产（`.js`、`.css`和`.image`文件）。

# webpack 的工作原理

我们已经看到了如何使用 CommonJS 和 ESM 模块语法。再次强调，CommonJS 是 Node.js 模块使用的语法。这意味着 Node.js 模块中的所有依赖项都是使用`require`命令描述的。与此相反，webpack 模块的依赖项可以用各种语法描述。例如，如果您的模块依赖于一个 SCSS 部分，您将使用`@import`语句。如果您正在导入 AMD 模块的依赖项，您将使用其自己的`require`和`define`语法。

这意味着，基本上*webpack 模块接受导入各种依赖项的不同语法*。甚至`src`属性（用于`img` HTML 元素）也被视为 webpack 模块的依赖项。

# 构建一个新项目并在其上运行 webpack

现在，让我们通过以下步骤构建一个项目并将 webpack 捆绑到我们的工作流程中：

1.  让我们添加一个新目录。让我们运行一个不存在的命令，如下所示：

```js
new-project-with-webpack
```

控制台将返回以下内容：

```js
bash: new-project-with-webpack: command not found
```

1.  太棒了！现在，让我们使用*重复上一条命令*的快捷方式，双感叹号，如下所示：

```js
mkdir !! && cd !!
```

运行上述命令将创建我们的`new-project-with-webpack`文件夹，并将`cd`进入这个新目录。双和符号命令(`&&`)只是一种运行多个命令的方式，而不是一个接一个地输入它们。双感叹号命令(`!!`)表示*重复上一行*，所以上述命令实际上意味着以下内容：

```js
mkdir new-project-with-webpack && cd new-project-with-webpack
```

1.  接下来，让我们添加我们的`package.json`，并接受所有默认值（使用`-y`标志）如下：

```js
npm init -y
```

1.  让我们按以下步骤检查我们在 VS Code 中的文件夹内容：

```js
code .
```

1.  一旦 VS Code 在我们的屏幕上运行，我们可以双击`package.json`文件并验证其内容如下：

```js
{
  "name": "new-project-with-webpack",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "keywords": [],
  "author": "",
  "license": "ISC"
}

```

1.  现在，让我们按照以下步骤将 webpack 添加到我们的项目中：

```js
npm install --save-dev webpack webpack-cli --verbose
```

1.  完成后，让我们回到 VS Code 并再次审查我们的`package.json`如下：

```js
{
  "name": "new-project-with-webpack",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "keywords": [],
  "author": "",
  "license": "ISC",
  "devDependencies": {
    "webpack": "⁴.29.5",
    "webpack-cli": "³.2.3"
  }
}
```

正如我们所看到的，一个新的键已经被添加：`devDependencies`。在其中，我们有`webpack`和`webpack-cli`开发依赖。这些`devDependencies`是你在构建项目时才会使用的依赖项，而 webpack 就是这样一个依赖的完美例子：你在生产环境中不需要 webpack。这就是为什么我们在通过 NPM 安装 webpack 时使用了`--save-dev`标志。

查看我们项目的文件结构，我们现在可以看到以下内容：

```js
node_modules/
package.json
package-lock.json
```

如果你打开`node_modules`文件夹，你会看到里面有 300 多个文件夹。这个庞大的依赖列表以一个`.bin`文件夹开始。与我们之前的一个例子`vue-from-npm`相比，其中`node_modules`文件夹内只有四个子文件夹，尽管我们安装了`vue`和`accounting-js`两个 NPM 包。还要注意的是，在`vue-from-npm`文件夹内，没有`.bin`文件夹。无论你在运行`npm install`时使用`--save`还是`--save-dev`标志，情况都是如此。虽然这对于更有经验的开发人员可能是显而易见的，但对于那些在 Node.js 和 NPM 生态系统方面经验不足的开发人员来说，更好地理解这一点可能是很重要的。

那么，这个`.bin`文件夹是什么？它只是存储了你使用`npm install`安装的 Node 模块的编译后的本地二进制文件（即可执行文件）。并非所有的 NPM 模块都有这些编译后的本地二进制文件，这就是为什么你不会总是在`node_modules`文件夹内看到`.bin`文件夹的原因。在这个`.bin`文件夹内，有许多不同的 Node 模块。这些对于 webpack 正常工作都是必要的。

回到我们的项目，现在让我们向其中添加两个文件：`index.js`和`whatever.js`，如下所示：

```js
touch index.js whatever.js
```

目前，我们不会向这些文件中添加任何代码。现在，我们将专注于在我们的项目中运行 webpack。

# 在一个项目上运行 webpack

回到我们的`new-project-with-webpack`文件夹，再次检查`package.json`的内容，重点关注`scripts`键如下：

```js
"scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
},
```

在 Git Bash 中使用以下命令运行`test`脚本：

```js
npm run test
```

这将抛出一个带有`exit code 1`的错误。

让我们对它做一些更改，如下所示：

```js
"scripts": {
    "test": "echo \"You haven't specified any tests\""
},
```

让我们再次用`npm run test`来运行测试。这次控制台的输出不会那么可怕，因为我们删除了`exit 1`命令，并且改变了运行`test`命令时会被回显的内容。

让我们尝试完全不同的东西，如下所示：

```js
"scripts": {
    "test": "node index.js"
},
```

现在，我们不会得到错误，因为我们的`index.js`是空的。让我们添加一些内容，如下所示：

```js
// add up 2 numbers
console.log(2+2)
```

保存对`index.js`的更改，再次运行`npm run test`，这次在 Git Bash 中的输出将会打印出数字`4`。

这告诉我们什么？它告诉我们我们完全控制我们的脚本将要做什么！所以，最初我们有一个名为 test 的脚本。这个脚本会回显一条消息，并抛出一个带有`exit code 1`的错误。

就像我们可以给我们的脚本任意的键名，比如`test`，我们也可以给它们任意的值。当然，`console.log(2+2)`是一个愚蠢的值给一个脚本键。我们可以给我们的脚本键更好的值，例如：

```js
  "scripts": {
    "webpack": "webpack"
  },
```

现在，当我们用 webpack 的值运行一个 NPM 脚本时，这个脚本将运行 webpack 可执行文件。让我们试一下，如下所示：

```js
npm run webpack
```

这会返回一个错误，但在所有被记录下来的信息中，以下两行是最重要的：

```js
Insufficient number of arguments or no entry found.
Alternatively, run 'webpack(-cli) --help' for usage info.
```

我们得到这个错误的原因是因为 webpack 在寻找入口点来启动。默认情况下，这个入口点被设置为`./src/index.js`。所以，让我们添加这个`src`文件夹，并将我们的`index.js`移动到其中，如下所示：

```js
mkdir src && mv index.js $_
```

现在，让我们再次从命令行运行 webpack，如下所示：

```js
npm run webpack
```

这次我们会得到一个更好的输出。然而，默认情况下 Git Bash 没有语法高亮。这可以很快解决。因为我们已经在使用 VS Code，只需键入*Ctrl* + *~*的快捷键。如果你对这个符号不熟悉，它叫做*tilde*，位于*Esc*键下方，*Tab*键上方。按下这个快捷键将在 VS Code 中打开一个终端窗口，如果你再次执行`npm run webpack`命令，你会得到格式良好且带有颜色高亮的输出，就像这样：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/3d6cb640-cf6b-4d45-8781-a79d20bdb165.png)

图 2.1：在 VS Code 中将信息记录到控制台的 webpack 作为一个侧面说明，你的屏幕颜色可能会有所不同，这取决于你在 VS Code 中使用的颜色方案。要访问颜色主题，请使用以下键盘快捷键：*Ctrl + K* *Ctrl + T*。

查看控制台输出的消息，我们可以看到它可以分为两部分：实际信息（哈希、版本、时间、构建时间、入口点等）和警告。警告显示我们没有设置`mode`选项。

如果未设置，`mode`选项默认为生产模式。但是，我们也可以将其设置为`development`，这对于更快的构建进行了优化。这意味着我们可以在`package.json`的`scripts`部分中添加另一个脚本，然后可以用于项目的开发构建。这是更新后的`scripts`部分：

```js
"scripts": {
    "webpack": "webpack",
    "dev": "webpack --mode=development"
},
```

现在，我们可以使用以下命令在 webpack 中运行开发模式：

```js
npm run dev
```

这是控制台中的完整输出：

```js
Hash: 86c0da41f48381d9bd70
Version: webpack 4.29.5
Time: 108ms
Built at: 2019-02-27 12:23:30
 Asset Size Chunks Chunk Names
main.js 3.81 KiB main [emitted] main
Entrypoint main = main.js
[./src/index.js] 38 bytes {main} [built]
```

我们可以看到，webpack 在开发模式下花了`108ms`来打包我的项目。当我在生产模式下运行它（在我的设置中默认的`npm run webpack`命令），它花了`447ms`。

运行这个命令时实际上发生了什么？webpack 在后台做了什么？它构建了所有模块依赖的依赖图。回到本章前面的比喻，就好像我们给了它一堆电视剧的剧集，录在一堆蓝光光盘上，它把它们全部拿来并正确地排列起来。Webpack 找出了每个模块的正确位置，然后将它们捆绑起来并提供给`dist`文件夹。如果再次查看项目的文件结构，你会发现有一个新的添加：`dist`文件夹。如果我们检查`dist`文件夹的内容，我们会看到：

```js
./dist/
   |- main.js
```

如果我们检查`main.js`文件，我们会看到 webpack 添加了很多东西。即使在像我们这样的小项目上，输出也会有大约 100 行长。

我们的`main.js`文件的前几行如下：

```js
/******/ (function(modules) { // webpackBootstrap
/******/ // The module cache
/******/ var installedModules = {};
...
```

让我们再次运行`npm run webpack`命令，看看它如何影响`main.js`中的输出。

如果我们检查`main.js`，我们会看到现在只有一行代码，以以下内容开头：

```js
!function(e){var t={};function n(r){if(t[r])return t[r].exports;var ...
```

这意味着当以生产模式运行时，webpack 会对我们的代码进行混淆和缩小。

显然，这也会影响文件大小。在开发模式下，打包的`main.js`文件大小为 3.81 KB，而在生产模式下，它只有 944 字节。

最后，为了避免看到警告消息，我们可以将`package.json`中的脚本条目更新为：

```js
"scripts": {
    "webpack": "webpack --mode=production",
    "dev": "webpack --mode=development"
},
```

在这一点上，我们可以开始使用 webpack 与 Vue。但是，我们不会使用 Vue CLI。相反，我们将看到如何手动设置所有内容。这不是做事情的最佳方式，但它将帮助我们更好地理解为什么在 Vue 生态系统中会这样做。

# 通过 NPM 添加一个 Vue 项目并使用 webpack

在这一部分，我们将使用 NPM 构建一个新项目，然后将 webpack 添加到其中，并最终添加一个 Vue 单文件组件。

首先，让我们按照以下步骤新建一个目录。我们将我们的项目命名为`npm-vue-webpack`：

1.  打开 Git Bash 并按照以下方式添加一个新文件夹：

```js
mkdir npm-vue-webpack && cd $_
```

1.  按照以下方式初始化`npm`：

```js
npm init -y
```

1.  接下来，按照以下步骤将 Vue 和 webpack 安装到我们的新项目中：

```js
npm install vue webpack webpack-cli --save-dev --verbose
```

一旦 NPM 安装完成，我们可以像在本章前面那样验证`package.json`的文件夹和内容。

1.  接下来，按照以下方式添加我们的项目将使用的源文件夹和输出文件夹：

```js
mkdir dist src
```

1.  按照以下步骤打开我们的新项目在 VS Code 中：

```js
code .
```

现在，我们可以直接从 VS Code 编辑器中添加两个新文件。我们将第一个文件命名为`source.js`，第二个文件命名为`output.js`。确保在此阶段将这两个空文件添加并保存到您的项目中：`source.js`在`src`文件夹中，`output.js`在`dist`文件夹中。

# 将我们的 Vue 组件添加为 JavaScript 模块

现在让我们添加我们的 Vue 组件：

1.  接下来，让我们按照以下方式将这段代码添加到`source.js`中：

```js
import CustomArticle from './CustomArticle.js';

new Vue({
    el: '#app',
    render: h => h(CustomArticle),
})
```

1.  在第一行，我们正在导入一个名为`CustomArticle.js`的文件。

1.  让我们在`src`文件夹内新建一个文件。我们将这个文件命名为`CustomArticle.js`。

1.  并将以下代码添加到其中：

```js
let CustomArticle = Vue.component('custom-article', {
    template: `
      <article>
        Our own custom article component!
      </article>`
  })

export default CustomArticle;
```

我们可以看到，我们正在使用 ESM 语法来导出和导入 JS 模块。

# 使用 webpack 编译 JavaScript 模块

现在我们几乎可以准备好使用 webpack 将我们的`source.js`编译为`output.js`了。但在这之前，我们仍然需要按照以下方式更新我们的`package.json`中的`scripts`部分：

```js
"scripts": {
    "webpack": "webpack"
},
```

现在，我们可以在 Git Bash 中运行以下命令：

```js
npm run webpack ./src/source.js ./dist/output.js
```

正如预期的那样，我们在控制台中看到了输出，以及关于设置模式选项的警告。我们现在知道这意味着什么，所以在这个时候处理它并不重要。

如果我们检查`output.js`的内容，我们会发现它是空的，并且默认情况下，webpack 会将我们的输出代码压缩和混淆到默认的`main.js`文件中，具体如下：

```js
!function(e){var t={};function n(r){if(t[r])return t[r].exports;var o=t[r]={i ...
```

那么，我们如何让 webpack 输出到一个不同的文件，而不是默认的`main.js`？我们使用 webpack 配置文件！

# 通过 webpack 配置文件添加选项

使用 webpack 配置文件，我们可以添加各种选项来打包我们的应用程序。具体如下：

1.  在项目的根目录添加一个新文件。我们将这个文件命名为`webpack.config.js`。代码如下：

```js
module.exports = {
  output: {
    filename: 'output.js',
  }
};
```

1.  现在，再次运行我们的命令如下：

```js
npm run webpack ./src/source.js ./dist/output.js
```

这次它输出到了正确的文件。

1.  就像我们可以指定输出文件一样，我们也可以指定输入文件如下：

```js
module.exports = {
 entry: './src/source.js',
 output: {
 filename: 'output.js',
 }
};
```

我们仍然需要在屏幕上的某个位置渲染我们的 Vue 组件。我们需要一个 HTML 文件来实现这一点。

# 添加一个 HTML 文件，以便渲染我们的 Vue 组件

让我们在`dist`文件夹中添加一个新的 HTML 文件，我们将其命名为`index.html`，具体如下：

```js
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Compiled HTML file</title>
</head>
<body>
    <div id="entryPoint"></div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/vue/2.5.13/vue.min.js"></script>
    <script src="output.js"></script>
</body>
</html>
```

就像我们在本章开头讨论的那样，我们以*老派*的方式直接向 HTML 中添加脚本，只需在 HTML 文件底部堆叠`script`标签。我们使用的第一个`script`标签是从 CDN 获取 Vue，第二个`script`标签从`dist`文件夹中获取我们的`output.js`文件。

如果你使用 VS Code，现在可以右键单击新的`dist/index.html`文件，然后单击“在默认浏览器中打开”命令。

在打开的网页上会看到以下句子：

我们自己的自定义文章组件！

现在，我们需要让 webpack 能够输出 HTML 文件。为此，我们需要使用`html-webpack-plugin`。

# 赋予 webpack 输出 HTML 文件的能力

在本节中，我们将看到如何使用 webpack 插件输出 HTML 文件，具体步骤如下：

1.  通过 NPM 安装`html-webpack-plugin`如下：

```js
npm install html-webpack-plugin --save-dev --verbose
```

1.  我们的`package.json`的`devDependencies`已相应更新如下：

```js
"devDependencies": {
    "html-webpack-plugin": "³.2.0",
    "vue": "².6.7",
    "webpack": "⁴.29.5",
    "webpack-cli": "³.2.3"
}
```

1.  现在，按照以下步骤更新我们的`webpack.config.js`：

```js
let HtmlWebpackPlugin = require('html-webpack-plugin');

module.exports = {
    entry: './src/source.js',
    output: {
        filename: 'output.js',
    },
    plugins: [new HtmlWebpackPlugin()]
};
```

1.  在继续之前，删除`dist`文件夹中的`index.html`文件。不过不用担心删除它，因为 webpack 很快就会重新创建它。

1.  接下来，再次运行 webpack 脚本如下：

```js
npm run webpack
```

Webpack 刚刚为我们创建了一个新的`index.html`文件！文件内容如下：

```js
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <title>Webpack App</title>
  </head>
  <body>
  <script type="text/javascript" src="output.js"></script></body>
</html>
```

这都很好，但显然，我们的文件不一样了。我们丢失了 Vue 组件的入口点。此外，我们需要更新我们的 Vue 代码，使其作为单文件组件工作。

# 将.vue 文件作为 JavaScript 模块添加

首先，让我们更新`source.js`文件，如下所示：

```js
import Vue from 'vue';
import CustomArticle from './CustomArticle.vue';

new Vue({
    el: '#entryPoint',
    render: h => h(CustomArticle),
})
```

现在我们还可以将`CustomArticle.js`重命名为`CustomArticle.vue`，并向其中添加以下代码：

```js
<template>
  <div id="entryPoint">
      <article>
        Our own custom article component!
      </article>
  </div>
</template>
```

不幸的是，webpack 不能直接处理`.vue`文件。为了解决目前的问题，我们需要使用**webpack 加载器**。webpack 加载器帮助 webpack 理解它正在处理的文件。有许多加载器，但现在我们需要使用 Vue。

# 添加 webpack 加载器以处理.vue 文件

要处理`.vue`文件，请按以下步骤进行：

1.  通过 NPM 安装名为`vue-loader`的 webpack 加载器，如下所示：

```js
npm install vue-loader --save-dev --verbose
```

1.  现在我们已经保存了它，我们需要使用它，我们将通过更新 webpack 配置来做到这一点：

```js
let HtmlWebpackPlugin = require('html-webpack-plugin');
let VueLoaderPlugin = require('vue-loader/lib/plugin');

module.exports = {
    entry: './src/source.js',
    output: {
        filename: 'output.js',
    },
    plugins: [
        new HtmlWebpackPlugin(),
        new VueLoaderPlugin(), 
    ]
};
```

1.  现在尝试运行 webpack，如下所示。剧透警告：它会失败：

```js
npm run webpack
```

我们得到的错误消息如下：

```js
Error: [VueLoaderPlugin Error] No matching rule for .vue files found.
```

1.  要修复此错误，我们需要为我们的 Vue 加载器添加一个规则，通过更新我们的`webpack.config.js`文件如下：

```js
let HtmlWebpackPlugin = require('html-webpack-plugin');
let VueLoaderPlugin = require('vue-loader/lib/plugin');

module.exports = {
    entry: './src/source.js',
    output: {
        filename: 'output.js',
    },
    module: {
        rules: [
            { test: /\.vue$/, use: 'vue-loader' }
        ]
    },
    plugins: [
        new HtmlWebpackPlugin(),
        new VueLoaderPlugin(), 
    ]
};
```

`rules`选项中数组内的`test`键接收一个正则表达式作为值。这个正则表达式检查是否存在一个带有`vue`文件扩展名的文件。如果匹配，也就是说，如果找到了一个`vue`文件，它将在其上使用`vue-loader`模块。

1.  让我们再次运行我们的 webpack 脚本，如下所示：

```js
npm run webpack
```

这将抛出另一个错误，如下所示：

```js
ERROR in ./src/CustomArticle.vue
Module Error (from ./node_modules/vue-loader/lib/index.js):
[vue-loader] vue-template-compiler must be installed as a peer dependency, or a compatible compiler implementation must be passed via options
```

1.  控制台中记录了更多错误，但我们需要通过添加另一个 NPM 包来解决这个。

```js
npm install vue-template-compiler --save-dev --verbose
```

`package.json`中的`devDependencies`条目刚刚又更新了，如下所示：

```js
  "devDependencies": {
    "html-webpack-plugin": "³.2.0",
    "vue": "².6.7",
    "vue-loader": "¹⁵.6.4",
    "vue-template-compiler": "².6.7",
    "webpack": "⁴.29.5",
    "webpack-cli": "³.2.3"
  }
```

所以，现在我们可以再次运行 webpack，如下所示：

```js
npm run webpack
```

在 webpack 运行后，如果此时打开`output.js`，你会看到它里面有完整的 Vue 库，以及我们的`CustomArticle`在最后。所有这些都没有任何错误编译。

# 修复我们的 index.html 文件的问题

我们仍然有`dist`文件夹中的`index.html`文件的问题。这很容易解决！我们只需在`src`文件夹中添加我们自己的`index.html`文件，内容如下：

```js
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Compiled HTML file</title>
</head>
<body>
    <div id="entryPoint"></div>
</body>
</html>
```

请注意，我们现在已经删除了自己的`script`标签，因为 webpack 将添加它们。另外，请确保删除`dist`文件夹中的`index.html`文件。现在，再次运行`npm run webpack`命令，你将在`dist/index.html`中得到以下输出：

```js
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <title>Webpack App</title>
  </head>
  <body>
  <script type="text/javascript" src="output.js"></script></body>
</html>
```

为什么这不起作用？

它不起作用，因为我们需要更新要输出的 JS 文件以及 HTML 文件。目前，我们只更新 JS 文件，但我们仍然需要为我们的`index.html`文件做同样的操作。幸运的是，我们已经有`html-webpack-plugin`来帮忙。

# 通过 html-webpack-plugin 使用 webpack 传递 HTML 文件

我们将首先更新`webpack.config.js`文件中的`html-webpack-plugin`如下：

```js
plugins: [
    new HtmlWebpackPlugin({
        template: './src/index.html',
    }),
        new VueLoaderPlugin(), 
]
```

在插件部分所做的是，我们向`HtmlWebpackPlugin()`调用传递了一个`options`对象。在这个`options`对象内部，我们指定了我们的模板：`./src/index.html`。

在我们再次运行 webpack 脚本之前，我们需要确保添加`meta`标签，并将`charset`设置为`utf-8`。否则，当我们在浏览器中打开`dist/index.html`时，我们将在控制台中收到错误。

现在让我们再次运行`npm run webpack`。这次，一切都正常！我们在屏幕上得到了我们看起来很简单的句子：

我们自己的自定义文章组件！

恭喜！虽然它看起来很简单，但您已成功将一个 Vue 应用程序添加到了运行在 webpack 上的 NPM 项目中。

接下来，我们将学习 HMR 以及它如何在 Vue 开发中帮助我们。

# 了解 Vue 中的热模块替换

HMR 在过去几年已经成为了一个热门词汇。这有什么了不起的？在本节中，我们将讨论 HMR 的工作原理。

为了做到这一点，我们将构建另一个默认的简单应用程序，就像我们在第一章中所做的那样，*介绍 Vue CLI 3*：

```js
vue create -d second-default-app
```

过一会儿，一旦完成，我们将按以下方式进入我们应用程序的目录：

```js
cd second-default-app
```

让我们按以下方式在 VS Code 中打开项目文件夹：

```js
code .
```

现在，我们可以看到整个`second-default-project`的内容。

现在，我们可以按以下方式提供应用程序：

```js
npm run serve
```

当然，我们的应用程序现在正在浏览器中提供。

要查看您的应用程序，请在浏览器中访问`localhost:8080`。

让我们实时查看 HMR 更新。

# 观察 HMR 更新

在浏览器窗口处于活动状态时，让我们按下*F12*键打开开发者工具。还要确保我们的元素面板是开发工具内的活动选项卡，这样我们就可以看到**文档对象模型**（**DOM**）结构，就像在浏览器中放大的截图中一样：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/555e8cdc-a628-43eb-870d-45c51239a104.png)

图 2.2：打开开发工具中元素面板的 second-default-app 的欢迎屏幕

现在，让我们看看 HMR 的实际效果。理想情况下，要看到这一点，您需要使用两个监视器。因此，您可以将 VS Code 窗口移动到左侧监视器，将为应用程序提供的浏览器移动到右侧监视器。或者，您可以使用单个监视器并将两个应用程序并排查看（每个应用程序占据屏幕宽度的一半）。这个练习的重点是能够同时看到您的 VS Code 窗口、Vue 应用程序浏览器窗口和浏览器开发工具中的 Elements 面板。

接下来，在 VS Code 中打开项目的`src`文件夹中的`App.vue`文件。查看第 4 行，目前的内容如下：

```js
<HelloWorld msg="Welcome to Your Vue.js App"/>
```

我们很快就会将该行更改为其他内容。在更改该行之前，请注意这些更改如何在为您提供应用程序的浏览器中反映。浏览器会刷新吗？

现在，您专注于跟踪浏览器中的更改，让我们按照以下方式更新`App.vue`中的第 4 行：

```js
<HelloWorld msg="HMR is cool"/>
```

在保存`App.vue`中的更改时，请注意浏览器。最好的方法是让 VS Code 处于焦点状态，但要观察浏览器窗口，特别是 Elements 面板。将 VS Code 置于焦点状态，您可以使用快捷键*Ctrl* + *S*保存更改。

如果您仔细观察，并且正在使用 Chrome 浏览器，您会注意到 Elements 面板内出现了一道紫色的闪光。这是 Chrome 浏览器通知我们 Vue 应用程序的 DOM 发生了变化。如果您仔细观察，您会注意到`head`元素上有一道闪光，以及`h1`元素和其子文本节点`HMR is cool`上也有一道闪光。

您可能会注意到浏览器没有刷新。无论是 webpack、我们的应用代码还是我们自己都没有强制浏览器刷新。这里的结论是什么？Webpack 实际上并没有使用 HMR 强制刷新页面！相反，它只是注入了 HMR。

虽然`h1`元素的更改是显而易见的（因为它是我们更改`App.vue`文件中文本的直接可见结果），但在`head`元素中发生的更新既更加隐晦又更有帮助。为了看到发生了什么，让我们点击 Elements 面板中`head`标签左侧的小黑三角形展开 head 标签，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/495be8e0-9fbb-415a-ac5e-e73a101235f3.png)

图 2.3：在开发工具中的 Elements 面板中展开 head 标签

接下来，我们需要滚动到最后的`</head>`标签。在它的上方，会有一个类似于这样的`script`标签：

```js
<script charset="utf-8" src="/app.c7e7b2f6599f49948328.hot-update.js"></script>
```

当我们对`App.vue`进行另一个更改时，让我们密切关注元素面板中 DOM 树的这一部分。让我们将第 4 行的`msg`属性更新为这样：

```js
<HelloWorld msg="HMR is cool indeed"/>
```

如果你观察了`script`标签，你会注意到它的变化如下：

```js
<script charset="utf-8" src="/app.417e697f270d544a21b3.hot-update.js"></script>
```

你有没有注意到 Vue 在闭合的`</head>`标签上面注入了另一个脚本？那个注入的脚本就是 HMR 在那里发挥作用。

让我们检查附加的脚本文件的第一行，如下所示：

```js
webpackHotUpdate("app",{
```

整个过程是如何工作的呢？Webpack 简单地运行我们的更改，捆绑了我们应用程序的更新，并且，由于它已经在运行，使用 Vue 加载器注入了新的代码。

所以，正如我们刚才看到的，HMR 只是 webpack 的一个功能，帮助我们更顺畅地进行操作，而不需要担心刷新我们的应用程序。

# 摘要

在本章中，我们讨论了 JS 语言及其生态系统的演变，以及这种演变如何导致模块捆绑器的出现。我们还看了 webpack，这是 Vue CLI 3 的首选模块捆绑器。

我们看了如何插入一个非常基本的 Vue 应用程序，运行在单文件 Vue 模板上。除了这个小项目，我们还看了一些重要的 webpack 概念。我们通过观察 Vue 项目上的 HMR 来结束了本章。

现在我们知道了 webpack 的基本工作原理，在接下来的章节中，我们将讨论一些其他相关技术，并且在 webpack 和 Vue CLI 3 的知识基础上进行深入。我们将密切关注的下一个主题是 Babel。


# 第三章：Vue CLI 3 中的 Babel

在本章中，我们将使用 Babel 将**JavaScript**（**JS**）的新功能带到浏览器中，使其在浏览器能够理解之前将其转换为旧版本的 JS。我们将讨论以下内容：

+   理解 Babel

+   使用 ES5 和 ES6 运行 webpack

+   更新我们的 webpack 配置以适配 Babel

+   Vue，Babel 和 JSX

+   手动添加 Babel 插件

让我们首先看看 Babel 解决了什么问题。

# 理解 Babel

正如我们在之前的章节中已经看到的，一旦使用 Vue CLI 构建了默认的 Vue 应用程序，您可以使用`npm run serve`来提供它。

您的应用程序通常会在`localhost:8080`上提供。查看默认内容的服务页面时，您会注意到在已安装的 CLI 插件标题下列出了两个插件：`babel`和`eslint`。

为什么这两个插件会预先安装在默认应用程序中呢？显然，Vue 框架团队正在努力遵循最佳实践，并与构建 Web 应用程序的现代方法保持最新。使用 Babel 就是其中之一。

如果您访问 Babel 网站，您会看到以下关于它的定义：

“Babel 是一个主要用于将 ECMAScript 2015+代码转换为当前和旧版浏览器或环境中的 JS 的向后兼容版本的工具链。”

那么，我们如何使用 Vue CLI Babel 插件？以及获取有关它的更多信息的最简单方法是什么？

由于我们已经使用 Vue CLI 创建了默认的 Vue 应用程序，并且已经了解了 Vue CLI 的 UI，我们可以通过打开 Git Bash 并启动 Vue CLI UI 轻松地访问官方文档：

```js
vue ui
```

正如我们在第一章中所看到的，*介绍 Vue CLI 3*，这个命令将使 webpack 在浏览器中为我们最新的项目仪表板提供服务。在那里，我们可以点击插件图标，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/6041d666-2d4e-4056-b36c-5db5021024cb.png)

一旦您点击了已安装的插件链接，您将看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/f6d4909a-8125-4c75-9cc1-3559a4cff885.png)

此应用程序列出了三个默认安装的插件：*@vue/cli-service*，*@vue/cli-plugin-babel*和*@vue/cli-plugin-eslint*。为了更容易理解，其他插件已被灰掉，并且在截图中添加了编号框：

1.  更多信息链接到`cli-plugin-babel`的 GitHub 存储库

1.  更新`@vue/cli-plugin-babel`

1.  带有主页图标的按钮是指向 Vue UI 项目管理器的链接，列出了所有可用的项目。

1.  UI 的这一部分显示了您的操作系统中当前 Vue 项目的位置

1.  单击此处可让您切换 Vue UI 的日志开关

1.  正如我们之前所看到的，这使您可以在 Vue UI 的两种颜色变化之间切换

1.  报告错误图标将带您到 Vue-CLI 错误报告网页。

1.  如果您有兴趣翻译 UI，此按钮链接到 UI 本地化页面

1.  此图标仅刷新插件的 API

如果您需要使用流行的**vuex**或**vue-router**插件，您可以简单地点击插件页面顶部的相应按钮来安装它们。

在“添加 vuex”和“添加 vue-router”按钮右侧的搜索输入框可让您过滤已安装的插件，“添加插件”按钮将带您转到`localhost:8000/plugins/add`屏幕，您可以从多个插件中进行选择，例如`@vue/cli-plugin-unit-jest`，`@vue/cli-plugin-typescript`，`@vue/cli-plugin-pwa`等。这里有大量的插件可供选择，我们将在后面的章节中更详细地了解它。

在下一节中，我们将讨论`cli-plugin-babel`的所有功能。

# @vue/cli-plugin-babel 的构建模块

`@vue/cli-plugin-babel`默认提供了几个部分。这些是 Babel 7、babel-loader 和`@vue/cli-plugin-babel`。

# @vue/cli-plugin-babel 中的 Babel 7

这就是 Babel 解决的问题。

假设您正在开发您的 Web 应用的前端，并且正在使用 JS 语言的更现代的 ES6+语法。一旦您的应用程序完成，并发布到互联网上，您的一些用户在 Internet Explorer 上运行您的 Web 应用程序。与您的 Web 应用程序的其他用户相反，他们可以顺利运行您的应用程序，Internet Explorer 用户将收到语法错误。

Babel 就是对这样的问题的答案。它*平衡了竞争环境*：它允许开发人员将他们的 JS 浏览器兼容性问题外包给 Babel。他们不必再担心和迎合旧版浏览器，他们可以简单地使用语言的最新功能来编写他们的 JS 代码，甚至在任何浏览器完全支持之前。然后，Babel 负责将此代码转换为旧的 JS 方言，这是旧版浏览器可以理解的。

`@vue/cli-plugin-babel`运行在 Babel 7 上，Babel 7 于 2018 年 8 月 27 日发布。Babel 6 和 Babel 7 之间相差三年，这一迭代带来了一系列改进。Vue CLI 支持如此近期的更新是其团队致力于尽可能跟上时代的又一个证明。

# `@vue/cli-plugin-babel`中 babel-loader 的作用

正如我们在前一章中看到的，Vue CLI 运行在 webpack 4 上。

为了能够使用 Babel 7，`@vue/cli-plugin-babel`使用 babel-loader，可以在这里找到：[`github.com/babel/babel-loader`](https://github.com/babel/babel-loader)。

如前一章所述，使用 webpack 加载器，我们可以预处理和捆绑一堆不同的资源，不仅仅是常规 JS，而是几乎任何其他静态资源。

具体来说，`babel-loader`接收 ES6+ JS，并将其转换为 ES5 JS。这个过程通常被称为**转译**。因此，`@vue/cli-plugin-babel`中 babel-loader 的作用是将我们的 ES6+代码转译为 ES5。

# `@vue/babel-preset-app`的作用

`@vue/cli-plugin-babel`还有更多功能。它包括`@vue/babel-preset-app`，其唯一目的是在通过 Vue CLI 生成的项目中使用。在不深入讨论`@vue/babel-preset-app`的工作原理的情况下，我们可以列出其主要功能：

+   它使用`browserslist`来查看您的浏览器目标

+   它自动应用所需的转换和填充（借助`@babel/preset-env`实现）

+   它增加了对 Vue JSX 的支持

+   它阻止在构建过程中将所有文件中的辅助程序内联

除了之前列出的功能之外，`@vue/cli-plugin-babel` 还有其他功能，我们将在下一节中讨论它们。

# `@vue/cli-plugin-babel`的其他功能

除了前一节中列出的默认设置，`@vue/cli-plugin-babel`也是可扩展的。我们可以使用`babel.config.js`添加其他 Babel 预设和插件。

它使用了一些 webpack 加载器来执行另外两个主要任务：缓存（借助 cache-loader 的帮助）和利用多核处理器（借助 thread-loader 的帮助）。这被称为**并行化**。

在下一节中，类似于我们在第二章中所做的，*Vue CLI 3 中的 Webpack*，我们将介绍在 Vue 中设置 Babel 而不使用 CLI。之后，我们将看看 CLI 如何使事情变得更容易，以及如何进一步扩展。

# 在 Vue 2 中使用 Babel 和 webpack 而不使用 Vue CLI

让我们将我们的新项目命名为`npm-vue-babel-webpack`。我们将打开 Git Bash，添加此项目的文件夹，并`cd`进入其中：

```js
mkdir npm-vue-babel-webpack && cd $_
```

我们将初始化 NPM 并接受所有默认设置：

```js
npm init -y
```

在第二章中，*Vue CLI 3 中的 Webpack*，我们逐个安装了 NPM 包，解释了每个包的作用，并在此过程中修复了任何错误。这使我们对 webpack 的构建模块和 Vue 与 webpack 的配合方式有了深入的了解。为了避免不必要的重复，这次我们将一次性安装所有内容。

# 安装必要的 NPM 包

安装必要的 NPM 包：

```js
npm install vue webpack webpack-cli html-webpack-plugin vue-loader vue-template-compiler --save-dev --verbose
```

现在将`src`和`dist`文件夹添加到我们的项目中，并在 VS Code 中打开我们的项目：

```js
mkdir dist src && code .
```

随时在 VS Code 中检查`package.json`的内容，以确认所有 NPM 包确实已安装。

让我们在`src`文件夹内创建三个新文件，具体为`main.js`、`App.vue`和`index.html`，几乎与我们在第二章中所做的一样，*Vue CLI 3 中的 Webpack*。

以下是要添加到`index.html`中的代码：

```js
<!DOCTYPE html>
<html lang="en">
<head>
   <meta charset="utf-8">
    <title>Compiled HTML file</title>
</head>
<body>
    <div id="entryPoint"></div>
</body>
</html>
```

以下是`main.js`的内容：

```js
import Vue from 'vue';
import App from './App.vue';

new Vue({
    el: '#entryPoint',
    render: h => h(App),
})
```

最后，这是`App.vue`的内容：

```js
<template>
  <div id="entryPoint">
      <article>
        Our own custom article component!
      </article>
      <AnotherComponent />
  </div>
</template>

<script>
import AnotherComponent from './components/AnotherComponent.vue';

export default {
    name: 'entryPoint',
    components: {
        AnotherComponent
    }
}
</script>
```

请注意，在上述`script`标签内部，我们正在从`components`文件夹中导入`AnotherComponent`。

因此，让我们在项目的`src`文件夹内添加一个`components`文件夹。在`components`文件夹内，我们将添加一个新文件并将其命名为`AnotherComponent.vue`。

接下来，将此代码添加到`AnotherComponent.vue`中：

```js
<template>
  <p>
    This is another component.
    <button v-on:click="alertTime">What's the time?</button>
  </p>
</template>

<script>
export default {
  name: "AnotherComponent",
  data() {
    return {
    }
  },
  methods: {
    alertTime: function() {
      alert(new Date());
    }
  }
};
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
</style>
```

在上述代码中，我们终于看到了一个示例，其中我们的组件具有一些基本的 JS 驱动的 Vue 功能。我们正在使用 Vue 的内置`data`和`methods`选项。在`methods`选项内，我们定义了`alertTime`函数，每当它被调用时，都会在警报框中显示当前时间。

讨论所有这些组成部分如何运作的细节超出了本书的范围。本章的重点是理解 Babel。如果您需要更多关于 Vue 的基本概念的信息，比如前几段提到的内容，请参考 Packt 图书馆中的许多有用资源之一。本书的一个很好的伴侣将是对 Vue 2 框架的快速介绍：*Vue.js 快速入门指南*，作者是*Ajdin Imsirovic*（[`prod.packtpub.com/in/application-development/vuejs-quick-start-guide`](https://prod.packtpub.com/in/application-development/vuejs-quick-start-guide)）。

我们现在需要关注的重点是在我们的`methods`选项中使用 ES6+功能。目前，`methods`选项的代码是用 ES5 JS 编写的，因此很容易在此代码上运行 webpack，我们很快就会看到。

# 使用 ES5 代码运行 webpack

要运行 webpack，请执行以下操作：

1.  在项目的根目录中添加另一个文件`webpack.config.js`，以便我们可以设置我们的 webpack 配置如下：

```js
let HtmlWebpackPlugin = require('html-webpack-plugin');
let VueLoaderPlugin = require('vue-loader/lib/plugin');

module.exports = {
    entry: './src/main.js',
    output: {
        filename: 'main.js',
    },
    module: {
        rules: [
            { test: /\.vue$/, use: 'vue-loader' }
        ]
    },
    plugins: [
        new HtmlWebpackPlugin({
            template: './src/index.html',
        }),
        new VueLoaderPlugin(), 
    ]
};
```

请注意，入口和输出文件都是`main.js`，所以我们不必指定它们，但是在前面的代码中我们还是这样做了，以使事情更明显。

1.  接下来，在`package.json`中，更新`scripts`键：

```js
"scripts": {
    "webpack": "webpack"
 },
```

1.  现在从 Git Bash 运行我们的项目，使用以下命令：

```js
npm run webpack
```

1.  现在，在 VS Code 中，导航到我们项目中的`dist`文件夹。

1.  右键单击`index.html`，然后单击“在默认浏览器中打开”命令。

我们的浏览器现在将显示以下输出（放大以便查看）：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/330dd18a-b7ff-4a6f-9006-17a6d5dd4d29.png)

如果用户单击“现在几点了？”按钮，将在网页上出现一个警报框，显示当前时间。现在让我们将我们的`methods`选项更新为 ES6 语法，然后看看会发生什么。

# 添加 webpack-dev-server

在我们开始将代码更新为 ES6 语法之前，还有一件事可以让事情变得更快捷和更方便：

1.  添加`webpack-dev-server`。借助这个 NPM 包，我们的代码将不断地被提供和监视变化。让我们使用以下命令安装它：

```js
npm install webpack-dev-server --save-dev --verbose
```

1.  为了让 webpack 开发服务器运行并提供我们的代码，我们还需要将`package.json`条目的`scripts`更新为以下内容：

```js
"scripts": {
  "webpack": "webpack",
  "webpack-dev": "webpack-dev-server --mode development"
},
```

现在我们可以尝试向我们的组件添加各种功能，并在我们在 VS Code 中保存代码时，观察它们在浏览器中进行热重载。

1.  现在让我们立即通过运行以下命令来测试它：

```js
npm run webpack-dev
```

您可以在`http://localhost:8080/`上测试提供的网页，并且您会注意到它仍然像以前一样工作。

接下来，我们将在`methods`选项中添加一些 ES6 语法。

# 将方法选项更新为 ES6 语法

让我们更新`AnotherComponent.vue`文件中的`methods`选项。以下是更新后的代码：

```js
methods: {
    alertTime: () => {
      alert(new Date());
      alert('something else');
    }
}
```

一旦您在 VS Code 中保存了更改，您可以单击“现在几点了？”按钮，然后会出现预期的警报，然后是另一个读取其他内容的警报。这样，我们可以确保我们正在查看更新的应用程序。

现在让我们在`dist`文件夹中的编译后的`main.js`文件中找到我们的 ES6 代码。

如果我们在开发工具中检查`/dist/index.html`文件，我们可以看到对`main.js`的引用，这是 webpack 编译的 JS 代码。如果右键单击`main.js`并在上下文右键菜单中点击“在新标签页中打开”命令，您将在新标签页中看到完整的代码。要找到我们的 ES6 代码，让我们按下*Ctrl* + *F*快捷键，以便输入我们的搜索词：`alertTime`。

在文件的底部，我们看到了我们的 ES6 箭头函数：

```js
alertTime: () => {\r\n      alert('something else');
```

在接下来的部分，我们将使用 babel-loader 更新我们的 webpack 配置，并看看 webpack 将如何将前面的代码转译为 ES5。

# 将 babel-loader 添加到我们的 webpack 配置中

在开始之前，我们需要停止 webpack-dev-server，使用 Git Bash 中的*Ctrl* + *C*组合键。

接下来，为了能够在我们的项目中转译 ES6+语法，我们需要使用 Babel 更新我们的 webpack 配置。让我们首先使用 NPM 安装 babel-loader 包：

```js
npm install babel-loader --save-dev --verbose
```

接下来，让我们再次在项目上运行 webpack：

```js
npm run webpack
```

不幸的是，这仍然不起作用。如果我们检查我们转译后的`main.js`，我们仍然会看到`alertTime`键和它的 ES6 匿名函数。这意味着我们仍然需要另一个包：`babel core`。

```js
npm install @babel/core --save-dev --verbose
```

如果我们此时运行 webpack，我们会发现我们的问题仍然没有解决。

这意味着我们仍然需要添加`babel-preset-env`：

```js
npm install @babel/preset-env --save-dev --verbose
```

此时，验证一下我们的`package.json`中的`devDependencies`是否都有预期的更新是没有坏处的：

```js
"devDependencies": {
  "@babel/core": "⁷.3.4",
  "@babel/preset-env": "⁷.3.4",
  "babel-loader": "⁸.0.5",
  "html-webpack-plugin": "³.2.0",
  "vue": "².6.9",
  "vue-loader": "¹⁵.7.0",
  "vue-template-compiler": "².6.9",
  "webpack": "⁴.29.6",
  "webpack-cli": "³.2.3",
  "webpack-dev-server": "³.2.1"
}
```

最后，在我们重新运行 webpack 之前，我们需要设置一个`babel.config.js`文件，这是 Babel 自己的配置文件（类似于 webpack 的`webpack.config.js`）。

让我们在项目的根目录中创建一个新文件`babel.config.js`，并添加以下代码：

```js
module.exports = {
  presets: ['@babel/preset-env']
}
```

现在我们需要做的就是更新我们的 webpack 配置，使其能够与 Babel 一起工作。

# 更新我们的 webpack 配置以使用 babel

为了使我们的 webpack 能够使用 babel，我们需要告诉它何时使用 babel-loader。我们通过在`webpack.config.js`的`module`选项内添加一个测试规则来实现，如下所示：

```js
module: {
    rules: [
        { test: /\.js$/, use: 'babel-loader' }, 
        { test: /\.vue$/, use: 'vue-loader' }
    ]
},
```

现在我们已经设置好了一切，我们可以再次在 Git Bash 中运行`npm run webpack-dev`命令。

这里有一个快速的方法来查看 webpack 是否与之前不同地捆绑了我们的 JS 文件：只需查看 Git Bash 中的 webpack 日志信息。在我们之前尝试将 Babel 与 webpack 配合工作时，捆绑大小恰好是 70.2 KB。然而，在`webpack` NPM 脚本的最后一次运行之后，`main.js`的捆绑大小为 70.6 KB。我们可以再次在开发工具中检查`./dist/main.js`文件。或者，你可以在 VS Code 中直接搜索`./dist/main.js`中的`alertTime`字符串。

无论我们如何定位它，我们捆绑的`main.js`文件的`methods`条目看起来是这样的：

```js
methods:{alertTime:function(){alert(new Date),alert("something else")}}}...
```

仅仅瞥一眼前面的代码并看到`function`关键字，就应该明显地意识到这段代码是 ES5 的，这意味着 Babel 已经成功地被 webpack 运行，我们在`src`文件夹中的输入文件中的 ES6 `alertTime` Vue 方法已经成功地被转译到了`dist`文件夹中的输出文件中。

为了验证我们的设置是否有效，我们可以再次运行`webpack-dev-server`，并且在它运行时，对`AnotherComponent.vue`中的`methods`选项进行另一个小改动：

```js
methods: {
    alertTime: () => {
      alert(new Date());
      alert('whatever');
    }
}
```

如果你查看在`localhost:8080`上提供的项目，你会看到它按预期工作，如果你从开发工具中打开`main.js`，你也会看到转译后的语法。

在下一节中，我们将简要提到一个常见的困惑来源以及在 Vue 中如何处理它。这与箭头函数语法和`this`关键字有关。

# 箭头函数中的 this 关键字在 Vue 中的问题

不幸的是，当 Babel 将箭头函数中的`this`关键字转译为`_this`时，这意味着我们的任何方法都将被破坏，我们的应用程序将无法工作。这背后的原因是箭头函数的作用域与 ES5 函数不同。

在下一节中，我们将看一下在 Vue 实例的方法选项中定义函数的推荐方法。

# 关键字问题的推荐解决方案

在 Vue 组件中解决`this`关键字的推荐解决方案是不使用箭头函数语法，因为由于作用域问题，它不会产生预期的结果。具体来说，箭头函数的作用域是父上下文。

让我们看一个简单的应用作为问题的例子。

# 添加一个计数器应用

在开始之前，请确保你回到了`VUE-CLI-3-QSG/Chapter03`文件夹，这是本章中所有项目的根文件夹。

在我们开始构建应用程序之前，我们需要提醒自己在使用`vue create`时有一些选项，因此让我们运行这个：

```js
vue create --help
```

在选项列表中，我们可以看到`-d`代表`--default`标志，跳过提示并使用默认预设，而`-b`选项是`--bare`标志的简写，用于在不带初学者说明的情况下搭建我们的项目。

有趣的是，我们可以组合这些单独的标志，我们现在就来做。让我们通过运行以下命令来开始我们的应用程序：

```js
vue create add-one-counter -db
```

正如我们所看到的，我们可以在`vue create`命令后附加的标志的字母别名之间进行链接，这是一个很好的小型生产力提升。

在构建的应用程序中，我们将更改`src`文件夹中的`main.js`的内容。这个文件将与之前的示例应用程序（上一节中的`npm-vue-b-w-es6-syntax`应用程序）完全相同，因此您可以将该文件从之前的 Vue 应用程序中复制并粘贴到我们的新示例应用程序`add-one-counter`中。

如果您在 VS Code 中打开我们的新的`add-one-counter`应用程序，您还会注意到另一个文件夹：`public`文件夹，其中包含`index.html`。我们将保留此文件不变。

回到`src`文件夹，我们需要更改`App.vue`的内容如下：

```js
<template>
  <div id="app">
      <article>
        Our own custom article component!
      </article>
      <AnotherComponent />
  </div>
</template>

<script>
import AnotherComponent from './components/AnotherComponent.vue';

export default {
    name: 'app',
    components: {
        AnotherComponent
    }
}
</script>
```

最后，我们需要在项目的根目录下添加一个`components`文件夹，并在其中添加`AnotherComponent.vue`文件。以下是`AnotherComponent.vue`的内容：

```js
<template>
  <p>
    This is another component.
    <button v-on:click="incrementUp">Add One</button>
    <br>
    <span>Current value of the counter: {{ counter }}</span>
  </p>
</template>

<script>
export default {
  name: "AnotherComponent",
  data() {
    return {
      counter: 0
    }
  },
  methods: {
    incrementUp: function() {
      this.counter++;
    }
  }
};
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
</style>
```

在`methods`选项中，我们可以看到`incrementUp`函数使用 ES6 语法进行定义。

如果您尝试运行此应用程序，它将无法工作。这是因为箭头函数的作用域和 Babel 设置使得在`arrow`函数中正确设置 Vue 应用程序的`methods`变得困难。

唯一的改进，也是在方法选项中编写函数的通常方式，是避免使用箭头函数语法和`function`关键字的使用，如下所示：

```js
methods: {
    incrementUp() {
        this.counter++;
    }
}
```

`incrementUp`函数被称为**简写**函数。您可以在以下网址阅读更多信息：[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Object_initializer#Method_definitions`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Object_initializer#Method_definitions)。

让我们通过 UI 来测试驱动应用程序：

```js
vue ui
```

一旦 Vue UI 在浏览器中提供服务，让我们将浏览器的地址栏指向`http://localhost:8000/project/select`。接下来，点击`add-one-counter`文件夹，然后点击导入此文件夹按钮。

接下来，点击主菜单上的 Tasks 按钮。最后，点击 Serve 图标。点击 Output 按钮查看应用程序的构建和服务情况。

最后，在`http://localhost:8080/`打开网站。你会看到一个正在提供服务的工作中的应用程序：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue-cli3-qk-st-gd/img/9f8b4063-82e3-4dea-b2a7-a549b4e0e610.png)

前面的例子向我们展示了如何在 Vue 实例中命名和组织方法的最佳实践。此外，我们还学会了如何使用 Vue UI 来自动化 webpack 的构建和服务应用程序，只需点击几下，比本章大部分内容中我们所做的要好得多！这让我们得出一个结论：很多的管道和功能都被抽象化了，因此，使用 Vue UI 和 Babel 设置变得更加容易和方便。

# 摘要

在本章中，我们简要概述了 Babel 是什么，它的作用以及使其与 Vue 一起工作所需的内容。所有这些都是通过`vue-cli-service`来抽象化的，它在幕后由 webpack 提供支持。现在我们已经了解了所有这些不同部分是如何一起工作的，我们将开始只使用 Vue CLI 及其 UI，并在接下来的章节中学习如何更好地使用它。

我们将从理解在 Vue CLI 中使用 Jest 进行测试开始。我们还将学习**测试驱动开发**（TDD）以及如何使用 Vue CLI UI 运行测试。
