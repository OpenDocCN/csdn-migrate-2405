# Webpack 5 启动和运行指南（一）

> 原文：[`zh.annas-archive.org/md5/D84E54A317E3F5B84C857CD1B0FA20B6`](https://zh.annas-archive.org/md5/D84E54A317E3F5B84C857CD1B0FA20B6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

当我被要求写这本培训书时，我意识到关于 Webpack 及其用途的了解很少。通常这是开发人员偶然发现并在工作中学习的东西，这可能是一个非常费力的过程。Webpack.js 网站上有一些文档，以及一些可靠的资源，比如 Medium。然而，这些资源往往从专家的角度来与读者交流，而我个人发现这并不理想。

作为一名网页开发讲师，我看到非常有技术和智慧的人可能存在盲点和知识空白。作为一名讲师，我被告知，并且也传达这个信息，那就是“没有愚蠢的问题”。许多没有教学背景的人可能会建议他们不想对你说教，宁愿你不问愚蠢的问题。我们发现，如果学生宁愿保持沉默而不问问题，这是有害的。

我打算尽可能保持简单。也许我已经失败了，使用了“定制”这样的词，尽管如此，前提是我们所有人都会有让人啪啪打脑袋的时刻，我们本应该做某事，后来意识到我们做错了。对吧？这种事发生在我们最聪明的人身上。此外，大多数讲师可能不愿意对你进行详尽的解释，因为他们担心冒犯你。问题在于，总会有一些平凡的细节，开发人员认为显而易见，但可能有多种解释。当我讲课时的规则是：“没有愚蠢的问题”，所以我希望证明这个理论的必要性。

# 这本书适合谁

这本书是为希望通过学习 Webpack 来开始他们的 Web 项目依赖管理的 Web 开发人员而写的。假定读者具有 JavaScript 的工作知识。

# 本书涵盖的内容

第一章，“Webpack 5 简介”，将向您介绍 Webpack——具体来说，是 Webpack 5 版本。它将概述围绕 Webpack 的核心概念以及它的使用方式。

第二章，“使用模块和代码拆分”，将详细介绍模块和代码拆分，以及 Webpack 5 的一些突出和有趣的方面，这些方面对于理解 Webpack 至关重要。

第三章，“使用配置和选项”，将探讨配置的世界，了解其局限性和能力，以及选项在其中的作用。

第四章，“API、插件和加载器”，将深入探讨 API、加载器和插件的世界。这些 Webpack 的特性阐述了平台的能力，从配置和选项出发。

第五章，“库和框架”，将讨论库和框架。我们对插件、API 和加载器的研究表明，有时我们不想使用诸如库之类的远程代码，但有时我们确实需要。Webpack 通常处理本地托管的代码，但有时我们可能需要使用库。这为我们引入了这个话题。

第六章，“生产、集成和联合模块”，将深入介绍这个主题，并希望解决开发人员可能存在的任何疑虑。

第七章，“调试和迁移”，将讨论热模块替换和实时编码，并深入了解一些严肃的教程。

第八章，*编写教程和实时编码技巧*，将向您展示 Webpack 5 的工作示例，特别是 Webpack 5 相对于早期版本的差异。将有纯 JavaScript 教程以及常见的框架，Vue.js 将是一个不错的选择。

# 为了充分利用本书

您可以在[`github.com/PacktPublishing/Webpack-5-Up-and-Running`](https://github.com/PacktPublishing/Webpack-5-Up-and-Running)找到本书所有章节中使用的代码。为了充分利用本书，您需要以下内容：

+   JavaScript 的基本知识。

+   确保您已安装最新版本的 Webpack 5。

+   您需要使用命令行界面，如命令提示符或其他您选择的命令行实用程序。

+   您将需要 Node.js，JavaScript 运行环境。

+   确保您已安装最新版本的 Node.js（webpack 5 至少需要 Node.js 10.13.0（LTS））；否则，您可能会遇到许多问题。

+   您需要在本地计算机上安装具有管理员级别权限的`npm`。Webpack 和 Webpack 5 在 Node.js 环境中运行，这就是为什么我们需要它的包管理器——NPM。

+   截至撰写本文时，最新版本是 Webpack 5。访问[`webpack.js.org`](https://webpack.js.org)查找适合您的最新版本。

# 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](https://www.packtpub.com/support)并注册，以便文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packt.com](http://www.packt.com)。

1.  选择“支持”选项卡。

1.  点击“代码下载”。

1.  在搜索框中输入书名，并按照屏幕上的说明操作。

下载文件后，请确保使用以下最新版本的解压缩或提取文件夹：

+   Windows 使用 WinRAR/7-Zip

+   Mac 使用 Zipeg/iZip/UnRarX

+   Linux 使用 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Webpack-5-Up-and-Running`](https://github.com/PacktPublishing/Webpack-5-Up-and-Running)。如果代码有更新，将在现有的 GitHub 存储库中更新。

我们还有其他代码包来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)找到。快去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。以下是一个示例：“以下行是`package.json`文件中的代码片段。”

代码块设置如下：

```js
"scripts": {
"build": "webpack --config webpack.config.js"
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```js
<!doctype html>
<html>
 <head>
 <title>Webpack - Test</title>
 <script src="img/lodash@4.16.6"></script>
 </head>
 <body>
 <script src="img/index.js"></script>
 </body>
</html>
```

任何命令行输入或输出都以以下形式编写：

```js
npm install --save-dev webpack-cli
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种形式出现在文本中。以下是一个示例：“从管理面板中选择系统信息。”

警告或重要说明会以这种形式出现。

提示和技巧会出现在这样的形式中。


# 第一章：Webpack 5 简介

本书面向有经验的 JavaScript 开发人员，旨在通过逐步的过程带您完成一个特定示例项目的开发和生产。当您完成本指南时，您应该能够完全设置和部署一个可工作的捆绑应用程序。

本章将向您介绍 Webpack——具体来说，是 Webpack 5 版本。它将包括对 Webpack 周围的核心概念以及其用法的概述。

本章面向对 Webpack 和 Webpack 5 新手程序员。本章将涵盖初始设置，以及对该过程的概述，并将向您展示如何部署您的第一个捆绑应用程序。

本章将涵盖以下主题：

+   Webpack 5 的基础知识

+   设置 Webpack

+   创建一个示例项目

# 技术要求

您可以在本书的所有章节中找到使用的代码[`github.com/PacktPublishing/Webpack-5-Up-and-Running`](https://github.com/PacktPublishing/Webpack-5-Up-and-Running)：

+   要使用本指南，您需要对 JavaScript 有基本的了解。

+   确保您已安装了 Webpack 5 的最新版本。

+   您将需要使用命令行，如命令提示符或您选择的其他命令行实用程序。

+   您将需要 Node.js，JavaScript 运行环境。

+   确保你已经安装了最新版本的 Node.js；否则，你可能会遇到很多问题。

+   您需要在本地计算机上安装`npm`并具有管理员级别的权限。Webpack 和 Webpack 5 在 Node.js 环境中运行，这就是为什么我们需要它的包管理器 npm。

+   截至撰写本文时，最新版本是 Webpack 5。访问[`webpack.js.org`](https://webpack.js.org)找到适合您的最新版本。

# Webpack 5 的基础知识

基本上，Webpack 是一个用于 JavaScript 应用程序的模块打包工具。Webpack 接受一系列 JavaScript 文件，以及构成应用程序的图像文件等依赖项，并构建所谓的依赖图。依赖图是这些文件和依赖项在应用程序中如何排序和链接的表示，并显示文件之间的交互方式。

然后，这个依赖图形成了一个模板，捆绑器在将所有依赖项和文件压缩成更小的集合时会遵循这个模板。然后 Webpack 能够将这些文件捆绑成更大、但通常更少的文件集。这消除了未使用的代码、重复的代码以及重写的需要。在某种程度上，代码可以更简洁地格式化。

Webpack 递归地构建应用程序中的每个模块，然后将所有这些模块打包成少量的捆绑包。在大多数情况下，捆绑的应用程序将包含一个脚本，非常适合被程序（如 Web 浏览器）读取，但对程序员来说太复杂了。因此，开发人员将会拿一组源文件并对程序的这一部分进行更改，然后将这些源文件捆绑成一个输出——一个捆绑的应用程序。

捆绑最初是为了提高浏览器的阅读性能，但它还有许多其他优点。一旦 Webpack 捆绑了一组源文件，它通常会遵循一种系统化和常规的文件结构。代码中的错误可能会中断捆绑操作；本书将指导您如何克服这些问题。

现在，让我们探索 Webpack 5 周围的一般概念。

# Webpack 5 背后的一般概念

在这里，我们将开始理解 Webpack 的关键概念和目的，而不是期望您有任何先前的了解。捆绑通常在桌面上使用 Node.js 或`npm`和**命令行界面**（**CLI**）（通常是命令提示符）上进行。

Webpack 是一个构建工具，将所有资产放入一个依赖图中。这包括 JavaScript 文件、图像、字体和**层叠样式表**（**CSS**）。它将**Sassy CSS**（**SCSS**）和 TypeScript 文件分别放入 CSS 和 JavaScript 文件中。只有当代码与后者格式兼容时，Webpack 才能做到这一点。

在 JavaScript 和其他语言编程时，源代码通常会使用诸如`require()`的语句，将一个文件指向另一个文件。Webpack 将检测这个语句，并确定所需的文件作为依赖项。这将决定最终 JavaScript 捆绑包中的文件如何处理。这还包括将 URL 路径替换为**内容传送网络**（**CDN**）——这实质上是一组代理服务器网络——与本地文件。

以下图表是 Webpack 的一般目的的表示，即获取一组文件或依赖项并以优化的形式输出内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/wpk5-uprn/img/a69b6e79-5bb7-4de7-acd2-f0cf6cd10d25.jpg)

现在，让我们更仔细地看一些您可能不熟悉但在使用 Webpack 时可以被视为常用术语的术语。

# 术语

本节将涵盖 Webpack 5 中使用的术语。这将包括本地术语，以及一些更不寻常的缩写词。

+   **资产：**这是 Webpack 中经常使用的一个术语，用于防止概念的混淆。它指的是软件在生成捆绑应用程序时收集的图像文件，甚至是数据或脚本文件。

+   **捆绑：**这指的是 Webpack 编译应用程序后输出的应用程序。这是原始或源应用程序的优化版本——这将在后面的章节中详细讨论原因。捆绑器将这些文件合并成一个文件，这使得解包和破解变得非常困难。它还提高了浏览器的性能。它通过确保处理器保持在最佳水平，并删除任何不符合标准的编码结构来实现这一点。这也鼓励开发人员更加认真地采用惯例。如果存在任何不安全的编程，这些位置更容易被识别、隔离和纠正。

+   **SASS：**CSS 的增强版本。Webpack 处理这段代码就像处理 CSS 一样；然而，这可能是一个让你感到困惑的短语，所以了解一下是值得的。

+   **SCSS：**这只是用于给 SASS 增加额外功能的语法版本的名称。值得知道的是，Webpack 能够转译这两种语法。

+   **转译：**这是 Webpack 5 将一组输入源代码转换为更优化的输出分发代码的过程。这是通过删除未使用或重复的代码来完成的。转译用于将一组文件转换为更简单的一组文件。例如，SCSS 通常包含可以轻松存储在 CSS 文件中的脚本。您还可以将 SCSS 转译为 CSS，或将 TypeScript 转译为 JavaScript。

+   **TypeScript：**对于未经训练的人来说，TypeScript 是一种在许多方面类似于 JavaScript 的代码类型。例如，浏览器最常运行 JavaScript，因此在可能的情况下使用 JavaScript 可能更合适。当前，Webpack 5 将在前者允许时将 TypeScript 转译为 JavaScript。

+   **CDN：**CDN 是一组代理服务器网络，提供高可用性和高性能。一些例子是谷歌 API，如谷歌字体，以及其他类似的工具，所有 JavaScript 开发人员无疑都很熟悉。

+   **依赖图：**在 Webpack 5 中，依赖图是表示多个资产相互依赖的有向图。Webpack 5 将映射资产和依赖项的列表，并记录它们在应用程序中如何相互依赖。它使用这个来推导出一个适当的输出文件结构。

尽管 JavaScript 是入口点，但 Webpack 意识到您的其他资产类型（如 HTML、CSS 和 SVG）都有自己的依赖关系，这些依赖关系应该作为构建过程的一部分进行考虑。

Webpack 由**输入**和**输出**组成。输出可以由一个或多个文件组成。除了捆绑模块外，Webpack 还可以对您的文件执行许多功能。输入是指在捆绑之前，原始文件的原始结构。输出是指捆绑后的文件在其新的和优化的文件结构中的结果。因此，输入由源文件组成，输出可以由开发文件或生产文件组成。

输入和输出以及源代码和开发代码之间经常混淆。

**源代码**指的是捆绑之前的原始应用程序。**开发代码**指的是将应用程序放入 Node.js 环境并以开发模式捆绑后的应用程序。在生产模式下会产生一个更“紧凑”的捆绑版本，但这个版本很难进行工作。因此，在捆绑后可以在一定程度上修改开发代码，这非常有用，例如在您修改数据库连接配置的情况下。

在使用 Webpack 5 时，这些短语可能会出现，重要的是您不要对它们感到太困惑。

大多数其他术语将在我们遇到它时进行解释，或者如果您熟悉 JavaScript，它是如此常见，我们假设您了解这些术语。

这总结了您在使用 Webpack 时会遇到的大部分术语。现在，我们将探讨软件的工作原理。

# Webpack 的工作原理

Webpack 通过生成一组源文件中资产的依赖图来工作，然后从中转换出一组优化的分发文件。这些源和分发文件分别包含源代码和分发代码。这些分发代码形成了输出。分发只是输出或捆绑的另一个名称。

Webpack 首先在源文件中找到一个入口点，然后构建一个依赖图。在 Webpack 5 中，选择入口点是可选的，选择的方式将改变构建过程的性质，无论是速度还是输出优化。

Webpack 5 能够转换、捆绑或打包几乎任何资源或资产。

我们已经对软件的工作原理进行了良好的概述；之前使用过 Webpack 的有经验的用户可能会认为这个概述很基础，所以让我们来看看这个当前版本中有什么新东西。

# Webpack 5 中有什么新功能？

备受欢迎的 Webpack 模块捆绑器已经经历了一次大规模更新，发布了第 5 版。Webpack 5 提供了巨大的性能改进、更动态的可扩展性和基本的向后兼容性。

Webpack 5 接替了第 4 版，第 4 版并非总是与许多可用的各种加载器向后兼容，这些加载器通常更兼容第 2 版，这意味着如果不使用第 2 版，开发人员通常会在命令行中遇到弃用警告。Webpack 5 现在已经解决了这个问题。

第 5 版的另一个重要卖点是联邦模块。我们将在稍后的第六章中更详细地讨论这一点，*生产、集成和联邦模块*。然而，总结一下，联邦模块本质上是捆绑应用程序以利用和与远程存储的单独捆绑中的模块和资产进行交互的一种方式。

Webpack 5 的优点总结如下：

+   Webpack 5 提供了对 HTTP 请求的控制，这提高了速度和性能，也减轻了安全问题。

+   Webpack 5 相对于竞争对手 Browserify 和 systemjs 有一些优势，特别是速度。构建时间直接取决于配置，但比最近的竞争对手更快。

+   使用 Webpack 5 几乎不需要任何配置，但您始终可以选择配置。

+   与其他替代方案相比，使用起来可能更复杂，但这主要是由于其多功能和范围，值得克服。

+   Webpack 5 具有优化插件，可以很好地删除未使用的代码。它还具有许多相关功能，例如树摇动，我们将在本书后面更详细地讨论。

+   它比 Browserify 更灵活，允许用户选择更多的入口点并使用不同类型的资产。在捆绑大型 Web 应用程序和单页面 Web 应用程序时，它在速度和灵活性方面也更好。

Webpack 现在被认为是应用程序开发和 Web 开发中非常重要的工具，它可以改变结构并优化所有 Web 资产的加载时间，例如 HTML、JS、CSS 和图像。现在让我们实际使用 Webpack。为了做到这一点，我们将首先看一下可能对您来说是新的东西——如果您到目前为止只使用原生 JavaScript——模式。

# 模式

一旦您理解了一般概念，运行构建时需要了解的第一件事就是模式。模式对于 Webpack 的工作和编译项目至关重要，因此最好在继续之前简要但重要地介绍一下这个主题。

模式使用 CLI，这是我们稍后将更详细介绍的一个过程。如果您习惯使用原生 JavaScript，这可能对您来说是新的。但是，请放心，这不是一个难以理解的复杂主题。

Webpack 附带两个配置文件，如下所示：

+   **开发配置**：这使用`webpack-dev-server`（热重载）、启用调试等。

+   **生产配置**：这将生成一个在生产环境中使用的优化、最小化（uglify JS）、源映射的捆绑包。

自从发布第 5 版以来，Webpack 默认通过简单地向命令添加`mode`参数来处理模式功能。Webpack 不能仅使用`package.json`来查找模式以确定正确的构建路径。

现在我们已经掌握了基本原理，是时候进入实际设置了。

# 设置 Webpack

本书将逐步介绍一个示例项目的开发，我相信您会发现这是学习如何使用 Webpack 5 的简单方法。

Webpack 5 在本地机器上打包所有依赖项。理论上，这可以远程完成，但为了避免给第一次使用者带来任何困惑，我将强调使用本地机器。

对于大多数项目，建议在本地安装软件包。当引入升级或破坏性更改时，这样做会更容易。

我们将从`npm`安装开始。npm 是您将与 Webpack 5 一起使用的软件包管理器。一旦在本地机器上安装了它，您就可以使用 CLI，例如命令提示符，来使用`npm`命令。

安装了`npm`后，您可以继续下一步，即打开 CLI。有很多选择，但为了本教程的缘故，我们将使用命令提示符。

让我们一步一步地分解这个过程，这样您就可以跟上：

1.  安装`npm`软件包管理器，您将与 Wepback 5 一起使用它。

1.  打开 CLI（在本教程中，我们将使用命令提示符）并输入以下内容：

```js
mkdir webpack4 && cd webpack5
npm init -y
npm install webpack webpack-cli --save-dev
```

让我们分解一下代码块。前面的命令首先会在您的本地计算机上创建一个名为`webpack5`的新目录。然后，它将把当前目录（`cd`）标识为`webpack5`。这意味着通过 CLI 进行的任何进一步的命令都将是相对于该目录进行的。接下来的命令是初始化`npm`。这些基本命令及其含义的完整列表可以在本章末尾的*进一步阅读*部分找到。这部分内容很有趣，我相信您会学到一些新东西。然后，我们在本地安装 Webpack 并安装`webpack-cli`——这是用于在命令行上运行 Webpack 的工具。

1.  接下来，安装最新版本或特定版本的 Webpack，并运行以下命令。但是，在第二行，用您选择的版本替换`<version>`，例如`5.00`：

```js
npm install --save-dev webpack
npm install --save-dev webpack@<version>
```

1.  下一个命令是`npm install`，它将在目录中安装 Webpack 5，并将项目保存在开发环境中。重要的是要注意开发环境和生产环境（或模式）之间的区别：

```js
npm install --save-dev webpack-cli
```

以下行是`package.json`文件中的代码片段。我们需要这些输入文件来生成`webpack.config.js`文件，其中包含 Webpack 捆绑的配置信息。

1.  我们必须确保`package.json`文件的编码如下：

```js
"scripts": {
"build": "webpack --config webpack.config.js"
}
```

在使用 Webpack 5 时，您可以通过在 CLI 中运行`npx webpack`来访问其二进制版本。

我们还应该决定我们需要哪种类型的安装；任何重新安装都会覆盖先前的安装，所以如果您已经按照前面的步骤进行了操作，就不用担心了。

1.  如果适用，现在让我们进行安装。

有两种类型的安装：

+   +   **全局**：全局安装将锁定您的安装到特定版本的 Webpack。

以下`npm`安装将使 Webpack 全局可用：

```js
npm install --global webpack
```

+   +   **本地**：本地安装将允许您在项目目录中运行 Webpack。这需要通过`npm`脚本完成：

```js
npm install webpack --save-dev
```

每次在新的本地计算机上开始新项目时，您都需要执行所有前面的步骤。完成安装后，是时候把注意力转回到构建项目上了。

# 创建一个示例项目

现在，我们将创建一个实验项目，具有以下目录结构、文件及其内容。

以下代码块是指您本地计算机上的一个文件夹。它说明了 Webpack 通常使用的格式和命名约定。您应该遵循此格式，以确保您的项目与本教程保持一致，如下所示：

1.  首先设置**项目树**：

```js
webpack5-demo
 |- package.json
  |- index.html
  |- /src
  |- index.js
```

项目树向我们展示了我们将要处理的文件。

1.  现在让我们仔细看一下索引文件，因为它们将成为我们前端的关键，从`src/index.js`开始：

```js
function component() {
 let element = document.createElement('div');
// Lodash, currently included via a script, is required for this 
// line to work
 element.innerHTML = _.join(['Testing', 'webpack'], ' ');
 return element;
}
document.body.appendChild(component());
```

`index.js`包含我们的 JS。接下来的`index.html`文件是我们用户的前端。

1.  它还需要设置，所以让我们打开并编辑`index.html`：

```js
<!doctype html>
<html>
 <head>
 <title>Webpack - Test</title>
 <script src="img/lodash@4.16.6"></script>
 </head>
 <body>
 <script src="img/index.js"></script>
 </body>
</html>
```

请注意前面的`<script src="img/lodash@4.16.6">`标签。这是指使用`lodash`库。`index.js`文件（而不是`index.html`文件）需要调用此库。Webpack 将从库中获取所需的模块，并使用它们来构建捆绑包的依赖关系图。

Lodash 是一个提供函数式编程任务的 JavaScript 库。它是在 MIT 许可下发布的，基本上使处理数字、数组、字符串和对象变得更容易。

需要注意的是，如果没有明确说明您的代码依赖于外部库，应用程序将无法正常运行。例如，依赖项可能丢失或包含顺序错误。相反，如果包含了但未使用依赖项，浏览器将下载不必要的代码。

我们可以使用 Webpack 5 来管理这些脚本。

1.  你还需要调整你的`package.json`文件，将你的软件包标记为私有，并删除主入口点。这是为了防止意外发布你的代码：

```js
{
 "name": "webpack5",
 "version": "1.0.0",
 "description": "",
 "private": true,
 "main": "index.js",
 "scripts": {
 "test": "echo \"Error: no test specified\" && exit 1"
 },
 "keywords": [],
 "author": "",
 "license": "ISC",
 "devDependencies": {
 "webpack": "⁵.0.0",
 "webpack-cli": "³.1.2"
 },
 "dependencies": {}
 }
```

你可以从前面代码中的粗体文本中看到如何进行这些修改。请注意，我们的入口点将设置为`index.js`。这是 Webpack 在开始捆绑编译时将读取的第一个文件（请参阅依赖图的先前定义）。

如果你想了解更多关于`package.json`文件的信息，请访问[`docs.npmjs.com/getting-started/`](https://docs.npmjs.com/getting-started/)，这里提供了关于`npm`的信息。

我们现在已经完成了第一个演示应用程序捆绑的源代码。这构成了我们现在将通过 Webpack 运行以生成我们的第一个捆绑应用程序的输入或源文件。

# 捆绑你的第一个项目

Web 打包简单地意味着捆绑项目。这是 Webpack 的本质，从这个非常简单的介绍开始学习应用程序是一个很好的方法。

首先，我们需要通过略微改变我们的目录结构来将源代码与分发代码分开。这个源代码用于编写和编辑，分发代码是经过最小化和优化的捆绑，是我们构建过程的结果。

现在，我们将详细介绍构建我们的第一个项目的每个步骤：

1.  我们将首先构建项目和目录结构。首先注意`/src`和`/dist`这两个术语；它们分别指的是源代码和分发代码：

```js
webpack5-demo
|- package.json
  |- /dist
  |- index.html
  |- index.js
|- /src
|- index.js
```

1.  要将`lodash`依赖项与`index.js`捆绑，我们需要在本地安装该库：

```js
npm install --save lodash
```

在安装将捆绑到生产捆绑包的软件包时，应使用以下命令：

```js
npm install --save 
```

如果你正在为开发目的安装软件包（例如，一个代码检查工具、测试库等），你应该使用以下命令：

```js
npm install --save-dev
```

1.  现在，让我们使用**`src/main.js`**将`lodash`导入到我们的脚本中：

```js
import_ from 'lodash';

function component() {
let element = document.createElement('div');
 // Lodash, currently included via a script, is required for this 
// line to work
element.innerHTML = _.join(['Hello', 'Webpack'], ' ');
return element;
}
document.body.appendChild(component());
```

1.  接下来，更新你的`dist/index.html`文件。我们将删除对`lodash`库的引用。

这样做是因为我们将在本地安装库进行捆绑，不再需要远程调用库：

```js
<!doctype html>
<html>
<head>
<title>Getting Started</title>
  <script src="img/lodash@4.16.6"></script>
  //If you see the above line, please remove it.
</head>
<body>
  <script src="img/main.js"></script>
</body>
</html>
```

1.  接下来，我们将使用命令行运行`npx webpack`。`npx`命令随 Node 8.2/npm 5.0.0 或更高版本一起提供，并运行 Webpack 二进制文件（`./node_modules/.bin/webpack`）。这将把我们的脚本`src/index.js`作为入口点，并生成`dist/main.js`作为输出：

```js
npx webpack
...
Built at: 14/03/2019 11:50:07
Asset Size Chunks Chunk Names
main.js 70.4 KiB 0 [emitted] main
...
WARNING in configuration
The 'mode' option has not been set, webpack will fallback to 'production' for this value. Set 'mode' option to 'development' or 'production' to enable defaults for each environment.
You can also set it to 'none' to disable any default behavior. Learn more: https://webpack.js.org/concepts/mode/
```

如果没有错误，构建可以被视为成功。

请注意，警告不被视为错误。警告只是因为尚未设置模式而显示的。

我不会担心这个，因为 Webpack 将默认为生产模式。我们将在本指南的后面处理模式设置。

1.  当你在浏览器中打开`index.html`时，你应该看到以下文本：

```js
Testing Webpack5
```

万岁——我们已经完成了我们的第一个应用程序捆绑，我敢打赌你一定为自己感到非常自豪！这是一个开始的基本步骤；我们将在后面的章节中继续学习 Webpack 的更复杂的元素，并开始将它们应用到需要捆绑的现有项目中。

# 摘要

总之，Webpack 5 是一个非常多才多艺的捆绑工具，几乎使用了每一种可想象的方法来优化应用程序的大小并提高整体性能。了解它是非常值得的，本指南将向你展示你需要了解的一切。

现在，你应该了解 Webpack 背后的基本概念，以及基本术语。你现在也应该知道如何安装先决条件，比如 Node.js，并设置和部署——以及制作——你的第一个捆绑使用命令行。

在下一章中，我们将详细介绍模块和代码拆分，以及 Webpack 5 的一些更显著和有趣的方面，这些方面对理解 Webpack 至关重要。

# 问题

以下是与本章相关的一系列问题，您应该尝试回答以帮助您的学习。答案可以在本书的*评估*部分中找到：

1.  什么是 Webpack？

1.  Webpack 中的捆绑包是什么？

1.  根据本指南，Webpack 的最新版本是多少？

1.  Webpack 在哪个环境中工作？

1.  什么是依赖图？

1.  在捆绑时，以下命令缺少哪个入口？

`npm --save lodash`

1.  我们在 Webpack 5 中使用的包管理器的名称是什么？

1.  如何使用命令行删除`lodash`库？

1.  在使用 Webpack 5 时，源代码和分发代码之间有什么区别？

1.  在设置项目时，为什么要调整`package.json`文件？


# 第二章：使用模块和代码拆分

本章将探讨 Webpack 5 中的模块和代码拆分。模块是一种按功能将代码分组的方式。代码拆分是 Webpack 用来自动构建这些模块的方法；它将项目中的代码分割成最适合完成项目的功能和结构的模块。

本章涵盖的主题如下：

+   解释模块

+   理解代码拆分

+   预取和预加载模块

+   最佳实践

# 解释模块

Webpack 使用称为模块的元素。它使用这些模块来构建依赖图。

模块是处理相关功能的代码部分；根据模块化构建项目将提高功能。例如，与未使用模块构建的项目相比，只有与相关操作相关的代码需要运行。

说到这里，下一件要理解的事情是模块的具体功能，这将在接下来的部分中讨论。

# 模块的功能

模块是一组代码片段：例如，相似语言的代码具有共同的功能——也就是说，它是应用程序中相同功能或操作的一部分。

通常，Webpack 5 中的模块根据使用的脚本语言进行分组，如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/wpk5-uprn/img/d145de8d-82c2-403f-a485-52765c3d1801.jpg)

前面的图表应该有助于说明大多数人在探索 Webpack 构建内容时看到的内容。

然后将应用程序分成模块和资产。正如我们在第一章中所解释的那样，资产基本上是开发人员不认为是脚本的图像和视频。然后，目录结构通常被细分为这些模块，通常在它们自己的目录中。

将应用程序分成模块将自然使调试过程更容易。这也将有助于我们进行验证和测试。

以这种方式构建应用程序可以确保在良好编写的代码和更加可疑的代码之间建立边界。当然，这有助于目录导航，因为每个模块都有一个明确定义的目的。

许多平台使用模块，这是一个您在一般的 Web 开发中肯定会习惯的术语。然而，每个平台略有不同。

Webpack 5 根据模块的依赖关系表达方式来形成这些模块。以下是 Webpack 5 表达它们的一些示例：

+   通过**2015 ECMAScript**的`import`语句

+   通过**CommonJS **的`require()`语句

+   通过**异步模块定义 **(**ASM**)的`define`和`require`语句

+   通过样式表中的 imageURL

+   通过样式表中的`@import`语句

总之，模块化的代码使事情变得更容易，了解 Webpack 如何表达依赖关系将帮助您了解应该如何编译代码。从这里开始，自然的下一步是查看支持的模块类型以及加载器如何与它们一起工作。

# 支持的模块语言和加载器

为了确保 Webpack 5 支持这些模块，它们必须用可以理解和处理的编程语言编写。Webpack 5 通过使用称为加载器的东西来实现这一点。

加载器使 Webpack 在竞争对手捆绑器中真正脱颖而出。简单来说，加载器告诉 Webpack 如何处理不是 JavaScript 或其他 Webpack 自动理解的预定义代码（如 JSON 或 HTML）的代码。Webpack 5 将会将这些处理过的代码作为依赖项包含在您的捆绑包中。

Webpack 5 拥有一个开发者社区，称为 Webpack 社区，他们构建了这些加载器。这些加载器目前支持大量的语言和处理器；一些例子如下：

+   **TypeScript**

+   **SASS**

+   **LESS**

+   **C++ **

+   **Babel**

+   **Bootstrap**

有关可用加载器的完整列表，请参阅本章末尾的“进一步阅读”部分。

成为 Webpack 社区的一部分意味着您可以编写自己的加载器！这是值得考虑的事情，因为这可能是满足项目要求的最佳方式。

有许多更多的加载器可用于 Webpack 社区。使用加载器意味着 Webpack 5 可以被描述为一个动态平台，允许定制几乎任何技术堆栈。在本章中，我们将开始积极地使用加载器作为一些示例用例的一部分，您可以练习自己编码。

在开发过程中，您可能会遇到“封装”一词，特别是在处理模块和加载器时。

要理解封装，您首先需要了解软件有时可以独立开发，直到需要互动才会出现。为了使软件在项目中一起工作，必须在两个技术堆栈之间创建一个依赖关系。这就是“封装”一词的含义。

封装是一个简单的主题，但模块化编码的下一个领域是解析。这是一个更广泛的主题，因此已经作为自己的子部分进行了详细说明。

启用新的资产模块类型是 v5 的一个实验性功能。资产模块类型类似于`file-loader`、`url-loader`或`raw-loader`（自 alpha.19 以来的`experiments.asset`）数据 URL 和相关选项自 beta.8 以来得到支持。

# 模块解析

模块解析是通过解析器进行的。解析器帮助您通过其绝对路径找到一个模块——在整个项目中通用的模块路径。

请注意，一个模块可以作为另一个模块的依赖项，例如以下情况：

```js
import example from 'path/to/module';
```

无论依赖模块是来自另一个库（而不是解析器本身）还是应用程序本身，解析器都将帮助找到所需的模块代码以包含在捆绑包中。Webpack 5 也可以在捆绑时使用`enhance-resolve`来解析路径。

Webpack 5 的解析规则意味着，使用`enhanced-resolve`方法，Webpack 5 可以解析三种文件路径：

+   绝对路径

+   相对路径

+   模块路径

以下部分将详细说明每个文件路径的含义，并且每个部分都将有一个示例。随着我们开始构建项目捆绑包，这将变得更加重要。

# 绝对路径

对于初学者来说，绝对路径是指文件路径和项目使用的所有文件和资产的位置。这个共同的位置有时被称为`home`或`root`目录。以下是一个命令行位置的示例：

```js
import 'C:\\Users\\project\\file';
```

前一行是绝对路径的一个示例。术语“绝对”是每个 JavaScript 开发人员都应该熟悉的内容。它涉及到系统中普遍存在的对象文件或目录的位置。

如果我们已经有了绝对路径，就像前一行一样，就不需要进一步解析了。

# 相对路径

相对路径是指一个对象文件或目录到另一个位置的位置。在这种情况下，它是“上下文”目录的位置——开发进行的当前工作位置：

```js
import '../src/file';
```

在前面的示例中，资源文件的目录被认为是“上下文”目录。资源文件是指`import()`语句、`require()`语句或对外部文件的调用发生的文件。

在这种情况下，相对路径与上下文目录路径相结合，然后产生绝对路径。

# 模块路径

模块路径是并非所有 JavaScript 开发人员都习惯的东西。在 Webpack 中，它指的是相对于模块的位置。在下面的代码片段中，`module`将被用于你希望使用的任何特定模块名称的名称——例如你项目中现有模块的名称：

```js
import 'module/sub-directory/file';
```

Webpack 5 搜索所有在`resolve.module`指令中指定的模块的目录。可以使用`resolve.alias`配置为每个原始模块文件路径创建别名。使用这种方法，Webpack 5 会检查文件路径以及它指向文件还是目录。

Webpack 5 有一个名为`resolve.extension`的选项。如果路径没有文件扩展名，这个解析器将指示 Webpack 可以用于解析的扩展名。这些可能包括`.js`、`.jsx`或类似的扩展名。

如果文件路径不指向文件而只指向目录，Webpack 5 会搜索该目录中的`package.json`文件。然后 Webpack 5 使用`resove.main`字段配置中指定的字段来搜索`package.json`中包含的字段，并从中确定要使用的正确上下文文件路径。

如果目录中没有`package.json`文件，或者主字段没有返回有效路径，Webpack 5 会简单地搜索`resolve.main`配置中指定的文件名。

文件扩展名的解析方式类似，但使用`resolve.extension`选项。

到目前为止，我们已经涵盖了模块、路径解析、支持的语言和加载程序。下一个重要的理解是代码拆分——它是什么，以及 Webpack 如何利用它来形成它的模块和一般输出。

# 理解代码拆分

代码拆分允许用户将代码拆分成各种捆绑包，然后按需或并行加载。Webpack 的开发人员认为这是 Webpack 的“最引人注目的功能之一”([Webpack.js.org](http://webpack.js.org))。

代码拆分有两个关键优势——这个过程可以用来实现更小的捆绑包，并控制资源加载的优先级。这可以导致加载时间的改善。

Webpack 5 中有三种通用的代码拆分方法：

+   **入口点**：这是使用入口点配置手动拆分代码。

+   **防止重复**：这种方法使用`SplitChunksPlugin`来运行一个称为**dedupe**的过程，将代码拆分成称为**chunks**的模块组。

+   **动态导入**：这种方法使用内联函数在模块内部进行**调用**以拆分代码。

一个 chunk 指的是一组模块。这是 Webpack 使用的一个术语，在其他平台上并不经常遇到。

dedupe 是一个使用机器学习快速执行匹配、**去重**和实体解析的 Python 库。它有助于从姓名和地址的电子表格中删除重复条目。

有了这三种方法的概述，我们现在可以在接下来的章节中详细讨论每一种方法。让我们从入口点开始。

# 入口点

使用入口点可能是执行代码拆分的最简单方法。这是一个手动操作，因此不像其他方法那样自动化。

我们现在将看一下从主捆绑包中拆分一个模块的开发。为此，我们将从一些实际工作开始。然后，我们将讨论重复和动态导入的概念。

我们现在将回到我们在第一章中工作的项目，*Webpack 5 简介*。这一次，我们将利用到目前为止在本章中学到的知识。

首先，创建一个工作目录。在这种情况下，我们使用了上一章中使用的目录名称。遵循相同的约定可能是一个好主意，这样你就可以在继续阅读本书的过程中跟踪项目的发展。

在下面的例子中，我们将做以下操作：

1.  组织一个项目文件夹结构，以开始一个展示入口点如何工作的项目。您应该在练习项目目录中构建这组目录。这与在桌面上创建文件夹的方式相同。为了本示例，我们将称此文件夹为`webpack5-demo`（但您可以选择任何您喜欢的名称）：

```js
package.json
webpack.config.js
/dist
/src
 index.js
/node_modules
/node_modules/another-module.js
```

1.  如果您使用的代码缺少最后一行文本（用粗体标记），请确保添加。这可以在命令行上完成；如果您决定使用命令行，请参考第一章，*Webpack 5 简介*，以获取指导。您可能已经注意到了`another-module.js`的包含。您可能不会认为这是一个典型的构建，但是您需要包含这个示例。

最终，您可以随意命名项目，但是为了遵循此实践项目，您应该使用到目前为止使用的相同命名约定以防混淆。

为了跟踪此项目的开发，使用您的**集成开发环境**（**IDE**）或记事本，您应该创建前面提到的每个文件和文件夹。`**/**`字符表示一个文件夹。请注意`another-module.js`文件；它位于`/node_modules`目录中。

现在，我们将编辑并编译一个构建，从`another-module.js`文件开始。

1.  在您选择的 IDE 或记事本中打开`another-module.js`：

```js
import _ from 'lodash';
console.log(
  _.join(['Another', 'module', 'loaded!'], ' ')
 );

// webpack.config.js 
 const path = require('path');
 module.exports = {
   mode: 'development',
   entry: {
     index: './src/index.js',
     another: './src/another-module.js'
 },
 output: {
   filename: '[name].bundle.js',
   path: path.resolve(__dirname, 'dist')
  }
 };
```

该文件基本上导入了`lodash`，确保加载的模块记录在控制台日志中，将 Webpack 构建模式设置为开发模式，并设置 Webpack 开始映射应用程序中的资产进行捆绑的入口点，并设置输出捆绑名称和位置。

1.  现在，通过在命令行中输入上下文目录的位置（您正在开发的目录）并输入以下内容来使用`npm`运行构建：

```js
npm run build
```

这就是您需要产生捆绑输出或开发应用程序的全部内容。

1.  然后，检查是否成功编译。当在命令行中运行构建时，您应该看到以下消息：

```js
...
 Asset Size Chunks Chunk Names
 another.bundle.js 550 KiB another [emitted] another
 index.bundle.js 550 KiB index [emitted] index
 Entrypoint index = index.bundle.js
 Entrypoint another = another.bundle.js
 ...
```

成功！但是，在使用开发人员应该注意的入口点时，可能会出现一些潜在问题：

+   如果入口块之间存在重复的模块，它们将包含在两个捆绑包中。

对于我们的示例，由于`lodash`也作为`./src/index.js`文件的一部分导入到项目目录中，它将在两个捆绑包中重复。通过使用`SplitChunksPlugin`可以消除此重复。

+   它们不能用于根据应用程序的编程逻辑动态拆分代码。

现在，我们将介绍如何防止重复。

# 使用 SplitChunksPlugin 防止重复

`SplitChunksPlugin`允许将常见依赖项提取到入口块中，无论是现有的还是新的。在以下步骤中，将使用此方法来从前面示例中去重`lodash`依赖项。

以下是从前面示例的项目目录中找到的`webpack.config.js`文件中的代码片段。此示例显示了使用该插件所需的配置选项：

1.  我们将首先确保我们的配置与前面示例中的配置相同：

```js
const path = require('path');
module.exports = {
  mode: 'development',
  entry: {
    index: './src/index.js',
    another: './src/another-module.js'
 },
 output: {
   filename: '[name].bundle.js',
   path: path.resolve(__dirname, 'dist')
 },
 optimization: {
   splitChunks: {
 chunks: 'all'
   }
  }
 };
```

使用`optimization.splitChunks`配置，重复的依赖项现在应该从`index.bundle.js`和`another.bundle.js`中删除。`lodash`已被分离到一个单独的块和主捆绑包中。

1.  接下来，执行`npm run build`：

```js
...
Asset Size Chunks Chunk Names
another.bundle.js 5.95 KiB another [emitted] another
index.bundle.js 5.89 KiB index [emitted] index
vendors~another~index.bundle.js 547 KiB vendors~another~index [emitted]    vendors~another~index
Entrypoint index = vendors~another~index.bundle.js index.bundle.js
Entrypoint another = vendors~another~index.bundle.js another.bundle.js
...
```

有其他由社区开发的加载器和插件可用于拆分代码。一些更值得注意的例子如下：

+   `bundle-loader`：用于拆分代码和延迟加载生成的捆绑包

+   `promise-loader`：类似于`bundle-loader`，但使用 promises

+   `mini-css-extract-plugin`：用于从主应用程序中拆分 CSS

现在，通过对如何防止重复的理解牢固，我们将转向一个更困难的主题——动态导入。

# 动态导入

动态导入本质上是 Webpack 上的按需导入。如果您已经捆绑了大量代码，但需要对其进行补丁，动态导入方法将会派上用场。这还包括动态代码拆分，即在构建包后拆分代码并优化它。

Webpack 5 支持两种方法来做到这一点：

+   第一种方法使用了`import()`语法，符合 ECMAScript 的动态导入提案。

+   第二种是**特定于 webpack**的方法，使用`require.ensure`方法（这是一种传统方法）。

以下是第一种方法的示例；目标是演示使用动态导入的现代方法，这在最近的项目中将更常见。

`import()`调用是对承诺的内部调用。**承诺**指的是从加载程序返回的信息。

在与旧版浏览器一起使用`import()`时，使用`polyfill`函数，例如`es6-promise`或`promise-polyfill`，来**模拟承诺**。`shim-loader`是一个在 Webpack 5 环境中转换代码以使其工作的加载程序；这与使用`imports-loader`和`exports-loader`手动执行类似。

下一步是删除配置文件中的任何多余条目，其中包括`optmization.splitChunks`的引用，因为在接下来的演示中将不需要它：

1.  现在，打开`webpack.config.js`文件并进行以下条目：

```js
const path = require('path');
module.exports = {
 mode: 'development',
 entry: {
   index: './src/index.js'
   index: './src/index.js',
 },
 output: {
   filename: '[name].bundle.js',
   chunkFilename: '[name].bundle.js',
   path: path.resolve(__dirname, 'dist')
 },
 };
```

请注意`chunkFilename`的使用，它确定非入口块文件的名称。

前面的配置是为了准备您的项目使用动态导入。确保删除粗体文本，因为在处理相同代码时可能会看到这些。

回到项目中，我们需要更新它以删除未使用的文件的说明。

您可能已经设置了练习目录；但是，建议您从不包含任何实验代码的新目录集开始。

以下演示将使用动态导入来分离一个块，而不是静态导入`lodash`。

1.  打开`index.js`文件，确保进行以下条目：

```js
function getComponent() {
  return import(/* webpackChunkName: "lodash" */ 'lodash').then((
      { default: _ }) => {
 var element = document.createElement('div');

 element.innerHTML = _.join(['Hello', 'Webpack'], ' ');

 return element;

 }).catch(error => 'An error occurred while loading 
     the component');
 }

  getComponent().then(component => {
    document.body.appendChild(component);
  })
```

在导入`CommonJS`模块时，此导入将不会解析`module.exports`的值；而是将创建一个人工命名空间对象。因此，在导入时我们需要一个默认值。

在注释中使用`webpackChunkName`将导致我们的单独包被命名为`lodash.bundle.js`，而不仅仅是`[your id here].bundle.js`。有关`webpackChunkName`和其他可用选项的更多信息，请参阅`import()`文档。

如果现在运行 Webpack，`lodash`将分离成一个新的包。

1.  可以使用**命令行界面**（**CLI**）运行`npm run build`。在 CLI 实用程序中，键入以下内容：

```js
npm run build
```

运行构建时，您应该看到以下消息：

```js
...
 Asset Size Chunks Chunk Names
 index.bundle.js 7.88 KiB index [emitted] index
 vendors~lodash.bundle.js 547 KiB vendors~lodash [emitted] vendors~lodash
 Entrypoint index = index.bundle.js
 ...
```

`import()`可以与异步函数一起使用，因为它返回一个承诺。这需要使用预处理器，例如`syntax-dynamic-import` Babel 插件。

1.  使用`src/index.js`，进行以下修改以显示代码如何可以简化：

```js
async function getComponent() {
 'lodash').then(({ default: _ }) => {
const element = document.createElement('div');
const { default: _ } = await import(/* webpackChunkName: "lodash" */ 'lodash');

element.innerHTML = _.join(['Hello', 'webpack'], ' ');

return element;
}

  getComponent().then(component => {
    document.body.appendChild(component);
  });
```

前面的示例使用了我们在*动态导入*部分中使用的相同文件。我们将多行代码转换为单行代码，用异步代码替换了返回函数，加快了我们的编码实践。您会发现它现在比以前的代码简单得多——它使用了相同的文件`src/index.js`，并实现了相同的功能。

我们经常简化代码以帮助加载时间。改善浏览速度的另一个关键方法是缓存。

# 缓存

在我们完成代码拆分的这一部分之前，我们将介绍缓存。缓存与之前的过程有关，毫无疑问，在编程过程中会遇到。对于初学者来说，缓存是存储先前计算的数据以便更快地提供的方法。它还与下一节关于预取和预加载有关，这些方法控制内存的使用方式。

了解缓存将确保您知道如何更有效地拆分代码。在下一个示例中，我们将看到如何做到这一点。在 Webpack 中，缓存是通过**文件名哈希**（当计算机递归跟踪文件位置时）完成的，特别是输出包的哈希化：

```js
 module.exports = {
   entry: './src/index.js',
   plugins: [
    // new CleanWebpackPlugin(['dist/*']) for < v2 versions 
       of CleanWebpackPlugin
    new CleanWebpackPlugin(),
    new HtmlWebpackPlugin({
      title: 'Output Management',
      title: 'Caching',
   }),
 ],
 output: {
  filename: 'bundle.js',
  filename: '[name].[contenthash].js',
  path: path.resolve(__dirname, 'dist'),
  },
};
```

请注意前面的代码块中的`output`键处理程序；在括号内，您将看到`bundle.js`文件名，下面是我们称之为哈希的内联元素。您应该用您的偏好替换括号内的术语。这种方法产生了一种替代输出，只有在内容更新时才会更新，并作为我们的缓存资源。

每个文件系统访问都被缓存，以便同一文件的多个并行或串行请求更快。在`watch`模式下，只有修改的文件才会从缓存中删除。如果关闭`watch`模式，则在每次编译之前都会清除缓存。

这将引导我们进入下一节，这也与导入有关——预取和预加载。

# 预取和预加载模块

在声明导入时，Webpack 5 可以输出一个**资源提示**。它会给浏览器以下命令：

+   `preload`（可能在当前导航期间需要）

+   `prefetch`（可能在未来的导航中需要）

“当前”和“未来”这些术语可能会令人困惑，但它们基本上指的是`prefetch`在用户需要之前加载内容，以某种方式提前加载和排队内容。这是一个简单的定义——接下来会有一个完整的解释——但总的来说，您可以从内存使用和用户体验的效率方面看到优缺点。

需要注意的是，在 Webpack 5 中，预取对**Web Assembly**（**WASM**）尚不起作用。

这个简单的`prefetch`示例可以有一个`HomePage`组件，它渲染一个`LoginButton`组件，当被点击时加载一个`LoginModal`组件。

`LoginButton`文件需要被创建；按照`LoginButton.js`中的说明进行操作：

```js
import(/* webpackPrefetch: true */ 'LoginModal');
```

前面的代码将导致以下代码片段被附加到页面的头部：

```js
 <linkrel="prefetch" href="login-modal-chunk.js"> 
```

这将指示浏览器在空闲时预取`**login-modal-chunk.js**`文件。

与`prefetch`相比，`preload`指令有很多不同之处：

+   使用`preload`指令的块与其父块并行加载，而预取的块在父块加载完成后开始加载。

+   当预加载时，块必须由父块立即请求，而预取的块可以随时使用。

+   使用`preload`指令的块在调用时立即下载。在浏览器空闲时下载预取的块。

+   简单的`preload`指令可以有组件，它们总是依赖应该在单独块中的库。

使用`preload`或`prefetch`的选择在很大程度上取决于上下文；随着教程的进行，您将发现这可能如何适用于您。

根据前面的要点，您应该根据您的开发需求选择使用`prefetch`或`preload`。这在很大程度上取决于项目的复杂性，最终是开发人员做出的判断。

以下示例提出了一个想象的组件`ChartComponent`，在`ChartComponent.js`中需要一个我们称之为`ChartingLibrary`的库。它会在需要时立即导入库，并在渲染时显示`LoadingIndicator`：

```js
import(/* webpackPreload: true */ 'ChartingLibrary');
```

当请求`ChartComponent`时，也会通过`<link rel="preload">`请求`charting-library-chunk`。

假设`page-chunk`加载完成得更快，页面将显示为`LoadingIndicator`，直到`charting-library-chunk`加载完成。这将提高加载时间，因为它只需要一个循环处理而不是两个。这在高延迟环境中尤其如此（在这些环境中，数据处理网络经常发生延迟）。

使用`webpackPreload`不正确可能会损害性能，因此在使用时要注意。

版本 5 中添加的一个功能是有用的，并与获取相关，即顶级等待，这是一个使模块可以作为大型异步函数的功能。这意味着它们将被异步处理。使用顶级等待，**ECMAScript 模块**（**ESM**）可以等待资源，导致导入它们的其他模块在开始评估主体之前等待。

现在您应该了解了`prefetch`和`preload`的目的，以及如果使用不正确会如何影响性能。关于它们的使用决定将在很大程度上取决于您希望应用程序的性能如何。最好的方法是在进行正式捆绑包分析后再决定它们的使用，我们将在下一节中讨论。

# 最佳实践

与所有编程一样，有最佳实践可以确保最佳交付。这也是结束本章的一个很好的方式。如果遵循最佳实践，开发人员可以保护他们的应用程序免受安全漏洞和黑客攻击、性能不佳以及在团队协作或未来开发需要新开发人员时出现困难，从而使构建具有未来性。这后一点更适用于产品所有者或项目经理，而不是开发团队。

在 Webpack 方面，这里最重要的领域将是捆绑包分析和代码清理。

# 捆绑包分析

一旦开始拆分代码，分析输出并检查模块的最终位置将是有用的。充分利用捆绑包非常重要，因此捆绑包分析的正式程序可以被视为基本的，以及浏览器和安全性测试。建议使用官方分析工具。还有一些其他选项：

+   `webpack-bundle-analyzer`：这是一个插件和 CLI 实用程序，它将捆绑包内容表示为方便的交互式**树状图**，其中有缩放选项。

+   `webpack-bundle-optimize-helper`：这个工具将分析您的捆绑包，并提出减小捆绑包大小的建议。

+   `webpack-visualizer`：这用于可视化分析捆绑包，以查看哪些模块占用了太多空间，哪些可能是重复的。

+   `webpack-chart`：这提供了一个用于 Webpack 统计的交互式饼图。

树状图是一种用于使用嵌套图形（通常是矩形）显示分层数据的方法。

所有先前提到的工具都将有助于优化，这是 Webpack 的主要目的。

# 代码清理

另一种改进应用程序的方法是通过删除不需要的代码。当自动化时，这通常被称为树摇，我们将在后面的章节中讨论。当手动进行时，它被称为代码清理。由于这是一个在编程中不经常遇到的短语，可能需要给出一个定义。

代码清理是删除不需要或多余代码的过程，就像从一件西装上除去绒毛一样。这可能包括未使用的编码工件、错误的代码或其他任何不需要的东西。Webpack 在与**Gulp**等任务运行器集成时使用自动化过程来执行此操作。这将在下一章第六章中讨论，*生产、集成和联合模块*。

如果您遵循这些步骤，那么毫无疑问，您的应用程序将发挥出最佳性能。代码拆分和模块化编程对于 Webpack 来说至关重要，需要牢固的理解，以防止在捆绑项目的复杂性不断提高时迷失方向。

# 总结

本章已经介绍了各种代码拆分实践，包括代码块和动态导入。现在，您将拥有扎实的知识基础，可以进行代码拆分和使用模块。这些是 Webpack 的基本特性，因此需要扎实的基础知识。

代码拆分和模块是 Webpack 应用程序结构上的必要性。对于需要大量编程的专业任务来说，代码块和动态导入将更加重要。

我们已经介绍了预取模块和捆绑分析——这些是需要清楚理解下一章内容的重要步骤，我们将在下一章中探讨配置的世界，了解其限制和能力，以及选项在其中发挥作用。

随着配置在 Webpack 开发中的中心地位和日常编程的重要性，这些概念变得更加重要。当涉及到生产环境并且需要项目正常运行时，选项变得更加重要。

为了测试您的技能，请尝试以下测验，看看您对本章涵盖的主题的理解是否达到标准。

# 问题

我们将以一组问题来结束本章，以测试您的知识。这些问题的答案可以在本书的后面，*评估* 部分找到。

1.  代码拆分和模块化编程有何不同？

1.  什么是代码块？

1.  动态导入与入口点有何不同？

1.  `preload` 指令与 `prefetch` 指令有何优势？

1.  代码清理是什么意思？

1.  术语“promise”是什么意思？

1.  `SplitChunksPlugin` 如何防止重复？

1.  `webpack-bundle-optimize-helper` 工具提供了什么？

1.  `webpack-chart` 插件的作用是什么？

1.  什么是树状映射？

# 进一步阅读

要查看完整的加载器列表，请转到 [`github.com/webpack-contrib/awesome-webpack`](https://github.com/webpack-contrib/awesome-webpack)。


# 第三章：使用配置和选项

本章将包括配置和选项的实际用法，以及它们在任何给定构建中的相互关系和作用。它还将详细说明输出管理，也就是捆绑过程的输出和资产管理，以及作为依赖图的一部分的资产。这将涵盖文件放置和文件结构等子主题。

模块用于解决 JavaScript 具有全局函数的特性。Webpack 与这些模块一起工作，并隔离了变量和函数的暗示全局性质。

配置和选项是必要的，以便充分利用 Webpack。每个项目都是定制的，因此每个项目都需要对其参数进行特定的定制。本章将详细探讨这两个主题的确切性质，每个主题的限制以及何时使用它们。

本章讨论以下主题：

+   理解配置

+   理解资产管理

+   理解输出管理

+   探索 Webpack 5 的选项

# 理解配置

通过使用配置文件，在 Webpack 中进行配置通常是`webpack.config.js`，除非在特殊情况下可以有一个以上的文件分配给这个任务。在`webpack.config.js`的情况下，它是一个 JavaScript 文件，应该被修改以改变任何特定项目的配置设置。

在启动时，Webpack 和 Webpack 5 不需要配置文件，但软件会将`src/index`识别为默认项目输入。它还将结果输出到名为`dist/main.js`的位置。这个输出将被"缩小"并优化为生产环境。

*缩小*，或*最小化*，简单地指的是 Webpack 的主要功能之一：将使用的代码量减少到最小。这是通过消除重复、错误或多余的代码来实现的。

然而，一个 Webpack 项目通常需要改变其默认配置。默认配置是 Webpack 在没有任何加载器或特殊参数的情况下运行的方式，比如在第一章中描述的*Webpack 5 简介*的*Webpack 工作原理*子部分。这是通过使用配置文件来完成的。开发人员应该创建一个名为`webpack.config.js`的文件，并将其放在项目的根文件夹中。这个文件将被 Webpack 自动检测和读取。

让我们通过探索使用多个配置文件来开始我们的讨论。

# 使用不同的配置文件

Webpack 5 提供了使用不同配置文件的选项，具体取决于情况。不仅如此，还可以使用命令行实用程序来更改正在使用的文件。在一个项目中使用多个捆绑包时，可能会遇到这种情况，这个主题将在本指南的后面详细介绍。以下代码片段显示了开发人员如何更改正在使用的配置文件。在这个例子中，一个文件被指向一个名为`package.json`的文件，这是 Webpack 经常使用的一个常见文件。这种技术被称为*config flag*：

```js
"scripts": {
  "build": "webpack --config example.config.js" }
```

请注意，Webpack 5 还允许自定义配置，正如在第一章中所解释的*Webpack 5 简介*，这是使用 Webpack 5 的一个显著优势。这是通过使用自定义配置文件来完成的。这与选项不同，因为这些变量不是使用**命令行界面**（**CLI**）设置的。

# 使用选项

在 Webpack 中，*选项*指的是通过命令行而不是配置文件进行的设置，这是通过修改配置脚本来完成的。

在下面的例子中，我们将首先修改配置文件，简单地为我们的选项教程奠定基础。

在接下来的配置中，Node 的**路径模块**被使用，并且前缀是`_dirname`全局变量。Node 的路径模块只是 Node 用于处理文件或目录路径的实用程序。在操作系统之间工作时可能会出现文件路径问题，这可以防止这些问题发生，并确保相对路径正常工作。

示例中涉及的文件名为`webpack.config.js`。我们将用它来设置项目的模式，并且我们需要在到达选项之前这样做：

```js
const path = require('path');

module.exports = {
  mode: "production", // "production" | "development" | "none"
  entry: "./app/entry", // string | object | array
```

在前面的代码块中，所选择的**模式**指示 Webpack 相应地使用其内置的优化。**entry**路径默认为`./src`。这是应用程序执行开始和捆绑开始的地方。

下面的代码块将显示相同文件的其余部分：

```js
output: {
  path: path.resolve(__dirname, "dist"), // string
 filename: "bundle.js", // string
  publicPath: "/assets/", // string
  library: "MyLibrary", // string,
 libraryTarget: "umd", // universal module definition
  },
```

代码片段的这一部分显示了与 Webpack 发出结果相关的选项。

所有输出文件的目标目录必须是绝对路径（使用**Node.js**路径模块）。

`filename`指示入口块的文件名模板，`publicPath`是**统一资源定位符**（**URL**），指的是相对于相关 HTML 页面解析到输出目录的路径。简而言之，这意味着从您可能使用的 HTML 页面到捆绑项目文件的文件路径。代码的其余部分涉及导出库的名称和导出库的性质。

接下来的主题涉及与模块相关的配置。在处理输出选项之后，这将是项目开发中的下一个逻辑步骤：

```js
module: { 
   rules: [
        {
        test: /\.jsx?$/,
        include: [
          path.resolve(__dirname, "app")
        ],
        exclude: [
          path.resolve(__dirname, "app/demo-files")
        ],
```

前面的代码块包括了对模块的规则，比如解析器选项和加载器的配置。这些都是匹配条件，每个都接受一个字符串或正则表达式。术语`test`的行为与`include`相同。它们都必须匹配，但对于`exclude`来说并非如此。`exclude`优先于`test`和`include`选项。

为了最佳实践，`RegExp`应该只在文件名匹配时用于`test`。在使用路径数组时，应优先使用绝对路径而不是`include`和`exclude`选项。`include`选项应优先于`exclude`方法：

```js
issuer: { test, include, exclude },
        enforce: "pre",
        enforce: "post",
        loader: "babel-loader",
        options: { presets: ["es2015"] },
},
      {
        test: /\.html$/,
        use: [ "htmllint-loader",
{
            loader: "html-loader",
            options: {
              / *...* /
            }
          }
        ]
      },
```

前面的代码块包括了对发行者和导入元素的来源的条件。代码还包括了标记这些规则的应用的选项，即使它们被覆盖了。然而，这是一个高级选项。

对`loader`的引用指示应用哪个加载器。这是相对于上下文位置解析的。自 Webpack 2 以来，加载器后缀不再是可选的，为了清晰起见。还有空间应用多个其他选项和加载器。

在相同的配置中，我们将探讨可以在同一过程中应用的规则和条件，如下面的代码块所示：

```js
{ oneOf: [ / rules / ] },
{ rules: [ / rules / ] },
{ resource: { and: [ / conditions / ] } }, 
{ resource: { or: [ / conditions / ] } },
{ resource: [ / conditions / ] },
{ resource: { not: / condition / } }],
    /* Advanced module configuration */
  },
  resolve: {
```

前面的代码块包括了嵌套规则，所有这些规则都与条件结合在一起是有用的。解释一下，注意以下每个命令及其表示的含义：

+   `and`选项只有在所有条件也匹配时才会进行匹配。

+   `or`匹配在条件匹配时应用——这是数组的默认值。

+   `not`指示条件是否不匹配。

还有一个选项用于解析模块请求；这不适用于解析加载器。以下示例显示了使用此`resolve`模块请求：

```js
modules: [
      "node_modules",
      path.resolve(__dirname, "app")
    ], extensions: [".js", ".json", ".jsx", ".css"], 
    alias: { 
              "module": "new-module",
              "only-module$": "new-module",
              "module": path.resolve(__dirname, "app/third/module.js"),
           },
},

  performance: {
    hints: "warning", // enum
    maxAssetSize: 200000, // int (in bytes),
    maxEntrypointSize: 400000, // int (in bytes)
    assetFilter: function(assetFilename) {
    return assetFilename.endsWith('.css') || assetFilename.endsWith('.js');
    }
  },
```

前面的代码块显示了我们在本节中一直在遵循的相同配置文件。然而，让我们看一下一些关键元素。在`path.resolve`处，这指的是要查找模块的目录。直接下面的`], extensions:`指的是使用的文件扩展名。

在此部分之后是代码，按降序列出模块名称的别名列表。模块的别名是相对于当前位置上下文导入的，如下面的代码块所示：

```js
devtool: "source-map", // enum
context: __dirname, // string (absolute path!)
target: "web", // enum
externals: ["react", /^@angular/],
serve: { //object
    port: 1337,
    content: './dist',
    // ...
  },
stats: "errors-only",
```

`devtool`配置通过为浏览器添加元数据来增强调试。请注意，`source-map`选项可能更详细，但这是以构建速度为代价的，`web`选项指示 Webpack 的主目录。入口和`module.rules.loader`选项相对于此目录解析，并指的是捆绑包应该运行的环境。`serve`配置允许您为`webpack-serve`提供选项，并精确控制显示哪些捆绑信息，例如以下内容：

```js
devServer: { proxy: { // proxy URLs to backend development server '/api': 'http://localhost:3000' },
    contentBase: path.join(__dirname, 'public'), 
    compress: true, 
    historyApiFallback: true, 
    hot: true, 
    https: false, 
    noInfo: true, 

  },
  plugins: [

  ],
  // list of additional plugins
```

让我们解释前面的代码块。当它声明`compress: true`时，这启用了内容的**gzip**压缩。`historyApiFallback: true`部分是当遇到任何 404 页面加载错误时为真。`hot: true`文本指的是是否允许热模块替换；这取决于是否首先安装了`HotModuleReplacementPlugin`。`https`应设置为`true`以用于自签名对象或证书授权对象。如果`noInfo`键设置为`true`，则只会在热重新加载时获得错误和警告。

配置完成，现在可以运行构建。要做到这一点，使用以下命令：

```js
npx webpack-cli init
```

一旦在命令行环境中运行了前面的代码，用户可能会被提示安装`@webpack-cli/init`，如果它尚未安装在项目中。

运行`npx webpack-cli init`后，根据配置生成期间所做的选择，可能会在项目中安装更多的包。以下代码块显示了运行 NPX Webpack 的 CLI 初始化时的输出：

```js
npx webpack-cli init

 INFO For more information and a detailed description of each question, have a look at https://github.com/webpack/webpack-cli/blob/master/INIT.md
 INFO Alternatively, run `webpack(-cli) --help` for usage info.

 Will your application have multiple bundles? No
 Which module will be the first to enter the application? [default: ./src/index]
 Which folder will your generated bundles be in? [default: dist]:
 Will you be using ES2015? Yes
 Will you use one of the below CSS solutions? No

  babel-plugin-syntax-dynamic-import@6.18.0
  uglifyjs-webpack-plugin@2.0.1
  webpack-cli@3.2.3
  @babel/core@7.2.2
  babel-loader@8.0.4
  @babel/preset-env@7.1.0
  webpack@4.29.3
  added 124 packages from 39 contributors, updated 4 packages and audited 
  25221 packages in 7.463s
  found 0 vulnerabilities

Congratulations! Your new webpack configuration file has been created!

```

如果你在 CLI 中的输出看起来像前面的代码块，那么你的配置就成功了。这基本上是从命令行自动读取的，应该表示在前面的代码块中设置的所有选项都已记录。

我们已经通过配置和选项，你现在应该知道每个选项的区别和使用范围。现在自然而然地转向资产管理。

# 理解资产管理

资产主要通过依赖图进行管理，我们在第一章中已经介绍过，*Webpack 5 简介*。

在 Webpack 伟大的出现之前，开发人员会使用诸如**grunt**和**gulp**之类的工具来处理这些资产，并将它们从源文件夹移动到生产目录或开发目录（通常分别命名为`/build`和`/dist`）。

JavaScript 模块也使用了相同的原则，但 Webpack 5 会动态捆绑所有依赖项。由于每个模块都明确声明了它的依赖项，未使用的模块将不会被捆绑。

在 Webpack 5 中，除了 JavaScript 之外，现在还可以包含任何其他类型的文件，使用加载器。这意味着使用 JavaScript 时可能的所有功能也可以被利用。

在接下来的小节中，我们将探讨实际的资产管理。将涵盖以下主题：

+   为资产管理配置设置项目

+   加载**层叠样式表**（**CSS**）文件

+   加载图像

+   加载字体

+   加载数据

+   添加全局资产

然后，将有一个小节来总结。

每个小节都将有步骤和指导内容要遵循。这可能是一个相当大的主题，所以紧紧抓住！我们将从准备项目的配置开始。

# 为资产管理配置设置项目

为了在项目中设置资产管理配置，我们需要通过以下步骤准备我们的项目索引和配置文件：

1.  首先，通过使用`dist/index.html`文件对示例项目进行微小的更改，如下所示：

```js
  <!doctype html>
  <html>
    <head>
    <title>Asset Management</title>
    </head>
    <body>
     <script src="img/bundle.js"></script>
    </body>
  </html>
```

1.  现在，使用`webpack.config.js`编写以下内容：

```js
  const path = require('path');

  module.exports = {
    entry: './src/index.js',
    output: {
     filename: 'bundle.js',
     path: path.resolve(__dirname, 'dist')
    }
  };
```

前面的两个代码块只是显示了一个占位符索引文件，我们将用它来进行资产管理的实验。后一个代码块显示了一个标准配置文件，将索引文件设置为第一个入口点，并设置输出捆绑包的名称。这将在我们完成资产管理实验后为我们的项目准备捆绑。

您的项目现在已经设置好了资产管理配置。本指南现在将向您展示如何加载 CSS 文件。

# 加载 CSS 文件

示例项目现在将显示 CSS 的包含。这是一个非常容易掌握的事情，因为大多数从 Webpack 5 开始的前端开发人员应该对它很熟悉。

要加载 CSS 并运行构建，请执行以下步骤：

1.  首先，使用以下命令行指令将`style-loader`和`css-loader`安装并添加到项目的模块配置中：

```js
npm install --save-dev style-loader css-loader
```

1.  接下来，向`webpack.config.js`文件添加以下内容：

```js
  const path = require('path');

  module.exports = {
    entry: './src/index.js',
    output: {
      filename: 'bundle.js',
      path: path.resolve(__dirname, 'dist')
    },
   module: {
     rules: [
       {
         test: /\.css$/,
         use: [
           'style-loader',
           'css-loader'
         ]
       }
     ]
   }
  };
```

从前面的代码块中可以看出，以下添加是指向代码块末尾的`style-loader`和`css-loader`的使用。为了避免出现错误，您应该确保您的代码与示例相符。

`style-loader`和`css-loader`之间的区别在于前者确定样式将如何被注入到文档中，比如使用样式标签，而后者将解释`@import`和`require`语句，然后解析它们。

建议同时使用这两个加载程序，因为几乎所有**CSS**操作在项目开发的某个阶段都涉及这些方法的组合。

在 Webpack 中，正则表达式用于确定应该查找哪些文件并将其提供给特定的加载程序。这允许将样式表导入到依赖它进行样式设置的文件中。当运行该模块时，一个带有字符串化 CSS 的`<style>`标签将被插入到 HTML 文件的`<head>`中。

1.  现在，导航到目录结构，我们可以在以下示例中看到：

```js
webpack5-demo 
package.json 
webpack.config.js 
/dist 
bundle.js 
index.html 
/src  
style.css 
index.js 
/node_modules
```

从这个结构中我们可以看到有一个名为`style.css`的样式表。我们将使用这个来演示`style-loader`的使用。

1.  在`src/style.css`中输入以下代码：

```js
.hello {
  color: blue;
}
```

上面的代码只是创建了一个颜色类样式，我们将使用它来附加样式到我们的前端，并展示 CSS 加载的工作原理。

1.  同样，将以下内容追加到`src/index.js`中：

```js
  import _ from 'lodash';
  import './style.css';

  function component() {
    const element = document.createElement('div');

    // Lodash, now imported by this script
    element.innerHTML = _.join(['Hello', 'Webpack'], ' ');
    element.classList.add('hello');

    return element;
  }

  document.body.appendChild(component());
```

前面的代码都发生在`index.js`文件中。它基本上创建了一个 JavaScript 函数，该函数在从浏览器调用它的任何文件中插入一个`<div>`元素。在这个示例中，它将是`index.html`文件，在目录结构示例中提到的。前面的代码将在网页上“连接”一个**HTML**元素，其中包含文本“`Hello, Webpack`”。我们将使用这个来测试`style-loader`和`css-loader`是否被正确使用。正如脚本的注释部分所述，这个元素附加将自动导入`lodash`以便与 Webpack 一起使用。

1.  最后，运行`build`命令，如下所示：

```js
npm run build

...
    Asset      Size  Chunks             Chunk Names
bundle.js  76.4 KiB       0  [emitted]  main
Entrypoint main = bundle.js
...
```

当在浏览器窗口中打开`index.html`文件时，您应该看到“`Hello Webpack`”现在以蓝色样式显示。

要查看发生了什么，请检查页面（不是页面源代码，因为它不会显示结果），并查看页面的头标签。最好使用谷歌的 Chrome 浏览器进行。它应该包含我们在`index.js`中导入的样式块。

您可以并且在大多数情况下应该最小化 CSS 以获得更好的生产加载时间。

下一个自然的步骤是开始添加图片。图片可以以与任何网站应用程序相同的方式添加到项目中。将这些图片放在图像文件夹中以任何所需的格式。这必须在`/src`文件夹中，但它们可以放在其中的任何位置。下一个步骤是使用 Webpack 加载图片，我们现在将进行这一步。

# 加载图片

现在，让我们尝试使用文件加载程序加载图像和图标，这可以很容易地整合到我们的系统中。

要做到这一点，执行以下步骤：

1.  使用命令行，安装`file-loader`，如下所示：

```js
npm install --save-dev file-loader
```

1.  现在，使用通常的`webpack.config.js`Webpack 配置文件，对其进行以下修改：

```js
  const path = require('path');
  module.exports = {
    entry: './src/index.js',
    output: {
      filename: 'bundle.js',
      path: path.resolve(__dirname, 'dist')
    },
    module: {
      rules: [
        {
          test: /\.css$/,
          use: [
            'style-loader',
            'css-loader'
          ]
        },
        {
          test: /\.(png|svg|jpg|gif)$/, 
          use: [  
             'file-loader'
          ]
        }
      ]
    }
  };
```

现在，由于前面的代码块中的代码，当您导入图像时，该图像将被处理到输出目录，并且与该图像相关联的变量将在处理后包含该图像的最终**URL**。当使用`css-loader`时，类似的过程将发生在**CSS**文件中图像文件的**URL**上。加载程序将识别这是一个本地文件，并将本地路径替换为输出目录中图像的最终路径。**`html-loader`**以相同的方式处理`<img src="img/my-image.png" />`。

1.  接下来，要开始添加图像，您需要导航到项目文件结构，看起来像这样：

```js
  webpack5-demo
  |- package.json
  |- webpack.config.js
  |- /dist
    |- bundle.js
    |- index.html
  |- /src
 |- icon.png
    |- style.css
    |- index.js
  |- /node_modules
```

这个结构看起来与之前的项目非常相似，直接用于大部分“加载 CSS 文件”教程，只是增加了`icon.png`图像文件。

1.  然后，导航到 JavaScript 前端文件`src/index.js`。以下代码块显示了内容：

```js
import _ from 'lodash'; import './style.css';  
import Icon from './icon.png'; 
function component() { 
    const element = document.createElement('div'); 
    // Lodash, now imported by this script 
        element.innerHTML = _.join(['Hello', 'Webpack'], ' '); 
        element.classList.add('hello');  
    // Add the image to our existing div.  
    const myIcon = new Image(); myIcon.src = Icon; 
    element.appendChild(myIcon); 
    return element; 
} 
document.body.appendChild(component());
```

从前面的代码块可以看出，导入**lodash**将允许您的页面的**HTML**附加`Hello Webpack`文本。除此之外，这段代码只是用一些巧妙的 JavaScript 设置了我们的网页和图像。它首先创建一个名为`Icon`的变量，并为其赋予图像文件的**URL**的值。在代码的后面，它将这个值分配给一个名为`myIcon`的元素的源。

1.  从这里开始，我们想要设置一些非常基本的样式来处理我们的图像。在`src/style.css`文件中，追加以下代码：

```js
  .hello {
    color: red;
    background: url('./icon.png');
  }
```

当然，它将显示您的图像图标作为我们在**HTML**中分配代码的`div`的背景，其中应用了`.hello`类的地方文本变为**红色**。

1.  运行新的构建并打开`index.html`文件，如下所示：

```js
npm run build

...
Asset                                 Size          Chunks         Chunk Names
da4574bb234ddc4bb47cbe1ca4b20303.png  3.01 MiB          [emitted]  [big]
bundle.js                             76.7 KiB       0  [emitted]         main
Entrypoint main = bundle.js
...
```

这将创建图标重复作为背景图像的效果。在`Hello Webpack`文本旁边还会有一个`img`元素。

通常，即使对于经验丰富的开发人员，这个命令也可能出错。例如，图像可能根本不加载，太大，或者无法正确捆绑。这可能是由多种因素造成的，包括以不寻常的方式使用加载程序。在使用长文件名时，Webpack 也可能会出现代码跳过的情况。

如果是这种情况，只需重复以下步骤：

1.  使用命令行安装`file-loader`。

1.  按照前面的示例修改`webpack.config.js`文件。

1.  检查项目文件结构和索引文件是否正确格式化以加载图像文件。

1.  检查**CSS**是否也按您的要求格式化。

1.  然后，使用`npm`和命令行运行构建。

1.  检查索引文件是否正确加载图像。

如果检查该元素，可以看到实际的文件名已更改为类似于`da4574bb234ddc4bb47cbe1ca4b20303.png`的内容。这意味着 Webpack 在源文件夹中找到了我们的文件并对其进行了处理。

这为您提供了一个管理图像的坚实框架。在下一小节中，我们将讨论 Webpack 资产的字体管理。

# 加载字体

现在，我们将在资产的上下文中检查字体。文件和 URL 加载程序将接受通过它们加载的任何文件，并将其输出到您的构建目录。这意味着我们可以将它们用于任何类型的文件，包括字体。

我们将首先更新 Webpack 配置 JavaScript 文件，需要处理字体，如下所示：

1.  确保更新配置文件。我们在这里更新了通常的`webpack.config.js`配置文件，但您会注意到在末尾添加了一些字体类型，例如`.woff`、`.woff2`、`.eot`、`.ttf`和`.otf`，如下面的代码块所示：

```js
  const path = require('path');

  module.exports = {
    entry: './src/index.js',
    output: {
      filename: 'bundle.js',
      path: path.resolve(__dirname, 'dist')
    },
    module: {
      rules: [
        {
          test: /\.css$/,
          use: [
            'style-loader',
            'css-loader'
          ]
        },
        {
          test: /\.(png|svg|jpg|gif)$/,
          use: [
            'file-loader'
          ]
        },
       {
         test: /\.(woff|woff2|eot|ttf|otf)$/,
         use: [
           'file-loader'
         ]
       }
      ]
    }
  };
```

此配置允许 Webpack 的`file-loader`合并字体类型，但我们仍然需要向项目添加一些字体文件。

1.  现在，我们可以执行将字体添加到源目录的基本任务。下面的代码块说明了文件结构，指示新字体文件可以添加的位置：

```js
  webpack5-demo
  |- package.json
  |- webpack.config.js
  |- /dist
    |- bundle.js
    |- index.html
  |- /src
    |- sample-font.woff
    |- sample-font.woff2
    |- icon.png
    |- style.css
    |- index.js
  |- /node_modules
```

注意`src`目录和`sample-font.woff`和`sample-font.woff2`文件。这两个文件应该被您选择的任何字体文件替换。**Web Open Font**（**WOFF**）格式通常建议与 Webpack 项目一起使用。

通过使用`@font-face`声明，可以将字体合并到项目的样式中。Webpack 将以与处理图像相同的方式找到本地 URL 指令。

1.  使用`src/style.css`文件更新样式表，以在我们的主页上包含示例字体。这是通过在代码块顶部使用字体声明和在下面使用类定义来完成的，如下面的代码块所示：

```js
 @font-face {
    font-family: 'SampleFont';
    src:  url('./sample-font.woff2') format('woff2'),
          url('./sample-font.woff') format('woff');
    font-weight: 600;
    font-style: normal;
  }

  .hello {
    color: blue;
 font-family: 'SampleFont';
    background: url('./icon.png');
  }
```

请注意，您必须将`'SampleFont'`文本更改为与您选择的字体文件相对应的文本。前面的代码显示了通过 CSS 加载字体以及设置自定义值，如`font-weight`和`font-style`。**CSS**代码然后使用`.hello`类将该字体分配给任何潜在的**HTML**元素。请注意，我们在前两个教程中已经为此准备好了我们的`index.html`文件，*加载 CSS* *文件*和*加载图像*。

1.  现在，像往常一样使用命令行实用程序以开发模式运行`npm`构建，如下所示：

```js
npm run build

...
                                 Asset      Size  Chunks                    Chunk Names
5439466351d432b73fdb518c6ae9654a.woff2  19.5 KiB          [emitted]
 387c65cc923ad19790469cfb5b7cb583.woff  23.4 KiB          [emitted]
  da4574bb234ddc4bb47cbe1ca4b20303.png  3.01 MiB          [emitted]  [big]
bundle.js                                 77 KiB       0  [emitted]         main
Entrypoint main = bundle.js
...
```

再次打开`index.html`，看看我们使用的`Hello Webpack`示例文本是否已更改为新字体。如果一切正常，您应该能看到变化。

这应该作为一个简单的教程来理解字体管理。下一节将涵盖文件的数据管理，如**可扩展标记语言**（**XML**）和**JavaScript 对象表示**（**JSON**）文件。

# 加载数据

另一个有用的资源是数据。数据是一个非常重要的要加载的资源。这将包括**JSON**、**逗号分隔值**（**CSV**）、**制表符分隔值**（**TSV**）和**XML**文件等文件。使用诸如`import Data from './data.json'`这样的命令默认情况下可以工作，这意味着**JSON**支持内置到 Webpack 5 中。

要导入其他格式，必须使用**加载器**。以下子节演示了处理所有三种格式的方法。应采取以下步骤：

1.  首先，您必须使用以下命令行安装`csv-loader`和`xml-loader`加载器。

```js
npm install --save-dev csv-loader xml-loader
```

前面的代码块只是显示了安装两个数据加载器的命令行。

1.  打开并追加`webpack.config.js`配置文件，并确保其看起来像以下示例：

```js
  const path = require('path');

  module.exports = {
    entry: './src/index.js',
    output: {
      filename: 'bundle.js',
      path: path.resolve(__dirname, 'dist')
    },
    module: {
      rules: [
        {
          test: /\.css$/,
          use: [
            'style-loader',
            'css-loader'
          ]
        },
        {
          test: /\.(png|svg|jpg|gif)$/,
          use: [
            'file-loader'
          ]
        },
        {
          test: /\.(woff|woff2|eot|ttf|otf)$/,
          use: [
            'file-loader'
          ]
        },
        {
          test: /\.(csv|tsv)$/,
          use: [
            'csv-loader'
          ]
        },
        {
          test: /\.xml$/,
          use: [
            'xml-loader'
          ]
        }
      ]
    }
  };
```

在前面的代码块中，下部显示了`csv-loader`和`xml-loader`的使用。这次需要进行的修改是将数据加载到我们的项目中。

1.  接下来，我们必须向源目录添加一个数据文件。我们将在我们的项目中添加一个**XML**数据文件，如下面代码块中的粗体文本所示：

```js
  webpack5-demo
  |- package.json
  |- webpack.config.js
  |- /dist
    |- bundle.js
    |- index.html
  |- /src
    |- data.xml
    |- samplefont.woff
    |- sample-font.woff2
    |- icon.png
    |- style.css
    |- index.js
  |- /node_modules
```

查看您**项目**文件夹的`src`目录中的前述`data.xml`文件。让我们更仔细地查看一下这个文件里的数据，如下所示：

```js
<?xml version="1.0" encoding="UTF-8"?>
<note>
  <to>Tim</to>
  <from>Jakob</from>
  <heading>Reminder</heading>
  <body>Call me tomorrow</body>
</note>
```

从前面的代码块中可以看出，内容是一个非常基本的**XML**数据集。我们将使用它来导入**XML**数据到我们项目的`index.html`页面中，并且需要正确格式化以确保其正常工作。

这四种类型的数据（**JSON**、**CSV**、**TSV**和**XML**）中的任何一种都可以被导入，并且您导入的`data`变量将包含解析后的 JSON。

1.  确保修改`src/index.js`文件以公开数据文件。注意`./data.xml`的导入，如下面的代码块所示：

```js
  import _ from 'lodash';
  import './style.css';
  import Icon from './icon.png';
  import Data from './data.xml';

  function component() {
    const element = document.createElement('div');

    // Lodash, now imported by this script
    element.innerHTML = _.join(['Hello', 'Webpack'], ' ');
    element.classList.add('hello');

    // Add the image to our existing div.
    const myIcon = new Image();
    myIcon.src = Icon;

    element.appendChild(myIcon);

    console.log(Data);

    return element;
  }

  document.body.appendChild(component());
```

这次我们只需要添加`import`函数，几乎没有别的东西，来演示使用方法。熟悉 JavaScript 的人也会知道如何轻松地运行他们的特定项目。

1.  运行构建并检查数据是否正确加载，方法如下：

```js
npm run build
```

运行`npm`构建后，可以打开`index.html`文件。检查控制台（例如在 Chrome 中使用**开发者工具**）将显示导入后记录的数据。

与项目架构相关的是为项目消耗安排全局资产的方式。让我们在下一小节中探讨这一点。

# 添加全局资产

以前述方式加载资产允许模块以更直观、实用和可用的方式进行分组。

与包含每个资产的全局资产目录不同，资产可以与使用它们的代码分组。以下文件结构或树演示了一个非常实用和可用的示例：

```js
  |- /assets
  |– /components
  |  |– /my-component |  |  |– index.jsx
  |  |  |– index.css
  |  |  |– icon.svg
  |  |  |– img.png
```

前面的例子使您的代码更具可移植性。如果您想将一个组件放在另一个目录中，只需将其复制或移动到那里。或者，如果您的开发工作遵循老式的方式，也可以使用基本目录。此外，别名也是一个选择。

# 用最佳实践结束教程

这是一个漫长的教程，你的一些代码可能已经出错了。清理这些代码并检查是否有任何错误是一个好习惯。

清理是一个好习惯。在接下来的部分中，*理解输出管理*，我们不会使用很多资产，所以让我们从那里开始。

1.  我们开始用项目目录**项目树**结束。让我们检查它们是否正确。它应该看起来像下面这样：

```js
  webpack5-demo
  |- package.json
  |- webpack.config.js
  |- /dist
    |- bundle.js
    |- index.html
  |- /src
    |- data.xml
    |- sample-font.woff
    |- sample-font.woff2
    |- icon.png
    |- style.css
    |- index.js
  |- /node_modules
```

在结束时，您应该删除与前面代码块中加粗文本相对应的文件。

这应该让你对项目文件和文件夹的外观有一个很好的了解。确保我们一直在使用的所有文件都在那里，并且在适当的文件夹中。

1.  让我们检查我们配置的格式。

在`webpack.config.js`上已经做了很多工作，我们必须确保内容格式正确。请参考以下代码块，并将其与您自己的代码进行对比，以确保正确。通常有用的是计算`{`的数量，并使用传统结构美化您的代码，以使这个过程更容易：

```js
  const path = require('path'); module.exports = {
    entry: './src/index.js',
    output: {
      filename: 'bundle.js',
      path: path.resolve(__dirname, 'dist')
    },
    module: {
      rules: [
        {
          test: /\.css$/,
          use: [
            'style-loader',
            'css-loader'
          ]
        },
        {
          test: /\.(png|svg|jpg|gif)$/,
          use: [
            'file-loader'
          ]
        },
        {
          test: /\.(woff|woff2|eot|ttf|otf)$/,
          use: [
            'file-loader'
          ]
        },
        {
          test: /\.(csv|tsv)$/,
          use: [
            'csv-loader'
          ]
        },
        {
          test: /\.xml$/,
          use: [
            'xml-loader'
          ]
        }
      ]
    }
  };
```

注意到对 CSS、图像文件、诸如`.woff`的字体以及独立处理程序中的数据文件（如`.csv`和`.xml`）的广泛引用。所有这些都很重要，您应该花时间确保脚本准确，因为这是一个广泛的主题和实际练习，所以很多东西可能被忽视。

1.  接下来，我们需要检查`src/index.js`文件的脚本，方法如下：

```js
  import _ from 'lodash';
 import './style.css';
  import Icon from './icon.png';
  import Data from './data.xml';

  function component() {
    const element = document.createElement('div');

 // Lodash, now imported by this script
    element.innerHTML = _.join(['Hello', 'Webpack'], ' ');
 element.classList.add('hello');

    // Add the image to our existing div.
    const myIcon = new Image();
    myIcon.src = Icon;

    element.appendChild(sampleIcon);

    console.log(Data);

    return element;
  }

  document.body.appendChild(component());
```

再次，我们在这里结束，以便在使用多个教程后代码是可重用的，所以请确保在您的版本中删除加粗的文本。

我们已经经历了一系列的资产管理操作，并以项目整理过程结束。为了使其正常运行，您的所有代码应该看起来像包装部分中的以前的代码块。

现在您应该对 Webpack 如何管理这些资产以及在使用 Webpack 时如何管理它们有了清晰的理解。通过整理文件结构和代码，我们现在可以开始输出管理。

# 理解输出管理

输出是指从源文件创建的包。源文件在 Webpack 中被称为输入。输出管理指的是对这些新打包文件的管理。根据 Webpack 在构建开始时运行的模式，这些包将是开发包还是生产包。

Webpack 从源文件生成输出或包的过程称为编译。编译是 Webpack 5 组装信息（包括资产、文件和文件夹）的过程。配置的主题涉及 Webpack 中可能的各种选项和配置，这些选项和配置将改变编译的样式和方法。

开发包允许一些定制（例如本地测试），但生产包是成品和完全压缩的版本，准备发布。

在本章中，资产已经手动添加到了**HTML**文件中。随着项目的发展，手动处理将变得困难，特别是在使用多个包时。也就是说，存在一些插件可以使这个过程变得更容易。

现在我们将讨论这些选项，但首先要准备您现在非常繁忙的项目结构，这将成为项目发展中越来越重要的实践。

# 输出管理教程准备

首先，让我们稍微调整一下项目文件结构树，使事情变得更容易。这个过程遵循以下步骤：

1.  首先，找到项目文件夹中的`print.js`文件，如下所示：

```js
  webpack5-demo
  |- package.json
  |- webpack.config.js
  |- /dist
  |- /src
    |- index.js |- print.js  |- /node_modules
```

注意我们项目结构的添加——特别是`print.js`文件。

1.  通过向`src/print.js`文件添加一些逻辑来追加代码，如下所示：

```js
export default function printIt() {
  console.log('This is called from print.js!');
}
```

您应该在`src/index.js`文件中使用`printIt()`JavaScript 函数，就像前面的代码块中所示。

1.  准备`src/index.js`文件，以导入所需的外部文件，并在其中编写一个简单的函数以允许交互，如下所示：

```js
  import _ from 'lodash';
  import printMe from './print.js';

  function component() {
    const element = document.createElement('div');
    const btn = document.createElement('button');

    element.innerHTML = _.join(['Hello', 'Webpack'], ' ');

    btn.innerHTML = 'Click here then check the console!';
    btn.onclick = printIt();

    element.appendChild(btn);

    return element;
  }

  document.body.appendChild(component());
```

我们已经更新了我们的`index.js`文件，在顶部导入了`print.js`文件，并在底部添加了一个新的`printIt();`函数按钮。

1.  我们必须更新`dist/index.html`文件。这次更新是为了准备拆分条目，并在下面的代码块中进行了说明：

```js
  <!doctype html>
  <html>
    <head>
      <title>Output Management</title>
      <script src="img/print.bundle.js"></script>
    </head>
    <body>
      <script src="img/app.bundle.js"></script>
    </body>
  </html>
```

前面的**HTML**脚本将加载`print.bundle.js`文件，以及下面的`bundle.js`和`app.bundle.js`文件。

1.  接下来，确保项目的配置符合动态入口点。`src/print.js`文件将被添加为新的入口点。输出也将被更改，以便根据入口点名称动态生成包的名称。在`webpack.config.js`中，由于这个自动过程，不需要更改目录名称。下面的代码块显示了`webpack.config.js`的内容：

```js
  const path = require('path');

  module.exports = {
    entry: './src/index.js',
    entry: {
      app: './src/index.js',
      print: './src/print.js'
    },
    output: {
      filename: 'bundle.js',
      filename: '[name].bundle.js',
      path: path.resolve(__dirname, 'dist')
    }
  };
```

配置简单地为我们正在工作的新文件`index.js`和`print.js`设置了新的入口点。

1.  确保您执行了构建。一旦您运行了`npm`构建，您将会看到以下内容：

```js
...
Asset           Size      Chunks                  Chunk Names
app.bundle.js   545 kB    0, 1  [emitted]  [big]  app
print.bundle.js  2.74 kB  1     [emitted]         print
...
```

在浏览器中打开`index.html`文件后，您会看到 Webpack 生成了`print.bundle.js`和`app.bundle.js`文件。我们现在应该检查它是否工作了！如果更改了入口点名称或添加了新的入口点，**index HTML**仍然会引用旧的名称。这可以通过`HtmlWebpackPlugin`来纠正。

# 设置 HtmlWebpackPlugin

`HtmlWebpackPlugin`将允许 Webpack 处理包含 JavaScript 的 HTML 文件。要开始使用它，我们需要使用命令行安装它，然后正确设置配置，如下所示：

1.  首先，使用命令行实用程序安装插件，然后调整`webpack.config.js`文件，如下所示：

```js
npm install --save-dev html-webpack-plugin
```

前面的代码块显示了在我们的项目中使用`HtmlWebpackPlugin`的安装。

1.  接下来，我们需要将插件合并到我们的配置中。让我们看一下与该插件相关联的`webpack.config.js`文件，如下所示：

```js
  const path = require('path');
 const HtmlWebpackPlugin = require('html-webpack-plugin');

  module.exports = {
    entry: {
      app: './src/index.js',
      print: './src/print.js'
    },
    plugins: [
 new HtmlWebpackPlugin({
        title: 'Output Management'
      })
    ],
    output: {
      filename: '[name].bundle.js',
      path: path.resolve(__dirname, 'dist')
    }
  };
```

注意`require`表达式和`plugins:`选项键的使用，这两者都允许使用插件。

在运行构建之前，请注意`HtmlWebpackPlugin`将默认生成它的`index.html`文件，即使`dist/`文件夹中已经有一个。因此，现有文件将被覆盖。

为了最佳实践，复制现有的索引文件并将其命名为`index2.html`。将这个新文件放在原文件旁边，然后运行构建。

1.  现在，使用命令行实用程序运行构建。一旦完成，你将在命令行实用程序窗口中看到以下结果，表明成功捆绑：

```js
...
           Asset       Size  Chunks                    Chunk Names
 print.bundle.js     544 kB       0  [emitted]  [big]  print
   app.bundle.js    2.81 kB       1  [emitted]         app
      index.html  249 bytes          [emitted]
...
```

打开代码编辑器或**记事本**中的`index.html`文件将会显示插件已经创建了一个新文件，并且所有的捆绑包都被自动添加了。

另外，为什么不看一下`html-webpack-template`，它在默认模板的基础上提供了一些额外的功能呢？

这就结束了我们对 Webpack 的`HtmlWebpackPlugin`的教程。在接下来的小节中，我们将再次开始整理你的项目目录。

# 清理分发目录

在项目开发过程中，`/dist`文件夹会变得相当混乱。良好的做法涉及良好的组织，这包括在每次构建之前清理`/dist`文件夹。有一个`clean-webpack-plugin`插件可以帮助你做到这一点，如下所示：

1.  首先安装`clean-webpack-plugin`。以下示例向你展示如何做到这一点：

```js
npm install --save-dev clean-webpack-plugin 
```

插件安装完成后，我们可以重新进入配置文件。

1.  使用**`webpack.config.js`**，在文件中进行以下条目：

```js
  const path = require('path');
  const HtmlWebpackPlugin = require('html-webpack-plugin');
 const CleanWebpackPlugin = require('clean-webpack-plugin');

  module.exports = {
    entry: {
      app: './src/index.js',
      print: './src/print.js'
    },
    plugins: [
 new CleanWebpackPlugin(),
      new HtmlWebpackPlugin({
        title: 'Output Management'
      })
    ],
    output: {
      filename: '[name].bundle.js',
      path: path.resolve(__dirname, 'dist')
    }
  };
```

注意使用`CleanWebpackPlugin`，继续使用`const`限定符。这将是`module.export`插件选项的添加，它将创建一个与插件相关联的新函数，并使插件在 Webpack 编译期间可用。

1.  现在你应该运行一个`npm`构建，这将会将一个捆绑包输出到`/dist`分发文件夹中。

运行`npm`构建后，可以检查`/dist`文件夹。假设过程正常，你应该只看到新生成的文件，不再有旧文件。

我们已经生成了很多文件，为了帮助我们跟踪，有一个叫做清单的东西，我们接下来会介绍。

# 利用清单

Webpack 可以通过清单知道哪些文件正在生成。这使得软件能够跟踪所有输出捆绑包并映射模块。为了以其他方式管理输出，利用清单是个好主意。

Webpack 基本上将代码分为三种类型：开发人员编写的源代码；第三方编写的供应商代码；以及 Webpack 的运行时清单，它负责所有模块的交互。

运行时和清单数据是 Webpack 在浏览器中运行时连接你的模块化应用程序所需的。

如果你决定通过使用浏览器缓存来提高性能，这个过程将成为一个重要的事情。

通过在捆绑文件名中使用内容哈希，你可以告诉浏览器文件内容已经改变，从而使缓存失效。这是由运行时和清单的注入引起的，它们会随着每次构建而改变。

Webpack 有`WebpackManifestPlugin`，可以将清单数据提取到一个**JSON**文件中。

现在你已经了解了动态向你的 HTML 中添加捆绑包，让我们深入开发指南。或者，如果你想深入更高级的主题，我们建议重新阅读上一章节第二章中的*代码拆分*部分。

# 探索 Webpack 5 的选项

选项是可以使用 CLI 进行更改的一组变量。另一方面，通过更改文件内容来进行配置。但是可以使用配置文件来调整选项的设置。以下是当前由 Webpack 5 支持的选项列表：

+   **异步模块定义**（**AMD**）

+   Bail

+   Cache

+   Loader

+   Parallelism

+   Profile

+   Records Path

+   Records Input Path

+   记录输出路径

+   Name

以下各节将更详细地描述和说明每个选项。我们将从一些东西开始，经过对 Webpack 配置的粗略检查后，可能会让你感到困惑：AMD 选项。

# AMD

**AMD**是一个`object bool: false`选项。它也是**异步模块定义**的缩写。本质上，它是为开发人员提供模块化 JavaScript 解决方案的格式。该格式本身是一个用于定义模块的提案，其中模块和依赖项都可以异步加载。

这允许您设置`require.amd`或`define.amd`的值。将`amd`设置为`false`将禁用**AMD**支持。

查看`webpack.config.js`文件，如下所示：

```js
module.exports = {
  amd: {
    jQuery: true
  }
};
```

**AMD**的流行模块，例如 jQuery 版本 1.7.0 至 1.9.1，只有在加载程序指示允许在同一页上使用多个版本时才会注册为**AMD**模块。另一个类似的选项，就布尔变量而言，是**Bail**。让我们仔细看一下。

# Bail

**Bail**是一个`bool`值。这将强制 Webpack 退出其捆绑过程。这将导致 Webpack 在第一个错误上失败，而不是容忍它。默认情况下，Webpack 将在终端（使用**HMR**时也在浏览器控制台）中以红色文本记录这些错误，但将继续捆绑。

要启用此选项，请打开`webpack.config.js`，如下所示：

```js
module.exports = {
  bail: true
};

```

如果您希望 Webpack 在某些情况下退出捆绑过程，这将非常有帮助。也许您只想要项目的一部分捆绑。这完全取决于您。接下来是缓存。

# Cache

缓存是一个指代`bool`对象的术语。它将缓存生成的 Webpack 模块和块；这提高了构建的速度。它通过在编译器调用之间保持对此对象的引用来实现。在**观察模式**和开发模式下，默认情况下启用缓存。

在观察模式下，在初始构建之后，Webpack 将继续监视任何已处理文件的更改。基本上，**Webpack 配置 JavaScript**文件应该在`module.export`运算符内包含`watch: true`操作数。

要启用缓存，可以在 webpack.config.js 中手动将其设置为`true`，如下例所示：

```js
module.exports = {
  cache: false
};
```

`webpack.config.js`文件显示了允许共享缓存所需的配置，如下所示：

```js
let SharedCache = {};

module.exports = {
  cache: SharedCache
};
```

前两个示例显示了缓存配置设置为`false`和`sharedCache`。这是 Webpack 中可以设置的两个布尔值。

警告：缓存不应在不同选项的调用之间共享。

Webpack 中还有一些可以设置的选项：Loader、Parallelism、Profile、Records Path、Records Input Path、Records Output Path 和 Name。让我们逐个进行解释，现在就开始吧。

# Loader

这被表示为`loader`，并在以下代码块中展示了在 loader 上下文中公开自定义值：

```js
use: [
    {
       loader: worker-loader
    }
]
```

您可以从前面的代码示例中看到如何在配置文件中使用此选项。这个示例对于遵循本指南并配置加载程序的任何人来说应该很熟悉。此示例仅使用`worker-loader`作为示例。其中一些选项是布尔值或二进制值，例如接下来要描述的`profile`选项。

# Profile

`profile`选项将捕获应用程序的配置文件，然后可以使用**Analyze**工具进行分析，如下面的代码片段所示：

```js
profile: true,
```

请注意，这是一个布尔值。您可以使用`StatsPlugin`来更好地控制配置文件。这也可以与`parallelism`选项结合使用以获得更好的结果。

# 并行性

并行性将限制并行处理模块的数量。这可以用于微调性能或更可靠的分析。以下示例将限制数字为`1`，但您可以根据需要更改：

```js
parallelism: 1
```

Webpack 5 允许并行处理模块以及并行捆绑。这可能会占用内存，因此应该在较大的项目上注意此选项。

随着项目变得更加复杂，您可能希望记录编译过程，这可以帮助跟踪错误和错误。**Records Path**将帮助您做到这一点，我们现在将更仔细地看一下。

# Records Path

Records Path 选项表示为字符串。应该使用此选项来生成包含记录的**JSON**文件。这些是用于在多个构建之间存储模块标识符的数据片段。这可以用于跟踪模块在构建之间的变化。要生成一个，只需指定一个位置，如下面的示例中使用`webpack.config.js`文件：

```js
module.exports = {
  recordsPath: path.join(__dirname, 'records.json')
};
```

如果您有一个使用代码拆分的复杂项目，记录非常有用。这些记录的数据可用于确保在处理拆分包时缓存的行为是否正确。

尽管编译器生成此文件，但应使用源代码控制来跟踪它，并随时间保留其使用历史记录。

设置`recordsPath`也会将`recordsInputPath`和`recordsOutputPath`设置为相同的位置。

# 记录输入路径

此选项表示为字符串`recordsInputPath`，如下面的代码块所示：

```js
module.exports = { 
recordsInputPath: path.join(__dirname, 'records.json'), 
};
```

它将指定从中读取最后一组记录的文件，并可用于重命名记录文件。相关的是 Records Output Path 选项，我们现在将对其进行讨论。

# 记录输出路径

Records Output Path 是一个**字符串**，用于指定记录应写入的位置。以下代码示例显示了如何在重命名记录文件时结合使用此选项与`recordsInputPath`。我们将使用`webpack.config.js`来完成这个操作：

```js
module.exports = {
  recordsInputPath: path.join(__dirname, 'records.json'),
  recordsOutputPath: path.join(__dirname, 'outRecords.json')
};
```

上述代码将设置记录写入的位置。如果是输入记录，它将被写入`__dirname/records.json`。如果是输出记录，它将被写入`__dirname/newRecords.json`。

我们需要讨论的下一个选项是 Name 选项。

# 名称

**Name**选项表示为**字符串**，表示配置的名称。在加载多个配置时应使用它。以下示例显示了应该成为`webpack.config.js`文件的一部分的代码：

```js
module.exports = {
  name: 'admin-app'
};
```

在使用多个配置文件时，上述代码非常有用。该代码将将此配置文件命名为`admin-app`。这为您提供了一份选项的详细清单以及如何使用它们。现在让我们回顾一下本章中涵盖的内容。

# 总结

本章遵循了配置文件、资产管理和选项的实践。本章开始时带领读者了解了 Webpack 和配置的各种功能，并探讨了如何管理这些资产并相应地控制内容。您被引导了解了输入和输出管理，以及加载外部内容，如字体和图像。从那里，本章带领我们了解了选项和两者之间的区别，并向读者解释了可以通过简单配置实现的选项可以实现的内容。

然后，您将通过常见的选项方法以及如何使用它们进行了指导。您现在已经完全了解了选项和配置。您现在应该知道两者之间的区别以及采用的最佳方法，无论可能需要哪种技术。

在下一章中，我们将深入研究 API 的加载器和插件世界。Webpack 的这些功能阐述了平台的能力，从配置和选项中跳跃出来。

您将了解加载器和插件之间的区别，以及加载器使用默认不支持的语言和脚本的基本性质。许多这些加载器是由第三方开发人员提供的，因此插件填补了加载器无法使用的功能差距，反之亦然。

然后将扩展 API 的类似主题。API 基本上用于将应用程序连接到网络上的远程应用程序。这使它们具有与加载器类似的特征，并且它们经常用于本机脚本不可用的地方。

# 问题

为了帮助你学习，这里有一组关于本章涵盖的主题的问题（你会在本指南的后面找到答案）：

1.  Webpack 5 中配置和选项的区别是什么？

1.  配置标志是什么？

1.  加载图像到 Webpack 项目需要哪个加载器？

1.  Webpack 允许导入哪种类型的数据文件而不使用加载器？

1.  Webpack 的清单记录表示什么？

1.  Bail 选项是做什么的？

1.  并行选项是做什么的？

1.  Records Input Path 选项是做什么的？

1.  将 AMD 设置为`false`会做什么？

1.  什么是编译？
