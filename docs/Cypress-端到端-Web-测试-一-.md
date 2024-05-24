# Cypress 端到端 Web 测试（一）

> 原文：[`zh.annas-archive.org/md5/CF3AC9E3793BF8801DD5A5B999C00FD9`](https://zh.annas-archive.org/md5/CF3AC9E3793BF8801DD5A5B999C00FD9)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Cypress 是一个专门用于进行前端测试的 JavaScript 自动化测试框架。Cypress 在重新发明测试的执行方式方面表现出色，特别是对于现代 Web。与 Selenium WebDriver 等其他测试框架不同，Cypress 运行速度更快，因为它在浏览器中运行，并且与其他测试框架相比，学习曲线更低。

使用前端应用程序的开发人员将能够利用这本实用指南的知识，并在端到端测试中发展他们的技能。这本书采用了实践方法来实施和相关方法，让您可以立即投入运行并提高生产力。

# 这本书适合对象

这本书适合测试专业人士、软件和 Web 测试人员，以及精通 JavaScript 的 Web 开发人员，可能熟悉或不熟悉自动化测试的概念。前三章提供了一个快速入门指南，将帮助您熟悉 Cypress 的工作原理，以及如何开始，如果您是一个完全的 Cypress 新手。如果您是一个想要迁移到 Cypress 并发现其功能的 Selenium 测试人员，您会发现这本书非常有用。需要对 Web 测试和 JavaScript 有很好的理解。

# 这本书涵盖了什么

*第一章*，*安装和设置 Cypress*，带您了解使用 Cypress 的基本知识，包括安装 Cypress 包、默认配置和自定义设置。在本章中，您将了解 Cypress 的工作原理，它运行所需的模块，测试文件命名建议，以及如何开始使用 Cypress。了解 Cypress 的工作原理将确保您能够掌握 Cypress 的内部工作原理，并能够全面理解 Cypress 框架的结构，从而能够独立安装和设置后续项目。

*第二章*，*Selenium WebDriver 和 Cypress 之间的区别*，我们将探讨 Cypress 与 Selenium WebDriver 的不同之处，并突出选择 Cypress 运行端到端测试的一些优缺点。在本章中，我们还将探讨使 Cypress 比 Selenium 更适合测试的因素，以及用户如何扩展其功能。

*第三章*，*使用 Cypress 命令行工具*，让您了解不同的 Cypress 命令，您可以使用这些命令来执行 Cypress 命令。本章将解释如何运行命令，以及如何使用 Cypress 命令调试应用程序。

*第四章*，*编写您的第一个测试*，将带您使用 Cypress 编写您的第一个测试。我们将从一个通过的测试开始，以检查一切是否正常工作，然后转移到一个失败的测试，然后我们将看到 Cypress 的行为以及自动重新加载功能是如何工作的。在本章的第二部分，我们将专注于更高级的场景，让您了解如何正确编写 Cypress 测试。

*第五章*，*调试 Cypress 测试*，深入探讨了 Cypress 包含的不同类型的工具，以帮助调试应用程序。使用 Cypress 的调试工具，您将学会如何回溯到每个命令的快照，查看执行过程中发生的不同页面事件，并可视化不同命令以及元素隐藏和发现的时间。您还将学会如何在命令快照之间前进和后退，以及以迭代方式暂停和逐步执行命令快照。

*第六章*, *使用 TDD 方法编写 Cypress 测试*，向您介绍了**测试驱动开发**（**TDD**）的概念以及如何将其应用于编写 Cypress 测试。您将学习如何使用 TDD 方法编写测试，以及如何在尚未开发的应用程序中实际应用 TDD。

*第七章*, *了解 Cypress 中的元素交互*，介绍了如何与 DOM 的各种元素进行交互。本章还将教您如何与动画交互，如何悬停在元素上，以及如何检查元素是否被禁用。通过本章结束时，您将能够舒适地浏览 DOM 元素并为元素编写有意义的测试。

*第八章*, *了解 Cypress 中的变量和别名*，探讨了如何通过使用别名来处理异步命令。我们还将确定通过使用别名可以简化测试的方法。最后，我们将确定如何在路由和请求中使用别名。

*第九章*, *Cypress 测试运行器的高级用法*，介绍了如何利用 Cypress 测试运行器编写更好的测试。我们将重点放在仪表板和选择器工具上。我们将学习如何使用仪表板来理解间谍和存根的概念，以及 Cypress 如何解释它们。

*第十章*, *练习-导航和网络请求*，向您展示了实际示例和练习，旨在练习如何使用和进行网络请求的导航。该练习还将结合别名和变量的概念，以确保您能够链接本书第二部分学到的不同概念。

*第十一章*, *练习-存根和间谍 XHR 请求*，介绍了理解 XHR 请求以及 Cypress 如何帮助存根需要太长时间或者复杂以接收响应的请求。Cypress 的存根将对确保实施的测试不会出现问题以及我们可以获得自定义响应而不是等待请求的服务器响应非常重要。

*第十二章*, *Cypress 中的视觉测试*，介绍了 Cypress 中的视觉测试工作原理。我们将探讨视觉测试是什么，不同类型的测试，以及现代网络中视觉测试的重要性。我们还将研究视口以及它们如何影响视觉测试的过程，最后看看视觉测试自动化工具，如 Applitools 和 Percy，我们可以使用它们进行视觉验证。

# 为了充分利用本书

您需要一些 JavaScript 的理解，还需要在您的计算机上安装 Node.js 和 Yarn 和 npm 软件包管理器。所有给出的代码示例都在 macOS 上进行了测试，并且应该在所有 Linux 操作系统上都可以正常工作。对于 Windows 操作系统，特别是最后三章，请在*技术要求*部分的信息框中阅读有关如何在 Windows 上运行命令的附加说明。在撰写本文时，所有示例都已经使用 Cypress 版本 6.2.1 进行了测试。

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/B15616_Preface_Table_1_AM.jpg)

重要提示

在出版时，本书是基于 Cypress 版本 6.2.1 编写的，一些功能可能已经被破坏或废弃。请查看我们的 GitHub 存储库以获取最新的代码更新和更改。

**如果您使用的是本书的数字版本，我们建议您自己输入代码或通过 GitHub 存储库访问代码（链接在下一节中提供）。这样做将帮助您避免与复制和粘贴代码相关的潜在错误。**

*始终尝试练习；它们不仅仅是为了好玩，而是精心设计帮助您学习和掌握章节内容。*

# 下载示例代码文件

您可以从您在[www.packt.com](http://www.packt.com)的账户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packt.com](http://www.packt.com)。

1.  选择**支持**选项卡。

1.  点击**代码下载**。

1.  在**搜索**框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用以下最新版本的解压缩或提取文件夹：

+   Windows 系统下使用 WinRAR/7-Zip

+   Mac 系统下使用 Zipeg/iZip/UnRarX

+   Linux 系统下使用 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/End-to-End-Web-Testing-with-Cypress`](https://github.com/PacktPublishing/End-to-End-Web-Testing-with-Cypress)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自我们丰富的书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`文本中的代码`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。例如："`cy.intercept()`命令监听 XHR 响应，并知道 Cypress 何时为特定的 XHR 请求返回响应。"

代码块设置如下：

```js
it('can wait for a comment response', () => {
      cy.request('https://jsonplaceholder.cypress.io/comments/6')
    .as('sixthComment');
      cy.get('@sixthComment').should((response) => {
        expect(response.body.id).to.eq(6)
    });
 });
```

任何命令行输入或输出都以以下方式编写：

```js
npm run cypress:open 
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。例如："要做到这一点，在浏览器中打开浏览器控制台，然后点击**网络**选项卡，然后选择**XHR 过滤器**选项。"

提示或重要说明

看起来像这样。


# 第一部分：Cypress 作为前端应用的端到端测试解决方案

本节重点介绍了我们将在整本书中使用的基本原则和开发方法论。这些入门章节对于更好地了解 Cypress、如何设置它以及它与 Selenium WebDriver 等其他测试工具的区别至关重要。

我们将首先看如何安装和设置 Cypress。然后，我们将涵盖 Cypress 架构的不同主题以及 Cypress 和 Selenium 之间的区别。然后，我们最终将开始编写我们的第一个测试，从中更好地理解如何正确调试 Cypress 测试。

在这一部分，我们将涵盖以下章节：

+   *第一章*, *安装和设置 Cypress*

+   *第二章*, *Selenium WebDriver 和 Cypress 之间的区别*

+   *第三章*, *使用 Cypress 命令行工具*

+   *第四章*, *编写您的第一个测试*

+   *第五章*, *调试 Cypress 测试*


# 第一章：安装和设置 Cypress

Cypress 是一个为现代 Web 应用程序构建和设计的端到端测试自动化框架。它专注于通过确保您可以在浏览器上编写、调试和运行测试而无需额外的配置或额外的包来消除测试中的不一致性。Cypress 作为一个独立的应用程序工作，并且可以在 macOS、Unix/Linux 和 Windows 操作系统上使用连字符应用程序或命令行工具进行安装。Cypress 主要是为使用 JavaScript 编写他们的应用程序的开发人员构建的，因为它可以用来测试在浏览器上运行的所有应用程序。在本章中，我们将涵盖以下主题：

+   在 Windows 上安装 Cypress

+   在 macOS 上安装 Cypress

+   通过直接下载安装 Cypress

+   打开 Cypress 测试运行器

+   切换 Cypress 浏览器

+   添加 npm 脚本

+   运行 Cypress 测试

通过本章结束时，您将了解如何在 Windows 和 Mac 操作系统上正确设置 Cypress 以及如何运行 Cypress 测试。您还将了解如何使用 npm 脚本来自动化运行测试和打开测试运行器的过程。

## 技术要求

Cypress 可以作为一个独立的应用程序安装在您的计算机上，并且可以在至少有 2GB RAM 并满足以下任一操作系统要求的机器上运行：

+   macOS 10.9 及以上版本（仅 64 位）

+   Linux Ubuntu 12.04 及以上版本，Fedora 21 和 Debian 8（仅 64 位）

+   Windows 7 及以上

为了在这里列出的操作系统之一上使用 Cypress，必须首先安装 Node.js 8 或更高版本。Node.js 是一个 JavaScript 运行时环境，允许在浏览器之外运行 JavaScript 代码。安装 Node.js 会安装 npm，它允许我们从[`www.npmjs.com/`](https://www.npmjs.com/)安装 JavaScript 包。npm 是 Node.js 的默认包管理器，用户可以使用它或使用第三方包管理器，如 Yarn。在本节中，我们将在 macOS 和 Windows 操作系统上安装 Cypress。

# 在 Windows 上安装 Cypress

在本节中，我们将在 Windows 操作系统上安装 Cypress 和 Node.js，以便我们可以运行我们的测试。

## 下载并安装 Node.js

以下步骤将指导您完成安装 Node.js：

1.  访问官方 Node.js 网站（[`nodejs.org/en/download/`](https://nodejs.org/en/download/)）。

1.  选择 Windows 安装程序选项。

1.  下载安装程序包。

1.  按照 Node.js 网站上的说明安装 Node.js 包。

接下来，让我们初始化项目。

## 初始化项目

作为最佳实践，Cypress 安装在项目所在的目录中；这样，我们可以确保 Cypress 测试属于项目。在我们的情况下，我们将在`Documents`内创建一个名为`cypress-tests`的文件夹，然后在安装 Cypress 时导航到该目录。我们可以在 Windows PowerShell 终端中使用以下命令来创建`cypress-tests`目录并导航到该目录：

```js
$ cd .\Documents
$ cd mkdir cypress-tests
```

成功运行这些命令后，我们将启动 PowerShell 并导航到我们刚刚创建的目录，使用以下命令：

```js
$ cd .\Documents\cypress-tests
```

创建目录后，我们将通过在 PowerShell 中运行以下命令来初始化一个空的 JavaScript 项目：

```js
$ npm init –y
```

这将创建一个默认的`package.json`文件，用于定义我们的项目。

## 在 Windows 上安装 Cypress

现在，我们将使用以下命令在我们的项目目录中使用 npm 安装 Cypress：

```js
$ npm install cypress --save-dev
```

运行此命令后，您应该能够看到 Cypress 的安装和安装进度。这种方法将 Cypress 安装为我们空项目的`dev`依赖项。

有关 macOS 安装，请参阅下一节主要部分。

## 总结-在 Windows 上安装 Cypress

在本节中，我们学习了如何在 Windows 操作系统上安装 Cypress。我们还学会了如何使用 PowerShell 向项目添加 Cypress，以及如何初始化一个空项目。在下一节中，我们将看看如何在 macOS 上安装 Cypress。

# 在 MacOS 上安装 Cypress

在本节中，我将使用 macOS 机器来安装 Cypress 和 Node.js。在本节结束时，您将学会如何初始化一个空的 JavaScript 项目，以及如何将 Cypress 测试框架添加到 macOS 中。我们还将深入探讨如何在我们的项目中使用 npm、Yarn 或直接 Cypress 下载。

## 安装 Node.js

以下步骤将指导您安装 Node.js：

1.  访问官方 Node.js 网站（[`nodejs.org/en/download/`](https://nodejs.org/en/download/)）。

1.  选择 macOS 安装程序选项。

1.  下载安装程序包。

1.  按照 Node.js 网站上的说明安装 Node.js 包。

接下来，让我们初始化项目。

## 初始化项目

要安装 Cypress，我们需要导航到项目文件夹，并在我们希望 Cypress 测试位于的位置进行安装。在我们的情况下，我们将在“文档”中创建一个名为`cypress-tests`的文件夹，然后在安装 Cypress 时使用我们的终端导航到该目录。然后，我们将启动我们的终端应用程序，并使用以下命令导航到我们刚刚创建的目录：

```js
$ cd  ~/Documents/cypress-tests
```

创建目录后，我们将通过运行以下命令初始化一个空的 JavaScript 项目：

```js
$ npm init –y
```

这将创建一个默认的`package.json`文件，用于定义我们的项目。

## 在 Mac 上安装 Cypress

要安装 Cypress，我们将使用 Node.js 捆绑的 npm 包管理器。为了实现这一点，我们需要运行以下命令：

```js
$ npm install cypress --save-dev
```

运行此命令后，您应该能够在`package.json`文件中看到 Cypress 的安装进度，并在命令行上看到安装进度。这种方法将 Cypress 安装为我们空项目的`dev`依赖项。

作为 Windows 和 macOS 都可以使用的替代包管理器，您可以使用 Yarn。我们将在下一节中看到如何使用 Yarn 安装 Cypress。

## 使用 Yarn 安装 Cypress

在 Windows 和 macOS 中，您可以选择另一种包管理器。可用的替代方案之一是 Yarn 包管理器。与 npm 一样，您首先需要使用 macOS Homebrew 包管理器下载 Yarn 包管理器，方法是运行以下命令：

```js
$ brew install yarn
```

就像 npm 一样，Yarn 可以管理项目的依赖关系，并且可以用作项目管理器。Yarn 比 npm 的一个优势是它能够以一种不需要重新下载依赖项的方式缓存已下载的包，因此更好地利用资源。

安装 Yarn 后，我们可以使用它来安装包，就像我们使用 npm 一样，方法是运行以下命令：

```js
$ yarn add cypress –dev
```

我们还有最后一种安装方法，即通过直接下载。这将在下一节中介绍。

## 通过直接下载安装 Cypress

我们可以通过直接下载在 Windows、Linux 或 macOS 上安装 Cypress。如果您不需要安装 Cypress 附带的依赖项，或者只是尝试 Cypress，这种方法是推荐的。重要的是要注意，尽管这是安装 Cypress 的最快方式，但这个版本不具备诸如记录测试到仪表板的功能。

以下步骤将指导您通过直接下载安装 Cypress：

1.  导航到[`cypress.io`](https://cypress.io)。

1.  选择**立即下载**链接。

Cypress 将自动下载，因为它将自动检测下载.zip 文件的用户的操作系统。然后，您应该解压缩 zip 文件并在不安装任何其他依赖项的情况下运行 Cypress。

## 总结-在 macOS 上安装 Cypress

在本节中，我们学习了如何使用 npm 在 macOS 上安装 Cypress 测试框架，以及如何初始化一个将利用 Cypress 测试的空 JavaScript 项目。我们还学习了如何使用 Yarn 软件包管理器安装 Cypress，以及如何在不使用任何软件包管理器的情况下直接下载 Cypress 到我们的项目中。在下一节中，我们将看看如何打开 Cypress 测试框架。

# 打开 Cypress

安装 Cypress 是编写端到端测试旅程的第一步；现在，我们需要学习如何使用 Cypress 提供的工具来使用图形用户界面和仪表板运行测试。有四种方法可以运行已在您的计算机上安装的 Cypress 可执行文件。打开 Cypress 后，您应该看到 Cypress 测试运行器。无论以哪种方式打开 Cypress，您所看到的测试运行器仪表板都是相同的。以下部分详细介绍了打开和运行 Cypress 的不同方法。

## 使用 Npx 运行

npx 用于执行 npm 包二进制文件，并且从版本 5.2 开始，所有 npm 版本都带有 npx。也可以使用 npm 从`npmjs.com`安装 npx。要使用 npx 运行 Cypress，您需要运行以下命令：

```js
 npx cypress open
```

## 使用 Yarn 运行

如果使用 Yarn 安装了 Cypress，您可以使用以下命令打开 Cypress：

```js
Yarn run cypress open
```

## 使用 node 模块路径运行

Cypress 也可以通过引用 node 模块上的安装根路径来运行。这可以通过使用`node_modules` bin 中 Cypress 可执行文件的完整路径或使用 npm bin 快捷方式来实现，如下节所示。

### 使用完整路径启动 Cypress

这种启动 Cypress 的方法引用了`node_modules`中安装的 Cypress 可执行文件，并通过运行可执行文件来打开 Cypress：

```js
$ ./node_modules/.bin/cypress open
```

### 使用快捷方式启动 Cypress

就像使用完整路径启动 Cypress 一样，这种方法以相同的方式启动 Cypress，但是它不是引用完整路径，而是使用 npm bin 变量来定位`node_modules` bin 文件夹的默认位置：

```js
$(npm bin)/cypress open
```

## 桌面应用程序启动

如果您将应用程序下载为桌面应用程序，您可以通过导航到解压后的 Cypress 文件夹的位置，并单击该文件夹中存在的 Cypress 可执行文件来打开 Cypress。

现在我们已经成功通过我们喜欢的方法打开了 Cypress，我们将看看如果我们不想使用 Cypress 捆绑的默认浏览器，我们如何在 Cypress 中选择替代浏览器。

## 总结-打开 Cypress

在本节中，我们学习了如何打开 Cypress 测试框架仪表板，以及如何以不同的方式运行 Cypress，包括使用*npx*、*Yarn*或*node_modules*路径运行 Cypress 仪表板。在下一节中，我们将学习如何切换在 Cypress 中运行的测试的浏览器。

# 切换浏览器

Cypress 在安装时默认使用 Electron 作为浏览器，但它也可以与其他兼容的浏览器集成，这些浏览器包含**Chromium 项目**，除了 Firefox。目前，Cypress 支持 Firefox 浏览器、Chrome 浏览器、Chromium 和 Edge 浏览器。启动 Cypress 时，它将自动查找运行机器上的所有兼容浏览器，您可以随时使用测试运行器在这些浏览器之间切换。要从一个浏览器切换到另一个浏览器，您需要点击右上角的浏览器按钮，并从下拉链接中选择替代浏览器。

Cypress 测试也可以通过命令行在不同的浏览器上运行或打开，可以通过在打开 Cypress 测试运行器或运行 Cypress 测试时指定浏览器来实现。所有基于 Chromium 的浏览器、Edge 和 Firefox 都可以使用以下命令在命令行中启动：

```js
$ cypress run --browser {browser-name}
```

命令中指定的`browser-name`可以是 Edge、Chrome 或 Firefox。要指定 Cypress 应启动的浏览器的路径，您可以选择使用浏览器的可执行二进制文件而不是浏览器的名称来运行浏览器名称，如下所示：

```js
$ cypress run --browser /path/to/binary/of/browser
```

能够在 Cypress 中切换浏览器可以确保用户可以在不同设备上运行其测试套件，并验证不同浏览器的输出在整个测试套件中是一致的。在 Cypress 上切换浏览器还可以确保测试的验证可以进行，并且所有元素可见或可以在一个浏览器上执行的操作也可以在另一个浏览器上执行。

让我们利用到目前为止所学到的知识来尝试使用 Cypress 进行实际练习。

## 练习

结合打开 Cypress 和切换浏览器的知识，尝试以下步骤：

1.  导航到我们在初始化 Cypress 时创建的文件夹。

1.  运行 Cypress 启动时自动生成的所有默认测试。

1.  在测试运行器上切换浏览器。

1.  使用不同的浏览器重新运行测试。

现在我们已经学会了如何在不同的浏览器中运行 Cypress 测试，在接下来的部分中，我们将探讨如何使用 npm 脚本自动化运行测试的过程。

## 回顾 - 切换浏览器

在本节中，我们学习了 Cypress 支持的不同浏览器以及如何切换不同的 Cypress 浏览器，无论是使用命令行还是使用 Cypress 仪表板。我们还进行了一个简单的练习，以帮助我们了解 Cypress 浏览器切换的工作原理，以及如何使用 Cypress 运行我们的测试。在下一节中，我们将学习如何将 npm 脚本添加到我们的`package.json`文件中，以自动化一些 Cypress 任务。

# 添加 npm 脚本

`scripts`是`package.json`的属性，它使用户能够通过 JavaScript 应用程序的命令行运行命令。npm 脚本可用于向应用程序的属性添加环境变量，将应用程序打包成生产就绪的捆绑包，运行测试，或自动化 JavaScript 应用程序中的任何其他活动。npm 脚本可以根据用户的偏好和应用程序进行自定义，也可以按照`npmjs.com`定义的方式使用。在本节中，我们将学习如何编写 npm 脚本来运行我们的 Cypress 测试，打开我们的 Cypress 测试，甚至组合不同的 npm 脚本以实现不同的结果。

## 打开 Cypress 命令脚本

要创建一个`scripts`命令来打开 Cypress，您需要编写脚本名称，然后添加 npm 在执行脚本时将运行的命令。在这种情况下，我们打开 Cypress 的命令将嵌入到一个名为`open`的脚本中。我们可以通过将以下命令添加到`package.json`中的`scripts`对象来实现这一点：

```js
"scripts": {
  "open": "npx cypress open" 
}
```

要运行`open`命令，您只需运行`npm run open`命令，测试运行器应该会在 Cypress 测试运行器中选择的默认浏览器上打开。

## 回顾 - 添加 npm 脚本

在本节中，我们学习了什么是 npm 脚本以及如何将它们添加到`package.json`文件中。我们还学会了如何运行我们已经添加到`package.json`文件中的 npm 脚本，以执行和自动化项目中的任务。接下来，我们将学习如何在 Cypress 中运行测试。

# 运行 Cypress 测试

在本节中，我们将重点放在如何在浏览器上运行 Cypress 测试。为此，我们将编写测试脚本，可以像打开 Cypress 脚本一样运行测试：

```js
"scripts": {
"test:chrome": "cypress run –browser chrome",
"test:firefox": "cypress run –browser firefox" 
}
```

前面的脚本将用于在 Chrome 浏览器或 Firefox 浏览器中运行测试，具体取决于用户在命令行终端上运行的命令。要执行测试，您可以运行`npm run test:chrome`在 Chrome 中运行测试，或者`npm run test:firefox`在 Firefox 中执行测试。命令的第一部分指示 Cypress 以无头模式运行测试，而第二部分指示 Cypress 在哪个浏览器中运行测试。运行 Cypress 测试不仅限于 Chrome 和 Firefox，并且可以扩展到 Cypress 支持的任何浏览器，还可以根据需要自定义运行脚本的名称。

## 使用脚本组合 Cypress 命令

`package.json`中的`scripts`对象为您提供了灵活性，可以组合命令以创建可以执行不同功能的高级命令，例如将环境变量传递给正在运行的测试，甚至指示 Cypress 根据传递的变量运行不同的测试。组合 Cypress 命令确保我们编写短小的可重用语句，然后可以用来构建执行多个功能的命令。在下面的示例中，我们将使用`scripts`对象编写一个命令来打开 Cypress，设置端口，设置环境，并根据我们选择运行的命令设置浏览器为 Chrome 或 Firefox：

```js
"scripts": {
"test": "cypress run",
"test:dev": "npm test --env=dev",
"test:uat": "npm test --env=uat",
"test:dev:chrome": "npm run test:dev –browser chrome",
"test:uat:chrome": " npm run test:uat –browser chrome", 
"test:dev:firefox": "npm run test:dev –browser firefox",
"test:uat:firefox": "npm run test:uat –browser firefox" 
}
```

前面的脚本可以在两个浏览器中运行 Cypress 测试。这些脚本还有助于确定要根据`-env`变量运行测试的环境。最后两个脚本组合了一系列运行 Cypress 的脚本，附加了一个环境变量，并选择了要在其上运行测试的浏览器，这使得`package.json`中的脚本功能在编写要在测试套件中执行的 Cypress 命令时非常有用。要在 Firefox 中运行测试，我们只需运行`npm run test:uat:firefox`命令进行 UAT 测试，或者`test:dev:firefox`进行`dev`环境的测试。您还可以使用`test:uat:chrome`在 Chrome 中运行 UAT 测试，或者`test:dev:chrome`进行`dev`环境的测试。

重要提示

要在不同的环境中运行测试，您需要在项目中已经设置好在不同环境中运行测试的配置。

## 总结-运行 Cypress 测试

在本节中，我们看了如何在 Cypress 中执行我们的测试。我们还看了不同的方法，通过传递环境变量和更改脚本中的参数来执行我们的测试的 npm 脚本。我们还学会了如何组合多个 Cypress 命令来运行我们的测试，从而减少我们需要编写的代码量。

# 总结

在本章中，我们学习了如何在 Windows 和 Mac 操作系统上安装 Cypress。在两种安装中，我们涵盖了作为下载应用程序或通过命令行安装 Cypress。我们还涵盖了使用 Node.js（npm）自带的默认包管理器或第三方依赖管理器（如 Yarn）。我们学会了如何利用测试运行器来运行我们的测试，以及如何在`package.json`中自动化我们的脚本，以帮助我们有效地运行测试。为了测试我们的知识，我们还进行了一个练习，练习在不同的 Cypress 浏览器中运行测试。

在下一章中，我们将深入探讨 Selenium 和 Cypress 之间的区别，以及为什么 Cypress 应该是首选。我们将进一步建立在本章中所获得的对 Cypress 的理解基础上。


# 第二章：Selenium WebDriver 和 Cypress 之间的差异

Cypress 和 Selenium WebDriver 都是支持端到端测试的测试自动化框架，当有人提到 Cypress 时，很快就需要比较或找出哪个比另一个更好。在我们开始了解 Selenium WebDriver 和 Cypress 之间的差异之前，我们首先需要了解两个测试框架开发的不同动机以及它们的预期用户是谁。

了解 Cypress 和 Selenium WebDriver 在架构上为何不同将在帮助您了解 Selenium WebDriver 和 Cypress 框架的不同和相似方面起到重要作用。在本节中，我们将评估 WebDriver 和 Cypress 在不同方面的独特之处、不同之处和相似之处。

我们将探讨 Selenium WebDriver 和 Cypress 的不同用例，并检查每个用例适用的目的。我们还将清楚地确定每个测试框架的受众，以及您可以从两者或每个测试框架中获得什么。我们将描述为什么应该选择 Cypress 作为测试自动化框架，以及为什么它是端到端测试自动化的完美候选者。

在了解了 Cypress 和 WebDriver 之间的差异和相似之处后，我们将总结列出使其在端到端网页测试自动化方面脱颖而出并领先于其他测试框架的因素和工具。以下是本章将涵盖的关键主题：

+   为什么选择 Cypress？

+   比较 Cypress 和 Selenium WebDriver

+   使用 Cypress 进行前端测试

通过本章的学习，您将能够了解 Cypress 与 Selenium WebDriver 之间的差异和相似之处，以及它在前端 Web 自动化测试中的优势。

# 为什么选择 Cypress？

Cypress 是一个端到端测试框架，由开发人员为开发人员和质量保证（QA）工程师编写。Cypress 专注于测试 Web 应用程序，由于自动化 Web 的唯一方法是使用 JavaScript，因此 Cypress 仅支持使用 JavaScript 编写其测试。

Cypress 专门为利用 JavaScript 开发其产品的前端团队编写，以及需要快速开始编写单元、集成和端到端测试的团队，而无需正确设置测试框架的复杂细节。

Cypress 不仅适合初学者，而且确保开发人员或 QA 工程师需要开始测试的一切都已经打包在从 Cypress 网站下载和安装的捆绑包中。Cypress 捆绑了自己的浏览器、测试运行器和 chai 作为断言框架。

拥有一个包含一切所需的捆绑包，可以让任何人开始测试的过程，而无需了解断言框架、测试运行器的设置过程，甚至不需要添加浏览器驱动程序，就像使用 Selenium WebDriver 的情况一样。

Cypress 使用 JavaScript，这使得 JavaScript 开发人员更容易上手并快速掌握 Cypress 的概念。上手的简便性还确保开发人员和 QA 工程师可以快速掌握使用 Cypress 编写测试的技能。由于 Cypress 是用 JavaScript 开发的，使用 JavaScript 的开发人员和 QA 团队发现它更容易调试，也更容易理解错误，因为它们与 JavaScript 应用程序中的错误类似。

Cypress 使用的通用驱动程序目前与 Firefox、Edge、Chrome 和 Chromium 系列浏览器兼容。与 Selenium 不同，Selenium 使用 WebDriver 并通过 HTTP 网络请求与**文档对象模型**（**DOM**）进行交互，而 Cypress 驱动程序直接在浏览器中工作，无需进行网络请求。在浏览器中运行测试的能力确保了 Cypress 能够有效地解释命令，而不会在命令从测试传递到驱动程序，然后到浏览器中运行的应用程序时引入超时。

使用通用驱动程序还确保了 Cypress 在所有浏览器中使用的方法的一致性，以及测试的标准格式，无论测试将在哪个浏览器中运行。采用这种方法，QA 团队或个人开发人员可以扩展他们的跨浏览器测试，因为唯一需要做的就是在新支持的浏览器上运行他们现有的测试套件。

Cypress 框架在浏览器上运行，因此在架构上与 Selenium WebDriver 等其他测试自动化工具不同。Cypress 在浏览器上运行的能力使其比其他自动化工具具有竞争优势，因为它自带了自动等待序列，否则需要在测试中定义。因此，Cypress 知道何时等待事件，例如网络请求，否则需要在 Selenium 驱动的测试中指定为显式或隐式等待。

像 JavaScript 框架这样的软件开发技术变化比测试技术和可用框架快得多。Cypress 提供了一个独特的机会，开发人员和 QA 工程师可以快速开始编写测试，而无需担心测试设置的问题。消除对底层测试基础设施的担忧不仅加快了测试过程，还确保团队可以快速开始软件开发生命周期中重要的任务。

## 总结-为什么选择 Cypress？

在这一部分，我们了解了为什么 Cypress 在网页开发测试方面是首选，以及它与其他测试框架（包括 Selenium WebDriver）的区别和优势。在下一部分，我们将直接比较 Cypress 和 Selenium WebDriver 之间的差异和相似之处。

# 比较 Cypress 和 Selenium WebDriver

很容易陷入这样的陷阱，认为 Cypress 可以取代 Selenium WebDriver，其使用可能会使 Selenium WebDriver 在测试自动化领域完全过时。虽然直接假设 Cypress 要么更好，要么优于 Selenium，或者反过来，这种想法是错误的，在大多数情况下都是不正确的。

在这一部分，我们将介绍 Cypress 的独特之处，以及它的目的如何更多地是作为 Selenium WebDriver 的补充而不是附加。接下来的部分将概述 Selenium WebDriver 和 Cypress 之间的一些差异。

## 浏览器驱动程序

Cypress 使用一个通用驱动程序来支持所有浏览器，而另一方面，Selenium WebDriver 使用不同的驱动程序来支持每个不同的浏览器。使用通用驱动程序可以在安装时在所有 Cypress 支持的浏览器上运行测试，而无需安装外部驱动程序。另一方面，Selenium 需要为每个浏览器安装驱动程序才能在不同浏览器中运行测试。通用驱动程序还使 Cypress 具有竞争优势，因为开发团队能够解决 WebDriver 中常见的问题，并将功能扩展到不同的浏览器。

## 重试和等待

Cypress 内置了显式重试来搜索**DOM**中的元素，并在测试被视为失败之前显式等待事件发生。Cypress 配备了确定请求是否需要等待的事件，然后浏览器决定它们是失败还是通过。Cypress 能够处理等待和重试，因为它与测试一起在浏览器上运行，并能够了解任何给定时间测试的状态。

另一方面，Selenium 利用 HTTP 请求到 WebDriver，因此在测试运行时很难确定是否需要显式或隐式等待。为了解决这个问题，Selenium 用户必须在测试需要等待请求完成后再执行下一步时自己编写等待。在测试运行时，Selenium 也不自带自动重试的功能，而 Cypress 却具备这一功能。

## 目标使用

Cypress 是为 JavaScript 开发人员和 QA 工程师设计的，他们希望快速建立自动化框架并开始测试端到端的 Web 应用程序，而不需要花费太多带宽来设置测试框架或理解构建测试框架背后的技术。使用 Cypress，开发人员可以轻松地从编写单元测试转向编写集成测试，甚至是接受测试，包括存根外部依赖项的功能，并测试他们的应用程序的行为。Cypress 目前也更偏向于与 Chromium 系列浏览器兼容的开发人员和 QA 实践，包括 Edge，还有目前处于测试阶段的 Firefox。

另一方面，Selenium WebDriver 是用来测试在网络上运行的任何东西。Selenium 专注于想要测试其 Web 应用程序的每个方面的 QA 团队，并不受浏览器兼容性或单一测试运行器等因素的限制，而这在 Cypress 中是存在的。Selenium WebDriver 为用户提供了使用不同浏览器和插件扩展它的选项，还支持不同的语言，如 Java、Python、Ruby、C＃、JavaScript、Perl 和 PHP。很难明确地说 Selenium 是 Cypress 的直接竞争对手，因为我们可以清楚地看到，虽然它们的用例非常相似，但它们的受众和目标用户完全不同。虽然 Selenium 针对所有主要开发语言的用户，甚至支持在诸如 Appium 之类的工具中进行移动自动化，但 Cypress 只专注于为理解 JavaScript 语言的 Web 开发人员和 QA 工程师提供更好的测试。

## 架构

Cypress 在浏览器上运行，这使其比 Selenium WebDriver 等工具更具优势。在浏览器上运行意味着 Cypress 速度更快，可以在运行时更快地解释命令，因为没有第三方服务代表其解释命令或向浏览器驱动程序发送 HTTP 请求。虽然所有 Cypress 命令都在浏览器内运行，但 Cypress 可以了解浏览器外发生的事情，因为它可以访问应用程序的所有内容，包括窗口对象、DOM、文档对象或任何其他进程和方法。只要您的应用程序有访问权限，Cypress 测试就会有访问权限。以下图表显示了 Cypress 与 Selenium WebDriver 架构的对比。在 Cypress 中，执行在浏览器中进行，而在 Selenium 中，执行在浏览器外进行：

![图 2.1– Selenium 与 Cypress 测试执行架构的对比](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Chapter_2_Image01.jpg)

图 2.1– Selenium 与 Cypress 测试执行架构的对比

## 跨浏览器兼容性

Cypress 目前不支持像 Selenium WebDriver 那样支持所有主要浏览器。Cypress 目前支持使用 Chromium 开源项目构建的浏览器，Firefox，Edge 和 Electron（Cypress 中的默认浏览器）。另一方面，Selenium 支持所有主要浏览器，这使得它在能够在多个平台上测试应用程序的能力方面具有优势。虽然可以争论跨三个以上浏览器的跨浏览器功能会增加架构复杂性，对测试过程的价值很小，但支持多个浏览器可能会导致识别出优先级较高的错误，即使错误的严重性可能很低。

## Cypress 的权衡

如前所述，Cypress 是一个专注于浏览器端到端测试自动化的测试工具。能够在浏览器上运行意味着 Cypress 可以与浏览器上的元素进行更好的交互，但这也意味着 Cypress 具有永久的权衡，由于其架构无法更改。这些权衡在以下子节中描述。

### 范围限制

Cypress 在作为 QA 工程师和编写测试的开发人员的自动化工具时效果最佳。Cypress 不支持手动自动化工具，并且没有计划在框架中集成手动测试工具。

Cypress 也不适用于诸如 Web 索引和性能测试之类的活动，进行这些活动可能会降低框架的性能能力。

### 环境限制

Cypress 在浏览器上运行，这意味着它始终支持的语言将是 JavaScript，因为测试代码将始终在浏览器中进行评估。能够在浏览器中运行意味着要连接到数据库或服务器，我们只能使用 Cypress 命令`cy.exec()`，`cy.request()`或`cy.task()`，这提供了一种公开数据库或服务器的方法，这可能比明确定义它们的配置并让 Cypress 理解它们更费力。在浏览器中运行测试为运行测试提供了很好的体验，但是要插入需要在浏览器外部运行的功能有点麻烦。

### 多个浏览器和多个标签-限制

Cypress 框架不支持测试在运行时控制多个浏览器的能力。这是一个永久的权衡，因为在一个浏览器中运行测试时无法控制多个浏览器。

Cypress 框架不支持与多个浏览器标签交互的能力，因为这种功能在浏览器内部不可用。但是，Cypress 提供了集成其他工具（如 Selenium 或 Puppeteer）以在需要时操作和驱动多个浏览器标签的能力。

### 控制来源的限制

Cypress 只支持在同一个测试中访问来自相同来源的 URL。控制来源的限制意味着对于任何特定的测试，您无法访问不属于相同来源的不同 URL。例如，尝试在同一个测试中发送请求到[`github.com`](https://github.com)和[`gitlab.com`](https://gitlab.com)将导致错误。以下示例说明了编写 Cypress 测试时利用跨域的不正确和正确的方式。

#### 正确地利用跨域来运行测试

在以下测试中，用户提示 Cypress 首先导航到[`github.com`](https://github.com) GitHub 网站，然后导航到[`docs.github.com/en`](https://docs.github.com/en)（文档链接）以获取 GitHub 资源。这两个链接都属于相同的来源`github.com`，因此 Cypress 执行请求时不会出现问题。

```js
It('can navigate to code repository hosting service', () => {
    cy.visit('https://github.com');
    cy.visit('https://docs.github.com');  });
```

#### 不正确地利用跨域来运行测试

在这个测试中，用户首先提示 Cypress 导航到[`github.com`](https://github.com)，然后再导航到 https://gitlab.com，这是与第一个 URL 不同源的网站。当运行测试时，这将导致错误被抛出：

```js
It('can navigate to code repository hosting service', () => {
    cy.visit('https://github.com');
    cy.visit('https://gitlab.com');  })
```

### Cypress 和 Selenium 互补的行动

在某些罕见但仍可实现的情况下，我们可以同时利用 Cypress 和 Selenium 编写测试。虽然 Cypress 有不能控制多个浏览器标签的限制，但可以配置 Cypress 使用 Selenium 来运行多个标签。我们还可以利用 Cypress 进行端到端测试，而使用 Selenium 进行诸如负载测试之类的活动。Selenium 能够执行 Cypress 不支持的负载测试等测试，并且在这种情况下，两个测试框架可以一起使用。

## 总结差异

Cypress 是为网络而构建的，并且经过优化以在浏览器上运行。Cypress 的架构允许它有效地运行测试，同时克服了 WebDriver 的挑战。虽然 Cypress 能够在浏览器上运行，但 WebDriver 使用 HTTP 协议与浏览器交互，因此在运行测试时会导致延迟和未知的等待事件。Cypress 还针对寻求编写测试而不必担心基础架构和断言库和编程语言限制的质量保证工程师和开发人员。Cypress 还承诺未来，计划支持 Safari 和 Internet Explorer，这将确保开发人员和测试人员可以在他们选择的浏览器上尝试 Cypress。

Cypress 捆绑了所有的优势，但也伴随着一些临时和永久的权衡。一些临时的权衡是支持所有主要浏览器或执行某些功能，比如悬停在一个元素上。另一方面，永久的权衡意味着 Cypress 的架构甚至在未来也无法支持它们。它们包括控制多个打开的浏览器和/或在浏览器中操作多个标签，能够连接到外部数据库和服务器，并调用不同的跨源。所有永久的权衡都有解决方法，用户可以随时实施解决方法。然而，Cypress 建议在不应该使用解决方法的情况下不要使用解决方法，因为这可能会导致测试自动化复杂性，从而降低 Cypress 作为自动化工具的效果。

## 总结-比较 Cypress 和 Selenium WebDriver

在这一部分，我们了解了使用 Cypress 的优势，并将其与使用 Selenium 编写测试进行了比较。我们还确定了为什么 Selenium 在架构上与 Cypress 不同，以及为什么两者更多地是互补而不是补充。我们探讨了 Cypress 存在的权衡以及在 Cypress 自动化框架中克服永久权衡的一些解决方案。在下一节中，我们将深入探讨使 Cypress 成为端到端网页测试自动化的最佳选择的工具。

# Cypress 用于前端应用程序

Cypress 是为网络而构建的，这意味着它装载了一些其他框架可能没有的工具和功能。这提高了前端 Web 开发人员和质量保证工程师的测试体验。在这一部分，我们将探讨 Cypress 装载的不同元素，这些元素使其用户可以方便地开始并快速上手。以下是一些使 Cypress 脱颖而出的元素，这些元素使其与其他前端应用程序的测试自动化框架不同。

## 测试运行器

当 Cypress 安装在用户的计算机上时，默认情况下会附带 Cypress 测试运行器。这是一个交互式用户界面，允许 Cypress 框架的用户查看测试中运行的命令，以及与之交互的应用程序。测试运行器具有显示测试失败次数、测试通过次数、跳过的测试、命令日志以及测试运行时浏览器的视口的能力。

## 设置过程

如前一章所述，Cypress 的设置过程不仅清晰简单，而且确保 QA 工程师和前端开发人员只需运行一个命令即可安装 Cypress。这消除了配置外部依赖项来开始编写测试的需要。Cypress 文档也非常互动和清晰，这使得开发人员和 QA 工程师可以快速上手并使用 Cypress 的功能。

## 实施和调试

Cypress 测试运行器带有内置的命令日志，这意味着在调试模式下，用户可以实时检查已通过的命令和断言，以及未通过的命令。突出显示失败的命令并检查未能调用的元素或失败的功能的能力使 Cypress 脱颖而出，因为调试前端应用程序不仅变得轻而易举，而且还节省了用于调查失败原因的时间。命令日志还为 Cypress 用户提供了即时反馈，他们可以通过检查测试运行器上运行的命令来判断测试是否已经正确编写。

## 全面的测试能力

Cypress 结合了编写功能测试和检查前端发出的 API 调用的响应的能力。它还具有可视化回归功能，可以识别应用程序是否有意进行了更改。

在编写功能测试时，Cypress 框架会检查前端功能是否符合需求文档中规定的要求，这可能涉及点击按钮或注册用户等过程。

API 验证测试另一方面检查返回的 XHR（XMLHttpRequest）请求是否成功，并在请求返回时收到正确的响应。XHR 请求为 API 测试提供了额外的验证层，因为我们可以确认预期数据的结构与前端应用程序中收到的数据类似。

重要说明

XHR 作为 API 工作，但以对象的形式表示，其主要目的是在给定的 Web 服务器和 Web 浏览器之间传输数据。

可视化回归测试通过比较基线的页面快照和最新测试运行的页面快照来检查页面元素的一致性。如果发现差异，那么正在运行的测试将失败。失败时，将创建一个显示预期图像和生成图像之间差异的快照，以显示生成的快照与基线图像之间的差异。测试运行后，QA 工程师或开发人员可以接受或拒绝对前端应用程序所做的更改。

## 回顾-用于前端应用程序的 Cypress

在本节中，我们了解了为什么 Cypress 在测试前端应用程序时是最合适的。我们了解了使其成为首选测试框架的不同因素，以及如何利用其优势来编写更好、更全面的测试。

# 总结

毫无疑问，Cypress 是一个强大的工具，可以被前端团队和质量保证工程师利用，快速开始编写测试，而不必担心从头开始构建测试自动化工具所带来的额外开销。在本章中，我们了解了为什么 Cypress 是用于测试的最佳 Web 自动化框架，我们通过比较 Cypress 和现有测试自动化工具之间的不同工具来做到这一点。我们还介绍了 Cypress 和 Selenium 之间的区别，以及两者之间的特定架构相似性和差异性。最后，我们探讨了如何利用这些工具。在下一章中，我们将学习如何使用命令行工具来运行、测试和调试 Cypress 测试。


# 第三章：使用 Cypress 命令行工具

在上一章中，我们了解了 Cypress 与 Selenium 等其他测试自动化工具的不同之处，以及在 Web 自动化测试方面的突出表现。在本章中，我们将继续使用 Cypress 命令行工具来构建我们对 Cypress 的使用知识。为此，我们将介绍您可以使用的命令，以利用 Cypress 的功能。

其中一些命令将涉及功能，如运行单个或所有测试，调试 Cypress，在不同浏览器上启动 Cypress 测试，以及其他 Cypress 命令行功能。我们将参考本章的 GitHub 存储库文件夹，并将为您的参考和练习包括在存储库中编写的每个命令和代码。

在本章中，我们将涵盖以下关键主题：

+   运行 Cypress 命令

+   理解基本的 Cypress 命令

+   Cypress 在命令行上调试

一旦您完成了每个主题，您将准备好编写您的第一个测试。

## 技术要求

本章的 GitHub 存储库可以在[`github.com/PacktPublishing/End-to-End-Web-Testing-with-Cypress`](https://github.com/PacktPublishing/End-to-End-Web-Testing-with-Cypress)找到。

本章的源代码可以在`chapter-03`目录中找到。

要运行本章中的示例，您需要克隆本书的 GitHub 存储库，并按照`READMe.md`文件中的说明正确设置和运行测试。您可以在`docs.github.com/en/free-pro-team@latest/github/creating-cloning-and-archiving-repositories/cloning-a-repository`上阅读有关如何使用 GitHub 在本地机器上克隆项目的更多信息。

# 运行 Cypress 命令

有效利用 Cypress 框架需要您了解 Cypress 以及如何使用命令行运行不同功能。Cypress 命令允许 Cypress 框架的用户自动化流程，并在初始化和运行时向框架和测试提供特定指令。

在大多数情况下，通过命令行运行 Cypress 测试比使用浏览器运行测试更快。这是因为通过命令行运行测试可以减少运行特定测试所需的资源数量。原因是在命令行中运行的测试通常是无头的，这意味着分配给运行测试的资源较少，而在有头模式下执行测试则不同。

重要提示

有头模式是指测试可以在浏览器上可视化运行，而无头模式是指测试执行过程不会打开可见的浏览器。相反，所有测试都在命令行上运行并输出。

首先，让我们看看如何运行全局和本地的 Cypress 命令。

## 全局和本地命令

Cypress 命令可以从包含 Cypress 安装和代码的特定目录中运行，也可以从全局 Cypress 安装中运行。全局安装 Cypress 可确保用户可以从操作系统中的任何目录运行 Cypress，而使用本地 Cypress 安装，Cypress 只能从安装的单个目录中访问。

### 运行全局 Cypress 命令

在 Cypress 中，全局命令是通过访问全局安装的 Cypress 版本来运行的。运行全局版本的 Cypress 时调用的命令不一定是用户生成或定义的，因为它们内置在框架中。要能够全局运行 Cypress 命令，您需要使用以下命令全局安装 Cypress：

```js
npm install cypress --global
or (shorter version)
npm i -g cypress
```

上述命令将全局安装 Cypress，并确保从任何 Cypress 安装目录调用任何已知的 Cypress 命令都会产生结果或错误，具体取决于提供的命令的执行情况。

要运行全局命令，您需要使用`cypress`关键字定义命令，然后是命令；例如，`cypress run`或`cypress open`。

### 本地运行 Cypress 命令

本地 Cypress 命令源自 Cypress 全局命令，并且是运行命令的另一种选择。要在本地运行 Cypress 命令，您需要使用以下命令在您的目录中安装 Cypress：

```js
npm install cypress 
or (shorter version)
npm i cypress
```

我们可以通过在`package.json`文件的`scripts`部分中定义所需的命令来将其集成到开发环境中，如下所示：

```js
{
  "scripts": {
    "cypress:run": "cypress run",
    "cypress:open": "cypress open"
  }
}
```

将命令添加到`package.json`中允许我们以与执行 JavaScript 包的 npm 命令相同的方式使用这些命令。`package.json`文件中定义的命令在运行时由 Node.js 环境解释，并且在执行时，它们会被执行为全局命令。

重要提示

建议在运行`npm install cypress`命令之前在终端中运行`npm init`命令。如果在未初始化项目的情况下运行 Cypress，Cypress 的目录将不可见。通过运行`init`命令，Cypress 将识别项目目录为现有项目，因此它会初始化并创建其目录，而无需我们在终端上运行额外的命令。

在`package.json`中定义命令不仅使开发人员和质量保证工程师更容易知道要运行哪些命令，而且简化了运行、调试或维护测试时需要运行的命令的性质。

重要提示

Cypress 开发团队建议按项目安装 Cypress，而不是使用全局安装方法。本地安装提供了某些优势，例如用户能够快速更新 Cypress 依赖项，并减少循环依赖问题，这些问题会在不同项目中破坏一些测试，而 Cypress 在另一个项目中运行良好。

要在命令行中运行脚本，您需要调用`npm run`，然后是命令的名称。在我们之前定义的命令中，您只需要运行以下命令来同时执行这些命令：

```js
npm run cypress:run  // command  to run tests on terminal
npm run cypress:open // command to run tests on cypress runner
```

是时候快速回顾一下了。

## 回顾-运行 Cypress 命令

在本节中，我们学习了如何调用本地或全局命令，以及如何从 Cypress 终端或测试运行程序中运行测试，后者利用了图形用户界面。在接下来的部分中，我们将在已经获得的运行 Cypress 命令的知识基础上，了解如何在 Cypress 中使用不同的命令。

# 了解基本的 Cypress 命令

在本节中，我们将探讨各种 Cypress 命令，我们可以使用这些命令通过终端或使用 Cypress 测试运行程序来运行我们的测试。我们还将观察这些命令如何用于实现不同的结果。本节还将介绍如何定制与我们的应用程序交互的不同测试，以实现特定的结果。我们将深入了解最常见的 Cypress 命令以及如何使用 Cypress 框架中预先构建的选项来扩展这些命令。我们将探讨的命令如下：

+   `cypress run`

+   `cypress open`

+   `cypress info`

+   `cypress version`

让我们从`cypress run`开始。

## cypress run

`cypress run`命令以无头方式执行 Cypress 套件中的所有测试，并默认在 Electron 浏览器中运行测试。如果没有使用其他配置扩展，该命令将运行 Cypress 的`integration`文件夹中所有`.spec.js`格式的文件。`Cypress run`命令可以使用以下配置选项运行：

```js
cypress run {configuration-options}
```

最常见的 Cypress 配置选项包括以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Table_3.1.jpg)

接下来的几节将扩展前面表格中显示的每个配置选项。

### cypress run --env <env-variable>

Cypress 环境变量是*动态名称-值对*，影响 Cypress 执行测试的方式。当需要在多个环境中运行测试，或者定义的值容易快速更改时，这些环境变量非常有用。

在 Cypress 中，您可以将单个或多个环境变量定义为字符串或 JSON 对象。

在本节中，我们将为一个开源的**todoMVC**应用程序编写测试。这些测试的代码基础可以在本书的 GitHub 存储库中的`chapter 03`目录中找到。被测试的应用程序是一个使用 React 开发的**待办事项列表**应用程序。使用该应用程序，我们可以添加待办事项，标记为已完成，删除它们，查看已完成的项目，甚至在*活动*、*全部*和*已完成*待办事项之间切换。

使用该应用程序，我们可能计划扩展应用程序以使用**HTTPS**而不是当前的**HTTP**协议。即使目前不支持 HTTPS 功能，我们可以在 Cypress 测试中添加对其的支持。为此，我们将把**传输协议**URL 部分定义为环境变量，然后将其传递给`package.json`中的命令，如下例所示。

以下代码片段可以在`chapter 03`的子文件夹中提到的 GitHub 存储库中找到。`Todo-app.spec.js`文件的完整源代码位于`Cypress/integration/examples`文件夹下。我们将在本章中探讨的 Cypress 测试是版本 1 的测试。

下面的`Todo-app.spec.js`文件演示了在导航到 URL 时如何使用环境变量。它是主要的测试文件，位于本书的 GitHub 存储库中的`chapter-03/cypress/integration/examples/todo-app.spec.js`中。

```js
... 
context('TODO MVC Application Tests', () => {
  beforeEach(() => {
    cy.visit(
      `${Cypress.env('TransferProtocol')}://todomvc.com/examples/react/#/`)
  });
...
```

下面的`package.json`文件也位于`chapter-03/`目录中，包含了用于执行 JavaScript 应用程序的测试或执行命令的所有命令。它位于`chapter-03/`目录的根位置：

```js
...
"scripts": {
    "cypress:run": "cypress run --env 
    TransferProtocol='http'",
    "cypress:run:v2": "cypress run --env 
    TransferProtocol='https'",
  },
...
```

上述脚本表明，如果 URL 协议发生变化，我们可以运行前述任何测试命令来替换我们在运行 Cypress 测试时声明的环境变量。我们可以依次执行前述脚本，使用`npm run cypress:run`和`npm run cypress:run:v2`。

重要提示

HTTPS 与 HTTP 相同，不同之处在于 HTTPS 更安全。这是因为发送请求和接收响应的过程使用 TLS(SSL)安全协议进行加密。

传输协议是 URL 的一部分，它确定 URL 是否使用 HTTP 或 HTTPS 协议。使用 HTTP 协议的 URL 以`http://`开头，而使用 HTTPS 的 URL 以`https://`开头。

### cypress run --browser <browser-name>

Cypress 命令行具有内置功能，可以在主机计算机上安装的不同浏览器中运行 Cypress 测试，并且这些浏览器受 Cypress 框架支持。Cypress 会尝试自动检测已安装的浏览器，并可以在`chrome`、`chromium`、`edge`、`firefox`或`electron`中运行测试。要在特定浏览器中运行测试，您需要使用`--browser`配置选项提供浏览器名称。您还可以选择提供浏览器路径而不是浏览器名称；只要它是有效的并且受 Cypress 支持，Cypress 仍然会在提供的浏览器路径中运行测试。

下面的代码片段显示了在本书 GitHub 存储库的`chapter-03`目录中的`package.json`的`scripts`部分中定义的脚本。这些脚本定义了我们的测试将在其中运行的浏览器，并且还传递了 URL 的一部分作为环境变量：

```js
...
"scripts": {
    "cypress:chrome": "cypress run --env 
    TransferProtocol='http' --browser chrome",
    "cypress:firefox": " cypress run --env 
    TransferProtocol='http' --browser firefox"
  },
...
```

在上述命令中，我们可以使用`npm run cypress:chrome`和`npm run cypress:firefox`命令在 Chrome 或 Firefox 中运行测试。

重要提示

要在特定浏览器中运行测试，该浏览器必须安装在您的计算机上，并且还必须是 Cypress 支持的浏览器列表中的一员。

### Cypress run --config <configuration(s)-option>

Cypress 可以使用在终端上运行的命令设置和覆盖配置。Cypress 的配置可以作为单个值、以逗号分隔的多个值，或作为字符串化的 JSON 对象传递。Cypress 中的任何定义的配置都可以通过`cypress run --config`配置选项进行更改或修改。配置选项可能包括指定替代的`viewportHeight`和`ViewportWidth`、超时和文件更改等其他配置。在我们的脚本中，我们将更改 Cypress 运行测试的视口，而不是默认的视口，即 1000x660，我们将在平板视口的 763x700 上运行测试。

下面的代码片段在我们的`chapter-03`根目录的`package.json`文件中定义。以下脚本用于在平板视图中运行测试。为此，您必须覆盖 Cypress 默认配置的视口高度和宽度：

```js
...
"scripts": {
"cypress:tablet-view": "cypress run --env TransferProtocol='http' --config viewportHeight=763,viewportWidth=700",
}
...
```

前面的脚本可以使用`npm run cypress:tablet-view`命令运行。

重要提示

在 Cypress 中传递多个配置选项时，不要在不同配置的逗号分隔值之间留下空格（如上面的代码所示）；否则，Cypress 会抛出错误。

### cypress run --config-file <configuration-file>

Cypress 可以覆盖位于`/cypressRootDirectory/cypress.json`的默认配置文件。您可以定义一个或多个次要的 Cypress 配置文件以运行它们的测试。Cypress 还允许您完全禁用使用配置文件。

下面的脚本位于本书 GitHub 存储库的`chapter-03`目录中的`package.json`中，这是一个命令，使 Cypress 能够覆盖用于运行测试的配置文件。执行该命令时，将使用位于`chapter-03/config/cypress-config.json`下的`cypress-config.json`文件，而不是使用位于`chapter-03`中的默认`cypress.json`文件：

```js
...
"scripts": {
"cypress:run:secondary-configuraton": "cypress run --env TransferProtocol='http' --browser chrome --config-file config/cypress-config.json"
},...
```

运行上述脚本，您需要运行`npm run cypress:run:secondary-configuraton`命令，该命令将使用位于`/cypressRootDirectory/config/cypress-config.json`的配置文件运行测试。

### cypress run --headed

Cypress 提供了一个命令，允许您以无头和有头模式运行浏览器。当定义有头模式时，测试在运行时会打开浏览器。此选项可以在 Cypress 捆绑的默认 Electron 浏览器中使用。在 Electron 中使用`run`命令运行 Cypress 测试的默认模式是无头模式，要覆盖这一点，我们需要在运行测试时传递`--headed`配置。

下面的脚本可以在本书 GitHub 存储库的`chapter-03`目录中的`package.json`文件中找到。运行以下脚本命令将使 Cypress 以有头模式运行，允许在浏览器上看到运行的测试：

```js
...
"scripts": {
"cypress:electron:headed": "cypress run --env TransferProtocol='http' --headed"
},
...
```

前面的脚本可以使用`npm run cypress:electron:headed`命令运行。

### cypress run --headless

Cypress 在 Chrome 和 Firefox 浏览器中以有头模式运行测试，并且每次运行测试时都会启动一个浏览器。要更改此行为并确保测试在不启动浏览器的情况下运行，您需要配置运行 Chrome 或 Firefox 浏览器的命令，以便它们以无头模式运行。

以下脚本位于本书 GitHub 仓库的 `chapter-03` 目录中的 `package.json` 文件中。运行以下命令将使 Cypress 以无头模式运行，测试命令只能在命令行界面上看到：

```js
...
"scripts": {
"cypress:chrome:headless": "cypress run --env TransferProtocol='http' --browser chrome --headless",
"cypress:firefox:headless": "cypress run --env TransferProtocol='http' --browser firefox --headless"
},
...
```

使用上述命令以无头模式运行 Chrome，您需要运行 `npm run cypress:chrome:headless`。要在 Firefox 中以无头模式运行命令，您需要运行 `npm run cypress:firefox:headless` 命令。

### cypress run --spec <spec-file>

Cypress 允许我们指定可以运行的不同测试文件。使用此命令，可以指定在目录中运行 *单个* 测试文件，而不是在目录中运行 *所有* 测试文件。还可以指定不同目录中的不同测试，以便它们同时运行，并指定与特定目录匹配的正则表达式模式。

以下代码片段是 `package.json` 文件的一部分，位于本书 GitHub 仓库的 `chapter-03` 目录中。第一个脚本只能运行目录中的特定文件，而第二个脚本可以运行单个目录中的多个文件：

```js
... 
"scripts": {
  "cypress:integration-v2:todo-app": "cypress run --env 
  TransferProtocol='http' --spec 'cypress/integration/
  integration-v2/todo-app.spec.js'",
  "cypress:integration-v2": "cypress run --env 
  TransferProtocol='http' --spec 'cypress/
  integration/integration-v2/**/'"
},
...
```

第一个命令指定将运行位于 `integration-v2` 文件夹中的 `todo-app.spec.js` 文件的测试。第二个命令将运行位于 `integration-v2` 文件夹中的所有测试文件。

## cypress open

`cypress open` 命令在测试运行器中运行 Cypress 测试，并将配置选项应用于您正在运行的项目的测试。当运行 `cypress open` 命令时传递的配置选项也会覆盖 `cypress.json` 文件中指定的默认值，该文件位于 `tests root` 文件夹中，如果在运行测试时指定了配置。以下命令显示如何运行任何 `cypress open` 命令：

```js
cypress open {configuration-options}
```

命令的第一部分显示了 `cypress open` 命令，而第二部分显示了可以与其链接的配置选项。

最常见的 Cypress 配置选项包括以下内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Table_3.2.jpg)

我们将在接下来的几节中详细介绍每个选项。

### cypress open --env <env-variable(s)>

就像运行 `cypress run` 命令一样，`cypress open` 命令可以在运行测试时使用指定的环境变量运行。与 `cypress run` 命令类似，可以使用 `--env` 配置选项声明一个或多个环境变量来运行测试运行器中的测试。

在前一节中，我们指定了如何通过在 `cypress run` 命令中传递环境变量来通过命令行运行测试。我们将传递相同的环境变量来使用我们的 Cypress 测试运行器运行测试，并且测试应该正常运行。传递的环境变量将确定 **todoMVC** 应用程序 URL 的传输协议是 **HTTP** 还是安全的 **HTTPS**。

以下代码片段位于 `Todo-app.spec.js` 文件中，该文件是我们 `chapter-03/` 目录中的主要测试文件。`todo-app.spec.js` 文件位于 `chapter-03/` 目录中的 `integration/examples` 下。在以下代码片段中，就像在 `cypress run` 中一样，我们可以使用 `cypress open` 命令将环境变量传递给 URL：

```js
... 
context('TODO MVC Application Tests', () => {
  beforeEach(() => {
    cy.visit(
      `${Cypress.env('TransferProtocol')}://todomvc.com/examples/react/#/`)
  });
...
```

以下代码片段位于本书 GitHub 仓库的 `chapter-03/` 根目录中的 `package.json` 文件中。使用此片段，我们将 `'http'` 环境变量传递给我们的测试。这是我们可以完成我们的 URL 并执行我们的测试的时候：

```js
...
"scripts": {
    "cypress:open": "cypress open --env 
    TransferProtocol='http'"
  },
...
```

要打开测试运行器并验证测试运行，您可以运行`npm run cypress:open`，这应该会自动将**TransferProtocol**环境变量添加到运行测试的配置中。

### cypress open --browser </path/to/browser>

当指定时，`--browser`选项指向一个自定义浏览器，该浏览器将被添加到测试运行器中的可用浏览器列表中。要添加的浏览器必须得到 Cypress 的支持，并且必须安装在运行 Cypress 测试的计算机上。

默认情况下，在选择要运行的规范之前，可以通过单击测试运行器中的浏览器选择按钮来查看 Cypress 中的所有可用浏览器。浏览器选择下拉菜单包含已在系统上安装并得到 Cypress 支持的所有浏览器。浏览器选择下拉菜单还允许您切换测试浏览器，从而在不同的浏览器下测试功能：

![图 3.1 - 测试浏览器选择下拉菜单](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Chapter_3_Image01.jpg)

图 3.1 - 测试浏览器选择下拉菜单

要指定路径以便添加浏览器（例如 Chromium），您需要具有以下配置以将 Chromium 添加到可用浏览器列表中。在这里，您需要运行`npm run cypress:chromium`命令。

该书的 GitHub 存储库中的`chapter-03/`目录下的`package.json`文件中包含以下脚本。当执行该脚本作为命令时，它将查找指定位置的浏览器，并将其添加到用于运行 Cypress 测试的浏览器列表中。

```js
...
"scripts": {
    "cypress:chromium": "cypress open --browser 
    /usr/bin/chromium"
  },
..
```

要执行上述脚本来运行我们的测试，我们需要在终端中运行`npm run cypress:chromium`命令。这将在`/usr/bin/chromium`位置找到 Chromium 浏览器并用它来运行我们的测试。

### cypress open --config <configuration-option(s)>

Cypress 框架允许我们在测试运行器中运行测试并提供必须在初始化测试运行器时传递的配置选项。在传递`--config`选项时，可以传递一个环境变量或用逗号分隔的多个环境变量。以下脚本指定了视口尺寸应为平板电脑，并通过`--config`选项传递配置。要运行所需的命令，您需要运行`npm run cypress:open:tablet-view`。

位于该书的`chapter-03/`根目录下的`package.json`文件中的以下脚本用于更改可见浏览器上运行的测试的视口配置。

```js
...
"scripts": {
    "cypress:open:tablet-view":"cypress open --env 
    TransferProtocol='http' --config 
    viewportHeight=763,viewportWidth=700"
  },
...
```

执行时，该命令会修改浏览器尺寸的默认 Cypress 配置。提供的视口高度和视口宽度将以类似于平板显示屏的方式显示内容。

重要提示

使用`--config`选项指定的配置选项将覆盖`cypress.json`文件中指定的默认配置。

### cypress open --config-file <configuration-file>

就像在`Cypress run`命令的情况下一样，通过测试运行器运行的 Cypress 测试可以具有覆盖默认`cypress.json`文件的覆盖配置文件，该文件包含默认的 Cypress 配置。它位于测试文件的根文件夹中。

位于`chapter-03/`目录的根文件夹中的`package.json`文件中的以下代码片段覆盖了默认的 Cypress 配置文件，该文件被标识为`cypress.json`。当执行时，该命令将读取一个已在`chapter-03/config/cpress-config.json`中声明的替代配置文件：

```js
..."scripts": {
"cypress:open:secondary-configuraton": "cypress open --env TransferProtocol='http' --config-file config/cypress-config.json"
},...
```

要执行上述命令并更改默认的 Cypress 配置文件位置，您需要在命令行界面中运行以下命令：

```js
npm run cypress:open:secondary-configuration
```

现在，让我们看另一个命令。

### cypress open --global

正如我们之前提到的，Cypress 可以全局安装。您可以使用全局 Cypress 安装来运行不同的 Cypress 测试，而不是在每个项目中安装它。这种全局安装还允许您触发全局命令，而不必在调用 Cypress 命令的特定目录中安装 Cypress。要以全局模式打开 Cypress，您需要传递`--global`选项，如下所示：

```js
cypress open --global 
```

通过运行此命令，Cypress 将识别我们要使用全局版本的 Cypress 执行测试，而不是我们的本地实例。

### cypress open --project <project-path>

Cypress 具有内置功能，可以覆盖 Cypress 运行测试时的默认路径。当定义了`--project`选项时，它指示 Cypress 放弃默认的目录/项目路径，而是使用提供的项目路径来运行位于指定项目路径中的 Cypress 测试。在这种设置中，可以在不同的目录或嵌套目录中运行完全不同的 Cypress 项目。

本书`chapter-03/`根目录中的`package.json`文件中的以下代码片段执行了完全不同的 Cypress 项目中的测试。该脚本执行了位于`chapter-03/cypress/todo-app-v3`中的项目：

```js
"scripts": {
"cypress:project:v3": "cypress open --env TransferProtocol='http' --project 'cypress/todo-app-v3/'"
},
```

在上一个脚本中，用户可以运行位于`cypress/todo-app-v3`文件夹中的不同 Cypress 项目。要运行该脚本，我们需要运行`npm run:cypress:project:v3`命令。`version-3`项目是一个独立的项目，不依赖于父 Cypress 项目。它可以使用自己的`cypress.json`文件来确定运行配置，如下面的截图所示：

![图 3.2 - todo-app-v3 项目测试文件夹](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/第三章 _ 图像 02.jpg)

图 3.2 - todo-app-v3 项目测试文件夹

如前面的截图所示，我们已经修改了`todo-app-v3`项目中的`integrationFolder`属性，将主测试文件夹中的`cypress/integration`设置为`cypress/tests`。

### cypress open --port <port-number>

默认情况下，Cypress 在端口`8080`上运行。在传递`--port`选项的同时运行`cypress run`命令，可以覆盖测试运行的默认端口，将其更改为您选择的特定端口。

以下代码片段是本书 GitHub 存储库中`chapter-03/`目录中的`package.json`文件的一部分。运行以下命令会更改 Cypress 运行的默认端口：

```js
"scripts": {"cypress:open:changed-port": "cypress open --env TransferProtocol='http' --port 3004"
  },
```

要运行前面的 Cypress 脚本，您需要运行`npm run cypress:open:changed-port`命令。运行此命令将确保测试在端口`3004`上运行，而不是 Cypress 默认在测试运行器上运行的端口：

![图 3.3 - 覆盖默认的 Cypress 测试端口](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/第三章 _ 图像 03.jpg)

图 3.3 - 覆盖默认的 Cypress 测试端口

前面的截图显示了如何在使用`--port`选项覆盖后，在端口`3004`上运行测试，该选项被传递给`cypress run`命令。这里使用的端口仅用于演示目的；用户的机器上可以传递任何可用端口作为 Cypress 应用程序的覆盖端口。

## 使用 cypress info 命令

在终端上运行`cypress info`命令将在终端上打印 Cypress 安装信息和环境配置。该命令打印的信息包括以下内容：

+   已在计算机上安装并被 Cypress 检测到的浏览器。

+   有关主机操作系统的信息。

+   Cypress 二进制缓存的位置。

+   运行时数据存储的位置。

+   已添加前缀**CYPRESS**的环境变量，用于控制配置，如系统代理。

## 使用 cypress 版本命令

`cypress version`命令打印出 Cypress 的二进制版本和已安装的 Cypress 模块的 npm 版本。大多数情况下，版本应该是相同的，但当安装的模块（如二进制版本）无法作为 npm 包模块安装时，版本可能会有所不同。`cypress version`命令的输出如下截图所示：

![图 3.4 - cypress 版本命令的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Chapter_3_Image04.jpg)

图 3.4 - cypress 版本命令的输出

前面的截图显示了我机器上安装的 Cypress 包和二进制版本。Cypress 的包版本和二进制版本都是相同的版本。

## Cypress 命令使用的可选练习

在我们项目规范中定义的**todoMVC**项目中，创建一个脚本，可以运行以下测试场景：

+   使用 edge 浏览器进行无头测试。

+   在`chapter 03`根文件夹中的`cypress.json`中指定`TransferProtocol`环境变量的测试运行器上的测试。

通过这个练习，您将了解如何运行有头和无头测试，以及如何向脚本添加环境变量，以便我们可以使用不同的 Cypress 命令来执行。您还将学习如何使用不同的浏览器来执行 Cypress 测试。

## 总结 - 了解基本的 Cypress 命令

在本节中，我们学习了如何使用不同的 Cypress 命令来使用命令行或 Cypress 测试运行器运行 Cypress，后者使用已安装在系统上的不同浏览器运行。我们了解到，尽管 Cypress 带有默认命令来运行测试，但我们可以扩展这些命令，并通过利用可用的命令和选项来定制 Cypress 以增加运行测试的效率。我们还提供了一个练习，让您应用您对`cypress run`和`cypress open`命令的使用知识。在下一节中，您将学习如何使用内置的 Cypress 调试器来查看重要的调试信息，这对于使用我们的终端进行故障排除非常重要。

# 在命令行上进行 Cypress 调试

在本节中，我们将探讨如何使用 Cypress 的命令行调试属性来解决运行测试时可能遇到的问题。我们还将探讨 Cypress 通过命令行提供的不同调试选项。

Cypress 具有内置的调试模块，可以通过在运行测试之前使用`cypress run`或`cypress open`传递调试命令来向用户公开。要从终端接收调试输出，需要在 Mac 或 Linux 环境中设置`DEBUG`环境变量，然后再运行 Cypress 测试。

以下脚本可以在`chapter-03/`根目录的`package.json`文件中找到，并用于在执行命令时显示调试输出。第一个脚本可用于在使用`cypress open`命令运行测试时显示调试输出，而第二个脚本可用于在使用`cypress run`命令运行测试时显示调试输出：

```js
"scripts": {
"cypress:open:debugger": "DEBUG=cypress:* cypress open --env TransferProtocol='http'",
    "cypress:run:debugger": "DEBUG=cypress:* cypress run --
    env TransferProtocol='http'"
  },
} 
```

如前述命令所示，运行`npm run cypress:open:debugger`将在终端中运行 Cypress 测试，并记录运行时的调试输出。第二个命令可以通过`npm run cypress:run:debugger`运行，将在 Cypress 测试运行器上运行测试时运行调试器。

Cypress 使得过滤调试输出变得容易，因为您可以选择有关特定模块的调试信息，例如 Cypress 服务器、CLI 或启动器模块。

以下脚本位于本书 GitHub 存储库的`chapter-03/`目录中的`package.json`文件中。运行时，它将为 Cypress 服务器模块下的所有日志提供调试输出：

```js
...
"scripts": {
"cypress:open:server-debugger": "DEBUG=cypress:server:* cypress open --env TransferProtocol='http'"
} 
...
```

使用`npm run cypress:run:server-debugger`运行上述命令将只输出与 Cypress 服务器相关的调试器信息。使用过滤命令不仅可以轻松缩小 Cypress 中的问题范围，还有助于过滤噪音，留下对于调试 Cypress 信息重要的日志，并将我们带到问题的源头。

## Cypress 调试的可选练习

使用我们项目规范中定义的**todoMVC**项目，在脚本中创建将运行以下测试场景的脚本：

+   调试 Cypress CLI 模块

+   调试`cypress:server`项目模块

通过本次练习，您将掌握 Cypress 调试的概念，并了解如何在`package.json`文件中创建和运行 Cypress 脚本。

## 回顾-在命令行上调试 Cypress

在本节中，我们学习了如何利用 Cypress 通过设置`DEBUG`环境变量查看有关测试运行的其他信息。我们还学习了如何利用 Cypress 的`debug`变量来过滤我们需要的调试输出，并进行了一项练习，以扩展我们在命令行上调试的知识。

# 总结

在本章中，我们学习了`cypress open`和`cypress run`命令，以及如何使用配置选项将这两个命令链接起来以扩展它们的用途。我们还学习了如何检查已安装在系统上的 Cypress 信息和 Cypress 版本。在最后一节中，我们学习了如何使用 Cypress 提供调试输出，并找出测试失败的原因。在下一章中，我们将深入了解编写 Cypress 测试和理解测试的不同部分。


# 第四章：编写您的第一个测试

在开始本章之前，您需要了解 Cypress 测试的运行方式，不同的 Cypress 命令，如何设置 Cypress，在命令行上运行 Cypress 以及如何使用测试运行器打开 Cypress 测试。这些信息在前三章中已经涵盖，将帮助您更好地理解我们在本章中编写第一个测试时所要建立的基础知识。

在本章中，我们将介绍创建测试文件和编写基本测试的基础知识，然后我们将继续编写更复杂的测试，并使用 Cypress 断言各种元素。

我们将在本章中涵盖以下主题：

+   创建测试文件

+   编写您的第一个测试

+   编写实用测试

+   Cypress 的自动重新加载功能

+   Cypress 断言

通过完成本章，您将准备好学习如何使用测试运行器调试运行中的测试。

# 技术要求

本章的 GitHub 存储库可以在以下链接找到：

[`github.com/PacktPublishing/End-to-End-Web-Testing-with-Cypress`](https://github.com/PacktPublishing/End-to-End-Web-Testing-with-Cypress)

本章的源代码可以在`chapter-04`目录中找到。

# 创建测试文件

Cypress 中的所有测试必须在测试文件中才能运行。要使测试被认为是有用的，它必须验证我们在测试中定义的所有条件，并返回一个响应，说明条件是否已满足。Cypress 测试也不例外，所有在测试文件中编写的测试都必须有一组要验证的条件。

在本节中，我们将介绍编写测试文件的过程，从 Cypress 中测试文件应该位于的位置开始，Cypress 支持的不同扩展名，以及 Cypress 中编写的测试文件应该遵循的文件结构。

## 测试文件位置

Cypress 在初始化时默认在`cypress/integration/examples`目录中创建测试文件。但是，这些文件可以被删除，因为它们旨在展示利用不同的 Cypress 测试类型和断言的正确格式。Cypress 允许您在定位不同模块和文件夹结构时具有灵活性。

建议在您第一次项目中工作时，使用前面段落中提到的位置来编写您的 Cypress 测试。要重新配置 Cypress 文件夹结构，您可以更改 Cypress 默认配置并将新配置传递到`cypress.json`文件中。更改默认 Cypress 配置的一个很好的例子是将我们的测试目录从`cypress/integration/examples`更改为`cypress/tests/todo-app`或其他位置。要更改默认目录，我们只需要更改我们的`cypress.json`配置，如下所示：

```js
{
"integrationFolder": "cypress/tests"
}
```

前面的代码块显示了`integrationFolder`设置，它改变了 Cypress `tests`字典的配置方式。

## 测试文件扩展名

Cypress 接受不同的文件扩展名，这使我们能够编写超出正常 JavaScript 默认格式的测试。以下文件扩展名在 Cypress 测试中是可接受的：

+   `.js`

+   `.jsx`

+   `.coffee`

+   `.cjsx`

除此之外，Cypress 还原生支持 ES2015 和 CommonJS 模块，这使我们可以在没有任何额外配置的情况下使用**import**和**require**等关键字。

## 测试文件结构

Cypress 中的测试文件结构与大多数其他用于编写测试或甚至普通 JavaScript 代码的结构类似。Cypress 测试的结构考虑了模块导入和声明，以及包含测试的测试主体。这可以在以下示例测试文件中看到：

```js
 // Module declarations
import {module} from 'module-package';
 // test body
describe('Test Body', () => {
   it('runs sample test', () => {
      expect(2).to.eq(2);
   })
})
```

正如您所看到的，每个测试文件都需要在测试文件的最顶部进行声明。通过这样做，测试可以嵌套在`describe`块中，这些块指定了将要运行的测试的范围和类型。

## 创建我们的测试文件

使用*技术要求*部分中的 GitHub 链接，打开`chapter-04`文件夹。按照以下步骤创建您的第一个测试文件：

1.  导航到 Cypress 目录内的`integration`文件夹目录。

1.  创建一个名为`sample.spec.js`的空测试文件。

1.  为了演示目的，我们已经在`chapter-04`根目录中为您创建了一个`package.json`文件。您现在只需要运行命令，不用担心它们的工作原理。

1.  使用`npm run cypress:run`命令启动 Cypress 测试运行器。

1.  检查测试运行器预览，并确认我们添加的测试文件是否可见。

现在是快速回顾的时候了。

## 总结-创建测试文件

在本节中，我们学习了如何创建测试文件，Cypress 如何接受不同的测试文件格式，以及如何更改 Cypress 测试的默认目录。我们还学习了测试的结构，以及 Cypress 如何借鉴诸如 JavaScript 等语言的测试格式。在下一节中，您将专注于编写您的第一个测试。

# 编写您的第一个测试

Cypress 测试与任何其他测试没有区别。与所有其他测试一样，当预期结果与被测试应用程序的预期一致时，Cypress 测试应该通过；当预期结果与应用程序应该执行的操作不一致时，测试应该失败。在本节中，我们将探讨不同类型的测试、测试的结构以及 Cypress 如何理解测试文件中的更改并重新运行测试。本节还将介绍如何编写实用测试。

## 示例测试

在本节中，我们将看一下 Cypress 测试的基本结构。这在本章的大部分测试中保持标准。以下测试检查我们期望的结果和返回的结果是否等于`true`。当我们运行它时，它应该通过：

```js
describe('Our Sample Test', () => {
  it('returns true', () => {
    expect(true).to.equal(true);
  });
});
```

在这里，我们可以看到测试中有`describe()`和`it()`钩子。Cypress 测试中包含的钩子默认来自**Chai**断言库，Cypress 将其用作默认断言库。这些钩子用于帮助您理解测试的不同阶段。`describe`钩子帮助将不同的测试封装到一个块中，而`it`钩子帮助我们在测试块中识别特定的测试。

重要提示

Chai 断言库作为一个包包含在 Cypress 框架中。这是 Cypress 用来验证测试成功或失败的默认断言库。

考虑到我们在本节中看到的测试，我们现在将探讨 Cypress 中不同类型的测试分类。

## 测试分类

测试可以根据运行后产生的结果进行分类。Cypress 测试也可以根据它们的状态进行分类。测试可以处于以下任何状态：

+   通过

+   失败

+   跳过

在接下来的几节中，我们将详细了解这三个类别。

### 通过测试

通过测试是正确验证输入是否与预期输出匹配的测试。在 Cypress 中，通过测试会被清晰地标记为通过，并且这在命令日志和 Cypress 测试运行器上是可见的。使用我们之前创建的`sample.spec.js`文件，我们可以创建我们的第一个通过测试，如下面的代码块所示：

```js
describe('Our Passing Test', () => {
  it('returns true', () => {
    expect(true).to.equal(true);
  });
});
```

要在使用`chapter-04`目录作为参考时运行测试，我们可以在命令行界面上运行以下命令：

```js
npm run cypress:open 
```

在这个测试中，我们正在验证给定的输入`true`是否与我们期望的测试输出`true`相似。这个测试可能并不是非常有用，但它的目的是展示一个通过的测试。以下截图显示了一个通过的测试：

![图 4.1-通过测试](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_4.1_B15616.jpg)

图 4.1 – 通过的测试

前面的截图显示了在命令日志中通过测试的结果。我们可以通过查看左上角的绿色复选标记进一步验证测试是否通过了所有其他条件。

### 失败的测试

与通过的测试一样，失败的测试也验证测试输入与测试期望，并将其与结果进行比较。如果预期结果和测试输入不相等，则测试失败。Cypress 在显示失败的测试并描述测试失败方面做得很好。使用我们之前创建的`sample.spec.js`文件，创建一个失败的测试，如下面的代码块所示：

```js
describe('Our Failing Test', () => {
  it('returns false, () => {
    expect(true).to.equal(false);
  });
});
```

要运行测试，我们将使用`chapter-04`目录作为参考，然后在终端中运行以下命令：

```js
npm run cypress:open
```

在这个失败的测试中，我们将一个`true`的测试输入与一个`false`的测试期望进行比较，这导致了一个设置为`true`的失败测试，它不等于`false`。由于它未通过确定我们的测试是否通过的验证，测试自动失败。以下截图显示了我们失败测试的结果在命令日志中：

![图 4.2 – 失败的测试](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_4.2_B15616.jpg)

图 4.2 – 失败的测试

查看命令日志，我们可以看到我们有两个测试：一个通过，一个失败。在失败的测试中，Cypress 命令日志显示了未满足我们期望的断言。另一方面，测试运行器继续显示一个失败的测试，作为我们测试运行的摘要。当测试失败时，Cypress 允许我们阅读发生的确切异常。在这种情况下，我们可以清楚地看到测试在断言级别失败，原因是断言不正确。

### 跳过的测试

Cypress 中的跳过测试不会被执行。跳过测试用于省略那些要么失败要么不需要在执行其他测试时运行的测试。跳过测试在其测试钩子后缀为`.skip`关键字。我们可以通过使用`describe.skip`跳过整个代码块中的测试，或者通过使用`it.skip`跳过单个测试。以下代码块显示了两个测试，其中主`describe`块被跳过，另一个测试在`describe`块内被跳过。以下代码说明了跳过 Cypress 测试的不同方法：

```js
describe.skip('Our Skipped Tests', () => {
    it('does not execute', () => {
        expect(true).to.equal(true);
    });
    it.skip('is skipped', () => {
        expect(true).to.equal(false);
    });
});
```

在这里，我们可以看到当我们在`it`或`describe`钩子中添加`.skip`时，我们可以跳过整个代码块或特定测试。以下截图显示了一个跳过的测试：

![图 4.3 – 跳过测试](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_4.3_B15616.jpg)

图 4.3 – 跳过测试

跳过的测试在命令日志和测试运行器中只显示为跳过；对于已跳过的测试块或单个测试，不会发生任何活动。前面的截图显示了我们在`sample.spec.js`文件中定义的跳过测试的状态，该文件可以在我们的`chapter-04`GitHub 存储库目录中找到。现在我们知道如何编写不同类型的测试，我们可以开始编写实际的测试。但首先，让我们测试一下我们的知识。

## 测试分类练习

使用您在本章节阅读中获得的知识，编写符合以下标准的测试：

+   一个通过的测试，断言一个变量是`string`类型

+   一个失败的测试，断言一个有效的变量等于`undefined`

+   一个跳过的测试，检查布尔变量是否为`true`

现在，让我们回顾一下本节我们所涵盖的内容。

## 总结 – 编写您的第一个测试

在本节中，我们学习了如何识别不同类型的测试，并了解了 Cypress 框架如何处理它们。我们学习了通过测试、失败测试和跳过测试。我们还学习了 Cypress 测试运行器如何显示已通过、失败或已跳过的测试状态。最后，我们进行了一项练习，以测试我们对测试分类的知识。现在，让我们继续撰写一个实际的测试。

# 撰写实际测试

在上一节中，我们学习了 Cypress 中不同测试分类的基础知识以及分类结果。在本节中，我们将专注于编写超越断言布尔值是否等于另一个布尔值的测试。

对于任何测试都需要有价值，它需要有三个基本阶段：

1.  设置应用程序的期望状态

1.  执行要测试的操作

1.  在执行操作后断言应用程序的状态

在我们的实际测试中，我们将使用我们的**Todo**应用程序来编写与编写有意义的测试所需的三个基本阶段相对应的测试。为此，我们将完成以下步骤：

1.  访问 Todo 应用程序页面。

1.  搜索元素。

1.  与元素交互。

1.  对应用程序状态进行断言。

这些步骤将指导我们即将撰写的实际测试，并将帮助我们全面了解 Cypress 测试。

## 访问 Todo 应用程序页面

这一步涉及访问 Todo 应用程序页面，这是我们将运行测试的地方。Cypress 提供了一个内置的`cy.visit()`命令用于导航到网页。以下代码块显示了我们需要遵循的步骤来访问我们的 Todo 页面。这个代码块可以在本书的 GitHub 存储库的`chapter-04`文件夹中的`practical-tests.spec.js`文件中找到：

```js
describe('Todo Application tests', () => {
  it('Visits the Todo application', () => {
    cy.visit('http://todomvc.com/examples/react/#/')
  })
})
```

当此测试运行时，在观察命令日志时，我们将看到`visit`命令，以及我们刚刚访问的应用程序在右侧的 Cypress 应用程序预览中，如下图所示：

![图 4.4 - 访问 Todo 应用程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_4.4_B15616.jpg)

图 4.4 - 访问 Todo 应用程序

即使我们的应用程序没有任何断言，我们的测试仍然通过，因为没有导致 Cypress 抛出异常从而导致测试失败的错误。Cypress 命令默认会在遇到错误时失败，这增加了我们在编写测试时的信心。

## 搜索元素

为了确保 Cypress 在我们的应用程序中执行某些操作，我们需要执行一个会导致应用程序状态改变的操作。在这里，我们将搜索一个 Todo 应用程序输入元素，该元素用于*添加一个 Todo*项目到我们的应用程序中。以下代码块将搜索负责添加新 Todo 项目的元素，并验证它是否存在于我们刚刚导航到的 URL 中：

```js
it('Contains todo input element', () => {
  cy.visit('http://todomvc.com/examples/react/#/')
  cy.get('.new-todo')
});
```

当 Cypress 的`cy.get()`命令找不到输入元素时，将抛出错误；否则，Cypress 将通过测试。要获取输入元素，我们不需要验证元素是否存在，因为 Cypress 已经使用大多数 Cypress 命令中链接的**默认断言**来处理这个问题。

重要提示

Cypress 中的默认断言是内置机制，将导致命令失败，而无需用户声明显式断言。通过这些命令，Cypress 会处理异常的行为，如果在执行该命令时遇到异常。

以下屏幕截图显示了 Cypress 搜索负责向我们的 Todo 列表添加 Todo 项目的 Todo 输入元素：

![图 4.5 - 搜索 Todo 输入元素](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_4.5_B15616.jpg)

图 4.5 - 搜索 Todo 输入元素

在这里，我们可以验证 Cypress 访问了 Todo 应用程序的 URL，然后检查添加 Todo 项目的输入元素是否存在。

## 与待办事项输入元素交互

现在我们已经确认我们的待办事项应用程序中有一个输入元素，是时候与应用程序进行交互并改变其状态了。为了改变待办事项应用程序的状态，我们将使用我们验证存在的输入元素添加一个待办事项。Cypress 将命令链接在一起。为了与我们的元素交互，我们将使用 Cypress 的`.type()`命令向元素发送一个字符串，并将待办事项添加到应用程序状态中。以下的代码块将使用待办事项输入元素添加一个新的待办事项：

```js
it('Adds a New Todo', () => {
  cy.visit('http://todomvc.com/examples/react/#/')
  cy.get('.new-todo').type('New Todo {enter}')
});
```

上面的代码块建立在之前的代码基础上，使用了 Cypress 的`type()`函数来添加一个新的待办事项。在这里，我们还调用了 Cypress `type`方法的`{enter}`参数来模拟*Enter*键的功能，因为待办事项应用程序没有提交按钮供我们点击来添加新的待办事项。以下的截图显示了添加的待办事项。通过这个项目，我们可以验证我们的测试成功地添加了一个新的待办事项。这个项目在待办事项列表上是可见的：

![图 4.6 – 与待办事项输入元素交互](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_4.6_B15616.jpg)

图 4.6 – 与待办事项输入元素交互

我们的测试运行器显示已创建了一个新的待办事项。再次，我们的测试通过了，即使没有断言，因为已运行的命令已经通过了默认的 Cypress 断言。现在，我们需要断言应用程序状态已经改变。

## 断言应用程序状态

现在我们已经添加了我们的待办事项，我们需要断言我们的新待办事项已经被添加，并且应用程序状态已经因为添加待办事项而改变。为了做到这一点，我们需要在添加待办事项后添加一个断言。在下面的代码块中，我们将断言我们对应用程序状态的更改。在这里，我们添加了一个断言来检查`.Todo-list`类，它包含了列表项，是否等于`2`：

```js
it('asserts change in application state', () => {
      cy.visit('http://todomvc.com/examples/react/#/')

      cy.get('.new-todo').type('New Todo {enter}')
      cy.get('.new-todo').type(Another Todo {enter}')
      cy.get(".todo-list").find('li').should('have.length', 2)
   });
```

为了进一步验证我们的状态更改，我们可以添加更多的待办事项来验证随着我们添加待办事项，待办事项的数量是否增加。

在 Cypress 中，我们可以使用断言函数，比如`.should()`和`expect()`，它们都包含在构成 Cypress 的工具中。默认情况下，Cypress 扩展了 Chai 库中的所有函数，这是默认的 Cypress 断言库。下面的截图显示了两个已添加的待办事项和 Cypress 预览中的确认说明，说明这两个已添加的待办事项存在于待办事项列表中：

![图 4.7 – 断言应用程序状态](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_4.7_B15616.jpg)

图 4.7 – 断言应用程序状态

在这个测试中，我们可以验证所有添加的待办事项是否在 Cypress 应用程序的预览页面上可见，并且我们的断言通过了。现在我们可以添加更多的断言，特别是检查第一个待办事项的名称是否为`New Todo`，而另一个添加的待办事项是否叫做`Another Todo`。为了做到这一点，我们将在我们的测试中添加更多的断言，并检查我们的待办事项的具体细节。在下面的代码块中，我们将验证 Cypress 是否能够检查已添加的待办事项的名称；即*New Todo*和*Another Todo*：

```js
  it('asserts inserted todo items are present', () => {
     cy.visit('http://todomvc.com/examples/react/#/')

     cy.get('.new-todo').type('New Todo {enter}')
     cy.get('.new-todo').type('Another Todo {enter}')
     cy.get(".todo-list").find('li').should('have.length', 2)
     cy.get('li:nth-child(1)>div>label').should(         'have.text', 'New Todo')
     cy.get('li:nth-child(2)>div>label').should(         'have.text', 'Another Todo')
    });
```

在这些断言中，我们使用了 Cypress 的`cy.get()`方法通过它们的 CSS 类来查找元素，然后通过它们的文本标识了第一个和最后一个添加的待办事项。

## 实际测试练习

使用*技术要求*部分提到的 GitHub 存储库链接，编写一个测试，导航到待办事项应用程序并向其添加三个新的待办事项。编写测试来检查已添加的待办事项是否存在，通过验证它们的值和数量。

## 总结 – 编写实际测试

在本节中，我们编写了我们的第一个实际测试。在这里，我们访问了一个页面，检查页面是否有一个输入元素，与该元素进行交互，并断言应用程序状态是否发生了变化。在了解了 Cypress 中测试的流程之后，我们现在可以继续并了解 Cypress 中使测试编写变得有趣的功能，比如自动重新加载。

# Cypress 的自动重新加载功能

默认情况下，Cypress 会监视文件更改，并在检测到文件更改时立即重新加载测试。这仅在 Cypress 运行时发生。Cypress 的自动重新加载功能非常方便，因为您无需在对测试文件进行更改后重新运行测试。

通过自动重新加载功能，可以立即获得反馈，并了解他们的更改是否成功，或者他们的测试是否失败。因此，这个功能可以节省本来用于调试测试或检查所做更改是否修复问题的时间。

虽然 Cypress 的自动重新加载功能默认启用，但您可以选择关闭它，并在进行更改后手动重新运行测试。Cypress 允许您停止监视文件更改。这可以通过配置`cypress.json`文件或使用 Cypress 的命令行配置选项来完成。在使用`cypress.json`配置文件时，您必须使用以下设置来禁用监视文件更改：

```js
{
 "watchForFileChanges": "false"
}
```

此设置将持续并永久禁用文件更改，只要 Cypress 正在运行，除非配置被更改为`true`。在禁用 Cypress 监视文件更改方面的另一个选项是使用此处显示的命令行配置选项：

```js
cypress open --config watchForFileChanges=false
```

使用这个命令，Cypress 将暂时停止监视文件更改，并且只有在我们在终端窗口停止 Cypress 执行时才会改变这种行为。然后 Cypress 将继续监视文件更改，并在对测试文件进行更改时自动重新加载。

## 总结 - Cypress 的自动重新加载功能

在本节中，我们学习了 Cypress 如何利用自动重新加载功能来监视文件更改，并在测试文件发生任何更改时立即重新加载和重新运行。我们还学习了如何通过永久禁用它使用`cypress.json`文件或在运行测试时通过命令行配置传递命令来轻松关闭 Cypress 的自动重新加载功能。接下来，我们将看看 Cypress 断言。

# Cypress 断言

正如我们在上一节中学到的，当编写我们的第一个测试时，断言存在是为了描述应用程序的期望状态。Cypress 中的断言就像是测试的守卫，它们验证期望状态和当前状态是否相同。Cypress 断言是独特的，因为它们在 Cypress 命令运行时会重试，直到超时或找到元素为止。

Cypress 断言源自**chai**、**chai-jquery**和**sinon-chai**模块，这些模块与 Cypress 安装捆绑在一起。Cypress 还允许您使用 Chai 插件编写自定义断言。但是，在本节中，我们将重点放在 Cypress 捆绑的默认断言上，而不是可以扩展为插件的自定义断言。

我们可以以两种方式编写 Cypress 断言：要么显式定义主题，要么隐式定义主题。Cypress 建议在断言中隐式定义主题，因为它们与 Cypress 命令正在处理的元素直接相关。以下是 Cypress 框架中断言的分类方式：

+   隐式主题：`.should()`或`.and()`

+   显式主题：`expect()`

让我们详细看看每一个。

## 隐式主题

`should`或`and`命令是 Cypress 命令，这意味着它们可以直接作用于 Cypress 立即产生的主题。这些命令也可以与其他 Cypress 命令链接，这使它们易于使用，同时在调用它们时保证立即响应。以下代码块演示了如何测试隐式主题。在这里，我们将使用`cy.get`命令的输出来对我们的测试进行断言：

```js
describe('Cypress Assertions', () => {
    it('Using Implicit subjects - should', () => {
        cy.visit('http://todomvc.com/examples/react/#/')
        // Check if todo input element has expected 
        // placeholder value
        cy.get(".new-todo").should('have.attr', 'placeholder',
        'What needs to be done?')
    });
});
```

在这里，我们使用`should()`命令来断言 Todo 项目的输入元素是否具有占位符值。`should`命令是从`cy.get()`命令链接的。这不仅使其易于使用，而且还减少了断言占位符是什么的代码量。在以下代码块中，我们正在组合`cy.get`命令返回的隐式主题的不同断言：

```js
it('Using Implicit subjects - and()', () => {
        cy.visit('http://todomvc.com/examples/react/#/')
        // Check if todo input element has expected   
        // placeholder value
        cy.get(".new-todo")
         .should('have.attr', 'placeholder',
          'What needs to be done?')
        .and('have.class', 'new-todo')
    });
```

在这里，我们使用了`.and()`Cypress 命令来进一步验证刚刚产生的元素既有一个占位符，又有一个名为`new-todo`的 CSS 类。通过这些隐式断言，我们可以验证通过隐式主题，我们可以从 Cypress 的相同产生的响应中链接多个命令，并且还可以断言不同的项目。以下代码块显示了使用显式主题进行的代码断言，其中我们必须声明我们正在断言的每个主题：

```js
it('Using Explicit subjects', () => {
        cy.visit('http://todomvc.com/examples/react/#/')
        cy.get(".new-todo").should( ($elem) => {
        expect($elem).to.have.class('new-todo')
        expect($elem).to.have.attr('placeholder','What needs 
        to be done?')
        })
    });
```

正如您所看到的，当使用隐式主题时，我们可以进行更清晰的断言，并减少我们编写的代码量。在这个代码块中，每个断言都必须在同一行上并且单独执行。

## 显式主题

当我们想要断言在运行测试时定义的特定主题时，我们使用`expect()`。显式主题在**单元测试**中很常见，在需要在执行断言之前执行一些逻辑或者对同一主题进行多个断言时非常有用。以下代码块显示了使用`expect`方法进行显式主题断言：

```js
it('can assert explicit subjects', () => {
  const eqString = 'foo';  
  expect(eqString).to.eq('foo');
  expect(eqString).to.have.lengthOF(3);
  expect(eqString).to.be.a('string');
})
```

这个代码块显示了对实例化的`string`与我们的期望进行显式比较。声明的`string`是一个显式主题，这意味着它可以被断言多次，并且在执行断言之前也可以被操作。

对于复杂的断言，我们可以使用`.should()`方法来断言显式主题。这允许传递一个回调函数作为第一个参数，该回调函数具有作为第一个参数产生的主题。我们可以在`should`函数内添加断言，如下所示：

```js
it('Using Should with Explicit subjects', () => {
        cy.visit('http://todomvc.com/examples/react/#/')
        cy.get(".new-todo").should( ($elem) => {
        expect($elem).to.have.class('new-todo')
        })
 });
```

在这里，我们访问了 URL，然后使用从`cy.get('new-todo')`产生的元素来断言名为`new-todo`的 CSS 类是否存在。这个测试允许我们查询一个元素，并且根据需要为主题编写不同的断言。

## 练习-隐式和显式主题

使用您从本节中获得的知识，并使用*技术要求*部分提到的 GitHub 存储库链接作为参考点，完成以下练习。

转到 Todo 应用程序 URL（[`todomvc.com/examples/react/#/`](http://todomvc.com/examples/react/#/)）并添加一个 Todo：

+   使用隐式主题断言编写一个测试，以断言 Todo 已添加，并且输入的名称与 Todo 项目列表上显示的名称相同。

+   在 Todo 应用程序 URL 上，将一个 Todo 标记为已完成。然后，使用显式主题的断言，编写一个测试来验证已完成的 Todo 是否已标记为已完成。

## 总结- Cypress 断言

在本节中，我们学习了如何断言显式和隐式主题，并看了它们之间的不同和相似之处。我们还了解到不同的断言类型可以用于不同的主题。然后我们有机会进行练习，以练习我们断言隐式和显式主题的技能。

# Summary

在本章中，我们学习了如何通过理解 Cypress 中的通过、失败和跳过测试的含义以及 Cypress 在测试运行器和命令日志中查看和表示测试来对测试进行分类。我们还了解了测试文件的结构以及 Cypress 测试的可接受文件扩展名。然后，我们编写了我们的第一个实际测试，测试了一个待办事项应用程序能够添加、删除和标记待办事项为已完成。本章的重点是学习 Cypress 如何监视文件更改以及我们如何在 Cypress 中进行断言，无论是通过显式断言我们的测试对象还是隐式断言它们。通过完成本章，您将了解如何通过使用元素并理解可用的断言来在 Cypress 中编写基本测试。在下一章中，我们将学习如何在 Cypress 中调试运行测试以及我们可以用于此目的的工具。


# 第五章：调试 Cypress 测试

调试是识别和消除软件应用程序中的错误的能力。了解 Cypress 中的调试并学习如何解释 Cypress 的调试输出对于使用 Cypress 框架至关重要。Cypress 以其能够立即提供关于测试是否通过或失败的反馈而自豪。为了让 Cypress 实现即时反馈机制，它必须在调试消息的结构上有效，以便为用户提供解释的便利性。

要在本章取得成功，您需要阅读前几章，因为它们将帮助您了解测试的运行方式，Cypress 的工作原理以及我们可以运行 Cypress 测试的不同方式。在本章中，我们将专注于在测试运行器中运行 Cypress 测试时调试 Cypress 测试。

虽然本章将探讨使用测试运行器调试 Cypress，但 Cypress 捆绑了其他调试工具，我们可能不会在本章中涵盖，因为它们要么已经在前几章中涵盖过，要么超出了本书的范围。在本章中，我们将学习 Cypress 调试在测试运行器中的工作原理。为此，我们将涵盖以下主题：

+   理解页面事件

+   理解测试运行器上的错误

+   理解执行测试的时间旅行

+   理解测试快照

+   理解控制台调试输出

+   特殊调试命令

一旦您完成了这些主题中的每一个，您就准备好开始本书的第二部分，其中涉及使用**测试驱动开发**（**TDD**）方法编写 Cypress 测试。

# 技术要求

本章的 GitHub 存储库可以在[`github.com/PacktPublishing/End-to-End-Web-Testing-with-Cypress`](https://github.com/PacktPublishing/End-to-End-Web-Testing-with-Cypress)找到。

本章的源代码可以在`chapter-05`目录中找到。

# 理解页面事件

Cypress 记录测试运行时发生的每个主要事件。它可以检测到 URL 的更改，按钮的点击，甚至断言的执行。页面事件捕获了测试运行时 DOM 经历的重要事件。

为了演示页面事件的工作原理，我们将使用我们的待办事项应用程序，就像在上一章中一样。在我们的 GitHub 存储库中的`chapter-05`目录中，我们将在 Cypress 集成子目录中创建我们的测试文件，并将其命名为`debugging.spec.js`。然后，我们将在新创建的规范文件中创建我们的测试，该测试将导航到待办事项应用程序，添加一个待办事项，并检查在我们的 Cypress 测试运行器中弹出的页面事件。以下代码块将处理将待办事项添加到我们的应用程序中：

```js
it('can add a todo', () => {
      cy.get(".new-todo").type("New Todo {Enter}");
      cy.get(".todo-list").find('li').should('have.length', 
      1)
 });
```

在这个测试中，我们正在添加一个待办事项，并检查我们添加的项目是否可以从待办事项列表中查看。以下屏幕截图显示了一个 XHR 页面事件：

![图 5.1 - XHR 页面事件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_5.1_B15616.jpg)

图 5.1 - XHR 页面事件

上述屏幕截图显示了前一个测试的命令日志的一部分。名为`xhr`的突出显示部分是在 Cypress 中加载新页面的页面事件。页面事件由 Cypress 机制自动检测到，并自动记录 - 不是作为需要执行的命令，而是作为触发应用程序状态变化的事件。

Cypress 记录以下页面事件：

+   提交表单

+   加载新页面

+   用于网络调用的 XHR 请求

+   测试 URL 的哈希更改

要识别 Cypress 页面事件，我们需要查找 Cypress 命令日志中灰色且没有任何编号的日志，例如在执行 Cypress 测试中的命令。

## 总结 - 理解页面事件

在本节中，我们介绍了页面事件是什么，它们何时以及如何被记录，以及如何在 Cypress 中识别它们。我们还了解到页面事件在追踪测试执行时发生的主要事件方面是有用的。在下一节中，我们将看看当测试抛出错误时如何获得进一步的调试信息。我们将通过理解可能抛出的错误消息来做到这一点。

# 了解测试运行器上的错误

在本节中，我们将解析测试运行器上的 Cypress 错误，从而解开 Cypress 抛出的错误的内容以及如何解释它们。我们将涵盖 Cypress 错误中存在的不同类型的信息，包括错误名称、错误消息、代码框架文件、堆栈跟踪、打印到控制台选项和了解更多。了解 Cypress 中的错误不仅有助于我们编写更好的测试，还将在测试失败时指导我们进行调试过程。

Cypress 在测试失败事件中记录异常方面做得非常出色。Cypress 不仅记录了哪些测试失败，而且还深入挖掘了遇到的错误的具体信息。例如，Cypress 命令日志上可见成功的测试执行以及提供了可能导致遇到错误的描述性信息。有时，Cypress 甚至会在命令日志上打印出解决错误所需的建议。

在本节中，我们将在`debugging.spec.js`中添加一个测试，当在 Cypress 中运行时会抛出一个错误。在接下来的测试中，我们将探索 Cypress 在遇到错误时提供的信息，并尝试理解为什么这些信息与调试过程相关。

```js
it('Error Test: can add a todo', () => {
      cy.get(".new-todo").type("New Todo {Enter}");
      cy.get(".todo-list").find('li').should('have.length', 
      2)
 });
```

这个测试应该故意抛出一个错误，因为我们期望待办事项的数量等于`2`，尽管我们只添加了一个名为`New Todo`的待办事项。

Cypress 抛出的每个错误都包含以下信息。这些信息将帮助您确定问题的根源以及导致 Cypress 抛出错误的原因：

+   错误名称

+   错误消息

+   代码框架文件

+   代码框架

+   堆栈跟踪

+   打印到控制台选项

+   了解更多（可选）

让我们详细看看每一个。

## 错误名称

Cypress 会抛出不同类型的错误，这取决于它遇到的错误。Cypress 中的错误通过它们的类型进行识别，它们可以按照 Cypress 错误和断言错误等类型进行分类。Cypress 抛出的错误类型有助于调试。这是因为我们可以充分了解测试是从正在运行的测试失败还是 Cypress 内部遇到的错误。这个错误显示在*图 5.2*中，被引用为*1*，带有错误名称。

## 错误消息

每个错误都伴随着一条消息。这条消息详细解释了测试运行时出了什么问题。错误消息因测试而异。虽然有些消息可能很直接地告诉您出了什么问题，但其他消息会更进一步，甚至详细说明您可以采取哪些步骤来修复错误。一些错误消息包含一个**了解更多**部分，它将引导您查阅与遇到的错误相关的 Cypress 文档。这个错误消息显示在*图 5.2*中，被引用为*2*。

## 代码框架文件

这是包含 Cypress 遇到的错误的文件。该文件显示为堆栈跟踪的最顶部项目。代码框文件显示了在 Cypress 错误框中突出显示的行号和列号。当单击堆栈跟踪中的代码框文件时，它将在首选编辑器中打开，并突出显示发生错误的行和列，如果用于打开文件的编辑器支持代码突出显示的话。我们可以在图 5.2 中看到代码框文件，它被引用为数字*3*。

## 代码框

这是 Cypress 标记为错误原因的代码片段。它可以在先前提到的代码框文件中找到。Cypress 在代码框片段中突出显示了导致测试执行问题的特定行，以及列。我们可以通过检查图 5.2 中标有*4*的代码片段来确定导致失败的代码框。

## 堆栈跟踪

堆栈跟踪显示了在错误发生时正在执行的不同方法，导致了异常。在 Cypress 错误中，您可以切换堆栈跟踪，它可以在错误的代码框下方找到。这应该向您显示测试在遇到错误并失败时正在执行的函数。图 5.2 中的数字*5*显示了堆栈跟踪区域。

## 打印到控制台

Cypress 错误还为您提供了将遇到的错误打印到 DevTools 控制台的选项。将遇到的错误打印到命令提示符的选项使我们能够选择堆栈跟踪中的一行并将其打印到控制台。我们可以在图 5.2 中看到这一点，标有*6*。

## 了解更多

正如我们之前提到的，一些测试失败会打印出一个**了解更多**的链接，单击该链接将为我们提供有关发生的错误的相关 Cypress 文档的指引。当错误可能需要调整断言或正在测试的期望之外的更多时，Cypress 失败会提供**了解更多**的链接：

![图 5.2 - 测试错误时显示的信息](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_5.2_B15616.jpg)

图 5.2 - 测试错误时显示的信息

前面的截图显示了测试抛出异常时显示的错误信息的时间结构。正如我们所看到的，测试只向待办事项列表添加了一个项目，但期望找到两个。错误发生在测试断言上，因为 Cypress 期望找到两个项目，但只找到了一个，导致了错误。

失败测试提供的信息对于调试过程至关重要。这是因为不仅易于确定测试失败的原因，而且还帮助我们了解需要进行哪些更改才能将测试从失败状态恢复到通过状态。

## 总结 - 了解测试运行器上的错误

在本节中，我们了解了 Cypress 错误的信息量有多大。我们得以调查嵌入在 Cypress 错误消息中的不同信息片段以及它们在调试过程中的作用。了解 Cypress 在发生错误时如何呈现其错误使我们能够知道如何处理 Cypress 错误以及了解这些错误来自何处。在接下来的部分，我们将看一下 Cypress 的时间旅行功能。

# 了解执行测试的时间旅行

时间旅行，就像科幻电影中的情节一样，但现在是在测试的背景下，它是指能够回到测试执行时的状态。当 Cypress 测试执行时，它们会创建 DOM 快照，我们可以利用这些快照来回溯时间，检查测试在不同时间和不同操作发生时的状态。通过时间旅行，我们可以检查预期的操作是否发生以及它是如何发生的。时间旅行还允许我们调查和审计测试运行时采取了哪些操作以及为什么会出现错误。

为了研究 Cypress 测试中的时间旅行，我们将导航到本书的 GitHub 存储库中的`chapter-05`文件夹，并在`debugging.spec.js`文件中创建一个新的测试，这是我们之前创建的。以下代码块是一个测试，将标记添加的待办事项为已完成。通过时间旅行，我们可以识别应用程序的不同状态，当我们添加待办事项时，然后将它们标记为已完成：

```js
it('can mark a todo as completed', () => {
      cy.get(".new-todo").type("New Todo {Enter}");
      cy.get(".new-todo").type("Another New Todo {Enter}");
      cy.get('.todo-list>li:nth-
      child(1)').find('.toggle').click();
      cy.get('.todo-list>li:nth-
      child(2)').find('.toggle').click();
    });
```

上面的代码块向待办事项列表中添加了两个待办事项，然后将待办事项标记为已完成。使用 Cypress 的时间旅行功能，我们可以参考 Cypress 来检查我们添加第一个待办事项时的状态，甚至是添加第二个待办事项时的状态。通过使用时间旅行功能，如下截图所示，我们可以进一步验证在将它们标记为已完成之前，这两个项目在正确的状态下，并且在执行过程中进行了适当的导航：

![图 5.3-测试中的时间旅行和 DOM 快照](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_5.3_B15616.jpg)

图 5.3-测试中的时间旅行和 DOM 快照

在上面的截图中，我们可以看到测试已经完成运行并且已经通过了。我们还可以看到我们可以倒退时间并调查当待办事项列表中的第一个待办事项被点击时发生了什么。由于 Cypress 可以倒退时间并在特定时间点向我们显示 DOM，我们实际上可以验证达到测试的最终结果的步骤——无论是测试通过还是测试失败。所示的数字显示了 Cypress 时间旅行机制的主要部分和事件发生的顺序。

时间旅行的第一步是等待测试运行完成，然后选择要倒退时间的步骤。Cypress 不仅显示测试步骤，还允许您将步骤的 DOM 快照固定到 Cypress 预览窗口。

选择时间旅行步骤后，我们选择的感兴趣的步骤被固定为 DOM 快照。我们可以查看步骤在当时的状态以及在操作发生后转变为的新状态。这可以在上面截图的预览窗口中看到。

时间旅行检查过程的第三步是在**之后**和**之前**之间选择 DOM 快照。在**之后**和**之前**之间切换显示 DOM 快照中的更改。这种切换帮助我们了解我们正在检查的 Cypress 步骤的操作如何改变了那个特定阶段的 DOM。当我们完成检查时，我们可以继续到下一个执行步骤并固定测试在那个特定执行步骤的状态。

重要提示

Cypress 时间旅行在测试仍在执行并且尚未通过或失败时不起作用。为了获得正确的结果，您必须等待执行完成，然后才能看到所有相关步骤的最终结果。

## 总结-了解执行测试的时间旅行

在本节中，我们了解了 Cypress 如何为我们提供时间旅行功能，以便我们可以返回到 Cypress 执行测试的不同步骤。在 Cypress 中进行时间旅行允许我们检查 Cypress 执行测试的步骤，无论是将其声明为失败还是通过。我们还有机会看到时间旅行功能如何与快照功能配合使用，我们将在下一节中介绍。

# 了解测试快照

当我们解释 Cypress 中的时间旅行过程时，我们简要介绍了快照的概念。然而，这并不意味着我们已经充分利用了快照功能的优势。

快照非常强大，因为它们让我们一睹测试的执行过程以及所采取的步骤，这些步骤要么导致测试失败，要么导致测试成功。当我们固定 DOM 快照时，Cypress 会冻结测试并突出显示所有已执行的操作。固定的快照允许我们检查 DOM 的状态，同时查看在该特定步骤中发生的所有事件。例如，在前面的屏幕截图中，在*步骤 2*中，有一个显示第一个待办事项被点击的**事件点击框**。以下屏幕截图显示了 Cypress 在测试运行时如何解释发生的事件：

![图 5.4 - 一个切换的待办事项的事件点击框](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_5.4_B15616.jpg)

图 5.4 - 一个切换的待办事项的事件点击框

在前面的屏幕截图中显示了事件点击框的作用。在这里，我们可以看到发生了一个点击事件，影响了待办事项应用程序的状态。

重要提示

事件点击框是在固定的 Cypress 快照上弹出的突出显示，以显示测试与元素的交互。事件点击框可以由 Cypress 事件触发，例如`.click()`方法。

**快照**菜单允许我们在快照的状态之间切换。如果发生了改变 DOM 的事件，我们可以切换以查看改变发生前的状态，然后切换以查看改变发生后的状态。**之前**快照切换将显示所选测试步骤触发的任何事件之前的状态。另一方面，**之后**切换将显示所选步骤触发事件后应用程序的状态。以下屏幕截图显示了固定的 DOM 快照的切换，显示了事件发生前快照的样子以及事件发生后快照的样子：

![图 5.5 - 一个 DOM 快照菜单](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_5.5_B15616.jpg)

图 5.5 - 一个 DOM 快照菜单

在前面的屏幕截图中，我们可以看到**快照**菜单项。第一个类似窗口的图标将隐藏或显示固定的 DOM 快照上的**事件点击框**，而**之前**和**之后**菜单用于显示所选步骤的 DOM 的转换。**快照**菜单的**关闭**图标在点击时会取消固定 DOM 快照，并将其恢复到没有固定 DOM 快照的测试完成步骤。

重要提示

快照菜单项的**之前**和**之后**事件的显示取决于发生的事件。在改变 DOM 状态的事件中，之前和之后的快照将是不同的。当执行的操作不直接改变 DOM 时：可能会在测试步骤的之前和之后状态中有相似的快照。

## 总结 - 理解测试快照

在本节中，我们学习了 Cypress 在每次测试运行后如何将重要的调试信息存储在 DOM 快照中。我们还学习了如何利用 Cypress 快照来检查测试步骤的前后状态，然后在调试的调查过程中使用这些信息。在接下来的部分中，我们将学习如何利用控制台的调试输出来获取信息。

# 理解控制台调试输出

在本节中，我们将了解如何利用 Cypress 的控制台调试输出来理解应用程序状态的变化。我们将在浏览器的控制台中打开并与控制台输出进行交互。理解浏览器控制台中的输出将使我们能够更好地调试测试，因为我们可以调查 Cypress 抛出的错误并快速解决问题。

Cypress 非常擅长提供调试信息。由于快照提供的所有信息可能不足够，Cypress 提供了额外的步骤，以便您可以查看特定步骤的信息及其对元素的影响。要查看控制台调试输出，我们需要打开 DevTools。要打开 Cypress 测试浏览器的 DevTools 控制台，我们需要按照一定的步骤进行操作，所有这些步骤将在以下各节中讨论。

## macOS

要在 macOS 上打开 Cypress 测试浏览器的**DevTools**控制台，请按照以下步骤操作：

1.  在 Cypress 测试浏览器预览时，用两根手指按住触控板。

1.  从弹出菜单中选择**Inspect**选项。

1.  从**DevTools**控制台中选择**Console**选项卡。

您还可以使用*Option* + *J*快捷键在 Mac 上打开**DevTools**菜单。

## Windows/Linux 操作系统

要在 Windows 和 Linux 操作系统上打开 Cypress 测试浏览器的**DevTools**控制台，请按照以下步骤操作：

1.  在 Cypress 测试预览时，右键单击 Cypress 测试浏览器。

1.  从浏览器弹出菜单中选择**Inspect**选项。

1.  从**DevTools**控制台中选择**Console**选项卡。

您还可以使用*Shift* + *Ctrl* + *J*快捷键在 Windows 操作系统或 Linux 上打开**DevTools**控制台。

一旦您可以看到控制台输出，请选择一个测试步骤，如下面的屏幕截图所示：

![图 5.6-浏览器控制台上的调试输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_5.6_B15616.jpg)

图 5.6-浏览器控制台上的调试输出

上述屏幕截图显示了在命令提示符上选择的 Cypress 命令的输出。正如我们所看到的，当单击特定命令步骤时，DOM 快照会固定到 Cypress 浏览器的预览屏幕上。固定 DOM 快照使我们能够在固定快照上无间断地与元素交互。

在上述屏幕截图中，我们选择了`get`方法和第一个待办事项，可以通过`.todo-list>li:nth-child(1)`CSS 选择器进行识别。我们还可以看到 Cypress `get`方法找到了第一个待办事项的 CSS 选择器，并将其切换为已完成状态。通过查看控制台调试信息，我们可以看到 Cypress 在控制台上打印的与操作步骤相关的附加信息，现在已固定到 DOM 上。

在**Console**区域，我们可以看到以下内容：

+   **Command**：这是我们发出的命令。在我们的情况下，它是一个`cy.get()`命令。

+   **Yielded**：这会打印由调用的命令返回的语句。在我们的情况下，它将打印与输入相同的内容。这是因为我们没有改变元素的状态。

+   **Elements**：这会打印从我们的`get`命令返回的元素。在我们的情况下，我们只有一个元素是通过 CSS 选择器找到的。但是，如果我们有多个元素，我们将能够看到找到的元素。

+   **Selector**：这是指我们用来在 DOM 中识别待办事项的 CSS 选择器。

重要提示

由于发出和检查的不同命令，控制台上显示的信息可能会发生变化。这并不是所有在控制台日志上检查的 Cypress 命令的标准。

使用这些调试信息，并将其与我们之前介绍的方法的调试信息相结合，将使您了解 Cypress 测试失败的原因。在大多数情况下，您只需要学习如何阅读常见的 Cypress 错误，以了解错误是如何抛出的以及为什么会出现这些错误。

## 总结-了解控制台调试输出

在本节中，我们学习了如何利用 Cypress 中的控制台调试输出来了解应用程序状态的变化。我们还学习了如何打开和访问控制台信息并与其交互。在下一节中，我们将学习如何利用 Cypress 的特殊调试命令。

# 特殊调试命令

如果跳转命令不是您的菜，或者您发现难以理解如何通过时间倒流来显示测试执行顺序，Cypress 会帮助您。Cypress 包括对调试有帮助的命令，甚至为您提供了在使用普通代码调试器时会有的选项。我们将在本节中探讨的两个命令如下：

+   `cy.debug()`

+   `cy.pause()`

使用这些 Cypress 调试命令，我们可以了解如何从测试本身调试 Cypress。这两个特殊的调试命令将允许我们在执行测试时直接控制调试过程。在测试本身中停止执行的能力使我们能够只调试在 Cypress 中抛出错误的特定部分。

## cy.debug

`cy.debug()`命令是 Cypress 默认提供的调试命令。该命令将记录到控制台，并记录其链式调用的命令的输出。要使用`cy.debug()`命令，您需要从任何`cy`命令进行链式调用，或者将其用作独立的 Cypress 命令。在我们的上下文中，我们将通过从`cy.get()`命令进行链式调用来使用该命令。

该命令在调用时暂停测试的执行，并显示系统地从命令向前步进并暂停调试器的选项。实际上，调试器允许我们以所需的速度执行测试，同时检查执行步骤时发生了什么。除了调试器界面外，该 Cypress 命令还会在控制台输出中显示详细信息，例如命令名称、命令类型，甚至是我们从中链式调用调试器的主题。

现在我们已经添加了我们的两个待办事项，并检查了控制台日志和 Cypress 测试运行器预览窗格，我们可以添加调试器。以下代码块显示了一个将待办事项标记为已完成的测试。但是，我们将在添加第二个待办事项后打开调试器，而不是执行整个测试：

```js
it('Special commands-debug : can mark a todo as completed', () => {
      cy.get(".new-todo").type("New Todo {Enter}");
      cy.get(".new-todo").type("Another New Todo 
      {Enter}").debug();
      cy.get('.todo-list>li:nth-
      child(1)').find('.toggle').click();
      cy.get('.todo-list>li:nth-
      child(2)').find('.toggle').click();
    });
```

在上述代码块中，我们希望在添加第二个待办事项后检查我们的应用程序状态。以下屏幕截图显示了在添加第二个待办事项后打开的调试器：

![图 5.7 - 运行测试的调试器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_5.7_B15616.jpg)

图 5.7 - 运行测试的调试器

正如我们所看到的，调试器在添加第二个待办事项后暂停了我们的运行测试。在这里，我们可以观察到，一旦调试器暂停了我们的运行测试，我们就可以以自己的步调与应用程序进行交互和检查元素。有了调试器，我们可以看到应用程序状态的变化，以及在控制台输出中显示的其他调试信息。完成检查状态后，我们可以删除`.debug()`命令，或者将其放在我们希望检查的另一行中。

## cy.pause

Cypress 的`pause`命令与`cy.debug()`命令非常相似，但它不是链式调用其他命令，而是可以独立使用，就像调试器一样。当使用`pause`命令时，Cypress 会减慢执行速度，并且只有在单击前进按钮时才执行下一步。与调试器一样，Cypress 的`pause`命令将控制权交给执行测试的人，并允许他们调查每个测试步骤。以下代码块显示了一个将待办事项标记为已完成的测试。但是，在执行完成之前，我们在添加第一个待办事项后暂停测试：

```js
it('Special commands - Pause: can mark a todo as completed', () => {
      cy.get(".new-todo").type("New Todo {Enter}");
      cy.pause();
      cy.get('.todo-list>li:nth-
      child(1)').find('.toggle').click();
 });
```

在这里，我们添加了一个待办事项，然后在标记为已完成之前暂停了执行：

![图 5.8 - 运行测试的暂停菜单](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_5.8_B15616.jpg)

图 5.8 - 运行测试的暂停菜单

正如我们所看到的，添加待办事项后，执行会暂停，直到我们在**暂停**菜单的顶部部分按下**步进**按钮。当所有步骤都执行完毕后，测试将退出，并根据执行的步骤的输出结果，要么通过要么失败。在我们的案例中，我们有一个通过的测试 - 万岁！

重要提示

Cypress 特殊调试命令只应在我们调查运行中的测试状态或进行调试时使用。它们不应该在**持续集成**（**CI**）中运行的测试中使用，因为这可能会导致超时，随后导致测试失败。

## 回顾 - 特殊调试命令

在本节中，我们了解了 Cypress 特殊命令，这些命令可用于提供额外的调试信息。我们了解到，当我们想要减慢测试的执行速度时，Cypress 的`debug`和`pause`命令都非常有用。我们还了解到调试命令可以作为补充工具，用于 Cypress 测试运行器提供的工具，例如 DOM 快照。

# 总结

在本章中，我们探讨了调试在执行测试时的作用。我们确定了 Cypress 框架的一些方面，这些方面使得 Cypress 中的调试过程对于任何编写测试和实施 Cypress 框架的人都非常有用。我们还了解到，Cypress 捆绑了不同的工具，可以用于实现不同的目的或相同的目的。最重要的是，无论遇到什么错误，Cypress 都会为您找到一种方法来识别和解决它。

通过完成本章，您已经了解了 Cypress 中的页面事件是什么，如何解释 Cypress 测试运行器的错误，执行测试中时间旅行的工作原理，以及如何解释测试快照。您还学会了如何解释来自 Cypress 的控制台输出信息，以及如何使用可用的两个特殊调试命令。

现在我们了解了调试及其对我们测试的影响，我们可以舒适地深入本书的第二部分，这将涉及使用 Cypress 进行**测试驱动开发**（**TDD**）方法。在下一章中，我们将通过测试优先的方法开发应用程序，我们将在开始开发应用程序之前编写测试。稍后我们将使用这些测试来指导我们完成应用程序开发的过程。


# 第二部分：使用 TDD 方法进行自动化测试

本节构成本书的支柱，并将向您介绍与 Cypress 相关的更高级主题以及如何使用它。在本节中，将介绍如何通过**测试驱动开发**（TDD）来思考一个想法并将其从构思阶段发展到开发阶段。在本章中，我们还将学习诸如使用 Cypress 与元素交互、使用别名以及 Cypress 测试运行器等主题。

本节包括以下章节：

+   第六章，使用 TDD 方法编写 Cypress 测试

+   第七章，了解 Cypress 中的元素交互

+   第八章，了解 Cypress 中的变量和别名

+   第九章，Cypress 测试运行器的高级用法
