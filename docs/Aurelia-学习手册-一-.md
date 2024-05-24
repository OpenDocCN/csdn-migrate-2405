# Aurelia 学习手册（一）

> 原文：[`zh.annas-archive.org/md5/31FCE017BF58226A6BEEA3734CAADF0F`](https://zh.annas-archive.org/md5/31FCE017BF58226A6BEEA3734CAADF0F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

网络发展非常快。技术不断更迭，每几年就会出现新的想法，广泛流行，然后被其他东西取代。

如果你从事网页开发已经很多年，很可能你已经见证了这个周期的发展。像 Prototype，还有 jQuery，在 2000 年代中期广泛流行，现在许多项目仍在使用。

然后，随着浏览器和 JavaScript 引擎性能的不断提高，过去十年左右，出现了许多基于 JavaScript 的全功能前端框架，如 Angular 和 Durandal。最近，基于不同概念或范式的现代框架，如 React 和 Polymer，已经获得了大量流行。

Aurelia 就是一个现代框架。它是 Rob Eisenberg 的杰作，Durandal 的创始人，基于前沿的 Web 标准，建立在现代软件架构概念和思想之上，提供强大的工具集和惊人的开发者体验。

# 本书内容覆盖

第一章，*入门*，带你了解 Aurelia 的基本概念，解释如何设置你的环境并开始一个项目。

第二章，*布局、菜单及熟悉*，深入探讨了 Aurelia 核心概念，如依赖注入、日志记录和插件系统。它还解释了如何创建多页面应用程序的主布局和导航菜单。

第三章，*显示数据*，指导你了解模板和数据绑定系统，这样你就可以构建复杂的视图。

第四章，*表单及其验证方式*，在前一章的基础上，展示了如何构建丰富的表单以及如何使用 Aurelia 的灵活且强大的验证机制。它还探讨了不同的编辑模型，例如内联编辑或基于对话框的编辑。

第五章，*创建可复用的组件*，向你展示如何构建可复用的 Aurelia 组件，如自定义 HTML 元素和属性。它还解释了如何利用 Aurelia 支持的某些前沿 Web 标准，如 Shadow DOM 和内容投射。

第六章，*设计关注点——组织和解耦*，带你了解组织和管理 Aurelia 应用程序的不同方式。它还讨论了管理解耦组件之间通信的各种技术。

第七章，*测试一切*，教你如何为 Aurelia 应用程序编写和运行自动化测试，包括单元测试和端到端测试。

第八章：国际化，*国际化*，向你展示了如何对文本和各种数据类型的格式进行国际化，例如日期和数字。

第九章：动画，*动画*，教你如何使用 CSS 动画化视图转换，并介绍通用动画 API，这样你就可以使用更丰富的动画插件。

第十章：生产环境打包，*生产环境打包*，向你展示了如何通过将应用程序打包成一个或多个捆绑包来优化生产。

第十一章：与其他库集成，*与其他库集成*，给出了如何在你的应用程序中集成各种 UI 库的示例，例如 Bootstrap 小部件、jQuery UI、D3 和 Polymer 组件。

附录 A：使用 JSPM，*使用 JSPM*，向你展示了如何使用 SystemJS 和 JSPM 开发、构建和捆绑一个 Aurelia 应用程序。

附录 B：使用 Webpack，*使用 Webpack*，向你展示了如何使用 Webpack 开发、构建和捆绑一个 Aurelia 应用程序。

# 你需要这本书的原因

为了获得最佳体验，你需要一台运行 Windows、Linux 或 Mac OS X 的 PC/笔记本电脑，一个互联网连接，以及一个现代浏览器。所有代码示例都是使用 Google Chrome 开发和测试的；因此，它是我们推荐的浏览器。

本书中提到的所有软件都是免费的，可以从互联网上下载。

# 这本书面向谁

这本书面向所有开发者，无论是想学习使用 Aurelia 构建单页应用程序，还是只是对框架感到好奇。了解 JavaScript 的基础知识 ideal 跟进这本书；然而，如果你是 JS 的新手，你会在路上学会大部分基础知识。

# 约定

在这本书中，你会发现有许多文本样式用来区分不同类型的信息。以下是一些这些样式的示例及其含义解释。

文本中的代码词汇、数据库表名、文件夹名、文件名、文件扩展名、路径名、假网址、用户输入和 Twitter 处理方式如下所示："因此，在 `aurelia_project/aurelia.json` 文件中，在 `build` 部分，在 `bundles` 下，让我们向名为 `vendor-bundle.js` 的捆绑包的 `dependencies` 中添加以下条目："

代码块如下所示：

```js
{ 
  "name": "aurelia-i18n", 
  "path": "../node_modules/aurelia-i18n/dist/amd", 
  "main": "aurelia-i18n" 
}, 
{ 
  "name": "i18next", 
  "path": "../node_modules/i18next/dist/umd", 
  "main": "i18next" 
}, 
{ 
  "name": "i18next-xhr-backend", 
  "path": "../node_modules/i18next-xhr-backend/dist/umd", 
  "main": "i18nextXHRBackend" 
},
```

当我们希望吸引您的注意力到代码块的某个特定部分时，相关的行或项目被设置为粗体：

```js
<template> 
  <h1 t="404.title"></h1> 
  <p t="404.explanation"></p> 
</template>
```

任何命令行输入或输出如下所示：

```js
> npm install aurelia-i18n i18next --save

```

新术语和重要词汇以粗体显示。例如，在菜单或对话框中出现的屏幕上的词汇，在文本中如下所示："在此阶段，如果您运行应用程序，点击 **新建** 按钮，然后例如在 **生日** 文本框中输入胡言乱语，然后尝试保存。"

### 注意

警告或重要说明以这样的盒子出现。

### 提示

技巧和小窍门如下所示。

# 读者反馈

来自我们读者的反馈总是受欢迎的。告诉我们您对这本书的看法——您喜欢或不喜欢什么。读者反馈对我们很重要，因为它帮助我们开发出您会真正从中受益的标题。

要发送给我们一般性反馈，只需将反馈发送至 feedback@packtpub.com，并在消息主题中提到书籍的标题。

如果您在某个主题上有专业知识，并且有兴趣撰写或贡献书籍，请查看我们的作者指南：[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

既然您已经成为 Packt 书籍的自豪拥有者，我们有很多事情可以帮助您充分利用您的购买。

## 下载示例代码

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的账户上下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便将文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  使用您的电子邮件地址和密码登录或注册我们的网站。

1.  将鼠标指针悬停在顶部的**支持**标签上。

1.  点击**代码下载与勘误**。

1.  在**搜索**框中输入书籍的名称。

1.  选择您想要下载代码文件的书籍。

1.  从您购买本书的下拉菜单中选择。

1.  点击**代码下载**。

您还可以通过点击 Packt Publishing 网站上书籍网页上的**代码文件**按钮来下载代码文件。您可以通过在搜索框中输入书籍的名称来访问此页面。请注意，您需要登录到您的 Packt 账户。

下载文件后，请确保使用最新版本解压或提取文件夹：

+   WinRAR / 7-Zip for Windows

+   Zipeg / iZip / UnRarX for Mac

+   7-Zip / PeaZip for Linux

本书的代码包也托管在 GitHub 上，地址为：[`github.com/PacktPublishing/Learning-Aurelia`](https://github.com/PacktPublishing/Learning-Aurelia)。我们还有其他来自我们丰富目录的书籍和视频的代码包，可以在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)找到。去看看吧！

## 勘误表

尽管我们已经竭尽全力确保内容的准确性，但错误仍可能发生。如果您在我们的图书中发现任何错误——可能是文本或代码中的错误——我们将非常感激您能向我们报告。这样做不仅能让其他读者避免沮丧，还能帮助我们改进本书的后续版本。如果您发现任何错误，请访问 [`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书籍，点击“错误提交表单”链接，并输入错误的详细信息。一旦您的错误得到验证，您的提交将被接受，并且错误将被上传到我们的网站，或添加到该标题的错误部分已有的错误列表中。

要查看之前提交的错误，请前往 [`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，在搜索框中输入书籍名称。所需的信息将在错误部分出现。

## 版权侵犯

互联网上侵犯版权材料的问题持续存在，涵盖所有媒体。在 Packt，我们对保护我们的版权和许可非常重视。如果您在互联网上以任何形式发现我们作品的非法副本，请立即提供给我们位置地址或网站名称，以便我们可以寻求解决方案。

如果您发现任何可疑的版权侵犯材料，请联系我们 copyright@packtpub.com。

我们非常感谢您在保护我们的作者权益和为我们提供有价值内容方面所给予的帮助。

## 问题咨询

如果您在阅读本书的过程中遇到任何问题，欢迎您通过 questions@packtpub.com 与我们联系，我们将竭诚为您解决问题。


# 第一章：入门

Aurelia 开发者体验是其关键优势。该框架的作者对开发过程中的每一个环节都给予了深思熟虑的关注，因此使用该框架的过程无缝而流畅，从而使得学习曲线尽可能平滑。

这本书谦虚地遵循了同样的哲学。它将教你如何从 A 到 Z 使用 Aurelia 构建真实世界的应用程序。实际上，在阅读本书并跟随代码示例时，你确实会做这件事。你将从设置你的开发环境和创建项目开始，然后我会引导你了解诸如路由、模板、数据绑定、自动化测试、国际化以及打包等概念。我们将讨论应用程序设计、组件之间的通信以及第三方集成。我们将涵盖所有现代、真实世界的单页应用程序所需的主题。

在第一章中，我们将首先定义一些将在整本书中使用的术语。我们将快速介绍 Aurelia 的核心概念。然后，我们将查看核心 Aurelia 库，并了解它们如何相互交互以形成一个完整、功能丰富的框架。我们还将了解开发 Aurelia 应用程序所需的工具以及如何安装它们。最后，我们将开始创建我们的应用程序并探索其全局结构。

# 术语

由于这本书是关于一个 JavaScript 框架的，因此 JavaScript 在其中扮演着中心角色。如果你对最近几年变化很大的术语不是完全了解，让我来澄清一些事情。

JavaScript（或 JS）是 **ECMAScript**（**ES**）标准的方言或实现。它不是唯一的实现，但绝对是其中最受欢迎的。在这本书中，我将使用 JS 缩写来讨论实际的 JavaScript 代码或代码文件，而在谈论实际的 ECMAScript 标准版本时，我将使用 ES 缩写。

就像计算机编程中的所有事物一样，ECMAScript 标准随时间不断发展。在撰写本书时，最新版本是 **ES2016**，于 2016 年 6 月发布。它最初被称为 **ES7，**但制定规范的 **TC39** 委员会决定改变他们的批准和命名模型，因此有了新名字。

之前的版本，在命名模型改变之前称为 **ES2015**（**ES6**）的版本，于 2015 年 6 月发布，与之前的版本相比是一个很大的进步。这个较早的版本，称为 **ES5**，于 2009 年发布，是六年来最新的版本，因此现在所有现代浏览器都广泛支持。如果你在过去五年中一直在编写 JavaScript，你应该熟悉 ES5。

当他们决定改变 ES 命名模型时，TC39 委员会还选择改变规格的批准模型。这个决定是为了更快地发布语言的新版本。因此，新的特性正在社区中起草和讨论，必须通过一个批准过程。每年，将发布一个新的规格版本，包括当年批准的特性和概念。

这些即将推出的功能通常被称为**ESNext**。这个术语包括已经批准或至少相当接近批准但尚未发布的语言特性。可以合理地期待其中大多数或至少一些特性将在下一个语言版本中发布。

由于 ES2015 和 ES2016 仍然是较新的版本，它们并没有得到大多数浏览器的完全支持。此外，ESNext 特性通常根本没有浏览器支持。

这些多个名称可能会让人感到相当困惑。为了简化事情，我将坚持使用官方名称 ES5 代表之前版本，ES2016 代表当前版本，ESNext 代表下一个版本。但这只是我的偏好；在接下来的章节中，我们可能会遇到一些仍然使用原始命名法的工具或库。

在深入之前，你应该熟悉 ES2016 引入的功能以及 ESNext 装饰器（如果你还不熟悉的话）。我们将在整本书中使用这些功能。

### 注意

如果你不知道从 ES2015 和 ES2016 开始，你可以在 Babel 网站上找到新特性的概述：

[`babeljs.io/docs/learn-es2015/`](https://babeljs.io/docs/learn-es2015/)

至于 ESNext 装饰器，谷歌工程师 Addy Osmani 解释得相当好：

[`medium.com/google-developers/exploring-es7-decorators-76ecb65fb841`](https://medium.com/google-developers/exploring-es7-decorators-76ecb65fb841)

为进一步阅读，你可以查看未来 ES 版本的特性提案（如装饰器、类属性声明、异步函数等）：

[`github.com/tc39/proposals`](https://github.com/tc39/proposals)

# 核心概念

在我们开始实践之前，有几个核心概念需要解释。

## 约定

首先，Aurelia 非常依赖约定。其中大多数约定是可配置的，如果它们不符合你的需求，可以进行更改。每当我们在书中遇到一个约定时，我们都会看看是否有可能改变它。

## 组件

组件是 Aurelia 的一等公民。Aurelia 组件是什么？它由一个 HTML 模板组成，称为**视图**，和一个 JavaScript 类组成，称为**视图模型**。视图负责显示组件，而视图模型控制其数据和行为。通常，视图位于一个`.html`文件中，视图模型在`.js`文件中。按照约定，这两个文件通过命名规则绑定，它们必须位于同一目录中，并且具有相同的名称（当然，除了它们的扩展名）。

以下是一个没有数据、没有行为和静态模板的空组件的示例：

`component.js`

```js
export class MyComponent {} 

```

`component.html`

```js
<template> 
  <p>My component</p> 
</template> 

```

组件必须遵守两个约束，视图的根 HTML 元素必须是`template`元素，视图模型类必须从`.js`文件中导出。作为一个经验法则，组件的 JS 文件应该只导出一个视图模型类。如果导出了多个类或函数，Aurelia 将在文件的导出函数和类上迭代，并使用找到的第一个作为视图模型。然而，由于 ES 规范中对象的键的枚举顺序不是确定的，没有任何保证导出会按照它们声明的顺序进行迭代，所以 Aurelia 可能会将错误的类作为组件的视图模型。

那个规则的唯一例外是一些视图资源，我们将在第三章，*显示数据*，和第五章，*创建可复用的组件*中看到它们。除了它的视图模型类，一个组件的 JS 文件可以导出像值转换器、绑定行为和自定义属性等东西，基本上任何不能有视图的视图资源，这排除了自定义元素。

组件是 Aurelia 应用的主要构建块。组件可以使用其他组件；它们可以组合成更大的或更复杂的组件。得益于插槽机制，你可以设计一个组件的模板，使其部分可以被替换或自定义。我们将在接下来的章节中看到所有这些。

# 架构

Aurelia 不是您通常意义上的单页应用的单体框架。它是一组松散耦合的库，具有明确定义的抽象。它的每个核心库都解决了一个特定且明确定义的问题，这是单页应用中常见的。Aurelia 利用依赖注入和插件架构，因此您可以丢弃框架的部分内容，用第三方甚至您自己的实现来替换它们。或者，您也可以丢弃不需要的功能，使您的应用程序更轻便，加载速度更快。我们将在第二章，*布局、菜单和熟悉*中更深入地了解这个插件机制。

核心 Aurelia 库可以分为多个类别。让我们快速浏览一下。

## 核心功能

以下库大多相互独立，如果需要，可以单独使用。它们各自提供一组专注的功能，是 Aurelia 的核心：

+   `aurelia-dependency-injection`：一个轻量级但强大的依赖注入容器。它支持多种生命周期管理策略和子容器。

+   `aurelia-logging`：一个简单的日志记录器，支持日志级别和可插拔的消费者。

+   `aurelia-event-aggregator`：一个轻量级的消息总线，用于解耦通信。

+   `aurelia-router`：一个客户端路由器，支持静态、参数化或通配符路由，以及子路由。

+   `aurelia-binding`：一个适应性强且可插拔的数据绑定库。

+   `aurelia-templating`：一个可扩展的 HTML 模板引擎。

## 抽象层

以下库主要定义接口和抽象，以解耦关注点并启用可扩展性和可插拔行为。这并不意味着上一节中的某些库没有除了它们的功能之外的自己的抽象。其中一些确实有。但当前节中描述的库几乎除了定义抽象之外没有其他目的：

+   `aurelia-loader`：一个定义了加载 JS 模块、视图和其他资源的接口的抽象。

+   `aurelia-history`：一个定义了历史管理接口的抽象，被路由使用。

+   `aurelia-pal`：一个用于平台特定能力的抽象。它用于抽象代码运行的平台，如浏览器或 Node.js。实际上，这意味着一些 Aurelia 库可以在服务器端使用。

## 默认实现

以下库是前两节库暴露的抽象的默认实现：

+   `aurelia-loader-default`：`aurelia-loader`抽象的 SystemJS 和`require`基础加载器的实现。

+   `aurelia-history-browser`：基于标准浏览器哈希变化和推态机制的`aurelia-history`抽象的实现。

+   `aurelia-pal-browser`：`aurelia-pal`抽象的浏览器实现。

+   `aurelia-logging-console`：`aurelia-logging`抽象的浏览器控制台实现。

## 集成层

以下库的目的是将一些核心库集成在一起。它们提供接口实现和适配器，以及默认配置或行为：

+   `aurelia-templating-router`：`aurelia-router`和`aurelia-templating`库之间的集成层。

+   `aurelia-templating-binding`：`aurelia-templating`和`aurelia-binding`库之间的集成层。

+   `aurelia-framework`：一个将所有核心 Aurelia 库集成到一个功能齐全的框架的集成层。

+   `aurelia-bootstrapper`：一个将`aurelia-framework`的默认配置带入并处理应用程序启动的集成层。

## 附加工具和插件

如果你查看 Aurelia 在 GitHub 上的组织页面[`github.com/aurelia`](https://github.com/aurelia)，你会看到更多仓库。前面部分列出的库只是 Aurelia 的核心——如果我可以这么说的话，这只是冰山一角。在 GitHub 上还有许多其他库，它们提供了额外的功能或集成了第三方库，其中一些是由 Aurelia 团队开发和维护的，许多其他是由社区开发的。我们将在后续章节中介绍一些这些额外的库，但我强烈建议你在阅读完这本书后自己探索 Aurelia 生态系统，因为它是快速发展的，Aurelia 社区正在做一些非常令人兴奋的事情。

# 工具

在接下来的部分，我们将介绍开发 Aurelia 应用程序所需的工具。

## Node.js 和 NPM

由于 Aurelia 是一个 JavaScript 框架，因此其开发工具自然也是用 JavaScript 编写的。这意味着当你开始学习 Aurelia 时，你需要做的第一件事就是在你的开发环境中安装 Node.js 和 NPM。

### 注意

Node.js 是基于 Google 的 V8 JavaScript 引擎的服务器端运行环境。它可以用来构建完整的网站或网络 API，但它也被许多前端项目用于开发和构建任务，如转换、校验和压缩。

NPM 是 Node.js 的默认包管理器。它使用[`www.npmjs.com`](http://www.npmjs.com)作为其主要仓库，所有可用的包都存储在这里。它与 Node.js 捆绑在一起，因此如果你在电脑上安装了 Node.js，NPM 也会被安装。

要在你的开发环境中安装 Node.js 和 NPM，你只需要访问[`nodejs.org/`](https://nodejs.org/)并下载适合你环境的正确安装程序。

如果 Node.js 和 NPM 已经安装，我强烈建议你确保使用至少版本 3 的 NPM，因为旧版本可能与我们将要使用的其他一些工具存在兼容性问题。如果你不确定你有哪些版本，你可以在控制台中运行以下命令来检查：

```js
> npm -v

```

如果 Node.js 和 NPM 已经安装但你需要升级 NPM，你可以通过运行以下命令来实现：

```js
> npm install npm -g

```

## Aurelia 命令行界面（CLI）

尽管可以使用任何包管理器、构建系统或打包器来构建 Aurelia 应用程序，但管理 Aurelia 项目的最佳工具是命令行界面，也称为 CLI。

截至撰写本文时，CLI 只支持 NPM 作为其包管理器以及`requirejs`作为其模块加载器和打包器，这可能是因为它们都是最成熟和最稳定的。它还在幕后使用 Gulp 4 作为其构建系统。

基于 CLI 的应用在运行时总是会被打包，即使在开发环境中也是这样。这意味着在开发过程中应用的性能将与生产环境中的性能非常接近。这也意味着打包是一个持续关注的问题，因为新的外部库必须添加到某些打包中，以便在运行时可以使用。我们将在第十章详细看到这一点，*生产环境下的打包*。

在本书中，我们将坚持使用首选方案并使用 CLI。然而，书末有两个附录介绍了替代方案，第一个是针对 Webpack 的，第二个是针对 SystemJS 和 JSPM 的。

### 安装 CLI

CLI 是一个命令行工具，应该通过打开控制台并执行以下命令来全局安装：

```js
> npm install -g aurelia-cli

```

根据你的环境，你可能需要以管理员权限运行这个命令。

如果你已经安装了它，请确保你有最新版本，通过运行以下命令：

```js
> au -v

```

然后你可以将这个命令输出的版本与 GitHub 上标记的最新版本号进行比较，地址是：[`github.com/aurelia/cli/releases/latest`](https://github.com/aurelia/cli/releases/latest)。

如果你没有最新版本，你可以通过运行以下命令简单地更新它：

```js
> npm install -g aurelia-cli

```

如果出于某种原因更新 CLI 的命令失败了，只需卸载然后重新安装即可：

```js
> npm uninstall aurelia-cli -g
> npm install aurelia-cli -g

```

这应该会重新安装最新版本。

# 项目骨架

作为 CLI 的替代方案，项目骨架可在 [`github.com/aurelia/skeleton-navigation`](https://github.com/aurelia/skeleton-navigation) 找到。这个仓库包含多个样本项目，基于不同的技术，如 SystemJS 和 JSPM、Webpack、ASP .Net Core 或 TypeScript。

准备骨架非常简单。你只需要从 GitHub 下载并解压存档，或者在本地克隆仓库。每个目录都包含一个不同的骨架。根据你的选择，你可能需要安装不同的工具并运行设置命令。通常，骨架中的 `README.md` 文件中的说明是非常清晰的。

这些骨架是使用不同技术开始新应用的其他良好起点。本书的最后两章附录展示了如何使用其中一些骨架，使用 SystemJS 和 JSPM 或 Webpack 构建应用程序。

除了附录，本书其余部分将继续使用 CLI。

## 我们的应用

使用 CLI 创建 Aurelia 应用非常简单。你只需要在你想创建项目的目录中打开一个控制台，并运行以下命令：

```js
> au new

```

CLI 的项目创建过程将开始，你应该看到类似这样的内容：

![我们的应用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/lrn-aurelia/img/image_01_001.jpg)

命令行界面（CLI）首先会询问您想要为您项目命名什么。这个名称将用于创建项目所在的目录以及设置一些值，例如它将创建的`package.json`文件中的`name`属性。让我们给我们的应用命名为`learning-aurelia`：

![我们的应用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/lrn-aurelia/img/image_01_002.jpg)

接下来，CLI 会询问我们想要使用哪些技术来开发应用。在这里，您可以选择一个自定义转换器，如 TypeScript，以及一个 CSS 预处理器，如 LESS 或 SASS。

### 注意

转换器，编译器的小表亲，将一种编程语言翻译成另一种。在我们的案例中，它将用于将 ESNext 代码转换为 ES5，后者被所有现代浏览器理解。

默认选择是使用 ESNext 和普通 CSS，这是我们将会选择的：

![我们的应用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/lrn-aurelia/img/image_01_003.jpg)

接下来的步骤简单回顾了我们所做的选择，并请求确认创建项目，然后询问我们是否想要安装项目的依赖，默认情况下它会这样做。在此阶段，命令行界面将创建项目并在幕后运行`npm install`。一旦完成，我们的应用就准备好了：

![我们的应用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/lrn-aurelia/img/image_01_004.jpg)

在此阶段，您运行`au new`的目录将包含一个名为`learning-aurelia`的新目录。这个子目录将包含 Aurelia 项目。我们将在下一节中稍作探讨。

### 注意

命令行界面（CLI）可能会发生变化，在将来提供更多选项，因为计划支持更多工具和技术。如果您运行它，不要惊讶看到不同或新的选项。

我们创建项目的路径使用了 Visual Studio Code 作为默认代码编辑器。如果你想使用其他编辑器，比如**Atom**、**Sublime**或**WebStorm**，这些是在撰写本文时支持的其他选项，你只需要在创建过程开始时选择选项#3 自定义转换器、CSS 预处理器等，然后为每个问题选择默认答案，直到被要求选择您的默认代码编辑器。创建过程的其余部分应该基本保持不变。请注意，如果您选择不同的代码编辑器，您的体验可能与本书中找到的示例和屏幕截图不同，因为撰写本书时使用的是 Visual Studio Code。

如果您是 TypeScript 开发者，您可能想创建一个 TypeScript 项目。然而，我建议您坚持使用简单的 ESNext，因为本书中的每个示例和代码示例都是用 JS 编写的。尝试跟随 TypeScript 可能会证明很繁琐，尽管如果您喜欢挑战，可以尝试。

## 基于 CLI 的项目的结构

如果您在代码编辑器中打开新创建的项目，您应该看到以下文件结构：

+   `node_modules`：包含项目依赖的标准 NPM 目录

+   `src`：包含应用源代码的目录

+   `test`：包含应用自动化测试套件的目录，我们将在第七章中探索，*测试所有事物*

+   `.babelrc`：Babel 的配置文件，CLI 使用它将我们的应用的 ESNext 代码转换成 ES5，这样大多数浏览器都可以运行它。

+   `index.html`：加载并启动应用的 HTML 页面

+   `karma.conf.js`：**Karma**的配置文件，CLI 使用它来运行单元测试；

+   `package.json`：标准的 Node.js 项目文件

这个目录还包括其他文件，如`.editorconfig`、`.eslintrc.json`和`.gitignore`，它们对学习 Aurelia 来说兴趣不大，所以我们不覆盖它们。

除了所有这些，你应该看到一个名为`aurelia_project`的目录。这个目录包含与使用 CLI 构建和打包应用相关的事物。让我们看看它由什么组成。

### `aurelia.json`文件

这个目录中最重要的文件是一个名为`aurelia.json`的文件。这个文件包含了 CLI 用于测试、构建和打包应用的配置。这个文件根据你在项目创建过程中的选择可能会有很大的变化。

### 注意

这种情况非常少见，需要手动修改这个文件。向应用中添加一个外部库就是这种情况，我们在接下来的章节中会面临多次。除了这种情况，这个文件基本上不应该手动更新。

这个文件中第一个有趣的部分是`platform`：

```js
"platform": { 
  "id": "web", 
  "displayName": "Web", 
  "output": "scripts", 
  "index": "index.html" 
}, 

```

这一部分告诉 CLI，输出目录的名称是`scripts`，它还告诉 CLI，将加载并启动应用的 HTML 主页是`index.html`文件。

下一个有趣的部分是`transpiler`部分：

```js
"transpiler": { 
  "id": "babel", 
  "displayName": "Babel", 
  "fileExtension": ".js", 
  "options": { 
    "plugins": [ 
      "transform-es2015-modules-amd" 
    ] 
  }, 
  "source": "src/**/*.js" 
}, 

```

这一部分告诉 CLI 使用 Babel 转换应用的源代码。它还定义了额外的插件，因为有些插件已经在`.babelrc`中配置好，在转换源代码时使用。在这种情况下，它添加了一个插件，将以 AMD 兼容模块的形式输出转换后的文件，以兼容`requirejs`。

这个文件中有许多其他部分，其中一些我们将在后续章节中覆盖，还有一些我留给你们自己探索。

### 任务

`aurelia_project`目录包含一个名为`tasks`的子目录。这个子目录包含各种 Gulp 任务，用于构建、运行和测试应用。这些任务可以使用 CLI 执行。

你可以首先尝试不带任何参数运行`au`：

```js
> au

```

这将列出所有可用的命令以及它们的可用参数。这个列表包括内置命令，比如我们已经在用的`new`，或者在下一节中会看到的`generate`，还有在`tasks`目录中声明的 Gulp 任务。

要运行这些任务中的一个，只需执行`au`，后面跟上任务的名称作为它的第一个参数：

```js
> au build

```

此命令将运行定义在`aurelia_project/tasks/build.js`中的`build`任务。这个任务使用 Babel 转换应用程序代码，如果有的话，执行 CSS 和标记预处理器，并在`scripts`目录中打包代码。

运行后，你应在`scripts`目录下看到两个新文件：`app-bundle.js`和`vendor-bundle.js`。这两个文件是在应用程序启动时由`index.html`加载的实际文件。前者包含所有应用程序代码，包括 JS 文件和模板，而后者包含应用程序使用的所有外部库，包括 Aurelia 库。我们将在第十章中学习如何自定义打包——*生产环境下的打包*。

你可能会注意到列表中有一个名为`run`的命令。这个任务定义在`aurelia_project/tasks/run.js`中，在启动本地 HTTP 服务器以提供应用程序之前内部执行`build`任务：

```js
> au run

```

默认情况下，HTTP 服务器将在端口 9000 上监听请求，因此你可以打开你喜欢的浏览器，访问 http://localhost:9000/ 来查看默认的演示应用程序。

### 注意

如果你需要更改开发 HTTP 服务器运行的端口号，你只需要打开`aurelia_project/tasks/run.js`，找到对`browserSync`函数的调用。传递给这个函数的对象包含一个名为`port`的属性。你可以相应地更改它的值。

`run`任务可以接受一个`--watch`开关：

```js
> au run --watch

```

如果存在此开关，任务将继续监控源代码，并在任何代码文件更改时重新构建应用程序并自动刷新浏览器。这在开发过程中非常有用。

### 生成器

命令行界面（CLI）还提供了一种生成代码的方法，使用位于`aurelia_project/generators`目录中的类。在撰写本文时，有创建自定义属性、自定义元素、绑定行为、值转换器和甚至任务和生成器的生成器。是的，有一个生成器用于生成生成器。

### 注意

如果你对 Aurelia 一无所知，那些概念（值转换器、绑定行为以及自定义属性和元素）可能对你来说毫无意义。不用担心，我们将在接下来的章节中介绍这些主题。

可以使用内置的`generate`命令执行生成器：

```js
> au generate attribute

```

此命令将运行自定义属性生成器。它会询问要生成的属性的名称，然后在其`src/resources/attributes`目录中创建它。

如果你看一下这个生成器，它可以在`aurelia_project/generators/attribute.js`中找到，你会发现文件导出一个名为`AttributeGenerator`的单一类。这个类使用`@inject`装饰器（我们将在第二章中更详细地看到，*布局、菜单和熟悉*)来声明`aurelia-cli`库中的各种类作为依赖项，并在其构造函数中注入它们的实例。它还定义了一个`execute`方法，当生成器运行时由 CLI 调用。这个方法利用`aurelia-cli`提供的服务与用户交互并生成代码文件。

### 注意

默认可用的生成器名称有`attribute`、`element`、`binding-behavior`、`value-converter`、`task`和`generator`。

### 环境

基于 CLI 的应用程序支持环境特定的配置值。默认情况下，CLI 支持三个环境-开发、暂存和生产。这些环境的每个配置对象都可以在`aurelia_project/environments`目录中的不同文件`dev.js`、`stage.js`和`prod.js`中找到。

一个典型的环境文件看起来像这样：

`aurelia_project/environments/dev.js`

```js
export default { 
  debug: true, 
  testing: true 
}; 

```

默认情况下，环境文件用于根据环境启用 Aurelia 框架的调试日志和仅限测试的模板功能。我们将在下一节看到这一点。然而，环境对象可以增强任何所需的属性。通常，它可用于根据环境配置后端的不同 URL。

添加新环境仅仅是 在`aurelia_project/environments`目录中为其添加一个文件的问题。例如，您可以通过在目录中创建一个`local.js`文件来添加一个`local`环境。

许多任务，基本上是`build`和所有使用它的任务，如`run`和`test`，都期望使用`env`参数指定环境：

```js
> au build --env prod

```

在这里，应用程序将使用`prod.js`环境文件进行构建。

如果没有提供`env`参数，默认使用`dev`。

### 注意

当执行`build`任务时，它只是在运行转译器和打包输出之前将适当的环境文件复制到`src/environment.js`。这意味着`src/environment.js`绝不应该手动修改，因为它将被`build`任务自动覆盖。

## Aurelia 应用程序的结构

上一节描述了特定于基于 CLI 的项目的一些文件和文件夹。然而，项目中的某些部分无论构建系统和包管理器如何都是相同的。这些是在本节中将要看到的更全局的主题。

### 托管页面

Aurelia 应用程序的第一个入口点是 HTML 页面的加载和托管。默认情况下，这个页面名为`index.html`，位于项目的根目录中。

默认的托管页面看起来像这样：

`index.html`

```js
<!DOCTYPE html> 
<html> 
  <head> 
    <meta charset="utf-8"> 
    <title>Aurelia</title> 
  </head> 

  <body aurelia-app="main"> 
    <script src="img/vendor-bundle.js"  
            data-main="aurelia-bootstrapper"></script> 
  </body> 
</html> 

```

当页面加载时，`body`元素内的`script`元素加载了`scripts/vendor-bundle.js`文件，该文件包含了`requirejs`本身以及所有外部库的定义和对`app-bundle.js`的引用。加载时，`requirejs`检查`data-main`属性并将其值作为入口点模块使用。在这里，`aurelia-bootstrapper`开始工作。

启动器首先在 DOM 中查找具有`aurelia-app`属性的元素。我们可以在默认的`index.html`文件中的`body`元素中找到这样的属性。这个属性识别作为应用程序视图口的元素。启动器使用属性的值作为应用程序的主模块名称，定位模块，加载它，并在元素内渲染结果 DOM，覆盖任何先前的内容。应用程序现在正在运行。

### 注意

尽管默认的应用程序没有说明这种情况，但一个 HTML 文件托管多个 Aurelia 应用程序是可能的。它只需要包含多个带有`aurelia-app`属性的元素，每个元素都引用自己的主模块。

### 主模块

按惯例，由`aurelia-app`属性引用的主模块命名为`main`，因此位于`src/main.js`中。此文件预计将导出一个`configure`函数，该函数将由 Aurelia 启动过程调用，并将传递一个用于配置和启动框架的配置对象。

默认情况下，主要的`configure`函数看起来像这样：

`src/main.js`

```js
import environment from './environment'; 

export function configure(aurelia) { 
  aurelia.use 
    .standardConfiguration() 
    .feature('resources'); 

  if (environment.debug) { 
    aurelia.use.developmentLogging(); 
  } 

  if (environment.testing) { 
    aurelia.use.plugin('aurelia-testing'); 
  } 

  aurelia.start().then(() => aurelia.setRoot()); 
} 

```

`configure`函数首先告诉 Aurelia 使用其默认配置，并加载`resources`特性，我们将在第二章，*布局、菜单和熟悉*中看到特性是如何工作的。它还根据环境的`debug`属性有条件地加载开发日志插件，并根据环境的`testing`属性有条件地加载测试插件。这意味着，默认情况下，两个插件将在开发中加载，而在生产中不会加载任何一个。

最后，该函数启动了框架，然后将根组件附加到 DOM。

### 注意

`start`方法返回一个`Promise`，其解析触发了对`setRoot`的调用。如果你不熟悉 JavaScript 中的`Promise`，我强烈建议你在继续之前查阅相关资料，因为它们是 Aurelia 中的核心概念。

### 根组件

任何 Aurelia 应用程序的根部都有一个单一的组件，包含应用程序内的所有内容。按惯例，这个根组件名为`app`。它由两个文件组成：`app.html`，其中包含渲染组件的模板，以及`app.js`，其中包含其视图模型类。

在默认的应用程序中，模板非常简单：

`src/app.html`

```js
<template> 
  <h1>${message}</h1> 
</template> 

```

这个模板由一个单一的 `h1` 元素组成，它将包含视图模型的 `message` 属性的值作为文本，感谢字符串插值，我们将在 第三章，*显示数据* 中更详细地探讨。

`app` 视图模型看起来像这样：

`src/app.js`

```js
export class App { 
  constructor() { 
    this.message = 'Hello World!'; 
  } 
} 

```

这个文件简单地导出一个类，该类有一个 `message` 属性，包含字符串 `Hello World!`。

应用程序启动时，此组件将被渲染。如果你运行应用程序并使用你最喜欢的浏览器导航到应用程序，你会看到一个包含 `Hello World!` 的 `h1` 元素。

你可能会注意到，这个组件的代码中没有提到 Aurelia。实际上，视图模型只是普通的 ESNext，Aurelia 可以原样使用它。当然，我们稍后会在很多视图模型中利用许多 Aurelia 特性，所以大多数视图模型实际上将依赖于 Aurelia 库，但这里的重点是，如果你不想在视图模型中使用任何 Aurelia 库，你就不必使用，因为 Aurelia 设计得尽可能不具侵入性。

## 传统引导方式

可以在宿主页面中将 `aurelia-app` 属性留空：

```js
<body aurelia-app> 

```

在这种情况下，引导过程要简单得多。而不是加载一个包含 `configure` 函数的主模块，引导器将简单地使用框架的默认配置并作为应用程序根加载 `app` 组件。

对于一个非常简单的应用程序来说，这可能是一个更简单的开始方式；因为它消除了 `src/main.js` 文件的必要性，你可以直接删除它。然而，这意味着你被默认框架配置所束缚。你不能加载功能或插件。对于大多数实际应用，你需要保留主模块，这意味着指定为 `aurelia-app` 属性值的 `aurelia-app`。

## 自定义 Aurelia 配置

主模块的 `configure` 函数接收一个配置对象，用于配置框架：

`src/main.js`

```js
//Omitted snippet... 
aurelia.use 
  .standardConfiguration() 
  .feature('resources'); 

if (environment.debug) { 
  aurelia.use.developmentLogging(); 
} 

if (environment.testing) { 
  aurelia.use.plugin('aurelia-testing'); 
} 
//Omitted snippet... 

```

这里，`standardConfiguration()` 方法是一个简单的助手，它封装了以下内容：

```js
aurelia.use 
  .defaultBindingLanguage() 
  .defaultResources() 
  .history() 
  .router() 
  .eventAggregator(); 

```

这是 Aurelia 的默认配置。它加载了默认的绑定语言、默认的模板资源、浏览器历史插件、路由插件和事件聚合器。这是典型 Aurelia 应用程序使用的默认一组功能。本书的各个章节都会涉及到这些插件。除了绑定语言之外的所有这些插件都是可选的，绑定语言是模板引擎所必需的。如果你不需要其中一个，那就不要加载它。

除了标准配置之外，根据环境设置还会加载一些插件。当环境的`debug`属性为`true`时，会使用`developmentLogging()`方法加载 Aurelia 的控制台日志记录器，因此可以在浏览器控制台中看到跟踪和错误信息。当环境的`testing`属性为`true`时，会使用`plugin`方法加载`aurelia-testing`插件。这个插件注册了一些在调试组件时非常有用的资源。

`configure`函数中的最后一行启动了应用程序并显示其根组件，根据约定，这个组件的名称是`app`。然而，如果你违反了约定并为根组件指定了其他名称，你可以通过将根组件的名称作为`setRoot`函数的第一个参数来绕过这个约定：

```js
aurelia.start().then(() => aurelia.setRoot('root')); 

```

在这里，预期根组件位于`src/root.html`和`src/root.js`文件中。

# 总结

得益于 Aurelia 的命令行界面（CLI），入门非常简单。安装工具并创建一个空项目仅仅是运行几个命令的问题，通常等待初始 NPM 安装完成的时间比实际设置的时间还要长。

在下一章中，我们将介绍依赖注入和日志记录，并开始通过向应用程序中添加组件和配置路由来导航它们来构建我们的应用程序。


# 第二章：布局、菜单和熟悉

至此，你应该已经对如何创建 Aurelia 应用程序有了很好的了解。大局可能仍然模糊，但随着我们贯穿本章，细节将不断出现。我们首先将了解依赖注入和 Aurelia 的插件系统是如何工作的，然后我们将了解如何使用、配置和自定义 Aurelia 日志记录器，以便我们可以追踪和监控我们代码中的情况。最后，我们将探讨 Aurelia 路由器和导航模型。顺便说一下，在我们开始构建真实应用程序时，我们将继续研究模板，通过创建全局布局模板及其导航菜单来构建真实应用程序。

在本书中，我们将逐步构建一个应用程序。在每一章中，我们将添加功能性和技术性特征。它从这一章开始。所以在深入技术之前，请允许我首先描述我们的应用程序将做什么。

我们将要构建一个联系人管理应用程序。这个应用程序将允许用户浏览联系人、执行搜索、创建和编辑条目。当然，它将依赖于一个 HTTP API 来管理数据。这个后端可以在 [`github.com/PacktPublishing/Learning-Aurelia`](https://github.com/PacktPublishing/Learning-Aurelia)找到；这是一个简单的基于 Node.js 的服务。只需下载它，在一个目录中解压，在该目录中打开控制台并运行 `npm install` 以恢复所需包，然后运行 `npm start` 来启动网络服务器。

接下来，你应该去使用 Aurelia CLI 创建一个空项目，最好使用默认选项。本书中的所有示例和代码样本都是使用默认 CLI 设置构建的；如果你定制项目创建或使用骨架，一些代码片段可能无法工作。因此，为了使学习过程尽可能顺利，我强烈建议你从默认设置开始。

# 依赖注入

**SOLID** 原则最早是由罗伯特·C·马丁（Robert C. Martin）在 2000 年代初提出的，他也被大家亲切地称为“Uncle Bob”。这个记忆助手的缩写后来由迈克尔·费瑟斯（Michael Feathers）提出，为这些原则的普及做出了贡献。它们描述了良好面向对象设计的核心五个关注点。尽管**SOLID**原则本身超出了本书的范围，但我们将详细讨论其中一个原则：依赖倒置。

依赖倒置原则表明类和模块应该依赖于抽象。当一个类依赖于抽象时，它无法负责创建这些依赖，它们必须被注入到对象中。这就是我们所说的**依赖注入**（**DI**）。它极大地增加了解耦和组合性，并强制执行一种在应用程序顶层或接近应用程序入口点组合对象图的编码风格。这样，应用程序的行为可以通过改变根部对象组合的方式而无需修改大量代码来改变。

然而，手动创建整个对象图，或者像 Mark Seemann 所说的“穷人版 DI”，很快就会变得单调。这就是依赖注入容器发挥作用的地方。一个 DI 容器，利用约定和配置，能够理解如何创建对象图。

在 Aurelia 中，几乎所有的对象都是由一个 DI 容器提供的。这个容器有两个责任：创建和组装对象，之后管理它们的生存周期。它可以通过使用附加到它必须实例化的类的元数据来做到这一点。

## `inject`装饰器

让我们想象一个显示人员列表的`PersonListView`组件。视图模型需要一个`PersonService`实例，用于检索一个`Person`对象列表：

`src/person-list-view.js`

```js
import {PersonService} from 'app-services'; 
import {inject} from 'aurelia-framework'; 

@inject(PersonService) 
export class PersonListView { 

  constructor(personService) { 
    this.personService = personService; 
  } 

  getPeople() { 
    return this.personService.getAll(); 
  } 
} 

```

在这里，我们有一个简单的视图模型，其构造函数期望一个`personService`参数。这个参数然后存储在一个实例变量中，以便稍后使用。视图模型还有一个`getPeople`方法，该方法调用`personService`的`getAll`方法来检索人员列表。如果你熟悉面向对象设计和依赖倒置，这里没有什么新东西。

这段代码片段中有趣的是`PersonListView`类上的`inject`装饰器。这个装饰器是从 Aurelia 导入的，指示 DI 容器在创建`PersonListView`的新实例时，解析一个`PersonService`实例，并将其作为构造函数的第一个参数注入。这里重要的是，传递给`inject`装饰器的依赖项列表与构造函数期望的参数列表一致。如果类有多个依赖项，你必须将它们全部按正确顺序传递给`inject`：

`src/person-list-view.js`

```js
import {PersonService, AnotherService} from 'app-services'; 
import {inject} from 'aurelia-framework'; 

@inject(PersonService, AnotherService) 
export class PersonListView { 

  constructor(personService, anotherService) { 
    this.personService = personService; 
    this.anotherService = anotherService; 
  } 

  getPeople() { 
    return this.personService.getAll(); 
  } 
} 

```

### 注意

装饰器是 ESNext 的一个特性；目前没有任何浏览器支持它们。此外，Babel 默认也不支持它们，所以如果你想在你的代码中使用它们，你需要添加`babel-plugin-transform-decorators-legacy`插件。使用 CLI 创建的项目已经包含了这个设置。

## TypeScript 和 autoinject

如果你使用 TypeScript，在构造函数声明中指定了每个依赖项的类型时，使用`inject`装饰器是相当冗余的。为了简化事情，Aurelia 提供了一个`autoinject`装饰器，它利用了 TypeScript 转译器添加到转译后的 JS 类中的类型元数据。

为了使用`autoinject`，你首先需要在你的`tsconfig.json`文件中将`experimentalDecorators`设置为`true`以启用装饰器和元数据发射，然后在同一文件的`compilerOptions`部分将`emitDecoratorMetadata`设置为`true`。由 CLI 创建的 TypeScript 项目已经包含了这些设置。

下面是使用 TypeScript 的相同`PersonListView`的示例：

`src/person-list-view.js`

```js
import {PersonService} from 'app-services'; 
import {Person} from 'models'; 
import {autoinject} from 'aurelia-framework'; 

@autoinject 
export class PersonListView { 

  constructor(private personService: PersonService) { 
  } 

  getPeople(){ 
    return this.personService.getAll(); 
  } 
} 

```

在这里，DI 容器知道，为了创建一个`PersonListView`实例，它首先需要解析一个`PersonService`实例并在`PersonListView`的构造函数中注入它，这要归功于`autoinject`装饰器。

## 静态 inject 方法或属性

如果你不使用 ESNext 装饰器也不是 TypeScript，或者不想在给定类内部有 Aurelia 的依赖，你可以使用返回这些依赖的静态`inject`方法声明类的依赖：

`src/person-list-view.js`

```js
import {PersonService} from 'app-services'; 

export class PersonListView { 
  static inject() { return [PersonService]; } 

  constructor(personService) { 
    this.personService = personService; 
  } 

  getPeople() { 
    return this.personService.getAll(); 
  } 
} 

```

静态的`inject`方法应该返回包含类依赖的数组。

或者，也可以支持包含依赖项数组的静态`inject`属性。实际上，当你使用`inject`或`autoinject`装饰器时，背后发生的就是这件事，它们只是将依赖项分配给类的静态`inject`属性。它们只是语法糖。

## 根容器和子容器

在 Aurelia 中，一个容器可以创建子容器，这些子容器又可以创建自己的子容器，从而形成从应用程序的根容器开始的容器树。每个子容器继承其父容器的服务，但可以注册自己的服务以覆盖父容器的服务。

如我们在第一章中看到的，*入门 *，一个应用程序从根组件开始。它也从根容器开始。当评估一个视图时，模板引擎会在每次遇到视图内的子组件时创建一个子容器，无论是自定义元素、具有自定义属性的元素还是通过路由或组合创建的视图模型。子组件的视图模型类将在子容器中注册为单例，然后用于解析子组件实例。随着这个组件的视图被加载和分析，这个过程会递归进行。随着组件被组合成树状结构，容器也是如此。

由于子容器通常是由模板引擎创建的，所以你很可能永远不需要手动创建一个子容器。不过，这里有一个例子展示了它是如何完成的：

```js
let childContainer = container.createChild(); 

```

## 解析实例

实例的解析涉及到解析器。我们稍后会回到这部分，详细解释它们是如何工作的以及如何使用，但与此同时，可以先将它们视为负责解析 DI 容器请求的类实例的策略。

解析实例时，根容器首先检查它是否已经有了一个针对该类的`Resolver`。如果有，这个`Resolver`就被用来获取一个实例。如果没有找到`Resolver`，根容器将自动注册一个单例`Resolver`对该类进行实例获取。

使用子容器解析实例时，情况有点不同。子容器仍然检查它是否有该类的`Resolver`，如果有，则使用它来获取实例。然而，如果没有找到`Resolver`，子容器将委托其父容器进行解析。父容器会重复这个过程，直到实例被解析或解析请求上升到根容器。当它这样做时，根容器按照前述方式解析实例。

这意味着当首次解析时动态注册的类的实例是应用单例，因为它们是在根容器中注册的，所以每个子容器最终都会解析为这个单一实例。

视图模型由模板引擎使用容器解析，所以你大多数时候永远不需要手动解析一个实例。然而，有一些场景你可能希望在一个对象中注入一个容器并手动解析服务。以下是这样做的方法：

```js
let personService = container.get(PersonService); 

```

在这里，`get` 方法是用 `PersonService` 类调用，并返回这个类的实例。

## 生命周期

由容器创建的任何对象都有生命周期。有三种典型的生命周期：

+   **容器单例**：当容器首次请求类时实例化该类，然后保留对该实例的引用。每当从容器中请求该类的实例时，这个相同的实例会被返回。这意味着实例的生命周期与容器的生命周期绑定。它不会被垃圾回收，直到容器被丢弃，且没有其他对象持有对实例的引用。

+   **应用单例**：作为应用单例注册的类，其实质是在应用的根容器中注册的一个容器单例，因此整个应用中都会重用同一个实例。

+   **瞬态**：当一个类被注册为瞬态时，容器每次请求实例时都会创建一个新的实例。它不会保留对任何这些实例的引用。容器仅仅作为一个工厂。

## 注册

为了解析一个类的实例，容器首先必须了解它。这个学习过程被称为注册。大多数时候，它是由容器在接收到解析请求时自动且即时执行的。它也可以通过使用容器的注册 API 手动执行。

### 容器注册 API

`Container` 类提供了多种方法用于手动注册一个类。

```js
container.registerSingleton(key: any, fn?: Function): void 

```

此方法将类注册为容器单例。`key` 将在查找时使用，`fn` 预期是要实例化的类。如果只提供 `key`，则预期它是一个类，因为它将用于查找和实例化。

例如，`container.registerSingleton(HttpClient)` 将 `HttpClient` 类注册为单例。第一次解析 `HttpClient` 时，将创建一个实例并返回。对于后续每次解析 `HttpClient` 的请求，都将返回这个单一实例。

另外，`container.registerSingleton(PersonService, CachingPersonService)` 使用 `PersonService` 作为键来注册 `CachingPersonService` 类。这意味着当解析 `PersonService` 类时，将返回 `CachingPersonService` 的单一实例。这种映射在处理抽象时非常重要。

当然，类是容器单例还是应用单例，仅仅取决于调用它的容器是否是应用的根容器。

```js
container.registerTransient(key: any, fn?: Function): void 

```

此方法将类注册为瞬态，意味着每次请求`key`时，都会创建`fn`的新实例。与`registerSingleton`类似，`fn`可以省略，在这种情况下，`key`将用于查找和实例创建。

```js
container.registerInstance(key: any, instance?: any): void 

```

此方法将现有实例注册为单例。如果你已经有一个实例并希望将其注册到容器中，这很有用。与`registerSingleton`的区别在于，传递的是实际的单例实例，而不是类。如果只提供`key`，它将用于查找和作为实例，但我真的看不到这种情况会有什么用，因为你需要已经拥有值才能查找它。

例如，`container.registerInstance(HttpClient, myClient)` 为 `HttpClient` 类注册 `myClient` 实例。每次从容器中请求 `HttpClient` 实例时，将返回 `myClient` 实例：

```js
container.registerHandler(key: any, 
  (container?: Container, key?: any, resolver?: Resolver) => any): void 

```

此方法注册一个自定义处理程序，这是一个每次容器根据`key`请求时将被调用的函数。这个处理函数将传递容器、`key` 和内部存储处理器的 `Resolver`。这支持了超出标准单例和瞬态生命周期的多种场景。

例如，`container.registerHandler(PersonService, () => new PersonService(myConfig))` 注册了一个工厂函数。每次从容器中请求一个`PersonService`实例时，该处理函数将被调用，并使用捕获的`myConfig`值创建一个新的`PersonService`实例：

```js
container.registerResolver(key: any, resolver: Resolver): void 

```

此方法注册一个自定义 `Resolver` 实例。在幕后，我们之前看到的所有容器方法都使用这个方法带有内置解析器。然而，创建我们自己的 `Resolver` 实现也是可能的。

### 注意

虽然大多数时候键是类，但它们可以是任何东西，包括字符串、数字、符号或对象。

### 自动注册

类的自动注册由以下类方法处理：

```js
container.autoRegister(key: any, fn?: Function): Resolver 

```

这个方法可以带有单一参数，即要注册的类，或者带有两个参数，第一个参数是要注册的类的键，第二个参数是要注册的类。当只有一个参数传递时，类本身被用作键。

容器在尝试解析一个找不到任何解析器的类的实例时，会自动调用`autoRegister`。它很少被应用程序直接使用。

### 注册策略

给定类的自动注册过程可以通过将`Registration`策略附加到类的元数据来定制。这可以通过使用注册装饰器之一来完成：

```js
import {transient} from 'aurelia-framework'; 

@transient() 
export class MyModel {} 

```

在这个例子中，`transient`装饰器将告诉`autoRegister`方法，`MyModel`类必须作为暂态注册，所以每次容器必须解析`MyModel`实例时，它将创建一个新的实例。

另外，你可以使用`singleton(registerInChild: boolean = false)`装饰器。当`registerInChild`参数为`false`时，默认就是这样，这个装饰器告诉`autoRegister`方法，这个类应该在根容器上注册为单例。这使得这个类成为应用程序的单例，而这本来就是容器的默认行为，所以将`singleton`与`registerInChild`设置为`false`或让其保持默认值是有点没用的。

然而，`singleton`中`registerInChild`设置为`true`表示，该类应该作为单例注册，不是在根容器上，而是在实际调用`autoRegister`方法的容器上。这允许我们装饰一个类，使得每个容器都有自己的实例：

```js
import {singleton} from 'aurelia-framework'; 

@singleton(true) 
export class MyModel {} 

```

在这个例子中，`MyModel`将被注册为容器单例。每个容器都将有自己的实例。

这两个装饰器背后依赖于`registration(registration: Registration)`。这个第三个装饰器用于将一个`Registration`策略与一个类关联。如果你创建了自己的自定义`Registration`策略，可以使用它。它被`transient`和`singleton`背后使用，将内置的`Registration`策略之一附加到它们装饰的类上。

### 创建自定义注册策略

注册策略必须实现以下方法：

```js
registerResolver(container: Container, key: any, fn: Function): Resolver 

```

默认情况下，`autoRegister`方法将传递给它的类注册为应用程序单例。然而，当被调用时，拥有附加到其元数据的`Registration`策略的类，`autoRegister`将委托该类的注册到`Registration`的`registerResolver`方法，该方法预期为该类创建一个`Resolver`，将其注册到容器中，并返回它。

通常，`registerResolver`方法实现将使用作为参数传递的`Container`实例的注册 API 来注册类。例如，内置的`TransientRegistration`类`registerResolver`方法，它被`transient`装饰器在幕后使用，看起来像这样：

```js
registerResolver(container, key, fn) { 
  return container.registerTransient(key, fn); 
} 

```

在这里，该方法调用容器的`registerTransient`方法，该方法创建一个瞬态`Resolver`，并返回它。

## 解析器

我们之前定义了`Resolver`作为负责解析实例的策略。当容器简化为最基本的形式时，它仅仅管理一个将`key`与相应的`Resolver`相关联的`Map`，这些`Resolver`是通过`Registration`策略或容器注册方法创建的。

除了在注册服务时使用解析器之外，解析器还可以在声明依赖时使用：`inject`装饰器，因此顺便说一下，`inject`静态方法或属性，可以作为`Resolver`而不是`key`传递。正如我们之前所见，在解析`key`依赖时，容器或其一个祖先将找到该`key`的`Resolver`，或者根容器将自动注册一个单例`Resolver`，这个`Resolver`将用于解析一个实例。但是，当解析一个`Resolver`依赖时，容器将直接使用这个`Resolver`来解析一个实例。这允许我们在特定注入的上下文中覆盖给定类注册的解析策略。

通常在注入时有用的大约有六个解析器。

### 懒惰

`Lazy`解析器注入一个函数，当评估时，延迟解析依赖项：

```js
import {Lazy, inject} from 'aurelia-dependency-injection'; 
import {PersonService} from 'person-service'; 

@inject(Lazy.of(PersonService)) 
Export class PersonListView { 
  constructor(personServiceAccessor) { 
    this.personServiceAccessor = personServiceAccessor; 
  } 

  getPeople() { 
    return this.personServiceAccessor().getAll(); 
  } 
} 

```

这意味着在实例创建时不会解析`PersonService`，而是在调用`personServiceAccessor`函数时解析。如果解析需要在创建对象之后而不是创建对象时进行委托，或者在对象生命周期内必须重新评估多次解析，这可能很有用。

### 全部

默认情况下，`Container`解析为与请求键匹配的第一个实例。`All`解析器允许我们注入一个包含给定键注册的所有服务的数组：

```js
import {All, inject} from 'aurelia-dependency-injection'; 
import {PersonValidator} from 'person-validator'; 

@inject(All.of(PersonValidator)) 
Export class PersonForm { 
  constructor(validators) { 
    this.validators = validators; 
  } 

  validate() { 
    for (let i = 0; i < this.validators.length; ++i) { 
      this.validators[i].validate(); 
    } 
  } 
} 

```

在这里，我们可以想象多个对象或类已经使用`PersonValidator`键进行了注册，并且它们都被作为数组注入到`PersonForm`视图模型中。

### 可选

`Optional`解析器只有在给定键已经注册时才注入实例。如果没有，它不会自动注册，而是注入`null`。第二个参数省略或设置为`true`时，使查找解析器上升到容器层次结构。如果设置为`false`，则只检查当前容器。

```js
import {Optional, inject} from 'aurelia-dependency-injection'; 
import {PersonService} from 'person-service'; 

@inject(Optional.of(PersonService, false)) 
Export class PersonListView { 
  constructor(personService) { 
    this.personService = personService; 
  } 

  getPeople() { 
    return this.personService ? this.personService.getAll() : []; 
  } 
} 

```

在这里，只有在当前容器中已经注册了`PersonService`实例时，才在`PersonListView`构造函数中注入`PersonService`的一个实例。如果没有，则注入`null`。

### 父级

`Parent`解析器跳过当前容器，从父容器开始解析。如果当前容器是根容器，则注入`null`：

```js
import {Parent, inject} from 'aurelia-dependency-injection'; 
import {PersonService} from 'person-service'; 

@inject(Parent.of(PersonService)) 
Export class PersonListView { 
  constructor(personService) { 
    this.personService = personService; 
  } 
} 

```

### 工厂

`Factory`解析器注入一个工厂函数。每次执行工厂函数时，它将请求容器中的新实例。此外，传递给这个工厂函数的任何参数都将由容器传递给类构造函数。如果类有依赖项，使用任何`inject`策略声明，额外的参数将在解析的依赖项传递到构造函数时附加：

```js
import {Factory, inject} from 'aurelia-dependency-injection'; 
import {AddressService} from 'address-service'; 

@inject(AddressService) 
class Person { 
  constructor(addressService, address) { 
    this.addressService = addressService; 
    this.address = address; 
  } 
} 

@inject(Factory.of(Person)) 
export class PersonListView { 
  constructor(personFactory) { 
    this.personFactory = personFactory; 
  } 

  createPerson(address) { 
    return this.personFactory(address); 
  } 
} 

```

在这个例子中，我们首先看到一个`Person`类被`inject`装饰器修饰，这暗示容器其构造函数需要一个`AddressService`实例作为第一个参数。我们也可以看到，构造函数实际上期望一个名为`address`的第二个参数，容器对此一无所知。接下来，我们有一个`PersonListView`类，以一种`Person`工厂在其构造函数中被注入的方式被装饰。其`createPerson`方法，传入一个`address`，用这个地址调用`Person`工厂函数。

当被调用时，为了创建一个`Person`实例，容器将首先解析一个`AddressService`实例来满足`Person`的依赖关系，然后用解析的`AddressService`实例和传递给工厂函数的`address`调用`Person`构造函数。

### 新实例

`NewInstance`解析器让容器在每次注入时创建类的全新实例，完全忽略类任何现有的注册。

```js
import {NewInstance, inject} from 'aurelia-dependency-injection'; 
import {PersonService} from 'person-service'; 

@inject(NewInstance.of(PersonService)) 
Export class PersonListView { 
  constructor(personService) { 
    this.personService = personService; 
  } 
} 

```

# 插件系统

既然我们已经对 Aurelia 中依赖注入的工作原理有了很好的理解，我们就可以开始使用它了。除了用于使用`inject`和`Resolver`创建和组合组件外，依赖注入还是 Aurelia 插件系统的核心。

## 插件

几乎 Aurelia 的每一个部分都是以插件的形式出现的。事实上，`aurelia-framework`库只是一个插件系统和配置机制，Aurelia 的其他核心库都是以这种方式 plugged into this mechanism。

一个 Aurelia 插件从`index.js`文件开始，这个文件必须导出一个`configure`函数。这个函数将在 Aurelia 启动时被调用，并接收一个 Aurelia 配置对象作为其第一个参数和一个可选的配置回调函数。

### 一个示例

让我们想象一个名为`our-plugin`的插件。这个插件首先需要在我们的`main.js`文件中的`configure`函数中启用：

**src/main.js**

```js
export function configure(aurelia) { 
  aurelia.use 
    .standardConfiguration() 
    .developmentLogging() 
    .plugin('our-plugin', config => { config.debug = true; }); 
  aurelia.start().then(() => aurelia.setRoot()); 
} 

```

在这里，除了标准的应用程序配置外，我们还告诉 Aurelia 加载`our-plugin`。我们还告诉 Aurelia 使用作为`plugin`函数第二个参数提供的回调来配置`our-plugin`。这个回调接收到由`our-plugin`定义的配置对象，我们将其`debug`属性设置为`true`。

现在让我们想象一下我们插件的`index.js`文件：

```js
export function configure(aurelia, callback) { 
  let config = { debug: false }; 
  if (typeof callback === 'function') { 
    callback(config); 
  } 
  aurelia.container.registerInstance(OurPluginConfig, config); 
} 

```

在这里，我们首先可以为我们的插件创建一个默认配置对象，如果提供了配置回调，我们将用我们的配置调用它，给插件的使用者机会更改它。然后我们可以将我们的配置对象注册为`OurPluginConfig`类的唯一实例。然后我们可以想象，由`our-plugin`暴露的服务会有这个`OurPluginConfig`的依赖，所以当它们由容器实例化时，它们会注入配置对象。

### 注册全局资源

使用这个`configure`函数，任何插件都可以注册自己的服务，甚至更改或覆盖其他插件声明的服务。它还可以为模板引擎注册资源：

```js
export function configure(aurelia) { 
  aurelia.globalResources('./my-component'); 
} 

```

在这里，一个插件注册了一个名为`my-component`的资源。这个资源可能有很多不同的事物；我们将在下一章节中覆盖模板资源。

## 特性

插件是组织和解除代码耦合的好方法。但是插件作为项目依赖存在于外部库中。例如，在使用 CLI 时，插件位于`node_modules`目录中。在典型项目中，那里的代码不受版本控制。这部分代码不应作为项目的一部分进行修改。实际上它不属于项目；它由其他人管理，或者至少在一个不同的项目工作流中。

但是，如果我们想要像这样结构自己的应用程序怎么办呢？使用插件机制会使这变得相当复杂，因为我们需要将不同的插件视为不同的项目，并单独打包它们，然后在应用程序中安装它们。每次需要更改插件中的任何一个时，都需要单独进行更改，然后发布并更新应用程序中的依赖关系。尽管有时共享在多个项目中使用的通用组件或行为很有用，但这种工作流程在非必要时增加了开发过程的复杂性。

幸运的是，Aurelia 有一个解决方案，即特性。特性与插件完全一样工作，但它位于应用程序内部。让我们看一个例子：

`src/my-feature/index.js`

```js
export function configure(aurelia) { 
  // register some services or resources used by this feature 
} 

```

**src/main.js**

```js
export function configure(aurelia) { 
  aurelia.use 
    .standardConfiguration() 
    .developmentLogging() 
    .feature('my-feature'); 
  aurelia.start().then(() => aurelia.setRoot()); 
} 

```

特性工作方式和插件完全一样，不同之处在于我们使用`feature`方法而不是`plugin`方法来加载它们，并且它们位于`src`目录内。像插件一样，特性预期在其根目录下有一个`index.js`文件，该文件应导出一个`configure`函数。像插件一样，它可以传递一个配置回调作为`feature`方法的第二个参数，这个回调将传递给特性的`configure`函数。

`feature`方法期望相对路径到包含`index.js`文件的目录。例如，如果我的特性位于`src/some/path/index.js`，加载它的调用将是`feature('some/path')`。

特性是组织代码的好方法。它们使你更容易将可能是一个巨大、单块的应用程序分解成一系列设计良好的模块。当然，这都取决于开发团队的设计技能。在第六章，*设计关注 - 组织和解耦*，我们将介绍一些模式、策略和组织代码的方法，以构建更好的 Aurelia 应用程序。

# 日志记录

Aurelia 带有一个简单而强大的日志系统。它支持日志级别和可插拔的附加器。

## 配置

为了配置日志，至少必须添加一个日志附加器：

`**src/main.js**`

```js
import * as LogManager from 'aurelia-logging'; 
import {ConsoleAppender} from 'aurelia-logging-console'; 

export function configure(aurelia) { 
  aurelia.use.standardConfiguration(); 

  LogManager.addAppender(new ConsoleAppender()); 
  LogManager.setLevel(LogManager.logLevel.info); 

  aurelia.start().then(() => aurelia.setRoot()); 
}; 

```

在这里，首先向日志模块添加了`ConsoleAppender`实例，该实例从`aurelia-logging-console`库导入。这个附加器简单地将日志输出到浏览器的控制台。

为了使日志工作，至少必须添加一个附加器。如果没有添加附加器，日志将被简单丢弃。

接下来，日志级别被设置为`info`。这意味着所有较低级别的日志不会被分发到附加器。Aurelia 支持四个日志级别，从最低到最高：`debug`、`info`、`warn`和`error`。例如，将最小日志级别设置为`warn`意味着`debug`和`info`日志将被忽略。此外，还有一个`none`日志级别可用。当设置时，它简单地执行没有任何过滤，并将所有日志分发到附加器。

### 默认配置

上一个示例旨在展示一个完全自定义的设置。相反，你可以在配置应用程序时使用`developmentLogging`方法：

`**src/main.js**`

```js
export function configure(aurelia) { 
  aurelia.use 
    .standardConfiguration() 
    .developmentLogging(); 

  aurelia.start().then(() => aurelia.setRoot()); 
}; 

```

这个默认配置安装了`ConsoleAppender`，并将日志级别设置为`none`。

## 附加器

附加器必须实现一个简单的接口，每个日志级别有一个方法。例如，以下是 Aurelia 的`ConsoleAppender`实现：

```js
export class ConsoleAppender { 
  debug(logger, ...rest) { 
    console.debug(`DEBUG [${logger.id}]`, ...rest); 
  } 

  info(logger, ...rest) { 
    console.info(`INFO [${logger.id}]`, ...rest); 
  } 

  warn(logger, ...rest) { 
    console.warn(`WARN [${logger.id}]`, ...rest); 
  } 

  error(logger, ...rest) { 
    console.error(`ERROR [${logger.id}]`, ...rest); 
  } 
} 

```

正如你所看到的，每个方法首先接收初始化日志的日志器，然后是传递给日志器的日志方法的参数。

## 写日志

为了写日志，你首先需要获取一个日志器：

```js
import {LogManager} from 'aurelia-framework'; 
const logger = LogManager.getLogger('my-logger'); 

```

`getLogger`方法期望日志器的名称，并返回日志器实例。如果为提供的名称不存在日志器，则会创建一个新的。日志器是单例，所以对于给定的名称始终返回相同的实例。

一旦你有一个日志器实例，你可以调用它的四个日志方法之一：`debug()`、`info()`、`warn()`或`error()`。每个这些方法都将调用所有附加器的相应级别方法，假设方法日志级别等于或高于配置的最小日志级别。否则，附加器不会被调用，日志将被丢弃。

日志器方法可以传递任意数量的参数，这些参数将被分发到附加器。例如，当在日志器上调用`error('A message', 12)`时，调用将被委派给附加器的`appender.error`(`logger, 'A message', 12)`。

默认情况下，所有日志记录器都使用全局日志级别进行配置。然而，日志记录器还具有一个`setLevel`方法，允许为单个日志记录器设置不同的日志级别：

```js
logger.setLevel(LogManager.logLevel.warn); 

```

# 路由

除了非常简单的情况外，一个典型的单页应用程序通常由多个视图组成。大多数时候，这样的应用程序有一个固定的全局布局，包括一个显示当前视图的可变区域和一个允许用户从一个视图导航到另一个视图的菜单。在 Aurelia 中，这些功能由路由器插件支持。

## 配置路由器

为了启用路由，请确保您的应用程序依赖于`aurelia-router`和`aurelia-templating-router`库，就像基于 CLI 的项目那样默认依赖。然后在你`main.js`文件的`configure`函数中加载路由插件， either by loading the whole `standardConfiguration()`, which includes the router, or by loading the `router()`individually. 有关如何在应用程序`configure`函数中加载插件的更多信息，请参阅第一章，*入门*。

## 声明路由

我们将从向我们的根组件添加一个`configureRouter`方法开始。当 Aurelia 检测到组件上的这个回调方法时，它会在组件初始化周期中调用它。这个方法接收两个参数：一个路由配置对象和路由本身：

`src/app.js`

```js
export class App { 
  configureRouter(config, router) { 
    this.router = router; 
    config.title = 'Learning Aurelia'; 
    config.map([ 
      { route: ['', 'contacts'], name: 'contacts', moduleId: 'contact-list', nav: true, title: 'Contacts' }, 
      { route: 'contacts/:id', name: 'contact-details', moduleId: 'contact-details' }, 
    ]); 
  } 
} 

```

在`configureRouter`方法中，我们首先将路由器分配给一个实例变量。这很重要，因为我们的根组件的视图需要访问路由器以渲染菜单和活动路由组件。

一旦完成，我们设置全局标题。这个值将显示在浏览器标题栏中。

接下来，我们使用`map`方法配置两个路由。路由配置基本上是将一个 URL 路径模式与一个组件的映射，当路径匹配时激活路由，并在路由激活时显示组件。它还包含其他属性。让我们分解一个路由配置：

+   `route`属性是 URL 路径模式。重要的是要注意，这些模式省略了路径的前斜杠。有三种类型的模式：

    +   **静态路由**：该模式完全匹配路径。我们第一个路由的第一个模式是这种模式的例子：它匹配根路径（`/`），由于省略了前斜杠，它匹配空字符串。这使得它成为默认路由。

    +   **参数化路由**：该模式完全匹配路径，并且与占位符匹配的路径部分（前缀为冒号`:`）被解析为路由参数。这些参数的值在屏幕激活生命周期中作为路由组件的一部分提供。我们第二个路由的模式是这种模式的例子：它匹配以`/contacts/`开头的路径，后跟第二个部分，被解释为联系人的`id`。

        ### 注意

        此外，可以通过在参数后添加一个问号使其成为可选参数。 例如，`contacts/:id?/details` 模式将匹配 `/contacts/12/details` 和 `/contacts/details` 两者。 当在路径中省略参数时，传递给路由组件的相应参数将是 `undefined`。

    +   **通配符路由**：该模式匹配路径的开始部分，路径的其余部分被视为一个单一参数，其值在屏幕激活生命周期中作为路由组件的一部分提供。 例如，`my-route*param` 模式将匹配任何以 `/my-route` 开头的路径，`param` 将是 一个参数，其值是匹配到的路径的其余部分。

+   `name` 属性唯一标识路由。 我们稍后可以看到如何使用它来生成路由的 URL。

+   `moduleId` 属性是路由组件的路径。

+   `nav` 属性，当设置为 `true` 值时，告诉路由器将此路由包含在其导航模型中，该模型用于自动构建应用程序的导航菜单。另外，如果 `nav` 是一个数字，则路由器将使用它来对导航菜单中的项目进行排序。

+   `title` 属性在路由活动时将显示在浏览器标题栏中，除非组件覆盖它。 如果 `nav` 是 `true`，它也用作路由的菜单项文本。

+   `settings` 属性是可选的，可以包含激活组件或管道步骤可以使用任意数据，我们将在本章后面看到。

### 重定向路由

代替 `moduleId`，路由可以声明一个 `redirect` 属性。 当这样的路由被激活时，路由器将执行内部重定向到代表该属性值的路径。 这允许用多个模式技术声明默认路由的替代方法，正如我们第一个路由所展示的那样。 相反，我们可以声明以下路由：

```js
config.map([ 
  { route: '', redirect: 'contacts' }, 
  { route: 'contacts', name: 'contacts', moduleId: 'contact-list', nav: true, title: 'Contacts' }, 
  { route: 'contacts/:id', name: 'contact-details', moduleId: 'contact-details' }, 
]); 

```

与这个配置的主要区别是，当访问 `/` 时，浏览器地址栏中的 URL 将更改为 `/contacts`，因为路由器将执行重定向。

使用此模式时，`nav` 属性应该只在目标路由上设置为 `true`。 如果它在重定向路由上设置而不是目标路由，那么路由器将无法突出显示相应的菜单项，因为该路由在目标路由激活之前仅短暂激活片刻。 最后，在重定向路由及其目标路由上都设置为 `true` 会导致两者都在菜单中渲染，这是没有意义的，因为它们都通向同一个地方。

如果 `nav` 属性是 `false`，那么设置 `title` 也是没有意义的，因为该路由从未激活足够长的时间以至于标题可见。

然而，为重定向路由设置`name`可能是有用的。当重定向预期在未来会改变时，可以使用重定向路由的`name`来生成链接，而不是目标路由的。这样，路由的`redirect`属性是唯一需要改变的东西，依赖于这个路由的每一个链接都会随之改变。

### 导航策略

除了`moduleId`和`redirect`属性之外，路由还可以有一个`navigationStrategy`属性。其值必须是一个函数，该函数将由路由器调用，并传递一个`NavigationInstruction`实例。然后可以动态地配置这个对象。例如，我们的最后一个路由可以配置成这样：

```js
{ 
  route: 'contacts/:id', name: 'contact-details',  
  navigationStrategy: instruction => { 
    instruction.config.moduleId = 'contact-details'; 
  } 
} 

```

最后，这个路由做的和之前一样。但对于需要比`moduleId`和`redirect`更灵活的场景，这个替代方案可以变得很有用，因为`NavigationInstruction`实例包含以下属性：

+   `config`：正在导航到的路由的配置对象

+   `fragment`：触发导航的 URL 路径

+   `params`：包含从路由模式中提取的每个参数的对象

+   `parentInstruction`：如果这个路由是一个子路由，则是指令父路由的指令

+   `plan`：由路由器内部构建并使用以执行导航的导航计划

+   `previousInstruction`：当前指令将在路由器中替换的导航指令

+   `queryParams`：包含从查询字符串解析出的值的对象

+   `queryString`：原始查询字符串

+   `viewPortInstructions`：视口指令，由路由器内部构建并使用以执行导航

## 布局我们的应用程序

基于其路由配置，路由器生成一个导航模型，可以用来自动生成导航菜单。因此，当添加新路由时，我们不需要改变路由的配置和菜单视图。

由于我们根组件的视图模型负责声明路由，它的视图应该是全局布局并渲染导航菜单。让我们使用这个导航模型来创建根组件的视图：

`src/app.html`

```js
<template> 
  <require from="app.css"></require> 
  <nav class="navbar navbar-default navbar-fixed-top" role="navigation"> 
    <div class="navbar-header"> 
      <button type="button" class="navbar-toggle" data-toggle="collapse" 
              data-target="#skeleton-navigation-navbar-collapse"> 
        <span class="sr-only">Toggle Navigation</span> 
      </button> 
      <a class="navbar-brand" href="#"> 
        <i class="fa fa-home"></i> 
        <span>${router.title}</span> 
      </a> 
    </div> 

    <div class="collapse navbar-collapse" id="skeleton-navigation-navbar-collapse"> 
      <ul class="nav navbar-nav"> 
        <li repeat.for="row of router.navigation" class="${row.isActive ? 'active' : ''}"> 
          <a data-toggle="collapse" data-target="#skeleton-navigation-navbar-collapse.in" href.bind="row.href"> 
            ${row.title} 
          </a> 
        </li> 
      </ul> 

      <ul class="nav navbar-nav navbar-right"> 
        <li class="loader" if.bind="router.isNavigating"> 
          <i class="fa fa-spinner fa-spin fa-2x"></i> 
        </li> 
      </ul> 
    </div> 
  </nav> 
  <div class="page-host"> 
    <router-view></router-view> 
  </div> 
</template> 

```

这个模板中突出显示的部分是最有趣的部分。让我们来看一下。

首先要注意的是，我们需要一个名为`app.css`的文件，我们将在一会儿写它。这个文件将样式化我们的应用程序组件。

接下来，视图使用了`router`属性，该属性定义在我们根组件的视图模型的`configureRouter`方法中。我们首先在带有`nav-brand`类的`a`标签中看到它，其中字符串插值指令渲染文档标题。

然后，我们在`li`标签上发现了一个`repeat.for="row of router.navigation"`属性。这个绑定指令为`router.navigation`数组中的每个项目重复`li`标签。这个`navigation`属性包含了路由器的导航模型，该模型是用路由的 truthy `nav`属性构建的。在渲染每个`li`标签时，模板引擎的绑定上下文中都有一个包含当前导航模型项的`row`变量。

`li`标签还有一个`class="${row.isActive ? 'active' : ''}"`属性。这个字符串插值指令使用当前导航模型项的`isActive`属性。如果`isActive`评估为`true`值，它就会给`li`标签分配一个`active` CSS 类。这个属性由路由器管理，仅当导航模型项属于活动路由时才是`true`。在这个模板中，它用来突出显示活动菜单项。

`li`标签内的锚点有一个`href.bind="row.href"`属性。这个指令将标签的`href`属性绑定到当前导航模型项的`href`属性。这个`href`属性是由路由器使用路由的路径模式构建的。此外，在锚点内部，还渲染了路由的`title`。

在菜单的末尾，我们可以看到一个带有`loader` CSS 类的`li`标签。这个元素包含一个旋转图标。它有一个`if.bind="router.isNavigating"`属性，它将这个元素在 DOM 中的存在与路由器的`isNavigating`属性的值绑定在一起。这意味着当路由器执行导航时，顶部的右角将显示一个旋转图标。当没有导航发生时，这个图标不仅不可见，实际上甚至根本不在 DOM 中，感谢`if`属性。

最后，`router-view`元素作为路由视图 port，显示活动路由组件。这是整个模板中唯一必需的部分。当一个组件配置路由器时，其视图必须包含一个`router-view`元素，否则将抛出错误。利用导航模型是可选的，菜单可以是静态的，或者通过任何你能想象到的其他方式构建。显示标题也是可选的。利用`isNavigating`指示器绝对是完全不必要的。然而，如果一个组件配置了路由器，而它的视图却不能显示活动路由组件，那么这个组件配置路由器就是毫无意义的。

这个视图使用了一种结构，如果你曾经使用过 Bootstrap，你可能就会熟悉。Bootstrap 是由 Twitter 开发的 CSS 框架，我们将在我们的应用程序中使用它。让我们来安装它：

```js
> npm install bootstrap --save

```

我们还需要在我们的应用程序中加载它：

`index.html`

```js
<!DOCTYPE html> 
<html> 
  <head> 
    <title>Learning Aurelia</title> 
    <link href="node_modules/bootstrap/dist/css/bootstrap.min.css" rel="stylesheet"> 
  </head> 
  <!-- Omitted snippet... --> 
</html> 

```

我们的`app`组件在能正常工作之前还缺最后一块拼图，那就是`app.css`文件。文件内容如下：

`src/app.css`

```js
.page-host { 
  position: absolute; 
  left: 0; 
  right: 0; 
  top: 50px; 
  bottom: 0; 
  overflow-x: hidden; 
  overflow-y: auto; 
} 

```

### 尝试一下

至此，如果你运行我们的应用程序，你应在浏览器的控制台看到一个路由错误。那是因为默认路由试图加载`contact-list`组件，而这个组件还不存在。

让我们创建一个空的文件：

`src/contact-list.html`

```js
<template> 
<h1>Contacts</h1> 
</template> 

```

`src/contact-list.js`

```js
export class ContactList {} 

```

现在如果你再次尝试运行应用程序，你应该看到应用程序正确加载，显示顶部菜单和空的 `contact-list` 组件。

## 屏幕激活生命周期

当路由器检测到 URL 路径发生变化时，它会经历以下生命周期：

1.  确定目标路由。如果没有任何路由与新路径匹配，将抛出一个错误，并且在这里停止处理过程。

1.  给活动路由组件一个拒绝停用的机会，在这种情况下，路由器恢复之前的 URL 并在这里停止处理过程。

1.  给目标路由组件一个拒绝激活的机会，在这种情况下，路由器恢复之前的 URL 并在这里停止处理过程。

1.  停用活动路由组件。

1.  激活目标路由组件。

1.  视图被交换。

为了加入这个生命周期，组件可以实现以下任意一个回调方法：

+   `canActivate(params, routeConfig, navigationInstruction)`：在步骤 #2 时调用，以知道组件是否可以被激活。可以返回一个 `boolean` 值、一个 `Promise` 类型的 `boolean` 值、一个导航命令，或者一个 `Promise` 类型的导航命令。

+   `activate(params, routeConfig, navigationInstruction)`：在步骤 #5 时调用，当组件被激活时。可以返回一个可选的 `Promise`。

+   `canDeactivate()`：在步骤 #3 时调用，以知道组件是否可以被停用。可以返回一个 `boolean` 值、一个 `Promise` 类型的 `boolean` 值、一个导航命令，或者一个 `Promise` 类型的导航命令。

+   `deactivate()`：在步骤 #4 时调用，当组件被停用时。可以返回一个可选的 `Promise`。

`Promise` 在整个生命周期中都是被支持的。这意味着当回调方法中的任何一个返回一个 `Promise` 时，路由器会在继续处理之前等待其解决。

此外，`canActivate` 和 `activate` 都接收与导航上下文相关的参数：

+   `params` 对象将有一个属性，用于每个解析的路由模式中的参数，以及每个查询字符串值的属性。例如，我们的 `contact-details` 组件将接收一个具有 `id` 属性的 `params` 对象。在匹配路径中没有值的可选参数将被设置为 `undefined`。

+   `routeConfig` 将是原始的路由配置对象，具有一个额外的 `navModel` 属性。这个 `navModel` 对象有一个 `setTitle(title: string)` 方法，该方法可以被组件用来将文档标题更改为动态值，如激活期间加载的数据。我们将在第三章中看到更多内容，*显示数据*。

+   `navigationInstruction` 是路由器用来执行导航的 `NavigationInstruction` 实例。

最后，`canDeactivate`和`canActivate`都可以如果它们返回`false`、一个解析为`false`的`Promise`、一个导航命令或一个解析为导航命令的`Promise`来取消导航。

## 导航命令

导航命令是一个具有`navigate(router: Router)`方法的对象。当从`canDeactivate`或`canActivate`返回导航命令时，路由器取消当前导航并将控制权委托给命令。Aurelia 自带一个导航命令：`Redirect`。这是一个使用它的示例：

`src/contact-details.js`

```js
import {inject} from 'aurelia-framework'; 
import {Redirect} from 'aurelia-router'; 
import {ContactService} from 'app-services'; 

@inject(ContactService) 
export class ContactDetails { 
  constructor(contactService) { 
    this.contactService = contactService; 
  } 

  canActivate(params) { 
    return this.contactService.getById(params.id) 
      .then(contact => { this.contact = contact; }) 
      .catch(e => new Redirect('error')); 
  } 
} 

```

在这里，在`canActivate`回调方法中，`ContactDetails`视图模型尝试通过其`id`加载联系人。如果由`getById`返回的`Promise`被拒绝，用户将被重定向到`error`路由。

## 处理未知路由

当路由器无法将 URL 路径与任何路由匹配时，它会抛出一个错误。但在提出这个错误之前，它首先将导航指令委托给一个未知的路由处理程序，如果有的话。此处理程序可以通过使用`mapUnknownRoutes`方法进行配置，该方法可以接受以下值之一作为参数：

+   组件显示的路径，而不是抛出错误。

+   路由配置对象，包含`moduleId`、`redirect`或`navigationStrategy`属性之一。路由器将委托导航到此路由，而不是抛出错误。

+   一个接收`NavigationInstruction`实例并返回要显示的组件路径而不是抛出错误的函数。

让我们实现一个`not-found`组件，当链接断裂时，我们的应用程序将显示它：

`src/not-found.html`

```js
<template> 
  <h1>Something is broken...</h1> 
  <p>The page cannot be found.</p> 
</template> 

```

`src/not-found.js`

```js
export class NotFound {} 

```

在我们的根组件中，我们只需要添加突出显示的行：

`src/app.js`

```js
export class App { 
  configureRouter(config, router) { 
    this.router = router; 
    config.title = 'Learning Aurelia';  
    config.map([ /* omitted for brevity */ ]); 
    config.mapUnknownRoutes('not-found'); 
  } 
} 

```

任何时候路由器无法将 URL 路径与现有路由匹配，我们的`not-found`组件都将显示。

### 约定路由

`mapUnknownRoutes`提供的另一个选项是使用路由约定而不是一组静态定义的路由。如果你的所有路由都遵循路径和`moduleId`之间的相同命名模式，我们可以想象这样的事情：

`src/app.js`

```js
export class App { 
  configureRouter(config, router) { 
    this.router = router; 
    config.title = 'Learning Aurelia'; 
    config.mapUnknownRoutes(instruction => getComponentForRoute(instruction.fragment)); 
  } 
} 

```

在这里，路由依赖于一个由`getComponentForRoute`函数实现的约定，该函数接收触发导航的 URL 路径，并返回必须显示的组件路径。

## 激活策略

当多个静态路由导致相同的组件，并在这些路由之间发生导航时，路由器只是保持相同的组件实例。由于这个原因，激活生命周期不会执行。这种行为由激活策略决定。`activationStrategy`枚举有两个值：

+   `replace`：用新路由替换当前路由，保持相同的组件实例，不经过激活生命周期。这是默认行为。

+   `invokeLifecycle`：即使活动组件没有变化，也要经历激活生命周期。

改变这种行为有两种方法：

+   在路由的配置对象中，你可以添加一个`activationStrategy`属性，指定激活此路由时应使用哪种策略。

+   在路由组件的视图模型中，你可以添加一个`determineActivationStrategy`方法，该方法必须返回所有显示此组件的路由所使用的策略。

## 子路由 (Child routers)

就像 DI 一样，容器可以有子容器，形成一个容器树；就像组件可以包含子组件，形成一个组件树，路由器也可以有子路由器。这意味着一个路由组件的视图模型可以有自己的`configureRouter`方法，其视图有一个`router-view`元素。当遇到这样的组件时，路由器将为这个子组件创建一个子路由器。这个子路由器的路由模式相对于父路由的模式是相对的。

这使得应用程序可以有一个具有多级层次的导航树。在讨论如何组织大型应用程序时，我们将会看到如何利用这一特性，请参阅第六章，*设计关注点 - 组织和解耦*。

## 管道 (Pipelines)

可能很有必要将路由器与一些在每次发出导航请求时都会被调用的逻辑连接起来。例如，具有认证机制的应用程序可能需要将某些路由限制为仅限认证用户。Aurelia 路由器的管道正是为这类场景而设计的。

路由器支持四个管道：`authorize`、`preActivate`、`preRender`和`postRender`。这些管道在导航过程中的不同阶段被调用。让我们看看它们各自发生在哪里：

1.  如果存在的话，当前路由组件的`canDeactivate`方法会被调用。

1.  执行`authorize`管道。

1.  如果存在的话，目标路由组件的`canActivate`方法会被调用。

1.  执行`preActivate`管道。

1.  如果存在的话，当前路由组件的`deactivate`方法会被调用。

1.  如果存在的话，目标路由组件的`activate`方法会被调用。

1.  执行`preRender`管道。

1.  在路由视口中交换视图。

1.  执行`postRender`管道。

管道由步骤组成，这些步骤按顺序调用。管道步骤是一个具有`run(instruction, next)`方法类的实例，其中`instruction`是一个`NavigationInstruction`实例，`next`是一个`Next`对象。

`Next`对象是一个具有方法的对象。

当调用`next()`时，它告诉路由器管道继续执行下一个步骤。`next.cancel()`方法取消了导航过程，并期望传递一个导航命令或`Error`对象作为参数。

两者都返回`Promise`。

让我们看一个例子：

`src/app.js`

```js
import {AuthenticatedStep} from 'authenticated-step'; 

export class App { 
  configureRouter(config, router) { 
    config.title = 'Aurelia'; 
    config.addPipelineStep('authorize', AuthenticatedStep); 
    config.map([ 
      { route: 'login', name: 'login', moduleId: 'login', title: 'Login' }, 
      { route: 'management', name: 'management', moduleId: 'management',  
        settings: { secured: true } }, 
    ]); 
    this.router = router; 
  } 
} 

```

这里需要注意的是，`AuthenticatedStep`类被添加到了`authorize`管道中。管道步骤作为类添加，而不是实例。这是因为路由使用其 DI 容器来解析步骤的实例。这允许步骤有依赖关系，这些依赖关系在执行前被解析和注入。

第二个要注意的是，`management`路由有一个`settings`对象，其`secured`属性被设置为`true`。它将由以下片段中的管道步骤使用，以识别需要对已认证用户限制的路由。

`src/authenticated-step.js`

```js
import {inject} from 'aurelia-framework'; 
import {Redirect} from 'aurelia-router'; 
import {User} from 'user'; 

@inject(User) 
export class AuthenticatedStep { 
  constructor(user) { 
    this.user = user; 
  } 

  run(instruction, next) { 
    let isRouteSecured = instruction.getAllInstructons().some(i => i.config.settings.secured); 
      if (isRouteSecured && !this.user.isAuthenticated) { 
      return next.cancel(new Redirect('login')); 
    } 
    return next(); 
  } 
} 

```

这是实际的管道步骤。在这个例子中，我们可以想象我们的应用程序包含一个`User`类，它暴露了当前用户的信息。我们的管道依赖于这个类的实例，以知道当前用户是否已认证。

`run`方法首先检查指令中的任何路由是否被配置为安全。这是通过检查所有导航指令，包括潜在父路由的指令，并检查其配置的`settings`中的真值`secured`属性来实现的。

例如，当导航到前一个代码片段中定义的`management`路由时，`isRouteSecured`的值将被设置为`true`。如果`management`组件声明了子路由，并且导航是对其中之一进行的，那么情况也会如此。在这种情况下，即使子路由没有被配置为`secured`，`isRouteSecured`仍将是`true`，因为其中一个父路由将是`secured`。

当目标路由或其之一被设置为安全时，如果用户未认证，导航将被取消，用户将被重定向到`login`路由。否则，调用`next`，让路由器知道它可以继续导航过程。

## 事件

Aurelia 路由还提供了另一个扩展点。除了屏幕激活生命周期和管道之外，路由还通过事件聚合器发布事件，这是 Aurelia 的核心库之一。

可以在`samples/chapter-2/router-events`中找到路由事件的演示。让我们看看这些事件：

+   `router:navigation:processing`：每次路由开始处理导航指令时，都会触发此事件。

+   `router:navigation:error`：当导航指令触发错误时，会触发此事件。

+   `router:navigation:canceled`：当导航指令被取消时，会触发此事件，取消可以是当前或目标路由组件的屏幕激活生命周期回调方法之一，或者是管道步骤。

+   `router:navigation:success`：当导航指令成功时，会触发此事件。

+   `router:navigation:complete`：一旦导航指令的处理完成，无论它失败、被取消还是成功，都会触发此事件。

所有这些事件的负载都包含一个`NavigationInstruction`实例，作为`instruction`属性存储。此外，除了`router:navigation:processing`之外，其他事件的所有负载都有一个`PipelineResult`作为`result`属性。例如，在处理`error`事件时，可以使用`result`属性的`output`属性来访问被抛出的`Error`对象。

我们将在第六章中看到事件聚合器是如何工作的，*设计关注 - 组织和解耦*。

## 多个视口

在所有之前的示例中，`router-view`元素从未有过任何属性。它实际上可以有一个`name`属性。当省略这个属性时，由元素声明在路由器上的视口被称为`default`。您看到这里的含义了吗？

如果你回答路由支持多个视口，那你猜对了。当然，这也意味着每个声明在视图中的视口都必须为每个视口配置路由。让我们看看这是如何工作的：

### 注意

以下代码片段摘自`samples/chapter-2/router-multiple-viewports`。

`src/app.html`

```js
<template> 
  <require from="nav-bar.html"></require> 
  <require from="bootstrap/css/bootstrap.css"></require> 

  <nav-bar router.bind="router"></nav-bar> 

  <div class="page-host"> 
    <router-view name="header"></router-view> 
    <router-view name="content"></router-view> 
  </div> 
</template> 

```

在组件的视图中，有趣的是注意到有两个`router-view`元素，有不同的`name`属性。这个组件的路由最终会有两个视口：一个名为`header`，另一个名为`content`：

`src/app.js`

```js
export class App { 
  configureRouter(config, router) { 
    config.title = 'Learning Aurelia'; 
    config.map([ 
      { 
        route: ['', 'page-1'], name: 'page-1', nav: true, title: 'Page 1',  
        viewPorts: {  
          header: { moduleId: 'header' },  
          content: { moduleId: 'page-1' } 
        } 
      }, 
      { 
        route: 'page-2', name: 'page-2', nav: true, title: 'Page 2',  
        viewPorts: {  
          header: { moduleId: 'header' },  
          content: { moduleId: 'page-2' } 
        } 
      }, 
    ]); 

    this.router = router; 
  } 
} 

```

在视图模型的`configureRouter`回调方法中，两个路由都使用特定的`moduleId`进行了配置，既适用于`header`，也适用于`content`和`viewPorts`。

如果在路由激活时没有为每个路由的视口配置路由，则路由器将抛出错误。无论是否静态地使用`viewPorts`属性为每个视口定义了`moduleId`，还是`viewPorts`属性通过`navigationStrategy`动态配置，都不重要。在前一个示例中，`page-2`路由可以被替换为：

```js
{ 
  route: 'page-2', name: 'page-2', nav: true, title: 'Page 2',  
  navigationStrategy: instruction => { 
    instruction.config.viewPorts = { 
      header: { moduleId: 'header' },  
      content: { moduleId: 'page-2' } 
    }; 
  } 
} 

```

此路由与前一个示例中的效果相同。这里唯一的区别是，每次路由激活时都会动态地配置视口。

当然，重定向路线不会受到视口的影响，因为它们不会渲染任何内容。

## 状态推送与哈希变化

路由器通过响应 URL 的变化来工作。在旧浏览器中，只有 URL 中的#符号后面的部分，即哈希部分，可以改变而不触发页面重载。因此，在这些浏览器上运行的路由器只能更改哈希部分，并监听哈希部分的更改。

随着 HTML5 的推出，一个新的历史 API 被引入，以实现对浏览器历史的操作。这使得运行在现代浏览器上的 JavaScript 路由器可以直接操作其当前 URL 和浏览历史，并监控当前 URL 的变化。这个 API 使得路由器能够使用完整的 URL，并允许诸如同构应用之类的技术，具有服务器渲染和渐进增强。这些技术可以使应用程序的内容能够被更广泛的客户端访问，同时也将提高应用程序的 SEO，因为谷歌已经弃用了基于哈希的带有 AJAX 内容加载的应用（参见[`googlewebmastercentral.blogspot.com/2015/10/deprecating-our-ajax-crawling-scheme.html`](https://googlewebmastercentral.blogspot.com/2015/10/deprecating-our-ajax-crawling-scheme.html)）。

### 注意

当一个应用程序可以在客户端和服务器上执行时，它被称为同构应用程序。通常，同构应用程序在服务器端执行，以渲染基于文本的 HTML 表示，然后可以返回给客户端；例如，搜索引擎爬虫。当在客户端执行时，它通常通过运行时事件处理程序、数据绑定和实际行为进行增强，以便用户可以与应用程序互动。

奥雷利亚（Aurelia）的路由插件可以与这两种策略中的任何一种工作。默认情况下，它被配置为使用基于哈希的策略，因为状态推送需要服务器相应地配置。此外，基于哈希的策略支持不完全兼容 HTML5 的旧浏览器。

然而，如果不需要支持旧浏览器，或者需要服务器端渲染，并且应用程序可能会向同构方向发展，路由器可以配置为使用历史 API。

### 注意

下面的代码片段是`samples/chapter-2/router-push-state`的摘录。

首先，在`index.html`文件中，在头部部分，必须添加一个`<base href="/">`标签。这个元素指示浏览器`/`是页面中所有相对 URL 的基础。

接下来，在根组件的视图模型中，路由必须配置不同：

`src/app.js`

```js
export class App { 
  configureRouter(config, router) { 
    this.router = router; 
    config.title = 'Aurelia'; 
    config.options.pushState = true; 
    config.options.hashChange = false; 
    config.map([ /* omitted for brevity */ ]); 
  } 
} 

```

此外，为了在用户使用除根 URL 以外的 URL 访问应用程序时显示正确的路由，服务器需要输出`index.html`页面，而不是对未知路径的 404 响应。这样，当用户访问应用程序的路由时，服务器将响应 index 页面，然后应用程序启动，路由器将处理路由并显示正确的视图。这意味着应用程序中的路由和服务器端资源（如 CSS、图片、字体、JS、HTML 或必须由 index 页面或应用程序从服务器加载的任何文件）之间必须没有命名冲突。

## 生成 URL

路由器能够对 URL 的变化做出反应，并相应地更新其视口，这是一件事。但是关于允许它导航的链接呢？如果我们硬编码 URL，任何路由路径模式的更改都需要更改路由配置，还要检查用于导航的每个地方，无论是 JS 代码还是视图，并修改它。

幸运的是，路由器也能够在生成 URL。要生成一个路由路径，有两个要求：

+   路由配置必须有一个唯一的`name`属性

+   如果路由具有参数化或通配符模式，生成 URL 时必须提供包含每个参数值的参数对象。

### 在代码中

要在 JS 代码中生成 URL 路径，你首先必须有一个路由器的实例，通常是通过在需要它的类中注入它来获得的。然后，你可以调用以下方法：

```js
router.generate(name: string, params?: any, options?: any): string 

```

必须使用路由名称、路由有时的参数对象以及可选的选项对象调用此方法，并将返回生成的 URL。目前唯一支持的选择是`absolute`，当设置为`true`时，强制路由器返回绝对 URL 而不是相对 URL。

例如，对于路径模式为`contacts/:id`的名为`contact-details`的路由，为 id 为 12 的联系人生成 URL 的调用将是：

```js
let url = router.generate('contact-details', { id: 12 }); 

```

而对于绝对 URL：

```js
let url = router.generate('contact-details', { id: 12 }, { absolute: true }); 

```

### 在视图中

如果我们需要在视图中渲染一个指向我们路由的链接怎么办？我猜你可以看到如何将路由器注入视图模型中，调用`generate`方法，并将锚点的`href`属性与结果数据绑定。在最坏的情况下，这会很快变得繁琐。

`aurelia-templating-router`库带有一个`route-href`属性，这使得这变得容易得多。例如，要为名为`contact-details`的路由渲染一个到 id 为 12 的联系人链接的模板片段将是：

```js
<a route-href="route: contact-details; params.bind: { id: 12 }"> 
  Contact #12</a> 

```

机会很大，ID 不会被硬编码，而是存储在一个对象中：

```js
<a route-href="route: contact-details; params.bind: { id: contact.id }"> 
  ${contact.name}</a> 

```

默认情况下，`route-href`属性会将生成的 URL 分配给它所在元素的`href`属性，但它支持一个`attribute`属性，可以用来指定必须设置 URL 的属性名称：

```js
<q route-href="route: quote; attribute: cite">...</q> 

```

在这里，`quote`路由的 URL 将被分配给`q`元素的`cite`属性。

## 导航

路由器提供了方便的方法，可以从 JS 代码执行导航：

+   `navigate(fragment: string, options?: any): boolean`：导航到新的位置，其路径为`fragment`。如果导航成功，则返回`true`，否则返回`false`。目前支持两个`options`：

    +   `replace: boolean`：如果设置为`true`，新 URL 将替换历史记录中的当前位置，而不是添加到历史记录中。

    +   `trigger: boolean`：如果设置为`false`，Aurelia 的路由器将不会被触发。这意味着如果 URL 是相对的，它会在浏览器的地址栏中更改，但实际上不会发生导航。

+   `navigateToRoute(name: string, params?: any, options?: any): boolean`：方便地包装了对`generate`的调用，然后是`navigate`。

+   `navigateBack(): void`：返回历史记录中的上一个位置。

# 摘要

依赖注入是 Aurelia 的核心，因此理解其工作方式很重要。如果你在本章之前对这个概念不熟悉，一下子可能接受不了这么多；但请放心，由于我们将在书的剩余部分大量使用这些功能，这将帮助你更加熟悉它。

插件、功能和路由也是如此。我们将在书的后面继续深入研究这些主题，特别是在第六章，*设计关注 - 组织和解耦*，当我们讨论各种应用程序结构的实现方式时。

在到达那里之前，我们还有很多内容需要学习。在下一章，我们将讨论数据绑定和模板的基础知识，并将组件添加到我们的联系人管理应用程序中以获取和显示数据。
