# React16 模具（一）

> 原文：[`zh.annas-archive.org/md5/649B7A05B5FE7684E1D753EE428FF41C`](https://zh.annas-archive.org/md5/649B7A05B5FE7684E1D753EE428FF41C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

任何技术都取决于支持它的工具。React 也不例外。尽管 React 只是一个用于创建用户界面的库，但围绕它产生的生态系统意味着典型的 React 项目有许多组成部分。如果没有适当的工具支持，您最终会花费大量时间手动执行最好由工具自动化的任务。

React 工具有很多形式。有些已经存在一段时间，而其他一些是全新的。有些在浏览器中找到，而其他一些严格在命令行中。React 开发人员可以使用很多工具——我试图专注于对我所在项目产生直接影响的最强大的工具。

本书的每一章都专注于一个 React 工具。从基本开发工具开始，进入有助于完善 React 组件设计的工具，最后是用于在生产中部署 React 应用程序的工具。

# 这本书是为谁准备的

这本书适用于不断寻找更好工具和技术来提升自己水平的 React 开发人员。虽然阅读本书并不严格要求具有 React 经验，但如果您事先了解一些 React 的基础知识，您将获得最大的价值。

# 充分利用这本书

+   学习 React 的基础知识。

+   如果您已经在项目中使用 React，请确定缺少的工具。

# 下载示例代码文件

您可以从您在[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本解压缩或提取文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/React-16-Tooling`](https://github.com/PacktPublishing/React-16-Tooling)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自我们丰富书籍和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/React16Tooling_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/React16Tooling_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。这是一个例子：“接下来，让我们看看由*Create React App*创建的`package.json`文件。”

代码块设置如下：

```jsx
import React from 'react'; 

const Heading = ({ children }) => ( 
  <h1>{children}</h1> 
); 

export default Heading;
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项将以粗体显示：

```jsx
import React from 'react'; 

const Heading = ({ children }) => ( 
  <h1>{children}</h1> 
); 

export default Heading;
```

任何命令行输入或输出都是这样写的：

```jsx
$ npm install -g create-react-app
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词在文本中显示为这样。这是一个例子：“一旦您点击“添加扩展”按钮，该扩展将被标记为已安装。”

警告或重要提示会出现在这样。提示和技巧会出现在这样。


# 第一章：创建个性化的 React 开发生态系统

当人们听到 React 时，他们会想到一个专注于高效渲染用户界面的库。当人们听到框架时，他们会想到一个庞大的系统，其中可能有一些有用的工具，但其他方面都是臃肿的混乱。在大多数情况下，他们对框架是正确的，但说 React 不是框架有点误导人。

如果你拿出 React 并尝试进行任何有意义的开发，你很快就会遇到障碍。这是因为 React 不是作为一个单一的框架分发的，而是更好地描述为一个核心库，周围有一系列工具的生态系统。

框架的优势在于你可以一次性安装核心库以及支持的工具。缺点是每个项目都不同，你无法确定你需要哪些工具，哪些不需要。另一个优势是拥有一系列工具的生态系统可以独立演进；你不必等待整个框架的新版本来增强你的项目所使用的工具之一。

本书的目的是向你展示如何最好地利用围绕 React 的工具生态系统。在本章中，你将通过学习以下内容来介绍 React 工具的概念：

+   没有工具的 React

+   工具介绍

+   本书涵盖的工具

+   决定项目所需的工具

# React 包含了什么

在我们深入讨论工具之前，让我们确保我们对 React 是什么，以及在安装时实际包含了哪些内容有相同的理解。运行 React web 应用程序需要两个核心 React 包。我们现在来看一下这些，为你提供一些关于思考 React 工具的背景知识。

# 比较渲染树的组件

React 核心的第一部分是名为`react`的包。这个包是我们在编写 React 组件时直接接触的。它是一个小型 API——我们真正使用它的唯一时机是在创建带有状态并且需要扩展`Component`类的组件时。

`react`包的内部有很多工作。这就是渲染树所在的地方，负责高效地渲染 UI 元素。渲染树的另一个名称是虚拟 DOM。其思想是你只需要编写描述要渲染的 UI 元素的 JSX 标记，而渲染树会处理其他一切：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/3fd72d11-9b79-4d85-8bd4-cd8f68547a27.png)

在这个图表中，你看到的是你的代码直接与之交互的组件，以及处理由改变状态的组件导致的呈现变化的渲染树。渲染树及其为你做的一切是 React 的关键价值主张。

# DOM 渲染目标

React 核心的第二部分是**文档对象模型**（**DOM**）本身。事实上，虚拟 DOM 的名称根植于 React 在实际与 DOM API 交互之前在 JavaScript 中创建 DOM 表示。然而，渲染树是一个更好的名称，因为 React 基于 React 组件及其状态创建了一个**AST**（抽象语法树）。这就是为什么相同的 React 库能够与 React Native 等项目一起工作。

`react-dom`包用于通过直接与浏览器 DOM API 通信，将渲染树实际转换为 DOM 元素。以下是包括`react-dom`的先前图表的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/8e5ffcbe-79f4-48a4-b513-7bccb31b8ae7.png)

这是一个很好的架构——这意味着你可以轻松地用另一个渲染目标替换`react-dom`。正如你所看到的，React 的核心层是最小的。难怪它如此受欢迎——我们可以使用声明性代码创建易于维护且高效的用户界面，而我们的工作量很少。有了这个想法，让我们把注意力转向使所有这些成为可能的工具。

# 介绍工具？

工具并不是 React 独有的。每个项目都有自己的一套工具，处理与核心技术相关的任务，这样你就不必自己去处理。对于框架，工具大部分都已经内置到项目中。对于像 React 这样的库，你可以选择你需要的工具，而不需要那些在你的项目中没有作用的工具。

现在你知道了 React 核心是什么，那么 React 生态系统的其余部分是什么呢？

# React 之外的辅助任务

框架膨胀是许多人的主要抵触因素。之所以感觉膨胀，是因为它们有许多你可能永远不会使用的功能。React 处理这一点很好，因为它清楚地区分了核心库和其他任何东西，包括对 React 开发至关重要的东西。

关于 React 及其在周围生态系统中的定位，我做出了两点观察：

+   依赖于简单库而不是包含所有功能的框架的应用程序更容易部署

+   当你有工具大部分时间都不会妨碍你的时候，就更容易思考应用程序开发了。

换句话说，你不必使用大部分 React 工具，但其中一些工具非常有帮助。

任何给定的工具都是外部的，与你正在使用的库是分开的；这一点很重要。工具的存在是为了自动化一些本来会占用我们更多开发时间的事情。生命太短暂，没有时间手动做可以由软件代替的事情。我重申一遍，生命太短暂，没有时间做软件可以比我们做得更好的任务。如果你是一个 React 开发者，可以放心，有工具可以帮你完成所有重要的事情，而你自己没有时间去做。

# 建筑工地的类比

也许，认真对待工具的最终动机是想象一下，如果没有我们作为专业人士所依赖的工具，生活会是什么样子。建筑行业比软件更成熟，并且是一个很好的例子。

想象一下，你是一个负责建造房屋的团队的一部分，这是一个非常复杂的任务，有许多组成部分。现在，想想你要使用的所有东西。让我们从材料本身开始。任何不必在现场组装的东西都不会在现场组装。当你建造房屋时，许多部件会部分组装好。例如，屋顶框架的部分或混凝土在需要时出现。

然后是建筑工人在组装房屋时使用的实际工具——简单的螺丝刀、锤子和卷尺被视为理所当然。如果没有能力在现场制造部件或使用日常建筑材料的工具，建筑生活会是什么样子呢？建造房屋会变得不可能吗？不会。建造过程会变得非常昂贵和缓慢，以至于很可能在完成之前就会被取消吗？会。

不幸的是，在软件世界中，我们才刚刚开始意识到工具的重要性。如果我们没有正确的工具，就算拥有建造未来之屋所需的所有材料和知识也没有用。

# JSX 需要被编译成 JavaScript

React 使用一种类似 HTML 的特殊语法来声明组件。这种标记语言叫做 JSX，它嵌入在组件的 JavaScript 中，在可被浏览器使用之前需要被编译成 JavaScript。

最常见的方法是使用 Babel——一个 JavaScript 编译器——以及一个 JSX 插件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/d382e4e0-f43a-40cb-95b1-6f5f50439286.png)

关键是找到一种使这个编译步骤尽可能无缝的方法。作为开发人员，你不应该需要关心 Babel 产生的 JavaScript 输出。

# 新的 JavaScript 语言特性需要被转译

与将 JSX 编译成 JavaScript 类似，新的 JavaScript 语言特性需要被编译成广泛支持的浏览器版本。事实上，一旦你弄清楚了如何将 JSX 编译成 JavaScript，同样的过程也可以用来在不同版本的 JavaScript 之间进行转译：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/c5c1a2d2-8696-4ee7-bb0b-5f79eca3f567.png)

你不应该担心你的 JSX 或 JavaScript 编译的转换输出。这些活动更适合由工具来处理，这样你就可以专注于应用程序开发。

# 热模块加载以实现应用程序开发

Web 应用程序开发的独特之处在于，它主要是静态内容，加载到浏览器中。浏览器加载 HTML，然后加载任何脚本，然后运行完成。有一个长时间运行的过程，根据应用程序的状态不断刷新页面——一切都是通过网络进行的。

正如你所想象的那样，在开发过程中这是特别令人恼火的，当你想要看到代码更改的结果时。你不想每次做一些事情都要手动刷新页面。这就是热模块替换发挥作用的地方。基本上，HMR 是一个监听代码更改的工具，当它检测到更改时，它会向浏览器发送模块的新版本：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/6d12572f-842d-44d5-b59a-c5147690afcf.png)

即使使用了像 Webpack 及其 HMR 组件这样的工具，为了使这个设置正确工作，即使对于简单的 React 项目也是耗时且容易出错的。幸运的是，今天有工具可以隐藏这些设置细节。

# 自动运行单元测试

你知道你需要为你的组件编写测试。并不是你不想编写实际的测试；而是设置它们能够运行可能会很麻烦。Jest 单元测试工具简化了这一点，因为它知道在哪里找到测试并且可以运行它们：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/14dadefa-9bce-4892-a641-114900a5f804.png)

使用 Jest，我们有一个地方可以放置所有的单元测试，每个测试都依赖于它们所测试的组件。这个工具知道在哪里找到这些测试以及如何运行它们。结果是，当我们需要时，我们可以得到很好的单元测试和代码覆盖率输出。除了实际编写测试之外，没有额外的开销。

# 考虑类型安全性

JavaScript 不是一种类型安全的语言。类型安全性可以通过消除运行时错误的可能性大大提高应用程序的质量。我们可以再次使用工具来创建类型安全的 React 应用程序。Flow 工具可以检查你的代码，查找类型注释，并在发现错误时通知你。

# 代码质量检查

拥有一个能够工作的应用程序是一回事；拥有一个既能工作又具有可维护代码的应用程序是另一回事。实现可衡量的代码质量的最佳方法是采用标准，比如 Airbnb 的（[`github.com/airbnb/javascript`](https://github.com/airbnb/javascript)）。强制执行编码标准的最佳方法是使用一个代码检查工具。对于 React 应用程序，首选的代码检查工具是 ESLint（[`eslint.org/`](https://eslint.org/)）。

# 隔离组件开发环境

也许 React 开发者最容易忽视的工具是 Storybook，它用于隔离组件开发。在开发组件时，你可能意识不到，但应用程序可能会妨碍你。有时，你只想看看组件是什么样子，以及它是如何行为的。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/28eee3d6-3e93-4332-9ded-55c40c924acd.png)

使用类似 Storybook 这样的工具，为组件提供一个与其他组件无关的隔离环境是微不足道的。

# 提供基于浏览器的调试环境

有时，查看单元测试输出和源代码并不足以解决您正在经历的问题。相反，您需要查看与应用程序本身的交互情况。在浏览器中，您可以安装 React 工具，以便轻松检查与呈现的 HTML 内容相关的 React 组件。

React 还具有一些内置的性能监控功能，可以扩展浏览器开发人员工具的功能。您可以使用它们来检查和分析您的组件的低级别情况。

# 部署 React 应用程序

当您准备部署 React 应用程序时，它并不像简单地生成构建并分发那样简单。实际上，如果您正在构建托管服务，您甚至可能根本不会分发它。无论您的应用程序的最终用例是什么，除了 React 前端之外，可能还会有几个移动部分。越来越多地，将构成应用程序堆栈的主要进程容器化是首选方法：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/6ab65be2-2dc4-4289-85dc-adc0e84f0910.png)

为了创建和部署像这样的 React 应用程序堆栈，您将依赖于诸如 Docker 之类的工具，特别是在自动化项目的各种部署场景时。

# 选择正确的工具

如果上一节中的工具对于单个项目来说似乎有点过多，不要担心。试图同时利用每个可能的 React 工具总是一个错误。从基本工具开始，逐个解决问题。随着项目的推进，逐渐添加可选工具以扩展您的工具集。

# 基本工具

有一些 React 工具是您简直无法离开的。例如，浏览器无法理解 JSX 语法，因此需要将其编译为 JavaScript。在编写代码时，您会希望对其进行 lint 处理，以确保不会错过基本错误，并且您会希望运行单元测试。如果努力尝试，您可能可以在没有这些工具的情况下完成。但问题是，您将花费更多的精力来不使用给定的工具，而不是简单地接受它。

作为起点，找到一组最小的 React 工具，使您能够取得进展。一旦您的进展明显放缓，就是时候考虑引入其他工具了。

# 可选工具

可选工具是你可能不会从中获得任何真正价值的东西。例如，你可能不会在项目开始阶段就使用 Flow 来检查类型安全性或 Storybook 来隔离组件开发而获得巨大的好处。

要记住的关键是任何 React 工具都是可选的，没有永久的决定。你可以随时引入 Flow，如果隔离组件开发不是你的菜，你也可以随时放弃 Storybook。

# 总结

本章介绍了 React 生态系统中工具的概念。你了解到 React 本质上是一个简单的库，它依赖于使用多种工具才能在现实世界中产生任何价值。框架试图为你的项目提供所有你需要的工具。虽然方便，但框架用户的需求很难预测，可能会分散注意力，而不是专注于核心功能。

接下来，你了解到 React 中的工具可能是一个挑战，因为作为 React 开发者，你需要负责选择合适的工具并管理它们的配置。然后，你对本书剩余部分将更详细学习的工具进行了概述。最后，你了解到一些工具对于 React 开发是至关重要的，你需要立即设置它们。其他工具是可选的，你可能直到项目后期真正需要时才开始使用它们。

在下一章中，你将使用*Create React App*工具来启动一个 React 项目。


# 第二章：使用 Create React App 高效引导 React 应用程序

本书中您将学习的第一个 React 工具是*Create React App*。它是一个命令行实用程序，帮助您惊人地创建一个 React 应用程序。这可能听起来像是您不需要太多帮助的事情，但当您使用这个工具时，您不再需要考虑很多配置。在本章中，您将学习：

+   在系统上安装*Create React App*工具

+   引导创建您的 React 应用程序

+   创建新应用程序时安装了哪些包

+   应用程序的目录组织和文件

# 安装 Create React App

第一步是安装*Create React App*，这是一个 npm 包：`create-react-app`。这个包应该全局安装，因为它在您的系统上安装了一个用于创建 React 项目的命令。换句话说，`create-react-app`实际上并不是您的 React 项目的一部分，它用于初始化您的 React 项目。

以下是您可以全局安装*Create React App*的方法：

```jsx
$ npm install -g create-react-app
```

注意命令中的`-g`标志—这确保`create-react-app`命令被全局安装。安装完成后，您可以通过运行以下命令来确保该命令可以正常运行：

```jsx
$ create-react-app -V

> 1.4.1 
```

现在，您已经准备好使用这个工具来创建您的第一个 React 应用程序了！

# 创建您的第一个应用程序

我们将在本章的剩余部分使用*Create React App*创建您的第一个 React 应用程序。别担心，这很容易做到，所以这将是一个简短的章节。*Create React App*的目标是尽快开始为您的应用程序构建功能。如果您花费时间配置系统，就无法做到这一点。

*Create React App*提供了所谓的**零配置应用程序**。这意味着我们提供应用程序的名称，然后它将安装我们需要的依赖项，并为我们创建样板目录结构和文件。让我们开始吧。

# 指定项目名称

您需要向*Create React App*提供的唯一配置值是名称，以便它可以引导您的项目。这作为参数传递给`create-react-app`命令：

```jsx
$ create-react-app my-react-app
```

如果当前目录中不存在`my-react-app`目录，它将在其中创建一个，如果已经存在，则将使用该目录。这是你将找到与你的应用程序有关的一切。一旦目录创建完成，它将安装包依赖项并创建项目目录和文件。这是`create-react-app`命令输出的缩短版本可能看起来像：

```jsx
Creating a new React app in 02/my-react-app.

Installing packages. This might take a couple of minutes.
Installing react, react-dom, and react-scripts...

+ react-dom@16.0.0
+ react@16.0.0
+ react-scripts@1.0.14
added 1272 packages in 57.831s

Success! Created my-react-app at 02/my-react-app
Inside that directory, you can run several commands:

  npm start
    Starts the development server.

  npm run build
    Bundles the app into static files for production.

  npm test
    Starts the test runner.

  npm run eject
    Removes this tool and copies build dependencies,
    configuration files and scripts into the app directory.
    If you do this, you can't go back!

We suggest that you begin by typing:

  cd my-react-app
  npm start

Happy hacking!
```

这个输出向你展示了一些有趣的东西。首先，它显示了安装了哪些东西。其次，它向你展示了在你的项目中可以运行的命令。你将在本书的后续章节中学习如何使用这些命令。现在，让我们看看你刚刚创建的项目，并看看它包含了什么。

# 自动依赖处理

接下来，让我们看看在引导过程中安装的依赖项。你可以通过运行`npm ls --depth=0`来列出你的项目包。`--depth=0`选项意味着你只想看到顶层依赖项：

```jsx
├── react@16.0.0 
├── react-dom@16.0.0 
└── react-scripts@1.0.14 
```

这里没有太多东西，只有你需要的两个核心 React 库，还有一个叫做`react-scripts`的东西。后者包含了你想要在这个项目中运行的脚本，比如启动开发服务器和生成生产版本。

接下来，让我们看看*Create React App*创建的`package.json`文件：

```jsx
{ 
  "name": "my-react-app", 
  "version": "0.1.0", 
  "private": true, 
  "dependencies": { 
    "react": "¹⁶.0.0", 
    "react-dom": "¹⁶.0.0", 
    "react-scripts": "1.0.14" 
  }, 
  "scripts": { 
    "start": "react-scripts start", 
    "build": "react-scripts build", 
    "test": "react-scripts test --env=jsdom", 
    "eject": "react-scripts eject" 
  } 
} 
```

这里是跟踪依赖关系的地方，这样你就可以在没有*Create React App*的不同机器上安装你的应用程序。你可以看到`dependencies`部分与`npm ls --depth=0`命令的输出相匹配。`scripts`部分指定了在这个项目中可用的命令。这些都是`react-scripts`命令——`react-scripts`被安装为一个依赖项。

*Create React App*的一个更强大的方面是，它为你简化了`package.json`的配置。你不再需要维护几十个依赖项，而是只有少数几个依赖项。`react-scripts`包为你处理了动态配置方面。

例如，当您运行 React 开发服务器时，通常需要花费大量时间来处理 Webpack 配置，并确保适当的 Babel 插件已安装。由于`react-scripts`会动态创建这些内容的标准配置，您就不必担心了。相反，您可以立即开始编写应用程序代码。

`react-scripts`包还处理了许多通常需要自己处理的依赖关系。您可以使用`npm ls --depth=1`来了解这个包为您处理了哪些依赖关系：

```jsx
└─┬ react-scripts@1.0.14 
     ├── autoprefixer@7.1.2 
     ├── babel-core@6.25.0 
     ├── babel-eslint@7.2.3 
     ├── babel-jest@20.0.3 
     ├── babel-loader@7.1.1 
     ├── babel-preset-react-app@3.0.3 
     ├── babel-runtime@6.26.0 
     ├── case-sensitive-paths-webpack-plugin@2.1.1 
     ├── chalk@1.1.3 
     ├── css-loader@0.28.4 
     ├── dotenv@4.0.0 
     ├── eslint@4.4.1 
     ├── eslint-config-react-app@2.0.1 
     ├── eslint-loader@1.9.0 
     ├── eslint-plugin-flowtype@2.35.0 
     ├── eslint-plugin-import@2.7.0 
     ├── eslint-plugin-jsx-a11y@5.1.1 
     ├── eslint-plugin-react@7.1.0 
     ├── extract-text-webpack-plugin@3.0.0 
     ├── file-loader@0.11.2 
     ├── fs-extra@3.0.1 
     ├── fsevents@1.1.2 
     ├── html-webpack-plugin@2.29.0 
     ├── jest@20.0.4 
     ├── object-assign@4.1.1 deduped 
     ├── postcss-flexbugs-fixes@3.2.0 
     ├── postcss-loader@2.0.6 
     ├── promise@8.0.1 
     ├── react-dev-utils@4.1.0 
     ├── style-loader@0.18.2
```

```jsx
 ├── sw-precache-webpack-plugin@0.11.4 
     ├── url-loader@0.5.9 
     ├── webpack@3.5.1 
     ├── webpack-dev-server@2.8.2 
     ├── webpack-manifest-plugin@1.2.1 
     └── whatwg-fetch@2.0.3 
```

通常，您不会在应用程序代码中与大多数这些包进行交互。当您不得不积极管理自己没有直接使用的依赖关系时，会感觉像是在浪费大量时间。*Create React App*有助于消除这种感觉。

# 目录结构

到目前为止，您已经了解了在使用*Create React App*创建项目时作为其一部分安装的依赖关系。除了依赖关系外，*Create React App*还设置了一些其他样板文件和目录。让我们快速地过一遍这些，这样您就可以在下一章开始编码了。

# 顶层文件

在您的应用程序的顶层只创建了两个文件，您需要关注：

+   `README.md`：这个 Markdown 文件用于描述项目。如果您计划将您的应用程序作为 GitHub 项目，这是一个很好的地方来解释您的项目存在的原因以及人们如何开始使用它。

+   `package.json`：这个文件用于配置分发您的应用程序作为 npm 包的所有方面。例如，这是您可以添加新依赖项或删除过时依赖项的地方。如果您计划将您的应用程序发布到主 npm 注册表，这个文件就非常重要。

# 静态资产

*Create React App*为您创建了一个 public 目录，并在其中放置了一些文件。这是静态应用程序资产的存放位置。默认情况下，它包含以下内容：

+   `favion.ico`：这是在浏览器标签中显示的 React 标志。在发布之前，您会希望用代表您的应用程序的东西替换它。

+   `index.html`：这是提供给浏览器的 HTML 文件，也是您的 React 应用程序的入口点。

+   `manifest.json`：当应用程序添加到主屏幕时，一些移动操作系统会使用这个文件。

# 源代码

`src`目录是由`create-react-app`创建的应用程序中最重要的部分。这是你创建的任何 React 组件的所在地。默认情况下，这个目录中有一些源文件，可以让你开始，尽管随着你的进展，你显然会替换大部分文件。以下是默认情况下你会找到的内容：

+   `App.css`：这定义了一些简单的 CSS 来为`App`组件设置样式

+   `App.js`：这是渲染应用程序 HTML 的默认组件

+   `App.test.js`：这是`App`组件的基本测试

+   `index.css`：这定义了应用程序范围的样式

+   `index.js`：这是你的应用程序的入口点—渲染`App`组件

+   `logo.svg`：一个由`App`组件渲染的动画 React 标志

+   `registerServiceWorker.js`：在生产构建中，这将使组件从离线缓存中加载

有这些默认源文件为你创建有两个好处。首先，你可以快速启动应用程序，确保一切正常运行，而且你没有犯任何基本错误。其次，它为你的组件设定了一个基本模式。在本书中，你将看到如何将模式应用到组件实际上有助于工具化。

# 概要

在本章中，你学会了如何在你的系统上安装*Create React App*工具。*Create React App*是启动现代 React 应用程序的首选工具。*Create React App*的目标是让开发人员在最短的时间内从零开始创建 React 组件。

安装了这个工具后，你使用它创建了你的第一个 React 应用程序。你需要提供的唯一配置是应用程序名称。一旦工具完成安装依赖项并创建样板文件和目录，你就可以开始编写代码了。

然后，我们看了`react-scripts`和这个包所处理的依赖项。然后，你被带领快速浏览了为你创建的应用程序的整体结构。

在接下来的章节中，我们将开始开发一些 React 组件。为此，我们将启动开发服务器。你还将学习如何使用`create-react-app`开发环境快速上手。


# 第三章：开发模式和精通热重载

在上一章中，你学会了如何使用`create-react-app`。这只是我们*React 工具链*旅程的开始。通过使用`create-react-app`来引导你的应用程序，你安装了许多其他用于开发的工具。这些工具是`react-scripts`包的一部分。本章的重点将是`react-scripts`附带的开发服务器，我们将涵盖：

+   启动开发服务器

+   自动 Webpack 配置

+   利用热组件重新加载

# 启动开发服务器

如果你在上一章中使用`create-react-app`工具创建了一个 React 应用程序，那么你已经拥有了启动开发服务器所需的一切。不需要进行任何配置！让我们立即启动它。首先确保你在项目目录中：

```jsx
cd my-react-app/ 
```

现在你可以启动开发服务器了：

```jsx
npm start 
```

这将使用`react-scripts`包中的`start`脚本启动开发服务器。你应该会看到类似于这样的控制台输出：

```jsx
Compiled successfully!

You can now view my-react-app in the browser.

  Local:            http://localhost:3000/
  On Your Network:  http://192.168.86.101:3000/

Note that the development build is not optimized.
To create a production build, use npm run build. 
```

你会注意到，除了在控制台中打印这个输出之外，这个脚本还会在浏览器中打开一个新的标签页，地址为`http://localhost:3000/`。显示的页面看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/1dcf9a53-b771-44f1-bf22-e40360ffbf28.png)

到目前为止，在仅仅几章中我们已经取得了很多成就。让我们暂停一下，回顾一下我们所做的事情：

1.  你使用`create-react-app`包创建了一个新的 React 应用程序。

1.  你已经有了基本的项目结构和一个占位符`App`组件来渲染。

1.  你启动了开发服务器，现在你准备构建 React 组件了。

在没有`create-react-app`和`react-scripts`的情况下，要达到这一点通常需要花费数小时。你可能没有数小时来处理元开发工作。很多工作已经为你自动化了！

# Webpack 配置

Webpack 是构建现代 Web 应用程序的首选工具。它强大到足以将从 JSX 语法到静态图像的所有内容编译成准备部署的捆绑包。它还带有一个开发服务器。它的主要缺点是复杂性。有很多需要配置的移动部分才能让 Webpack 起步，但你不需要触及其中任何部分。这是因为大多数为 React 应用程序设置的 Webpack 配置值对于大多数 React 应用程序都是相同的。

有两个独立的开发服务器配置。首先是 Webpack 开发服务器本身。然后是主要的 Webpack 配置，即使你没有使用 Webpack 开发服务器，你也需要它。那么这些配置文件在哪里？它们是`react-scripts`包的一部分，这意味着你不必去瞎折腾它们！

现在让我们浏览一些这些配置值，让你更好地了解你可以避免的不必要的头痛。

# 入口点

入口点用于告诉 Webpack 从哪里开始查找用于构建应用程序的模块。对于一个简单的应用程序，你不需要更多的东西，只需要一个文件作为入口点。例如，这可以是用于渲染你的根 React 组件的`index.js`文件。从其他编程语言借来的术语来看，这个入口点也可以被称为主程序。

当你运行`start`脚本时，`react-scripts`包会在你的源文件夹中寻找一个`index.js`文件。它还添加了一些其他入口点：

+   `Promise`、`fetch()`和`Object.assign()`的填充。只有在目标浏览器中不存在时才会使用它们。

+   一个用于热模块重载的客户端。

这最后两个入口点对于 React 开发非常有价值，但当你试图启动一个项目时，它们并不是你想要考虑的事情。

# 构建输出

Webpack 的工作是打包你的应用程序资源，以便它们可以轻松地从网络中提供。这意味着你必须配置与包输出相关的各种事物，从输出路径和文件开始。Webpack 开发服务器实际上并不会将捆绑文件写入磁盘，因为假定构建会频繁发生。生成的捆绑文件保存在内存中。即使有这个想法，你仍然需要配置主要输出路径，因为 Webpack 开发服务器仍然需要将其作为真实文件提供给浏览器。

除了主要的输出位置，你还可以配置块文件名和用于提供文件的公共路径。块是被分割成更小的片段以避免创建一个太大并可能导致性能问题的单个捆绑文件。等等，什么？在你甚至为你的应用程序实现一个组件之前就考虑性能和用于提供资源的路径？在项目的这一阶段完全是不必要的。别担心，`react-scripts`已经为你提供了配置，你可能永远不需要改变。

# 解析输入文件

Webpack 的一个关键优势是你不需要提供一个需要捆绑的模块列表。一旦在 Webpack 配置中提供了一个入口点，它就可以找出你的应用程序需要哪些模块，并相应地捆绑它们。不用说，这是 Webpack 为你执行的一个复杂的任务，它需要尽可能多的帮助。

例如，`resolve`配置的一部分是告诉 Webpack 要考虑哪些文件扩展名，例如`.js`或`.jsx`。你还想告诉 Webpack 在哪里查找包模块。这些是你没有编写的模块，也不是你应用程序的一部分。这些通常可以在项目的`node_modules`目录中找到的 npm 包。

还有更高级的选项，比如为模块创建别名并使用解析器插件。再次强调，在编写任何 React 代码之前，这些都与你无关，但你需要配置它们以便开发你的组件，除非你正在使用`react-scripts`来处理这个配置。

# 加载和编译文件

加载和编译文件对于你的捆绑来说可能是 Webpack 最重要的功能。有趣的是，Webpack 在加载文件后并不直接处理它们。相反，它通过 Webpack 加载器插件协调 I/O。例如，`react-scripts`使用以下加载器插件的 Webpack 配置：

+   **Babel**：Babel 加载器将你应用程序的源文件中的 JavaScript 转译成所有浏览器都能理解的 JavaScript。Babel 还会处理将你的 JSX 语法编译成普通的 JavaScript。

+   **CSS**：`react-scripts`使用了一些加载程序来生成 CSS 输出：

+   `style-loader`：使用`import`语法像导入 JavaScript 模块一样导入 CSS 模块。

+   `postcss-loader`：增强的 CSS 功能，如模块、函数和自定义属性。

+   **图片**：通过 JavaScript 或 CSS 导入的图片使用`url-loader`进行捆绑。

随着你的应用程序成熟，你可能会发现自己需要加载和捆绑不在默认`react-scripts`配置范围内的不同类型的资产。由于你在项目开始时不需要担心这一点，所以没有必要浪费时间配置 Webpack 加载器。

# 配置插件

似乎有一个无穷无尽的插件列表可以添加到你的 Webpack 配置中。其中一些对开发非常有用，所以你希望这些插件在前期就配置好。其他一些可能在项目成熟后才会有用。`react-scripts`默认使用的插件有助于无缝的 React 开发体验。

# 热重载

热模块重载机制需要在主 Webpack 捆绑配置文件和开发服务器配置中进行配置。这是另一个你在开始开发组件时想要的东西的例子，但不想花时间去做。`react-scripts`的`start`命令启动了一个已经配置好了热重载的 Webpack 开发服务器。

# 热组件重载正在进行中

在本章的前面，你学会了如何启动`react-scripts`开发服务器。这个开发服务器已经配置好了热模块重载，可以直接使用。你只需要开始编写组件代码。

让我们从实现以下标题组件开始：

```jsx
import React from 'react'; 

const Heading = ({ children }) => ( 
  <h1>{children}</h1> 
); 

export default Heading; 
```

这个组件将任何子文本呈现为`<h1>`标签。简单吗？现在，让我们改变`App`组件来使用`Heading`：

```jsx
import React, { Component } from 'react'; 
import './App.css'; 
import Heading from './Heading';

class App extends Component { 
  render() { 
    return ( 
      <div className="App"> 
        <Heading> 
          My App 
        </Heading> 
      </div> 
    ); 
  } 
} 

export default App; 
```

然后，你可以看到这是什么样子的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/485a5c5f-f3a7-44db-b479-b00cd63f5c98.png)

`Heading`组件按预期渲染。现在你已经在浏览器中初始化加载了你的应用程序，是时候让热重载机制开始工作了。假设你决定改变这个标题的标题：

```jsx
<Heading> 
  My App Heading 
</Heading> 
```

当你在代码编辑器中保存时，Webpack 开发服务器会检测到发生了变化，新代码应该被编译、捆绑并发送到浏览器。由于`react-scripts`已经配置好了 Webpack，你可以直接进入浏览器，观察变化的发生：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/e7c80c59-40c7-4e5c-9a24-49c2a71ce4b7.png)

这应该有助于加快开发速度！事实上，它已经做到了，你刚刚见证了。你修改了一个 React 元素的文本，并立即看到了结果。你本可以花几个小时来设置 Webpack 配置，但你不必这样做，因为你只需重用`react-scripts`提供的配置，因为几乎所有的 React 开发配置看起来都应该差不多。随着时间的推移，它们会分歧，但没有任何组件的项目看起来都非常相似。关键是要快速上手。

现在让我们尝试一些不同的东西。让我们添加一个带有`state`的组件，并看看当我们改变它时会发生什么。这是一个简单的按钮组件，它会跟踪自己的点击次数：

```jsx
import React, { Component } from 'react'; 

class Button extends Component { 
  style = {} 

  state = { 
    count: 0 
  } 

  onClick = () => this.setState(state => ({ 
    count: state.count + 1 
  })); 

  render() { 
    const { count } = this.state; 
    const { 
      onClick, 
      style 
    } = this; 

    return ( 
      <button {...{ onClick, style }}> 
        Clicks: {count} 
      </button> 
    ); 
  } 
} 

export default Button;
```

让我们分解一下这个组件的运行情况：

1.  它有一个`style`对象，但没有任何属性，所以这没有任何效果。

1.  它有一个`count`状态，每次点击按钮时都会增加。

1.  `onClick()`处理程序设置了新的`count`状态，将旧的`count`状态增加`1`。

1.  `render()`方法渲染了一个带有`onClick`处理程序和`style`属性的`<button>`元素。

一旦你点击这个按钮，它就会有一个新的状态。当我们使用热模块加载时会发生什么？让我们试一试。我们将在我们的`App`组件中渲染这个`Button`组件，如下所示：

```jsx
import React, { Component } from 'react'; 
import './App.css'; 
import Heading from './Heading'; 
import Button from './Button'; 

class App extends Component { 
  render() { 
    return ( 
      <div className="App"> 
        <Heading> 
          My App Heading 
        </Heading> 
        <Button/> 
      </div> 
    ); 
  } 
} 

export default App; 
```

当你加载 UI 时，你应该看到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/d1d97bb0-a1fc-4eb7-9769-4c83ad7d8f19.png)

点击按钮应该将`count`状态增加`1`。确实，点击几次会导致渲染的按钮标签发生变化，反映出新的状态：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/0753634f-4787-49aa-9bdb-f3a75138c414.png)

现在，假设你想改变按钮的样式。我们将使文本加粗：

```jsx
class Button extends Component { 
  style = { fontWeight: 'bold' } 

  ... 

  render() { 
    const { count } = this.state; 
    const { 
      onClick, 
      style 
    } = this; 

    return ( 
      <button {...{ onClick, style }}> 
        Clicks: {count} 
      </button> 
    ); 
  } 
} 

export default Button; 
```

热模块机制的工作正常，但有一个重要的区别：`Button`组件的状态已经恢复到初始状态：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/20a0a67c-9e7c-471b-a3f8-37919c578ef6.png)

这是因为当`Button.js`模块被替换时，现有的组件实例在被新实例替换之前会被卸载。组件的状态和组件本身都会被清除。

解决这个问题的方法是使用*React Hot Loader*工具。这个工具将保持你的组件在其实现更新时挂载。这意味着状态会保持不变。在某些情况下，这可能非常有帮助。当你刚开始时是否需要这个？可能不需要——不保持状态的热模块重载已经足够让你开始。

# 从 Create React App 中弹出

`create-react-app`和`react-scripts`的目标是零配置的 React 开发。你花在配置开发样板的时间越少，你就能花更多时间开发组件。你应该尽可能地避免担心为你的应用程序进行配置。但是在某个时候，你将不得不放弃`create-react-app`并维护自己的配置。

提供零配置环境之所以可能，是因为`create-react-app`假定了许多默认值和许多限制。这是一种权衡。通过为大多数 React 开发人员必须做但不想做的事情提供合理的默认值，你正在为开发人员做出选择。这是一件好事——在应用程序开发的早期阶段能够推迟决策会让你更加高效。

React 组件热加载是`create-react-app`的一个限制的很好的例子。它不是`create-react-app`提供的配置的一部分，因为在项目初期你可能不需要它。但随着事情变得更加复杂，能够在不中断当前状态的情况下对组件进行故障排除是至关重要的。在项目的这一阶段，`create-react-app`已经完成了它的使命，现在是时候弹出了。

要从`create-react-app`中弹出，运行`eject`脚本：

```jsx
npm run eject
```

你将被要求确认此操作，因为没有回头的余地。在这一点上，值得强调的是，在`create-react-app`不再适用之前，你不应该弹出。记住，一旦你从`create-react-app`中弹出，你现在要承担维护所有曾经隐藏在视图之外的脚本和配置的责任。

好消息是，弹出过程的一部分涉及为项目设置脚本和配置值。基本上，这与`react-scripts`在内部使用的是相同的东西，只是现在这些脚本和配置文件被复制到你的项目目录中供你维护。例如，弹出后，你会看到一个包含以下文件的`scripts`目录：

+   `build.js`

+   `start.js`

+   `test.js`

现在，如果您查看`package.json`，您会发现您使用`npm`调用的脚本现在引用您的本地脚本，而不是引用`react-scripts`包。反过来，这些脚本使用在您运行弹出时为您创建的`config`目录中找到的文件。以下是在此处找到的相关 Webpack 配置文件：

+   `webpack.config.dev.js`

+   `webpack.config.prod.js`

+   `webpackDevServer.config.js`

请记住，这些文件是从`react-scripts`包中复制过来的。弹出只是意味着您现在控制了曾经隐藏的一切。它的设置方式仍然完全相同，并且在您更改它之前将保持不变。

例如，假设您已经决定需要 React 的热模块替换，以一种可以保持组件状态的方式。现在您已经从`create-react-app`中弹出，可以配置启用`react-hot-loader`工具所需的部分。让我们从安装依赖开始：

```jsx
npm install react-hot-loader --save-dev
```

接下来，让我们更新`webpack.config.dev.js`文件，以便它使用`react-hot-loader`。这是在我们弹出之前不可能配置的东西。有两个部分需要更新：

1.  首先，在`entry`部分找到以下行：

```jsx
      require.resolve('react-dev-utils/webpackHotDevClient'), 
```

1.  用以下两行替换它：

```jsx
      require.resolve('webpack-dev-server/client') + '?/', 
      require.resolve('webpack/hot/dev-server'), 
```

1.  接下来，您需要将`react-hot-loader`添加到 Webpack 配置的`module`部分。找到以下对象：

```jsx
      { 
        test: /\.(js|jsx|mjs)$/, 
        include: paths.appSrc, 
        loader: require.resolve('babel-loader'), 
        options: { 
          cacheDirectory: true, 
        }, 
      }
```

1.  将其替换为以下内容：

```jsx
      { 
        test: /\.(js|jsx|mjs)$/, 
        include: paths.appSrc, 
        use: [ 
          require.resolve('react-hot-loader/webpack'), 
          { 
            loader: require.resolve('babel-loader'), 
            options: { 
              cacheDirectory: true, 
            }, 
          } 
        ] 
      }, 
```

在这里所做的只是将`loader`选项更改为`use`选项，以便您可以传递一系列的加载器。您之前使用的`babel-loader`保持不变。但现在您还添加了`react-hot-loader/webpack`加载器。现在这个工具可以在源代码更改时检测何时需要热替换 React 组件。

这就是您需要更改开发 Webpack 配置的全部内容。接下来，您需要更改根 React 组件的渲染方式。以下是`index.js`以前的样子：

```jsx
import React from 'react'; 
import ReactDOM from 'react-dom'; 
import './index.css'; 
import App from './App'; 
import registerServiceWorker from './registerServiceWorker'; 

ReactDOM.render(<App />, document.getElementById('root')); 
registerServiceWorker(); 
```

为了启用热组件替换，您可以更改`index.js`，使其看起来像这样：

```jsx
import 'react-hot-loader/patch'; 
import React from 'react'; 
import ReactDOM from 'react-dom'; 
import { AppContainer } from 'react-hot-loader'; 

import './index.css'; 
import App from './App'; 
import registerServiceWorker from './registerServiceWorker'; 

const render = Component => { 
  ReactDOM.render( 
    <AppContainer> 
      <Component /> 
    </AppContainer>, 
    document.getElementById('root') 
  ) 
};
```

```jsx
render(App); 

if (module.hot) { 
  module.hot.accept('./App', () => { 
    render(App); 
  }); 
} 

registerServiceWorker(); 
```

让我们分解一下您刚刚添加的内容：

1.  `import 'react-hot-loader/patch'`语句是必要的，用于引导`react-hot-loader`机制。

1.  您创建了一个接受要渲染的组件的`render()`函数。该组件被`react-hot-loader`的`AppContainer`组件包装，该组件处理了一些与热加载相关的簿记工作。

1.  对`render(App)`的第一次调用渲染了应用程序。

1.  对 `module.hot.accept()` 的调用设置了一个回调函数，当组件的新版本到达时渲染 `App` 组件。

现在您的应用程序已准备好接收热更新的 React 组件。当您的源代码发生更改时，它总是能够接收更新，但正如本章前面讨论的那样，这些更新将在组件重新渲染之前清除组件中的任何状态。现在 `react-hot-loader` 已经就位，您可以保留组件中的任何状态。让我们试一试。

加载 UI 后，点击按钮几次以更改其状态。然后，更改 `style` 常量以使字体加粗：

```jsx
const style = { 
  fontWeight: 'bold' 
}; 
```

保存此文件后，您会注意到按钮组件已更新。更重要的是，状态没有改变！如果您点击按钮两次，现在应该是这样的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/b7439ce3-0172-47ea-a557-57f5447d0030.png)

这只涉及一个按钮的简单示例。但是，通过从 `create-react-app` 中弹出，调整开发 Webpack 配置，并改变 `App` 组件渲染方式所创建的设置可以支持未来创建的每个组件的热加载。

将 `react-hot-loader` 包添加到您的项目中只是需要从 `create-react-app` 中弹出以便您可以调整配置的一个例子。我建议不要更改绝对必要的内容。确保在更改 `create-react-app` 给您的配置时有一个具体的目标。换句话说，不要撤消 `create-react-app` 为您所做的所有工作。

# 总结

在本章中，您学会了如何为使用 `create-react-app` 创建的项目启动开发服务器。然后您了解到 `react-scripts` 包在为您启动开发服务器时使用自己的 Webpack 配置。我们讨论了在尝试编写应用程序时不一定需要考虑的配置的关键领域。

最后，您看到了热模块重新加载的实际操作。`react-scripts`默认情况下在您进行源代码更改时重新加载应用程序。这会导致页面刷新，这已经足够好用了。然后我们看了一下使用这种方法开发组件可能面临的挑战，因为它会清除组件在更新之前的任何状态。因此，您从`create-react-app`中退出，并自定义了项目的 Webpack 配置，以支持保留状态的热组件重新加载。

在接下来的章节中，您将使用工具来支持在您的 React 应用程序中进行单元测试。


# 第四章：优化测试驱动的 React 开发

也许，React 生态系统中最重要的工具之一是 Jest——用于测试 React 组件的测试运行器和单元测试库。Jest 旨在克服其他测试框架（如 Jasmine）面临的挑战，并且是针对 React 开发而创建的。有了像 Jest 这样强大的测试工具，您更有能力让您的单元测试影响 React 组件的设计。在本章中，您将学到：

+   Jest 的总体设计理念及其对 React 开发者的意义

+   在`create-react-app`环境和独立的 React 环境中运行 Jest 单元测试

+   使用 Jest API 编写有效的单元测试和测试套件

+   在您的代码编辑器中运行 Jest 单元测试并将测试集成到您的开发服务器中

# Jest 的驱动理念

在上一章中，您了解到`create-react-app`工具是为了使开发 React 应用程序更容易而创建的。它通过消除前期配置来实现这一目的——您直接开始构建组件。Jest 也是出于同样的目的而创建的，它消除了您通常需要创建的前期样板，以便开始编写测试。除了消除初始单元测试配置因素之外，Jest 还有一些其他技巧。让我们来看看使用 Jest 进行测试的一些驱动原则。

# 模拟除应用程序代码之外的所有内容

你最不想花时间测试别人的代码。然而，有时你被迫这样做。例如，假设您想测试一个调用某个 HTTP API 的`fetch()`函数。另一个例子：您的 React 组件使用某个库来帮助设置和操作其状态。

在这两个例子中，有一些您没有实现的代码在运行您的单元测试时被执行。您绝对不希望通过 HTTP 与外部系统联系。您绝对不希望确保您的组件状态是根据另一个库的函数输出正确设置的。对于我们不想测试的代码，Jest 提供了一个强大的模拟系统。但是您需要在某个地方划清界限——您不能模拟每一个小事物。

这是一个组件及其依赖项的示例：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/409c52f1-1a46-4eae-a4d0-0c6cc1957722.png)

这个组件需要三个库才能正常运行。你可能不想按原样对这个组件进行单元测试，因为这样你也会测试其他三个库的功能。你不想在单元测试期间运行的库可以使用 Jest 进行模拟。你不必对每个库进行模拟，对一些库来说，模拟它们可能会带来更多麻烦。

举个例子，假设在这种情况下**Lib C**是一个日期库。你真的需要对它进行模拟吗，还是你实际上可以在组件测试中使用它产生的值？日期库是相当低级的，所以它可能是稳定的，对你的单元测试的功能可能造成非常小的风险。另一方面，库的级别越高，它所做的工作越多，对你的单元测试就越有问题。让我们看看如果你决定使用 Jest 来模拟**Lib A**和**Lib B**会是什么样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/0b3ee051-6f68-4083-8f0e-8f8f1952a0f3.png)

如果你告诉 Jest 你想要模拟**Lib A**和**Lib B**的实现，它可以使用实际的模块并自动创建一个对象供你的测试使用。因此，几乎不费吹灰之力，你就可以模拟那些对测试你的代码构成挑战的依赖关系。

# 隔离测试并并行运行

Jest 使得在一个沙盒环境中隔离你的单元测试变得容易。换句话说，运行一个测试的副作用不能影响其他测试的结果。每次测试运行完成后，全局环境会自动重置为下一个测试。由于测试是独立的，它们的执行顺序并不重要，Jest 会并行运行测试。这意味着即使你有数百个单元测试，你也可以频繁地运行它们，而不必担心等待的问题。

这是 Jest 如何在它们自己的隔离环境中并行运行测试的示例：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/fe1e3a8d-c7d8-499f-b765-972d6212107a.png)

最好的部分是 Jest 会为你处理扩展进程的问题。例如，如果你刚刚开始，你的项目只有少数几个单元测试，Jest 不会生成八个并行进程。它只会在一个进程中运行它们。你需要记住的关键是，单元测试是它们自己的宇宙，不受其他宇宙的干扰。

# 测试应该感觉自然

Jest 让你很容易开始运行你的测试，但是写测试呢？Jest 提供的 API 使得编写没有太多复杂部分的测试变得容易。API 文档（[`facebook.github.io/jest/docs/en/api.html`](https://facebook.github.io/jest/docs/en/api.html)）被组织成易于查找所需内容的部分。例如，如果你正在编写一个测试并且需要验证一个期望值，你可以在 API 文档的*Expect*部分找到你需要的函数。或者，你可能需要帮助配置一个模拟函数——API 文档的*Mock Functions*部分包含了你在这个主题上需要的一切。

Jest 真正脱颖而出的另一个领域是当你需要测试异步代码时。这通常涉及使用 promise。Jest API 使得在不必写大量异步样板的情况下，轻松期望解析或拒绝的 promise 返回特定值变得容易。正是这些小细节使得为 Jest 编写单元测试感觉像是实际应用代码的自然延伸。

# 运行测试

Jest 命令行工具是运行单元测试所需的全部。工具有多种使用方式。首先，你将学习如何在`create-react-app`环境中调用测试运行器以及如何使用交互式观察模式选项。然后，你将学习如何在没有`create-react-app`帮助的情况下在独立环境中运行 Jest。

# 使用 react-scripts 运行测试

当你使用`create-react-app`创建你的 React 应用时，你可以立即运行测试。实际上，在为你创建的样板代码中，已经为`App`组件创建了一个单元测试。这个测试被添加以便 Jest 能够找到一个可以运行的测试。它实际上并没有测试你的应用中的任何有意义的东西，所以一旦添加更多测试，你可能会删除它。

另外，`create-react-app`会在你的`package.json`文件中添加适当的脚本来运行你的测试。你可以在终端中运行以下命令：

```jsx
npm test
```

这实际上会调用`react-scripts`中的`test`脚本。这将调用 Jest，运行它找到的任何测试。在这种情况下，因为你正在使用一个新项目，它只会找到`create-react-app`创建的一个测试。运行这个测试的输出如下：

```jsx
PASS  src/App.test.js
 ![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/a021b99a-9dbe-4033-9351-6670f4a36ba6.png) renders without crashing (3ms)

Test Suites: 1 passed, 1 total
Tests:       1 passed, 1 total
Snapshots:   0 total
Time:        0.043s, estimated 1s
```

运行的测试位于`App.test.js`模块中——所有的 Jest 测试文件名中都应该包含`test`。一个好的约定是`ComponentName.test.js`。然后，你可以看到在这个模块中运行的测试列表，它们花费了多长时间，以及它们是否通过或失败。

在底部，Jest 打印出了运行的摘要信息。这通常是一个很好的起点，因为如果你的所有测试都通过了，你可能不会关心任何其他输出。另一方面，当一个测试失败时，信息越多越好。

`react-scripts`中的`test`脚本以观察模式调用 Jest。这意味着当文件发生更改时，你可以选择实际运行哪些测试。在命令行中，菜单看起来像这样：

```jsx
Watch Usage
 > Press a to run all tests.
 > Press p to filter by a filename regex pattern.
 > Press t to filter by a test name regex pattern.
 > Press q to quit watch mode.
 > Press Enter to trigger a test run. 
```

当 Jest 以观察模式运行时，进程不会在所有测试完成后立即退出。相反，它会监视你的测试和组件文件的更改，并在检测到更改时运行测试。这些选项允许你在发生更改时微调运行哪些测试。`p`和`t`选项只有在你有成千上万个测试并且其中许多测试失败时才有用。这些选项对于深入了解并找到正在开发的有问题的组件非常有用。

默认情况下，当 Jest 检测到更改时，只有相关的测试会被运行。例如，更改测试或组件将导致测试再次运行。在你的终端中运行`npm test`，让我们打开`App.test.js`并对测试进行小小的更改：

```jsx
it('renders without crashing', () => { 
  const div = document.createElement('div'); 
  ReactDOM.render(<App />, div); 
}); 
```

你可以只需更改测试的名称，使其看起来像下面这样，然后保存文件：

```jsx
it('renders the App component', () => { 
  const div = document.createElement('div'); 
  ReactDOM.render(<App />, div); 
}); 
```

现在，看一下你的终端，你在那里让 Jest 以观察模式运行：

```jsx
PASS  src/App.test.js
 ![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/a021b99a-9dbe-4033-9351-6670f4a36ba6.png) renders the App component (4ms)
```

Jest 检测到了你的单元测试的更改，并运行它，生成了更新的控制台输出。现在让我们引入一个新的组件和一个新的测试，看看会发生什么。首先，你将实现一个`Repeat`组件，看起来像下面这样：

```jsx
export default ({ times, value }) => 
  new Array(parseInt(times, 10))
    .fill(value)
    .join(' ');
```

这个组件接受一个`times`属性，用于确定重复`value`属性的次数。下面是`Repeat`组件被`App`组件使用的方式：

```jsx
import React, { Component } from 'react'; 
import logo from './logo.svg'; 
import './App.css'; 
import Repeat from './Repeat'; 

class App extends Component { 
  render() { 
    return ( 
      <div className="App"> 
        <header className="App-header"> 
          <img src={logo} className="App-logo" alt="logo" /> 
          <h1 className="App-title">Welcome to React</h1> 
        </header> 
        <p className="App-intro"> 
          <Repeat times="5" value="React!" /> 
        </p> 
      </div> 
    ); 
  } 
} 

export default App; 
```

如果你查看这个应用程序，你会在页面上看到字符串`React!`被渲染了五次。你的组件按预期工作，但在提交新组件之前，让我们确保添加一个单元测试。创建一个名为`Repeat.test.js`的文件，内容如下：

```jsx
import React from 'react'; 
import ReactDOM from 'react-dom'; 
import Repeat from './Repeat'; 

it('renders the Repeat component', () => { 
  const div = document.createElement('div'); 
  ReactDOM.render(<Repeat times="5" value="test" />, div); 
}); 
```

实际上，这是用于`App`组件的相同单元测试。它除了组件可以渲染而不触发某种错误之外，没有太多测试内容。现在 Jest 有两个组件测试要运行：一个是`App`，另一个是`Repeat`。如果你查看 Jest 的控制台输出，你会看到两个测试都被运行了：

```jsx
PASS  src/App.test.js
PASS  src/Repeat.test.js

Test Suites: 2 passed, 2 total
Tests:       2 passed, 2 total
Snapshots:   0 total
Time:        0.174s, estimated 1s
Ran all test suites related to changed files.
```

注意输出中的最后一行。Jest 的默认监视模式是查找尚未提交到源代码控制的文件，并已保存的文件。通过忽略已提交的组件和测试，你知道它们没有改变，因此运行这些测试是没有意义的。让我们尝试更改`Repeat`组件，看看会发生什么（实际上你不需要更改任何内容，只需保存文件就足以触发 Jest）：

```jsx
 PASS  src/App.test.js 
 PASS  src/Repeat.test.js 
```

为什么`App`测试会运行？它已经提交并且没有改变。问题在于，由于`App`依赖于`Repeat`，对`Repeat`组件的更改可能会导致`App`测试失败。

让我们引入另一个组件和测试，不过这次我们不会引入任何依赖导入新组件。创建一个`Text.js`文件，并保存以下组件实现：

```jsx
export default ({ children }) => children; 
```

这个`Text`组件只会渲染传递给它的任何子元素或文本。这是一个人为的组件，但这并不重要。现在让我们编写一个测试，验证组件返回预期的值：

```jsx
import Text from './text'; 

it('returns the correct text', () => {
  const children = 'test';
  expect(Text({ children })).toEqual(children);
});
```

`toEqual()`断言在`Text()`返回的值等于`children`值时通过。当你保存这个测试时，看一下 Jest 控制台输出：

```jsx
PASS  src/Text.test.js
 ![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/a021b99a-9dbe-4033-9351-6670f4a36ba6.png) returns the correct text (1ms)

Test Suites: 1 passed, 1 total
Tests:       1 passed, 1 total
```

现在你有一个没有任何依赖的测试，Jest 会自行运行它。其他两个测试已经提交到 Git，所以它知道这些测试不需要运行。你永远不会提交不能通过单元测试的东西，对吧？

现在让我们让这个测试失败，看看会发生什么。将`Test`组件更改为以下内容：

```jsx
export default ({ children }) => 1;
```

这将导致测试失败，因为它期望组件函数返回传递给`children`属性的值。现在如果你回到 Jest 控制台，输出应该是这样的：

```jsx
FAIL  src/Text.test.js
 ● returns the correct text

   expect(received).toEqual(expected)

   Expected value to equal:
     "test"
   Received:
     1

   Difference:

    Comparing two different types of values. Expected string but 
     received number.
```

测试失败了，正如你所知道的。有趣的是，这又是唯一运行的测试，因为根据 Git，没有其他东西发生变化。对你有利的是，一旦你有了数百个测试，你就不需要等待所有测试都运行完毕，才能运行当前正在工作的组件的失败测试。

# 使用独立的 Jest 运行测试

在前一节中你刚刚了解到的`react-scripts`中的`test`脚本是一个很好的工具，可以在你构建应用程序时在后台运行。它在你实现组件和单元测试时给出了即时的反馈。

其他时候，你只想运行所有的测试，并在打印结果输出后立即退出进程。例如，如果你正在将 Jest 输出集成到持续集成流程中，或者如果你只想看一次测试结果，你可以直接运行 Jest。

让我们尝试单独运行 Jest。确保你仍然在项目目录中，并且已经停止了`npm test`脚本的运行。现在只需运行：

```jsx
jest
```

与在观察模式下运行 Jest 不同，这个命令只是尝试运行所有的测试，打印结果输出，然后退出。然而，这种方法似乎存在问题。像这样运行 Jest 会导致错误：

```jsx
FAIL  src/Repeat.test.js
 ● Test suite failed to run

   04/my-react-app/src/Repeat.test.js: Unexpected token (7:18)
        5 | it('renders the Repeat component', () => {
        6 |   const div = document.createElement('div');
      > 7 |   ReactDOM.render(<Repeat times="5" value="test"...
          |                   ^
        8 | });
```

这是因为`react-scripts`中的`test`脚本为我们设置了很多东西，包括解析和执行 JSX 所需的所有 Jest 配置。鉴于我们有这个工具可用，让我们使用它，而不是试图从头开始配置 Jest。记住，你的目标是只运行一次 Jest，而不是在观察模式下运行。

事实证明，`react-scripts`中的`test`脚本已经准备好处理持续集成环境。如果它发现`CI`环境变量，它就不会在观察模式下运行 Jest。让我们尝试通过导出这个变量来验证一下：

```jsx
export CI=1
```

现在当你运行`npm test`时，一切都按预期进行。当一切都完成时，进程退出：

```jsx
PASS  src/Text.test.js
PASS  src/App.test.js
PASS  src/Repeat.test.js

Test Suites: 3 passed, 3 total
Tests:       3 passed, 3 total
Snapshots:   0 total
Time:        1.089s
Ran all test suites.
```

当你完成后，可以取消这个环境变量：

```jsx
unset CI 
```

大多数情况下，你可能只会在观察模式下使用 Jest。但是，如果你需要在短暂的进程中快速运行测试，你可以暂时进入持续集成模式。

# 编写 Jest 测试

现在你知道如何运行 Jest 了，让我们写一些单元测试。我们将涵盖 Jest 可用于测试 React 应用的基础知识以及更高级的功能。我们将开始将你的测试组织成套件，并介绍 Jest 中的基本断言。然后，你将创建你的第一个模拟模块并处理异步代码。最后，我们将使用 Jest 的快照机制来帮助测试 React 组件的输出。

# 使用套件组织测试

套件是你的测试的主要组织单元。套件不是 Jest 的要求——`create-react-app`创建的测试不包括套件：

```jsx
it('renders without crashing', () => { 
  ... 
}); 
```

`it()`函数声明了一个通过或失败的单元测试。当你刚开始项目并且只有少数测试时，不需要套件。一旦你有了多个测试，就是时候开始考虑组织了。把套件看作是一个容器，你可以把你的测试放进去。你可以有几个这样的容器，以你认为合适的方式组织你的测试。通常，一个套件对应一个源模块。以下是如何声明套件：

```jsx
describe('BasicSuite', () => { 
  it('passes the first test', () => { 
    // Assertions... 
  }); 

  it('passes the second test', () => { 
    // Assertions... 
  }); 
}); 
```

这里使用`describe()`函数声明了一个名为`BasicSuite`的测试套件。在套件内部，我们声明了几个单元测试。使用`describe()`，你可以组织你的测试，使相关的测试在测试结果输出中被分组在一起。

然而，如果套件是唯一可用于组织测试的机制，你的测试将很快变得难以管理。原因是通常一个类、方法或函数位于一个模块中会有多个测试。因此，你需要一种方法来说明测试实际上属于代码的哪一部分。好消息是你可以嵌套调用`describe()`来为你的套件提供必要的组织：

```jsx
describe('NestedSuite', () => { 
  describe('state', () => { 
    it('handles the first state', () => { 

    }); 

    it('handles the second state', () => { 

    }); 
  }); 

  describe('props', () => { 
    it('handles the first prop', () => { 

    });
 it('handles the second prop', () => { 

    }); 
  });

 describe('render()', () => { 
    it('renders with state', () => { 

    }); 

    it('renders with props', () => { 

    }); 
  }); 
}); 
```

最外层的`describe()`调用声明了测试套件，对应于一些顶层的代码单元，比如一个模块。对`describe()`的内部调用对应于更小的代码单元，比如方法和函数。这样，你可以轻松地为给定的代码片段编写多个单元测试，同时避免对实际被测试的内容产生困惑。

让我们来看一下你刚刚创建的测试套件的详细输出。为此，请运行以下命令：

```jsx
npm test -- --verbose
```

第一组双破折号告诉`npm`将后面的任何参数传递给`test`脚本。以下是你将看到的内容：

```jsx
PASS  src/NestedSuite.test.js
 NestedSuite
   state
     ![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/05ee9296-041a-4087-b809-ef2d86a9a6bb.png) handles the first state (1ms)
     ![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/05ee9296-041a-4087-b809-ef2d86a9a6bb.png) handles the second state
   props
     ![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/05ee9296-041a-4087-b809-ef2d86a9a6bb.png) handles the first prop
     ![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/05ee9296-041a-4087-b809-ef2d86a9a6bb.png) handles the second prop
   render()
     ![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/05ee9296-041a-4087-b809-ef2d86a9a6bb.png) renders with state
     ![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/05ee9296-041a-4087-b809-ef2d86a9a6bb.png) renders with props (1ms)

PASS  src/BasicSuite.test.js
 BasicSuite
   ![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/05ee9296-041a-4087-b809-ef2d86a9a6bb.png) passes the first test
   ![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/05ee9296-041a-4087-b809-ef2d86a9a6bb.png) passes the second test
```

在`NestedSuite`下，你可以看到`state`是被测试的代码，并且有两个测试通过了。`props`和`render()`也是一样的情况。

# 基本断言

在单元测试中，使用 Jest 的期望 API 创建断言。当代码的期望未达到时，这些函数会触发单元测试失败。使用此 API 时，测试失败的输出会显示您期望发生的事情以及实际发生的事情。这严重减少了您追踪值所花费的时间。

# 基本相等

您可以使用 `toBe()` 期望方法来断言两个值相同：

```jsx
describe('basic equality', () => { 
  it('true is true', () => { 
    expect(true).toBe(true); 
    expect(true).not.toBe(false); 
  }); 

  it('false is false', () => { 
    expect(false).toBe(false); 
    expect(false).not.toBe(true); 
  }); 
}); 
```

在第一个测试中，您期望 `true` 等于 `true`。然后，在下一行使用 `.not` 属性否定这个期望。如果这是一个真正的单元测试，您不必像这样证明您刚刚做出的断言的相反情况——我这样做是为了说明您的一些选择。

在第二个测试中，我们执行相同的断言，但期望值为 `false`。`toBe()` 方法使用严格相等来比较其值。

# 近似相等

有时，在代码中检查某些东西的确切值并没有什么区别，而且可能比值得的工作更多。例如，您可能只需要确保某个值存在。您可能还需要执行相反的操作——确保没有值。在 JavaScript 术语中，某物与无物是“真值”与“假值”。

要在 Jest 单元测试中检查真值或假值，您将分别使用 `isTruthy()` 或 `isFalsy()` 方法：

```jsx
describe('approximate equality', () => { 
  it('1 is truthy', () => { 
    expect(1).toBeTruthy(); 
    expect(1).not.toBeFalsy(); 
  }); 

  it('\'\' is falsy', () => { 
    expect('').toBeFalsy(); 
    expect('').not.toBeTruthy(); 
  }); 
});
```

值 `1` 不是 true，但在布尔比较的上下文中使用时，它会计算为 `true`。同样，空字符串计算为 `false`，因此被视为假值。

# 值相等

在处理对象和数组时，检查相等可能很痛苦。通常您不能使用严格相等，因为您在比较引用，而引用总是不同的。如果您要比较的是值，您需要逐个迭代对象或集合并比较值、键和索引。

由于没有人在理智的头脑中想要做所有这些工作来执行简单的测试。Jest 提供了 `toEqual()` 方法，它可以为您比较对象属性和数组值：

```jsx
describe('value equality', () => { 
  it('objects are the same', () => { 
    expect({ 
      one: 1, 
      two: 2 
    }).toEqual({ 
      one: 1, 
      two: 2, 
    });

    expect({ 
      one: 1, 
      two: 2 
    }).not.toBe({ 
      one: 1, 
      two: 2
 }); 
  }); 

  it('arrays are the same', () => { 
    expect([1, 2]).toEqual([1, 2]); 
    expect([1, 2]).not.toBe([1, 2]); 
  }); 
}); 
```

这个例子中的每个对象和数组都是唯一的引用。然而，这两个对象和两个数组在其属性和值方面是相等的。`toEqual()` 方法检查值的相等性。之后，我要展示 `toBe()` 不是你想要的——这会返回 `false`，因为它在比较引用。

# 集合中的值

Jest 中有比我在这本书中介绍的断言方法更多。我鼓励你查看 Jest API 文档中的 *Expect* 部分：[`facebook.github.io/jest/docs/en/expect.html`](https://facebook.github.io/jest/docs/en/expect.html)。

我想要和你讨论的最后两个断言方法是 `toHaveProperty()` 和 `toContain()`。前者测试对象是否具有给定属性，而后者检查数组是否包含给定值：

```jsx
describe('object properties and array values', () => { 
  it('object has property value', () => { 
    expect({ 
      one: 1, 
      two: 2 
    }).toHaveProperty('two', 2); 

    expect({ 
      one: 1, 
      two: 2 
    }).not.toHaveProperty('two', 3); 
  });
  it('array contains value', () => { 
    expect([1, 2]).toContain(1); 
    expect([1, 2]).not.toContain(3); 
  }); 
}); 
```

当你需要检查对象是否具有特定属性值时，`toHaveProperty()` 方法非常有用。当你需要检查数组是否具有特定值时，`toContain()` 方法非常有用。

# 使用模拟

当你编写单元测试时，你是在测试自己的代码。至少这是理论上的想法。实际上，这比听起来更困难，因为你的代码不可避免地会使用某种库。这是你不想测试的代码。编写调用其他库的单元测试的问题在于它们通常需要访问网络或文件系统。你绝对不希望由于其他库的副作用而产生误报。

Jest 提供了一个强大的模拟机制，使用起来很容易。你给 Jest 提供要模拟的模块的路径，它会处理剩下的事情。在某些情况下，你不需要提供模拟实现。在其他情况下，你需要以与原始模块相同的方式处理参数和返回值。

假设你创建了一个如下所示的 `readFile()` 函数：

```jsx
import fs from 'fs'; 

const readFile = path => new Promise((resolve, reject) => { 
  fs.readFile(path, (err, data) => { 
    if (err) { 
      reject(err); 
    } else { 
      resolve(data); 
    } 
  }); 
}); 

export default readFile; 
```

这个函数需要来自 `fs` 模块的 `readFile()` 函数。它返回一个 promise，在传递给 `readFile()` 的回调函数被调用时解析，除非出现错误。

现在你想为这个函数编写一个单元测试。你想做出如下断言：

+   它是否调用了 `fs.readFile()`？

+   返回的 promise 是否以正确的值解析？

+   当传递给 `fs.readFile()` 的回调接收到错误时，返回的 promise 是否被拒绝？

您可以通过使用 Jest 对其进行模拟来执行所有这些断言，而不必依赖于`fs.readFile()`的实际实现。您不必对外部因素做任何假设；您只关心您的代码是否按照您的预期工作。

因此，让我们尝试为使用模拟的`fs.readFile()`实现的此函数实施一些测试：

```jsx
import fs from 'fs'; 
import readFile from './readFile'; 

jest.mock('fs'); 

describe('readFile', () => { 
  it('calls fs.readFile', (done) => { 
    fs.readFile.mockReset(); 
    fs.readFile.mockImplementation((path, cb) => { 
      cb(false); 
    }); 

    readFile('file.txt') 
      .then(() => { 
        expect(fs.readFile).toHaveBeenCalled(); 
        done(); 
      }); 
  }); 

  it('resolves a value', (done) => { 
    fs.readFile.mockReset(); 
    fs.readFile.mockImplementation((path, cb) => { 
      cb(false, 'test'); 
    }); 

    readFile('file.txt') 
      .then((data) => { 
        expect(data).toBe('test'); 
        done(); 
      }); 
  }); 

  it('rejects on error', (done) => { 
    fs.readFile.mockReset(); 
    fs.readFile.mockImplementation((path, cb) => { 
      cb('failed'); 
    }); 

    readFile() 
      .catch((err) => { 
        expect(err).toBe('failed'); 
        done(); 
      }); 
  }); 
}); 
```

通过调用`jest.mock('fs')`来创建`fs`模块的模拟版本。请注意，在模拟之前实际导入了真实的`fs`模块，并且在任何测试实际使用它之前就已经模拟了它。在每个测试中，我们都在创建`fs.readFile()`的自定义实现。默认情况下，Jest 模拟的函数实际上不会执行任何操作。这很少足以测试大多数事情。模拟的美妙之处在于您可以控制代码使用的库的结果，并且您的测试断言确保您的代码相应地处理一切。

通过将其作为函数传递给`mockImplementation()`方法来提供实现。但在这样做之前，一定要确保调用`mockReset()`来清除有关模拟的任何存储信息，比如它被调用的次数。例如，第一个测试有断言`expect(fs.readFile).toHaveBeenCalled()`。您可以将模拟函数传递给`expect()`，Jest 提供了知道如何与它们一起工作的方法。

对于类似的功能，可以遵循相同的模式。这是`readFile()`的对应函数：

```jsx
import fs from 'fs'; 

const writeFile = (path, data) => new Promise((resolve, reject) => { 
  fs.writeFile(path, data, (err) => { 
    if (err) { 
      reject(err); 
    } else { 
      resolve(); 
    } 
  }); 
}); 

export default writeFile; 
```

`readFile()`和`writeFile()`之间有两个重要的区别：

+   `writeFile()`函数接受第二个参数，用于写入文件的数据。这个参数也传递给`fs.writeFile()`。

+   `writeFile()`函数不会解析值，而`readFile()`会解析已读取的文件数据。

这两个差异对您创建的模拟实现有影响。现在让我们来看看它们：

```jsx
import fs from 'fs'; 
import writeFile from './writeFile'; 

jest.mock('fs'); 

describe('writeFile', () => { 
  it('calls fs.writeFile', (done) => { 
    fs.writeFile.mockReset(); 
    fs.writeFile.mockImplementation((path, data, cb) => { 
      cb(false); 
    }); 

    writeFile('file.txt') 
      .then(() => { 
        expect(fs.writeFile).toHaveBeenCalled(); 
        done(); 
      }); 
  }); 

  it('resolves without a value', (done) => { 
    fs.writeFile.mockReset(); 
    fs.writeFile.mockImplementation((path, data, cb) => { 
      cb(false, 'test'); 
    }); 

    writeFile('file.txt', test) 
      .then(() => { 
        done(); 
      }); 
  }); 

  it('rejects on error', (done) => { 
    fs.writeFile.mockReset(); 
    fs.writeFile.mockImplementation((path, data, cb) => { 
      cb('failed'); 
    });
 writeFile() 
      .catch((err) => { 
        expect(err).toBe('failed'); 
        done(); 
      }); 
  }); 
}); 
```

现在`data`参数需要成为模拟实现的一部分；否则，将无法访问`cb`参数并调用回调函数。

在`readFile()`和`writeFile()`测试中，您必须处理异步性。这就是为什么我们在`then()`回调中执行断言的原因。从`it()`传入的`done()`函数在测试完成时被调用。如果您忘记调用`done()`，测试将挂起并最终超时和失败。

# 单元测试覆盖率

Jest 自带对测试覆盖报告的支持。将这包含在测试框架中是很好的，因为并非所有测试框架都支持这一点。如果你想看看你的测试覆盖率是什么样子，只需在启动 Jest 时传递 `--coverage` 选项即可：

```jsx
npm test -- --coverage 
```

当你这样做时，测试会像平常一样运行。然后，Jest 内部的覆盖工具会计算你的测试覆盖源代码的程度，并生成一个报告，看起来像这样：

```jsx
----------|--------|----------|---------|---------|----------------|
File      |% Stmts | % Branch | % Funcs | % Lines |Uncovered Lines |
----------|--------|----------|---------|---------|----------------|
All files |   2.17 |        0 |    6.25 |    4.55 |                |
 App.js   |    100 |      100 |     100 |     100 |                |
 index.js |      0 |        0 |       0 |       0 |  1,2,3,4,5,7,8 |
----------|--------|----------|---------|---------|----------------|
```

如果你想提高你的覆盖率，看看报告中的 `Uncovered Lines` 列。其他列告诉你测试覆盖的代码类型：语句、分支和函数。

# 异步断言

Jest 预期你会有异步代码需要测试。这就是为什么它提供了 API 来使编写单元测试中的这一方面感觉自然。在前一节中，我们编写了在 `then()` 回调中执行断言并在所有异步测试完成时调用 `done()` 的测试。在本节中，我们将看另一种方法。

Jest 允许你从单元测试函数中返回 promise 期望，并会相应地处理它们。让我们重构一下你在前一节中编写的 `readFile()` 测试：

```jsx
import fs from 'fs'; 
import readFile from './readFile'; 

jest.mock('fs'); 

describe('readFile', () => { 
  it('calls fs.readFile', () => { 
    fs.readFile.mockReset(); 
    fs.readFile.mockImplementation((path, cb) => { 
      cb(false); 
    });
return readFile('file.txt') 
      .then(() => { 
        expect(fs.readFile).toHaveBeenCalled(); 
      }); 
  }); 

  it('resolves a value', () => { 
    fs.readFile.mockReset(); 
    fs.readFile.mockImplementation((path, cb) => { 
      cb(false, 'test'); 
    }); 

    return expect(readFile('file.txt')) 
      .resolves 
      .toBe('test'); 
  }); 

  it('rejects on error', () => { 
    fs.readFile.mockReset(); 
    fs.readFile.mockImplementation((path, cb) => { 
      cb('failed'); 
    }); 

    return expect(readFile()) 
      .rejects 
      .toBe('failed'); 
  }); 
}); 
```

现在测试返回的是 promises。当返回一个 promise 时，Jest 会等待它解析完成，然后才捕获测试结果。你也可以传递一个 promise 给 `expect()`，并使用 `resolves` 和 `rejects` 对象来执行断言。这样，你就不必依赖 `done()` 函数来指示测试的异步部分已经完成了。

`rejects` 对象在这里特别有价值。确保函数按预期拒绝是很重要的。但如果没有 `rejects`，这是不可能做到的。在这个测试的先前版本中，如果你的代码因某种原因解析了，而本应拒绝，那就无法检测到这一点。现在，如果发生这种情况，使用 `rejects` 会导致测试失败。

# React 组件快照

React 组件会渲染输出。自然地，你希望组件单元测试的一部分是确保正确的输出被创建。一种方法是将组件渲染到基于 JS 的 DOM 中，然后对渲染输出执行单独的断言。至少可以说，这将是一个痛苦的测试编写体验。

快照测试允许你生成渲染组件输出的*快照*。然后，每次运行测试时，输出会与快照进行比较。如果有什么看起来不同，测试就会失败。

让我们修改`create-react-app`为你添加的`App`组件的默认测试，使其使用快照测试。这是原始测试的样子：

```jsx
import React from 'react'; 
import ReactDOM from 'react-dom'; 
import App from './App'; 

it('renders without crashing', () => { 
  const div = document.createElement('div'); 
  ReactDOM.render(<App />, div); 
}); 
```

这个测试实际上并没有验证渲染的内容——只是没有抛出错误。如果你做出了导致意外结果的更改，你将永远不会知道。这是相同测试的快照版本：

```jsx
import React from 'react'; 
import renderer from 'react-test-renderer'; 
import App from './App'; 

it('renders without crashing', () => { 
  const tree = renderer 
    .create(<App />) 
    .toJSON(); 

  expect(tree).toMatchSnapshot(); 
}); 
```

在运行这个测试之前，我必须安装`react-test-renderer`包：

```jsx
npm install react-test-renderer --save-dev
```

也许有一天这将被添加到`create-react-app`中。与此同时，你需要记得安装它。然后，你的测试可以导入测试渲染器并使用它来创建一个 JSON 树。这是渲染组件内容的表示。接下来，你期望这个树与第一次运行此测试时创建的快照匹配，使用`toMatchSnapshot()`断言。

这意味着第一次运行测试时，它总是会通过，因为这是第一次创建快照。快照文件是应该提交到项目的源代码控制系统的工件，就像单元测试源代码本身一样。这样，项目中的其他人在运行你的测试时就会有一个快照文件可供使用。

关于快照测试的误解在于它给人的印象是你实际上不能改变组件以产生不同的输出。事实上，这是真的——改变组件产生的输出会导致快照测试失败。不过，这并不是一件坏事，因为它迫使你在每次更改时查看你的组件渲染的内容。

让我们修改`App`组件，使其对单词`started`添加强调。

```jsx
<p className="App-intro"> 
  To get <em>started</em>, edit <code>src/App.js</code> and save to  
  reload. 
</p> 
```

现在如果你运行你的测试，你会得到一个类似这样的失败：

```jsx
Received value does not match stored snapshot 1\. 

- Snapshot 
+ Received 

 @@ -16,11 +16,15 @@ 
    </h1> 
    </header> 
    <p 
       className="App-intro" 
    > 
-    To get started, edit  
+    To get  
+    <em> 
+      started 
+    </em> 
+    , edit  
```

哇！这很有用。统一的差异显示了组件输出的确切变化。你可以查看这个输出，并决定这正是你期望看到的变化，或者你犯了一个错误，需要去修复它。一旦你对新的输出满意，你可以通过向`test`脚本传递参数来更新存储的快照：

```jsx
npm test -- --updateSnapshot
```

这将在运行测试之前更新存储的快照，任何失败的快照测试现在都将通过，因为它们符合其输出期望：

```jsx
PASS  src/App.test.js
 ![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/a3323890-90b8-4d05-a479-d8046e057b2d.png) renders without crashing (12ms)

Snapshot Summary
 > 1 snapshot updated in 1 test suite.

 Test Suites: 1 passed, 1 total
 Tests:       1 passed, 1 total
 Snapshots:   1 updated, 1 total
 Time:        0.631s, estimated 1s 
```

Jest 告诉您在运行任何测试之前快照已更新，通过传递`--updateSnapshot`参数来实现。

# 总结

在本章中，您了解了 Jest。您了解到 Jest 的关键驱动原则是创建有效的模拟、测试隔离和并行执行，以及易用性。然后，您了解到`react-scripts`通过提供一些基本配置使运行单元测试变得更加容易。

在运行 Jest 时，您会发现通过`react-scripts`运行 Jest 时，观察模式是默认模式。观察模式在有许多不需要在每次源代码更改时运行的测试时特别有用，只有相关的测试会被执行。

接下来，您在单元测试中执行了一些基本断言。然后，您为`fs`模块创建了一个模拟，并对模拟函数进行断言，以确保它们被预期使用。然后，您进一步发展了这些测试，以利用 Jest 的固有异步能力。单元测试覆盖报告内置在 Jest 中，您学会了如何通过传递额外的参数来查看此报告。

在下一章中，您将学习如何使用 Flow 创建类型安全的组件。


# 第五章：使用类型安全简化开发和重构 React 组件

本章重点介绍的工具是 Flow，它是 JavaScript 应用程序的静态类型检查器。Flow 的范围和你可以用它做的事情是巨大的，所以我将在引入 Flow 的上下文中介绍它，这是一个用于改进 React 组件的工具。在本章中，你将学到以下内容：

+   通过引入类型安全解决的问题

+   在你的 React 项目中启用 Flow

+   使用 Flow 验证你的 React 组件

+   使用类型安全增强 React 开发的其他方法

# 类型安全解决了什么问题？

类型安全并非万能药。例如，我完全有能力编写一个充满错误的类型安全应用程序。有趣的是，只是在引入类型检查器后，那种停止发生的错误。那么在引入 Flow 这样的工具后，你可以期待什么类型的事情？我将分享我在学习 Flow 时经历的三个因素。Flow 文档中的*类型系统*部分对这个主题进行了更详细的介绍，可在[`flow.org/en/docs/lang/`](https://flow.org/en/docs/lang/)上找到。

# 用保证替换猜测

JavaScript 这样的动态类型语言的一个很好的特性是，你可以编写代码而不必考虑类型。类型是好的，它们确实解决了很多问题——你可能不相信，但有时你需要能够只是编写代码而不必正式验证正确性。换句话说，有时候猜测恰恰是你需要的。

如果我正在编写一个我知道接受一个对象作为参数的函数，我可以假设传递给我的函数的任何对象都将具有预期的属性。这使我能够实现我需要的东西，而不必确保正确的类型作为参数传递。然而，这种方法只能持续那么长时间。因为不可避免地，你的代码将会得到一些意外的输入。一旦你有了一个由许多组成部分组成的复杂应用程序，类型安全可以消除猜测。

Flow 采取了一种有趣的方法。它不是基于类型编译新的 JavaScript 代码，而是简单地根据类型注释检查源代码是否正确。然后将这些注释从源代码中移除，以便可以运行。通过使用 Flow 这样的类型检查器，你可以明确地指定每个组件愿意接受的输入，并通过使用类型注释来说明它与应用程序的其他部分是如何交互的。

# 移除运行时检查

在诸如 JavaScript 之类的动态语言中处理未知类型的数据的解决方案是在运行时检查值。根据值的类型，你可能需要执行一些替代操作来获取你的代码所期望的值。例如，在 JavaScript 中的一个常见习惯是确保一个值既不是 undefined 也不是 null。如果是，那么我们要么抛出一个错误，要么提供一个默认值。

当你执行运行时检查时，它会改变你对代码的思考方式。一旦你开始执行这些检查，它们不可避免地会演变成更复杂的检查和更多的检查。这种思维方式实际上意味着不相信自己或他人能够使用正确的数据调用代码。你会认为，由于很可能你的函数会被用垃圾参数调用，你需要准备好处理任何被传递给你的函数的东西。

另一方面，拥抱类型安全意味着你不必依赖于实现自定义解决方案来防御错误数据。让类型系统来代替你处理这个问题。你只需要考虑你的代码需要处理什么类型的数据，然后从那里开始。思考我的代码需要什么，而不是如何获得我的代码需要的东西。

# 明显的低严重性错误

如果你可以使用诸如 Flow 之类的类型检查器来消除由于错误类型而产生的隐匿错误，那么你将只剩下高级别的应用程序错误。当这些错误发生时，它们是显而易见的，因为应用程序是错误的。它产生了错误的输出，计算出了错误的数字，其中一个屏幕无法加载，等等。你可以更容易地看到并与这些类型的错误进行交互。这使它们变得显而易见，而当错误显而易见时，它们更容易被追踪和修复。

另一方面，您可能会遇到微妙错误的错误。这些可能是由于错误的类型。这些类型的错误特别可怕的原因是您甚至不知道出了什么问题。您的应用程序可能有些微妙的问题。或者它可能完全崩溃，因为您的代码的一部分期望一个数组，但它在某些地方可以工作，因为它得到了另一种可迭代的东西，但在其他地方却不行。

如果您只是使用类型注释并使用 Flow 检查了您的源代码，它会告诉您正在传递的不是数组。当类型静态检查时，这些类型的错误就没有了容身之地。原来，这些通常是更难解决的错误。

# 安装和初始化 Flow

在您开始实现类型安全的 React 组件之前，您需要安装和初始化 Flow。我将向您展示如何在`create-react-app`环境中完成此操作，但几乎可以为几乎任何 React 环境遵循相同的步骤。

您可以全局安装 Flow，但我建议将其与项目依赖的所有其他软件包一起本地安装。除非有充分的理由全局安装某些东西，否则请将其本地安装。这样，安装您的应用程序的任何人都可以通过运行`npm install`来获取每个依赖项。

在本地安装 Flow，请运行以下命令：

```jsx
npm install flow-bin --save-dev
```

这将在本地安装 Flow 可执行文件到您的项目，并将更新您的`package.json`，以便 Flow 作为项目的依赖项安装。现在让我们向`package.json`添加一个新的命令，以便您可以针对您的源代码运行 Flow 类型检查器。使`scripts`部分看起来像这样：

```jsx
"scripts": { 
  "start": "react-scripts start",
```

```jsx
  "build": "react-scripts build", 
  "test": "react-scripts test --env=jsdom", 
  "eject": "react-scripts eject", 
  "flow": "flow" 
}, 
```

现在，您可以通过在终端中执行以下命令来运行 Flow：

```jsx
npm run flow
```

这将按预期运行`flow`脚本，但 Flow 将抱怨找不到 Flow 配置文件：

```jsx
Could not find a .flowconfig in . or any of its parent directories. 
```

解决此问题的最简单方法是使用`flow init`命令：

```jsx
npm run flow init 
```

这将在您的项目目录中创建一个`.flowconfig`文件。您现在不需要担心更改此文件中的任何内容；只是 Flow 希望它存在。现在当您运行`npm run flow`时，您应该会收到一条指示没有错误的消息：

```jsx
Launching Flow server for 05/installing-and-initializing-flow
Spawned flow server (pid=46516)
No errors!  
```

原来，实际上没有检查您的任何源文件。这是因为默认情况下，Flow 只检查具有`// @flow`指令作为其第一行的文件。让我们继续在`App.js`的顶部添加这一行：

```jsx
// @flow 
import React, { Component } from 'react'; 
import logo from './logo.svg'; 
import './App.css'; 

class App extends Component { 
  render() { 
    return ( 
      <div className="App"> 
        <header className="App-header"> 
          <img src={logo} className="App-logo" alt="logo" /> 
          <h1 className="App-title">Welcome to React</h1> 
        </header> 
        <p className="App-intro"> 
          To get started... 
```

```jsx
        </p> 
      </div> 
    ); 
  } 
} 

export default App; 
```

现在 Flow 正在检查这个模块，我们得到了一个错误：

```jsx
      6: class App extends Component {
                           ^^^^^^^^^ Component. Too few type arguments. Expected at least 1
```

这是什么意思？Flow 试图在错误输出的下一行提供解释：

```jsx
Component<Props, State = void> { 
          ^^^^^^^^^^^^ See type parameters of definition here. 
```

Flow 抱怨你正在用`App`扩展的`Component`类。这意味着你需要为`Component`提供至少一个`type`参数来表示 props。由于`App`实际上并没有使用任何 props，现在可以暂时使用一个空类型：

```jsx
// @flow 
import React, { Component } from 'react'; 
import logo from './logo.svg'; 
import './App.css'; 

type Props = {}; 

class App extends Component<Props> { 
  render() { 
    return ( 
      <div className="App"> 
        <header className="App-header"> 
          <img src={logo} className="App-logo" alt="logo" /> 
          <h1 className="App-title">Welcome to React</h1> 
        </header> 
        <p className="App-intro"> 
          To get started... 
        </p> 
      </div> 
    ); 
  } 
}
export default App; 
```

现在当你再次运行 Flow 时，在`App.js`中就没有任何错误了！这意味着你已经成功地用类型信息注释了你的模块，Flow 用它来静态分析你的源代码，确保一切都是正确的。

那么 Flow 是如何知道 React 的`Component`类在泛型方面期望什么的呢？事实证明，React 本身是 Flow 类型注释的，这就是当 Flow 检测到问题时你会得到具体错误消息的原因。

接下来，让我们在`index.js`的顶部添加`// @flow`指令：

```jsx
// @flow 
import React from 'react'; 
import ReactDOM from 'react-dom'; 
import './index.css'; 
import App from './App'; 
import registerServiceWorker from './registerServiceWorker'; 

const root = document.getElementById('root'); 

ReactDOM.render( 
  <App />, 
  root 
); 

registerServiceWorker(); 
```

如果你再次运行`npm run flow`，你会看到以下错误：

```jsx
    Error: src/index.js:12
     12:   root
    ^^^^ null. This type is incompatible with the expected param 
                type of Element  
```

这是因为`root`的值来自`document.getElementById('root')`。由于这个方法没有返回元素的 DOM，Flow 检测到一个`null`值并抱怨。由于这是一个合理的担忧（`root`元素可能不存在），我们需要在没有元素时为 Flow 提供路径，你可以添加一些逻辑来处理这种情况：

```jsx
// @flow 
import React from 'react'; 
import ReactDOM from 'react-dom'; 
import './index.css'; 
import App from './App';
import registerServiceWorker from './registerServiceWorker'; 

const root = document.getElementById('root'); 

if (!(root instanceof Element)) { 
  throw 'Invalid root'; 
} 

ReactDOM.render( 
  <App />, 
  root 
); 

registerServiceWorker(); 
```

在调用`ReactDOM.render()`之前，你可以手动检查`root`的类型，以确保它是 Flow 期望看到的类型。现在当你运行`npm run flow`时，就不会有错误了。

你已经准备好了！你已经在本地安装和配置了 Flow，并且`create-react-app`的初始源已经通过了类型检查。现在你可以继续开发类型安全的 React 组件了。

# 验证组件属性和状态

React 设计时考虑了 Flow 静态类型检查。在 React 应用程序中，Flow 最常见的用途是验证组件属性和状态是否被正确使用。你还可以强制执行作为另一个组件子元素的组件的类型。

在 Flow 之前，React 依赖于 prop-types 机制来验证传递给组件的值。现在这是 React 的一个单独包，你仍然可以使用它。Flow 比 prop-types 更优秀，因为它执行静态检查，而 prop-types 执行运行时验证。这意味着你的应用程序在运行时不需要运行多余的代码。

# 原始属性值

通过 props 传递给组件的最常见的值类型是原始值——例如字符串、数字和布尔值。使用 Flow，您可以声明自己的类型，指定给定属性允许哪些原始值。

让我们看一个例子：

```jsx
// @flow 
import React from 'react'; 

type Props = { 
  name: string, 
  version: number 
}; 

const Intro = ({ name, version }: Props) => ( 
  <p className="App-intro"> 
    <strong>{name}:</strong>{version} 
  </p> 
); 

export default Intro; 
```

这个组件渲染了一些应用程序的名称和版本。这些值是通过属性值传递的。对于这个组件，让我们说您只想要`name`属性的字符串值和`version`属性的数字值。这个模块使用`type`关键字声明了一个新的`Props`类型：

```jsx
type Props = { 
  name: string, 
  version: number 
}; 
```

这个 Flow 语法允许您创建新类型，然后可以用来对函数参数进行类型化。在这种情况下，您有一个功能性的 React 组件，其中 props 作为第一个参数传递。这是告诉 Flow，props 对象应该具有特定类型的地方：

```jsx
({ name, version }: Props) => (...) 
```

有了这个，Flow 可以找出我们传递无效的属性类型到这个组件的任何地方！更好的是，这是在静态地完成的，在浏览器中运行任何东西之前。在 Flow 之前，您必须使用`prop-types`包在运行时验证组件属性。

让我们使用这个组件，然后我们将运行 Flow。这是`App.js`使用`Intro`组件：

```jsx
// @flow 
import React, { Component } from 'react'; 
import logo from './logo.svg'; 
import './App.css'; 
import Intro from './Intro';

type Props = {}; 

class App extends Component<Props> { 
  render() { 
    return ( 
      <div className="App"> 
        <header className="App-header"> 
          <img src={logo} className="App-logo" alt="logo" /> 
          <h1 className="App-title">Welcome to React</h1> 
        </header> 
        <Intro name="React" version={16} /> 
      </div> 
    ); 
  } 
} 

export default App; 
```

传递给`Intro`的属性值符合`Props`类型的期望：

```jsx
<Intro name="React" version={16} /> 
```

您可以通过运行`npm run flow`来验证这一点。您应该会看到`没有错误！`作为输出。让我们看看如果我们改变这些属性的类型会发生什么：

```jsx
<Intro version="React" name={16} /> 
```

现在我们正在传递一个字符串，而期望的是一个数字，以及一个数字，而期望的是一个字符串。如果您再次运行`npm run flow`，您应该会看到以下错误：

```jsx
    Error: src/App.js:17
     17:         <Intro version="React" name={16} />
                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ props of React element `Intro`. This type is incompatible with
      9: const Intro = ({ name, version }: Props) => (
                                           ^^^^^ object type. See: src/Intro.js:9
      Property `name` is incompatible:
         17:         <Intro version="React" name={16} />
                                                  ^^ number. This type is incompatible with
          5:   name: string,
                     ^^^^^^ string. See: src/Intro.js:5

    Error: src/App.js:17
```

```jsx
     17:         <Intro version="React" name={16} />
                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ props of React element `Intro`. This type is incompatible with
```

```jsx
      9: const Intro = ({ name, version }: Props) => (
                                           ^^^^^ object type. See: src/Intro.js:9
      Property `version` is incompatible:
         17:         <Intro version="React" name={16} />
                                    ^^^^^^^ string. This type is incompatible with
          6:   version: number
                        ^^^^^^ number. See: src/Intro.js:6

```

这两个错误都非常详细地向您展示了问题所在。它首先向您展示了组件属性值被传递的地方：

```jsx
    <Intro version="React" name={16} />
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ props of React element `Intro`. 

```

然后，它向您展示了`Props`类型被用来声明属性参数的类型：

```jsx
    This type is incompatible with
      9: const Intro = ({ name, version }: Props) => (
                                           ^^^^^ object type. See: src/Intro.js:9

```

最后，它向您展示了类型的确切问题是什么：

```jsx
    Property `name` is incompatible:
         17:         <Intro version="React" name={16} />
                                                  ^^ number. This type is incompatible with
          5:   name: string,
                     ^^^^^^ string. See: src/Intro.js:5

```

流错误消息试图为您提供尽可能多的信息，这意味着您花费的时间更少，寻找文件。

# 对象属性值

在前面的部分，您学会了如何检查原始属性类型。React 组件也可以接受具有原始值和其他对象的对象。如果您的组件期望一个对象作为属性值，您可以使用与原始值相同的方法。不同之处在于您如何构造`Props`类型声明：

```jsx
// @flow 
import React from 'react'; 

type Props = { 
  person: { 
    name: string, 
    age: number 
  } 
}; 

const Person = ({ person }: Props) => ( 
  <section> 
    <h3>Person</h3> 
    <p><strong>Name: </strong>{person.name}</p> 
    <p><strong>Age: </strong>{person.age}</p> 
  </section> 
); 

export default Person; 
```

此组件期望一个`person`属性，它是一个对象。此外，它期望此对象具有一个`name`字符串属性和一个数字`age`属性。实际上，如果您有其他需要`person`属性的组件，您可以将此类型分解为可重用的部分：

```jsx
type Person = { 
  name: string, 
  age: number 
}; 

type Props = { 
  person: Person 
}; 
```

现在让我们看看作为属性传递给此组件的值：

```jsx
// @flow 
import React, { Component } from 'react'; 
import logo from './logo.svg'; 
import './App.css'; 
import Person from './Person'; 

class App extends Component<{}> { 
  render() { 
    return ( 
      <div className="App"> 
        <header className="App-header"> 
          <img src={logo} className="App-logo" alt="logo" /> 
          <h1 className="App-title">Welcome to React</h1> 
        </header> 
        <Person person={{ name: 'Roger', age: 20 }} /> 
      </div> 
    ); 
  } 
} 

export default App; 
```

而不是将`Person`组件传递给几个属性值，它被传递了一个单一的属性值，一个符合`Props`类型期望的对象。如果不符合，Flow 会抱怨。让我们试着从这个对象中删除一个属性：

```jsx
<Person person={{ name: 'Roger' }} /> 
```

现在当您运行`npm run flow`时，它会抱怨传递给`person`的对象的缺少属性：

```jsx
    15:         <Person person={{ name: 'Roger' }} />
                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ props of React element `Person`. This type is incompatible with
     11: const Person = ({ person }: Props) => (
                                     ^^^^^ object type. See: src/Person.js:11
      Property `person` is incompatible:
         15:         <Person person={{ name: 'Roger' }} />
                                     ^^^^^^^^^^^^^^^^^ object literal. This type is incompatible with
                       v
          5:   person: {
          6:     name: string,
          7:     age: number
```

```jsx
          8:   }
               ^ object type. See: src/Person.js:5
          Property `age` is incompatible:
                           v
              5:   person: {
              6:     name: string,
              7:     age: number
              8:   }
                   ^ property `age`. Property not found in. See: src/Person.js:5
             15:         <Person person={{ name: 'Roger' }} />
                                         ^^^^^^^^^^^^^^^^^ object literal

```

无论您如何奇特地使用属性值，Flow 都可以弄清楚您是否在错误使用它们。尝试在运行时使用诸如`prop-types`之类的东西来实现相同的功能最多是麻烦的。

# 验证组件状态

您可以通过对传递给组件的 props 参数进行类型化来验证功能性 React 组件的属性。您的一些组件将具有状态，您可以验证组件的状态与属性的方式大致相同。您可以创建一个表示组件状态的类型，并将其作为类型参数传递给`Component`。

让我们看一个包含由子组件使用和操作的状态的容器组件：

```jsx
// @flow 
import React, { Component } from 'react'; 
import Child from './Child'; 

type State = { 
  on: boolean 
}; 

class Container extends Component<{}, State> { 
  state = { 
    on: false 
  } 

  toggle = () => { 
    this.setState(state => ({ 
      on: !state.on 
    }));
```

```jsx
  } 

  render() { 
    return ( 
      <Child 
        on={this.state.on} 
        toggle={this.toggle} 
      />); 
  } 
} 

export default Container; 
```

由`Container`渲染的`Child`组件需要一个`on`布尔属性和一个`toggle`函数。`Child`传递给的“toggle（）”方法将改变`Container`的状态。这意味着`Child`可以调用此函数以改变其父级的状态。在模块顶部，在组件类的上方，有一个`State`类型，用于指定允许设置为状态的值。在这种情况下，状态只是一个简单的`on`布尔值：

```jsx
type State = { 
  on: boolean 
}; 
```

然后在扩展时将此类型作为类型参数传递给`Component`：

```jsx
class Container extends Component<{}, State> { 
  ... 
} 
```

通过将此类型参数传递给`Component`，您可以随意设置组件状态。例如，`Child`组件调用“toggle（）”方法来改变`Container`组件的状态。如果此调用设置状态不正确，Flow 将检测到并抱怨。让我们更改“toggle（）”实现，使其通过将状态设置为与 Flow 不一致的内容而失败：

```jsx
toggle = () => { 
  this.setState(state => ({ 
    on: !state.on + 1 
  })); 
} 
```

您将收到以下错误：

```jsx
    Error: src/Container.js:16
     16:       on: !state.on + 1
                   ^^^^^^^^^^^^^ number. This type is incompatible with
      6:   on: boolean
               ^^^^^^^ boolean
```

在开发过程中错误地设置组件状态是很容易的，因此让 Flow 告诉您您做错了什么是真正的时间节省器。

# 函数属性值

将函数从一个组件传递到另一个组件作为属性是完全正常的。您可以使用 Flow 来确保不仅将函数传递给组件，而且还传递了正确类型的函数。

让我们通过查看 React 应用程序中的常见模式来检验这个想法。假设您有以下渲染`Article`组件的`Articles`组件：

```jsx
// @flow 
import React, { Component } from 'react'; 
import Article from './Article'; 

type Props = {}; 
type State = { 
  summary: string, 
  selected: number | null, 
  articles: Array<{ title: string, summary: string}> 
}; 

class Articles extends Component<Props, State> { 
  state = { 
    summary: '', 
    selected: null, 
    articles: [ 
      { title: 'First Title', summary: 'First article summary' }, 
      { title: 'Second Title', summary: 'Second article summary' }, 
      { title: 'Third Title', summary: 'Third article summary' } 
    ] 
  }
```

```jsx
  onClick = (selected: number) => () => { 
    this.setState(prevState => ({ 
      selected, 
      summary: prevState.articles[selected].summary 
    })); 
  } 

  render() { 
    const { 
      summary, 
      selected, 
      articles 
    } = this.state; 

    return ( 
      <div> 
        <strong>{summary}</strong> 
        <ul> 
          {articles.map((article, index) => ( 
            <li key={index}> 
              <Article 
                index={index} 
                title={article.title} 
                selected={selected === index} 
                onClick={this.onClick} 
              /> 
            </li> 
          ))} 
        </ul> 
      </div> 
    ); 
  } 
} 

export default Articles; 
```

`Articles`组件是一个容器组件，因为它具有状态，并且使用此状态来渲染子`Article`组件。它还定义了一个`onClick()`方法，用于更改`summary`状态和`selected`状态。其想法是`Article`组件需要访问此方法，以便触发状态更改。如果您仔细观察`onClick()`方法，您会注意到它实际上返回了一个新的事件处理程序函数。这样，当单击事件实际调用返回的函数时，它将具有对选定参数的作用域访问权限。

现在让我们看看`Article`组件，看看 Flow 如何帮助您确保您得到了您期望传递给组件的函数：

```jsx
// @flow 
import React from 'react'; 

type Props = { 
  title: string, 
  index: number, 
  selected: boolean, 
  onClick: (index: number) => Function 
}; 

const Article = ({ 
  title, 
  index, 
  selected, 
  onClick 
}: Props) => ( 
  <a href="#" 
    onClick={onClick(index)} 
    style={{ fontWeight: selected ? 'bold' : 'normal' }} 
  > 
    {title} 
  </a> 
); 

export default Article; 
```

此组件渲染的`<a>`元素的`onClick`处理程序调用了作为属性传递的`onClick()`函数，并期望返回一个新函数。如果您查看`Props`类型声明，您会发现`onClick`属性期望特定类型的函数：

```jsx
type Props = { 
  onClick: (index: number) => Function, 
  ... 
}; 
```

这告诉 Flow，这个属性必须是一个接受数字参数并返回一个新函数的函数。将此组件传递给一个事件处理程序函数，而不是返回事件处理程序函数的函数是一个容易犯的错误。Flow 可以轻松发现这一点，并让您轻松进行更正。

# 强制子组件类型

除了验证状态和属性值的类型之外，Flow 还可以验证您的组件是否获得了正确的子组件。接下来的部分将向您展示 Flow 可以在哪些常见情况下告诉您，当您通过传递错误的子组件来误用组件时。

# 具有特定子类型的父级

您可以告诉 Flow 组件只能与特定类型的子组件一起使用。假设您有一个`Child`组件，并且这是唯一允许作为正在处理的组件的子组件的类型。以下是如何告诉 Flow 这个约束的方法：

```jsx
// @flow 
import * as React from 'react'; 
import Child from './Child'; 

type Props = { 
  children: React.ChildrenArray<React.Element<Child>>, 
}; 

const Parent = ({ children }: Props) => ( 
  <section> 
    <h2>Parent</h2> 
    {children} 
  </section> 
); 

export default Parent; 
```

让我们从第一个`import`语句开始：

```jsx
 import * as React from 'react'; 
```

您希望将星号导入为`React`的原因是因为这将引入 React 中可用的所有 Flow 类型声明。在此示例中，您使用`ChildrenArray`类型来指定该值实际上是组件的子组件，并使用`Element`来指定您需要一个 React 元素。在此示例中使用的类型参数告诉 Flow，`Child`组件是此处可接受的唯一组件类型。

给定子组件约束，此 JSX 将通过 flow 验证：

```jsx
<Parent> 
  <Child /> 
  <Child /> 
</Parent> 
```

对于作为`Parent`子组件渲染的`Child`组件的数量没有限制，只要至少有一个即可。

# 只有一个子组件的父组件

对于某些组件，拥有多个子组件是没有意义的。对于这些情况，您将使用`React.Element`类型而不是`React.ChildrenArray`类型：

```jsx
// @flow
import * as React from 'react';
import Child from './Child';

type Props = {
  children: React.Element<Child>,
};

const ParentWithOneChild = ({ children }: Props) => (
  <section>
    <h2>Parent With One Child</h2>
    {children}
  </section>
);

export default ParentWithOneChild; 
```

与之前的示例一样，您仍然可以指定允许的子组件类型。在这种情况下，子组件称为`Child`，从`'./Child'`导入。以下是如何将此组件传递给子组件的方法：

```jsx
<ParentWithOneChild> 
  <Child /> 
</ParentWithOneChild> 
```

如果您传递多个`Child`组件，Flow 会抱怨：

```jsx
    Property `children` is incompatible:
         24:         <ParentWithOneChild>
                     ^^^^^^^^^^^^^^^^^^^^ React children array. Inexact type is incompatible with exact type
          6:   children: React.Element<Child>,
                         ^^^^^^^^^^^^^^^^^^^^ object type. See: src/ParentWithOneChild.js:6

```

再次，Flow 错误消息会准确显示代码的问题所在。

# 具有可选子组件的父组件

始终需要一个子组件并不是必要的，实际上可能会引起麻烦。例如，如果没有要渲染的内容，因为 API 没有返回任何内容怎么办？以下是如何使用 Flow 语法指定子组件是可选的示例：

```jsx
// @flow
import * as React from 'react';
import Child from './Child';

type Props = {
  children?: React.Element<Child>,
};

const ParentWithOptionalChild = ({ children }: Props) => (
  <section>
    <h2>Parent With Optional Child</h2>
    {children}
  </section>
);

export default ParentWithOptionalChild;
```

这看起来很像需要特定类型元素的 React 组件。不同之处在于有一个问号：`children?`。这意味着可以传递`Child`类型的子组件，也可以不传递任何子组件。

# 具有原始子值的父组件

渲染接受原始值作为子组件的 React 组件是很常见的。在某些情况下，您可能希望接受字符串或布尔类型。以下是您可以这样做的方法：

```jsx
// @flow
import * as React from 'react';

type Props = {
  children?: React.ChildrenArray<string|boolean>,
};

const ParentWithStringOrNumberChild = ({ children }: Props) => (
  <section>
    <h2>Parent With String or Number Child</h2>
    {children}
  </section>
);

export default ParentWithStringOrNumberChild;
```

再次，您可以使用`React.ChildrenArray`类型来指定允许多个子元素。要指定特定的子类型，您将其传递给`React.ChildrenArray`作为类型参数—在这种情况下是字符串和布尔联合。现在您可以使用字符串渲染此组件：

```jsx
<ParentWithStringOrNumberChild>
  Child String
</ParentWithStringOrNumberChild>
```

或者使用布尔值：

```jsx
<ParentWithStringOrNumberChild> 
  {true} 
</ParentWithStringOrNumberChild> 
```

或者两者都使用：

```jsx
<ParentWithStringOrNumberChild> 
  Child String 
  {false} 
</ParentWithStringOrNumberChild> 
```

# 验证事件处理程序函数

React 组件使用函数来响应事件。这些被称为**事件处理程序函数**，当 React 事件系统调用它们时，它们会被传递一个事件对象作为参数。使用 Flow 明确地为这些事件参数类型化可能是有用的，以确保您的事件处理程序获得它所期望的元素类型。

例如，假设您正在开发一个组件，该组件响应来自`<a>`元素的点击。您的事件处理程序函数还需要与被点击的元素交互，以获取`href`属性。使用 React 公开的 Flow 类型，您可以确保正确的元素类型确实触发了导致函数运行的事件：

```jsx
// @flow
import * as React from 'react';
import { Component } from 'react';

class EventHandler extends Component<{}> {
  clickHandler = (e: SyntheticEvent<HTMLAnchorElement>): void => {
    e.preventDefault();
    console.log('clicked', e.currentTarget.href);
  }

  render() {
    return (
      <section>
        <a href="#page1" onClick={this.clickHandler}>
          First Link
        </a>
      </section>
    );
  }
}

export default EventHandler;
```

在这个例子中，`clickHandler()`函数被分配为`<a>`元素的`onClick`处理程序。注意事件参数的类型：`SyntheticEvent<HTMLAnchorElement>`。Flow 将使用此来确保您的代码只访问事件的适当属性和事件的`currentTarget`。

`currentTarget`是触发事件的元素，在这个例子中，您已指定它应该是`HTMLAnchorElement`。如果您使用了其他类型，Flow 会抱怨您引用`href`属性，因为其他 HTML 元素中不存在该属性。

# 将 Flow 引入开发服务器

如果您希望在项目中为此功能，您需要从`create-react-app`中退出。

这种方法的目标是在检测到更改时让开发服务器为您运行 Flow。然后，您可以在开发服务器控制台输出和浏览器控制台中看到 Flow 输出。

一旦您通过运行`npm eject`从`create-react-app`中退出，您需要安装以下 Webpack 插件：

```jsx
npm install flow-babel-webpack-plugin --save-dev
```

然后，您需要通过编辑`config/webpack.config.dev.js`来启用插件。首先，您需要包含插件：

```jsx
const FlowBabelWebpackPlugin = require('flow-babel-webpack-plugin');
```

然后，你需要将插件添加到`plugins`选项中的数组中。之后，这个数组应该看起来像这样：

```jsx
plugins: [ 
  new InterpolateHtmlPlugin(env.raw), 
  new HtmlWebpackPlugin({ 
    inject: true, 
    template: paths.appHtml, 
  }), 
  new webpack.NamedModulesPlugin(), 
  new webpack.DefinePlugin(env.stringified), 
  new webpack.HotModuleReplacementPlugin(), 
  new CaseSensitivePathsPlugin(), 
  new WatchMissingNodeModulesPlugin(paths.appNodeModules), 
  new webpack.IgnorePlugin(/^./locale$/, /moment$/), 
  new FlowBabelWebpackPlugin() 
], 
```

就是这样。现在当你启动开发服务器时，Flow 将自动运行并在 Webpack 构建过程中对你的代码进行类型检查。让我们在`App.js`的顶部添加`@flow`指令，然后运行`npm start`。由于`App`组件不会作为`Component`的子类进行验证，你应该会在开发服务器控制台输出中得到一个错误：

```jsx
    Failed to compile.

    Flow: Type Error
    Error: src/App.js:6
      6: class App extends Component {
                           ^^^^^^^^^ Component. Too few type arguments. Expected at least 1
     26: declare class React$Component<Props, State = void> {
                                       ^^^^^^^^^^^^ See type parameters of definition here.

    Found 1 error

```

我真的很喜欢这种方法，即使有 Flow 错误，开发服务器仍然会启动。如果你在浏览器中查看应用程序，你会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/3b760a4f-2ae2-47cf-afa9-527bb9be4fa1.png)

这意味着在开发过程中，你甚至不需要查看开发服务器控制台来捕捉类型错误！而且由于它是开发服务器的一部分，每次你进行更改时，Flow 都会重新检查你的代码。所以让我们通过传递一个属性类型参数(`<{}>`)来修复`App.js`中的当前错误。

```jsx
class App extends Component<{}> { 
  ... 
} 
```

一旦进行了这个改变，保存文件。就像这样，错误就消失了，你又可以继续工作了。

# 将 Flow 整合到你的编辑器中

我们将看一下最后一个选项，用于使用 Flow 验证你的 React 代码，那就是将这个过程整合到你的代码编辑器中。我正在使用流行的 Atom 编辑器，所以我会以此为例，但很可能也有其他编辑器可以与 Flow 整合。

要在 Atom 编辑器中启用 Flow 功能，你需要安装`linter-flow`包：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/ae5686bc-9c22-44a0-a10c-e07202c52db4.png)

安装完成后，你需要改变`linter-flow`的可执行路径设置。默认情况下，插件假设你已经全局安装了 Flow，但实际上你可能没有。你需要告诉插件在本地的`node_modules`目录中查找 Flow 可执行文件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/0d2e1839-6db9-4019-ac26-08ffda5f2104.png)

你已经准备好了。为了验证这是否按预期工作，请打开一个新的`create-react-app`安装中的`App.js`，并在文件顶部添加`@flow`指令。这应该会触发 Flow 的错误，并应该在 Atom 中显示出来：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/09fe4981-2a7c-4620-98df-5a60dc5d2b13.png)

Linter 还会突出显示导致 Flow 抱怨的有问题的代码：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react16-tl/img/e0f29729-4e75-4715-a42b-0bc789def958.png)

通过在编辑器中使用 Flow 的方法，您甚至不需要保存，更不用说切换窗口来进行代码类型检查——您只需要编写代码。

# 总结

在本章中，您了解了为什么对 React 代码进行类型检查很重要。您还了解了 Flow——用于对 React 代码进行类型检查的工具。对于 React 应用程序来说，类型检查很重要，因为它消除了在大多数情况下执行值的运行时检查的需要。这是因为 Flow 能够静态地跟踪代码路径，并确定是否一切都被按照预期使用。

然后，您在本地安装了 Flow 到一个 React 应用程序，并学会了如何运行它。接下来，您学会了验证 React 组件的属性和状态值的基础知识。然后，您学会了验证函数类型以及如何强制执行子 React 组件类型。

Flow 可以在`create-react-app`开发服务器中使用，但您必须先进行弹出。在未来的`create-react-app`版本中，可能会有更好的集成支持，可以作为开发服务器的一部分运行 Flow。另一个选择是在诸如 Atom 之类的代码编辑器中安装 Flow 插件，并在编写代码时直接在眼前显示错误。

在接下来的章节中，您将学习如何借助工具来强制执行 React 代码的高质量水平。
