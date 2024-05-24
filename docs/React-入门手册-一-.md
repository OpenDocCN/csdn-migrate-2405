# React 入门手册（一）

> 原文：[`zh.annas-archive.org/md5/2B8E3D6DF41679F5F06756066BE8F7E8`](https://zh.annas-archive.org/md5/2B8E3D6DF41679F5F06756066BE8F7E8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

诸如 Angular 和 React 之类的项目正在迅速改变开发团队构建和部署 Web 应用程序到生产环境的方式。在本书中，你将学习到使用 React 入门所需的基础知识，并应对现实世界的项目和挑战。本书包含了在开发过程中考虑关键用户需求的实用指导，并展示了如何处理高级概念，如状态管理、数据绑定、路由以及流行的 JSX 组件标记。完成本书中的示例后，你将发现自己已经准备好转向实际的个人或专业前端项目。

完成本书后，你将能够：

+   理解 React 如何在更广泛的应用程序堆栈中工作

+   分析如何将标准界面分解为特定组件

+   成功创建你自己的越来越复杂的 React 组件，无论是使用 HTML 还是 JSX

+   正确处理多个用户事件及其对整体应用程序状态的影响

+   理解组件生命周期以优化应用程序的用户体验

+   配置路由以允许通过你的组件进行轻松、直观的导航

# 本书适合的读者

如果你是一名前端开发者，希望在 JavaScript 中创建真正反应式的用户界面，那么这本书适合你。对于 React，你需要在 JavaScript 语言的基本要素方面有坚实的基础，包括 ES2015 中引入的新 OOP 特性。假设你了解 HTML 和 CSS，并且对 Node.js 有基本了解，这在管理开发工作流程的上下文中将是有用的，但不是必需的。

# 本书涵盖的内容

第一章，*介绍 React 和 UI 设计*，介绍 React 并帮助我们开始构建基于 React 的应用程序的基本基础设施。然后，我们将分析如何设计用户界面，以便它可以轻松映射到 React 组件。

第二章，*创建组件*，教我们如何实现 React 组件，如何将多个组件组合成一个，以及如何管理它们的内部状态。我们将通过构建一个简单的应用程序来探索 React 组件的实现。

第三章，*管理用户交互*，教我们如何管理用户与基于 React 的用户界面组件交互产生的事件。我们将探索在 React 组件生命周期中触发的事件，并学习如何利用它们来创建高效的组件。

# 充分利用本书

本书将需要具有以下最低硬件要求的系统：

+   处理器：Pentium 4（或同等产品）

+   4 GB RAM

+   硬盘空间：10 GB

+   互联网连接

以下软件也应该安装：

+   任何现代操作系统（最好是 Windows 10 版本 1507）

+   最新版本的 Node.js（[`nodejs.org/en/`](https://nodejs.org/en/)）

+   任何现代浏览器的最新版本（最好是 Chrome）

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)上的帐户下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便将文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册于[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择支持选项卡。

1.  点击代码下载与勘误。

1.  在搜索框中输入书名，并按照屏幕上的指示操作。

下载文件后，请确保使用最新版本的以下软件解压缩或提取文件夹：

+   适用于 Windows 的 WinRAR/7-Zip

+   适用于 Mac 的 Zipeg/iZip/UnRarX

+   适用于 Linux 的 7-Zip/PeaZip

本书的代码包也托管在 GitHub 上，地址为[`github.com/TrainingByPackt/Beginning-React`](https://github.com/TrainingByPackt/Beginning-React)。如果有代码更新，将会在现有的 GitHub 仓库中更新。

我们还有来自丰富图书和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上查看。去看看吧！

# 下载彩色图像

我们还提供了一个包含本书中使用的截图/图表的彩色图像的 PDF 文件。您可以在此处下载：[`www.packtpub.com/sites/default/files/downloads/BeginningReact_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/BeginningReact_ColorImages.pdf)。

# 使用的约定

本书中使用了多种文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如：“通过包装`App`组件，`BrowserRouter`组件为其赋予了路由功能。”

代码块设置如下：

```jsx
class Catalog extends React.Component {
  constructor() {
    super();
```

当我们希望引起您对代码块特定部分的注意时，相关行或项目以粗体显示：

```jsx
import { BrowserRouter } from 'react-router-dom'
ReactDOM.render(
 <BrowserRouter>
    <App />
 </BrowserRouter>
  , document.getElementById('root'));
```

任何命令行输入或输出都以下列方式书写：

```jsx
create-react-app --version
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词以这种方式出现在文本中。例如：“现在我们需要创建一个视图来显示**目录**组件或**关于**页面。”

**活动**：这些是基于场景的活动，将让您在完整的部分过程中实际应用所学知识。它们通常是在现实世界问题或情况的背景下。

警告或重要提示以这种方式出现。


# 第一章：介绍 React 和用户界面设计

React 无疑是网络上讨论最多的库之一。它已经变得像 jQuery 在其鼎盛时期一样流行，越来越多的开发者选择它来构建他们的网页应用程序的用户界面。为什么它变得如此流行？为什么这个 JavaScript 库与其他库相比如此创新？

我们将在本书中尝试回答这些问题，展示该库提供的内容，并使用它来构建高效的网页用户界面。

在本章中，我们将介绍 React，并开始构建基于 React 的应用程序的基本基础设施。然后，我们将分析如何设计用户界面，以便它可以轻松映射到 React 组件，充分利用 React 的内部架构。

在本章结束时，你将能够：

+   描述 React 是什么以及它在你的应用程序开发中的作用

+   搭建基于 React 的应用程序的基础设施

+   设计你的应用程序的用户界面，并优化其在 React 中的使用

# 什么是 React？

简而言之，React 是一个用于构建可组合用户界面的 JavaScript 库。这意味着我们可以通过组合称为**组件**的项来构建用户界面。组件是构建用户界面的元素。它可以是一个文本框、一个按钮、一个完整的表单、一组其他组件，等等。甚至整个应用程序的用户界面也是一个组件。因此，React 鼓励创建组件来构建用户界面；如果这些组件是可重用的，那就更好了。

React 组件有能力展示随时间变化，并且当我们遵循一些指导原则时，该变化数据的可视化是自动的。

由于该库涉及用户界面，你可能会好奇 React 受到了哪些展示设计模式的影响：**模型-视图-控制器**、**模型-视图-展示器**、**模型-视图-视图模型**，还是其他。React 并不局限于特定的展示模式。React 实现了最常见模式中的*视图*部分，让开发者自由选择最佳方法来实现模型、展示器以及构建应用程序所需的其他一切。这一点很重要，因为它使我们能够将其归类为库，而不是框架；因此，与 Angular 等框架的比较可能会出现一些不一致之处。

# 如何搭建基于 React 的应用程序

React 是一个 JavaScript 库，因此我们应该能够通过 HTML 页面中的`<script>`标签引用它并开始编写我们的 Web 应用程序。然而，这种方法会阻止我们利用现代 JavaScript 开发环境提供的一些功能——这些功能使我们的生活更轻松。例如，我们将无法使用 ECMAScript 2015+的最新功能，如类、模块、箭头函数、`let`和`const`语句等。或者，我们可以使用这些功能，但只有最近的浏览器才会支持它们。

**ECMAScript 与 JavaScript 的关系**

使用最新的 ECMAScript 功能需要一个真正的开发环境，允许我们将代码转换为 ECMAScript 5 版本的 JavaScript 代码，以便即使旧的浏览器也能够运行我们的应用程序。设置现代 JavaScript 开发环境需要安装和配置一些工具：一个转换器、一个语法检查器、一个模块捆绑器、一个任务运行器等。学习正确使用这些工具需要大量时间，甚至在开始编写一行代码之前。

# **安装 create-react-app**

幸运的是，我们可以使用`create-react-app`，这是一个**命令行界面**（**CLI**）工具，它允许我们无需配置任何上述工具即可设置基于 React 的应用程序。它基于 Node.js，并提供命令以即时方式设置和修改 React 应用程序。

为了安装`create-react-app`，您需要在您的机器上安装 Node.js。您可以在控制台窗口中输入以下命令来安装 CLI：

```jsx
npm install -g create-react-app
```

安装后，您可以通过输入以下命令来验证是否已正确安装：

```jsx
create-react-app --version
```

如果一切正常，将显示已安装的`create-react-app`版本。

# **创建您的第一个 React 应用程序**

既然开发环境已安装，让我们创建我们的第一个 React 应用程序。我们可以在控制台窗口中输入以下命令来执行此操作：

```jsx
create-react-app hello-react
```

此命令告诉`create-react-app`为名为`hello-react`的 React 应用程序设置所有先决条件。创建过程可能需要几分钟，因为它必须下载项目所需的 npm 包。

npm 是 Node.js 环境的默认包管理器。当进程结束时，您将在屏幕上找到可用于管理项目的可用命令列表。我们稍后会回到这一点。项目创建的结果将是一个名为`hello-react`的文件夹，在其中您将找到构成一个虚拟的——但可工作的——基于 React 的应用程序的项。

# **活动：使用 create-react-app 创建应用程序**

**场景**

我们需要设置一个开发环境，以便创建一个使用 React 构建的产品目录应用程序。

**目的**

活动的目的是开始熟悉`create-react-app`及其创建的内容。

**完成步骤**

1.  使用 `create-react-app` 创建开发环境

1.  将示例应用程序命名为 `my-shop`

**解决方案**

没有正式的解决方案。你应该专注于由 `create-react-app` 创建的内容，因为接下来我们将在以下部分中分析它。

# 探索生成的内容

让我们来看看 `create-react-app` 生成的文件，以便我们能够理解基于 React 的应用程序的结构。我们将在 `HELLO-REACT` 文件夹中找到这些文件和文件夹，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/bg-react/img/b24741a3-0f38-44cd-a832-5fd756aa5339.png)

在根文件夹中，我们可以看到一个 `README.md` 文件、`package.json` 文件和 `.gitignore` 文件。

`README` 文档包含开始构建基于 React 的应用程序所需的所有引用。它是以 Markdown 格式编写的，你可以将其与自己的文档集成或覆盖。

Markdown 是一种简单的标记语言，常用于创建软件库的技术文档。它只需要一个简单的文本编辑器，并且可以将 Markdown 文档转换为 HTML。

`package.json` 文件包含有关项目的信息，如名称、版本等，以及对当前项目使用的所有 npm 包的引用。这是一个 Node.js 资源，允许你在将项目复制到另一台机器时下载所需的包。它还包含允许我们管理项目本身的脚本定义。

以下是 `package.json` 文件内容的示例：

```jsx
{
  "name": "hello-react",
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

正如我们所见，文件内容是一个 JSON 对象，有几个易于识别的属性。特别是，我们可以识别项目的名称、版本和包依赖项。除了名称和版本属性外，通常你不需要手动更改这些设置。

`.gitignore` 文件是 Unix 系统中的隐藏文件，它允许我们跟踪在使用 Git 作为版本控制系统时要忽略的文件。`create-react-app` 工具添加了这个文件，因为现在，将项目置于版本控制之下是必不可少的。它建议使用 Git，因为它是目前最流行的版本控制系统之一。

`public` 文件夹包含我们应用程序的静态部分：

+   `favicon`：这是在浏览器地址栏中显示的图标，用于书签

+   `index.html`：这是包含对我们的 React 代码的引用并提供 React 渲染上下文的 HTML 页面

+   `manifest.json`：这是一个根据 **渐进式 Web 应用**（**PWA**）标准包含元数据的配置文件

特别是，`index.html` 文件是我们应用程序的起点。让我们来看看它，以便我们能够理解它的特别之处：

```jsx
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="theme-color" content="#000000">
    <link rel="manifest" href="%PUBLIC_URL%/manifest.json">
...
    <title>React App</title>
  </head>
  <body>
    <noscript>
      You need to enable JavaScript to run this app.
    </noscript>
  <div id="root"></div>
...
</html>
```

正如我们所见，它是一个标准的 HTML 页面；然而，有几点需要注意。首先，我们看到一个指向 `manifest.json` 文件的链接：

```jsx
<link rel="manifest" href="%PUBLIC_URL%/manifest.json">
```

这个清单包含将我们的应用配置为 PWA 的元数据。

渐进式 Web 应用是适用于每个浏览器和平台的 Web 应用，甚至可以离线工作。它们的基本原则是响应性和渐进增强。

我们注意到的第二件事是两个链接引用中都存在的`%PUBLIC_URL%`占位符。

```jsx
<link rel="manifest" href="%PUBLIC_URL%/manifest.json">
<link rel="shortcut icon" href="%PUBLIC_URL%/favicon.ico">
```

这个占位符将在构建过程中被`public`文件夹的实际 URL 替换。

HTML 页面的主体包含一个带有根标识符的空`div`。这是我们 React 应用程序正确设置的一个重要项目，我们很快就会看到。除了`<noscript>`标签外，我们在主体中看不到其他元素。然而，我们需要在 HTML 页面和 JavaScript 之间建立绑定。构建过程将负责向主体添加所需的脚本。

我们可以向 HTML 页面添加任何其他必需的项目，例如元标签、网络字体等。但是，请记住，HTML 标记中引用的文件应该放在`public`文件夹中。`node_modules`文件夹包含项目使用的 npm 包。通常，您不需要直接管理这些文件。

开发我们应用程序最重要的文件夹是`src`文件夹。它包含我们可以根据需要修改的基本文件和代码。

特别是，我们将找到以下文件：

+   `index.js`：包含我们应用程序的启动点。

+   `index.css`：存储我们应用程序的基本样式。

+   `App.js`：包含示例应用程序的主要组件的定义。

+   `App.css`：包含`App`组件的样式。

+   `logo.svg`：这是 React 的标志。

+   `App.test.js`：存储涉及`App`组件的基本单元测试。

+   `registerServiceWorker.js`：包含注册服务工作者的代码，以便允许离线行为，符合 PWA 的要求。

让我们分析一下这些文件的内容，因为它们的代码对于理解 React 应用程序的启动方式至关重要。

让我们从`index.js`文件开始。其内容如下所示：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import App from './App';
import registerServiceWorker from './registerServiceWorker';

ReactDOM.render(<App />, document.getElementById('root'));
registerServiceWorker();
```

它是一个 ECMAScript 2015 模块，导入其他模块。特别是，它从`react`和`react-dom`模块分别导入`React`和`ReactDOM`对象。这两个模块都是 React 库的一部分，存储在`node_modules`文件夹中。

`react`模块提供组件创建和状态管理的功能。`react-dom`模块是 React 组件和 HTML DOM 之间的粘合剂。React 库被分为两个模块，以将组件管理与实际渲染分离。当我们想要针对的不是 Web 的渲染平台时，这种分离可能会有用；例如，如果我们想要针对原生移动渲染。

其他模块从与`index.js`文件相同的文件夹中导入。特别是，我们从`App`模块导入`App`组件。`App`组件由`ReactDOM`对象的`render()`方法使用，以便将其绑定到 HTML 页面中的`div`元素。这个魔法是通过以下语句实现的：

```jsx
ReactDOM.render(<App />, document.getElementById('root'));
```

目前，我们先忽略用于渲染`App`组件的语法。这将在下一章中介绍。这个语句的含义是将`App`模块内部定义的 React`App`组件与`root`ID 标识的 HTML 元素关联起来。

`registerServiceWorker()`函数的导入和调用启用了离线行为支持，符合 PWA 规范，而`index.css`的导入使 CSS 样式对应用程序可用。

`App.js`文件包含了代表应用程序的 React 组件的定义。其内容如下所示：

```jsx
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
...
export default App;
```

让我们快速看一下代码，因为它将在下一章中详细介绍。目前，我们只想对 React 组件的定义有一个非常基本的了解。在这里，我们看到一个模块从其他模块导入一些项目，通过继承`Component`类定义`App`类，并将`App`类本身作为默认导出。目前就是这样。我们将在下一章中深入介绍这段代码，详细理解其含义。

# create-react-app 命令

`create-react-app` CLI 提供了几个命令来管理我们的 React 项目。这些命令以`npm <command>`的形式出现，因为它们基于 npm。

如果你更喜欢使用 YARN 作为包管理器，你应该在任何地方找到`npm`时替换为`yarn`。

# npm start 命令

我们将介绍的第一个命令是`npm start`。这个命令启动一个开发 Web 服务器，接受`http://localhost:3000`的请求。

因此，在启动这个命令后，我们可以在浏览器中看到以下结果：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/bg-react/img/576f13fd-abeb-46d3-a45f-dfacde3d733b.png)

开发 Web 服务器有一个热重载系统，允许我们更改应用程序的代码并在保存文件后在浏览器中刷新页面。

# 更改文件内容并查看结果

以下步骤展示了如何通过更改文件内容来使应用程序在浏览器中重新加载：

1.  打开一个控制台窗口。

1.  转到`hello-react`文件夹。

1.  运行`npm start`。

1.  启动浏览器并访问`http://localhost:3000`。

1.  启动文本编辑器并打开`App.js`文件。

1.  查找以下代码行：

```jsx
To get started, edit <code>src/App.js</code> and save to reload.
```

1.  将第 6 步中提到的代码替换为以下代码行：

```jsx
Hello React!
```

1.  保存文件。

1.  检查浏览器内容。现在它应该显示新文本。

# 活动：启动和更改应用程序

**场景**

我们想要更改在前一个活动中创建的应用程序的标题。

**目的**

活动的目的是熟悉启动应用程序并欣赏热重载功能。

**完成步骤**

1.  启动应用程序，以便您可以在浏览器中看到它

1.  编辑`App.js`文件并将标题设置为`My Shop`

**解决方案**

没有正式的解决方案。您应该专注于正确更改标题并使应用程序运行。

# npm 测试命令

`create-react-app`通过生成一个示例单元测试文件（我们已经看到过）并提供一组工具来运行这些测试，从而推广使用单元测试。

这些工具基于**Jest**，我们可以通过运行以下命令来运行我们应用程序中编写的测试：

```jsx
npm test
```

这个命令将开始运行我们的测试，并显示结果，如以下截图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/bg-react/img/6214f136-1247-4f58-ae30-447792398d06.png)

# npm 运行构建命令

当我们准备好将应用程序移动到生产环境时，我们需要发布工件。我们可以通过运行以下命令来生成这些工件：

```jsx
npm run build
```

运行此命令的结果是一个新的`BUILD`文件夹，我们将在这里找到所有需要移动到生产环境的文件。该命令对我们的开发环境文件进行一些处理。简单来说，它将我们编写的所有 ES2015 代码转换为与 ES5 兼容的代码，以便它也可以用于旧版浏览器。这个过程称为**转译**。此外，它还减小了代码本身的大小，允许通过网络更快地下载。这个过程称为**压缩**。最后，它将我们开发环境中的文件合并为几个文件，称为捆绑包，以减少网络请求。

以下截图显示了示例应用程序的`BUILD`文件夹的内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/bg-react/img/751f24bf-3ab9-4bde-aa22-52c5c896fc43.png)

要发布我们应用程序的生产构建，我们只需将`BUILD`文件夹的内容复制到生产服务器的文件夹中。

生产构建的结果假设工件将被发布到 Web 服务器根目录，也就是说，在一个位置，应用程序将通过一个 URL（如`http://www.myapplication.com`）访问。

如果我们需要在根目录的子文件夹中发布应用程序，也就是说，在一个位置，应用程序将通过一个 URL（如`http://www.myapplication.com/app`）访问，我们需要对`package.json`文件进行轻微更改。

在这种情况下，我们需要在配置 JSON 中添加一个`homepage`键，其值为 URL，如下所示：

`"homepage": "http://www.myapplication.com/app"`。

# npm 运行 eject 命令

我们要介绍的最后一个命令是`eject`命令：

```jsx
npm run eject
```

当我们对使用`create-react-app`底层工具充满信心并且需要自定义环境配置时，我们可以使用此命令。此命令将我们的应用程序从 CLI 上下文中移出，并赋予我们管理和负责它的能力。

这是一个单向过程。如果我们为应用程序离开`create-react-app`上下文，我们就无法返回。

# 如何设计 UI

现在，我们将看到如何设计我们的应用程序，以便它在用 React 实现时很好地适应。

# 一切都是组件

在用户界面设计和实现中引入的主要概念是 React 的组件概念。用户界面是组件的聚合，整个 React 应用程序是组件的聚合。现在我们将更详细地了解从设计角度来看组件是什么。

从设计的角度来看，我们可以说组件是用户界面的一部分，具有特定的作用。组件的层次结构通常被称为组件树。

考虑网页中的一个表单。它可以被视为一个组件，因为它有一个特定的作用：收集数据并将其发送到服务器。此外，表单内的文本框也可以被视为一个组件。它有一个特定的作用：收集单个数据片段，该数据将被发送到服务器。因此，一个组件可能包含其他组件。这通常是发生的情况：用户界面是组件的层次结构，其中一些组件包含其他组件。

记住这个概念，因为它将有助于实现高效和可重用的用户界面。

# 分解用户界面

为了更好地理解如何设计用户界面以及如何创建组件来实现它们，我们将尝试分解一个广为人知的网页用户界面——YouTube 主页：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/bg-react/img/e9867a5a-8ca0-4c86-9b7e-73501a8bde50.png)

我们可以检测到页面上的多个项目，每个项目都有特定的作用，从页面本身开始，其作用是允许用户与系统交互。

如果我们考虑页眉、左侧边栏和主区域，所有这些项目都是页面的组件。您可以在下面的截图中看到它们被突出显示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/bg-react/img/094ad032-347c-4c84-9cfd-c33f4ce932f8.png)

当然，我们可以继续识别其他组件。例如，我们可以将主区域中的每个视频预览框视为一个组件。您可以在下面的截图中看到它们：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/bg-react/img/fbd31514-b679-4314-9c01-bd23302a7d35.png)

这个分解过程使我们能够专注于界面中每个项目的特定作用，以便我们可以尝试隔离每个功能并创建可重用的组件，即只具有真正重要的依赖关系的组件。

# 容器和展示组件

我们可以将用户界面中的组件分为容器组件和展示组件。

容器组件是那些没有显著视觉效果的组件。它们的主要作用是组合其他组件，即*包含*其他组件。例如，一个表单通常是容器组件，因为它的主要作用是包含其他组件，如文本框、标签、按钮等。

展示组件是那些以某种图形形式显示数据的组件。文本框、日期选择器和工具栏都是展示组件的例子。

区分容器组件和展示组件对于在 React 中创建高效的用户界面非常重要。我们将在学习管理组件状态和通过组件传播数据时利用这种区分。

# 活动：在网页用户界面中识别组件

**场景**

我们需要将维基百科网站的用户界面（[`en.wikipedia.org`](https://en.wikipedia.org)）转换为 React 组件。

**目标**

该活动的目的是解决在实现基于 React 的用户界面时的设计过程。

**完成步骤**

1.  分析页面的当前结构并识别可以作为组件实现的项目

1.  指出了哪些是容器组件，哪些是展示组件

**解决方案**

假设以下是当前的维基百科首页：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/bg-react/img/3efcae52-04c7-429a-92d7-fd347d736c11.png)

可能的解决方案如下。

我们可以识别以下组件：

+   *首页*组件包含*左侧边栏*组件、*头部*组件和*主区域*组件。所有这些组件都是容器组件。

+   *左侧边栏*组件包含*徽标*组件（展示型）和一组*节*组件（展示型）。

+   *头部*组件包含一组*链接*组件（展示型），指向一般的功能块。

+   *主区域*组件包含一组*标签*组件（容器型）和一个*搜索*组件（展示型）。

+   *主标签*组件包含一个*横幅*组件（展示型），一个*主题索引*组件（展示型），以及一组*块*组件（展示型）。

# **总结**

在本章中，我们开始探索 React 世界。特别是，我们：

+   确定了 React 是一个用户界面库，用于实现各种 MV*设计模式中的视图部分

+   介绍了`create-react-app`工具，它帮助我们设置一个开发环境来构建基于 React 的应用程序

+   探索了构成典型基于 React 的应用程序的各个部分

+   分析了最适合 React 世界的用户界面设计方法

在下一章中，我们将学习如何创建 React 组件来构建我们应用程序的用户界面。


# 第二章：创建组件

在本章中，我们将学习如何实现 React 组件，如何将多个组件组合成一个，以及如何管理它们的内部状态。我们将通过构建一个简单的应用程序来探索 React 组件的实现。这个应用程序将逐步实现，以便将概述的概念付诸实践。

在本章结束时，您将能够：

+   创建基本的 React 组件

+   使用 JSX 来定义组件的标记

+   组合多个 React 组件以创建复杂的 UI 元素

+   管理 React 组件的内部状态

# 组件定义

如前一章所定义，组件是 React 的基本构建块。用户界面中的几乎任何视觉项都可以是一个组件。从正式的角度来看，我们会说一个 React 组件是一段定义用户界面一部分的 JavaScript 代码。

考虑以下代码文件：

```jsx
import React from 'react';

class Catalog extends React.Component {
  render() {
    return <div><h2>Catalog</h2></div>;
  }
}

export default Catalog;
```

这是一个 ECMAScript 2015 模块，定义了一个基本的 React 组件。

它从 `react` 模块导入 `React` 命名空间，并通过扩展 `React.Component` 类来定义 `Catalog` 类。该模块将 `Catalog` 类作为默认导出。

这个定义的有趣之处在于 `render()` 方法的实现。

`render()` 方法定义了组件的视觉部分。它可以执行任何 JavaScript 代码，并应返回一个定义其视觉输出的标记表达式。`render()` 方法对于 React 组件是强制性的。在我们的示例中，`render()` 方法返回以下标记：

```jsx
<div><h2>Catalog</h2></div>
```

它看起来像 HTML；尽管它使用类似的语法，但它定义了称为 **元素** 的普通对象。React 元素类似于 **文档对象模型** (**DOM**) 元素，但更轻便且更高效。因此，React 组件生成一组将由库引擎映射到 DOM 元素的 React 元素。这组 React 元素称为 **虚拟 DOM**，是浏览器 DOM 的轻量级表示。React 负责更新 DOM 以匹配虚拟 DOM，仅在严格必要时进行。这种方法使得 React 在渲染用户界面时具有非常高的性能。

`render()` 方法必须遵守一些约束：

+   它是强制性的；也就是说，每个 React 组件都必须实现它

+   它必须返回一个 React 元素；也就是说，一个带有任何嵌套元素的单个标记项

+   它应该是纯函数；也就是说，它不应该改变组件的内部状态（我们将在下一节详细讨论这个话题）

+   它不应该直接与浏览器交互；也就是说，它不应该包含试图访问 DOM 的语句

纯函数是指其输出结果仅依赖于输入数据，且执行过程中没有副作用，例如，不会更新全局变量。给定一个输入值，纯函数总是返回相同的结果。

纯组件是一种像纯函数一样工作的组件。这意味着，给定相同的初始条件，它总是渲染相同的输出。保持`render()`方法为纯函数非常重要。这样可以避免我们在下一章中看到的奇怪的错误。

一旦我们定义了组件，我们就可以在任何其他 React 组件中将其作为 React 元素使用。例如，我们知道 React 应用程序本身已经是一个 React 组件。让我们回顾一下`create-react-app`工具在`App.js`文件中生成的代码：

```jsx
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
          To get started, edit <code>src/App.js</code> and save to reload.
        </p>
      </div>
    );
  }
}

export default App;
```

我们可以看到这段代码与我们所定义的`Catalog`组件具有相同的结构。让我们更改这段代码，以便在`App`组件内部使用我们的组件：

```jsx
import React, { Component } from 'react';
import './App.css';
import Catalog from './Catalog';

class App extends Component {
  render() {
    return (
      <div className="App">
        <header className="App-header">
          <h1 className="App-title">The Catalog App</h1>
        </header>
        <Catalog />
      </div>
    );
  }
}

export default App;
```

我们通过删除一些自动生成的标记简化了代码。然后导入`Catalog`组件，并将`<Catalog />`元素放入应用程序`render()`方法返回的`<div>`元素中。

# 构建我们的第一个 React 组件

打开现有项目`my-shop-01`，以展示之前代码更改的结果：

1.  打开一个控制台窗口

1.  转到`my-shop-1`文件夹

1.  运行`npm install`

1.  运行`npm start`

以下是我们在浏览器窗口中将看到的一个示例：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/bg-react/img/888b626e-0f78-4346-9515-29ba28498237.png)

我们已经构建了我们的第一个 React 组件，并且可以看到它在运行！

# 管理样式

也许您已经注意到，在`App`组件模块中有一个关于 CSS 文件的`import`语句：

```jsx
import React, { Component } from 'react';
import './App.css';
import Catalog from './Catalog';
```

这可能看起来有点奇怪，因为`import`语句应该只适用于 JavaScript 代码。然而，由于`create-react-app`提供的开发环境，我们甚至可以使用相同的语法，即使对于 CSS 文件也是如此。这允许我们在组件中使用`App.css`中定义的类和其他 CSS 定义，将组件特定的样式保持在组件定义本身附近。例如，如果我们想让`Catalog`组件的标题为红色，我们可以按照以下步骤进行。

# 添加 CSS

我们现在将更改现有项目`my-shop-01`的内容，以便添加一些 CSS 代码并将目录标题显示为红色：

1.  打开一个控制台窗口。

1.  转到`my-shop-1/src`文件夹。

1.  创建一个文件，`Catalog.css`，并添加以下代码：

```jsx
h2 { color: red }
```

1.  打开`Catalog.js`文件并添加以下语句以导入`Catalog.css`模块：

```jsx
import React from 'react';
import './Catalog.css';

class Catalog extends React.Component {
  render() {
    return <div><h2>Catalog</h2></div>;
  }
}
export default Catalog;
```

1.  运行`npm start`并查看结果。

您可以在`Code/Chapter-2`中的`my-shop-02`文件夹中找到一个准备好的项目。

浏览器将显示红色 Catalog 标题：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/bg-react/img/2e2fe10c-32de-4a03-8f13-3a1ebfa19cc5.png)CSS 导入不是 React 的特性，也不是 React 所必需的。它是开发环境提供的一种便利，由`create-react-app`构建。特别是，这个特性是由**webpack**提供的，**webpack**是最常用的打包器和模块加载器之一。

当你想将应用程序迁移到一个不基于 webpack 的开发环境时，应该考虑这一点。

# 活动：定义购物车

**场景**

我们的电子商店需要一个购物车。

**目标**

此活动的目的是开始使用 React 定义一个组件。

**完成步骤**

1.  我们应该定义一个作为购物车基础的 React 组件

1.  它应该是一个仅显示字符串`Cart`的组件。

使用`create-react-app`创建一个新的 React 应用程序，并按照当前章节所示进行更改。

**解决方案**

一个可能的解决方案包含在`Code/Chapter-2/`下的`my-cart-01`文件夹中。

# 使用 JSX

在前面的示例中，我们使用类似 HTML 的标记表达式定义了组件的`render()`方法返回的视觉输出。例如，让我们看看`Catalog`组件的定义：

```jsx
import React from 'react';
import './Catalog.css';

class Catalog extends React.Component {
  render() {
    return <div><h2>Catalog</h2></div>;
  }
}

export default Catalog;
```

标记表达式并未使用 JavaScript 语法，但它被包含在一个 JavaScript 代码片段内。我们为什么要混合 HTML 和 JavaScript 语法？这是如何实现的？

首先，我们要说的是，描述 React 组件视觉输出的类似 HTML 的语言被称为**JSX**。这种语言通过在 JavaScript 代码中添加 XML 表达式来简化 HTML 元素的创建。你可以将其视为一种`document.write("...")`，但功能更强大。实际上，在构建 React 应用程序时，JSX 标记由特定的解析器预处理，以生成纯 JavaScript 代码。因此，我们可以利用使用声明性标记语言的简单性，该语言将自动转换为优化的 JavaScript 代码。

如前所述，JSX 表达式创建了一个 React 元素，它是 HTML 元素的对应物。从语法角度来看，JSX 表达式是一个带有任何嵌套元素的单个标记项。因此，以下是一个有效的 JSX 表达式：

```jsx
<div><h2>Catalog</h2></div>
```

以下不是一个有效的 JSX 表达式，因为它包含两个标记项：

```jsx
<div><h2>Catalog</h2></div>
<div><img src="image.png" /></div>
```

JSX 表达式是 XML 片段，因此它们遵循 XML 语法规则。这意味着，除其他事项外，标记是区分大小写的，并且所有标签都必须关闭。

例如，以下 JSX 表达式是无效的：

`<img src="image.png">`

其有效版本如下：

`<img src="image.png"/>`

我们可以将 JSX 表达式赋值给一个变量，如下例所示：

```jsx
import React from 'react';
import './Catalog.css';

class Catalog extends React.Component {
  render() {
    let output = <div><h2>Catalog</h2></div>;
    return output;
  }
}

export default Catalog;
```

我们还可以在 JSX 表达式中嵌入任何 JavaScript 表达式，方法是将其用大括号包裹，如下例所示：

```jsx
import React from 'react';
import './Catalog.css';

class Catalog extends React.Component {
  render() {
    let title = "Catalog";
    return <div><h2>{title}</h2></div>;
  }
}
export default Catalog;
```

当然，JavaScript 表达式可以像我们需要的那样复杂，如下面的组件定义所示：

```jsx
import React from 'react';
import './Catalog.css';

class Catalog extends React.Component {
  render() {
    let title = "The Catalog of today " + new Date().toDateString();
    return <div><h2>{title}</h2></div>;
  }
}

export default Catalog;
```

除了优化输出渲染，JSX 还提供支持以防止注入攻击。实际上，任何嵌入 JSX 表达式的值在被渲染之前都会被转义。例如，这可以防止用户输入的恶意代码被插入。

结合 JavaScript 和 JSX 表达式的常见用法称为**条件渲染**；也就是说，一种根据某些布尔条件生成 JSX 表达式的技术。考虑以下示例：

```jsx
import React from 'react';
import './Message.css';

class Message extends React.Component {
  render() {
    let message;
    let today = new Date().getDay();

    if (today == 0) {
 message = <div className="sorry">We are closed on Sunday...</div>;
 } else {
 message = <div className="happy">How can we help you?</div>
 }

    return message;
  }
}

export default Message;
```

在前面的示例中，`render()`方法根据当前星期几返回一条不同的消息，这导致生成具有不同消息和 CSS 类的 React 元素，但我们甚至可以返回完全不同的标记。

您可以将 JSX 表达式放在多行中，如下所示：

```jsx
import React from 'react';
import './Catalog.css';

class Catalog extends React.Component {
  render() {
    let title = "Catalog";

    return <div>
 <h2>{title}</h2>
 </div>;
  }
}

export default Catalog;
```

当返回 JSX 表达式时，在`return`语句的同一行开始它非常重要，如前一个示例所示。如果您想在新行开始 JSX 表达式，则需要将其括在圆括号中，并将左括号放在与`return`语句相同的行上，如下所示：

`return (`

`  <div>`

`    <h2>Catalog</h2>`

`  </div>);`

您可以使用 JavaScript 语法将注释放在 JSX 表达式中，用大括号括起来。以下是带有注释的 JSX 表达式的示例：

```jsx
<div>
  <h2>Catalog</h2>
  {//This is a comment}
 {/* This is a comment, too */}
</div>;
```

JSX 标签匹配 HTML 标签，这就是为什么我们可以使用整个 HTML 语法来定义 JSX 元素。但是，有一些限制：

+   所有 HTML 标签均为小写

+   您需要使用`className`而不是`class`属性

+   您需要使用`htmlFor`而不是`for`属性

以下示例展示了使用`className`属性而不是`class`：

```jsx
<div className="catalog-style">
  <h2>Catalog</h2>
</div>;
```

JSX 使用`className`和`htmlFor`属性而不是`class`和`for`，因为 JSX 表达式在 JavaScript 内部，`class`和`for`可能与相应的保留关键字冲突。

# 活动：将 HTML 转换为 JSX

**场景**

图形部门已向您提供了一个 HTML 片段，您需要将其翻译为 JSX 以创建 React 组件。

**目标**

此活动的目的是了解 HTML 和 JSX 之间的区别。

**完成步骤**

1.  打开`Code02.txt`文件

1.  将包含的 HTML 代码转换为 JSX

**解决方案**

可能的解决方案是包含在`Code/Chapter-2/`中的`activity-b.html`文件。

# 组合组件

在定义 React 组件时，我们可以将它们用作另一个组件的子组件，方法是将其作为 React 元素使用。当我们包含`Catalog`组件在`App`组件内部时，我们已经看到了这一点，但是让我们进一步分析这种组合。

# 组合组件

现在我们将看到如何组合组件以创建新的、复杂的组件：

1.  在`my-shop-03`文件夹中打开`src/ProductList.js`文件

1.  按照文本直到本节结束

让我们考虑以下组件：

```jsx
import React from 'react';
class ProductList extends React.Component {
  render() {
    return <ul>
      <li>
        <h3>Traditional Merlot</h3>
        <p>A bottle of middle weight wine, lower in tannins (smoother), 
           with a more red-fruited flavor profile.</p>
      </li>
      <li>
        <h3>Classic Chianti</h3>
        <p>A medium-bodied wine characterized by a marvelous freshness with 
           a lingering, fruity finish</p>
      </li>
      <li>
        <h3>Chardonnay</h3>
        <p>A dry full-bodied white wine with spicy, bourbon-y notes in an 
           elegant bottle</p>
      </li>
      <li>
 <h3>Brunello di Montalcino</h3> <p>A bottle red wine with exceptionally bold fruit flavors, 
           high tannin, and high acidity</p>
      </li>
    </ul>;
  }
}
export default ProductList; 
```

该组件定义了酒名和描述的列表。

我们希望将我们的`Catalog`组件与酒单集成。由于我们已经创建了`ProductList`组件，因此我们可以将其用作`Catalog`组件的 JSX 标记中的标签，如下所示：

```jsx
import React from 'react';
import ProductList from './ProductList';

class Catalog extends React.Component {
  render() {
    return <div>
      <h2>Catalog</h2>
      <ProductList />
    </div>;
  }
}

export default Catalog;
```

如您所见，我们只需导入`ProductList`组件，以便在`Catalog`组件的模块中使其可用，并在我们希望酒单出现的地方使用`ProductList`标签。

运行`npm start`以启动应用程序。生成的页面将如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/bg-react/img/772ab3c7-0d0d-49dc-b8cf-08cb9a057d5e.png)

我们说过，JSX 表达式中的 HTML 标签应该始终是小写的。然而，我们在 Pascal case 中使用了`ProductList`标签。

对应于组件的标签必须遵循类定义中使用的案例，并且按照惯例，组件类名使用 Pascal case，尽管这不是 React 所要求的。

React 组件的组合简便性使得创建用户界面变得非常简单，遵循上一章提供的指导原则。我们可以将页面布局分解为一系列层次化的组件，每个组件又由其他组件组成。这种方法使我们能够专注于单个组件的行为，并促进其可重用性。

# 活动：定义一个组合的购物车

**场景**

我们想要为我们的购物车创建一些内容。

**目的**

这项活动的目的是组合 React 组件。

**完成步骤**

将之前创建的`Cart`组件整合，以便包含一个显示两个项目的`CartList`组件。

**解决方案**

可能的解决方案是包含在`Code/Chapter-2/`下的`my-cart-02`文件夹中的方案。

# 数据传播

`ProductList`组件，我们在上一节中定义的，是不切实际的。让我们再次看看它：

```jsx
import React from 'react';
import './ProductList.css';

class ProductList extends React.Component {
  render() {
    return <ul>
      <li>
        <h3>Traditional Merlot</h3>
        <p>A bottle of middle weight wine, lower in tannins (smoother), 
           with a more red-fruited flavor profile.</p>
      </li>
      <li>
        <h3>Classic Chianti</h3>
        <p>A medium-bodied wine characterized by a marvelous freshness with 
           a lingering, fruity finish</p>
      </li>
      <li>
        <h3>Chardonnay</h3>
        <p>A dry full-bodied white wine with spicy, bourbon-y notes in an 
           elegant bottle</p>
      </li>
      <li>
        <h3>Brunello di Montalcino</h3>
        <p>A bottle of red wine with exceptionally bold fruit flavors, high 
           tannin, and high acidity</p>
      </li>
      </ul>;
   }
}

export default ProductList;
```

列表项都是作为 JSX 标记定义的，因此，如果您需要更改目录产品的图形外观，则需要更改每个`<li>`元素的所有出现位置。

我们可以通过进一步分解用户界面来实现更好的实现。我们可以将每个列表项视为一个组件，并将`Product`组件视为以下代码定义的组件：

```jsx
import React from 'react';

class Product extends React.Component {
  render() {
    return <li>
      <h3>Product name</h3>
      <p>Product description</p>
    </li>;
  }
}

export default Product;
```

这段代码作为每个列表项的模板，以便我们可以动态构建我们的产品列表，如下所示：

```jsx
import React from 'react';
import './ProductList.css';
import Product from './Product';

class ProductList extends React.Component {
  render() {
    let products = [
      {code:"P01", name: "Traditional Merlot", description: "A bottle 
       of middle weight wine, lower in tannins (smoother), with a 
       more red-fruited flavor profile."},
      {code:"P02", name: "Classic Chianti", description: "A medium-bodied
       wine characterized by a marvelous freshness with a lingering, 
       fruity finish"},
      {code:"P03", name: "Chardonnay", description: "A dry full-bodied
       white wine with spicy, bourbon-y notes in an elegant bottle"},
      {code:"P04", name: "Brunello di Montalcino", description: "A bottle
       of red wine with exceptionally bold fruit flavors, high tannin,
       and high acidity"}
    ];
    let productComponents = [];

    for (let product of products) {
      productComponents.push(<Product/>);
    }

    return <ul>{productComponents}</ul>;
  }
}

export default ProductList;
```

我们可以看到一个对象数组的定义，`products`，包含每个产品的相关数据。第二个数组，`productComponents`，将包含由合并产品数据与`Product`组件的标记创建的 React 组件列表。`for`循环旨在执行此类合并。最后，将返回包围在`<ul>`元素中的结果`productComponents`数组。

即使代码结构看起来是正确的，结果也不会如预期。实际上，我们将得到一个具有固定名称和描述的项列表，这些名称和描述是我们放在`Product`组件定义中的。换句话说，数据与组件定义的合并没有发生。

实际上，我们需要一种方法将每个产品的数据传递给`Component`类。让我们将 React 组件视为普通的 JavaScript 函数。它们可以实现为返回 React 元素的函数，并且，与任何函数一样，组件可以有数据输入。这种数据输入通过 JSX 属性传递，并且可以在组件内部通过一个特殊的对象`**props**`访问。让我们更改`ProductList`组件的代码，以便通过 JSX 属性传递数据：

```jsx

import React from 'react';
import Product from './Product';

class ProductList extends React.Component {
  render() {
    let products = [
      {code:"P01", name: "Traditional Merlot", description: "A bottle
       of middle weight wine, lower in tannins (smoother), with a 
       more red-fruited flavor profile."},
      {code:"P02", name: "Classic Chianti", description: "A medium-bodied
       wine characterized by a marvelous freshness with a lingering, 
       fruity finish"},
      {code:"P03", name: "Chardonnay", description: "A dry full-bodied
       white wine with spicy, bourbon-y notes in an elegant bottle"},
      {code:"P04", name: "Brunello di Montalcino", description: "A bottle
       of red wine with exceptionally bold fruit flavors, high tannin, 
       and high acidity"}
    ];

    let productComponents = [];

    for (let product of products) {
      productComponents.push(<Product
      item={product}/>);
    }

    return <ul>{productComponents}</ul>;
  }
}

export default ProductList;
```

我们在`<Product>`标签上添加了一个`item`属性，并将`products`数组中的单个对象分配给它。这允许我们将每个产品的数据传递给`Product`组件。

另一方面，我们修改了`Product`组件的代码，以便接收和管理传递的数据：

```jsx
import React from 'react';

class Product extends React.Component {
  render() {
    return <li>
      <h3>{this.props.item.name}</h3>
      <p>{this.props.item.description}</p>
    </li>;
  }
}

export default Product;
```

你可以在`Code/Chapter-2/my-shop-04`文件夹中找到一个准备好的项目。

每个 React 组件都有一个`props`属性。这个属性的目的是收集传递给组件本身的数据输入。每当将 JSX 属性附加到 React 元素时，具有相同名称的属性就会附加到`props`对象上。因此，我们可以通过使用附加的属性来访问传递的数据。在我们的例子中，我们找到了通过`item`属性传递的产品数据映射到`this.props.item`属性。

`props`是不可变的；也就是说，它们是只读属性。

这种新的实现方式允许目录像以前一样显示，但使图形标记独立于产品的数据。

在组件层次结构中，数据传播非常重要。它允许我们将组件视为具有输入和输出的函数。此外，`props`的不变性允许我们将组件视为纯函数，这些函数是没有副作用的函数（因为它们不改变其输入数据）。我们可以将从一个组件到另一个组件的数据传递视为**单向数据流**，从父组件流向子组件。这为我们提供了一个更可控的系统。

下图显示了我们如何理想地想象组件层次结构中的数据传播：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/bg-react/img/4e8e2c52-6d4e-4ebc-969a-497971c28dfb.png)

状态的变化会导致数据通过`props`属性向子组件传播。

# 活动：创建购物车项组件

**场景**

我们希望将`CartList`组件变为一个动态组件，以便它能够根据接收到的数据调整其内容。

**目标**

这项活动的目的是组合 React 组件并在它们之间传递数据。

**完成步骤**

1.  创建一个显示商品名称的`CartItem`组件。

1.  更改之前创建的`CartList`组件，使其根据`items`数组动态地由`CartItem`实例组成。

**解决方案**

一个可能的解决方案是包含在`Code/Chapter-2/my-cart-03`文件夹中的那个。

# 管理内部状态

组件具有存储随时间变化的数据的能力。

当组件显示随时间变化，的数据时，我们希望尽快显示更改。例如，考虑`ProductList`组件：它显示`products`数组中的产品列表。如果向数组添加新产品，我们希望它立即显示。React 提供了一种机制来支持数据变化时组件的自动渲染。这种机制基于**状态**的概念。

React `state`是一个代表随时间变化的数据的属性。每个组件都支持`state`属性，但应谨慎使用。

再次考虑`ProductList`组件：

```jsx
import React from 'react';
import Product from './Product';

class ProductList extends React.Component {
  render() {
    let products = [
      {code:"P01", name: "Traditional Merlot", description: "A bottle
       of middle weight wine, lower in tannins (smoother), with a more 
       red-fruited flavor profile."},
      {code:"P02", name: "Classic Chianti", description: "A medium-bodied
       wine characterized by a marvelous freshness with a lingering, 
       fruity finish"},
      {code:"P03", name: "Chardonnay", description: "A dry full-bodied 
       white wine with spicy, bourbon-y notes in an elegant bottle"},
      {code:"P04", name: "Brunello di Montalcino", description: "A bottle
       of red wine with exceptionally bold fruit flavors, high tannin, 
       and high acidity"}
    ];

    let productComponents = [];

    for (let product of products) {
      productComponents.push(<Product item={product}/>);
    }

    return <ul>{productComponents}</ul>;
  }
}

export default ProductList;
```

从实用的角度来看，这并不那么有用。它显示了一个硬编码的产品列表。如果我们想添加新产品，我们需要修改组件源代码。

在现实世界场景中，我们希望保持组件代码独立于产品数据。例如，我们会通过向 Web 服务器发出 HTTP 请求来获取产品数据。在这种情况下，`products`数组代表随时间变化，的数据：最初是一个空数组，然后会填充从服务器接收的产品数据，并且可以通过后续对服务器的请求再次更改。

存储随时间变化，的数据的组件被称为**有状态组件**。有状态组件将状态存储在`this.state`属性中。要通知组件状态已更改，必须使用`setState()`方法。此方法为组件设置新状态；它不更新它。状态的变化触发组件的渲染；即`render()`方法的自动执行。

让我们看看如何通过更改`ProductList`组件定义来管理状态：

```jsx
import React from 'react';
import Product from './Product';

class ProductList extends React.Component {
  constructor() {
 super();
 this.state = { products: [] };

 fetch("products.json")
 .then(response => response.json())
 .then(json => {this.setState({products: json})})
 .catch(error => console.log(error));
 }

  render() {
    let productComponents = [];

    for (let product of this.state.products) {
      productComponents.push(<Product item={product}/>);
    }
    return <ul>{productComponents}</ul>;
  }
}
export default ProductList;
```

我们向组件添加了构造函数。构造函数运行超类构造函数，并将组件的初始状态设置为具有`products`属性的空数组的对象。

然后，通过`fetch()`向服务器发送 GET HTTP 请求。由于请求是异步的，组件的初始渲染将是一个空的产品列表。

状态初始化是唯一可以不使用`setState()`而直接给`this.state`属性赋值的情况。

当接收到 HTTP 响应时，它用于通过`setState()`更改组件的状态。这种状态变化导致`render()`的自动执行，这将显示从服务器接收的产品列表。

既然我们已经知道如何管理组件的状态，那么在使用`setState()`方法时，有几点需要记住：

+   `setState()`将新数据与状态中已有的旧数据合并，并覆盖先前的状态。

+   `setState()`触发`render()`方法的执行，因此您永远不应该显式调用`render()`。

组件状态管理看似非常简单。然而，在决定什么应该被视为状态以及哪个组件应该是有状态的时，很容易陷入困境。

以下是关于状态的一些建议：

+   状态应包含 UI 中随时间变化，所需的最小数据；任何可以从这些最小数据中推导出的信息都应在`render()`方法内部计算。

+   应尽可能避免使用状态，因为它会给组件增加复杂性。

+   有状态的组件应该位于 UI 组件层次结构的高层。

我们可以将最后一条建议视为第二条建议的后果。如果我们应该限制使用状态，我们应该减少有状态组件的数量。因此，将状态组件的角色分配给用户界面中组件层次结构的根组件是一个很好的规则。你还记得我们在上一章中讨论的将组件分为展示组件和容器组件的分类吗？通常，容器组件是有状态组件的良好候选者。

在我们的示例应用程序中，我们将有状态组件的角色分配给了`ProductList`组件。即使它是一个容器组件，它也不是应用程序组件层次结构中最高的。也许这个角色更适合`Catalog`组件。在这种情况下，我们应该将获取数据的逻辑移到`Catalog`组件内部，如下面的代码所示：

```jsx
import React from 'react';
import './Catalog.css';
import ProductList from './ProductList';

class Catalog extends React.Component {
  constructor() {
    super();
    this.state = { products: [] };

    fetch("products.json")
      .then(response => response.json())
      .then(json => {this.setState({products: json})})
      .catch(error => console.log(error));
  }

  render() {
    return <div><h2>Wine Catalog</h2><ProductList 
 items={this.state.products}/></div>;
  }
}

export default Catalog;
```

你可以在`Code/Chapter-2`下的`my-shop-05`文件夹中找到一个准备好的项目。

# 活动：向购物车组件添加状态管理。

**场景**

为了使`Cart`组件准备好投入生产，我们添加了状态管理和动态数据加载。

**目标**

该活动的目的是熟悉组件状态管理。

**完成步骤**

将之前创建的`Cart`组件更改为添加状态管理，以便通过 HTTP 请求加载数据，并且购物车的内容会自动更新。

**解决方案**

一个可能的解决方案包含在`Code/Chapter-2/`下的`my-cart-04`文件夹中。

# 总结

在本章中，我们开始创建 React 组件并探索它们的基本功能。特别是，我们：

+   学习了如何将组件定义为从`React.Component`派生的类，以及如何导入特定的 CSS 样式。

+   探索了 JSX 语法，它允许我们快速定义组件的图形方面，并使用在其他地方定义的 React 组件。

+   组合 React 组件以构建其他组件。

+   使用状态管理功能，以便 React 组件在数据变化时自动更新其视觉表示。

在下一章中，我们将分析如何管理用户与基于 React 的应用程序的交互；换句话说，如何捕获事件并使 UI 对这些事件做出反应。


# 第三章：管理用户交互性

在本章中，我们将学习如何管理由用户与 React 基础用户界面的组件交互产生的事件。我们将探讨在 React 组件生命周期中触发的事件，并学习如何利用它们来创建高效的组件。最后，我们将使用 React Router 库来允许在由组件实现的不同的视图之间轻松导航。

在本章结束时，你将能够：

+   处理由用户交互产生的事件

+   在事件触发时更改组件的状态

+   使用组件的生命周期事件以获得更好的用户体验

+   配置路由以允许通过组件进行导航

# 管理用户交互

任何 Web 应用程序都需要用户与**用户界面**（**UI**）之间的交互。没有交互的应用程序不是真正的应用程序；交互性是一个基本要求。

我们在上一章构建的应用程序不允许交互。它只是显示数据，用户无法对其进行任何操作（除了查看）。

假设我们想在上一章开始构建的目录应用程序中引入一点交互。例如，也许我们想在用户点击产品区域时显示一个带有产品价格的警告。

假设产品数据包括价格，如下面的 JSON 对象所示：

```jsx
[
  {"code":"P01", 
   "name": "Traditional Merlot", 
   "description": "A bottle of middle weight wine, lower in tannins
      (smoother), with a more red-fruited flavor profile.", 
   "price": 4.5, "selected": false},
  {"code":"P02", 
   "name": "Classic Chianti", 
   "description": "A medium-bodied wine characterized by a marvelous
      freshness with a lingering, fruity finish", 
   "price": 5.3, "selected": false},
  {"code":"P03", 
   "name": "Chardonnay", 
   "description": "A dry full-bodied white wine with spicy, 
      bourbon-y notes in an elegant bottle", 
   "price": 4.0, "selected": false},
  {"code":"P04", 
   "name": "Brunello di Montalcino", 
   "description": "A bottle of red wine with exceptionally bold fruit 
      flavors, high tannin, and high acidity", 
   "price": 7.5, "selected": false}
]
```

我们可以如下实现这种行为：

```jsx
import React from 'react';

class Product extends React.Component {
  showPrice() {
 alert(this.props.item.price);
 }

  render() {
    return <li onClick={() => this.showPrice()}>
      <h3>{this.props.item.name}</h3>
      <p>{this.props.item.description}</p>
    </li>;
  }
}

export default Product;
```

让我们分析组件的代码，并强调与前一个版本的不同之处。

首先，我们添加了`showPrice()`方法，通过一个警告框显示当前产品实例的价格。这个方法在箭头函数内部被调用，该箭头函数被分配给`<li>`标签的`onClick`属性。

这些简单的更改允许`Product`组件捕获`click`事件并执行`showPrice()`方法。

现在我们将打开现有的项目`my-shop-01`，以展示之前的代码更改的结果：

1.  打开一个控制台窗口

1.  转到`my-shop-01`文件夹

1.  运行`npm install`

1.  运行`npm start`

点击产品的结果显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/bg-react/img/4f5a555a-4d0e-43e1-ad83-5f723cf29071.png)

# HTML 事件与 React 事件

正如我们所见，React 处理事件的方法与 HTML 中的经典事件管理非常相似。然而，有一些细微的差别需要注意。

HTML 事件使用小写字母命名，而 JSX 事件使用驼峰命名法。例如，在 HTML 中，你应该使用以下语法：

```jsx
<li onclick="...">...</li>
```

但在 JSX 中，你使用这种语法：

```jsx
<li onClick=...>...</li>
```

在 HTML 中，你分配一个代表函数调用的字符串，而在 JSX 中，你分配一个函数，如下所示：

```jsx
<li onclick="showPrice()">...</li>
<li onClick={showPrice}>...</li>
```

当然，你可以分配任何返回或代表函数的 JavaScript 表达式，如下例所示：

```jsx
<li onClick={() => this.showPrice()}>
```

最后，您可以通过返回`false`来阻止大多数 HTML 事件的默认行为，而在 JSX 事件中，您需要显式调用`preventDefault`。以下是一个典型示例：

```jsx
<a href="#" onClick={(e) => { e.preventDefault();
console.log("Clicked");}}>Click</a>
```

# Event Handlers 和 this 关键字

在前面的定义`Product`组件的示例中，我们将箭头函数分配给了`onClick`属性，而不是简单的`showPrice()`方法。这不仅仅是一个偏好问题。这是必要的，因为我们使用了`showPrice()`方法内部的`this`关键字。

实际上，当事件处理程序执行时，`this`关键字不再绑定到`Product`类，因为它是在不同的上下文中异步执行的。这种行为不依赖于 React，而是依赖于 JavaScript 的工作方式。

为了将方法绑定到当前类，我们有几个选项：

1.  使用箭头函数并在其体内调用方法，如下例所示：

```jsx
<li onClick={() => this.showPrice()}>
```

1.  使用`bind()`方法将方法绑定到当前类上下文，如下例所示：

```jsx
<li onClick={this.showPrice.bind(this)}>
```

1.  您可以在类构造函数中使用`bind()`，而不是在将方法分配给事件属性时内联使用。以下是这种方法的示例：

```jsx
constructor() {
this.showPrice = this.showPrice.bind(this);
}
...
<li onClick={this.showPrice}>
```

# 更改状态

我们看过的这个事件管理示例非常简单，但它只展示了 React 事件管理的基础。这个示例不涉及状态，其管理是直接的。在许多现实世界的情况下，一个事件导致应用程序状态的变化，这意味着组件状态的变化。

假设，例如，您想允许从目录中选择产品。为此，我们为每个产品对象添加`selected`属性，如下面的数组所示：

```jsx
[
  {"code":"P01", 
   "name": "Traditional Merlot", 
   "description": "A bottle of middle weight wine, lower in tannins
      (smoother), with a more red-fruited flavor profile.", 
   "price": 4.5, "selected": false},
  {"code":"P02", 
   "name": "Classic Chianti", 
   "description": "A medium-bodied wine characterized by a marvelous
      freshness with a lingering, fruity finish", 
   "price": 5.3, "selected": false},
  {"code":"P03", 
   "name": "Chardonnay", 
   "description": "A dry full-bodied white wine with spicy, bourbon-y
      notes in an elegant bottle", 
   "price": 4.0, "selected": false},
  {"code":"P04", 
   "name": "Brunello di Montalcino", 
   "description": "A bottle of red wine with exceptionally bold fruit
      flavors, high tannin, and high acidity", 
   "price": 7.5, "selected": false}
]  
```

当用户点击产品区域时，`selected`属性的值会切换，并且区域背景颜色会改变。以下代码片段展示了`Product`组件的新版本：

```jsx
import React from 'react';
import './Product.css'

class Product extends React.Component {
  select() {
 this.props.item.selected = !this.props.item.selected;
 }

  render() {
    let classToApply = this.props.item.selected? "selected": "";

    return <li onClick={() => this.select()} className={classToApply}>
             <h3>{this.props.item.name}</h3>
             <p>{this.props.item.description}</p>
           </li>;
  }
}

export default Product;
```

`select()`方法切换`selected`属性的值，而在渲染方法中，我们根据`selected`属性的值计算要应用的类的名称。然后，生成的类名被分配给`className`属性。

意外地，这段代码没有正确工作。您可以通过执行以下步骤来验证。我们可以打开现有项目`my-shop-02`，以便查看之前代码的结果。请按照以下步骤操作：

1.  打开一个控制台窗口

1.  转到`my-shop-02`文件夹

1.  运行`npm install`

1.  运行`npm start`

代码没有按预期工作，因为`select()`方法没有改变组件的状态，所以`render()`方法没有被触发。此外，请记住`props`属性是只读的，因此对其的任何更改都不会产生影响。

`Product`组件是一个无状态组件，因此我们没有状态需要改变。产品的数据来自通过`props`传递的`Catalog`根组件。那么，我们如何从`Product`组件实例触发的事件开始改变`Catalog`组件的状态呢？

具体来说，子组件如何改变其父组件的状态？

实际上，子组件没有机会改变父组件的状态，因为在 React 组件层次结构中，数据以单向方式流动，从父组件流向子组件。我们在下面的图表中说明了这种流动：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/bg-react/img/e619f805-e32d-446c-9b2b-f9bd1d036e19.png)

我们不能将数据从子组件推送到父组件。为了让子组件改变父组件的状态，我们需要获取一个方法来操作该状态。由于组件状态只能由组件本身访问，因此父组件必须通过`props`属性向其子组件提供该方法。

考虑以下代码：

```jsx
import React from 'react';
import './Catalog.css';
import ProductList from './ProductList';

class Catalog extends React.Component {
  constructor() {
    super();
    this.state = { products: [] };

    fetch("products.json")
      .then(response => response.json())
      .then(json => {this.setState({products: json})})
      .catch(error => console.log(error));
  }

  select(productCode) {
 let productList = this.state.products.map(function(p) {
 if (p.code === productCode) {
 p.selected = (!p.selected);
 }
 return p;
 });
 this.setState({products: productList});
 }

  render() {
    return <div><h2>Wine Catalog</h2><ProductList 
      items={this.state.products} selectHandler={this.select}/></div>;
  }
}

export default Catalog;
```

前面的代码将`select()`方法添加到`Catalog`组件中。该方法接受一个产品代码作为输入参数，从组件的状态中获取产品列表，并更新相应产品的`selected`属性。然后使用新的产品列表更新组件的状态。

`select()`方法被分配给`ProductList`标签中的新`selectHandler`属性，因此相应的组件可以通过`props`属性访问它。

以下代码展示了如何将`this.props.selectHandler`从`ProductList`组件传递到`Product`组件，通过`selectHandler`属性：

```jsx
import React from 'react';
import './ProductList.css';
import Product from './Product';

class ProductList extends React.Component {
  render() {
    let products = [];

    for (let product of this.props.items) {
      products.push(<Product item={product} 
 selectHandler={this.props.selectHandler}/>);
    }

    return <ul>{products}</ul>;
  }
}

export default ProductList;
```

最后，`Product`组件通过调用通过`this.props.selectHandler`属性传递的`select()`方法来处理`onClick`事件，并使用适当的产品代码：

```jsx
import React from 'react';
import './Product.css'

class Product extends React.Component {
  render() {
    let classToApply = this.props.item.selected? "selected": ""; 
 return <li onClick={() => this.props.selectHandler 
    (this.props.item.code)} className={classToApply}>
      <h3>{this.props.item.name}</h3>
      <p>{this.props.item.description}</p>
    </li>
  }
}

export default Product;
```

现在我们将打开现有的项目`my-shop-03`，以便查看之前代码的结果。请按照以下步骤操作：

1.  打开一个控制台窗口

1.  转到`my-shop-03`文件夹

1.  运行`npm install`

1.  运行`npm start`

我们可以得出结论，子组件上的事件触发了通过`props`传递的父组件方法的执行。该方法改变了父组件的状态，这种变化的效果再次通过`props`传播到子组件。以下图表说明了这种行为：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/bg-react/img/c5f36cd8-28ca-4ccb-a05b-7fd69497a78e.png)

# 活动：将商品添加到购物车

**场景**

我们希望允许用户从产品目录中选择商品并将其添加到购物车中。

**目标**

此活动的目的是熟悉 React 中的事件管理。

**完成步骤**

1.  考虑`my-cart-01`文件夹中的现有项目

1.  处理`Product`组件的“添加到购物车”按钮的点击事件，以便将该商品添加到购物车中

**解决方案**

一个可能的解决方案包含在`Code/Chapter-3/`下的`my-cart-02`文件夹中。

# 组件生命周期事件

在 React 应用程序中，组件根据应用程序运行时的演变动态创建。用户的交互启动了组件的创建、屏幕上的可视化、更新和销毁。

因此，组件在应用程序执行期间经历不同的阶段：这些阶段代表了它们的生命周期。

React 允许我们以自定义的方式拦截和管理组件生命周期的各个阶段，这得益于我们可以通过实现特定方法来处理的一组事件。

在分析组件的生命周期事件之前，我们应该强调，创建组件的第一步是执行其构造函数。虽然它不是 React 生命周期阶段的一部分，但它是组件生命的第一步。在组件构造函数执行期间，DOM 不可用，也无法访问任何子组件。构造函数执行是执行不涉及图形渲染或子组件操作的初始化的正确时机。

组件创建后，React 将触发几个对应于组件生命周期相应阶段的事件。我们可以捕获这些事件并通过在我们的组件中实现一些方法来处理它们。考虑以下方法：

```jsx
componentWillMount
```

这种方法在组件即将被插入到 DOM 中时执行。它只被调用一次，就在初始渲染发生之前。通常，这个方法用于执行与 DOM 无关的组件初始化，例如初始化组件的属性或本地变量。

你可以在`componentWillMount()`中使用`setState()`方法，但它不会触发组件的重新渲染，所以要谨慎使用。

`componentWillReceiveProps`是在组件通过`props`从父组件接收到新值之前渲染时调用的方法。这个方法接收新值作为参数，我们可以通过`this.props`访问旧值。

如果我们尝试在这个方法执行期间改变组件状态，我们将不会触发任何额外的渲染。此外，`componentWillReceiveProps()`在初始渲染时不会被调用。

`shouldComponentUpdate`方法应该返回一个布尔值，表示组件是否应该被渲染（`true`）或不渲染（`false`）。如果该方法返回`false`，则不会调用下一个方法，包括`render()`。

它有两个参数：`nextProps`，包含`props`的新值，以及`nextState`，包含组件状态的新值。

`componentWillUpdate`在`render()`方法之前立即被调用，因此它是更新组件之前执行某些处理的最后机会。

在`shouldComponentUpdate()`的实现中不能使用`setState()`。

`componentDidUpdate`在渲染发生后立即调用，在其执行期间，我们可以访问 DOM 中组件的新版本。该方法有两个参数：之前的`props`和之前的状态。

`componentDidMount`在组件被插入到 DOM 后调用，并且只调用一次。

`componentWillUnmount`在组件从 DOM 中移除之前立即调用。

在这个方法执行期间，你不能使用`setState()`。

我们可以将组件生命周期事件分为三个主要区域：

+   **挂载**：这个`props`组包含与 DOM 操作相关的事件：`componentWillMount`、`componentDidMount`和`componentWillUnmount`

+   **通过 props 更新**：这个组包含当组件通过其父组件传递的`props`更新时触发的事件，包括：`componentWillReceiveProps`、`shouldComponentUpdate`、`componentWillUpdate`和`componentDidUpdate`。

+   **通过 setState()更新**：在这个组中，我们找到当组件通过`setState()`更新时触发的事件：`shouldComponentUpdate`、`componentWillUpdate`和`componentDidUpdate`。

下面的图表说明了事件流，并使用不同的颜色突出了我们刚刚讨论的三个区域：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/bg-react/img/77905891-cf29-46ca-a169-f0453358e90b.png)

# 活动：显示添加到购物车的商品数量

**场景**

我们希望避免购物车中出现同一产品的多个实例。相反，我们希望购物车中只有单一产品及其数量的出现，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/bg-react/img/c60ffc2b-daab-4b7b-be17-7fd2b6b772b0.png)

**目标**

这个活动的目的是利用 React 组件的生命周期事件。

**完成步骤**

1.  利用在前一个活动中更改的项目（或在`my-cart-02`文件夹中的现有项目）。

1.  更改`Cart`组件以显示一个无重复产品的列表及其相关出现次数。

处理`componentWillReceiveProps`事件，为`Cart`组件的内部状态准备数据。

**解决方案**

一个可能的解决方案是在`Code/Chapter-3`中的`my-cart-03`文件夹中包含的解决方案。

# 管理路由

基于单页应用程序模型的现代 Web 应用程序，不能没有路由机制，这是一种在同一 HTML 页面上浏览视图的方式。

我们可以将视图视为 UI 中的一个占位符，在其中我们可以动态地渲染一个组件或另一个组件，以独占的方式。让我们尝试用一个例子来澄清这个概念。

假设我们想在我们的*葡萄酒目录*应用程序中添加一个导航栏。在最简单的实现中，我们想交替显示目录和一个关于部分，提供一些关于应用程序本身的信息。新的 UI 将如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/bg-react/img/73e59b33-0f9c-4a43-9024-556c5bca4ea7.png)

当点击菜单项时，我们希望主区域发生变化，而头部保持不变。在这种情况下，主区域将是我们显示`Catalog`组件或`About`组件的视图，具体取决于我们点击的菜单项。

我们如何在 React 中实现路由机制？

# 安装 React Router

我们可以通过使用**React Router**，一个为我们提供特定 React 组件的包，来启用基于 React 的应用程序的路由，这些组件允许我们设置一个完整的路由系统。

我们在应用程序的文件夹中输入以下命令来安装该包：

```jsx
npm install --save react-router-dom
```

React Router 提供了三个包：

+   `react-router`

+   `react-router-dom`

+   `react-router-native`

第一个包提供了核心路由组件和功能。第二个包为浏览器环境提供了特定组件，第三个包支持`react-native`，这是一个将 React 组件映射到原生移动 UI 小部件的环境。`react-router-dom`和`react-router-native`都使用`react-router`功能。

# 使用路由器

一旦我们在环境中安装了 React Router 包，我们需要在应用程序中使用提供的组件。

首先，我们需要为应用程序添加路由功能。我们可以通过更改`index.js`文件的代码来实现这一点，如下所示：

```jsx
import React from 'react';
...
import { BrowserRouter } from 'react-router-dom'

ReactDOM.render(
  <BrowserRouter>
    <App />
  </BrowserRouter>
  , document.getElementById('root'));
registerServiceWorker();
```

我们强调了与前一版本代码的主要区别。如您所见，我们从`react-router-dom`模块导入了`BrowserRouter`组件，并将其包裹在`App`组件内部。

通过包装`App`组件，`BrowserRouter`组件为其赋予了路由功能。

这是一个组件组合，因此我们称之为组件包装。

# 定义视图

现在，我们需要创建一个视图来显示`Catalog`组件或关于页面，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/bg-react/img/9aded227-73da-4ec8-9c1d-a9109033be9b.png)

我们可以通过更改`App.js`代码来实现这一点，如下所示：

```jsx
import React, { Component } from 'react';
import './App.css';
import Catalog from './Catalog';
import About from './About';
import { Switch, Route } from 'react-router-dom'

class App extends Component {
  render() {
    return (
      <div className="App">
        <header className="App-header">
          <h1 className="App-title">The Catalog App</h1>
          <nav>
            <ul>
              <li><Link to='/'>Catalog</Link></li>
              <li><Link to='/about'>About</Link></li>
            </ul>
          </nav>
        </header>
        <Switch>
 <Route exact path='/' component={Catalog}/>
 <Route path='/about' component={About}/>
 </Switch>
      </div>
    );
  }
}

export default App;
```

我们从`react-router-dom`模块导入了`Switch`和`Route`组件，并在 JSX 表达式中使用了它们，该表达式曾经是`Catalog`元素所在的位置。

`Switch`组件允许我们定义一个视图，即我们将在其中切换组件的区域。`Route`组件用作`Switch`的子元素，它们允许我们将 URL 映射到组件。在我们的示例中，我们将根 URL（`/`）映射到`Catalog`组件，将`/about` URL 映射到`About`组件。这意味着当`BrowserRouter`拦截到移动到这些 URL 之一的请求时，它将在视图中渲染适当的组件。

允许我们显示目录或应用程序信息的导航栏实现如下：

```jsx
import React, { Component } from 'react';
import './App.css';
import Catalog from './Catalog';
import About from './About';
import { Switch, Route, Link } from 'react-router-dom'

class App extends Component {
  render() {
    return (
      <div className="App">
        <header className="App-header">
          <h1 className="App-title">The Catalog App</h1>
          <nav>
 <ul>
 <li><Link to='/'>Catalog</Link></li>
 <li><Link to='/about'>About</Link></li>
 </ul>
 </nav>        </header>
        <Switch>
          <Route exact path='/' component={Catalog}/>
          <Route path='/about' component={About}/>
        </Switch>
      </div>
    );
  }
}

export default App;
```

在这里，我们添加了对`Link`组件的导入，并在突出显示的标记中使用了它。`Link`组件允许我们创建一个超链接元素，该元素将被`BrowserRouter`组件捕获。

这些更改为我们的应用程序添加了一个可用的导航栏。您可以通过执行以下步骤来查看这些更改的结果。

我们将打开现有的项目`my-shop-04`，以展示前面代码的结果：

1.  打开一个控制台窗口

1.  转到`my-shop-04`文件夹

1.  运行`npm install`

1.  运行`npm start`

# 关于路由组件的一些注意事项

请注意，`Route`组件具有`path`属性（允许我们指定要映射的 URL）和`component`属性（允许我们分配要在当前视图中渲染的组件）：

```jsx
<Switch>
<Route exact path='/' component={Catalog}/>
<Route path='/about' component={About}/>
</Switch>
```

`path`属性用于 React Router 来检测要渲染的组件，如相应的`component`属性所指定。

在前面的路由映射中，如果我们点击与`/about` URL 关联的`Link`组件，具有根路径（`/`）的路由将匹配`/about`的起始部分，并且`Catalog`组件将被渲染。

当用户通过点击`Link`组件请求 URL 时，路由列表会按顺序扫描以找到与 URL 起始部分匹配的路径值。第一个匹配的值决定了要渲染的组件。

如果我们想要在`path`属性的值和 URL 之间进行严格比较，我们需要指定`exact`属性，如下所示：

```jsx
<Switch>
<Route exact path='/' component={Catalog}/>
<Route path='/about' component={About}/>
</Switch>
```

这可以防止任何以`/`开头的 URL 被第一个路由捕获。

`Route`组件的`component`属性允许我们指定要渲染的组件。或者，我们可以使用`render`属性来指定调用一个返回 React 元素的函数，如下例所示：

```jsx
<Route path='/about' render={() => (<About data={someData}/>)}/>
```

这种方法类似于使用`component`属性，但它可能对于内联渲染和当我们需要向元素传递值时很有用。

路由组件还允许我们指定`children`属性。与`render`一样，我们可以将一个函数赋给这个属性，但该函数返回的元素将*始终*被渲染，无论路径是否匹配。

考虑以下示例：

```jsx
<Switch>
<Route exact path='/' component={Catalog}/>
<Route path='/about' component={About}/>
<Route path='/footer' children={() => (<Footer />)}/>
</Switch>
```

`Footer`组件将始终被渲染，即使路径`/footer`不匹配。

# 嵌套视图

在前面的示例中，我们通过使用 React Router 提供的`Switch`、`Route`和`Link`组件，在`App`组件中实现了视图导航。我们可以在任何其他组件中使用这些路由组件，以便我们可以构建嵌套视图和嵌套路由。

让我们尝试用一个例子来说明这一点。假设我们想在我们的应用程序中添加一个酿酒师列表。我们可以在导航栏中添加一个新项，允许我们导航到一个显示该列表的页面。

以下屏幕截图显示了新布局的外观：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/bg-react/img/27b9a00c-cc5f-4cf9-9130-728896366abe.png)

因此，让我们更改`App`组件的 JSX 标记，如下所示：

```jsx
import React, { Component } from 'react';
import './App.css';
import Catalog from './Catalog';
import About from './About';
import WineMakers from './WineMakers';
import { Switch, Route, Link } from 'react-router-dom';

class App extends Component {
  render() {
    return (
      <div className="App">
        <header className="App-header">
          <h1 className="App-title">The Catalog App</h1>
          <nav>
            <ul>
              <li><Link to='/'>Catalog</Link></li>
              <li><Link to='/winemakers'>WineMakers</Link></li>
              <li><Link to='/about'>About</Link></li>
            </ul>
          </nav>
        </header>
        <Switch>
          <Route exact path='/' component={Catalog}/>
          <Route path='/winemakers' component={WineMakers}/>
          <Route path='/about' component={About}/>
        </Switch>
      </div>
    );
  }
}

export default App;
```

我们导入了`WineMakers`组件，定义了一个将`/winemakers`路径映射到新组件的路由，并添加了一个链接以导航到它。

我们可以如下实现酿酒师列表：

```jsx
import React from 'react';
import WineMaker from './WineMaker';
import { Switch, Route, Link } from 'react-router-dom';

class WineMakers extends React.Component {
  renderWineMakersList() {
    return <ul>
  ...
        <Link to="/winemakers/WM2">Wine & Co</Link>
      </li>
    </ul>;
  }

  render() {
    return <Switch>
    ...

export default WineMakers;
```

`WineMakers`组件具有`renderWineMakersList()`方法，该方法返回实现每个酿酒师链接列表的 React 元素。此方法用作组件`render()`方法中与`/winemakers`路径匹配的路由的`render`属性的值。其他路由获取指向每个特定酿酒师的路径，并根据标识码渲染`WineMaker`组件。

您可能会注意到，我们正在`WineMakers`组件中实现一个视图，该视图显示在`App`组件中实现的视图内。换句话说，我们通过组合实现视图的组件来实现嵌套视图。

# 路径参数

`WineMakers`组件的`render()`方法如下实现最终视图：

```jsx
render() {
  return <Switch>
    <Route exact path='/winemakers' render={this.renderWineMakersList}/>
    <Route path='/winemakers/WM1' render={() => (<WineMaker code='WM1' />}/>
    <Route path='/winemakers/WM2' render={() => (<WineMaker code='WM2' />}/>
  </Switch>;
}
```

这段代码很简单，而且有效，但它迫使我们每当在我们的列表中添加新的酿酒师时都要添加一个新的路由。

我们可以通过使用`path`参数来避免这种情况，如下面的代码所示：

```jsx
render() {
  return <Switch>
    <Route exact path='/winemakers' render={this.renderWineMakersList}/>
    <Route path='/winemakers/:code' component={WineMaker}/>
  </Switch>;
}
```

如您所见，我们现在可以通过指定`:code`参数来使用指向特定酿酒师的单个路由。路径表达式中的冒号表示 URL 的后续部分是变量值。您可能还会注意到，我们使用了`component`属性而不是`render`属性。实际上，在这种情况下，我们不需要将酿酒师的代码显式传递给`WineMaker`组件。React Router 为我们做到了这一点，通过在`props`属性中提供一个特殊对象。

让我们看一下`WineMaker`组件的实现：

```jsx
import React from 'react';

class WineMaker extends React.Component {
  constructor() {
    super();
    this.wineMakers = [
      {code: "WM1", name: "Wine & Wine", country: "Italy",
      description:"Wine & Wine produces an excellent Italian wine..."},

export default WineMaker;
```

在组件的构造函数中，我们将酿酒师列表定义为对象数组。

在`render()`方法中，我们通过将数组中每个`winemaker`对象的`code`属性与`match.params.code`属性（由`this.props`提供）进行比较来查找要显示的酿酒师。

我们将`winemakers`列表实现为`WineMaker`组件的属性，而不是`state`对象的属性，因为由于列表嵌入到代码中并且不应该更改，我们不需要将其实现为`state`属性。请记住，我们只将随时间变化，我们只将随时间变化的数据标识为状态。

我们找到的对象用于适当地渲染有关`WineMaker`的数据。

通常，通过路由到达的 React 组件在`this.props`属性中接收`match`对象。该对象包含有关`Route`定义中匹配路径的信息。特别是，`match`对象的以下属性可用：

+   `params`：这是一个对象，其属性与路径中的参数匹配；也就是说，动态部分，前面有冒号

+   `isExact`：这是一个布尔值，指示 URL 是否与路径匹配

+   `path`：这是分配给所选路由的`path`属性的字符串

+   `url`：这是与路由路径匹配的 URL

通过执行以下步骤，我们可以看到最终结果。我们打开现有的项目`my-shop-05`，以展示之前代码的结果：

1.  打开一个控制台窗口

1.  转到`my-shop-05`文件夹

1.  运行`npm install`

1.  运行`npm start`

# 活动：添加有关运输方法的视图

**场景**

我们希望在我们的目录应用中添加一个包含有关可用运输方法信息的章节。

**目标**

本活动的目的是探索 React 路由提供的组件。

**完成步骤**

1.  考虑在前一活动中更改的项目（或位于`my-cart-03`文件夹中的现有项目）。

1.  创建一个`ShippingMethods`组件，显示可用运输方法的列表，以及一个`ShippingMethod`组件，根据通过`props`传递的代码显示每个运输方法的详细信息（可用的运输方法包括**经济配送**（**ECO**）、**标准配送**（**STD**）和**快递配送**（**EXP**））。

1.  创建一个导航栏和一个路由配置，允许我们在`Catalog`和`Shipping`方法视图之间导航。

**解决方案**

一个可能的解决方案是位于`Code/Chapter-3`中的`my-cart-04`文件夹中的那个。

# 总结

在本章中，我们学习了如何管理用户交互。特别是，我们涵盖了以下内容：

+   管理不涉及组件状态变化的事件

+   处理涉及组件状态变化的事件

+   探索了组件生命周期并学习了如何自定义每个阶段

+   使用 React Router 的组件来配置组件之间的导航

本章为本书的结尾。它提供了理解 React 工作原理以及如何构建基于 React 的应用程序的基础知识。我们从 React 的简介开始，然后详细探讨了创建组件的过程。最后，我们研究了如何使用 React 管理用户交互。
