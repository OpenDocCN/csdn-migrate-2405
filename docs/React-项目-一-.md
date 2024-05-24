# React 项目（一）

> 原文：[`zh.annas-archive.org/md5/67d21690ff58712c68c8d6f205c8e0a0`](https://zh.annas-archive.org/md5/67d21690ff58712c68c8d6f205c8e0a0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书将帮助您将 React 知识提升到下一个水平，教您如何应用基本和高级的 React 模式来创建跨平台应用程序。React 的概念以一种既适合新手又适合有经验的开发人员理解的方式进行描述；虽然不需要有 React 的先前经验，但这将有所帮助。

在本书的 12 章中，您将使用 React、React Native 或 React 360 创建一个项目。这些章节中创建的项目实现了流行的 React 功能，如用于重用逻辑的**高阶组件**（HOCs）、用于状态管理的上下文 API 和用于生命周期的 Hooks。用于路由的流行库，如 React Router 和 React Navigation，以及用于编写应用程序的单元测试的 JavaScript 测试框架 Jest。此外，一些更高级的章节涉及 GraphQL 服务器，并且 Expo 用于帮助您创建 React Native 应用程序。

# 本书适合对象

本书适用于希望探索用于构建跨平台应用程序的 React 工具和框架的 JavaScript 开发人员。对 Web 开发、ECMAScript 和 React 的基本知识将有助于理解本书涵盖的关键概念。

本书支持的 React 版本为：

+   React - v16.10.2

+   React Native - v0.59

+   React 360 - v1.1.0

# 本书涵盖的内容

第一章，“在 React 中创建电影列表应用程序”，将探讨构建可扩展的 React 项目的基础。将讨论和实践如何组织文件、使用的包和工具的最佳实践。通过构建电影列表来展示构建 React 项目的最佳方法。此外，使用 webpack 和 Babel 来编译代码。

第二章，“使用可重用的 React 组件创建渐进式 Web 应用程序”，将解释如何在整个应用程序中设置和重用 React 组件中的样式。我们将构建一个 GitHub 卡片应用程序，以了解如何在 JavaScript 中使用 CSS 并在应用程序中重用组件和样式。

第三章，“使用 React 和 Suspense 构建动态项目管理看板”，将介绍如何创建确定其他组件之间数据流的组件，即所谓的 HOCs。我们将构建一个项目管理看板，以了解数据在整个应用程序中的流动。

第四章，使用 React Router 构建基于 SSR 的社区动态，将讨论路由设置，从设置基本路由、动态路由处理，到如何为服务器端渲染设置路由。

第五章，使用 Context API 和 Hooks 构建个人购物清单应用程序，将向您展示如何使用 React 上下文 API 和 Hooks 处理整个应用程序中的数据流。我们将创建一个个人购物清单，以了解如何使用 Hooks 和上下文 API 从父组件到子组件以及反之访问和更改数据。

第六章，使用 Jest 和 Enzyme 构建探索 TDD 的应用程序，将专注于使用断言和快照进行单元测试。还将讨论测试覆盖率。我们将构建一个酒店评论应用程序，以了解如何测试组件和数据流。

第七章，使用 React Native 和 GraphQL 构建全栈电子商务应用程序，将使用 GraphQL 为应用程序提供后端。本章将向您展示如何设置基本的 GraphQL 服务器并访问该服务器上的数据。我们将构建一个电子商务应用程序，以了解如何创建服务器并向其发送请求。

第八章，使用 React Native 和 Expo 构建房屋列表应用程序，将涵盖 React Native 应用程序的扩展和结构，这与使用 React 创建的 Web 应用程序略有不同。本章将概述开发环境和工具（如 Expo）的差异。我们将构建一个房屋列表应用程序，以检验最佳实践。

第九章，使用 React Native 和 Expo 构建动画游戏，将讨论动画和手势，这正是移动应用程序与 Web 应用程序的真正区别。本章将解释如何实现它们。此外，通过构建一个具有动画并响应手势的纸牌游戏应用程序，将展示 iOS 和 Android 之间手势的差异。

第十章 *使用 React Native 和 Expo 创建实时消息应用程序*，将涵盖通知，这对于让应用程序的用户保持最新状态非常重要。本章将展示如何通过 Expo 从 GraphQL 服务器添加通知并发送通知。我们将通过构建消息应用程序来学习如何实现所有这些。

第十一章 *使用 React Native 和 GraphQL 构建全栈社交媒体应用程序*，将介绍如何使用 React Native 和 GraphQL 构建全栈应用程序。演示服务器和应用程序之间的数据流动，以及如何从 GraphQL 服务器获取数据。

第十二章 *使用 React 360 创建虚拟现实应用程序*，将讨论如何通过创建全景查看器来开始使用 React 360，使用户能够在虚拟世界中四处张望并在其中创建组件。

# 为了充分利用本书

本书中的所有项目都是使用 React、React Native 或 React 360 创建的，需要您具备 JavaScript 的基础知识。虽然本书中描述了 React 和相关技术的所有概念，但我们建议您在想要了解更多功能时参考 React 文档。在接下来的部分，您可以找到关于为本书设置您的计算机以及如何下载每一章的代码的一些信息。

# 设置您的计算机

对于本书中创建的应用程序，您需要至少在您的计算机上安装 Node.js v10.16.3，以便您可以运行 npm 命令。如果您尚未在计算机上安装 Node.js，请访问[`nodejs.org/en/download/`](https://nodejs.org/en/download)，在那里您可以找到 macOS、Windows 和 Linux 的下载说明。

安装 Node.js 后，在命令行中运行以下命令以检查已安装的版本：

+   对于 Node.js（应为 v10.16.3 或更高版本）：

```jsx
node -v
```

+   对于 npm（应为 v6.9.0 或更高版本）：

```jsx
npm -v
```

此外，您还应该安装**React Developer Tools**插件（适用于 Chrome 和 Firefox）并将其添加到您的浏览器中。可以从**Chrome Web Store**([`chrome.google.com/webstore`](https://chrome.google.com/webstore))或 Firefox Addons([`addons.mozilla.org`](https://addons.mozilla.org))安装此插件。

# 下载示例代码文件

您可以从您在[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[www.packtpub.com/support](https://www.packtpub.com/support)并注册，以便文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

文件下载后，请确保使用最新版本的解压缩软件解压缩文件夹：

+   Windows 的 WinRAR/7-Zip

+   Mac 的 Zipeg/iZip/UnRarX

+   Linux 的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/React-Projects`](https://github.com/PacktPublishing/React-Projects)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自丰富书籍和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。快去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`static.packt-cdn.com/downloads/9781789954937_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781789954937_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这里有一个例子：“由于您将在本章中构建一个电影列表应用程序，因此将此目录命名为`movieList`。”

代码块设置如下：

```jsx
{
    "name": "movieList",
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

当我们希望引起您对代码块的特定部分的注意时，相关行或项目以粗体设置：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';
+ import List from './containers/List';

const App = () => {
-   return <h1>movieList</h1>;
+   return <List />;
};

ReactDOM.render(<App />, document.getElementById('root'));
```

任何命令行输入或输出都是这样写的：

```jsx
npm init -y
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这里有一个例子：“当用户单击关闭 X 按钮时，组件的显示样式规则将设置为 none。”

警告或重要说明是这样显示的。提示和技巧是这样显示的。


# 第一章：在 React 中创建电影列表应用程序

当您购买这本书时，您可能之前已经听说过 React，甚至可能尝试过一些在线找到的代码示例。这本书的构建方式是，每一章的代码示例逐渐增加复杂性，因此即使您对 React 的经验有限，每一章也应该是可以理解的，如果您已经阅读了前一章。当您阅读完本书时，您将了解如何使用 React 及其稳定功能，直到 16.11 版本，并且您还将有使用 React Native 和 React 360 的经验。

本章首先学习如何构建一个简单的电影列表应用程序，并为您提供我们将从外部来源获取的热门电影的概述。入门 React 的核心概念将应用于这个项目，如果您之前有一些使用 React 构建应用程序的经验，这应该是可以理解的。如果您之前没有使用过 React，也没有问题；本书将沿途描述代码示例中使用的 React 功能。

在本章中，我们将涵盖以下主题：

+   使用 webpack 和 React 设置新项目

+   构建 React 项目结构

让我们开始吧！

# 项目概述

在本章中，我们将在 React 中创建一个电影列表应用程序，该应用程序从本地 JSON 文件中检索数据，并在浏览器中使用 webpack 和 Babel 运行。样式将使用 Bootstrap 完成。您将构建的应用程序将返回截至 2019 年的最卖座电影列表，以及一些更多的细节和每部电影的海报。

构建时间为 1 小时。

# 入门

本章的应用程序将从头开始构建，并使用可以在 GitHub 上找到的资产：[`github.com/PacktPublishing/React-Projects/tree/ch1-assets`](https://github.com/PacktPublishing/React-Projects/tree/ch1-assets)。这些资产应下载到您的计算机上，以便您稍后在本章中使用。本章的完整代码也可以在 GitHub 上找到：[`github.com/PacktPublishing/React-Projects/tree/ch1`](https://github.com/PacktPublishing/React-Projects/tree/ch1)。

对于本书中创建的应用程序，您需要在计算机上安装至少 Node.js v10.16.3，以便可以运行`npm`命令。如果您尚未在计算机上安装 Node.js，请转到[`nodejs.org/en/download/`](https://nodejs.org/en/download/)，在那里您可以找到 macOS、Windows 和 Linux 的下载说明。

安装 Node.js 后，在命令行中运行以下命令以检查已安装的版本：

+   对于 Node.js（应为 v10.16.3 或更高版本）：

```jsx
node -v
```

+   对于`npm`（应为 v6.9.0 或更高版本）：

```jsx
npm -v
```

此外，您应该已安装了**React Developer Tools**插件（适用于 Chrome 和 Firefox），并将其添加到浏览器中。可以从**Chrome Web Store**（[`chrome.google.com/webstore`](https://chrome.google.com/webstore)）或 Firefox Addons（[`addons.mozilla.org`](https://addons.mozilla.org)）安装此插件。

# 创建电影列表应用程序

在本节中，我们将从头开始创建一个新的 React 应用程序，首先设置一个带有 webpack 和 Babel 的新项目。从头开始设置一个 React 项目将帮助您了解项目的基本需求，这对您创建的任何项目都是至关重要的。

# 设置项目

每次创建新的 React 项目时，第一步是在本地计算机上创建一个新目录。由于您将在本章中构建一个电影列表应用程序，因此将此目录命名为`movieList`。

在这个新目录中，从命令行执行以下操作：

```jsx
npm init -y
```

运行此命令将创建一个`package.json`文件，其中包含`npm`对该项目的基本信息的最低要求。通过在命令中添加`-y`标志，我们可以自动跳过设置`name`、`version`和`description`等信息的步骤。运行此命令后，将创建以下`package.json`文件：

```jsx
{
    "name": "movieList",
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

如您所见，由于我们尚未安装任何依赖项，因此`npm`包没有依赖项。我们将在本节的下一部分中安装和配置的第一个包是 webpack。

# 设置 webpack

要运行 React 应用程序，我们需要安装 webpack 4（在撰写本书时，webpack 的当前稳定版本为版本 4）和 webpack CLI 作为**devDependencies**。让我们开始吧：

1.  使用以下命令从`npm`安装这些包：

```jsx
npm install --save-dev webpack webpack-cli
```

1.  下一步是在`package.json`文件中包含这些包，并在我们的启动和构建脚本中运行它们。为此，将`start`和`build`脚本添加到我们的`package.json`文件中：

```jsx
{
    "name": "movieList",
    "version": "1.0.0",
    "description": "",
    "main": "index.js",
    "scripts": {
_       "start": "webpack --mode development",
+       "build": "webpack --mode production",
        "test": "echo \"Error: no test specified\" && exit 1"
    },
    "keywords": [],
    "author": "",
    "license": "ISC"
}
```

"+"符号用于添加的行，"-"符号用于删除的行在代码中。

上述配置将使用 webpack 为我们的应用程序添加`start`和`build`脚本。正如您所看到的，`npm start`将在开发模式下运行 webpack，而`npm build`将在生产模式下运行 webpack。最大的区别在于，在生产模式下运行 webpack 将最小化我们的代码，以减小项目捆绑的大小。

1.  在我们的项目内创建一个名为`src`的新目录，并在这个目录内创建一个名为`index.js`的新文件。稍后，我们将配置 webpack，使这个文件成为我们应用程序的起点。将以下代码放入这个新创建的文件中：

```jsx
console.log("movieList")
```

如果我们现在在命令行中运行`npm start`或`npm build`命令，webpack 将启动并创建一个名为`dist`的新目录。在这个目录里，将会有一个名为`main.js`的文件，其中包含我们的项目代码。根据我们是在开发模式还是生产模式下运行 webpack，这个文件中的代码将被最小化。您可以通过运行以下命令来检查您的代码是否工作：

```jsx
node dist/main.js
```

这个命令运行我们应用程序的捆绑版本，并应该在命令行中返回`movieList`字符串作为输出。现在，我们可以从命令行运行 JavaScript 代码。在本节的下一部分中，我们将学习如何配置 webpack，使其与 React 一起工作。

# 配置 webpack 以与 React 一起工作

现在我们已经为 JavaScript 应用程序设置了一个基本的开发环境，可以开始安装我们运行任何 React 应用程序所需的包。这些包括`react`和`react-dom`，前者是 React 的通用核心包，后者提供了浏览器 DOM 的入口点，并渲染 React。让我们开始吧：

1.  通过在命令行中执行以下命令来安装这些包：

```jsx
npm install react react-dom
```

仅仅安装 React 的依赖是不足以运行它的，因为默认情况下，并非每个浏览器都能读取您的 JavaScript 代码所写的格式（如 ES2015+或 React）。因此，我们需要将 JavaScript 代码编译成每个浏览器都能读取的格式。

1.  为此，我们将使用 Babel 及其相关包，可以通过运行以下命令将其安装为`devDependencies`：

```jsx
npm install --save-dev @babel/core @babel/preset-env @babel/preset-react babel-loader
```

除了 Babel 核心之外，我们还将安装`babel-loader`，这是一个辅助工具，使得 Babel 可以与 webpack 一起运行，并安装两个预设包。这些预设包有助于确定将用于将我们的 JavaScript 代码编译为浏览器可读格式的插件（`@babel/preset-env`）以及编译 React 特定代码（`@babel/preset-react`）。

安装了 React 和正确的编译器包后，下一步是使它们与 webpack 配合工作，以便在运行应用程序时使用它们。

1.  要做到这一点，在项目的根目录中创建一个名为`webpack.config.js`的文件。在这个文件中，添加以下代码：

```jsx
module.exports = {
    module: {
        rules: [
            {
                test: /\.js$/,
                exclude: /node_modules/,
                use: {
                    loader:'"babel-loader',
                },
            },
        ],
    },
}
```

这个文件中的配置告诉 webpack 对具有`.js`扩展名的每个文件使用`babel-loader`，并排除 Babel 编译器中`node_modules`目录中的`.js`文件。`babel-loader`的实际设置放在一个名为`.babelrc`的单独文件中。

1.  我们还可以在项目的根目录中创建`.babelrc`文件，并在其中放置以下代码，该代码配置`babel-loader`在编译我们的代码时使用`@babel/preset-env`和`@babel/preset-react`预设：

```jsx
{
    "presets": [
        [
            "@babel/preset-env", 
            {
                "targets": {
                    "node": "current"
                }
            }
        ],
        "@babel/react"
    ]
}
```

我们还可以直接在`webpack.config.js`文件中声明`babel-loader`的配置，但为了更好的可读性，我们应该将其放在一个单独的`.babelrc`文件中。此外，Babel 的配置现在可以被与 webpack 无关的其他工具使用。

`@babel/preset-env`预设中定义了选项，确保编译器使用最新版本的 Node.js，因此诸如`async/await`等功能的 polyfill 仍然可用。现在我们已经设置了 webpack 和 Babel，我们可以从命令行运行 JavaScript 和 React。在本节的下一部分中，我们将创建我们的第一个 React 代码，并使其在浏览器中运行。

# 渲染 React 项目

现在我们已经设置了 React，使其可以与 Babel 和 webpack 一起工作，我们需要创建一个实际的 React 组件，以便进行编译和运行。创建一个新的 React 项目涉及向项目添加一些新文件，并对 webpack 的设置进行更改。让我们开始吧：

1.  让我们编辑`src`目录中已经存在的`index.js`文件，以便我们可以使用`react`和`react-dom`：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';

const App = () => {
    return <h1>movieList</h1>;
};

ReactDOM.render(<App />, document.getElementById('root'));
```

正如你所看到的，这个文件导入了`react`和`react-dom`包，定义了一个简单的组件，返回一个包含你的应用程序名称的`h1`元素，并使用`react-dom`渲染了这个组件。代码的最后一行将`App`组件挂载到文档中`root`ID 的元素上，这是应用程序的入口点。

1.  我们可以通过在`src`目录中添加一个名为`index.html`的新文件并在其中添加以下代码来创建此文件：

```jsx
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>movieList</title>
</head>
<body>
    <section id="root"></section>
</body>
</html>
```

这将添加一个 HTML 标题和主体。在`head`标签中是我们应用程序的标题，在`body`标签中是一个带有`id`属性`root`的部分。这与我们在`src/index.js`文件中将`App`组件挂载到的元素相匹配。

1.  渲染我们的 React 组件的最后一步是扩展 webpack，以便在运行时将压缩的捆绑代码添加到`body`标签作为`scripts`。因此，我们应该将`html-webpack-plugin`包安装为 devDependency：

```jsx
npm install --save-dev html-webpack-plugin
```

将这个新包添加到`webpack.config.js`文件中的 webpack 配置中：

```jsx
const HtmlWebPackPlugin = require('html-webpack-plugin');

const htmlPlugin = new HtmlWebPackPlugin({
 template: './src/index.html',
 filename: './index.html',
});

module.exports = {
    module: {
        rules: [
            {
                test: /\.js$/,
                exclude: /node_modules/,
                use: {
                    loader: 'babel-loader',
                },
            },
        ],
    },
    plugins: [htmlPlugin],
};
```

在`html-webpack-plugin`的配置中，我们将应用程序的入口点设置为`index.html`文件。这样，webpack 就知道在`body`标签中添加捆绑包的位置。

我们还可以通过在导出的 webpack 配置中直接添加插件的配置来将这个新包添加到 webpack 配置中，以替换导出配置中的`htmlPlugin`常量。随着我们的应用程序规模的增长，这可能会使 webpack 配置变得不太可读，这取决于我们的偏好。

现在，如果我们再次运行`npm start`，webpack 将以开发模式启动，并将`index.html`文件添加到`dist`目录中。在这个文件中，我们会看到，在你的`body`标签中，一个新的`scripts`标签已经被插入，指向我们的应用程序捆绑包，也就是`dist/main.js`文件。如果我们在浏览器中打开这个文件，或者从命令行运行`open dist/index.html`，它将直接在浏览器中返回`movieList`的结果。当运行`npm build`命令以启动生产模式下的 Webpack 时，我们也可以做同样的操作；唯一的区别是我们的代码将被压缩。

通过使用 webpack 设置开发服务器，可以加快这个过程。我们将在本节的最后部分进行这个操作。

# 创建开发服务器

在开发模式下工作时，每次对应用程序中的文件进行更改时，我们需要重新运行`npm start`命令。由于这有点繁琐，我们将安装另一个名为`webpack-dev-server`的包。该包添加了选项，强制 webpack 在我们对项目文件进行更改时重新启动，并将我们的应用程序文件管理在内存中，而不是构建`dist`目录。`webpack-dev-server`包也可以使用`npm`安装：

```jsx
npm install --save-dev webpack-dev-server
```

此外，我们需要编辑`package.json`文件中的`start`脚本，以便在运行`start`脚本时直接使用`webpack-dev-server`而不是 webpack：

```jsx
{
    "name": "movieList",
    "version": "1.0.0",
    "description": "",
    "main": "index.js",
    "scripts": {
-       "start": "webpack --mode development",
+       "start": "webpack-dev-server --mode development --open",        
        "build": "webpack --mode production"
    },
    "keywords": [],
    "author": "",
    "license": "ISC"

    ...
}
```

上述配置将在启动脚本中用`webpack-dev-server`替换 webpack，以开发模式运行 webpack。这将创建一个本地服务器，使用`--open`标志运行应用程序，确保每次更新项目文件时 webpack 都会重新启动。

要启用热重载，将`--open`标志替换为`--hot`标志。这将仅重新加载已更改的文件，而不是整个项目。

现在，我们已经为 React 应用程序创建了基本的开发环境，在本章的下一部分中，您将进一步开发和构建它。

# 项目结构

设置开发环境后，是时候开始创建电影列表应用程序了。首先让我们看一下项目的当前结构，在项目根目录中有两个重要的目录：

+   第一个目录称为`dist`，其中包含 webpack 打包版本的应用程序输出

+   第二个称为`src`，包括我们应用程序的源代码：

```jsx
movieList
|-- dist
    |-- index.html
    |-- main.js
|-- node_modules
|-- src
    |-- index.js
    |-- index.html
.babelrc
package.json
webpack.config.js
```

在我们项目的根目录中还可以找到另一个目录，名为`node_modules`。这是我们使用`npm`安装的每个包的源文件所在的地方。建议您不要手动更改此目录中的文件。

在接下来的小节中，我们将学习如何构建 React 项目。这种结构将在本书的其余章节中使用。

# 创建新组件

React 的官方文档并未说明如何构建 React 项目的首选方法。尽管社区中有两种常见的方法：按功能或路由结构化文件，或按文件类型结构化文件。

电影列表应用程序将采用混合方法，首先按文件类型结构化，其次按功能结构化。实际上，这意味着将有两种类型的组件：顶层组件，称为容器，和与这些顶层组件相关的低级组件。创建这些组件需要添加以下文件和代码更改：

1.  实现这种结构的第一步是在`src`目录下创建一个名为`containers`的新子目录。在此目录中，创建一个名为`List.js`的文件。这将是包含电影列表的容器，其中包含以下内容：

```jsx
import React, { Component } from 'react';

class List extends Component {
    render() {
        return <h1>movieList</h1>;
    }
};

export default List;
```

1.  应该在应用程序的入口点中包含此容器，以便它可见。因此，我们需要在`src`目录内的`index.js`文件中包含它，并引用它：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';
+ import List from './containers/List';

const App = () => {
-   return <h1>movieList</h1>;
+   return <List />;
};

ReactDOM.render(<App />, document.getElementById('root'));
```

1.  如果我们仍在运行开发服务器（如果没有，请再次执行`npm start`命令），我们将看到我们的应用程序仍然返回相同的结果。我们的应用程序应该具有以下文件结构：

```jsx
movieList
|-- dist
    |-- index.html
    |-- main.js
|-- src
 |-- containers
 |-- List.js
    |-- index.js
    |-- index.html
.babelrc
package.json
webpack.config.js
```

1.  下一步是向`List`容器添加一个组件，稍后我们将使用它来显示有关电影的信息。此组件将被称为`Card`，应位于名为`components`的新`src`子目录中，该子目录将放置在与组件相同名称的目录中。我们需要在`src`目录内创建一个名为`components`的新目录，然后在其中创建一个名为`Card`的新目录。在此目录中，创建一个名为`Card.js`的文件，并将以下代码块添加到空的`Card`组件中：

```jsx
import React from 'react';

const Card = () => {
    return <h2>movie #1</h2>;
};

export default Card;
```

1.  现在，将`Card`组件导入`List`容器中，并用以下代码替换`return`函数，返回此组件而不是`h1`元素：

```jsx
import React, { Component } from 'react';
+ import Card from '../components/Card/Card';

class List extends Component {
    render() {
-       return <h1>movieList</h1>;
+       return <Card />;
    }
};

export default List;
```

现在我们已经添加了这些目录和`Card.js`文件，我们的应用程序文件结构将如下所示：

```jsx
movieList
|-- dist
    |-- index.html
    |-- main.js
|-- src
 |-- components
 |-- Card
 |-- Card.js
    |-- containers
        |-- List.js
    |-- index.js
    |-- index.html
.babelrc
package.json
webpack.config.js
```

如果我们再次在浏览器中访问我们的应用程序，将不会有可见的变化，因为我们的应用程序仍然返回相同的结果。但是，如果我们在浏览器中打开 React Developer Tools 插件，我们会注意到应用程序当前由多个堆叠的组件组成：

```jsx
<App>
    <List>
        <Card>
            <h1>movieList</h1>
        </Card>
    </List>
</App>
```

在本节的下一部分，您将利用对 React 项目进行结构化的知识，并创建新组件来获取有关我们想要在此应用程序中显示的电影的数据。

# 检索数据

随着开发服务器和项目结构的设置完成，现在是时候最终向其中添加一些数据了。如果您还没有从*入门*部分的 GitHub 存储库中下载资产，现在应该这样做。这些资产是此应用程序所需的，包含有关五部票房最高的电影及其相关图像文件的 JSON 文件。

`data.json`文件由一个包含有关电影信息的对象数组组成。该对象具有`title`、`distributor`、`year`、`amount`、`img`和`ranking`字段，其中`img`字段是一个具有`src`和`alt`字段的对象。`src`字段指的是也包含在内的图像文件。

我们需要将下载的文件添加到此项目的根目录中的不同子目录中，`data.json`文件应放在名为`assets`的子目录中，图像文件应放在名为`media`的子目录中。添加了这些新目录和文件后，我们的应用程序结构将如下所示：

```jsx
movieList
|-- dist
    |-- index.html
    |-- main.js
|-- src
 |-- assets
 |-- data.json
    |-- components
        |-- Card
            |-- Card.js
    |-- containers
        |-- List.js
 |-- media
 |-- avatar.jpg
 |-- avengers_infinity_war.jpg
 |-- jurassic_world.jpg
 |-- star_wars_the_force_awakens.jpg
 |-- titanic.jpg
    |-- index.js
    |-- index.html
.babelrc
package.json
webpack.config.js
```

此数据将仅在顶层组件中检索，这意味着我们应该在`List`容器中添加一个`fetch`函数，该函数更新此容器的状态并将其作为 props 传递给低级组件。`state`对象可以存储变量；每当这些变量发生变化时，我们的组件将重新渲染。让我们开始吧：

1.  在检索电影数据之前，`Card`组件需要准备好接收这些信息。为了显示有关电影的信息，我们需要用以下代码替换`Card`组件的内容：

```jsx
import React from 'react';

const Card = ({ movie }) => {
     return (
        <div>
            <h2>{`#${movie.ranking} - ${movie.title} (${movie.year})`}</h2>
            <img src={movie.img.src} alt={movie.img.alt} width='200' />
            <p>{`Distributor: ${movie.distributor}`}</p>
            <p>{`Amount: ${movie.amount}`}</p>
        </div>
    );
};

export default Card;
```

1.  现在，可以通过向`List`组件添加一个`constructor`函数来实现检索数据的逻辑，该函数将包含一个空数组作为电影的占位符以及一个指示数据是否仍在加载的变量：

```jsx
...

class List extends Component {+
+   constructor() {
+       super()
+       this.state = {
+           data: [],
+           loading: true,
+       };
+   }

    return (
      ...

```

1.  在设置`constructor`函数之后，我们应该设置一个`componentDidMount`函数，在此函数中，我们将在`List`组件挂载后获取数据。在这里，我们应该使用`async/await`函数，因为`fetch` API 返回一个 promise。获取数据后，应通过用电影信息替换空数组来更新`state`，并将`loading`变量设置为`false`：

```jsx
...

class List extends Component {

    ...

 +    async componentDidMount() {
 +        const movies = await fetch('../../assets/data.json');
 +        const moviesJSON = await movies.json();

 +        if (moviesJSON) {
 +            this.setState({
 +                data: moviesJSON,
 +                loading: false,
 +            });
 +        }
 +    }

    return (
      ...
```

我们以前使用的从 JSON 文件中使用`fetch`检索信息的方法并没有考虑到对该文件的请求可能会失败。如果请求失败，`loading`状态将保持为`true`，这意味着用户将继续看到加载指示器。如果您希望在请求失败时显示错误消息，您需要将`fetch`方法包装在`try...catch`块中，这将在本书的后面部分中介绍。

1.  将此状态传递给`Card`组件，最终可以在第一步中更改的`Card`组件中显示。此组件还将获得一个`key`属性，这是在迭代中呈现的每个组件都需要的。由于这个值需要是唯一的，所以使用电影的`id`，如下所示：

```jsx
class List extends Component {

    ...

    render() {
 _     return <Card />
 +     const { data, loading } = this.state;

+      if (loading) {
+         return <div>Loading...</div>
+      }

+      return data.map(movie => <Card key={ movie.id } movie={ movie } />);
    }
}

export default List;
```

如果我们再次在浏览器中访问我们的应用程序，我们会看到它现在显示了一系列电影，包括一些基本信息和一张图片。此时，我们的应用程序将看起来类似于以下的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/4b123e00-9d07-40fe-ad51-012675df5fed.png)

如您所见，应用程序已经应用了有限的样式，并且只呈现了从 JSON 文件中获取的信息。在本节的下一部分中，将使用一个名为**Bootstrap**的包来添加样式。

# 添加样式

仅显示电影信息是不够的。我们还需要对项目应用一些基本样式。使用 Bootstrap 包可以为我们的组件添加样式，这些样式是基于类名的。Bootstrap 可以从`npm`中安装，并需要进行以下更改才能使用：

1.  要使用 Bootstrap，我们需要从`npm`中安装它并将其放在这个项目中：

```jsx
npm install --save-dev bootstrap
```

1.  还要将此文件导入到我们的 React 应用程序的入口点`index.js`中，以便我们可以在整个应用程序中使用样式：

```jsx
import React, { Component } from 'react';
import ReactDOM from 'react-dom';
import List from './containers/List';
+ import 'bootstrap/dist/css/bootstrap.min.css';

const App = () => {
    return <List />;
}

ReactDOM.render(<App />, document.getElementById('root'));
```

如果我们再次尝试运行开发服务器，我们将收到一个错误，显示“您可能需要一个适当的加载程序来处理此文件类型。”。因为 Webpack 无法编译 CSS 文件，我们需要添加适当的加载程序来实现这一点。我们可以通过运行以下命令来安装这些加载程序：

```jsx
npm install --save-dev css-loader style-loader
```

1.  我们需要将这些包添加为 webpack 配置的规则：

```jsx
const HtmlWebPackPlugin = require('html-webpack-plugin');

const htmlPlugin = new HtmlWebPackPlugin({
    template: './src/index.html',
    filename: './index.html',
});

module.exports = {
    module: {
        rules: [
            {
                test: /\.js$/,
                exclude: /node_modules/,
                use: {
                    loader: "babel-loader"
                }
            },
+           {
+               test: /\.css$/,
+               use: ['style-loader', 'css-loader']
+           }
        ]
    },
    plugins: [htmlPlugin]
};
```

加载程序的添加顺序很重要，因为`css-loader`处理 CSS 文件的编译，而`style-loader`将编译后的 CSS 文件添加到 React DOM 中。Webpack 从右到左读取这些设置，CSS 需要在附加到 DOM 之前进行编译。

1.  应用程序现在应该在浏览器中正确运行，并且应该已经从默认的 Bootstrap 样式表中接收到一些小的样式更改。让我们首先对`index.js`文件进行一些更改，并将其样式化为整个应用程序的容器。我们需要更改渲染到 DOM 的`App`组件，并用`div`容器包装`List`组件：

```jsx
...

const App = () => {
    return (
+        <div className='container-fluid'>
            <List />
 </div>
    );
};

ReactDOM.render(<App />, document.getElementById('root'));
```

1.  在`List`组件内部，我们需要设置网格以显示显示电影信息的`Card`组件。使用以下代码包装`map`函数和`Card`组件：

```jsx
...

class List extends Component {

    ...

    render() {
        const { data, loading } = this.state;

        if (loading) {
            return <div>Loading...</div>;
        }

         return (
 +         <div class='row'>
                {data.map(movie =>
 +                 <div class='col-sm-2'>
                        <Card key={ movie.id } movie={ movie } />
 +                 </div>
                )}
 +          </div>
        );
    }
}

export default List;
```

1.  `Card`组件的代码如下。这将使用 Bootstrap 为`Card`组件添加样式：

```jsx
import React from 'react';

const Card = ({ movie }) => {
    return (
        <div className='card'>
            <img src={movie.img.src} className='card-img-top' alt={movie.img.alt} />
            <div className='card-body'>
                <h2 className='card-title'>{`#${movie.ranking} - ${movie.title} (${movie.year})` }</h2>
            </div>
            <ul className='list-group list-group-flush'>
                <li className='list-group-item'>{`Distributor: ${movie.distributor}`}</li>
                <li className='list-group-item'>{`Amount: ${movie.amount}`}</li>
            </ul>
        </div>
    );
};

export default Card;
```

1.  为了添加最后的修饰，打开`index.js`文件并插入以下代码，以添加一个标题，将放置在应用程序中电影列表的上方：

```jsx
...

const App = () => {
    return (
        <div className='container-fluid'>
_            <h1>movieList</h1>
+            <nav className='navbar sticky-top navbar-light bg-dark'>
+               <h1 className='navbar-brand text-light'>movieList</h1>
+           </nav>

            <List />
        </div>
    );
};

ReactDOM.render(<App />, document.getElementById('root'));
```

如果我们再次访问浏览器，我们会看到应用程序已经通过 Bootstrap 应用了样式，使其看起来如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/11d65233-61d0-4897-8d37-ec219c48815c.png)

Bootstrap 的样式规则已应用到我们的应用程序中，使其看起来比以前更完整。在本节的最后部分，我们将向项目添加 ESLint 包，这将通过在整个项目中同步模式来使维护我们的代码更容易。

# 添加 ESLint

最后，我们将添加 ESLint 到项目中，以确保我们的代码符合某些标准，例如，我们的代码遵循正确的 JavaScript 模式。添加 ESLint 需要以下更改：

1.  通过运行以下命令从`npm`安装 ESLint：

```jsx
npm install --save-dev eslint eslint-loader eslint-plugin-react
```

第一个包叫做`eslint`，是核心包，帮助我们识别 JavaScript 代码中的潜在问题模式。`eslint-loader`是一个由 Webpack 使用的包，每次更新代码时都会运行 ESLint。最后，`eslint-plugin-react`为 React 应用程序向 ESLint 添加特定规则。

1.  要配置 ESLint，我们需要在项目的根目录中创建一个名为`.eslintrc.js`的文件，并将以下代码添加到其中：

```jsx
module.exports = {
    "env": {
        "browser": true,
        "es6": true
    },
    "parserOptions": {
        "ecmaFeatures": {
            "jsx": true
        },
        "ecmaVersion": 2018,
        "sourceType": "module"
    },
    "plugins": [
        "react"
    ],
    "extends": ["eslint:recommended", "plugin:react/recommended"]
};       
```

`env`字段设置了我们的代码将运行的实际环境，并将在其中使用`es6`函数，而`parserOptions`字段为使用`jsx`和现代 JavaScript 添加了额外的配置。然而，有趣的地方在于`plugins`字段，这是我们指定我们的代码使用`react`作为框架的地方。`extends`字段是使用`eslint`的`recommended`设置以及 React 的特定设置的地方。

我们可以运行`eslint --init`命令来创建自定义设置，但建议使用前面的设置，以确保我们的 React 代码的稳定性。

1.  如果我们查看命令行或浏览器，我们将看不到错误。但是，我们必须将`eslint-loader`包添加到 webpack 配置中。在`webpack.config.js`文件中，将`eslint-loader`添加到`babel-loader`旁边：

```jsx
...

module.exports = {
    module: {
        rules: [
            {
                test: /\.js$/,
                exclude: /node_modules/,
+               use: ['babel-loader', 'eslint-loader'] 
            },
            {
                test: /\.css$/,
                use: ['style-loader', 'css-loader']
            }
        ]
    },
    plugins: [htmlPlugin]
};
```

通过重新启动开发服务器，webpack 现在将使用 ESLint 来检查我们的 JavaScript 代码是否符合 ESLint 的配置。在我们的命令行（或浏览器中的控制台选项卡）中，应该可以看到以下错误：

```jsx
movieList/src/components/Card/Card.js
 3:17  error 'movie' is missing in props validation  react/prop-types
```

在使用 React 时，建议我们验证发送到组件的任何 props，因为 JavaScript 的动态类型系统可能会导致变量未定义或类型不正确的情况。我们的代码将在不验证 props 的情况下工作，但为了修复此错误，我们必须安装`prop-types`包，这曾经是 React 的一个功能，但后来被弃用了。让我们开始吧：

1.  我们用于检查 prop 类型的包可以从`npm`安装：

```jsx
npm install --save prop-types
```

1.  现在，我们可以通过将该包导入`Card`组件并将验证添加到该文件的底部来验证组件中的`propTypes`。

```jsx
import React from 'react';
+ import PropTypes from 'prop-types';

const Card = ({ movie }) => {
    ...
};

+ Card.propTypes = {
+    movie: PropTypes.shape({}),
+ };

export default Card;
```

1.  如果我们再次查看命令行，我们会发现缺少的`propTypes`验证错误已经消失了。但是，我们的 props 的验证仍然不是很具体。我们可以通过还指定`movie` prop 的所有字段的`propTypes`来使其更具体：

```jsx
...

Card.propTypes = {
_   movie: PropTypes.shape({}),
+    movie: PropTypes.shape({
+    title: PropTypes.string,
+    distributor: PropTypes.string,
+     year: PropTypes.number,
+     amount: PropTypes.string,
+     img: PropTypes.shape({
+       src: PropTypes.string,
+       alt: PropTypes.string
+     }),
+     ranking: PropTypes.number
+   }).isRequired  
};  
```

我们还可以通过将`isRequired`添加到`propTypes`验证中来指示`React`渲染组件所需的 props。

恭喜！您已经使用 React、ReactDom、webpack、Babel 和 ESLint 从头开始创建了一个基本的 React 应用程序。

# 总结

在本章中，您从头开始为 React 创建了一个电影列表应用程序，并了解了核心 React 概念。本章以您使用 webpack 和 Babel 创建一个新项目开始。这些库可以帮助您以最小的设置编译和在浏览器中运行 JavaScript 和 React 代码。然后，我们描述了如何构建 React 应用程序的结构。这种结构将贯穿本书始终。应用的原则为您提供了从零开始创建 React 应用程序并以可扩展的方式构建它们的基础。

如果您之前已经使用过 React，那么这些概念可能不难理解。如果没有，那么如果某些概念对您来说感觉奇怪，也不用担心。接下来的章节将建立在本章中使用的功能之上，让您有足够的时间充分理解它们。

下一章中您将构建的项目将专注于使用更高级的样式创建可重用的 React 组件。由于它将被设置为**渐进式 Web 应用程序**（**PWA**），因此将可以离线使用。

# 进一步阅读

+   在 React 中思考 [`reactjs.org/docs/thinking-in-react.html`](https://reactjs.org/docs/thinking-in-react.html)

+   Bootstrap [`getbootstrap.com/docs/4.3/getting-started/introduction/`](https://getbootstrap.com/docs/4.3/getting-started/introduction/)

+   ESLint [`eslint.org/docs/user-guide/getting-started`](https://eslint.org/docs/user-guide/getting-started)


# 第二章：使用可重用的 React 组件创建渐进式 Web 应用程序

在完成第一章后，您是否已经对 React 的核心概念感到熟悉？太好了！这一章对您来说将不成问题！如果没有，不要担心-您在上一章中遇到的大多数概念将被重复。但是，如果您想获得更多关于 webpack 和 Babel 的经验，建议您再次尝试在第一章中创建项目，*在 React 中创建电影列表应用程序*，因为本章不会涵盖这些主题。

在这一章中，您将使用 Create React App，这是一个由 React 核心团队创建的入门套件，可以快速开始使用 React，并且可以用作**渐进式 Web 应用程序**（**PWA**）-一种行为类似移动应用程序的 Web 应用程序。这将使模块捆绑器和编译器（如 webpack 和 Babel）的配置变得不必要，因为这将在 Create React App 包中处理。这意味着您可以专注于构建您的 GitHub 作品集应用程序，将其作为一个 PWA，重用 React 组件和样式。

除了设置 Create React App 之外，本章还将涵盖以下主题：

+   创建渐进式 Web 应用程序

+   构建可重用的 React 组件

+   使用`styled-components`在 React 中进行样式设置

迫不及待？让我们继续吧！

# 项目概述

在这一章中，我们将使用 Create React App 和`styled-components`创建具有可重用 React 组件和样式的 PWA。该应用程序将使用从公共 GitHub API 获取的数据。

建立时间为 1.5-2 小时。

# 入门

在本章中，您将创建的项目将使用 GitHub 的公共 API，您可以在[`developer.github.com/v3/`](https://developer.github.com/v3/)找到。要使用此 API，您需要拥有 GitHub 帐户，因为您将希望从 GitHub 用户帐户中检索信息。如果您还没有 GitHub 帐户，可以通过在其网站上注册来创建一个。此外，您需要从这里下载 GitHub 标志包：[`github-media-downloads.s3.amazonaws.com/GitHub-Mark.zip`](https://github-media-downloads.s3.amazonaws.com/GitHub-Mark.zip)。此应用程序的完整源代码也可以在 GitHub 上找到：[`github.com/PacktPublishing/React-Projects/tree/ch2`](https://github.com/PacktPublishing/React-Projects/tree/ch2)。

# GitHub 作品集应用程序

在这一部分，我们将学习如何使用 Create React App 创建一个新的 React 项目，并将其设置为一个可以重用 React 组件和使用`styled-components`进行样式设置的 PWA。

# 使用 Create React App 创建 PWA

每次创建新的 React 项目都需要配置 webpack 和 Babel 可能会非常耗时。此外，每个项目的设置可能会发生变化，当我们想要为我们的项目添加新功能时，管理所有这些配置变得困难。

因此，React 核心团队推出了一个名为 Create React App 的起始工具包，并在 2018 年发布了稳定版本 2.0。通过使用 Create React App，我们不再需要担心管理编译和构建配置，即使 React 的新版本发布了，这意味着我们可以专注于编码而不是配置。此外，它还具有我们可以使用的功能，可以轻松创建 PWA。

PWA 通常比普通的 Web 应用程序更快、更可靠，因为它专注于离线/缓存优先的方法。这使得用户在没有或者网络连接缓慢的情况下仍然可以打开我们的应用程序，因为它专注于缓存。此外，用户可以将我们的应用程序添加到他们的智能手机或平板电脑的主屏幕，并像本地应用程序一样打开它。

这一部分将向我们展示如何创建一个具有 PWA 功能的 React 应用程序，从设置一个新的应用程序开始，使用 Create React App。

# 安装 Create React App

Create React App 可以通过命令行安装，我们应该全局安装它，这样该包就可以在我们本地计算机的任何地方使用，而不仅仅是在特定项目中：

```jsx
npm install -g create-react-app
```

现在`create-react-app`包已经安装完成，我们准备创建我们的第一个 Create React App 项目。有多种设置新项目的方法，但由于我们已经熟悉了`npm`，我们只需要学习两种方法。让我们开始吧：

1.  第一种方法是使用`npm`创建一个新项目，运行以下命令：

```jsx
npm init react-app github-portfolio
```

您可以将`github-portfolio`替换为您想要为此项目使用的任何其他名称。

1.  另外，我们也可以使用`npx`，这是一个与`npm`（v5.2.0 或更高版本）预装的工具，简化了我们执行`npm`包的方式：

```jsx
npx create-react-app github-portfolio
```

这两种方法都将启动 Create React App 的安装过程，这可能需要几分钟，具体取决于您的硬件。虽然我们只执行一个命令，但 Create React App 的安装程序将安装我们运行 React 应用程序所需的软件包。因此，它将安装`react`，`react-dom`和`react-scripts`，其中最后一个软件包包含了编译、运行和构建 React 应用程序的所有配置。

如果我们进入项目的根目录，该目录以我们的项目名称命名，我们会看到它具有以下结构：

```jsx
github-portfolio
|-- node_modules
|-- public
    |-- favicon.ico
    |-- index.html
    |-- manifest.json
|-- src
    |-- App.css
    |-- App.js
    |-- App.test.js
    |-- index.css
    |-- index.js
    |-- logo.svg
    |-- serviceWorker.js
.gitignore
package.json
```

这个结构看起来很像我们在第一章设置的结构，尽管有一些细微的差异。`public`目录包括所有不应包含在编译和构建过程中的文件，而该目录中的文件是唯一可以直接在`index.html`文件中使用的文件。`manifest.json`文件包含 PWA 的默认配置，这是我们将在本章后面学到更多的内容。

在另一个名为`src`的目录中，我们将找到在执行`package.json`文件中的任何脚本时将被编译和构建的所有文件。有一个名为`App`的组件，它由`App.js`，`App.test.js`和`App.css`文件定义，以及一个名为`index.js`的文件，它是 Create React App 的入口点。`serviceWorker.js`文件是设置 PWA 所需的，这也是本节下一部分将讨论的内容。

如果我们打开`package.json`文件，我们会看到定义了三个脚本：`start`，`build`和`test`。由于测试是目前尚未处理的事情，我们现在可以忽略这个脚本。为了能够在浏览器中打开项目，我们只需在命令行中输入以下命令，即以开发模式运行`package react-scripts`：

```jsx
npm start
```

如果我们访问`http://localhost:3000/`，默认的 Create React App 页面将如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/9bb5ddd7-fd07-4bc3-b309-718f18728581.png)

由于`react-scripts`默认支持热重载，我们对代码所做的任何更改都将导致页面重新加载。如果我们运行构建脚本，将在项目的根目录中创建一个名为`build`的新目录，其中可以找到我们应用程序的缩小捆绑包。

使用基本的 Create React App 安装完成后，本节的下一部分将向我们展示如何启用功能，将该应用程序转变为 PWA。

# 创建 PWA

Create React App 自带了一个支持 PWA 的配置，在我们初始化构建脚本时生成。我们可以通过访问`src/index.js`文件并修改最后一行来将我们的 Create React App 项目设置为 PWA，这将注册`serviceWorker`：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import App from './App';
import * as serviceWorker from './serviceWorker';

ReactDOM.render(<App />, document.getElementById('root'));

// If you want your app to work offline and load faster, you can change
// unregister() to register() below. Note this comes with some pitfalls.
// Learn more about service workers: http://bit.ly/CRA-PWA
- //serviceWorker.register();
+ serviceWorker.register();
```

现在，当我们运行构建脚本时，我们的应用程序的压缩包将使用离线/缓存优先的方法。在幕后，`react-scripts`使用一个名为`workbox-webpack-plugin`的包，它与 webpack 4 一起工作，将我们的应用程序作为 PWA 提供。它不仅缓存放在`public`目录中的本地资产；它还缓存导航请求，以便我们的应用程序在不稳定的移动网络上更可靠地运行。

另一个在使用 Create React App 设置 PWA 中起作用的文件是`manifest.json`。我们的 PWA 的大部分配置都放在这里，如果我们打开`public/manifest.json`文件就可以看到。在这个配置 JSON 文件中，我们会找到操作系统和浏览器的最重要的部分。让我们来分解一下：

1.  这个文件包含了`short_name`和`name`字段，描述了我们的应用程序应该如何被用户识别：

```jsx
{
  "short_name": "React App",
  "name": "Create React App Sample",

...
```

`short_name`字段的长度不应超过 12 个字符，并将显示在用户主屏幕上应用程序图标的下方。对于`name`字段，我们最多可以使用 45 个字符。这是我们应用程序的主要标识符，并且可以在将应用程序添加到主屏幕的过程中看到。

1.  当用户将我们的应用程序添加到主屏幕时，他们看到的特定图标可以在`icons`字段中配置：

```jsx
  "icons": [
    {
      "src": "favicon.ico",
      "sizes": "64x64 32x32 24x24 16x16",
      "type": "image/x-icon"
    }
  ],
```

正如我们之前提到的，`favicon.ico`文件被用作唯一的图标，并以`image/x-icon`格式以多种尺寸提供。对于`manifest.json`，同样的规则适用于`index.html`。只有放在 public 目录中的文件才能从这个文件中引用。

1.  最后，使用`theme_color`和`background_color`字段，我们可以为打开我们的应用程序时在移动设备主屏幕上设置顶部栏的颜色（以十六进制格式）：

```jsx
  ...
  "theme_color": "#000000",
  "background_color": "#ffffff"
}
```

默认的工具栏和 URL 框不会显示；相反，会显示一个顶部栏。这种行为类似于原生移动应用程序。

配置文件还可以处理的另一件事是国际化，当我们的应用程序以不同的语言提供内容时，这将非常有用。如果我们的应用程序有多个版本在生产中，我们还可以在这个文件中添加版本控制。

我们在这里所做的更改配置了应用程序，使其作为 PWA 运行，但目前还不向用户提供这些功能。在本节的下一部分，我们将学习如何提供这个 PWA 并在浏览器中显示出来。

# 提供 PWA

PWA 的配置已经就绪，现在是时候看看这将如何影响应用程序了。如果您仍在运行 Create React App（如果没有，请再次执行`npm start`命令），请访问项目`http://localhost:3000/`。我们会发现目前还没有任何变化。正如我们之前提到的，只有当我们的应用程序的构建版本打开时，PWA 才会可见。为了做到这一点，请在项目的根目录中执行以下命令：

```jsx
npm run build 
```

这将启动构建过程，将我们的应用程序最小化为存储在`build`目录中的捆绑包。我们可以从本地机器上提供这个构建版本的应用程序。如果我们在命令行上查看构建过程的输出，我们会看到 Create React App 建议我们如何提供这个构建版本。

```jsx
npm install -g serve
serve -s build
```

`npm install`命令安装了`serve`包，用于提供构建的静态站点或者 JavaScript 应用程序。安装完这个包后，我们可以使用它在服务器或本地机器上部署`build`目录，方法如下：

```jsx
serve -s build
```

`-s`标志用于将任何未找到的导航请求重定向回我们的`index.js`文件。

如果我们在浏览器中访问我们的项目`http://localhost:5000/`，我们会发现一切看起来和我们在`http://localhost:3000/`上运行的版本完全一样。然而，有一个很大的不同：构建版本是作为 PWA 运行的。这意味着如果我们的互联网连接失败，应用程序仍然会显示。我们可以通过断开互联网连接或从命令行停止`serve`包来尝试这一点。如果我们在`http://localhost:5000/`上刷新浏览器，我们会看到完全相同的应用程序。

这是如何工作的？如果我们在浏览器（Chrome 或 Firefox）中打开开发者工具并访问应用程序选项卡，我们将看到侧边栏中的项目。我们首先应该打开的是 Service Workers。如果您使用 Chrome 作为浏览器，结果将类似于以下截图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/2c9e3fb0-c08f-48fe-bc28-e909727e7679.png)

如果我们点击 Service Worker 侧边栏项目，我们将看到正在运行的所有 service worker 的列表。对于`localhost`，有一个活动的 service worker，其源为`service-worker.js` - 这与我们项目中的文件相同。该文件确保在没有或者网络连接缓慢的情况下提供我们应用程序的缓存版本。

当我们使用`npm start`在本地运行应用程序时，service worker 不应处于活动状态。由于 service worker 将缓存我们的应用程序，我们将无法看到我们所做的任何更改，因为缓存版本将是一个服务器。

这些缓存文件存储在浏览器缓存中，也可以在工具栏的缓存存储下找到。在这里，我们可能会看到多个缓存位置，这些位置是在构建应用程序时由`workbox-webpack-plugin`包创建的。

与我们应用程序相关的一个是`workbox-precache-v2-http://localhost:5000/`，其中包含我们应用程序的所有缓存文件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/66b6b067-7474-4ce0-842d-66e05cecdd46.png)

在上述截图中，我们可以看到浏览器为我们的应用程序缓存了哪些文件，其中`index.html`文件是应用程序的入口点，以`static/`开头的文件是在构建过程中创建的，并代表我们应用程序的缩小捆绑包。正如我们所看到的，它包括缩小的`.js`、`.css`和`.svg`文件，这些文件存储在浏览器缓存中。每当用户加载我们的应用程序时，它都会尝试首先提供这些文件，然后再寻找网络连接。

创建了我们的第一个 PWA 并安装了 Create React App 后，我们将开始着手创建项目的组件并为它们设置样式。

# 构建可重用的 React 组件

在上一章中简要讨论了使用 JSX 创建 React 组件，但在本章中，我们将通过创建可以在整个应用程序中重用的组件来进一步探讨这个主题。首先，让我们看看如何构建我们的应用程序，这是基于上一章的内容的。

# 构建我们的应用程序

首先，我们需要以与第一章相同的方式构建我们的应用程序。这意味着我们需要在`src`目录内创建两个新目录，分别为`components`和`containers`。`App`组件的文件可以移动到`container`目录，`App.test.js`文件可以删除，因为测试还没有涉及到。

创建完目录并移动文件后，我们的应用程序结构将如下所示：

```jsx
github-portfolio
|-- node_modules
|-- public
    |-- favicon.ico
    |-- index.html
    |-- manifest.json
|-- src
 |-- components
 |-- containers
 |-- App.css
 |-- App.js
    |-- index.css
    |-- index.js
    |-- serviceWorker.js
.gitignore
package.json
```

不要忘记在`src/index.js`中更改对`App`组件的导入位置：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
- import App from './App';
+ import App from './containers/App';
import * as serviceWorker from './serviceWorker';

ReactDOM.render(<App />, document.getElementById('root'));

...
```

在`src/containers/App.js`中的 React `logo`的位置也做同样的事情：

```jsx
import React, { Component } from 'react';
- import logo from './logo.svg';
+ import logo from '../logo.svg';
import './App.css';

class App extends Component {

...
```

如果我们再次运行`npm start`并在浏览器中访问项目，将不会有可见的变化，因为我们只是改变了项目的结构，而没有改变其内容。

我们的项目仍然只包含一个组件，这并不使它非常可重用。下一步将是将我们的`App`组件也分成`Components`。如果我们查看`App.js`中这个组件的源代码，我们会看到返回函数中已经有一个 CSS `header`元素。让我们将`header`元素改成一个 React 组件：

1.  首先，在`components`目录内创建一个名为`Header`的新目录，并将`classNames`、`App-header`、`App-logo`和`App-link`的样式复制到一个名为`Header.css`的新文件中：

```jsx
.App-logo {
  height: 40vmin;
  pointer-events: none;
}

.App-header {
  background-color: #282c34;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  font-size: calc(10px + 2vmin);
  color: white;
}

.App-link {
  color: #61dafb;
}

@keyframes App-logo-spin {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}
```

1.  现在，在这个目录内创建一个名为`Header.js`的文件。这个文件应该返回与`<header>`元素相同的内容。

```jsx
import React from 'react';
import './Header.css';

const Header = () => (
 <header className='App-header'>
     <img src={logo} className='App-logo' alt='logo' />
     <p>
       Edit <code>src/App.js</code> and save to reload.
     </p>
     <a
       className='App-link'
       href='https://reactjs.org'
       target='_blank'
       rel='noopener noreferrer'
     >
       Learn React
     </a>
 </header>
);

export default Header;
```

1.  在`App`组件内导入这个`Header`组件，并将其添加到`return`函数中：

```jsx
import React, { Component } from 'react';
+ import Header from '../components/App/Header';
import logo from '../logo.svg';
import './App.css';

class App extends Component {
 render() {
   return (
     <div className='App'>
-      <header  className='App-header'> -        <img  src={logo}  className='App-logo'  alt='logo'  /> -        <p>Edit <code>src/App.js</code> and save to reload.</p> -        <a -          className='App-link' -          href='https://reactjs.org' -          target='_blank' -          rel='noopener noreferrer' -        >
-          Learn React
-        </a> -      </header>
+      <Header />
     </div>
   );
 }
}

export default App;
```

当我们再次在浏览器中访问我们的项目时，会看到一个错误，说 logo 的值是未定义的。这是因为新的`Header`组件无法访问在`App`组件内定义的`logo`常量。根据我们在第一章学到的知识，我们知道这个 logo 常量应该作为 prop 添加到`Header`组件中，以便显示出来。让我们现在来做这个：

1.  将`logo`常量作为 prop 发送到`src/container/App.js`中的`Header`组件：

```jsx
...
class App extends Component {
 render() {
   return (
     <div className='App'>
-      <Header />
+      <Header logo={logo} />
     </div>
   );
 }
}

export default App;
```

1.  获取`logo`属性，以便它可以被`img`元素作为`src`属性在`src/components/App/Header.js`中使用：

```jsx
import React from 'react';

- const Header = () => (
+ const Header = ({ logo }) => (
 <header className='App-header'>
   <img src={logo} className='App-logo' alt='logo' />

   ...
```

在上一章中，演示了`prop-types`包的使用，但在本章中没有使用。如果您想在本章中也使用`prop-types`，可以使用`npm install prop-types`从`npm`安装该包，并在要使用它的文件中导入它。

在这里，当我们在浏览器中打开项目时，我们看不到任何可见的变化。但是，如果我们打开 React 开发者工具，我们将看到项目现在被分成了一个`App`组件和一个`Header`组件。该组件以`.svg`文件的形式接收`logo`属性，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/788394ba-bd16-4e9e-8b36-8e4216d6cd50.png)

`Header`组件仍然被分成多个可以拆分为单独组件的元素。看看`img`和`p`元素，它们看起来已经很简单了。但是，`a`元素看起来更复杂，需要接受诸如`url`、`title`、`className`等属性。为了将这个`a`元素改为可重用的组件，它需要被移动到我们项目中的不同位置。

为此，在`components`目录中创建一个名为`Link`的新目录。在该目录中，创建一个名为`Link.js`的新文件。该文件应返回与我们已经在`Header`组件中拥有的相同的`a`元素。此外，我们可以将`url`和`title`作为属性发送到该组件。现在让我们这样做：

1.  从`src/components/Header/Header.css`中删除`App-link`类的样式，并将其放置在名为`Link.css`的文件中：

```jsx
.App-link {
    color: #61dafb;
}
```

1.  创建一个名为`Link`的新组件，该组件接受`url`和`title`属性。该组件将这些属性添加为`<a>`元素的属性，放在`src/components/Link/Link.js`中：

```jsx
import React from 'react';
import './Link.css';

const Link = ({ url, title }) => (
  <a
    className='App-link'
    href={url}
    target='_blank'
    rel='noopener noreferrer'
  >
    {title}
  </a>
);

export default Link;
```

1.  导入这个`Link`组件，并将其放置在`src/components/Header/Header.js`中的`Header`组件中：

```jsx
import React from 'react';
+ import Link from '../Link/Link';

const Header = ({ logo }) => (
 <header className='App-header'>
   <img src={logo} className='App-logo' alt='logo' />
   <p>Edit <code>src/App.js</code> and save to reload.</p>
-  <a -    className='App-link' -    href='https://reactjs.org' -    target='_blank' -    rel='noopener noreferrer' -  > -    Learn React
-  </a>
+  <Link url='https://reactjs.org' title='Learn React' />
 </header>
);

export default Header;
```

我们的代码现在应该如下所示，这意味着我们已成功将目录分成了`containers`和`components`，其中组件被放置在以组件命名的单独子目录中：

```jsx
github-portfolio
|-- node_modules
|-- public
    |-- favicon.ico
    |-- index.html
    |-- manifest.json
|-- src
    |-- components
        |-- Header
            |-- Header.js
            |-- Header.css
        |-- Link
            |-- Link.js
            |-- Link.css
    |-- containers
        |-- App.css
        |-- App.js
    |-- index.css
    |-- index.js
    |-- serviceWorker.js
.gitignore
package.json
```

然而，如果我们在浏览器中查看项目，就看不到任何可见的变化。然而，在 React 开发者工具中，我们的应用程序结构已经形成。`App`组件显示为组件树中的父组件，而`Header`组件是一个具有`Link`作为子组件的子组件。

在本节的下一部分，我们将向该应用程序的组件树中添加更多组件，并使这些组件在整个应用程序中可重用。

# 在 React 中重用组件

我们在本章中构建的项目是一个 GitHub 作品集页面；它将显示我们的公共信息和公共存储库的列表。因此，我们需要获取官方的 GitHub REST API（v3）并从两个端点拉取信息。获取数据是我们在第一章中做过的事情，但这次信息不会来自本地 JSON 文件。检索信息的方法几乎是相同的。我们将使用 fetch API 来做这件事。

我们可以通过执行以下命令从 GitHub 检索我们的公共 GitHub 信息。将代码的粗体部分末尾的`username`替换为您自己的`username`：

```jsx
curl 'https://api.github.com/users/username'
```

如果您没有 GitHub 个人资料或者没有填写所有必要的信息，您也可以使用`octocat`用户名。这是 GitHub `吉祥物`的用户名，已经填充了示例数据。

这个请求将返回以下输出：

```jsx
{
  "login": "octocat",
  "id": 1,
  "node_id": "MDQ6VXNlcjE=",
  "avatar_url": "https://github.com/images/error/octocat_happy.gif",
  "gravatar_id": "",
  "url": "https://api.github.com/users/octocat",
  "html_url": "https://github.com/octocat",
  "followers_url": "https://api.github.com/users/octocat/followers",
  "following_url": "https://api.github.com/users/octocat/following{/other_user}",
  "gists_url": "https://api.github.com/users/octocat/gists{/gist_id}",
  "starred_url": "https://api.github.com/users/octocat/starred{/owner}{/repo}",
  "subscriptions_url": "https://api.github.com/users/octocat/subscriptions",
  "organizations_url": "https://api.github.com/users/octocat/orgs",
  "repos_url": "https://api.github.com/users/octocat/repos",
  "events_url": "https://api.github.com/users/octocat/events{/privacy}",
  "received_events_url": "https://api.github.com/users/octocat/received_events",
  "type": "User",
  "site_admin": false,
  "name": "monalisa octocat",
  "company": "GitHub",
  "blog": "https://github.com/blog",
  "location": "San Francisco",
  "email": "octocat@github.com",
  "hireable": false,
  "bio": "There once was...",
  "public_repos": 2,
  "public_gists": 1,
  "followers": 20,
  "following": 0,
  "created_at": "2008-01-14T04:33:35Z",
  "updated_at": "2008-01-14T04:33:35Z"
}
```

JSON 输出中的多个字段都被突出显示，因为这些是我们在应用程序中将使用的字段。这些字段是`avatar_url`，`html_url`，`repos_url`，`name`，`company`，`location`，`email`和`bio`，其中`repos_url`字段的值实际上是另一个我们需要调用以检索该用户所有存储库的 API 端点。这是我们将在本章稍后要做的事情。

由于我们想在应用程序中显示这个结果，我们需要做以下事情：

1.  要从 GitHub 检索这些公共信息，请创建一个名为`Profile`的新容器，并将以下代码添加到`src/containers/Profile.js`中：

```jsx
import React, { Component } from 'react';

class Profile extends Component {
  constructor() {
    super();
    this.state = {
      data: {},
      loading: true,
    }
  }

  async componentDidMount() {
    const profile = await fetch('https://api.github.com/users/octocat');
    const profileJSON = await profile.json();

    if (profileJSON) {
      this.setState({
        data: profileJSON,
        loading: false,
      })
    }
  }

  render() {
    return (
      <div></div>
    );
  }
}

export default Profile;
```

这个新组件包含一个`constructor`，其中设置了`state`的初始值，以及一个`componentDidMount`生命周期方法，该方法在异步使用时，当获取的 API 返回结果时，为`state`设置一个新值。由于我们仍然需要创建新组件来显示数据，因此尚未呈现任何结果。

现在，将这个新组件导入到`App`组件中：

```jsx
import React, { Component } from 'react';
+ import Profile from './Profile';
import Header from '../components/Header/Header';
import logo from '../logo.svg';
import './App.css';

class App extends Component {
  render() {
    return (
      <div className='App'>
        <Header logo={logo} />
+       <Profile />
      </div>
    );
  }
}

export default App;
```

1.  快速查看我们项目运行的浏览器，我们会发现这个新的`Profile`组件还没有显示。这是因为`Header.css`文件具有`height`属性，其`view-height`为`100`，这意味着组件将占据整个页面的高度。要更改此设置，请打开`scr/components/App/Header.css`文件并更改以下突出显示的行：

```jsx
.App-logo {
- height: 40vmin;
+ height: 64px;
  pointer-events: none;
}

.App-header {
  background-color: #282c34;
- min-height: 100vh;
+ height: 100%;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  font-size: calc(10px + 2vmin);
  color: white;
}

...
```

1.  我们的页面上应该有足够的空间来显示`Profile`组件，因此我们可以再次打开`scr/containers/Profile.js`文件，并显示 GitHub API 返回的`avatar_url`、`html_url`、`repos_url`、`name`、`company`、`location`、`email`和`bio`字段：

```jsx
...

render() {
+   const { data, loading } = this.state;

+   if (loading) {
+       return <div>Loading...</div>;
+   }

    return (
      <div>
+       <ul>
+         <li>avatar_url: {data.avatar_url}</li>
+         <li>html_url: {data.html_url}</li>
+         <li>repos_url: {data.repos_url}</li>
+         <li>name: {data.name}</li>
+         <li>company: {data.company}</li>
+         <li>location: {data.location}</li>
+         <li>email: {data.email}</li>
+         <li>bio: {data.bio}</li>
+       </ul>
      </div>
    );
  }
}

export default Profile;
```

保存此文件并在浏览器中访问我们的项目后，我们将看到显示 GitHub 信息的项目列表，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/7b14fcee-a574-4e35-a40a-ed63173b16df.png)

由于这看起来不太好看，页眉与页面内容不匹配，让我们对这两个组件的`样式`文件进行一些更改：

1.  更改`Header`组件的代码，删除 React 标志，并用 GitHub 标志替换它。我们不再需要从`App`组件中获取`logo`作为属性。此外，`Link`组件可以从这里删除，因为我们将在稍后在`Profile`组件中使用它：

```jsx
import React from 'react';
- import logo from '../logo.svg';
+ import logo from '../../GitHub-Mark-Light-64px.png';
- import Link from '../components/Link';
import './Header.css';

- const Header = ({ logo }) => (
+ const Header = () => (
  <header className='App-header'>
    <img src={logo} className='App-logo' alt='logo' />
-   <p>
+   <h1>
-     Edit <code>src/App.js</code> and save to reload.
+     My Github Portfolio
-   </p>
+   </h1> -   <Link url='https://reactjs.org' title='Learn React' />
  </header>
);

export default Header;
```

1.  更改`scr/containers/Profile.js`中的突出显示的行，我们将把头像图像与项目列表分开，并在字段名称周围添加`strong`元素。还记得我们之前创建的`Link`组件吗？这将用于在 GitHub 网站上创建指向我们个人资料的链接：

```jsx
import React, { Component } from 'react';
+ import Link from '../components/Link/Link';
+ import './Profile.css';

class Profile extends Component {

  ...

      return (
-       <div>
+       <div className='Profile-container'>
+         <img className='Profile-avatar' src={data.avatar_url} alt='avatar' />
-         <ul>
-           ...
-         </ul>
+         <ul>
+           <li><strong>html_url:</strong> <Link url={data.html_url} title='Github URL' /></li>
+           <li><strong>repos_url:</strong> {data.repos_url}</li>
+           <li><strong>name:</strong> {data.name}</li>
+           <li><strong>company:</strong> {data.company}</li>
+           <li><strong>location:</strong> {data.location}</li>
+           <li><strong>email:</strong> {data.email}</li>
+           <li><strong>bio:</strong> {data.bio}</li>
+         </ul>
+      </div>
    );
  }
}

export default Profile;
```

1.  不要忘记创建`src/containers/Profile.css`文件，并将以下代码粘贴到其中。这定义了`Profile`组件的样式：

```jsx
.Profile-container {
  width: 50%;
  margin: 10px auto;
}

.Profile-avatar {
  width: 150px;
}

.Profile-container > ul {
 list-style: none;
 padding: 0;
 text-align: left;
}

.Profile-container > ul > li {
 display: flex;
 justify-content: space-between;
}
```

最后，我们可以看到应用程序开始看起来像一个 GitHub 作品集页面，其中有一个显示 GitHub 标志图标和标题的页眉，接着是我们的 GitHub 头像和我们的公共信息列表。这导致应用程序看起来类似于以下截图中显示的内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/4a6bca76-315e-4f83-993b-f5d29a3e0840.png)

如果我们查看`Profile`组件中的代码，我们会发现有很多重复的代码，因此我们需要将显示我们公共信息的列表转换为一个单独的组件。让我们开始吧：

1.  在新的`src/components/List`目录中创建一个名为`List.js`的新文件：

```jsx
import React from 'react';

const List = () => (
  <ul></ul>
);

export default List;
```

1.  在`Profile`组件中，可以在`src/containers/Profile.js`文件中找到，我们可以导入这个新的`List`组件，构建一个包含我们想要在此列表中显示的所有项目的新数组，并将其作为一个 prop 发送。对于`html_url`字段，我们将发送`Link`组件作为值，而不是从 GitHub API 返回的值：

```jsx
import React, { Component } from 'react';
import Link from '../components/Link/Link';
+ import List from '../components/List/List';

class Profile extends Component {

...

render() {
  const { data, loading } = this.state;

  if (loading) {
    return <div>Loading...</div>;
  }

+ const items = [
+   { label: 'html_url', value: <Link url={data.html_url} title='Github URL' /> },
+   { label: 'repos_url', value: data.repos_url },
+   { label: 'name', value: data.name},
+   { label: 'company', value: data.company },
+   { label: 'location', value: data.location },
+   { label: 'email', value: data.email },
+   { label: 'bio', value: data.bio }
+ ]

  return (
    <div className='Profile-container'>
      <img className='Profile-avatar' src={data.avatar_url} alt='avatar' />
-     <ul>
-       <li><strong>html_url:</strong> <Link url={data.html_url} title='Github URL' /></li>
-       <li><strong>repos_url:</strong> {data.repos_url}</li>
-       <li><strong>name:</strong> {data.name}</li>
-       <li><strong>company:</strong> {data.company}</li>
-       <li><strong>location:</strong> {data.location}</li>
-       <li><strong>email:</strong> {data.email}</li>
-       <li><strong>bio:</strong> {data.bio}</li>
-     </ul>
+     <List items={items} />
    </div>
   );
  }
}

export default Profile;
```

1.  在`List`组件中，我们现在可以映射`items`属性并返回带有样式的列表项：

```jsx
import React from 'react';

- const List = () => (
+ const List = ({ items }) => (
  <ul>
+   {items.map(item =>
+     <li key={item.label}>
+       <strong>{item.label}</strong>{item.value}
+     </li>
+   )}
  </ul>
);

export default List;
```

假设我们正确执行了前面的步骤，你的应用在美学上不应该有任何变化。然而，如果我们查看 React 开发者工具，我们会发现组件树已经发生了一些变化。

在下一节中，我们将使用`styled-components`而不是 CSS 来为这些组件添加样式，并添加链接到我们 GitHub 账户的存储库。

# 使用`styled-components`在 React 中添加样式

到目前为止，我们一直在使用 CSS 文件为我们的 React 组件添加样式。然而，这迫使我们在不同的组件之间导入这些文件，这使得我们的代码不够可重用。因此，我们将把`styled-components`包添加到项目中，这允许我们在 JavaScript 中编写 CSS（所谓的**CSS-in-JS**）并创建组件。

通过这样做，我们将更灵活地为我们的组件添加样式，可以防止由于`classNames`而产生样式重复或重叠，并且可以轻松地为组件添加动态样式。所有这些都可以使用我们用于 CSS 的相同语法来完成，就在我们的 React 组件内部。

第一步是使用`npm`安装`styled-components`：

```jsx
npm install styled-components
```

如果你查看`styled-components`的官方文档，你会注意到他们强烈建议你也使用这个包的 Babel 插件。但是，由于你使用 Create React App 来初始化你的项目，你不需要添加这个插件，因为所有编译你的应用程序需要的工作已经被`react-scripts`处理了。

安装`styled-components`后，让我们尝试从其中一个组件中删除 CSS 文件。一个很好的开始是`Link`组件，因为这是一个非常小的组件，功能有限：

1.  首先导入`styled-components`包并创建一个名为`InnerLink`的新样式化组件。这个组件扩展了一个`a`元素，并采用了我们已经为`className` `App-link`得到的 CSS 规则：

```jsx
import React from 'react';
+ import styled from 'styled-components'; import './Link.css';

+ const InnerLink = styled.a`
+  color: #61dafb;
+ `;

const Link = ({ url, title }) => (
  <a className='App-link'
    href={url}
    target='_blank'
    rel='noopener noreferrer'
  >
    {title}
  </a>
);

export default Link;
```

1.  添加了这个组件后，我们可以用这个 styled component 替换现有的`<a>`元素。此外，我们也不再需要导入`Link.css`文件，因为所有的样式现在都在这个 JavaScript 文件中进行了设置。

```jsx
import React from 'react';
import styled from 'styled-components';
- import './Link.css';

const InnerLink = styled.a`
 color: #61dafb;
`;

const Link = ({ url, title }) => (
- <a className='App-link'
+ <InnerLink
    href={url}
    target='_blank'
    rel='noopener noreferrer'
  >
    {title}
- </a>
+ </InnerLink>
);

export default Link;
```

如果我们再次运行`npm start`并在浏览器中访问我们的项目，我们会看到删除 CSS 文件后，我们的应用程序仍然看起来一样。下一步是替换所有导入 CSS 文件进行样式设置的其他组件：

1.  为`src/components/Header/Header.js`中的`Header`组件添加`styled-components`并删除 CSS 文件：

```jsx
import React from 'react';
+ import styled from 'styled-components';
import logo from '../../GitHub-Mark-Light-64px.png';
- import './Header.css'

+ const HeaderWrapper = styled.div`
+  background-color: #282c34;
+  height: 100%;
+  display: flex;
+  flex-direction: column;
+  align-items: center;
+  justify-content: center;
+  font-size: calc(10px + 2vmin);
+  color: white;
+ `;

+ const Logo = styled.img`
+  height: 64px;
+  pointer-events: none;
+ `;

const Header = ({ logo }) => (
- <header className='App-header'>
+ <HeaderWrapper>
    <Logo src={logo} alt='logo' />
    <h1>My Github Portfolio</h1>
- </header>
+ </HeaderWrapper>
);

export default Header;
```

1.  为`src/containers/App.js`中的`App`组件添加`styled-components`并删除 CSS 文件：

```jsx
import React, { Component } from 'react';
+ import styled from 'styled-components';
import Profile from './Profile';
import Header from '../components/App/Header';
- import './App.css'; 
+ const AppWrapper = styled.div`
+  text-align: center;
+ `;

class App extends Component {
 render() {
   return (
-    <div className="App">
+    <AppWrapper>
       <Header />
       <Profile />
-    </div>
+    </AppWrapper>
   );
  }
}

export default App;
```

1.  为`List`组件中的`ul`、`li`和`strong`元素添加一些 styled components：

```jsx
import React from 'react';
+ import styled from 'styled-components';

+ const ListWrapper = styled.ul`
+  list-style: none;
+  text-align: left;
+  padding: 0;
+ `;

+ const ListItem = styled.li`
+  display: flex;
+  justify-content: space-between;
+ `;

+ const Label = styled.span`
+  font-weight: strong;
+ `;

const List = ({ items }) => (
- <ul>
+ <ListWrapper>
    {items.map(item =>
-     <li key={item.label}>
+     <ListItem key={item.label}>
-       <strong>{item.label}</strong>{item.value}
+       <Label>{item.label}</Label>{item.value}
-     </li>
+     </ListItem>
    )}
-  </ul>
+  </ListWrapper>
);

export default List;
```

1.  最后，通过将`Profile`组件中的最后两个元素转换为 styled components，删除`Profile.css`文件：

```jsx
import React, { Component } from 'react';
+ import styled from 'styled-components';
import Link from '../components/Link/Link';
import List from '../components/List/List';
- import './Profile.css';

+ const ProfileWrapper = styled.div`
+  width: 50%;
+  margin: 10px auto;
+ `;

+ const Avatar = styled.img`
+  width: 150px;
+ `;

class Profile extends Component {

...

  return (
-   <div className='Profile-container'>
+   <ProfileWrapper>
-     <img className='Profile-avatar' src={data.avatar_url} alt='avatar' />
+     <Avatar src={data.avatar_url} alt='avatar' />
 <List items={items} />
-   </div>
+   </ProfileWrapper>
  );
 }
}

export default Profile;
```

现在再次在浏览器中打开项目；我们的应用程序应该看起来仍然一样。我们所有的组件都已经转换为使用`styled-components`，不再使用 CSS 文件和`classNames`进行样式设置。不要忘记删除`containers`和`components`目录及子目录中的`.css`文件。

然而，在项目中仍然有一个 CSS 文件直接位于`src`目录内。这个 CSS 文件包含了`<body>`元素的样式，该元素存在于`public/index.html`文件中，并已被导入到`src/index.js`文件中。为了删除这个 CSS 文件，我们可以使用`styled-components`中的`createGlobalStyle`函数来为我们的应用程序添加`<body>`元素的样式。

我们可以为`App`组件内的全局样式创建一个 styled component，并将`<body>`元素的 CSS 样式粘贴到其中。由于这个组件应该与我们的`AppWrapper`组件在组件树中处于相同的层次结构，我们需要使用**React Fragments**，因为 JSX 组件应该被封装在一个封闭标签内。

```jsx
import React, { Component } from 'react';
- import styled from 'styled-components';
+ import styled, { createGlobalStyle } from 'styled-components';
import Profile from './Profile';
import Header from '../components/App/Header';

+ const GlobalStyle = createGlobalStyle`
+  body {
+    margin: 0;
+    padding: 0;
+    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Roboto", "Oxygen",
+    "Ubuntu", "Cantarell", "Fira Sans", "Droid Sans", "Helvetica Neue",
+    sans-serif;
+    -webkit-font-smoothing: antialiased;
+    -moz-osx-font-smoothing: grayscale;
+  }
+ `;

...

class App extends Component {
 render() {
   return (
+   <> 
+    <GlobalStyle />
     <AppWrapper>
       <Header />
       <Profile />
     </AppWrapper>
+   </>
  );
 }
}

export default App;
```

`<>`标签是`<React.Fragment>`的简写。这些 React Fragments 用于在单个封闭标签内列出子组件，而无需向 DOM 添加额外的节点。

现在，我们应该能够删除项目中的最后一个 CSS 文件，即`src/index.css`。我们可以通过在浏览器中查看项目来确认这一点。我们将看不到由`src/index.css`文件设置的`body`字体的任何更改。

最后一步是在 Github 作品集页面上显示我们 Github 个人资料中的存储库。检索这些存储库的 API 端点也是由检索我们用户信息的端点返回的。要显示这些存储库，我们可以重用之前创建的`List`组件：

1. 从 API 端点加载存储库列表并将其添加到`src/containers/Profile.js`中的`state`中：

```jsx
...

class Profile extends Component {
  constructor() {
    super();
    this.state = {
      data: {},
+     repositories: [],
      loading: true,
    }
  }

  async componentDidMount() {
    const profile = await fetch('https://api.github.com/users/octocat');
    const profileJSON = await profile.json();

    if (profileJSON) {
+     const repositories = await fetch(profileJSON.repos_url);
+     const repositoriesJSON = await repositories.json();

      this.setState({
        data: profileJSON,
+       repositories: repositoriesJSON,
        loading: false,
      })
    }
  }

  render() {
-   const { data, loading } = this.state; 
+   const { data, loading, repositories } = this.state;

    if (loading) {
      return <div>Loading...</div>
    }

    const items = [
      ...
    ];

 +  const projects = repositories.map(repository => ({
 +    label: repository.name,
 +    value: <Link url={repository.html_url} title='Github URL' />
 +  }));

...
```

1.  接下来，为存储库返回一个`List`组件，并向该列表发送一个名为`title`的 prop。我们这样做是因为我们想显示两个列表之间的区别：

```jsx
...

  render() {

  ...

    const projects = repositories.map(repository => ({
      label: repository.name,
      value: <Link url={repository.html_url} title='Github URL' />
    }));

    return (
      <ProfileWrapper>
         <Avatar src={data.avatar_url} alt='avatar' />
-       <List items={items} />
+       <List title='Profile' items={items} />
+       <List title='Projects' items={projects} />
      </ProfileWrapper>
    );
  }
}

export default Profile;
```

1.  对`src/components/List/List.js`中的`List`组件进行更改，并在每个列表的顶部显示标题。在这种情况下，我们将使用 React Fragments 来防止不必要的节点被添加到 DOM 中：

```jsx
import React from 'react';
import styled from 'styled-components';

+ const Title = styled.h2`
+  padding: 10px 0;
+  border-bottom: 1px solid lightGrey;
+ `;

...

- const List = ({ items }) => (
+ const List = ({ items, title }) => (
+  <>
+    <Title>{title}</Title>
     <ListWrapper>
       {items.map(item =>
         <ListItem key={item.label}>
           <Label>{item.label}</Label>{item.value}
         </ListItem>
       )}
     </ListWrapper>
+  </>
);

export default List;
```

现在，如果我们再次在浏览器中访问该项目，我们将看到我们在本章中创建的 GitHub 作品集页面。该应用程序将看起来像以下截图所示，其中使用了上一节中的默认 GitHub 用户来获取数据：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/00e9930a-3f0f-49b0-9e4d-9ff95764cf33.png)

现在，我们已经使用了 Create React App 并启用了项目作为 PWA 的设置，当我们访问项目的`build`版本时，应该能够看到一个缓存版本。要构建项目，请运行以下命令：

```jsx
npm run build
```

然后，通过运行以下命令来提供`build`版本：

```jsx
serve -s build
```

我们可以通过访问`http://localhost:5000/`来查看我们应用程序的`build`版本。但是，我们可能会看到我们应用程序的第一个版本。这是因为该项目已创建为 PWA，因此将显示应用程序的缓存版本。我们可以通过转到浏览器的开发者工具中的`Application`选项卡来重新启动 Service Worker 并缓存我们应用程序的新版本：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-pj/img/80bd80d0-95b5-4e87-b362-4ddb32fcb1af.png)

在此页面中，选择侧边栏中的 Service Workers。从这里，我们可以通过按下`Update`按钮来更新`localhost`的 service worker。`service-worker.js`文件将被再次调用，并且当前缓存的版本将被新版本替换。我们还可以通过检查`Offline`复选框来测试我们的应用程序在互联网连接失败时的响应方式。

正如我们所看到的，`Header`组件已经被正确缓存，但是没有来自 GitHub 的信息被显示出来。相反，`Profile`组件显示了一个`Loading...`消息，因为没有从 API 请求中返回任何信息。如果我们在浏览器中打开开发者工具并查看控制台，我们会看到一个错误消息。我们可以捕获这个错误来显示为什么我们的应用程序不包含任何内容的原因：

1.  为了做到这一点，我们需要改变`src/containers/Profile.js`文件，并向`state`添加一个名为`error`的变量：

```jsx
...

class Profile extends Component {
  constructor() {
    super();
    this.state = {
      data: {},
      repositories: [],
      loading: false,
+     error: '',
    }
  }

  async componentDidMount() {
     ...
```

1.  这个变量要么是一个空字符串，要么包含`try...catch`方法返回的错误消息：

```jsx
...

  async componentDidMount() {
+   try {
      const profile = await fetch('https://api.github.com/users/octocat');
      const profileJSON = await profile.json();

      if (profileJSON) {
        const repositories = await fetch(profileJSON.repos_url);
        const repositoriesJSON = await repositories.json();

       this.setState({
         data: profileJSON,
         repositories: repositoriesJSON,
         loading: false,
       });
     }
   }
+  catch(error) {
+    this.setState({
+      loading: false,
+      error: error.message,
+    });
+  }
+ } ...
```

1.  当组件被渲染时，如果发生错误，错误状态也应该从状态中获取并显示，而不是显示加载状态。

```jsx
...

render() {
-  const { data, loading, repositories } = this.state;
+  const { data, loading, repositories, error } = this.state;

-  if (loading) {
-    return <div>Loading...</div>;
+  if (loading || error) {
+    return <div>{loading ? 'Loading...' : error}</div>;
  }

...

export default Profile;
```

通过这些更改，状态现在具有加载状态的初始值，在应用程序首次挂载时显示`Loading...`消息。GitHub 端点被包裹在`try...catch`语句中，这意味着当`fetch`函数失败时，我们可以捕获错误消息。如果发生这种情况，`loading`的值将被错误消息替换。

我们可以通过再次构建我们的应用程序并在本地运行它来检查这些更改是否起作用，就像这样：

```jsx
npm run build
serve -s build
```

当我们访问项目`http://localhost:5000`并在浏览器的开发者工具中的`Application`选项卡中将应用程序设置为离线模式时，我们将看到一个`Failed to fetch`消息被显示出来。现在，我们知道如果用户在没有活动互联网连接的情况下使用我们的应用程序，他们将看到这条消息。

# 总结

在本章中，您使用 Create React App 创建了 React 应用程序的起始项目，该项目具有用于库（如 Babel 和 webpack）的初始配置。通过这样做，您不必自己配置这些库，也不必担心您的 React 代码将如何在浏览器中运行。此外，Create React App 还提供了 PWA 的默认设置，您可以通过注册服务工作程序来使用。这使得您的应用程序在没有互联网连接或在移动设备上运行时可以平稳运行。还记得以前如何使用 CSS 来为应用程序添加样式吗？本章向您展示了如何使用`styled-components`包来创建可重用且无需导入任何 CSS 文件的样式化组件，因为它使用了 CSS-in-JS 原则。

即将到来的章节将全部使用 Create React App 创建的项目，这意味着这些项目不需要您对 webpack 或 Babel 进行更改。您在本章中喜欢使用`styled-components`吗？那么您将喜欢这本书中大多数项目都是使用这个包进行样式设计，包括下一章。

在下一章中，我们将在本章的基础上创建一个使用 React 的动态项目管理板，其中使用了**Suspense**等功能。

# 进一步阅读

+   Create React App: [`facebook.github.io/create-react-app/`](https://facebook.github.io/create-react-app/)

+   使用 npx: [`medium.com/@maybekatz/introducing-npx-an-npm-package-runner-55f7d4bd282b`](https://medium.com/@maybekatz/introducing-npx-an-npm-package-runner-55f7d4bd282b)

+   使用 Create React App 创建 PWA [`facebook.github.io/create-react-app/docs/making-a-progressive-web-app`](https://facebook.github.io/create-react-app/docs/making-a-progressive-web-app)

+   关于`manifest.json`文件：[`developers.chrome.com/apps/manifest`](https://developers.chrome.com/apps/manifest)

+   Styled components: [`www.styled-components.com/docs/basics`](https://www.styled-components.com/docs/basics)
