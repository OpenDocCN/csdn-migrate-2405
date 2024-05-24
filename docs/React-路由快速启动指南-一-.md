# React 路由快速启动指南（一）

> 原文：[`zh.annas-archive.org/md5/64054E4C94EED50A4AF17DC3BC635620`](https://zh.annas-archive.org/md5/64054E4C94EED50A4AF17DC3BC635620)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Facebook 的 React 框架重新定义了前端应用程序的构建方式。React Router 已成为使用 React 构建的应用程序的事实标准路由框架。通过其最新的 4 版本发布，该库已经在 React 中重写，并且它允许您以声明方式处理路由。在本书中，您将学习 react-router 库如何在任何 React 应用程序中使用，包括使用 React Native 开发的 Web 和原生移动应用程序。该书还涵盖了诸如服务器端路由和 Redux 与 React Router 集成等主题。

# 这本书适合谁

本书适用于考虑使用 React 和 React Router 构建应用程序的 Web 和原生移动应用程序开发人员。了解 React 框架和 JavaScript 的一些知识将有助于理解本书中讨论的概念。

# 要充分利用这本书

React Router 用于使用 React 开发的 Web 和原生应用程序。本书假定您对 JavaScript 有很好的理解，并且了解 ECMAScript 6 中引入的一些新语言特性，例如类和扩展运算符。

本书简要介绍了 React 和基于组件的架构。React 的一些其他核心概念在[`reactjs.org`](https://reactjs.org)有文档记录。

本书假定读者已经使用 Node.js 和 NPM 从 NPM 存储库安装了库和软件包。

# 下载示例代码文件

您可以从[www.packt.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[www.packt.com/support](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册

1.  选择“支持”选项卡

1.  单击“代码下载和勘误”

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保您使用最新版本的解压缩或提取文件夹：

+   WinRAR/Windows 的 7-Zip

+   Mac 的 Zipeg/iZip/UnRarX

+   7-Zip/PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/React-Router-Quick-Start-Guide`](https://github.com/PacktPublishing/React-Router-Quick-Start-Guide)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：`www.packtpub.com/sites/default/files/downloads/9781789532555_ColorImages.pdf.`

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：指示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。”

代码块设置如下：

```jsx
In GitHubComponent
GitHub ID - mjackson
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```jsx
<Route
 to='/github/**:githubID**'
    component={GitHubComponent}  />
```

任何命令行输入或输出都以以下方式编写：

```jsx
 Root:
 path: /category, isExact: true
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“从管理面板中选择系统信息。”

警告或重要说明会出现在这样的地方。提示和技巧会出现在这样的地方。


# 第一章：React Router 4 简介和创建您的第一个路由

单页应用程序（SPA）已成为开发 Web 应用程序的事实标准。许多 JavaScript 库和框架已经出现，帮助前端工程师开发 SPA。其中包括 React、Angular、Ember 和 Backbone 等。这些库或框架抽象了原生 API，并提供了可以用于更快地构建应用程序的服务和组件。SPA 是提供流畅用户体验的绝佳选择；当用户在网站中浏览时，会触发 HTTP 请求，只会更新页面的某些部分，而不是请求整个页面的服务器。

React 是一个开源的 JavaScript 库，帮助您构建 Web 和移动应用程序中的用户界面和视图层。它鼓励开发人员将视图层视为可以在整个应用程序中重用的组件集合。大多数前端框架都包含一个路由包，它使您能够在用户点击网站上提供的各种链接时更新页面的各个部分。前端框架中的路由器会监听 URL 的变化，并通过渲染相应的视图组件来保持应用程序同步。例如，当用户访问`'/dashboard'`时，页面将呈现各种仪表板组件，如图表和表格；当用户访问`'/user'`时，页面将列出各种用户属性。在基于 React 的应用程序中，需要一个路由器库，因为 React 本身不带有路由器。React-Router 是一个完全基于 React 构建的流行路由库。该库包括各种组件，可用于在用户浏览应用程序时呈现视图。除了匹配 URL 和呈现视图组件外，React-Router 还具有一些功能，可帮助您轻松配置路由。

本章讨论以下主题：

+   React 简介：本节介绍了 React 中的一些核心概念，如基于组件的架构、在 React 中创建组件以及如何向应用程序树中的子组件提供数据

+   React-Router 简介：在这里，我们首先使用`create-react-app` CLI 创建一个 React 应用程序，然后将 React-Router 库（`'react-router-dom'`包）添加为依赖项

+   创建您的第一个路由：在添加 React-Router 作为依赖项后，使用 `<BrowserRouter>` 和 `<Route>` 组件创建应用程序的第一个路由。

# 简要了解 React

React 是一个提供一组组件和服务的 JavaScript 库，使您能够构建用户界面。

以下是来自 `reactjs.org` 的引用：

"React 是一个声明式、高效、灵活的 JavaScript 库，用于构建用户界面。"

该库由 Facebook 开发和维护，根据 MIT 许可。它被广泛用于构建 Facebook 的各种应用程序，包括 Facebook 网站和 Instagram 网站。

React 使您能够构建视图组件，在应用程序状态更改时进行更新。这里的状态可能指的是底层领域数据，也可能反映用户在应用程序旅程中的位置。React 确保视图组件反映应用程序状态。

React 的一些重要特性：

+   JSX：React 应用程序中的组件使用类似 XML/HTML 的语法，称为 JSX，来渲染视图元素。JSX 允许您在 JavaScript/React 代码中包含 HTML；在 React 组件的渲染函数中使用熟悉的带有属性的 HTML 语法，无需学习新的模板语言。预处理器（如 Babel）将使用 JSX 将 HTML 文本转译为 JavaScript 对象，以便 JavaScript 引擎能够理解。

+   单向数据绑定：React 应用程序组织为一系列嵌套组件；一组不可变值作为属性传递给组件的渲染器，以 HTML 标签的形式。组件不会修改其从父组件接收的属性（或 props）；相反，子组件将用户操作传达给其父组件，父组件通过更新组件的状态来修改这些属性。

+   虚拟 DOM：在 React 中，为每个 DOM 对象创建一个相应的虚拟 DOM 对象，其具有与真实 DOM 对象相同的一组属性。但是，虚拟 DOM 对象缺乏在用户与页面交互时更新视图的能力。React 中的组件在检测到状态变化时重新渲染视图元素，这种重新渲染会更新虚拟 DOM 树。然后，React 将此虚拟 DOM 树与更新前创建的快照进行比较，以确定更改的 DOM 对象。最后，React 通过仅更新更改的 DOM 对象来修改真实 DOM。

# React 中的基于组件的架构

自 2013 年发布以来，React 已经重新定义了前端应用程序的构建方式。它引入了基于组件的架构的概念，本质上允许您将应用程序视为由小型、自包含的视图组件组成。这些视图组件是可重用的；也就是说，诸如`CommentBox`或`Footer`之类的组件封装了必要的功能，并可以在站点的各个页面中使用。

在这种情况下，页面本身是一个视图组件，由其他小的视图组件组成，如下所示：

```jsx
<Dashboard>
    <Header>
        <Brand />
    </Header>
    <SideNav>
        <NavLink key=”1”>
        <NavLink key=”2”>
    </SideNav>
    <ContentArea>
        <Chart>
        <Grid data="stockPriceList">
    </ContentArea>
    <Footer />
</Dashboard>
```

在这里，`<Dashboard>`是一个视图组件，包含了几个其他视图组件（`Header`、`SideNav`、`ContentArea`和`Footer`），这些又由小组件（`Brand`、`NavLink`、`Chart`和`Grid`）组成。基于组件的架构鼓励您构建提供特定功能并且不与任何父级或同级组件紧密耦合的组件。这些组件实现了某些功能，并提供了一个接口，通过这个接口它们可以被包含在页面中。

在前面的例子中，`<Grid>`组件将包括渲染数据的行和列、提供搜索功能，以及按升序或降序对列进行排序的功能。`<Grid>`组件将实现所有上述功能，并提供一个接口，通过这个接口它可以被包含在页面中。这里的接口将包括标签名（`Grid`）和一组属性（`props`），接受来自其父组件的值。在这里，`<Grid>`组件可以与后端系统进行接口，并检索数据；然而，这将使组件与给定的后端接口紧密耦合，因此无法重用。理想情况下，视图组件将从其父组件接收数据并相应地进行操作。

```jsx
<Grid data="stockPriceList" />
```

在这里，`<Grid>`组件通过其`data`属性接收包含股票价格信息的列表，并以表格格式呈现这些信息。包含这个`<Grid>`组件的组件可以被称为`Container`组件，`Grid`作为子组件。

`Container`组件也是`View`组件；然而，它的责任包括为其子组件提供必要的数据来渲染。`Container`组件可以发起 HTTP 调用到后端服务并接收渲染其子组件所需的数据。此外，`Container`组件还负责将单个视图组件定位在其视图区域内。

# 创建一个 React 组件

通过扩展 React 提供的`Component`类来创建 React 组件如下：

```jsx
import React, { Component } from 'react';
import './button.css';

export class Button extends Component {
    render() {
        return (
            <button className={this.props.type}>
                {this.props.children}
            </button>
        );
    }
}
```

在这里，`Button`类扩展了 React 的`Component`类并重写了`render`方法。`render`方法返回将在页面加载时呈现在 DOM 上的 JSX。`type`和`children`属性在`this.props`中可用。React 允许您通过 props 将数据传递给其组件，并通过以下语法来实现：

```jsx
import React, { Component } from 'react';
import { Button } from './components/Button/button';
import './App.css';

export default class App extends Component {
    render() {
        return (
            <div className="App">
                <Button type="secondary">CANCEL</Button>
                <Button type="primary">OK</Button>
            </div>
        );
    }
}
```

在这里，我们将`Button`组件包裹在父组件`App`中，以渲染两个按钮元素。`type`属性被`Button`组件使用来设置`CANCEL`和`OK`按钮的类名(`className`)和`Button`标签内提到的文本。这可以通过`children`属性来引用。`children`属性可以是纯文本或其他视图组件。子组件使用`this.props`来引用其父组件提供的数据。`'this.props'`中的`children`属性提供了父组件在标签之间包含的所有子元素的引用。如果您以前使用过 Angular，请将前面的片段视为类似于在 AngularJS 中使用`ng-transclude`或在 Angular 中使用`ng-content`来包含元素。

在这里，`<App>`组件包含`<Button>`组件，可以被称为容器组件，负责在页面上渲染按钮。

下一步是在 DOM 上呈现`<App>`组件。`<App>`组件充当根组件，即树中的根节点。应用程序中的每个组件都将`<App>`组件作为其最顶层的父组件：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';
import App from './App'; 
import './index.css'; 

ReactDOM.render(<App />, document.getElementById('root'));
```

这段代码包含在`index.js`中，它导入了`React`和`ReactDOM`库。`ReactDOM`库有一个`render`方法，它接受要渲染的组件作为其第一个参数，并且根组件要渲染到的 DOM 节点的引用作为第二个参数。

运行应用程序时，将呈现在`<App>`组件内的内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rtr-qk-st-gd/img/f609ed22-23a6-483c-ae65-56181fbc1ef5.png)

# React-Router 简介

React-Router 是用 React 构建的 SPA 的路由库。React-Router 版本 4 是一个完全的重写，并采用了基于组件的架构的 React 哲学。

这是来自 React-Router 文档（[`reacttraining.com/react-router/`](https://reacttraining.com/react-router/)）

“React Router 是一组与您的应用程序声明性地组合的**导航组件**。无论您是想为您的 Web 应用程序拥有**可书签的 URL**还是想以**React Native**中的可组合方式导航，*React Router*都可以在 React 渲染的任何地方使用--所以*随你*选择！”

React-Router 可以在 React 可以应用的任何地方使用；也就是说，React-Router 在浏览器和使用 React Native 的本地环境中都可以工作。

该库分为三个包：

+   `react-router`：DOM 和本地版本的常见核心组件

+   `react-router-dom`：用于浏览器和 Web 应用程序的组件

+   `react-router-native`：用于使用 React Native 构建的本地应用程序的组件

该库提供了各种组件，可用于动态添加路由到您的应用程序。React-Router v4 中的动态路由允许您在用户通过应用程序旅程时指定应用程序路由。诸如 AngularJS 和 Express 之类的框架要求您预先指定路由，并且在应用程序引导时需要此路由信息。实际上，React-Router 的早期版本遵循了相同的范例，并且需要提前提供路由配置。

除了在 React 应用程序中进行动态路由和提供流畅导航之外，该库还包括传统网站中可用的各种功能。这些包括以下内容：

+   通过应用程序向后和向前导航，维护历史记录，并恢复应用程序的状态

+   在提供 URL（深度链接）时呈现适当的页面组件

+   将用户从一个路由重定向到另一个路由

+   在没有任何路由匹配 URL 时支持呈现 404 页面

+   支持基于哈希的路由和使用 HTML5 模式的漂亮 URLs

React-Router 是 Facebook 提供的官方路由解决方案是一个常见的误解。实际上，它是一个第三方库，根据 MIT 许可证授权。

# 使用 React-Router 入门

让我们创建一个 React 应用程序，然后将 React-Router 作为依赖项添加进去。

为了创建一个 React 应用程序，我们将使用`create-react-app`CLI。`create-react-app`CLI 使创建一个已经工作的应用程序变得更容易。CLI 创建了一个项目脚手架，以便您可以开始使用最新的 JavaScript 功能，并提供了用于为生产环境构建应用程序的脚本。有各种 React 和 React-Router 入门套件可用；然而，使用`create-react-app`有助于演示如何将 React-Router 添加到现有的基本 React 应用程序中。

第一步是使用 NPM 全局安装`create-react-app`，如下所示：

```jsx
npm install -g create-react-app
```

CLI 要求`node`版本大于或等于 6，并且`npm`版本大于 5.2.0。

安装完 CLI 后，我们将使用`create-react-app`命令创建一个新的应用程序，如下所示：

```jsx
create-react-app react-router-demo-app
```

当`create-react-app`完成安装包时，将显示以下输出：

```jsx
Inside that directory, you can run several commands:
 npm start
 Starts the development server.

 npm run build
 Bundles the app into static files for production.

 npm test
 Starts the test runner.

 npm run eject
 Removes this tool and copies build dependencies, configuration 
 files
 and scripts into the app directory. If you do this, you can't 
 go back!
 We suggest that you begin by typing:
 cd react-router-demo-app
 npm start
```

如果您使用`yarn`包管理器（[`yarnpkg.com/en/`](https://yarnpkg.com/en/)），则前面片段中的`npm`命令将被替换为`yarn`。

在安装过程中创建了`react-router-demo-app`目录（如果尚不存在）。在该目录内，创建了以下项目结构：

```jsx
/react-router-demo-app
    |--node_modules
    |--public
    |   |--favicon.ico 
    |   |--index.html
    |   |--manifest.json
    |--src
    |   |--App.css
    |    |--App.js
    |    |--App.test.js
    |    |--index.css
    |    |--index.js
    |    |--logo.svg
    |    |--registerServiceWorker.js
    |--package-lock.json
    |--package.json
    |--README.md
```

CLI 安装了所有必要的依赖项，如 Babel，用于将 ES6 代码转译为 ES5，从而使您能够利用最新的 JavaScript 功能。它还使用 webpack 创建了一个构建管道配置。安装后，无需额外配置即可启动或构建应用程序。如前面的输出所示，您可以使用`npm start`命令启动应用程序，并使用`npm build`构建一个生产就绪的应用程序。

运行`npm start`后，应用程序将被编译，并将打开一个浏览器窗口，显示“欢迎来到 React”的消息，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rtr-qk-st-gd/img/2bdc0379-2deb-4bc9-9f52-a9a65537e570.png)

在`index.js`文件中，使用`ReactDOM`引用来呈现应用程序的根组件，如下所示：

```jsx
ReactDOM.render(<App />, document.getElementById('root'));
```

`<App>`组件标记了应用程序启动时将呈现的树的开始。

# 添加 React-Router 库

现在我们的示例应用程序已经运行起来了，让我们使用`npm`添加 React-Router 库作为一个依赖项：

```jsx
npm install --save react-router-dom
```

此命令将下载并将`react-router-dom`添加到`/node_modules`目录中。`package.json`文件现在将其包含为一个依赖项：

```jsx
"dependencies": {
 "react": "¹⁶.4.0",
 "react-dom": "¹⁶.4.0",
 "react-router-dom": "⁴.3.0",
 "react-scripts": "1.1.4"
}
```

在撰写本书时，`react-router-dom`的版本为 4.3.0。您可以通过在使用`npm`包含库时提到`react-router-dom@next`来尝试 alpha 和 beta 版本。 

# 定义应用程序路由

`react-router-dom`包括一个`<BrowserRouter>`组件，它用作在应用程序中添加路由之前的包装器。要在 React Native 应用程序中使用 React-Router，需要使用`react-router-native`包。这将在后面的章节中详细讨论。`<BrowserRouter>`组件是路由器接口的一种实现，它利用 HTML5 的历史 API 来使 UI 与 URL 路径保持同步。

第一步是使用`<BrowserRouter>`将应用程序的根组件包装起来，如下所示：

```jsx
import { BrowserRouter } from 'react-router-dom';

ReactDOM.render(
    <BrowserRouter>
        <App />
    </BrowserRouter>,
    document.getElementById('root')
);
```

将您的应用程序包装在`<BrowserRouter>`中将为我们的`<App>`组件创建一个 history 实例，使其所有子组件都可以访问来自原生浏览器历史 API 的 props。这允许组件匹配 URL 路径并呈现适当的页面组件。

History 是一个 JavaScript 库，它允许您管理历史堆栈导航，并有助于在会话之间保持状态。

在 React-Router 中的路由实际上并不是路由-它是基于与当前 URL 路径匹配的模式的组件的条件渲染。要定义路由，我们需要两个信息：要匹配的 URL 路径和要呈现的组件。让我们创建两个组件，`HomeComponent`和`DashboardComponent`，分别在`/home`和`/dashboard`上呈现。

在`src/components/home/home.component.js`中：

```jsx
import  React  from  'react'; export  const  HomeComponent  = () => ( <div> Inside Home route </div> );
```

在`src/components/dashboard/dashboard.component.js`中：

```jsx
import  React  from  'react'; export  const  DashboardComponent  = () => ( <div  className="dashboard"> Inside Dashboard route </div> );
```

由于我们从前面的组件返回 JSX，所以需要`import`语句。

下一步是使用`Route`组件（来自`'react-router-dom'`）定义路由。`Route`组件接受几个 props，但在本例中，我们将使用`path`和`component`。

在`App.js`中：

```jsx
class  App  extends  Component { render() { return ( <div  className="container"> <Route path="/home" component={HomeComponent} /> <Route path="/dashboard" component={DashboardComponent} /> </div> ); } } export  default  App;
```

在这里，我们在`<App>`组件的`'render'`方法中定义路由。每个`<Route>`组件都有一个`path`属性，它提到要匹配的 URL 路径，以及一个`component`属性，提到一旦路径匹配 URL 就要呈现的组件。

在前面的示例中，该组件是在不扩展 React 组件类的情况下创建的。如果通过将扩展 React 组件类创建的组件作为`component`属性的值提供，则每次`<Route>`呈现组件时都会调用组件的生命周期方法`componentWillMount`和`componentWillUnmount`。

当您运行应用程序（`npm start`）并访问`localhost:3000/home`时，将呈现`HomeComponent`并显示消息“Inside Home Component”。类似地，当您访问`localhost:3000/dashboard`时，将呈现`DashboardComponent`。

`<BrowserRouter>`创建一个`History`对象，它用于跟踪当前位置并在位置更改时重新渲染站点。`<BrowserRouter>`通过 React 的上下文将`History`对象提供给其后代子组件。如果一个`Route`组件没有`<BrowserRouter>`作为其父级，它将无法工作。

另外，`<BrowserRouter>`必须只有一个子元素的要求。在下面的片段中，`<BrowserRouter>`给出了两个子元素：

```jsx
<BrowserRouter>
    <Route
        path="/home"
        component={HomeComponent} />
    <Route
        path="/dashboard"
        component={DashboardComponent} />
</BrowserRouter>
```

上述代码将导致错误，例如“<Router>只能有一个子元素”。要解决此问题，您可以将这些路由移入一个组件并提供组件引用，或者将前面片段中的`<Route>`组件包装在另一个元素中，例如`div`或`React Fragment`。

`React fragment`用于将一组子元素分组，而不向 DOM 添加额外的节点。当组件返回多个元素时，使用片段。

除了`BrowserRouter`之外，React-Router 库中还有其他类型的路由器：`HashRouter`，`MemoryRouter`和`StaticRouter`。这些将在后面的章节中讨论。

# 总结

React 是一个用于构建用户界面的 JavaScript 库。与 Angular 和 Ember 等库不同，它们包括路由包，React 库不包括任何帮助进行路由的组件或服务。React-Router 是一个路由库，可以在任何 React 应用程序中使用，包括 Web 或原生应用。React-Router 版本 4 是对早期版本的完全重写，所有组件都是用 React 编写的。该库包括用于 Web 应用程序的`react-router-dom`包；用于使用 React-Native 构建的原生应用程序的`react-router-native`；以及`react-router`，这是`react-router-dom`和`react-router-native`都依赖的核心包。

`create-react-app` CLI 用于快速搭建 React 应用程序。它包括可以用于生成开发和生产环境构建的构建配置脚本。然后将`react-router-dom`包添加为应用程序的依赖项。该包包括`<BrowserRouter>`组件，它实现了`History`接口。应用程序的根组件`<App />`被包裹在 React-Router 的`<BrowserRouter>`组件中，以使`History`对象对应用程序树中的所有组件都可用。

创建我们的第一个路由，包括`<Route>`组件。它接受`path`和`component`作为 props，并在浏览器的 URL 匹配`<Route>`路径时渲染组件。

在第二章中，*配置路由-在 Route 组件中使用各种选项*，详细讨论了`<Route>`组件的 props。此外，我们将看看渲染组件接收的各种 props，并考虑如何使用这些 props 来创建嵌套路由。


# 第二章：配置路由-使用路由组件中的各种选项

React-Router 允许您使用`<Route>`组件声明性地定义路由。它是 React-Router 的主要构建块，并在`path` prop 中提到的路径值与浏览器的 URL 位置匹配时呈现`component` prop 中提到的组件。`<Route>`组件像任何其他 React 组件一样，接受一组 props。这些 props 可以更精细地控制浏览器的 URL 路径应该如何匹配`<Route>`组件的路径，以及一些其他呈现选项。

在上一章中，我们简要地看到了如何使用`<Route>`组件来匹配 URL 路径并呈现组件。在本章中，我们将看一下以下内容：

+   深入研究可以添加到`<Route>`组件的各种 props，例如`exact`，`strict`，`render`，`children`和`sensitive`。

+   **路由组件 props**：作为`<Route>`路径匹配的结果呈现的组件接收数据作为 props，然后可以用于创建嵌套路由。

+   **路由参数**：`<Route>`组件的路径可以配置为从 URL 段接受附加参数，并且可以在呈现的组件中读取这些参数。

+   **嵌套或动态路由**：可以在呈现的组件中添加`<Route>`组件，而不是在应用程序级别定义路由。因此，呈现的组件为应用程序旅程提供了下一步。

+   **从 JSON 配置生成路由**：JSON 对象中可用的路由信息可用于向应用程序添加路由。

# 路由 props

当您查看 React-Router 的源代码时，`<Route>`组件接受以下 props：

```jsx
Route.propTypes  = { computedMatch:  PropTypes.object, // private, from <Switch> path:  PropTypes.string, exact:  PropTypes.bool, strict:  PropTypes.bool, sensitive:  PropTypes.bool, component:  PropTypes.func, render:  PropTypes.func, children:  PropTypes.oneOfType([PropTypes.func, PropTypes.node]), location:  PropTypes.object };
```

让我们在下一节中看看这些 props 的每一个。

# exact prop

在我们之前的`<Route>`示例中，让我们将`'/home'`路由路径更改为`'/'`，如下所示：

```jsx
<div className="container">
     <Route
         path="/"
         component={HomeComponent} 
     />
     <Route
         path="/dashboard"
         component={DashboardComponent} 
     />
 </div>
```

有了这些路由，当浏览器的 URL 设置为`/dashboard`时，您会注意到两个组件的内容如下显示：

```jsx
Inside Home route
Inside Dashboard route
```

在这里，`'/dashboard'`中的`'/'`匹配`<Route>`的两个路径`'/'`和`'/dashboard'`；因此它从两个组件中呈现内容。要使浏览器的`location.pathname`与`<Route>`组件的路径完全匹配，请向`<Route>`添加 exact prop，如下所示：

```jsx
..
 <Route
     path="/"
     component={HomeComponent}
     exact
 />
 ..
```

类似地，当您尝试访问`'/dashboard'`和`'/dashboard/portfolio'`路径时，您会注意到在两种情况下都会呈现`DashboardComponent`。为了防止`'/dashboard/portfolio'`与具有`'/dashboard'`路径的`<Route>`组件匹配，添加`exact`属性。

React-Router 在内部使用`path-to-regexp`库来确定路由元素的路径属性是否与当前位置匹配。

# 严格属性

当`<Route>`路径有尾随斜杠，并且您希望将此路径与浏览器的 URL 匹配，包括尾随斜杠时，请包括`strict`属性。例如，在将`<Route>`路径从`'/dashboard'`更改为`'/dashboard/'`后，`<Route>`组件仍将匹配不带尾随斜杠的 URL 路径。换句话说，`'/dashboard'`将匹配具有`'/dashboard/'`路径的`<Route>`组件。

但是，在添加`strict`属性之后，React-Router 确保`<Route>`仅在 URL 有尾随斜杠时匹配：

```jsx
<Route
    path="/dashboard/"
    component={DashboardComponent}
    strict
/>
```

有了这个`<Route>`配置，`'/dashboard'`路径将不匹配。但是，当您在 URL 中添加尾随斜杠时，例如`'/dashboard/'`，具有`strict`属性的`<Route>`组件将匹配，并且将呈现`DashboardComponent`。

请注意，如果您提到额外的 URL 段，那么它仍将匹配`<Route>`组件中提到的`path`属性。例如，如果 URL 路径是`'/dashboard/123'`，它将与具有`strict`属性的`<Route>`组件匹配`'/dashboard/'`路径。要匹配包括额外 URL 段的路径，可以在`strict`属性旁边指定`exact`属性。

# 敏感属性

`<Route>`组件的路径不区分大小写，也就是说，`<Route>`组件的路径属性值设置为`'/Dashboard'`将匹配`'/dashboard'`或`'/DASHBOARD'`的 URL 路径。要使`<Route>`组件的路径区分大小写，添加`sensitive`属性：

```jsx
<Route
 path="/Dashboard" component={DashboardComponent} **sensitive** />
```

`sensitive`属性确保在将其与浏览器的 URL 路径匹配时，考虑路径属性的大小写。通过添加`sensitive`属性，可以使用不同的大小写定义具有相同路径名的路由。

```jsx
<Route
 path=**"/Dashboard"** component={DashboardComponent} **sensitive** /> <Route path=**"/dashboard"** component={StockListComponent} **sensitive** />
```

这段代码将创建两个不同的路由，并且当`<Route>`组件的区分大小写路径与浏览器的 URL 路径匹配时，将呈现相应的组件。

# 使用 render prop 进行内联渲染

我们已经看过`component`属性如何在`<Route>`路径匹配浏览器的`location.pathname`时用于渲染视图。还有两个其他可用于渲染视图的属性：`render`和`children`。

`render`属性用于内联渲染。作为`render`属性值的函数应返回一个类似于以下的 React 元素：

```jsx
<Route
    path="/user"
    render={() => (
 <div> Inside User Route </div>
 )}
/>
```

从前面的代码片段中，当`'/user'`路径匹配浏览器的 URL 时，作为`render`属性值指定的函数被执行，并且从该函数返回的 React 元素被渲染。

当在同一个`<Route>`组件中同时指定`component`和`render`属性时，`component`属性将优先。

# 使用 children 属性进行内联渲染

`children`属性应该在您想要渲染视图的情况下使用，无论是否有路径匹配。`children`属性的语法与`render`属性类似，如下所示：

```jsx
<Route
    path="/sidenav"
    children={() => (
 <div> Inside Sidenav route </div>
 )}
/>
```

具有`children`属性的`<Route>`组件即使未指定`path`属性也会被渲染。此外，`exact`和`strict`属性对具有`children`属性的`<Route>`组件没有任何影响。

`component`和`render`属性都优先于`children`属性。此外，当`component`或`render`属性被提及时，只有当路径匹配请求的 URL 时才会渲染视图。

基于路由列表中的位置，具有`children`属性的`<Route>`组件被渲染。例如，如果前一个`<Route>`组件被指定为路由列表中的最后一个条目，则在渲染所有先前匹配的路由之后被渲染。此外，如果前一个`<Route>`组件在匹配路由之前列出，则路由的内容在渲染匹配路由的内容之前被渲染，如下所示：

```jsx
<Route
 path="/sidenav"
 children={() => ( <div> Inside Sidenav route </div>
 )} /> <Route path="/user" render={() => ( <div> Inside User route </div> )} />
```

在这里，当您尝试访问`'/user'`路径时，具有`children`属性的`<Route>`组件在渲染`'/user'`路径之前被渲染。

# 路由组件属性

当`<Route>`路径匹配浏览器的 URL 路径时，被渲染的组件接收特定的`props`，例如`history`、`location`、`match`和`staticContext`。这些 props 提供的数据包括与路由相关的信息。这些 props 可用于使用`<Route>`组件的`component`、`render`或`children`属性渲染的组件。

当您在服务器端渲染应用程序时设置`staticContext`属性，并且在客户端路由器中（即使用`<BrowserRouter>`接口时）不可用（即设置为`undefined`）时。

# 历史

React-Router 依赖于`history`包。`history`是一个 JavaScript 库，用于在任何 JavaScript 应用程序中维护会话。请考虑来自`history`文档的以下引用（[`github.com/ReactTraining/history`](https://github.com/ReactTraining/history)）：

“**history**是一个 JavaScript 库，让您可以轻松地在 JavaScript 运行的任何地方管理会话历史。`history`抽象了各种环境的差异，并提供了一个最小的 API，让您可以管理历史堆栈、导航、确认导航和在会话之间保持状态。”

`history`对象有几个属性和方法：

+   动作：当前动作，`PUSH`、`POP`或`REPLACE`

+   长度：历史堆栈中条目的计数

+   位置：包括`hash`、`pathname`、`search`和`state`属性的当前位置

+   `hash`：哈希片段

+   `pathname`：URL 路径

+   `search`：URL 查询字符串

+   状态：使用`location.pushState`从一个路由导航到另一个路由时提供的状态信息

+   `block()`: 注册一个提示消息的函数，当用户尝试离开当前页面时将显示该消息。

+   `createHref()`: 构造 URL 段的函数；它接受一个带有`pathname`、`search`和`hash`属性的对象。

+   `go(n)`: 导航历史堆栈。`history.go(-1)`将指针向后移动一个位置，`history.go(1)`将指针向前移动一个位置。

+   `goBack()`: 将指针向后移动一个位置在`history`堆栈中；与`history.go(-1)`相同。

+   `goForward()`: 将指针向前移动一个位置在`history`堆栈中；与`history.go(1)`相同。

+   `listen(listenerFn)`: 注册一个监听器函数，每当`history.location`发生变化时就会调用该函数。

+   `push(path, state?)`: 导航到给定的路径名，向`history`堆栈添加一个条目。它可以选择接受一个`state`参数，用于传递应用程序状态数据。

+   `replace(path, state?)`: 一个函数，用于导航到给定的路径名，替换`history`堆栈中的当前条目。它还接受一个可选的`state`参数。

`history`对象由 React-Router 在内部使用，用于在用户尝试在页面之间导航时更新历史堆栈中的条目。它作为 prop 提供给渲染的组件，以便用户可以使用`history`对象中的上述方法导航到不同的页面。在下一章中，我们将看看 React-Router 提供的各种 API，帮助您导航到应用程序中定义的不同路由。

# 位置对象

`location`对象提供了表示应用程序当前状态的数据快照。它包括以下属性：`pathname`、`hash`、`search`和`state`。导航组件可以为这些 prop 提供值，然后由匹配浏览器 URL 的渲染组件读取。如前所述，我们将在第三章中看看各种导航组件，*使用 Link 和 NavLink 组件导航到路由*。

位置信息也可以在`history`对象中找到；但是，`history`对象是可变的，因此应避免在`history`对象中访问位置。

# 匹配对象

`match`对象包含有关`<Route>`路径如何匹配当前 URL 的信息。它包括`url`、`path`、`isExact`和`params`属性。

让我们参考之前使用`render` prop 的路由之一：

```jsx
<Route
 path="/user" render={({ match }) => { console.log(match);
        return ( <div> Inside User route </div> ); }} />
```

当您尝试访问`/user`路径时，`match`对象的属性将具有以下值：

```jsx
url - '/user'
path - '/user'
params - {}
isExact - true
```

+   `url`: 返回 URL 的匹配部分的字符串

+   `path`: 返回路由路径字符串的字符串，即在`<Route>`组件的路径 prop 中提到的路径模式

+   `params`: 包含传递给路由的路径参数列表的对象（在接下来的部分中将更多地介绍参数）

+   `isExact`: 一个布尔值；如果 URL 完全匹配提供的`path` prop，则为`true`

如果 URL 段的部分仅匹配`<Route>`组件的路径，则`isExact`属性为`false`。例如，具有`/user`路径的`<Route>`组件与`/user/123`的 URL 不完全匹配，在这种情况下，`isExact`为 false。

如前所述，带有 `children` 属性的 `<Route>` 组件会被渲染，无论 `path` 属性是否匹配浏览器的 URL 路径。在这种情况下，如果路径不匹配 URL 段，`match` 对象将被设置为 null：

```jsx
<Route
 path="/sidenav" children={({ match }) => { console.log(match) return ( <div> Inside Sidenav route </div> ); }} />
```

使用这个 `<Route>` 配置时，当您尝试访问 `/user` 路径时，将匹配带有 `/sidenav` 路径的 `<Route>` 组件，因为它有一个 `children` 属性。然而，在这里，`match` 对象被设置为 null。这有助于确定带有 `children` 属性的 `<Route>` 组件的路径是否匹配了 URL 段。

# 路由参数

在 React-Router 中，可以配置 `<Route>` 组件来接受给定对象的 URL 参数。例如，要显示给定 `userID` 的用户信息，URL 路径可能看起来像 `'/user/1'`（`userID` 为 `'1'` 的用户）和 `'/user/123'`（`userID` 为 `'123'` 的用户）。URL 的最后部分是动态的；然而，在每种情况下，渲染的组件都会对给定的 `userID` 执行相同的操作。

这样的用例示例是 Twitter 的个人资料页面。该页面接受 `twitterID` 并显示给定用户的动态。

在 `to` 属性中附加一个以冒号 (:) 为前缀的额外路径，可以配置 React-Router 中的 `<Route>` 组件来接受 URL 中的动态部分，如下所示：

```jsx
<Route
 to='/github/**:githubID**'
    component={GitHubComponent}  />
```

在这里，`'/:githubID'` 路径是动态的，可以匹配诸如 `'/github/ryanflorence'` 和 `'/github/mjackson'` 这样的路径（React-Router 的创建者的 GitHub ID）。

然后，可以在渲染的组件中使用 `match.params` 来使用这些匹配的 URL 参数：

```jsx
export  class  GitHubComponent  extends  Component { render() { const { match: { params } } =  this.props; return ( <div> In GitHubComponent <br  /> GitHub ID - {params.githubID} </div> ) } }
```

当您尝试访问 `'/github/mjackson'` URL 路径时，您将看到这条消息：

```jsx
In GitHubComponent
GitHub ID - mjackson
```

`match.params` 对象包含路由中匹配参数的键值对。`<Route>` 组件也可以接受 URL 中的多个参数，如下所示：

```jsx
<Route
 path="/github/**:githubID**/**:twitterID**" component={GitHubComponent} />
```

在这里，`githubID` 和 `twitterID` 参数是动态的，可以匹配 URL 路径，比如 `'/github/ryanflorence/mjackson'`。第二个参数 `twitterID` 可以在组件中使用 `match.params.twitterID` 进行读取。

在之前的 `<Route>` 配置中，`githubID` 和 `twitterID` 参数是必需的参数，也就是说，如果 URL 路径中没有这两个参数，路由就不会匹配。要将参数标记为可选的，可以在参数后面加上问号 (`?`)，如下面的代码片段所示：

```jsx
<Route
 path="/github/:githubID/**:twitterID?**" component={GitHubComponent} />
```

在前面的`<Route>`配置中，`twitterID`参数被标记为可选。这意味着当您尝试访问`'/github/ryanflorence'`路径，即在 URL 中不提供`twitterID`参数的值时，路径将匹配 URL 并渲染组件。然而，当组件尝试使用`match.params.twitterID`访问参数时，它将返回`undefined`。

`<Route>`路径也可以配置为接受与正则表达式匹配的参数，如下所示：

```jsx
...
<Route
 path="/github/**:githubID(\w+)**" component={GitHubComponent} /> <Route path="/user/**:userID(\d+)**" component={UserComponent} />
...
```

在这里，`githubID`参数限制为字母数字字符串，`userID`参数限制为数字值。参数后缀有一个正则表达式模式，用于定义`<Route>`参数将接受的值的类型，即限制可以提供给参数的值的模式。

# 嵌套路由和动态路由

React-Router 的早期版本要求预先定义路由，并将子路由嵌套在另一个路由内，如下所示：

```jsx
<Router>
    <Route path='/' component={Container}>
        <IndexRoute component={Home} />
        <Route path='user' component={User}>
            <IndexRoute component={Twitter} />
            <Route path='instagram' component={Instagram} />
        </Route>
    </Route>
</Router>
```

这段代码可以被认为是静态路由，即在应用程序初始化时，库需要路由配置。在这里，具有`'/'`路径的路由作为所有路由的父路由，具有`'user'`路径的路由是`'/'`的子路由，也是具有`'instagram'`路径的路由的父路由。

在 React-Router v4 中，可以在渲染的组件内定义嵌套路由，也就是说，随着用户在应用程序中导航，路由会被注册。通过 v4 的重写，`<Route>`是一个 React 组件，因此可以包含在任何组件的`render`方法中。

考虑在`App.js`（`<App />`根组件）中定义的父路由：

```jsx
<Route
 path="/category" component={CategoryComponent} />
```

在这里，`'/category'`路径映射到`CategoryComponent`组件。

`CategoryComponent`可以反过来使用相同的`<Route>`组件渲染其他路由。然而，在渲染组件（`CategoryComponent`）内部定义路由时，需要在`<Route>`组件的`to`属性中指定对当前匹配 URL 的引用。例如，可以使用`<Route>`组件创建一个带有`'/pictures'`路径的子路由；然而，在`to`属性中需要指定绝对路径，即`'/category/pictures'`或更一般地，`'/<current_matching_url>/pictures'`。

如前所述，传递给呈现组件的`match`属性包含有关路径如何匹配当前 URL 的信息。`match`属性的 URL 属性可用于引用父 URL：

```jsx
export  const  CategoryComponent  = ({ match }) => { return ( <div  className="nested-route-container"> <div  className="root-info"> <h4> Root: </h4> <h5> path: {match.path}, isExact: {match.isExact.toString()}</h5> </div> <Route path={`${match.url}/pictures`} render={({ match }) => { return ( <div> <h4> Viewing pictures: </h4> <h5> path: {match.path}, 
                                 isExact: {match.isExact.toString**()}** </h5> </div>  ) }} /> <Route path={`${match.url}/books`} render={({ match }) => { return ( <div> <h4> Viewing books: </h4> <h5> path: {match.path},
                                 isExact: {match.isExact.toString()**}** </h5> <Route path={`${match.url}/popular`} render={({ match }) => ( <div> Inside popular, 
                                          path: {match.path} </div> )}  /> </div>  ) }} /> </div> ) }
```

在前面片段中定义的`CategoryComponent`接受`match`属性，并且组件中定义的路由具有`'${match.url}/<child_route_path>'`格式的路径值。`match.url`模板变量包含父路由的 URL 值，在本例中为`/category`。使用相同的原则，还定义了路径为`'/category/pictures'`和`'/category/books'`的路由。

让我们测试这些路由：

+   **场景 1**：`location.pathname` 是 `'/category'`：

在这里，将呈现父路由，并且页面将呈现如下路由信息：

```jsx
         Root:
         path: /category, isExact: true
```

在这里，`match.isExact`为 true，因为在`/category`路径之后没有其他 URL 段。

+   **场景 2**：`location.pathname` 是 `'/category/pictures'` 或 `'/category/books'`：

呈现`'/category'`父路由后，库会查找具有`'/category/pictures'`和`'/category/books'`路径的`<Route>`组件。它找到一个并呈现相应的组件：

```jsx
            Root:
            path: /category, isExact: false
            Viewing pictures:
           path: /category/pictures, isExact: true
```

现在，在父路由（具有`'/category'`路径的`<Route>`组件）中，`match.isExact`为 false；但是在子路由中为 true。

+   **场景 3**：`location.pathname` 是 `'/category/books/popular'`：

您可以嵌套任意多个路由。在这里，`'/books'` 是一个嵌套路由，并且还有另一个嵌套路由，`'/popular'`，它匹配了`'/category/books/popular'`路径：

```jsx
              Root:path: /category, 
              isExact: false
              Viewing books:
             path: /category/books, isExact: false
             Inside popular, 
             path: /category/books/popular
```

`match`属性在创建嵌套路由时非常有用。这些嵌套路由只有在呈现其父路由时才可访问，从而允许您动态添加路由。

# 来自 JSON 的动态路由

还可以通过查找包含路由配置选项集合的数组来生成一组`<Route>`组件。每个路由选项应包含必要的详细信息，如`'path'`和`'component'`。

一组路由可能如下所示：

```jsx
const  STOCK_ROUTES  = [ { path:  'stats', component:  StatsComponent, }, { path:  'news', component:  NewsComponent }, { path:  'trending', component:  TrendingComponent  } ];
```

前面数组中的每个对象都包含一个指定路由路径的`'path'`键，以及包含用户访问路由时要呈现的组件的引用的`'component'`键。然后可以在组件的`render`方法中使用前面的集合来生成一组`<Route>`组件，如下所示：

```jsx
...
render() {
 const { match } =  this.props; return ( <div> Inside Stocks, try /stocks/stats or /stocks/news or /stocks/trending { STOCK_ROUTES.map((route, index) => { return ( <Route key={index} path={`${match.url}/${route.path}`} component={route.component} /> ) **})** } </div> ); }
...
```

在`STOCK_ROUTES`中定义的路由配置用于在`StockComponent`渲染时添加一系列`<Route>`组件。父级`<Route>`组件在`'/stocks'`路径处渲染，因此在生成`'/stocks'`路径下的`<Route>`组件时使用了`match.url`。

# 总结

在本章中，我们了解到`<Route>`组件可以使用各种 props 进行配置。这包括使用`exact` prop 仅在浏览器的 URL 路径与`<Route>`组件中的路径值匹配时才渲染组件；在`<Route>`组件中使用`strict` prop 确保 URL 路径与`path` prop 中指定的尾部斜杠匹配；包括`sensitive` prop 使`path` prop 的值区分大小写；以及使用`render`和`children` props 进行内联渲染。带有`children` prop 的`<Route>`组件会渲染，而不管`path` prop 中指定的值是什么。这在页面布局中有多个视图组件并且这些组件应该渲染时非常有用，而不管`path` prop 中指定的值是什么。

由于`<Route>`路径匹配的结果组件可以接收数据作为 props。这包括 props，如`history`、`location`、`match`和`staticContext`。`match` prop 可用于创建嵌套路由，即`match` prop 中的`url`属性包含的信息可以用于渲染组件中包含的`<Route>`组件的`path` prop 中。`<Route>`组件也可以通过查找对象中指定的配置来添加。然后可以使用包含`path`和`component`信息的数组来在应用程序中添加多个路由。

`<Route>`组件的`path` prop 可以配置为接受 URL 段作为路径参数。然后渲染的组件可以使用`match.params`来读取这些参数。可以通过在`path`参数的后缀中指定正则表达式来配置参数以接受特定值。


# 第三章：使用 Link 和 NavLink 组件导航到路由

React-Router 提供了 `<Link>` 和 `<NavLink>` 组件，允许您导航到应用程序中定义的不同路由。这些导航组件可以被视为页面上的锚链接，允许您导航到站点中的其他页面。在传统网站中，使用锚链接导航应用程序会导致页面刷新，并且页面中的所有组件都会重新渲染。使用 `<Link>` 和 `<NavLink>` 创建的导航链接不会导致页面刷新，只有使用 `<Route>` 定义的页面特定部分并匹配 URL 路径的部分会更新。

与 `<Route>` 组件类似，导航组件 `<Link>` 和 `<NavLink>` 是 React 组件，允许您声明性地定义导航链接。

在本章中，我们将看看导航到应用程序中定义的路由的各种选项。这包括以下内容：

+   `<Link>` 组件及其属性

+   `<NavLink>` 组件及其属性

+   使用 `match` 属性导航到嵌套路由

+   使用 `history` 程序化地导航到路由

+   使用高阶组件 `withRouter`

+   使用 `<Prompt>` 组件阻止路由转换

# <Link> 组件

使用 `<Link>` 组件导航到使用 `<Route>` 组件定义的现有路由。要导航到一个路由，将路由中使用的路径名指定为 `to` 属性的值：

```jsx
import { Link } from 'react-router-dom';

class  App  extends  Component {
    render() {
        return (
            <div class="container">
                <nav>
                    **<Link to="/">Home</Link>**
                    **<Link to="/dashboard">Dashboard</Link>**
                </nav>
                <Route
                    path="/"
                    component={HomeComponent}
                    exact 
                />
                <Route
                    path="/dashboard"
                    component={DashboardComponent} 
                />
            </div>
        );
    }
} 
```

注意 `to` 属性的值与 `<Route>` 中分配给 `path` 属性的值相同。页面现在呈现两个链接：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rtr-qk-st-gd/img/935a19d9-f2c7-4d1e-af10-4ce9d5dacb91.png)

当您点击主页时，您将看到显示的文本“Inside Home route”，当您点击仪表板时，您将被导航到其 `path` 属性设置为 `/dashboard` 的路由。

当您使用 `<Link>` 导航到一个路由时，会调用 `history.push()`，这会向历史堆栈添加一个条目。因此，当您点击浏览器的返回按钮时，您将被导航到之前访问的上一个路由（主页路由）。如前一章所述，React-Router 使用 `history` 库来在用户在应用程序旅程中穿越各种路由时维护应用程序的状态。

`<Link>` 组件还有两个其他属性——`replace` 和 `innerRef`。

# replace 属性

`replace`属性在`<Link>`中调用`history.replace()`，用`to`属性中提到的新路径名替换历史堆栈中的当前条目：

```jsx
<Link  to="/dashboard" replace>Dashboard</Link>
```

例如，如果您访问路径为`/home`的页面，则访问上述链接将用`/dashboard`替换历史堆栈中的当前条目，这基本上将条目`/home`替换为`/dashboard`。

# innerRef 属性

React 提供`ref`来获取对渲染的 DOM 元素的引用。然后可以使用此引用（`ref`）来执行常规流程之外的某些操作，例如聚焦输入元素，媒体播放等。`<Link>`是一个复合组件，在 DOM 上呈现一个锚元素。

在前面的代码片段中提到的`<Link>`组件翻译为以下锚元素：

```jsx
..
<nav>
    <a href="/">Home</a>
    <a href="/dashboard">Dashboard</a>
</nav>
..
```

要获取对此渲染的锚元素的引用，需要将`innerRef`属性添加到`<Link>`中：

```jsx
<nav> <Link to="/" innerRef={this.refCallback}> Home </Link> <Link to="/dashboard" innerRef={this.refCallback}> Dashboard </Link> </nav>
```

`innerRef`属性接受回调函数作为其值；在这里，函数`refCallback`被指定为`innerRef`属性的值。`refCallback`获取对`<Link>`组件的内部元素的引用：

```jsx
refCallback(node) { node.onmouseover  = () => { node.focus(); } } 
```

回调函数`refCallback`在`<Link>`组件挂载时被调用。从上述代码片段中，我们可以看到为两个`<Link>`组件渲染的锚元素都添加了`mouseover`处理程序。当用户悬停在链接上时，相应的锚点获得焦点。

# 带有对象的 to 属性

`to`属性可以是字符串，也可以是对象。该对象可以包含以下属性：

+   `pathname`：要导航到的路径

+   `search`：路径的查询参数，表示为字符串值

+   `hash`：要添加到 URL 的哈希字符串

+   `state`：包含渲染组件可以使用的状态信息的对象

使用这些参数，让我们添加一个`<Link>`组件：

```jsx
<Link to={{ pathname:  '/user', search:  '?id=1', hash:  '#hash',
```

```jsx
 state: { isAdmin:  true } }}>
 User </Link>
```

前面的代码翻译为以下内容：

```jsx
<a href="/user?id=1#hash">User</a>
```

`state`信息不包含在 URL 路径中；但是，它可用于作为`<Route>`匹配的结果呈现的组件：

```jsx
<Route path="/user" render={({ location }) => { const { pathname, search, hash, state } = location; return ( <div> Inside User route <h5>Pathname: {pathname}</h5> <h5>Search: {search}</h5> <h5>Hash: {hash}</h5> <h5>State: {'{'}  {Object.keys(state).map((element, index) => { return ( <span  key={index}> {element}: {state[element].toString()} </span> ) })}  {'}'} </h5> </div> ); }} />
```

`location`对象包含所有先前定义的参数，包括`state`对象。

`state`对象可用于在用户浏览应用程序时存储数据，并将此数据提供给由于`<Route>`匹配而呈现的下一个组件。

# <NavLink>组件

`<NavLink>`组件类似于`<Link>`组件，不同之处在于可以指定多个属性，这些属性可以帮助您有条件地向呈现的元素添加样式属性。它接受与`<Link>`组件相同的一组属性（`to`，`replace`和`innerRef`）用于导航到一个路由，并包括用于样式化选定路由的属性。

让我们来看看这些属性，它们可以帮助您为`<NavLink>`组件设置样式。

# activeClassName 属性

默认情况下，类名`active`将应用于活动的`<NavLink>`组件。例如，当点击`<NavLink>`并呈现相应的路由时，所选的`<NavLink>`的类名将设置为`active`。要更改此类名，请在`<NavLink>`组件上指定`activeClassName`属性，并将其值设置为要应用的 CSS 类名：

```jsx
<nav>
    <NavLink to="/">Home</NavLink> <NavLink to="/dashboard" activeClassName="selectedLink"> Dashboard
    </NavLink> </nav>
```

下一步是在应用程序的 CSS 文件中指定 CSS 类`selectedLink`的样式。请注意，第一个`<NavLink>`没有指定`activeClassName`属性。在这种情况下，当点击`<NavLink>`时，将添加`active`类：

```jsx
<nav>
    <a class="active" aria-current="page" href="/">Home</a>
    <a aria-current="page" href="/dashboard">Dashboard</a>
</nav>
```

然而，当点击第二个`<NavLink>`时，将应用`selectedLink`类：

```jsx
<nav>
    <a aria-current="page" href="/">Home</a>
    <a class="selectedLink" aria-current="page" href="/dashboard">Dashboard</a>
</nav>
```

# activeStyle 属性

`activeStyle`属性也用于为选定的`<NavLink>`设置样式。但是，与其在`<NavLink>`被选中时提供一个类不同，可以在内联中提供 CSS 样式属性：

```jsx
<NavLink
 to="/user" activeStyle={{ background:  'red', color:  'white' }}> User </NavLink>
```

# exact 属性

当您点击具有`to`属性`/dashboard`的`<NavLink>`时，`active`类（或在`activeStyle`属性中指定的内联样式）将应用于页面中的两个`<NavLink>`组件。与`<Route>`组件类似，`/dashboard`中的`/`与`to`属性中指定的路径匹配，因此将`active`类应用于两个`<NavLink>`组件。

在这种情况下，`exact`属性可用于仅在路径与浏览器的 URL 匹配时应用`active`类或`activeStyle`。

```jsx
<NavLink
 to="/" exact> Home </NavLink> <NavLink to="/dashboard" activeClassName="selectedLink"> Dashboard </NavLink>
```

# strict 属性

`<NavLink>`组件还支持`strict`属性，可用于匹配`to`属性中指定的尾随斜杠。

```jsx
<NavLink
 to="/dashboard/"
 activeClassName="selectedLink"
 strict>
 Dashboard </NavLink>
```

在这里，当浏览器的 URL 路径匹配路径`/dashboard/`时，类`selectedLink`仅应用于`<NavLink>`组件，例如，当 URL 中存在尾随斜杠时。

# isActive 属性

`isActive` 属性用于确定 `<NavLink>` 组件是否应用 `active` 类（或在 `activeStyle` 属性中指定的内联样式）。作为 `isActive` 属性值指定的函数应返回一个布尔值：

```jsx
<NavLink
 to={{ pathname:  '/user', search:  '?id=1', hash:  '#hash', state: { isAdmin:  true } }} activeStyle={{ background:  'red', color:  'white' }} isActive={(match, location) => { if (!match) { return  false; } const  searchParams = new  URLSearchParams(location.search); return  match.isExact && searchParams.has('id'**)**; }}> User </NavLink>
```

从上面的例子中，该函数接受两个参数——`match` 和 `location`。仅当条件 `match.isExact && searchParams.has('id')` 评估为 true 时，才会应用在 `activeStyle` 属性中定义的样式，因此，只有当 `match` 是 `exact` 并且 URL 具有查询参数 `id` 时。

当浏览器的 URL 是 `/user` 时，与 `<Route>` 定义的相应路由将显示。然而，`<NavLink>` 组件将具有默认样式，而不是 `activeStyle` 属性中提到的样式，因为缺少查询参数 `id`。

# 位置属性

`<NavLink>` 中的 `isActive` 函数接收浏览器的历史 `location`，并确定浏览器的 `location.pathname` 是否与给定条件匹配。要提供不同的位置，包括 `location` 属性：

```jsx
<NavLink
 to="/user" activeStyle={{ background:  'red', color:  'white' }} location={{ search:  '?id=2', }**}** isActive={(match, location) => { if (!match) { return  false; } const  searchParams = new  URLSearchParams(location.search); return  match.isExact && searchParams.has('id'**)**; }}> User </NavLink>
```

请注意，`to` 属性没有指定 `search` 参数；然而，`location` 属性包括它，因此当浏览器的位置是 `/user` 时，`isActive` 函数返回 true，因为搜索参数包括 `id` 属性。

# 导航到嵌套路由

在上一章中，我们看到如何使用渲染组件接收的 `match` 属性创建嵌套路由。`match.url` 属性包含与 `<Route>` 组件的路径匹配的浏览器 URL 路径。同样，`<Link>` 和 `<NavLink>` 组件可用于创建导航链接以访问这些嵌套路由：

```jsx
<nav>
 <Link to={`${match.url}/pictures`}> Pictures </Link> <NavLink to={`${match.url}/books`**}** activeStyle={{ background:  'orange' }}>
     Books
    </NavLink> </nav>
```

在前面的代码片段中，`<Link>` 和 `<NavLink>` 组件利用 `match.url` 来获取对当前渲染路由的引用，并添加所需的附加路径值以导航到嵌套路由。

# 使用历史对象以编程方式导航到路由

`<Link>` 和 `<NavLink>` 组件在页面上呈现锚链接，允许您从当前路由导航到新路由。然而，在许多情况下，当事件发生时，用户应该以编程方式导航到新的路由。例如，在登录表单中点击提交按钮时，用户应该被导航到新的路由。在这种情况下，渲染组件可用的 `history` 对象可以被使用：

```jsx
export  const  DashboardComponent  = (props) => (    <div  className="dashboard"> Inside Dashboard route <button  onClick={() =>  props.history.push('/user')}> User </button> </div> );
```

在这里，`DashboardComponent`将`props`作为其参数，其中包含`history`对象。`onClick`处理程序调用`props.history.push`，路径名为`/user`。此调用将向历史堆栈添加一个条目，并将用户导航到路径为`/user`的`<Route>`。`history`对象还可以用于使用`history.replace`替换历史堆栈中的当前条目，而不是使用`history.push`。

# 使用 withRouter 高阶组件

`history`对象可用于使用`<Route>`匹配渲染的组件。在前面的示例中，`DashboardComponent`作为导航到路径`/dashboard`的结果进行了渲染。渲染的组件接收了包含`history`对象（以及`match`，`location`和`staticContext`）的`props`。在页面上渲染的组件不是路由导航的结果时，`history`对象将不可用于该组件。

考虑在`App.js`中包含的`FooterComponent`：

```jsx
class  FooterComponent  extends  Component { render() { return ( <footer> In Footer <div> <button  onClick={() =>                         this.props.history.push('/user')}> User </button> <button  onClick={() =>                          this.props.history.push('/stocks')}> Stocks </button> </div> </footer> ) } }
```

`FooterComponent`有两个按钮，调用`history.push`导航到应用程序中的一个页面。单击按钮时，会抛出错误`TypeError: Cannot read property 'push' of undefined`。错误是因为`history`对象在`props`属性中不可用，因为该组件不是作为导航的结果进行渲染的。为了避免这种情况，使用高阶组件`withRouter`：

```jsx
export  const  Footer  =  withRouter(FooterComponent**)**;
```

在这里，`react-router`包中定义的`withRouter`函数接受一个 React 组件作为其参数，并增强它以在`props`属性上提供必要的对象—`history`，`match`，`location`和`staticContext`。

有关 HOC 的 React 文档：高阶组件是一个接受组件并返回新组件的函数。尽管组件将 props 转换为 UI，但高阶组件将组件转换为另一个组件。

包装在`withRouter` HOC 中的组件可以使用`<Route>`，`<Link>`和`<NavLink>`定义路由和导航链接：

```jsx
import { withRouter } from 'react-router';

class  FooterComponent  extends  Component { render() { return ( <footer> In Footer <div> <button  onClick={() =>                  this.props.history.push('/user')}>User</button> <button  onClick={() =>                   this.props.history.push('/stocks')}>Stocks</button> <Link  to='subroute'>User</Link> <Route path='/subroute' render={() => { return  <span>Inside Footer Subroute</span> }}  /> </div> </footer  > ) } } export const Footer = withRouter(FooterComponent);
```

在前面的代码片段中，`withRouter` HOC 使组件能够获取路由器的上下文，因此使诸如`Link`，`NavLink`和`Route`之类的组件可用。

# 使用<Prompt>阻止转换

当您在应用程序中的页面之间导航时，转换到新路由会立即发生。然而，有些情况下，您希望根据应用程序的状态来阻止这种转换。一个常见的例子是，当用户在表单字段中输入数据并花费了几分钟（或几个小时）填写表单数据时。如果用户意外点击导航链接，所有在表单中输入的数据将丢失。用户应该被通知这种路由导航，以便用户有机会保存输入到表单中的数据。

传统网站会跟踪表单的状态，并在用户尝试离开包含尚未提交到服务器的表单的页面时显示确认消息。在这些情况下，将显示一个带有两个选项（OK 和 CANCEL）的确认对话框；前者允许用户转换到下一步，后者取消转换：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rtr-qk-st-gd/img/986b5084-e5e1-445d-a608-0279df2edbff.png)

React-Router 提供了`<Prompt>`组件，可以用来显示确认对话框，以防止用户意外离开当前的`<Route>`：

```jsx
import { **Prompt** } from 'react-router-dom'

**<**Prompt
 when={this.state.isFormSubmitted} message='Are you sure?'  />
```

`<Prompt>`组件在这里接受两个属性——`when`和`message`。从前面的代码片段可以看出，如果`state`属性`isFormSubmitted`的值为`true`，并且用户尝试离开当前路由时，将向用户显示带有消息“您确定吗？”的确认对话框。

请注意，只有当用户尝试离开当前路由时，才会显示`<Prompt>`消息。当`state`属性设置为`true`时，不会显示任何消息。

分配给`when`属性的值可以是任何布尔变量或布尔值。在 React 中，组件的`state`被用作视图模型来维护呈现组件的状态。在这种情况下，`state`属性非常理想，可以确定当用户尝试离开当前路由时是否应该显示`<Prompt>`。

`message`属性的值可以是字符串或函数：

```jsx
<Prompt
 when={this.state.isFormSubmitted} message={(location) => 'Are you sure you want to navigate to ${location.pathname}?'}  />
```

该函数接收`location`参数，其中包括用户试图导航到的路由的位置信息。

与`'react-router-dom'`包中的其他组件类似，`<Prompt>`组件应该在渲染的`<Route>`内使用。当您尝试在没有当前路由上下文的情况下使用`<Prompt>`时，会显示消息。您不应该在`<Router>`之外使用`<Prompt>`。

还可以通过不包括`when`属性来在用户尝试离开当前路由时（不考虑应用程序的`state`）显示消息。

```jsx
<Prompt  message=**'Are you sure?**'  />
```

往往在`<Prompt>`中包含`when`属性，并且分配给`when`属性的值用于确定是否应该显示确认对话框。

在尝试这些示例时，请确保给定的`<Route>`只有一个`<Prompt>`，否则库将报告警告`历史记录一次只支持一个提示`。

# 总结

在本章中，我们看了如何使用`<Link>`和`<NavLink>`导航组件导航到应用程序中定义的各种路由。这些组件在页面中呈现`anchor`链接，当用户点击这些链接时，页面的部分会更新，而不是进行完整的页面重新加载，从而提供清晰的用户体验。`<Link>`组件接受`to`、`replace`和`innerRef`等 props。

`<NavLink>`组件类似于`<Link>`组件，并接受`<Link>`组件使用的所有 props。除了向页面添加链接外，`<NavLink>`组件还接受几个 props——`activeClassName`、`activeStyle`、`exact`、`strict`和`isActive`。

要创建到嵌套路由的链接，`<Link>`和`<NavLink>`组件可以在`to`属性中使用前缀`match.url`。此外，您还可以在事件处理程序函数中使用`history.push`或`history.replace`进行程序化导航。通过`withRouter`高阶组件，可以使`history`、`match`、`location`和`staticContext`等 props 在 Route 上下文之外呈现的组件中可用。`'react-router-dom'`包包括一个`<Prompt>`组件，可用于在用户尝试通过意外点击导航链接导航到路由时显示确认对话框。`<Prompt>`组件接受`when`和`message`属性，并根据分配给`when`属性的布尔值，将显示在`message`属性中指定的消息给用户。

在第四章中，*使用重定向和切换组件*，我们将看看`<Redirect>`和`<Switch>`组件。此外，我们将看到这些组件如何用于保护路由，并在页面中没有任何路由匹配请求的 URL 时显示一个未找到页面。


# 第四章：使用重定向和切换组件

使用 React-Router 的`<Redirect>`组件可以将用户从一个路由重定向到另一个路由。在传统网站中，页面是在服务器端呈现的，托管应用程序的 Web 服务器配置了重写规则，将用户重定向到不同的 URL。当内容已经移动到新页面或者网站的某些页面仍在建设中时，可以使用此重定向。HTTP 重定向是一项昂贵的操作，因此也会影响应用程序的性能。

在单页应用程序（SPA）中，重定向发生在浏览器上，根据特定条件将用户重定向到不同的路由。这种重定向更快，因为没有涉及 HTTP 往返，并且转换类似于使用`<Link>`或`<NavLink>`组件从一个路由导航到另一个路由。

本章讨论以下主题：

+   `<Redirect>`组件：将用户从一个路由重定向到另一个路由

+   保护路由和授权：一种情况是当用户尝试访问受保护的路由时，将用户重定向到登录页面

+   `<Switch>`组件：渲染第一个匹配的`<Route>`

+   添加 404 页面未找到页面：一种情况是当没有任何`<Route>`组件匹配浏览器的 URL 路径时，使用`<Switch>`和`<Route>`或`<Switch>`和`<Redirect>`组件来渲染 404 页面

# `<Redirect>`组件

`<Redirect>`组件包含在`react-router-dom`包中。它帮助将用户从包含它的组件重定向到`'to'`属性中指定的路由：

```jsx
import { Redirect } from 'react-router-dom';

export class HomeComponent extends Component {
    render() {
        return (
            <Redirect to='/dashboard' />
        )
    }
}
```

在上述情况下，当`HomeComponent`被渲染时（基于`<Route>`匹配），用户将被重定向到`'/dashboard'`路由。例如，当用户访问主页（路径为`'/'`）时，具有路径`'/'`的`<Route>`会渲染先前的组件，然后用户立即被重定向到具有路径值`'/dashboard'`的`<Route>`。这类似于使用带有`'to'`属性的`<Link>`或`<NavLink>`组件将用户导航到不同的路由。在这里，重定向发生在组件被渲染时，而不是作为用户操作的结果触发导航。

先前提到的重定向示例在应用程序中的某些页面已经移动到不同的目录的情况下是理想的。

`<Redirect>`组件类似于 React-Router 中的其他组件，如`<Route>`和`<Link>`。正如之前观察到的那样，它是一个可以包含在渲染函数中的 React 组件。此外，`<Redirect>`组件接受与`<Link>`组件相似的一组 props。

# to 属性

to 属性用于指定用户应该被重定向到的路由。如果找到匹配的`<Route>`，用户将被重定向到指定的路径，并渲染相应的组件。

to 属性还可以接受一个对象，该对象指定了`pathname`、`search`、`hash`和`state`属性的值：

```jsx
<Redirect 
    to={{
        pathname: '/dashboard',
        search: '?q=1',
        hash: '#hash',
        state: { from: match.url }
      }} 
/>
```

与`<Link>`组件类似，前面提到的属性被指定在`<Redirect>`组件的 to 属性中。请注意，状态属性的值为`{ from: match.url }`。在这里，`match.url`提供了浏览器 URL 路径的当前值，然后在重定向发生时将该值提供给渲染的组件。

然后，渲染的组件可以使用`this.props.location.state`来读取状态信息：

```jsx
export class DashboardComponent extends Component {
    render() {
        const { location } = this.props;
        return (
            <div>
                In DashboardComponent <br />
                From : {location.state.from}
            </div>
        )
    }
}
```

在前面的示例中，`DashboardComponent`作为从`HomeComponent`重定向的结果进行渲染。`location.state.from`的值与被重定向的组件共享有关重定向发生的页面的路径信息。当您希望被重定向到一个通用页面，并且被重定向的页面必须显示有关重定向发生的路径的信息时，这将非常有用。例如，当应用程序发生错误时，用户应该被重定向到一个呈现错误消息的页面，提供有关发生错误的页面的信息。在这种情况下，状态信息可以包括属性`errorMessage`和`from`；后者的值为`match.url`，即发生错误的页面。

如果未找到被重定向的`<Route>`，浏览器的 URL 将被更新，不会抛出错误。这是有意设计的；理想情况下，如果没有匹配的路由，用户应该被重定向到一个`404`或`Page Not Found`页面。在下一节中将讨论当没有匹配时渲染的`<Route>`。

在组件内部，当您尝试重定向到相同的路由时，React-Router 会抛出警告消息 Warning: You tried to redirect to the same route you're currently on: `"/home"`。这个检查确保重定向不会导致无限循环。

还可能遇到这样的情况，被重定向的组件在其渲染方法中包含一个`<Redirect>`，将用户重定向回相同的路由，也就是说，按照这个路由重定向`path: /home => /dashboard => /home`。这样会一直循环，直到 React 停止渲染组件；然后 React 会抛出一个错误，最大更新深度超过。当组件在`componentWillUpdate`或`componentDidUpdate`中重复调用`setState`时，就会发生这种情况。React 限制了嵌套更新的次数，以防止无限循环。React-Router 使用状态来跟踪用户在应用程序旅程中的位置，因此在重定向时，由于重定向的原因，React 尝试多次更新状态而导致前面的错误发生。在处理重定向时，您需要确保它不会导致无限循环的重定向。

# 推送属性

`<Redirect>`组件通过调用`history.replace(<path>)`将用户重定向到给定的路径，即用新路径替换历史堆栈中的当前条目。通过在`<Redirect>`组件中指定推送属性，将调用`history.push`而不是`history.replace`：

```jsx
<Redirect to="/dashboard" push />
```

# 保护路由和授权

使用`<Route>`组件定义的路由可以通过浏览器的 URL 访问，通过使用`<Link>`或`<NavLink>`导航到路由，或者通过使用`<Redirect>`组件将用户重定向。但是，在大多数应用程序中，一些路由应该只对授权或已登录的用户可用。例如，假设`/user`路径显示已登录用户的数据；这个路径应该受到保护，只有已登录用户才能访问该路径。在这些情况下，当您尝试访问路径`/user`时，`<Redirect>`组件非常有用，它会将用户重定向到登录页面（在路径`/login`）。

为了证明这一点，让我们创建一个名为`UserComponent`的组件，当您尝试访问路径`/user`时，它将被渲染出来：

```jsx
export class UserComponent extends Component {
    render() {
        const { location } = this.props;
        return (
            <div>
                Username: {location && location.state ? location.state.userName 
                 : ''} <br />
                From: {location && location.state ? location.state.from : ''} 
                 <br />
                <button onClick={this.logout}>LOGOUT</button>
            </div>
        )
    }
}
```

从前面的代码片段中，我们可以看到`UserComponent`显示了在`this.props.location`中可用的状态信息和 LOGOUT 按钮。

要检查用户是否已登录，应该向服务器发出请求，以检查用户的会话是否存在。但是，在我们的情况下，通过引用浏览器的`localStorage`中的变量来检查用户是否已登录：

```jsx
export class UserComponent extends Component {
    state = {
       isUserLoggedIn: false
    }
    componentWillMount() {
        const isUserLoggedIn = localStorage.getItem('isUserLoggedIn');
        this.setState({isUserLoggedIn});
    }
    render() {
    ...
    }
}
```

在这里，组件的状态属性`isUserLoggedIn`将使用存储在同名 localStorage 变量中的值进行更新。

下一步是在`UserComponent`类的渲染函数中使用此状态信息，并使用`<Redirect>`组件重定向用户：

```jsx
export class UserComponent extends Component {
    ...
    render() {
        const { location } = this.props;
        if (!this.state.isUserLoggedIn) {
            return (
                <Redirect to="/login" />
            );
        }
        ...
    }
}
```

在这里，将检查状态属性`isUserLoggedIn`的值，如果评估为 false，或者未找到，则将用户重定向到路径`'/login'`。

最后一步是实现`logout`函数，当用户点击 LOGOUT 按钮时调用：

```jsx
export class UserComponent extends Component {
    logout = (event) => {
        localStorage.removeItem('isUserLoggedIn');
        this.setState({ isUserLoggedIn: false });
    }
    ...
}
```

登出用户涉及删除`localStorage`变量并将状态属性`isUserLoggedIn`更新为`'false'`。

有了这些更改，当状态属性`isUserLoggedIn`设置为 false 时，`UserComponent`会重新渲染，并将用户重定向到路径`/login`，要求用户提供凭据以访问页面。此外，现在当您尝试通过在浏览器地址栏中输入路径`/user`来访问时，具有路径属性`/user`的`<Route>`将匹配。然而，当`UserComponent`被渲染时，状态属性`isUserLoggedIn`将评估为 false，将用户重定向到`/login`页面。

# 使用回调路由进行重定向

当您尝试访问受保护的`<Route>`时，将被重定向到登录页面以提供凭据。提供凭据后，您应该被重定向到之前尝试访问的页面。例如，当您尝试访问路径`/stocks`的受保护路由时，您将被重定向到路径`/login`，然后，在提供正确的凭据后，您应该被重定向到之前尝试访问的相同路径`/stocks`。然而，根据先前的示例，您将被重定向到路径`/user`，并显示用户的个人资料信息。期望的行为是重定向到受保护的路径`/stocks`，而不是路径`/user`。

这可以通过在重定向用户时提供状态信息来实现。

在`StocksComponent`（作为`<Route>`匹配结果呈现的组件，`/stocks`），当您将用户重定向到登录页面时，在 to 属性中提供状态信息：

```jsx
export class StocksComponent extends Component {
    ...
    render() {
        const {match } = this.props;
        if (!this.state.isUserLoggedIn) {
            return (
                <Redirect 
                    to={{
                        pathname: "/login",
                        state: { callbackURL: match.url }
                    }}
                />
            )
        }

        return (
            <div>
                In StocksComponent
            </div>
        )
    }
}
```

在组件的渲染函数中，用户使用`<Redirect>`组件被重定向到登录页面。这里的`<Redirect>`组件包括一个 to 属性，指定用户应该被重定向到的`pathname`，它还包括一个状态对象，提到了`callbackURL`属性。`callbackURL`属性的值是`match.url`，即当前浏览器的 URL 路径`/stocks`。

然后可以在`LoginComponent`中使用这些状态信息将用户重定向到路径`/stocks`：

```jsx
export class LoginComponent extends Component {
    ...
    render() {
        const { location: { state } } = this.props;
        if (this.state.isUserLoggedIn) {
            return (
                <Redirect 
                    to={{
                        pathname: state && 
                        state.callbackURL || "/user",
                        state: {
                            from: this.props.match.url,
                            userName: this.state.userName
                        }
                    }} 
                />
            )
        }
        ...
    }
}
```

在这里，当用户提供凭据访问受保护的路由时，`<Redirect>`组件将用户重定向到`state.callbackURL`中提到的路径。如果`callbackURL`不可用，用户将被重定向到默认路由，该路由将重定向到路径`/user`。

Route 组件的 props、`match.url`和 location.state 的组合可以用来将用户重定向到之前请求的受保护路由。

# 使用<Switch>组件进行独占路由

当 URL 被提供给`<BrowserRouter>`时，它将寻找使用`<Route>`组件创建的路由，并渲染所有与浏览器 URL 路径匹配的路由。例如，考虑以下路由：

```jsx
<Route
    path="/login"
    component={LoginComponent}
/>
<Route
    path="/:id"
    render={({ match }) => 
        <div> Route with path {match.url}</div>
    }
/>
```

在这里，具有路径`/login`和`/:id`的两个路由都匹配`/login`的 URL 路径。React-Router 渲染所有与 URL 路径匹配的`<Route>`组件。然而，为了只渲染第一个匹配的路由，该库提供了`<Switch>`组件。`<Switch>`组件接受一组`<Route>`组件作为其子组件，并且只渲染与浏览器 URL 匹配的第一个`<Route>`：

```jsx
<Switch>
    <Route
        path="/login"
        component={LoginComponent}
    />
    <Route
        path="/:id"
```

```jsx
        render={({ match }) =>
            <div> Route with path {match.url}</div>
        }
    />
</Switch>
```

通过将一组`<Route>`组件包装在`<Switch>`组件内，React-Router 会顺序搜索与浏览器 URL 路径匹配的`<Route>`。一旦找到匹配的`<Route>`，`<Switch>`就会停止搜索并渲染匹配的`<Route>`。

在上面的例子中，如果浏览器的 URL 路径是/login，那么`<Switch>`中的第一个`<Route>`将被渲染，而除/login 之外的路径（如/123、/products、/stocks 等）将匹配第二个路由并渲染相应的组件。

如果交换前两个`<Route>`组件的顺序（即，将具有路径/:id 的`<Route>`列在具有路径/login 的`<Route>`之上），那么具有路径/login 的`<Route>`将永远不会被渲染，因为`<Switch>`只允许渲染一个第一个匹配的路由。

# <Switch>中<Route>组件的顺序

`<Switch>`中`<Route>`组件的顺序很重要，因为`<Switch>`组件会顺序查找匹配的`<Route>`，一旦找到与浏览器 URL 匹配的`<Route>`，就会停止搜索。这种行为可能不是期望的，您可能希望渲染`<Switch>`中列出的另一个路由。但是，可以通过更改在`<Switch>`中列出`<Route>`的顺序来纠正这一点：

在以下示例中，提到了在`<Switch>`中列出`<Route>`组件时的一些常见错误：

# 带有路径'/'的`<Route>`作为`<Switch>`的第一个子级

考虑以下代码片段：

```jsx
<Switch>
    <Route
        path="/"
        component={LoginComponent}
    />
    <Route
        path="/dashboard"
        component={DashboardComponent}
    />
</Switch>
```

如果浏览器的 URL 路径是`/dashboard`，它将匹配第一个路径为`/`的`<Route>`，而路径为`/dashboard`的`<Route>`将永远不会匹配和渲染。要解决这个问题，要么包括`exact`属性，要么将路径为`/`的`<Route>`列为`<Switch>`中的最后一个条目。

# 带有路径参数的`<Route>`

在以下代码片段中，将带有路径参数的`<Route>`列为第二个条目：

```jsx
<Switch>
    <Route
        path="/github"
        component={LoginComponent}
    />
    <Route
        path="/github/:userId"
        component={DashboardComponent}
    />
</Switch>
```

在上一个示例中，路径为`/github`的`<Route>`将匹配 URL 路径`/github`以及路径`/github/mjackson`；因此，即使有特定路径的`<Route>`可用，第一个`<Route>`也会被渲染。要解决这个问题，要么提供`exact`属性，要么将路径为`/github`的`<Route>`列在路径为`/github/:userId`的`<Route>`下面。

从前一段提到的两种情况中，将具体路径的`<Route>`组件列在通用路径的`<Route>`组件上面，可以避免不良结果。

# 添加 404 - 未找到页面

如前所述，`<Switch>`组件会顺序查找所有`<Route>`组件，一旦找到与浏览器 URL 匹配的`<Route>`，就会停止搜索。这与在页面中列出`<Route>`的列表不同，页面中的每个匹配的`<Route>`都会被渲染。因此，`<Switch>`非常适合渲染`Page Not Found`页面，即在`<Switch>`的子级中没有任何匹配浏览器 URL 的`<Route>`时渲染一个组件。

让我们在`<Switch>`中包含一个没有路径属性的`<Route>`作为最后一个条目：

```jsx
<Switch>
    <Route
        path="/login"
        component={LoginComponent}
    />
    <Route
        path="/user"
        render={({ match }) =>
            <div> Route with path {match.url}</div>
        }
    />
    <Route
        render={({ location }) =>
            <div> 404 - {location.pathname} not 
            found</div>
        }
    />
</Switch>
```

从前面的代码片段中，我们可以看到当没有任何带有路径属性的`<Route>`与浏览器的 URL 匹配时，最后一个没有路径属性的`<Route>`将匹配并渲染。

包括`Page Not Found <Route>`作为最后一个条目是很重要的，因为`<Switch>`组件一旦找到匹配的`<Route>`就会停止搜索。在前面的情况下，如果没有属性的`<Route>`被包括在其他`<Route>`上面，那么即使列表中存在与浏览器 URL 匹配的`<Route>`，`Page Not Found`路由也会被渲染。

您还可以指定一个`<Route>`，其路径属性值为`*`，而不是没有路径属性的`<Route>`，以渲染`Page Not Found`页面：

```jsx
<Switch>
    ...
    <Route
        path="*"
        render={({ location }) =>
            <div> 404 - {location.pathname} not 
            found</div>
        }
    />
</Switch>
```

在这两种情况下，路径将匹配浏览器的 URL 并渲染`Page Not Found`页面。

# 在`<Switch>`中使用`<Redirect>`重定向到一个 Page Not Found 页面

`<Switch>`组件的子元素也可以包括一系列`<Route>`和`<Redirect>`组件。当包括为`<Switch>`中的最后一个条目时，`<Redirect>`组件将在没有任何在`<Redirect>`组件上面提到的`<Route>`匹配浏览器 URL 时将用户重定向到给定路径：

```jsx
<Switch>
    <Route
        path="/login"
        component={LoginComponent}
    />
    <Route
        path="/user"
        render={({ match }) =>
            <div> Route with path {match.url}</div>
        }
    />
    <Redirect to="/home" />
</Switch>
```

前面提到的`<Redirect>`组件将用户重定向到路径为`/home`的`<Route>`。这类似于显示`404：Page Not Found`页面；而不是在行内显示组件，用户被重定向到不同的路径。

例如，如果浏览器的 URL 路径是`/dashboard`，前两个路径（路径为`/login`和`/user`）不会匹配，因此用户将使用在`<Switch>`中作为最后一个条目提到的`<Redirect>`组件进行重定向。

# 从旧路径重定向到新路径

`<Redirect>`组件也可以用于将用户从给定路径重定向到新路径。`<Redirect>`组件接受一个`from`属性，该属性可用于指定应该匹配用户应该被重定向的浏览器 URL 的路径。此外，应该在`to`属性中指定用户应该被重定向到的路径。

```jsx
<Switch>
    <Route
        path="/login"
        component={LoginComponent}
    />
    <Route
        path="/user"
        render={({ match }) =>
            <div> Route with path {match.url}</div>
        }
    />
    <Redirect
        from="/home"
        to="/login"
    />
    <Redirect to="/home" />
</Switch>
```

从前面的例子中，我们可以看到当浏览器的 URL 路径是`/home`时，具有`from`属性的`<Redirect>`组件将匹配给定路径并将用户重定向到路径为`/login`的`<Route>`。

`<Redirect>`组件的`from`属性在网站上的一些页面已经移动到新目录时非常有用。例如，如果用户页面已经移动到新的目录路径`settings/user`，那么`<Redirect from="/user" to="/settings/user" />`将把用户重定向到新路径。

# 总结

`<Redirect>`组件可用于将用户从当前渲染的路由重定向到新的路由。该组件接受 props：to 和 push。当应用程序中的组件已经移动到不同的目录，或者用户未被授权访问页面时，可以使用此重定向。`<Redirect>`组件在用户访问受保护的路由并且只有授权用户被允许查看页面时非常有用。

`<Switch>`组件用于在一组`<Route>`中只渲染一个`<Route>`。`<Switch>`组件接受`<Route>`和`<Redirect>`组件的列表作为其子组件，并依次搜索匹配的`<Route>`或`<Redirect>`组件。当找到匹配时，`<Switch>`渲染该组件并停止寻找匹配的路径。

`<Switch>`的这种行为可以用来构建一个`404：页面未找到`，当`<Switch>`中列出的`<Route>`组件都不匹配浏览器的 URL 路径时，将会渲染该页面。通过在`<Switch>`的最后一个条目中列出一个没有任何路径属性的`<Route>`，如果上面列出的`<Route>`组件都不匹配浏览器的 URL 路径，那么将会渲染该`<Route>`。另外，也可以将`<Redirect>`组件列为最后一个条目，以在`<Switch>`中没有匹配的`<Route>`组件时将用户重定向到另一个页面。


# 第五章：理解核心路由器，并配置`BrowserRouter`和`HashRouter`组件

React-Router 库提供了几个组件，用于解决各种用例，例如使用`<Link>`和`<NavLink>`添加导航链接，使用`<Redirect>`组件重定向用户等。`<BrowserRouter>`组件包装了应用程序的根组件（`<App />`），并使这些组件能够与`history`对象交互。当应用程序初始化时，`<BrowserRouter>`组件初始化`history`对象，并使用 React 的`context`使其可用于所有子组件。

单页应用程序中的路由实际上并不是真正的路由；相反，它是组件的条件渲染。`<BrowserRouter>`组件创建了`history`对象，`history`对象具有诸如`push`、`replace`、`pop`等方法，这些方法在导航发生时被使用。`history`对象使应用程序能够在用户在页面之间导航时保持历史记录。除了`<BrowserRouter>`，React-Router 还提供了各种 Router 实现——`<HashRouter>`、`<StaticRouter>`、`<MemoryRouter>`和`<NativeRouter>`。这些路由器利用了包含在`react-router`核心包中的低级`Router`接口。

在本章中，我们将看一下低级`<Router>`组件和各种路由器实现：

+   `<Router>`和`react-router`包

+   `<BrowserRouter>`属性

+   `HashRouter`——用于在旧版浏览器中使用的 Router 实现

其他`<Router>`实现，如`<StaticRouter>`、`<MemoryRouter>`和`<NativeRouter>`，将在接下来的章节中讨论。

# `<Router>`组件

如前所述，React-Router 提供了各种 Router 实现：

+   `<BrowserRouter>`

+   `<HashRouter>`

+   `<MemoryRouter>`

+   `<StaticRouter>`

+   `<NativeRouter>`

这些路由器利用了低级接口`<Router>`。`<Router>`组件是`react-router`包的一部分，`<Router>`接口提供的功能由这些 Router 实现扩展。

`<Router>`组件接受两个 props——`history`和`children`。`history`对象可以是对浏览器历史记录的引用，也可以是应用程序中维护的内存中的历史记录（这在原生应用程序中很有用，因为浏览器历史记录的实例不可用）。`<Router>`组件接受一个子组件，通常是应用程序的根组件。此外，它创建一个`context`对象，`context.router`，通过它，所有后代子组件，如`<Route>`、`<Link>`、`<Switch>`等，都可以获得`history`对象的引用。

来自 reactjs.org：

上下文提供了一种通过组件树传递数据的方式，而无需在每个级别手动传递 props。

通常不使用`<Router>`接口来构建应用程序；而是使用适合给定环境的高级别 Router 组件之一。使用`<Router>`接口的常见用例之一是将自定义的`history`对象与诸如`Redux`和`MobX`之类的状态管理库同步。

# 包括来自 react-router 的<Router>

核心的`react-router`包可以通过`npm`安装：

```jsx
npm install --save react-router
```

`Router`类然后可以包含在应用程序文件中：

```jsx
import { Router } from 'react-router'
```

下一步是创建一个`history`对象，然后将其作为值提供给`<Router>`的`history` prop：

```jsx
import  createBrowserHistory  from  'history/createBrowserHistory'; const customHistory = createBrowserHistory()
```

在这里，使用`history`包中的`createBrowserHistory`类来为浏览器环境创建`history`对象。`history`包包括适用于各种环境的类。

最后一步是用`<Router>`组件包装应用程序的根组件并渲染应用程序：

```jsx
ReactDOM.render(
 **<**Router  history={customHistory}**>** <App  /> </Router>, document.getElementById('root'));
```

注意，`<Router>`组件接受一个`history` prop，其值是使用`createBrowserHistory`创建的`history`对象。与`<BrowserRouter>`组件类似，`<Router>`组件只接受一个子组件，在有多个子组件时会抛出错误。

React 允许其 prop 值发生变化，并在检测到变化时重新渲染组件。在这种情况下，如果我们尝试更改分配给 history prop 的值，React-Router 会抛出警告消息。考虑以下代码片段：

```jsx
class  App  extends  Component { state  = { customHistory:  createBrowserHistory() } componentDidMount() { this.setState({ customHistory:  createBrowserHistory() **});** } render() { return ( <Router  history={**this**.state.customHistory}> <Route path="/" render={() =>  <div> In Home </div>}  /> </Router> ); } }
```

在前面的例子中，state 属性`customHistory`包含了提供给`<Router>`组件的`history`对象。然而，当`customHistory`的值在`componentDidMount`生命周期函数中改变时，React-Router 会抛出警告消息 Warning: You cannot change <Router> history。

# react-router 包

`react-router`包括一些核心组件，比如之前提到的`<Router>`组件。该包还包括其他一些组件，然后被`react-router-dom`和`react-router-native`包中的组件使用。`react-router`包导出这些组件：

```jsx
export MemoryRouter from "./MemoryRouter";
export Prompt from "./Prompt";
export Redirect from "./Redirect";
export Route from "./Route";
export Router from "./Router";
export StaticRouter from "./StaticRouter";
export Switch from "./Switch";
export generatePath from "./generatePath";
export matchPath from "./matchPath";
export withRouter from "./withRouter";
```

这里提到的一些组件在之前的章节中已经讨论过。该包还提供了一些辅助函数，比如`generatePath`和`matchPath`，以及 Router 实现，比如`<MemoryRouter>`和`<StaticRouter>`。`react-router-dom`和`react-router-native`中定义的组件和服务导入了这些组件和服务，并包含在各自的包中。

# react-router-dom 包

`react-router-dom`包提供了可以在基于浏览器的应用程序中使用的组件。它声明了对`react-router`包的依赖，并导出以下组件：

```jsx
export BrowserRouter from "./BrowserRouter";
export HashRouter from "./HashRouter";
export Link from "./Link";
export MemoryRouter from "./MemoryRouter";
export NavLink from "./NavLink";
export Prompt from "./Prompt";
export Redirect from "./Redirect";
export Route from "./Route";
export Router from "./Router";
export StaticRouter from "./StaticRouter";
export Switch from "./Switch";
export generatePath from "./generatePath";
export matchPath from "./matchPath";
export withRouter from "./withRouter";
```

请注意，这里提到的一些组件也包含在`react-router`包中。`react-router-dom`中的组件导入了`react-router`中定义的组件，然后导出它们。例如，看一下`<Route>`组件：

```jsx
import { Route } from "react-router";
export default Route;
```

`BrowserRouter`、`<HashRouter>`和`<MemoryRouter>`的 Router 实现会创建一个特定于给定环境的`history`对象，并渲染`<Router>`组件。我们很快将会看一下这些 Router 实现。

`react-router-native`包使用了`react-router`中的`<MemoryRouter>`实现，并提供了一个`<NativeRouter>`接口。`NativeRouter`的实现和其打包细节将在接下来的章节中讨论。

# <BrowserRouter>组件

`<BrowserRouter>`组件在第一章中简要讨论过。正如其名称所示，`<BrowserRouter>`组件用于基于浏览器的应用程序，并使用 HTML5 的 history API 来保持 UI 与浏览器的 URL 同步。在这里，我们将看一下该组件如何为浏览器环境创建`history`对象并将其提供给`<Router>`。

`<BrowserRouter>`组件接受以下属性：

```jsx
static propTypes = {
    basename: PropTypes.string,
    forceRefresh: PropTypes.bool,
    getUserConfirmation: PropTypes.func,
    keyLength: PropTypes.number,
    children: PropTypes.node
};
```

与`<Router>`接口类似，`<BrowserRouter>`只接受一个子组件（通常是应用程序的根组件）。前面代码片段中提到的`children`属性指的是这个子节点。使用`history`包中的`createBrowserHistory`方法来创建一个用于初始化`<Router>`的`history`对象：

```jsx
import { createBrowserHistory as createHistory } from "history";
import Router from "./Router";

class  BrowserRouter  extends  React.Component {    ...
    history = createHistory(this.props);
    ...
    render() {
        return <Router 
                   history={this.history}
                   children={this.props.children}
               />;
    }
}
```

在前面的代码片段中，`<BrowserRouter>`使用提供的属性使用`history/createBrowserHistory`类创建一个`history`对象。然后渲染`<Router>`组件，并从属性中提供创建的`history`对象和`children`对象。

# basename 属性

`basename`属性用于为应用程序中的所有位置提供基本的 URL 路径。例如，如果您希望在`/admin`路径上呈现应用程序，而不是在根路径`/`上呈现，则在`<BrowserRouter>`中指定`basename`属性：

```jsx
<BrowserRouter basename="/admin">
    <App />
</BrowerRouter>
```

`basename`属性现在将基本 URL 路径`/admin`添加到应用程序中。当您使用`<Link>`和`<NavLink>`进行导航时，`basename`路径将添加到 URL 中。例如，考虑以下带有两个`<Link>`组件的代码：

```jsx
<BrowserRouter  basename="/admin">
 <div  className="component">
 <nav> <Link  to="/">Home</Link**>** <Link  to="/dashboard">Dashboard</Link**>** </nav>
    </div> </BrowserRouter>
```

当您点击`Home`链接（路径`/`）时，您会注意到 URL 路径更新为`/admin`而不是`/`。当您点击`Dashboard`链接时，更新后的 URL 路径为`/admin/dashboard`。使用`<BrowserRouter>`中的`basename`属性，前面的`<Link>`组件转换为以下内容：

```jsx
<a href='/admin'>Home</a>
<a href='/admin/dashboard'>Dashboard</a>
```

锚链接的`href`属性前缀为`/admin`路径。

# forceRefresh 属性

`forceRefresh`属性是一个布尔属性，当设置为`true`时，导航到任何路由都会导致页面刷新 - 而不是更新页面的特定部分，整个页面都会重新加载：

```jsx
<BrowserRouter forceRefresh={true}>
    <Link to="/dashboard">Dashboard</Link>
</BrowserRouter>
```

当您点击导航链接`Dashboard`时，您会注意到在请求 URL 路径`/dashboard`时页面重新加载。

# keyLength 属性

`keyLength`属性用于指定`location.key`的长度。`locaction.key`属性表示提供给位置的唯一键。看一下以下代码片段：

```jsx
<BrowserRouter keyLength={10}>
    <div  className="container"> <nav> <Link  to="/dashboard">Dashboard</Link> <Link  to="/user">User</Link> </nav> <Route path="/dashboard" render={({ location }) => <div> In Dashboard, Location Key: {location.key}  </div> }
        />
        <Route path="/user" render={({ location }) => <div> In User, Location Key: {location.key}  </div> }
        />
    </div>
</BrowserRouter>
```

当您导航到`/dashboard`或`/user`路径中的任何一个时，`location.key`的值将是一个长度为 10 的随机字母数字字符串。默认情况下，用于生成密钥的`keyLength`属性的值为 6。

当您使用导航链接在`/dashboard`和`/user`路径之间来回导航时，您会注意到每次导航都会生成一个新的键。这是因为当您使用导航链接导航时，会调用`history.push`并生成一个新的键，而该键对于历史堆栈中的每个条目都是唯一的。因此，当您通过单击浏览器的后退按钮导航时，将调用`history.pop`，您会注意到为位置生成的键，并且不会生成新的键。

# getUserConfirmation 属性

`getUserConfirmation`属性接受一个函数作为其值，并且当用户发起的导航被`<Prompt>`组件阻止时执行。`<Prompt>`组件使用`window.confirm`方法显示一个确认对话框，并且仅当用户单击确定按钮时才将用户导航到所选路径。然而，当`<BrowserRouter>`组件指定了`getUserConfirmation`属性时，将执行作为该属性值的函数。这提供了显示自定义对话框的机会。

让我们看一下以下配置：

```jsx
<BrowserRouter getUserConfirmation={this.userConfirmationFunc**}**>
    <div className="container">
        <nav>  <Link  to="/dashboard">Dashboard</Link> <Link  to="/user">User</Link> </nav>
        <Route path="/dashboard" render={({ location }) => <div> In Dashboard, Location Key: {location.key}  </div> }
        />
        <Route path="/user" render={({ location }) => <div> In User, Location Key: {location.key} <Prompt  message="This is shown in a confirmation 
                     window" **/>** </div> }
        />
    </div>
</BrowserRouter>
```

假设当前的 URL 路径是`/user`，您尝试通过单击`nav`菜单中提供的导航链接来导航到不同的路由，比如`/dashboard`。如果未指定`getUserConfirmation`属性，则会显示`<Prompt>`消息。在这种情况下，将执行在组件类中定义的`userConfirmationFunc`函数。

您可以调用`window.confirm`来显示一个确认对话框，询问用户是否导航：

```jsx
userConfirmationFunc  = (message, callback) => { const  status  =  window.confirm(message); callback(status**);** }
```

该函数接受两个参数——`message`和`callback`。`message`参数指定需要显示的消息，而`<Prompt>`组件中包含的`message`属性提供了该值。该函数预计执行作为第二个参数提供的回调函数。

在这里，`<BrowserRouter>`的第二个参数提供了一个回调函数。使用提供的`message`调用`window.confirm`函数，用户将看到两个按钮——确定和取消；单击确定时，`status`设置为 true，单击取消时，`status`设置为`false`。将使用作为第二个参数提供的`callback`函数调用此`status`值；这是一个允许用户导航到所选路由的真值。

这是默认行为；在允许用户导航到所选页面之前，会显示一个原生浏览器确认对话框。然而，这种行为可以在前面提到的`userConfirmationFunc`中进行更改；你可以显示一个自定义对话框，而不是显示浏览器的原生确认对话框。

# 使用 getUserConfirmation prop 显示自定义对话框

为了这个例子，让我们添加`material-UI`，其中包括一个自定义对话框组件：

```jsx
npm install --save @material-ui/core
```

让我们创建一个自定义对话框，将`Dialog`组件包装在`@material-ui/core`中：

```jsx
import { Button, Dialog, DialogActions, DialogContent, DialogTitle } from  '@material-ui/core'; export  class **ConfirmationDialog** extends  Component { render() { const { message, handleClose, isOpen } =  this.props; return ( <Dialog open={isOpen**}**> <DialogTitle>Custom Prompt</DialogTitle> <DialogContent>{message}</DialogContent> <DialogActions> <Button onClick={handleClose.bind(this, true)}> OK
                    </Button> <Button  onClick={handleClose.bind(this, false)}> CANCEL
                    </Button> </DialogActions> </Dialog> )
    }
}
```

这个组件接受三个 props——`message`、`handleClose`和`isOpen`。`message` prop 是你想在自定义对话框中显示的消息，`handleClose` prop 是一个函数引用，当用户点击 OK 或 CANCEL 按钮时调用该函数引用，分别允许或取消转换到所选路径。

让我们在根组件文件（在`App.js`中）中使用这个，并在用户尝试导航到不同的路由时显示`ConfirmationDialog`：

```jsx
class  App  extends  Component {    state  = { showConfirmationDialog:  false, message:  '', callback:  null }
    ...
```

我们首先在 React 组件中将`state`属性设置为它们的初始值。当用户尝试导航到不同的路由时，前面提到的`state`属性会发生变化：

```jsx
... userConfirmationFunc  = (message, callback) => { this.setState({ showConfirmationDialog:  true, message:  message, callback:  callback });
    }
```

前面的`userConfirmationFunc`函数设置`state`属性，以便在用户尝试离开当前路由时显示自定义确认对话框(`ConfirmationDialog`)。

在`App`组件中定义的以下`handleClose`函数将提供给我们之前创建的`ConfirmationDialog`组件：

```jsx
    ...
 handleClose(status) { this.state.callback(status**)**; this.setState({ showConfirmationDialog:  false, message:  '', callback:  null })
    }
```

这为我们提供了一种隐藏自定义确认对话框和将组件的`state`属性重置为它们的初始值的方法。`this.state.callback(status)`语句将关闭确认对话框，并且根据状态为真还是假，将用户导航到所选路由（如果状态为真）或取消导航（如果状态为假）。

这是组件类的更新渲染方法：

```jsx
    ...
    render() { return ( <BrowserRouter getUserConfirmation={this.userConfirmationFunc**}**> ...
                <Route path="/user" render={({ location }) => {
                        return ( <div> In User, Location Key: {location.key} <Prompt  message="This is shown in a 
                             confirmation modal" **/>** </div>
                        ); }}
                />
                <ConfirmationDialog isOpen={this.state.showConfirmationDialog} message={this.state.message} handleClose={this.handleClose.bind(this)} />
                ...
            </BrowserRouter>
        )
    }
}
```

在前面的渲染方法中，包括了自定义的`ConfirmationDialog`对话框，并且只有当`state`属性`showConrfirmationDialog`设置为`true`时才会渲染。`userConfirmationFunc`设置`state`属性，自定义对话框显示如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rtr-qk-st-gd/img/afdee1c8-4d60-4068-a613-05f1941e945e.png)

在前面的代码片段中，`handleClose` 函数是由 `ConfirmDialog` 框在用户单击 OK 或 CANCEL 按钮时调用的。OK 按钮将发送值 `true`，而 CANCEL 按钮将发送值 `false` 到先前定义的 `handleClose` 函数。

# <HashRouter> 组件

`<HashRouter>` 组件是 `react-router-dom` 包的一部分，与 `<BrowserRouter>` 类似，也用于构建浏览器环境的应用程序。`<BrowserRouter>` 和 `<HashRouter>` 之间的主要区别是组件创建的 URL：

`<BrowserRouter>` 创建的 URL 如下：

```jsx
www.packtpub.com/react-router
```

`<HashRouter>` 在 URL 中添加了一个哈希：

```jsx
www.packtpub.com/#/react-router
```

`<BrowserRouter>` 组件利用 HTML5 History API 来跟踪路由历史记录，而 `<HashRouter>` 组件使用 `window.location.hash`（URL 的哈希部分）来记住浏览器历史堆栈中的更改。应该在支持 HTML5 History API 的现代浏览器上构建应用程序时使用 `<BrowserRouter>`，而在需要支持旧版浏览器的应用程序中使用 `<HashRouter>`。

`<HashRouter>` 使用 `createHashHistory` 类来创建 `history` 对象。然后将此 `history` 对象提供给核心 `<Router>` 组件：

```jsx
import { createHashHistory  as  createHistory } from  "history";  class  HashRouter  extends  React.Component {    ...
    history =  createHistory(this.props**)**; ...
    render() {
        return **<Router 
                  history={this.history}
                  children={this.props.children} 
               />**;
    } }
```

`<HashRouter>` 接受以下 props：

```jsx
static propTypes = {
    basename: PropTypes.string,
    getUserConfirmation: PropTypes.func,
    hashType: PropTypes.oneOf(["hashbang", "noslash", "slash"]),
    children: PropTypes.node
};
```

与`<BrowserRouter>`类似，props `basename` 和 `getUserConfirmation` 用于分别指定基本 URL 路径和确认导航到所选 URL 的函数。然而，`<HashRouter>` 不支持 `location.key` 和 `location.state`，因此不支持 prop `keyLength`。此外，也不支持 prop `forceRefresh`。

让我们来看看 `hashType` prop。

# hashType prop

`hashType` prop 用于指定用于 `window.location.hash` 的编码方法。可能的值包括 `slash`、`noslash` 和 `hashbang`。

让我们来看看在包含 `hashType` prop 时如何形成 URL：

```jsx
<HashRouter hashType="slash">
    <App />
</HashRouter>
```

当您将 `slash` 指定为 `hashType` prop 的值时，会在哈希 (`#`) 后添加斜杠 (`/`)。因此，URL 将采用以下形式 — `#/`，`#/dashboard`，`#/user` 等。

请注意，`slash` 是 prop `hashType` 的默认值，如果要在 `#` 后添加斜杠，则不需要包括 `hashType` prop。

类似地，当`hashType`属性的值为`noslash`时，URL 的形式为—`#`、`#dashboard`、`#user`等：

```jsx
<HashRouter hashType="noslash">
```

当`hashType`属性分配值`hashbang`时，它创建的 URL 形式为—`#!/`、`#!/dashboard`、`#!/user`等：

```jsx
<HashRouter  hashType="hashbang">
```

`hashbang`是为了让搜索引擎爬虫可以爬取和索引单页面应用程序而添加的。然而，谷歌已经弃用了这种爬取策略。在这里阅读更多信息：[`webmasters.googleblog.com/2015/10/deprecating-our-ajax-crawling-scheme.html`](https://webmasters.googleblog.com/2015/10/deprecating-our-ajax-crawling-scheme.html)。

# 摘要

`react-router`包中的`<Router>`组件提供了路由器接口的低级实现。`react-router-dom`和`react-router-native`中的各种路由器使用这个低级的`<Router>`接口为特定环境提供路由功能。`<Router>`中的`history`属性用于指定给定环境的`history`对象。例如，`<BrowserRouter>`组件在浏览器环境中使用`history/createBrowserHistory`来创建`history`对象。所有的 Router 组件只接受一个子组件，通常是应用程序的根组件。

`react-router-dom`中的`BrowserRouter`组件利用 HTML5 历史 API 与浏览器历史记录同步以保持应用程序的 URL。它接受`basename`、`keyLength`、`forceRefresh`和`getUserConfirmation`等 props。另一方面，`<HashRouter>`在浏览器的 URL 中添加一个哈希(#)并使用`window.location.hash`来跟踪历史记录。它接受`basename`、`getUserConfirmation`和`hashType`等 props。`hashType`属性用于指定用于`window.location.hash`的编码方法；可能的值有`slash`、`noslash`和`hashbang`。

在第六章中，*在服务器端渲染的 React 应用程序中使用 StaticRouter*，我们将介绍使用`<StaticRouter>`组件进行服务器端渲染。
