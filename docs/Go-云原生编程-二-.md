# Go 云原生编程（二）

> 原文：[`zh.annas-archive.org/md5/E4B340F53EAAF54B7D4EF0AD6F8B1333`](https://zh.annas-archive.org/md5/E4B340F53EAAF54B7D4EF0AD6F8B1333)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：使用 React 构建前端

在之前的章节中，您已经使用 Go 构建了多个微服务，并使用 REST Web 服务和异步消息队列进行了集成。然而，即使是最可扩展的云应用程序，如果没有用户可以轻松交互的界面，也只有一半的用处（除非，当然，向用户提供 REST API 是您的实际产品）。为了使前几章中构建的 API 更具体，我们现在将为我们的应用程序添加一个基于 Web 的前端。

为此，我们将离开 Go 编程世界一段时间，并短暂地转向 JavaScript 编程世界。更确切地说，我们将看一下 React 框架，并将其用于为（现在几乎完成的）MyEvents 后端构建前端应用程序。

在构建前端应用程序时，我们还将接触到 JavaScript 生态系统中许多组件。例如，我们将使用 TypeScript 编译器以便以类型安全的方式进行编程。此外，我们将使用 Webpack 模块打包程序，以便轻松部署我们的 JavaScript 应用程序，以便在所有现代 Web 浏览器中轻松使用。

在本章中，我们将涵盖以下主题：

+   设置 Node.js/TypeScript/React 开发环境

+   启动一个新项目

+   React 组件

+   Webpack 模块打包程序

+   使用 RESTful 后端构建 React 应用程序

# 开始使用 React

在本章中，我们将暂时离开 Go 生态系统。要使用 React，您需要一个开发环境，其中包括 Node.js、npm 和 TypeScript 编译器，我们将在下一节中设置。

# 设置 Node.js 和 TypeScript

JavaScript 是一种动态类型语言。尽管（像 Go 一样）它确实有数据类型的概念，但 JavaScript 变量基本上可以在任何时候具有任何类型（与 Go 不同）。由于我们不希望您在我们短暂进入 JavaScript 世界的过程中开始错过 Go 编译器和 Go 的类型安全性，因此我们将在此示例中使用 TypeScript。TypeScript 是 JavaScript 的类型安全超集，它添加了静态类型和基于类的面向对象编程。您可以使用 TypeScript 编译器（或简称为*tsc*）将 TypeScript 编译为 JavaScript。

首先，除了 Go 运行时，您还需要在开发机器上设置一个可用的 Node.js 运行时。查看[`nodejs.org/en/download`](https://nodejs.org/en/download)了解如何在您的机器上设置 Node.js。如果您使用 Linux（或 macOS 使用 Homebrew 等软件包管理器），请查看[`nodejs.org/en/download/package-manager`](https://nodejs.org/en/download/package-manager)。

安装了 Node.js 后，继续使用 Node 包管理器（npm）安装 TypeScript 编译器：

```go
$ npm install -g typescript
```

这将下载并安装 TypeScript 编译器到您系统的`PATH`中。运行上述命令后，您应该能够在命令行上调用 tsc。

在这个项目中，我们还将使用 Webpack 模块打包程序。模块打包程序获取 Node.js 模块并生成静态 JavaScript 文件，可在浏览器环境中使用。您可以通过 npm 安装 Webpack，就像您为 TypeScript 编译器所做的那样：

```go
$ npm install -g webpack
```

# 初始化 React 项目

首先为您的 React 前端应用程序创建一个新目录。接下来，将该目录初始化为一个新的`npm`包：

```go
$ npm init
```

`npm init`命令将提示您输入有关您的项目的一些（多多少少）重要信息。最后，它应该会生成一个`package.json`文件，大致如下：

```go
{ 
  "name": "myevents-ui", 
  "version": "1.0.0", 
  "description": "", 
  "main": "dist/bundle.js", 
  "author": "Martin Helmich", 
  "license": "MIT" 
} 
```

一般来说，我们的应用程序将具有以下目录结构：

+   我们的 TypeScript 源文件将放在`src/`目录中。

+   编译后的 JavaScript 文件将放在`dist/`目录中。由于我们将使用 Webpack 作为模块打包程序，我们的`dist/`目录很可能只包含一个文件，其中包含整个编译后的源代码。

+   我们将通过 npm 安装的库作为依赖项安装到`node_modules/`目录中。

现在我们可以使用 npm 向我们的项目添加依赖项。让我们从安装 React 和 ReactDOM 包开始：

```go
$ npm install --save react@16 react-dom@16 @types/react@16 @types/react-dom@16
```

TypeScript 编译器需要`@types`包。由于 React 是一个 JavaScript（而不是 TypeScript）库，TypeScript 编译器将需要有关由 react 库定义的类和它们的方法签名的额外信息。例如，这些**typings**可能包含有关 React 提供的某些函数所需的参数类型和它们的返回类型的信息。

我们还需要一些开发依赖项：

```go
$ npm install --save-dev typescript awesome-typescript-loader source-map-loader
```

这些库将被 Webpack 模块捆绑器需要将我们的源文件编译为 JavaScript 文件。但是，我们只需要这些依赖项来*构建*应用程序，而不是实际*运行*它。因此，我们使用`--save-dev`标志将它们声明为开发依赖项。

接下来，我们需要配置 TypeScript 编译器。为此，在项目目录中创建一个新的`tsconfig.json`文件：

```go
{ 
  "compilerOptions": { 
    "outDir": "./dist/", 
    "module": "commonjs", 
    "target": "es5", 
    "sourceMap": true, 
    "noImplicitAny": true, 
    "jsx": "react" 
  }, 
  "include": [ 
    "./src/**/*" 
  ] 
} 
```

请注意，我们正在配置 TypeScript 编译器，使用`include`属性从`src/`目录加载其源文件，并使用`outDir`属性将编译后的输出文件保存到`dist/`。

最后，我们还需要通过创建一个`webpack.config.js`文件来配置 Webpack 模块捆绑器：

```go
module.exports = { 
  entry: "./src/index.tsx", 
  output: { 
    filename: "bundle.js", 
    path: __dirname + "/dist" 
  }, 
  resolve: { 
    extensions: [".ts", ".tsx"] 
  }, 
  module: { 
    rules: [ 
      { 
        test: /\.tsx?$/, 
        loader: "awesome-typescript-loader" 
      } 
    ] 
  }, 
  externals: { 
    "react": "React", 
    "react-dom": "ReactDOM" 
  } 
} 
```

这个文件配置 Webpack 在所有`.ts`和`.tsx`文件上使用 TypeScript 加载器，编译它们，并将所有模块捆绑到`dist/bundle.js`文件中。但在实际执行之前，您需要添加一些要编译的源文件。

在这样做之前，让我们看看 React 实际上是如何工作的。

# 基本的 React 原则

React 应用程序是由**组件**构建的。组件是一个 JavaScript 类，它接受一组值（称为属性，或简称为*props*），并返回可以由浏览器呈现的 DOM 元素树。

考虑以下简单的例子。我们将从纯 JavaScript 实现开始，然后向您展示如何使用 TypeScript 添加静态类型：

```go
class HelloWorld extends React.Component { 
  render() { 
    return <div className="greeting"> 
      <h1>Hello {this.props.name}!</h1> 
    </div>; 
  } 
} 
```

即使您习惯于 JavaScript，该语法对您来说可能会很新。从技术上讲，前面的代码示例不是纯 JavaScript（任何浏览器都会拒绝实际运行此代码），而是**JSX**。JSX 是 JavaScript 的一种特殊语法扩展，允许您直接使用它们的 HTML 表示来定义 DOM 元素。这使得定义 React 组件变得更加容易。如果不使用 JSX，前面的代码示例将需要按照以下方式编写：

```go
class HelloWorld extends React.Component { 
  render() { 
    return React.createElement("div", {class: "greeting"}, 
      React.createElement("h1", {}, `Hello ${this.props.name}!`) 
    ); 
  } 
} 
```

当实际在浏览器中运行 JSX 源代码时，它需要首先转换为普通的 JavaScript。这将在实际构建应用程序时由 Webpack 模块捆绑器完成。

还有 JSX 的 TypeScript 变体，称为**TSX**。它的工作方式完全相同，但具有静态类型。使用 TypeScript 构建 React 组件时，您还可以为组件 props 定义接口。

由于这实际上是一本 Go 书，很重要的一点是要注意 TypeScript 接口与 Go 接口相比是非常不同的。虽然 Go 接口描述了一个结构体需要实现的一组方法，但 TypeScript 接口定义了对象需要具有的属性和/或方法。

要将 React 组件与 props 接口关联起来，`React.Component`类具有一个类型参数，您可以在扩展类时指定：

```go
export interface HelloWorldProps { 
  name: string; 
} 

export class HelloWorld extends React.Component 
<HelloWorldProps, any> { 
  render() { 
    // ... 
  } 
} 
```

组件可以嵌套在彼此中。例如，您现在可以在另一个组件中重用之前的`HelloWorld`组件：

```go
import {HelloWorld} from "./hello_world"; 

class ExampleComponents extends React.Component<{}, any> { 
  render() { 
    return <div class="greeting-list"> 
      <HelloWorld name="Foo"/> 
      <HelloWorld name="Bar"/> 
    </div> 
  } 
} 
```

使用 TypeScript 的一个优点是，当您使用通过接口定义 props 的组件时，TypeScript 编译器会检查您是否实际上提供了正确的 props 给组件。例如，在前面的例子中省略`name` prop（或将其传递给另一个值而不是字符串）将触发编译错误。

传递给 React 组件的 props 被视为不可变的。这意味着当 prop 的值之一更改时，组件不会重新渲染。但是，每个 React 组件可能有一个内部状态，可以进行更新。每当组件的状态更改时，它将被重新渲染。考虑以下例子：

```go
export interface CounterState { 
  counter: number; 
} 

export class Counter extends React.Component<{}, CounterState> { 
  constructor() { 
    super(); 
    this.state = {counter: 0}; 
  } 

  render() { 
    return <div>Current count: {this.state.counter}</div>; 
  } 
} 
```

现在，我们可以使用组件的`setState()`方法随时更新此状态。例如，我们可以使用计时器每秒增加计数器：

```go
constructor() { 
  super();
   this.state = {counter: 0}; 

  setInterval(() => { 
    this.setState({counter: this.state.counter + 1}); 
  }, 1000); 
} 
```

改变组件的状态将导致重新渲染。在前面的例子中，这将导致计数器每秒可见地增加 1。

当然，我们也可以组合 props 和 state。一个常见的用例是使用传递给组件的 props 来初始化该组件的状态：

```go
export interface CounterProps { 
  start: number; 
} 

export interface CounterState { 
  counter: number 
} 

export class Counter extends React.Component<CounterProps, CounterState> { 
  constructor(props: CounterProps) { 
    super(props); 

    this.state = { 
      counter: props.start 
    }; 

    setInterval(() => { 
      // ... 
  } 
} 
```

掌握了 React 组件的知识后，我们现在可以开始构建 MyEvents 平台的前端。

# 启动 MyEvents 前端

我们将首先构建一个简单的 React 应用程序，从服务器获取可用事件列表并将其显示为简单列表。

在开始之前，我们需要引导我们的 React 应用程序。为此，我们需要构建一个可以作为应用程序入口点的`index.html`文件。通常，这个文件不会很长，因为它的大部分逻辑将以 React 组件的形式存在：

```go
<!DOCTYPE html> 
<html lang="en"> 
  <head> 
    <meta charset="UTF-8"> 
    <title>MyEvents</title> 
  </head> 
  <body> 
    <div id="myevents-app"></div> 

    <script src="img/react.production.min.js"></script> 
    <script src="img/react-dom.production.min.js"></script> 
    <script src="img/bundle.js"></script> 
  </body> 
</html> 
```

让我们更详细地看一下这个 HTML 文件。具有`myevents-app` ID 的`DIV`将成为我们的 React 应用程序将呈现的位置。然后，大部分文件由从相应的 npm 包加载 React 库和加载我们的实际应用程序包（将由 Webpack 构建）组成。

为了使我们的应用程序看起来更好一些，我们还将在前端添加 Twitter Bootstrap 框架。像往常一样，您可以使用`npm`来安装 Bootstrap：

```go
$ npm install --save bootstrap@³.3.7
```

安装 Bootstrap 后，您可以在`index.html`文件的头部部分包含相应的 CSS 文件：

```go
<!DOCTYPE html> 
<html lang="en"> 
<head> 
  <meta charset="UTF-8"> 
  <title>MyEvents</title> 
  <link rel="stylesheet" href="./node_modules/bootstrap/dist/css/bootstrap.min.css"/> 
</head> 
<body> 
  <!-- ... --> 
</body> 
</html> 
```

要开始，请现在添加一个新的 React 组件。为此，在项目目录中创建`src/components/hello.tsx`文件：

```go
import * as React from "React"; 

export interface HelloProps { 
  name: string; 
} 

export class Hello extends React.Component<HelloProps, {}> { 
  render() { 
    return <div>Hello {this.props.name}!</div>; 
  } 
} 
```

我们的 React 应用程序的实际入口点将放在`src/index.tsx`文件中。您可能还记得，这也是我们在`webpack.config.js`文件中指定为 Webpack 模块打包程序的入口点的文件：

```go
import * as React from "react"; 
import * as ReactDOM from "react-dom"; 
import {Hello} from "./components/hello"; 

ReactDOM.render( 
  <div className="container"> 
    <h1>MyEvents</h1> 
    <Hello name="World"/> 
  </div>, 
  document.getElementById("myevents-app") 
); 
```

看一下前面代码示例中的`className`属性。在 JSX 或 TSX 中使用纯 HTML 元素时，您需要使用`className`而不是`class`。这是因为`class`是 JavaScript 和 TypeScript 中的保留关键字，因此仅使用`class`会严重混淆编译器。

创建了所有这些文件后，现在可以运行 Webpack 打包程序来创建您的`bundle.js`文件：

```go
$ webpack
```

在开发过程中，您还可以让 Webpack 打包程序持续运行，每当源文件之一更改时更新您的`bundle.js`文件。只需在后台的 shell 窗口中保持启动的进程运行：

```go
$ webpack --watch
```

现在可以在浏览器中打开`index.html`文件。但是，直接在浏览器中打开本地文件将在以后向后端服务发出 HTTP 请求时引起问题。您可以使用`http-server` npm 包快速设置一个可以提供这些本地文件的 HTTP 服务器。只需通过`npm`安装它，然后在项目目录中运行它：

```go
$ npm install -g http-server
$ http-server
```

默认情况下，Node.js HTTP 服务器将在 TCP 端口`8080`上监听，因此您可以通过在浏览器中导航到`http://localhost:8080`来访问它：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/66fc2cd7-4f3f-41fe-9c4e-9b06844fbc75.png)

输出（http://localhost:8080）

恭喜！您刚刚构建了您的第一个 React 应用程序。当然，对于 MyEvents 平台，我们将需要比 Hello World!更多。我们的第一个任务之一将是从后端服务加载可用事件并以美观的方式显示它们。

# 实现事件列表

为了显示可用事件的列表，我们将需要一个解决方案来从后端服务加载这些事件，更准确地说，是您在第二章中构建的事件服务的 REST API，*使用 Rest API 构建微服务*，以及第三章，*保护微服务*。

# 自己带来客户端

React 是一个模块化的框架。与其他 JavaScript 前端框架（如 Angular）不同，React 不提供自己的 REST 调用库，而是期望您自己带来。为了从服务器加载数据，我们将使用 fetch API。fetch API 是一个较新的 JavaScript API，用于向许多现代浏览器（主要是 Firefox 和 Chrome）中实现的后端服务进行 AJAX 调用。对于尚未实现 fetch API 的旧版浏览器，有一个`polyfill`库，您可以通过`npm`添加到您的应用程序中：

```go
$ npm install --save whatwg-fetch promise-polyfill
```

您需要在`index.html`文件中将这两个`polyfill`库与其他 JavaScript 库一起包含：

```go
<script src="img/react.min.js"></script> 
<script src="img/react-dom.min.js"></script> 
<script src="img/promise.min.js"></script> 
<script src="img/fetch.js"></script> 
<script src="img/bundle.js"></script> 
```

当浏览器的 fetch API 可用时，fetch `polyfill`库将使用浏览器的 fetch API，并在不可用时提供自己的实现。几年后，当更多的浏览器支持 fetch API 时，您将能够安全地删除`polyfill`。

# 构建事件列表组件

现在让我们考虑一下我们将需要哪些 React 组件来构建我们的事件列表。以下图表显示了我们将要构建的组件的概述：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/0f475ad6-376b-4108-8f95-131ae2ba5c34.png)

事件列表将构建的组件概述

这些组件将有以下职责：

+   `EventListContainer`组件将负责从后端服务加载事件列表并在其自己的状态中管理事件列表。然后，它将当前的事件集传递给`EventList`组件的 props。

+   `EventList`组件将负责呈现事件列表将呈现的容器。首先，我们将选择一个简单的表格视图。然后，这个表格将被填充一个`EventListItem`集合，每个事件一个。

+   `EventListItem`组件将在事件列表中呈现单个事件项。

从技术上讲，`EventList`组件可以同时加载来自后端服务的事件并管理事件列表呈现。然而，这将违反**单一责任原则**；这就是为什么我们有两个组件的原因——一个加载事件并将其传递给另一个，另一个向用户呈现它们。

让我们首先告诉 TypeScript 编译器事件实际上是什么样子。为此，我们将定义一个 TypeScript 接口，描述后端服务在使用`GET`获取 URL`/events`时传递的 JSON 响应。创建一个新的`./src/models/event.ts`文件，内容如下：

```go
export interface Event { 
  ID string; 
  Name string; 
  Country string; 
  Location { 
    ID string; 
    Name string; 
    Address string; 
  }; 
  StartDate number; 
  EndDate number; 
  OpenTime: number; 
  CloseTime: number; 
} 
```

注意这个接口定义与事件服务代码中定义的`persistence.Event`结构是多么相似。为了使前端和后端能够良好协作，这两个定义在发生更改时需要保持同步。

现在您可以继续构建 React 组件。我们将从底部开始实现`EventListItem`。为此，请创建一个新的`src/components/event_list_item.tsx`文件：

```go
import {Event} from "../models/event"; 
import * as React from "react"; 

export interface EventListItemProps { 
  event: Event; 
} 

export class EventListItem extends React.Component<EventListItemProps, {}> { 
  render() { 
    const start = new Date(this.props.event.StartDate * 1000); 
    const end = new Date(this.props.event.EndDate * 1000); 

    return <tr> 
      <td>{this.props.event.Name}</td> 
      <td>{this.props.event.Location.Name}</td> 
      <td>{start.toLocaleDateString()}</td> 
      <td>{end.toLocaleDateString()}</td> 
      <td></td> 
    </tr> 
  } 
} 
```

接下来，在`src/components/event_list.tsx`文件中定义`EventList`组件：

```go
import {Event} from "../models/event"; 
import {EventListItem} from "./event_list_item"; 
import * as React from "react"; 

export interface EventListProps { 
  events: Event[]; 
} 

export class EventList extends React.Component<EventListProps, {}> { 
  render() { 
    const items = this.props.events.map(e => 
      <EventListItem event={e} /> 
    ); 

    return <table className="table"> 
      <thead> 
        <tr> 
          <th>Event</th> 
          <th>Where</th> 
          <th colspan="2">When (start/end)</th> 
          <th>Actions</th> 
        </tr> 
      </thead> 
      <tbody> 
        {items} 
      </tbody> 
    </table> 
  }   
} 
```

注意`EventList`组件如何使用 JavaScript 的原生`map`函数将事件对象数组转换为`EventListItem`列表（传递事件作为 prop）非常容易。`EventListItem`列表然后插入到`EventList`组件创建的表的主体中。

最后，我们可以构建`EventListContainer`组件。在这个组件中，我们将使用 fetch API 从服务器加载事件。首先，让我们在`src/components/event_list_container.tsx`文件中实现`EventListContainer`的 props 和 state 的定义：

```go
import * as React from "react"; 
import {EventList} from "./event_list"; 
import {Event} from "../models/event"; 

export interface EventListContainerProps { 
  eventListURL: string; 
} 

export interface EventListContainerState { 
  loading: boolean; 
  events: Event[] 
} 
```

接下来，我们可以实现实际的组件：

```go
export class EventListContainer extends React.Component 
<EventListContainerProps, EventListContainerState> { 
  construct(p: EventListContainerProps) { 
    super(p); 

    this.state = { 
      loading: true, 
      events: [] 
    }; 

    fetch(p.eventListURL) 
      .then<Event[]>(response => response.json()) 
      .then(events => { 
        this.setState({ 
          loading: false, 
          events: events 
        }); 
      }); 
  } 
} 
```

在构造函数中，我们将首先初始化组件的状态。在这里，重要的是要记住 JavaScript 中的 HTTP 操作通常是异步的。尽管我们在构造函数中调用`fetch`函数，但 JavaScript 运行时将异步执行此 HTTP 请求，并且即使没有加载数据（尚未），组件也将被创建。因此，我们的组件状态包括一个名为`loading`的布尔属性，指示数据是否仍在加载。稍后，组件可以根据这个状态属性调整其呈现。

`fetch`方法返回一个 promise。promise 是一个尚未可用的值的占位符。您可以在 promise 实例上使用`then(...)`函数，以便在承诺的值变为可用时立即运行代码。您还可以链接 promise；在这种情况下，`fetch`函数返回一个 HTTP 响应的 promise（即`Response`类的实例）。这个类本身有一个`json()`函数，它本身返回另一个解码后的 JSON 值的 promise。当传递给`then(...)`调用的函数返回另一个 promise 时，返回的 promise 将替换原始 promise。这意味着我们可以在链中添加另一个`then()`调用，当 HTTP 响应可用并且成功解码为 JSON 时将调用该调用。当发生这种情况时，我们将更新组件的状态，指示组件不再处于加载状态，并且包含实际事件列表的`events`属性。

最后，通过添加一个`render()`方法来完成`EventListContainer`组件：

```go
render() { 
  if (this.state.loading) { 
    return <div>Loading...</div>; 
  } 

  return <EventList events={this.state.events} />; 
} 
```

为了实际在我们的页面上显示事件列表，现在可以在`index.tsx`文件中使用`EventListContainer`：

```go
import * as React from "react"; 
import * as ReactDOM from "react-dom"; 
import {EventListContainer} from "./components/event_list_container"; 

ReactDOM.render( 
  <div className="container"> 
    <h1>MyEvents</h1> 
    <EventListContainer eventListURL="http://localhost:8181"/> 
  </div>, 
  document.getElementById("myevents-app") 
); 
```

一般来说，构建一个可以作为应用程序的单一入口点的根组件也被认为是一种良好的做法。我们可以将`ReactDOM.render`调用中的 DOM 元素提取到自己的组件中，然后在`ReactDOM.render`调用中使用它：

```go
class App extends React.Component<{}, {}> { 
  render() { 
    return <div className="container"> 
      <h1>MyEvents</h1> 
      <EventListContainer eventListURL="http://localhost:8181"/> 
    </div> 
  } 
} 

ReactDOM.render( 
  <App/> 
  document.getElementById("myevents-app") 
); 
```

# 在后端服务中启用 CORS

在测试前端应用程序之前，您需要确保后端服务（更准确地说，事件服务和预订服务）支持**跨源资源共享**（**CORS**）。否则，当前端在`http://localhost:8080`上提供，后端服务在其他 TCP 端口上运行时，浏览器将不会执行对任何后端服务的 HTTP 请求。

原则上，CORS 只是需要在 HTTP 响应中存在的一些额外标头。例如，为了允许来自另一个域的 AJAX 请求，HTTP 响应需要包含一个`Access-Control-Allow-Origin`标头。具有这样一个标头的 HTTP 响应可能如下所示：

```go
HTTP/1.1 200 OK
 Content-Type: application/json; charset=utf-8
 Content-Length: 1524
 Date: Fri, 24 Mar 2017 16:02:55 GMT
 Access-Control-Allow-Origin: http://localhost:8080 
```

由于我们在事件和预订服务中都使用 Gorilla 工具包，因此添加 CORS 功能很容易。首先，我们需要获取`github.com/gorilla/handlers`包：

```go
$ go get github.com/gorilla/handlers
```

之后，我们可以使用`handlers.CORS`函数将 CORS 功能添加到现有的 HTTP 服务器中。这允许我们调整事件服务的`rest.go`文件如下：

```go
package rest 

import ( 
  // ... 
  "github.com/gorilla/mux" 
  "github.com/gorilla/handlers" 
) 

func ServeAPI(endpoint string, dbHandler persistence.DatabaseHandler, eventEmitter msgqueue.EventEmitter) error { 
  handler := newEventHandler(dbHandler, eventEmitter) 
  r := mux.NewRouter() 

  // ... 

  server := handlers.CORS()(r) 
  return http.ListenAndServe(endpoint, server) 
} 
```

以相同的方式调整预订服务。之后，您将能够从前端应用程序无问题地与两个服务进行通信。

# 测试事件列表

为了测试你的应用程序，请确保你的事件服务实例在本地运行，并监听 TCP 端口`8181`。还要确保你已经使用事件服务的 REST API 创建了一个或两个事件。然后，在你的前端应用目录中启动 Node.js `http-server`，并在浏览器中导航到`http://localhost:8080`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/df05a321-6a76-4287-a1a8-57f641e80d96.png)

输出（http://localhost:8080）

# 添加路由和导航

在我们为前端应用添加更多功能之前，让我们花时间添加一个强大的导航和路由层。这将使我们的应用在添加更多功能时保持易于维护。

为了支持多个应用视图，我们首先将`react-router-dom`包添加到我们的应用中：

```go
$ npm install --save react-router-dom
$ npm install --save-dev @types/react-router-dom
```

`react-router-dom`包为我们的应用添加了一些新组件。我们可以在根组件中使用这些组件来轻松实现路由：

```go
import * as React from "react"; 
import * as ReactDOM from "react-dom"; 
import {HashRouter as Router, Route} from "react-router-dom"; 
// ... 

class App extends React.Component<{}, {}> { 
  render() { 
    const eventList = () => <EventListContainer eventServiceURL="http://localhost:8181"/> 

    return <Router> 
      <div className="container"> 
        <h1>My Events</h1> 

        <Route exact path="/" component={eventList}/> 
      </div> 
    </Router> 
  } 
} 
```

请注意容器中如何使用`<Route>`组件；在这一点上，我们可以稍后添加多个`Route`组件，React 路由将根据当前 URL 呈现这些组件。这允许我们的应用使用普通的旧链接将用户从一个视图引导到另一个视图。

请注意在前面的`render()`方法中声明的`eventList`常量。这是因为`Route`组件接受一个`component`属性，它引用一个组件或一个函数，每当匹配到这个`Route`时都会调用它。然而，我们无法指定应该传递给相应组件的 props。这就是为什么我们声明一个函数，用默认 props 初始化`EventListContainer`组件，允许它在`Route`组件中使用。

现在我们有了一个工作的路由层；让我们确保我们的用户始终能找到回到事件列表的方法。为此，我们将添加一个新的导航栏组件，我们可以在根组件中使用。创建一个新的`src/components/navigation.tsx`文件：

```go
import * as React from "react"; 
import {Link} from "react-router-dom"; 

export interface NavigationProps { 
  brandName: string; 
} 

export class Navigation extends React.Component<NavigationProps, {}> { 
} 
```

接下来，在新组件中添加一个`render()`方法：

```go
render() { 
  return <nav className="navbar navbar-default"> 
    <div className="container"> 
      <div className="navbar-header> 
        <Link to="/" className="navbar-brand"> 
          {this.props.brandName} 
        </Link> 
      </div> 

      <ul className="nav navbar-nav"> 
        <li><Link to="/">Events</Link></li> 
      </ul> 
    </div> 
  </nav> 
} 
```

请注意我们的`Navigation`组件如何使用`Link`组件来创建到其他 React 路由的链接，鉴于我们现在只有`/`路由，这并不复杂。

要实际使用我们的新导航组件，请将其添加到根组件的`render`方法中：

```go
// ... 
import {Navigation} from "./components/navigation"; 

class App extends React.Component<{}, {}> { 
  render() { 
    const eventList = () => <EventListContainer eventServiceURL="http://localhost:8181"/> 

    return <Router> 
      <Navigation brandName="MyEvents"/> 
      <div className="container"> 
        <h1>My Events</h1> 

        <Route exact path="/" component={eventList}/> 
      </div> 
    </Router> 
  } 
} 
```

# 实现预订流程

现在我们已经有了一个工作的路由和导航，我们可以实现下一个功能——预订流程。为了本书的目的，我们将保持预订流程简单。我们之前实现的事件列表中的每一行都应该有一个按钮，可以将用户带到预订表单。在这个表单中，他们将被要求输入他们想要预订的票数，然后可以提交表单。提交后，前端应用将执行一个 HTTP 请求到预订服务。

当然，我们将把预订表单实现为一个 React 组件。与之前一样，我们将分开职责并构建单独的组件来处理后端通信和前端呈现。`EventBookingFormContainer`将负责从事件服务加载事件记录，并将实际预订保存到预订服务。然后`EventBookingForm`将负责表单的实际前端呈现。为了使表单呈现更容易，我们还将引入一个`FormRow`组件。以下图表概述了这些组件及它们之间的关系：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/da695a1f-2970-4f7b-99de-cf52a8f9de57.png)

组件之间的关系

`FormRow`组件将是一个纯粹的呈现组件，以便更容易使用 Bootstrap 框架的表单 CSS 类。与之前一样，我们将自下而上实现这些组件，从最内部的组件开始。为此，创建`src/components/form_row.tsx`文件：

```go
import * as React from "react"; 

export interface FormRowProps { 
  label?: string; 
} 

export class FormRow extends React.Component<FormRowProps, {}> { 
  render() { 
    return <div className="form-group"> 
      <label className="col-sm-2 control-label"> 
        {this.props.label} 
      </label> 
      <div className="col-sm-10"> 
        {this.props.children} 
      </div> 
    </div> 
  } 
} 
```

在这种情况下，我们使用了特殊的 prop`children`。虽然我们没有在`FormRowProps`接口中明确定义这个 prop，但我们可以在任何 React 组件中使用`children`prop。它将包含传递给当前组件的任何 DOM 元素的子元素。这将允许您像下面这样使用`FormRow`组件：

```go
<FormRow label="Some input field"> 
  <input className="form-control" placeholder="Some value..."/> 
</FormRow> 
```

接下来，我们可以使用`FormRow`组件来构建`EventBookingForm`组件。为此，创建一个名为`src/components/event_booking_form.tsx`的新文件：

```go
import * as React from "react"; 
import {Event} from "../model/event"; 
import {FormRow} from "./form_row"; 

export interface EventBookingFormProps { 
  event: Event; 
  onSubmit: (seats: number) => any 
} 

export interface EventBookingFormState { 
  seats: number; 
} 

export class EventBookingForm
  extends React.Component<EventBookingFormProps, EventBookingFormState> { 
  constructor(p:  EventBookingFormProps) { 
    super(p); 

    this.state = {seats: 1}; 
  } 
} 
```

`EventBookingForm`组件既有输入 props，也有内部状态。输入属性包含实际的事件，为其应该呈现预订表单，并且一个回调方法。我们稍后将配置预订表单，在表单提交时调用这个回调方法。表单的内部状态包含应该预订的门票数量的变量。

现在，为`EventBookingForm`组件添加一个`render()`方法：

```go
render() { 
  return <div> 
    <h2>Book tickets for {this.props.event.name}</h2> 
    <form className="form-horizontal"> 
      <FormRow label="Event"> 
        <p className="form-control-static"> 
          {this.props.event.name} 
        </p> 
      </FormRow> 
      <FormRow label="Number of tickets"> 
        <select className="form-control" value={this.state.seats} 
onChange={event => this.handleNewAmount(event)}> 
          <option value="1">1</option> 
          <option value="2">2</option> 
          <option value="3">3</option> 
          <option value="4">4</option> 
        </select> 
      </FormRow> 
      <FormRow> 
        <button className="btn btn-primary" 
onClick={() => this.props.onSubmit(this.state.seats)}> 
          Submit order 
        </button> 
      </FormRow> 
    </form> 
  </div> 
} 
```

这将生成一个小表单，用户将能够查看他们预订门票的事件，选择所需数量的门票，然后提交订单。请注意，`onSubmit`属性在按钮的`onClick`事件上被调用。

另外，请注意选择字段的`onChange`事件调用了一个`this.handleNewAmount`方法，我们还没有定义。现在让我们来做这个：

```go
import * as React from "react"; 
import {ChangeEvent} from "react"; 
// ... 

export class EventBookingForm extends React.Component<EventBookingFormProps, EventBookingFormState> { 
  // ... 

  private handleNewAmount(event: ChangeEvent<HTMLSelectElement>) { 
    const state: EventBookingFormState = { 
      seats: parseInt(event.target.value) 
    } 

    this.setState(state); 
  } 
} 
```

最后但并非最不重要的是，我们现在可以实现`EventBookingFormContainer`组件。这个组件将负责处理与相应后端服务的 AJAX 通信（因为我们正在处理事件预订，我们还必须与我们在第四章中构建的预订服务进行通信，*使用消息队列的异步微服务架构*）。

让我们首先定义组件的 props 和 state。为此，创建一个新的`src/components/event_booking_form_container.tsx`文件：

```go
import * as React from "react"; 
import {EventBookingForm} from "./event_booking_form"; 
import {Event} from "../model/event"; 
export class EventBookingFormContainerProps { 
  eventID: string; 
  eventServiceURL: string; 
  bookingServiceURL: string; 
} 
export class EventBookingFormContainerState { 
  state: "loading"|"ready"|"saving"|"done"|"error"; 
  event?: Event; 
} 
```

`EventBookingFormContainer`将需要对事件服务和预订服务进行 AJAX 调用。当创建这个组件的新实例时，它将通过其属性传递一个事件 ID，然后使用该 ID 从事件服务加载相应的事件数据到组件的状态中。

加载事件数据是我们可以在接下来定义的组件构造函数中做的事情：

```go
export class EventBookingFormContainer
  extends React.Component<EventBookingFormContainerProps,  EventBookingFormContainerState> { 
  constructor(p: EventBookingFormContainerProps) { 
    super(p); 

    this.state = {state: "loading"}; 

    fetch(p.eventServiceURL + "/events/" + p.eventID) 
      .then<Event>(response => response.json()) 
      .then(event => { 
        this.setState({ 
          state: "ready", 
          event: event 
        }) 
      }); 
  } 
} 
```

现在，我们可以为这个组件添加一个`render`方法，一旦事件被加载，就会呈现实际的预订表单：

```go
render() { 
  if (this.state.state === "loading") { 
    return <div>Loading...</div>; 
  } 

  if (this.state.state === "saving") { 
    return <div>Saving...</div>; 
  } 

  if (this.state.state === "done") { 
    return <div className="alert alert-success"> 
      Booking completed! Thank you! 
    </div> 
  } 

  if (this.state.state === "error" || !this.state.event) { 
    return <div className="alert alert-danger"> 
      Unknown error! 
    </div> 
  } 

  return <EventBookingForm event={this.state.event} 
onSubmit={seats => this.handleSubmit(seats)} /> 
} 
```

这个`render()`方法基本上涵盖了组件状态的所有可能变体，然后打印相应的状态消息。当事件成功加载时，实际的`EventBookingForm`就会被呈现出来。

最后，我们需要实现`handleSubmit`方法：

```go
private handleSubmit(seats: number) { 
  const url = this.props.bookingServiceURL + "/events/" + this.eventID + "/bookings"; 
  const payload = {seats: seats}; 

  this.setState({ 
    event: this.state.event, 
    state: "saving" 
  }); 

  fetch(url, {method: "POST", body: JSON.stringify(payload)}) 
    .then(response => { 
      this.setState({ 
        event: this.state.event, 
        state: response.ok ? "done" : "error" 
      }); 
    }) 
} 
```

这结束了我们对预订表单的工作。到目前为止，我们只错过了一件小事——还没有办法访问这个表单。让我们现在修正这个疏忽。

首先，在`index.tsx`文件中添加一个新的路由，更确切地说，在`App`组件的`render`方法中：

```go
render() { 
  const eventList = () => <EventListContainer eventServiceURL="http://localhost:8181" />; 
  const eventBooking = ({match}: any) => 
    <EventBookingFormContainer eventID={match.params.id} 
      eventServiceURL="http://localhost8181" 
      bookingServiceURL="http://localhost:8282" />; 

  return <Router> 
    <div className="container"> 
      <h1>My Events</h1> 

      <Route exact path="/" component={eventList} /> 
      <Route path="/events/:id/book" component={eventBooking} /> 
    </div> 
  </Router> 
} 
```

在这个代码示例中，你可以看到多个内容。首先，我们声明了一个新的本地组件`eventBooking`，它基本上返回一个带有一些默认参数的`EventBookingFormContainer`组件。这个组件将被传递一个带有`match`属性的 prop 对象（参数声明中的花括号是所谓的**解构赋值**）。这个 match 对象包含了前面示例中声明的`/events/:id/book`路由的路由参数。这允许我们将事件 ID 作为路由参数包含进去（例如，`localhost:8080/#/events/58d543209cdd4128c06e59db/book`）。

此外，为了使这段代码工作，我们假设您已经从第四章中获得了一个运行并监听在本地 TCP 端口`8282`上的预订服务的实例，*使用消息队列的异步微服务架构*。

最后，我们需要添加一个按钮，允许用户实际到达这个路由。为此，我们将修改本章前面部分中创建的`src/component/event_list_item.tsx`文件中的`EventListItem`组件。我们将使用您之前使用过的`react-router-dom`包中的`Link`组件：

```go
import {Link} from "react-router-dom"; 
// ... 

export class EventListItem extends React.Component<EventListItemProps, {}> { 
  render() { 
    const start = new Date(this.props.event.StartDate * 1000); 
    const end = new Date(this.props.event.EndDate * 1000); 

    return <tr> 
      <td>{this.props.event.Name}</td> 
      <td>{this.props.event.Location.Name}</td> 
      <td>{start.toLocaleDateString()}</td> 
      <td>{end.toLocaleDateString()}</td> 
      <td> 
        <Link to={`/events/${this.props.event.ID}/book`}> 
          Book now! 
        </Link> 
      </td> 
    </tr> 
  } 
} 
```

在您的前端应用程序中，您现在将看到一个名为“立即预订！”的额外按钮：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/4be3b4b9-3be5-412e-a5c8-484e30221a82.png)

立即预订！按钮

活动列表中的`EventistItem`组件现在包含每个活动预订表单的链接。点击其中一个按钮后，应用程序将链接到相应活动的实际预订表单：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/bd606b09-37e8-4d93-958e-f6eb9d91e2a1.png)

活动预订表单的实际操作

请注意包含活动 ID 的 URL。由于我们已经构建了`EventBookingFormContainer`，它在构建时从活动服务加载活动数据，现在甚至可以使用这个 URL 直接在浏览器中打开。React 路由将立即打开预订表单，然后从活动服务加载活动数据。这使您可以直接在 React 应用程序中打开子路由，甚至共享或收藏这些 URL。

# 摘要

在本章中，我们为您展示了使用 React 进行前端开发的一瞥。当然，我们只是触及了 React 框架可能性的冰山一角。在实际的现实世界应用中，我们仍然需要为前端应用程序添加相当多的功能，才能真正完成（例如，我们需要添加一些琐碎的东西，比如用户注册和更复杂的结账流程）。

到目前为止，我们大部分时间都在做实际的编程，既在后端使用 Go 语言，又在前端使用 TypeScript。然而，软件开发不仅仅是编程。在接下来的几章中，我们将关注应用程序的部署。这将包括后端服务（例如在之前章节中构建的活动和预订服务），还有持久性和消息服务（例如数据库或消息队列）。为此，我们将研究现代容器技术以及如何将其部署到云端。敬请关注。


# 第六章：在容器中部署您的应用程序

在过去的几章中，我们专注于我们的 Go 应用程序的实际开发。然而，软件工程不仅仅是编写代码。通常情况下，您还需要关注如何将应用程序部署到其运行时环境中的问题。特别是在微服务架构中，每个服务可能构建在完全不同的技术堆栈上，部署很快就会变成一个挑战。

当您部署使用不同技术的服务（例如，当您有使用 Go、Node.js 和 Java 编写的服务时），您需要提供一个环境，其中所有这些服务实际上可以运行。使用传统虚拟机或裸机服务器，这可能会变得非常麻烦。即使现代云提供商可以快速生成和处理虚拟机，维护所有可能类型服务的基础设施也会成为一个运营挑战。

这就是现代容器技术（如**Docker**或**RKT**）的亮点所在。使用容器，您可以将应用程序及其所有依赖项打包到容器映像中，然后使用该映像快速生成在任何可以运行这些容器的服务器上运行您的应用程序的容器。需要在服务器上运行的唯一软件（无论是虚拟化还是裸机）是容器运行时环境（通常是 Docker 或 RKT）。

在本章中，我们将向您展示如何将我们在过去几章中构建的 MyEvents 应用程序打包成容器映像，并如何部署这些映像。由于我们的设想很大，我们还将研究诸如**Kubernetes**之类的集群管理器，它允许您一次在许多服务器上部署容器，从而使您的应用程序部署更具弹性和可伸缩性。

在本章中，我们将涵盖以下主题：

+   使用 Docker 构建和运行容器映像

+   使用 Docker Compose 设置复杂的多容器应用程序

+   使用 Kubernetes 的容器云基础设施

# 什么是容器？

诸如 Docker 之类的容器技术使用现代操作系统提供的隔离功能，例如 Linux 中的**命名空间**和**控制组**（**cgroups**）。使用这些功能允许操作系统在很大程度上隔离多个运行中的进程。例如，容器运行时可能会使用两个完全独立的文件系统命名空间或使用网络命名空间来提供两个完全独立的网络堆栈。除了命名空间，cgroups 还可以用于确保每个进程不会使用超过先前分配的资源量（例如 CPU 时间、内存或 I/O 和网络带宽）。

与传统虚拟机相比，容器完全在主机环境的操作系统中运行；没有虚拟化的硬件和操作系统在其中运行。此外，在许多容器运行时中，您甚至没有在常规操作系统中找到的所有典型进程。例如，Docker 容器通常不会像常规 Linux 系统那样具有 init 进程；相反，容器中的根进程（PID 1）将是您的应用程序（此外，由于容器只存在于其**PID 1**进程存在的时间，一旦您的应用程序存在，它就会停止存在）。

当然，这并不适用于所有容器运行时。例如，LXC 将在容器中为您提供完整的 Linux 系统（至少是用户空间的部分），包括 PID 1 作为 init 进程。

大多数容器运行时还具有**容器镜像**的概念。这些镜像包含预打包的文件系统，可以从中生成新的容器。许多基于容器的部署实际上使用容器镜像作为部署工件，其中实际的构建工件（例如，编译的 Go 二进制文件、Java 应用程序或 Node.js 应用程序）与其运行时依赖项一起打包（对于编译的 Go 二进制文件来说，依赖项并不多；但是对于其他应用程序来说，容器镜像可能包含 Java 运行时、Node.js 安装或应用程序工作所需的其他任何内容）。为您的应用程序拥有一个容器镜像也可以帮助使您的应用程序具有可伸缩性和弹性，因为很容易从您的应用程序镜像中生成新的容器。

诸如 Docker 之类的容器运行时还倾向于将容器视为**不可变**（意味着容器通常在启动后不会以任何方式更改）。在容器中部署应用程序时，部署新版本应用程序的典型方式是构建一个新的容器镜像（其中包含更新版本的应用程序），然后从该新镜像创建一个新的容器，并删除运行旧版本应用程序的容器。

# Docker 简介

目前，应用程序容器运行时的事实标准是**Docker**，尽管还有其他运行时，例如 RKT（发音为 rocket）。在本章中，我们将专注于 Docker。但是，许多容器运行时是可互操作的，并建立在共同的标准上。例如，RKT 容器可以轻松地从 Docker 镜像生成。这意味着即使您决定使用 Docker 镜像部署应用程序，也不会陷入供应商锁定。

# 运行简单的容器

我们之前在第四章中使用 Docker 快速设置了 RabbitMQ 和 Kafka 消息代理，但是我们没有详细介绍 Docker 的工作原理。我们假设您已经在本地机器上安装了可用的 Docker。如果没有，请查看官方安装说明，了解如何在您的操作系统上安装 Docker：[`docs.docker.com/engine/installation/`](https://docs.docker.com/engine/installation/)。

要测试您的 Docker 安装是否正常工作，请在命令行上尝试以下命令：

```go
$ docker container run --rm hello-world 
```

上述命令使用了 Docker 1.13 中引入的新 Docker 命令结构。如果您使用的是较旧版本的 Docker，请使用`docker run`而不是`docker container run`。您可以使用`docker version`命令测试当前的 Docker 版本。此外，请注意，Docker 在 1.13 版本之后改变了其版本方案，因此 1.13 之后的下一个版本将是 17.03。

Docker run 命令遵循`docker container run [flags...] [image name] [arguments...]`模式。在这种情况下，`hello-world`是要运行的镜像的名称，`--rm`标志表示容器在完成运行后应立即被删除。运行上述命令时，您应该会收到类似以下截图中的输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/c105a19e-13ea-4866-b495-8bd31540f1b4.png)

docker container run 输出

实际上，`docker run`命令在这里做了多件事情。首先，它检测到`hello-world`镜像在本地机器上不存在，并从官方 Docker 镜像注册表下载了它（如果再次运行相同的命令，您会注意到镜像不会被下载，因为它已经存在于本地机器上）。

然后它从刚刚下载的`hello-world`镜像创建了一个新的容器，并启动了该容器。容器镜像只包含一个小程序，该程序将一些文本打印到命令行，然后立即退出。

记住，Docker 容器没有 init 系统，通常只有一个在其中运行的进程。一旦该进程终止，容器将停止运行。由于我们使用`--rm`标志创建了容器，Docker 引擎在容器停止运行后也会自动删除容器。

接下来，让我们做一些更复杂的事情。执行以下命令：

```go
$ docker container run -d --name webserver -p 80:80 nginx 
```

这个命令将下载`nginx`镜像并从中生成一个新的容器。与`hello-world`镜像相比，这个镜像将运行一个无限时间的 Web 服务器。为了不让你的 shell 无限期地阻塞，使用`-d`标志（代表`--detach`）在后台启动新的容器。`--name`标志负责为新容器指定一个实际的名称（如果省略，容器将生成一个随机名称）。

默认情况下，在容器中运行的**NGINX** Web 服务器监听 TCP 端口 80。然而，每个 Docker 容器都有自己独立的网络堆栈，所以你不能通过导航到`http://localhost`来访问这个端口。`-p 80:80`标志告诉 Docker 引擎将容器的 TCP 端口 80 转发到 localhost 的端口 80。要检查容器是否实际在运行，运行以下命令：

```go
$ docker container ls 
```

前面的命令列出了所有当前运行的容器，它们所创建的镜像，以及它们的端口映射。你应该会收到类似以下截图的输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/a55cd8f5-2137-449c-bc44-e91a42579439.png)

docker 容器 ls 输出

当容器运行时，你现在可以通过`http://localhost`访问你刚刚启动的 Web 服务器。

# 构建你自己的镜像

到目前为止，你已经使用了来自 Docker Hub 的公开可用的预制镜像，比如`nginx`镜像（或者第四章中的 RabbitMQ 和 Spotify/Kafka 镜像，*使用消息队列的异步微服务架构*）。然而，使用 Docker，构建自己的镜像也很容易。通常，Docker 镜像是从**Dockerfile**构建的。Dockerfile 是一种新 Docker 镜像的构建手册，描述了应该如何从给定的基础镜像构建 Docker 镜像。由于从完全空的文件系统开始（即*没有 shell 或标准库*）很少有意义，因此镜像通常是在包含流行 Linux 发行版用户空间工具的发行版镜像上构建的。流行的基础镜像包括 Ubuntu、Debian 或 CentOS。

让我们构建一个简短的`Dockerfile`示例。为了演示目的，我们将构建自己版本的`hello-world`镜像。为此，创建一个新的空目录，并创建一个名为`Dockerfile`的新文件，内容如下：

```go
FROM debian:jessie 
MAINTAINER You <you@example.com> 

RUN echo 'Hello World' > /hello.txt 
CMD cat /hello.txt 
```

以`FROM`开头的行表示你正在构建自定义镜像的基础镜像。它总是需要作为`Dockerfile`的第一行。`MAINTAINER`语句只包含元数据。

`RUN`语句在构建容器镜像时执行（这意味着最终容器镜像将在其文件系统中有一个`/hello.txt`文件，内容为`Hello World`）。一个`Dockerfile`可能包含许多这样的`RUN`语句。

相比之下，`CMD`语句在从镜像创建的容器运行时执行。这里指定的命令将是从镜像创建的容器的第一个和主要进程（PID 1）。

你可以使用`docker image build`命令（在 1.13 版本之前的版本中使用`docker build`）来构建实际的 Docker 镜像，如下所示：

```go
$ docker image build -t test-image .
```

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/cb54a379-ad3a-435c-808a-f90e39cd9075.png)

docker 镜像构建输出

`-t test-image`标志包含你的新镜像应该得到的名称。构建完镜像后，你可以使用`docker image ls`命令找到它：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/6834320f-4f42-402d-976f-cef8450e908f.png)

docker 镜像 ls 输出

使用`-t`指定的名称允许您使用已知的`docker container run`命令从前面的镜像创建和运行新的容器：

```go
$ docker container run --rm test-image
```

与以前一样，这个命令将创建一个新的容器（这次是从我们新创建的镜像），启动它（实际上是启动`Dockerfile`中`CMD`语句指定的命令），然后在命令完成后删除容器（感谢`--rm`标志）。

# 网络容器

通常，您的应用程序由多个相互通信的进程组成（从相对简单的情况，如应用服务器与数据库通信，到复杂的微服务架构）。当使用容器管理所有这些进程时，通常每个进程都有一个容器。在本节中，我们将看看如何让多个 Docker 容器通过它们的网络接口相互通信。

为了实现容器之间的通信，Docker 提供了网络管理功能。命令行允许您创建新的虚拟网络，然后将容器添加到这些虚拟网络中。同一网络中的容器可以相互通信，并通过 Docker 内置的 DNS 服务器解析它们的内部 IP 地址。

让我们通过使用`docker network create`命令在 Docker 中创建一个新网络来测试一下：

```go
$ docker network create test
```

之后，您将能够通过运行`docker network ls`来看到新的网络：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/827535c6-bac6-4153-9588-2900e0d82ac0.png)

docker 网络 ls 输出

创建了一个新网络后，您可以将容器连接到这个网络。首先，从`nginx`镜像创建一个新容器，并使用`--network`标志将其附加到测试网络：

```go
$ docker container run -d --network=test --name=web nginx 
```

接下来，在相同的网络中创建一个新的容器。由于我们已经启动了一个 web 服务器，我们的新容器将包含一个 HTTP 客户端，我们将使用它来连接到我们的新 web 服务器（请注意，我们没有像之前那样使用`-p`标志将容器的 HTTP 端口绑定到本地主机）。为此，我们将使用适当的/curl 镜像。这是一个基本上包含了 cURL 命令行实用程序的容器化版本的镜像。由于我们的 web 服务器容器的名称为 web，我们现在可以简单地使用该名称来建立网络连接：

```go
$ docker container run --rm --network=test appropriate/curl http://web/
```

这个命令将简单地将 web 服务器的索引页面打印到命令行：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/4dd1c98a-6d10-4638-855e-f7855e635eba.png)

docker 容器运行输出

这表明从适当的/curl 镜像创建的 cURL 容器能够通过 HTTP 访问 web 容器。在建立连接时，您可以简单地使用容器的名称（在本例中为*web*）。Docker 将自动将此名称解析为容器的 IP 地址。

掌握了 Docker 镜像和网络的知识，现在可以将 MyEvents 应用程序打包成容器镜像并在 Docker 上运行。

# 使用卷

单个 Docker 容器通常存活时间很短。部署应用程序的新版本可能会导致删除多个容器并生成新的容器。如果您的应用程序在云环境中运行（我们将在本章后面看到基于云的容器环境），您的容器可能会受到节点故障的影响，并将被重新调度到另一个云实例上。对于无状态应用程序（在我们的示例中，事件服务和预订服务），这是完全可以接受的。

然而，对于有状态的容器（在我们的示例中，这将是消息代理和数据库容器），这变得困难。毕竟，如果您删除一个 MongoDB 容器，并创建一个具有类似配置的新容器，那么数据库管理的实际数据将会丢失。这就是**卷**发挥作用的地方。

卷是 Docker 使数据持久化超出单个容器生命周期的方式。它们包含文件，独立于单个容器存在。每个卷可以被挂载到任意数量的容器中，允许您在容器之间共享文件。

为了测试这一点，使用`docker volume create`命令创建一个新卷：

```go
$ docker volume create test 
```

这将创建一个名为*test*的新卷。您可以使用`docker volume ls`命令再次找到这个卷：

```go
$ docker volume ls 
```

创建了一个卷后，您可以使用`docker container run`命令的`-v`标志将其挂载到容器中：

```go
$ docker container run --rm -v test:/my-volume debian:jessie 
/bin/bash -c "echo Hello > /my-volume/test.txt" 
```

这个命令创建一个新的容器，将测试卷挂载到`/my-volume`目录中。容器的命令将是一个创建`test.txt`文件的 bash shell。之后，容器将终止并被删除。

为了确保卷内的文件仍然存在，现在可以将此卷挂载到第二个容器中：

```go
$ docker container run -rm -v test:/my-volume debian:jessie 
cat /my-volume/test.txt
```

该容器将`test.txt`文件的内容打印到命令行。这表明测试卷仍然包含所有数据，即使最初填充数据的容器已经被删除。

# 构建容器

我们将从构建 MyEvents 应用程序的组件容器镜像开始。目前，我们的应用程序由三个组件组成——两个后端服务（事件和预订服务）和 React 前端应用程序。虽然前端应用程序本身不包含任何后端逻辑，但我们至少需要一个 Web 服务器将此应用程序提供给用户。这总共需要构建三个容器镜像。让我们从后端组件开始。

# 为后端服务构建容器

事件和预订服务都是编译为单个可执行二进制文件的 Go 应用程序。因此，在 Docker 镜像中不需要包含任何源文件甚至 Go 工具链。

在这一点上需要注意的是，您将需要为接下来的步骤编译 Go 应用程序的 Linux 二进制文件。在 macOS 或 Windows 上，调用`go build`时需要设置`GOOS`环境变量：

```go
$ GOOS=linux go build 
```

在 macOS 和 Linux 上，您可以使用`file`命令检查正确的二进制类型。对于 Linux 的`ELF`二进制文件，`file`命令应该打印类似以下的输出：

```go
$ file eventservice 
eventservice: ELF 64-bit executable, x86-64, version 1 (SYSV),  
statically linked, not stripped 
```

首先编译 Linux 二进制文件，分别用于事件服务和预订服务。

当您编译了这两个服务后，继续为事件服务定义 Docker 镜像构建过程。为此，在事件服务的根目录中创建一个名为`Dockerfile`的新文件：

```go
FROM debian:jessie 

COPY eventservice /eventservice 
RUN  useradd eventservice 
USER eventservice 

ENV LISTEN_URL=0.0.0.0:8181 
EXPOSE 8181 
CMD ["/eventservice"] 
```

这个 Dockerfile 包含了一些我们之前没有涉及的新语句。`COPY`语句将文件从主机的本地文件系统复制到容器镜像中。这意味着我们假设您在开始 Docker 构建之前已经使用`go build`构建了 Go 应用程序。`USER`命令导致所有后续的`RUN`语句和`CMD`语句以该用户身份运行（而不是 root）。`ENV`命令设置一个环境变量，将对应用程序可用。最后，`EXPOSE`语句声明从该镜像创建的容器将需要 TCP 端口`8181`。

继续使用`docker image build`命令构建容器镜像：

```go
$ docker image build -t myevents/eventservice .
```

接下来，向`bookingservice`添加一个类似的 Docker 文件：

```go
FROM debian:jessie 

COPY bookingservice /bookingservice 
RUN  useradd bookingservice 
USER bookingservice 

ENV LISTEN_URL=0.0.0.0:8181 
EXPOSE 8181 
CMD ["/bookingservice"] 
```

再次使用`docker image build`命令构建镜像：

```go
$ docker image build -t myevents/bookingservice .
```

为了测试我们的新镜像，现在可以生成相应的容器。但是，在启动实际应用程序容器之前，我们需要为这些容器和所需的持久性服务创建一个虚拟网络。事件和预订服务分别需要一个 MongoDB 实例和一个共享的 AMQP（或 Kafka）消息代理。

让我们从创建容器网络开始：

```go
$ docker network create myevents
```

接下来，将 RabbitMQ 容器添加到您的网络中：

```go
$ docker container run -d --name rabbitmq --network myevents 
rabbitmq:3-management
```

继续添加两个 MongoDB 容器：

```go
$ docker container run -d --name events-db --network myevents mongo 
$ docker container run -d --name bookings-db --network myevents mongo 
```

最后，您可以启动实际的应用程序容器：

```go
$ docker container run \ 
    --detach \ 
    --name events \ 
    --network myevents \ 
    -e AMQP_BROKER_URL=amqp://guest:guest@rabbitmq:5672/ \ 
    -e MONGO_URL=mongodb://events-db/events \ 
    -p 8181:8181 \ 
    myevents/eventservice 
$ docker container run \ 
    --detach \ 
    --name bookings \ 
    --network myevents \ 
    -e AMQP_BROKER_URL=amqp://guest:guest@rabbitmq:5672/ \ 
    -e MONGO_URL=mongodb://bookings-db/bookings \ 
    -p 8282:8181 \
    myevents/bookingservice 
```

注意端口映射。目前，两个服务都在 TCP 端口`8181`上监听其 REST API。只要这两个 API 在不同的容器中运行，这是完全有效的。但是，当将这些端口映射到主机端口（例如，用于测试目的）时，我们将会有一个端口冲突，我们通过将预订服务的端口`8181`映射到`8282`来解决这个问题。

另外，注意如何使用`-e`标志将环境变量传递到运行的容器中。例如，使用`MONGO_URL`环境变量，可以轻松地将两个应用程序容器连接到不同的数据库。

在启动了所有这些容器之后，您将能够从本地机器通过`http://localhost:8181`访问事件服务，通过`http://localhost:8282`访问预订服务。以下`docker container ls`命令现在应该显示您有五个正在运行的容器：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/ecbca662-2530-4267-a40b-8d8974f8304c.png)

docker container ls 输出

# 使用静态编译以获得更小的镜像

目前，我们正在构建我们的应用程序镜像，这些镜像是基于`debian:jessie`镜像的。这个镜像包含了典型的 Debian 安装的用户空间工具和库，大小约为 123MB（您可以使用`docker image ls`命令找到这一点）。再加上另外 10MB 用于编译的 Go 应用程序，每个生成的镜像大小约为 133MB（这并不意味着我们的事件服务和预订服务的两个镜像将共同占用 266MB 的磁盘空间。它们都是基于相同的基础镜像构建的，Docker 非常有效地优化了容器镜像的磁盘空间使用）。

然而，我们的应用程序并没有使用大部分这些工具和库，所以我们的容器镜像可以更小。通过这样做，我们可以优化本地磁盘空间的使用（尽管 Docker 引擎已经相当有效），优化从镜像仓库下载镜像时的传输时间，并减少对恶意用户的攻击面。

通常，编译的 Go 二进制文件几乎没有依赖性。您不需要任何运行时库或虚拟机，您在项目中使用的所有 Go 库都直接嵌入到生成的可执行文件中。但是，如果您在 Linux 上编译应用程序，Go 编译器将会将生成的二进制文件链接到一些 C 标准库，这些库通常在任何 Linux 系统上都可用。如果您在 Linux 上，可以通过使用`ldd`二进制文件并将其中一个已编译的 Go 二进制文件作为参数来轻松找出您的程序链接到了哪些库。如果您的二进制文件链接到 C 标准库，您将收到以下输出：

```go
$ ldd ./eventservice 
    linux-vdso.so.1 (0x00007ffed09b1000) 
    libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007fd523c36000) 
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fd52388b000) 
    /lib64/ld-linux-x86-64.so.2 (0x0000564d70338000)  
```

这意味着您的 Go 应用程序实际上需要这些 Linux 库来运行，您不能随意从镜像中删除它们以使其更小。

如果您在 Windows 或 macOS 上使用`GOOS=linux`环境变量交叉编译应用程序，您可能不会遇到这个问题。因为这些系统上的编译器无法访问 Linux 标准 C 库，它将默认产生一个没有任何依赖的静态链接二进制文件。当使用这样的二进制文件调用`ldd`时，将呈现以下输出：

```go
$ ldd ./eventservice 
    not a dynamic executable 
```

在 Linux 上，您可以通过为 Go 构建命令设置`CGO_ENABLED=0`环境变量来强制 Go 编译器创建静态链接的二进制文件：

```go
$ CGO_ENABLED=0 go build 
$ ldd ./eventservice 
    not a dynamic executable 
```

完全静态链接的二进制文件使您可以创建一个更小的容器镜像。现在，您可以使用*scratch*镜像而不是在`debian:jessie`上构建基础镜像。`scratch`镜像是一个特殊的镜像。它直接内置在 Docker Engine 中，您无法从 Docker Hub 下载它。`scratch`镜像的特殊之处在于它完全为空，没有一个文件——这意味着没有标准库，没有系统实用程序，甚至没有一个 shell。尽管这些特性通常使得 scratch 镜像难以使用，但它非常适合为静态链接应用程序构建最小的容器镜像。

按照以下方式更改事件服务的`Dockerfile`：

```go
FROM scratch 

COPY eventservice /eventservice 

ENV LISTEN_URL=0.0.0.0:8181 
EXPOSE 8181 
CMD ["/eventservice"] 
```

接下来，以类似的方式更改预订服务的`Dockerfile`。然后，使用前面的代码中的`docker image build`命令再次构建这两个容器镜像。之后，使用`docker image ls`命令验证您的镜像大小：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/2e70b403-4ec6-4fd8-a171-df7d4bee38b8.png)

docker image ls 输出

# 为前端构建容器

现在我们已经为后端应用程序构建了容器镜像，我们可以将注意力转向前端应用程序。由于该应用程序在用户的浏览器中运行，我们实际上不需要为其提供容器化的运行时环境。但我们确实需要一种向用户交付应用程序的方式。由于整个应用程序由一些 HTML 和 JavaScript 文件组成，我们可以构建一个包含简单 NGINX Web 服务器的容器镜像，用于向用户提供这些文件。

为此，我们将在`nginx:1.11-alpine`镜像上构建。该镜像包含了一个基于 Alpine Linux 构建的最小版本的 NGINX Web 服务器。Alpine 是一个针对小尺寸进行优化的 Linux 发行版。整个`nginx:1.11-alpine`镜像的大小仅为 50MB。

将以下`Dockerfile`添加到前端应用程序目录中：

```go
FROM nginx:1.11-alpine 

COPY index.html /usr/share/nginx/html/ 
COPY dist /usr/share/nginx/html/dist/ 
COPY node_modules/bootstrap/dist/css/bootstrap.min.css /usr/share/nginx/html/node_modules/bootstrap/dist/css/bootstrap.min.css 
COPY node_modules/react/umd/react.production.min.js /usr/share/nginx/html/node_modules/react/umd/react.production.min.js
COPY node_modules/react-dom/umd/react-dom.production.min.js /usr/share/nginx/html/node_modules/react-dom/umd/react-dom.production.min.js
COPY node_modules/promise-polyfill/promise.min.js /usr/share/nginx/html/node_modules/promise-polyfill/promise.min.js 
COPY node_modules/whatwg-fetch/fetch.js /usr/share/nginx/html/node_modules/whatwg-fetch/fetch.js 
```

显然，我们的 Web 服务器需要为用户提供`index.html`和`dist/bundle.js`中编译的 Webpack 捆绑文件的服务，因此这些文件将使用`COPY`复制到容器镜像中。然而，从`node_modules/`目录中安装的所有依赖项中，我们的用户只需要一个非常特定的子集。因此，我们将这五个文件明确地复制到容器镜像中，而不是仅使用`COPY`复制整个`node_modules/`目录。

在实际构建容器镜像之前，请确保您的应用程序有最新的 Webpack 构建和所有安装的依赖项。您还可以使用`-p`标志来触发 Webpack 创建一个针对大小进行优化的生产构建：

```go
$ webpack -p 
$ npm install 
```

之后，构建您的容器：

```go
$ docker container build -t myevents/frontend . 
```

现在，您可以使用以下命令启动此容器：

```go
$ docker container run --name frontend -p 80:80 myevents/frontend
```

请注意，在这种情况下，我们没有传递`--network=myevents`标志。这是因为前端容器实际上不需要直接与后端服务通信。所有通信都是由用户的浏览器发起的，而不是从实际的前端容器内部发起的。

`-p 80:80`标志将容器的 TCP 端口 80 绑定到本地 TCP 端口 80。这样，您现在可以在浏览器中打开`http://localhost`并查看 MyEvents 前端应用程序。如果您仍然在运行前几节的后端容器，则应用程序应该可以直接使用。

# 使用 Docker Compose 部署应用程序

到目前为止，从现有的容器镜像部署 MyEvents 应用程序实际上涉及了许多`docker container run`命令。尽管这对于测试来说效果还不错，但一旦您的应用程序在生产环境中运行时，特别是当您想要部署更新或扩展应用程序时，这将变得很繁琐。

这个问题的一个可能解决方案是**Docker Compose**。Compose 是一个工具，允许您以声明方式描述由多个容器组成的应用程序（在本例中，是一个描述构建应用程序的组件的 YAML 文件）。

Docker Compose 是常规 Docker 安装包的一部分，因此如果你在本地机器上安装了 Docker，你也应该有 Docker Compose 可用。你可以通过在命令行上调用以下命令来轻松测试：

```go
$ docker-compose -v 
```

如果你的本地机器上没有 Compose，请查阅[`docs.docker.com/compose/install`](https://docs.docker.com/compose/install)上的安装手册，详细描述如何设置 Compose。

每个 Compose 项目都由一个`docker-compose.yml`文件描述。Compose 文件将包含你的应用程序所需的所有容器、网络和卷的描述。Compose 将尝试通过创建、删除、启动或停止容器等方式，将 Compose 文件中表达的期望状态与本地 Docker 引擎的实际状态协调。

在你的项目目录的根目录创建一个包含以下内容的文件：

```go
version: "3" 
networks: 
  myevents: 
```

在 Compose 文件中注意`version: "3"`的声明。Compose 支持多种声明格式，最近的版本是版本 3。在一些文档、示例或开源项目中，你很可能会遇到为旧版本编写的 Compose 文件。根本不声明版本的 Compose 文件被解释为版本 1 文件。

现在，上述 Compose 文件仅仅声明你的应用程序需要一个名为`myevents`的虚拟网络。然而，你可以使用 Compose 通过运行以下命令来协调所需的状态（必须存在一个名为`myevents`的网络）：

```go
$ docker-compose up 
```

现在，上述命令将打印一个警告消息，因为我们声明了一个没有被任何容器使用的容器网络。

容器在 Compose 文件中声明在`services`下。每个容器都有一个名称（在 YAML 结构中用作键）和各种属性（例如要使用的镜像）。让我们继续向 Compose 文件中添加一个新的容器：

```go
version: "3" 
networks: 
  myevents:

services: 
  rabbitmq: 
    image: rabbitmq:3-management 
    ports: 
      - 15672:15672 
    networks: 
      - myevents 
```

这是你之前使用`docker container run -d --network myevents -p 15672:15672 rabbitmq:3-management`命令手动创建的 RabbitMQ 容器。

现在，你可以通过运行以下命令创建这个容器：

```go
$ docker-compose up -d 
```

`-d`标志与 docker container run 命令具有相同的效果；它将导致容器在后台启动。

一旦 RabbitMQ 容器开始运行，你实际上可以随意多次调用`docker-compose up`。由于已经运行的 RabbitMQ 容器与 Compose 文件中的规范匹配，Compose 不会采取任何进一步的操作。

让我们继续向 Compose 文件中添加两个 MongoDB 容器：

```go
version: "3" 
networks: 
  - myevents

services: 
  rabbitmq: #... 

  events-db: 
    image: mongo 
    networks: 
      - myevents 

  bookings-db: 
    image: mongo 
    networks: 
      - myevents 
```

再次运行`docker-compose up -d`。Compose 仍然不会触及 RabbitMQ 容器，因为它仍然符合规范。但是，它将创建两个新的 MongoDB 容器。

接下来，我们可以添加两个应用程序服务：

```go
version: "3" 
networks: 
  - myevents

services: 
  rabbitmq: #... 
  events-db: #... 
  bookings-db: #... 
  events: 
    build: path/to/eventservice 
    ports: 
      - "8181:8181" 
    networks: 
      - myevents 
    environment: 
      - AMQP_BROKER_URL=amqp://guest:guest@rabbitmq:15672/ 
      - MONGO_URL=mongodb://events-db/events 
  bookings: 
    build: path/to/bookingservice 
    ports: 
      - "8282:8181" 
    networks: 
      - myevents 
    environment: 
      - AMQP_BROKER_URL=amqp://guest:guest@rabbitmq:15672/ 
      - MONGO_URL=mongodb://bookings-db/bookings 
```

注意，我们没有为这两个容器指定`image`属性，而是使用了`build`属性。这将导致 Compose 根据需要从各自目录中的 Dockerfile 实际构建这些容器的镜像。

重要的是要注意，Docker 构建不会编译你的 Go 二进制文件。相反，它将依赖于它们已经存在。在第九章 *持续交付*中，你将学习如何使用 CI 流水线来自动化这些构建步骤。

你也可以使用`docker-compose`命令单独触发这个流水线的各个步骤。例如，使用`docker-compose pull`从 Docker Hub 下载 Compose 文件中使用的所有镜像的最新版本：

```go
$ docker-compose pull 
```

对于不使用预定义镜像的容器，使用`docker-compose build`重新构建所有镜像：

```go
$ docker-compose build 
```

使用另一个`docker-compose up -d`创建新的容器。

确保已停止任何先前创建的可能绑定到 TCP 端口 8181 或 8282 的容器。使用`docker container ls`和`docker container stop`命令来定位并停止这些容器。

您还可以使用`docker-compose ps`命令来查看与当前 Compose 项目关联的当前正在运行的容器的概述：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/bbe15948-950f-4e04-948f-1eab0d05b679.png)

docker-compose ps 输出

最后，将前端应用程序添加到 Compose 文件中：

```go
version: "3" 
networks: 
  - myevents

services: 
  rabbitmq: #... 
  events-db: #... 
  bookings-db: #... 
  events: #... 
  bookings: #... 

  frontend: 
    build: path/to/frontend 
    ports: 
      - "80:80" 
```

正如您在本节中学到的，Docker Compose 使您能够以声明方式描述应用程序的架构，从而可以在支持 Docker 实例的任何服务器上轻松部署和更新应用程序。

到目前为止，我们一直在单个主机上工作（很可能是您的本地机器）。这对开发来说很好，但是对于生产设置，您需要考虑将应用程序部署到远程服务器上。此外，由于云架构都是关于规模的，接下来的几节中，我们还将看看如何在规模上管理容器化应用程序。

# 发布您的镜像

现在，您可以从应用程序组件构建容器镜像，并在本地机器上从这些镜像运行容器。但是，在生产环境中，构建容器镜像的机器很少是您将在其上运行它的机器。要实际能够将应用程序部署到任何云环境，您需要一种将构建的容器镜像分发到任意数量的主机的方法。

这就是容器注册表发挥作用的地方。实际上，在本章的早些时候，您已经使用过一个容器注册表，也就是 Docker Hub。每当您使用本地机器上不存在的 Docker 镜像（比如，例如`nginx`镜像），Docker 引擎将从 Docker Hub 将此镜像拉到您的本地机器上。但是，您也可以使用诸如 Docker Hub 之类的容器注册表来发布自己的容器镜像，然后从另一个实例中拉取它们。

在 Docker Hub（您可以通过浏览器访问[`hub.docker.com`](https://hub.docker.com)），您可以注册为用户，然后上传自己的镜像。为此，请在登录后单击创建存储库，然后选择一个新名称作为您的镜像。

要将新镜像推送到您新创建的存储库中，您首先需要在本地机器上使用您的 Docker Hub 帐户登录。使用以下`docker login`命令：

```go
$ docker login 
```

现在，您将能够将镜像推送到新的存储库中。镜像名称将需要以您的 Docker Hub 用户名开头，后面跟着一个斜杠：

```go
$ docker image build -t martinhelmich/test . 
$ docker image push martinhelmich/test 
```

默认情况下，推送到 Docker Hub 的镜像将是公开可见的。Docker Hub 还提供了推送私有镜像作为付费功能的可能性。只有在成功使用`docker login`命令进行身份验证后，才能拉取私有镜像。

当然，您不必使用 Docker Hub 来分发自己的镜像。还有其他提供者，比如 Quay（[`quay.io`](https://quay.io/)），所有主要的云提供商也提供了托管容器注册表的可能性。但是，当使用除 Docker Hub 之外的注册表时，一些前面的命令将略有变化。首先，您将不得不告诉`docker login`命令您将要登录的注册表：

```go
$ docker login quay.io 
```

此外，您想要推送的容器镜像不仅需要以您的 Docker Hub 用户名开头，还需要以整个注册表主机名开头：

```go
$ docker image build -t quay.io/martinhelmich/test .
$ docker image push quay.io/martinhelmich/test 
```

如果您不想将您的容器镜像委托给第三方提供者，您还可以部署自己的容器注册表。恰当地，有一个 Docker 镜像可以让您快速设置自己的注册表：

```go
$ docker volume create registry-images 
$ docker container run \ 
    --detach \ 
    -p 5000:5000 \ 
    -v registry-images:/var/lib/registry \ 
    --name registry \ 
    registry:2.6.1 
```

这将设置一个可在`http://localhost:5000`访问的容器注册表。您可以像对待其他第三方注册表一样对待它：

```go
$ docker image build -t localhost:5000/martinhelmich/test . 
$ docker image push localhost:5000/martinhelmich/test 
```

拥有一个在`localhost:5000`上监听的私有容器注册表对于开发来说是可以的，但是对于生产设置，您将需要额外的配置选项。例如，您将需要为您的注册表配置 TLS 传输加密（默认情况下，Docker 引擎将拒绝除 localhost 以外的任何非加密 Docker 注册表），您还需要设置身份验证（除非您明确打算运行一个公开访问的容器注册表）。查看注册表的官方部署指南，了解如何设置加密和身份验证：[`docs.docker.com/registry/deploying/`](https://docs.docker.com/registry/deploying/)。

# 将您的应用程序部署到云端

在本章结束时，我们将看看如何将容器化的应用部署到云环境中。

容器引擎，比如 Docker，允许您在隔离的环境中提供多个服务，而无需为单独的服务提供独立的虚拟机。然而，与典型的云应用一样，我们的容器架构需要易于扩展，并且对故障有弹性。

这就是容器编排系统（如 Kubernetes）发挥作用的地方。这些系统允许您在整个主机集群上部署容器化的应用程序。它们允许轻松扩展，因为您可以轻松地向现有集群添加新主机（之后新的容器工作负载可能会自动安排在它们上面），并且使您的系统具有弹性；节点故障可以被快速检测到，这允许在其他地方启动那些节点上的容器以确保它们的可用性。

# Kubernetes 简介

最著名的容器编排器之一是 Kubernetes（希腊语意为*舵手*）。Kubernetes 是由谷歌最初开发的开源产品，现在由云原生计算基金会拥有。

以下图表显示了 Kubernetes 集群的基本架构：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/392103eb-b9ad-4cdc-9ccc-5413b070389c.png)

每个 Kubernetes 集群的中心组件是主服务器（当然，不一定是实际的单个服务器。在生产设置中，您通常会有多个配置为高可用性的主服务器）。主服务器将整个集群状态存储在端数据存储中。API 服务器是提供 REST API 的组件，可以被内部组件（如调度器、控制器或 Kubelet）和外部用户（您！）使用。调度器跟踪各个节点上的可用资源（如内存和 CPU 使用情况），并决定集群中新容器应该在哪个节点上安排。控制器是管理高级概念的组件，如复制控制器或自动缩放组。

Kubernetes 节点是由主服务器管理的实际应用程序容器启动的地方。每个节点运行一个 Docker 引擎和一个**Kubelet**。Kubelet 连接到主服务器的 REST API，并负责实际启动调度器为该节点安排的容器。

在 Kubernetes 中，容器被组织在 Pod 中。Pod 是 Kubernetes 的最小调度单元，由一个或多个 Docker 容器组成。Pod 中的所有容器都保证在同一主机上运行。每个 Pod 将接收一个唯一的可路由 IP 地址，该地址在整个集群内是唯一的（这意味着在一个主机上运行的 Pod 将能够通过它们的 IP 地址与在其他节点上运行的 Pod 进行通信）。

Kube Proxy 是确保用户实际可以访问您的应用程序的组件。在 Kubernetes 中，您可以定义将多个 Pod 分组的服务。Kube Proxy 为每个服务分配一个唯一的 IP 地址，并将网络流量转发到服务匹配的所有 Pod。这样，Kube Proxy 还实现了一个非常简单但有效的负载平衡，当多个应用程序实例在多个 Pod 中运行时。

您可能已经注意到 Kubernetes 的架构非常复杂。设置 Kubernetes 集群是一项具有挑战性的任务，在本书中我们不会详细介绍。对于本地开发和测试，我们将使用 Minikube 工具，在您的本地机器上自动创建一个虚拟化的 Kubernetes 环境。当您在公共云环境中运行应用程序时，您还可以使用工具为您自动设置一个生产就绪的 Kubernetes 环境。一些云提供商甚至为您提供托管的 Kubernetes 集群（例如，**Google 容器引擎**和**Azure 容器服务**都是基于 Kubernetes 构建的）。

# 使用 Minikube 设置本地 Kubernetes

要开始使用 Minikube，您需要在本地机器上安装三个工具：Minikube 本身（将在您的机器上设置虚拟 Kubernetes 环境），VirtualBox（将用作虚拟化环境）和 kubectl（用于与 Kubernetes 一起工作的命令行客户端）。尽管在本示例中我们使用 Minikube，但我们在接下来的章节中展示的每个 kubectl 命令几乎都适用于几乎每个 Kubernetes 集群，无论它是如何设置的。

首先设置 VirtualBox。为此，请从官方下载页面[`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads)下载安装程序，并按照您的操作系统的安装说明进行操作。

接下来，下载最新版本的 Minikube。您可以在[`github.com/kubernetes/minikube/releases`](https://github.com/kubernetes/minikube/releases)找到所有版本（在撰写本文时，最新版本为 0.18.0）。同样，按照您的操作系统的安装说明进行操作。或者，使用以下命令快速下载并设置 Minikube（分别将`linux`替换为`darwin`或`windows`）：

```go
$ curl -Lo minikube https://storage.googleapis.com/minikube/releases/v0.18.0/minikube-linux-amd64 && chmod +x minikube && sudo mv minikube /usr/local/bin/ 
```

最后，设置 kubectl。您可以在以下位置找到安装说明：[`kubernetes.io/docs/tasks/kubectl/install`](https://kubernetes.io/docs/tasks/kubectl/install)。或者，使用以下命令（根据需要将`linux`替换为`darwin`或`windows`）：

```go
curl -LO https://storage.googleapis.com/kubernetes-release/release/1.6.1/bin/linux/amd64/kubectl && chmod +x kubectl && sudo mv kubectl /usr/local/bin 
```

在设置好所有要求之后，您可以使用`minikube start`命令启动本地 Kubernetes 环境：

```go
$ minikube start 
```

该命令将下载一个 ISO 镜像，然后从该镜像启动一个新的虚拟机，并安装各种 Kubernetes 组件。喝杯咖啡，如果这需要几分钟，不要感到惊讶：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/e2c578b1-67b9-475e-8318-1b47a0864fd6.png)

minikube start 输出

`minikube start`命令还会创建一个配置文件，用于使您可以在没有任何进一步配置的情况下使用 kubectl 与 minikube VM。您可以在主目录下的`~/.kube/config`中找到此文件。

测试整个设置是否按预期工作，请运行`kubectl get nodes`命令。该命令将打印出 Kubernetes 集群中所有节点的列表。在 Minikube 设置中，您应该只能看到一个节点：

```go
$ kubectl get nodes 
```

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/2259d431-8edc-496e-8ab7-8b073fe91bf1.png)

kubectl get nodes 输出

# Kubernetes 的核心概念

在深入了解 MyEvents 之前，让我们更仔细地看一下一些 Kubernetes 的核心概念。我们将首先创建一个包含简单 NGINX Web 服务器的新 Pod。

Kubernetes 资源（如 Pod 和服务）通常在 YAML 文件中定义，这些文件以声明方式描述了您的集群的期望状态（类似于您之前使用的 Docker Compose 配置文件）。对于我们的新 NGINX Pod，创建一个名为`nginx-pod.yaml`的新文件，放在您的本地文件系统的任何位置：

```go
apiVersion: v1 
kind: Pod 
metadata: 
  name: nginx-test 
spec: 
  containers: 
  - name: nginx 
    image: nginx 
    ports: 
      - containerPort: 80 
        name: http 
        protocol: TCP 
```

这个所谓的清单文件描述了你的新 Pod 应该是什么样子。在`metadata`部分，您可以设置基本的元数据，比如 Pod 的名称或任何额外的标签（我们以后会需要这些）。`spec`部分包含了 Pod 应该是什么样子的实际规范。正如你所看到的，`spec.containers`部分被格式化为一个列表；理论上，你可以在这里添加额外的容器，然后在同一个 Pod 中运行。

创建完这个文件后，使用`kubectl apply`命令创建 Pod：

```go
$ kubectl apply -f nginx-pod.yaml 
```

之后，您可以使用`kubectl get pods`命令验证您的 Pod 是否已成功创建。请注意，从`ContainerCreating`到`Running`状态可能需要几秒钟到几分钟的时间：

```go
$ kubectl get pods 
```

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/fcfee8cc-9752-48f7-b3ae-d564aec74df2.png)

kubectl get pods 输出

请注意，`kubectl`命令直接与 Kubernetes API 服务器通信（尽管在使用 Minikube 时，这并没有太大的区别，因为所有组件都在同一台虚拟机上运行），而不是与集群节点通信。理论上，您的 Kubernetes 集群可能由许多主机组成，Kubernetes 调度程序会自动选择最适合的主机来运行您的新 Pod。

有更多的事情可以为单个 Pod 配置。例如，您可能希望限制应用程序的内存或 CPU 使用。在这种情况下，您可以将以下设置添加到您新创建的 Pod 清单中：

```go
# ... 
spec: 
  containers: 
  - name: nginx 
    image: nginx 
    resources: 
      limits: 
        memory: 128Mi 
        cpu: 0.5 
    ports: # ... 
```

`resources.limits`部分将指示 Kubernetes 创建一个带有 128MB 内存限制和半个 CPU 核心的容器。

关于 Kubernetes Pod 的重要事情是，它们不是持久的。Pod 可能会在任何时候被终止，并且在节点失败时可能会丢失。因此，建议使用 Kubernetes 控制器（如部署控制器）为您创建 Pod。

在继续之前，使用`kubectl delete`命令删除您的 Pod：

```go
$ kubectl delete pod nginx-test 
```

接下来，创建一个新的`nginx-deployment.yaml`文件：

```go
apiVersion: apps/v1beta1 
kind: Deployment 
metadata: 
  name: nginx-deployment 
spec: 
  replicas: 2 
  template: 
    metadata: 
      labels: 
        app: nginx 
    spec: 
      containers: 
      - name: nginx 
        image: nginx 
        ports: 
        - containerPort: 80 
          name: http 
          protocol: TCP 
```

这个清单将为您创建一个所谓的部署控制器。部署控制器将确保在任何时候运行指定配置的给定数量的 Pod——在这种情况下，两个 Pod（在`spec.replicas`字段中指定）由`spec.template`字段描述（注意`spec.template`字段匹配我们之前已经编写的 Pod 定义，减去名称）。

与之前一样，使用`kubectl apply`命令创建部署：

```go
$ kubectl apply -f nginx-deployment.yaml 
```

使用`kubectl get pods`命令验证您的操作的成功。您应该注意到将安排两个 Pod（名称类似于`nginx-deployment-1397492275-qz8k5`）：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/24c3dc96-8f3e-4085-9ad2-16fea98b64b0.png)

kubectl get pods 输出

部署还有更多的功能。首先，尝试使用`kubectl delete`命令删除一个自动生成的 Pod（请记住，在您的机器上，您将有一个不同的 Pod 名称）：

```go
$ kubectl delete pod nginx-deployment-1397492275-qz8k5 
```

删除 Pod 后，再次调用`kubectl get pods`。您会注意到，部署控制器几乎立即创建了一个新的 Pod。

此外，您可能会决定您的应用程序的两个实例不足，您希望进一步扩展您的应用程序。为此，您可以简单地增加部署控制器的`spec.scale`属性。要增加（或减少）规模，您可以编辑现有的 YAML 文件，然后再次调用`kubectl apply`。或者，您可以直接使用`kubectl edit`命令编辑资源：

```go
$ kubectl edit deployment nginx-deployment 
```

特别是对于`spec.scale`属性，还有一个特殊的`kubectl scale`命令可以使用：

```go
$ kubectl scale --replicas=4 deployment/nginx-deployment 
```

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/0f53bd75-2285-45b3-ab56-5e01be6f9f7f.png)

kubectl get pods 输出

# 服务

目前，我们有四个运行的 NGINX 容器，但没有实际访问它们的方式。这就是服务发挥作用的地方。创建一个名为`nginx-service.yaml`的新 YAML 文件：

```go
apiVersion: v1 
kind: Service 
metadata: 
  name: nginx 
spec: 
  type: NodePort 
  selector: 
    app: nginx 
  ports: 
  - name: http 
    port: 80 
```

请注意，`spec.selector`属性与您在部署清单中指定的`metadata.labels`属性匹配。由部署控制器创建的所有 Pod 都将具有一组给定的标签（实际上只是任意的键/值映射）。服务的`spec.selector`属性现在指定了一个 Pod 应该具有哪些标签，以便被此服务识别。还要注意`type: NodePort`属性，这将在后面变得重要。

创建文件后，像往常一样使用`kubectl apply`来创建服务定义：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/b7f872bb-8f02-4beb-87a1-89a89edd01c0.png)

kubectl apply 输出

<pre>**$ kubectl apply -f nginx-service.yaml**

接下来，调用`kubectl get services`来检查新创建的服务定义。

在`kubectl get services`输出中，您将找到您新创建的`nginx`服务（以及始终存在的 Kubernetes 服务）。

记住在创建服务时指定的`type: NodePort`属性吗？这个属性的效果是，每个节点上的 Kube 代理现在打开了一个 TCP 端口。此端口的端口号是随机选择的。在前面的例子中，这是 TCP 端口 31455。您可以使用此端口从 Kubernetes 集群外部连接到您的服务（例如，从您的本地计算机）。在此端口接收到的任何流量都将转发到服务规范中指定的`selector`匹配的 Pod 之一。

服务的特殊之处在于，它们通常会比平均 Pod 的寿命要长得多。当添加新的 Pod（可能是因为您增加了部署控制器的副本数量）时，这些将自动添加。同样，当 Pod 被删除（可能是因为副本数量发生了变化，也可能是因为节点故障或者只是手动删除了 Pod），它们将停止接收流量。

如果您使用 Minikube，现在可以使用`minikube service`命令快速找到节点的公共 IP 地址，以在浏览器中打开此服务：

```go
$ minikube service nginx 
```

除了节点端口，还要注意前面输出中的集群 IP 属性；这是一个 IP 地址，您可以在集群内使用它来访问此服务匹配的任何 Pod。因此，在这个例子中，您可以启动一个运行您自己应用程序的新 Pod，并使用 IP 地址`10.0.0.223`来访问此应用程序中的`nginx`服务。此外，由于 IP 地址很麻烦，您还可以使用服务名称（在本例中为`nginx`）作为 DNS 名称。

# 持久卷

通常，您需要一个持久地存储文件和数据的地方。由于在 Kubernetes 环境中，单个 Pod 的生命周期相当短暂，直接在容器的文件系统中存储文件通常不是一个好的解决方案。在 Kubernetes 中，通过使用持久卷来解决这个问题，这基本上是 Docker 卷的更灵活的抽象，您之前已经使用过。

要创建一个新的持久卷，创建一个新的`example-volume.yaml`文件，内容如下：

```go
apiVersion: v1 
kind: PersistentVolume 
metadata: 
  name: volume01 
spec: 
  capacity: 
    storage: 1Gi 
  accessModes: 
  - ReadWriteOnce 
  - ReadWriteMany 
  hostPath: 
    path: /data/volume01 
```

使用`kubectl apply -f example-volume.yaml`创建卷。之后，您可以通过运行`kubectl get pv`再次找到它。

前面的清单文件创建了一个新的卷，将其文件存储在所使用的主机上的`/data/volume01`目录中。

除了在本地开发环境之外，使用 hostPath 卷来存储持久数据是一个糟糕的主意。如果使用此持久卷的 Pod 在另一个节点上重新调度，它将无法访问之前的相同数据。Kubernetes 支持多种卷类型，可以使卷在多个主机之间可访问。

例如，在 AWS 中，你可以使用以下卷定义：

```go
apiVersion: v1 
kind: PersistentVolume 
metadata: 
  name: volume01 
spec: 
  capacity: 
    storage: 1Gi 
  accessModes: 
  - ReadWriteOnce 
  awsElasticBlockStore: 
    volumeID: <volume-id> 
    fsType: ext4 
```

在 Pod 中使用持久卷之前，你需要索赔它。Kubernetes 在创建持久卷和在容器中使用它之间有一个重要的区别。这是因为创建持久卷的人和使用（索赔）它的人通常是不同的。此外，通过解耦卷的创建和使用，Kubernetes 还将卷在 Pod 中的使用与实际底层存储技术解耦。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/65c9aafa-74bd-4d3c-9404-2c32b6da6253.png)

接下来，通过创建一个`example-volume-claim.yaml`文件，然后调用`kubectl apply -f example-volume-claim.yaml`来创建一个`PersistentVolumeClaim`：

```go
apiVersion: v1 
kind: PersistentVolumeClaim 
metadata: 
  name: my-data 
spec: 
  accessModes: 
    - ReadWriteOnce 
  resources: 
    requests: 
      storage: 1Gi 
```

再次调用`kubectl get pv`时，你会发现`volume01`卷的状态字段已更改为`Bound`。现在你可以在创建 Pod 或 Deployment 时使用新创建的持久卷索赔：

```go
apiVersion: v1 
kind: Pod 
spec: 
  volumes: 
  - name: data 
    persistentVolumeClaim: 
      claimName: my-data 
  containers: 
  - name: nginx 
    image: nginx 
    volumeMounts: 
    - mountPath: "/usr/share/nginx/html" 
      name: data 
```

当你在云环境中操作你的 Kubernetes 集群时，Kubernetes 还能够通过与云提供商的 API 交谈来自动创建新的持久卷，例如创建新的 EBS 设备。

# 将 MyEvents 部署到 Kubernetes

现在你已经在 Kubernetes 上迈出了第一步，我们可以开始将 MyEvents 应用程序部署到 Kubernetes 集群中。

# 创建 RabbitMQ 代理

让我们从创建 RabbitMQ 代理开始。由于 RabbitMQ 不是一个无状态的组件，我们将使用 Kubernetes 提供的一个特殊控制器——`StatefulSet`控制器。这与 Deployment 控制器类似，但会创建具有持久标识的 Pod。

要创建一个新的`StatefulSet`，创建一个名为`rabbitmq-statefulset.yaml`的新文件：

```go
apiVersion: apps/v1beta1 
kind: StatefulSet 
metadata: 
  name: rmq 
spec: 
  serviceName: amqp-broker 
  replicas: 1 
  template: 
    metadata: 
      labels: 
        myevents/app: amqp-broker 
    spec: 
      containers: 
      - name: rmq 
        image: rabbitmq:3-management 
        ports: 
        - containerPort: 5672 
          name: amqp 
        - containerPort: 15672 
          name: http 
```

不过，这个定义缺少一个重要的东西，那就是持久性。目前，如果 RabbitMQ Pod 因任何原因失败，新的 Pod 将被调度而不会保留之前的状态（在这种情况下，交换、队列和尚未分发的消息）。因此，我们还应该声明一个持久卷，可以被这个`StatefulSet`使用。我们可以简单地为`StatefulSet`声明一个`volumeClaimTemplate`，让 Kubernetes 自动提供新的卷，而不是手动创建新的`PersistentVolume`和`PersistentVolumeClaim`。在 Minikube 环境中，这是可能的，因为 Minikube 附带了这样的卷的自动提供程序。在云环境中，你会找到类似的卷提供程序。

将以下部分添加到`StatefulSet`中：

```go
apiVersion: apps/v1beta1 
kind: StatefulSet 
metadata: 
  name: rmq 
spec: 
  serviceName: amqp-broker 
  replicas: 1 
  template: # ... 
  volumeClaimTemplates: 
  - metadata: 
      name: data 
      annotations: 
        volume.alpha.kubernetes.io/storage-class: standard 
    spec: 
      accessModes: ["ReadWriteOnce"] 
      resources: 
        requests: 
          storage: 1Gi 
```

`volumeClaimTemplate`将指示`StatefulSet`控制器自动为`StatefulSet`的每个实例提供新的`PersistentVolume`和新的`PersistentVolumeClaim`。如果增加副本计数，控制器将自动创建更多的卷。

最后要做的事情是实际在`rabbitmq`容器中使用卷索赔。为此，修改容器规范如下：

```go
containers: 
- name: rmq 
  image: rabbitmq:3-management 
  ports: # ... 
  volumeMounts: 
  - name: data 
    mountPath: /var/lib/rabbitmq 
```

使用`kubectl apply -f rabbitmq-statefulset.yaml`创建`StatefulSet`。之后，当你运行`kubectl get pods`时，你应该会看到一个名为`rmq-0`的新 Pod 正在启动。当分别运行`kubectl get pv`和`kubectl get pvc`时，你还应该看到自动生成的持久卷和相应的索赔。

接下来，创建一个`Service`，允许其他 Pod 访问你的 RabbitMQ 代理：

```go
apiVersion: v1 
kind: Service 
metadata: 
  name: amqp-broker 
spec: 
  selector: 
    myevents/app: amqp-broker 
  ports: 
  - port: 5672 
    name: amqp 
```

像往常一样，使用`kubectl apply -f rabbitmq-service.yaml`创建 Service。创建 Service 后，你将能够通过主机名`amqp-broker`（或其完整形式`amqp-broker.default.svc.cluster.local`）通过 DNS 解析它。

# 创建 MongoDB 容器

接下来，让我们创建 MongoDB 容器。在概念上，它们与您在前一节中创建的 RabbitMQ 容器没有太大的不同。与之前一样，我们将使用自动配置的卷来创建`StatefulSet`。将以下内容放入一个名为`events-db-statefulset.yaml`的新文件中，然后在此文件上调用`kubectl apply`：

```go
apiVersion: apps/v1beta1 
kind: StatefulSet 
metadata: 
  name: events-db 
spec: 
  serviceName: events-db 
  replicas: 1 
  template: 
    metadata: 
      labels: 
        myevents/app: events 
        myevents/tier: database 
    spec: 
      containers: 
      - name: mongo 
        image: mongo:3.4.3 
        ports: 
        - containerPort: 27017 
          name: mongo 
        volumeMounts: 
        - name: database 
          mountPath: /data/db 
  volumeClaimTemplates: 
  - metadata: 
      name: data 
      annotations: 
        volume.alpha.kubernetes.io/storage-class: standard 
    spec: 
      accessModes: ["ReadWriteOnce"] 
      resources: 
        requests: 
          storage: 1Gi 
```

接下来，通过创建一个新文件`events-db-service.yaml`，并调用`kubectl apply`来定义与此`StatefulSet`匹配的 Service：

```go
apiVersion: v1 
kind: Service 
metadata: 
  name: events-db 
spec: 
  clusterIP: None 
  selector: 
    myevents/app: events 
    myevents/tier: database 
  ports: 
  - port: 27017 
    name: mongo 
```

现在，我们需要为预订服务的 MongoDB 容器重复这个过程。您几乎可以从上面重复相同的定义；只需用`bookings`替换`events`，并创建`StatefulSet`和 Service`bookings-db`。

# 使镜像可用于 Kubernetes

现在，您需要确保 Kubernetes 集群可以访问您的镜像，然后才能部署实际的微服务。通常，您需要将自己构建的镜像可用于容器注册表。如果您使用 Minikube 并且想要避免设置自己的镜像注册表的麻烦，可以使用以下方法：

```go
$ eval $(minikube docker-env) 
$ docker image build -t myevents/eventservice .
```

第一条命令将指示您的本地 shell 连接到 Minikube VM 内的 Docker Engine，而不是本地 Docker Engine。然后，使用常规的`docker container build`命令，您可以直接在 Minikube VM 上构建要使用的容器镜像。

如果您的镜像可用于私有注册表（例如 Docker Hub、Quay.io 或自托管注册表），则需要配置 Kubernetes 集群，以便它被授权实际访问这些镜像。为此，您将把注册表凭据添加为`Secret`对象。使用`kubectl create secret`命令：

```go
$ kubectl create secret docker-registry my-private-registry \
 --docker-server https://index.docker.io/v1/ \
 --docker-username <your-username> \
 --docker-password <your-password> \
 --docker-email <your-email>
```

在上面的代码示例中，`my-private-registry`是您的 Docker 凭据集的任意选择的名称。`--docker-server`标志`https://index.docker.io/v1/`指定了官方 Docker Hub 的 URL。如果您使用第三方注册表，请记住相应地更改此值。

现在，您可以在创建新的 Pod 时使用这个新创建的`Secret`对象，通过向 Pod 规范添加`imagePullSecrets`属性：

```go
apiVersion: v1
kind: Pod
metadata:
  name: example-from-private-registry
spec:
  containers:
  - name: secret
    image: quay.io/martins-private-registry/secret-application:v1.2.3
  imagePullSecrets:
  - name: my-private-registry
```

当您使用`StatefulSet`或 Deploymet 控制器创建 Pod 时，`imagePullSecrets`属性也可以使用。

# 部署 MyEvents 组件

现在，您的容器镜像可以在 Kubernetes 集群上使用（无论是在 Minikube VM 上本地构建还是将它们推送到注册表并授权您的集群访问该注册表），我们可以开始部署实际的事件服务。由于事件服务本身是无状态的，我们将使用常规的 Deployment 对象部署它，而不是`StatefulSet`。

接下来，通过创建一个新文件`events-deployment.yaml`，并使用以下内容：

```go
apiVersion: apps/v1beta1 
kind: Deployment 
metadata: 
  name: eventservice 
spec: 
  replicas: 2 
  template: 
    metadata: 
      labels: 
        myevents/app: events 
        myevents/tier: api 
    spec: 
      containers: 
      - name: api 
        image: myevents/eventservice 
        imagePullPolicy: Never 
        ports: 
        - containerPort: 8181 
          name: http 
        environment: 
        - name: MONGO_URL 
          value: mongodb://events-db/events 
        - name: AMQP_BROKER_URL 
          value: amqp://guest:guest@amqp-broker:5672/ 
```

请注意`imagePullPolicy: Never`属性。如果您直接在 Minikube VM 上构建了`myevents/eventservice`镜像，则这是必需的。如果您有一个实际的容器注册表可用，可以将镜像推送到该注册表，您应该省略此属性（并添加`imagePullSecrets`属性）。

接下来，通过创建一个新文件`events-service.yaml`来创建相应的 Service：

```go
apiVersion: v1 
kind: Service 
metadata: 
  name: events 
spec: 
  selector: 
    myevents/app: events 
    myevents/tier: api 
  ports: 
  - port: 80 
    targetPort: 8181 
    name: http 
```

使用相应的`kubectl apply`调用创建 Deployment 和 Service。不久之后，您应该会在`kubectl get pods`输出中看到相应的容器出现。

类似地进行预订服务。您可以在本书的代码示例中找到预订服务的完整清单文件。

最后，让我们部署前端应用程序。使用以下清单创建另一个 Deployment： 

```go
apiVersion: apps/v1beta1 
kind: Deployment 
metadata: 
  name: frontend 
spec: 
  replicas: 2 
  template: 
    metadata: 
      labels: 
        myevents/app: frontend 
    spec: 
      containers: 
      - name: frontend 
        image: myevents/frontend 
        imagePullPolicy: Never 
        ports: 
        - containerPort: 80 
          name: http 
```

通过创建以下清单来创建相应的`Service`：

```go
apiVersion: v1 
kind: Service 
metadata: 
  name: frontend 
spec: 
  selector: 
    myevents/app: frontend 
  ports: 
  - port: 80 
    targetPort: 80 
    name: http 
```

# 配置 HTTP Ingress

此时，您的 Kubernetes 集群中正在运行 MyEvents 应用程序所需的所有服务。但是，目前还没有方便的方法可以从集群外部访问这些服务。使它们可访问的一种可能解决方案是使用**NodePort**服务（我们在以前的某个部分中已经做过）。但是，这将导致您的服务在一些随机选择的高 TCP 端口上暴露，这对于生产设置来说是不可取的（HTTP(S)服务应该在 TCP 端口`80`和`443`上可用）。

如果您的 Kubernetes 集群在公共云环境中运行（更确切地说是 AWS、GCE 或 Azure），您可以按以下方式创建`LoadBalancer` `Service`：

```go
apiVersion: v1 
kind: Service 
metadata: 
  name: frontend 
spec: 
  type: LoadBalancer 
  selector: 
    myevents/app: frontend 
  # ... 
```

这将为您的服务提供适当的云提供商资源（例如，在 AWS 中为**弹性负载均衡器**）以使您的服务在标准端口上公开访问。

但是，Kubernetes 还提供了另一个功能，允许您处理传入的 HTTP 流量，称为**Ingress**。Ingress 资源为您提供了更精细的控制，以确定您的 HTTP 服务应该如何从外部世界访问。例如，我们的应用程序由两个后端服务和一个前端应用程序组成，这三个组件都需要通过 HTTP 公开访问。虽然可以为这些组件的每个创建单独的`LoadBalancer`服务，但这将导致这三个服务分别获得自己的 IP 地址，并需要自己的主机名（例如，在`https://myevents.example`上提供前端应用程序，并在`https://events.myevents.example`和`https://bookings.myevents.example`上提供两个后端服务）。这可能会变得繁琐，并且在许多微服务架构中，通常需要提供外部 API 访问的单个入口点。使用 Ingress，我们可以声明路径到服务的映射，例如，使所有后端服务在`https://api.myevents.example`上可访问。

[`github.com/kubernetes/ingress/blob/master/controllers/nginx/README.md`](https://github.com/kubernetes/ingress/blob/master/controllers/nginx/README.md)。

在使用 Ingress 资源之前，您需要为 Kubernetes 集群启用 Ingress 控制器。这与您的个人环境高度相关；一些云提供商提供了处理 Kubernetes Ingress 流量的特殊解决方案，而在其他环境中，您需要自己运行。但是，使用 Minikube，启用 Ingress 是一个简单的命令：

```go
$ minikube addons enable ingress 
```

如果您打算在 Kubernetes 上运行自己的 Ingress 控制器，请查看 NGINX Ingress 控制器的官方文档。起初可能看起来很复杂，但就像许多内部 Kubernetes 服务一样，Ingress 控制器也只包括 Deployment 和 Service 资源。

在 Minikube 中启用 Ingress 控制器后，您的 Minikube VM 将开始在端口`80`和`443`上响应 HTTP 请求。要确定需要连接的 IP 地址，运行`minikube ip`命令。

为了使我们的服务对外界可访问，创建一个新的 Kubernetes 资源文件`ingress.yaml`，其中包含以下内容：

```go
apiVersions: extensions/v1beta1 
kind: Ingress 
metadata: 
  name: myevents 
spec: 
  rules: 
  - host: api.myevents.example 
    http: 
      paths: 
      - path: /events 
        backend: 
          serviceName: events 
          servicePort: 80 
      - path: /bookings 
        backend: 
          serviceName: bookings 
          servicePort: 80 
  - host: www.myevents.example 
    http: 
      paths: 
      - backend: 
          serviceName: frontend 
          servicePort: 80 
```

使用`kubectl apply -f ingress.yaml`创建 Ingress 资源。当然，`myevents.example`域名将不会公开访问（这是`.example`顶级域的整个目的）；因此，要实际测试此设置，您可以将一些条目添加到您的主机文件（macOS 和 Linux 上的`/etc/hosts`；Windows 上的`C:\Windows\System32\drivers\etc\hosts`）：

```go
192.168.99.100 api.myevents.example 
192.168.99.100 www.myevents.example
```

通常，`192.168.99.100`应该是 Minikube VM 的（唯一可路由的）IP 地址。通过运行`minikube ip`命令的输出进行交叉检查以确保。

# 总结

在本章中，您学会了如何使用诸如 Docker 之类的容器技术将您的应用程序及其所有依赖项打包到容器映像中。您学会了如何从您的应用程序构建容器映像，并在基于 Kubernetes 构建的生产容器环境中部署它们。

我们将在第九章回到构建容器映像，您将学习如何进一步自动化容器构建工具链，使您能够完全自动化应用程序部署，从 git push 命令开始，到在您的 Kubernetes 云中运行更新的容器映像结束。

到目前为止，我们一直相当云不可知。到目前为止，我们所看到的每个示例都可以在任何主要的公共或私有云中运行，无论是 AWS、Azure、GCE 还是 OpenStack。事实上，容器技术通常被认为是摆脱云提供商的个别怪癖并避免（潜在的昂贵）供应商锁定的绝佳方式。

所有这些将在接下来的两章中发生变化，我们将看看其中一个主要的云服务提供商——**亚马逊网络服务**（**AWS**）。您将了解每个提供商的复杂性，如何将 MyEvents 应用程序部署到这些平台上，以及如何使用它们提供的独特功能。
