# SpringBoot2 和 React 全栈开发实用指南（二）

> 原文：[`zh.annas-archive.org/md5/B5164CAFF262E48113020BA46AD77AF2`](https://zh.annas-archive.org/md5/B5164CAFF262E48113020BA46AD77AF2)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：设置环境和工具 - 前端

本章描述了使用 React 所需的开发环境和工具。这一章是为了能够开始前端开发。我们将使用 Facebook 制作的 Create React App 入门套件创建一个简单的 React 应用。

在本章中，我们将研究以下内容：

+   安装 Node.js 和 VS Code

+   使用`create-react-app`创建一个 React.js 应用

+   运行 React.js 应用

+   安装 React 开发者工具

# 技术要求

在本书中，我们使用 Windows 操作系统，但所有工具也适用于 Linux 和 macOS。

# 安装 Node.js

Node.js 是一个基于 JavaScript 的开源服务器端环境。Node.js 适用于多个操作系统，如 Windows，macOS 和 Linux。Node.js 是开发 React 应用所需的。

Node.js 安装包可以在[`nodejs.org/en/download/`](https://nodejs.org/en/download/)找到。为您的操作系统下载最新的**长期支持**（**LTS**）版本。在本书中，我们使用 Windows 10 操作系统，您可以为其获取 Node.js MSI 安装程序，这样安装就非常简单。当您执行安装程序时，您将通过安装向导，并且可以使用默认设置进行操作：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/3408e032-c037-402a-8bcc-7afa005e8d9e.png)

安装完成后，我们可以检查一切是否正确。打开 PowerShell，或者您正在使用的终端，然后输入以下命令：

```java
node -v
```

```java
npm -v
```

这些命令应该显示已安装的版本，Node.js 和 npm：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/7abacf7a-b0d3-4ebf-a31d-9495a2d28cea.png)

npm 随 Node.js 安装而来，是 JavaScript 的包管理器。在接下来的章节中，当我们安装不同的节点模块到我们的 React 应用时，我们会经常使用它。还有另一个称为 Yarn 的包管理器，您也可以使用。

# 安装 VS Code

**Visual Studio Code**（**VS Code**）是一个用于多种编程语言的开源代码编辑器。VS Code 由 Microsoft 开发。还有许多不同的代码编辑器可用，如 Atom，Brackets 等，如果您熟悉其他编辑器，也可以使用其他编辑器。VS Code 适用于 Windows，macOS 和 Linux，您可以从[`code.visualstudio.com/`](https://code.visualstudio.com/)下载它。

Windows 的安装是通过 MSI 安装程序完成的，您可以使用默认设置进行安装。以下截图显示了 VS Code 的工作台。左侧是活动栏，您可以使用它在不同视图之间导航。活动栏旁边是侧边栏，其中包含不同的视图，如项目文件资源管理器。

编辑器占据了工作台的其余部分：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/d5eae059-c075-4556-8e57-a1e597fee33c.png)

VS Code 还有一个集成终端，您可以使用它来创建和运行 React 应用。终端可以在 View | Integrated Terminal 菜单中找到。在后续章节中，当我们创建更多的 React 应用时，您也可以使用它。

有很多可用于不同语言和框架的扩展。如果您从活动栏打开扩展管理器，可以搜索不同的扩展。一个真正方便的 React 开发扩展是 Reactjs Code Snippets，我们建议安装。它有多个可用于 React.js 应用的代码片段，可以加快开发过程。我们稍后会向您展示如何使用该扩展。这只是许多有用的扩展之一，您应该探索更多可能使您的生活更轻松的扩展。例如，ESLint 扩展可以帮助您快速找到拼写错误和语法错误，并使源代码的格式化更容易：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/d52ba971-e180-477e-ba19-31f11274615f.png)

# 创建和运行一个 React 应用

当我们安装了 Node.js 和代码编辑器后，我们就可以创建我们的第一个 React.js 应用程序了。我们使用 Facebook 的`create-react-app` ([`github.com/facebook/create-react-app`](https://github.com/facebook/create-react-app))。以下是制作第一个应用程序的步骤：

1.  打开 PowerShell 或命令行工具，然后输入以下命令。该命令安装了`create-react-app` starter，我们将用它来开发 React 应用程序。命令中的参数`-g`表示全局安装。

如果您使用的是 npm 版本 5.2 或更高版本，您也可以使用`npx`代替`npm`：

```java
npm install -g create-react-app
```

1.  安装完成后，我们通过输入以下命令来创建我们的第一个应用程序：

```java
create-react-app myapp
```

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/ab7d67dd-2ebb-4c2e-adfa-682232267988.png)

1.  应用程序创建后，将其移动到您的`app`文件夹中：

```java
cd myapp
```

1.  然后，您可以使用以下命令运行应用程序。该命令在端口`3000`中运行应用程序，并在浏览器中打开应用程序：

```java
npm start
```

1.  现在您的应用程序正在运行，您应该在浏览器中看到以下页面。`npm start`命令以开发模式启动应用程序：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/68631788-67ba-4fee-8dac-c2e6a4b25aa2.png)

您可以通过在 PowerShell 中按*Ctrl* + *C*来停止开发服务器。

要为生产构建应用程序的缩小版本，您可以使用`npm run build`命令，该命令将在`build`文件夹中构建您的应用程序。

# 修改 React 应用程序

通过选择文件 | 打开文件夹在 VS Code 中打开您的 React 应用程序文件夹。您应该在文件资源管理器中看到应用程序结构。在这个阶段中最重要的文件夹是`src`文件夹，其中包含 JavaScript 源代码：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/ed2e43da-66eb-4f31-9586-190defd8904a.png)

在代码编辑器中的`src`文件夹中打开`App.js`文件。删除显示图像的行并保存文件。您暂时不需要了解有关此文件的更多信息。我们将在下一章中深入讨论这个主题：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/f9d09e6e-8bc2-499a-b6b0-782fcc6bd584.png)

现在，如果您查看浏览器，您应该立即看到图像已从页面中消失：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/d5ab979f-f2b0-4a91-a38a-ab4be689254b.png)

要调试 React 应用程序，我们还应该安装 React Developer Tools，它们适用于 Chrome 或 Firefox 浏览器。可以从 Chrome Web Store ([`chrome.google.com/webstore/category/extensions`](https://chrome.google.com/webstore/category/extensions))安装 Chrome 插件，从 Firefox 插件站 ([`addons.mozilla.org`](https://addons.mozilla.org))安装 Firefox 插件。安装了 React Developer Tools 后，当您导航到 React 应用程序时，您应该在浏览器的开发者工具中看到一个新的 React 标签。以下屏幕截图显示了 Chrome 浏览器中的开发者工具：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/a35e4b79-8a77-45fc-8c8d-f863aed1c81f.png)

# 摘要

在本章中，我们安装了开始使用 React.js 进行前端开发所需的一切。首先，我们安装了 Node.js 和 VS Code 编辑器。然后，我们使用了`create-react-app` starter 套件来创建我们的第一个 React.js 应用程序。最后，我们运行了应用程序，并演示了如何修改它。这只是应用程序结构和修改的概述，我们将在接下来的章节中继续讨论。

# 问题

1.  什么是 Node.js 和 npm？

1.  如何安装 Node.js？

1.  什么是 VS Code？

1.  如何安装 VS Code？

1.  如何使用`create-react-app`创建 React.js 应用程序？

1.  如何运行 React.js 应用程序？

1.  如何对应用程序进行基本修改？

# 进一步阅读

Packt 还有其他很好的资源可以学习 React：

+   [`www.packtpub.com/web-development/getting-started-react`](https://www.packtpub.com/web-development/getting-started-react)

+   [`www.packtpub.com/web-development/react-16-tooling`](https://www.packtpub.com/web-development/react-16-tooling)


# 第六章：开始使用 React

本章描述了 React 编程的基础知识。我们将介绍创建 React 前端基本功能所需的技能。在 JavaScript 中，我们使用 ES6 语法，因为它提供了许多使编码更清晰的功能。

在本章中，我们将看到以下内容：

+   如何创建 React 组件

+   如何在组件中使用状态和属性

+   有用的 ES6 功能

+   JSX 是什么

+   如何在 React 中处理事件和表单

# 技术要求

在本书中，我们使用的是 Windows 操作系统，但所有工具也适用于 Linux 和 macOS。

# 基本的 React 组件

根据 Facebook 的说法，React 是一个用于用户界面的 JavaScript 库。自版本 15 以来，React 已经在 MIT 许可证下开发。React 是基于组件的，组件是独立和可重用的。组件是 React 的基本构建块。当您开始使用 React 开发用户界面时，最好从创建模拟界面开始。这样，可以轻松地确定需要创建哪种组件以及它们如何交互。

从模拟的下图中，我们可以看到用户界面如何分割成组件。在这种情况下，将有一个应用根组件，一个搜索栏组件，一个表格组件和一个表格行组件：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/ea445c35-4e5f-4944-8d8c-fc3baaf3eb57.png)

然后，这些组件可以按以下树形层次结构排列。理解 React 的重要一点是，数据流是从父组件到子组件的：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/97b274c3-687d-47fa-ade1-1949c057daf1.png)

React 使用虚拟 DOM 来选择性地重新渲染用户界面，这使得它更具成本效益。虚拟 DOM 是 DOM 的轻量级副本，对虚拟 DOM 的操作比真实 DOM 快得多。虚拟 DOM 更新后，React 将其与在更新运行之前从虚拟 DOM 中获取的快照进行比较。比较后，React 知道哪些部分已更改，只有这些部分才会更新到真实 DOM 中。

React 组件可以通过使用 JavaScript 函数或 ES6 JavaScript 类来定义。我们将在下一节更深入地了解 ES6。以下是一个简单的组件源代码，用于呈现`Hello World`文本。第一个代码块使用了 JavaScript 函数：

```java
// Using JavaScript function
function Hello() {
  return <h1>Hello World</h1>;
}
```

这个例子使用类来创建一个组件：

```java
// Using ES6 class
class Hello extends React.Component {
  render() {
    return <h1>Hello World</h1>;
  }
}
```

使用类实现的组件包含所需的`render()`方法。这个方法显示和更新组件的呈现输出。用户定义的组件名称应以大写字母开头。

让我们对组件的`render`方法进行更改，并添加一个新的标题元素进去：

```java
class App extends Component {
  render() {
    return (
      <h1>Hello World!</h1>
      <h2>From my first React app</h2>
    );
  }
}
```

当您运行应用程序时，会出现“相邻的 JSX 元素必须包装在一个封闭标记中”的错误。要解决这个错误，我们必须将标题包装在一个元素中，比如`div`；自 React 版本 16.2 以来，我们还可以使用`Fragments`，它看起来像空的 JSX 标签：

```java
// Wrap headers in div
class App extends Component {
  render() {
    return (
      <div>
        <h1>Hello World!</h1>
        <h2>From my first React app</h2>
      </div>
    );
  }
}

// Or using fragments
class App extends Component {
  render() {
    return (
      <>
        <h1>Hello World!</h1>
        <h2>From my first React app</h2>
      </>
    );
  }
}

```

让我们更仔细地看一下我们在上一章中使用`create-react-app`创建的第一个 React 应用程序。根文件夹中`Index.js`文件的源代码如下：

```java
import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import App from './App';
import registerServiceWorker from './registerServiceWorker';

ReactDOM.render(<App />, document.getElementById('root'));
registerServiceWorker();
```

在文件的开头，有一些`import`语句，用于加载组件或资源到我们的文件中。例如，第二行从`node_modules`文件夹中导入了`react-dom`包，第四行导入了`App`（根文件夹中的`App.js`文件）组件。`react-dom`包为我们提供了特定于 DOM 的方法。要将 React 组件呈现到 DOM 中，我们可以使用`react-dom`包中的`render`方法。第一个参数是将要呈现的组件，第二个参数是组件将要呈现的元素或容器。在这种情况下，`root`元素是`<div id="root"></div>`，可以在`public`文件夹中的`index.html`文件中找到。请参阅以下`index.html`文件：

```java
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1,
     shrink-to-fit=no">
    <meta name="theme-color" content="#000000">

    <link rel="manifest" href="%PUBLIC_URL%/manifest.json">
    <link rel="shortcut icon" href="%PUBLIC_URL%/favicon.ico">

    <title>React App</title>
  </head>
  <body>
    <div id="root"></div>
  </body>
</html>
```

以下源代码显示了我们第一个 React 应用程序的`App.js`组件。您可以看到`import`也适用于图像和样式表等资产。在源代码的末尾，有一个`export`语句，导出组件，并且可以通过导入在其他组件中使用。每个文件只能有一个默认导出，但可以有多个命名导出：

```java
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

以下示例显示了如何导入默认和命名导出：

```java
import React from 'react' // Import default value
import { Component } from 'react' // Import named value
```

导出如下：

```java
export default React // Default export
export {Component} // Named export
```

# ES6 基础

ES6（ECMAScript 2015）于 2015 年发布，引入了许多新功能。ECMAScript 是一种标准化的脚本语言，而 JavaScript 是其一种实现。在这里，我们将介绍 ES6 中发布的最重要的功能，这些功能将在接下来的部分中使用。

# 了解常量

常量或不可变变量可以通过使用`const`关键字来定义。使用`const`关键字时，变量内容不能被重新分配：

```java
const PI = 3.14159;
```

`const`的作用域是块作用域，与`let`相同。这意味着`const`变量只能在定义它的块内使用。在实践中，块是花括号`{ }`之间的区域。以下示例代码显示了作用域的工作原理。第二个`console.log`语句会报错，因为我们试图在作用域之外使用`total`变量：

```java
var count = 10;
if(count > 5) {
  const total = count * 2;
  console.log(total); // Prints 20 to console
}
console.log(total); // Error, outside the scope
```

值得知道的是，如果`const`是对象或数组，则内容可以更改。以下示例演示了这一点：

```java
const myObj = {foo : 3};
myObj.foo = 5; // This is ok
```

# 箭头函数

箭头函数使函数声明更加紧凑。在 JavaScript 中定义函数的传统方式是使用`function`关键字。以下函数获取一个参数，然后返回参数值：

```java
function hello(greeting) {
    return greeting;
}
```

通过使用 ES6 箭头函数，函数如下所示：

```java
const hello = greeting => { greeting }

// function call
hello('Hello World'); // returns Hello World
```

如果有多个参数，必须使用括号将参数括起来，并用逗号分隔参数。以下函数获取两个参数并返回参数的总和。如果函数体是一个表达式，则不需要使用`return`关键字。该表达式总是从函数中隐式返回的：

```java
const calcSum = (x, y) => { x + y }

// function call
calcSum(2, 3); // returns 5
```

如果函数没有任何参数，则语法如下：

```java
() => { ... }
```

# 模板文字

模板文字可用于连接字符串。连接字符串的传统方式是使用加号运算符：

```java
var person = {firstName: 'John', lastName: 'Johnson'};
var greeting = "Hello " + ${person.firstName} + " " + ${person.lastName};
```

使用模板文字，语法如下。您必须使用反引号（`` ``）而不是单引号或双引号：

```java
var person = {firstName: 'John', lastName: 'Johnson'};
var greeting = `Hello ${person.firstName} ${person.lastName}`;
```

# 类和继承

ES6 中的类定义类似于 Java 或 C#等面向对象语言。定义类的关键字是`class`。类可以有字段、构造函数和类方法。以下示例代码显示了 ES6 类：

```java
class Person {
    constructor(firstName, lastName) {
        this.firstName = firstName;
        this.lastName = lastName;
    }  
}
```

继承是使用`extends`关键字完成的。以下示例代码显示了一个继承`Person`类的`Employee`类。因此，它继承了父类的所有字段，并且可以具有特定于员工的自己的字段。在构造函数中，我们首先使用`super`关键字调用父类构造函数。这个调用是必需的，如果缺少它，您将会收到一个错误：

```java
class Employee extends Person {
    constructor(firstName, lastName, title, salary) {
        super(firstName, lastName);
        this.title= title;
        this.salary = salary;
    }  
}
```

尽管 ES6 已经相当古老，但现代 Web 浏览器仍然只支持部分。Babel 是一个 JavaScript 编译器，用于将 ES6 编译为与所有浏览器兼容的旧版本。您可以在 Babel 网站上测试编译器（[`babeljs.io`](https://babeljs.io)）。以下屏幕截图显示了箭头函数编译回旧的 JavaScript 语法：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/6181624b-547b-4a21-9e8f-a50fc4306e18.png)

# JSX 和样式

JSX 是 JavaScript 的语法扩展。在 React 中使用 JSX 不是强制的，但有一些好处可以使开发更容易。例如，JSX 可以防止注入攻击，因为在渲染之前 JSX 中的所有值都会被转义。最有用的功能是可以通过花括号包裹 JavaScript 表达式在 JSX 中嵌入 JavaScript 表达式，这在接下来的章节中会经常使用。在这个例子中，我们可以在使用 JSX 时访问组件的 props。组件的 props 将在下一节中介绍：

```java
class Hello extends React.Component {
  render() {
    return <h1>Hello World {this.props.user}</h1>;
  }
}
```

你也可以将 JavaScript 表达式作为 props 传递：

```java
<Hello count={2+2} />
```

JSX 通过 Babel 编译为`React.createElement()`调用。你可以在 React JSX 元素中使用内部或外部样式。以下是两个内联样式的例子。第一个直接在`div`元素内定义样式：

```java
<div style={{height: 20, width: 200}}>
  Hello
</div>
```

第二个例子首先创建样式对象，然后在`div`元素中使用。对象名称应该使用驼峰命名约定：

```java
const divStyle = {
  color: 'red',
  height: 30
};

const MyComponent = () => (
  <div style={divStyle}>Hello</div>
);
```

如前一节所示，你可以向 React 组件导入样式表。要引用外部 CSS 文件中的类，应该使用`className`属性：

```java
import './App.js';

...

<div className="App-header">
  This is my app
</div>
```

# Props 和 state

Props 和 state 是渲染组件的输入数据。props 和 state 都是 JavaScript 对象，当 props 或 state 发生变化时，组件会重新渲染。

props 是不可变的，所以组件不能改变它的 props。props 是从父组件接收的。组件可以通过`this.props`对象访问 props。例如，看下面的组件：

```java
class Hello extends React.Component {
  render() {
    return <h1>Hello World {this.props.user}</h1>;
  }
}
```

父组件可以通过以下方式向`Hello`组件发送 props：

```java
<Hello user="John" />
```

当`Hello`组件被渲染时，它会显示`Hello World John`文本。

状态可以在组件内部改变。状态的初始值在组件的构造函数中给出。可以通过`this.state`对象访问状态。状态的作用域是组件，因此不能在定义它的组件外部使用。如下例所示，props 作为参数传递给构造函数，状态在构造函数中初始化。然后可以使用花括号`{this.state.user}`在 JSX 中渲染状态的值：

```java
class Hello extends React.Component {
  constructor(props) {
    super(props);
    this.state = {user: 'John'}
  }

  render() {
    return <h1>Hello World {this.state.user}</h1>;
  }
}
```

状态可以包含不同类型的多个值，因为它是一个 JavaScript 对象，如下例所示：

```java
  constructor(props) {
    super(props);
    this.state = {firstName: 'John', lastName: 'Johnson', age: 30}
  }
```

使用`setState`方法改变状态的值：

```java
this.setState({firstName: 'Jim', age: 31});  // Change state value
```

不应该使用等号操作符来更新状态，因为这样 React 不会重新渲染组件。改变状态的唯一方法是使用`setState`方法，这会触发重新渲染：

```java
this.state.firstName = 'Jim'; // WRONG
```

`setState`方法是异步的，因此你不能确定状态何时会更新。`setState`方法有一个回调函数，在状态更新后执行。

状态的使用是可选的，它增加了组件的复杂性。只有 props 的组件称为**无状态**组件。当具有相同输入时，它们总是呈现相同的输出，这意味着它们非常容易测试。同时具有状态和 props 的组件称为**有状态**组件。以下是一个简单无状态组件的示例，它是使用类定义的。也可以使用函数定义它：

```java
export default class MyTitle extends Component {
  render() {
    return (
     <div>
      <h1>{this.props.text}</h1>
     </div>
    );
 };
};

// The MyTitle component can be then used in other component and text value is passed to props
<MyTitle text="Hello" />
// Or you can use other component's state
<MyTitle text={this.state.username} />
```

如果要更新依赖当前状态的状态值，应该向`setState()`方法传递更新函数而不是对象。一个常见的情况是计数器示例：

```java
// This solution might not work correctly
incerementCounter = () => {
 this.setState({count: this.state.count + 1});
}

// The correct way is the following
incrementCounter = () => {
  this.setState((prevState) => {
    return {count: prevState.count + 1}
  });
}
```

# 组件生命周期方法

React 组件有许多生命周期方法可以重写。这些方法在组件生命周期的某些阶段执行。生命周期方法的名称是合乎逻辑的，你几乎可以猜到它们何时会被执行。具有前缀的生命周期方法在发生任何事情之前执行，而具有前缀的方法在发生某事之后执行。挂载是组件生命周期的一个阶段，也是组件创建并插入 DOM 的时刻。我们已经介绍的两个生命周期方法在组件挂载时执行：`constructor()`和`render()`。

在挂载阶段中一个有用的方法是`componentDidMount()`，它在组件挂载后调用。这个方法适合调用一些 REST API 来获取数据，例如。以下示例代码演示了如何使用`componentDidMount()`方法。

在下面的示例代码中，我们首先将`this.state.user`的初始值设置为`John`。然后，当组件挂载时，我们将值更改为`Jim`：

```java
class Hello extends React.Component {
  constructor(props) {
    super(props);
    this.state = {user: 'John'}
  }

  componentDidMount() {
    this.setState({user: 'Jim'});
  }

  render() {
    return <h1>Hello World {this.state.user}</h1>;
  }
}
```

还有一个`componentWillMount()`生命周期方法，在组件挂载之前调用，但 Facebook 建议不要使用它，因为它可能用于内部开发目的。

当状态或属性已更新并且组件将被渲染之前，会调用`shouldComponentUpdate()`方法。该方法将新属性作为第一个参数，新状态作为第二个参数，并返回布尔值。如果返回的值为`true`，则组件将重新渲染；否则，它将不会重新渲染。这个方法允许你避免无用的渲染并提高性能：

```java
shouldComponentUpdate(nextProps, nextState) {
  // This function should return a boolean, whether the component should re-render.
  return true; 
}
```

在组件从 DOM 中移除之前，会调用`componentWillUnmount()`生命周期方法。这是一个清理资源、清除定时器或取消请求的好时机。

错误边界是捕获其子组件树中 JavaScript 错误的组件。它们还应记录这些错误并在用户界面中显示备用内容。为此，有一个名为`componentDidCatch()`的生命周期方法。它与 React 组件一起工作，就像标准 JavaScript`catch`块一样。

# 使用 React 处理列表

对于列表处理，我们引入了一个新的 JavaScript 方法`map()`，当你需要操作列表时很方便。`map()`方法创建一个新数组，其中包含调用原始数组中每个元素的函数的结果。在下面的示例中，每个数组元素都乘以 2：

```java
const arr = [1, 2, 3, 4];

const resArr = arr.map(x => x * 2); // resArr = [2, 4, 6, 8]
```

`map()`方法还有第二个参数`index`，在处理 React 中的列表时非常有用。React 中的列表项需要一个唯一的键，用于检测已更改、添加或删除的行。

以下示例显示了将整数数组转换为列表项数组并在`ul`元素中呈现这些列表项的组件：

```java
class App extends React.Component {
  render() { 
    const data = [1, 2, 3, 4, 5];
    const rows = data.map((number, index) =>
     <li key={index}>Listitem {number}</li>
    );

    return (
     <div>
      <ul>{rows}</ul>
     </div>
    );
  }
}
```

以下屏幕截图显示了组件在呈现时的外观：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/c743b210-5e4e-44f1-a93e-36a62b76ffa7.png)

如果数据是对象数组，最好以表格格式呈现数据。思路与列表相同，但现在我们只需将数组映射到表格行并在表格元素中呈现这些行，如下面的代码所示：

```java
class App extends Component {
  render() { 
    const data = [{brand: 'Ford', model: 'Mustang'}, 
    {brand:'VW', model: 'Beetle'}, {brand: 'Tesla', model: 'Model S'}];
    const tableRows = data.map((item, index) =>
     <tr key={index}><td>{item.brand}</td><td>{item.model}</td></tr>
    );

    return (
     <div>
      <table><tbody>{tableRows}</tbody></table>
     </div>
    );
  }
}
```

以下屏幕截图显示了组件在呈现时的外观：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/b7cd5a40-a4be-40c7-9976-ec5828bf2dc8.png)

# 使用 React 处理事件

React 中的事件处理与处理 DOM 元素事件类似。与 HTML 事件处理相比，不同之处在于 React 中事件命名使用驼峰命名法。以下示例代码向按钮添加了一个事件监听器，并在按下按钮时显示警报消息：

```java
class App extends React.Component {
  // This is called when the button is pressed
  buttonPressed = () => {
    alert('Button pressed');
  }

  render() { 
    return (
     <div>
      <button onClick={this.buttonPressed}>Press Me</button>
     </div>
    );
  }
}
```

在 React 中，你不能从事件处理程序中返回`false`来阻止默认行为。相反，你应该调用`preventDefault()`方法。在下面的示例中，我们使用一个表单，并希望阻止表单提交：

```java
class MyForm extends React.Component {
  // This is called when the form is submitted
  handleSubmit(event) {
    alert('Form submit');
    event.preventDefault();  // Prevents default behavior
  }

  render() {
    return (
      <form onSubmit={this.handleSubmit}>
        <input type="submit" value="Submit" />
      </form>
    );
  }
}
```

# 使用 React 处理表单

使用 React 处理表单有点不同。当提交 HTML 表单时，它将导航到下一个页面。一个常见情况是，我们希望在提交后调用一个 JavaScript 函数，该函数可以访问表单数据并避免导航到下一个页面。我们已经在前一节中介绍了如何使用`preventDefault()`来避免提交。

让我们首先创建一个最简单的表单，其中包含一个输入字段和提交按钮。为了能够获取输入字段的值，我们使用`onChange`事件处理程序。当输入字段的值更改时，新值将保存到状态中。`this.setState({text: event.target.value});`语句从输入字段获取值并将其保存到名为`text`的状态中。最后，当用户按下提交按钮时，我们将显示输入的值。以下是我们第一个表单的源代码：

```java
class App extends Component {
  constructor(props) {
    super(props);
    this.state = {text: ''};
  }

  // Save input box value to state when it has been changed
  inputChanged = (event) => {
    this.setState({text: event.target.value});
  }

  handleSubmit = (event) => {
    alert(`You typed: ${this.state.text}`);
    event.preventDefault();
  }

  render() {
    return (
      <form onSubmit={this.handleSubmit}>
        <input type="text" onChange={this.inputChanged} 
            value={this.state.text}/>
        <input type="submit" value="Press me"/>
      </form>
    );
  } 
}
```

以下是我们的表单组件在按下提交按钮后的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/e9abef54-c2c6-4991-b125-2b7b1b4117b4.png)

现在是时候看一下 React Developer Tools 了，这是用于调试 React 应用程序的方便工具。如果我们打开 React Developer Tools 并在 React 表单应用程序中输入内容，我们可以看到状态值的变化。我们可以检查当前的 props 和 state 值。以下屏幕截图显示了当我们在输入字段中输入内容时状态的变化：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/1d572fac-91b1-4dd8-9b37-fe65bac3f6a5.png)

通常，表单中会有多个输入字段。处理多个输入字段的一种方法是添加与输入字段数量相同的更改处理程序。但这会创建大量样板代码，我们要避免这种情况。因此，我们向输入字段添加名称属性，并且可以在更改处理程序中利用它来识别触发更改处理程序的输入字段。输入字段的名称属性值必须与我们想要保存值的状态的名称相同。

现在处理程序看起来像下面这样。如果触发处理程序的输入字段是名字字段，则`event.target.name`是`firstName`，并且输入的值将保存到名为`firstName`的状态中。通过这种方式，我们可以使用一个更改处理程序处理所有输入字段：

```java
 inputChanged = (event) => {
    this.setState({[event.target.name]: event.target.value});
  }
```

以下是组件的完整源代码：

```java
class App extends Component {
  constructor(props) {
    super(props);
    this.state = {firstName: '', lastName: '', email: ''};
  }

  inputChanged = (event) => {
    this.setState({[event.target.name]: event.target.value});
  }

  handleSubmit = (event) => {
    alert(`Hello ${this.state.firstName} ${this.state.lastName}`);
    event.preventDefault();
  }

  render() {
    return (
      <form onSubmit={this.handleSubmit}>
        <label>First name </label>
        <input type="text" name="firstName" onChange={this.inputChanged} 
            value={this.state.firstName}/><br/>
        <label>Last name </label>
        <input type="text" name="lastName" onChange={this.inputChanged} 
            value={this.state.lastName}/><br/>
        <label>Email </label>
        <input type="email" name="email" onChange={this.inputChanged} 
            value={this.state.email}/><br/>
        <input type="submit" value="Press me"/>
      </form>
    );
  } 
}
```

以下是我们的表单组件在按下提交按钮后的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/dc15c8f6-50a4-429d-931b-a6f58d46450b.png)

# 总结

在本章中，我们开始了解 React，我们将使用它来构建我们的前端。在开始使用 React 进行开发之前，我们涵盖了 React 组件、JSX、props 和 state 等基础知识。在我们的前端开发中，我们使用 ES6，这使我们的代码更清晰。我们了解了我们需要进一步开发的功能。我们还学会了如何处理 React 中的表单和事件。

# 问题

1.  什么是 React 组件？

1.  状态和 props 是什么？

1.  数据在 React 应用程序中如何流动？

1.  无状态组件和有状态组件有什么区别？

1.  JSX 是什么？

1.  组件生命周期方法是什么？

1.  我们应该如何处理 React 中的事件？

1.  我们应该如何处理 React 中的表单？

# 进一步阅读

Packt 还有其他很好的资源可供学习 React：

+   [`www.packtpub.com/web-development/getting-started-react`](https://www.packtpub.com/web-development/getting-started-react)

+   [`www.packtpub.com/web-development/react-16-essentials-second-edition`](https://www.packtpub.com/web-development/react-16-essentials-second-edition)


# 第七章：使用 React 消费 REST API

本章解释了 React 的网络。我们将学习承诺，使异步代码更清晰和可读。对于网络，我们将使用`fetch`库。例如，我们使用 GitHub REST API 来演示如何在 React 中消费 RESTful Web 服务。

在本章中，我们将看看以下内容：

+   使用承诺

+   如何使用 Fetch

+   如何向 REST API 发出请求

+   如何处理来自 REST API 的响应

+   如何创建一个消费 REST API 的 React 应用程序

# 技术要求

在本书中，我们使用的是 Windows 操作系统，但所有工具都适用于 Linux 和 macOS，因为 Node.js 和`create-react-app`必须安装。

# 使用承诺

处理异步操作的传统方法是使用回调函数来处理操作的成功或失败。根据调用的结果，将调用其中一个回调函数。以下示例展示了使用回调函数的思想：

```java
function doAsyncCall(success, failure) {
    // Do some api call
    if (SUCCEED)
        success(resp);
    else
        failure(err);
}

success(response) {
    // Do something with response
}

failure(error) {
    // Handle error
}

doAsyncCall(success, failure);
```

承诺是表示异步操作结果的对象。使用承诺在进行异步调用时简化了代码。承诺是非阻塞的。

承诺可以处于三种状态之一：

+   **待定**：初始状态

+   **完成**：操作成功

+   **拒绝**：操作失败

使用承诺，我们可以进行异步调用，如果我们使用的 API 支持承诺。在下一个示例中，异步调用完成后，当响应返回时，`then`中的函数将被执行，并将响应作为参数传递：

```java
doAsyncCall()
.then(response => // Do something with the response);
```

您可以将`then`链接在一起，这意味着您可以依次运行多个异步操作：

```java
doAsyncCall()
.then(response => // Get some result from the response)
.then(result => // Do something with the result);
```

您还可以通过使用`catch()`向承诺添加错误处理：

```java
doAsyncCall()
.then(response => // Get some result from the response)
.then(result => // Do something with result);
.catch(error => console.error(error))
```

有一种更现代的处理异步调用的方法，使用了 ECMAScript 2017 引入的`async`/`await`，它还没有像承诺那样得到浏览器的广泛支持。`async`/`await`实际上是基于承诺的。要使用`async`/`await`，您必须定义一个可以包含等待表达式的`async`函数。以下是使用`async`/`await`进行异步调用的示例。正如您所看到的，您可以以类似于同步代码的方式编写代码：

```java
doAsyncCall = async () => {
    const response = await fetch('http://someapi.com');
    const result = await response.json();
    // Do something with the result
}
```

对于错误处理，您可以使用`async`/`await`和`try…catch`，如下例所示：

```java
doAsyncCall = async () => {
  try {
    const response = await fetch('http://someapi.com');
    const result = await response.json();
    // Do something with the result
  }
  catch(err) {
    console.error(err);
  } 
}
```

# 使用 Fetch API

使用 Fetch API，您可以进行 Web 请求。Fetch API 的思想类似于传统的`XMLHttpRequest`，但 Fetch API 也支持承诺，使其更易于使用。

Fetch API 提供了一个`fetch()`方法，它有一个必需的参数，即您正在调用的资源的路径。对于 Web 请求，它将是服务的 URL。对于简单的`GET`方法调用，返回 JSON 响应，语法如下。`fetch()`方法返回一个包含响应的承诺。您可以使用`json()`方法从响应中解析 JSON 主体：

```java
fetch('http://someapi.com')
.then(response => response.json())
.then(result => console.log(result));
.catch(error => console.error(error))
```

使用另一种 HTTP 方法，比如`POST`，你可以在`fetch`方法的第二个参数中定义它。第二个参数是一个对象，你可以在其中定义多个请求设置。以下源代码使用`POST`方法发出请求：

```java
fetch('http://someapi.com', {method: 'POST'})
.then(response => response.json())
.then(result => console.log(result))
.catch(error => console.error(error));
```

您还可以在第二个参数中添加标头。以下`fetch`调用包含`'Content-Type' : 'application/json'`标头：

```java
fetch('http://someapi.com', 
 {
  method: 'POST', 
  headers:{'Content-Type': 'application/json'}
 }
.then(response => response.json())
.then(result => console.log(result))
.catch(error => console.error(error));
```

如果您必须在请求体中发送 JSON 编码的数据，语法如下：

```java
fetch('http://someapi.com', 
 {
  method: 'POST', 
  headers:{'Content-Type': 'application/json'},
  body: JSON.stringify(data)
 }
.then(response => response.json())
.then(result => console.log(result))
.catch(error => console.error(error));
```

您还可以使用其他库进行网络调用。一个非常流行的库是`axios`（[`github.com/axios/axios`](https://github.com/axios/axios)），你可以使用 npm 将其安装到你的 React 应用程序中。axios 有一些好处，比如自动转换 JSON 数据。以下代码显示了使用`axios`进行示例调用：

```java
axios.get('http://someapi.com')
.then(response => console.log(response))
.catch(error => console.log(error));
```

`axios`有自己的调用方法，用于不同的 HTTP 方法。例如，如果您想发出`DELETE`请求，`axios`提供了`axios.delete`方法。

# 实际示例

我们将介绍使用一些开放的 REST API 的两个示例。首先，我们将制作一个 React 应用程序，显示伦敦的当前天气。天气是从**OpenWeatherMap**([`openweathermap.org/`](https://openweathermap.org/))获取的。你需要注册到 OpenWeatherMap 获取 API 密钥。我们将使用免费账户，因为这对我们的需求已经足够。注册后，转到你的账户信息找到 API 密钥选项卡。在那里你会看到你需要用于 React 天气应用程序的 API 密钥：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/5c8092f6-ddb2-4eb7-997e-0f8efb109fcc.png)

让我们用`create-react-app`创建一个新的 React 应用程序。打开你正在使用的 PowerShell 或其他终端，并输入以下命令：

```java
create-react-app weatherapp
```

移动到`weatherApp`文件夹：

```java
cd weatherapp
```

用以下命令启动你的应用程序：

```java
npm start
```

用 VS Code 打开你的项目文件夹，并在编辑器视图中打开`App.js`文件。删除`<div className="App"></div>`分隔符内的所有代码。现在你的源代码应该如下所示：

```java
import React, { Component } from 'react';
import './App.css';

class App extends Component {
  render() {
    return (
      <div className="App">
      </div>
    );
  }
}

export default App;
```

如果你已经在 VS Code 中安装了*Reactjs code snippets*，你可以通过输入`con`来自动创建一个默认构造函数。对于典型的 React 方法，还有许多不同的快捷方式，比如`cdm`代表`componentDidMount()`。

首先，我们添加一个必要的构造函数和状态。我们将在我们的应用程序中显示温度、描述和天气图标，因此，我们定义了三个状态值。我们还将添加一个布尔状态来指示获取加载的状态。以下是构造函数的源代码：

```java
  constructor(props) {
    super(props);
    this.state = {temp: 0, desc: '', icon: '', loading: true}
  }
```

当你使用 REST API 时，你应该首先检查响应，以便能够从 JSON 数据中获取值。在下面的示例中，你可以看到返回伦敦当前天气的地址。将地址复制到浏览器中，你可以看到 JSON 响应数据：

```java
api.openweathermap.org/data/2.5/weather?q=London&units=Metric&APIkey=YOUR_KEY
```

从响应中，你可以看到可以使用`main.temp`来访问`temp`。`description`和`icon`在`weather`数组中，该数组只有一个元素，我们可以使用`weather[0].description`和`weather[0].icon`来访问它：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/58d33570-1810-4bd8-b7bc-ee969bf1982b.png)

在`componentDidMount()`生命周期方法中使用`fetch`进行 REST API 调用。在成功响应后，我们将天气数据保存到状态中，并将`loading`状态更改为`false`。状态更改后，组件将重新渲染。我们将在下一步中实现`render()`方法。以下是`componentDidMount()`方法的源代码：

```java
  componentDidMount() {
    fetch('http://api.openweathermap.org/data/2.5/weather?
      q=London&units=Metric
      &APIkey=c36b03a963176b9a639859e6cf279299')
    .then(response => response.json()) 
    .then(responseData => {
      this.setState({ 
         temp: responseData.main.temp,
         desc: responseData.weather[0].description,
         icon: responseData.weather[0].icon, 
         loading: false 
       })
     })
     .catch(err => console.error(err)); 
  }
```

在添加了`componentDidMount()`方法后，当组件挂载时会进行请求。我们可以使用 React Developer Tool 检查一切是否正确。在浏览器中打开你的应用程序，并打开浏览器开发者工具的 React 选项卡。现在你可以看到状态已更新为响应中的值。你还可以从网络选项卡中检查请求状态是否为 200 OK：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/6a5fcf09-fa18-4fe1-a7c8-056e19dfe85f.png)

最后，我们实现`render()`方法来显示天气数值。我们使用条件渲染，否则，我们会因为第一次渲染调用中没有图像代码而出现错误，图像上传也不会成功。为了显示天气图标，我们必须在图标代码之前添加`http://openweathermap.org/img/w/`，在图标代码之后添加`.png`。然后，我们可以将连接的图像 URL 设置为`img`元素的`src`属性。温度和描述显示在段落元素中。`°C` HTML 实体显示摄氏度符号：

```java
  render() {
    const imgSrc =    `http://openweathermap.org/img/w/${this.state.icon}.png`;

    if (this.state.loading) {
      return <p>Loading</p>;
    }
 else {
      return (
        <div className="App">
          <p>Temperature: {this.state.temp} °C</p>
          <p>Description: {this.state.desc}</p>
          <img src={imgSrc} alt="Weather icon" />
        </div>
      );
    }
  }
```

现在你的应用程序应该准备好了。当你在浏览器中打开它时，它应该看起来像下面的图片：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/d49416f9-8258-45c6-abf7-b97051ccffb0.png)

整个`App.js`文件的源代码如下所示：

```java
import React, { Component } from 'react';
import './App.css';

class App extends Component {
  constructor(props) {
    super(props);
    this.state = {temp: 0, desc: '', icon: ''}
  }

  componentDidMount() {
    fetch('http://api.openweathermap.org/data/2.5/weather?
      q=London&units=Metric&APIkey=YOUR_KEY')
    .then(response => response.json()) 
    .then(responseData => {
      this.setState({ 
         temp: responseData.main.temp,
        desc: responseData.weather[0].description,
        icon: responseData.weather[0].icon 
       }); 
    });
  }

  render() {
    const imgSrc = 'http://openweathermap.org/img/w/' + 
    this.state.icon + '.png';

```

```java
    return (
      <div className="App">
        <p>Temperature: {this.state.temp}</p>
        <p>Description: {this.state.desc}</p>
        <img src={imgSrc} />
      </div>
    );
  }
}

export default App;
```

在第二个示例中，我们将使用 GitHub API 按关键字获取存储库。使用与上一个示例相同的步骤，创建一个名为`restgithub`的新 React 应用程序。启动应用程序并用 VS Code 打开项目文件夹。

从`App.js`文件中的`<div className="App"></div>`分隔符中删除额外的代码，然后您的`App.js`代码应如下示例代码所示：

```java
import React, { Component } from 'react';
import './App.css';

class App extends Component {
  render() {
    return (
      <div className="App">
      </div>
    );
  }
}

export default App;
```

GitHub REST API 的 URL 如下：

```java
https://api.github.com/search/repositories?q=KEYWORD
```

让我们通过在浏览器中输入 URL 并使用`react`关键字来检查 JSON 响应。从响应中，我们可以看到存储库作为名为`items`的 JSON 数组返回。从各个存储库中，我们将显示`full_name`和`html_url`的值。我们将在表中呈现数据，并使用`map`函数将值转换为表行，就像在上一章中所示的那样：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/c321abb3-1e98-45ad-801a-871562227449.png)

我们将使用用户输入的关键字进行 REST API 调用。因此，我们不能在`componentDidMount()`方法中进行 REST API 调用，因为在那个阶段，我们没有用户输入可用。实现这一点的一种方法是创建一个输入字段和按钮。用户在输入字段中输入关键字，当按下按钮时进行 REST API 调用。我们需要两个状态，一个用于用户输入，一个用于 JSON 响应中的数据。以下是`constructor`的源代码。数据状态的类型是数组，因为存储库作为 JSON 数组返回在响应中：

```java
  constructor(props) {
    super(props);
    this.state = { keyword: '', data: [] };
  }
```

接下来，我们将在`render()`方法中实现输入字段和按钮。我们还必须为输入字段添加一个更改监听器，以便能够将输入值保存到名为`keyword`的状态中。按钮有一个点击监听器，调用将使用给定关键字进行 REST API 调用的函数。

```java
  fetchData = () => {
    // REST API call comes here
  }

  handleChange = (e) => {
    this.setState({keyword: e.target.value});
  }

  render() {
    return (
      <div className="App">
        <input type="text" onChange={this.handleChange} />
        <button onClick={this.fetchData} value={this.state.keyword} >Fetch</button>
      </div>
    );
  }
```

在`fetchData`函数中，我们使用模板文字将`url`和`keyword`状态连接起来。然后我们将响应中的`items`数组保存到名为`data`的状态中。以下是`fetchData`函数的源代码：

```java
  fetchData = () => {
    const url = `https://api.github.com/search/repositories?
       q=${this.state.keyword}`;
    fetch(url)
    .then(response => response.json()) 
    .then(responseData => {
      this.setState({data : responseData.items }); 
    }); 
  } 
```

在`render`方法中，我们首先使用`map`函数将`data`状态转换为表行。`url`存储库将是链接元素的`href`：

```java
  render() {
    const tableRows = this.state.data.map((item, index) => 
      <tr key={index}><td>{item.full_name}</td>
      <td><a href={item.html_url}>{item.html_url}</a></td></tr>); 

    return (
      <div className="App">
        <input type="text" onChange={this.handleChange} />
        <button onClick={this.fetchData} value={this.state.keyword} >Fetch</button>
        <table><tbody>{tableRows}</tbody></table>
      </div>
    );
```

以下屏幕截图显示了在 REST API 调用中使用 React 关键字时的最终应用程序：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/57460be9-dbdb-4481-a62d-4d545ba5ea6a.png)

整个`App.js`文件的源代码如下所示：

```java
import React, { Component } from 'react';
import './App.css';

class App extends Component {
  constructor(props) {
    super(props);
    this.state = { keyword: '', data: [] };
  }

  fetchData = () => {
    const url = `https://api.github.com/search/repositories?
      q=${this.state.keyword}`;
    fetch(url)
    .then(response => response.json()) 
    .then(responseData => {
      this.setState({data : responseData.items }); 
    }); 
  }

  handleChange = (e) => {
    this.setState({keyword: e.target.value});
  }

  render() {
    const tableRows = this.state.data.map((item, index) => 
      <tr key={index}><td>{item.full_name}</td>
      <td><a href={item.html_url}>{item.html_url}</a></td></tr>); 

    return (
      <div className="App">
        <input type="text" onChange={this.handleChange} />
        <button onClick={this.fetchData} 
        value={this.state.keyword} >Fetch</button>
        <table><tbody>{tableRows}</tbody></table>
      </div>
    );
  }
}
```

# 摘要

在这一章中，我们专注于使用 React 进行网络编程。我们从使异步网络调用更容易实现的 promise 开始。这是一种更清洁的处理调用的方式，比传统的回调函数要好得多。在本书中，我们使用 Fetch API 进行网络编程，因此我们介绍了使用`fetch`的基础知识。我们实现了两个实用的 React 应用程序，调用了开放的 REST API，并在浏览器中呈现了响应数据。在下一章中，我们将介绍一些有用的 React 组件，这些组件将在我们的前端中使用。

# 问题

1.  什么是 promise？

1.  什么是`fetch`？

1.  您应该如何从 React 应用程序调用 REST API？

1.  您应该如何处理 REST API 调用的响应？

# 进一步阅读

Packt 还有其他很好的资源可供学习 React：

+   [`www.packtpub.com/web-development/getting-started-react`](https://www.packtpub.com/web-development/getting-started-react)

+   [`www.packtpub.com/web-development/react-16-essentials-second-edition`](https://www.packtpub.com/web-development/react-16-essentials-second-edition)


# 第八章：React 的有用第三方组件

React 是基于组件的，我们可以找到许多有用的第三方组件，可以在我们的应用程序中使用。在本章中，我们将看一些组件，我们将在前端中使用。我们将看到如何找到合适的组件，以及如何在自己的应用程序中使用这些组件。

在本章中，我们将看以下内容：

+   如何找到第三方 React 组件

+   如何安装组件

+   如何使用 React 表格组件

+   如何使用模态窗口组件

+   如何使用 Material UI 组件库

+   如何在 React 中管理路由

# 技术要求

在本书中，我们使用的是 Windows 操作系统，但所有工具都适用于 Linux 和 macOS，因为 Node.js 和`create-react-app`必须安装。

# 使用第三方 React 组件

有许多不同目的的不错的 React 组件可用。我们的第一个任务是找到适合您需求的组件。搜索组件的一个好网站是 JS.coach ([`js.coach/`](https://js.coach/))。您只需输入关键字，搜索，并从框架列表中选择 React。在下面的屏幕截图中，您可以看到搜索 React 表组件的结果：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/f994a30d-033c-4a6a-a3be-1d1b9ec22336.png)

另一个获取 React 组件的好来源是 Awesome React Components ([`github.com/brillout/awesome-react-components`](https://github.com/brillout/awesome-react-components))。

组件通常有良好的文档，帮助您在自己的 React 应用程序中使用它们。让我们看看如何将第三方组件安装到我们的应用程序中并开始使用它。转到 JS.coach 网站，输入`list`以搜索输入字段，并按 React 进行过滤。从搜索结果中，您可以找到名为`react-tiny-virtual-list`的列表组件：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/b1d661a3-734f-4496-af43-f35249f99835.png)

单击组件链接以查看有关组件的更详细信息。通常，您可以在那里找到安装说明，以及如何使用组件的一些简单示例。信息页面通常提供组件网站或 GitHub 存储库的地址，您可以在那里找到完整的文档：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/cf6b1ef2-f13a-4cc4-a661-b08087c54ecb.png)

从组件的信息页面可以看出，使用`npm`安装组件。命令的语法如下：

```java
npm install component_name --save
```

或者，如果您使用 Yarn，则如下所示：

```java
yarn add component_name
```

`--save`参数将组件的依赖项保存到 React 应用程序根文件夹中的`package.json`文件中。如果您使用的是 npm 5 或更高版本，则默认情况下会执行此操作，无需`--save`参数。对于 Yarn，您不必指定，因为它默认保存组件依赖项。

现在我们将`react-tiny-virtual-list`组件安装到我们在上一章中创建的`myapp` React 应用程序中。您必须转到应用程序的根文件夹，并输入以下命令：

```java
npm install react-tiny-virtual-list --save
```

如果您打开应用程序根文件夹中的`package.json`文件，您会看到该组件现在已添加到依赖项中：

```java
{
  "name": "myapp",
  "version": "0.1.0",
  "private": true,
  "dependencies": {
    "react": "¹⁶.3.2",
    "react-dom": "¹⁶.3.2",
    "react-scripts": "1.1.4",
    "react-tiny-virtual-list": "².1.4"
  },
  "scripts": {
    "start": "react-scripts start",
    "build": "react-scripts build",
    "test": "react-scripts test --env=jsdom",
    "eject": "react-scripts eject"
  }
}
```

安装的组件保存在应用程序的`node_modules`文件夹中。如果打开该文件夹，您应该会找到`react-tiny-virtual-list`文件夹：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/0856b3ab-d105-43ee-bef5-255de4baf67b.png)

现在，如果您将 React 应用程序源代码推送到 GitHub，则不应包括`node_modules`，因为该文件夹非常大。`create-react-app`包含一个`.gitignore`文件，该文件将`node_modules`文件夹从存储库中排除。`.gitignore`文件的内容如下：

```java
# See https://help.github.com/ignore-files/ for more about ignoring files.

# dependencies
/node_modules

# testing
/coverage

# production
/build

# misc
.DS_Store
.env.local
.env.development.local
.env.test.local
.env.production.local

npm-debug.log*
yarn-debug.log*
yarn-error.log*
```

想法是，当您从 GitHub 克隆应用程序时，您键入`npm install`命令，该命令从`package.json`文件中读取依赖项，并将其下载到您的应用程序中。

开始使用已安装组件的最后一步是将其导入到您使用它的文件中：

```java
import VirtualList from 'react-tiny-virtual-list';
```

# React 表格

React Table ([`react-table.js.org`](https://react-table.js.org))是用于 React 应用程序的灵活表格组件。它具有许多有用的功能，如过滤、排序和透视。让我们使用在上一章中创建的 GitHub REST API 应用程序：

1.  安装`react-table`组件。打开 PowerShell 并移动到`restgithub`文件夹，这是应用程序的根文件夹。通过输入以下命令来安装组件：

```java
 npm install react-table --save
```

1.  使用 VS Code 打开`App.js`文件，并删除`render()`方法中的所有代码，除了包含按钮和输入字段的`return`语句。现在`App.js`文件应该如下所示：

```java
      import React, { Component } from 'react';
      import './App.css';

      class App extends Component {
        constructor(props) {
          super(props);
          this.state = { keyword: '', data: [] };
        }

        fetchData = () => {
          const url = `https://api.github.com/search/repositories?
           q=${this.state.keyword}`;
          fetch(url)
```

```java
          .then(response => response.json()) 
          .then(responseData => {
            this.setState({data : responseData.items }); 
          }); 
        }

        handleChange = (e) => {
          this.setState({keyword: e.target.value});
        }

        render() {
          return (
            <div className="App">
              <input type="text" onChange={this.handleChange} />
              <button onClick={this.fetchData} value=
               {this.state.keyword} >Fetch</button>
            </div>
          );
        }
      }

      export default App;
```

1.  在`App.js`文件的开头添加以下行来导入`react-table`组件和样式表：

```java
      import ReactTable from "react-table";
      import 'react-table/react-table.css';
```

1.  要填充 React Table 的数据，你必须将数据传递给组件的数据属性。数据可以是数组或对象，因此我们可以使用我们的状态，称为`data`。列使用列属性进行定义，该属性是必需的：

```java
      <ReactTable
        data={data}
        columns={columns}
      />
```

1.  我们将通过在`render()`方法中创建列对象数组来定义我们的列。在列对象中，你至少需要定义列的标题和数据访问器。数据访问器的值来自我们的 REST API 响应数据。你可以看到我们的响应数据包含一个名为`owner`的对象，我们可以使用`owner.field_name`语法显示这些值：

```java
      const columns = [{
         Header: 'Name',  // Header of the column  
         accessor: 'full_name' // Value accessor
        }, {
         Header: 'URL',
         accessor: 'html_url',
        }, {
         Header: 'Owner',
         accessor: 'owner.login',
      }]
```

1.  将 React Table 组件添加到我们的`render()`方法中，然后该方法的源代码如下：

```java
      render() {
        const columns = [{
          Header: 'Name', // Header of the column
          accessor: 'full_name' // Value accessor
        }, {
          Header: 'URL',
          accessor: 'html_url',
        }, {
          Header: 'Owner',
          accessor: 'owner.login',
        }]

        return (
          <div className="App">
            <input type="text" onChange={this.handleChange} />
            <button onClick={this.fetchData} 
             value={this.state.keyword} >Fetch</button>
            <ReactTable
              data={this.state.data}
              columns={columns}

            />
          </div>
        );
      }
```

1.  运行应用程序并导航到`localhost:3000`。表看起来非常不错。它默认提供了排序和分页功能：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/23376f91-4b30-4a06-9879-499da8c4f3ab.png)

过滤默认情况下是禁用的，但你可以使用`ReactTable`组件中的`filterable`属性来启用它。你还可以设置表的页面大小：

```java
<ReactTable
   data={this.state.data}
   columns={columns}
   filterable={true}
   defaultPageSize = {10}
/>
```

现在你应该在你的表中看到过滤元素。你可以使用任何列进行过滤，但也可以在列级别设置过滤和排序：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/608986ae-592d-44f8-9fd7-42390b471a3e.png)

你可以从 React Table 网站上找到表格和列的不同属性。

单元格渲染器可用于自定义表格单元格的内容。以下示例显示了如何将按钮呈现为表格单元格。单元格渲染器中的函数将`value`作为参数传递，而在这种情况下，值将是列的访问器中定义的`full_name`。另一个选项是传递一个行，它将整个`row`对象传递给函数。然后你需要定义`btnClick`函数，当按钮被按下时将被调用，你可以对发送到函数的值进行操作：

```java
render() {
  const columns = [{
    Header: 'Name', // Header of the column
    accessor: 'full_name' // Value accessor
  }, {
    Header: 'URL',
    accessor: 'html_url',
  }, {
    Header: 'Owner',
    accessor: 'owner.login',
  }, {
    id: 'button',
    sortable: false,
    filterable: false,
    width: 100,
    accessor: 'full_name',
```

```java
    Cell: ({value}) => (<button className="btn btn-default btn-link" onClick=                            {() => {this.btnClick(value)}}>Press me</button>)
}]
```

以下是带有按钮的表格的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/84d1aae2-eb68-4223-9266-3a6715e609cc.png)

# 模态窗口组件

模态窗口在创建 CRUD 应用程序时非常有用。我们将创建一个简单的购物清单应用程序，用户可以使用模态窗口添加新项目。我们在示例中将使用的模态窗口组件是`react-skylight`（[`marcio.github.io/react-skylight/`](https://marcio.github.io/react-skylight/)）：

1.  创建一个名为`shoppinglist`的新 React 应用程序，并使用以下命令安装`react-skylight`：

```java
 npm install react-skylight --save
```

1.  使用 VS Code 打开`app`文件夹，并在代码编辑器中打开`App.js`文件。在`App.js`组件中，我们只需要一个状态来保存购物清单项目。一个购物清单项目包含两个字段——产品和数量。我们还需要一个方法来向列表中添加新项目。以下是构造函数和向列表中添加新项目的方法的源代码。在`addItem`方法中，我们使用了扩展符号（`...`），用于在现有数组的开头添加新项目：

```java
      constructor(props) {
        super(props);
        this.state={ items: [] };
      }

      addItem = (item) => {
        this.setState({items: [item, ...this.state.items]});
      }
```

1.  添加一个新组件来添加购物项。在应用程序的根文件夹中创建一个名为`AddItem.js`的新文件。该组件将使用 React Skylight 模态表单，因此让我们导入`react-skylight`。在`render()`方法中的 React Skylight 组件内，我们将添加两个输入字段（产品和数量）和一个调用`addItem`函数的按钮。为了能够调用`App.js`组件中的`addItem`函数，我们必须在渲染`AddItem`组件时将其作为 prop 传递。在 React Skylight 组件之外，我们将添加一个按钮，当按下时打开模态表单。该按钮是组件初始渲染时唯一可见的元素，并调用 React Skylight 的`show()`方法来打开模态表单。我们还必须处理输入字段的更改事件，以便访问已输入的值。当模态表单内的按钮被点击时，将调用`addItem`函数，并使用 React Skylight 的`hide()`方法关闭模态表单。该函数从输入字段值创建一个对象，并调用`App.js`组件的`addItem`函数，最终向状态数组中添加一个新项目并重新渲染用户界面：

```java
import React, { Component } from 'react';
import SkyLight from 'react-skylight';

class AddItem extends Component {
  constructor(props) {
    super(props);
  }

  // Create new shopping item and calls addItem function. 
  // Finally close the modal form
  addItem = () => {
    const item = {product: this.state.product,
     amount: this.state.amount};
    this.props.additem(item);
    this.addform.hide();
  }

  handleChange = (e) => {
    this.setState({[e.target.name]: e.target.value});
  }

  render() {
    return (
      <div>
        <section>
          <button onClick={() => this.addform.show()}>Add
           Item</button>
        </section>
        <SkyLight 
          hideOnOverlayClicked 
          ref={ref => this.addform = ref} 
          title="Add item">
          <input type="text" name="product"
           onChange={this.handleChange} 
           placeholder="product" /><br/>
          <input type="text" name="amount"
           onChange={this.handleChange} 
           placeholder="amount" /><br/>
          <button onClick={this.addItem}>Add</button>
        </SkyLight> 
      </div>
    );
  }
}

export default AddItem;
```

1.  在`App.js`文件中修改`render()`方法。将`AddItem`组件添加到`render()`方法中，并将`addItem`函数作为 prop 传递给`AddItem`组件。在方法的开头，我们使用`map`函数将项目转换为`listItems`(`<li></li>`)：

```java
// App.js
render() {
  const listItems = this.state.items.map((item, index) => 
    <li key={index}>{item.product} {item.amount}</li>)

  return (
    <div className="App">
      <h2>Shopping list</h2>
      <AddItem additem={this.addItem}/>
      <ul>{listItems}</ul>
    </div>
  );
}
```

现在打开应用程序时，您将看到一个空列表和一个添加新项目的按钮：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/7a8d772a-6ae4-433a-809b-6c9ef2dfc910.png)

当您按下“Add Item”按钮时，模态表单将打开：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/40899635-da48-4bb4-9e43-4efa66de2624.png)

在输入框中输入一些值，然后按下“Add”按钮。模态表单将关闭，并且新项目将显示在列表中：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/c0a470fd-74c3-40d0-8e8c-36dbe27acdf6.png)

# Material UI 组件库

Material UI 是实现 Google 的 Material Design 的 React 组件库。它包含许多不同的组件，如按钮、列表、表格和卡片，您可以使用它们来获得一个漂亮和统一的用户界面。我们将继续使用购物清单应用程序，并开始使用 Material UI 来设计用户界面：

1.  使用 VS Code 打开购物清单应用程序。在根文件夹中键入以下命令来安装 Material UI 到 PowerShell 或您正在使用的任何合适的终端中：

```java
npm install @material-ui/core --save

OR with yarn

yarn add @material-ui/core
```

1.  我们准备开始使用 Material UI 组件。首先，我们将更改`AddItem.js`文件中的按钮，以使用 Material UI 的`Button`组件。我们必须导入`Button`组件，然后在`render()`方法中使用它。Material UI 文档中可以找到`Button`的不同 props：

```java
// Import RaisedButton
import RaisedButton from '@material-ui/core/Button';

// Use RaisedButton in render() method
render() {
  return (
    <div>
      <section>
        <Button onClick={() => this.addform.show()} 
         variant="raised" color="primary">
         Add Item</ Button>
      </section>
      <SkyLight 
        hideOnOverlayClicked 
        ref={ref => this.addform = ref} 
        title="Add item">
        <input type="text" name="product" 
         onChange={this.handleChange} 
         placeholder="product" /><br/>
        <input type="text" name="amount" 
         onChange={this.handleChange} 
         placeholder="amount" /><br/>
        <Button onClick={this.addItem} 
         variant="default"  >Add</ Button>
      </SkyLight> 
    </div>
  );
}
```

现在应用程序使用`RaisedButton`，效果如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/9bd9c0fb-64a3-451d-abe3-4e875b490adb.png)

1.  将`AddItem.js`中的输入字段更改为使用 Material UI 的`TextField`组件。步骤与按钮相同。导入`TextField`组件，然后在`render()`方法中使用它：

```java
// Import TextField component
import TextField from '@material-ui/core/TextField';

// Use TextField in render() method
render() {
  return (
    <div>
      <section>
        <Button onClick={() => this.addform.show()} 
         variant="raised" color="primary">
         Add Item</ Button>
      </section>
      <SkyLight 
        hideOnOverlayClicked 
        ref={ref => this.addform = ref} 
        title="Add item">
        <TextField type="text" name="product" 
          onChange={this.handleChange} 
          placeholder="product" /><br/>
        <TextField type="text" name="amount" 
          onChange={this.handleChange} 
          placeholder="amount" /><br/>
        <Button onClick={this.addItem} 
         variant="default"  >Add</ Button>     
      </SkyLight> 
    </div>
  );
}
```

在更改后，您的表单应如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/ac8e042d-fe61-4654-9c1e-6f55e9e370fe.png)

1.  在`App.js`文件中更改我们的列表，使用 Material UI 的`List`和`ListItem`组件。导入这些组件，并在创建`listItems`和渲染`List`的地方使用`ListItem`。我们将在`ListItemText`组件的次要文本中显示产品的数量：

```java
// Import List, ListItem and ListItemText components
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemText from '@material-ui/core/ListItemText';

// Use List and ListItem in render() method
render() {
 // Use ListItem component here instead of li 
    const listItems = this.state.items.map((item, index) => 
     <ListItem key={index}>
     <ListItemText primary={item.product} secondary={item.amount} />
     </ListItem>)
  return (
    <div className="App">
      <h2>Shopping list</h2>
      <AddItem additem={this.addItem}/>
      <List>{listItems}</List>
    </div>
  );
}
```

现在用户界面如下所示。通过少量的工作，用户界面现在更加精致：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/8dbdd374-f4e9-4c2b-bca5-05f0f3a0943d.png)

# 路由

React 中有多种可用的路由解决方案。最流行的解决方案是 React Router（[`github.com/ReactTraining/react-router`](https://github.com/ReactTraining/react-router)）。对于 Web 应用程序，React Router 提供了一个名为`react-router-dom`的包。

要开始使用 React Router，我们必须使用以下命令进行安装：

```java
npm install react-router-dom --save
```

在`react-router-dom`中有四个不同的组件需要实现路由。`BrowserRouter`是用于基于 Web 的应用程序的路由器。`Route`组件在给定位置匹配时呈现定义的组件。以下是`Route`组件的两个示例。第一个示例在用户导航到`/contact`端点时呈现`Contact`组件。您还可以使用`Route`组件进行内联呈现，如第二个示例所示：

```java
<Route path="/contact" component={Contact} />
// Route with inline rendering
<Route path="/links" render={() => <h1>Links</h1>} />
```

`Switch`组件包装多个`Route`组件。`Link`组件提供了应用程序的导航。以下示例显示了`Contact`链接，并在单击链接时导航到`/contact`端点：

```java
<Link to="/contact">Contact</Link>
```

以下示例显示了如何在实践中使用这些组件。让我们使用`create-react-app`创建一个名为`routerapp`的新 React 应用程序。使用 VS Code 打开应用程序文件夹，并打开`App.js`文件以编辑视图。从`react-router-dom`包中导入组件，并从渲染方法中删除额外的代码。修改后，您的`App.js`源代码应如下所示：

```java
import React, { Component } from 'react';
import './App.css';
import { BrowserRouter, Switch, Route, Link } from 'react-router-dom'

class App extends Component {
  render() {
    return (
      <div className="App">
      </div>
    );
  }
}

export default App;
```

让我们首先创建两个简单的组件，我们可以在路由中使用。在应用程序根文件夹中创建两个名为`Home.js`和`Contact.js`的新文件。只需向`render()`方法中添加标题，以显示组件的名称。请参阅以下组件的代码：

```java
//Contact.js
import React, { Component } from 'react';

class Contact extends Component {
  render() {
    return (
      <div>
        <h1>Contact.js</h1>
      </div>
    );
  }
}

export default Contact;

// Home.js
import React, { Component } from 'react';

class Home extends Component {
  render() {
    return (
      <div>
        <h1>Home.js</h1>
      </div>
    );
  }
}

export default Links;
```

打开`App.js`文件，让我们添加一个路由器，允许我们在组件之间导航：

```java
import React, { Component } from 'react';
import './App.css';
import { BrowserRouter, Switch, Route, Link } from 'react-router-dom'
import Contact from './Contact';
import Home from './Home';

class App extends Component {
  render() {
    return (
      <div className="App">
        <BrowserRouter>
          <div>
            <Link to="/">Home</Link>{' '}
            <Link to="/contact">Contact</Link>{' '} 
            <Link to="/links">Links</Link>{' '} 
            <Switch>
              <Route exact path="/" component={Home} />
              <Route path="/contact" component={Contact} />
              <Route path="/links" render={() => <h1>Links</h1>} />
              <Route render={() => <h1>Page not found</h1>} />
            </Switch>
          </div>
        </BrowserRouter>
      </div>
    );
  }
}

export default App;
```

现在，当您启动应用程序时，您将看到链接和`Home`组件，该组件显示在根端点（`localhost:3030/`）中，如第一个`Route`组件中所定义。第一个`Route`组件中的`exact`关键字表示路径必须完全匹配。如果删除该关键字，则路由始终转到`Home`组件：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/dc6583d7-4b81-4746-a4d5-a1c1d4188a4e.png)

当您点击`Contact`链接时，将呈现`Contact`组件：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/1f11cf3a-14b9-48bd-bfee-a5e4dc0a178a.png)

# 总结

在本章中，我们学习了如何使用第三方 React 组件。我们熟悉了几个我们将在前端中使用的组件。React Table 是带有内置功能（如排序、分页和过滤）的表组件。React Skylight 是我们将在前端中使用的模态表单组件，用于创建添加和编辑项目的表单。Material UI 是提供多个实现 Google Material Design 的用户界面组件的组件库。我们还学习了如何在 React 应用程序中使用 React Router 进行路由。在下一章中，我们将为前端开发构建一个环境。

# 问题

1.  您应该如何找到 React 的组件？

1.  您应该如何安装组件？

1.  您应该如何使用 React Table 组件？

1.  您应该如何使用 React 创建模态表单？

1.  您应该如何使用 Material UI 组件库？

1.  您应该如何在 React 应用程序中实现路由？

# 进一步阅读

Packt 有其他很好的资源可以学习 React：

+   [`www.packtpub.com/web-development/getting-started-react`](https://www.packtpub.com/web-development/getting-started-react)

+   [`www.packtpub.com/web-development/react-16-essentials-second-edition`](https://www.packtpub.com/web-development/react-16-essentials-second-edition)


# 第九章：为我们的 Spring Boot RESTful Web Service 设置前端

本章解释了开始开发前端部分所需的步骤。我们首先会定义我们正在开发的功能。然后我们将对用户界面进行模拟。作为后端，我们将使用我们在第四章中的 Spring Boot 应用程序，*保护和测试您的后端*。我们将使用后端的未安全版本开始开发。最后，我们将创建我们将在前端开发中使用的 React 应用程序。

在本章中，我们将看到以下内容：

+   为什么以及如何进行模拟

+   为前端开发准备我们的 Spring Boot 后端

+   为前端创建 React 应用

# 技术要求

我们需要在第四章中创建的 Spring Boot 应用程序，*保护和测试您的后端*。

Node.js 和`create-react-app`应该已安装。

# 模拟用户界面

在本书的前几章中，我们创建了一个提供 REST API 的汽车数据库后端。现在是时候开始构建我们应用程序的前端了。我们将创建一个从数据库中列出汽车并提供分页、排序和过滤的前端。有一个按钮可以打开模态表单，将新车添加到数据库中。在汽车表的每一行中，都有一个按钮可以从数据库中删除汽车。表行也是可编辑的，可以通过单击行中的“保存”按钮将修改保存到数据库中。前端包含一个链接或按钮，可以将表中的数据导出到 CSV 文件中。

让我们从用户界面创建一个模拟。有很多不同的应用程序可以用来创建模拟，或者你甚至可以使用铅笔和纸。您还可以创建交互式模拟以演示一些功能。如果您已经完成了模拟，那么在开始编写任何实际代码之前，与客户讨论需求就会更容易。有了模拟，客户也更容易理解前端的想法并对其产生影响。与真实的前端源代码相比，对模拟的修改真的很容易和快速。

以下截图显示了我们汽车列表前端的模拟：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/92b24332-5307-4bbf-8723-da74f6572512.png)

当用户按下“New Car”按钮时打开的模态表单如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/f07703b7-c21b-441d-983a-585199ad9456.png)

# 准备 Spring Boot 后端

我们将使用后端的未安全版本开始前端开发。在第一阶段，我们实现所有 CRUD 功能并测试这些功能是否正常工作。在第二阶段，我们在后端启用安全性，并进行所需的修改，最后我们实现身份验证。

使用 Eclipse 打开 Spring Boot 应用程序，我们在第四章中创建的，*保护和测试您的后端*。打开定义 Spring Security 配置的`SecurityConfig.java`文件。暂时注释掉当前配置，并允许每个人访问所有端点。参见以下修改：

```java
  @Override
  protected void configure(HttpSecurity http) throws Exception {
   // Add this row to allow access to all endpoints
   http.cors().and().authorizeRequests().anyRequest().permitAll(); 

   /* Comment this out
   http.cors().and().authorizeRequests()
     .antMatchers(HttpMethod.POST, "/login").permitAll()
     .anyRequest().authenticated()
     .and()
     // Filter for the api/login requests
     .addFilterBefore(new LoginFilter("/login", authenticationManager()),
             UsernamePasswordAuthenticationFilter.class)
     // Filter for other requests to check JWT in header
     .addFilterBefore(new AuthenticationFilter(),
      UsernamePasswordAuthenticationFilter.class);
     */
    }
```

现在，如果您运行后端并使用 Postman 测试`http:/localhost:8080/api/cars`端点，您应该会在响应中获得所有汽车，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/eac8b4ea-1136-4f36-8db0-098bd92fb585.png)

# 为前端创建 React 项目

在开始编写前端代码之前，我们必须创建一个新的 React 应用程序：

1.  打开 PowerShell 或任何其他适合的终端。通过输入以下命令创建一个新的 React 应用程序：

```java
create-react-app carfront
```

1.  通过输入以下命令运行应用程序：

```java
npm start
```

或者，如果您正在使用 Yarn，请输入以下内容：

```java
yarn start
```

1.  使用 VS Code 打开`app`文件夹，删除任何额外的代码，并从`App.js`文件中更改标题文本。修改后，您的`App.js`文件源代码应如下所示：

```java
import React, { Component } from 'react';
import './App.css';

class App extends Component {
  render() {
    return (
      <div className="App">
        <header className="App-header">
          <h1 className="App-title">CarList</h1>
        </header> 
      </div>
    );
  }
}

export default App;
```

1.  让我们也减少标题的高度，并将颜色更改为`lightblue`。打开`App.css`文件，你可以在`App.js`文件的样式中找到。将标题高度从 150 减少到 50，并将颜色更改为`lightblue`：

```java
.App-header {
  background-color:lightblue;
  height: 50px;
  padding: 20px;
  color: white;
}
```

现在你的前端起点应该如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-flstk-dev-sprbt2-react/img/d015edb2-9242-4c7c-9029-fd0af0a225bf.png)

# 总结

在本章中，我们开始开发我们的前端，使用我们在第四章中创建的后端，*保护和测试您的后端*。我们定义了前端的功能，并创建了用户界面的模拟。我们从未经保护的后端开始了前端开发，因此，我们对 Spring Security 配置类进行了一些修改。我们还创建了我们在开发过程中将要使用的 React 应用程序。在下一章中，我们将开始为我们的前端添加 CRUD 功能。

# 问题

1.  为什么你应该做用户界面的模拟？

1.  你应该如何做用户界面的模拟？

1.  你应该如何从后端禁用 Spring Security？

# 进一步阅读

Packt 还有其他关于学习 React 的很棒的资源：

+   [`www.packtpub.com/web-development/getting-started-react`](https://www.packtpub.com/web-development/getting-started-react)

+   [`www.packtpub.com/web-development/react-16-essentials-second-edition`](https://www.packtpub.com/web-development/react-16-essentials-second-edition)
