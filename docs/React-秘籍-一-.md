# React 秘籍（一）

> 原文：[`zh.annas-archive.org/md5/AADE5F3EA1B3765C530CB4A24FAA7E7E`](https://zh.annas-archive.org/md5/AADE5F3EA1B3765C530CB4A24FAA7E7E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

现在存在大量用于 Web 开发的 JavaScript 库、框架和工具。然而，我们应该评估每种技术是否符合我们项目的要求。这就是为什么我想向你介绍 React，这是一个创建动态 UI 的最强大的库之一。它是目前由 Facebook 制作的最流行的库（不是框架）。我在不同的项目中使用过其他 JS 框架，比如 AngularJS（还有新版本的 Angular 2、4、5）、Backbone.js、Ember 和 Vue.js，但我可以告诉你，使用 React 我更喜欢开发新的 Web 应用程序。

React 改变了 Web 应用程序的开发方式，结合 Redux，我们得到了一个强大的前端架构，这不仅对有经验的开发人员有意义，也对刚开始前端之旅的人有意义。

本书介绍了 React 的所有工具和最佳实践，以简单易行的食谱形式呈现，本书中的所有食谱都是 100%实用的，每一个都有必要的代码来理解所有重要的内容。

欢迎来到一个更美好的未来，愿你在阅读和学习本书时玩得开心。

# 本书适合对象

本书可以被任何具有构建 Web 应用程序基础知识的开发人员使用。主要是 JavaScript 开发人员，但不限于任何其他类型的开发人员。

# 本书内容

[第一章]，使用 React 工作，React 是一个由 Facebook 制作的 JavaScript 库（MIT 许可证），用于创建交互式 UI。它用于创建动态和可重用的组件。React 最强大的地方在于它可以在客户端、服务器、移动应用甚至 VR 应用中使用。

[第二章]，征服组件和 JSX，本章包含了有关如何在 React 中创建组件的技巧。我们将学习如何创建 React 组件（类组件、纯组件和函数组件）并组织我们的项目结构。

[第三章]，处理事件、绑定和有用的 React 包，本章包含与处理事件、在 React 中绑定方法以及实现一些最有用的 React 包相关的技巧。

[第四章]，使用 React Router 为我们的应用程序添加路由，本章中，我们将学习如何使用 React Router v4 在我们的项目中添加动态路由。

第五章，《精通 Redux》，Redux 是 JavaScript 应用程序的可预测状态容器。这意味着 Redux 可以与原生 JavaScript 或诸如 Angular 和 jQuery 之类的框架/库一起使用。Redux 主要是一个负责发出状态更新和对操作做出响应的库。

第六章，《使用 Redux Form 创建表单》，表单是任何 Web 应用程序的基本部分，在接下来的教程中，我们将学习如何使用带有或不带有 Redux Form 的表单。

第七章，《使用 React 进行动画》，动画在任何 Web 应用程序中都很常见。自 CSS3 以来，动画已经变得普遍且易于实现。动画最常见的用途是过渡，其中您可以更改 CSS 属性并定义持续时间或延迟。

第八章，《使用 Node.js 和 MongoDB 以及 MySQL 创建 API》，Node.js 广泛用作 Web 应用程序的后端，因为它易于创建 API，并且其性能优于诸如 Java、PHP 和 Ruby 等技术。通常，使用 Node.js 的最流行方式是使用一个名为 Express 的框架。

第九章，《Apollo 和 GraphQL》，GraphQL 是一种应用层查询语言，可以与任何数据库一起使用，也是一个由 Facebook 创建的开源项目（MIT 许可证）。与 REST 的主要区别在于 GraphQL 不使用端点而是使用查询，并且受大多数服务器语言的支持，如 JavaScript（Node.js）、Go、Ruby、PHP、Java、Python 等。

第十章，《精通 Webpack 4.x》，Webpack 4 默认情况下不需要配置文件。在旧版本中，你必须有一个配置文件，但是当然，如果你需要根据项目需求自定义 Webpack 4，你仍然可以创建一个配置文件，这样会更容易配置。

[第十一章]（884074f8-0a8a-4e3f-b9dc-b817e0f3f7c3.xhtml）*，实现服务器端渲染*，如果你不太关心 SEO，可能就不需要担心服务器端渲染（SSR）。目前，Googlebot 支持客户端渲染（CSR），它可以在 Google 中索引我们的网站，但如果你关心 SEO，并且担心在其他搜索引擎（如 Yahoo、Bing 或 DuckDuckGo）上改善 SEO，那么使用服务器端渲染（SSR）是一个好方法。

[第十二章]（1daa68c4-442d-479f-b1b6-3efa80592901.xhtml）*，测试和调试，*测试和调试对于任何希望拥有最佳质量的项目都非常重要。不幸的是，许多开发人员不关心测试（单元测试），因为他们认为这会减慢开发速度，有些人把它留到项目结束时。根据我的个人经验，我可以说，从项目开始就进行测试会节省时间，因为最后你需要修复的错误会更少。

[第十三章]（863541f6-a9a0-4a1b-8d1b-e448571b24e1.xhtml）*，部署到生产环境*，现在是时候将我们的应用部署到生产环境并展示给世界。在这一章中，你将学习如何使用最好的云服务之一：Digital Ocean 来部署我们的 React 应用。

[第十四章]（2b2d55bd-c734-4907-9688-0a9e9a2ff0cb.xhtml）*，使用 React Native 工作*，React Native 是使用 JavaScript 和 React 构建移动应用的框架。许多人认为使用 React Native 可以制作一些“移动 Web 应用”或“混合应用”（如 Ionic、PhoneGap 或 Sencha），但实际上你构建的是原生应用，因为 React Native 会将你的 React 代码转换为 Android 的 Java 和 iOS 应用的 Objective-C。

# 要充分利用这本书

要掌握 React，你需要对 JavaScript 和 Node.js 有基本的了解。这本书主要针对 Web 开发人员，写作时做出了以下假设：

+   读者知道如何安装最新版本的 Node.js。

+   能理解 JavaScript ES6 语法的中级开发人员。

+   对 CLI 工具和 Node.js 语法有一些经验。

这本书也有一些内容适用于使用 React Native 的移动开发人员（iOS 和 Android），如果你是初学者，你应该学习如何安装 Android SDK 或使用 Xcode 安装 iOS 模拟器。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便将文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)上登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在“搜索”框中输入书名，然后按照屏幕上的说明进行操作。

下载文件后，请确保使用最新版本的解压缩软件解压文件夹：

+   Windows 用户可使用 WinRAR/7-Zip

+   Mac 用户可使用 Zipeg/iZip/UnRarX

+   Linux 用户可使用 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/React-Cookbook`](https://github.com/PacktPublishing/React-Cookbook)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自丰富图书和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。快去看看吧！

警告或重要说明会显示为这样。提示和技巧会显示为这样。


# 第一章：使用 React

在本章中，将涵盖以下示例：

+   介绍

+   在 React 中使用最新的 JS 功能

+   React 中有什么新功能？

+   在 Windows 上使用 React

# 介绍

React 是一个由 Facebook 制作的 JavaScript 库（MIT 许可证），用于创建交互式 UI。它用于创建动态和可重用的组件。React 最强大的地方在于它可以在客户端、服务器、移动应用程序甚至 VR 应用程序中使用。

在现代网络中，我们需要不断地操作 DOM；问题是这样做可能会严重影响我们应用程序的性能。React 使用虚拟 DOM，这意味着所有更新都发生在内存中（这比直接操作真实 DOM 更快）。与其他 JavaScript 框架（如 Angular、Vue 或 Backbone）相比，React 的学习曲线较短，主要是因为 React 代码大多是用现代 JavaScript（类、箭头函数、字符串模板等）编写的，而没有太多用于编写代码的模式，比如依赖注入，或者像 Angular 中的模板系统。

像 Airbnb、Microsoft、Netflix、Disney、Dropbox、Twitter、PayPal、Salesforce、Tesla 和 Uber 这样的公司在他们的项目中广泛使用 React。在这本书中，你将学习如何像他们一样使用最佳实践来开发你的 React 应用程序。

# 在 React 中使用最新的 JS 功能

正如我在介绍中所说，React 主要是用现代 JavaScript（ES6、ES7 和 ES8）编写的。如果你想利用 React，有一些现代 JS 功能是你应该掌握的，以获得你的 React 应用程序的最佳结果。在这个第一个示例中，我们将涵盖基本的 JS 功能，这样你就可以准备好开始在你的第一个 React 应用程序上工作了。

# 如何做到…

在本节中，我们将看到如何在 React 中使用最重要的 JS 功能：

1.  `let`和`const`：在 JavaScript 中声明变量的新方法是使用`let`或`const`。你可以使用`let`来声明可以在块作用域中改变其值的变量。`let`和`var`的区别在于，`let`是一个块作用域变量，不能是全局的，而用`var`可以声明一个全局变量，例如：

```jsx
 var name = 'Carlos Santana';
    let age = 30;

    console.log(window.name); // Carlos Santana
    console.log(window.age);  // undefined
```

1.  理解“块作用域”的最好方法是通过使用`var`和`let`声明`for`循环。首先，让我们使用`var`并看看它的行为：

```jsx
 for (var i = 1 ; i <= 10; i++) {
      console.log(i); // 1, 2, 3, 4... 10
    }

    console.log(i); // Will print the last value of i: 10
```

1.  如果我们用`let`写相同的代码，会发生这种情况：

```jsx
 for (let i = 1 ; i <= 10; i++) {
      console.log(i); // 1, 2, 3, 4... 10
    }

    console.log(i); // Uncaught ReferenceError: i is not defined
```

1.  使用`const`，我们可以声明常量，这意味着值不能被改变（除了数组和对象）：

```jsx
 const pi = 3.1416;
    pi = 5; // Uncaught TypeError: Assignment to constant variable.
```

1.  如果我们用`const`声明一个数组，我们可以操作数组元素（添加、删除或修改元素）：

```jsx
 const cryptoCurrencies = ['BTC', 'ETH', 'XRP'];

    // Adding ERT: ['BTC', 'ETH', 'XRP', 'ERT'];
    cryptoCurrencies.push('ERT'); 

 // Will remove the first element: ['ETH', 'XRP', 'ERT']; cryptoCurrencies.**shift**();

    **// Modifying an element**
    cryptoCurrencies[1] = 'LTC'; **// ['ETH', 'LTC', 'ERT'];**
```

1.  此外，使用对象，我们可以添加、删除或修改节点：

```jsx
 const person = {
      name: 'Carlos Santana',
      age: 30,
      email: 'carlos@milkzoft.com'
    };

    // Adding a new node...
    person.website = 'https://www.codejobs.com';

    // Removing a node...
    delete person.email;

    // Updating a node...
    person.age = 29;
```

1.  扩展运算符：扩展运算符（...）将可迭代对象分割成单独的值。在 React 中，它可以用于将值推入另一个数组，例如当我们想要通过利用`setState`向待办事项列表添加新项目时（这将在下一章中解释）：

```jsx
    this.setState({
      items: [
        ...this.state.items, // Here we are spreading the current items
        {
      task: 'My new task', // This will be a new task in our Todo list.
        }
      ]
    });
```

1.  此外，扩展运算符可以在 React 中用于在 JSX 中扩展属性（props）：

```jsx
    render() {
      const props = {};

      props.name = 'Carlos Santana';
      props.age = 30;
      props.email = 'carlos@milkzoft.com';

      return <Person {...props} />;
    }
```

1.  剩余参数：`rest`参数也用`...`表示。在函数中以`...`为前缀的最后一个参数称为剩余参数。剩余参数是一个数组，当参数的数量超过命名参数的数量时，它将包含函数的其余参数：

```jsx
 function setNumbers(param1, param2, ...args) {
      // param1 = 1
      // param2 = 2
      // args = [3, 4, 5, 6];
      console.log(param1, param2, ...args); // Log: 1, 2, 3, 4, 5, 6
    }

    setNumbers(1, 2, 3, 4, 5, 6);
```

1.  解构赋值：解构赋值是 React 中最常用的功能。它是一个表达式，允许我们将可迭代对象的值或属性分配给变量。通常，我们可以将组件的 props 转换为变量（或常量）：

```jsx
 // Imagine we are on our <Person> component and we are 
 // receiving the props (in this.props): name, age and email. render() { // Our props are: 
      // { name: 'Carlos Santana', age: 30, email: 
       'carlos@milkzoft.com' } console.log(this.props); 
      const { name, age, email } = this.props;

      // Now we can use the nodes as constants... console.log(name, age, email);

      return (
        <ul>
          <li>Name: {name}</li>
          <li>Age: {age}</li>
          <li>Email: {email}</li>
        </ul> ); }

    // Also the destructuring can be used on function parameters
    const Person = ({ name, age, email }) => (
      <ul>
        <li>Name: {name}</li>
        <li>Age: {age}</li>
        <li>Email: {email}</li>
      </ul>
    );
```

1.  箭头函数：ES6 提供了一种使用`=>`运算符创建函数的新方法。这些函数称为箭头函数。这种新方法有更短的语法，箭头函数是匿名函数。在 React 中，箭头函数用作绑定方法中的`this`对象的一种方式，而不是在构造函数中绑定它。

```jsx
 class Person extends Component {
      showProps = () => {
        console.log(this.props); // { name, age, email... }
      }

      render() {
        return (
          <div>
            Consoling props: {this.showProps()}
          </div>
        );
      }
    }
```

1.  模板文字：模板文字是使用反引号（` `）而不是单引号（''）或双引号（""）创建字符串的新方法。React 使用模板文字来连接类名或使用三元运算符呈现字符串：

```jsx
 render() {
      const { theme } = this.props;

      return (
        <div 
 className={`base ${theme === 'dark' ? 'darkMode' : 
         'lightMode'}`}        >
          Some content here...
        </div>
      );
    }
```

1.  映射：`map()`方法返回一个新数组，其中包含对调用数组中每个元素的提供函数的结果。在 React 中，映射的使用非常广泛，主要用于在 React 组件内呈现多个元素；例如，它可以用于呈现任务列表：

```jsx
 render() {
      const tasks = [
        { task: 'Task 1' },
        { task: 'Task 2' },
        { task: 'Task 3' }
      ];

      return (
        <ul>
          {tasks.map((item, key) => <li key={key}>{item.task}</li>}
        </ul>
      );
    }
```

1.  **Object.assign()**：`Object.assign()` 方法用于将一个或多个源对象的所有可枚举自有属性的值复制到目标对象中。它将返回目标对象。这个方法主要用于 Redux，用于创建不可变对象并将新状态返回给 reducers（Redux 将在第五章，*精通 Redux*中介绍）：

```jsx
    export default function coinsReducer(state = initialState, action) {
      switch (action.type) {
        case FETCH_COINS_SUCCESS: {
          const { payload: coins } = action;

          return Object.assign({}, state, {
            coins
          });
        }

        default:
         return state;
      }
    };
```

1.  **类**：JavaScript 类是 ES6 中引入的，主要是现有基于原型的继承的新语法。类是函数，不会被提升。React 使用类来创建类 *组件*：

```jsx
    import React, { Component } from 'react';

    class Home extends Component {
      render() {
        return <h1>I'm Home Component</h1>;
      }
    }

    export default Home;
```

1.  **静态方法**：静态方法不是在类的实例上调用的。相反，它们是在类本身上调用的。这些通常是实用函数，比如用来创建或克隆对象的函数。在 React 中，它们可以用来定义组件中的 `PropTypes`：

```jsx
 import React, { Component } from 'react';
    import PropTypes from 'prop-types';
    import logo from '../../images/logo.svg';

    class Header extends Component {
      static propTypes = {
        title: PropTypes.string.isRequired,
        url: PropTypes.string
      };

      render() {
        const { 
          title = 'Welcome to React', 
          url = 'http://localhost:3000' 
        } = this.props;

        return (
          <header className="App-header">
            <a href={url}>
              <img src={logo} className="App-logo" alt="logo" />
            </a>
            <h1 className="App-title">{title}</h1>
          </header>
        );
      }
    }

    export default Header;
```

1.  **Promises**：`Promise` 对象表示异步操作的最终完成（或失败）及其结果值。我们将在 React 中使用 promises 来处理请求，例如使用 axios 或 fetch；此外，我们将使用 Promises 来实现服务器端渲染（这将在第十一章*，实现服务器端渲染*中介绍）。

1.  **async/await**：async 函数声明定义了一个异步函数，返回一个 `AsyncFunction` 对象。这也可以用来执行服务器请求，例如使用 axios：

```jsx
    Index.getInitialProps = async () => {
      const url = 'https://api.coinmarketcap.com/v1/ticker/';
      const res = await axios.get(url);

      return {
        coins: res.data
      };
    };
```

# React 有什么新功能？

这段文字是在 2018 年 8 月 14 日写的，当时 React 的最新版本是 16.4.2。React 16 版本有一个名为 Fiber 的新核心架构。

在这个配方中，我们将看到这个版本中最重要的更新，你应该了解这些更新，以充分利用 React。

# 如何做...

让我们看看新的更新：

1.  **组件现在可以从渲染中返回数组和字符串**：以前，React 强制你返回一个包裹在 <div> 或其他标签中的元素；现在可以直接返回数组或字符串：

```jsx
    // Example 1: Returning an array of elements.
 render() {
      // Now you don't need to wrap list items in an extra element
      return [
        <li key="1">First item</li>,
        <li key="2">Second item</li>,
        <li key="3">Third item</li>,
      ];
    }

    // Example 2: Returning a string
    render() {
      return 'Hello World!';
    }
```

1.  此外，React 现在有一个名为 **Fragment** 的新功能，它也可以作为元素的特殊包装器。它可以用空标签（`<></>`）指定，也可以直接使用 `React.Fragment`：

```jsx
    // Example 1: Using empty tags <></>
 render() {
      return (
        <>
          <ComponentA />
          <ComponentB />
          <ComponentC />
        </>
      );
    }

    // Example 2: Using React.Fragment
    render() {
      return (
        <React.Fragment>
          <h1>An h1 heading</h1>
          Some text here.
          <h2>An h2 heading</h2>
          More text here.
          Even more text here.
        </React.Fragment>
      );
    }

 // Example 3: Importing Fragment
    import React, { Fragment } from 'react';
    ...
    render() {
      return (
        <Fragment>
          <h1>An h1 heading</h1>
          Some text here.
          <h2>An h2 heading</h2>
          More text here.
          Even more text here.
        </Fragment>
      );
    }
```

1.  **来自官方网站的错误边界**：

UI 的一部分出现 JavaScript 错误不应该导致整个应用程序崩溃。为了解决 React 用户的这个问题，React 16 引入了一个新概念，即"错误边界"。错误边界是 React 组件，它们捕获其子组件树中任何位置的 JavaScript 错误，记录这些错误，并显示一个替代 UI，而不是崩溃的组件树。错误边界在渲染期间、生命周期方法中以及它们下面整个树的构造函数中捕获错误。如果一个类组件定义了一个名为 componentDidCatch(error, info)的新生命周期方法，它就成为了一个错误边界。

```jsx
    class ErrorBoundary extends React.Component {
      constructor(props) {
        super(props);

        this.state = { 
          hasError: false 
        };
      }

      componentDidCatch(error, info) {
        // Display fallback UI
        this.setState({ 
          hasError: true 
        });

        // You can also log the error to an error reporting service
        logErrorToMyService(error, info);
      }

      render() {
        if (this.state.hasError) {
          // You can render any custom fallback UI
          return <h1>Something went wrong.</h1>;
        }

        return this.props.children;
      }
    }

    // **Then you can use it as a regular component:
**    **render**() {
   **   <ErrorBoundary>**
        <MyComponent />
      **</ErrorBoundary>
**    }
```

1.  **更好的服务器端渲染** 来自官方网站：

React 16 包括一个完全重写的服务器渲染器。它非常快。它支持流式传输，因此您可以更快地开始向客户端发送字节。并且由于一种新的打包策略，它会编译掉 process.env 检查（信不信由你，在 Node 中读取 process.env 真的很慢！），您不再需要捆绑 React 以获得良好的服务器渲染性能。

1.  从官方网站上减小文件大小："尽管增加了所有这些内容，React 16 实际上比 15.6.1 要小。

+   react 为 5.3 kb（经过 gzip 压缩为 2.2 kb），而之前为 20.7 kb（经过 gzip 压缩为 6.9 kb）

+   react-dom 为 103.7 kb（经过 gzip 压缩为 32.6 kb），而之前为 141 kb（经过 gzip 压缩为 42.9 kb）

+   react + react-dom 为 109 kb（经过 gzip 压缩为 34.8 kb），而之前为 161.7 kb（经过 gzip 压缩为 49.8 kb）

与上一个版本相比，这相当于总体减小了 32%的大小（gzip 后减小了 30%）。

如果您想查看 React 的最新更新，可以访问官方 React 博客：[`reactjs.org/blog`](https://reactjs.org/blog)。

# 在 Windows 上使用 React

我不是 Windows 的开发大粉丝，因为有时配置起来有点问题。我总是更喜欢 Linux 或 Mac，但我知道很多读者会使用 Windows。在这个配方中，我将向您展示在使用 Windows 时可能遇到的最常见问题。

# 如何做...

我们现在将看到在开发中使用 Windows 时最常见的问题：

1.  **终端**：你将面临的第一个问题是使用 Windows 终端（CMD），因为它不支持 Unix 命令（如 Linux 或 Mac）。解决方法是安装一个 Unix 终端；最受推荐的是使用**Git Bash**终端，它在你安装**Git**时就包含在内（[`git-scm.com`](https://git-scm.com)），第二个选择是安装**Cygwin**，它是 Windows 中的 Linux 终端（[`www.cygwin.com`](https://www.cygwin.com)）。

1.  **环境变量**：在 Windows 上使用的另一个常见问题是设置环境变量。通常，当我们编写 npm 脚本时，我们设置诸如`NODE_ENV=production`或`BABEL_ENV=development`之类的环境变量，但在 Windows 中设置这些变量时，你需要使用`SET`命令，这意味着你需要执行`SET NODE_ENV=production`或`SET BABEL_ENV=development`。这样做的问题是，如果你与其他使用 Linux 或 Mac 的人一起工作，他们将会遇到`SET`命令的问题，而且你可能需要忽略这个文件，只为你的本地环境修改它。这可能会很繁琐。解决这个问题的方法是使用一个叫做 cross-env 的包；你可以通过执行`npm install cross-env`来安装它，这将在 Windows、Mac 和 Linux 上都能工作：

```jsx
   "scripts": {
      "start": "cross-env NODE_ENV=development webpack-dev-server --
       mode development --open",
      "start-production": "cross-env NODE_ENV=production webpack-dev-
       server --mode production"
    }
```

1.  **区分大小写的文件或目录**：实际上，在 Linux 上也会发生这种情况，但有时很难识别这个问题，例如，如果你在`components/**home**/Home.jsx`目录中创建一个组件，但在你的代码中尝试像这样导入组件：

```jsx
 import Home from './components/Home/Home';
```

通常，这在 Mac 上不会引起任何问题，但可能会在 Linux 或 Windows 上生成错误，因为我们试图将一个文件以不同的名称（因为它是区分大小写的）导入到目录中。

1.  **路径**：Windows 使用反斜杠（`\`）来定义路径，而在 Mac 或 Linux 中使用正斜杠（`/`）。这是有问题的，因为有时我们需要定义一个路径（在 Node.js 中大多数情况下），我们需要做类似这样的事情：

```jsx
 // In Mac or Linux
    app.use(
      stylus.middleware({
        src: __dirname + '/stylus',
        dest: __dirname + '/public/css',
        compile: (str, path) => {
          return stylus(str)
            .set('filename', path)
            .set('compress', true);
        }
      })
    );

    // In Windows
    app.use(
      stylus.middleware({
        src: __dirname + '\stylus',
        dest: __dirname + '\public\css',
        compile: (str, path) => {
          return stylus(str)
            .set('filename', path)
            .set('compress', true);
        }
      })
    );

    // This can be fixed by using path
    import path from 'path';

   // path.join will generate a valid path for Windows or Linux and Mac
    app.use(
      stylus.middleware({
        src: path.join(__dirname, 'stylus'),
        dest: path.join(__dirname, 'public', 'css'),
        compile: (str, path) => {
          return stylus(str)
            .set('filename', path)
            .set('compress', config().html.css.compress);
        }
      })
    );
```


# 第二章：征服组件和 JSX

在本章中，将涵盖以下内容：

+   创建我们的第一个 React 组件

+   组织我们的 React 应用程序

+   使用 CSS 类和内联样式为组件设置样式

+   将 props 传递给组件并使用 PropTypes 进行验证

+   在组件中使用本地状态

+   创建一个函数式或无状态组件

+   理解 React 生命周期方法

+   理解 React 纯组件

+   在 React 中防止 XSS 漏洞

# 介绍

本章包含与在 React 中创建组件相关的内容。我们将学习如何创建 React 组件（类组件、纯组件和函数组件）并组织我们的项目结构。我们还将学习如何使用 React 本地状态，实现所有 React 生命周期方法，最后，我们将看到如何防止 XSS 漏洞。

# 创建我们的第一个 React 组件

组件是 React 的重要部分。使用 React，您可以构建交互式和可重用的组件。在这个配方中，您将创建您的第一个 React 组件。

# 准备工作

首先，我们需要使用`create-react-app`创建我们的 React 应用程序。完成后，您可以继续创建您的第一个 React 组件。

在安装`create-react-app`之前，请记住您需要从[www.nodejs.org](http://www.nodejs.org)下载并安装 Node。您可以为 Mac、Linux 和 Windows 安装它。

通过在终端中输入以下命令全局安装`create-react-app`：

```jsx
 npm install -g create-react-app
```

或者您可以使用快捷方式：

```jsx
 npm i -g create-react-app
```

# 如何做...

通过以下步骤构建我们的第一个 React 应用程序：

1.  使用以下命令创建我们的 React 应用程序：

```jsx
 create-react-app my-first-react-app
```

1.  转到新应用程序，使用`cd my-first-react-app`进入，并使用`npm start`启动它。

1.  应用程序现在应该在`http://localhost:3000`上运行。

1.  在您的`src`文件夹中创建一个名为`Home.js`的新文件：

```jsx
import React, { Component } from 'react';

class Home extends Component {
  render() {
    return <h1>I'm Home Component</h1>;
  }
}

export default Home;
```

文件：src/Home.js

1.  您可能已经注意到我们在文件末尾导出了我们的类组件，但直接在类声明上导出也是可以的，就像这样：

```jsx
 import React, { Component } from 'react';
 export default class Home extends Component {
      render() {
        return <h1>I'm Home Component</h1>;
      }
    }
```

文件：src/Home.js

我更喜欢在文件末尾导出它，但有些人喜欢以这种方式做，所以这取决于您的偏好。

1.  现在我们已经创建了第一个组件，我们需要渲染它。因此，我们需要打开`App.js`文件，导入`Home`组件，然后将其添加到`App`组件的渲染方法中。如果我们是第一次打开这个文件，我们可能会看到类似这样的代码：

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
              To get started, edit <code>src/App.js</code> 
              and save to reload.
            </p>
          </div>
        );
      }
    }

 export default App;
```

文件：src/App.js

1.  让我们稍微改变一下这段代码。正如我之前所说，我们需要导入我们的`Home`组件，然后将其添加到 JSX 中。我们还需要用我们的组件替换`<p>`元素，就像这样：

```jsx
 import React, { Component } from 'react';
 import logo from './logo.svg';

 // We import our Home component here...
 import Home from './Home';
 import './App.css';

 class App extends Component {
      render() {
        return (
          <div className="App">
            <header className="App-header">
              <img src={logo} className="App-logo" alt="logo" />
              <h1 className="App-title">Welcome to React</h1>
            </header>
            {/* Here we add our Home component to be render it */}
            <Home />
          </div>
        );
      }
    }

 export default App;
```

文件：src/App.js

# 它是如何工作的...

正如你所看到的，我们从 React 库中导入了`React`和`Component`。你可能注意到我们并没有直接使用`React`对象。要在 JSX 中编写代码，你需要导入`React`。JSX 类似于 HTML，但有一些不同之处。在接下来的示例中，你将学习更多关于 JSX 的知识。

这个组件被称为`class`组件（`React.Component`），有不同的类型：纯组件（`React.PureComponent`）和功能组件，也被称为无状态组件，我们将在接下来的示例中介绍。

如果你运行应用程序，你应该会看到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/37d1b4cf-d6b1-4f07-abbf-904a802e686a.png)

# 还有更多...

在我们的示例中，我们创建了`Home.js`文件，我们组件的名称是`Home`。

所有 React 组件的名称都应该以文件和类名的首字母大写开头。一开始，你可能会感到不舒服，但这是 React 中的最佳实践。

JSX 和 HTML 之间的一些主要区别是属性名称。你可能已经注意到，我们使用`className`而不是`class`。这是唯一的特殊属性名称。其他由破折号分隔的两个单词需要转换为驼峰命名法，例如，`onClick`，**`srcSet`**和`tabIndex`。`aria-*`和`data-*`属性仍然使用相同的命名法（`data-something`和`aria-label`）。

# 组织我们的 React 应用程序

在这个示例中，我们将学习如何更好地组织我们的项目。

# 如何做到...

我们可以使用`create-react-app`提供的默认结构创建 React 组件，但在这个示例中，我将向你展示更好的组织项目的方法，以便在应用程序增长时做好准备。

1.  我们需要创建一个新的 React 应用程序（如果你还没有创建 React 应用程序，请查看上一个示例）

1.  目前，我们的 React 应用程序目录树看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/92e8684d-42cf-416f-a60a-5afcff61c84b.png)

1.  我们需要创建`src/components`和`src/shared`目录

1.  之后，我们需要为我们的组件创建`src/components/Home`目录，并将**`Home.js`**移动到这个文件夹中

1.  `App.js`文件保持在`src/components`级别

1.  此外，`App.css`和`App.test.js`将保持在`src/components`级别

1.  将`logo.svg`文件移动到`src/shared/images`

1.  我们的`index.js`将保持在`src/`级别

1.  现在你的目录树应该是这样的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/3ba9e4f5-31dd-4ec2-b313-a65fc5056d59.png)我强烈建议你为共享组件创建另一个目录，`src/shared/components`。我将在下一个教程中详细解释这一点。

1.  在`App.js`文件中，更改`logo`和`Home`的引入：

```jsx
 import logo from '../shared/images/logo.svg';
 import Home from './Home/Home';
```

文件：src/components/App.js

1.  在你改变了那个之后，我们需要打开`index.js`并修复`App`组件的导入路径：

```jsx
import App from './components/App';
```

文件：src/index.js

# 工作原理...

这种新的结构将使我们更灵活地智能地分组我们的 React 组件。有了这种新的结构，我们将能够创建子组件，如果我们需要的话，这在使用 React 开发复杂应用程序时非常重要。

在下一个教程中，我们将看到如何在我们的应用程序中共享组件。

# 使用 CSS 类和内联样式来为组件添加样式

在上一个教程中，我们学会了如何创建一个类组件。现在让我们为`Home`组件添加一些 CSS。

在 React 中，最佳实践之一是将样式文件放在与组件相同的目录中。如果你曾经使用过 PHP、Node 或任何其他服务器语言，你可能会将样式写在一个`style.css`文件中，并在模板中使用`link`标签进行引入。React 使用的是目前最流行的模块打包工具 Webpack。通过 Webpack，我们可以配置处理样式的方式（直接使用 CSS 或使用 CSS 预处理器如 Sass、Stylus 或 Less CSS），并且我们可以实现 CSS 模块化。这是一个强大的方式来避免 CSS 的三个主要问题：

+   不再有冲突（意外的 CSS 覆盖）

+   显式依赖（每个组件的样式）

+   没有全局作用域

在第十章*，《掌握 Webpack 4.x*》，我们将介绍 Webpack，并且我们将能够在项目中使用 Sass 或 Stylus 来实现 CSS 模块。

# 操作步骤...

现在我们将为`Home`组件添加 CSS：

1.  创建一个新的应用程序，或者使用之前的一个（`my-first-react-app`）。

1.  然后为我们的`Home`组件创建一个新的 CSS 文件。让我们重用上一个示例中创建的`Home`组件。现在，您需要在与您的`Home.js`文件相同级别的位置（在`components`文件夹内）创建一个`Home.css`文件。在创建此文件之前，让我们稍微修改我们的`Home`组件：

```jsx
 import React, { Component } from 'react';

 // We import our Home.css file here
 import './Home.css';

 class Home extends Component {
      render() {
        return (
          <div className="Home">
            <h1>Welcome to Codejobs</h1>

            <p>
              In this recipe you will learn how to add styles to 
              components. If you want to learn more you can visit 
              our Youtube Channel at 
              <a href="http://youtube.com/codejobs">Codejobs</a>.
            </p>
          </div>
        );
      }
    }

 export default Home;
```

文件：src/components/Home/Home.js

1.  现在让我们给我们的`Home.css`**添加样式**。基本上，我们将我们的组件包装在一个`className`为 Home 的`div`中，里面有一个文本为`Welcome to Codejobs`的`<h1>`标签，然后是一个消息的`<p>`标签。我们需要直接导入我们的`Home.css`文件，然后我们的 CSS 文件将如下所示：

```jsx
  .Home {
      margin: 0 auto;
      width: 960px;
  }

  .Home h1 {
      font-size: 32px;
      color: #333;
  }

  .Home p {
      color: #333;
      text-align: center;
  }

  .Home a {
      color: #56D5FA;
      text-decoration: none;
  }

  .Home a:hover {
      color: #333;
  }
```

文件：src/components/Home/Home.css

1.  现在假设您需要添加内联样式。我们可以使用 style 属性来实现这一点，CSS 属性需要以驼峰命名法写在`{{ }}`之间，就像这样：

```jsx
 import React, { Component } from 'react';

 // We import our Home.css file here
 import './Home.css';

 class Home extends Component {
    render() {
      return (
        <div className="Home">
          <h1>Welcome to Codejobs</h1>
          <p>
            In this recipe you will learn how to add styles to 
            components. If you want to learn more you can visit 
            our Youtube Channel at 
            <a href="http://youtube.com/codejobs">Codejobs</a>.
          </p>

          <p>
            <button 
 style={{ 
 backgroundColor: 'gray', 
 border: '1px solid black' 
 }}            >
              Click me!
            </button>
          </p>
        </div>
      );
    }
  }

 export default Home;
```

文件：src/components/Home/Home.js

1.  您还可以像这样将对象传递给`style`属性：

```jsx
 import React, { Component } from 'react';

 // We import our Home.css file here
 import './Home.css';

 class Home extends Component {
    render() {
      // Style object...
      const buttonStyle = {
        backgroundColor: 'gray',
        border: '1px solid black'
      };

      return (
        <div className="Home">
          <h1>Welcome to Codejobs</h1>
          <p>
            In this recipe you will learn how to add styles to 
            components. If you want to learn more you can visit 
            our Youtube Channel at 
            <a href="http://youtube.com/codejobs">Codejobs</a>.
          </p>
          <p>
            <button style={buttonStyle}>Click me!</button>
          </p>
        </div>
      );
    }
  }

 export default Home;
```

文件：src/components/Home/Home.js

# 它是如何工作的...

如您所见，将 CSS 文件连接到我们的组件非常简单，如果您正确地按照所有步骤进行操作，您的网站应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/a94c164c-7ab3-4d97-a5f2-7a46f396c26f.png)

# 还有更多...

您可能好奇 CSS 代码是如何添加到浏览器中的，因为我们没有直接向项目导入 CSS 文件（例如使用`<link>`标签）。好吧，您会惊讶地发现，CSS 代码是通过使用`<style>`标签将其注入到我们的`<head>`标签中的每个导入样式表中的。如果您使用 Chrome DevTools 检查您的项目，您会看到类似于这样的内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/737dff60-3cf8-44ac-8d83-b3734177d630.png)

这是因为在我们使用`create-react-app`创建应用程序时，默认使用了名为`style-loader`的 Webpack 加载器：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/26c0d48b-1281-498b-a93c-ef8424d21f29.png)

当我们使用`create-react-app`时，没有直接修改 Webpack 配置的方法，因为它使用一个名为`react-scripts`的包，但是在第十章*，掌握 Webpack*中，我们将看到如何配置我们的 Webpack，而不使用`create-react-app`这样的起始工具包。

还有更多的 Webpack 加载程序可以执行不同的操作，例如`css-loader`用于 CSS 模块，`sass-loader`用于实现 Sass，`stylus-loader`用于实现 Stylus，以及`extract-text-plugin`用于将 CSS 代码移动到`.css`文件中，而不是将其注入到 DOM 中（通常，这仅在生产中使用）。

# 将 props 传递给组件并使用 PropTypes 进行验证

到目前为止，您已经熟悉了 React 组件，但它不仅仅是渲染静态 HTML。像任何应用程序一样，我们需要能够将信息（通过 props）发送到不同的元素。在这个示例中，我们将创建新的组件：`Header`，`Content`和`Footer`（我们将把这些组件分组到一个名为`layout`的文件夹中），并且我们将发送一些 props（作为属性和子元素）并使用`PropTypes`进行验证。

# 如何做...

以前创建的 React 应用程序的名称相同，让我们首先创建我们的`Header`组件。

1.  此时，我们当前的`header`放置在`App.js`中。

```jsx
 import React, { Component } from 'react';
 import logo from '../shared/images/logo.svg';
 import Home from './Home/Home';
 import './App.css';

 class App extends Component {
    render() {
      return (
        <div className="App">
          <header className="App-header">
 <img src={logo} className="App-logo" alt="logo" />
 <h1 className="App-title">Welcome to React</h1>
 </header>

          <Home />
        </div>
      );
    }
  }

 export default App;
```

文件：src/components/App.js

1.  让我们将该标题移动到我们的新`Header`组件中，然后将其导入到`App`组件中。因为`layout components`是全局或共享的，所以我们需要在我们的`shared components`目录（`src/shared/components/layout`）中创建一个`layout directory`。

1.  在继续之前，您必须安装一个名为`prop-types`的软件包，以使用`PropTypes`验证：

```jsx
npm install prop-types
```

1.  `PropTypes`最初作为 React 核心模块的一部分发布，并且通常与 React 组件一起使用。`PropTypes`用于记录传递给组件的属性的预期类型。React 将检查传递给组件的 props 与这些定义是否匹配，并且如果不匹配，它将在开发中发送警告：

```jsx
 import React, { Component } from 'react';
 import PropTypes from 'prop-types';
 import logo from '../../images/logo.svg';

 class Header extends Component {
      // Here you can define your PropTypes.
      static propTypes = {
        title: PropTypes.string.isRequired,
        url: PropTypes.string
      };

      render() {
        const { 
 title = 'Welcome to React', 
 url = 'http://localhost:3000' 
        } = this.props;

        return (
          <header className="App-header">
            <a href={url}>
              <img src={logo} className="App-logo" alt="logo" />
            </a>
            <h1 className="App-title">{title}</h1>
          </header>
        );
      }
    }

 export default Header;
```

文件：src/shared/components/layout/Header.js

1.  `static`的`PropTypes`属性基本上是一个对象，在其中您需要定义将传递的 prop 的类型。`array`，`bool`，`func`，`number`，`object`，`string`和`symbol`是原始类型，但也有特定的类型，例如`node`，`element`，`instanceOf`，`oneOf`，`oneOfType`，`arrayOf`，`objectOf`，`shape`和`any`。还有一个可选属性叫做`isRequired`，如果 prop 是必需的，将其添加到任何类型中，如果未定义，将产生 React 警告。

1.  导入并渲染我们的`Header`组件：

```jsx
 import React, { Component } from 'react';
 import Home from './Home/Home';
 import Header from '../shared/components/layout/Header';
 import './App.css';

 class App extends Component {
      render() {
        return (
          <div className="App">
            <Header title="Welcome to Codejobs" />
            <Home />
          </div>
        );
      }
    }

 export default App;
```

文件：src/components/App.js 不要与`<Header/>`组件混淆，它与 HTML5 中的`<header>`标签不同，这就是为什么在 React 中建议在类名中使用大写字母。

1.  传递给我们组件的所有属性都包含在这个 props 中。您可能已经注意到，我们只发送了`title`属性，因为它是唯一必需的属性。`url`属性是可选的，并且在解构中也有一个默认值（`http://localhost:3000`）。如果我们不传递 title 属性，即使在解构中有一个默认值 Welcome to React，我们也会收到警告，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/8eca84f1-f852-4e7e-8dc5-e9714dbcb28d.png)

1.  创建我们的`Footer`组件：

```jsx
 import React, { Component } from 'react';

 class Footer extends Component {
      render() {
        return (
       <footer>&copy; Codejobs {(new Date()).getFullYear()}</footer>
        );
      }
    }

 export default Footer;
```

文件：src/shared/components/layout/Footer.js

1.  到目前为止，我们只将 props 作为属性传递（使用自关闭组件`<Component />`），但还有另一种将 props 作为子元素传递的方式（`<Component>Children Content</Component>`）。让我们创建一个`Content`组件，并将我们的`Home`组件作为内容的子组件发送：

```jsx
 import React, { Component } from 'react';
 import PropTypes from 'prop-types';

 class Content extends Component {
    static propTypes = {
      children: PropTypes.element.isRequired
    };

    render() {
      const { children } = this.props;

      return (
        <main>
          {children}
        </main>
      );
    }
  }

 export default Content;
```

文件：src/shared/components/layout/Content.js

1.  通过这些更改，我们的`App.js`文件现在应该是这样的：

```jsx
 import React, { Component } from 'react';
 import Home from './Home/Home';

  // Layout Components
 import Header from '../shared/components/layout/Header';
 import Content from '../shared/components/layout/Content';
 import Footer from '../shared/components/layout/Footer';

 import './App.css';

 class App extends Component {
    render() {
      return (
        <div className="App">
          <Header title="Welcome to Codejobs" />

          <Content>
            <Home />
          </Content>

          <Footer />
        </div>
      );
    }
  }

 export default App;
```

文件：src/components/App.js

# 它是如何工作的...

PropTypes 验证对开发人员非常重要，因为它们强制我们定义我们将在组件中接收哪种类型的属性，并验证其中一些是否是必需的。

如果您正确地按照所有步骤进行了操作，您应该会看到类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/bce4d668-5bad-4606-ab16-94f1e06ea367.png)

# 还有更多...

如您所见，有许多将 props 发送到组件的方法。还有更多接收 props 的方法，例如使用 Redux（通过容器）或 React Router，但这些是我们将在下一章中涵盖的主题。

# 在组件中使用本地状态

本地状态是 React 创建动态组件的基本功能。本地状态仅在类组件上可用，并且每个组件都管理其状态。您可以在组件的构造函数中定义状态的初始值，并且当您更新状态的值时，组件将重新渲染自身。

本地状态对于切换、处理表单非常有帮助，并且用于在同一组件内管理信息。如果我们需要在不同组件之间共享数据，不建议使用本地状态。在这种情况下，我们需要实现 Redux 状态，我们将在第五章*精通 Redux*中介绍。

# 如何做...

让我们定义我们的初始状态。让我们看看当本地状态更新时组件的`render`方法是如何工作的：

1.  使用我们的`Home`组件，我们将添加一个构造函数并定义我们的初始状态：

```jsx
 import React, { Component } from 'react';
 import './Home.css';

 class Home extends Component {
    constructor() {
 // We need to define super() at the beginning of the 
 // constructor to have access to 'this'
      super();

      // Here we initialize our local state as an object
      this.state = {
        name: 'Carlos'
      };
    }

    render() {
      return (
        <div className="Home">
          {/* Here we render our state name */}
          <p>Hi my name is {this.state.name}</p>
        </div>
      );
    }
  }

 export default Home;
```

文件：src/components/Home/Home.js

1.  在这个例子中，我们在构造函数中将本地状态定义为一个对象，并在渲染时直接打印值。我们在构造函数的开头使用`super()`。这是用来调用父构造函数`(React.Component)`的。如果我们不包括它，我们会得到这样的错误：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/e13d8fc3-393a-4ead-89d0-a24cf1c86db7.png)

1.  在我们添加了`super()`之后，我们需要将我们的初始状态定义为一个普通对象：

```jsx
  this.state = {
    name: 'Carlos'
  };
```

1.  **使用`this.setState()`更新我们的本地状态**：现在，这只是一个没有被更新的状态。这意味着组件将永远不会再次重新渲染。要更新状态，我们需要使用`this.setState()`方法并传递状态的新值。我们可以添加一个`setTimeout`来在 1 秒后（1,000 毫秒）更新名称状态，所以我们需要修改我们的`render`方法如下：

```jsx
 render() {
    setTimeout(() => {
      this.setState({
        name: 'Cristina' // Here we update the value of the state
      });
    }, 1000);

    console.log('Name:', this.state.name);

    return (
      <div className="Home">
        <p>Hi my name is {this.state.name}</p>
      </div>
    );
  }
```

1.  如果你在浏览器中运行这个，你会看到状态的第一个值是 Carlos，1 秒后它会变成 Cristina。我已经添加了一个`console.log`来记录状态名称的值。如果你打开浏览器控制台，你会看到这个：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/c13cfaec-5e84-41ba-833c-6489ab557835.png)

1.  **在**`componentDidMount`**生命周期方法中更新我们的本地状态**：您可能想知道为什么重复这么多次。很简单；这是 React 的工作方式。每次更新状态时，都会触发 render 方法，在这段代码中，我们添加了一个`setTimeout`，它在一秒后更新状态。这意味着`render`方法每秒都会被调用，导致无限循环。这将影响我们应用的性能，这就是为什么在更新状态时需要小心。正如您所看到的，在 render 方法中更新它不是一个好主意。那么，我应该在哪里更新状态呢？嗯，这取决于您的应用，但现在，我将向您展示一种属于 React 生命周期的方法，称为`componentDidMount()`：

```jsx
 import React, { Component } from 'react';
 import './Home.css';

 class Home extends Component {
    constructor() {
      super();

      this.state = {
        name: 'Carlos'
      };
    }

    componentDidMount() {
      setTimeout(() => {
        this.setState({
          name: 'Cristina'
        });
      }, 1000);
    }

    render() {
      console.log('Name:', this.state.name);

      return (
        <div className="Home">
          <p>Hi my name is {this.state.name}</p>
        </div>
      );
    }
  }

 export default Home;
```

文件：src/components/Home/Home.js

1.  如果您运行此代码并查看控制台，现在您将看到这个：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/f08c1634-0c26-487d-808e-aebd5beba711.png)

# 它是如何工作的...

使用`componentDidMount`，我们避免了无限循环。这种方法更好的原因是，`componentDidMount`在组件已经挂载时只执行一次，并且在该方法中，我们只执行一次`setTimeout`并更新名称状态。在接下来的示例中，我们将学习更多关于 React 生命周期方法的知识。

# 还有更多...

本地状态也用于处理表单，但我们将在第六章*使用 Redux Form 创建表单*中进行介绍。

# 创建一个函数式或无状态组件

到目前为止，我们只学习了如何在 React 中创建*类组件*。当您需要处理本地状态时，这些组件非常有用，但在某些情况下，我们需要渲染静态标记。对于静态组件，我们需要使用*函数组件*，也称为*无状态组件*。这将提高我们应用的性能。

在*将 props 传递给组件并使用 PropTypes 进行验证*示例中，我们创建了一些布局组件（`Header`，`Content`和`Footer`）。这些组件通常不是动态的（除非您想在标题中添加切换菜单或一些用户信息），所以在这种情况下，我们可以将它们转换为函数组件。

# 如何做...

现在是时候将我们的`Header`组件转换为函数组件了：

1.  首先，让我们看看当前的`Header`组件是什么样子的：

```jsx
 import React, { Component } from 'react';
 import PropTypes from 'prop-types';
 import logo from '../../images/logo.svg';

 class Header extends Component {
    static propTypes = {
      title: PropTypes.string.isRequired,
      url: PropTypes.string
    };

    render() {
      const { 
        title = 'Welcome to React', 
        url = 'http://localhost:3000' 
      } = this.props;

      return (
        <header className="App-header">
          <a href={url}>
            <img src={logo} className="App-logo" alt="logo" />
          </a>
          <h1 className="App-title">{title}</h1>
        </header>
      );
    }
  }

 export default Header;
```

文件：src/shared/components/layout/Header.js

1.  第一件事是将我们的类组件转换为箭头函数，通过这个改变，我们不再需要导入`React.Component`。迁移的第二部分是将 props 作为函数的参数传递，而不是从`this.props`获取它们，最后一步是将我们的静态`propTypes`移动为函数的一个节点。在这些改变之后，我们的代码应该是这样的：

```jsx
 import React from 'react';
 import PropTypes from 'prop-types';
 import logo from '../../images/logo.svg';

  // We created a component with a simple arrow function.
 const Header = props => {
    const { 
      title = 'Welcome to React', 
      url = 'http://localhost:3000' 
    } = props;

    return (
      <header className="App-header">
        <a href={url}>
          <img src={logo} className="App-logo" alt="logo" />
        </a>
        <h1 className="App-title">{title}</h1>
      </header>
    );
  };

  // Even with Functional Components we are able to validate our 
  // PropTypes.
  Header.propTypes = {
    title: PropTypes.string.isRequired,
    url: PropTypes.string
  };

 export default Header;
```

文件：src/shared/components/layout/Header.js 功能组件相当于只有渲染方法。这就是为什么我们只需要直接返回 JSX。

1.  在我们迁移了`Header`组件之后，我们将迁移`Footer`组件；这更容易，因为它没有 props。首先，让我们看看我们的`Footer`组件是什么样的：

```jsx
 import React, { Component } from 'react';

 class Footer extends Component {
    render() {
      return (
        <footer>
          &copy; Codejobs {(new Date()).getFullYear()}
 </footer>
      );
    }
  }

 export default Footer;
```

文件：src/shared/components/layout/Footer.js

1.  现在，作为一个功能组件，它应该是这样的：

```jsx
 import React from 'react';

  // Since we don't have props, we can directly return our JSX.
 const Footer = () => (
    <footer>&copy; Codejobs {(new Date()).getFullYear()}</footer>
  );

 export default Footer;
```

文件：src/shared/components/layout/Footer.js 在这种情况下，正如您所看到的，我们需要创建一个没有参数的箭头函数（因为我们没有任何 props），并直接返回我们需要渲染的 JSX。

1.  将`Content`组件转换为功能组件：

```jsx
 import React, { Component } from 'react';
 import PropTypes from 'prop-types';

 class Content extends Component {
    static propTypes = {
      children: PropTypes.element.isRequired
    };

    render() {
      const { children } = this.props;

      return (
        <main>
          {children}
        </main>
      );
    }
  }

 export default Content;
```

文件：src/shared/components/layout/Content.js

1.  这个组件类似于我们的`Header`组件。我们需要将 props 作为参数传递并保留我们的`propTypes`：

```jsx
 import React from 'react';
 import PropTypes from 'prop-types';

 const Content = props => { 
    const { children } = props;

    return ( 
      <main>
        {children} 
      </main>
    ); 
  };

  Content.propTypes = {
    children: PropTypes.element.isRequired
  };

 export default Content;
```

文件***:*** src/shared/components/layout/Content.js

# 它是如何工作的...

即使使用功能组件，我们也可以验证我们的`PropTypes`。请记住，如果您不需要任何动态数据或本地状态，那么您应该考虑使用无状态组件。这将提高您的应用程序的性能。

# 还有更多...

一个功能组件不仅没有状态，而且也没有 React 生命周期方法。

# 理解 React 生命周期方法

React 提供了处理组件生命周期期间数据的方法。当我们需要在特定时间更新我们的应用程序时，这是非常有用的。

# 如何做...

在本节中，我们将独立解释每个示例。

# 待办事项列表 - 实现 ComponentWillMount

在这个示例中，您将学习有关 React 生命周期方法的信息流。我们将看到信息如何在组件预装载、已装载和已卸载时流动。在这个示例中，我们将开发的待办事项列表将如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/7b3d85d6-75af-4b01-bfb2-b80d34257fa2.png)

1.  对于这个待办事项列表，我们需要在我们的`components`目录中创建一个名为`Todo`的新文件夹，并且你还需要创建名为`Todo.js`和`Todo.css`的文件。这是`Todo`组件的骨架：

```jsx
import React, { Component } from 'react';
import './Todo.css';

class Todo extends Component {
  constructor() {
    super();
  }

  componentWillMount() {

  }

  render() {
    return (
      <div className="Todo">
        <h1>New Task:</h1>
      </div>
    );
  }
}

export default Todo;
```

文件：src/components/Todo/Todo.js

1.  **构造函数：**构造函数是一个在对象初始化之前执行的独特方法。构造函数可以使用`super`关键字调用父类（超类）的构造函数。这个方法用于初始化我们的本地状态或绑定我们的方法。对于待办事项列表，我们需要在构造函数中用一些值初始化本地状态或`items`数组：

```jsx
constructor() {
  super();

  // Initial state...
  this.state = {
    task: '',
    items: []
  };
}
```

1.  `componentWillMount`方法在组件挂载之前执行一次。在这种情况下，在我们的组件挂载之前，我们需要使用默认任务更新我们的`items`状态：

```jsx
componentWillMount() {
  // Setting default tasks...
  this.setState({
    items: [
      {
        id: uuidv4(),
        task: 'Pay the rent',
        completed: false
      },
      {
        id: uuidv4(),
        task: 'Go to the gym',
        completed: false
      },
      {
        id: uuidv4(),
        task: 'Do my homework',
        completed: false
      }
    ]
  });
}
```

1.  我们使用`uuidv4`来生成随机 ID。要安装这个包，你需要运行以下命令：

```jsx
 npm install uuid
```

1.  然后你需要像这样导入它：

```jsx
 import uuidv4 from 'uuid/v4';
```

1.  在我们定义了默认任务之后，让我们看看如何渲染待办事项列表：

```jsx
 render() {
    return (
      <div className="Todo">
        <h1>New Task:</h1>

        <form onSubmit={this.handleOnSubmit}>
          <input 
            value={this.state.task} 
            onChange={this.handleOnChange} 
          />
        </form>

        <List
          items={this.state.items}
          markAsCompleted={this.markAsCompleted}
          removeTask={this.removeTask}
        />
      </div>
    );
  }
```

1.  我们的 JSX 分为两部分。第一部分是一个表单，其中包含一个与我们的本地状态（`this.state.task`）连接的输入，并且当用户提交表单时我们将保存任务（`onSubmit`）。第二部分是组件列表，我们将在其中显示我们的待办事项列表（或任务列表），传递`items`数组和`markAsCompleted`（标记任务为已完成）和`removeTask`（从列表中移除任务）函数。

1.  `handleOnChange`方法用于将我们的输入值与我们的状态任务连接起来：

```jsx
 handleOnChange = e => {
    const { target: { value } } = e;

    // Updating our task state with the input value...
    this.setState({
      task: value
    });
  }
```

1.  `handleOnSubmit`方法用于更新`items`状态并将新任务推送到数组中：

```jsx
 handleOnSubmit = e => {
    // Prevent default to avoid the actual form submit...
    e.preventDefault();

 // Once is submited we reset the task value and we push 
 // the new task to the items array.
    if (this.state.task.trim() !== '') {
      this.setState({
        task: '',
        items: [
          ...this.state.items,
          {
            id: uuidv4(),
            task: this.state.task,
            complete: false
          }
        ]
      });
    }
  }
```

1.  `markAsCompleted`函数将从我们的`List`组件中调用，并且需要接收我们想要标记为已完成的任务的`id`。有了这个，我们可以在我们的 items 数组中找到特定的任务，将节点修改为已完成，然后更新本地状态：

```jsx
 markAsCompleted = id => {
    // Finding the task by id...
    const foundTask = this.state.items.find(
      task => task.id === id
    );

    // Updating the completed status...
    foundTask.completed = true;

    // Updating the state with the new updated task...
    this.setState({
      items: [
        ...this.state.items,
        ...foundTask
      ]
    });
  }
```

1.  `removeTask`函数也是从`List`组件中调用的，和`markAsCompleted`一样，我们需要接收`id`来移除特定的任务：

```jsx
 removeTask = id => {
    // Filtering the tasks by removing the specific task id...
    const filteredTasks = this.state.items.filter(
      task => task.id !== id
    );

    // Updating items state...
    this.setState({
      items: filteredTasks
    });
  }
```

1.  让我们把所有的部分放在一起。我们的`Todo`组件应该是这样的：

```jsx
 import React, { Component } from 'react';
 import uuidv4 from 'uuid/v4';
 import List from './List';
 import './Todo.css';

 class Todo extends Component {
    constructor() {
      super();

      // Initial state...
      this.state = {
        task: '',
        items: []
      };
    }

    componentWillMount() {
      // Setting default tasks...
      this.setState({
        items: [
          {
            id: uuidv4(),
            task: 'Pay the rent',
            completed: false
          },
          {
            id: uuidv4(),
            task: 'Go to the gym',
            completed: false
          },
          {
            id: uuidv4(),
            task: 'Do my homework',
            completed: false
          }
        ]
      });
    }

    handleOnChange = e => {
      const { target: { value } } = e;

      // Updating our task state with the input value...
      this.setState({
        task: value
      });
    }

    handleOnSubmit = e => {
      // Prevent default to avoid the actual form submit...
      e.preventDefault();

      // Once is submitted we reset the task value and 
      // we push the new task to the items array.
      if (this.state.task.trim() !== '') {
        this.setState({
          task: '',
          items: [
            ...this.state.items,
            {
              id: uuidv4(),
              task: this.state.task,
              complete: false
            }
          ]
        });
      }
    }

    markAsCompleted = id => {
      // Finding the task by id...
      const foundTask = this.state.items.find(
        task => task.id === id
      );

      // Updating the completed status...
      foundTask.completed = true;

      // Updating the state with the new updated task...
      this.setState({
        items: [
          ...this.state.items,
          ...foundTask
        ]
      });
    }

    removeTask = id => {
      // Filtering the tasks by removing the specific task id...
      const filteredTasks=this.state.items.filter(
        task => task.id !== id
      );

      // Updating items state...
      this.setState({
        items: filteredTasks
      });
    }

    render() {
      return (
        <div className="Todo">
          <h1>New Task:</h1>

          <form onSubmit={this.handleOnSubmit}>
            <input 
              value={this.state.task} 
 onChange={this.handleOnChange}
            />
          </form>

          <List
            items={this.state.items}
            markAsCompleted={this.markAsCompleted}
            removeTask={this.removeTask}
          />
        </div>
      );
    }
  }

 export default Todo;
```

文件：src/components/Todo/Todo.js

1.  现在我们已经完成了`Todo`组件，让我们看看我们的`List`组件是什么样子的：

```jsx
 import React from 'react';

 const List = props => (
    <ul>
      {props.items.map((item, key) => (
        <li 
 key={key} 
          className={`${item.completed ? 'completed' : 'pending'}`}                        
        >
          {/* 
            * If the task is completed we assign the * .completed class otherwise .pending 
            */}
          {item.task}

          <div className="actions">
            {/* 
              * Using a callback on the onClick we call our 
              * markAsCompleted function 
              */}
            <span 
              className={item.completed ? 'hide' : 'done'} 
 onClick={() => props.markAsCompleted(item.id)}
            >
              <i className="fa fa-check"></i>
            </span>

            {/* 
              * Using a callback on the onClick we call 
              * our removeTask function 
              */}
            <span 
              className="trash" 
 onClick={() => props.removeTask(item.id)}
            >
              <i className="fa fa-trash"></i>
            </span>
          </div>
        </li>
      ))}
    </ul>
  );

 export default List;
```

文件：src/components/Todo/List.js

1.  每当我们使用`.map`函数从数组中渲染多个 React 元素时，我们必须为我们创建的每个项目添加 key 属性。否则，我们将收到类似于此的 React 警告：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/31fa593a-8e11-43ac-901e-f9038e1be126.png)

1.  您可能已经注意到，我们还包含了一些 Font Awesome 图标，并且为了使其工作，我们需要将 Font Awesome CDN 添加到主`index.html`文件中：

```jsx
  <head>
    <title>React App</title>
    <link 
 href="https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css" 
 rel="stylesheet" 
    />
  </head>
```

文件：public/index.html

1.  最后一部分是 Todo 列表的 CSS（如果您愿意，可以自由更改样式）：

```jsx
 .Todo {
     background-color: #f5f5f5;
     border-radius: 4px;
     border: 1px solid #e3e3e3;
     box-shadow: inset 0 1px 1px rgba(0,0,0,.05);
     margin: 50px auto;
     min-height: 20px;
     padding: 20px;
     text-align: left;
     width: 70%;
 }

 .Todo ul {
     margin: 20px 0px;
     padding: 0;
     list-style: none;
 }

 .Todo ul li {
     background-color: #fff;
     border: 1px solid #ddd;
     display: flex;
     justify-content: space-between;
     margin-bottom: -1px;
     padding: 10px 15px;
 }

 .Todo ul li .hide {
     visibility: hidden;
 }

 .Todo ul li.completed {
     background-color: #dff0d8;
 }

 .Todo ul li .actions {
     display: flex;
     justify-content: space-between;
     width: 40px;
 }

 .Todo ul li span {
     cursor: pointer;
 }

 .Todo ul li .done {
     color: #79c41d;
     display: block;
 }

 .Todo ul li .trash {
     color: #c41d1d;
     display: block;
 }

 .Todo form input {
     background-color: #fff;
     border-radius: 4px;
     border: 1px solid #ccc;
     box-shadow: inset 0 1px 1px rgba(0,0,0,.075);
     color: #555;
     font-size: 14px;
     height: 34px;
     line-height: 34px;
     padding: 6px 12px;
     width: 40%;
 }
```

文件：src/components/Todo/Todo.css

1.  不要忘记将`Todo`组件导入到您的`App`组件中。否则，组件将无法渲染：

```jsx
  import React, { Component } from 'react';
  import Todo from './Todo/Todo';
  import Header from '../shared/components/layout/Header';
  import Content from '../shared/components/layout/Content';
  import Footer from '../shared/components/layout/Footer';
  import './App.css';

  class App extends Component {
    render() {
      return (
        <div className="App">
          <Header title="Todo List" />

          <Content>
            <Todo />
          </Content>

          <Footer />
        </div>
      );
    }
  }

 export default App;
```

文件：src/components/App.js

1.  如果您正确地遵循了所有说明，您应该看到 Todo 列表如下所示：

+   具有默认任务的初始状态：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/b11119df-92bf-45bf-b33d-534c8d80c369.png)

+   添加新任务：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/c219e590-ec67-4d43-803a-9edab71965e3.png)

+   写下任务标题，然后按*Enter*：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/a1c1f936-b61e-4798-8d92-16a1a794248c.png)

+   标记任务为完成：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/f0129857-e44e-42ec-b668-eeb1d7d14a59.png)

+   删除任务：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/ccb14d7c-04a6-4f45-8cf2-1b18023052bf.png)

我挑战您使用`localStorage`保存任务，而不是使用`componentWillMount`定义默认任务。

# 番茄工作法计时器 - 实现构造函数和 componentDidMount

要理解`componentDidMount`，我们将创建一个番茄工作法计时器（如果您不知道它是什么，可以阅读这篇文章：[`en.wikipedia.org/wiki/Pomodoro_Technique`](https://en.wikipedia.org/wiki/Pomodoro_Technique)）。

我们的番茄工作法计时器将如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/b3474db4-b21d-4fb6-81ea-7f2d9b3c16ec.png)

创建我们的番茄工作法计时器：

1.  我们需要做的第一件事是在我们的`components`目录中创建一个名为`Pomodoro`的新文件夹，以及一个名为`Timer.js`和 CSS 文件`Timer.css`。这是我们将用于此组件的类组件的骨架：

```jsx
import React, { Component } from 'react';
import './Timer.css';

class Timer extends Component {
  constructor() {
    super();
  }

  componentDidMount() {

  }

  render() {
    return (
      <div className="Pomodoro">

      </div>
    );
  }
}

export default Timer;
```

文件：src/components/Pomodoro/Timer.js

1.  对于我们的番茄工作法计时器，我们需要在构造函数中使用一些值初始化我们的本地状态，用于时间和警报（当时间结束时）：

```jsx
 constructor() {
    super();

    // Initial State
    this.state = {
      alert: {
        type: '',
        message: ''
      },
      time: 0
    };

    // Defined times for work, short break and long break...
    this.times = {
      defaultTime: 1500, // 25 min
      shortBreak: 300, // 5 min
      longBreak: 900 // 15 min
    };
  }
```

1.  `componentDidMount`方法在组件挂载后调用，并且仅执行一次。在这种情况下，一旦我们的组件挂载，我们需要使用默认时间（25 分钟）更新我们的时间状态，为此，我们需要创建一个名为`setDefaultTime`的新方法，然后在我们的`componentDidMount`方法中执行它：

```jsx
  componentDidMount() {
    // Set default time when the component mounts
    this.setDefaultTime();
  }

  setDefaultTime = () => {
    // Default time is 25 min
    this.setState({
      time: this.times.defaultTime
    });
  }
```

1.  在将默认时间定义为我们的时间状态之后，让我们看看我们需要如何渲染番茄钟计时器。我们的`render`方法应该是这样的：

```jsx
 render() {
    const { alert: { message, type }, time } = this.state;

    return (
      <div className="Pomodoro">
        <div className={`alert ${type}`}>
          {message}
        </div>

        <div className="timer">
          {this.displayTimer(time)}
        </div>

        <div className="types">
          <button 
            className="start" 
 onClick={this.setTimeForWork}
          >
            Start Working
          </button>
          <button 
            className="short" 
 onClick={this.setTimeForShortBreak}
          >
            Short Break
          </button>
          <button 
            className="long" 
 onClick={this.setTimeForLongBreak}
          >
            Long Break
          </button>
        </div>
      </div>
    );
  }
```

1.  在这种情况下，我们的 JSX 非常简单。我们从本地状态（`message`，`type`和`time`）中获取值，并显示一个 div 来显示用户接收到的警报消息。我们有另一个 div 来显示我们的计时器，这里我们将我们当前的时间（以秒为单位）传递给`displayTimer`方法，该方法将这些秒转换为`mm:ss`格式。布局的最后一部分是用于选择计时器类型的按钮（开始工作 25 分钟，短暂休息 5 分钟或长时间休息 15 分钟），您可能已经注意到我们在每种计时器的`onClick`事件上执行不同的方法。

1.  `setTimeForWork`，`setTimeForShortBreak`和`setTimeForLongBreak`：这三个函数的目的是根据计时器的类型更新警报消息，然后调用一个名为`setTime`的公共函数，将特定时间作为参数传递给它。让我们首先看看这三个函数应该是什么样子的：

```jsx
  setTimeForWork = () => {
    this.setState({
      alert: {
        type: 'work',
        message: 'Working!'
      }
    });

    return this.setTime(this.times.defaultTime);
  }

  setTimeForShortBreak = () => {
    this.setState({
      alert: {
        type: 'shortBreak',
        message: 'Taking a Short Break!'
      }
    });

    return this.setTime(this.times.shortBreak);
  }

  setTimeForLongBreak = () => {
    this.setState({
      alert: {
        type: 'longBreak',
        message: 'Taking a Long Break!'
      }
    });

    return this.setTime(this.times.longBreak);
  }
```

1.  正如我们在之前的示例中学到的，当我们在类中使用箭头函数指定我们的方法时，它们会自动绑定（它们可以访问`this`对象）。这意味着我们不需要在构造函数中绑定它们。现在让我们创建我们的`setTime`方法：

```jsx
  setTime = newTime => {
    this.restartInterval();

    this.setState({
      time: newTime
    });
  }
```

1.  如您所见，我们执行了一个名为`restartInterval()`的新方法，并使用`newTime`变量更新了我们的本地状态，我们将其作为参数传递（可以是 1,500 秒=25 分钟，300 秒=5 分钟或 900 秒=15 分钟）。您可能已经注意到，从函数的名称中，我们将使用`setInterval`函数，该函数用于每 X 毫秒调用一次函数。我们的`restartInterval`函数应该像这样：

```jsx
  restartInterval = () => {
    // Clearing the interval
    clearInterval(this.interval);

 // Execute countDown function every second
    this.interval = setInterval(this.countDown, 1000);
  }
```

1.  在这种情况下，我们首先用`clearInterval(this.interval)`清除了我们的间隔。这是因为用户可以在不同类型的计时器之间切换，所以我们需要在设置新的计时器时清除间隔。清除间隔后，我们使用`setInterval`每秒调用`countDown`函数。`countDown`函数如下：

```jsx
  countDown = () => {
    // If the time reach 0 then we display Buzzzz! alert.
    if (this.state.time === 0) {
      this.setState({
        alert: {
          type: 'buz',
          message: 'Buzzzzzzzz!'
        }
      });
    } else {
      // We decrease the time second by second
      this.setState({
        time: this.state.time - 1
      });
    }
  }
```

1.  这个谜题的最后一块是`displayTimer`函数，它将把时间转换成`mm:ss`格式，并在我们的组件中显示出来：

```jsx
 displayTimer(seconds) {
    // Formatting the time into mm:ss
    const m = Math.floor(seconds % 3600 / 60);
    const s = Math.floor(seconds % 3600 % 60);

 return `${m < 10 ? '0' : ''}${m}:${s < 10 ? '0' : ''}${s}`;
 }
```

1.  让我们把它全部整合起来：

```jsx
 import React, { Component } from 'react';
 import './Timer.css';

 class Timer extends Component {
    constructor() {
      super();

      // Initial State
      this.state = {
        alert: {
          type: '',
          message: ''
        },
        time: 0
      };

      // Defined times for work, short break and long break...
      this.times = {
        defaultTime: 1500, // 25 min
        shortBreak: 300, // 5 min
        longBreak: 900 // 15 min
      };
    }

    componentDidMount() {
      // Set default time when the component mounts
      this.setDefaultTime();
    }

    setDefaultTime = () => {
      // Default time is 25 min
      this.setState({
        time: this.times.defaultTime
      });
    }

    setTime = newTime => {
      this.restartInterval();

      this.setState({
        time: newTime
      });
    }

    restartInterval = () => {
      // Clearing the interval
      clearInterval(this.interval);

      // Execute countDown every second
      this.interval = setInterval(this.countDown, 1000);
    }

    countDown = () => {
      // If the time reach 0 then we display Buzzzz! alert.
      if (this.state.time === 0) {
        this.setState({
          alert: {
            type: 'buz',
            message: 'Buzzzzzzzz!'
          }
        });
      } else {
        // We decrease the time second by second
        this.setState({
          time: this.state.time - 1
        });
      }
    }

    setTimeForWork = () => {
      this.setState({
        alert: {
          type: 'work',
          message: 'Working!'
        }
      });

      return this.setTime(this.times.defaultTime);
    }

    setTimeForShortBreak = () => {
      this.setState({
        alert: {
          type: 'shortBreak',
          message: 'Taking a Short Break!'
        }
      });

      return this.setTime(this.times.shortBreak);
    }

    setTimeForLongBreak = () => {
      this.setState({
        alert: {
          type: 'longBreak',
          message: 'Taking a Long Break!'
        }
      });

      return this.setTime(this.times.longBreak);
    }

    displayTimer(seconds) {
      // Formatting the time into mm:ss
      const m = Math.floor(seconds % 3600 / 60);
      const s = Math.floor(seconds % 3600 % 60);

      return `${m < 10 ? '0' : ''}${m}:${s < 10 ? '0' : ''}${s}`;
    }

    render() {
      const { alert: { message, type }, time } = this.state;

      return (
        <div className="Pomodoro">
          <div className={`alert ${type}`}>
            {message}
          </div>

          <div className="timer">
            {this.displayTimer(time)}
          </div>

          <div className="types">
            <button 
              className="start" 
 onClick={this.setTimeForWork}
            >
              Start Working
            </button>
            <button 
              className="short" 
 onClick={this.setTimeForShortBreak}
            >
              Short Break
            </button>
            <button 
              className="long" 
 onClick={this.setTimeForLongBreak}
            >
              Long Break
            </button>
          </div>
        </div>
      );
    }
  }

 export default Timer;
```

文件：src/components/Pomodoro/Timer.js

1.  在我们完成了组件之后，最后一步是添加我们的样式。这是用于番茄钟计时器的 CSS。当然，如果你愿意，你可以进行更改：

```jsx
.Pomodoro {
    padding: 50px;
}

.Pomodoro .timer {
    font-size: 100px;
    font-weight: bold;
}

.Pomodoro .alert {
    font-size: 20px;
    padding: 50px;
    margin-bottom: 20px;
}

.Pomodoro .alert.work {
    background: #5da423;
}

.Pomodoro .alert.shortBreak {
    background: #f4ad42;
}

.Pomodoro .alert.longBreak {
    background: #2ba6cb;
}

.Pomodoro .alert.buz {
    background: #c60f13;
}

.Pomodoro button {
    background: #2ba6cb;
    border: 1px solid #1e728c;
    box-shadow: 0 1px 0 rgba(255, 255, 255, 0.5) inset;
    color: white;
    cursor: pointer;
    display: inline-block;
    font-size: 14px;
    font-weight: bold;
    line-height: 1;
    margin: 50px 10px 0px 10px;
    padding: 10px 20px 11px;
    position: relative;
    text-align: center;
    text-decoration: none;
}

.Pomodoro button.start {
    background-color: #5da423;
    border: 1px solid #396516;
}

.Pomodoro button.short {
    background-color: #f4ad42;
    border: 1px solid #dd962a;
}
```

文件：src/components/Pomodoro/Timer.css

不要忘记将`<Timer />`组件导入到`App.js`中。如果你按照一切正确的步骤进行，你应该会看到番茄钟计时器的工作方式如下：

+   工作中：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/81c80738-f47f-401e-bc31-4b466d615a82.png)

+   短时间休息：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/c83b17af-37eb-471d-b357-ec59075cf219.png)

+   长时间休息：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/1199ed97-04e1-4fa4-bb9f-35d879943f67.png)

+   嗡嗡声 - 时间到了！：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/065a22f1-9ada-4ee5-92ae-55e7af538040.png)我向你挑战，添加一个播放、暂停和重置按钮来控制计时器。

# 加密货币兑换器 - 实现 shouldComponentUpdate

今天，每个人都在谈论比特币、以太坊、瑞波和其他加密货币。让我们创建我们自己的加密货币兑换器，来学习`shouldComponentUpdate`是如何工作的。

我们的计时器将会是这样的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/ea808246-e7f9-4527-8ae4-85f573f40fe3.png)

1.  我们将出售整个硬币。这意味着我们不会用小数进行交易；一切都应该是整数，每种货币的成本是 10 美元**。**我们的代码很简单，所以让我们来看一下：

```jsx
import React, { Component } from 'react';
import './Coins.css';

class Coins extends Component {
  constructor() {
    super();

    // Initial state...
    this.state = {
      dollars: 0
    };
  }

  shouldComponentUpdate(props, state) {
    // We only update if the dollars are multiples of 10
    return state.dollars % 10 === 0;
  }

  handleOnChange = e => {
    this.setState({
      dollars: Number(e.target.value || 0)
    });
  }

  render() {
    return (
      <div className="Coins">
        <h1>Buy Crypto Coins!</h1>

        <div className="question">
          <p>How much dollars do you have?</p>

          <p>
            <input 
              placeholder="0" 
 onChange={this.handleOnChange} 
              type="text" 
            />
          </p>
        </div>

        <div className="answer">
          <p>Crypto Coin price: $10</p>
          <p>
            You can buy <strong>{this.state.dollars / 10}</strong> 
            coins.
          </p>
        </div>
      </div>
    );
  }
}

export default Coins;
```

文件：src/components/Coins/Coins.js

1.  每当用户在输入框中输入内容并将值转换为数字时，我们都会更新我们的 dollars 状态，但是如果你运行这段代码，你可能会注意到，当你输入小于 10 的数字时，消息**你可以购买 0 个硬币**直到你写下 10、20、30、40 等数字时才会改变。

1.  `shouldComponentUpdate`：这个方法是改善我们应用程序性能的最重要的方法之一。每当我们更新本地状态时，它都会接收两个参数（props，state），当一个 prop 被更新时，这个方法就会被执行。返回的值必须是布尔值，这意味着如果你有意写下面的内容，你的组件将永远不会更新，因为这个方法会阻止它更新：

```jsx
shouldComponentUpdate(props, state) {
  return false;
}
```

1.  但是，另一方面，如果你返回 true，甚至如果你根本没有定义这个方法，React 的默认行为总是更新组件，在某些情况下，当我们渲染大量视图并处理经常变化的大量数据时，这可能会导致性能问题。

1.  在我们的例子中，只有当用户输入的美元数量是 10 的倍数时，我们才返回 true。这就是为什么你只会在这种情况下看到组件更新：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/8c2d7386-d2d6-4ec5-be6b-e781097a21b6.png)

1.  但是对于不是 10 的倍数的数字，它是不会起作用的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/49507625-ed20-4e88-95cd-0d662fd310f5.png)

1.  现在，如果我们从组件中删除`shouldComponentUpdate`方法，或者直接返回一个`true`值，每次我们写一个数字，组件都会更新，这将是结果：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/75f61086-21c6-4837-bd44-6c5a57ff487b.png)

1.  正如你所看到的，通过`shouldComponentUpdate`，我们可以控制组件的更新，这显著提高了应用程序的性能。我们例子的最后一部分是 CSS：

```jsx
  .Coins {
    background-color: #f5f5f5;
    border-radius: 4px;
    border: 1px solid #e3e3e3;
    box-shadow: inset 0 1px 1px rgba(0,0,0,.05);
    margin-bottom: 20px;
    margin: 50px auto;
    min-height: 20px;
    padding: 19px;
    text-align: left;
    width: 70%;
  }

  .Coins input {
    background-color: #fff;
    border-radius: 4px;
    border: 1px solid #ccc;
    box-shadow: inset 0 1px 1px rgba(0,0,0,.075);
    color: #555;
    font-size: 14px;
    height: 34px;
    line-height: 34px;
    padding: 6px 12px;
    width: 120px;
  }
```

文件：src/components/Coins/Coins.css

# 笔记 - 实现 componentWillReceiveProps 和 componentWillUnmount

在这个例子中，我们将创建一个简单的笔记列表，在这个列表中，每 10 秒，我们将模拟从服务接收到新数据的更新，并且通过`componentWillReceiveProps`，我们将记录我们上次从服务器接收到更新的时间：

1.  `componentWillReceiveProps`方法在渲染之前被调用。像`shouldComponentUpdate`一样，每当新的 props 被传递给组件，或者状态发生改变时，它都会被调用。在这个例子中，我们需要创建假数据，但数据通常需要来自实际的服务：

```jsx
 export const notes1 = [
    {
      title: 'Note 1',
      content: 'Content for Note 1'
    },
    {
      title: 'Note 2',
      content: 'Content for Note 2'
    },
    {
      title: 'Note 3',
      content: 'Content for Note 3'
    }
  ];

 export const notes2 = [
    {
      title: 'Note 4',
      content: 'Content for Note 4'
    },
    {
      title: 'Note 5',
      content: 'Content for Note 5'
    },
    {
      title: 'Note 6',
      content: 'Content for Note 6'
    }
  ];
```

文件：src/components/Notes/data.js

1.  在我们创建了假数据之后，让我们创建我们的组件：

```jsx
 import React, { Component } from 'react';
 import moment from 'moment';
 import './Notes.css';

  const formatTime = 'YYYY-MM-DD HH:mm:ss';

 class Notes extends Component {
    constructor() {
      super();

      // We save the first date when the data is 
      // rendered at the beginning
      this.state = {
        lastUpdate: moment().format(formatTime).toString()
      }
    }

    componentWillReceiveProps(nextProps) {
      // If the prop notes has changed...
      if (nextProps.notes !== this.props.notes) {
        this.setState({
          lastUpdate: moment().format(formatTime).toString()
        });
      }
    }
    render() {
      const { notes } = this.props;

      return (
        <div className="Notes">
          <h1>Notes:</h1>

          <ul>
            {notes.map((note, key) => (
              <li key={key}>{note.title} - {note.content}</li>
            ))}
          </ul>

          <p>Last Update: <strong>{this.state.lastUpdate}</strong>
          </p>
        </div>
      );
    }
  }

 export default Notes;
```

文件：src/components/Notes/Notes.js

1.  在这个例子中，我们使用了`moment.js`库。要安装它，你需要运行以下命令：

```jsx
 npm install moment
```

1.  现在，在我们的`App.js`文件中，我们将模拟在第一次渲染后 10 秒收到来自服务的新更新并渲染新的笔记：

```jsx
 import React, { Component } from 'react';
 import Notes from './Notes/Notes';
 import Header from '../shared/components/layout/Header';
 import Content from '../shared/components/layout/Content';
 import Footer from '../shared/components/layout/Footer';

 // This is our fake data...
 import { notes1, notes2 } from './Notes/data';
 import './App.css';

 class App extends Component {
    constructor() {
      super();

      // The first time we load the notes1...
      this.state = {
        notes: notes1
      };
    }

    componentDidMount() {
      // After 10 seconds (10000 milliseconds) we concatenate our       
      // data with notes2...
      setTimeout(() => {
        this.setState({
          notes: [...this.state.notes, ...notes2]
        });
      }, 10000);
    }

    render() {
      return (
        <div className="App">
          <Header title="Notes" />

          <Content>
            <Notes notes={this.state.notes} />
          </Content>

          <Footer />
        </div>
      );
    }
  }

 export default App;
```

文件：src/components/App.js

1.  最后一部分是 CSS 文件：

```jsx
  .Notes {
    background-color: #f5f5f5;
    border-radius: 4px;
    border: 1px solid #e3e3e3;
    box-shadow: inset 0 1px 1px rgba(0,0,0,.05);
    margin-bottom: 20px;
    margin: 50px auto;
    min-height: 20px;
    padding: 19px;
    text-align: left;
    width: 70%;
  }

 .Notes ul {
    margin: 20px 0px;
    padding: 0;
    list-style: none;
  }

 .Notes ul li {
    background-color: #fff;
    border: 1px solid #ddd;
    display: flex;
    justify-content: space-between;
    margin-bottom: -1px;
    padding: 10px 15px;
    position: relative;
  }
```

文件：src/components/Notes/Notes.css

1.  如果您运行应用程序，您将看到类似于这样的东西：

！[](assets/d7508b74-c308-4345-aee1-68778a10ed3f.png)

1.  10 秒后，您将看到这个：

！[](assets/be3a42cb-a6ae-4dee-9e16-8dd99516de82.png)

1.  如您所见，最后更新日期已从 2018-02-20 00:07:28 更改为 2018-02-20 00:07:**38**（10 秒后）。

1.  `componentWillUnmount`：这是在组件从 DOM 中被移除之前立即调用的最后一个方法。通常，用于对`componentWillMount`方法创建的任何 DOM 元素或定时器进行清理。让我们稍微修改我们的代码以便调用这个方法。在我们的`Notes`组件中，您可以在`render`方法之后添加这段代码：

```jsx
 componentWillUnmount() {
    console.log('Hasta la vista baby!');
    document.body.style = 'background: black;';
    document.getElementById('unmountMessage').style.color = 'white';
  }
```

1.  我们需要修改我们的`index.html`文件手动包含一个不会成为 React 的一部分的按钮：

```jsx
  <body>
    <div id="root"></div>

    <div id="unmountMessage">There is no mounted component!</div>

    <button 
      id="unmount" 
 style="margin:0 auto;display:block;background:red;color:white;"
    >
      Unmount
    </button>
  </body>
```

文件：public/index.html

1.  然后，在我们的`index.js`文件中，我们正在渲染我们的`<App />`组件，让我们添加一些额外的代码（实际上我们需要从 DOM 中删除元素）：

```jsx
 import React from 'react';
 import ReactDOM from 'react-dom';
 import './index.css';
 import App from './components/App';
 import registerServiceWorker from './registerServiceWorker';

 const unmountButton = document.getElementById('unmount');

 // Is not very common to remove a Component from the DOM,           
  // but this will be just to understand how  
  // componentWillUnmount works.
 function unmount() {              
 ReactDOM.unmountComponentAtNode(
 document.getElementById('root')
    );

 document.getElementById('unmountMessage')
      .style.display = 'block';

 unmountButton.remove();
  }

  unmountButton.addEventListener('click', unmount);

  document.getElementById('unmountMessage')
    .style.display = 'none';

 ReactDOM.render(<App />, document.getElementById('root'));
  registerServiceWorker();
```

文件：src/index.js

1.  有了这个，我们将在页面底部有一个丑陋的红色按钮，当我们点击它时，我们将卸载我们的组件。背景将变黑，我们将显示文本“没有安装的组件！”，控制台将显示 Hasta la vista baby！：

！[](assets/ae76a546-97bb-4c7f-9e59-11b66531863a.png)

1.  点击按钮后，您将看到这个：

！[](assets/e1a1ace9-acbc-49ed-a93c-bcc20d31817f.png)

# C3.js 图表 - 实现 componentDidUpdate

C3.js 是一个第三方库，通过包装构建整个图表所需的代码，使得生成基于 D3 的图表变得容易。这意味着您不再需要编写任何 D3 代码：

1.  `componentDidUpdate`：这个 React 方法通常用于管理第三方 UI 元素并与原生 UI 交互。当我们使用第三方库如 C3.js 时，我们需要使用新数据更新 UI 库。使用 npm 安装 C3.js：

```jsx
 npm install c3
```

1.  安装 C3.js 后，我们需要将 C3 CSS 文件添加到我们的`index.html`中。现在，我们可以使用他们提供的 CDN：

```jsx
<!-- Add this on the <head> tag -->
<link href="https://cdnjs.cloudflare.com/ajax/libs/c3/0.4.10/c3.min.css" rel="stylesheet" />
```

文件：public/index.html

1.  现在我们可以创建我们的`Chart`组件：

```jsx
 import React, { Component } from 'react';
 import c3 from 'c3';
 import './Chart.css';

 class Chart extends Component {
    componentDidMount() {
      // When the component mounts the first time we update  
      // the chart.
      this.updateChart();
    }

    componentDidUpdate() {
      // When we receive a new prop then we update the chart again.
      this.updateChart();
    }

    updateChart() {
      c3.generate({
        bindto: '#chart',
        data: {
          columns: this.props.columns,
          type: this.props.chartType
        }
      });
    }

    render() {
      return <div id="chart" />;
    }
  }

 export default Chart;
```

文件：src/components/Chart/Chart.js

1.  正如您所看到的，我们在`componentDidUpdate`上执行`updateChart`方法，每当用户从`App.js`接收新的 props 时都会执行。让我们在我们的`App.js`文件中添加一些我们需要的逻辑：

```jsx
 import React, { Component } from 'react';
 import Chart from './Chart/Chart';
 import Header from '../shared/components/layout/Header';
 import Content from '../shared/components/layout/Content';
 import Footer from '../shared/components/layout/Footer';
 import './App.css';

 class App extends Component {
    constructor(props) {
      super(props);

      this.state = {
        chartType: 'line'
      };

      this.columns = [
        ['BTC', 3000, 6000, 10000, 15000, 13000, 11000],
        ['ETH', 2000, 3000, 5000, 4000, 3000, 940],
        ['XRP', 100, 200, 300, 500, 400, 300],
      ];
    }

    setBarChart = () => {
      this.setState({
        chartType: 'bar'
      });
    }

    setLineChart = () => {
      this.setState({
        chartType: 'line'
      });
    }

    render() {
      return (
        <div className="App">
          <Header title="Charts" />

          <Content>
            <Chart 
 columns={this.columns} 
 chartType={this.state.chartType} 
            />

            <p>
              Chart Type
              <button onClick={this.setBarChart}>Bar</button>
              <button onClick={this.setLineChart}>Line</button>
            </p>
          </Content>

          <Footer />
        </div>
      );
    }
  }

 export default App;
```

文件：src/components/App.js

1.  现在让我们给我们的`Chart`组件添加一些基本样式：

```jsx
 p {
    text-align: center;
  }

 button {
    background: #159fff;
    border: none;
    color: white;
    margin-left: 1em;
    padding: 0.5em 2em;
    text-transform: uppercase;
    &:hover {
      background: darken(#159fff, 5%);
    }
  }

 #chart {
    background: #fff;
    width: 90%;
    margin: 1em auto;
  }
```

文件：src/components/Chart.css

1.  在这种情况下，我们创建了一些图表来显示有关当今最重要的加密货币（BTC - 比特币，ETH - 以太坊和 XRP - 瑞波）的信息。它应该是这样的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/1174221c-8d3f-44bf-92b7-6b22e5155778.png)这张图片让你了解折线图是什么样子的

1.  我们有两个按钮可以在图表类型之间切换（柱状图或折线图）。如果我们点击 BAR，我们应该看到这个图表：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/881f0098-b76d-4104-a56a-90d2e4f69b10.png)这张图片让你了解柱状图是什么样子的。

1.  如果您从`Chart`组件中删除`componentDidUpdate`方法，那么当您按下按钮时，图表将不会更新。这是因为每当我们需要刷新数据时，我们需要调用`c3.generate`方法，在这种情况下，React 的`componentDidUpdate`方法非常有用。

# 基本动画 - 实现 componentWillUpdate

在这个例子中，我们将学习如何使用`componentWillUpdate`：

1.  `componentWillUpdate`允许您在组件接收新的 props 或新的状态之前对组件进行操作。它通常用于动画。让我们创建一个基本的动画（淡入/淡出）来看如何使用它：

```jsx
 import React, { Component } from 'react';
 import './Animation.css';

 class Animation extends Component {
    constructor() {
      super();

      this.state = {
        show: false
      };
    }

    componentWillUpdate(newProps, newState) {
      if (!newState.show) {
        document.getElementById('fade').style = 'opacity: 1;';
      } else {
        document.getElementById('fade').style = 'opacity: 0;';
      }
    }

    toggleCollapse = () => {
      this.setState({
        show: !this.state.show
      });
    }

    render() {
      return (
        <div className="Animation">
          <button onClick={this.toggleCollapse}>
            {this.state.show ? 'Collapse' : 'Expand'}
          </button>

          <div 
 id="fade" 
 className={
              this.state.show ? 'transition show' : 'transition'
            }
          >
            This text will disappear
          </div>
        </div>
      );
    }
  }

 export default Animation;
```

文件：src/components/Animation/Animation.js

1.  正如您所看到的，我们正在用`newState`验证`show state`，并观察它是 true。然后我们添加`opacity 0`，如果它是 false，我们添加`opacity 1`。关于`componentWillUpdate`我想提到的一件重要的事情是，您不能在这个方法中更新状态（这意味着您不能使用`this.setState`），因为这将导致对相同方法的另一个调用，从而创建一个无限循环。让我们添加一些样式：

```jsx
.Animation {
background: red;
 }
.Animation .transition {
transition: all 3s ease 0s;
color: white;
padding-bottom: 10px;
}
.Animation .transition.show {
padding-bottom: 300px;
background: red;
}
```

文件：src/components/Animation/Animation.css

1.  如果您运行应用程序，您将看到这个视图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/167ba80f-84d3-4d4e-b5ec-62a8a1fca076.png)

1.  在您点击按钮之后，您将看到一个文本淡出的动画，红色的 div 将被扩展，给您这个结果：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/c1e8a457-1fe6-4bb7-92d1-7bfd9669db4e.png)

# 它是如何工作的...

正如你可以看到所有这些例子，React 生命周期方法被用来处理我们应用程序中的不同场景。在*第五章，精通 Redux*中，我们将看到如何实现 Redux 以及生命周期方法如何与 Redux 状态一起工作。

# 理解 React Pure Components

许多人对函数组件和纯组件之间的区别感到困惑。他们中的大多数人认为它们是相同的，但这是不正确的。当我们使用纯组件时，我们需要从 React 中导入 `PureComponent`：

```jsx
 import React, { PureComponent } from 'react';
```

如果你的 React 组件的 render 方法是“纯”的（这意味着它根据相同的 props 和 state 渲染相同的结果），你可以使用这个函数来提高你的应用程序的性能。纯组件对 props 和 nextProps 对象以及 state 和 nextState 对象进行浅比较。纯组件不包括 `shouldComponentUpdate(nextProps, nextState)` 方法，如果我们尝试添加它，我们将收到来自 React 的警告。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/ac0abe9f-9602-4501-85c5-cabaff680fa4.png)

在这个示例中，我们将创建一个基本的例子来理解 Pure Components 是如何工作的。

# 准备工作

对于这个示例，我们需要安装 Chrome 扩展 React Developer Tools 来在我们的应用程序中进行简单的调试。在第十二章，测试和调试中，我们将深入探讨这个主题。

你可以从[`chrome.google.com/webstore/detail/react-developer-tools/fmkadmapgofadopljbjfkapdkoienihi`](https://chrome.google.com/webstore/detail/react-developer-tools/fmkadmapgofadopljbjfkapdkoienihi)下载 React Developer Tools。

# 如何做…

我们将创建一个组件，其中我们将对输入的所有数字进行求和。我们可以从最后的一些示例中开始：

1.  首先，我们要做的是修改我们的 `App.js` 并包括 Numbers 组件：

```jsx
    import React, { Component } from 'react';
    import Numbers from './Numbers/Numbers';

    import Header from '../shared/components/layout/Header';
    import Content from '../shared/components/layout/Content';
    import Footer from '../shared/components/layout/Footer';
    import './App.css';

    class App extends Component {
      render() {
        return (
          <div className="App">
            <Header title="Understanding Pure Components" />

            <Content>
              <Numbers />
            </Content>

            <Footer />
          </div>
        );
      }
    }

 export default App;
```

文件：src/components/App.js

1.  现在我们将创建 Numbers 组件：

```jsx
    // Dependencies
    import React, { Component } from 'react';

    // Components
    import Result from './Result';

    // Styles
    import './Numbers.css';

    class Numbers extends Component {
      state = {
        numbers: '', // Here we will save the input value
        results: []  // In this state we will save the results of the sums
      };

      handleNumberChange = e => {
        const { target: { value } } = e;

        // Converting the string value to array
 // "12345" => ["1", "2", "3", "4", "5"]
        const numbers = Array.from(value);

        // Summing all numbers from the array
 // ["1", "2", "3", "4", "5"] => 15
        const result = numbers.reduce((a, b) => Number(a) + Number(b), 0);

        // Updating the local state
        this.setState({
          numbers: value,
          results: [...this.state.results, result]
        });
      }

      render() {
        return (
          <div className="Numbers">
            <input
              type="number"
              value={this.state.numbers}
              onChange={this.handleNumberChange}
            />

            {/* Rendering the results array */}
            <ul>
              {this.state.results.map((result, i) => (
 <Result key={i} result={result} />
              ))}
            </ul>
          </div>
        )
      }
    }

    export default Numbers;
```

文件：src/components/Numbers/Numbers.js

1.  然后，让我们创建 Result 组件（作为一个类组件）：

```jsx
    import React, { Component } from 'react';

    class Result extends Component {
      render() {
        return <li>{this.props.result}</li>;
      }
    }

    export default Result;
```

文件：src/components/Numbers/Result.js

1.  最后，样式：

```jsx
    .Numbers {
      padding: 30px;
    }

    .Numbers input[type=number]::-webkit-inner-spin-button,
 .Numbers input[type=number]::-webkit-outer-spin-button {
      -webkit-appearance: none;
      margin: 0;
    }

    .Numbers input {
      width: 500px;
      height: 60px;
      font-size: 20px;
      outline: none;
      border: 1px solid #ccc;
      padding: 10px;
    }

    .Numbers ul {
      margin: 0 auto;
      padding: 0;
      list-style: none;
      width: 522px;
    }

    .Numbers ul li {
      border-top: 1px solid #ccc;
      border-left: 1px solid #ccc;
      border-right: 1px solid #ccc;
      padding: 10px;
    }

    .Numbers ul li:first-child {
      border-top: none;
    }

    .Numbers ul li:last-child {
      border-bottom: 1px solid #ccc;
    }
```

文件：src/components/Numbers/Numbers.css

# 它是如何工作的…

如果你运行应用程序，你会看到这个：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/da16b38c-61c7-4f56-bb6e-6e4e5b79dbc4.png)

正如你所看到的，我们使用的是类型为数字的输入，这意味着如果你开始输入数字（1，然后 2，然后 3，等等），你将看到每一行的求和结果（0 + 1 = **1**，1 + 2 = **3**，3 + 3 = **6**）。

！[](assets/97ddc724-b477-4d01-a79e-52f3782eff44.png)

对你来说，这可能看起来很简单，但是如果我们使用 React 开发者工具来检查应用程序，我们需要启用“高亮更新”选项。

！[](assets/49a2ab49-32a0-40ba-9de3-bb72d58e19ee.png)

之后，快速在输入框中输入多个数字，你将看到 React 正在执行的所有渲染。

！[](assets/de4fb8e3-93b4-409a-98cd-31234874ff9c.png)

正如你所看到的，React 正在进行大量的渲染。当高亮显示为红色时，意味着该组件的性能不佳。这就是 Pure Components 将帮助我们的地方；让我们将我们的 Result 组件迁移到成为 Pure Component：

```jsx
    import React, { PureComponent } from 'react';

    class Result extends PureComponent {
      render() {
        return <li>{this.props.result}</li>;
      }
    }

    export default Result;
```

文件：src/components/Numbers/Result.js

现在，如果我们尝试对数字做同样的事情，让我们看看有什么不同。

！[](assets/79143d3f-f02c-4263-849d-5c76f3f97b30.png)

正如你所看到的，使用 Pure Component React 与 Class Component 相比，渲染次数较少。也许现在你认为，如果我们使用无状态组件而不是 Pure Component，结果将是相同的。不幸的是，这不会发生；如果你想验证这一点，让我们再次更改 Result 组件，并将其转换为 Functional Component。：

```jsx
    import React from 'react';

    const Result = props => <li>{props.result}</li>;

    export default Result;
```

文件：src/components/Numbers/Result.js

即使代码更少，但让我们看看渲染发生了什么。

！[](assets/087b2535-7c5f-4639-8494-e7c20374a4b7.png)

正如你所看到的，结果与 Class Component 相同，这意味着并非始终使用无状态组件必然会帮助我们改善应用程序的性能。如果你认为某些组件是纯粹的，请考虑将它们转换为 Pure components。

# 在 React 中防止 XSS 漏洞

在这个示例中，我们将学习有关 React 中跨站脚本（XSS）漏洞的知识。XSS 攻击在 Web 应用程序中很常见，一些开发人员仍然不知道这一点。XSS 攻击是恶意脚本，被注入到未受保护的 Web 应用程序的 DOM 中。每个应用程序的风险都可能不同。它可能只是一个无害的警报脚本注入，或者更糟糕的是，有人可以访问你的 Cookie 并窃取你的私人凭据（密码）。

让我们创建一个 XSS 组件，开始玩一下 XSS 攻击。我们将有一个模拟来自真实服务器的响应的变量，并且我们将模拟使用 Redux 的初始状态（我们将在第五章中看到 Redux，精通 Redux）。

# 如何做到…

现在我们将看到如何创建我们的 XSS 组件：

1.  创建一个 XSS 组件：

```jsx
 import React, { Component } from 'react';

 // Let's suppose this response is coming from a service and have     
  // some XSS attacks in the content...
 const response = [
    {
      id: 1,
      title: 'My blog post 1...',
      content: '<p>This is <strong>HTML</strong> code</p>'
    },
    {
      id: 2,
      title: 'My blog post 2...',
      content: `<p>Alert: <script>alert(1);</script></p>`
    },
    {
      id: 3,
      title: 'My blog post 3...',
      content: `
 <p>
       <img onmouseover="alert('This site is not secure');" 
 src="attack.jpg" />
        </p>
      `
    }
  ];

 // Let's suppose this is our initialState of Redux 
  // which is injected to the DOM...
 const initialState = JSON.stringify(response);

 class Xss extends Component {
    render() {
      // Parsing the JSON string to an actual object...
      const posts = JSON.parse(initialState);

      // Rendering our posts...
      return (
        <div className="Xss">
          {posts.map((post, key) => (
            <div key={key}>
              <h2>{post.title}</h2>

              <p>{post.content}</p>
            </div>
          ))}
        </div>
      );
    }
  }

 export default Xss;
```

文件：src/components/Xss/Xss.js

1.  如果您呈现此组件，您将看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/5237a4d6-1d66-4b9e-bcf8-005a133c9ada.png)

1.  正如您所看到的，默认情况下，React 会阻止我们直接向组件中注入 HTML 代码。它会将 HTML 呈现为字符串。这很好，但有时我们需要在组件中插入 HTML 代码。

1.  实现`dangerouslySetInnerHTML`：这个属性可能会让你有点害怕（也许是因为它明确地说出了“危险”这个词！）。我将向您展示，如果我们知道如何安全地使用它，这个属性并不太糟糕。让我们修改我们之前的代码，然后我们将添加这个属性来看看 HTML 是如何渲染的：

```jsx
import React, { Component } from 'react';
 // Let's suppose this response is coming from a service and have       
  // some XSS attacks in the content...
 const response = [
    {
      id: 1,
      title: 'My blog post 1...',
      content: '<p>This is <strong>HTML</strong> code</p>'
    },
    {
      id: 2,
      title: 'My blog post 2...',
      content: `<p>Alert: <script>alert(1);</script></p>`
    },
    {
      id: 3,
      title: 'My blog post 3...',
      content: `
        <p>
          <img onmouseover="alert('This site is not secure');" 
          src="attack.jpg" />
        </p>
      `
    }
  ];

 // Let's suppose this is our initialState of Redux 
  // which is injected to the DOM...
 const initialState = JSON.stringify(response);

 class Xss extends Component {
    render() {
      // Parsing the JSON string to an actual object...
      const posts = JSON.parse(initialState);

      // Rendering our posts...
      return (
        <div className="Xss">
          {posts.map((post, key) => (
            <div key={key}>
              <h2>{post.title}</h2>
              <p><strong>Secure Code:</strong></p>
              <p>{post.content}</p>
              <p><strong>Insecure Code:</strong></p>
              <p 
 dangerouslySetInnerHTML={{ __html: post.content }} 
              />
            </div>
          ))}
        </div>
      );
    }
  }

 export default Xss;
```

文件：src/components/Xss/Xss.js

1.  我们的网站现在应该是这样的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/8b877eca-d229-4b4e-801b-5a191683871b.png)

1.  这很有趣，也许您认为“我的博客文章 2”的内容会在浏览器中触发警报，但实际上并没有。如果我们检查代码，警报脚本是存在的。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/2a74381f-e333-4620-913b-70446e824d4e.png)

1.  即使我们使用`dangerouslySetInnerHTML`，React 也会保护我们免受恶意脚本注入的影响，但这对我们来说还不够安全，我们不能放松对网站安全性的警惕。现在让我们看看“我的博客文章 3”的内容存在的问题。代码`<img onmouseover="alert('This site is not secure');" src="attack.jpg" />`并不直接使用`<script>`标签来注入恶意代码，而是使用了一个带有事件（`onmouseover`）的`img`标签。因此，如果您对 React 的保护感到满意，我们可以看到，如果我们将鼠标移到图像上，这个 XSS 攻击将被执行：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/ff3f07da-b726-4e70-be35-06d32a7a9192.png)

1.  删除 XSS 攻击：这有点可怕，对吧？但正如我在本教程开头所说的，有一种安全的方法来使用`dangerouslySetInnerHTML`，是的，正如你现在可能在想的那样，我们需要在使用`dangerouslySetInnerHTML`渲染之前清理我们的恶意脚本。下一个脚本将负责删除`<script>`标签和标签中的事件，当然，你可以根据你想要的安全级别进行修改：

```jsx
 import React, { Component } from 'react';

 // Let's suppose this response is coming from a service and have 
  // some XSS attacks in the content...
 const response = [
    {
      id: 1,
      title: 'My blog post 1...',
      content: '<p>This is <strong>HTML</strong> code</p>'
    },
    {
      id: 2,
      title: 'My blog post 2...',
      content: `<p>Alert: <script>alert(1);</script></p>`
    },
    {
      id: 3,
      title: 'My blog post 3...',
      content: `
        <p>
          <img onmouseover="alert('This site is not secure');" 
          src="attack.jpg" />
        </p>
      `
    }
  ];

 // Let's suppose this is our initialState of Redux 
  // which is injected to the DOM...
 const initialState = JSON.stringify(response);

 const removeXSSAttacks = html => {
    const SCRIPT_REGEX = /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi;

    // Removing the <script> tags
    while (SCRIPT_REGEX.test(html)) {
      html = html.replace(SCRIPT_REGEX, '');
    }

    // Removing all events from tags...
    html = html.replace(/ on\w+="[^"]*"/g, '');

    return {
      __html: html
    }
  };

 class Xss extends Component {
    render() {
      // Parsing the JSON string to an actual object...
      const posts = JSON.parse(initialState);

      // Rendering our posts...
      return (
        <div className="Xss">
          {posts.map((post, key) => (
            <div key={key}>
              <h2>{post.title}</h2>
              <p><strong>Secure Code:</strong></p>
              <p>{post.content}</p>
              <p><strong>Insecure Code:</strong></p>
              <p 
 dangerouslySetInnerHTML=
              {removeXSSAttacks(post.content)} 
              />
            </div>
          ))}
        </div>
      );
    }
  }

 export default Xss;
```

文件：src/components/Xss/Xss.js

1.  如果我们现在查看代码，我们会发现现在我们的渲染更加安全：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-cb/img/4cf149d2-6a90-40ea-9cc1-0a1364ae1612.png)

1.  JSON.stringify 的问题：到目前为止，我们已经学会了如何使用`dangerouslySetInnerHTML`将 HTML 代码注入到 React 组件中，但是使用 JSON.stringify 也存在潜在的安全问题。如果我们的响应中存在 XSS 攻击（内容中包含`<script>`标签），然后我们使用 JSON.stringify 将对象转换为字符串，那么 HTML 标签将不会被编码。这意味着，如果我们将该字符串注入到我们的 HTML 中（就像 Redux 在初始状态中所做的那样），我们将会有潜在的安全问题。`JSON.stringify(response)`的输出如下：

```jsx
  [
      {"id":1,"title":"My blog post 1...","content":"<p>This is <strong>HTML</strong> code</p>"},
      {"id":2,"title":"My blog post 2...","content":"<p>Alert: <script>alert(1);</script></p>"},
      {"id":3,"title":"My blog post 3...","content":"<p><img onmouseover=\"alert('This site is not secure');\" src=\"attack.jpg\" /></p>"}
  ]    
```

1.  正如你所看到的，所有的 HTML 都是裸露的，没有任何编码字符，这是一个问题。但是我们如何解决这个问题呢？我们需要安装一个叫做`serialize-javascript`的包：

```jsx
 **npm install serialize-javascript**
```

1.  我们需要使用`serialize`而不是`JSON.stringify`来序列化代码，像这样：

```jsx
 import serialize from 'serialize-javascript';

 // Let's suppose this response is coming from a service and have    
  // some XSS attacks in the content...
 const response = [
    {
      id: 1,
      title: 'My blog post 1...',
      content: '<p>This is <strong>HTML</strong> code</p>'
    },
    {
      id: 2,
      title: 'My blog post 2...',
      content: `<p>Alert: <script>alert(1);</script></p>`
    },
    {
      id: 3,
      title: 'My blog post 3...',
      content: `<p><img onmouseover="alert('This site is not 
      secure');" src="attack.jpg" /></p>`
    }
  ];

 // Let's suppose this is our initialState of Redux which is 
  // injected to the DOM...
 const initialState = serialize(response);
 console.log(initialState);
```

1.  控制台的输出如下：

```jsx
  [
      {"id":1,"title":"My blog post 1...","content":"\u003Cp\u003EThis is \u003Cstrong\u003EHTML\u003C\u002Fstrong\u003E code\u003C\u002Fp\u003E"},
      {"id":2,"title":"My blog post 2...","content":"\u003Cp\u003EAlert: \u003Cscript\u003Ealert(1);\u003C\u002Fscript\u003E\u003C\u002Fp\u003E"},
      {"id":3,"title":"My blog post 3...","content":"\u003Cp\u003E\u003Cimg onmouseover=\"alert('This site is not secure');\" src=\"attack.jpg\" \u002F\u003E\u003C\u002Fp\u003E"}
    ]
```

1.  现在我们的代码中有 HTML 实体（已编码）而不是直接包含 HTML 标签，好消息是我们可以使用`JSON.parse`将这个字符串再次转换为我们原始的对象。我们的组件应该是这样的：

```jsx
 import React, { Component } from 'react';
 import serialize from 'serialize-javascript';

 // Let's suppose this response is coming from a service and have 
  // some XSS attacks in the content...
 const response = [
    {
      id: 1,
      title: 'My blog post 1...',
      content: '<p>This is <strong>HTML</strong> code</p>'
    },
    {
      id: 2,
      title: 'My blog post 2...',
      content: `<p>Alert: <script>alert(1);</script></p>`
    },
    {
      id: 3,
      title: 'My blog post 3...',
      content: `<p><img onmouseover="alert('This site is not secure');" 
      src="attack.jpg" /></p>`
    }    
  ];

  // Let's suppose this is our initialState of Redux which is 
  // injected to the DOM...
 const secureInitialState = serialize(response);
 // const insecureInitialState = JSON.stringify(response);

 console.log(secureInitialState);

 const removeXSSAttacks = html => {
    const SCRIPT_REGEX = /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi;

    // Removing the <script> tags
    while (SCRIPT_REGEX.test(html)) {
      html = html.replace(SCRIPT_REGEX, '');
    }

    // Removing all events from tags...
    html = html.replace(/ on\w+="[^"]*"/g, '');

    return {
      __html: html
    }
  };

 class Xss extends Component {
    render() {
      // Parsing the JSON string to an actual object...
      const posts = JSON.parse(secureInitialState);

      // Rendering our posts...
      return (
        <div className="Xss">
          {posts.map((post, key) => (
            <div key={key}>
              <h2>{post.title}</h2>
              <p><strong>Secure Code:</strong></p>
              <p>{post.content}</p>
              <p><strong>Insecure Code:</strong></p>
              <p 
 dangerouslySetInnerHTML={removeXSSAttacks(post.content)} 
              />
            </div>
          ))}
        </div>
      );
    }
  }

 export default Xss;
```

文件：src/components/Xss/Xss.js

# 它是如何工作的...

正如你所看到的，XSS 攻击是很普遍的，许多网站都在不知情的情况下遭受这种问题。还有其他的注入攻击，比如 SQL 注入，在 API 中如果我们不采取最低限度的安全预防措施，可能会发生。

# 还有更多...

以下是一些安全建议：

+   始终对来自表单的用户内容进行清理。

+   始终使用`serialize`而不是`JSON.stringify`。

+   只在绝对必要时使用`dangerouslySetInnerHTML`。

+   为你的组件编写单元测试，并尝试覆盖所有可能的 XSS 攻击（我们将在第十二章中看到单元测试，测试和调试）。

+   始终使用`sha1`和`md5`加密密码，并不要忘记添加盐值（例如，如果密码是`abc123`，那么你的盐可以像这样加密：`sha1(md5('$4ltT3xt_abc123'))`。

+   如果你使用 cookie 来存储敏感信息（主要是个人信息和密码），你可以使用 Base64 保存 cookie 以混淆数据。

+   将 API 添加一些保护（安全令牌），除非你需要公开。在第八章*《使用 Node.js 和 MongoDB 以及 MySQL 创建 API》*中有关安全令牌的方法。
