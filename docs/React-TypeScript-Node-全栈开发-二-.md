# React TypeScript Node 全栈开发（二）

> 原文：[`zh.annas-archive.org/md5/F7C7A095AD12AA62E0C9F5A1E1F6F281`](https://zh.annas-archive.org/md5/F7C7A095AD12AA62E0C9F5A1E1F6F281)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第二部分：使用 React 学习单页面应用开发

在本节中，我们将学习如何设置和构建 React Web 应用程序。

本节包括以下章节：

+   *第四章*，*学习单页面应用概念以及 React 如何实现它们*

+   *第五章*，*使用 Hooks 进行 React 开发*

+   *第六章*，*使用 create-react-app 设置项目并使用 Jest 进行测试*

+   *第七章*，*学习 Redux 和 React Router*


# 第四章：学习单页应用程序的概念以及 React 如何实现它们

在本章中，我们将学习**单页应用程序**（**SPA**）。这种编程 Web 应用程序的风格在 Web 开发的历史上相对较新，但近年来已经得到了广泛的应用。它的使用现在是构建需要感觉像原生桌面或移动应用程序的大型复杂 Web 应用程序的常见做法。

我们将回顾构建 Web 应用程序的以前方法以及为什么创建了 SPA 风格的应用程序。然后，我们将学习 React 如何帮助我们以高效和有效的方式构建这种应用程序风格。

在本章中，我们将涵盖以下主要主题：

+   了解过去网站是如何构建的

+   理解 SPA 的好处和属性

+   了解 React 如何帮助构建 SPA 应用程序

# 技术要求

本章的要求与*第三章*的要求相似，*使用 ES6+功能构建更好的应用程序*。您应该对 JavaScript 以及 HTML 和 CSS 有基本的了解。我们将再次使用 Node.js 和**Visual Studio Code**（**VSCode**）。

GitHub 存储库再次位于[`github.com/PacktPublishing/Full-Stack-React-TypeScript-and-Node`](https://github.com/PacktPublishing/Full-Stack-React-TypeScript-and-Node)。使用`Chap4`文件夹中的代码。

设置本章的代码文件夹，转到您的`HandsOnTypescript`文件夹并创建一个名为`Chap4`的新文件夹。

# 了解过去网站是如何构建的

在本节中，我们将通过回顾设计和编写网页的原始方法来调查 SPA 风格编程的创建原因。了解这些知识将帮助我们理解转向 SPA 的原因。

最初，当 Web 开始时，没有 JavaScript 语言。最初，这只是为了在科学家之间共享文档而创建的静态 HTML 页面。一旦这种文档格式和互联网变得更受欢迎，人们意识到这些文档需要改进的样式方法来增强沟通。因此，创建了 CSS，并且它成为了 HTML 文档的样式和布局的标准。最后，网景浏览器公司决定 Web 需要一种脚本语言来使页面内容更加动态，于是他们创建了 JavaScript。

尽管有这些功能，原始的 Web 仍然非常静态。当您在浏览器中输入 URL 时，您会收到一个文档，即服务器上的实际文件，对于您输入的每个 URL 都是如此。CSS 和 JavaScript 确实有助于使 Web 看起来更好，更具动态性，但它并没有改变 Web 的面向页面的模型。

随着网站变得越来越复杂，许多网页开发人员希望更好地控制他们的网页文档。他们希望动态控制网页的布局和内容。这导致了**通用网关接口**（**CGI**）的创建。CGI 是对**服务器端渲染**（**SSR**）的早期尝试。这基本上意味着浏览器的请求被 Web 服务器接收，但服务器不会返回静态 HTML 页面，而是运行一个处理器，根据参数和逻辑动态生成页面，然后发送回去。

无论网站使用静态 HTML 页面还是在服务器上使用服务器端逻辑呈现其页面，在过去，重点是向浏览器发送完整的 HTML 页面作为文件。这通常是网站的工作方式。

这种单文件或基于页面的模型与本机应用程序的工作方式完全不同，无论是在桌面还是移动设备上。本机应用程序模型不同之处在于整个应用程序被下载并安装到用户的设备上。用户打开应用程序时，它已经准备好在那一刻全部使用。需要在屏幕上绘制的任何控件都是从已经存在的代码中完成的，除了发送或获取数据的调用之外，不需要额外调用后端服务器（其他调用）。这使应用程序的响应速度和速度比旧模型中不断需要刷新页面以显示新内容的经典 Web 应用程序明显更快。

SPA 应用程序的动机是使 Web 应用程序感觉更像本机设备应用程序，以便给它们相同的速度和响应性感觉。因此，SPA 风格使用各种技术和库使 Web 应用程序的功能和感觉更像本机应用程序。

在本节中，我们回顾了早期 Web 构建网站的方式。当时，重点是生成和提供单独的 HTML 文档文件。我们看到了这种编程风格的局限性，特别是与本机应用程序相比，以及 SPA 风格应用程序是试图解决这些限制并使 Web 应用程序看起来像本机应用程序的尝试。在下一节中，您将看到 SPA 应用程序是什么，以及它们如何改进原始 Web 的页面集中模型。

# 理解 SPA 的好处和特性

在本节中，我们将了解 SPA 应用程序的好处和特性。通过了解这些特性，它们将帮助我们理解在创建 React 时所做的一些架构决策，以及在创建 React 应用程序时使用的一些相关库和组件。

正如前面提到的，使用 SPA 风格的应用程序构建的动机是使我们的 Web 应用程序看起来和感觉上更像本机应用程序。通过使用 SPA 应用程序方法，我们将使我们的程序响应和外观看起来像是安装在设备上的。经典风格的 Web 应用程序可能会显得迟钝，因为对页面的任何更改都需要回调服务器以获取新屏幕。然而，SPA 风格的应用程序可以立即重绘屏幕的部分，而无需等待服务器返回新文件。因此，就用户而言，SPA 应用程序就像本机设备应用程序一样。

构建 SPA 应用程序非常复杂，需要使用许多组件和库。然而，无论我们使用 Angular、Vue、React 还是其他框架，SPA 应用程序始终具有某些特性和要求。

让我们了解一些要求：

+   顾名思义，整个应用程序只存在于一个 HTML 页面上。与使用单独页面显示不同屏幕的标准 HTML 应用程序不同，第一个页面是 SPA 应用程序上唯一加载的页面。

+   与静态 HTML 文件不同，JavaScript 动态渲染屏幕。因此，首先下载的 HTML 页面实际上几乎完全没有内容。但它将有一个根元素，位于 body 标记内，成为整个应用程序的容器，再次随着用户与应用程序的交互而实时渲染。

+   通常在检索主 HTML 文件时，需要运行应用程序的所有脚本和文件都会被下载。然而，这种方法正在改变，越来越多的应用程序只下载一个基本级别的脚本文件，然后根据需要按需下载其他脚本。我们将在后面讨论如何使用这些技术，因为它们可以通过减少屏幕等待时间来增强用户体验。

+   对于单页应用程序，URL 路由的处理方式有所不同。在 SPA 应用程序中，根据您选择的框架，会使用一些机制来创建**虚拟路由**。虚拟路由简单地意味着，尽管对用户来说，不同的调用会导致对不同的服务器端 URL 的访问，但实际上，“路由”只是在客户端浏览器上进行，以便对不同的屏幕进行逻辑转换。换句话说，不会发出对服务器的调用，URL 路由成为将应用程序逻辑上分隔成不同屏幕的手段。例如，当用户在浏览器中输入 URL 时，他们必须按下*Enter*才能将提交发送回 URL 的目的地服务器。然而，在 SPA 应用程序中发生路由时，URL 中并没有实际的服务器路径。它不存在。因此，提交不会被触发。相反，应用程序使用 URL 作为应用程序各部分的容器，并在给定某些 URL 时触发某些行为。话虽如此，URL 路由仍然是一个有用的功能，因为大多数用户都希望具有路由功能，并且它允许他们将屏幕加为书签。

在本节中，我们已经了解了构成 SPA 的属性。我们涵盖了处理整个应用程序只有一个文件的不同方法以及用于构建这些应用程序的方法。在下一节中，我们将深入了解 React 如何实现 SPA 以及 React 团队为创建这种应用程序风格所做的决定。

# 理解 React 如何帮助构建单页应用

在这一部分，我们将以高层次了解 React。这种理解将有助于我们构建更好的基于 React 的应用程序，因为我们将了解 React 在内部是如何运作的。

如前所述，网站主要只是一个 HTML 文件，这是一个基于文本的文档。这个文件包含浏览器用来创建一个称为**文档对象模型**（**DOM**）的逻辑树的代码。这个树根据它们的顺序和相对于结构中其他元素的位置来表示文件中的所有 HTML 元素。所有网站都在其页面上有一个 DOM 结构，无论它们是否使用 SPA 风格。然而，React 以独特的方式利用 DOM 来帮助构建应用程序。

React 有两个主要构造：

+   React 在运行时维护自己的虚拟 DOM。这个虚拟 DOM 与浏览器的 DOM 是不同的。它是 React 根据我们的代码指令创建和维护的 DOM 的独特副本。这个虚拟 DOM 是根据 React 服务内部执行的协调过程创建和编辑的。协调过程是一个比较过程，React 会查看浏览器 DOM 并将其与自己的虚拟 DOM 进行对比。这个协调过程通常被称为**渲染阶段**。当发现差异时，例如虚拟 DOM 包含一个浏览器 DOM 中没有的元素时，React 将向浏览器 DOM 发送指令，以创建该元素，以使浏览器 DOM 和虚拟 DOM 匹配。这个添加、编辑或删除元素的过程被称为**提交阶段**。

+   React 开发的另一个主要特点是它是状态驱动的。在 React 中，一个应用程序由许多组件组成，在每个组件中可能有一些本地状态（即数据）。如果由于任何原因这些数据发生变化，React 将触发其协调过程，并在需要时更改 DOM。

为了使这些概念更具体，我们应该看一个简单的 React 应用程序的例子。但在这之前，让我们回顾一下 React 应用程序是由什么组成的。

## React 应用程序的属性

在其核心，现代 React 应用程序需要一些基本功能才能运行。我们需要`npm`来帮助我们管理应用程序的依赖关系。正如您从我们之前的练习中看到的，`npm`是一个允许我们从中央存储库下载开源依赖项并在我们的应用程序中使用它们的存储库。我们还需要一个称为捆绑的工具。捆绑系统是一种服务，它聚合我们所有的脚本文件和资产，例如 CSS 文件，并将它们最小化为一组文件。最小化过程会从我们的脚本中删除空格和其他不需要的文本，以便最终下载到用户浏览器上的文件尽可能小。这种较小的有效载荷大小可以提高应用程序的启动时间并改善用户体验。我们将使用的捆绑系统称为 webpack，我们选择它是因为它是捆绑 React 应用程序的行业标准。此外，我们可以使用`npm`的内置脚本系统并创建脚本来自动化我们的一些工作。例如，我们可以创建脚本来启动我们的测试服务器，运行我们的测试，并构建应用程序的最终生产版本。

如果我们使用`create-react-app` `npm`包，我们可以获得所有先前提到的依赖项，以及进行 React 开发的常见依赖项和一些内置脚本来管理我们的应用程序。让我们使用这个包并创建我们的第一个应用程序：

1.  在您的终端或命令行中，转到`HandsOnTypescript/Chap4`文件夹并运行以下命令：

```ts
npx, instead of npm i -g, so that you don't have to install create-react-app locally.
```

1.  一旦这个命令完成，打开 VSCode 并打开新创建的`try-react`文件夹，这是我们在本章开始时创建的。

1.  在 VSCode 中打开终端并运行以下命令：

```ts
build. After the build completes, you should see the following structure from VSCode:
```

![图 4.1 - try-react](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_4.1_B15508.jpg)

图 4.1 - try-react

让我们从顶部开始看看`create-react-app`给我们提供了什么：

+   `build`文件夹是所有捆绑和最小化的最终生产文件的目的地。它们已经被缩小到尽可能小，并且调试信息也已被删除以提高性能。

+   接下来，我们有`node_modules`文件夹，其中包含我们从`npm`存储库下载的所有依赖项。

+   然后，我们有`public`文件夹，这是一个用于静态资产的文件夹，例如`index.html`文件，它将用于构建我们的最终应用程序。

+   接下来，也许最重要的文件夹是`src`。正如缩写的名称所示，这是包含所有源脚本的文件夹。任何扩展名为`.tsx`的文件都表示一个 React 组件。`.ts`文件只是普通的 TypeScript 文件。最后，`.css`文件包含我们的样式属性（可能不止一个）。`d.ts`文件包含 TypeScript 类型信息，编译器用它来确定需要进行的静态类型检查。

+   接下来是`.gitignore`文件。这个文件用于 GitHub 代码存储库，我们正在用它来保存本书的源代码。正如其名称所示，通过这个文件，我们告诉我们的`git`系统不要上传某些文件和文件夹，而是忽略它们。

+   `package.json`和`package-lock.json`文件用于配置和设置我们的依赖关系。此外，它们还可以存储我们构建、测试和运行脚本的配置，以及 Jest 测试框架的配置。

+   最后，我们有我们的`tsconfig.json`文件，我们在*第二章*中讨论过，*探索 TypeScript*。它将配置 TypeScript 编译器。请注意，默认情况下，严格模式已打开，因此我们不能使用隐式的`any`或`undefined`。

现在我们已经快速盘点了我们的项目，让我们来看看一些文件的内容。首先，我们将从`package.json`文件开始。`package.json`文件有许多部分，但让我们看一些最重要的部分：

+   `dependencies`部分包含我们的应用程序将用于某些功能的库。这些依赖包括 React，以及用于测试的 TypeScript 和 Jest 库。`@types`依赖项包含 TypeScript 定义文件。TypeScript 定义文件存储了 JavaScript 编写的框架的静态类型信息。换句话说，这个文件告诉 TypeScript 编译器框架使用的类型的形状，以便进行类型声明和检查。

+   还有另一个依赖项部分，称为`devDependencies`——虽然这里没有使用——通常存储开发时依赖项（与`dependencies`部分相对，后者通常只存储运行时依赖项）。出于某种原因，React 团队决定将两者合并为`dependencies`。话虽如此，你应该意识到这一点，因为你会在许多项目中看到这个部分。

+   脚本部分用于存储管理应用程序的脚本。例如，`start`脚本通过调用`npm run start`或`npm start`来使用。此脚本用于使用开发服务器启动我们的应用程序。我们还可以添加自己的脚本，稍后将会这样做，用于将生产文件部署到服务器等操作。

请注意，由`create-react-app`创建的项目已经被 React 团队进行了大量修改。它们已经被团队优化，并且隐藏了不容易看到的脚本和配置，例如基本的 webpack 配置和脚本。如果你感兴趣，你可以运行`npm run eject`来查看所有这些配置和脚本。然而，请注意这是不可逆转的。因此，你将无法撤消它。我们不会使用已弹出的项目，因为这样做没有太多好处。

现在，让我们看一些脚本。从`src`文件夹中打开`index.tsx`文件，你会看到以下内容：

```ts
import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import App from './App';
import * as serviceWorker from './serviceWorker';
ReactDOM.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
  document.getElementById('root')
);
// If you want your app to work offline and load faster, you 
   // can change
// unregister() to register() below. Note this comes with some 
 // pitfalls.
// Learn more about service workers: https://bit.ly/CRA-PWA
serviceWorker.unregister();
```

Service workers

Service workers 是 JavaScript 中进行简单线程处理的一种方式。我们不会使用这个功能，但它作为`create-react-app`项目的一部分存在，所以我留下它是为了完整性。

再次强调，任何包含返回 JSX 的 React 组件的文件都将具有`.tsx`文件扩展名。我们从这个文件开始，因为这是 React 应用程序的入口点。这是 React 开始其运行时构建过程的地方。现在，如果我们从顶部开始，我们可以看到正在使用 ES6 语法导入依赖项。导入了 React 和相关模块，包括核心的`App`模块，我们很快会探索。在导入之后，我们可以看到调用了`ReactDOM.render`，它最终“写出”了所有组件组合的 HTML。它接受两个参数。一个是从哪个最低级的 React 组件开始渲染，另一个是用于包含渲染内容的 HTML 元素。正如你所看到的，`App`组件被包裹在一个名为`React.StrictMode`的组件中。这个组件只是开发的辅助。在生产模式下编译时，它没有影响，也不会影响性能。然而，在开发模式下，它提供了关于代码潜在问题的额外信息。这可能会随时间而改变，但这里是它目前提供的帮助列表：

+   识别具有不安全生命周期的组件：它将向您显示是否正在使用不安全的生命周期调用，例如`componentWillMount`，`componentWillReceiveProps`和`componentWillUpdate`。在使用 Hooks 编码时，这些问题不适用，但了解传统基于类的组件对它们很有好处。

+   关于传统字符串引用 API 的警告：创建对 HTML 元素的引用的旧方法，而不是 React 组件，是使用字符串，例如`<div ref="myDiv">{content}</div>`。因为这种方法使用字符串，它存在问题，现在更倾向于使用`React.createRef`。我们将在后面的章节讨论为什么可能使用引用。

+   关于废弃的`findDOMNode`用法的警告：`findDOMNode`现在已经被废弃，因为它违反了抽象原则。具体来说，它允许父组件在组件树中为特定子组件编写代码。这种与代码实现的关联意味着以后更改代码变得困难，因为父组件现在依赖于其组件树中存在的某些内容。我们在*第二章*中讨论了面向对象编程原则，包括抽象。

+   检测意外副作用：副作用是我们代码的意外后果。例如，如果我的类组件在构造函数中从其他函数或属性初始化其状态，那么如果该状态有时接收不同的值进行初始化，这是不可接受的。为了帮助捕捉这类问题，`React.StrictMode`将运行某些生命周期调用，例如构造函数或`getDerivedStateFromProps`，两次尝试并显示是否发生了这种情况。请注意，这仅在开发过程中发生。

+   检测旧版上下文 API：上下文 API 是 React 的一个功能，它提供了应用程序所有组件的全局状态。有一个更新版本的 API，旧版本现在已经不推荐使用。这检查您是否在使用旧版本。

大部分检查都围绕旧的基于类的组件样式进行。然而，由于您可能需要维护的现有代码绝大部分仍然是用旧样式和类编写的，因此了解这一点仍然很重要。

接下来，让我们看一下`App.tsx`文件：

```ts
import React from 'react';
import logo from './logo.svg';
import './App.css';
function App() {
  return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo" />
        <p>
          Edit <code>src/App.tsx</code> and save to reload.
        </p>
        <a
          className="App-link"
          href="https://reactjs.org"
          target="_blank"
          rel="noopener noreferrer"
        >
          Learn React
        </a>
      </header>
    </div>
  );
}
export default App;
```

重要提示

请注意，这里显示的 JSX 语法实际上不是 HTML。它是自定义的 JavaScript。因此，每当可能与 JavaScript 关键字发生冲突时，React 都会使用另一个名称。例如，`class`是 JavaScript 中的保留关键字。因此，React 使用`className`来表示 CSS 类。

尽管`index.tsx`文件是 React 的主要起点，但我们将为应用程序构建的实际组件始于`App.tsx`文件。因此，这对我们来说是非常重要的文件。

让我们讨论一下这段代码中的一些项目：

+   首先，我们从 React 的`npm`依赖中导入 React。如果你查看`npm_modules`文件夹，你会发现一个名为`react`的子文件夹，这个文件夹就是这个`import`语句所指的。我们自己没有创建的任何代码导入都将在`node_modules`文件夹中。

+   接下来是`logo`的导入。图像资源被导入到一个 JavaScript 变量中，这种情况下是`logo`变量。另外，正如你所看到的，由于这不是一个`npm`模块，它需要一个点引用。`npm`模块不需要相对路径，因为系统知道从哪个文件夹开始查找，`npm_modules`。

+   接下来，我们导入`App.css`。这个文件是样式文件，因此没有与之关联的 JavaScript 变量。由于它不是一个`npm`包，所以它还需要一个相对路径。

+   `App`组件是一个函数组件，如其语法所示。`App`组件是整个应用程序的根父组件。该组件本身没有状态，只是渲染内容。因此，`return`语句是渲染的内容，它使用**JSX**。

+   我们将在后面的章节中详细讨论 JSX 是什么；但是，现在，JSX 是用 JavaScript 编写的类似 HTML 的语法。它是由 React 团队创建的，旨在使使用 React 组件创建 HTML 内容更容易和更清晰。需要注意的主要事项是，尽管它看起来几乎与 HTML 相同，但它实际上并不是 HTML，因此在工作方式上存在一些差异。

+   对 CSS 类的样式引用，通常设置为`class`，现在设置为`className`，如代码所示。这是因为`class`是 JavaScript 关键字，因此不能在这里使用。

+   花括号表示正在传递代码，而不是字符串。例如，`img`标签的`src`属性接受 JavaScript 变量`logo`作为其值，并且该值也在花括号内。要传递字符串，请使用引号。

让我们以开发模式启动我们的应用程序，看看这个基本屏幕是什么样子。运行以下命令：

```ts
npm start
```

运行前面的命令后，你应该在浏览器中看到以下屏幕：

![图 4.2 – 应用程序启动](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_4.2_B15508.jpg)

图 4.2 – 应用程序启动

如你所见，来自我们的`App.tsx`文件的文本和标志正在显示，因为这是我们应用程序的主要起始组件。一旦我们开始编码，我们将让这个服务器保持运行状态，当我们保存任何脚本文件时，页面将自动更新，让我们实时看到我们的更改。

为了更好地了解在 React 中构建组件以及 React 路由是如何工作的，让我们创建我们的第一个简单组件：

1.  在`src`文件夹中创建一个名为`Home.tsx`的新文件，并添加以下代码：

```ts
import React, { FC } from "react";
const Home: FC = () => {
  return <div>Hello World! Home</div>;
};
export default Home;
```

1.  现在，如你所见，我们正在创建一个名为`Home`的组件，它返回一个带有`Hello World!`字样的`div`标签。你还应该注意到，我们使用了`FC`，函数组件，声明来为我们的组件进行类型定义。在使用 React Hooks 时，函数组件是创建组件的唯一方式，而不是旧的类样式。这是因为 React 团队认为组合作为代码重用的手段比继承更有效。但请注意，无论采用何种方法，代码重用的重要性仍然存在。

1.  现在，为了让我们的组件显示在屏幕上，我们需要将它添加到我们的`App.tsx`文件中。但让我们也为我们的应用程序添加路由并探索一下。首先，像这样更新`index.tsx`文件：

```ts
import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import App from './App';
import * as serviceWorker from './serviceWorker';
import { BrowserRouter } from "react-router-dom";
ReactDOM.render(
  <React.StrictMode>
    <BrowserRouter>
    <App />
    </BrowserRouter>
  </React.StrictMode>,
  document.getElementById('root')
);
// If you want your app to work offline and load faster, 
  // you can change
// unregister() to register() below. Note this comes with
  // some pitfalls.
// Learn more about service workers: 
   // https://bit.ly/CRA-PWA
serviceWorker.unregister();
```

`index.tsx`文件现在有一个名为`BrowserRouter`的组件。这个组件是 React Router 的一部分，是一个基础组件，允许整个应用程序进行路由。由于它包裹了我们的`App`组件，而应用程序的其余部分都存在于这个`App`组件内部，这意味着整个应用程序都提供了路由服务。

1.  由于我们将使用 React Router，让我们也为第二个路由创建一个名为`AnotherScreen`的组件：

```ts
import React, { FC } from "react";
const AnotherScreen: FC = () => {
  return <div>Hello World! Another Screen</div>;
};
export default AnotherScreen;
```

1.  现在，像这样更新`App.tsx`文件：

```ts
import React from "react";
import "./App.css";
import Home from "./Home";
import AnotherScreen from './AnotherScreen';
import { Switch, Route } from "react-router";
function App() {
  return (
    <div className="App">
      <header className="App-header">
        Switch. This component acts a lot like a switch statement. It tells React Router which component to display when a certain route, URL path, is given. Inside of the Switch component, we can see two Route components. The first one is for the default root route, as indicated by path being equal to "/". For this route, React Router will display the Home component (note that using exact just means the URL should be an exact match). The second route is for the "/another" path. So, when this path is in the URL box, the AnotherScreen component will be loaded. 
```

1.  如果你让`npm start`保持运行状态，你应该会看到**Hello World!** Home，如下所示：![图 4.3 – 主页](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_4.3_B15508.jpg)

图 4.3 – 主页

1.  如果你看一下 URL，你会发现它在站点的根目录上。让我们尝试将 URL 切换到`http://localhost:3000/another`：

![图 4.4 – 另一个屏幕](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_4.4_B15508.jpg)

图 4.4 – 另一个屏幕

如你所见，它加载了`AnotherScreen`组件，根据我们的指示加载了该组件用于特定 URL。

此外，如果你打开 Chrome 浏览器的调试器，你会发现实际上没有网络调用到该特定路径。再次确认了 React Router 对这些路径没有进行任何后台处理，它们只存在于浏览器本地：

![图 4.5 – Chrome 调试器](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_4.5_B15508.jpg)

图 4.5 – Chrome 调试器

这只是一个快速的例子，用于构建 React 应用程序和组件，让我们开始。

在本节中，我们了解了 React 的内部工作原理以及如何设置 React 项目。随着我们开始构建我们的应用程序，这些知识将在接下来的章节中变得有价值。

# 摘要

在本章中，我们了解了早期网站是如何构建的。我们还了解了旧式网页开发的一些局限性，以及 SPA 应用程序是如何试图克服它们的。我们看到了 SPA 应用程序的主要驱动力是使 Web 应用程序更像本机应用程序。最后，我们对 React 开发和构建组件有了一个简介。

在下一章中，我们将在这些知识的基础上深入探讨 React 组件的构建。我们将研究基于类的组件，并将它们与更新的 Hook-style 组件进行比较和对比。到目前为止，我们所学到的关于 Web 开发和基于 React 的 Web 开发的知识将帮助我们更好地理解下一章。


# 第五章：使用 Hooks 进行 React 开发

在本章中，我们将学习使用 React Hooks 进行开发。我们将比较和对比使用旧的基于类的样式和使用 Hooks 进行开发的方式，看看为什么使用 Hooks 进行开发是 React 中更好的开发方式。我们还将学习在使用 Hooks 编码时的最佳实践，以便我们可以拥有最高质量的代码。

在本章中，我们将涵盖以下主要主题：

+   了解类式组件的限制

+   学习 React Hooks 并了解其好处

+   比较和对比类式和 Hooks 式样

# 技术要求

您应该对 Web 开发和 SPA 编码风格有基本的了解。我们将再次使用 Node 和 Visual Studio Code。

GitHub 存储库位于[`github.com/PacktPublishing/Full-Stack-React-TypeScript-and-Node`](https://github.com/PacktPublishing/Full-Stack-React-TypeScript-and-Node)。使用`Chap5`文件夹中的代码。

设置*第五章*的代码文件夹，转到您的`HandsOnTypescript`文件夹并创建一个名为`Chap5`的新文件夹。

# 了解旧类式组件的限制和问题

在本节中，我们将回顾什么是类式组件。我们将看到为什么继承式代码重用和生命周期方法，尽管初衷良好，最终并没有提供良好的代码重用和组件结构能力。尽管我们不会用类组件编写代码，但了解基于类的组件非常重要，因为大多数现有的 React 代码使用类，因为 Hooks 仍然有些新。因此，作为专业开发人员，您将不得不阅读和维护这些代码库，直到它使用 Hooks 为止。

为了了解类式组件的限制，我们首先需要回顾一下它们是什么。一个 React 应用程序由许多称为组件的个体结构组成。在使用基于类的样式时，这些组件是继承自`React.Component`的 JavaScript ES6 类。组件基本上是一个可能包含数据（称为状态）的机器，并且根据这些数据的更改通过一种称为 JSX 的语言发出 HTML。尽管组件可能变得非常复杂，但在基本层面上，这就是它们。

类组件通常有自己的状态，尽管这不是必需的。此外，基于类的组件可以有子组件。子组件只是其他 React 组件，已嵌入到父组件的渲染函数中，因此在渲染父组件时也会被渲染出来。

类组件必须继承自`React.Component`对象。通过这样做，它将获得作为 React 组件的所有功能，包括生命周期函数。这些函数是 React 提供的事件处理程序，允许开发人员在 React 组件的生命周期中特定时间发生的事件中进行挂钩。换句话说，这些函数允许我们作为开发人员在所需的时间注入我们自己的代码和逻辑到 React 组件中。

## 状态

我们在*第四章**中提到了状态，学习单页应用程序概念以及 React 如何实现它们*。在我们学习更多关于 React 组件之前，让我们深入了解一下。React 使用 JSX 将 HTML 呈现到浏览器。然而，触发这些呈现的是组件状态，或者更准确地说，是对组件状态的任何更改。那么，什么是组件状态？在 React 类组件中，有一个名为`state`的字段。这个字段是一个对象，可以包含描述相关组件的任意数量的属性。函数不应用于状态，但您可以将任意数量的函数作为类组件的成员。

正如前面提到的，改变状态会导致 React 系统重新渲染您的组件。状态变化驱动了 React 中的渲染，组件只包含自己的 UI 元素，这是保持关注点分离和清晰编码实践的好方法。基于类的组件中的状态变化是由`setState`函数触发的。这个函数接受一个参数，即您的新状态，React 稍后会异步更新您的状态。这意味着实际的状态更改不会立即发生，而是由 React 系统控制。

除了状态之外，还可以使用 props 共享组件的状态。Props 是已传递给组件的子组件的状态属性。就像当状态改变时，如果 props 改变，子组件也会触发重新渲染。父组件的重新渲染也会触发子组件的重新渲染。请注意，重新渲染并不意味着整个 UI 都会更新。协调过程仍将运行，并且将根据状态的变化和屏幕上已有的内容来确定需要更改什么。

## 生命周期方法

下面的图片很好地概述了基于类的 React 组件中的生命周期调用。正如您所看到的，它非常复杂。此外，图表中还没有提到几个已弃用的函数，比如`componentWillReceiveProps`，它们已经完全被淘汰，因为它们会导致不必要的渲染和无限循环：

![图 5.1 – React 类组件生命周期](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_5.1_B15508.jpg)

图 5.1 – React 类组件生命周期

图片来源：[`projects.wojtekmaj.pl/react-lifecycle-methods-diagram/`](http://projects.wojtekmaj.pl/react-lifecycle-methods-diagram/)

让我们从高层次开始审查这个图表。首先，您可以看到我们有**装载**、**更新**和**卸载**。装载只是组件的实例化和初始化，然后将初始化的组件添加到虚拟 React DOM 中。我们在*第四章**，学习单页应用程序概念以及 React 如何实现它们*中讨论了 React 使用的虚拟 DOM 来在自身和真实浏览器 DOM 之间协调组件。更新指的是重新渲染。当状态改变时，UI 必须更新。卸载是指组件不再使用并且将从 DOM 中移除。

现在我们将介绍生命周期方法。由于有很多方法，让我们列出它们。

### 装载

在装载下，我们有以下方法：

+   构造函数：这不是一个生命周期方法，而是内置的类构造函数。传统上用于初始化状态和绑定任何自定义事件函数。您可能还记得*第三章**，使用 ES6+功能构建更好的应用程序*中提到，`bind`用于切换函数的`this`对象。这是在构造函数中完成的。

+   `getDerivedStateFromProps(props, state)`: 如果您的本地状态基于父级的 props，您将使用此函数。这是一个静态函数。应该谨慎使用，因为它会触发额外的渲染。它也可以在更新中使用。

+   `render`：这也可以在更新时运行进行重新渲染。这个函数触发了 React 的协调过程。它应该只渲染出 JSX，也可以在数组或纯文本中。如果由于状态或 props 决定没有东西需要渲染，应该返回`null`。可能返回布尔值，但除了测试之外，我认为这样做没有太大的价值。

+   `componentDidMount`：这个函数在组件完成挂载（初始化）后触发。你可以在这里放置网络 API 调用。你也可以在这里添加事件处理程序订阅，但你必须记得在`componentWillUnmount`函数中取消订阅，否则会导致内存泄漏。你可以在这里调用`setState`来改变本地状态数据，但这样会触发第二次渲染，所以应该谨慎使用。`SetState`用于更新本地状态。

+   `UNSAFE`已弃用的方法（不要使用）是`UNSAFE_componentWillMount`，`UNSAFE_componentWillReceiveProps`和`UNSAFE_componentWillUpdate`。

### 更新

让我们来看看更新下的方法：

+   `shouldComponentUpdate(nextProps, nextState)`：用于决定是否应该进行重新渲染。它通常会比较先前的 props 和当前的 props。

+   `getSnapshotBeforeUpdate(prevProps, prevState)`：这个函数在 DOM 渲染之前立即运行，这样你就可以在 React 改变它之前捕获 DOM 状态。如果你从这个函数返回了一些东西，它会作为参数传递给`componentDidUpdate`函数。

+   `componentDidUpdate(prevProps, prevState, snapshot)`：这个函数在重新渲染完成后立即运行。你可以在这里对完成的 DOM 进行更改，或者你可以调用`setState`，但你必须有一个条件，以免引起无限循环错误。快照状态来自`getSnapshotBeforeUpdate`函数。

### 卸载

以下方法在这个级别上使用：

+   `componentWillUnmount`：这类似于 C#等语言中的`dispose`函数，可以用于清理工作，例如，移除事件监听器或其他订阅。

处理任何生命周期方法时的主要关注点是防止不必要或不想要的重新渲染。我们必须选择那种不太可能触发不必要重新渲染的方法，或者如果我们需要在特定时间运行代码，我们应该添加 prop 和 state 检查以减少不必要的重新渲染。重要的是要控制渲染，否则用户体验会因为慢和有 bug 的应用而受到影响。

让我们来看一些主要的调用。让我们从`getDerivedStateFromProps`开始。一般来说，最好避免使用这个函数，或者只是少量使用。根据经验，这使得很难弄清楚组件何时会重新渲染。一般来说，它往往会触发不必要的重新渲染，这可能会导致意外行为，而这又很难追踪。

React 团队推荐了一些替代方法，我们应该始终优先考虑这些方法，因为它们几乎总是更容易理解和行为更一致：

+   当需要根据改变的 prop 值触发行为时。例如，获取网络数据或触发其他操作。使用`componentDidUpdate`。只要在引起任何改变状态之前进行检查，就不太可能触发无限循环。例如，你可以使用`prevProps`参数并将其与你的本地状态值进行比较，然后调用`setState`来改变你的状态数据。

+   使用`memoization`技术（请注意，这个想法不一定是 React 的一部分；它只是一种编程技术）。`Memoization`基本上就像缓存，只是不是通过缓存过期来更新缓存，而是通过变量改变来更新缓存。因此，在 React 中，这只是意味着使用一个属性或函数，首先检查 props 值是否与上次不同，只有在不同的情况下才触发状态更新。

React 中有一个内置的组件包装器叫做`React.memo`。它只会在子组件的 props 改变时触发重新渲染，而不会在父组件重新渲染时触发重新渲染。

+   使您的组件完全受控，这意味着它不会有自己的状态，并且在父组件的指导下渲染，每当 props 改变或父组件渲染时。Facebook 还建议使用未受控组件，方法是通过更改它们的 key（key 是组件的唯一标识符），然后触发重新渲染。然而，我不同意这个建议。正如您所记得的，我们在[*第一章*]（B15508_01_Final_JC_ePub.xhtml#_idTextAnchor017）*，理解 TypeScript*中讨论了封装和抽象，这意味着未受控组件的行为对父组件来说应该是未知的。这也意味着它不完全受父组件控制，也不应该受到控制。因此，让未受控组件执行父组件想要的操作可能会诱使在组件内部添加实现更改，这将使其与父组件更紧密地联系在一起。有时这是不可避免的，但如果可以避免，就应该避免。

+   如果您的组件的渲染状态取决于网络数据，您可以使用`componentDidMount`在那里进行网络调用，然后更新状态（假设您只需要在加载时获取此数据）。请注意，`componentDidMount`仅在组件首次加载时运行一次。此外，如果您使用此函数，将会进行一次额外的渲染，但这仍然比可能导致额外不必要的渲染要好。

+   `ComponentDidUpdate`可用于处理由于 prop 更改而需要更改状态的情况。由于此方法在渲染后调用，因此触发任何状态更改之前将 props 与状态进行比较，不太可能导致无限渲染循环。话虽如此，最好尽量避免派生状态，并将状态保留在单个父根组件中，并通过 props 共享该状态。老实说，这是繁琐的工作，因为您需要通过 props 将状态传递给可能有几层深的子组件。这也意味着您需要很好地构建状态模式，以便可以清晰地分离为特定子组件绑定的状态。稍后当我们使用 Hooks 时，您将看到使用 Hooks 比使用单个状态对象更容易。然而，尽可能减少本地组件状态是 React 开发的最佳实践。

让我们创建一个小项目，尝试使用类组件并讨论其特性：

1.  将您的命令行或终端切换到`Chap5`文件夹。

1.  在该文件夹中运行以下命令：

```ts
npx create-react-app class-components -–template typescript
```

1.  现在在您刚创建的`class-components`文件夹中打开 Visual Studio，并在同一文件夹中打开终端或命令行。让我们在`src`文件夹中创建一个名为`Greeting.tsx`的新文件。它应该是这样的：

```ts
import React from "react";
interface GreetingProps {
    tsx. When using TypeScript and creating a React component you must use tsx as your file's extension. Next, when we look at the code we see the import of React, which provides not only the Component to inherit from but also access to JSX syntax. Next, we see two new interfaces: GreetingProps and GreetingState. Again, because we are using TypeScript and want type safety we are creating the expected types for both any props that come into our component and the state that is being used inside of our component. Also take note that the name field in the GreetingProps interface is optional, which means it can also be set to undefined, as we'll use it later. Again, avoid having local state in your non-parent non-root components when possible. I am doing this for example purposes here.
```

1.  当我们创建类时，还需要记得导出它，以便任何将使用它的组件都可以访问它。这是通过`React.Component<GreetingProps>`完成的。这种类型声明不仅表示这个类是一个 React 组件，还表示它接受`GreetingProps`类型的 prop。声明设置后，我们定义构造函数，它接受相同类型的 prop，`GreetingProps`。

重要提示

如果您的组件接受 props，重要的是在构造函数内部进行的第一个调用是对基类构造函数`super(props)`的调用。这确保了 React 知道您传入的 props，因此可以在 props 改变时做出反应（无意冒犯）。在构造函数内部，我们不需要使用`this.props`来引用`props`对象，因为它作为构造函数参数传入。在其他任何地方，都需要使用`this.props`。

1.  接下来，我们看到`state`在`constructor`中被实例化，变量及其类型在下一行被声明为`GreetingState`类型。最后，我们有我们的`render`函数，它声明了最终将被转换为 HTML 的 JSX。请注意，`render`函数具有逻辑`if`/`else`语句，根据`this.props.name`的值显示不同的 UI。`render`函数应该尽量控制正确的 UI，在没有理由渲染任何内容时不要渲染任何内容。这样做可以在一致性的情况下提高性能和内存。如果没有要`render`的内容，只需返回`null`，因为 React 理解这个值表示不要渲染任何内容。

1.  现在我们只需要更新`App.tsx`文件，以便包含我们的`Greeting.tsx`组件。打开`App.tsx`文件并像这样更新它：

```ts
import React from 'react';
import logo from './logo.svg';
import './App.css';
Greeting class. Since our Greeting class is the default export of the Greeting.tsx module file (we don't need to indicate the extension) we need not use {} in between import and from. If the Greeting class was not the default export, for example, if we had many exports in the same module file, then we would need to use this syntax: import { Greeting } from "./Greeting".
```

1.  正如您所看到的，我们使用`Greeting`组件替换了部分已经存在的 JSX。请注意，我们没有将`name`属性传递给`Greeting`。让我们看看当我们运行应用程序时会发生什么。在终端中执行此命令，确保您在`class-components`文件夹中：

```ts
name property to our Greeting component. As we saw, it was possible to leave this property empty because of the ? next to the field's type definition. 
```

1.  现在让我们去我们的`App.tsx`文件，并更新`Greeting`以添加一个`name`值。用以下内容替换`App.tsx`中的`Greeting`组件：

```ts
import React from 'react';
import logo from './logo.svg';
import './App.css';
import Greeting from "./Greeting";
function App() {
  return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo"          />
        name with a value of my own name. Feel free to enter your name instead and then save the file. Since React includes an auto-updating test server, the browser page should update with your new code automatically. You should see your name like this on the screen:
```

![图 5.3 - 更新屏幕](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_5.3_B15508.jpg)

图 5.3 - 更新屏幕

好的，我们已经创建了一个简单的基于类的组件。现在让我们开始使用一些生命周期方法，并看看它们是如何工作的：

1.  更新`Greeting.tsx`以包括`getDerivedStateFromProps`函数：

```ts
import React from "react";
interface GreetingProps {
    name?: string
}
interface GreetingState {
    message: string
}
export default class Greeting extends 
 React.Component<GreetingProps> {
    constructor(props: GreetingProps){
        super(props);
        this.state = {
            message: `Hello from, ${props.name}`
        }
    }
    state: GreetingState;
```

1.  代码几乎相同，除了我们现在将`getDerivedStateFromProps`函数添加到`render`函数的上面：

```ts
    render function we are console logging the fact that the render function was called. 
```

1.  现在让我们暂时保留这段代码，并更新我们的`App.tsx`文件，以便它可以接受一个输入，该输入获取当前用户的名字：

```ts
import React from 'react';
import logo from './logo.svg';
import './App.css';
import Greeting from "./Greeting";
class App extends React.Component {
  constructor(props:any) {
    super(props);
    state object with a field called enteredName. We also create a new function called onChangeName and bind it to the current this class instance, like we learned in *Chapter 3**, Building Better Apps with ES6+ Features*.
```

1.  在`onChangeName`中，我们将`state`属性`enteredName`设置为用户输入的值，使用`setState`函数。在类组件中，您绝对不能在不使用这个函数的情况下修改状态，否则您的状态将与 React 运行时失去同步：

```ts
  render() {
      console.log("rendering App");
      return (
      <div className="App">
        <header className="App-header">
          <img src={logo} className="App-logo" alt="logo"          />
          <input value={this.state.enteredName} 
            onChange={this.onChangeName} />
          <Greeting name={this.state.enteredName} />
        </header>
      </div>
    )
  }
}
export default App;
```

1.  接下来，我们添加了一个`console.log`语句，以查看`App.tsx`的`render`函数何时被调用。此外，我们定义了一个新的`input`控件，其值为`this.state.enteredName`，其`onChange`事件与我们的`onChangeName`函数相关联。如果您保存此代码并打开 Chrome 开发工具，您将会看到这个：![图 5.4 - 渲染问候](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_5.4_B15508.jpg)

图 5.4 - 渲染问候

您可以看到我们的`render`日志消息，以及`Greeting`的`name`属性和`message`状态值。另外，由于我们没有在`input`中输入值，`name`属性为空，因此我们的`Greeting`组件的`name`属性和`message`字符串的末尾也为空。您可能想知道为什么`Greeting`的日志运行两次。这是因为我们正在开发目的下运行在 StrictMode 中。

1.  让我们快速删除它，以免混淆。转到您的`index.tsx`文件，并用以下代码替换：

```ts
import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import App from './App';
import * as serviceWorker from './serviceWorker';
ReactDOM.render(
  StrictMode with Fragment. We don't actually need Fragment as it's only used to wrap a set of JSX elements that don't have a parent wrapping element such as div, but it's fine for our testing, and I want to leave a placeholder to put back the StrictMode tags. 
```

1.  如果您保存并查看浏览器调试控制台，您将会看到这个：![图 5.5 - 浏览器调试控制台](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_5.5_B15508.jpg)

图 5.5 - 浏览器调试控制台

所有这些工作的原因是为了显示特定可以触发渲染调用的内容，以及我们如何更加小心谨慎地处理这些内容。

1.  现在让我们在输入框中输入我们的名字，您会看到这个：![图 5.6 - App.tsx 输入](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_5.6_B15508.jpg)

图 5.6 - App.tsx 输入

1.  问题是，为什么我的消息以"Hello from, "结尾？如果您查看`Greeting`中的代码，您会发现我们只在构造函数运行期间设置了`message`状态属性一次（这实际上就像使用`componentDidMount`）。因此，由于此事件仅在屏幕首次加载时运行一次，那时`this.props.name`为空，因为我们还没有输入值。那么，我们能做些什么呢？好吧，让我们尝试使用`getDerivedStateFromProps`函数，看看会发生什么：

```ts
export default class Greeting extends React. Component<GreetingProps> {
    constructor(props: GreetingProps){
        super(props);
        this.state = {
            message: Greeting.getNewMessage(props.name)
        }
    }
    state: GreetingState;
```

1.  我只展示`Greeting`类，因为这是我想要为这个示例做出改变的唯一内容。因此，在下面的代码中，看一下更新的`getDerivedStateFromProps`：

```ts
    static getDerivedStateFromProps(props: GreetingProps, 
      state:GreetingState) {
        console.log(props, state);
        if(props.name && props.name !== state.message) {
            const newState = {...state};
            newState.message =
              Greeting.getNewMessage(props.name);
            return newState;
        }
        return state;
    }
    static getNewMessage(name: string = "") {
        return `Hello from, ${name}`;
    }
    render() {
        console.log("rendering Greeting")
        if(!this.props.name) {
            return <div>no name given</div>;
        }
        return <div>
            {this.state.message}
        </div>;
    }
}
```

正如您所看到的，这个函数现在变得更加复杂，我正在对新的属性和我们现有的状态进行比较。然后我们克隆我们的`state`对象。非常重要的是要确保您这样做，以免意外直接编辑您的状态。然后我们使用一个新的静态函数`getNewMessage`来更新`state.message`的值（因为我在多个地方设置了消息）。现在让我们尝试添加我们的名字。如果您这样做，您会发现我们的名字被添加到消息中，但是每输入一个字母，我们都会得到一个`Greeting`和`App`的渲染。现在这还不算太糟糕，因为我们的代码还不多，但是您可以想象，如果我们在`Greeting`组件的本地状态上不断添加新属性，并且我们有一个更复杂的应用程序，事情可能会变得非常困难。

让我们重构一下这段代码，看看我们是否能稍微改进一下：

1.  更新`App.tsx`：

```ts
class App extends React.Component {
  constructor(props:any) {
    super(props);
    this.state = {
      enteredName: "",
      App class since that's all we're changing. As you can see, we add a new property to our state object called message (we'll be removing message from Greeting shortly) and we update it whenever the user enters a new username into the input element:

```

render() {

console.log("rendering App");

return (

<div className="App">

<header className="App-header">

<img src={logo} className="App-logo" alt="logo"          />

<input value={this.state.enteredName}

onChange={this.onChangeName} />

<Greeting message state property to our Greeting component as a prop.

```ts

```

1.  现在我们将看一下我们的`Greeting`组件，但为了保持清晰，让我们创建一个名为`GreetingFunctional.tsx`的新文件，并将以下代码放入其中：

```ts
import React from "react";
interface GreetingProps {
    message: string
}
export default function Greeting(props: GreetingProps) {
    console.log("rendering Greeting")
    return (<div>
            {props.message}
        </div>);    
}
```

1.  一旦您添加了这个文件，您还需要更新您的`App.tsx`文件中对`Greeting`的导入，以便像这样引用这个文件：

```ts
import Greeting from "./GreetingFunctional";
```

正如您所看到的，`Greeting`已经大大缩短并变得更简单。它现在是一个功能组件，因为最佳实践是将没有本地状态的组件制作成函数而不是类。我们无法减少重新渲染，因为更改消息必然会触发重新渲染，但即使这种缩短和减少代码也值得这种改变。此外，即使我们将一些代码移到`App.tsx`中，您会注意到这段代码也比我们原来的`Greeting`组件中的代码少得多。

这种组件构建风格存在一个问题，即大部分状态都在一个单独的父组件中，子组件通过传递 props 来获取状态，对于复杂的多级组件层次结构，可能需要大量的样板代码来将 props 传递给多个级别的组件。对于这些情况，我们可以使用 React Context 来绕过层次结构，直接将父状态发送给子组件。但是，我不喜欢使用 Context，因为绕过自然的组件层次结构，任意向某个组件注入状态，感觉像是一种反模式（一种不应该使用的设计方法）。这很可能会引起混乱，并使以后重构代码变得更加困难。我稍后会更详细地介绍 Context，见*第七章**，学习 Redux 和 React Router*。

在本节中，我们了解了基于类的 React 组件。由于 Hooks 仍然相对较新，大多数现有的 React 应用程序仍在使用基于类的组件，因此了解这种编码风格仍然很重要。在下一节中，我们将探索基于 Hook 的组件，然后稍后比较这两种风格。

# 学习 React Hooks 并了解它是如何改进类式组件的。

在本节中，我们将学习 React Hooks。我们将看一个示例项目并了解它是如何工作的。由于本书主要是关于 Hooks，至少就 React 而言，它将帮助我们以后编写我们的代码。

让我们讨论一些使用 Hooks 的原因。我们在类组件部分看到，类有生命周期方法，允许您处理组件存活时发生的某些事件。使用 React Hooks，我们没有这些生命周期方法，因为使用 Hooks 时所有组件都是功能组件。在上一节的类组件示例应用程序中创建了一个功能组件`GreetingFunctional`。功能组件是一个 JavaScript 函数并返回 JSX 的组件。这种变化的原因是整个设计试图摆脱**面向对象编程**（**OOP**）继承模型，而是使用组合作为其主要代码重用模型。我们在*第二章**，探索 TypeScript*中介绍了 OOP 继承模型，但组合意味着我们不是从某个父类继承功能，而是简单地组合功能组件，有点像乐高积木，来设计我们的屏幕。

除了这些功能组件，我们还有 Hooks。Hooks 只是提供某些功能给组件的 JavaScript 函数。这些功能包括状态的创建、访问网络数据，以及组件需要的任何其他功能。此外，Hooks 不是特定于组件的，因此任何 Hook 都可以在任何组件中使用——假设它是有用的并且是合理的。如果您回顾一下我们的类组件项目，您会发现没有办法共享生命周期事件方法中的逻辑。我们不能轻松地将其提取出来，然后在其他类组件中重用。这是 React 中创建 Hooks 模型的主要原因之一。因此，这两个部分，功能组件和可重用函数（Hooks），是理解 React Hooks 的关键。

首先，让我们列出我们在代码中将要使用的一些更重要的 Hooks。我们很快会在代码中给出它们的使用示例，但现在，我们将在高层次上讨论它们：

+   `useState`：这个函数是使用 Hooks 进行开发的基础。它替换了类组件中的`state`和`setState`调用。`useState`以一个值作为参数，表示它正在尝试表示的状态属性的初始状态。它还返回一个数组。第一项是实际的状态属性，第二项是一个可以更新该属性的函数。一般来说，它用于更新单个值，而不是具有多个属性的更复杂的对象。这种类型状态的更好的 Hook 可能是`useReducer`，稍后会解释。

+   `useEffect`：这个函数在组件完成绘制到屏幕后触发。它类似于`componentDidMount`和`componentDidUpdate`。但是，它们在绘制到屏幕之前运行。它旨在用于更新状态对象。因此，例如，如果您需要获取网络数据然后更新状态，可以在这里做。您也可以在这里订阅事件，但是您还应该通过返回一个执行取消订阅的函数来取消订阅。

您可以有多个独立的`useEffect`实现，每个负责执行某些独特的操作。这个函数通常在每次完成屏幕绘制后运行。因此，如果任何组件状态或 props 发生变化，它将运行。您可以通过将空数组作为参数传递来强制它只运行一次，就像`componentDidMount`一样。您还可以通过将它们作为数组传递到`useEffect`数组参数中，来强制它仅在特定的 props 或状态更改时运行。

这个函数是异步运行的，但是如果你需要知道屏幕上一些元素的值，比如滚动位置，你可能需要使用`useLayoutEffect`。这个函数是同步运行的，允许你以同步的方式获取屏幕上某些元素的值，然后以同步的方式对它们进行操作。但是，当然，这会阻塞你的 UI，所以你只能做一些非常快速的事情，否则用户体验会受到影响。

+   `useCallback`：这个函数将在一组参数发生变化时创建一个函数实例。这个函数存在是为了节省内存，否则函数的实例将在每次渲染时重新创建。它以处理函数作为第一个参数，然后以一个可能会改变的项目数组作为第二个参数。如果项目没有改变，回调函数就不会得到一个新的实例。因此，这个函数内部使用的任何属性都将是之前的值。当我第一次了解这个函数时，我觉得很难理解，所以我稍后会举个例子。

+   `useMemo`：这个函数旨在保存长时间运行任务的结果。它有点像缓存，但只有在参数数组发生变化时才会运行，所以在这个意义上它类似于`useCallback`。然而，`useMemo`返回的是一些重型计算的结果。

+   `useReducer`：这个函数与`React Redux`类似。它接受两个参数，`reducer`和`initial state`，并返回两个对象：一个由`reducer`更新的`state`对象和一个接收更新后的状态数据（称为`action`）并将其传递给`reducer`的分发器。`reducer`充当过滤机制，并确定如何使用动作数据来更新状态。我们稍后会在代码中展示一个例子。当你想要有一个具有多个可能需要更新的属性的单一复杂状态对象时，这种方法效果很好。

+   `useContext`：这个函数是一种具有全局状态数据的方式，可以在组件之间共享。最好谨慎使用它，因为它可以任意地将状态注入到任何子组件中，而不考虑层次结构。我们将使用`React Redux`而不是`Context`，但知道它的存在是很好的。

+   `useRef`：这可以用来保存当前属性中的任何值。如果它发生变化，这个值不会触发重新渲染，而且这个值的生存期与它所创建的组件的生存期一样长。这是一种保持状态的方式，对渲染没有影响。它的一个用例是保存 DOM 元素。你可能想这样做，因为在某些情况下，有必要退出标准的基于状态的 React 模型，直接访问 HTML 元素。为此，`useRef`用于访问元素的实例。

当然，还有许多其他的 Hooks，既有来自 React 团队的，也有第三方的。但是一旦你熟悉了，你就能看到你可能需要什么，甚至更好的是，能够创建你自己的 Hooks。我们也将为我们的项目创建自己的 Hooks。

让我们来看一些使用 Hooks 的例子。我们将在`Chap5`中创建一个新项目来开始：

1.  将你的命令行或终端切换到`Chap5`文件夹，并在该文件夹中运行以下命令：

```ts
npx create-react-app hooks-components –template typescript
```

1.  在类组件项目的最后一个例子中，我们创建了一个名为`Greeting.tsx`的类组件，它有自己的状态。为了演示目的，让我们将相同的组件创建为 React Hooks 函数组件。在`hooks-components`项目的`src`文件夹中，创建一个名为`Greeting.tsx`的新文件，并添加以下代码：

```ts
import React, { FC, useState, useEffect } from 'react';
interface GreetingProps {
    name?: string
}
const Greeting: FC<GreetingProps> = ({name}:GreetingProps) => {
    const [message, setMessage] = useState("");
    useEffect(() => {
        if(name) {
            setMessage(`Hello from, ${name}`);
        }
    }, [name])
    if(!name) {
        return <div>no name given</div>;
    }
    return <div>
        {message}
    </div>;
}
export default Greeting;
```

这是代码的一个版本，我们将一个名字作为 prop 并拥有我们自己的本地状态。我们应该尽量避免使用本地状态，但我正在做这个来进行演示。正如你所看到的，这比类版本要短得多。此外，我们没有生命周期函数需要重写。我们使用箭头函数是因为它比使用常规函数要短，而且我们不需要函数的特性。正如你所看到的，我们对`Greeting`组件进行了声明。它使用了`FC`，`GreetingProps`接口。状态存储在`message`属性中，使用了`useState`函数，这是一个小的一行语句，没有构造函数，因为这是一个函数而不是一个类。注意`GreetingProps`在参数旁边并不是必要的；我只是为了完整性才包含它。还要注意，我们使用了参数解构，通过传递`{ name }`而不是`props`。

接下来，我们有我们的`useEffect`函数。正如所述，这有点类似于`componentDidMount`或`componentDidUpdate`，但是在绘制到屏幕完成后运行。每当我们的`name`prop 更新时，它将更新`message`状态属性，因为我们将它作为参数传递给`useEffect`函数。由于这不是一个类，我们没有渲染函数。函数的返回值是调用渲染。

1.  现在我们将通过将我们的状态放入`App.tsx`组件中来进行一些重构。让我们像我们在组件的类版本中做的那样，将`GreetingFunctional.tsx`组件做成这样：

```ts
import React from "react";
interface GreetingProps {
    message: string
}
export default function Greeting(props: GreetingProps) {
    console.log("rendering Greeting")
    return (<div>
            {props.message}
        </div>);    
}
```

1.  现在让我们将`App.tsx`重构为一个函数组件，并使用我们在本节学到的`useReducer` Hook。我们将省略导入，因为它们是一样的：

```ts
const reducer = (state: any, action: any) => {
  console.log("enteredNameReducer");
  switch(action.type) {
    case "enteredName":
      if(state.enteredName === action.payload) {
        return state;
      }
      return { ...state, enteredName: action.payload}
    case "message":
      return { ...state, message: `Hello, ${action.       payload}` }
    default:
      throw new Error("Invalid action type " + action.       type);
  }
}
const initialState = {
  enteredName: "",
  message: "",
};
```

我们定义了我们的 reducer 和一个名为`initialState`的初始状态对象。reducer 的默认签名是`any`类型的参数，因为状态和动作对象都可以是任何类型。如果你看一下`reducer`函数，你会注意到它试图通过返回一个新的状态对象和一个适当更新的成员来处理不同类型的动作（再次强调，你绝对不能直接修改原始状态对象。复制它，然后在新对象上进行更新并返回它）。所以，这就是`useReducer`的预期用法。如果你的状态对象很复杂，改变属性的逻辑也很复杂，你会使用`useReducer`函数。你可以把它看作是对状态对象上相关逻辑的一种封装。接下来，你可以在`App`组件中看到对`useReducer`的实际调用：

```ts
function App() {  
    const [{ message, enteredName }, dispatch] = 
      useReducer(reducer, initialState);

    const onChangeName = (e: React.     ChangeEvent<HTMLInputElement>)
      => {
      dispatch ({ type: "enteredName", payload: e.target.       value 
       });
      dispatch ({ type: "message", payload: e.target.       value });
    }

    return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo"          />
        <input value={enteredName}        onChange={onChangeName} />
        <Greeting message={message} />
      </header>
    </div>
    )
  }
  export default App;
```

正如你所看到的，这个函数返回一个对象和一个`dispatch`函数。对象是 reducer 运行后的整个状态对象，但在我们的情况下，我们进行了解构，所以我们可以直接调用`message`和`enteredName`属性。在这个设置之后，定义了`onChangeName`事件，当触发时，运行`useReducer`的分发器`dispatch`，通过发送适当的动作来触发实际的更改。如果你运行这段代码，你会发现它和以前一样运行。

现在，所有这些的好处是，正如你所看到的，我们可以把我们的`reducer`函数拿来在其他函数组件中重用。我们也可以把我们的分发器传递给子组件，这样子组件也可以触发对我们状态的更新。让我们试一试：

1.  让我们用这段代码更新我们的`GreetingFunctional.tsx`组件：

```ts
import React from "react";
interface GreetingProps {
    enteredName: string;
    message: string;
     greetingDispatcher: React.Dispatch<{ type: string,     payload: string }>;
}
export default function Greeting(props: GreetingProps) {
    console.log("rendering Greeting")
    const onChangeName = (e: React.      ChangeEvent<HTMLInputElement>) => {
        props. greetingDispatcher ({ type: "enteredName", 
          payload: e.target.value });
        props. greetingDispatcher ({ type: "message", 
           payload: e.target.value });
      }
    return (<div>
        <input value={props.enteredName} onChange=
          {onChangeName} />
            <div>
                {props.message}
            </div>
        </div>);    
}
```

正如你所看到的，我们已经将`enteredName`和`greetingDispatcher`作为 props 传递给了我们的`Greeting`组件。然后我们还带入了`input`和`onChangeName`事件，以便在我们的组件中使用它们。

1.  现在，让我们像这样更新我们的`App.tsx`文件：

```ts
function App() {  
const [{ message, enteredName }, dispatch] = useReducer(reducer, initialState);
  return (
  <div className="App">
    <header className="App-header">
      <img src={logo} className="App-logo" alt="logo" />

      <Greeting 
        message={message} 
        enteredName={enteredName} 
        greetingDispatcher={ dispatch } />
    </header>
  </div>
  )
}
```

正如你所看到的，我们已经移除了`onChangeName`和输入，以便我们可以在我们的`GreetingFunctional.tsx`组件中使用它。我们还将`enteredName`、`message`和`dispatch`作为参数传递给`Greeting`组件。如果你运行这个，你会看到触发`reducer`更新的是我们的子`GreetingFunctional.tsx`组件。

1.  接下来，让我们看看`useCallback`函数。像这样更新`App.tsx`：

```ts
function App() {  
const [{ message, enteredName }, dispatch] = useReducer(reducer, initialState);
  const [startCount, setStartCount] = useState(0);
  const [count, setCount] = useState(0);
  const setCountCallback = useCallback(() => {
    const inc = count + 1 > startCount ? count + 1 : 
      Number(count + 1) + startCount;
    setCount(inc);
  }, [count, startCount]);
  const onWelcomeBtnClick = () => {
    setCountCallback();
  }
  const onChangeStartCount = (e: 
   React.ChangeEvent<HTMLInputElement>) => {
    setStartCount(Number(e.target.value));
  }
```

我们正在使用一个输入，该输入将使用`startCount`获取用户的初始数字值。然后，我们将通过单击`setCountCallback`递增该数字。但请注意，`useCallback`是如何将`count`状态作为参数的。这意味着当`count`更改时，`setCountCallback`将重新初始化为当前值。其余的代码返回了所需的 JSX，将生成最终的 HTML：

```ts
  console.log("App.tsx render");
  return (    
  <div className="App">
    <header className="App-header">
      <img src={logo} className="App-logo" alt="logo" />

      <Greeting 
        message={message} 
        enteredName={enteredName} 
        greetingDispatcher={dispatch} />
      <div style={{marginTop: '10px'}}>
        <label>Enter a number and we'll increment           it</label>
        <br/>
        <input value={startCount}          onChange={onChangeStartCount} 
          style={{width: '.75rem'}} />&nbsp;
        <label>{count}</label>
        <br/>
        <button onClick={onWelcomeBtnClick}>Increment           count</button>
      </div>
    </header>
  </div>
  )
}
```

返回提供了这种递增能力的 UI。

如果您运行此代码并单击**增加计数**按钮，您将看到它会增加，如下所示：

![图 5.7 – 单击增加计数 8 次](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_5.7_B15508.jpg)

图 5.7 – 单击增加计数 8 次

但是，尝试更改传入的数组`[count, startCount]`，并删除`count`变量，使其只说`[startCount]`。现在，它不会继续递增，因为没有依赖于`count`。无论我们点击多少次，它只会计数一次，第一次运行时，无论我们点击多少次：

![图 5.8 – 删除 count 后](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_5.8_B15508.jpg)

图 5.8 – 删除 count 后

因此，即使您点击多次，它也将始终递增一次，因为该函数被缓存在内存中，并且始终以`count`的相同初始值运行。

让我们再看一个性能示例。我们将在此示例中使用 memo 包装器以减少重新渲染。这不是一个 Hook，但它是最近添加到 React 中的一个新功能。让我们看看步骤：

1.  创建一个名为`ListCreator.tsx`的新文件，并添加以下代码：

```ts
import React, { FC, useEffect, useRef } from 'react';
export interface ListItem {
    id: number;
}
export interface ListItems {
    listItems?: Array<ListItem>;
}
const ListCreator: FC<ListItems> = ({listItems}:ListItems) => {
    let renderItems = useRef<Array<JSX.Element> |     undefined>();
    useEffect(() => {
        console.log("listItems updated");
        renderItems.current = listItems?.map((item,          index) => {
            return <div key={item.id}>
                {item.id}
            </div>;
        });
    }, [listItems]);
    console.log("ListCreator render");
    return (
        <React.Fragment>
        {renderItems.current}
        </React.Fragment>
    );
}
export default ListCreator;
```

此组件将接受一个项目列表并将其呈现为列表。

1.  现在，让我们更新我们的`App.tsx`文件，以根据递增计数发送新的列表项。再次，我只包含了`App`函数。请注意，还需要一个名为`ListCreator`的新导入：

```ts
function App() {  
const [{ message, enteredName }, dispatch] = useReducer(reducer, initialState);
  const [startCount, setStartCount] = useState(0);
  const [count, setCount] = useState(0);
  const setCountCallback = useCallback(() => {
    const inc = count + 1 > startCount ? count + 1 :      Number(count
      + 1) + startCount;
    setCount(inc);
  }, [count, startCount]);
  listItems and a new useEffect function to populate that list. The list is updated any time count is updated:

```

const onWelcomeBtnClick = () => {

setCountCallback();

}

const onChangeStartCount = (e:

React.ChangeEvent<HTMLInputElement>) => {

setStartCount(Number(e.target.value));

}

console.log("App.tsx render");

return (

<div className="App">

<header className="App-header">

<img src={logo} className="App-logo" alt="logo" />

问候

message={message}

enteredName={enteredName}

greetingDispatcher={ dispatch } />

<div style={{marginTop: '10px'}}>

<label>输入一个数字，我们将递增           它</label>

<br/>

<input value={startCount}           onChange={onChangeStartCount}

style={{width: '.75rem'}} />&nbsp;

<label>{count}</label>

<br/>

<button onClick={onWelcomeBtnClick}>增加

count</button>

</div>

<div>

<ListCreator listItems={listItems} />

</div>

</header>

</div>

)

}

```ts

If you run this example, you will see that not only do we get new list item elements when we increment the number, but we also get them when we type our name. This is because whenever the parent component renders, as its state was updated, so do any children.
```

1.  让我们对`ListCreator`进行一些小的更新，以减少我们的渲染：

```ts
const ListCreator: FC<ListItems> = 
  React.memo(({listItems}:ListItems) => {
    let renderItems = useRef<Array<JSX.Element> |     undefined>();
    useEffect(() => {
        console.log("listItems updated");
        renderItems.current = listItems?.map((item,           index) => {
            return <div key={item.id}>
                {item.id}
            </div>;
        });
    }, [listItems]);
    console.log("ListCreator render");
    return (
        <React.Fragment>
        {renderItems.current}
        </React.Fragment>
    );
});
```

我只展示了`ListCreator`组件，但是您可以看到我们添加了一个名为`React.memo`的包装器。此包装器仅在传入的 props 发生更改时才允许组件更新。因此，我们获得了一些小的性能优势。如果这是一个具有大量元素的复杂对象，它可能会产生很大的差异。

正如您在这些示例中所看到的，对于任何给定的 Hook，我们可以在不同的组件中重用相同的 Hook，并使用不同的参数。这是 Hooks 的关键要点。代码重用现在变得更加容易。

请注意，`useState`和`useReducer`只是可重用的函数，允许您在多个组件中使用函数。因此，在组件 A 中使用`useState`，然后在组件 B 中使用`useState`将不允许您在两个组件之间共享状态，即使状态名称相同也是如此。你只是重用功能，仅此而已。

在本节中，我们学习了 React Hooks。我们回顾了库中一些主要的 Hooks 以及如何使用其中一些。我们将在以后的章节中涵盖更多的 Hooks，并开始构建我们的应用程序。这些 Hooks 的覆盖将帮助我们以后开始构建我们的组件。

# 比较和对比类方式与 Hooks 方式

在本节中，我们将讨论在 React 中以类方式和 Hooks 方式编写代码之间的一些差异。我们将看到为什么 React 团队决定使用 Hooks 是前进的方式。了解这些细节将使我们对在自己的代码中使用 Hooks 更有信心。

## 代码重用

如果你看一下基于类的生命周期方法，不仅有许多需要记住和理解的方法，而且你还可以看到对于每个类组件，你将有一个几乎独特的生命周期函数实现。这使得使用类进行代码重用变得困难。使用 Hooks，我们还有许多不同的内置 Hooks 可以使用和需要了解。然而，它们不是组件特定的，可以随意重用于不同的组件。这是使用 Hooks 的关键动机。代码重用变得更容易，因为 Hooks 不与任何特定的类绑定。每个 Hook 都专注于提供特定的功能或功能，无论它在哪里使用。此外，如果我们努力构建自己的 Hooks，我们也可以在适当的时候重用它们。

在类组件项目中查看`Greeting`。我们如何在这个组件中重用代码？即使我们可以做到这一点，它也没有真正的价值或好处。除此之外，`getDerivedStateFromProps`增加了可能触发重新渲染的复杂性。而且我们根本没有使用任何其他生命周期方法。

Hook 组件和 React 总体上优先考虑组件化而不是继承。事实上，React 团队表示，最佳实践是使用组件在其他组件中共享代码，而不是继承。

因此，要重申一下，生命周期组件通常与特定组件绑定，但是通过一些工作，Hooks 可以跨组件使用并适当地泛化它们。

## 简单性

你还记得一旦我们在其中添加了`getDerivedStateFromProps`调用，`Greeting`变得多么庞大吗？此外，我们总是需要一个构造函数来实例化我们的状态，并为所有组件使用`bind`。由于我们的组件很简单，这并不重要。但是对于生产代码，你会看到许多函数的组件都需要进行`bind`调用。

在 hooks-component 项目中，`Greeting`要简单得多。即使该组件增长，调用的 Hooks 大部分都会重复，这还会使代码更易于阅读。

# 总结

本章涵盖了大量的信息。我们了解了基于类的组件以及使它们难以使用的原因。我们还了解了基于 Hook 的组件，它们更简单，更容易重用。

我们现在了解了 React 编程的基础知识。我们现在可以创建自己的 React 组件并开始构建我们的应用程序！

在下一章中，我们将学习关于 React 周围的工具。我们将结合我们在这里获得的知识和工具信息，这将帮助我们编写干净、响应迅速的代码。


# 第六章：使用 create-react-app 设置我们的项目，并使用 Jest 进行测试

在本章中，我们将学习帮助我们构建 React 应用程序的工具。无论语言或框架如何，高级的专业应用程序开发总是涉及使用工具来帮助更快地构建应用程序并提高代码质量。React 开发生态系统也不例外。一个社区已经围绕着某些工具和编码方法形成，并且我们将在本章中介绍这些。这些复杂的工具和方法将帮助我们编写更好的应用程序，并帮助我们重构我们的代码以使其适应新的需求。

在本章中，我们将涵盖以下主要主题：

+   学习 React 开发方法和构建系统

+   了解 React 的客户端测试

+   学习 React 开发的常见工具和实践

# 技术要求

您应该对 Web 开发和我们在之前章节中学习的 SPA 编码风格有基本的了解。我们将再次使用 Node（npm）和 VS Code。

GitHub 存储库位于[`github.com/PacktPublishing/Full-Stack-React-TypeScript-and-Node`](https://github.com/PacktPublishing/Full-Stack-React-TypeScript-and-Node)。使用`Chap6`文件夹中的代码。

要在您自己的机器上设置*第六章*代码文件夹，请转到您的`HandsOnTypescript`文件夹并创建一个名为`Chap6`的新文件夹。

# 学习 React 开发方法和构建系统

在本节中，我们将学习用于编码和构建 React 应用程序的工具和实践。这些方法中的许多方法通常用于现代 JavaScript 开发，甚至在竞争框架如 Angular 和 Vue 中也是如此。

为了构建大型、复杂的应用程序，我们需要工具 - 大量的工具。其中一些工具将帮助我们编写更高质量的代码，一些将帮助我们共享和管理我们的代码，还有一些将存在只是为了增强开发人员的生产力，并使调试和测试我们的代码变得更容易。因此，通过学习用于构建现代 React 应用程序的工具，我们将确保我们的应用程序能够以最少的问题正常工作。

## 项目工具

正如我们从之前的章节中看到的，现代 React 开发使用许多组件来构建最终的应用程序。对于项目结构和基本依赖项，大多数开发人员将使用`create-react-app`，这是基于最初为 Node 开发（npm）创建的开发工具。我们已经看到了`create-react-app`可以做什么，但在本节中，我们将深入了解一下。

但首先，我们需要了解我们是如何使用当前的工具和编码方式的。这些知识将帮助我们更好地理解为什么要转向当前的风格以及好处是什么。

### 以前是如何完成的

网络实际上是由不同的技术拼凑而成的。HTML 首先出现，用于创建文本共享功能。然后是 CSS，用于更好的样式和文档结构。最后是 JavaScript，用于添加一些事件驱动的功能和编程控制。因此，难怪有时将这些技术整合到一个统一的应用程序中会感到尴尬甚至困难。让我们看一些例子，将这些部分整合在一起而不使用太多的工具：

1.  打开您的终端或命令行到`Chap6`文件夹。创建一个名为`OldStyleWebApp`的新文件夹。

1.  使用 VS Code 创建一个名为`index.html`的 HTML 文件，并将以下代码添加到其中。我们将创建一个简单的输入和显示：

```ts
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Learn React</title>
  <link rel="stylesheet" href="core.css">
</head>
<body>	
<label>Enter your name</label>
<input id="userName" />
<p id="welcomeMsg"></p>
  	<script src="img/script.js"></script>
</body>
</html>
```

1.  在同一文件夹中创建一个名为`core.css`的`.css`文件。

1.  在同一文件夹中创建一个名为`script.js`的`.js`文件。

现在，我们稍后会填写 CSS 和 JS 文件，但是立即我们遇到了一个问题。我怎么运行这个应用程序？换句话说，我怎么看到它运行，以便我可以检查它是否工作？让我们看看我们能做什么：

1.  在您的 VS Code 中，右键单击`index.html`文件并复制其路径，如下所示：![图 6.1 – 复制 index.html](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_6.01_B15508.jpg)

图 6.1 – 复制 index.html

1.  现在，打开您的浏览器，并将此文件路径粘贴到 URL 中。您应该会看到以下内容：![图 6.2 – 浏览器中的 index.html](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_6.02_B15508.jpg)

图 6.2 – 浏览器中的 index.html

您可能还不知道，但您不需要 HTTP 服务器才能在浏览器中查看 HTML 文件。但是，您可以看到这个过程并不是最有效的，如果能自动化，包括在我对任何相关文件进行更改时自动刷新，那将更好。

1.  现在，让我们填写我们的 CSS 文件：

```ts
label {
    color: blue;
}
p {
    font-size: 2rem;
}
```

您会注意到，即使我保存了这个文件，Web 浏览器上的`label`元素也不会自动更新。我必须刷新浏览器，然后它才会更新。如果我在开发会话期间更新了数十个文件怎么办？每次都手动刷新将不是一个好的体验。

1.  接下来，让我们在`script.js`中添加一些代码：

```ts
const inputEl = document.querySelector("#userName");
console.log("input", doesnotexist);
```

我们要仔细阅读这段代码，因为它存在多个问题。让我们看看这些问题是什么。如果我们保存这个文件，打开浏览器调试工具，然后刷新浏览器，您会看到在`create-react-app`项目工具中立即出现了这个错误。`create-react-app`项目具有所谓的 linter。linter 是一个代码检查工具，它在您编写代码时在后台运行。它将检查常见错误，比如我们刚刚看到的错误，以便它们不会出现在您的生产代码中。linter 还有更多功能，但我们将在以后更深入地探讨它们。关键在于我们希望在运行应用程序之前避免这些类型的错误。而`create-react-app`，或者在这种情况下一些内置的工具，可以帮助我们做到这一点。

1.  让我们尝试添加正确的变量名，并再次重新加载浏览器。像这样更新`script.js`文件，保存它，然后重新加载浏览器：

```ts
const inputEl = document.querySelector("#userName");
console.log("input", inputEl);
```

正如您在调试器控制台中所看到的，日志语句找不到`inputEl`，因为它返回`null`。这是因为我们将`input`元素的`id`误写为`"userNam"`而不是`"userName"`。现在，再次运行`create-react-app`项目时，这种错误根本不可能发生，因为绝大多数 React 代码不会尝试查询或查找我们 HTML 页面中的元素。相反，我们直接使用 React 组件，因此我们可以完全避免这类错误。诚然，可以选择退出此行为并通过`useRef`使用对 HTML 元素的引用。然而，这应该是一种谨慎的做法，因为通过使用此 Hook 故意退出正常的 React 生态系统行为，从而失去其好处。

1.  让我们修复我们的`script.js`文件并完成它。像这样更新它：

```ts
const inputEl = document.querySelector("#userName");
console.log("input", inputEl);
const parEl = document.querySelector("#welcomeMsg");
inputEl.addEventListener("change", (e) => {
    parEl.innerHTML = "Welcome " + e.target.value;
});
```

如果您通过刷新浏览器来运行此代码，您会看到如果您在输入框中输入您的姓名，然后点击输入元素外部，将显示如下消息：

![图 6.4 – 欢迎显示](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_6.04_B15508.jpg)

图 6.4 – 欢迎显示

所以，这段代码确实可以显示欢迎消息。然而，很容易出错，而且没有任何帮助指示原因。除此之外，请注意，由于浏览器不运行 TypeScript，我们没有 TypeScript。这意味着我们也缺少了类型指示器，这些指示器在避免与不正确类型相关的错误方面也很有帮助。

所以，我们已经看到了在原始的 web 方式下做事情的一些问题。但事实上，我们甚至还没有触及以这种方式进行开发的问题的表面。例如，在我们的 HTML 中嵌入脚本标签是一个合理的做法，当我们只有少量脚本要处理时。但是当我们的依赖增长时呢？对于更大的应用程序，很可能会有数百个依赖项。管理那么多脚本标签将会非常困难。而且不仅如此 - 很多 JavaScript 依赖项不再提供可以调用的 URL。

说了这么多，也许最大的问题之一是代码的高度自由形式。如果你再看一下`script.js`文件，你会发现代码没有模式或结构。当然，你的团队可能会自己想出一种模式，但是新加入团队的程序员呢？他们将不得不学习一种特定于你的团队的代码结构方式。

因此，工具、框架和结构提供了一致、可重复的编写和维护代码的方式。你可以把它看作是一种编程文化，每个人都接受了文化的规范和实践，因此知道该做什么和如何行事。这使得代码更容易编写、共享和重构。现在我们已经看过了自由形式的编码，让我们开始更深入地了解`create-react-app`。

### create-react-app

在之前的章节中，比如[*第四章*]（B15508_04_Final_JC_ePub.xhtml#_idTextAnchor072），*学习单页应用程序概念以及 React 如何实现它们*，以及[*第五章*]（B15508_05_Final_JC_ePub.xhtml#_idTextAnchor081），*使用 Hooks 进行 React 开发*，我们使用`create-react-app`来设置我们的基础应用程序项目。让我们更仔细地看一下`create-react-app`项目的内部。为了更好地理解组成`create-react-app`项目的部分，我们首先需要`弹出`它。在这里，弹出只是意味着我们将揭示所有使`create-react-app`工作的内部依赖项和脚本，因为通常这些是隐藏的。

警告：弹出是一个不可逆转的操作

在绝大多数情况下，你不会弹出`create-react-app`项目，因为这样做没有多大价值。我们在这里这样做只是为了更深入地了解这个项目是如何工作的。

让我们看一下步骤：

1.  通过在`Chap6`文件夹内执行以下命令来在其中创建一个新项目：

```ts
Chap6 called ejected-app.
```

1.  现在让我们弹出项目。在命令行中切换到新的`ejected-app`文件夹，并运行以下命令：

```ts
npm run eject
```

然后在提示符处输入`y`继续。

让我们从 VS Code 资源管理器菜单的顶部看一下这个项目：

+   `config`

这个文件夹包含了大部分配置文件和脚本，项目用来设置自身。需要注意的主要是，React 团队默认使用**Jest**进行测试和**Webpack**进行 JavaScript 文件的捆绑和最小化。我们将在*了解 React 的客户端测试*部分讨论 Jest，而 Webpack 将在本节后面讨论。

+   `node_modules`

正如你所知，这个文件夹包含了我们项目的依赖项。正如你所看到的，即使在我们添加自己的依赖项之前，默认的依赖项集合就已经非常庞大了。试图使用 HTML 脚本标签列出这些依赖项将会非常困难。而且在大多数情况下，这些依赖项不支持脚本标签引用。

+   `public`

这个文件夹包含用于生成我们的单页应用程序的静态资产。这包括我们的一个名为`index.html`的 HTML 文件，如果我们正在构建 PWA 应用程序，则需要的`manifest.json`文件。还可以添加其他文件，比如用于部署的图像文件。

+   `scripts`

`scripts` 文件夹包含用于管理项目的脚本，例如，构建、启动或启动应用程序测试的脚本。实际的测试文件不应该添加在这里。我们将在稍后的 *理解 React 客户端测试* 部分介绍测试。

+   `src` 

这当然是包含我们项目源文件的文件夹。

+   `.gitignore`

`.gitignore` 是一个文件，告诉 Git 源代码仓库系统不要跟踪哪些文件和文件夹。我们将在本节后面更深入地了解 Git。

+   `package.json` 

如前几章所述，npm 是最初为 Node 服务器框架创建的依赖管理系统。这个依赖管理器的功能和流行度最终使它成为客户端开发的标准。因此，React 团队使用 npm 作为项目创建和依赖管理的基础系统。

除了列出项目的依赖关系，它还可以列出可以运行以管理项目的脚本。

它还具有配置 Jest、ESLint 和 Babel 等功能。

+   `Package-lock.json`

这是一个相关文件，它有助于维护一组正确的依赖关系和子依赖关系，而不管它们安装的顺序如何。我们不需要直接处理这个文件，但知道这有助于防止不同开发人员在不同时间使用不同的现有依赖关系更新他们的 `npm_modules` 文件夹时出现问题是很有用的知识。

+   `tsconfig.json`

我们已经在 *第二章* 中回顾过这个文件，*探索 TypeScript*，并且如该章节中提到的，它包含了 TypeScript 编译器的设置。请注意，一般来说，React 团队更喜欢更严格的编译设置。还要注意目标 JavaScript 版本是 ES5。这是因为一些浏览器尚不兼容 ES6。

`create-react-app` 还包含两个非常重要的工具，它们使一些功能得以实现：Webpack 和 ESLint。Webpack 是一个捆绑和最小化工具，它自动完成了收集项目中所有文件的任务，移除任何多余的、未使用的部分，并将它们合并成几个文件。通过移除多余的部分，比如空格和未使用的文件或脚本，它可以大大减小用户浏览器需要下载的文件大小。当然，这会增强用户体验。除了这个核心功能，它还提供了一个“热重载”开发服务器，可以让某些脚本更改自动显示在浏览器中，而无需刷新页面（尽管大多数更改似乎会触发浏览器刷新，但至少这些是自动的）。

ESLint 也是一个重要的工具。由于 JavaScript 是一种脚本语言而不是编译语言，它没有编译器来检查语法和代码的有效性（显然，TypeScript 有，但 TypeScript 编译器主要关注类型问题）。因此，ESLint 提供了开发时代码检查，以确保它是有效的 JavaScript 语法。此外，它还允许创建自定义代码格式规则。这些规则通常用于确保团队中的每个人都使用相同的编码风格；例如，变量命名约定和括号缩进。一旦规则设置好，ESLint 服务将通过警告消息强制执行这些规则。

这些规则不仅适用于 JavaScript，还可以是关于如何为 React 等框架编写代码的规则。例如，在 `create-react-app` 项目中，ESLint 设置为 `react-app`，如 `package.json` 中所示，这是一组特定于 React 开发的编码规则。因此，我们将看到的许多消息并不一定是 JavaScript 错误，而是关于编写 React 应用程序的最佳实践的规则。

Webpack 虽然功能强大，但设置起来也非常困难。为 ESLint 创建自定义规则可能需要很长时间。所幸使用`create-react-app`的另一个好处是它为这两个工具提供了良好的默认配置。

## 转译

我们在*第一章*中介绍了转译，*理解 TypeScript*。然而，在这一章中，我们应该更深入地介绍它，因为`create-react-app`在很大程度上依赖于转译来生成其代码。`create-react-app`允许我们使用 TypeScript 或 Babel，以便我们可以用一种语言或语言版本开发代码，并将代码作为不同的语言或语言版本发出。下面是一个简单的图表，显示了在 TypeScript 转译过程中代码的流动。

![图 6.5-从 TypeScript 到 JavaScript 的转译](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_6.05_B15508.jpg)

图 6.5-从 TypeScript 到 JavaScript 的转译

TypeScript 编译器将搜索您的项目，并找到根代码文件夹（通常为`src`）中的所有`ts`或`tsx`文件。如果有错误，它会停止并通知我们，否则，它将解析并将 TypeScript 转换为纯 JavaScript 作为`js`文件，并在系统上运行。请注意，在图表中，我们还更改了 JavaScript 版本。因此，转译很像编译。代码被检查有效性和某些类别的错误，但不是转换为可以直接运行的字节码，而是转换为不同的语言或语言版本。Babel 也能够发出 JavaScript 并处理 TypeScript 开发人员的代码。但是，我更喜欢使用原始的 TypeScript 编译器，因为它是由设计 TypeScript 的同一个团队制作的，通常更加更新。

选择转译作为编译方法有多个重要的好处。首先，开发人员不需要担心他们的代码是否能在浏览器上运行，或者用户是否需要在机器上升级或安装一堆依赖。TypeScript 编译器发出 Web 标准 ECMAScript（ES3、ES5、ES6 等），因此代码可以在任何现代浏览器上运行。

转译还允许开发人员在最终发布之前利用 JavaScript 的新版本。由于 JavaScript 几乎每年都会更新一次，这个功能在利用新的语言特性或性能能力方面非常有用；例如，当考虑 JavaScript 的新功能时。ECMA 基金会，维护 JavaScript 语言的标准机构，在将更改纳入 JavaScript 的官方版本之前会经历几个阶段。但是 TypeScript 和 Babel 团队有时会在这些较早阶段之一接受新的 JavaScript 功能。这就是许多 JavaScript 开发人员在它成为官方标准之前就能在他们的代码中使用 async-await 的方式。

## 代码存储库

代码存储库是一个允许多个开发人员共享源代码的系统。代码可以被更新、复制和合并。对于大型团队来说，这个工具对于构建复杂的应用程序是绝对必要的。最流行的现代源代码控制和存储库是 Git。而最流行的在线存储库主机是 GitHub。

尽管彻底学习 Git 超出了本书的范围，但了解一些基本概念和命令是很重要的，因为在与其他开发人员互动和维护自己的项目时，您将需要它们。

任何代码存储库的更重要的概念之一是分支。这意味着能够指示项目的多个版本。例如，这些分支可以用于项目的版本号，如 1.0.0、1.0.1 等。也可以用于创建应用程序的不同版本，其中可能正在尝试一些实验性或高风险的代码。将这样的代码放入主分支不是一个好主意。这是 React GitHub 页面及其许多版本的一个例子：

![图 6.6 – React GitHub](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_6.06_B15508.jpg)

图 6.6 – React GitHub

如您所见，有许多分支。当前稳定的分支，虽然在此截图中看不到，通常称为主分支。

再次，要全面了解 Git 需要一本专门的书，所以在这里我只会介绍一些您每天会使用的主要命令：

+   `git`：此命令是 Git `git`命令，您正在使用存储库的本地副本；直到将更改推送到服务器之前，您不会直接在在线存储库上工作或影响您的队友的存储库。

+   `克隆`：此命令允许您将存储库复制到本地计算机上。请注意，当您克隆时，通常会默认为主分支。这是一个例子：

```ts
git clone https://github.com/facebook/react.git
```

+   `检出`：此子命令允许您将工作分支更改为不同的所需分支。因此，如果您想要在主分支之外的另一个分支中工作，您将使用此命令。这是一个例子：

```ts
git checkout <branch-name>
```

+   `添加`：此子命令将您最近更改的文件添加为需要跟踪的文件，这表示您稍后将它们提交到存储库中。您可以使用`add`后的`.`一次性处理所有更改的文件，或者明确指定文件：

```ts
git add <file name>
```

+   `提交`：此子命令表示您最终将使用您刚刚在本地添加的文件更新您的工作分支。如果添加`-m`参数，您可以内联添加标签来描述您的提交。此命令有助于团队成员跟踪每个提交中所做的更改：

```ts
git commit -m "My change to xyz"
```

+   `推送`：此子命令将本地提交的文件实际移动到远程存储库中：

```ts
git push origin <branch name>
```

在本节中，我们介绍了一些适用于 React 开发人员的核心项目工具。`create-react-app`、ESLint、Webpack 和 npm 提供了宝贵的功能，使开发更高效，减少错误。我们还介绍了转译，以了解如何利用新的语言版本，而不影响最终用户设备的兼容性。

另外，我们快速看了一下 Git。目前，它是最受欢迎的代码共享存储库。作为专业开发人员，您肯定会在项目中使用它。

现在我们已经掌握了一些重要的核心工具知识，我们将在下一节中继续讨论测试。现代开发实践大量使用测试和测试框架。幸运的是，JavaScript 有很好的测试框架，可以帮助我们编写高质量的测试。

# 理解 React 的客户端测试

单元测试是开发的一个非常重要的部分。如今，没有任何大型项目会在没有一定级别的单元测试的情况下编写。测试的目的是确保您的代码始终正常工作并执行预期的操作。当代码被修改时，即重构时，这一点尤为重要。事实上，更改现有复杂代码可能比创建全新代码更困难。单元测试可以防止在重构过程中破坏现有代码。但是，如果代码出现故障，它也可以帮助准确定位代码不再起作用的确切位置，以便快速修复。

在 React 中，以前有两个常用的主要测试库：`create-react-app`。因此，在本书中，我们将学习 Jest 和 testing-library。

所有单元测试都以相同的方式工作。这不仅适用于 React 和 JavaScript 测试，而且适用于任何语言的测试都以相同的方式工作。那么，什么是单元测试？单元测试尝试测试代码的一个特定部分，并试图断言关于它的某些内容是真实的。基本上就是这样。换句话说，这意味着测试是在检查某些预期的东西是否确实如此。如果不是，那么测试应该失败。尽管这个目标很简单，但创建高质量的测试并不简单。因此，我们将在这里介绍一些例子，但请记住，大型应用程序的测试可能会比实际创建应用程序的代码更复杂。因此，您需要一些时间才能熟练地编写测试。

为了更清晰，让我们看一个简单的测试。请执行以下操作：

1.  打开 VS Code 并在路径`ejected-app/src/App.test.tsx`中打开文件。这是对`App`组件的测试。我们将在接下来的内容中讨论测试的内容。

1.  打开您的终端到`ejected-app`并运行以下命令：

```ts
test. Additionally, this test script is actually running our tests in a:
```

![图 6.7 – 测试运行选项](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_6.07_B15508.jpg)

图 6.7 – 测试运行选项

如果您的测试已经运行或者您选择了`a`，您应该会看到以下结果：

![图 6.8 – 测试成功完成](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_6.08_B15508.jpg)

图 6.8 – 测试成功完成

正如您所看到的，我们的测试已经被自动发现并运行（尽管目前我们只有一个）。在这次运行中，一个测试成功，这意味着预期的事情发生了。如果有任何失败，同样的 UI 将指示有多少测试失败和多少成功。

现在，让我们看一下`App.test.tsx`中的测试：

```ts
import React from 'react';
import { render } from '@testing-library/react';
import App from './App';
test('renders learn react link', () => {
  const { getByText } = render(<App />);
  const linkElement = getByText(/learn react/i);
  expect(linkElement).toBeInTheDocument();
});
```

首先，您会注意到文件名中包含文本`test`。这告诉 Jest 这是一个测试文件。一些团队喜欢将所有测试放在一个文件夹中。一些团队更喜欢将测试放在被测试的实际文件旁边，就像这种情况。没有标准答案。做最适合您和您的团队的事情。在本书中，我们将把我们的测试放在被测试的文件旁边。让我们来看看我们`test`文件的内容：

1.  请注意，在导入中，我们引用了`@testing-library/react`。如前所述，这个库将为我们提供一些额外的工具，以使组件输出的测试更容易。

1.  现在，注意`test`函数。这个函数充当我们单个测试的封装包装器。这意味着与这个测试相关的所有内容都存在于这个函数内部，不能从外部访问。这确保了我们的测试不会受到其他测试的影响。

1.  这个函数的第一个参数是一个描述。描述是完全任意的，您的团队将有自己的标准，描述应该如何编写。我们唯一需要关注的是让描述简洁明了，清楚地说明正在测试的内容。

1.  第二个参数是运行实际测试的函数。在这种情况下，测试检查特定文本是否出现在我们的`App`组件的生成的 HTML 中。让我们逐行查看代码。

1.  在*第 6 行*，我们运行`render`，将`App`组件传递给它。这个`render`函数执行我们的组件，并返回一些属性和函数，允许我们测试生成的 HTML。在这种情况下，我们决定只接收`getByText`函数，这意味着返回一个包含特定文本的元素。

1.  在*第 7 行*，我们通过使用参数`/learn react/i`调用`getByText`来获取我们的 HTML DOM 元素，这是用于运行正则表达式的语法，但在这种情况下，它是针对文本的硬编码。

1.  最后，在*第 8 行*，进行了一个称为`expect`的断言，它期望名为`linkElement`的元素对象使用`toBeInTheDocument`函数在 DOM 中。因此，理解测试的一种简单方法是将它们的断言读作一个句子。例如，我们可以这样读取这个断言，"我期望 linkElement 在文档中"（当然，文档是浏览器 DOM）。通过这种方式阅读，很清楚意图是什么。

1.  现在，让我们看看如果我们稍微改变代码会发生什么。使用以下内容更新`App.tsx`（出于简洁起见，我只显示`App`函数）：

```ts
function App() {
  return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo"            />
        <p>
          Edit <code>src/App.tsx</code> and save to             reload.
        </p>
        <a
          className="App-link"
          href="https://reactjs.org"
          target="_blank"
          rel="noopener noreferrer"
        >
          React in Learn React.
```

1.  保存此文件后，您应该立即看到如下错误：

![图 6.9-更改 App.tsx 后的错误](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_6.09_B15508.jpg)

图 6.9-更改 App.tsx 后的错误

同样，测试运行程序正在观察模式下运行，因此只要保存更改，您就应该看到测试结果。正如您所看到的，我们的测试失败，因为未找到文本`learn react`，因此断言`expect(linkElement).toBeInTheDocument()`不成立。

好的，所以我们已经看了一下`create-react-app`提供的内置测试。现在让我们创建一个新组件，这样我们就可以从头开始编写我们自己的测试。请按照以下步骤操作：

1.  让我们保持测试处于观察模式运行，即使它显示错误，并通过单击 VS Code 终端窗口右上角的加号按钮创建一个新的终端窗口。该按钮如下所示：![图 6.10：新终端的加号标志](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_6.10_B15508.jpg)

图 6.10：新终端的加号标志

1.  现在，在`src`文件夹中创建一个名为`DisplayText.tsx`的新文件，并添加以下代码：

```ts
import React, { useState } from "react";
const DisplayText = () => {
    const [txt, setTxt] = useState("");
    const [msg, setMsg] = useState("");
    const onChangeTxt = (e: React.      ChangeEvent<HTMLInputElement>)
     => {
        setTxt(e.target.value);
    }
    const onClickShowMsg = (e: React.      MouseEvent<HTMLButtonElement, MouseEvent>) => {
        e.preventDefault();
        setMsg(`Welcome to React testing, ${txt}`);
    }
```

这个组件将在有人输入他们的名字并点击`DisplayText`后简单地显示一个新消息。

1.  然后，我们创建一些组件工作所必需的状态和事件处理程序，以处理新文本和消息的显示（我们已经介绍了如何在*第五章*中使用 Hooks 创建 React 组件）：

```ts
    return (
        <form>
            <div>
                <label>Enter your name</label>
            </div>
            <div>
                <input data-testid="user-input" 
                  value={txt} onChange={onChangeTxt} />
            </div>
            <div>
                <button data-testid="input-submit" 
                 onClick={onClickShowMsg}>Show                     Message</button>
            </div>
            <div>
                <label data-testid="final-msg" 
                   >{msg}</label>
            </div>
        </form>
    )
}
export default DisplayText;
```

1.  最后，我们返回我们的 UI，其中包括一个输入和一个提交按钮。请注意`data-testid`属性，以便稍后可以轻松地通过我们的测试找到元素。如果您运行此代码并输入您的姓名并单击按钮，您应该会看到类似于这样的东西：

![图 6.11-用于测试的新组件](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_6.11_B15508.jpg)

图 6.11-用于测试的新组件

正如您所看到的，我们的显示只是返回输入的文本和欢迎消息。然而，即使这个简单的例子也有几个不同的测试内容。首先，我们希望确保输入框中输入了文本，并且是单词而不是数字或符号。我们还希望确保当我们单击按钮时，消息被显示，并且以字符串`"Welcome to React testing"`开头，并以用户输入的文本结尾。

现在我们有了我们的组件，让我们为它构建我们的测试：

1.  我们需要注意一下我们的`tsconfig.json`文件中的一个小问题。正如我之前所述，您可以将测试放在一个单独的文件夹中，通常称为`__test__`，或者您可以将其与组件文件放在一起。为了方便起见，我们将它放在一起。如果我们这样做，我们将需要更新我们的`tsconfig.json`文件以包括这个`compilerOption`：

```ts
"types": ["node", "jest"]
```

1.  通过创建一个名为`DisplayText.test.tsx`的新文件为这个组件创建测试文件，并将初始代码添加到其中：

```ts
import React from 'react';
import { render, fireEvent } from '@testing-library/react';
import DisplayText from './DisplayText';
import "@testing-library/jest-dom/extend-expect";
describe("Test DisplayText", () => {
    it("renders without crashing", () => {
        const { baseElement } = render(<DisplayText />);
        expect(baseElement).toBeInTheDocument();
    });
    it("receives input text", () => {
        const testuser = "testuser";
        const { getByTestId } = render(<DisplayText />);
        const input = getByTestId("user-input");
        fireEvent.change(input, { target: { value:         testuser } });
        expect(input).toBeInTheDocument();
        expect(input).toHaveValue(testuser);
    })
});
```

从顶部开始，您会注意到我们从`@testing-library/react`导入了`render`，我们还从`@testing-library/jest-dom/extend-expect`导入了扩展，这使我们能够进行断言。`expect`关键字的扩展给了我们额外的函数，让我们能够以更多的方式进行测试。例如，我们使用`toHaveValue`来获取`input`的值。

在导入之后，您会注意到一些新的语法。`describe`就像其名称所示的那样，只是一种创建带有有用标签的分组容器的方法。此容器可以有多个测试，但这些测试应该都与测试特定组件或功能相关。在这种情况下，我们试图测试`DisplayText`组件，因此`describe`中的所有测试都将仅测试该组件。

因此，我们的第一个测试是使用名为`it`的函数开始的。此函数检查我们的组件`DisplayText`是否可以呈现为 HTML 而不崩溃或出错。`render`函数尝试进行呈现，`expect`和`toBeInTheDocument`函数通过检查它是否在 DOM 中来确定呈现是否成功。作为一个实验，在第一个测试`it`函数中的以`const { baseElement }`开头的行下面添加此代码`console.log(baseElement.innerHTML)`。您应该在终端中看到这个 HTML 字符串：

![图 6.12-日志：结果测试 HTML](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_6.12_B15508.jpg)

```ts
it("receive input text", () => {
        const username = "testuser";        
        const { getByTestId } = render(<DisplayText />);
        const input = getByTestId("user-input");
        fireEvent.change(input, { target: { value:           username } });
        expect(input).toBeInTheDocument();
        expect(input).toHaveValue(username);
    });
```

1.  现在，让我们创建另一个测试，以显示我们组件的端到端测试。在第二个`it`函数之后添加以下代码：

```ts
it("shows welcome message", () => {
        const testuser = "testuser";
        const msg = `Welcome to React testing,           ${testuser}`;
        const { getByTestId } = render(<DisplayText />);
        const input = getByTestId("user-input");
        const label = getByTestId("final-msg");
        fireEvent.change(input, { target: { value:           testuser } });
        const btn = getByTestId("input-submit");
        fireEvent.click(btn);

        expect(label).toBeInTheDocument();
        expect(label.innerHTML).toBe(msg);
    });
```

这个测试类似于我们的第二个测试，它在我们的`input`中添加了一个值，然后继续获取我们的`button`，然后获取我们的`label`。然后创建一个`click`事件来模拟按下按钮，在常规代码中，这会导致我们的`label`被我们的欢迎消息填充。然后测试我们`label`的内容。同样，一旦保存了这个文件，我们的测试应该重新运行，所有测试都应该通过。

1.  现在，让我们也看看快照。显然，React 开发的一个重要部分不仅是我们应用程序中可用的行为或操作，还有我们向用户呈现的实际 UI。因此，通过快照测试，我们能够检查组件确实创建了所需的 UI，HTML 元素。让我们在“呈现无崩溃”测试之后的测试中添加此代码：

```ts
it("matches snapshot", () => {
        const { baseElement } = render(<DisplayText />);
        expect(baseElement).toMatchSnapshot();
    });
```

正如您所看到的，我们的`render`函数设置为通过使用`baseElement`属性返回`DisplayText`组件的最根元素。此外，我们可以看到我们有一个名为`toMatchSnapshot`的新`expect`函数。此函数执行了一些操作：

+   第一次运行时，它会在我们的`src`文件夹的根目录下创建一个名为`__snapshot__`的文件夹。

+   然后，它添加或更新一个与我们的测试文件同名且以扩展名`.snap`结尾的文件。因此，在这种情况下，我们的测试文件快照文件将是`DisplayText.test.tsx.snap`。

此快照文件的内容是我们组件的发出 HTML 元素。因此，您拥有的快照应该看起来像这样：

```ts
// Jest Snapshot v1, https://goo.gl/fbAQLP
exports[`Test DisplayText matches snapshot 1`] = `
<body>
  <div>
    <form>
      <div>
        <label>
          Enter your name
        </label>
      </div>
      <div>
        <input
          data-testid="user-input"
          value=""
        />
      </div>
      <div>
        <button
          data-testid="input-submit"
        >
          Show Message
        </button>
      </div>
      <div>
        <label
          data-testid="final-msg"
        />
      </div>
    </form>
  </div>
</body>
`;
```

正如您所看到的，这是我们期望的 HTML 的精确副本，由我们的`DisplayText`组件发出。还要注意给出的描述以及指示它是“快照 1”。随着您的添加，编号将递增。

1.  好的，现在我们有了一个快照，我们的第一次测试运行成功了。让我们看看如果我们改变我们的`DisplayText` JSX 会发生什么。更新`DisplayText.tsx`文件，而不是您的测试文件，就像这样（为了简洁起见，我只会显示组件定义）：

```ts
const DisplayText = () => {
    const [txt, setTxt] = useState("");
    const [msg, setMsg] = useState("");
    const onChangeTxt = (e: React.     ChangeEvent<HTMLInputElement>)
      => {
        setTxt(e.target.value);
    }
    const onClickShowMsg = (e: 
      React.MouseEvent<HTMLButtonElement, MouseEvent>) =>      {
        e.preventDefault();
        setMsg(`Welcome to React testing, ${txt}`);
    }
```

前面的代码保持完全相同，但是在`return`中，我们添加了一个虚拟的`div`标签，如下所示：

```ts
    return (
        <form>
            <div>
                <label>Enter your name</label>
            </div>
            <div>
                <input data-testid="user-input"                 value={txt} 
                  onChange={onChangeTxt} />
            </div>
            <div>
                <button data-testid="input-submit" 
                 onClick={onClickShowMsg}>Show                   Message</button>
            </div>
            <div>
                <label data-testid="final-msg" >{msg}                    </label>
            </div>
            DisplayText component UI? In this case, we can force a snapshot update by entering the u character under the w character. If this does not work for you, just stop and restart your test. This is what the Watch Usage list looks like:![Figure 6.14 – Watch Usage list    ](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_6.14_B15508.jpg)Figure 6.14 – Watch Usage list
```

1.  在选择`u`之后，我们的快照文件应该成功更新，我们的快照测试应该完成。如果您打开本地快照文件，您应该看到我们之前添加到组件中的相同的新`div`标签。

所以现在我们已经看到了一些简单的测试，帮助我们入门。接下来，我们将介绍模拟的主题。

# 模拟

模拟就是用默认值替换测试中的特定功能。模拟的一个例子可能是假装进行网络调用，而实际上返回一个硬编码的值。我们这样做的原因是我们只想测试单个单元或代码的一小部分。通过模拟一些与我们正在测试的内容无关的代码部分，我们避免了混淆，并确保我们的测试始终有效。例如，如果我们试图测试代码中的输入，我们不希望网络调用失败影响该测试的结果，因为网络调用与输入元素无关。当我们想进行端到端测试或集成测试时，我们可以担心网络调用。但这与单元测试是不同的（在一些团队中，集成测试由 QA 团队单独处理），我们在这里不涉及它。现在，当涉及到 React 组件时，testing-library 实际上建议不要模拟，因为这实际上使我们的测试不太像实际代码。话虽如此，有时模拟仍然是有帮助的，所以我将展示如何模拟组件。

## 使用 jest.fn 进行模拟

让我们学习使用 Jest 进行模拟，因为它也与 Node 开发一起使用。在 Jest 中进行模拟的第一种方法是使用`fn`模拟特定函数。这个函数接受另一个函数作为参数，这个函数将执行您需要执行的任何操作来设置您想要的模拟。但除了替换任意现有代码和值的能力之外，创建模拟还将使您可以访问一个名为`mock`的成员。这个成员提供了有关您的模拟调用的指标。这很难概念化，所以让我们创建一个例子：

1.  让我们更新我们的`DisplayText`组件，以便向 Web API 发出网络调用。我们将使用`DisplayText`，它是一个根据用户名返回用户全名的函数。我们需要首先更新`App`函数文件如下：

```ts
function App() {
  const getUserFullname = async (username: string):   Promise<string> => {
    getUserFullname and then passing that as a property to our DisplayText component. As you can see, it is based on a network call to the web API of JsonPlaceholder. It calls into the users collection and then it filters the collection using the find array function. The result will get a user's full name from their username by calling userByName.name.
```

1.  现在，让我们看看更新的`DisplayText`组件代码：

```ts
import React, { useState, FC } from "react";
DisplayTextProps to house our getUserFullname function. This function is being passed in as a prop from our App component. And then we use that function within the onClickShowMsg event handler to show the welcome message with the user's full name:

```

返回（

<form>

<div>

<label>输入您的姓名</label>

</div>

<div>

<input data-testid="user-input"                   value={txt}

onChange={onChangeTxt} />

</div>

<div>

<button data-testid="input-submit"

onClick={onClickShowMsg}>显示消息</                  按钮>

</div>

<div>

<label data-testid="final-msg" >{msg}</label>

</div>

</form>

)

}

export default DisplayText;

```ts

The rest of the code is the same but is shown for completeness. So then, now if we run our app, we should see something like this:
```

![图 6.15 - 用户的全名](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_6.15_B15508.jpg)

图 6.15 - 用户的全名

如您所见，具有用户名**bret**的用户的全名为**Leanne Graham**。

现在让我们编写我们的测试，并使用 Jest 模拟我们的网络调用：

1.  打开`DisplayText.test.tsx`，注意到我们所有的测试都失败了，因为它们都没有新属性`getUserFullname`。所以，让我们更新我们的测试并模拟这个函数。以下是新的测试：

```ts
import React from 'react';
import { render, fireEvent, cleanup, wait from @testing-library/react. This is to handle asynchronous calls within our test items. For example, getUserFullname is an asynchronous call and so we need to await it. But if we do not await it, our test will fail because it will not have waited for the call to finish before moving to the next step: 

```

afterEach(cleanup);

userFullName 和 getUserFullnameMock。由于我们将在几个测试中运行我们的模拟函数，我们创建了 getUserFullnameMock 函数，以便我们可以重复使用它来给我们提供 getUserFullname 模拟函数和其他一些需要的项目。但问题可能是为什么它们看起来这么复杂？让我们浏览一下代码，弄清楚它在做什么：*在设置`userFullName`变量之后，我们创建了`getUserFullnameMock`函数。正如你所看到的，`getUserFullnameMock`函数接受一个`username`作为参数，就像真正的`getUserFullname`函数一样，并返回一个`promise`和一个`Mock`对象。*在`getUserFullnameMock`内部，定义实例化了一个`promise`对象，并使用`jest.fn`来模拟我们的`getUserFullname`函数。我们需要一个 promise 来模拟网络调用，并且稍后使用 testing-library 的`wait`调用来等待它。*如前所述，`jest.fn`用于实例化一个模拟，并让模拟执行我们可能需要的任何操作。在这种情况下，由于我们正在模拟的`getUserFullname`函数正在进行网络调用，我们需要让我们的`jest.fn`模拟返回一个 promise。它通过返回我们在上一行创建的`promise`来实现这一点。*最后，`promise`和新的模拟函数`getUserFullname`都被返回。*我们在这里做了很多工作，但在这种情况下，消除慢速和容易出错的网络调用是一个好主意。否则，如果网络调用失败，我们可能会错误地认为我们的测试和代码失败了。*接下来，让我们看看我们的模拟在测试中是如何使用的：

```ts
     it("renders without crashing", () => {
        const username = "testuser";
        getUserFullname function and pass it as a property to DisplayText. They don't otherwise use it, but it's still needed since it's a required property of DisplayText.
```

```ts

```

1.  最后一个测试已更新，因为它测试了欢迎消息。像这样更新你的最后一个测试：

```ts
    it("shows welcome message", async () => {
        const username = "testuser";
        getUserFullname function provides the user's fullname and that is fed into the welcome message that's shown in our label. In order to test that, we do an assertion with expect and toBe. Additionally, notice the await wait call just above toBe. This call must run first because our getUserFullname function is an async function and needs therefore to be awaited in order to get its results.
```

因此，通过使用`jest.fn`，我们可以模拟出一段代码，以便它可以给我们一个一致的值。同样，这有助于我们创建一致、可重现的测试，我们只测试特定的代码单元。

## 组件模拟

第二种模拟的形式是完全替换整个组件，并在我们想要测试其他代码时使用它们代替真实组件。为了测试这个，按照这里给出的步骤进行：

1.  让我们的`DisplayText`组件根据插入的用户名显示用户待办事项列表。更新组件如下：

```ts
import React, { useState, FC } from "react";
interface DisplayTextProps {
    getUserFullname: (username: string) =>       Promise<string>;
}
const DisplayText: FC<DisplayTextProps> = ({ getUserFullname })
  => {
    const [txt, setTxt] = useState("");
    const [msg, setMsg] = useState("");
    const [todos, setTodos] = useState<Array<JSX.     Element>>();
```

在这里，我们创建了一些稍后使用的状态：

```ts
    const onChangeTxt = (e: React.      ChangeEvent<HTMLInputElement>)
      => {
        setTxt(e.target.value);
    }
```

在这里，我们使用用户提供的用户名的值更新我们的输入：

```ts
    const onClickShowMsg = async (e: 
      React.MouseEvent<HTMLButtonElement, MouseEvent>) =>         {
        e.preventDefault();
        setMsg(`Welcome to React testing, ${await 
         getUserFullname(txt)}`);  
        setUsersTodos();      
    }   
```

一旦单击**显示消息**按钮，我们就会更新要显示的消息以及要显示的待办事项列表。

1.  我们将接受一个属性作为我们的消息前缀使用：

```ts
const setUsersTodos = async () => {
        const usersResponse = await 
          fetch('https://jsonplaceholder.typicode.com/          users');
        if(usersResponse.ok) {
            const users = await usersResponse.json();
            const userByName = users.find((usr: any) => {
                return usr.username.toLowerCase() ===                    txt;
            });
            console.log("user by username", userByName);
```

类似于我们通过使用他们的`username`获取用户的`fullname`，我们通过调用 JSONPlaceholder API 来获取用户的待办事项列表。首先，我们通过调用用户集合来找到用户：

```ts
            const todosResponse = await  
             fetch('https://jsonplaceholder.typicode.com/              todos');
            if(todosResponse.ok) {
                const todos = await todosResponse.json();
                const usersTodos = todos.filter((todo:                 any) => {
                    return todo.userId === userByName.id;
                });
                const todoList = usersTodos.map((todo:                  any) => {
                    return <li key={todo.id}>
                        {todo.title}
                    </li>
                });
                setTodos(todoList);
                console.log("user todos", usersTodos);
            }
        }
    }
```

然后我们调用待办事项集合，并将待办事项与先前找到的用户进行匹配。

1.  最后，我们通过 UI 返回一个未排序的待办事项列表：

```ts
    return (
        <form>
            <div>
                <label>Enter your name</label>
            </div>
            <div>
                <input data-testid="user-input"                 value={txt} 
                  onChange={onChangeTxt} />
            </div>
            <div>
                <button data-testid="input-submit" 
                 onClick={onClickShowMsg}>Show Message</                  button>
            </div>
            <div>
                <label data-testid="final-msg" >{msg}</                label>
            </div>
            bret has any todos). Note that the text that you see is *lorem ipsum*. It is just placeholder text. It is coming straight from the JSONPlaceholder API:
```

![图 6.16 - 用户待办事项列表](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_6.16_B15508.jpg)

图 6.16 - 用户待办事项列表

在这里，我们显示用户 bret 的待办事项列表。

现在，假设我们想要测试我们的`DisplayText`组件，而不测试这个待办事项列表。我们如何重构这段代码，使得我们的测试不会那么庞大？让我们重构我们的`DisplayText`组件，并将待办事项功能提取为自己的组件：

1.  像这样更新`DisplayText`文件：

```ts
import React, { useState, FC } from "react";
import UserTodos from "./UserTodos";
interface DisplayTextProps {
    getUserFullname: (username: string) =>       Promise<string>;
}
const DisplayText: FC<DisplayTextProps> = ({ getUserFullname }) => {
    const [txt, setTxt] = useState("");
    const [msg, setMsg] = useState("");
    todoControl. The type of this state is the type of our new UserTodos component, which we'll show later. We've gotten this type by using the utility type ReturnType. As you can see, it is a simple way of creating a type definition by using an object: 

```

const onClickShowMsg = async (e：

React.MouseEvent<HTMLButtonElement, MouseEvent>) =>         {

e.preventDefault();

setTodoControl(null);

setMsg(`欢迎来到 React 测试，${await

getUserFullname(txt)}`);

onClickShowMsg 事件处理程序将调用 setTodoControl 并将我们的 UserTodos 组件传递给用户名：

```ts
    return (
        <form>
            <div>
                <label>Enter your name</label>
            </div>
            <div>
                <input data-testid="user-input"                 value={txt} 
                  onChange={onChangeTxt} />
            </div>
            <div>
                <button data-testid="input-submit" 
                 onClick={onClickShowMsg}>Show Message</                    button>
            </div>
            <div>
                <label data-testid="final-msg" >{msg}</                label>
            </div>    
            todoControl gets displayed with our UI.
```

```ts

```

1.  现在让我们创建我们的新`UserTodos`组件。创建一个名为`UserTodos.tsx`的文件，并添加以下代码：

```ts
import React, { FC, useState, useEffect } from 'react';
interface UserTodosProps {
    username: string;
}
```

我们现在从父级获取用户名作为一个属性：

```ts
const UserTodos: FC<UserTodosProps> = ({ username }) => {
    const [todos, setTodos] = useState<Array<JSX.      Element>>();
    const setUsersTodos = async () => {
        const usersResponse = await 
         fetch('https://jsonplaceholder.typicode.com/          users');
        if(usersResponse) {
            const users = await usersResponse.json();
            const userByName = users.find((usr: any) => {
                return usr.username.toLowerCase() ===                  username;
            });
            console.log("user by username", userByName);
```

首先，我们再次从用户集合中获取我们的用户，并过滤以找到我们的一个用户，通过匹配`username`：

```ts
            const todosResponse = await 
             fetch('https://jsonplaceholder.typicode.com/             todos');
            if(userByName && todosResponse) {
                const todos = await todosResponse.json();
                const usersTodos = todos.filter((todo:                 any) => {
                    return todo.userId === userByName.id;
                });
                const todoList = usersTodos.map((todo:                 any) => {
                    return <li key={todo.id}>
                        {todo.title}
                    </li>
                });
                setTodos(todoList);
                console.log("user todos", usersTodos);
            }
        }
    }
```

然后我们获取找到用户的匹配待办事项。然后我们运行 JavaScript 的`map`函数为每个待办事项创建一个`li`元素的集合：

```ts
    useEffect(() => {
        if(username) {
        setUsersTodos();
        }
    }, [username]);
```

通过使用`useEffect`，我们表明每当我们的`username`属性发生变化时，我们都希望更新我们的待办事项列表：

```ts
    return <ul style={{marginTop: '1rem', listStyleType: 
     'none'}}>
        {todos}
    </ul>;
}
export default UserTodos;
```

最后，我们将我们的待办事项输出为无序列表元素。如果你运行这段代码，当你点击**显示消息**时，你应该会看到这个：

![图 6.17 – 重构后的待办事项](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_6.17_B15508.jpg)

图 6.17 – 重构后的待办事项

好的，现在我们可以添加一个新的测试，模拟我们的`UserTodos`组件，从而允许独立测试`DisplayText`。还要注意，使用 Jest 有两种主要的模拟方式。我们可以进行内联调用来模拟，也可以使用一个模拟文件。在这个例子中，我们将使用一个模拟文件。让我们看看步骤：

1.  在`src`文件夹中，创建一个新文件夹`__mocks__`。在该文件夹中，创建一个名为`UserTodos.tsx`的文件，并将以下代码添加到其中：

```ts
import React, { ReactElement } from 'react';
export default (): ReactElement => {
    return <></>;
  };
```

这个文件将是函数组件的模拟版本。正如你所看到的，它什么也不返回，也没有真正的成员。这意味着与真实组件不同，它不会进行任何网络调用或发出任何 HTML，这对于测试来说是我们想要的。

1.  现在让我们用以下代码更新`DisplayText.test.tsx`：

```ts
import React from 'react';
import { render, fireEvent, cleanup, wait } from '@testing-library/react';
import DisplayText from './DisplayText';
import "@testing-library/jest-dom/extend-expect";
jest.mock("./UserTodos");
afterEach(cleanup);
describe("Test DisplayText", () => {
    const userFullName = "John Tester";

    const getUserFullnameMock = (username: string): 
    [Promise<string>, jest.Mock<Promise<string>,         [string]>] => {        
        const promise = new Promise<string>((res, rej) => {
            res(userFullName);
        });
        const getUserFullname = jest.fn(async (username:          string):
          Promise<string> => {             
            return promise;
        });
        return [promise, getUserFullname];
    }
```

首先，我们可以看到我们在任何测试之外导入了我们的模拟`UserTodos`组件。这是必要的，因为在测试内部这样做是行不通的。

其余的测试都是一样的，但现在它们内部使用`UserTodos`的模拟。因此，由于没有网络调用，测试运行得更快。作为对你新学到的测试技能的试验，尝试单独为`UserTodos`组件创建你自己的测试。

在本节中，我们学习了使用 Jest 和 testing-library 测试 React 应用程序。单元测试是应用程序开发的一个非常重要的部分，作为专业程序员，你几乎每天都会编写测试。它可以帮助编写和重构代码。

在接下来的部分，我们将继续通过讨论在 React 应用程序开发中常用的工具来增加我们的开发者技能。

# 学习 React 开发的常用工具和实践

有许多工具可以帮助编写 React 应用程序。它们太多了，无法详尽列举，但我们将在这里回顾一些最常见的。这些工具对于编写和调试你的代码至关重要，所以你应该花一些时间熟悉它们。

## VS Code

在整本书中，我们一直使用 VS Code 作为我们的代码编辑器。对于 JavaScript 开发，VS Code 显然是目前使用最广泛的编辑器。以下是一些你应该知道的事实，以便最大限度地利用 VS Code：

+   VS Code 有一个庞大的扩展生态系统，可以帮助编码。其中许多依赖于开发者的偏好，所以你应该快速搜索并查看一下。然而，以下是一些你应该考虑使用的常见扩展：

**Visual Studio IntelliCode**：提供了一个基于人工智能驱动的代码完成和语法高亮的语言服务。

阿波罗 GraphQL：GraphQL 的代码完成和格式化助手。

**与 React 相关的插件**：有许多与 React 相关的插件，可以通过提供代码片段或将 Hooks 集成到 NPM 等服务来帮助。以下只是其中一些：

![图 6.18 – React VS Code 插件](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_6.18_B15508.jpg)

图 6.18 – React VS Code 插件

+   VS Code 有一个内置的调试器，允许你在代码上中断（停止）并查看变量值。我不会在这里演示它，因为前端开发的标准是使用 Chrome 调试器，它也允许在代码上中断，但一旦我们开始使用 Node，我会演示它。

+   配置文件：在 VS Code 中，有两种设置项目偏好的方式，一个是工作区，另一个是`settings.json`文件。关于字体、扩展、窗口等方面，VS Code 有大量的配置方式。这些配置可以在全局范围内进行，也可以在每个项目中进行。我在`ejected-app`项目中包含了一个`.vscode/settings.json`文件，用于演示目的。工作区文件基本上与设置文件相同，只是它们用于在单个文件夹中使用多个项目。工作区文件的命名为`<name>.code-workspace`。

## Prettier

在编写代码时，使用一致的风格非常重要，以提高可读性。例如，如果想象一个有许多开发人员的大团队，如果他们每个人都以自己的风格编写代码，采用不同的缩进方式、变量命名等，那将是一团混乱。此外，有行业标准的 JavaScript 格式化方式可以使其更易读，因此更易理解。这就是 Prettier 等工具提供的功能。

Prettier 将在每次保存时自动将您的代码格式化为一致且可读的格式，无论是谁在编写代码。只需记住，在安装 Prettier 后，您需要设置`settings.json`或您的工作区文件来使用它。同样，我在我们的`ejected-app`项目中包含了一个示例`settings.json`文件。

## Chrome 调试器

Chrome 浏览器提供了用于 Web 开发的内置工具。这些工具包括查看页面的所有 HTML、查看控制台消息、在 JavaScript 代码上中断以及查看浏览器所做的网络调用。即使没有任何插件，它也非常广泛。对于许多前端开发人员来说，Chrome 是调试代码的主要工具。

让我们来看看`ejected-app`的调试器，并学习一些基础知识：

1.  如果您的本地`ejected-app`实例没有运行，请重新启动它，并打开您的 Chrome 浏览器到默认的`localhost:3000` URL。一旦到达那里，通过按下*F12*键或转到`root div`标签打开您的 Chrome 调试器，那里是我们应用程序的其余部分。在这个截图中，我们可以看到我们已经调用 Web API 来获取用户`Bret`的待办事项。因此，我们可以使用 Chrome 调试器来找到我们的 HTML 元素，检查它们的属性，并调整 CSS 值，使我们的 UI 精确地符合我们的要求。

1.  接下来，转到**控制台**选项卡，您应该会看到类似于这样的内容：![图 6.20：Chrome 调试器控制台选项卡](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_6.20_B15508.jpg)

图 6.20：Chrome 调试器控制台选项卡

所以，在这里，我们可以检查变量和函数返回数据的值，确保它们是我们想要的并且符合预期。

1.  使用 Chrome 调试器，可以在运行代码时中断。打开`UserTodos.tsx`文件，然后添加如下所示的断点：![图 6.21 - Chrome 调试器源选项卡](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_6.21_B15508.jpg)

图 6.21 - Chrome 调试器源选项卡

正如你所看到的，我们能够在我们的断点上停下来，这是由*行 30*旁边的点所指示的。如果你悬停在某些变量上，你将能够看到它们当前的值，即使它们包含其他组件等对象。这是一个在代码调试中非常有用的功能。这个功能是由一种叫做源映射的东西所启用的。源映射是将源代码映射或绑定到缩小后的运行时代码的文件。它们在开发时被创建并发送到浏览器，允许在运行时断点和查看变量值。

1.  现在让我们移除断点，转到**网络**选项卡。这个选项卡显示了浏览器所做的所有网络连接。这不仅包括对网络资源（如数据）的调用，还可以包括获取图像或静态文件（如 HTML 文件）的调用。如果我们打开这个选项卡，然后进行调用以获取用户 Bret 的待办事项，我们应该会看到这个：

![图 6.22 - Chrome 调试器网络选项卡](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_6.22_B15508.jpg)

图 6.22 – Chrome 调试器网络选项卡

正如你所看到的，我们可以查看从 Web API 调用返回的所有数据。这是一个方便的工具，可以让我们比较来自我们网络资源的数据，并将其与我们的代码似乎正在使用的数据进行比较。当我们进行 GraphQL 调用时，我们也将在以后使用这个工具。

好的，这是对 Chrome 调试器的快速概述，但 Chrome 还提供了能够提供 React 特定帮助的扩展。React 开发者工具提供有关我们组件层次结构和每个组件的属性信息；例如，这是我们应用程序中的一个示例：

![图 6.23 – React 开发者工具](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_6.23_B15508.jpg)

图 6.23 – React 开发者工具

正如你所看到的，这个工具显示了我们的组件层次结构，并显示了当前选定组件的属性。当我们在层次结构中选择特定组件时，它还会在屏幕上显示组成我们组件的元素的高亮显示。这是一个方便的工具，可以从 React 组件结构的角度查看我们的元素，而不是 HTML 结构。Chrome 生态系统的扩展非常广泛，还有针对 Redux 和 Apollo GraphQL 的扩展。我们将在*第八章*中探索这些，*使用 Node.js 和 Express 学习服务器端开发*，以及*第九章*中，*什么是 GraphQL？*。

## 替代 IDE

在本书中，我们使用 VS Code 作为我们的代码编辑器。它运行良好，并已成为最受欢迎的 JavaScript 和 TypeScript 编辑器。但是，你没有理由非要使用它。你应该知道还有其他选择。我只会在这里列出其中一些，这样你就知道一些选项：

+   **Atom**：除了 VS Code 之后可能是最受欢迎的免费编辑器。

+   **Sublime Text**：更快速、更响应的编辑器之一。也有免费版本。

+   **Vim**：Unix 文本编辑器，通常用于编辑代码。

+   **Webstorm**：来自 JetBrains 的商业编辑器。

尝试一些这些编辑器，因为拥有一个好的代码编辑器肯定可以提高你的生产力。

本节回顾了 React 开发中一些常用的工具。虽然这些工具并不是我们应用程序编写代码的主要工具，但它们对于帮助我们更快速、更高质量地编写代码至关重要。它们还将减少我们编写代码时的痛点，因为找到错误通常与解决错误一样具有挑战性。

# 总结

在本章中，我们了解了许多专业前端开发人员用来帮助编写高质量代码的工具。无论是用于编写代码的 VS Code 编辑器，还是用于共享代码的源代码存储库 Git，这里提到的所有工具在前端工程师的工作中都至关重要。

通过了解这些工具，你将成为一个更好的程序员，你的代码质量将大大提高。此外，作为开发人员，你的生活质量也会提高，因为这些工具中的许多工具可以帮助你更快速地跟踪问题，并帮助你比完全靠自己解决问题更容易地解决问题。

在下一章中，我们将通过学习 Redux 和 React Router 来扩展我们对 React 的了解。Redux 将帮助我们管理全局状态，而 React Router 将帮助我们创建客户端 URL。这两个框架在 React 社区中非常受欢迎，并提供许多功能，将帮助我们创建一个更复杂、更有能力的应用程序。
