# React 和 Bootstrap Web 开发学习手册（一）

> 原文：[`zh.annas-archive.org/md5/59c715363f0dff298e7d1cff58a50a77`](https://zh.annas-archive.org/md5/59c715363f0dff298e7d1cff58a50a77)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

我们都知道 JavaScript 应用程序是 Web 开发的未来，有许多不同的框架可用于构建同构 JavaScript Web 应用程序。然而，随着 Web 开发世界的变化，我们都需要作为开发人员现代化，学习新的框架并构建新的工具。重要的是要分析框架的代码方法，并采用相同的方法，而不是迷失在框架市场中。ReactJS 是一个开源的 JavaScript 库，类似于 Bootstrap，用于构建用户界面，被称为*MVC*中的*V*（视图）。当我们谈论*M*和*C*的定义时，我们可以使用其他框架，如 Redux 和 Flux，来处理远程数据。

Bootstrap 是一个用于开发响应式网站和 Web 应用程序的开源前端框架。它包括 HTML、CSS 和 JavaScript 代码来构建用户界面组件。这是一种更快、更简单的开发强大的移动优先响应式设计的方法。Bootstrap 库包括响应式的 12 列网格和预定义的类，用于简单的布局选项（固定宽度和全宽度）。Bootstrap 有数十个预定义的可重用组件和自定义的 jQuery 插件，如按钮、警报、下拉菜单、模态框、工具提示标签、分页、轮播、徽章和图标。

本书从对 ReactJS 和 Bootstrap 的详细研究开始。本书进一步介绍了如何使用 Twitter Bootstrap、React-Bootstrap 等来创建 ReactJS 的小组件。它还让我们了解了 JSX、Redux 和 Node.js 集成，以及高级概念，如 reducers、actions、store、live reload 和 webpack。目标是帮助读者使用 ReactJS 和 Bootstrap 构建响应式和可扩展的 Web 应用程序。

# 本书内容

第一章 *，使用 React 和 Bootstrap 入门*，介绍了 ReactJS、它的生命周期和 Bootstrap，以及一个小型表单组件。

第二章 *，使用 React-Bootstrap 和 React 构建响应式主题*，介绍了 React-Bootstrap 集成，它的好处以及 Bootstrap 响应式网格系统。

第三章 *，ReactJS-JSX*，讲述了 JSX，它的优势，以及在 React 中的工作原理和示例。

第四章 *，使用 ReactJS 进行 DOM 交互*，深入解释了 props 和 state 以及 React 如何与 DOM 交互，附有示例。

第五章 *，使用 React 的 jQuery Bootstrap 组件*，探讨了我们如何将 Bootstrap 组件与 React 集成，附有示例。

第六章 *，Redux 架构*，涵盖了使用 ReactJS 和 Node.js 的 Redux 架构，并附有示例，以及其优势和集成。

第七章 *，使用 React 进行路由*，展示了 React 路由器与 ReactJS 和 Bootstrap 的导航组件的示例，以及其优势和集成。

第八章 *，ReactJS API*，探讨了我们如何在 ReactJS 中集成 Facebook 等第三方 API 以获取个人资料。

第九章 *，React 与 Node.js*，涵盖了为服务器端 React 应用程序设置的 Node.js，并涵盖了使用 Bootstrap 和 ReactJS npm 模块创建小型应用程序。

第十章，*最佳实践*，列出了创建 React 应用程序的最佳实践，并帮助我们理解 Redux 和 Flux 之间的区别，Bootstrap 自定义以及要关注的项目列表。

# 这本书需要什么

要运行本书中的示例，需要以下工具：

| **ReactJS** | **15.1 及以上** | [`facebook.github.io/react/`](https://facebook.github.io/react/) |
| --- | --- | --- |
| ReactJS DOM | 15.1 及以上 | [`facebook.github.io/react/`](https://facebook.github.io/react/) |
| Babel | 5.8.23 | [`cdnjs.com/libraries/babel-core/5.8.23`](https://cdnjs.com/libraries/babel-core/5.8.23) |
| Bootstrap | 3.3.5 | [getbootstrap.com/](http://getbootstrap.com/) |
| jQuery | 1.10.2 | [`jquery.com/download/`](http://jquery.com/download/) |
| React-Bootstrap | 1.0.0 | [`react-bootstrap.github.io/`](https://react-bootstrap.github.io/) |
| JSX 转换器 | 0.13.3 | [`cdnjs.com/libraries/react/0.13.0`](https://cdnjs.com/libraries/react/0.13.0) |
| React Router 库 | 3.0.0 | [`unpkg.com/react-router@3.0.0/umd/ReactRouter.min.js`](https://unpkg.com/react-router@3.0.0/umd/ReactRouter.min.js) |
| Node.js | 0.12.7 | [`nodejs.org/en/blog/release/v0.12.7/`](https://nodejs.org/en/blog/release/v0.12.7/) |
| MongoDB | 3.2 | [`www.mongodb.org/downloads#production`](https://www.mongodb.org/downloads#production) |

# 这本书适合谁

如果您对 HTML、CSS 和 JavaScript 有中级知识，并且想要学习为什么 ReactJS 和 Bootstrap 是开发人员创建应用程序快速、响应式和可扩展用户界面的第一选择，那么这本书适合您。如果您对模型、视图、控制器（MVC）概念很清楚，那么理解 React 的架构就是一个额外的优势。

# 约定

在本书中，您将找到一些文本样式，用于区分不同类型的信息。以下是这些样式及其解释的一些示例。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下：“现在我们需要在`chapter1`文件夹内创建几个文件夹，分别命名为`images`、`css`和`js`（JavaScript），以便使您的应用程序更易管理。”

代码块设置如下：

```jsx
<section> 
    <h2>Add your Ticket</h2> 
</section> 
<script> 
    var root = document.querySelector
    ('section').createShadowRoot(); 
    root.innerHTML = '<style>h2{ color: red; }</style>' + 
    '<h2>Hello World!</h2>'; 
</script>
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项将以粗体显示：

```jsx
<div className="container"> 
    <h1>Welcome to EIS</h1> 
    <hr/> 
        <div className="row"> 
            <div className="col-md-12 col-lg-12"> 
**{this.props.children}** 
            </div> 
        </div> 
</div>
```

任何命令行输入或输出都按照以下方式编写：

```jsx
**npm install <package name> --save**
```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中以这种方式出现：“在**仪表板页面**上，您的左侧导航显示**设置**链接。请点击该链接设置应用程序的**基本**和**高级**设置。”

### 注意

警告或重要提示会以这样的方式出现在一个框中。

### 提示

提示和技巧如下所示。


# 第一章：开始使用 React 和 Bootstrap

使用 JavaScript 和 CSS 构建现代 Web 应用程序有许多不同的方法，包括许多不同的工具选择和许多新的理论需要学习。本书向您介绍了 ReactJS 和 Bootstrap，您在学习现代 Web 应用程序开发时可能会遇到它们。它们都用于构建快速和可扩展的用户界面。React 以（视图）而闻名于 MVC。当我们谈论定义*M*和*C*时，我们需要寻找其他地方，或者我们可以使用其他框架如 Redux 和 Flux 来处理远程数据。

学习代码的最佳方法是编写代码，所以我们将立即开始。为了向您展示使用 Bootstrap 和 ReactJS 轻松上手的方法，我们将涵盖理论，并制作一个超级简单的应用程序，可以让我们构建一个表单，并实时在页面上显示它。

您可以以任何您感觉舒适的方式编写代码。尝试创建小组件/代码示例，这将让您更清楚/了解任何技术。现在，让我们看看这本书将如何在涉及 Bootstrap 和 ReactJS 时让您的生活变得更轻松。我们将涵盖一些理论部分，并构建两个简单的实时示例：

+   Hello World！使用 ReactJS

+   使用 React 和 Bootstrap 的简单静态表单应用程序

Facebook 通过引入 React 真正改变了我们对前端 UI 开发的看法。这种基于组件的方法的主要优势之一是易于理解，因为视图只是属性和状态的函数。

我们将涵盖以下主题：

+   设置环境

+   ReactJS 设置

+   Bootstrap 设置

+   为什么要使用 Bootstrap

+   使用 React 和 Bootstrap 的静态表单示例

# ReactJS

React（有时称为 React.js 或 ReactJS）是一个开源的 JavaScript 库，提供了一个将数据呈现为 HTML 的视图。组件通常用于呈现包含自定义 HTML 标记的其他组件的 React 视图。React 为您提供了一个微不足道的虚拟 DOM，强大的视图而无需模板，单向数据流和显式变异。当数据发生变化时，它在更新 HTML 文档方面非常有条理；并在现代单页应用程序上提供了组件的清晰分离。

观察以下示例，我们将清楚地了解普通 HTML 封装和 ReactJS 自定义 HTML 标记。

观察以下 JavaScript 代码片段：

```jsx
<section> 
    <h2>Add your Ticket</h2> 
</section> 
<script> 
    var root = document.querySelector
    ('section').createShadowRoot(); 
    root.innerHTML = '<style>h2{ color: red; }</style>' + 
    '<h2>Hello World!</h2>'; 
</script> 

```

观察以下 ReactJS 代码片段：

```jsx
var sectionStyle = { 
    color: 'red' 
}; 

var AddTicket = React.createClass({ 
    render: function() { 
        return (<section><h2 style={sectionStyle}> 
        Hello World!</h2></section>)} 
}) 
ReactDOM.render(<AddTicket/>, mountNode); 

```

随着应用程序的出现和进一步发展，确保组件以正确的方式使用是有利的。React 应用程序由可重用组件组成，这使得代码重用、测试和关注点分离变得容易。

React 不仅是 MVC 中的*V*，还具有有状态组件（有状态组件记住`this.state`中的所有内容）。它处理输入到状态变化的映射，并渲染组件。在这个意义上，它做了 MVC 所做的一切。

让我们来看一下 React 的组件生命周期及其不同的级别。我们将在接下来的章节中更多地讨论这个问题。观察以下图表：

![ReactJS](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_01_001.jpg)

### 注意

React 不是一个 MVC 框架；它是一个用于构建可组合用户界面和可重用组件的库。React 在 Facebook 的生产阶段使用，并且[instagram.com](https://www.instagram.com/?hl=en)完全基于 React 构建。

# 设置环境

当我们开始使用 ReactJS 制作应用程序时，我们需要进行一些设置，这只涉及一个 HTML 页面和包含一些文件。首先，我们创建一个名为`chapter1`的目录（文件夹）。在任何代码编辑器中打开它。直接在其中创建一个名为`index.html`的新文件，并添加以下 HTML5 样板代码：

```jsx
<!doctype html> 
<html class="no-js" lang=""> 
    <head> 
    <meta charset="utf-8"> 
<title>ReactJS Chapter 1</title> 
    </head> 
    <body> 
        <!--[if lt IE 8]> 
            <p class="browserupgrade">You are using an 
            <strong>outdated</strong> browser.  
            Please <a href="http://browsehappy.com/">
            upgrade your browser</a> to improve your 
            experience.</p> 
        <![endif]--> 
        <!-- Add your site or application content here --> 
        <p>Hello world! This is HTML5 Boilerplate.</p>      
    </body> 
</html> 

```

这是一个标准的 HTML 页面，一旦我们包含了 React 和 Bootstrap 库，就可以更新它。

现在我们需要在`chapter1`文件夹内创建`images`、`css`和`js`（JavaScript）等几个文件夹，以便使应用程序更易管理。完成文件夹结构后，它将如下所示：

![设置环境](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_01_002.jpg)

# 安装 ReactJS 和 Bootstrap

创建文件夹结构完成后，我们需要安装 ReactJS 和 Bootstrap 两个框架。只需在页面中包含 JavaScript 和 CSS 文件即可。我们可以通过**内容传送网络**（**CDN**）来实现这一点，比如谷歌或微软，但我们将在应用程序中手动获取文件，这样就不必依赖互联网，可以离线工作。

## 安装 React

首先，我们需要转到此网址[`facebook.github.io/react/`](https://facebook.github.io/react/)，然后点击**下载 React v15.1.0**按钮：

![安装 React](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_01_003.jpg)

这将为您提供最新版本的 ReactJS 的 ZIP 文件，其中包括 ReactJS 库文件和一些 ReactJS 的示例代码。

现在，我们在我们的应用程序中只需要两个文件：从提取的文件夹的`build`目录中的`react.min.js`和`react-dom.min.js`。

以下是我们需要遵循的几个步骤：

1.  将`react.min.js`和`react-dom.min.js`复制到您的项目目录，`chapter1/js`文件夹，并在编辑器中打开您的`index.html`文件。

1.  现在您只需要在页面的`head`标签部分添加以下脚本：

```jsx
        <script type="text/js" src="js/react.min.js"></script>
        <script type="text/js" src="js/react-dom.min.js"></script>
```

1.  现在我们需要在我们的项目中包含编译器来构建代码，因为现在我们正在使用诸如 npm 之类的工具。我们将从以下 CDN 路径下载文件，[`cdnjs.cloudflare.com/ajax/libs/babel-core/5.8.23/browser.min.js`](https://cdnjs.cloudflare.com/ajax/libs/babel-core/5.8.23/browser.min.js)，或者您可以直接给出 CDN 路径。

1.  `head`标签部分将如下所示：

```jsx
        <script type="text/js" src="js/react.min.js"></script>
        <script type="text/js" src="js/react-dom.min.js"></script> 
        <script type="text/js" src="js/browser.min.js"></script>
```

这是您的`js`文件夹的最终结构将是这样的：

![安装 React](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_01_004.jpg)

# Bootstrap

Bootstrap 是由 Twitter 维护的开源前端框架，用于开发响应式网站和 Web 应用程序。它包括 HTML、CSS 和 JavaScript 代码来构建用户界面组件。这是开发强大的移动优先用户界面的快速简便的方式。

Bootstrap 网格系统允许您创建响应式的 12 列网格、布局和组件。它包括预定义的类，用于简单的布局选项（固定宽度和全宽度）。Bootstrap 有数十个预定义的可重用组件和自定义 jQuery 插件，如按钮、警报、下拉菜单、模态框、工具提示标签、分页、轮播、徽章、图标等等。

## 安装 Bootstrap

现在，我们需要安装 Bootstrap。访问[`getbootstrap.com/getting-started/#download`](http://getbootstrap.com/getting-started/#download)，然后点击**下载 Bootstrap**按钮：

![安装 Bootstrap](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_01_005.jpg)

这包括我们应用程序的`css`和`js`的编译和压缩版本；我们只需要 CSS`bootstrap.min.css`和`fonts`文件夹。这个样式表将为您提供所有组件的外观和感觉，并为我们的应用程序提供响应式布局结构。Bootstrap 的早期版本包括图标作为图像，但在 3 版本中，图标已被替换为字体。我们还可以根据应用程序中使用的组件自定义 Bootstrap CSS 样式表：

1.  解压缩 ZIP 文件夹，并将 Bootstrap CSS 从`css`文件夹复制到项目文件夹的 CSS 中。

1.  现在将 Bootstrap 的`fonts`文件夹复制到您的项目根目录中。

1.  在编辑器中打开你的`index.html`，并在`head`部分添加这个`link`标签：

```jsx
        <link rel="stylesheet" href="css/bootstrap.min.css">.
```

就是这样。现在我们可以再次在浏览器中打开`index.html`，看看我们正在处理的内容。以下是我们迄今为止编写的代码：

```jsx
<!doctype html> 
<html class="no-js" lang=""> 
    <head> 
        <meta charset="utf-8"> 
<title>ReactJS Chapter 1</title> 

<link rel="stylesheet" href="css/bootstrap.min.css"> 

<script type="text/javascript" src="js/react.min.js">
</script> 
<script type="text/javascript" src="js/react-dom.min.js">
</script> 
<script src="https://cdnjs.cloudflare.com/ajax/libs/babel-
core/5.8.23/browser.min.js"></script> 
    </head> 
    <body> 
        <!--[if lt IE 8]> 
            <p class="browserupgrade">You are using an
            <strong>outdated</strong> browser.  
            Please <a href="http://browsehappy.com/">upgrade
            your browser</a> to improve your experience.</p> 
        <![endif]--> 
        <!-- Add your site or application content here --> 

    </body> 
</html> 

```

# 使用 React

现在我们已经从 ReactJS 和 Bootstrap 样式表中初始化了我们的应用程序。现在让我们开始编写我们的第一个 Hello World 应用程序，使用`ReactDOM.render()`。

`ReactDOM.render`方法的第一个参数是我们要渲染的组件，第二个参数是它应该挂载（附加）到的 DOM 节点。观察以下代码：

```jsx
ReactDOM.render( ReactElement element, DOMElement container,
[function callback] )
```

为了将其转换为纯 JavaScript，我们在我们的 React 代码中使用包裹，`<script type"text/babel">`，这个标签实际上在浏览器中执行转换。

让我们从在`body`标签中放一个`div`标签开始：

```jsx
<div id="hello"></div>

```

现在，添加带有 React 代码的`script`标签：

```jsx
<script type="text/babel"> 
    ReactDOM.render( 
        <h1>Hello, world!</h1>, 
        document.getElementById('hello') 
    ); 
</script>

```

JavaScript 的 XML 语法称为 JSX。我们将在后续章节中探讨这一点。

让我们在浏览器中打开 HTML 页面。如果你在浏览器中看到**Hello, world!**，那么我们就走在了正确的轨道上。观察以下截图：

![使用 React](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_01_006.jpg)

在上面的截图中，你可以看到它在你的浏览器中显示了**Hello, world!**。太棒了。我们已经成功完成了我们的设置，并构建了我们的第一个 Hello World 应用程序。以下是迄今为止我们编写的完整代码：

```jsx
<!doctype html> 
<html class="no-js" lang=""> 
    <head> 
        <meta charset="utf-8"> 
    <title>ReactJS Chapter 1</title>           
<link rel="stylesheet" href="css/bootstrap.min.css"> 

<script type="text/javascript" src="js/react.min.js"></script> 
<script type="text/javascript" src="js/react-dom.min.js"></script> 
    <script src="https://cdnjs.cloudflare.com/ajax/libs/babel-
    core/5.8.23/browser.min.js"></script> 
    </head> 
    <body> 
        <!--[if lt IE 8]> 
            <p class="browserupgrade">You are using an
            <strong>outdated</strong> browser.  
            Please <a href="http://browsehappy.com/">upgrade your
            browser</a> to improve your experience.</p> 
    <![endif]--> 
    <!-- Add your site or application content here --> 
    <div id="hello"></div> 
        <script type="text/babel"> 
            ReactDOM.render( 
                <h1>Hello, world!</h1>, 
                document.getElementById('hello') 
            ); 
        </script> 

    </body> 
</html>

```

# 使用 React 和 Bootstrap 创建静态表单

我们已经完成了我们的第一个使用 React 和 Bootstrap 的 Hello World 应用程序，一切看起来都很好，符合预期。现在是时候做更多的事情，创建一个静态登录表单，并将 Bootstrap 的外观和感觉应用到它上面。Bootstrap 是一个很好的方式，可以使您的应用程序成为不同移动设备的响应式网格系统，并在 HTML 元素上应用基本样式，包括一些类和 divs。

### 注意

响应式网格系统是一种简单、灵活、快速的方式，可以使您的 Web 应用程序具有响应性和移动优先性，适当地按设备和视口大小扩展到 12 列。

首先，让我们开始制作一个 HTML 结构，以遵循 Bootstrap 网格系统。

创建一个`div`，并添加一个`className .container`（固定宽度）和`.container-fluid`（全宽度）。使用`className`属性而不是使用`class`：

```jsx
<div className="container-fluid"></div> 

```

正如我们所知，`class`和`for`被不鼓励作为 XML 属性名称。此外，这些在许多 JavaScript 库中都是保留字，因此，为了有一个清晰的区别和相同的理解，我们可以使用`className`和`htmlFor`来代替使用`class`和`for`。创建一个`div`并添加`className="row"`。`row`必须放在`.container-fluid`中：

```jsx
<div className="container-fluid"> 
    <div className="row"></div> 
</div>

```

现在创建必须是行的直接子元素的列：

```jsx
<div className="container-fluid"> 
    <div className="row"> 
<div className="col-lg-6"></div> 
        </div> 
</div>
```

`.row`和`.col-xs-4`是预定义的类，可用于快速创建网格布局。

为页面的标题添加`h1`标签：

```jsx
<div className="container-fluid"> 
    <div className="row"> 
<div className="col-sm-6"> 
<h1>Login Form</h1> 
</div> 
    </div> 
</div>
```

网格列是由给定的`col-sm-*`中的指定数量的 12 个可用列创建的。例如，如果我们使用四列布局，我们需要指定`col-sm-3`以获得相等的列：

| **类名** | **设备** |
| --- | --- |
| `col-sm-*` | 小设备 |
| `col-md-*` | 中等设备 |
| `col-lg-*` | 大设备 |

我们使用`col-sm-*`前缀来调整我们的小设备的列。在列内，我们需要将我们的表单元素`label`和`input`标签包装在具有`form-group`类的`div`标签中：

```jsx
<div className="form-group"> 
    <label for="emailInput">Email address</label> 
    <input type="email" className="form-control" id="emailInput" 
    placeholder="Email"/> 
</div>

```

忘记 Bootstrap 的样式；我们需要在输入元素中添加`form-control`类。如果我们需要在`label`标签中添加额外的填充，那么我们可以在`label`上添加`control-label`类。

让我们快速添加其余的元素。我将添加一个`password`和`submit`按钮。

在 Bootstrap 的早期版本中，表单元素通常包装在具有`form-action`类的元素中。然而，在 Bootstrap 3 中，我们只需要使用相同的`form-group`而不是`form-action`。我们将在第二章中更详细地讨论 Bootstrap 类和响应性，*使用 React-Bootstrap 和 React 构建响应式主题*。

这是我们完整的 HTML 代码：

```jsx
<div className="container-fluid">
    <div className="row">
        <div className="col-lg-6">
            <form>
                <h1>Login Form</h1>
                <hr/>
                <div className="form-group">
                    <label for="emailInput">Email address</label>
                    <input type="email" className="form-control"
                    id="emailInput" placeholder="Email"/>
                </div>
                <div className="form-group">
                    <label for="passwordInput">Password</label>
                    <input type="password" className=
                    "form-control" id="passwordInput" 
                    placeholder="Password"/>
                </div>
                <button type="submit" className="btn btn-default
                col-xs-offset-9 col-xs-3">Submit</button>
            </form>
        </div>
    </div>
</div>
```

现在在`var loginFormHTML`脚本标签内创建一个对象，并将此 HTML 分配给它：

```jsx
Var loginFormHTML = <div className="container-fluid">
<div className="row">
    <div className="col-lg-6">
        <form>
            <h1>Login Form</h1>
            <hr/>
            <div className="form-group">
                <label for="emailInput">Email              
                address</label>
                <input type="email" className="form-control"
                id="emailInput" placeholder="Email"/>
            </div>
            <div className="form-group">
                <label for="passwordInput">Password</label>
                <input type="password" className="form-
                control" id="passwordInput" placeholder="Password"/>
            </div>
            <button type="submit" className="btn btn-default col-xs-
            offset-9 col-xs-3">Submit</button>
        </form>
    </div>
</div>
```

我们将在`React.DOM()`方法中传递这个对象，而不是直接传递 HTML：

```jsx
ReactDOM.render(LoginformHTML,document.getElementById('hello'));
```

我们的表单已经准备好了。现在让我们看看它在浏览器中的样子：

![使用 React 和 Bootstrap 的静态表单](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_01_007.jpg)

编译器无法解析我们的 HTML，因为我们没有正确地封闭其中一个`div`标签。您可以在我们的 HTML 中看到，我们没有在最后关闭包装器`container-fluid`。现在在最后关闭包装器标签，然后在浏览器中重新打开文件。 

### 提示

每当您手工编写 HTML 代码时，请仔细检查您的起始标记和结束标记。它应该被正确地编写/关闭，否则它将破坏您的 UI/前端外观和感觉。

在关闭`div`标签后的 HTML 如下：

```jsx
<!doctype html>
<html class="no-js" lang="">
    <head>
        <meta charset="utf-8">
        <title>ReactJS Chapter 1</title>
        <link rel="stylesheet" href="css/bootstrap.min.css">
        <script type="text/javascript" src="js/react.min.js"></script>
        <script type="text/javascript" src="js/react-dom.min.js"> 
        </script>
        <script src="js/browser.min.js"></script>
    </head>
    <body>
        <!-- Add your site or application content here -->
        <div id="loginForm"></div>
        <script type="text/babel">
            var LoginformHTML = 
            <div className="container-fluid">
             <div className="row">
            <div className="col-lg-6">
            <form>
              <h1>Login Form</h1>
            <hr/>
            <div className="form-group">
              <label for="emailInput">Email address</label>
              <input type="email" className="form-control" id=
              "emailInput" placeholder="Email"/>
            </div>
            <div className="form-group">
            <label for="passwordInput">Password</label>
            <input type="password" className="form-control"
            id="passwordInput" placeholder="Password"/>
            </div>
            <button type="submit" className="btn btn-default 
            col-xs-offset-9 col-xs-3">Submit</button>
            </form>
             </div>
            </div>
            </div>

ReactDOM.render(LoginformHTML,document.getElementById
('loginForm');

        </script>    
    </body>
</html>
```

现在，您可以在浏览器上检查您的页面，您将能够看到表单的外观和感觉如下屏幕截图所示：

![使用 React 和 Bootstrap 的静态表单](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_01_008.jpg)

现在它运行良好，看起来不错。Bootstrap 还提供了两个额外的类来使您的元素变小和变大：`input-lg`和`input-sm`。您还可以通过调整浏览器大小来检查响应式行为。观察以下屏幕截图：

![使用 React 和 Bootstrap 的静态表单](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_01_009.jpg)

看起来不错。我们的小型静态登录表单应用程序已经具备了响应式行为。

由于这是一个介绍性的章节，您可能会想知道 React 如何有益或有利？

这就是你的答案：

+   渲染您的组件非常容易

+   通过 JSX 的帮助，阅读组件的代码将会非常容易

+   JSX 还将帮助您检查布局以及检查组件之间的插件

+   您可以轻松测试您的代码，它还允许其他工具集成以进行增强

+   React 是一个视图层，您还可以将其与其他 JavaScript 框架一起使用。

上述观点是非常高层次的，我们将在接下来的章节中详细了解更多好处。

# 总结

我们简单的静态登录表单应用程序和 Hello World 示例看起来很棒，而且正好按照预期工作，所以让我们回顾一下我们在本章中学到的内容。

首先，我们看到了使用 JavaScript 文件和样式表轻松安装 ReactJS 和 Bootstrap 的方法。我们还看了 React 应用程序是如何初始化的，并开始构建我们的第一个表单应用程序。

我们创建的 Hello World 应用程序和表单应用程序演示了 React 和 Bootstrap 的一些基本功能，例如以下内容：

+   ReactDOM

+   渲染

+   Browserify

+   Bootstrap

使用 Bootstrap，我们努力为不同的移动设备实现响应式网格系统，并应用了一些类和 div 的基本 HTML 元素样式。

我们还看到了框架的新的移动优先响应式设计，而不会在我们的标记中添加不必要的类或元素。

在第二章中，*让我们使用 React-Bootstrap 和 React 构建一个响应式主题*，我们将深入了解 Bootstrap 的特性以及如何使用网格。我们将探索一些更多的 Bootstrap 基础知识，并介绍我们将在本书中构建的项目。


# 第二章：使用 React-Bootstrap 和 React 构建响应式主题

现在，您已经使用 ReactJS 和 Bootstrap 完成了您的第一个 Web 应用程序，我们将使用这两个框架构建您的应用程序的第一个响应式主题。我们还将涉及到两个框架的全部潜力。所以，让我们开始吧！

# 设置

首先，我们需要为我们在第一章中制作的 Hello World 应用创建一个类似的文件夹结构，*使用 React 和 Bootstrap 入门*。

以下屏幕截图描述了文件夹结构：

![设置](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_02_001.jpg)

现在，您需要将 ReactJS 和 Bootstrap 文件从“第一章”复制到“第二章”的重要目录中，并在根目录中创建一个`index.html`文件。以下代码片段只是一个包含 Bootstrap 和 React 的基本 HTML 页面。

这是我们 HTML 页面的标记：

```jsx
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>ReactJS theme with bootstrap</title>
        <link rel="stylesheet" href="css/bootstrap.min.css">
        <script type="text/javascript" src="js/react.min.js">
        </script>
        <script type="text/javascript" src="js/react-dom.min.js">
        </script>
        <script src="js/browser.min.js"></script>
    </head>
    <body>
    </body>
</html>

```

# 脚手架

所以现在我们有了基本文件和文件夹结构。下一步是使用 Bootstrap CSS 开始搭建我们的应用程序。

我相信你有一个问题：什么是脚手架？简单地说，它提供了一个支撑结构，使您的基础更加牢固。

除此之外，我们还将使用 React-Bootstrap JS，其中包含了为 React 重新构建的 Bootstrap 组件集。我们可以在我们的**员工信息系统**（**EIS**）中使用这些组件。Bootstrap 还包括一个非常强大的响应式网格系统，帮助我们为应用程序创建响应式主题布局/模板/结构。

# 导航

导航是任何静态或动态页面的非常重要的元素。所以现在我们将构建一个导航栏（用于导航）来在我们的页面之间切换。它可以放在我们页面的顶部。

这是 Bootstrap 导航的基本 HTML 结构：

```jsx
<nav className="navbar navbar-default navbar-static-top" role="navigation">
    <div className="container">
        <div className="navbar-header">
            <button type="button" className="navbar-toggle"
            data-toggle="collapse" data-target=".navbar-collapse">
            <span className="sr-only">Toggle navigation</span>
            <span className="icon-bar"></span>
            <span className="icon-bar"></span>
            <span className="icon-bar"></span>
            </button>
            <a className="navbar-brand" href="#">EIS</a>
        </div>
        <div className="navbar-collapse collapse">
            <ul className="nav navbar-nav">
                <li className="active"><a href="#">Home</a></li>
                <li><a href="#">Edit Profile</a></li>
                <li className="dropdown">
                    <a href="#" className="dropdown-toggle"
                    data-toggle="dropdown">Help Desk 
                    <b className="caret"></b></a>
                    <ul className="dropdown-menu">
                        <li><a href="#">View Tickets</a></li>
                        <li><a href="#">New Ticket</a></li>
                    </ul>
                </li>
            </ul>
        </div>
    </div>
</nav>

```

用于容纳“导航栏”内的所有内容的`<nav>`标签，而不是分成两个部分：`navbar-header`和`navbar-collapse`，如果您查看导航结构。导航栏是响应式组件，因此`navbar-header`元素专门用于移动导航，并控制导航的展开和折叠，使用`toggle`按钮。按钮上的`data-target`属性直接对应于`navbar-collapse`元素的`id`属性，因此 Bootstrap 知道应该在移动设备中包装哪个元素以控制切换。

现在我们还需要在页面中包含 jQuery，因为 Bootstrap 的 JS 依赖于它。您可以从[`jquery.com/`](http://jquery.com/)获取最新的 jQuery 版本。现在您需要从 Bootstrap 提取的文件夹中复制`bootstrap.min.js`，并将其添加到您的应用程序的`js`目录中，然后在`bootstrap.min.js`之前在页面中包含它。

请确保您的 JavaScript 文件按以下顺序包含：

```jsx
<script type="text/javascript" src="js/react.min.js"></script> 
<script type="text/javascript" src="js/react-dom.min.js"></script> 
<script src="js/browser.min.js"></script> 
<script src="js/jquery-1.10.2.min.js"></script> 
<script src="js/bootstrap.min.js"></script>
```

在集成 React 后，让我们快速查看`navbar`组件代码：

```jsx
<div id="nav"></div>
<script type="text/babel">
    var navbarHTML = 
      <nav className="navbar navbar-default navbar-static-top"
      role="navigation">
      <div className="container">
        <div className="navbar-header">
        <button type="button" className="navbar-toggle"
        data-toggle="collapse" data-target=".navbar-collapse">
          <span className="sr-only">Toggle navigation</span>
          <span className="icon-bar"></span>
          <span className="icon-bar"></span>
          <span className="icon-bar"></span>
        </button>
        <a className="navbar-brand" href="#">EIS</a>
        </div>
        <div className="navbar-collapse collapse">
        <ul className="nav navbar-nav">
          <li className="active"><a href="#">Home</a></li>
          <li><a href="#">Edit Profile</a></li>
          <li className="dropdown">
          <a href="#" className="dropdown-toggle"
          data-toggle="dropdown">Help Desk <b className="caret">
          </b></a>
          <ul className="dropdown-menu">
            <li><a href="#">View Tickets</a></li>
            <li><a href="#">New Ticket</a></li>
          </ul>
          </li>
        </ul>
        </div>
      </div>
      </nav>
      ReactDOM.render(navbarHTML,document.getElementById('nav'));
</script> 

```

在浏览器中打开`index.html`文件以查看`navbar`组件。以下截图显示了我们的导航的外观：

![导航](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_02_002.jpg)

我们直接在`<body>`标签中包含了导航，以覆盖浏览器的整个宽度。现在我们将使用 React-Bootstrap JS 框架来做同样的事情，以了解 Bootstrap JS 和 React-Bootstrap JS 之间的区别。

# React-Bootstrap

React-Bootstrap JavaScript 框架类似于为 React 重建的 Bootstrap。它是 Bootstrap 前端可重用组件在 React 中的完全重新实现。React-Bootstrap 不依赖于任何其他框架，如 Bootstrap JS 或 jQuery。这意味着，如果您使用 React-Bootstrap，则不需要将 jQuery 作为依赖项包含在项目中。使用 React-Bootstrap，我们可以确保不会有外部 JavaScript 调用来渲染组件，这可能与`ReactDOM.render`不兼容。但是，您仍然可以实现与 Twitter Bootstrap 相同的功能、外观和感觉，但代码更清晰。

## 安装 React-Bootstrap

要获取这个 React-Bootstrap，我们可以直接使用 CDN，或者从以下 URL 获取：[`cdnjs.cloudflare.com/ajax/libs/react-bootstrap/0.29.5/react-bootstrap.min.js`](https://cdnjs.cloudflare.com/ajax/libs/react-bootstrap/0.29.5/react-bootstrap.min.js)。打开此 URL 并将其保存在本地目录以获得更快的性能。下载文件时，请确保同时下载源映射（`react-bootstrap.min.js.map`）文件，以便更轻松地进行调试。下载完成后，将该库添加到应用程序的`js`目录中，并在页面的`head`部分包含它，如下面的代码片段所示。您的`head`部分将如下所示：

```jsx
<script type="text/javascript" src="js/react.min.js"></script> 
<script type="text/javascript" src="js/react-dom.min.js"></script> 
<script src="js/browser.min.js"></script> 
<script src="js/react-bootstrap.min.js"></script> 

```

## 使用 React-Bootstrap

现在，你可能会想，既然我们已经有了 Bootstrap 文件，还添加了 React-Bootstrap JS 文件，它们不会冲突吗？不，它们不会。React-Bootstrap 与现有的 Bootstrap 样式兼容，所以我们不需要担心任何冲突。

现在我们要在 React-Bootstrap 中创建相同的`Navbar`组件。

这里是 React-Bootstrap 中`Navbar`组件的结构：

```jsx
var Nav= ReactBootstrap.Nav;
var Navbar= ReactBootstrap.Navbar;
var NavItem= ReactBootstrap.NavItem;
var NavDropdown = ReactBootstrap.NavDropdown;
var MenuItem= ReactBootstrap.MenuItem;
var navbarReact =(
<Navbar>
    <Navbar.Header>
        <Navbar.Brand>
            <a href="#">EIS</a>
        </Navbar.Brand>
        <Navbar.Toggle />
    </Navbar.Header>
    <Navbar.Collapse>
        <Nav>
            <NavItem eventKey={1} href="#">Home</NavItem>
            <NavItem eventKey={2} href="#">Edit Profile</NavItem>
            <NavDropdown eventKey={3}  id="basic-
            nav-dropdown">
                <MenuItem eventKey={3.1}>View Tickets</MenuItem>
                <MenuItem eventKey={3.2}>New Ticket</MenuItem>
            </NavDropdown>
        </Nav>
    </Navbar.Collapse>
</Navbar>
); 

```

以下是前述代码的亮点（顺序已从好处部分下移至上方）。

`<Navbar>`标签是组件的容器，分为两个部分：`<Navbar.Header>`和`<Nav>`。

为了响应式行为，我们添加了`<Navbar.Toggle/>`标签，用于控制展开和折叠，并将`<Nav>`包装到`<Navbar.Collapse>`中以显示和隐藏导航项。

为了捕获事件，我们使用了`eventKey={1}`；当我们选择任何菜单项时，会触发一个回调，它接受两个参数，(`eventKey: any`, `event: object`) => `any`

## React-Bootstrap 的好处

让我们来看看使用 React-Bootstrap 的好处。

正如你在前述代码中所看到的，它看起来比 Twitter Bootstrap 组件更清晰，因为我们可以从 React-Bootstrap 中导入单个组件，而不是包含整个库。

例如，如果我想用 Twitter Bootstrap 构建一个`navbar`，那么代码结构是：

```jsx
<nav class="navbar navbar-default">
    <div class="container-fluid">
        <div class="navbar-header">
            <button type="button" class="navbar-toggle collapsed"
            data-toggle="collapse" data-target="#bs-example-navbar-
            collapse-1" aria-expanded="false">
            <span class="sr-only">Toggle navigation</span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
            </button>
            <a class="navbar-brand" href="#">EIS</a>
        </div>
        <div class="collapse navbar-collapse" id="bs-example-
        navbar-collapse-1">
            <ul class="nav navbar-nav">
                <li class="active"><a href="#">Home <span class=
                "sr-only">(current)</span></a></li>
                <li><a href="#">Edit Profile</a></li>
            </ul>
            <form class="navbar-form navbar-left" role="search">
                <div class="form-group">
                    <input type="text" class="form-control"
                    placeholder="Search">
                </div>
                <button type="submit" class="btn
                btn-default">Submit</button>
            </form>
        </div>
        <!-- /.navbar-collapse -->
    </div>
    <!-- /.container-fluid -->
</nav>
```

现在你可以轻松比较代码，我相信你也会同意使用 React-Bootstrap，因为它非常具体化，而在 Twitter Bootstrap 中，我们需要维护多个元素的正确顺序才能获得类似的结果。

通过这样做，React-Bootstrap 只提取我们想要包含的特定组件，并帮助显著减少应用程序包大小。React-Bootstrap 提供以下一些好处：

+   React-Bootstrap 通过压缩 Bootstrap 代码节省了一些输入并减少了错误

+   它通过压缩 Bootstrap 代码减少了冲突

+   我们不需要考虑 Bootstrap 与 React 采用的不同方法

+   它很容易使用

+   它封装在元素中

+   它使用 JSX 语法

+   它避免了 React 渲染虚拟 DOM

+   很容易检测 DOM 的变化并更新 DOM 而不会发生冲突

+   它不依赖于其他库，比如 jQuery

这里是我们`Navbar`组件的完整代码视图：

```jsx
<div id="nav"></div>
<script type="text/babel">
var Nav= ReactBootstrap.Nav;
var Navbar= ReactBootstrap.Navbar;
var NavItem= ReactBootstrap.NavItem;
var NavDropdown = ReactBootstrap.NavDropdown;
var MenuItem= ReactBootstrap.MenuItem;
var navbarReact =(
    <Navbar>
        <Navbar.Header>
        <Navbar.Brand>
            <a href="#">EIS</a>
        </Navbar.Brand>
        <Navbar.Toggle />
        </Navbar.Header>
        <Navbar.Collapse>
            <Nav>
            <NavItem eventKey={1} href="#">Home</NavItem>
            <NavItem eventKey={2} href="#">Edit Profile</NavItem>
            <NavDropdown eventKey={3}  id="basic-
            nav-dropdown">
                <MenuItem eventKey={3.1}>View Tickets</MenuItem>
                <MenuItem eventKey={3.2}>New Ticket</MenuItem>
            </NavDropdown>
            </Nav>
        </Navbar.Collapse>
    </Navbar>
    );
    ReactDOM.render(navbarReact,document.getElementById('nav')); 

```

哇哦！让我们在浏览器中看看我们的第一个 React-Bootstrap 组件。以下截图显示了组件的外观：

![React-Bootstrap 的好处](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_02_003.jpg)

现在来检查`Navbar`，如果你调整浏览器窗口大小，你会注意到 Bootstrap 在 768 像素以下的平板电脑纵向模式下显示移动头部和切换按钮。然而，如果你点击按钮切换导航，你会看到移动端的导航。

以下截图显示了移动导航的外观：

![React-Bootstrap 的好处](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_02_004.jpg)

现在我们对 React-Bootstrap 和 Bootstrap 有了主要的了解。React-Bootstrap 正在进行积极的开发工作，以保持更新。

# Bootstrap 网格系统

Bootstrap 基于一个 12 列网格系统，包括强大的响应式结构和移动优先的流体网格系统，允许我们用很少的元素来搭建我们的 Web 应用。在 Bootstrap 中，我们有一系列预定义的类来组成行和列，所以在开始之前，我们需要在我们的行和列周围包含带有`container`类的`<div>`标签。否则，框架不会如预期般响应，因为 Bootstrap 编写了依赖于它的 CSS，我们需要在我们的`navbar`下面添加它：

```jsx
<div class="container"><div> 

```

这将使您的 Web 应用程序成为页面的中心，并控制行和列以响应预期地工作。

有四个类前缀，帮助定义列的行为。所有类都与不同的设备屏幕大小相关，并以熟悉的方式响应。来自[`getbootstrap.com/`](http://getbootstrap.com/)的以下表格定义了所有四个类之间的差异：

|   | **额外小设备****手机（<768px）** | **小设备****平板电脑（≥768px）** | **中等设备****台式电脑（≥992px）** | **大型设备****台式电脑（≥1200px）** |
| --- | --- | --- | --- | --- |
| **网格行为** | **始终水平** | **在断点以上折叠，水平** |
| **容器宽度** | 无（自动） | 750px | 970px | 1170px |
| **类前缀** | .col-xs- | .col-sm- | .col-md- | .col-lg- |
| **列数** | 12 |   |   |   |
| **列宽** | 自动 | ~62px | ~81px | ~97px |
| **间距宽度** | 30px（每列两侧各 15px） |   |   |   |
| **可嵌套** | 是 |   |   |   |
| **偏移** | 是 |   |   |   |
| **列排序** | 是 |   |   |   |

在我们的应用程序中，我们需要为主要内容区域和侧边栏创建一个两列布局。正如我们所知，Bootstrap 有一个 12 列网格布局，所以以一种覆盖整个区域的方式划分您的内容。

### 提示

请理解，Bootstrap 使用`col-*-1`到`col-*-12`类来划分 12 列网格。

我们将把 12 列分为两部分：一部分是主要内容的九列，另一部分是侧边栏的三列。听起来很完美。所以，这是我们如何实现的。

首先，我们需要在我们的`container`内包含`<div>`标签，并添加`class`为`"row"`。根据设计需求，我们可以有多个带有`row`类的`div`标签，每个标签最多可以容纳 12 列。

```jsx
<div class="container"> 
    <div class="row"> 
    </div> 
<div> 

```

众所周知，如果我们希望我们的列在移动设备上堆叠，我们应该使用`col-sm-`前缀。创建列就像简单地取所需的前缀并将要添加的列数附加到它一样简单。

让我们快速看一下我们如何创建一个两列布局：

```jsx
<div class="container">
    <div class="row">
        <div class="col-sm-3">
            Column Size 3 for smaller devices
        </div>
        <div class="col-sm-9">
            Column Size 9 for smaller devices
        </div>
    </div>
</div>

```

如果我们希望我们的列不仅在较小的设备上堆叠，还可以通过向列添加`col-md-*`和`col-xs-*`来使用额外的小和中等网格类：

```jsx
<div class="container"> 
    <div class="row"> 
<div class="col-xs-12 col-md-4"> 

```

在手机视图中，这一列将是全宽，在平板视图中，它将是四个中等网格宽度。

```jsx
</div> 
<div class="col-xs-12 col-md-8"> 
In mobile view, this column will be full width and in tablet view, it will be eight medium grid width.</div> 
</div> 
</div> 

```

因此，当它在比移动设备更大的屏幕上显示时，Bootstrap 将自动在每列之间添加 30 像素的间距（两个元素之间的空间为 15 像素）。如果我们想在列之间添加额外的空间，Bootstrap 将提供一种方法，只需将额外的类添加到列中即可：

```jsx
<div class="container"> 
<div class="row"> 
<div class="col-xs-12 col-md-7 col-md-offset-1"> 

```

手机上的列是一个全宽和另一个半宽，离左边更远：

```jsx
        </div> 
    </div> 
</div> 

```

这次我们使用了`offset`关键字。该类名末尾的数字用于控制要偏移的列数。

### 提示

`offset`列数等于行中的总列数`12`。

现在，让我们创建一些复杂的布局，嵌套额外的行和列：

```jsx
<div class="row">
    <div class="col-sm-9">
        Level 1 - Lorem ipsum...
        <div class="row">
            <div class="col-xs-8 col-sm-4">
                Level 2 - Lorem ipsum...   
            </div>
            <div class="col-xs-4 col-sm-4">
                Level 2 - Lorem ipsum...
            </div>
        </div>
    </div>
</div>

```

如果您在浏览器中打开它，您将看到这将在我们之前创建的主要内容容器`col-sm-9`中创建两列。然而，由于我们的网格是嵌套的，我们可以创建一个新行，并拥有一个单列或两列，无论您的布局需要什么。我已经添加了一些虚拟文本来演示嵌套列。

Bootstrap 还将通过使用`col-md-push-*`和`col-md-pull-*`类在网格系统中提供更改列的顺序的选项。

```jsx
<div class="row">
    <div class="col-sm-9">
        Level 1 - Lorem ipsum...
        <div class="row">
            <div class="col-xs-8 col-sm-4 col-sm-push-4">
                Level 2 - col-xs-8 col-sm-4 col-sm-push-4   
            </div>
            <div class="col-xs-4 col-sm-4 col-sm-pull-4">
                Level 2 - col-xs-8 col-sm-4 col-sm-pull4      
            </div>
        </div>
    </div>
</div>

```

观察以下屏幕截图：

![Bootstrap 网格系统](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_02_005.jpg)

Bootstrap 还包括一些预定义的类，以便在特定屏幕尺寸下显示或隐藏元素。这些类使用与 Bootstrap 网格相同的预定义尺寸。

例如，以下代码将在特定屏幕尺寸下隐藏一个元素：

```jsx
<div class="hidden-md"></div> 

```

这将在中等设备上隐藏元素，但在手机、平板电脑和大型台式机上仍然可见。要在多个设备上隐藏元素，我们需要使用多个类：

```jsx
<div class="hidden-md hidden-lg"></div> 

```

同样，与可见类一样，它们可以反向工作，在特定尺寸下显示元素。

但是，与隐藏类不同，它们还要求我们设置显示值。这可以是`block`，`inline`或`inline-block`：

```jsx
<div class="visible-md-block"></div> 
<div class="visible-md-inline"></div> 
<div class="visible-md-inline-block"></div> 

```

当然，我们可以在一个元素中使用各种类。例如，如果我们想在较小的屏幕上使用`block`级元素，但稍后将其变为`inline-block`，我们将使用以下代码：

```jsx
<div class="visible-sm-block visible-md-inline-block"></div> 

```

如果您记不住各种类的大小，请务必再次查看*了解 Bootstrap 网格*部分，以了解屏幕尺寸。

# 辅助类

Bootstrap 还包括一些辅助类，我们可以用来调整布局。让我们看一些例子。

## 浮动

Bootstrap 的浮动类将帮助您在 Web 上创建一个体面的布局。以下是两个 Bootstrap 类，用于将您的元素向左和向右拉：

```jsx
<div class="pull-left">...</div> 
<div class="pull-right">...</div> 

```

当我们在元素上使用浮动时，我们需要在我们的浮动元素中包装一个`clearfix`类。这将清除元素，您将能够看到容器元素的实际高度：

```jsx
<div class="helper-classes"> 
    <div class="pull-left">...</div> 
    <div class="pull-right">...</div> 
    <div class="clearfix"> 
</div> 

```

如果`float`类直接位于具有`row`类的元素内部，则我们的浮动将被 Bootstrap 自动清除，无需手动应用`clearfix`类。

## 中心元素

要使其居中`block-level`元素，Bootstrap 允许使用`center-block`类：

```jsx
<div class="center-block">...</div> 

```

这将将您的元素属性`margin-left`和`margin-right`属性设置为`auto`，这将使元素居中。

## 显示和隐藏

您可能希望使用 CSS 显示和隐藏元素，Bootstrap 为此提供了一些类：

```jsx
<div class="show">...</div> 
<div class="hidden">...</div> 

```

### 注意

`show`类将`display`属性设置为`block`，因此只将其应用于`block-level`元素，而不是希望以`inline`或`inline-block`显示的元素。

# React 组件

React 基于模块化构建，具有封装的组件，这些组件管理自己的状态，因此当数据发生变化时，它将有效地更新和渲染您的组件。在 React 中，组件的逻辑是用 JavaScript 编写的，而不是模板，因此您可以轻松地通过应用程序传递丰富的数据并管理 DOM 之外的状态。

使用`render()`方法，我们正在在 React 中呈现一个组件，该组件接受输入数据并返回您想要显示的内容。它可以接受 HTML 标签（字符串）或 React 组件（类）。

让我们快速看一下两者的示例：

```jsx
var myReactElement = <div className="hello" />; 
ReactDOM.render(myReactElement, document.getElementById('example')); 

```

在这个例子中，我们将 HTML 作为字符串传递给`render`方法，之前我们已经在创建`<Navbar>`之前使用过它：

```jsx
var ReactComponent = React.createClass({/*...*/}); 
var myReactElement = <ReactComponent someProperty={true} />; 
ReactDOM.render(myReactElement, document.getElementById('example')); 

```

在上面的例子中，我们正在渲染组件，只是为了创建一个以大写约定开头的局部变量。在 React 的 JSX 中使用大写与小写的约定将区分本地组件类和 HTML 标签。

因此，我们可以以两种方式创建 React 元素或组件：一种是使用`React.createElement`的纯 JavaScript，另一种是使用 React 的 JSX。

因此，让我们为应用程序创建侧边栏元素，以更好地理解`React.createElement`。

## React.createElement()

在 React 中使用 JSX 完全是可选的。正如我们所知，我们可以使用`React.createElement`创建元素，它接受三个参数：标签名或组件、属性对象和可变数量的子元素（可选）。观察以下代码：

```jsx
var profile = React.createElement('li',{className:'list-group-item'},
'Profile'); 

var profileImageLink = React.createElement('a',{className:'center-
block text-center',href:'#'},'Image'); 

    var profileImageWrapper = React.createElement('li',
    {className:'list-group-item'}, profileImageLink); 

    var sidebar = React.createElement('ul', { className: 'list-
    group' }, profile, profileImageWrapper); 

    ReactDOM.render(sidebar, document.getElementById('sidebar')); 

```

在上面的例子中，我们使用`React.createElement`生成了一个`ul`-`li`结构。React 已经为常见的 DOM HTML 标签内置了工厂。

以下是一个示例：

```jsx
var Sidebar = React.DOM.ul({ className: 'list-group' }, 
React.DOM.li({className:'list-group-item text-muted'},'Profile'), 
React.DOM.li({className:'list-group-item'}, 
React.DOM.a({className:'center-block text-center',href:'#'},'Image') 
    ), 
React.DOM.li({className:'list-group-item text-right'},'2.13.2014', 
React.DOM.span({className:'pull-left'}, 
React.DOM.strong({className:'pull-left'},'Joining Date') 
    ), 
    React.DOM.div({className:'clearfix'}) 
));                                  
ReactDOM.render(Sidebar, document.getElementById('sidebar'));
```

让我们快速在浏览器中查看我们的代码，它应该类似于以下截图：

![React.createElement()](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_02_006.jpg)

到目前为止，这是我们编写的包含`<Navbar>`组件的全部代码：

```jsx
<script type="text/babel">
    var Nav= ReactBootstrap.Nav;
    var Navbar= ReactBootstrap.Navbar;
    var NavItem= ReactBootstrap.NavItem;
    var NavDropdown = ReactBootstrap.NavDropdown;
    var MenuItem= ReactBootstrap.MenuItem;
    var navbarReact =(
    <Navbar>
    <Navbar.Header>
    <Navbar.Brand>
      <a href="#">EIS</a>
    </Navbar.Brand>
    <Navbar.Toggle />
    </Navbar.Header>
    <Navbar.Collapse>
    <Nav>
    <NavItem eventKey={1} href="#">Home</NavItem>
    <NavItem eventKey={2} href="#">Edit Profile</NavItem>
    <NavDropdown eventKey={3}  id="basic-
    nav-dropdown">
      <MenuItem eventKey={3.1}>View Tickets</MenuItem>
      <MenuItem eventKey={3.2}>New Ticket</MenuItem>
    </NavDropdown>
    </Nav>
    </Navbar.Collapse>
    </Navbar>
    );
    ReactDOM.render(navbarReact,document.getElementById('nav'));

    var Sidebar = React.DOM.ul({ className: 'list-group' },
     React.DOM.li({className:'list-group-item text-muted'},'Profile'),
     React.DOM.li({className:'list-group-item'},
      React.DOM.a({className:'center-block
      text-center',href:'#'},'Image')
      ),
    React.DOM.li({className:'list-group-item text-right'},
    '2.13.2014',
    React.DOM.span({className:'pull-left'},
    React.DOM.strong({className:'pull-left'},'Joining Date')
    ),
      React.DOM.div({className:'clearfix'})
    ));            
    ReactDOM.render(Sidebar, document.getElementById('sidebar'));

</script>
<div id="nav"></div>
<div class="container">
    <hr>
    <div class="row">
        <div class="col-sm-3" id="sidebar">
            <!--left col-->
        </div>
        <!--/col-3-->
        <div class="col-sm-9 profile-desc"></div>
        <!--/col-9-->
    </div>
</div>
<!--/row-->

```

我们的应用程序代码看起来非常混乱。现在是时候让我们的代码变得整洁和结构良好。

将`navbar`代码复制到另一个文件中，并将其保存为`navbar.js`。

现在将`sidebar`代码复制到另一个文件中，并保存为`sidebar.js`。

在根目录中创建一个名为 components 的文件夹，并将`navbar.js`和`sidebar.js`都复制到其中。

在`head`部分包含两个`js`文件。

`head`部分将如下所示：

```jsx
<script type="text/javascript" src="js/react.min.js"></script> 
<script type="text/javascript" src="js/react-dom.min.js"></script> 
<script src="js/browser.min.js"></script> 
<script src="js/jquery-1.10.2.min.js"></script> 
<script src="js/react-bootstrap.min.js"></script> 
<script src="components/navbar.js" type="text/babel"></script> 
<script src="components/sidebar.js" type="text/babel"></script> 

```

以下是您的 HTML 代码：

```jsx
<div id="nav"></div>
<div class="container">
    <hr>
    <div class="row">
        <div class="col-sm-3" id="sidebar">
            <!--left col-->
        </div>
        <!--/col-3-->
        <div class="col-sm-9 profile-desc"></div>
        <!--col-9-->
    </div>
</div>
<!--/row--> 

```

现在我们的代码看起来更加清晰。让我们快速查看一下您在浏览器中的代码输出：

![React.createElement()](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_02_007.jpg)

### 提示

当我们从外部来源引用 ReactJS 文件时，我们需要一个 Web 服务器或者像 WAMP 或 XAMPP 这样的全栈应用，因为一些浏览器（例如 Chrome）在不通过 HTTP 提供文件的情况下会加载失败。

# 总结

我们已经从本章节中积累了相当多关于 Bootstrap 和 React-Bootstrap 的基础知识，所以让我们快速复习一下我们到目前为止学到的东西。

在了解 Bootstrap 和 React-Bootstrap 的定义和用法时，我们发现 React-Bootstrap 是一个非常有潜力、更灵活、更智能的解决方案。

我们已经看到了如何通过使用 Bootstrap 和 React-Bootstrap 的一些特性来创建移动导航，这些特性在所有预期的设备上以及桌面浏览器上都能很好地工作。

我们还研究了包括 Bootstrap 在内的强大响应式网格系统，并创建了一个简单的两列布局。在做这些的时候，我们学到了四种不同的列类前缀，以及如何嵌套我们的网格。

我们还看到了 Bootstrap 的一些非常好的特性，比如`offset`，`col-md-push-*`，`col-md-pull-*`，`hidden-md`，`hidden-lg`，`visible-sm-block`，`visible-md-inline-block`和`helper-classes`。

我们希望你也已经准备好了响应式布局和导航。现在让我们跳到下一章。


# 第三章：ReactJS-JSX

在上一章中，我们通过使用 React-Bootstrap 和 React 来构建响应式主题的过程。我们看到了它的示例以及 Twitter Bootstrap 和 React-Bootstrap 之间的区别。

我现在非常兴奋，因为我们将深入了解 ReactJS 的核心，即 JSX。那么，你们准备好了吗？让我们深入学习 ReactJS-JSX。

# 在 React 中的 JSX 是什么

JSX 是 JavaScript 语法的扩展，如果您观察 JSX 的语法或结构，您会发现它类似于 XML 编码。

使用 JSX，您可以执行预处理步骤，将 XML 语法添加到 JavaScript 中。虽然您当然可以在没有 JSX 的情况下使用 React，但 JSX 使 React 变得更加整洁和优雅。与 XML 类似，JSX 标记具有标记名称、属性和子级，如果属性值被引号括起来，该值就成为一个字符串。

XML 使用平衡的开放和关闭标记。JSX 类似地工作，它还有助于比 JavaScript 函数和对象更容易地阅读和理解大量的结构。

## 在 React 中使用 JSX 的优点

以下是一些优点的列表：

+   与 JavaScript 函数相比，JSX 非常容易理解和思考

+   JSX 的标记更容易让非程序员熟悉

+   通过使用 JSX，您的标记变得更有语义、有组织和有意义

## 如何使您的代码整洁和干净

正如我之前所说，这种结构/语法非常容易可视化/注意到，这意味着当我们将其与 JavaScript 语法进行比较时，JSX 格式的代码更加清晰和易于理解。

以下是简单的代码片段，将给你一个清晰的想法。让我们看看在渲染时 JavaScript 语法的以下示例中的代码片段：

```jsx
render: function () {
    return React.DOM.div({className:"divider"},
        "Label Text",
        React.DOM.hr()
    );
}  

```

观察以下 JSX 语法：

```jsx
render: function () { 
    return <div className="divider"> 
    Label Text<hr /> 
</div>; 
} 

```

我假设现在很清楚 JSX 对于通常不习惯处理编码的程序员来说是非常容易理解的，并且他们可以学习和执行它，就像执行 HTML 语言一样。

# 熟悉或理解

在开发领域，UI 开发人员、用户体验设计师和质量保证人员并不太熟悉任何编程语言，但 JSX 通过提供简单的语法结构使他们的生活变得更加轻松，这个结构在视觉上类似于 HTML 结构。

JSX 显示了一种路径，以一种坚实而简洁的方式指示和看到您的思维结构。

# 语义/结构化语法

到目前为止，我们已经看到了 JSX 语法是如何易于理解和可视化的，原因在于语义化的语法结构。

JSX 将您的 JavaScript 代码转换为更标准的解决方案，这样可以清晰地设置您的语义化语法和重要组件。借助于 JSX 语法，您可以声明自定义组件的结构和信息，就像在 HTML 语法中一样，这将为您的语法转换为 JavaScript 函数提供魔力。

`React.DOM`命名空间帮助我们使用所有 HTML 元素，借助于 ReactJS：这不是一个令人惊讶的功能吗！而且，好处是您可以使用`React.DOM`命名空间编写自己命名的组件。

请查看以下简单的 HTML 标记以及 JSX 组件如何帮助您创建语义化标记：

```jsx
<div className="divider"> 
<h2>Questions</h2><hr /> 
</div> 

```

正如您在前面的示例中所看到的，我们用`<div>`标记包裹了`<h2>Questions</h2><hr />`，并且`<div>`标记具有`className="divider"`。因此，在 React 复合组件中，您可以创建类似的结构，就像在使用语义化语法的 HTML 编码时一样简单：

```jsx
 <Divider> Questions </Divider>

```

让我们详细了解一下复合组件是什么，以及我们如何构建它。

# 复合组件

正如我们所知，您可以使用 JSX 标记和 JSX 语法创建自定义组件，并将您的组件转换为 JavaScript 语法组件。

让我们设置 JSX：

```jsx
<script type="text/javascript" src="js/react.min.js"></script> 
<script type="text/javascript" src="js/react-dom.min.js"></script> 
<script src="js/browser.min.js"></script> 
<script src="js/divider.js" type="text/babel"></script>

```

在您的 HTML 中包含以下文件：

```jsx
<div>
    <Divider>...</Divider>
    <p>...</p>
</div>

```

将此 HTML 添加到您的`<body>`部分。

现在，我们已经准备好使用 JSX 定义自定义组件了。

要创建自定义组件，我们必须将上述提到的 HTML 标记表达为 React 自定义组件。您只需按照给定的示例执行包装的语法/代码，然后在渲染后，它将给您预期的标记结果。`Divider.js`文件将包含：

```jsx
var Divider = React.createClass({ 
    render: function () { 
        return ( 
            <div className="divider"> 
                <h2>Questions</h2><hr /> 
            </div> 
        ); 
    } 
}); 

```

如果您想将子节点附加到您的组件中，那么在 React-JSX 中是可能的。在前面的代码中，您可以看到我们创建了一个名为`divider`的变量，并且借助于 React-JSX，我们可以将其用作 HTML 标记，就像我们使用定义的 HTML 标记`<div>`，`<span>`等一样。您还记得我们在之前的示例中使用了以下标记吗？如果没有，请再次参考前面的主题，因为它将消除您的疑虑。

```jsx
<Divider>Questions</Divider> 

```

与 HTML 语法一样，在这里，子节点被捕获在开放和关闭标记之间的数组中，您可以将其设置在组件的`props`（属性）中。

在这个例子中，我们将使用`this.props.children` = `["Questions"]`，其中`this.props.children`是 React 的方法：

```jsx
var Divider = React.createClass({ 
    render: function () { 
        return ( 
            <div className="divider"> 
                <h2>{this.props.children}</h2><hr /> 
            </div> 
        ); 
    } 
}); 

```

正如我们在前面的示例中看到的，我们可以像在任何 HTML 编码中一样创建带有开放和关闭标记的组件：

```jsx
<Divider>Questions</Divider>
```

我们将得到以下预期的输出：

```jsx
<div className="divider"> 
    <h2>Questions</h2><hr /> 
</div> 

```

# 命名空间组件

命名空间组件是 React JSX 中可用的另一个功能请求。我知道你会有一个问题：什么是命名空间组件？好的，让我解释一下。

我们知道 JSX 只是 JavaScript 语法的扩展，它还提供了使用命名空间的能力，因此 React 使用 JSX 命名空间模式而不是 XML 命名空间。通过使用标准的 JavaScript 语法方法，即对象属性访问，这个功能对于直接分配组件作为`<Namespace.Component/>`而不是分配变量来访问存储在对象中的组件非常有用。

让我们从以下的显示/隐藏示例开始，以便清楚地了解命名空间组件：

```jsx
var MessagePanel = React.createClass({ 
    render: function() { 
        return <div className='collapse in'> {this.props.children} </div> 
  } 
}); 
var MessagePanelHeading = React.createClass({ 
  render: function() { 
    return <h2>{this.props.text}</h2>} 
}); 

var MessagePanelContent = React.createClass({ 
  render: function() { 
    return <div className='well'> {this.props.children} </div> 
  } 
}); 

```

从以下示例中，我们将看到如何组合`MessagePanel`：

```jsx
<MessagePanel> 
<MessagePanelHeading text='Show/Hide' /> 
<MessagePanelContent> 
     Phasellus sed velit venenatis, suscipit eros a, laoreet dui. 
</MessagePanelContent> 
</MessagePanel> 

```

`MessagePanel`是一个组件，用于在用户界面中呈现消息。

它主要有两个部分：

+   `MessagePanelHeading`：这显示消息的标题

+   `MessagePanelContent`：这是消息的内容

有一种更健康的方式来组成`MessagePanel`，即通过将子组件作为父组件的属性来实现。

让我们看看如何做到这一点：

```jsx
var MessagePanel = React.createClass({ 
    render: function() { 
        return <div className='collapse in'>    
        {this.props.children} </div> 
    } 
}); 

MessagePanel.Heading = React.createClass({ 
    render: function() { 
        return <h2>{this.props.text}</h2> 
    } 
}); 

MessagePanel.Content = React.createClass({ 
    render: function() { 
        return <div className='well'> {this.props.children} </div> 
} 
}); 

```

因此，在前面的代码片段中，您可以看到我们如何通过只添加新的 React 组件`Heading`和`Content`来扩展`MessagePanel`。

现在，让我们看看当我们引入命名空间符号时，组合会发生什么变化：

```jsx
<MessagePanel> 
    <MessagePanel.Heading text='Show/Hide' /> 
    <MessagePanel.Content> 
    Phasellus sed velit venenatis, suscipit eros a, laoreet dui. 
    </MessagePanel.Content> 
</MessagePanel>
```

现在，我们将在 React 中与 Bootstrap 集成后看到命名空间组件代码的实际示例：

```jsx
<!doctype html>
<html>
    <head>
        <title>React JS – Namespacing component</title>
            <link rel="stylesheet" href="css/bootstrap.min.css">
            <link rel="stylesheet" href="css/custom.css">
        <script type="text/javascript" src="js/react.min.js"></script>
        <script type="text/javascript" src="js/JSXTransformer.js">
        </script>
    </head>
    <script type="text/jsx">
    /** @jsx React.DOM */
    var MessagePanel = React.createClass({
        render: function() {
            return <div className='collapse in'> {this.props.children}
            </div>
        }
    });

    MessagePanel.Heading = React.createClass({
        render: function() {
            return <h2>{this.props.text}</h2>
        }
    });

    MessagePanel.Content = React.createClass({
        render: function() {
            return <div className='well'> {this.props.children} </div>
        }
    });

    var MyApp = React.createClass({
        getInitialState: function() {
            return {
                collapse: false
            };
        },
        handleToggle: function(evt){
            var nextState = !this.state.collapse;
            this.setState({collapse: nextState});
        },

        render: function() {
            var showhideToggle = this.state.collapse ?
            (<MessagePanel>
            <MessagePanel.Heading text='Show/Hide' />
            <MessagePanel.Content>
                Phasellus sed velit venenatis, suscipit eros a,
                laoreet dui.
            </MessagePanel.Content>
            </MessagePanel>)
            : null;
            return (<div>
                <h1>Namespaced Components Demo</h1>
                <p><button onClick={this.handleToggle} className="btn
                btn-primary">Toggle</button></p>
                {showhideToggle}
                </div>)
            }
        });

        React.render(<MyApp/>, document.getElementById('toggle-
        example'));
    </script>
    </head>
    <body>
        <div class="container">
            <div class="row">
                <div id="toggle-example" class=”col-sm-12”>
                </div>
            </div>
        </div>
    </body>
</html>

```

让我解释一下前面的代码：

+   `State`属性包含我们组件的`setState`和`getInitialState`设置的状态

+   `setState(changes)`方法将给定的更改应用于此状态并重新呈现它

+   `handleToggle`函数处理我们组件的状态并返回布尔值`true`或`false`

我们还使用了一些 Bootstrap 类来赋予我们的组件外观和感觉：

+   `.collapse`：这是用于隐藏内容的。

+   `.collapse.in`：这是用于显示内容的。

+   `.well`：这是用于内容周围的背景、边框和间距。

+   `.btn .btn-primary`：这是按钮的外观。Bootstrap 还为您提供了一些不同颜色样式的不同类，帮助读者提供视觉指示：

+   `.btn-default`、`.btn-success`、`.btn-info`、`.btn-warning`、`.btn-danger`和`.btn-link`。

+   我们可以使用`<a>`、`<button>`或`<input>`元素。

+   `.col-sm-12`：这是为了使你的组件在小屏幕上响应。

现在，让我们在浏览器中打开你的 HTML 并查看输出：

![命名空间组件](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_03_001.jpg)

现在调整屏幕大小，看看效果：

![命名空间组件](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_03_002.jpg)

看起来很棒！

## JSXTransformer

**JSXTransformer**是另一个在浏览器中编译 JSX 的工具。在阅读代码时，浏览器将读取你所提到的`<script>`标签中的`attribute type="text/jsx"`，它只会转换那些具有提到`type`属性的脚本，然后执行你的脚本或文件中的函数。代码将以与`react-tools`在服务器上执行的相同方式执行。访问[`facebook.github.io/react/blog/2015/06/12/deprecating-jstransform-and-react-tools.html`](https://facebook.github.io/react/blog/2015/06/12/deprecating-jstransform-and-react-tools.html)了解更多。

JSXTransformer 在当前版本的 React 中已经被弃用，但你可以在任何提供的 CDN 和 Bower 上找到当前版本。依我看来，使用**Babel REPL**([`babeljs.io/repl/#?babili=false&evaluate=true&lineWrap=false&presets=es2015%2Creact%2Cstage-2&code=`](https://babeljs.io/repl/#?babili=false&evaluate=true&lineWrap=false&presets=es2015%2Creact%2Cstage-2&code=))工具来编译 JavaScript 会很棒。它已经被 React 和更广泛的 JavaScript 社区所采用。

### 注意

这个例子在最新版本的 React 中不起作用。使用旧版本，比如 0.13，因为 JSXTransformer 已经被弃用，它被 Babel 所取代，用于在浏览器中转换和运行 JSX 代码。当浏览器具有`type="text/babel"`类型属性时，它才能理解你的`<script>`标签，我们之前在第一章和第二章的例子中使用过这种类型属性。

# 属性表达式

如果您看一下前面的显示/隐藏示例，您会发现我们使用属性表达式来显示消息面板并隐藏它。在 React 中，写属性值有一个小改变，在 JavaScript 表达式中，我们用引号(`""`)来写属性，但在 React 中，我们必须提供一对花括号(`{}`)：

```jsx
var showhideToggle = this.state.collapse ? (<MessagePanel>):null/>; 

```

## 布尔属性

布尔属性有两个值，它们可以是`true`或`false`，如果我们在 JSX 中声明属性时忽略了值，那么默认情况下它会取值为`true`。如果我们想要一个`false`属性值，那么我们必须使用属性表达式。当我们使用 HTML 表单元素时，这种情况经常发生，例如`disabled`属性，`required`属性，`checked`属性和`readOnly`属性。

在 Bootstrap 示例中`aria-haspopup="true"aria-expanded="true"`：

```jsx
// example of writing disabled attribute in JSX 
<input type="button" disabled />; 
<input type="button" disabled={true} />; 

```

## JavaScript 表达式

如前面的示例所示，您可以使用在任何句柄用户习惯的语法中在 JSX 中嵌入 JavaScript 表达式，例如，`style = { displayStyle }`将`displayStyle` JavaScript 变量的值分配给元素的`style`属性。

### 样式

与表达式一样，您可以通过将普通的 JavaScript 对象分配给`style`属性来设置样式。多么有趣。如果有人告诉你不要编写 CSS 语法，您仍然可以编写 JavaScript 代码来实现这一点，而不需要额外的努力。这不是很棒吗！是的，确实如此。

### 事件

有一组事件处理程序，您可以以一种熟悉 HTML 的方式绑定它们。

一些 React 事件处理程序的名称如下：

+   剪贴板事件

+   组合事件

+   键盘事件

+   焦点事件

+   表单事件

+   鼠标事件

+   选择事件

+   触摸事件

+   UI 事件

+   滚轮事件

+   媒体事件

+   图像事件

+   动画事件

+   过渡事件

### 属性

JSX 的一些定义的`PropTypes`如下：

+   `React.PropTypes.array`

+   `React.PropTypes.bool`

+   `React.PropTypes.func`

+   `React.PropTypes.number`

+   `React.PropTypes.object`

+   `React.PropTypes.string`

+   `React.PropTypes.symbol`

如果您提前了解所有属性，那么在使用 JSX 创建组件时会很有帮助：

```jsx
var component = <Component foo={x} bar={y} />; 

```

改变`props`是不好的做法，让我们看看为什么。

通常，根据我们的做法，我们将属性设置为非推荐的标准对象：

```jsx
var component = <Component />; 
component.props.foo = x; // bad 
component.props.bar = y; // also bad 

```

如前面的例子所示，您可以看到反模式，这不是最佳实践。如果您不了解 JSX 属性的属性，则`propTypes`将不会被设置，并且将抛出难以跟踪的错误。

`props`是属性的一个非常敏感的部分，所以您不应该更改它们，因为每个 prop 都有一个预定义的方法，您应该按照其预期的方式使用它，就像我们使用其他 JavaScript 方法或 HTML 标签时一样。这并不意味着不可能更改`props`。这是可能的，但这违反了 React 定义的标准。即使在 React 中，它也会抛出错误。

### 扩展属性

让我们看看 JSX 的特性--扩展属性：

```jsx
  var props = {}; 
  props.foo = x; 
  props.bar = y; 
  var component = <Component {...props} />; 

```

在前面的例子中，您声明的属性也已成为组件的`props`的一部分。

属性的可重用性在这里也是可能的，您还可以将其与其他属性进行映射。但是在声明属性时，您必须非常小心，因为它将覆盖先前声明的属性，最后声明的属性将覆盖之前的属性。

```jsx
var props = { foo: 'default' }; 
var component = <Component {...props} foo={'override'} />; 
console.log(component.props.foo); // 'override' 

```

希望您现在对 JSX、JSX 表达式和属性有了清楚的了解。那么，让我们看看如何使用 JSX 动态构建简单的表单。

## 使用 JSX 构建动态表单的示例

在使用 JSX 构建动态表单之前，我们必须了解 JSX 表单库。

通常，HTML 表单元素输入将其值作为显示文本/值，但在 React JSX 中，它们将相应元素的属性值作为显示文本/值。由于我们已经直观地感知到我们不能直接更改`props`的值，所以输入值不会具有转变后的值作为展示值。

让我们详细讨论一下。要更改表单输入的值，您将使用`value`属性，然后您将看不到任何更改。这并不意味着我们不能更改表单输入的值，但是为此我们需要监听输入事件，然后您将看到值的变化。

以下异常是不言自明的，但非常重要：

+   在 React 中，`Textarea`内容将被视为`value`属性。

+   由于`For`是 JavaScript 的保留关键字，HTML 的`for`属性应该像`htmlFor`prop 一样被绑定

现在是时候学习了，为了在输出中拥有表单元素，我们需要使用以下脚本，并且还需要用先前编写的代码替换它。

现在让我们开始为我们的应用程序构建一个添加工单表单。

在根目录中创建一个`React-JSXform.html`文件。以下代码片段只是一个包含 Bootstrap 和 React 的基本 HTML 页面。

这是我们 HTML 页面的标记：

```jsx
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Dynamic form with JSX</title>
        <link rel="stylesheet" href="css/bootstrap.min.css">
    </head>
    <body>
        <script type="text/javascript" src="js/react.min.js"></script>
        <script type="text/javascript" src="js/react-dom.min.js">
        </script>
        <script src="js/browser.min.js"></script>
    </body>
</html> 

```

将所有脚本加载到页面底部，在`<body>`标签关闭之前，总是一个良好的做法，这样可以成功加载组件到 DOM 中，因为当脚本在`<head>`部分执行时，文档元素不可用，因为脚本本身在`<head>`部分。解决此问题的最佳方法是将脚本保持在页面底部，在`<body>`标签关闭之前执行，这样在加载所有 DOM 元素后执行，不会引发任何 JavaScript 错误。

现在让我们使用 Bootstrap 和 JSX 创建`<form>`元素：

```jsx
<form> 
    <div className="form-group"> 
        <label htmlFor="email">Email <span style={style}>*</span>
        </label> 
       <input type="text" id="email" className="form-control" 
       placeholder="Enter email" required/> 
    </div> 
</form>
```

在上面的代码中，我们使用`class`作为`className`，`for`作为`htmlFor`，因为 JSX 类似于 JavaScript，而`for`和`class`是 JavaScript 中的标识符。我们应该在`ReactDOM`组件中将`className`和`htmlFor`作为属性名称使用。

所有表单元素`<input>`、`<select>`和`<textarea>`都将使用`.form-control`类获得全局样式，并默认应用`width:100%`。因此，当我们在输入框中使用标签时，我们需要使用`.form-group`类进行包装，以获得最佳间距。

对于我们的添加工单表单，我们需要以下表单字段以及标签：

+   `邮箱：<input>`

+   `问题类型：<select>`

+   `分配部门：<select>`

+   `评论：<textarea>`

+   `按钮：<button>`

为了使其成为响应式表单，我们将使用`*col-*`类。

让我们快速查看一下我们的表单组件代码：

```jsx
var style = {color: "#ffaaaa"};
var AddTicket = React.createClass({
    handleSubmitEvent: function (event) {
        event.preventDefault();
    },
    render: function() {
        return (
            <form onSubmit={this.handleSubmitEvent}>
                <div className="form-group">
                    <label htmlFor="email">Email <span style={style}>*
                    </span></label>
                    <input type="text" id="email" className="form-
                    control" placeholder="Enter email" required/>
                </div>
                <div className="form-group">
                    <label htmlFor="issueType">Issue Type <span style=
                    {style}>*</span></label>
                    <select className="form-control" id="issueType"
                    required>
                        <option value="">-----Select----</option>
                        <option value="Access Related Issue">Access
                        Related Issue</option>
                        <option value="Email Related Issues">Email
                        Related Issues</option>
                        <option value="Hardware Request">Hardware
                        Request</option>
                        <option value="Health & Safety">Health &
                        Safety</option>
                        <option value="Network">Network</option>
                        <option value="Intranet">Intranet</option>
                        <option value="Other">Other</option>
                    </select>
                </div>
                <div className="form-group">
                    <label htmlFor="department">Assign Department
                    <span style={style}>*</span></label>
                    <select className="form-control" id="department"
                    required>
                        <option value="">-----Select----</option>
                        <option value="Admin">Admin</option>
                        <option value="HR">HR</option>
                        <option value="IT">IT</option>
                        <option value="Development">Development
                        </option>
                    </select>
                </div>
                <div className="form-group">
                    <label htmlFor="comments">Comments <span style=
                    {style}>*</span></label>(<span id="maxlength">
                    200</span> characters left)
                <textarea className="form-control" rows="3" 
                id="comments" required></textarea>
            </div>
            <div className="btn-group">
                <button type="submit" className="btn btn-primary">
                Submit</button>
                <button type="reset" className="btn btn-link">
                cancel</button>
            </div>
        </form>
    );
}
});
ReactDOM.render(
<AddTicket />
,
    document.getElementById('form')
);

```

在属性值中应用样式或调用`onSubmit`函数，而不是使用引号(`""`)，我们必须在 JavaScript 表达式中使用一对花括号(`{}`)。现在，创建一个`component`文件夹，并将此文件保存为`form.js`，然后将其包含在您的 HTML 页面中。这是我们页面的样子：

```jsx
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8" />
        <title>Dynamic form with JSX</title>
        <link rel="stylesheet" href="css/bootstrap.min.css">
    </head>
    <body>
        <div class="container">
            <div class="row">
                <div class="col-sm-12 col-md-6">
                    <h2>Add Ticket</h2>
                    <hr/>
                    <div id="form">
                    </div>
                </div>
            </div>
        </div>
        <script type="text/javascript" src="js/react.min.js"></script>
        <script type="text/javascript" src="js/react-dom.min.js">
        </script>
        <script src="js/browser.min.js"></script>
        <script src="component/form.js" type="text/babel"></script>
    </body>
</html>

```

让我们快速查看一下我们组件在浏览器中的输出：

![JSX 动态表单示例](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_03_003.jpg)

哦，太酷了！看起来很棒。

在调整浏览器大小时，让我们检查一下表单组件的响应行为：

![JSX 动态表单示例](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_03_004.jpg)

### 提示

在创建 React 组件时，第一个字符应始终是大写。例如，`AddTicket`。

# 总结

在本章中，我们已经看到了 JSX 在制作自定义组件方面起着重要作用，使它们非常简单易于可视化、理解和编写。

本章中展示的关键示例将帮助您了解 JSX 语法及其实现。

本章的最后一个示例涵盖了响应式的使用 JSX 和 Bootstrap 创建添加工单表单，这给了您关于 JSX 语法执行以及如何创建自定义组件的想法。您可以在与 HTML 交互时轻松使用它并进行调整。

如果您仍然不确定 JSX 及其行为，我建议您再次阅读本章，因为这也将帮助您在查看未来章节时。

如果您完全理解了本章，那么让我们继续阅读第四章，*ReactJS 中的 DOM 交互*，这一章将讨论 DOM 与 React 的交互，我们将看到 DOM 与 ReactJS 的交互。这是一个有趣的章节，因为当我们谈论输入和输出之间的交互时，我们必须考虑后端代码和 DOM 元素。您将看到一些非常有趣的主题，如 props 和 state，受控组件，不受控组件，非 DOM 属性键和引用，以及许多示例。
