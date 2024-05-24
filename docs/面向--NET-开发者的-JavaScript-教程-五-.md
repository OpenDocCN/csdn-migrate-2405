# 面向 .NET 开发者的 JavaScript 教程（五）

> 原文：[`zh.annas-archive.org/md5/9D370F6C530A09D4B2BBB62567683DDF`](https://zh.annas-archive.org/md5/9D370F6C530A09D4B2BBB62567683DDF)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：Node.js 对 ASP.NET 开发者的意义

JavaScript 已经成为一种不仅运行在客户端，也运行在服务器端的流行语言之一。**Node.js** 使 JavaScript 能够运行在服务器端，并提供非阻塞 I/O、一个事件驱动的模型，这使得它更加轻量级、可伸缩和高效。如今，它在执行实时操作、开发业务应用程序、数据库操作等方面得到了更广泛的应用。**Node.js** 上的 JavaScript 可以与运行在 IIS 上的 ASP.NET 或其他网络服务器相关联。

# **Node.js** 简介

**Node.js** 是一个使用 JavaScript 构建服务器端应用程序的强大平台。**Node.js** 本身不是用 JavaScript 编写的，但它提供了一个运行 JavaScript 代码的运行时环境。它允许在服务器端运行 JavaScript 代码，提供基于 Google V8 JavaScript 引擎的运行时，这是一个用 C++编写的开源 JavaScript 引擎，由 Google Chrome 使用，用于在 V8 即时编译器执行时将 JavaScript 代码编译成机器代码。

**Node.js** 工作在单线程上；与其他创建每个请求单独线程的服务器端技术不同，**Node.js** 使用事件回调系统，通过单线程处理请求。如果多个请求同时到达，它们必须等待线程可用，然后才能获取它。在错误情况下，**Node.js** 不会抛出错误，这是避免错误冒泡和单线程中断的一个基本技术。如果在处理请求时出现任何错误，**Node.js** 会在响应本身中发送错误日志，通过回调参数。这使得主线程能够传播错误并延迟响应。**Node.js** 适合编写网络应用程序。它包括 HTTP 请求、其他网络通信任务，以及使用 Web Sockets 进行实时客户端/服务器通信。

## **Node.js** 网络服务器请求处理

**Node.js** 网络服务器维护一个有限的线程池来处理客户端请求。当请求到达服务器时，**Node.js** 网络服务器把这个请求放入一个事件队列中。然后事件循环组件——它在一个无限循环中工作——在空闲时处理这个请求。这个事件循环组件是单线程的，如果请求涉及到如文件系统访问、数据库访问等的 I/O 阻塞操作，它会检查内部线程池中的线程可用性，并将请求分配给可用线程。否则，它会一次性处理请求并将响应发送回客户端。当内部线程完成了 I/O 阻塞请求，它会首先将响应发送回事件循环，然后事件循环再将响应发送回客户端。

## **Node.js** 与.NET 的比较

**ASP.NET** 和**Node.js** 都是服务器端技术。下面的图表展示了**Node.js** 与.NET 的比较：

![Node.js 与 .NET 比较](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00082.jpeg)

## NPM

**Node 包管理器**（**NPM**）是用于安装 Node 模块的 Node.js 包管理器。Node.js 提供了一种编写 JavaScript 模块的方法，借助 NPM，我们可以在其他应用程序中添加和使用这些模块。在使用 ASP.NET Core 时，我们已经在使用一些模块，例如使用 Gulp 和 Grunt 压缩 CSS 和 JavaScript 文件，以及执行复制和合并操作。`package.json` 文件是包含有关应用程序和项目中使用的 Node 模块的元数据信息的配置文件。以下是 `package.json` 文件的示例截图：

![NPM](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00083.jpeg)

可以通过执行以下命令来安装依赖项：

```js
npm install NAME_OF_THE_PACKAGE –save

```

示例：

```js
npm install gulp –save

```

`--save` 用于更新 `package.json` 的依赖项部分并添加下载的包。

# 安装 Node.js

Visual Studio 为使用 Node.js 开发程序提供了强大的支持。要在 Windows 平台上配置 Node.js 开发环境，请从 [`nodejs.org`](http://nodejs.org) 下载并安装 Node.js。根据平台不同，可用的安装程序各不相同，如下面的截图所示：

![安装 Node.js](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00084.jpeg)

对于 Windows，我们将下载 64 位的 Windows 安装程序，该程序下载`.msi`包并通过一些简单的向导屏幕引导您。您会注意到 Node.js 安装程序包含一个运行 Node 程序的运行时和 NPM，以便在您的程序中引用其他 Node 模块。以下截图展示了这一点：

![安装 Node.js](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00085.jpeg)

`npm` 和 `node` 这样的命令已经添加到了环境路径中，我们可以直接从命令提示符执行这些命令。因此，如果我们打开命令提示符并输入 `node`，它将给出 Node 提示符，允许你即兴编写 JavaScript 代码并执行，如下面的截图所示：

![安装 Node.js](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00086.jpeg)

另外，我们还可以通过调用`node javascriptfile.js`来运行`.js`文件。

以下是一个名为`example1.js`的示例文件，该文件用于计算数组中定义的数字之和：

```js
console.log("NodeJs example");

var numbers= [100,20,29,96,55];

var sum=0;
for(i=0; i< numbers.length; i++)
{
 sum += numbers[i];
}
console.log("total sum is "+ sum);

```

以下是输出结果：

![安装 Node.js](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00087.jpeg)

# 使用 Node.js 与 Visual Studio 2015

市场上有很多支持 Node.js 工具的集成开发环境（IDE）。像 Visual Studio Code、Sublime、Komodo 和 Node Eclipse 这样的 IDE 都是流行的 Node.js 工作环境，但实际上，大多数 .NET 开发人员更习惯并熟悉使用 Visual Studio IDE。因此，在本章中，我们将使用 Visual Studio 2015 社区版。

可以在 Visual Studio 2015 中通过安装其扩展来安装 Node.js 模板。可以从 Visual Studio 菜单选项 **工具** | **扩展和更新** 中安装扩展：

![使用 Node.js 与 Visual Studio 2015](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00088.jpeg)

这个 Node.js 扩展安装了各种模板，用于开始使用 Node.js 开发应用程序。有一个模板是使用空白 Node.js 控制台应用程序模板开发控制台应用程序，有一个使用 Node.js express 模板开发 web 应用程序等等：

![使用 Node.js 和 Visual Studio 2015](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00089.jpeg)

使用这些模板的基本优势是节省手动配置事物的时间，这些模板通过提供基本的项目结构来帮助开发者立即启动 Node.js 应用程序。

让我们先创建一个基本的控制台应用程序模板。基本的控制台应用程序有一个`npm`文件夹，包含 node 包，`package.json`包含元数据信息和其他配置属性，还有`app.js`，其中包含实际的 JavaScript 代码：

![使用 Node.js 和 Visual Studio 2015](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00090.jpeg)

这个 Node.js 扩展提供了一个方便的功能，通过在`npm`文件夹上右键点击并选择**安装新的 npm 包**选项，即可添加 Node 模块，如下面的屏幕截图所示：

![使用 Node.js 和 Visual Studio 2015](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00091.jpeg)

选择这个选项后，Visual Studio 会打开一个窗口，帮助搜索任何 node 包，并几点击添加到你的应用程序中：

![使用 Node.js 和 Visual Studio 2015](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00092.jpeg)

前面的图表展示了可以通过这个选项添加的`Gulp`包的版本。

**交互式窗口**是 Visual Studio 中的另一个好功能，它打开了一个集成在 Visual Studio 标签中的命令提示符，你可以立即编写 JavaScript 代码并执行命令，如下面的屏幕截图所示：

![使用 Node.js 和 Visual Studio 2015](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00093.jpeg)

使用 Visual Studio 还有其他几个好处：你可以使用 Git 或 TFS 版本库，在 JavaScript 文件上调试你的代码并设置断点等等。针对 Node.js 的 Visual Studio 特定项目文件称为`.njsproj`，位于你项目的主文件夹中。

## 使用 Node.js 的简单控制台应用程序

一个 Node.js 应用程序由一个或多个提供特定功能的 JavaScript 文件组成。在一个 JavaScript 文件中写入成千上万行代码在实际中是不可能的，而且也会增加可维护性问题。在 Node.js 中，我们可以创建多个 JavaScript 文件，并通过`require`和`export`对象使用它们，这些对象是 Common JS 模块系统的组成部分：

```js
export: used to export variables, functions and objects 

//exportexample.js
module.exports.greeting = "Hello World";

require: To use the objects resides in different JavaScript files using require object. 

//consumerexample.js – referencing through file
var obj = require('./exportexample.js');
```

另外，我们也可以调用`require`而不指定`.js`文件扩展名，它会自动加载特定路径上存在的文件。如果该路径对应于一个文件夹，所有 JavaScript 文件都将被加载：

```js
//consumerexample.js – referencing through file
var obj= require('./exportexample');
```

当应用程序启动时，定义在`package.json`中的是主要入口点。在下面的屏幕截图中，`app.js`是主入口文件，首先被 Node.js 加载并执行：

![使用 Node.js 的简单控制台应用程序](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00094.jpeg)

让我们实现一个基本示例，有两个文件，分别是`app.js`（主入口）和`cars.js`，并返回`car`对象的几个属性，例如`name`、`model`和`engine`。首先，创建一个控制台应用程序项目并添加一个`cars.js`文件。

以下是`cars.js`的代码：

```js
module.exports.cars = [
{name:"Honda Accord" , model:"2016", engine: "V6"}, 
{name:"BMW X6", model:"2015", engine: "V8"}, 
{name:"Mercedez Benz",model:"2016", engine:"V12"}
];
```

通过`module.exports`，我们可以导出任何对象。无论是变量、函数还是 JSON 对象，都可以通过这个方法导出。此外，导出的对象可以通过`app.js`中的`require`对象使用，如下面的代码所示：

```js
var cars = require('./cars.js');
console.log(cars);
```

以下是输出：

![使用 Node.js 的简单控制台应用程序](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00095.jpeg)

前面的代码显示了`cars.js`文件中定义的 JSON 输出。为了初始化`cars`对象，并遍历列表中定义的汽车项目，我们需要将其作为函数导出，并通过`this`关键字定义它。通过`this`指定它将使列表从我们在`app.js`文件中创建的`cars`对象中访问。

以下是`cars.js`的修改版本：

```js
module.exports = function () {
  this.carsList =   
  [
    { name: "Honda Accord" , model: "2016", engine: "V6" }, 
    { name: "BMW X6", model: "2015", engine: "V8" }, 
    { name: "Mercedez Benz", model: "2016", engine: "V12" }
  ];
};
```

下面是初始化`cars`对象并遍历列表的`app.js`文件的修改版本：

```js
var cars = require('./cars.js');
var c = new cars();
var carsList = c.carsList;
for (i = 0; i < carsList.length; i++) { 
  console.log(carsList[i].name);
}
```

## 使用 Node.js 的 Web 应用程序

有各种 Node.js Web 框架可供选择。像 Express 和 Hapi.js 这样的框架是强大的框架，具有不同的架构和设计。在本节中，我们将使用 Express 框架，这是 Node.js 中最广泛使用的 Web 框架之一，用于 Web 和移动应用程序，并提供应用程序框架模型以开发 Web **Application Programming Interfaces**（**APIs**）。

## 创建空白 Node.js 应用程序

```js
listen() method that actually listens for the incoming requests, and sends the response using the res.end() method. Alternatively, we can also specify the content we are returning using the res.write() method. Here is the more simplified version of the same code, to understand how the pieces fit together:
```

```js
//Initialized http object
var http = require('http');

//declared port
var port = process.env.port || 1337;

//Initialized http server object and use res.write() to send actual response content
var httpServer= http.createServer(function (req, res) {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.write('Hello World\n');
    res.end();
});

//listening for incoming request
httpServer.listen(port);
```

## 在 Node.js 中使用 Express 框架的 Web 应用程序

在任何编程语言中，框架的一个重要好处是减少开发 Web 应用程序所需的努力。框架扮演着处理请求的重要角色，例如加载特定的视图、将模型注入视图等。与 ASP.NET 一样，我们有两种 Web 应用程序框架，ASP.NET Web Forms 和 ASP.NET MVC，Node.js 提供 Express EJS、Jade 以及许多其他 Web 应用程序框架来构建健壮的 Web 应用程序。

### 将简单的 Node.js 扩展以使用 Express

使用 Node.js 的 Visual Studio 扩展，你可以获得所有模板来开始使用 Express 3.0 和 Express 4.0 应用程序框架。Express 4.0 是最新的版本，有一些新功能和改进。我们可以使用引导大多数配置级别工作的模板，但为了获得更多清晰度，我们将扩展前面创建的简单 Node.js 示例，并使用 Express 框架在其上开发一个简单的 Web 应用程序。

要使用`Express`，我们必须使用 NPM 添加其包依赖，如下面的截图所示：

![将简单的 Node.js 扩展以使用 Express](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00098.jpeg)

一旦添加了 Express 包，您可以添加以下代码片段来启动 Express 应用程序：

```js
//Initialized http object
var http = require('http');

//adding express dependency
var express = require('express');

//creating express application
var expressApp = express();

//Configuring root call where '/' represents root path of the URL
expressApp.get("/", function (req, res) {
    res.send("<html><body><div>Hello World</div></body></html>");
});

//declared port
var port = process.env.port || 1337;

//Initialized http server object and use res.write() to send actual response content
var httpServer = http.createServer(expressApp);

//listening for incoming request
httpServer.listen(port);
```

这是一个简单的`Hello World`示例，返回 HTML 内容。现在，在我们要返回特定视图而不是静态 HTML 内容的情况下，我们可以通过使用 Express 视图引擎来实现，接下来将讨论这一点。

### Express 视图引擎

Express 拥有多种视图引擎，尽管 Jade 和 EJS 是最广泛使用的。我们将逐一了解这些差异是什么。

#### EJS 视图引擎

在 EJS 视图引擎中，视图是 HTML 页面，模型属性可以使用脚本片段`<% %>`绑定。

为了开始使用 EJS，我们需要通过 Visual Studio 中的 NPM 包管理器选项添加 EJS 包，或者通过执行`npm install ejs –save`命令来添加：

![EJS 视图引擎](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00099.jpeg)

添加此代码后，我们可以将视图引擎设置为`ejs`，如下面的代码片段所示：

```js
//Initialized http object
var http = require('http');

//adding express dependency
var express = require('express');

//creating express application
var expressApp = express();

//Set jade for Node.js application
expressApp.set('view engine', 'ejs') 
```

通过调用响应对象的`render()`方法设置`ejs`视图的路径，如下所示：

```js
//Configuring root call where '/' represents root path of the URL
expressApp.get("/", function (req, res) {
    res.render("ejsviews/home/index");
});
```

在`home`文件夹中添加`index.ejs`文件。所有视图都应该存放在根`Views`文件夹下，否则当应用程序运行时它们不会被加载。因此，应该在`Views`文件夹下定义`ejsviews`文件夹，在`ejsviews`文件夹下定义`home`，如下面的屏幕截图所示：

![EJS 视图引擎](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00100.jpeg)

以下是在应用程序启动时将被渲染的 EJS 视图的内容：

```js
<html>
 <body>
  <div> <h1> This is EJS View </h1> </div>
 </body>
</html>
```

在`ejsserver.js`文件的底部添加创建服务器并监听端口号`1337`的代码：

```js
//declared port
var port = process.env.port || 1337;

//Initialized http server object and use res.write() to send actual response content
var httpServer = http.createServer(expressApp);

//listening for incoming request
httpServer.listen(port);
```

当应用程序运行时，`index.ejs`将被加载并渲染以下所示的 HTML 内容：

![EJS 视图引擎](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00101.jpeg)

我们也可以通过 JSON 对象的形式传递模型。假设我们需要传递应用程序名称和描述；我们可以在调用响应对象的`render()`方法时传递这些值，如下所示：

```js
//Configuring root call where '/' represents root path of the URL
expressApp.get("/", function (req, res) {
    res.render("ejsviews/home/index", { appName: "EJSDemo", message: "This is our first EJS view engine example!" });
});
```

在`index.ejs`中，我们可以使用脚本片段将这些值与 HTML 控件绑定：

```js
<html>
 <body>
   <h1> <%= appName %> </h1>
  <p> <%= message %></p>
 </body>
</html>
```

EJS 还支持包含静态内容的布局页面，比如网页应用的头部和底部。因此，开发者不需要在每一页上都重新定义主要的布局内容，我们可以将其集中管理，就像我们在 ASP.NET MVC 中使用`_layout.cshtml`和 ASP.NET web forms 中的`Site.master`一样。

为了使用主页面，我们需要再添加一个包，称为`ejs-local`。此包可以通过 Visual Studio 中的 NPM 包管理器窗口添加，或者通过运行`npm install ejs-local --save`命令来添加：

![EJS 视图引擎](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00102.jpeg)

在添加此包后，我们可以添加`ejs-locals`，如下所示。必须在设置视图引擎之前设置它：

```js
//Initialized http object
var http = require('http');

//adding express dependency
var express = require('express');
var ejsLocal = require('ejs-locals');
//creating express application
var expressApp = express();

//Add engine that supports master pages
app.engine('ejs', ejsLocal);
```

在同一个`ejsviews`文件夹中添加`layout.ejs`页面，并指定 HTML 内容：

```js
<html>
<head>
  <title> <%= appName %> </title>
</head>
<body>
  <%= body %>
</body>
</html>
```

```js
index.ejs file:
```

```js
<% layout('../layout.ejs') -%>
<h1><%= appName %></h1>
<p> <%= message %></p>
```

以下输出生成：

![EJS 视图引擎](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00103.jpeg)

#### Jade 视图引擎

Jade 视图引擎是另一个 Node.js 视图引擎，其语法与我们之前在 EJS 中看到的有很大不同。当我们定义视图时，需要先通过 NPM 安装 Jade 视图引擎。我们可以在 Visual Studio 的 NPM 包管理器中安装，或者通过运行 `npm install jade –save` 命令：

![Jade 视图引擎](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00104.jpeg)

安装后，它将在 `package.json` 的依赖项部分添加 Jade 包。我们将从在 `app.js` 文件（Node.js 项目的入口点）中设置 Jade 视图引擎开始。

以下是在 `app.js` 中设置 Jade 视图引擎的代码：

```js
//adding express dependency
var express = require('express');

//creating express application
var expressApp = express();

//Set jade for Node.js application
expressApp.set('view engine', 'jade');
```

你会注意到我们没有通过 `require` 对象指定 Jade 引用。这是因为当 Express 框架被加载时，它将自动注册 Jade 的依赖项。以下代码片段加载了 Jade 视图：

```js
//Configuring root call where '/' represents root path of the URL
expressApp.get("/", function (req, res) {
res.render("home/index", 
{ 
appName: "JadeDemo",   
message: "This is our first Jade view engine example!"
}
);
});
```

Jade 视图语法通常与 HTML 不同，所有视图扩展名都应该是 `.jade`。在前面的代码中，我们指向了 `index.jade`，其中不需要显式指定 Jade。`Index.jade` 应该位于 `views/home` 文件夹下。让我们创建一个名为 `views` 的文件夹，然后在里面创建一个名为 `home` 的文件夹。添加一个新的 Jade 文件并将其命名为 `index.jade`。以下代码显示了 `appName` 和 `message` 在 HTML 元素中：

```js
doctype
html
    body
        h1= appName
        p= message
```

使用 Jade 语法，你不需要定义完整的 HTML 标签，你只需通过它们的名称指定，后面跟着分配给它们的值。例如，在前面的示例中，我们通过响应 `render()` 方法传递的 JSON 对象设置了 `appName` 和 `message` 的值。然而，HTML 元素支持许多更多的属性，如设置控件宽度、字体颜色、字体样式等。在后面的章节中，我们将了解如何在 Jade 中实现这一点。

等于（`=`）操作符只有在您绑定到注入到视图中的任何值时才需要。如果您想要指定一个硬编码的静态值，那么可以很容易地不使用等于操作符来设置，如下面的代码所示：

```js
doctype
html
    body
        h1 Jade App
        p This is Jade View
```

以下是一些使用 Jade 语法处理 HTML 特定场景的示例：

| 属性 | Jade | HTML |
| --- | --- | --- |
| 文本框 |

```js
input(type='text' name='txtName')
```

|

```js
<input type='text' name='txtName'/>
```

|

| 锚点标签 |
| --- |

```js
a(href='microsoft.com') Microsoft
```

|

```js
<a href="microsoft.com">Microsoft</a>
```

|

| 复选框 |
| --- |

```js
input(type='checkbox', checked)
```

|

```js
<input type="checkbox" checked="checked"/>
```

|

| 带样式属性的锚点 |
| --- |

```js
a(style = {color: 'green', background: 'black'})
```

|

```js
<a style="color:green;background:black"></a>
```

|

| 链接按钮 |
| --- |

```js
input(type='button' name='btn')
```

|

```js
<input type="button" name="btn"/>
```

|

你可以在 [`jade-lang.com/`](http://jade-lang.com/) 了解更多关于 Jade 语言的信息。

Jade 的框架也支持布局页面。布局页面包含网站的静态信息，这些信息大部分位于页眉、页脚或侧边栏中，而实际内容根据请求的页面而变化。在 ASP.Net Web 表单中，我们使用`<asp:ContentPlaceHolder>`标签定义主页面，该页面将渲染页面的内容引用到该主页面。在 ASP.NET MVC 中，这可以通过使用 Razor `@RenderBody`元素来实现。在 Jade 中，我们可以使用`block`关键字后跟块的名称来定义内容块。例如，以下是的`layout.jade`，其中包含`block contentBlock`声明，其中`block`表示子页面的内容渲染位置，`contentBlock`是要在子页面中定义的块的名称。在单个视图中也可以定义多个块。

以下是布局页面的内容：

```js
doctype html
html
  head
    title Jade App
  body
  block contentBlock
```

布局页面可以使用`extends`关键字后跟布局页面名称与`layout`页面一起使用。Jade 视图引擎会自动搜索具有该名称的页面，如果找到，则搜索块名称并在该位置放置内容。以下是使用布局页面`layout.jade`的子页面`index.jade`：

```js
extends layout
block contentBlock
        h1= appName
        p= message
```

输出将会如下所示：

![玉视引擎](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00105.jpeg)

#### Express 应用程序中的路由

我们已经学习了 EJS 和 Jade 视图引擎的基本知识。两者都提供类似的功能，但语法不同。在前面的示例中，我们发送了一个响应，指向一个特定的页面，在客户端渲染内容。

Express 框架提供了与 HTTP 方法相对应的多个方法，如`get`、`post`、`put`、`delete`等。我们可以使用`get`方法来获取一些内容，`post`来创建一个记录，`put`来更新，等等。页面可以位于`Views`文件夹内的任何地方，但是路由实际上定义了当在特定的 URL 路径上请求时必须加载哪个页面。

让我们在`Views/ejsviews/home`文件夹内创建一个名为`about.ejs`的 EJS 页面。

路由可以通过 Express 应用程序对象来定义，如下面的代码所示：

```js
expressApp.get("/About", function (req, res) {
    res.render("ejsviews/home/about");
});
```

当用户浏览到`http://localhost/About`时，会显示**关于**页面。

# 中间件

Node.js Express 还提供了一个特殊的路由方法`all()`，它没有映射到任何 HTTP 方法。但是，它用于在路径上加载中间件，而不管请求的 HTTP 方法是什么。例如，对`http://localhost/middlewareexample`进行 HTTP `GET`和`POST`请求将会执行下面代码中显示的相同的`all()`方法：

```js
expressApp.all('/middlewareexample', function (req, res) {
    console.log('Accessing the secret1 section ...');
});
```

就像在 .NET 中一样，我们有 OWIN 中间件可以链接到请求管道。同样，Node.js Express 中间件也可以链接，并且可以通过稍微修改函数签名来调用下一个中间件。以下是修改后的版本，在响应对象之后添加了 `next` 参数，为特定请求路径定义管道中的下一个中间件的处理器：

```js
expressApp.all('/middlewareexample', function (req, res, next) {
    console.log('Accessing the secret1 section ...');
    next();
});
```

例如，假设我们有两个中间件，第一个中间件只是将信息输出到控制台窗口，而第二个中间件则将 HTML 内容返回给客户端。以下是包含这两个中间件的 EJS 视图引擎的 `server.js` 文件：

```js
//Initialized http object
var http = require('http');
//adding express dependency
var express = require('express');

//creating express application
var expressApp = express();

expressApp.all('/middlewareexample', function (req, res, next) {
    console.log('Middleware executed now calling next middleware in the pipeline');
    next(); // pass control to the next handler
});
expressApp.all('/middlewareexample', function (req, res) {
    res.send("<html><body><div>Middleware executed</div></body></html>");    
});

//declared port
var port = process.env.port || 1337;

//Initialized http server object and use res.write() to send actual response content
var httpServer = http.createServer(expressApp);

//listening for incoming request
httpServer.listen(port);
```

现在当我们访问 URL 路径 `http://localhost/middlewareexample` 时，消息将在控制台打印，并在浏览器中呈现 HTML 内容：

![中间件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00106.jpeg)

以下是将在浏览器中呈现的 HTML 内容：

![中间件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00107.jpeg)

# MVC 与 Express 框架

几乎每个应用程序都由无数页面组成，而在主 `server.js` 中定义所有逻辑和路由既不实际也不易维护。在本节中，我们将了解如何使用 Express 框架实现 **模型-视图-控制器**（**MVC**）模式。我们将开发一个简单的应用程序，以了解如何创建控制器和数据服务，以及如何使用 Express 框架加载视图并注入模型。

## 模型-视图-控制器模式

模型-视图-控制器（MVC）是一种用于分离应用程序关注点的软件架构模式。模型表示包含属性以持有信息的实体，而控制器则用于将模型注入视图并加载视图。控制器还用于将模型存储在数据库中，而视图是呈现由控制器注入的模型的页面，并在需要时使用它。

### 创建控制器

我们将从创建一个简单的 `homeController` 开始，以渲染主页。让我们扩展上述开发的 EJS 视图引擎示例，并在项目的根目录下创建一个 `Controllers` 文件夹。在 `Controllers` 文件夹内，创建一个 `HomeController.js` 文件，并将以下代码片段放在那里：

```js
(function (homeController) {
    homeController.load = function (expressApp) {
        expressApp.get('/', function (req, res) {
            res.render("ejsviews/home/index", {appName: "EJS Application", message:"EJS MVC Implementation"})
        });
    };
})(module.exports);
```

在前面的代码中，有一个匿名 JavaScript 函数，它接受 `module.export` 对象，并在执行时将其绑定到 `homeController`。以这种方式实现的基本优点是，定义在 `homeController` 对象中的每个方法或属性都将可导出并可供调用对象访问。在前面的示例中，我们定义了一个 `load()` 方法，它定义了根路径（`/`）的路由并返回 **Index** 页面给客户端。

在主 `ejsserver.js` 文件中，我们可以使用控制器，如以下代码所示，通过使用 `require` 对象：

```js
//Initialized http object
var http = require('http');

//adding express dependency
var express = require('express');

//adding ejs locals
var ejsLocal = require('ejs-locals');

//creating express application
var expressApp = express();

//Add engine that supports master pages
expressApp.engine('ejs', ejsLocal);

//Set jade for Node.js application
expressApp.set('view engine', 'ejs');

//Initializing HomeController
var homeController = require('./Controllers/HomeContoller.js');
homeController.load(expressApp);

//declared port
var port = process.env.port || 1337;

//Initialized http server object and use res.write() to send actual response content
var httpServer = http.createServer(expressApp);

//listening for incoming request
httpServer.listen(port);
```

在前面的代码中，我们使用 `require` 对象添加了 `HomeController` 对象，并调用 `load()` 方法来定义路由，使得当网站运行时能够导航到索引页面。

### 创建数据服务

每个商业应用程序都涉及大量的 CRUD（创建、读取、更新、删除）操作。为了更好的设计，这些操作可以分别实现在数据服务对象中，所以如果多个控制器想要使用同一个服务，它们可以重复使用而不需要重复编写相同的代码。在本节中，我们将创建一个名为 `DataServices` 的文件夹，位于应用程序的根目录下，并在其中创建 `ProductService.js`。以下是 `ProductService.js` 的代码，它返回产品数组：

```js
(function(data){
    data.getProducts = function () {
        return [{
                name: 'Product1',
                price: 200,
            }, 
            {
                name: 'Product2',
                price: 500
            },
            {
                name: 'Product3',
                price: 1000
            }
        ];
    };
})(module.exports);
```

我们可以通过 `require` 对象在 `HomeController` 中使用这个 `ProductService`：

```js
(function (homeController) {
    var productService = require('../DataServices/ProductService');

    homeController.load = function (expressApp) {
        expressApp.get('/', function (req, res) {
            var products = productService.getProducts();
            res.render("ejsviews/home/index", { appName: "EJS Application", message: "EJS MVC Implementation", data: products });
        });
    };
})(module.exports);
```

以下是 `index.ejs` 文件，它遍历产品并显示产品名称和价格：

```js
<% layout('../layout.ejs') -%>
<h1><%= appName %></h1>

<p> <%= message %></p>

<div>

 <% data.forEach(function(product) { %>
   <li><%= product.name %> - <%= product.price %></li>
 <% }); %>

</div>
```

最后，输出结果如下：

![创建数据服务](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00108.jpeg)

# 在 Node.js 中访问 Microsoft SQL 服务器

Node.js 提供了不同的数据库驱动，可以作为 node 包添加。有 MongoDB 驱动、Microsoft SQL Server 驱动等等。我们将使用 Node.js 的 MS SQL 驱动来连接 Microsoft SQL 服务器数据库。要安装 `mssql`，您可以运行 `npm install mssql –save` 命令，或者从 NPM 包管理器窗口中添加，如下面的截图所示：

![在 Node.js 中访问 Microsoft SQL 服务器](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00109.jpeg)

### 提示

使用 MSSQL 驱动时，对于相应的 SQL 服务器实例应启用 TCP/IP。

## 从 Microsoft SQL 服务器数据库中读取记录

在 `DataService.js` 文件中，我们将添加 `getProducts()` 方法，它从 SQL Server 数据库加载产品列表。

以下是 `getProducts()` 方法，它接受回调函数，所以一旦从数据库中获取了产品列表，它就会在调用者的回调函数中传递：

```js
(function(data){
data.getRecords = function (callbackFn) {
        //loaded SQL object
        var sql = require('mssql');

        //database configuration attributes to connect
        var config = {
            user: 'sa',
            password: '123',
            server: 'ovais-pc', // You can use 'localhost\\instance' to connect to named instance 
            database: 'products'
        }

        var products = null;
        //Connect to SQL Server returns a promise and on successfull connection executing a query using Request object
        sql.connect(config).then(function () {
            new sql.Request().query('select * from products', function (err, recordset) {      
                callbackFn(recordset);        
            });
        });

     };
})(module.exports);
```

在前面的代码中，我们使用 `require` 对象初始化了 `sql` 对象。`Config` 变量包含连接属性，如 `username`、`password`、`server` 和 `database`。在调用 `sql connect()` 方法时传递这个属性。`Connect()` 方法返回一个 `then()` 承诺，通过它我们可以使用 `sql.Request()` 方法发起 SQL 查询请求。如果请求成功，我们将在 `recordset` 对象中获取结果集，并通过其回调函数返回给调用者。

以下是修改后的 `HomeController.js` 文件，它调用 `DataService` 的 `getRecords()` 方法，并将检索到的产品列表作为模型传递给索引视图：

```js
(function (homeController) {
    var productService = require('../DataServices/ProductService');

    homeController.load = function (expressApp) {
        expressApp.get('/', function (req, res) {
            var products = productService.getRecords(function (products) {
                console.dir(products);
                res.render("ejsviews/home/index", { appName: "EJS Application", message: "EJS MVC Implementation", data: products });
            });
        });
    };
})(module.exports);
```

以下是 `index.js` 文件，它遍历产品列表并显示产品名称和价格：

```js
<% layout('../layout.ejs') -%>
<h1><%= appName %></h1>
<p> <%= message %></p>

<table>
<th> 
<td> Product Name </td>
<td> Description </td>
<td> Price </td>
</th>
 <% data.forEach(function(product) { %>
  <tr> <td><%= product.Name %> </td> <td> <%= product.Description %> </td><td> <%= product.Price %> </td></tr>
 <% }); %>
</table>
```

## 在 Microsoft SQL 服务器数据库中创建记录

要在数据库中创建记录，我们可以定义 HTML 表单标签内的 HTML 输入元素，并在表单提交时通过在`HomeController.js`文件中定义`post`方法来发送 POST 请求：当表单提交时，可以使用`request.body`对象检索值。这是一个解析器，它解析 DOM 并创建一个包含表单标签下的元素的列表。我们可以像`req.body.txtName`这样访问它，其中`txtName`是 HTML 输入元素，`req`是请求对象。

Express 4.0 将`body-parser`对象解耦为一个单独的包，可以使用`npm install body-parser –save`命令单独下载，或者通过 NPM 包管理器窗口，如下面的屏幕截图所示：

![在 Microsoft SQL 服务器数据库中创建记录](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00110.jpeg)

在你的主`ejsserver.js`文件中，使用`require`对象添加`body-parser`，并通过调用`expressApp,use()`方法将其传递给`expressApp`对象：

```js
var bodyParser = require('body-parser');

expressApp.use(new bodyParser());
```

一旦添加了这些内容，我们就可以修改`HomeController.js`，并定义一个`POST`方法，一旦表单提交，该方法将被调用：

```js
    expressApp.post('/', function (req, res) {
            console.log(req.body.txtName);
           productService.saveProduct(req.body.txtName, req.body.txtDescription, req.body.txtPrice, function (result) {
                res.send("Record saved successfully");
            });
        });
```

```js
DataService.js file:
```

```js
data.saveProduct = function (name, description, price, callbackFn) {

        //loaded SQL object
        var sql = require('mssql');

        //database configuration attributes to connect
        var config = {
            user: 'sa',
            password: '123',
            server: 'ovais-pc', // You can use 'localhost\\instance' to connect to named instance 
            database: 'products'
        }

        //Connect to SQL Server returns a promise and on successfull connection executing a query using Request object
        sql.connect(config).then(function () {
            new sql.Request().query("INSERT into products (Name, Description, Price) values('"+ name +"', '"+ description+"',"+ price+")", function (err, recordset) {
                callbackFn(recordset);
            });
       });

    };
```

最后，这是包含`Name`、`Description`和`Price`字段的表单的`Index.ejs`视图：

```js
<form method="post">
<table>
<tr>
  <td> Product Name: </td>
  <td> <input type='text' name='txtName'  /> </td>
</tr>
<tr>
  <td> Description: </td>
  <td><input type='text' name='txtDescription'  /></td>
</tr>
<tr>
  <td> Price: </td>
  <td><input type='number' name='txtPrice' /></td>

</tr>
<tr>
<td> &nbsp; </td>
<td><input type="submit" value="Save" /> </td>
</tr>
</table>
</form>
```

要了解关于`mssql`节点包的更多信息，请使用这个链接：[`www.npmjs.com/package/mssql`](https://www.npmjs.com/package/mssql)。

# 总结

本章介绍了 Node.js 的基础知识以及如何使用它们来开发使用 JavaScript 的服务器端应用程序。我们了解到了两种视图引擎，EJS 和 Jade，以及如何使用它们。我们还学习了如何使用控制器和服务来实现 MVC 模式。最后，我们通过查看访问 Microsoft SQL 服务器数据库的示例，来了解如何执行数据库上的增删改查操作。在下一章中，我们将关注在大型应用程序中使用 JavaScript 的最佳实践。


# 第九章：使用 JavaScript 进行大规模项目

大型网络应用项目由多个模块组成。随着各种 JavaScript 框架的开发不断进步和提升，开发者在应用程序的展示或前端层频繁使用 JavaScript，而服务器端操作只在需要时执行。例如，当从服务器保存或读取数据，或进行其他数据库或后端操作时，向服务器发送 HTTP 请求，返回纯 JSON 对象并更新 DOM 元素。随着这些发展，应用程序的大部分前端代码都位于客户端。然而，当 JavaScript 最初被开发时，它的目标是用于执行一些基本操作，比如更新 DOM 元素或显示确认对话框等相对操作。JavaScript 代码主要存在于页面本身的`<script>`脚本标签中。然而，大规模应用程序包含许多代码行，在设计和架构前端时需要适当的关注。在本章中，我们将讨论一些概念和最佳实践，以帮助使应用程序前端更具可扩展性和可维护性。

# 在行动之前先思考

大规模应用通常包含许多 JavaScript 文件，合理地组织这些文件可以提高可见性。像 AngularJS、EmberJS 这样的 JavaScript 框架已经提供了适当的组织和指导，用于定义控制器、工厂和其他对象，同时也提供了使用它们的最佳实践。这些框架非常流行，并且已经符合了更高可扩展性和可维护性的需求。然而，在某些情况下，我们可能想严格依赖纯 JavaScript 文件，并为特定需求开发自己的自定义框架。为了认可这些情况，行业内已经采用了某些最佳实践，这些实践使得基于 JavaScript 的前端更加可维护和可扩展。

当我们在大型应用程序上工作时，我们需要思考应用程序的范围是什么。我们需要考虑应用程序如何容易地被扩展，以及如何快速地实现其他模块或功能。如果任何模块失败，它会影响应用程序的行为还是导致其他模块崩溃？例如，如果我们正在使用某个第三方 JavaScript 库，该库修改了它们某些方法签名。在这种情况下，如果我们在应用程序的每个地方都频繁使用第三方库，我们就必须在每个点上修改方法，而且不仅更改，而且测试也可能是一个繁琐的过程。另一方面，如果已经实现了一些 Facade 或包装器，那么我们只需要在一个地方进行更改，而不是到处更新。因此，设计应用程序架构或框架是一个深思熟虑的过程，但它使应用程序更加健壮和健康。

# 开发高度可扩展和可维护的应用程序

以下是我们应该考虑的因素，以创建高度可扩展和可维护的基于 JavaScript 的 Web 应用程序。

## 模块化

在大型的应用程序中，将所有内容写入一个 JavaScript 文件是不好的做法。尽管如此，即使你为不同的模块分离了不同的 JavaScript 文件，并通过脚本`<script>`标签引用它们，这也会使全局命名空间膨胀。应该进行适当的结构化，以将 JavaScript 文件保存在单独的模块文件夹中。例如，一个 ERP 应用程序包括几个模块。我们可以为每个模块创建单独的文件夹，并使用特定的 JavaScript 文件为特定的视图或页面提供某些功能。然而，公共文件可以存放在公共文件夹中。

以下是一个根据 ERP 模块来组织 JavaScript 文件的示例项目结构。每个模块都有一个`service`文件夹，其中包含一些用于服务器端读或写操作的文件，以及一个`Views`文件夹，用于在数据加载或任何控件事件触发后操作特定视图的 DOM 元素。`common`文件夹可能包含所有其他模块都会使用的助手工具和函数。例如，在控制台日志消息，或在服务器端发送 HTTP 请求，这些功能可以定义在公共 JavaScript 文件中，并且它们可以被服务或视图 JavaScript 文件使用：

![模块化](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00111.jpeg)

在前面的结构中，`Services`文件夹可以包含与调用某些 Web API 或 Web 服务执行数据库的**创建**、**检索**、**更新**、**和删除**（**CRUD**）操作相关的函数，而像`FIMain.js`这样的视图文件包含页面特定的函数。

为了保持 HTML 页面的整洁，将 JavaScript 文件与 HTML 页面分开是一个更好的方法。所以在之前的截图中，`FIMain.js`包含了与主页面对应的 JavaScript 函数，而`FIDashboard.js`包含了与仪表板页面对应的 JavaScript 函数，依此类推。

这些文件可以通过`<script>`脚本标签简单地添加，但在 JavaScript 世界中，直接在页面上添加 JavaScript 文件是不好的做法。模块可以通过实现模块模式在 JavaScript 中定义。然而，大多数开发者更愿意使用 RequireJS API 来定义模块，以使模块加载更简单，并提供更好的变量和函数定义范围。它与 CommonJS 系统等效，但由于其异步行为而受到推荐。它以异步方式加载 JavaScript 模块，使页面加载周期更快。

### 实现模块模式

模块模式是用于创建松耦合架构和使 JavaScript 代码片段独立于其他模块的最流行的设计模式。

模块就像.NET 类一样，可以有私有、受保护和使用公开的属性和方法，并为开发者提供控制，只暴露其他类需要的属性和方法。

在 JavaScript 中，模块模式可以通过**立即执行函数表达式**（**IIFE**）实现，该表达式立即执行并返回一个闭包。闭包实际上隐藏了私有变量和方法，并返回一个只包含公共方法和变量的对象，供其他模块访问。

以下是暴露了`logMessage()`方法的`Logger`模块，该方法调用一个私有`formatMessage()`方法来附加日期，并返回格式化后的消息，然后将其打印在浏览器的**控制台**窗口上：

```js
<script>
  var Logger= (function () {

    //private method
    var formatMessage = function (message) {
      return message + " logged at: " + new Date();
    }

    return {
      //public method
      logMessage: function (message) {
        console.log(formatMessage(message));
      }
    };

  })();

  Logger.logMessage("hello world");
</script>
```

在前面的代码中，`logMessage()`方法返回一个通过`Logger`命名空间调用的对象。

模块可以包含多个方法和属性，为了实现这种情况，让我们修改前面的示例，再添加一个显示警告消息的方法和一个访问日志名称的属性，并通过对象字面量语法暴露它们。对象字面量是另一种表示将方法和属性作为名称值对分离并用逗号分隔的绑定方式，提供了更清晰的表示。以下是修改后的代码：

```js
<script> 
  var Logger= (function () {
    //private variable
    var loggerName = "AppLogger";

    //private method
    var formatMessage = function (message) {
      return message + " logged at: " + new Date();
    }

    //private method
    var logMessage= function (message){
      console.log(formatMessage(message));
    }

    //private method
    var showAlert = function(message){
      alert(formatMessage(message));
    }

    return {

      //public methods and variable
      logConsoleMessage: logMessage,
      showAlertMessage: showAlert,
      loggerName: loggerName
    };

  })();

  Logger.logConsoleMessage("Hello World");
  Logger.showAlertMessage("Hello World");
  console.log(Logger.loggerName);
</script>
```

在前面的代码中，`logMessage()`和`showAlert()`将通过`logConsoleMessage()`和`showAlertMessage()`方法进行访问。

### 使用 RequireJS 对 JavaScript 代码进行模块化

RequireJS 中的模块是模块模式的扩展，其好处是不需要全局变量来引用其他模块。RequireJS 是一个 JavaScript API，用于定义模块并在需要时异步加载它们。它异步下载 JavaScript 文件，并减少整个页面加载的时间。

#### 使用 RequireJS API 创建模块

在 RequireJS 中，可以通过`define()`方法创建模块，并使用`require()`方法加载。RequireJS 提供了两种语法风格来定义模块，如下所示：

+   **使用 CommonJS 风格定义模块**：以下是在 CommonJS 风格中定义模块的代码片段：

    ```js
    define(function (require, exports, module) {
      //require to use any existing module
      var utility = require('utility');

      //exports to export values
      exports.example ="Common JS";

      //module to export values 
      module.exports.name = "Large scale applications";

      module.exports.showMessage = function (message) {
        alert(utility.formatMessage(message));
      }
    });
    ```

    前面的 CommonJS 风格语法使用了 RequireJS API 的`define()`方法，该方法接受一个函数。此函数接受三个参数：`require`、`exports`和`module`。后两个参数`exports`和`module`是可选的。但是，它们必须按照相同的顺序定义。如果你不使用`require`，只想通过`exports`对象导出一些功能，那么需要提供`require`参数。`require`参数用于导入使用`exports`或`module.exports`在其他模块中导出的模块。在前面的代码中，我们通过在调用`require`方法时指定`utility.js`文件的路径，添加了`utility`模块的依赖。添加任何依赖时，我们只需要指定路径以及 JavaScript 文件的名称，而不需要`.js`文件扩展名。文件由 RequireJS API 自动识别。我们可以通过`exports`或`module.exports`适当地导出其他模块需要使用的任何函数或变量。

+   **在 AMD 风格中定义模块**：以下是在 AMD 风格语法中定义模块的代码片段：

    ```js
    define(['utility'], function (utility) {
      return {
        example: "AMD",
        name: "Large scale applications",
        showMessage: function () {
          alert(utility.formatMessage(message));
        }
      }

    });
    ```

    AMD 风格语法将依赖项数组作为第一个参数。要使用 AMD 风格语法加载模块依赖项，你必须将它们定义在一个数组中。第二个参数接受`function`参数，它取模块名称，映射到依赖项数组中定义的模块，以便在函数体中使用。要导出变量或方法，我们可以通过对象字面量语法进行导出。

#### 启动 RequireJS

让我们通过一个简单的例子来了解如何在 ASP.NET 应用程序中使用 RequireJS。要在 ASP.NET Core 应用程序中使用 RequireJS API，你必须下载并将在`wwwroot/js`文件夹中放置`Require.js`文件。在下面的例子中，我们将编写一个`logging`模块，其中包含一些方法，如写入控制台、显示警告以及向服务器写入。

让我们在`wwwroot/js/common`文件夹中创建一个`Logging.js`文件，并写入以下代码：

```js
define(function () {
  return {
    showMessage: function (message) {
      alert(message);
    },
    writeToConsole: function (message) {
      console.log(message);
    },
    writeToServer: function (message) {
      //write to server by doing some Ajax request
      var xhr = new XMLHttpRequest();
      xhttp.open("POST", "http://localhost:8081/Logging?message="+message, true);
      xhttp.send();
    }
  }
});
```

以下是`Index.cshtml`页面的代码，当页面加载时会显示一个警告消息：

```js
<script src="img/require.js"></script>
<script>
  (function () {
    require(["js/common/logging"], function(logging){
      logging.showMessage("demo");
    });
  })();
</script>
```

我们还可以将前面的函数包装在`main.js`文件中，并通过脚本`<script>`标签启动它。有一个特殊的属性称为`data-main`，它是由 RequireJS 用作应用程序的入口点。

以下是位于`wwwroot/JS`文件夹中的`main.js`代码。因为`main.js`位于`wwwroot/js`文件夹中，所以路径将是`common/logging`：

```js
//Main.js
require(["common/logging"], function(logging){
  logging.showMessage("demo");
});
```

最后，我们可以使用脚本标签启动`main.js`，如下面的代码所示：

```js
<script data-main="~/js/main.js" src="img/require.js"></script>
```

以下是一个包含`Common`文件夹的示例项目结构，以存储常见的 JavaScript 文件；而`FI`和`HR`文件夹用于模块特定的 JavaScript 文件：

![启动 RequireJS](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00112.jpeg)

假设我们想要修改之前的例子，并在按钮的`click`事件上从输入控件传递消息。这可以通过为特定页面开发一个`view`模块并在其中注入`logging`模块来实现。

以下是要包含`input`和`button`元素的 HTML 标记：

```js
<div id="myCarousel" class="carousel slide" data-ride="carousel" data-interval="6000">
  <input type="text" id="txtMessage" />
  <button id="btnSendMessage" >Send Message</button>
</div>
```

下面的`view.js`文件通过读取`txtMessage`元素的值来调用`logging`模块的`sendMessage()`方法：

```js
define(['common/logging'], function(logging) {
  $('#btnSendMessage').on('click', function(e) {
    sendMessage();
    e.preventDefault();
  });
  function sendMessage(){
    var message= document.getElementById('txtMessage').value;
    logging.showMessage(message);
  }
  return {
    sendMessage: sendMessage
  };
});
```

当按钮被点击时，将显示一个警告消息。

## 事件驱动的消息传递

在前一部分，我们为 JavaScript 文件启用了模块化支持并将它们转换为模块。在大型应用程序中，我们不能仅仅依赖于在其他模块中注入模块，我们可能需要一些灵活性，通过某种发布/订阅模式调用某些模块的事件。我们已经在第七章中看到了发布/订阅模式，该模式维护一个注册事件（指向某些回调函数）的集中式列表，并通过发布者对象调用这些事件。这种模式在使模块之间的事件驱动消息传递变得非常实用，但还有一种更好的模式，即中介者模式，它是发布/订阅模式的一个超集。中介者模式更好，因为它允许发布者或中介者访问订阅对象的其他事件/方法，并允许中介者决定需要调用哪个方法或事件。

### 为模块之间的通信实现中介者模式

中介者将对象封装在集中式列表中并调用它们的方法。这个列表将所有对象（或模块）放在中央位置，从而允许它们之间改进的通信。

让我们通过一个实现中介者模式的实际例子来了解。中介者作为一个集中控制的对象，模块可以进行订阅或取消订阅。它提供了抽象方法，任何源订阅模块都可以调用这些方法与目标订阅模块进行通信。中介者持有一个集中式字典对象，根据某些键（或通常是名称）持有订阅对象，并根据订阅者传递的模块名称调用目标模块方法。在下面的例子中，我们有了`MediatorCore`（中介者）、`EmployeeRepository`（订阅者）和`HRModule`（订阅者）对象。我们将使用 RequireJS API 将 JavaScript 文件转换为模块。

下面的`MediatorCore` JavaScript 文件：

```js
//MediatorCore.js
define(function () {
  return {

    mediator: function () {
      this.modules = [];

      //To subscribe module
      this.subscribe = function (module) {
        //Check if module exist or initialize array
        this.modules[module.moduleName] = this.modules[module.moduleName] || [];

        //Add the module object based on its module name
        this.modules[module.moduleName].push(module);
        module.mediator = this;
      },

      this.unsubscribe = function (module) {
        //Loop through the array and remove the module
        if (this.modules[module.moduleName]) {
          for (i = 0; i < this.modules[module.moduleName].length; i++) {
            if (this.modules[module.moduleName][i] === module) {
              this.modules[module.moduleName].splice(i, 1);
              break;
            }
          }
        }
      },

      /* To call the getRecords method of specific module based on module name */
      this.getRecords = function (moduleName) {
        if (this.modules[moduleName]) {
          //get the module based on module name
          var fromModule = this.modules[moduleName][0];
          return fromModule.getRecords();
        }
      },

      /* To call the insertRecord method of specific module based on module name */
      this.insertRecord = function (record, moduleName) {
        if (this.modules[moduleName]) {
          //get the module based on module name
          var fromModule = this.modules[moduleName][0];
          fromModule.insertRecord(record);
        }
      },

      /* To call the deleteRecord method of specific module based on module name */
      this.deleteRecord = function (record, moduleName) {
        if (this.modules[moduleName]) {
          //get the module based on module name
          var fromModule = this.modules[moduleName][0];
          fromModule.deleteRecord(record);

        }
      },

      /* To call the updateRecord method of specific module based on module name */
      this.updateRecord = function (record, moduleName) {
        if (this.modules[moduleName]) {
          //get the module based on module name
          var fromModule = this.modules[moduleName][0];
          fromModule.updateRecord(record);

        }
      }

    }
  }
});
```

```js
EmployeeRepository that contains the concrete implementation of the abstract methods defined in the mediator:
```

```js
//EmployeeRepository.js
define(function () {
  return {

    //Concrete Implementation of Mediator Interface
    EmployeeRepository: function (uniqueName) {
      this.moduleName = uniqueName;
      //this reference will be used just in case to call some other module methods
      this.mediator = null;

      //Concrete Implementation of getRecords method
      this.getRecords = function () {
        //Call some service to get records

        //Sample text to return data when getRecords method will be invoked
        return "This are test records";

      },
      //Concrete Implementation of insertRecord method
      this.insertRecord = function (record) {
        console.log("saving record");
        //Call some service to save record.
      },

      //Concrete Implementation of deleteRecord method
      this.deleteRecord = function (record) {
        console.log("deleting record");
        //Call some service to delete record
      }

      //Concrete Implementation of updateRecord method
      this.updateRecord = function (record) {
        console.log("updating record");
        //Call some service to delete record
      }

    }
  }
});
```

`EmployeeRepository`在初始化时接收一个名称参数，并定义了一个中介变量，该变量在注册中介时可以设置。这样提供的目的是，如果`EmployeeRepository`想要调用其他模块或订阅模块的仓库，就可以这样做。我们可以创建多个仓库，例如为`HRModule`创建`RecruitmentRepository`和`AppraisalRepository`，并在需要时使用它们。

以下是`HRModule`的代码，通过中介调用`EmployeeRepository`：

```js
//HRModule.js
define(function () {
  return {
    HRModule: function (uniqueName) {
      this.moduleName = uniqueName;
      this.mediator = null;
      this.repository = "EmployeeRepository";

      this.getRecords = function () {
        return this.mediator.getRecords(this.repository);
      },

      this.insertRecord = function (record) {
        this.mediator.insertRecord(record, this.repository);
      },

      this.deleteRecord = function (record) {
        this.mediator.deleteRecord(record, this.repository);
      }

      this.updateRecord = function (record) {
        this.mediator.updateRecord(record, this.repository);
      }

    }
  }
});
```

现在，我们将注册`HRModule`和`EmployeeRepository`到中介，并调用`HRModule`方法以执行 CRUD 操作。

以下是`HRView.js`的代码，用于捕获表单上按钮的`click`事件，并在按钮被点击时调用`getRecords()`方法：

```js
//HRView.js
define(['hr/mediatorcore','hr/employeerepository','hr/hrmodule'], function (mediatorCore, employeeRepository, hrModule) {
  $('#btnGetRecords').on('click', function (e) {
    getRecords();
    e.preventDefault();
  });
  function getRecords() {
    var mediator = new mediatorCore.mediator();
    var empModule = new hrModule.HRModule("EmployeeModule");
    mediator.subscribe(empModule);

    var empRepo = new employeeRepository.EmployeeRepository("EmployeeRepository");
    mediator.subscribe(empRepo);

    alert("Records: "+ empModule.getRecords());
  }
  return {
    getRecords: getRecords
  };
});
```

以下是使用 RequireJS API 引导`HRView.js`文件的`main.js`文件：

```js
//main.js
require(["./hrview"], function(hr){
});
```

最后，我们可以在 ASP.NET 的`Index.cshtml`页面上使用上述`Main.js`模块，如下所示：

```js
//Index.cshtml

@{
  ViewData["Title"] = "Home Page";
}
<script data-main="js/main.js"  src="img/require.js"></script>

<div id="myCarousel" class="carousel slide" data-ride="carousel" data-interval="6000">
  <input type="text" id="txtMessage" />
  <button id="btnGetRecords" >Send Message</button>
</div>
```

以下是显示模块如何相互通信的逻辑图：

![模块间通信的中介者模式实现](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00113.jpeg)

## 封装复杂代码

开发高度可扩展和可维护应用程序的另一个核心原则是使用包装器，并将复杂代码封装到更简单的接口中。这可以通过实现一个外观模式来完成。

外观模式（Facade Pattern）用于简化复杂代码，通过暴露一个方法并隐藏所有复杂代码在 Facade 对象内部。例如，有多种方法和 API 可用于执行 Ajaxified 操作。可以使用一个普通的`XmlHttpRequest`对象发出 Ajax 请求，或者使用 jQuery，使用`$.post()`和`$.get()`方法非常容易。在 AngularJS 中，可以使用其自己的`http`对象来调用服务等等。这些类型的操作可以通过封装，在内部 API 更改时，或者当你决定使用另一个更好的 API 时受益；修改工作量远小于更改所有使用过的地方。使用外观模式，你只需要在 Facade 对象中修改一次，并节省在所有使用过的地方更新它的时间。

使用外观模式的另一个优点是，它通过将一串代码封装到一个简单的方法中，减少了开发工作量，并使消费者容易使用。外观模式通过最小化调用特定功能所需的代码行数，减少了开发工作量。要了解更多关于外观模式的信息，请参考第七章，《JavaScript 设计模式》。

## 生成文档

适当的文档可以提高你的应用程序的可维护性，并使开发者在需要时或定制应用程序时更容易参考。市场上有很多文档生成器可供选择。JSDoc 和 YUIDoc 是非常流行的 JavaScript 文档生成器，但在本节中，我们将使用 JSDoc3，它不仅可以生成文档，还可以为你的自定义 JavaScript 模块启用 intellisense，以便在开发过程中提供便利。

JSDoc 是一个类似于 JavaDoc 和 PHPDoc 的 API。可以直接在 JavaScript 代码中添加注释。它还通过 JSDoc 工具提供了文档网站的生成。

### 在 ASP.NET Core 中安装 JSDoc3

JSDoc3 可以作为一个 Node 包添加，我们还可以使用 Gulp 任务运行器来生成文档。要将 JSDoc3 添加到你的 ASP.NET Core 项目中，你可以首先在由 Node 使用的`package.json`文件中添加一个条目。这个条目必须在开发依赖项中完成：

![在 ASP.NET Core 中安装 JSDoc3](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00114.jpeg)

前一张截图中定义的第一个开发依赖是 Gulp，它用于创建任务，而`gulp-jsdoc3`是实际的文档生成器，当你运行那个任务时，它会生成 HTML 网站。

任务可以定义如下：

```js
/// <binding Clean='clean' />
"use strict";

var gulp = require("gulp"),
jsdoc = require("gulp-jsdoc3");

var paths = {
  webroot: "./wwwroot/"
};

paths.appJs = paths.webroot + "app/**/*.js";

gulp.task("generatedoc", function (cb) {
  gulp.src(['Readme.md', paths.appJs], { read: false })
  .pipe(jsdoc(cb));
});
```

```js
generatedoc, in which we are reading the files placed at wwwroot/app/**/*.js and generating documentation. The jsdoc object takes the configuration defaults to generate documentation. To pass the default configuration attributes, we can just specify the cb parameter injected in the function level by Gulp. When you run this generatedoc task from the task runner in Visual Studio, it will add a docs folder at the root path of your web application project. As in ASP.NET Core, we already know that all static content should reside in the wwwroot folder, and to access it from browser, simply drag and drop this folder in the wwwroot folder and access it by running your website.
```

#### 添加注释

为了生成文档，我们需要用注释注释我们的代码。提供的注释越多，生成的文档就会越好。注释可以通过`/**`作为开始标签和`*/`作为结束标签来添加：

```js
/** This method is used to send HTTP Get Request **/
function GetData(path) {
  $.get(path, function (data) {
    return data;
  })
}
```

如果函数是构造函数，你可以在注释中指定`@constructor`，以便向读者传达更多意义：

```js
/** This method is used to send HTTP Get Request
   @constructor
*/
function GetData(path) {
  $.get(path, function (data) {
    return data;
  })
}
```

函数接收参数，这可以通过在注释中使用`@param`来表示。以下是同一个函数，它接收某个服务的实际路径作为参数来检索记录：

```js
/** This method is used to send HTTP Get Request 
  @constructor
  @param path – Specify URI of the resource that returns data
*/
function GetData(path) {
  $.get(path, function (data) {
    return data;
  })
}
```

当你运行你的应用程序时，它将按如下方式显示文档：

![添加注释](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00115.jpeg)

我们已经看到了使用 JSDoc3 生成文档是多么简单。这不仅有助于理解代码，而且在开发过程中通过提供 intellisense，也有助于开发者。要了解更多关于 JSDoc3 的信息，请参考[`usejsdoc.org/`](http://usejsdoc.org/)。

## 部署优化

```js
gulp, gulp-concat, gulp-cssmin, and gulp-uglify. The following is the description of each module:
```

| ``` |
| --- |
| ``` |
| ``` |
| ``` |
| ``` |
| ``` |

以下是可以用于压缩 JavaScript 和 CSS 文件的示例`gulpfile.js`：

```js
/// <binding Clean='clean' />
"use strict";

//Adding references of gulp modules
var gulp = require("gulp"),
rimraf = require("rimraf"),
concat = require("gulp-concat"),
cssmin = require("gulp-cssmin"),
uglify = require("gulp-uglify");

//define root path where all JavaScript and CSS files reside
var paths = {
  webroot: "./wwwroot/"
};

/* Path where all the non-minified JavaScript file resides. JS is the folder and ** is used to handle for sub folders */
paths.js = paths.webroot + "js/**/*.js";

/* Path where all the minified JavaScript file resides. JS is the folder and ** is used to handle for sub folders */
paths.minJs = paths.webroot + "js/**/*.min.js";

/* Path where all the non-minified CSS file resides. Css is the main folder and ** is used to handle for sub folder */
paths.css = paths.webroot + "css/**/*.css";

/* Path where all the minified CSS file resides. Css is the main folder and ** is used to handle for sub folder */
paths.minCss = paths.webroot + "css/**/*.min.css";

/* New JavaScript file site.min.js that contains all the compressed and merged JavaScript files*/
paths.concatJsDest = paths.webroot + "js/site.min.js";

/* New CSS file site.min.css that will contain all the compressed and merged CSS files */
paths.concatCssDest = paths.webroot + "css/site.min.css";

//to delete site.min.js file
gulp.task("clean:js", function (cb) {
  rimraf(paths.concatJsDest, cb);
});

//to delete site.min.css file
gulp.task("clean:css", function (cb) {
  rimraf(paths.concatCssDest, cb);
});

/* To merge, compress and place the JavaScript files into one single file site.min.js */
gulp.task("min:js", function () {
  return gulp.src([paths.js, "!" + paths.minJs], { base: "." })
  .pipe(concat(paths.concatJsDest))
  .pipe(uglify())
  .pipe(gulp.dest("."));
});

/* to merge, compress and place the CSS files into one single file site.min.css */
gulp.task("min:css", function () {
  return gulp.src([paths.css, "!" + paths.minCss])
  .pipe(concat(paths.concatCssDest))
  .pipe(cssmin())
  .pipe(gulp.dest("."));
});
```

```js
`clean:js`: This removes the `site.min.js` file`clean:css`: This removes the `site.min.css` file`min:js`: This merges all the files specified in `paths.js` and `paths.minJs`, minifies them using `uglify()`, and finally creates the `site.main.js` file`min:css`: This merges all the files specified in `paths.css` and `paths.minCss`, minifies them using `cssmin()`, and finally creates the `site.main.css` file
```

在 Visual Studio 2015 中，你可以使用**任务运行器浏览器**运行这些任务，并将它们与`build`事件绑定：

![部署优化](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00117.jpeg)

以下是你可以为特定`build`事件关联的选项：

![部署优化](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00118.jpeg)

前一个屏幕截图显示了将`clean:js`任务与**清理**构建事件绑定的步骤。因此，无论何时你清理你的项目，它都会运行`clean:js`并删除`site.min.js`文件。

# 总结

在本章中，我们讨论了几个关于如何结构化基于 JavaScript 的项目并将其划分为模块以提高可扩展性和可维护性的概念。我们还看到了如何有效地使用中介者模式（mediator pattern）来提供模块间的通信。文档也扮演着重要的角色并增加了可维护性，我们使用了 JSDoc3，这是最流行的 JavaScript 文档 API 之一，它帮助开发者参考并理解 JavaScript 的功能。最后，我们讨论了如何通过将 JavaScript 文件压缩和合并成一个最小化的 JavaScript 文件来优化应用程序的加载时间以提高性能。在下一章中，我们将讨论如何测试和调试 JavaScript 应用程序以及可用的工具，以便有效地解决问题。


# 第十章：测试和调试 JavaScript

在每一个软件生命周期中，测试和调试都扮演着重要的角色。彻底的测试可以使软件无懈可击，而优秀的调试技术不仅可以帮助解决问题，还能帮助准确地识别并修复问题。

测试是创建任何健壮应用程序的核心本质。然而，应用程序为了达到特定的目标，采用了不同的实践和框架，根据应用程序的性质，架构也会有所不同。因此，有时对于开发者来说，测试客户端代码会变得困难，例如，如果一个应用程序在其页面中包含一些 JavaScript 代码，如内联事件处理程序，这会使它与页面紧密耦合。另一方面，即使将 JavaScript 代码模块化，也会带来一些测试套件限制，并使应用程序的测试过程更难以执行。

调试是查找和修复应用程序错误的过程。它是软件开发中最重要的核心技能之一。如果开发者能够熟练掌握调试工具并了解调试的方方面面，他们就可以快速识别根本原因并开始修复错误。调试是任何软件开发生命周期中的基本过程。无论应用程序是复杂的还是简单的，调试都起着重要的作用，以追踪和修正错误。通过设置断点并逐阶段地执行程序流，调试可以帮助开发者中断程序执行并识别程序流程。此外，几乎所有的调试工具都提供其他有用的信息，例如观察程序中正在使用的变量或对象的状态，并在调试生命周期的每个阶段观察它们。

# 测试 JavaScript 代码

通常，网络应用程序会经历不同类型的测试，例如**用户界面**（**UI**）测试，通过向表单输入某些内容并验证应用程序的行为来检查 UI 的功能。这种类型的测试主要是手动完成或通过自动化测试工具完成。另一种测试类型是**压力测试**，主要用于检查应用程序的性能，通过对应用程序施加一些负载来进行。简单地说，它可以是登录应用程序的许多用户或通过自动化例程执行某些操作的示例，以测试应用程序的行为。还有几种其他类型的测试，但确保应用程序功能并验证应用程序是否符合要求的最重要的测试类型是单元测试。在本节中，我们将讨论使用 Jasmine（一个流行的 JavaScript 单元测试框架）对 JavaScript 代码进行单元测试，并使用 Karma 和 Grunt 在 ASP.NET 应用程序中使用 Visual Studio 2015 IDE 执行测试用例。

## 单元测试

单元测试是一种测试模块中个别单元的方法，包括相关的数据和程序，以验证应用程序的功能符合要求。单元测试由开发者完成，它允许开发者测试应用程序的每个用例，以确保它满足需求并按预期工作。

单元测试的基本优势在于，它将应用程序的每个部分分离成更小的单元，并帮助开发者在开发周期初期集中精力和识别错误。单元测试是任何应用程序承受的第一次测试，它允许测试人员和开发人员在**用户验收测试**（**UAT**）阶段发布应用程序。

### 编写单元测试

为了测试 JavaScript 代码，有许多测试套件可供选择。最受欢迎的是 Jasmine，Mocha 和 QUnit。在本章中，我们将使用 Jasmine 与 Karma 和 Grunt 一起使用。

#### Jasmine

Jasmine 是一个用于测试 JavaScript 代码的行为驱动开发框架。它提供了一些函数，如`it()`，`describe()`，`expect()`等，以编写 JavaScript 代码的测试脚本。这个框架的基本优势在于它非常容易理解，并帮助用非常简单的代码行编写测试 JavaScript 代码。

例如，考虑以下 JavaScript 代码，它计算作为参数传递的两个数字的和：

```js
(function () {
  var addTwoNumbers = function (x, y) {
    return x+y;
  };

})();
```

前面函数的测试用例将类似于以下内容：

```js
describe('Calculator', function () {
  it('Results will be 20 for 10 + 10', function () {
    expect(addTwoNumbers(10,10)).toBe(20);
  });
});
```

#### Karma

Karma 是一个可以与 Jasmine、Mocha 等其他测试框架集成的 JavaScript 测试运行器。它通过提供一个模拟的测试环境并加载执行测试 JavaScript 代码的浏览器，来执行通过 Jasmine 或其他测试框架定义的测试用例。Karma 配置文件被称为`Karma.config.js`。一旦执行测试，结果将显示在控制台窗口中。

#### Grunt

Grunt 相当于 Gulp。它用于执行任务，如 CSS 文件或 JavaScript 文件的压缩，多个 JavaScript 文件的合并和合并等。Grunt 有数百个插件可用于自动化特定任务。与前面章节中使用的 Gulp 不同，我们将使用 Grunt，看看它与 Karma（测试运行器）和 Jasmine（测试套件）一起提供了什么。Grunt 和 Gulp 都是知名的开发任务运行器。在这里使用 Grunt 的原因是为了了解另一个同样知名且受 Visual Studio 2015 支持的 JavaScript 任务运行器，并讨论它提供以使用 Karma 和 Jasmine 进行测试的包。

### 使用 Jasmine、Karma 和 Grunt 开发单元测试

在本节中，我们将开发一个简单的单元测试，以展示如何在 ASP.NET Core 应用程序中使用 Jasmine、Karma 和 Grunt 框架进行单元测试。首先，从 Visual Studio 2015 创建一个 ASP.NET Core 应用程序。

#### 添加包

打开你 ASP.NET Core 应用程序中的`package.json`文件，添加如`grunt`、`grunt-karma`、`karma`、`karma-phantomjs-launcher`、`karma-jasmine`、`karma-spec-reporter`和`karma-cli`等包，如下所示：

![添加包](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00119.jpeg)

以下表格显示了每个包的描述：

| 包名称 | 描述 |
| --- | --- |
| `grunt` | 这配置和运行任务 |
| `grunt-karma` | 这是用于 Karma 测试运行器的 Grunt 插件 |
| `karma` | 这是 JavaScript 的测试运行器 |
| `karma-phantomjs-launcher` | 这是 Karma 插件，用于启动 PhantomJS 浏览器 |
| `karma-jasmine` | 这是 Karma 插件，用于 Jasmine 测试套件 |
| `karma-spec-reporter` | 这是 Karma 插件，用于将测试结果报告到控制台 |
| `karma-cli` | 这是 Karma 命令行界面 |

#### 添加 Grunt 文件

在你的 ASP.NET 应用程序中添加`Gruntfile.js`以定义 Grunt 任务。`Gruntfile.js`是所有任务配置的主文件。在 Visual Studio 的**任务运行器浏览器**窗口中可以看到配置的任务。

##### 添加 Karma 规格说明

`Gruntfile.js`文件提供了主要的`initConfig()`方法，在 Grunt 加载时调用。这是定义 Karma 规格说明的起点。

以下是在`initConfig()`方法内定义的 Karma 规格说明：

```js
grunt.initConfig({
  karma: {
    unit: {
      options: {
        frameworks: ['jasmine'],
        singleRun: true,
        browsers: ['PhantomJS'],
        files: [
          './wwwroot/js/**/*.js',
          './wwwroot/tests/**/*.test.js'

        ]
      }
    }
  }
});
```

在前面的脚本中，我们首先指定了一个 Karma 的目标平台。在`karma`内部，我们将指定用于运行单元测试的单元。在`unit`内部，我们可以定义一些配置属性，如`frameworks`、`singleRun`、`browsers`和`files`：

+   `frameworks`：这是一个我们要使用的测试框架数组。在这个练习中，我们使用了 Jasmine。然而，也可以使用其他框架，如 Mocha 和 QUnit。

    ### 提示

    请注意，在使用 Karma 中的任何框架时，必须使用**Node 包管理器**（**NPM**）单独安装该框架的附加插件/库。

+   `singleRun`：如果这个设置为`true`，Karma 将开始捕获配置的浏览器并在这些浏览器上执行测试。测试完成后，它会顺利退出。

+   `browsers`：这是一个用逗号分隔的值定义多个浏览器的数组。在我们的示例中使用了 PhantomJS，它是一个无头浏览器，在后台运行测试。Karma 支持其他浏览器，如 Chrome、Firefox、IE 和 Safari，这些可以通过这个属性进行配置。

+   `files`: 这里包含所有的测试文件、源文件和依赖。例如，如果我们正在测试脚本中使用 jQuery，或者原始源代码，我们也可以添加这个库的路径。在前面的配置中，我们使用了通配符来加载`js`文件夹下定义的所有源文件，以及`tests`文件夹下带有`test.js`后缀的测试文件。

Karma 配置中还可以使用更多的属性，可以在这里参考：

[`karma-runner.github.io/0.13/config/configuration-file.html`](http://karma-runner.github.io/0.13/config/configuration-file.html)

##### 加载 npm 任务

为了加载 Karma 测试运行工具，我们需要在`Gruntfile.js`中指定它，在前面的配置之后，如下所示：

```js
grunt.loadNpmTasks('grunt-karma');
```

##### 注册任务

最后，我们将向注册任务中添加 Grunt 任务。第一个参数是任务名称，它将出现在 Visual Studio 中的**任务运行器资源管理器**中，第二个参数接受一个数组以执行多个任务：

```js
grunt.registerTask('test', ['karma']);
```

#### 源 JavaScript 文件

在这个例子中，我们有一个`product.js`文件，它包含一个`saveProduct()`方法，该方法将在点击**保存**按钮的事件上被调用。

将此文件添加到`wwwroot/js`文件夹路径中：

```js
window.product = window.product || {};

(function () {
  var saveProduct = function () {
    var prodCode = document.getElementById('txtProdCode').value;
    var prodUnitPrice = document.getElementById('txtProdUnitPrice').value;
    var prodExpiry = document.getElementById('txtProdExpiry').value;
    var prodQuantity = document.getElementById('txtProdQuantity').value;
    var totalPrice = prodUnitPrice * prodQuantity;
    document.getElementById('totalAmount').innerHTML = totalPrice;
  };

  window.product.init = function () {
    document.getElementById('save').addEventListener('click', saveProduct);
  };

})();
```

```js
saveProduct() method that reads the HTML elements and calculates the total price based on the quantity and unit price entered. On the page initialization, we will register the Save button's click event handler that calls the saveProduct() method and calculate the total price.
```

### 提示

建议将你的 JavaScript 代码与 HTML 标记分开。

### 添加单元测试脚本文件

在这里，我们将在`wwwroot/tests`文件夹下添加另一个 JavaScript 文件，并将其命名为`product.test.js`。在编写测试时，可以添加`*.test.js`后缀以使其唯一标识，并将其与源 JavaScript 文件分开。

以下是`product.test.js`的代码：

```js
describe('Product', function () {

  // inject the HTML fixture for the tests
  beforeEach(function () {
    var fixture = '<div id="fixture">'+
      '<input id="txtProdCode" type="text">' +
      '<input id="txtProdExpiry" type="text">' +
      '<input id="txtProdUnitPrice" type="text">' +
      '<input id="txtProdQuantity" type="text">' +
      '<input id="save" type="button" value="Save">' +
      'Total Amount: <span id="totalAmount" /></div>';

    document.body.insertAdjacentHTML(
      'afterbegin',
      fixture);
  });

  // remove the html fixture from the DOM
  afterEach(function () {
    document.body.removeChild(document.getElementById('fixture'));
  });

  // call the init function of calculator to register DOM elements
  beforeEach(function () {
    window.product.init();
  });

  it('Expected result should be 0 if the Unit price is not valid', function () {
    document.getElementById('txtProdUnitPrice').value = 'a';
    document.getElementById('txtProdQuantity').value = 2;
    document.getElementById('save').click();
    expect(document.getElementById('totalAmount').innerHTML).toBe('0');
  });

  it('Expected result should be 0 if the Product Quantity is not valid', function () {
    document.getElementById('txtProdUnitPrice').value = 30;
    document.getElementById('txtProdQuantity').value = 'zero';
    document.getElementById('save').click();
    expect(document.getElementById('totalAmount').innerHTML).toBe('0');
  });

});
```

Jasmine 框架提供了一些特定的关键字来定义在特定条件下运行的特定块，如下所示：

+   `describe()`：这是一个全局 Jasmine 函数，包含两个参数：字符串和函数。字符串是要测试的功能名称。函数包含实际实现 Jasmine 套件的代码，并包含单元测试的逻辑。

+   `it()`：在这里，通过调用全局 Jasmine 函数`it()`定义规格。这也需要字符串和函数，其中它包含实际的单元测试名称和函数块包含实际的代码逻辑以及预期结果。

+   `expect()`：可以使用`expect()`函数指定`it()`函数内定义的某些值的预期结果。这还与一个匹配函数（如`toBe()`或`not.toBe()`）相链式调用，以匹配或取消匹配预期值。

在.NET 中，它等效于**准备**、**行动**和**断言**模式。在这里，准备用于初始化对象并设置传递给测试方法的数据的值。行动模式实际调用测试方法，断言验证测试方法如预期行为。

### 运行测试任务

运行这些任务很简单，它可以通过 Visual Studio 2015 中的**任务运行器**窗口运行。以下是显示`Gruntfile.js`中定义的任务的**任务运行器**窗口截图：

![运行测试任务](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00120.jpeg)

当我们运行测试任务时，它会显示类似以下输出：

![运行测试任务](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00121.jpeg)

在我们的`product.test.js`测试脚本中，有两个任务。一个是检查传递字符串值到两个元素中的一个（如`txtProdUnitPrice`和`txtProdQuantity`）是否会返回`0`。由于我们的`product.js`文件没有处理这个条件，它会给出一个错误。

为了解决这个问题，我们将修改我们的`product.js`，并添加这两行以处理此逻辑，检查值是否为数字：

```js
prodUnitPrice = isNaN(prodUnitPrice) ? 0 : prodUnitPrice;
prodQuantity = isNaN(prodQuantity) ? 0 : prodQuantity;
```

现在，当我们再次运行我们的测试时，我们将得到以下输出：

![运行测试任务](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00122.jpeg)

在前一个示例中，我们在`product.test.js`文件的`beforeEach()`函数内定义了 HTML 标记。对于简单的应用程序，重新定义 HTML 标记作为测试用例并使用它们来执行测试可能不是一个繁琐的过程。然而，大多数 Web 应用程序都使用一些客户端框架，如 Knockout、AngularJS 等，这些框架将 HTML 视图中的控件绑定到 ViewModel，这个 ViewModel 负责读取或写入控件值。

在以下示例中，我们将使用实现 Model-View-ViewModel 模式的 Knockout JavaScript 库，并了解如何以这种方式编写单元测试。

### 使用 Knockout 实现模型-视图-视图模型并运行测试

**模型-视图-视图模型**（**MVVM**）是构建用户界面的设计模式。它分为三部分，如下面的图所示：

![使用 Knockout 和运行测试实现 Model-View-ViewModel](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00123.jpeg)

这三个部分如下所述：

+   **模型**：这包含调用后端服务并通过与持久存储通信来保存或检索数据的后台逻辑。

+   **视图模型**：这包含视图特定的操作和数据。它表示与视图元素绑定的视图模型。例如，包含一些 HTML 元素的表单将有一个 ViewModel，这是一个包含一些要与这些控件绑定数据的属性的对象。

+   **视图**：这是用户与之交互的用户界面。它显示来自 ViewModel 的信息，在 ViewModel 上引发事件，并在 ViewModel 更改时更新它。

让我们使用**Knockout** JavaScript 库按照以下步骤实现 MVVM 模式。

#### 添加 Knockout 包

首先，让我们通过`bower.json`在你的 ASP.NET Core 应用程序中添加 Knockout.js。可以通过在`bower.json`文件的依赖项部分添加条目来实现，Visual Studio 会自动下载包并将其放置在`wwwroot/lib/knockout`文件夹中。

以下语句可以在`bower.json`文件中添加：

```js
"knockout": "3.4.0",
```

#### 添加 ProductViewModel

`ProductViewModel`包含产品代码、单价、数量、到期日和总金额等属性。以下是`ProductViewModel.js`的代码片段：

```js
var ProductViewModel = function () {

  this.prodCode = ko.observable('');
  this.prodUnitPrice = ko.observable(0);
  this.prodQuantity = ko.observable(0);
  this.prodExpiry = ko.observable('');
  this.prodTotalAmount =0;

  ko.applyBindings(this);

  this.saveProduct=function(){
    var unitPrice = this.prodUnitPrice();
    var quantity = this.prodQuantity();
    var total = unitPrice * quantity;
    this.prodTotalAmount = total;

    //call some service to save product
  }

};
```

```js
ProductViewModel class that contains a few properties, each property is assigned to ko.observable().
```

`ko`基本上是提供一种补充方式的 Knockout 对象，将对象模型与视图链接起来，其中`ko.observable()`是一个 Knockout 函数，使 Model 属性变得可观察并与视图数据同步。这意味着当 ViewModel 属性值发生变化时，视图也会更新；当控件值被修改时，ViewModel 属性也会更新。

```js
0 in the following statement will set the control value 0 when the control binding is done:
```

```js
this.prodUnitPrice = ko.observable(0)
```

`ko.applyBindings()`实际上激活 Knockout 以执行 Model 属性与 View 元素的绑定。

#### 添加产品视图

Knockout 提供了一种非常合适的方式来将 ViewModel 属性绑定到控件元素上。绑定包括两部分，名称和值，由冒号分隔。为了将 ViewModel 与输入元素绑定，我们可以使用 data-bind 属性，并指定值名称后跟`:`和 ViewModel 的属性名称。每个控件都有一组特定的属性，可以根据需要进行元素绑定。

例如，以下是如何使用文本名称将`span`元素绑定到视图模型属性的示例：

```js
Product code is: <span data-bind="text: prodCode"></span>
```

以下是产品视图的修改版本：

```js
<body>
  <div>
    <label> Product Code: </label>
    <input type="text" data-bind="value: prodCode" />
  </div>
  <div>
    <label> Product Unit Price: </label>
    <input type="text" data-bind="value: prodUnitPrice" />
  </div>
  <div>
    <label> Product Expiry: </label>
    <input type="text" data-bind="value: prodExpiry" />
  </div>
  <div>
    <label> Product Quantity: </label>
    <input type="text" data-bind="value: prodQuantity" />
  </div>
  <div>
    <input id="btnSaveProduct" type="button" value="Save Product" />
  </div>
  <script src="img/knockout.js"></script>
  <script src="img/ProductViewModel.js"></script>
  <script>
    (function () {
      var prod = new ProductViewModel();
      document.getElementById("btnSaveProduct").onclick = function () { prod.saveProduct(); };
    })();
  </script>
</body>
```

这就是我们在产品视图中配置 Knockout 所需的所有内容。当点击`btnSaveProduct`按钮时，它会计算总金额并调用产品服务以保存记录。

#### 修改测试配置

以下是之前创建的`Gruntfile.js`的修改版本。我们在`files`数组中添加了`ProductViewModel.js`和 Knockout 依赖项：

```js
/*
This file in the main entry point for defining grunt tasks and using grunt plugins.
*/
module.exports = function (grunt) {
  grunt.initConfig({
    karma: {
      unit: {
        options: {
          frameworks: ['jasmine'],
          singleRun: true,
          browsers: ['PhantomJS'],
          files: [
            './wwwroot/lib/knockout/dist/knockout.js',
            './wwwroot/js/ProductViewModel.js',
            './wwwroot/test/**/product.test.js'
          ]
        }
      }
    }
  });

  grunt.loadNpmTasks('grunt-karma');
  grunt.registerTask('test', ['karma']);
};
```

#### 修改产品测试脚本

由于我们不直接依赖 HTML 视图，因此可以通过产品视图模型来测试我们的单元测试用例。以下是未定义任何固定装置的 `product.test.js` 修改版本：

```js
describe('Product', function () {

  it('Expected Total Amount should be 600', function () {
    var product = new ProductViewModel();
    product.prodQuantity(3);
    product.prodUnitPrice(200);
    product.saveProduct();
    expect(product.prodTotalAmount).toBe(600);
  });
});
```

当运行测试时，将生成以下输出：

![修改产品测试脚本](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00124.jpeg)

# 调试 JavaScript

客户端浏览器上运行 JavaScript，几乎所有浏览器，如 Internet Explorer、Microsoft Edge、Chrome 和 Firefox，都提供集成的 JavaScript 调试器和**开发者工具**窗口。使用 Visual Studio，我们还可以通过将 Internet Explorer 设置为默认浏览器来调试 JavaScript 代码。Chrome 默认不支持，但通过某些步骤可以实现。

## 2015 年 Visual Studio 中的调试选项

Visual Studio 提供了某些相当不错的功能来调试 JavaScript 和解决错误。在 Visual Studio 中，只有与 Internet Explorer 一起使用时才能调试 JavaScript。通过以调试模式启动应用程序，然后在 JavaScript 代码中放置一些断点来开始调试。当达到断点时，我们可以使用在调试 C# 和 VB.NET 代码时已经熟悉的 Visual Studio 中的所有调试选项，例如单步进入 (*F11*)，单步跳过 (*F10*)，单步退出 (*Shift* + *F11*)，条件断点，以及观察变量，所有这些选项都适用于 JavaScript 代码。

### 使用 Internet Explorer 在 Visual Studio 中进行调试

在 Visual Studio 中，可以为特定的网络应用程序项目设置默认浏览器，方法是选择**网络浏览器 (Internet Explorer)** | **Internet Explorer** 选项，如下面的屏幕截图所示：

![使用 Internet Explorer 在 Visual Studio 中进行调试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00125.jpeg)

## 使用 Google Chrome 在 Visual Studio 中进行调试

2015 年的 Visual Studio 不提供用于调试 JavaScript 应用程序的默认支持，除了与 Internet Explorer 一起使用的情况。作为 Node.js 的技术基础与 Google Chrome 相同（都基于 V8 引擎），因此没有缺点。

要在 Visual Studio 中使用 Chrome 开始调试，我们必须使用远程调试器参数运行 Google 的 `chrome.exe` 文件。以下命令会使用远程调试运行 Google Chrome，并且可以从 Visual Studio 指向相同的 Chrome 实例进行附加：

```js
chrome.exe – remote-debugging-port=9222

```

`9222` 是 Visual Studio 在附加到其进程时默认连接的端口。

从 Visual Studio 出发，您可以通过按下 *Ctrl* + *Alt* + *P*，或者通过在菜单栏中选择**调试** | **附加到进程**来附加进程，然后选择 Chrome 实例。

## 开发者工具

```js
The fourth pane is the Call stack and Breakpoints. Call stack shows the chain of function calls that are executed and it is helpful to understand the code-execution flow. For example, if an A() method calls a B() method, and the B() method calls a C() method, it shows the complete flow of execution from the A() method to the C() method.
```

**断点** 选项卡显示脚本中使用的所有断点列表，用户可以通过启用或禁用、删除或添加新事件来管理这些断点：

![Microsoft Edge 中的调试选项](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00127.jpeg)

只有当**F12 开发者工具**窗口被打开时，调试才能开始，并且可以通过菜单栏的**…** | **F12 开发者工具**窗口选项或按*F12*键来打开。窗口打开后，你可以在 JavaScript 代码上设置断点并对页面执行特定操作。

以下表格展示了调试工具栏中一些重要的选项：

| 图标 | 选项 | 快捷键 | 描述 |
| --- | --- | --- | --- |
| ![Microsoft Edge 中的调试选项](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00128.jpeg) | 继续 | *F5* 或 *F8* | 这将释放断点模式，并继续到下一个断点。 |
| ![Microsoft Edge 中的调试选项](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00129.jpeg) | 断点 | *Ctrl* + *Shift* + *B* | 这将在下一条语句处设置断点。 |
| ![Microsoft Edge 中的调试选项](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00130.jpeg) | 步进 | *F11* | 这将步进到被调用函数或下一条语句。 |
| ![Microsoft Edge 中的调试选项](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00131.jpeg) | 单步跳过 | *F10* | 这将跳过被调用函数或下一条语句。 |
| ![Microsoft Edge 中的调试选项](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00132.jpeg) | 步出 | *Shift* + *F11* | 这将跳出当前函数，进入调用函数。 |
| ![Microsoft Edge 中的调试选项](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00133.jpeg) | 在新工作者创建时断点 | *Ctrl* + *Shift* + *W* | 这将在新 web 工作者创建时设置断点。 |
| ![Microsoft Edge 中的调试选项](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00134.jpeg) | 异常控制 | *Ctrl* + *Shift* + *E* | 这可用于在所有异常或未处理的异常处设置断点。默认情况下，它设置为忽略异常。 |
| ![Microsoft Edge 中的调试选项](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00135.jpeg) | 断开调试器 |   | 这将断开调试器，不再运行断点。 |
| ![Microsoft Edge 中的调试选项](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00136.jpeg) | 只调试我的代码 | *Ctrl* + *J* | 这将忽略调试第三方库。 |
| ![Microsoft Edge 中的调试选项](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00137.jpeg) | 美丽打印 | *Ctrl* + *Shift* + *P* | 这将搜索 JavaScript 块的压缩版本并使其可读。 |
| ![Microsoft Edge 中的调试选项](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00138.jpeg) | 单词换行 | *Alt* + *W* | 这将根据内容窗体大小调整句子。 |

微软 Edge 提供了以下五种断点类型：

+   标准

+   条件

+   跟踪点

+   XHR

+   事件

### 标准断点

这些断点可以通过简单地从脚本代码中选择语句来设置：

![标准断点](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00139.jpeg)

### 条件断点

这类断点在满足特定条件或变量达到特定状态时会被触发。例如，我们可以在循环内的语句使用这个，当计数器达到 10 的值时中断执行。

可以通过点击现有断点并从**上下文**菜单选择**条件…** 来设置：

![条件断点](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00140.jpeg)

此选项将打开**条件断点**窗口，条件可以设置如下截图所示：

![条件断点](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00141.jpeg)

一旦设置了条件，图标将变为![条件断点](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00142.jpeg)

### 跟踪点

跟踪点用于在语句通过时在控制台写消息，跟踪点是通过点击以下选项设置的：**从**上下文菜单中点击**插入跟踪点**

![跟踪点](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00143.jpeg)

一旦设置了跟踪点，图标将发生变化，如下：

![跟踪点](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00144.jpeg)

当语句执行时，它将在控制台窗口上打印如下截图中的消息：

![跟踪点](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00145.jpeg)

### 事件

微软 Edge 提供了从**断点**面板注册事件跟踪点和断点的选项。事件可以是鼠标事件、键盘事件或定时器事件。这项功能在大型或复杂的网络应用程序中大量使用，在这些应用程序中，不知道确切的断点位置。在某些情况下，当事件处理程序在多个地方指定时，此功能更有用。例如，如果一个页面包含 5 个按钮控件，我们需要在任何一个按钮引发点击事件时中断执行，我们只需通过断点事件指定鼠标点击事件；每当任何按钮事件被引发时，断点将被执行并聚焦于该语句。

#### 添加事件跟踪点

用户可以使用以下选项添加事件跟踪点：

![添加事件断点](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00146.jpeg)

以下窗口显示了当鼠标点击时事件跟踪点的注册情况：

![添加事件跟踪点](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00147.jpeg)

#### 添加事件断点

用户可以使用以下选项添加事件断点：

![添加事件断点](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00148.jpeg)

以下窗口显示了当鼠标点击时事件断点的注册情况：

![添加事件断点](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00149.jpeg)

### XHR

与事件类似，XHR 事件也可以从浏览器的**断点**面板中注册。当从 JavaScript 代码中发起任何 Ajax 请求时，这些事件将被触发。用户可以从以下截图中的图标注册 XHR 事件：

![XHR](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00150.jpeg)

一旦我们点击这个事件，它就会被添加到**断点**窗口中，如下截图所示：

![XHR](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00151.jpeg)

## 调试 TypeScript

在第五章 *使用 Angular 2 和 Web API 开发 ASP.NET 应用程序*中，我们已经讨论了 TypeScript 以及它如何转换成最终在浏览器上运行的 JavaScript 代码。开发人员用 TypeScript 编写代码，但在浏览器上运行的是生成的 JavaScript 文件。当 TypeScript 文件被转换成一个 JavaScript 文件时，会生成一个映射文件，其扩展名为`*.map.js`。这个文件包含了有关实际 TypeScript 文件和生成的 JavaScript 文件的信息。不仅如此，生成的 JavaScript 文件还包含了一个关于映射文件的条目，这个条目实际上告诉浏览器通过读取映射文件来加载相应的源 TypeScript 文件。

当 TypeScript 文件被转换成 JavaScript 文件时，每个生成的 JavaScript 文件都包含以下条目：

```js
//# sourceMappingURL=http://localhost:12144/todosapp/apps/createTodo.component.js.map
```

这可以通过`TSConfig.json`文件中的`sourceMap`属性进行配置。如果`sourceMap`属性为`true`，它将生成映射文件，并在生成的 JavaScript 文件中创建一个条目。另外，在 ASP.NET Core 应用程序中工作的时候，所有的静态文件都必须放在`wwwroot`文件夹中。所以，为了调试 TypeScript，所有相应的 TypeScript (`.ts`) 文件必须移动到`wwwroot`文件夹下的任何文件夹中，这样就可以通过浏览器访问了。

这里是有调试器窗口，它显示左侧的 TypeScript 文件列表和右上角的图标，可以切换源文件和编译后的 JavaScript 版本：

![调试 TypeScript](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00152.jpeg)

## 所有浏览器都支持`debugger`关键字

我们也可以通过`debugger`关键字显式地在某个点上中断控制。如果没有设置断点，但是指定了`debugger`关键字，调试将启用并中断执行。它可以从代码中设置，如下面的屏幕截图所示：

![所有浏览器都支持`debugger`关键字](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00153.jpeg)

# 总结

在本章中，我们讨论了如何测试和调试 JavaScript 应用程序。对于测试 JavaScript 应用程序，我们讨论了可以轻松与 Karma（一个测试运行器）集成的 Jasmine 测试套件，它还可以与 Grunt 一起使用，从 Visual Studio **任务运行器浏览器**窗口执行。我们还讨论了 MVVM 模式的基础知识以及如何使用 Knockout JavaScript 库来实现它。然后我们将测试用例修改为与视图模型一起工作。对于调试，我们讨论了使用 Visual Studio 调试 JavaScript 的一些技巧和技术，以及 Microsoft Edge 通过**开发者工具**窗口提供的内容，以使调试变得容易。最后，我们还学习了有关基本主题的知识，例如 Microsoft Edge 如何启用对 TypeScript 文件的调试以及实现此目的所需的配置。
