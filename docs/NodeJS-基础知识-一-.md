# NodeJS 基础知识（一）

> 原文：[`zh.annas-archive.org/md5/41C152E6702013095E0E6744245B8C51`](https://zh.annas-archive.org/md5/41C152E6702013095E0E6744245B8C51)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Node.js 只是一个让您在服务器端使用 JavaScript 的工具。但是，它实际上做的远不止这些——通过扩展 JavaScript，它允许更加集成和高效的开发方式。毫不奇怪，它是全栈 JavaScript 开发人员的基本工具。无论您是在后端还是前端工作，使用 Node.js 都可以采用更加协作和敏捷的工作方式，这样您和您的团队就可以专注于交付高质量的最终产品。这将确保您准备好迎接任何新的挑战。

本书将快节奏地介绍依赖管理、运行自己的 HTTP 服务器、实时通信以及一切必要的内容，让您快速上手 Node.js。

# 本书涵盖内容

第一章，“入门”，介绍了 Node.js 的设置。您还将学习如何利用和管理依赖项。

第二章，“简单 HTTP”，介绍了如何运行一个简单的 HTTP 服务器，并帮助您理解路由和中间件的使用。

第三章，“认证”，介绍了使用中间件和 JSON Web Token 对用户进行认证。

第四章，“调试”，介绍了在开发任务中集成事后调试技术以及如何调试您的 Node.js 程序。

第五章，“配置”，介绍了使用集中式配置选项、参数和环境变量配置和维护软件。

第六章，“LevelDB 和 NoSQL”，介绍了 NoSQL 数据库的概念，如 LevelDB 和 MongoDB。还介绍了简单键/值存储和更完整的文档数据库的使用。

第七章，“Socket.IO”，探讨了客户端、服务器之间的实时通信，以及它如何对用户进行身份验证和通知。

第八章，“创建和部署包”，侧重于共享模块并为生态系统做出贡献

第九章，“单元测试”，使用 Mocha、Sinon 和 Chance 测试您的代码，并介绍如何使用模拟函数和生成随机值来测试您的代码

第十章，“使用不止 JavaScript”，解释了在 Node.js 中使用 CoffeeScript 来扩展语言功能。

# 您需要什么

需要一台运行 Unix（Macintosh）、Linux 或 Windows 的计算机，以及您喜欢的集成开发环境。如果您没有集成开发环境，那么您有几个选择，例如：

+   Atom：[`atom.io/`](https://atom.io/)

+   Sublime：[`www.sublimetext.com/`](http://www.sublimetext.com/)

+   Cloud 9：[`c9.io/`](https://c9.io/)

# 这本书适合谁

这本书对任何想了解 Node.js 的人都有帮助（Node.js 是什么，如何使用它，它在哪里有用以及何时使用它）。熟悉服务器端和 Node.js 是先决条件。

# 约定

在本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码字词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下：“我们可以通过使用`include`指令包含其他上下文。”

代码块设置如下：

```js
<script type='application/javascript' src='script_a.js'></script>
<script type='application/javascript' src='script_b.js'></script>
```

任何命令行输入或输出都以以下形式编写：

```js
[~]$ npm install -g n

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，比如菜单或对话框中的单词，会在文本中以这种方式出现：“如果用户没有同时输入用户名和密码，服务器将返回**500 Bad Request**”。

### 注意

警告或重要提示会以这样的方式出现在框中。

### 提示

技巧和窍门会以这种方式出现。


# 第一章：入门

每个 Web 开发人员都必须偶尔遇到它，即使他们只是涉足简单的网页。每当您想要使您的网页更加交互式时，您会使用您值得信赖的朋友，比如 JavaScript 和 jQuery，并一起开发一些新的东西。您可能已经使用 AngularJS 或 Backbone 开发了一些令人兴奋的前端应用程序，并且想了解您可以用 JavaScript 做些什么。

在多个浏览器上测试您的网站时，您可能会偶尔遇到谷歌浏览器，并且您可能已经注意到它是 JavaScript 应用程序的一个很好的平台。

谷歌浏览器和 Node.js 有一个非常大的共同点：它们都在谷歌的高性能 V8 JavaScript 引擎上运行，这使我们在浏览器中使用的引擎与后端使用的引擎相同，非常酷，对吧？

# 设置

为了开始使用 Node.js，我们需要下载并安装 Node.js。最好的安装方式是前往[`nodejs.org/`](https://nodejs.org/)并下载安装程序。

在撰写本文时，当前版本的 Node.js 是 4.2.1。

为了确保一致性，我们将使用`npm`包来安装正确版本的 Node.JS，为此，我们将使用[`www.npmjs.com/package/n`](https://www.npmjs.com/package/n)中描述的`n`包。

目前，这个包只支持`*nix`机器。对于 Windows，请参见 nvm-windows 或从[`nodejs.org/dist/v4.2.1/`](https://nodejs.org/dist/v4.2.1/)下载二进制文件。

一旦你安装了 Node.js，打开终端并运行：

```js
[~]$ npm install -g n

```

`-g`参数将全局安装包，这样我们就可以在任何地方使用这个包。

Linux 用户可能需要运行安装全局包的命令作为`sudo`。

使用最近安装的包，运行：

```js
[~]$ n

```

这将显示一个包含以下包的屏幕：

```js
 node/0.10.38
 node/0.11.16
 node/0.12.0
 node/0.12.7
 node/4.2.1

```

如果`node/4.2.1`没有标记，我们可以简单地运行以下包；这将确保安装`node/4.2.1`：

```js
[~]$ sudo n 4.2.1

```

为了确保`node`运行正常，让我们创建并运行一个简单的`hello world`示例：

```js
[~/src/examples/example-1]$ touch example.js
[~/src/examples/example-1]$ echo "console.log(\"Hello world\")" > example.js
[~/src/examples/example-1]$ node example.js
Hello World

```

很好，它起作用了；现在让我们开始做正事。

# Hello require

在前面的示例中，我们只是记录了一个简单的消息，没有什么有趣的，所以让我们在这一部分深入一点。

在浏览器中使用多个脚本时，我们通常只需要包含另一个脚本标签，如：

```js
<script type='application/javascript' src='script_a.js'></script>
<script type='application/javascript' src='script_b.js'></script>
```

这两个脚本共享相同的全局范围，这通常会导致一些不寻常的冲突，当人们想要给变量赋予相同的名称时。

```js
//script_a.js
function run( ) {
    console.log( "I'm running from script_a.js!" );
}
$( run );

//script_b.js
function run( ) {
    console.log( "I'm running from script_b.js!" );
}
$( run );
```

这可能会导致混乱，当许多文件被压缩并挤在一起时会导致问题；`script_a`声明了一个全局变量，然后在`script_b`中再次声明，运行代码时，我们在控制台上看到以下内容：

```js
> I'm running from script_b.js!
> I'm running from script_b.js!

```

解决这个问题并限制全局范围的污染最常见的方法是将我们的文件包装在一个匿名函数中，如下所示：

```js
//script_a.js
(function( $, undefined ) {
    function run( ) {
        console.log( "I'm running from script_a.js!" );
    }
    $( run );
})( jQuery );

//script_b.js
(function( $, undefined ) {
    function run( ) {
        console.log( "I'm running from script_b.js!" );
    }
    $( run );
})( jQuery );
```

现在当我们运行这个时，它按预期工作：

```js
> I'm running from script_a.js!
> I'm running from script_b.js!
```

这对于不依赖外部的代码来说是很好的，但是对于依赖外部代码的代码该怎么办呢？我们只需要*导出*它，对吧？

类似以下代码将会起作用：

```js
(function( undefined ) {
    function Logger(){  
    }
    Logger.prototype.log = function( message /*...*/ ){
        console.log.apply( console, arguments );
    }
    this.Logger = Logger; 
})( )
```

现在，当我们运行这个脚本时，我们可以从全局范围访问 Logger：

```js
var logger = new Logger( );
logger.log( "This", "is", "pretty", "cool" )
> This is pretty cool
```

所以现在我们可以分享我们的库，一切都很好；但是如果其他人已经有一个暴露相同`Logger`类的库呢。

`node`是如何解决这个问题的呢？Hello require！

Node.js 有一种简单的方式来从外部来源引入脚本和模块，类似于 PHP 中的 require。

让我们在这个结构中创建一些文件：

```js
/example-2
    /util
        index.js
        logger.js
    main.js

/* util/index.js */
var logger = new Logger( )
var util = {
    logger: logger
};

/* util/logger.js */

function Logger(){
}
Logger.prototype.log = function( message /*...*/ ){
    console.log.apply( console, arguments );
};

/* main.js */
util.logger.log( "This is pretty cool" );
```

我们可以看到`main.js`依赖于`util/index.js`，而`util/index.js`又依赖于`util/logger.js`。

这应该可以正常工作吧？也许不是。让我们运行命令：

```js
[~/src/examples/example-2]$ node main.js
ReferenceError: logger is not defined
 at Object.<anonymous> (/Users/fabian/examples/example-2/main.js:1:63)
 /* Removed for simplicity */
 at Node.js:814:3

```

那么为什么会这样呢？它们不应该共享相同的全局范围吗？嗯，在 Node.js 中，情况有些不同。还记得我们之前包装文件的那些匿名函数吗？Node.js 会自动将我们的脚本包装在其中，这就是 Require 适用的地方。

让我们修复我们的文件，如下所示：

```js
/* util/index.js */
Logger = require( "./logger" )

/* main.js */
util = require( "./util" );  
```

如果您注意到，我在需要`util/index.js`时没有使用`index.js`；原因是当您需要一个文件夹而不是一个文件时，您可以指定一个代表该文件夹代码的索引文件。这对于像模型文件夹这样的东西非常方便，您可以在一个 require 中公开所有模型，而不是为每个模型单独 require。

现在，我们已经需要了我们的文件。但是我们得到了什么？

```js
[~/src/examples/example-2]$ node
> var util = require( "./util" );
> console.log( util );
{} 

```

但是，还没有日志记录器。我们错过了一个重要的步骤；我们没有告诉 Node.js 我们想要在我们的文件中公开什么。

要在 Node.js 中公开某些内容，我们使用一个名为`module.exports`的对象。有一个简写引用，就是*exports*。当我们的文件包装在一个匿名函数中时，*module*和*exports*都作为参数传递，如下例所示：

```js
function Module( ) {
    this.exports = { };
}

function require( file ) {
    // .....
    returns module.exports;
} 

var module = new Module( );
var exports = module.exports;

(function( exports, require, module ) {
    exports = "Value a"
    module.exports = "Value b"
})( exports, require, module );
console.log( module.exports );
// Value b
```

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)购买的所有 Packt 图书中下载示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

示例显示*exports*最初只是对`module.exports`的引用。这意味着，如果您使用`exports = { }`，则您设置的值在函数范围之外将无法访问。但是，当您向*exports*对象添加属性时，实际上是向`module.exports`对象添加属性，因为它们都是相同的值。将值分配给`module.exports`将导出该值，因为它可以通过模块在函数范围之外访问。

有了这个知识，我们最终可以以以下方式运行我们的脚本：

```js
/* util/index.js */
Logger = require( "./logger.js" );
exports.logger = new Logger( );

/* util/logger.js */
function Logger( ){
} 
Logger.prototype.log = ( message /*...*/ ) {
    console.log.apply( console, arguments );
};
module.exports = Logger;

/* main.js */
util = require( "./utils" );
util.logger.log( "This is pretty cool" );
```

运行`main.js`：

```js
[~/src/examples/example-2]$ node main.js
This is pretty cool

```

还可以使用 Require 在我们的代码中包含模块。在需要模块时，我们不需要使用文件路径，只需要使用我们想要的`node`模块的名称。

Node.js 包括许多预构建的核心模块，其中之一是`util`模块。您可以在[`nodejs.org/api/util.html`](https://nodejs.org/api/util.html)找到`util`模块的详细信息。

让我们看看`util`模块命令：

```js
[~]$ node
> var util = require( "util" )
> util.log( 'This is pretty cool as well' )
01 Jan 00:00:00 - This is pretty cool as well 

```

# 你好 npm

除了内部模块之外，还有一个完整的包生态系统；Node.js 最常见的包管理器是`npm`。截至目前，共有 192,875 个可用的包。

我们可以使用`npm`来访问为我们执行许多操作的包，从路由 HTTP 请求到构建我们的项目。您还可以浏览[`www.npmjs.com/`](https://www.npmjs.com/)上提供的包。

使用包管理器，您可以引入其他模块，这很好，因为您可以花更多时间在业务逻辑上，而不是重新发明轮子。

让我们下载以下包，使我们的日志消息变得丰富多彩：

```js
[~/src/examples/example-3]$ npm install chalk

```

现在，要使用它，创建一个文件并需要它：

```js
[~/src/examples/example-3]$ touch index.js
/* index.js */
var chalk = require( "chalk" );
console.log( "I am just normal text" )
console.log( chalk.blue( "I am blue text!" ) )

```

运行此代码时，您将看到默认颜色的第一条消息和蓝色的第二条消息。让我们看看这个命令：

```js
[~/src/examples/example-3]$ node index.js
I am just normal text
I am blue text!

```

当您需要某个其他人已经实现的东西时，下载现有包的能力非常方便。正如我们之前所说，有很多可供选择的包。

我们需要跟踪这些依赖关系，有一个简单的解决方案：`package.json`。

使用`package.json`，我们可以定义诸如项目名称、主要脚本是什么、如何运行测试、我们的依赖关系等内容。您可以在[`docs.npmjs.com/files/package.json`](https://docs.npmjs.com/files/package.json)找到属性的完整列表。

`npm`提供了一个方便的命令来创建这些文件，并且会询问您创建`package.json`文件所需的相关问题：

```js
[~/src/examples/example-3]$ npm init

```

上述实用程序将引导您完成创建`package.json`文件的过程。

它只涵盖了最常见的项目，并尝试猜测有效的默认值。

运行`npm help json`命令以获取有关这些字段的最终文档，并了解它们的确切作用。

之后，使用`npm`和安装`<pkg> --save`来安装一个包并将其保存为`package.json`文件中的依赖项。

按`^C`随时退出：

```js
name: (example-3)
version: (1.0.0) 
description: 
entry point: (main.js)
test command: 
git repository: 
keywords:
license: (ISC) 
About to write to /examples/example-3/package.json:
{
  "name": "example-3",
  "version": "1.0.0",
  "description": "",
  "main": "main.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "....",
  "license": "ISC"
}
Is this ok? (yes) 
```

该实用程序将为您提供默认值，因此最好只需使用*Enter*键跳过它们。

现在，在安装我们的包时，我们可以使用`--save`选项将`chalk`保存为依赖项，如下所示：

```js
[~/src/examples/example-3]$ npm install --save chalk
```

我们可以看到 chalk 已经被添加了：

```js
[~/examples/example-3]$ cat package.json
{
  "name": "example-3",
  "version": "1.0.0",
  "description": "",
  "main": "main.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "...",
  "license": "ISC",
  "dependencies": {
    "chalk": "¹.0.0"
  }
}
```

我们可以通过修改`package.json`文件手动添加这些依赖项；这是保存依赖项的最常见方法。

您可以在此处阅读有关包文件的更多信息：[`docs.npmjs.com/files/package.json`](https://docs.npmjs.com/files/package.json)。

如果您正在创建服务器或应用程序而不是模块，您很可能希望找到一种方法，以便无需始终提供主文件的路径来启动您的进程；这就是`package.json`文件中的脚本对象发挥作用的地方。

要设置启动脚本，您只需在`scripts`对象中设置`start`属性，如下所示：

```js
"scripts": {
    "test": "echo \"Error: no test specified\" && exit 1",
    "start": "node server.js"
}
```

现在，我们需要做的就是运行 `npm` start，然后 `npm` 将运行我们已经指定的启动脚本。

我们可以定义更多的脚本，例如，如果我们想要一个用于开发环境的启动脚本，我们也可以定义一个开发属性；但是，对于非标准的脚本名称，我们需要使用`npm run <script>`而不是只使用`npm <script>`。例如，如果我们想要运行我们的新开发脚本，我们将不得不使用`npm run development`。

`npm`具有在不同时间触发的脚本。我们可以定义一个`postinstall`脚本，该脚本在运行`npm install`后运行；如果我们想要触发包管理器来安装模块（例如，bower），我们可以使用这个。

您可以在此处阅读有关脚本对象的更多信息：[`docs.npmjs.com/misc/scripts`](https://docs.npmjs.com/misc/scripts)。

如果您正在团队开发中工作，需要定义一个包，其中项目将安装在不同的机器上。如果您使用诸如**git**之类的源代码控制工具，建议您将`node_modules`目录添加到您的忽略文件中，如下所示：

```js
[~/examples/example-3]$ echo "node_modules" > .gitignore
[~/examples/example-3]$ cat .gitignore
node_modules

```

# 总结

这很快，不是吗？我们已经涵盖了我们继续旅程所需的 Node.js 的基础知识。

我们已经介绍了相对于常规 JavaScript 代码在浏览器中，如何轻松地暴露和保护公共和私有代码，全局范围可能会受到严重污染。

我们还知道如何从外部源包括包和代码，以及如何确保所包含的包是一致的。

正如您所看到的，在许多包管理器中有一个庞大的包生态系统，例如`npm`，正等待我们使用和消耗。

在下一章中，我们将专注于创建一个简单的服务器来路由、认证和消耗请求。

为 Bentham Chang 准备，Safari ID 为 bentham@gmail.com 用户编号：2843974 © 2015 Safari Books Online，LLC。此下载文件仅供个人使用，并受到服务条款的约束。任何其他用途均需版权所有者的事先书面同意。未经授权的使用、复制和/或分发严格禁止，并违反适用法律。保留所有权利。


# 第二章：简单的 HTTP

现在我们已经了解了基础知识，我们可以继续学习一些更有用的东西。在本章中，我们将学习如何创建一个 HTTP 服务器和路由请求。在使用 Node.js 时，你会经常遇到 HTTP，因为服务器端脚本是 Node.js 的常见用途之一。

Node.js 自带一个内置的 HTTP 服务器；你所需要做的就是要求包含的`http`包并创建一个服务器。你可以在[`nodejs.org/api/http.html`](https://nodejs.org/api/http.html)上阅读更多关于该包的信息。

```js
var Http = require( 'http' );

var server = Http.createServer( );
```

这将创建一个属于你自己的 HTTP 服务器，准备就绪。然而，在这种状态下，它不会监听任何请求。我们可以在任何可用的端口或套接字上开始监听，如下所示：

```js
var Http = require( 'http' );

var server = Http.createServer( );
server.listen( 8080, function( ) {
    console.log( 'Listening on port 8080' ); 
});
```

让我们把前面的代码保存为`server.js`并运行它：

```js
[~/examples/example-4]$ node server.js
Listening on port 8080

```

通过在浏览器中导航到`http://localhost:8080/`，你会看到请求已被接受，但服务器没有响应；这是因为我们还没有处理这些请求，我们只是在监听它们。

当我们创建服务器时，我们可以传递一个回调函数，每次有请求时都会调用它。传递的参数将是：`request`，`response`。

```js
function requestHandler( request, response ) {
}
var server = Http.createServer( requestHandler );
```

现在每次收到请求时，我们都可以做一些事情：

```js
var count = 0;
function requestHandler( request, response ) {
    var message;
    count += 1;
    response.writeHead( 201, {
        'Content-Type': 'text/plain'
    });

    message = 'Visitor count: ' + count;
    console.log( message );
    response.end( message );
}
```

让我们运行脚本并从浏览器请求页面；你应该看到`访客计数：1`返回到浏览器：

```js
[~/examples/example-4]$ node server.js
Listening on port 8080
Visitor count: 1
Visitor count: 2
```

然而，出现了一些奇怪的事情：多生成了一个请求。谁是访客 2？

`http.IncomingMessage`（参数`request`）*暴露*了一些属性，可以用来弄清楚这一点。我们现在最感兴趣的属性是`url`。我们期望只有`/`被请求，所以让我们把这个添加到我们的消息中：

```js
message = 'Visitor count: ' + count + ', path: ' + request.url;
```

现在你可以运行代码，看看发生了什么。你会注意到`/favicon.ico`也被请求了。如果你没有看到这个，那么你一定在想我在说什么，或者你的浏览器最近是否访问过`http://localhost:8080`并且已经缓存了图标。如果是这种情况，你可以手动请求图标，例如从`http://localhost:8080/favicon.ico`：

```js
[~/examples/example-4]$ node server.js
Listening on port 8080
Visitor count: 1, path: /
Visitor count: 2, path: /favicon.ico

```

我们还可以看到，如果我们请求任何其他页面，我们将得到正确的路径，如下所示：

```js
[~/examples/example-4]$ node server.js
Listening on port 8080
Visitor count: 1, path: /
Visitor count: 2, path: /favicon.ico
Visitor count: 3, path: /test
Visitor count: 4, path: /favicon.ico
Visitor count: 5, path: /foo
Visitor count: 6, path: /favicon.ico
Visitor count: 7, path: /bar
Visitor count: 8, path: /favicon.ico
Visitor count: 9, path: /foo/bar/baz/qux/norf
Visitor count: 10, path: /favicon.ico

```

然而，这并不是我们想要的结果，除了少数路由之外，我们希望返回`404: Not Found`。

# 介绍路由

路由对于几乎所有的 Node.js 服务器都是必不可少的。首先，我们将实现我们自己的简单版本，然后再转向更复杂的路由。

我们可以使用`switch`语句来实现我们自己的简单路由器，例如：

```js
function requestHandler( request, response ) {
    var message,
        status = 200;

    count += 1;

    switch( request.url ) {
        case '/count':
            message = count.toString( );
            break;
        case '/hello':
            message = 'World';
            break;
        default: 
            status = 404;
            message = 'Not Found';
            break;
    }

    response.writeHead( 201, {
        'Content-Type': 'text/plain'
    });
    console.log( request.url, status, message );
    response.end( message ); 
}
```

让我们运行以下示例：

```js
[~/examples/example-4]$ node server.js
Listening on port 8080
/foo 404 Not Found
/bar 404 Not Found
/world 404 Not Found
/count 200 4
/hello 200 World
/count 200 6

```

你可以看到每次请求时计数都在增加；然而，它并不是每次都返回。如果我们没有为该路由定义一个特定的情况，我们将返回`404: Not Found`。

对于实现 RESTful 接口的服务，我们希望能够根据 HTTP 方法路由请求。请求对象使用`method`属性来暴露这一点。

将这个添加到日志中，我们可以看到这个：

```js
console.log( request.method, request.url, status, message );
```

运行示例并执行你的请求，你可以使用一个 REST 客户端来调用一个 POST 请求：

```js
[~/examples/example-4]$ node server.js
Listening on port 8080
GET /count 200 1
POST /count 200 2
PUT /count 200 3
DELETE /count 200 4

```

我们可以实现一个路由器来根据方法路由，但是已经有一些包可以为我们做到这一点。现在我们将使用一个叫做`router`的简单包：

```js
[~/examples/example-5]$ npm install router

```

现在，我们可以对我们的请求进行一些更复杂的路由：

让我们创建一个简单的 RESTful 接口。

首先，我们需要创建服务器，如下所示：

```js
/* server.js */
var Http = require( 'http' ),
    Router = require( 'router' ), 
    server,
    router; 

router = new Router( );

server = Http.createServer( function( request, response ) {
    router( request, response, function( error ) {
        if( !error ) {
            response.writeHead( 404 );
        } else {
            //Handle errors
            console.log( error.message, error.stack );
            response.writeHead( 400 );
        }       
        response.end( '\n' );
    });
});

server.listen( 8080, function( ) {
    console.log( 'Listening on port 8080' );
});
```

运行服务器应该显示服务器正在监听。

```js
[~/examples/example-5]$ node server.js
Listening on port 8080

```

我们想要定义一个简单的接口来读取、保存和删除消息。我们可能还想要读取单个消息以及消息列表；这本质上定义了一组 RESTful 端点。

REST 代表**R**epresentational **S**tate **T**ransfer；这是许多 HTTP 编程接口使用的一种非常简单和常见的风格。

我们想要定义的端点是：

| HTTP 方法 | 端点 | 用途 |
| --- | --- | --- |
| `POST` | `/message` | 创建消息 |
| `GET` | `/message/:id` | 读取消息 |
| `DELETE` | `/message/:id` | 删除消息 |
| `GET` | `/message` | 读取多条消息 |

对于每种 HTTP 方法，路由器都有一种用于映射路由的方法。这个接口的形式是：

```js
router.<HTTP method>( <path>, [ ... <handler> ] )
```

我们可以为每个路由定义多个处理程序，但我们稍后会回到这一点。

我们将逐个路由进行实现，并将代码追加到`server.js`的末尾。

我们想要把我们的消息存储在某个地方，在现实世界中我们会把它们存储在数据库中；然而，为了简单起见，我们将使用一个带有简单计数器的数组，如下所示：

```js
var counter = 0,
    messages = { };
```

我们的第一个路由将用于创建消息：

```js
function createMessage( request, response ) {
    var id = counter += 1;
    console.log( 'Create message', id );
    response.writeHead( 201, {
        'Content-Type': 'text/plain'
    });
    response.end( 'Message ' + id );
}
router.post( '/message', createMessage );
```

我们可以通过运行服务器并向`http://localhost:8000/message`发送 POST 请求来确保这个路由工作。

```js
[~/examples/example-5]$ node server.js
Listening on port 8080
Create message 1
Create message 2
Create message 3

```

我们还可以确认计数器正在递增，因为每次我们发出请求时 id 都会增加。我们将这样做来跟踪消息的数量并为每条消息赋予一个*唯一*的 id。

现在这个工作了，我们需要能够读取消息文本，为此我们需要能够读取客户端发送的请求正文。这就是多个处理程序发挥作用的地方。我们可以以两种不同的方式来解决这个问题，如果我们只在一个路由中读取正文，或者如果我们正在执行与路由特定的其他操作，例如授权，我们将在路由中添加一个额外的处理程序，例如：

```js
router.post( '/message', parseBody, createMessage ) 
```

我们可以通过为所有方法和路由添加一个处理程序来完成另一种方式；这将在路由处理程序之前首先执行，这些通常被称为中间件。您可以将处理程序视为一系列函数，其中每个函数都在完成其任务后调用下一个函数。有了这个想法，您应该注意添加处理程序的顺序，无论是中间件还是路由，都将决定操作的顺序。这意味着，如果我们注册一个对所有方法执行的处理程序，我们必须首先执行这个处理程序。

路由器*公开*了一个函数来添加以下处理程序：

```js
router.use( function( request, response, next ) {
    console.log( 'middleware executed' );
    // Null as there were no errors
    // If there was an error then we could call `next( error );`
    next( null );
});
```

您可以将此代码添加到`createMessage`的实现之前：

完成后，运行服务器并进行以下请求：

```js
[~/examples/example-5]$ node server.js
Listening on port 8080
middleware executed
Create message 1

```

中间件在路由处理程序之前执行。

现在我们知道了中间件的工作原理，我们可以按照以下方式使用它们：

```js
[~/examples/example-5]$ npm install body-parser

```

用以下内容替换我们的自定义中间件：

```js
var BodyParser = require( 'body-parser' );
router.use( BodyParser.text( ) );
```

在这个阶段，我们只想将所有请求读取为纯文本。

现在我们可以在`createMessage`中检索消息。

```js
function createMessage( request, response ) {
    var id = counter += 1,
        message = request.body;

    console.log( 'Create message', id, message );
    messages[ id ] = message;
    response.writeHead( 201, {
        'Content-Type': 'text/plain',
        'Location': '/message/' + id 
    });
    response.end( message );
}
```

运行`server.js`并向`http://localhost:8080/message`发送`POST`请求；你会看到类似以下消息：

```js
[~/examples/example-5]$ node server.js
Listening on port 8080
Create message 1 Hello foo
Create message 2 Hello bar

```

如果你注意到，你会发现一个标题返回了消息的新位置和它的 id，如果我们请求`http://localhost:8080/message/1`，应该返回第一条消息的内容。

然而，这个路由有一些不同之处；每次创建消息时都会生成一个密钥。我们不想为每条新消息设置一个新的路由，因为这样效率非常低。相反，我们创建一个与模式匹配的路由，比如`/message/:id`。这是在 Node.js 中定义动态路由的常见方式。

路由的`id`部分称为参数。我们可以在我们的路由中定义任意数量的这些参数，并使用请求引用它们；例如，我们可以有一个类似于`/user/:id/profile/:attribute`的路由。

有了这个想法，我们可以创建我们的`readMessage`处理程序，如下所示：

```js
function readMessage( request, response ) {
    var id = request.params.id,
        message = messages[ id ];
    console.log( 'Read message', id, message );

    response.writeHead( 200, {
        'Content-Type': 'text/plain'
    });
    response.end( message );
}
router.get( '/message/:id', readMessage );
```

现在让我们把前面的代码保存在`server.js`文件中并运行服务器：

```js
[~/examples/example-5]$ node server.js
Listening on port 8080
Create message 1 Hello foo
Read message 1 Hello foo
Create message 2 Hello bar
Read message 2 Hello bar
Read message 1 Hello foo

```

通过向服务器发送一些请求，我们可以看到它正在工作。

删除消息几乎与读取消息相同；但我们不返回任何内容并将原始消息值设置为 null：

```js
function deleteMessage( request, response ) {
    var id = request.params.id;

    console.log( 'Delete message', id );

    messages[ id ] = undefined;

    response.writeHead( 204, { } );

    response.end( '' );
}

router.delete( '/message/:id', deleteMessage )
```

首先运行服务器，然后按照以下方式创建、读取和删除消息：

```js
[~/examples/example-5]$ node server.js
Listening on port 8080
Delete message 1
Create message 1 Hello
Read message 1 Hello
Delete message 1
Read message 1 undefined

```

看起来不错；然而，我们遇到了一个问题。我们不应该在删除消息后再次读取消息；如果我们找不到消息，我们将在读取和删除处理程序中返回`404`。我们可以通过向我们的读取和删除处理程序添加以下代码来实现这一点：

```js
    var id = request.params.id,
        message = messages[ id ];

    if( typeof message !== 'string' ) {
        console.log( 'Message not found', id );

        response.writeHead( 404 );
        response.end( '\n' );
        return;
    } 
```

现在让我们把前面的代码保存在`server.js`文件中并运行服务器：

```js
[~/examples/example-5]$ node server.js
Listening on port 8080
Message not found 1
Create message 1 Hello
Read message 1 Hello

```

最后，我们希望能够阅读所有消息并返回所有消息值的列表：

```js
function readMessages( request, response ) {
    var id,
        message,
        messageList = [ ],
        messageString;

    for( id in messages ) {
        if( !messages.hasOwnProperty( id ) ) {
            continue;
        }
        message = messages[ id ];
        // Handle deleted messages
        if( typeof message !== 'string' ) {
            continue;
        }
        messageList.push( message );
    }

    console.log( 'Read messages', JSON.stringify( 
        messageList, 
        null, 
        '  ' 
    ));

    messageString = messageList.join( '\n' );

    response.writeHead( 200, {
        'Content-Type': 'text/plain'
    });

    response.end( messageString );
}
router.get( '/message', readMessages );
```

现在让我们把前面的代码保存在`server.js`文件中并运行服务器：

```js
[~/examples/example-5]$ node server.js
Listening on port 8080
Create message 1 Hello 1
Create message 2 Hello 2
Create message 3 Hello 3
Create message 4 Hello 4
Create message 5 Hello 5
Read messages [
 "Hello 1",
 "Hello 2",
 "Hello 3",
 "Hello 4",
 "Hello 5"
]

```

太棒了；现在我们有了一个完整的 RESTful 接口来读写消息。但是，我们不希望每个人都能读取我们的消息；它们应该是安全的，我们还想知道谁创建了这些消息，我们将在下一章中介绍这个问题。

# 总结

现在我们拥有了制作一些非常酷的服务所需的一切。我们现在可以从头开始创建一个 HTTP，路由我们的请求，并创建一个 RESTful 接口。

这将帮助您创建完整的 Node.JS 服务。在下一章中，我们将介绍身份验证。

为 Bentham Chang 准备，Safari ID 为 bentham@gmail.com 用户编号：2843974 © 2015 Safari Books Online，LLC。此下载文件仅供个人使用，并受到服务条款的约束。任何其他使用均需版权所有者的事先书面同意。未经授权的使用、复制和/或分发严格禁止并违反适用法律。保留所有权利。


# 第三章：认证

我们现在可以创建 RESTful API，但我们不希望每个人都能访问我们暴露的所有内容。我们希望路由是安全的，并且能够跟踪谁在做什么。

Passport 是一个很棒的模块，另一个中间件，帮助我们验证请求。

Passport 公开了一个简单的 API，供提供者扩展并创建策略来验证用户。在撰写本文时，有 307 个官方支持的策略；但是，您完全可以编写自己的策略并发布供他人使用。

# 基本身份验证

passport 最简单的策略是接受用户名和密码的本地策略。

我们将为这些示例引入 express 框架，现在您已经了解了它在底层的基本工作原理，我们可以将它们整合在一起。

您可以安装`express`、`body-parser`、`passport`和`passport-local`。Express 是一个内置电池的 Node.js Web 框架，包括路由和使用中间件的能力：

```js
[~/examples/example-19]$ npm install express body-parser passport passport-local

```

目前，我们可以将我们的用户存储在一个简单的对象中，以便以后引用，如下所示：

```js
var users = {
    foo: {
        username: 'foo',
        password: 'bar',
        id: 1
    },
    bar: {
        username: 'bar',
        password: 'foo',
        id: 2
    }
}
```

一旦我们有了一些用户，我们就需要设置 passport。当我们创建本地策略的实例时，我们需要提供一个`verify`回调，其中我们检查用户名和密码，同时返回一个用户：

```js
var Passport = require( 'passport' ),
    LocalStrategy = require( 'passport-local' ).Strategy;

var localStrategy = new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password'
  },
  function(username, password, done) {
    user = users[ username ];

    if ( user == null ) {
        return done( null, false, { message: 'Invalid user' } );
    }

    if ( user.password !== password ) {
        return done( null, false, { message: 'Invalid password' } );    
    }

    done( null, user );
  }
)
```

在这种情况下，`verify`回调期望使用`done`调用用户。它还允许我们在用户无效或密码错误时提供信息。

现在，我们有了一个策略，我们可以将其传递给 passport，这允许我们以后引用它并用它来验证我们的请求，如下所示：

```js
Passport.use( 'local', localStrategy );
```

您可以在每个应用程序中使用多种策略，并通过您传递的名称引用每个策略，在这种情况下是`'local'`。

现在，让我们创建我们的服务器，如下所示：

```js
var Express = require( 'express' );

var app = Express( );
```

我们将不得不使用`body-parser`中间件。这将确保当我们发布到我们的登录路由时，我们可以读取我们的主体；我们还需要初始化 passport：

```js
var BodyParser = require( 'body-parser' );
app.use( BodyParser.urlencoded( { extended: false } ) );
app.use( BodyParser.json( ) );
app.use( Passport.initialize( ) );
```

要登录到我们的应用程序，我们需要创建一个使用身份验证的`post`路由作为处理程序之一。其代码如下：

```js
app.post(
    '/login',
    Passport.authenticate( 'local', { session: false } ),
    function ( request, response ) {

    }
);
```

现在，当我们向`/login`发送`POST`请求时，服务器将验证我们的请求。

经过身份验证后，`user`属性将填充在请求对象上，如下所示：

```js
app.post(
    '/login',
    Passport.authenticate( 'local', { session: false } ),
    function ( request, response ) {
        response.send( 'User Id ' + request.user.id );
    }
);
```

最后，我们需要监听请求，就像所有其他服务器一样：

```js
app.listen( 8080, function( ) {
    console.log( 'Listening on port 8080' );
});
```

让我们运行示例：

```js
[~/examples/example-19]$ node server.js
Listening on port 8080

```

现在，当我们向服务器发送`POST`请求时，我们可以验证用户。如果用户没有同时传递用户名和密码，服务器将返回`400 Bad Request`。

### 提示

如果您不熟悉`curl`，您可以使用诸如 Advanced REST Client 之类的工具：

[`chromerestclient.appspot.com/`](https://chromerestclient.appspot.com/)

在接下来的示例中，我将使用命令行界面`curl`。

我们可以通过执行`POST`到`/login`命令来执行登录请求：

```js
[~]$ curl -X POST http://localhost:8080/login -v
< HTTP/1.1 400 Bad Request

```

如果用户提供了错误的详细信息，那么将返回`401 Unauthorized`：

```js
[~]$ curl -X POST http://localhost:8080/login \
 -H 'Content-Type: application/json' \
 -d '{"username":"foo","password":"foo"}' \
 -v
< HTTP/1.1 401 Unauthorized

```

如果我们提供了正确的详细信息，那么我们可以看到我们的处理程序被调用，并且正确的数据被返回：

```js
[~]$ curl -X POST http://localhost:8080/login \
 -H 'Content-Type: application/json' \
 -d '{"username":"foo","password":"bar"}'
User Id 1
[~]$ curl -X POST http://localhost:8080/login \
 -H 'Content-Type: application/json' \
 -d '{"username":"bar","password":"foo"}'
User Id 2

```

# Bearer 令牌

现在我们有了一个经过身份验证的用户，我们可以生成一个令牌，以便在将来的请求中使用，而不是在任何地方都传递我们的用户名和密码。这通常被称为 Bearer 令牌，方便的是，passport 有一个策略可以实现这一点。

对于我们的令牌，我们将使用一种称为**JSON Web Token**（**JWT**）的东西。JWT 允许我们从 JSON 对象中编码令牌，然后解码和验证它们。存储在其中的数据是开放和简单的，因此不应该在其中存储密码；但是，它使验证用户变得非常简单。我们还可以为这些令牌提供到期日期，这有助于限制令牌被暴露的严重性。

您可以在[`jwt.io/`](http://jwt.io/)上阅读有关 JWT 的更多信息。

您可以使用以下命令安装 JWT：

```js
[~/examples/example-19]$ npm install jsonwebtoken

```

一旦用户经过身份验证，我们就可以安全地为他们提供一个令牌，以便在将来的请求中使用：

```js
var JSONWebToken = require( 'jsonwebtoken' ),
    Crypto = require( 'crypto' );

var generateToken = function ( request, response ) {

    // The payload just contains the id of the user
    // and their username, we can verify whether the claim
    // is correct using JSONWebToken.verify     
    var payload = {
        id: user.id,
        username: user.username
    };
    // Generate a random string
    // Usually this would be an app wide constant
    // But can be done both ways
    var secret = Crypto.randomBytes( 128 )
                       .toString( 'base64' );
    // Create the token with a payload and secret
    var token = JSONWebToken.sign( payload, secret );

    // The user is still referencing the same object
    // in users, so no need to set it again
    // If we were using a database, we would save
    // it here
    request.user.secret = secret

    return token;
}

var generateTokenHandler = function ( request, response  ) {
    var user = request.user;    
    // Generate our token
    var token = generateToken( user );
    // Return the user a token to use
    response.send( token );
};

app.post(
    '/login',
    Passport.authenticate( 'local', { session: false } ),
    generateTokenHandler
);
```

现在，当用户登录时，他们将收到一个我们可以验证的令牌。

让我们运行我们的 Node.js 服务器：

```js
[~/examples/example-19]$ node server.js
Listening on port 8080

```

现在我们登录时会收到一个令牌：

```js
[~]$ curl -X POST http://localhost:8080/login \
 -H 'Content-Type: application/json' \
 -d '{"username":"foo","password":"bar"}'
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZC
I6MSwidXNlcm5hbWUiOiJmb28iLCJpYXQiOjE0MzcyO
TQ3OTV9.iOZO7oCIceZl6YvZqVP9WZLRx-XVvJFMF1p
pPCEsGGs

```

我们可以将此输入调试器中的[`jwt.io/`](http://jwt.io/)并查看内容，如下所示：

```js
{
  "id": 1,
  "username": "foo",
  "iat": 1437294795
}
```

如果我们有密钥，我们可以验证令牌是否正确。签名每次请求令牌时都会更改：

```js
[~]$ curl -X POST http://localhost:8080/login \
 -H 'Content-Type: application/json' \
 -d '{"username":"foo","password":"bar"}'
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZC
I6MSwidXNlcm5hbWUiOiJmb28iLCJpYXQiOjE0MzcyO
TQ5OTl9.n1eRQVOM9qORTIMUpslH-ycTNEYdLDKa9lU
pmhf44s0

```

我们可以使用`passport-bearer`对用户进行身份验证；它的设置方式与`passport-local`非常相似。但是，与其从主体接受用户名和密码不同，我们接受一个持票人令牌；这可以通过查询字符串、主体或`Authorization`标头传递：

首先，我们必须安装`passport-http-bearer`：

```js
[~/examples/example-19]$ npm install passport-http-bearer

```

然后让我们创建我们的验证器。有两个步骤：第一步是确保解码的信息与我们的用户匹配，这通常是我们检索用户的地方；然后，一旦我们有一个用户并且它是有效的，我们可以根据用户的密钥检查令牌是否有效：

```js
var BearerStrategy = require( 'passport-http-bearer' ).Strategy;

var verifyToken = function( token, done ) {
    var payload = JSONWebToken.decode( token );
    var user = users[ payload.username ];
    // If we can't find a user, or the information
    // doesn't match then return false
    if ( user == null ||
         user.id !== payload.id ||
         user.username !== payload.username ) {
        return done( null, false );
    }
    // Ensure the token is valid now we have a user
    JSONWebToken.verify( token, user.secret, function ( error, decoded ) {
        if ( error || decoded == null ) {
            return done( error, false );
        }
        return done( null, user );
    });
}   
var bearerStrategy = new BearerStrategy(
    verifyToken
)
```

我们可以将此策略注册为持票人，以便以后使用：

```js
Passport.use( 'bearer', bearerStrategy );
```

我们可以创建一个简单的路由，用于检索经过身份验证的用户的用户详细信息：

```js
app.get(
    '/userinfo',
    Passport.authenticate( 'bearer', { session: false } ),
    function ( request, response ) {
        var user = request.user;
        response.send( {
            id: user.id,
            username: user.username
        });
    }
);
```

让我们运行 Node.js 服务器：

```js
[~/examples/example-19]$ node server.js
Listening on port 8080

```

一旦我们收到一个令牌：

```js
[~]$ curl -X POST http://localhost:8080/login \
 -H 'Content-Type: application/json' \
 -d '{"username":"foo","password":"bar"}'

```

我们可以在我们的请求中使用结果：

```js
[~]$ curl -X GET http://localhost:8080/userinfo \
 -H 'Authorization: Bearer <token>'
{"id":1,"username":"foo"}

```

# OAuth

OAuth 提供了许多优势；例如，它不需要处理用户的实际识别。我们可以让用户使用他们信任的服务登录，例如 Google、Facebook 或 Auth0。

在接下来的示例中，我将使用`Auth0`。他们提供了一个免费帐户供您使用：[`auth0.com/`](https://auth0.com/)。

您需要注册并创建一个`api`（选择`AngularJS + Node.js`），然后转到设置并记下域、客户端 ID 和客户端密钥。您需要这些来设置`OAuth`。

我们可以使用`passport-oauth2`使用 OAuth 进行身份验证：

```js
[~/examples/example-19]$ npm install --save passport-oauth2

```

与我们的持票人令牌一样，我们希望验证服务器返回的内容，这将是一个具有 ID 的用户对象。我们将与我们的数据中的用户匹配或创建一个新用户：

```js
var validateOAuth = function ( accessToken, refreshToken, profile, done ) {

    var keys = Object.keys( users ), user = null;

    for( var iKey = 0; iKey < keys.length; i += 1 ) {
        user = users[ key ];
        if ( user.thirdPartyId !== profile.user_id ) { continue; }
        return done( null, user );
    }

    users[ profile.name ] = user = {
        username: profile.name,
        id: keys.length,
        thirdPartyId: profile.user_id
    }
    done( null, user );

};
```

一旦我们有一个验证用户的函数，我们就可以为我们的 OAuth 策略组合选项：

```js
var oAuthOptions = {
    authorizationURL: 'https://<domain>.auth0.com/authorize',
    tokenURL: 'https://<domain>.auth0.com/oauth/token',
    clientID: '<client id>',
    clientSecret: '<client secret>',
    callbackURL: "http://localhost:8080/oauth/callback"
}
```

然后我们创建我们的策略，如下所示：

```js
var OAuth2Strategy = require( 'passport-oauth2' ).Strategy;
oAuthStrategy = new OAuth2Strategy( oAuthOptions, validateOAuth );
```

在使用我们的策略之前，我们需要使用我们自己的策略`userProfile`方法进行鸭子类型处理，这样我们就可以请求用户对象在`validateOAuth`中使用：

```js
var parseUserProfile = function ( done, error, body ) {
    if ( error ) {
        return done( new Error( 'Failed to fetch user profile' ) )
    }

    var json;
    try {
        json = JSON.parse( body );
    } catch ( error ) {
        return done( error );
    }
    done( null, json );
}

var getUserProfile = function( accessToken, done ) {
    oAuthStrategy._oauth2.get(
        "https://<domain>.auth0.com/userinfo",
        accessToken,
        parseUserProfile.bind( null, done )
    )
}
oAuthStrategy.userProfile = getUserProfile
```

我们可以将此策略注册为`oauth`，以便以后使用：

```js
Passport.use( 'oauth', oAuthStrategy );
```

我们需要创建两个路由来处理我们的 OAuth 身份验证：一个路由用于启动流程，另一个用于识别服务器返回：

```js
app.get( '/oauth', Passport.authenticate( 'oauth', { session: false } ) );
```

我们可以在这里使用我们的`generateTokenHandler`，因为我们的请求上会有一个用户。

```js
app.get( '/oauth/callback',
  Passport.authenticate( 'oauth', { session: false } ),
  generateTokenHandler
);
```

我们现在可以启动我们的服务器并请求`http://localhost:8080/oauth`；服务器将重定向您到`Auth0`。登录后，您将收到一个令牌，您可以在`/userinfo`中使用。

如果您使用会话，您可以将用户保存到会话中，并将其重定向回您的首页（或为已登录用户设置的默认页面）。对于单页应用程序，例如使用 Angular 时，您可能希望将用户重定向到 URL 中带有令牌，以便客户端框架抓取并保存。

# 总结

我们现在可以对用户进行身份验证；这很棒，因为我们现在可以弄清楚这些人是谁，然后限制用户访问某些资源。

在下一章中，我们将介绍调试，如果我们的用户没有被验证，我们可能需要使用它。

为 Bentham Chang 准备，Safari ID bentham@gmail.com 用户编号：2843974 © 2015 Safari Books Online，LLC。此下载文件仅供个人使用，并受到服务条款的约束。任何其他用途均需著作权所有者的事先书面同意。未经授权的使用、复制和/或分发严格禁止并违反适用法律。保留所有权利。


# 第四章：调试

在使用 Node.js 的过程中，不可避免地会遇到一些棘手的错误。因此，让我们预先期望它们并为那一天做好准备。

# 日志

我们可以使用一些方法来调试我们的软件；我们要看的第一种方法是日志记录。记录消息的最简单方法是使用`console`。在大多数先前的示例中，`console`已被用来描述正在发生的事情，而无需查看整个 HTTP 请求和响应，从而使事情变得更加可读和简单。

一个例子是：

```js
var Http = require( 'http' );

Http.createServer( function( request, response ) {
    console.log( 
        'Received request', 
        request.method,
        request.url 
    )

    console.log( 'Returning 200' );

    response.writeHead( 200, { 'Content-Type': 'text/plain' } );
    response.end( 'Hello World\n' );

}).listen( 8000 );

console.log( 'Server running on port 8000' );
```

运行此示例将在控制台上记录请求和响应：

```js
[~/examples/example-6]$ node server.js
Server running on port 8000
Received request GET /
Returning 200
Received request GET /favicon.ico
Returning 200
Received request GET /test
Returning 200
Received request GET /favicon.ico
Returning 200

```

如果我们使用接受中间件的框架，比如 express，我们可以使用一个简单的`npm`包叫做**morgan**；您可以在[`www.npmjs.com/package/morgan`](https://www.npmjs.com/package/morgan)找到该包：

```js
[~/examples/example-7]$ npm install morgan
[~/examples/example-7]$ npm install router

```

我们可以通过使用`require`将其引入我们的代码并将其添加为中间件来使用它：

```js
var Morgan = require( 'morgan' ),
    Router = require( 'router' ),
    Http = require( 'http' );

router = new Router( );

router.use( Morgan( 'tiny' ) ); 

/* Simple server */
Http.createServer( function( request, response ) {
    router( request, response, function( error ) {
        if( !error ) {
            response.writeHead( 404 );  
        } else {
            //Handle errors
            console.log( error.message, error.stack );
            response.writeHead( 400 );
        }
        response.end( '\n' );

    });
}).listen( 8000 );

console.log( 'Server running on port 8000' );

function getInfo ( request, response ) {
    var info = process.versions;

    info = JSON.stringify( info );
    response.writeHead( 200, { 'Content-Type': 'application/json' } );
    response.end( info );
}
router.get( '/info', getInfo );
```

服务器运行时，我们可以在不必为每个处理程序添加日志的情况下查看每个请求和响应：

```js
[~/examples/example-7]$ node server.js
Server running on port 8000
GET /test 404 - - 4.492 ms
GET /favicon.ico 404 - - 2.281 ms
GET /info 200 - - 1.120 ms
GET /info 200 - - 1.120 ms
GET /test 404 - - 0.199 ms
GET /info 200 - - 0.494 ms
GET /test 404 - - 0.162 ms
```

这种类型的日志记录是查看服务器上正在使用的内容以及每个请求花费多长时间的简单方法。在这里，您可以看到第一个请求花费的时间最长，然后它们变得快得多。差异仅为 3 毫秒；如果时间更长，可能会成为一个大问题。

我们可以通过更改我们传递给 morgan 的格式来增加记录的信息，如下所示：

```js
router.use( Morgan( 'combined' ) );
```

通过运行服务器，您将看到更多信息，例如远程用户、请求的日期和时间、返回的内容量以及他们正在使用的客户端。

```js
[~/examples/example-7]$ node server.js 
Server running on port 8000
::1 - - [07/Jun/2015:11:09:03 +0000] "GET /info HTTP/1.1" 200 - "-" "--REMOVED---"

```

时间绝对是一个重要因素，因为在筛选您将获得的大量日志时，它可能会有所帮助。有些错误就像一个定时炸弹，等待在周六晚上 3 点爆炸。如果进程已经死亡并且日志已经消失，所有这些日志对我们来说都毫无意义。还有另一个流行且有用的包叫做`bunyan`，它将许多日志记录方法包装成一个。

Bunyan 带来了可写流的优势，可以将日志写入磁盘上的文件或`stdout`。这使我们能够保存日志以进行事后调试。您可以在[`www.npmjs.com/package/bunyan`](https://www.npmjs.com/package/bunyan)找到有关`bunyan`的更多详细信息。

现在，让我们安装该软件包。我们希望它在本地和全局都安装，以便我们还可以将其用作命令行工具：

```js
 [~/examples/example-8]$ npm install –g bunyan
 [~/examples/example-8]$ npm install bunyan 

```

现在，让我们做一些日志记录：

```js
var Bunyan = require( 'bunyan' ),
    logger;

logger = Bunyan.createLogger( {
    name: 'example-8'
});
logger.info( 'Hello logging' );
```

运行我们的示例：

```js
[~/examples/example-8]$ node index.js
{"name":"example-8","hostname":"macbook.local","pid":2483,"level":30,"msg":"Hello logging","time":"2015-06-07T11:35:13.973Z","v":0}

```

这看起来不太好看，对吧？Bunyan 使用简单的结构化 JSON 字符串保存消息；这使得它易于解析、扩展和阅读。Bunyan 配备了一个 CLI 实用程序，使一切变得美观。

如果我们使用实用程序运行示例，那么我们将看到输出格式很好：

```js
[~/examples/example-8]$ node index.js | bunyan
[2015-06-07T11:38:59.698Z]  INFO: example-8/2494 on macbook.local: Hello logging

```

如果我们添加了更多级别，您将在控制台上看到每个级别的颜色不同，以帮助我们识别它们：

```js
var Bunyan = require( 'bunyan' ),
    logger;
logger = Bunyan.createLogger( {
    name: 'example-8'
});
logger.trace( 'Trace' );
logger.debug( 'Debug' );
logger.info( 'Info' );
logger.warn( 'Warn' );
logger.error( 'Error' );
logger.fatal( 'Fatal' );

logger.fatal( 'We got a fatal, lets exit' );
process.exit( 1 );
```

让我们运行示例：

```js
[~/examples/example-8]$ node index.js | bunyan
[2015-06-07T11:39:55.801Z]  INFO: example-8/2512 on macbook.local: Info
[2015-06-07T11:39:55.811Z]  WARN: example-8/2512 on macbook.local: Warn
[2015-06-07T11:39:55.814Z] ERROR: example-8/2512 on macbook.local: Error
[2015-06-07T11:39:55.814Z] FATAL: example-8/2512 on macbook.local: Fatal
[2015-06-07T11:39:55.814Z] FATAL: example-8/2512 on macbook.local: We got a fatal, lets exit

```

如果注意到，跟踪和调试没有在控制台上输出。这是因为它们用于跟踪程序的流程而不是关键信息，通常非常嘈杂。

我们可以通过在创建记录器时将其作为选项传递来更改我们想要查看的日志级别：

```js
logger = Bunyan.createLogger( {
    name: 'example-8',
    level: Bunyan.TRACE 
});
```

现在，当我们运行示例时：

```js
[~/examples/example-8]$ node index.js | bunyan
[2015-06-07T11:55:40.175Z] TRACE: example-8/2621 on macbook.local: Trace
[2015-06-07T11:55:40.177Z] DEBUG: example-8/2621 on macbook.local: Debug
[2015-06-07T11:55:40.178Z]  INFO: example-8/2621 on macbook.local: Info
[2015-06-07T11:55:40.178Z]  WARN: example-8/2621 on macbook.local: Warn
[2015-06-07T11:55:40.178Z] ERROR: example-8/2621 on macbook.local: Error
[2015-06-07T11:55:40.178Z] FATAL: example-8/2621 on macbook.local: Fatal
[2015-06-07T11:55:40.178Z] FATAL: example-8/2621 on macbook.local: We got a fatal, lets exit

```

通常我们不希望看到低于信息级别的日志，因为任何有用于事后调试的信息都应该使用信息级别或更高级别进行记录。

Bunyan 的 API 非常适用于记录错误和对象的功能。它在其 JSON 输出中保存了正确的结构，可以直接显示：

```js
try {
    ref.go( );
} catch ( error ) {
    logger.error( error );
}
```

让我们运行示例：

```js
[~/examples/example-9]$ node index.js | bunyan
[2015-06-07T12:00:38.700Z] ERROR: example-9/2635 on macbook.local: ref is not defined
 ReferenceError: ref is not defined
 at Object.<anonymous> (~/examples/example-8/index.js:9:2)
 at Module._compile (module.js:460:26)
 at Object.Module._extensions..js (module.js:478:10)
 at Module.load (module.js:355:32)
 at Function.Module._load (module.js:310:12)
 at Function.Module.runMain (module.js:501:10)
 at startup (node.js:129:16)
 at node.js:814:3

```

如果我们查看示例并进行漂亮打印，我们将看到它们将其保存为错误：

```js
[~/examples/example-9]$ npm install -g prettyjson
[~/examples/example-9]$ node index.js | prettyjson
name:     example-9
hostname: macbook.local
pid:      2650
level:    50
err: 
 message: ref is not defined
 name:    ReferenceError
 stack: 
 """
 ReferenceError: ref is not defined
 at Object.<anonymous> (~/examples/example-8/index.js:9:2)
 at Module._compile (module.js:460:26)
 at Object.Module._extensions..js (module.js:478:10)
 at Module.load (module.js:355:32)
 at Function.Module._load (module.js:310:12)
 at Function.Module.runMain (module.js:501:10)
 at startup (node.js:129:16)
 at node.js:814:3
 """
msg:      ref is not defined
time:     2015-06-07T12:02:33.875Z
v:        0

```

这很有用，因为如果您只记录错误，如果您使用了`JSON.stringify`，则会得到一个空对象，或者如果您使用了`toString`，则只会得到消息：

```js
try {
    ref.go( );
} catch ( error ) {
    console.log( JSON.stringify( error ) );
    console.log( error );
    console.log( {
        message: error.message
        name: error.name
        stack: error.stack
    });
}
```

让我们运行示例：

```js
[~/examples/example-10]$ node index.js
{}
[ReferenceError: ref is not defined]
{ message: 'ref is not defined',
 name: 'ReferenceError',
 stack: '--REMOVED--' }

```

使用`logger.error( error )`比`logger.error( { message: error.message /*, ... */ } );`更简单和更清晰。

如前所述，`bunyan`使用流的概念，这意味着我们可以写入文件、`stdout`或任何其他我们希望扩展到的服务。

要写入文件，我们只需要将其添加到设置时传递给`bunyan`的选项中：

```js
var Bunyan = require( 'bunyan' ),
    logger;

logger = Bunyan.createLogger( {
    name: 'example-11',
    streams: [
        {
            level: Bunyan.INFO,
            path: './log.log'   
        }
    ]
});
logger.info( process.versions );
logger.info( 'Application started' );
```

通过运行示例，您将看不到任何日志输出到控制台，而是会写入文件：

```js
 [~/examples/example-11]$ node index.js

```

如果您列出目录中的内容，您会看到已创建了一个新文件：

```js
[~/examples/example-11]$ ls 
index.js     log.log      node_modules

```

如果您读取文件中的内容，您会看到日志已经被写入：

```js
[~/examples/example-11]$ cat log.log
{"name":"example-11","hostname":"macbook.local","pid":3614,"level":30,"http_parser":"2.3","node":"0.12.2","v8":"3.28.73","uv":"1.4.2-node1","zlib":"1.2.8","modules":"14","openssl":"1.0.1m","msg":"","time":"2015-06-07T12:29:46.606Z","v":0}
{"name":"example-11","hostname":"macbook.local","pid":3614,"level":30,"msg":"Application started","time":"2015-06-07T12:29:46.608Z","v":0}

```

我们可以通过`bunyan`运行它，以便将其打印出来：

```js
[~/examples/example-11]$ cat log.log | bunyan
[~/examples/example-11]$ cat log.log | bunyan
[2015-06-07T12:29:46.606Z]  INFO: example-11/3614 on macbook.local:  (http_parser=2.3, node=0.12.2, v8=3.28.73, uv=1.4.2-node1, zlib=1.2.8, modules=14, openssl=1.0.1m)
[2015-06-07T12:29:46.608Z]  INFO: example-11/3614 on macbook.local: Application started

```

现在我们可以记录到文件中，我们还希望能够在消息显示时看到它们。如果我们只是记录到文件中，我们可以使用：

```js
[~/examples/example-11]$ tail -f log.log | bunyan

```

这将记录到正在写入的文件`stdout`；或者我们可以向`bunyan`添加另一个流：

```js
logger = Bunyan.createLogger( {
    name: 'example-11',
    streams: [
        {
            level: Bunyan.INFO,
            path: './log.log'   
        },
        {
            level: Bunyan.INFO,
            stream: process.stdout
        }
    ]
});
```

运行示例将在控制台上显示日志：

```js
[~/examples/example-11]$ node index.js | bunyan
 [2015-06-07T12:37:19.857Z] INFO: example-11/3695 on macbook.local: (http_parser=2.3, node=0.12.2, v8=3.28.73, uv=1.4.2-node1, zlib=1.2.8, modules=14, openssl=1.0.1m) [2015-06-07T12:37:19.860Z] INFO: example-11/3695 on macbook.local: Application started

```

我们还可以看到日志已经附加到文件中：

```js
[~/examples/example-11]$ cat log.log | bunyan
 [2015-06-07T12:29:46.606Z]  INFO: example-11/3614 on macbook.local:  (http_parser=2.3, node=0.12.2, v8=3.28.73, uv=1.4.2-node1, zlib=1.2.8, modules=14, openssl=1.0.1m)
[2015-06-07T12:29:46.608Z]  INFO: example-11/3614 on macbook.local: Application started
[2015-06-07T12:37:19.857Z]  INFO: example-11/3695 on macbook.local:  (http_parser=2.3, node=0.12.2, v8=3.28.73, uv=1.4.2-node1, zlib=1.2.8, modules=14, openssl=1.0.1m)
[2015-06-07T12:37:19.860Z]  INFO: example-11/3695 on macbook.local: Application started

```

很好，现在我们已经记录下来了，我们应该怎么处理呢？

好吧，知道错误发生的地方是有帮助的，当您周围有很多匿名函数时，情况就会变得非常混乱。如果您注意到覆盖 HTTP 服务器的示例中，大多数函数都是命名的。当涉及到回调时，这对于跟踪错误非常有帮助。

让我们看看这个例子：

```js
try {
    a = function( callback ) {
        return function( ) {
            callback( );
        };
    };
    b = function( callback ) {
        return function( ) {
            callback( );
        }
    };
    c = function( callback ) {
        return function( ) {
            throw new Error( "I'm just messing with you" ); 
        };
    };
    a( b( c( ) ) )( );
} catch ( error ) {
    logger.error( error );
}
```

它可能看起来有点混乱，因为它确实如此。让我们运行以下示例：

```js
[~/examples/example-12]$ node index.js | bunyan
 [2015-06-07T12:51:11.665Z] ERROR: example-12/4158 on macbook.local: I'm just messing with you
 Error: I'm just messing with you
 at /Users/fabian/examples/example-12/index.js:19:10
 at /Users/fabian/examples/example-12/index.js:14:4
 at /Users/fabian/examples/example-12/index.js:9:4
 at Object.<anonymous> (/Users/fabian/examples/example-12/index.js:22:16)
 at Module._compile (module.js:460:26)
 at Object.Module._extensions..js (module.js:478:10)
 at Module.load (module.js:355:32)
 at Function.Module._load (module.js:310:12)
 at Function.Module.runMain (module.js:501:10)
 at startup (node.js:129:16)

```

您可以看到我们的代码中没有函数名称，堆栈跟踪也没有命名，这与前几个函数不同。在 Node.js 中，函数的命名将来自变量名或实际函数名。例如，如果您使用`Cls.prototype.func`，那么名称将是`Cls.func`，但如果您使用函数`func`，那么名称将是`func`。

您可以看到这里有一点好处，但是一旦您开始使用涉及`async`回调的模式，这将变得非常有用：

```js
[~/examples/example-13]$ npm install q

```

让我们在回调中抛出一个错误：

```js
var Q = require( 'q' );

Q( )
.then( function() {
    // Promised returned from another function
    return Q( )
    .then( function( ) {
        throw new Error( 'Hello errors' ); 
    });
})
.fail( function( error ) {
    logger.error( error );
});
```

运行我们的示例给我们：

```js
[~/examples/example-13]$ node index.js | bunyan
 [2015-06-07T13:03:57.047Z] ERROR: example-13/4598 on macbook.local: Hello errors
 Error: Hello errors
 at /Users/fabian/examples/example-13/index.js:12:9
 at _fulfilled (/Users/fabian/examples/example-13/node_modules/q/q.js:834:54)

```

这是开始变得难以阅读的地方；为我们的函数分配简单的名称可以帮助我们找到错误的来源：

```js
return Q( )
    .then( function resultFromOtherFunction( ) {
        throw new Error( 'Hello errors' ); 
    });
```

运行示例：

```js
[~/examples/example-13]$ node index.js | bunyan
 [2015-06-07T13:04:45.598Z] ERROR: example-13/4614 on macbook.local: Hello errors
 Error: Hello errors
 at resultFromOtherFunction (/Users/fabian/examples/example-13/index.js:12:9)
 at _fulfilled (/Users/fabian/examples/example-13/node_modules/q/q.js:834:54)

```

# 错误处理

调试的另一个方面是处理和预期错误。我们可以以三种方式处理我们的错误：

+   一个简单的`try`/`catch`

+   在进程级别捕获它们

+   在域级别捕获错误

如果我们期望发生错误并且我们能够在不知道正在执行的结果的情况下继续，那么`try`/`catch`函数就足够了，或者我们可以处理并返回错误，如下所示：

```js
function parseJSONAndUse( input ) {
    var json = null;
    try {
        json = JSON.parse( input );
    } catch ( error ) {
        return Q.reject( new Error( "Couldn't parse JSON" ) );
    }
    return Q( use( json ) );
}
```

另一种捕获错误的简单方法是向您的进程添加错误处理程序；在这个级别捕获的任何错误通常是致命的，应该视为这样处理。进程的退出应该跟随，您应该使用一个包，比如`forever`或`pm2`：

```js
process.on( 'uncaughtException', function errorProcessHandler( error ) {
    logger.fatal( error );
    logger.fatal( 'Fatal error encountered, exiting now' );
    process.exit( 1 );
});
```

在捕获到未捕获的错误后，您应该始终退出进程。未捕获的事实意味着您的应用程序处于未知状态，任何事情都可能发生。例如，您的 HTTP 路由器可能出现错误，无法将更多请求路由到正确的处理程序。您可以在[`nodejs.org/api/process.html#process_event_uncaughtexception`](https://nodejs.org/api/process.html#process_event_uncaughtexception)上阅读更多相关信息。

在全局级别处理错误的更好方法是使用`domain`。使用域，您几乎可以*沙箱*一组异步代码在一起。

让我们在请求服务器的情境下思考。我们发出请求，从数据库中读取数据，调用外部服务，写回数据库，进行一些日志记录，执行一些业务逻辑，并且我们期望来自代码周围所有外部来源的数据都是完美的。然而，在现实世界中并非总是如此，我们无法处理可能发生的每一个错误；此外，我们也不希望因为一个非常特定的请求出现错误而导致整个服务器崩溃。这就是我们需要域的地方。

让我们看下面的例子：

```js
var Domain = require( 'domain' ),
    domain;

domain = Domain.create( );

domain.on( 'error', function( error ) {
    console.log( 'Domain error', error.message );
});

domain.run( function( ) {
    // Run code inside domain
    console.log( process.domain === domain );
    throw new Error( 'Error happened' ); 
});
```

让我们运行这段代码：

```js
[~/examples/example-14]$ node index.js
true
Domain error Error happened

```

这段代码存在问题；然而，由于我们是同步运行的，我们仍然将进程置于一个破碎的状态。这是因为错误冒泡到了节点本身，然后传递给了活动域。

当我们在异步回调中创建域时，我们可以确保进程可以继续。我们可以通过使用`process.nextTick`来模拟这一点：

```js
process.nextTick( function( ) {
    domain.run( function( ) {
        throw new Error( 'Error happened' );
    });
    console.log( "I won't execute" );
}); 

process.nextTick( function( ) {
    console.log( 'Next tick happend!' );
});

console.log( 'I happened before everything else' );
```

运行示例应该显示正确的日志：

```js
[~/examples/example-15]$ node index.js
I happened before everything else
Domain error Error happened
Next tick happend!

```

# 摘要

在本章中，我们介绍了一些事后调试方法，帮助我们发现错误，包括日志记录、命名惯例和充分的错误处理。

在下一章中，我们将介绍如何配置我们的应用程序。

为 Bentham Chang 准备，Safari ID 为 bentham@gmail.com 用户编号：2843974 © 2015 Safari Books Online，LLC。此下载文件仅供个人使用，并受到服务条款的约束。任何其他使用都需要版权所有者的事先书面同意。未经授权的使用、复制和/或分发严格禁止并违反适用法律。保留所有权利。
