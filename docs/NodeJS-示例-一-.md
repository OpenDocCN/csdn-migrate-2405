# NodeJS 示例（一）

> 原文：[`zh.annas-archive.org/md5/59094B51B116DA7DDAC7E4359313EBB3`](https://zh.annas-archive.org/md5/59094B51B116DA7DDAC7E4359313EBB3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Node.js 是当今最流行的技术之一。其不断增长的社区以每天产生大量的模块而闻名。这些模块可以作为服务器端应用程序的构建模块。我们在服务器端和客户端都使用相同的语言（JavaScript）使得开发更加流畅。

本书包含 11 章，提供了构建社交网络的逐步指南。像 Facebook 和 Twitter 这样的系统是复杂且具有挑战性的开发。我们将了解 Node.js 的能力，但如果能在具体的上下文中进行学习，将会更加有趣。本书涵盖了基本阶段，如架构和资产管道的管理，并讨论了用户友谊和实时通信等功能。

# 本书涵盖内容

第一章, *Node.js 基础*，教授了 Node.js 的基础知识，技术背后的原理，以及其模块管理系统和包管理器。

第二章, *构建项目*，揭示了 Gulp 等构建系统的强大功能。在开始构建我们的社交网络之前，我们将规划项目。我们将讨论测试驱动开发和模型-视图-控制器模式。本章将涵盖启动项目所需的 Node.js 模块。

第三章, *管理资产*，涵盖了构建 Web 应用程序。因此，我们必须处理 HTML、CSS、JavaScript 和图像。在本章中，我们将介绍资产服务背后的过程。

第四章, *开发模型-视图-控制器层*，讨论了我们应用程序的基本结构。我们将创建视图、模型和控制器的类。在接下来的几章中，我们将以这些类为基础。

第五章, *用户管理*，讨论了实现用户注册、授权和配置管理。

第六章, *添加友谊功能*，解释了现代社交网络背后的主要概念之一——友谊。找到朋友并关注他们的动态是一个重要部分。本章专门讨论了用户之间的这种关系的发展。

第七章, *发布内容*，指出每个社交网络的支柱是用户添加到系统中的内容。在本章中，我们将实现发布内容的过程。

第八章, *创建页面和活动*，指出为用户提供创建页面和活动的能力将使我们的社交网络更加有趣。用户可以添加任意数量的页面。其他用户将能够加入我们网络中新创建的地方。我们还将添加代码来收集统计数据。

第九章, *标记、分享和点赞*，解释了除了发布和审查内容之外，社交网络的用户还应该能够标记、分享和点赞帖子。本章专门讨论了这些功能的开发。

第十章, *添加实时聊天*，讨论了用户在当今世界对即时了解一切的期望。他们希望能够更快地相互交流。在本章中，我们将开发一个实时聊天功能，使用户可以即时发送消息。

第十一章 *测试用户界面* 解释了完成工作的重要性，但覆盖工作功能的测试也很重要。在本章中，我们将看到如何测试用户界面。

# 本书所需内容

本书基于 Node.js 版本 0.10.36。我们还将使用 MongoDB（[`www.mongodb.org/`](http://www.mongodb.org/)）作为数据库，Ractive.js（[`www.ractivejs.org/`](http://www.ractivejs.org/)）作为客户端框架。

# 本书适合谁

如果您了解 JavaScript 并想了解如何在后端使用它，那么本书适合您。它将引导您创建一个相当复杂的社交网络。您将学习如何使用数据库并创建实时通信渠道。

# 约定

在本书中，您会发现一些区分不同信息类型的文本样式。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄都显示如下： "如果 Ractive 组件有一个`friends`属性，那么我们将渲染一个用户列表。"

代码块设置如下：

```js
<li class="right"><a on-click="goto:logout">Logout</a></li>
<li class="right"><a on-click="goto:profile">Profile</a></li>
<li class="right"><a on-click="goto:find-friends">Find  friends</a></li>
```

任何命令行输入或输出都以如下形式书写：

```js
sudo apt-get update
sudo apt-get install nodejs
sudo apt-get install npm

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，比如菜单或对话框中的单词，会以这样的形式出现在文本中：“它显示他们的名字和一个**添加为好友**按钮。”

### 提示

提示和技巧会出现在这样的形式中。


# 第一章：Node.js 基础知识

Node.js 是当今最流行的 JavaScript 驱动技术之一。它是由 Ryan Dahl 于 2009 年创建的，自那时起，该框架已经发展成为一个完善的生态系统。它的包管理器中充满了有用的模块，全世界的开发人员已经开始在他们的生产环境中使用 Node.js。在本章中，我们将学习以下内容：

+   Node.js 构建模块

+   环境的主要功能

+   Node.js 的包管理

# 理解 Node.js 架构

在过去，Ryan 对开发网络应用程序很感兴趣。他发现大多数高性能服务器遵循类似的概念。它们的架构类似于事件循环，并且它们使用非阻塞的输入/输出操作。这些操作允许其他处理活动在进行中的任务完成之前继续进行。如果我们想处理成千上万个同时的请求，这些特征是非常重要的。

大多数用 Java 或 C 编写的服务器使用多线程。它们在新线程中处理每个请求。Ryan 决定尝试一些不同的东西——单线程架构。换句话说，服务器收到的所有请求都由单个线程处理。这可能听起来像一个不可扩展的解决方案，但 Node.js 绝对是可扩展的。我们只需运行不同的 Node.js 进程，并使用一个负载均衡器来在它们之间分发请求。

Ryan 需要一个基于事件循环的快速工作的东西。正如他在其中一次演讲中指出的，像谷歌、苹果和微软这样的大公司投入了大量时间开发高性能的 JavaScript 引擎。它们每年都变得越来越快。在那里，事件循环架构得到了实现。JavaScript 近年来变得非常流行。社区和成千上万的开发人员准备贡献，让 Ryan 考虑使用 JavaScript。这是 Node.js 架构的图表：

![理解 Node.js 架构](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00157.jpeg)

总的来说，Node.js 由三部分组成：

+   V8 是谷歌的 JavaScript 引擎，用于 Chrome 浏览器（[`developers.google.com/v8/`](https://developers.google.com/v8/)）

+   线程池是处理文件输入/输出操作的部分。所有阻塞系统调用都在这里执行（[`software.schmorp.de/pkg/libeio.html`](http://software.schmorp.de/pkg/libeio.html)）

+   事件循环库（[`software.schmorp.de/pkg/libev.html`](http://software.schmorp.de/pkg/libev.html)）

在这三个模块之上，我们有几个绑定，它们公开了低级接口。Node.js 的其余部分都是用 JavaScript 编写的。几乎所有我们在文档中看到的内置模块的 API 都是用 JavaScript 编写的。

# 安装 Node.js

安装 Node.js 的一种快速简便的方法是访问[`nodejs.org/download/`](https://nodejs.org/download/)并下载适合您操作系统的安装程序。对于 OS X 和 Windows 用户，安装程序提供了一个漂亮、易于使用的界面。对于使用 Linux 作为操作系统的开发人员，Node.js 可以在 APT 软件包管理器中找到。以下命令将设置 Node.js 和**Node Package Manager**（**NPM**）：

```js
sudo apt-get update
sudo apt-get install nodejs
sudo apt-get install npm

```

## 运行 Node.js 服务器

Node.js 是一个命令行工具。安装后，`node`命令将在我们的终端上可用。`node`命令接受几个参数，但最重要的是包含我们的 JavaScript 的文件。让我们创建一个名为`server.js`的文件，并将以下代码放入其中：

```js
var http = require('http');
http.createServer(function (req, res) {
   res.writeHead(200, {'Content-Type': 'text/plain'});
   res.end('Hello World\n');
}).listen(9000, '127.0.0.1');
console.log('Server running at http://127.0.0.1:9000/');
```

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt Publishing 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，文件将直接通过电子邮件发送给您。

如果你在控制台中运行`node ./server.js`，你将拥有 Node.js 服务器在运行。它在本地（`127.0.0.1`）的端口`9000`上监听传入的请求。前面代码的第一行需要内置的`http`模块。在 Node.js 中，我们有`require`全局函数，它提供了使用外部模块的机制。我们将看到如何定义我们自己的模块。之后，脚本继续使用`http`模块上的`createServer`和`listen`方法。在这种情况下，模块的 API 被设计成我们可以像在 jQuery 中那样链接这两种方法。

第一个（`createServer`）接受一个函数，也称为回调，每当有新的请求到达服务器时就会调用它。第二个使服务器监听。

在浏览器中得到的结果如下：

![运行 Node.js 服务器](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00158.jpeg)

# 定义和使用模块

作为一种语言，JavaScript 没有定义真正的类的机制。事实上，JavaScript 中的一切都是对象。我们通常从一个对象继承属性和函数到另一个对象。幸运的是，Node.js 采用了**CommonJS**定义的概念——这是一个为 JavaScript 指定生态系统的项目。

我们将逻辑封装在模块中。每个模块都在自己的文件中定义。让我们用一个简单的例子来说明一切是如何工作的。假设我们有一个代表这本书的模块，并将其保存在一个名为`book.js`的文件中：

```js
// book.js
exports.name = 'Node.js by example';
exports.read = function() {
   console.log('I am reading ' + exports.name);
}
```

我们定义了一个公共属性和一个公共函数。现在，我们将使用`require`来访问它们：

```js
// script.js
var book = require('./book.js');
console.log('Name: ' + book.name);
book.read();
```

现在我们将创建另一个名为`script.js`的文件。为了测试我们的代码，我们将运行`node ./script.js`。终端中的结果如下：

![定义和使用模块](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00159.jpeg)

除了`exports`，我们还有`module.exports`可用。两者之间有区别。看看下面的伪代码。它说明了 Node.js 如何构建我们的模块：

```js
var module = { exports: {} };
var exports = module.exports;
// our code
return module.exports;
```

因此，最终返回`module.exports`，这就是`require`产生的。我们应该小心，因为如果在某个时刻我们直接应用一个值到`exports`或`module.exports`，我们可能得不到我们需要的东西。就像在下面的片段末尾，我们将一个函数设置为一个值，这个函数暴露给外部世界：

```js
exports.name = 'Node.js by example';
exports.read = function() {
   console.log('Iam reading ' + exports.name);
}
module.exports = function() {  ... }
```

在这种情况下，我们无法访问`.name`和`.read`。如果我们再次尝试执行`node ./script.js`，我们将得到以下输出：

![定义和使用模块](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00160.jpeg)

为了避免这种问题，我们应该坚持两种选项之一——`exports`或`module.exports`——但要确保我们没有两者都有。

我们还应该记住，默认情况下，`require`会缓存返回的对象。因此，如果我们需要两个不同的实例，我们应该导出一个函数。这是一个提供 API 方法来评价书籍并且不正常工作的`book`类的版本：

```js
// book.js
var ratePoints = 0;
exports.rate = function(points) {
   ratePoints = points;
}
exports.getPoints = function() {
   return ratePoints;
}
```

让我们创建两个实例，并用不同的`points`值对书籍进行评分：

```js
// script.js
var bookA = require('./book.js');
var bookB = require('./book.js');
bookA.rate(10);
bookB.rate(20);
console.log(bookA.getPoints(), bookB.getPoints());
```

逻辑上的响应应该是`10 20`，但我们得到了`20 20`。这就是为什么导出一个每次产生不同对象的函数是一个常见的做法：

```js
// book.js
module.exports = function() {
   var ratePoints = 0;
   return {
      rate: function(points) {
         ratePoints = points;
      },
      getPoints: function() {
         return ratePoints;
      }
   }
}
```

现在，我们还应该有`require('./book.js')()`，因为`require`返回的是一个函数，而不再是一个对象。

# 管理和分发包

一旦我们理解了`require`和`exports`的概念，我们应该开始考虑将我们的逻辑分组到构建块中。在 Node.js 世界中，这些块被称为**模块**（或**包**）。Node.js 受欢迎的原因之一就是其包管理。

Node.js 通常带有两个可执行文件—`node`和`npm`。NPM 是一个命令行工具，用于下载和上传 Node.js 包。官方网站[`npmjs.org/`](https://npmjs.org/)充当中央注册表。当我们通过`npm`命令创建一个包时，我们将其存储在那里，以便其他开发人员可以使用它。

## 创建模块

每个模块都应该存在于自己的目录中，该目录还包含一个名为`package.json`的元数据文件。在这个文件中，我们至少设置了两个属性—`name`和`version`：

```js
{
   "name": "my-awesome-nodejs-module",
   "version": "0.0.1"
}
```

我们可以在同一个目录中放置任何我们喜欢的代码。一旦我们将模块发布到 NPM 注册表并有人安装它，他/她将得到相同的文件。例如，让我们添加一个`index.js`文件，这样我们的包中就有两个文件了：

```js
// index.js
console.log('Hello, this is my awesome Node.js module!');
```

我们的模块只做一件事—在控制台上显示一个简单的消息。现在，要上传模块，我们需要导航到包含`package.json`文件的目录，并执行`npm publish`。这是我们应该看到的结果：

![创建模块](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00161.jpeg)

我们准备好了。现在我们的小模块已经列在 Node.js 包管理器的网站上，每个人都可以下载它。

## 使用模块

总的来说，有三种使用已创建的模块的方法。所有三种方法都涉及包管理器：

+   我们可以手动安装特定的模块。假设我们有一个名为`project`的文件夹。我们打开文件夹并运行以下命令：

```js
npm install my-awesome-nodejs-module

```

管理器会自动下载模块的最新版本，并将其放在一个名为`node_modules`的文件夹中。如果我们想要使用它，就不需要引用确切的路径。默认情况下，Node.js 在需要时会检查`node_modules`文件夹。因此，只需`require('my-awesome-nodejs-module')`就足够了。

+   全局安装模块是一种常见的做法，特别是当涉及到使用 Node.js 制作命令行工具时。它已经成为一种易于使用的技术来开发这样的工具。我们创建的小模块并不是作为一个命令行程序，但我们仍然可以通过运行以下代码全局安装它：

```js
npm install my-awesome-nodejs-module -g

```

注意最后的`-g`标志。这是告诉管理器我们希望这个模块是全局的方式。当进程完成时，我们就没有了`node_modules`目录。`my-awesome-nodejs-module`文件夹存储在系统的另一个位置。为了能够使用它，我们必须在`package.json`中添加另一个属性，但我们将在下一节中更多地讨论这个问题。

+   解决依赖关系是 Node.js 包管理器的关键特性之一。每个模块可以有任意多的依赖关系。这些依赖关系只是已上传到注册表的其他 Node.js 模块。我们所要做的就是在`package.json`文件中列出所需的包：

```js
{
    "name": "another-module", 
    "version": "0.0.1", 
    "dependencies": {
        "my-awesome-nodejs-module": "0.0.1"   
    }
}
```

现在我们不需要明确指定模块，只需执行`npm install`来安装我们的依赖。管理器会读取`package.json`文件，并再次将我们的模块保存在`node_modules`目录中。使用这种技术是很好的，因为我们可以一次添加多个依赖并一次性安装它们。这也使得我们的模块可传输和自我记录。无需向其他程序员解释我们的模块由什么组成。

## 更新我们的模块

让我们将我们的模块转换成一个命令行工具。一旦我们这样做，用户就可以在他们的终端中使用`my-awesome-nodejs-module`命令。我们需要在`package.json`文件中做两个更改：

```js
{
   "name": "my-awesome-nodejs-module",
   "version": "0.0.2",
   "bin": "index.js"
}
```

添加了一个新的`bin`属性。它指向我们应用程序的入口点。我们有一个非常简单的例子，只有一个文件—`index.js`。

我们必须进行的另一个更改是更新`version`属性。在 Node.js 中，模块的版本起着重要作用。如果回顾一下，我们会发现在`package.json`文件中描述依赖关系时，我们指出了确切的版本。这确保了在将来，我们将获得具有相同 API 的相同模块。`version`属性中的每个数字都有意义。包管理器使用**语义化版本 2.0.0**（[`semver.org/`](http://semver.org/)）。其格式为*MAJOR.MINOR.PATCH*。因此，作为开发人员，我们应该递增以下内容：

+   如果我们进行不兼容的 API 更改，则为 MAJOR 号

+   如果我们以向后兼容的方式添加新功能/特性，则为 MINOR 号

+   如果我们有错误修复，则为 PATCH 号

有时，我们可能会看到版本号如`2.12.*`。这意味着开发人员有兴趣使用确切的 MAJOR 和 MINOR 版本，但他/她同意将来可能会有错误修复。也可以使用值如`>=1.2.7`来匹配任何等于或大于的版本，例如`1.2.7`，`1.2.8`或`2.5.3`。

我们更新了`package.json`文件。下一步是将更改发送到注册表。这可以在包含 JSON 文件的目录中再次使用`npm publish`来完成。结果将是类似的。我们将在屏幕上看到新的**0.0.2**版本号：

![更新我们的模块](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00162.jpeg)

在此之后，我们可以运行`npm install my-awesome-nodejs-module -g`，新版本的模块将安装在我们的机器上。不同之处在于现在我们有`my-awesome-nodejs-module`命令可用，如果运行它，它会显示在`index.js`文件中编写的消息：

![更新我们的模块](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00163.jpeg)

# 介绍内置模块

Node.js 被认为是一种可以用来编写后端应用程序的技术。因此，我们需要执行各种任务。幸运的是，我们可以使用一堆有用的内置模块。

## 使用 HTTP 模块创建服务器

我们已经使用了 HTTP 模块。这可能是 Web 开发中最重要的模块，因为它启动一个在特定端口上监听的服务器：

```js
var http = require('http');
http.createServer(function (req, res) {
   res.writeHead(200, {'Content-Type': 'text/plain'});
   res.end('Hello World\n');
}).listen(9000, '127.0.0.1');
console.log('Server running at http://127.0.0.1:9000/');
```

我们有一个`createServer`方法，返回一个新的 web 服务器对象。在大多数情况下，我们运行`listen`方法。如果需要，有`close`，它可以停止服务器接受新连接。我们传递的回调函数总是接受`request`（`req`）和`response`（`res`）对象。我们可以使用第一个来检索有关传入请求的信息，例如`GET`或`POST`参数。

## 读取和写入文件

负责读写过程的模块称为`fs`（它源自**文件系统**）。以下是一个简单的例子，说明如何将数据写入文件：

```js
var fs = require('fs');
fs.writeFile('data.txt', 'Hello world!', function (err) {
   if(err) { throw err; }
   console.log('It is saved!');
});
```

大多数 API 函数都有同步版本。前面的脚本可以用`writeFileSync`编写，如下所示：

```js
fs.writeFileSync('data.txt', 'Hello world!');
```

然而，在此模块中使用函数的同步版本会阻塞事件循环。这意味着在操作文件系统时，我们的 JavaScript 代码会被暂停。因此，在 Node 中，尽可能使用方法的异步版本是最佳实践。

文件的读取几乎是相同的。我们应该以以下方式使用`readFile`方法：

```js
fs.readFile('data.txt', function(err, data) {
   if (err) throw err;
   console.log(data.toString());
});
```

## 使用事件

观察者设计模式在 JavaScript 世界中被广泛使用。这是我们系统中的对象订阅其他对象发生的变化。Node.js 有一个内置模块来管理事件。这里是一个简单的例子：

```js
var events = require('events');
var eventEmitter = new events.EventEmitter();
var somethingHappen = function() {
   console.log('Something happen!');
}
eventEmitter
.on('something-happen', somethingHappen)
.emit('something-happen');
```

`eventEmitter`对象是我们订阅的对象。我们使用`on`方法来实现这一点。`emit`函数触发事件，执行`somethingHappen`处理程序。

`events`模块提供了必要的功能，但我们需要在自己的类中使用它。让我们从上一节的书籍想法中获取并使其与事件一起工作。一旦有人对书进行评分，我们将以以下方式分派事件：

```js
// book.js
var util = require("util");
var events = require("events");
var Class = function() { };
util.inherits(Class, events.EventEmitter);
Class.prototype.ratePoints = 0;
Class.prototype.rate = function(points) {
   ratePoints = points;
   this.emit('rated');
};
Class.prototype.getPoints = function() {
   return ratePoints;
}
module.exports = Class;
```

我们想要继承`EventEmitter`对象的行为。在 Node.js 中实现这一点的最简单方法是使用实用程序模块（`util`）及其`inherits`方法。定义的类可以像这样使用：

```js
var BookClass = require('./book.js');
var book = new BookClass();
book.on('rated', function() {
   console.log('Rated with ' + book.getPoints());
});
book.rate(10);
```

我们再次使用`on`方法订阅`rated`事件。`book`类在我们设置了分数后显示了这条消息。然后终端显示了**Rated with 10**文本。

## 管理子进程

Node.js 有一些我们无法做到的事情。我们需要使用外部程序来完成相同的任务。好消息是，我们可以在 Node.js 脚本中执行 shell 命令。例如，假设我们想要列出当前目录中的文件。文件系统 API 确实提供了相应的方法，但如果我们能够获得`ls`命令的输出就更好了：

```js
// exec.js
var exec = require('child_process').exec;
exec('ls -l', function(error, stdout, stderr) {
    console.log('stdout: ' + stdout);
    console.log('stderr: ' + stderr);
    if (error !== null) {
        console.log('exec error: ' + error);
    }
});
```

我们使用的模块叫做`child_process`。它的`exec`方法接受所需的命令作为字符串和一个回调。`stdout`项是命令的输出。如果我们想处理错误（如果有的话），我们可以使用`error`对象或`stderr`缓冲区数据。前面的代码产生了以下截图：

![管理子进程](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00164.jpeg)

除了`exec`方法，我们还有`spawn`。它有点不同，但非常有趣。想象一下，我们有一个命令不仅完成了它的工作，还输出了结果。例如，`git push`可能需要几秒钟，可能会不断向控制台发送消息。在这种情况下，`spawn`是一个很好的选择，因为我们可以访问一个流：

```js
var spawn = require('child_process').spawn;
var command = spawn('git', ['push', 'origin', 'master']);
command.stdout.on('data', function (data) {
   console.log('stdout: ' + data);
});
command.stderr.on('data', function (data) {
   console.log('stderr: ' + data);
});
command.on('close', function (code) {
   console.log('child process exited with code ' + code);
});
```

这里，`stdout`和`stderr`都是流。它们会分发事件，如果我们订阅了这些事件，我们将得到命令的确切输出。在前面的例子中，我们运行了`git push origin master`并将完整的命令响应发送到控制台。

# 摘要

现在很多公司都在使用 Node.js。这证明它已经足够成熟，可以在生产环境中使用。在本章中，我们了解了这项技术的基本原理。我们涵盖了一些常用的情况。在下一章中，我们将从我们示例应用程序的基本架构开始。这不是一个简单的应用程序。我们将构建我们自己的社交网络。


# 第二章：设计项目

软件开发是一个复杂的过程。我们不能只是开始编写一些代码，然后期望能够达到我们的目标。我们需要计划和定义我们应用程序的基础。换句话说，在你开始实际编写脚本之前，你必须设计项目结构。在本章中，我们将涵盖以下内容：

+   Node.js 应用程序的基本层

+   使用任务运行器和构建系统

+   测试驱动开发

+   模型-视图-控制器模式

+   REST API 概念

# 介绍应用程序的基本层

如果我们计划建造一座房子，我们可能会想要从一个非常好的基础开始。如果建筑的基础不牢固，我们就不能建造第一层和第二层。

然而，对于软件来说，情况有些不同。我们可以在没有良好基础的情况下开始开发代码。我们称之为**蛮力驱动开发**。在这种情况下，我们会一次又一次地生产功能，而实际上并不关心我们代码的质量。结果可能在开始时有效，但从长远来看，它会消耗更多的时间，可能还有金钱。众所周知，软件只是放置在彼此之上的构建块。如果我们程序的下层设计不好，那么整个解决方案都会因此而受到影响。

让我们考虑一下我们的项目——我们想用 Node.js 构建的社交网络。我们从一个简单的代码开始，就像这样：

```js
var http = require('http');
http.createServer(function (req, res) {
   res.writeHead(200, {'Content-Type': 'text/plain'});
   res.end('Hello World\n');
}).listen(1337, '127.0.0.1');
console.log('Server running at http://127.0.0.1:1337/');
```

你可能注意到的第一件事是，你向用户提供了文本，但你可能想要提供文件内容。Node.js 类似于 PHP。然而，有一个根本的区别。PHP 需要一个接受请求并将其传递给 PHP 解释器的服务器。然后，PHP 代码被处理，响应再次由服务器传递给用户。在 Node.js 世界中，我们没有一个单独的外部服务器。Node.js 本身扮演着这个角色。开发人员需要处理传入的请求，并决定如何处理它们。

如果我们拿上面的代码并假设我们有一个包含基本 HTML 布局的`page.html`和一个包含 CSS 样式的`styles.css`文件，我们的下一步将是这样的（查看书中代码示例的`planning`文件夹）：

```js
var http = require('http');
var fs = require('fs');
http.createServer(function (req, res) {
   var content = '';
   var type = '';
   if(req.url === '/') {
      content = fs.readFileSync('./page.html');
      type = 'text/html';
   } else if(req.url === '/styles.css') {
      content = fs.readFileSync('./styles.css');
      type = 'text/css';
   }
   res.writeHead(200, {'Content-Type': type});
   res.end(content + '\n');
}).listen(1337, '127.0.0.1');
console.log('Server running at http://127.0.0.1:1337/');
```

我们将检查传入请求的 URL。如果我们只是打开`http://127.0.0.1:1337/`，我们将收到`page.html`的代码作为响应。如果`page.html`文件中有一个请求`style.css`的`<link>`标签，浏览器也会为此发出请求。URL 不同，但它再次被`if`子句捕获，然后提供适当的内容。

现在这样做还可以，但我们可能需要提供不是两个而是许多文件。我们不想描述所有这些文件。因此，这个过程应该被优化。每个 Node.js 服务器的第一层通常处理路由。它解析请求的 URL 并决定要做什么。如果我们需要传递静态文件，那么我们最终会将处理逻辑放在一个外部模块中，该模块找到文件，读取它们，并以适当的内容类型发送响应。这可以成为我们架构的第二层。

除了交付文件，我们还需要编写一些后端逻辑。这将是第三层。同样，根据 URL，我们将执行与业务逻辑相关的一些操作，如下所示：

```js
var http = require('http');
var fs = require('fs');
http.createServer(function (req, res) {
   var content = '';
   var type = '';
   if(req.url === '/') {
      content = fs.readFileSync('./page.html');
      type = 'text/html';
   } else if(req.url === '/styles.css') {
      content = fs.readFileSync('./styles.css');
      type = 'text/css';
   } else if(req.url === '/api/user/new') {
         // Do actions like
      // reading POST parameters
      // storing the user into the database
      content = '{"success": true}';
      type = 'application/json';
   }
   res.writeHead(200, {'Content-Type': type});
   res.end(content + '\n');
}).listen(1337, '127.0.0.1');
console.log('Server running at http://127.0.0.1:1337/');
```

请注意我们返回了 JSON 数据。因此，我们的 Node.js 服务器现在充当 API。我们将在本章末讨论这一点。

下面的图表显示了我们刚刚谈到的三个层次：

![介绍应用程序的基本层](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00165.jpeg)

这些将是我们应用程序的主要层。在接下来的章节中，我们将对它们进行处理。但在那之前，让我们看看在达到那一点之前我们还需要做什么其他工作。

# 任务运行器和构建系统

除了运行 Node.js 服务器的实践之外，还有其他与 Web 开发任务相关的最佳实践可以考虑。我们正在构建一个 Web 应用程序。因此，我们有客户端 JavaScript 和 CSS 需要以最佳方式交付。换句话说，为了提高网站的性能，我们需要将所有 JavaScript 合并到一个文件中并进行压缩。对 CSS 样式表也是如此。如果这样做，浏览器将减少对服务器的请求。

Node.js 是一个常见的命令行实用工具，除非你想要运行 Web 服务器。有许多可用于打包和优化资产的模块。很棒的是有任务运行器和构建系统可以帮助你管理这些过程。

## 介绍 Grunt

Grunt 是基于 Node.js 的最流行的任务运行器之一。它可以在包管理器注册表中找到，并且可以通过以下命令安装：

```js
npm install -g grunt-cli

```

一旦我们在终端中运行了这个命令，我们就会得到一个全局的`grunt`命令供我们使用。我们需要在项目的根目录中创建一个`Gruntfile.js`文件，这是我们定义任务的地方。通过任务，我们指的是诸如文件合并和文件压缩等我们想要对特定文件执行的操作。以下是一个简单的`Gruntfile.js`：

```js
module.exports = function(grunt) {
   grunt.initConfig({
      concat: {
         javascript: {
            src: 'src/**/*.js',
            dest: 'build/scripts.js'
         }
      }
   });
   grunt.loadNpmTasks('grunt-contrib-concat');
   grunt.registerTask('default', ['concat']);
}
```

在本书的第一章中，我们看到了如何定义 Node.js 模块。Grunt 所需的配置只是一个简单的模块。我们导出一个函数，该函数接受一个包含运行器所有公共 API 函数的`grunt`对象。在`initConfig`块中，我们放置我们的操作，而使用`registerTask`，我们组合操作和任务。至少应该有一个任务使用名称`default`进行定义。这是如果我们在终端中不传递额外参数时 Grunt 运行的内容。

在前面的例子中还有一个最后使用的函数——`loadNpmTasks`。Grunt 的真正强大之处在于我们有数百个可用的插件。`grunt`命令是一个接口，你可以用它来控制这些插件完成真正的工作。由于它们都在 Node.js 包管理器中注册，我们需要在`package.json`文件中包含它们。对于前面的代码，我们需要以下内容：

```js
{
   "name": "GruntjsTest",
   "version": "0.0.1",
   "description": "GruntjsTest",
   "dependencies": {},
   "devDependencies": {
      "grunt-contrib-concat": "0.3.0"
   }
}
```

让我们继续向我们的 Grunt 设置添加另外两个功能。一旦我们将 JavaScript 合并，我们可能会希望有编译文件的缩小版本；`grunt-contrib-uglify`就是完成这项工作的模块：

```js
module.exports = function(grunt) {
   grunt.initConfig({
      concat: {
         javascript: {
            src: 'src/**/*.js',
            dest: 'build/scripts.js'
         }
      },
      uglify: {
         javascript: {
            files: {
               'build/scripts.min.js': '<%= concat.javascript.dest %>'
            }
         }
      }
   });
   grunt.loadNpmTasks('grunt-contrib-concat');
   grunt.loadNpmTasks('grunt-contrib-uglify');
   grunt.registerTask('default', ['concat', 'uglify']);
}
```

我们应该提到`uglify`任务应该在`concat`之后运行，因为它们彼此依赖。还有一个快捷方式——`<%= concat.javascript.dest %>`。我们使用这样的表达式来简化`Gruntfile.js`文件的维护。

我们有 Grunt 任务来处理我们的 JavaScript。但是，如果我们每次进行更改都必须返回控制台并运行`grunt`，那将会很烦人。这就是为什么存在`grunt-contrib-watch`的原因。这是一个模块，它会监视文件更改并运行我们的任务。以下是更新后的`Gruntfile.js`：

```js
module.exports = function(grunt) {
   grunt.initConfig({
      concat: {
         javascript: {
            src: 'src/**/*.js',
            dest: 'build/scripts.js'
         }
      },
      uglify: {
         javascript: {
            files: {
               'build/scripts.min.js': '<%= concat.javascript.dest %>'
            }
         }
      },
      watch: {
         javascript: {
            files: ['<%= concat.javascript.src %>'],
            tasks: ['concat', 'uglify']
         }
      }
   });
   grunt.loadNpmTasks('grunt-contrib-concat');
   grunt.loadNpmTasks('grunt-contrib-uglify');
   grunt.loadNpmTasks('grunt-contrib-watch');
   grunt.registerTask('default', ['concat', 'uglify', 'watch']);
}
```

为了让脚本工作，我们还需要运行`npm install grunt-contrib-watch grunt-contrib-uglify –save`。这个命令将安装模块并更新`package.json`文件。

下面的截图显示了当我们调用`grunt`命令时终端中的结果：

![介绍 Grunt](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00166.jpeg)

现在我们可以看到我们的任务是如何运行的，监视任务也开始了。一旦我们保存了一个被监视的文件的更改，合并和压缩操作都会再次触发。

# 发现 Gulp

Gulp 是一个自动化常见任务的构建系统。与 Grunt 一样，我们可以组合我们的资产管道。但是，两者之间有一些区别：

+   我们仍然有一个配置文件，但它被称为`gulpfile.js`。

+   Gulp 是基于流的工具。它在工作时不会在磁盘上存储任何东西。Grunt 需要创建临时文件以便将数据从一个任务传递到另一个任务，但是 Gulp 将数据保存在内存中。

+   Gulp 遵循**代码优于配置**的原则。在`gulpfile.js`文件中，我们像编写常规的 Node.js 脚本一样编写我们的任务。我们将在一分钟内看到这个演示。

要使用 Gulp，我们必须先安装它。以下命令将全局设置该工具：

```js
npm install -g gulp

```

我们将使用一些插件——`gulp-concat`、`gulp-uglify`和`gulp-rename`。将它们添加到我们的`package.json`文件中后，运行`npm install`以安装它们。

下一步是在项目的根目录中创建一个新的`gulpfile.js`文件，并运行`gulp`命令。让我们保留上一节中的相同任务，并将它们转换为 Gulp：

```js
var gulp = require('gulp');
var concat = require('gulp-concat');
var uglify = require('gulp-uglify');
var rename = require('gulp-rename');

gulp.task('js', function() {
   gulp.src('./src/**/*.js')
   .pipe(concat('scripts.js'))
   .pipe(gulp.dest('./build/'))
   .pipe(rename({suffix: '.min'}))
   .pipe(uglify())
   .pipe(gulp.dest('./build/'))
});
gulp.task('watchers', function() {
   gulp.watch('src/**/*.js', ['js']);
});
gulp.task('default', ['js', 'watchers']);
```

文件顶部有几个`require`调用。我们初始化了 Gulp 的公共 API（`gulp`对象）和我们想要执行的操作所需的插件。我们需要将所有这些模块添加到我们的`package.json`文件中。在那之后，我们使用(`task_name`, `callback_function`)语法定义了三个任务：

+   `js`：这是获取我们的 JavaScript 文件的任务，将它们传输到连接文件的插件，并保存结果。然后我们将数据发送到`uglify`模块，对我们的代码进行最小化处理，最后保存一个带有`.min`后缀的新文件。

+   `watchers`：通过这个任务，我们可以监视我们的 JavaScript 文件的更改并运行`js`任务。

+   `default`：默认情况下，Gulp 运行我们文件的这部分。我们可以通过在终端中的`gulp`调用中添加一个参数来指定任务。

上述脚本的结果应该如下截图所示。再次，我们可以看到自动化是如何发生的。监视部分也存在。

![发现 Gulp](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00167.jpeg)

# 测试驱动开发

测试驱动开发是一种软件开发过程，其中自动化测试驱动新产品或功能的开发周期。从长远来看，它加快了开发速度，并倾向于产生更好的代码。如今，许多框架都有帮助您创建自动化测试的工具。因此，作为开发人员，我们需要在编写任何新代码之前首先编写和运行测试。我们始终检查我们工作的结果是什么。在 Web 开发中，我们通常打开浏览器并与我们的应用程序进行交互，以查看我们的代码行为如何。因此，我们的大部分时间都花在测试上。好消息是我们可以优化这个过程。我们可以编写代码来代替我们的工作。有时，依赖手动测试并不是最佳选择，因为它需要时间。以下是进行测试的几个好处：

+   测试提高了我们应用程序的稳定性

+   自动化测试节省了时间，可以用来改进或重构系统的代码

+   测试驱动开发倾向于随着时间的推移产生更好的代码，因为它让我们考虑更好的结构和模块化方法

+   持续测试帮助我们在现有应用程序上开发新功能，因为如果我们引入破坏旧功能的代码，自动化测试将失败

+   测试可以用作文档，特别是对于刚加入团队的开发人员

在过程开始时，我们希望我们的测试失败。之后，我们逐步实现所需的逻辑，直到测试通过。以下图表显示了这个过程：

![测试驱动开发](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00168.jpeg)

开发人员经常使用帮助他们编写测试的工具。我们将使用一个名为**Mocha**的测试框架。它适用于 Node.js 和浏览器，并且在自动化测试方面是最受欢迎的解决方案之一。让我们安装 Mocha 并看看 TDD 是如何工作的。我们将运行以下命令：

```js
npm install mocha -g

```

正如我们在书中已经做了几次，我们将全局安装包。为了这个例子，我们假设我们的应用程序需要一个模块来读取外部的 JSON 文件。让我们创建一个空文件夹，并将以下内容放入`test.js`文件中：

```js
var assert = require('assert');
describe('Testing JSON reader', function() {
   it('should get json', function(done) {
      var reader = require('./JSONReader');
      assert.equal(typeof reader, 'object');
      assert.equal(typeof reader.read, 'function');
      done();
   });
});
```

`describe`和`it`函数是 Mocha 特定的函数。它们是全局的，我们可以随时使用。`assert`模块是一个原生的 Node.js 模块，我们可以用它来进行检查。一些流行的测试框架有自己的断言方法。Mocha 没有，但它可以很好地与`Chai`或`Expect.js`等库一起使用。

我们使用`describe`来形成一系列测试，使用`it`来定义逻辑块。我们假设当前目录中有一个`JSONReader.js`文件，当需要其中的模块时，我们有一个公共的`read`方法可用。现在，让我们用`mocha .\test.js`来运行我们的测试。结果如下：

![测试驱动开发](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00169.jpeg)

当然，我们的测试失败是因为没有这样的文件。如果我们创建文件并将以下代码放入其中，我们的测试将通过：

```js
// JSONReader.js
module.exports = {
   read: function() {
      // get JSON
      return {};
   }
}
```

`JSONReader`模块通过`read`公共方法导出一个对象。我们将再次运行`mocha .\test.js`。然而，这一次，测试中列出的所有要求都得到了满足。现在，终端应该是这样的：

![测试驱动开发](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00170.jpeg)

假设我们的`JSONReader`模块变得越来越大。新的方法出现了，不同的开发人员在同一个文件上工作。我们的测试仍然会检查模块是否存在，以及是否有`read`函数。这很重要，因为在项目开始的某个地方，程序员已经使用了`JSONReader`模块，并期望它有可用的`read`函数。

在我们的测试中，我们只添加了一些断言。然而，在现实世界中，会有更多的`describe`和`it`块。测试覆盖的案例越多，越好。很多时候，公司在发布新产品版本之前会依赖他们的测试套件。如果有一个测试失败了，他们就不发布任何东西。在书的接下来的几章中，我们经常会写测试。

# 模型-视图-控制器模式

开始一个新项目或实现一个新功能总是困难的。我们不知道如何组织我们的代码，要写哪些模块，它们将如何通信。在这种情况下，我们经常信任众所周知的实践——设计模式。设计模式是常见问题的可重用解决方案。例如，**模型-视图-控制器**模式已被证明是 Web 开发中最有效的模式之一，因为它清晰地分离了数据、逻辑和表示层。我们将以这种模式的变体为基础构建我们的社交网络。传统的部分及其职责如下：

![模型-视图-控制器模式](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00171.jpeg)

+   **模型**：**模型**是存储数据或状态的部分。一旦有变化，它就会触发**视图**的更新。

+   **视图**：**视图**通常是用户可以看到的部分。它是数据或**模型**状态的直接表示。

+   **控制器**：用户通过**控制器**（有时通过**视图**）进行交互。它可以向**模型**发送命令以更新其状态。在某些情况下，它还可以通知**视图**，以便用户可以看到**模型**的另一个表示。

然而，在 Web 开发中（特别是在浏览器中运行的代码），**View**和**Controller**共享相同的功能。很多时候，两者之间没有严格的区分。在本书中，控制器也将处理 UI 元素。让我们从 Node.js 环境开始。为了简化示例，我们将把我们的代码放在一个名为`server.js`的文件中。我们的应用程序只会做一件事——更新存储在内存中的变量的值。

在我们的上下文中，**View**将生成 HTML 标记。稍后，该标记将被发送到浏览器，如下所示：

```js
var view = {
   render: function() {
      var html = '';
      html += '<!DOCTYPE html>';
      html += '<html>';
      html += '<head><title>Node.js byexample</title></head>';
      html += '<body>';
      html += '<h1>Status ' + (model.status ? 'on' : 'off') + '</h1>';
      html += '<a href="/on">switch on</a><br />';
      html += '<a href="/off">switch off</a>';
      html += '</body>';
      html += '</html>';
      res.writeHead(200, {'Content-Type': 'text/html'});
      res.end(html + '\n');
   }
};
```

在这段代码中，有一个 JavaScript 对象文字，只有一个`render`方法。为了构建`h1`标记的正确内容，我们将使用模型及其`status`变量。还有两个链接。第一个将`model.status`更改为`true`，第二个将其更改为`false`。

`Model`对象相当小。与**View**一样，它只有一个方法：

```js
var model = {
   status: false,
   update: function(s) {
      this.status = s;
      view.render();
   }
};
```

请注意，**Model**触发了视图的渲染。在这里重要的一点是，模型不应该知道其数据在视图层的表示。它所要做的就是向视图发送信号，通知它已更新。

我们模式的最后一部分是**Controller**。我们可以将其视为脚本的入口点。如果我们正在构建一个 Node.js 服务器，这是接受`request`和`response`对象的函数：

```js
var http = require('http'), res;
var controller = function(request, response) {
   res = response;
   if(request.url === '/on') {
      model.update(true);
   } else if(request.url === '/off') {
      model.update(false);
   } else {
      view.render();
   }   
}
http.createServer(controller).listen(1337, '127.0.0.1');
console.log('Server running at http://127.0.0.1:1337/');
```

我们在全局变量中缓存了`response`参数，以便我们可以从其他函数中访问它。

这类似于本章开头发生的情况，我们在那里使用`request.url`属性来控制应用程序的流程。当用户访问`/on`或`/off` URL 时，前面的代码会改变模型的状态。如果没有，它只是触发视图的`render`函数。

模型-视图-控制器模式很适合 Node.js。正如我们所看到的，它可以很容易地实现。由于它非常受欢迎，有使用这个概念的模块甚至框架。在接下来的几章中，我们将看到这种模式在大型应用程序中的运作方式。

# 介绍 REST API 概念

**REST**代表**表述性状态转移**。根据定义，它是 Web 的一种架构原则。在实践中，它是一组简化客户端-服务器通信的规则。许多公司提供 REST API，因为它们简单且高度可扩展。

为了更好地理解 REST 的确切含义，让我们举一个简单的例子。我们有一个在线商店，我们想要管理系统中的用户。我们在各种控制器中实现了后端逻辑。我们希望通过 HTTP 请求触发那里的功能。换句话说，我们需要这些控制器的应用程序接口。我们首先规划要访问服务器的 URL。如果我们遵循 REST 架构，那么我们可能会有以下路由：

+   `GET`请求到`/users`返回系统中所有用户的列表

+   `POST`请求到`/users`创建新用户

+   `PUT`请求到`/users/24`编辑具有唯一标识号`24`的用户的数据

+   `DELETE`请求到`/users/24`删除具有唯一标识号`24`的用户的个人资料

有一个定义的资源——**user**。URL 是使 REST 简单的关键。`GET`请求用于检索数据，`POST`用于存储，`PUT`用于编辑，`DELETE`用于删除记录。

我们小型社交网络的一些部分将基于 REST 架构。我们将有处理四种类型请求并执行必要操作的控制器。然而，在我们达到本书的那一部分之前，让我们编写一个简单的 Node.js 服务器，接受`GET`、`POST`、`PUT`和`DELETE`请求。以下代码放入一个名为`server.js`的文件中：

```js
var http = require('http');
var url = require('url');
var controller = function(req, res) {
   var message = '';
   switch(req.method) {
      case 'GET': message = "Thats GET message"; break;
      case 'POST': message = "That's POST message"; break;
      case 'PUT': message = "That's PUT message"; break;
      case 'DELETE': message = "That's DELETE message"; break;
   }
   res.writeHead(200, {'Content-Type': 'text/html'});
   res.end(message + '\n');   
}
http.createServer(controller).listen(1337, '127.0.0.1');
console.log('Server running at http://127.0.0.1:1337/');
```

`req`对象有一个`method`属性。它告诉我们请求的类型。我们可以使用`node .\server.js`运行前面的服务器，并发送不同类型的请求。为了测试它，我们将使用流行的`curl`命令：

![介绍 REST API 概念](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00172.jpeg)

让我们尝试一个更复杂的`PUT`请求。以下示例使用 cURL。这是一个帮助您运行请求的命令行工具。在我们的情况下，我们将向服务器执行一个`PUT`请求：

![介绍 REST API 概念](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00173.jpeg)

我们使用`-X`选项更改了请求方法。除此之外，我们传递了一个名为`book`的变量，其值为`Node.js by example`。然而，我们的服务器没有处理参数的代码。我们将在`server.js`中添加以下函数：

```js
var qs = require('querystring');
var processRequest = function(req, callback) {
   var body = '';
   req.on('data', function (data) {
      body += data;
   });
   req.on('end', function () {
      callback(qs.parse(body));
   });
}
```

该代码接受`req`对象和回调函数，因为收集数据是一个异步操作。`body`变量填充了传入的数据，一旦收集到所有块，我们通过传递请求的解析主体来触发回调。以下是更新后的控制器：

```js
var controller = function(req, res) {
   var message = '';
   switch(req.method) {
      case 'GET': message = "That's GET message"; break;
      case 'POST': message = "That's POST message"; break;
      case 'PUT': 
         processRequest(req, function(data) {
            message = "That's PUT message. You are editing " + data.book + " book."; 
            res.writeHead(200, {'Content-Type': 'text/html'});
            res.end(message + "\n");   
         });
         return;
      break;
      case 'DELETE': message = "That's DELETE message"; break;
   }
   res.writeHead(200, {'Content-Type': 'text/html'});
   res.end(message + '\n');   
}
```

请注意，我们在`PUT` catch 语句中调用了`return`。我们这样做是为了应用程序流在那里停止并等待请求被处理。这是终端中的结果：

![介绍 REST API 概念](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00174.jpeg)

# 摘要

软件开发是一项复杂的任务。像每个复杂的过程一样，它需要规划。它需要一个良好的基础和一个精心设计的架构。在本章中，我们看到了规划一个大型 Node.js 应用程序的几个不同方面。在下一章中，我们将学习如何管理我们的资产。


# 第三章：管理资产

第一章和第二章是 Node.js 应用程序开发的基本构建块和结构的良好介绍。我们了解了技术的基本知识，并揭示了重要的模式，如模型-视图-控制器。我们谈论了测试驱动开发和 REST API。在本章中，我们将创建我们社交网络的基础。应用程序资产的适当交付和管理是系统的重要组成部分。在大多数情况下，它决定了我们的工作流程。在本章中，我们将讨论以下主题：

+   使用 Node.js 提供文件

+   CSS 预处理

+   打包客户端 JavaScript

+   交付 HTML 模板

# 使用 Node.js 提供文件

Node.js 与通常的 Linux-Apache-MySQL-PHP 设置不同。我们必须编写处理传入请求的服务器。当用户需要从我们的后端获取图像时，Node.js 不会自动提供。我们社交网络的第一个文件将是`server.js`，内容如下：

```js
var http = require('http');
var fs = require('fs');
   var path = require('path');

var files = {};
var port = 9000;
var host = '127.0.0.1';

var assets = function(req, res) {
  // ...
};

var app = http.createServer(assets).listen(port, host);
console.log("Listening on " + host + ":" + port);
```

我们需要三个本地模块，用于驱动服务器和交付资产。前面代码的最后两行运行服务器并在控制台打印消息。

目前，我们应用程序的入口点是`assets`函数。此方法的主要目的是从硬盘读取文件并提供给用户。我们将使用`req.url`来获取当前请求路径。当 Web 浏览器访问我们的服务器并在浏览器中请求`http://localhost:9000/static/css/styles.css`时，`req.url`将等于`/static/css/styles.css`。从这一点开始，我们有一些任务要处理：

+   检查文件是否存在，如果不存在，则向用户发送适当的消息（HTTP 错误代码）

+   读取文件并找出其扩展名

+   以正确的内容类型将文件内容发送到浏览器

最后一点很重要。以错误或缺少的内容类型提供文件可能会导致问题。浏览器可能无法正确识别和处理资源。

为了使流程顺利，我们将为提到的每个任务创建一个单独的函数。最短的函数是向用户发送错误消息的函数：

```js
var sendError = function(message, code) {
  if(code === undefined) {
     code = 404;
  }
  res.writeHead(code, {'Content-Type': 'text/html'});
  res.end(message);
}
```

默认情况下，`code`变量的值为`404`，表示“未找到”。然而，有不同类型的错误，如客户端错误（4XX）和服务器错误（5XX）。最好留下更改错误代码的选项。

假设我们有文件的内容和扩展名。我们需要一个函数来识别正确的内容类型并将资源提供给客户端。为了简单起见，我们将执行文件扩展名的简单字符串检查。以下代码正是如此：

```js
var serve = function(file) {
  var contentType;
  switch(file.ext.toLowerCase()) {
    case "css": contentType = "text/css"; break;
    case "html": contentType = "text/html"; break;
    case "js": contentType = "application/javascript"; break;
    case "ico": contentType = "image/ico"; break;
    case "json": contentType = "application/json"; break;
    case "jpg": contentType = "image/jpeg"; break;
    case "jpeg": contentType = "image/jpeg"; break;
    case "png": contentType = "image/png"; break;
    default: contentType = "text/plain";
  }
  res.writeHead(200, {'Content-Type': contentType});
  res.end(file.content);
}
```

`serve`方法接受一个带有两个属性的`file`对象——`ext`和`content`。在接下来的几章中，我们可能会向列表中添加更多文件类型。但是，目前，提供 JavaScript、CSS、HTML、JPG 和 PNG 图像就足够了。

我们必须覆盖的最后一个任务是实际读取文件。Node.js 有一个内置模块来读取文件，称为`fs`。我们将使用其异步方法。使用同步函数，JavaScript 引擎可能会被阻塞，直到特定操作完全执行。在这种情况下，即读取文件。在异步编程中，我们允许程序执行其余的代码。在这种情况下，我们通常传递一个回调函数——当操作结束时将执行的函数：

```js
var readFile = function(filePath) {
  if(files[filePath]) {
        serve(files[filePath]);
    } else {
      fs.readFile(filePath, function(err, data) {
        if(err) {
          sendError('Error reading ' + filePath + '.');
          return;
        }
        files[filePath] = {
          ext: filePath.split(".").pop(),
          content: data
        };
        serve(files[filePath]);
      });
    }
}
```

该函数接受路径并打开文件。如果文件丢失或读取时出现问题，它会向用户发送错误。一开始，我们定义了一个`files`变量，它是一个空对象。每次我们读取一个文件，我们都将其内容存储在那里，这样下次读取时，我们就不必再次访问磁盘。每个 I/O 操作，比如读取文件，都需要时间。通过使用这种简单的缓存逻辑，我们提高了应用程序的性能。如果一切正常，我们调用`serve`方法。

以下是如何组合所有前面的片段：

```js
var http = require('http');
var fs = require('fs');
var path = require('path');
var files = {};
var port = 9000;

var assets = function(req, res) {
  var sendError = function(message, code) { ... }
  var serve = function(file) { ... }
  var readFile = function(filePath) { ... }

  readFile(path.normalize(__dirname + req.url));
}

var app = http.createServer(assets).listen(port, '127.0.0.1');
console.log("Listening on 127.0.0.1:" + port);
```

发送到服务器的每个 HTTP 请求都由`assets`处理程序处理。我们从当前目录开始组成文件的路径。`path.normalize`参数确保我们的字符串在不同的操作系统上看起来都很好。例如，它不包含多个斜杠。

# CSS 预处理

CSS 预处理器是接受源代码并生成 CSS 的工具。很多时候，输入与 CSS 语言的语法类似。然而，预处理的主要思想是添加社区所需但缺失的功能。在过去几年里，CSS 预处理已成为热门话题。它带来了许多好处，并且这个概念已经被社区热烈接受。有两种主要的 CSS 预处理器——**Less** ([`lesscss.org/`](http://lesscss.org/)) 和 **Sass** ([`sass-lang.com/`](http://sass-lang.com/))。Sass 基于 Ruby 语言，需要更多的工作才能在 Node.js 项目中运行。因此，在本书中，我们将使用 Less。

在上一章中，我们谈到了构建系统和任务运行器。CSS 预处理和我们稍后将讨论的其他一些任务应该自动发生。Gulp 似乎是一个不错的选择。让我们继续添加一个`package.json`文件，我们将在其中描述所有我们需要的与 Gulp 相关的模块：

```js
{
  "name": "nodejs-by-example",
  "version": "0.0.1",
  "description": "Node.js by example",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "gulp": "3.8.8",
    "gulp-less": "1.3.6",
    "gulp-rename": "~1.2.0",
    "gulp-minify-css": "~0.3.11"
  }
}
```

设置`"start": "node server.js"`将允许我们输入`npm start`并运行我们的服务器。我们将开始的依赖关系如下：

+   Gulp 本身

+   `gulp-less`：这是一个包装了 Less 预处理器的插件

+   `gulp-rename`：这会更改生成文件的名称

+   `gulp-minify-css`：这会压缩我们的 CSS

因此，除了`server.js`，我们现在还有`package.json`。我们运行`npm install`，包管理器会添加一个包含模块的`node_modules`目录。让我们在另一个名为`gulpfile.js`的文件中定义我们的 Gulp 任务：

```js
var path = require('path');
var gulp = require('gulp');
var less = require('gulp-less');
var rename = require("gulp-rename");
var minifyCSS = require('gulp-minify-css');

gulp.task('css', function() {
  gulp.src('./less/styles.less')
  .pipe(less({
    paths: [ path.join(__dirname, 'less', 'includes') ]
  }))
  .pipe(gulp.dest('./static/css'))
  .pipe(minifyCSS({keepBreaks:true}))
  .pipe(rename({suffix: '.min'}))
  .pipe(gulp.dest('./static/css'));
});

gulp.task('watchers', function() {
  gulp.watch('less/**/*.less', ['css']);
});

gulp.task('default', ['css', 'watchers']);
```

我们从两个任务开始——`css`和`watchers`。第一个任务期望我们有一个`less`目录和一个`styles.less`文件。这将是我们所有 CSS 样式的入口点。从 Gulp 任务中可以看到，我们将文件的内容传输到预处理器，并将结果导出到`static/css`目录。由于 Gulp 中的一切都是流，我们可以继续压缩 CSS，将文件重命名为`styles.min.css`，并将其导出到相同的文件夹。

我们不希望每次更改文件时都要自己运行构建过程。因此，我们为`less`文件夹中的文件注册`watchers`。`watcher`是一个监视特定文件的过程，一旦这些文件被更改，就会通知系统的其余部分。

在这一步结束时，我们的项目看起来是这样的：

![CSS 预处理](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00175.jpeg)

# 打包客户端 JavaScript

与 CSS 一样，我们的目标应该是只向客户端浏览器提供一个 JavaScript 文件。我们不希望强迫用户发出多个请求，因为这样效率较低，意味着网页浏览器需要更长的时间来处理和显示页面的内容。如今，应用程序的客户端部分相当复杂。与复杂系统一样，我们将逻辑分成不同的模块。通常，不同的模块意味着不同的文件。幸运的是，Node.js 充满了可以用来打包 JavaScript 的工具。让我们看看两种最流行的工具。

## 使用 Gulp 进行合并

作为构建系统，Gulp 有几个模块来连接文件。我们感兴趣的是一个叫做`gulp-concat`的模块。让我们把它添加到`package.json`文件中：

```js
"dependencies": {
  "gulp": "3.8.8",
  "gulp-less": "1.3.6",
  "gulp-rename": "1.2.0",
  "gulp-minify-css": "0.3.11",
  "gulp-concat": "2.4.1"
}
```

下一步是编写一个使用它的任务。同样，我们将使用`src`和`dest` Gulp 方法，在它们之间是连接：

```js
var concat = require('gulp-concat');

gulp.task('js', function() {
  gulp.src('./js/*.js')
  .pipe(concat('scripts.js'))
  .pipe(gulp.dest('./static/js'))
});
```

需要提到的是，文件将按字母顺序添加到最终文件中。因此，每当有一些代码依赖时，我们都应该小心。如果是这种情况，我们应该以这样的方式命名文件，使它们的名称以唯一数字开头——01、02、03 等等。

我们接下来要做的逻辑任务是压缩我们的 JavaScript。和 Less 编译一样，我们希望提供尽可能小的文件。帮助我们实现这一目标的模块是`gulp-uglify`。同样，我们应该把它添加到`package.json`文件中（`"gulp-uglify": "1.0.1"`）。之后，对我们新创建的任务进行一点调整就可以压缩 JavaScript 了：

```js
var concat = require('gulp-concat');
var uglify = require('gulp-uglify');

gulp.task('js', function() {
  gulp.src('./js/*.js')
  .pipe(concat('scripts.js'))
  .pipe(gulp.dest('./static/js'))
  .pipe(uglify())
  .pipe(rename({suffix: '.min'}))
  .pipe(gulp.dest('./static/js'))
});
```

请注意，我们再次使用了`gulp-rename`插件。这是必要的，因为我们想生成一个不同的文件。

## 使用 RequireJS 在浏览器中进行模块化

在构建软件时，思考的最重要的概念之一是将我们的系统分割成模块。Node.js 有一个很好的内置系统来编写模块。我们在第一章中提到过，*Node.js 基础*。我们将我们的代码封装在一个单独的文件中，并使用`module.exports`或`exports`来创建公共 API。稍后，通过`require`函数，我们访问创建的功能。

然而，对于客户端 JavaScript，我们没有这样的内置系统。我们需要使用一个额外的库来允许我们定义模块。有几种可能的解决方案。我们将首先看一下的是 RequireJS（[`requirejs.org/`](http://requirejs.org/)）。我们将从官方网站下载这个库（版本 2.1.16），并像这样包含在我们的页面中：

```js
<script data-main="scripts/main" src="img/require.js">
</script>
```

这里的关键属性是`data-main`。它告诉 RequireJS 我们应用的入口点。事实上，我们应该在项目文件夹中有`scripts/main.js`文件才能让前面的行起作用。在`main.js`中，我们可以使用`require`全局函数：

```js
// scripts/main.js
require(["modules/ajax", "modules/router"], function(ajax, router) {
    // ... our logic
});
```

假设我们的`main.js`代码依赖于另外两个模块——Ajax 包装器和路由器。我们在一个数组中描述这些依赖关系，并提供一个回调，稍后用两个参数执行。这些参数实际上是对必要模块的引用。

使用另一个全局函数`define`可以定义模块。这是 Ajax 包装器的样子：

```js
// modules/ajax.js
define(function () {
    // the Ajax request implementation
    ...
    // public API
    return {
        request: function() { ... }
    }
});
```

默认情况下，RequireJS 在后台异步解析依赖项。换句话说，它为每个所需模块执行 HTTP 请求。在某些情况下，这可能会导致性能问题，因为每个请求都需要时间。幸运的是，RequireJS 有一个解决这个问题的工具（优化器）。它可以将所有模块捆绑成一个单独的文件。这个工具也适用于 Node.js，并且随`requirejs`包一起分发：

```js
npm install -g requirejs

```

安装成功后，我们将在终端中有`r.js`命令。基本调用如下：

```js
// in code_requirejs folder
r.js -o build.js
```

和 Grunt 和 Gulp 一样，我们有一个文件指导 RequireJS 如何工作。以下是涵盖我们示例的片段：

```js
// build.js
({
    baseUrl: ".",
    paths: {},
    name: "main",
    out: "main-built.js"
})
```

`name`属性是入口点，`out`是结果文件。很好的是我们有`paths`属性可用。这是一个我们可以直接描述模块的地方；例如，`jquery: "some/other/jquery"`。在我们的代码中，我们不必写文件的完整路径。只需简单的`require(['jquery'], ...)`就足够了。

默认情况下，`r.js`命令的输出是经过压缩的。如果我们在终端中添加一个`optimize=none`参数到命令中，我们将得到以下结果：

```js
// main-built.js
define('modules/ajax',[],function () {
    ...
});

define('modules/router',[],function () {
    ...
});

require(['modules/ajax', 'modules/router'], function(ajax, router) {
    ...
});
define("main", function(){});
```

`main-built.js`文件包含了主模块及其依赖项。

## 从 Node.js 移动到使用 Browserify 的浏览器

RequireJS 确实解决了模块化的问题。然而，它让我们写更多的代码。此外，我们应该始终按照严格的格式描述我们的依赖关系。让我们看看我们在上一节中使用的代码：

```js
require(['modules/ajax', 'modules/router'], function(ajax, router) {
    ...
});
```

确实，如果我们使用以下代码会更好：

```js
var ajax = require('modules/ajax');
var router = require('modules/router');
```

现在代码简单多了。这是我们在 Node.js 环境中获取模块的方式。如果我们能在浏览器中使用相同的方法就好了。

Browserify ([`browserify.org/`](http://browserify.org/))是一个将 Node.js 的`require`模块带到浏览器中的模块。让我们首先使用以下代码安装它：

```js
npm install -g browserify

```

同样，为了说明这个工具是如何工作的，我们将创建`main.js`，`ajax.js`和`router.js`文件。这一次，我们不打算使用`define`这样的全局函数。相反，我们将使用通常的 Node.js `module.exports`：

```js
// main.js
var ajax = require('./modules/ajax');
var router = require('./modules/router');

// modules/ajax.js
module.exports = function() {};

// modules/router.js
module.exports = function() {};
```

默认情况下，Browserify 作为一个命令行工具。我们需要提供一个入口点和一个输出文件：

```js
browserify ./main.js -o main-built.js
```

编译文件中的结果如下：

```js
// main-built.js
(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var  a=typeof require=="function"&&require;if(!u&&a)return  a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module  '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var  l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var  n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return  n[o].exports}var i=typeof require=="function"&&require;for(var  o=0;o<r.length;o++)s(r[o]);return  s})({1:[function(require,module,exports){
var ajax = require('./modules/ajax');
var router = require('./modules/router');
},{"./modules/ajax":2,"./modules/router":3}],2:[function(require,module,exports){
module.exports = function() {};
},{}],3:[function(require,module,exports){
module.exports=require(2)
},{".../modules/ajax.js":2}]},{},[1]);
```

请注意，编译文件除了模块之外，还包含`require`函数的定义和实现。这确实只是一小段代码，使 Browserify 成为浏览器中传递模块化 JavaScript 的最受欢迎的方式之一。这是我们接下来几章要使用的方法。

我们已经开始了一个 Gulp 设置。让我们在那里添加 Browserify。我们已经对 JavaScript 进行了合并。让我们用 Browserify 替换它。我们将在`package.json`文件中添加模块，如下所示：

```js
"dependencies": {
  "gulp": "3.8.8",
  "gulp-less": "1.3.6",
  "gulp-rename": "1.2.0",
  "gulp-minify-css": "0.3.11",
  "gulp-concat": "2.4.1",
  "gulp-uglify": "1.0.1",
  "gulp-browserify": "0.5.0"
}
```

运行`npm install`后，我们将安装并准备好使用插件。我们需要做两个更改，用`browserify`替换`concat`，并指出应用程序的主文件：

```js
var browserify = require('gulp-browserify');
var uglify = require('gulp-uglify');

gulp.task('js', function() {
  gulp.src('./js/app.js')
  .pipe(browserify())
  .pipe(gulp.dest('./static/js'))
  .pipe(uglify())
  .pipe(rename({suffix: '.min'}))
  .pipe(gulp.dest('./static/js'))
});
```

现在，`src`方法只接受一个文件。这是我们的入口点。这是 Browserify 开始解析依赖关系的地方。其余部分都是一样的。我们仍然使用`uglify`进行最小化和`rename`来更改文件的名称。

# 传递 HTML 模板

在前面的章节中，您看到了如何为浏览器打包 CSS 和 JavaScript。在本章的最后，我们将探讨各种传递 HTML 的方式。在客户端应用程序的上下文中，模板仍然包含 HTML。然而，我们需要一种动态的方式来渲染并填充它们的数据。

## 在脚本标记中定义模板

Ember.js 框架采用了直接将 HTML 模板添加到页面中的概念，使用流行的**handlebars** ([`handlebarsjs.com/`](http://handlebarsjs.com/))模板引擎。然而，由于我们不想搞乱已经存在的标记，我们将它们放在`<script>`标记中。这样做的好处是，如果我们设置`type`属性的自定义值，浏览器就不会处理其中的代码。这里有一个演示：

```js
<script type="text/x-handlebars" id="my-template">
   <p>Hello, <strong> </strong>!</p>
</script>
```

由于标签有一个`id`属性，我们可以通过以下方式轻松地获取它的内容：

```js
var template = document.querySelector('#my-template').innerHTML;
```

这种技术的好处是模板在页面上，我们可以立即访问它。此外，模板只在被 JavaScript 处理后显示所需的内容。因此，如果浏览器中未启用 JavaScript，我们不希望显示未经处理的原始模板。这个概念的一个主要问题是，我们将用大量代码淹没我们的 HTML 页面。如果我们有一个大型应用程序，那么用户将不得不下载所有模板，即使他/她只使用其中的一部分。

## 外部加载模板

将模板定义为外部文件并使用 Ajax 请求加载到页面上也是一种常见做法。以下伪代码使用 jQuery 的`get`方法来完成这项工作：

```js
$.get('/templates/template.html', function(html) {
    // ...
});
```

我们有清晰的标记，但用户必须进行额外的 HTTP 请求才能获取模板。这种方法使代码更复杂，因为过程是异步的。它还使处理和渲染内容比前一种方法更慢。

## 在 JavaScript 中编写 HTML

随着移动应用程序的兴起，许多大公司已经开始开发自己的框架。由于这些公司有足够的资源，他们通常会产生一些有趣的东西。例如，Facebook 创建了一个名为**React** ([`facebook.github.io/react/`](http://facebook.github.io/react/))的框架。它直接在 JavaScript 中定义其模板，如下所示：

```js
<script type="text/jsx">
  var HelloMessage = React.createClass({
     render: function() {
      // Note: the following line is invalid JavaScript,
         // and only works using React parser.
      return <div>Hello {this.props.name}</div>;
     }
  });
</script>
```

来自 Facebook 的开发人员采用了本节中提到的第一种技术。他们将一些代码放在`<script>`标签中。为了使事情正常运行，他们有自己的解析器。它处理脚本并将其转换为有效的 JavaScript。

有一些解决方案没有以 HTML 形式的模板。有些工具使用 JSON 或 YAML 编写的模板。例如，**AbsurdJS** ([`absurdjs.com/`](http://absurdjs.com/))可以将其模板保存在 JavaScript 类定义中，如下所示：

```js
body: {
  'section.content#home': {
    nav: [
      { 'a[href="#" class="link"]': 'A' },
      { 'a[href="#" class="link"]': 'B' },
      { 'a[href="#" class="link"]': 'C' }
    ]
  },
  footer: {
    p: 'Text in the Footer'
  }
}
```

## 预编译模板

将模板传递到客户端的另一种流行方式是使用预编译。这是我们将在项目中使用的方法。预编译是将 HTML 模板转换为 JavaScript 对象的过程，该对象已准备好在我们的代码中使用。这种方法有几个好处，其中一些如下：

+   我们不必考虑访问 HTML 模板

+   标记仍然与 JavaScript 代码分开

+   我们不浪费时间去获取和处理 HTML

不同的客户端框架有不同的工具来预编译模板。我们将在以后详细介绍这一点，但我们将在我们的社交网络应用程序中使用的工具称为 Ractive.js ([`www.ractivejs.org/`](http://www.ractivejs.org/))。这是一个最初由 TheGuardian 的人员开发的客户端框架，用于制作新闻应用程序。它跨浏览器，在移动设备上表现良好。

为了将我们的 HTML 转换为 Ractive 预编译模板，我们需要在`package.json`文件中添加两个新模块：

```js
"ractive": "0.6.1",
"gulp-tap": "0.1.3"
```

`gulp-tap`插件允许我们处理发送到 Gulp 管道的每个文件。以下是我们必须添加到`gulpfile.js`文件的新任务：

```js
var Ractive = require('ractive');
var tap = require('gulp-tap');

gulp.task('templates', function() {
  gulp.src('./tpl/**/*.html')
  .pipe(tap(function(file, t) {
    var precompiled = Ractive.parse(file.contents.toString());
    precompiled = JSON.stringify(precompiled);
    file.contents = new Buffer('module.exports = ' + precompiled);
  }))
  .pipe(rename(function(path) {
    path.extname = '.js';
  }))
  .pipe(gulp.dest('./tpl'))
});

gulp.task('default', ['css', 'templates', 'js', 'watchers']);
```

`Ractive.parse`返回预编译模板。由于它是一个 JavaScript 对象，我们使用`JSON.stringify`将其转换为字符串。我们使用 Browserify 来控制我们的客户端模块化，因此在模板代码前面附加了`module.exports`。最后，我们使用`gulp-rename`生成一个 JavaScript 文件。

假设我们有一个包含以下内容的`/tpl/template.html`文件：

```js
<section>
  <h1>Hello {{name}}</h1>
</section>
```

当我们运行`gulp`命令时，我们将收到包含相应标记的 JavaScript 的`/tpl/template.js`文件：

```js
module.exports =  {"v":1,"t":[{"t":7,"e":"section","f":[{"t":7,"e":"h1","f":["Hello ",{"t":2,"r":"name"}]}]}]}
```

现在可能看起来很奇怪，但在接下来的几章中，您将看到如何使用这样的模板。

# 摘要

资产是 Web 应用程序的重要组成部分。通常，公司对这一部分不够重视，这导致加载时间变慢，Web 托管成本增加，特别是当您的网站变得更受欢迎时。在本章中，我们看到找到正确的设置并以最有效的方式交付图像、CSS、JavaScript 和 HTML 是很重要的。

在下一章中，我们将开始在我们的社交网络上大量工作。我们将探索模型-视图-控制器模式的世界。


# 第四章：开发模型-视图-控制器层

在上一章中，我们学习了如何准备应用程序所需的资源。现在是时候继续前进，开始编写我们社交网络的基本层。在本章中，我们将使用模型-视图-控制器模式，并准备我们的代码基础以实现我们应用程序的未来。以下是本章将讨论的内容：

+   将代码从上一章转换为更好的文件结构

+   实现在后端和前端环境中都能工作的路由器

+   简要介绍 Ractive.js——这是我们将在项目的客户端部分使用的框架

+   开发应用程序的主文件

+   实现控制器、视图和模型类

# 发展当前的设置

编写软件是困难的。通常，这是一个变化的过程。为了发展和扩展我们的系统，我们必须对代码进行更改。我们将从上一章的代码中提取一些新的文件和文件夹。我们将稍微改变架构，以便在开发之后适应。

## 目录结构

将逻辑分为前端和后端是一种常见的做法。我们将遵循相同的方法。以下是新的文件结构：

![目录结构](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00176.jpeg)

`backend`目录将包含在 Node.js 环境中使用的文件。正如我们所看到的，我们将之前在主目录中的文件移动到`frontend`文件夹中。这些文件产生了放置在`static`目录中的资源。我们仍然有必要的`gulpfile.js`，`package.json`和`server.js`文件，其中包含了 Node.js 服务器的代码。

## 形成主服务器处理程序

到目前为止，我们的服务器只有一个请求处理程序——`assets`。以下是我们在上一章中启动服务器的方式：

```js
var app = http.createServer(assets).listen(port, '127.0.0.1');
```

除了提供资源，我们还必须添加另外两个处理程序，如下所示：

+   **API 处理程序**：我们应用程序的客户端部分将通过 REST API 与后端通信。我们在第二章中介绍了这个概念，*项目架构*。

+   **页面处理程序**：如果发送到服务器的请求不是用于资源或 API 资源，我们将提供一个 HTML 页面，这是普通用户将看到的页面。

将所有内容保存在一个文件中并不是一个好主意。因此，第一步是将`assets`函数提取到自己的模块中：

```js
// backend/Assets.js
module.exports = function(req, res) {
...
}

// server.js
var Assets = require('./backend/Assets');
```

我们将采用类似的方法创建一个`backend/API.js`文件。它将负责 REST API。我们将使用 JSON 作为数据传输的格式。我们可以使用的最简单的代码如下：

```js
// backend/API.js
module.exports = function(req, res) {
  res.writeHead(200, {'Content-Type': 'application/json'});
  res.end('{}' + '\n');
}
```

设置正确的`Content-Type`值很重要。如果缺少或者值错误，那么接收响应的浏览器可能无法正确处理结果。最后，我们返回一个最小的空 JSON 字符串。

最后，我们将添加`backend/Default.js`。这是将在浏览器中生成用户将看到的 HTML 页面的文件：

```js
// backend/Default.js
var fs = require('fs');
var html = fs.readFileSync(__dirname + '/tpl/page.html').toString('utf8');
module.exports = function(req, res) {
  res.writeHead(200, {'Content-Type': 'text/html'});
  res.end(html + '\n');
}
```

`Default.js`的内容看起来与`API.js`类似。我们将再次设置`Content-Type`值，并使用`response`对象的`end()`方法。然而，在这里，我们从外部文件中加载 HTML Unicode 字符串，该文件存储在`backend/tpl/page.html`中。文件的读取是同步的，并且只在开始时发生一次。以下是`page.html`的代码：

```js
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Node.js by example</title>
  <meta http-equiv="Content-Type" content="text/html;  charset=utf-8" />
  <meta name="description" content="Node.js by examples">
  <meta name="author" content="Packt">
  <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body>
  <script src="img/ractive.js"></script>
  <script src="img/app.js"></script>
</body>
</html>
```

这是一个基本的 HTML5 样板代码，包含头部、主体标签、CSS 和 JavaScript 导入。我们的应用程序只需要以下两个 JavaScript 文件才能运行：

+   `ractive.js`：这是我们将在客户端使用的框架。关于这个更多的内容将在接下来的几节中讨论。

+   `app.js`：这是我们的客户端 JavaScript。如前一章所述，它是由 Gulp 设置生成的。

在提到后端处理程序之后，我们准备好开始编写将在浏览器中运行的代码。

# 实现路由器

几乎每个 Web 应用程序都需要一个路由器，它是一个作为前门的组件，接受传入的查询。它分析请求的参数，并决定我们系统的哪个模块将提供结果。

我们在后端（通过 Node.js）和前端（由 Web 浏览器解释）中使用 JavaScript 语言。在本节中，我们将编写一个在应用程序的两侧都能工作的路由器。让我们开始检查 Node.js 部分需要什么：

```js
// frontend/js/lib/Router.js
module.exports = function() {
  return {
    routes: [],
    add: function(path, handler) {
      // ...
    },
    check: function(fragment, params) {
      // ...
    }
  }
};
```

`Router.js`导出两种方法。第一个方法通过接受路径和处理程序函数来注册路由，如果当前 URL 与路径匹配，则将调用该处理程序。`check`函数只是执行实际检查。

这是`add`方法的样子：

```js
add: function(path, handler) {
  if(typeof path === 'function') {
    handler = path;
    path = '';
  }
  this.routes.push({
    path: path,
    handler: handler
  });
  return this;
}
```

我们可以跳过`path`参数，只注册一个匹配每个路由的函数。在某些情况下，支持这种行为是很好的，我们想定义一个默认路由。

`check`函数稍微复杂一些。它不仅涵盖简单的字符串匹配，还应该支持动态参数。我们将使用`:id`来表示这些动态参数。例如：

+   `/home`：这匹配`http://localhost/home`

+   `/user/feed`：这匹配`http://localhost/user/feed`

+   /user/:id/profile：这匹配`http://localhost/user/45/profile`

+   `/user/:id/:action`：这匹配`http://localhost/user/45/update`

为了实现这个功能，我们将以以下方式使用正则表达式：

```js
check: function(f, params) {
  var fragment, vars;
  if(typeof f !== 'undefined') {
    fragment = f.replace(/^\//, '');
  } else {
    fragment = this.getFragment(); 
  }
  for(var i=0; i<this.routes.length; i++) {
    var match, path = this.routes[i].path;
    path = path.replace(/^\//, '');
    vars = path.match(/:[^\s/]+/g);
    var r = new RegExp('^' + path.replace(/:[^\s/]+/g,  '([\\w-]+)'));
    match = fragment.match(r);
    if(match) {
      match.shift();
      var matchObj = {};
      if(vars) {
        for(var j=0; j<vars.length; j++) {
          var v = vars[j];
          matchObj[v.substr(1, v.length)] = match[j];
        }
      }
      this.routes[i].handler.apply({},  (params || []).concat([matchObj]));
      return this;
    }
  }
  return false;
}
```

让我们逐行浏览该函数。该方法的参数是`f`和`parameters`。片段实际上是一个路径。这是我们要检查的 URL。在`add`方法中，我们添加了一个处理程序，一旦匹配，就会触发。如果我们能够向该方法发送额外的变量，那将是很好的。`parameters`参数涵盖了这个功能。我们可以发送一个数组，稍后将其转换为处理程序的参数。

该函数继续检查片段是否已定义。在 Node.js 环境中，我们必须发送 URL。但是，由于我们将在浏览器中使用相同的代码，我们定义了一个`getFragment`辅助方法：

```js
getFragment: function() {
  var fragment = '';
  fragment = this.clearSlashes(decodeURI(window.location.pathname  + location.search));
  fragment = fragment.replace(/\?(.*)$/, '');
  fragment = this.root !== '/' ? fragment.replace(this.root, '') : fragment;
  return this.clearSlashes(fragment);
}
```

这个辅助程序的主要思想是通过使用全局的`window.location`对象来获取浏览器的当前 URL。您可能会注意到另一个`clearSlashes`函数。它确切地做了它的名字所暗示的。它从字符串的开头和结尾删除不必要的斜杠：

```js
clearSlashes: function(path) {
  return path.toString().replace(/\/$/, '').replace(/^\//, '');
}
```

让我们回到`check`函数。我们将继续循环遍历已注册的路由。对于每个路由，我们执行以下操作：

+   我们通过提取动态部分（如果有）来准备一个正则表达式；例如，`users/:id/:action`被转换为`test/([\w-]+)/([\w-]+)`。我们将在本书中稍后使用这个。

+   我们检查正则表达式是否与片段匹配。如果匹配，则我们组成一个参数数组并调用路由的处理程序。

有趣的是，如果我们传递我们自己的路径（片段），我们可以在 Node.js 和浏览器环境中使用相同的 JavaScript。

应用程序的客户端将需要另外两种方法。到目前为止，我们已经注册了路由并检查这些规则是否特定匹配 URL。这对于后端可能有效，但在前端，我们需要不断监视当前浏览器位置。这就是为什么我们将添加以下功能：

```js
listen: function() {
  var self = this;
  var current = self.getFragment();
  var fn = function() {
    if(current !== self.getFragment()) {
      current = self.getFragment();
      self.check(current);
    }
  }
  clearInterval(this.interval);
  this.interval = setInterval(fn, 50);
  return this;
}
```

通过使用`setInterval`，我们将再次运行`fn`闭包。它检查当前 URL 是否已更改，如果是，则触发`check`方法，这已经解释过了。

该类的最后一个添加是`navigate`函数：

```js
navigate: function(path) {
  path = path ? path : '';
  history.pushState(null, null, this.root + this.clearSlashes(path));
  return this;
}
```

我们可能希望在代码中更改当前页面。路由是一个很好的工具。一旦我们更改浏览器的 URL，该类就会自动调用正确的处理程序。上述代码使用了 HTML5 历史 API（[`diveintohtml5.info/history.html`](http://diveintohtml5.info/history.html)）。`pushState`方法会更改浏览器地址栏的字符串。

通过添加`navigate`方法，我们完成了我们的路由器，它是一个可以在后端和前端使用的模块。在继续介绍模型-视图-控制器组件之前，我们将简要介绍 Ractive.js—我们将用作用户界面开发的驱动力的框架。

# 介绍 Ractive.js

Ractive.js 是由著名新闻机构 TheGuardian 开发的框架（[`www.theguardian.com/`](http://www.theguardian.com/)）。它简化了 DOM 交互，并提供了诸如双向数据绑定和自定义组件创建等功能。我们现在不打算涵盖框架的所有功能。新功能将在后面的章节中介绍。

在像我们这样的复杂 Web 应用程序中，将不同的逻辑部分拆分成组件非常重要。幸运的是，Ractive.js 为此提供了一个接口。以下是典型组件的外观：

```js
var Component = Ractive.extend({
  template: '<div><h1>{{title}}</h1></div>',
  data: {
    title: 'Hello world'
  }
});
var instance = new Component();
instance.render(document.'body);
```

`template`属性包含 HTML 标记或（在我们的情况下）预编译模板。数据对象可以在我们的模板中访问。Ractive.js 使用**mustache**（[`mustache.github.io/`](http://mustache.github.io/)）作为模板语言。我们可以添加另一个名为`el`的属性，并直接选择组件在初始化后将呈现的位置。然而，还有另一种方式—`render`方法。该方法接受一个 DOM 元素。在上述代码中，这只是页面的 body。

与浏览器中的 DOM 树类似，我们需要组件的嵌套。框架通过引入自定义标签定义来很好地处理了这一点，如下例所示：

```js
var SubComponent = Ractive.extend({
    template: '<small>Hello there!</small>'
});
var Component = Ractive.extend({
  template: '\
    <div>\
        <h1>{{title}}</h1>\
        <my-subcomponent />\
    </div>\
  ',
  data: {
    title: 'Hello world'
  },
  components: {
    'my-subcomponent': SubComponent
  }
});
var instance = new Component();
instance.render(document.querySelector('body'));
```

每个组件可能都有一个哈希映射对象（`components`），用于定义我们的自定义标签。我们可以嵌套任意多个组件。上述代码生成的 HTML 如下所示：

```js
<div>
  <h1>Hello world</h1>
  <small>Hello there!</small>
</div>
```

在不同的 Ractive.js 组件之间建立通信的几种方式。最方便的一种方式是触发和监听事件。让我们来看一下以下代码片段：

```js
var Component = Ractive.extend({
  template: '<div><h1>{{title}}</h1></div>',
  notifyTheOutsideWorld: function() {
    this.fire('custom-event');
  }
});
var instance = new Component();
instance.on('custom-event', function() {
  this.set('title', 'Hey!');
  instance.render(document.querySelector('body'));
});
instance.notifyTheOutsideWorld();
```

我们提出了一些新概念。首先，我们定义了一个公共函数—`notifyTheOutsideWorld`。Ractive.js 允许您注册自定义方法。使用`on`方法，我们订阅了特定事件，并使用`fire`来分发事件。

在上面的示例中，我们使用了另一个到目前为止尚未解释的方法。`set`函数修改了组件的数据对象。我们将经常使用这个函数。

关于 Ractive.js，我们在本章中要提到的最后一件事是它观察组件数据属性变化的功能。下面的代码演示了对`title`属性的观察：

```js
var Component = Ractive.extend({
  template: '<div><h1>{{title}}</h1></div>'
});
var instance = new Component();
instance.observe('title', function(value) {
    alert(value);
});
instance.set('title', 'Hello!');
```

上面的示例显示了一个带有`Hello!`文本的`alert`窗口。让我们继续定义主应用程序文件的过程，换句话说，我们的社交网络的客户端入口点。

# 构建应用程序的入口点

在构建 Gulp 设置时，我们为 JavaScript 捆绑创建了一个任务。Browserify 需要一个入口点来解析依赖关系。我们设置为`frontend/js/app.js`。同样，对于后端，我们将围绕路由构建我们的逻辑。以下代码设置了两个路由，并提供了一个辅助函数来在页面上呈现 Ractive.js 组件：

```js
// frontend/js/app.js
var Router = require('./lib/Router')();
var Home = require('./controllers/Home');
var currentPage;
var body;

var showPage = function(newPage) {
  if(currentPage) { currentPage.teardown(); }
  currentPage = newPage;
  body.innerHTML = '';
  currentPage.render(body);
}

window.onload = function() {

  body = document.querySelector('body');

  Router
  .add('home', function() {
    var p = new Home();
    showPage(p);
  })
  .add(function() {
    Router.navigate('home');
  })
  .listen()
  .check();

}
```

我们需要在顶部引入`Router`变量。除此之外，我们还需要获取负责主页的控制器。我们将在下一节中详细了解这一点。现在，我们只会说它是一个 Ractive.js 组件。

我们不希望在页面资源完全加载之前运行任何 JavaScript。因此，我们将在`window.onload`处理程序中包装我们的引导代码。Ractive.js 组件的持有者将是`body`标签，我们将创建对它的引用。我们定义了一个名为`showPage`的辅助函数。它的工作是呈现当前页面并确保最后添加的页面被正确移除。`teardown`方法是框架的内置函数。它取消呈现组件并删除所有事件处理程序。

在本章中，我们将只有一个页面-主页。我们将使用我们为后端创建的路由器并注册一个`/home`路由。我们传递给`add`函数的第二个处理程序基本上是在没有匹配路由的情况下调用的。我们所做的是立即将用户转发到`/home` URL。最后，我们触发了路由器的监听并触发了初始检查。

在下一节中，我们将定义我们的第一个控制器-将控制我们的主页的组件。

# 定义控制器

在我们的上下文中，控制器的作用将是编排页面。换句话说，它们将充当管理子组件之间发生的过程的页面包装器。`controllers/Home.js`文件的内容如下：

```js
module.exports = Ractive.extend({
  template: require('../../tpl/home'),
  components: {
    navigation: require('../views/Navigation'),
    appfooter: require('../views/Footer')
  },
  onrender: function() {
    console.log('Home page rendered');
  }
});
```

在您查看模板和组件的属性之前，我们必须对`onrender`说几句话。Ractive.js 组件提供了一个接口，用于定义在组件生命周期的每个阶段内部发生的处理程序。例如，我们几乎每次在组件呈现在页面上后都需要执行一些操作。还有`onconstruct`，`onteardown`或`onupdate`。这无疑是实现业务逻辑的一种好方法。所有这些属性都在框架的官方文档中列出，网址为[`docs.ractivejs.org/latest/options`](http://docs.ractivejs.org/latest/options)。

我们在向您介绍 Ractive.js 时已经提到了`template`属性。但是，在下面的代码中，我们没有一个字符串作为值。我们需要另一个 JavaScript 文件-预编译的 HTML 模板。预编译是由构建系统 Gulp 完成的，如下所示：

```js
// gulpfile.js
gulp.task('templates', function() {
  gulp.src('./frontend/tpl/**/*.html')
  .pipe(tap(function(file, t) {
    var precompiled = Ractive.parse(file.contents.toString());
    precompiled = JSON.stringify(precompiled);
    file.contents = new Buffer('module.exports = ' + precompiled);
  }))
  .pipe(rename(function(path) {
    path.extname = '.js';
  }))
  .pipe(gulp.dest('./frontend/tpl'))
});
```

我们将从`frontend/tpl`目录获取所有 HTML 文件，并将它们转换为 Ractive.js 和 Browserify 理解的 JavaScript 文件。最后，Gulp 在同一目录中创建一个具有相同名称但扩展名不同的文件。例如，我们的主页模板可以如下所示：

```js
// frontend/tpl/home.html
<header>
  <navigation />
  <div class="hero">
    <h1>Node.js by example</h1>
  </div>
</header>
<appfooter />
```

当我们在终端中运行`gulp`时，我们将得到`frontend/tpl/home.js`，其内容如下：

```js
module.exports =  {"v":1,"t":[{"t":7,"e":"footer","f":["Version:  ",{"t":2,"r":"version"}]}]}
```

我们不必完全理解这些属性的含义。将 JavaScript 文件转换为 HTML 是框架预留的工作。

如果您检查前面代码中的模板和组件定义，您会注意到有两个子组件，`navigation`和`appfooter`。让我们看看如何创建它们。

# 管理我们的视图

再次，视图是 Ractive.js 组件。它们有自己的模板。事实上，`Home.js`模块也可以被称为视图。浏览器中的模型-视图-控制器模式经常会发生变化，并且不遵循精确的定义。这在我们的应用程序中是这样的，因为我们使用的框架有一些规则，并且提供了一些特定的功能，这些功能与典型的 MVC 不一致。当然，这并没有什么问题。只要我们分开责任，我们的架构就会很好。

`navigation`视图相当简单。它只定义了需要呈现的模板：

```js
// views/navigation.js
module.exports = Ractive.extend({
  template: require('../../tpl/navigation')
});
```

为了使事情更有趣并引入模型的定义，我们将在页脚中显示一个版本号。这个数字将来自于在`models/Version.js`中创建的模型。以下是`views/Footer.js`文件的代码：

```js
var FooterModel = require('../models/Version');

module.exports = Ractive.extend({
  template: require('../../tpl/footer'),
  onrender: function() {
    var model = new FooterModel();
    model.bindComponent(this).fetch();
  }
});
```

在解释`bindComponent`到底发生了什么之前，让我们来看看`tpl/footer.html`中有什么：

```js
<footer>
  Version: {{version}}
</footer>
```

我们有一个动态变量，`version`。如果我们不使用模型，我们必须在组件的`data`属性中定义它，或者使用`this.set('data', value)`。然而，`FooterModel`模块将使我们的生活更轻松，并更新与其绑定的组件的变量。这就是为什么我们将这个模块传递给`bindComponent`的原因。正如我们将在下一节中看到的，`fetch`方法将模型的数据与后端的数据同步。

# 创建一个模型

我们可能会有几个模型，它们都将共享相同的方法。通常，模型向服务器发出 HTTP 请求并获取数据。所以，这是我们需要抽象的东西。幸运的是，Ractive.js 使您能够扩展组件。这是`models/Version.js`文件的代码：

```js
var Base = require('./Base');
module.exports = Base.extend({
  data: {
    url: '/api/version'
  }
});
```

我们有`models/Base.js`，这个文件将包含这些通用函数。它将是一个基类，我们稍后会继承它。

```js
var ajax = require('../lib/Ajax');
module.exports = Ractive.extend({
  data: {
    value: null,
    url: ''
  },
  fetch: function() {
    var self = this;
    ajax.request({
      url: self.get('url'),
      json: true
    })
    .done(function(result) {
      self.set('value', result);
    })
    .fail(function(xhr) {
      self.fire('Error fetching ' + self.get('url'))
    });
    return this;
  },
  bindComponent: function(component) {
    if(component) {
      this.observe('value', function(v) {
        for(var key in v) {
         component.set(key, v[key]);
           }
      }, { init: false });
    }
    return this;
  }
});
```

我们定义了两个方法——`fetch`和`bindComponent`。第一个使用一个辅助的 Ajax 包装器。我们现在不打算深入讨论这个细节。它类似于 jQuery 的`.ajax`方法，并实现了 promise 接口模式。实际的源代码可以在随本书提供的文件中找到。

扩展`Base`模块的组件应该提供一个 URL。这是模型将发出请求的终点。在我们的情况下，这是`/api/version`。我们的后端将在这个 URL 上提供内容。

如果你回头检查我们对以`/api`开头的 URL 所做的事情，你会发现结果只是一个空对象。让我们改变这一点，覆盖`/api/version`路由的实现。我们将更新`backend/API.js`如下：

```js
var response = function(result, res) {
  res.writeHead(200, {'Content-Type': 'application/json'});
  res.end(JSON.stringify(result) + '\n');
}
var Router = require('../frontend/js/lib/router')();
Router
.add('api/version', function(req, res) {
  response({
    version: '0.1'
  }, res);
})
.add(function(req, res) {
  response({
    success: true
  }, res);
});

module.exports = function(req, res) {
  Router.check(req.url, [req, res]);
}
```

我们使用相同的路由器将 URL 映射到特定的响应。所以，在这个改变之后，我们的模型将获取`0.1`作为值。

最后，让我们揭示`bindComponent`函数中发生的魔法：

```js
bindComponent: function(component) {
  if(component) {
    this.observe('value', function(v) {
      for(var key in v) component.set(key, v[key]);
    }, { init: false });
  }
  return this;
}
```

我们观察本地`data`属性值的变化。在成功的`fetch`方法调用后进行更新。新值传递给处理程序，我们只是将变量传递给组件。这只是几行代码，但它们成功地带来了一个很好的抽象。在实际的模型定义中，我们只需要指定 URL。`Base`模块会处理其余部分。

# 总结

在本章中，我们构建了我们应用程序的基础。我们还创建了我们系统的基础——路由器。控制器现在很好地绑定到路由，并且视图在页面上呈现，当模型的值发生变化时，显示会自动更新。我们还引入了一个简单的模型，它从后端的 API 获取数据。

在下一章中，我们将实现一个真正有效的功能——我们将管理我们系统的用户。
