# NodeJS 秘籍（一）

> 原文：[`zh.annas-archive.org/md5/B8CF3F6C144C7F09982676822001945F`](https://zh.annas-archive.org/md5/B8CF3F6C144C7F09982676822001945F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

异步事件驱动编程的原则非常适合当今的 Web，其中高效的实时应用程序和可伸缩性处于前沿。服务器端 JavaScript 自上世纪九十年代以来就一直存在，但 Node 做得很好。随着蓬勃发展的社区和互联网巨头的兴趣，它可能成为明天的 PHP。

《Node Cookbook》向您展示如何将您的 JavaScript 技能转移到服务器端编程。通过简单的示例和支持代码，《Node Cookbook》带您了解各种服务器端场景，通常通过演示最佳实践并向您展示如何避免安全错误，从而节省时间、精力和麻烦。

从制作自己的 Web 服务器开始，本书中的实用食谱旨在平稳地引导您制作完整的 Web 应用程序、命令行应用程序和 Node 模块。《Node Cookbook》带您了解与各种数据库后端的接口，如 MySQL、MongoDB 和 Redis，使用 Web 套接字，并与网络协议进行接口，如 SMTP。此外，还有关于处理数据流、安全实现、编写自己的 Node 模块以及将应用程序上线的不同方法的食谱。

# 本书涵盖内容

第一章，“制作 Web 服务器”，涵盖了提供动态和静态内容，将文件缓存在内存中，直接从磁盘上 HTTP 流式传输大文件以及保护您的 Web 服务器。

第二章，“探索 HTTP 对象”，解释了如何接收和处理 POST 请求和文件上传，使用 Node 作为 HTTP 客户端，并讨论了如何限制下载速度。

第三章，“数据序列化”，解释了如何将应用程序中的数据转换为 XML 和 JSON 格式，以便发送到浏览器或第三方 API。

第四章，“与数据库接口”，涵盖了如何使用 Redis、CouchDB、MongoDB、MySQL 或普通 CSV 文件实现持久数据存储。

第五章，“超越 AJAX：使用 WebSockets”，帮助您使用现代浏览器 WebSocket 技术制作实时网络应用程序，并优雅地降级到长轮询和其他方法，使用`Socket.io`。

第六章，“使用 Express 加速开发”，解释了如何利用 Express 框架实现快速 Web 开发。它还涵盖了使用模板语言和 CSS 引擎，如 LESS 和 Stylus。

第七章，“实施安全、加密和身份验证”，解释了如何设置 SSL 安全的 Web 服务器，使用加密模块创建强密码哈希，并保护用户免受跨站点请求伪造攻击。

第八章，“集成网络范式”，讨论了发送电子邮件和创建自己的电子邮件服务器，发送短信，实施虚拟主机，以及使用原始 TCP 进行有趣和有趣的事情。

第九章，“编写自己的 Node 模块”，解释了如何创建测试套件，编写解决方案，重构，改进和扩展，然后部署自己的 Node 模块。

第十章，“上线”，讨论了如何将您的 Web 应用程序部署到实时服务器，确保您的应用程序通过崩溃恢复技术保持在线，实施持续部署工作流程，或者简单地使用作为服务提供商。

# 您需要什么

+   Windows、Mac OS X 或 Linux

+   Node 0.6.x 或 Node 0.8.x 可从[`www.nodejs.org`](http://www.nodejs.org)免费获取

将继续适用于 Node 的 1.x.x 版本

# 这本书适合谁

如果您对 JavaScript 有一些了解，并且想要构建快速、高效、可扩展的客户端-服务器解决方案，那么*Node Cookbook*就是为您准备的。有经验的 Node 用户将提高他们的技能，即使您以前没有使用过 Node，这些实用的配方也将使您轻松上手。

# 约定

在这本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码单词显示如下：“为了创建服务器，我们需要`http`模块。”

一块代码设置如下：

```js
	var http = require('http');
	http.createServer(function (request, response) {
	response.writeHead(200, {'Content-Type': 'text/html'}); 
	response.end('Woohoo!');
	}).listen(8080);

```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目会以粗体显示：

```js
	var http = require('http');
	var path = require('path'); 
	http.createServer(function (request, response) {
	var lookup=path.basename(decodeURI(request.url)); 

```

任何命令行输入或输出都是这样写的：

```js
sudo npm -g install express 

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，比如菜单或对话框中的单词，会在文本中出现，就像这样：“我们可以让一个假设的用户表明他们是否受到了一句引语的启发，比如一个**喜欢**按钮。”

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会出现在这样。


# 第一章：创建 Web 服务器

在本章中，我们将涵盖：

+   设置路由

+   提供静态文件

+   在内存中缓存内容以立即提供

+   使用流优化性能

+   防止文件系统黑客攻击

# 介绍

Node 的一个伟大特点是它的简单性。与 PHP 或 ASP 不同，它没有将 web 服务器和代码分开，也不需要定制大型配置文件来获得我们想要的行为。使用 Node，我们可以创建服务器，自定义它，并在代码级别提供内容。本章演示了如何使用 Node 创建 web 服务器，并通过它提供内容，同时实现安全性和性能增强以满足各种情况。

# 设置路由

为了提供 web 内容，我们需要使 URI 可用。本教程将指导我们创建一个公开路由的 HTTP 服务器。

## 准备工作

首先，让我们创建我们的服务器文件。如果我们的主要目的是公开服务器功能，通常的做法是将文件命名为`server.js`，然后将其放在一个新文件夹中。安装和使用`hotnode`也是一个好主意：

```js
sudo npm -g install hotnode
hotnode server.js

```

当我们保存更改时，`hotnode`将方便地自动重新启动服务器。

## 如何做...

为了创建服务器，我们需要`http`模块，所以让我们加载它并使用`http.createServer`方法：

```js
	var http = require('http');
	http.createServer(function (request, response) {
	response.writeHead(200, {'Content-Type': 'text/html'});
	response.end('Woohoo!');
	}).listen(8080);

```

### 提示

**下载示例代码**

您可以从您在[`www.PacktPub.com`](http://www.PacktPub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.PacktPub.com/support`](http://www.PacktPub.com/support)并注册，以便直接通过电子邮件接收文件。

现在，如果我们保存我们的文件并在 web 浏览器上或使用 curl 访问`localhost:8080`，我们的浏览器（或 curl）将会呼喊：`'Woohoo!'`。然而，在`localhost:8080/foo`上也会发生同样的事情。实际上，任何路径都会产生相同的行为，因此让我们构建一些路由。我们可以使用`path`模块提取路径的`basename`（路径的最后一部分），并使用`decodeURI`从客户端反转任何 URI 编码：

```js
	var http = require('http');
	var path = require('path'); 
	http.createServer(function (request, response) {
	var lookup = path.basename(decodeURI(request.url)); 

```

现在我们需要一种定义路由的方法。一种选择是使用对象数组：

```js
	var pages = [
	  {route: '', output: 'Woohoo!'},
	  {route: 'about', output: 'A simple routing with Node example'},
	  {route: 'another page', output: function() {return 'Here\'s '+this.route;}},
	];

```

我们的`pages`数组应该放在`http.createServer`调用之上。

在我们的服务器内部，我们需要循环遍历我们的数组，并查看查找变量是否与我们的路由中的任何一个匹配。如果匹配，我们可以提供输出。我们还将实现一些`404`处理：

```js
	http.createServer(function (request, response) {
	  var lookup=path.basename(decodeURI(request.url));
	  pages.forEach(function(page) {
	    if (page.route === lookup) {
	      response.writeHead(200, {'Content-Type': 'text/html'});
	      response.end(typeof page.output === 'function' 
	                   ? page.output() : page.output);
	    }
	  });
	  if (!response.finished) {
	     response.writeHead(404);
	     response.end('Page Not Found!');
	  }
	}).listen(8080);

```

## 工作原理...

我们提供给`http.createServer`的回调函数为我们提供了通过`request`和`response`对象与服务器进行交互所需的所有功能。我们使用`request`来获取请求的 URL，然后我们使用`path`获取它的`basename`。我们还使用`decodeURI`，如果没有它，我们的`another page`路由将失败，因为我们的代码将尝试将`another%20page`与我们的`pages`数组进行匹配并返回`false`。

一旦我们有了`basename`，我们可以以任何我们想要的方式进行匹配。我们可以将其发送到数据库查询以检索内容，使用正则表达式进行部分匹配，或者将其与文件名匹配并加载其内容。

我们本可以使用`switch`语句来处理路由，但我们的`pages`数组有几个优点。它更容易阅读和扩展，并且可以无缝转换为 JSON。我们使用`forEach`循环遍历我们的`pages`数组。

Node 是建立在谷歌的 V8 引擎上的，它为我们提供了许多 ECMAScript 5 功能。这些功能不能在所有浏览器中使用，因为它们尚未普遍实现，但在 Node 中使用它们没有问题！`forEach`是 ES5 的实现，但 ES3 的方法是使用不太方便的`for`循环。

在循环遍历每个对象时，我们检查它的`route`属性。如果我们找到匹配，我们将写入`200 OK`状态和`content-type`头。然后我们用对象的输出属性结束响应。

`response.end`允许我们向其传递参数，在完成响应之前写入。在`response.end`中，我们使用了一个三元运算符（?:）来有条件地调用`page.output`作为函数或简单地将其作为字符串传递。请注意，`another page`路由包含一个函数而不是一个字符串。该函数通过`this`变量可以访问其父对象，并允许更灵活地组装我们想要提供的输出。如果在我们的`forEach`循环中没有匹配，`response.end`将永远不会被调用。因此，客户端将继续等待响应，直到超时。为了避免这种情况，我们检查`response.finished`属性，如果为 false，我们写入一个`404`头并结束响应。

`response.finished`取决于`forEach`回调，但它并不嵌套在回调内部。回调函数主要用于异步操作。因此，表面上看起来像是潜在的竞争条件，但`forEach`并不是异步操作。它会继续阻塞，直到所有循环完成。

## 还有更多...

有许多方法可以扩展和修改这个示例。还有一些非核心模块可供我们使用。

### 简单多级路由

到目前为止，我们的路由只处理单级路径。多级路径（例如，`/about/node`）将简单地返回`404`。我们可以修改我们的对象以反映子目录结构，删除`path`，并使用`request.url`而不是`path.basename`来作为我们的路由。

```js
	var http=require('http');
	var pages = [
	  {route: '/', output: 'Woohoo!'},
	  {route: '/about/this', output: 'Multilevel routing with Node'},
	  {route: '/about/node', output: 'Evented I/O for V8 JavaScript.'},
	  {route: '/another page', output: function () {return 'Here\'s ' + this.route; }}
	];
	http.createServer(function (request, response) {
	  var lookup = decodeURI(request.url);

```

### 注意

在提供静态文件时，必须在获取给定文件之前清理`request.url`。请查看本章中讨论的*防止文件系统黑客攻击*部分。

多级路由可以进一步进行，允许我们构建然后遍历一个更复杂的对象。

```js
	{route: 'about', childRoutes: [
	  {route: 'node', output: 'Evented I/O for V8 Javascript'},
	  {route: 'this', output: 'Complex Multilevel Example'}
	]}

```

在第三或第四级之后，查看这个对象将变得非常庞大。我们可以创建一个辅助函数来定义我们的路由，从而为我们拼接对象。或者，我们可以使用开源 Node 社区提供的出色的非核心路由模块之一。已经存在出色的解决方案，提供了帮助方法来处理可扩展多级路由的不断增加的复杂性（请参阅本章和第六章中讨论的*路由模块*，*使用 Express 加速开发*）。

### 解析查询字符串

另外两个有用的核心模块是`url`和`querystring`。`url.parse`方法允许两个参数。首先是 URL 字符串（在我们的情况下，这将是`request.url`），第二个是名为`parseQueryString`的布尔参数。如果设置为`true`，它会延迟加载`querystring`模块，省去了我们需要要求它来解析查询为对象。这使我们可以轻松地与 URL 的查询部分交互。

```js
	var http = require('http');
	var url = require('url');
	var pages = [
		{id: '1', route: '', output: 'Woohoo!'},
		{id: '2', route: 'about', output: 'A simple routing with Node example'},
		{id: '3', route: 'another page', output: function () {return 'Here\'s ' + this.route; }},
	];
	http.createServer(function (request, response) {
		var id = url.parse(decodeURI(request.url), true).query.id;
	if (id) {
		pages.forEach(function (page) {
			if (page.id === id) {
				response.writeHead(200, {'Content-Type': 'text/html'});
				response.end(typeof page.output === 'function'
					? page.output() : page.output);
			}
		});
	}
	if (!response.finished) {
		response.writeHead(404);
		response.end('Page Not Found');
	}
}).listen(8080);

```

通过添加`id`属性，我们可以通过`localhost:8080?id=2`等方式访问我们的对象数据。

### 路由模块

有关 Node 的各种路由模块的最新列表，请访问[`www.github.com/joyent/node/wiki/modules#wiki-web-frameworks-routers`](https://www.github.com/joyent/node/wiki/modules#wiki-web-frameworks-routers)。这些由社区制作的路由器适用于各种场景。在将其引入生产环境之前，重要的是要研究模块的活动和成熟度。在第六章中，*使用 Express 加速开发*，我们将更详细地讨论使用内置的 Express/Connect 路由器来实现更全面的路由解决方案。

## 另请参阅

+   本章中讨论的*提供静态文件*和*防止文件系统黑客攻击*。

+   在第六章中讨论的*动态路由*。

# 提供静态文件

如果我们在磁盘上存储了要作为 Web 内容提供的信息，我们可以使用`fs`（文件系统）模块加载我们的内容并通过`createServer`回调传递。这是提供静态文件的基本概念起点。正如我们将在接下来的示例中学到的，还有更高效的解决方案。

## 准备工作

我们需要一些要提供的文件。让我们创建一个名为`content`的目录，其中包含以下三个文件：

`index.html:`

```js
	<html>
	<head>
	<title>Yay Node!</title>
	<link rel=stylesheet href=styles.css type=text/css>
	<script src=script.js type=text/javascript></script>
	</head>
	<body>
	<span id=yay>Yay!</span>
	</body>
	</html>

```

`script.js:`

```js
window.onload=function() {alert('Yay Node!');};

```

`styles.css:`

```js
#yay {font-size:5em;background:blue;color:yellow;padding:0.5em}

```

## 操作步骤...

与之前的示例一样，我们将使用核心模块`http`和`path`。我们还需要访问文件系统，因此我们也需要`fs`模块。让我们创建我们的服务器：

```js
	var http = require('http');
	var path = require('path');
	var fs = require('fs');
	http.createServer(function (request, response) {
	  var lookup = path.basename(decodeURI(request.url)) || 'index.html',
	    f = 'content/' + lookup;
	  path.exists(f, function (exists) {
	    console.log(exists ? lookup + " is there" : lookup + " doesn't exist");
	  });
	}).listen(8080);

```

如果我们还没有，我们可以初始化我们的`server.js`文件：

```js
 hotnode server.js 

```

尝试加载`localhost:8080/foo`，控制台将显示`foo 不存在`，因为它确实不存在。`localhost:8080/script.js`将告诉我们`script.js 存在`，因为它确实存在。在保存文件之前，我们应该让客户端知道`content-type`，我们可以从文件扩展名中确定。因此，让我们使用对象快速创建一个映射：

```js
	var mimeTypes = {
	  '.js' : 'text/javascript',
	  '.html': 'text/html',
	  '.css' : 'text/css'
	};

```

我们以后可以扩展我们的`mimeTypes`映射以支持更多类型。

### 注意

现代浏览器可能能够解释某些 MIME 类型（例如`text/javascript`）而无需服务器发送`content-type`头。然而，旧版浏览器或较少使用的 MIME 类型将依赖服务器发送正确的`content-type`头。

请记住，将`mimeTypes`放在服务器回调之外，因为我们不希望在每个客户端请求上初始化相同的对象。如果请求的文件存在，我们可以通过将`path.extname`传递给`mimeTypes`，然后将我们检索到的`content-type`传递给`response.writeHead`来将我们的文件扩展名转换为`content-type`。如果请求的文件不存在，我们将写出`404`并结束响应。

```js
	//requires variables, mimeType object...
	http.createServer(function (request, response) {
		var lookup = path.basename(decodeURI(request.url)) || 'index.html',
			f = 'content/' + lookup;
		fs.exists(f, function (exists) {
			if (exists) {
				fs.readFile(f, function (err, data) {
					if (err) { response.writeHead(500);
						response.end('Server Error!'); return; }
					var headers = {'Content-type': mimeTypes[path. extname(lookup)]};
					response.writeHead(200, headers);
					response.end(data);
				});
				return;
			}
			response.writeHead(404); //no such file found!
			response.end();
		});
}).listen(8080);

```

目前，仍然没有内容发送到客户端。我们必须从我们的文件中获取这些内容，因此我们将响应处理包装在`fs.readFile`方法的回调中。

```js
	//http.createServer, inside path.exists:
	if (exists) {
	  fs.readFile(f, function(err, data) {
	    var headers={'Content-type': mimeTypes[path.extname(lookup)]};
	    response.writeHead(200, headers);
	    response.end(data);
	  });
	 return;
	}

```

在我们完成之前，让我们对我们的`fs.readFile`回调应用一些错误处理，如下所示：

```js
	//requires variables, mimeType object...
	//http.createServer,  path exists, inside if(exists):  
	fs.readFile(f, function(err, data) {
	    if (err) {response.writeHead(500); response.end('Server Error!');  return; }
	    var headers = {'Content-type': mimeTypes[path.extname(lookup)]};
	    response.writeHead(200, headers);
	    response.end(data);            
	  });
	 return;
	}

```

请注意，`return`保持在`fs.readFile`回调之外。我们从`fs.exists`回调中返回，以防止进一步的代码执行（例如，发送`404`）。在`if`语句中放置`return`类似于使用`else`分支。然而，在 Node 中，`if return`模式通常比使用`if else`更可取，因为它消除了另一组花括号。

现在我们可以导航到`localhost:8080`，这将提供我们的`index.html`文件。`index.html`文件调用我们的`script.js`和`styles.css`文件，我们的服务器也以适当的 MIME 类型提供这些文件。结果可以在以下截图中看到：

![操作步骤...](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-cb/img/7188_01_image.jpg)

这个示例用来说明提供静态文件的基本原理。请记住，这不是一个高效的解决方案！在现实世界的情况下，我们不希望每次请求到达服务器时都进行 I/O 调用，尤其是对于较大的文件来说，这是非常昂贵的。在接下来的示例中，我们将学习更好的方法来提供静态文件。

## 工作原理...

我们的脚本创建了一个服务器并声明了一个名为`lookup`的变量。我们使用双管道（||）*或*运算符为`lookup`赋值。这定义了一个默认路由，如果`path.basename`为空的话。然后我们将`lookup`传递给一个新变量，我们将其命名为`f`，以便将我们的`content`目录前置到预期的文件名。接下来，我们通过`fs.exists`方法运行`f`并检查回调中的`exist`参数，以查看文件是否存在。如果文件存在，我们使用`fs.readFile`进行异步读取。如果访问文件出现问题，我们将写入`500`服务器错误，结束响应，并从`fs.readFile`回调中返回。我们可以通过从`index.html`中删除读取权限来测试错误处理功能。

```js
chmod -r index.html 

```

这样做将导致服务器抛出`500`服务器错误状态码。要再次设置正确，请运行以下命令：

```js
chmod +r index.html 

```

只要我们可以访问文件，就可以使用我们方便的`mimeTypes`映射对象来获取`content-type`，编写标头，使用从文件加载的数据结束响应，最后从函数返回。如果请求的文件不存在，我们将绕过所有这些逻辑，写入`404`，并结束响应。

## 还有更多...

需要注意的一点是...

### 网站图标陷阱

当使用浏览器测试我们的服务器时，有时会观察到意外的服务器请求。这是浏览器请求服务器可以提供的默认`favicon.ico`图标文件。除了看到额外的请求之外，这通常不是问题。如果网站图标请求开始干扰，我们可以这样处理：

```js
	if (request.url === '/favicon.ico') {
	  response.end();
	  return;
	}

```

如果我们想对客户端更有礼貌，还可以在发出`response.end`之前使用`response.writeHead(404)`通知它`404`。

## 另请参阅

+   *在本章中讨论的将内容缓存在内存中以进行即时传递*

+   *在本章中讨论的使用流来优化性能*

+   *在本章中讨论的防止文件系统黑客攻击*

# 将内容缓存在内存中以进行即时传递

直接在每个客户端请求上访问存储并不理想。在本例中，我们将探讨如何通过仅在第一次请求时访问磁盘、为第一次请求缓存文件数据以及从进程内存中提供所有后续请求来增强服务器效率。

## 准备工作

我们将改进上一个任务中的代码，因此我们将使用`server.js`，以及`content`目录中的`index.html，styles.css`和`script.js`。

## 操作步骤...

让我们首先看一下上一个配方“提供静态文件”的脚本

```js
	var http = require('http');
	var path = require('path');
	var fs = require('fs');  

	var mimeTypes = {
	  '.js' : 'text/javascript',
	  '.html': 'text/html',
	  '.css' : 'text/css'
	} ;

	http.createServer(function (request, response) {
	  var lookup = path.basename(decodeURI(request.url)) || 'index.html';
	  var f = 'content/'+lookup;
	  path.exists(f, function (exists) {
	    if (exists) {
	      fs.readFile(f, function(err,data) {
	      if (err) {response.writeHead(500); response.end('Server Error!'); return; }
	      var headers = {'Content-type': mimeTypes[path.extname(lookup)]};
	        response.writeHead(200, headers);
	        response.end(data);            
	      });
	      return;
	    }
	      response.writeHead(404); //no such file found!
	      response.end('Page Not Found!');
	  });

```

我们需要修改这段代码，只读取文件一次，将其内容加载到内存中，然后从内存中响应所有对该文件的请求。为了保持简单和可维护性，我们将缓存处理和内容传递提取到一个单独的函数中。因此，在`http.createServer`上方，并在`mimeTypes`下方，我们将添加以下内容：

```js
	var cache = {};
	function cacheAndDeliver(f, cb) {
	  if (!cache[f]) {
	    fs.readFile(f, function(err, data) {
	      if (!err) {
	        cache[f] = {content: data} ;
	      }     
	      cb(err, data);
	    });
	    return;
	  }
	  console.log('loading ' + f + ' from cache');
	  cb(null, cache[f].content);
	}
	//http.createServer …..

```

添加了一个新的`cache`对象，用于将文件存储在内存中，以及一个名为`cacheAndDeliver`的新函数。我们的函数接受与`fs.readFile`相同的参数，因此我们可以在`http.createServer`回调中替换`fs.readFile`，同时保持其余代码不变：

```js
	//...inside http.createServer:
	path.exists(f, function (exists) {
	    if (exists) {
	      cacheAndDeliver(f, function(err, data) {
	        if (err) {response.writeHead(500); response.end('Server Error!'); return; }
	        var headers = {'Content-type': mimeTypes[path.extname(f)]};
	        response.writeHead(200, headers);
	        response.end(data);      
	      });
	  return;
	    }
	//rest of path exists code (404 handling)...

```

当我们执行`server.js`文件并连续两次访问`localhost:8080`时，第二个请求会导致控制台输出以下内容：

```js
 loading content/index.html from cache
	loading content/styles.css from cache
	loading content/script.js from cache

```

## 工作原理...

我们定义了一个名为`cacheAndDeliver`的函数，类似于`fs.readFile`，它接受文件名和回调作为参数。这很棒，因为我们可以将完全相同的`fs.readFile`回调传递给`cacheAndDeliver`，在不向`http.createServer`回调内部添加任何额外可视复杂性的情况下，为服务器添加缓存逻辑。目前来看，将我们的缓存逻辑抽象成外部函数的价值是有争议的，但是随着我们不断增强服务器的缓存能力，这种抽象变得越来越可行和有用。我们的`cacheAndDeliver`函数检查所请求的内容是否已经缓存，如果没有，我们调用`fs.readFile`并从磁盘加载数据。一旦我们有了这些数据，我们可能会保留它，因此它被放入由其文件路径引用的`cache`对象中（`f`变量）。下次有人请求文件时，`cacheAndDeliver`将看到我们在`cache`对象中存储了文件，并将发出包含缓存数据的替代回调。请注意，我们使用另一个新对象填充了`cache[f]`属性，其中包含一个`content`属性。这样做可以更容易地扩展将来的缓存功能，因为我们只需要将额外的属性放入我们的`cache[f]`对象中，并提供与这些属性相对应的接口逻辑。

## 还有更多...

如果我们修改正在提供的文件，任何更改都不会反映在我们重新启动服务器之前。我们可以解决这个问题。

### 反映内容更改

要检测请求的文件自上次缓存以来是否发生了更改，我们必须知道文件何时被缓存以及上次修改时间。为了记录文件上次缓存的时间，让我们扩展`cache[f]`对象：

```js
	cache[f] = {content: data,
	                      timestamp: Date.now() //store a Unix time stamp
	                     };

```

现在我们需要找出文件上次更新的时间。`fs.stat`方法在其回调的第二个参数中返回一个对象。该对象包含与命令行 GNU coreutils `stat.fs.stat`提供的相同有用信息：上次访问时间（`atime`）、上次修改时间（`mtime`）和上次更改时间（`ctime`）。`mtime`和`ctime`之间的区别在于`ctime`将反映对文件的任何更改，而`mtime`只会反映对文件内容的更改。因此，如果我们更改了文件的权限，`ctime`会更新，但`mtime`会保持不变。我们希望在发生权限更改时注意到，因此让我们使用`ctime`属性：

```js
	//requires and mimeType object....
	var cache = {};
	function cacheAndDeliver(f, cb) {
		fs.stat(f, function (err, stats) {
			var lastChanged = Date.parse(stats.ctime),
				isUpdated = (cache[f]) && lastChanged > cache[f].timestamp;
			if (!cache[f] || isUpdated) {
				fs.readFile(f, function (err, data) {
					console.log('loading ' + f + ' from file');
					//rest of cacheAndDeliver
		}); //end of fs.stat
	} // end of cacheAndDeliver

```

`cacheAndDeliver`的内容已经包装在`fs.stat`回调中。添加了两个变量，并修改了`if(!cache[f])`语句。我们解析了第二个参数`stats`的`ctime`属性，使用`Date.parse`将其转换为自 1970 年 1 月 1 日午夜以来的毫秒数（Unix 纪元），并将其分配给我们的`lastChanged`变量。然后我们检查所请求文件的上次更改时间是否大于我们缓存文件的时间（假设文件确实已缓存），并将结果分配给我们的`isUpdated`变量。之后，只需通过`||`（或）运算符将`isUpdated`布尔值添加到条件`if(!cache[f])`语句中。如果文件比我们缓存的版本更新（或者尚未缓存），我们将文件从磁盘加载到缓存对象中。

## 另请参阅

+   在本章中讨论了通过流优化性能

+   *在* 第三章 *中讨论了通过 AJAX 进行浏览器-服务器传输*，*数据序列化处理*

# 通过流优化性能

缓存内容确实改进了每次请求时从磁盘读取文件。但是，使用`fs.readFile`时，我们是在将整个文件读入内存后再将其发送到`response`中。为了提高性能，我们可以从磁盘流式传输文件，并将其直接传输到`response`对象，一次发送一小部分数据到网络套接字。

## 准备工作

我们正在构建上一个示例中的代码，所以让我们准备好`server.js, index.html, styles.css`和`script.js`。

## 如何做...

我们将使用`fs.createReadStream`来初始化一个流，可以将其传输到`response`对象。在这种情况下，在我们的`cacheAndDeliver`函数中实现`fs.createReadStream`并不理想，因为`fs.createReadStream`的事件监听器将需要与`request`和`response`对象进行接口。为了简单起见，这些最好在`http.createServer`回调中处理。为了简洁起见，我们将放弃我们的`cacheAndDeliver`函数，并在服务器回调中实现基本的缓存：

```js
	//requires, mime types, createServer, lookup and f vars...
	path.exists(f, function (exists) {
	    if (exists) {  
	      var headers = {'Content-type': mimeTypes[path.extname(f)]};
	      if (cache[f]) {
	        response.writeHead(200, headers);              
	        response.end(cache[f].content);  
	        return;
	      } //...rest of server code...

```

稍后，当我们与`readStream`对象进行接口时，我们将填充`cache[f].content`。以下是我们如何使用`fs.createReadStream：`

```js
var s = fs.createReadStream(f);

```

这将返回一个`readStream`对象，该对象流式传输由`f`变量指向的文件。`readStream`发出我们需要监听的事件。我们可以使用`addEventListener`进行监听，也可以使用简写的`on:`

```js
var s = fs.createReadStream(f).on('open', function () {
//do stuff when the readStream opens
});

```

由于`createReadStream`返回`readStream`对象，我们可以使用点符号的方法链接将我们的事件监听器直接附加到它上面。每个流只会打开一次，我们不需要继续监听它。因此，我们可以使用`once`方法而不是`on`方法，在第一次事件发生后自动停止监听：

```js
var s = fs.createReadStream(f).once('open', function () {
//do stuff when the readStream opens
});

```

在我们填写`open`事件回调之前，让我们按照以下方式实现错误处理：

```js
	var s = fs.createReadStream(f).once('open', function () {
	//do stuff when the readStream opens
	}).once('error', function (e) {
	    console.log(e);
	    response.writeHead(500);
	    response.end('Server Error!');
	});

```

整个努力的关键是`stream.pipe`方法。这使我们能够直接从磁盘获取文件并将其直接通过我们的`response`对象流式传输到网络套接字。

```js
	var s = fs.createReadStream(f).once('open', function () {
	    response.writeHead(200, headers);      
	    this.pipe(response);
	}).once('error', function (e) {
	    console.log(e);
	    response.writeHead(500);
	    response.end('Server Error!');
	});

```

结束响应怎么办？方便的是，`stream.pipe`会检测流何时结束，并为我们调用`response.end`。出于缓存目的，我们需要监听另一个事件。在我们的`fs.exists`回调中，在`createReadStream`代码块下面，我们编写以下代码：

```js
	 fs.stat(f, function(err, stats) {
		        var bufferOffset = 0;
	      	  cache[f] = {content: new Buffer(stats.size)};
		       s.on('data', function (chunk) {
	             chunk.copy(cache[f].content, bufferOffset);
	             bufferOffset += chunk.length;
	        });
	      }); 

```

我们使用`data`事件来捕获正在流式传输的缓冲区，并将其复制到我们提供给`cache[f].content`的缓冲区中，使用`fs.stat`来获取文件的缓冲区大小。

## 它是如何工作的...

客户端不需要等待服务器从磁盘加载完整的文件然后再发送给客户端，我们使用流来以小的、有序的片段加载文件，并立即发送给客户端。对于较大的文件，这是特别有用的，因为在文件被请求和客户端开始接收文件之间几乎没有延迟。

我们通过使用`fs.createReadStream`来开始从磁盘流式传输我们的文件。`fs.createReadStream`创建了`readStream`，它继承自`EventEmitter`类。

`EventEmitter`类实现了 Node 标语中的*evented*部分：Evented I/O for V8 JavaScript。因此，我们将使用监听器而不是回调来控制流逻辑的流程。

然后我们使用`once`方法添加了一个`open`事件监听器，因为我们希望一旦触发就停止监听`open`。我们通过编写标头并使用`stream.pipe`方法将传入的数据直接传输到客户端来响应`open`事件。

`stream.pipe`处理数据流。如果客户端在处理过程中变得不堪重负，它会向服务器发送一个信号，服务器应该通过暂停流来予以尊重。在底层，`stream.pipe`使用`stream.pause`和`stream.resume`来管理这种相互作用。

当响应被传输到客户端时，内容缓存同时被填充。为了实现这一点，我们必须为`cache[f].content`属性创建一个`Buffer`类的实例。`Buffer`必须提供一个大小（或数组或字符串），在我们的情况下是文件的大小。为了获取大小，我们使用了异步的`fs.stat`并在回调中捕获了`size`属性。`data`事件将`Buffer`作为其唯一的回调参数返回。

流的默认`bufferSize`为 64 KB。任何大小小于`bufferSize`的文件将只触发一个`data`事件，因为整个文件将适合第一个数据块中。但是，对于大于`bufferSize`的文件，我们必须一次填充我们的`cache[f].content`属性的一部分。

### 注意

更改默认的`readStream`缓冲区大小：

我们可以通过传递一个`options`对象并在`fs.createReadStream`的第二个参数中添加一个`bufferSize`属性来更改`readStream`的缓冲区大小。

例如，要将缓冲区加倍，可以使用`fs.createReadStream(f,{bufferSize: 128 * 1024})`；

我们不能简单地将每个`chunk`与`cache[f].content`连接起来，因为这样会将二进制数据强制转换为字符串格式，尽管不再是二进制格式，但以后会被解释为二进制格式。相反，我们必须将所有小的二进制缓冲区`chunks`复制到我们的二进制`cache[f].content`缓冲区中。

我们创建了一个`bufferOffset`变量来帮助我们。每次我们向我们的`cache[f].content`缓冲区添加另一个`chunk`时，我们通过将`chunk`缓冲区的长度添加到它来更新我们的新`bufferOffset`。当我们在`chunk`缓冲区上调用`Buffer.copy`方法时，我们将`bufferOffset`作为第二个参数传递，以便我们的`cache[f].content`缓冲区被正确填充。

此外，使用`Buffer`类进行操作可以提高性能，因为它可以绕过 V8 的垃圾回收方法。这些方法往往会使大量数据碎片化，从而减慢 Node 处理它们的能力。

## 还有更多...

虽然流解决了等待文件加载到内存中然后传递它们的问题，但我们仍然通过我们的`cache`对象将文件加载到内存中。对于较大的文件或大量文件，这可能会产生潜在的影响。

### 防止进程内存溢出

进程内存有限。默认情况下，V8 的内存在 64 位系统上设置为 1400 MB，在 32 位系统上设置为 700 MB。可以通过在 Node 中运行`--max-old-space-size=N`来改变这个值，其中`N`是以兆字节为单位的数量（实际可以设置的最大值取决于操作系统和可用的物理 RAM 数量）。如果我们绝对需要占用大量内存，我们可以在大型云平台上运行服务器，分割逻辑，并使用`child_process`类启动新的 node 实例。

在这种情况下，高内存使用并不一定是必需的，我们可以优化我们的代码，显著减少内存溢出的可能性。对于缓存较大的文件，好处较少。与总下载时间相比，轻微的速度提高是微不足道的，而缓存它们的成本相对于我们可用的进程内存来说是相当显著的。我们还可以通过在缓存对象上实现过期时间来提高缓存效率，然后用它来清理缓存，从而删除低需求的文件，并优先处理高需求的文件以实现更快的传递。让我们稍微重新排列一下我们的`cache`对象：

```js
	var cache = {
	  store: {},
	  maxSize : 26214400, //(bytes) 25mb
	}

```

为了更清晰的思维模型，我们要区分缓存作为一个功能实体和缓存作为存储（这是更广泛的缓存实体的一部分）。我们的第一个目标是只缓存一定大小的文件。我们为此定义了`cache.maxSize`。现在我们只需要在`fs.stat`回调中插入一个`if`条件：

```js
	 fs.stat(f, function (err, stats) {
	        if (stats.size < cache.maxSize) {
	          var bufferOffset = 0;
	          cache.store[f] = {content: new Buffer(stats.size),
	                                     timestamp: Date.now() };
	          s.on('data', function (data) {
	            data.copy(cache.store[f].content, bufferOffset);
	            bufferOffset += data.length;
	          });
	        }  
	      });

```

请注意，我们还在我们的`cache.store[f]`中悄悄地添加了一个新的`timestamp`属性。这是为了清理缓存，这是我们的第二个目标。让我们扩展`cache:`。

```js
	var cache = {
	  store: {},
	  maxSize: 26214400, //(bytes) 25mb
	  maxAge: 5400 * 1000, //(ms) 1 and a half hours
	  clean: function(now) {
	      var that = this;
	      Object.keys(this.store).forEach(function (file) {
	        if (now > that.store[file].timestamp + that.maxAge) {
	          delete that.store[file];      
	        }
	      });
	  }
	};

```

因此，除了`maxSize`，我们创建了一个`maxAge`属性并添加了一个`clean`方法。我们在服务器底部调用`cache.clean`，如下所示：

```js
	//all of our code prior
	  cache.clean(Date.now());
	}).listen(8080); //end of the http.createServer

```

`cache.clean`循环遍历`cache.store`，并检查它是否已超过指定的生命周期。如果是，我们就从`store`中移除它。我们将再添加一个改进，然后就完成了。`cache.clean`在每个请求上都会被调用。这意味着`cache.store`将在每次服务器命中时被循环遍历，这既不必要也不高效。如果我们每隔两个小时或者更长时间清理一次缓存，效果会更好。我们将向`cache`添加两个属性。第一个是`cleanAfter`，用于指定清理缓存的时间间隔。第二个是`cleanedAt`，用于确定自上次清理缓存以来的时间。

```js
	var cache = {
	  store: {},
	  maxSize: 26214400, //(bytes) 25mb
	  maxAge : 5400 * 1000, //(ms) 1 and a half hours
	   cleanAfter: 7200 * 1000,//(ms) two hours
	  cleanedAt: 0, //to be set dynamically
	  clean: function (now) {
	     if (now - this.cleanAfter > this.cleanedAt) {
	      this.cleanedAt = now;
	      that = this;
	        Object.keys(this.store).forEach(function (file) {
	          if (now > that.store[file].timestamp + that.maxAge) {
	            delete that.store[file];      
	          }
	        });
	    }
	  }
	};

```

我们将我们的`cache.clean`方法包裹在一个`if`语句中，只有当它距离上次清理已经超过两个小时（或者`cleanAfter`设置为其他值）时，才允许对`cache.store`进行循环。

## 另请参阅

+   *处理文件上传*在第二章中讨论过，*探索 HTTP 对象*

+   *防止文件系统黑客攻击*在本章中讨论。

# 防止文件系统黑客攻击

要使 Node 应用程序不安全，必须有攻击者可以与之交互以进行利用的东西。由于 Node 的极简主义方法，大部分责任都落在程序员身上，以确保他们的实现不会暴露安全漏洞。这个配方将帮助识别在处理文件系统时可能出现的一些安全风险反模式。

## 准备工作

我们将使用与以前的配方中相同的`content`目录，但我们将从头开始创建一个新的`insecure_server.js`文件（名字中有提示！）来演示错误的技术。

## 如何做...

我们以前的静态文件配方倾向于使用`path.basename`来获取路由，但这会使所有请求都处于平级。如果我们访问`localhost:8080/foo/bar/styles.css`，我们的代码会将`styles.css`作为`basename`，并将`content/styles.css`交付给我们。让我们在`content`文件夹中创建一个子目录，称之为`subcontent`，并将我们的`script.js`和`styles.css`文件移动到其中。我们需要修改`index.html`中的脚本和链接标签：

```js
	<link rel=stylesheet type=text/css href=subcontent/styles.css>
	<script src=subcontent/script.js type=text/javascript></script>

```

我们可以使用`url`模块来获取整个`pathname`。所以让我们在我们的新的`insecure_server.js`文件中包含`url`模块，创建我们的 HTTP 服务器，并使用`pathname`来获取整个请求路径：

```js
	var http = require('http'); var path = require('path'); 
	var url = require('url');
	var fs = require('fs'); 
	http.createServer(function (request, response) {
	  var lookup = url.parse(decodeURI(request.url)).pathname;
	  lookup = (lookup === "/") ? '/index.html' : lookup;
	  var f = 'content' + lookup;
	  console.log(f);
	  fs.readFile(f, function (err, data) {
	    response.end(data);
	  });
	}).listen(8080);

```

如果我们导航到`localhost:8080`，一切都很顺利。我们已经多级了，万岁。出于演示目的，一些东西已经从以前的配方中剥离出来（比如`fs.exists`），但即使有了它们，以下代码也会呈现相同的安全隐患：

```js
curl localhost:8080/../insecure_server.js 

```

现在我们有了我们服务器的代码。攻击者也可以通过几次猜测相对路径来访问`/etc/passwd`：

```js
curl localhost:8080/../../../../../../../etc/passwd 

```

为了测试这些攻击，我们必须使用 curl 或其他等效工具，因为现代浏览器会过滤这些请求。作为解决方案，如果我们为要提供的每个文件添加一个唯一的后缀，并且要求服务器在提供文件之前必须存在这个后缀，会怎么样？这样，攻击者就可以请求`/etc/passwd`或我们的`insecure_server.js`，因为它们没有唯一的后缀。为了尝试这个方法，让我们复制`content`文件夹，并将其命名为`content-pseudosafe`，并将我们的文件重命名为`index.html-serve`、`script.js-serve`和`styles.css-serve`。让我们创建一个新的服务器文件，并将其命名为`pseudosafe_server.js`。现在我们只需要让`-serve`后缀成为必需的：

```js
	//requires section...
	http.createServer(function (request, response) {
	  var lookup = url.parse(decodeURI(request.url)).pathname;
	  lookup = (lookup === "/") ? '/index.html-serve' : lookup + '-serve';
	  var f = 'content-pseudosafe' + lookup;

```

出于反馈目的，我们还将使用`fs.exists`来处理一些`404`。

```js
	//requires, create server etc  
	path.exists(f, function (exists) {
	    if (!exists) {  
	      response.writeHead(404);
	      response.end('Page Not Found!');
	      return;
	    }
	//read file etc

```

让我们启动我们的`pseudosafe_server.js`文件，并尝试相同的攻击：

```js
curl -i localhost:8080/../insecure_server.js 

```

我们使用了`-i`参数，以便 curl 输出头部。结果是什么？一个`404`，因为它实际上正在寻找的文件是`../insecure_server.js-serve`，这个文件不存在。这种方法有什么问题？嗯，它很不方便，容易出错。然而，更重要的是，攻击者仍然可以绕过它！

```js
curl localhost:8080/../insecure_server.js%00/index.html 

```

然后！这是我们的服务器代码。我们问题的解决方案是`path.normalize`，它可以在`fs.readFile`之前清理我们的`pathname`。

```js
	http.createServer(function (request, response) {
	  var lookup = url.parse(decodeURI(request.url)).pathname;
	  lookup = path.normalize(lookup);
	  lookup = (lookup === "/") ? '/index.html' : lookup;
	  var f = 'content' + lookup

```

之前的示例没有使用`path.normalize`，但它们仍然相对安全。`path.basename`给出了路径的最后部分，因此任何前导的相对目录指针（../）都被丢弃，从而防止了目录遍历的利用。

## 它是如何工作的...

在这里，我们有两种文件系统利用技术：**相对目录遍历**和**毒空字节攻击**。这些攻击可以采取不同的形式，比如在 POST 请求中或来自外部文件。它们可能会产生不同的影响。例如，如果我们正在写入文件而不是读取它们，攻击者可能会开始对我们的服务器进行更改。在所有情况下，安全性的关键是验证和清理来自用户的任何数据。在`insecure_server.js`中，我们将用户请求传递给我们的`fs.readFile`方法。这是愚蠢的，因为它允许攻击者利用我们操作系统中相对路径功能，通过使用`../`来访问本应禁止访问的区域。通过添加`-serve`后缀，我们没有解决问题。我们只是贴了一张创可贴，这可以被毒空字节绕过。这种攻击的关键是`%00`，这是空字节的 URL 十六进制代码。在这种情况下，空字节使 Node 对`../insecure_server.js`部分变得盲目，但当同样的空字节通过我们的`fs.readFile`方法发送时，它必须与内核进行接口。然而，内核对`index.html`部分变得盲目。所以我们的代码看到的是`index.html`，但读取操作看到的是`../insecure_server.js`。这就是空字节毒害。为了保护自己，我们可以使用`regex`语句来删除路径中的`../`部分。我们还可以检查空字节并输出`400 Bad Request`语句。但我们不需要，因为`path.normalize`已经为我们过滤了空字节和相对部分。

## 还有更多...

让我们进一步探讨在提供静态文件时如何保护我们的服务器。

### 白名单

如果安全性是一个极端重要的优先事项，我们可以采用严格的白名单方法。在这种方法中，我们将为我们愿意交付的每个文件创建一个手动路由。不在我们的白名单上的任何内容都将返回`404`。我们可以在`http.createServer`上方放置一个`whitelist`数组，如下面的代码所示：

```js
	var whitelist = [
	  '/index.html',
	  '/subcontent/styles.css',
	  '/subcontent/script.js'
	];

```

在我们的`http.createServer`回调中，我们将放置一个`if`语句来检查请求的路径是否在`whitelist`数组中：

```js
	if (whitelist.indexOf(lookup) === -1) {
	  response.writeHead(404);
	  response.end('Page Not Found!');
	  return;
	}

```

就是这样。我们可以通过在我们的`content`目录中放置一个文件`non-whitelisted.html`来测试这个。

```js
curl -i localhost:8080/non-whitelisted.html 

```

上述命令将返回`404`，因为`non-whitelisted.html`不在白名单上。

### Node-static

[`github.com/joyent/node/wiki/modules#wiki-web-frameworks-static`](https://github.com/joyent/node/wiki/modules#wiki-web-frameworks-static)列出了可用于不同目的的静态文件服务器模块的列表。在依赖它来提供您的内容之前，确保项目是成熟和活跃的是一个好主意。Node-static 是一个开发完善的模块，内置缓存。它还符合 RFC2616 HTTP 标准规范。这定义了如何通过 HTTP 传递文件。Node-static 实现了本章讨论的所有基本要点，以及更多。这段代码略有改动，来自 node-static 的 Github 页面[`github.com/cloudhead/node-static:`](https://github.com/cloudhead/node-static)

```js
	var static = require('node-static');
	var fileServer = new static.Server('./content');
	require('http').createServer(function (request, response) {
	  request.addListener('end', function () {
	    fileServer.serve(request, response);
	  });
	}).listen(8080);

```

上述代码将与`node-static`模块进行接口，以处理服务器端和客户端缓存，使用流来传递内容，并过滤相对请求和空字节，等等。

## 另请参阅

+   *防止跨站点请求伪造*在第七章中讨论，*实施安全、加密和身份验证*

+   设置 HTTPS Web 服务器 在第七章 *实施安全、加密和认证*

+   部署到服务器环境 在第十章 *上线*

+   密码哈希加密 在第七章 *实施安全、加密和认证*


# 第二章：探索 HTTP 对象

在本章中，我们将涵盖：

+   处理 POST 数据

+   处理文件上传

+   使用 Node 作为 HTTP 客户端

+   实现下载节流

# 介绍

在上一章中，我们使用`http`模块创建了一个 Web 服务器。现在我们将探讨一些与简单地从服务器向客户端推送内容之外的一些相关用例。前三个示例将探讨如何通过客户端发起的 HTTP POST（和 PUT）请求接收数据，最后一个示例将演示如何对出站数据流进行节流。

# 处理 POST 数据

如果我们想要接收 POST 数据，我们必须指示服务器如何接受和处理 POST 请求。在 PHP 中，我们可以无缝访问我们的 POST 值`$_POST['fieldname']`，因为它会阻塞，直到数组值被填充。相比之下，Node 提供了与 HTTP 数据流的低级交互，允许我们与传入的消息体接口，完全由开发人员将该流转换为可用数据。

## 准备工作

让我们创建一个准备好我们的代码的`server.js`文件，以及一个名为`form.html`的 HTML 文件，其中包含以下代码：

```js
<form method=post>
  <input type=text name=userinput1><br>
  <input type=text name=userinput2><br>
  <input type=submit>
</form>

```

### 提示

对于我们的目的，我们将把`form.html`放在与`server.js`相同的文件夹中，尽管这通常不是推荐的做法。通常，我们应该将我们的公共代码放在与服务器代码不同的文件夹中。

## 如何做...

我们将为我们的服务器提供 GET 和 POST 请求。让我们从 GET 开始，通过要求`http`模块并通过`createServer`加载`form.html`进行服务：

```js
var http = require('http');
var form = require('fs').readFileSync('form.html');
http.createServer(function (request, response) {
  if (request.method === "GET") {
    response.writeHead(200, {'Content-Type': 'text/html'});
    response.end(form);
  }
}).listen(8080);

```

我们在初始化时同步加载`form.html`，而不是在每个请求上访问磁盘。如果我们导航到`localhost:8080`，我们将看到一个表单。但是，如果我们填写我们的表单，什么也不会发生，因为我们需要处理 POST 请求：

```js
  if (request.method === "POST") {
  	var postData = '';
request.on('data', function (chunk) {
    		postData += chunk;
 	}).on('end', function() {
 	   console.log('User Posted:\n' + postData);
  	   response.end('You Posted:\n' + postData);
});
  }

```

一旦表单完成并提交，浏览器和控制台将输出从客户端发送的原始查询字符串。将`postData`转换为对象提供了一种与提交的信息进行交互和操作的简单方法。`querystring`模块有一个`parse`方法，可以将查询字符串转换为对象，由于表单提交以查询字符串格式到达，我们可以使用它将我们的数据转换为对象，如下所示：

```js
var http = require('http');
var querystring = require('querystring');
var util = require('util');
var form = require('fs').readFileSync('form.html');

http.createServer(function (request, response) {
  if (request.method === "POST") {
    var postData = '';
    request.on('data', function (chunk) {
      postData += chunk;
    }).on('end', function () {
      var postDataObject = querystring.parse(postData);
      console.log('User Posted:\n', postData);
      response.end('You Posted:\n' + util.inspect(postDataObject));
    });

  }
  if (request.method === "GET") {
    response.writeHead(200, {'Content-Type': 'text/html'});
    response.end(form);
  }
}).listen(8080);

```

注意`util`模块。我们需要它来使用其`inspect`方法，以简单地将我们的`postDataObject`输出到浏览器。

最后，我们将保护我们的服务器免受内存超载攻击。

### 提示

**保护 POST 服务器**

V8（因此 Node）具有基于处理器架构和操作系统约束的虚拟内存限制。这些限制远远超出了大多数用例的需求。然而，如果我们不限制我们的 POST 服务器将接受的数据量，我们可能会使自己暴露于一种拒绝服务攻击。如果没有保护，一个非常大的 POST 请求可能会导致我们的服务器显著减速甚至崩溃。

为了实现这一点，我们将为最大可接受的数据大小设置一个变量，并将其与我们的`postData`变量不断增长的长度进行比较。

```js
var http = require('http');
var querystring = require('querystring');
var util = require('util');
var form = require('fs').readFileSync('form.html');
var maxData = 2 * 1024 * 1024; //2mb
http.createServer(function (request, response) {
  if (request.method === "POST") {
    var postData = '';
    request.on('data', function (chunk) {
      postData += chunk;
      if (postData.length > maxData) {
        postData = '';
        this.pause();
        response.writeHead(413); // Request Entity Too Large
        response.end('Too large');
      }
    }).on('end', function () {
      if (!postData) { response.end(); return; } //prevents empty post requests from crashing the server
      var postDataObject = querystring.parse(postData);

      console.log('User Posted:\n', postData);

      response.end('You Posted:\n' + util.inspect(postDataObject));

    });
//rest of our code....

```

## 它是如何工作的...

一旦我们知道服务器已经发出了 POST 请求（通过检查`request.method`），我们通过`request`对象上的`data`事件监听器将我们的传入数据聚合到我们的`postData`变量中。但是，如果我们发现提交的数据超过了我们的`maxData`限制，我们将清除我们的`postData`变量，并`pause`传入流，阻止客户端进一步传入数据。使用`stream.destroy`而不是`stream.pause`似乎会干扰我们的响应机制。一旦流暂停了一段时间，它就会被 v8 的垃圾收集器自动从内存中删除。

然后我们发送一个`413 Request Entity Too Large`的 HTTP 头。在`end`事件监听器中，只要`postData`没有因超过`maxData`（或者一开始就不是空的）而被清除，我们就使用`querystring.parse`将我们的 POST 消息体转换成一个对象。从这一点开始，我们可以执行任意数量的有趣活动：操作、分析、传递到数据库等等。然而，对于这个例子，我们只是将`postDataObject`输出到浏览器，将`postData`输出到控制台。

## 还有更多...

如果我们希望我们的代码看起来更加优雅，而且我们不太关心处理 POST 数据流，我们可以使用一个用户自定义（非核心）模块来为我们的语法增添一些便利。

### 使用 connect.bodyParser 访问 POST 数据

Connect 是 Node 的一个出色的中间件框架，提供了一个方法框架，为常见的服务器任务提供了更高级别的抽象。Connect 实际上是 Express Web 框架的基础，将在第六章中讨论，*使用 Express 加速开发*

Connect 捆绑的一个中间件是`bodyParser`。通过将`connect.bodyParser`链接到普通的回调函数，我们突然可以通过`request.body`访问 POST 数据（当数据通过 POST 请求发送时，它被保存在消息体中）。结果，`request.body`与我们在配方中生成的`postDataObject`完全相同。

首先，让我们确保已安装 Connect：

```js
npm install connect 

```

我们需要使用`connect`来代替`http`，因为它为我们提供了`createServer`的功能。要访问`createServer`方法，我们可以使用`connect.createServer`，或者简写版本，即`connect`。Connect 允许我们通过将它们作为参数传递给`createServer`方法来将多个中间件组合在一起。以下是如何使用 Connect 实现类似的行为，就像在配方中一样：

```js
var connect = require('connect');
var util = require('util');
var form = require('fs').readFileSync('form.html');
connect(connect.limit('64kb'), connect.bodyParser(),
  function (request, response) {
    if (request.method === "POST") {
      console.log('User Posted:\n', request.body);
      response.end('You Posted:\n' + util.inspect(request.body));
    }
    if (request.method === "GET") {
      response.writeHead(200, {'Content-Type': 'text/html'});
      response.end(form);
    }
  }).listen(8080);

```

请注意，我们不再直接使用`http`模块。我们将`connect.limit`作为第一个参数传递，以实现主要示例中实现的相同的`maxData`限制。

接下来，我们传入`bodyParser`，允许`connect`为我们检索 POST 数据，将数据对象化为`request.body`。最后，有我们的回调函数，除了用于将我们的数据对象（现在是`request.body`）回显到控制台和浏览器的代码之外，我们剥离了所有以前的 POST 功能。这是我们与原始配方略有不同的地方。

在配方中，我们将原始的`postData`返回到控制台，而在这里我们返回`request.body`对象。要使用 Connect 输出原始数据，要么需要无意义地拆解我们的对象以重新组装原始查询字符串，要么需要扩展`bodyParser`函数。这就是使用第三方模块的权衡之处：我们只能轻松地与模块作者期望我们交互的信息进行交互。

让我们来看一下内部情况。如果我们启动一个没有任何参数的`node`实例，我们可以访问 REPL（Read-Eval-Print-Loop），这是 Node 的命令行环境。在 REPL 中，我们可以写：

```js
console.log(require('connect').bodyParser.toString()); 

```

如果我们查看输出，我们会看到它的`connect.bodyParser`函数代码，并且应该能够轻松地从`connect.bodyParser`代码中识别出我们的配方中的基本元素。

## 参见

+   *处理文件上传*在本章中讨论

+   *通过 AJAX 进行浏览器-服务器传输*在第三章中讨论，*数据序列化处理*

+   *初始化和使用会话*在第六章中讨论，*使用 Express 加速开发*

# 处理文件上传

我们无法像处理其他 POST 数据那样处理上传的文件。当文件输入以表单形式提交时，浏览器会将文件处理成**多部分消息**。

多部分最初是作为一种电子邮件格式开发的，允许将多个混合内容组合成一条消息。如果我们直觉地尝试接收上传作为流并将其写入文件，我们将得到一个充满多部分数据而不是文件本身的文件。我们需要一个多部分解析器，其编写超出了一篇食谱的范围。因此，我们将使用众所周知且经过考验的`formidable`模块将我们的上传数据转换为文件。

## 准备工作

让我们为存储上传文件创建一个新的`uploads`目录，并准备修改我们上一个食谱中的`server.js`文件。

我们还需要安装`formidable`，如下所示：

```js
npm install formidable@1.x.x 

```

最后，我们将对上一个食谱中的`form.html`进行一些更改：

```js
<form method=POST enctype=multipart/form-data>
  <input type=file name=userfile1><br>
  <input type=file name=userfile2><br>
  <input type=submit>
</form>

```

我们已经包含了一个`enctype`属性为`multipart/form-data`，以向浏览器表示表单将包含上传数据，并用文件输入替换了文本输入。

## 操作步骤...

让我们看看当我们使用修改后的表单从上一个食谱中上传文件到服务器时会发生什么。让我们上传`form.html`本身作为我们的文件：

![操作步骤...](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-cb/img/7188-02-1.jpg)

我们的 POST 服务器只是将原始的 HTTP 消息主体记录到控制台中，这种情况下是多部分数据。我们在表单上有两个文件输入。虽然我们只上传了一个文件，但第二个输入仍然包含在多部分请求中。每个文件都由`Content-Type`HTTP 头的次要属性中设置的预定义边界分隔。我们需要使用`formidable`来解析这些数据，提取其中包含的每个文件。

```js
var http = require('http');
var formidable = require('formidable');
var form = require('fs').readFileSync('form.html');

http.createServer(function (request, response) {
  if (request.method === "POST") {
    var incoming = new formidable.IncomingForm();
    incoming.uploadDir = 'uploads';
    incoming.on('file', function (field, file) {
      if (!file.size) { return; }
      response.write(file.name + ' received\n');
    }).on('end', function () {
      response.end('All files received');
    });
    incoming.parse(request);
  }
  if (request.method === "GET") {
    response.writeHead(200, {'Content-Type': 'text/html'});
    response.end(form);
  }
}).listen(8080);

```

我们的 POST 服务器现在已经成为一个上传服务器。

## 它是如何工作的...

我们创建一个`formidable IncomingForm`类的新实例，并告诉它在哪里上传文件。为了向用户提供反馈，我们可以监听我们的`incoming`实例。`IncomingForm`类会发出自己的高级事件，因此我们不是监听`request`对象的事件并在数据到来时处理数据，而是等待`formidable`解析多部分消息中的文件，然后通过其自定义的`file`事件通知我们。

`file`事件回调为我们提供了两个参数：`field`和`file`。`file`参数是一个包含有关上传文件信息的对象。我们使用这个来过滤空文件（通常是由空输入字段引起的），并获取文件名，然后向用户显示确认。当`formidable`完成解析多部分消息时，它会发送一个`end`事件，我们在其中结束响应。

## 还有更多...

我们可以从浏览器中发布不仅仅是简单的表单字段和值。让我们来看看如何从浏览器传输文件到服务器。

### 使用 formidable 接受所有 POST 数据

`formidable`不仅处理上传的文件，还会处理一般的 POST 数据。我们只需要为`field`事件添加一个监听器，以处理同时包含文件和用户数据的表单。

```js
 incoming.on('file', function (field, file) {
      response.write(file.name + ' received\n');
    })
    .on('field', function (field, value) {
      response.write(field + ' : ' + value + '\n');
    })
    .on('end', function () {
      response.end('All files received');
    });

```

无需手动实现字段数据大小限制，因为`formidable`会为我们处理这些。但是，我们可以使用`incoming.maxFieldsSize`更改默认设置，这允许我们限制所有字段的总字节数。这个限制不适用于文件上传。

### 使用 formidable 保留文件名

当`formidable`将我们的文件放入`uploads`目录时，它会为它们分配一个由随机生成的十六进制数字组成的名称。这可以防止同名文件被覆盖。但是如果我们想知道哪些文件是哪些，同时保留唯一文件名的优势呢？我们可以在`fileBegin`事件中修改`formidable`命名每个文件的方式，如下面的代码所示：

```js
  if (request.method === "POST") {
  var incoming = new formidable.IncomingForm();
  incoming.uploadDir = 'uploads';
   incoming.on('fileBegin', function (field, file) {
    if (file.name){
      file.path += "-" + file.name;
    } //...rest of the code
  }).on('file', function (field, file) {
//...rest of the code

```

我们已经将原始文件名附加到`formidable`分配的随机文件名的末尾，并用破折号分隔它们。现在我们可以轻松地识别我们的文件。然而，对于许多情况来说，这可能并不是必要的，因为我们可能会将文件信息输出到数据库，并将其与随机生成的名称进行交叉引用。

### 通过 PUT 上传

也可以通过 HTTP PUT 请求上传文件。虽然我们每次只能发送一个文件，但在服务器端我们不需要进行任何解析，因为文件将直接流向我们的服务器，这意味着更少的服务器端处理开销。如果我们可以通过将表单的`method`属性从`POST`更改为`PUT`来实现这一点就太好了，但遗憾的是不行。然而，由于即将到来的`XMLHttpRequest Level 2`（xhr2），我们现在可以在一些浏览器中通过 JavaScript 传输二进制数据（参见[`www.caniuse.com/#search=xmlhttprequest%202)`](http://www.caniuse.com/#search=xmlhttprequest%202)）。我们使用文件元素上的`change`事件监听器来获取文件指针，然后打开一个 PUT 请求并发送文件。以下是用于`form.html`的代码，我们将其保存为`put_upload_form.html`：

```js
<form id=frm>
  <input type=file id=userfile name=userfile><br>
  <input type=submit>
</form>
<script>
(function () {
  var userfile = document.getElementById('userfile'),
    frm = document.getElementById('frm'),
    file;
  userfile.addEventListener('change', function () {
    file = this.files[0];
  });
  frm.addEventListener('submit', function (e) {
    e.preventDefault();
    if (file) {
      var xhr = new XMLHttpRequest();
      xhr.file = file;
      xhr.open('put', window.location, true);
      xhr.setRequestHeader("x-uploadedfilename", file.fileName || file.name);
      xhr.send(file);
      file = '';
      frm.reset();
    }
  });
}());
</script>

```

在表单和文件输入中添加了`Id`，同时删除了`method`和`enctype`属性。我们只使用一个文件元素，因为我们只能在一个请求中发送一个文件，尽管示例可以扩展为异步流式传输多个文件到我们的服务器。

我们的脚本为文件输入元素附加了一个`change`监听器。当用户选择文件时，我们能够捕获文件的指针。在提交表单时，我们阻止默认行为，检查是否选择了文件，初始化`xhr`对象，向我们的服务器打开一个 PUT 请求，设置自定义标头以便稍后获取文件名，并将文件发送到我们的服务器。我们的服务器代码如下：

```js
var http = require('http');
var fs = require('fs');
var form = fs.readFileSync('put_upload.html');
http.createServer(function (request, response) {
  if (request.method === "PUT") {
    var fileData = new Buffer(+request.headers['content-length']);
    var bufferOffset = 0;
    request.on('data', function(chunk) {
      chunk.copy(fileData, bufferOffset);
      bufferOffset += chunk.length;
    }).on('end', function() {
        var rand = (Math.random()*Math.random())
                          .toString(16).replace('.','');
      var to = 'uploads/' + rand + "-" +
                     request.headers['x-uploadedfilename'];
      fs.writeFile(to, fileData, function(err) {
        if (err) { throw err; }
	  console.log('Saved file to ' + to);
        response.end();
      });
    });
  }
  if (request.method === "GET") {
  response.writeHead(200, {'Content-Type': 'text/html'});
  response.end(form);
  }
}).listen(8080);

```

我们的 PUT 服务器遵循了*处理 POST 数据*中简单 POST 服务器的类似模式。我们监听数据事件并将块拼接在一起。然而，我们不是将我们的数据串联起来，而是必须将我们的块放入缓冲区，因为缓冲区可以处理包括二进制在内的任何数据类型，而字符串对象总是将非字符串数据强制转换为字符串格式。这会改变底层二进制，导致文件损坏。一旦触发了`end`事件，我们会生成一个类似于`formidable`命名约定的随机文件名，并将文件写入我们的`uploads`文件夹。

### 注意

这个*通过 PUT 上传*的演示在旧版浏览器中无法工作，因此在生产环境中应提供替代方案。支持此方法的浏览器包括 IE 10 及以上版本、Firefox、Chrome、Safari、iOS 5+ Safari 和 Android 浏览器。然而，由于浏览器供应商对相同功能的实现不同，示例可能需要一些调整以实现跨浏览器兼容性。

## 另请参阅

+   *在第八章中讨论的发送电子邮件* 第八章，*集成网络范式*

+   *在本章中讨论的将 Node 用作 HTTP 客户端*。

# 使用 Node 作为 HTTP 客户端

HTTP 对象不仅提供了服务器功能，还为我们提供了客户端功能。在这个任务中，我们将使用`http.get`和`process`通过命令行动态获取外部网页。

## 准备就绪

我们不是在创建服务器，因此在命名约定中，我们应该为我们的新文件使用不同的名称，让我们称之为`fetch.js`。

## 如何做...

`http.request`允许我们发出任何类型的请求（例如 GET、POST、DELETE、OPTION 等），但对于 GET 请求，我们可以使用`http.get`方法进行简写，如下所示：

```js
var http = require('http');
var urlOpts = {host: 'www.nodejs.org', path: '/', port: '80'};
http.get(urlOpts, function (response) {
  response.on('data', function (chunk) {
    console.log(chunk.toString());
  });
});

```

基本上我们已经完成了。

```js
node fetch.js 

```

如果我们运行上述命令，我们的控制台将输出`nodejs.org`的 HTML。然而，让我们用一些交互和错误处理来填充它，如下所示的代码所示：

```js
var http = require('http');
var url = require('url');
var urlOpts = {host: 'www.nodejs.org', path: '/', port: '80'};
if (process.argv[2]) {
  if (!process.argv[2].match('http://')) {
    process.argv[2] = 'http://' + process.argv[2];
  }
  urlOpts = url.parse(process.argv[2]);
}
http.get(urlOpts, function (response) {
  response.on('data', function (chunk) {
    console.log(chunk.toString());
  });
}).on('error', function (e) {
  console.log('error:' + e.message);
});

```

现在我们可以像这样使用我们的脚本：

```js
node fetch.js www.google.com 

```

## 它是如何工作的...

`http.get`接受一个定义我们所需请求条件的对象。我们为此目的定义了一个名为`urlOpts`的变量，并将我们的主机设置为[www.nodejs.org](http://www.nodejs.org)。我们使用`process.argv`属性检查是否通过命令行指定了网址。像`console`一样，`process`是一个在 Node 运行环境中始终可用的全局变量。`process.argv[2]`是第三个命令行参数，`node`和`fetch.js`分别分配给`[0]`和`[1]`。

如果`process.argv[2]`存在（也就是说，如果已经指定了地址），我们会追加`http://`。如果不存在（`url.parse`需要它），则用`url.parse`的输出替换我们默认的`urlOpts`中的对象。幸运的是，`url.parse`返回一个具有与`http.get`所需属性相同的对象。

作为客户端，我们与服务器对我们的响应进行交互，而不是与客户端对我们的请求进行交互。因此，在`http.get`回调中，我们监听`response`上的`data`事件，而不是（与我们的服务器示例一样）`request`。随着`response`数据流的到达，我们将块输出到控制台。

## 还有更多...

让我们探索一下`http.get`的底层`http.request`方法的一些可能性。

### 发送 POST 请求

我们需要启动我们的`server.js`应用程序来接收我们的 POST 请求。让我们创建一个新文件，将其命名为`post.js`，我们将使用它来向我们的 POST 服务器发送 POST 请求。

```js
var http = require('http');
var urlOpts = {host: 'localhost', path: '/', port: '8080', method: 'POST'};
var request = http.request(urlOpts, function (response) {
    response.on('data', function (chunk) {
      console.log(chunk.toString());
    });
  }).on('error', function (e) {
    console.log('error:' + e.stack);
  });
process.argv.forEach(function (postItem, index) {
  if (index > 1) { request.write(postItem + '\n'); }
});
request.end();

```

由于我们使用的是更通用的`http.request`，我们必须在`urlOpts`变量中定义我们的 HTTP 动词。我们的`urlOpts`变量还指定了服务器为`localhost:8080`（我们必须确保我们的 POST 服务器正在运行，以便此代码能够工作）。

与以前一样，我们在`response`对象的`data`回调中设置了一个事件监听器。`http.request`返回一个`clientRequest`对象，我们将其加载到一个名为`request`的变量中。这是一个新声明的变量，它保存了从`http.request`方法返回的`clientRequest`对象。

在我们的事件监听器之后，我们使用 Ecmascript 5 的`forEach`方法循环遍历命令行参数（在 Node 中是安全的，但在浏览器中还不是）。在运行此脚本时，`node`和`post.js`将分别是第 0 个和第 1 个参数，因此我们在发送任何参数作为 POST 数据之前检查数组索引是否大于 1。我们使用`request.write`发送数据，类似于我们在构建服务器时使用`response.write`。尽管它使用了回调，但`forEach`不是异步的（它会阻塞直到完成），因此只有在处理完每个元素后，我们的 POST 数据才会被写入，我们的请求才会结束。这是我们使用它的方式：

```js
node post.js foo=bar&x=y&anotherfield=anothervalue 

```

### 作为客户端的多部分文件上传

我们将使用*处理文件上传*中的上传服务器来接收来自我们上传客户端的文件。为了实现这一点，我们必须处理多部分数据格式。为了告知服务器客户端打算发送多部分数据，我们将`content-type`头设置为`multipart/form-data`，并添加一个名为`boundary`的额外属性，这是一个自定义命名的分隔符，用于分隔多部分数据中的文件。

```js
var http = require('http');
var fs = require('fs');
var urlOpts = { host: 'localhost', path: '/', port: '8080', method: 'POST'};
var boundary = Date.now();
urlOpts.headers = {
  'Content-Type': 'multipart/form-data; boundary="' + boundary + '"'
};

```

我们在这里也需要`fs`模块，因为我们稍后将需要加载我们的文件。

我们将我们的`boundary`设置为当前的 Unix 时间（1970 年 1 月 1 日午夜以来的毫秒数）。我们不需要再以这种格式使用`boundary`，所以让我们用所需的多部分双破折号（`--`）前缀更新它，并设置我们的`http.request`调用：

```js
boundary = "--" + boundary;
var request = http.request(urlOpts, function (response) {
    response.on('data', function (chunk) {
      console.log(chunk.toString());
    });
  }).on('error', function (e) {
    console.log('error:' + e.stack);
  });

```

我们希望能够将多部分数据流式传输到服务器，这些数据可能由多个文件编译而成。如果我们同时尝试将这些文件流式传输并将它们同时编译成多部分格式，数据很可能会从不同的文件流中混合在一起，顺序难以预测，变得无法解析。因此，我们需要一种方法来保留数据顺序。

我们可以一次性构建所有内容，然后将其发送到服务器。然而，一个更有效（并且类似于 Node 的）的解决方案是，通过逐步将每个文件组装成多部分格式来构建多部分消息，同时在构建时即时流式传输多部分数据。

为了实现这一点，我们可以使用一个自迭代的函数，从`end`事件回调中调用每个递归，以确保每个流都被单独捕获并按顺序进行。

```js
(function multipartAssembler(files) {
  var f = files.shift(), fSize = fs.statSync(f).size;
  fs.createReadStream(f)
    .on('end', function () {
      if (files.length) { multipartAssembler(files); return; //early finish}
	//any code placed here wont execute until no files are left
	//due to early return from function.
    });
}(process.argv.splice(2, process.argv.length)));

```

这也是一个自调用函数，因为我们已经将它从声明更改为表达式，通过在其周围加括号。然后我们通过附加括号来调用它，同时传入命令行参数，指定要上传的文件：

```js
node upload.js file1 file2 fileN 

```

我们在`process.argv`数组上使用`splice`来删除前两个参数（即`node`和`upload.js`）。结果作为我们的`files`参数传递到我们的`multipartAssembler`函数中。

在我们的函数内部，我们立即将第一个文件从`files`数组中移除，并将其加载到变量`f`中，然后将其传递到`createReadStream`中。一旦读取完成，我们将任何剩余的文件再次通过我们的`multipartAssembler`函数，并重复该过程，直到数组为空。现在让我们用多部分的方式来完善我们的自迭代函数，如下所示：

```js
(function multipartAssembler(files) {
  var f = files.shift(), fSize = fs.statSync(f).size,
	progress = 0;
  fs.createReadStream(f)
    .once('open', function () {
      request.write(boundary + '\r\n' +
                   'Content-Disposition: ' +
                   'form-data; name="userfile"; filename="' + f + '"\r\n' +
                   'Content-Type: application/octet-stream\r\n' +
                   'Content-Transfer-Encoding: binary\r\n\r\n');
    }).on('data', function(chunk) {
      request.write(chunk);
      progress += chunk.length;
      console.log(f + ': ' + Math.round((progress / fSize) * 10000)/100 + '%');
    }).on('end', function () {
      if (files.length) { multipartAssembler(files); return; //early finish }
      request.end('\r\n' + boundary + '--\r\n\r\n\r\n');    
    });
}(process.argv.splice(2, process.argv.length)));

```

我们在`content-type`头部中首先设置了预定义边界的部分。每个部分都需要以一个头部开始，我们利用`open`事件来发送这个头部。

`content-disposition`有三个部分。在这种情况下，第一部分将始终是`form-data`。第二部分定义了字段的名称（例如，文件输入的`name`属性）和原始文件名。`content-type`可以设置为任何相关的 mime。然而，通过将所有文件设置为`application/octet-stream`并将`content-transfer-encoding`设置为`binary`，如果我们只是将文件保存到磁盘而没有任何中间处理，我们可以安全地以相同的方式处理所有文件。我们在每个多部分头部的末尾使用双 CRLF（`\r\n\r\n`）来结束我们的`request.write`。

还要注意，我们在`multipartAssembler`函数的顶部分配了一个新的`progress`变量。我们使用这个变量来通过将到目前为止接收到的块数（`progress`）除以总文件大小（`fSize`）来确定上传的相对百分比。这个计算是在我们的`data`事件回调中执行的，我们也在那里将每个块流到服务器上。

在我们的`end`事件中，如果没有更多的文件需要处理，我们将以与其他边界分区相同的最终多部分边界结束请求，除了它有前导和尾随斜杠。

## 另请参阅

+   *使用真实数据：获取热门推文* 在第三章中讨论了*使用数据序列化*

# 实施下载限速

对于传入的流，Node 提供了`pause`和`resume`方法，但对于传出的流则不然。基本上，这意味着我们可以在 Node 中轻松地限制上传速度，但下载限速需要更有创意的解决方案。

## 准备工作

我们需要一个新的`server.js`以及一个很大的文件来提供服务。使用`dd`命令行程序，我们可以生成一个用于测试的文件。

```js
dd if=/dev/zero of=50meg count=50 bs=1048576 

```

这将创建一个名为`50meg`的 50MB 文件，我们将提供服务。

### 提示

对于一个类似的 Windows 工具，可以用来生成一个大文件，请查看[`www.bertel.de/software/rdfc/index-en.html`](http://www.bertel.de/software/rdfc/index-en.html)。

## 如何做...

为了尽可能简单，我们的下载服务器将只提供一个文件，但我们将以一种方式来实现，可以轻松地插入一些路由代码来提供多个文件。首先，我们将需要我们的模块并设置一个`options`对象来设置文件和速度设置。

```js
var http = require('http');
var fs = require('fs');

var options = {}
options.file = '50meg';
options.fileSize = fs.statSync(options.file).size;
options.kbps = 32;

```

如果我们正在提供多个文件，我们的 `options` 对象将大部分是多余的。但是，在这里我们使用它来模拟用户确定的文件选择概念。在多文件情况下，我们将根据请求的 URL 加载特定文件信息。

### 注意

要了解这个方法如何配置以服务和限制多个文件，请查看 第一章 中的路由方法，*制作 Web 服务器*

`http` 模块用于服务器，而 `fs` 模块用于创建 `readStream` 并获取我们文件的大小。

我们将限制一次发送多少数据，但首先我们需要获取数据。所以让我们创建我们的服务器并初始化一个 `readStream`。

```js
http.createServer(function(request, response) {
  var download = Object.create(options);
  download.chunks = new Buffer(download.fileSize);
  download.bufferOffset = 0;

  response.writeHeader(200, {'Content-Length': options.fileSize});

   fs.createReadStream(options.file)
    .on('data', function(chunk) {  
      chunk.copy(download.chunks,download.bufferOffset);
      download.bufferOffset += chunk.length;
    })
    .once('open', function() {
    	 //this is where the throttling will happen
     });    
}).listen(8080);

```

我们已经创建了我们的服务器并指定了一个叫做 `download` 的新对象，它继承自我们的 `options` 对象。我们向我们的请求绑定的 `download` 对象添加了两个属性：一个 `chunks` 属性，它在 `readStream` 数据事件监听器中收集文件块，以及一个 `bufferOffset` 属性，它将用于跟踪从磁盘加载的字节数。

现在我们所要做的就是实际的限流。为了实现这一点，我们只需每秒从我们的缓冲区中分配指定数量的千字节，从而实现指定的每秒千字节。我们将为此创建一个函数，它将放在 `http.createServer` 之外，并且我们将称我们的函数为 `throttle`。

```js
function throttle(download, cb) {
  var chunkOutSize = download.kbps * 1024,
      timer = 0;

  (function loop(bytesSent) {
    var remainingOffset;
    if (!download.aborted) {
      setTimeout(function () {      
        var bytesOut = bytesSent + chunkOutSize;

        if (download.bufferOffset > bytesOut) {
          timer = 1000;         
          cb(download.chunks.slice(bytesSent,bytesOut));
          loop(bytesOut);
          return;
        }

        if (bytesOut >= download.chunks.length) {
            remainingOffset = download.chunks.length - bytesSent;
            cb(download.chunks.slice(remainingOffset,bytesSent));
            return;
        }

          loop(bytesSent); //continue to loop, wait for enough data
      },timer);
    }  
   }(0));

   return function () { //return a function to handle an abort scenario
    download.aborted = true;
   };

}

```

`throttle` 与每个服务器请求上创建的 `download` 对象交互，根据我们预定的 `options.kbps` 速度分配每个块。对于第二个参数（`cb`），`throttle` 接受一个功能回调。`cb` 反过来接受一个参数，即 `throttle` 确定要发送的数据块。我们的 `throttle` 函数返回一个方便的函数，用于在中止时结束循环，避免无限循环。我们通过在服务器回调中调用我们的 `throttle` 函数来初始化下载限流时钟，当 `readStream` 打开时。

```js
//...previous code
  fs.createReadStream(options.file)
      .on('data', function (chunk) {  
        chunk.copy(download.chunks,download.bufferOffset);
        download.bufferOffset += chunk.length;
      })
      .once('open', function () {
         var handleAbort = throttle(download, function (send) {
                       			      response.write(send);
                           		    });

         request.on('close', function () {
            handleAbort();
         }); 
       });    

}).listen(8080);

```

## 它是如何工作的...

这个方法的关键是我们的 `throttle` 函数。让我们来看看它。为了实现指定的速度，我们每秒发送一定大小的数据块。大小由所需的每秒千字节数量确定。因此，如果 `download.kbps` 是 32，我们将每秒发送 32 KB 的数据块。

缓冲区以字节为单位工作，所以我们设置一个新变量叫做 `chunkOutSize`，并将 `download.kbps` 乘以 1024 以实现适当的块大小（以字节为单位）。接下来，我们设置一个 `timer` 变量，它被传递给 `setTimeout`。它首先设置为 `0` 有两个原因。首先，它消除了不必要的初始 1000 毫秒开销，使我们的服务器有机会立即发送第一块数据（如果可用）。其次，如果 `download.chunks` 缓冲区不足以满足 `chunkOutSize` 的需求，嵌入的 `loop` 函数在不改变 `timer` 的情况下进行递归。这会导致 CPU 实时循环，直到缓冲区加载足够的数据以传递一个完整的块（这个过程应该在一秒钟内完成）。

一旦我们有了第一个块的足够数据，`timer` 就设置为 1000，因为从这里开始我们希望每秒推送一个块。

`loop` 是我们限流引擎的核心。它是一个自递归函数，它使用一个参数 `bytesSent` 调用自身。`bytesSent` 参数允许我们跟踪到目前为止发送了多少数据，并且我们使用它来确定从我们的 `download.chunks` 缓冲区中切出哪些字节，使用 `Buffer.slice`。`Buffer.slice` 接受两个参数，`start` 和 `end`。这两个参数分别由 `bytesSent` 和 `bytesOut` 实现。`bytesOut` 也用于与 `download.bufferOffset` 对比，以确保我们加载了足够的数据以便发送一个完整的块。

如果有足够的数据，我们继续将`timer`设置为 1000，以启动我们的每秒一个块的策略，然后将`download.chunks.slice`的结果传递给`cb`，这将成为我们的`send`参数。

回到服务器内部，我们的`send`参数被传递到`throttle`回调中的`response.write`，因此每个块都被流式传输到客户端。一旦我们将切片的块传递给`cb`，我们调用`loop(bytesOut)`进行新的迭代（因此`bytesOut`变成`bytesSent`），然后我们从函数中返回，以防止进一步执行。

`bytesOut`第三次出现的地方是在`setTimeout`回调的第二个条件语句中，我们将其与`download.chunks.length`进行比较。这对于处理最后一块数据很重要。我们不希望在最后一块数据发送后再次循环，如果`options.kbps`不能完全整除总文件大小，最后的`bytesOut`将大于缓冲区的大小。如果未经检查地传递给`slice`方法，这将导致对象越界（`oob`）错误。

因此，如果`bytesOut`等于或大于分配给`download.chunks`缓冲区的内存（即我们文件的大小），我们将从`download.chunks`缓冲区中切片剩余的字节，并在不调用`loop`的情况下从函数中返回，有效地终止递归。

为了防止连接意外关闭时出现无限循环（例如在连接失败或客户端中止期间），`throttle`返回另一个函数，该函数在`handleAbort`变量中捕获并在`response`的`close`事件中调用。该函数简单地向`download`对象添加一个属性，表示下载已中止。这在`loop`函数的每次递归中都会进行检查。只要`download.aborted`不是`true`，它就会继续迭代，否则循环会提前停止。

### 注意

操作系统上有（可配置的）限制，定义了可以同时打开多少文件。我们可能希望在生产下载服务器中实现缓存，以优化文件系统访问。有关 Unix 系统上的文件限制，请参阅[`www.stackoverflow.com/questions/34588/how-do-i-change-the-number-of-open-files-limit-in-linux`](http://www.stackoverflow.com/questions/34588/how-do-i-change-the-number-of-open-files-limit-in-linux)。

### 启用断点续传

如果连接中断，或用户意外中止下载，客户端可以通过向服务器发送`Range` HTTP 头来发起恢复请求。`Range`头可能如下所示：

```js
Range: bytes=512-1024

```

当服务器同意处理`Range`头时，它会发送`206 Partial Content`状态，并在响应中添加`Content-Range`头。如果整个文件大小为 1 MB，对先前的`Range`头的`Content-Range`回复可能如下所示：

```js
Content-Range: bytes 512-1024/1024

```

请注意，在`Content-Range`头中`bytes`后面没有等号（=）。我们可以将对象传递给`fs.createReadStream`的第二个参数，指定从哪里开始和结束读取。由于我们只是处理恢复，因此只需要设置`start`属性。

```js
//requires, options object, throttle function, create server etc...
download.readStreamOptions = {};
download.headers = {'Content-Length': download.fileSize};
download.statusCode = 200;
  if (request.headers.range) {
    download.start = request.headers.range.replace('bytes=','').split('-')[0];
    download.readStreamOptions = {start: +download.start};
    download.headers['Content-Range'] = "bytes " + download.start + "-" + 											     download.fileSize + "/" + 												     download.fileSize;
    download.statusCode = 206; //partial content
  }
  response.writeHeader(download.statusCode, download.headers);
  fs.createReadStream(download.file, download.readStreamOptions)
//...rest of the code....

```

通过向`download`添加一些属性，并使用它们有条件地响应`Range`头，我们现在可以处理恢复请求。

## 另请参阅

+   *设置路由器*讨论在第一章中，*制作 Web 服务器*

+   *在内存中缓存内容以进行即时交付*讨论在第一章中，*制作 Web 服务器*

+   *通过 TCP 通信*讨论在第八章中，*集成网络范式*


# 第三章：使用数据序列化

在本章中，我们将涵盖：

+   将对象转换为 JSON，然后再转换回来

+   将对象转换为 XML，然后再转换回来

+   通过 AJAX 进行浏览器-服务器传输

+   使用真实数据：获取热门推文

# 介绍

如果我们想让第三方安全地访问原始数据，我们可以使用序列化将其发送到请求者能够理解的格式中。在本章中，我们将研究两种著名标准中的数据序列化，JSON 和 XML。

# 将对象转换为 JSON，然后再转换回来

JSON（JavaScript 对象表示法）与 JavaScript 对象非常相关，因为它是 JavaScript 的子集。这项任务将演示如何使用 JSON 转换的构建块：`JSON.parse`和`JSON.stringify`。

## 准备工作

我们需要创建两个名为`profiles.js`和`json_and_back.js`的新文件。

## 如何做...

让我们创建一个对象，稍后将其转换为 JSON。

```js
module.exports = {
  ryan : {
           name: "Ryan Dahl",
           irc:'ryah',
           twitter:'ryah',
           github:'ry',
           location:'San Francisco, USA',
           description: "Creator of node.js"
          },
  isaac : {
            name: "Isaac Schlueter",
            irc:'isaacs',
            twitter:'izs',
            github:'isaacs',
            location:'San Francisco, USA',
            description: "Author of npm, core contributor"
           },
  bert : {
           name: "Bert Belder",
           irc:'piscisaureus',
           twitter:'piscisaureus',
           github:'piscisaureus',
           location:'Netherlands',
           description: "Windows support, overall contributor"
          },
  tj : {
          name: "TJ Holowaychuk",
          irc:'tjholowaychuk',
          twitter:'tjholowaychuk',
          github:'visionmedia',
          location:'Victoria, BC, Canada',
          description: "Author of express, jade and other popular modules"
          },
  felix : {
          name: "Felix Geisendorfer",
          irc:'felixge',
          twitter:'felixge',
          github:'felixge',
          location:'Berlin, Germany',
          description: "Author of formidable, active core developer"
          }
};

```

这个对象包含了 Node 社区一些领先成员的个人资料信息（尽管它并不全面，甚至不包含所有的核心开发团队）。这里需要注意的一点是使用了`module.exports`。我们将在第九章中看到更多关于这个的内容，*编写自己的模块*。我们在这里使用`module.exports`来模块化我们的`profiles`对象，以保持我们的代码整洁。我们可以将任何表达式加载到`module.exports`中，将其保存为一个单独的文件（在我们的情况下，我们将称之为`profiles.js`），并在我们的主文件中使用`require`来动态加载它进行初始化。

```js
var profiles = require('./profiles'); // note the .js suffix is optional

```

整洁而清晰。为了将我们的`profiles`对象转换为 JSON 表示，我们使用`JSON.stringify`，它将返回由 JSON 数据组成的字符串。我们将使用`replace`从根本上改变我们的对象（现在是一个字符串）。

```js
profiles = JSON.stringify(profiles).replace(/name/g, 'fullname');

```

在这里，我们调用了`replace`，使用全局`g`选项的正则表达式来将我们的 JSON 字符串中的每个`name`更改为`fullname`。

但等等！似乎出现了某种错误。Felix 的姓缺少一个分音符！让我们通过将我们的 JSON 数据转换回对象，并通过修改重新指定的`fullname`属性的值来纠正他的名字：

```js
profiles = JSON.parse(profiles);
profiles.felix.fullname = "Felix Geisendörfer";
console.log(profiles.felix);

```

当我们运行我们的应用程序时，`console.log`将输出以下内容：

```js
{ fullname: 'Felix Geisendörfer',
  irc: 'felixge',
  twitter: 'felixge',
  github: 'felixge',
  location: 'Berlin, Germany',
  description: 'Author of formidable, active core developer' }

```

第一个键现在是`fullname`，而`Geisendörfer`的拼写是正确的。

## 它是如何工作的...

首先，我们有一个日常的 JavaScript 对象，我们将其序列化为 JSON 表示。我们还在我们的 JSON 字符串上调用`String.replace`方法，将每个`name`的出现更改为`fullname`。

以这种方式使用 replace 并不是一个明智的做法，因为任何`name`的出现都会被替换。字符串中很容易有其他地方可能存在`name`，这样会意外地被替换。我们在这里使用`replace`来确认配置文件已经成为 JSON 字符串，因为我们无法在对象上使用`replace`。

然后，我们使用`JSON.parse`将修改后的 JSON 字符串转换回对象。为了测试我们的键确实从`name`转换为`fullname`，并确认我们再次使用对象，我们通过`profiles.felix.fullname`纠正`felix`配置文件，然后将`profiles.felix`记录到控制台。

## 还有更多...

JSON 是一种非常灵活和多功能的跨平台通信工具。让我们看看标准的更高级应用。

### 构建 JSONP 响应

JSONP（带填充的 JSON）是一个跨域策略的变通方法，允许开发人员与其他域上的资源进行接口。它涉及在客户端定义一个回调函数，通过它的第一个参数处理 JSON，然后将这个回调函数的名称作为查询参数传递给`script`元素的`src`属性，该元素指向另一个域上的 web 服务。然后，web 服务返回 JSON 数据，包装在一个根据客户端设置的查询参数命名的函数中。可能更容易通过代码来说明这一点。

```js
<html>
<head>
<script>
  var who = 'ryan';
  function cb(o) {
    alert(o.name + ' : ' + o.description);
  }
  var s = document.createElement('script');
  s.src = 'http://localhost:8080/?callback=cb&who=' + who;
  document.getElementsByTagName("head")[0].appendChild(s);
</script>
</head>
</html>

```

我们定义了一个名为`cb`的函数，它以一个对象作为参数，然后输出`name`和`description`属性。在此之前，我们设置了一个名为`who`的变量，它将被传递给服务器以为我们获取特定的数据。然后，我们动态注入一个新的脚本元素，将`src`设置为一个象征性的第三方域（为了方便演示，是 localhost），并添加`callback`和`who`查询参数。`callback`的值与我们的函数`cb`函数的名称匹配。我们的服务器使用此参数将 JSON 包装在函数调用中。

```js
var http = require('http');
var url = require('url');
var profiles = require('./profiles');

http.createServer(function (request, response) {
  var urlObj = url.parse(request.url, true), 
    cb = urlObj.query.callback, who = urlObj.query.who,
    profile;

  if (cb && who) {
    profile = cb + "(" + JSON.stringify(profiles[who]) + ")";
    response.end(profile);
  }

}).listen(8080);

```

我们创建一个服务器，提取`callback`和`who`查询参数，并写一个包含传递我们的 JSON 数据作为参数的函数调用的响应。这个脚本由我们的客户端加载，其中调用`cb`函数并将 JSON 作为对象接收到函数中（因为它看起来像一个对象）。

### 安全和 JSONP

由于 JSONP 使用脚本注入，任何脚本都可以插入到我们的页面中。因此，强烈建议只在受信任的来源使用此方法。不受信任的来源可能在页面上运行恶意代码。

## 另请参阅

+   *在本章中讨论的通过 AJAX 进行浏览器-服务器传输*

+   *在本章中讨论的使用真实数据：获取热门推文*

# 将对象转换为 XML，然后再转回来

由于 JSON 是 JavaScript 对象的基于字符串的表示，因此在两者之间进行转换是简单的。但是，XML 不方便处理。尽管如此，可能有时我们不得不使用它，例如，如果 API 只能使用 XML，或者如果我们与要求 XML 支持的项目签约。

有各种非核心 XML 解析器可用。其中一个解析器是非核心模块`xml2js`。`xml2js`的前提是，使用 JavaScript 中的对象比使用 XML 更合适。`xml2js`为我们提供了一个基础，让我们通过将 XML 转换为 JavaScript 对象来与 XML 交互。

在这个任务中，我们将编写一个函数，使用前一个配方中的`profiles`对象来创建一个有效的 XML 字符串，然后将其通过`xml2js`，从而将其转换回对象。

## 准备工作

在开始之前，让我们创建我们的文件`xml_and_back.js`，确保我们的单独模块化的`profiles.js`也在同一个目录中。我们还应该安装`xml2js`。

```js
npm install xml2js 

```

## 如何做...

首先，我们需要引入我们的`profiles`对象以及`xml2js`：

```js
var profiles = require('./profiles');
var xml2js = new (require('xml2js')).Parser();

```

请注意，我们不仅仅需要`xml2js`模块，还初始化了它的`Parser`方法的一个新实例，并将其加载为我们的`xml2js`变量。这与`xml2js`模块的工作方式有关。我们必须创建一个新的`Parser`实例，以便将一段 XML 解析为一个对象。由于我们的代码相对简单，我们可能会在需要时进行初始化工作。

就像 XML 具有树状结构一样，对象可以在其中嵌套对象。我们需要一个函数，可以循环遍历我们的对象和所有子对象，将所有属性转换为父 XML 节点，将所有非对象值转换为文本 XML 节点：

```js
function buildXml(rootObj, rootName) {
  var xml = "<?xml version='1.0' encoding='UTF-8'?>\n";
  rootName = rootName || 'xml';
  xml += "<" + rootName + ">\n";
  (function traverse(obj) {
    Object.keys(obj).forEach(function (key) {
     var open = "<" + key + ">",
        close = "</" + key + ">\n",
        isTxt = (obj[key]
          && {}..toString.call(obj[key]) !== "[object Object]");

      xml += open;

      if (isTxt) {
        xml += obj[key];
        xml += close;
        return;
      }

      xml += "\n";
      traverse(obj[key]);
      xml += close;
    });
  }(rootObj));

  xml += "</" + rootName + ">";
  return xml;
}

```

`buildXml`接受两个参数，对象和一个字符串来命名第一个根 XML 节点，并返回表示我们对象的 XML 数据的字符串。

让我们将所有`name`的出现替换为`fullname`，就像我们的*将对象转换为 JSON，然后再转回来*配方中一样。

```js
profiles = buildXml(profiles, 'profiles').replace(/name/g, 'fullname');
console.log(profiles); // <-- show me the XML!

```

现在我们将`profiles`转回为一个对象，使用重命名的`fullname`属性来更正 Felix Geisendörfer 的名字，然后将 Felix 记录到控制台上以显示它已经生效。

```js
xml2js.parseString(profiles, function (err, obj) {
  profiles = obj;
  profiles.felix.fullname = "Felix Geisendörfer";
  console.log(profiles.felix);
});

```

`xml2js.parseString`接受 XML（此时保存在`profiles`变量中）并将其组装成一个对象，作为其回调中的`obj`参数传递。

## 它是如何工作的...

JavaScript 对象是一个键值存储，而 XML 是一种以资源为中心的标记语言。在 XML 中，键和值可以用两种方式表示：要么作为父节点和子节点，要么作为 XML 节点上的属性。我们将我们的键和值转换为父节点和子节点，主要是因为单个 XML 节点充满了大量的属性，而有效的 XML 似乎违反了 XML 的精神。

我们通过`buildXml`实现了我们的转换，它是一个包装另一个自调用递归函数`traverse`的函数。我们这样做是为了利用 JavaScript 中的闭包原理，它允许我们在内部和外部函数之间共享变量。这使我们能够使用外部的`xml`变量来组装我们的序列化 XML。

在我们的外部函数中，我们从`<?xml?>`声明开始，设置所需的`version`属性和可选的`encoding`属性为`UTF-8`。我们还将`traverse`渲染的任何输出都包装在一个以我们的`rootName`参数命名的结束和关闭标签中。因此，在我们的情况下，`buildXml`将以下内容放入我们的`xml`变量中：

```js
<?xml version='1.0' encoding='UTF-8'?>
<profiles>
	<!-- Traverse XML Output Here -->
</profiles>

```

如果`rootName`丢失，我们默认为`<xml>`作为根节点。我们的`traverse`内部函数接受一个参数，即要转换为 XML 的对象。我们将`rootObj`传递给调用括号：

```js
(function traverse(obj) {
	// traverse function code here...
  }(rootObj));  // ? passing in our root object parameter

```

`traverse`使用`forEach`循环遍历此对象的键，通过`forEach`回调的第一个参数访问每个键。我们使用每个`key`的名称来生成 XML 标签的开头和结尾，并将`open`标签附加到我们共享的`xml`变量上。然后我们检查我们的`isTxt`变量，它测试嵌套对象并在不是对象时返回`true`（假设它必须是文本）。如果`isTxt`为`true`，我们输出当前属性的值并从`forEach`回调返回，继续到下一个属性。这就是我们获取文本节点的方式——值。否则，我们在`xml`中附加一个换行符，并在子对象上调用`traverse`，通过完全相同的过程进行，只是这次它嵌入在父`traverse`函数中。一旦我们嵌套调用`traverse`返回，我们就在`xml`中附加`close`标签，我们的`traverse`函数就完成了。最后，我们的外部函数附加了关闭根节点标签，并返回所有生成的 XML。

## 还有更多...

我们可以进一步调整我们的代码，以更好地与`xml2js`库集成，通过将其对某些 XML 特性的解释反映到 JavaScript 对象等价物中。我们还可以将其扩展为将更复杂的 JavaScript 对象转换为有效的 XML。

### 包含数组和函数的对象

除了对象和字符串之外，对象属性还可以包含函数和数组。就目前而言，我们的方法将这些解释为文本，对于数组，输出一个逗号分隔的值列表，并在文本节点中返回函数的内容。

这并不理想，所以我们将修改我们的`traverse`函数来处理这些类型：

```js
  (function traverse(obj) {
    Object.keys(obj).forEach(function (key) {
     var open = "<" + key + ">",
        close = "</" + key + ">\n",
        nonObj = (obj[key]  
          && {}.toString.call(obj[key]) !== "[object Object]"),
        isArray = Array.isArray(obj[key]),
        isFunc =(typeof obj[key] === "function");

      if (isArray) {
        obj[key].forEach(function (xmlNode) {
          var childNode = {};
          childNode[key] = xmlNode;
          traverse(childNode);
        });
        return;
      }

      xml += open;      
      if (nonObj) {
        xml += (isFunc) ? obj[key]() : obj[key];
        xml += close;
        return;
      }
//rest of traverse function

```

我们将保存我们修改后的代码为`xml_with_arrays_and_functions.js`。为了语义上的完整，我们将`isTxt`重命名为`nonObj`，并添加了两个更多的测试变量，`isArray`和`isFunc`。如果我们遍历的对象的值是一个数组，我们创建一个临时的`childNode`对象，然后将其传回`traverse`。我们对数组的每个值都做同样的操作，每次创建一个新的`childNode`对象，其中键相同但值是下一个数组元素。这有效地创建了多个相同名称的子节点。

为了测试数组支持，让我们将`profiles.js`文件复制到`profiles_with_arrays_and_functions.js`，并要求它而不是`profiles.js`。Ryan Dahl 还推送到另一个 Github 帐户：joyent。所以让我们用 Github 帐户的数组更新他的个人资料：

```js
module.exports = {
  ryan : {
           name: "Ryan Dahl",
           irc:"ryah",
           twitter:"ryah",
           github:["ry","joyent"],
           location:"San Francisco, USA",
           description: "Creator of node.js"
          },
//...rest of profiles...

```

现在，如果我们这样做：

```js
profiles = buildXml(profiles, 'profiles');
console.log(profiles); // <-- show me the XML!

```

看一下输出，我们会发现 Ryan 有两个 Github XML 节点：

```js
<?xml encoding='UTF-8'?>
<profiles>
<ryan>
<name>Ryan Dahl</name>
<irc>ryah</irc>
<twitter>ryah</twitter>
<github>ry</github>
<github>joyent</github>
<location>San Francisco, USA</location>
<description>Creator of node.js</description>
</ryan>
<!-- REST OF THE XML OUTPUT -->

```

我们的另一个变量`isFunc`在`nonObj`条件语句内进行检查。我们用它来确定我们是应该只将对象属性的文本添加到我们的`xml`变量中，还是调用对象属性以获得其返回值。Bert 的 IRC、Twitter 和 Github 帐户都是一样的，所以让我们添加从他的 Github 值中提取 IRC 和 Twitter 值的方法：

```js
//...prior profiles code.
bert : {
           name: "Bert Belder",
           irc:function () { return this.github; },
           twitter:function () { return this.github; },
           github:"piscisaureus",
           location:"Netherlands",
           description: "Windows support, overall contributor"
          },
//..rest of profiles code...

```

如果我们从对象构建 XML，然后使用`xml2js`将其转换回对象，这些属性不应再是函数，而应该是函数/方法的返回值：

```js
xml2js.parseString(profiles, function (err, obj) {
  profiles = obj;
  console.log(profiles.bert);
});

```

输出将如下所示：

```js
{ name: 'Bert Belder',
  irc: 'piscisaureus',
  twitter: 'piscisaureus',
  github: 'piscisaureus',
  location: 'Netherlands',
  description: 'Windows support, overall contributor' }

```

### 生成 XML 属性

在 XML 中，我们可以用父节点、子节点和文本节点来表示数据关系，也可以使用属性。如果我们想让我们的`buildXml`函数能够处理 XML 属性，我们需要一个约定来定义对象中的属性。在从 XML 转换为对象时，`xml2js`通过添加一个包含特殊`@`属性的对象来解释属性，该对象又包含属性的另一个子对象。通过在`buildXml`中实现相同的约定，我们可以使我们的代码与`xml2js`很好地配合。让我们取`profiles_with_arrays_and_functions.js`中的`profiles`对象，并进一步更新`location`属性如下：

```js
module.exports = {
  ryan : {
		//ryans other keys here...
           location:{'@':{city: 'San Francisco',country: 'USA'}},
           description: 'Creator of node.js'
          },
  isaac : {
		//isaacs other keys here...
            location:{'@':{city: 'San Francisco',country: 'USA'}},
            description: 'Author of npm, core contributor'
           },
  bert : {
		//berts other keys here...
           location:{'@':{country: 'Netherlands'}},
           description: 'Windows support, overall contributor'
          },
  tj: {}, //<-- TJs keys
  felix: {}, //<-- Felix's keys
};

```

我们将其保存为`profiles_with_attributes.js`，并在`xml_and_back_with_arrays_and_functions.js`代码中更改`profiles`变量的`require`位置，保存为`xml_and_back_with_attributes.js`：

```js
var profiles = require('./profiles_with_attributes');

```

让我们编写另一个函数，应该放在`buildXml`函数内部来处理我们的属性：

```js
function attributes(obj, key) {
    if (obj[key].hasOwnProperty("@")) {
     xml = xml.substr(0, xml.length – 1); //remove the “>” part of open tag

     Object.keys(obj[key]['@']).forEach(function (attrKey) {
        xml += ' ' + attrKey + '="' + obj[key]['@'][attrKey] + '"';
      });

     xml += ">"; // add the “>” back on

     delete obj[key]['@']; //remove the key so it isn't traversed as an object
    }
  }

```

我们的新`attributes`函数应该放在我们的`buildXml`函数内，并且将在`traverse`内部调用，就在我们将键的`open`标签变量添加到`xml`变量之后，以及在检查`nonObj`节点之前：

```js
(function traverse(obj) {
  //...prior traverse function code...
  xml += open;
  attributes(obj, key);
  If (nonObj) {
  //rest of traverse function code...

```

我们将当前由我们的`traverse`函数处理的对象和键传递进去，检查`obj`的这个特定属性是否包含一个名为`@`的属性。我们还在隐式地检查我们当前对象键的值是否本身是一个对象，因为只有对象才有属性。

当前的属性`@`属性对应于当前标签。因此，如果找到一个`@`属性，我们会删除`xml`的最后一个字符（这将是一个右尖括号`>`），并循环遍历我们子对象（`obj[key][@]`）的键，将每个键及其值添加到最后的`open`标签中，以便附加到`xml`，完成后重新添加右尖括号。如果我们将`@`对象留在`profiles`对象中，它将稍后被传回`traverse`函数，导致以下行为：

```js
<@>
<city>San Francisco</city>
<country>USA</country>
</@>

```

我们不想要那样，所以我们最后删除了对象中的`attributes`子对象。在我们的`buildXml`函数下面，我们有以下代码：

```js
profiles = buildXml(profiles, 'profiles').replace(/name/g, 'fullname');
console.log(profiles; //show me the xml!

```

这将把`name`键更改为`fullname`，并将我们的 XML 输出到控制台，呈现出带有属性的`location`标签。

```js
<ryan>
<fullname>Ryan Dahl</fullname>
<irc>ryah</irc>
<twitter>ryah</twitter>
<github>ry</github>
<github>joyent</github>
<location city="San Francisco" country="USA">
</location>
<description>Creator of node.js</description>
</ryan>
<!-- rest of the XML output -->

```

### 文本值与属性声明并列

我们的属性解决方案揭示了另一个问题。没有办法让带属性的节点包含文本节点，因为我们将字符串类型转换为文本节点，但使用对象来声明属性。`xml2js`通过`charkey`属性解决了这个问题的敌意。通过以下代码，我们可以完全兼容`xml2js`：

```js
//previous code
      if (key === '#') { //explicit text
        xml += obj[key] + '\n';
        return;
      }
      xml += open;
      attributes(obj, key);
      if (nonObj) {
//rest of the code

```

现在这个困境已经解决，我们可以明确地添加包含文本节点的属性节点，就像这样：

```js
//prior profiles
 tj : {
          name: "TJ Holowaychuk",
          irc:"tjholowaychuk",
          twitter:"tjholowaychuk",
          github:"visionmedia",
          location:{'@':{city: 'Victoria',country: 'Canada'},region: {'#' :'British Columbia','@':{type:'province'}}},
          description: "Author of express, jade and other popular modules"
          },
//rest of profiles

```

这导致：

```js
<irc>tjholowaychuk</irc>
<twitter>tjholowaychuk</twitter>
<github>visionmedia</github>
<github s="special">
</github>
<location city="Victoria" country="Canada">
<region type="province">
British Columbia
</region>
</location>
<description>Author of express, jade and other popular modules</description>
</tj>

```

## 另请参阅

+   *在本章中讨论的将对象转换为 JSON 然后再转换回来*

+   本章讨论了*通过 AJAX 进行浏览器-服务器传输*

+   本章讨论了*使用真实数据：获取热门推文*

# 通过 AJAX 进行浏览器-服务器传输

我们可以通过 AJAX 直接将新内容加载到页面中，而不是为每个内容请求加载新页面，从而增强用户体验。

在本示例中，我们将根据用户请求将序列化数据传输到浏览器，然后与我们的客户端数据进行交互。我们将在浏览器中实现一个配置文件查看器，该查看器以 JSON 或 XML 格式检索所选配置文件，并输出该配置文件的键值或父子节点。

## 准备工作

我们将继续使用我们的`profiles.js`对象模块（来自本章的前两个示例）。对于 XML 传递，我们还将从*将对象转换为 XML 并再次转换*示例中获取我们的`buildXml`函数，并将其转换为一个简单的模块（就像我们在上一个示例中对`profiles`对象所做的那样）：

```js
module.exports = function buildXml(rootObj, rootName) {
//..buildXml function code
}

```

我们将将此保存为`buildXml.js`并将其放在一个文件夹中，该文件夹中包含我们的`profiles.js`文件的副本，以及两个新创建的文件：`server.js`和`index.html`。

## 如何做...

让我们从我们的`index.html`文件开始。我们将快速实现一个粗略的布局，用于我们的个人资料查看器，包括一个带有两个`select`元素的`form`，一个用于输出格式化对象数据的`div`，以及一个用于呈现原始序列化数据的`textarea`元素。

```js
<!doctype html>
<html>
<head>
<script src=http://ajax.googleapis.com/ajax/libs/jquery/1.7.1/jquery.min.js>
</script>
<style>
#frm, #raw {display:block; float:left; width:210px}
#raw {height:150px; width:310px; margin-left:0.5em}
</style>
</head>
<body>
<form id=frm>
Profile: <select id=profiles>
		 <option></option>
		 </select> <br>
Format:<select id=formats>
		  <option value=json> JSON </option>
		  <option value=xml> XML </option>
		  </select><br> <br>
<div id=output></div>
</form>  
<textarea id=raw></textarea>
</body>
</html>

```

请注意，我们已经包含了 jQuery 以获得跨浏览器的好处，特别是在 AJAX 请求的领域。我们将很快在客户端脚本中使用 jQuery，但首先让我们制作我们的服务器。

对于我们的模块，我们将需要`http，path`和`fs`以及我们自定义的`profiles`和`buildXml`模块。为了使我们的代码工作，我们需要在我们的服务器中托管`index.html`，以防止跨域策略错误。

```js
var http = require('http');
var fs = require('fs');
var path = require('path');
var profiles = require('./profiles');
var buildXml = require('./buildXml');

var index = fs.readFileSync('index.html');
var routes,
  mimes = {xml: "application/xml", json: "application/json"};

```

我们还定义了`routes`和`mimes`变量，以便我们可以回答来自客户端的特定数据请求，并附上正确的`Content-Type`标头。我们将创建两个路由，一个将提供配置文件名称列表，另一个将指示对特定配置文件的请求。

```js
routes = {
  'profiles': function (format) {
    return output(Object.keys(profiles), format);
  },
  '/profile': function (format, basename) {
    return output(profiles[basename], format, basename);
  }
};

```

我们刚刚在`routes`中提到的`output`函数应放置在`routes`对象上方，并且看起来像以下代码：

```js
function output(content, format, rootNode) {
  if (!format || format === 'json') {
    return JSON.stringify(content);
  }
  if (format === 'xml') {
    return buildXml(content, rootNode);
  }
}

```

要完成我们的服务器，我们只需调用`http.createServer`并在回调中与我们的`routes`对象进行交互，在找不到路由的情况下输出`index.html`：

```js
http.createServer(function (request, response) {
  var dirname = path.dirname(request.url), 
    extname = path.extname(request.url), 
    basename = path.basename(request.url, extname); 
    extname = extname.replace('.',''); //remove period 

  response.setHeader("Content-Type", mimes[extname] || 'text/html');

  if (routes.hasOwnProperty(dirname)) {
    response.end(routesdirname);
    return;
  }
  if (routes.hasOwnProperty(basename)) {
    response.end(routesbasename);
    return;
  }
  response.end(index);
}).listen(8080);

```

最后，我们需要编写我们的客户端代码，以通过 AJAX 与我们的服务器进行交互，该代码应放置在我们的`index.html`文件的`#raw`文本区域的下方的脚本标签中，但在`</body>`标签的上方（以确保 HTML 元素在脚本执行之前已加载）：

```js
<script>
$.get('http://localhost:8080/profiles',
  function (profile_names) {
    $.each(profile_names, function (i, pname) {
      $('#profiles').append('<option>' + pname + '</option>');
    });
  }, 'json');
$('#formats, #profiles').change(function () {
  var format = $('#formats').val();
  $.get('http://localhost:8080/profile/' + $('#profiles').val() + '.' + format,
    function (profile, stat, jqXHR) {
      var cT = jqXHR.getResponseHeader('Content-Type');
      $('#raw').val(profile);
      $('#output').html('');
      if (cT === 'application/json') {
        $.each($.parseJSON(profile), function (k, v) {
          $('#output').append('<b>' + k + '</b> : ' + v + '<br>');
        });
        return;
      }

      if (cT === 'application/xml') {
        profile = jqXHR.responseXML.firstChild.childNodes;
        $.each(profile,
          function (k, v) {
            if (v && v.nodeType === 1) {
              $('#output').append('<b>' + v.tagName + '</b> : ' +
		   v.textContent + '<br>');
            }
          });

      }
    }, 'text');

});
</script>

```

## 它是如何工作的...

让我们从服务器开始。在我们的`http.createServer`回调中，我们设置了适当的标头，并检查`routes`对象是否具有指定的目录名。如果`routes`中存在目录名，我们将其作为函数调用，并传入`basename`和`extname`（我们使用`extname`来确定所需的格式）。在没有目录名匹配的情况下，我们检查是否存在与`basename`匹配的属性。如果有，我们调用它并传入扩展名（如果有）。如果这两个测试都不成立，我们只需输出我们的`index.html`文件的内容。

我们的两个路由是`profiles`和`/profile`，后者有一个前导斜杠，对应于`path.dirname`返回路径的目录名的方式。我们的`/profile`路由旨在允许包含所请求的配置文件和格式的子路径。例如，`http://localhost:8080/profile/ryan.json`将以 JSON 格式返回 Ryan 的配置文件（如果未给出扩展名，则默认为 JSON 格式）。

`profiles`和`/profile`方法都利用我们的自定义`output`函数，该函数使用`format`参数（最初在`http.createServer`回调中为`extname`）从传递给它的`content`生成 JSON（使用`JSON.stringify`）或 XML（使用我们自己的`buildXml`函数）。`output`还接受一个条件性的第三个参数，该参数传递给`buildXml`以定义生成的 XML 的`rootNode`。

在客户端，我们要做的第一件事是调用 jQuery 的`$.get`方法获取`http://localhost:8080/profiles`。这会导致服务器调用`route`对象上的`profiles`方法。这将调用我们的`output`函数，并传入来自我们的`profiles.js`对象的顶级属性数组。由于我们没有在`$.get`中指定扩展名，`output`函数将默认为 JSON 格式，并将`JSON.stringify`的结果传递给`response.end`。

回到客户端，我们在第一个`$.get`调用中的第三个参数是`'json'`，这确保`$.get`将传入的数据解释为 JSON，并将其转换为对象。对象作为`$.get`的回调函数的第一个参数（`$.get`的第二个参数）传递给我们命名为`profile_names`的函数。我们使用 jQuery 的`$.each`循环遍历`profile_names`，通过将 jQuery 的`append`方法应用于元素，并在循环`$.each`时将每个配置文件名称添加到`<option>`元素中，从而填充第一个`select`元素（`#profiles`）。

接下来，我们为我们的两个`select`元素应用一个监听器（`change`），其回调根据用户的选择组装一个 URL，并将此 URL 传递给另一个使用`$.get`的 AJAX 请求。

这次在服务器端，调用`/profile route`方法，将对应的配置文件从我们的`profiles`对象传递给`output`。此属性将包含所请求个人的配置文件信息的对象。

在我们的第二个`$.get`调用中，我们将第三个参数设置为`'text'`。这将强制 jQuery 不自动将传入的数据解释为 JSON 或 XML。这给了我们更多的控制，并使得更容易将原始数据输出到`textarea`中。在`$.get`回调中，我们使用`jqXHR`参数来确定`Content-Type`，以查看我们是否有 JSON 或 XML。我们根据其类型（Object 或 XMLObject）循环返回的数据，并将其附加到我们的`#output div`中。

## 还有更多...

我们还可以在浏览器中将我们的对象转换为 JSON 和 XML，然后将它们发送到服务器，我们可以再次将它们作为对象进行交互。

### 从客户端发送序列化数据到服务器

让我们扩展我们的示例，使用我们的浏览器界面将新配置文件添加到服务器上的`profiles`对象中。

从`index.html`开始（我们将其复制到`add_profile_index.html` - 我们还将`server.js`复制到`add_profile_server.js`），让我们添加一个名为`#add`的表单，并对其进行样式设置。这是表单：

```js
<form id=add>
<div><label>profile name</label><input name="profileName"></div>
<div><label>name</label><input name="name"></div>
<div><label>irc</label><input name="irc"></div>
<div><label>twitter</label><input name="twitter"></div>
<div><label>github</label><input name="github"></div>
<div><label>location</label><input name="location"></div>
<div><label>description</label><input name="description"></div>
<div><button>Add</button></div>
</form>

```

还有一些额外的样式：

```js
<style>
#frm, #raw {display:block; float:left; width:210px}
#raw {height:150px; width:310px; margin-left:0.5em}
#add {display:block; float:left; margin-left:1.5em}
#add div {display:table-row}
#add label {float:left; width:5.5em}
div button {float:right}
</style>

```

我们将在客户端使用我们的`buildXml`函数（我们在*将对象转换为 XML 并再次转换回来*中创建了`buildXml`）。这个函数已经在我们的服务器上可用，所以我们将它转换为字符串，并在服务器启动时提供一个路由供客户端访问：

```js
var index = fs.readFileSync('add_profile_index.html');
var buildXmljs = buildXml.toString();
var routes,
  mimes = {
   js: "application/JavaScript",
   json: "application/json",
   xml: "application/xml"
  };
routes = {
  'profiles': function (format) {
    return output(Object.keys(profiles), format);
  },
  '/profile': function (format, basename) {
    return output(profiles[basename], format, basename);
  },
  'buildXml' : function(ext) {
    if (ext === 'js') { return buildXmljs; }
  }
};

```

我们还更新了我们的`mimes`对象，准备交付`application/javascript Content-Type`，并修改了索引变量以使用我们的新的`add_profile_index.html`文件。回到客户端代码，我们通过在头部部分包含另一个`<script>`标签来获取我们的`buildXml`函数：

```js
<script src=buildXml.js></script>

```

我们将我们对服务器的初始`$.get`调用（用于获取`select`元素的所有配置文件名称）包装在一个名为`load`的函数中。这使我们能够在添加配置文件后动态重新加载配置文件名称：

```js
function load() {
$.get('http://localhost:8080/profiles',
  function (profile_names) {
    $.each(profile_names, function (i, pname) {
      $('#profiles').append('<option>' + pname + '</option>');
    });

  }, 'json');
}
load();

```

现在我们为`#add`表单定义一个处理程序：

```js
$('#add').submit(function(e) {
  var output, obj = {}, format = $('#formats').val();
  e.preventDefault();
  $.each($(this).serializeArray(), function(i,nameValPair) {
    obj[nameValPair.name] = nameValPair.value; //form an object
  });  
  output = (format === 'json') ? JSON.stringify(obj) : buildXml(obj,'xml');

  $.ajax({ type: 'POST', url: '/', data: output,
    contentrendingTopicsype: 'application/' + format, dataType: 'text',
    success: function(response) {
      $('#raw').val(response);
      $('#profiles').html('<option></option>');
      load();
    }
  });
}); 

```

我们的处理程序从表单输入构建一个对象，将其序列化为指定格式。它使用`jQuery.ajax`将序列化数据发送到我们的服务器，然后重新加载配置文件。在我们的服务器上，我们将编写一个处理 POST 请求的函数：

```js
function addProfile(request,cb) {
  var newProf, profileName, pD = ''; //post data
  request
    .on('data', function (chunk) { pD += chunk; })
    .on('end',function() {
      var contentrendingTopicsype = request.headers['content-type'];
      if (contentrendingTopicsype === 'application/json') {
        newProf = JSON.parse(pD);
      }

      if (contentrendingTopicsype === 'application/xml') {
        xml2js.parseString(pD, function(err,obj) {
          newProf = obj;  
        });
      }
      profileName = newProf.profileName;
      profiles[profileName] = newProf;    
      delete profiles[profileName].profileName;
      cb(output(profiles[profileName],
        contentrendingTopicsype.replace('application/', ''), profileName));
});
}

```

为了使我们的新`addProfile`函数工作，我们需要包含`xml2js`模块，该模块用于将序列化的 XML 转换回对象。因此，除了我们所有的初始变量，我们还添加了以下内容：

```js
var xml2js = new (require('xml2js')).Parser();

```

在第二章的第一个食谱中，*探索 HTTP 对象*，在处理 POST 数据时，`addProfile`将所有传入的数据汇编在一起。在`end`事件中，我们使用适合其类型的方法将序列化数据转换为对象。我们将这个对象添加到我们的`profiles`对象中，使用`profileName`属性作为子对象的键。一旦我们添加了对象，我们就会`delete`冗余的`profileName`属性。

为了将数据返回给客户端，`addProfile`函数调用回调（cb）参数，传入我们自定义的`output`函数，该函数将根据指定的格式返回序列化数据（通过在`Content-Type`头上使用`replace`确定）。

我们像这样在我们的服务器中包含我们的`addProfile`函数：

```js
http.createServer(function (request, response) {
//initial server variables...
  if (request.method === 'POST') {
    addProfile(request, function(output) {
      response.end(output);
    });
    return;
  }
//..rest of the server code (GET handling..)

```

在我们的`addProfile`回调函数中，我们只需使用从`output`函数返回的数据结束响应，通过`output`参数访问这个数据，这个参数在`addProfile`回调中定义。新的配置文件只保存在操作内存中，所以在服务器重新启动时会丢失。如果我们要将这些数据存储在磁盘上，理想情况下我们会希望将其保存在数据库中，这将在下一章*与数据库交互*中讨论。

## 另请参阅

+   *设置路由*在第一章中讨论，制作 Web 服务器

+   *处理 POST 数据*在第二章中讨论，探索 HTTP 对象

+   *将对象转换为 JSON 然后再转换回来*在本章中讨论

+   *将对象转换为 XML 然后再转换回来*在本章中讨论

# 处理真实数据：获取热门推文

许多在线实体将他们的响应数据格式化为 JSON 和 XML，以在他们的应用程序编程接口（API）中向第三方开发人员公开相关信息，这些开发人员随后可以将这些数据集成到他们的应用程序中。

一个这样的在线实体是 Twitter。在这个食谱中，我们将制作一个命令行应用程序，向 Twitter 的 REST 服务发出两个请求。第一个将检索 Twitter 上当前最受欢迎的话题，第二个将返回关于 Twitter 上最热门话题的最新推文。

## 准备工作

让我们创建一个文件，命名为`twitter_trends.js`。我们可能还希望安装第三方`colors`模块，使我们的输出更加美观：

npm install colors

## 如何做...

我们需要`http`模块来进行请求，并且需要`colors`模块来在控制台输出中添加一些颜色：

```js
var http = require('http');
var colors = require('colors');

```

我们将在另一个 GET 请求内部进行 GET 请求。在这些请求之间，我们将处理 JSON 数据，要么传递到后续请求，要么输出到控制台。为了遵循 DRY（不要重复自己）的精神，并演示如何避免意大利面代码，我们将抽象出我们的 GET 请求和 JSON 处理到一个名为`makeCall`的函数中。

```js
function makeCall(urlOpts, cb) {
  http.get(urlOpts, function (response) { //make a call to the twitter API  
    trendingTopics.jsonHandler(response, cb);
  }).on('error', function (e) {
    console.log("Connection Error: " + e.message);
  });
}
}

```

注意`trendingTopics`及其`jsonHandler`方法的神秘出现。`trendingTopics`是一个将为我们的 Twitter 交互提供所有设置和方法的对象。`jsonHandler`是`trendingTopics`对象上的一个方法，用于接收响应流并将 JSON 转换为对象。

我们需要为我们对趋势和推文 API 的调用设置选项，以及一些与 Twitter 交互相关的功能。因此，在我们的`makeCall`函数之上，我们将创建`trendingTopics`对象，如下所示：

```js
var trendingTopics = module.exports = {
  trends: {
    urlOpts: {
      host: 'api.twitter.com',
      path: '/1/trends/1.json', //1.json provides global trends,
      headers: {'User-Agent': 'Node Cookbook: Twitter Trends'}
    }
  },
  tweets: {
    maxResults: 3, //twitter applies this very loosely for the "mixed" type
    resultsType: 'realtime', //choice of mixed, popular or realtime
    language: 'en', //ISO 639-1 code
    urlOpts: {
      host: 'search.twitter.com',
      headers: {'User-Agent': 'Node Cookbook: Twitter Trends'}
    }
  },
  jsonHandler: function (response, cb) {
    var json = '';
    response.setEncoding('utf8');
    if (response.statusCode === 200) {
      response.on('data', function (chunk) {
        json += chunk;
      }).on('end', function () {
        cb(JSON.parse(json));
      });
    } else {
      throw ("Server Returned statusCode error: " + response.statusCode);
    }
  },
  tweetPath: function (q) {
    var p = '/search.json?lang=' + this.tweets.language + '&q=' + q +
        '&rpp=' + this.tweets.maxResults + '&include_entities=true' +
        '&with_twitter_user_id=true&result_type=' +
        this.tweets.resultsType;
    this.tweets.urlOpts.path = p;
  }
};

```

在创建`trendingTopics`变量时，我们还将对象转换为模块，同时将其加载到`module.exports`中。看看我们如何在*还有更多...*部分中使用它。

在我们的`trendingTopics`对象中，我们有`trends`和`tweets`对象以及两个方法：`jsonHandler`和`tweetPath`。

最后，我们将调用我们的`makeCall`函数来请求来自 Twitter 趋势 API 的全球热门趋势，将返回的 JSON 转换为对象，并使用该对象来确定请求关于最热门话题的推文的路径，使用另一个嵌入的`makeCall`调用。

```js
makeCall(trendingTopics.trends.urlOpts, function (trendsArr) {
  trendingTopics.tweetPath(trendsArr[0].trends[0].query);
  makeCall(trendingTopics.tweets.urlOpts, function (tweetsObj) {
    tweetsObj.results.forEach(function (tweet) {
      console.log("\n" + tweet.from_user.yellow.bold + ': ' + tweet.text);
    });
  });
});

```

## 工作原理...

让我们来分析一下`trendingTopics`对象。`trends`和`tweets`提供了与 Twitter API 相关的设置。对于`trends`来说，这只是一个 URL 选项对象，稍后将传递给`http.get`。在`tweets`对象中，我们有 URL 对象以及一些其他属性，涉及我们可以在对 Twitter 搜索 API 的 REST 调用中设置的选项。

### Twitter API 和 User-Agent 头

请注意，我们已经费心设置了`User-Agent`头。这是由于 Twitter API 政策，对缺少`User-Agent`字符串的惩罚是降低速率限制。

我们在`trendingTopics`对象上的`jsonHandler`方法接受`response`和`cb`（回调）参数。`trendingTopics.jsonHandler`使用`http.get`调用中的`response`对象来捕获传入数据流到一个变量（`json`）中。当流结束时，使用`response`上的`end`事件监听器来检测，`cb`调用转换后的 JSON 作为参数。`trendingTopics.jsonHandler`的回调找到了它的方式进入`makeCall`的回调。

`makeCall`抽象地结合了 GET 请求和 JSON 处理，并提供了一个带有单个参数的回调函数，该参数是 Twitter 返回的解析 JSON 数据（在本例中，它是一个对象数组）。

在外部的`makeCall`调用中，我们将参数命名为`trendsArr`，因为 Twitter 将其 JSON 数据返回在一个数组包装器中。我们使用`trendsArr`来定位 Twitter 的顶级趋势的查询片段表示，并将其传递给我们的`trendingTopics`对象的最终方法：`trendingTopics.tweetPath`。该方法以查询片段（`q`）作为其单个参数。然后，它使用此参数以及`trendingTopics.tweets`中的选项来构建最终的 Search API 路径。它将此路径注入到`trendingTopics.tweets`的`urlOpts`对象中，然后传递到内部的`makeCall`调用中。

在内部的`makeCall`调用中，我们将参数命名为`tweetsArr`。这是一个包含推文数据的对象数组，是对前一个对 Trend API 的调用中返回的 Twitter 搜索 API 的查询的顶级趋势的响应。我们使用可变的`forEach`（ES5）循环函数循环遍历数组，处理通过循环传递的每个元素作为`tweet`。

`tweetsArr`数组中包含很多数据，如时间信息，转发次数等。但是，我们只对推文的内容和发推者感兴趣。因此，我们将每个`tweet`的`from_user`和`text`属性记录到控制台上：

![Twitter API 和 User-Agent 头](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-cb/img/7188-03-01.jpg)

这也是`colors`模块派上用场的地方，因为在`console.log`中我们有`tweet.from_user.yellow.bold`。颜色不是 Twitter 返回的对象的属性，而是`colors`模块执行的一些技巧，提供了一个易于使用的界面来为控制台文本设置样式。

## 还有更多...

让我们来看看如何使用基于 XML 的服务。

### 将 Google 热门趋势与 Twitter 推文进行交叉引用

可以注意到，热门推文往往受到 Twitter 社区内部产生的时尚影响。Google 热门趋势是另一个热门信息的来源。它提供最热门搜索的每小时更新。

我们可以扩展我们的示例来访问和处理 Google 的热门趋势 XML 原子源，并将顶部结果集成到我们的 Twitter 搜索 API 请求中。为此，让我们创建一个名为`google_trends.twitter.js`的新文件。将 XML 数据作为 JavaScript 对象处理很好，因此我们将在本章的*将对象转换为 XML，然后再次转换为对象*配方中引入非核心的`xml2js`，以及`http，colors`和我们自己的`trendingTopics`模块。

```js
var http = require('http');
var xml2js = new (require('xml2js')).Parser(); 
var colors = require('colors'); //for prettifying the console output
var trendingTopics = require('./twitter_trends'); //load trendingTopics obj

```

现在我们将通过使用 EcmaScript 5 的`Object.create`方法从中继承来扩展我们的`trendingTopics`对象。

```js
var hotTrends = Object.create(trendingTopics, {trends: {value: {urlOpts: {
    host: 'www.google.com',
    path: '/trends/hottrends/atom/hourly',
    headers: {'User-Agent': 'Node Cookbook: Twitter Trends'}
  }
    }}});

hotTrends.xmlHandler = function (response, cb) {
  var hotTrendsfeed = '';
  response.on('data', function (chunk) {
    hotTrendsfeed += chunk;
  }).on('end', function () {
    xml2js.parseString(hotTrendsfeed, function (err, obj) {
      if (err) { throw (err.message); }
      xml2js.parseString(obj.entry.content['#'],
	function (err, obj) {
        if (err) { throw (err.message); }
        cb(encodeURIComponent(obj.li[0].span.a['#']));
      });
    });
  });
};

```

我们声明了一个名为`hotTrends`的变量，并使用`Object.create`来初始化一个`trendingTopics`的实例，通过属性声明对象（`Object.create`的第二个参数）重新实例化了`trends`属性。这意味着`trends`不再是一个继承属性，而是属于`hotTrends`，当将其添加到新的`hotTrends`对象时，我们没有覆盖`trendingTopics`中的`trends`属性。

然后我们添加了一个新的方法：`hotTrends.xmlHandler`。这将所有传入的块组合成`hotTrendsfeed`变量。一旦流结束，它会调用`xml2js.parseString`并将`hotTrendsfeed`中包含的 XML 传递给它。在第一个`parseString`方法的回调中，我们再次调用`xml2js.parseString`。为什么？因为我们必须解析两组 XML，或者说一组 XML 和一组格式良好的 HTML。（如果我们前往[`www.google.com/trends/hottrends/atom/hourly`](http://www.google.com/trends/hottrends/atom/hourly)，它将被呈现为 HTML。如果我们查看源代码，然后会看到一个包含嵌入式 HTML 内容的 XML 文档。）

Google 的热门趋势 XML 源以 HTML 的形式包含在其`content` XML 节点中。

HTML 被包裹在`CDATA`部分中，因此第一次不会被`xml2js`解析。因此，我们创建了一个新的`Parser`，然后通过`obj.entry.content['#']`解析 HTML。

最后，`hotTrends.xmlHandler`方法在第二个嵌入的`xml2js`回调中完成，其中执行了它自己的回调参数（cb），生成了从 HTML 中的顶部列表项元素生成的查询片段。

现在我们只需要对`makeCall`进行一些调整：

```js
function makeCall(urlOpts, handler, cb) {
  http.get(urlOpts, function (response) { //make a call to the twitter api  
    handler(response, cb);
  }).on('error', function (e) {
    console.log("Connection Error: " + e.message);
  });
}

makeCall(hotTrends.trends.urlOpts, hotTrends.xmlHandler, function (query) {
  hotTrends.tweetPath(query);
  makeCall(hotTrends.tweets.urlOpts, hotTrends.jsonHandler, function (tweetsObj) {
    tweetsObj.results.forEach(function (tweet) {
      console.log("\n" + tweet.from_user.yellow.bold + ': ' + tweet.text);
    });
  });
});

```

由于我们现在处理 JSON 和 XML，我们在`makeCall`函数声明中添加了另一个参数：`handler`。`handler`参数允许我们指定是使用继承的`jsonHander`方法还是我们补充的`xmlHandler`方法。

当我们调用外部的`makeCall`时，我们传入`hotTrends.xmlHandler`，将参数命名为`query`。这是因为我们直接传入了由`xmlHandler`生成的查询片段，而不是从 Twitter 返回的数组。这直接传递到`tweetPath`方法中，因此更新了`hotTrends.tweets.urlOpts`对象的`path`属性。

我们将`hotTrends.tweets.urlOpts`传递给第二个`makeCall`，这次将`handler`参数设置为`hotTrends.jsonHandler`。

第二个`makeCall`回调的行为与主要的配方完全相同。它将推文输出到控制台。但是这次，它基于 Google 热门趋势输出推文。

## 另请参阅

+   *在第二章中讨论了使用 Node 作为 HTTP 客户端，探索 HTTP 对象

+   *在本章中讨论的*将对象转换为 JSON，然后再次转换为对象*

+   *在本章中讨论的*将对象转换为 XML，然后再次转换为对象*
