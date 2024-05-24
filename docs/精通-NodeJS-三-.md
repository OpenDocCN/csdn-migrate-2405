# 精通 NodeJS（三）

> 原文：[`zh.annas-archive.org/md5/54EB7E80445F684EF94B4738A0764C40`](https://zh.annas-archive.org/md5/54EB7E80445F684EF94B4738A0764C40)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：管理许多同时客户连接

“如果每个人都帮助撑起天空，那么一个人就不会感到疲倦。”

- Tshi 谚语

在网络软件的不可预测和*突发*环境中管理成千上万个同时客户事务的同时保持高吞吐量是开发人员对他们的 Node 实现的一个期望。鉴于历史上失败和不受欢迎的解决方案，处理并发问题甚至被赋予了自己的数字缩写：“*C10K 问题*”。应该如何设计能够自信地为 10,000 个同时客户提供服务的网络软件？

如何构建高并发系统的最佳方法的问题在过去几十年引发了许多理论争论，主要是在线程和事件之间。

“线程允许程序员编写直线代码，并依赖操作系统通过透明地在线程之间切换来重叠计算和 I/O。另一种选择，事件，允许程序员通过将代码结构化为一个单线程处理程序来显式地管理并发，以响应事件（如非阻塞 I/O 完成、特定于应用程序的消息或定时器事件）。”

- “高并发系统的设计框架”  （韦尔什，格里布尔，布鲁尔和卡勒，2000），第 2 页。

在上述引用中提出了两个重要观点：

+   开发人员更喜欢编写结构化代码（直线；单线程），以尽可能隐藏多个同时操作的复杂性

+   I/O 效率是高并发应用的主要考虑因素

直到最近，编程语言和相关框架并不是（必然）针对在分布式网络或甚至跨处理器上执行的软件进行优化。算法应该是确定性的；写入数据库的数据应该立即可供阅读。在这个时代的最终一致性数据库和异步控制流中，开发人员不能再期望在任何给定时间点知道应用程序的精确状态；这对高并发系统的架构师来说是一种有时令人费解的挑战。

正如我们在第二章中所学到的，*理解异步事件驱动编程*，Node 的设计试图结合线程和事件的优势，通过在单个线程上为所有客户提供服务（一个包装 JavaScript 运行时的事件循环），同时将阻塞工作（I/O）委托给一个优化的线程池，通过事件通知系统通知主线程状态变化。

清楚地思考以下 HTTP 服务器实现，运行在单个 CPU 上，通过将回调函数包装在请求的上下文中，并将执行上下文推送到一个不断被清空和重建的堆栈中，该堆栈绑定到事件循环的单个线程中，以响应每个客户请求：

```js
require('http').createServer((req, res) => {
  res.writeHead(200, {'Content-Type': 'text/plain'});
  res.end('Hello client from ${req.connection.remoteAddress}`);
  console.log(req);
}).listen(8000);
```

从图上看，情况是这样的：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/7dcb3dae-75b2-4ef1-ba34-433e6e556c37.png)

另一方面，像 Apache 这样的服务器为每个客户请求启动一个线程：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/9db30472-79fb-46ca-a25c-65579afd9641.png)

这两种方法非常不同。Node 设计中隐含的声明是：当程序流沿着单个线程组织时，更容易推理高并发软件，并且即使在单线程执行模型中，减少 I/O 延迟也会增加可以支持的同时客户数量。第二个声明将在以后进行测试，但现在，让我们看看构建自然扩展的基本流程有多容易。

我们将演示如何使用 Node 跟踪和管理并发进程之间的关系，特别是那些同时为多个客户提供服务的进程。我们的目标是建立对在 Node 服务器或其他进程中如何对状态进行建模的基本理解。一个大型在线社交网络如何为您提供根据您的友谊或兴趣定制的信息？您的购物车如何在多次购物会话中保持不变，甚至包含基于您的购买历史的建议？一个客户端如何与其他客户端进行交互？

# 理解并发性

我们都会同意世界上有意想不到的事件，其中许多事件恰好发生在同一时间。很明显，任何给定系统的状态可能由任意数量的子状态组成，即使是微小的状态变化的全部后果也很难预测——蝴蝶煽动翅膀的力量足以将一个更大的系统推入另一个状态。此外，我们也知道，系统的体积和形状随着时间的推移以难以预测的方式发生变化。

在他 1981 年撰写的博士论文《*Actor 语义的基础》中，William Clinger 提出他的工作是：

“……受到高度并行计算机的前景的激励，这些计算机由数十、数百甚至数千个独立的微处理器组成，每个微处理器都有自己的本地存储器和通信处理器，通过高性能通信网络进行通信。”

事实证明，Clinger 有所发现。并发是由许多同时执行的操作组成的系统的属性，我们现在正在构建的网络软件类似于他所设想的，只是规模更大，*数百甚至数千*是下限，而不是上限。

Node 使并发变得容易访问，同时可以跨多个核心、多个进程和多台机器进行扩展。重要的是要注意，Node 对程序的简单性和一致性的重视程度与成为最快解决方案的重视程度一样高，通过采用和强制非阻塞 I/O 来提供高并发性，以及通过设计良好和可预测的接口。这就是 Dahl 说的“Node 的目标是提供一种构建可扩展网络程序的简单方法”的意思。

令人高兴的是，Node 非常快。

# 并发不等于并行。

将问题分解为较小的问题，将这些较小的问题分散到一个可用的人员或工人池中并行处理，并同时交付并行的结果，可以解决问题。

多个进程同时解决单个数学问题的一部分是并行性的一个例子。

Rob Pike，一位通用的巫师黑客和 Google Go 编程语言的共同发明者，以这种方式定义并发：

“并发是一种构造事物的方式，使您可以可能使用并行性来做得更好。但并行性不是并发的目标；并发的目标是一个良好的结构。”

成功的高并发应用程序开发框架提供了一种简单而富有表现力的词汇，用于描述这样的系统。

Node 的设计表明，实现其主要目标——提供一种构建可扩展网络程序的简单方法——包括简化共存进程的执行顺序的结构和组合。Node 帮助开发人员更好地组织他们的代码，解决了在一个程序中同时发生许多事情（比如为许多并发客户提供服务）的问题。

这并不是说 Node 是为了保持简单的接口而设计的，而牺牲效率——恰恰相反。相反，这个想法是将实现高效并行处理的责任从开发人员转移到系统的核心设计中，使开发人员可以通过简单和可预测的回调系统来构建并发，远离死锁和其他陷阱。

Node 的简洁来得正是时候，因为社交和社区网络与世界数据一起增长。系统正在被扩展到很少有人预测的规模。现在是进行新思考的好时机，比如如何描述和设计这些系统，以及它们如何相互请求和响应。

# 请求路由

HTTP 是建立在请求/响应模型之上的数据传输协议。使用这个协议，我们中的许多人向朋友传达我们的当前状态，为家人买礼物，或者与同事通过电子邮件讨论项目。令人震惊的是，许多人已经开始依赖这个基础性的互联网协议。

通常，浏览器客户端会向服务器发出 HTTP GET 请求。然后服务器返回所请求的资源，通常表示为 HTML 文档。HTTP 是无状态的，这意味着每个请求或响应都不保留先前请求或响应的信息——通过网页的前后移动，整个浏览器状态都会被销毁并从头开始重建。

服务器从客户端路由状态更改请求，最终导致返回新的状态表示，客户端（通常是浏览器）重新绘制或报告。当 WWW 首次构想时，这个模型是有意义的。在很大程度上，这个新网络被理解为一个分布式文件系统，任何人都可以通过网络浏览器访问，可以通过 HTTP 请求（例如 GET）从网络上的某个位置（Internet Protocol 或 IP 地址）的文件服务器计算机（服务器）请求特定资源（例如报纸文章），只需输入 URL（例如[`www.example.org/articles/april/showers.html`](http://www.example.org/articles/april/showers.html)）。用户请求一个页面，页面出现，可能包含到相关页面的（超）链接。

然而，由于无状态协议不保留上下文信息，服务器操作员几乎不可能在一系列请求中与访问者建立更有趣的关系，或者访问者动态地将多个响应聚合成一个视图。

此外，请求的表达能力受到协议本身的限制，也受到服务器内容不足以有用地支持更具描述性词汇的限制。在很大程度上，请求就像指着一个对象说“给我那个”。考虑典型 URL 的部分：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/8e5bfd4c-8f16-4b85-8909-315c391656bd.png)

我们可以看到，在描述简单资源位置时，客户端工作量很大，查询参数和资源目标成为一个笨拙的事后想法，一旦使用了多个资源描述符，几乎变得无法使用。虽然在简单文档和不变的层次结构的时代，这是可行的，但现代网络软件的需求和复杂性使原始概念变得不可行并需要改进。

传递越来越复杂的键/值对以维护用户状态的笨拙性开始让这个新媒介的抱负受挫。很快，开发人员意识到，对互联网作为世界信息、软件和商业的实用通信层的日益依赖需要更精细的方法。

随着时间的推移，这些限制已经通过对 HTTP 协议的改进、引入 JavaScript 到浏览器、诸如浏览器 cookie 等技术以及开发人员构建产品和服务来利用这些进步的创新的结合而被克服。

然而，HTTP 协议本身仍然被个体文件样式资源存在于一个独特和永久路径，并由一个通常不具描述性的名称标识的相同主题所支配。

现在许多服务器上实际存在的是一个复杂的软件，指定了数据模型的网络接口。与这些类型的网络应用程序通信涉及到获取和设置该数据模型的状态，无论是一般的还是特定于向发出请求的客户端的状态。

部署实时解决方案的客户端在服务器上设置和获取资源状态表示。应用服务器必须在每个请求中报告客户端的状态与多个进程（数据库、文件、规则引擎、计算引擎等）的关系，并且通常在应用状态发生变化时单方面报告（例如，用户失去访问权限）。客户端通常不是浏览器，而是其他服务器。它们应该如何通信？

# 理解路线

路由将 URL 映射到操作。与构建应用程序界面以 URL 路径到包含一些逻辑的特定文件的方式不同，使用路由进行设计涉及将特定功能分配给 URL 路径和请求方法的不同组合。例如，一个接受城市列表请求的 Web 服务可能以这种方式被调用：

```js
GET /services/cities.php?country=usa&state=ohio 
```

当您的服务器收到此请求时，它将把 URL 信息传递给一个 PHP 进程，该进程将执行`cities.php`中的应用逻辑，比如读取查询、解析国家和州、调用数据库、构建响应并返回。Node 具有作为服务器和应用环境的双重优势。服务器可以直接处理请求。因此，使用 URL 作为简单的意图陈述更有意义：

```js
GET /listCities/usa/ohio 
```

在 Node 服务器中，我们可能会使用以下代码来处理这些城市的请求：

```js
let app = http.createServer((request, response) => {
  let url = request.url;
  let method = request.method;
  if (method === "GET") {
    if (url === "/listCities/usa/ohio") {
      database.call("usa","ohio", (err, data) => {
        response.writeHead(200, {'Content-Type': 'application/json' });
        // Return list of cities in Ohio, USA
        response.end(JSON.stringify(data));
      });
    }
    if (url === "/listCities/usa/arizona") { ... }
    if (url === "/listCities/canada/ontario") { ... }
  }
})
```

有一个好的和一个坏的跳出来：

+   URL 处理清晰地组织在一个地方

+   代码是不可思议的重复

写出每种可能的路线是行不通的。我们将保持组织，但需要在路线中创建变量，更倾向于定义一个通用的路线表达式，如下所示：

```js
/listCities/:country/:state 
```

方法`listCities`可以接受`country`和`state` *变量*参数，用冒号(`:`)前缀标识。在我们的服务器中，我们需要将这个符号表达式转换成正则表达式。在这种情况下，`RegExp /^\/listCities\/([^\/\.]+)\/([^\/\.]+)\/?$/`可以用来从我们的示例 URL 中提取有序值，形成一个类似于值映射的值映射：

```js
{ country: "usa", state: "ohio" } 
```

通过将请求视为表达式，我们的服务器设计变得更加理智，将任何国家/州的组合都很好地路由到一个公共处理程序函数：

```js
if (request.method === "GET") {
  let match = request.url.match(/^\/listCities\/([^\/\.]+)\/([^\/\.]+)\/?$/);
  if (match) {
    database.call(match[1],match[2],function(err, data) {…}
  }
}
```

这种形式的请求路由在 Node 社区中*赢得了争论*，成为各种框架和工具的默认行为。事实上，这种关于路由请求的思考方式已经在许多其他开发环境中得到了接受，比如 Ruby on Rails。因此，大多数 Node 的 Web 应用程序框架都是围绕路由开发的。

Node 最流行的 Web 应用程序框架是 T.J. Holowaychuk 的 Express 框架，我们将在本书中经常使用这个框架来设计路由服务器。您可以通过运行`npm install express`来安装它。

# 使用 Express 路由请求

Express 简化了定义路由匹配例程的复杂性。我们的示例可能以以下方式使用 Express 编写：

```js
const express = require('express');
let app = express();
app.get('/listCities/:country/:state', (request, response) => {
  let country = request.params.country;
  let state = request.params.state;
  response.end(`You asked for country: ${country}and state: ${state}`);
});
app.listen(8080);

GET /listCities/usa/ohio
// You asked for country: usa and state: ohio
GET /didnt/define/this
// Cannot GET /didnt/define/this
GET /listCities // note missing arguments
// Cannot GET /listCities
```

实例化 Express 提供了一个完全成型的 Web 服务器，包装在一个易于使用的应用程序开发 API 中。我们的城市服务已经清晰定义，并声明了其变量，期望通过 GET 调用（也可以使用`app.post(...)`或`app.put(...)`，或任何其他标准的`HTTP`方法）。

Express 还引入了请求处理程序链的概念，在 Express 中被理解为中间件。在我们的示例中，我们调用一个单个函数来处理城市请求。如果在调用数据库之前，我们想要检查用户是否经过身份验证呢？我们可以在主要服务方法之前添加一个`authenticate()`方法：

```js
let authenticate = (request, response, next) => {
  if (validUser) {
    next();
  } else {
    response.end("INVALID USER!");
  }
}
app.get('/listCities/:country/:state', authenticate, (request, response) => { ... });
```

中间件可以链接，换句话说，简化了复杂执行链的创建，很好地遵循了模块化规则。已经开发了许多类型的中间件，用于处理网站图标、日志记录、上传、静态文件请求等。要了解更多，请访问：[`expressjs.com/`](https://expressjs.com/)。

在为 Node 服务器配置路由请求的正确方式已经建立之后，我们现在可以开始讨论如何识别发出请求的客户端，为该客户端分配一个唯一的会话 ID，并通过时间管理该会话。

# 使用 Redis 跟踪客户端状态

在本章的一些应用程序和示例中，我们将使用**Redis**，这是由*Salvatore Sanfilippo*开发的内存键/值（KV）数据库。有关 Redis 的更多信息，请访问：[`redis.io`](http://redis.io)。Redis 的一个知名竞争对手是**Memcached**（[`memcached.org`](http://memcached.org)）。

一般来说，任何必须维护许多客户端会话状态的服务器都需要一个高速数据层，具有几乎即时的读/写性能，因为请求验证和用户状态转换可能在每个请求上发生多次。传统的基于文件的关系数据库在这个任务上往往比内存 KV 数据库慢。我们将使用 Redis 来跟踪客户端状态。

Redis 是一个在内存中运行的单线程数据存储。它非常快，专注于实现多个数据结构，如哈希、列表和集合，并对这些数据执行操作（如集合交集和列表推送和弹出）。有关安装 Redis 的说明，请访问：[`redis.io/topics/quickstart`](https://redis.io/topics/quickstart)。

与 Redis 交互：

```js
$ redis-cli 
```

值得注意的是，亚马逊的 ElastiCache 服务可以将 Redis 作为内存缓存“云”化，具有自动扩展和冗余功能，网址为：[`aws.amazon.com/elasticache/`](https://aws.amazon.com/elasticache/)。

Redis 支持预期操作的标准接口，例如获取或设置键/值对。要`get`存储在键上的值，请首先启动 Redis CLI：

```js
 $ redis-cli
 redis> get somerandomkey
 (nil)
```

当键不存在时，Redis 会返回（`nil`）。让我们`set`一个键：

```js
redis> set somerandomkey "who am I?"
redis> get somerandomkey
"who am I?"
```

要在 Node 环境中使用 Redis，我们需要某种绑定。我们将使用 Matt Ranney 的`node_redis`模块。使用以下命令行通过 npm 安装它：

```js
$ npm install redis 
```

要在 Redis 中设置一个值并再次获取它，我们现在可以在 Node 中这样做：

```js
let redis = require("redis");
let client = redis.createClient();
client.set("userId", "jack", (err) => {
  client.get("userId", (err, data) => {
    console.log(data); // "jack"
  });
});
```

# 存储用户数据

管理许多用户意味着至少跟踪他们的用户信息，一些长期存储（例如地址、购买历史和联系人列表），一些会话数据短期存储（自登录以来的时间、最后一次游戏得分和最近的答案）。

通常，我们会创建一个安全的接口或类似的东西，允许管理员创建用户帐户。读者在本章结束时将清楚如何创建这样的接口。在接下来的示例中，我们只需要创建一个用户，作为志愿者。让我们创建`Jack`：

```js
redis> hset jack password "beanstalk"
redis> hset jack fullname "Jack Spratt"
```

这将在 Redis 中创建一个键—Jack—包含一个类似的哈希：

```js
{
  "password": "beanstalk",
  "fullname": "Jack Spratt"
}
```

如果我们想要创建一个哈希并一次添加多个 KV 对，我们可以使用`hmset`命令来实现前面的操作：

```js
redis> hmset jack password "beanstalk" fullname "Jack Spratt"
```

现在，`Jack`存在了：

```js
redis> hgetall jack
 1) "password"
 2) "beanstalk"
 3) "fullname"
 4) "Jack Spratt"
```

我们可以使用以下命令来获取存储在 Jack 账户中特定字段的值：

```js
redis> hget jack password // "beanstalk"
```

# 处理会话

服务器如何知道当前客户端请求是否是先前请求链的一部分？Web 应用程序通过长事务链与客户端进行交互——包含要购买的商品的购物车即使购物者离开进行一些比较购物也会保留。我们将称之为会话，其中可能包含任意数量的 KV 对，例如用户名、产品列表或用户的登录历史。

会话是如何开始、结束和跟踪的？有许多方法可以解决这个问题，这取决于不同体系结构上存在的许多因素。特别是，如果有多个服务器用于处理客户端，那么会话数据是如何在它们之间共享的？

我们将使用 cookie 来存储客户端的会话 ID，同时构建一个简单的长轮询服务器。请记住，随着应用程序的复杂性增加，这个简单的系统将需要扩展。此外，长轮询作为一种技术正在为我们在讨论实时系统构建时将要探索的更强大的套接字技术所取代。然而，在服务器上同时保持许多连接的客户端，并跟踪它们的会话时所面临的关键问题应该得到证明。

# Cookie 和客户端状态

Netscape 在 1997 年提供了有关 cookie 的初步规范：

根据[`web.archive.org/web/20070805052634/http://wp.netscape.com/newsref/std/cookie_spec.html`](https://web.archive.org/web/20070805052634/http://wp.netscape.com/newsref/std/cookie_spec.html)，“Cookie 是一种通用机制，服务器端连接（如 CGI 脚本）可以使用它来存储和检索与连接的客户端一侧有关的信息。简单、持久的客户端状态的添加显著扩展了基于 Web 的客户端/服务器应用程序的功能。服务器在向客户端返回 HTTP 对象时，还可以发送一个状态信息片段，客户端将存储该状态。该状态对象包括一个描述该状态有效的 URL 范围。客户端以后在该范围内发出的任何 HTTP 请求都将包括将当前状态对象的值从客户端传输回服务器。状态对象称为 cookie，没有强制的原因。”

在这里，我们首次尝试*修复*HTTP 的无状态性，特别是会话状态的维护。这是一个很好的尝试，它仍然是 Web 的一个基本部分。

我们已经看到如何使用 Node 读取和设置 cookie 头。Express 使这个过程变得更容易：

```js

const express = require('express');
const cookieParser = require('cookie-parser');
const app = express();

app.use(cookieParser());

app.get('/mycookie', (request, response) => {
   response.end(request.cookies.node_cookie);
});

app.get('/', (request, response) => {
   response.cookie('node_cookie', parseInt(Math.random() * 10e10));
   response.end("Cookie set");
});

app.listen(8000);
```

注意`use`方法，它允许我们为 Express 打开 cookie 处理中间件。在这里，我们看到每当客户端访问我们的服务器时，该客户端都会被分配一个随机数作为 cookie。通过导航到`/mycookie`，该客户端可以看到 cookie。

# 一个简单的轮询

接下来，让我们创建一个并发环境，一个有许多同时连接的客户端。我们将使用一个长轮询服务器来做到这一点，通过`stdin`向所有连接的客户端进行广播。此外，每个客户端将被分配一个唯一的会话 ID，用于标识客户端的`http.serverResponse`对象，我们将向其推送数据。

长轮询是一种技术，其中服务器保持与客户端的连接，直到有数据可发送。当数据最终发送到客户端时，客户端重新连接到服务器，进程继续进行。它被设计为对短轮询的改进，短轮询是盲目地每隔几秒钟检查一次服务器是否有新信息的低效技术，希望有新数据。长轮询只需要在向客户端传递实际数据后重新连接。

我们将使用两个路由。第一个路由使用斜杠(`/`)描述，即根域请求。对该路径的调用将返回一些形成客户端 UI 的 HTML。第二个路由是`/poll`，客户端将使用它在接收到一些数据后重新连接服务器。

客户端 UI 非常简单：它的唯一目的是向服务器发出 XML HTTP 请求（XHR）（服务器将保持该请求直到接收到一些数据），在接收到一些数据后立即重复此步骤。我们的 UI 将在无序列表中显示接收到的消息列表。对于 XHR 部分，我们将使用 jQuery 库。可以使用任何类似的库，并且构建纯 JavaScript 实现并不困难。

HTML：

```js
<ul id="results"></ul> 
```

JavaScript：

```js
function longPoll() {
  $.get('http://localhost:2112/poll', (data) => {
    $('<li>' + data + '</li>').appendTo('#results');
    longPoll();
  });
}
longPoll();
```

在上面的客户端代码中，您应该看到这将如何工作。客户端对/poll 进行 GET 调用，并将等待直到接收到数据。一旦接收到数据，它将被添加到客户端显示，并进行另一个/poll 调用。通过这种方式，客户端保持与服务器的长连接，并且仅在接收到数据后重新连接。

服务器也很简单，主要负责设置会话 ID 并保持并发客户端连接，直到数据可用，然后将数据广播到所有连接的客户端。数据通过 redis pub/sub 机制可用。这些连接通过会话 ID 进行索引，使用 cookie 进行维护：

```js
const fs = require('fs');
const express = require('express');
const cookieParser = require('cookie-parser');
const redis = require("redis");
const receiver = redis.createClient();
const publisher = redis.createClient();
const app = express();

app.use(cookieParser());

let connections = {};

app.get('/poll', (request, response) => {
   let id = request.cookies.node_poll_id;
   if(!id) {
      return;
   }
   connections[id] = response;
});

app.get('/', (request, response) => {
    fs.readFile('./poll_client.html', (err, data) => {
       response.cookie('node_poll_id', Math.random().toString(36).substr(2, 9));
        response.writeHead(200, {'Content-Type': 'text/html'});
        response.end(data);
    });
});

app.listen(2112);

receiver.subscribe("stdin_message");
receiver.on("message", (channel, message) => {
   let conn;
   for(conn in connections) {
      connections[conn].end(message);
   }
    console.log(`Received message: ${message} on channel: ${channel}`);
});

process.stdin.on('readable', function() {
   let msg = this.read();
   msg && publisher.publish('stdin_message', msg.toString());
});
```

在命令行上运行此服务器，并通过浏览器连接到服务器（http://localhost:2112）。将显示一个带有文本“Results:”的页面。返回到命令行并输入一些文本-此消息应立即显示在您的浏览器中。当您在命令行上继续输入时，您的消息将被路由到连接的客户端。您也可以尝试使用多个客户端进行此操作--请注意，您应该使用不同的浏览器，隐身模式或其他方法来区分每个客户端。

虽然这是用于演示的玩具服务器（您可能不应该使用长轮询--更好的选项在第六章中提出，*创建实时应用程序*），但最终应该看到如何使用一些业务逻辑来更新状态，然后捕获这些状态更改事件，然后使用类似 Redis pub/sub 的机制广播到监听客户端。

# 验证连接

与建立客户端会话对象相结合，Node 服务器通常需要身份验证凭据。Web 安全的理论和实践是广泛的。

我们希望将我们的理解简化为两种主要的身份验证场景：

+   当传输协议是 HTTPS 时

+   当它是 HTTP 时

第一个自然是安全的，第二个不是。对于第一个，我们将学习如何在 Node 中实现基本身份验证，对于第二个，将描述一种挑战-响应系统。

# 基本身份验证

如前所述，基本身份验证在传输中发送包含用户名/密码组合的明文，使用标准 HTTP 头。这是一个简单而广为人知的协议。发送正确头的任何服务器都将导致任何浏览器显示登录对话框，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/8b8f4ff2-1e85-46b4-8ef2-59f273085118.png)

尽管如此，这种方法仍然不安全，在传输中发送非加密的明文数据。为了简单起见，我们将在 HTTP 服务器上演示此身份验证方法，但必须强调的是，在实际使用中，服务器必须通过安全协议进行通信，例如 HTTPS。

让我们使用 Node 实现此身份验证协议。利用之前在 Redis 中开发的用户数据库，我们通过检查用户对象以验证提交的凭据，处理失败和成功来验证提交的凭据：

```js
http.createServer(function(req, res) {

   let auth = req.headers['authorization']; 
   if(!auth) {   
      res.writeHead(401, {'WWW-Authenticate': 'Basic realm="Secure Area"'});
      return res.end('<html><body>Please enter some credentials.</body></html>');
   }

   let tmp = auth.split(' ');   
   let buf = Buffer.from(tmp[1], 'base64'); 
   let plain_auth = buf.toString();   
   let creds = plain_auth.split(':'); 
   let username = creds[0];

   // Find this user record
   client.get(username, function(err, data) {
      if(err || !data) {
         res.writeHead(401, {'WWW-Authenticate': 'Basic realm="Secure Area"'});
         return res.end('<html><body>You are not authorized.</body></html>');
      }
      res.statusCode = 200;
      res.end('<html><body>Welcome!</body></html>');
   });
}).listen(8080);
```

通过在新的客户端连接上发送`401`状态和`'authorization'`头，将创建一个类似于上一个屏幕截图的对话框，通过这段代码：

```js
  res.writeHead(401, {'WWW-Authenticate': 'Basic realm="Secure Area"'});
  return res.end('<html><body>Please enter some credentials.</body></html>');
```

通过这种方式，可以设计一个简单的登录系统。由于浏览器会自然地提示用户请求访问受保护的域，甚至登录对话框也会被处理。

# 握手

在无法建立 HTTPS 连接的情况下考虑的另一种身份验证方法是挑战/响应系统：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/53a64cb6-d275-4202-8fd3-f0fb575ba817.png)

在这种情况下，客户端请求服务器访问特定用户、用户名、ID 或类似的内容。通常，这些数据将通过登录表单发送。让我们模拟一个挑战/响应场景，使用我们之前创建的用户 Jack 作为示例。

挑战/响应系统的一般设计和目的是避免在网络上传输任何明文密码数据。因此，我们需要决定一个加密策略，客户端和服务器都共享。在我们的示例中，让我们使用 SHA256 算法。Node 的 crypto 库包含了创建这种类型哈希所需的所有工具。客户端可能没有，所以我们必须提供一个。我们将使用由 Chris Veness 开发的一个，可以从以下链接下载：[`github.com/chrisveness/crypto/blob/master/sha256.js.`](https://github.com/chrisveness/crypto/blob/master/sha256.js)

要启动此登录，客户端需要为用户 Jack 发送身份验证请求：

```js
GET /authenticate/jack 
```

作为响应，客户端应该收到服务器生成的公钥——挑战。现在，客户端必须形成一个以此键为前缀的 Jack 的密码字符串。从中创建一个 SHA256 哈希，并将生成的哈希传递给`/login/`。服务器也将创建相同的 SHA256 哈希——如果两者匹配，则客户端已经通过身份验证：

```js
<script src="img/sha256.js"></script>
<script>
$.get("/authenticate/jack", (publicKey) => {
    if (publicKey === "no data") {
    return alert("Cannot log in.");
  }
  // Expect to receive a challenge: the client should be able to derive a SHA456 hash
  // String in this format: publicKey + password. Return that string.
  let response = Sha256.hash(publicKey + "beanstalk");
  $.get("/login/" + response, (verdict) => {
    if (verdict === "failed") {
      return alert("No Dice! Not logged in.");
    }
    alert("You're in!");
  });
});
</script>
```

服务器本身非常简单，由两个提到的身份验证路由组成。我们可以在以下代码中看到，当收到用户名（`jack`）时，服务器将首先检查 Redis 中是否存在用户哈希，如果找不到这样的数据，则中断握手。如果记录存在，我们创建一个新的随机公钥，组成相关的 SHA256 哈希，并将此挑战值返回给客户端。此外，我们将此哈希设置为 Redis 中的一个键，其值为发送的用户名：

```js
const crypto = require('crypto');
const fs = require('fs');
const express = require('express');
const redis = require("redis");

let app = express();
let client = redis.createClient();

app.get('/authenticate/:username', (request, response) => {
  let publicKey = Math.random();
  let username = request.params.username; // This is always "jack"
  // ... get jack's data from redis
  client.hgetall(username, (err, data) => {
    if (err || !data) {
      return response.end("no data");
    }
    // Creating the challenge hash
    let challenge = crypto.createHash('sha256').update(publicKey + data.password).digest('hex');
    // Store challenge for later match
    client.set(challenge, username);
    response.end(challenge);
  });
});
app.get('/login/:response', (request, response) => {
  let challengehash = request.params.response;
  client.exists(challengehash, (err, exists) => {
    if (err || !exists) {
    return response.end("failed");
    }
  });
  client.del(challengehash, () => {
    response.end("OK");
  });
});
```

在`/login/`路由处理程序中，我们可以看到如果响应存在于 Redis 中，则会进行检查，并且如果找到，则立即删除该键。这是有几个原因的，其中之一是防止其他人发送相同的响应并获得访问权限。我们也通常不希望这些现在无用的键堆积起来。这带来了一个问题：如果客户端从不响应挑战会怎么样？由于键清理仅在进行`/login/`尝试时发生，因此此键将永远不会被删除。

与大多数 KV 数据存储不同，Redis 引入了**键过期**的概念，其中设置操作可以为键指定**生存时间**（**TTL**）。例如，在这里，我们使用`setex`命令将键`userId`设置为值`183`，并指定该键应在一秒后过期：

```js
 client.setex("doomed", 10, "story", (err) => { ... }); 
```

这个功能为我们的问题提供了一个很好的解决方案。通过用以下行替换`client.set(challenge, username);`行：

```js
client.setex(challenge, 5, username); 
```

我们确保无论如何，这个键都会在`5`秒内消失。以这种方式做事也可以作为一种轻量级的安全措施，留下一个非常短的时间窗口使响应保持有效，并自然地怀疑延迟的响应。

# 使用 JSON Web 令牌进行身份验证

基本的身份验证系统可能需要客户端在每个请求上发送用户名和密码。要启动基于令牌的身份验证会话，客户端只需发送一次凭据，然后收到一个令牌作为交换，并在随后的请求中只发送该令牌，获取该令牌提供的任何访问权限。不再需要不断传递敏感凭据。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/0b5ae151-9f87-4a30-8abd-b3f01561c0aa.png)

JWT 的一个特别优势是，服务器不再需要维护一个共同的凭据数据库，因为只有发行机构需要验证初始登录。在使用 JWT 时，无需维护会话存储。因此，发行的令牌（可以将其视为访问卡）可以在任何识别和接受它的域（或服务器）内使用。在性能方面，现在请求的成本是解密哈希的成本，而不是进行数据库调用来验证凭据的成本。我们还避免了在移动设备上使用 cookie 时可能遇到的问题，跨域问题（cookie 是与域名绑定的），某些类型的请求伪造攻击等。

如果您想要与 Express 集成，`express-jwt`模块可能会很有用：[`github.com/auth0/express-jwt`](https://github.com/auth0/express-jwt)。

让我们看一下 JWT 的结构，然后构建一个简单的示例，演示如何发出，验证和使用 JWT 来管理会话。

JWT 令牌具有以下格式：

```js
<base64-encoded header>.<base64-encoded claims>.<base64-encoded signature>
```

每个部分都以 JSON 格式描述。**header**只是描述令牌的类型和加密算法。考虑以下示例：

```js
{ 
  "typ":"JWT", 
  "alg":"HS256" 
}
```

在这里，我们声明这是一个 JWT 令牌，使用 HMAC SHA-256 进行加密。有关加密的更多信息，请参阅[`nodejs.org/api/crypto.html`](https://nodejs.org/api/crypto.html)，以及如何在 Node 中执行加密。JWT 规范本身可以在以下网址找到：[`tools.ietf.org/html/rfc7519`](https://tools.ietf.org/html/rfc7519)。

**claims**部分概述了安全性和其他约束条件，任何接收 JWT 的服务都应该检查这些条件。查看完整的规范。通常，JWT 声明清单会想要指示 JWT 的发行时间，发行者，过期时间，JWT 的主题以及谁应该接受 JWT：

```js
{ 
  "iss": "http://blogengine.com", 
  "aud": ["http://blogsearch.com", "http://blogstorage"], 
  "sub": "blogengine:uniqueuserid", 
  "iat": "1415918312", 
  "exp": "1416523112", 
  "sessionData": "<some data encrypted with secret>" 
}
```

`iat`（发行时间）和`exp`（过期时间）声明都设置为数字值，表示自 Unix 纪元以来的秒数。`iss`（发行者）应该是描述 JWT 发行者的 URL。任何接收 JWT 的服务都必须检查`aud`（受众），如果它不出现在受众列表中，该服务必须拒绝 JWT。JWT 的`sub`（主题）标识 JWT 的主题，例如应用程序的用户——一个永远不会重新分配的唯一值，例如发行服务的名称和唯一用户 ID。

最后，使用任何您喜欢的键/值对附加一些有用的数据。在这里，让我们称之为令牌数据 sessionData。请注意，我们需要加密这些数据——JWT 的签名部分防止篡改会话数据，但 JWT 本身并不加密（尽管您始终可以加密整个令牌本身）。

最后一步是创建一个签名，如前所述，防止篡改——JWT 验证器专门检查签名和接收到的数据包之间的不匹配。

接下来是一个示例服务器和客户端的框架，演示如何实现基于 JWT 的身份验证系统。我们将使用`jwt-simple`包来实现各种签名和验证步骤，而不是手动实现。随时浏览您的代码包中的`/jwt`文件夹，其中包含我们将在接下来解压缩的完整代码。

要请求令牌，我们将使用以下客户端代码：

```js
function send(route, formData, cb) {
  if(!(formData instanceof FormData)) {
    cb = formData;
    formData = new FormData();
  }
  let caller = new XMLHttpRequest();
  caller.onload = function() {
     cb(JSON.parse(this.responseText));
  };
  caller.open("POST", route);
  token && caller.setRequestHeader('Authorization', 'Bearer ' + token);
  caller.send(formData);
}
```

当我们以某种方式收到`username`和`password`时：

```js
formData = new FormData();
formData.append("username", "sandro");
formData.append("password", 'abcdefg');

send("/login", formData, function(response) {
  token = response.token;
  console.log('Set token: ' + token);
});
```

接下来我们将实现服务器代码。现在，请注意我们有一个发送方法，该方法在某个时候期望有一个全局令牌设置，以便在进行请求时传递。最初的`/login`是我们请求该令牌的地方。

使用 Express，我们创建以下服务器和`/login`路由：

```js
const jwt = require('jwt-simple');
const app = express();
app.set('jwtSecret', 'shhhhhhhhh');

...

app.post('/login', auth, function(req, res) {
   let nowSeconds     = Math.floor(Date.now()/1000);
   let plus7Days  = nowSeconds + (60 * 60 * 24 * 7);
   let token = jwt.encode({
      "iss" : "http://blogengine.com", 
      "aud" : ["http://blogsearch.com", "http://blogstorage"],
      "sub" : "blogengine:uniqueuserid",
      "iat" : nowSeconds,
      "exp" : plus7Days,
      "sessionData" : encrypt(JSON.stringify({
         "department" : "sales"
      }))
   }, app.get('jwtSecret'));

   res.send({
      token : token
   })
})
```

请注意，我们将`jwtsecret`存储在应用服务器上。这是在签署令牌时使用的密钥。当尝试登录时，服务器将返回`jwt.encode`的结果，该结果编码了前面讨论过的 JWT 声明。就是这样。从现在开始，任何客户端只要向正确的受众提到这个令牌，就可以与这些受众成员提供的任何服务进行交互，有效期为自发行日期起的 7 天。这些服务将实现类似以下内容的内容：

```js
app.post('/tokendata', function(req, res) { 
   let </span>token = req.get('Authorization').replace('Bearer ', '');
   let decoded = jwt.decode(token, app.get('jwtSecret'));
   decoded.sessionData = JSON.parse(decrypt(decoded.sessionData));
   let now = Math.floor(Date.now()/1000);
   if(now > decoded.exp) {
      return res.end(JSON.stringify({
         error : "Token expired"
      }));
   }
   res.send(decoded)
});
```

在这里，我们只是获取**Authorization**头（去掉**Bearer**）并通过`jwt.decode`进行解码。服务至少必须检查令牌是否过期，我们通过比较自纪元以来的当前秒数和令牌的过期时间来实现这一点。使用这个简单的框架，您可以创建一个易于扩展的身份验证/会话系统，使用安全标准。不再需要维护与公共凭据数据库的连接，个别服务（可能部署为微服务）可以使用 JWT 验证请求，而几乎不会产生 CPU、延迟或内存成本。

# 总结

Node 提供了一组工具，可帮助设计和维护面对 C10K 问题的大规模网络应用程序。在本章中，我们已经迈出了第一步，创建了具有许多同时客户端的网络应用程序，跟踪它们的会话信息和凭据。这种并发性的探索展示了一些路由、跟踪和响应客户端的技术。我们提到了一些简单的扩展技术，例如使用 Redis 数据库构建的发布/订阅系统来实现进程内消息传递。我们还提到了各种认证机制，从基本认证到基于 JSON Web Tokens 的基于令牌的认证。

我们现在准备深入探讨实时软件的设计——在使用 Node 实现高并发和低延迟之后的逻辑下一步。我们将扩展我们在长轮询讨论中概述的想法，并将它们放在更健壮的问题和解决方案的背景下。

# 进一步阅读

并发性和并行性是丰富的概念，经过了严格的研究和辩论。当应用架构设计支持线程、事件或某种混合时，架构师很可能对这两个概念持有看法。鼓励您深入理论，阅读以下文章。对辩论的准确理解将提供一个客观的框架，可用于评估选择（或不选择）Node 的决定：

+   一些数字：[`citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.154.7354&rep=rep1&type=pdf`](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.154.7354&rep=rep1&type=pdf)

+   线程是一个坏主意：[`web.stanford.edu/~ouster/cgi-bin/papers/threads.pdf`](https://web.stanford.edu/~ouster/cgi-bin/papers/threads.pdf)

+   事件是一个坏主意：[`people.eecs.berkeley.edu/~brewer/papers/threads-hotos-2003.pdf`](https://people.eecs.berkeley.edu/~brewer/papers/threads-hotos-2003.pdf)

+   一起怎么样？：[`www.cis.upenn.edu/~stevez/papers/LZ06b.pdf`](https://www.cis.upenn.edu/~stevez/papers/LZ06b.pdf)

+   科学：[`courses.cs.vt.edu/cs5204/fall09-kafura/Presentations/Threads-VS-Events.pdf`](http://courses.cs.vt.edu/cs5204/fall09-kafura/Presentations/Threads-VS-Events.pdf)


# 第六章：创建实时应用程序

“唯一不变的是变化。”

- 赫拉克利特

什么是实时软件？好友列表在有人加入或退出时立即更新。交通信息会自动流入正在寻找最佳回家路线的司机的智能手机。在线报纸的体育版会在实际比赛中得分时立即更新比分和排名。这类软件的用户期望对变化的反应能够快速传达，这种期望要求软件设计者特别关注减少网络延迟。数据 I/O 更新必须在亚秒级时间范围内发生。

让我们退一步，考虑一下 Node 环境和社区的一般特点，使其成为创建这类响应式网络应用程序的绝佳工具。

可以说，Node 设计的一些验证可以在庞大的开发者社区中找到，这些开发者正在贡献企业级 Node 系统。多核、多服务器的企业系统正在使用大部分用 JavaScript 编写的免费软件创建。

为什么有这么多公司在设计或更新产品时都向 Node 迁移？以下列举了原因：

+   Node 提供了出色的 npm 包管理系统，可以轻松与 Git 版本控制系统集成。浅显易懂的学习曲线帮助即使是经验不足的开发人员也能安全地存储、修改和分发新的模块、程序和想法。开发人员可以在私人 Git 存储库上开发私有模块，并使用 npm 在私人网络中安全地分发这些存储库。因此，Node 用户和开发人员的社区迅速扩大，一些成员声名鹊起。*如果你建造它，他们就会来*。

+   Node 打破了系统访问的障碍，突然释放了大批技术娴熟的程序员的才华，为一个需要在基础设施上进行许多改进的热门新项目提供了机遇生态系统。关键在于：Node 将并发的机会与原生 JavaScript 事件相结合；其设计精巧的 API 允许使用众所周知的编程范式的用户利用高并发 I/O。*如果你奖励他们，他们就会来*。

+   Node 打破了网络访问的障碍，让一大批 JavaScript 开发人员的工作和抱负开始超越客户端开发者可用的小沙盒。不应忘记，从 1995 年引入 JavaScript 到现在已经过去了 20 多年。几乎一个开发人员的一代人一直在努力尝试在以事件驱动的开发环境中实现新的网络应用想法，而这个环境以其限制而闻名，甚至被定义。Node 一夜之间消除了这些限制。*如果你清理路径，他们就会来*。

+   Node 提供了一种构建可扩展网络程序的简单方法，其中网络 I/O 不再是瓶颈。真正的转变不是从另一个流行系统到 Node，而是摆脱了需要昂贵和复杂资源来构建和维护需要突发并发的高效应用程序的观念。如果可以廉价实现一个弹性和可扩展的网络架构，那么释放出的资源可以用来解决其他紧迫的软件挑战，比如并行化数据过滤、构建大规模多人游戏、构建实时交易平台或协作文档编辑器，甚至在热系统中实现实时代码更改。信心带来进步。*如果你让它变得容易，他们就会来*。

Node 在那些构建动态网页的人已经开始遇到服务器无法顺利处理许多小型同时请求的限制时出现。软件架构师现在必须解决一些有趣的问题：*实时*的规则是什么——用户是否满意于*很快*，还是*现在*是唯一正确的响应？最好的设计系统满足这些用户需求的方式是什么？

在本章中，我们将调查开发人员在构建实时网络应用程序时可以使用的三种标准技术：AJAX、WebSockets 和服务器发送事件（SSE）。我们本章的目标是了解每种技术的优缺点，并使用 Node 实现每种技术。记住我们的目标是实现一个一致的架构，反映 Node 的事件流设计，我们还将考虑每种技术作为可读、可写或双工流的表现能力。

我们将以构建一个协作代码编辑器来结束本章，这应该展示了 Node 为那些希望构建实时协作软件的人提供的机会。当您逐步学习示例并构建自己的应用程序时，这些都是值得自问的一些问题：

+   我预计每秒要处理的消息量是多少？在高峰时段和非高峰时段，预计会有多少同时连接的客户端？

+   传输的消息的平均大小是多少？

+   如果我能接受偶尔的通信中断或丢失的消息，是否可以通过这种让我获得更低的平均延迟？

+   我真的需要双向通信吗，还是一方几乎负责所有消息量？我是否需要一个复杂的通信接口？

+   我的应用程序将在哪些网络中运行？在客户端和我的 Node 服务器之间会有代理服务器吗？支持哪些协议？

+   我需要一个复杂的解决方案，还是简单直接，甚至稍慢一些的解决方案会在长远带来其他好处？

# 引入 AJAX

2005 年，Jesse James Garrett 发表了一篇文章，试图将他所看到的网站设计方式的变化压缩成一种模式。在研究了这一趋势之后，Garrett 提出，动态更新页面代表了一种新的软件浪潮，类似于桌面软件，他创造了缩写*AJAX*来描述推动这种快速向*Web 应用程序*发展的技术概念。

这是他用来展示一般模式的图表：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/705a2392-c4f4-4f16-b238-d58c5e77eca4.png)

原始文章链接：

[`adaptivepath.org/ideas/ajax-new-approach-web-applications/`](http://adaptivepath.org/ideas/ajax-new-approach-web-applications/).

在 2000 年前后，*Garrett*的图表中提到的"*AJAX 引擎*"实际上已经存在于大多数常见的浏览器中，甚至在一些浏览器中更早。这些浏览器中的 JavaScript 实现了**XMLHttpRequest** (**XHR**)对象，使网页能够从服务器请求 HTML 或其他数据的*片段*。部分更新可以动态应用于网页，从而为新型用户界面创造了机会。例如，最新的活动图片可以神奇地出现在用户面前，而无需用户主动请求页面刷新或点击下一张图片按钮。

更重要的是，Garrett 还理解了*旧*互联网的同步、无状态世界正在变成异步、有状态的世界。客户端和服务器之间的对话不再因突然失忆而中断，可以持续更长时间，共享越来越有用的信息。Garret 将此视为网络软件新一代的转变。

# 回应呼叫

如果可以在不需要完全重建状态和状态显示的情况下引入更改到 Web 应用程序中，更新客户端信息将变得更加便宜。客户端和服务器可以更频繁地交流，定期交换信息。服务器可以识别、记住并立即响应客户端的愿望，通过反应式界面收集用户操作，并几乎实时地在 UI 中反映这些操作的影响。

使用 AJAX，支持实时更新每个客户端对整个应用程序状态的视图的多用户环境的构建涉及客户端定期轮询服务器以检查重要更新：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/1f9a7fcf-e3cd-460c-b6ac-2759125b945a.png)

轮询状态的重大缺点是，其中许多请求将是徒劳的。客户端变成了一个破碎的记录，不断地请求状态更新，无论这些更新是否可用或即将到来。当应用程序花费时间或精力执行不必要的任务时，应该存在一些明显的好处，以抵消这种成本。此外，每次徒劳的调用都会增加建立然后拆除 HTTP 连接的成本。

这样的系统只能在定期间隔内获取状态的快照，由于轮询间隔可能增加到几秒钟，以减少冗余的网络通信，我们对状态变化的意识可能开始显得迟钝，稍微落后于最新消息。

在上一章中，我们看到了一个更好的解决方案——长轮询，即让服务器保持与客户端的连接，直到有新数据可用。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/e75d3f2e-60b1-43ad-90b5-302707dde4c5.png)

这种改进的 AJAX 技术并没有完全摆脱建立和拆除网络连接的成本，但显著减少了这类昂贵操作的数量。总的来说，AJAX 无法提供流畅的、类似流的事件接口，需要大量的服务来持久化状态，因为连接经常中断然后重新建立。

然而，AJAX 仍然是一些应用的真正选择，特别是简单的应用，其中理想的轮询间隔相当明确，每次轮询都有很大机会收集有用的结果。让我们使用 Node 构建一个能够与股票报告服务通信的服务器，并构建一个定期请求该服务器以检查更改并报告它们的轮询客户端。

# 创建股票行情

最终，我们将创建一个应用程序，允许客户端选择一只股票，并观察与该股票相关的数据点的变化，如其价格，并突出正面或负面的变化：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/daf8e1a5-a9f3-430a-9a96-822e15020901.png)

要创建客户端，我们的工作很少。我们只需要每隔几秒钟轮询我们的服务器，更新我们的界面以反映任何数据更改。让我们使用 jQuery 作为我们的 AJAX 库提供程序。要使用 jQuery 从服务器获取 JSON，通常会这样做：

```js
function fetch() {
  $.getJSON("/service", (data) => {
    // Do something with data
    updateDisplay(data);
    // Call again in 5 seconds
    setTimeout(fetch, 5000);
  });
}
fetch(); 
```

Node 服务器将接收此更新请求，执行一些 I/O（检查数据库，调用外部服务），并以数据响应，客户端可以使用。

在我们的示例中，Node 将用于连接到 IEX Developer Platform ([`iextrading.com/developer/`](https://iextrading.com/developer/))，该平台免费提供股票报价。

我们将构建一个 Node 服务器，监听客户端请求更新给定股票代码（如“IBM”）的数据。然后，Node 服务器将为该股票代码创建一个 YQL 查询，并通过`http.get`执行该查询，将接收到的数据包装好发送回调用客户端。

这个包还将被分配一个新的`callIn`属性，表示客户端在再次调用之前应该等待的毫秒数。这是一个有用的技术要记住，因为我们的股票数据服务器将比客户端更好地了解交通状况和更新频率。我们的服务器可以在每次调用后重新校准这个频率，甚至要求客户端停止调用，而不是盲目地按照固定的时间表检查。

由于这种设计，特别是视觉设计，可以通过多种方式完成，我们将简单地看一下我们客户需要的核心功能，包含在以下的`fetch`方法中：

```js
function fetch() {
  clearTimeout(caller);
  let symbol = $("#symbol").val();

  $.getJSON(`/?symbol=${symbol}`, function(data) {
    if(!data.callIn) {
      return;
    }
    caller = setTimeout(fetch, data.callIn);
    if(data.error) {
      return console.error(data.error);
    }
    let quote = data.quote;
    let keys = fetchNumericFields(quote);

    ...

    updateDisplay(symbol, quote, keys);
  });
}
```

在这个页面上，用户将股票符号输入到 ID 为`#symbol`的输入框中。然后从我们的数据服务中获取这些数据。在前面的代码中，我们看到通过`$.getJSON jQuery`方法进行服务调用，接收到 JSON 数据，并使用 Node 发送回来的`callIn`间隔设置了`setTimeout`属性。

我们的服务器负责与数据服务协商前面的客户端调用。假设我们有一个正确配置的服务器成功地从客户端接收股票符号，我们需要打开到服务的 HTTP 连接，读取任何响应，并返回这些数据：

```js
https.get(query, res => {
 let data = "";
 res.on('readable', function() {
   let d;
   while(d = this.read()) {
     data += d.toString();
   }
 }).on('end', function() {
   let out = {};
   try {
     data = JSON.parse(data);
     out.quote = data;
     out.callIn = 5000;

     Object.keys(out.quote).forEach(k => {
       // Creating artificial change (random)
       // Normally, the data source would change regularly.
       v = out.quote[k];
       if(_.isFinite(v)) {
         out.quote[k] = +v + Math.round(Math.random());
       }
     })

   } catch(e) {
     out = {
       error: "Received empty data set",
       callIn: 10000
     };
   }
   response.writeHead(200, {
     "Content-type" : "application/json"
   });
   response.end(JSON.stringify(out));
  });
}).on('error', err => {
  response.writeHead(200, {
    "Content-type" : "application/json"
  });
  response.end(JSON.stringify({
    error: err.message,
    callIn: null
  }));
});
```

在这里，我们看到了一个很好的例子，说明为什么让服务器，作为主要的状态观察者，调节客户端轮询的频率是一个好主意。如果成功接收到数据对象，我们将轮询间隔(`callIn`)设置为大约五秒。如果发生错误，我们将延迟增加到 10 秒。很容易看出，如果重复发生错误，我们可能会做更多的事情，例如进一步限制连接。鉴于这一点，应用程序可能会对向外部服务发出请求的速率有限制（例如限制一小时内可以发出的调用次数）；这也是一个确保不断的客户端轮询不会超过这些速率限制的有用技术。

AJAX 是创建实时应用程序的原始技术。在某些情况下仍然有用，但已被更高效的传输方式取代。在离开这一部分时，让我们记住一些轮询的优缺点：

| **优点** | **缺点** |
| --- | --- |
| REST 的理论和实践是可用的，允许更标准化的通信 | 建立和断开连接会对网络延迟产生成本，特别是如果经常这样做 |
| 不需要任何特殊的协议服务器，轮询可以很容易地使用标准的 HTTP 服务器实现 | 客户端必须请求数据；服务器无法单方面更新客户端以响应新数据的到来 |
| HTTP 是众所周知且一贯实施的 | 即使长轮询也会使需要维持持久连接的网络流量翻倍 |
|  | 数据是盲目地推送和拉取，而不是在频道上平稳地广播和监听 |

现在让我们进入讨论一些较新的协议，部分设计用于解决我们在 AJAX 中发现的一些问题：WebSockets 和 SSE。

# 使用 socket.io 进行双向通信

我们已经熟悉套接字是什么。特别是，我们知道如何使用 Node 建立和管理 TCP 套接字连接，以及如何通过它们双向或单向地传输数据。

W3C 提出了一个套接字 API，允许浏览器通过持久连接与套接字服务器通信。`socket.io`是一个库，为那些使用 Node 开发的人提供了一个基于 Node 的套接字服务器和一个用于不支持原生`WebSocket` API 的浏览器的仿真层，从而便于建立持久套接字连接。

让我们首先简要看一下原生 WebSocket API 是如何实现的，以及如何使用 Node 构建支持该协议的套接字服务器。然后，我们将使用`socket.io`和 Node 构建一个协作绘图应用程序。

`WebSocket` API 的完整规范可以在以下网址找到：[`www.w3.org/TR/websockets/. `](http://www.w3.org/TR/websockets/)有关`socket.io`的文档和安装说明可以在以下网址找到：[`socket.io/`](http://socket.io/)

# 使用 WebSocket API

套接字通信是高效的，只有当其中一方有有用的东西要说时才会发生：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/20c55a5c-de5a-4eb0-8151-7e06441bdb44.png)

这种轻量级模型非常适合需要在客户端和服务器之间进行高频消息传递的应用程序，例如在多人网络游戏或聊天室中发现的情况。

根据 W3C，WebSocket API 旨在“使 Web 应用程序能够与服务器端进程保持双向通信。”假设我们已经在`localhost:8080`上运行了一个套接字服务器，我们可以从包含以下 JavaScript 行的浏览器连接到此服务器：

```js
let conn = new WebSocket("ws://localhost:8080", ['json', 'xml']); 
```

`WebSocket`需要两个参数：以`ws://`为前缀的 URL 和一个可选的子协议列表，可以是服务器可能实现的协议的数组或单个字符串。

要建立安全的套接字连接，请使用`wss://`前缀。与 HTTPS 服务器一样，您将需要 SSL 证书。

一旦发出套接字请求，浏览器可以处理连接事件、打开、关闭、错误和消息：

```js
<head>
  <title></title>
   <script>

     let conn = new WebSocket("ws://localhost:8080", 'json');
     conn.onopen = () => {
       conn.send('Hello from the client!');
     };
     conn.onerror = (error) => {
       console.log('Error! ' + error);
     };
     conn.onclose = () => {
       console.log("Server has closed the connection!");
     };
     conn.onmessage = (msg) => {
       console.log('Received: ' + msg.data);
     };
   </script>
</head>

```

在这个例子中，我们将使用 ws 模块在 Node 中实现一个`WebSocket`服务器：[`github.com/websockets/ws`](https://github.com/websockets/ws)。使用 npm 安装 ws（`npm i ws`）后，建立一个 Node 套接字服务器非常简单：

```js
let SocketServer = require('ws').Server;
  let wss = new SocketServer({port: 8080});
  wss.on('connection', ws => {
    ws.on('message', (message) => {
      console.log('received: %s', message);
    });
    ws.send("You've connected!");
 });

```

在这里，我们可以看到服务器只是简单地监听来自客户端的`connection`和`message`事件，并根据需要做出响应。如果有必要终止连接（也许是如果客户端失去授权），服务器可以简单地发出`close`事件，客户端可以监听该事件：

```js
ws.close(); 
```

因此，使用 WebSocket API 创建双向通信的应用程序的一般示意图如下：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/3c6e068c-8269-4d4d-b0da-61edf9fce8fa.png)

本地 WebSocket 浏览器实现用于与我们的自定义 Node 套接字服务器进行通信，该服务器处理来自客户端的请求，并在必要时向客户端广播新数据或信息。

# socket.io

如前所述，`socket.io`旨在提供一个仿真层，将在支持它的浏览器中使用本机`WebSocket`实现，并在旧浏览器中（如长轮询）使用其他方法来模拟本机 API。这是一个重要的事实要记住：仍然有一些旧的浏览器存在。

尽管如此，`socket.io`在隐藏浏览器差异方面做得非常好，并且在套接字提供的控制流对于您的应用程序的通信模型是一种理想选择时，它仍然是一个很好的选择。

在前面示例中使用的`WebSocket`实现（`ws`）中，可以清楚地看到套接字服务器独立于任何特定的客户端文件。我们编写了一些 JavaScript 来在客户端上建立`WebSocket`连接，独立地使用 Node 运行套接字服务器。与这种本机实现不同，`socket.io`需要在服务器上安装自定义客户端库以及`socket.io`服务器模块：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/ba61389a-37f6-422b-9be3-5cb98714aa72.png)

`socket.io`可以使用`npm`包管理器进行安装：

```js
$ npm install socket.io 
```

设置客户端/服务器套接字配对非常简单。

在服务器端：

```js
let io = require('socket.io').listen(8080);
io.sockets.on('connection', socket => {
  socket.emit('broadcast', { message: 'Hi!' });
  socket.on('clientmessage', data => {
    console.log("Client said" + data);
  });
});
```

在客户端：

```js
<script src="img/socket.io.js"></script>
 <script>
   let socket = io.connect('http://localhost:8080');
   socket.on('broadcast', data => {
     console.log(`Server sent: ${JSON.stringify(data)}`);
     socket.emit('clientmessage', { message: 'ohai!' });
   });
 </script> 
```

我们可以看到客户端和服务器都使用相同的文件`socket.io.js`。使用`socket.io`的服务器在请求时会自动处理向客户端提供`socket.io.js`文件。还应该注意到`socket.io` API 与标准 Node`EventEmitter`接口非常相似。

# 协作绘图

让我们使用`socket.io`和 Node 创建一个协作绘图应用。我们想要创建一个空白画布，同时显示所有连接客户端所做的*笔迹*：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/2fcb18fa-585d-4dce-aef8-cb16bde157b2.png)

从服务器端来看，要做的事情很少。当客户端通过移动鼠标更新坐标时，服务器只需将此更改广播给所有连接的客户端：

```js
io.sockets.on('connection', socket => {
  let id = socket.id;

  socket.on('mousemove', data => {
    data.id = id;
    socket.broadcast.emit('moving', data);
  });

  socket.on('disconnect', () => {
    socket.broadcast.emit('clientdisconnect', id);
  });
});
```

`socket.io`会自动生成一个唯一的 ID 用于每个 socket 连接。每当发生新的绘图事件时，我们将传递这个 ID，允许接收端客户端跟踪有多少用户连接。同样，当一个客户端断开连接时，所有其他客户端都会被指示删除对这个客户端的引用。稍后，我们将看到这个 ID 在应用 UI 中如何使用，以维护表示所有连接客户端的指针。

这是一个很好的例子，展示了使用 Node 和 Node 社区创建的包来创建多用户网络应用是多么简单。让我们来分析一下这个服务器在做什么。

因为我们需要提供客户端用于绘制的 HTML 文件，所以服务器设置的一半涉及创建一个静态文件服务器。为了方便起见，我们将使用 node-static 包：[`github.com/cloudhead/node-static`](https://github.com/cloudhead/node-static)。我们的实现将为任何连接的客户端提供一个`index.html`文件。

我们的`socket.io`实现期望从客户端接收`mousemove`事件，它的唯一任务是向所有连接的客户端发送这些新坐标，它通过其`broadcast`方法通过发出一个移动事件来实现。当一个客户端通过绘制一条线改变画布状态时，所有客户端都将收到更新画布状态所需的信息，以实时更新他们的画布状态视图。

通信层建立完成后，我们现在必须创建客户端视图。如前所述，每个客户端将加载一个包含必要的 canvas 元素和监听移动事件的 JavaScript 的`index.html`文件，以及将客户端绘制事件广播到我们的服务器的`socket.io`发射器：

```js
<head>
     <style type="text/css">
     /* CSS styling for the pointers and canvas */
     </style>
     <script src="img/socket.io.js"></script>
     <script src="img/script.js"></script>
 </head>
 <body>
     <div id="pointers"></div>
     <canvas id="canvas" width="2000" height="1000"></canvas>
 </body>

```

创建一个`pointers`元素来保存所有连接客户端光标的可见表示，这些表示将随着连接客户端移动其指针和/或绘制某些东西而更新。

在`script.js`文件中，我们首先在`canvas`元素上设置事件监听器，监听`mousedown`和`mousemove`事件的组合，指示绘图动作。请注意，我们创建了一个 50 毫秒的时间缓冲，延迟每次绘制事件的广播，略微降低了绘图的分辨率，但避免了过多的网络事件：

```js
let socket = io.connect("/");
let prev = {};
let canvas = document.getElementById('canvas');
let context = canvas.getContext('2d');
let pointerContainer = document.getElementById("pointers");

let pointer = document.createElement("div");
pointer.setAttribute("class", "pointer");

let drawing = false;
let clients = {};
let pointers = {};

function drawLine(fromx, fromy, tox, toy) {
  context.moveTo(fromx, fromy);
  context.lineTo(tox, toy);
  context.stroke();
}
function now() {
  return new Date().getTime();
}
let lastEmit = now();
canvas.onmouseup = canvas.onmousemove = canvas.onmousedown = function(e) {
  switch(e.type) {
    case "mouseup":
      drawing = false;
      break;

    case "mousemove":
      if(now() - lastEmit > 50) {
        socket.emit('mousemove', {
          'x' : e.pageX,
          'y' : e.pageY,
          'drawing' : drawing
        });
        lastEmit = now();
      }
      if(drawing) {
        drawLine(prev.x, prev.y, e.pageX, e.pageY);
        prev.x = e.pageX;
        prev.y = e.pageY;
      }
      break;

    case "mousedown":
      drawing = true;
      prev.x = e.pageX;
      prev.y = e.pageY;
      break;

    default: 
      break;
  }
};
```

每当发生绘图动作（`mousedown`和`mousemove`事件的组合），我们会在客户端的机器上绘制请求的线条，然后通过`socket.emit('mousemove', ...)`将这些新坐标广播到我们的`socket.io`服务器，记得传递绘图客户端的`id`值。服务器将通过`socket.broadcast.emit('moving', data)`广播它们，允许客户端监听器在它们的`canvas`元素上绘制等效的线条：

```js
socket.on('moving', data => {
  if (!clients.hasOwnProperty(data.id)) {
    pointers[data.id] = pointerContainer.appendChild(pointer.cloneNode());
  }
  pointers[data.id].style.left = data.x + "px";
  pointers[data.id].style.top = data.y + "px";

  if (data.drawing && clients[data.id]) {
    drawLine(clients[data.id].x, clients[data.id].y, data.x, data.y);
  }
  clients[data.id] = data;
  clients[data.id].updated = now();
});

```

在这个监听器中，如果发送的客户端 ID 以前没有看到过，客户端将建立一个新的客户端指针，并且动画化一条线的绘制和客户端指针，从而在单个客户端视图中创建多个光标绘制不同线条的效果。

回想一下我们在服务器上跟踪的`clientdisconnect`事件，我们还使客户端能够监听这些断开连接，从视图（可视化指针）和我们的`clients`对象中删除丢失客户端的引用：

```js
socket.on("clientdisconnect", id => {
  delete clients[id];
  if (pointers[id]) {
    pointers[id].parentNode.removeChild(pointers[id]);
  }
}); 
```

`socket.io`是一个很好的工具，用于构建交互式的、多用户的环境，需要连续快速的双向数据传输。

现在，让我们来看看`socket.io`的优缺点：

| **优点** | **缺点** |
| --- | --- |
| 对于实时游戏、协作编辑工具和其他应用程序来说，快速的双向通信至关重要 | 允许的持久套接字连接数量可以在服务器端或任何中间位置进行限制 |
| 比标准 HTTP 协议请求的开销更低，降低了在网络上发送数据包的价格 | 许多代理和反向代理都会使套接字实现混乱，导致客户端丢失 |
| 套接字的事件驱动和流式特性在概念上与 Node 架构相吻合——客户端和服务器只是通过一致的接口来回传递数据 | 需要自定义协议服务器，通常需要自定义客户端库 |

另一个有趣的项目是 SockJS，它在许多不同的语言中实现了套接字服务器，包括 Node.js。查看：[`github.com/sockjs/sockjs-node`](https://github.com/sockjs/sockjs-node)。

# 监听服务器发送的事件

SSE 是简单而具体的。它们在大多数数据传输是从服务器到客户端单向进行时使用。传统和类似的概念是*推送*技术。SSE 传递带有简单格式的文本消息。许多类型的应用程序被动地接收简短的状态更新或数据状态更改。SSE 非常适合这些类型的应用程序。

与`WebSocket`一样，SSE 也消除了 AJAX 的冗余交流。与`WebSocket`不同，SSE 连接只关注从服务器向连接的客户端广播数据：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/6e993b38-8ad7-41c4-9e68-b340567b01f2.png)

通过将路径传递给`EventSource`构造函数，客户端连接到支持 SSE 的服务器：

```js
let eventSource = new EventSource('/login'); 
```

`EventSource`的这个实例现在将在从服务器接收到新数据时发出可订阅的数据事件。

# 使用 EventSource API

`EventSource`实例发出可订阅的数据事件，每当从服务器接收到新数据时，就像`Readable`流在 Node 中发出数据事件一样，正如我们在这个示例客户端中所看到的：

```js
<script>
  let eventSource = new EventSource('/login');
  eventSource.addEventListener('message', (broadcast) => {
    console.log("got message: " + broadcast);
  });
  eventSource.addEventListener('open', () => {
    console.log("connection opened");
  });
  eventSource.addEventListener('error', () => {
    console.log("connection error/closed");
  });
 </script> 
```

`EventSource`实例会发出三个默认事件：

+   `open`：当连接成功打开时，将触发此事件

+   `message`：分配给此事件的处理程序将接收一个对象，其`data`属性包含广播消息

+   `error`：每当服务器发生错误，或服务器断开连接或以其他方式与此客户端断开连接时，都会触发此事件

作为标准 HTTP 协议的一部分，响应 SSE 请求的服务器需要进行最少的配置。以下服务器将接受`EventSource`绑定并每秒向绑定的客户端广播当前日期：

```js
const http = require("http");
const url = require("url");
http.createServer((request, response) => {
  let parsedURL = url.parse(request.url, true);
  let pathname = parsedURL.pathname;
  let args = pathname.split("/");
  let method = args[1];
  if (method === "login") {
    response.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive"
    });
    response.write(":" + Array(2049).join(" ") + "\n");
    response.write("retry: 2000\n");
    response.on("close", () => {
      console.log("client disconnected");
    });
    setInterval(() => {
      response.write("data: " + new Date() + "\n\n");
    }, 1000);
    return;
  }
}).listen(8080);
```

该服务器监听请求并选择在路径`/login`上进行的请求，将其解释为对`EventSource`绑定的请求。建立`EventSource`连接只是简单地通过使用`Content-Type`头部为`text/event-stream`来响应请求。此外，我们指示客户端的`Cache-Control`行为应设置为`no-cache`，因为我们期望在此通道上有大量原始材料。

从连接点开始，此客户端的`response`对象将保持一个开放的管道，可以通过`write`发送消息。让我们看看接下来的两行：

```js
response.write(":" + Array(2049).join(" ") + "\n");
response.write("retry: 2000\n");
```

这第一次写入是为了调整一些浏览器中 XHR 实现的特性，最终需要所有 SSE 流都以 2KB 填充为前缀。这个写入操作只需要发生一次，对后续消息没有影响。

SSE 的一个优点是，客户端在连接断开时会自动尝试重新连接服务器。重试的毫秒数将因客户端而异，并且可以使用重试字段进行控制，我们在这里使用它来设置两毫秒的重试间隔。

最后，我们监听客户端的关闭事件，当客户端断开连接时触发，并开始以一秒的间隔广播时间：

```js
setInterval(() => {
  response.write("data: " + new Date() + "\n\n");
 }, 1000);
```

一个网站可能会绑定到这个时间服务器并显示当前的服务器时间：

```js
<html>
 <head>
     <script>
       let ev = new EventSource('/login');
       ev.addEventListener("message", broadcast => {
         document.getElementById("clock").innerHTML = broadcast.data;
       });
     </script>
 </head>
 <body>
     <div id="clock"></div>
 </body>
 </html>
```

因为连接是单向的，任意数量的服务可以很容易地设置为发布者，客户端通过新的`EventSource`实例分别绑定到这些服务。例如，可以通过修改前面的服务器，使其定期发送`process.memoryUsage()`的值，轻松实现服务器监视。作为练习，使用 SSE 重新实现我们在 AJAX 部分中介绍的股票服务。

# EventSource 流协议

一旦服务器建立了客户端连接，它现在可以随时通过这个持久连接发送新消息。这些消息由一个或多个文本行组成，由以下四个字段中的一个或多个分隔：

+   `event`：这是一个事件类型。发送此字段的消息将触发客户端的一般`EventSource`事件处理程序处理任何消息。如果设置为诸如*latestscore*之类的字符串，客户端的`message`处理程序将不会被调用，处理将委托给使用`EventSource.addEventListener('latestscore'…)`绑定的处理程序。

+   `data`：这是要发送的消息。这始终是`String`类型，尽管它可以有用地传输通过`JSON.stringify()`传递的对象。

+   `id`：如果设置，此值将出现为发送的消息对象的`lastEventID`属性。这对于对客户端进行排序、排序和其他操作非常有用。

+   重试：重新连接间隔，以毫秒为单位。

发送消息涉及组成包含相关字段名称并以换行符结尾的字符串。这些都是有效的消息：

```js
response.write("id:" + (++message_counter) + "\n");
response.write("data: I'm a message\n\n");
response.write("retry: 10000\n\n");
response.write("id:" + (++message_counter) + "\n");
response.write("event: stock\n");
response.write("data: " + JSON.stringify({price: 100, change: -2}) + "\n\n");
response.write("event: stock\n");
response.write("data: " + stock.price + "\n");
response.write("data: " + stock.change + "\n");
response.write("data: " + stock.symbol + "\n\n");
response.write("data: Hello World\n\n");
```

我们可以看到也可以设置多个`data`字段。需要注意的一点是在最后一个数据字段之后发送双换行（`"\n\n"`）。之前的字段应该只使用单个换行。

默认的`EventSource`客户端事件（`open`，`message`和`close`）足以对大多数应用程序接口进行建模。服务器发送的所有广播都在唯一的`message`处理程序中捕获，该处理程序负责路由消息或以其他方式更新客户端，就像在使用 JavaScript 处理 DOM 中的事件时工作时事件委托会起作用一样。

在需要许多唯一的消息标识符的情况下，压倒一个单一处理函数可能不是理想的。我们可以使用 SSE 消息的`event`字段来创建自定义事件名称，客户端可以单独绑定，从而整洁地分离关注点。

例如，如果正在广播两个特殊事件`actionA`和`actionB`，我们的服务器将像这样结构化它们：

```js
 event: actionA\n
 data: Message A here\n\n

 event: actionB\n
 data: Message B here\n\n
```

我们的客户端将以正常方式绑定到它们，如下面的代码片段所示：

```js
ev.addEventListener("actionA", (broadcast) => {
  console.log(broadcast.data);
});
ev.addEventListener("actionB", (broadcast) => {
  console.log(broadcast.data);
}); 
```

在单个消息处理函数变得过长或过于复杂的情况下，考虑使用唯一命名的消息和处理程序。

# 提问和获取答案

如果我们想要创建一个与兴趣相关的接口怎么办？让我们构建一个应用程序，使任意数量的人可以提问和/或回答问题。我们的用户将加入社区服务器，看到一个开放问题的列表以及对这些问题的答案，并在添加新问题或答案时实时获取更新。有两个关键活动需要建模：

+   每个客户端必须在另一个客户端提问或发布答案时得到通知。

+   客户端可以提问或提供答案

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/1d168c9c-c488-4c1d-b08b-5f7910f26b61.png)

在一个大量的同时贡献者的大型群体中，最大的变化会发生在哪里？

任何个别的客户端都可以提出几个问题或提供几个答案。客户端还可以选择问题，并查看答案。我们只需要满足少量的客户端到服务器的请求，比如向服务器发送新问题或答案。大部分工作将在满足客户端请求数据（问题的答案列表）和向所有连接的客户端广播应用程序状态更改（添加新问题；给出新答案）方面。在这种协作应用程序中存在的一对多关系意味着单个客户端广播可能会创建与连接的客户端数量相等的服务器广播，从 1 到 10,000 或更多。SSE 在这里非常合适，所以让我们开始吧。

此应用程序的三个主要操作如下：

+   提问

+   回答问题

+   选择问题

这些操作中的任何一个都会改变应用程序的状态。由于这个状态必须在所有客户端上反映出来，我们将在服务器上存储应用程序的状态——所有问题、答案以及客户端与这些数据对象的关系。我们还需要唯一标识每个客户端。通常，人们会使用数据库来持久化其中一些信息，但出于我们的目的，我们将简单地将这些数据存储在我们的 Node 服务器中：

```js
let clients = {};
let clientQMap = {};
let questions = {};
let answers    = {};

function removeClient(id) {
  if(id) {
    delete clients[id];
    delete clientQMap[id];
  }
}
```

除了 `questions` 和 `answers` 存储对象之外，我们还需要存储客户端对象本身——客户端被分配一个唯一的 ID，可以用来查找信息（比如客户端的套接字），当进行广播时使用。

我们只想向对特定问题感兴趣的客户端广播答案数据——因为客户端 UI 只显示单个问题的答案，当然我们不会向客户端不加区分地广播答案。因此，我们保留了一个 `clientQMap` 对象，它将一个问题映射到所有关注该问题的客户端，通过 ID。

`removeClient` 方法很简单：当客户端断开连接时，该方法会从池中删除其数据。稍后我们会再次看到这一点。

有了这个设置，接下来我们需要构建我们的服务器来响应 `/login` 路径，这是由 `EventSource` 用于建立连接的。这个服务负责为客户端配置一个适当的事件流，将这个 `Response` 对象存储起来以备后用，并为用户分配一个唯一标识符，这个标识符将在将来的客户端请求中用于识别客户端并获取该客户端的通信套接字：

```js

 http.createServer((request, response) => {
   let parsedURL = url.parse(request.url, true);
   let pathname = parsedURL.pathname;
   let args = pathname.split("/");
   //  Lose initial null value
   args.shift();
   let method = args.shift();
   let parameter = decodeURIComponent(args[0]);
   let sseUserId = request.headers['_sse_user_id_'];
   if (method === "login") {
     response.writeHead(200, {
       "Content-Type": "text/event-stream",
       "Cache-Control": "no-cache"
   });
   response.write(":" + Array(2049).join(" ") + "\n"); // 2kB
   response.write("retry: 2000\n");
   removeClient(sseUserId);
   // A very simple id system. You'll need something more secure.
   sseUserId = (USER_ID++).toString(36);
   clients[sseUserId] = response;
   broadcast(sseUserId, {
     type : "login",
     userId : sseUserId
   });
   broadcast(sseUserId, {
     type : "questions",
     questions : questions
   });
   response.on("close", () => {
     removeClient(sseUserId);
   });

   // To keep the conn alive we send a "heartbeat" every 10 seconds.
   // https://bugzilla.mozilla.org/show_bug.cgi?id=444328
   setInterval(() => {
     broadcast(sseUserId, new Date().getTime(), "ping");
   }, 10000);
   return;
}).listen(8080);
```

在建立请求参数之后，我们的服务器会检查请求中的 `_sse_user_id_` 头部，这是在初始 `EventSource` 绑定中分配给用户的唯一字符串，位于 `/login` 中：

```js
sseUserId = (USER_ID++).toString(36);
clients[sseUserId] = response;
```

然后通过即时广播将此 ID 发送给客户端，我们利用这个机会发送当前批次的问题：

```js
broadcast(sseUserId, sseUserId, "login");
```

现在客户端负责在进行调用时传递这个 ID。通过监听 `/login` 事件并存储传递的 ID，客户端可以在进行 HTTP 调用时自我识别：

```js
 evSource.addEventListener('login', broadcast => {
   USER_ID = JSON.parse(broadcast.data);
 });
 let xhr = new XMLHttpRequest();
 xhr.open("POST", "/...");
 xhr.setRequestHeader('_sse_user_id_', USER_ID);
 ...
```

请记住，我们刚刚从服务器到客户端创建了一个单向事件流。这个通道用于与客户端通信，而不是 `response.end()` 或类似的方法。在 `/login` 中引用的广播方法完成了广播流事件的任务，如下面的代码所示：

```js
let broadcast = function(toId, msg, eventName) {
  if (toId === "*") {
    for (let p in clients) {
      broadcast(p, msg);
    }
    return;
  }
  let clientSocket = clients[toId];
  if (!clientSocket) {
    return;
  }
  eventName && clientSocket.write(`event: ${eventName}\n`);
  clientSocket.write(`id: ${++UNIQUE_ID}\n`);
  clientSocket.write(`data: ${JSON.stringify(msg)}\n\n`);
 }

```

从下往上扫描这段代码。注意广播的主要目的是获取客户端 ID，查找该客户端的事件流，并向其写入，如果需要，接受自定义事件名称。然而，由于我们将定期向所有连接的客户端广播，我们允许使用特殊的 `*` 标志来指示大规模广播。

现在一切都设置好了，只需要为此应用程序的三个主要操作定义服务：添加新问题和答案，以及记住每个客户端正在关注的问题。

当提出问题时，我们确保问题是唯一的，将其添加到我们的`question`集合中，并告诉所有人新的问题列表：

```js
if (method === "askquestion") {
  // Already asked?
  if (questions[parameter]) {
    return response.end();
  }
  questions[parameter] = sseUserId;    
  broadcast("*", {
    type : "questions",
    questions : questions
  });
  return response.end();
} 
```

处理答案几乎相同，只是这里我们只想将新答案广播给询问正确问题的客户端：

```js
if (method === "addanswer") {
     ...
  answers[curUserQuestion] = answers[curUserQuestion] || [];
  answers[curUserQuestion].push(parameter);
  for (var id in clientQMap) {
    if (clientQMap[id] === curUserQuestion) {
      broadcast(id, {
        type : "answers",
        question : curUserQuestion,
        answers : answers[curUserQuestion]
      });
    }
  }
  return response.end();
}
```

最后，通过更新`clientQMap`来存储客户端兴趣的更改：

```js
if (method === "selectquestion") {
  if (parameter && questions[parameter]) {
    clientQMap[sseUserId] = parameter;
    broadcast(sseUserId, {
      type : "answers",
      question : parameter,
      answers : answers[parameter] ? answers[parameter] : []
    });
  }
   return response.end();
}
```

虽然我们不会深入讨论客户端 HTML 和 JavaScript，但我们将看看如何处理一些核心事件。

假设 UI 以 HTML 呈现，一侧列出答案，另一侧列出问题，包含用于添加新问题和答案的表单，以及用于选择要跟随的问题的表单，我们的客户端代码非常轻量且易于跟踪。在与服务器进行初始`/login`握手后，此客户端只需通过 HTTP 发送新数据即可。服务器响应的处理被整洁地封装成三个事件，使得事件流处理变得易于跟踪：

```js
 let USER_ID = null;
 let evSource = new EventSource('/login');
 let answerContainer = document.getElementById('answers');
 let questionContainer = document.getElementById('questions');

 let showAnswer = (answers) => {
   answerContainer.innerHTML = "";
   let x = 0;
   for (; x < answers.length; x++) {
     let li = document.createElement('li');
     li.appendChild(document.createTextNode(answers[x]));
     answerContainer.appendChild(li);
   }
 }

 let showQuestion = (questions) => {
   questionContainer.innerHTML = "";
   for (let q in questions) {
     //... show questions, similar to #showAnswer
   }
 }

 evSource.addEventListener('message', (broadcast) => {
   let data = JSON.parse(broadcast.data);
   switch (data.type) {
     case "questions":
       showQuestion(data.questions);
     break;
     case "answers":
       showAnswer(data.answers);
     break;
     case "notification":
       alert(data.message);
     break;
     default:
       throw "Received unknown message type";
     break;
   }
 });

 evSource.addEventListener('login', (broadcast) => {
   USER_ID = JSON.parse(broadcast.data);
 });

```

此界面只需等待新的问题和答案数据，并在列表中显示它。三个回调足以使此客户端保持最新状态，无论有多少不同的客户端更新应用程序的状态。

| **优点** | **缺点** |
| --- | --- |
| 轻量级：通过使用原生 HTTP 协议，可以使用几个简单的标头创建 SSE 服务器 | 不一致的浏览器支持需要为客户端到服务器通信创建自定义库，不支持的浏览器通常会进行长轮询 |
| 能够单方面向客户端发送数据，而无需匹配客户端调用 | 单向：不适用于需要双向通信的情况 |
| 自动重新连接断开的连接，使 SSE 成为可靠的网络绑定 | 服务器必须每隔大约 10 秒发送“心跳”以保持连接活动 |
| 简单，易于定制，易于理解的消息格式 |  |

`EventSource`不受所有浏览器支持（特别是 IE）。可以在以下网址找到 SSE 的出色仿真库：[`github.com/Yaffle/EventSource`](https://github.com/Yaffle/EventSource)。

# 构建协同文档编辑应用程序

现在我们已经研究了构建协同应用程序时要考虑的各种技术，让我们使用**操作转换**（**OT**）来组合一个协同代码编辑器。

在这里，OT 将被理解为一种允许许多人同时编辑同一文档的技术——协同文档编辑。Google 以以下方式描述了他们（现已关闭的）Wave 项目：

正如[`svn.apache.org/repos/asf/incubator/wave/whitepapers/operational-transform/operational-transform.html`](https://svn.apache.org/repos/asf/incubator/wave/whitepapers/operational-transform/operational-transform.html)所说，“协同文档编辑意味着多个编辑者能够同时编辑共享文档。当用户可以逐个按键地看到另一个人所做的更改时，它是实时和并发的。Google Wave 提供了富文本文档的实时并发编辑。”。

参与 Wave 项目的工程师之一是 Joseph Gentle，Gentle 先生很友好地编写了一个模块，将 OT 技术带到了 Node 社区，命名为**ShareJS**，后来成为了**ShareDB**，Derby web 框架的 OT 后端（[`derbyjs.com/`](http://derbyjs.com/)）。我们将使用此模块创建一个允许任何人创建新的协同编辑文档的应用程序。

此示例大量借鉴了 ShareDB GitHub 存储库中包含的许多示例。要深入了解 ShareDB 的可能性，请访问：[`github.com/share/sharedb`](https://github.com/share/sharedb)。

首先，我们需要一个代码编辑器来绑定我们的 OT 层。对于这个项目，我们将使用优秀的 Quill 编辑器，可以从以下地址克隆：[`github.com/quilljs/quill`](https://github.com/quilljs/quill)。Quill 特别适用于与 ShareDB 一起使用，因为它被设计为将文档表示为 JSON 中的一系列变更集（[`github.com/ottypes/rich-text`](https://github.com/ottypes/rich-text)），这些变更集可以映射到 ShareDB 理解的 OT 类型。虽然超出了本节的范围，但读者可能会对 OT 如何工作，特别是这两个库如何工作感兴趣。

作为一个协作的实时应用程序，我们将使用**ws**套接字服务器来管理客户端和数据库之间的通信，并使用**Express**来管理提供静态文件，如`index.html`。

在本章的代码捆绑包中，将会有一个 sharedb 文件夹。要安装并尝试它，请运行以下命令：

```js
npm i
npm run build
npm start
// Now navigate to localhost:8080 and start editing.
// Open another browser to localhost:8080 to see collaboration in action!
```

主要文件将是`client.js`和`server.js`。将使用**Browserify**捆绑`client.js`文件，生成客户端将使用的 JavaScript。让我们看看`client.js`文件：

```js
const sharedb = require('sharedb/lib/client');
const richText = require('rich-text');
const Quill = require('quill');

sharedb.types.register(richText.type);

const socket = new WebSocket('ws://' + window.location.host);
const connection = new sharedb.Connection(socket);

window.disconnect = () => connection.close();
window.connect = () => connection.bindToSocket(new WebSocket('ws://' + window.location.host));

// 0: Name of collection
// 1: ID of document
let doc = connection.get('examples', 'richtext');

doc.subscribe(err => {
  if(err) {
    throw err;
  }
  let quill = new Quill('#editor', {
    theme: 'snow'
  });
  quill.setContents(doc.data);
  // ... explained below
});
```

该文件的标题只是实例化了 ShareDB，将其文档类型设置为`rich-text`，并为实例提供了与服务器的通信套接字。为了演示的目的，我们将在单个集合`examples`和一个文件`richtext`上操作。这种集合/文档配对是您在 ShareDB 中处理文档的方式，并且很快将在我们即将看到的`server.js`文件中反映出来。在更高级的实现中，您可能需要创建某种集合/文档管理层，将这些集合链接到特定用户，添加用户帐户、权限等。

一旦我们订阅了服务器，我们就将一个新的 Quill 实例绑定到`#editor`元素，将其内容（`quill.setContents`）设置为服务器返回的当前文档，并声明我们想要使用`snow`主题，其 css 已包含在`index.html`中：

```js
<!DOCTYPE html>
<html lang="en">
<head>
  ...
  <link href="quill.snow.css" rel="stylesheet">
</head>
<body>
  <div id="editor"></div>
  <script src="img/bundle.js"></script>
</body>
</html>
```

剩下的就是创建将 OT 功能暴露给客户端的 Node 服务器。为此，我们需要接受来自服务器的 OT 更改（增量）并将这些更改应用到 Quill 编辑器，并在用户使用 Quill 编辑器时向服务器报告更改：

```js
doc.subscribe(err => {
  ...
  quill.setContents(doc.data);
  quill.on('text-change', (delta, oldDelta, source) => {
   ...
   doc.submitOp(delta, {
     source: quill
   });
  });
  doc.on('op', (op, source) => {
    ...
    quill.updateContents(op);
  });
}
```

我们现在已经设置好了，每当 Quill 编辑器中有`text-change`时，我们将更新文档数据库，并在共享文档上有新的`op`时，我们将`updateContents`到任何连接的客户端编辑器。

服务器实现在很大程度上反映了客户端实现：

```js
const http = require('http');
const express = require('express');
const ShareDB = require('sharedb');
const richText = require('rich-text');
const WebSocket = require('ws');
const WebSocketJSONStream = require('websocket-json-stream');

ShareDB.types.register(richText.type);

const app = express();
app.use(express.static('static'));
app.use(express.static('node_modules/quill/dist'));

const backend = new ShareDB();
const connection = backend.connect();

// 0: Name of collection
// 1: ID of document
let doc = connection.get('examples', 'richtext');

doc.fetch(err => {
  if (err) {
    throw err;
  }
  if (doc.type === null) {
    return doc.create([
      {insert: 'Say Something!'}
    ], 'rich-text', startServer);
  }
  startServer();
});

function startServer() {
  const server = http.createServer(app);
  const wss = new WebSocket.Server({server: server});
  wss.on('connection', (ws, req) => {
    backend.listen(new WebSocketJSONStream(ws));
  });
  server.listen(8080, () => console.log('Editor now live on http://localhost:8080'));
}
```

我们需要所有的库，注意 websocket-json-stream 的要求，这是一个在套接字上创建 JSON 对象流的库，需要表示我们将使用的 JSON 变更集。

然后，我们建立客户端期望的集合/文档设置，如果文档不存在，则使用一些虚拟文本“说点什么！”创建文档。唯一剩下的事情就是将 ShareDB 后端绑定到这个双向 JSON 对象流：

```js
backend.listen(new WebSocketJSONStream(ws))
```

该服务器现在可以用于在所有请求具有相同名称的文档的客户端之间共享文档状态，从而促进协作编辑。

# 总结

在本章中，我们已经讨论了构建实时应用程序时使用的三种主要策略：AJAX、WebSocket 和 SSE。我们已经展示了使用 Node 可以用非常少的代码开发复杂的协作应用程序。我们还看到了一些策略如何使客户端/服务器通信建模为事件数据流接口。我们考虑了这些各种技术的优缺点，并且通过一些清晰的示例介绍了每种技术的最佳使用场景。

此外，我们已经展示了如何在 Node 服务器中构建和管理客户端标识符和状态数据，以便状态更改可以安全地封装在一个中心位置，并安全可靠地广播到许多连接的客户端。通过使用操作转换，展示了与 Node 社区开发的模块的质量，我们创建了一个协作代码编辑系统。

在下一章中，我们将学习如何协调多个同时运行的 Node 进程的努力。通过示例，我们将学习如何使用 Node 实现并行处理，从生成运行 Unix 程序的许多子进程到创建负载均衡 Node 套接字服务器集群。


# 第七章：使用多个进程

“现在很遗憾的是，现在几乎没有多余的信息。”

– 奥斯卡·王尔德

对于目睹着越来越多的应用程序产生的数据量急剧增加的人来说，I/O 效率的重要性是不言而喻的。用户生成的内容（博客、视频、推文和帖子）正在成为互联网内容的主要类型，这一趋势与社交软件的兴起同步进行，其中对内容之间的交集进行映射产生了另一层数据的指数级增长。

一些数据储存库，如谷歌、Facebook 和其他数百家公司，通过 API 向公众公开其数据，通常是免费的。这些网络每个都收集了令人惊讶的内容、观点、关系等大量数据，这些数据还通过市场研究和各种类型的流量和使用分析进一步增加。这些 API 大多是双向的，既收集并储存成员上传的数据，又提供这些数据。

Node 已经在这一数据扩张期间到来。在本章中，我们将探讨 Node 如何满足对大量数据进行排序、合并、搜索和其他操作的需求。调整软件，使其能够安全、廉价地处理大量数据，在构建快速和可扩展的网络应用程序时至关重要。

我们将在下一章中处理特定的扩展问题。在本章中，我们将研究在设计多个 Node 进程共同处理大量数据的系统时的一些最佳实践。

作为讨论的一部分，我们将研究在构建数据密集型应用程序时的并行策略，重点是如何利用多个 CPU 环境、使用多个工作进程，并利用操作系统本身来实现并行性的效率。通过示例来演示如何将这些独立而高效的处理单元组装成应用程序的过程。 

如第五章*中所述，管理许多同时的客户端连接*，并发性并不等同于并行性。并发的目标是为程序提供良好的结构，简化模拟处理多个同时进行的进程所固有的复杂性。并行性的目标是通过将任务或计算的部分分配给多个工作进程来提高应用程序的性能。值得回顾的是*Clinger*对“…数十、数百甚至数千个独立微处理器，每个都有自己的本地内存和通信处理器，通过高性能通信网络进行通信”的愿景。

我们已经讨论了 Node 如何帮助我们理解非确定性控制流。让我们还记得 Node 的设计者遵循**模块化规则**，鼓励我们编写简单的部分，并通过清晰的接口连接起来。这条规则导致了对简单的网络化进程的偏好，这些进程使用共同的协议进行通信。相关的规则是**简单规则**，如下所述：

正如[`en.wikipedia.org/wiki/Unix_philosophy`](https://en.wikipedia.org/wiki/Unix_philosophy)所说，“开发人员应该通过寻找将程序系统分解为小而简单的协作部分的方法来设计简单。这条规则旨在阻止开发人员对编写“错综复杂且美丽的复杂性”产生情感，而这些实际上是容易出错的程序。”

在我们继续阅读本章内容时，记住这条规则是很好的。为了控制不断增长的数据量，我们可以构建庞大、复杂和强大的单体，希望它们能够保持足够的规模和强大。或者，我们可以构建小而有用的处理单元，可以组合成任意大小的单一处理团队，就像超级计算机可以由成千上万甚至数百万台廉价的处理器构建而成一样。

在阅读本章时，进程查看器将非常有用。Unix 系统的一个很好的工具是**htop**，可以从以下网址下载：[`hisham.hm/htop/`](http://hisham.hm/htop/)。该工具提供了 CPU 和内存使用情况的视图；在这里，我们可以看到负载是如何分布在所有八个核心上的：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/54113a36-c425-40c0-9f3f-dd1e012b09af.png)

让我们开始研究线程和进程。

# Node 的单线程模型

Node 环境的整体展示了多线程并行性的效率和适用于具有高并发性特征的应用程序的表达语法。使用 Node 不会限制开发人员、开发人员对系统资源的访问，或者开发人员可能想要构建的应用程序类型。

然而，令人惊讶的是，对 Node 的许多持久批评都是基于这种误解。正如我们将看到的，认为 Node 不是多线程的，因此慢，或者还没有准备好投入使用，简单地错过了重点。JavaScript 是单线程的；Node 堆栈不是。JavaScript 代表了用于协调执行多个多线程 C++进程的语言，甚至是您开发人员创建的定制 C++附加组件。Node 提供 JavaScript，通过 V8 运行，主要作为建模并发的工具。此外，您可以仅使用 JavaScript 编写整个应用程序，这只是该平台的另一个好处。您不必一直使用 JavaScript-如果您选择，可以在 C++中编写大部分应用程序。

在本章中，我们将尝试解决这些误解，为使用 Node 进行乐观开发铺平道路。特别是，我们将研究跨核心、进程和线程分配工作的技术。目前，本节将尝试澄清单个线程的能力有多大（提示：通常您所需要的就是这个）。

# 单线程编程的好处

很难找到任何数量可观的专业软件工程师愿意否认多线程软件开发是痛苦的。然而，为什么做得好这么难呢？

并不是说多线程编程本身很困难-困难在于线程同步的复杂性。使用线程模型构建高并发性非常困难，特别是在状态共享的模型中。一旦应用程序超出最基本的形状，几乎不可能预料到一个线程中的操作可能如何影响其他所有线程。纠缠和冲突迅速增加，有时会破坏共享内存，有时会创建几乎不可能追踪的错误。

Node 的设计者选择认识到线程的速度和并行化优势，而不要求开发人员也这样做。特别是，Node 的设计者希望免除开发人员管理伴随线程系统的困难。

+   共享内存和锁定行为导致系统在复杂性增加时变得非常难以理解。

+   任务之间的通信需要实现各种同步原语，如互斥锁和信号量、条件变量等。一个本来就具有挑战性的环境需要高度复杂的工具，扩展了完成甚至相对简单系统所需的专业知识水平。

+   这些系统中常见的竞争条件和死锁是常见的陷阱。在共享程序空间内同时进行读写操作会导致顺序问题，两个线程可能会不可预测地*竞争*影响状态、事件或其他关键系统特征的权利。

+   由于在线程之间和它们的状态之间保持可靠的边界是如此困难，确保一个库（对于 Node 来说是一个*模块*）是线程安全的需要大量的开发人员时间。我能知道这个库不会破坏我的应用的某个部分吗？保证线程安全需要库开发人员的极大细心，而这些保证可能是有条件的；例如，一个库在读取时可能是线程安全的，但在写入时可能不是。

单线程的主要论点是，在并发环境中控制流是困难的，特别是当内存访问或代码执行顺序是不可预测的时候：

+   开发人员不再需要关注任意锁定和其他冲突，可以专注于构建可预测顺序的执行链。

+   由于并行化是通过使用多个进程完成的，每个进程都有一个独立和不同的内存空间，进程之间的通信保持简单——通过简单性原则，我们不仅实现了简单和无错的组件，还实现了更容易的互操作性。

+   由于状态不会（任意地）在单个 Node 进程之间共享；单个进程会自动受到保护，不会受到其他进程对内存重新分配或资源垄断的意外访问。通信是通过清晰的通道和基本协议进行的，所有这些都使得编写跨进程进行不可预测更改的程序变得非常困难。

+   线程安全是开发人员不再需要浪费时间担心的一个问题。由于单线程并发消除了多线程并发中存在的冲突，开发可以更快地进行，更加稳固。在下图中，我们可以看到左侧如何跨线程共享状态需要细心管理以防止冲突，而右侧的“无共享”架构避免了冲突和阻塞动作：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/3da79fcb-5688-4fe0-bb98-5a24cd07bf7b.png)

由事件循环高效管理的单个线程为 Node 程序带来了稳定性、可维护性、可读性和韧性。重要的消息是，Node 继续向开发人员提供多线程的速度和能力——Node 设计的精华使得这种能力变得透明，反映了 Node 既定目标的一部分，即为最多的人带来最大的力量，而最少的困难。

在下图中，展示了两种单线程模型和多线程模型之间的差异：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/39063bd4-4b00-4411-b0ae-c614baa4aa91.png)

没有逃脱阻塞操作的可能性——例如，从文件中读取始终需要一些时间。单线程同步模型迫使每个任务在开始之前等待其他任务完成，消耗更多时间。使用线程可以并行启动多个任务，甚至在不同的时间，总执行时间不会超过最长运行线程所需的时间。当使用线程时，开发人员需要负责同步每个单独线程的活动，使用锁定或其他调度工具。当线程数量增加时，这可能变得非常复杂，而在这种复杂性中存在非常微妙和难以发现的错误。

与其让开发人员为这种复杂性而苦苦挣扎，Node 本身管理 I/O 线程。您无需微观管理 I/O 线程；只需设计一个应用程序来建立数据可用性点（回调），以及一旦该数据可用就执行的指令。线程在底层提供了相同的效率，但它们的管理通过一个易于理解的接口暴露给开发人员。

# 多线程已经是本地和透明的

Node 的 I/O 线程池在操作系统范围内执行，并且其工作分布在核心之间（就像操作系统安排的任何其他作业一样）。当您运行 Node 时，您已经利用了其多线程执行。

在即将讨论的子进程和集群模块中，我们将看到这种并行性的实现。我们将看到 Node 并没有被剥夺操作系统的全部功能。

正如我们之前所看到的，在讨论 Node 的核心架构时，执行 JavaScript 程序的 V8 线程绑定到`libuv`，后者作为主要的系统级 I/O 事件分发器。在这种情况下，`libuv`处理由相关 JavaScript 进程或模块命令请求的定时器、文件系统调用、网络调用和其他 I/O 操作，例如`fs.readFile`和`http.createServer`。因此，主 V8 事件循环最好被理解为一个控制流编程接口，由高效的、多线程的系统代理`libuv`支持和驱动。

*Bert Belder*，Node 的核心贡献者之一，也是`libuv`的核心贡献者之一。事实上，Node 的发展引发了`libuv`开发的同时增加，这种反馈循环只会提高这两个项目的速度和稳定性。它已经合并并取代了形成 Node 原始核心的`libeo`和`libev`库。

考虑雷蒙德的另一条规则，**分离原则**：“分离策略和机制；分离接口和引擎。”驱动 Node 的异步、事件驱动编程风格的引擎是`libuv`；该引擎的接口是 V8 的 JavaScript 运行时。继续看雷蒙德的话：

"实现这种分离的一种方法是，例如，将您的应用程序编写为由嵌入式脚本语言驱动的 C 服务例程库，其中控制流程由脚本语言而不是 C 编写。"

在单个可预测线程的抽象中编排超高效的并行操作系统进程的能力是有意设计的，而不是妥协。

它总结了应用程序开发过程如何改进的务实分析，绝对不是对可能性的限制。

libuv 的详细拆包可以在以下网址找到：[`github.com/nikhilm/uvbook`](https://github.com/nikhilm/uvbook)。**Burt Belder**也在以下网址深入讲解了 libuv 和 Node 在内部是如何工作的：[`www.youtube.com/watch?v=PNa9OMajw9w`](https://www.youtube.com/watch?v=PNa9OMajw9w)。

# 创建子进程

软件开发不再是单片程序的领域。在网络上运行的应用程序不能放弃互操作性。现代应用程序是分布式和解耦的。我们现在构建连接用户与分布在互联网上的资源的应用程序。许多用户同时访问共享资源。如果整个复杂系统被理解为解决一个或几个明确定义的相关问题的程序接口的集合，那么这样的系统更容易理解。在这样的系统中，预期（并且是可取的）进程不会空闲。

Node 的早期批评是它没有多核意识，也就是说，如果 Node 服务器在具有多个核心的机器上运行，它将无法利用这种额外的计算能力。在这个看似合理的批评中隐藏着一种基于草人的不公正偏见：一个程序如果无法显式分配内存和执行*线程*以实现并行化，就无法处理企业级问题。

这种批评是持久的。这也是不正确的。

虽然单个 Node 进程在单个核心上运行，但可以通过`child_process`模块生成任意数量的 Node 进程。该模块的基本用法很简单：我们获取一个`ChildProcess`对象并监听数据事件。此示例将调用 Unix 命令`ls`，列出当前目录：

```js
const spawn = require('child_process').spawn;
let ls = spawn('ls', ['-lh', '.']);
ls.stdout.on('readable', function() {
    let d = this.read();
    d && console.log(d.toString());
});
ls.on('close', code => {
    console.log(`child process exited with code: ${code}`);
});
```

在这里，我们生成了`ls`进程（列出目录），并从生成的`readable`流中读取，接收到类似以下内容：

```js
-rw-r--r-- 1 root root 43 Jul 9 19:44 index.html
 -rw-rw-r-- 1 root root 278 Jul 15 16:36 child_example.js
 -rw-r--r-- 1 root root 1.2K Jul 14 19:08 server.js
 child process exited with code 0
```

可以以这种方式生成任意数量的子进程。这里需要注意的是，当生成子进程或以其他方式创建子进程时，操作系统本身会将该进程的责任分配给特定的 CPU。Node 不负责操作系统分配资源的方式。结果是，在具有八个核心的机器上，生成八个进程很可能会导致每个进程分配到独立的处理器。换句话说，操作系统会自动将子进程跨 CPU 分配，这证明了 Node 可以充分利用多核环境的说法是错误的。

每个新的 Node 进程（子进程）分配了 10MB 的内存，并表示一个至少需要 30 毫秒启动的新 V8 实例。虽然您不太可能生成成千上万个这样的进程，但了解如何查询和设置用户创建进程的操作系统限制是有益的；htop 或 top 将报告当前运行的进程数量，或者您可以在命令行中使用`ps aux | wc –l`。`ulimit` Unix 命令（[`ss64.com/bash/ulimit.html`](https://ss64.com/bash/ulimit.html)）提供了有关操作系统上用户限制的重要信息。通过传递`ulimit`，-u 参数将显示可以生成的最大用户进程数。通过将其作为参数传递来更改限制：`ulimit –u 8192`。

`child_process`模块表示一个公开四个主要方法的类：`spawn`、`fork`、`exec`和`execFile`。这些方法返回一个扩展了`EventEmitter`的`ChildProcess`对象，公开了一个用于管理子进程的接口和一些有用的函数。我们将看一下它的主要方法，然后讨论常见的`ChildProcess`接口。

# 生成进程

这个强大的命令允许 Node 程序启动并与通过系统命令生成的进程进行交互。在前面的示例中，我们使用 spawn 调用了一个本机操作系统进程`ls`，并传递了`lh`和`.`参数给该命令。通过这种方式，任何进程都可以像通过命令行启动一样启动。该方法接受三个参数：

+   **命令**：要由操作系统 shell 执行的命令

+   **参数（可选）**：这些是作为数组发送的命令行参数

+   **选项**：用于`spawn`的可选设置映射

`spawn`的选项允许仔细定制其行为：

+   `cwd`（字符串）：默认情况下，命令将理解其当前工作目录与调用 spawn 的 Node 进程相同。使用此指令更改该设置。

+   `env`（对象）：用于将环境变量传递给子进程。例如，考虑使用环境对象生成子进程，如下所示：

```js
{
  name: "Sandro",
  role: "admin"
}
```

子进程环境将可以访问这些值：

+   `detached`（布尔值）：当父进程生成子进程时，两个进程形成一个组，父进程通常是该组的领导者。使用`detached`可以使子进程成为组的领导者。这将允许子进程在父进程退出后继续运行。这是因为父进程默认会等待子进程退出。您可以调用`child.unref()`告诉父进程的事件循环不应计算子引用，并在没有其他工作存在时退出。

+   `uid`（数字）：设置子进程的`uid`（用户标识）指令，以标准系统权限的形式，例如具有子进程执行权限的 UID。

+   gid（数字）：为子进程设置`gid`（组标识）指令，以标准系统权限的形式，例如具有对子进程执行权限的 GID。

+   stdio（字符串或数组）：子进程具有文件描述符，前三个是`process.stdin`，`process.stdout`和`process.stderr`标准 I/O 描述符，按顺序（fds = 0,1,2）。此指令允许重新定义、继承这些描述符等。

考虑以下子进程程序的输出：

```js
process.stdout.write(Buffer.from("Hello!"));
```

在这里，父进程将监听`child.stdout`。相反，如果我们希望子进程继承其父进程的`stdio`，这样当子进程写入`process.stdout`时，发出的内容会通过管道传输到父进程的`process.stdout`，我们将传递相关的父进程文件描述符给子进程，覆盖其自己的文件描述符：

```js
spawn("node", ['./reader.js', './afile.txt'], {
  stdio: [process.stdin, process.stdout, process.stderr]
});
```

在这种情况下，子进程的输出将直接传输到父进程的标准输出通道。此外，有关此类模式的更多信息，请参见 fork 如下。

三个（或更多）文件描述符可以取六个值中的一个：

+   管道：这在子进程和父进程之间创建了一个管道。由于前三个子文件描述符已经暴露给了父进程（`child.stdin`，`child.stdout`和`child.stderr`），这只在更复杂的子实现中是必要的。

+   ipc：这在子进程和父进程之间创建了一个 IPC 通道，用于传递消息。子进程可能有一个 IPC 文件描述符。一旦建立了这种连接，父进程可以通过`child.send`与子进程通信。如果子进程通过此文件描述符发送 JSON 消息，则可以使用`child.on("message")`捕获这些消息。如果作为子进程运行 Node 程序，可能更好的选择是使用`ChildProcess.fork`，它内置了这个消息通道。

+   ignore：文件描述符 0-2 将附加到`/dev/null`。对于其他文件描述符，将不会在子进程上设置引用的文件描述符。

+   流对象：这允许父进程与子进程共享流。为了演示目的，假设有一个子进程，它将相同的内容写入任何提供的`WritableStream`，我们可以这样做：

```js
let writer = fs.createWriteStream('./a.out');
writer.on('open', () => {
  let cp = spawn("node", ['./reader.js'], {
    stdio: [null, writer, null]
  });
});
```

子进程现在将获取其内容并将其传输到已发送的任何输出流：

```js
fs.createReadStream('cached.data').pipe(process.stdout);
```

+   整数：文件描述符 ID。

+   null 和 undefined：这些是默认值。对于文件描述符 0-2（`stdin`，`stdout`和`stderr`），将创建一个管道；其他默认为`ignore`。

除了将`stdio`设置作为数组传递之外，还可以将某些常见的分组传递

通过传递以下这些快捷字符串值之一来实现：

+   `'ignore' = ['ignore', 'ignore', 'ignore']`

+   `'pipe' = ['pipe', 'pipe', 'pipe']`

+   `'inherit' = [process.stdin, process.stdout, process.stderr]`

+   `[0,1,2]`

我们已经展示了使用`spawn`来运行 Node 程序作为子进程的一些示例。虽然这是一个完全有效的用法（也是尝试 API 选项的好方法），但`spawn`主要用于运行系统命令。有关将 Node 进程作为子进程运行的更多信息，请参阅 fork 的讨论如下。

应该注意的是，生成任何系统进程的能力意味着可以使用 Node 来运行安装在操作系统上的其他应用程序环境。如果安装了流行的 PHP 语言，就可以实现以下功能：

```js
const spawn = require('child_process').spawn;
let php = spawn("php", ['-r', 'print "Hello from PHP!";']);
php.stdout.on('readable', () => {
  let d;
  while (d = this.read()) {
    console.log(d.toString());
  }
});
// Hello from PHP!
```

运行一个更有趣、更大的程序同样容易。

除了通过这种技术异步地运行 Java 或 Ruby 或其他程序，我们还对 Node 的一个持久的批评有了一个很好的回答：JavaScript 在处理数字或执行其他 CPU 密集型任务方面不如其他语言快。这是真的，从这个意义上说，Node 主要针对 I/O 效率进行了优化，并帮助管理高并发应用程序，并且 JavaScript 是一种解释性语言，没有专注于重型计算。

然而，使用`spawn`，可以很容易地将大量计算和长时间运行的例程传递给其他环境中的独立进程，例如分析引擎或计算引擎。当这些操作完成时，Node 的简单事件循环将确保通知主应用程序，无缝地集成产生的数据。与此同时，主应用程序可以继续为客户端提供服务。

# 分叉进程

与`spawn`一样，`fork`启动一个子进程，但设计用于运行 Node 程序，并具有内置的通信通道的额外好处。与将系统命令作为其第一个参数传递给`fork`不同，可以将路径传递给 Node 程序。与`spawn`一样，命令行选项可以作为第二个参数发送，并在分叉的子进程中通过`process.argv`访问。

可选的选项对象可以作为第三个参数传递，具有以下参数：

+   `cwd`（字符串）：默认情况下，命令将理解其当前工作目录与调用`fork`的 Node 进程的相同。使用此指令更改该设置。

+   `env`（对象）：这用于将环境变量传递给子进程。参考 spawn。

+   `encoding`（字符串）：这设置了通信通道的编码。

+   `execPath`（字符串）：这是用于创建子进程的可执行文件。

+   `silent`（布尔值）：默认情况下，fork 的子进程将与父进程关联（例如，`child.stdout`与`parent.stdout`相同）。将此选项设置为 true 将禁用此行为。

`fork`和`spawn`之间的一个重要区别是，前者的子进程在完成时不会自动退出。这样的子进程在完成时必须显式退出，可以通过`process.exit()`轻松实现。

在下面的例子中，我们创建一个子进程，每十分之一秒发出一个递增的数字，然后父进程将其转储到系统控制台。首先，让我们看看子程序：

```js
let cnt = 0;
setInterval(() => {
  process.stdout.write(" -> " + cnt++);
}, 100);
```

同样，这将简单地写入一个不断增加的数字。记住，使用`fork`，子进程将继承其父进程的`stdio`，我们只需要创建子进程即可在运行父进程的终端中获得输出：

```js
var fork = require('child_process').fork;
fork('./emitter.js');
// -> 0 -> 1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> 8 -> 9 -> 10 ...
```

这里可以演示静默选项；`fork('./emitter.js', [], { silent: true });`关闭了对终端的任何输出。

创建多个并行进程很容易。让我们增加创建的子进程数量：

```js
fork('./emitter.js');
fork('./emitter.js');
fork('./emitter.js');
// 0 -> 0 -> 0 -> 1 -> 1 -> 1 -> 2 -> 2 -> 2 -> 3 -> 3 -> 3 -> 4 ...
```

到这一点应该很清楚，通过使用`fork`，我们正在创建许多并行执行上下文，分布在所有机器核心上。

这足够简单，但内置的`fork`通信通道使得与分叉子进程的通信变得更加容易和清晰。考虑以下文件，它生成一个子进程并与其通信：

```js
// parent.js
const fork = require('child_process').fork;
let cp = fork('./child.js');
cp.on('message', msgobj => {
    console.log(`Parent got message: ${msgobj.text}`);
});
cp.send({
    text: 'I love you'
});
```

我们看到现在有一个通信通道可用，通过它父进程可以发送消息，同时也可以接收来自子进程的消息，如下所示：

```js
// child.js
process.on('message', msgobj => {
    console.log('Child got message:', msgobj.text);
    process.send({
        text: `${msgobj.text} too`
    });
});
```

通过执行父脚本，我们将在控制台中看到以下内容：

```js
Child got message: I love you
Parent got message: I love you too
```

我们将很快深入探讨这个重要的跨进程通信概念。

# 缓冲进程输出

在某些情况下，子进程的完整缓冲输出足够，无需通过事件管理数据，`child_process`提供了`exec`方法。该方法接受三个参数：

+   **command：**命令行字符串。与`spawn`和`fork`不同，它通过数组将参数传递给命令，这个第一个参数接受一个完整的命令字符串，例如`ps aux | grep node`。

+   **选项：**这是一个可选参数：

+   `cwd`（字符串）：这设置了命令进程的工作目录。

+   `env`（对象）：这是一个键值对的映射，将被暴露给子进程。

+   `encoding`（字符串）：这是子进程数据流的编码。默认值为`'utf8'`。

+   `timeout`（数字）：这指定等待进程完成的毫秒数，此时子进程将收到`killSignal.maxBuffer`值。

+   `killSignal.maxBuffer`（数字）：这是`stdout`或`stderr`上允许的最大字节数。当超过这个数字时，进程将被杀死。默认为 200 KB。

+   `killSignal`（字符串）：在超时后，子进程接收到此信号。默认为`SIGTERM`。

+   **回调**：这个接收三个参数：一个`Error`对象（如果有的话），`stdout`（包含结果的`Buffer`对象），`stderr`（包含错误数据的`Buffer`对象，如果有的话）。如果进程被杀死，`Error.signal`将包含杀死信号。

当您想要`exec`的缓冲行为，但是针对的是一个 Node 文件时，请使用`execFile`。重要的是，`execFile`不会生成一个新的子 shell，这使得它的运行成本稍微降低。

# 与您的子进程通信

所有`ChildProcess`对象的实例都扩展了`EventEmitter`，公开了用于管理子数据连接的有用事件。此外，`ChildProcess`对象公开了一些有用的方法，用于直接与子进程交互。现在让我们来看一下这些方法，首先是属性和方法：

+   `child.connected`: 当子进程通过`child.disconnect()`与其父进程断开连接时，此标志将设置为`false`。

+   `child.stdin`: 这是一个对应于子进程标准输入的`WritableStream`。

+   `child.stdout`: 这是一个对应于子进程标准输出的`ReadableStream`。

+   `child.stderr`: 这是一个对应于子进程标准错误的`ReadableStream`。

+   `child.pid`: 这是一个整数，表示分配给子进程的进程 ID（PID）。

+   `child.kill`: 尝试终止子进程，发送一个可选的信号。如果未指定信号，则默认为`SIGTERM`（有关信号的更多信息，请访问：[`en.wikipedia.org/wiki/Signal_(IPC)`](https://en.wikipedia.org/wiki/Signal_(IPC))）。虽然方法名称听起来是终端的，但不能保证杀死进程 - 它只是向进程发送一个信号。危险的是，如果尝试对已经退出的进程进行`kill`，则可能会导致新分配了死进程的 PID 的另一个进程接收到信号，后果不可预测。此方法应该触发`close`事件，该事件用于关闭进程的信号。

+   `child.disconnect()`: 此命令断开子进程与其父进程之间的 IPC 连接。然后，子进程将会优雅地死去，因为它没有 IPC 通道来保持其存活。您也可以在子进程内部调用`process.disconnect()`。一旦子进程断开连接，该子引用上的`connected`标志将被设置为`false`。

# 向子进程发送消息

正如我们在讨论`fork`时所看到的，并且在`spawn`的`ipc`选项上使用时，子进程可以通过`child.send`发送消息，消息作为第一个参数传递。可以将 TCP 服务器或套接字句柄作为第二个参数传递。通过这种方式，TCP 服务器可以将请求分布到多个子进程。例如，以下服务器将套接字处理分布到等于可用 CPU 总数的多个子进程。每个分叉的子进程都被赋予一个唯一的 ID，在启动时报告。每当 TCP 服务器接收到一个套接字时，该套接字将作为一个句柄传递给一个随机的子进程：

```js
// tcpparent.js
const fork = require('child_process').fork;
const net = require('net');
let children = [];
require('os').cpus().forEach((f, idx) => {
 children.push(fork('./tcpchild.js', [idx]));
});
net.createServer((socket) => { 
 let rand = Math.floor(Math.random() * children.length);
 children[rand].send(null, socket);
}).listen(8080)
```

然后，该子进程发送一个唯一的响应，证明了套接字处理正在分布式进行：

```js
// tcpchild.js
let id = process.argv[2];
process.on('message', (n, socket) => {
 socket.write(`child ${id} was your server today.\r\n`);
 socket.end();
});
```

在一个终端窗口中启动父服务器。在另一个窗口中，运行`telnet 127.0.0.1 8080`。您应该看到类似以下输出，每次连接都显示一个随机的子 ID（假设存在多个核心）：

```js
Trying 127.0.0.1...
 …
 child 3 was your server today.
 Connection closed by foreign host.
```

多次访问该端点。您应该看到您的请求是由不同的子进程处理的。

# 使用多个进程解析文件

许多开发人员将承担的任务之一是构建日志文件处理器。日志文件可能非常大，有数兆字节长。任何一个单独处理非常大文件的程序都很容易遇到内存问题，或者运行速度太慢。逐块处理大文件是有意义的。我们将构建一个简单的日志处理器，将大文件分成多个部分，并将每个部分分配给几个子工作进程，以并行运行它们。

此示例的完整代码可以在代码包的`logproc`文件夹中找到。我们将专注于主要例程：

+   确定日志文件中的行数

+   将它们分成相等的块

+   为每个块创建一个子进程并传递解析指令

+   组装并显示结果

为了获得文件的字数，我们使用`child.exec`和`wc`命令，如下面的代码所示：

```js
child.exec(`wc -l ${filename}`, function(e, fL) {
  fileLength = parseInt(fL.replace(filename, ""));

  let fileRanges = [];
  let oStart = 1;
  let oEnd = fileChunkLength;

  while(oStart < fileLength) {
    fileRanges.push({
      offsetStart: oStart,
      offsetEnd: oEnd
    })
    oStart = oEnd + 1;
    oEnd = Math.min(oStart + fileChunkLength, fileLength);
  } 
  ...
}
```

假设我们使用 500,000 行的`fileChunkLength`。这意味着将创建四个子进程，并且每个子进程将被告知处理文件中的 500,000 行的范围，例如 1 到 500,000：

```js
let w = child.fork('bin/worker');
w.send({
  file: filename,
  offsetStart: range.offsetStart,
  offsetEnd: range.offsetEnd
});
w.on('message', chunkData => {
  // pass results data on to a reducer.
});
```

这些工作进程本身将使用子进程来获取它们分配的块，使用`sed`，这是 Unix 的本地流编辑器：

```js
process.on('message', (m) => {
  let filename = m.file;
  let sed = `sed -n '${m.offsetStart},${m.offsetEnd}p' ${filename}`;
  let reader = require('child_process').exec(sed, {maxBuffer: 1024e6}, (err, data, stderr) => {

     // Split the file chunk into lines and process it.
     //
     data = data.split("\n");
     ...
  })
})            
```

在这里，我们执行`sed –n '500001,1000001p' logfile.txt`命令，该命令会提取给定范围的行并返回它们以进行处理。一旦我们处理完数据的列（将它们相加等），子进程将把数据返回给主进程（如前所述），数据结果将被写入文件，否则将被操作，或者发送到`stdout`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/82dec7c0-d77b-4218-9152-3bab484979d4.jpg)

这个示例的完整文件要长得多，但所有额外的代码只是格式和其他细节——我们已经描述的 Node 子进程管理足以创建一个并行化的系统，用于处理数百万行代码，只需几秒钟。通过使用更多的进程分布在更多的核心上，日志解析速度甚至可以进一步降低。

在您的代码包中的`/logproc`文件夹中查看`README.MD`文件，以尝试此示例。

# 使用集群模块

正如我们在处理大型日志文件时所看到的，一个主父控制器对多个子进程的模式非常适合 Node 的垂直扩展。作为对此的回应，Node API 已经通过`cluster`模块进行了增强，该模块正式化了这种模式，并有助于更容易地实现它。继续 Node 的核心目标，帮助构建可扩展的网络软件更容易，`cluster`的特定目标是促进在许多子进程之间共享网络端口。

例如，以下代码创建了一个共享相同 HTTP 连接的工作进程的`cluster`：

```js
const cluster = require('cluster');
const http = require('http');
const numCPUs = require('os').cpus().length;

if(cluster.isMaster) {
   for(let i = 0; i < numCPUs; i++) {
      cluster.fork();
   }
}

if(cluster.isWorker) {
   http.createServer((req, res) => {
      res.writeHead(200);
      res.end(`Hello from ${cluster.worker.id}`);
   }).listen(8080);
}
```

我们将很快深入了解细节。现在，请注意`cluster.fork`没有带任何参数。`fork`没有命令或文件参数会做什么？在`cluster`中，默认操作是`fork`当前程序。我们在`cluster.isMaster`期间看到，操作是`fork`子进程（每个可用的 CPU 一个）。当这个程序在分叉的上下文中重新执行时，`cluster.isWorker`将为`true`，并且将启动一个在共享端口上运行的新 HTTP 服务器。多个进程共享单个服务器的负载。

使用浏览器启动并连接到此服务器。您将看到类似`Hello from 8`的内容，这是与负责处理您的请求的唯一`cluster.worker.id`值相对应的整数。自动处理所有工作进程的负载平衡，因此刷新浏览器几次将导致显示不同的工作进程 ID。

稍后，我们将通过一个示例来介绍如何在集群中共享套接字服务器。现在，我们将列出集群 API，它分为两部分：可用于集群主进程的方法、属性和事件，以及可用于子进程的方法、属性和事件。在这种情况下，使用 fork 定义工作进程，`child_process`的该方法的文档也可以应用于这里：

+   `cluster.isMaster`：这是一个布尔值，指示进程是否为主进程。

+   `cluster.isWorker`：这是一个布尔值，指示进程是否是从主进程 fork 出来的。

+   `cluster.worker`：这将引用当前工作进程对象，仅对子进程可用。

+   `cluster.workers`：这是一个哈希，包含对所有活动工作进程对象的引用，以工作进程 ID 为键。在主进程中使用此方法循环遍历所有工作进程对象。这仅存在于主进程中。

+   `cluster.setupMaster([settings])`：这是一种方便的方法，用于传递默认参数映射，以在 fork 子进程时使用。如果所有子进程都将 fork 相同的文件（通常情况下），通过在这里设置，可以节省时间。可用的默认值如下：

+   `exec`（字符串）：这是进程文件的文件路径，默认为`__filename`。

+   `args`（数组）：这包含作为参数发送到子进程的字符串。默认情况下，使用`process.argv.slice(2)`获取参数。

+   `silent`（布尔值）：这指定是否将输出发送到主进程的 stdio，默认为 false。

+   `cluster.fork([env])`：创建一个新的工作进程。只有主进程可以调用此方法。要将键值对映射暴露给子进程的环境，请发送一个对象到`env`。

+   `cluster.disconnect([callback])`：用于终止集群中的所有工作进程。一旦所有工作进程都已经优雅地死亡，如果集群进程没有更多事件需要等待，它将自行终止。要在所有子进程过期时收到通知，请传递`callback`。

# 集群事件

集群对象发出几个事件，如下所列：

+   `fork`：当主进程尝试 fork 一个新的子进程时触发。这与`online`不同。这接收一个`worker`对象。

+   `online`：当主进程收到子进程完全绑定的通知时触发。这与`fork`事件不同，并接收一个`worker`对象。

+   `listening`：当工作进程执行需要`listen()`调用的操作（例如启动 HTTP 服务器）时，此事件将在主进程中触发。该事件发出两个参数：一个`worker`对象和包含连接的`address`、`port`和`addressType`值的地址对象。

+   `disconnect`：每当子进程断开连接时调用，这可能是通过进程退出事件或调用`child.kill()`后发生的。这将在`exit`事件之前触发-它们不是相同的。这接收一个`worker`对象。

+   `exit`：每当子进程死亡时，都会触发此事件。该事件接收三个参数：一个`worker`对象，退出代码数字和导致进程被杀死的信号字符串，如`SIGNUP`。

+   `setup`：在`cluster.setupMaster`执行后调用。

# 工作进程对象属性

工作进程具有以下属性和方法：

+   `worker.id`：这是分配给工作进程的唯一 ID，也代表`cluster.workers`索引中的工作进程键。

+   `worker.process`：这指定了一个引用工作进程的`ChildProcess`对象。

+   `worker.suicide`：最近已经对其进行了`kill`或`disconnect`调用的工作进程将其`suicide`属性设置为`true`。

+   `worker.send(message, [sendHandle])`：参考之前提到的`child_process.fork()`。

+   `worker.kill([signal])`：杀死一个工作进程。主进程可以检查该工作进程的`suicide`属性，以确定死亡是有意还是意外的。发送的默认信号值是`SIGTERM`。

+   `worker.disconnect()`：这指示工作人员断开连接。重要的是，与工作人员的现有连接不会立即终止（与`kill`一样），而是允许它们正常退出，然后工作人员完全断开连接。这是因为现有连接可能存在很长时间。定期检查工作人员是否实际断开连接可能是一个很好的模式，也许可以使用超时。

# 工作人员事件

工作人员也会发出事件，例如以下列表中提到的事件：

+   `message`：参考`child_process.fork`

+   `online`：这与`cluster.online`相同，只是检查仅针对指定的工作人员

+   `listening`：这与`cluster.listening`相同，只是检查仅针对指定的工作人员

+   `disconnect`：这与`cluster.disconnect`相同，只是检查仅针对指定的工作人员

+   `exit`：参考`child_process`的`exit`事件

+   `setup`：在`cluster.setupMaster`执行后调用

现在，根据我们现在对`cluster`模块的了解，让我们实现一个实时工具，用于分析许多用户同时与应用程序交互时发出的数据流。

# 使用 PM2 管理多个进程

PM2 旨在成为企业级进程管理器。如其他地方所讨论的，Node 在 Unix 进程中运行，其子进程和集群模块用于在跨多个核心扩展应用程序时生成更多进程。PM2 可用于通过命令行和以编程方式进行部署和监视 Node 进程。PM2 免除了开发人员配置集群样板的复杂性，自动处理重启，并提供了开箱即用的高级日志记录和监视工具。

全局安装 PM2：`npm install pm2 -g`

使用 PM2 的最简单方法是作为一个简单的进程运行程序。以下程序将每秒递增并记录一个值：

```js
// script.js
let count = 1;
function loop() {
  console.log(count++);
  setTimeout(loop, 1000);
}
loop();
```

在这里，我们从`script.js`中派生一个新的进程，在后台*永远*运行，直到我们停止它。这是运行守护进程的绝佳方式：

```js
pm2 start script.js 
// [PM2] Process script.js launched
```

脚本启动后，您应该在终端中看到类似于以下内容：

！[](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/c79e0330-beca-4f40-af85-6c6b84c36df8.png)

大多数值的含义应该是清楚的，例如您的进程使用的内存量，它是否在线，它已经运行了多长时间等（模式和观看字段将很快解释）。进程将继续运行，直到停止或删除。

要在启动进程时为其设置自定义名称，请将`--name`参数传递给 PM2：`pm2 start script.js --name 'myProcessName'`。

可以随时通过命令`pm2 list`查看所有正在运行的 PM2 进程的概述。

PM2 提供其他简单的命令：

+   `pm2 stop <app_name | id | all>`：按名称停止进程，id 或停止所有进程。已停止的进程将保留在进程列表中，并且可以稍后重新启动。

+   `pm2 restart <app_name | id | all>`：重新启动进程。在所有进程列表中显示了进程重新启动的次数。要在达到某个最大内存限制（比如 15M）时自动重新启动进程，请使用命令`pm2 start script.js --max-memory-restart 15M`。

+   `pm2 delete <app_name | id | all>`：删除进程。此进程无法重新启动。pm2 delete all 删除所有 PM2 进程。

+   `pm2 info <app_name | id>`：提供有关进程的详细信息。

您将经常使用`pm2 info <processname>`。确保`script.js`作为 PM2 进程运行，使用`PM2 list`，然后使用`pm2 info script`检查该进程信息：

！[](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/480ac271-bf14-4d44-9e8f-bd564a647a33.png)

注意为错误和其他日志给出的路径。请记住，我们的脚本每秒递增一个整数并记录该计数。如果您`cat /path/to/script/out/log`，您的终端将显示已写入输出日志的内容，这应该是一个递增的数字列表。错误同样会写入日志。此外，您可以使用`pm2 logs`实时流式传输输出日志：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/97391b02-5a37-4577-bcf7-78b0d0b619ad.png)

要清除所有日志，请使用`pm2 flush`。

您还可以以编程方式使用 PM2。要复制我们使用 PM2 运行`scripts.js`的步骤，首先创建以下脚本`programmatic.js`：

```js
const pm2 = require('pm2');

pm2.connect(err => {
   pm2.start('script.js', { 
      name: 'programmed script runner',
      scriptArgs: [
         'first',
         'second',
         'third'
      ],
      execMode : 'fork_mode'
   }, (err, proc) => {
      if(err) {
         throw new Error(err);
      }
   });
});
```

此脚本将使用 pm2 模块将`script.js`作为进程运行。继续使用`node programmatic.js`运行它。执行`pm2 list`应该显示编程脚本运行器是活动的：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/2592f665-3ed5-4929-8a02-b014a68ffe9e.png)

要确保，请尝试`pm2 logs`——您应该看到数字正在递增，就像以前一样。您可以在此处阅读有关完整编程选项的信息：[`pm2.keymetrics.io/docs/usage/pm2-api/`](http://pm2.keymetrics.io/docs/usage/pm2-api/)。

# 监控

PM2 使进程监控变得简单。要查看进程的 CPU 和内存使用情况的实时统计信息，只需输入命令`pm2 monit`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/205b443c-55ea-47d0-b1be-1526cedfd881.png)

相当不错，对吧？在通过 PM2 管理的生产服务器上，您可以使用此界面快速查看应用程序的状态，包括内存使用情况和运行日志。

PM2 还可以轻松创建基于 Web 的监控界面——只需运行`pm2 web`即可。此命令将启动一个在端口 9615 上监听的受监视进程——运行`pm2 list`现在将列出一个名为`pm2-http-interface`的进程。运行 web 命令，然后在浏览器中导航到`localhost:9615`。您将看到有关您的进程、操作系统等的详细快照，以 JSON 对象的形式：

```js
... 
"monit": {
  "loadavg": [ 1.89892578125, 1.91162109375, 1.896484375 ],
  "total_mem": 17179869184, "free_mem": 8377733120, 
...
{
  "pid": 13352,
  "name": "programmed script runner",
  "pm2_env": {
    "instance_var": "NODE_APP_INSTANCE",
    "exec_mode": "fork_mode",
...
  "pm_id": 8, // our script.js process "monit": {
  "memory": 19619840, "cpu": 0 
...
```

创建一个基于 Web 的 UI，每隔几秒轮询您的服务器，获取进程信息，然后绘制图表，由于 PM2 的这一内置功能，变得更加简单。PM2 还有一个选项，可以在所有管理的脚本上设置一个监视器，这样监视的脚本的任何更改都会导致自动进程重启。这在开发过程中非常有用。

作为演示，让我们创建一个简单的 HTTP 服务器并通过 PM2 运行它：

```js
// server.js
const http = require('http');
http.createServer((req, resp) => {
   if(req.url === "/") {
      resp.writeHead(200, {
         'content-type' : 'text/plain'
      });
      return resp.end("Hello World");
   }
   resp.end();
}).listen(8080);
```

每当访问`localhost:8080`时，此服务器将回显“Hello World”。现在，让我们使用 PM2 进程文件进行更多涉及配置。

# 进程文件

继续使用`pm2 delete all`杀死所有正在运行的 PM2 进程。然后，创建以下`process.json`文件：

```js
// process.json
{
  "apps" : [{
    "name" : "server",
    "script" : "./server.js",
    "watch" : true,
    "env": {
      "NODE_ENV": "development"
    },
    "instances" : 4,
    "exec_mode" : "cluster"
  }]
}
```

我们将使用此部署定义在 PM2 上启动我们的应用程序。请注意，apps 是一个数组，这意味着您可以列出几个不同的应用程序，并使用不同的配置同时启动它们。我们将在下面解释这些字段，但现在，请使用`pm2 start process.json`执行此清单。您应该会看到类似于这样的内容：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/bff9c69a-8e2a-4a83-97ac-6785f5e67314.png)

部署多进程（集群）应用程序如此简单。PM2 将自动在实例之间平衡负载，在清单中通过`instances`属性设置为 4 个 CPU，`exec_mode`为*cluster*（默认模式为“fork”）。在生产环境中，您可能希望在最大核心数之间平衡负载，只需将`instances`设置为`0`即可。此外，您可以看到我们通过`env:`设置了环境变量，您可以在此处为服务器创建*dev*和*prod*（甚至*stage*）配置，设置 API 密钥和密码以及其他环境变量。

打开浏览器并访问`localhost:8080`，以查看服务器是否正在运行。请注意，在我们的 JSON 清单中，我们将`watch`设置为`true`。这告诉 PM2 在您的存储库中更改任何文件时自动重新启动应用程序，跨所有核心。通过更改服务器上的“Hello”消息为其他内容来测试它。然后重新加载`localhost:8080`，您将看到新消息，表明服务器已重新启动。如果列出正在运行的 PM2 进程，您将看到重新启动的次数：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/c0362078-38db-4864-9ce1-1e125a22145d.png)

试着多次尝试。重新启动是稳定的，快速的，自动的。

您还可以为监视器指定特定的文件：

```js
{
  "apps" : [{
    ...
    "watch": [
      "tests/*.test",
      "app" 
    ],
    "ignore_watch": [
      "**/*.log"
    ],
    "watch_options": {
      "followSymlinks": false
    },
    ...
  }]
}
```

在这里，我们告诉 PM2 只监视`/test`中的`.test`文件和`/app`目录，忽略任何.log 文件的更改。在底层，PM2 使用 Chokidar ([`github.com/paulmillr/chokidar#api`](https://github.com/paulmillr/chokidar#api))来监视文件更改，因此您可以通过在`watch_options`上设置 Chokidar 选项来进一步配置监视器。请注意，您可以在这些设置中使用 glob 表达式（和正则表达式）。

您可以在此处阅读 PM2 进程文件的完整选项列表：[`pm2.keymetrics.io/docs/usage/application-declaration/`](http://pm2.keymetrics.io/docs/usage/application-declaration/)。

一些需要注意的地方：

+   `max_restarts`：PM2 允许的不稳定重新启动次数。

+   `min_uptime`：在被视为不稳定并触发重新启动之前，应用程序被给予启动的最短时间。

+   `autorestart`：是否在崩溃时重新启动。

+   `node_args`：将命令行参数传递给 Node 进程本身。例如：`node_args: "--harmony"`相当于`node --harmony server.js`。

+   `max_memory_restart`：当内存使用量超过此阈值时发生重新启动。

+   `restart_delay`：特别是在`watch`场景中，您可能希望在文件更改时延迟重新启动，等待一段时间再做出反应。

由于 PM2，服务器应用程序的实时开发变得更加容易。

# 多个工作结果的实时活动更新

利用我们所学到的知识，我们将构建一个多进程系统来跟踪所有访问者对示例网页的行为。这将由两个主要部分组成：一个由 WebSocket 驱动的客户端库，它将在用户移动鼠标时广播每次移动，以及一个管理界面，可视化用户交互以及用户连接和断开系统的时间。我们的目标是展示如何设计一个更复杂的系统（例如跟踪和绘制用户可能进行的每次点击、滑动或其他交互）。

最终的管理界面将显示几个用户的活动图表，并类似于这样：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/b44a0606-3afa-4d83-8047-faa9831cc5ea.jpg)

由于该系统将跟踪所有用户所做的每次鼠标移动的 X 和 Y 位置，我们将使用`cluster`将这连续的数据流跨越所有可用的机器核心，集群中的每个工作进程都共享承载大量套接字数据的负担，这些数据被馈送到一个共享端口。继续访问本章的代码包，并按照`/watcher`文件夹中的`README.MD`说明进行操作。

一个很好的开始是设计模拟客户端页面，它负责捕获所有鼠标移动事件并通过`WebSocket`将它们广播到我们的集群套接字服务器。我们正在使用本机的`WebSocket`实现；您可能希望使用一个库来处理旧版浏览器（如`Socket.IO`）：

```js
<head>
  <script>
    let connection = new WebSocket('ws://127.0.0.1:8081', ['json']);
      connection.onopen = () => {
        let userId = 'user' + Math.floor(Math.random()*10e10);
        document.onmousemove = e => {
          connection.send(JSON.stringify({id: userId, x: e.x, y: e.y}));
        }
      };
  </script>
</head>
```

在这里，我们只需要简单地打开基本的`mousemove`跟踪，它将在每次移动时广播用户鼠标的位置到我们的套接字。此外，我们还发送一个唯一的用户 ID，因为跟踪客户端身份对我们来说以后很重要。请注意，在生产环境中，您将希望通过服务器端身份验证模块实现更智能的唯一 ID 生成器。

为了使这些信息传达给其他客户端，必须设置一个集中的套接字服务器。正如前面提到的，我们希望这个套接字服务器是集群的。每个集群子进程，都是以下程序的副本，将处理客户端发送的鼠标数据：

```js
const SServer = require('ws').Server;
let socketServer = new SServer({port: 8081});
socketServer.on('connection', socket => {
  let lastMessage = null;
  function kill() => {
    if (lastMessage) {                                              
      process.send({kill: lastMessage.id});            
    }
  }
  socket.on('message', message => {
    lastMessage = JSON.parse(message);   
    process.send(lastMessage);                                                                  
  });
  socket.on('close', kill);
  socket.on('error', kill);
});
```

在这个演示中，我们使用了*Einar Otto Stangvik*的非常快速和设计良好的套接字服务器库`ws`，它托管在 GitHub 上：[`github.com/websockets/ws`](https://github.com/websockets/ws)

值得庆幸的是，我们的代码仍然非常简单。我们有一个监听消息的套接字服务器（记住客户端发送的是一个带有鼠标*X*和*Y*以及用户 ID 的对象）。最后，当接收到数据时（`message`事件），我们将接收到的 JSON 解析为一个对象，并通过`process.send`将其传递回我们的集群主。

还要注意我们如何存储最后一条消息（`lastMessage`），出于簿记原因，当连接终止时，我们将需要将此连接上看到的最后一个用户 ID 传递给管理员。

现在已经设置好了捕捉客户端数据广播的部分。一旦接收到这些数据，它是如何传递给先前展示的管理界面的？

我们设计这个系统时考虑了扩展性，并希望将数据的收集与广播数据的系统分离。我们的套接字服务器集群可以接受来自成千上万客户端的持续数据流，并且应该针对这一点进行优化。换句话说，集群应该将广播鼠标活动数据的责任委托给另一个系统，甚至是其他服务器。

在下一章中，我们将研究更高级的扩展和消息传递工具，比如消息队列和 UDP 广播。对于我们在这里的目的，我们将简单地创建一个 HTTP 服务器，负责管理来自管理员的连接并向他们广播鼠标活动更新。我们将使用 SSE 来实现这一点，因为数据流只需要单向，从服务器到客户端。

HTTP 服务器将为管理员登录实现一个非常基本的验证系统，以一种允许我们的套接字集群向所有成功连接广播鼠标活动更新的方式保留成功的连接。它还将作为一个基本的静态文件服务器，当请求时发送客户端和管理 HTML，尽管我们只关注它如何处理两个路由：“admin/adminname”和`/receive/adminname`。一旦服务器被理解，我们将进入我们的套接字集群如何连接到它。

第一个路由`/admin/adminname`主要负责验证管理员登录，还要确保这不是重复登录。一旦确认了身份，我们就可以向管理界面发送一个 HTML 页面。用于绘制先前图片中的图表的特定客户端代码将不在这里讨论。我们需要的是与服务器建立 SSE 连接，以便界面的图表工具可以实时接收鼠标活动的更新。返回的管理员页面上的一些 JavaScript 建立了这样的连接：

```js
let ev = new EventSource('/receive/adminname');
ev.addEventListener("open", () => {
  console.log("Connection opened");
});
ev.addEventListener("message", data => {
  //  Do something with mouse data, like graph it.
}
```

在我们的服务器上，我们实现了`/receive/adminname`路由：

```js
if (method === "receive") {
  // Unknown admin; reject
  if (!admins[adminId]) {
    return response.end();
  }
  response.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive"
  });
  response.write(":" + Array(2049).join(" ") + "\n");
  response.write("retry: 2000\n");
  response.on("close", () => {
    admins[adminId] = {};
  });
  setInterval(() => {
    response.write("data: PING\n\n");
  }, 15000);
  admins[adminId].socket = response;
  return;
}
```

这个路由的主要目的是建立 SSE 连接并存储管理员的连接，以便我们以后可以向其广播。

现在我们将添加一些部分，将鼠标活动数据传递给可视化界面。使用集群模块跨核心扩展这个子系统是我们的下一步。集群主现在只需要等待来自其提供套接字服务的子进程的鼠标数据，就像之前描述的那样。

我们将使用在之前的集群讨论中提出的相同思想，简单地将先前的套接字服务器代码分叉到所有可用的 CPU 上：

```js
if (cluster.isMaster) {
  let i;
  for (i = 0; i < numCPUs; i++) {
    cluster.fork();
}
cluster.on('exit', (worker, code, signal) => {
  console.log(`worker ${worker.process.pid} died`);
})

// Set up socket worker listeners
Object.keys(cluster.workers).forEach(id => {
  cluster.workers[id].on('message', msg => {
    let a;
    for (a in admins) {
      if (admins[a].socket) {
        admins[a].socket.write(`data: ${JSON.stringify(msg)}\n\n`);
      }
    }
  });
});
```

鼠标活动数据通过套接字传输到一个集群工作进程，并通过`process.send`广播到之前描述的集群主进程。在每个工作进程的消息中，我们遍历所有连接的管理员，并使用 SSE 将鼠标数据发送到他们的可视化界面。管理员现在可以观察客户端的到来和离开，以及他们个人的活动水平。

为了测试系统，首先以默认管理员身份登录，网址为`http://localhost:2112/admin/adminname`。你应该会看到一个青绿色的背景，目前为空，因为没有连接的客户端。接下来，通过打开一个或多个浏览器窗口并导航到`http://localhost:2112`来创建一些客户端，你会看到一个空白屏幕。随意在屏幕上移动鼠标。如果你返回管理员界面，你会看到你的鼠标移动（一个或多个客户端）正在被跟踪和绘制成图表。

# 总结

这是我们真正开始测试 Node 可扩展性目标的第一章。在考虑了关于并发和并行思考方式的各种论点之后，我们理解了 Node 如何成功地在并发模型中包裹了所有这些复杂性，使其易于理解和稳健，同时保持了线程和并行处理的优势。

深入了解了进程的工作方式，特别是子进程如何相互通信，甚至生成更多的子进程，我们看了一些用例。将原生 Unix 命令进程与自定义 Node 进程无缝结合的示例，让我们找到了一种高效且简单的处理大文件的技术。然后，集群模块被应用于如何在多个工作进程之间共享处理繁忙套接字的问题，这种在进程之间共享套接字句柄的能力展示了 Node 设计的一个强大方面。我们还了解了一个生产级的进程管理器 PM2，以及它如何使管理单个进程和集群变得更容易。

在看到了 Node 应用如何进行垂直扩展之后，我们现在可以研究跨多个系统和服务器的水平扩展。在下一章中，我们将学习如何将 Node 与亚马逊和 Twilio 等第三方服务连接，设置多个 Node 服务器在代理后面，并且更多内容。
