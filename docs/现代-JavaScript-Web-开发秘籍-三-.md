# 现代 JavaScript Web 开发秘籍（三）

> 原文：[`zh.annas-archive.org/md5/BB6CAA52F3F342E8C4B91D9CE02FEBF6`](https://zh.annas-archive.org/md5/BB6CAA52F3F342E8C4B91D9CE02FEBF6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：测试和调试你的服务器

在本章中，我们将看到以下的方法：

+   使用 Winston 添加日志记录

+   - 使用 Morgan 添加 HTTP 日志记录

+   为不同环境配置你的服务器

+   - 对你的代码进行单元测试

+   - 测量你的测试覆盖率

+   - 调试你的代码

+   从命令行测试简单服务

+   - 使用 Postman 测试更复杂的调用序列

+   使用 Swagger 记录和测试你的 REST API

# 介绍

在之前的章节中，我们安装了`Node`并创建了一个 RESTful 服务器。一切准备好了吗？通常情况下，事情不会那么顺利——bug 会悄悄地爬进来，你将不得不找出如何修复你的代码。在本章中，我们将进入实际细节，比如测试和调试你的服务器。

所以，在本章之后，你的`Node` RESTful 服务器将准备好部署和正式生产工作。让我们开始必要的任务。

# - 使用 Winston 添加日志记录

让我们从一个简单的基本需求开始：*日志记录*。建立稳固、正确的日志记录可以帮助你快速找到问题，而不完整或其他缺乏的日志记录可能会让你寻找几个小时，而问题可能只是一个简单的琐事。任何应用程序的基本规则是确保设置适当的登录，这样你就可以确信任何出现的情况至少会被识别和记录以供将来分析。

你可能的第一个想法是只使用控制台系列函数，比如`console.log()`，`console.warn()`，`console.info()`等。（有关完整参考，请查看[`developer.mozilla.org/en-US/docs/Web/API/console`](https://developer.mozilla.org/en-US/docs/Web/API/console)。）虽然这些对于快速调试很好，但对于应用级别的日志记录来说并不够。你应该能够选择你想要的日志类型（全部？仅错误？）来决定你在不同环境下看到的日志（例如，在开发中你可能想看到某些类型的日志，但在生产中不需要），甚至可以启用或禁用日志。最后，我们希望对提供的信息有一些控制：

+   - *时间戳*，了解每个日志写入的时间

+   - *文本格式化*，使日志可以被人类理解，但也可以被应用程序解析

+   *级别设置*，通常在一个范围内从*error*（最严重）到*warning*，*informative*，*verbose*，最后是*debugging*和*silly*（是的，真的！）

+   *选择目的地*，比如`stdout`或`stderr`，文件系统等

在`npm`列表中，你会发现许多可以进行日志记录的模块：有些是通用工具，而其他一些则更具体。在我们的情况下，我们将使用`Winston`进行通用的应用级别日志记录，并且我们将转向另一个工具`Morgan`，它专门用于 HTTP 流量日志记录，我们将在下一节中看到。

- 你可以在[`github.com/winstonjs/winston`](https://github.com/winstonjs/winston)了解更多关于`Winston`的信息。

# 如何做到...

- 我们想要安装`Winston`，所以第一步将是应用这个历史悠久的方法：

```js
 npm install winston --save
```

目前，版本 3.0 还处于测试版阶段，但当你拿到这本书的时候，它几乎肯定已经不再是测试版，而是准备投入生产了。（顺便说一句，我通过使用略微修改的命令安装了测试版：`npm install winston@next --save`；否则，我会得到一个 2.x.x 版本。）

关于`Winston`的（彻底的！）文档，请查看它自己的 GitHub 页面[`github.com/winstonjs/winston`](https://github.com/winstonjs/winston)。不过要小心网络上的文章，因为在版本 3 中有一些重要的更改，所以大多数代码在没有更新的情况下是无法工作的。

我们想要看一个关于`Winston`使用的简单例子。这个包有许多配置参数，所以让我们尝试建立一个基本的、合理的配置，这样你就可以自己扩展了：

```js
// Source file: winston_server.js

/* @flow */
"use strict";

const express = require("express");
const winston = require("winston");

const app = express();

const logger = winston.createLogger({
    transports: [
        new winston.transports.Console({
            level: "info",
            format: winston.format.combine(
                winston.format.colorize({ all: true }),
                winston.format.label({ label: "serv" }),
                winston.format.timestamp(),
                winston.format.printf(
                    msg =>
                       `${msg.timestamp} [${msg.label}] ${msg.level} ${
                            msg.message
                        }`
                )
            )
        }),
        new winston.transports.File({
            filename: "serv_error.txt.log",
            level: "warn",
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.printf(
                    msg =>
                        `${msg.timestamp} [serv] ${msg.level} ${
                            msg.message
                        }`
                )
            )
        }),
        new winston.transports.File({
            filename: "serv_error.json.log",
            level: "warn"
        })
    ]
});

// *continues...*
```

`Winston`可以同时处理多个传输，而*传输*意味着您记录的任何内容的存储设备。单个记录器可以有多个传输，但配置不同：例如，您可能希望在控制台上显示所有日志，但只在警告和错误时写入文件，还有更多可能性，包括写入数据库或将数据发送到某个 URL。格式也可能不同（控制台的文本行，文件可能是 JSON 格式？），因此您在配置消息的输出位置方面有很大的灵活性。

在我们的情况下，我们创建了三个传输：

+   *控制台输出*，用于所有标记为`"info"`及以上的消息，使用带有时间戳的着色输出（我们马上就会看到），发出带有时间戳、标签（`"serv"`）的输出，以帮助区分服务器的消息和可能出现在控制台上的其他应用程序的消息，错误级别和消息

+   *一个文件输出*，用于所有标记为`"warn"`及以上的消息，以文本格式

+   *另一个文件输出*，用于相同的消息，但以 JSON 格式

我们将在本章的后面部分，*为不同环境配置服务器*，中看到如何调整日志记录（和其他功能），这样您就可以更加灵活地进行日志记录和其他功能。

创建了记录器并定义了传输后，我们只需在需要的地方使用它。我将从一个非常基本的服务器开始，这样我们就可以专注于使日志记录工作：我们只处理两个路由——`/`，它将发送一条消息，和`/xyzzy`，它将模拟一些程序故障，而不是发送一个“什么也没发生”的消息。

一开始，我们可以手动记录每个请求——尽管我们将在之后看到，使用`Morgan`会得到更好的输出。以下代码就是这样做的：

```js
// ...*continued*

app.use((req, res, next) => {
    logger.info(`${req.method} request for ${req.originalUrl}`);
    next();
});

// *continues...*
```

然后，对于每个路由，我们可以添加一些`info`或`debug`消息，因为我们可能需要：

```js
// ...*continued*

app.get("/", (req, res) => {
    logger.info("Doing some processing...");
 logger.debug("Some fake step 1; starting");
 logger.debug("Some fake step 2; working");
 logger.debug("Some fake step 3; finished!");
    res.send("Winston server!");
});

app.get("/xyzzy", (req, res) => {
    logger.info("Adventurer says 'XYZZY'");
    res.say_xyzzy(); // this will fail
    res.send("Nothing happens.");
});

// *continues...*
```

处理错误路由可能会产生一个`warn`消息，在其他未经计划的情况下，会直接产生一个`error`。对于前者，我只列出了所需的路由，对于后者，列出了错误消息和回溯堆栈，以帮助未来调试：

```js
// ...*continued*

app.use((req, res) => {
    logger.warn(`UNKNOWN ROUTE ${req.originalUrl}`);
    res.status(404).send("NOT FOUND");
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    logger.error(`GENERAL ERROR ${err.message}\n${err.stack}`);
    res.status(500).send("INTERNAL SERVER ERROR");
});

app.listen(8080, () => {
    logger.info("Ready at http://localhost:8080");
});
```

我们准备好了！让我们试一试。

# 它是如何工作的...

构建项目后，我运行了`Winston`日志记录代码来捕获所有生成的日志。我用`curl`模拟了一系列调用进行了尝试；我们将在本章的后面部分中看到如何在更复杂的任务中执行此操作：

```js
> curl localhost:8080/ 
Winston server!
> curl localhost:8080/ 
Winston server!
> curl localhost:8080/invented 
NOT FOUND
> curl localhost:8080/ 
Winston server!
> curl localhost:8080/xyzzy 
INTERNAL SERVER ERROR
> curl localhost:8080/ 
Winston server!
> curl localhost:8080/ 
Winston server!
```

控制台上的输出可以在下面的截图中看到。正常行是绿色的（是的，在黑白书中很难看到，对此很抱歉！），警告是黄色的，错误是红色的。对于不存在的`/invented`路径的请求以警告结束，而对于`/xyzzy`的请求产生了一个错误，因为我们尝试调用一个不存在的函数：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/5bacbfc1-3d5f-4ee8-a6f9-295db6fe93b0.png)

温斯顿的控制台输出一些虚拟请求

不同的日志文件记录了什么？根据我们的规范，只有警告和错误消息被存储。文本文件基本上与控制台输出相同，这是有道理的，因为我们为这两个传输选择的格式规范完全相同：

```js
2018-05-28T00:29:06.651Z [serv] warn UNKNOWN ROUTE /invented
2018-05-28T00:29:11.214Z [serv] error GENERAL ERROR res.say_xyzzy is not a function
TypeError: res.say_xyzzy is not a function
 at app.get (/home/fkereki/MODERNJS/chapter05/out/winston_server.js:60:9)
 at Layer.handle [as handle_request] (/home/fkereki/MODERNJS/chapter05/node_modules/express/lib/router/layer.js:95:5)
 at next (/home/fkereki/MODERNJS/chapter05/node_modules/express/lib/router/route.js:137:13)
 at Route.dispatch (/home/fkereki/MODERNJS/chapter05/node_modules/express/lib/router/route.js:112:3)
 at Layer.handle [as handle_request] (/home/fkereki/MODERNJS/chapter05/node_modules/express/lib/router/layer.js:95:5)
 at /home/fkereki/MODERNJS/chapter05/node_modules/express/lib/router/index.js:281:22
 at Function.process_params (/home/fkereki/MODERNJS/chapter05/node_modules/express/lib/router/index.js:335:12)
 at next (/home/fkereki/MODERNJS/chapter05/node_modules/express/lib/router/index.js:275:10)
 at app.use (/home/fkereki/MODERNJS/chapter05/out/winston_server.js:47:5)
 at Layer.handle [as handle_request] (/home/fkereki/MODERNJS/chapter05/node_modules/express/lib/router/layer.js:95:5)
```

另一方面，JSON 文件有点简化：每行包括一个带有`message`和`level`属性的对象，因为我们没有指定应该添加什么。但是，您可以更改这一点：阅读温斯顿的文档[`github.com/winstonjs/winston/blob/master/README.md`](https://github.com/winstonjs/winston/blob/master/README.md)，您将有很多可用的可能性：

```js
{"message":"UNKNOWN ROUTE /invented","level":"warn"}
{"message":"GENERAL ERROR res.say_xyzzy is not a function\nTypeError: res.say_xyzzy is not a function\n at app.get (/home/fkereki/MODERNJS/chapter05/out/winston_server.js:60:9)\n at Layer.handle [as handle_request] *...part of the text snipped out...*
(/home/fkereki/MODERNJS/chapter05/out/winston_server.js:47:5)\n at Layer.handle [as handle_request] (/home/fkereki/MODERNJS/chapter05/node_modules/express/lib/router/layer.js:95:5)","level":"error"}
```

因此，我们有一种灵活的方式来记录几乎我们想要的任何内容，但是我们的 HTTP 日志记录特别简略，这是包括`Morgan`的一个很好的理由，正如我们将看到的。

# 还有更多...

你可能还对其他软件包感兴趣，比如`Bunyan`（[`github.com/trentm/node-bunyan`](https://github.com/trentm/node-bunyan)）或`Pino`（[`github.com/pinojs/pino`](https://github.com/pinojs/pino)）；后者据说是性能最佳的日志软件包，但不要听我的，自己试试看！最后，如果你在开发`npm`软件包，那么`debug`（[`github.com/visionmedia/debug`](https://github.com/visionmedia/debug)）可能是你的首选软件包——它基本上是`console`方法的包装器，非常简单，也适用于 Web 应用和`Node`。

# 使用 Morgan 添加 HTTP 日志

在上一节中，当我们包含了一些进行`Winston`记录的中间件时，我们成功提供了一个非常基本的 HTTP 记录功能：

```js
app.use((req, res, next) => {
    logger.info(`${req.method} request for ${req.originalUrl}`);
    next();
});
```

虽然这样做可以工作，但我们可能还需要更多的信息，比如响应的 HTTP 状态码，所需的处理时间等，所以让我们将`Morgan`加入进来，因为该软件包专门用于请求记录。

你可以在[`github.com/expressjs/morgan`](https://github.com/expressjs/morgan)了解更多关于`Morgan`的信息。

在这个示例中，我们将`Morgan`添加到我们的软件堆栈中，以便为所有已处理的请求获得更好的日志。

# 如何做...

让我们从常规方法开始安装`Morgan`：

```js
 npm install morgan --save
```

现在我们必须在服务器中包含它，并且我们还需要`fs`软件包来将`Morgan`的日志写入文件。请注意，我是在我们之前的服务器上添加的，所以`Winston`的部分将保持不变，与我们在上一节中看到的一样：

```js
// Source file: src/morgan_server.js

/* @flow */
"use strict";

const express = require("express");
const winston = require("winston");
const morgan = require("morgan");
const fs = require("fs");

const app = express();

// *continues...*
```

我们想要对文件进行一些一般性的记录，以及所有错误（HTTP 状态码为 400 及更高）输出到控制台，所以我们必须将`morgan`添加两次到我们的中间件堆栈中。`morgan`的第一个参数定义了日志消息的形式：你必须提供一个函数来生成将被记录的消息，或者一个包含`morgan`将在运行时替换的标记的字符串。在下面的代码片段中，我使用了两种风格，只是为了多样化：文件输出使用函数，控制台使用字符串：

```js
// ...*continued*

const morganStream = fs.createWriteStream("serv_http_errors.log", {
    flags: "a"
});

app.use(
    morgan(
        (tokens, req, res) =>
 `${new Date().toISOString()} [http] ` +
 `${tokens.method(req, res)} ${tokens.url(req, res)}`,
        {
            immediate: true,
            stream: morganStream
        }
    )
);

app.use(
    morgan(
        `:date[iso] [http] ` +
 `:method :url (:status) :res[content-length] - :response-time ms`,
        {
            skip: (req, res) => res.statusCode < 400
        }
    )
);

// *continues...*
```

`morgan`的第二个选项允许你添加一些选项，例如以下内容：

+   `immediate`，意味着请求将在进来时立即记录（`immediate:true`）或在处理后记录（`immediate:false`）。前者的优势在于你可以确保所有请求都会被记录，即使发生严重崩溃，但后者提供了更多信息。

+   `skip()`，一个函数，让你决定是否记录给定的请求。在我们的情况下，我们将使用它来记录得到 400 或更高状态的请求。

+   `stream`，输出应写入的流。

在指定输出格式时，你可以访问多个数据片段，称为 Morgan 术语中的*标记*，例如以下内容，但请查阅完整列表的文档：

| `:date[format]` | 当前日期和时间（以 UTC 时间）以多种格式显示 |
| --- | --- |
| `:http-version` | 请求的 HTTP 版本 |
| `:method` | 请求的 HTTP 方法 |
| `:remote-addr` | 请求的远程地址 |
| `:req[header]` | 请求的给定标头，如果标头不存在则为“-” |
| `:res[header]` | 响应的给定标头，如果标头不存在则为“-” |
| `:response-time` | 处理时间，以毫秒为单位 |
| `:status` | 响应的 HTTP 状态 |
| `:url` | 请求的 URL |

你可以看到我在设置`Morgan`的输出时使用了几个这些标记。现在，让我们看看它是如何工作的。

# 它是如何工作的...

让我们试一试，使用我们为`winston`使用的相同示例。由于我们将控制台输出设置为仅显示警告和错误，我们将只看到添加的一对行。显示`[http]`而不是`[serv]`有助于在控制台输出的其余部分中找到它们。

```js
.
.
.
2018-05-28T19:27:19.232Z [http] GET /invented (404) 9 - 0.886 ms
.
.
.
2018-05-28T19:27:23.771Z [http] GET /xyzzy (500) 21 - 0.925 ms
.
.
.
```

（完整的）HTTP 日志被记录到一个文件中，只是所有请求的列表：

```js
2018-05-28T19:27:16.871Z [http] GET /
2018-05-28T19:27:17.827Z [http] GET /
2018-05-28T19:27:19.231Z [http] GET /invented
2018-05-28T19:27:20.677Z [http] GET /
2018-05-28T19:27:23.770Z [http] GET /xyzzy
2018-05-28T19:27:25.296Z [http] GET /
```

请注意，我们选择立即记录日志，这意味着所有请求——即使可能导致一切崩溃的请求——都会被记录，但请求本身的结果则不可用。如果您希望获取该信息，但仅针对导致某些错误的请求，您可以添加第三个`morgan`目标，共享相同的文件流，但仅用于错误，如下面的代码片段所示：

```js
app.use(
    morgan(
        `:date[iso] [http] ` +
            `:method :url (:status) :res[content-length] - :response-time ms`,
        {
            skip: (req, res) => res.statusCode < 400,
            stream: morganStream
        }
    )
);
```

使用这个方法，日志将包括更多数据，但仅适用于您选择的请求：

```js
2018-05-28T19:36:54.968Z [http] GET /
2018-05-28T19:36:55.453Z [http] GET /
2018-05-28T19:36:56.011Z [http] GET /
2018-05-28T19:36:58.149Z [http] GET /invented
2018-05-28T19:36:58.151Z [http] GET /invented (404) 9 - 1.230 ms
2018-05-28T19:36:59.528Z [http] GET /
2018-05-28T19:37:00.033Z [http] GET /
2018-05-28T19:37:01.886Z [http] GET /xyzzy
2018-05-28T19:37:01.888Z [http] GET /xyzzy (500) 21 - 1.115 ms
2018-05-28T19:37:03.060Z [http] GET /
2018-05-28T19:37:03.445Z [http] GET /
2018-05-28T19:37:03.903Z [http] GET /
```

# 还有更多...

如果您愿意，可以将`Morgan`的输出发送到`Winston`中，以获得单个公共日志流，如下所示：

```js
// Source file: src/morgan_in_winston_server.js

app.use(
    morgan(
        `:method :url (:status) :res[content-length] - :response-time ms`,
        {
 stream: {
 write: message => logger.info(message.trim())
 }
        }
    )
);
```

一些输出可能如下；我突出显示了`morgan`行：

```js
2018-05-28T20:03:59.931Z [serv] info Ready at http://localhost:8080
2018-05-28T20:04:02.140Z [serv] info Doing some processing...
2018-05-28T20:04:02.146Z [serv] info GET / (200) 15 - 3.642 ms
2018-05-28T20:04:02.727Z [serv] info Doing some processing...
2018-05-28T20:04:02.728Z [serv] info GET / (200) 15 - 0.581 ms
2018-05-28T20:04:04.479Z [serv] warn UNKNOWN ROUTE /invented
2018-05-28T20:04:04.480Z [serv] info GET /invented (404) 9 - 1.170 ms
2018-05-28T20:04:05.842Z [serv] info Doing some processing...
2018-05-28T20:04:05.843Z [serv] info GET / (200) 15 - 0.490 ms
2018-05-28T20:04:07.640Z [serv] info Adventurer says 'XYZZY'
```

我所做的更改的一些细节如下：

+   添加`.trim()`可以去除可能存在的额外换行符

+   由于所有消息都通过`winston`发送，因此您在输出中看不到`[http]`的区分文本

+   如果您希望发送警告状态码为 400 或以上的警告，您将需要编写一个更复杂的函数，该函数将扫描消息文本并决定是否使用`logger.info()`或其他方法

# 为不同环境配置服务器

无论您开发什么，可以肯定的是，您至少会使用两个环境，*开发*和*生产*，并且代码的设置不会相同。例如，您不会使用相同的配置来访问数据库、记录错误或连接到分析服务等等：在开发环境中运行时，您将需要一定的设置，而在生产环境中可能会有很多变化。

您可以在代码中设置所有内容，但是在明文中保存用户、密码、IP 等敏感数据，并将其保存在可能被黑客攻击的源代码存储库中，这并不是一个安全的做法。您应该专门处理开发配置，并将实际部署留给另一个团队，他们将安全地处理该配置。

Node 允许您访问环境变量并将其用于配置，以便您可以将该设置移出代码之外。在本章中，让我们看看如何处理所有这些，这也将在本章后期间接下来的测试间接帮助我们。

# 如何做...

当您开发软件时，显然会在与生产不同的环境中工作；事实上，您可能有多个环境，如*开发*、*测试*、*预生产*、*生产*等。我们也会这样做；让我们首先回顾一些我们在本书中已经看到的配置。

在第三章的*使用 Node 进行开发*部分的*获取连接*部分中，当我们创建服务时，我们定义了四个常量来访问数据库，如下所示：

```js
const DB_HOST = "127.0.0.1";
const DB_USER = "fkereki";
const DB_PASS = "modernJS!!";
const DB_SCHEMA = "world";
```

在上一章的*使用 JWT 添加身份验证*部分中，我们有一个用于签名的密钥：

```js
const SECRET_JWT_KEY = "modernJSbook";
```

最后，在这一章中，我们决定应该做哪些级别的日志记录。然而，我们对这些级别进行了硬编码，没有可能在生产中进行不同的设置：

```js
const logger = winston.createLogger({
    transports: [
        new winston.transports.Console({
            level: "info",
            format: winston.format.combine(
                winston.format.colorize({ all: true }),
                .
                .
                .
```

我们还写了以下内容，并进行了一些硬编码：

```js
const morganStream = fs.createWriteStream("serv_http_errors.log", {
    flags: "a"
});

app.use(
    morgan(
        `:date[iso] [http] ` +
            `:method :url (:status) :res[content-length] - :response-time ms`,
        {
            skip: (req, res) => res.statusCode < 400
```

值得指出的是，开发和生产之间的更改不仅限于列出或不列出；您还可以更改日志格式、日志应写入的文件等等。

动态更改配置的关键是使用环境变量，这些变量通过`process.env`对象提供。您环境中的每个配置变量都将显示为该对象的属性。如果我们编写并运行一个仅包含单个`console.log(process.env)`行的程序（或者在命令行中执行`node -e "console.log(process.env)"`），您将获得类似以下的输出：

```js
> node show_env.js
{ GS_LIB: '/home/fkereki/.fonts',
 KDE_FULL_SESSION: 'true',
 PILOTPORT: 'usb:',
 HOSTTYPE: 'x86_64',
 VSCODE_NLS_CONFIG: '{"locale":"en-us","availableLanguages":{}}',
 XAUTHLOCALHOSTNAME: 'linux',
 XKEYSYMDB: '/usr/X11R6/lib/X11/XKeysymDB',
 LANG: 'en_US.UTF-8',
 WINDOWMANAGER: '/usr/bin/startkde',
 LESS: '-M -I -R',
 DISPLAY: ':0',
 JAVA_ROOT: '/usr/lib64/jvm/jre',
 HOSTNAME: 'linux',
 .
 .
 .
 . *many, many lines snipped out*
 .
 .
 .
 PATH: '/home/fkereki/bin:/usr/local/bin:/usr/bin:/bin:/usr/lib/mit/sbin',
 JAVA_BINDIR: '/usr/lib64/jvm/jre/bin',
 KDE_SESSION_UID: '1000',
 KDE_SESSION_VERSION: '5',
 SDL_AUDIODRIVER: 'pulse',
 HISTSIZE: '1000',
 SESSION_MANAGER: 'local/linux:@/tmp/.ICE-unix/2202,unix/linux:/tmp/.ICE-unix/2202',
 CPU: 'x86_64',
 CVS_RSH: 'ssh',
 LESSOPEN: 'lessopen.sh %s',
 GTK_IM_MODULE: 'ibus',
 NODE_VERSION: '9' }
```

在[`nodejs.org/api/process.html#process_process_env`](https://nodejs.org/api/process.html#process_process_env)了解更多关于`process.env`及其内容的信息。

有两种利用这一点的方法。我们可以使用一个`环境`变量来检查我们是在开发中、生产中还是其他任何情况下，并根据此设置一些属性，或者我们可以直接从环境中获取这些属性的值。这两种解决方案中的任何一种都将帮助您将代码与环境解耦；让我们看看这在实践中是如何工作的。

# 它是如何工作的...

让我们从确定环境开始。标准是在运行`Node`服务器之前设置一个名为`NODE_ENV`的环境变量，其中包含环境的名称。如何做取决于您的实际机器，但在 Linux 中，类似以下内容，而在 Windows 中则需要`SET`命令：

```js
> export NODE_ENV=production 
> echo $NODE_ENV 
Production

```

在您的代码中，如果您正在开发中，则可以将`isDev`变量设置为 true（否则为 false），只需两行代码。如果未指定环境，则第一行将默认为`"development"`，这很可能是最安全的选择：

```js
// Source file: show_env.js

const dev = process.env.NODE_ENV || "development";
const isDev = dev === "development";
```

```js
level attribute gets its value, depending on the environment:
```

```js
const logger = winston.createLogger({
    transports: [
        new winston.transports.Console({
            level: isDev ? "info" : "warn",
            format: winston.format.combine(
                winston.format.colorize({ all: true }),
                .
                .
                .
```

更改日志文件也很简单，与前面的代码类似：

```js
let loggingFile;
if (isDev) { 
    loggingFile = "serv_http_errors.log";
} else {
    loggingFile = "/var/log/http_server.txt";
}

const morganStream = fs.createWriteStream(loggingFile, {
    flags: "a"
});
```

这种风格有效，但仍然存在一些问题：

+   环境的任何更改都需要更改（硬编码的）服务器

+   路径、令牌、密码等都驻留在源代码中，处于非常可见的状态

因此，我们可以通过直接从环境中直接获取内部变量的值来做得更好：

```js
const DB_HOST = process.env.DB_HOST;
const DB_USER = process.env.DB_USER;
const DB_PASS = process.env.DB_PASS;
const DB_SCHEMA = process.env.DB_SCHEMA;
const SECRET_JWT_KEY = process.env.SECRET_JWT_KEY;
```

或者，对于日志记录，我们可以使用以下内容：

```js
const logger = winston.createLogger({
    transports: [
        new winston.transports.Console({
            level: process.env.WINSTON_LEVEL,
            format: winston.format.combine(
                winston.format.colorize({ all: true }),
                .
                .
                .
```

# 还有更多...

如果您想简化在开发中的工作，但同时也希望在将代码推送到生产或其他环境时为其他人提供便利，您可能需要研究一下`dotenv`，这是一个`npm`包，可以让您在文本文件中使用环境变量。使用`npm install dotenv --save`安装该包，然后在项目的根目录创建一个具有`.env`扩展名的文件，其中包含所需的变量值：

```js
DB_HOST=127.0.0.1
DB_USER=fkereki
DB_PASS=modernJS!!
DB_SCHEMA=world
SECRET_JWT_KEY=modernJSbook
```

然后，在您的代码中，您只需要添加一行代码，它将加载并合并`.env`文件中的所有定义到`process.env`中。当然，如果您只想在开发中使用此功能（正如`dotenv`的创建者最初打算的那样），您可以先检查`isDev`变量，就像我们之前看到的那样：

```js
if (isDev) {
    dotenv.load();
}
```

环境文件不应上传到源代码控制，因此在您的`.gitignore`文件中添加一行`**/*.env`是有意义的。但是，您可以上传一个示例文件（比如`config.env.example`），但不包含环境变量的实际值；这将帮助新开发人员获取必要的文件，同时保护安全性。

您可以在[`github.com/motdotla/dotenv`](https://github.com/motdotla/dotenv)了解更多关于`dotenv`的信息。

# 单元测试您的代码

确保质量并保护自己免受回归错误（在修改某些内容并重新引入先前已纠正的错误时发生的错误）的最佳实践之一是确保您的代码经过*单元测试*。有三种类型的测试：

+   *单元测试*，适用于每个组件，各自独立

+   *集成测试*，适用于组件共同工作

+   ***端到端***（**E2E**）*测试*，适用于整个系统

单元测试很好——不仅因为它有助于尝试您的代码，而且因为如果做得好，就像**测试驱动设计**（**TDD**）一样，您基本上首先设置测试，然后再编写代码——因为它将有助于生成更高质量的代码，这肯定会对系统中的所有错误产生影响。（甚至在任何测试工作开始之前发现错误也是节省金钱的；您发现并修复错误的越早，成本就越低。）因此，让我们专注于如何在 Node 工作中使用单元测试。

当然，众所周知*测试可以证明错误的存在，但不能证明它们的不存在*，所以无论您做多少测试，都会有一些错误漏掉！当发生这种情况时，TDD 将使您首先创建一些新的单元测试来定位错误，然后才开始实际修复它；至少，特定的错误不会再次出现，因为它将被检测到。

有很多用于单元测试的工具和框架，在本书中我们将使用`Jest`，这是一个现代的*令人愉快的 JavaScript 测试*工具，它是由 Facebook 开发的。我们还有额外的优势，可以将它用于 React 或 React Native。安装非常简单，只需要`npm install jest --save-dev`。做完这些之后，我们就可以编写我们的测试了；让我们看看如何做。

您可以在官方网页上阅读更多关于`Jest`的信息，网址是[`facebook.github.io/jest/`](https://facebook.github.io/jest/)。

在这个配方中，我们将看看如何为`Node`编写单元测试，并为未来的章节获得有效的经验。

# 如何做...

编写单元测试可能更简单或更困难，这取决于您如何设计代码。如果您以清晰、无副作用的方式工作，那么编写功能测试将会非常简单。如果您开始添加诸如回调或承诺、数据库或文件系统等复杂性，那么您将需要更多的工作，因为您将不得不*模拟*其中一些元素；毕竟，您不想在生产数据库上运行测试，对吧？

在接下来的章节中，我们将看看如何编写单元测试，并学习如何处理一些特定的概念，如*模拟*或*间谍*。

# 进行功能测试

首先，让我们看一个简单的、基本的功能测试集，为此，让我们回到我们在第三章的*使用模块*部分编写的四舍五入库。当您测试一个模块时，您只测试导出的函数，看它们是否按照规格执行。然后，有趣的部分是测试以下内容：

```js
const addR = (x: number, y: number): number => roundToCents(x + y);

const subR = (x: number, y: number): number => addR(x, changeSign(y));

const multR = (x: number, y: number): number => roundToCents(x * y);

const divR = (x: number, y: number): number => {
    if (y === 0) {
        throw new Error("Divisor must be nonzero");
    } else {
        return roundToCents(x / y);
    }
};
```

这四个函数在功能上是完全的，因为它们的计算结果仅取决于它们的输入参数，并且它们绝对没有副作用。编写测试需要（1）定义测试组，和（2）在每个组中包含一个或多个测试。在这里，为每个函数编写一个组是有意义的，所以让我们看看代码可能是怎样的；我们可以从`addR()`函数开始，然后写出类似这样的东西：

```js
// Source file: src/roundmath.test.js

/* @flow */
"use strict";

const rm = require("./roundmath");

describe("addR", () => {
    it("should add first and round later", () => {
        expect(rm.addR(1.505, 2.505)).toBe(4.01);
    });

    it("should handle negatives", () => {
        expect(rm.addR(3.15, -2.149)).toBe(1.0);
    });
});

// *continues...*
```

最常见的风格是将单元测试文件命名为与被测试文件相同的方式，只是在文件扩展名之前添加`"test"`或`"spec"`。在我们的情况下，对于`roundmath.js`，我们将单元测试文件命名为`roundmath.test.js`。至于放置位置，`Jest`能够找到您的测试，无论您将它们放在何处，所以通常的做法是将这个新文件放在原始文件旁边，以便找到它。

每个`describe()`调用定义了一个组，其中的每个`it()`调用定义了一个特定的测试。如果测试失败，Jest 将报告它，给出组和测试的描述，如“addR 应该先添加，然后再四舍五入”。测试包括（1）设置事物，如果需要的话；（2）通过调用函数实际运行测试；和（3）检查函数是否按我们的预期执行。

我们编写的第一个测试验证了当添加数字时，应该先进行加法，然后再进行四舍五入；先进行四舍五入，然后再进行加法是不正确的。我们通过调用`addR(1.505, 2.505)`来测试这一点，我们期望结果是`4.01`；如果函数先进行了四舍五入，结果将会是`4.02`。每个测试都应该能够验证函数的至少一个属性；我们的第二个测试检查`addR()`是否能够处理负数。

您编写关于代码的假设的风格旨在易于阅读：*期望某某是某个值*。诸如`toBe()`或`toThrow()`（见我们的下一个示例）的方法称为匹配器；有关更多信息，请参阅[`facebook.github.io/jest/docs/en/expect.html`](https://facebook.github.io/jest/docs/en/expect.html)上的相当长的列表。

当然，对于复杂的代码，可能只有几个测试是不够的，通常会有更多的测试，但是作为一个例子，这些就足够了。请注意，我们应该为所有函数编写测试；例如，`divR()`可以使用类似这样的东西。虽然第一个测试非常直接（类似于`addR()`的测试），但在第二个测试中，我们验证调用`divR()`时，如果除数为零，应该抛出异常：

```js
// ...*continued*

describe("divR", () => {
    it("should divide first, then round", () => {
        expect(rm.divR(22.96, 0.001)).toBe(22960);
    });

    it("should not divide by zero", () =>
        expect(() => rm.divR(22, 0)).toThrow());
});
```

如果您错过了一些函数或它们的一部分，稍后在本章中，我们将看看如何检测到；现在不要担心。此时，我们将继续编写测试，然后运行完整的测试套件。

# 使用间谍

我们编写的功能测试非常好，但在某些情况下不适用，比如当您使用回调时。让我们转向另一段我们编写的代码：我们用于 JWT 的用户验证例程。基本上，这个函数接收一个用户名、一个密码和一个错误回调，用于表示用户名是否真的有这个密码。我们编写了非常基本的验证代码（只接受一个用户！），但这里并不重要；我们想看看如何处理回调。我们现在关心的重要部分在以下代码片段中突出显示：

```js
const validateUser = (
    userName: string,
    password: string,
    callback: (?string, ?string) => void) => {
    if (!userName || !password) {
        callback("Missing user/password", null);
    } else if (userName === "fkereki" && password === "modernjsbook") {
        callback(null, "fkereki"); // OK, send userName back
    } else {
        callback("Not valid user", null);
 }
};
```

测试这将需要实际传递一个回调，然后尝试看它是如何被调用的；这是可以做到的，但细节会很混乱。或者，我们可以有一个间谍——一个虚拟函数，稍后我们可以询问它是否被调用，以及它是如何被调用的，以及更多：

```js
// Source file: validate_user.test.js

/* @flow */
"use strict";

const validateUser = require("./validate_user");

describe("validateUser", () => {
    let cb;
    beforeEach(() => {
        cb = jest.fn();
    });

    it("should reject a call with empty user", () => {
        validateUser("", "somepass", cb);
        expect(cb).toHaveBeenCalled();
        expect(cb).toHaveBeenCalledWith("Missing user/password", null);
    });

    it("should reject a wrong password", () => {
        validateUser("fkereki", "wrongpassword", cb);
        expect(cb).toHaveBeenCalledWith("Not valid user", null);
    });

    it("should accept a correct password", () => {
        validateUser("fkereki", "modernjsbook", cb);
        expect(cb).toHaveBeenCalledWith(null, "fkereki");
    });
});
```

我们可以通过调用`jest.fn()`来创建这样的间谍。由于我们将为每个测试编写一个新的间谍，我们可以利用`beforeEach()`函数，Jest 将在运行每个单独的测试之前自动调用它；这将节省一些额外的编写。实际上有四个函数可以使用，如下所示：

+   `beforeAll()`将在开始测试之前只调用一次；例如，您可以在这里设置一个测试数据库并填充它的某些数据

+   `beforeEach()`将在每个测试之前调用，就像我们在示例中创建间谍时所做的那样。

+   `afterEach()`将在每个测试后调用，以*清理*

+   `afterAll()`将在运行所有测试后调用；例如，您可以销毁仅用于测试目的创建的测试数据库

这三个测试都是类似的；我们将选择第一个。我们调用验证例程，但传递一个空参数。根据验证规范，这应该创建一个错误。通过这样做，我们可以测试回调是否真的被调用，并且它是通过传递一个错误作为第一个参数，以及作为第二个参数传递了什么来调用的。

（当然，第一个测试使用`.toHaveBeenCalled()`匹配器是不需要的，因为第二个测试测试了它是否使用特定值调用，但我们只是想展示一个新的匹配器对。）

如果我们只关心看一个给定的函数是否被调用，使用间谍是非常实用的，但是如果被测试的函数实际上需要从我们的间谍那里返回一些值会发生什么？我们也可以解决这个问题；让我们进入一个更复杂的例子。

# 使用模拟

让我们最后使用一个更复杂的例子来工作——一个处理与地区相关的 REST 代码的部分，它需要一个数据库并使用承诺，还有其他几个复杂情况。让我们以`DELETE`方法处理程序为例：

```js
const deleteRegion = async (
    res: any,
    dbConn: any,
    country: string,
    region: string
) => {
    try {
        const sqlCities = `
            SELECT 1 FROM cities 
            WHERE countryCode="${country}" 
            AND regionCode="${region}" 
            LIMIT 1 
        `;

        const cities = await dbConn.query(sqlCities);

        if (cities.length > 0) {
            res.status(405).send("Cannot delete a region with cities");
        } else {
            const deleteRegion = `
                DELETE FROM regions 
                WHERE countryCode="${country}" 
                AND regionCode="${region}"
            `;

            const result = await dbConn.query(deleteRegion);

            if (result.info.affectedRows > 0) {
                res.status(204).send();
            } else {
                res.status(404).send("Region not found");
            }
        }
    } catch (e) {
        res.status(500).send("Server error");
    }
};
```

通过将数据库连接（`dbConn`）作为参数传递给函数，我们做对了一些事情。这意味着我们可以*模拟*它——也就是提供一个替代版本，它将按照我们的意愿行事，但实际上不使用任何数据库。同样，处理我们的请求将需要模拟一个响应对象（`res`），我们将要检查其状态码；我们可以手工编码，但使用`node-mocks-http`包更简单，所以只需使用`npm install node-mocks-http --save`进行安装。查看其文档[`github.com/howardabrams/node-mocks-http`](https://github.com/howardabrams/node-mocks-http)，获取更多信息——它可以做更多！

我们知道`DELETE`方法应该（1）确认要删除的区域不能有城市，（2）如果是真的，那么就删除该区域。我们如何测试第一个检查是否有效？让我们为`deleteRegion()`提供一个模拟，它会说我们想要删除的区域实际上有一些城市：

```js
// Source file: src/restful_regions.test.js

/* @flow */
"use strict";

const { deleteRegion } = require("./restful_regions");
const mockRes = require("node-mocks-http");

describe("deleteRegion", () => {
    let mDb;
    let mRes;
    beforeEach(() => {
        mDb = { query: jest.fn() };
        mRes = new mockRes.createResponse();
    });

    it("should not delete a region with cities", async () => {
        mDb.query.mockReturnValueOnce(Promise.resolve([1]));
        await deleteRegion(mRes, mDb, "FK", "22");
        expect(mRes.statusCode).toBe(405);
    });

// *continues*...
```

我们可以编写一个完整的模拟数据库，分析传入的查询，然后提供一些预期的答案，但在这种情况下，对代码如何检查城市有一些了解是很有帮助的。我们可以创建一个带有查询属性（`mDb.query`）的模拟数据库对象，并设置当第一次调用`mDb.query()`时，它将返回一个解析为包含单个 1 的数组的 promise——因为这就是实际的 SQL 语句在检查实际包含一些城市的区域时会产生的结果。我们还将创建一个模拟响应对象（`mRes`），它将得到例程的答复。

还剩下什么要做？你只需要调用`deleteRegion()`函数并传入所有参数，`await`其结果，并验证响应状态码是否为 405，然后你就完成了！

其他测试类似，但我们必须模拟两个 SQL 访问，而不是一个：

```js
// ...*continued*

    it("should delete a region without cities", async () => {
        mDb.query
 .mockReturnValueOnce(Promise.resolve([]))
 .mockReturnValueOnce(
 Promise.resolve({
 info: { affectedRows: 1 }
 })
 );
        await deleteRegion(mRes, mDb, "ST", "12");
        expect(mRes.statusCode).toBe(204);
    });

    it("should produce a 404 for non-existing region", async () => {
        mDb.query
            .mockReturnValueOnce(Promise.resolve([]))
            .mockReturnValueOnce(
                Promise.resolve({
                    info: { affectedRows: 0 }
                })
            );
        await deleteRegion(mRes, mDb, "IP", "24");
        expect(mRes.statusCode).toBe(404);
    });
});
```

有趣的是，我们可以设置一个模拟函数，每次调用时产生不同的答案，根据我们的需要。因此，为了测试`deleteRegion()`是否能正确删除没有城市的区域，我们的模拟 DB 对象必须执行以下操作：

+   首先，返回一个空数组，显示要删除的区域没有城市

+   其次，返回一个带有`affectedRows:1`的对象，显示（假设的）`DELETE` SQL 命令成功了

设置完这些后，其余的代码就像我们的第一个案例一样；等待函数并检查状态码。

# 它是如何工作的...

为了运行测试，我们需要编辑`package.json`中的一个脚本。更改`"test"`脚本，到目前为止只有一个错误消息，所以它将读取如下内容：

```js
 "test": "jest out/"
```

`"test"`脚本可以通过输入`npm test`来运行。在我们的案例中，由于我们的输出代码进入`out/`目录，我们告诉 Jest 检查该目录，并运行它可以找到的所有测试（默认情况下是`*.test.js`文件）。你可以修改 Jest 的配置以适应更特定的情况，但总的来说，它在*零配置*的情况下工作得很好。输出简洁实用，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/2759c870-b28f-4bad-9c53-ca83f4232aaf.png)

npm test 命令的结果简洁明了

在我们的案例中，匹配我们所做的，它显示我们运行了三套测试，总共包括 10 个测试，它们都通过了。如果一个或多个测试产生了错误的结果，我们将得到另一种结果，有很多红色。我故意修改了一个测试，以便它失败，以下输出是结果：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/23ee0762-814f-48a3-9f1f-db97e5f150e8.png)

修改一个测试以使其失败，并运行 Jest，会产生一个包括未达预期、失败测试等的列表

在上述屏幕截图中，我们可以看到一个测试失败，在`restful_regions.test.js`文件中，显示期望获得 204 结果，但实际收到了 404 错误。该文件标有红色的`FAIL`消息；其他两个文件标有绿色的`PASS`。在我们的情况下，这是因为我们故意编写了一个失败的测试，但在现实生活中，如果测试之前一切正常，现在失败了，这意味着有人搞乱了代码并意外引入了错误。（公平地说，还存在测试当时不完全正确，而被测试的函数实际上是正确的可能性！）无论如何，获得红色结果意味着代码不能被视为准备就绪，需要更多的工作。

# 还有更多....

如果您需要模拟一些无法（或不愿意）将其作为参数注入到函数中的包，可以向 Jest 提供完整的模拟版本。假设您想要模拟`"fs"`包：您将首先在`node_modules`的同一级别创建一个`__mocks__`目录，然后在那里编写和放置您的手动模拟代码，最后您将在测试文件的开头指定`jest.mock("fs")`，以便`Jest`将使用您的模块而不是标准模块。

所有这些都可能变成一项琐事，所以最好尝试将所有模块作为参数提供给您的函数（就像我们在删除区域时使用`dbConn`一样），以便可以使用标准模拟。但是，如果您无法这样做，请查看[`facebook.github.io/jest/docs/en/manual-mocks.html`](https://facebook.github.io/jest/docs/en/manual-mocks.html)获取更多信息。

# 测量您的测试覆盖率

好吧，您已经编写了很多测试，但实际上您测试了多少代码？这种测试质量（广度）的度量称为*覆盖率*，并且很容易确定；在本教程中，让我们找出如何做到这一点。幸运的是，鉴于我们所做的所有工作，这将是一个非常简单的教程。

# 如何做...

要使`Jest`生成覆盖率报告，显示哪些部分的代码被您的测试覆盖（或未覆盖），您只需在`package.json`文件中的相应脚本中添加一对参数即可：

```js
 "test": "jest out/ --coverage --no-cache"
```

在上一行代码中，第一个参数`--coverage`告诉`Jest`收集所有必要的信息，第二个参数`--no-cache`确保所有信息都是最新的；在某些情况下，当省略此参数时，可能会产生不完全正确的结果。这如何影响测试？让我们看看！

# 它是如何工作的...

使用覆盖率运行`Jest`的关键区别是控制台中添加了不同的报告，并且还构建了一个 HTML 页面。首先，让我们检查前者：查看以下屏幕截图-再次，我承认在黑白中看到颜色真的很难！

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/d757eb05-b88d-4248-996e-0e0cd50becf5.png)

在运行 Jest 时包括覆盖率选项会产生对测试的更详细的分析

对于每个文件，您将获得以下信息：

+   `％Stmts`：由于您的测试至少执行了一次的语句百分比。理想情况下，每个语句都应该至少执行一次；否则，任何未执行的语句都可能是任何内容，您都不会意识到。

+   `％Branch`：采取的分支百分比。这与`％Stmts`的推理类似-如果有一些分支（例如，else）从未被采取，这意味着您的代码中存在一些可能执行任何操作的路径。

+   `％Funcs`：文件中调用的函数百分比。

+   `％Lines`：覆盖的行数百分比。请注意，一行可能有几个语句，因此`％Lines`始终大于或等于`％Stmts`。

+   `未覆盖的行号`：这不是行数（几十亿！？），而是从未执行的特定行的数字。

在我们的案例中，我们发现`validate_user.js`中的所有函数都经过了测试，但是`roundmath.js`中的一半函数被忽略了（我们测试了`addR()`和`divR()`，但忘记了`subR()`和`multR()`，所以是正确的），而`restful_regions.js`中只测试了一个函数（`DELETE`处理程序）。获得更好的覆盖率意味着更多的工作，而且从经济角度来看，追求 100%可能并不总是明智的（80%-90%是常见的），但 25%或 50%绝对太低了，因此需要更多的工作。

更有趣的部分是，您可以通过查看项目的`coverage/lcov_report/`目录并在浏览器中打开`index.html`来深入分析测试运行情况，如下面的屏幕截图所示：

！[](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/9a5cc820-34f4-46f8-ac51-3d304b3e030b.png)

Web 覆盖率报告的主页显示的数据基本上与控制台运行相同

首先，您可以看到不同颜色的文件：通常，红色表示不太好的结果，绿色是最好的结果。有趣的部分是，如果您点击文件，您将获得详细的分析，包括每一行，是否执行或未执行等：

！[](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/b33abb0b-42aa-4653-8a5b-b1874ca5dae5.png)

您可以看到哪些行被执行，哪些被忽略，以及为什么没有达到 100%

在我们的案例中，即使我们认为我们已经覆盖了`deleteRegion()`中的所有情况，屏幕显示我们错过了一个可能的情况：SQL 服务器无法回答。当然，是否为此包含特定测试是您必须做出的决定：至少我们可以看到所有最重要的代码都被覆盖了，但不要忘记同一文件中未经测试的其他函数！

# 调试您的代码

在某个时候，您将不得不调试您的代码。您可能只需使用一点日志记录就足够了（使用控制台对象，正如我们在*使用 Winston 添加日志记录*部分中所看到的那样），但使用更强大的调试器会很有帮助。在这个教程中，让我们看看如何使用断点、变量检查等进行实时调试，这样您就不会仅仅通过查看控制台日志来推断出问题所在。

# 如何做...

有两种调试方法；让我们在这里看看这两种方法。

如果您只想留在您的 IDE 中，Visual Studio Code 允许您直接开始调试会话。只需单击要运行的代码（提醒：选择 out/目录中的代码，并不要忘记使用`npm run build`），然后在菜单中选择 Debug | Start Debugging。窗口将如下所示：

！[](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/581706b5-7073-4c25-9a07-27c979ddf08d.png)

您可以在 Visual Studio Code 中直接开始调试会话

或者，如果您宁愿继续使用 Chrome 的您最喜欢的开发人员工具，那么您可以使用另一种方法。首先，在 Chrome 中，搜索`N.I.M.`，*Node.js V8 Inspector Manager*，可以在[`chrome.google.com/webstore/detail/nodejs-v8-inspector-manag/gnhhdgbaldcilmgcpfddgdbkhjohddkj`](https://chrome.google.com/webstore/detail/nodejs-v8-inspector-manag/gnhhdgbaldcilmgcpfddgdbkhjohddkj)找到，并将其添加到您的浏览器中。

这样做后，通过转到`about:inspect`打开`N.I.M.`控制台，您将获得如下屏幕截图所示的内容：

！[](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/2a6771ba-1e14-40f8-804d-f7125f58e909.png)

N.I.M.扩展允许您使用 Chrome 的开发人员工具调试 Node 会话

现在，您只需转到 VSC 或 shell 会话，并运行您的代码。在执行此操作之前，添加`--inspect`选项，如`node --inspect out/restful_server.js`。您将收到以下输出：

！[](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/1d034af3-ca27-4439-ba1a-cdf3a2594935.png)

要将 Node 连接到 Chrome 的开发人员工具，您必须使用额外的`--inspect`选项运行您的代码

之后，将打开一个窗口，您将完全访问 Chrome 的调试器控制台，如下面的屏幕截图所示：

如果您在 Chrome 的调试器中检查 URL，您会看到类似`chrome-devtools://devtools/bundled/inspector.html?experiments=true&v8only=true&ws=...`的东西，后面跟着一个 URL 和一个（长）十六进制数。这些值在运行`Node`时使用`--inspect`列出，在以"Debugger listening on ws..."开头的行中。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/7aa4099c-240d-43ae-bee1-e6ed3be30038.png)

如果 N.I.M.已启用，您的 Node 会话将连接到它，并且您将能够从 Chrome 内部调试您的代码

最后，在任何情况下，您都准备好开始一个严肃的调试会话；让我们看看您能做些什么。

如果您想了解代码检查的工作原理，请阅读以下文章：[`nodejs.org/en/docs/guides/debugging-getting-started/`](https://nodejs.org/en/docs/guides/debugging-getting-started/)。这也为您提供了在其他 IDE 中进行调试的提示。

# 它是如何工作的...

在前面的屏幕截图中，无论是 VSC 还是 Chrome，我都打开了`out/restful_regions.js`文件，并在进行`SELECT`以获取一些地区的地方设置了一个断点。对`/regions/uy`的请求导致运行在这一点暂停。然后您可以执行以下操作：

+   检查所有变量，包括块、局部和全局变量——这包括修改它们的值的可能性，如果您想的话

+   添加一些变量或表达式以进行监视；每当执行暂停时，您将看到它们的值

+   查看调用堆栈

+   设置一些特定的断点

关于程序执行，您可以执行以下操作：

+   在任何断点处停止执行

+   重新开始执行

+   逐步执行您的代码，选择*下钻*以分析函数调用

如果您使用 Chrome，您将能够获得一些额外的选项，比如内存使用分析或代码执行分析，但显然这些特定于 Web 的选项不会有任何好处。然而，通过使用检查选项来调试您的代码是一个非常好的帮助，所以要习惯它；您会非常感激它！

# 从命令行测试简单服务

每当您创建服务时，您都需要一种测试它们的方法。到目前为止，我们已经看到了一些使用`curl`进行测试的例子。因此，在这个教程中，让我们深入一点，看看一些您可能会发现有用的选项。或者，您可以选择另一个工具，比如`wget`。对于我们的目的，这两个选项都差不多，允许我们做我们需要的 RESTful 服务测试：它们是可脚本化的，它们可以下载东西，它们也可以发送请求来发布数据，所以您使用的将主要是个人偏好的问题。

如果您想了解更多关于`curl`的信息，请访问其网站[`curl.haxx.se/`](https://curl.haxx.se/)，或者查看源代码[`github.com/curl/curl`](https://github.com/curl/curl)。您可能还对*Everything Curl*感兴趣，这是一本详细介绍这个工具的书籍，可以在[`www.gitbook.com/download/pdf/book/bagder/everything-curl`](https://www.gitbook.com/download/pdf/book/bagder/everything-curl)免费获取——但是，请注意它有 300 多页长！

# 准备工作

如何安装`curl`将取决于您的操作系统，但它几乎适用于您可能使用的每个平台；只需查看[`curl.haxx.se/download.html`](https://curl.haxx.se/download.html)上的所有下载。该命令有数十种可能的选项，但对于我们的意图，我们将查看以下表格。请注意，大多数选项都有两个版本：一个短的，单个字符的版本，和一个更长的版本，旨在更清晰地理解：

| `-K filename``--config filename` | 允许您指定一个包含选项的文件的名称，以便您的命令更短。在给定的文件中，每个选项将在不同的行中。 |
| --- | --- |
| `-d key=value``--data key=value` | 允许您在请求的正文中发送数据。如果您多次使用此选项，`curl`将使用`&`作为分隔符，作为标准。 |
| `--data-binary someData` | 类似于`--data`，但用于发送二进制数据。最常见的是后面跟着`@filename`，意思是将发送命名文件的内容。 |
| `-D filename``--dump-header filename` | 将接收到的数据的标头转储到文件中。 |
| `-H "header:value"``--header "header:value"` | 允许您设置并发送请求的某些标头。您可以多次使用此选项来设置多个标头。 |
| `-i``--include` | 在输出中包含接收数据的标头。 |
| `-o filename``--output filename` | 将接收到的数据存储在给定的文件中。 |
| `-s``--silent` | 最小化控制台输出。 |
| `-v``--verbose` | 最大化控制台输出。 |
| `-X method``--request method` | 指定将使用的 HTTP 方法，例如`GET`、`POST`、`PUT`等。 |

最后，如果您需要帮助，请使用`curl --help`或`curl --manual`，您将得到该实用程序及其选项的完整描述。现在让我们看看如何使用`curl`来测试我们的服务。

# 如何做到...

让我们为上一章中创建的 RESTful 服务器进行一整套测试，包括 JWT 在内的所有选项都已启用，您会记得，我们为了简化代码而删除了 JWT！让我们按照以下步骤进行：

首先，我们可以验证服务器是否正在运行；`/`路由不需要令牌。请记住我们使用的是`8443`，实际上是 HTTPS：请求将发送到该端口：

```js
> curl localhost:8443/
Ready
```

现在，如果我们尝试访问某个区域，我们将被拒绝，因为缺少授权的 JWT：

```js
> curl localhost:8443/regions/uy/10 
No token specified

```

+   如果该行以`*`开头，则是`curl`本身的一些信息

+   如果该行以`>`开头，则是请求中发送的标头

+   如果该行以`<`开头，则是接收到的标头

在下面的清单中，我突出显示了传入的数据：

```js
> curl localhost:8443/regions/uy/10 --verbose
* Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 8443 (#0)
> GET /regions/uy/10 HTTP/1.1
> Host: localhost:8443
> User-Agent: curl/7.59.0
> Accept: */*
> 
< HTTP/1.1 401 Unauthorized
< X-Powered-By: Express
< Access-Control-Allow-Origin: *
< Connection: close
< Content-Type: text/html; charset=utf-8
< Content-Length: 18
< ETag: W/"12-s2+Ia/H9PDrgc59/6Z0mcWLfxuw"
< Date: Sun, 03 Jun 2018 21:00:40 GMT
< 
* Closing connection 0
No token specified
```

我们可以通过使用`/gettoken`路由并提供`user`和`password`值来获取令牌。让我们将接收到的令牌存储在一个文件中，以简化未来的测试。

```js
> curl localhost:8443/gettoken -d "user=fkereki" -d "password=modernjsbook" -o token.txt 
 % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current 
 Dload  Upload   Total   Spent    Left  Speed 
100   187  100   153  100    34   149k  34000 --:--:-- --:--:-- --:--:--  182k 

> cat token.txt 
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiJma2VyZWtpIiwiaWF0IjoxNTI4MDU5Nzc0LCJleHAiOjE1MjgwNjMzNzR9.6tioV798HHqriOFkhUpf8xJc8wq5TY5g-jN-XhgwaTs

```

现在我们可以尝试一个简单的`GET`。我们可以在标头中剪切和粘贴令牌，或者在 Linux 系统中至少使用一些 shell 功能，并利用反引号选项将令牌文件的内容包含在请求中：

```js
> curl localhost:8443/regions/uy/10 -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiJma2VyZWtpIiwiaWF0IjoxNTI4MDU5Nzc0LCJleHAiOjE1MjgwNjMzNzR9.6tioV798HHqriOFkhUpf8xJc8wq5TY5g-jN-XhgwaTs" 
[{"countryCode":"UY","regionCode":"10","regionName":"Montevideo"}]

> curl localhost:8443/regions/uy/10 -H "Authorization: Bearer `cat token.txt`" 
[{"countryCode":"UY","regionCode":"10","regionName":"Montevideo"}]

```

我们所剩下的就是尝试其他路由和方法。让我们将蒙得维的亚的名称更改为 MVD，实际上这是其国际机场的 IATA 代码；我们首先进行`PUT`（应该产生一个 204 状态码），然后进行`GET`以验证更新：

```js
> curl localhost:8443/regions/uy/10 -H "Authorization: Bearer `cat token.txt`" -X PUT -d "name=MVD" --verbose 
*   Trying 127.0.0.1... 
* TCP_NODELAY set 
* Connected to localhost (127.0.0.1) port 8443 (#0) 
> PUT /regions/uy/10 HTTP/1.1 
> Host: localhost:8443 
> User-Agent: curl/7.59.0 
> Accept: */* 
> Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiJma2VyZWtpIiwiaWF0IjoxNTI4MDU5Nzc0LCJleHAiOjE1MjgwNjMzNzR9.6tioV798HHqriOFkhUpf8xJc8wq5TY5g-jN-XhgwaTs 
> Content-Length: 8 
> Content-Type: application/x-www-form-urlencoded 
> 
* upload completely sent off: 8 out of 8 bytes 
< HTTP/1.1 204 No Content 
< X-Powered-By: Express 
< Access-Control-Allow-Origin: * 
< Connection: close 
< Date: Sun, 03 Jun 2018 21:09:01 GMT 
< 
* Closing connection 0

> curl localhost:8443/regions/uy/10 -H "Authorization: Bearer `cat token.txt`"
[{"countryCode":"UY","regionCode":"10","regionName":"MVD"}]

```

在一个实验中，我创建了一个新的区域，编号为 20。让我们删除它，并验证它是否已经消失，然后再进行另一个`GET`。第一个请求应该得到一个 204 状态，第二个请求应该得到一个 404，因为该区域将不再存在：

```js
> curl localhost:8443/regions/uy/20 -H "Authorization: Bearer `cat token.txt`" -X DELETE --verbose  
*   Trying 127.0.0.1... 
* TCP_NODELAY set 
* Connected to localhost (127.0.0.1) port 8443 (#0) 
> DELETE /regions/uy/20 HTTP/1.1 
> Host: localhost:8443 
> User-Agent: curl/7.59.0 
> Accept: */* 
> Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOiJma2VyZWtpIiwiaWF0IjoxNTI4MDU5Nzc0LCJleHAiOjE1MjgwNjMzNzR9.6tioV798HHqriOFkhUpf8xJc8wq5TY5g-jN-XhgwaTs 
> 
< HTTP/1.1 204 No Content 
< X-Powered-By: Express 
< Access-Control-Allow-Origin: * 
< Connection: close 
< Date: Sun, 03 Jun 2018 21:12:06 GMT 
< 
* Closing connection 0 

> curl localhost:8443/regions/uy/20 -H "Authorization: Bearer `cat token.txt`" -X DELETE --verbose  
.
. *several lines snipped out*
.
< HTTP/1.1 404 Not Found 
.
. *more snipped lines*
.
Region not found

```

最后，让我们发明一个新的区域来验证`POST`也起作用；应该返回 201 状态，以及新的 ID（在我们删除了之前发明的第 20 个乌拉圭区域后，应该是 20）：

```js
> curl localhost:8443/regions/uy -H "Authorization: Bearer `cat token.txt`" -X POST -d "name=Fictitious" --verbose 
.
. *lines snipped out*
.
< HTTP/1.1 201 Created 
< X-Powered-By: Express 
< Access-Control-Allow-Origin: * 
< Connection: close 
< Location: /regions/uy/20 
.
. *snipped lines*
.
Region created

> curl localhost:8443/regions/uy -H "Authorization: Bearer `cat token.txt`" 
[{"countryCode":"UY","regionCode":"1","regionName":"Artigas"},{"countryCode":"UY","regionCode":"10","regionName":"MVD"},
.
. *snipped out lines*
.
{"countryCode":"uy","regionCode":"20","regionName":"Fictitious"},
.
. *more snipped out lines*
.
{"countryCode":"UY","regionCode":"9","regionName":"Maldonado"}]

```

因此，通过使用`curl`和一些控制台工作，我们可以开始测试任何类型的服务。然而，在某些时候，您可能需要处理更复杂的服务调用序列，并且手动完成所有这些工作可能会变得繁琐。通过谨慎的脚本编写，您可以简化工作，但让我们考虑另一个工具 Postman，它更适合这种工作。

# 使用 Postman 测试更复杂的调用序列

手动测试服务，甚至使用精心制作的 shell 脚本也不是很容易。此外，如果您需要进行某种复杂的测试，使用脚本可能会变得太难。`Postman`可以用来为服务编写测试，将它们组织成完整的测试套件，并记录您的 RESTful API 的工作方式。您还可以用它来模拟服务或作为开发的帮助，但我们不会在这里讨论这些。在这个配方中，我们将专注于测试方面。

# 准备就绪

从[`www.getpostman.com/`](https://www.getpostman.com/)下载`Postman`，并根据每个平台的说明进行安装。记得查看其文档，了解更多我们这里不会看到的功能。

# 如何做...

Postman 允许您创建可以存储在集合中的请求。在每个请求之前和之后，您可以执行 JavaScript 代码，无论是为即将到来的请求设置，处理结果响应，还是为测试序列中未来的请求存储一些信息。让我们看看以下部分。

# 进行基本请求

首先，我们将从一个简单的测试开始，以获取 JWT，然后将其存储，以便我们可以在即将进行的测试中使用。打开`Postman`应用程序，点击 New 创建一个请求。给它一个名称和描述，然后选择或创建一个集合或文件夹来保存它。不要太担心实际的放置位置；您可以移动请求，编辑它们，等等。

然后，为了获取令牌，我们需要一个`POST`，所以设置方法。选择 BODY 选项卡，选择`x-www-form-urlencoded`选项，并添加两个值，`user`和`password`，这些值将随请求一起发送。（对于其他情况，您可能会发送原始数据，如 XML 或 JSON，或二进制数据，如文件。）查看以下截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/3487874e-670b-4b7c-a13d-f3f44f017af6.png)

创建一个 POST 请求来获取 JWT

现在，如果您点击发送进行测试，请求将发送到服务器，答复将出现在屏幕底部：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/cf772a36-3196-4c25-acfe-e4f755049fa1.png)

我们的请求测试显示一切正常运行

# 添加一些检查

然而，这还不够。我们不仅想检查`/gettoken`端点是否工作，我们还想测试令牌是否正确，并且如果正确，存储它以便后续请求可以使用。我们将创建一个环境（点击右上角的齿轮图标）并添加一个`token`条目，以便我们可以存储和检索从服务器获取的值：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/a6954463-3113-468a-866b-b12194276ba3.png)

创建环境是您可以在请求之间共享数据的一种方式

最后，让我们为令牌编写一些测试，并将其值存储在环境中。编写测试本身与我们已经做过的有些类似，但您需要查看文档，了解可用的对象和方法。至于测试本身，它们使用`Chai`（参见[`www.chaijs.com/`](http://www.chaijs.com/)），在编写您的期望方面类似于`Jest`，但并非完全相同：

```js
pm.test("Response is long enough", () => 
    pm.expect(pm.response.text()).to.have.lengthOf.above(40)); 

pm.test("Response has three parts", () => 
    pm.expect(pm.response.text().split(".")).to.have.lengthOf(3));

pm.environment.set("token", pm.response.text()); // for later scripts
```

首先，我们将测试答复至少应该有 40 个字节长；令牌没有特定的大小限制，但 40 个字符偏低。然后，第二个测试将检查令牌由三部分组成，由句点分隔。最后，我们将把响应本身存储在环境中，以备将来使用。如果您检查 TESTS 选项卡，您会看到我们的两个测试都通过了，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/3f82702e-4cd4-4d3e-b00d-6047f7b378d4.png)

我们创建的两个测试都成功了

# 链接请求

如果您检查环境，您会看到令牌已经存储。现在让我们写一个第二个测试，一个`GET`，将使用令牌。我通过对`/regions/uy`进行请求，但我在标头中添加了一行，使用`Authorization`键和`Bearer {{token}}`值，以便以前存储的令牌值将替换标头中的值。我还添加了一些测试，以确保（1）我得到了成功的 JSON 答复，以及（2）答复是至少 19 个地区的数组。（是的，我知道我的国家乌拉圭确实有 19 个地区，但有时，出于测试目的，我可能会添加一些新的！）这些测试显示了一些我们以前没有见过的功能：

```js
pm.test("Answer should be JSON", () => {
    pm.response.to.be.success;
    pm.response.to.have.jsonBody(); 
});

pm.test("Answer should have at least 19 regions", () => {
    const regions = JSON.parse(pm.response.text());
    pm.expect(regions).to.have.lengthOf.at.least(19);
});
```

通过这种方式，您可以创建完整的请求序列；确保获取 JWT 放在列表中较早的位置。在一个集合中，您还可以有许多文件夹，每个文件夹都有一个不同的步骤序列。（您也可以通过程序更改序列，但我们不会在这里讨论这个问题；请查看[`www.getpostman.com/docs/v6/postman/scripts/branching_and_looping`](https://www.getpostman.com/docs/v6/postman/scripts/branching_and_looping)获取更多信息。）

我创建了两个文件夹来测试一些`GET`和一个`DELETE`，但是，当然，您应该编写更多的测试来验证每种方法，以及尽可能多的不同序列。让我们看看如何使它们运行。

# 工作原理...

一旦您将请求组织到文件夹中，您可以通过单击左侧边栏上的文件夹来运行任何给定的序列。如果一切正常，所有测试都将获得绿色标记；红色标记表示存在问题：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/4c6ba089-e7b6-4de0-8c9f-acaabd7f706b.png)

运行一个集合会运行其中的每个测试。绿色块表示成功；红色块表示错误。

有了这个，您已经有了一个很好的工具来记录您的 API（确保每个测试和字段都有解释），并确保它保持工作状态，超越单元测试进入完整的端到端（E2E）测试。

根据您的`Postman`帐户，您还可以设置定期监视您的 API；请查看[`www.getpostman.com/docs/v6/postman/monitors/intro_monitors`](https://www.getpostman.com/docs/v6/postman/monitors/intro_monitors)获取更多信息。

# 还有更多...

通过使用`newman`包（使用`npm install newman --save-dev`进行安装），您可以从命令行运行您的`Postman`测试，这也可以让您将其包含在持续集成工作流程中。首先，从`Postman`中导出您的集合（我无聊地称之为`postman_collection.json`），然后在您的`package.json`文件中添加一个名为`"newman":"newman run postman_collection.json"`的新脚本。然后使用`npm run newman`将产生类似于以下代码片段中所示的输出。您还可以测试所有测试是否都运行良好，或者是否存在问题：

```js
> npm run newman

> simpleproject@1.0.0 newman /home/fkereki/MODERNJS/chapter05
> newman run postman_collection.json

newman

Restful server testing for regions

❏ Test Delete
↳ Get JWT
  POST localhost:8443/gettoken [200 OK, 386B, 14ms]
  ✓ Response is long enough
  ✓ Response has three parts

↳ Delete non-existing region
  DELETE localhost:8443/regions/zz/99 [404 Not Found, 255B, 4ms]
  ✓ Status code is 404 baby!!

❏ Test Get
↳ Get JWT
  POST localhost:8443/gettoken [200 OK, 386B, 2ms]
  ✓ Response is long enough
  ✓ Response has three parts

↳ Get /regions/uy
  GET localhost:8443/regions/uy [200 OK, 1.46KB, 2ms]
  ✓ Answer should be JSON
  ✓ Answer should have at least 19 regions

↳ Get /regions/uy/10
  GET localhost:8443/regions/uy/11 [200 OK, 303B, 2ms]
  ✓ Answer has a single region
  ✓ Country code is UY
  ✓ Region code is 11
  ✓ Region name is Paysandu
  ✓ Answer is valid, JSON

```

# 使用 Swagger 文档和测试您的 REST API

现在让我们更专注于使用一个众所周知的工具进行文档编写和测试：`Swagger`。这是一个旨在帮助您设计、建模和测试 API 的工具。关键思想是，最终您将拥有一个在线交互式文档，其中将详细描述所有 API 调用、参数类型和限制、必需和可选值等，甚至让您可以即时尝试调用，以更好地理解 API 的使用方式。

# 如何做...

设置`Swagger`的第一步，也是最难的一步是准备完整 API 的规范。这意味着要用**YAML Ain't Markup Language**（YAML）编写，可能很难搞定。但是，您可以使用 Web 编辑器，可以在自己的服务器上运行（转到[`swagger.io/tools/swagger-editor/`](https://swagger.io/tools/swagger-editor/)进行必要的下载）或在线运行[`editor.swagger.io`](https://editor.swagger.io)。然而，在写完之后，设置一切将变得非常容易，只需要三行代码！

YAML 是一个递归缩写，代表*YAML Ain't Markup Language*。如果您想了解更多信息，请访问[`yaml.org/`](http://yaml.org/)。

# 编写我们的规范

我们无法在这里介绍编写 API 规范的全部规则，也无法在我们的示例中包含所有功能。此外，任何 API 的完整描述可能长达数百行，这是另一个问题。因此，让我们先了解一些基本定义，以及一些服务，以了解需要做些什么。首先，我们需要一些关于我们服务器的基本数据：

```js
swagger: "2.0"
info:
  description: "This is a RESTful API to access countries, regions, and cities."
  version: "1.0.0"
  title: "World Data API"

host: "127.0.0.1:8443"
schemes:
- "http"
```

然后我们必须描述标签（考虑*部分*），我们的文档将被分成。我们使用令牌（用于安全性），加上国家、地区和城市，因此这些似乎是所需的定义：

```js
tags:
- name: "token"
  description: "Get a JWT for authorization"
- name: "countries"
  description: "Access the world countries"
- name: "regions"
  description: "Access the regions of countries"
- name: "cities"
  description: "Access the world cities"
```

让我们看看`/gettoken`路由。我们定义了一个 POST 请求，它获取编码的参数，并返回纯文本。需要两个字符串参数，`user`和`password`。如果一切正常，API 可能会返回 200 状态，否则返回 401：

```js
paths:
 /gettoken:
    post:
      tags:
      - "token"
      summary: "Get a token to authorize future requests"
      consumes: 
        - "application/x-www-form-urlencoded"
      produces:
        - text/plain
      parameters:
        - in: formData
          name: user
          required: true
          type: string
        - in: formData
          name: password
          required: true
          type: string
      responses:
        200:
          description: A valid token to use for other requests
        401:
          description: "Wrong user/password"
```

获取一个国家的地区将得到类似的规范：

```js
/regions:
  get:
    tags:
    - "regions"
    summary: "Get all regions of all countries"
    produces:
      - application/json
    parameters:
      - in: header
        name: "Authorization"
        required: true
        type: string
        description: Authorization Token
    responses:
      200:
        description: "OK"
      401:
        description: "No token provided"
```

# 启用 Swagger

要启用`Swagger`文档，我们需要`swagger-ui-express`包，并且还需要加载 YAML 规范的 JSON 版本，因此您需要几行代码。首先，使用通常的`npm install swagger-ui-express --save`安装包，然后将以下行添加到您的服务器：

```js
const swaggerUi = require("swagger-ui-express");
const swaggerDocument = require("../swagger.json");
```

在服务器上，我们还必须添加一行以启用新路由，在其他`app.use()`语句之后。我们正在为我们的 RESTful API 添加`Swagger`，并且没有令牌：您可能更喜欢设置一个不同的服务器，只提供对 API 的访问，并可能还启用授权，但这两个更改都很容易实现。所以，让我们在这里选择更简单的版本：

```js
app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));

```

您已经准备好了！重新构建项目并启动服务器后，新路由将可用，为您的服务器提供在线文档。

# 它是如何工作的...

如果您启动服务器，访问`/api-docs`路由将提供访问主`Swagger`屏幕，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/f8f6622a-7084-4a05-9343-0dc3f4b2c694.png)

Swagger 生成一个主页面，可以访问您定义的每个路由

交互很容易：选择一个区域，点击一个给定的请求，您将获得所有路由和操作的列表。例如，让我们看看如何获取乌拉圭的地区。首先，我们必须获取一个令牌，所以我们想要打开令牌区域，并输入必要的用户和密码，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/92c311dd-05dc-4a78-9d05-fa6e9b34e8fc.png)

发出请求只是填写字段并执行查询的问题

当进程运行时，您将得到答案，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/fd190496-fc79-4ed7-958f-02e56334257f.png)

成功的请求返回了安全令牌

您可以在顶部看到等效的`curl`请求，与本章前面所做的内容相匹配，在*从命令行测试简单服务*部分。现在，复制该令牌并粘贴到`/regions/uy`端点意味着我们已经准备好进行查询了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/66b6e274-3f42-40c4-8064-12c47c3f01a5.png)

获得令牌后，我们可以设置查询以获取一个国家的所有地区。

剩下要做的就是执行该查询，我们将得到所需的结果，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/f361107e-a79d-47b2-97e6-300869feaa4c.png)

可以进行一系列调用，Swagger 让您轻松尝试不同的端点

我们可以指出什么？首先，显然，`Swagger`是一个非常好的工具，就文档而言。您可以为方法、参数、结果添加描述，甚至包括示例值和结果。这意味着需要使用您的 API 的开发人员将有一个非常好的学习如何使用它的方式。就实际使用您的 API 而言，`Swagger`比`curl`或`Postman`更简单，但它不能链操作，这将由您自己完成。您应该真的考虑使用这个工具开始您的开发，并且只有在您把一切都记录下来后才继续实际编码；试一试吧！


# 第六章：使用 React 进行开发

在本章中，我们将涵盖以下内容：

+   开始使用 React

+   重新安装您的工具

+   定义组件

+   处理状态

+   组合组件

+   处理生命周期事件

+   使用 Storybook 简化组件开发

# 介绍

在最后三章中，我们正在使用`Node`开发后端，现在我们将转向前端，构建一个 Web 应用程序：特别是一种现代风格的**单页应用程序**（**SPA**），用户已经习惯了。

# 开始使用 React

假设您想构建一个 Web 应用程序。您会如何做？除非您一直躲在某个地方，否则您可能已经意识到，有许多框架可以帮助您构建和组织您的网页。但是，您可能会想知道，如果您已经了解 HTML、CSS 和 JS，为什么要使用框架，而不是继续使用纯 JS，可能还有一些库，如`jQuery`或`Lodash`？毕竟，框架会施加一些规则和工作方式，您可能会认为这些规则令人讨厌或麻烦。

当然，您还必须*学习*如何使用框架，而且直到您熟练掌握它之前，您可能不会从中受益。因此，对于*为什么？*这个问题有几种可能的答案，甚至包括*当然，不使用任何框架！*，这对于一个非常小的、简单的项目可能也是可以的：

+   框架为您提供了一个经过充分测试的、稳固的方式来组织您的项目

+   框架通常更适合大型应用程序

+   框架让您在更高级的抽象层次上工作（例如，创建和使用自己的组件），并处理让一切正常运行的琐碎方面

+   培养新开发人员通常更简单：如果他们了解框架，他们已经知道应该放置在哪里以及它们如何相互作用

当然，正如我之前提到的，所有这些优势并不适用于小型项目，只有少数开发人员。

然而，还有一个更重要的原因。框架帮助您解决保持状态（数据）和视图同步的困难任务。对于大型应用程序，应用程序中一个*角落*发生的更改或事件可能会对应用程序的其他地方产生影响。试图将所有更改正确传播到代码中并不是一件简单的事情。

大多数框架会自动生成视图，从数据中获取，每当状态发生变化时，它们会以最佳方式更新屏幕。例如，假设您在某处有一个 doodads 列表。然后，您调用一个网络服务，获取更新后的列表——大多数 doodads 匹配，但有一些被添加了，有一些缺失了。当然，您可以从零开始重新创建列表，但那看起来不太好，如果您决定每次发生变化时重新生成整个屏幕，性能会受到影响。通常情况下，框架会计算当前列表和新列表之间的差异，并相应地更新 HTML 代码，添加或删除 DOM 元素，以使列表再次正确。手动完成所有这些工作，并将其扩展到整个应用程序，将是一件有点太多的事情！

有几个知名的框架，如`Angular`（由 Google）、`Vue`、`Ember`、`Backbone`、`Knockout`等等。（有时候你会觉得每天都有一个新的框架诞生！）我们将在本书中使用`React`（由 Facebook）。

承认一点：`React`更正确地称为*库*而不是框架，因为它不包含您开箱即用开发应用程序所需的一切。然而，所有必要的包都在那里，所以这不会妨碍我们。顺便说一句，这种批评也适用于`Vue`、`Knockout`和`Backbone`。

`React`还可以用于使用`React-Native`创建移动应用程序，我们将在本书的第十一章中看到，*使用 React Native 创建移动应用程序*。

一篇有趣的文章，*JavaScript 框架的终极指南*，在[`javascriptreport.com/the-ultimate-guide-to-javascript-frameworks/`](https://javascriptreport.com/the-ultimate-guide-to-javascript-frameworks/)列出了 50 多个框架！看一看，看看每个框架有什么优缺点。

在这个步骤中，我们将安装必要的包并构建我们自己的非常基本的第一个 Web 应用程序。

# 如何做...

让我们继续创建我们的基本应用程序。如果你不得不纯手工设置一个项目，你会发现自己不得不处理许多不同的工具，比如`Babel`用于转译，`ESLint`用于代码检查，`Jest`用于测试，或者`Webpack`用于将你的整个应用程序打包在一起，而不是不得不将数十个或数百个单独的文件发送到网络上。然而，如今，有一个更简单的工具，`create-react-app`，可以处理这个繁琐的工作，并让你迅速开始`React`开发。其关键卖点是*零配置*，这意味着已经选择了一些合理的好选择，用于开发和生产构建，并且你可以直接开始编写代码，而不必关心无数的配置细节。

对于内行的人来说，`create-react-app`被称为 CRA，这就是我们将要使用的名称。顺便说一句，CRA 并不是创建项目的唯一可能方式；例如，`react-boilerplate`（在[`github.com/react-boilerplate/react-boilerplate`](https://github.com/react-boilerplate/react-boilerplate)）提供了一个替代方案，但所选择的一套包和工具更适合有经验的`React`开发人员。

要创建基本结构（我们稍后会解释），我们将使用`npx`来运行应用程序创建工具，如下面的代码所示。由于我们在第六章，让我们（想象！）将我们的项目命名为`chapter06`！

```js
> npx create-react-app chapter06 Creating a new React app in /home/fkereki/JS_BOOK/modernjs/chapter06.

Installing packages. This might take a couple minutes.
Installing react-scripts...

*...many lines describing installed packages, snipped out...*

Success! Created chapter06 at /home/fkereki/JS_BOOK/modernjs/chapter06
Inside that directory, you can run several commands:

  npm start
    Starts the development server.

  npm run build
    Bundles the app into static files for production.

  npm test
    Starts the test runner.

  npm run eject
    Removes this tool and copies build dependencies, configuration files
    and scripts into the app directory. If you do this, you can’t go back!

We suggest that you begin by typing:

  cd chapter06
  npm start

Happy hacking!
```

如果你好奇，`npx`类似于`npm`，但它执行一个*二进制*命令，该命令要么在你的`node_modules`目录中找到，要么在一个中央缓存中找到，甚至安装它可能需要运行的任何包。有关更多信息，请访问其 GitHub 页面[`github.com/zkat/npx`](https://github.com/zkat/npx)，或者更好的是，阅读 npx 的创建者的一篇文章，*Introducing npx: an npm package runner* [`medium.com/@maybekatz/introducing-npx-an-npm-package-runner-55f7d4bd282b`](https://medium.com/@maybekatz/introducing-npx-an-npm-package-runner-55f7d4bd282b)。

# 它是如何工作的...

运行脚本将创建一个基本的项目结构，包括以下内容：

+   一个`package.json`文件，以及一个相应的`node_modules`目录。

+   一个`README.md`文件，基本上是你可以在[`github.com/wmonk/create-react-app-typescript/blob/master/packages/react-scripts/template/README.md`](https://github.com/wmonk/create-react-app-typescript/blob/master/packages/react-scripts/template/README.md)找到的内容的副本。特别注意它，因为它充满了提示、建议和解决你可能遇到的常见问题。

+   一个`public/`目录，其中包含应用程序的`index.html`基本 HTML 代码，以及一个`favicon.ico`图标文件和一个描述你的应用程序的`manifest.json`文件。（如果你想了解更多关于后者的信息，请查看[`developer.mozilla.org/en-US/Add-ons/WebExtensions/manifest.json`](https://developer.mozilla.org/en-US/Add-ons/WebExtensions/manifest.json)。）

+   一个`src/`目录，其中包含你的应用程序的`index.js`基本代码，带有 CSS 样式的`index.css`，以及显示一些欢迎文本和一些基本说明的`App`组件。你所有的 JS 和 CSS 文件都应该放在`src/`或其子目录中，否则它们将不会被包含在构建中。

基本上，你会想要编辑`index.*`和`App.*`文件，并通过扩展其结构来提供更多的组件、样式等来扩展项目。（注意：不要更改`index.*`文件的名称，否则你的项目将无法运行！）在开始编写代码之前，就像前面的运行所示，在创建的项目目录中，你应该尝试`npm start`。

通过这样做，你将能够看到新的应用程序，就像下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/edd6e9b1-b0cd-491b-b374-c8f1e4444b86.png)

创建的应用程序，准备开始编码

如果你愿意，你可以在`App.js`中进行任何小的更改，保存它，然后注意浏览器页面的立即变化。关于你可以在编码中使用的 JS 功能，项目已经设置为接受大多数现代选项，从 ES6（完整）、ES7（如指数运算符，你可能永远不会使用！），甚至更新的（最有趣的是`async`和`await`），再加上一些*Stage 3*提案；查看[`github.com/facebook/create-react-app/blob/master/packages/react-scripts/template/README.md#supported-language-features-and-polyfills`](https://github.com/facebook/create-react-app/blob/master/packages/react-scripts/template/README.md#supported-language-features-and-polyfills)获取更新的列表。值得注意的是，Flow 是被认可的，还有 JSX，我们将在后面的部分中使用。

# 还有更多...

可能会发生这样的情况，有时你需要做一些额外的配置，CRA 没有考虑到，或者你无法以其他方式添加它。在这种情况下，你可以使用`npm run eject`命令将所有配置、脚本和依赖项直接移动到你的项目中，这样你就可以按照自己的方式开始调整事情。当然，这将比使用*零配置*设置更困难，但至少你不会被锁定，没有出路。

如果你好奇想知道所有这些东西都藏在哪里，可能想研究一下所有设置是如何进行的，答案是“在`node_modules/create_react_app`”目录中；弹出项目会将这个目录中的东西复制到你的项目中。

# 重新安装你的工具

我们一直在使用`ESLint`进行代码质量检查，`Prettier`进行格式化，`Flow`进行数据类型检查。在这个教程中，我们将重新使用这些包，并且将测试（`Jest`等）留到第十章，*测试你的应用程序*。对于我们的两个工具来说，这将是非常简单的，但对于第三个工具来说会稍微复杂一些。

# 如何做...

通过完全手动安装，让所有东西一起工作将会非常困难，但 CRA 已经包含了我们需要的几乎所有东西，所以你只需要添加一些配置细节。

# 重新安装 Flow 和 Prettier

让我们从`Flow`开始。这很简单：我只是像对`Node`做的一样，添加了相同的包、脚本、`.flowconfig`文件等。（如果需要，查看第一章，*使用 JavaScript 开发工具*中的*添加 Flow 进行数据类型检查*部分获取更多信息。）

接下来，让我们处理`Prettier`。这也很简单：我不得不从`package.json`中删除以下行，并将它们放在一个单独的`.prettierrc`文件中：

```js
{
    "tabWidth": 4,
    "printWidth": 75
}
```

`Flow`已经*知道*关于`React`和 CRA 的一切，所以在这方面你不需要任何东西。然而，要使用`PropTypes`（我们很快就会讲到），你需要适当的 flow-typed 包，这很容易安装：

```js
npm run addTypes prop-types@15
```

# 重新安装 ESLint

最后，我们的第三个工具需要更多的工作。对于`ESLint`，我们也不能使用`package.json`，我们需要一个`.eslintrc`文件。但是，即使你提取了那部分，你会发现配置并没有关注你的设置，这是因为 CRA 有自己一套`ESLint`规则，你无法更改！除非当然，你决定弹出项目并开始自己进行配置，但你会尽量避免这样做。有一个包，`react-app-rewired`，它允许你在不弹出的情况下更改内部配置。首先安装一些必需的包：

```js
npm install react-app-rewired react-app-rewire-eslint --save-dev
```

至于规则本身，你会想要有以下内容：

```js
npm install eslint-plugin-flowtype eslint-config-recommended eslint-plugin-react --save-dev
```

现在你需要在`package.json`中更改一些脚本：

```js
"scripts": {
    "start": "react-app-rewired start",
    "build": "react-app-rewired build",
    "test": "react-app-rewired test --env=jsdom",
    "eject": "react-app-rewired eject",
    .
    .
    .
```

最后，在项目的根目录下创建一个`config-overrides.js`文件，与`package.json`文件处于同一级别。`/* global module */`的注释是为了避免在`ESLint`开始工作后出现一个错误，报告`module`未定义：

```js
const rewireEslint = require("react-app-rewire-eslint");
function overrideEslintOptions(options) {
    // *do stuff with the eslint options...*
    return options;
}

/* global module */
module.exports = function override(config, env) {
    config = rewireEslint(config, env, overrideEslintOptions);
    return config;
};
```

你已经准备好了！你的`.eslintrc`文件应该如下所示，其中包括一些添加和更改：

```js
{
    "parser": "babel-eslint",
    "parserOptions": {
        "ecmaVersion": 2017,
        "sourceType": "module"
    },
    "env": {
        "node": true,
        "browser": true,
        "es6": true,
        "jest": true
    },
    "extends": [
        "eslint:recommended",
        "plugin:flowtype/recommended",
        "plugin:react/recommended"
    ],
    "plugins": ["babel", "flowtype", "react"],
    "rules": {
        "no-console": "off",
        "no-var": "error",
        "prefer-const": "error",
        "flowtype/no-types-missing-file-annotation": 0
    }
}
```

如果你想知道为什么我留下了`Node`这一行，那是因为`Storybook`（我们将在本章末看到）使用了一个`module`变量，否则它将被标记为未定义。

# 它是如何工作的...

在这种情况下，没有太多需要解释的。项目的正常配置已经包括了我们需要的所有工具，所以我们只是在进行一些配置，而不是按照标准进行操作。

至于`ESLint`，当你现在使用`npm start`时，`ESLint`配置将被*重新配置*以适应你的配置，而不是 CRA 的配置。这意味着你所有的标准设置和检查将继续运行，你将为 React 应用相同的质量检查运行，除了显然的 React 特定的检查。

你可以在[`github.com/timarney/react-app-rewired`](https://github.com/timarney/react-app-rewired)了解更多关于`react-app-rewired`的信息。

# 定义组件

使用`React`的关键思想是，一切 - 我的意思是，*一切* - 都是一个组件。你整个的网络应用将是一个组件，它本身由其他组件组成，这些组件本身又有更小的组件，依此类推。组件生成 HTML，显示在屏幕上。HTML 的数据来自外部分配的*props*（属性）和内部维护的*state*。每当 props 或 state 发生变化时，React 会负责刷新 HTML，以便视图（用户所见的内容）始终保持最新。

让我们来看一个例子。想象一下，你想创建一个屏幕，让用户查询世界各地区域的数据。你该如何设计？查看以下屏幕截图以获取详细信息：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/bc5eb0a4-0eb1-462b-8b9f-ac1b15faee08.png)

每当用户选择一个国家，我们将显示几张关于其地区的信息卡片。

注意：我在 http://www.wireframes.com 上创建了这个草图，但不要因为我糟糕的素描能力而责怪这个工具！

你的整个视图将是一个组件，但显然这对编码或测试并不会有所帮助。一个很好的设计原则是*每个组件应负责单一职责*，如果它需要做更多的事情，就将其分解为更小的组件。在我们的例子中，我们将有以下内容：

+   整个表格是一个`RegionsInformationTable`。

+   顶部的部分可以是`CountryFilterBar`，带有一个国家的下拉菜单

+   在底部我们有一个`ResultsDataTable`，显示了一系列`ExpandableCard`组件，每个组件都有一个标题，一个切换开关，以及更多组件的空间。我们本可以为这种情况设计一个特定的卡片，但是拥有一个通用的卡片，其组件可以是我们想要的任何东西，更加强大。

第一条规则涉及事件，例如单击元素，输入数据等。它们应该一直传递到某个组件能够完全处理它们为止：*事件向上流动*。例如，当用户单击按钮时，该组件不应该（也不能）完全处理它，至少因为它无法访问表格。因此，事件将通过回调传递（通过回调）直到某个组件能够处理它。您可能有选择：例如，`CountryFilterBar`组件可以处理调用服务并获取数据，然后将结果传递给`RegionsInformationTable`，以便它可以将其传递给`ResultsDataTable`组件，后者将生成必要的`ExpandableCard`元素。另一种选择是将`CountryFilterBar`的值传递给`RegionsInformationTable`，后者将自行进行搜索，或者将其传递得更高，以便某个组件进行搜索并将数据作为 props 推送到我们的大表格。

前面的解释帮助我们做出第二个决定。您应该分析组件层次结构，并决定数据（props 或 state）应该放在哪里。一个关键规则是：如果两个（或更多）组件共享数据（或者一个组件产生其他组件需要的数据），它应该属于更高级的组件，它将根据需要向下传递：*数据向下流动*。在我们的情况下，当我们决定区域数据将由`CountryFilterBar`拥有，然后传递给`RegionResults`表时，我们已经应用了该规则；每个`ExpandableCard`只能使用它接收到的 props。

即使我们还不知道如何处理 Web 服务请求以获取必要的数据（或者例如初始化国家下拉菜单），我们可以构建组件的静态版本并查看其工作原理。

最好从 Web 设计的这些静态方面开始，然后再处理动态方面，例如对事件的反应或获取数据。让我们开始编写代码。

# 如何做...

我们需要创建几个组件，这将使我们能够找出如何在其他组件中包含组件，如何传递属性，如何定义它们等。让我们逐个组件地进行。

# 创建应用程序

要启动一个`React`应用程序，我们只需要一个基本的 HTML 页面，CRA 已经在`public/index.html`中提供了一个。简化到基础部分（查看完整版本的书源代码），它大致如下，关键部分是`<div>`，其中将放置所有`React`生成的 HTML 代码：

```js
<!DOCTYPE html>
<html lang="en">
    <head>
        .
        .
        .
        <title>React App</title>
    </head>
    <body>
 <div id="root"></div>
    </body>
</html>
```

我们应用程序的入口将是`index.js`，它（我们在这里省略了一些无关紧要的代码行）归结为以下代码：

```js
/* @flow */

import React from "react";
import ReactDOM from "react-dom";
import App from "./App";

const root = document.getElementById("root");
if (root) {
    ReactDOM.render(<App />, root);
}
```

为什么我们需要定义一个`root`变量和`if`？关键是`Flow`检查：`document.getElementById(...)`调用可能会产生一个 Web 节点，也可能为空，并且`Flow`提醒我们在承诺工作之前检查空值。

现在我们有了基本的脚手架，让我们开始编写一些实际的`React`组件！

# 创建基本的 App 组件

让我们从`App.js`文件开始；我们将呈现一个简单的`RegionsInformationTable`。我们正在扩展一个名为`PureComponent`的`React`类；我们稍后会解释这意味着什么。您自己的组件名称应以大写字母开头，以区别于应该以小写字母开头的 HTML 名称。每个组件都应该有一个`.render()`方法，用于生成所需的 HTML；还有更多方法可以用于此，我们将会看到：

```js
/* @flow */

import React from "react";
import { RegionsInformationTable } from "./components/regionsInformationTable";

class App extends React.PureComponent<{}> {
 render() {
 return <RegionsInformationTable />;
 }
}

export default App;
```

在定义组件时必须指定的唯一方法是`.render()`。组件还有许多其他方法，包括几种*生命周期*方法，我们将在*处理生命周期事件*部分中看到，但它们都是可选的。

您可能会问自己：为什么要费事创建一个什么都不做，只是生成一个`<RegionsInformationTable>`组件的`<App>`组件？为什么不直接使用后者？我们将在接下来的部分中解释原因；我们希望`<App>`组件能做更多的事情，比如定义路由、管理存储等。因此，即使在这个特定的小例子中，这是多余的-这是我们想要保留的一种模式。

您还需要注意我们写了`React.PureComponent<{}>`，这是为了让`Flow`知道我们的组件既不需要属性也不需要状态。在后面的部分中，我们将看到更多需要更好类型定义的示例。

# 创建`RegionsInformationTable`组件

我们可以立即看到`RegionsInformationTable`组件是如何渲染的：它只依赖于我们决定创建的另外两个组件。请注意，我们返回 HTML 代码，就好像它是一个有效的 JS 值：这就是 JSX，它提供了一种非常简单的方式来交织 JS 代码和 HTML 代码。我们将有一个国家列表（大大减少！）据说来自于一个 Web 服务，以及一个地区列表（也减少了，带有虚假数据），它将在用户选择国家后来自不同的服务。这些数据是组件的*状态*；每当这些列表中的任何一个发生变化时，React 都会重新渲染组件及其包含的所有内容。我们将在*处理状态*部分进一步讨论这一点：

```js
// Source file: src/components/regionsInformationTable/index.js

/* @flow */

import React from "react";

import { CountryFilterBar } from "../countryFilterBar";
import { ResultsDataTable } from "../resultsDataTable.2";

export class RegionsInformationTable extends React.PureComponent<
    {},
    {
        countries: Array<{
            code: string,
            name: string
        }>,
        regions: Array<{
            id: string,
            name: string,
            cities: number,
            pop: number
        }>
    }
> {
    state = {
        countries: [
            { code: "AR", name: "Argentine" },
            { code: "BR", name: "Brazil" },
            { code: "PY", name: "Paraguay" },
            { code: "UY", name: "Uruguay" }
        ],

        regions: []
    };

    update = (country: string) => {
        console.log(`Country ... ${country}`);

        this.setState(() => ({
            regions: [
                {
                    id: "UY/5",
                    name: "Durazno",
                    cities: 8,
                    pop: 60000
                },
                {
                    id: "UY/7",
                    name: "Florida",
                    cities: 20,
                    pop: 67000
                },
                {
                    id: "UY/9",
                    name: "Maldonado",
                    cities: 17,
                    pop: 165000
                },
                {
                    id: "UY/10",
                    name: "Montevideo",
                    cities: 1,
                    pop: 1320000
                },
                {
                    id: "UY/11",
                    name: "Paysandu",
                    cities: 16,
                    pop: 114000
                }
            ]
        }));
    }

    render() {
        return (
            <div>
 <CountryFilterBar
 list={this.state.countries}
 onSelect={this.update}
 />
 <ResultsDataTable results={this.state.regions} />
            </div>
        );
    }
}
```

这个组件不接收任何属性，但使用状态，因此为了`Flow`的缘故，我们不得不写`React.PureComponent<{},{countries:..., regions:...}>`，为状态元素提供数据类型。您还可以在单独的文件中定义这些数据类型（有关此内容的更多信息，请参见[`flow.org/en/docs/types/modules/`](https://flow.org/en/docs/types/modules/)），但我们就此打住。

关于国家列表呢？`CountryFilterBar`应该显示一些国家，所以父组件将作为属性提供列表；让我们看看它将如何接收和使用该列表。我们还将提供一个回调函数`onSelect`，子组件将使用它来在用户选择国家时通知您。最后，我们将把（虚假的，硬编码的）地区列表传递给`ResultsDataTable`。

值得注意的是：属性是使用`name=...`语法传递的，与 HTML 元素的标准用法相同；您的`React`元素与常见的标准 HTML 元素的用法相同。这里唯一的区别是您使用大括号，以模板方式包含任何表达式。

顺便说一句，注意我们的地区列表起初是空的；结果表将不得不处理这一点。当用户选择一个国家时，`.update()`方法将运行，并使用`.setState()`方法加载一些地区，我们将在下一节中看到。在本书的后面，我们还将看到如何使用 Web 服务获取这些数据，但目前，固定的结果将不得不使用。

# 创建`CountryFilterBar`组件

我们需要的下一个组件更复杂：它接收一对属性，并且首先提供了这些属性的`PropTypes`定义：

```js
// Source file: src/components/countryFilterBar.js

/* @flow */

import React from "react";
import PropTypes from "prop-types";

export class CountryFilterBar extends React.PureComponent<{
    list?: Array<{ code: string, name: string }>,
    onSelect: string => void
}> {
    static propTypes = {
        list: PropTypes.arrayOf(PropTypes.object),
        onSelect: PropTypes.func.isRequired
    };

    static defaultProps = {
        list: []
    };
// *continued...*
```

这是我们第一个接收属性的组件。我们将为`Flow`提供一个定义，很简单：组件将接收`list`，一个对象数组，和`onSelect`，一个带有单个字符串参数的函数，不返回任何内容。

`React`还允许您为参数定义运行时检查。我们定义了一个`propTypes`类属性，其中包含我们的组件将接收的每个实际属性的元素，以及另一个`defaultProps`属性，用于在未提供实际值时提供默认值。如果需要定义数据类型（例如，`onSelect`是一个函数），以及它们是必需的还是可选的（在这种情况下都是必需的）。在开发中（而不是在生产中），每当您将属性传递给对象时，它们将根据其定义进行检查，如果存在某种不匹配，将产生警告；这是一种很好的调试技术。

为什么要同时使用`Flow`和`PropTypes`，如果它们似乎都是做同样的工作？基本上，`Flow`是一个静态检查器，而`PropTypes`是一个动态的运行时检查器。如果您在整个应用程序中都使用`Flow`，理论上，您可以不使用`PropTypes` - 但由于这个包在测试中会捕捉到您忽略的任何内容，它是代码的额外“安全网”。我同意写两套数据类型确实很麻烦。

这些有效的类型如下：

+   `any`，如果任何类型都可以接受 - 这不是一个好的做法

+   `array`

+   `arrayOf(someType)`，指定数组元素的值

+   `bool`，用于布尔值

+   `element`，用于 React 元素

+   `func`，用于函数

+   `instanceOf(SomeClass)`，用于必须是给定类的实例的对象

+   `node`，对于任何可以呈现为 HTML 的东西，比如数字或字符串

+   `number`

+   `object`

+   `objectOf(SomeType)`，指定具有给定类型的属性值的对象

+   `oneOf([...值数组...])`，验证属性是否限制在某些值上

+   `oneOfType([...类型数组...])`，指定一个属性将是类型列表中的一个

+   `shape({...具有类型的对象...})`，完全定义一个对象，包括键和值类型

+   `string`

+   `symbol`

您甚至可以进一步定义，例如，用于类型验证的特定函数。有关`PropTypes`的所有可能性的完整解释，请阅读[`reactjs.org/docs/typechecking-with-proptypes.html`](https://reactjs.org/docs/typechecking-with-proptypes.html)。

现在，我们如何为过滤器生成 HTML 呢？我们需要几个`<option>`元素，并且我们可以将`.map()`应用于`this.props.list`（通过`this.props`访问属性），如下所示。还要注意我们如何使用`onChange`回调来在选择不同的国家时通知父组件：

```js
// *...continues*

    onSelect(e) {
        this.props.onSelect(e.target.value);
    }

    render() {
        return (
            <div>
                Country:&nbsp;
                <select onChange={this.onSelect}>
                    <option value="">Select a country:</option>
                    {this.props.list.map(x => (
 <option key={x.code} value={x.code}>
 {x.name}
 </option>
 ))}
                </select>
            </div>
        );
    }
}
```

输入属性（`this.props`）应被视为只读，永远不要修改。另一方面，组件的状态（`this.state`）是可读写的，可以被修改，尽管不是直接修改，而是通过`this.setState()`，我们将看到。

`key=`属性需要特别解释。每当您定义一个列表（例如`<option>`或`<li>`）并且 React 需要重新呈现它时，`key`属性用于识别已经可用的元素并避免重新生成它们，而是重复使用它们。请记住，`CountryFilterBar`组件将随着时间的推移以不同的国家列表呈现，因此 React 将通过避免创建已经存在的列表元素来优化其性能。

# 创建 ResultsDataTable 组件

构建结果表格很容易，需要的工作与我们在国家选择器中所做的类似。我们只需要检查特殊情况，即当我们没有任何地区要显示时：

```js
// Source file: src/components/resultsDataTable.1/index.js

/* @flow */

import React from "react";
import PropTypes from "prop-types";

import { ExpandableCard } from "../expandableCard.1";
import "../general.css";

export class ResultsDataTable extends React.PureComponent<{
    results: Array<{
        id: string,
        name: string,
        cities: number,
        pop: number
    }>
}> {
    static propTypes = {
        results: PropTypes.arrayOf(PropTypes.object).isRequired
    };

    render() {
        if (this.props.results.length === 0) {
            return <div className="bordered">No regions.</div>;
        } else {
            return (
                <div className="bordered">
                    {this.props.results.map(x => (
 <ExpandableCard
 key={x.id}
 name={x.name}
 cities={x.cities}
 population={x.pop}
 />
 ))}
                </div>
            );
        }
    }
}
```

一个附带的评论：`React`允许我们将 props 定义为可选的（意味着在定义`PropTypes`时没有包含`isRequired`），并提供默认值。在这种情况下，如果结果可能*不*被提供，您将编写以下代码，使用`defaultProps`来提供必要的默认值：

```js
    static propTypes = {
        results: PropTypes.arrayOf(PropTypes.object)
    };

 static defaultProps = {
 results: []
 }
```

在`Flow`和`PropTypes`方面，定义与之前的非常相似。有趣的部分是使用`.map()`来处理所有接收到的对象，为每个创建一个`ExpandableCard`；这是 React 中非常常见的模式。因此，我们现在需要完成我们的应用程序的是提供一个可展开的卡片，所以让我们开始吧。

# 创建可展开卡组件

首先，让我们忘记扩展卡片 - 即使这使得组件的名称不准确！在这里，我们只是制作一个显示几个字符串的组件。在*组合组件*部分，我们将看到一些实现我们最初目标的有趣方法：

```js
// Source file: src/components/expandableCard.1/index.js

/* @flow */

import React from "react";
import PropTypes from "prop-types";

import "../general.css";

export class ExpandableCard extends React.PureComponent<{
    name: string,
    cities: number,
    population: number
}> {
    static propTypes = {
        name: PropTypes.string.isRequired,
        cities: PropTypes.number.isRequired,
        population: PropTypes.number.isRequired
    };

    render() {
        return (
            <div className="bordered">
                NAME:{this.props.name}
                <br />
                CITIES:{this.props.cities}
                <br />
                POPULATION:{this.props.population}
            </div>
        );
    }
}
```

一切准备就绪；让我们看看它是如何以及为什么运作的！

# 它是如何工作的...

当你用`npm start`启动应用程序时，你会得到我们的基本屏幕，显示带有国家的下拉框，以及没有卡片，如下面的截图所示：

！[](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/9d19b73b-35af-41bf-8382-373c442edc67.png)

我们的基本应用程序，显示固定的、不变的卡片

然后，假设你选择了一个国家；会发生什么？让我们一步一步地跟踪一下：

1.  在`CountryFilterBar`中，`onChange`事件将触发并执行一个回调(`this.props.onSelect()`)，并提供所选国家的代码。

1.  在`RegionsInformationTable`中，提供给`CountryFilterBar`的回调是`this.update()`，因此该方法将被执行。

1.  更新方法将记录国家(仅供参考)并使用`this.setState` (见下一节)在`RegionsInformationTable`状态中加载一些区域。

1.  状态的改变将导致`React`重新渲染组件。

1.  `CountryFilterBar`不需要重新渲染，因为它的 props 和状态都没有改变。

1.  另一方面，`ResultsDataTable`将重新渲染，因为它的 props 将改变，接收一个新的区域列表。

因此，说了这么多之后，新的视图将如下所示：

！[](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/f5f0f845-1642-40cd-8994-40f552af1691.png)

React 处理所有必要的重新渲染后，更新的视图

这基本上是你的应用程序将如何工作的：事件被捕获和处理，状态被改变，props 被传递，`React`负责重新渲染需要重新渲染的部分。

# 还有更多...

让我们回到`CountryFilterBar`组件。我们使用了最近的 JS 方式来定义它，但在许多文章和书籍中，你可能会发现一个你应该了解的旧风格，这样你就可以更好地理解这个变体：

```js
// Source file: src/components/countryFilterBar.old.style.js

/* @flow */

import React from "react";
import PropTypes from "prop-types";
import "../general.css";

export class CountryFilterBar extends React.PureComponent<{
    list: Array<{ code: string, name: string }>,
    onSelect: string => void
}> {
 constructor(props) {
 super(props);
 this.onSelect = this.onSelect.bind(this);
 }

 onSelect(e: { target: HTMLOptionElement }) {
 this.props.onSelect(e.target.value);
 }

    render() {
        return (
            <div className="bordered">
                Country:&nbsp;
                <select onChange={this.onSelect}>
                    <option value="">Select a country:</option>
                    {this.props.list.map(x => (
                        <option key={x.code} value={x.code}>
                            {x.name}
                        </option>
                    ))}
                </select>
            </div>
        );
    }
}

CountryFilterBar.propTypes = {
 list: PropTypes.arrayOf(PropTypes.object).isRequired,
 onSelect: PropTypes.func.isRequired
};

CountryFilterBar.defaultProps = {
 list: []
};
```

我们可以总结如下的差异：

+   `propTypes`和`defaultProps`的值是通过直接修改类来分别定义的

+   我们在构造函数中绑定了`this.onSelect`，所以当调用这个方法时，`this`的值将是`window`对象，而不是我们需要的。

使用现代 JS 功能，这是不需要的，但要注意，在旧的 JS 代码中，你可能会发现这些模式。

# 处理状态

在前一节中，我们看到了*state*用于区域的用法；让我们深入了解一下。状态的概念与 props 非常相似，但有关键的区别：props 是从外部分配的，是只读的，而状态是私下处理的，是可读写的。如果一个组件需要保留一些信息，它可以用来渲染自己，那么使用状态就是解决方案。

# 如何做...

通过使用类字段来定义状态，这是 JS 的一个相当新的功能，通过`Babel`启用，因为它还没有完全正式化。(请参阅[`github.com/tc39/proposal-class-fields`](https://github.com/tc39/proposal-class-fields)查看提案，该提案处于第 3 阶段，意味着它离正式采纳只有一步之遥。)在旧的 JS 版本中，你必须在类构造函数中创建`this.state`，但这种语法更清晰。让我们记住代码是什么样子的，然后放弃 Flow 定义。

首先，让我们修改`RegionsInformationTable`组件：

```js
export class RegionsInformationTable extends React.PureComponent<...> {
 state = {
        countries: [
            { code: "AR", name: "Argentine" },
            { code: "BR", name: "Brazil" },
            { code: "PY", name: "Paraguay" },
            { code: "UY", name: "Uruguay" }
        ],

        regions: []
 };
```

其次，让我们看看当国家改变时会发生什么。对象的渲染可以取决于它的 props(如我们所说，它不能改变)和它的状态(它可以改变)，但在更新状态时有一个重要的限制。你不能简单地给组件的状态赋一个新值，因为`React`不会检测到它，然后不会进行任何渲染。相反，你必须使用`.setState()`方法。这个方法可以以不同的方式调用，但*functional*`.setState()`是最安全的方法。通过这种方式，你必须传递一个函数，该函数将接收状态和 props，并返回需要更新的状态的任何部分。在我们之前的代码中，我们将写下以下内容：

```js
update(country: string) {
        .
        .
        .
        this.setState((state, props) => ({ regions: [ 
                .
                .
                .
            ]}));
```

如果你检查一下，你会发现我们在实际代码中没有包括`state`和`props`参数，但这是为了满足 ESLint 关于函数中没有未使用的参数的规则。

# 它是如何工作的...

为什么我们需要传递一个函数？理解这一点有一个关键：*状态更新是异步的*。每当你调用`.setState()`时，`React`将更新组件的状态并启动协调过程以更新 UI 视图。但是如果有多个`.setState()`调用会发生什么呢？问题就在这里。

`React`允许*排队*许多这样的调用一起进行单个更新，以实现更好的性能，这具有重要的影响：在执行`.setState()`之前，状态可能已经发生了变化！（即使这样，如果进行批处理，更新将按照调用它们的顺序进行。）因此，你提供一个函数，`React`将使用适当更新的`state`参数调用它。不要做任何依赖于`this.state`的事情，因为它可能是错误的；始终使用`state`参数进行操作。

无论如何，你应该知道有一个快捷方式。如果（仅当）你的更新不以任何方式依赖于状态或 props 值，你可以使用另一种调用而不需要一个函数。例如，我们的更新可以简单地写成如下形式，`this.state.regions`将被改变，而其余状态将保持不变；关键是`regions`属性的新值不以任何方式依赖于状态或 props：

```js
this.setState({ regions: [ ...]});
```

为什么这样会起作用？因为在这种情况下，即使状态在之前已经改变，你的更新仍然是相同的。但要小心，只有当你的更新完全独立于状态和 props 时，才使用这种语法；否则，使用我们首先展示的函数式方法。

一旦你意识到状态更新是函数，你就可以将逻辑从组件中移出，进行独立的编码和测试，这将与我们在第八章中使用`Redux`进行的操作非常相似，*扩展你的应用程序*。你会写`this.setState(someFunction)`，然后`someFunction()`会被单独定义；你的代码将变得更加声明式。

# 还有更多...

通过我们在这里所做的一切，你可能会意识到你拥有处理任何应用程序规模的状态所需的一切-你是对的！你可以在`App`组件中设置整个应用程序的一般状态（记得我们提到过`App`将有更多的责任？），并且你将能够进行以下操作：

+   通过使用 props 将其传递给组件

+   根据组件发送的事件进行更新

这是一个完全有效的解决方案，`App.state`可以包含整个页面的各种数据。例如，`App`可以处理调用 Web 服务以获取给定国家的地区，将结果存储在其状态中，并将其传递给我们的组件以便它们进行渲染。在我们的硬编码版本中，`RegionsInformationTable`拥有国家列表（它是从哪里获取的？）并处理地区的请求（通过返回硬编码数据）。实际上，正如我们将在本书后面看到的那样，从服务器获取这种信息将以不同的方式处理，并且在更高的级别：`RegionsInformationTable`将处理渲染表格，并将数据收集留给解决方案的另一部分。

即使你将 Web 服务处理传递给`App`，随着应用程序规模的增长，由于你可能需要跟踪的数据字段数量，这种解决方案可能变得难以控制。在第八章中，我们将为此找到更好的可扩展解决方案，通过添加一个特定的包来更有序、结构化地处理状态更新。

# 组合组件

让我们回到`ExpandableCard`，之前我们没有完全完成。我们当然可以做一个特定于地区的卡片，但似乎可扩展或压缩的卡片的一般概念足够有用，以至于我们可能更喜欢一个更一般的解决方案。`React`允许我们通过*组合*来做到这一点，我们将在本节中看到。

# 如何做...

我们想要创建的组件可以包含任何类型的内容。（顺便说一句，相同的想法也适用于通用对话框、标题部分或侧边栏。）React 允许您传递一个特殊的 children 属性（`this.props.children`），以便您可以将子元素传递给原始组件。

首先，让我们看看我们的`ResultsDataTable`代码会如何改变。首先，`render()`方法将需要更改：

```js
render() {
    if (this.props.results.length === 0) {
        return <div className="bordered">No regions.</div>;
    } else {
        return (
            <div className="bordered">
                {this.props.results.map(x => (
 <ExpandableCard key={x.id} title={x.name}>
 <div>CITIES:{x.cities}</div>
 <div>POPULATION:{x.pop}</div>
 </ExpandableCard>
                ))}
            </div>
        );
    }
}
```

其次，让我们定义我们正在使用的组件。我们正在插入一个带有键和标题的`ExpandableCard`组件，并在其中包含一对`<div>`元素，其中包含城市和人口的数据。这些内容将作为`this.prop.children`可用，我们稍后会看到。我们还添加了一个`title`prop 和一个内部状态`open`，当您通过`.toggle()`方法展开或压缩卡片时，它将被切换。首先，让我们看看 props、state 和类型：

```js
// Source file: src/comopnents/expandableCard.2/index.js

/* @flow */

import * as React from "react";
import PropTypes from "prop-types";

import "../general.css";
import "./expandableCard.css";

export class ExpandableCard extends React.PureComponent<
    {
        children: React.ChildrenArray<React.ChildrenArray<React.Node>>,
        title: string
    },
    { open: boolean }
> {
    static propTypes = {
        children: PropTypes.arrayOf(PropTypes.element).isRequired,
        title: PropTypes.string.isRequired
    };

    state = {
        open: false
    };

// *continues...*
```

对于`React`，`Flow`预定义了许多数据类型。（您可以在[`github.com/facebook/flow/blob/master/website/en/docs/react/types.md`](https://github.com/facebook/flow/blob/master/website/en/docs/react/types.md)上了解更多信息。）

您可能需要的一些更常见的类型如下，但是请阅读上述网页以获取完整的列表：

| **数据类型** | **解释** |
| --- | --- |
| `React.ChildrenArray<T>` | 一个子元素数组，类型为`<T>`，就像前面的代码中所示的那样。 |
| `React.Element<typeof Component>` | 特定类型的节点：例如，`React.Element<"div">`是一个渲染`<div>`的元素。 |
| `React.Key` | 用作键的 prop 的类型：基本上是数字或字符串。 |
| `React.Node` | 可以呈现的任何节点，包括 React 元素、数字、字符串、布尔值、未定义、null 或这些类型的数组。 |

最后，让我们来到组件的功能部分。让我们看看当组件的状态显示应该展开时，如何显示组件的子元素。还有一个有趣的地方是看看点击卡片如何调用`.toggle()`方法来改变组件的`state.open`值：

```js
// *continued*...

    toggle = () => {
        this.setState(state => ({ open: !state.open }));
    }

    render() {
        if (this.state.open) {
            return (
                <div className="bordered">
                    {this.props.title}
                    <div
                        className="toggle"
                        onClick={this.toggle}
                    >
                        △
                    </div>
 <div>{this.props.children}</div>
                </div>
            );
        } else {
            return (
                <div className="bordered">
                    {this.props.title}
                    <div
                        className="toggle"
                        onClick={this.toggle}
                    >
                        ▽
                    </div>
                </div>
            );
        }
    }
}
```

我们完成了！让我们看看这一切是如何结合在一起的。

# 它是如何工作的...

当此对象首次呈现时，`this.state.open`为 false，因此`.render()`方法将只产生卡片的标题，以及一个指向下方的三角形，表明可以通过点击展开卡片。当用户点击三角形时，将调用`this.setState()`，并传递一个函数，该函数将获取`this.state.open`的当前值，并切换它。`React`将决定对象是否需要重新呈现（因为状态的改变），这一次，由于`this.state.open`将为 true，将呈现卡片的扩展完整版本。特别是，三角形将指向上方，因此用户将了解如果他们在那里点击，卡片将被压缩。查看以下截图，进行试运行，显示一些展开和压缩的卡片：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/6ebbbdd8-b518-4165-bb85-4c37b287df5a.png)

我们应用程序的运行；一些卡片已展开并显示其子元素

扩展卡的内容将是什么？这就是`this.props.children`发挥作用的地方。任何作为 props 提供的元素都将在这里呈现。通过这种方式，你可以重用你的`ExpandableCard`来呈现任何类型的内容。主要特征（标题，展开/收缩卡的三角形）将始终存在，但由于使用了组合，你可以拥有任何你需要的可展开卡的版本。

# 处理生命周期事件

组件不仅有一个`.render()`方法 - 它们还可以实现许多更多的*生命周期*事件，可以帮助你在特定情况下。在这一节中，让我们介绍所有可用的方法，并提供关于何时使用它们的想法。

要获取所有可用方法的完整描述，请访问[`reactjs.org/docs/react-component.html`](https://reactjs.org/docs/react-component.html) - 但要特别注意一些已弃用的、遗留的方法，应该避免使用，并且阅读每个方法的条件和参数。

# 如何做...

让我们按顺序来看一下组件的生命周期，从组件被创建并放入 DOM 中开始，到它的生命周期中可能被更新的时候，直到组件从 DOM 中被移除的时刻。我们只会介绍主要的方法，即使这样，你可能也不会用到所有的方法：

+   `constructor()`: 这个方法在组件被挂载之前被调用，用于基本设置和初始化。这个方法用于各种初始化。唯一的关键规则是在做任何其他事情之前，你应该始终先调用`super(props)`，这样`this.props`就会被创建并且可以访问。

+   `componentDidMount()`: 这个方法在组件被挂载后被调用。

+   `shouldComponentUpdate(nextProps, nextState)`: 这个方法被 React 用来决定一个组件是否需要重新渲染。

+   `render()`: 这个（强制性的）方法产生 HTML 元素，理想情况下只基于`this.props`和`this.state`。如果函数返回一个`boolean`或`null`值，将不会呈现任何内容。这个方法应该是纯的，不尝试修改组件的状态（这可能导致恶性循环）或使用除了状态和 props 之外的任何东西。

+   `forceUpdate()`: 这个方法不是真正的生命周期方法，你可以在任何时候调用它来强制重新渲染。

+   `componentDidUpdate(previousProps, previousState)`: 这个方法在组件更新后被调用。

+   `componentWillUnmount()`: 这个方法在组件将要被卸载之前被调用。

# 它是如何工作的...

我们已经介绍了上一节中的方法。现在让我们来看一些关于让不太明显的方法工作的想法：

| **方法 ** | **解释** |
| --- | --- |
| `componentDidMount()` | 这是开始从网络服务获取数据的常规位置。一个常见的技巧是有一个状态属性，比如`this.state.loading`，当你请求数据时将其初始化为 true，并在数据到来后重置为 false。然后可以让`.render()`方法产生不同的输出，可能是加载图标，直到数据到来，然后是真实的数据。 |
| `shouldComponentUpdate(...)` | 这个方法作为性能优化，允许 React 跳过不必要的更新。对于`React.PureComponent`，这是通过比较当前状态和下一个状态，以及当前 props 和下一个 props 来实现的。对于普通的`React.Components`，这个方法总是返回`true`，强制重新渲染。如果你的组件是基于任何额外的东西（比如除了状态和 props 之外的其他东西）进行渲染，你应该使用`Component`而不是`PureComponent`。 |
| `componentDidUpdate(...)` | 您可以使用此方法执行一些动画，或从 Web 服务获取数据，但在后一种情况下，您可能希望将当前状态和 props 与先前的值进行比较，因为如果没有更改，则可能不需要请求，或者可能已经完成了。 |
| `componentWillUnmount()` | 这是通常执行一些清理任务的地方，比如禁用定时器或删除侦听器。 |

# 使用 Storybook 简化组件开发

在开发组件时，有一个基本而重要的问题：如何尝试它们？当然，您可以在任何页面的任何地方包含它们，但是每当您想要查看它们的工作方式时，您必须按照应用程序的完整路径，以便您可以实际看到组件。

`Storybook`是一个 UI 开发环境，可以让您在应用程序之外独立地可视化您的组件，甚至以交互方式对它们进行更改，直到您完全正确为止！

# 如何做...

首先，安装`Storybook`本身；我们将使用这个版本的`React`，但这个工具也可以与`Angular`和`Vue`一起使用：

```js
npm install @storybook/react --save-dev
```

然后在`package.json`中添加一些脚本：一个将启动`Storybook`（稍后我们将看到），另一个将构建一个独立的应用程序，您可以使用它来展示您的组件：

```js
"scripts": { 
 "storybook": "start-storybook -p 9001 -c .storybook",    "build-storybook": "build-storybook -c .storybook -o out_sb",
    .
    .
    .

```

现在让我们为`ExpandableCard`编写一个简单的故事。在该组件所在的同一目录中（最终版本，实际上允许展开和压缩，而不是没有该行为的第一个版本），创建一个`ExpandableCard.story.js`文件。您想展示关于您的组件的内容是什么？您可以显示以下内容：

+   一个可展开的卡片，里面有几行，就像我们之前使用的那样

+   另一张卡片，有很多行，展示卡片如何拉伸

+   一个包含其他卡片的卡片，每个卡片都有一些最小的内容

代码风格与我们在第五章中为`Node`编写的测试非常相似，*测试和调试您的服务器*。我假设您可以弄清楚每个测试的作用：

```js
// Source file: src/components/expandableCard.2/expandableCard.story.js

import React from "react";
import { storiesOf } from "@storybook/react";

import { ExpandableCard } from "./";

storiesOf("Expandable Card", module)
    .add("with normal contents", () => (
        <ExpandableCard key={229} title={"Normal"}>
            <div>CITIES: 12</div>
            <div>POPULATION: 41956</div>
        </ExpandableCard>
    ))

    .add("with many lines of content", () => (
        <ExpandableCard key={229} title={"Long contents"}>
            Many, many lines<br />
            Many, many lines<br />
            Many, many lines<br />
            Many, many lines<br />
            Many, many lines<br />
            Many, many lines<br />
            Many, many lines<br />
            Many, many lines<br />
            Many, many lines<br />
            Many, many lines<br />
            Many, many lines<br />
            Many, many lines<br />
            Many, many lines<br />
            Many, many lines<br />
        </ExpandableCard>
    ))

    .add("with expandable cards inside", () => (
        <ExpandableCard key={229} title={"Out card"}>
            <ExpandableCard key={1} title={"First internal"}>
                A single 1
            </ExpandableCard>
            <ExpandableCard key={2} title={"Second internal"}>
                Some twos
            </ExpandableCard>
            <ExpandableCard key={3} title={"Third internal"}>
                Three threes: 333
            </ExpandableCard>
        </ExpandableCard>
    ));
```

为了不只有一个故事，让我们为`CountryFilterBar`组件写一个简短的故事；它将在相同的目录中，命名为`countryFilterBar.story.js`。是的，我知道这是一个非常简单的组件，但这只是为了我们的例子！

```js
// Source file: src/components/countryFilterBar/countryFilterBar.story.js

import React from "react";
import { storiesOf } from "@storybook/react";

import { CountryFilterBar } from "./";

const countries = [
    { code: "AR", name: "Argentine" },
    { code: "BR", name: "Brazil" },
    { code: "PY", name: "Paraguay" },
    { code: "UY", name: "Uruguay" }
];

storiesOf("Country Filter Bar", module).add("with some countries", () => (
    <CountryFilterBar list={countries} onSelect={() => null} />
));
```

最后，我们需要一个启动器。在项目的根目录下创建一个`.storybook`目录，并在其中创建一个`config.js`文件，如下所示：

```js
import { configure } from "@storybook/react";

configure(() => {
    const req = require.context("../src", true, /\.story\.js$/);
    req.keys().forEach(filename => req(filename));
}, module);

configure(loadStories, module);
```

是的，这有点神秘，但基本上是要扫描`/src`目录，并选择所有文件名以`.story.js`结尾的文件。现在我们准备好看看这一切是如何结合在一起的。

# 它是如何工作的...

我们只为一些组件编写了故事，但这对我们的目的足够了。要启动`Storybook`服务器，您必须运行我们在本节早些时候创建的脚本之一：

```js
npm run storybook
```

经过一些工作，你会得到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/414d3646-e57c-4fb0-8adc-7b84cecad785.png)

Storybook，显示所有可用的故事。您可以与组件交互，单击它们，甚至测试源代码中的更改。

您可以在左侧边栏中选择任何组件（甚至使用过滤文本框），并获取它的各个故事。单击一个故事将在右侧显示相应的组件。您可以使用组件并查看其外观和性能...如果您不满意，您可以动态更改其源代码，并立即查看结果！

最后，让我们构建一个独立的展示应用程序：

```js
$ npm run build-storybook

> chapter06@0.1.0 build-storybook /home/fkereki/JS_BOOK/modernjs/chapter06
> build-storybook -s public -o out_sb

info @storybook/react v3.4.8
info
info => Loading custom addons config.
info => Using default webpack setup based on "Create React App".
info => Copying static files from: public
info Building storybook ...
info Building storybook completed.
```

在`/out_sb`目录中，我们将拥有一个完整的独立版本的展示。要查看它的工作原理，我们可以使用 Chrome 浏览器的 Web 服务器应用程序（在 Chrome 扩展中搜索），并选择输出目录：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/d567adc8-893b-462b-9cd1-e1e3c29a06a2.png)

Chrome 的 Web 服务器应用程序足以让我们看到独立的 Storybook 会是什么样子

如果您打开屏幕上显示的 Web 服务器 URL，您将得到与之前完全相同的输出-但现在您可以将`out_sb`目录复制到其他位置，并将其用作展示工具，独立于开发人员。

# 还有更多...

您可以通过*插件*扩展`Storybook`，从而增强您的展示。在众多可用的插件中，我们将安装其中三个，并快速查看它们的用法：

+   `addon-actions`允许您查看事件处理程序接收的数据，以查看例如当用户单击组件时会发生什么

+   `addon-notes`允许您向组件添加注释，以解释其工作原理或提供有关其用法的见解

+   `addon-knobs`允许您动态调整组件的属性以查看其变化

您可以在[`storybook.js.org/addons/introduction/`](https://storybook.js.org/addons/introduction/)上阅读有关插件的更多信息，并查看可用插件的画廊[`storybook.js.org/addons/addon-gallery/`](https://storybook.js.org/addons/addon-gallery/)。

由于插件非常简单，让我们看一个使用了所有前述插件的示例。首先，我们需要在`.storybook`目录中创建一个`addons.js`文件，每个要使用的插件都需要一行：

```js
import "@storybook/addon-actions/register";
import "@storybook/addon-knobs/register";
import "@storybook/addon-notes/register";
```

现在让我们修改我们的故事，使`CountryFilterBar`将显示其在选择事件上发送的值，并且还将显示一些描述该组件的注释，以便`ExpandableCard`可以让您调整其接收到的属性：

```js
// Source file: src/components/expandableCard.2/expandableCardWithAddon.story.js

import React from "react";
import { storiesOf } from "@storybook/react";
import { action } from "@storybook/addon-actions";
import { withNotes } from "@storybook/addon-notes";

import { CountryFilterBar } from "./";
import markDownText from "./countryFilterBar.md";

const countries = [
    { code: "AR", name: "Argentine" },
    { code: "BR", name: "Brazil" },
    { code: "PY", name: "Paraguay" },
    { code: "UY", name: "Uruguay" }
];

storiesOf("Country Filter Bar (with addons)", module).add(
    "with some countries - with actions and notes",
    withNotes(markDownText)(() => (
        <CountryFilterBar
            list={countries}
            onSelect={action("change:country")}
        />
    ))
);
```

对于动作，我提供了一个`action(...)`函数，它将在另一个选项卡“ACTION LOGGER”中显示其结果，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/87d8f759-c6a5-4ddf-8f57-cbb7d292837f.png)

每当您选择一个国家时，执行的回调及其参数将显示在 ACTIONS 选项卡中。

我点击了我的国家乌拉圭，我可以看到正在发送“UY”。

我还添加了一个`withNotes(...)`调用，提供了我创建的一个 markdown 文件中的文本。此内容将显示在 NOTES 选项卡中，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/4864a6f4-ebd6-45a8-a334-2032c28e1cf6.png)

您可以为每个组件提供良好的文档（不像我的！）

最后，我们可以添加一些“旋钮”，让用户动态修改参数。让他们修改卡片的标题和其中显示的数字：

```js
import React from "react";
import { storiesOf } from "@storybook/react";

import { withKnobs, text, number } from "@storybook/addon-knobs";

import { ExpandableCard } from "./";

storiesOf("Expandable Card (with knobs)", module)
 .addDecorator(withKnobs)
    .add("with normal contents", () => (
        <ExpandableCard key={229} title={text("Card title", "XYZZY")}>
            <div>CITIES: {number("Number of cities", 12)}</div>
            <div>POPULATION: {number("Population", 54321)}</div>
        </ExpandableCard>
    ));
```

当用户看到这个故事时，KNOBS 面板会让他们在屏幕上立即更新一些值。

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/mod-js-webdev-cb/img/43d12d96-4aa9-4cd5-8bae-6509eb01aec1.png)

向故事添加旋钮可以让用户尝试不同的设置。您在旋钮面板中输入的值会自动反映在组件中。

我们仅使用文本和数字，但您还可以为布尔值、颜色、日期、给定范围内的数字、对象、字符串数组和列表中的选项提供旋钮。
