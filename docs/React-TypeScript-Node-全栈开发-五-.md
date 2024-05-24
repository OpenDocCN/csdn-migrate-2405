# React TypeScript Node 全栈开发（五）

> 原文：[`zh.annas-archive.org/md5/F7C7A095AD12AA62E0C9F5A1E1F6F281`](https://zh.annas-archive.org/md5/F7C7A095AD12AA62E0C9F5A1E1F6F281)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：使用 Express 和 Redis 设置会话状态。

在本章中，我们将学习如何使用 Express 和 Redis 数据存储创建会话状态。Redis 是最流行的内存数据存储之一。它被 Twitter、GitHub、Stack Overflow、Instagram 和 Airbnb 等公司使用。我们将使用 Express 和 Redis 来创建我们的会话状态，这将成为我们应用程序身份验证功能的基础。

在本章中，我们将涵盖以下主要主题：

+   理解会话状态

+   理解 Redis

+   使用 Express 和 Redis 构建会话状态

# 技术要求

您应该对使用 Node.js 进行 Web 开发有很好的理解。我们将再次使用 Node 和 Visual Studio Code。

GitHub 存储库位于[`github.com/PacktPublishing/Full-Stack-React-TypeScript-and-Node`](https://github.com/PacktPublishing/Full-Stack-React-TypeScript-and-Node)。使用`Chap13`文件夹中的代码。

要设置*第十三章*代码文件夹，请转到您的`HandsOnTypescript`文件夹并创建一个名为`Chap13`的新文件夹。

# 理解会话状态

在本节中，我们将学习会话状态是什么以及为什么需要它。我们将重新审视网络工作的一些概念，并理解为什么我们需要会话状态。

网络实际上并不是一件事。它是许多技术的集合。网络的核心是 HTTP 协议。这是允许网络在互联网上工作的通信协议。协议只是一组用于通信的约定规则。这听起来有些简单，对于某些事情来说可能是。然而，对于我们的应用程序来说，情况就有点复杂了。

HTTP 协议是一种无连接的协议。这意味着 HTTP 连接仅在发出请求时建立，然后释放。因此，即使用户在网站上活跃使用数小时，连接也不会保持。这使得 HTTP 更具可伸缩性。然而，这也意味着在使用该协议时更难创建大型网站需要的某些功能。

让我们看一个现实世界的例子。假设我们是亚马逊，我们网站上有数百万用户试图购买物品。现在因为人们正在尝试购买物品，我们需要能够唯一标识这些用户。例如，如果我们同时在亚马逊上购物，您试图将物品添加到购物车中，我们需要确保您的物品不会出现在我的购物车中，反之亦然。这似乎应该很容易做到。然而，在像 HTTP 这样的无连接协议中，这很难。

在 HTTP 中，每个请求都会创建一个新的连接，每个新请求都不知道任何先前的请求。也就是说，它不保存状态数据。因此，回到我们的亚马逊例子，这意味着如果用户发出请求将物品添加到购物车中，没有内置的功能可以区分这个用户的请求和其他任何请求。当然，我们可以介入使用我们自己的功能，当然，这正是我们将在本章讨论的内容。但关键是，没有现成的东西可以直接使用。

需要明确的是，处理这个特定问题有许多方法。也许我们可以给每个用户一个唯一的 ID，并且他们可以在每次调用时传递它。或者我们可以将会话信息保存到数据库中，例如将购买物品保存在购物车中。当然，根据具体的要求，还有许多其他选项。然而，这些简单的想法需要详细阐述并详细说明。然后我们需要花时间测试它们。因此，实际上，无论我们在哪里，我们都希望避免自己开发功能，并且应选择行业标准解决方案。如果我们使用这些解决方案，我们知道它们已经经过了健壮性和安全性测试，并且将使用最佳实践。

我们将使用区分用户的方法将重点放在服务器端技术上，使用 Express 会话和 Redis 作为我们的数据存储。我们不会使用 JWT，因为它是客户端技术，比服务器端解决方案更容易受到安全漏洞的影响。

重要提示

每种解决方案都有其优缺点。当然，任何服务器都可能被黑客攻击。在服务器上使用安全解决方案并不能保证任何事情。然而，当涉及到您的服务器时，您至少可以保护和控制其设置，以尽量最大化其安全性。在用户的机器上，您根本无法控制。

在本节中，我们了解了会话状态是什么以及为什么它是必要的。我们了解了 HTTP 协议的一些缺失功能，以及我们如何为自己提供这些功能。在下一节中，我们将继续学习 Redis，这是我们将用来维护会话数据的数据存储。

# 了解 Redis

在这一部分，我们将学习关于 Redis 并安装它。我们还将简单介绍 Redis 以及它的工作原理。

Redis 是一个内存数据存储。它非常快速和可扩展。您可以使用 Redis 存储字符串、数据列表、集合等。成千上万的公司使用 Redis，它是免费和开源的。一般来说，Redis 最常用作内存数据库或缓存。

对于我们的用例，我们将使用 Redis 来作为 Express 会话的数据存储。Redis 支持 Linux 和 Mac。它在 Windows 上没有官方支持。您可以通过在 Windows 上使用 Docker 镜像来获得非官方支持，但这超出了本书的范围。然而，您通常可以在云提供商上获得免费的 Linux 虚拟机进行试用。因此，如果您使用 Windows，可以尝试其中的一项服务。

注意

`Redis.conf`有一个叫做 bind 的设置，它设置了 Redis 服务器将使用的本地 IP 地址，以及允许访问它的外部 IP 地址。将此设置注释将允许任何 IP 地址访问服务器。这对开发目的来说是可以的。然而，一旦进入生产阶段，您应该将其设置为特定值，并且只允许您希望访问服务器 IP 的 IP 地址。

让我们开始安装 Redis。目前，我正在使用 Mac：

1.  转到 Redis 网站[`redis.io/download`](https://redis.io/download)，并在稳定版本下选择**下载**。这是当前 6.0.7 版本的示例屏幕截图：

注意

请下载 6.0.x 版本，因为更高或更低版本可能会有破坏性的更改。

![图 13.1 – Redis 下载](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_13.1_B15508.jpg)

图 13.1 – Redis 下载

1.  一旦您下载并成功解压缩文件到一个文件夹中，使用终端并进入该文件夹。例如，这是我解压缩 tar 文件后终端的样子：![图 13.2 – Redis 稳定版解压缩](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_13.2_B15508.jpg)

图 13.2 – Redis 稳定版解压缩

1.  现在我们必须将我们的源文件制作成可运行的应用程序。只需在终端中输入`make`并让其运行。这将需要一些时间来完成。`make`命令运行的开始将如下所示：![图 13.3 – 运行 make 命令](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_13.3_B15508.jpg)

图 13.3 – 运行 make 命令

1.  现在我们已经构建了我们的服务器，随意将其移动到任何您喜欢的位置。我将其移动到了我的`Applications`文件夹中。在切换到`Redis`文件夹后，您需要运行以下命令：

```ts
src/redis-server
```

这是我本地运行的 Redis 服务器的屏幕截图：

![图 13.4 – 运行 Redis](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_13.4_B15508.jpg)

图 13.4 – 运行 Redis

警告

在 Mac 上，您可能会收到一个警告，询问您是否要允许 Redis 接受传入的网络请求。您应该允许此操作。

1.  让我们快速测试一下 Redis 是否正常工作。在 Redis 运行时，打开一个新的终端窗口，并从 Redis 的`src`文件夹中，输入以下命令：

```ts
ping to check that Redis is running. Then we use the set command to create a new value with the key test and value 1. Then we get that value successfully.
```

1.  现在我们知道我们的服务器已经正确安装，我们需要进行一些小的配置。首先用这个命令关闭服务器：

```ts
Chapter13 source code folder and copy the contents of the redis/redis.conf file. Then, in the terminal, run the following command:

```

sudo 密码，输入你的密码。这是大多数 Redis 配置位置的默认文件夹。接下来，运行这个命令：

```ts
redis.conf, file into this newly created file on /etc/redis/redis.conf.If you view this file and search for the keyword `requirepass`, pressing *Ctrl* + *W* or viewing from VSCode, you will see the password we are going to use for testing purposes only. Please do not use this password in production.For any other settings, we should be fine with the defaults.
```

```ts

```

1.  好的，现在让我们重新启动我们的 Redis 服务器，但这次指向我们的新`redis.conf`文件。输入这个命令：

```ts
Configuration loaded.Note that if you want to test the server again, this time you need to authenticate since we configured a password:

```

src/redis-cli

auth <password>

```ts

This is what it looks like:
```

![图 13.6 - Redis 的测试重启和 auth](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_13.6_B15508.jpg)

图 13.6 - Redis 的测试重启和 auth

在这一部分，我们讨论了 Redis 是什么，并进行了 Redis 服务的基本安装。在下一部分中，我们将通过创建一个最基本的 Node 和 Express 服务器并设置基于 Redis 的会话状态来启动我们的后端服务器代码。

# 使用 Express 和 Redis 构建会话状态

在这一部分，我们将开始构建我们的后端。我们将创建我们的 Express 项目并设置基于 Redis 的会话状态。

现在我们了解了 Redis 是什么以及如何安装它。让我们来看看 Express 和 Redis 如何在我们的服务器中一起工作。正如我们在*第八章*中讨论的那样，*使用 Node.js 和 Express 学习服务器端开发*，Express 基本上是 Node 的一个包装器。这个包装器通过使用中间件为 Node 提供了额外的功能。会话状态也是 Express 的一个中间件。

在我们的应用程序中，Express 将提供一个具有相关功能的会话对象，比如在用户浏览器上创建 cookie 以及各种函数来帮助设置和维护会话。Redis 将是我们会话数据的数据存储。由于 Redis 在存储和检索数据方面非常快速，它是 Redis 的一个很好的使用案例。

现在让我们使用 Express 和 Redis 创建我们的项目：

1.  首先，我们需要创建我们的项目文件夹`super-forum-server`。创建后，我们需要通过运行这个命令将其初始化为一个 NPM 项目（确保你的终端已经在`super-forum-server`文件夹中）：

```ts
name field inside of package.json to say super-forum-server. Feel free to also update the author field to your name as well.
```

1.  现在让我们安装我们的依赖项：

```ts
express package, but we also installed express-session. This package is what enables sessions in Express. We also installed connect-redis, which is what connects our Express session to a Redis data store. In addition to connect-redis, we need the ioredis package because it is the client that gives us access to the Redis server itself. I'll explain this further once we start coding. The dotenv package will allow us to use a config file, .env, to hold things like server passwords and other configurations. Then, in the second `install` command, we can see our development-related packages, which are mostly TypeScript definition packages like `@types/express`. However, notice in the end, we also install `ts-node-dev`. We use this package to help us start our server through the main `index.ts` file. The `ts-node-dev` package will trigger `tsc`, the TypeScript compiler, and get the final server up and running.WarningNever include your `dotenv` config file, `.env`, in your Git repository. It has sensitive information. You should have an offline process to maintain this file and share it with your developers.
```

1.  现在让我们更新我们的`package.json`文件，使用`ts-node-dev`助手。这个包非常有用，因为它在我们更改任何脚本时也会自动重新启动我们的服务器。将这一行添加到`package.json`的`scripts`部分中：

```ts
"start": "ts-node-dev --respawn src/index.ts"
```

注意在`respawn`之前有两个破折号。`index.ts`文件将是启动我们服务器的根文件。

1.  现在我们应该在我们的项目中设置 TypeScript。我们之前已经多次看到了 TypeScript 配置文件`tsconfig.json`，所以我不会在这里列出它（当然你可以在我们的源文件中找到它）。但请注意，我们将`target`设置为`ES6`，并且生产文件保存在`./dist`文件夹中。

1.  在项目的根目录下创建`src`文件夹。

1.  现在让我们创建我们的`.env`文件及其条目。将这些设置复制到你自己的文件中，但使用你自己的唯一的秘密值！[](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/B15508_13_Table_AM.jpg)

1.  现在让我们创建`index.ts`文件。首先让我们创建一个最基本的文件，只是为了确保我们的服务器能够运行。将这个输入到文件中：

```ts
import express from "express";
```

在这里，我们已经导入了 Express。

```ts
console.log(process.env.NODE_ENV);
```

在这里，我们展示了我们所在的环境 - 生产环境还是开发环境。如果你还没有设置你的本地环境，请在终端上使用这个命令来设置。

对于 Mac，使用这个命令：

```ts
dotenv package and set up default configurations. This is what allows our .env file to be used in our project.

```

const app = express();

```ts

Here, we instantiate our `app` object with `express`. So, we'll add all our middleware onto the `app` object. Since almost everything in Express is middleware, session state is also middleware.

```

app.listen({ port: process.env.SERVER_PORT }, () => {

console.log(`服务器已准备就绪，端口为${process.env.   SERVER_PORT}`);

});

```ts

And here, we have initialized our server and when it is running, it will show the log message shown. Run the following command:

```

npm start

```ts

You should see the following log message on your terminal:![Figure 13.7 First run of the Express server    ](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_13.7_B15508.jpg)Figure 13.7 First run of the Express server
```

1.  现在我们知道我们的基本服务器已经正确运行，让我们添加我们的 Express 会话状态和 Redis：

```ts
import express from "express";
import session from "express-session";
import connectRedis from "connect-redis";
import Redis from "ioredis";
```

首先，你可以看到我们导入了`expression-session`和我们的与 Redis 相关的包。

```ts
console.log(process.env.NODE_ENV);
require("dotenv").config();
const app = express();
const router = express.Router();
```

在这里，我们初始化了我们的`router`对象。

```ts
const redis = new Redis({
  port: Number(process.env.REDIS_PORT),
  host: process.env.REDIS_HOST,
  password: process.env.REDIS_PASSWORD,
});
```

`redis`对象是我们的 Redis 服务器的客户端。正如你所看到的，我们已经将配置信息的值隐藏在我们的`.env`文件后面。你可以想象一下，如果我们能够看到密码和其他安全信息硬编码到我们的代码中，那将是多么不安全。

```ts
const RedisStore = connectRedis(session);
const redisStore = new RedisStore({
  client: redis,
});
```

现在我们已经创建了我们的`RedisStore`类和`redisStore`对象，我们将使其成为我们 Express 会话的数据存储。

```ts
app.use(
  session({
    store: redisStore,
    name: process.env.COOKIE_NAME,
    sameSite: "Strict",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      path: "/",
      httpOnly: true,
      secure: false,
      maxAge: 1000 * 60 * 60 * 24,
    },
  } as any)
);
```

会话对象有一些选项。一个选项，`store`，是我们添加`redisStore`对象的地方。`sameSite`值表示不允许来自其他域的 cookie，这增强了安全性。`secret`字段再次是我们特定会话的一种密码或唯一 ID。`cookie`字段设置了我们保存到用户浏览器上的 cookie。`httpOnly`字段意味着 cookie 无法从 JavaScript 中获取。这使得 cookie 更加安全，可以防止 XSS 攻击。`secure`字段是`false`，因为我们没有使用 HTTPS。

```ts
app.use(router);
router.get("/", (req, res, next) => {
  if (!req.session!.userid) {
    req.session!.userid = req.query.userid;
    console.log("Userid is set");
    req.session!.loadedCount = 0;
  } else {
    req.session!.loadedCount = Number(req.session!.     loadedCount) + 1;
  }
```

我们已经设置了我们的`router`对象和我们的一个路由，即 GET。基本上，我们所做的是从 URL 查询字符串中获取`userid`，然后用它设置我们用户的唯一`session.userid`字段。我们还计算调用的次数，以显示会话在调用之间保持活动状态。

```ts
  res.send(
    `userid: ${req.session!.userid}, loadedCount: 
      ${req.session!.loadedCount}`
  );
```

在这里，我们通过发送会话信息作为字符串返回来做出响应。

```ts
});
app.listen({ port: process.env.SERVER_PORT }, () => {
  console.log(`Server ready on port ${process.env.SERVER_   PORT}`);
});
```

最后，我们的`express`服务器在端口 5000 上监听，这是我们的`SERVER_PORT`设置的值。如下图所示，cookie 在第一次加载时被创建：

![图 13.8 - 两个浏览器显示不同的会话状态](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_13.8_B15508.jpg)

图 13.8 - 两个浏览器显示不同的会话状态

请注意，我们使用两个浏览器来显示创建唯一会话。如果我们使用一个浏览器，会话将不是唯一的，因为将使用相同的 cookie。

在本节中，我们利用了我们对 Express 和 Redis 的知识，并为我们的 SuperForum 应用程序实现了一个基本项目。我们看到了 Express 和 Redis 在创建会话中所起的作用。我们还看到了如何使用会话为每个访问我们网站的用户创建一个唯一的数据容器。

# 总结

在本章中，我们学习了会话和 Redis 数据存储服务。我们还学习了如何将 Redis 与 Express 集成，以便为我们的用户创建唯一的会话。这对于在后续章节中构建我们的身份验证服务至关重要。

在下一章中，我们将设置我们的 Postgres 服务器并创建我们的数据库架构。我们还将学习 TypeOrm，这将允许我们从我们的应用程序集成和使用 Postgres。最后，我们还将构建我们的身份验证服务并将其与我们的会话状态联系起来。


# 第十四章：使用 TypeORM 设置 Postgres 和存储库层

在本章中，我们将学习如何使用 Postgres 作为我们的数据库和 TypeORM 作为访问数据库的库来设置存储库层。我们将构建我们的数据库架构，并借助 TypeORM，我们将能够为我们的应用程序执行**CRUD**（**创建，读取，更新，删除**）操作。这是一个关键的章节，因为我们的后端的核心活动将是检索和更新数据。

在本章中，我们将涵盖以下主要主题：

+   设置我们的 Postgres 数据库

+   通过使用 TypeORM 来理解对象关系映射器

+   使用 Postgres 和 TypeORM 构建我们的存储库层

# 技术要求

本书不会教授关系数据库知识。因此，你应该对 SQL 有基本的了解，包括简单的查询和表结构，以及使用 Node 进行 Web 开发。我们将再次使用 Node 和 Visual Studio Code 来编写我们的代码。

GitHub 存储库位于[`github.com/PacktPublishing/Full-Stack-React-TypeScript-and-Node`](https://github.com/PacktPublishing/Full-Stack-React-TypeScript-and-Node)。使用`Chap14`文件夹中的代码。

要设置*第十四章*的代码文件夹，请转到你的`HandsOnTypescript`文件夹，并创建一个名为`Chap14`的新文件夹。

# 设置我们的 Postgres 数据库

在本节中，我们将安装和设置 Postgres 数据库。关系数据库仍然非常重要，而现在 NoSQL 数据库非常流行。然而，根据 StackOverflow 的说法，Postgres 仍然是世界上最受欢迎的数据库之一。此外，它的性能是世界一流的，比 MongoDB 高出很大的边际（[`www.enterprisedb.com/news/new-benchmarks-show-postgres-dominating-mongodb-varied-workloads`](https://www.enterprisedb.com/news/new-benchmarks-show-postgres-dominating-mongodb-varied-workloads)）。因此，Postgres 是我们将使用的数据库技术。

让我们安装我们的 Postgres 数据库。我们将使用 EDB 提供的安装程序。EDB 是一家第三方公司，提供支持 Postgres 的工具和服务：

1.  转到网址[`www.enterprisedb.com/downloads/postgres-postgresql-downloads`](https://www.enterprisedb.com/downloads/postgres-postgresql-downloads)，并选择适合你平台的下载。我将使用 Mac 的 12.4 版本，这是我写作时的最新 Mac 版本。

1.  接受安装程序上的所有默认设置，包括要安装的组件列表，如下所示：![图 14.1 - Postgres 设置屏幕](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_14.01_B15508.jpg)

图 14.1 - Postgres 设置屏幕

1.  安装完成后，启动`pgAdmin`应用程序。这个应用程序是 Postgres 的管理员应用程序。你应该会看到这样的屏幕：![图 14.2 - pgAdmin 的第一个视图](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_14.02_B15508.jpg)

图 14.2 - pgAdmin 的第一个视图

如你所见，这是一个 Web 浏览器应用程序。我在我的安装中有一些其他服务器，但如果这是你的第一个`pgAdmin`安装，你的安装应该没有任何服务器。

1.  现在，让我们创建一个名为`HandsOnFullStackGroup`的新服务器组，这样我们就可以将我们的工作与其他人分开。服务器组只是一个容器，可以容纳多个服务器实例，每个服务器可以在其中拥有多个数据库。请注意，一个服务器**并不**表示一个单独的物理机器。

1.  首先，通过右键单击**Servers**项目，选择**Server Group**选项，如下所示：![图 14.3 - pgAdmin 添加服务器组](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_14.03_B15508.jpg)

图 14.3 - pgAdmin 添加服务器组

1.  接下来，在第一个屏幕上右键单击新的`SuperForumServers`，创建一个服务器，如下所示：![图 14.4 - 创建 - 服务器选项卡](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_14.04_B15508.jpg)

图 14.4 - 创建 - 服务器选项卡

1.  现在，选择第二个选项卡，`localhost`作为`postgres`。Postgres 账户是根管理员账户，所以你需要记住这个密码。这是这个选项卡的截图：![图 14.5 – 连接选项卡](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_14.05_B15508.jpg)

图 14.5 – 连接选项卡

1.  选择**保存**，你的服务器将被创建。你应该会看到以下视图：

![图 14.6 – 新的 HandsOnFullStackGroup 和 SuperForumServers 视图](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_14.06_B15508.jpg)

图 14.6 – 新的 HandsOnFullStackGroup 和 SuperForumServers 视图

请注意，那里已经有一个名为**postgres**的数据库。这个数据库是空的，但可以用来存储全局数据。

现在，让我们为我们的应用程序创建数据库。但是，在我们这样做之前，我们需要创建一个新的账户，专门用于与我们的新数据库相关联。使用默认管理员账户 postgres 不是一个好主意，因为如果被黑客攻击，它将给予攻击者对整个服务器的访问权限：

1.  在`pgAdmin`中，右键单击`superforumsvc`。然后，在**定义**选项卡中，设置您自己的密码。接下来，转到**权限**选项卡，并**确保**启用登录。其余设置可以保持默认设置。

1.  接下来，右键单击`SuperForum`，选择**superforumsvc**作为**所有者**：![图 14.7 – 创建 SuperForum 数据库](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_14.07_B15508.jpg)

图 14.7 – 创建 SuperForum 数据库

1.  然后，点击**保存**。你的视图现在应该显示如下：

![图 14.8 – 新数据库和用户](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_14.08_B15508.jpg)

图 14.8 – 新数据库和用户

太棒了！我们现在有了一个数据库。如果我们不使用 ORM，我们将不得不经历手动创建表和字段的繁琐过程。但是，正如你将看到的，TypeORM 可以帮我们省去这些苦工，同时为我们提供了很棒的语言特性来查询我们的数据库。

在下一节中，我们将深入了解 TypeORM。我们将学习它是如何工作的，以及它如何在许多层面上帮助我们与我们的数据库交互。

# 通过使用 TypeORM 来理解对象关系映射器

在本节中，我们将学习什么是**对象关系映射器**（**ORM**）技术。我们还将了解 TypeORM，这是 JavaScript 中最流行的 ORM 框架之一。ORM 可以使与数据库的工作变得更加容易，并减少开发人员的一些认知负担。

作为程序员，你知道不同的编程语言具有不兼容的类型。例如，尽管名字相似，JavaScript 不能直接使用甚至访问 Java 类型。为了让任一语言使用另一语言的类型，我们需要进行某种形式的翻译。部分原因是有了诸如 Web API 这样的服务。Web API 以字符串格式（如 JSON）提供所有数据给调用者。这允许任何调用者使用数据，因为它可以被任何语言读取。

数据库到编程语言的转换具有类似的类型不兼容性。因此，通常在进行返回数据的查询之后，我们需要从数据库中取出每个字段的值，并手动编写代码将其转换为编程语言中的特定类型。然而，如果我们使用 ORM，大部分工作都会消失。

ORM 被设计成*知道*如何将数据库字段映射到代码字段，并为我们处理这些翻译工作。此外，大多数 ORM 都具有某种能力，根据在代码中创建的实体结构自动在数据库上创建表和字段。你可以将实体视为编程语言端表示与数据库端表类似对象的类型。例如，如果我们在 JavaScript 中有一个名为`User`的实体，那么我们期望在数据库中有一个名为`Users`的表与之匹配（它是复数形式，因为一个表可以容纳多个用户）。

仅此功能就可以为开发人员节省大量的时间和精力，但除此之外，一个良好的 ORM 还将具有帮助构建查询、安全插入参数（减少 SQL 注入攻击的机会）以及处理事务的功能。事务是必须完全完成的原子数据库操作，否则涉及的所有操作都将被撤消。

注意

SQL 注入攻击是恶意人员尝试插入与开发人员最初意图不同的 SQL 代码的尝试。它可能导致诸如数据丢失和应用程序失败等问题。

对于我们的应用程序，我们将使用 TypeORM。TypeORM 是一个受欢迎且备受好评的 TypeScript ORM，在 GitHub 上有超过 20,000 个赞。它提供了所有提到的功能，并且很容易入门，尽管成为高级用户需要相当大的努力。它支持多个数据库，包括 Microsoft SQL、MySQL 和 Oracle。

它将通过其丰富的功能集为我们节省大量时间，并且因为许多 JavaScript 项目使用 TypeORM，所以有一个庞大的开发人员社区可以在您使用它时提供帮助。

在本节中，我们了解了 ORM 技术。我们了解了它是什么，以及为什么使用它是重要和有价值的。在下一节中，我们将使用 TypeORM 来构建我们自己的项目。让我们开始吧。

# 使用 Postgres 和 TypeORM 构建我们的存储库层

在本节中，我们将了解使用存储库层的重要性。为我们的应用程序的一个重要部分设置一个单独的层可以帮助简化代码重构。从逻辑上分离主要部分也有助于理解应用程序的工作原理。

在*第一章*中，*理解 TypeScript*，我们学习了**面向对象编程**（**OOP**）。实现 OOP 设计的主要机制之一是使用抽象。通过在其自己的单独层中创建我们的数据库访问代码，我们正在使用抽象。正如您可能记得的那样，抽象的好处之一是它隐藏了代码的内部实现并向外部调用者公开接口。此外，因为与访问数据库相关的所有代码都在一个地方，我们不必四处寻找我们的数据库查询代码。我们知道这段代码位于我们应用程序的哪个层中。保持代码逻辑上的分离被称为关注点分离。

因此，让我们开始构建我们的存储库层：

1.  首先，我们需要复制我们在*第十三章*中创建的服务器代码，*使用 Express 和 Redis 设置会话状态*。转到源代码中的`Chapter13`文件夹，并将`super-forum-server`文件夹复制到`Chapter14`文件夹中。

```ts
npm install 
```

1.  接下来，我们需要安装 TypeORM 及其相关依赖项。运行以下命令：

```ts
typeorm. pg is the client to communicate with Postgres. bcryptjs is an encryption library that we will use to encrypt our passwords before inserting into the database. cors is needed to allow us to receive client-side requests from a different domain, other than our server's domain. In modern apps, it's possible the client-side code is not being served from the same server as the server-side code. This is especially true when we are creating an API such as GraphQL, which may be used by multiple clients. You'll also see this when we start integrating our client's React app with the server, as they will run on different ports.`class-validator` is a dependency for assigning decorators for validation. We'll discuss this in more detail later with the help of examples.
```

1.  现在，在我们开始创建我们的实体数据库之前，我们需要创建一个配置文件，以便我们的 TypeORM 代码可以访问我们的 Postgres 数据库。这意味着我们还需要更新我们的`.env`文件与我们的数据库配置。打开`.env`文件并添加这些变量。我们的服务器是在本地安装的，所以`PG_HOST`的值为`localhost`：

```ts
PG_HOST=localhost
```

服务器用于通信的端口如下：

```ts
PG_PORT=5432
```

我们的数据库帐户名称如下：

```ts
PG_ACCOUNT=superforumsvc
```

使用您为自己的数据库创建的密码：

```ts
PG_PASSWORD=<your-password>
```

我们的数据库名称如下：

```ts
PG_DATABASE=SuperForum
```

如前所述，TypeORM 将为我们创建表和字段，并在其更改时对其进行维护。 `PG_SYNCHRONIZE`启用了该功能：

```ts
PG_SYNCHRONIZE=true
```

当然，一旦您在生产中投入使用，您必须禁用此功能，以防止不必要的数据库更改。

我们的实体文件的位置，包括子目录，如下：

```ts
PG_ENTITIES="src/repo/**/*.*"
```

我们的实体的根目录如下：

```ts
PG_ENTITIES_DIR="src/repo"
```

`PG_LOGGING`确定是否在服务器上启用日志记录：

```ts
PG_LOGGING=false
```

在生产环境中应该启用日志以跟踪问题。但是，日志可能会创建巨大的文件，所以我们不会在开发中启用它。

1.  现在我们可以创建我们的 TypeORM 配置文件。在我们项目的根目录`Chap13/super-forum-server`中，创建名为`ormconfig.js`的文件，并将以下代码添加到其中：

```ts
require("dotenv").config();
```

首先，我们通过`require`获取我们的`.env`配置：

```ts
module.exports = [
  {
    type: "postgres",
```

我们将连接到哪种数据库类型？由于 TypeORM 支持多个数据库，我们需要指示这一点。

其余的值使用我们的`.env`文件中的配置，因此它们是不言自明的：

```ts
    host: process.env.PG_HOST,
    port: process.env.PG_PORT,
    username: process.env.PG_ACCOUNT,
    password: process.env.PG_PASSWORD,
    database: process.env.PG_DATABASE,
    synchronize: process.env.PG_SYNCHRONIZE,
    logging: process.env.PG_LOGGING,
    entities: [process.env.PG_ENTITIES],
    cli: {
      entitiesDir: process.env.PG_ENTITIES_DIR
    },
  }
];
```

现在，我们准备开始创建我们的实体。

1.  现在我们已经安装了依赖项并设置了数据库的配置，让我们创建我们的第一个实体，用户。将目录更改为`Chap14/super-forum-server`文件夹，然后在`src`文件夹内创建一个名为`repo`的文件夹。我们将把所有的存储库代码放在那里。然后，在`repo`内创建一个名为`User.ts`的文件，并在其中添加以下代码：

```ts
import { Entity, PrimaryGeneratedColumn, Column } from "typeorm";
```

这些 TypeORM 导入将允许我们创建我们的`User`实体类。`Entity`、`PrimaryGeneratedColumn`和`Column`被称为装饰器。装饰器是放置在相关代码行之前的属性，提供有关字段或对象的附加配置信息。你可以把它们看作是一种快捷方式。你可以简单地添加一个标签来设置配置，而不是编写一些长长的代码行。我们将在这段代码中看到例子：

```ts
import { Length } from "class-validator";
```

这是一个长度的验证器。

接下来是我们第一次使用装饰器。`Entity`装饰器告诉 TypeORM 即将定义的类是一个名为`Users`的实体。换句话说，在我们的代码中，我们将有一个称为`User`的对象，它直接映射到我们数据库中称为`Users`的表：

```ts
@Entity({ name: "Users" })
```

在数据库中，每个表必须有一个唯一的标识字段。这就是`PrimaryGeneratedColumn`的含义。字段名称将是`id`。请注意，`id`中的"""不是大写。我们稍后会解决这个问题：

```ts
export class User {
  @PrimaryGeneratedColumn({ name: "id", type: "bigint" })
  id: string;
```

接下来，我们将首次使用`Column`装饰器：

```ts
  @Column("varchar", {
    name: "Email",
    length: 120,
    unique: true,
    nullable: false,
  })
  email: string;
```

正如你所看到的，它用于定义数据库字段`Email`，在我们的 TypeScript 代码中将被称为`email`。因此，装饰器再次被用来将我们的代码对象映射到数据库实体。现在，让我们更仔细地看一下`Column`装饰器。首先，它定义了我们的列是`varchar`数据库类型。再次强调，数据库类型与代码类型不同，如此处所示。接下来，我们看到`name`字段，设置为`Email`。这将是`Users`表中此字段的确切名称。然后我们有`length`，它表示此字段允许的最大字符数。`unique`属性告诉 Postgres 强制每个`User`条目必须具有唯一的电子邮件。最后，我们将`nullable`设置为`false`，这意味着此字段在数据库中必须有一个值：

```ts
  @Column("varchar", {
    name: "UserName",
    length: 60,
    unique: true,
    nullable: false,
  })
  userName: string;
  @Column("varchar", { name: "Password", length: 100,   nullable: false })
@Length(8, 100)
```

在这里，我们使用`Length`装饰器来确保输入的字段具有最小和最大字符长度：

```ts
  password: string;
```

两个字段，`userName`和`password`，都将`varchar`作为列，具有与`email`类似的设置：

```ts
  @Column("boolean", { name: "Confirmed", default: false, 
    nullable: false })
  confirmed: boolean;
```

现在，我们看到了一个`confirmed`字段，它是`boolean`类型。`confirmed`字段将显示新注册用户帐户是否已经通过电子邮件验证。请注意，这是相当不言自明的，但默认设置表明，当前记录插入数据库时，除非明确设置，它将被设置为`false`：

```ts
  @Column("boolean", { name: "IsDisabled", default:     false, nullable: false }) 
  isDisabled: boolean;
}
```

最后，这是`isDisabled`字段，它将允许我们出于管理目的禁用帐户。

1.  太好了！现在我们可以看到 TypeORM 是否会代表我们创建新的`Users`表。我们需要做的最后一件事是从我们的代码连接到 Postgres 数据库。像这样更新`index.ts`：

```ts
import express from "express";
import session from "express-session";
import connectRedis from "connect-redis";
import Redis from "ioredis";
import { createConnection } from "typeorm";
require("dotenv").config();
```

我们已经从 TypeORM 导入了`createConnection`函数：

```ts
const main = async () => {
  const app = express();
  const router = express.Router();
await createConnection();
```

在这里，我们调用了`createConnection`。但请注意，我们的代码现在包裹在一个名为`main`的`async`函数中。我们需要这样做的原因是`createConnection`是一个`async`调用，需要一个`await`前缀。因此，我们不得不将其包装在一个`async`函数中，这就是`main`函数的作用。

其余的代码是一样的，如下所示：

```ts
  const redis = new Redis({
    port: Number(process.env.REDIS_PORT),
    host: process.env.REDIS_HOST,
    password: process.env.REDIS_PASSWORD,
  });
  const RedisStore = connectRedis(session);
  const redisStore = new RedisStore({
    client: redis,
  });
  app.use(
    session({
      store: redisStore,
      name: process.env.COOKIE_NAME,
      sameSite: "Strict",
      secret: process.env.SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      cookie: {
        path: "/",
        httpOnly: true,
        secure: false,
        maxAge: 1000 * 60 * 60 * 24,
      },
    } as any)
);
```

再次，代码是一样的：

```ts
  app.use(router);
  router.get("/", (req, res, next) => {
    if (!req.session!.userId) {
      req.session!.userId = req.query.userid;
      console.log("Userid is set");
      req.session!.loadedCount = 0;
    } else {
      req.session!.loadedCount = Number(req.session!.       loadedCount) + 1;
    }
    res.send(
      `userId: ${req.session!.userId}, loadedCount: 
        ${req.session!.loadedCount}`
    );
  });
  app.listen({ port: process.env.SERVER_PORT }, () => {
    console.log(`Server ready on port 
     ${process.env.SERVER_PORT}`);
  });
};
main();
```

最后，我们调用了我们的`main`函数来执行它。

1.  现在，通过运行以下命令来运行我们的应用程序：

```ts
pgAdmin and go to the Users table with all of its columns created for us:![Figure 14.9 – New Users table    ](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_14.09_B15508.jpg)Figure 14.9 – New Users tableThis is such a huge time saver! Could you imagine if we had to create each of our tables manually ourselves? With all of their fields and constraints? This would take hours.Notice that our columns have the same settings as from our decorators. For example, our email has a variety of characters, with a length of 120, and is not nullable. 
```

1.  然而，我们有一个小问题。我们的`id`列尽管其他列都是大写，但没有使用大写。让我们来修复这个问题。再次打开`User.ts`文件，只需将`PrimaryGeneratedColumn`装饰器的名称设置更改为`Id`而不是`id`（只在装饰器中；在我们的 JavaScript 中保留`id`字段名称）。如果您的服务器没有运行，请重新启动。但重新启动后，刷新`id`列已更新为`Id`。这是 TypeORM 的一个很棒的功能，因为手动更改列名或约束有时可能很痛苦。

1.  太棒了！现在我们只需要创建我们的其他实体：`Thread`和`ThreadItem`。再次强调，`Thread`是我们论坛中的初始帖子，而`ThreadItems`是回复。首先，停止服务器，以免在我们准备好之前创建数据库项。现在，由于这大部分是重复的，我将在这里只显示代码而不加注释。

这两个文件的导入将是相同的，如下所示：

```ts
import { Entity, PrimaryGeneratedColumn, Column } from "typeorm";
import { Length } from "class-validator";
```

`Thread`实体目前看起来是这样的（一旦建立了表关系，我们将添加更多字段）：

```ts
@Entity({ name: "Threads" })
export class Thread {
  @PrimaryGeneratedColumn({ name: "Id", type: "bigint" })
  id: string;
  @Column("int", { name: "Views", default: 0, nullable:    false })
  views: number;
  @Column("boolean", { name: "IsDisabled", default:     false, nullable: false }) 
  isDisabled: boolean;
  @Column("varchar", { name: "Title", length: 150,    nullable: false })
  @Length(5, 150)
  title: string;
  @Column("varchar", { name: "Body", length: 2500,    nullable: true
   })
  @Length(10, 2500)
  body: string;
}
```

`ThreadItem`看起来是这样的：

```ts
@Entity({ name: "ThreadItems" })
export class ThreadItem {
  @PrimaryGeneratedColumn({ name: "Id", type: "bigint" })
  id: string;
  @Column("int", { name: "Views", default: 0, nullable:   false })
  views: number;
  @Column("boolean", { name: "IsDisabled", default:    false, nullable: false })
  isDisabled: boolean;
  @Column("varchar", { name: "Body", length: 2500,    nullable: true
   })
  @Length(10, 2500)
  body: string;
}
```

1.  如您所见，这两个实体都非常简单。现在重新启动服务器，您应该会看到两个新表：**Threads**和**ThreadItems**：

![图 14.10 - Threads 和 ThreadItems](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_14.10_B15508.jpg)

图 14.10 - Threads 和 ThreadItems

我们还有许多字段要添加，比如 points 列。但首先，让我们在表之间建立一些关系。例如，每个表都应该与特定的用户有关联。让我们从添加这些关系开始：

1.  首先，停止服务器。然后，在您的`User.ts`文件中，将此添加到您的类的底部。我假设您现在知道如何添加任何必需的导入，不再提及它们：

```ts
@OneToMany(() => Thread, (thread) => thread.user)
  threads: Thread[];
```

`OneToMany`装饰器显示每个单独的`User`可能有多个关联的`Threads`。

1.  现在，将这段代码添加到您的`Thread.ts`文件的`Thread`类的底部：

```ts
@ManyToOne(
    () => User,
    (user:User) => user.threads
  )
  user: User;
```

`ManyToOne`装饰器显示每个`Thread`只有一个与之关联的`User`。尽管教授 SQL 超出了本书的范围，但简单地说，这些关系作为数据库的约束，意味着我们无法插入没有意义的数据；例如，拥有多个`Users`*拥有*一个`Thread`。

1.  现在，让我们建立`Thread`与`ThreadItems`之间的关系。将以下代码添加到`Thread`类中：

```ts
@OneToMany(
    () => ThreadItem,
    threadItems => threadItems.thread
  )
  threadItems: ThreadItem[];
```

再次，这表明一个`Thread`可以有多个与之关联的`ThreadItems`。现在，让我们更新我们的`ThreadItem`：

```ts
@ManyToOne(() => User, (user) => user.threads)
  user: User;
```

`ThreadItem`和`Thread`一样，只能与一个`User`关联为所有者：

```ts
  @ManyToOne(() => Thread, (thread) => thread.   threadItems)
  thread: Thread;
```

1.  每个`ThreadItem`只能有一个父`Thread`。现在，如果重新启动服务器，您应该会看到这些新的关系：

![图 14.11 - 关系](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_14.11_B15508.jpg)

图 14.11 - 关系

您将看到`Threads`和`ThreadItems`表中已添加了新列。例如，在`ThreadItems`中，添加了`userId`和`threadId`以指示它们的相关关系。但是，在`Users`表中没有添加任何内容。这是因为`Users`表与`Threads`表具有`OneToMany`关系。因此，此关系由图像中`CREATE TABLE public."Threads"`脚本所示的约束表示。正如您所看到的，`userId`列有一个约束。因此，通过指示每个线程都有一个与之关联的`User`，它隐含地指示每个`User`可以拥有一个或多个自己拥有的`Threads`。

现在，让我们设置我们的积分系统。在积分的情况下，即喜欢或不喜欢，我们需要允许用户只能投票一次。但是，没有办法在单个表的术语中指示这一点。因此，我们将创建两个新表，`ThreadPoints`和`ThreadItemPoints`，它们将与相关的`Users`，`Threads`和`ThreadItems`关联。

1.  首先，关闭服务器，然后创建`ThreadPoint.ts`文件。然后，将以下代码添加到其中：

```ts
@Entity({ name: "ThreadPoints" })
export class ThreadPoint {
  @PrimaryGeneratedColumn({ name: "Id", type: "bigint" }) 
    // for typeorm
  id: string;
  @Column("boolean", { name: "IsDecrement", default:    false, nullable: false })
  isDecrement: boolean;
  @ManyToOne(() => User, (user) => user.threadPoints)
  user: User;
  @ManyToOne(() => Thread, (thread) => thread.   threadPoints)
  thread: Thread;
}
```

因此，在这段代码中，我们在指定特定的`User`和`Thread`。我们还指出，如果`isDecrement`字段为`true`，则这构成了不喜欢。这意味着积分有三种可能的状态：没有积分，喜欢或不喜欢。我们稍后将编写一些代码来处理这三种状态的存储库查询。

1.  现在，将以下代码添加到`User.ts`类中：

```ts
@OneToMany(() => ThreadPoint, (threadPoint) => threadPoint.user)
  threadPoints: ThreadPoint[];
```

同样，此代码完成了代码中的关联。

1.  接下来，将以下内容添加到`Thread.ts`类中：

```ts
@OneToMany(() => ThreadPoint, (threadPoint) => 
 threadPoint.thread)
  threadPoints: ThreadPoint[];
```

这也完成了与`ThreadPoint`的关联。

1.  现在，我们需要为`ThreadItemPoints`做同样的事情。创建`ThreadItemPoint.ts`并添加以下代码：

```ts
@Entity({ name: "ThreadItemPoints" })
export class ThreadItemPoint {
  @PrimaryGeneratedColumn({ name: "Id", type: "bigint" }) 
    // for typeorm
  id: string;
  @Column("boolean", { name: "IsDecrement", default:   false,
   nullable: false })
  isDecrement: boolean;
  @ManyToOne(() => User, (user) => user.threadPoints)
  user: User;
  @ManyToOne(() => ThreadItem, (threadItem) => 
    threadItem.threadItemPoints)
  threadItem: ThreadItem;
}
```

这与`ThreadPoint`的设置非常相似。

1.  现在，通过添加以下内容来更新我们的`User`类：

```ts
@OneToMany(() => ThreadItemPoint, (threadItemPoint) => 
 threadItemPoint.user)
  threadItemPoints: ThreadItemPoint[];
```

然后，通过添加以下内容来更新我们的`ThreadItem`类：

```ts
@OneToMany(
    () => ThreadItemPoint,
    (threadItemPoint) => threadItemPoint.threadItem
  )
  threadItemPoints: ThreadItemPoint[];
```

这也完成了与`ThreadItemPoint`相关的关联。

但我们还没有完成。您可能还记得*第十一章*，*我们将学到什么-在线论坛应用*，我们的主题将有类别，因此我们还需要创建该实体及其关系：

1.  首先，创建`ThreadCategory.ts`文件，并将以下代码添加到其中：

```ts
@Entity({ name: "ThreadCategories" })
export class ThreadCategory {
  @PrimaryGeneratedColumn({ name: "Id", type: "bigint" }) 
    // for typeorm
  id: string;
  @Column("varchar", {
    name: "Name",
    length: 100,
    unique: true,
    nullable: false,
  })
  name: string;
  @Column("varchar", {
    name: "Description",
    length: 150,
    nullable: true,
  })
  description: string;
  @OneToMany(() => Thread, (thread) => thread.category)
  threads: Thread[];
}
```

`ThreadCategory`与其他实体有一个非常相似的设置。

1.  现在，将以下内容添加到`Thread.ts`类中：

```ts
@ManyToOne(() => ThreadCategory, (threadCategory) => 
  threadCategory.threads)
  category: ThreadCategory;
```

当然，这就建立了`Thread`和`ThreadCategory`之间的关系。

1.  现在，运行服务器，它应该创建表和关联。

现在我们已经创建了所需的实体及其关联。但是，每当我们向数据库添加数据时，我们希望记录其创建或更改的时间。但是，实现这一点将在所有实体中创建相同的字段，我们不希望一遍又一遍地编写相同的代码。

由于 TypeScript 允许我们在类中使用继承，因此让我们创建一个具有我们需要的这些字段的基本类型，然后让每个实体简单地从这个基类继承。此外，TypeORM 要求我们的实体必须从其自己的基类继承，以便能够连接到其 API。因此，让我们在我们自己的基类中也添加 TypeORM 基类：

1.  创建一个名为`Auditable.ts`的文件，并添加以下代码：

```ts
import { Column, BaseEntity } from "typeorm";
export class Auditable extends BaseEntity {
  @Column("varchar", {
    name: "CreatedBy",
    length: 60,
    default: () => `getpgusername()`,
    nullable: false,
  })
  createdBy: string;
```

`Getpgusername`是服务账户`superforumsvc`，除非明确设置，否则该字段将默认为此：

```ts
  @Column("timestamp with time zone", {
    name: "CreatedOn",
    default: () => `now()`,
    nullable: false,
  })
  createdOn: Date;
```

除非明确设置，否则该字段将默认为当前时间和日期`now()`。

正如您所看到的，字段的作用是相当不言自明的。但是，请注意我们的基类`Auditable`还扩展了名为`BaseEntity`的 TypeORM 基类。这种`BaseEntity`继承是允许我们的实体通过 TypeORM 访问 Postgres 数据库的原因：

```ts
  @Column("varchar", {
    name: "LastModifiedBy",
    length: 60,
    default: () => `getpgusername()`,
    nullable: false,
  })
  lastModifiedBy: string;
  @Column("timestamp with time zone", {
    name: "LastModifiedOn",
    default: () => `now()`,
    nullable: false,
  })
  lastModifiedOn: Date;
}
```

1.  好的，这就是新的`Auditable`基类的内容。现在我们想让我们的实体继承它。这很简单。例如，在`User`类中，只需添加`extends`关键字并像这样添加`Auditable`类：

```ts
export class User extends Auditable {
```

对每个实体重复此过程，然后重新启动服务器（记得根据需要添加导入语句）。刷新视图后，您应该看到新的字段如下：

![图 14.12-更新为可审计的用户](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_14.12_B15508.jpg)

图 14.12-更新为可审计的用户

太棒了！现在我们可以创建实际调用我们数据库的存储库库。由于我们在上一章中创建了我们的会话状态，[*第十三章*]（B15508_13_Final_JC_ePub.xhtml#_idTextAnchor208），*使用 Express 和 Redis 设置会话状态*，让我们首先创建与身份验证相关的调用：

1.  在创建我们的主要代码之前，我们需要先做一些事情。您可能还记得[*第十一章*]（B15508_11_Final_JC_ePub.xhtml#_idTextAnchor167），*我们将学到什么-在线论坛应用*，我们使用了一个名为`isPasswordValid`的函数来检查用户的密码是否足够长和复杂。因为，正如我当时提到的，通常应该在客户端和服务器上进行验证。因此，让我们暂时将`PasswordValidator.ts`文件和`common/validators`文件夹结构复制到我们的服务器项目中，稍后我将展示一种在多个项目之间共享代码的方法。

1.  让我们还为电子邮件地址创建一个验证器。在相同的`common/validators`目录中创建一个`EmailValidator.ts`文件，并添加此代码：

```ts
export const isEmailValid = (email: string) => {
if (!email) return "Email cannot be empty";
```

在这里，我检查了一个空地址。

```ts
  if (!email.includes("@")) {
    return "Please enter valid email address.";
```

在这里，我检查了@符号。

```ts
  }
  if (/\s+/g.test(email)) {
    return "Email cannot have whitespaces";
```

最后，在这里我检查了空格。

```ts
  }
  return "";
};
```

如果没有发现问题，将返回一个空字符串。

1.  创建`UserRepo.ts`文件并添加此代码：

```ts
import { User } from "./User";
import bcrypt from "bcryptjs";
import { isPasswordValid } from "../common/validators/PasswordValidator";
import { isEmailValid } from "../common/validators/EmailValidator";
```

首先，我们有我们的导入，包括我们的验证器。

```ts
const saltRounds = 10;
```

`saltRounds`用于密码加密，很快您就会看到。

```ts
export class UserResult {
  constructor(public messages?: Array<string>, public    user?:
   User) {}
}
```

我们将使用`UserResult`类型指示身份验证期间是否发生错误。正如您所看到的，它基本上是`User`对象的包装器。我们正在将此对象用作我们函数的返回类型。我们这样做是因为在进行网络调用或其他复杂调用时，出现问题是很常见的。因此，具有在对象中包含错误或状态消息的能力是有益的。请注意，`messages`和`user`两个成员都是可选的。一旦我们开始使用这种类型，这将非常方便。

```ts
export const register = async (
  email: string,
  userName: string,
  password: string
): Promise<UserResult> => {
```

这是我们的`register`函数的开始。

```ts
  const result = isPasswordValid(password);
  if (!result.isValid) {
    return {
      messages: [
        "Passwords must have min length 8, 1 upper          character, 1 number, and 1 symbol",
      ],
    };
  }
  const trimmedEmail = email.trim().toLowerCase();
  const emailErrorMsg = isEmailValid(trimmedEmail);
  if (emailErrorMsg) {
    return {
      messages: [emailErrorMsg],
    };
  }
```

在这里，我们运行了我们的两个验证器`isPasswordValid`和`isEmailValid`。请注意，我们使用对象字面量作为返回对象，而没有包含`user`成员。同样，TypeScript 只关心我们对象的形状是否与类型的形状匹配。因此，在这种情况下，由于我们的`UserResult`成员`user`是可选的，我们可以创建一个不包括它的`UserResult`对象。TypeScript 真的很灵活。

```ts
  const salt = await bcrypt.genSalt(saltRounds);
  const hashedPassword = await bcrypt.hash(password,    salt);
```

在这里，我们使用`saltRounds`常量和`bcryptjs`加密了我们的密码。

```ts
  const userEntity = await User.create({
    email: trimmedEmail,
    userName,
    password: hashedPassword,
  }).save();
```

然后，如果我们通过了验证，我们将`create`我们的`User`实体，然后立即`save`它。这两种方法都来自 TypeORM，请注意，当对实体数据库进行更改时，您需要使用`save`函数，否则它将无法在服务器上完成。

```ts
  userEntity.password = ""; // blank out for security
  return {
     user: userEntity
  };
};
```

然后，我们返回新实体，再次，由于我们的调用没有错误，我们只返回不包含任何`messages`的`user`对象。

1.  让我们尝试这个新功能`register`，进行真正的网络调用。像这样更新`index.ts`文件：

```ts
import express from "express";
import session from "express-session";
import connectRedis from "connect-redis";
import Redis from "ioredis";
import { createConnection } from "typeorm";
import { register } from "./repo/UserRepo";
import bodyParser from "body-parser";
```

请注意，我们现在导入了`bodyParser`。

```ts
require("dotenv").config();
const main = async () => {
  const app = express();
  const router = express.Router();
  await createConnection();
  const redis = new Redis({
    port: Number(process.env.REDIS_PORT),
    host: process.env.REDIS_HOST,
    password: process.env.REDIS_PASSWORD,
  });
  const RedisStore = connectRedis(session);
  const redisStore = new RedisStore({
    client: redis,
  });
  app.use(bodyParser.json());	
```

在这里，我们设置了我们的`bodyParser`，这样我们就可以从帖子中读取`json`参数。

```ts
  app.use(
    session({
      store: redisStore,
      name: process.env.COOKIE_NAME,
      sameSite: "Strict",
      secret: process.env.SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      cookie: {
        path: "/",
        httpOnly: true,
        secure: false,
        maxAge: 1000 * 60 * 60 * 24,
      },
    } as any)
  );
```

所有这些代码保持不变：

```ts
  app.use(router);
  router.post("/register", async (req, res, next) => {
    try {
      console.log("params", req.body);
      const userResult = await register(
        req.body.email,
        req.body.userName,
        req.body.password
      );
      if (userResult && userResult.user) {
        res.send(`new user created, userId: ${userResult.         user.id}`);
      } else if (userResult && userResult.messages) {
        res.send(userResult.messages[0]);
      } else {
        next();
      }
    } catch (ex) {
      res.send(ex.message);
    }
  });
```

如您所见，我们删除了以前的`get`路由，并在注册 URL 上用`post`替换它。这个调用现在运行我们的`UserRepo` `register`函数，如果成功，它会发送一个带有新用户 ID 的消息。如果不成功，它会发送回来自存储库调用的错误消息。在这种情况下，我们只使用第一条消息，因为我们将删除这些路由，并在*第十五章*中用 GraphQL 替换它们，*添加 GraphQL 模式-第一部分*：

```ts
  app.listen({ port: process.env.SERVER_PORT }, () => {
    console.log(`Server ready on port
     ${process.env.SERVER_PORT}`);
  });
};
main();
```

现在我们将开始测试。但是，我们需要切换到使用 Postman 而不是 curl。Postman 是一个免费的应用程序，它允许我们向服务器发出`GET`和`POST`调用，并接受会话 cookie。它非常容易使用：

1.  首先，转到[`www.postman.com/downloads`](https://www.postman.com/downloads)，并下载并安装适用于您系统的 Postman。

1.  安装后，您应该首先在 Postman 上运行站点根目录的`GET`调用。我在`index.ts`中为根目录创建了一个简单的路由，它将初始化会话及其 cookie。像这样在我们的站点上运行`GET`调用：

![图 14.13-在站点根目录上运行 Postman](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_14.13_B15508.jpg)

图 14.13-在站点根目录上运行 Postman

这就是您可以运行相同`GET`调用的方法：

1.  在标有**GET**的顶部标签下，您应该看到左侧的一个下拉菜单。选择**GET**并添加本地 URL。没有参数，所以只需点击**Send**。

1.  然后，在左下角，您将看到另一个下拉菜单。选择**Cookies**，您应该会看到我们的名为**superforum**的 cookie。

现在您已经获得了维护会话状态所需的 cookie。因此，我们现在可以继续我们的测试，从`register`函数开始：

1.  打开一个新标签，选择`http://localhost:5000/register`。

1.  点击**Headers**选项卡，并插入**Content-Type**，如下所示：![图 14.14-内容类型](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_14.14_B15508.jpg)

图 14.14-内容类型

1.  现在，选择`电子邮件`，尽管它是无效的，`用户名`和`密码`，也是无效的。

但是，这种失败仍然是好的，因为我们已经确认了我们的验证是有效的。

1.  让我们修复密码，然后再试一次。将密码更新为`Test123!@#`，然后再次运行它：![图 14.16-尝试再次注册](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_14.16_B15508.jpg)

图 14.16-尝试再次注册

现在您应该会看到消息**请输入有效的电子邮件地址**。再次强调，这正是我们想要的，因为显然给出的电子邮件是无效的。

1.  让我们再试一次。将电子邮件更新为`test@test.com`，并运行此操作：![图 14.17-成功注册](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_14.17_B15508.jpg)

图 14.17-成功注册

输出消息为`10`，因为我在准备本书时进行了一些测试。ID 字段通常将从`1`开始。如果您再次看不到此结果，请确保在使用`GET`调用时在我们网站的根目录上运行 Postman。

1.  太棒了！成功了！现在，让我们查看我们的`Users`表，以确保用户确实已添加：![图 14.18-向用户表添加新用户](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_14.18_B15508.jpg)

图 14.18-向用户表添加新用户

您可以通过右键单击`pgAdmin`中的`Users`表并选择`Scripts > SELECT Script`来运行所示的查询。您可以通过点击顶部的播放按钮来运行脚本。但是，如您所见，我们的用户已插入到数据库中。

1.  现在，让我们用我们的`login`函数更新`UserRepo`。将以下代码添加到`UserRepo`的末尾：

```ts
export const login = async (
  userName: string,
  password: string
): Promise<UserResult> => {
  const user = await User.findOne({
    where: { userName },
  });
  if (!user) {
    return {
      messages: [userNotFound(userName)],
    };
  }
  if (!user.confirmed) {
    return {
      messages: ["User has not confirmed their        registration email yet."],
    };
  }
  const passwordMatch = await bcrypt.compare(password, 
    user?.password);
  if (!passwordMatch) {
    return {
      messages: ["Password is invalid."],
    };
  }
  return {
    user: user,
  };
};
```

这里没有太多要展示的。 我们尝试查找具有给定`userName`的用户。 如果找不到，则返回一条消息，指出未找到`user`，使用名为`userNotFound`的函数。 我使用函数是因为我们稍后将重用此消息。 这是一个简单的函数，所以我不会在这里介绍它（它在源代码中）。 如果找到用户，那么我们首先看一下帐户是否已确认。 如果没有，我们会提供一个错误。 接下来，我们通过使用`bcryptjs`来检查他们的密码，因为我们在注册时使用了该工具对其进行加密。 如果不匹配，我们还会提供一个错误。 如果一切顺利，用户存在，我们将返回用户。

1.  让我们也尝试运行这个。 通过在注册路线下方添加这个新路线来更新`index.ts`：

```ts
router.post("/login", async (req, res, next) => {
    try {
      console.log("params", req.body);
      const userResult = await login(req.body.userName, 
        req.body.password);
      if (userResult && userResult.user) {
        req.session!.userId = userResult.user?.id;
        res.send(`user logged in, userId: 
         ${req.session!.userId}`);
      } else if (userResult && userResult.messages) {
        res.send(userResult.messages[0]);
      } else {
        next();
      }
    } catch (ex) {
      res.send(ex.message);
    }
  });
```

这与我们的`register`路线非常相似。 但是，在这里，我们将用户的`id`保存到会话状态中，然后使用该会话发送一条消息。

1.  让我们运行这个路线，看看会发生什么。 再次在 Postman 中打开一个新标签，并按照这里显示的设置运行。 **记住**在**Headers**选项卡中**添加** **Content-Type**标头：![图 14.19 - 登录路线](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_14.19_B15508.jpg)

图 14.19 - 登录路线

同样，这是很好的，因为我们的验证正在起作用。

1.  转到您的`pgAdmin`，打开您用于运行`SELECT`查询以查看我们第一个插入的用户的相同屏幕。 然后，运行此 SQL 以将我们的用户的`confirmed`列更新为`true`：![图 14.20 - 更新用户的确认字段](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_14.20_B15508.jpg)

图 14.20 - 更新用户的确认字段

运行查询后，您应该会看到与*图 14.20*中显示的相同消息。

1.  现在，让我们运行 Postman 再次尝试登录：

![图 14.21 - 登录用户](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_14.21_B15508.jpg)

图 14.21 - 登录用户

现在，我们的用户可以登录，并且根据返回的消息，我们现在可以看到我们正在使用会话状态。 我已在源代码中创建了`logout`函数和路线。 我不会在这里展示它，因为它很简单。

注意

如果您尝试保存到会话失败，请确保您的 Redis 服务正在运行。

太棒了！ 我们已经走了很长的路。 我们现在拥有基于会话的身份验证，但我们还没有完成。 我们需要创建插入`Threads`和`ThreadItems`以及检索它们的方法。 让我们从`Threads`开始：

1.  在创建新的`ThreadRepo`存储库之前，让我们构建一个小助手。 在`UserRepo`中，我们有一个名为`UserResult`的类型，其中包含一组消息和一个用户作为成员。 您会注意到任何`Threads`、`ThreadItems`和`Categories`的存储库都需要类似的构造。 它应该有一组消息和实体，尽管返回的实体将是一组项目，而不仅仅是一个。

这似乎是使用 TypeScript 泛型的好地方，这样我们可以在所有这些实体之间共享单个结果类型。 让我们创建一个名为`QueryResult`的新通用结果对象类型。 我们在*第二章*中学习了有关 TypeScript 泛型的知识，*探索 TypeScript*。

创建一个名为`QueryArrayResult.ts`的文件，并将以下代码添加到其中：

```ts
export class QueryArrayResult<T> {
  constructor(public messages?: Array<string>, public    entities?: Array<T>) {}
}
```

如您所见，这与原始的`UserResult`非常相似。 但是，此类型使用类型`T`的通用类型来指示我们的任何实体。

警告

`pg`依赖项还有一个名为`QueryArrayResult`的类型。 在导入我们的依赖项时，请确保导入我们的文件，而不是`pg`。

1.  现在，让我们在`ThreadRepo`中使用这种新的`QueryArrayResult`类型。 在`repo`文件夹中创建一个名为`ThreadRepo.ts`的新文件，并添加以下代码：

```ts
export const createThread = async (
  userId: string,
  categoryId: string,
  title: string,
  body: string
): Promise<QueryArrayResult<Thread>> => {
```

所示的参数是必需的，因为每个“线程”必须与用户和类别相关联。 请注意，`userId`是从我们的会话中获取的。

```ts
  const titleMsg = isThreadTitleValid(title);
  if (titleMsg) {
    return {	
      messages: [titleMsg],
    };
  }
  const bodyMsg = isThreadBodyValid(body);
  if (bodyMsg) {
    return {
      messages: [bodyMsg],
    };
  }
```

在这里，我们验证我们的`title`和`message`。

```ts
  // users must be logged in to post
  const user = await User.findOne({
    id: userId,
  });
  if (!user) {
    return {
      messages: ["User not logged in."],
    };
  }
```

在这里，我们获取我们提供的会话`userId`，并尝试找到匹配的`user`。 我们稍后需要这个`user`对象来创建我们的新`Thread`。

```ts
  const category = await ThreadCategory.findOne({
    id: categoryId,
  });
  if (!category) {
    return {
      messages: ["category not found."],
    };
  }
```

在这里，我们得到一个`category`对象，因为我们在创建新的`Thread`时需要传递它。

```ts
  const thread = await Thread.create({
    title,
    body,
    user,
    category,
  }).save();
  if (!thread) {
    return {
      messages: ["Failed to create thread."],
    };
  }
```

正如你所看到的，我们传递`title`、`body`、`user`和`category`来创建我们的新`Thread`。

```ts
  return {
    messages: ["Thread created successfully."],
  };
};
```

我们只返回消息，因为我们不需要返回实际的对象。此外，返回不需要的对象在 API 负载大小方面是低效的。

1.  在我们继续之前，我们需要向数据库中添加一些`ThreadCategories`，这样我们才能真正使用`createThread`函数。去源代码中找到`utils/InsertThreadCategories.txt`文件。将这些`insert`语句复制粘贴到`pgAdmin`的查询屏幕中并运行。这将创建列出的`ThreadCategories`。

1.  接下来，我们需要添加用于创建`Threads`的路由。将以下代码添加到`index.ts`中：

```ts
router.post("/createthread", async (req, res, next) => {
    try {
      console.log("userId", req.session);
      console.log("body", req.body);
      const msg = await createThread(
        req.session!.userId, // notice this is from          session!
        req.body.categoryId,
        req.body.title,
        req.body.body
      );
```

在这个超级简单的调用中，我们向`createThread`函数传递参数。同样，我们的`userId`来自我们的会话，因为用户应该登录才能被允许发布，然后我们简单地返回结果消息。

```ts
      res.send(msg);
    } catch (ex) {
      console.log(ex);
      res.send(ex.message);
    }
  });
```

1.  让我们尝试运行这个路由。不过，在此之前，先在 Postman 中运行登出路由。你可以在`http://localhost:5000/logout`URL 中找到它。我相信你现在可以自己设置 Postman。一旦完成，让我们尝试运行`createthread`路由，希望它应该会失败验证:![图 14.22 – 测试 createthread 路由](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_14.22_B15508.jpg)

图 14.22 – 测试 createthread 路由

是的，它如预期般失败了验证。

1.  现在，让我们再次登录，以便我们的会话得到创建。再次使用 Postman 进行操作，然后再次运行`createthread`路由。这次，它应该会显示消息，**Thread created successfully**。

1.  好的。现在我们需要另外两个函数，一个是根据其 ID 获取单个`Thread`，另一个是获取`ThreadCategory`的所有线程。将以下代码添加到`ThreadRepo`中：

```ts
export const getThreadById = async (
  id: string
): Promise<QueryOneResult<Thread>> => {
  const thread = await Thread.findOne({ id });
  if (!thread) {
    return {
      messages: ["Thread not found."],
    };
  }
  return {
    entity: thread,
  };
};
```

这个`getThreadById`函数非常简单。它只是基于 ID 查找单个线程。

```ts
export const getThreadsByCategoryId = async (
  categoryId: string
): Promise<QueryArrayResult<Thread>> => {
  const threads = await Thread.   createQueryBuilder("thread")
    .where(`thread."categoryId" = :categoryId`, {       categoryId })
    .leftJoinAndSelect("thread.category", "category")
    .orderBy("thread.createdOn", "DESC")
    .getMany();
```

这个`getThreadsByCategoryId`函数更有趣。`Thread.createQueryBuilder`是 TypeORM 中的一个特殊函数，允许我们构建更复杂的查询。函数的`thread`参数是一个别名，用于表示查询中的 Threads 表。因此，如果你看一下查询的其余部分，比如`where`子句，你会发现我们使用`thread`作为字段或关系的前缀。`leftJoinAndSelect`函数意味着我们要进行 SQL 左连接，但同时也要返回相关的实体，即`ThreadCategory`与结果集一起。`OrderBy`相当直观，`getMany`只是意味着返回所有项目。

```ts
  if (!threads) {
    return {
      messages: ["Threads of category not found."],
    };
  }
  console.log(threads);
  return {
    entities: threads,
  };
};
```

1.  其余的代码非常简单。让我们测试`getThreadsByCategoryId`作为一个路由。将其添加到`index.ts`文件中：

```ts
router.post("/threadbycategory", async (req, res, next) => {
    try {
      const threadResult = await 
       getThreadsByCategoryId(req.body.categoryId);
```

在这里，我们使用`categoryId`参数调用了`getThreadsByCategoryId`。

```ts
      if (threadResult && threadResult.entities) {
        let items = "";
        threadResult.entities.forEach((th) => {
          items += th.title + ", ";
        });
        res.send(items);
      } else if (threadResult && threadResult.messages) {
        res.send(threadResult.messages[0]);
      }
```

在这个`if else`代码中，我们要么显示所有标题，要么显示错误。

```ts
    } catch (ex) {
      console.log(ex);
      res.send(ex.message);
    }
  });
```

1.  其余的代码与之前一样。在你的 Postman 客户端中运行这个，你应该会看到这个。再次提醒，你的 ID 号码可能会有所不同：

![图 14.23 – 测试 threadsbycategory 路由](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_14.23_B15508.jpg)

图 14.23 – 测试 threadsbycategory 路由

我会把`getThreadById`的测试留给你，因为它很容易。同样，源代码在我们的项目存储库中。

`ThreadItems`的代码几乎相同，并且在我们的源代码中。所以，我不会在这里进行复习。现在，我们需要一些额外的函数来获取诸如`ThreadCategories`之类的东西，以填充我们的 React 应用程序的`LeftMenu`。我们还需要检索我们的`Threads`和`ThreadItems`的积分。我们还需要`UserProfile`屏幕的相关`Thread`数据。然而，这些调用将重复我们在本节学到的许多概念，而且我们将不得不创建路由，最终我们将在开始 GraphQL 服务器代码后删除。因此，让我们把这些留到*第十五章*，*添加 GraphQL 模式-第一部分*，在那里我们还可以开始将后端 GraphQL 代码与我们的 React 前端集成。

在本节中，我们学习了如何构建一个存储库层，并使用 TypeORM 进行 Postgres 查询。一旦我们开始在下一章中集成 GraphQL，我们将会重复使用我们的查询技能，因此这是我们将继续使用的重要知识。

# 总结

在本章中，我们学习了如何设置一个 Postgres 数据库以及如何使用 ORM TypeORM 进行查询。我们还学习了如何通过使用存储库层来保持我们的代码清晰分离。

在下一章中，我们将学习如何在我们的服务器上启用 GraphQL。我们还将完成我们的数据库查询，并将我们的后端集成到我们的 React 前端中。


# 第十五章：添加 GraphQL 模式第一部分

在本章中，我们将继续通过集成 GraphQL 来构建我们的应用程序。我们将在客户端和服务器上都这样做。我们还将完成构建后端 Express 服务器并将该后端与我们的 React 客户端集成。

在本章中，我们将涵盖以下主要主题：

+   创建 GraphQL 服务器端的 typedefs 和解析器

+   将身份验证与 GraphQL 解析器集成

+   为查询 Apollo GraphQL 创建 React 客户端 Hooks

# 技术要求

您应该对 GraphQL 有基本的了解，并且对 React、Node.js、Postgres 和 Redis 有很好的了解。我们将再次使用 Node 和**Visual Studio Code**（**VSCode**）来编写我们的代码。

GitHub 存储库位于[`github.com/PacktPublishing/Full-Stack-React-TypeScript-and-Node`](https://github.com/PacktPublishing/Full-Stack-React-TypeScript-and-Node)。使用`Chap15`文件夹中的代码。

要设置*第十五章*代码文件夹，请执行以下操作：

1.  转到您的`HandsOnTypescript`文件夹，并创建一个名为`Chap15`的新文件夹。

1.  现在转到`Chap14`文件夹，并将`super-forum-server`文件夹复制到`Chap15`文件夹中。确保所有文件都已复制。

1.  在`super-forum-server`文件夹中删除`node_modules`文件夹和`package-lock.json`文件。确保您在`super-forum-server`文件夹中，并运行此命令：

```ts
npm install 
```

1.  现在确保您的 Postgres 服务器和 Redis 服务器正在运行，如*第十三章*中所示，*使用 Express 和 Redis 设置会话状态*，以及*第十四章*，*使用 TypeORM 设置 Postgres 和存储库层*。然后，通过运行此命令来测试您的服务器：

```ts
npm start 
```

1.  现在让我们复制我们的客户端应用。转到`Chap13`文件夹，将`super-forum-client`复制到`Chap15`的根目录。确保所有文件都已复制。

1.  删除`node_modules`文件夹和`package-lock.json`文件。现在确保您在`super-forum-client`文件夹中，并运行此命令：

```ts
npm install
```

1.  通过运行此命令测试它是否有效：

```ts
npm start 
```

# 创建 GraphQL 服务器端 typedefs 和解析器

在本节中，我们将把 GraphQL 服务添加到我们的 Express 服务器中。我们还将开始将我们在*第十四章*中创建的路由转换为 GraphQL 查询。我们还将完善我们需要的其余调用，作为 GraphQL 查询。

让我们首先将 GraphQL 集成到我们的 Express 应用程序中（我们在*第九章*中介绍了 GraphQL，*什么是 GraphQL*，以及*第十章*，*使用 TypeScript 和 GraphQL 依赖项设置 Express 项目*）：

注意

本章中将有大量的代码，不是所有代码都可以在文本中显示。请经常参考 GitHub 存储库代码，这是章节源代码。还要注意，章节源代码是最终运行的项目，只包含最终的工作代码。

1.  让我们开始安装 GraphQL。运行这个命令：

```ts
npm i apollo-server-express graphql graphql-middleware graphql-tools
```

1.  接下来，让我们创建我们的初始类型定义`typeDefs`。在`src`文件夹内创建一个名为`gql`的文件夹。然后在其中创建文件`typeDefs.ts`。现在添加此代码：

```ts
import { gql } from "apollo-server-express";
const typeDefs = gql`
  scalar Date
```

我们定义了一个新的自定义`scalar`类型，`Date`，在 GraphQL 中默认不可用于日期和时间：

```ts
  type EntityResult {
    messages: [String!]
  }
```

这种`EntityResult`类型将在我们的解析器返回错误或消息而不是实体时使用：

```ts
  type User {
    id: ID!
    email: String!
    userName: String!
    password: String!
    confirmed: Boolean!
    isDisabled: Boolean!
    threads: [Thread!]
    createdBy: String!
    createdOn: Date!
    lastModifiedBy: String!
    lastModifiedOn: Date!
  }
```

我们在这里创建了我们的`User`类型。注意到与`Thread`和`ThreadItem`的关系。我们还使用了我们的`Date`类型：

```ts
  type Thread {
    id: ID!
    views: Int!
    isDisabled: Boolean!
    title: String!
    body: String!
    user: User!
    threadItems: [ThreadItem!]
    category: ThreadCategory
    createdBy: String!
    createdOn: Date!
    lastModifiedBy: String!
    lastModifiedOn: Date!
}
```

我们创建了我们的`Thread`类型及其关系：

```ts
  union ThreadResult = Thread | EntityResult
```

现在我们正在实现我们的真实应用程序，是时候使用一些更复杂的 GraphQL 特性了。`union`类型与 TypeScript 中的概念相同。它将允许我们从可能的 GraphQL 类型列表中返回任何类型。例如，在这个例子中，这个类型可以表示*要么*是 Thread，要么是 EntityResult，但不能同时是两者。我将很快展示这种类型的用法，它将变得更清晰。

```ts
  type ThreadItem {
    id: ID!
    views: Int!
    isDisabled: Boolean!
    body: String!
    user: User!
    thread: Thread!
    createdBy: String!
    createdOn: Date!
    lastModifiedBy: String!
    lastModifiedOn: Date!
  }
```

我们创建了我们的`ThreadItem`类型。

```ts
  type ThreadCategory {
    id: ID!
    name: String!
    description: String
    threads: [Thread!]!
    createdBy: String!
    createdOn: Date!
    lastModifiedBy: String!
    lastModifiedOn: Date!
}
```

`ThreadCategory`类型还指的是它包含的`Threads`。

```ts
  type Query {
    getThreadById(id: ID!): ThreadResult
  }
`;
```

在这里，我们有一个带有`getThreadById`函数的`Query`。注意它返回我们的`union` `ThreadResult`。我们稍后会详细介绍这个。

```ts
export default typeDefs;
```

1.  现在让我们创建一个简单的解析器文件，以开始使用我们的 GraphQL 安装。在`gql`文件夹中创建一个名为`resolvers.ts`的文件，并添加以下代码：

```ts
import { IResolvers } from "apollo-server-express";
interface EntityResult {
  messages: Array<string>;
}
```

我们将使用`EntityResult`作为我们的错误和状态消息的返回类型。还要将我们的类型映射添加到`typeDefs`文件中的相同类型：

```ts
const resolvers: IResolvers = {
  ThreadResult: {
    __resolveType(obj: any, context: GqlContext, info:      any) {
      if (obj.messages) {
        return "EntityResult";
      }
      return "Thread";
    },
},
```

这是我们正在使用的 GraphQL 的另一个新特性。`ThreadResult`是在 GraphQL 中表示两种类型`Thread`和`EntityResult`的`union`。这个解析器注意到即将返回一个`ThreadResult`，并在内部确定它是哪种类型。您使用的方法完全取决于您确定要发送的类型，但在这里，我们通过检查`obj.message`对`EntityResult`类型的`message`字段进行了简单的检查：

```ts
  Query: {
    getThreadById: async (
      obj: any,
      args: { id: string },
      ctx: GqlContext,
      info: any
    ): Promise<Thread | EntityResult> => {
      let thread: QueryOneResult<Thread>;
      try {
        thread = await getThreadById(args.id);
        if (thread.entity) {
          return thread.entity;
        }
        return {
          message: thread.messages ? thread.messages[0] :            "test",
        };
      } catch (ex) {
        throw ex;
      }
    },
  },
};
export default resolvers;
```

我们在*第九章*中学习了 GraphQL 查询，所以我不会在这里过多地介绍它。只需注意，在这个调用中，我接受来自`getThreadById`调用的结果类型`QueryOneResult`，并在一些处理之后，返回实际的实体本身或`EntityResult`。同样，由于我们的`typeDefs`文件将我们的查询返回为`ThreadResult`，它将转到`ThreadResult`查询并确定要返回的类型。这是我们将重复用于大多数存储库调用的模式。存储库在*第十四章*中有所涵盖，*使用 TypeORM 设置 Postgres 和存储库层*。

注意

对于这个示例应用程序，我们只是重新抛出可能发生的错误。但在您的生产应用程序中，您应该根据您的应用程序适当地处理错误，通常意味着至少记录问题，以便以后查看。

我们将稍后用更多的查询和变异填充这段代码，但现在让我们专注于完成我们的基本设置。

1.  将`Chap10/gql-server/src`文件夹中的`GqlContext.ts`文件复制并粘贴到`gql`文件夹中。正如我们在*第九章*中所展示的，*什么是 GraphQL？*，这是我们的请求和响应对象在 GraphQL 调用中的位置。

1.  现在让我们打开我们的`index.ts`文件，并将 GraphQL 添加到其中。在调用`listen`之前添加以下代码，并确保添加必要的导入，现在您应该能够自己完成：

```ts
const schema = makeExecutableSchema({ typeDefs, resolvers });
const apolloServer = new ApolloServer({
    schema,
    context: ({ req, res }: any) => ({ req, res }),
});
apolloServer.applyMiddleware({ app });
```

这基本上是与*第九章*中相似的代码，*什么是 GraphQL？*，在那里我们实例化我们的`ApolloServer`并将其带入我们的`typeDefs`、`resolvers`和 Express`app`实例。

1.  让我们测试一下，确保它能正常工作。打开 URL `http://localhost:5000/graphql`。这是我们在*第九章*中审查过的 GraphQL playground，*什么是 GraphQL？*。按照所示运行它：![图 15.1 – 对 GraphQL 的第一个查询](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_15.01_B15508.jpg)

图 15.1 – 对 GraphQL 的第一个查询

所以，你可以看到，我们的调用现在可以工作了。与我们之前对 GraphQL 的一些调用的唯一区别是，由于我们的调用可能返回两种不同的类型，我们使用`… on <some type>`语法来决定返回时我们想要哪个实体和字段（这个功能称为内联片段）。同样，请记住你的本地 ID 号可能不会和我的一样，所以你需要发送在你的数据库中确实存在的 ID。

1.  好的，让我们再做一个。这次，我们选择一个不返回实体的函数 - `createThread`函数。首先，在你的`typeDefs`文件末尾添加这个 mutation：

```ts
type Mutation {
    createThread(
      userId: ID!
      categoryId: ID!
      title: String!
      body: String!
    ): EntityResult
}
```

请注意我们没有返回`ThreadResult`。我们的`createThread`函数只返回一个字符串消息。所以这就是我们需要的全部。

1.  现在让我们更新`resolvers`文件。将此函数作为一个 mutation 添加进去。同样，你需要自己导入所需的任何内容：

```ts
Mutation: {
    createThread: async (
      obj: any,
      args: { userId: string; categoryId: string; title:        string; body: string },
      ctx: GqlContext,
      info: any
    ): Promise<EntityResult> => {
```

再次，和往常一样的参数列表，但这次我们只返回`EntityResult`，因为没有必要返回整个实体：

```ts
      let result: QueryOneResult<Thread>;
      try {
        result = await createThread(
          args.userId,
          args.categoryId,
          args.title,
          args.body
        );
```

在这里，我们调用了存储库的`createThread`并得到了结果。

```ts
        return {
          messages: result.messages
            ? result.messages
            : ["An error has occurred"],
        };
```

现在我们正在返回可能的消息列表来指示结果的状态。

```ts
      } catch (ex) {
        throw ex;
```

在生产中，你不应该简单地重新抛出异常，而是应该记录或以其他方式处理错误。我们在这里重新抛出异常是为了简化并专注于手头的概念，而不要被岔开。

```ts
      }
    },
  },
```

1.  所以，现在如果我们运行我们的代码，我们应该会看到这个：![图 15.2 - createThread 函数](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_15.02_B15508.jpg)

图 15.2 - createThread 函数

1.  好的，让我们再为 Threads 做一个调用。在`ThreadRepo`中有一个调用`getThreadsByCategoryId`，它返回一个 Threads 数组。这是一个问题，因为 GraphQL 的`union`运算符不支持数组。所以我们需要在`typeDefs`文件中创建另一个新的实体来表示一个 Threads 数组，然后我们可以创建我们的 union。通过在 ThreadResult union 下面添加以下内容来更新`typeDefs`文件：

```ts
type ThreadArray {
    threads: [Thread!]
}
union ThreadArrayResult = ThreadArray | EntityResult
```

所以我们首先创建了一个返回 Threads 数组的实体。然后我们创建了我们的`union`，它可以返回该实体类型或`EntityResult`。

现在在`getThreadById`查询之后添加这个：

```ts
getThreadsByCategoryId(categoryId: ID!): ThreadArrayResult!
```

1.  现在我们可以构建我们的解析器。通过添加以下内容更新`resolvers`查询部分：

```ts
getThreadsByCategoryId: async (
      obj: any,
      args: { categoryId: string },
      ctx: GqlContext,
      info: any
    ): Promise<{ threads: Array<Thread> } | EntityResult>      => {
      let threads: QueryArrayResult<Thread>;
      try {
        threads = await getThreadsByCategoryId(args.         categoryId);
        if (threads.entities) {
          return {
            threads: threads.entities,
          };
        }
```

在这里，我们返回我们的 Threads 数组。

```ts
        return {
          messages: threads.messages
            ? threads.messages
            : ["An error has occurred"],
        };
```

在这里，如果没有 Threads，我们返回我们的消息。

```ts
      } catch (ex) {
        throw ex;
      }
    },
```

1.  我们只缺少一个项目。当我们首次使用`union`时，我们必须为`EntityResult`类型创建一个查询。因此，我们需要为我们的新`ThreadArrayResult`类型做同样的事情。在`resolvers`文件中`EntityResult`定义之后输入以下代码：

```ts
ThreadArrayResult: {
    __resolveType(obj: any, context: GqlContext, info:     any) {
      if (obj.messages) {
        return "EntityResult";
      }
      return "ThreadArray";
    },
  },
```

这和之前的情况一样。如果`obj`有一个`messages`属性，我们返回`EntityResult`类型；如果没有，我们返回`ThreadArray`类型。

1.  如果我们运行这个查询，我们应该会看到类似这样的结果（注意我的结果中充满了重复的测试数据）：

![图 15.3 - getThreadsByCategoryId 函数](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_15.03_B15508.jpg)

图 15.3 - getThreadsByCategoryId 函数

请注意我们添加了一个额外的字段叫做`__typename`。这个字段将告诉我们返回的是哪种类型，如所示是`ThreadArray`。

好的，现在我们有一个可以工作的 GraphQL 服务器，可以查询 Threads。尝试并集成*第十四章*中与身份验证无关的调用，*使用 TypeORM 设置 Postgres 和存储库层*。如果你遇到困难，可以参考源代码。但重要的是你尝试并且*不要*查看，因为这样你才能确切地知道你是否理解了材料。

## ThreadPoint System

现在我们已经集成了现有的解析器调用，让我们创建一些我们仍然需要的调用。我们为我们的 Threads 和 ThreadItems 创建了一个点系统。现在让我们实现一种增加和减少点数的方法。如果已经有一段时间了，请在继续之前查看一下 ThreadPoint 和 ThreadItemPoint 实体。您会注意到一个名为 `points` 的新字段，我将在我们开始编写代码时解释：

1.  首先，在 repo 文件夹内创建一个名为 `ThreadPointRepo.ts` 的文件，并将以下代码添加到其中（再次假设您知道如何添加必要的导入）：

```ts
export const updateThreadPoint = async (
  userId: string,
  threadId: string,
  increment: boolean
): Promise<string> => {
```

请注意参数中有一个 `increment` 布尔值。这决定了我们是要添加还是删除一个点。

```ts
  // todo: first check user is authenticated
```

一旦我们创建了我们的身份验证调用，我们将重新访问这个注释，并用代码填充它。请注意，添加一个 `todo` 注释是跟踪剩余待完成项目的好方法。它还通知团队成员这一事实。

```ts
  let message = "Failed to increment thread point";
  const thread = await Thread.findOne({
    where: { id: threadId },
    relations: ["user"],
  });
  if (thread!.user!.id === userId) {
    message = "Error: users cannot increment their own      thread";
    return message;
}
```

因此，我们首先获取给定 `threadId` 的 `Thread`。请注意，我们还检查了给定的 `User` 是否不是拥有该线程的相同 `User`。如果您的数据库中只有一个 `User`，您需要添加另一个 `User`，以便拥有 `Thread` 的所有者不是尝试增加其点数的相同人。您可以通过使用 SQL 插入查询或重用我们在*第十四章*中的注册路由来添加用户，*使用 TypeORM 设置 Postgres 和存储库层*。

```ts
  const user = await User.findOne({ where: { id: userId } });
```

在这里，我们在实际需要使用它们之前稍微获取了匹配的 `User`。我们稍后会看到为什么我们正在做一些看起来可能效率低下的事情。

```ts
  const existingPoint = await ThreadPoint.findOne({
    where: {
      thread: { id: threadId },
      user: { id: userId },
    },
    relations: ["thread"],
});
```

在这里，我们正在查看现有的点实体是否已经存在。我们将使用这个对象来决定如何稍后添加或删除点：

```ts
await getManager().transaction(async (transactionEntityManager) => {
```

正如您所看到的，我们有一些新的 TypeORM 代码。`getManager().transaction` 调用正在创建一个 SQL 事务。事务是一种将多个 SQL 操作作为单个原子操作执行的方式。换句话说，要么每个操作都将成功完成，要么全部失败。因此，此范围内运行的所有内容都是事务的一部分。

另外，我们之前注意到我们提前创建了一个 `User` 实体。这是因为最佳实践是避免在事务内进行选择查询。这不是一个硬性规定。但一般来说，在事务内进行选择查询会使事情变慢。

```ts
    if (existingPoint) {
      if (increment) {
        if (existingPoint.isDecrement) {
          await ThreadPoint.remove(existingPoint);
          thread!.points = Number(thread!.points) + 1;
          thread!.lastModifiedOn = new Date();
          thread!.save();
        }
      } else {
        if (!existingPoint.isDecrement) {
          await ThreadPoint.remove(existingPoint);
          thread!.points = Number(thread!.points) - 1;
          thread!.lastModifiedOn = new Date();
          thread!.save();
        }
      }
```

在本节中，我们通过检查 `existingPoint`（记住 `ThreadPoint` 可以表示正点或负点，如 `isDecrement` 字段所示）来检查 `ThreadPoint` 是否已经存在。一旦确定了这一点，我们决定是在进行增加还是减少。如果进行增加并且存在减少的 `ThreadPoint`，我们将删除该实体并且不做其他操作。如果我们正在进行减少并且存在增加的 `ThreadPoint`，我们将删除该实体并且不做其他操作。

现在，另一件需要注意的事情是我们的 Thread 实体现在有一个名为 points 的字段，我们根据需要进行增加或减少。这个字段将作为我们的 UI 中的一种快捷方式，它将允许我们获取当前 `Thread` 的点总数，而无需对该 `Thread` 的所有 `ThreadPoints` 进行求和：

```ts
    } else {
      await ThreadPoint.create({
        thread,
        isDecrement: !increment,
        user,
      }).save();
      if (increment) {
        thread!.points = Number(thread!.points) + 1;
      } else {
        thread!.points = Number(thread!.points) - 1;
      }
      thread!.lastModifiedOn = new Date();
      thread!.save();
    }
```

否则，如果根本没有现有的点，我们只需创建一个新的点，无论是增加还是减少：

```ts
    message = `Successfully ${
      increment ? "incremented" : "decremented"
    } point.`;
  });
  return message;
};
```

1.  现在像这样向 `typeDefs` 添加 `Mutation`：

```ts
updateThreadPoint(userId: ID!, threadId: ID!, increment: Boolean!): String!
```

1.  然后，通过将 `updateThreadPoint` 调用添加到 `Mutation` 部分来更新解析器。由于这只是对执行实际工作的存储库调用的包装器，我不会在这里显示代码。尝试看看是否可以在不查看代码的情况下创建 `Mutation`。

注意

我们将使用的大多数解析器只是我们的存储库调用的包装器。这使我们的解析器代码与我们的数据库和存储库调用分开。因此，大多数时候，我不会显示解析器代码，因为它很少并且在源代码中可用。

1.  运行如上所示的`Mutation`，然后检查您的数据库：

![图 15.4 - 运行 updateThreadPoint](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_15.04_B15508.jpg)

图 15.4 - 运行 updateThreadPoint

在这里，我们在 Postgres 数据库中的 mutation 结果，使用 pgAdmin：

![图 15.5 - 运行 updateThreadPoint 数据库结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_15.05_B15508.jpg)

图 15.5 - 运行 updateThreadPoint 数据库结果

因此，我们的记录已成功创建，如图所示。

现在让我们再多讨论一下我们拥有的积分系统以及它是如何工作的。*喜欢*积分系统可以允许正面和负面积分，就像我们的系统一样。然而，它还必须防止用户投票超过一次。为了做到这一点，我们需要将每个积分与给出它的用户以及他们放在其上的 Thread 或 ThreadItem 相关联。这就是为什么我们有 ThreadPoint 和 ThreadPointItem 实体。

在一个用户众多的流量大的网站上，随时添加或删除积分可能对服务器造成重大负载。但比这更糟糕的是，如果我们每次调用获取 Thread 或 ThreadItem 数据时都必须总结所有这些 ThreadPoints 或 ThreadItemPoints。这是不可行的。因此，对于第一个问题，我们必须将其视为“每个用户一票”的积分系统的一部分。然而，对于积分总和的问题，我们可以尝试几种不同的方法来提高性能。

最有效的方法是添加一个缓存系统，使用像 Redis 这样的辅助服务。然而，构建缓存系统并不是一件微不足道的事情，远远超出了本书的范围。我们可以争论说，在我们的网站刚刚起步之前，要取得辉煌的成功和数十亿美元，我们不会有那种流量。因此，作为一个开始，我们可以尝试一些更简单的东西。

因此，我们所做的是将积分字段添加到我们的 Thread 和 ThreadItem 实体中，并在进行添加或删除积分的调用时递增值。这不是最好的解决方案，但现在可以。随着时间的推移，可以构建出更复杂的缓存系统或其他机制。

ThreadItemPoint 的代码几乎是相同的。继续尝试看看是否可以自己构建`ThreadItemPointRepo.ts`文件。如果遇到困难，可以随时查看源代码。

在本节中，我们开始将我们的存储库调用与我们的 GraphQL 层集成。我们还完善了我们的 Thread 和 ThreadItem 积分系统。在下一节中，我们将继续通过集成我们的身份验证调用来构建我们的 GraphQL API。 

# 将身份验证与 GraphQL 解析器集成

将身份验证集成到 GraphQL 中并不比添加任何其他功能有多大区别。在本节中，我们将学习如何做到这一点。

现在让我们集成我们与身份验证相关的调用。让我们从`register`调用开始：

1.  您会记得我们已经在*第十四章*中创建了我们的`register`调用，*使用 TypeORM 设置 Postgres 和存储库层*。现在，让我们添加我们的`typeDefs`和`resolvers`。首先，在`Mutation`部分的`typeDefs`文件中添加源代码中的`register`调用：

1.  现在，在我们的解析器文件中，在`Mutation`部分，添加我们的 GitHub 源代码中的代码。

这只是我们存储库调用的一个包装器，所以没有太多需要解释的，但请注意我们没有返回`User`对象；我们只返回一个状态消息。这是因为我们希望减少泄露不必要信息的机会。在尝试运行之前，让我们启用 GraphQL playground 以接受 cookie，以便我们进行测试。我们需要启用 cookie，以便我们的会话状态可以被保存，这样我们的调用可以检查用户是否已经登录。

在播放器的右上角，点击齿轮图标。将`request.credentials`字段设置为`include`，然后保存并刷新屏幕。如果现在运行它，我们应该会看到这个：

![图 15.6 - 注册](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_15.06_B15508.jpg)

图 15.6 - 注册

1.  让我们继续`login`函数。将登录源代码添加到您的`typeDefs`文件的`Mutation`部分。

1.  现在添加源代码中的`login`解析器代码。我们的 Repository `login`调用正在检查用户是否存在，并确保密码匹配。然后 GraphQL 调用将`user.id`取出，并将其设置为 Session 对象`ctx.req.session.userId`，如果登录成功的话。还要注意的是，我们的解析器在成功时不返回`user`对象。我们稍后将创建一个新的函数来提供`User`信息。

1.  现在让我们做`logout`函数。首先，按照源代码中所示，在`Mutation`部分内添加`typeDefs`条目。

1.  现在从源代码中更新`Mutation`的解析器`logout`解析器代码。请注意，无论存储库`logout`调用返回什么响应，我们都会使用`ctx.req.session?.destroy`来`destroy` `session`，并将`ctx.req.session?.userId`设置为`undefined`。

1.  现在我们需要添加一个新的调用和一个新的类型到我们的`typeDefs`中。按照源代码中的代码，在`typeDefs`文件的`Query`部分中添加`me`函数。接下来，在`User`类型下面，添加这个`union`：

```ts
union UserResult = User | EntityResult
```

为什么我们需要这些？在我们调用`register`和`login`时，我们消除了返回的`User`对象，因为在这些调用之后可能会或可能不会使用`User`详细信息，我们不希望不必要地暴露`User`数据。然而，有时一旦`User`登录，我们可能希望查看他们的相关数据。例如，当他们访问他们的 UserProfile 屏幕时。因此，我们将使用这个`me`函数来处理。

1.  现在让我们为`me`函数添加我们的`UserRepo`调用。将此函数添加到`UserRepo`中：

```ts
export const me = async (id: string): Promise<UserResult> => {
  const user = await User.findOne({
    where: { id },
    relations: ["threads", "threads.threadItems"],
});
```

首先，请注意我们找到的`user`对象包括属于用户的任何`Threads`和`ThreadItems`。我们将在我们的 UserProfile 屏幕中使用这些：

```ts
  if (!user) {
    return {
      messages: ["User not found."],
    };
  }
  if (!user.confirmed) {
    return {
      messages: ["User has not confirmed their       registration email yet."],
    };
  }
  return {
    user: user,
  };
};
```

函数的其余部分与登录函数非常相似。

1.  现在让我们为`UserResult`和`me`函数创建我们的`resolvers`。在`const`的解析器顶部，按照代码中所示添加 UserResult 解析器。这与其他 Result `union`解析器相同-这里没有新的内容需要解释。

1.  在`Query`部分，按照源代码中的代码添加`me`函数的代码。

请注意，此解析器不接受任何参数，因为它从会话中获取`userId`。在第 193 行，它检查会话中是否有`userId`。如果没有，它会提前退出。如果会话中有`userId`，它将使用我们的`UserRepo` `me`函数来获取当前登录的`user`。其余部分基本上与返回实体的其他函数相同。

1.  让我们尝试运行我们的`me`解析器。确保您已经登录过一次，并且已经按照 GraphQL playground 中*Step 3*的说明进行了操作。如果您按照所示运行`me`，您应该会得到相关的数据：

![图 15.7 - 调用 me 解析器](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_15.07_B15508.jpg)

图 15.7 - 调用 me 解析器

如您所见，我们再次使用内联片段，并且能够获取相关的 Threads 和 ThreadItems。

在本节中，我们将我们的存储库层身份验证调用与 GraphQL 联系起来，并测试它们的功能。在下一节中，我们将通过将我们几乎完成的后端与我们的前端联系起来，完成我们的应用程序。

# 为 Apollo GraphQL 查询创建 React 客户端端 Hooks

在本节中，我们将通过将我们的 React 客户端连接到我们的 GraphQL 后端来完成我们的应用程序。我们已经走了很长的路，我们快要到达目的地了。

为了将我们应用程序的两个部分联系起来，我们需要将 CORS 添加到我们的 Express 服务器中。**CORS**代表**跨源资源共享**。这意味着我们的服务器将被设置为允许与其自身域不同的客户端域。

在即使是相当复杂的大多数服务器配置中，托管客户端应用程序的服务器和提供 API 的服务器并不位于同一域上。通常，您会有某种代理，例如 NGINX，它将接受来自浏览器的调用。该代理将根据需要“重定向”调用。我们将在*第十七章*中更详细地解释反向代理的工作原理，*将应用程序部署到 AWS*。

注意

代理是服务或某些服务的替身。当使用代理时，如果客户端调用服务，他们最终首先访问代理而不是直接访问服务。然后代理确定客户端的请求应该路由到哪里。因此，代理为公司提供了更好地控制其服务访问的能力。

启用 CORS 也是必要的，因为 React 应用程序在其自己的测试 Web 服务器上运行。在我们的情况下，它在端口`3000`上运行，而服务器在端口`5000`上运行。尽管它们都使用 localhost，但具有不同的端口实际上意味着不同的域。要更新 CORS，请执行以下操作：

1.  首先，我们需要更新我们的`.env`文件，以便包含客户端开发服务器的路径：

```ts
CLIENT_URL=http://localhost:3000
```

1.  打开`index.ts`并在`const app = express();`之后立即添加以下代码：

```ts
app.use(
    cors({
      credentials: true,
      origin: process.env.CLIENT_URL,
    })
);
```

`credentials`设置启用了标题 Access-Control-Allow-Credentials。这允许客户端 JavaScript 在成功提供凭据后从服务器接收响应。

1.  还要更新 Apollo Server，以便禁用其自己的`cors`。在`listen`之前更新此行：

```ts
apolloServer.applyMiddleware({ app, cors, which is enabled by default so we want to disable it.
```

现在我们已经将 CORS 安装到我们的服务器上。现在让我们在自己的 VSCode 窗口中打开我们的 React 项目，并安装 GraphQL 以开始与我们的 GraphQL 服务器集成：

1.  在自己的 VSCode 窗口中打开`super-forum-client`文件夹后，首先尝试运行它以确保它正常工作。如果您还没有这样做，请删除`node_modules`文件夹和`package-lock.json`文件，然后运行`npm install`一次。

1.  现在让我们安装 Apollo GraphQL 客户端。打开终端到`super-forum-client`的根目录，并运行以下命令：

```ts
npm install @apollo/client graphql 
```

1.  现在我们需要配置我们的客户端。打开`index.ts`并在`ReactDOM.render`之前添加以下代码：

```ts
const client = new ApolloClient({
  uri: 'http://localhost:5000/graphql',
  credentials: "include",
  cache: new InMemoryCache()
});
```

像往常一样，添加你的导入 - 这很容易理解。我们设置服务器的 URL，包括所需的任何凭据，并设置`cache`对象。请注意，这意味着 Apollo 会缓存我们所有的查询结果。

1.  接下来更新`ReactDOM.render`，并让其包括`ApolloProvider`：

```ts
ReactDOM.render(
  <Provider store={configureStore()}>
    <BrowserRouter>
    <ApolloProvider client={client}>
      <ErrorBoundary>{[<App key="App" />]}</       ErrorBoundary>
      </ApolloProvider>
    </BrowserRouter>
  </Provider>,
  document.getElementById("root")
);
```

1.  现在让我们通过获取 ThreadCategories 来测试它是否正常工作。打开`src/components/areas/LeftMenu.tsx`文件并进行以下更新：

```ts
import React, { useEffect, useState } from "react";
import { useWindowDimensions } from "../../hooks/useWindowDimensions";
import "./LeftMenu.css";
import { gql, useQuery } from "@apollo/client";
```

我们已经从 Apollo 客户端导入了一些项目。`gql`允许我们为 GraphQL 查询获取语法高亮显示和格式化。`UseQuery`是我们的第一个与 GraphQL 相关的客户端 Hook。它允许我们执行 GraphQL 查询，而不是执行 Mutation，但它会立即运行。稍后，我将展示一个允许延迟加载的 Hook：

```ts
const GetAllCategories = gql`
  query getAllCategories {
    getAllCategories {
      id
      name
    }
  }
`;
```

这是我们的查询。这里没有什么需要解释的，但请注意我们获取了`id`和`name`。

```ts
const LeftMenu = () => {
const { loading, error, data } = useQuery(GetAllCategories);
```

我们的`useQuery`调用返回属性`loading`，`error`和`data`。每个 Apollo GraphQL Hook 返回一组不同的相关属性。我们将看到这些特定属性如何在以下代码中使用：

```ts
  const { width } = useWindowDimensions();
  const [categories, setCategories] = useState<JSX.   Element>(
    <div>Left Menu</div>
  );
  useEffect(() => {
    if (loading) {
      setCategories(<span>Loading ...</span>);
```

在刚刚显示的代码中，我们首先检查数据是否仍在加载，方法是使用`loading`属性并在这种情况下提供占位文本。

```ts
    } else if (error) {
      setCategories(<span>Error occurred loading        categories ...</span>);
```

在此错误部分中，我们指示查询运行期间发生了错误。

```ts
    } else {
      if (data && data.getAllCategories) {
        const cats = data.getAllCategories.map((cat: any)         => {
          return <li key={cat.id}>
        <Link to={`/categorythreads/${cat.id}`}>{cat.         name}</Link>
     </li>;
        });
        setCategories(<ul className="category">{cats}        </ul>);
      }
```

最后，如果一切顺利，我们得到了我们的数据，然后我们显示一个无序列表，表示每个 ThreadCategory。请注意，每个`li`元素都有一个唯一的键标识符。在提供一组类似元素时，拥有键总是很重要的，因为它减少了不必要的渲染。此外，每个元素都是一个链接，向用户显示与特定`ThreadCategory`相关的所有 Threads：

```ts
    }
    // eslint-disable-next-line react-hooks/exhaustive-     //deps
  }, [data]);
  if (width <= 768) {
    return null;
  }
  return <div className="leftmenu">{categories}</div>;
};
export default LeftMenu;
```

1.  在桌面模式下运行应用程序应该显示这个屏幕。请注意，我已经点击了一个具有关联 Thread 数据的 ThreadCategory 链接。但当然，我们目前仍在使用`dataService`返回硬编码数据：

![图 15.8 – 左侧菜单线程类别列表](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_15.08_B15508.jpg)

图 15.8 – 左侧菜单线程类别列表

太棒了 - 我们现在连接到了我们的 GraphQL 服务器！

## 主屏幕

恭喜 - 你已经走了很长的路。现在我们需要更新我们的 Main 组件，以便从我们的 GraphQL 服务返回真实的数据。让我们现在创建它：

1.  转到我们的`super-forum-server`项目，打开`typeDefs`文件，并在源代码中的`getThreadsByCategoryId`查询下方添加函数`getThreadsLatest`的模式条目。在这里，我们正在创建一个新的解析器`getThreadsLatest`，当没有特定的 ThreadCategory 给出时，它会给我们最新的 Threads。当给出 ThreadCategory 时，我们已经有了`getThreadsByCategoryId`解析器。

1.  打开`ThreadRepo`并添加这个函数：

```ts
export const getThreadsLatest = async (): Promise<QueryArrayResult<Thread>> => {
  const threads = await Thread.createQueryBuilder("thread")
    .leftJoinAndSelect("thread.category", "category")
    .leftJoinAndSelect("thread.threadItems",      "threadItems")
    .orderBy("thread.createdOn", "DESC")
    .take(10)
    .getMany();
```

我们有一个包括 ThreadCategories 和 ThreadItems 的查询 - `leftJoinAndSelect`，按`createdOn`字段排序，`orderBy`，并且只取最多 10 个项目（`take`）：

```ts
  if (!threads || threads.length === 0) {
    return {
      messages: ["No threads found."],
    };
  }
  return {
    entities: threads,
  };
};
```

其余部分与`getThreadsByCategoryId`类似，不再赘述。

让我们也更新我们的`getThreadsByCategoryId`函数，包括 ThreadItems：

```ts
export const getThreadsByCategoryId = async (
  categoryId: string
): Promise<QueryArrayResult<Thread>> => {
  const threads = await Thread.   createQueryBuilder("thread")
    .where(`thread."categoryId" = :categoryId`, {       categoryId })
    .leftJoinAndSelect("thread.category", "category")
    .leftJoinAndSelect("thread.threadItems",       "threadItems")
    .orderBy("thread.createdOn", "DESC")
    .getMany();
  if (!threads || threads.length === 0) {
    return {
      messages: ["Threads of category not found."],
    };
  }
  return {
    entities: threads,
  };
};
```

它与以前一样，只是多了一个`leftJoinAndSelect`函数。

1.  打开`resolvers`文件，并在 Query 部分的末尾添加源代码中的`getThreadsLatest`函数。这是一个几乎与`getThreadsByCategoryId`解析器相同的包装器，只是调用了`getThreadsLatest`。

1.  现在我们需要更新我们的`Main`React 组件，使其使用我们的 GraphQL 解析器而不是来自`dataService`的假数据。打开`Main`并像这样更新文件。

`const` `GetThreadsByCategoryId`是我们的第一个查询。正如您所看到的，它使用内联片段并获取我们的 Thread 数据字段：

```ts
const GetThreadsByCategoryId = gql`
  query getThreadsByCategoryId($categoryId: ID!) {
    getThreadsByCategoryId(categoryId: $categoryId) {
      ... on EntityResult {
        messages
      }
      ... on ThreadArray {
        threads {
          id
          title
          body
          views
          threadItems {
            id
          }
          category {
            id
            name
          }
        }
      }
    }
  }
`;
```

`GetThreadsLatest`基本上与`GetThreadsByCategoryId`相同：

```ts
const GetThreadsLatest = gql`
  query getThreadsLatest {
    getThreadsLatest {
      ... on EntityResult {
        messages
      }
      ... on ThreadArray {
        threads {
          id
          title
          body
          views
          threadItems {
            id
          }
          category {
            id
            name
          }
        }
      }
    }
  }
`;
```

现在我们开始使用`useLazyQuery` Hooks 定义我们的`Main`组件：

```ts
const Main = () => {
  const [
    execGetThreadsByCat,
    {
      //error: threadsByCatErr,
      //called: threadsByCatCalled,
      data: threadsByCatData,
    },
  ] = useLazyQuery(GetThreadsByCategoryId);
  const [
    execGetThreadsLatest,
    {
      //error: threadsLatestErr,
      //called: threadsLatestCalled,
      data: threadsLatestData,
    },
] = useLazyQuery(GetThreadsLatest);
```

现在显示的两个 Hooks 正在使用我们的查询。请注意，这些是延迟的 GraphQL 查询。这意味着它们不会立即运行，不像`useQuery`，只有在进行`execGetThreadsByCat`或`execGetThreadsLatest`调用时才会运行。`data`属性包含我们查询的返回数据。此外，我已经注释掉了两个返回的属性，因为我们没有使用它们。但是，如果您的调用遇到错误，它们是可用的。`Error`包含有关失败的信息，`called`指示 Hook 是否已经被调用。

```ts
  const { categoryId } = useParams();
  const [category, setCategory] = useState<Category |   undefined>();
  const [threadCards, setThreadCards] =   useState<Array<JSX.Element> | null>(
    null
  );
```

先前的状态对象保持不变。

```ts
  useEffect(() => {
    if (categoryId && categoryId > 0) {
      execGetThreadsByCat({
        variables: {
          categoryId,
        },
      });
    } else {
      execGetThreadsLatest();
    }
    // eslint-disable-next-line react-hooks/exhaustive-    // deps
  }, [categoryId]);
```

这个`useEffect`现在更新为只在需要时执行`execGetThreadsByCat`或`execGetThreadsLatest`。如果给定了`categoryId`参数，应该运行`execGetThreadsByCat`；如果没有，应该运行另一个：

```ts
  useEffect(() => {
    if (
      threadsByCatData &&
      threadsByCatData.getThreadsByCategoryId &&
      threadsByCatData.getThreadsByCategoryId.threads
    ) {
      const threads = threadsByCatData.      getThreadsByCategoryId.threads;
      const cards = threads.map((th: any) => {
        return <ThreadCard key={`thread-${th.id}`}         thread={th} />;
      });
      setCategory(threads[0].category);
      setThreadCards(cards);
    }
}, [threadsByCatData]);
```

在`useEffect`中，`threadsByCatData`的变化导致我们使用`getThreadsByCategoryId`查询的数据更新`category`和`threadCards`。

```ts
  useEffect(() => {
    if (
      threadsLatestData &&
      threadsLatestData.getThreadsLatest &&
      threadsLatestData.getThreadsLatest.threads
    ) {
      const threads = threadsLatestData.getThreadsLatest.      threads;
      const cards = threads.map((th: any) => {
        return <ThreadCard key={`thread-${th.id}`}         thread={th} />;
      });
      setCategory(new Category("0", "Latest"));
      setThreadCards(cards);
    }
  }, [threadsLatestData]);
```

在`useEffect`中，`threadsLatestData`的变化导致我们使用`getThreadsLatest`查询的数据更新`category`和`threadCards`。请注意，当没有给出`categoryId`时，我们只是使用一个通用的“最新”名称作为我们的 ThreadCategory。

```ts
  return (
    <main className="content">
      <MainHeader category={category} />
      <div>{threadCards}</div>
    </main>
  );
};
export default Main;
```

其余代码与以前相同。

1.  现在，如果我们为`categoryId`运行这个，我们应该会看到这个：

![图 15.9 – 有 categoryId](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_15.09_B15508.jpg)

图 15.9 – 有 categoryId

如果我们在没有`categoryId`的情况下运行这个，我们应该会看到这个：

![图 15.10 – 没有 categoryId](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_15.10_B15508.jpg)

图 15.10 – 没有 categoryId

好了，现在我们的网站屏幕上有一些实际的真实数据了。在继续之前，让我们稍微清理一下我们的样式，并去掉一些占位背景颜色。我对`Nav.css`和`Home.css`文件进行了微小的更改。现在是这个样子的：

![图 15.11 - 主屏幕样式更新](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_15.11_B15508.jpg)

图 15.11 - 主屏幕样式更新

好了，这样好多了。在我们屏幕的移动版本上有一件事要注意 - 我们没有办法让用户切换到另一个类别，如下图所示：

![图 15.12 - 主屏幕移动视图](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_15.12_B15508.jpg)

图 15.12 - 主屏幕移动视图

因此，让我们添加一个下拉菜单，允许用户切换类别。这个下拉菜单应该只在移动模式下出现。在跟随之前尝试构建这个控件。提示：使用 React-DropDown 构建下拉菜单，并用下拉控件替换类别标签。例如，在*图 15.12*中，我们看到所选的类别是`MainHeader`控件。因此，只在移动模式下用下拉菜单替换该标签。请注意，我们已经在我们的 ThreadCategory 路由中使用了下拉菜单，因此我们应该将其创建为一个组件，以便它可以被重用。

如果你已经尝试过了，现在让我们一起开始构建，这样你就可以进行比较。这里有一点我说了谎。这是一个相当复杂的改变，因为它需要两个主要的事情。首先，我们希望为 ThreadCategories 添加一个新的 Reducer，因为我们知道 ThreadCategories 的列表至少在两个独立的组件中被使用。我们还需要将 ThreadCategory 组件中的下拉菜单组件化，以便它可以在多个地方使用。第二个部分相当复杂，因为新的下拉组件必须足够复杂，以便从外部接收 props，并在每次更改时发送所选的类别：

1.  首先，让我们创建我们的新 Reducer。在`store`文件夹中创建一个名为`categories`的新文件夹。在该文件夹中，创建一个名为`Reducer.ts`的文件，并将源代码添加到其中。这个文件很像我们的`User` Reducer，只是它返回一个`Category`对象数组作为有效负载。

1.  接下来，我们需要将新的 Reducer 添加到我们的`AppState`的`rootReducer`中，就像这样：

```ts
export const rootReducer = combineReducers({
  user: UserProfileReducer,
  categories: ThreadCategoriesReducer,
});
```

我们的新`rootReducer`成员将被称为`Categories`。

1.  现在更新`App.tsx`组件，以便在应用程序加载时，我们立即获取我们的 ThreadCategories 并将它们添加到 Redux 存储中。

在这里，我们添加了`GetAllCategories` GraphQL 查询：

```ts
const GetAllCategories = gql`
  query getAllCategories {
    getAllCategories {
      id
      name
    }
  }
`;
function App() {
  const { data } = useQuery(GetAllCategories);
  const dispatch = useDispatch();
  useEffect(() => {
    dispatch({
      type: UserProfileSetType,
      payload: {
        id: 1,
        userName: "testUser",
      },
    });
    if (data && data.getAllCategories) {
      dispatch({
        type: ThreadCategoriesType,
        payload: data.getAllCategories,
      });
```

我们之前看到的大部分代码都是一样的，但这是我们将 ThreadCategories 的有效负载发送到 Redux 存储的地方：

```ts
    }
  }, [dispatch, data]);
  const renderHome = (props: any) => <Home {...props} />;
  const renderThread = (props: any) => <Thread {...props}    />;
  const renderUserProfile = (props: any) => <UserProfile    {...props} />;
  return (
    <Switch>
      <Route exact={true} path="/" render={renderHome} />
      <Route path="/categorythreads/:categoryId"       render={renderHome} />
      <Route path="/thread/:id" render={renderThread} />
      <Route path="/userprofile/:id"       render={renderUserProfile} />
    </Switch>
  );
}
```

其他一切都保持不变。请注意，您需要更新您的导入。

1.  `LeftMenu`和`ThreadCategory`组件将需要删除它们获取 ThreadCategories 和创建下拉菜单的代码。但首先，让我们创建我们的共享控件来完成所有这些。在`src/components`文件夹中创建一个名为`CategoryDropDown.tsx`的文件，并添加这段代码。确保您添加任何必要的导入：

```ts
const defaultLabel = "Select a category";
const defaultOption = {
  value: "0",
  label: defaultLabel
};
```

通过`defaultOption`，我们为我们的下拉菜单创建了一个初始值。

```ts
class CategoryDropDownProps {
  sendOutSelectedCategory?: (cat: Category) => void;
  navigate?: boolean = false;
  preselectedCategory?: Category;
}
```

`CategoryDropDownProps`将是我们的`CategoryDropDown`组件的参数类型。`sendOutSelectedCategory`是由父调用者传递的函数，将用于接收父级选择的下拉选项。`Navigate`是一个布尔值，确定在选择新的下拉选项时屏幕是否会移动到新的 URL。`preselectedCategory`允许父级在加载时强制下拉菜单选择指定的 ThreadCategory：

```ts
const CategoryDropDown: FC<CategoryDropDownProps> = ({
  sendOutSelectedCategory,
  navigate,
  preselectedCategory,
}) => {
  const categories = useSelector((state: AppState) =>   state.categories);
  const [categoryOptions, setCategoryOptions] = useState<
    Array<string | Option>
  >([defaultOption]);
  const [selectedOption, setSelectedOption] =   useState<Option>(defaultOption);
  const history = useHistory();
```

根据我们之前的学习，这些列出的 Hooks 的使用是非常明显的。但请注意，我们正在使用`useSelector`从 Redux 存储中获取 ThreadCategories 的列表。

```ts
  useEffect(() => {
    if (categories) {
      const catOptions: Array<Option> = categories.      map((cat: Category) => {
        return {
          value: cat.id,
          label: cat.name,
        };
      });
```

在这里，我们构建了一个选项数组，以供稍后给我们的下拉菜单。

```ts
      setCategoryOptions(catOptions);
```

在`setCategoryOptions`中，我们正在接收我们的 ThreadCategory 选项元素列表并设置它们，以便稍后可以被我们的下拉菜单使用。

```ts
      setSelectedOption({
        value: preselectedCategory ? preselectedCategory.        id : "0",
        label: preselectedCategory ? preselectedCategory.        name : defaultLabel,
      });
```

在这里，我们已经设置了我们默认的下拉选择。

```ts
    }
  }, [categories, preselectedCategory]);
  const onChangeDropDown = (selected: Option) => {
    setSelectedOption(selected);
    if (sendOutSelectedCategory) {
      sendOutSelectedCategory(
        new Category(selected.value, selected.label?.valueOf().toString() ?? "")
      );
    }
```

在这里的下拉更改处理程序中，我们正在通知父级选择发生了变化。

```ts
    if (navigate) {
      history.push(`/categorythreads/${selected.value}`);
    }
```

如果父级请求，我们将导航到下一个 ThreadCategory 路由。

```ts
  };
  return (
    <DropDown
      className="thread-category-dropdown"
      options={categoryOptions}
      onChange={onChangeDropDown}
      value={selectedOption}
      placeholder=defaultLabel
    />
  );
};
export default CategoryDropDown;
```

最后，这是我们实际的 JSX，它非常容易理解。

1.  现在我们需要像这样更新`MainHeader.tsx`文件：

```ts
interface MainHeaderProps {
  category?: Category;
}
const MainHeader: FC<MainHeaderProps> = ({ category }) => {
  const { width } = useWindowDimensions();
```

唯一重要的更改是`getLabelElement`函数，它决定屏幕是否为移动设备，并在是的情况下呈现`CategoryDropDown`：

```ts
  const getLabelElement = () => {
    if (width <= 768) {
      return (
        <CategoryDropDown navigate={true}         preselectedCategory={category} />
      );
    } else {
      return <strong>{category?.name || "Placeholder"}      </strong>;
    }
  };
  return (
    <div className="main-header">
      <div
        className="title-bar"
        style={{ marginBottom: ".25em", paddingBottom:         "0" }}
      >
        {getLabelElement function.

```

</div>

</div>

);

};

```ts

```

其余的代码大部分是删除的代码，所以请尝试自己做。当然，如果需要，可以查看源代码。受影响的文件是`ThreadCategory.tsx`，`LeftMenu.tsx`和`Thread.css`。

## 与身份验证相关的功能

现在让我们继续更新与身份验证相关的功能。请记住，所有您的“用户”帐户在能够登录之前必须将其`confirmed`字段设置为 true：

1.  我们首先要做的是让用户能够登录。为了做到这一点，然后能够更新我们在全局 Redux 存储中的`User`对象，我们将重构我们的 Redux 用户 Reducer。

首先，在`models`文件夹中，创建一个名为`User.ts`的新文件并将源代码添加到其中。请注意，我们的`User`类有一个名为 threads 的字段。这将包含不仅是用户拥有的 Threads，还有这些 Threads 的 ThreadItems。

1.  现在让我们更新我们的 Reducer。打开`store/user/Reducer.ts`并通过删除`UserProfilePayload`接口并用我们刚刚创建的新`User`类替换其引用来更新它。如果需要，查看源代码。

1.  现在我们可以像这样更新我们的`Login`组件。根据需要更新导入。

请注意，我们已经导入了 Hook`useRefreshReduxMe`。我们将在一会儿定义这个 Hook，但首先我想介绍一些`useMutation` GraphQL Hook 的特性：

```ts
const LoginMutation = gql`
  mutation Login($userName: String!, $password: String!)  {
    login(userName: $userName, password: $password)
  }
`;
```

这是我们的登录`Mutation`：

```ts
const Login: FC<ModalProps> = ({ isOpen, onClickToggle }) => {
  const [execLogin] = useMutation(LoginMutation, {
    refetchQueries: [
      {
        query: Me,
      },
    ],
  });
```

让我解释一下这个`useMutation`调用。调用以 Mutation 查询`LoginMutation`和称为`refetchQueries`的东西作为参数。`refetchQueries`强制其中列出的任何查询重新运行，然后缓存它们的值。如果我们不使用`refetchQueries`并再次运行`Me`查询，我们最终会得到最后缓存的版本而不是最新的数据。请注意，它不会自动刷新依赖于其查询的任何调用；我们仍然必须进行这些调用以获取新数据。

输出`execLogin`是一个可以随后执行的函数。

```ts
const [
    { userName, password, resultMsg, isSubmitDisabled },
    dispatch,
  ] = useReducer(userReducer, {
    userName: "test1",
    password: "Test123!@#",
    resultMsg: "",
    isSubmitDisabled: false,
  });
  const { execMe, updateMe } = useRefreshReduxMe();
  const onChangeUserName = (e: React.   ChangeEvent<HTMLInputElement>) => {
    dispatch({ type: "userName", payload: e.target.value     });
    if (!e.target.value)
      allowSubmit(dispatch, "Username cannot be empty",       true);
    else allowSubmit(dispatch, "", false);
  };
  const onChangePassword = (e: React.  ChangeEvent<HTMLInputElement>) => {
    dispatch({ type: "password", payload: e.target.value     });
    if (!e.target.value)
      allowSubmit(dispatch, "Password cannot be empty",       true);
    else allowSubmit(dispatch, "", false);
  };
```

之前的调用与以前一样。

```ts
const onClickLogin = async (
    e: React.MouseEvent<HTMLButtonElement, MouseEvent>
  ) => {
    e.preventDefault();
    onClickToggle(e);
    const result = await execLogin({
      variables: {
        userName,
        password,
      },
    });
    execMe();
    updateMe();
  };
```

`onClickLogin`处理程序现在正在使用适当的参数调用我们的`execLogin`函数。在`execLogin`完成后，它将自动调用我们的`refetchQueries`查询列表。之后，我们调用来自我们的 Hook 的函数，`useRefreshReduxMe`，`execMe`和`updateMe`。`execMe`函数将获取最新的`User`对象，`updateMe`将将其添加到 Redux 存储中。其余的代码是相同的，所以我不会在这里展示它。

1.  现在让我们定义我们的 Hook`useRefreshReduxMe`。我们想要创建这个 Hook，以便我们的设置或取消 Redux`User`对象的代码可以在这个单个文件中。我们将从几个组件中使用这个 Hook。在 hooks 文件夹中创建一个名为`useRefreshReduxMe.ts`的文件并添加源代码。

从顶部，我们可以看到`Me` `const`是用于获取用户信息的查询。`EntityResult`内联片段用于获取消息的字符串（如果返回的是消息）。如果我们获取实际的用户数据，那么所需的字段由`User`内联片段定义。

接下来，`UseRefreshReduxMeResult`接口是我们 Hook 的返回类型。

在第 37 行，我们已经定义了`useLazyQuery`，以允许我们的 Hook 用户在自己选择的时间执行对`Me`查询的调用。

接下来，我们定义了一个函数`deleteMe`，允许我们的 Hook 的用户随时销毁 Redux`User`对象。例如，当用户注销时。

最后，我们有`updateMe`函数，允许设置 Redux`User`对象。然后我们返回所有这些函数，以便它们可以被我们的 Hook 调用者使用。

1.  在应用加载时，我们应立即检查我们的`User`是否已登录以及是谁。因此，打开`App.tsx`并像这样更新它：

```ts
function App() {
  const { data: categoriesData } =   useQuery(GetAllCategories);
  const { execMe, updateMe } = useRefreshReduxMe();
```

在这里，我们初始化了我们的`useRefreshReduxMe` Hook。

```ts
  const dispatch = useDispatch();
  useEffect(() => {
    execMe();
  }, [execMe]);
```

在这里，我们调用我们的`execMe`来从 GraphQL 获取`User`数据。

```ts
  useEffect(() => {
    updateMe();
  }, [updateMe]);
```

在这里，我们调用`updateMe`来使用`User`数据更新我们的 Redux 用户 Reducer。

```ts
  useEffect(() => {
    if (categoriesData && categoriesData.    getAllCategories) {
      dispatch({
        type: ThreadCategoriesType,
        payload: categoriesData.getAllCategories,
      });
    }
  }, [dispatch, categoriesData]);
```

我将我们原始的数据字段名称更改为`categoriesData`，这样它就更清楚它的用途了。其余的代码保持不变。

1.  如果您现在登录，您会看到我们的`SideBar` `userName`更新为已登录用户：

![图 15.13 - 已登录用户](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_15.13_B15508.jpg)

图 15.13 - 已登录用户

所以，现在我们可以登录，然后显示`userName`。

很棒，但现在让我们修复我们的`SideBar`，以便在适当的时间只显示适当的链接。例如，如果用户已登录，我们不应该看到**登录**或**注册**链接：

1.  为了确保用户登录或注销时显示正确的菜单，让我们首先更新我们的`Logout`组件。确保导入已经更新：

```ts
const LogoutMutation = gql`
  mutation logout($userName: String!) {
    logout(userName: $userName)
  }
`;
```

这是我们的`logout` mutation。

```ts
const Logout: FC<ModalProps> = ({ isOpen, onClickToggle }) => {
  const user = useSelector((state: AppState) => state.  user);
  const [execLogout] = useMutation(LogoutMutation, {
    refetchQueries: [
      {
        query: Me,
      },
    ],
  });
```

在这里，我们再次强制刷新我们的 GraphQL 缓存，以获取`Me`查询的数据。

```ts
  const { execMe, deleteMe } = useRefreshReduxMe();
  const onClickLogin = async (
    e: React.MouseEvent<HTMLButtonElement, MouseEvent>
  ) => {
    e.preventDefault();
    onClickToggle(e);
    await execLogout({
      variables: {
        userName: user?.userName ?? "",
      },
    });    
    deleteMe();
  };
```

我们再次使用了我们的`useRefreshReduxMe` Hook，但这里我们只调用了`deleteMe`函数，因为我们只是在注销。其余的代码保持不变，所以我不会在这里展示。

1.  现在我们要更新`SideBarMenus`组件，以便在适当的时间只显示适当的菜单。打开该文件并按照以下方式更新它。

在这种情况下，我只会显示返回的 JSX，因为除了导入之外，这是唯一改变的事情：

```ts
return (
    <React.Fragment>
      <ul>
        {user ? (
          <li>
            <FontAwesomeIcon icon={faUser} />
            <span className="menu-name">
              <Link to={`/userprofile/${user?.               id}`}>{user?.userName}</Link>
            </span>
          </li>
        ) : null}
```

正如您所看到的，我们正在测试`user`对象是否有值，然后显示相同的`userName` UI，否则我们什么都不显示。

```ts
        {user ? null : (
          <li>
            <FontAwesomeIcon icon={faRegistered} />
            <span onClick={onClickToggleRegister}              className="menu-name">
              register
            </span>
            <Registration
              isOpen={showRegister}
              onClickToggle={onClickToggleRegister}
            />
          </li>
        )}
```

在这种情况下，如果用户存在，我们不想显示我们的注册 UI，这就是我们正在做的。

```ts
        {user ? null : (
          <li>
            <FontAwesomeIcon icon={faSignInAlt} />
            <span onClick={onClickToggleLogin}             className="menu-name">
              login
            </span>
            <Login isOpen={showLogin}              onClickToggle={onClickToggleLogin} />
          </li>
        )}
```

同样，如果`user`对象已经存在，我们不会显示登录，因为这表示用户已经登录。

```ts
        {user ? (
          <li>
            <FontAwesomeIcon icon={faSignOutAlt} />
            <span onClick={onClickToggleLogout}              className="menu-name">
              logout
            </span>
            <Logout isOpen={showLogout}              onClickToggle={onClickToggleLogout} />
          </li>
        ) : null}
```

在这里，如果`user`对象有值，我们会显示注销 UI。

```ts
      </ul>
    </React.Fragment>
  );
```

1.  如果您现在运行此代码，当尚未登录时，您会看到这个：

![图 15.14 - 未登录的 SideBarMenus](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_15.14_B15508.jpg)

图 15.14 - 未登录的 SideBarMenus

现在，当登录时，我们应该看到这个：

![图 15.15 - 已登录的 SideBarMenus](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_15.15_B15508.jpg)

图 15.15 - 已登录的 SideBarMenus

所以我们的侧边栏现在显示正确的链接和文本。现在让我们来处理我们的用户资料屏幕。

## 用户资料屏幕

现在，既然我们在认证部分，让我们完成我们的用户资料屏幕。我们需要进行多个更改来配置这个屏幕：

1.  首先，让我们通过向我们的`User`类型添加一个字段来更新我们的 GraphQL。通过在`typeDefs`文件的`User`类型下面添加这个字段来更新`User`类型：

```ts
  threadItems. Note that this is different from threadItems that's part of the threads field, as we are trying to retrieve the ThreadItem entities the user themselves has authored.
```

1.  我们还需要通过添加一个新字段来更新我们的 User Entity。通过在`User.ts`文件中添加这个字段来更新`User` Entity：

```ts
  @OneToMany(() => ThreadItem, (threadItem) =>   threadItem.user)
  threadItems: ThreadItem[];
```

这允许我们的`User`实体在 ThreadItems 实体上有关联的实体。还要确保您已经在`ThreadItem.ts`文件中有匹配的字段，像这样：

```ts
@ManyToOne(() => User, (user) => user.threadItems)
  user: User;
```

1.  现在让我们打开我们的 UserRepo Repository 文件，并更新我们的`me`函数，以便它包括用户的 ThreadItems。像这样更新 UserRepo `User.findOne`函数：

```ts
    relations: ["threads", "threads.threadItems",    threadItems and threadItems.thread relations.
```

1.  您会注意到用户资料屏幕具有更改密码功能。所以现在让我们构建出来。首先，我们需要在我们的`typeDefs`文件中添加一个新的 Mutation。将此 Mutation 添加到 Mutation 部分：

```ts
changePassword(newPassword: String!): String!
```

一个相当自解释的 Mutation 定义。

1.  现在让我们在我们的 UserRepo 中实现这个函数。在源代码中的 UserRepo 末尾添加`changePassword`函数。

从第 125 行开始，因为如果进行了这个调用，用户将会被登录，我们期望从解析器代码中传递用户 `id`。如果不存在，那么当然我们会出错。

然后我们尝试获取 `User` 对象，然后运行一些检查以确保用户是有效的。最后，我们使用 `bcrypt` 生成我们的哈希密码。

1.  现在我们可以创建我们的解析器。打开 `resolvers` 文件，并将 `changePassword` 函数的源代码添加到 Mutation 部分。

首先，在第 389 行，我们检查一个有效的 Session 和在该 Session 中存在的 `userId`，因为这是指示用户已登录的标志。

最后，我们使用 Session `userId` 和给定的新密码调用我们的 `changePassword` 仓库函数。

1.  现在让我们更新我们的 `UserProfile` 组件。更新代码如下：

更新导入，因为我们导入了一些新项目，`gql` 和 `useMutation`：

```ts
const ChangePassword = gql`
  mutation ChangePassword($newPassword: String!) {
    changePassword(newPassword: $newPassword)
  }
`;
```

这里，我们有我们的新 Mutation，`ChangePassword`。

```ts
const UserProfile = () => {
  const [
    { userName, password, passwordConfirm, resultMsg,    isSubmitDisabled },
    dispatch,
  ] = useReducer(userReducer, {
    userName: "",
    password: "*********",
    passwordConfirm: "*********",
    resultMsg: "",
    isSubmitDisabled: true,
  });
  const user = useSelector((state: AppState) => state.   user);
  const [threads, setThreads] = useState<JSX.Element |    undefined>();
  const [threadItems, setThreadItems] = useState<JSX.   Element | undefined>();
  const [execChangePassword] =    useMutation(ChangePassword Mutation with useMutation.The `useEffect` code shown here is the same as before:

```

useEffect(() => {

if (user) {

dispatch({

type: "userName",

payload: user.userName,

});

getUserThreads(user.id).then((items) => {

const threadItemsInThreadList: Array<ThreadItem>        = [];

const threadList = items.map((th: Thread) => {

for (let i = 0; i < th.threadItems.length; i++) {

threadItemsInThreadList.push(th.            threadItems[i]);

}

return (

<li key={`user-th-${th.id}`}>

<Link to={`/thread/${th.id}`}    className="userprofile-link">

{th.title}

</Link>

</li>

);

});

setThreads(<ul>{threadList}</ul>);

const threadItemList = threadItemsInThreadList.        map((ti: ThreadItem) => (

<li key={`user-th-${ti.threadId}`}>

<Link to={`/thread/${ti.threadId}`}       className="userprofile-link">

{ti.body}

</Link>

</li>

));

setThreadItems(<ul>{threadItemList}</ul>);

});

}

}, [user]);

```ts

This `onClickChangePassword` function is new. It triggers the `changePassword` call and then updates the UI status message.

```

const onClickChangePassword = async (

e: React.MouseEvent<HTMLButtonElement, MouseEvent>

) => {

e.preventDefault();

const { data: changePasswordData } = await       execChangePassword({

variables: {

newPassword: password,

},

});

dispatch({

type: "resultMsg",

payload: changePasswordData ? changePasswordData.      changePassword : "",

});

};

return (

<div className="screen-root-container">

<div className="thread-nav-container">

<Nav />

</div>

<form className="userprofile-content-container">

<div>

<strong>用户资料</strong>

<label style={{ marginLeft: ".75em"     }}>{userName}</label>

</div>

<div className="userprofile-password">

<div>

<PasswordComparison

dispatch={dispatch}

password={password}

passwordConfirm={passwordConfirm}

/>

<button

className="action-btn"

disabled={isSubmitDisabled}

onClick={onClickChangePassword}

```ts

The `onClickChangePassword` handler is set here onto our Change Password button.

```

修改密码

</button>

</div>

<div style={{ marginTop: ".5em" }}>

<label>{resultMsg}</label>

</div>

</div>

<div className="userprofile-postings">

<hr className="thread-section-divider" />

<div className="userprofile-threads">

<strong>发布的主题</strong>

{threads}

</div>

<div className="userprofile-threadIems">

<strong>发布的主题项</strong>

{threadItems}

</div>

</div>

</form>

</div>

);

};

export default UserProfile;

```ts

The remaining code is the same.
```

现在让我们展示用户的主题和主题项：

1.  首先，我们需要更新我们的用户模型。在 `User.ts` 文件中添加这个字段：

```ts
public threadItems: Array<ThreadItem>
```

1.  现在像这样更新 `useRefreshReduxMe` Hook 中的 `Me` 查询：

```ts
export const Me = gql`
  query me {
    me {
      ... on EntityResult {
        messages
      }
      ... on User {
        id
        userName
        threads {
          id
          title
        }
        threadItems from getting the threads' threadItems to getting the user's threadItems. We also now get the threadItems' thread.
```

1.  现在，在你的 `UserProfile` 组件中，像这样更新 `useEffect`：

```ts
useEffect(() => {
    if (user) {
      dispatch({
        type: "userName",
        payload: user.userName,
      });
```

我们现在从 `user.threads` 数组中获取我们的主题，而不是我们的虚假 `dataService` 调用，如下所示：

```ts
      const threadList = user.threads?.map((th: Thread)      => {
        return (
          <li key={`user-th-${th.id}`}>
            <Link to={`/thread/${th.id}`}             className="userprofile-link">
              {th.title}
            </Link>
          </li>
        );
      });
      setThreads(
        !user.threadItems || user.threadItems.length ===          0 ? undefined : (
          <ul>{threadList}</ul>
        )
      );
```

我们也对 `threadItems` 做同样的事情。注意我们的 `Link to` 被更新了，所以它使用 `ti.thread?.id` 而不是 `ti.threadId`：

```ts
      const threadItemList = user.threadItems?.map((ti:        ThreadItem) => (
        <li key={`user-ti-${ti.id}`}>
          <Link to={`/thread/${ti.thread?.id}`}            className="userprofile-link">
            {ti.body.length <= 40 ? ti.body : ti.body.             substring(0, 40) + " ..."}
```

在这里，我们添加了一点额外的逻辑来格式化可能会横向超出屏幕并换行的长文本。基本上，这意味着如果文本超过 40 个字符，我们会在文本后面添加 `"…"`。

```ts
          </Link>
        </li>
      ));
      setThreadItems(
        !user.threadItems || user.threadItems.length ===          0 ? undefined : (
          <ul>{threadItemList}</ul>
        )
      );
    } else {
      dispatch({
        type: "userName",
        payload: "",
      });
      setThreads(undefined);
      setThreadItems(undefined);
    }
  }, [user]);
```

剩下的代码是相同的。如果你运行这个，你应该会看到类似以下的东西（再次说明，你的数据将会不同）：

![图 15.16 – 用户的主题和主题项](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/flstk-react-ts-node/img/Figure_15.16_B15508.jpg)

图 15.16-用户的 Threads 和 ThreadItems

好的，这就是我们的 UserProfile。因为这是一大堆要涵盖的材料，让我们在下一章继续我们的工作，[*第十六章*]，*添加 GraphQL 模式-第二部分*。

# 总结

在本章中，我们通过将前端和后端与 GraphQL 集成，几乎完成了我们的应用。这是一个庞大而复杂的章节，所以你应该为自己已经走过的路感到自豪。

在下一章，[*第十六章*]，*添加 GraphQL 模式-第二部分*，我们将通过在 Thread 屏幕上工作来完成我们应用的编码，这样我们就可以查看和发布 Threads，并且通过 Points 系统来查看用户对单个 Threads 的受欢迎程度。
