# Deno Web 开发（三）

> 原文：[`zh.annas-archive.org/md5/05CD4283AEDF57F3F0FCDC18A95F489E`](https://zh.annas-archive.org/md5/05CD4283AEDF57F3F0FCDC18A95F489E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：HTTPS，提取配置，Deno 在浏览器中运行

在上一章中，我们基本上完成了应用程序的所有功能。我们添加了授权和持久性，最终得到了一个连接到 MongoDB 实例的应用程序。在本章中，我们将专注于一些已知的最优实践，这些实践在生产应用程序中是标准的：基本安全实践和处理配置。

首先，我们将为我们的**应用程序编程接口**（**API**）添加一些基本的安全特性，从**跨源资源共享**（**CORS**）保护开始，以启用基于来源的请求过滤。然后，我们将学习如何在我们的应用程序中启用**安全超文本传输协议**（**HTTPS**），以便它支持加密连接。这将允许用户使用安全的连接对 API 进行请求。

到目前为止，我们使用了一些秘密值，但我们并不担心它们在代码中。在本章中，我们将提取配置和秘密值，以便它们不必存在于代码库中。我们还将学习如何安全地存储和注入这些值。这样，我们可以确保这些值保持秘密，并且不在代码中。通过这样做，我们还将使不同的部署具有不同的配置成为可能。

接下来，我们将探索由 Deno 的其中一个特定功能启用的能力：在浏览器中编译和运行代码的能力。通过使用 Deno 与 ECMAScript 6（现代浏览器支持的）的兼容性，我们将 API 和前端之间的代码共享，启用一个全新的可能性世界。

利用这个特定功能，我们将探索一个特定的场景：为 API 构建一个 JavaScript 客户端。这个客户端将使用与服务器上运行的相同类型和代码部分构建，并探索由此带来的好处。

本章结束了本书的*构建应用程序*部分，我们一步一步地构建了一个应用程序，用逐步增加的方法添加了一些常见应用程序特性。在学习的同时，我们还确保这个应用程序尽可能接近现实，这是一本介绍性的书籍。这使我们能够在创建功能应用程序的同时学习 Deno，它的许多 API 以及一些社区包。

到本章结束时，您将熟悉以下主题：

+   启用 CORS 和 HTTPS

+   提取配置和秘密值

+   在浏览器中运行 Deno 代码

# 技术要求

本章所需的代码文件可以在以下 GitHub 链接中找到：

链接：[`github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter07/sections`](https://github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter07/sections)

# 启用 CORS 和 HTTPS

CORS 保护和 HTTPS 支持是任何运行中的生产应用程序考虑的两个关键因素。本节将解释如何将它们添加到我们正在构建的应用程序中。

还有许多其他的安全实践可以添加到任何 API 中。由于这些不是 Deno 特定内容，并且应该单独成书，所以我们决定专注于这两个要素。

我们将首先了解 CORS 以及如何利用`oak`和我们所知的中间件功能来实现它。然后，我们将学习如何使用自签名证书，并使我们的 API 处理安全 HTTP 连接。

让我们开始吧，从 CORS 开始。

## 启用 CORS

如果你不熟悉 CORS，它是一种机制，使服务器能够指示浏览器它们应该允许从哪些源加载资源。当应用程序在 API 相同的域上运行时，CORS 甚至是不必要的，因为名称直接表明了一切。

以下是从**Mozilla 开发者网络**（**MDN**）摘录的关于 CORS 的解释：

"跨源资源共享（CORS）是一个基于 HTTP 头的机制，允许服务器指示浏览器应该允许从其自身以外的任何其他源（域、协议或端口）加载资源。CORS 还依赖于一种机制，通过这种机制，浏览器向跨源资源所在的服务器发起一个“预检”请求，以检查服务器是否允许实际请求。在预检中，浏览器发送头信息，指示实际请求中将使用的 HTTP 方法和头信息。"

为了给你一个更具体的例子，想象你有一个运行在`the-best-deno-api.com`的 API，并且你想处理从`the-best-deno-client.com`发起的请求。在这里，你希望你的服务器对`the-best-deno-client.com`域启用 CORS。

如果你没有启用它，浏览器将向你的 API 发起一个预检请求（使用`OPTIONS`方法），对这个请求的响应将不会包含`Access-Control-Allow-Origin: the-best-deno-client.com`头，导致请求失败并阻止浏览器进一步请求。

我们将学习如何在我们的应用程序中启用这个机制，允许从`http://localhost:3000`发起请求。

由于我们的应用程序使用了`oak`框架，我们将学习如何使用这个框架来实现。然而，这与其他任何 HTTP 框架非常相似。我们基本上需要添加一个中间件函数，该函数处理请求并将请求的来源与允许的域列表进行比对。

我们将使用一个名为`cors`的社区包：（https://deno.land/x/cors@v1.2.1）

重要提示

我们将使用前一章中创建的代码来启动此实现。这可以在[`github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter06/sections/4-connecting-to-mongodb/museums-api`](https://github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter06/sections/4-connecting-to-mongodb/museums-api)找到。你也可以查看本节完成后的代码：

[`github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter07/sections/3-deno-on-the-browser/museums-api`](https://github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter07/sections/3-deno-on-the-browser/museums-api)

在这里，我们将向我们的应用程序添加`cors`包，以及我们自己的允许域名列表。最终目标是使我们可以从可信网站向此 API 发送请求。

让我们这样做。按照以下步骤进行：

1.  通过更新`deps`文件安装`cors`模块（参考第三章，《运行时和标准库》，了解如何进行此操作）。代码如下所示：

    ```js
    export { oakCors } from
      "https://deno.land/x/cors@v1.2.1/oakCors.ts";
    ```

1.  接下来，运行`cache`命令以更新`lock`文件，如下所示：

    ```js
    $ deno cache --lock=lock.json --lock-write --unstable src/deps.ts
    ```

1.  在`src/web/index.ts`上导入`oakCors`，并在注册路由之前注册它，如下所示：

    ```js
    import { Algorithm, oakCors } from "../deps.ts"
    …
    oakCors middleware creator function, by sending it an array of allowed origins—in this case, http://localhost:3000. This will make the API answer to the OPTIONS request with an Access-Control-Allow-Origin: http://localhost:3000 header, which will signal to the browser that if the website making requests is running on http://localhost:3000, it should allow further requests.This will work just fine. However, having this *hardcoded* domain here seems a little bit strange. We've been injecting all the similar configuration to the application. Remember what we did with the `port` configuration? Let's do the same for the allowed domains.
    ```

1.  将`createServer`函数的参数更改为在`configuration`内部接收一个名为`allowedOrigins`的字符串数组，并将其传递给`oakCors`中间件创建函数。这段代码如下所示：

    ```js
    interface CreateServerDependencies {
      configuration: {
        port: number,
        authorization: {
          key: string,
          algorithm: Algorithm
        },
        oakCors middleware creator.
    ```

1.  然而，还有一件事缺失——我们需要从`src/index.ts`发送这个`allowedOrigins`数组。让我们这样做，如下所示：

    ```js
    createServer({
      configuration: {
        port: 8080,
        authorization: {
          key: authConfiguration.key,
          algorithm: authConfiguration.algorithm
        },
        http://localhost:3000. 
    ```

1.  让我们来测试一下，首先通过以下方式运行 API：

    ```js
    $ deno run --allow-net --unstable --allow-env --allow-read --allow-write --allow-plugin src/index.ts
    Application running at http://localhost:8080
    ```

1.  要测试它，请在根目录（`museums-api`）中创建一个名为`index.html`的 HTML 文件，其中包含一个执行`POST`请求到`http://localhost:8080/api/users/register`的脚本。这段代码如下所示：

    ```js
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width,
           initial-scale=1.0" />
        <title>Test CORS</title>
      </head>
      <body>
        <div id="status"></div>
        <script type="module">              
        div tag and altering its inner HTML code in the cases that the request works or fails so that it's easier for us to diagnose.In order for us to serve the HTML file and test this, you can leverage Deno and its ability to run remote scripts.
    ```

1.  在创建`index.html`文件的同一目录下，让我们运行 Deno 的标准库 Web 服务器，使用`-p`标志将端口设置为`3000`，`--host`将主机设置为`localhost`。这段代码如下所示：

    ```js
    $ deno run --allow-net --allow-read https://deno.land/std@0.83.0/http/file_server.ts -p 3000 --host localhost
    HTTP server listening on http://localhost:3000/
    ```

1.  用浏览器访问`http://localhost:3000`，你应该会看到一个**WORKING**消息，如下截图所示：![Figure 7.1 – 测试 CORS API 是否正常工作    ](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/deno-web-dev/img/Figure_7.1_B16380.jpg)

    Figure 7.1 – 测试 CORS API 是否正常工作

1.  如果你想要测试当源不在`allowedOrigins`列表中时会发生什么，你可以运行相同的命令，但使用不同的端口（或主机），并检查行为。这段代码如下所示：

    ```js
    $ deno run --allow-net --allow-read https://deno.land/std/http/file_server.ts -p 3001 --host localhost
    HTTP server listening on http://localhost:3001/
    ```

    现在，你可以在新建的**统一资源定位符**（**URL**）上用浏览器导航，你应该会看到一个**NOT WORKING**消息。如果你查看浏览器的控制台，你还可以确认浏览器正在警告你 CORS 预检请求失败。这是期望的行为。

这就是我们需要的，以便在 API 上启用 CORS！

我们使用的第三方模块还有一些其他选项供您探索-例如过滤特定的 HTTP 方法或用不同的状态码回答预检请求。 目前，默认选项对我们来说已经足够了。 现在，我们将进入并了解如何使用户能够通过 HTTPS 连接到应用程序，添加一个额外的安全层和加密层。

## 启用 HTTPS

如今任何面向用户的应用程序不仅应该允许，还应该强制其用户通过 HTTPS 连接。这是一个在 HTTP 之上添加的安全层，确保所有连接都通过可信证书进行加密。 once again，我们不会尝试给出定义，而是使用以下来自 MDN 的定义([`developer.mozilla.org/en-US/docs/Glossary/https`](https://developer.mozilla.org/en-US/docs/Glossary/https)):

"HTTPS（安全超文本传输协议）是 HTTP 协议的加密版本。 它使用 SSL 或 TLS 来加密客户端和服务器之间的所有通信。 这条安全连接允许客户端安全地与服务器交换敏感数据，例如执行银行活动或在线购物时。"

通过在我们的应用程序中启用 HTTPS 连接，我们可以确保它更难拦截和解释请求。如果没有这个，恶意用户可以拦截登录请求，并获得用户的密码-用户名组合。我们在保护用户的敏感数据。

由于我们在应用程序中使用`oak`，我们将寻找一个解决方案，了解如何在它的文档中支持 HTTPS 连接。通过查看`doc.deno.land/https/deno.land/x/oak@v6.3.1/mod.ts`，我们可以看到`Application.listen`方法接收一个`configuration`对象，与我们之前用来发送`port`变量的对象相同。 还有一些其他选项，正如我们在这里看到的：`doc.deno.land/https/deno.land/x/oak@v6.3.1/mod.ts#Application`。 我们将使用它来启用 HTTPS。

让我们看看如何通过以下步骤更改`oak`的配置，以便它支持安全连接：

1.  打开`src/web/index.ts`，并在`listen`方法调用中添加`secure`、`keyFile`和`certFile`选项，如下所示：

    ```js
    await app.listen({
      port,
    certFile and keyFile properties expect a path to the certificate and the key files. If you don't have a certificate or you don't know how to create a self-signed one, no worries. Since this is only for learning purposes, you can use ours from the book's files at [`github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter07/sections/1-enabling-cors-and-https/museums-api`](https://github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter07/sections/1-enabling-cors-and-https/museums-api). Here, you'll find `certificate.pem` and `key.pem` files that you can download and use. You can download them wherever you want in your computer, but we'll assume they're at the project root folder (`museums-api`) in the next code samples.
    ```

1.  为了保持我们的代码整洁且更可配置，让我们提取这些选项并将它们作为参数发送到`createServer`函数中，如下所示：

    ```js
    export async function createServer({
      configuration: {
        …
        secure,
        keyFile,
        certFile,
      },
      …
    }: CreateServerDependencies) {
    ```

1.  这是`CreateServerDependencies`参数类型应该的样子：

    ```js
    interface CreateServerDependencies {
      configuration: {
        port: number,
        authorization: {
          key: string,
          algorithm: Algorithm
        },
        allowedOrigins: string[],
        secure: boolean,
        keyFile: string,
        certFile: string
      },
      museum: MuseumController,
      user: UserController
    }
    ```

1.  这就是之后的`createServer`函数的样子，带有解构的参数：

    ```js
    export async function createServer({
      configuration: {
        port,
        authorization,
        allowedOrigins,
        secure,
        keyFile,
        certFile,
      },
      museum,
      user
    }: CreateServerDependencies) {
    …
    await app.listen({
      port,
      secure,
      keyFile,
      certFile
    });
    ```

1.  最后，我们将从`src/index.ts`文件发送证书和密钥文件的路径，如下所示：

    ```js
    createServer({
      configuration: {
        port: 8080,
        authorization: {
          key: authConfiguration.key,
          algorithm: authConfiguration.algorithm
        },
        allowedOrigins: ['http://localhost:3000'],
        secure: true,
        certFile: './certificate.pem',
        keyFile: './key.pem'
      },
      museum: museumController,
      user: userController
    })
    ```

    现在，为了保持日志的准确性，我们需要修复我们之前创建的日志程序，该程序记录应用程序正在运行。这个处理程序现在应该考虑到应用程序可能通过 HTTP 或 HTTPS 运行，并相应地记录。

1.  回到`src/web/index.ts`，修复监听`listen`事件的监听器，使其检查连接是否安全。这段代码如下：

    ```js
      app.addEventListener('listen', e => {
        console.log(`Application running at 
          ${e.secure ? 'https' : 'http'}://${e.hostname ||
            'localhost'}:${port}`)
      })
    ```

1.  让我们运行这个应用程序，看看它是否工作：

    ```js
    $ deno run --allow-net --unstable --allow-env --allow-read --allow-plugin src/index.ts
    Application running at https://localhost:8080
    ```

你现在应该能够访问该 URL 并连接到应用程序。

你可能仍然会看到安全警告，但不用担心。你可以点击**高级**和**继续访问 localhost (不安全)**，如图所示：

![Figure 7.2 – Chrome 安全警告屏幕](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/deno-web-dev/img/Figure_7.2_B16380.jpg)

Figure 7.2 – Chrome 安全警告屏幕

这是由于证书是自签名的，并没有被可信任的证书机构签名。然而，这并不会有很大影响，因为过程与生产证书完全相同。

如果你仍然有问题，你可能需要直接访问 API URL，然后打开这个页面（`https://localhost:8080/`）。从那里，你可以按照以下链接（https://jasonmurray.org/posts/2021/thisisunsafe/)的程序，启用与不使用可信任证书的 API 的通信。之后，访问`https://localhost:8080`就会正常工作。

一旦你有一个合适的证书，由可信任的证书机构签名，你可以像我们这样使用它，一切都会正常工作。

这部分就到这里！我们向现有应用程序添加了 CORS 和 HTTPS 支持，提高了其安全性。

在下一节中，我们将了解如何从我们的代码中提取配置和密钥，使其从外部更加灵活和可配置。

出发吧！

# 提取配置和密钥

任何应用，无论其规模如何，都会有配置参数。通过查看我们在前几章中构建的应用程序，即使我们看最简单的版本——*Hello World* Web 服务器——我们也会发现配置值，如`port`值。

同时，我们发送一个名为`configuration`的完整对象到`createServer`函数中，该函数用于启动 Web 服务器。同时，我们还有一些知道应该是密钥的值。它们目前保存在代码库中，因为这对于我们的目的（学习）来说是可行的，但我们希望改变它。

我们考虑的东西比如**JSON Web Token**（**JWT**）加密密钥，或者 MongoDB 的凭据。这些绝对不是你想放进你的版本控制系统的东西。这一节就是讲这个。

我们将查看当前存储在代码库中的配置值和秘密。我们将提取它们，以便它们可以保持机密，并且只在应用程序运行时传递给应用程序。

进行这个过程可能在应用程序中配置值分散在多个模块和文件时是一项艰巨的工作。然而，由于我们遵循一些架构最佳实践，并考虑保持代码解耦和可配置，我们使自己的生活变得稍微容易了一些。

通过查看`src/index.ts`，你可以确认我们正在使用的所有配置值和秘密都存储在那里。这意味着所有其他模块都不知道配置，这才是正确的做法。

我们将分两个阶段进行这个“迁移”。首先，我们将所有配置值提取到一个`configuration`模块中，然后我们将提取秘密。

## 创建配置文件

首先，让我们找出代码中哪些硬编码值应该存储在配置文件中。以下代码片段突出了我们不想在代码中存储的值：

```js
client.connectWithUri("mongodb+srv://deno-
  api:password@denocluster.wtit0.mongodb.net/
    ?retryWrites=true&w=majority")
const db = client.database("getting-started-with-deno");
…
const authConfiguration = {
  algorithm: 'HS512' as Algorithm,
  key: 'my-insecure-key',
  tokenExpirationInSeconds: 120
}
createServer({
  configuration: {
    port: 8080,
    authorization: {
      key: authConfiguration.key,
      algorithm: authConfiguration.algorithm
    },
    allowedOrigins: ['http://localhost:3000'],
    secure: true,
    certFile: './certificate.pem',
    keyFile: './key.pem'
  },
…
```

通过查看我们应用程序代码中的这段代码，我们可以 already 识别出一些东西，如下所示：

+   集群 URL 和数据库名称（用户名和密码是秘密）

+   JWT 算法和过期时间（密钥是秘密）

+   Web 服务器端口

+   CORS 允许的源

+   HTTPS 证书和密钥文件路径

这里是我们将要提取的元素。我们将从创建包含所有这些值的我们的配置文件开始。

我们将使用**YAML Ain't Markup Language**（**YAML**），因为这是一种常用于配置的文件类型。如果你不熟悉它，不用担心——它是相当简单的。你可以在官方网站上获得它的工作方式的概述，网址为：[`yaml.org/`](https://yaml.org/)。

我们还将确保为不同的环境有不同的配置文件，从而创建一个以环境名命名的文件。

接下来，我们将实现一个功能，允许我们将配置存储在文件中，首先创建文件本身，如下所示：

1.  在项目的根目录下创建一个`config.dev.yaml`文件，并添加所有配置，像这样：

    ```js
    web:
      port: 8080
    cors:
      allowedOrigins:
        - http://localhost:3000
    https:
      key: ./key.pem
      certificate: ./certificate.pem
    jwt:
      algorithm: HS512
      expirationTime: 120
    mongoDb:
      clusterURI: deno-cluster.wtit0.mongodb.net/
        ?retryWrites=true&w=majority
      database: getting-started-with-deno
    ```

    我们现在需要一种将此文件加载到我们应用程序中的方法。为此，我们将在`src`文件夹中创建一个名为`config`的模块。

    为了读取配置文件，我们将使用我们在第二章*《工具链》*中学到的文件系统函数，以及 Deno 标准库中的`encoding`包。

1.  在`src`目录下创建一个名为`config`的文件夹，并在其中创建一个名为`index.ts`的文件。

    在这里，我们将定义一个名为`load`的函数，并将其导出。这个函数将负责加载配置文件。这段代码展示了这个功能：

    ```js
    export async function load() {
    }
    ```

1.  由于我们使用 TypeScript，我们将定义将成为我们配置文件的类型，并将其作为`load`函数的返回类型。这应该与之前创建的配置文件的结构相匹配。这段代码如下所示：

    ```js
    import type { Algorithm } from "../deps.ts";
    type Configuration = {
      web: {
        port: number
      },
      cors: {
        allowedOrigins: string[],
      },
      https: {
        key: string,
        certificate: string
      },
      jwt: {
        algorithm: Algorithm,
        expirationTime: number
      },
      mongoDb: {
        clusterURI: string,
        database: string
      },
    }
    export async function load(): Promise<Configuration> {
    …
    ```

1.  在`load`函数内部，我们现在应该尝试加载我们之前创建的配置文件，通过使用 Deno 文件系统 API。由于根据环境可能会有多个文件，我们还将`env`作为`load`函数的参数，默认值为`dev`，如下所示：

    ```js
    export async function load(env = 'dev'):
      Promise<Configuration> {
      Object so that we can access it. For this, we'll use the YAML encoding functionality from the standard library.
    ```

1.  从 Deno 标准库安装 YAML 编码器模块，使用`deno cache`确保我们更新`lock`文件（参考第三章，*运行时和标准库*），并在`src/deps.ts`中导出，如下所示：

    ```js
    export { parse } from
      "https://deno.land/std@0.71.0/encoding/yaml.ts"
    ```

1.  在`src/config/index.ts`中导入它，并使用它解析读取文件的 contents，如下所示：

    ```js
    import { Algorithm, parse } from "../deps.ts";
    …
    export async function load(env = 'dev'):
      Promise<Configuration> {
      src/index.ts and do it.
    ```

1.  导入`config`模块，调用其`load`函数，并使用之前硬编码的配置值。

    这是之后`src/index.ts`文件应该的样子：

    ```js
    import { load as loadConfiguration } from
      './config/index.ts';
    const config = await loadConfiguration();
    …
    client.connectWithUri(`mongodb+srv://
      deno-api:password @${config.mongoDb.clusterURI}`);
    …
    const authConfiguration = {
      algorithm: config.jwt.algorithm,
      key: 'my-insecure-key',
      tokenExpirationInSeconds: config.jwt.expirationTime
    }
    …
    createServer({
      configuration: {
        port: config.web.port,
        authorization: {
          key: authConfiguration.key,
          algorithm: authConfiguration.algorithm,
        },
        allowedOrigins: config.cors.allowedOrigins,
        secure: true,
        certFile: config.https.certificate,
        keyFile: config.https.key
      },
    …
    ```

    现在我们应该能够像之前一样运行我们的应用程序，区别在于我们所有的配置现在都存放在一个单独的文件中。

关于配置就这些！我们将配置从代码中提取到`config`文件中，使它们更容易阅读和维护。我们还创建了一个模块，它抽象了所有配置文件的读取和解析，确保应用程序的其余部分不关心这一点。

接下来，我们将学习如何扩展这个`config`模块，以便它还包括从环境变量中读取的机密值。

## 访问秘密值

如我之前提到的，我们使用了一些应该保密的值，但我们最初把它们放在了代码里。这些值可能会因环境而异，我们想将配置作为机密信息出于安全原因。这个要求使得它们不可能被检出到版本控制中，因此它们必须存在于其他地方。

一个常见的做法是使用环境变量获取这些值。Deno 提供了一个 API，我们将使用它来读取环境变量。我们将扩展`config`模块，使其在导出的`Configuration`对象类型中也包括机密值。

以下是仍然在代码中存在的应该保密的值：

+   MongoDB 用户名

+   MongoDB 密码

+   JWT 加密密钥

让我们将它们从代码中提取出来，并通过以下步骤将它们添加到`configuration`对象中：

1.  在`src/config/index.ts`中，将 MongoDB 用户名和密码以及 JWT 密钥添加到配置中，如下所示：

    ```js
    type Configuration = {
      web: {…};
      cors: {…};
      https: {…};
      jwt: {
        algorithm: Algorithm;
        expirationTime: number;
        load function so that it extends the configuration object.
    ```

1.  在`configuration`对象中扩展`username`和`password`缺失的属性到`mongoDb`，以及在`jwt`上的`key`，如下所示：

    ```js
    export async function load(env = 'dev'):
      Promise<Configuration> {
      const configuration = parse(await Deno.readTextFile
        (`./config.${env}.yaml`)) as Configuration;
      return {
        ...configuration,
        mongoDb: {
          ...configuration.mongoDb,
          username: 'deno-api',
          password: 'password'
        },
        jwt: {
          ...configuration.jwt,
          key: 'my-insecure-key'
        }
      };
    }
    ```

    剩下要做的唯一事情就是从环境中获取这些值，而不是将它们硬编码在这里。我们将使用 Deno 的 API 来实现这一点，以便访问环境（https://doc.deno.land/builtin/stable#Deno.env）。

1.  使用`Deno.env.get`从环境中获取变量。我们还应该设置一个默认值，以防`env`变量不存在。代码如下：

    ```js
    export async function load(env = 'dev'):
     Promise<Configuration> {
      const configuration = parse(await Deno.readTextFile
       (`./config.${env}.yaml`)) as Configuration;
      return {
        ...configuration,
        mongoDb: {
          ...configuration.mongoDb,
          username: Deno.env.get
            ('MONGODB_USERNAME') ||'deno-api',
          password: Deno.env.get
            ('MONGODB_PASSWORD') || 'password'
        },
        jwt: {
          ...configuration.jwt,
          key: Deno.env.get('JWT_KEY') || 'insecure-key'
        }
      }
    }
    ```

1.  让我们回到`src/index.ts`，并使用我们刚刚添加到`configuration`对象中的密钥值，如下所示：

    ```js
    client.connectWithUri
    (`mongodb+srv://${--allow-env permission. Let's try it.Just make sure you add the username and password values you previously created. The code can be seen in the following snippet:
    ```

```js
$ MONGODB_USERNAME=add-your-username MONGODB_PASSWORD=add-your-password JWT_KEY=add-your-jwt-key deno run --allow-net --unstable --allow-env --allow-read --allow-plugin src/index.ts
Application running at https://localhost:8080
```

现在，如果我们尝试注册和登录，我们将验证一切是否正常工作。应用程序连接到 MongoDB，并正确地检索到 JWT 令牌——密钥正在工作！

给 Windows 用户的提示

在 Windows 系统中，您可以使用`set`命令（[`docs.microsoft.com/en-us/windows-server/administration/windows-commands/set_1`](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/set_1)）来设置环境变量。Windows 不支持内联设置环境变量，因此，您必须在运行 API 之前运行这些命令。在整个书中，我们将使用*nix 语法，但如果您使用 Windows，您必须使用`set`命令，如下面的代码所示。

以下是 Windows 系统的`set`命令：

```js
C:\Users\alexandre>set MONGODB_USERNAME=your-username
C:\Users\alexandre>set MONGODB_PASSWORD=your-password
C:\Users\alexandre>set JWT_KEY=jwt-key
```

我们刚刚成功将所有的配置和密钥从代码中提取出来！这一步通过将它们写入文件使配置更容易阅读和维护，通过将它们通过环境发送到应用程序来使密钥更加安全，而不是将它们放在代码库中。

我们正在接近一个可以在不同环境中轻松部署和配置的应用程序，我们将在第九章中介绍如何部署 Deno 应用程序。

在下一节中，我们将利用 Deno 的功能将代码打包成浏览器可用的格式，创建一个非常简单的 JavaScript 客户端，该客户端可以连接到 API。这个客户端随后可以被前端客户端使用，从而抽象出 HTTP 连接；它还将与 API 代码共享代码和类型。

加入我们吧！

# 在浏览器中运行 Deno 代码

我们在前一章中提到的一个事情，也是我们认为 Deno 的一个卖点，就是它对 ECMAScript6 的完全兼容。这使得 Deno 代码可以被编译并在浏览器中运行。这个编译是由 Deno 本身完成的，打包器包含在工具链中。

这个功能开启了一系列的可能性。其中很多是因为 API 和客户端之间可以共享代码，这是我们将在本节中探讨的。

我们将构建一个非常简单的 JavaScript 客户端来与刚刚构建的博物馆 API 进行交互。这个客户端然后可以被任何想要连接到 API 的浏览器应用程序使用。我们将在 Deno 中编写该客户端并将其捆绑，以便它可以被客户端使用，甚至可以由应用程序本身提供服务。

我们将要编写的客户端是一个非常基础的 HTTP 客户端，因此我们不会过多关注代码。我们这样做是为了展示如何复用 Deno 中的代码和类型来生成在浏览器上运行的代码。同时，我们也将解释将客户端及其 API 放在一起的一些优点。

让我们从创建一个名为`client`的新模块开始，如下所示：

1.  在`src`内部创建一个名为`client`的文件夹，在文件夹内部创建一个名为`index.ts`的文件。

1.  让我们创建一个名为`getClient`的导出方法，它应该返回具有`login`、`register`和`getMuseums`三个函数的 API 客户端实例。以下代码片段显示了此内容：

    ```js
    interface Config {
      baseURL: string;
    }
    export function getClient(config: Config) {
      return {
        login: () => null,
        register: () => null,
        getMuseums: () => null,
      };
    }
    ```

    注意我们是如何获取一个包含`baseURL`的`config`对象的。

1.  现在，只是实现 HTTP 逻辑以向 API 发送请求的问题。我们不会逐步指导如何实现这一点，因为这相当直接，但你可以访问书中的完整客户端文件([`github.com/PacktPublishing/Deno-Web-Development/blob/master/Chapter07/sections/3-deno-on-the-browser/museums-api/src/client/index.ts`](https://github.com/PacktPublishing/Deno-Web-Development/blob/master/Chapter07/sections/3-deno-on-the-browser/museums-api/src/client/index.ts)).

    `register`方法看起来会像这样：

    ```js
    import type { RegisterPayload, LoginPayload,
      UserDto  } from "../users/types.ts";
    …
    const headers = new Headers();
    headers.set("content-type", "application/json");
    …
    register: ({ username, password }: RegisterPayload):
      Promise<UserDto> => {
      return fetch(
        `${config.baseURL}/api/users/register`,
        {
          body: JSON.stringify({ username, password }),
          method: "POST",
          headers,
        },
      ).then((r) => r.json());
    },
    …
    ```

    注意我们是如何从`users`模块导入类型，并将它们添加到我们的应用程序中的。这会使我们的函数更加可读，并允许我们在使用 TypeScript 客户端编写测试时进行类型检查和补全。我们还创建了一个带有`content-type`头的对象，该对象将用于所有请求。

    通过创建一个 HTTP 客户端，我们可以自动处理诸如认证之类的任务。在这种情况下，我们的客户端可以在用户登录后自动保存令牌，并在未来的请求中发送它。

    这就是`login`方法的样子：

    ```js
    export function getClient(config: Config) {
      let token = "";
      …
      return {
        …
        login: (
          { username, password }: LoginPayload,
        ): Promise<{ user: UserDto; token: string }> => {
          return fetch(
            `${config.baseURL}/api/login`,
            {
              body: JSON.stringify({ username, password }),
              method: "POST",
              headers
            },
          ).then((response) => {
            const json = await response.json();
    token = json.token;
    return json;
          });
      },
    ```

它目前设置了客户端实例上的`token`变量。该令牌随后被添加到诸如`getMuseums`函数之类的认证请求中，如下所示：

```js
getMuseums: (): Promise<{ museums: Museum[] }> => {
  const authenticatedHeaders = new Headers();
authenticatedHeaders.set("authorization", `Bearer
  ${token}`);
  return fetch(
    `${config.baseURL}/api/users/register`,
    {
      headers: authenticatedHeaders,
    },
).then((r) => r.json());
},
```

创建客户端后，我们希望分发它。我们可以使用我们在第二章*中学习的 Deno 捆绑命令来做到这一点，《工具链》。

如果我们希望由我们的 Web 服务器提供服务，我们还可以通过添加一个处理我们客户端文件捆绑内容的服务器来完成。它看起来会像这样：

```js
apiRouter.get("/client.js", async (ctx) => {
    const {
      diagnostics,
      files,
    } = await Deno.emit(
      "./src/client/index.ts",
      { bundle: "esm" },
    );
    if (!diagnostics.length) {
      ctx.response.type = "application/javascript";
      ctx.response.body = files["deno:///bundle.js"];
      return;
    }
  });
```

你可能需要回到你的`.vscode/settings.json`文件，并启用`unstable`属性，这样它才能识别我们正在使用不稳定的 API。这在下述代码片段中有所展示：

```js
{
  …
  "deno.unstable": true
}
```

注意我们如何使用不稳定的`Deno.emit`API 并设置`content-type`为`application/javascript`。

然后，我们将 Deno 生成的文件（`deno:///bundle.js`）作为请求体发送。

这样，如果客户端对`/api/client.js`执行`GET`请求，它将打包并服务我们刚刚编写的客户端内容。最终结果将是一个打包的、与浏览器兼容的 JavaScript 文件，该文件可用于应用程序。

最后，我们将在一个 HTML 文件中使用这个客户端进行认证并从 API 获取博物馆信息。按照以下步骤进行：

1.  在项目的根目录下创建一个名为`index-with-client.html`的 HTML 文件，如下代码片段所示：

    ```js
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width,
          initial-scale=1.0" />
        <title>Testing client</title>
      </head>
      <body>
      </body>
    </html>
    ```

1.  创建一个`script`标签，并直接从 API URL 导入脚本，如下所示：

    ```js
    <script type="module">
      import { getClient } from
        "https://localhost:8080/api/client.js";
    </script>
    ```

1.  现在，只需使用我们构建的客户端。我们将使用它登录（使用你之前创建的用户）并获取博物馆列表。代码如下片段所示：

    ```js
     async function main() {
      const client = getClient
        ({ baseURL: "https://localhost:8080" });
      const username = window.prompt("Username");
      const password = window.prompt("Password");
      await client.login({ username, password });
      const { museums } = await client.getMuseums();
      museums.forEach((museum) => {
        const node = document.createElement("div");
        node.innerHTML = `${museum.name} –
          ${museum.description}`;
        document.body.appendChild(node);
      });
    }
    ```

    我们将在用户访问页面时使用`window.prompt`获取用户名和密码，然后使用这些数据登录并获取博物馆信息。在此之后，我们只需将其添加到**文档对象模型**（**DOM**）中，创建一个博物馆列表。

1.  让我们再次启动应用程序，如下所示：

    ```js
    $ MONGODB_USERNAME=deno-api MONGODB_PASSWORD=your-password deno run --allow-net --allow-env --unstable --allow-read --allow-plugin --allow-write src/index.ts
    Application running at https://localhost:8080
    ```

1.  然后，此次为前端应用程序提供服务，这次添加了`–cert`和`--key`标志，带有各自文件的路径，以使用 HTTPS 运行文件服务器，如下代码片段所示：

    ```js
    $ deno run --allow-net --allow-read https://deno.land/std@0.83.0/http/file_server.ts -p 3000 --host localhost --key key.pem --cert certificate.pem
    HTTPS server listening on https://localhost:3000/
    ```

1.  现在，我们可以访问 https://localhost:3000/index-with-client.html 的网页，输入用户名和密码，并在屏幕上获取博物馆列表，如下截图所示：

![图 7.3 – 使用 JavaScript 客户端从 API 获取数据的网页](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/deno-web-dev/img/Figure_7.3_B16380.jpg)

图 7.3 – 使用 JavaScript 客户端从 API 获取数据的网页

在上一步登录时，你需要使用一个之前在应用程序上注册的用户。如果你没有，你可以使用以下命令创建：

```js
$ curl -X POST -d'{"username": "your-username", "password": "your-password" }' -H 'Content-Type: application/json' https://localhost:8080/api/users/register
```

确保将`your-username`替换为所需的用户名，将`your-password`替换为所需的密码。

至此，我们关于在浏览器上使用 Deno 的部分就结束了！

我们刚刚所做的可以进一步探索，解锁大量的潜力；这只是适用于我们用例的快速示例。这种实践使得任何浏览器应用程序更容易与刚刚编写的应用程序集成。客户端无需处理 HTTP 逻辑，只需调用方法并接收其响应。正如我们所看到的，这个客户端还可以自动处理诸如认证和 cookies 等主题。

本节探讨了 Deno 所启用的一项功能：为浏览器编译代码。

我们在应用程序的上下文中应用了它，通过创建一个抽象了用户和 API 之间关系的 HTTP 客户端。这个特性可以用来做很多事情，目前正被用于在 Deno 内部编写前端 JavaScript 代码。

正如我们在第二章《工具链》中解释的那样，当我们为浏览器编写代码时，需要考虑的唯一事情就是不要使用`Deno`命名空间中的函数。遵循这些限制，我们可以非常容易地在 Deno 中使用其所有优势编写代码，并将其编译为 JavaScript 进行分发。

这只是一个非常具有前景特性的介绍。这个特性，就像 Deno 一样，还处于起步阶段，社区将会发现它有很多用途。现在你也有了这方面的认识，我相信你也会想出很多好主意。

# 总结

这是一个我们重点关注将应用程序实践带入可部署到生产环境状态的章节。我们首先探索了基本的安全实践，向 API 添加了 CORS 机制和 HTTPS。这两个功能几乎是任何应用程序的标准，在现有基础上提供了很大的安全性提升。

另外，考虑到应用程序的部署，我们还从代码库中抽象出了配置和机密信息。我们首先创建了一个抽象概念，它将处理配置，使配置不会分散，模块只需接收它们的配置值，而无需了解它们是如何加载的。然后，我们继续在我们的当前代码库中使用这些值，这实际上变得非常简单。这一步骤将配置值从代码中移除，并将它们移动到配置文件中。

完成配置后，我们使用了同样的抽象概念来处理应用程序中的机密信息。我们实现了一个功能，它从环境变量中加载值并将它们添加到应用程序配置中。然后，我们在需要的地方使用这些机密值，比如 MongoDB 凭据和令牌签名密钥。

我们通过探索 Deno 自第一天起就提供的可能性结束了这一章节：为浏览器打包代码。将这个特性应用到我们的应用程序上下文中，我们决定编写一个 JavaScript HTTP 客户端来连接到 API。

这一步骤探讨了 API 和客户端之间共享代码的潜力，解锁了无数的可能性。借助这个功能，我们探讨了如何在 Deno 的捆绑功能下，将文件在运行时编译并服务于用户。这个功能的部分优势也将在下一章中探讨，我们将为我们的应用程序编写单元和集成测试。其中一些测试将使用在这里创建的 HTTP 客户端，利用这种实践的一个巨大优势：客户端和服务器在同一个代码库中。

在下一章，我们将深入探讨测试。我们将为书中剩余部分编写的逻辑编写测试，从业务逻辑开始。我们将学习如何通过添加测试来提高代码库的可靠性，以及我们创建的层次结构和架构在编写它们时的关键性。我们将编写的测试从单元测试到集成测试，并探索它们适用的用例。我们将看到测试在编写新功能和维护旧功能方面所增加的价值。在这个过程中，我们将了解一些新的 Deno API。

代码编写完成的标准是测试是否完成，因此我们将编写测试来结束我们的 API。

让我们开始吧！


# 第三部分：测试与部署

在本节中，你将创建有意义的集成和单元测试，使应用程序能够增长，并将学习如何将 Deno 应用程序容器化并在云端部署。

本节包含以下章节：

+   第八章，[测试 – 单元和集成](https://epic.packtpub.com/index.php?module=oss_Chapters&action=DetailView&record=825fa87f-4618-2790-1a60-5f32422b4c47)

+   第九章，[部署 Deno 应用程序](https://epic.packtpub.com/index.php?module=oss_Chapters&action=DetailView&record=98b91ae7-2855-39f3-f6b4-5f32426d1b76)

+   第十章，[接下来做什么？](https://epic.packtpub.com/index.php?module=oss_Chapters&action=DetailView&record=6128cca6-e773-f0c6-9ca0-5f3242cf7f1e)


# 第八章：测试 – 单元和集成

代码在相应的测试编写完成后才会创建。既然你正在阅读这一章，那么我可以假设我们可以同意这个观点。然而，你可能想知道，为什么我们一个测试都没有编写呢？这是可以理解的。

我们选择不这样做，因为我们认为这会让内容更难吸收。由于我们希望你在构建应用程序的同时专注于学习 Deno，所以我们决定不这样做。第二个原因是，我们确实希望有一个完整的章节专注于测试；即这一章。

测试是软件生命周期中的一个非常重要的部分。它可以用来节省时间，明确需求，或者只是因为你希望在以后重新编写和重构时感到自信。无论动机是什么，有一点是肯定的：你会编写测试。我也真心相信测试在软件设计中扮演着重要的角色。容易测试的代码很可能容易维护。

由于我们非常倡导测试的重要性，所以我们不能不学习它就认为这是一本完整的 Deno 指南。

在这一章中，我们将编写不同类型的测试。我们将从单元测试开始，这对于开发者和维护周期来说是非常有价值的测试。然后，我们将进行集成测试，在那里我们将运行应用程序并对其执行几个请求。最后，我们将使用在前一章中编写的客户端。在这个过程中，我们将向之前构建的应用程序添加测试，一步一步地进行，并确保我们之前编写的代码正常工作。

本章还将展示我们在这本书的开始时做出的某些架构决策将如何得到回报。这将是介绍我们如何使用 Deno 及其工具链编写简单的模拟和干净、专注的测试的入门。

在这一章中，我们将介绍以下主题：

+   在 Deno 中编写你的第一个测试

+   编写集成测试

+   测试网络服务器

+   为应用程序创建集成测试

+   一起测试 API 和客户端

+   基准测试应用程序的部分

让我们开始吧！

## 技术要求

本章中将使用的代码可以在 [`github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter08/sections`](https://github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter08/sections) 找到。

# 在 Deno 中编写你的第一个测试

在我们开始编写测试之前，记住一些事情是很重要的。其中最重要的原因是，我们为什么要测试？

对于这个问题，可能会有多个答案，但大多数都会指向保证代码正在运行。你也可能说，你使用它们以便在重构时具有灵活性，或者你重视在实施时拥有短暂的反馈周期——我们可以同意这两点。由于我们在实现这些功能之前没有编写测试，所以后者对我们来说并不适用。

在本章中，我们将保持这些目标。在本节中，我们将编写我们的第一个测试。我们将使用在前几章中编写的应用程序并为其添加测试。我们将编写两种类型的测试：集成和单元测试。

集成测试将测试应用程序不同组件之间的交互。单元测试测试隔离的层。如果我们把它看作是一个光谱，那么单元测试更接近代码，而集成测试更接近用户。在用户端的尽头，还有端到端测试。这些测试通过模拟用户行为来测试应用程序，我们将在本章不涉及这些内容。

我们在开发实际应用程序时使用的部分模式，如依赖注入和控制反转，在测试时非常有用。由于我们的代码通过注入其所有依赖关系来开发，现在，只需在测试中模拟这些依赖关系即可。记住：易于测试的代码通常也易于维护。

我们首先要做的是为业务逻辑编写测试。目前，由于我们的 API 相当简单，所以它没有太多的业务逻辑。大部分都存在于`UserController`中，因为`MuseumController`非常简单。我们从后者开始。

为了在 Deno 中编写测试，我们需要使用以下内容：

+   在第二章，*工具链*中介绍的 Deno 测试运行器

+   来自 Deno 命名空间的`test`方法([`doc.deno.land/builtin/stable#Deno.test`](https://doc.deno.land/builtin/stable#Deno.test))

+   来自 Deno 标准库的断言方法(`doc.deno.land/https/deno.land/std@0.83.0/testing/asserts.ts`)

这些都是 Deno 的组成部分，由核心团队分发和维护。社区中还有许多其他可以在测试中使用的库。我们将使用 Deno 中提供的默认设置，因为它工作得很好，并允许我们编写清晰易读的测试。

让我们去学习我们如何定义一个测试！

## 定义测试

Deno 提供了一个定义测试的 API。这个 API，`Deno.test` ([`doc.deno.land/builtin/stable#Deno.test`](https://doc.deno.land/builtin/stable#Deno.test))，提供了两种不同的定义测试的方法。

其中一个是我们在第二章*中所展示的*，*工具链*，由两部分组成；也就是说，测试名称和测试函数。这可以在以下示例中看到：

```js
Deno.test("my first test", () => {})
```

我们可以这样做另一种方式是调用相同的 API，这次发送一个对象作为参数。 你可以发送函数和测试名称，以及几个其他选项，到这个对象，如你在以下示例中所见：

```js
Deno.test({
  name: "my-second-test",
  fn: () => {},
  only: false,
  sanitizeOps: true,
  sanitizeResources: true,
});
```

这些标志行为在文档中解释得非常清楚([`doc.deno.land/builtin/stable#Deno.test`](https://doc.deno.land/builtin/stable#Deno.test))，但这里有一个总结供您参考：

+   `only`：只运行设置为`true`的测试，并使测试套件失败，因此这应该只用作临时措施。

+   `sanitizeOps`：如果 Deno 的核心启动的所有操作都不成功，则测试失败。这个标志默认是`true`。

+   `sanitizeResources`：如果测试结束后仍有资源在运行，则测试失败（这可能表明内存泄漏）。这个标志确保测试必须有一个清理阶段，其中资源被停止，默认情况下是`true`。

既然我们知道了 API，那就让我们去编写我们的第一个测试——对`MuseumController`函数的单元测试。

## 对 MuseumController 的单元测试

在本节中，我们将编写一个非常简单的测试，它将只涵盖我们在`MuseumController`中编写的功能，不多不少。

它列出了应用程序中的所有博物馆，尽管目前它还没有做什么，只是作为`MuseumRepository`的代理工作。我们可以通过以下步骤创建这个简单功能的测试文件和逻辑：

1.  创建`src/museums/controller.test.ts`文件。

    测试运行器将自动将名称中包含`.test`的文件视为测试文件，以及其他在第二章《工具链》中解释的约定，*章节目录*.

1.  使用`Deno.test`([`doc.deno.land/builtin/stable#Deno.test`](https://doc.deno.land/builtin/stable#Deno.test))声明第一个测试：

    ```js
    Deno.test("it lists all the museums", async () => {});
    ```

1.  现在，从标准库中导出断言方法，并将其命名空间命名为`t`，这样我们就可以在测试文件中使用它们，通过在`src/deps.ts`中添加以下内容：

    ```js
    export * as t from
      "https://deno.land/std@0.83.0/testing/asserts.ts";
    ```

    如果您想了解标准库中可用的断言方法，请查看`doc.deno.land/https/deno.land/std@0.83.0/testing/asserts.ts`。

1.  现在，您可以使用标准库中的断言方法来编写一个测试，该测试实例化`MuseumController`并调用`getAll`方法：

    ```js
    import { t } from "../deps.ts";
    import { Controller } from "./controller.ts";
    Deno.test("it lists all the museums", async () => {
      const controller = new Controller({
    MuseumController and sending in a mocked version of museumRepository, which returns a static array. This is how we're sure we're testing only the logic inside MuseumController, and nothing more. Closer to the end of the snippet, we're making sure the getAll method's result is returning the museum being returned by the mocked repository. We are doing this by using the assertion methods we exported from the dependencies file.
    ```

1.  让我们运行测试并验证它是否正常工作：

    ```js
    $ deno test --unstable --allow-plugin --allow-env --allow-read –-allow-write --allow-net src/museums
    running 1 tests
    test it lists all the museums ... ok (1ms)
    test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out (1ms)
    ```

我们的第一个测试成功了！

注意测试输出如何列出测试的名称、状态以及运行所需的时间，同时还包括测试运行的摘要。

`MuseumController`内部的逻辑相当简单，因此这也一个非常简单的测试。然而，它隔离了控制器的行为，允许我们编写一个非常专注的测试。如果您对为应用程序的其他部分创建单元测试感兴趣，它们可以在本书的存储库中找到([`github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter08/sections/7-final-tested-version/museums-api`](https://github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter08/sections/7-final-tested-version/museums-api)).

在接下来的几节中，我们将编写更多有趣的测试。这些测试将教会我们如何检查应用程序不同模块之间的集成。

# 编写集成测试

我们在上一节创建的第一个单元测试依赖于仓库的模拟实例，以保证我们的控制器正在工作。这个测试在检测`MuseumController`中的错误时增加了很大的价值，但它在了解控制器是否与仓库良好工作时并不重要。

这就是集成测试的目的：它们测试多个组件如何相互集成。

在本节中，我们将编写一个集成测试，用于测试`MuseumController`和`MuseumRepository`。这些测试将紧密模仿应用程序运行时发生的情况，并有助于我们后来在检测这两个类之间的任何问题时提供帮助。

让我们开始：

1.  在`src/museums`中为这个模块的集成测试创建一个文件，称为`museums.test.ts`，并在其中添加第一个测试用例。

    它应该测试是否可以获取所有博物馆，这次使用仓库的实例而不是模拟的一个：

    ```js
    Deno.test("it is able to get all the museums from
      storage", async () => {});
    ```

1.  我们将首先实例化仓库并在其中添加几个测试用例：

    ```js
    import { t } from "../deps.ts";
    import { Controller, Repository } from "./index.ts";
    Deno.test("it is able to get all the museums from
      storage", async () => {
      const repository = new Repository();
      repository.storage.set("0", {
        description: "museum with id 0",
        name: "my-museum",
        id: "0",
        location: { lat: "123", lng: "321" },
      });
      repository.storage.set("1", {
        description: "museum with id 1",
        name: "my-museum",
        id: "1",
        location: { lat: "123", lng: "321" },
      });
    …
    ```

1.  现在我们已经有了一个仓库，我们可以用它来实例化控制器：

    ```js
    const controller = new Controller({ museumRepository:
      repository });
    ```

1.  现在我们可以编写我们的断言，以确保一切正常工作：

    ```js
    const allMuseums = await controller.getAll();
    t.assertEquals(allMuseums.length, 2);
    t.assertEquals(allMuseums[0].name, "my-museum", "has
      name");
    t.assertEquals(
      allMuseums[0].description,
      "museum with id 0",
      "has description",
    );
    t.assertEquals(allMuseums[0].id, "0", "has id");
    t.assertEquals(allMuseums[0].location.lat, "123", "has
      latitude");
    t.assertEquals(allMuseums[0].location.lng, "321", assertEquals, allowing us to get a proper message when this assertion fails. This is something that all assertion methods support.
    ```

1.  让我们运行测试并查看结果：

    ```js
    $ deno test --unstable --allow-plugin --allow-env --allow-read –-allow-write --allow-net src/museums
    running 2 tests
    test it lists all the museums ... ok (1ms)
    test it is able to get all the museums from storage ... ok (1ms)
    test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out (2ms)
    ```

它通过了！这就是我们需要的仓库和控制器集成测试的全部！当我们要更改`MuseumController`或`MuseumRepository`中的代码时，这个测试很有用，因为它确保它们在一起工作时没有问题。

如果你对应用程序其他部分的集成测试如何工作感到好奇，我们在这本书的仓库中提供了它们([`github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter08/sections/7-final-tested-version/museums-api`](https://github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter08/sections/7-final-tested-version/museums-api)).

在第一部分，我们创建了一个单元测试，在这里，我们创建了一个集成测试，但我们还没有为应用程序的界面编写任何测试——Web 部分，它使用 HTTP。那就是我们下一节要做的。我们将学习如何孤立地测试 Web 层中的逻辑，不使用任何其他模块。

# 测试 Web 服务器

到目前为止，我们已经学习了如何测试应用程序的不同部分。我们始于业务逻辑，它测试如何与与持久性（仓库）交互的模块集成，但 Web 层仍然没有测试。

确实，那些测试非常重要，但我们可以说，如果 Web 层失败，用户将无法访问任何逻辑。

这就是我们将在本节中做的事情。我们将启动我们的 web 服务器，模拟其依赖项，并向其发送几个请求以确保 web*单元*正在工作。

让我们通过以下步骤创建 web 模块的单元测试：

1.  前往`src/web`，并创建一个名为`web.test.ts`的文件。

1.  现在，为了测试 web 服务器，我们需要回到`src/web/index.ts`中的`createServer`函数，并导出它创建的`Application`对象：

    ```js
    const app = new Application();
    …
    return { app };
    ```

1.  我们还希望能够在任何时候停止应用程序。我们还没有实现这一点。

    如果我们查看 oak 的文档，我们会看到它非常完善([`github.com/oakserver/oak#closing-the-server`](https://github.com/oakserver/oak#closing-the-server))。

    要取消由`listen`方法启动的应用程序，我们还需要返回`AbortController`。所以，让我们在`createServer`函数的最后这样做。

    如果你不知道`AbortController`是什么，我将留下一个来自 Mozilla 开发者网络的链接([`developer.mozilla.org/en-US/docs/Web/API/AbortController`](https://developer.mozilla.org/en-US/docs/Web/API/AbortController)),它解释得非常清楚。简而言之，它允许我们取消一个进行中的承诺：

    ```js
    const app = new Application();
    …
    const controller = new AbortController();
    const { signal } = controller;
    …
    return { app, controller };
    ```

    注意我们是如何实例化`AbortController`的，与文档中的示例类似，并在最后返回它，以及`app`变量。

1.  回到我们的测试中，让我们创建一个测试，以检查服务器是否响应`hello world`：

    ```js
    Deno.test("it responds to hello world", async () => {})
    ```

1.  让我们用之前创建的函数来启动服务器的实例；也就是说，`createServer`。记住，要调用这个函数，我们必须发送它的依赖项。在这里，我们需要模拟它们：

    ```js
    import { Controller as UserController } from
      "../users/index.ts";
    import { Controller as MuseumController } from
      "../museums/index.ts";
    import { createServer } from "./index.ts";
    …
    const server = await createServer({
      configuration: {
        allowedOrigins: [],
        authorization: {
          algorithm: "HS256",
          key: "abcd",
        },
        certFile: "",
        keyFile: "",
        port: 9001,
        secure: false,
      },
    9001 and with HTTPS disabled, along with some random algorithm and key.Note how we're using TypeScript's `as` keyword to pass mocked types into the `createServer` function without TypeScript warning us about the type.
    ```

1.  现在我们可以创建一个测试，通过响应 hello world 请求来检查 web 服务器是否正常工作：

    ```js
    import { t } from "../deps.ts";
    …
    const response = await fetch(
      "http://localhost:9001/",
      {
        method: "GET",
      },
    ).then((r) => r.text());
    t.assertEquals(
      response,
      "Hello World!",
      "responds with hello world",
    );
    ```

1.  我们需要做的最后一件事是在测试运行后关闭服务器。Deno 默认让我们测试失败，如果我们不做这件事（因为`sanitizeResources`默认是`true`），这可能会导致内存泄漏：

    ```js
      server.controller.abort();
    ```

这标志着我们 web 层的第一个测试结束！这是一个单元测试，它测试了启动服务器的逻辑，并确保 Hello World 运行正常。接下来，我们将为端点编写更完整的测试，包括业务逻辑。

在下一节中，我们将开始为登录和注册功能编写集成测试。这些测试比我们为博物馆模块编写的测试要复杂一些，因为它们将测试整个应用程序，包括其业务逻辑、持久性和 web 逻辑。

# 为应用程序创建集成测试

我们迄今为止编写的三个测试都是针对单一模块的单元测试以及两个不同模块之间的集成测试。然而，为了确信我们的代码正在工作，如果我们可以测试整个应用程序的话，那将会很酷。那就是我们在这里要做的。我们将用测试配置设置我们的应用程序，并对它运行一些测试。

我们首先调用用于初始化 Web 服务器的同一个函数，然后创建所有其依赖项（控制器、存储库等）的实例。我们会确保使用诸如内存持久化之类的东西来做到这一点。这将确保我们的测试是可复制的，并且不需要复杂的拆卸阶段或连接到真实数据库，因为这将减慢测试速度。

我们将从创建一个测试文件开始，这个文件现在将包含整个应用程序的集成测试。随着应用程序的发展，可能很有必要在每个模块内部创建一个测试文件夹，但现在，这个解决方案将完全没问题。

我们将使用与生产环境中运行的非常接近的设置实例化应用程序，并对它进行一些请求和断言：

1.  创建`src/index.test.ts`文件，与`src/index.ts`文件并列。在它里面，创建一个测试声明，测试用户是否可以登录：

    ```js
    Deno.test("it returns user and token when user logs
      in", async () => {})
    ```

1.  在我们开始编写这个测试之前，我们将创建一个帮助函数，该函数将为测试设置 Web 服务器。它将包含实例化控制器和存储库的所有逻辑，以及向应用程序发送配置。它看起来像这样：

    ```js
    import { CreateServerDependencies } from
      "./web/index.ts";
    …
    function createTestServer(options?: CreateServerDependencies) {
      const museumRepository = new MuseumRepository();
      const museumController = new MuseumController({
        museumRepository });
      const authConfiguration = {
        algorithm: "HS256" as Algorithm,
        key: "abcd",
        tokenExpirationInSeconds: 120,
      };
      const userRepository = new UserRepository();
      const userController = new UserController(
        {
          userRepository,
          authRepository: new AuthRepository({
            configuration: authConfiguration,
          }),
        },
      );
      return createServer({
        configuration: {
          allowedOrigins: [],
          authorization: {
            algorithm: "HS256",
            key: "abcd",
          },
          certFile: "abcd",
          keyFile: "abcd",
          port: 9001,
          secure: false,
        },
        museum: museumController,
        user: userController,
        ...options,
      });
    }
    ```

    我们在这里所做的是非常类似于我们在`src/index.ts`中做的布线逻辑。唯一的区别是，我们将显式导入内存存储库，而不是 MongoDB 存储库，如下面的代码块所示：

    ```js
    import {
      Controller as MuseumController,
      InMemoryRepository as MuseumRepository,
    } from "./museums/index.ts";
    import {
      Controller as UserController,
      InMemoryRepository as UserRepository,
    } from "./users/index.ts";
    ```

    为了让我们能够访问`Museums`和`Users`模块的内存存储库，我们需要进入这些模块并将它们导出。

    这就是`src/users/index.ts`文件应该看起来像的样子：

    ```js
    export { Repository } from "./repository/mongoDb.ts";
    Repository but also exporting InMemoryRepository at the same time.Now that we have a way to create a test server instance, we can go back to writing our tests.
    ```

1.  使用我们刚刚创建的帮助函数`createTestServer`创建一个服务器实例，并使用`fetch`向 API 发送注册请求：

    ```js
    Deno.test("it returns user and token when user logs
      in", async () => {
      const jsonHeaders = new Headers();
      jsonHeaders.set("content-type", "application/json");
      const server = await createTestServer();
      // Registering a user
      const { user: registeredUser } = await fetch(
        "http://localhost:9001/api/users/register",
        {
          method: "POST",
          headers: jsonHeaders,
          body: JSON.stringify({
            username: "asantos00",
            password: "abcd",
          }),
        },
      ).then((r) => r.json())
    …
    ```

1.  由于我们可以访问注册的用户，我们可以尝试使用同一个用户登录：

    ```js
      // Login in with the createdUser
      const response = await
        fetch("http://localhost:9001/api/login", {
          method: "POST",
          headers: jsonHeaders,
          body: JSON.stringify({
          username: registeredUser.username,
          password: "abcd",
        }),
      }).then((r) => r.json())
    ```

1.  我们现在准备开发一些断言来检查我们的登录响应是否是我们预期的那样：

    ```js
      t.assertEquals(response.user.username, "asantos00",
        "returns username");
      t.assert(!!response.user.createdAt, "has createdAt
        date");
      t.assert(!!response.token, "has token");
    ```

1.  最后，我们需要在我们的服务器上调用`abort`函数：

    ```js
    server.controller.abort();
    ```

这是我们第一次进行应用程序集成测试！我们让应用程序运行起来，对它执行注册和登录请求，并断言一切按预期进行。在这里，我们逐步构建了测试，但如果你想要查看完整的测试，它可在本书的 GitHub 仓库中找到（[`github.com/PacktPublishing/Deno-Web-Development/blob/master/Chapter08/sections/7-final-tested-version/museums-api/src/index.test.ts`](https://github.com/PacktPublishing/Deno-Web-Development/blob/master/Chapter08/sections/7-final-tested-version/museums-api/src/index.test.ts)）。

为了结束本节，我们将再写一个测试。还记得在前一章节中，我们创建了一些授权逻辑，只允许已登录的用户访问博物馆列表吗？让我们用另一个测试来检查这个逻辑是否生效：

1.  在`src/index.test.ts`中创建另一个测试，用于检测带有有效令牌的用户是否可以访问博物馆列表：

    ```js
    Deno.test("it should let users with a valid token
      access the museums list", async () => {})
    ```

1.  由于我们想要再次登录和注册，我们将提取这些功能到一个我们可以用于多个测试的实用函数中：

    ```js
    function register(username: string, password: string) {
      const jsonHeaders = new Headers();
      jsonHeaders.set("content-type", "application/json");
      return
       fetch("http://localhost:9001/api/users/register", {
         method: "POST",
         headers: jsonHeaders,
         body: JSON.stringify({
          username,
          password,
        }),
      }).then((r) => r.json());
    }
    function login(username: string, password: string) {
      const jsonHeaders = new Headers();
      jsonHeaders.set("content-type", "application/json");
      return fetch("http://localhost:9001/api/login", {
        method: "POST",
        headers: jsonHeaders,
        body: JSON.stringify({
          username,
          password,
        }),
      }).then((r) => r.json());
    }
    ```

1.  有了这些函数，我们现在可以重构之前的测试，使其看起来更简洁，如下面的代码段所示：

    ```js
    Deno.test("it returns user and token when user logs
      in", async () => {
      const jsonHeaders = new Headers();
      jsonHeaders.set("content-type", "application/json");
      const server = await createTestServer();
      // Registering a user
      await register("test-user", "test-password");
      const response = await login("test-user", "test-
      password");
      // Login with the created user
      t.assertEquals(response.user.username, "test-user",
        "returns username");
      t.assert(!!response.user.createdAt, "has createdAt
        date");
      t.assert(!!response.token, "has token");
      server.controller.abort();
    });
    ```

1.  让我们回到我们正在编写的测试——那个检查已认证用户是否可以访问博物馆的测试——并使用`register`和`login`函数来注册和认证一个用户：

    ```js
    Deno.test("it should let users with a valid token
      access the museums list", async () => {
      const jsonHeaders = new Headers();
      jsonHeaders.set("content-type", "application/json");
      const server = await createTestServer();
      // Registering a user
      await register("test-user", "test-password");
      const { token } = await login("test-user", "test-
        password");
    ```

1.  现在，我们可以使用`login`函数返回的令牌，在`Authorization`头中进行认证请求：

    ```js
      const authenticatedHeaders = new Headers();
      authenticatedHeaders.set("content-type",
        "application/json");
      login function and sending it with the Authorization header in the request to the museums route. Then, we're checking if the API responds correctly to the request with the 200 OK status code. In this case, since our application doesn't have any museums, it is returning an empty array, which we're also asserting.Since we're testing this authorization feature, we can also test that a user with no token or an invalid token can't access this same route. Let's do it.
    ```

1.  创建一个测试，检查用户是否可以在没有有效令牌的情况下访问`museums`路由。它应该与之前的测试非常相似，只是我们现在发送一个无效的令牌：

    ```js
    Deno.test("it should respond with a 401 to a user with
      an invalid token", async () => {
      const server = await createTestServer();
      const authenticatedHeaders = new Headers();
      authenticatedHeaders.set("content-type",
        "application/json");
    authenticatedHeaders.set("authorization", 
       `Bearer invalid-token`);
      const response = await
        fetch("http://localhost:9001/api/museums", {
          headers: authenticatedHeaders,
          body: JSON.stringify({
          username: "test-user",
          password: "test-password",
        }),
      });
      t.assertEquals(response.status, 401);
      t.assertEquals(await response.text(),
       "Authentication failed");
      server.controller.abort();
    });
    ```

1.  现在，我们可以运行所有测试并确认它们都通过了：

    ```js
    $ deno test --unstable --allow-plugin --allow-env --allow-read –-allow-write --allow-net src/index.test.ts      
    running 3 tests
    test it returns user and token when user logs in ... Application running at http://localhost:9001
    POST http://localhost:9001/api/users/register - 3ms
    POST http://localhost:9001/api/login - 3ms
    ok (24ms)
    test it should let users with a valid token access the museums list ... Application running at http://localhost:9001
    POST http://localhost:9001/api/users/register - 0ms
    POST http://localhost:9001/api/login - 1ms
    GET http://localhost:9001/api/museums - 8ms
    ok (15ms)
    test it should respond with a 400 to a user with an invalid token ... Application running at http://localhost:9001
    An error occurred Authentication failed
    ok (5ms)
    test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out (45ms)
    ```

本书中我们将要编写的应用程序集成测试就到这里为止！如果你想要了解更多，请不要担心——关于测试的所有代码都可在本书的 GitHub 仓库中找到（[`github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter08/sections/7-final-tested-version/museums-api`](https://github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter08/sections/7-final-tested-version/museums-api)）。

我们现在对代码的信心大大增强。我们创造了机会，可以在以后更少的担忧下重构、扩展和维护代码。在隔离测试代码方面，我们所做的架构决策越来越显示出其价值。

在上一章中，当我们创建我们的 JavaScript 客户端时，我们提到了将其保存在 API 代码库中的一个优点是，我们可以轻松地为客户端和 API 编写测试，以确保它们能很好地一起工作。在下一节中，我们将展示如何做到这一点。这些测试将与我们在这里所做的非常相似，唯一的区别是，我们使用的是我们创建的 API 客户端，而不是使用`fetch`进行原始请求。

# 与应用和 API 客户端一起测试

当你向用户提供 API 客户端时，你有责任确保它与你的应用程序完美配合。确保这种配合的一种方法是拥有一个完整的测试套件，不仅测试客户端本身，还测试它与 API 的集成。在这里我们将处理后者。

我们将使用 API 客户端的一个特性，并创建一个测试，确保它正在工作。再次，你会注意到这些测试与我们在上一部分末尾编写的测试有一些相似之处。我们将复制之前测试的逻辑，但这次我们将使用客户端。让我们开始吧：

1.  在同一个`src/index.test.ts`文件中，为登录功能创建一个新的测试：

    ```js
    Deno.test("it returns user and token when user logs in
      with the client", async () => {})
    ```

    为了这次测试，我们知道我们需要访问 API 客户端。我们需要从`client`模块中导入它。

1.  从`src/client/index.ts`导入`getClient`函数：

    ```js
    import { getClient } from "./client/index.ts"
    ```

1.  让我们回到`src/index.test.ts`测试，导入`client`，从而创建一个它的实例。记住，它应该使用测试网络服务器创建的相同地址：

    ```js
    Deno.test("it returns user and token when user logs in
      with the client", async () => {
      const server = await createTestServer();
      const client = getClient({
    createTestServer function and this test, but for simplicity, we won't do this here.
    ```

1.  现在，只需编写调用使用`client`的`register`和`login`方法的逻辑即可。最终测试将如下所示：

    ```js
    Deno.test("it returns user and token when user logs in
      with the client", async () => {
    …
      // Register a user
      await client.register(
        { username: "test-user", password: "test-password"
           },
      );
      // Login with the createdUser
      const response = await client.login({
        username: "test-user",
        password: "test-password",
      });
      t.assertEquals(response.user.username, "test-user",
        "returns username");
      t.assert(!!response.user.createdAt, "has createdAt
        date");
      t.assert(!!response.token, "has token");
    …
    });
    ```

    注意我们是如何使用客户端的方法进行登录和注册，同时保留来自先前测试的断言。

遵循相同的指南，我们可以为客户端的所有功能编写测试，确保它与 API 一起正常工作，从而使我们能够自信地维护它。

为了简洁起见，而且因为这些测试类似于我们之前编写的测试，我们在这里不会提供为客户端所有功能编写测试的逐步指南。然而，如果你感兴趣，你可以在本书的 GitHub 存储库中找到它们([`github.com/PacktPublishing/Deno-Web-Development/blob/master/Chapter08/sections/7-final-tested-version/museums-api/src/index.test.ts`](https://github.com/PacktPublishing/Deno-Web-Development/blob/master/Chapter08/sections/7-final-tested-version/museums-api/src/index.test.ts)).

在下一节中，我们将简要介绍一个可能位于应用程序路径末端的特性。总有一天，你会发现应用程序的某些部分似乎变得很慢，你希望追踪它们的性能，这时性能测试就派上用场了。因此，我们将引入基准测试。

# 基准测试应用程序的部分

当涉及到在 JavaScript 中编写基准测试时，该语言本身提供了一些函数，所有这些函数都包含在高级分辨率时间 API 中。

由于 Deno 完全兼容 ES6，这些相同的功能都可以使用。如果你有时间查看 Deno 的标准库或官方网站，你会发现人们对基准测试给予了大量的关注，并且跟踪了 Deno 各个版本中的基准测试([`deno.land/benchmarks`](https://deno.land/benchmarks))。在检查 Deno 的源代码时，你会发现有关如何编写它们的非常不错的示例集。

对于我们的应用程序，我们可以轻松地使用浏览器上可用的 API，但 Deno 本身在其标准库中提供了功能，以帮助编写和运行基准测试，因此我们将在这里使用它。

首先，我们需要了解 Deno 的标准库基准测试工具，这样我们才知道我们可以做什么（[`github.com/denoland/deno/blob/ae86cbb551f7b88f83d73a447411f753485e49e2/std/testing/README.md#benching`](https://github.com/denoland/deno/blob/ae86cbb551f7b88f83d73a447411f753485e49e2/std/testing/README.md#benching)）。在本节中，我们将使用两个可用的函数编写一个非常简单的基准测试；即`bench`和`runBenchmarks`。第一个将定义一个基准测试，而第二个将运行它并将结果打印到控制台。

记得我们在第五章《添加用户和迁移到 Oak》中写的函数吗？该函数用于生成一个散列和一个盐，使我们能够将用户凭据安全地存储在数据库上。我们将按照以下步骤为此编写一个基准测试：

1.  首先，在`src/users/util.ts`旁边创建一个名为`utilBenchmarks.ts`的文件。

1.  导入我们要测试的`util`中的两个函数，即`generateSalt`和`hashWithSalt`：

    ```js
    import { generateSalt, hashWithSalt } from "./util.ts"
    ```

1.  是时候将基准测试工具添加到我们的`src/deps.ts`文件中，并运行`deno cache`命令（我们在第二章《工具链》中了解到它），在此处导入它。我们将把它作为`benchmark`导出到`src/deps.ts`中，以避免命名冲突：

    ```js
    export * as benchmark from
      "https://deno.land/std@0.83.0/testing/bench.ts";
    ```

1.  将基准测试工具导入到我们的基准文件中，并为`generateSalt`函数编写第一个基准测试。我们希望它运行 1000 次：

    ```js
    import { benchmarks } from "../deps.ts";
    benchmarks.bench({
      name: "runsSaltFunction1000Times",
      runs: 1000,
      func: (b) => {
        bench function (as stated in the documentation). Inside this object, we're defining the number of runs, the name of the benchmark, and the test function. That function is what will run every time, since an argument is an object of the BenchmarkTimer type with two methods; that is, start and stop. These methods are used to start and stop the timings of the benchmarks, respectively.
    ```

1.  我们所缺少的就是在基准测试定义之后调用`runBenchmarks`：

    ```js
    benchmarks.bench({
      name: "runsSaltFunction1000Times",
      …
    });
    benchmarks.runBenchmarks();
    ```

1.  是时候运行这个文件并查看结果了。

    记住，由于我们希望我们的基准测试精确，所以我们正在处理高级分辨率时间。为了让这段代码访问这个系统特性，我们需要以`--allow-hrtime`权限运行这个脚本（如第二章《工具链》中所解释）：

    ```js
    $ deno run --unstable --allow-plugin --allow-env --allow-read --allow-write --allow-hrtime src/users/utilBenchmarks.ts
    running 1 benchmarks ...
    benchmark runsSaltFunction1000Times ...
        1000 runs avg: 0.036691561000000206ms
    benchmark result: DONE. 1 measured; 0 filtered
    ```

1.  让我们为第二个函数编写基准测试，即`hashWithSalt`：

    ```js
    benchmarks.bench({
      name: "runsHashFunction1000Times",
      runs: 1000,
      func: (b) => {
        b.start();
        hashWithSalt("password", "salt");
        b.stop();
      },
    });
    benchmarks.runBenchmarks();
    ```

1.  现在，让我们运行它，以便我们得到最终结果：

    ```js
    $ deno run --allow-hrtime --unstable --allow-plugin --allow-env –-allow-write --allow-read src/users/utilBenchmarks.ts     
    running 2 benchmarks ...
    benchmark runsSaltFunction100Times ...
        1000 runs avg: 0.036691561000000206ms
    benchmark runsHashFunction100Times ...
        1000 runs avg: 0.02896806399999923ms
    benchmark result: DONE. 2 measured; 0 filtered
    ```

就是这样！现在您可以随时使用我们刚刚编写的代码来分析这些函数的性能。您可能需要这样做，是因为您已经更改了此代码，或者只是因为您想对其进行严格跟踪。您可以将其集成到诸如持续集成服务器之类的系统中，这样您就可以定期检查这些值并保持其正常运行。

这部分结束了本书的基准测试部分。我们决定给它一个简短的介绍，并展示从 Deno 获取的哪些 API 可以促进基准测试需求。我们相信，这里介绍的概念和示例将允许您跟踪应用程序的运行情况。

# 总结

随着这一章的结束，我们已经完成了我们一直在构建的应用程序的开发周期。我们开始时编写了一些简单的类和业务逻辑，编写了 web 服务器，最后将其与持久化集成。我们通过学习如何测试我们编写的功能来结束这一部分，这就是我们在这章所做的。我们决定使用几种不同类型的测试，而不是深入每个模块编写所有测试，因为我们认为这样做会带来更多的价值。

我们首先为业务逻辑编写了一个非常简单的单元测试，然后进行了一个带有多个类的集成测试，后来编写了一个针对 web 服务器的测试。这些测试只能通过利用我们创建的架构、遵循依赖注入原则，并尽可能使代码解耦来编写。

随着章节的进展，我们转向了集成测试，这些测试紧密地模仿了将在生产环境中运行的队列应用程序，使我们能够提高对我们刚刚编写的代码的信心。我们创建了测试，这些测试通过测试环境实例化了应用程序，使我们能够启动带有所有应用程序层（业务逻辑、持久化和网络）的 web 服务器，并对它进行断言。在这些测试中，我们可以非常有信心地断言登录和注册行为是否正常工作，因为我们向 API 发送了真实的请求。

为了结束这一章，我们将它与前一章连接起来，我们在那一章为 API 编写了一个 JavaScript 客户端。我们利用了客户端与 API 位于同一代码库中的一个巨大优势，并一起测试了客户端及其应用程序。这是确保一切按预期工作，并在发布 API 和客户端更改时保持信心的一种很好的方式。

这一章节试图展示如何在 Deno 中使用测试来提高我们对所编写代码的信心，以及当它们用于关注简单结果时所体现的价值。这类测试在应用更改时将非常有用，因为我们可以使用它们来添加更多功能或改进现有功能。在这里，我们了解到 Deno 提供的测试套件足以编写清晰、可读的测试，而无需任何第三方包。

下一章节将关注应用开发过程中最重要的阶段之一，那就是部署。我们将配置一个非常简单的持续集成环境，在该环境中我们可以将应用部署到云端。这是一个非常重要的章节，因为我们还将体验到 Deno 在部署方面的某些优势。

迫不及待地想让你的应用供用户使用吗？我们也是——让我们开始吧！


# 第九章：部署 Deno 应用程序

部署是任何应用程序的关键部分。我们可能构建了一个伟大的应用程序，遵循最佳实践，并编写测试，但最终，当它到达用户手中时，它将在这里证明其价值。由于我们希望这本书能带领读者经历应用程序的所有不同阶段，因此我们将使用关于应用程序部署的这一章节来结束整个周期。

请注意，我们没有—也不会—将部署视为软件开发的最后阶段，而是视为将多次运行的周期中的一个阶段。我们坚信部署不应该是一个让大家害怕的事件。相反，我们认为它们是我们向用户发送功能的高兴时刻。这是大多数公司在现代软件项目中看待部署的方式，我们确实是这种观点的忠实倡导者。部署应该是定期、自动化且容易执行的事情。它们是我们将功能带给用户的第一步，而不是最后一步。

为了使流程具有这种灵活性并在应用程序中实现快速迭代，本章将重点学习有关容器以及如何使用它们部署 Deno 应用程序的知识。

我们将利用容器化的好处，创建一个隔离的环境来安装、运行和分发我们的应用程序。

随着章节的进行，我们将学习如何使用 Docker 和`git`创建一个自动化工作流程，以在云环境中部署我们的 Deno 应用程序。然后，我们将调整应用程序加载配置的方式，以支持根据环境不同而有不同的配置。

到本章结束时，我们的应用程序将在云环境中运行，并有一个自动化过程，使我们能够发送它的迭代版本。

在本章中，您将熟悉以下主题：

+   为应用程序准备环境

+   为 Deno 应用程序创建一个`Dockerfile`

+   在 Heroku 中构建和运行应用程序

+   配置应用程序以进行部署

# 技术要求

本章中使用的代码可以在以下 GitHub 链接中找到：

`https://github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter09`

# 为应用程序准备环境

应用程序运行的环境总是对其产生很大影响。这是导致常见说法“*在我的机器上工作*”的其中一个重要原因。多年来，开发者一直在创造尽可能减少这种影响的解决方案。这些解决方案可以从为应用程序自动提供新的干净实例，到创建更完整的包，其中包含应用程序依赖的一切。

我们可以将**虚拟机**（**VMs**）或容器视为实现这一目标的途径。两者都是为同一问题提供的不同解决方案，但有一个很大的共同点：资源隔离。两者都试图将应用程序与周围的环境隔离。这有许多原因，从安全、自动化到可靠性。

容器是提供应用程序包的一种现代方式。现代软件项目使用它们来提供一个包含应用程序运行所需的大多数内容的单一容器镜像。

如果你不清楚容器是什么，我给你提供一下来自 Docker（一个容器引擎）官方网站的定义：

容器是“一种标准的软件单元，它将代码及其所有依赖打包在一起，使得应用程序能够从一个计算环境快速、可靠地运行到另一个计算环境。”

在我们使应用程序容易部署的路径中，我们将使用 Docker 为我们的 Deno 应用程序创建这一层隔离。

最终目标是创建一个开发者可以用来部署和测试应用程序特定版本的镜像。要使用 Docker 完成这个目标，我们需要配置应用程序将运行的运行时。这个配置定义在一个叫做`Dockerfile`的文件中。

这是我们接下来要学习的内容。

# 为 Deno 应用程序创建 Dockerfile

`Dockerfile`将允许我们指定创建新 Docker 镜像所需的内容。这个镜像将提供包含应用程序所有依赖的环境，既可用于开发目的，也可用于生产部署。

在本节中，我们将学习如何为 Deno 应用程序创建 Docker 镜像。Docker 提供了一个基本上只包含容器运行时和隔离的基镜像，叫做`alpine`。我们可以使用这个镜像，配置它，安装所有需要的工具和依赖（即 Deno），等等。然而，我认为我们在这里不应该重新发明轮子，因此我们使用一个社区 Docker 镜像。

尽管这个镜像解决了许多我们的问题，我们仍然需要调整它以适应我们的用例。Dockerfile 可以组合，这意味着它们可以扩展其他 Docker 镜像的功能，我们将使用这个特性。

重要提示

如你所想象的，我们不会深入讲解 Docker 的基础知识，因为那将是一本书的内容。如果你对 Docker 感兴趣，你可以从官方文档的*入门指南*开始([`docs.docker.com/get-started/`](https://docs.docker.com/get-started/))。然而，如果你目前对 Docker 不是非常熟悉，也不用担心，我们会解释足够让你理解我们在这里做什么的内容。

在开始之前，请确保通过以下链接中列出的步骤在您的机器上安装了 Docker Desktop：[`docs.docker.com/get-docker/`](https://docs.docker.com/get-docker/)。安装并启动它之后，我们就有了创建我们第一个 Docker 镜像所需的一切。让我们通过以下步骤来创建它：

1.  在我们项目的根目录下创建一个`Dockerfile`。

1.  正如提到的，我们将使用一个社区中已经安装了 Deno 的镜像——`hayd/deno` ([`hub.docker.com/r/hayd/deno`](https://hub.docker.com/r/hayd/deno))。

    此图像的版本管理方式与 Deno 相同，因此我们将使用版本`1.7.5`。Docker 的`FROM`命令允许我们扩展一个镜像，指定其名称和版本标签，如下面的代码片段所示：

    ```js
    FROM hayd/alpine-deno:1.7.5
    ```

1.  我们需要做的下一件事是在容器内部定义我们将工作的文件夹。

    Docker 容器提供了一个 Linux 文件系统，默认的`workdir`是它的根（`/`）。Docker 的`WORKDIR`命令将允许我们在这个文件系统内的同一个文件夹中工作，使事情变得更有条理。该命令可在此处查看：

    ```js
    WORKDIR /app
    ```

1.  现在，我们需要将一些文件复制到我们的容器镜像中。在`COPY`命令的帮助下，我们将只复制安装步骤所需的文件。在我们的案例中，这些是`src/deps.ts`和`lock.json`文件，如下所示：

    ```js
    COPY command from Docker allows us to specify a file to copy from the local filesystem (the first parameter) into the container image (the last parameter), which is currently the app folder. By dividing our workflows and copying only the files we need, we allow Docker to cache and rerun part of the steps only when the involved files changed. 
    ```

1.  在容器内部拥有文件后，我们现在需要安装应用程序的依赖项。我们将使用`deno cache`来完成此操作，如下所示：

    ```js
    deno-mongo) and also using the lock file, we have to pass additional flags. Docker's `RUN` command enables us to run this specific command inside the container.
    ```

1.  依赖项安装完成后，我们现在需要将应用程序的代码复制到容器中。再一次，我们将使用 Docker 的`COPY`命令来完成此操作，如下所示：

    ```js
    workdir (/app folder) inside the container.
    ```

1.  我们需要为我们的镜像做最后一件事情，以便它能够即插即用，那就是引入一个在任何人都“执行”这个镜像时都会运行的命令。我们将使用 Docker 的`CMD`命令来完成此操作，如下所示：

    ```js
    CMD ["deno", "run", "--allow-net", "--unstable", "--allow-env", "--allow-read", "--allow-write", "--allow-plugin", "src/index.ts" ]
    ```

    这个命令接受一个命令和参数数组，当有人尝试运行我们的镜像时将被执行。

这就是我们定义我们 Deno 应用程序的 Docker 镜像所需要的一切！拥有这些功能将使我们可以像在生产环境中一样在本地上运行我们的代码，这对于调试和调查生产问题来说是一个很大的优势。

我们唯一缺少的是生成工件的实际步骤。

我们将使用 Docker `-t`标志的`build`命令来设置标签。按照以下步骤生成工件：

1.  在项目文件夹内，运行以下命令为镜像生成标签：

    ```js
    museums-api in this example) and choose whichever version you want (0.0.1 in the example).This should produce the following output:

    ```

    museums-api:0.0.1。我们现在可以在私有镜像仓库中发布它，或者使用公共的，比如 Docker Hub。我们稍后设置的持续集成（CI）管道将配置为自动执行这个构建步骤。我们现在可以做的就是在本地下载这个镜像，以验证一切是否按预期工作。

    ```js

    ```

1.  为了在本地运行镜像，我们将使用 Docker CLI 的`run`命令。

    由于我们正在处理一个网络应用程序，我们需要暴露它正在运行的端口（在应用程序的`configuration`文件中设置）。我们将通过使用`-p`标志告诉 Docker 将容器端口绑定到我们机器的端口，如下代码段所示：

    ```js
    0.0.1 of the museums-api image, binding the 8080 container port to the 8080 host port. We can now go to http://localhost:8080 and see that the application is running.
    ```

稍后，我们将使用这个镜像定义在 CI 系统中，每当代码更改时，它都会创建一个镜像并将其推送到生产环境。

拥有一个包含应用程序的 Docker 镜像可以服务于多个目的。其中之一就是本章的目标：部署它；然而，这个同样的 Docker 镜像也可以用来在特定版本上运行和调试一个应用程序。

让我们学习如何在特定版本的某个应用程序中运行一个终端，这是一个非常常见的调试步骤。

## 在容器内运行终端

我们可以使用 Docker 镜像在容器内执行一个终端。这可能在调试或尝试特定应用程序版本的某事物时很有用。

我们可以通过使用之前相同的命令和几个不同的标志来实现这一点。

我们将使用`-it`标志，这将允许我们有一个与镜像内的终端的交互式连接。我们还将发送一个参数，即我们希望在镜像内首先执行的命令的名称。在这个例子中是`sh`，标准的 Unix 外壳，正如你在以下示例中可以看到的：

```js
$ docker run -p 8080:8080 -it  museums-api:0.0.1 sh
```

这将运行`museums-api:0.0.1`镜像，将其`8080`端口绑定到宿主机的`8080`端口，并在带有交互式终端的其中执行`sh`命令，如下代码段所示：

```js
$ docker run -p 8080:8080 -it  museums-api:0.0.1 sh        
/app # ls
Dockerfile           certificate.pem      config.staging.yaml  index.html           lock.json
README.md            config.dev.yaml      heroku.yml        key.pem              src
```

请注意，初始打开的目录是我们定义为`WORKDIR`的目录，我们的所有文件都在那里。在前面的例子中，我们还执行了`ls`命令。

由于我们在这个容器上附加了一个交互式外壳，我们可以用它来运行 Deno 命令，例如，如下代码段所示：

```js
/app # deno --version
deno 1.7.2 (release, x86_64-unknown-linux-gnu)
v8 8.9.255.3
typescript 4.1.3 
/app #
```

这将使我们在开发和调试方面具备一整套可能性，因为我们将有能力查看应用程序在特定版本上的运行情况。

我们已经完成了这一节的讨论。在这里，我们探讨了容器化，介绍了 Docker 以及它是如何让我们创建一个“应用程序包”的。这个包将负责应用程序周围的环境，确保它无论在何处只要有 Docker 运行时就可以运行。

在下一节中，我们将使用这个相同的包，在云环境中部署我们本地构建的镜像。让我们开始吧！

# 在 Heroku 中构建和运行应用程序

正如我们在章节开始时提到的，我们的初步目标是有一种简单、自动化且可复制的部署应用程序的方法。在上一节中，我们创建了将作为该基础的容器镜像。下一步是创建一个管道，以便在有更新时构建和部署我们的代码。我们将使用`git`作为我们的真相来源和触发管道构建的机制。

我们将代码部署的平台是 Heroku。这是一个旨在通过提供一套工具简化开发人员和公司部署过程的平台，这些工具消除了诸如配置机器和设置大型 CI 基础架构等常见障碍。使用这样的平台，我们可以更专注于应用程序以及 Deno，这是本书的目的。

在这里，我们将使用我们之前创建的`Dockerfile`，并设置它在 Heroku 上部署并运行。我们将了解如何轻松地在那里设置应用程序，稍后我们还将探索如何通过环境变量定义配置值。

在开始之前，请确保您已经创建了账户并安装了 Heroku CLI，然后按照这里提供的两个链接进行步骤指南：

+   创建账户：[`signup.heroku.com/dc`](https://signup.heroku.com/dc)。

+   安装 CLI：[`devcenter.heroku.com/articles/heroku-cli`](https://devcenter.heroku.com/articles/heroku-cli)。

现在我们已经创建了账户并安装了 CLI，我们可以开始在 Heroku 上设置我们的项目。

## 在 Heroku 上创建应用程序

在这里，我们将了解在 Heroku 上进行身份验证并创建应用程序所需的步骤。我们几乎准备好了，但还有一件事我们必须先弄清楚。

重要提示

由于 Heroku 使用`git`作为真相来源，您将*无法*在书籍的文件仓库内执行以下过程，因为它已经是一个包含应用程序多个阶段的 Git 仓库。

我建议您将应用程序文件复制到另一个不同的文件夹中，*位于书籍仓库外部*，并从那里开始这个过程。

您可以从*第八章*，*测试 – 单元和集成*([`github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter08/sections/7-final-tested-version/museums-api`](https://github.com/PacktPublishing/Deno-Web-Development/tree/master/Chapter08/sections/7-final-tested-version/museums-api))复制最新版本的运行中应用程序，这是我们将在这里使用的版本。

现在文件已经被复制到了一个新的文件夹（主仓库外部），接下来通过以下步骤在 Heroku 上部署`Dockerfile`并运行它：

1.  我们首先要做的就是使用 CLI 登录，运行`heroku login`。这应该会打开一个浏览器窗口，您可以在其中输入您的用户名和密码，如下面的代码片段所示：

    ```js
    $ heroku login
    heroku: Press any key to open up the browser to login or q to exit:
    Opening browser to https://cli-auth.heroku.com/auth/cli/...
    Logging in... done
    Logged in as your-login-email@gmail.com
    ```

1.  由于 Heroku 部署是基于`git`的，而我们现在在一个不是 Git 仓库的文件夹中，我们需要初始化它，如下所示：

    ```js
    $ git init
    Initialized empty Git repository in /Users/alexandre/dev/ museums-api/.git/
    ```

1.  然后，我们通过使用`heroku create`来创建 Heroku 上的应用程序，如下所示：

    ```js
    heroku, which is where we have to push our code to trigger the deployment process.
    ```

如果您在运行前面的命令后访问 Heroku 仪表板，您会发现那里有一个新的应用程序。当应用程序创建时，Heroku 在控制台打印一个 URL；然而，由于我们还没有配置任何内容，我们的应用程序目前还不可用。

我们接下来需要做的是配置 Heroku，以便它在每次部署时知道它应该构建和执行我们的镜像。

## 构建和运行 Docker 镜像

默认情况下，Heroku 试图通过运行代码使您的应用程序可用。这对于许多语言来说都是可能的，您可以在 Heroku 文档中找到相关指南。由于我们想要使用容器来运行我们的应用程序，因此该过程需要一些额外的配置。

Heroku 提供了一组功能，允许我们定义当代码发生更改时会发生什么，通过一个名为`heroku.yml`的文件。我们现在将创建该文件，如下所示：

1.  在仓库根目录下创建一个`heroku.yml`文件，并添加以下代码行，以便使用我们在上一节中创建的`Dockerfile`使用 Docker 构建我们的镜像：

    ```js
    build:
      docker:
        web: Dockerfile
    ```

1.  现在，在同一个文件中，添加以下代码行以定义 Heroku 将执行以运行应用程序的命令：

    ```js
    build:
      docker:
        web: Dockerfile
    Dockerfile, and that's true. Normally, Heroku would run the command from the `Dockerfile` to execute the image, and it would work. It happens that Heroku doesn't run these commands as root, as a security best practice. Deno, at its current stage, needs root privileges whenever you want to use plugins (an unstable feature). As our application is using a plugin to connect with MongoDB, we need this command to be explicitly defined on `heroku.yml` so that it is run with root privileges and works when Deno is starting up the application.  
    ```

1.  接下来我们需要做的就是将应用程序类型设置为`container`，告知 Heroku 我们希望应用程序以这种方式运行。以下代码片段显示了此操作的代码：

    ```js
    heroku.yml file included) to version control and push it to Heroku so that it starts the build.
    ```

1.  添加所有文件以确保`git`正在跟踪它们：

    ```js
    $ git add .
    ```

1.  提交所有文件，并附上如下信息：

    ```js
    -m flag that we've used is a command that allows us to create a commit with a message with a short syntax.
    ```

1.  现在，关键是要把文件推送到`heroku`远程。

    这应该触发 Docker 镜像的构建过程，您可以在日志中进行检查。然后，在最后阶段，这个镜像被推送到 Heroku 的内部镜像注册表中，如下代码片段所示：

    ```js
    Dockerfile, following all the steps specified there, as happened when we built the image locally, as illustrated in the following code snippet: 

    ```

    remote: === 正在推送 web (Dockerfile)

    remote: 标记镜像 "5c154f3fcb23f3c3c360e16e929c22b62847fcf8" 为 "registry.heroku.com/boiling-dusk-18477/web"

    remote: 使用默认标签: latest

    remote: 推送指的是仓库 [registry.heroku.com/boiling-dusk-18477/web]

    remote: 6f8894494a30: 正在准备

    remote: f9b9c806573a: 正在准备

    ```js

    And it should be working, right? Well…, not really. We still have a couple of things that we need to configure, but we're almost there.
    ```

请记住，我们的应用程序依赖于配置，而配置的一部分来自环境。Heroku 不可能不知道我们需要哪些配置值。还有一些设置我们需要配置以使我们的应用程序运行，接下来我们就做这件事。

# 为部署配置应用程序

现在我们有一个应用程序，当代码推送到`git`时，它会启动构建镜像并部署它。我们目前的应用程序已经部署了，但实际上并没有运行，这是因为缺少配置。

您可能首先注意到的是，我们的应用程序总是从开发环境加载配置文件，`config.dev.yml`，它不应该这样做。

当我们第一次实现这个功能时，我们以为不同的环境会有不同的配置，我们是对的。当时，我们不需要为多个环境设置配置，所以我们使用了`dev`作为默认值。让我们解决这个问题。

记得我们创建加载配置文件的函数时，明确使用了环境参数吗？当时我们没有使用它，但我们留下了一个默认值。

请查看`src/config/index.ts`中的以下代码片段：

```js
export async function load(
  env = "dev",
): Promise<Configuration> {
```

我们需要做的是将此更改为支持多个环境。所以，让我们按照以下步骤来做到这一点：

1.  回到`src/index.ts`，确保我们将名为`DENO_ENV`的环境变量发送到`load`函数，如下所示：

    ```js
    const config = await
      loadConfiguration(DENO_ENV is not defined, and allow us to load a different configuration file in production.
    ```

1.  创建生产配置文件，`config.production.yml`。

    目前，它应该与`config.dev.yml`没有太大区别，除了`port`。让我们在生产环境中以端口`9001`运行它，如下所示：

    ```js
    web:
      port: 9001
    ```

    为了在本地测试这一点，我们可以使用`DENO_ENV`变量设置为`production`来运行应用程序，像这样：

    ```js
    DENO_ENV). We mentioned how you can do this in *Chapter 7**, HTTPS, Extracting Configuration, and Deno in the Browser*, in the *Accessing secret values* section.And after running it we can confirm it's loading the correct file, because the application port is now `9001`.
    ```

有了我们刚刚实现的内容，我们现在可以根据环境控制加载哪些配置值。这是我们已经在本地测试过的，但在 Heroku 上还没有做过。

我们已经解决了部分问题——我们根据环境加载不同的配置文件，但我们的应用程序依赖的其他配置值来自环境。这些是诸如**JSON Web Token**（**JWT**）密钥或 MongoDB 凭据等秘密值。

有许多方法可以做到这一点，所有云服务提供商都提供了相应的解决方案。在 Heroku 上，我们可以通过使用`config`命令来实现，如下所示：

1.  使用`heroku config:set`命令定义 MongoDB 凭据变量、JWT 密钥和环境，如下所示：

    ```js
    DENO_ENV variable so that our application knows that, when running in Heroku, it is the production environment.If you are not using your own MongoDB cluster and you have questions about its credentials, you can go back to *Chapter 6*, *Adding Authentication and Connecting to the Database*, where we created a MongoDB cluster in MongoDB Atlas.If you're using a different cluster, remember that it is defined in the configuration file in `config.production.yml` and not in the environment, and thus you need to add your cluster URL and database in the configuration file as follows:

    ```

    …

    MongoDB:

    集群 URL: <添加您的集群 URL>

    数据库: <添加您的数据库名称>

    ```js

    ```

1.  再次，我们将我们的更改添加到`git`中，如下所示：

    ```js
    $ git commit -am "Configure environment variables and DENO_ENV"
    ```

1.  然后，我们将更改推送到 Heroku 以触发部署过程，如下所示：

    ```js
    $ git push heroku master
    …
    remote: Verifying deploy... done.
    To https://git.heroku.com/boiling-dusk-18477.git
       9340446..36a061e  master -> master
    ```

    然后它应该能正常工作。如果我们现在前往 Heroku 控制台([`dashboard.heroku.com/`](https://dashboard.heroku.com/)），然后进入我们应用程序的控制台([`dashboard.heroku.com/apps/boiling-dusk-18477`](https://dashboard.heroku.com/apps/boiling-dusk-18477)，在我的案例中)并点击**打开应用程序**按钮，它应该能打开我们的应用程序，对吧？

    还不是，但我们快了——我们还需要解决一件事情。

## 从环境中获取应用程序端口

Heroku 在运行 Docker 镜像时有一些特别之处。它不允许我们设置应用程序运行的端口。它所做的是分配一个应用程序应该运行的端口，然后将来自应用程序 URL 的**超文本传输协议**（**HTTP**）和**安全的超文本传输协议**（**HTTPS**）流量重定向到那里。如果这听起来仍然很奇怪，不用担心——我们会搞定的。

正如你所知，我们明确地在`config.production.yml`文件中定义了应用程序将要运行的端口。我们需要适应这个。

Heroku 定义应用程序应该运行在哪个端口的方式是通过设置`PORT`环境变量。这在以下链接中有文档记录：

[Heroku 容器注册表和运行时](https://devcenter.heroku.com/articles/container-registry-and-runtime#dockerfile-commands-and-runtime)

你可能从标题中知道我们接下来要做什么。我们要更改我们的应用程序，以便来自环境的 Web 服务器端口覆盖配置文件中定义的那个。

回到应用程序中的`src/config/index.ts`，确保它正在从环境中读取`PORT`变量，覆盖来自文件的配置。代码可以在以下片段中看到：

```js
type Configuration = {
  web: {
    port: number;
  };
  cors: { 
…
export async function load(
  env = "dev",
): Promise<Configuration> {
  const configuration = parse(
    await Deno.readTextFile(`./config.${env}.yaml`),
  ) as Configuration;
  return {
    ...configuration,
    web: {
      ...configuration.web,
      port: Number(Deno.env.get("PORT")) ||
        configuration.web.port,
    },
…
```

这样，我们确保我们从`PORT`环境变量中读取变量，使用配置文件中的值作为默认值。

这样应该就足够让我们的应用程序在 Heroku 中顺利运行了！

再次，我们可以通过访问 Heroku 仪表板（[`dashboard.heroku.com/apps/boiling-dusk-18477`](https://dashboard.heroku.com/apps/boiling-dusk-18477)）并点击**打开应用**按钮来测试这一点，或者你可以直接访问 URL——在我的情况下，它是[`boiling-dusk-18477.herokuapp.com/`](https://boiling-dusk-18477.herokuapp.com/)。

重要提示

如果你正在使用 MongoDB Atlas，正如我们在第六章中*添加身份验证并连接到数据库*所做的那样，并且想要允许你的应用程序访问数据库，你必须配置它使其能够从"任何地方"进行连接。这不是一个推荐的做法，如果你将应用程序暴露给你的用户，而且这只发生因为我们正在使用 Heroku 的免费层。由于它在共享集群中运行，我们没有办法知道运行应用程序的机器的固定的**互联网协议**（**IP**）地址是什么，我们只能这样做。

以下链接展示了如何配置数据库的网络访问： [`docs.atlas.mongodb.com/security/ip-access-list`](https://docs.atlas.mongodb.com/security/ip-access-list)。确保你在 MongoDB Atlas 网络访问屏幕上点击**允许从任何地方访问**。

网络访问屏幕就是这样子的：

![图 9.1 – MongoDB Atlas 网络访问屏幕](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/deno-web-dev/img/Figure_9.1_B16380.jpg)

图 9.1 – MongoDB Atlas 网络访问屏幕

在此之后，我们的应用程序应该按预期工作；您可以尝试执行一个注册用户的请求（该请求连接到数据库）并检查一切是否正常，如下面的代码片段所示：

```js
$ curl -X POST -d '{"username": "test-username-001", "password": "testpw1" }' -H 'Content-Type: application/json' https://boiling-dusk-18477.herokuapp.com/api/users/register
{"user":{"username":"test-username-001","createdAt":"2020-12-19T16:49:51.809Z"}}%
```

如果您得到的响应与前面的类似，那就大功告成了！我们成功地在云环境中配置并部署了我们的应用程序，并创建了一种自动化的方式将更新推送给我们的用户。

为了进行最后的测试，以确认代码是否成功部署，我们可以尝试更改代码的一部分并再次触发部署过程。让我们这样做！按照以下步骤进行：

1.  将`src/web/index.ts`中的`"Hello World"`消息更改为`"Hello Deno World!"`，如下面的代码片段所示：

    ```js
    app.use((ctx) => {
      ctx.response.body = "Hello Deno World!";
    });
    ```

1.  按照以下步骤将此更改添加到版本控制中：

    ```js
    $ git commit -am "Change Hello World message"
    [master 35f7db7] Change Hello World message
     1 file changed, 1 insertion(+), 1 deletion(-)
    ```

1.  将其推送到 Heroku 的`git`远程仓库，如下所示：

    ```js
    $ git push heroku master
    Enumerating objects: 9, done.
    Counting objects: 100% (9/9), done.
    Delta compression using up to 8 threads
    Compressing objects: 100% (5/5), done.
    Writing objects: 100% (5/5), 807 bytes | 807.00 KiB/s, done.
    Total 5 (delta 4), reused 0 (delta 0)
    remote: Compressing source files… Done
    …
    remote: Verifying deploy... done.
    To https://git.heroku.com/boiling-dusk-18477.git
    ```

1.  如果我们现在访问应用程序的 URL（在我们的情况下是[`boiling-dusk-18477.herokuapp.com/`](https://boiling-dusk-18477.herokuapp.com/)），您应该会看到`Hello Deno World`消息。

这意味着我们的应用程序已成功部署。由于我们使用的是提供比这里学到的更多功能的云平台，我们可以探索 Heroku 的其他功能，例如日志记录。

在 Heroku 控制面板上的**打开应用**按钮旁边，有一个**更多**按钮。其中一个选项是**查看日志**，正如您在下面的屏幕截图中所看到的：

![图 9.2 – Heroku 控制面板中的应用更多选项](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/deno-web-dev/img/Figure_9.3_B16380.jpg)

](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/deno-web-dev/img/Figure_9.2_B16380.jpg)

图 9.2 – Heroku 控制面板中的应用更多选项

如果您点击那里，将出现一个实时显示日志的界面。您可以尝试通过点击**打开应用**按钮在另一个标签页中打开您的应用程序来尝试它。

您会看到日志立即更新，那里应该会出现类似这样的内容：

```js
2020-12-19T17:04:23.639359+00:00 app[web.1]: GET http://boiling-dusk-18477.herokuapp.com/ - 1ms
```

这对于您想要对应用程序的运行情况进行非常轻量级的监控非常有用。日志记录功能在免费层中提供，但还有许多其他功能供您探索，例如我们在这里不会进行的**指标**功能。

如果您想详细了解您的应用程序何时以及由谁部署，您还可以使用 Heroku 控制面板的**活动**部分，如下面的屏幕截图所示：

![图 9.3 – Heroku 控制面板应用程序选项](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/deno-web-dev/img/Figure_9.3_B16380.jpg)

图 9.3 – Heroku 控制面板应用程序选项

然后，您将看到您最近部署日志的记录，这是 Heroku 的另一个非常有趣的功能，如下面的屏幕截图所示：

![图 9.4 – Heroku 控制面板应用程序的活动标签](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/deno-web-dev/img/Figure_9.4_B16380.jpg)

](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/deno-web-dev/img/Figure_9.4_B16380.jpg)

图 9.4 – Heroku 控制面板应用程序的活动标签

这结束了我们在云环境中部署应用程序的部分。

我们关注的是应用程序以及可以在您的代码运行的平台独立重复使用的主题。我们迭代了加载配置的应用程序逻辑，使其能够根据环境加载不同的配置。

然后，我们学习了如何将包含机密配置值的环境变量发送到我们的应用程序，最后我们探索了在 Heroku 这个示例选择的平台上进行日志记录——就此结束。

我们成功让我们的应用程序运行起来，并且围绕它建立了一个完整的架构，这将使未来的迭代能够轻松地部署给我们的用户。希望我们经历了一些你们下次决定部署 Deno 应用程序时也会遇到阶段。

# 摘要

差不多完成了！本章通过部署完成了我们应用程序开发阶段的循环。我们从构建一个非常简单的应用程序开始，到向其中添加功能，到添加测试，最后——部署它。

在这里，我们学习了如何在我们的应用程序中使用一些容器化的好处。我们开始了解 Docker，我们选择的容器运行时，并迅速地创建了我们应用程序的镜像。在学习的过程中了解一些 Docker 命令，我们也体验了准备 Deno 应用程序部署是多么的容易。

创建这个 Docker 镜像使我们能够有一种可复现的方式来安装、运行和分发我们的应用程序，创建一个包含应用程序所需一切的包。

当章节进行时，我们开始探索如何使用这个应用程序包将其部署在云环境中。我们首先配置了本指南的分步指南选择的云平台 Heroku，使其每次发生变化时都会重新构建并运行我们应用程序的代码，在`git`和 Heroku 文档的帮助下，我们非常容易地实现了它。

当配置自动化流水线时，我们理解了需要将配置值发送到我们的应用程序。我们之前在早期章节中实现的一些相同的配置值，需要以两种不同的方式发送到应用程序，通过配置文件和通过环境变量。我们逐一解决了这些需求，首先通过迭代应用程序代码使其根据环境加载不同的配置，后来学习如何在 Heroku 上设置配置值。

最终，我们让我们的应用程序无缝运行，并完成了本章的目标：拥有一个可复现、自动化的方式将代码部署给我们的用户。与此同时，我们了解了一些关于 Docker 以及当涉及到发布代码时容器化和自动化的好处。

这本书的内容基本上已经讲到这里了。我们决定让这个过程成为一个建立应用程序的旅程，分别经历它的所有阶段并在需要时解决它们。这是最后一个阶段——部署，希望这能为您从编写第一行代码到部署的整个周期画上句号。

下一章将重点关注 Deno 接下来的发展，包括运行时和您个人方面。我希望这能让您成为 Deno 的爱好者，并且您对它以及它所开启的无限可能世界像我一样充满热情。
