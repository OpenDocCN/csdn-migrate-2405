# NodeJS10 REST Web API 设计（一）

> 原文：[`zh.annas-archive.org/md5/557690262B22107951CBB4677B02B662`](https://zh.annas-archive.org/md5/557690262B22107951CBB4677B02B662)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

RESTful 服务已成为社交服务、新闻订阅和移动设备的事实标准数据提供者。它们向数百万用户提供大量数据。因此，它们需要满足高可用性要求，如可靠性和可扩展性。本书将向您展示如何利用 Node.js 平台实现强大和高性能的数据服务。通过本书，您将学会如何实现一个真实的 RESTful 服务，利用现代 NoSQL 数据库来提供 JSON 和二进制内容。

重要的主题，如正确的 URI 结构和安全功能也有详细的例子，向您展示开始实施强大的 RESTful API 所需的一切。

# 这本书是为谁准备的

这本书的目标读者是想通过学习如何基于 Node.js 平台开发可扩展的服务器端 RESTful 应用程序来丰富他们的开发技能的开发人员。您还需要了解 HTTP 通信概念，并且应该具备 JavaScript 语言的工作知识。请记住，这不是一本教你如何在 JavaScript 中编程的书。了解 REST 将是一个额外的优势，但绝对不是必需的。

# 为了充分利用这本书

1.  告知读者在开始之前需要了解的事项，并明确您所假设的知识

1.  他们需要获取的任何额外安装说明和信息

# 下载示例代码文件

您可以从您的帐户在[www.packtpub.com](http://www.packtpub.com)下载这本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，文件将直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

该书的代码包也托管在 GitHub 上**[`github.com/PacktPublishing/RESTful-Web-API-Design-with-Node.js-10-Third-Edition`](https://github.com/PacktPublishing/RESTful-Web-API-Design-with-Node.js-10-Third-Edition)**。如果代码有更新，将在现有的 GitHub 存储库上更新。

我们还有其他代码包，可以在我们丰富的书籍和视频目录中找到**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**。去看看吧！

# 使用的约定

在这本书中，您会发现一些不同类型信息的文本样式。以下是一些这些样式的例子，以及它们的含义解释。

文本中的代码字，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄显示如下：

“这告诉`npm`我们的包依赖于 URL 和 express 模块。”

代码块设置如下：

```js
router.get('/v1/item/:itemId', function(request, response, next) {
  console.log(request.url + ' : querying for ' + request.params.itemId);
  catalogV1.findItemById(request.params.itemId, response);
});

router.get('/v1/:categoryId', function(request, response, next) {
  console.log(request.url + ' : querying for ' + request.params.categoryId);
  catalogV1.findItemsByCategory(request.params.categoryId, response);
});
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```js
router.get('/v1/:categoryId', function(request, response, next) {
  console.log(request.url + ' : querying for ' + request.params.categoryId);
  catalogV1.findItemsByCategory(request.params.categoryId, response);
});
```

任何命令行输入或输出都以以下形式书写：

```js
$ npm install -g express
```

**粗体**：表示一个新术语，一个重要的词或您在屏幕上看到的词。例如，菜单或对话框中的单词会在文本中以这种形式出现。这是一个例子：

警告或重要说明会出现在这样的形式中。

提示和技巧会以这种形式出现。


# 第一章：REST - 你不知道的

在过去的几年里，我们已经开始认为，为内容提供数据源、移动设备服务提供数据源或云计算都是由现代技术驱动的，例如 RESTful Web 服务。每个人都在谈论他们的无状态模型如何使应用程序易于扩展，以及它如何强调数据提供和数据消费之间的明确解耦。如今，架构师已经开始引入微服务的概念，旨在通过将核心组件拆分为简单执行单个任务的小独立部分来减少系统的复杂性。因此，企业级软件即将成为这些微服务的组合。这使得维护变得容易，并且在需要引入新部分时允许更好的生命周期管理。毫不奇怪，大多数微服务都由 RESTful 框架提供服务。这个事实可能会让人觉得 REST 是在过去的十年中发明的，但事实远非如此。事实上，REST 自上个世纪的最后一个十年就已经存在了！

本章将带领您了解**表述状态转移**（**REST**）的基础，并解释 REST 如何与 HTTP 协议配合。您将了解在将任何 HTTP 应用程序转换为 RESTful 服务启用应用程序时必须考虑的五个关键原则。您还将了解描述 RESTful 和经典**简单对象访问协议**（**SOAP**）的 Web 服务之间的区别。最后，您将学习如何利用已有的基础设施来使自己受益。

本章中，我们将涵盖以下主题：

+   REST 基础知识

+   REST 与 HTTP

+   描述、发现和文档化 RESTful 服务与经典 SOAP 服务之间的基本差异

+   利用现有基础设施

# REST 基础知识

实际上，这实际上是在 1999 年发生的，当时有一份请求提交给了**互联网工程任务组（IETF;** [`www.ietf.org/`](http://www.ietf.org/))，通过 RFC 2616：*超文本传输协议-HTTP/1.1*。其中一位作者 Roy Fielding 后来定义了围绕 HTTP 和 URI 标准构建的一组原则。这就诞生了我们今天所知的 REST。

这些定义是在 Fielding 的论文《网络软件架构的体系结构风格和设计》的第五章*表述状态转移（REST）*中给出的，该论文可以在[`www.ics.uci.edu/~fielding/pubs/dissertation/fielding_dissertation.pdf `](https://www.ics.uci.edu/~fielding/pubs/dissertation/fielding_dissertation.pdf)找到。该论文仍然可以在[`www.ics.uci.edu/~fielding/pubs/dissertation/rest_arch_style.htm`](http://www.ics.uci.edu/~fielding/pubs/dissertation/rest_arch_style.htm)找到。

让我们看看围绕 HTTP 和 URI 标准的关键原则，坚持这些原则将使您的 HTTP 应用程序成为 RESTful 服务启用应用程序：

1.  一切都是资源

1.  每个资源都可以通过**唯一标识符**（**URI**）进行识别

1.  资源通过标准的 HTTP 方法进行操作

1.  资源可以有多种表示形式

1.  以无状态方式与资源进行通信

# 原则 1 - 一切都是资源

要理解这一原则，必须构想通过特定格式而不是包含一堆字节的物理文件来表示数据的想法。互联网上的每个数据都有一个描述它的格式，称为内容类型；例如，JPEG 图像、MPEG 视频、HTML、XML、文本文档和二进制数据都是具有以下内容类型的资源：image/jpeg、video/mpeg、text/html、text/xml 和 application/octet-stream。

# 原则 2 - 每个资源都可以通过唯一标识符进行识别

由于互联网包含了如此多不同的资源，它们都应该通过 URI 访问，并且应该被唯一标识。此外，尽管它们的使用者更可能是软件程序而不是普通人，但 URI 可以采用可读性强的格式。

可读性强的 URI 使数据自我描述，并且便于进一步开发。这有助于将程序中的逻辑错误风险降到最低。

以下是目录应用程序中表示不同资源的一些示例 URI：

+   [`www.mycatalog.com/categories/watches`](http://www.mycatalog.com/categories/watches)

+   [`www.mycatalog.com/categories/watches?collection=2018`](http://www.mycatalog.com/categories/watches?collection=2018)

+   [`www.mycatalog.com/categories/watches/model-xyz/image`](http://www.mycatalog.com/categories/watches/model-xyz/image)

+   [`www.mycatalog.com/categories/watches/model-xyz/video`](http://www.mycatalog.com/categories/watches/model-xyz/video)

+   [`www.mycatalog.com/archives/2017/categories/watches.zip`](http://www.mycatalog.com/archives/2017/categories/watches.zip)

这些可读性强的 URI 以直接的方式公开了不同类型的资源。在前面的示例 URI 中，很明显数据是目录中的物品，这些物品被分类为手表。第一个链接显示了该类别中的所有物品。第二个只显示了 2018 年收藏中的物品。接下来是一个指向物品图像的链接，然后是一个指向示例视频的链接。最后一个链接指向一个 ZIP 存档中包含上一收藏物品的资源。每个 URI 提供的媒体类型都很容易识别，假设物品的数据格式是 JSON 或 XML，因此我们可以很容易地将自描述 URL 的媒体类型映射到以下之一：

+   描述物品的 JSON 或 XML 文档

+   图像

+   视频

+   二进制存档文件

# 原则 3 - 通过标准 HTTP 方法操作资源

原生 HTTP 协议（RFC 2616）定义了八种动作，也称为 HTTP 动词：

+   获取

+   发布

+   放置

+   删除

+   头

+   选项

+   跟踪

+   连接

前四个在资源上下文中感觉很自然，特别是在定义数据操作的动作时。让我们与相对 SQL 数据库进行类比，那里数据操作的本机语言是 CRUD（即 Create、Read、Update 和 Delete），源自不同类型的 SQL 语句，分别是 INSERT、SELECT、UPDATE 和 DELETE。同样地，如果你正确应用 REST 原则，HTTP 动词应该如下所示使用：

| **HTTP 动词** | **动作** | **HTTP 响应状态码** |
| --- | --- | --- |
| `GET` | 检索现有资源。 | 如果资源存在则返回`200 OK`，如果资源不存在则返回`404 Not Found`，其他错误则返回`500 Internal Server Error`。 |
| `PUT` | 更新资源。如果资源不存在，服务器可以决定使用提供的标识符创建它，或者返回适当的状态代码。 | 如果成功更新则返回`200 OK`，如果创建了新资源则返回`201 Created`，如果要更新的资源不存在则返回`404 Not found`，其他意外错误则返回`500 Internal Server Error`。 |
| `POST` | 使用服务器端生成的标识符创建资源，或者使用客户端提供的现有标识符更新资源。如果此动词仅用于创建而不用于更新，则返回适当的状态代码。 | 如果创建了新资源则返回`201 CREATED`，如果资源已成功更新则返回`200 OK`，如果资源已存在且不允许更新则返回`409 Conflict`，如果要更新的资源不存在则返回`404 Not Found`，其他错误则返回`500 Internal Server Error`。 |
| `DELETE` | 删除资源。 | `200 OK`或`204 No Content`如果资源已成功删除，`404 Not Found`如果要删除的资源不存在，`500 Internal Server Error`用于其他错误。 |

请注意，资源可以由`POST`或`PUT` HTTP 动词创建，具体取决于应用程序的策略。但是，如果必须在由客户端提供的特定 URI 下创建资源，则`PUT`是适当的操作：

```js
PUT /categories/watches/model-abc HTTP/1.1
Content-Type: text/xml
Host: www.mycatalog.com

<?xml version="1.0" encoding="utf-8"?>
<Item category="watch">
    <Brand>...</Brand>
    </Price></Price>
</Item>

HTTP/1.1 201 Created 
Content-Type: text/xml 
Location: http://www.mycatalog.com/categories/watches/model-abc

```

但是，在您的应用程序中，您可能希望由后端 RESTful 服务决定在何处公开新创建的资源，并因此在适当但仍未知或不存在的位置下创建它。

例如，在我们的示例中，我们可能希望服务器定义新创建项目的标识符。在这种情况下，只需使用`POST`动词到 URL 而不提供标识符参数。然后由服务本身提供新的唯一且有效的标识符，并通过响应的`Location`标头公开此 URL：

```js
POST /categories/watches HTTP/1.1
Content-Type: text/xml
Host: www.mycatalog.com

<?xml version="1.0" encoding="utf-8"?>
<Item category="watch">
    <Brand>...</Brand>
    </Price></Price>
</Item>

HTTP/1.1 201 Created 
Content-Type: text/xml 
Location: http://www.mycatalog.com/categories/watches/model-abc
```

# 原则 4-资源可以具有多个表示

资源的一个关键特征是它可以以与存储格式不同的格式表示。因此，可以请求或创建不同的表示。只要支持指定的格式，REST 启用的端点应该使用它。在前面的示例中，我们发布了手表项目的 XML 表示，但如果服务器支持 JSON 格式，以下请求也将有效：

```js
POST /categories/watches HTTP/1.1
Content-Type: application/json
Host: www.mycatalog.com

{
  "watch": {
    "id": ""watch-abc"",
    "brand": "...",
    "price": {
      "-currency": "EUR",
      "#text": "100"
    }
  }
}
HTTP/1.1 201 Created
Content-Type: application/json
Location: http://mycatalog.com/categories/watches/watch-abc   
```

# 原则 5-以无状态的方式与资源通信

通过 HTTP 请求进行的资源操作应始终被视为原子操作。应在 HTTP 请求中以隔离的方式执行所有对资源的修改。请求执行后，资源将处于最终状态；这隐含地意味着不支持部分资源更新。您应始终发送资源的完整状态。

回到我们的目录示例，更新给定项目的价格字段意味着使用完整文档（JSON 或 XML）进行 PUT 请求，其中包含整个数据，包括更新后的价格字段。仅发布更新后的价格不是无状态的，因为这意味着应用程序知道资源具有价格字段，也就是说，它知道它的状态。

RESTful 应用程序要求的另一个条件是，一旦服务部署在生产环境中，传入的请求很可能由负载均衡器提供服务，确保可伸缩性和高可用性。一旦通过负载均衡器公开，将应用程序状态保留在服务器端的想法就会受到威胁。这并不意味着您不允许保留应用程序的状态。这只是意味着您应该以 RESTful 的方式保留它。例如，在 URI 中保留部分状态，或使用 HTTP 标头提供附加的与状态相关的数据

您的 RESTful API 的无状态性使调用方与服务器端的更改隔离开来。因此，不希望调用方在连续请求中与同一服务器通信。这允许在服务器基础架构中轻松应用更改，例如添加或删除节点。

请记住，保持 RESTful API 的无状态性是您的责任，因为 API 的使用者期望它们是无状态的。

现在您知道 REST 大约有 18 年的历史，一个明智的问题是，“为什么它最近才变得如此受欢迎？”嗯，我们开发人员通常拒绝简单直接的方法，大多数时候更喜欢花更多时间将已经复杂的解决方案变得更加复杂和复杂。

以经典的 SOAP web 服务为例。它们的各种 WS-*规范如此之多，有时定义得如此松散，以至于为了使来自不同供应商的不同解决方案能够互操作，引入了一个单独的规范 WS-Basic Profile。它定义了额外的互操作性规则，以确保 SOAP-based web 服务中的所有 WS-*规范可以一起工作。

当涉及使用经典的 Web 服务通过 HTTP 传输二进制数据时，情况变得更加复杂，因为基于 SOAP 的 Web 服务提供了不同的传输二进制数据的方式。每种方式都在其他规范集中定义，比如**SOAP with** **Attachment References** (**SwaRef**)和**Message Transmission** **Optimization Mechanism (MTOM)**。所有这些复杂性主要是因为 Web 服务的最初想法是远程执行业务逻辑，而不是传输大量数据。

现实世界告诉我们，在数据传输方面，事情不应该那么复杂。这就是 REST 适应大局的地方——通过引入资源的概念和一种标准的方式来操作它们。

# REST 的目标

现在我们已经介绍了主要的 REST 原则，是时候深入探讨遵循这些原则时可以实现什么了：

+   表示和资源的分离

+   可见性

+   可靠性

+   可扩展性

+   性能

# 表示和资源的分离

资源只是一组信息，如原则 4 所定义，它可以有多种表示；但是它的状态是原子的。调用者需要在 HTTP 请求中使用`Accept`头指定所需的媒体类型，然后由服务器应用程序处理表示，返回资源的适当内容类型以及相关的 HTTP 状态码。

+   在成功的情况下返回`HTTP 200 OK`

+   如果给出了不支持的格式或任何其他无效的请求信息，则返回`HTTP 400 Bad Request`

+   如果请求了不支持的媒体类型，则返回`HTTP 406 Not Acceptable`

+   在请求处理过程中发生意外情况时，返回`HTTP 500 Internal Server Error`

假设在服务器端，我们有以 XML 格式存储的项目资源。我们可以有一个 API，允许消费者以各种格式请求项目资源，比如`application/xml`，`application/json`，`application/zip`，`application/octet-stream`等等。

由 API 自身来加载请求的资源，将其转换为请求的类型（例如 JSON 或 XML），并且可以使用 ZIP 进行压缩，或直接将其刷新到 HTTP 响应输出。

调用者将使用`Accept` HTTP 头来指定他们期望的响应的媒体类型。因此，如果我们想要以 XML 格式请求前一节中插入的项目数据，应执行以下请求：

```js
GET /category/watches/watch-abc HTTP/1.1 
Host: my-computer-hostname 
Accept: text/xml 

HTTP/1.1 200 OK 
Content-Type: text/xml 
<?xml version="1.0" encoding="utf-8"?>
<Item category="watch">
    <Brand>...</Brand>
    </Price></Price>
</Item>
```

要请求以 JSON 格式获取相同的项目，`Accept`头需要设置为`application/json`：

```js
GET /categoery/watches/watch-abc HTTP/1.1 
Host: my-computer-hostname 
Accept: application/json 

HTTP/1.1 200 OK 
Content-Type: application/json 
{
  "watch": {
    "id": ""watch-abc"",
    "brand": "...",
    "price": {
      "-currency": "EUR",
      "#text": "100"
    }
  }
}
```

# 可见性

REST 的设计是可见和简单的。服务的可见性意味着它的每个方面都应该是自描述的，并且遵循自然的 HTTP 语言，符合原则 3、4 和 5。

在外部世界的上下文中，可见性意味着监控应用程序只对 REST 服务和调用者之间的 HTTP 通信感兴趣。由于请求和响应是无状态和原子的，没有必要流动应用程序的行为，也不需要了解是否出现了问题。

记住，缓存会降低你的 RESTful 应用的可见性，一般情况下应该避免使用，除非需要为大量调用者提供资源。在这种情况下，缓存可能是一个选择，但需要仔细评估提供过时数据的可能后果。

# 可靠性

在谈论可靠性之前，我们需要定义在 REST 上下文中哪些 HTTP 方法是安全的，哪些是幂等的。因此，让我们首先定义什么是安全和幂等方法：

+   如果一个 HTTP 方法在请求时不修改或导致资源状态的任何副作用，则被认为是安全的。

+   如果一个 HTTP 方法的响应保持不变，无论请求的次数如何，那么它被认为是幂等的，重复相同的幂等请求总是返回相同的结果。

以下表格列出了 RESTful 服务中哪些 HTTP 方法是安全的，哪些是幂等的：

| **HTTP 方法** | **安全** | **幂等** |
| --- | --- | --- |
| `GET` | 是 | 是 |
| `POST` | 否 | 否 |
| `PUT` | 否 | 是 |
| `DELETE` | 否 | 是 |

消费者应该考虑操作的安全性和幂等性特性，以便可靠地提供服务。

# 可扩展性和性能

到目前为止，我们强调了对于 RESTful Web 应用程序来说，具有无状态行为的重要性。**万维网**（**WWW**）是一个庞大的宇宙，包含大量数据和许多渴望获取这些数据的用户。WWW 的发展带来了这样的要求，即应用程序应该在负载增加时能够轻松扩展。具有状态的应用程序的扩展难以实现，特别是当期望零或接近零的运行停机时间时。

这就是为什么对于任何需要扩展的应用程序来说，保持无状态是至关重要的。在最理想的情况下，扩展应用程序可能需要您为负载均衡器添加另一台硬件，或者在云环境中引入另一个实例。不需要不同的节点之间进行同步，因为它们根本不需要关心状态。可扩展性的主要目标是在可接受的时间内为所有客户提供服务。其主要思想是保持应用程序运行，并防止由大量传入请求引起的**拒绝服务**（**DoS**）。

可扩展性不应与应用程序的性能混淆。性能是通过处理单个请求所需的时间来衡量的，而不是应用程序可以处理的总请求数。Node.js 的异步非阻塞架构和事件驱动设计使其成为实现可扩展和性能良好的应用程序的合乎逻辑的选择。

# 使用 WADL

如果您熟悉 SOAP Web 服务，可能已经听说过**Web 服务定义语言**（**WSDL**）。它是服务接口的 XML 描述，并定义了调用的端点 URL。对于 SOAP Web 服务来说，必须由这样的 WSDL 定义来描述。

与 SOAP Web 服务类似，RESTful 服务也可以使用一种称为 WADL 的描述语言。**WADL**代表**Web 应用程序定义语言**。与 SOAP Web 服务的 WSDL 不同，RESTful 服务的 WADL 描述是可选的，也就是说，使用服务与其描述无关。

以下是描述我们目录服务的`GET`操作的 WADL 文件的示例部分：

```js
<?xml version="1.0" encoding="UTF-8"?>
<application xmlns="http://wadl.dev.java.net/2009/02" xmlns:service="http://localhost:8080/catalog/" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <grammer>
    <include href="items.xsd" />
    <include href="error.xsd" />
  </grammer>
  <resources base="http://localhost:8080/catalog/categories">
    <resource path="{category}">
      <method name="GET">
        <request>
          <param name="category" type="xsd:string" style="template" />
        </request>
        <response status="200">
          <representation mediaType="application/xml" element="service:item" />
          <representation mediaType="application/json" />
        </response>
        <response status="404">
          <representation mediaType="application/xml" element="service:item" />
        </response>
      </method>
    </resource>
  </resources>
</application>
```

WADL 文件的这一部分显示了如何描述公开资源的应用程序。简而言之，每个资源必须是应用程序的一部分。资源提供了一个`base`属性，描述了它位于何处，并在方法中描述了它支持的每个 HTTP 方法。此外，可以在资源和应用程序中使用可选的`doc`元素来提供有关服务及其操作的额外文档。

尽管 WADL 是可选的，但它显著减少了发现 RESTful 服务的工作量。

# 使用 Swagger 记录 RESTful API

在 Web 上公开的 API 应该有很好的文档，否则开发人员将难以在其应用程序中使用它们。虽然 WADL 定义可能被认为是文档的来源，但它们解决了不同的问题——服务的发现。它们为机器提供服务的元数据，而不是为人类。Swagger 项目([`swagger.io/`](https://swagger.io/))解决了对 RESTful API 进行整洁文档的需求。它从几乎可读的 JSON 格式定义了 API 的元描述。以下是部分描述目录服务的示例`swagger.json`文件：

```js
{
  "swagger": "2.0",
  "info": {
    "title": "Catalog API Documentation",
    "version": "v1"
  },
  "paths": {
    "/categories/{id}" : {
      "get": {
        "operationId": "getCategoryV1",
        "summary": "Get a specific category ",
        "produces": [
          "application/json"
        ],
        "responses": {
          "200": {
            "description": "200 OK",
            "examples": 
              {"application/json": {                
                "id": 1,
                "name": "Watches",
                "itemsCount": 550
                }                
              } 
          },
          "404": {"description" : "404 Not Found"},
          "500": {"description": "500 Internal Server Error"}
        }
      }
    }
  },
  "consumes": ["application/json"]
}
```

`swagger.json`文件非常简单：它定义了 API 的名称和版本，并简要描述了它公开的每个操作，与示例有效负载很好地结合在一起。但它的真正好处来自 Swagger 的另一个子项目，称为`swagger-ui` ([`swagger.io/swagger-ui/`](https://swagger.io/swagger-ui/))，它实际上将`swagger.json`中的数据很好地呈现为交互式网页，不仅提供文档，还允许与服务进行交互：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/rst-webapi-dsn-node10/img/6c16dc3b-58bd-440b-9c9f-ff960921f30a.png)

我们将查看并利用`swagger-ui` Node.js 模块来提供我们将在本书中稍后开发的 API，以及最新的文档。

# 利用现有基础设施

开发和分发 RESTful 应用程序最好的部分是所需的基础设施已经存在，可供您使用。由于 RESTful 应用程序大量使用现有的网络空间，因此在开发时您无需做任何其他事情，只需遵循 REST 原则。此外，针对任何平台都有大量可用的库，我是指任何平台。这简化了 RESTful 应用程序的开发，因此您只需选择您喜欢的平台并开始开发。

# 摘要

在本章中，您了解了 REST 的基础知识，看了五个关键原则，将 Web 应用程序转变为 REST 启用的应用程序。我们简要比较了 RESTful 服务和传统的 SOAP Web 服务，最后看了一下 RESTful 服务的文档以及我们如何简化我们开发的服务的发现。

现在您已经了解了基础知识，我们准备深入了解 Node.js 实现 RESTful 服务的方式。在下一章中，您将了解 Node.js 的基本知识以及必须使用和了解的相关工具，以构建真正完整的网络服务。


# 第二章：使用 Node.js 入门

在本章中，您将获得您的第一个真正的 Node.js 体验。我们将从安装 Node.js 开始，以及一些我们将在整本书中使用的模块。然后，我们将设置一个开发环境。在整本书中，将使用 Atom IDE。是的，GitHub 的在线编辑器终于登陆了桌面环境，并且可以在您喜欢的平台上使用！

接下来，我们将创建一个工作空间，并开始开发我们的第一个 Node.js 应用程序。这将是一个简单的服务器应用程序，用于处理传入的 HTTP 请求。我们将进一步演示如何将我们的 JavaScript 代码模块化和单元测试。最后，我们将在 Heroku 云应用平台上部署我们的第一个应用程序。

总之，在本章中，我们将涵盖以下主题：

+   安装 Node.js

+   安装 Express 框架和其他模块

+   设置开发环境

+   处理 HTTP 请求

+   模块化代码

+   测试 Node.js

+   部署应用程序

# 安装 Node.js

让我们从 Node.js 安装开始我们的 Node.js 之旅。Windows 和 macOS 都可以在[`nodejs.org/en/download/`](https://nodejs.org/en/download/)上找到安装程序。在撰写本文时，Node.js 10 刚刚发布为当前版本，并将于 2018 年 8 月成为下一个长期支持版本。Linux 用户可以从可用的 Linux 二进制文件构建 Node.js，或者利用他们的软件包管理器，因为 Node.js 在不同 Linux 发行版的大多数流行软件包存储库中都可用。例如，Ubuntu 和其他基于 Debian 的发行版应该首先指向最新的 Node.js 10 软件包，然后通过 shell 中的`apt-get`命令进行安装：

```js
curl -sL https://deb.nodesource.com/setup_10.x | sudo -E bash -
sudo apt-get install nodejs
```

如果您决定使用 macOS 或 Windows 可用的安装程序，向导将指导您完成一个相当典型的安装过程，您需要接受 Node.js 许可协议，然后提供安装路径。

通过软件包管理器执行安装的 Linux 用户需要单独安装**Node Package Manager (npm)**；我们将在下一节中进行安装。

安装成功后，您应该已经将 Node 设置在您的`PATH`环境变量中。

安装程序将为您预先选择 Node.js 运行时、npm、在线文档资源的快捷方式，以及将 Node.js 和 npm 添加到操作系统`PATH`环境变量的选项。

要验证您的安装是否成功，请从 shell 中执行以下操作：

```js
node --version 
```

在撰写本文时，最新的 Node.js 版本是 10.0.0，因此预期的输出版本号将是这个版本号。Node.js 10 将是下一个长期支持的版本，因此在接下来的几年里它将保持最新。

# Npm

Node.js 通过提供**npm**来方便地支持第三方开源开发的模块。它允许您作为开发人员轻松安装、管理甚至提供自己的模块包。npm 包存储库位于[`www.npmjs.org/`](http://www.npmjs.org/)，可以通过其命令行界面访问。

如果您没有使用安装程序，那么您需要单独安装`npm`。例如，Ubuntu 用户可以按照以下方式使用他们的软件包安装程序：

```js
apt-get npm install
```

如果您升级了 Node.js 安装，并且之前安装了 npm 5.6，系统会要求您将其升级到版本 6。要执行此操作，只需执行：

```js
sudo npm i -g npm
```

一旦安装了 npm，通过编辑`~/.profile`文件将其永久设置在用户配置文件的`PATH`环境变量中是很有用的，以便导出 npm 的路径如下：

```js
export PATH=$PATH:/path/to/npm
```

成功安装 npm 后，使用 npm 的`ls`选项来显示当前安装的 Node.js 模块：

```js
bojinov@developer-machine:~$ npm ls
/home/bojinov
├─┬ accepts@1.3.3
│ ├─┬ mime-types@2.1.13
│ │ └── mime-db@1.25.0
│ └── negotiator@0.6.1
├── array-flatten@1.1.1
├─┬ cache-control@1.0.3
│ ├─┬ cache-header@1.0.3
│ │ ├── lodash.isnumber@2.4.1 deduped
│ │ ├── lodash.isstring@2.4.1
│ │ └── regular@0.1.6 deduped
│ ├─┬ fast-url-parser@1.1.3
│ │ └── punycode@1.4.1
│ ├─┬ glob-slasher@1.0.1
│ │ ├── glob-slash@1.0.0
│ │ ├─┬ lodash.isobject@2.4.1
│ │ │ └── lodash._objecttypes@2.4.1
│ │ └─┬ toxic@1.0.0
│ │ └── lodash@2.4.2
│ ├─┬ globject@1.0.1
│ │ └── minimatch@2.0.10 extraneous
│ ├── lodash.isnumber@2.4.1
│ ├── on-headers@1.0.1
│ └── regular@0.1.6
├── content-disposition@0.5.1
├── content-type@1.0.2
├── cookie@0.3.1
├── cookie-signature@1.0.6
```

# 安装 Express 框架和其他模块

现在我们安装了`npm`，让我们利用它并安装一些在本书中将大量使用的模块。其中最重要的是 Express 框架([`www.expressjs.com/`](http://www.expressjs.com/))。它是一个灵活的 Web 应用程序框架，为 Node.js 提供了一个强大的 RESTful API，用于开发单页或多页 Web 应用程序。以下命令将从 npm 仓库下载 Express 模块，并使其可用于我们的本地 Node.js 安装：

```js
npm install -g express 
```

在成功安装后，你将在`npm ls`的结果中找到`express`模块。在本章的后面，我们将学习如何为我们的 Node.js 模块编写单元测试。为此，我们将需要`nodeunit`模块：

```js
npm install nodeunit -g 
```

`-g`选项会全局安装`nodeunit`。这意味着该模块将被存储在你的文件系统的一个中央位置；通常是`/usr/lib/node_modules`或者`/usr/lib/node`，但这可以配置到你的 Node.js 的全局配置。全局安装的模块对所有正在运行的 node 应用程序都是可用的。

本地安装的模块将存储在你项目的当前工作目录的`node_modules`子目录中，并且只对该单个项目可用。

现在，回到`nodeunit`模块——它提供了用于创建基本单元测试的基本断言测试函数，以及用于执行它们的工具。

在开始使用 Node.js 开发之前，我们还有一件事要了解：Node.js 应用程序的包描述文件。

所有的 Node.js 应用程序或模块都包含一个`package.json`描述文件。它提供关于模块、作者和它使用的依赖的元信息。让我们来看一下我们之前安装的`express`模块的`package.json`文件：

```js
{
  "_from": "express",
  "_id": "express@4.16.1",
  "_inBundle": false,
  "_integrity": "sha512-STB7LZ4N0L+81FJHGla2oboUHTk4PaN1RsOkoRh9OSeEKylvF5hwKYVX1xCLFaCT7MD0BNG/gX2WFMLqY6EMBw==",
  "_location": "/express",
  "_phantomChildren": {},
  "_requested": {
    "type": "tag", "registry": true, "raw": "express", "name": "express",
    "escapedName": "express","rawSpec": "", "saveSpec": null, "fetchSpec": "latest"
  },
  "_requiredBy": [
    "#USER"
  ],
  "_resolved": "https://registry.npmjs.org/express/-/express-4.16.1.tgz",
  "_shasum": "6b33b560183c9b253b7b62144df33a4654ac9ed0",
  "_spec": "express",
  "_where": "/home/valio/Downloads",
  "author": {
    "name": "TJ Holowaychuk",
    "email": "tj@vision-media.ca"
  },
  "bugs": {
    "url": "https://github.com/expressjs/express/issues"
  },
  "bundleDependencies": false,
  "contributors": [
    {
      "name": "Aaron Heckmann",
      "email": "aaron.heckmann+github@gmail.com"
    },
   ...,
    {
      "name": "Young Jae Sim",
      "email": "hanul@hanul.me"
    }
  ],
  "dependencies": {
    "accepts": "~1.3.4",
    "array-flatten": "1.1.1",
    "body-parser": "1.18.2",
    ...,
    "type-is": "~1.6.15",
    "utils-merge": "1.0.1",
    "vary": "~1.1.2"
  },
  "deprecated": false,
  "description": "Fast, unopinionated, minimalist web framework",
  "devDependencies": {
    "after": "0.8.2",
    "connect-redis": "~2.4.1",
    ...,
    "should": "13.1.0",
    "supertest": "1.2.0",
    "vhost": "~3.0.2"
  },
  "engines": {
    "node": ">= 0.10.0"
  },
  "files": ["LICENSE", "History.md", "Readme.md", "index.js","lib/"],
  "homepage": "http://expressjs.com/",
  "keywords": [
    "express", "framework", "sinatra", "web", "rest", "restful", "router", "app", "api"
  ],
  "license": "MIT",
  "name": "express",
  "repository": {
    "type": "git",
    "url": "git+https://github.com/expressjs/express.git"
  },
  "scripts": {
    "lint": "eslint .",
    "test": "mocha --require test/support/env --reporter spec --bail --check-leaks test/ test/acceptance/"
  },
  "version": "4.16.1"
}
```

包的名称和版本是每个模块的必需属性。所有其他的元信息，比如贡献者列表、仓库类型和位置、许可信息等等，都是可选的。其中一个最有趣的属性是`dependencies`属性。它告诉 npm 你的包依赖于哪些模块。让我们深入了解一下这是如何指定的。每个依赖都有一个名称和一个版本。

这告诉 npm 该包依赖于版本为 1.3.4 的`accepts`模块和版本为 1.8.2 的`body-parse`模块。所以，当 npm 安装该模块时，它将隐式地下载并安装依赖的最新次要版本，如果它们尚未可用。

依赖的版本是以以下格式指定的：`major.minor.patch-version`。你可以指定 npm 如果你想让 npm 使用确切指定的版本，或者你可以让 npm 始终下载最新可用的次要版本，通过以`~`开头的版本；参考`accepts`依赖。

有关版本控制的更多信息，请访问语义版本规范的网站[`www.semver.org/`](http://www.semver.org/)。

依赖于自动管理的版本可能导致向后不兼容，请确保每次切换版本时都测试你的应用程序。

# 设置开发环境

JavaScript 开发人员很少在 IDE 中开发他们的项目；他们中的大多数人使用文本编辑器，并倾向于对与他们观点相矛盾的任何东西持偏见。GitHub 终于通过发布桌面环境的 Atom IDE 来平息了他们中的大多数人。这可能解决不了关于哪种环境最好的争论，但至少会带来一些和平，并让人们专注于他们的代码，而不是工具，这最终是个人偏好的问题。本书中的示例是在 Atom IDE 中开发的，但请随意使用任何可以创建文件的软件，包括 vi 或 vim 等命令行编辑器，如果这样做会让您感觉像 JS 超级英雄，尽管请记住超级英雄已经过时了！

您可以从[`ide.atom.io/`](https://ide.atom.io/)下载 Atom IDE。

现在是启动我们的第一个 Node.js 应用程序的时候了，一个简单的 Web 服务器响应`Hello from Node.js`。从您的项目中选择一个目录，例如`hello-node`，然后从中打开一个 shell 终端并执行`npm init`：

```js
npm init

package name: (hello-node) 
version: (1.0.0) 
description: Simple hello world http handler
entry point: (index.js) app.js
test command: test
git repository: 
keywords: 
author: Valentin Bojinov
license: (ISC) 
About to write to /home/valio/nodejs8/hello-node/package.json:

{
 "name": "hello-node",
 "version": "1.0.0",
 "description": "Simple hello world http handler",
 "main": "app.js",
 "scripts": {
 "test": "test"
 },
 "author": "Valentin Bojinov",
 "license": "ISC"
}

Is this ok? (yes) yes

```

一个命令行交互向导将询问您的项目名称，版本，以及一些其他元数据，如 Git 存储库，您的姓名等等，并最终预览要生成的`package.json`文件；完成后，您的第一个 Node.js 项目准备开始。

现在是花一些时间研究本书中使用的代码约定的合适时机；当需要定义短回调函数时，将使用 ES6 内联匿名函数，而当期望可重用性和可测试性时，将使用常规的 javascript 函数。

启动 Atom IDE，选择文件|添加项目文件夹...，并导入您定义项目的目录。最后，在成功导入后，您将在项目中看到生成的`package.json`文件。右键单击目录，选择新建文件，并创建一个名为`hello-node.js`的文件：

```js
var http = require('http');

http.createServer((request, response) => {
  response.writeHead(200, {
    'Content-Type' : 'text/plain'
  });
  response.end('Hello from Node.JS');
  console.log('Hello handler requested');
}).listen(8180, '127.0.0.1', () => {
  console.log('Started Node.js http server at http://127.0.0.1:8180');
});
```

`hello-node.js`文件使用 Node.js HTTP 模块开始监听端口`8180`上的传入请求。它将对每个请求回复静态的`Hello from Node.JS`，并在控制台中记录一个 hello 日志条目。在启动应用程序之前，我们必须安装创建 HTTP 服务器的`http`模块。让我们全局安装它以及`--save`选项，这将在项目的`package.json`文件中添加对它的依赖。然后我们可以启动应用程序：

```js
npm install -g http --save
node hello-node.js  
```

从浏览器打开`http://localhost:8180/`将导致向服务器应用程序发送请求，这将在控制台中记录一个日志条目，并在浏览器中输出`Hello from Node.JS`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/rst-webapi-dsn-node10/img/3c01bdd5-3c7e-4458-a8f3-88140949e0b4.png)

# 处理 HTTP 请求

目前，我们的服务器应用程序无论处理什么类型的 HTTP 请求都会以相同的方式行为。让我们以这样的方式扩展它，使其更像一个 HTTP 服务器，并根据其类型开始区分传入请求，通过为每种类型的请求实现处理程序函数。

让我们创建一个名为`hello-node-http-server.js`的新文件：

```js
var http = require('http');
var port = 8180;

function handleGetRequest(response) {
  response.writeHead(200, {'Content-Type' : 'text/plain'});
  response.end('Get action was requested');
}

function handlePostRequest(response) {
  response.writeHead(200, {'Content-Type' : 'text/plain'});
  response.end('Post action was requested');
}

function handlePutRequest(response) {
  response.writeHead(200, {'Content-Type' : 'text/plain'});
  response.end('Put action was requested');
}

function handleDeleteRequest(response) {
  response.writeHead(200, {'Content-Type' : 'text/plain'});
  response.end('Delete action was requested');
}

function handleBadRequest(response) {
  console.log('Unsupported http mehtod');
  response.writeHead(400, {'Content-Type' : 'text/plain'  });
  response.end('Bad request');
}

function handleRequest(request, response) {
  switch (request.method) {
    case 'GET':
      handleGetRequest(response);
      break;
    case 'POST':
      handlePostRequest(response);
      break;
    case 'PUT':
      handlePutRequest(response);
      break;
    case 'DELETE':
      handleDeleteRequest(response);
      break;
    default:
      handleBadRequest(response);
      break;
  }
  console.log('Request processing completed');
}

http.createServer(handleRequest).listen(8180, '127.0.0.1', () => {
  console.log('Started Node.js http server at http://127.0.0.1:8180');
});
```

当我们运行此应用程序时，我们的 HTTP 服务器将识别`GET`、`POST`、`PUT`和`DELETE` HTTP 方法，并将在不同的函数中处理它们。对于所有其他 HTTP 请求，它将以`HTTP 400 BAD REQUEST`状态代码优雅地响应。为了与 HTTP 应用程序交互，我们将使用 Postman，可从[`www.getpostman.com/`](https://www.getpostman.com/)下载。这是一个轻量级的应用程序，用于向端点发送 HTTP 请求，指定 HTTP 标头，并提供有效载荷。试试并执行我们之前实现的每个处理程序函数的测试请求：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/rst-webapi-dsn-node10/img/46971774-7421-435b-98a2-125e36aa07f3.png)

# 模块化代码

到目前为止，我们开发了一个简单的 HTTP 服务器应用程序，用于监听和处理已知的请求类型；但是，它的结构并不是很好，因为处理请求的函数不可重用。Node.js 支持模块，支持代码隔离和可重用性。

用户定义的模块是一个由一个或多个相关函数组成的逻辑单元。该模块可以向其他组件导出一个或多个函数，同时将其他函数保持对自身可见。

我们将重新设计我们的 HTTP 服务器应用程序，使整个请求处理功能都包装在一个模块中。该模块将只导出一个通用处理程序函数，该函数将以请求对象作为参数，并根据其请求类型将处理委托给模块外部不可见的内部函数。

让我们首先在项目中创建一个新的模块目录。我们将通过将以下函数提取到新创建的目录中的`http-module.js`文件中来重构我们以前的源文件：

```js
function handleGetRequest(response) {
  response.writeHead(200, {'Content-Type' : 'text/plain'});
  response.end('Get action was requested');
}

function handlePostRequest(response) {
  response.writeHead(200, {'Content-Type' : 'text/plain'});
  response.end('Post action was requested');
}

function handlePutRequest(response) {
  response.writeHead(200, {'Content-Type' : 'text/plain'});
  response.end('Put action was requested');
}

function handleDeleteRequest(response) {
  response.writeHead(200, {'Content-Type' : 'text/plain'});
  response.end('Delete action was requested');
}

function handleBadRequest(response) {
  console.log('Unsupported http mehtod');
  response.writeHead(400, {'Content-Type' : 'text/plain'  });
  response.end('Bad request');
}

exports.handleRequest = function(request, response) {
  switch (request.method) {
    case 'GET':
      handleGetRequest(response);
      break;
    case 'POST':
      handlePostRequest(response);
      break;
    case 'PUT':
      handlePutRequest(response);
      break;
    case 'DELETE':
      handleDeleteRequest(response);
      break;
    default:
      handleBadRequest(response);
      break;
  }
  console.log('Request processing completed');
}
```

该文件创建了一个用户定义的模块，导出`handleRequest`函数，使其可用于其他组件。所有其他函数只能在模块内部访问。虽然示例只导出一个函数，但模块可以导出尽可能多的函数。

让我们在我们的第一个项目的`main`目录中的`main.js`文件中使用新的`http-module`。我们必须使用 Node.js 内置的`http`模块创建一个`http`服务器，其`createServer`将其`handleRequest`函数作为参数传递。它将作为服务器在每个请求上调用的回调函数：

```js
var http = require('http');
var port = 8180;

var httpModule = require('./modules/http-module');

http.createServer(httpModule.handleRequest).listen(8180, '127.0.0.1', () => {
  console.log('Started Node.js http server at http://127.0.0.1:8180');
});
```

我们将创建服务器套接字的创建与处理与其绑定的传入请求的业务逻辑分开。使用`require`指令导入我们的模块。它使用相对路径。也可以使用 Postman 工具执行另一个测试请求来尝试这个版本。

幸运的是，在实现支持 RESTful 的应用程序时，我们不需要创建自己的 HTTP 处理程序。Express 框架将为我们完成这些工作。本章的示例旨在清楚地展示 Node.js 在处理 HTTP 请求和实现用户模块方面的可能性。我们将在第三章中详细了解 Express 框架，*构建典型的 Web API*。

# 测试 Node.js

现在我们将通过为 HTTP 模块提供一个单元测试来扩展我们的项目，但在深入研究之前，让我们先看看 Node.js 如何支持单元测试。在本章的开头，我们安装了 Nodeunit 模块。好吧，现在是时候开始尝试一下了。

首先，让我们创建另一个简单的 Node.js 模块，我们将用它来实现我们的第一个单元测试。然后我们将转向更高级的主题，比如模拟 JavaScript 对象并使用它们来为我们的 HTTP 模块创建单元测试。

我选择开发一个简单的数学模块，导出用于添加和减去整数的函数，因为它足够简单，每个操作的结果都是严格定义的。

让我们从模块开始，在我们的`module`目录中创建以下`math.js`文件：

```js
exports.add = function (x, y) { 
  return x + y; 
}; 
exports.subtract = function (x, y) { 
  return x - y; 
}; 
```

下一步是在项目的`test`子目录中创建一个`test-math.js`文件：

```js
var math = require('../modules/math');
exports.addTest = function (test) {
  test.equal(math.add(1, 1), 2);
  test.done();
};
exports.subtractTest = function (test) {
  test.equals(math.subtract(4,2), 2);
  test.done();
};
```

最后，使用 shell 终端运行`nodeunit test/test-math.js`来运行测试模块。输出将显示所有测试方法的结果，指定它们是否成功通过：

```js
nodeunit test/test-math.js    
    test-math.js
    test-math.js
 addTest
 subtractTest

OK: 2 assertions (5ms)
```

让我们修改`addTest`，使其出现故障，看看 Nodeunit 模块如何报告测试失败：

```js
exports.test_add = function (test) { 
    test.equal(math.add(1, 1), 3); 
    test.done(); 
}; 
```

这次执行测试会导致失败，并显示一些断言失败的消息，最后会有一个汇总，显示执行的测试中有多少失败了：

```js
nodeunit test-math.js
test-math.js
 addTest
at Object.equal (/usr/lib/node_modules/nodeunit/lib/types.js:83:39)
at Object.exports.addTest (../hello-node/test/test-math.js:
(..)

AssertionError: 2 == 3
 subtractTest
FAILURES: 1/2 assertions failed (12ms)
```

我们刚刚创建了 Nodeunit 的第一个单元测试。但是，它以一种相对隔离的方式测试数学函数。我想你会想知道我们如何使用 Nodeunit 来测试具有复杂参数的函数，比如绑定到上下文的 HTTP 请求和响应。这是可能的，使用所谓的**模拟对象**。它们是复杂基于上下文的参数或函数状态的预定义版本，在我们的单元测试中，我们想要使用这些对象来测试模块的行为以获取对象的确切状态。

要使用模拟对象，我们需要安装一个支持对象模拟的模块。那里有各种类型的测试工具和模块可用。然而，大多数都是设计用于测试 JavaScript 客户端功能。有一些模块，比如 JsMockito，这是 Java 著名 Mockito 框架的 JavaScript 版本，还有 node-inspector，这是一个提供 JavaScript 调试器的模块，它会在 Google Chrome 浏览器中隐式启动。

对于 Chrome 浏览器的本地支持是合理的，因为 Node.js 是构建在 Google V8 JavaScript 引擎之上的。由于我们正在开发服务器端应用程序，这些并不是最方便的工具，因为 JsMockito 不能作为 Node.js 模块进行插件化，并且在浏览器中使用调试器来调试后端应用程序对我来说并不合适。无论如何，如果你打算深入了解 Node.js，你应该一定要试试。

为了测试服务器端 JavaScript 模块，我们将使用 Sinon.JS 模块。像所有其他模块一样，它可以在 npm 仓库中找到，因此执行以下命令来安装它：

```js
npm install -g sinon
```

Sinon.JS 是一个非常灵活的 JavaScript 测试库，提供了对 JavaScript 对象进行模拟、存根和监视的功能。它可以在任何 JavaScript 测试框架中使用，网址是 [`sinonjs.org`](http://sinonjs.org)。让我们看看我们需要什么来测试我们的 HTTP 模块。它导出一个单一方法 `handleRequest`，该方法以 HTTP 请求和响应对象作为参数。基于请求的方法，该模块调用其内部函数来处理不同的请求。每个请求处理程序向响应写入不同的输出。

要在诸如 Nodeunit 这样的隔离环境中测试此功能，我们需要模拟对象，然后将其作为参数传递。为了确保模块的行为符合预期，我们需要访问存储在这些对象中的数据。

# 使用模拟对象

使用模拟对象时需要执行的步骤如下：

1.  使用 `sinon` 作为参数调用 `require` 函数，并从中导出一个 `test` 函数：

```js
var sinon = require('sinon'); 
exports.testAPI(test){...} 
```

1.  如下所示定义要模拟的方法的 API 描述：

```js
var api = {'methodX' : function () {},  
  'methodY' : function() {},  
  'methodZ' : function() {}}; 
```

1.  在导出的函数中使用 `sinon` 来根据 `api` 描述创建模拟对象：

```js
var mock = sinon.mock(api);
```

1.  设置模拟对象的期望。期望是在模拟对象上设置的，描述了模拟方法应该如何行为，它应该接受什么参数，以及它应该返回什么值。当模拟方法以与描述不同的状态调用时，期望在后来验证时将失败：

```js
mock.expects('methodX').once().withArgs('xyz') 
.returns('abc'); 
api.methodX('xyz') 
```

1.  上面的示例期望 `methodX` 被调用一次，并且带有 `xyz` 参数，它将强制该方法返回 `abc`。Sinon.JS 模块使我们能够实现这一点。

调用描述对象的方法，而不是模拟对象的方法。模拟对象用于设置模拟方法的期望，并在后来检查这些期望是否已经实现。

1.  在测试环境中使用模拟对象，然后调用其 `verify()` 方法。该方法将检查被测试代码是否与模拟对象正确交互，即该方法被调用的次数以及是否使用了预期的参数进行调用。如果任何期望未能满足，那么将抛出错误，导致测试失败。

1.  我们的测试模块的导出`test`函数有一个参数。该参数提供了可以用来检查测试条件的断言方法。在我们的示例中，我们模拟了该方法，以便在使用`'xyz'`参数调用时始终返回`abc`。因此，为了完成测试，可以进行以下断言，并且最后需要验证模拟对象：

```js
mock.expects('methodX').once().withArgs('xyz') 
.returns('abc');           
test.equals(api.methodX('xyz'), 'abc'); 
mock.verify(); 
```

1.  尝试修改传递给`methodX`的参数，使其不符合预期，您将看到这会破坏您的测试。

1.  让我们将这些步骤付诸实践，并在`test`目录中创建以下`test-http-module.js`文件：

```js
var sinon = require('sinon');
exports.handleGetRequestTest =  (test) => {
  var response = {'writeHead' : () => {}, 'end': () => {}};
  var responseMock = sinon.mock(response);
    responseMock.expects('end').once().withArgs('Get action was requested');
    responseMock.expects('writeHead').once().withArgs(200, {
      'Content-Type' : 'text/plain'});

  var request = {};
  var requestMock = sinon.mock(request);
  requestMock.method = 'GET';

  var http_module = require('../modules/http-module');
  http_module.handleRequest(requestMock, response);
  responseMock.verify();
  test.done();
};
```

1.  使用 Nodeunit 的`test-http-module.js`开始测试以验证其是否成功通过。您的下一步将是扩展测试，以便覆盖我们的 HTTP 模块中所有 HTTP 方法的处理：

```js
nodeunit test/test-http-module.js 

test-http-module.js
Request processing completed
 handleGetRequestTest

OK: 0 assertions (32ms)
```

# 部署应用程序

Node.js 具有事件驱动的、非阻塞的 I/O 模型，这使其非常适合在分布式环境中良好扩展的实时应用程序，例如公共或私有云平台。每个云平台都提供工具，允许其托管应用程序的无缝部署、分发和扩展。在本节中，我们将看一下两个公开可用的 Node.js 应用程序云提供商——Nodejitsu 和 Microsoft Azure。

但首先，让我们花一些时间来了解集群支持，因为这对于理解为什么 Node.js 非常适合云环境至关重要。Node.js 内置了集群支持。在您的应用程序中使用集群模块允许它们启动尽可能多的工作进程来处理它们将面临的负载。通常建议将工作进程的数量与您的环境的线程数或逻辑核心数匹配。

您的应用程序的核心是主进程。它负责保持活动工作进程的注册表和应用程序的负载，以及如何创建它。当需要时，它还会创建更多的工作进程，并在负载减少时减少它们。

云平台还应确保在部署应用程序的新版本时没有任何停机时间。在这种情况下，主进程需要被通知要分发新版本。它应该 fork 新的工作进程的新应用程序版本，并通知当前使用旧版本的工作进程关闭它们的监听器；因此，它停止接受连接并在完成后优雅地退出。因此，所有新的传入请求将由新启动的工作进程处理，并在过时的工作进程终止后，所有运行中的工作进程将运行最新版本。

# Nodejitsu

让我们更仔细地看一些 Node.js**平台即服务**（**PaaS**）提供。我们将首先看一下 Nodejitsu，可在[`www.nodejitsu.com`](https://www.nodejitsu.com)上找到。

这允许在云上无缝部署 Node.js 应用程序，具有许多有用的功能，用于 Node.js 应用程序的开发、管理、部署和监控。要与 jitsu 交互，您需要安装其命令行界面，该界面可作为 Node.js 模块使用：

```js
npm install -g jitsu 
```

安装 jitsu 并使用`jitsu`启动后，您将受到热烈欢迎，友好的控制台屏幕将向您介绍基本的 jitsu 命令，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/rst-webapi-dsn-node10/img/57d146c5-2355-45cd-a97c-de2762730c20.png)

为了与 jitsu 交互，您需要注册。Jitsu 提供不同的定价计划，以及免费试用服务。

您可以从他们的网站或使用`jitsu signup`命令来执行此操作。然后，您可以开始使用命令行界面提供的工具。

# 微软 Azure

微软的云平台即服务 Azure 也提供 Node.js 应用程序的托管。他们选择了一个略有不同的方法，而不是提供一个命令行界面来与他们的存储库交互，他们利用了他们的 Git 集成；也就是说，您与 Azure 的交互方式与您与任何其他 Git 存储库的交互方式相同。如果您对 Git 不熟悉，我强烈建议您了解更多关于这个分布式源代码版本控制系统的知识。

如果您选择 Azure 作为您的平台，您会发现以下链接非常有用：[`azure.microsoft.com/en-us/develop/nodejs/`](http://azure.microsoft.com/en-us/develop/nodejs/)。

# Heroku

Heroku 是一个公共云服务，允许您管理、部署和扩展 Node.js 应用程序。准备将您的 Node 应用程序适应 Heroku 环境并不需要太多的努力，只要安装其命令行界面，可以在[`devcenter.heroku.com/articles/heroku-cli`](https://devcenter.heroku.com/articles/heroku-cli)或通过您的包管理器获得。

```js
npm install -g heroku-cli
```

您只需在`package.json`文件中提供一个`'start script'`元素，使用`git push master heroku`将其推送到相关的 Git 存储库，然后登录并创建您的应用程序，使用`heroku login`和`heroku create`命令。

# 自测问题

为了对您新获得的知识更有信心，浏览下一组陈述，并说明它们是真还是假：

1.  Node 模块可以向外部组件导出多个函数

1.  Node 模块是可扩展的

1.  模块总是需要明确声明它们对其他模块的依赖关系

1.  在测试环境中使用模拟时，模拟的方法是在模拟对象上调用的

1.  调试 Node.js 代码并不像其他非 JavaScript 代码那样直截了当

# 总结

在本章中，您获得了第一个 Node.js 体验，从一个简单的`Hello world`应用程序开始，然后转移到一个处理传入 HTTP 请求的更复杂的样本 HTTP 服务器应用程序。更加自信地使用 Node.js，您重构了应用程序以使用用户模块，然后使用模拟框架为您的模块创建了单元测试，以消除测试环境中复杂对象的依赖关系。

现在您已经了解了如何处理和测试传入的 HTTP 请求，在下一章中，我们的下一步将是定义典型 Web API 的外观以及如何进行测试。


# 第三章：构建典型的 Web API

我们的第一个草案 API 将是只读版本，并且不支持创建或更新目录中的项目，就像真实世界的应用程序一样。相反，我们将集中在 API 定义本身，并且稍后会担心数据存储。当然，对于向数百万用户公开的数据使用文件存储绝非选择，因此在我们查看现代 NoSQL 数据库解决方案之后，将为我们的应用程序提供数据库层。

我们还将涵盖内容协商的主题，这是一种允许消费者指定请求数据期望格式的机制。最后，我们将看看几种暴露服务不同版本的方式，以防它以不向后兼容的方式发展。

总之，在本章中，您将学习以下内容：

+   如何指定 Web API

+   如何实现路由

+   如何查询您的 API

+   内容协商

+   API 版本控制

在本章之后，您应该能够完全指定一个 RESTful API，并且几乎准备好开始实现真实的 Node.js RESTful 服务。

# 指定 API

项目通常开始的第一件事是定义 API 将公开的操作。根据 REST 原则，操作由 HTTP 方法和 URI 公开。每个操作执行的操作不应违反其 HTTP 方法的自然含义。以下表格详细说明了我们 API 的操作：

| **方法** | **URI** | **描述** |
| --- | --- | --- |
| `GET` | `/category` | 检索目录中所有可用类别。 |
| `GET` | `/category/{category-id}/` | 检索特定类别下所有可用项目。 |
| `GET`  |  `/category/{category-id}/{item-id}`  | 通过其 ID 在特定类别下检索项目。 |
| `POST` | `/category` | 创建一个新类别；如果存在，它将对其进行更新。 |
| `POST`  | `/category/{category-id}/`  | 在指定类别中创建一个新项目。如果项目存在，它将对其进行更新。 |
| `PUT`  |  `/category/{category-id}`  | 更新类别。 |
| `PUT` | `/category/{category-id}/{item-id}` | 更新指定类别中的项目。 |
| `DELETE` | `/category/{category-id}` | 删除现有类别。 |
| `DELETE` | `/category/{category-id}/{item-id}` | 删除指定类别中的项目。 |

第二步是为我们的目录应用程序的数据选择适当的格式。JSON 对象受 JavaScript 的本地支持。它们在应用程序演变期间易于扩展，并且几乎可以被任何可用的平台消耗。因此，JSON 格式似乎是我们的逻辑选择。这是本书中将使用的项目和类别对象的 JSON 表示：

```js
{ 
    "itemId": "item-identifier-1", 
    "itemName": "Sports Watch", 
    "category": "Watches", 
    "categoryId": 1,
    "price": 150, 
    "currency": "EUR"
} 

{
    "categoryName" : "Watches",
    "categoryId" : "1",
    "itemsCount" : 100,
    "items" : [{
            "itemId" : "item-identifier-1",
            "itemName":"Sports Watch",
            "price": 150,
            "currency" : "EUR"    
     }]
}
```

到目前为止，我们的 API 已经定义了一组操作和要使用的数据格式。下一步是实现一个模块，该模块将导出为路由中的每个操作提供服务的函数。

首先，让我们创建一个新的 Node.js Express 项目。选择一个存储项目的目录，并从您的 shell 终端中执行`express chapter3`。如果您使用 Windows，您需要在生成项目之前安装`express-generator`模块。`express-generator`将在所选目录中创建初始的 express 项目布局。该布局为您提供了默认的项目结构，确保您的 Express 项目遵循标准的项目结构。这使得您的项目更容易导航。

下一步是将项目导入 Atom IDE。在项目选项卡中的任何位置右键单击，然后选择“添加项目文件夹”，然后选择 Express 为您生成的目录。

正如您所看到的，Express 已经为我们做了一些后台工作，并为我们创建了应用程序的起点：`app.js`。它还为我们创建了`package.json`文件。让我们从`package.json`开始查看这些文件中的每一个：

```js
{
  "name": "chapter3",
  "version": "1.0.0",
  "description": "",
  "main": "app.js",
  "scripts": {
    "test": "test"
  },
  "author": "",
  "license": "ISC",
  "dependencies": {
 "dependencies": {
    "body-parser": "~1.13.2",
    "cookie-parser": "~1.3.5",
    "debug": "~2.2.0",
    "express": "~4.16.1",
    "jade": "~1.11.0",
    "morgan": "~1.6.1",
    "serve-favicon": "~2.3.0"

  }
}
```

当我们创建一个空白的 Node.js Express 项目时，我们最初只依赖于 Express 框架，一些中间件模块，如`morgan`、`body-parser`和`cookie-parser`，以及 Jade 模板语言。Jade 是一种简单的模板语言，用于在模板中生成 HTML 代码。如果您对此感兴趣，可以在[`www.jade-lang.com`](http://www.jade-lang.com/)了解更多信息。

撰写时，Express 框架的当前版本是 4.16.1；要更新它，请从`chapter3`目录执行`npm install express@4.16.1 --save`。此命令将更新应用程序对所需版本的依赖。`--save`选项将更新并保存项目的`package.json`文件中的新版本依赖。

当您引入新的模块依赖项时，您需要保持`package.json`文件的最新状态，以便维护应用程序所依赖的模块的准确状态。

我们稍后会讲解中间件模块是什么。

目前，我们将忽略`public`和`view`目录的内容，因为它与我们的 RESTful 服务无关。它们包含了自动生成的样式表和模板文件，如果我们决定在以后阶段开发基于 Web 的服务消费者，这些文件可能会有所帮助。

我们已经提到 Express 项目在`app.js`中为我们的 Web 应用程序创建了一个起点。让我们深入了解一下：

```js
var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');

var routes = require('./routes/index');
var users = require('./routes/users');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', routes);
app.use('/users', users);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
      message: err.message,
      error: err
    });
  });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
    message: err.message,
    error: {}
  });
});

module.exports = app;
```

显然，Express 生成器为我们做了很多工作，它实例化了 Express 框架，并为其分配了完整的开发环境。它做了以下工作：

+   配置了在我们的应用程序中使用的中间件，`body-parser`、默认路由器，以及我们的开发环境的错误处理中间件

+   注入了 morgan 中间件模块的日志记录器实例

+   配置了 Jade 模板，因为它已被选为我们应用程序的默认模板

+   配置了我们的 Express 应用程序将监听的默认 URI，`/`和`/users`，并为它们创建了虚拟的处理函数

您需要安装`app.js`中使用的所有模块，以便成功启动生成的应用程序。此外，在安装它们后，请确保使用`--save`选项更新您的`package.json`文件的依赖项。

Express 生成器还为应用程序创建了一个起始脚本。它位于项目的`bin/www`目录下，看起来像下面的片段：

```js
#!/usr/bin/env node

/**
 * Module dependencies.
 */

var app = require('../app');
var debug = require('debug')('chapter3:server');
var http = require('http');

/**
 * Get port from environment and store in Express.
 */

var port = normalizePort(process.env.PORT || '3000');
app.set('port', port);

/**
 * Create HTTP server.
 */

var server = http.createServer(app);

/**
 * Listen on provided port, on all network interfaces.
 */

server.listen(port);
server.on('error', onError);
server.on('listening', onListening);

/**
 * Normalize a port into a number, string, or false.
 */

function normalizePort(val) {
  var port = parseInt(val, 10);

  if (isNaN(port)) {
    // named pipe
    return val;
  }

  if (port >= 0) {
    // port number
    return port;
  }

  return false;
}

/**
 * Event listener for HTTP server "error" event.
 */

function onError(error) {
  if (error.syscall !== 'listen') {
    throw error;
  }

  var bind = typeof port === 'string'
    ? 'Pipe ' + port
    : 'Port ' + port;

  // handle specific listen errors with friendly messages
  switch (error.code) {
    case 'EACCES':
      console.error(bind + ' requires elevated privileges');
      process.exit(1);
      break;
    case 'EADDRINUSE':
      console.error(bind + ' is already in use');
      process.exit(1);
      break;
    default:
      throw error;
  }
}

/**
 * Event listener for HTTP server "listening" event.
 */

function onListening() {
  var addr = server.address();
  var bind = typeof addr === 'string'
    ? 'pipe ' + addr
    : 'port ' + addr.port;
  debug('Listening on ' + bind);
}
```

要启动应用程序，请执行`node bin/www`；这将执行上面的脚本，并启动 Node.js 应用程序。因此，在浏览器中请求`http://localhost:3000`将导致调用默认的`GET`处理程序，它会给出一个热烈的欢迎响应：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/rst-webapi-dsn-node10/img/6edf1a93-d7b2-4d91-8d56-7c73ec1628d1.png)

Express 应用程序的默认欢迎消息

生成器创建了一个虚拟的`routes/users.js`；它公开了一个与`/users`位置上的虚拟模块相关联的路由。请求它将导致调用用户路由的`list`函数，该函数输出一个静态响应：`respond with a resource`。

我们的应用程序将不使用模板语言和样式表，因此让我们摆脱在应用程序配置中设置视图和视图引擎属性的行。此外，我们将实现自己的路由。因此，我们不需要为我们的应用程序绑定`/`和`/users`的 URI，也不需要`user`模块；相反，我们将利用`catalog`模块和一个路由：

```js
var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');

var routes = require('./routes/index');
var catalog = require('./routes/catalog')
var app = express();

//uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', routes);
app.use('/catalog', catalog);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

//development error handler will print stacktrace
if (app.get('env') === 'development') {
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
      message: err.message,
      error: err
    });
  });
}

// production error handler no stacktraces leaked to user
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
    message: err.message,
    error: {}
  });
});

module.exports = app;

```

经过这次清理之后，我们的应用程序看起来更加整洁，我们准备继续前进。

在这之前，有一个术语需要进一步解释：中间件。它是由`Express.js`路由层调用的一组链式函数的子集，在调用用户定义的处理程序之前。中间件函数可以完全访问`request`和`response`对象，并且可以修改它们中的任何一个。中间件链总是按照定义的确切顺序调用，因此您需要确切知道特定中间件正在做什么。一旦中间件函数完成，它通过调用其下一个参数作为函数来调用链中的下一个函数。在完整的链执行完毕后，将调用用户定义的请求处理程序。

以下是适用于中间件链的基本规则：

+   中间件函数具有以下签名：`function (request, response, next)`。

+   中间件函数按照它们被添加到应用程序链中的确切顺序执行。这意味着如果您希望在特定路由之前调用您的中间件函数，您需要在声明路由之前添加它。

+   中间件函数使用它们的第三个参数`next`作为函数来指示它们已完成工作并退出。当调用链中最后一个函数的`next()`参数时，链式执行完成，并且`request`和`response`对象以中间件设置的状态到达定义的处理程序。

现在我们知道了中间件函数是什么，让我们澄清当前使用的中间件函数为我们的应用程序提供了什么。`body-parser`中间件是 Express 框架内置的解析器。它解析`request`体，并在中间件执行完成后填充`request`对象，即提供 JSON 负载处理。

现在是时候继续实现我们的用户模块，该模块将映射到我们的 URI。该模块将命名为`modules/catalog.js`：

```js
var fs = require('fs');

function readCatalogSync() {
   var file = './data/catalog.json';
   if (fs.existsSync(file)) {
     var content = fs.readFileSync(file);
     var catalog = JSON.parse(content);
     return catalog;
   }
   return undefined;
 }

exports.findItems = function(categoryId) {
  console.log('Returning all items for categoryId: ' + categoryId);
  var catalog = readCatalogSync();
  if (catalog) {
    var items = [];
    for (var index in catalog.catalog) {
        if (catalog.catalog[index].categoryId === categoryId) {
          var category = catalog.catalog[index];
          for (var itemIndex in category.items) {
            items.push(category.items[itemIndex]);
          }
        }
    }
    return items;
  }
  return undefined;
}

exports.findItem = function(categoryId, itemId) {
  console.log('Looking for item with id' + itemId);
  var catalog = readCatalogSync();
  if (catalog) {
    for (var index in catalog.catalog) {
        if (catalog.catalog[index].categoryId === categoryId) {
          var category = catalog.catalog[index];
          for (var itemIndex in category.items) {
            if (category.items[itemIndex].itemId === itemId) {
              return category.items[itemIndex];
            }
          }
        }
    }
  }
  return undefined;
}

exports.findCategoryies = function() {
  console.log('Returning all categories');
  var catalog = readCatalogSync();
  if (catalog) {
    var categories = [];
    for (var index in catalog.catalog) {
        var category = {};
        category["categoryId"] = catalog.catalog[index].categoryId;
        category["categoryName"] = catalog.catalog[index].categoryName;

        categories.push(category);
    }
    return categories;
  }
  return [];
}
```

目录模块围绕存储在`data`目录中的`catalog.json`文件构建。源文件的内容使用文件系统模块`fs`在`readCatalogSync`函数内同步读取。文件系统模块提供多个有用的文件系统操作，如创建、重命名或删除文件或目录的函数；截断；链接；`chmod`函数；以及用于读取和写入数据的同步和异步文件访问。在我们的示例应用程序中，我们旨在使用最直接的方法，因此我们实现了利用文件系统模块的`readFileSync`函数读取`catalog.json`文件的函数。它以同步调用的方式将文件内容作为字符串返回。模块的所有其他函数都被导出，并可用于根据不同的条件查询源文件的内容。

目录模块导出以下函数：

+   `findCategories`: 返回包含`catalog.json`文件中所有类别的 JSON 对象数组

+   `findItems (categoryId)`: 返回表示给定类别中所有项目的 JSON 对象数组

+   `findItem(categoryId, itemId)`: 返回表示给定类别中单个项目的 JSON 对象

现在我们有了三个完整的函数，让我们看看如何将它们绑定到我们的 Express 应用程序。

# 实现路由

在 Node.js 术语中，路由是 URI 和函数之间的绑定。Express 框架提供了对路由的内置支持。一个`express`对象实例包含了每个 HTTP 动词命名的函数：`get`、`post`、`put`和`delete`。它们的语法如下：`function(uri, handler);`。它们用于将处理程序函数绑定到在 URI 上执行的特定 HTTP 动作。处理程序函数通常接受两个参数：`request`和`response`。让我们通过一个简单的`Hello route`应用程序来看一下：

```js
var express = require('express'); 
var app = express(); 

app.get('/hello', function(request, response){ 
  response.send('Hello route'); 
}); 

app.listen(3000); 
```

在本地主机上运行此示例并访问`http://localhost:3000/hello`将调用您的处理程序函数，并且它将响应说`Hello route`，但路由可以提供更多。它允许您定义带参数的 URI；例如，让我们使用`/hello/:name`作为路由字符串。它告诉框架所使用的 URI 由两部分组成：一个静态部分（`hello`）和一个变量部分（`name`参数）。

此外，当路由字符串和处理函数与 Express 实例的`get`函数一起定义时，在处理程序函数的`request`参数中直接提供了参数集合。为了证明这一点，让我们稍微修改我们之前的例子：

```js
var express = require('express'); 
var app = express(); 

app.get('/hello:name', function(request, response){ 
  response.send('Hello ' + request.params.name); 
}); 

app.listen(3000); 
```

如您在上述代码片段中所见，我们使用冒号（`:`）将 URI 的参数部分与静态部分分开。您可以在 Express 路由中有多个参数；例如，`/category/:category-id/items/:item-id`定义了一个用于显示属于类别的项目的路由，其中`category-id`和`item-id`是参数。

现在让我们试一下。请求`http://localhost:3000/hello/friend`将导致以下输出：

```js
hello friend
```

这就是我们如何在 Express 中提供参数化的 URI。这是一个很好的功能，但通常还不够。在 Web 应用程序中，我们习惯使用`GET`参数提供额外的参数。

不幸的是，Express 框架对`GET`参数的支持并不是很好。因此，我们必须利用`url`模块。它内置在 Node.js 中，提供了一种使用 URL 解析的简单方法。让我们再次在应用程序中使用我们的`hello`结果和其他参数，但以一种方式扩展它，使其在请求`/hello`时输出`hello all`，在请求的 URI 为`/hello?name=friend`时输出`hello friend`：

```js
var express = require('express'); 
var url = require('url'); 
var app = express(); 

app.get('/hello', function(request, response){ 
   var getParams = url.parse(request.url, true).query; 

   if (Object.keys(getParams).length == 0) {       
      response.end('Hello all');    
   } else {
      response.end('Hello ' + getParams.name); 
   }    
}); 

app.listen(3000); 
```

这里有几件值得一提的事情。我们使用了`url`模块的`parse`函数。它以 URL 作为第一个参数，以布尔值作为可选的第二个参数，指定是否应解析查询字符串。`url.parse`函数返回一个关联对象。我们使用`Object.keys`将其与关联对象中的键转换为数组，以便我们可以检查其长度。这将帮助我们检查我们的 URI 是否已使用`GET`参数调用。除了以每个 HTTP 动词命名的路由函数之外，还有一个名为`all`的函数。当使用时，它将所有 HTTP 动作路由到指定的 URI。

现在我们知道了在 Node.js 和 Express 环境中路由和`GET`参数的工作原理，我们准备为`catalog`模块定义一个路由并将其绑定到我们的应用程序中。以下是在`routes/catalog.js`中定义的路由。

```js
var express = require('express');
var catalog = require('../modules/catalog.js')

var router = express.Router();

router.get('/', function(request, response, next) {
  var categories = catalog.findCategoryies();
  response.json(categories);
});

router.get('/:categoryId', function(request, response, next) {
  var categories = catalog.findItems(request.params.categoryId);
  if (categories === undefined) {
    response.writeHead(404, {'Content-Type' : 'text/plain'});
    response.end('Not found');
  } else {
    response.json(categories);
  }
});

router.get('/:categoryId/:itemId', function(request, response, next) {
  var item = catalog.findItem(request.params.categoryId, request.params.itemId);
  if (item === undefined) {
    response.writeHead(404, {'Content-Type' : 'text/plain'});
    response.end('Not found');
  } else {
  response.json(item);
  }
});
module.exports = router;

```

首先，从 Express 模块创建了一个`Router`实例。下面是一个很好描述我们刚刚实现的路由的表格。这将在我们测试 API 时很有帮助：

| **HTTP 方法** | **路由** | **目录模块函数** |
| --- | --- | --- |
| `GET` | `/catalog` | `findCategories()` |
| `GET` | `/catalog/:categoryId` | `findItems(categoryId)`  |
| `GET` | `/catalog/:categoryId/:itemId` | `findItem(categoryId, itemId)`  |

# 使用测试数据查询 API

我们需要一些测试数据来测试我们的服务，所以让我们使用项目的`data`目录中的`catalog.json`文件。这些数据将允许我们测试我们的三个函数，但为了做到这一点，我们需要一个可以针对端点发送 REST 请求的客户端。如果您还没有为测试应用程序创建 Postman 项目，现在是创建它的合适时机。

请求`/catalog`应该返回`test`文件中的所有类别：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/rst-webapi-dsn-node10/img/dbb3692b-d7fe-4b4d-8296-edaa181a5a7e.png)

因此，请求`/catalog/1`应该返回属于`Watches`类别的所有项目的列表：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/rst-webapi-dsn-node10/img/e2930458-a2e5-4167-a9a6-e1302dc820ae.png)

最后，请求`http://localhost:3000/catalog/1/item-identifier-1`将仅显示由`item-identifier-1`标识的项目，请求不存在的项目将导致状态码`404`的响应：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/rst-webapi-dsn-node10/img/136fe902-939f-4458-bcfb-a58d74b7ddba.png)

# 内容协商

到目前为止，目录服务仅支持 JSON 格式，因此仅使用媒体类型`application/json`。假设我们的服务必须以不同的格式提供数据，例如 JSON 和 XML。然后，消费者需要明确定义他们需要的数据格式。在 REST 中进行内容协商的最佳方式长期以来一直是一个备受争议的话题。

在他关于正确实施内容协商的著名讨论中，罗伊·菲尔丁陈述了以下观点：

所有重要资源都必须有 URI。

然而，这留下了如何以不同的数据格式公开相同资源的空白，因此罗伊继续如下：

代理驱动的谈判效果更好，但我和 HTTP 工作组主席之间存在巨大分歧，我的 HTTP/1.1 的原始代理驱动设计实际上被委员会埋没了。为了正确进行谈判，客户端需要了解所有的替代方案以及应该用作书签的内容。

虽然可以选择继续使用 URI 驱动的谈判，通过提供自定义的`GET`参数来提供所需的格式，但 REST 社区选择坚持罗伊的代理驱动谈判建议。现在距离这场争论开始已经将近十年了，已经证明他们做出了正确的决定。代理驱动的谈判使用`Accept` HTTP 头。

`Accept` HTTP 头指定了消费者愿意处理的资源的媒体类型。除了`Accept`头之外，消费者还可以使用`Accept-Language`和`Accept-Encoding`头来指定结果应该提供的语言和编码。如果服务器未能以预期的格式提供结果，它可以返回默认值，或者使用`HTTP 406 Not acceptable`，以避免在客户端引起数据混淆错误。

Node.js 的 HTTP `response`对象包含一个名为`format`的方法，该方法基于`request`对象中设置的`Accept` HTTP 头执行内容协商。它使用内置的`request.accepts()`来为请求选择适当的处理程序。如果找不到，服务器将调用默认处理程序，该处理程序将返回`HTTP 406 Not acceptable`。让我们创建一个演示，演示如何在我们的路由中使用`format`方法。为此，让我们假设我们在我们的`catalog`模块中实现了一个名为`list_groups_in_xml`的函数，该函数以 XML 格式提供组数据：

```js
app.get('/catalog', function(request, response) { 
    response.format( { 
      'text/xml' : function() { 
         response.send(catalog.findCategoiesXml()); 
      }, 
      'application/json' : function() { 
         response.json(catalog.findCategoriesJson()); 
      }, 
      'default' : function() {. 
         response.status(406).send('Not Acceptable'); 
      }    
    }); 
}); 
```

这是您可以以清晰简单的方式实施内容协商的方法。

# API 版本控制

不可避免的事实是，所有应用程序 API 都在不断发展。然而，具有未知数量的消费者的公共 API 的演变，例如 RESTful 服务，是一个敏感的话题。由于消费者可能无法适当处理修改后的数据，并且没有办法通知所有消费者，我们需要尽可能保持 API 的向后兼容性。其中一种方法是为我们应用程序的不同版本使用不同的 URI。目前，我们的目录 API 在`/catalog`上可用。

当时机成熟，例如，版本 2 时，我们可能需要保留以前的版本在另一个 URI 上以实现向后兼容。最佳做法是在 URI 中编码版本号，例如`/v1/catalog`，并将`/catalog`映射到最新版本。因此，请求`/catalog`将导致重定向到`/v2/catalog`，并将使用 HTTP `3xx`状态代码指示重定向到最新版本。

另一个版本控制的选项是保持 API 的 URI 稳定，并依赖自定义的 HTTP 标头来指定版本。但这并不是一个非常稳定的方法，因为与其在请求中修改发送的标头，不如在应用程序中修改请求的 URL 更自然。

# 自测问题

为了获得额外的信心，请浏览这组陈述，并说明它们是真还是假：

1.  REST 启用的端点必须支持与 REST 原则相关的所有 HTTP 方法。

1.  当内容协商失败时，由于接受标头的值作为不支持的媒体类型，301 是适当的状态代码。

1.  在使用参数化路由时，开发人员可以指定参数的类型，例如，它是数字类型还是文字类型。

# 总结

在本章中，我们深入了一些更复杂的主题。让我们总结一下我们所涵盖的内容。我们首先指定了我们的 Web API 的操作，并定义了操作是 URI 和 HTTP 动作的组合。接下来，我们实现了路由并将它们绑定到一个操作。然后，我们使用 Postman REST 客户端请求每个操作以请求我们路由的 URI。在内容协商部分，我们处理了`Accept` HTTP 标头，以便按照消费者请求的格式提供结果。最后，我们涵盖了 API 版本的主题，这使我们能够开发向后兼容的 API。

在本章中，我们对我们的数据使用了老式的文件系统存储。这对于 Web 应用程序来说并不合适。因此，我们将在下一章中研究现代、可扩展和可靠的 NoSQL 存储。


# 第四章：使用 NoSQL 数据库

在上一章中，我们实现了一个暴露只读服务的示例应用程序，提供了目录数据。为了简单起见，我们通过使用文件存储在这个实现中引入了性能瓶颈。这种存储不适合 Web 应用程序。它依赖于 33 个物理文件，阻止我们的应用程序为重负载提供服务，因为文件存储由于磁盘 I/O 操作而缺乏多租户支持。换句话说，我们绝对需要寻找更好的存储解决方案，当需要时可以轻松扩展，以满足我们的 REST 应用程序的需求。NoSQL 数据库现在在 Web 和云环境中被广泛使用，确保零停机和高可用性。它们比传统的事务 SQL 数据库具有以下优势：

+   它们支持模式版本；也就是说，它们可以使用对象表示而不是根据一个或多个表的定义填充对象状态。

+   它们是可扩展的，因为它们存储了一个实际的对象。数据演变得到了隐式支持，所以您只需要调用存储修改后对象的操作。

+   它们被设计为高度分布式和可扩展的。

几乎所有现代 NoSQL 解决方案都支持集群，并且可以随着应用程序的负载进一步扩展。此外，它们中的大多数都具有基于 HTTP 的 REST 接口，可以在高可用性场景中通过负载均衡器轻松使用。传统的数据库驱动程序通常不适用于传统的客户端语言，如 JavaScript，因为它们需要本机库或驱动程序。然而，NoSQL 的理念起源于使用文档数据存储。因此，它们中的大多数都支持 JavaScript 的本机 JSON 格式。最后但并非最不重要的是，大多数 NoSQL 解决方案都是开源的，并且可以免费使用，具有开源项目提供的所有好处：社区、示例和自由！

在本章中，我们将介绍 MongoDB NoSQL 数据库和与之交互的 Mongoose 模块。我们将看到如何为数据库模型设计和实现自动化测试。最后，在本章末尾，我们将消除文件存储的瓶颈，并将我们的应用程序移至几乎可以投入生产的状态。

# MongoDB - 一个文档存储数据库

MongoDB 是一个具有内置对 JSON 格式支持的开源文档数据库。它提供了对文档中任何可用属性的完整索引支持。由于其可扩展性特性，它非常适合高可用性场景。MongoDB，可在[`mms.mongodb.com`](https://mms.mongodb.com/)找到，具有其管理服务**MongoDB 管理服务**（MMS）。它们利用和自动化大部分需要执行的开发操作，以保持您的云数据库良好运行，负责升级、进一步扩展、备份、恢复、性能和安全警报。

让我们继续安装 MongoDB。Windows、Linux、macOS 和 Solaris 的安装程序可在[`www.mongodb.org/downloads`](http://www.mongodb.org/downloads)找到。Linux 用户可以在所有流行的发行版存储库中找到 MongoDB，而 Windows 用户可以使用用户友好的向导来指导您完成安装步骤，对于典型的安装，您只需要接受许可协议并提供安装路径。

安装成功后，执行以下命令启动 MongoDB。如果要指定数据的自定义位置，必须使用`--dbpath`参数。可选地，您可以通过`--rest`参数启动 MongoDB HTTP 控制台：

```js
mongod --dbpath ./data --rest
```

与 MongoDB 通信的默认端口是`27017`，其 HTTP 控制台隐式配置为使用比数据端口高 1,000 的端口。因此，控制台的默认端口将是`28017`。HTTP 控制台提供有关数据库的有用信息，例如日志、健康状态、可用数据库等。我强烈建议您花一些时间了解它。控制台还可以用作数据库的 RESTful 健康检查服务，因为它提供有关运行中的数据库服务和上次发生的错误的 JSON 编码信息：

```js
GET /replSetGetStatus?text=1 HTTP/1.1
Host: localhost:28017
Connection: Keep-Alive
User-Agent: RestClient-Tool

HTTP/1.0 200 OK
Content-Length: 56
Connection: close
Content-Type: text/plain;charset=utf-8

{
"ok": 0,
"errmsg": "not running with --replSet"
}
```

此 REST 接口可用于脚本或应用程序，以自动更改通知，提供数据库引擎的当前状态等。

控制台的日志部分显示您的服务器是否成功运行（如果是）。现在我们准备进一步了解如何将 Node.js 连接到 MongoDB。

# 使用 Mongoose 进行数据库建模

**Mongoose**是一个将 Node.js 连接到 MongoDB 的模块，采用**对象文档映射器**（**ODM**）风格。它为存储在数据库中的文档提供了**创建、读取、更新和删除**（也称为**CRUD**）功能。Mongoose 使用模式定义文档的结构。模式是 Mongoose 中数据定义的最小单元。模型是根据模式定义构建的。它是一个类似构造函数的函数，可用于创建或查询文档。文档是模型的实例，并表示与存储在 MongoDB 中的文档一一映射。模式-模型-文档层次结构提供了一种自描述的定义对象的方式，并允许轻松进行数据验证。

让我们从使用`npm`安装 Mongoose 开始：

```js
npm install mongoose
```

现在我们已经安装了 Mongoose 模块，我们的第一步将是定义一个将在目录中表示项目的模式：

```js
var mongoose = require('mongoose'); 
var Schema = mongoose.Schema;
var itemSchema = new Schema ({
    "itemId" : {type: String, index: {unique: true}},
    "itemName": String,
    "price": Number,
    "currency" : String,
    "categories": [String]
}); 
```

上面的代码片段创建了一个项目的模式定义。定义模式很简单，与 JSON 模式定义非常相似；您必须描述并附加其类型，并可选择为每个键提供附加属性。在目录应用程序的情况下，我们需要使用`itemId`作为唯一索引，以避免具有相同 ID 的两个不同项目。因此，除了将其类型定义为`String`之外，我们还使用`index`属性来描述`itemId`字段的值必须对于每个单独的项目是唯一的。

Mongoose 引入了术语**模型**。模型是根据模式定义编译出的类似构造函数的函数。模型的实例表示可以保存到数据库中或从数据库中读取的文档。通过调用`mongoose`实例的`model`函数并传递模型应该使用的模式来创建模型实例：

```js
var CatalogItem = mongoose.model('Item', itemSchema);
```

模型还公开了用于查询和数据操作的函数。假设我们已经初始化了一个模式并创建了一个模型，将新项目存储到 MongoDB 就像创建一个新的`model`实例并调用其`save`函数一样简单：

```js
var mongoose = require('mongoose');

mongoose.connect('mongodb://localhost/catalog');
var db = mongoose.connection;

db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', function() {
  var watch = new CatalogItem({
    itemId: 9 ,
    itemName: "Sports Watch1",
    brand: 'А1',
    price: 100,
    currency: "EUR",
    categories: ["Watches", "Sports Watches"]
  });

  watch.save((error, item, affectedNo)=> {
    if (!error) {
      console.log('Item added successfully to the catalog');
    } else {
      console.log('Cannot add item to the catlog');
    }
  });
});

db.once('open', function() {
  var filter = {
    'itemName' : 'Sports Watch1',
    'price': 100
  }

  CatalogItem.find(filter, (error, result) => {
    if (error) {
      consoloe.log('Error occured');
    } else {
      console.log('Results found:'+ result.length);
      console.log(result);
    }
  });
});

```

以下是如何使用模型来查询表示属于`Watches`组的运动手表的文档的方法：

```js
db.once('open', function() {
  var filter = {
    'itemName' : 'Sports Watch1',
    'price': 100
  }
  CatalogItem.findOne(filter, (error, result) => {
    if (error) {
      consoloe.log('Error occurred');
    } else {
      console.log(result);
    }
  });
});
```

模型还公开了`findOne`函数，这是一种方便的方法，可以通过其唯一索引查找对象，然后对其进行一些数据操作，即删除或更新操作。以下示例删除了一个项目：

```js
CatalogItem.findOne({itemId: 1 }, (error, data) => { 
  if (error) {  
    console.log(error); 
    return; 
  } else { 
    if (!data) { 
    console.log('not found'); 
      return; 
    } else { 
      data.remove(function(error){ 
        if (!error) { data.remove();} 
        else { console.log(error);} 
        }); 
      } 
    } 
 });
```

# 使用 Mocha 测试 Mongoose 模型

Mocha 是 JavaScript 中最流行的测试框架之一；它的主要目标是提供一种简单的方法来测试异步 JavaScript 代码。让我们全局安装 Mocha，以便将来可以在任何 Node.js 应用程序中使用它：

```js
npm install -g mocha
```

我们还需要一个断言库，可以与 Mocha 一起使用。断言库提供了用于验证实际值与预期值的函数，当它们不相等时，断言库将导致测试失败。`Should.js`断言库模块易于使用，这将是我们的选择，因此让我们也全局安装它：

```js
npm install -g should
```

现在我们已经安装了测试模块，需要在`package.json`文件中指定我们的`testcase`文件路径。让我们通过在脚本节点中添加指向 Mocha 和`testcase`文件的`test`元素来修改它：

```js
{ 
"name": "chapter4", 
"version": "0.0.0", 
"private": true, 
"scripts": { 
"start": "node ./bin/www", 
"test": "mocha test/model-test.js" 
 }, 
"dependencies": { 
"body-parser": "~1.13.2", 
"cookie-parser": "~1.3.5", 
"debug": "~2.2.0", 
"express": "~4.16.0", 
"jade": "~1.11.0", 
"morgan": "~1.6.1", 
"serve-favicon": "~2.3.0" 
 } 
} 
```

这将告诉 npm 包管理器在执行`npm`测试时触发 Mocha。

Mongoose 测试的自动化不得受到数据库当前状态的影响。为了确保每次测试运行时结果是可预测的，我们需要确保数据库状态与我们期望的完全一致。我们将在`test`目录中实现一个名为`prepare.js`的模块。它将在每次测试运行之前清除数据库：

```js
var mongoose = require('mongoose');
beforeEach(function (done) {
  function clearDatabase() {
    for (var i in mongoose.connection.collections) {
      mongoose.connection.collections[i].remove(function() 
      {});
    }
    return done();
  }
  if (mongoose.connection.readyState === 0) {
    mongoose.connect(config.db.test, function (err) {
      if (err) {
        throw err;
      }
      return clearDatabase();
    });
  } else {
    return clearDatabase();
  }
});
afterEach(function (done) {
  mongoose.disconnect();
  return done();
});
```

接下来，我们将实现一个 Mocha 测试，用于创建一个新项目：

```js
var mongoose = require('mongoose');
var should = require('should');
var prepare = require('./prepare');

const model = require('../model/item.js');
const CatalogItem = model.CatalogItem;

mongoose.createConnection('mongodb://localhost/catalog');

describe('CatalogItem: models', function () {
  describe('#create()', function () {
    it('Should create a new CatalogItem', function (done) {

      var item = {
        "itemId": "1",
        "itemName": "Sports Watch",
        "price": 100,
        "currency": "EUR",
        "categories": [
          "Watches",
          "Sports Watches"
        ]

      };

      CatalogItem.create(item, function (err, createdItem) {
        // Check that no error occured
        should.not.exist(err);
        // Assert that the returned item has is what we expect

        createdItem.itemId.should.equal('1');
        createdItem.itemName.should.equal('Sports Watch');
        createdItem.price.should.equal(100);
        createdItem.currency.should.equal('EUR');
        createdItem.categories[0].should.equal('Watches');
        createdItem.categories[1].should.equal('Sports Watches');
        //Notify mocha that the test has completed
        done();
      });
    });
  });
});
```

现在执行`npm test`将导致针对 MongoDB 数据库的调用，从传递的 JSON 对象创建一个项目。插入后，assert 回调将被执行，确保由 Mongoose 传递的值与数据库返回的值相同。尝试一下，打破测试-只需在断言中将预期值更改为无效值-您将看到测试失败。

# 围绕 Mongoose 模型创建用户定义的模型

看到模型如何工作后，现在是时候创建一个用户定义的模块，用于包装目录的所有 CRUD 操作。由于我们打算在 RESTful web 应用程序中使用该模块，因此将模式定义和模型创建留在模块外，并将它们作为每个模块函数的参数提供。相同的模式定义在单元测试中使用，确保模块的稳定性。现在让我们为每个 CRUD 函数添加一个实现，从`remove()`函数开始。它根据其`id`查找项目并从数据库中删除它（如果存在）：

```js
exports.remove = function (request, response) {
  console.log('Deleting item with id: '    + request.body.itemId);
  CatalogItem.findOne({itemId: request.params.itemId}, function(error, data) {
      if (error) {
          console.log(error);
          if (response != null) {
              response.writeHead(500, contentTypePlainText);
              response.end('Internal server error');
          }
          return;
      } else {
          if (!data) {
              console.log('Item not found');
              if (response != null) {
                  response.writeHead(404, contentTypePlainText);
                  response.end('Not Found');
              }
              return;
          } else {
              data.remove(function(error){
                  if (!error) {
                      data.remove();
                      response.json({'Status': 'Successfully deleted'});
                  }
                  else {
                      console.log(error);
                      response.writeHead(500, contentTypePlainText);
                      response.end('Internal Server Error');
                  }
              });
          }
      }
  });
}
```

`saveItem()`函数将请求体有效负载作为参数。有效的更新请求将包含以 JSON 格式表示的`item`对象的新状态。首先，从 JSON 对象中解析出`itemId`。接下来进行查找。如果项目存在，则进行更新。否则，创建一个新项目：

```js
exports.saveItem = function(request, response)
{
  var item = toItem(request.body);
  item.save((error) => {
    if (!error) {
      item.save();
      response.writeHead(201, contentTypeJson);
      response.end(JSON.stringify(request.body));
    } else {
      console.log(error);
      CatalogItem.findOne({itemId : item.itemId    },
      (error, result) => {
        console.log('Check if such an item exists');
            if (error) {
                console.log(error);
                response.writeHead(500, contentTypePlainText);
                response.end('Internal Server Error');
            } else {
                if (!result) {
                    console.log('Item does not exist. Creating a new one');
                    item.save();
                    response.writeHead(201, contentTypeJson);
                    response.
                    response.end(JSON.stringify(request.body));
                } else {
                    console.log('Updating existing item');
                    result.itemId = item.itemId;
                    result.itemName = item.itemName;
                    result.price = item.price;
                    result.currency = item.currency;
                    result.categories = item.categories;
                    result.save();
                    response.json(JSON.stringify(result));
                }
           }
      });
    }
  });
};
```

`toItem()`函数将 JSON 有效负载转换为`CatalogItem`模型实例，即一个项目文档：

```js
function toItem(body) {
    return new CatalogItem({
        itemId: body.itemId,
        itemName: body.itemName,
        price: body.price,
        currency: body.currency,
        categories: body.categories
    });
}
```

我们还需要提供一种查询数据的方法，因此让我们实现一个查询特定类别中所有项目的函数：

```js
exports.findItemsByCategory = function (category, response) {
    CatalogItem.find({categories: category}, function(error, result) {
        if (error) {
            console.error(error);
            response.writeHead(500, { 'Content-Type': 'text/plain' });
            return;
        } else {
            if (!result) {
                if (response != null) {
                    response.writeHead(404, contentTypePlainText);
                    response.end('Not Found');
                }
                return;
            }

            if (response != null){
                response.setHeader('Content-Type', 'application/json');
                response.send(result);
            }
            console.log(result);
        }
    });
}
```

类似于`findItemsByCategory`，以下是一个按其 ID 查找项目的函数：

```js
exports.findItemById = function (itemId, response) {
    CatalogItem.findOne({itemId: itemId}, function(error, result) {
        if (error) {
            console.error(error);
            response.writeHead(500, contentTypePlainText);
            return;
        } else {
            if (!result) {
                if (response != null) {
                    response.writeHead(404, contentTypePlainText);
                    response.end('Not Found');
                }
                return;
            }

            if (response != null){
                response.setHeader('Content-Type', 'application/json');
                response.send(result);
            }
            console.log(result);
        }
    });
}
```

最后，有一个列出数据库中存储的所有目录项目的函数。它使用 Mongoose 模型的`find`函数来查找模型的所有文档，并使用其第一个参数作为过滤器。我们需要一个返回所有现有文档的函数；这就是为什么我们提供一个空对象。这将返回所有可用的项目。结果在`callback`函数中可用，它是模型`find`函数的第二个参数：

```js
exports.findAllItems = function (response) {
    CatalogItem.find({}, (error, result) => {
        if (error) {
            console.error(error);
            return null;
        }
        if (result != null) {
            response.json(result);
        } else {
      response.json({});
    }
    });
};
```

`catalog`模块将成为我们 RESTful 服务的基础。它负责所有数据操作，以及不同类型的查询。它以可重用的方式封装了所有操作。

# 将 NoSQL 数据库模块与 Express 连接起来

现在我们已经为模型和使用它们的用户定义模块自动化了测试。这确保了模块的稳定性，并使其准备好进行更广泛的采用。

是时候构建一个基于 Express 的新应用程序并添加一个路由，将新模块暴露给它：

```js
const express = require('express');
const router = express.Router();

const catalog = require('../modules/catalog');
const model = require('../model/item.js');

router.get('/', function(request, response, next) {
  catalog.findAllItems(response);
});

router.get('/item/:itemId', function(request, response, next) {
  console.log(request.url + ' : querying for ' + request.params.itemId);
  catalog.findItemById(request.params.itemId, response);
});

router.get('/:categoryId', function(request, response, next) {
  console.log(request.url + ' : querying for ' + request.params.categoryId);
  catalog.findItemsByCategory(request.params.categoryId, response);
});

router.post('/', function(request, response, next) {
  console.log('Saving item using POST method);
  catalog.saveItem(request, response);
});

router.put('/', function(request, response, next) {
  console.log('Saving item using PUT method');
  catalog.saveItem(request, response);
});

router.delete('/item/:itemId', function(request, response, next) {
  console.log('Deleting item with id: request.params.itemId);
  catalog.remove(request, response);
});

module.exports = router;
```

总之，我们将目录数据服务模块的每个函数路由到 RESTful 服务的操作：

+   `GET /catalog/item/:itemId`：这将调用`catalog.findItemById()`

+   `POST /catalog`: 这调用了`catalog.saveItem()`

+   `PUT /catalog`: 这调用了`catalog.saveItem()`

+   `DELETE / catalog/item/:id`: 这调用了`catalog.remove()`

+   `GET /catalog/:category`: 这调用了`catalog.findItemsByCategory()`

+   `GET /catalog/`: 这调用了`catalog.findAllItems()`

由于我们已经暴露了我们的操作，我们准备进行一些更严肃的 REST 测试。让我们启动 Postman 并测试新暴露的端点：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/rst-webapi-dsn-node10/img/484b04fb-0f1b-4977-83e4-564dee530a13.png)

花一些时间彻底测试每个操作。这将帮助您确信目录数据服务模块确实有效，并且还会让您更加熟悉 HTTP 响应的服务和读取方式。作为一个 RESTful API 开发人员，您应该能够流利地阅读 HTTP 转储，显示不同的请求有效载荷和状态码。

# 自测问题

回答以下问题：

+   你会如何使用 Mongoose 执行多值属性的单个值的查询？

+   定义一个测试 Node.js 模块操作 NoSQL 数据库的策略。

# 摘要

在本章中，我们看了看 MongoDB，一个强大的面向文档的数据库。我们利用它并利用 Mocha 来实现对数据库层的自动化测试。现在是时候构建一个完整的 RESTful web 服务了。在下一章中，我们将通过包含对文档属性的搜索支持，添加过滤和分页功能来扩展用户定义的模块，最终演变成一个完整的 RESTful 服务实现。
