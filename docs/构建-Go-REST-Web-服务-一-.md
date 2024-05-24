# 构建 Go REST Web 服务（一）

> 原文：[`zh.annas-archive.org/md5/57EDF27484D8AB35B253814EEB7E5A77`](https://zh.annas-archive.org/md5/57EDF27484D8AB35B253814EEB7E5A77)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

最初，基于 SOAP 的 Web 服务因 XML 而变得更受欢迎。然后，自 2012 年以来，REST 加快了步伐，并完全取代了 SOAP。新一代的 Web 语言，如 Python、JavaScript（Node.js）和 Go，展示了与传统的 ASP.NET 和 Spring 等相比，不同的 Web 开发方法。自本十年以来，由于其速度和直观性，Go 变得越来越受欢迎。少量冗长的代码、严格的类型检查和对并发的支持使 Go 成为编写任何 Web 后端的更好选择。一些最好的工具，如 Docker 和 Kubernetes，都是用 Go 编写的。谷歌在日常活动中大量使用 Go。您可以在[`github.com/golang/go/wiki/GoUsers`](https://github.com/golang/go/wiki/GoUsers)上看到使用 Go 的公司列表。

对于任何互联网公司，Web 开发部门至关重要。公司积累的数据需要以 API 或 Web 服务的形式提供给客户。各种客户端（浏览器、移动应用程序和服务器）每天都会使用 API。REST 是一种定义资源消耗形式的架构模式。

Go 是一个更好的编写 Web 服务器的语言。作为中级 Go 开发人员，了解如何使用语言中提供的构造创建 RESTful 服务是其责任。一旦掌握了基础知识，开发人员应该学习其他内容，如测试、优化和部署服务。本书旨在使读者能够舒适地开发 Web 服务。

专家认为，在不久的将来，随着 Python 进入数据科学领域并与 R 竞争，Go 可能会成为与 NodeJS 竞争的 Web 开发领域的唯一选择语言。本书不是一本食谱。然而，在您的旅程中，它提供了许多技巧和窍门。通过本书，读者最终将能够通过大量示例舒适地进行 REST API 开发。他们还将了解到最新的实践，如协议缓冲区/gRPC/API 网关，这将使他们的知识提升到下一个水平。

# 本书涵盖内容

第一章，“开始 REST API 开发”，讨论了 REST 架构和动词的基本原理。

第二章，“为我们的 REST 服务处理路由”，描述了如何为我们的 API 添加路由。

第三章，“使用中间件和 RPC”，讲述了如何使用中间件处理程序和基本的 RPC。

第四章，“使用流行的 Go 框架简化 RESTful 服务”，介绍了使用框架进行快速原型设计 API。

第五章，“使用 MongoDB 和 Go 创建 REST API”，解释了如何将 MongoDB 用作我们 API 的数据库。

第六章，“使用协议缓冲区和 gRPC”，展示了如何使用协议缓冲区和 gRPC 来获得比 HTTP/JSON 更高的性能提升。

第七章，“使用 PostgreSQL、JSON 和 Go”，解释了使用 PostgreSQL 和 JSON 存储创建 API 的好处。

第八章，“在 Go 中构建 REST API 客户端和单元测试”，介绍了在 Go 中构建客户端软件和使用单元测试进行 API 测试的技术。

第九章，“使用微服务扩展我们的 REST API”，讲述了如何使用 Go Kit 将我们的 API 服务拆分为微服务。

第十章，“部署我们的 REST 服务”，展示了如何使用 Nginx 部署服务，并使用 supervisord 进行监控。

第十一章，“使用 API 网关监控和度量 REST API”，解释了如何通过在 API 网关后添加多个 API 来使我们的服务达到生产级别。

第十二章，“为我们的 REST 服务处理身份验证”，讨论了如何使用基本身份验证和 JSON Web Tokens（JWT）保护我们的 API。

# 本书所需内容

对于这本书，您需要一台安装了 Linux（Ubuntu 16.04）、macOS X 或 Windows 的笔记本电脑/个人电脑。我们将使用 Go 1.8+作为我们的编译器版本，并安装许多第三方软件包，因此需要一个可用的互联网连接。

我们还将在最后的章节中使用 Docker 来解释 API 网关的概念。建议使用 Docker V17.0+。如果 Windows 用户在本书中的任何示例中遇到原生 Go 安装的问题，请使用 Docker for Windows 并运行 Ubuntu 容器，这样会更灵活；有关更多详细信息，请参阅[`www.docker.com/docker-windows`](https://www.docker.com/docker-windows)。

在深入阅读本书之前，请在[`tour.golang.org/welcome/1`](https://tour.golang.org/welcome/1)上复习您的语言基础知识。

尽管这些是基本要求，但我们将在必要时为您安装指导。

# 这本书适合谁

这本书适用于所有熟悉 Go 语言并希望学习 REST API 开发的开发人员。即使是资深工程师也可以享受这本书，因为它涵盖了许多尖端概念，如微服务、协议缓冲区和 gRPC。

已经熟悉 REST 概念并从其他平台（如 Python 和 Ruby）进入 Go 世界的开发人员也可以受益匪浅。

# 约定

在本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是一些这些样式的示例及其含义的解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："将前面的程序命名为`basicHandler.go`。"

代码块设置如下：

```go
{
 "ID": 1,
 "DriverName": "Menaka",
 "OperatingStatus": true
 }
```

任何命令行输入或输出都以以下形式编写：

```go
go run customMux.go
```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中以这种方式出现："它返回消息，说成功登录。"

警告或重要说明会以这样的形式出现在一个框中。

提示和技巧会出现在这样的形式。


# 第一章：开始使用 REST API 开发

Web 服务是在不同计算机系统之间定义的通信机制。没有 Web 服务，自定义的点对点通信变得繁琐且特定于平台。这就像是网络需要理解和解释的一百种不同的东西。如果计算机系统与网络易于理解的协议相一致，那将是一个很大的帮助。

Web 服务是一种旨在支持网络上可互操作的机器对机器交互的软件系统，**万维网联盟**（**W3C**），[`www.w3.org/TR/ws-arch/`](https://www.w3.org/TR/ws-arch/)。

现在，简单来说，Web 服务是两个端点之间的通路，消息可以顺利传输。在这里，这种传输通常是单向的。两个独立的可编程实体也可以通过它们自己的 API 相互通信。两个人通过语言进行交流。两个应用程序通过**应用程序编程接口**（**API**）进行通信。

读者可能会想知道，在当前数字世界中 API 的重要性是什么？**物联网**（**IoT**）的兴起使 API 的使用比以往更加重要。对 API 的认识日益增长，每天都有数百个 API 在全球各地被开发和记录。一些重要的大型企业正在看到**作为服务的 API**（**AAAS**）的未来。一个明显的例子是**亚马逊网络服务**（**AWS**）。它在云世界取得了巨大的成功。开发人员使用 AWS 提供的 REST API 编写自己的应用程序。

一些更隐秘的用例来自像 Ibibo 和 Expedia 这样的旅行网站，它们通过调用第三方网关和数据供应商的 API 来获取实时价格。如今，Web 服务通常会收费。

本章将涵盖的主题包括：

+   可用的不同 Web 服务

+   详细介绍表现状态转移（REST）架构

+   介绍使用 REST 构建单页应用程序（SPA）

+   设置 Go 项目并运行开发服务器

+   为查找罗马数字构建我们的第一个服务

+   使用 Gulp 自动编译 Go 代码

# Web 服务的类型

随着时间的推移，出现了许多类型的 Web 服务。其中一些主要的是：

+   SOAP

+   UDDI

+   WSDL

+   REST

在这些中，**SOAP**在 2000 年代初变得流行，当时 XML 处于风口浪尖。各种分布式系统使用 XML 数据格式进行通信。SOAP 的实现过于复杂。SOAP 的批评者指出了 SOAP HTTP 请求的臃肿。

SOAP 请求通常由以下三个基本组件组成：

+   信封

+   头部

+   主体

仅仅执行一个 HTTP 请求和响应周期，我们就必须在 SOAP 中附加大量额外的数据。一个示例 SOAP 请求如下：

```go
POST /StockQuote HTTP/1.1
Host: www.stockquoteserver.com
Content-Type: text/xml; charset="utf-8"
Content-Length: nnnn
SOAPAction: "Some-URI"

<SOAP-ENV:Envelope
  xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
  SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
   <SOAP-ENV:Body>
       <m:GetLastTradePrice >
           <symbol>DIS</symbol>
       </m:GetLastTradePrice>
   </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```

这是来自 W3C 标准的 SOAP 的标准示例（[`www.w3.org/TR/2000/NOTE-SOAP-20000508/`](https://www.w3.org/TR/2000/NOTE-SOAP-20000508/)）。如果我们仔细观察，它是以 XML 格式呈现的，其中特殊标签指定了信封和主体。由于 XML 操作需要大量的命名空间来运行，额外的信息也会起作用。

# REST API

**表现状态转移**（**REST**）这个名字是由加利福尼亚大学的 Roy Fielding 创造的。与 SOAP 相比，它是一个非常简化和轻量级的 Web 服务。性能、可伸缩性、简单性、可移植性和可修改性是 REST 设计的主要原则。

REST API 允许不同的系统以非常简单的方式进行通信和发送/接收数据。每个 REST API 调用都与 HTTP 动词和 URL 之间存在关系。应用程序中的数据库资源可以与 REST 中的 API 端点进行映射。

当您在手机上使用移动应用时，您的手机可能会秘密地与许多云服务进行通信，以检索、更新或删除您的数据。REST 服务对我们的日常生活有着巨大的影响。

REST 是一个无状态、可缓存的、简单的架构，不是协议而是一种模式。

# REST 服务的特点

这些是使 REST 简单且与其前身相比独特的主要特性：

+   **基于客户端-服务器的架构：** 这种架构对于现代 Web 通过 HTTP 进行通信至关重要。单个客户端-服务器最初看起来可能很天真，但许多混合架构正在发展。我们将很快讨论更多这些内容。

+   **无状态：** 这是 REST 服务最重要的特点。REST HTTP 请求包含服务器理解和返回响应所需的所有数据。一旦请求被处理，服务器就不会记住请求是否在一段时间后到达。因此，操作将是无状态的。

+   **可缓存：** 许多开发人员认为技术堆栈阻碍了他们的 Web 应用程序或 API。但实际上，他们的架构才是原因。数据库可以成为 Web 应用程序中的潜在调优部分。为了很好地扩展应用程序，我们需要缓存内容并将其作为响应交付。如果缓存无效，我们有责任清除它。REST 服务应该被适当地缓存以进行扩展。

+   **按需脚本：** 您是否曾经设计过一个 REST 服务，该服务提供 JavaScript 文件并在运行时执行它们？这种按需代码也是 REST 可以提供的主要特点。从服务器请求脚本和数据更为常见。

+   **多层系统：** REST API 可以由多个服务器提供。一个服务器可以请求另一个服务器，依此类推。因此，当客户端发出请求时，请求和响应可以在多个服务器之间传递，最终向客户端提供响应。这种易于实现的多层系统对于保持 Web 应用程序松散耦合始终是一个良好的策略。

+   **资源的表示：** REST API 提供了统一的接口进行通信。它使用统一资源标识符（URI）来映射资源（数据）。它还具有请求特定数据格式作为响应的优势。互联网媒体类型（MIME 类型）可以告诉服务器请求的资源是特定类型的。

+   **实现自由：** REST 只是定义 Web 服务的一种机制。它是一种可以以多种方式实现的架构风格。由于这种灵活性，您可以按照自己的意愿创建 REST 服务。只要遵循 REST 的原则，您的服务器就有自由选择平台或技术。

周到的缓存对于 REST 服务的扩展至关重要。

# REST 动词和状态码

REST 动词指定要在特定资源或资源集合上执行的操作。当客户端发出请求时，应在 HTTP 请求中发送此信息：

+   REST 动词

+   头信息

+   正文（可选）

正如我们之前提到的，REST 使用 URI 来解码其要处理的资源。有许多 REST 动词可用，但其中六个经常被使用。它们如下：

+   `GET`

+   `POST`

+   `PUT`

+   `PATCH`

+   `DELETE`

+   `OPTIONS`

如果您是软件开发人员，您将大部分时间处理这六个。以下表格解释了操作、目标资源以及请求成功或失败时会发生什么：

| **REST 动词** | **操作** | **成功** | **失败** |
| --- | --- | --- | --- |
| `GET` | 从服务器获取记录或资源集 | 200 | 404 |
| `OPTIONS` | 获取所有可用的 REST 操作 | 200 | - |
| `POST` | 创建新的资源集或资源 | 201 | 404, 409 |
| `PUT` | 更新或替换给定的记录 | 200, 204 | 404 |
| `PATCH` | 修改给定的记录 | 200, 204 | 404 |
| `DELETE` | 删除给定的资源 | 200 | 404 |

前表中**成功**和**失败**列中的数字是 HTTP 状态码。每当客户端发起 REST 操作时，由于 REST 是无状态的，客户端应该知道如何找出操作是否成功。因此，HTTP 为响应定义了状态码。REST 为给定操作定义了前面的状态码类型。这意味着 REST API 应严格遵循前面的规则，以实现客户端-服务器通信。

所有定义的 REST 服务都具有以下格式。它由主机和 API 端点组成。API 端点是服务器预定义的 URL 路径。每个 REST 请求都应该命中该路径。

一个微不足道的 REST API URI：`http://HostName/API endpoint/Query(optional)`

让我们更详细地看一下所有的动词。REST API 设计始于操作和 API 端点的定义。在实现 API 之前，设计文档应列出给定资源的所有端点。在接下来的部分中，我们将使用 PayPal 的 REST API 作为一个用例，仔细观察 REST API 端点。

# GET

`GET`方法从服务器获取给定的资源。为了指定资源，`GET`使用了几种类型的 URI 查询：

+   查询参数

+   基于路径的参数

如果你不知道，你所有的网页浏览都是通过向服务器发出`GET`请求来完成的。例如，如果你输入[www.google.com](http://www.google.com)，你实际上是在发出一个`GET`请求来获取搜索页面。在这里，你的浏览器是客户端，而 Google 的 Web 服务器是 Web 服务的后端实现者。成功的`GET`操作返回一个 200 状态码。

路径参数的示例：

每个人都知道**PayPal**。PayPal 与公司创建结算协议。如果您向 PayPal 注册支付系统，他们会为您提供一个 REST API，以满足您所有的结算需求。获取结算协议信息的示例`GET`请求如下：`/v1/payments/billing-agreements/agreement_id`。

在这里，资源查询是通过路径参数进行的。当服务器看到这一行时，它会将其解释为*我收到了一个需要从结算协议中获取 agreement_id 的 HTTP 请求*。然后它会在数据库中搜索，转到`billing-agreements`表，并找到一个具有给定`agreement_id`的协议。如果该资源存在，它会发送详细信息以便在响应中复制（200 OK）。否则，它会发送一个响应，说明资源未找到（404）。

使用`GET`，你也可以查询资源列表，而不是像前面的例子那样查询单个资源。PayPal 的用于获取与协议相关的结算交易的 API 可以通过`/v1/payments/billing-agreements/transactions`获取。这一行获取了在该结算协议上发生的所有交易。在这两种情况下，数据以 JSON 响应的形式检索。响应格式应该事先设计好，以便客户端可以在协议中使用它。

查询参数的示例如下：

+   查询参数旨在添加详细信息，以从服务器识别资源。例如，以这个虚构的 API 为例。假设这个 API 是为了获取、创建和更新书籍的详细信息而创建的。基于查询参数的`GET`请求将采用这种格式：

```go
 /v1/books/?category=fiction&publish_date=2017
```

+   前面的 URI 有一些查询参数。该 URI 请求一本满足以下条件的书籍：

+   它应该是一本虚构的书

+   这本书应该在 2017 年出版

*获取所有在 2017 年出版的虚构书籍*是客户端向服务器提出的问题。

Path vs Query 参数——何时使用它们？一个常见的经验法则是，`Query` 参数用于基于查询参数获取多个资源。如果客户端需要具有精确 URI 信息的单个资源，可以使用 `Path` 参数来指定资源。例如，用户仪表板可以使用 `Path` 参数请求，并且可以使用 `Query` 参数对过滤数据进行建模。

在 `GET` 请求中，对于单个资源使用 `Path` 参数，对于多个资源使用 `Query` 参数。

# POST、PUT 和 PATCH

`POST` 方法用于在服务器上创建资源。在之前的书籍 API 中，此操作使用给定的详细信息创建新书籍。成功的 `POST` 操作返回 201 状态码。`POST` 请求可以更新多个资源：`/v1/books`。

`POST` 请求的主体如下：

```go
{"name" : "Lord of the rings", "year": 1954, "author" : "J. R. R. Tolkien"}
```

这实际上在数据库中创建了一本新书。为这条记录分配了一个 ID，以便当我们 `GET` 资源时，URL 被创建。因此，`POST` 应该只在开始时执行一次。事实上，*指环王* 是在 1955 年出版的。因此我们输入了错误的出版日期。为了更新资源，让我们使用 `PUT` 请求。

`PUT` 方法类似于 `POST`。它用于替换已经存在的资源。主要区别在于 `PUT` 是幂等的。`POST` 调用会创建两个具有相同数据的实例。但 `PUT` 会更新已经存在的单个资源：

```go
/v1/books/1256
```

带有如下 JSON 主体：

```go
{"name" : "Lord of the rings", "year": 1955, "author" : "J. R. R. Tolkien"}
```

`1256` 是书籍的 ID。它通过 `year:1955` 更新了前面的书籍。你注意到 `PUT` 的缺点了吗？它实际上用新的记录替换了整个旧记录。我们只需要更改一个列。但 `PUT` 替换了整个记录。这很糟糕。因此，引入了 `PATCH` 请求。

`PATCH` 方法类似于 `PUT`，只是它不会替换整个记录。`PATCH`，顾名思义，是对正在修改的列进行修补。让我们使用一个新的列名 `ISBN` 更新书籍 `1256`：

```go
/v1/books/1256
```

使用如下的 JSON 主体：

```go
{"isbn" : "0618640150"}
```

它告诉服务器，*搜索 ID 为 1256 的书籍。然后添加/修改此列的给定值*。

`PUT` 和 `PATCH` 都对成功返回 200 状态，对未找到返回 404。

# DELETE 和 OPTIONS

`DELETE` API 方法用于从数据库中删除资源。它类似于 `PUT`，但没有任何主体。它只需要资源的 ID 来删除。一旦资源被删除，后续的 `GET` 请求会返回 404 未找到状态。

对这种方法的响应*不可缓存*（如果实现了缓存），因为 `DELETE` 方法是幂等的。

`OPTIONS` API 方法是 API 开发中最被低估的。给定资源，该方法尝试了解服务器上定义的所有可能的方法（`GET`、`POST`等）。这就像在餐厅看菜单然后点菜一样（而如果你随机点一道菜，服务员会告诉你这道菜没有了）。在服务器上实现 `OPTIONS` 方法是最佳实践。从客户端确保首先调用 `OPTIONS`，如果该方法可用，然后继续进行。

# 跨域资源共享（CORS）

这个 `OPTIONS` 方法最重要的应用是**跨域资源共享**（**CORS**）。最初，浏览器安全性阻止客户端进行跨域请求。这意味着使用 URL [www.foo.com](http://www.foo.com) 加载的站点只能对该主机进行 API 调用。如果客户端代码需要从 [www.bar.com](http://www.bar.com) 请求文件或数据，那么第二个服务器 [bar.com](https://bar.com/) 应该有一种机制来识别 [foo.com](http://foo.com) 以获取其资源。

这个过程解释了 CORS：

1.  [foo.com](http://foo.com) 在 [bar.com](http://bar.com) 上请求 `OPTIONS` 方法。

1.  [bar.com](http://bar.com) 在响应客户端时发送了一个头部，如 `Access-Control-Allow-Origin: http://foo.com`。

1.  接下来，[foo.com](http://foo.com)可以访问[bar.com](https://bar.com/)上的资源，而不受任何限制，调用任何`REST`方法。

如果[bar.com](http://bar.com)感觉在一次初始请求后向任何主机提供资源，它可以将访问控制设置为*（即任何）。

以下是描述依次发生的过程的图表：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/32a06a64-3c6b-4f5d-90da-8c4745a520a1.png)

# 状态代码的类型

有几个状态代码家族。每个家族都全局解释了一个操作状态。该家族的每个成员可能有更深层的含义。因此，REST API 应该严格告诉客户端操作后到底发生了什么。有 60 多种状态代码可用。但对于 REST，我们集中在几个代码家族上。

# 2xx 家族（成功）

200 和 201 属于成功家族。它们表示操作成功。纯**200**（**操作成功**）是成功的 CRUD 操作：

+   **200**（**操作成功**）是 REST 中最常见的响应状态代码

+   **201**（**创建成功**）当`POST`操作成功在服务器上创建资源时返回

+   **204**（**无内容**）在客户端需要状态但不需要任何数据时发出

# 3xx 家族（重定向）

这些状态代码用于传达重定向消息。最重要的是**301**和**304**：

+   **301**在资源永久移动到新的 URL 端点时发出。当旧的 API 被弃用时，这是必不可少的。它返回响应中的新端点和 301 状态。通过查看这一点，客户端应该使用新的 URL 以响应实现其目标。

+   **304**状态代码表示内容已缓存，并且服务器上的资源未发生修改。这有助于在客户端缓存内容，并且仅在缓存被修改时请求数据。

# 4xx 家族（客户端错误）

这些是客户端需要解释和处理进一步操作的标准错误状态代码。这与服务器无关。错误的请求格式或格式不正确的 REST 方法可能会导致这些错误。其中，API 开发人员最常用的状态代码是**400**、**401**、**403**、**404**和**405**：

+   **400**（**错误请求**）当服务器无法理解客户端请求时返回。

+   **401**（**未经授权**）当客户端未在标头中发送授权信息时返回。

+   **403**（**禁止**）当客户端无法访问某种类型的资源时返回。

+   **404**（**未找到**）当客户端请求的资源不存在时返回。

+   **405**（**方法不允许**）如果服务器禁止资源上的一些方法，则返回。`GET`和`HEAD`是例外。

# 5xx 家族（服务器错误）

这些是来自服务器的错误。客户端请求可能是完美的，但由于服务器代码中的错误，这些错误可能会出现。常用的状态代码有**500**、**501**、**502**、**503**和**504**：

+   **500**（**内部服务器错误**）状态代码给出了由一些错误的代码或一些意外条件引起的开发错误

+   **501**（**未实现**）当服务器不再支持资源上的方法时返回

+   **502**（**错误网关**）当服务器本身从另一个服务供应商那里收到错误响应时返回

+   **503**（**服务不可用**）当服务器由于多种原因而关闭，如负载过重或维护时返回

+   **504**（**网关超时**）当服务器等待另一个供应商的响应时间过长，并且为客户端提供服务的时间太长时返回

有关状态代码的更多详细信息，请访问此链接：[`developer.mozilla.org/en-US/docs/Web/HTTP/Status`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status)

# REST API 与单页应用的崛起

您需要了解为什么**单页应用程序**（**SPA**）是当今的热门话题。这些 SPA 设计使开发人员以一种完全不同的方式编写代码，而不是以传统方式构建 UI（请求网页）。有许多 MVC 框架，如 AngularJS、Angular2、React JS、Knockout JS、Aurelia 等，可以快速开发 Web UI，但它们的本质都非常简单。所有 MVC 框架都帮助我们实现一种设计模式。这种设计模式是*不请求网页，只使用 REST API*。

自 2010 年以来，现代 Web 前端开发已经取得了很大进步。为了利用**Model-View-Controller**（**MVC**）架构的特性，我们需要将前端视为一个独立的实体，只使用 REST API（最好是 REST JSON）与后端进行通信。

# SPA 中的旧和新数据流的方式

所有网站都经历以下步骤：

1.  从服务器请求网页。

1.  验证并显示仪表板 UI。

1.  允许用户进行修改和保存。

1.  根据需要从服务器请求尽可能多的网页，以在站点上显示单独的页面。

但在 SPA 中，流程完全不同：

1.  一次性向浏览器请求 HTML 模板。

1.  然后，查询 JSON REST API 以填充模型（数据对象）。

1.  根据模型（JSON）中的数据调整 UI。

1.  当用户修改 UI 时，模型（数据对象）应该自动更改。例如，在 AngularJS 中，可以通过双向数据绑定实现。最后，可以随时进行 REST API 调用，通知服务器进行更改。

这样，通信只以 REST API 的形式进行。客户端负责逻辑地表示数据。这导致系统从**响应导向架构**（**ROA**）转移到**服务导向架构**（**SOA**）。请看下面的图表：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/19a08895-c507-4a77-b9f1-830361ac0668.jpeg)

SPA 减少了带宽，并提高了站点的性能。

# 为什么选择 Go 进行 REST API 开发？

REST 服务在现代网络中是微不足道的。SOA（我们稍后会更详细地讨论）为 REST 服务创造了一个活动空间，将 Web 开发推向了一个新的水平。**Go**是谷歌公司推出的一种编程语言，用于解决他们所面临的更大的问题。自首次出现以来已经过去了八年多。它随着开发者社区的加入而不断成熟，并在其中创建了大规模的系统。

Go 是 Web 的宠儿。它以一种简单的方式解决了更大的问题。

人们可以选择 Python 或 JavaScript（Node）进行 REST API 开发。Go 的主要优势在于其速度和编译时错误检测。通过各种基准测试，Go 被证明在计算性能方面比动态编程语言更快。这就是公司应该使用 Go 编写其下一个 API 的三个原因：

+   为了扩展 API 以吸引更广泛的受众

+   为了使您的开发人员能够构建健壮的系统

+   为了投资未来项目的可行性

您可以查看关于 Go 的 REST 服务的不断进行的在线辩论以获取更多信息。在后面的章节中，我们将尝试构建设计和编写 REST 服务的基础知识。

# 设置项目并运行开发服务器

这是一本系列构建的书。它假设您已经了解 Go 的基础知识。如果没有，也没关系。您可以从 Go 的官方网站[`golang.org/`](https://golang.org/)快速入门并快速学习。Go 使用一种不同的开发项目的方式。编写一个独立的简单程序不会让您感到困扰。但是在学习了基础知识之后，人们会尝试进一步发展。因此，作为 Go 开发人员，您应该了解 Go 项目的布局方式以及保持代码清晰的最佳实践。

在继续之前，请确保已完成以下工作：

+   在您的计算机上安装 Go 编译器

+   设置`GOROOT`和`GOPATH`环境变量

有许多在线参考资料可以了解到前面的细节。根据你的机器类型（Windows、Linux 或 macOS X），设置一个可用的 Go 编译器。我们将在下一节中看到有关`GOPATH`的更多细节。

# 解密 GOPATH

`GOPATH`只是你的机器上当前指定的工作空间。它是一个环境变量，告诉 Go 编译器你的源代码、二进制文件和包的位置。

来自 Python 背景的程序员可能知道 Virtualenv 工具，可以同时创建多个项目（使用不同的 Python 解释器版本）。但在某个时间点，只能激活一个环境并开发自己的项目。同样，你可以在你的机器上有任意数量的 Go 项目。在开发时，将`GOPATH`设置为你的一个项目。Go 编译器现在激活了该项目。

在家目录下创建一个项目并设置`GOPATH`环境变量是一种常见的做法，就像这样：

```go
>mkdir /home/naren/myproject
export GOPATH=/home/naren/myproject
```

现在我们这样安装外部包：

```go
go get -u -v github.com/gorilla/mux
```

Go 将名为`mux`的项目复制到当前激活的项目`myproject`中。

对于 Go get，使用`-u`标志来安装外部包的更新依赖项，使用`-v`来查看安装的详细信息。

一个典型的 Go 项目具有以下结构，正如官方 Go 网站上所述：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/b5ae002f-d91f-4d0f-bbb0-e5b366ae3876.png)

让我们在深入研究之前先了解这个结构：

+   `bin`：存储我们项目的可运行二进制文件

+   `pkg`：包含包对象的目录；一个提供包方法的编译程序

+   `src`：项目源代码、测试和用户包的位置

在 Go 中，你导入到你的主程序中的所有包都有一个相同的结构，`github.com/user/project`。但是谁创建所有这些目录？开发者需要做吗？不需要。开发者的责任是为他/她的项目创建目录。这意味着他/她只创建`src/github.com/user/hello`目录。

当开发者运行以下命令时，如果之前不存在，将创建`bin`和`package`目录。`.bin`包含我们项目源代码的二进制文件，`.pkg`包含我们在 Go 程序中使用的所有内部和外部包：

```go
 go install github.com/user/project
```

# 构建我们的第一个服务-查找罗马数字

有了我们到目前为止建立的概念，让我们编写我们的第一个基本 REST 服务。这个服务从客户端获取数字范围（1-10），并返回其罗马字符串。非常原始，但比 Hello World 好。

**设计：**

我们的 REST API 应该从客户端获取一个整数，并返回罗马数字等价物。

API 设计文档的块可能是这样的：

| **HTTP 动词** | **路径** | **操作** | **资源** |
| --- | --- | --- | --- |
| `GET` | `/roman_number/2` | 显示 | `roman_number` |

**实施：**

现在我们将逐步实现前面的简单 API。

该项目的代码可在[`github.com/narenaryan/gorestful`](https://github.com/narenaryan/gorestful)上找到。

正如我们之前讨论的，你应该首先设置`GOPATH`。假设`GOPATH`是`/home/naren/go`。在以下路径中创建一个名为`romanserver`的目录。用你的 GitHub 用户名替换*narenaryan*（这只是属于不同用户的代码的命名空间）：

```go
mkdir -p $GOPATH/src/github.com/narenaryan/romanserver
```

我们的项目已经准备好了。我们还没有配置任何数据库。创建一个名为`main.go`的空文件：

```go
touch $GOPATH/src/github.com/narenaryan/romanserver/main.go
```

我们的 API 服务器的主要逻辑放在这个文件中。现在，我们可以创建一个作为我们主程序的数据服务的数据文件。再创建一个目录来打包罗马数字数据：

```go
mkdir $GOPATH/src/github.com/narenaryan/romanNumerals
```

现在，在`romanNumerals`目录中创建一个名为`data.go`的空文件。到目前为止，`src`目录结构看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/5d36f6b4-c619-4e06-8ddd-9374c32ac864.png)

现在让我们开始向文件添加代码。为罗马数字创建数据：

```go
// data.go
package romanNumerals

var Numerals = map[int]string{
  10: "X",
  9: "IX",
  8: "VIII",
  7: "VII",
  6: "VI",
  5: "V",
  4: "IV",
  3: "III",
  2: "II",
  1: "I",
}
```

我们正在创建一个名为**Numerals**的映射。这个映射保存了将给定整数转换为其罗马等价物的信息。我们将把这个变量导入到我们的主程序中，以便为客户端的请求提供服务。

打开`main.go`并添加以下代码：

```go
// main.go
package main

import (
   "fmt"
   "github.com/narenaryan/romanNumerals"
   "html"
   "net/http"
   "strconv"
   "strings"
   "time"
)

func main() {
   // http package has methods for dealing with requests
   http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
       urlPathElements := strings.Split(r.URL.Path, "/")
       // If request is GET with correct syntax
       if urlPathElements[1] == "roman_number" {
           number, _ := strconv.Atoi(strings.TrimSpace(urlPathElements[2]))
           if number == 0 || number > 10 {
           // If resource is not in the list, send Not Found status
               w.WriteHeader(http.StatusNotFound)
               w.Write([]byte("404 - Not Found"))
           } else {
             fmt.Fprintf(w, "%q", html.EscapeString(romanNumerals.Numerals[number]))
           }
       } else {
           // For all other requests, tell that Client sent a bad request
           w.WriteHeader(http.StatusBadRequest)
           w.Write([]byte("400 - Bad request"))
       }
   })
 // Create a server and run it on 8000 port
   s := &http.Server{
     Addr: ":8000",
     ReadTimeout: 10 * time.Second,
     WriteTimeout: 10 * time.Second,
     MaxHeaderBytes: 1 << 20,
   }
   s.ListenAndServe()
}
```

始终使用 Go fmt 工具格式化你的 Go 代码。

用法示例：`go fmt github.com/narenaryan/romanserver`

现在，使用 Go 命令`install`安装这个项目：

```go
go install github.com/narenaryan/romanserver
```

这一步做了两件事：

+   编译包`romanNumerals`并将副本放在`$GOPATH/pkg`目录中

+   将二进制文件放入`$GOPATH/bin`

我们可以像这样运行前面的 API 服务器：

```go
$GOPATH/bin/romanserver
```

服务器正在`http://localhost:8000`上运行。现在我们可以使用像`浏览器`或`CURL`命令这样的客户端发出`GET`请求到 API。让我们用一个合适的 API`GET`请求来发出一个`CURL`命令。

请求一如下：

```go
curl -X GET "http://localhost:8000/roman_number/5" # Valid request
```

响应如下：

```go
HTTP/1.1 200 OK
Date: Sun, 07 May 2017 11:24:32 GMT
Content-Length: 3
Content-Type: text/plain; charset=utf-8

"V"
```

让我们尝试一些格式不正确的请求。

请求二如下：

```go
curl -X GET "http://localhost:8000/roman_number/12" # Resource out of range
```

响应如下：

```go
HTTP/1.1 404 Not Found
Date: Sun, 07 May 2017 11:22:38 GMT
Content-Length: 15
Content-Type: text/plain; charset=utf-8

404 - Not Found
```

请求三如下：

```go
curl -X GET "http://localhost:8000/random_resource/3" # Invalid resource
```

响应如下：

```go
"HTTP/1.1 400 Bad request
Date: Sun, 07 May 2017 11:22:38 GMT
Content-Length: 15
Content-Type: text/plain; charset=utf-8
400 - Bad request
```

我们的小罗马数字 API 正在做正确的事情。正确的状态码正在被返回。这是所有 API 开发者应该牢记的要点。客户端应该被告知为什么出了问题。

# 代码分解

我们一次性更新了空文件并启动了服务器。现在让我解释一下`main.go`文件的每一部分：

+   导入了一些包。`github.com/narenaryan/romanNumerals`是我们之前创建的数据服务。

+   `net/http`是我们用来处理 HTTP 请求的核心包，通过它的`HandleFunc`函数。该函数的参数是`http.Request`和`http.ResponseWriter`。这两个处理 HTTP 请求的请求和响应。

+   `r.URL.Path`是 HTTP 请求的 URL 路径。对于 CURL 请求，它是`/roman_number/5`。我们正在拆分这个路径，并使用第二个参数作为资源，第三个参数作为值来获取罗马数字。`Split`函数在一个名为`strings`的核心包中。

+   `Atoi`函数将字母数字字符串转换为整数。为了使用数字映射，我们需要将整数字符串转换为整数。`Atoi`函数来自一个名为`strconv`的核心包。

+   我们使用`http.StatusXXX`来设置响应头的状态码。`WriteHeader`和`Write`函数可用于在响应对象上分别写入头部和正文。

+   接下来，我们使用`&http`创建了一个 HTTP 服务器，同时初始化了一些参数，如地址、端口、超时等。

+   `time`包用于在程序中定义秒。它说，在 10 秒的不活动后，自动向客户端返回 408 请求超时。

+   `EscapeString`将特殊字符转义为有效的 HTML 字符。例如，Fran & Freddie's 变成了`Fran &amp; Freddie's&#34`。

+   最后，使用`ListenAndServe`函数启动服务器。它会一直运行你的 Web 服务器，直到你关闭它。

应该为 API 编写单元测试。在接下来的章节中，我们将看到如何对 API 进行端到端测试。

# 使用 supervisord 和 Gulp 实时重新加载应用程序

Gulp 是一个用于创建工作流的好工具。工作流是一个逐步的过程。它只是一个任务流程应用程序。你需要在你的机器上安装 NPM 和 Node。我们使用 Gulp 来监视文件，然后更新二进制文件并重新启动 API 服务器。听起来很酷，对吧？

监督程序是一个在应用程序被杀死时重新加载服务器的应用程序。一个进程 ID 将被分配给你的服务器。为了正确重新启动应用程序，我们需要杀死现有的实例并重新启动应用程序。我们可以用 Go 编写一个这样的程序。但为了不重复造轮子，我们使用一个叫做 supervisord 的流行程序。

# 使用 supervisord 监控你的 Go Web 服务器

有时，您的 Web 应用程序可能会因操作系统重新启动或崩溃而停止。每当您的 Web 服务器被终止时，supervisor 的工作就是将其重新启动。即使系统重新启动也无法将您的 Web 服务器从客户端中移除。因此，请严格使用 supervisord 来监控您的应用程序。

# 安装 supervisord

我们可以使用`apt-get`命令在 Ubuntu 16.04 上轻松安装 supervisord：

```go
sudo apt-get install -y supervisor
```

这将安装两个工具，`supervisor`和`supervisorctl`。`supervisorctl`用于控制 supervisord 并添加任务，重新启动任务等。

在 macOS X 上，我们可以使用`brew`命令安装`supervisor`：

```go
brew install supervisor
```

现在，在以下位置创建一个配置文件：

```go
/etc/supervisor/conf.d/goproject.conf
```

您可以添加任意数量的配置文件，supervisord 将它们视为独立的进程来运行。将以下内容添加到之前的文件中：

```go
[supervisord]
logfile = /tmp/supervisord.log
```

```go
[program:myserver]
command=$GOPATH/bin/romanserver
autostart=true
autorestart=true
redirect_stderr=true
```

默认情况下，我们在`/etc/supervisor/`目录下有一个名为`.supervisord.conf`的文件。查看它以获取更多参考信息。在 macOS X 中，相同的文件将位于`/usr/local/etc/supervisord.ini`。

关于之前的配置：

+   `[supervisord]`部分告诉 supervisord 的日志文件位置

+   **`[program:myserver]`**是任务块，它遍历到给定目录并执行给定的命令

现在我们可以要求我们的`supervisorctl`重新读取配置并重新启动任务（进程）。只需说：

+   `supervisorctl reread`

+   `supervisorctl update`

然后，使用以下命令启动`supervisorctl`：

```go
supervisorctl
```

您将看到类似于这样的内容：

`supervisorctl`是一个用于控制 supervisor 程序的强大工具。![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/0719632a-e003-4969-8db2-ab30fffaa133.png)

由于我们在 supervisor 配置文件中将我们的 romanserver 命名为`myserver`，我们可以从`supervisorctl`启动，停止和重新启动该程序。

# 使用 Gulp 创建自动代码编译和服务器重新加载

在我们之前的章节中对 Gulp 进行了简要介绍，我们将编写一个 gulpfile 来告诉计算机执行一些任务。

我使用`npm`安装 Gulp 和 Gulp-shell：

```go
npm install gulp gulp-shell
```

之后，在项目的根目录中创建一个`gulpfile.js`。这里是`github.com/src/narenaryan/romanserver`。现在将以下内容添加到`gulpfile.js`。首先，每当文件更改时，将执行安装二进制任务。然后，supervisor 将被重新启动。监视任务会查找任何文件更改并执行之前的任务。我们还对任务进行排序，以便它们按顺序同步执行。所有这些任务都是 Gulp 任务，并且可以通过`gulp.task`函数定义。它接受两个参数，任务名称和任务。`sell.task`允许 Gulp 执行系统命令：

```go
var gulp = require("gulp");
var shell = require('gulp-shell');

// This compiles new binary with source change
gulp.task("install-binary", shell.task([
 'go install github.com/narenaryan/romanserver'
]));

// Second argument tells install-binary is a deapendency for restart-supervisor
gulp.task("restart-supervisor", ["install-binary"], shell.task([
 'supervisorctl restart myserver'
]))

gulp.task('watch', function() {
 // Watch the source code for all changes
 gulp.watch("*", ['install-binary', 'restart-supervisor']);

});

gulp.task('default', ['watch']);
```

现在，如果在`source`目录中运行`gulp`命令，它将开始监视您的源代码更改：

```go
gulp
```

现在，如果我们修改了代码，那么代码会被编译，安装，并且服务器会立即重新启动：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/b381310c-588c-4a06-af59-74a57019858f.png)

# 理解 gulpfile

在 gulpfile 中，我们执行以下指令：

1.  导入 Gulp 和 Gulp-shell。

1.  使用`shell.task`创建任务作为执行函数。

1.  `shell.task`可以执行命令行指令。将你的 shell 命令放在该函数内。

1.  为监视源文件添加一个监视任务。当文件被修改时，任务列表将被执行。

1.  为运行创建一个默认任务。为其添加一个监视。

Gulp 是这类用例的绝佳工具。因此，请仔细阅读 Gulp 的官方文档[`gulpjs.com/`](http://gulpjs.com/)。

# 总结

在本章中，我们介绍了 REST API。我们看到 REST 不是一个协议，而是一种架构模式。HTTP 是我们可以实现 REST 服务的实际协议。我们深入了解了 REST API 的基本原理，以便清楚地了解它们实际上是什么。然后我们探讨了 Web 服务的类型。在 REST 之前，我们有一个叫做 SOAP 的东西，它使用 XML 作为数据格式。REST 使用 JSON 作为主要格式。REST 有动词和状态码。我们了解了给定状态码指的是什么。我们构建了一个简单的服务，为给定的数字提供罗马数字。在这个过程中，我们还看到了如何打包一个 Go 项目。我们了解了 GOPATH 环境变量。它是 Go 中定义变量的工作空间。所有的包和项目都驻留在这个路径中。然后我们看到了如何使用 supervisord 和 Gulp 来实时重新加载开发项目。这些都是 Node 工具，但可以帮助我们保持我们的 Go 项目正常运行。

在下一章中，我们将深入研究 URL 路由。从内置路由器开始，我们将探索 Gorilla Mux，一个强大的 URL 路由库。


# 第二章：处理我们的 REST 服务的路由

在本章中，我们将讨论应用程序的路由。为了创建一个 API，第一步是定义路由。因此，为了定义路由，我们需要找出 Go 中可用的构造。我们从 Go 中的基本内部路由机制开始。然后，我们看看如何创建一个自定义的多路复用器。由于 ServeMux 的功能非常有限，我们将探索一些其他用于此目的的框架。本章还包括使用第三方库（如`httprouter`和`Gorilla Mux`）创建路由。我们将在整本书中构建一个 URL 缩短的 API。在本章中，我们为 API 定义路由。然后，我们讨论诸如 URL 的 SQL 注入之类的主题。Web 框架允许开发人员首先创建一个路由，然后将处理程序附加到它上。这些处理程序包含应用程序的业务逻辑。本章的关键是教会您如何使用`Gorilla Mux`在 Go 中创建 HTTP 路由。我们还讨论 URL 缩短服务的功能，并尝试设计一个逻辑实现。

我们将涵盖以下主题：

+   在 Go 中构建一个基本的 Web 服务器

+   理解 net/http 包

+   ServeMux，在 Go 中的基本路由器

+   理解 httprouter，一个路由器包

+   介绍 Gorilla Mux，一个强大的 HTTP 路由器

+   介绍 URL 缩短服务设计

# 获取代码

您可以从[`github.com/narenaryan/gorestful/tree/master/chapter2`](https://github.com/narenaryan/gorestful/tree/master/chapter2)下载本章的代码。欢迎添加评论和拉取请求。克隆代码并在`chapter2`目录中使用代码示例。

# 理解 Go 的 net/http 包

Go 的`net/http`包处理 HTTP 客户端和服务器的实现。在这里，我们主要关注服务器的实现。让我们创建一个名为`basicHandler.go`的小型 Go 程序，定义路由和一个函数处理程序：

```go
package main
import (
    "io"
    "net/http"
    "log"
)
// hello world, the web server
func MyServer(w http.ResponseWriter, req *http.Request) {
    io.WriteString(w, "hello, world!\n")
}
func main() {
    http.HandleFunc("/hello", MyServer)
    log.Fatal(http.ListenAndServe(":8000", nil))
}
```

这段代码做了以下几件事情：

1.  创建一个名为`/hello`的路由。

1.  创建一个名为`MyServer`的处理程序。

1.  每当请求到达路由（`/hello`）时，处理程序函数将被执行。

1.  向响应中写入`hello, world`。

1.  在端口`8000`上启动服务器。如果出现问题，`ListenAndServe`将返回**`error`**。因此，使用`log.Fatal`记录它。

1.  `http`包有一个名为**`HandleFunc`**的函数，使用它可以将 URL 映射到一个函数。

1.  这里，**`w`**是一个响应写入器。`ResponseWriter`接口被 HTTP 处理程序用来构造 HTTP 响应。

1.  `req`是一个请求对象，处理 HTTP 请求的所有属性和方法。

使用日志功能来调试潜在的错误。如果有错误，`ListenAndServe`函数会返回一个错误。

# 运行代码

我们可以将上述代码作为一个独立的程序运行。将上述程序命名为`basicHandler.go`。将其存储在任何您希望的位置，然后使用以下命令运行它：

```go
go run basicHandler.go
```

现在打开一个 shell 或浏览器来查看服务器的运行情况。在这里，我使用 CURL 请求：

```go
curl -X GET http://localhost:8000/hello
```

响应是：

```go
hello, world
```

Go 有一个处理请求和响应的不同概念。我们使用`io`库来写入响应。对于 Web 开发，我们可以使用模板自动填充细节。Go 的内部 URL 处理程序使用 ServeMux 多路复用器。

# ServeMux，在 Go 中的基本路由器

ServeMux 是一个 HTTP 请求多路复用器。我们在前面的部分中使用的`HandleFunc`实际上是 ServeMux 的一个方法。通过创建一个新的 ServeMux，我们可以处理多个路由。在此之前，我们还可以创建自己的多路复用器。多路复用器只是处理将路由与名为`ServeHTTP`的函数分离的逻辑。因此，如果我们创建一个具有`ServeHTTP`方法的新结构，它就可以完成这项工作。

将路由视为字典（映射）中的键，然后将处理程序视为其值。路由器从路由中找到处理程序，并尝试执行`ServeHTTP`函数。让我们创建一个名为`customMux.go`的程序，并看看这个实现的效果：

```go
package main
import (
    "fmt"
    "math/rand"
    "net/http"
)
// CustomServeMux is a struct which can be a multiplexer
type CustomServeMux struct {
}
// This is the function handler to be overridden
func (p *CustomServeMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    if r.URL.Path == "/" {
        giveRandom(w, r)
        return
    }
    http.NotFound(w, r)
    return
}
func giveRandom(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Your random number is: %f", rand.Float64())
}
func main() {
    // Any struct that has serveHTTP function can be a multiplexer
    mux := &CustomServeMux{}
    http.ListenAndServe(":8000", mux)
}
```

在这段代码中，我们创建了一个名为**`CustomServeMux`**的自定义结构，它将负责我们的路由。我们实现了一个名为**`ServeHTTP`**的函数，以便捕获请求并向其写入响应。通常使用`fmt`包来创建字符串。**`Fprinf`**将提供的参数组合成字符串。

在主函数中，我们创建了一个**`CustomServeMux`**的实例，并将其传递给`http`的`ListenAndServe`函数。`"math/rand"`是负责生成随机数的库。当我们讨论向 API 服务器添加身份验证时，这个基本的基础将对我们有所帮助。

# 运行代码

让我们发出一个 CURL 请求并查看各种路由的响应：

```go
go run customMux.go
```

现在，打开一个 shell 或浏览器来查看服务器的运行情况。在这里，我使用 CURL 请求：

```go
curl -X GET http://localhost:8000/
```

响应是：

```go
Your random number is: 0.096970
```

使用*Ctrl* + *C*或*Cmd* + *C*来停止您的 Go 服务器。如果您将其作为后台进程运行，请使用**`pgrep go`**来查找`processID`，然后使用`kill pid`来杀死它。

# 使用 ServeMux 添加多个处理程序

我们创建的前面的自定义 Mux 在具有不同功能的不同端点时可能会很麻烦。为了添加该逻辑，我们需要添加许多`if/else`条件来手动检查 URL 路由。我们可以实例化一个新的`ServeMux`并像这样定义许多处理程序：

```go
newMux := http.NewServeMux()

newMux.HandleFunc("/randomFloat", func(w http.ResponseWriter, r *http.Request) {
 fmt.Fprintln(w, rand.Float64())
})

newMux.HandleFunc("/randomInt", func(w http.ResponseWriter, r *http.Request) {
 fmt.Fprintln(w, rand.Int(100))
})
```

这段代码显示了如何创建一个 ServerMux 并将多个处理程序附加到它上。`randomFloat`和`randomInt`是我们为返回一个随机`float`和随机`int`创建的两个路由。现在我们可以将这个传递给`ListenAndServe`函数。`Intn(100)`从 0-100 的范围内返回一个随机整数。有关随机函数的更多详细信息，请访问[`golang.org`](http://golang.org)上的 Go 随机包页面。

```go
http.ListenAndServe(":8000", newMux)
```

完整的代码如下：

```go
package main
import (
    "fmt"
    "math/rand"
    "net/http"
)
func main() {
    newMux := http.NewServeMux()
    newMux.HandleFunc("/randomFloat", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintln(w, rand.Float64())
    })
    newMux.HandleFunc("/randomInt", func(w http.ResponseWriter, r
*http.Request) {
        fmt.Fprintln(w, rand.Intn(100))
    })
    http.ListenAndServe(":8000", newMux)
}
```

# 运行代码

我们可以直接运行程序使用 run 命令：

```go
go run customMux.go
```

现在，让我们执行两个 CURL 命令并查看输出：

```go
curl -X GET http://localhost:8000/randomFloat
curl -X GET http://localhost:8000/randomInt
```

响应将是：

```go
0.6046602879796196
87
```

由于随机数生成器，您的响应可能会发生变化。

我们看到了如何使用基本的 Go 构造创建 URL 路由器。现在我们将看一下一些广泛被 Go 社区用于其 API 服务器的流行 URL 路由框架。

# 介绍 httprouter，一个轻量级的 HTTP 路由器

**httprouter**，顾名思义，将 HTTP 请求路由到特定的处理程序。与基本路由器相比，它具有以下特点：

+   允许在路由路径中使用变量

+   它匹配 REST 方法（`GET`，`POST`，`PUT`等）

+   不会影响性能

我们将在下一节中更详细地讨论这些特性。在那之前，有一些值得注意的点，使 httprouter 成为一个更好的 URL 路由器：

+   httprouter 与内置的`http.Handler`很好地配合

+   httprouter 明确表示一个请求只能匹配一个路由或没有

+   路由器的设计鼓励构建合理的、分层的 RESTful API

+   您可以构建高效的静态文件服务器

# 安装

要安装 httprouter，我们只需要运行`get`命令：

```go
go get github.com/julienschmidt/httprouter
```

所以，现在我们有了`httprouter`。我们可以在我们的源代码中引用这个库：

```go
import "github.com/julienschmidt/httprouter"
```

通过一个例子可以理解 httprouter 的基本用法。在这个例子中，让我们创建一个小型 API，从服务器获取有关文件和程序安装的信息。在直接进入程序之前，您应该知道如何在 Go 上执行系统命令。有一个叫做`os/exec`的包。它允许我们执行系统命令并将输出返回给程序。

```go
import "os/exec"
```

然后它可以在代码中被访问为这样：

```go
// arguments... means an array of strings unpacked as arguments in Go
cmd := exec.Command(command, arguments...)
```

**`exec.Command`**是一个接受命令和额外参数数组的函数。额外的参数是命令的选项或输入。它可以通过两种方式执行：

+   立即运行命令

+   启动并等待其完成

我们可以通过将`Stdout`附加到自定义字符串来收集命令的输出。获取该字符串并将其发送回客户端。代码在这里更有意义。让我们编写一个 Go 程序来创建一个 REST 服务，它可以做两件事：

+   获取 Go 版本

+   获取给定文件的文件内容

这个程序使用`Hhttprouter`创建服务。让我们将其命名为`execService.go`：

```go
package main
import (
        "bytes"
        "fmt"
        "log"
        "net/http"
        "os/exec"
        "github.com/julienschmidt/httprouter"
)
// This is a function to execute a system command and return output
func getCommandOutput(command string, arguments ...string) string {
        // args... unpacks arguments array into elements
        cmd := exec.Command(command, arguments...)
        var out bytes.Buffer
        var stderr bytes.Buffer
        cmd.Stdout = &out
        cmd.Stderr = &stderr
        err := cmd.Start()
        if err != nil {
                log.Fatal(fmt.Sprint(err) + ": " + stderr.String())
        }
        err = cmd.Wait()
        if err != nil {
                log.Fatal(fmt.Sprint(err) + ": " + stderr.String())
        }
        return out.String()
}
func goVersion(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
        fmt.Fprintf(w, getCommandOutput("/usr/local/bin/go", "version"))
}
func getFileContent(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
        fmt.Fprintf(w, getCommandOutput("/bin/cat",
params.ByName("name")))
}
func main() {
        router := httprouter.New()
        // Mapping to methods is possible with HttpRouter
        router.GET("/api/v1/go-version", goVersion)
        // Path variable called name used here
        router.GET("/api/v1/show-file/:name", getFileContent)
        log.Fatal(http.ListenAndServe(":8000", router))
}
```

# 程序解释

前面的程序试图使用`httprouter`**实现 REST 服务。**我们在这里定义了两个路由：

+   `/api/v1/go-version`

+   `/api/v1/show-file/:name`

这里的`:name`是路径参数。它表示显示名为 xyz 的文件的 API。基本的 Go 路由器无法处理这些参数，通过使用`httprouter`，我们还可以匹配 REST 方法。在程序中，我们匹配了`GET`请求。

在一个逐步的过程中，前面的程序：

+   导入了`httprouter`和其他必要的 Go 包

+   使用`httprouter`的`New()`方法创建了一个新的路由器

+   路由器有`GET`，`POST`，`DELETE`等方法

+   `GET`方法接受两个参数，`URL 路径表达式`和`处理程序函数`

+   这个路由器可以传递给 http 的`ListenAndServe`函数

+   现在，谈到处理程序，它们看起来与属于 ServeMux 的处理程序相似，但第三个参数称为**`httprouter.Params`**保存有关使用`GET`请求提供的所有参数的信息

+   我们定义了路径参数（URL 路径中的变量）称为`name`并在程序中使用它

+   `getCommandOutput`函数接受命令和参数并返回输出

+   第一个 API 调用 Go 版本并将输出返回给客户端

+   第二个 API 执行了文件的`cat`命令并将其返回给客户端

如果您观察代码，我使用了`/usr/local/bin/go`作为 Go 可执行文件位置，因为这是我 MacBook 上的 Go 编译器位置。在执行`exec.Command`时，您应该给出可执行文件的绝对路径。因此，如果您在 Ubuntu 机器或 Windows 上工作，请使用可执行文件的路径。在 Linux 机器上，您可以通过使用`$ which go`命令轻松找到。

现在在同一目录中创建两个新文件。这些文件将由我们的文件服务器程序提供。您可以在此目录中创建任何自定义文件进行测试：

`Latin.txt`：

```go
Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean commodo ligula eget dolor. Aenean massa. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Donec quam felis, ultricies nec, pellentesque eu, pretium quis, sem. Nulla consequat massa quis enim. Donec pede justo, fringilla vel, aliquet nec, vulputate eget, arcu.
```

`Greek.txt`：

```go
Οἱ δὲ Φοίνιϰες οὗτοι οἱ σὺν Κάδμῳ ἀπιϰόμενοι.. ἐσήγαγον διδασϰάλια ἐς τοὺς ῞Ελληνας ϰαὶ δὴ ϰαὶ γράμματα, οὐϰ ἐόντα πρὶν ῞Ελλησι ὡς ἐμοὶ δοϰέειν, πρῶτα μὲν τοῖσι ϰαὶ ἅπαντες χρέωνται Φοίνιϰες· μετὰ δὲ χρόνου προβαίνοντος ἅμα τῇ ϕωνῇ μετέβαλον ϰαὶ τὸν ϱυϑμὸν τῶν γραμμάτων. Περιοίϰεον δέ σϕεας τὰ πολλὰ τῶν χώρων τοῦτον τὸν χρόνον ῾Ελλήνων ῎Ιωνες· οἳ παραλαβόντες διδαχῇ παρὰ τῶν Φοινίϰων τὰ γράμματα, μεταρρυϑμίσαντές σϕεων ὀλίγα ἐχρέωντο, χρεώμενοι δὲ ἐϕάτισαν, ὥσπερ ϰαὶ τὸ δίϰαιον ἔϕερε ἐσαγαγόντων Φοινίϰων ἐς τὴν ῾Ελλάδα, ϕοινιϰήια ϰεϰλῆσϑαι.
```

现在使用此命令运行程序。这一次，我们不使用 CURL 命令，而是使用浏览器作为我们的`GET`输出。Windows 用户可能没有 CURL 作为首选应用程序。他们可以在开发 REST API 时使用像 postman 客户端这样的 API 测试软件。看一下以下命令：

```go
go run execService.go
```

第一个`GET`请求的输出如下：

```go
curl -X GET http://localhost:8000/api/v1/go-version
```

结果将是这样的：

```go
go version go1.8.3 darwin/amd64
```

第二个`GET`请求请求`Greek.txt`是：

```go
curl -X GET http://localhost:8000/api/v1/show-file/greek.txt
```

现在，我们将看到希腊语的文件输出如下：

```go
Οἱ δὲ Φοίνιϰες οὗτοι οἱ σὺν Κάδμῳ ἀπιϰόμενοι.. ἐσήγαγον διδασϰάλια ἐς τοὺς ῞Ελληνας ϰαὶ δὴ ϰαὶ γράμματα, οὐϰ ἐόντα πρὶν ῞Ελλησι ὡς ἐμοὶ δοϰέειν, πρῶτα μὲν τοῖσι ϰαὶ ἅπαντες χρέωνται Φοίνιϰες· μετὰ δὲ χρόνου προβαίνοντος ἅμα τῇ ϕωνῇ μετέβαλον ϰαὶ τὸν ϱυϑμὸν τῶν γραμμάτων. Περιοίϰεον δέ σϕεας τὰ πολλὰ τῶν χώρων τοῦτον τὸν χρόνον ῾Ελλήνων ῎Ιωνες· οἳ παραλαβόντες διδαχῇ παρὰ τῶν Φοινίϰων τὰ γράμματα, μεταρρυϑμίσαντές σϕεων ὀλίγα ἐχρέωντο, χρεώμενοι δὲ ἐϕάτισαν, ὥσπερ ϰαὶ τὸ δίϰαιον ἔϕερε ἐσαγαγόντων Φοινίϰων ἐς τὴν ῾Ελλάδα, ϕοινιϰήια ϰεϰλῆσϑαι.
```

# 在几分钟内构建简单的静态文件服务器

有时，作为 API 的一部分，我们应该提供静态文件。httprouter 的另一个应用是构建可扩展的文件服务器。这意味着我们可以构建自己的内容传递平台。一些客户端需要从服务器获取静态文件。传统上，我们使用 Apache2 或 Nginx 来实现这一目的。但是，从 Go 服务器内部，为了提供静态文件，我们需要通过类似这样的通用路由进行路由：

```go
/static/*
```

请参阅以下代码片段以了解我们的实现。想法是使用`http.Dir`方法加载文件系统，然后使用`httprouter`实例的**`ServeFiles` **函数。它应该提供给定公共目录中的所有文件。通常，静态文件保存在 Linux 机器上的文件夹**`/var/public/www` **中。由于我使用的是 OS X，我在我的主目录中创建了一个名为`static`的文件夹：

```go
mkdir /users/naren/static
```

现在，我复制了我们为上一个示例创建的`Latin.txt`和`Greek.txt`文件到之前的静态目录。在这样做之后，让我们为文件服务器编写程序。您会对`httprouter`的简单性感到惊讶。创建一个名为`fileserver.go`的程序：

```go
package main
import (
    "github.com/julienschmidt/httprouter"
    "log"
    "net/http"
)
func main() {
    router := httprouter.New()
    // Mapping to methods is possible with HttpRouter
    router.ServeFiles("/static/*filepath",
http.Dir("/Users/naren/static"))
    log.Fatal(http.ListenAndServe(":8000", router))
}
```

现在运行服务器并查看输出：

```go
go run fileserver.go
```

现在，让我们打开另一个终端并发送这个 CURL 请求：

```go
http://localhost:8000/static/latin.txt
```

现在，输出将是来自我们文件服务器的静态文件内容服务器：

```go
Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean commodo ligula eget dolor. Aenean massa. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Donec quam felis, ultricies nec, pellentesque eu, pretium quis, sem. Nulla consequat massa quis enim. Donec pede justo, fringilla vel, aliquet nec, vulputate eget, arcu.
```

# 介绍 Gorilla Mux，一个强大的 HTTP 路由器

Mux 代表多路复用器。同样，Gorilla Mux 是一个设计用于将 HTTP 路由（URL）多路复用到不同处理程序的多路复用器。处理程序是可以处理给定请求的函数。Gorilla Mux 是一个非常好的包，用于为我们的 Web 应用程序和 API 服务器编写美丽的路由。

Gorilla Mux 提供了大量选项来控制路由到您的 Web 应用程序的方式。它允许许多功能。其中一些是：

+   基于路径的匹配

+   基于查询的匹配

+   基于域的匹配

+   基于子域的匹配

+   反向 URL 生成

# 安装

安装 Mux 包非常简单。您需要在终端（Mac 和 Linux）中运行此命令：

```go
go get -u github.com/gorilla/mux
```

如果您收到任何错误，说`package github.com/gorilla/mux: cannot download, $GOPATH not set. For more details see--go help gopath`，请使用以下命令设置`$GOPATH`环境变量：

```go
export GOPATH=~/go
```

正如我们在上一章中讨论的，这意味着所有的包和程序都放在这个目录中。它有三个文件夹：`bin`，`pkg`和`src`。现在，将`GOPATH`添加到`PATH`变量中，以便使用已安装的 bin 文件作为没有`./executable`样式的系统实用程序。参考以下命令：

```go
PATH="$GOPATH/bin:$PATH"
```

这些设置会一直保留，直到您关闭计算机。因此，要使其成为永久更改，请将上述行添加到您的 bash 配置文件中：

```go
vi ~/.profile
(or)
vi ~/.zshrc 
```

现在，我们已经准备好了。假设 Gorilla Mux 已安装，请继续进行基本操作。

# Gorilla Mux 的基础知识

Gorilla Mux 允许我们创建一个新的路由器，类似于 httprouter。但是在两者之间，将处理程序函数附加到给定的 URL 路由的方式是不同的。如果我们观察一下，Mux 附加处理程序的方式类似于基本 ServeMux。与 httprouter 不同，它修改请求对象而不是使用附加参数将 URL 参数传递给处理程序函数。我们可以使用`Vars`方法访问参数。

我将从 Gorilla Mux 主页上的一个示例来解释它有多有用。创建一个名为`muxRouter.go`的文件，并添加以下代码：

```go
package main
import (
    "fmt"
    "log"
    "net/http"
    "time"
    "github.com/gorilla/mux"
)
// ArticleHandler is a function handler
func ArticleHandler(w http.ResponseWriter, r *http.Request) {
    // mux.Vars returns all path parameters as a map
    vars := mux.Vars(r)
    w.WriteHeader(http.StatusOK)
    fmt.Fprintf(w, "Category is: %v\n", vars["category"])
    fmt.Fprintf(w, "ID is: %v\n", vars["id"])
}
func main() {
    // Create a new router
    r := mux.NewRouter()
    // Attach a path with handler
    r.HandleFunc("/articles/{category}/{id:[0-9]+}", ArticleHandler)
    srv := &http.Server{
        Handler: r,
        Addr: "127.0.0.1:8000",
        // Good practice: enforce timeouts for servers you create!
        WriteTimeout: 15 * time.Second,
        ReadTimeout: 15 * time.Second,
    }
    log.Fatal(srv.ListenAndServe())
}
```

现在使用以下命令运行文件：

```go
go run muxRouter.go
```

通过以这种方式运行 CURL 命令，我们可以得到以下输出：

```go
curl http://localhost:8000/articles/books/123
Category is: books
ID is: 123
```

Mux 解析路径中的变量。通过调用`Vars`函数，可以使用解析的所有变量。不要陷入上述程序的自定义服务器细节中。只需观察 Mux 代码。我们将处理程序附加到 URL。我们将解析的变量写回 HTTP 响应。这一行很关键。在这里，`id`有一个正则表达式，表示`id`是一个数字（0-9），有一个或多个数字：

```go
r.HandleFunc("/articles/{category}/{id:[0-9]+}", ArticleHandler)
```

让我们称之为路由。有了这种模式匹配的灵活性，我们可以非常舒适地设计 RESTful API。

使用`http.StatusOK`写入响应的标头，以宣布 API 请求成功。同样，http 有许多状态代码，用于各种类型的 HTTP 请求。使用适当的状态代码传达正确的消息。例如，404 - 未找到，500 - 服务器错误，等等。

# 反向映射 URL

简单地说，反向映射 URL 就是获取 API 资源的 URL。当我们需要分享链接到我们的 Web 应用程序或 API 时，反向映射非常有用。但是为了从数据中创建 URL，我们应该将`Name`与 Mux 路由关联起来：

```go
r.HandlerFunc("/articles/{category}/{id:[0-9]+}", ArticleHandler).
  Name("articleRoute")
```

现在，如果我们有数据，我们可以形成一个 URL：

```go
url, err := r.Get("articleRoute").URL("category", "books", "id", "123")
fmt.Printf(url.URL) // prints /articles/books/123
```

Gorilla Mux 在创建自定义路由方面提供了很大的灵活性。它还允许方法链接以向创建的路由添加属性。

# 自定义路径

我们可以分两步定义前面的路由：

+   首先，在路由器上定义路径：

```go
      r := mux.NewRouter()
```

+   接下来，在路由器上定义处理程序：

```go
      r.Path("/articles/{category}/{id:[0-  9]+}").HandlerFunc(ArticleHandler) //chaining is possible
```

请注意，此处链接的方法是`HandlerFunc`而不是前面代码中显示的`HandleFunc`。我们可以使用`Subrouter`在 Mux 中轻松创建顶级路径并为不同的处理程序添加子路径：

```go
r := mux.NewRouter()
s := r.PathPrefix("/articles").Subrouter()
s.HandleFunc("{id}/settings", settingsHandler)
s.HandleFunc("{id}/details", detailsHandler)
```

因此，形式为`http://localhost:8000/articles/123/settings`的所有 URL 将重定向到`settingsHandler`，形式为`http://localhost:8000/articles/123/details`的所有 URL 将重定向到**`detailsHandler`**。当我们为特定 URL 路径创建命名空间时，这可能非常有用。

# 路径前缀

**路径前缀**是在定义路径之后进行匹配的通配符。一般用例是当我们从静态文件夹中提供文件并且所有 URL 都应该按原样提供时。从官方 Mux 文档中，我们可以用它来提供静态文件。这是使用`httprouter`在前面的程序中创建的静态文件服务器的 Mux 版本：

```go
r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("/tmp/static"))))
```

这可以提供目录中的所有类型的文件：

```go
http://localhost:8000/static/js/jquery.min.js 
```

# Strict Slash

Strict Slash 是 Mux 路由器上的一个参数，可以让路由器将带有尾随斜杠的 URL 路由重定向到没有尾随斜杠的路由。例如，**`/articles/`**可以是原始路径，但带有`/path`的路由将被重定向到原始路径：

```go
r := mux.NewRouter() 
r.StrictSlash(true)
r.Path("/articles/").Handler(ArticleHandler)
```

如果将`StrictSlash`参数设置为`true`，此 URL 将重定向到前面的`ArticleHandler`：

```go
http://localhost:8000/articles
```

# 编码路径

我们可以从一些客户端获取编码路径。为了处理这些编码路径，Mux 提供了一个名为**`UseEncodedPath`**的方法。如果我们在路由器变量上调用此方法，甚至可以匹配编码的 URL 路由并将其转发给给定的处理程序：

```go
r := NewRouter() 
r.UseEncodedPath()
r.NewRoute().Path("/category/id")
```

这可以匹配 URL：

```go
http://localhost:8000/books/1%2F2
```

`%2F`代表未编码形式中的`/`。如果不使用`UseEncodedPath`方法，路由器可能会将其理解为`/v1/1/2`。

# 基于查询的匹配

查询参数是与 URL 一起传递的参数。这是我们通常在 REST `GET`请求中看到的。Gorilla Mux 可以创建一个路由，用于匹配具有给定查询参数的 URL：

```go
http://localhost:8000/articles/?id=123&category=books
```

让我们给我们的程序添加功能：

```go
// Add this in your main program
r := mux.NewRouter()
r.HandleFunc("/articles", QueryHandler)
r.Queries("id", "category")
```

它限制了前面 URL 的查询。`id`和`category`与`Queries`列表匹配。参数允许为空值。`QueryHandler`如下所示。您可以使用`request.URL.Query()`在处理程序函数中获取查询参数：

```go
func QueryHandler(w http.ResponseWriter, r *http.Request){
  queryParams := r.URL.Query()
  w.WriteHeader(http.StatusOK)
  fmt.Fprintf(w, "Got parameter id:%s!\n", queryParams["id"])
  fmt.Fprintf(w, "Got parameter category:%s!", queryParams["category"])
}
```

# 基于主机的匹配

有时我们需要允许来自特定主机的请求。如果主机匹配，则请求将继续传递到路由处理程序。如果我们有多个域和子域并将它们与自定义路由匹配，这可能非常有用。

使用路由器变量上的`Host`方法，我们可以调节从哪些主机重定向路由：

```go
r := mux.NewRouter()
r.Host("aaa.bbb.ccc")
r.HandleFunc("/id1/id2/id3", MyHandler)
```

如果我们设置了这个，来自`aaa.bbb.ccc`主机的形式为`http://aaa.bbb.ccc/111/222/333`的所有请求将被匹配。类似地，我们可以使用`Schemes`来调节 HTTP 方案（http，https）和使用`Methods` Mux 函数来调节 REST 方法（`GET`，`POST`）。程序`queryParameters.go`解释了如何在处理程序中使用查询参数：

```go
package main
import (
    "fmt"
    "log"
    "net/http"
    "time"
    "github.com/gorilla/mux"
)
func QueryHandler(w http.ResponseWriter, r *http.Request) {
    // Fetch query parameters as a map
    queryParams := r.URL.Query()
    w.WriteHeader(http.StatusOK)
    fmt.Fprintf(w, "Got parameter id:%s!\n", queryParams["id"][0])
    fmt.Fprintf(w, "Got parameter category:%s!",
queryParams["category"][0])
}
func main() {
    // Create a new router
    r := mux.NewRouter()
    // Attach a path with handler
    r.HandleFunc("/articles", QueryHandler)
    r.Queries("id", "category")
    srv := &http.Server{
        Handler: r,
        Addr: "127.0.0.1:8000",
        // Good practice: enforce timeouts for servers you create!
        WriteTimeout: 15 * time.Second,
        ReadTimeout: 15 * time.Second,
    }
    log.Fatal(srv.ListenAndServe())
}
```

输出如下：

```go
go run queryParameters.go
```

让我们在终端中以这种格式发送一个 CURL 请求：

```go
curl -X GET http://localhost:8000/articles\?id\=1345\&category\=birds
```

我们需要在 shell 中转义特殊字符。如果在浏览器中，转义就没有问题。输出如下：

```go
Got parameter id:1345! 
Got parameter category:birds!
```

**`r.URL.Query()` **函数返回一个带有所有参数和值对的映射。它们基本上是字符串，为了在我们的程序逻辑中使用它们，我们需要将数字字符串转换为整数。我们可以使用 Go 的`strconv`包将字符串转换为整数，反之亦然。

其模式匹配功能和简单性使 Gorilla Mux 成为项目中 HTTP 路由器的热门选择。全球许多成功的项目已经在其路由需求中使用 Mux。

# URL 中的 SQL 注入及避免它们的方法

SQL 注入是使用恶意脚本攻击数据库的过程。如果我们在编写安全的 URL 路由时不小心，可能会存在 SQL 注入的机会。这些攻击通常发生在`POST`，`PUT`和`DELETE` HTTP 动词中。例如，如果我们允许客户端向服务器传递变量，那么攻击者有机会向这些变量附加一个字符串。如果我们直接将这些发送参数的用户插入到 SQL 查询中，那么它可能是可注入的。与数据库交谈的正确方式是允许驱动程序函数在插入字符串并在数据库中执行之前检查参数：

```go
username := r.Form.Get("id")
password := r.Form.Get("category")
sql := "SELECT * FROM article WHERE id='" + username + "' AND category='" + password + "'"
Db.Exec(sql)
```

在这个片段中，我们试图通过 id 和类别获取有关文章的信息。我们正在执行一个 SQL 查询。但由于我们直接附加值，我们可能在查询中包含恶意的 SQL 语句，如（`--`）注释和（`ORDER BY n`）范围子句：

```go
?category=books&id=10 ORDER BY 10--
```

这将泄漏表中的列信息。我们可以更改数字并查看我们从数据库收到错误消息的断点：

```go
Unknown column '10' in 'order clause'
```

我们将在接下来的章节中了解更多信息，我们将在其中使用其他方法构建完整的 REST 服务，如`POST`，`PUT`等：

现在，如何避免这些注入。有几种方法：

+   将用户级别权限设置为各种表

+   在使用 URL 参数时，仔细观察模式

+   使用 Go 的`text/template`包中的**`HTMLEscapeString`**函数来转义 API 参数中的特殊字符，如`body`和`path`

+   使用驱动程序代替执行原始 SQL 查询

+   停止数据库调试消息传回客户端

+   使用`sqlmap`等安全工具查找漏洞

# 为 URL 缩短服务创建基本的 API 布局

您是否曾经想过 URL 缩短服务是如何工作的？它们将一个非常长的 URL 转换为一个缩短、简洁和易记的 URL 提供给用户。乍一看，它看起来像魔术，但实际上是一个简单的数学技巧。

简而言之，URL 缩短服务建立在两个基础上：

+   一种字符串映射算法，将长字符串映射到短字符串（Base 62）

+   一个简单的 Web 服务器，将短 URL 重定向到原始 URL

URL 缩短有一些明显的优势：

+   用户可以记住 URL；易于维护

+   用户可以在文本长度有限的链接上使用，例如 Twitter

+   可预测的缩短 URL 长度

看一下下面的图表：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/cf0a2e5f-f392-415a-bbe6-e449a1baa9e2.jpg)

在 URL 缩短服务中，这些事情在幕后默默发生：

+   获取原始 URL。

+   对其应用 Base62 编码。它会生成一个缩短的 URL。

+   将该 URL 存储在数据库中。将其映射到原始 URL（`[shortened_url: orignial_url]`）。

+   每当请求到达缩短的 URL 时，只需对原始 URL 进行 HTTP 重定向。

我们将在接下来的章节中实现完整的逻辑，当我们将数据库集成到我们的 API 服务器时，但在那之前，我们应该指定 API 设计文档。让我们来做。看一下下表：

| **URL** | **REST 动词** | **动作** | **成功** | 失败 |
| --- | --- | --- | --- | --- |
| `/api/v1/new` | `POST` | 创建缩短的 URL | 200 | 500, 404 |
| `/api/v1/:url` | `GET` | 重定向到原始 URL | 301 | 404 |

作为练习，读者可以根据我们迄今为止建立的基础来实现这一点。您可以使用一个虚拟的 JSON 文件，而不是像我们在第一章中所做的那样使用数据库。无论如何，我们将在接下来的章节中实现这一点。

# 摘要

在本章中，我们首先介绍了 HTTP 路由器。我们尝试使用 Go 的 http 包构建了一个基本的应用程序。然后我们简要讨论了 ServeMux，并举例说明。我们看到了如何向多个路由添加多个处理程序。然后我们介绍了一个轻量级的路由器包，名为`httprouter`。`httprouter`允许开发人员创建可扩展的路由，还可以选择解析 URL 路径中传递的参数。我们还可以使用`httprouter`在 HTTP 上提供文件。我们构建了一个小型服务来获取 Go 版本和文件内容（只读）。该示例可以扩展到任何系统信息。

接下来，我们介绍了流行的 Go 路由库：`Gorilla Mux`。我们讨论了它与`httprouter`的不同之处，并通过实现实例来探索其功能。我们解释了如何使用`Vars`来获取路径参数和使用`r.URL.Query`来解析查询参数。然后我们讨论了 SQL 注入以及它如何在我们的应用程序中发生。我们给出了一些建议，以避免它。当我们构建一个包含数据库的完整 REST 服务时，我们将在即将到来的章节中看到这些措施。最后，我们制定了 URL 缩短的逻辑，并创建了一个 API 设计文档。

在下一章中，我们将介绍`中间件`函数，它们充当 HTTP 请求和响应的篡改者。这种现象将帮助我们即时修改 API 响应。下一章还涉及`RPC`（远程过程调用）。


# 第三章：使用中间件和 RPC 进行工作

在本章中，我们将研究中间件功能。什么是中间件，我们如何从头开始构建它？接下来，我们将转向为我们编写的更好的中间件解决方案，称为 Gorilla Handlers。然后，我们将尝试理解中间件可以帮助的一些用例。之后，我们将开始使用 Go 的内部 RPC 和 JSON RPC 构建我们的 RPC 服务。然后我们将转向一个高级的 RPC 框架，如 Gorilla HTTP RPC。

本章涵盖的主题有：

+   什么是中间件？

+   什么是 RPC（远程过程调用）？

+   我们如何在 Go 中实现 RPC 和 JSON RPC？

# 获取代码

本章的所有代码都可以在[`github.com/narenaryan/gorestful/tree/master/chapter3`](https://github.com/narenaryan/gorestful/tree/master/chapter3)找到。请参考第一章，*开始 REST API 开发*，以设置 Go 项目并运行程序。最好从 GitHub 克隆整个`gorestful`存储库。

# 什么是中间件？

中间件是一个钩入服务器请求/响应处理的实体。中间件可以在许多组件中定义。每个组件都有特定的功能要执行。每当我们为我们的 URL 模式定义处理程序（就像在上一章中那样），请求会命中处理程序并执行业务逻辑。因此，几乎所有中间件都应按顺序执行这些功能：

1.  在命中处理程序（函数）之前处理请求

1.  处理处理程序函数

1.  在将其提供给客户端之前处理响应

我们可以看到以可视化形式呈现的先前的要点：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/50edf7ee-41ae-4e5e-8f94-558c488e93f9.png)

如果我们仔细观察图表，请求的旅程始于客户端。在没有中间件的应用程序中，请求到达 API 服务器，并将由某个函数处理程序处理。响应立即从服务器发送回来，客户端接收到它。但在具有中间件的应用程序中，它通过一系列阶段，如日志记录、身份验证、会话验证等，然后继续到业务逻辑。这是为了过滤错误的请求，防止其与业务逻辑交互。最常见的用例有：

+   使用记录器记录每个请求命中 REST API

+   验证用户会话并保持通信活动

+   如果用户未经身份验证，则对用户进行身份验证

+   编写自定义逻辑以获取请求数据

+   在为客户端提供服务时附加属性到响应

借助中间件，我们可以将诸如身份验证之类的杂务工作保持在适当的位置。让我们创建一个基本的中间件并在 Go 中篡改 HTTP 请求。

当需要为每个请求或 HTTP 请求子集执行一段代码时，应该定义中间件函数。如果没有它们，我们需要在每个处理程序中重复逻辑。

# 创建基本中间件

构建中间件简单而直接。让我们根据第二章所学的知识构建一个程序。如果您对闭包函数不熟悉，闭包函数返回另一个函数。这个原则帮助我们编写中间件。我们应该做的第一件事是实现一个满足 http.Handler 接口的函数。

一个名为`closure.go`的示例闭包如下：

```go
package main
import (
    "fmt"
)
func main() {
    numGenerator := generator()
    for i := 0; i < 5; i++ {
        fmt.Print(numGenerator(), "\t")
    }
}
// This function returns another function
func generator() func() int {
    var i = 0
    return func() int {
        i++
        return i
    }
}
```

如果我们运行这段代码：

```go
go run closure.go
```

数字将使用制表符生成并打印：

```go
1 2 3 4 5
```

我们正在创建一个名为 generator 的闭包函数，并调用它以获取一个新的数字。生成器模式根据给定条件每次生成一个新项。返回的内部函数是一个匿名函数，没有参数，一个整数类型的返回类型。在外部函数中定义的变量`i`可用于匿名函数，使其在将来计算逻辑时有用。闭包的另一个很好的示例应用是创建一个计数器。您可以通过遵循前面代码中应用的相同逻辑来实现它。

在 Go 中，外部函数的函数签名应该与匿名函数的函数签名完全匹配。在前面的例子中，`func() int`是外部和内部函数的签名。

这个例子是为了理解闭包在 Go 中是如何工作的。现在，让我们使用这个概念来组合我们的第一个中间件：

```go
package main
import (
    "fmt"
    "net/http"
)
func middleware(handler http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        fmt.Println("Executing middleware before request phase!")
        // Pass control back to the handler
        handler.ServeHTTP(w, r)
        fmt.Println("Executing middleware after response phase!")
    })
}
func mainLogic(w http.ResponseWriter, r *http.Request) {
    // Business logic goes here
    fmt.Println("Executing mainHandler...")
    w.Write([]byte("OK"))
}
func main() {
    // HandlerFunc returns a HTTP Handler
    mainLogicHandler := http.HandlerFunc(mainLogic)
    http.Handle("/", middleware(mainLogicHandler))
    http.ListenAndServe(":8000", nil)
}
```

让我们运行代码：

```go
go run customMiddleware.go
```

如果您使用 CURL 请求或在浏览器中查看`http://localhost:8000`，控制台将收到此消息：

```go
Executing middleware before request phase!
Executing mainHandler...
Executing middleware after response phase!
```

如果您观察之前提供的中间件示意图，请求阶段由右箭头指向，响应是左箭头。这个程序实际上是最右边的矩形，也就是`CustomMiddleware`。

简单来说，前面的程序可以分解为这样：

+   通过将主处理程序函数（`mainLogic`）传递给`http.HandlerFunc()`来创建一个处理程序函数。

+   创建一个接受处理程序并返回处理程序的中间件函数。

+   方法`ServeHTTP`允许处理程序执行处理程序逻辑，即`mainLogic`。

+   `http.Handle`函数期望一个 HTTP 处理程序。考虑到这一点，我们以这样一种方式包装我们的逻辑，最终返回一个处理程序，但执行被修改了。

+   我们将主处理程序传递给中间件。然后中间件接管并返回一个函数，同时将主处理程序逻辑嵌入其中。这样，所有发送到处理程序的请求都会通过中间件逻辑。

+   打印语句的顺序解释了请求的过程。

+   最后，我们在`8000`端口上提供服务器。

像 Martini、Gin 这样的 Go Web 框架默认提供中间件。我们将在接下来的章节中了解更多关于它们的内容。对于开发人员来说，了解中间件的底层细节是很有益的。

以下的图表可以帮助您理解中间件中逻辑流程的发生：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/a4a887a7-9856-4aef-8414-9841ccb57e58.png)

# 多个中间件和链接

在前面的部分，我们构建了一个单个中间件，在请求到达处理程序之前或之后执行操作。也可以链接一组中间件。为了做到这一点，我们应该遵循与前一部分相同的闭包逻辑。让我们创建一个用于保存城市详细信息的城市 API。为了简单起见，API 将只有一个 POST 方法，主体包括两个字段：城市名称和城市面积。

让我们考虑一个场景，API 开发人员只允许客户端使用 JSON 媒体类型，并且需要为每个请求将服务器时间以 UTC 格式发送回客户端。使用中间件，我们可以做到这一点。

两个中间件的功能是：

+   在第一个中间件中，检查内容类型是否为 JSON。如果不是，则不允许请求继续进行。

+   在第二个中间件中，向响应 cookie 添加一个名为 Server-Time（UTC）的时间戳

首先，让我们创建`POST` API：

```go
package main

 import (
     "encoding/json"
     "fmt"
     "net/http"
 )

 type city struct {
     Name string
     Area uint64
 }

 func mainLogic(w http.ResponseWriter, r *http.Request) {
     // Check if method is POST
     if r.Method == "POST" {
         var tempCity city
         decoder := json.NewDecoder(r.Body)
         err := decoder.Decode(&tempCity)
         if err != nil {
             panic(err)
         }
         defer r.Body.Close()
         // Your resource creation logic goes here. For now it is plain print to console
         fmt.Printf("Got %s city with area of %d sq miles!\n", tempCity.Name, tempCity.Area)
         // Tell everything is fine
         w.WriteHeader(http.StatusOK)
         w.Write([]byte("201 - Created"))
     } else {
         // Say method not allowed
         w.WriteHeader(http.StatusMethodNotAllowed)
         w.Write([]byte("405 - Method Not Allowed"))
     }
 }

 func main() {
     http.HandleFunc("/city", mainLogic)
     http.ListenAndServe(":8000", nil)
 }
```

如果我们运行这个：

```go
go run cityAPI.go
```

然后给一个 CURL 请求：

```go
curl -H "Content-Type: application/json" -X POST http://localhost:8000/city -d '{"name":"New York", "area":304}'

curl -H "Content-Type: application/json" -X POST http://localhost:8000/city -d '{"name":"Boston", "area":89}'
```

Go 给了我们以下内容：

```go
Got New York city with area of 304 sq miles!
Got Boston city with area of 89 sq miles!
```

CURL 的响应将是：

```go
201 - Created
201 - Created
```

为了链接，我们需要在多个中间件之间传递处理程序。

以下是简单步骤中的程序：

+   我们创建了一个允许 POST 方法的 REST API。它还不完整，因为我们没有将数据存储到数据库或文件中。

+   我们导入了`json`包，并用它解码了客户端提供的 POST 主体。接下来，我们创建了一个映射 JSON 主体的结构。

+   然后，JSON 被解码并将信息打印到控制台。

在前面的例子中只涉及一个处理程序。但是，对于即将到来的任务，想法是将主处理程序传递给多个中间件处理程序。完整的代码看起来像这样：

```go
package main
import (
    "encoding/json"
    "log"
    "net/http"
    "strconv"
    "time"
)
type city struct {
    Name string
    Area uint64
}
// Middleware to check content type as JSON
func filterContentType(handler http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        log.Println("Currently in the check content type middleware")
        // Filtering requests by MIME type
        if r.Header.Get("Content-type") != "application/json" {
            w.WriteHeader(http.StatusUnsupportedMediaType)
            w.Write([]byte("415 - Unsupported Media Type. Please send JSON"))
            return
        }
        handler.ServeHTTP(w, r)
    })
}
// Middleware to add server timestamp for response cookie
func setServerTimeCookie(handler http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        handler.ServeHTTP(w, r)
        // Setting cookie to each and every response
        cookie := http.Cookie{Name: "Server-Time(UTC)", Value: strconv.FormatInt(time.Now().Unix(), 10)}
        http.SetCookie(w, &cookie)
        log.Println("Currently in the set server time middleware")
    })
}
func mainLogic(w http.ResponseWriter, r *http.Request) {
    // Check if method is POST
    if r.Method == "POST" {
        var tempCity city
        decoder := json.NewDecoder(r.Body)
        err := decoder.Decode(&tempCity)
        if err != nil {
            panic(err)
        }
        defer r.Body.Close()
        // Your resource creation logic goes here. For now it is plain print to console
        log.Printf("Got %s city with area of %d sq miles!\n", tempCity.Name, tempCity.Area)
        // Tell everything is fine
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("201 - Created"))
    } else {
        // Say method not allowed
        w.WriteHeader(http.StatusMethodNotAllowed)
        w.Write([]byte("405 - Method Not Allowed"))
    }
}
func main() {
    mainLogicHandler := http.HandlerFunc(mainLogic)
    http.Handle("/city", filterContentType(setServerTimeCookie(mainLogicHandler)))
    http.ListenAndServe(":8000", nil)
}
```

现在，如果我们运行这个：

```go
go run multipleMiddleware.go
```

并为 CURL 命令运行这个：

```go
curl -i -H "Content-Type: application/json" -X POST http://localhost:8000/city -d '{"name":"Boston", "area":89}'
```

输出是：

```go
HTTP/1.1 200 OK
Date: Sat, 27 May 2017 14:35:46 GMT
Content-Length: 13
Content-Type: text/plain; charset=utf-8

201 - Created
```

但是，如果我们尝试从 CURL 命令中删除`Content-Type:application/json`，中间件会阻止我们执行主处理程序：

```go
curl -i -X POST http://localhost:8000/city -d '{"name":"New York", "area":304}' 
HTTP/1.1 415 Unsupported Media Type
Date: Sat, 27 May 2017 15:36:58 GMT
Content-Length: 46
Content-Type: text/plain; charset=utf-8

415 - Unsupported Media Type. Please send JSON
```

并且 cookie 将从另一个中间件设置。

在前面的程序中，我们使用 log 而不是`fmt`包。尽管两者都是做同样的事情，但 log 通过附加日志的时间戳来格式化输出。它也可以很容易地定向到文件。

这个程序中有一些有趣的地方。我们定义的中间件函数具有相当常见的用例。我们可以扩展它们以执行任何操作。这个程序由许多元素组成。如果逐个函数地阅读它，逻辑可以很容易地展开。看一下以下几点：

+   创建了一个名为 city 的结构体来存储城市详情，就像上一个例子中一样。

+   `filterContentType`是我们添加的第一个中间件。它实际上检查请求的内容类型，并允许或阻止请求继续进行。我们使用`r.Header.GET`（内容类型）进行检查。如果是 application/json，我们允许请求调用`handler.ServeHTTP`函数，该函数执行`mainLogicHandler`代码。

+   `setServerTimeCookie`是我们设计的第二个中间件，用于在响应中添加一个值为服务器时间的 cookie。我们使用 Go 的`time`包来找到 Unix 纪元中的当前 UTC 时间。

+   对于 cookie，我们设置了`Name`和`Value`。cookie 还接受另一个名为`Expire`的参数，用于告知 cookie 的过期时间。

+   如果内容类型不是 application/json，我们的应用程序将返回 415-不支持的媒体类型状态码。

+   在 mainhandler 中，我们使用`json.NewDecoder`来解析 JSON 并将其填充到`city`结构体中。

+   `strconv.FormatInt`允许我们将`int64`数字转换为字符串。如果是普通的`int`，那么我们使用`strconv.Itoa`。

+   当操作成功时，返回的正确状态码是 201。对于所有其他方法，我们返回 405，即不允许的方法。

我们在这里进行的链式调用对于两到三个中间件是可读的：

```go
http.Handle("/city", filterContentType(setServerTimeCookie(mainLogicHandler)))
```

如果 API 服务器希望请求通过多个中间件，那么我们如何使这种链式调用简单且可读？有一个名为 Alice 的非常好的库可以解决这个问题。它允许您按语义顺序附加中间件到主处理程序。我们将在下一章中简要介绍它。

# 使用 Alice 轻松进行中间件链

当中间件列表很大时，`Alice`库可以降低中间件链的复杂性。它为我们提供了一个清晰的 API 来将处理程序传递给中间件。为了安装它，使用`go get`命令，就像这样：

```go
go get github.com/justinas/alice
```

现在我们可以在程序中导入 Alice 包并立即使用它。我们可以修改前面程序的部分以带来改进的链式调用相同的功能。在导入部分，添加`github.com/justinas/alice`，就像以下代码片段：

```go
import (
    "encoding/json"
    "github.com/justinas/alice"
    "log"
    "net/http"
    "strconv"
    "time"
)
```

现在，在主函数中，我们可以修改处理程序部分，就像这样：

```go
func main() {
    mainLogicHandler := http.HandlerFunc(mainLogic)
    chain := alice.New(filterContentType, setServerTimeCookie).Then(mainLogicHandler)
    http.Handle("/city", chain)
    http.ListenAndServe(":8000", nil)
}
```

这些添加更改的完整代码可在书的 GitHub 存储库的`第三章`文件夹中的名为`multipleMiddlewareWithAlice.go`的文件中找到。在掌握了前面的概念之后，让我们使用 Gorilla 工具包中的 Handlers 库构建一个日志中间件。

# 使用 Gorilla 的 Handlers 中间件进行日志记录

Gorilla Handlers 包提供了各种常见任务的中间件。列表中最重要的是：

+   `LoggingHandler`：用于记录 Apache 通用日志格式

+   `CompressionHandler`：用于压缩响应

+   `RecoveryHandler`：用于从意外的 panic 中恢复

在这里，我们使用`LoggingHandler`来执行 API 范围的日志记录。首先，使用`go get`安装这个库：

```go
go get "github.com/gorilla/handlers"
```

这个日志服务器使我们能够创建一个带有时间和选项的日志服务器。例如，当你看到`apache.log`时，你会发现类似这样的内容：

```go
192.168.2.20 - - [28/Jul/2006:10:27:10 -0300] "GET /cgi-bin/try/ HTTP/1.0" 200 3395
127.0.0.1 - - [28/Jul/2006:10:22:04 -0300] "GET / HTTP/1.0" 200 2216
```

格式是`IP-Date-Method:Endpoint-ResponseStatus`。编写我们自己的这样的中间件会需要一些工作。但是 Gorilla Handlers 已经为我们实现了它。看一下以下代码片段：

```go
package main
import (
    "github.com/gorilla/handlers"
    "github.com/gorilla/mux"
    "log"
    "os"
    "net/http"
)
func mainLogic(w http.ResponseWriter, r *http.Request) {
    log.Println("Processing request!")
    w.Write([]byte("OK"))
    log.Println("Finished processing request")
}
func main() {
    r := mux.NewRouter()
    r.HandleFunc("/", mainLogic)
    loggedRouter := handlers.LoggingHandler(os.Stdout, r)
    http.ListenAndServe(":8000", loggedRouter)
}
```

现在运行服务器：

```go
go run loggingMiddleware.go
```

现在，让我们在浏览器中打开`http://127.0.0.1:8000`，或者使用 CURL，你将看到以下输出：

```go
2017/05/28 10:51:44 Processing request!
2017/05/28 10:51:44 Finished processing request
127.0.0.1 - - [28/May/2017:10:51:44 +0530] "GET / HTTP/1.1" 200 2
127.0.0.1 - - [28/May/2017:10:51:44 +0530] "GET /favicon.ico HTTP/1.1" 404 19
```

如果你观察到，最后两个日志是由中间件生成的。Gorilla `LoggingMiddleware`在响应时写入它们。

在前面的例子中，我们总是在本地主机上检查 API。在这个例子中，我们明确指定用`127.0.0.1`替换 localhost，因为前者将显示为空 IP 在日志中。

来到程序，我们正在导入 Gorilla Mux 路由器和 Gorilla handlers。然后我们将一个名为`mainLogic`的处理程序附加到路由器上。接下来，我们将路由器包装在`handlers.LoggingHandler`中间件中。它返回一个更多的处理程序，我们可以安全地传递给 http.ListenAndServe。

你也可以尝试其他中间件，比如 handlers。这一节的座右铭是向你介绍 Gorilla Handlers。Go 还有许多其他外部包可用。有一个值得一提的库，用于直接在 net/http 上编写中间件。它是 Negroni（[github.com/urfave/negroni](http://github.com/urfave/negroni)）。它还提供了 Gorilla LoggingHandler 的功能。所以请看一下。

我们可以使用一个叫做 go.uuid 的库（[github.com/satori/go.uuid](http://github.com/satori/go.uuid)）和 cookies 轻松构建基于 cookie 的身份验证中间件。

# 什么是 RPC？

远程过程调用（RPC）是在各种分布式系统之间交换信息的进程间通信。一台名为 Alice 的计算机可以以协议格式调用另一台名为 Bob 的计算机中的函数（过程），并获得计算结果。我们可以从另一个地方或地理区域的网络请求东西，而不需要在本地实现功能。

整个过程可以分解为以下步骤：

+   客户端准备要发送的函数名和参数

+   客户端通过拨号连接将它们发送到 RPC 服务器

+   服务器接收函数名和参数

+   服务器执行远程过程

+   消息将被发送回客户端

+   客户端收集请求的数据并适当使用它

服务器需要公开其服务，以便客户端连接并请求远程过程。看一下下面的图表：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/bd-rst-websvc-go/img/7b0c08f9-936a-43f9-b7a1-f5b4addef8c5.png)

Go 提供了一个库来实现 RPC 服务器和 RPC 客户端。在上图中，RPC 客户端通过包含主机和端口等详细信息拨号连接。它发送两件事以及请求。一个是参数和回复指针。由于它是一个指针，服务器可以修改它并发送回来。然后客户端可以使用填入指针的数据。Go 有两个库，net/rpc 和 net/rpc/jsonrpc，用于处理 RPC。让我们编写一个 RPC 服务器，与客户端通信并提供服务器时间。

# 创建一个 RPC 服务器

让我们创建一个简单的 RPC 服务器，将 UTC 服务器时间发送回 RPC 客户端。首先，我们从服务器开始。

RPC 服务器和 RPC 客户端应该就两件事达成一致：

1.  传递的参数

1.  返回的值

前两个参数的类型应该完全匹配服务器和客户端：

```go
package main
import (
    "log"
    "net"
    "net/http"
    "net/rpc"
    "time"
)
type Args struct{}
type TimeServer int64
func (t *TimeServer) GiveServerTime(args *Args, reply *int64) error {
    // Fill reply pointer to send the data back
    *reply = time.Now().Unix()
    return nil
}
func main() {
    // Create a new RPC server
    timeserver := new(TimeServer)
    // Register RPC server
    rpc.Register(timeserver)
    rpc.HandleHTTP()
    // Listen for requests on port 1234
    l, e := net.Listen("tcp", ":1234")
    if e != nil {
        log.Fatal("listen error:", e)
    }
    http.Serve(l, nil)
}
```

我们首先创建 Args 结构。这个结构保存了从客户端（RPC）传递到服务器的参数信息。然后，我们创建了一个`TimeServer`数字来注册到`rpc.Register`。在这里，服务器希望导出一个类型为`TimeServer(int64)`的对象。`HandleHTTP`为 RPC 消息注册了一个 HTTP 处理程序到`DefaultServer`。然后我们启动了一个监听端口 1234 的 TCP 服务器。`http.Serve`函数用于将其作为一个运行程序提供。`GiveServerTime`是客户端将调用的函数，并返回当前服务器时间。

从前面的例子中有几点需要注意：

+   `GiveServerTime`以`Args`对象作为第一个参数和一个回复指针对象

+   它设置了回复指针对象，但除了错误之外没有返回任何东西

+   这里的`Args`结构没有字段，因为此服务器不希望客户端发送任何参数

在运行此程序之前，让我们也编写 RPC 客户端。两者可以同时运行。

# 创建 RPC 客户端

现在，客户端也使用相同的 net/rpc 包，但使用不同的方法拨号到服务器并执行远程函数。获取数据的唯一方法是将回复指针对象与请求一起传递，如下面的代码片段所示：

```go
package main
import (
    "log"
    "net/rpc"
)
type Args struct {
}
func main() {
    var reply int64
    args := Args{}
    client, err := rpc.DialHTTP("tcp", "localhost"+":1234")
    if err != nil {
        log.Fatal("dialing:", err)
    }
    err = client.Call("TimeServer.GiveServerTime", args, &reply)
    if err != nil {
        log.Fatal("arith error:", err)
    }
    log.Printf("%d", reply)}
```

客户端在这里执行以下操作：

1.  进行`DialHTTP`连接到运行在本地主机端口`1234`上的 RPC 服务器。

1.  使用`Name:Function`格式调用`Remote`函数，使用`args`并回复指针对象。

1.  将收集的数据放入`reply`对象中。

1.  **`Call` **函数是顺序性的。

现在我们可以同时运行服务器和客户端来看它们的运行情况：

```go
go run RPCServer.go
```

运行服务器。现在打开另一个 shell 选项卡并运行此命令：

```go
go run RPCClient.go 
```

现在服务器控制台将输出以下 UNIX 时间字符串：

```go
2017/05/28 19:26:31 1495979791
```

看到魔术了吗？客户端作为独立程序运行。在这里，两个程序可以在不同的机器上运行，计算仍然可以共享。这是分布式系统的核心概念。任务被分割并分配给各种 RPC 服务器。最后，客户端收集结果并将其用于进一步的操作。

自定义 RPC 代码仅在客户端和服务器都是用 Go 编写时才有用。因此，为了让 RPC 服务器被多个服务使用，我们需要定义基于 HTTP 的 JSON RPC。然后，任何其他编程语言都可以发送 JSON 字符串并获得 JSON 作为结果。

RPC 应该是安全的，因为它正在执行远程函数。在从客户端收集请求时需要授权。

# 使用 Gorilla RPC 进行 JSON RPC

我们看到 Gorilla 工具包通过提供许多有用的库来帮助我们。然后，我们探索了 Mux、Handlers，现在是 Gorilla RPC 库。使用这个，我们可以创建使用 JSON 而不是自定义回复指针进行通信的 RPC 服务器和客户端。让我们将前面的示例转换为一个更有用的示例。

考虑这种情况。服务器上有一个 JSON 文件，其中包含书籍的详细信息（名称、ID、作者）。客户端通过发出 HTTP 请求来请求书籍信息。当 RPC 服务器收到请求时，它从文件系统中读取并解析文件。如果给定的 ID 与任何书籍匹配，那么服务器将以 JSON 格式将信息发送回客户端。我们可以使用以下命令安装 Gorilla RPC：

```go
go get github.com/gorilla/rpc
```

该包源自标准的`net/rpc`包，但每次调用使用单个 HTTP 请求而不是持久连接。与`net/rpc`相比的其他差异：在以下部分中进行了解释。

可以在同一个服务器中注册多个编解码器。编解码器是根据请求的`Content-Type`标头选择的。服务方法还接收`http.Request`作为参数。此包可用于 Google App Engine。现在，让我们编写一个 RPC JSON 服务器。在这里，我们正在实现 JSON1.0 规范。对于 2.0，您应该使用 Gorilla JSON2：

```go
package main
import (
    jsonparse "encoding/json"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "github.com/gorilla/mux"
    "github.com/gorilla/rpc"
    "github.com/gorilla/rpc/json"
)
// Args holds arguments passed to JSON RPC service
type Args struct {
    Id string
}
// Book struct holds Book JSON structure
type Book struct {
    Id string `"json:string,omitempty"`
    Name string `"json:name,omitempty"`
    Author string `"json:author,omitempty"`
}
type JSONServer struct{}
// GiveBookDetail
func (t *JSONServer) GiveBookDetail(r *http.Request, args *Args, reply *Book) error {
    var books []Book
    // Read JSON file and load data
    raw, readerr := ioutil.ReadFile("./books.json")
    if readerr != nil {
        log.Println("error:", readerr)
        os.Exit(1)
    }
    // Unmarshal JSON raw data into books array
    marshalerr := jsonparse.Unmarshal(raw, &books)
    if marshalerr != nil {
        log.Println("error:", marshalerr)
        os.Exit(1)
    }
    // Iterate over each book to find the given book
    for _, book := range books {
        if book.Id == args.Id {
            // If book found, fill reply with it
            *reply = book
            break
        }
    }
    return nil
}
func main() {
    // Create a new RPC server
    s := rpc.NewServer()    // Register the type of data requested as JSON
    s.RegisterCodec(json.NewCodec(), "application/json")
    // Register the service by creating a new JSON server
    s.RegisterService(new(JSONServer), "")
    r := mux.NewRouter()
    r.Handle("/rpc", s)
    http.ListenAndServe(":1234", r)
}
```

这个程序可能与前面的 RPC 服务器实现不同。这是因为包含了 Gorilla **`Mux`、**Gorilla `rpc`和`jsonrpc`包。在解释发生了什么之前，让我们运行前面的程序。使用以下命令运行服务器：

```go
go run jsonRPCServer.go
```

现在客户端在哪里？在这里，客户端可以是 CURL 命令，因为 RPC 服务器通过 HTTP 提供请求。我们需要发布 JSON 以获取详细信息。因此，打开另一个 shell 并执行此 CURL 请求：

```go
curl -X POST \
 http://localhost:1234/rpc \
 -H 'cache-control: no-cache' \
 -H 'content-type: application/json' \
 -d '{
 "method": "JSONServer.GiveBookDetail",
 "params": [{
 "Id": "1234"
 }],
 "id": "1"
}'
```

输出将是一个漂亮的 JSON，直接从 JSON RPC 服务器提供：

```go
{"result":{"Id":"1234","Name":"In the sunburned country","Author":"Bill Bryson"},"error":null,"id":"1"}
```

现在，来到程序，我们有很多需要理解的地方。创建 RPC 服务的文档非常有限。因此，我们在程序中使用的技术可以应用于各种用例。首先，我们创建了`Args`和`Book`结构体，分别用于保存传递的 JSON 参数和书籍结构的信息。我们在名为`JSONServer`的资源上定义了一个名为`GiveBookDetail`的远程函数。这个结构体是一个服务，用于在 RPC 服务器的**`RegisterService`**函数中注册。如果您注意到，我们还注册了 JSON 编解码器。

每当我们从客户端收到请求时，我们将名为**`books.json`**的 JSON 文件加载到内存中，然后使用 JSON 的**`Unmarshal`**方法加载到`Book`结构体中。`jsonparse`是给予 Go 包**`encoding/json`**的别名，因为 Gorilla 导入的 JSON 包具有相同的名称。为了消除冲突，我们使用了一个别名。

`reply`引用被传递给远程函数。在远程函数中，我们使用匹配的书籍设置了回复的值。如果客户端发送的 ID 与 JSON 中的任何书籍匹配，那么数据就会被填充。如果没有匹配，那么 RPC 服务器将发送回空数据。通过这种方式，可以创建一个 JSON RPC 以允许客户端是通用的。在这里，我们没有编写 Go 客户端。任何客户端都可以从服务中访问数据。

当多个客户端技术需要连接到您的 RPC 服务时，最好使用 JSON RPC。

# 总结

在本章中，我们首先研究了中间件的确切含义，包括中间件如何处理请求和响应。然后，我们通过一些实际示例探讨了中间件代码。之后，我们看到了如何通过将一个中间件传递给另一个中间件来链接我们的中间件。然后，我们使用了一个名为`Alice`的包来进行直观的链接。我们还研究了 Gorilla 处理程序中间件用于日志记录。接下来，我们学习了 RPC 是什么，以及如何构建 RPC 服务器和客户端。之后，我们解释了什么是 JSON RPC，并看到了如何使用 Gorilla 工具包创建 JSON RPC。我们介绍了许多第三方中间件和 RPC 包，附有示例。

在下一章中，我们将探索一些著名的 Web 框架，这些框架进一步简化了 REST API 的创建。它们具有内置的中间件和 HTTP 路由器。
