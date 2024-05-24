# RESTful Java 模式和最佳实践（一）

> 原文：[`zh.annas-archive.org/md5/829D0A6DE6895E44AC3D7583B5540457`](https://zh.annas-archive.org/md5/829D0A6DE6895E44AC3D7583B5540457)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

社交网络、云计算和移动应用程序时代的融合，创造了一代新兴技术，使不同的网络设备能够通过互联网相互通信。过去，构建解决方案有传统和专有的方法，涵盖了不同的设备和组件在不可靠的网络或通过互联网相互通信。一些方法，如 RPC CORBA 和基于 SOAP 的 Web 服务，作为面向服务的体系结构（SOA）的不同实现而演变，需要组件之间更紧密的耦合以及更大的集成复杂性。

随着技术格局的演变，今天的应用程序建立在生产和消费 API 的概念上，而不是使用调用服务并生成网页的 Web 框架。这种基于 API 的架构实现了敏捷开发、更容易的采用和普及，以及与企业内外应用程序的规模和集成。

REST 和 JSON 的广泛采用打开了应用程序吸收和利用其他应用程序功能的可能性。REST 的流行主要是因为它能够构建轻量级、简单和成本效益的模块化接口，可以被各种客户端使用。

移动应用程序的出现要求更严格的客户端-服务器模型。在 iOS 和 Android 平台上构建应用程序的公司可以使用基于 REST 的 API，并通过结合来自多个平台的数据来扩展和加深其影响，因为 REST 基于 API 的架构。

REST 具有无状态的额外好处，有助于扩展性、可见性和可靠性，同时也是平台和语言无关的。许多公司正在采用 OAuth 2.0 进行安全和令牌管理。

本书旨在为热心读者提供 REST 架构风格的概述，重点介绍所有提到的主题，然后深入探讨构建轻量级、可扩展、可靠和高可用的 RESTful 服务的最佳实践和常用模式。

# 本书涵盖的内容

《第一章》*REST - 起源*，从 REST 的基本概念开始，介绍了如何设计 RESTful 服务以及围绕设计 REST 资源的最佳实践。它涵盖了 JAX-RS 2.0 API 在 Java 中构建 RESTful 服务。

《第二章》*资源设计*，讨论了不同的请求响应模式；涵盖了内容协商、资源版本控制以及 REST 中的响应代码等主题。

《第三章》*安全和可追溯性*，涵盖了关于 REST API 的安全和可追溯性的高级细节。其中包括访问控制、OAuth 身份验证、异常处理以及审计和验证模式等主题。

《第四章》*性能设计*，涵盖了性能所需的设计原则。它讨论了 REST 中的缓存原则、异步和长时间运行的作业，以及如何使用部分更新。

《第五章》*高级设计原则*，涵盖了高级主题，如速率限制、响应分页以及国际化和本地化原则，并提供了详细的示例。它涵盖了可扩展性、HATEOAS 以及测试和文档化 REST 服务等主题。

第六章*新兴标准和 REST 的未来*，涵盖了使用 WebHooks、WebSockets、PuSH 和服务器发送事件服务的实时 API，并在各个领域进行了比较和对比。此外，本章还涵盖了案例研究，展示了新兴技术如 WebSockets 和 WebHooks 在实时应用中的使用。它还概述了 REST 在微服务中的作用。

附录涵盖了来自 GitHub、Twitter 和 Facebook 的不同 REST API，以及它们如何与第二章*资源设计*中讨论的原则联系起来，一直到第五章*高级设计原则*。

# 您需要什么来阅读这本书

为了能够构建和运行本书提供的示例，您需要以下内容：

+   Apache Maven 3.0 及更高版本：Maven 用于构建示例。您可以从[`maven.apache.org/download.cgi`](http://maven.apache.org/download.cgi)下载 Apache Maven。

+   GlassFish Server Open Source Edition v4.0：这是一个免费的社区支持的应用服务器，提供了 Java EE 7 规范的实现。您可以从[`dlc.sun.com.edgesuite.net/glassfish/4.0/promoted/`](http://dlc.sun.com.edgesuite.net/glassfish/4.0/promoted/)下载 GlassFish 服务器。

# 这本书是为谁准备的

这本书是应用程序开发人员熟悉 REST 的完美阅读来源。它深入探讨了细节、最佳实践和常用的 REST 模式，以及 Facebook、Twitter、PayPal、GitHub、Stripe 和其他公司如何使用 RESTful 服务实现解决方案的见解。

# 约定

在这本书中，您会发现许多不同类型信息的文本样式。以下是一些这些样式的例子，以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："`GET`和`HEAD`是安全方法。"

代码块设置如下：

```java
    @GET
    @Path("orders")
    public List<Coffee> getOrders() {
        return coffeeService.getOrders();    }
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目以粗体设置：

```java
@Path("v1/coffees")
public class CoffeesResource {
    @GET
    @Path("orders")
    @Produces(MediaType.APPLICATION_JSON)
    public List<Coffee> getCoffeeList( ){
      //Implementation goes here

    }
```

任何命令行输入或输出都是这样写的：

```java
#  curl -X GET http://api.test.com/baristashop/v1.1/coffees

```

**新术语**和**重要单词**以粗体显示。

### 注意

警告或重要说明出现在这样的框中。

### 提示

提示和技巧看起来像这样。


# 第一章：REST - 从哪里开始

传统 SOA 格式的 Web 服务已经存在很长时间，用于实现应用程序之间的异构通信。支持这种通信的一种方式是使用**简单对象访问协议**（**SOAP**）/**Web 服务描述语言**（**WSDL**）方法。SOAP/WSDL 是一种基于 XML 的标准，在服务之间存在严格的合同时运行良好。我们现在处于分布式服务的时代，Web、移动客户端以及其他服务（内部或外部）可以利用不同供应商和开源平台提供的 API。这种要求强调了分布式服务之间信息交换的需求，以及可预测、健壮、明确定义的接口。

HTTP 1.1 在 RFC 2616 中定义，并且被广泛用作分布式协作超媒体信息系统的标准协议。**表述状态转移**（**REST**）受到 HTTP 的启发，可以在任何使用 HTTP 的地方使用。本章将介绍 RESTful 服务设计的基础知识，并展示如何基于标准 Java API 生成和消费 RESTful 服务。

本章涵盖以下主题。

+   REST 介绍

+   安全性和幂等性

+   构建 RESTful 服务的设计原则

+   RESTful 服务的 Java 标准 API

+   设计 RESTful 服务的最佳实践

# REST 介绍

REST 是一种符合 Web 标准的架构风格，例如使用 HTTP 动词和 URI。它受以下原则约束：

+   所有资源都由 URI 标识

+   所有资源都可以有多种表示

+   所有资源都可以通过标准 HTTP 方法进行访问/修改/创建/删除

+   服务器上没有状态信息

## REST 和无状态性

REST 受**无状态性**原则约束。客户端到服务器的每个请求必须具有理解请求的所有细节。这有助于提高请求的可见性、可靠性和可扩展性。

**可见性**得到改善，因为监视请求的系统不必查看超出一个请求以获取详细信息。**可靠性**得到改善，因为在部分故障的情况下不需要检查点/恢复。**可扩展性**得到改善，因为服务器可以处理的请求数量增加，因为服务器不负责存储任何状态。

### 注

Roy Fielding 关于 REST 架构风格的论文详细介绍了 REST 的无状态性。请访问[`www.ics.uci.edu/~fielding/pubs/dissertation/rest_arch_style.htm`](http://www.ics.uci.edu/~fielding/pubs/dissertation/rest_arch_style.htm)获取更多信息。

通过对 REST 的基础知识进行初步介绍，我们将在下一节中介绍不同的成熟度级别以及 REST 在其中的位置。

# Richardson 成熟度模型

**Richardson 成熟度模型**是由 Leonard Richardson 开发的模型。它从资源、动词和超媒体控制的角度讨论了 REST 的基础知识。成熟度模型的起点是使用 HTTP 层作为传输。如下图所示：

![Richardson 成熟度模型](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-ptn-best-prac/img/7963OS_01_01.jpg)

## 0 级 - 远程过程调用

0 级包含将数据作为**普通旧 XML**（**POX**）发送的 SOAP 或 XML-RPC。只使用`POST`方法。这是构建具有单个`POST`方法的 SOA 应用程序的最原始方式，并使用 XML 在服务之间进行通信。

## 1 级 - REST 资源

1 级使用`POST`方法，而不是使用函数和传递参数，而是使用 REST URI。因此，它仍然只使用一个 HTTP 方法。它比 0 级更好，因为它将复杂功能分解为多个资源，并使用一个`POST`方法在服务之间进行通信。

## 2 级 - 更多的 HTTP 动词

Level 2 使用其他 HTTP 动词，如`GET`、`HEAD`、`DELETE`和`PUT`，以及`POST`方法。 Level 2 是 REST 的真正用例，它倡导根据 HTTP 请求方法使用不同的动词，系统可以具有多个资源。

## Level 3 – HATEOAS

**超媒体作为应用状态的引擎**（**HATEOAS**）是 Richardson 模型的最成熟级别。对客户端请求的响应包含超媒体控件，这可以帮助客户端决定下一步可以采取什么行动。 Level 3 鼓励易于发现，并使响应易于自我解释。关于 HATEOAS 是否真正符合 RESTful 存在争议，因为表示包含了除了描述资源之外的更多信息。我们将展示一些平台如 PayPal 如何在其 API 的一部分中实现 HATEOAS 的详细信息在第五章，“高级设计原则”中。

下一节涵盖了安全性和幂等性，这是处理 RESTful 服务时的两个重要术语。

# 安全性和幂等性

下一节将详细讨论什么是安全和幂等方法。

## 安全方法

安全方法是不会改变服务器状态的方法。例如，`GET /v1/coffees/orders/1234`是一个安全方法。

### 注意

安全方法可以被缓存。`GET`和`HEAD`是安全方法。

`PUT`方法不安全，因为它会在服务器上创建或修改资源。`POST`方法由于相同的原因也不安全。`DELETE`方法不安全，因为它会删除服务器上的资源。

## 幂等方法

幂等方法是一种无论调用多少次都会产生相同结果的方法。

### 注意

`GET`方法是幂等的，因为对`GET`资源的多次调用将始终返回相同的响应。

`PUT`方法是幂等的，多次调用`PUT`方法将更新相同的资源并且不会改变结果。

`POST`不是幂等的，多次调用`POST`方法可能会产生不同的结果，并且会导致创建新资源。`DELETE`是幂等的，因为一旦资源被删除，它就消失了，多次调用该方法不会改变结果。

# 构建 RESTful 服务的设计原则

以下是设计、开发和测试 RESTful 服务的过程。我们将在本章中详细介绍每个过程：

+   识别资源 URI

此过程涉及决定名词将代表您的资源。

+   识别资源支持的方法

此过程涉及使用各种 HTTP 方法进行 CRUD 操作。

+   识别资源支持的不同表示

此步骤涉及选择资源表示应该是 JSON、XML、HTML 还是纯文本。

+   使用 JAX-RS API 实现 RESTful 服务

API 需要基于 JAX-RS 规范实现

+   部署 RESTful 服务

将服务部署在诸如 Tomcat、Glassfish 和 WildFly 之类的应用容器上。示例展示了如何创建 WAR 文件并在 Glassfish 4.0 上部署，它可以与任何符合 JavaEE 7 标准的容器一起使用。

+   测试 RESTful 服务

编写客户端 API 以测试服务，或使用 curl 或基于浏览器的工具来测试 REST 请求。

## 识别资源 URI

RESTful 资源由资源 URI 标识。由于使用 URI 来标识资源，REST 是可扩展的。

以下表格显示了示例 URI，可以表示系统中的不同资源：

| URI | URI 的描述 |
| --- | --- |
| `/v1/library/books` | 用于表示图书馆中的一组图书资源 |
| `/v1/library/books/isbn/12345678` | 用于表示由其 ISBN“12345678”标识的单本书 |
| `/v1/coffees` | 用于表示咖啡店出售的所有咖啡 |
| `/v1/coffees/orders` | 这用于表示所有已订购的咖啡 |
| `/v1/coffees/orders/123` | 这用于表示由“123”标识的咖啡订单 |
| `/v1/users/1235` | 这用于表示系统中由“1235”标识的用户 |
| `/v1/users/5034/books` | 这用于表示由“5034”标识的用户的所有书籍 |

所有前面的示例都显示了一个清晰可读的模式，客户端可以解释。所有这些资源都可以有多个表示。在前面的表中显示的这些资源示例可以由 JSON、XML、HTML 或纯文本表示，并且可以通过 HTTP 方法`GET`、`PUT`、`POST`和`DELETE`进行操作。

## 识别资源支持的方法

HTTP 动词占据了统一接口约束的主要部分，该约束定义了动词识别的操作与基于名词的 REST 资源之间的关联。

以下表格总结了 HTTP 方法和对资源采取的操作的描述，以图书馆中书籍集合的简单示例为例。

| HTTP 方法 | 资源 URI | 描述 |
| --- | --- | --- |
| `GET` | `/library/books` | 这获取书籍列表 |
| `GET` | `/library/books/isbn/12345678` | 这获取由 ISBN“12345678”标识的书籍 |
| `POST` | `/library/books` | 这创建一个新的书籍订单 |
| `DELETE` | `/library/books/isbn/12345678` | 这将删除由 ISBN“12345678”标识的书籍 |
| `PUT` | `/library/books/isbn/12345678` | 这将更新由 ISBN“12345678”标识的特定书籍 |
| `PATCH` | `/library/books/isbn/12345678` | 这可用于对由 ISBN“12345678”标识的书籍进行部分更新 |

下一节将介绍每个 HTTP 动词在 REST 上下文中的语义。

### HTTP 动词和 REST

HTTP 动词告诉服务器如何处理作为 URL 一部分发送的数据。

#### 获取

`GET`方法是 HTTP 的最简单动词，它使我们能够访问资源。每当客户端在浏览器中点击 URL 时，它会向 URL 指定的地址发送`GET`请求。`GET`是安全和幂等的。`GET`请求被缓存。`GET`请求中可以使用查询参数。

例如，检索所有活动用户的简单`GET`请求如下所示：

```java
curl http://api.foo.com/v1/users/12345?active=true
```

#### POST

`POST`用于创建资源。`POST`请求既不是幂等的，也不是安全的。多次调用`POST`请求可以创建多个资源。

如果存在缓存条目，`POST`请求应该使缓存条目无效。不鼓励在`POST`请求中使用查询参数。

例如，创建用户的`POST`请求可以如下所示：

```java
curl –X POST  -d'{"name":"John Doe","username":"jdoe", "phone":"412-344-5644"}' http://api.foo.com/v1/users
```

#### 放置

`PUT`用于更新资源。`PUT`是幂等的，但不安全。多次调用`PUT`请求应该通过更新资源产生相同的结果。

如果存在缓存条目，`PUT`请求应该使缓存条目无效。

例如，更新用户的`PUT`请求可以如下所示：

```java
curl –X PUT  -d'{ "phone":"413-344-5644"}'
http://api.foo.com/v1/users
```

#### DELETE

`DELETE`用于删除资源。`DELETE`是幂等的，但不安全。这是幂等的，因为根据 RFC 2616，N > 0 请求的副作用与单个请求相同。这意味着一旦资源被删除，多次调用`DELETE`将获得相同的响应。

例如，删除用户的请求可以如下所示：

```java
curl –X DELETE http://foo.api.com/v1/users/1234
```

#### 头

`HEAD`类似于`GET`请求。不同之处在于只返回 HTTP 标头，不返回内容。`HEAD`是幂等和安全的。

例如，使用 curl 发送`HEAD`请求的请求如下所示：

```java
curl –X HEAD http://foo.api.com/v1/users
```

### 提示

在尝试使用`GET`请求获取大型表示之前，发送`HEAD`请求以查看资源是否已更改可能很有用。

### PUT 与 POST

根据 RFC，`PUT`和`POST`之间的区别在于请求 URI。由`POST`标识的 URI 定义将处理`POST`请求的实体。`PUT`请求中的 URI 包括请求中的实体。

因此，`POST /v1/coffees/orders`表示创建一个新资源并返回一个标识符来描述该资源。相反，`PUT /v1/coffees/orders/1234`表示更新由`"1234"`标识的资源（如果存在）；否则创建一个新订单并使用`orders/1234` URI 来标识它。

### 注意

`PUT`和`POST`都可以用于创建或更新方法。方法的使用取决于期望从方法获得的幂等行为以及用于标识资源的位置。

下一节将介绍如何识别资源的不同表示形式。

## 识别资源的不同表示形式

RESTful 资源是抽象实体，需要在与客户端通信之前被序列化为表示。资源的常见表示可以是 XML、JSON、HTML 或纯文本。资源可以根据客户端的处理能力向客户端提供表示。客户端可以指定它偏好的语言和媒体类型。这被称为**内容协商**。第二章，“资源设计”，详细介绍了内容协商主题。

## 实现 API

现在我们对设计 RESTful 资源和将 HTTP 动词与资源上的操作关联有了一些了解，我们将介绍实现 API 和构建 RESTful 服务所需的内容。本节将涵盖以下主题：

+   用于 RESTful 服务的 Java API（JAX-RS）

### 用于 RESTful 服务的 Java API（JAX-RS）

用于 RESTful 服务的 Java API 提供了用于构建和开发基于 REST 架构风格的应用程序的可移植 API。使用 JAX-RS，Java POJO 可以作为 RESTful web 资源公开，这些资源独立于底层技术，并使用基于注释的简单 API。

JAX-RS 2.0 是规范的最新版本，与其前身 JAX-RS 1.0 相比，在以下领域特别是具有更新的功能：

+   Bean 验证支持

+   客户端 API 支持

+   异步调用支持

Jersey 是 JAX-RS 规范的实现。

我们将在随后的章节中详细介绍所有这些主题。我们正在演示一个简单的咖啡店示例，您可以在其中创建一个名为`CoffeesResource`的 REST 资源，该资源可以执行以下操作：

+   提供已下订单的详细信息

+   创建新订单

+   获取特定订单的详细信息

要创建一个 RESTful 资源，我们从一个名为`CoffeesResource`的 POJO 开始。以下是 JAX-RS 资源的示例：

```java
@Path("v1/coffees")
public class CoffeesResource {

    @GET
    @Path("orders")
    @Produces(MediaType.APPLICATION_JSON)
    public List<Coffee> getCoffeeList( ){
      //Implementation goes here

    }
```

1.  如前面的代码所示，我们创建了一个名为`CoffeesResource`的小型 POJO。我们使用`@Path("v1/coffees")`对类进行注释，该注释标识了该类为请求提供服务的 URI 路径。

1.  接下来，我们定义了一个名为`getCoffeeList()`的方法。该方法具有以下注释：

+   `@GET`：这表示被注释的方法代表一个 HTTP `GET`请求。

+   `@PATH`：在此示例中，`GET`请求`v1/coffees/orders`将由`getCoffeeList()`方法处理。

+   `@Produces`：这定义了此资源生成的媒体类型。在我们之前的片段中，我们定义了`MediaType.APPLICATION_JSON`，其值为`application/json`。

1.  另一种创建订单的方法如下：

```java
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ValidateOnExecution
    public Response addCoffee(@Valid Coffee coffee) {
    //Implementation goes here
    }
```

对于创建订单的第二种方法，我们定义了一个名为`addCoffee()`的方法。该方法具有以下注释：

+   `@POST`：这表示被注释的方法代表 HTTP `POST`请求。

+   `@Consumes`：这定义了此资源消耗的媒体类型。在我们之前的片段中，我们定义了`MediaType.APPLICATION_JSON`，其值为`application/json`。

+   `@Produces`：这定义了此资源生成的媒体类型。在我们之前的片段中，我们定义了`MediaType.APPLICATION_JSON`，其值为`application/json`。

+   `@ValidateOnExecution`：这指定了应在执行时验证其参数或返回值的方法。有关`@ValidateOnExecution`和`@Valid`注释的更多详细信息将在第三章*安全性和可追溯性*中介绍。

因此，我们看到了一个简单示例，说明了将简单的 POJO 转换为 REST 资源有多么容易。现在，我们将介绍`Application`子类，该子类将定义 JAX-RS 应用程序的组件，包括元数据。

以下是名为`CoffeeApplication`的示例`Application`子类的代码：

```java
@ApplicationPath("/")
public class CoffeeApplication extends Application {

    @Override
    public Set<Class<?>> getClasses() {
        Set<Class<?>> classes = new HashSet<Class<?>>();
        classes.add(CoffeesResource.class);
        return classes;
    }
```

如前面的代码片段所示，`getClasses()`方法已被重写，并且我们将`CoffeesResource`类添加到`Application`子类中。`Application`类可以是 WAR 文件中的`WEB-INF/classes`或`WEB-INF/lib`的一部分。

## 部署 RESTful 服务

一旦我们创建了资源并将元信息添加到 Application 子类中，下一步就是构建 WAR 文件。WAR 文件可以部署在任何 servlet 容器上。

示例的源代码作为本书的可下载捆绑包的一部分提供，其中将详细介绍部署和运行示例的步骤。

## 测试 RESTful 服务

然后，我们可以使用 JAX-RS 2.0 提供的 Client API 功能来访问资源。

本节将涵盖以下主题：

+   JAX-RS 2.0 的 Client API

+   使用 curl 或名为 Postman 的基于浏览器的扩展访问 RESTful 资源

### JAX-RS 2.0 的 Client API

JAX-RS 2.0 为访问 RESTful 资源提供了更新的 Client API。客户端 API 的入口点是`javax.ws.rs.client.Client`。

使用 JAX-RS 2.0 中新引入的 Client API，可以访问端点如下：

```java
Client client = ClientFactory.newClient();
WebTarget target = client.target("http://. . ./coffees/orders");
String response = target.request().get(String.class);
```

如前面的代码片段所示，使用`ClientFactory.newClient()`方法获取了客户端的默认实例。使用`target`方法，我们创建了一个`WebTarget`对象。然后使用这些目标对象通过添加方法和查询参数来准备请求。

在这些 API 之前，我们访问 REST 资源的方式是这样的：

```java
URL url = new URL("http://. . ./coffees/orders");
HttpURLConnection conn = (HttpURLConnection) url.openConnection();
conn.setRequestMethod("GET");
conn.setDoInput(true);
conn.setDoOutput(false);
BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
String line;
while ((line = br.readLine()) != null) {
    //. . .
}
```

因此，我们可以看到 JAX-RS 2.0 客户端 API 支持已经改进，以避免使用`HTTPURLConnection`，而是使用流畅的客户端 API。

如果请求是`POST`请求：

```java
Client client = ClientBuilder.newClient();
Coffee coffee = new Coffee(...);
WebTarget myResource = client.target("http://foo.com/v1/coffees");
myResource.request(MediaType.APPLICATION_XML) .post(Entity.xml(coffee), Coffee.class);
```

`WebTarget.request()`方法返回一个`javax.ws.rs.client.InvocationBuilder`，它使用`post()`方法来调用 HTTP `POST`请求。`post()`方法使用`Coffee`实例的实体，并指定媒体类型为`"APPLICATION_XML"`。

`MessageBodyReaderWriter`实现已在客户端中注册。有关`MessageBodyReader`和`MessageBodyWriter`的更多信息将在第二章*资源设计*中介绍。

以下表格总结了到目前为止我们所涵盖的一些主要 JAX-RS 类/注释。

| 注释名称 | 描述 |
| --- | --- |
| `javax.ws.rs.Path` | 这标识了资源为方法提供的 URI 路径 |
| `javax.ws.rs.ApplicationPath` | 这被`Application`的子类用作应用程序中所有资源提供的所有 URI 的基本 URI |
| `javax.ws.rs.Produces` | 这定义了资源可以生成的媒体类型 |
| `javax.ws.rs.Consumes` | 这定义了资源可以消耗的媒体类型 |
| `javax.ws.rs.client.Client` | 这定义了客户端请求的入口点 |
| `javax.ws.rs.client.WebTarget` | 这定义了由 URI 标识的资源目标 |

### 注意

客户端是帮助简化客户端通信基础设施的重量级对象。因此，建议在应用程序中仅构建少量客户端实例，因为初始化和处理客户端实例可能是一个相当昂贵的操作。此外，必须在处理之前正确关闭客户端实例，以避免资源泄漏。

### 访问 RESTful 资源

以下部分涵盖了客户端可以访问和测试 REST 资源的不同方式。

#### cURL

cURL 是一个用于测试 REST API 的流行命令行工具。cURL 库和 cURL 命令使用户能够创建请求，将其放在管道上，并探索响应。以下是一些用于一些基本功能的`curl`请求的示例：

| curl 请求 | 描述 |
| --- | --- |
| `curl http://api.foo.com/v1/coffees/1` | 这是一个简单的`GET`请求 |
| `curl -H "foo:bar" http://api.foo.com/v1/coffees` | 这是一个使用`-H`添加请求头的`curl`请求的示例 |
| `curl -i http://api.foo.com/v1/coffees/1` | 这是一个使用`-i`查看响应头的`curl`命令的示例 |
| `curl –X POST -d'{"name":"John Doe","username":"jdoe", "phone":"412-344-5644"} http://api.foo.com/v1/users` | 这是一个用于创建用户的`POST`方法的`curl`请求的示例 |

尽管 cURL 非常强大，但有很多选项需要记住和使用。有时，使用基于浏览器的工具来开发 REST API，如 Postman 或高级 REST 客户端，会有所帮助。

#### Postman

Chrome 浏览器上的 Postman 是一个非常好的测试和开发 REST API 的工具。它具有用于呈现数据的 JSON 和 XML 查看器。它还可以允许预览 HTTP 1.1 请求，重播，并组织请求以供将来使用。Postman 与浏览器共享相同的环境，也可以显示浏览器 cookie。

Postman 相对于 cURL 的优势在于有一个很好的用户界面，可以输入参数，用户不需要处理命令或脚本。还支持各种授权方案，如基本用户认证和摘要访问认证。

以下是一张截图，显示了如何在 Postman 中发送查询：

![Postman](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-ptn-best-prac/img/7963OS_01_02.jpg)

如前面的截图所示，我们看到了 Postman 应用程序。测试 Postman 的一个简单方法是从 Chrome 启动 Postman 应用程序。

然后，选择 HTTP 方法`GET`并粘贴`api.postcodes.io/random/postcodes` URL。（PostCodes 是一个基于地理数据的免费开源服务。）

您将看到一个 JSON 响应，类似于这样：

```java
{
    "status": 200,
    "result": {
        "postcode": "OX1 9SN",
        "quality": 1,
        "eastings": 451316,
        "northings": 206104,
        "country": "England",
        "nhs_ha": "South Central",
        "admin_county": "Oxfordshire",
        "admin_district": "Oxford",
        "admin_ward": "Carfax",
…}
}
```

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)购买的 Packt 图书的帐户中下载示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

在前面截图的左侧窗格中有不同的查询，这些查询已经根据本书中的各种示例添加到了一个集合中，例如获取所有咖啡订单，获取特定订单，创建订单等等。您也可以类似地创建自定义查询集合。

### 注意

要了解更多详情，请访问[`www.getpostman.com/`](http://www.getpostman.com/)。

#### 其他工具

以下是一些在处理 REST 资源时非常有用的其他工具。

##### 高级 REST 客户端

高级 REST 客户端是另一个基于 Google WebToolkit 的 Chrome 扩展，允许用户测试和开发 REST API。

##### JSONLint

JSONLint 是一个简单的在线验证器，可确保 JSON 有效。在发送 JSON 数据作为请求的一部分时，验证数据格式是否符合 JSON 规范是有用的。在这种情况下，客户端可以使用 JSONLint 验证输入。要了解更多详情，请访问[`jsonlint.com/`](http://jsonlint.com/)。

# 设计资源时的最佳实践

以下部分突出显示了设计 RESTful 资源时的一些最佳实践：

+   API 开发者应该使用名词来理解和浏览资源，使用 HTTP 方法和动词，例如，/user/1234/books 比/user/1234/getBook URI 更好。

+   在 URI 中使用关联来标识子资源。例如，要获取用户 1234 的书籍 5678 的作者，使用以下 URI：`/user/1234/books/5678/authors`。

+   对于特定的变化，使用查询参数。例如，要获取所有具有 10 条评论的书籍，使用`/user/1234/books?reviews_counts=10`。

+   如果可能，允许部分响应作为查询参数的一部分。例如，在获取用户的姓名和年龄时，客户端可以指定`?fields`作为查询参数，并使用`/users/1234?fields=name,age` URI 指定应该由服务器在响应中发送的字段列表。

+   在客户端没有指定感兴趣的格式时，为响应的输出格式设置默认值。大多数 API 开发人员选择将 JSON 作为默认响应 MIME 类型发送。

+   使用 camelCase 或使用`_`作为属性名称。

+   支持标准 API 以获取计数，例如`users/1234/books/count`，以便客户端可以了解响应中可以期望多少对象。

这也将帮助客户端进行分页查询。关于分页的更多细节将在第五章中涵盖，*高级设计原则*。

+   支持漂亮打印选项，`users/1234?pretty_print`。另外，不缓存带有漂亮打印查询参数的查询是一个良好的实践。

+   尽量详细地避免啰嗦。这是因为如果服务器在响应中没有提供足够的细节，客户端需要进行更多的调用以获取额外的细节。这不仅浪费了网络资源，还会影响客户端的速率限制。关于速率限制的更多细节在第五章中有所涵盖，*高级设计原则*。

# 推荐阅读

以下链接可能对查看更多细节有用：

+   **RFC 2616**：[`www.w3.org/Protocols/rfc2616/rfc2616-sec3.html`](http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html)

+   **Richardson 成熟度模型**：[`www.crummy.com/writing/speaking/2008-QCon/act3.html`](http://www.crummy.com/writing/speaking/2008-QCon/act3.html)

+   **JAX-RS 的 Jersey 实现**：[`jersey.java.net/`](https://jersey.java.net/)

+   **InspectB.in**: [`inspectb.in/`](http://inspectb.in/)

+   **Postman**：[`www.getpostman.com/`](http://www.getpostman.com/)

+   **高级 REST 客户端**：[`code.google.com/p/chrome-rest-client/`](https://code.google.com/p/chrome-rest-client/)

# 摘要

在本章中，我们介绍了 REST、CRUD API 的基础知识以及如何设计 RESTful 资源。我们使用了基于 JAX-RS 2.0 的注解来表示 HTTP 方法，以及可以用于定位资源的客户端 API。此外，我们还总结了设计 RESTful 服务时的最佳实践。

下一章将更深入地探讨这里涵盖的概念。我们还将涵盖诸如内容协商、JAX-RS 2.0 中的实体提供者、错误处理、版本控制方案和 REST 中的响应代码等主题。我们将探讨服务器可以使用流式传输或分块传输向客户端发送响应的技术。


# 第二章：资源设计

第一章，“REST - 起源”，介绍了 REST 的基础知识以及在设计 RESTful 资源时的最佳实践。本章将继续讨论请求响应模式的理解，如何处理资源的不同表示，API 版本控制的不同策略，以及如何使用标准 HTTP 代码来处理 REST 响应。本章的子章节将涵盖以下主题：

+   REST 响应模式

+   内容协商

+   实体提供程序和不同的表示

+   API 版本控制

+   响应代码和 REST 模式

我们还将介绍用于序列化和反序列化请求和响应实体的自定义实体提供程序，以及流式传输和分块等其他方法。

# REST 响应模式

在前一章中，我们看到了如何使用与域相关的数据来创建可读的 URI，使用不同的 CRUD 功能的 HTTP 方法，并使用标准化的 MIME 类型和 HTTP 响应代码在客户端和服务器之间传输数据。

以下是显示标准 REST 请求/响应模式的图表：

![REST 响应模式](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-ptn-best-prac/img/7963OS_02_01.jpg)

如前图所示，客户端发出 REST 请求，其中包括标准的 HTTP 方法、MIME 类型和目标 URI。服务器处理请求并发送回一个响应，其中包括标准的 HTTP 响应代码和 MIME 类型。我们之前介绍了 HTTP 方法以及如何使用 JAX-RS 注释。还列举了设计资源 URI 的最佳实践。在本章中，我们将介绍常用的 HTTP 响应代码以及如何处理不同的 MIME 类型。

# 内容协商

内容协商意味着在同一 URI 中允许资源的不同表示，以便客户端可以选择最适合它们的表示。

|   | *“HTTP 有几种机制来进行‘内容协商’-在有多个表示可用时选择给定响应的最佳表示的过程。”* |   |
| --- | --- | --- |
|   | --*RFC 2616, Fielding et al.* |

内容协商有不同的模式。具体如下：

+   使用 HTTP 头

+   使用 URL 模式

## 使用 HTTP 头进行内容协商

当客户端发送请求以创建或更新资源时，应从客户端传输某种有效负载到端点。此外，生成响应时，有效负载可以发送回客户端。这些有效负载由 HTTP 请求和响应实体处理，这些实体作为 HTTP 消息正文的一部分发送。

实体通常通过请求发送，通常用于 HTTP `POST` 和 `PUT` 方法，或者在 HTTP 方法的响应中返回。Content-Type HTTP 头用于指示服务器发送的实体的 MIME 类型。常见的内容类型示例包括`"text/plain"`、`"application/xml"`、`"text/html"`、`"application/json"`、`"image/gif"`和`"image/jpeg"`。

客户端可以向服务器发出请求，并在`Accept`HTTP 头的一部分中指定它可以处理的媒体类型以及其首选顺序。客户端还可以在`"Accept-Language"`头的一部分中指定它希望响应的语言。如果请求中没有`Accept`头，则服务器可以发送它选择的表示。

JAX-RS 规范提供了标准注释来支持内容协商。这些是`javax.ws.rs.Produces`和`javax.ws.rs.Consumes`注释。以下代码段显示了资源方法中`@Produces`注释的示例：

```java
    @GET
    @Path("orders")
    @Produces(MediaType.APPLICATION_JSON)
    public List<Coffee> getCoffeeList(){
        return CoffeeService.getCoffeeList();

    }
```

`getCoffeeList()`方法返回咖啡列表，并用`@Produces(MediaType.APPLICATION_JSON)`进行注释。`@Produces`注释用于指定资源可以发送给客户端的 MIME 类型，并将其与客户端的`Accept`头进行匹配。

此方法将产生如下响应：

```java
X-Powered-By: Servlet/3.1 JSP/2.3 (GlassFish Server Open Source Edition  4.0  Java/Oracle Corporation/1.7)
Server: GlassFish Server Open Source Edition  4.0 
Content-Type: application/json
Date: Thu, 31 Jul 2014 15:25:17 GMT
Content-Length: 268
{
    "coffees": [
        {
            "Id": 10,
            "Name": "Cappuchino",
            "Price": 3.82,
            "Type": "Iced",
            "Size": "Medium"
        },
        {
            "Id": 11,
            "Name": "Americano",
            "Price": 3.42,
            "Type": "Brewed",
            "Size": "Large"
        }
    ]
}
```

在资源中，如果没有方法能够生成客户端请求的 MIME 类型，JAX-RS 运行时会返回 HTTP `406 Not Acceptable`错误。

以下代码片段显示了一个使用`@Consumes`注解的资源方法：

```java
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response addCoffee(Coffee coffee) {
        // Implementation here
    }
```

`@Consumes`注解指定了资源可以消费的媒体类型。当客户端发出请求时，JAX-RS 会找到所有与路径匹配的方法，然后根据客户端发送的内容类型调用方法。

如果资源无法消费客户端请求的 MIME 类型，JAX-RS 运行时会返回 HTTP `415 ("Unsupported Media Type")`错误。

可以在`@Produces`或`@Consumes`注解中指定多个 MIME 类型，如`@Produces(MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML)`。

除了对静态内容协商的支持，JAX-RS 还包含使用`javax.ws.rs.core.Variant`类和`javax.ws.rs.core.Request`对象的运行时内容协商支持。在 JAX-RS 规范中，`Variant`对象是媒体类型、内容语言和内容编码以及 ETags、最后修改的标头和其他先决条件的组合。`Variant`对象定义了服务器支持的资源表示。`Variant.VariantListBuilder`类用于构建表示变体列表。

以下代码片段显示了如何创建资源表示变体列表：

```java
List<Variant>  variants = Variant.mediatypes("application/xml", "application/json").build();
```

代码片段调用了`VariantListBuilder`类的`build`方法。`Request.selectVariant`方法接受`Variant`对象列表，并根据客户端的`Accept`标头选择其中一个，如下面的代码片段所示：

```java
@GET
public Response getCoffee(@Context Request r) { 
    List<Variant> vs = ...;
    Variant v = r.selectVariant(vs);
    if (v == null) {
        return Response.notAcceptable(vs).build();
    } else {
        Coffee coffee = ..//select the representation based on v
        return Response.ok(coffee, v);
    }
}
```

## 基于 URL 模式的内容协商

一些 API 采用的内容协商的另一种方法是根据 URL 中资源的扩展名发送资源表示。例如，客户端可以使用`http://foo.api.com/v2/library/books.xml`或`http://foo.api.com/v2/library/books.json`来请求详细信息。服务器有不同的方法来处理这两个 URI。然而，这两者都是同一资源的表示。

```java
@Path("/v1/books/")
public class BookResource {
    @Path("{resourceID}.xml")
    @GET 
    public Response getBookInXML(@PathParam("resourceID") String resourceID) {
        //Return Response with entity in XML 
             }

    @Path("{resourceID}.json")
    @GET
    public Response getBookInJSON(@PathParam("resourceID") String resourceID) {
        //Return Response with entity in JSON
    }
}
```

如前面的代码片段所示，定义了两个方法：`getBookInXML()`和`getBookInJSON()`，响应是根据 URL 路径返回的。

### 提示

使用 HTTP 内容协商`Accept`标头是一个很好的做法。使用标头进行内容协商可以清晰地将 IT 关注点与业务分开。使用`Accept`标头进行内容协商的另一个优势是只有一个资源方法适用于所有不同的表示形式。

以下部分介绍了如何使用 JAX-RS 中的实体提供程序将资源序列化和反序列化为不同的表示形式。

# 实体提供程序和不同的表示形式

在前面的示例中，我们将从 URI 路径片段和请求的查询参数中提取的文字参数传递给资源方法。然而，有时我们希望在请求主体中传递有效负载，例如`POST`请求。JAX-RS 提供了两个可用的接口：一个用于处理入站实体表示到 Java 反序列化的`javax.ws.rs.ext.MessageBodyReader`，另一个用于处理出站实体 Java 到表示序列化的`javax.ws.rs.ext.MessageBodyWriter`。

`MessageBodyReader`将实体从消息主体表示反序列化为 Java 类。`MessageBodyWriter`将 Java 类序列化为特定表示格式。

以下表格显示了需要实现的方法：

| MessageBodyReader 的方法 | 描述 |
| --- | --- |
| `isReadable()` | 用于检查`MessageBodyReader`类是否支持从流到 Java 类型的转换 |
| `readFrom()` | 用于从`InputStream`类中读取类型 |

如表所示，`MessageBodyReader`实现类的`isReadable()`方法用于检查`MessageBodyReader`是否能处理指定的输入。当调用`MessageBodyReader`类的`readFrom()`方法时，它可以将输入流转换为 Java POJO。

下表显示了必须实现的`MessageBodyWriter`方法以及每个方法的简要描述：

| MessageBodyWriter 方法 | 描述 |
| --- | --- |
| `isWritable()` | 用于检查`MessageBodyWriter`类是否支持从指定的 Java 类型进行转换 |
| `getSize()` | 用于检查字节的长度，如果大小已知则返回长度，否则返回-1 |
| `writeTo()` | 用于从一种类型写入流 |

`MessageBodyWriter`实现类的`isWritable()`方法用于检查`MessageBodyWriter`类是否能处理指定的输入。当调用`MessageBodyWriter`的`writeTo()`方法时，它可以将 Java POJO 转换为输出流。本书的下载包中的示例展示了如何使用`MessageBodyReader`和`MessageBodyWriter`。

然而，还有一些轻量级的实现，如`StreamingOutput`和`ChunkingOutput`类，接下来的部分将介绍 JAX-RS 的 Jersey 实现已经支持基本格式，如文本、JSON 和 XML。

## StreamingOutput

`javax.ws.rs.core.StreamingOutput`类是一个回调，可以在应用程序希望流式传输输出时实现以发送响应中的实体。`StreamingOutput`类是`javax.ws.rs.ext.MessageBodyWriter`类的轻量级替代品。

以下是一个示例代码，展示了如何在响应的一部分中使用`StreamingOutput`：

```java
    @GET
    @Produces(MediaType.TEXT_PLAIN)
    @Path("/orders/{id}")
    public Response streamExample(@PathParam("id") int id) {
        final Coffee coffee = CoffeeService.getCoffee(id);
        StreamingOutput stream = new StreamingOutput() {
            @Override
            public void write(OutputStream os) throws IOException,
                    WebApplicationException {
                Writer writer = new BufferedWriter(new OutputStreamWriter(os));
                writer.write(coffee.toString());
                writer.flush();
            }
        };
        return Response.ok(stream).build();
    }
```

如前面的片段所示，`StreamingOutput`类的`write()`方法已被重写以写入输出流。`StreamingOutput`在以流的方式流式传输二进制数据时非常有用。要了解更多详情，请查看作为下载包的一部分提供的示例代码。

## ChunkedOutput

使用 JAX-RS 的 Jersey 实现，服务器可以使用`org.glassfish.jersey.server.ChunkedOutput`类在可用时立即以块的形式向客户端发送响应，而无需等待其他块也变为可用。`size`对象的值为-1 将在响应的`Content-Length`头中发送，以指示响应将被分块。在客户端，它将知道响应将被分块，因此它将单独读取每个响应的块并处理它，并等待更多块在同一连接上到来。服务器将继续发送响应块，直到在发送最后一个块后关闭连接并完成响应处理。

以下是一个示例代码，展示了如何使用`ChunkedOutput`：

```java
    @GET
    @Produces(MediaType.TEXT_PLAIN)
    @Path("/orders/{id}/chunk")
    public ChunkedOutput<String> chunkExample(final @PathParam("id") int id) {
        final ChunkedOutput<String> output = new ChunkedOutput<String>(String.class);

        new Thread() {
            @Override
            public void run() {
                try {
                    output.write("foo");
                    output.write("bar");
                    output.write("test");
                } catch (IOException e) {
                   e.printStackTrace();
                } finally {
                    try {
                        output.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }.start();
        return output;

    }
}
```

如片段所示，`chunkExample`方法返回一个`ChunkedOutput`对象。

在客户端，`org.glassfish.jersey.client.ChunkedInput`可用于接收以“类型化”块接收消息。这种数据类型对于从大型或连续数据输入流中消耗部分响应非常有用。以下片段显示了客户端如何从`ChunkedInput`类中读取：

```java
ChunkedInput<String> input = target().path("..").request().get(new GenericType<ChunkedInput<String>>() {
        });
while ((chunk = chunkedInput.read()) != null) {
    //Do something
}
```

### 注意

**ChunkedOutput 和 StreamingOutput 之间的区别**

`ChunkedOutput`是 Jersey 提供的内部类。它允许服务器在不关闭客户端连接的情况下发送数据的*块*。它使用一系列方便的调用`ChunkedOutput.write`方法，该方法接受 POJO 和媒体类型输入，然后使用 JAX-RS 的`MessageBodyWriter`类将 POJO 转换为字节。`ChunkedOutput`的写入是非阻塞的。

`StreamingOutput`是一个低级别的 JAX-RS API，直接使用字节。服务器必须实现`StreamingOutput`，并且其`write(OutputStream)`方法将被 JAX-RS 运行时调用一次，并且调用是阻塞的。

## Jersey 和 JSON 支持

Jersey 在处理 JSON 表示时提供了以下支持方法。

### 基于 POJO 的 JSON 绑定支持

基于 POJO 的 JSON 绑定支持非常通用，允许从任何 Java 对象映射到 JSON。这是通过 Jackson 的`org.codehaus.jackson.map.ObjectMapper`实例完成的。例如，要在`Coffee`对象中读取 JSON，我们使用以下方式：

```java
ObjectMapper objectMapper = new ObjectMapper();
Coffee coffee = objectMapper.readValue(jsonData, Coffee.class);
```

有关更多详细信息，请查看[`jersey.java.net/documentation/1.18/json.html`](https://jersey.java.net/documentation/1.18/json.html)。

### 基于 JAXB 的 JSON 绑定支持

如果资源可以生成和消耗 XML 或 JSON，则基于 JAXB 的 JSON 绑定支持非常有用。要实现这一点，可以使用`@XMLRootElement`注释一个简单的 POJO，如下面的代码所示：

```java
@XMLRootElement
public class Coffee {
    private String type;
    private String size;
}
```

使用前面的 JAXB bean 从资源方法生成 JSON 数据格式就像使用以下方式一样简单：

```java
 @GET
 @Produces("application/json")
 public Coffee getCoffee() { 
     //Implementation goes here
}
```

`Produces`注解将负责将`Coffee`资源转换为 JSON 表示。

### 低级 JSON 解析和处理支持

这最适用于使用`JSONArray`和`JSONObject`获得对 JSON 格式的精细控制，以创建 JSON 表示。这里的优势在于应用程序开发人员将完全控制所生成和使用的 JSON 格式。以下是使用`JSONArray`的示例代码：

```java
JsonObject myObject = Json.createObjectBuilder()
        .add("name", "Mocha")
        .add("size", "Large")
        .build();
```

另一方面，处理数据模型对象可能会更加复杂。例如，以下代码显示了拉取解析编程模型如何与 JSONParser 一起工作：

```java
JsonParser parser = Json.createParser(…)
Event event = parser.next(); // START_OBJECT
event = parser.next(); //END OBJECT
```

下一节将介绍如何对 API 进行版本控制，以便它可以随着时间的推移而发展，并确保客户端应用程序的基本功能不会因服务器端 API 版本更改而中断。

# API 版本控制

对于应用程序的演变，URI 设计应该有一些约束来识别版本。很难预见应用程序生命周期中将发生变化的所有资源。API 版本控制的目标是定义资源端点和寻址方案，并将版本与其关联。API 开发人员必须确保 HTTP 动词的语义和状态代码在版本更改时可以继续工作而无需人工干预。在应用程序的生命周期内，版本将会发展，API 可能需要被弃用。对于 API 的旧版本的请求可以重定向到最新的代码路径，或者可以使用适当的错误代码来指示 API 已过时。

可以有不同的方法来对 API 进行版本控制。这些方法如下：

+   在 URI 本身中指定版本

+   在请求查询参数中指定版本

+   在`Accept`标头中指定版本

所有这些都可以正常工作。下一节将详细介绍方法并突出每种方法的优缺点。

## URI 中的版本方法

在这种方法中，版本是服务器公开的资源的 URI 的一部分。

例如，在以下 URL 中，作为资源路径的一部分公开了“v2”版本：

`http://api.foo.com/v2/coffees/1234`

此外，API 开发人员可以提供一个路径，默认为最新版本的 API。因此，以下请求 URI 应该表现相同：

+   `http://api.foo.com/coffees/1234`

+   `http://api.foo.com/v2/coffees/1234`

这表示 v2 是最新的 API 版本。如果客户端指向旧版本，则应通知他们使用以下 HTTP 代码进行重定向以使用新版本：

+   `301 Moved permanently`：这表示具有请求的 URI 的资源已永久移动到另一个 URI。此状态代码可用于指示旧的或不受支持的 API 版本，通知 API 客户端资源 URI 已被资源永久替换。

+   `302 Found`：这表示所请求的资源暂时位于另一个位置，而所请求的 URI 可能仍然受支持。

## 作为请求查询参数的一部分的版本

使用 API 版本的另一种方式是将版本发送到请求参数中。资源方法可以根据请求中发送的版本选择代码流程。例如，在`http://api.foo.com/coffees/1234?version=v2` URL 中，v2 已被指定为查询参数`?version=v2`的一部分。

这种格式的缺点是响应可能无法被缓存。此外，资源实现的源代码将根据查询参数中的版本而有不同的流程，这并不直观或易于维护。

### 注意

有关缓存最佳实践的更多详细信息将在第四章中进行介绍，*性能设计*。

相比之下，如果 URI 包含版本信息，那么它会更清晰、更易读。此外，URI 的版本可能有一个标准的生命周期，在此之后，对于旧版本的所有请求都会重定向到最新版本。

### 注意

Facebook、Twitter 和 Stripe API 都将版本作为 URI 的一部分。Facebook API 在发布后两年内使版本不可用。如果客户端进行未版本化的调用，服务器将默认使用 Facebook API 的最早可用版本。

Twitter API 提供了六个月的时间来完全从 v1.0 过渡到 v1.1。

有关这些 API 的更多详细信息将在附录中找到。

## 在`Accept`头中指定版本

一些 API 更喜欢将版本作为`Accept`头的一部分。例如，看一下以下代码片段：

```java
Accept: application/vnd.foo-v1+json
```

在上面的片段中，`vnd`代表特定于供应商的 MIME 类型。这会移除 URL 的版本，并且受到一些 API 开发者的青睐。

### 注意

GitHub API 建议您明确发送`Accept`头，如下所示：

```java
Accept: application/vnd.github.v3+json
```

有关更多详细信息，请查看[`developer.github.com/v3/media/`](https://developer.github.com/v3/media/)。

下一节将介绍应该发送给客户端的标准 HTTP 响应代码。

# 响应代码和 REST 模式

HTTP 提供了可以针对每个请求返回的标准化响应代码。以下表格总结了基于 CRUD API 的 REST 响应模式。根据使用的操作以及是否将内容作为响应的一部分发送，会有细微的差异：

| 组 | 响应代码 | 描述 |
| --- | --- | --- |
| 成功 2XX | `200 OK` | 这可以用于使用`PUT`、`POST`或`DELETE`进行`create`、`update`或`delete`操作。这会作为响应的一部分返回内容。 |
|   | `201 Created` | 这可以用于使用`PUT`创建资源时。它必须包含资源的`Location`头。 |
|   | `204 No Content` | 这可以用于`DELETE`、`POST`或`PUT`操作。响应中不返回任何内容。 |
|   | `202 Accepted` | 这会在处理尚未完成时稍后发送响应。这用于异步操作。这还应返回一个`Location`头，可以指定客户端可以监视请求的位置。 |
| 重定向 3XX | `301 Permanent` | 这可以用于显示所有请求都被重定向到新位置。 |
|   | `302 Found` | 这可以用于显示资源已经存在且有效。 |
| 客户端错误 4XX | `401 Unauthorized` | 这用于显示基于凭据无法处理请求。 |
|   | `404 Not Found` | 这用于显示资源未找到。最好的做法是对未经认证的请求返回`404 Not Found`错误，以防止信息泄漏。 |
|   | `406 Not Acceptable` | 这可以用于当资源无法生成客户端指定的 MIME 类型时。当`Accept`头中指定的 MIME 类型与使用`@Produces`注释的资源方法/类中的任何媒体类型不匹配时，就会发生这种情况。 |
|   | `415 不支持的媒体类型` | 当客户端发送无法被资源消耗的媒体类型时可以使用。当`Content-Type`标头中指定的 MIME 类型与`@Consumes`注释的资源方法/类中的任何媒体类型不匹配时会发生这种情况。 |
| 服务器错误 5XX | `500 内部服务器错误` | 当没有特定细节可用时，这是一个通用的内部服务器错误消息。 |
|   | `503 服务不可用` | 当服务器正在维护或太忙无法处理请求时可以使用。 |

JAX-RS 定义了一个`javax.ws.rs.core.Response`类，该类具有使用`javax.ws.rs.core.Response.ResponseBuilder`创建实例的静态方法：

```java
@POST
 Response addCoffee(...) {
   Coffee coffee = ...
   URI coffeeId = UriBuilder.fromResource(Coffee.class)...
   return Response.created(coffeeId).build();
 }
```

上述代码片段显示了一个`addCoffee()`方法，该方法使用`Response.created()`方法返回`201 已创建`响应。有关其他响应方法的更多详细信息，请查看[`jersey.java.net/apidocs/latest/jersey/javax/ws/rs/core/Response.html`](https://jersey.java.net/apidocs/latest/jersey/javax/ws/rs/core/Response.html)。

# 推荐阅读

+   [`jersey.java.net/documentation/latest/representations.html`](https://jersey.java.net/documentation/latest/representations.html)：Jersey 内容协商的文档

+   [`docs.jboss.org/resteasy/docs/2.2.1.GA/userguide/html/JAX-RS_Content_Negotiation.html`](http://docs.jboss.org/resteasy/docs/2.2.1.GA/userguide/html/JAX-RS_Content_Negotiation.html)：RESTEasy 和基于 URL 的内容协商

+   [`dev.twitter.com/docs/api/1.1/overview`](https://dev.twitter.com/docs/api/1.1/overview)：Twitter REST API 和版本控制策略

+   [`developers.facebook.com/docs/apps/versions`](https://developers.facebook.com/docs/apps/versions)：Facebook API 和版本控制

# 摘要

在本章中，我们涵盖了内容协商、API 版本控制和 REST 响应代码等主题。本章的一个主要要点是要理解支持同一资源的各种表示形式有多么重要，以便客户端可以为其情况选择合适的表示形式。我们涵盖了流式传输和分块输出之间的差异，以及它们如何作为轻量级选项与自定义实体提供者（如`MessageBodyReader`和`MessageBodyWriter`）一起使用。我们看到了一些公司在其解决方案中使用版本控制的案例研究，以及在各种主题中散布的最佳实践和设计原则。

下一章将涵盖 REST 编程模型中的高级细节，如安全性、可追溯性和验证。


# 第三章：安全性和可追溯性

在开放平台时代，开发人员可以构建应用程序，这些应用程序可以很容易地并快速地与平台的业务周期解耦。这种基于 API 的架构实现了敏捷开发、更容易的采用、普及和规模化，并与企业内外的应用程序集成。应用程序的最重要考虑因素之一是处理安全性。构建应用程序的开发人员不应该关心用户的凭据。此外，还可以有其他客户端使用 REST 服务，包括但不限于浏览器和移动应用程序到其他服务。客户端可以代表其他用户执行操作，并且必须经过授权才能代表他们执行操作，而无需用户共享用户名和密码。这就是 OAuth 2.0 规范的作用所在。

构建分布式应用程序时需要考虑的另一个重要方面是可追溯性，这将涉及记录与请求相关的数据，以进行调试，这些请求在涵盖多个微服务的环境中可能是地理分布的，并且处理成千上万的请求。必须记录对 REST 资源的请求和状态代码，以帮助调试生产中的问题，并且还可以作为审计跟踪。本章将涵盖 REST 编程模型中安全性和可追溯性的高级细节。涵盖的主题如下：

+   记录 REST API

+   RESTful 服务的异常处理

+   验证模式

+   联合身份

+   SAML 2.0

+   OAuth 2.0

+   OpenID Connect

本章将总结构建可扩展、高性能的 RESTful 服务所需的各种构建块。

# 记录 REST API

复杂的分布式应用程序可能会引入许多故障点。问题很难找到和修复，因此延迟了事件响应并造成了昂贵的升级。应用程序开发人员和管理员可能无法直接访问他们所需的机器数据。

记录是构建 RESTful 服务的一个非常重要的方面，特别是在调试运行各种微服务的分布式节点中出现生产问题的情况下。它有助于链接构成应用程序或业务服务的各个组件之间的事件或事务。完整的日志序列可以帮助重现在生产系统中发生的事件过程。此外，日志还可以帮助索引、聚合、切片数据、分析请求模式，并提供大量潜在有用的信息。

以下代码涵盖了如何编写一个简单的日志记录过滤器，可以与 REST 资源集成。该过滤器将记录与请求相关的数据，如时间戳、查询字符串和输入：

```java
@WebFilter(filterName = "LoggingFilter",
        urlPatterns = {"/*"}
)
public class LoggingFilter implements Filter {
    static final Logger logger = Logger.getLogger(LoggingFilter.class);
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
            FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;

logger.info("request" +httpServletRequest.getPathInfo().toString());
        filterChain.doFilter(servletRequest, servletResponse);

    }
```

`LoggingFilter`类是一个简单的过滤器，实现了`javax.servlet.Filter`接口。记录器将记录所有带有请求路径和输入的消息。示例使用 Apache Log4j 设置日志记录。

### 注意

有关 Apache Log4J 的更多详细信息，请查看[`logging.apache.org/log4j/2.x/`](http://logging.apache.org/log4j/2.x/)。

然后可以从分布式日志服务器应用程序（例如 Splunk ([`www.splunk.com/`](http://www.splunk.com/)）中收集和挖掘这些日志，这可以为开发人员提供有关生产中故障或性能问题的信息和根本原因分析。在我们的咖啡店类比中，一个例子是处理咖啡订单时出现问题。如果请求细节被记录在 Splunk 等分布式日志服务器应用程序中，开发人员可以根据时间查询，并查看客户端尝试发送的内容以及请求失败的原因。

下一节将涵盖许多在记录 REST API 时要牢记的最佳实践。

## 记录 REST API 的最佳实践

在大规模分布式环境中，日志数据可能是开发人员用于调试问题的唯一信息。如果审计和日志记录做得好，可以极大地帮助解决此类生产问题，并重放出问题发生前的步骤序列。以下部分列出了一些用于理解系统行为和性能等问题的日志记录最佳实践。

### 在服务日志中包括详细的一致模式

记录模式至少应包括以下内容是一个良好的实践：

+   日期和当前时间

+   记录级别

+   线程的名称

+   简单的记录器名称

+   详细的消息

### 混淆敏感数据

在生产日志中掩盖或混淆敏感数据非常重要，以保护泄露机密和关键客户信息的风险。密码混淆器可以在日志过滤器中使用，它将从日志中掩盖密码、信用卡号等。**个人可识别信息**（**PII**是指可以单独使用或与其他信息一起用于识别个人的信息。PII 的例子可以是一个人的姓名、电子邮件、信用卡号等。表示 PII 的数据应该使用各种技术进行掩盖，如替换、洗牌、加密等技术。

### 注意

更多详情，请查看[`en.wikipedia.org/wiki/Data_masking`](http://en.wikipedia.org/wiki/Data_masking)。

### 识别调用者或发起者作为日志的一部分

在日志中标识调用者是一个良好的实践。API 可能被各种客户端调用，例如移动端、Web 端或其他服务。添加一种方式来识别调用者可能有助于调试问题，以防问题特定于某个客户端。

### 默认情况下不记录有效负载

具有可配置选项以记录有效负载，以便默认情况下不记录任何有效负载。这将确保对于处理敏感数据的资源，在默认情况下不会记录有效负载。

### 识别与请求相关的元信息

每个请求都应该有一些关于执行请求所花费的时间、请求的状态和请求的大小的细节。这将有助于识别延迟问题以及可能出现的大消息的其他性能问题。

### 将日志系统与监控系统绑定

确保日志中的数据也可以与监控系统绑定，后者可以在后台收集与 SLA 指标和其他统计数据相关的数据。

### 注意

**各种平台上分布式环境中日志框架的案例研究**

Facebook 开发了一个名为 Scribe 的自制解决方案，它是一个用于聚合流式日志数据的服务器。它可以处理全球分布的服务器每天大量的请求。服务器发送数据，可以进行处理、诊断、索引、汇总或聚合。Scribe 被设计为可以扩展到非常大量的节点。它被设计为能够经受住网络和节点故障的考验。系统中的每个节点都运行着一个 scribe 服务器。它被配置为聚合消息，并将它们发送到一个更大的组中的中央 scribe 服务器。如果中央 scribe 服务器宕机，消息将被写入本地磁盘上的文件，并在中央服务器恢复时发送。更多详情，请查看[`github.com/facebookarchive/scribe`](https://github.com/facebookarchive/scribe)。

Dapper 是谷歌的跟踪系统，它从成千上万的请求中采样数据，并提供足够的信息来跟踪数据。跟踪数据被收集在本地日志文件中，然后被拉入谷歌的 BigTable 数据库。谷歌发现对于常见情况采样足够的信息可以帮助跟踪细节。更多详情，请查看[`research.google.com/pubs/pub36356.html`](http://research.google.com/pubs/pub36356.html)。

接下来的部分将介绍如何验证 REST API 请求和/或响应实体。

# 验证 RESTful 服务

在暴露 REST 或基于 HTTP 的服务 API 时，验证 API 的行为是否正确以及暴露的数据格式是否按预期结构化是很重要的。例如，验证 RESTful 服务的输入，例如作为请求体发送的电子邮件，必须符合标准，负载中必须存在某些值，邮政编码必须遵循特定格式等。这可以通过 RESTful 服务的验证来完成。

JAX-RS 支持 Bean 验证来验证 JAX-RS 资源类。这种支持包括：

+   向资源方法参数添加约束注释

+   确保在将实体作为参数传递时实体数据有效

以下是包含`@Valid`注释的`CoffeesResource`类的代码片段：

```java
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @ValidateOnExecution
    public Response addCoffee(@Valid Coffee coffee) {
        …
            }
```

`javax.validation.executable.ValidateOnExecution`注释可以帮助指定哪个方法或构造函数应在执行时验证其参数和返回值。请求体上的`javax.validation.Valid`注释将确保`Coffee`对象将符合 POJO 中指定的规则。

以下是`Coffee` POJO 的代码片段：

```java
@XmlRootElement
public class Coffee {

    @VerifyValue(Type.class)
    private String type;

    @VerifyValue(Size.class)
    private String size;

    @NotNull
    private String name;
    // getters and setters
}
```

字段名具有`javax.validation.constrains.NotNull`注释，强制要求订单中的咖啡名称不能为空。同样，我们在示例中定义了自定义注释，它将验证类型和大小，并检查请求体中的值是否遵循正确的格式。

例如，`Size`可以是以下值之一：`Small`，`Medium`，`Large`或`ExtraLarge`：

```java
public enum Size {
    Small("S"), Medium("M"), Large("L"), ExtraLarge("XL");
    private String value;
}
```

`@VerifyValue(Size.class)`注释是在可下载示例中定义的自定义注释。

## 验证异常处理和响应代码

以下表格提供了在抛出各种与验证相关的异常时返回的响应代码的快速摘要。错误代码的类型取决于抛出的异常以及验证是在 HTTP 方法的请求还是响应上执行的。

| 返回的 HTTP 响应代码 | 异常类型 |
| --- | --- |
| `500 内部服务器错误` | 当验证方法返回类型时抛出`javax.validation.ValidationException`或`ValidationException`的任何子类，包括`ConstraintValidationException`时返回此错误代码 |
| `400 错误` | 当在验证方法中抛出`ConstraintViolationException`以及所有其他情况时 |

接下来的部分涵盖了 API 开发人员如何抛出特定于应用程序的异常，并根据异常映射 HTTP 错误代码。

# RESTful 服务的错误处理

在构建 RESTful API 时，需要抛出特定于应用程序的异常，并提供包含这些异常详细信息的特定 HTTP 响应。接下来的部分将介绍如何处理用户定义的异常并将它们映射到 HTTP 响应和状态代码。`javax.ws.rs.ext.ExceptionMapper`类是自定义的、应用程序提供的组件，它捕获抛出的应用程序异常并编写特定的 HTTP 响应。异常映射器类使用`@Provider`注释进行标注。

以下代码片段显示了如何构建自定义异常映射器：

```java
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/orders/{id}")
    public Response getCoffee(@PathParam("id") int id) {
        Coffee coffee =  CoffeeService.getCoffee(id);
        if (coffee == null)
            throw new CoffeeNotFoundException("No coffee found for order " + id);
        return Response.ok(coffee).type(MediaType.APPLICATION_JSON_TYPE).build();
    }
```

如前面的代码片段所示，`getCoffees()`方法返回一个带有指定路径参数的`Coffee`对象。如果找不到指定 ID 的咖啡，则代码会抛出`CoffeeNotFoundException`。

以下是`ExceptionMapper`类实现的代码：

```java
@Provider
public class MyExceptionMapper implements ExceptionMapper<Exception> {

    public Response toResponse(Exception e) {
        ResourceError resourceError = new ResourceError();

        String error = "Service encountered an internal error";
        if (e instanceof CoffeeNotFoundException) {
            resourceError.setCode(Response.Status.NOT_FOUND.getStatusCode());
            resourceError.setMessage(e.getMessage());

            return Response.status(Response.Status.NOT_FOUND).entity(resourceError)
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build();
        }
        return Response.status(503).entity(resourceError).type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }
}
```

前面的代码显示了`ExceptionMapper`的实现，其`toResponse()`方法已被覆盖。代码检查抛出的异常是否是`CoffeeNotFoundException`的实例，然后返回一个实体类型为`ResourceError`的响应。

`ResourceError`类是一个使用`@XMLRootElement`注释的 POJO，并作为响应的一部分发送：

```java
@XmlRootElement
public class ResourceError {

    private int code;
    private String message;
    //getters and setters
…}
```

您可以将示例作为可下载包的一部分运行，输出如下：

```java
HTTP/1.1 404 Not Found
X-Powered-By: Servlet/3.1 JSP/2.3 (GlassFish Server Open Source Edition  4.0  Java/Oracle Corporation/1.7)
Server: GlassFish Server Open Source Edition 4.0
Content-Type: application/json
Content-Length: 54

{"code":404,"message":"No coffee found for order 100"}
```

# 认证和授权

过去，组织需要一种方式来统一企业用户的身份验证。单点登录是一个解决方案，可以在企业的不同应用程序中保持一个用户名和密码的存储库。

随着面向服务的架构的发展，组织需要一种方式，使合作伙伴和其他服务可以使用 API，并且需要一种简化各种应用程序和平台之间登录过程的方式。随着社交媒体的发展，各种平台开放，API 和生态系统建立了大量应用程序和大量设备使用 Twitter、Facebook 和 LinkedIn 等平台。

因此，将认证和授权功能与消费应用程序解耦变得越来越重要。此外，并非每个应用程序都必须知道用户的凭据。接下来的部分将涵盖 SAML 2.0 和 OAuth 2.0，作为简化登录和增加安全性的联合身份的一部分。

子节将枚举以下主题：

+   SAML

+   OAuth

+   刷新令牌与访问令牌

+   Jersey 和 OAuth 2.0

+   何时使用 SAML 或 OAuth？

+   OpenID Connect

## 什么是认证？

认证是建立和传达操作浏览器或本机应用程序的人是他/她声称的人的过程。

### SAML

**安全断言标记语言**（**SAML**）是一个标准，包括配置文件、绑定和构造，以实现**单点登录**（**SSO**）、联合和身份管理。

SAML 2.0 规范提供了 Web 浏览器 SSO 配置文件，定义了如何实现 Web 应用程序的单点登录。它定义了三个角色：

+   **主体**：这通常是用户想要验证自己的身份的地方

+   **身份提供者**（**IdP**）：这是能够验证最终用户身份的实体

+   **服务提供者**（**SP**）：这是希望使用身份提供者验证最终用户身份的实体

以下流程显示了 SAML 的一个简单示例。比如，员工想要访问企业旅行网站。企业旅行应用程序将请求与员工关联的身份提供者来验证他的身份，然后为他采取行动。

![SAML](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-ptn-best-prac/img/7963OS_03_02.jpg)

流程解释如下：

1.  用户访问企业应用程序，比如旅行应用程序。

1.  旅行应用程序将生成一个 SAML 请求，并将用户重定向到雇主的**身份提供者**（**IdP**）。

1.  用户被重定向到雇主的身份提供者以获取 SAML 认证断言。

1.  IdP 解析 SAML 请求，对用户进行身份验证，并生成 SAML 响应。

1.  浏览器将 SAML 响应发送到旅行应用程序。

1.  收到访问令牌后，企业旅行应用程序随后能够通过在 HTTP 请求的标头中传递令牌来访问 Web 资源。访问令牌充当一个会话令牌，封装了旅行应用程序代表用户的事实。

SAML 具有用于 Web 浏览器、SSO、SOAP 和 WS-Security 的绑定规范，但没有正式的 REST API 绑定。

下一节涵盖了 OAuth，这已被 Twitter、Facebook 和 Google 等平台广泛使用于授权。

## 什么是授权？

授权是检查请求者是否有权限执行所请求操作的过程。

### OAuth

OAuth 代表**开放授权**，为用户授权应用程序访问其与账户相关的数据提供了一种方式，而不需要提供用户名和密码。

在客户端/服务器身份验证中，客户端使用其凭据访问服务器上的资源。服务器不在乎请求是来自客户端还是客户端是否为其他实体请求资源。实体可以是另一个应用程序或另一个人，因此客户端不是在访问自己的资源，而是在访问另一个用户的资源。请求访问受保护且需要身份验证的资源的任何人都必须得到资源所有者的授权。OAuth 是一种打开 Twitter、Facebook、Google+、GitHub 等公司的 REST API 以及建立在其之上的众多第三方应用程序的方法。OAuth 2.0 完全依赖于 SSL。

OAuth 请求中的步数指涉及的参与方数量。客户端、服务器和资源所有者都参与的流程表示 3-legged OAuth。当客户端代表自己行事时，它被称为 2-legged OAuth。

OAuth 通过访问令牌实现此功能。访问令牌就像提供有限功能的代客泊车钥匙，可以在有限的时间内访问。令牌的寿命有限，从几小时到几天不等。以下图表显示了 OAuth 的流程：

![OAuth](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-ptn-best-prac/img/7963OS_03_01.jpg)

上述图表显示了授权代码授予流程。

在这个例子中，用户在服务提供商网站上有他的照片，比如 Flickr。现在，用户需要调用打印服务来打印他的照片，例如 Snapfish，这是一个消费者应用程序。用户可以使用 OAuth 允许打印服务在有限的时间内访问他的照片，而不是将他的用户名和密码分享给消费者应用程序。

因此，在我们的示例中，有三个角色，如下所述：

+   **用户或资源所有者**：用户是希望打印他的照片的资源所有者

+   **消费者应用程序或客户端**：这是打印服务应用程序，将代表用户行事

+   **服务提供商或服务器**：服务提供商是将存储用户照片的资源服务器

有了这个例子，我们可以看到 OAuth 舞蹈中涉及的步骤：

1.  用户希望允许应用程序代表他执行任务。在我们的例子中，任务是打印照片，这些照片在服务器上使用消费者应用程序。

1.  消费者应用程序将用户重定向到服务提供商的授权 URL。

在这里，提供者显示一个网页，询问用户是否可以授予应用程序读取和更新其数据的访问权限。

1.  用户同意通过打印服务消费者应用程序授予应用程序访问权限。

1.  服务提供商将用户重定向回应用程序（通过重定向 URI），将授权代码作为参数传递。

1.  应用程序将授权代码交换为访问授权。服务提供商向应用程序发放访问授权。授权包括访问令牌和刷新令牌。

1.  现在连接建立，消费者应用程序现在可以获取对服务 API 的引用，并代表用户调用提供者。因此，打印服务现在可以从服务提供商的网站访问用户的照片。

### 注意

OAuth 的优势在于，由于使用访问令牌而不是实际凭据，受损的应用程序不会造成太多混乱。 SAML 承载流实际上与之前介绍的经典 OAuth 3-leg 流非常相似。但是，与将用户的浏览器重定向到授权服务器不同，服务提供商与身份提供商合作以获得简单的身份验证断言。服务提供商应用程序为用户交换 SAML 承载断言，而不是交换授权代码。

## OAuth 2.0 和 OAuth 1.0 之间的区别

OAuth 2.0 规范清楚地阐述了如何完全在浏览器中使用 JavaScript 使用 OAuth，而没有安全地存储令牌的方法。这还在高层次上解释了如何在手机上或甚至在根本没有网络浏览器的设备上使用 OAuth，涵盖了对智能手机和传统计算设备上的*应用程序*和*本机应用程序*的交互，以及网站。

OAuth 2.0 定义了以下三种类型的配置文件：

+   Web 应用程序（在这种情况下，客户端密码存储在服务器上，并且使用访问令牌。）

+   Web 浏览器客户端（在这种情况下，不信任 OAuth 凭据；一些提供商不会发布客户端密钥。一个例子是浏览器中的 JavaScript。）

+   本机应用程序（在这种情况下，生成的访问令牌或刷新令牌可以提供可接受的保护级别。一个例子包括移动应用程序。）

OAuth 2.0 不需要加密，使用的是 HTTPS 而不是 HMAC。此外，OAuth 2.0 允许限制访问令牌的生命周期。

### 授权授予

授权授予是代表资源所有者或用户授权的凭据，允许客户端访问其受保护的资源以获取访问令牌。OAuth 2.0 规范定义了四种授权类型，如下所示：

+   授权码授予

+   隐式授予

+   资源所有者密码凭据授予

+   客户端凭据授予

此外，OAuth 2.0 还定义了用于定义其他类型的可扩展机制。

## 刷新令牌与访问令牌

刷新令牌是用于获取访问令牌的凭据。当当前访问令牌无效或过期时，刷新令牌用于获取访问令牌。发放刷新令牌是服务器自行决定的可选项。

与访问令牌不同，刷新令牌仅用于与授权服务器一起使用，永远不会发送到资源服务器以访问资源。

### Jersey 和 OAuth 2.0

尽管 OAuth 2.0 被各个企业广泛使用，但 OAuth 2.0 RFC 是在其基础上构建解决方案的框架。在 RFC 中有许多灰色地带，规范留给实施者。在没有必需的令牌类型、令牌过期协议或令牌大小的具体指导的领域存在犹豫。

### 注意

阅读此页面以获取更多详细信息：

[`hueniverse.com/2012/07/26/oauth-2-0-and-the-road-to-hell/`](http://hueniverse.com/2012/07/26/oauth-2-0-and-the-road-to-hell/)

目前，Jersey 对 OAuth 2.0 的支持仅限于客户端。OAuth 2.0 规范定义了许多扩展点，由服务提供商来实现这些细节。此外，OAuth 2.0 定义了多个授权流程。授权码授予流程是 Jersey 目前支持的流程，其他流程都不受支持。有关更多详细信息，请查看[`jersey.java.net/documentation/latest/security.html`](https://jersey.java.net/documentation/latest/security.html)。

## REST API 中 OAuth 的最佳实践

以下部分列出了服务提供商实施 OAuth 2.0 可以遵循的一些最佳实践。

### 限制访问令牌的生命周期

协议参数`expires_in`允许授权服务器限制访问令牌的生命周期，并将此信息传递给客户端。此机制可用于发行短期令牌。

### 支持在授权服务器中提供刷新令牌

刷新令牌可以与短期访问令牌一起发送，以授予对资源的更长时间访问，而无需涉及用户授权。这提供了一个优势，即资源服务器和授权服务器可能不是同一实体。例如，在分布式环境中，刷新令牌总是在授权服务器上交换。

### 使用 SSL 和加密

OAuth 2.0 严重依赖于 HTTPS。这将使框架更简单但不太安全。

以下表格提供了何时使用 SAML 和何时使用 OAuth 的快速摘要。

| 场景 | SAML | OAuth |
| --- | --- | --- |
| 如果参与方之一是企业 | 使用 SAML |   |
| 如果应用程序需要为某些资源提供临时访问权限 |   | 使用 OAuth |
| 如果应用程序需要自定义身份提供者 | 使用 SAML |   |
| 如果应用程序有移动设备访问 |   | 使用 OAuth |
| 如果应用程序对传输没有限制，例如 SOAP 和 JMS | 使用 SAML |   |

## OpenID Connect

OpenID 基金会正在进行 OpenID Connect 的工作。OpenID Connect 是建立在 OAuth 2.0 之上的简单的基于 REST 和 JSON 的可互操作协议。它比 SAML 更简单，易于维护，并覆盖了从社交网络到商业应用程序再到高度安全的政府应用程序的各种安全级别。OpenID Connect 和 OAuth 是身份验证和授权的未来。有关更多详细信息，请访问[`openid.net/connect/`](http://openid.net/connect/)。

### 注意

**使用 OAuth 2.0 和 OpenID Connect 的公司案例**

Google+登录是建立在 OAuth 2.0 和 OpenID Connect 协议之上的。它支持空中安装、社交功能，并在标准化的 OpenID Connect 登录流程之上提供登录小部件。

接下来的部分将总结到目前为止我们在构建 RESTful 服务时涵盖的各种组件。

# REST 架构组件

接下来的部分将涵盖在构建 RESTful API 时必须考虑的各种组件。所有这些将在本书的各个部分中进行介绍。我们还将介绍在设计和开发 REST API 时要避免的各种陷阱的最佳实践。REST 架构组件如下图所示：

![REST 架构组件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-ptn-best-prac/img/7963OS_03_03.jpg)

从上图中可以看到，REST 服务可以从各种客户端和运行在不同平台和设备上的应用程序中消耗，例如移动设备和 Web 浏览器。

这些请求通过代理服务器发送。如前图所示，可以将图中的 REST 架构组件链接在一起。例如，可以有一个过滤器链，包括**Auth**、**速率限制**、**缓存**和**日志记录**相关的过滤器。这将负责对用户进行身份验证，检查来自客户端的请求是否在速率限制内，然后是一个缓存过滤器，可以检查请求是否可以从缓存中提供。接下来是一个日志记录过滤器，可以记录请求的详细信息。

在响应端，可以进行**分页**，以确保服务器发送结果的子集。此外，服务器可以进行**异步处理**，从而提高响应能力和规模。响应中可以包含链接，处理 HATEOAS。

这些是我们迄今为止涵盖的一些 REST 架构组件：

+   使用 HTTP 请求使用 HTTP 动词来使用 REST API 进行统一接口约束

+   内容协商，在存在多个表示可用时选择响应的表示

+   日志记录以提供可追溯性以分析和调试问题

+   异常处理以使用 HTTP 代码发送特定于应用程序的异常

+   使用 OAuth 2.0 进行身份验证和授权，以便为其他应用程序提供访问控制，并在用户无需发送其凭据的情况下执行操作

+   验证以向客户端发送详细的带有错误代码的消息，以及对请求中收到的输入进行验证

接下来的几章将重点介绍高级主题以及以下模块的最佳实践。我们将提供代码片段，以展示如何使用 JAX-RS 实现这些功能。

+   速率限制以确保服务器不会因来自单个客户端的太多请求而负担过重

+   缓存以提高应用程序的响应能力

+   异步处理，使服务器可以异步地向客户端发送响应

+   微服务将单片服务分解为细粒度服务

+   HATEOAS 通过在响应中返回链接列表来改善可用性、可理解性和可导航性

+   分页，允许客户端指定感兴趣的数据集中的项目

我们还将介绍主要平台，如 Facebook、Google、GitHub 和 PayPal 是如何在其 REST API 中采用这些解决方案的。

# 推荐阅读

以下链接可能对获取与本章主题相关的额外信息有用：

+   [`developers.google.com/oauthplayground/`](https://developers.google.com/oauthplayground/)：Google OAuth playground 用于创建和测试签名请求

+   [`hueniverse.com/2012/07/26/oauth-2-0-and-the-road-to-hell/`](http://hueniverse.com/2012/07/26/oauth-2-0-and-the-road-to-hell/)：OAuth 2.0 和通往地狱之路

+   [`developers.google.com/accounts/docs/OAuth2Login`](https://developers.google.com/accounts/docs/OAuth2Login)：Google 账户身份验证和授权

+   [`github.com/facebookarchive/scribe`](https://github.com/facebookarchive/scribe)：Facebook 的 Scribe 日志服务器

+   [`static.googleusercontent.com/media/research.google.com/en/us/pubs/archive/36356.pdf`](http://static.googleusercontent.com/media/research.google.com/en/us/pubs/archive/36356.pdf)：Google Dapper 大规模分布式跟踪架构

# 总结

本章以对记录 RESTful API 进行简要介绍开始，关键原则是认识到记录请求的重要性以及记录的最佳实践，包括安全合规性。我们学习了如何使用 Bean Validation 验证 JAX-RS 2.0 资源。在本章中，我们还看到了如何为特定应用程序情况编写通用异常映射器。

我们讨论了联合身份在当前互联混合系统、协议和设备时代的必要性。我们讨论了 SAML 和 OAuth 2.0 之间的相似之处，以及 3-legged OAuth 和 OAuth 的最佳实践。

下一章将介绍诸如缓存模式和异步 REST API 以提高性能和可伸缩性，然后更详细地了解如何使用 HTTP Patch 和更新 JSON Patch 执行部分更新。


# 第四章：性能设计

REST 是一种符合 Web 架构设计的架构风格，需要正确设计和实现，以便利用可扩展的 Web。本章涵盖了与性能相关的高级设计原则，每个开发人员在构建 RESTful 服务时都必须了解。

本章涵盖的主题包括以下内容：

+   缓存原则

+   REST 中的异步和长时间运行的作业

+   HTTP PATCH 和部分更新

我们将详细介绍不同的 HTTP 缓存头，并学习如何发送条件请求，以查看新内容或缓存内容是否需要返回。然后，我们将展示如何使用 JAX-RS 来实现缓存。

此外，我们将介绍 Facebook API 如何使用 ETags 进行缓存。接下来，我们将介绍如何使用 JAX-RS 进行异步请求响应处理以及最佳实践。最后，我们将介绍 HTTP PATCH 方法，并学习如何实现部分更新以及部分更新的常见实践。

本章包含了不同的代码片段，但展示这些片段在实际中的完整示例包含在本书的源代码下载包中。

# 缓存原则

在本节中，我们将介绍设计 RESTful 服务时涉及的不同编程原则。我们将涵盖的一个领域是缓存。缓存涉及将与请求相关的响应信息存储在临时存储中，以特定时间段内。这确保了服务器在未来不需要处理这些请求时，可以从缓存中满足响应。

缓存条目可以在特定时间间隔后失效。缓存条目也可以在缓存中的对象发生变化时失效，例如，当某个 API 修改或删除资源时。

缓存有许多好处。缓存有助于减少延迟并提高应用程序的响应速度。它有助于减少服务器需要处理的请求数量，因此服务器能够处理更多的请求，客户端将更快地获得响应。

通常，诸如图像、JavaScript 文件和样式表等资源都可以被相当大地缓存。此外，建议缓存可能需要在后端进行密集计算的响应。

## 缓存细节

接下来的部分涵盖了与缓存相关的主题。使缓存有效工作的关键是使用 HTTP 缓存头，指定资源的有效时间以及上次更改的时间。

## 缓存头的类型

下一节将介绍缓存头的类型，然后是每种缓存头的示例。以下是头部的类型：

+   强缓存头

+   弱缓存头

### 强缓存头

强缓存头指定了缓存资源的有效时间，浏览器在此期间不需要发送任何更多的`GET`请求。`Expires`和`Cache-Control max-age`是强缓存头。

### 弱缓存头

弱缓存头帮助浏览器决定是否需要通过发出条件`GET`请求从缓存中获取项目。`Last-Modified`和`ETag`是弱缓存头的示例。

### Expires 和 Cache-Control - max-age

`Expires`和`Cache-Control`头指定了浏览器可以在不检查更新版本的情况下使用缓存资源的时间段。如果设置了这些头部，直到到期日期或达到最大年龄为止，新资源将不会被获取。`Expires`头部接受一个日期，指定资源失效的时间。而`max-age`属性则指定资源在下载后的有效时间。

## 缓存控制头和指令

在**HTTP 1.1**中，`Cache-Control`头指定了资源的缓存行为以及资源可以被缓存的最大年龄。以下表格显示了`Cache-Control`头的不同指令：

| 指令 | 意义 |
| --- | --- |
| `private` | 当使用此指令时，浏览器可以缓存对象，但代理和内容交付网络不能 |
| `public` | 当使用此指令时，浏览器、代理和内容交付网络可以缓存对象 |
| `no-cache` | 当使用此指令时，对象将不被缓存 |
| `no-store` | 当使用此选项时，对象可以被缓存在内存中，但不应存储在磁盘上 |
| `max-age` | 表示资源有效的时间 |

以下是带有`Cache-Control HTTP/1.1`头的响应的示例：

```java
HTTP/1.1 200 OK Content-Type: application/json
Cache-Control: private, max-age=86400
Last-Modified: Thur, 01 Apr 2014 11:30 PST
```

前面的响应具有`Cache-Control`头，指令为`private`，`max-age`设置为 24 小时或 86400 秒。

一旦资源基于`max-age`或`Expires`头无效，客户端可以再次请求资源或发送条件`GET`请求，只有在资源发生更改时才获取资源。这可以通过较弱的缓存头来实现：如下一节所示的`Last-Modified`和 ETag 头。

### Last-Modified 和 ETag

这些头使浏览器能够检查资源自上次`GET`请求以来是否发生了更改。在`Last-Modified`头中，有一个与资源修改相关的日期。在 ETag 头中，可以有任何唯一标识资源的值（如哈希）。然而，这些头允许浏览器通过发出条件`GET`请求有效地更新其缓存资源。条件`GET`请求只有在服务器上的资源发生更改时才会返回完整的响应。这确保条件`GET`请求的延迟低于完整的`GET`请求。

## Cache-Control 头和 REST API

以下代码显示了如何向 JAX-RS 响应添加`Cache-Control`头。该示例可作为本书可下载源代码包的一部分。

```java
@Path("v1/coffees")
public class CoffeesResource {

    @GET
    @Path("{order}")
    @Produces(MediaType.APPLICATION_XML)
    @NotNull(message = "Coffee does not exist for the order id requested")
    public Response getCoffee(@PathParam("order") int order) {
        Coffee coffee = CoffeeService.getCoffee(order);
        CacheControl cacheControl = new CacheControl();
        cacheControl.setMaxAge(3600);
        cacheControl.setPrivate(true);
        Response.ResponseBuilder responseBuilder = Response.ok(coffee);
        responseBuilder.cacheControl(cacheControl);
        return responseBuilder.build();

    }
```

JAX-RS 有一个`javax.ws.rs.core.Cache-Control`类，它是`HTTP/1.1 Cache-Control`头的抽象。`cacheControl`对象上的`setMaxAge()`方法对应于`max-age`指令，`setPrivate(true)`对应于`private`指令。响应是使用`responseBuilder.build()`方法构建的。`cacheControl`对象被添加到`getCoffee()`方法返回的`Response`对象中。

以下是此应用程序生成的带有头的响应：

```java
curl -i http://localhost:8080/caching/v1/coffees/1
HTTP/1.1 200 OK
X-Powered-By: Servlet/3.1 JSP/2.3 (GlassFish Server Open Source Edition  4.0  Java/Oracle Corporation/1.7)
Server: GlassFish Server Open Source Edition  4.0 
Cache-Control: private, no-transform, max-age=3600
Content-Type: application/xml
Date: Thu, 03 Apr 2014 06:07:14 GMT
Content-Length: 143

<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<coffee>
<name>Mocha</name>
<order>1</order>
<size>Small</size>
<type>Chocolate</type>
</coffee>
```

## ETags

HTTP 定义了一个强大的缓存机制，其中包括以下头部： 

+   `ETag`头

+   `If-Modified-Since`头

+   `304 Not Modified`响应代码

#### ETags 工作原理

以下部分深入介绍了 ETags 的一些基础知识。以下图表更好地展示了这一点：

![ETags 工作原理](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-ptn-best-prac/img/7963OS_04_01.jpg)

让我们来看看与 ETags 相关的每个过程：

1.  客户端向[`api.com/coffee/1234`](http://api.com/coffee/1234) REST 资源发送一个`GET`请求。

1.  服务器发送一个带有**ETag**值的**200 OK**，例如，"**123456789"**。

1.  过一段时间，客户端发送另一个带有`If-None-Match: "123456789"`头的`GET`请求到[api.com/coffee/1234](http://api.com/coffee/1234) REST 资源。

1.  服务器检查资源的 MD5 哈希是否未被修改，然后发送一个没有响应主体的`304 Not-Modified`响应。

如果资源已更改，将发送 200 OK 作为响应。此外，作为响应的一部分，服务器还发送了一个新的 ETag。

### ETag 头和 REST API

以下代码显示了如何向 JAX-RS 响应添加`ETag`头：

```java
    @GET
    @Path("/etag/{order}")
    @Produces(MediaType.APPLICATION_JSON)
    @NotNull(message = "Coffee does not exist for the order id requested")
    public Response getCoffeeWithEtag(@PathParam("order") int order,
                                      @Context Request request
    ) {
        Coffee coffee = CoffeeService.getCoffee(order);
        EntityTag et = new EntityTag(
 "123456789");
        Response.ResponseBuilder responseBuilder  = request.evaluatePreconditions(et);
        if (responseBuilder != null) {
            responseBuilder.build();
        }
        responseBuilder = Response.ok(coffee);
        return responseBuilder.tag(et).build();
```

在上述代码片段中，使用资源的哈希创建了`javax.ws.core.EntityTag`对象的实例，为简单起见，我们使用了"123456789"。

`request,evalautePreconditions` 方法检查 `EntityTag et` 对象的值。如果满足先决条件，它将返回一个带有 `200 OK` 的响应。

然后，`EntityTag` 对象 `et` 与响应一起发送，该响应由 `getCoffeeWithETag` 方法返回。有关更多详细信息，请参考书籍源代码包中提供的示例。

### ETags 的类型

强验证 ETag 匹配表示两个资源的内容是逐字节相同的，并且所有其他实体字段（例如 Content-Language）也没有更改。

弱验证 ETag 匹配仅表示两个资源在语义上是等价的，并且可以使用缓存的副本。

缓存有助于减少客户端发出的请求次数。它还有助于通过条件 `GET` 请求和 ETags、`IF-None-Match` 头和 `304-Not Modified` 响应来减少完整响应的数量，从而节省带宽和计算时间。

### 提示

在 HTTP 响应中指定 `Expires` 或 `Cache-Control max-age` 以及两者中的一个 `Last-Modified` 和 ETag 头是一个很好的做法。同时发送 `Expires` 和 `Cache-Control max-age` 是多余的。同样，发送 `Last-Modified` 和 ETag 也是多余的。

## Facebook REST API 和 ETags

Facebook 营销 API 支持 Graph API 上的 ETags。当消费者进行 Graph API 调用时，响应头包括一个 ETag，其值是在 API 调用返回的数据的哈希值。下次消费者进行相同的 API 调用时，他可以在请求头中包含从第一步保存的 ETag 值的 `If-None-Match` 请求头。如果数据没有更改，响应状态码将是 `304 - Not Modified`，并且不返回数据。

如果服务器端的数据自上次查询以来发生了变化，则数据将像往常一样返回，并附带一个新的 ETag。这个新的 ETag 值可以用于后续调用。有关更多详细信息，请查看 [`developers.facebook.com`](http://developers.facebook.com)。

### RESTEasy 和缓存

RESTEasy 是 JBoss 项目，提供各种框架来帮助构建 RESTful web 服务和 RESTful Java 应用程序。RESTEasy 可以在任何 servlet 容器中运行，但与 JBoss 应用服务器有更紧密的集成。

RESTEasy 提供了一个 JAX-RS 的扩展，允许在成功的 `GET` 请求上自动设置 `Cache-Control` 头。

它还提供了一个服务器端的本地内存缓存，可以位于 JAX-RS 服务的前面。如果 JAX-RS 资源方法设置了 `Cache-Control` 头，则它会自动缓存来自 HTTP GET JAX-RS 调用的编组响应。

当 `HTTP GET` 请求到达时，RESTEasy 服务器缓存将检查 URI 是否存储在缓存中。如果是，则返回已经编组的响应，而不调用 JAX-RS 方法。

有关更多信息，请查看 [`www.jboss.org/resteasy`](http://www.jboss.org/resteasy)。

### 提示

**在服务器端进行缓存时的提示**

对于 `PUT` 或 `POST` 请求，使缓存条目无效。不要缓存具有查询参数的请求，因为一旦查询参数值发生变化，来自服务器的缓存响应可能无效。

# REST 中的异步和长时间运行的作业

在开发 RESTful API 中的一个常见模式是处理异步和长时间运行的作业。API 开发人员需要创建可能需要相当长时间的资源。他们不能让客户端等待 API 完成。

考虑在咖啡店订购咖啡。订单详细信息存储在队列中，当咖啡师有空时，他会处理您的订单。在那之前，您会收到一张收据确认您的订单，但实际的咖啡稍后到达。

异步资源处理遵循相同的原则。异步资源意味着资源不能立即创建。也许它将被放置在一个处理资源实际创建的任务/消息队列中，或者类似的东西。

考虑以下在我们示例中订购一杯小咖啡的请求：

```java
POST v1/coffees/order HTTP 1.1 with body
<coffee>
  <size> SMALL</coffee>
  <name>EXPRESSO</name>
  <price>3.50</price>
<coffee>
```

响应可以发送回以下内容：

```java
HTTP/1.1 202 Accepted
Location: /order/12345
```

响应发送一个`202 Accepted`头。`Location`头可以提供有关咖啡资源的详细信息。

## 异步请求和响应处理

异步处理包含在 JAX-RS 2.0 的客户端和服务器端 API 中，以促进客户端和服务器组件之间的异步交互。以下列表显示了添加到服务器端和客户端的新接口和类，以支持此功能：

+   服务器端：

+   `AsyncResponse`：这是一个可注入的 JAX-RS 异步响应，提供了异步服务器端响应处理的手段

+   `@Suspended`：`@Suspended`注解指示容器应在辅助线程中进行 HTTP 请求处理

+   `CompletionCallback`：这是一个接收请求处理完成事件的请求处理回调

+   `ConnectionCallback`：这是一个接收与连接相关的异步响应生命周期事件的异步请求处理生命周期回调

+   客户端端：

+   `InvocationCallback`：这是一个可以实现的回调，用于接收调用处理的异步处理事件

+   `Future`：这允许客户端轮询异步操作的完成情况，或者阻塞并等待它

### 注意

Java SE 5 中引入的`Future`接口提供了两种不同的机制来获取异步操作的结果：首先是通过调用`Future.get(…)`变体来阻塞直到结果可用或超时发生，第二种方式是通过调用`isDone()`和`isCancelled()`来检查完成情况，这些是返回`Future`当前状态的布尔方法。有关更多详细信息，请查看[`docs.oracle.com/javase/1.5.0/docs/api/java/util/concurrent/Future.html`](http://docs.oracle.com/javase/1.5.0/docs/api/java/util/concurrent/Future.html)。

以下图表显示了 JAX-RS 中的异步请求/响应处理：

![异步请求和响应处理](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/rst-java-ptn-best-prac/img/7963OS_04_02.jpg)

客户端发出对`CoffeeResource`上异步方法的请求。`CoffeeResource`类创建一个新线程，可以进行一些密集的操作，然后发送响应。同时，请求线程被释放，可以处理其他请求。当处理操作的线程完成处理时，将响应返回给客户端。

以下示例代码显示了如何使用 JAX-RS 2.0 API 开发异步资源：

```java
@Path("/coffees")
@Stateless
public class CoffeeResource {   
  @Context private ExecutionContext ctx;
  @GET @Produce("application/json")
  @Asynchronous
  public void order() {
        Executors.newSingleThreadExecutor().submit( new Runnable() {
         public void run() { 
              Thread.sleep(10000);     
              ctx.resume("Hello async world! Coffee Order is 1234");
          } });
ctx.suspend();
return;
  }
}
```

`CoffeesResource`类是一个无状态会话 bean，其中有一个名为`order()`的方法。该方法带有`@Asynchronous`注解，将以“发出并忘记”的方式工作。当客户端通过`order()`方法的资源路径请求资源时，会生成一个新线程来处理准备请求的响应。线程被提交给执行程序执行，处理客户端请求的线程被释放（通过`ctx.suspend`）以处理其他传入的请求。

当为准备响应创建的工作线程完成准备响应时，它调用`ctx.resume`方法，让容器知道响应已准备好发送回客户端。如果在`ctx.suspend`方法之前调用了`ctx.resume`方法（工作线程在执行到达`ctx.suspend`方法之前已准备好结果），则会忽略暂停，并且结果将发送到客户端。

可以使用以下代码片段中显示的`@Suspended`注解来实现相同的功能：

```java
@Path("/coffees")
@Stateless
public class CoffeeResource {
@GET @Produce("application/json")
@Asynchronous
  public void order(@Suspended AsyncResponse ar) {
    final String result = prepareResponse();
    ar.resume(result)
  }
}
```

使用`@Suspended`注解更清晰，因为这不涉及使用`ExecutionContext`变量来指示容器在工作线程完成时暂停然后恢复通信线程，即在这种情况下的`prepareResponse()`方法。消耗异步资源的客户端代码可以使用回调机制或在代码级别进行轮询。以下代码显示了如何通过`Future`接口进行轮询：

```java
Future<Coffee> future = client.target("/coffees")
               .request()
               .async()
               .get(Coffee.class);
try {
   Coffee coffee = future.get(30, TimeUnit.SECONDS);
} catch (TimeoutException ex) {
  System.err.println("Timeout occurred");
}
```

代码从形成对`Coffee`资源的请求开始。它使用`javax.ws.rs.client.Client`实例调用`target()`方法，该方法为`Coffee`资源创建一个`javax.ws.rs.client.WebTarget`实例。`Future.get(…)`方法会阻塞，直到从服务器收到响应或达到 30 秒的超时时间。

另一个用于异步客户端的 API 是使用`javax.ws.rs.client.InvocationCallback`实例，这是一个可以实现以获取调用的异步事件的回调。有关更多详细信息，请查看[`jax-rs-spec.java.net/nonav/2.0/apidocs/javax/ws/rs/client/InvocationCallback.html`](https://jax-rs-spec.java.net/nonav/2.0/apidocs/javax/ws/rs/ client/InvocationCallback.html)。

# 异步资源最佳实践

下一节列出了在处理异步 RESTful 资源时的最佳实践。

## 发送 202 Accepted 消息

对于异步请求/响应，API 应该返回一个`202 Accepted`消息，以表明请求是有效的，资源可能在时间上是可用的，即使只有几秒钟。`202 Accepted`表示请求已被接受处理，资源将很快可用。`202 Accepted`消息应指定`Location`头，客户端可以使用它来知道资源创建后将在哪里可用。如果响应不立即可用，API 不应返回`201 Created`消息。

## 设置队列中对象的过期时间

API 开发人员应该在队列中的一定时间后使对象过期。这样可以确保队列对象不会随着时间的推移而积累，并且会定期清除。

## 使用消息队列来处理任务异步

API 开发人员应考虑使用消息队列来进行异步操作，以便消息被放置在队列中，直到接收者接收到它们。**高级消息队列协议**（**AMQP**）是一种标准，它能够可靠和安全地路由、排队、发布和订阅消息。有关更多详细信息，请查看[`en.wikipedia.org/wiki/Advanced_Message_Queuing_Protocol`](http://en.wikipedia.org/wiki/Advanced_Message_Queuing_Protocol)上的高级消息队列协议。

例如，当调用异步资源方法时，使用消息队列发送消息，并根据消息和事件异步处理不同的任务。

在我们的示例中，如果下订单咖啡，可以使用 RabbitMQ（[`www.rabbitmq.com/`](http://www.rabbitmq.com/)）发送消息来触发`COMPLETED`事件。订单完成后，详细信息可以移至库存系统。

下一节涵盖了 RESTful 服务的另一个重要细节，即进行部分更新。

# HTTP PATCH 和部分更新

API 开发人员常见的问题是实现部分更新。当客户端发送一个请求，必须改变资源状态的一部分时，就会出现这种情况。例如，想象一下，有一个 JSON 表示您的`Coffee`资源的代码片段如下所示：

```java
{
 "id": 1,
 "name": "Mocha"
 "size": "Small",
 "type": "Latte",
 "status":"PROCESSING"
}
```

一旦订单完成，状态需要从`"PROCESSING"`更改为`"COMPLETED"`。

在 RPC 风格的 API 中，可以通过添加以下方法来处理这个问题：

```java
GET myservice/rpc/coffeeOrder/setOrderStatus?completed=true&coffeeId=1234
```

在 REST 情况下使用`PUT`方法，需要发送所有这样的数据，这将浪费带宽和内存。

```java
PUT /coffee/orders/1234
{
 "id": 1,
 "name": "Mocha"
 "size": "Small", 
 "type": "Latte", 
 "status": "COMPLETED"
}
```

为了避免在进行小的更新时发送整个数据，另一个解决方案是使用`PATCH`进行部分更新：

```java
PATCH /coffee/orders/1234
{
"status": "COMPLETED"
}
```

然而，并非所有的 Web 服务器和客户端都会提供对`PATCH`的支持，因此人们一直在支持使用`POST`和`PUT`进行部分更新：

```java
POST /coffee/orders/1234
{
"status": "COMPLETED"
}
```

使用`PUT`进行部分更新：

```java
PUT /coffee/orders/1234
{
"status": "COMPLETED"
}
```

总之，使用`PUT`或`POST`进行部分更新都是可以接受的。Facebook API 使用`POST`来更新部分资源。使用部分`PUT`将更符合我们实现 RESTful 资源和方法的方式，作为 CRUD 操作。

要实现对`PATCH`方法的支持，可以在 JAX-RS 中添加注释：

```java
  @Target({ElementType.METHOD})@Retention(RetentionPolicy.RUNTIME)@HttpMethod("PATCH")public @interface PATCH {}
```

上面的片段显示了如何将`javax.ws.rs.HTTPMethod`的注释与名称“`PATCH`”相关联。一旦创建了这个注释，那么`@PATCH`注释就可以用于任何 JAX-RS 资源方法。

# JSON Patch

JSON Patch 是 RFC 6902 的一部分。它是一个旨在允许对 JSON 文档执行操作的标准。JSON Patch 可以与`HTTP PATCH`方法一起使用。它对于提供 JSON 文档的部分更新非常有用。媒体类型`"application/json-patch+json"`用于识别此类补丁文档。

它包括以下成员：

+   `op`：这标识要在文档上执行的操作。可接受的值为`"add"`、`"replace"`、`"move"`、`"remove"`、`"copy"`或`"test"`。任何其他值都是错误的。

+   `path`：这是表示 JSON 文档中位置的 JSON 指针。

+   `value`：这表示要在 JSON 文档中替换的值。

`move`操作需要一个`"from"`成员，用于标识要从中移动值的目标文档中的位置。

这是一个 JSON Patch 文档的示例，发送在`HTTP PATCH`请求中：

```java
PATCH /coffee/orders/1234 HTTP/1.1
Host: api.foo.com
Content-Length: 100
Content-Type: application/json-patch

[
  {"op":"replace", "path": "/status", "value": "COMPLETED"}
]
```

上述请求显示了如何使用 JSON Patch 来替换由资源`coffee/orders/1234`标识的咖啡订单的状态。操作，即上面片段中的`"op"`，是`"replace"`，它将值`"COMPLETED"`设置为 JSON 表示中状态对象的值。

JSON Patch 对于单页应用程序、实时协作、离线数据更改非常有用，也可以用于需要在大型文档中进行小型更新的应用程序。有关更多详细信息，请查看[`jsonpatchjs.com/`](http://jsonpatchjs.com/)，这是`JSON Patch.(RFC 6902)`和`JSON Pointer.(RFC 6901)`的实现，采用 MIT 许可证。

# 推荐阅读

以下部分列出了与本章涵盖的主题相关的一些在线资源，可能对复习有用：

+   RESTEasy: [`resteasy.jboss.org/`](http://resteasy.jboss.org/)

+   Couchbase: [`www.couchbase.com/`](http://www.couchbase.com/)

+   Facebook Graph API Explorer: [`developers.facebook.com/`](https://developers.facebook.com/)

+   RabbitMQ: [`www.rabbitmq.com/`](https://www.rabbitmq.com/)

+   JSON Patch RFC 6902: [`tools.ietf.org/html/rfc6902`](http://tools.ietf.org/html/rfc6902)

+   JSON Pointer RFC 6901: [`tools.ietf.org/html/rfc6901`](http://tools.ietf.org/html/rfc6901)

# 摘要

本章涵盖了缓存的基本概念，演示了不同的 HTTP 缓存头，如`Cache-Control`，`Expires`等。我们还看到了头部是如何工作的，以及 ETags 和`Last-Modified`头部如何用于条件`GET`请求以提高性能。我们介绍了缓存的最佳实践，RESTEasy 如何支持服务器端缓存，以及 Facebook API 如何使用 ETags。本章讨论了异步 RESTful 资源以及在使用异步 API 时的最佳实践。我们介绍了 HTTP Patch 和 JSON Patch（RFC 6902）以及部分更新。

下一章将涉及每个构建 RESTful 服务的开发人员都应该了解的高级主题，涉及常用模式和最佳实践，如速率限制、响应分页和 REST 资源的国际化。它还将涵盖其他主题，如 HATEOAS、REST 及其可扩展性。
