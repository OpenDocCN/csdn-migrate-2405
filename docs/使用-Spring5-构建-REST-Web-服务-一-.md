# 使用 Spring5 构建 REST Web 服务（一）

> 原文：[`zh.annas-archive.org/md5/5A57DB9C3C86080E5A1093BAC90B467A`](https://zh.annas-archive.org/md5/5A57DB9C3C86080E5A1093BAC90B467A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

REST 是一种解决构建可扩展 Web 服务挑战的架构风格。在当今互联的世界中，API 在 Web 上扮演着核心角色。API 提供了系统相互交互的框架，而 REST 已经成为 API 的代名词。Spring 的深度、广度和易用性使其成为 Java 生态系统中最具吸引力的框架之一。因此，将这两种技术结合起来是非常自然的选择。

从 REST 背后的哲学基础开始，本书介绍了设计和实现企业级 RESTful Web 服务所需的必要步骤。采用实用的方法，每一章都提供了您可以应用到自己情况的代码示例。这第二版展示了最新的 Spring 5.0 版本的强大功能，使用内置的 MVC，以及前端框架。您将学习如何处理 Spring 中的安全性，并发现如何实现单元测试和集成测试策略。

最后，本书通过指导您构建一个用于 RESTful Web 服务的 Java 客户端，以及使用新的 Spring Reactive 库进行一些扩展技术，来结束。

# 这本书适合谁

本书适用于那些想要学习如何使用最新的 Spring Framework 5.0 构建 RESTful Web 服务的人。为了充分利用本书中包含的代码示例，您应该具备基本的 Java 语言知识。有 Spring Framework 的先前经验也将帮助您快速上手。

# 为了充分利用这本书

以下是测试本书中所有代码所需的要求的描述性列表：

+   硬件：64 位机器，至少 2GB RAM 和至少 5GB 的可用硬盘空间

+   软件：Java 9，Maven 3.3.9，STS（Spring Tool Suite）3.9.2

+   Java 9：所有代码都在 Java 9 上测试

+   SoapUI：REST API 调用使用 SoapUI 5.2.1（免费版本）

+   Postman：用于 REST 客户端测试，使用 Postman 5.0.4

# 下载示例代码文件

您可以从您的帐户在[www.packtpub.com](http://www.packtpub.com)下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

一旦文件下载完成，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Building-RESTful-Web-Services-with-Spring-5-Second-Edition`](https://github.com/PacktPublishing/Building-RESTful-Web-Services-with-Spring-5-Second-Edition)。我们还有其他代码包，来自我们丰富的书籍和视频目录，可以在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。快去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/BuildingRESTfulWebServiceswithSpring5_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/BuildingRESTfulWebServiceswithSpring5_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：指示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“让我们向类中添加一个`Logger`；在我们的情况下，我们可以使用`UserController`。”

代码块设置如下：

```java
@ResponseBody
  @RequestMapping("/test/aop/with/annotation")
  @TokenRequired
  public Map<String, Object> testAOPAnnotation(){
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("result", "Aloha");   
    return map;
  }
```

当我们希望引起你对代码块的特定部分的注意时，相关的行或项目会以粗体显示：

```java
2018-01-15 16:29:55.951 INFO 17812 --- [nio-8080-exec-1] com.packtpub.restapp.HomeController : {test} info
2018-01-15 16:29:55.951 WARN 17812 --- [nio-8080-exec-1] com.packtpub.restapp.HomeController : {test} warn 
2018-01-15 16:29:55.951 ERROR 17812 --- [nio-8080-exec-1] com.packtpub.restapp.HomeController : {test} error
```

任何命令行输入或输出都以以下方式书写：

```java
mvn dependency:tree
```

**粗体**：表示一个新术语，一个重要的词，或者你在屏幕上看到的词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“现在你可以通过点击生成项目来生成项目。”

警告或重要提示会显示为这样。

提示和技巧会显示为这样。


# 第一章：一些基础知识

随着世界进入大数据时代，收集和处理数据成为大多数 Web 应用程序的主要部分，Web 服务也是如此，因为 Web 服务只处理数据，而不处理用户体验、外观和感觉的其他部分。尽管用户体验对所有 Web 应用程序都非常重要，但 Web 服务通过从客户端消费服务在处理数据方面起着重要作用。

在 Web 服务的早期，**简单对象访问协议**（**SOAP**）是所有后端开发人员的默认选择，他们处理 Web 服务消费。SOAP 主要用于 HTTP 和**简单邮件传输协议**（**SMTP**）在相同或不同平台上进行消息传输。当没有**JavaScript 对象表示**（**JSON**）格式可用于 Web 服务时，XML 曾是 SOAP 可用于 Web 服务消费的唯一格式。

然而，在 JSON 时代，**表述性状态转移**（**REST**）开始主导基于 Web 服务的应用程序，因为它支持多种格式，包括 JSON、XML 和其他格式。REST 比 SOAP 更简单，REST 标准易于实现和消费。此外，与 SOAP 相比，REST 更轻量级。

在本章中，我们将涵盖以下主题：

+   REST——基本理解

+   响应式编程及其基础知识，包括响应式编程的好处

+   使用响应式编程的 Spring 5 基础知识

+   将用作本书其余部分基础的示例 RESTful Web 服务

# REST——基本理解

与流行观念相反，REST 不是一种协议，而是一种管理状态信息的架构原则。它主要用于 Web 应用程序。REST 是由 Roy Fielding 引入的，以克服 SOAP 中的实现困难。Roy 的博士论文为检索数据提供了一种简单的方法，而不管使用的平台是什么。您将在以下部分中看到 RESTful Web 服务的所有组件。

# 统一接口

在 REST 原则中，所有资源都由**统一资源标识符**（**URI**）标识。

HTTP REST 资源以 XML、JSON 和 RDF 等媒体类型表示。此外，RESTful 资源是自描述的，这意味着提供了足够的信息来描述如何处理请求。

在另一个 REST 原则中，客户端通过服务器动态提供的超媒体进行交互。除了端点，客户端不需要知道如何与 RESTful 服务进行交互。这个原则被称为**超媒体作为应用状态的引擎**（**HATEOAS**）。

# 客户端和服务器

通过分离 REST 实体，如客户端和服务器，我们可以减少 REST 原则的复杂性，这将显示服务器和客户端之间的明确边界。这种解耦将有助于开发人员独立地专注于客户端和服务器。此外，它将有助于管理客户端和服务器的不同角色。

# 无状态

在 REST 原则中，服务器不会在服务器端保留有关客户端会话的任何状态；因此，它是无状态的。如果从单个客户端向服务器发出两个调用，服务器将不会识别这两个调用是否来自同一个客户端。就服务器而言，每个请求都是独立的和新的。根据 URL、HTTP 标头和请求体，包括参数，操作可能会在服务器端发生变化。

# 可缓存的

使用 RESTful Web 服务，客户端可以缓存来自服务器的任何响应。服务器可以说明如何以及多长时间可以缓存响应。通过缓存选项，客户端可以使用响应而不是再次联系服务器。此外，缓存将通过避免客户端-服务器交互来提高可伸缩性和性能。

这个原则对可扩展性有显著的优势。缓存技术将在第八章 *性能*中讨论。

由于 REST 通常利用 HTTP，它继承了 HTTP 提供的所有缓存属性。

# 分层系统

通过提供分层系统，服务器可以隐藏其身份。通过这样做，客户端将不知道他们正在处理哪个服务器。这个策略通过提供中间服务器和支持负载平衡功能来提供更多的安全控制。此外，中间服务器可以通过负载平衡和共享缓存来提高可扩展性和性能。

# 按需代码（COD）

**按需代码**（**COD**）被认为是一个可选的原则。服务器可以通过传输可执行代码来扩展客户端的功能。例如，可以向基于 Web 的客户端提供 JavaScript 以自定义功能。由于按需代码减少了客户端的可见性，这个约束是可选的。也不是所有的 API 都需要这个功能。

# 更多关于 REST 的内容

在 Web 应用程序中，REST 通常是通过 HTTP 使用的。REST 不需要绑定到任何特定的协议。在 HTTP REST 中，我们主要使用`GET`、`POST`、`PUT`和`DELETE`方法来改变我们访问的资源的状态。其他 HTTP 方法，如`OPTIONS`、`HEAD`、`CONNECT`和`TRACE`，可以用于更高级的操作，例如用于缓存和调试目的。大多数服务器出于安全和简单性的原因已禁用了高级方法；但是，您可以通过调整服务器配置文件来启用它们。由于 JSON 被用作主要的媒体类型，我们在 Web 服务调用中也只使用 JSON 媒体类型。

# 命令式和响应式编程

让我们来看一下命令式编程和响应式编程之间的小比较：*x = y + z*。

在前面的表达式中，假设*y = 10*和*z = 15*。在这种情况下，*x*的值将是*25*。在表达式*x = y + z*的时候，*x*的值将被分配。在这个表达式之后，*x*的值将永远不会改变。

在传统编程世界中这是完全可以的。然而，我们可能需要一个场景，在这个场景中我们应该能够在改变*y*或*z*的值时跟进*x*。

我们的新场景基于以下值：

+   当*y = 20*和*z = 15*时，*x = 35*

+   当*y = 20*和*z = 25*时，*x = 45*

在日常编程中，我们通常使用的命令式编程中不可能出现上述情景。但在某些情况下，我们可能需要根据*y*或*z*的变化更新*x*的值。Reactive 编程是这种情况的完美解决方案。在 Reactive 编程中，*x*的值将会自动更新，以响应*y*或*z*的变化。

电子表格引用单元格是 Reactive 编程的最佳例子。如果一个单元格的值改变，被引用的单元格的值将自动更新。另一个例子可以在模型-视图-控制器架构中找到，Reactive 编程可以自动更新与模型相关联的视图。

Reactive 编程遵循观察者模式来操作和转换数据流，其中发布者（可观察者）根据订阅者的需求发出项目。当发布者发出项目时，订阅者从发布者那里消耗这些发出的项目。与迭代器拉取项目不同，在这里，发布者将项目推送给订阅者。

由于 Reactive 是非阻塞架构的一部分，当我们扩展应用程序时它将会很有用。此外，在非阻塞架构中，一切都被视为事件流。

我们将在本章后面讨论有关 Java 和 Spring 中的 Reactive 的更多内容。

# Reactive Streams

Reactive Streams 主要是处理异步数据流的数据项，应用程序在接收到数据项时对其做出反应。这种模型更节省内存，因为它不依赖于任何内存中的数据。

响应式流有四个主要组件：

1.  发布者。

1.  订阅者。

1.  订阅。

1.  处理器。

发布者发布数据流，订阅者异步订阅该数据流。处理器在不需要改变发布者或订阅者的情况下转换数据流。处理器（或多个处理器）位于发布者和订阅者之间，将一个数据流转换为另一个数据流。

# 响应式编程的好处

Netflix、Pivotal、Twitter、Oracle 和 TypeSafe 的工程师支持响应式流方法。特别是 TypeSafe 对响应式流做出了更多贡献。甚至 Netflix 工程师用他们自己的话说：

“使用 RxJava 进行响应式编程使 Netflix 开发人员能够利用服务器端并发，而无需担心典型的线程安全和同步问题。”

以下是响应式编程的好处：

+   专注于业务逻辑

+   流处理导致内存效率

+   克服低级线程、同步和并发问题

响应式原则在实时案例中得到应用，例如实时数据库查询、大数据、实时分析、HTTP/2 等。

# Java 和 Spring 5 中的响应式编程

Netflix 工程师引入了 RxJava，以支持 Java 8 中的响应式模型，并与 Reactive Streams 进行了桥接。然而，Java 从 Java 9 开始支持响应式模型，并且在 Java 9 中将 Reactive Streams 合并到了 JDK 中的`java.util.concurrent.Flow`中。

此外，Pivotal 推出了 Reactor 框架，该框架直接构建在 Reactive Streams 上，避免了对 Reactive Streams 的外部桥接。Reactor 被认为是第四代库。

最后，Spring Framework 5.0 添加了内置的响应式功能，包括用于 HTTP 服务器和客户端的工具。Spring 用户在处理 HTTP 请求时，特别是将响应式请求和背压问题分派给框架时，会发现注解和控制器非常方便。

响应式模型似乎在资源利用效率上是高效的，因为它可以使用更少的线程处理更高的负载。然而，响应式模型可能并不是所有问题的正确解决方案。在某些情况下，如果我们在错误的部分使用 Reactor，它可能会使情况变得更糟。

# 我们的 RESTful Web 服务架构

由于我们假设读者熟悉 Spring Framework，我们将直接关注我们将要构建的示例服务。

在本书中，我们将构建一个**工单管理系统**。为了清晰地描述工单管理系统及其使用方式，我们将提出一个场景。

假设我们有一个银行网站应用，由我们的客户 Peter 和 Kevin 使用，我们有 Sammy，我们的管理员，以及 Chloe，**客户服务代表**（CSR），在任何银行应用问题的情况下提供帮助。

如果 Kevin/Peter 在 Web 应用中遇到问题，他们可以在我们的工单管理系统中创建一个工单。这个工单将由管理员处理，并发送给处理工单的 CSR。

CSR 从用户那里获取更多信息，并将信息转发给技术团队。一旦 CSR 解决了问题，他们就可以关闭问题。

在我们的工单管理系统中，我们将使用以下组件：

| **工单** |
| --- |

+   `工单 ID`

+   `创建者 ID`

+   `创建时间`

+   `内容`

+   `严重程度`（轻微，正常，重要，严重）

+   `状态`（打开，进行中，已解决，重新打开）

|

| **用户** |
| --- |

+   `用户 ID`

+   `用户名`

+   `用户类型`（管理员，普通用户，CSR）

|

在这个工单管理系统中，我们将专注于：

1.  用户创建一个工单。

1.  用户更新工单。

1.  管理员更新工单状态。

1.  CSR 更新工单状态。

1.  用户和管理员删除工单。

在初始章节中，当我们涉及诸如 AOP、Spring Security 和 WebFlux 等主题时，我们将讨论用户管理，以保持业务逻辑的简单性。然而，在第十三章中，*票务管理-高级 CRUD*，我们将讨论票务管理系统，并实现我们之前提到的所有业务需求。在第十三章中，*票务管理-高级 CRUD*，您将使用其他章节中使用的所有高级技术来完成我们的业务需求。

# 总结

到目前为止，我们已经了解了 REST 和响应式编程的基础知识，以及响应式流的必要性。我们已经学习了带有 Reactor 支持的 Spring 5。此外，我们已经定义了本书其余部分将使用的业务示例和架构。

在下一章中，我们将讨论使用 Maven 进行简单项目创建以及简单的 REST API。此外，我们将讨论 Maven 文件结构和依赖项，包括示例。


# 第二章：使用 Maven 在 Spring 5 中构建 RESTful Web 服务

在本章中，我们将构建一个简单的 REST Web 服务，返回`Aloha`。在进行实现之前，我们将专注于创建 RESTful Web 服务所涉及的组件。在本章中，我们将涵盖以下主题：

+   使用 Apache Maven 构建 RESTful Web 服务

+   使用 Eclipse IDE 或 STS 进行 Spring REST 项目

+   在 Eclipse/STS 中创建一个新项目

+   运行和测试我们的 REST API

# Apache Maven

在构建 Jakarta Turbine 项目时，工程师们发现管理 Ant 构建工具很困难。他们需要一个简单的工具来构建具有清晰定义且易于理解的项目。他们的尝试塑造了 Apache Maven，并且 JAR 可以在中心位置跨多个项目共享。

有关 Maven 的更多信息可以在[`maven.apache.org`](https://maven.apache.org)找到。

Apache Maven 是为了支持 Java 项目和构建管理而创建的。此外，它的简化定义使 Java 开发人员在构建和部署 Java 项目时更加轻松。

在撰写本书时，Apache Maven 的最新版本是 3.5.0，可以从他们的网站下载：[`maven.apache.org/download.cgi`](https://maven.apache.org/download.cgi)。

Maven 3.3+需要 JDK 1.7 或更高版本。因此，请确保在使用 Maven 3.3 时检查您的 Java 版本。

您可以从上述链接获取二进制或源 ZIP 文件（或者您的操作系统所需的任何格式），并将 Maven 安装到您的计算机上。

可以通过在控制台/命令提示符中输入`mvn --version`命令来验证 Maven 的安装。如果安装成功，它将显示以下细节（仅适用于 Windows 操作系统）：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/51a26efb-2c2f-4b4a-bb44-8f65723646c4.png)

为了清晰起见，以下图片显示了在 Ubuntu 上执行的 Maven 版本检查：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/3c8368cf-d7f7-4308-8453-863ffa94a82b.png)

# 使用 Maven 创建项目

安装和验证 Maven 后，您将需要使用 Maven 创建一个项目。这可以在命令提示符中完成。只需在所需位置运行以下命令，然后项目将自动创建：

```java
mvn archetype:generate -DgroupId=com.packtpub.restapp -DartifactId=ticket-management -DarchetypeArtifactId=maven-archetype-quickstart -DinteractiveMode=false -Dversion=1.0.0-SNAPSHOT
```

如果在创建项目时遇到任何问题，请在 Maven 中使用`-X`选项，如下所示。它将指出发生错误的位置：

```java
mvn –X archetype:generate -DgroupId=com.packtpub.restapp -DartifactId=ticket-management -DarchetypeArtifactId=maven-archetype-quickstart -DinteractiveMode=false -Dversion=1.0.0-SNAPSHOT
```

在以下几点中，我们将逐个讨论用于创建 Maven 项目的命令的每个部分：

+   `archetype:generate`：如果目标是在指定的原型上创建一个新项目，可以使用这个命令，例如`maven-archetype-quickstart`。

+   `-Dgroupid=com.packtpub.restapp`：这部分定义了一个带有组标识符的项目，例如一个包。

+   `-DartifcatId=ticket-management`：这部分定义了我们的项目名称（文件夹）。

+   `-DarchetypeArtifactId=maven-archetype-quickstart`：这部分将用于在`archetype:generate`目标上选择原型。

+   `-Dversion=1.0.0-SNAPSHOT`：项目版本可以在这部分中提及。在部署和分发项目时会很有帮助。

# 在创建项目后查看 POM 文件

创建项目后，我们可以在项目文件夹中看到`pom.xml`文件。它将包含所有基本细节，例如`groupId`，`name`等。此外，您可以在`dependencies`配置部分下看到默认的`Junit`依赖项：

```java
<project  
xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.packtpub.restapp</groupId>
  <artifactId>ticket-management</artifactId>
  <packaging>jar</packaging>
  <version>1.0-SNAPSHOT</version>
  <name>ticket-management</name>
  <url>http://maven.apache.org</url>
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>3.8.1</version>
      <scope>test</scope>
    </dependency>
  </dependencies> 
</project>
```

Maven 构件属于一个组（通常是`com.organization.product`），必须有一个唯一的标识符。

在上述 POM 文件中，`version`中的`SNAPSHOT`后缀告诉 Maven 这个项目仍在开发中。

# POM 文件结构

在这里，我们将检查**项目对象模型**（**POM**）文件结构，看看它是如何组织的，`pom.xml`文件中有哪些部分可用。POM 文件可以有`properties`，`dependencies`，`build`和`profiles`。然而，这些部分对于不同的项目会有所不同。在其他项目中，我们可能不需要其中的一些部分：

```java
<project>
  // basic project info comes here  
  <properties>
    // local project based properties can be stored here 
  <properties>  
  <dependencies>
    // all third party dependencies come here
  </dependencies>
  <build>
    <plugins>
      // build plugin and compiler arguments come here
    </plugins>
  </build>
  <profiles>
    All profiles like staging, production come here
  </profiles> 
</project>
```

# 理解 POM 依赖关系

Maven 帮助管理你操作系统中的第三方库。在过去，你可能不得不手动将每个第三方库复制到你的项目中。当你有多个项目时，这可能是一个大问题。Maven 通过将所有库保存在每个操作系统的一个中央位置来避免这种第三方库管理混乱。无论你的项目数量如何，第三方库都只会下载到系统一次。

Maven 仓库可以在[`mvnrepository.com/`](https://mvnrepository.com/)找到。

每个操作系统都有自己的本地 Maven 仓库位置：

+   Windows Maven 中央仓库位置：

`C:\Users\<username>\.m2\repository\`

+   Linux Maven 中央仓库位置：

`/home/<username>/.m2/repository`

+   MAC Maven 中央仓库位置：

`/Users/<username>/.m2/repository`

每当你向你的 POM 依赖项中添加第三方库时，指定的 JAR 和相关文件将被复制到`\.m2\repository`的位置。

我们将通过查看一个示例来了解 Maven 依赖结构。假设我们需要在我们的应用程序中使用 Log4j 版本 2.9.1。为了使用它，我们需要将依赖项添加到我们的项目中。我们可以从[`mvnrepository.com`](https://mvnrepository.com)搜索`log4j-core`依赖项，并将依赖项复制到我们的 POM 下的`dependencies`中。

一个示例的 Maven 依赖如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/25dd845e-90ef-497b-bcea-fca8e661adf2.png)

# 将 Log4j 2.9.1 添加到 POM 依赖项

一旦依赖项被添加并且项目在你的 IDE 上更新，相应的库将被复制到`\.m2\repository`中：

```java
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.9.1</version>
</dependency>
```

前面的依赖项`log4j-core`将被添加到 POM 下。在这个依赖项中，你可以看到`groupId`，`artifactId`和`version`的解释如下：

+   `groupId`用于使 JAR/WAR 文件在所有项目中保持唯一。由于它将被全局使用，Maven 建议包名遵循与域名和子组相同的规则。一个示例`groupId`是`com.google.appengine`。然而，一些第三方依赖项不遵循`groupId`包命名策略。检查以下示例：

```java
<dependency>
    <groupId>joda-time</groupId>
    <artifactId>joda-time</artifactId>
    <version>2.9.9</version>
</dependency>
```

+   `artifactId`只是 JAR/WAR 文件的名称，不带扩展名。

+   `version`带有数字来显示 JAR 文件的版本。一些 JAR 文件带有额外的信息，比如`RELEASE`，例如`3.1.4.RELEASE`。

以下代码将下载`spring-security-web`库`3.1.4`的 JAR 文件到仓库位置：

```java
<dependency>
  <groupId>org.springframework.security</groupId>
  <artifactId>spring-security-web</artifactId>
  <version>3.1.4.RELEASE</version>
</dependency>
```

`Log4j-core`文件（在 Windows 中）将显示如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/6885c0ed-5235-46c9-84e7-90a5a307da1c.png)

有时，当你在 IDE 上更新项目时，你可能会看到`.jar`文件丢失。在这种情况下，删除整个文件夹（在我们的例子中是`log4j-core`文件夹），然后再次更新它们。为了更新丢失的 JAR 文件，在你删除文件夹后，只需更新你的 IDE（在我们的例子中是 STS/Eclipse），右键单击项目，然后选择 Maven | 更新项目。最后，确保你在文件夹下有`.jar`文件可用。

`.m2\repository`中的示例仓库应该如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/daa56abc-3dd9-4bf6-9d32-7ef734d980e2.png)

当你更新一个项目（在 Eclipse 或任何其他 IDE 中），它将从远程 Maven 仓库获取 JAR 和相关文件到你系统的中央仓库。

# 依赖树

依赖树可以用于项目中定位特定的依赖项。如果你想了解任何特定的库，比如为什么使用它，你可以通过执行依赖树来检查。此外，依赖树可以展开以显示依赖冲突。

以下代码显示了依赖库以及它们的组织方式：

```java
mvn dependency:tree
```

通过在项目文件夹（或者`pom.xml`文件可用的任何地方）上执行命令，你可以查看依赖树，其结构如下：

```java
[INFO] --- maven-dependency-plugin:2.8:tree (default-cli) @ ticket-management ---
[INFO] com.packtpub.restapp:ticket-management:jar:0.0.1-SNAPSHOT
[INFO] +- org.springframework:spring-web:jar:5.0.0.RELEASE:compile
[INFO] | +- org.springframework:spring-beans:jar:5.0.0.RELEASE:compile
[INFO] | \- org.springframework:spring-core:jar:5.0.0.RELEASE:compile
[INFO] | \- org.springframework:spring-jcl:jar:5.0.0.RELEASE:compile
[INFO] +- org.springframework.boot:spring-boot-starter-tomcat:jar:1.5.7.RELEASE:compile
[INFO] | +- org.apache.tomcat.embed:tomcat-embed-core:jar:8.5.20:compile
[INFO] | +- org.apache.tomcat.embed:tomcat-embed-el:jar:8.5.20:compile
[INFO] | \- org.apache.tomcat.embed:tomcat-embed-websocket:jar:8.5.20:compile
[INFO] +- org.springframework.boot:spring-boot-starter:jar:1.5.7.RELEASE:compile
[INFO] | +- org.springframework.boot:spring-boot:jar:1.5.7.RELEASE:compile
[INFO] | +- org.springframework.boot:spring-boot-autoconfigure:jar:1.5.7.RELEASE:compile
[INFO] | +- org.springframework.boot:spring-boot-starter-logging:jar:1.5.7.RELEASE:compile
[INFO] | | +- ch.qos.logback:logback-classic:jar:1.1.11:compile
[INFO] | | | \- ch.qos.logback:logback-core:jar:1.1.11:compile
[INFO] | | +- org.slf4j:jcl-over-slf4j:jar:1.7.25:compile
[INFO] | | +- org.slf4j:jul-to-slf4j:jar:1.7.25:compile
[INFO] | | \- org.slf4j:log4j-over-slf4j:jar:1.7.25:compile
[INFO] | \- org.yaml:snakeyaml:jar:1.17:runtime
[INFO] +- com.fasterxml.jackson.core:jackson-databind:jar:2.9.2:compile
[INFO] | +- com.fasterxml.jackson.core:jackson-annotations:jar:2.9.0:compile
[INFO] | \- com.fasterxml.jackson.core:jackson-core:jar:2.9.2:compile
[INFO] +- org.springframework:spring-webmvc:jar:5.0.1.RELEASE:compile
[INFO] | +- org.springframework:spring-aop:jar:5.0.1.RELEASE:compile
[INFO] | +- org.springframework:spring-context:jar:5.0.1.RELEASE:compile
[INFO] | \- org.springframework:spring-expression:jar:5.0.1.RELEASE:compile
[INFO] +- org.springframework.boot:spring-boot-starter-test:jar:1.5.7.RELEASE:test
[INFO] | +- org.springframework.boot:spring-boot-test:jar:1.5.7.RELEASE:test
[INFO] | +- org.springframework.boot:spring-boot-test-autoconfigure:jar:1.5.7.RELEASE:test
[INFO] | +- com.jayway.jsonpath:json-path:jar:2.2.0:test
[INFO] | | +- net.minidev:json-smart:jar:2.2.1:test
[INFO] | | | \- net.minidev:accessors-smart:jar:1.1:test
[INFO] | | | \- org.ow2.asm:asm:jar:5.0.3:test
[INFO] | | \- org.slf4j:slf4j-api:jar:1.7.16:compile
[INFO] | +- junit:junit:jar:4.12:test
[INFO] | +- org.assertj:assertj-core:jar:2.6.0:test
[INFO] | +- org.mockito:mockito-core:jar:1.10.19:test
[INFO] | | \- org.objenesis:objenesis:jar:2.1:test
[INFO] | +- org.hamcrest:hamcrest-core:jar:1.3:test
[INFO] | +- org.hamcrest:hamcrest-library:jar:1.3:test
[INFO] | +- org.skyscreamer:jsonassert:jar:1.4.0:test
[INFO] | | \- com.vaadin.external.google:android-json:jar:0.0.20131108.vaadin1:test
[INFO] | \- org.springframework:spring-test:jar:4.3.11.RELEASE:test
[INFO] +- io.jsonwebtoken:jjwt:jar:0.6.0:compile
[INFO] \- org.springframework.boot:spring-boot-starter-aop:jar:1.5.7.RELEASE:compile
[INFO] \- org.aspectj:aspectjweaver:jar:1.8.10:compile
```

# Spring Boot

Spring Boot 是一个快速且易于配置的 Spring 应用程序。与其他 Spring 应用程序不同，我们不需要太多的配置来构建 Spring Boot 应用程序，因此您可以非常快速和轻松地开始构建它。

Spring Boot 帮助我们创建一个独立的应用程序，可以快速嵌入 Tomcat 或其他容器。

# 开发 RESTful Web 服务

要创建新项目，我们可以使用 Maven 命令提示符或在线工具，如 Spring Initializr（[`start.spring.io`](http://start.spring.io)），生成项目基础。这个网站对于创建一个简单的基于 Spring Boot 的 Web 项目非常有用，可以让项目快速启动。

# 创建项目基础

让我们在浏览器中转到[`start.spring.io`](http://start.spring.io)并通过填写以下参数来配置我们的项目以创建项目基础：

+   组：`com.packtpub.restapp`

+   Artifact：`ticket-management`

+   搜索依赖项：`Web`（使用 Tomcat 和 Spring MVC 进行全栈 Web 开发）

配置完我们的项目后，它将如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/24789d0f-bbfb-4c62-bae2-715482399bd3.png)

现在，您可以通过单击“生成项目”来生成项目。项目（ZIP 文件）应下载到您的系统。解压缩`.zip`文件，您应该看到以下截图中显示的文件： 

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/084f460e-ba43-4322-9ba4-9aa6de5ae3e6.png)

复制整个文件夹（`ticket-management`）并将其保存在所需的位置。

# 使用您喜欢的 IDE

现在是选择 IDE 的时候了。虽然有许多 IDE 用于 Spring Boot 项目，但我建议使用**Spring Tool Suite**（**STS**），因为它是开源的，易于管理项目。在我的情况下，我使用`sts-3.8.2.RELEASE`。您可以从此链接下载最新的 STS：[`spring.io/tools/sts/all`](https://spring.io/tools/sts/all)。在大多数情况下，您可能不需要安装；只需解压文件并开始使用：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/e8cf1fb7-89c3-447b-8c29-374679aa4c27.png)

解压 STS 后，您可以通过运行`STS.exe`（如上截图所示）开始使用该工具。

在 STS 中，您可以通过选择现有的 Maven 项目导入项目，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/3b25c35d-504f-4bb6-a797-e23840c2714c.png)

导入项目后，您可以在包资源管理器中看到项目，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/42fe82b7-6ab5-4e24-9ff7-eae535635a13.png)

您可以默认查看主 Java 文件（`TicketManagementApplication`）：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/ab8d382c-e66c-4361-8be3-254c23e99d24.png)

为了简化项目，我们将清理现有的 POM 文件并更新所需的依赖项。将此文件配置添加到`pom.xml`：

```java
<?xml version="1.0" encoding="UTF-8"?>
<project  
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.packtpub.restapp</groupId>
  <artifactId>ticket-management</artifactId>
  <version>0.0.1-SNAPSHOT</version>
  <packaging>jar</packaging>
  <name>ticket-management</name>
  <description>Demo project for Spring Boot</description>
  <properties>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <project.reporting.outputEncoding>UTF-8</project.reporting.outputEncoding>
  </properties>
  <dependencies>
      <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-web</artifactId>
      <version>5.0.1.RELEASE</version>
    </dependency>  
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter</artifactId>
      <version>1.5.7.RELEASE</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-tomcat</artifactId>
      <version>1.5.7.RELEASE</version>
    </dependency>    
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.9.2</version>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-web</artifactId>
      <version>5.0.0.RELEASE</version>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-webmvc</artifactId>
      <version>5.0.1.RELEASE</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-test</artifactId>
      <scope>test</scope>
      <version>1.5.7.RELEASE</version> 
    </dependency> 
  </dependencies>
  <build>
    <plugins>
      <plugin>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-maven-plugin</artifactId>
      </plugin>
    </plugins>
  </build>
</project>
```

在上述配置中，您可以检查我们使用了以下库：

+   `spring-web`

+   `spring-boot-starter`

+   `spring-boot-starter-tomcat`

+   `spring-bind`

+   `jackson-databind`

由于项目需要上述依赖项才能运行，因此我们已将它们添加到我们的`pom.xml`文件中。

到目前为止，我们已经为 Spring Web 服务准备好了基本项目。让我们向应用程序添加基本的 REST 代码。首先，从`TicketManagementApplication`类中删除`@SpringBootApplication`注释，并添加以下注释：

```java
@Configuration
@EnableAutoConfiguration
@ComponentScan
@Controller
```

这些注释将帮助该类充当 Web 服务类。在本章中，我不打算详细讨论这些配置将做什么。添加注释后，请添加一个简单的方法来返回一个字符串作为我们的基本 Web 服务方法：

```java
@ResponseBody
@RequestMapping("/")
public String sayAloha(){
  return "Aloha";
}
```

最后，您的代码将如下所示：

```java
package com.packtpub.restapp.ticketmanagement;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
@Configuration
@EnableAutoConfiguration
@ComponentScan
@Controller
public class TicketManagementApplication { 
  @ResponseBody
  @RequestMapping("/")
  public String sayAloha(){
    return "Aloha";
  }
  public static void main(String[] args) {
    SpringApplication.run(TicketManagementApplication.class, args);
  }
}
```

一旦所有编码更改完成，只需在 Spring Boot 应用程序上运行项目（Run As | Spring Boot App）。您可以通过在控制台中检查此消息来验证应用程序是否已加载：

```java
Tomcat started on port(s): 8080 (http)
```

验证后，您可以通过在浏览器中简单地输入`localhost:8080`来检查 API。请查看下面的截图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/dfd51df8-24ba-4696-837e-e7742d1ec64b.png)

如果您想要更改端口号，可以在`application.properties`中配置不同的端口号，该文件位于`src/main/resources/application.properties`中。查看以下截图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/36d406d2-b55b-433d-888f-713d1a011ef2.png)

# 总结

在本章中，我们已经看到如何设置 Maven 构建以支持 Web 服务的基本实现。此外，我们还学习了 Maven 在第三方库管理以及 Spring Boot 和基本 Spring REST 项目中的帮助。在接下来的章节中，我们将更多地讨论 Spring REST 端点和 Reactor 支持。


# 第三章：Spring 中的 Flux 和 Mono（Reactor 支持）

在本章中，我们将向读者介绍更多在 Spring 5 中支持 Reactor 的实际方法，包括 Flux 和 Mono。用户将通过简单的 JSON 结果亲身体验 Flux 和 Mono。

本章将涵盖以下主题：

+   Reactive 编程和好处

+   Reactive Core 和 Streams

+   Spring REST 中的 Flux 和 Mono

+   使用 Reactive 的用户类——REST

# Reactive 编程的好处

假设我们的应用程序中有一百万个用户交易正在进行。明年，这个数字将增加到 1000 万，所以我们需要进行扩展。传统的方法是添加足够的服务器（水平扩展）。

如果我们不进行水平扩展，而是选择使用相同的服务器进行扩展，会怎么样？是的，Reactive 编程将帮助我们做到这一点。Reactive 编程是关于非阻塞的、同步的、事件驱动的应用程序，不需要大量线程进行垂直扩展（在 JVM 内部），而不是水平扩展（通过集群）。

Reactive 类型并不是为了更快地处理请求。然而，它们更关注请求并发性，特别是有效地从远程服务器请求数据。通过 Reactive 类型的支持，您将获得更高质量的服务。与传统处理相比，传统处理在等待结果时会阻塞当前线程，而 Reactive API 仅请求可以消耗的数据量。Reactive API 处理数据流，而不仅仅是单个元素。

总的来说，Reactive 编程是关于非阻塞、事件驱动的应用程序，可以通过少量线程进行扩展，背压是确保生产者（发射器）不会压倒消费者（接收器）的主要组成部分。

# Reactive Core 和 Streams

Java 8 引入了 Reactive Core，它实现了 Reactive 编程模型，并建立在 Reactive Streams 规范之上，这是构建 Reactive 应用程序的标准。由于 lambda 语法为事件驱动方法提供了更大的灵活性，Java 8 提供了支持 Reactive 的最佳方式。此外，Java 的 lambda 语法使我们能够创建和启动小型和独立的异步任务。Reactive Streams 的主要目标之一是解决背压问题。我们将在本章的后面部分更多地讨论背压问题。

Java 8 Streams 和 Reactive Streams 之间的主要区别在于 Reactive 是推模型，而 Java 8 Streams 侧重于拉模型。在 Reactive Streams 中，根据消费者的需求和数量，所有事件都将被推送给消费者。

自上次发布以来，Spring 5 对 Reactive 编程模型的支持是其最佳特性。此外，借助 Akka 和 Play 框架的支持，Java 8 为 Reactive 应用程序提供了更好的平台。

Reactor 是建立在 Reactive Streams 规范之上的。Reactive Streams 是四个 Java 接口的捆绑包：

+   `Publisher`

+   `Subscriber`

+   `Subscription`

+   `Processor`

`Publisher`将数据项的流发布给注册在`Publisher`上的订阅者。使用执行器，`Publisher`将项目发布给`Subscriber`。此外，`Publisher`确保每个订阅的`Subscriber`方法调用严格有序。

`Subscriber`只有在请求时才消耗项目。您可以通过使用`Subscription`随时取消接收过程。

`Subscription`充当`Publisher`和`Subscriber`之间的消息中介。

`Processor`代表一个处理阶段，可以包括`Subscriber`和`Publisher`。`Processor`可以引发背压并取消订阅。

Reactive Streams 是用于异步流处理的规范，这意味着所有事件都可以异步产生和消费。

# 背压和 Reactive Streams

反压是一种机制，授权接收器定义它希望从发射器（数据提供者）获取多少数据。响应式流的主要目标是处理反压。它允许：

+   在数据准备好被处理后，控制转到接收器以获取数据

+   定义和控制要接收的数据量

+   高效处理慢发射器/快接收器或快发射器/慢接收器的情况

# WebFlux

截至 2017 年 9 月，Spring 宣布了 5 的一般可用性。Spring 5 引入了一个名为 Spring WebFlux 的响应式 Web 框架。这是一个非阻塞的 Web 框架，使用 Reactor 来支持 Reactive Streams API。

传统上，阻塞线程会消耗资源，因此需要非阻塞异步编程来发挥更好的作用。Spring 技术团队引入了非阻塞异步编程模型，以处理大量并发请求，特别是对延迟敏感的工作负载。这个概念主要用于移动应用程序和微服务。此外，这个 WebFlux 将是处理许多客户端和不均匀工作负载的最佳解决方案。

# 基本 REST API

要理解 Flux 和 Mono 等响应式组件的实际部分，我们将不得不创建自己的 REST API，并开始在 API 中实现 Flux 和 Mono 类。在本章中，我们将构建一个简单的 REST Web 服务，返回`Aloha`。在进入实现部分之前，我们将专注于创建 RESTful Web 服务所涉及的组件。

在本节中，我们将涵盖以下主题：

+   Flux 和 Mono - Spring 5 的介绍：功能性 Web 框架组件

+   Flux 和 Mono - 在 REST API 中

# Flux

Flux 是 Reactor 中的主要类型之一。Flux 相当于 RxJava 的 Observable，能够发出零个或多个项目，然后选择性地完成或失败。

Flux 是实现了 Reactive Streams 宣言中的`Publisher`接口的 Reactive 类型之一。Flux 的主要作用是处理数据流。Flux 主要表示*N*个元素的流。

Flux 是一个发布者，特定**普通旧 Java 对象**（**POJO**）类型的事件序列。

# Mono

Mono 是 Reactor 的另一种类型，最多只能发出一个项目。只想要发出完成信号的异步任务可以使用 Mono。Mono 主要处理一个元素的流，而不是 Flux 的*N*个元素。

Flux 和 Mono 都利用这种语义，在使用一些操作时强制转换为相关类型。例如，将两个 Monos 连接在一起将产生一个 Flux；另一方面，在`Flux<T>`上调用`single()`将返回一个`Mono <T>`。

Flux 和 Mono 都是**Reactive Streams**（**RS**）发布者实现，并符合 Reactive-pull 反压。

Mono 在特定场景中使用，比如只产生一个响应的 HTTP 请求。在这种情况下，使用 Mono 将是正确的选择。

返回`Mono<HttpResponse>`来处理 HTTP 请求，就像前面提到的情况一样，比返回`Flux<HttpResponse>`更好，因为它只提供与零个或一个项目的上下文相关的操作符。

Mono 可以用来表示没有值的异步过程，只有完成的概念。

# 具有 Reactive 的 User 类 - REST

在第一章中，我们介绍了`Ticket`和`User`，这两个类与我们的 Web 服务有关。由于`Ticket`类与`User`类相比有点复杂，我们将使用`User`类来理解响应式组件。

由于 Spring 5 中的响应式还不是完全稳定的，我们只会在几章中讨论响应式。因此，我们将为基于响应式的 REST API 创建一个单独的包。此外，我们将在现有的`pom.xml`文件中添加基于响应式的依赖项。

首先，我们将不得不添加所有的响应式依赖。在这里，我们将在现有的`pom.xml`文件中添加代码：

```java
<?xml version="1.0" encoding="UTF-8"?>
<project  
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">  
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.packtpub.restapp</groupId>
  <artifactId>ticket-management</artifactId>
  <version>0.0.1-SNAPSHOT</version>
  <packaging>jar</packaging>
  <name>ticket-management</name>
  <description>Demo project for Spring Boot</description>  
<properties>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <project.reporting.outputEncoding>UTF-8</project.reporting.outputEncoding>
</properties>
<dependencyManagement>
   <dependencies>
    <dependency>
      <groupId>io.projectreactor</groupId>
      <artifactId>reactor-bom</artifactId>
      <version>Bismuth-RELEASE</version>
            <type>pom</type>
            <scope>import</scope>
    </dependency>
        </dependencies>
  </dependencyManagement>
  <dependencies>
      <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-web</artifactId>
      <version>5.0.1.RELEASE</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter</artifactId>
      <version>1.5.7.RELEASE</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-tomcat</artifactId>
      <version>1.5.7.RELEASE</version>
    </dependency>  
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.9.2</version>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-web</artifactId>
      <version>5.0.0.RELEASE</version>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-webmvc</artifactId>
      <version>5.0.1.RELEASE</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-test</artifactId>
      <scope>test</scope>
      <version>1.5.7.RELEASE</version> 
    </dependency>     
    <dependency>
      <groupId>org.reactivestreams</groupId>
      <artifactId>reactive-streams</artifactId>
    </dependency>
    <dependency>
      <groupId>io.projectreactor</groupId>
      <artifactId>reactor-core</artifactId>
    </dependency>
    <dependency>
      <groupId>io.projectreactor.ipc</groupId>
      <artifactId>reactor-netty</artifactId>
    </dependency>
    <dependency>
      <groupId>org.apache.tomcat.embed</groupId>
      <artifactId>tomcat-embed-core</artifactId>
      <version>8.5.4</version>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-context</artifactId>
      <version>5.0.0.RELEASE</version>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-webflux</artifactId>
      <version>5.0.0.RELEASE</version>
    </dependency>
  </dependencies>
  <build>
    <plugins>
      <plugin>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-maven-plugin</artifactId>
      </plugin>
    </plugins>
  </build>
</project>
```

对于与 Reactive 相关的工作，您可以使用现有项目，也可以创建一个新项目，以避免与非 Reactive（普通）REST API 发生冲突。您可以使用[`start.spring.io`](https://start.spring.io)获取基本项目，然后使用上述配置更新 Maven 文件。

在前面的 POM 配置中，我们已经在现有的依赖项上添加了 Reactor 依赖项（如下所示）：

+   `reactive-streams`

+   `reactor-core`

+   `reactor-netty`

+   `tomcat-embed-core`

+   `spring-webflux`

这些是使用 Reactor 所需的库。

`User`类的组件如下：

+   `userid`

+   `username`

+   `user_email`

+   `user_type`（管理员，普通用户，CSR）

在这里，我们使用了`User`类的四个变量。为了更容易理解 Reactive 组件，我们只使用了两个变量（`userid`，`username`）。让我们创建一个只有`userid`和`username`的 POJO 类。

`User` POJO 类如下：

```java
package com.packtpub.reactive;
public class User {
  private Integer userid;
  private String username;  
  public User(Integer userid, String username){
    this.userid = userid;
    this.username = username;
  }
  public Integer getUserid() {
    return userid;
  }
  public void setUserid(Integer userid) {
    this.userid = userid;
  }
  public String getUsername() {
    return username;
  }
  public void setUsername(String username) {
    this.username = username;
  } 
}
```

在上面的类中，我使用了两个变量和一个构造函数来在实例化时填充变量。同时，使用 getter/setter 来访问这些变量。

让我们为`User`类创建一个 Reactive 存储库：

```java
package com.packtpub.reactive;
import reactor.core.publisher.Flux;
public interface UserRepository {
  Flux<User> getAllUsers();
}
```

在上面的代码中，我们为`User`引入了一个 Reactive 存储库和一个只有一个方法的类，名为`getAllUsers`。通过使用这个方法，我们应该能够检索到用户列表。现在先不谈 Flux，因为它将在以后讨论。

您可以看到这个`UserRepository`是一个接口。我们需要有一个具体的类来实现这个接口，以便使用这个存储库。让我们为这个 Reactive 存储库创建一个具体的类：

```java
package com.packtpub.reactive;
import java.util.HashMap;
import java.util.Map;
import reactor.core.publisher.Flux;
public class UserRepositorySample implements UserRepository {  
  // initiate Users
  private Map<Integer, User> users = null;  
  // fill dummy values for testing
  public UserRepositorySample() {
    // Java 9 Immutable map used
    users = Map.of(
      1, (new User(1, "David")),
      2, (new User(2, "John")),
      3, (new User(3, "Kevin"))
    ); 
  }
  // this method will return all users
  @Override
  public Flux<User> getAllUsers() {
    return Flux.fromIterable(this.users.values());
  }
}
```

由于 Java 9 中有不可变映射可用，我们可以在我们的代码中使用不可变映射。然而，这些不可变对象仅适用于本章，因为我们不对现有条目进行任何更新。

在下一章中，我们将使用常规的映射，因为我们需要在 CRUD 操作中对它们进行编辑。

目前，我们能够从具体类中获取用户列表。现在我们需要一个 web 处理程序在控制器中检索用户。现在让我们创建一个处理程序：

```java
package com.packtpub.reactive;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
public class UserHandler {
  private final UserRepository userRepository;  
  public UserHandler(UserRepository userRepository){
    this.userRepository = userRepository;
  }  
  public Mono<ServerResponse> getAllUsers(ServerRequest request){
    Flux<User> users = this.userRepository.getAllUsers();
    return ServerResponse.ok().contentType(APPLICATION_JSON).body(users, User.class); 
  }
}
```

最后，我们将需要创建一个服务器来保留 REST API。在下面的代码中，我们的`Server`类将创建一个 REST API 来获取用户：

```java
package com.packtpub.reactive;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.web.reactive.function.server.RequestPredicates.GET;
import static org.springframework.web.reactive.function.server.RequestPredicates.POST;
import static org.springframework.web.reactive.function.server.RequestPredicates.accept;
import static org.springframework.web.reactive.function.server.RequestPredicates.contentType;
import static org.springframework.web.reactive.function.server.RequestPredicates.method;
import static org.springframework.web.reactive.function.server.RequestPredicates.path;
import static org.springframework.web.reactive.function.server.RouterFunctions.nest;
import static org.springframework.web.reactive.function.server.RouterFunctions.route;
import static org.springframework.web.reactive.function.server.RouterFunctions.toHttpHandler;
import java.io.IOException;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.HttpHandler;
import org.springframework.http.server.reactive.ReactorHttpHandlerAdapter;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.ipc.netty.http.server.HttpServer;
public class Server {
  public static final String HOST = "localhost";
  public static final int PORT = 8081;
  public static void main(String[] args) throws InterruptedException, IOException{
    Server server = new Server(); 
    server.startReactorServer();
    System.out.println("Press ENTER to exit.");
    System.in.read();
  }  
  public void startReactorServer() throws InterruptedException {
    RouterFunction<ServerResponse> route = routingFunction();
    HttpHandler httpHandler = toHttpHandler(route);
    ReactorHttpHandlerAdapter adapter = new ReactorHttpHandlerAdapter(httpHandler);
    HttpServer server = HttpServer.create(HOST, PORT);
    server.newHandler(adapter).block();
  }
  public RouterFunction<ServerResponse> routingFunction() {
    UserRepository repository = new UserRepositorySample();
    UserHandler handler = new UserHandler(repository);
    return nest (
        path("/user"),
        nest(
          accept(APPLICATION_JSON),
          route(GET("/{id}"), handler::getAllUsers)
          .andRoute(method(HttpMethod.GET), handler::getAllUsers)
        ).andRoute(POST("/").and(contentType(APPLICATION_JSON)), handler::getAllUsers));
  }
}
```

我们将在接下来的章节中更多地讨论我们是如何做到这一点的。只要确保您能够理解代码是如何工作的，并且可以通过访问 API 在浏览器上看到输出。

运行`Server.class`，您将看到日志：

```java
Press ENTER to exit.
```

现在您可以在浏览器/SoapUI/Postman 或任何其他客户端访问 API：

```java
http://localhost:8081/user/
```

由于我们在 Reactive 服务器中使用了`8081`端口，我们只能访问`8081`而不是`8080`：

```java
[ 
  { 
    "userid": 100, 
    "username": "David" 
  },
  { 
    "userid": 101, 
    "username": "John" 
  },
  { 
    "userid": 102, 
    "username": "Kevin" 
  }, 
]
```

# 总结

到目前为止，我们已经看到如何设置 Maven 构建来支持我们的基本 Web 服务实现。此外，我们还学习了 Maven 在第三方库管理以及 Spring Boot 和基本 Spring REST 项目中的帮助。在接下来的章节中，我们将更多地讨论 Spring REST 端点和 Reactor 支持。


# 第四章：Spring REST 中的 CRUD 操作

在本章中，我们将介绍 Spring 5 Reactive REST 中的基本**创建**，**读取**，**更新**和**删除**（**CRUD**）API。在本章之后，您将能够在具有 Reactor 支持的 Spring 5 中执行简单的 CRUD 操作。

在本章中，我们将介绍以下方法：

+   将 CRUD 操作映射到 HTTP 方法

+   创建用户

+   更新用户

+   删除用户

+   阅读（选择）用户

# Spring REST 中的 CRUD 操作

在本章中，我们将介绍 Spring 5 中的用户管理（带有 Reactive 支持）。我们将在用户管理中实现 CRUD 操作。

# HTTP 方法

根据 HTTP 1.1 规范，以下是方法定义：

+   `GET`：此方法获取 URI 中提到的信息。`GET`方法可用于单个或多个项目。

+   `POST`：此方法创建 URI 中提到的项目。通常，`POST`方法将用于项目创建和更安全的选项。由于参数在`POST`中是隐藏的，因此与`GET`方法相比，它将更安全。

+   `DELETE`：此方法删除请求的 URI 中的项目。

+   `PUT`：此方法更新请求的 URI 中的项目。根据 HTTP 规范，如果项目不可用，服务器可以创建项目。但是，这将由设计应用程序的开发人员决定。

+   **高级 HTTP 方法**：虽然我们可能不会始终使用高级方法，但了解这些方法将是有益的：

+   `HEAD`：此方法获取有关资源的元信息，而不是资源本身作为响应。它将用于缓存目的。

+   `TRACE`：此方法主要用于调试目的，其中 HTTP 请求的内容将被发送回请求者。

+   `CONNECT`：这用于打开隧道，可用于代理目的。

+   `OPTIONS`：此方法用于描述目标资源的通信选项。

以下是我们 CRUD 操作的 HTTP 方法建议：

| **操作** | **HTTP 方法** |
| --- | --- |
| 创建 | `POST` |
| 读取 | `GET` |
| 更新 | `PUT` |
| 删除 | `DELETE` |

在本章的其余部分，我们将展示如何构建 CRUD 操作。

# 响应式服务器初始化

在进入端点之前，我们将探索我们的文件结构，包括初始化程序、处理程序和存储库。

用于初始化我们的端口`8081`的`Server`类如下：

```java
public class Server { 
  public static final String HOST = "localhost";
  public static final int PORT = 8081;
  public static void main(String[] args) throws InterruptedException, IOException{
    Server server = new Server(); 
    server.startReactorServer(); 
    System.out.println("Press ENTER to exit.");
    System.in.read();
  }
  public void startReactorServer() throws InterruptedException {
    RouterFunction<ServerResponse> route = routingFunction();
    HttpHandler httpHandler = toHttpHandler(route);
    ReactorHttpHandlerAdapter adapter = new ReactorHttpHandlerAdapter(httpHandler);
    HttpServer server = HttpServer.create(HOST, PORT);
    server.newHandler(adapter).block();
  }
  public RouterFunction<ServerResponse> routingFunction() {
    // our Endpoints will be coming here
  }
} 
```

在上述方法中，我们创建了一个`main`类。在`main`方法中，我们将使用以下代码初始化服务器并启动服务器：

```java
Server server = new Server(); 
server.startReactorServer(); 
```

上述方法将启动 Reactor 服务器。 Reactor 服务器的实现如下：

```java
RouterFunction<ServerResponse> route = routingFunction();
HttpHandler httpHandler = toHttpHandler(route);
ReactorHttpHandlerAdapter adapter = new ReactorHttpHandlerAdapter(httpHandler);
HttpServer server = HttpServer.create(HOST, PORT);
server.newHandler(adapter).block();
```

让我们稍后再看这段代码，因为这个概念是基于 Reactive 的。假设这段代码运行良好，我们将继续前进，重点放在端点上。

以下是映射我们所有 CRUD 操作的 REST 端点的方法：

```java
public RouterFunction<ServerResponse> routingFunction() {
    // our Endpoints will be coming here
}
```

您可能会在`UserRepository`和`UserHandler`上遇到错误。现在让我们填写这些：

```java
package com.packtpub.reactive;
public interface UserRepository {
    // repository functions will be coming here
}
```

在上述代码中，我们刚刚在现有包`com.packtpub.reactive`中添加了`UserRepository`接口。稍后，我们将为我们的业务需求引入抽象方法。

现在，我们可以添加一个`UserHandler`类，并添加必要的内容：

```java
package com.packtpub.reactive;
// import statements
public class UserHandler {    
    private final UserRepository userRepository;  
    public UserHandler(UserRepository userRepository){
        this.userRepository = userRepository;
    }
}
```

在上面的代码中，`UserHandler`在其构造函数中初始化了`UserRepository`实例。如果有人获得了`UserHandler`的实例，他们将不得不将`UserRepository`类型传递给`UserHandler`的构造函数。通过这样做，`UserRepository`将始终被转发到`UserHandler`以满足业务需求。

# 存储库中的示例值

为了使用存储库，我们将不得不创建一个具体的类并填写一些值来测试`GET`操作。在下面的方法中，我们可以这样做：

```java
package com.packtpub.reactive;
// import statements
public class UserRepositorySample implements UserRepository {    
  // initiate Users
  private final Map<Integer, User> users = new HashMap<>();
  // fill dummy values for testing
  public UserRepositorySample() {
    this.users.put(100, new User(100, "David"));
    this.users.put(101, new User(101, "John"));
    this.users.put(102, new User(102, "Kevin"));
  }
} 
```

在上述类中，我们刚刚实现了`UserRepository`并填写了一些示例值。

为了简化我们的代码，我们只使用基于应用程序的数据存储，这意味着一旦应用程序重新启动，我们的数据将被重新初始化。在这种情况下，我们无法在我们的应用程序中存储任何新数据。但是，这将帮助我们专注于我们的主题，比如与持久性无关的 Reactive 和 Spring 5。

我们可以在`routing`方法中使用这个示例存储库：

```java
public RouterFunction<ServerResponse> routingFunction() {
    UserRepository repository = new UserRepositorySample();
    UserHandler handler = new UserHandler(repository);
}
```

上述行将在我们的存储库中插入虚拟值。这足以测试`GET`操作。

# 获取所有用户-映射

在`routingFunction`中，我们将为`getAllUsers`添加我们的第一个端点。起初，我们将在处理程序中保留`null`值，以避免代码中的错误：

```java
    return nest (
        path("/user"),
        nest(
          accept(MediaType.ALL),
          route(GET("/"), null)
        )    
    );
```

上述的`nest`方法将用于路由到正确的函数，并且还将用于分组其他路由器。在上述方法中，我们在我们的路径中使用`/user`，并使用`GET("/")`方法作为路由器。此外，我们使用`MediaType.ALL`来接受所有媒体范围，以简化代码。

# 获取所有用户-处理程序和存储库中的实现

在这里，我们将在我们的存储库中定义和实现`getAllUsers`方法。此外，我们将通过`UserHandler`在`main`类中调用`getAllUsers`方法。

我们将在`UserRepository`类中添加一个`getAllUsers`方法的抽象方法：

```java
Flux<User> getAllUsers();
```

与任何其他接口和具体类实现一样，我们必须在我们的接口中添加抽象方法，在我们的情况下是`UserRespository`。上述代码只是在`UserRepository`类中添加了`getAllUsers`。

在`UserRepositorySample`（`UserRepository`的具体类）中，我们将实现抽象方法`getAllUsers`：

```java
// this method will return all users
@Override
public Flux<User> getAllUsers() {
    return Flux.fromIterable(this.users.values());
}
```

在上面的代码中，我们已经添加了`getAllUsers`方法并实现了业务逻辑。由于我们已经在`UserRepositorySample`构造函数中定义了用户，我们只需要返回用户。`Flux`类有一个叫做`fromIterable`的方法，用于从我们的`UserRepositorySample`中获取所有用户。

`fromIterable`方法将返回一个发出 Java 集合接口中包含的项目的 Flux。由于 Collection 实现了 iterable 接口，`fromIterable`将是在我们的情况下返回`Flux`的完美方法。

在`UserHandler.java`文件中，我们将添加以 Reactive 方式获取所有用户的代码。以下代码将为我们提供必要的细节：

```java
public Mono<ServerResponse> getAllUsers(ServerRequest request){
  Flux<User> users = this.userRepository.getAllUsers();
  return ServerResponse.ok().contentType(APPLICATION_JSON).body(users, User.class); 
}
```

在上面的代码中，我们将从`Flux`中获取所有用户，并以 JSON 类型发送响应。服务器响应内容类型已更新为`APPLICATION_JSON`。

现在是时候在我们的路由方法中添加我们的第一个方法`getAllUsers`了。在这里，我们将只使用一个路由方法来映射所有的 REST API。

最后，在`Server.java`中，我们的路由函数将如下所示：

```java
public class Server {    
    // existing code is hidden
    public RouterFunction<ServerResponse> routingFunction() {
        UserRepository repository = new UserRepositorySample();
        UserHandler handler = new UserHandler(repository);
        return nest (
            path("/user"),
            nest(
              accept(MediaType.ALL),
              route(GET("/"), handler::getAllUsers)
        ) 
    );
}
```

在上面的代码中，我们创建了一个`UserRepository`并将其转发给我们的`UserHandler`。`UserHandler`将自动调用`UserSampleRepository`中的`getAllUsers`方法。通过调用`UserHandler`的`getAllUsers`方法，我们将从我们之前实现的示例存储库类中获取所有用户。

在这里，我们使用`nest`方法并提供参数，比如 API 路径`GET("/")`和媒体类型。由于`nest`方法接受`RoutingFunction`作为第二个参数，我们可以在基本的`nest`方法中使用更多的`nest`方法。通过使用内部嵌套方法，我们已经实现了业务需求：我们的基本 REST API 从`"/user"`开始，并通过`"/"`基本获取用户 API 路由。

因此，基本的 API 路径`/user`将自动调用上面代码中实现的`getAllUsers`方法。

# 测试端点-获取所有用户

由于我们已经完成了第一个 API 的实现，现在我们可以通过在浏览器中调用以下 URI 来测试它：

```java
http://localhost:8081/user
```

您应该得到以下结果： 

```java
[
  {
    userid: 100,
    username: "David"
  },
  {
    userid: 101,
    username: "John"
  },
  {
    userid: 102,
    username: "Kevin"
  }
]
```

您还可以在任何 REST 客户端中检查 API，比如 Postman/SoapUI 或其他任何 REST 客户端。

# getUser-处理程序和存储库中的实现

在这里，我们将在存储库中定义和实现`getUser`方法。此外，我们将通过`UserHandler`在`main`类中调用`getUser`方法。

我们将在`UserRepository`类中为`getUser`方法添加一个抽象方法：

```java
Mono<User> getUser(Integer id);
```

在这里，我们将添加`getUser`方法的代码。您可以看到我们使用了`Mono`返回类型来访问单个资源。

在`UserRepositorySample`类（`UserRepository`的具体类）中，我们将实现抽象方法`getUser`：

```java
@Override
public Mono<User> getUser(Integer id){
    return Mono.justOrEmpty(this.users.get(id)); 
}
```

在上述代码中，我们通过`id`检索了特定用户。此外，我们已经提到，如果用户不可用，应该要求该方法返回一个空的 Mono。

在`UserHandler`方法中，我们将讨论如何处理请求并应用我们的业务逻辑来获得响应：

```java
public Mono<ServerResponse> getUser(ServerRequest request){
    int userId = Integer.valueOf(request.pathVariable("id"));
    Mono<ServerResponse> notFound = ServerResponse.notFound().build();
    Mono<User> userMono = this.userRepository.getUser(userId);
    return userMono
        .flatMap(user -> ServerResponse.ok().contentType(APPLICATION_JSON).body(fromObject(user)))
        .switchIfEmpty(notFound); 
}
```

在上述代码中，我们刚刚将字符串`id`转换为整数，以便将其提供给我们的`Repository`方法（`getUser`）。一旦我们从`Repository`接收到结果，我们只需将其映射到带有`JSON`内容类型的`Mono<ServerResponse>`中。此外，我们使用`switchIfEmpty`来在没有项目可用时发送适当的响应。如果搜索项目不可用，它将简单地返回空的`Mono`对象作为响应。

最后，我们将在`Server.java`中的路由路径中添加`getUser`：

```java
public RouterFunction<ServerResponse> routingFunction() {
    UserRepository repository = new UserRepositorySample();
    UserHandler handler = new UserHandler(repository);    
    return nest (
      path("/user"),
      nest(
        accept(MediaType.ALL),
        route(GET("/"), handler::getAllUsers)
      )
      .andRoute(GET("/{id}"), handler::getUser)      
    );
}
```

在上述代码中，我们刚刚在现有路由路径中添加了一个新条目`.andRoute(GET("/{id}"), handler::getUser)`。通过这样做，我们已经添加了`getUser`方法和相应的 REST API 部分来访问单个用户。重新启动服务器后，我们应该能够使用 REST API。

# 测试端点-获取用户

由于我们已经完成了第一个 API 实现，现在可以通过在浏览器中使用`GET`方法调用以下 URI 来测试它：

```java
http://localhost:8081/user/100
```

您应该会得到以下结果：

```java
{
    userid: 100,
    username: "David"
}
```

# 创建用户-在处理程序和存储库中的实现

在这里，我们将在存储库中定义和实现`createUser`方法。此外，我们将通过`UserHandler`在`main`类中调用`createUser`方法。

我们将在`UserRepository`类中为`createUser`方法添加一个抽象方法：

```java
Mono<Void> saveUser(Mono<User> userMono);
```

在这里，我们将讨论如何使用示例存储库方法保存用户。

在`UserRepositorySample`（`UserRepository`的具体类）中，我们将实现抽象方法`createUser`：

```java
@Override
public Mono<Void> saveUser(Mono<User> userMono) {
    return userMono.doOnNext(user -> { 
      users.put(user.getUserid(), user);
      System.out.format("Saved %s with id %d%n", user, user.getUserid());
    }).thenEmpty(Mono.empty());
}
```

在上述代码中，我们使用`doOnNext`来保存用户在存储库中。此外，如果失败，该方法将返回空的`Mono`。

由于我们已经在存储库中添加了`createUser`方法，因此我们将在处理程序中进行后续操作：

```java
public Mono<ServerResponse> createUser(ServerRequest request) {
    Mono<User> user = request.bodyToMono(User.class);
    return ServerResponse.ok().build(this.userRepository.saveUser(user));
}
```

在`UserHandler`类中，我们创建了`createUser`方法，通过处理程序添加用户。在该方法中，我们通过`bodyToMono`方法将请求提取为`Mono`。一旦创建了`用户`，它将被转发到`UserRepository`以保存该方法。

最后，我们将在`Server.java`的现有路由函数中添加 REST API 路径以保存`用户`：

```java
public RouterFunction<ServerResponse> routingFunction() {
    UserRepository repository = new UserRepositorySample();
    UserHandler handler = new UserHandler(repository);
    return nest (
      path("/user"),
      nest(
        accept(MediaType.ALL),
        route(GET("/"), handler::getAllUsers)
      )
      .andRoute(GET("/{id}"), handler::getUser)
      .andRoute(POST("/").and(contentType(APPLICATION_JSON)), handler::createUser) 
    );
}
```

# 测试端点-创建用户

由于我们已经完成了第一个 API 实现，现在可以通过在浏览器中调用以下 URI 来测试它：

```java
http://localhost:8081/user
```

由于我们无法在浏览器中使用`POST`方法，因此我们将在名为 Postman 的 REST API 客户端中进行测试：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/82cd10d5-7c5a-445d-9586-4ad49159212a.png)

添加新用户后，您可以通过调用`getAllUsers` URI（`http://localhost:8081/user`）来检查结果。

**Postman**是一个 REST 客户端，可用于构建，测试和共享 REST API 调用。在测试 REST API 时，这样的工具将非常有帮助，而无需编写测试代码。

**SoapUI**是另一个 REST 客户端，可以作为 Postman 的替代品使用。

# 更新用户-在处理程序和存储库中的实现

在这里，我们将在存储库中定义和实现`updateUser`方法。此外，我们将通过`UserHandler`在`main`类中调用`updateUser`方法。

我们将在`UserRepository`类中为`updateUser`方法添加一个抽象方法：

```java
Mono<Void> updateUser(Mono<User> userMono);
```

在`UserRepositorySample`类中，我们将添加更新代码的逻辑。在这里，我们将使用`userid`作为键，并将`User`对象作为值存储在我们的映射中：

```java
@;Override
public Mono<Void> updateUser(Mono<User> userMono) {
    return userMono.doOnNext(user -> { 
      users.put(user.getUserid(), user);
      System.out.format("Saved %s with id %d%n", user, user.getUserid());
    }).thenEmpty(Mono.empty());
}
```

在上面的代码中，我们通过添加指定的用户（来自请求）来更新用户。一旦用户添加到列表中，该方法将返回`Mono<Void>`；否则，它将返回`Mono.empty`对象。

由于我们已经在存储库中添加了`updateUser`方法，现在我们将跟进我们的处理程序：

```java
public Mono<ServerResponse> updateUser(ServerRequest request) {
    Mono<User> user = request.bodyToMono(User.class);
    return ServerResponse.ok().build(this.userRepository.saveUser(user));
}
```

在上述代码中，我们通过调用`bodyToMono`方法将用户请求转换为`Mono<User>`。`bodyToMono`方法将提取主体并转换为`Mono`对象，以便用于保存选项。

与其他 API 路径一样，我们在`Server.java`中添加了`updateUser` API：

```java
public RouterFunction<ServerResponse> routingFunction() {
    UserRepository repository = new UserRepositorySample();
    UserHandler handler = new UserHandler(repository);
    return nest (
      path("/user"),
      nest(
        accept(MediaType.ALL),
        route(GET("/"), handler::getAllUsers)
      )
      .andRoute(GET("/{id}"), handler::getUser)
      .andRoute(POST("/").and(contentType(APPLICATION_JSON)), handler::createUser)
      .andRoute(PUT("/").and(contentType(APPLICATION_JSON)), handler::updateUser) 
    );
}
```

# 测试端点 - updateUser

由于我们已经添加了`deleteUser`方法，现在我们将通过在 Postman 或 SoapUI 中使用`PUT`方法调用 URI `http://localhost:8081/user` 来测试它：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/523cfdae-1c96-4847-bd10-03d5528e29b8.png)

更新新用户后，您可以通过调用`getAllUsers` URI (`http://localhost:8081/user`) 来检查结果。

# deleteUser - 处理程序和存储库中的实现

在这里，我们将在存储库中定义和实现`deleteUser`方法。此外，我们将通过`UserHandler`在`main`类中调用`deleteUser`方法。

像往常一样，我们将在`UserRepository`类中为`deleteUser`方法添加一个抽象方法：

```java
Mono<Void> deleteUser(Integer id);
```

在`UserRepositorySample.java`文件中，我们将添加`deleteUser`方法来从列表中删除指定的用户：

```java
@Override
public Mono<Void> deleteUser(Integer id) {
    users.remove(id); 
    System.out.println("user : "+users);   
    return Mono.empty();
}
```

在上述方法中，我们只是从用户中删除元素并返回一个空的`Mono`对象。

由于我们已经在存储库中添加了`deleteUser`方法，现在我们将跟进我们的处理程序：

```java
public Mono<ServerResponse> deleteUser(ServerRequest request) { 
    int userId = Integer.valueOf(request.pathVariable("id"));
    return ServerResponse.ok().build(this.userRepository.deleteUser(userId));
}
```

最后，我们将在`Server.java`中的现有路由函数中添加 REST API 路径以保存`user`：

```java
public RouterFunction<ServerResponse> routingFunction() {
    UserRepository repository = new UserRepositorySample();
    UserHandler handler = new UserHandler(repository);
    return nest (
      path("/user"),
      nest(
        accept(MediaType.ALL),
        route(GET("/"), handler::getAllUsers)
      )
      .andRoute(GET("/{id}"), handler::getUser)
      .andRoute(POST("/").and(contentType(APPLICATION_JSON)), handler::createUser)
      .andRoute(PUT("/").and(contentType(APPLICATION_JSON)), handler::updateUser)
      .andRoute(DELETE("/{id}"), handler::deleteUser)
    );
}
```

# 测试端点 - deleteUser

由于我们已经完成了第一个 API 的实现，现在我们可以通过在客户端（Postman 或 SoapUI）中使用`DELETE`方法调用 URI `http://localhost:8081/user/100` 来测试它：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/df51fdd2-5775-4372-b8a4-8db654b3a0ff.png)

删除新用户后，您可以通过调用`getAllUsers` URI (`http://localhost:8081/user`) 来检查结果。

# 总结

在本章中，我们学习了如何使用 Reactive 支持（Flux 和 Mono）以及如何将我们的 API 与 Reactive 组件集成。我们已经学习了如何使用 Reactor 服务器对基于 Reactive 的 REST API 进行基本的 CRUD 操作。此外，我们还介绍了如何为我们的 CRUD 操作添加路由选项，并简要讨论了在 CRUD 操作中 Flux 和 Mono 的实现。

在接下来的章节中，我们将专注于 Spring 5 REST（不带 Reactor 支持），因为 Spring Reactive 库/ API 仍处于不稳定状态，并且在主流应用程序中并没有被广泛使用。尽管 Spring 团队正式发布了对 Reactive 的支持，但大多数业务需求并没有得到清晰的实现和文档化。考虑到这种情况，在接下来的章节中，我们将讨论不涉及 Reactive 相关主题的 Spring 5。


# 第五章：普通 REST 中的 CRUD 操作（不包括 Reactive）和文件上传

在上一章中，我们探讨了对 Reactive 支持的 CRUD 操作。由于 Spring 开发团队仍在更新更多的 Reactive 实体，Reactive 支持还没有达到他们的水平。尽管 Spring 5 的 Reactive 支持运行良好，但他们仍需要改进以使其更加稳定。考虑到这些要点，我们计划避免使用 Reactive 支持，以使其对您更加简单。

在本章中，我们将介绍 Spring 5（不包括 Reactive）REST 中的基本 CRUD（创建、读取、更新和删除）API。在本章之后，您将能够在 Spring 5 中进行简单的 CRUD 操作，而无需 Reactive 支持。此外，我们将讨论 Spring 5 中的文件上传选项。

在本章中，我们将涵盖以下方法：

+   将 CRUD 操作映射到 HTTP 方法

+   创建用户

+   更新用户

+   删除用户

+   读取（选择）用户

+   Spring 中的文件上传

# 将 CRUD 操作映射到 HTTP 方法

在上一章中，您看到了控制器中的 CRUD 操作。在本章中，我们将进行相同的 CRUD 操作；但是，我们已经排除了所有 Reactive 组件。

# 创建资源

要创建基本的 Spring 项目资源，您可以使用 Spring Initializr（[`start.spring.io/`](https://start.spring.io/)）。在 Spring Initializr 中，提供必要的详细信息：

使用 Java 和 Spring Boot 1.5.9 生成一个 Maven 项目。

组：`com.packtpub.restapp`

Artifact：`ticket-management`

搜索依赖项：选择`Web（使用 Tomcat 和 Web MVC 进行全栈 Web 开发）`依赖项

填写完详细信息后，只需点击`Generate Project`；然后它将以 ZIP 格式创建 Spring 基本资源。我们可以通过将它们导入 Eclipse 来开始使用项目。

Spring 5 的 POM 文件将如下所示：

```java
<?xml version="1.0" encoding="UTF-8"?>
<project  
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.packtpub.restapp</groupId>
  <artifactId>ticket-management</artifactId>
  <version>0.0.1-SNAPSHOT</version>
  <packaging>jar</packaging>
  <name>ticket-management</name>
  <description>Demo project for Spring Boot</description>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>1.5.9.RELEASE</version>
    <relativePath/> <!-- lookup parent from repository -->
  </parent>
  <properties>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <project.reporting.outputEncoding>UTF-8</project.reporting.outputEncoding>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-test</artifactId>
      <scope>test</scope>
    </dependency>
  </dependencies>
  <build>
    <plugins>
      <plugin>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-maven-plugin</artifactId>
      </plugin>
    </plugins>
  </build>
</project>
```

让我们移除父级以简化 POM：

```java
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>1.5.9.RELEASE</version>
    <relativePath/> <!-- lookup parent from repository -->
  </parent>
```

由于我们移除了父级，我们可能需要在所有依赖项中添加版本。让我们在我们的依赖项中添加版本：

```java
<dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
      <version>1.5.9.RELEASE</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-test</artifactId>
      <scope>test</scope>
      <version>1.5.9.RELEASE</version>
    </dependency>
  </dependencies>
```

由于依赖项 artifact `spring-boot-starter-web`版本`1.5.9`基于 Spring 4.3.11，我们将不得不升级到 Spring 5。让我们清理并升级我们的 POM 文件以引入 Spring 5 更新：

```java
<?xml version="1.0" encoding="UTF-8"?>
<project  
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.packtpub.restapp</groupId>
  <artifactId>ticket-management</artifactId>
  <version>0.0.1-SNAPSHOT</version>
  <packaging>jar</packaging>
  <name>ticket-management</name>
  <description>Demo project for Spring Boot</description> 
  <properties>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <project.reporting.outputEncoding>UTF-8</project.reporting.outputEncoding>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
      <version>1.5.9.RELEASE</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-test</artifactId>
      <scope>test</scope>
      <version>1.5.9.RELEASE</version>
    </dependency>
  </dependencies>
  <build>
    <plugins>
      <plugin>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-maven-plugin</artifactId>
      </plugin>
    </plugins>
  </build>
</project>
```

您可以在上述 POM 文件中看到与 Spring 5 相关的依赖项。让我们使用 REST 端点对它们进行测试。首先，创建一个 Spring Boot 主文件来初始化 Spring Boot：

```java
@SpringBootApplication
public class TicketManagementApplication {  
  public static void main(String[] args) {
    SpringApplication.run(TicketManagementApplication.class, args);
  }
}
```

您可以通过右键单击项目并选择`Run As | Spring Boot App`在 Eclipse 上运行 Spring Boot。如果这样做，您将在 Eclipse 控制台中看到日志。

如果您看不到控制台，可以通过`Window | Show View | Console`获取它。

以下是一个示例日志。您可能看不到完全匹配；但是，您将了解服务器运行日志的外观：

```java

 . ____ _ __ _ _
 /\\ / ___'_ __ _ _(_)_ __ __ _ \ \ \ \
( ( )\___ | '_ | '_| | '_ \/ _` | \ \ \ \
 \\/ ___)| |_)| | | | | || (_| | ) ) ) )
 ' |____| .__|_| |_|_| |_\__, | / / / /
 =========|_|==============|___/=/_/_/_/
 :: Spring Boot :: (v1.5.7.RELEASE)

2017-11-05 15:49:21.380 INFO 8668 --- [ main] c.p.restapp.TicketManagementApplication : Starting TicketManagementApplication on DESKTOP-6JP2FNB with PID 8668 (C:\d\spring-book-sts-space\ticket-management\target\classes started by infoadmin in C:\d\spring-book-sts-space\ticket-management)
2017-11-05 15:49:21.382 INFO 8668 --- [ main] c.p.restapp.TicketManagementApplication : No active profile set, falling back to default profiles: default
2017-11-05 15:49:21.421 INFO 8668 --- [ main] ationConfigEmbeddedWebApplicationContext : Refreshing org.springframework.boot.context.embedded.AnnotationConfigEmbeddedWebApplicationContext@5ea434c8: startup date [Sun Nov 05 15:49:21 EST 2017]; root of context hierarchy
2017-11-05 15:49:22.205 INFO 8668 --- [ main] s.b.c.e.t.TomcatEmbeddedServletContainer : Tomcat initialized with port(s): 8080 (http)
2017-11-05 15:49:22.213 INFO 8668 --- [ main] o.apache.catalina.core.StandardService : Starting service [Tomcat]
...
..

...
...
2017-11-05 15:49:22.834 INFO 8668 --- [ main] o.s.j.e.a.AnnotationMBeanExporter : Registering beans for JMX exposure on startup
2017-11-05 15:49:22.881 INFO 8668 --- [ main] s.b.c.e.t.TomcatEmbeddedServletContainer : Tomcat started on port(s): 8080 (http)
```

您应该在日志的最后几行看到`Tomcat started on port(s): 8080`。

当您检查 URI `http://localhost:8080` 时，您将看到以下错误：

```java
Whitelabel Error Page

This application has no explicit mapping for /error, so you are seeing this as a fallback.

Sun Nov {current date}
There was an unexpected error (type=Not Found, status=404).
No message available
```

先前的错误是说应用程序中没有配置相应的 URI。让我们通过在`com.packtpub.restapp`包下创建一个名为`HomeController`的控制器来解决这个问题：

```java
package com.packtpub.restapp;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
@RestController
@RequestMapping("/")
public class HomeController {
  @ResponseBody
  @RequestMapping("")
  public Map<String, Object> test(){
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("result", "Aloha");    
    return map;
  }
}
```

在上述代码中，我们创建了一个名为`HomeController`的虚拟控制器，并将简单的`map`作为结果。此外，我们添加了新的控制器，我们需要让我们的主应用程序自动扫描这些类，在我们的情况下是`TicketManagementApplication`类。我们将通过在主类中添加`@ComponentScan("com.packtpub")`来告诉它们。最后，我们的主类将如下所示：

```java
package com.packtpub.restapp.ticketmanagement;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
@ComponentScan("com.packtpub")
@SpringBootApplication
public class TicketManagementApplication {
  public static void main(String[] args) {
    SpringApplication.run(TicketManagementApplication.class, args);
  }
}
```

当您重新启动 Spring Boot 应用程序时，您将看到 REST 端点正在工作（`localhost:8080`）：

```java
{
  result: "Aloha"
}
```

# Spring 5 中的 CRUD 操作（不包括 Reactive）

让我们执行用户 CRUD 操作。由于我们之前已经讨论了 CRUD 概念，因此在这里我们只讨论 Spring 5 上的用户管理（不包括 Reactive 支持）。让我们为 CRUD 端点填充所有虚拟方法。在这里，我们可以创建`UserContoller`并填充所有 CRUD 用户操作的方法：

```java
package com.packtpub.restapp;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
@RestController
@RequestMapping("/user")
public class UserController {  
  @ResponseBody
  @RequestMapping("")
  public Map<String, Object> getAllUsers(){
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("result", "Get All Users Implementation");    
    return map;
  }  
  @ResponseBody
  @RequestMapping("/{id}")
  public Map<String, Object> getUser(@PathVariable("id") Integer id){
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("result", "Get User Implementation");    
    return map;
  } 
  @ResponseBody
  @RequestMapping(value = "", method = RequestMethod.POST)
  public Map<String, Object> createUser(){
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("result", "Create User Implementation");    
    return map;
  }  
  @ResponseBody
  @RequestMapping(value = "", method = RequestMethod.PUT)
  public Map<String, Object> updateUser(){
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("result", "Update User Implementation");    
    return map;
  }
  @ResponseBody
  @RequestMapping(value = "", method = RequestMethod.DELETE)
  public Map<String, Object> deleteUser(){
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("result", "Delete User Implementation");    
    return map;
  }
}
```

我们已经为所有 CRUD 操作填充了基本端点。如果您在 Postman 上调用它们，并使用适当的方法，如`GET`，`POST`，`PUT`和`DELETE`，您将看到提到适当消息的结果。

例如，对于`getAllUsers` API（`localhost:8080/user`），您将获得：

```java
{
  result: "Get All Users Implementation"
}
```

# getAllUsers - 实现

让我们实现`getAllUsers` API。对于这个 API，我们可能需要在`com.packtpub.model`包下创建一个名为`User`的模型类：

```java
package com.packtpub.model;
public class User {
  private Integer userid;  
  private String username;   
  public User(Integer userid, String username){
    this.userid = userid;
    this.username = username;
  }  
  // getter and setter methods 
}
```

现在，我们将添加`getAllUsers`实现的代码。由于这是业务逻辑，我们将创建一个单独的`UserService`和`UserServiceImpl`类。通过这样做，我们可以将业务逻辑放在不同的地方，以避免代码复杂性。

`UserService`接口如下所示：

```java
package com.packtpub.service;
import java.util.List;
import com.packtpub.model.User;
public interface UserService {
  List<User> getAllUsers();
}
```

`UserServiceImpl`类的实现如下：

```java
package com.packtpub.service;
import java.util.LinkedList;
import java.util.List;
import org.springframework.stereotype.Service;
import com.packtpub.model.User;
@Service
public class UserServiceImpl implements UserService {
  @Override
  public List<User> getAllUsers() {    
    return this.users;
  }  
  // Dummy users
  public static List<User> users; 
  public UserServiceImpl() {
    users = new LinkedList<>();   
    users.add(new User(100, "David"));
    users.add(new User(101, "Peter"));
    users.add(new User(102, "John"));
  }
}
```

在前面的实现中，我们在构造函数中创建了虚拟用户。当类由 Spring 配置初始化时，这些用户将被添加到列表中。

调用`getAllUsers`方法的`UserController`类如下：

```java
@Autowired
UserService userSevice;
@ResponseBody
@RequestMapping("")
public List<User> getAllUsers(){
    return userSevice.getAllUsers();
}
```

在前面的代码中，我们通过在控制器文件中进行自动装配来调用`getAllUsers`方法。`@Autowired`将在幕后执行所有实例化魔术。

如果您现在运行应用程序，可能会遇到以下错误：

```java
***************************
APPLICATION FAILED TO START
***************************

Description:

Field userSevice in com.packtpub.restapp.UserController required a bean of type 'com.packtpub.service.UserService' that could not be found.

Action:

Consider defining a bean of type 'com.packtpub.service.UserService' in your configuration.
```

这个错误的原因是您的应用程序无法识别`UserService`，因为它在不同的包中。我们可以通过在`TicketManagementApplication`类中添加`@ComponentScan("com.packtpub")`来解决这个问题。这将识别不同子包中的所有`@service`和其他 bean：

```java
@ComponentScan("com.packtpub")
@SpringBootApplication
public class TicketManagementApplication {  
  public static void main(String[] args) {
    SpringApplication.run(TicketManagementApplication.class, args);
  }
}
```

现在您可以在调用 API（`http://localhost:8080/user`）时看到结果：

```java
[
  {
    userid: 100,
    username: "David"
  },
  {
    userid: 101,
    username: "Peter"
  },
  {
    userid: 102,
    username: "John"
  }
]
```

# getUser - 实现

就像我们在第四章中所做的那样，*Spring REST 中的 CRUD 操作*，我们将在本节中实现`getUser`业务逻辑。让我们使用 Java 8 Streams 在这里添加`getUser`方法。

`UserService`接口如下所示：

```java
User getUser(Integer userid);
```

`UserServiceImpl`类的实现如下：

```java
@Override
public User getUser(Integer userid) {     
    return users.stream()
    .filter(x -> x.getUserid() == userid)
    .findAny()
    .orElse(new User(0, "Not Available")); 
}
```

在之前的`getUser`方法实现中，我们使用了 Java 8 Streams 和 lambda 表达式来通过`userid`获取用户。与传统的`for`循环不同，lambda 表达式使得获取详细信息更加容易。在前面的代码中，我们通过过滤条件检查用户。如果用户匹配，它将返回特定用户；否则，它将创建一个带有`"Not available"`消息的虚拟用户。

`getUser`方法的`UserController`类如下：

```java
@ResponseBody
@RequestMapping("/{id}")
public User getUser(@PathVariable("id") Integer id){  
  return userSevice.getUser(100);
}
```

您可以通过访问客户端中的`http://localhost:8080/user/100`来验证 API（使用 Postman 或 SoapUI 进行测试）：

```java
{
  userid: 100,
  username: "David"
}
```

# createUser - 实现

现在我们可以添加创建用户选项的代码。

`UserService`接口如下所示：

```java
void createUser(Integer userid, String username);
```

`UserServiceImpl`类的实现如下：

```java
@Override
public void createUser(Integer userid, String username) {    
    User user = new User(userid, username); 
    this.users.add(user); 
}
```

`createUser`方法的`UserController`类如下：

```java
@ResponseBody
  @RequestMapping(value = "", method = RequestMethod.POST)
  public Map<String, Object> createUser(
    @RequestParam(value="userid") Integer userid,
    @RequestParam(value="username") String username
    ){    
    Map<String, Object> map = new LinkedHashMap<>(); 
    userSevice.createUser(userid, username);    
    map.put("result", "added");
    return map;
}
```

前面的代码将在我们的映射中添加用户。在这里，我们使用`userid`和`username`作为方法参数。您可以在以下 API 调用中查看`userid`和`username`：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/7eeaca9a-ea63-487a-94ef-2274187f0065.png)

当您使用 SoapUI/Postman 调用此方法时，您将获得以下结果。在这种情况下，我们使用参数（`userid`，`username`）而不是 JSON 输入。这只是为了简化流程：

```java
{"result": "added"}
```

# updateUser - 实现

现在我们可以添加更新用户选项的代码。

`UserService`接口如下所示：

```java
void updateUser(Integer userid, String username);
```

`UserServiceImpl`类的实现如下：

```java
@Override
public void updateUser(Integer userid, String username) {
    users.stream()
        .filter(x -> x.getUserid() == userid)
        .findAny()
        .orElseThrow(() -> new RuntimeException("Item not found"))
        .setUsername(username); 
}
```

在前面的方法中，我们使用了基于 Java Streams 的实现来更新用户。我们只需应用过滤器并检查用户是否可用。如果`userid`不匹配，它将抛出`RuntimeException`。如果用户可用，我们将获得相应的用户，然后更新`username`。

`updateUser`方法的`UserController`类如下：

```java
@ResponseBody
  @RequestMapping(value = "", method = RequestMethod.PUT)
  public Map<String, Object> updateUser(
      @RequestParam(value="userid") Integer userid,
      @RequestParam(value="username") String username
    ){
    Map<String, Object> map = new LinkedHashMap<>();
    userSevice.updateUser(userid, username);    
    map.put("result", "updated");    
    return map;
  }
```

我们将尝试将`userid`为`100`的`username`从`David`更新为`Sammy`。我们可以从以下截图中查看 API 的详细信息：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/af20ba48-60bf-42c3-901f-8b2fa59d37d5.png)

当我们使用 SoapUI/Postman 扩展（`http://localhost:8080/user`）调用此 API（`UPDATE`方法）时，我们将得到以下结果：

```java
{"result": "updated"}
```

您可以通过在 Postman 扩展中检查`getAllUsers` API（`GET`方法）（`http://localhost:8080/user`）来检查结果；您将得到以下结果：

```java
[
  {
    "userid": 100,
    "username": "Sammy"
  },
  {
    "userid": 101,
    "username": "Peter"
  },
  {
    "userid": 102,
    "username": "John"
  },
  {
    "userid": 104,
    "username": "Kevin"
  }
]
```

# deleteUser - 实现

现在我们可以添加`deleteUser`选项的代码。

`UserService`接口如下所示：

```java
void deleteUser(Integer userid);
```

`UserServiceImpl`类的实现如下：

```java
@Override
public void deleteUser(Integer userid) { 

   users.removeIf((User u) -> u.getUserid() == userid);

}
```

`UserController`类的`deleteUser`方法如下所示：

```java
@ResponseBody
@RequestMapping(value = "/{id}", method = RequestMethod.DELETE)
public Map<String, Object> deleteUser(
      @PathVariable("id") Integer userid) {
    Map<String, Object> map = new LinkedHashMap<>(); 
      userSevice.deleteUser(userid); 
      map.put("result", "deleted");
      return map;
}
```

当您使用 Postman 扩展调用此 API（`DELETE`方法）（`http://localhost:8080/user/100`）时，您将得到以下结果：

```java
{"result": "deleted"}
```

您还可以检查`getAllUsers`方法，以验证您是否已删除用户。

# 文件上传 - REST API

在支持`NIO`库和 Spring 的`MultipartFile`选项的支持下，文件上传变得非常容易。在这里，我们将添加文件上传的代码。

`FileUploadService`接口如下所示：

```java
package com.packtpub.service;
import org.springframework.web.multipart.MultipartFile;
public interface FileUploadService {
  void uploadFile(MultipartFile file) throws IOException;
}
```

在上述代码中，我们只是定义了一个方法，让具体类（实现类）覆盖我们的方法。我们在这里使用`MultipartFile`来传递文件，例如媒体文件，以满足我们的业务逻辑。

`FileUploadServerImpl`类的实现如下：

```java
package com.packtpub.service;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;
@Service
public class FileUploadServerImpl implements FileUploadService {
  private Path location;  
  public FileUploadServerImpl() throws IOException {
    location = Paths.get("c:/test/");
    Files.createDirectories(location);
  }
  @Override
  public void uploadFile(MultipartFile file) throws IOException {
    String fileName = StringUtils.cleanPath(file.getOriginalFilename());
    if (fileName.isEmpty()) {
      throw new IOException("File is empty " + fileName);
    } try {
      Files.copy(file.getInputStream(), 
            this.location.resolve(fileName),     
            StandardCopyOption.REPLACE_EXISTING);
    } catch (IOException e) {
      throw new IOException("File Upload Error : " + fileName);
    }
  }
}
```

在上述代码中，我们在构造函数中设置了位置，因此当 Spring Boot App 初始化时，它将设置正确的路径；如果需要，它将在指定位置创建一个特定的文件夹。

在`uploadFile`方法中，我们首先获取文件并进行清理。我们使用一个名为`StringUtils`的 Spring 实用类来清理文件路径。您可以在这里看到清理过程：

```java
String fileName = StringUtils.cleanPath(file.getOriginalFilename());
```

如果文件为空，我们只是抛出一个异常。您可以在这里检查异常：

```java
    if(fileName.isEmpty()){
      throw new IOException("File is empty " + fileName);
    }
```

然后是真正的文件上传逻辑！我们只是使用`Files.copy`方法将文件从客户端复制到服务器位置。如果发生任何错误，我们会抛出`RuntimeException`：

```java
try {
      Files.copy(
        file.getInputStream(), this.location.resolve(fileName),  
        StandardCopyOption.REPLACE_EXISTING
      );
    } catch (IOException e) { 
      throw new IOException("File Upload Error : " + fileName);
    }
```

由于具体类已经完成了主要实现，控制器只是将`MultipartFile`传递给服务。我们在这里使用了`POST`方法，因为它是上传文件的完美方法。此外，您可以看到我们使用了`@Autowired`选项来使用`service`方法。

`FileController`类的`uploadFile`方法如下所示：

```java
package com.packtpub.restapp;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import com.packtpub.service.FileUploadService;
@RestController
@RequestMapping("/file")
public class FileController {  
  @Autowired
  FileUploadService fileUploadSevice;
  @ResponseBody
  @RequestMapping(value = "/upload", method = RequestMethod.POST)
  public Map<String, Object> uploadFile(@RequestParam("file") MultipartFile file) {
    Map<String, Object> map = new LinkedHashMap<>();
    try {
      fileUploadSevice.uploadFile(file);      
      map.put("result", "file uploaded");
    } catch (IOException e) {
      map.put("result", "error while uploading : "+e.getMessage());
    }    
    return map;
  }
} 
```

# 测试文件上传

您可以创建一个 HTML 文件如下，并测试文件上传 API。您还可以使用任何 REST 客户端来测试。我已经给您这个 HTML 文件来简化测试过程：

```java
<!DOCTYPE html>
<html>
<body>
<form action="http://localhost:8080/file/upload" method="post" enctype="multipart/form-data">
    Select image to upload:
    <input type="file" name="file" id="file">
    <input type="submit" value="Upload Image" name="submit">
</form>
</body>
</html>
```

# 摘要

在本章中，我们已经介绍了 Spring 5 中的 CRUD 操作（不包括响应式支持），从基本资源开始进行自定义。此外，我们还学习了如何在 Spring 中上传文件。在下一章中，我们将更多地了解 Spring Security 和 JWT（JSON Web Token）。
