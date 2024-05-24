# TypeScript 微服务（三）

> 原文：[`zh.annas-archive.org/md5/042BAEB717E2AD21939B4257A0F75F63`](https://zh.annas-archive.org/md5/042BAEB717E2AD21939B4257A0F75F63)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：服务状态和服务间通信

现在我们已经开发了一些微服务，看到了 API 网关，并了解了服务注册表和发现，现在是时候深入了解微服务，并从单个微服务的角度了解系统。为了从微服务架构中获得最大的好处，系统中的每个组件都必须以恰当的方式进行协作，这种方式可以确保微服务之间几乎没有耦合，这将使我们能够灵活应对。

在本章中，我们将了解微服务之间的各种通信方式，以及服务之间如何交换数据。然后我们将转向服务总线，这是系统组件之间如何通信的企业方式。许多服务需要以一种形式或另一种形式持久化一些状态。我们将看到如何使我们的服务无状态。我们将了解当前的数据库格局并理解服务状态。我们将了解发布-订阅模式，并了解诸如 Kafka 和 RabbitMQ 之类的工具，以了解事件驱动架构。本章涵盖以下主题：

+   核心概念-状态、通信和依赖关系

+   通信方式

+   同步与异步的数据共享方式

+   微服务版本控制和故障处理

+   服务总线

+   微服务之间的数据共享

+   通过 Redis 进行缓存

+   发布-订阅模式

# 核心概念-状态、通信和依赖关系

每个微服务实现一个单一的能力，比如发货和从库存中扣除。然而，为了向最终用户交付一个服务请求，比如业务能力、用户需求或用户特定请求；可能是一组业务能力，也可能不是。例如，从用户的角度来看，想要购买产品的人是一个单一的服务请求。然而，这里涉及到多个请求，比如加入购物车微服务、支付微服务、发货微服务。因此，为了交付，微服务需要相互协作。在本节中，我们将看到微服务协作的核心概念，如服务状态、通信方式等。选择正确的通信方式有助于设计一个松散耦合的架构，确保每个微服务都有清晰的边界，并且它保持在其有界上下文内。在本节中，我们将看一些核心概念，这些概念将影响我们的微服务设计和架构。所以，让我们开始吧。

# 微服务状态

虽然我们确实应该努力使服务尽可能无状态，但有些情况下我们确实需要有状态的服务。状态只是在任何特定时间点的任何条件或质量。有状态的服务是依赖于系统状态的服务。有状态意味着依赖于这些时间点，而无状态意味着独立于任何状态。

在需要调用一些 REST 服务的工作流中，有状态的服务是必不可少的，我们需要在失败时支持重试，需要跟踪进度，存储中间结果等。我们需要在我们的服务实例边界之外的某个地方保持状态。这就是数据库出现的地方。

数据库是一个重要且有趣的思考部分。在微服务中引入数据库应该以这样一种方式进行，即其他团队不能直接与我们的数据库交谈。事实上，他们甚至不应该知道我们的数据库类型。当前的数据库格局对我们来说有各种可用的选项，包括 SQL 和 NoSQL 类别。甚至还有图数据库、内存数据库以及具有高读写能力的数据库。

我们的微服务可以既有无状态的微服务，也有有状态的微服务。如果一个服务依赖于状态，它应该被分离到一个专用容器中，这个容器易于访问，不与任何人共享。无状态的微服务具有更好的扩展性。我们扩展容器而不是扩展虚拟机。因此，每个状态存储应该在一个容器中，可以随时进行扩展。我们使用 Docker 来扩展数据库存储，它创建一个独立的持久化层，与主机无关。新的云数据存储，如 Redis、Cassandra 和 DynamoDB，最大程度地提高了可用性，同时最小化了一致性的延迟。设计具有异步和可扩展性特性的有状态微服务需要在问题上进行一些思考——找到一些通信状态的方法，以确保任何连续消息之间的通信状态，并确保消息不会混淆到任何不属于它们的上下文中。在本章中，我们将看到各种同步模式，如 CQRS 和 Saga，以实现这一点。

维护状态不仅仅是在服务层面上可以完成的事情。实际上，在网络中有三个地方可以维护状态：

+   **HTTP**：这实际上是应用层，大部分维护状态都是基于会话或持久化在数据库中。一般来说，通过在客户端和应用程序或服务之间维护通信层来维护状态。

+   **TCP**：这实际上是传输层。在这里维护状态的目的是确保客户端和应用程序或服务之间有一个可靠的传递通道。

+   **SSL**：这是在 TCP 和 HTTP 层之间没有家的层。它提供数据的机密性和隐私性。在这里维护状态，因为加密和解密完全依赖于客户端和应用程序或服务之间的连接的唯一信息。

因此，即使我们的服务是无状态的，TCP 和 SSL 层也需要维护状态。所以你永远不是纯粹的无状态。无论如何，我们将仅限于本书的范围内的应用层。

# 服务间通信

微服务因为粒度细和与范围紧密相关，需要以某种方式相互协作，以向最终用户提供功能。它们需要共享状态或依赖关系，或者与其他服务进行通信。让我们看一个实际的例子。考虑频繁购买者奖励计划微服务。这个微服务负责频繁购买者业务能力的奖励。该计划很简单——每当客户购买东西时，他们的账户中就会积累一些积分。现在，当客户购买东西时，他可以使用这些奖励积分来获得销售价格的折扣。奖励微服务依赖于客户购买微服务和其他业务能力。其他业务能力依赖于奖励计划。如下图所示，微服务需要与其他微服务协作：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/35077dd7-21de-47d6-a900-73df46b1d16f.png)

微服务的需求

如前图所示，微服务被细分为业务能力。然而，最终用户功能需要多个业务能力，因此微服务必须需要相互协作，以向最终用户提供用例。当任何微服务协作时，协作方式主要分为三类——**命令**、**查询**和**事件**。让我们通过一些例子来了解这三类。

# 命令

命令在任何微服务想要另一个微服务执行操作时使用。它们是同步的，通常使用 HTTP POST 或 PUT 请求来实现。例如，在前面的图中，奖励计划微服务向用户配置文件微服务或发票微服务发送命令，关于基于奖励的促销优惠。当发送命令失败时，发送者将不知道接收者是否处理了命令。如果发送方和接收方没有遵循一组规则，这可能导致错误或一些功能降级。

# 查询

与命令类似，查询在一个微服务需要从另一个微服务获取一些信息时使用。例如，在我们的购物车微服务中的发票过程中，我们需要有关奖励积分总数的信息，以便提供促销折扣，因此发票微服务查询奖励积分微服务。这是一种同步的通信模式，通常使用 HTTP GET 请求。每当查询失败时，调用者将无法获取所需的数据。如果调用者能够很好地处理异常，那么影响将很小，但功能可能会有所降级。如果处理错误不够好，错误将在整个系统中传播。

# 事件

在偏离标准方法的同时，第三种方法更多地是一种反应性方法。事件通常在一个微服务需要对另一个微服务中发生的事情做出反应时使用。自定义日志微服务监听所有其他服务的日志条目，以便它可以将日志推送到 Elasticsearch。类似地，奖励微服务监听购物追踪微服务，以便根据用户购物相应地更新用户奖励。当订阅者轮询任何事件源，如果调用失败，影响非常有限。订阅者仍然可以稍后轮询事件源，直到事件源恢复，并随时开始接收事件。一些事件将被延迟，但这不应该是一个问题，因为一切都是异步完成。

# 交换数据格式

微服务之间通信的本质或基本是以任何格式交换消息。消息通常包含数据，因此数据格式是非常重要的设计方面。这可以极大地影响通信的效率、可用性和变化，以及随时间演变的服务。选择跨消息格式非常必要。有两种消息格式——文本和二进制。在本节中，我们将看看两者。

# 基于文本的消息格式

常用的消息格式，如 JSON 和 XML，是人类可读的并且是自描述的。这些格式使用户能够挑选出消费者感兴趣的值并丢弃其余部分。对模式格式的任何更改都可以很容易地向后兼容。使用基于文本的格式的缺点包括其本质上过于冗长以及解析整个文本的开销。为了更高效，建议使用二进制格式。

# 二进制消息格式

这些格式为消息定义了一个结构的类型标识语言。然后编译器为我们生成序列化和反序列化消息的代码（我们将在本章后面看到 Apache Thrift）。如果客户端使用的是静态类型的语言，那么编译器会检查 API 是否被正确使用。Avro、Thrift 和 Google 的 protobuf 是著名的二进制消息格式。

现在我们对通信要点有了清晰的了解，我们可以继续下一节的依赖性。在继续之前，让我们总结一下要点。

如果满足以下用例，可以选择使用命令和查询：

+   为了处理服务请求，服务客户端需要响应以进一步推进其流程。例如，对于支付微服务，我们需要客户信息。

+   情况需要异步操作。例如，只有在付款已经完成并且产品已经处理好准备交付给客户时，才应扣减库存。

+   对其他服务的请求是一个简单的查询或命令，即可以通过 HTTP `GET`、`PUT`、`POST`和`DELETE`方法处理的内容。

如果满足以下用例，可以选择使用事件：

+   当您需要扩展应用程序时，纯命令和查询无法扩展到更大的问题集。

+   生产者或发送方不关心接收方或消费者端进行了多少额外的处理，这对生产者端没有影响。

+   当多个客户端读取单个消息时。例如，订单已开具发票，然后需要执行多个流程，如准备发货、更新库存、发送客户通知等。

# 依赖关系

现在我们已经意识到微服务中的通信风格，我们将学习开发中的下一个显而易见的事情——依赖关系和避免依赖地狱。随着越来越多的微服务的开发，你会发现多个微服务之间存在代码重复。为了解决这些问题，我们需要理解依赖关系以及如何分离支持代码。Node.js 拥有包管理器 NPM，可以获取应用程序的依赖项（以及依赖项的依赖项）。NPM 支持私有存储库，可以直接从 GitHub 下载，设置自己的存储库（如 JFrog、Artifactory），这不仅有助于避免代码重复，还有助于部署过程。

然而，我们不应忘记**微服务 101**。我们创建微服务是为了确保每个服务都可以独立发布和部署，因此我们必须避免依赖地狱。要理解依赖地狱，让我们考虑以下示例，购物车微服务具有列出产品的 API，现在已升级为具有特定品牌产品列表的 API。现在购物车微服务的所有依赖关系可能会发送消息到最初用于列出产品的特定品牌产品列表。如果不处理向后兼容性，那么这将演变成依赖地狱。为了避免依赖地狱，可以使用的策略包括——API 必须是前向和后向兼容的，它们必须有准确的文档，必须进行合同测试（我们将在第八章中看到，*测试、调试和文档*，在*PACT*下），并使用一个具有明确目标的适当工具库，如果遇到未知字段，则会抛出错误。为了确保我们要避免依赖地狱，我们必须简单地遵循这些规则：

+   微服务不能调用另一个微服务，也不能直接访问其数据源

+   微服务只能通过基于事件的机制或某些微服务脚本（脚本可以是任何东西，如 API 网关、UI、服务注册表等）调用另一个微服务

在下一节中，我们将研究微服务通信风格，看看它们如何相互协作。我们将研究基于不同分类因素的广泛使用的模式，并了解在什么时候使用哪种模式的场景。

# 通信风格

微服务生态系统本质上是在多台机器上运行的分布式系统。每个服务实例只是另一个进程。我们在之前的图表中看到了不同的进程通信。在本节中，我们将更详细地了解通信风格。

服务消费者和服务响应者可以通过许多不同类型的通信风格进行通信，每种通信风格都针对某些场景和预期结果。通信类型可以分为两个不同的方面。

第一个方面涉及协议类型，即同步或异步：

+   通过命令和查询（如 HTTP）调用的通信是同步的。客户端发送请求等待服务端响应。这种等待是与语言相关的，即可以是同步的（例如 Java 等语言），也可以是异步的（响应可以通过回调、承诺等方式处理，在我们的例子中是 Node.js）。重要的是，只有客户端收到正确的 HTTP 服务器响应后，服务请求才能得到服务。

+   其他协议，如 AMQP、sockets 等，都是异步的（日志和购物跟踪微服务）。客户端代码或消息发送者不会等待响应，只需将消息发送到任何队列或消息代理即可。

第二个方面涉及接收者的数量，无论是只有一个接收者还是有多个接收者：

+   对于单个接收者，每个请求只能由一个接收者或服务处理。命令和查询模式就是这种通信的例子。一对一的交互包括请求/响应模型，单向请求（如通知）以及请求/异步响应。

+   对于多个接收者，每个请求可以由零个或多个服务或接收者处理。这是一种异步的通信模式，以发布-订阅机制为例，促进事件驱动架构。多个微服务之间的数据更新通过通过某些服务总线（Azure 服务总线）或任何消息代理（AMQP、Kafka、RabbitMQ 等）实现的事件进行传播。

# 下一代通信风格

虽然我们看到了一些常见的通信风格，但世界在不断变化。随着各处的进化，甚至基本的 HTTP 协议也发生了变化，现在我们有了 HTTP 2.X 协议，带来了一些额外的优势。在本节中，我们将看看下一代通信风格，并了解它们所提供的优势。

# HTTP/2

HTTP/2 提供了显著的增强，并更加关注改进 TCP 连接的使用。与 HTTP/1.1 相比，以下是一些主要的增强：

+   **压缩和二进制帧**：HTTP/2 内置了头部压缩，以减少 HTTP 头部的占用空间（例如，cookies 可能增长到几千字节）。它还控制了在多个请求和响应中重复的头部。此外，客户端和服务器维护一个频繁可见字段的列表，以及它们的压缩值，因此当这些字段重复时，个体只需包含对压缩值的引用。除此之外，HTTP/2 使用二进制编码进行帧。

+   **多路复用**：与单一请求和响应流（客户端必须在发出下一个请求之前等待响应）相比，HTTP/2 通过实现流（哇，响应式编程！）引入了完全异步的请求多路复用。客户端和服务器都可以在单个 TCP 连接上启动多个请求。例如，当客户端请求网页时，服务器可以启动一个单独的流来传输该网页所需的图像和视频。

+   **流量控制**：随着多路复用的引入，需要有流量控制来避免在任何流中出现破坏性行为。HTTP/2 为客户端和服务器提供了适用于任何特定情况的适当流量控制的构建模块。流量控制可以让浏览器只获取特定资源的一部分，通过将窗口减小到零来暂停该操作，并在任何时间点恢复。此外，还可以设置优先级。

在本节中，我们将看看如何在我们的微服务系统中实现 HTTP/2。您可以查看`第七章`下的`示例 http2`，并跟随实现的源代码。

1.  Node.js 10.XX 支持 HTTP/2，但也有其他方法可以实现支持，而无需升级到最新版本，该版本是在写作时刚刚推出的（Node.js 10.XX 在写作时刚刚推出了两周）。我们将使用`spdy`节点模块，为我们的`Express`应用程序提供 HTTP/2 支持。从第二章中复制我们的`first-microservice`骨架，*为旅程做准备*，并使用以下命令将`spdy`安装为节点模块：

```ts
npm install spdy --save
```

1.  为了使 HTTP/2 正常工作，必须启用 SSL/TLS。为了使我们的开发环境正常工作，我们将自动生成 CSR 和证书，这些证书可以在生产环境中轻松替换。要生成证书，请按照以下命令进行操作：

```ts
// this command generates server pass key.
openssl genrsa -des3 -passout pass:x -out server.pass.key 2048
//we write our RSA key and let it generate a password
openssl rsa -passin pass:x -in server.pass.key -out server.key
rm server.pass.key //this command removes the pass key, as we are just on dev env
//following commands generates the csr file
openssl req -new -key server.key -out server.csr
//following command generates server.crt file
openssl x509 -req -sha256 -days 365 -in server.csr -signkey server.key -out server.crt
```

所有这些步骤的结果将产生三个文件：`server.crt`、`server.csr`和`server.key`。

1.  接下来，我们需要更改启动 express 服务器的方式。我们需要使用`spdy`提供的方法，而不是使用默认方法。在`Application.ts`中进行以下更改。用以下代码替换`this.express.app.listen`：

```ts
import * as spdy from 'spdy';
 const certsPath = path.resolve('certs');
 const options={         
     key:fs.readFileSync(certsPath+"/server.key"),
     cert:fs.readFileSync(certsPath+"/server.crt")
 }...
this.server=spdy.createServer(options,this.express.app)
                  .listen(port,(error:any)=>{                       
                  if(error){
                      logger.error("failed to start 
                      server with ssl",error);
                      return process.exit(1);}else{
                      logger.info(`Server Started! Express:                 
                      http://localhost:${port}`); }})
```

1.  我们已经准备好开始处理 HTTP/2 请求了。启动服务器并打开`https://localhost:3000/hello-world`。打开开发者控制台，您应该能够看到 HTTP/2，就像以下截图中一样：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/cf4057f7-f62e-4842-ab95-c2ed89c68b71.png)

HTTP 支持

这些是 HTTP 调用。在下一节中，我们将看一下 RPC 机制，这是微服务之间协作的另一种方式。

# 使用 Apache Thrift 的 gRPC

**gRPC**是一个专为编写跨语言 RPC（远程过程调用）客户端和服务器而设计的框架。它使用二进制格式，并专注于以 API 优先的方式设计任何服务。它提供固定的 IDL（交互式数据语言固定格式），以后可以生成符合该固定 IDL 格式的客户端存根和服务器端骨架。编译器可以为大多数语言生成代码，并且它们使用 HTTP/2 进行数据交换，这在长期内是有益的。Apache Thrift 是编写跨语言 RPC 客户端和服务器的一个很好的替代方案。它具有 C 风格的 IDL 定义语言。编译器可以为各种语言生成代码，包括 C++、Java，甚至 TypeScript。Thrift 定义与 TypeScript 接口非常类似。Thrift 方法可以输出任何值，或者它们可以只是单向通信。具有返回类型的方法实现请求/响应模型，而没有返回类型的方法被定义为实现通知模型。Thrift 还支持 JSON 和二进制。让我们从一个示例开始。您可以在提取的源代码中的第七章中的`thrift-rpc`文件夹中跟随。

我们要做的整个过程如下：

+   编写一个`.thrift`文件，描述我们的产品微服务和受欢迎度微服务

+   为我们将要编写的服务通信生成 TypeScript 的源代码

+   导入生成的代码并开始编写我们的服务

+   将受欢迎度的生成源包含在产品中并编写我们的服务

+   创建 API 网关作为单一入口点

尽管 Thrift 提供了 Node.js 和 TypeScript 库，但我们将使用**CreditKarma**（[`github.com/creditkarma`](https://github.com/creditkarma)）的`npm`模块，因为原始模块在生成严格类型方面存在不足。所以让我们开始吧。

现在，让我们执行以下步骤：

1.  初始化一个 Node.js 项目。我将使用`npm`模块而不是下载 Thrift。因此，将以下模块安装为依赖项：

```ts
npm install  @creditkarma/dynamic-config  @creditkarma/thrift-client @creditkarma/thrift-server-core @creditkarma/thrift-server-express @creditkarma/thrift-typescript --save
```

1.  创建一个名为`thrift`的文件夹，在其中创建两个 Thrift 文件——`PopularityService.thrift`（`thrift/popularity/PopularityService.thrift`）和`ProductService.thrift`（`thrift/product/ProductService.thrift`）。Thrift 文件就像 TypeScript 接口：

```ts
namespace js com.popularity
struct Popularity {
    1: required i32 id
    2: required i32 totalStars
    3: required string review
    4: required i32 productId}
exception PopularityServiceException {
    1: required string message}
service PopularityService {
    Popularity getPopularityByProduct(4: i32 productId) 
    throws (1: PopularityServiceException exp)}
```

由于我们需要在产品中使用流行度，我们将在`ProductService.thrift`中导入它，您可以在此处检查其他默认语法[`thrift.apache.org/docs/idl`](https://thrift.apache.org/docs/idl)。

1.  现在，我们将使用在前一步中定义的 IDL 文件生成我们的代码。打开`package.json`并在`scripts`标签内添加以下脚本：

```ts
"precodegen": "rimraf src/codegen",
"codegen": "npm run precodegen && thrift-typescript --target thrift-server --sourceDir thrift --outDir src/codegen"
```

这个脚本将为我们生成代码，我们只需要输入`npm run codegen`。

1.  下一部分涉及编写`findByProductId`和`findPopularityOfProduct`方法。在提取的源代码中查看`src/popularity/data.ts`和`src/product/data.ts`以获取虚拟数据和虚拟查找方法。

1.  我们现在将编写代码来启动`PopluarityThriftService`和`ProductThriftService`。在`src/popularity/server.ts`内创建一个`serviceHandler`如下：

```ts
const serviceHandler: PopularityService.IHandler<express.Request> = {
    getPopularityByProduct(id: number, context?:  
    express.Request): Popularity {
        //find method which uses generated models and types.
},
```

1.  通过将`ThriftServerExpress`添加为中间件，将此`server.ts`作为`express`启动：

```ts
app.use(serverConfig.path,bodyParser.raw(),
ThriftServerExpress({
    serviceName: 'popularity-service',
    handler: new PopularityService.Processor(serviceHandler),
}), ) 
app.listen(serverConfig.port, () => {//server startup code)})
```

1.  现在，在`src/product/server.ts`内，添加以下代码，将对`PopularityService`进行 RPC 调用以获取`productId`的流行度：

```ts
const popularityClientV1: PopularityService.Client = createHttpClient(PopularityService.Client, clientConfig)
const serviceHandler: ProductService.IHandler<express.Request> = {
    getProduct(id: number, context?: express.Request):      
    Promise<Product> {
        console.log(`ContentService: getProduct[${id}]`)
        const product: IMockProduct | undefined = findProduct(id)
        if (product !== undefined) {
            return       
            popularityClientV1.getPopularityByProduct(product.id)
            .then((popularity: Popularity) => {
            return new Product({
            id: product.id,
            feedback:popularity,
            productInfo: product.productInfo,
            productType: product.productType,
        })
})} else {
throw new ProductServiceException({
    message: `Unable to find product for id[${id}]`,
})}},}
```

1.  同样，`create gateway/server.ts`。为`/product/: productId`定义一个路由，并将其作为 RPC 调用`ProductMicroservice`来获取传递的`productId`的数据。

1.  运行程序并向`localhost:9000/product/1`发出请求，您将能够通过 RPC 调用看到组合通信响应。

在本节中，我们亲身体验了一些微服务通信风格以及一些实践。在下一节中，我们将看到如何对微服务进行版本控制，并使我们的微服务具有故障安全机制。

# 微服务版本控制和故障处理

进化是必要的，我们无法阻止它。每当我们允许其中一个服务进化时，服务版本控制就是维护的一个最重要的方面。在本节中，我们将看到与系统变化处理和克服系统中引入的任何故障相关的各种方面。

# 版本控制 101

首先应该考虑服务版本控制，而不是将其作为开发后的练习。API 是服务器和消费者之间的公开合同。维护版本帮助我们发布新服务而不会破坏现有客户的任何内容（并非每个人都在第一次尝试中接受变化）。新版本和旧版本应该并存。

流行的版本控制风格是使用语义版本。任何语义版本都有三个主要组成部分——**major**（每当有重大变化时），**minor**（每当有向后兼容的行为时），和**patch**（向后兼容的任何错误修复）。当微服务中有多个服务时，版本控制是极其棘手的。推荐的方法是在服务级别而不是在操作级别对任何服务进行版本控制。如果在任何操作中有单个更改，服务将升级并部署到**Version2**（**V2**），这适用于服务中的所有操作。我们可以以三种方式对任何服务进行版本控制：

+   **URI 版本控制**：服务的版本号包含在 URL 本身中。我们只需要担心这种方法的主要版本，因为那会改变 URL 路由。如果有次要版本或任何可用的补丁，消费者无需担心变化。保持最新版本的别名为非版本化的 URI 是需要遵循的良好实践之一。例如，URL `/api/v5/product/1234`应该被别名为`/api/product/1234`—别名为`v5`。此外，传递版本号也可以这样做：

```ts
 /api/product/1234?v=1.5
```

+   **媒体类型版本控制**：媒体类型版本控制采用略有不同的方法。这里，版本由客户端在 HTTP Accept 标头上设置。其结构与`Accept: application/vnd.api+json`类似。Accept 标头为我们提供了一种指定通用和不太通用的内容类型以及提供回退的方法。例如，`Accept: application/vnd.api.v5+json`命令明确要求 API 的`v5`版本。如果省略了 Accept 标头，消费者将与最新版本交互，这可能不是生产级别的。GitHub 使用这种版本控制。

+   **自定义标头**：最后一种方法是维护我们自己的自定义标头。消费者仍然会使用 Accept 标头，并在其上添加一个新的标头。它可能是这样的：`X-my-api-version:1`。

当比较前面三种方法时，客户端在 URI 方法中消费服务很简单，但在 URI 方法中管理嵌套的 URI 资源可能会很复杂。与媒体类型版本控制相比，基于 URI 的方法在迁移客户端时更复杂，因为我们需要维护多个版本的缓存。然而，大多数大公司，如谷歌、Salesforce 等，都采用 URI 方法。

# 当开发人员的噩梦成真

所有系统都会经历故障。微服务是分布式的，故障的概率非常高。我们如何处理故障和应对故障是定义开发人员的关键。虽然使整体产品生态系统具有弹性是令人惊叹的（活动包括集群服务器、设置应用程序负载均衡器、在多个位置之间分配基础设施以及设置灾难恢复），但我们的工作并不止于此。这部分只涉及系统的完全丢失。然而，每当服务运行缓慢或存在内存泄漏时，由于以下原因，极其难以检测问题：

+   服务降级开始缓慢，但迅速获得动力并像感染一样传播。应用程序容器完全耗尽其线程池资源，系统崩溃。

+   太多的同步调用，调用者必须无休止地等待服务返回响应。

+   应用程序无法处理部分降级。只要任何服务完全停机，应用程序就会继续调用该服务，很快就会出现资源耗尽。

这种情况最糟糕的是，这种故障会像传染病一样级联并对系统产生不利影响。一个性能不佳的系统很快就会影响多个依赖系统。有必要保护服务的资源，以免因其他性能不佳的服务而耗尽。在下一节中，我们将看一些模式，以避免系统中的故障级联并引起连锁效应。

# 客户端弹性模式

客户端弹性模式允许客户端快速失败，不会阻塞数据库连接或线程池。这些模式在调用任何远程资源的客户端层中实现。有以下四种常见的客户端弹性模式：

+   舱壁和重试

+   客户端负载均衡或基于队列的负载平衡

+   断路器

+   回退和补偿交易

这四种模式可以在下图中看到：

！[](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/236387ce-c92c-4ff1-a1e8-04fadc93b610.png)

客户端弹性模式

# 舱壁和重试模式

舱壁模式类似于建造船舶的模式，其中船被分成完全隔离和防水的舱壁。即使船体被刺穿，船也不会受到影响，因为它被分成防水的舱壁。舱壁将水限制在发生刺穿的船体特定区域，并防止船沉没。

类似的概念也适用于与许多远程资源交互的隔离模式。通过使用这种模式，我们将对远程资源的调用分解为它们自己的隔离区（自己的线程池），减少风险并防止应用因远程资源缓慢而崩溃。如果一个服务缓慢，那么该类型服务的线程池将变得饱和，以阻止进一步处理请求。对另一个服务的调用不会受到影响，因为每个服务都有自己的线程池。重试模式帮助应用程序处理任何预期的临时故障，每当它尝试连接到服务或任何网络资源时，通过透明地重试先前由于某些条件而失败的操作。它不是等待，而是进行固定次数的重试。

# 客户端负载均衡或基于队列的负载均衡模式

我们在第六章中看到了客户端负载均衡，*服务注册和发现*。它涉及客户端从任何服务发现代理（Eureka/Consul）查找所有服务的各个实例，然后缓存可用服务实例的位置。每当有进一步的请求时，客户端负载均衡器将从维护在客户端的服务位置池中返回一个位置。位置会根据一定的间隔定期刷新。如果客户端负载均衡器检测到任何服务位置存在问题，它将从池中移除它，并阻止任何进一步的请求命中该服务。例如，Netflix Ribbon。另一种弹性方法包括添加一个队列，作为任何任务和/或服务调用之间的缓冲，以便平稳处理任何间歇性负载，并防止数据丢失。

# 断路器模式

我们已经在第一章中看到了这种模式，*揭秘微服务*。让我们快速回顾一下。每当我们安装了断路器并调用远程服务时，断路器会监视调用。如果调用时间过长，断路器将终止调用并打开断路，使进一步的调用变得不可能。这就是快速失败，快速恢复的概念。

# 备用和补偿事务模式

在这种模式中，每当远程服务调用失败时，消费者会尝试以替代方式执行该操作，而不是生成异常。通常实现这一点的方法包括从备用数据源（比如缓存）获取数据，或将用户的输入排队以供将来处理。用户将被通知他们的请求将在以后处理，如果所有路由失败，系统会尝试补偿已经处理的任何操作。我们使用的一些常见的备用方法（由 Netflix 强调）包括：

+   **缓存**：如果实时依赖项丢失，则从本地或远程缓存获取数据，定期刷新缓存数据以避免旧数据

+   **最终一致性**：在服务可用时将数据持久化到队列中以进一步处理

+   **存根数据**：保留默认值，并在个性化或服务响应不可用时使用

+   **空响应**：返回空值或空列表

现在，让我们看一些实际案例研究，以处理故障并防止它们级联或造成连锁反应。

# 案例研究 - NetFlix 技术栈

在这个案例研究中，我们将拥抱 Netflix 堆栈并将其应用于我们的微服务。自时间开始以来，我们听说过：多语言开发环境。我们将在这里做同样的事情。在本节中，我们将使用 ZUUL 设置 API 网关，使用 Java 和 Typescript 添加自动发现。用户将不知道实际请求命中了哪里，因为他只会访问网关。案例研究的第一部分涉及介绍 Zuul、Eureka 并在其中注册一些服务，以及通过中央网关进行通信。下一部分将涉及更重要的事情，比如如何处理负载平衡、安全等。所以让我们开始吧。您可以在`Chapter 7/netflix`云文件夹中跟随示例。除非非常必要，否则我们不会重新发明轮子。让我们尽可能地利用这些资源。以下案例研究支持并鼓励多语言架构。所以让我们开始吧。

# 第一部分 - Zuul 和多语言环境

让我们看看以下步骤：

1.  首先我们需要的是一个网关（第五章，*理解 API 网关*）和服务注册和发现（第六章，*服务注册和发现*）解决方案。我们将利用 Netflix OSS 的 Zuul 和 Eureka。

1.  首先我们需要一个 Eureka 服务器，将源代码从`Chapter-6/ eureka/eureka-server`复制到一个新文件夹，或者按照第六章中的步骤，在 Eureka 部分创建一个新的服务器，该服务器将在 JVM 上运行。

1.  没有什么花哨的，只需在相关位置添加注释`@EnableEurekaServer`和`@SpringBootApplication`—`DemoServiceDiscoveryApplication.java`。

1.  通过添加以下内容在`application.properties`文件中配置属性，如端口号、健康检查：

```ts
eureka:
  instance:
    leaseRenewalIntervalInSeconds: 1         
    leaseExpirationDurationInSeconds: 2
  client:
  serviceUrl:
    defaultZone: http://127.0.0.1:8761/eureka/
    registerWithEureka: false
    fetchRegistry: true
  healthcheck:
    enabled: true
  server:
    port: 8761
```

1.  通过以下命令运行 Eureka 服务器：

```ts
mvn clean install && java -jar target\demo-service-discovery-0.0.1-SNAPSHOT.jar
```

您应该能够在端口`8761`上看到 Eureka 服务器正在运行。

1.  接下来是 Zuul 或我们的 API 网关。Zuul 将作为任何服务请求的路由点，同时它将与 Eureka 服务器保持不断联系。我们将启用服务与 Zuul 的自动注册，也就是说，如果任何服务注册或注销，我们不必重新启动 Zuul。将我们的网关放在 JVM 中而不是 Node.js 中也将显著提高耐用性。

1.  打开[`start.spring.io/`](https://start.spring.io/)并通过添加 Zuul 和 Eureka 发现作为依赖项来生成项目。（您可以在`Chapter 7/netflix cloud`下找到`zuuul-server`）。

1.  打开`NetflixOsssApplication`并在顶部添加以下注释。

```ts
@SpringBootApplication
@EnableDiscoveryClient
@EnableZuulProxy
public class NetflixOsssApplication { ...}
```

1.  接下来，我们将使用应用程序级属性配置我们的 Zuul 服务器：

```ts
server.port=8762
spring.application.name=zuul-server
eureka.instance.preferIpAddress=true
eureka.client.registerWithEureka=true
eureka.client.fetchRegistry=true
eureka.serviceurl.defaultzone=http://localhost:9091/eureka/
```

1.  通过`mvn clean install && java -jar target\netflix-osss-0.0.1-SNAPSHOT.jar`运行应用程序

1.  您应该能够在 Eureka 仪表板中看到您的 Zuul 服务器已注册，这意味着 Zuul 已经成功运行起来。

1.  接下来，我们将在 Node.js 和 Java 中创建一个服务，并在 Eureka 中注册它，因为 Zuul 已启用自动注册，我们的服务将直接路由，无需其他配置。哇！

1.  所以首先让我们创建一个 Node.js 微服务。通过在`Application.ts`（初始化 Express 的地方）中添加以下代码将您的微服务注册到 Eureka：

```ts
 let client=new Eureka({
     instance: {
         instanceId:'hello-world-chapter-6',
         app: 'hello-world-chapter-6',
         //other attributes
     }, vipAddress: 'hello-world-chapter-6',
     eureka: {
         host: 'localhost',
         port: 8761,
         servicePath: '/eureka/apps/',
     }
 });
```

我们没有做任何新的事情，这是我们在第六章中的相同代码。只需记住`instanceId`，`vipAddress`应该相同。

1.  现在通过`npm start`运行服务。它将在端口`3001`上打开，但我们的 Zuul 服务器正在端口`8762`上监听。因此，访问 URL `http://localhost:8762/hello-world-chapter-6`，其中`hello-world-chapter-6`是`vipAddress`或应用程序名称。您将能够看到相同的输出。这证实了我们 Zuul 服务器的工作。

1.  为了进一步了解微服务，我在 Java 中添加了一个微服务(`http://localhost:8080/product`)（没有花哨的东西，只是一个 GET 调用，请检查文件夹`java-microservice`）。在注册运行在端口`8080`的微服务之后，当我通过我的网关(`http://localhost:8762/java-microservice-producer/product`)进行检查时，它就像魅力一样运行。

我们的另一个可行选项包括使用 Netflix Sidecar。14.让我们休息一下，给自己鼓掌。我们已经实现了可以处理任何语言服务的自动注册/注销。我们已经创建了一个多语言环境。

# B 部分- Zuul，负载平衡和故障恢复

哇！！*A 部分*太棒了。我们将继续同样的轨道。我们盘子里的下一部分是，当交通繁忙时会发生什么。在这一部分中，我们将看到如何利用 Zuul，它具有内置的 Netflix Ribbon 支持，以在没有太多麻烦的情况下负载平衡请求。每当请求到达 Zuul 时，它会选择其中一个可用的位置，并将服务请求转发到那里的实际服务实例。整个过程都是缓存实例的位置并定期刷新它和

将请求转发到实际位置是无需任何配置即可获得的。在幕后，Zuul 使用 Eureka 来管理路由。此外，我们将在此示例中看到断路器，并在 Hystrix 仪表板中配置它以查看实时分析。在本节中，我们将配置断路器并将这些流发送到 Hystrix。所以让我们开始吧。您可以在`第七章/ hystrix`中跟随示例：

1.  在提取的源代码中抓取`standalone-hystrix-dashboard-all.jar`并输入`java -jar standalone-hystrix-dashboard-all.jar`命令。这将在端口`7979`上打开 Hystrix 仪表板。验证 URL`http://localhost:7979/hystrix-dashboard`以检查：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/00fa516c-e477-4428-90f8-2055fba54958.png)

1.  是时候编写一个简单的程序，在某个时间点打开一个电路。我们将利用`opossum`模块([`www.npmjs.com/package/opossum`](https://www.npmjs.com/package/opossum))来打开一个电路。通过`npm install opossum --save`命令安装 opossum 模块，并写下其自定义类型，因为它们尚不可用。

1.  我们将编写一个简单的逻辑。我们将初始化一个数字，如果达到阈值，那么电路将被打开-打开状态，我们的回退函数将触发。让我们做必要的事情。

1.  让我们定义我们的变量：

```ts
private baseline:number;
private delay:number;
private circuitBreakerOptions = {
    maxFailures: 5,
    timeout: 5000,
    resetTimeout: 10000, //there should be 5 failures
    name: 'customName',
    group: 'customGroupName'
};
```

1.  我们从计数 20 开始，并使用两个变量在时间上进行比较：

```ts
this.baseline=20;
 this.delay = this.baseline;
```

1.  我们定义`circuitBreaker`并指示我们的 express 应用程序使用它：

```ts
import * as circuitBreaker from 'opossum';
    const circuit = circuitBreaker(this.flakeFunction,   
    this.circuitBreakerOptions);
    circuit.fallback(this.fallback);
    this.app.use('/hystrix.stream', 
    hystrixStream(circuitBreaker));
    this.app.use('/', (request:any, response:any) => {
        circuit.fire().then((result:any) => {
            response.send(result);
        }).catch((err:any) => {
            response.send(err);
    });
});
```

1.  我们定义一个随时间增加的函数，直到它打开。并且我们定义一个类似的回退函数，比如糟糕！服务中断：

```ts
flakeFunction= ()=> {
    return new Promise((resolve, reject) => {
        if (this.delay > 1000) {
            return reject(new Error('Flakey Service is Flakey'));
        }
        setTimeout(() => {
            console.log('replying with flakey response 
            after delay of ', this.delay);
            resolve(`Sending flakey service. Current Delay at   
              ${this.delay}`);
            this.delay *= 2;
        }, this.delay);
    });
 }
 callingSetTimeOut(){
     setInterval(() => {
         if (this.delay !== this.baseline) {
              this.delay = this.baseline;
              console.log('resetting flakey service delay',    
              this.delay);
         }
     }, 20000);
 }
 fallback () => { return 'Service Fallback'; }
```

1.  就是这样！打开 Hystrix，输入 URL`http://localhost:3000/hystrix.stream`到 Hystrix 流中，您将能够看到电路的实时监控：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/efa92def-d38f-4d51-8656-8cbf38b0fd0e.png)

一旦达到峰值阶段，它将自动打开：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/4992df36-cc89-4678-bbeb-0f219ea4b1c8.png)

在预先配置的时间之后，它将再次处于关闭状态，并准备好为请求提供服务。可以在这里找到完整的详细 API[`www.npmjs.com/package/opossum`](https://www.npmjs.com/package/opossum)。

# 消息队列和代理

消息队列是应用程序间通信问题的解决方案。无论我的应用程序或数据在哪里，无论我是在同一台服务器上，独立的服务器上，带有不同操作系统的服务器上或类似的地方，这种通信都会发生。消息队列是为诸如任务列表或工作队列之类的场景而构建的。消息队列通过队列传递和发送数据来解决问题。然后应用程序利用消息中的信息进行进一步交互。所提供的平台是安全可靠的。而消息代理是为了扩展消息队列的功能而构建的，它能够理解通过代理传递的每条消息的内容。对每条消息定义的一组操作被处理。与消息代理一起打包的消息处理节点能够理解来自各种来源的消息，如 JMS、HTTP 和文件。在本节中，我们将详细探讨消息总线和消息代理。流行的消息代理包括 Kakfa、RabbitMQ、Redis 和 NSQ。我们将在下一节中更详细地了解 Apache Kakfa，这是消息队列的高级版本。

# 发布/订阅模式介绍

与消息队列一样，发布/订阅（发布-订阅）模式将信息从生产者传递给消费者。然而，这里的主要区别在于这种模式允许多个消费者在一个主题中接收每条消息。它确保消费者按照消息系统中接收消息的确切顺序接收主题中的消息。通过采用一个真实的场景，可以更好地理解这种模式。考虑股票市场。它被大量的人和应用程序使用，所有这些人和应用程序都应该实时发送消息，并且只有确切的价格顺序。股票上涨和下跌之间存在巨大的差异。让我们看一个例子，Apache Kafka 是在发布/订阅模式下的一个出色解决方案。根据 Apache Kafka 的文档，Kafka 是一个分布式、分区、复制的提交日志服务。它提供了消息系统的功能，但具有独特的设计。

Kafka 是一个允许应用程序获取和接收消息的流平台。它用于制作实时数据管道流应用程序。让我们熟悉一下 Kafka 的术语：

+   生产者是向 Kafka 发送数据的人。

+   消费者是从 Kafka 读取数据的人。

+   数据以记录的形式发送。每个记录都与一个主题相关联。主题有一个类别，它由一个键、一个值和一个时间戳组成。

+   消费者通常订阅特定的主题，并获得一系列记录，并在新记录到达时收到通知。

+   如果消费者宕机，他们可以通过跟踪最后的偏移量重新启动流。

消息的顺序是有保证的。

我们将分三个阶段开始这个案例研究：

1.  本地安装 Kakfa：

1.  要在本地设置 Kakfa，下载捆绑包并将其提取到所选位置。提取后，我们需要设置 Zookeeper。为此，请使用以下命令启动`zookeeper` - `bin\windows\zookeeper-server-start.bat config\zookeeper.properties`。对于这个案例研究，Java 8 是必不可少的。由于我在 Windows 上进行这个例子，我的命令中有`Windows`文件夹。一定要注意`.sh`和`.bat`之间的区别。

2. 接下来我们将启动 Kakfa 服务器。输入以下命令-

`bin\windows\kafka-server-start.bat config\server.properties`。

3. 我们将创建一个名为 offers 的主题，只有一个分区和一个副本 - `bin\windows\kafka-topics.bat --create --zookeeper localhost:2181 --replication-factor 1 --partitions 1 --topic offers`。您将收到提示 Created topic offers。要查看主题，我们可以输入`bin\windows\kafka-topics.bat --list --zookeeper localhost:2181`。

4. Kakfa 在`localhost:2181`上运行。我们甚至可以通过我们的代理或 Node.js 客户端创建主题。

1.  创建 Kafka 生产者

1.  我们将利用`kakfa-node`模块（[`www.npmjs.com/package/kafka-node`](https://www.npmjs.com/package/kafka-node)）。根据需要，我们可以设置一个单独的服务或集成到现有的应用服务中。

1.  现在我们将在两个不同的项目中编写两个单独的文件来测试我们的应用程序。

1.  您可以检查`Chapter-8/kakfka/node-producer`以查看源代码：

```ts
const client = new kafka.Client("http://localhost:2181", "kakfka-client", {
     sessionTimeout: 300,
     spinDelay: 100,
     retries: 2
 });
 const producer = new kafka.HighLevelProducer(client);
 producer.on("ready", function() {
     console.log("Kafka Producer is ready.");
 });
 // For this demo we just log producer errors
 producer.on("error", function(error:any) {
     console.error(error);
 });
 const KafkaService = {
     sendRecord: ({ type, userId, sessionId, data }:any,  
       callback = () => {}) => {
         if (!userId) {
             return callback(new Error(`A userId
                has to be provided.`));
         }
         const event = {
             id: uuid.v4(),
             timestamp: Date.now(),
             userId: userId,
             sessionId: sessionId,
             type: type,
             data: data
         };
         const buffer:any = new    
           Buffer.from(JSON.stringify(event));
         // Create a new payload
         const record = [
         {
             topic: "offers",
             messages: buffer,
             attributes: 1
         }
         ];
         //Send record to Kafka and log result/error
         producer.send(record, callback);
     }
 };
```

1.  您可以像这样绑定消息事件。通过相同的模块，我们可以创建一个客户端，他将监听报价消息并相应地处理事件：

```ts
const consumer = new kafka.HighLevelConsumer(client, topics, options);
 consumer.on("message", function(message:any) {
     // Read string into a buffer.
     var buf = new Buffer(message.value, "binary");
     var decodedMessage = JSON.parse(buf.toString());
     //Events is a Sequelize Model Object.
     return Events.create({
         id: decodedMessage.id,
         type: decodedMessage.type,
         userId: decodedMessage.userId,
         sessionId: decodedMessage.sessionId,
         data: JSON.stringify(decodedMessage.data),
         createdAt: new Date()
     });
 });
```

Kafka 是一个强大的工具，可以用于各种需要实时数据处理的场景。发布/订阅模式是实现事件驱动通信的一种很好的方式。

# 共享依赖

当构建可独立部署的可扩展代码库时，微服务非常出色，分离关注点，具有更好的弹性，多语言技术和更好的模块化，可重用性和开发生命周期。然而，模块化和可重用性是有代价的。更多的模块化和可重用性往往会导致高耦合或代码重复。将许多不同的服务连接到相同的共享库将很快使我们回到原点，最终我们将陷入单块地狱。

在本节中，我们将看到如何摆脱这种困境。我们将看到一些具有实际实现的选项，并了解共享代码和通用代码的过程。所以让我们开始吧。

# 问题和解决方案

在微服务之间共享代码总是棘手的。我们需要确保共同的依赖不会限制我们微服务的自由。我们在共享代码时要实现的主要目标是：

+   在我们的微服务之间共享通用代码，同时确保我们的代码是**不重复自己**（**DRY**）——这是一个编码原则，其主要目标是减少代码的重复

+   通过任何共享的共同库避免紧密耦合，因为它会消除微服务的自由。

+   使同步我们可以在微服务之间共享的代码变得简单

微服务会引入代码重复。为任何业务用例创建一个新的`npm`包是非常不切实际的，因为这将产生大量的开销，使维护任何代码更加困难。

我们将使用**bit**（[`bitsrc.io/`](https://bitsrc.io/)）来解决我们的依赖问题并实现我们的目标。Bit 的运作理念是组件是构建块，你是架构师。使用 bit，我们不必创建新的存储库或添加包来共享代码，而不是重复。您只需定义任何现有微服务的可重用部分，并将其共享到其他微服务作为任何包或跟踪的源代码。这样，我们可以轻松地使任何服务的部分可重用，而无需修改任何一行代码，也不会在服务之间引入紧密耦合。Bit 的主要优势在于它为我们提供了灵活性，使我们能够对与任何其他服务共享的代码进行更改，从而使我们能够在微服务生态系统中的任何地方开发和修改代码。

# 开始使用 bit

通过共同的库耦合微服务是非常糟糕的。Bit 提倡构建组件。我们只需隔离和同步任何可重用的代码，让 bit 处理如何在项目之间隔禅和跟踪源代码。这仍然可以通过 NPM 安装，并且可以从任何端口进行更改。假设您正在创建一些具有顶级功能的出色系统，这些功能在任何地方都很常见。您希望在这些服务之间共享代码。您可以在第七章的`bit-code-sharing`文件夹中跟随代码，*服务状态和服务间通信*：

1.  Bit 将作为全局模块安装。通过输入以下内容安装`bit`：

```ts
npm install bit-bin -g
```

1.  在这个例子中，查看`demo-microservice`，它具有常见的实用程序，比如从缓存中获取、常见的日志实用程序等。我们希望这些功能在任何地方都可以使用。这就是我们将使用`bit`使我们的文件`common/logging.ts`在任何地方都可用的地方。

1.  是时候初始化`bit`并告诉`bit`在跟踪列表中添加`logging.ts`。在终端中打开`demo-microservice`，然后输入`bit init`命令。这将创建一个`bit.json`文件。

1.  接下来，我们将告诉`bit`开始跟踪`common`文件夹。在终端中输入以下命令：

```ts
bit add src/common/*
```

在这里，我们使用`*`作为全局模式，这样我们就可以跟踪相同路径上的多个组件。它将跟踪`common`文件夹中的所有组件，你应该能够看到一个跟踪两个新组件的消息。

1.  Bit 组件已添加到我们的 bit 跟踪列表。我们可以简单地输入`bit status`来检查我们微服务中 bit 的当前状态。它将在“新组件”部分下显示两个组件。

1.  接下来，我们将添加构建和测试环境，以便在分享组件之前不会引入任何异常。首先是我们的构建环境。构建环境本质上是一个构建任务，由 bit 用于运行和编译组件，因为我们的文件是用 TypeScript 编写的。要导入依赖项，你需要在[`bitsrc.io`](https://bitsrc.io)创建一个账户，并注册公共层。

1.  通过添加以下行来导入 TypeScript 编译器：

```ts
bit import bit.envs/compilers/typescript -c
```

你需要输入刚刚创建的账户的用户凭据。安装后，我们将使用公共作用域。

1.  输入命令`bit build`，查看带有我们生成文件的`distribution`文件夹。你可以类似地编写测试来检查单元测试用例是否通过。Bit 内置支持 mocha 和 jest。我们现在只是创建一个`hello-world`测试。我们需要明确告诉 bit 对于哪个组件，哪个将是`test`文件。因此，让我们取消跟踪先前添加的文件，因为我们需要传递我们的规范文件：

```ts
bit untrack --all
```

1.  在`src`文件夹内创建一个`test`文件夹，并通过以下命令安装测试库：

```ts
npm install mocha chai @types/mocha @types/chai --save
```

1.  在`tests`文件夹内创建`logging.spec.ts`，并添加以下代码。类似地，创建`cacheReader.spec.ts`：

```ts
import {expect} from 'chai';
describe("hello world mocha test service", function(){
    it("should create the user with the correct name",()=>{
        let helloDef=()=>'hello world';
        let helloRes=helloDef();
        expect(helloRes).to.equal('hello world');
    });});
```

我们将在第八章中看到详细的测试概念，*测试、调试和文档*。

1.  要告诉`bit`我们的测试策略，输入以下命令：

```ts
bit import bit.envs/testers/mocha --tester
bit add src/common/cacheReader.ts  --tests 'src/tests/cacheReader.spec.ts'
bit add src/common/logging.ts --tests 'src/tests/logging.spec.ts'
```

1.  输入命令`bit test`，它将打印针对每个添加的组件的测试结果。

1.  我们已经完成了。是时候与世界分享我们全新的组件了。首先，我们将锁定一个版本，并将其与此项目的其他组件隔离开来。输入以下命令：

```ts
bit tag --all 1.0.0
```

你应该能够看到一个输出，指出已添加组件`common/logging@1.0.0`和`common@cache-reader@1.0.0`。当你执行`bit status`时，你将能够看到这些组件已从新组件移动到了暂存组件。

1.  为了与其他服务共享，我们使用`bit export`导出它。我们将把它推送到远程作用域，这样它就可以从任何地方访问。转到[`bitsrc.io/`](http://bitsrc.io/)，登录，然后在那里创建一个新的作用域。现在我们将把我们的代码推送到那个作用域：

```ts
bit export <username>.<scopename>
```

你可以登录你的账户，然后检查推送存储库中的代码。

1.  要在其他工作区中导入，可以按照以下步骤进行：

1.  我们需要告诉节点，bit 是我们的一个注册表之一，从中下载模块。因此，在`npm config`中添加`bit`仓库作为带有别名`@bit`的注册表之一：

```ts
npm config set '@bit:registry' https://node.bitsrc.io
```

1.  要从任何其他项目中下载，请使用以下命令：

```ts
npm i @bit/parthghiya.tsms.common.logging
```

该命令类似于`npm i <我们创建的别名>/<用户名>.<作用域名称>.<用户名>`。安装后，你可以像使用任何其他节点模块一样使用它。查看`chapter 9/bit-code-sharing/consumer`。

你还可以使用`bit import`和其他实用程序，比如进行更改、同步代码等。

共享代码对于开发和维护提供了必要的。然而，通过共享库紧密耦合服务破坏了微服务的意义。为任何新的常见用例在 NPM 中创建新的存储库是不切实际的，因为我们必须进行许多更改。像 bit 这样的工具拥有两全其美。我们可以轻松共享代码，还可以从任何端点进行制作和同步更改。

# 共享数据的问题

在微服务之间共享常见数据是一个巨大的陷阱。首先，不一定能满足所有微服务的需求。此外，它增加了开发时间的耦合。例如，`InventoryService`将需要与使用相同表的其他服务的开发人员协调模式更改。它还增加了运行时的耦合。例如，如果长时间运行的`ProductCheckOut`服务在`ORDER`表上持有锁定，那么使用相同表的任何其他服务都将被阻塞。每个服务必须有自己的数据库，并且数据不能直接被任何其他服务访问。

然而，有一个巨大的情况需要我们注意。事务问题以及如何处理它们。即使将与事务相关的实体保留在同一个数据库中并利用数据库事务似乎是唯一的选择，我们也不能这样做。让我们看看我们应该怎么做：

+   **选项 1**：如果任何更新只发生在一个微服务中，那么我们可以利用异步消息/服务总线来处理。服务总线将保持双向通信，以确保业务能力得到实现。

+   **选项 2**：这是我们希望处理事务数据的地方。例如，只有在付款完成后才能进行结账。如果没有，那么它不应该继续进行任何操作。要么我们需要合并服务，要么我们可以使用事务（类似于 Google Spanner 用于分布式事务）。我们卡在两个选项上，要么通过事务解决，要么相应地处理情况。让我们看看如何以各种方式处理这些情况。

为了管理数据一致性，最常用的模式之一是 saga 模式。让我们了解一个我们拥有的实际用例。我们有一个客户奖励积分服务，用于维护允许购买的总积分。应用程序必须确保新订单不得超过客户允许的奖励积分。由于订单和客户奖励积分存储在不同的数据库中，我们必须保持数据一致性。

根据 saga 模式，我们必须实现跨多个服务的每个业务交易。这将是一系列本地事务。每个单独的事务更新数据库并发布一个消息或事件，该消息或事件将触发 saga 中的下一个本地事务。如果本地事务失败，那么 saga 将执行一系列补偿事务，实际上撤消了上一个事务所做的更改。以下是我们将在我们的案例中执行的步骤。这是通过事件维护一致性的一个案例：

+   奖励服务创建一个处于挂起状态的订单并发布一个积分处理的事件。

+   客户服务接收事件并尝试阻止该订单的奖励。它发布了一个奖励被阻止的事件或奖励被阻止失败的事件。

+   订单服务接收事件并相应地更改状态。

最常用的模式如下：

+   **状态存储**：一个服务记录状态存储中的所有状态更改。当发生任何故障时，我们可以查询状态存储以找到并恢复任何不完整的事务。

+   **流程管理器**：一个监听任何操作生成的事件并决定是否完成事务的流程管理器。

+   **路由滑动**: 另一种主流方法是使所有操作异步进行。一个服务使用两个请求命令（借记和发货指令）创建一条称为路由滑动的滑动。这条消息从路由滑动传递到借记服务。借记服务执行第一个命令并填写路由滑动，然后将消息传递给完成发货操作的发货服务。如果出现故障，消息将被发送回错误队列，服务可以观察状态和错误状态以进行补偿。以下图表描述了相同的过程：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/77501b19-b2df-4878-9ce0-0e26bc299433.png)

路由滑动

微服务中的数据共享如果处理不当，总是会成为一个痛点。有各种解决方案可以处理微服务之间的分布式事务。我们看到了广泛使用的解决方案，比如 saga，并且了解了处理数据最终一致性的各种方法。

# 缓存

现在我们基本上掌握了微服务开发的主导权。我们已经开发了微服务，通过网关连接它们，并在它们之间建立了通信层。由于我们已经将代码分布到各种服务中，可能会出现的问题之一是在正确的时间访问所需的数据。使用内存具有一系列挑战，我们绝不希望引入（例如，需要引入负载均衡器、会话复制器等）。我们需要一种方式在服务之间访问临时数据。这将是我们的缓存机制：一个服务创建并将数据存储在缓存中，而其他服务可能根据需要和情况或失败情况使用它。这就是我们将引入 Redis 作为我们的缓存数据库的地方。著名的缓存解决方案包括 Redis 和 Hazelcast。

# 缓存的祝福和诅咒

每当我们被要求优化应用程序的性能方面时，首先想到的就是缓存。缓存可以被定义为暂时将检索或计算的数据保存在数据存储（服务器的 RAM，像 Redis 这样的键值存储）中，希望将来访问这些信息会更快。更新这些信息可以被触发，或者这个值可以在一定的时间间隔后失效。缓存的优势一开始看起来很大。计算资源一次，然后从缓存中获取（读取有效资源）可以避免频繁的网络调用，因此可以缩短加载时间，使网站更具响应性，并提供更多的收入。

然而，缓存并不是一劳永逸的解决方案。缓存确实是静态内容和可以容忍到一定程度的过时数据的 API 的有效策略，但在数据非常庞大和动态的情况下并不适用。例如，考虑我们购物车微服务中给定产品的库存。对于热门产品，这个数量会变化得非常快，而对于其他一些产品，它可能会变化。因此，在这里确定缓存的合适年龄是一个难题。引入缓存还需要管理其他组件（如 Redis、Hazelcast、Memcached 等）。这增加了成本，需要采购、配置、集成和维护的过程。缓存还可能带来其他危险。有时从缓存中读取可能会很慢（缓存层未得到良好维护，缓存在网络边界内等）。使用更新的部署维护缓存也是一个巨大的噩梦。

以下是一些需要保持的实践，以有效使用缓存，即使我们的服务工作量减少：

+   使用 HTTP 标准（如 If-modified-Since 和 Last-Modified 响应头）。

+   其他选项包括 ETag 和 If-none-match。在第一次调用后，将生成并发送唯一的**实体标签**（**ETag**）到服务请求，客户端在*if-none-match-header*中发送。当服务器发现 ETag 未更改时，它会发送一个带有`304 Not Modified`响应的空主体。

+   HTTP Cache-Control 头可以用于帮助服务控制所有缓存实体。它具有各种属性，如**private**（如果包含此头，则不允许缓存内容），**no-cache**（强制服务器重新提交以进行新的调用），**public**（标记任何响应为可缓存），以及**max-age**（最大缓存时间）。

查看以下图表以了解一些缓存场景：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/63da78bd-f083-4e76-bcbe-0c706ca5bc3f.png)

缓存场景

# Redis 简介

Redis 是一个专注于简单数据结构（键值对）的简单 NoSQL 数据库，具有高可用性和读取效率。Redis 是一个开源的，内存数据结构存储，可以用作数据库，缓存或消息代理。它具有内置数据结构的选项，如字符串，哈希，列表，集合，范围查询，地理空间索引等。它具有开箱即用的复制，事务，不同级别的磁盘持久性，高可用性和自动分区的选项。我们还可以添加持久性存储，而不是选择内存存储。

当 Redis 与 Node.js 结合使用时，就像天作之合一样，因为 Node.js 在网络 I/O 方面非常高效。NPM 仓库中有很多 Redis 包可以使我们的开发更加顺畅。领先的包有`redis` ([`www.npmjs.com/package/redis`](https://www.npmjs.com/package/redis))，`ioredis` ([`www.npmjs.com/package/ioredis`](https://www.npmjs.com/package/ioredis))和`hiredis` ([`www.npmjs.com/package/hiredis`](https://www.npmjs.com/package/hiredis))。`hiredis`包具有许多性能优势。要开始我们的开发，我们首先需要安装`redis`。在下一节中，我们将在项目中设置我们的分布式缓存。

# 使用 redis 设置我们的分布式缓存

为了理解缓存机制，让我们举一个实际的例子并实现分布式缓存。我们将围绕购物车的例子进行演变。将业务能力划分到不同的服务是一件好事，我们将我们的库存服务和结账服务划分为两个不同的服务。所以每当用户添加任何东西到购物车时，我们都不会持久化数据，而是将其临时存储，因为这不是永久的或功能性改变的数据。我们会将这种短暂的数据存储到 Redis 中，因为它的读取效率非常棒。我们对这个问题的解决方案将分为以下步骤：

1.  首先，我们专注于设置我们的`redis`客户端。像所有其他东西一样，通过`docker pull redis`拉取一个 docker 镜像。

1.  一旦镜像在我们的本地，只需运行`docker run --name tsms -d redis`。还有持久性存储卷的选项。您只需附加一个参数`docker run --name tsms -d redis redis-server --appendonly yes`。

1.  通过命令`redis-cli`验证 redis 是否正在运行，您应该能够看到输出 pong。

1.  是时候在 Node.js 中拉取字符串了。通过添加`npm install redis --save`和`npm install @types/redis --save`来安装模块。

1.  通过`import * as redis from 'redis'; let client=redis.createClient('127.0.0.1', 6379);`创建一个客户端。

1.  像任何其他数据存储一样使用 Redis：

```ts
redis.get(req.userSessionToken + '_cart', (err, cart) => { if (err) 
 { 
    return next(err); 
 } 
//cart will be array, return the response from cache }
```

1.  同样，您可以根据需要随时使用 redis。它甚至可以用作命令库。有关详细文档，请查看此链接 ([`www.npmjs.com/package/redis`](https://www.npmjs.com/package/redis))。

我们不得不在每个服务中复制 Redis 的代码。为了避免这种情况，在后面的部分中，我们将使用 Bit：一个代码共享工具。

在下一节中，我们将看到如何对微服务进行版本控制，并使我们的微服务具有故障安全机制。

# 摘要

在本章中，我们研究了微服务之间的协作。有三种类型的微服务协作。基于命令的协作（其中一个微服务使用 HTTP POST 或 PUT 来使另一个微服务执行任何操作），基于查询的协作（一个微服务利用 HTTP GET 来查询另一个服务的状态），以及基于事件的协作（一个微服务向另一个微服务公开事件源，后者可以通过不断轮询源来订阅任何新事件）。我们看到了各种协作技术，其中包括发布-订阅模式和 NextGen 通信技术，如 gRPC、Thrift 等。我们看到了通过服务总线进行通信，并了解了如何在微服务之间共享代码。

在下一章中，我们将研究测试、监控和文档的方面。我们将研究我们可以进行的不同类型的测试，以及如何编写测试用例并在发布到生产环境之前执行它们。接下来，我们将研究使用 PACT 进行契约测试。然后，我们将转向调试，并研究如何利用调试和性能分析工具有效监视我们协作门户中的瓶颈。最后，我们将使用 Swagger 为我们的微服务生成文档，这些文档可以被任何人阅读。


# 第八章：测试、调试和记录

到目前为止，我们已经编写了一些微服务实现（第四章，*开始您的微服务之旅*）；建立了一个单一的接触点，API 网关（第五章，*理解 API 网关*）；添加了一个注册表，每个服务都可以记录其状态（第六章，*服务注册表和发现*）；建立了微服务之间的协作（第七章，*服务状态和服务间通信*）；并编写了一些实现。从开发者的角度来看，这些实现似乎很好，但是现在没有测试就没有人会接受。这是行为驱动开发和测试驱动开发的时代。随着我们编写越来越多的微服务，开发没有自动化测试用例和文档的系统变得难以管理和痛苦。

本章将从理解测试金字塔开始，深入描述微服务中涉及的所有不同类型的测试。我们将了解测试框架，并了解基本的单元测试术语。然后我们将学习调试微服务的艺术，最后学习如何使用 Swagger 记录我们的微服务。

本章涵盖以下主题：

+   编写良好的自动化测试用例

+   理解测试金字塔并将其应用于微服务

+   从外部测试微服务

+   调试微服务的艺术

+   使用 Swagger 等工具记录微服务

# 测试

测试是任何软件开发的基本方面。无论开发团队有多么优秀，总会有改进的空间或者他们的培训中有遗漏的地方。测试通常是一项耗时的活动，根本没有得到应有的关注。这导致了行为驱动开发的普及，开发人员编写单元测试用例，然后编写代码，然后运行覆盖率报告以了解测试用例的状态。

# 什么和如何测试

由于微服务是完全分布式的，首先要考虑的问题是要测试什么以及如何测试。首先，让我们快速了解定义微服务并需要测试的主要特征：

+   **独立部署**：每当

+   当一个微服务部署了一个小的或安全的更改后，该微服务就准备好部署到生产环境了。但是我们如何知道更改是否安全呢？这就是自动化测试用例和代码覆盖率发挥作用的地方。有一些活动，比如代码审查、代码分析和向后兼容性设计，可能会起作用，但是测试是一项可以完全信任适应变化的活动。

+   **可以随意替换**：一组良好的测试总是有助于了解新实现是否等同于旧实现。任何新实现都应该针对具有正常工作流程的等效实现进行测试。

+   **小团队的所有权**：微服务是小型的，专注于一个团队，以满足单一的业务需求。我们可以编写覆盖微服务所有方面的测试。

测试过程必须快速、可重复，并且应该是自动化的。接下来的问题是如何测试以及测试时要关注什么。通常，所有测试被分为以下四个部分：

+   **理解用户**：主要的测试模式是发现用户需要什么以及他们遇到了什么问题。

+   **功能检查**：这种测试模式的目标是确保功能正确并符合规格。它涉及用户测试、自动化测试等活动。

+   **防止不必要的更改**：此测试的目标是防止系统中不必要的更改。每当部署新更改时，都会运行几个自动化测试，生成代码覆盖率报告，并可以决定代码覆盖级别。

+   测试金字塔 - 测试什么？

**服务测试（中层）**：这些测试检查系统业务能力的完整执行。它们检查特定的业务需求是否已经实现。它们不关心背后需要多少服务来满足需求。

# 系统测试

测试金字塔是一个指导我们编写何种测试以及在哪个级别进行测试的工具。金字塔顶部的测试表明需要较少的测试，而金字塔底部需要更多的测试。

**系统测试（顶层）**：这些测试跨越完整的分布式微服务系统，并通常通过 GUI 实现。

测试金字塔由四个级别组成，如下所述：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/7763e9e7-69e4-4955-8c0b-8b30f1384c3d.png)

+   **防止运行时行为**：此测试的目标是检查系统存在哪些运行时问题。在这里，我们通过压力测试、负载测试和监控来保护系统。

+   我们将在接下来的部分中更详细地讨论所有这些级别。

+   **单元测试（底层）**：这些测试在微服务中执行非常小的功能片段。几个较低级别的单元测试组合成一个微服务。单元测试仅涉及微服务内的一个小方面，或者我们可以说它们在宏观级别上运行。例如，我们的产品目录服务有许多服务。为其编写单元测试将涉及传递产品 ID 并确保我获得正确的产品。

+   在我们的购物车微服务中，系统测试的一个示例将是完整的结账流程。它使用添加到购物车系统的 Web UI，在那里我们添加多个项目，生成发票，应用折扣代码，并使用测试信用卡付款。如果测试通过，我们可以断言折扣代码可以应用并且可以收到付款。如果断言失败，任何事情都可能导致失败，例如商品的价格错误，可能添加了额外费用，或者可能支付服务失败。为了解决此问题，我们需要测试所有微服务以找到确切的罪魁祸首。

**合同测试（较低级别）**：这些测试在外部服务的边界上进行，以验证是否符合消费服务期望的合同。

# 在接下来的部分中，我们将讨论微服务中的测试金字塔。

位于金字塔顶部的是系统测试或端到端测试。它们具有非常广泛的范围，或者我们可以说它们具有 5 万英尺的范围，并试图在很少的测试中涵盖很多内容。它们不会降到宏观级别。每当系统测试失败时，很难确定问题所在，因为它的范围很大。测试覆盖整个分布式系统，因此问题可能出现在任何地方，任何组件中。

覆盖大量服务和更广泛的领域，系统测试通常倾向于缓慢和不精确（因为我们无法确定失败的确切服务）。而不是使用模拟系统，实际进行服务请求，将事物写入真实数据存储，并甚至轮询真实事件源以监视系统。

一个重要的问题是关于需要运行多少系统测试。系统测试成功时可以给予很大的信心，但它们也缓慢且不精确；我们只能为系统的最重要的用例编写系统级测试。这可以让我们覆盖系统中所有重要业务能力的成功路径。

对于完整的端到端测试，我们可以采取以下行动之一：

+   使用 JSON 请求测试我们的 API

+   使用 Selenium 测试 UI，模拟对 DOM 的点击。

+   使用行为驱动开发，将用例映射到我们应用程序中的操作，并在我们构建的应用程序上执行

我的建议是只编写面向业务的重要业务能力系统测试，因为这样可以对完全部署的系统进行大量练习，并涉及利用生态系统中的所有组件，如负载均衡器、API 网关等。

# 服务测试

这些测试处于测试金字塔的中间层，它们专注于与一个微服务的完整交互，并且是独立的。这个微服务与外部世界的协作被模拟 JSON 所取代。服务级测试测试场景，而不是进行单个请求。它们进行一系列请求，共同形成一个完整的图片。这些是真正的 HTTP 请求和响应，而不是模拟的响应。

例如，信用计划的服务级测试可以执行以下操作：

1.  发送命令以触发信用类别中的用户（这里的命令遵循 CQRS 模式，见第一章，“揭秘微服务”）。CQRS 遵循同步通信模式，因此，它的测试代码是相同的。我们发送命令以触发其他服务来满足我们的服务测试标准。

1.  根据用户的月度消费决定最佳的忠诚度优惠。这可以是硬编码的，因为它是一个不同的微服务。

1.  记录发送给用户的优惠，并发送响应以检查服务的功能。

当所有这些方面都通过时，我们可以断言信用计划微服务成功运行，如果任何一个功能失败，我们可以肯定问题出在信用计划微服务中。

服务级测试比系统级测试更精确，因为它们只涵盖一个单一的微服务。如果这样的测试失败，我们可以肯定地断言问题出在微服务内部，假设 API 网关没有错误，并且它提供了与模拟中写的完全相同的响应。另一方面，服务级测试仍然很慢，因为它们需要通过 HTTP 与被测试的微服务进行交互，并且需要与真实数据库进行交互。

我的建议是，应该为最重要的可行故障场景编写这些测试，要牢记编写服务级测试是昂贵的，因为它们使用微服务中的所有端点，并涉及基于事件的订阅。

# 合同测试

在分布式系统中，微服务之间有很多协作。协作需要作为一个微服务对另一个微服务的请求来实现。端点的任何更改都可能破坏调用该特定端点的所有微服务。这就是合同测试的作用所在。

当任何微服务进行通信时，发出请求的微服务对另一个微服务的行为有一些期望。这就是协作的工作方式：调用微服务期望被调用的微服务实现某个固定的合同。合同测试是为了检查被调用的微服务是否按照调用微服务的期望实现了合同的测试。

尽管契约测试是调用方微服务代码库的一部分，但它们也测试其他微服务中的内容。由于它们针对完整系统运行，因此有利于针对 QA 或分阶段环境运行它们，并配置在每次部署时自动运行契约测试。当契约失败时，意味着我们需要更新我们的测试替身或更改我们的代码以适应契约所做的新更改。这些测试应该根据外部服务的更改数量来运行。契约测试的任何失败都不会像普通测试失败那样破坏构建。这表明消费者需要跟上变化。我们需要更新测试和代码以使一切保持同步。这将引发与生产者服务的对话，讨论该变化如何影响其他方面。

我的结论是，契约测试与服务测试非常相似，但区别在于契约测试侧重于满足与服务通信的先决条件。契约测试不设置模拟协作者，实际上会向正在测试的微服务发出真实的 HTTP 请求。因此，如果可能的话，它们应该针对每个微服务进行编写。

# 单元测试

这些是测试金字塔底部的测试。这些测试也涉及单个微服务，但与服务测试不同，它们不关注整个微服务，也不通过 HTTP 工作。单元测试直接与正在测试的微服务的部分/单元进行交互，或通过内存调用。单元测试看起来就像您正在进行真实的 HTTP 请求，只是您在处理模拟和断言。通常涉及两种类型的单元测试：一种涉及数据库调用，另一种直接涉及内存调用。如果测试的范围非常小，并且测试代码和微服务中的生产代码在同一个进程中运行，那么测试可以被称为单元测试。

单元测试的范围非常狭窄，因此在识别问题时非常精确。这有助于有效处理故障和错误。有时，您可以通过直接实例化对象然后对其进行测试，使微服务的范围更窄。

对于我们的信用计划，我们需要几个单元测试来测试端点和业务能力。我们需要测试用户设置，包括有效和无效数据。我们需要测试读取现有和不存在的用户，以检查我们的忠诚度和月度福利。

我的建议是，我们应该决定最窄的单元测试可以有多窄。从测试应该覆盖的内容开始，然后逐渐添加更精细的细节。一般来说，我们可以使用两种单元测试风格：经典的（基于状态的行为测试）或模拟的（通过模拟实际行为支持的交互测试）。

在下图中，我们可以看到应用于微服务的所有测试类型：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/7ac4fe7b-1a39-4f63-b333-7a7c0364be9c.png)

测试类型

现在我们知道了微服务级别需要的所有测试类型，是时候看看我们的微服务测试框架了。在下一节中，我们将看到不同类型测试的实际实现，并进行微服务的代码覆盖率。让我们开始吧。

# 实践测试

现在是时候动手使用微服务测试框架了。在本节中，我们将首先了解测试基础知识，然后继续编写一些单元测试、合同测试和服务级测试。编写测试有很大的优势。我们被迫思考如何将代码分解为子函数，并根据单一职责原则编写代码。全面的测试覆盖率和良好的测试使我们了解应用程序的工作原理。在本节中，我们将使用一些著名的工具集：Mocha，Chai，Sinon 和 Ava。Ava 将是我们的测试运行器，Chai 将是我们的断言库，Sinon 将是我们的模拟库。

# 我们的库和测试工具类型

测试工具可以分为各种功能。为了充分利用它们，我们总是使用它们的组合。让我们根据它们的功能来看看可用的最佳工具：

+   提供测试基础：Mocha，Jasmine，Jest，Cucumber

+   提供断言函数：Chai，Jasmine，Jest，Unexpected

+   生成、显示和观察测试结果：Mocha，Jasmine，Jest，Karma

+   生成和比较组件和数据结构的快照：Jest，Ava

+   提供模拟、间谍和存根：Sinon，Jasmine，Enzyme，Jest，test double

+   生成代码覆盖报告：Istanbul，Jest，Blanket

+   E2E 测试：Casper，Nightwatch

在本节中，我们将快速浏览 Ava，Chai，Mocha 和 Sinon，并了解它们对我们有什么提供。

尽管 Mocha 是一个标准库，但我选择了 Ava，因为它与 Mocha 相比非常快，它将每个测试作为单独的 Node.js 进程运行，从而节省 CPU 使用率和内存。

# 柴

这是一个基本的断言库，遵循 TDD/BDD，可以与任何其他库一起使用，以获得高质量的测试。一个断言 i

任何必须实现的语句，否则应该抛出错误并停止测试。这是一个非常强大的工具，可以编写易于理解的测试用例。

它提供了以下三个接口，使测试用例更易读和更强大：

+   `should`

+   `expect`

+   `assert`

除了这三个接口，我们还可以使用各种自然语言词汇。完整列表可以在[`www.chaijs.com/api/bdd/`](http://www.chaijs.com/api/bdd/)找到。

你一定想知道`should`和`expect`之间的区别是什么。嗯，这是一个自然的问题。尽管`should`和`expect`做同样的事情，但根本区别在于`assert`和`expect`接口不修改`Object.prototype`，而`should`则会。

# Mocha

Mocha 是最著名和广泛使用的库之一，遵循行为驱动开发测试。在这里，测试描述了任何服务的用例，并且它使用另一个库的断言来验证执行代码的结果。Mocha 是一个测试运行器。它被用来

组织和运行测试通过`describe`和它的操作符。 Mocha 提供了各种功能，比如：

+   `beforeEach()`: 在测试文件中的每个规范之前调用一次，从中运行测试

+   `afterEach()`: 在测试文件中的每个规范之后调用一次

+   `before ()`: 这在任何测试之前运行代码

+   `after()`: 这在所有测试运行后运行代码

# Ava

Ava，像 Mocha 一样，是一个测试运行器。Ava 利用 Node.js 的并行和异步特性，并通过单独的进程并行处理运行测试文件。根据统计数据，在`pageres`（一个捕获屏幕截图的插件）中从 Mocha 切换到 Ava，将测试时间从 31 秒降至 11 秒（[`github.com/avajs/ava/blob/master/readme.md`](https://github.com/avajs/ava/blob/master/readme.md)）。它有各种选项，如快速失败、实时监视（在更改文件时以监视模式重新运行测试）、存储快照等。

Ava 是为未来设计的，完全使用 ES6 编写。测试可以并行运行，可以选择同步或异步进行测试。默认情况下，测试被认为是同步的，除非它们返回一个 promise 或一个 observable。它们大量使用异步函数：

```ts
import test from 'ava';
const fn = async () => Promise.resolve('typescript-microservices');
test(
  async (t) => {
    t.is(await fn(), 'typescript-microservices');
  });
```

它有各种选项，如：

+   报告（显示测试覆盖率的美观报告）

+   快速失败（在第一个失败的测试用例后停止）

+   跳过测试

+   未来的测试

# Sinon

通常，微服务需要调用其他微服务，但我们不想调用实际的微服务；我们只想关注方法是否被调用

或者不。为此，我们有 Sinon，一个框架，它给我们提供了模拟和间谍的选项，通过提供模拟响应或创建间谍服务来实现我们的目的。它提供以下功能：

+   **Stub**：存根是一个带有预先记录和特定响应的虚拟对象。

+   **Spy**：间谍是真实对象和模拟对象之间的混合体。一些方法被间谍对象遮蔽。

+   **Mock**：模拟是替换实际对象的虚拟对象。

# 伊斯坦布尔

这是一个代码覆盖工具，用于跟踪语句、分支和功能覆盖。模块加载器可以在不需要配置的情况下即时对代码进行检测。它提供多种报告格式，如 HTML、LCOV 等。它也可以用于命令行。通过将其嵌入为自定义中间件，它可以用作 Node.js 的服务器端代码覆盖工具。

# 使用 Pact.js 进行合同测试

每个微服务都有自己独立的实现；比如我们的类别服务（产品目录服务）。它有一个用于获取类别列表、获取与这些类别相关的产品列表、添加任何新类别等的端点。现在我们的购物车微服务（消费者）利用这个服务，但在任何时候，类别微服务（提供者）可能会发生变化。

在任何时候：

+   提供者可能会将端点`/categories/list`更改为`/categories`

+   提供者可能会更改有效负载中的几个内容

+   提供者可能会添加新的强制参数或引入新的身份验证机制

+   提供者可能会删除消费者所需的端点

任何这些情况都可能导致潜在的灾难！这些类型的测试不会被单元测试处理，传统方法是使用集成测试。但是，我们可以看到集成测试的潜在缺点，例如以下内容：

+   集成测试很慢。它们需要设置集成环境，满足提供者和消费者的依赖关系。

+   它们很脆弱，可能因其他原因而失败，比如基础设施。集成测试的失败并不一定意味着代码有问题。由于集成测试的范围很广，要找出实际问题变得非常痛苦。

因此，我们需要进行合同测试。

# 什么是消费者驱动的合同测试？

合同测试意味着我们根据一组期望（我们定义为合同的内容）来检查我们的 API，这些期望是要实现的。这意味着我们想要检查，当收到任何 API 请求时，我们的 API 服务器是否会返回我们在文档中指定的数据。我们经常忽略关于我们的 API 客户需求的精确信息。为了解决这个问题，消费者可以定义他们的期望集作为模拟，在单元测试中使用，从而创建他们期望我们实现的合同。我们收集这些模拟，并检查我们的提供者在以与模拟设置相同的方式调用时是否返回相同或类似的数据，从而测试服务边界。这种完整的方法被称为消费者驱动的合同测试。

消费者驱动的合同的想法只是为了规范消费者和提供者之间的任何或所有交互。消费者创建一个合同，这只是消费者和提供者之间关于将发生的交互量或简单地陈述消费者对提供者的期望的协议。一旦提供者同意了合同，消费者和提供者都可以拿到合同的副本，并使用测试来验证系统的任何一端不会发生合同违反。这种测试的主要优势是它们可以独立和本地运行，速度非常快，而且可以毫不费力地运行。同样，如果提供者有多个消费者，我们需要验证多个合同：每个消费者一个。这将帮助我们确保对提供者的更改不会破坏任何消费者服务。

Pact 是一个著名的开源框架，可以进行消费者驱动的合同测试。 Pact 有各种平台的不同实现，例如 Ruby、JVM 和.NET。我们将使用 JavaScript 版本的 Pact JS。所以让我们开始吧。让我们开始 Pact 之旅。

# Pact.js 简介

我们将利用 NPM 中可用的`pact`模块（[`www.npmjs.com/package/pact`](https://www.npmjs.com/package/pact)）。整个过程将如下所示，我们将

需要在消费者和提供者两个级别进行操作。

我们将把我们的实现分为两部分。我们将建立一个提供者以及一个客户端，以测试服务是否相互通信：

+   **在消费者端**：

1.  我们将创建一个模拟的网络服务器，它将充当服务提供者，而不是进行实际调用。 Pact.js 提供了这个功能。

1.  对于我们想要检查的任何请求，我们将定义模拟服务需要返回的预期响应，以检查是否有任何突然的变化。在 Pact 语言中，我们称这些为交互；也就是说，对于给定的请求，消费者希望提供者返回什么？

1.  接下来，我们创建单元测试，我们将运行我们的服务客户端与模拟提供者进行检查，以确保客户端返回这些预期值。

1.  最后，我们将创建一个包含消费者期望的合同的`pact`文件。

+   **在提供者端**：

1.  提供者端从消费者那里获取 pact 文件。

1.  它需要验证它不违反消费者的预期交互。`Pact.js`将读取`pact`文件，执行每个交互的请求，并确认服务是否返回消费者期望的有效负载。

1.  通过检查提供者不违反任何消费者的合同，我们可以确保对提供者代码的最新更改不会破坏任何消费者代码。

1.  这样，我们可以避免集成测试，同时对我们的系统充满信心。

在了解了整个过程之后，现在让我们来实现它。我们将依次遵循关于消费者和提供者的前述步骤。完整的示例可以在`chapter-8/pact-typescript`中找到。我们的示例项目是类别微服务，我们将围绕它进行操作。所以，让我们开始吧：

1.  我们首先创建一个提供者。我们将创建一个返回一些动物的服务以及一个在传递 ID 时给我动物的特定动物服务。

1.  按照提供者的代码，通过从`packt-typescript/src/provider`添加`provider.ts`、`providerService.ts`、`repository.ts`以及从`pact-typescript/data`添加`data.json`。

1.  添加以下依赖项：

```ts
npm install @pact-foundation/pact --save
```

1.  现在我们将创建一个消费者。消费者从提供者那里获取文件。我们将创建一个 Pact 服务器：

```ts
const provider = new Pact({
  consumer: "ProfileService",
  provider: "AnimalService",
  port: 8989,
  log: path.resolve(process.cwd(), "logs", "pact.log"),
  dir: path.resolve(process.cwd(), "pacts"),
  logLevel: "INFO",
  spec: 2
});
```

1.  接下来，我们定义我们的期望，我们将说：

```ts
const EXPECTED_BODY = [{..//JSON response here ...//…..}]
```

1.  接下来，我们编写通常的测试，但在添加测试之前，我们在 Pact 中添加这些交互：

```ts
describe('and there is a valid listing', () => {
     before((done) => {
       // (2) Start the mock server
       provider.setup()
         // (3) add interactions to the Mock Server, 
                as many as required
         .then(() => {
           return provider.addInteraction({//define interactions here })
                          .then(() => done())
```

1.  接下来，我们编写通常的测试：

```ts
// write your test(s)
     it('should give a list for all animals', () => {
  // validate the interactions you've registered 
     and expected occurrance
           // this will throw an error if it fails telling you 
              what went wrong
});
```

1.  关闭模拟服务器：

```ts
after(() => {provider.finalize()})
```

1.  现在我们已经完成了提供者方面的工作，我们需要验证我们的提供者。启动`provider`服务，并在其测试文件中添加以下代码：

```ts
const { Verifier } = require('pact');
let opts = { //pact verifier options};
new Verifier().verifyProvider(opts)
              .then(function () {
                 // verification complete.
});
```

# 奖励（容器化 pact broker）

在动态环境中，我们需要跨应用程序共享 Pacts，而不是在单个应用程序中工作。为此，我们将利用 Pact broker 的功能。您可以从[`hub.docker.com/r/dius/pact-broker/`](https://hub.docker.com/r/dius/pact-broker/)简单地下载它。您可以使用`docker pull dius/pact-broker`通过 Docker 下载它。一旦启动，您可以使用`curl -v http://localhost/9292 #`访问经纪人，您也可以在浏览器中访问！您还可以使用数据库配置它，并运行一个组合的`docker-compose.yml`文件。可以在[`github.com/DiUS/pact_broker-docker/blob/master/docker-compose.yml`](https://github.com/DiUS/pact_broker-docker/blob/master/docker-compose.yml)找到配置为 Postgres 的 pact-broker 的演示配置。通过执行`docker-compose up`命令配置后，可以在端口 80 或端口 443 上访问`pact` broker，具体取决于是否启用了 SSL。

# 重新审视测试关键点

在继续本书的下一部分之前，让我们回顾一下测试的关键点：

+   测试金字塔表示每种测试所需的测试数量。金字塔顶部的测试数量应该比它们下面的级别少。

+   由于其更广泛的范围，系统级测试应该是缓慢和不精确的。

+   系统级测试应该只用于为重要的业务功能提供一些测试覆盖。

+   服务级测试比系统级测试更快，更精确，因为它们只需处理较小的范围。

+   应该遵循一种实践，即为成功和重要的失败场景编写服务级测试。

+   合同测试很重要，因为它们验证一个微服务对另一个微服务的 API 和行为的假设。

+   单元测试应该快速，并且通过只包括一个单元或使用单一职责原则来保持快速。

+   为了拥有更广泛的测试覆盖范围，总是先编写服务测试，当编写服务测试变得难以管理时再编写单元测试。

+   我们使用 Sinon，Ava，Chai 和 Istanbul 来测试我们的微服务。

+   要编写服务级测试：

+   编写被测试微服务的模拟端点

+   编写与微服务交互的场景

+   对来自微服务的响应和它对协作者的请求进行断言

+   通过使用 Pact，您可以编写合同级别的测试，从而避免集成测试。

+   合同测试非常有帮助，因为它们确保微服务遵守其预先制定的合同，并且服务的任何突然变化都不会破坏任何业务功能。

+   **高级：** 有时您可能需要在实时环境中尝试代码片段，无论是为了重现问题还是在真实环境中尝试代码。Telepresence ([`telepresence.io/`](http://telepresence.io/)) 是一个工具，允许您在 Kubernetes 中交换运行的代码。

+   **高级：** Ambassador ([`www.getambassador.io/`](https://www.getambassador.io/)) 是一个 API 网关，允许微服务轻松注册其公共端点。它有各种选项，例如有关流量的统计信息，监控等。

+   **高级：** Hoverfly ([`hoverfly.io/`](https://hoverfly.io/)) 是实现微服务虚拟化的一种方式。我们可以通过它模拟 API 中的延迟和故障。

经过测试流程后，现在是时候通过调试解决问题了。我们将学习有关调试和分析微服务的内容。

# 调试

调试是任何系统开发中最重要的方面之一。调试或解决问题的艺术在软件开发中至关重要，因为它帮助我们识别问题、对系统进行分析，并确定导致系统崩溃的罪魁祸首。有一些关于调试的经典定义：

“调试就像解决一起谋杀案，而你是凶手。如果调试是消除错误的过程，那么软件开发就是将这些错误放入其中的过程”

- Edsgar Dijkstra。

调试 TypeScript 微服务与调试任何 Web 应用程序非常相似。在选择开源免费替代方案时，我们将选择 node-inspector，因为它还提供非常有用的分析工具。

我们已经在第二章《为旅程做准备》中通过 VS Code 进行了调试。

在下一节中，我们将学习如何使用 node-inspector 对我们的应用程序进行分析和调试。我们将看看远程调试的各个方面，以及如何构建一个代理来调试我们的微服务。所以，让我们开始吧。

# 构建一个代理来调试我们的微服务

微服务是基于业务能力分布的。对于最终用户来说，它们可能看起来像是单一功能，比如购买产品，但在幕后，涉及到许多微服务，比如支付服务、加入购物车服务、运输服务、库存服务等等。现在，所有这些服务不应该驻留在单个服务器内。它们根据设计和基础设施进行分布和分发。在某些情况下，两个服务器会相互协作，如果这些服务没有受到监控，就可能在任何级别出现不良行为。这是微服务中一个非常常见的问题，我们将使用`http-proxy`和隧道来解决。我们将创建一个非常简单的示例，记录任何请求的原始标头。这些信息可以为我们提供有关网络实际发生了什么的宝贵信息。这个概念与我们在 API 网关中使用的非常相似。通常，API 网关是所有请求的代理；它查询服务注册表动态获取微服务的位置。这个代理层，我们的网关，有各种优势，我们在第五章《理解 API 网关》中看到了。我们将使用 node 模块`http-proxy`（[`www.npmjs.com/package/http-proxy`](https://www.npmjs.com/package/http-proxy)）并在那里记录请求标头。初始化一个 Node.js 项目，添加`src`、`dist`和`tsconfig.json`文件夹，添加`http-proxy`模块及其类型。然后，在 index.ts 中输入以下代码以创建代理服务器。完整的代码可以在提取的源代码中找到，位于`第八章/ts-http-proxy`下：

```ts
export class ProxyServer {
  private proxy: any;
  constructor() {
    this.registerProxyServer();
    this.proxy = httpProxy.createProxyServer({});
    //we are passing zero server options, but we can pass lots of options such as buffer, target, agent, forward, ssl, etc. 
  }
  registerProxyServer(): void {
    http.createServer((req: IncomingMessage, res: ServerResponse) => {
      console.log("===req.rawHeaders====", req.rawHeaders);
      this.proxy.web(req, res, {
        target: 'http://127.0.0.1:3000/
            hello-world'})
        }).listen(4000)
    }}
  //after initializing make an object of this class
  new ProxyServer();
```

接下来，当您访问`localhost:4000`时，它将打印所有原始标头，您可以在源代码中检查并查看服务的响应。

在下一节中，我们将看看 Chrome 调试扩展和分析工具。

# 分析过程

在分析服务性能方面，分析是一个关键过程。Node.js 有一些原生工具可以对任何正在运行的 V8 进程进行分析。这些只是包含有关 V8 处理过程的统计信息的有效摘要的快照，以及 V8 在编译时如何处理该过程以及在优化运行热代码时所做的操作和决策。

我们可以通过传递`--prof`标志在任何进程中生成 v8 日志。`prof`代表配置文件。例如`node --prof index.js`。那不会是一个可读的格式。要创建一个更可读的格式，运行`node --prof-process <v8.logfilename>.log >`命令的配置文件。

在本节中，我们将学习如何使用配置文件日志进行分析、获取堆快照，并利用 Chrome 的 CPU 分析来进行微服务。所以，让我们开始吧。您可以使用`node --prof <file_name>.js`处理任何文件的日志。

# 转储堆

堆是一个巨大的内存分配。当我们谈论我们的情况时，它是分配给 V8 进程的内存（回想一下 Node.js 的工作原理-事件循环和内存分配）。通过检查内存使用情况，您可以跟踪诸如内存泄漏之类的问题，或者只是检查服务的哪个部分消耗最多，根据这一点，您可以相应地调整代码。我们有一个非常好的`npm`模块（[`github.com/bnoordhuis/node-heapdump`](https://github.com/bnoordhuis/node-heapdump)），它可以生成一个稍后用于检查的转储。让我们熟悉读取转储过程以及何时进行转储，尽管以下步骤：

1.  我们安装 Heap Dump 并创建一个准备好使用的转储。打开任何项目，并使用以下命令安装`heapdump`模块：

```ts
npm install heapdump --save and npm install @types/heapdump --save-dev
```

1.  接下来，将以下代码行复制到您想要创建快照的任何进程中。我将它们保留在`Application.ts`中，只是一个例子。您可以在`chapter8/heapdump_demo`中遵循代码：

```ts
import * as heapdump from 'heapdump';
import * as path from 'path';
heapdump.writeSnapshot(path.join(__dirname, `${Date.now()}.heapsnapshot`),
  (err, filename) => {
    if (err) {
      console.log("failed to create heap snapshot");
    } else {
      console.log("dump written to", filename);
    }
  }
);
```

1.  现在，当您运行程序时，您可以在我们运行前面的代码行的目录中找到快照。您将找到类似于转储写入到`/home/parth/chapter 8/heapdump_demo/../<timestamp>.heapsnapshot`的输出。

1.  我们必须有类似`<current_date_in_millis>.heapsnapshot`的东西。它将以不可读的格式存在，但这就是我们将利用 Chrome 的 DevTools 的地方。打开 Chrome DevTools 并转到 Memory | Select profiling type | Load 选项。打开快照文件，您将能够看到以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/ac3665aa-d69e-495b-a3dc-822e9b8f0d74.png)

1.  单击 Statistics，您将能够看到这个：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/dcca964f-77ed-4cb6-9560-a07abd7b8b84.png)

您可以通过以下链接深入了解性能分析：

+   [`developers.google.com/web/tools/chrome-devtools/memory-problems/memory-101`](https://developers.google.com/web/tools/chrome-devtools/memory-problems/memory-101)[h](https://addyosmani.com/blog/taming-the-unicorn-easing-javascript-memory-profiling-in-devtools/)

+   [ttps://addyosmani.com/blog/taming-the-unicorn-easing-javascript-memory-profiling-in-devtools/](https://addyosmani.com/blog/taming-the-unicorn-easing-javascript-memory-profiling-in-devtools/)

我们可以定期进行转储，或者在发生错误时进行转储，这将有助于找到微服务中的问题。接下来，我们将看看如何进行 CPU 分析。

# CPU 分析

Chrome 开发者工具有一些非常好的选项，不仅限于调试。我们还可以利用内存分配、CPU 分析等。让我们深入研究 CPU 分析。为了理解工具，我们将启动一个消耗大量 CPU 的程序：

1.  创建任何 express 应用程序并创建一个随机路由，基本上迭代 100 次并在内存中分配 10⁸的缓冲区。您可以在`chapter 8/cpu-profiling-demo`中遵循代码：

```ts
private $alloc(){
  Buffer.alloc(1e8, 'Z');
}

router.get('/check-mem',
  (req, res, next) => {
    let check = 100;
    while (check--) {
      this.$alloc()
    }
    res.status(200).send('I am Done');
  }
)
```

1.  下一步是在 Chrome DevTools 中运行 Node.js 进程。要这样做，只需在`node --inspect ./dist/bin/www.js`中添加`--inspect`标志。

Chrome 调试协议包含在 Node.js 核心模块中，我们不需要在每个项目中都包含它。

1.  打开`chrome://inspect`，我们将能够在其中看到我们的进程。单击 inspect，我们就可以像标准 Web 应用程序一样调试 Node.js 应用程序。

1.  单击 Profiler，这是我们将调试 CPU 行为的地方。单击 Start，打开任何选项卡，然后点击`localhost:3000/check-mem`。回到我们的选项卡。当您能够看到 I am done 时，单击 Stop。您应该能够看到类似于图中的分析和分析详细信息：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/628ae1c9-2bd5-432a-aa8e-2bbcf22065b9.jpg)

性能分析

1.  现在，将鼠标悬停在单行上，您将能够看到这样的详细视图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/afa6e1d0-7a44-4b3b-a4fa-e3d20b84da25.png)

分析细节

# 实时调试/远程调试

倒数第二个重要功能是实时调试问题。随着 Node.js 内部引入检查器协议，这变得非常容易，因为我们所要做的就是创建一个运行进程的`--inspect`版本。这将打印出调试打开的进程的 URL，类似于这样：

```ts
Debugger listening on ws://127.0.0.1:9229/1309f374-d358-4d41-9878-8448b721ac5c
```

您可以安装 Chrome 扩展程序 Node.js V8 --inspector Manager (NiM)，从[`chrome.google.com/webstore/detail/nim-node-inspector-manage/gnhhdgbaldcilmgcpfddgdbkhjohddkj`](https://chrome.google.com/webstore/detail/nim-node-inspector-manage/gnhhdgbaldcilmgcpfddgdbkhjohddkj)用于调试远程应用程序，或者您甚至可以生成一个用于调试的进程并指定一个端口。

```ts
node inspect --port=xxxx <file>.js
```

您可以在这里找到其他选项：[`nodejs.org/en/docs/guides/debugging-getting-started/#command-line-options`](https://nodejs.org/en/docs/guides/debugging-getting-started/#command-line-options)。当使用`--inspect`开关启动任何进程时，Node.js 通过套接字侦听它，以诊断命令唯一地标识主机和端口。每个进程都被分配一个唯一的 UUID 以进行跟踪。Node-Inspector 还提供了一个 HTTP 端点来提供有关调试器的元数据，包括其 WebSocket URL、UUID 和 Chrome DevTools URL。我们可以通过访问`<host:port>/json/list`来获取这些信息。

调试很棒，但我们应该确保它不会带来副作用。调试意味着打开一个端口，这将带来安全隐患。应该特别注意以下几点：

+   公开暴露调试端口是不安全的

+   在内部运行的本地应用程序可以完全访问应用程序检查器

+   应该保持同源策略

这结束了我们的调试和分析会话。在下一节中，我们将重新讨论关键点，然后转向文档编制。

# 调试的关键点

在本节中，我们看到了调试和与分析相关的核心方面。我们学习了如何诊断泄漏或观察堆转储内存以分析服务请求。我们看到了代理通常可以帮助，即使它增加了网络跳数：

+   为了避免过载，我们有一个提供`503`中间件的模块。有关实现细节，请参阅[`github.com/davidmarkclements/overload-protection`](https://github.com/davidmarkclements/overload-protection)。

+   Chrome Inspector 是调试 Node.js 微服务的非常有用的工具，因为它不仅提供了调试界面，还提供了堆快照和 CPU 分析。

+   VS Code 也是一个非常用户友好的工具。

+   Node.js 拥抱了 node-inspector 并将其包含在核心模块中，从而使远程调试变得非常容易。

现在我们知道了调试的基本方面，让我们继续进行开发人员生活的最后一部分。是的，你猜对了：适当的文档，这不仅为技术团队节省了一天，也为非技术人员节省了一天。

# 文档编制

**文档**是后端和前端之间的一种约定，它负责管理两侧之间的依赖关系。如果 API 发生变化，文档需要快速适应。开发中最容易出错的之一就是缺乏对其他人工作的可见性或意识。通常，传统的方法是编写服务规范文档或使用一些静态服务注册表来维护不同的内容。无论我们如何努力，文档总是过时的。

# 需要文档

开发文档和组织对系统的理解增加了开发人员的技能和速度，同时处理微服务采用中出现的两个最常见的挑战——技术和组织变革。彻底、更新的文档的重要性不容小觑。每当我们问别人在做任何新事物时面临的问题时，答案总是一样。我们都面临同样的问题：我们不知道这个东西是如何工作的，它是一个新的黑匣子，给出的文档毫无价值。

依赖项或内部工具的文档不完善会使开发人员的生活变成一场噩梦，并减慢他们的能力和服务的生产就绪性。这浪费了无数的时间，因为唯一剩下的方法是重新设计系统，直到我们找到解决方案。爱迪生确实说过，“我找到了 2000 种不制造灯泡的方法”，但我更愿意把时间花在找到让自己更出色的 2000 种方法上。服务的文档不完善也会影响到为其做出贡献的开发人员的生产力。

生产就绪文档的目标是制作和组织关于服务的知识的集中存储库。分享这些信息有两个方面：服务的基本部分以及服务对实现哪一部分功能的贡献。解决这两个问题需要标准化共享微服务理解的文档方法。我们可以总结以下文档要点：

+   任何服务都应该有全面和详细的文档（应该包括服务是什么以及它对什么做出了贡献）

+   文档应该定期更新（所有新方法和维护的版本）

+   所有人都应该理解，而不仅仅是技术团队

+   其架构每隔一段固定的时间进行审查和审核

在接近微服务时，随着我们将每个业务能力划分为不同的服务，痛苦呈指数级增加。我们需要一种更通用的方法来记录微服务。Swagger 目前是文档的领先者。

有了 Swagger，您将得到以下内容：

+   不再有不一致的 API 描述。这些将被更新为完整的合同细节和参数信息。

+   您将不再需要编写任何文档；它将自动生成。

+   当然，再也不会有关于文档不完善的争论了。

本节将探讨如何使用 Swagger，了解其核心工具、优势和工作实现。所以，让我们开始吧。

# Swagger 101

Swagger 是您的微服务或者任何 RESTful API 的强大表示。成千上万的开发人员支持 Swagger 几乎在每一种编程语言和环境中。有了 Swagger-enabled 环境，我们可以得到交互式文档、客户端 SDK 生成、可发现性和测试。

Swagger 是 Open API 倡议的一部分（一个标准化 REST API 应该如何描述的委员会）。它提供了一组工具来描述和记录 RESTful API。Swagger 最初是一个 API 文档工具，现在还可以通过 Swagger Codegen（https://github.com/wcandillon/swagger-js-codegen）生成样板代码。Swagger 有一个庞大的工具生态系统，但主要我们将使用以下一组工具。我们将了解如何将 Swagger 与现有应用程序集成，或者编写符合 Swagger 标准的 API，通过这些 API 我们的文档将自动生成。从以下图表中可以了解到涉及的整个过程：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/ef59d39a-761c-4b99-90c2-6d431f32d76f.png)

Swagger_workflow

现在让我们看一下涉及过程的整体工具，以便全面了解其中涉及的所有方面。

# Swagger 编辑器和描述符

Swagger Descriptor 采用了设计驱动开发的方法。在这里，我们通过在 YML/YAML 文件或 JSON 文件中描述它们来设计我们端点的行为。（当然，作为开发人员，我甚至懒得写这个文件，我更希望它是自动生成的，我们将在后面的部分中看到。）这是最重要的部分，因为它是有关服务的上下文信息。

查看`第八章/hello_world_swagger.yaml`以了解描述文件的内容。

# Swagger 和描述符的关键点

+   您的 URL 路由、参数和描述都在`.yaml`文件中定义。

+   无论参数是否必需，您都可以使用 required true 进行传递，这将在测试参数时进行验证

+   它还可以返回响应代码及其描述

+   Swagger 读取这个`.yaml`文件来生成其 Swagger UI 并使用 Swagger 检查器测试服务

# Swagger Editor

Swagger Editor 是一个在线工具，可以帮助您

您可以通过在浏览器中预览实时文档来编辑 Swagger API 规范。这样，我们可以看到应用最新更改后文档的实际外观。编辑器具有清晰的界面，易于使用，并具有许多功能，可设计和记录各种微服务。它可以在线访问：[`editor2.swagger.io/#!/`](https://editor2.swagger.io/#!/)。只需编写或导入一个`swagger.yaml`文件，我们就可以实时查看 Swagger UI。

让我们通过 Swagger Editor 和 Swagger Descriptor 动手：

1.  打开[`editor2.swagger.io`](https://editor2.swagger.io)，并输入我们之前的描述符（`hello_world_swagger.yaml`）。

1.  您将能够在右侧看到实时文档：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/fcdb4dcf-b65d-45f6-bdd2-7d48398895c4.png)

Swagger Editor

1.  尝试在描述符文件中插入更多代码，并查看交互式文档。另外，尝试运行“尝试此操作”。它将提供 HTTP 请求的描述以及所有标头和响应。

# Swagger Codegen

Swagger Codegen 是一个脚手架引擎，它可以根据 Swagger 定义生成交互式文档、API 客户端和服务器存根。我们在 Swagger Editor 中看到的以前的选项（生成服务器和生成客户端）类似于 Swagger Codegen 的实现。它支持许多语言。

客户端脚手架工具，支持 TypeScript Angular、TypeScript Node、JavaScript、Python、HTML、Java 和 C#等语言。服务器端脚手架工具支持 Haskell、Node.js、Go 语言和 Spring 等语言。

**Swagger CodeGen** ([`swagger.io/swagger-codegen/`](https://swagger.io/swagger-codegen/))帮助我们更快地构建 API，并通过遵循 OpenAPI 定义的规范来提高质量。它生成服务器存根和客户端 SDK，因此我们可以更专注于 API 实现和业务逻辑，而不是代码创建和采用标准：

+   **Swagger CodeGen 的优势**：

+   它生成服务器代码、客户端代码和文档

+   它允许更快地更改 API

+   生成的代码是开源的

+   **Swagger CodeGen 的缺点**：

+   通过添加额外的工具和库以及管理这些工具的复杂性，项目复杂性增加了

+   它可能会生成用户无法消化的大量代码

您可以查看`第八章/typescript-node-client/api.ts`，以查看基于我们最初的 Swagger 描述符定义生成的自动生成代码。

# Swagger UI

Swagger UI 允许我们可视化 RESTful API。可视化是从 Swagger 规范自动生成的。Swagger UI 接收 Swagger 描述文件并在 UI 中使用 Swagger 检查器创建文档。Swagger UI 就是我们在前面截图中右侧看到的内容。此外，这可以根据权限进行访问。Swagger UI 是一组 HTML、JavaScript 和 CSS 资源，可以从符合 Swagger 的 API 动态生成美丽的文档。我们将为我们的产品目录微服务生成文档，并在其中使用 Swagger UI 组件。

# Swagger 检查器

这是一种基于 OpenAPI 规范生成文档的无痛方式。一旦您检查了 SWAGGER 检查器的工作原理，然后您可以创建文档并与世界分享。我们可以通过选择历史记录中先前测试过的端点来轻松自动生成文档，然后发出创建 API 定义的命令。这在网上很像 Postman。您可以将 Swagger 检查器作为 Chrome 扩展程序下载。它具有以下选项：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/3a7c8ecd-ebe5-47a5-a01b-327fe63702dc.png)

Swagger 检查器

现在我们已经熟悉了 Swagger，让我们看看如何在微服务中使用 Swagger 为我们生成美丽的文档。接下来的部分讨论了我们可以集成 Swagger 的可能方法。

# 使用 Swagger 的可能策略

Swagger 主要用于记录服务和测试服务。在实施 Swagger 时有两种基本方法。它们如下：

+   **自上而下或设计优先方法：**在这里，使用 Swagger 编辑器创建 Swagger 定义，然后使用 Swagger Code-gen 生成客户端和服务器的代码。在编写任何代码之前，Swagger 将用于设计 API 和源。

+   **自下而上方法：**在这里，对于任何现有的 API，Swagger 用于生成文档。

我们将研究这两种方法以及我们可以使用的最佳实践。 

# 自上而下或设计优先方法

通常，通过添加几行代码来生成有效的 Swagger 文件和文档似乎是一个好主意。我们已经编写了所有的代码，然后我们记得：*天哪，我要如何向其他人解释这个？我需要记录每一个 API 吗？*在这种情况下，通过添加注释来实时生成文档似乎是一个梦想成真。TSOA（[`www.npmjs.com/package/tsoa`](https://www.npmjs.com/package/tsoa)）就是基于这样的原则设计的。根据 TSOA 的 README 文件，它从编写的控制器和包括以下内容的模型生成有效的 Swagger 规范。这本质上是一种自下而上的方法，我们已经有了现有的 REST API，并且利用 Swagger 来记录现有的 API。

TSOA 从控制器和模型生成有效的 Swagger `spec`文件，其中包括：

+   各种 REST URL 的路径（例如：`获取用户：- server_host/users/get_users`）

+   基于 TypeScript 接口的定义（这些是模型文件或属性描述符）

+   参数类型；也就是说，根据 TypeScript 语法，模型属性标记为必需或可选（例如，`productDescription?: string`在 Swagger 规范中标记为可选）

+   jsDoc 支持对象描述（大多数其他元数据可以从 TypeScript 类型中推断出）

与 routing-controllers 类似，路由可以为我们选择的任何中间件生成。选项包括 Express、Hapi 和 Koa。与 routing-controllers 类似，TSOA 内置了类验证器。TSOA 尽可能地减少样板代码，并提供了大量的注释。您可以在`npm`中查看文档，以详细了解各种可用的选项。我们主要关注`@Route`注释，它将为我们生成 Swagger 文档。在示例中，我们将使用 TSOA 并生成文档。

请参阅自上而下方法的提取源，示例非常简单，严格遵循文档。

# 自下而上的方法

哇！经过自上而下的方法，似乎是完美的计划。但是当我们已经开发了项目，现在我们想要生成我们的文档时怎么办呢？我们陷入了困境。我们该怎么办呢？幸运的是，我们有解决方案。我们将利用`swagger-ui-express` ([`www.npmjs.com/package/swagger-ui-express`](https://www.npmjs.com/package/swagger-ui-express))来生成文档。它每周有超过 45,000 次下载。这是一个由社区驱动的包，为您的 express 应用程序提供中间件，根据 Swagger 文档文件提供 Swagger UI。我们需要添加一个路由，用于托管 Swagger UI。文档很好，一切都在那里——我们需要的一切。所以，让我们开始吧。您可以在`Chapter 8/bottom-up-swagger`文件夹中跟随源代码。

1.  从`npm`中安装模块作为依赖项：

```ts
npm install swagger-ui-express --save
```

1.  接下来，我们需要添加一个路由，用于托管 Swagger UI。我们需要生成 Swagger 定义，并在每次部署时更新它。

1.  我们有两种选项来生成 Swagger 文档。要么我们在每个路由处理程序中添加注释，要么我们使用 Swagger inspector 来测试所有 REST API，将它们合并，并生成一个定义文件。

1.  无论我们选择哪种路线，我们的目标都是相同的：生成`swagger.json`文件。采用第一种方法，我们将使用`swagger-jsdoc` ([`www.npmjs.com/package/swagger-jsdoc`](https://www.npmjs.com/package/swagger-jsdoc))。通过以下命令将模块作为依赖项下载：

```ts
npm install swagger-jsdoc --save
```

1.  让我们开始配置。首先，我们需要在 Express 启动时初始化 Swagger JS Doc。创建一个类`SwaggerSpec`，并在其中添加以下代码：

```ts
export class SwaggerSpec {
  private static swaggerJSON: any;
  constructor() { }
  static setUpSwaggerJSDoc() {
    let swaggerDefinition = {
      info: {
        title: 'Bottom up approach Product Catalog',
        version: '1.0.0',
        description: 'Demonstrating TypeScript microservice bottom up approach'
      },
      host: 'localhost:8081',
      basePath: '/'
    };
    let options = {
      swaggerDefinition: swaggerDefinition,
      apis: ['./../service-layer/controllers/*.js']
    }
    this.swaggerJSON = swaggerJSDoc(options);
  }

  static getSwaggerJSON() {
    return this.swaggerJSON;
  }
}
```

在这里，我们初始化了 JSDoc，并将`swagger.json`存储在私有静态变量`swaggerJSON:any`中，这样在需要提供 JSON 时就可以使用它。我们在`JSDoc`对象中保留了通常的配置。

1.  接下来，在 express 启动时，我们需要初始化`setUpSwaggerJSDoc`方法，这样我们就可以在服务器启动时填充 JSON。

1.  创建一个新的`Controller`，它会给我们提供`swagger.json`作为 HTTP 端点。

```ts
@JsonController('/swagger')
export class SwaggerController {
  constructor() { }
  @Get('/swagger.json')
  async swaggerDoc( @Req() req, @Res() res) {
    return SwaggerSpec.getSwaggerJSON();
  }
}
```

1.  访问`http://localhost:8081/swagger/swagger.json`以查看初始的 Swagger JSON。

1.  现在，我们需要在每个路由中添加 JSDoc 风格的注释以生成 Swagger 规范，并在路由处理程序中添加 YAML 注释。添加适当的注释将填充我们的`swagger.json`：

```ts
/**
* @swagger
* definitions:
* Product:
* properties:
* name:
* type:string
* /products/products-listing:
* get:
* tags:
* - Products
* description: Gets all the products
* produces:
* - application/json
* responses:
* 200:
* description: An array of products
* schema:
* $ref: '#/definitions/Product'
*/
getProductsList() {
 //
}
```

1.  另一个选择是使用 Swagger inspector 生成文档。现在我们已经完成了 Swagger 生成，我们需要生成 Swagger UI。在`Express.ts`中添加以下内容：

```ts
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));
app.use('/api/v1', router);
```

Swagger 是一个很好的文档工具，可以满足我们所有的需求。无论是从一开始使用还是在开发之后使用，它都是满足我们文档需求的好选择。`./api/v1`文件将为您生成 Swagger 文档。

# 从 Swagger 定义生成项目

到目前为止，我们是从我们的源代码中生成 swagger 定义。反过来也是成立的。我们可以轻松地从 Swagger 定义和语言类型中生成项目（我们在第七章中看到了类似的内容，*服务状态和服务间通信*。有印象吗？没错。rPC 和代码生成）。让我们下载 swagger-code-generate 并创建我们的项目：

1.  检查提取的 src `chapter 8/swagger-code-gen`中更新的`hello_world_swagger.yml`。它增加了一个用于更新产品信息的 API 路由/端点。

1.  下一步是从[`github.com/swagger-api/swagger-codegen`](https://github.com/swagger-api/swagger-codegen)下载 swagger-code-gen，这样我们甚至可以将其配置为自动化或根据需要使用，而不是每次都去在线 Swagger 编辑器。你也可以在本书的提取源中找到 swagger-code-gen。

1.  由于这是一个在 JVM 上运行的项目，我们构建项目以便运行它。输入命令`mvn package`来构建 JAR。

1.  接下来，我们将生成源代码：

```ts
java -jar modules/swagger-codegen-cli/target/swagger-codegen-cli.jar generate -i  ..\hello_world_swagger.yaml -l typescript-node -o ../typescript-nodejs
```

1.  你可以在`chapter-8/swagger-code-gen`中探索`typescript-nodejs`，以了解生成的结构并进行实际操作。同样，你也可以选择任何其他语言。更多文档可以在这里找到[`github.com/swagger-api/swagger-codegen/blob/master/README.md`](https://github.com/swagger-api/swagger-codegen/blob/master/README.md)。

Swagger 是一个很棒的工具，可以按需生成文档。生成的文档即使对于产品经理或合作伙伴也是易懂的，可读性强，且易于调整。它不仅使我们的生活变得更加轻松，而且使 API 更易消费和管理，因为它符合 OpenAPI 规范。Swagger 被 Netflix、Yelp、Twitter 和 GitHub 等领先公司广泛使用。在本节中，我们看到了它的各种用途以及其周期和各种方法。

# 总结

在本章中，我们讨论了测试、调试和文档编制。我们研究了测试的一些基本方面。我们研究了测试金字塔以及如何进行单元测试、集成测试和端到端测试。我们使用 Pact 进行了契约测试。然后，我们看了一下调试和分析过程，这对解决关键问题非常有帮助。我们看到了在关键故障发生时如何进行调试。最后，我们看了一下文档工具 Swagger，它有助于保持中央文档，并且我们研究了引入 Swagger 到我们的微服务的策略。

在下一章中，我们将讨论部署。我们将看到如何部署我们的微服务，介绍 Docker，并了解 Docker 的基础知识。然后，我们将了解一些监控工具和日志选项。我们将集成 ELK 堆栈以进行日志记录。


# 第九章：部署、日志记录和监控

“没有战略的战术是失败前的噪音。”

- 孙子

在上线生产并开始赚取收入之前，我们需要一个非常强大的部署策略。缺乏计划总是会导致意外紧急情况，从而导致严重的失败。这就是我们在本章中要做的事情。现在我们已经完成了开发工作，并通过测试和提供文档添加了双重检查，我们现在要着手进行*上线阶段*。我们将看到部署中涉及的所有方面，包括当前流行的术语——持续集成、持续交付和新的无服务器架构。然后我们将看到日志的需求以及如何创建自定义的集中式日志解决方案。更进一步，我们将看看**Zipkin**——一个用于分布式系统日志记录的新兴工具。最后，我们将看到监控的挑战。我们将研究两个著名的工具——**Keymetrics**和**Prometheus**。

本章涵盖以下主题：

+   部署 101

+   构建流水线

+   Docker 简介

+   无服务器架构

+   日志记录 101

+   使用 ELK 进行定制日志记录

+   使用 Zipkin 进行分布式跟踪

+   监控 101

+   使用 Keymetrics、Prometheus 和 Grafana 等工具进行监控

# 部署

在生产环境中发布一个应用程序，有足够的信心它不会崩溃或让组织损失资金，这是开发者的梦想。即使是手动错误，比如没有加载正确的配置文件，也会造成巨大问题。在本节中，我们将看到如何自动化大部分事情，并了解持续集成和持续交付（CI 和 CD）。让我们开始了解整体构建流水线。

# 决定发布计划

自信是好事，但过分自信是不好的。在部署到生产环境时，我们应该随时准备好回滚新的更改，以防出现重大关键问题。需要一个整体的构建流水线，因为它可以帮助我们规划整个过程。在进行生产构建时，我们将采用这种技术：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/727d2a3e-ddc3-4320-8e5e-3dfb23ff35ac.png)

构建流水线

整个构建过程始于**开始**块。每当发生任何提交时，WebHooks（由 Bitbucket 和 GitHub 提供）会触发构建流水线。Bitbucket 也有构建流水线工具（[`bitbucket.org/product/features/pipelines`](https://bitbucket.org/product/features/pipelines)）。这个构建流水线可以在主分支合并时触发。一旦到达构建阶段，我们首先运行一些代码覆盖分析和单元测试。如果测试结果不符合要求的 SLA，我们会中止流程。如果符合整体 SLA，我们就会根据它创建一个镜像，并在暂存服务器上构建它（如果我们没有暂存服务器，我们可以直接移动到生产服务器）。一旦你有一个准备好的 Docker 镜像，你就根据你部署的位置设置环境。之后，运行一些理智检查以确保我们不部署破损的代码。在流水线的所有级别上运行它们是一个极好的想法，可以最大程度地减少错误的机会。现在，一旦服务符合 SLA，现在是时候在真实环境中部署它了。我通常遵循的一个良好实践是生产服务器不应该有版本控制。根据我们使用的任何工具（OpenShift、Kubernetes、Docker 等），我们将这些工具传递给它们来启动镜像。然后我们需要开始集成测试，其中包括检查容器是否健康以及与服务注册表和 API 网关检查服务是否注册。为了确保没有任何破坏，我们需要进行滚动更新，其中我们逐个部署新实例并移除旧实例。我们的代码库应该能够处理旧/遗留代码，并且只有在每个依赖方都接受后才能废弃它。完成集成测试后，下一个任务涉及运行契约测试和验收测试。一旦这些测试成功运行，我们就可以从暂存环境移动到生产环境或上线。如果流水线失败，上一个成功的源代码将作为回滚策略部署回来。

整个过程应该是自动化的，因为我们更容易出错。我们将研究 CI/CD 以及它们如何让我们的生活变得更加轻松。CI/CD 承诺，我们可以在功能完成时部署它，并且仍然相当有信心它不会破坏产品。我们所看到的流水线有大量与之相关的任务和阶段。让我们看看以下阶段：

+   **开发阶段/功能分支**：我们通过创建功能分支来开始开发。我们保持主分支不变，并且只在主分支中保留经过验证和测试的代码。这样，我们的生产环境就是主分支的复制品，我们可以在开发分支中进行任意数量的实验。如果某些东西失败了，我们总是可以回到主分支并丢弃或删除一个分支。

+   **测试阶段/QA 分支**：一旦我们的开发完成，我们将代码推送到 QA 分支。现代开发方法更进一步，我们采用 TDD/BDD。每当我们将代码推送到 QA 时，我们运行测试用例以获得精确的代码覆盖率。我们运行一些代码检查工具，这些工具给我们一个关于代码质量的想法。在所有这些之后，如果这些测试成功，那么我们才将代码推送到 QA 分支。

+   **发布阶段/主分支**：一旦我们的 QA 完成并且我们的测试用例覆盖通过了，我们将代码推送到主分支，希望将其推送到生产环境。我们再次运行我们的测试用例和代码覆盖工具，并检查是否有任何破坏。一旦成功，我们将代码推送到生产服务器并运行一些冒烟测试和契约测试。

+   **发布/标签**：一旦代码推送到生产环境并成功运行，我们会为发布创建一个分支/标签。这有助于确保我们可以在不久的将来返回到这一点。

在每个阶段手动进行这样的过程是一个繁琐的过程。我们需要自动化，因为人类容易出错。我们需要一个持续交付机制，其中我的代码中的一个提交可以确保我部署的代码对我的生态系统是安全的。在下一节中，我们将看看持续集成和持续交付：

+   **持续集成：**这是将新功能从其他分支集成或合并到主分支，并确保新更改不会破坏现有功能的实践。一个常见的 CI 工作流程是，除了代码，您还编写测试用例。然后创建代表更改的拉取请求。构建软件可以运行测试，检查代码覆盖率，并决定拉取请求是否可接受。一旦**拉取请求**（PR）合并，它就进入 CD 部分，即持续交付。

+   **持续交付：**这是一种方法，我们旨在随时无缝交付一小块可测试且易于部署的代码。CD 是高度可自动化的，在某些工具中，它是高度可配置的。这种自动化有助于快速将组件、功能和修复程序分发给客户，并让任何人对生产环境中有多少以及有什么有一个确切的想法。

随着 DevOps 的不断改进和容器的兴起，出现了许多新的自动化工具来帮助 CI/CD 流水线。这些工具与日常工具集成，例如代码存储库管理（GitHub 可以与 Travis 和 CircleCI 一起使用，Bitbucket 可以与 Bitbucket pipelines 一起使用）以及跟踪系统，如 slack 和 Jira。此外，出现了一个新的趋势，即无服务器部署，开发人员只需关注他们的代码和部署，其他问题将由提供者解决（例如，亚马逊有 AWS，谷歌有 GCP 函数）。在下一节中，我们将看看各种可用的部署选项。

# 部署选项

在这一部分，我们将看一些著名的可用部署选项，并了解它们各自的优势和劣势。我们将从容器的世界开始，看看为什么现在所有东西都是 docker 化的。所以，让我们开始吧。

在开始之前，让我们先了解一下 DevOps 101，以便理解我们将要使用的所有术语。

# DevOps 101

在这一部分，我们将了解一些基本的 DevOps 基础知识。我们将了解什么是容器以及它有什么优势。我们将看到容器和虚拟机之间的区别。

# 容器

随着云计算的进步，世界正在看到容器系统的重新进入。由于技术的简化（Docker 遵循与 GIT 相同的命令），容器已被广泛采用。容器在操作系统之上提供私有空间。这种技术也被称为系统中的虚拟化。容器是构建、打包和运行隔离的机制（软件仅驻留和限制在该容器中）。容器处理自己的文件系统、网络信息、内置内部进程、操作系统实用程序和其他应用程序配置。容器内部装载多个软件。

容器具有以下优势：

+   独立的

+   轻量级

+   易于扩展

+   易于移动

+   更低的许可和基础设施成本

+   通过 DevOps 自动化

+   像 GIT 一样进行版本控制

+   可重复使用

+   不可变的

# 容器与虚拟机（VMs）

虽然鸟瞰图似乎两者都在说同样的事情，但容器和虚拟机（VM）有很大的不同。虚拟机提供硬件虚拟化，例如 CPU 数量、内存存储等。虚拟机是一个独立的单元，还有操作系统。虚拟机复制完整的操作系统，因此它们很重。虚拟机为在其上运行的进程提供完全隔离，但它限制了可以启动的虚拟机数量，因为它很重且消耗资源，并且需要维护。与虚拟机不同，容器共享内核和主机系统，因此容器的资源利用率非常低。容器作为在主机操作系统之上提供隔离层，因此它们是轻量级的。容器镜像可以公开使用（有一个庞大的 Docker 存储库），这使得开发人员的生活变得更加轻松。容器的轻量特性有助于自动化构建、在任何地方发布构件、根据需要下载和复制等。

# Docker 和容器世界

虚拟化是 DevOps 中目前最大的趋势之一。虚拟化使我们能够在各种软件实例之间共享硬件。就像微服务支持隔离一样，Docker 通过创建容器来提供资源隔离。使用 Docker 容器进行微服务可以将整个服务以及其依赖项打包到容器中，并在任何服务器上运行。哇！安装软件在每个环境中的日子已经过去了。Docker 是一个开源项目，用于在新环境中轻松打包、运输和运行任何应用程序作为轻量级容器，而无需安装所有东西。Docker 容器既不依赖于平台也不依赖于硬件，这使得可以轻松地在任何地方运行容器，从笔记本电脑到任何服务器，而无需使用任何特定的语言框架或打包软件。当今，容器化通常被称为 dockerization。我们已经从第二章开始进行了 docker 化，*为旅程做准备*。因此，让我们了解涉及的整个过程和概念。

我们已经在第二章中看到了 Docker 的安装，*为旅程做准备*。现在，让我们深入了解 Docker。

# Docker 组件

Docker 有以下三个组件：

+   **Docker 客户端**：Docker 客户端是一个命令行程序，实际上通过套接字通信或 REST API 与 Docker 主机内的 Docker 守护程序进行通信。使用具有 CLI 选项的 Docker 客户端来构建、打包、运输和运行任何 Docker 容器。

+   **Docker 主机**：Docker 主机基本上是一个服务器端组件，包括一个 Docker 守护程序、容器和镜像：

+   Docker 守护程序是在主机机器上运行的服务器端组件，包含用于构建、打包、运行和分发 Docker 容器的脚本。Docker 守护程序为 Docker 客户端公开了 RESTful API，作为与其交互的一种方式。

+   除了 Docker 守护程序，Docker 主机还包括在特定容器中运行的容器和镜像。无论哪些容器正在运行，Docker 主机都包含这些容器的列表，以及启动、停止、重启、日志文件等选项。Docker 镜像是那些从公共存储库构建或拉取的镜像。

+   **Docker 注册表**：注册表是一个公开可用的存储库，就像 GitHub 一样。开发人员可以将他们的容器镜像推送到那里，将其作为公共库，或者在团队之间用作版本控制。

在下图中，我们可以看到所有三个 Docker 组件之间的整体流程：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/da4d11d3-3d0a-4817-97ae-abd01f7647c0.png)

Docker 组件和流程

以下是典型的 Docker 流程：

1.  每当我们运行诸如`sudo docker run ubuntu /bin/echo 'hello carbon five!'`的命令时，该命令会传递给守护进程。它会尝试搜索是否存在具有名称 Ubuntu 的现有镜像。如果没有，它会转到注册表并在那里找到镜像。然后它将在主机内下载该容器镜像，创建一个容器，并运行`echo`命令。它会将 Ubuntu 镜像添加到 Docker 主机内可用的镜像列表中。

1.  我们的大多数镜像都将基于 Docker Hub 存储库（[`hub.docker.com/`](https://hub.docker.com/)）中的可用镜像。除非非常需要，我们不会重新发明轮子。Docker pull 会向 Docker 主机发出命令，从存储库中拉取特定镜像，并使其在 Docker 主机的镜像列表中可用。

1.  `docker build`命令从 Dockerfile 和可用的上下文构建 Docker 镜像。构建的上下文是指在 Dockerfile 中指定的路径或 URL 中的文件集。构建过程可以引用上下文中的任何文件。例如，在我们的情况下，我们下载了 Node.js，然后根据`package.json`执行了`npm install`。Docker 构建创建一个镜像，并使其在 Docker 主机内的镜像列表中可用。

# Docker 概念

现在我们已经了解了核心的 Docker 流程，让我们继续了解 Docker 涉及的各种概念。这些概念将使我们更容易编写 Docker 文件并创建自己的微服务容器镜像：

+   **Docker 镜像**：Docker 镜像只是 Docker 业务能力组成部分的快照。它是操作系统库、应用程序及其依赖项的只读副本。一旦创建了镜像，它将在任何 Docker 平台上运行而不会出现任何问题。例如，我们的微服务的 Docker 镜像将包含满足该微服务实现的业务能力所需的所有组件。在我们的情况下，Web 服务器（NGINX）、Node.js、PM2 和数据库（NoSQL 或 SQL）都已配置为运行时。因此，当有人想要使用该微服务或在某处部署它时，他们只需下载镜像并运行它。该镜像将包含从 Linux 内核（`bootfs`）到操作系统（Ubuntu/CentOS）再到应用程序环境需求的所有层。

+   **Docker 容器**：Docker 容器只是 Docker 镜像的运行实例。您可以下载（或构建）或拉取 Docker 镜像。它在 Docker 容器中运行。容器使用镜像所在的主机操作系统的内核。因此，它们基本上与在同一主机上运行的其他容器共享主机内核（如前图所示）。Docker 运行时确保容器具有其自己的隔离的进程环境以及文件系统和网络配置。

+   **Docker Registry**：Docker Registry 就像 GitHub 一样，是 Docker 镜像发布和下载的中心位置。[`hub.docker.com`](https://hub.docker.com)是 Docker 提供的中央可用的公共注册表。就像 GitHub（提供版本控制的存储库），Docker 也提供了一个特定于需求的公共和私有镜像存储库（我们可以将我们的存储库设为私有）。我们可以创建一个镜像并将其注册到 Docker Hub。因此，下次当我们想在任何其他机器上使用相同的镜像时，我们只需引用存储库来拉取镜像。

+   **Dockerfile**：Dockerfile 是一个构建或脚本文件，其中包含了构建 Docker 镜像的指令。可以记录多个步骤，从获取一些公共镜像到在其上构建我们的应用程序。我们已经编写了 Docker 文件（回想一下第二章中的`.Dockerfile`，*为旅程做准备*）。

+   **Docker Compose**：Compose 是 Docker 提供的一个工具，用于在一个容器内运行多容器 Docker 应用程序。以我们的产品目录微服务为例，我们需要一个 MongoDB 容器以及一个 Node.js 容器。Docker compose 正是为此而设计的。Docker compose 是一个三步过程，我们在 Docker 文件中定义应用程序的环境，在`docker-compose.yml`中使其他服务在隔离的环境中运行，然后使用`docker-compose up`运行应用程序。

# Docker 命令参考

现在我们已经了解了 Docker 的概念，让我们来学习 Docker 命令，以便我们可以将它们添加到我们的实验中：

| **命令** | **功能** |
| --- | --- |
| `docker images` | 查看我的机器上所有可用的 Docker 镜像。 |
| `docker run <options> <docker_image_name>:<version> <operation>` | 将 Docker 镜像启动到容器中。 |
| `docker ps` | 检查 Docker 容器是否正在运行。 |
| `docker exec -ti <container-id> bash` | 通过实际在 bash 提示符上运行来查看 Docker 镜像内部的内容。能够使用诸如`ls`和`ps`之类的命令。 |
| `docker exec <container_id> ifconfig` | 查找 Docker 容器的 IP 地址。 |
| `docker build` | 根据`.DockerFile`中的指令构建镜像。 |
| `docker kill <containername> && docker rm <containername>` | 终止正在运行的 Docker 容器。 |
| `docker rmi <imagename>` | 从本地存储库中删除 Docker 镜像。 |
| `docker ps -q &#124; x args docker kill &#124; xargs docker rm` | 终止所有正在运行的 Docker 容器。 |

# 使用 NGINX、Node.js 和 MongoDB 设置 Docker

现在我们知道了基本命令，让我们为一个带有 NGINX 的产品目录服务编写 Dockerfile 和 Docker compose 文件，以处理负载平衡，就像我们在第四章中为 MongoDB 和 Node.js 编写`docker compose up`一样，*开始您的微服务之旅*。您可以按照`第九章/Nginx-node-mongo`中的示例进行操作，该示例只是在产品目录微服务的副本上添加了 NGINX，以便服务只能通过 NGINX 访问。创建以下结构：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/6748e0aa-115c-4f07-bc86-de307ecad01a.png)

NGINX-mongodb-node.js 文件结构

现在让我们写一些规则：

1.  我们将为 Node.js 创建 Dockerfile。它将与我们之前使用的内容相同。

1.  我们将为 NGINX 编写 Dockerfile。我们基本上告诉 NGINX 启用`sites-enabled`文件夹中定义的应用程序的规则：

```ts
FROM tutum/nginx
RUN rm /etc/nginx/sites-enabled/default
COPY nginx.conf /etc/nginx.conf
RUN mkdir /etc/nginx/ssl
COPY certs/server.key /etc/nginx/ssl/server.key
COPY certs/server.crt /etc/nginx/ssl/server.crt
ADD sites-enabled/ /etc/nginx/sites-enabled
```

1.  接下来，我们在 NGINX 中定义一些加固规则，以便处理我们的负载平衡以及缓存和其他需求。我们将在两个地方编写我们的规则——`nodejs_project`和`nginx.conf`。在`nodejs_project`中，我们定义所有代理级别设置和 NIGINX 服务器设置。在`nodejs_project`中写入以下代码：

```ts
server {
listen 80;
server_name product-catalog.org;
access_log /var/log/nginx/nodejs_project.log;
charset utf-8;
location / {
proxy_pass http://chapter9-app:8081;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}}
```

1.  让我们看一些用于配置 NGINX 以用于生产级别（加固我们的 Web 服务器）的示例规则。我们将这些规则写在`nginx.conf`中。为了压缩发送到我们的 NGINX 服务器的所有输入和输出请求，我们使用以下代码：

```ts
http {...
gzip on;
gzip_comp_level 6;
gzip_vary on;
gzip_min_length 1000;
gzip_proxied any;
gzip_types text/plain text/html text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript;
gzip_buffers 16 8k;
...
}
```

前面的参数只是配置了任何入站或出站的 HTTP 请求，具有这些属性。例如，它将对响应进行 gzip 压缩，对所有类型的文件进行 gzip 压缩等。

1.  无论服务器之间交换了什么资源，我们都有选项将其缓存，这样每次都不需要再次查询。这是在 Web 服务器层进行缓存：

```ts
http {
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=one:8m max_size=3000m inactive=600m;
proxy_temp_path /var/tmp;
}
```

1.  最后，我们创建我们的`docker compose`文件来启动 MongoDB、Node.js 和 NGINX 来定义。从源中复制`docker-compose.yml`文件以执行构建。

1.  打开终端，输入`docker-compose up --build`，看看我们的部署实际运行情况。

所有内部端口现在都将被阻止。唯一可访问的端口是默认端口`80`。访问`localhost/products/products/products-listing`URL 以查看我们的部署实时运行。再次访问 URL，将从缓存中加载响应。请参阅以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/c9386336-7251-4e1e-905b-213df0b086bc.png)

缓存响应

现在我们已经使用包含 Web 层的容器映像运行起来了，在接下来的部分中，我们将看一下我们的构建流水线以及 WebHooks 在其中扮演的重要角色。

# 我们构建流水线中的 WebHooks

WebHooks 是项目中可以用来绑定事件的东西，无论何时发生了什么。比如一个拉取请求被合并，我们想立即触发一个构建 - WebHooks 就可以做到这一点。WebHook 本质上是一个 HTTP 回调。您可以通过转到设置并添加 WebHook 来在存储库中配置 WebHook。典型的 WebHook 屏幕如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/38bddbf4-9f5d-45a5-b677-0ad20f06fbd8.png)

WebHook

如前面的屏幕截图所示，它有各种触发器，例如推送、分叉、更新、拉取请求、问题等。我们可以根据这个 WebHook 设置警报并触发各种操作。

在下一节中，我们将看到微服务开发中出现的新趋势，即无服务器部署。

请检查提取的源/流水线，以查看端到端流水线的运行情况。

# 无服务器架构

这些天出现的新趋势是无服务器拓扑结构。这并不实际上意味着无服务器或没有服务器。服务器被用户抽象化，用户只关注开发方面，其他一切都交给供应商。AWS Lambda 就是无服务器架构的一个例子，您只需将微服务打包为 ZIP 并上传到 AWS Lambda。亚马逊会处理其他事情，包括启动足够的实例来处理大量服务请求。

Lambda 函数是一个无状态函数。它通过调用 AWS 服务来处理请求。我们只需根据请求次数和提供这些请求所花费的时间来计费。同样，Google 也有云函数。但是，这种模式有以下优点和缺点：

+   **优点：**

+   我们只关注代码，不需要担心底层基础设施的细节。AWS 具有内置的网关，可与 Lambda 函数一起使用。

+   极具弹性的架构。它自动处理负载请求。

+   您只需为每个请求付费，而不是租用整个虚拟机并每月付费。

+   **缺点：**

+   仅支持少数语言。没有多语言环境的自由。

+   这些始终是无状态的应用程序。AWS Lambda 不能用于像 RabbitMQ 这样的队列处理。

+   如果应用程序启动不够快，无服务器架构就不适合我们。

这基本上就是部署的内容。在下一节中，我们将看一下日志记录以及如何创建定制的集中式日志记录解决方案。

# 日志记录

微服务完全分布式，作为单个请求可以触发对其他微服务的多个请求，跟踪失败或故障的根本原因或跨所有服务的请求流程变得困难。

在本节中，我们将学习如何通过正确的方式记录不同的 Node.js 微服务。回顾我们在第四章中看到的日志记录概念和日志类型，*开始您的微服务之旅*。我们将朝着这个方向前进，并创建一个集中式日志存储。让我们首先了解在分布式环境中我们的日志记录需求以及我们将遵循的一些最佳实践来处理分布式日志。

# 日志记录最佳实践

一旦在开发后出现任何问题，我们将完全迷失，因为我们不是在处理单个服务器。我们正在处理多个服务器，整个系统不断移动。哇！我们需要一个完整的策略，因为我们不能随意到处走动，检查每个服务的日志。我们完全不知道哪个微服务在哪个主机上运行，哪个微服务提供了请求。要在所有容器中打开日志文件，搜索日志，然后将其与所有请求相关联，这确实是一个繁琐的过程。如果我们的环境启用了自动扩展功能，那么调试问题将变得非常复杂，因为我们实际上必须找到提供请求的微服务实例。

以下是微服务日志记录的一些黄金规则，这将使生活更轻松。

# 集中和外部化日志存储

微服务分布在生态系统中，以简化开发并实现更快的开发。由于微服务在多个主机上运行，因此在每个容器或服务器级别都记录日志是不明智的。相反，我们应该将所有生成的日志发送到一个外部和集中的位置，从那里我们可以轻松地从一个地方获取日志信息。这可能是另一个物理系统或任何高可用性存储选项。一些著名的选项包括以下内容：

+   **ELK 或弹性堆栈**：ELK 堆栈（[`www.elastic.co/elk-stack`](https://www.elastic.co/elk-stack)）由 Elasticsearch（一个分布式、全文可扩展搜索数据库，允许存储大量数据集）、Logstash（它从多种来源收集日志事件，并根据需要进行转换）、和 Kibana（可视化存储在 Elasticsearch 中的日志事件或任何其他内容）组成。使用 ELK 堆栈，我们可以在由**Kibana**和**Logstash**提供的 Elasticsearch 中拥有集中的日志。

+   **CloudWatch（仅当您的环境在 AWS 中时）**：Amazon CloudWatch（[`aws.amazon.com/cloudwatch/`](https://aws.amazon.com/cloudwatch/)）是用于监视在 AWS 环境中运行的资源和应用程序的监控服务。我们可以利用 Amazon CloudWatch 来收集和跟踪指标，监视日志文件，设置一些关键警报，并自动对 AWS 资源部署中的更改做出反应。CloudWatch 具有监视 AWS 资源的能力，其中包括 Amazon EC2 实例、DynamoDB 表、RDS 数据库实例或应用程序生成的任何自定义指标。它监视所有应用程序的日志文件。它提供了系统级别的资源利用情况可见性，并监视性能和健康状况。

# 日志中的结构化数据

日志消息不仅仅是原始消息，还应包括一些内容，如时间戳；日志级别类型；请求所花费的时间；元数据，如设备类型、微服务名称、服务请求名称、实例名称、文件名、行号；等等，从中我们可以在日志中获取正确的数据来调试任何问题。

# 通过相关 ID 进行标识

当我们进行第一次服务请求时，我们会生成一个唯一标识符或相关 ID。生成的唯一 ID 会传递给其他调用的微服务。这样，我们可以使用来自响应的唯一生成的 ID 来获取指定于任何服务请求的日志。为此，我们有一个所谓的相关标识符或唯一生成的 UUID，将其传递给事务经过的所有服务。要生成唯一 ID，NPM 有模块 UUID（[`www.npmjs.com/package/uuid`](https://www.npmjs.com/package/uuid)）。

# 日志级别和日志机制

根据应用程序的不同方面，我们的代码需要不同的日志级别，以及足够的日志语句。我们将使用`winston`（[`www.npmjs.com/package/winston`](https://www.npmjs.com/package/winston)），它将能够动态更改日志级别。此外，我们将使用异步日志附加器，以便我们的线程不会被日志请求阻塞。我们将利用**异步钩子**（[`nodejs.org/api/async_hooks.html`](https://nodejs.org/api/async_hooks.html)），它将帮助我们跟踪我们的进程中资源的生命周期。异步钩子使我们能够通过向任何生命周期事件注册回调来监听任何生命周期事件。在资源初始化时，我们会得到一个唯一的标识符 ID（`asyncId`）和创建资源的父标识符 ID（`triggerAsyncId`）。

# 可搜索的日志

在一个地方收集的日志文件应该是可搜索的。例如，如果我们得到任何 UUID，我们的日志解决方案应该能够根据它来查找请求流程。现在，让我们看看我们将要实现的定制日志解决方案，并了解它将如何解决我们的日志问题：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/27d70bfb-2e91-4ce1-bd1e-6f0a9b09e733.png)

日志定制流

图表解释了核心组件及其定义的目的。在进入实施部分之前，让我们先看看所有组件及其目的：

+   日志仪表板：它是我们定制的中央日志解决方案的 UI 前端。我们将在 Elasticsearch 数据存储之上使用 Kibana（[`www.elastic.co/products/kibana`](https://www.elastic.co/products/kibana)），因为它提供了许多开箱即用的功能。我们将能够使用已记录的任何参数搜索索引日志。

+   日志存储：为了实现实时日志记录和存储大量日志，我们将使用 Elasticsearch 作为我们定制日志解决方案的数据存储。Elasticsearch 允许任何客户端根据基于文本的索引查询任何参数。另一个著名的选项是使用 Hadoop 的`MapReduce`程序进行离线日志处理。

+   日志流处理器：日志流处理器分析实时日志事件，用于快速决策。例如，如果任何服务持续抛出 404 错误，流处理器在这种情况下非常有用，因为它们能够对特定的事件流做出反应。在我们的情况下，流处理器从我们的队列获取数据，并在发送到 Elasticsearch 之前即时处理数据。

+   日志发货人：日志发货人通常收集来自不同端点和来源的日志消息。日志发货人将这些消息发送到另一组端点，或将它们写入数据存储，或将它们推送到流处理端点进行进一步的实时处理。我们将使用 RabbitMQ 和 ActiveMQ 等工具来处理日志流。现在我们已经看到了我们定制实现的架构，在下一节中我们将看到如何在我们当前的应用程序中实现它。所以，让我们开始吧。

# 集中式定制日志解决方案实施

在本节中，我们将看到定制日志架构的实际实施，这是我们在上一节中看到的。所以，让我们开始我们的旅程。作为一组先决条件，我们需要安装以下软件：

+   Elasticsearch 6.2.4

+   Logstash 6.2.4

+   Kibana 6.2.4

+   Java 8

+   RabbitMQ 3.7.3

# 设置我们的环境

我们在上一节讨论了相当多的软件。我们需要确保每个软件都已正确安装并在各自的端口上正常运行。此外，我们需要确保 Kibana 知道我们的 Elasticsearch 主机，Logstash 知道我们的 Kibana 和 Elasticsearch 主机。让我们开始吧：

1.  从[`www.elastic.co/downloads/elasticsearch`](https://www.elastic.co/downloads/elasticsearch)下载 Elasticsearch 并将其提取到所选位置。提取后，通过`eitherelasticsearch.bat`或`./bin/elasticsearch`启动服务器。访问`http://localhost:9200/`，您应该能够看到 JSON 标语：You Know, for Search，以及 Elasticsearch 版本。

1.  接下来是 Kibana。从[`www.elastic.co/downloads/kibana`](https://www.elastic.co/downloads/kibana)下载 Kibana 并将其提取到所选位置。然后打开`<kibana_home>/config/kibana.yml`并添加一行`elasticsearch.url: "http://localhost:9200"`。这告诉 Kibana 关于 Elasticsearch。然后从`bin`文件夹启动 Kibana 并导航到`http://localhost:5601`。您应该能够看到 Kibana 仪表板。

1.  从[`www.elastic.co/downloads/logstash`](https://www.elastic.co/downloads/logstash)下载 Logstash。将其提取到所选位置。我们将通过编写一个简单的脚本来检查 Logstash 的安装。创建一个文件`logstash-simple.conf`，并编写以下代码。您可以在`第九章/logstash-simple.conf`中找到此片段：

```ts
input { stdin { } }
output { elasticsearch { hosts => ["localhost:9200"] }
stdout { codec => rubydebug }}
```

现在运行`logstash -f logstash-simple.conf`。

您应该能够看到 Elasticsearch 信息的打印输出。这确保了我们的 Logstash 安装正常运行。

1.  接下来，我们需要安装 RabbitMQ。RabbitMQ 是用 Erlang 编写的，需要安装 Erlang。安装 Erlang 并确保环境变量`ERLANG_HOME`已设置。然后安装 RabbitMQ。安装完成后，按以下步骤启动`rabbitmq`服务：

```ts
rabbitmq-service.bat stop
rabbitmq-service.bat install
rabbitmq-service.bat start
```

1.  现在访问`http://localhost:15672`。您应该能够使用默认的 guest/guest 凭据登录，并且能够看到 RabbitMQ 仪表板。

如果您无法看到服务器，则可能需要启用插件，如下所示：

`rabbitmq-plugins.bat enable rabbitmq_management rabbitmq_web_mqtt rabbitmq_amqp1_0`

我们已成功安装了 RabbitMQ、Logstash、Elasticsearch 和 Kibana。现在我们可以继续我们的实施。

请检查提取的源代码`/customlogging`，以查看我们解决方案的运行情况。该解决方案利用了我们之前解释的架构。

# Node.js 中的分布式跟踪

分布式跟踪就像跟踪跨越涉及提供该请求的所有服务的特定服务请求一样。这些服务构建了一个图形，就像它们形成了一个以启动初始请求的客户端为根的树。Zipkin 提供了一个仪表层，用于为服务请求生成 ID，基于这个 ID，我们可以通过使用该 ID 跟踪所有应用程序的数据。在本节中，我们将看看如何使用 Zipkin。您可以在`第九章/Zipkin`中找到完整的源代码：

1.  从第四章 *开始您的微服务之旅*中启动我们的第一个微服务或任何单个微服务项目。我们将向其添加`zipkin`依赖项：

```ts
npm install zipkin zipkin-context-cls zipkin-instrumentation-express zipkin-instrumentation-fetch zipkin-transport-http node-fetch --save
npm install @types/zipkin-context-cls --save-dev
```

1.  现在我们需要一个 Zipkin 服务器。我们将配置它以使用 Zipkin 服务器以及其默认设置，并只安装其 jar。从[https:](https://search.maven.org/remote_content?g=io.zipkin.java&a=zipkin-server&v=LATEST&c=exec)[//search.maven.org/remote_content?g=io.zipkin.java&a=zipkin-server&v=LATEST&c=exec](https://search.maven.org/remote_content?g=io.zipkin.java&a=zipkin-server&v=LATEST&c=exec)下载`jar`，或者您可以在`第九章/zipkin`的`server`文件夹下找到它。下载完成后，按以下步骤打开 Zipkin 服务器：

```ts
java -jar zipkin-server-2.7.1-exec.jar
```

以下屏幕截图显示了一个 Zipkin 服务器：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/a3867b62-7ad7-4c7f-89a0-566dfee3c2d1.png)

记录 Zipkin

如屏幕截图所示，Zipkin 服务器有很多选项，包括提供用于接收跟踪信息的收集器、存储和 UI 选项以检查它。

1.  现在，我们将配置多个 Express 服务器，以观察 Zipkin 如何仪器化整个过程。我们将首先在单个微服务上设置 Zipkin，然后稍后在多个微服务上设置。我们在上一章的代码中将任何产品信息添加到我们的 MongoDB 数据库中。我们将在这里配置 Zipkin。我们需要告诉 Zipkin 要发送跟踪数据的位置（这是显而易见的！这将是运行在`9411`上的我们的 Zipkin 服务器）以及如何发送跟踪数据（这是个问题——Zipkin 有三种支持选项 HTTP、Kafka 和 Fluentd。我们将使用 HTTP）。因此，基本上我们向 Zipkin 服务器发送一个 POST 请求。

1.  我们需要一些导入来配置我们的 Zipkin 服务器。打开`Express.ts`并添加以下代码行：

```ts
import {Tracer} from 'zipkin';
import {BatchRecorder} from 'zipkin';
import {HttpLogger} from 'zipkin-transport-http';
const CLSContext = require('zipkin-context-cls');
```

+   `Tracer`用于提供诸如何在哪里以及如何发送跟踪数据的信息。它处理生成`traceIds`并告诉传输层何时记录什么。

+   `BatchRecorder`格式化跟踪数据以发送到 Zipkin 收集器。

+   `HTTPLogger`是我们的 HTTP 传输层。它知道如何通过 HTTP 发布 Zipkin 数据。

+   `CLSContext`对象是指 Continuation Local Storage。Continuation passing 是指函数调用链中的下一个函数使用它需要的数据的模式。其中一个例子是 Node.js 自定义中间件层。

1.  我们现在正在将所有部分放在一起。添加以下代码行：

```ts
const ctxImpl=new CLSContext();
const logRecorder=new BatchRecorder({
logger:new HttpLogger({
endpoint:`http://loclhost:9411/api/v1/spans` }) })
const tracer=new Tracer({ctxImpl:ctxImpl,recorder:logRecorder})
```

这将设置 Zipkin 基本要素以及将生成 64 位跟踪 ID 的跟踪器。现在我们需要为我们的 Express 服务器进行仪器化。

1.  现在，我们将告诉我们的`express`应用程序在其中间件层中使用`ZipkinMiddleware`：

```ts
import {expressMiddleware as zipkinMiddleware} from 'zipkin-instrumentation-express';
...
this.app.use(zipkinMiddleware({tracer,serviceName:'products-service'}))
```

在我们的情况下，服务的名称`'products-service'`实际上将出现在跟踪数据中。

1.  让我们调用我们的服务，看看实际结果是什么。运行程序，向`products/add-update-product`发出 POST 请求，并打开 Zipkin。您将能够在服务名称下拉菜单中看到`products-service`（我们在 Zipkin 服务器下注册的服务名称）。当您进行搜索查询时，您将能够看到类似以下内容的东西：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/2ed10c2e-8c07-4924-a91c-628676ef15f7.jpg)

Zipkin 服务日志

这就是当我们处理一个微服务时的情况。您在这里也会得到有关成功和失败服务调用的跟踪，就像图中所示的那样。我们希望能够理解涉及多个微服务的服务。

对于直接运行代码的人，请确保在`ProductsController.tslet`文件中注释掉以下行—`userRes= await this.zipkinFetch('http://localhost:3000/users/user-by-id/parthghiya');`和`console.log("user-res",userRes.text());`。

1.  假设在我们的情况下，我们还涉及另一个微服务，基于我们的业务能力，它与所有者的真实性有关。因此，每当添加产品时，我们希望检查所有者是否是实际用户。

我们将只创建两个带有虚拟逻辑的项目。

1.  创建另一个带有用户的微服务项目，并使用`@Get('/user-by-id/:userId')`创建一个 GET 请求，该请求基本上返回用户是否存在。我们将从现有项目中调用该微服务。您可以从`chapter-9/user`中跟随。

1.  在现有项目中，我们将 Zipkin 的配置移出到外部文件中，以便在整个项目中重复使用。查看`ZipkinConfig.ts`的源代码

1.  在`ProductController.ts`中，实例化一个新的 Zipkin 仪器化 fetch 对象，如下所示：

```ts
import * as wrapFetch from 'zipkin-instrumentation-fetch';
this.zipkinFetch = wrapFetch(fetch, {
tracer,
serviceName: 'products-service'
});
```

1.  进行 fetch 请求，如下所示：

```ts
let userRes= await this.zipkinFetch('http://localhost:3000/users/user-by-id/parthghiya');
```

1.  打开 Zipkin 仪表板，您将能够看到以下内容：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/1239f4ec-7071-47d5-ac1d-386301963cff.png)

Zipkin 组合

点击请求即可查看整体报告：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/e0bf0c1c-5dbf-42aa-8d50-37c406a5bb96.png)

跟踪报告

追踪是一个无价的工具，它可以通过跟踪整个微服务生态系统中的任何请求来帮助诊断问题。在下一节中，我们将了解监控微服务。

# 监控

微服务是真正分布式系统，具有庞大的技术和部署拓扑。如果没有适当的监控，运营团队可能很快就会遇到管理大规模微服务系统的麻烦。为了给我们的问题增加复杂性，微服务根据负载动态改变其拓扑。这需要一个适当的监控服务。在本节中，我们将了解监控的需求，并查看一些监控工具。

# 监控 101

让我们从讨论监控 101 开始。一般来说，监控可以被定义为一些指标、预定义的**服务水平协议**（SLAs）、聚合以及它们的验证和遵守预设的基线值的集合。每当服务水平出现违规时，监控工具必须生成警示并发送给管理员。在本节中，我们将查看监控，以了解系统的用户体验方面的行为，监控的挑战，以及了解 Node.js 监控所涉及的所有方面。

# 监控挑战

与记录问题类似，监控微服务生态系统的关键挑战在于有太多的动态部分。由于完全动态，监控微服务的主要挑战如下：

+   统计数据和指标分布在许多服务、多个实例和多台机器或容器上。

+   多语言环境增加了更多的困难。单一的监控工具无法满足所有所需的监控选项。

+   微服务部署拓扑在很大程度上不同。诸如可伸缩性、自动配置、断路器等多个参数会根据需求基础改变架构。这使得不可能监控预配置的服务器、实例或任何其他监控参数。

在接下来的部分，我们将看一下监控的下一个部分，即警示。由于错误，我们不能每次都发出警示。我们需要一些明确的规则。

# 何时警示何时不警示？

没有人会因为某些事情阻止客户使用系统并增加资金而在凌晨 3 点被吵醒而感到兴奋。警示的一般规则可以是，如果某事没有阻止客户使用您的系统并增加您的资金，那么这种情况不值得在凌晨 3 点被吵醒。在本节中，我们将查看一些实例，并决定何时警示何时不警示：

+   **服务宕机**：如果是单体化，这肯定会是一个巨大的打击，但作为一个优秀的微服务编码人员，您已经设置了多个实例和集群。这只会影响一个用户，该用户会在服务请求后再次获得功能，并防止故障级联。但是，如果许多服务宕机，那么这绝对值得警示。

+   内存泄漏：内存泄漏是另一件令人痛苦的事情，只有经过仔细监控，我们才能真正找到泄漏。良好的微服务实践建议设置环境，使其能够在实例超过一定内存阈值后停用该实例。问题将在系统重新启动时自行解决。但是，如果进程迅速耗尽内存，那么这是值得警示的事情。

+   **服务变慢**：一个慢的可用服务不值得警示，除非它占用了大量资源。良好的微服务实践建议使用基于事件和基于队列的异步架构。

+   **400 和 500 的增加**：如果 400 和 500 的数量呈指数增长，那么值得警示。4xx 代码通常表示错误的服务或配置错误的核心工具。这绝对值得警示。

在下一节中，我们将看到 Node.js 社区中可用的监控工具的实际实现。我们将在 Keymetrics 和 Grafana 中看到这些工具的实际示例。

# 监控工具

在这一节中，我们将看一些可用的监控工具，以及这些工具如何帮助我们解决不同的监控挑战。在监控微服务时，我们主要关注硬件资源和应用程序指标：

| **硬件资源** |
| --- |
| 内存利用率指标 | 应用程序消耗的内存量，比如 RAM 利用率、硬盘占用等等。 |
| CPU 利用率指标 | 在给定时间内使用了多少百分比的总可用 CPU 内存。 |
| 磁盘利用率指标 | 硬盘中的 I/O 内存，比如交换空间、可用空间、已用空间等等。 |
| **应用程序指标** |
| 每单位时间抛出的错误 | 应用程序抛出的关键错误的数量。 |
| 每单位时间的调用次数/服务占用率 | 这个指标基本上告诉我们服务的流量情况。 |
| 响应时间 | 用于响应服务请求所使用的时间。 |
| 服务重启次数 | Node.JS 是单线程的，这个事情应该被监控。 |

LINUX 的强大使得查询硬件指标变得容易。Linux 的`/proc`文件夹中包含了所有必要的信息。基本上，它为系统中运行的每个进程都有一个目录，包括内核进程。那里的每个目录都包含其他有用的元数据。

当涉及到应用程序指标时，很难使用一些内置工具。一些广泛使用的监控工具如下：

+   AppDynamics、Dynatrace 和 New Relic 是应用程序性能监控领域的领导者。但这些都是商业领域的。

+   云供应商都有自己的监控工具，比如 AWS 使用 Amazon Cloudwatch，Google Cloud 平台使用 Cloud monitoring。

+   Loggly、ELK、Splunk 和 Trace 是开源领域中的热门候选者。

现在我们将看一些 Node.js 社区中可用的工具。

# PM2 和 keymetrics

我们已经看到了 PM2 的强大之处，以及它如何帮助我们解决各种问题，比如集群、使 Node.js 进程永远运行、零停机时间等等。PM2 也有一个监控工具，可以维护多个应用程序指标。PM2 引入了 keymetrics 作为一个完整的工具，具有内置功能，如仪表板、优化过程、来自 keymetrics 的代码操作、异常报告、负载均衡器、事务跟踪、CPU 和内存监控等等。它是一个基于 SAAS 的产品，有免费套餐选项。在这一节中，我们将使用免费套餐。所以，让我们开始吧：

1.  我们需要做的第一件事是注册免费套餐。创建一个账户，一旦你登录，你就能看到主屏幕。注册后，我们将来到一个屏幕，在那里我们配置我们的 bucket。

一个 bucket 是一个容器，上面连接了多个服务器和多个应用程序。一个 bucket 是 keymetrics 定义上下文的东西。例如，我们的购物车微服务有不同的服务（支付、产品目录、库存等等）托管在某个地方，我们可以监控一个 bucket 中的所有服务器，这样一切都很容易访问。

1.  一旦我们创建了我们的 bucket，我们将会得到一个像下面这样的屏幕。这个屏幕上有所有启动 keymetrics 所需的信息和必要的文档：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/17044d3e-ccc1-4e78-8aaa-57bfc3f7a291.png)

创建 bucket 后的 Keymetrics

我们可以看到连接 PM2 到 keymetrics 和 Docker 与 keymetrics 的命令，我们将在接下来使用：

```ts
pm2 link <your_private_key> <your_public_key>
docker run -p 80:80 -v my_app:/app keymetrics/pm2 -e "KEYMETRICS_PUBLIC=<your_public_key>" -e "KEYMETRICS_SECRET=<your_secret_key>" 
```

作为安装的一部分，你将需要 PM2 监视器。一旦安装了 PM2，运行以下命令：

```ts
pm2 install pm2-server-monit
```

1.  下一步是配置 PM2 将数据推送到 keymetrics。现在，为了启用服务器和 keymetrics 之间的通信，需要打开以下端口：需要打开端口 80（TCP 输出）和 43554（TCP 输入/输出）。PM2 将数据推送到 keymetrics 的端口`80`，而 keymetrics 将数据推送回端口`43554`。现在，我们将在我们的产品目录微服务中配置 keymetrics。

1.  确保在您的系统中安装了 PM2。如果没有，请执行以下命令将其安装为全局模块：

```ts
npm install pm2 -g
```

1.  然后通过执行以下命令将您的 PM2 与 keymetrics 连接起来：

```ts
pm2 link 7mv6isclla7z2d0 0rb928829xawx4r
```

1.  一旦打开，只需更改您的`package.json`脚本，以使用 PM2 而不是简单的 node 进程启动。只需在`package.json`中添加以下脚本：

```ts
"start": "npm run clean && npm run build && pm2 start ./dist/index.js",
```

一旦作为 PM2 进程启动，您应该能够看到进程已启动和仪表板 URL：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/16c6686c-a4cc-4f88-8831-80634dd158b2.png)

使用 keymetrics 启动 PM2

1.  转到 keymetrics，您将能够看到实时仪表板：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/2d29e270-86ae-40e8-b8f5-96b057ae3220.png)

Keymetrics 仪表板

1.  它为我们提供了有趣的指标，比如 CPU 使用率、可用内存、HTTP 平均响应时间、可用磁盘内存、错误、进程等等。在接下来的部分，我们将看看如何利用 keymetrics 来解决我们的监控挑战。

# Keymetrics 监控应用程序异常和运行时问题

尽管 PM2 在保持服务器运行良好方面做得很好，但我们需要监视所有发生的未知异常或潜在的内存泄漏源。PMX 正好提供了这个模块。您可以在`第九章/pmx-utilities`中查看示例。像往常一样初始化`pmx`。只要有错误发生，就用`notify`方法通知`pmx`：

```ts
pmx.notify(new Error("Unexpected Exception"));
```

这足以向 keymetrics 发送错误，以便提供有关应用程序异常的信息。您也将收到电子邮件通知。

PMX 还监视服务的持续使用，以便检测内存泄漏。例如，检查路由`/memory-leak`。

以下显示了几个重要的 keymetrics 亮点：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/7f15decc-9a17-423a-82a0-b207195786fb.png)

Pmx 实用程序

# 添加自定义指标

最后，我们将看到如何根据我们的业务能力和需求添加自定义指标。大多数情况下，我们经常需要一些定制，或者我们无法使用现成的功能。Keymetrics 为我们提供了用于此目的的探针。在 keymetrics 中，探针是以编程方式发送到 keymetrics 的自定义指标。我们将看到四种探针及其示例：

+   **简单指标**：可以立即读取的值，用于监视任何变量值。这是一个非常基本的指标，开发人员可以为推送到 keymetrics 的数据设置一个值。

+   **计数器**：递增或递减的事物，比如正在处理的下载、已连接的用户、服务请求被命中的次数、数据库宕机等。

+   **计量器**：被视为事件/间隔进行测量的事物，比如 HTTP 服务器每分钟的请求次数等。

+   **直方图**：它保留了一个与统计相关的储备，特别偏向于最后五分钟，以探索它们的分布，比如监控最近五分钟内查询执行的平均时间等。

我们将使用`pmx`（[`www.npmjs.com/package/pmx`](https://www.npmjs.com/package/pmx)）来查看自定义指标的示例。PMX 是 PM2 运行器的主要模块之一，允许公开与应用程序相关的指标。它可以揭示有用的模式，有助于根据需求扩展服务或有效利用资源。

# 简单指标

设置 PM2 指标值只是初始化一个探针并在其中设置一个值的问题。我们可以通过以下步骤创建一个简单的指标。您可以在`第九章/简单指标`中查看源代码：

1.  从第二章复制我们的`first microservice`骨架，*为旅程做准备*。我们将在这里添加我们的更改。安装`pm2`和`pmx`模块作为依赖项：

```ts
npm install pm2 pmx -save
```

1.  在`HelloWorld.ts`中，使用以下代码初始化`pmx`。我们将添加一个简单的度量名称`'Simple Custom metric'`以及变量初始化：

```ts
constructor(){
this.pmxVar=pmx.init({http:true,errors:true, custom_probes:true,network:true,ports:true});
this.probe=this.pmxVar.probe();
this.metric=this.probe.metric({ name:'Simple custom metric' });}
```

我们用一些选项初始化了 pmx，比如以下内容：

+   `http`：HTTP 路由应该被记录，并且 PM2 将被启用来执行与 HTTP 相关的度量监视

+   `errors`：异常日志记录

+   `custom_probes`：JS 循环延迟和 HTTP 请求应该自动公开为自定义度量

+   `端口`：它应该显示我们的应用正在监听的端口

1.  现在你可以在任何地方使用以下方法初始化这个值：

```ts
this.metric.set(new Date().toISOString());
```

现在你可以在 keymetrics 仪表板中看到它，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/95b1e043-fcf4-45dc-86b8-03d680d2a9a6.png)

简单度量

# 计数器度量

这个度量是非常有用的，可以看到事件发生的次数。在这个练习中，我们将看到我们的`/hello-world`被调用的次数。你可以在`Chapter 9/counter-metric`中的示例中跟着做：

1.  像往常一样初始化项目。添加`pmx`依赖项。创建一个带有路由控制器选项的`CustomMiddleware`：

```ts
import { ExpressMiddlewareInterface } from "routing-controllers";
 const 
 pmx=require('pmx').init({http:true,errors:true, custom_probes:true,network:true,ports:true}); 

const pmxProbe=pmx.probe();
 const pmxCounter=pmxProbe.counter({
    name:'request counter for Hello World Controller',
    agg_type:'sum'}) 

export class CounterMiddleWare implements ExpressMiddlewareInterface {
    use(request: any, response: any, next: (err?: any) => any ):any {
        console.log("custom middle ware");
        pmxCounter.inc();
      next();   }} 
```

1.  在`HelloWorld.ts`之前添加注释并运行应用程序：

```ts
@UseBefore(CounterMiddleWare)
@Controller('/hello-world')
export class HelloWorld { ... }
```

你应该能够看到类似以下的东西：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/b8088b76-83df-4685-9c86-b67ea87f2502.png)

计数器度量

# 计量

这个度量允许我们记录事件实际发生的时间以及每个时间单位内事件发生的次数。计算平均值非常有用，因为它基本上给了我们一个关于系统负载的想法。在这个练习中，我们将看一下如何利用计量度量：

1.  像往常一样初始化项目。安装`pmx`和`pm2`依赖项。它包括以下关键字：

+   **样本：**此参数对应于我们想要测量指标的间隔。在我们的案例中，这是每分钟的呼叫次数，因此是`60`。

+   **时间范围：**这是我们想要保存 keymetrics 数据的时间长度，它将被分析的总时间范围。

在构造函数中添加以下代码以初始化计量器度量依赖项：

```ts
this.pmxVar=pmx.init({http:true,errors:true,custom_probes:true,network:true,ports:true});
  this.probe=this.pmxVar.probe();
 this.metric=this.probe.meter({
 name: 'averge per minute',
 samples:60,
 timeframe:3600 }) 
```

1.  在路由中，`@Get('/')`将初始化这个标记。这将给我们一个路由`<server_url>/hello-world`每分钟平均呼叫次数。

1.  现在运行这个度量。你将能够在 keymetrics 仪表板中看到这个值。同样，你可以使用直方图度量。

在下一节中，我们将看一下更高级的可用工具。

# Prometheus 和 Grafana

Prometheus 是一个著名的开源工具，它为 Node.js 监控提供了强大的数据压缩选项以及快速的时间序列数据查询。Prometheus 具有内置的可视化方法，但它的可配置性不足以在仪表板中利用。这就是 Grafana 的作用。在本节中，我们将看一下如何使用 Prometheus 和 Grafana 监控 Node.js 微服务。所以让我们开始动手编码吧。你可以在源代码中的`Chapter 9/prometheus-grafana`中的示例中跟着做：

1.  像往常一样，从`chapter-2/first microservice`初始化一个新项目。添加以下依赖项：

```ts
npm install prom-client response-time --save
```

这些依赖项将确保我们能够监控 Node.js 引擎，并能够从服务中收集响应时间。

1.  接下来，我们将编写一些中间件，用于跨微服务阶段使用，比如在 Express 中注入，并在后期使用中间件。创建一个`MetricModule.ts`文件，并添加以下代码：

```ts
import * as promClient from 'prom-client';
 import * as responseTime from 'response-time';
 import { logger } from '../../common/logging'; 

export const Register=promClient.register;
 const Counter=promClient.Counter;
 const Histogram=promClient.Histogram;
 const summary=promClient.Summary; 
```

1.  接下来我们将创建一些自定义函数用作中间件。在这里，我们将创建一个函数；你可以在`Chapter 9/prometheus-grafana/config/metrics-module/MetricModule.ts`中查看其他函数：

```ts
//Function 1
 export var numOfRequests=new Counter({
    name:'numOfRequests',
    help:'Number of requests which are made through out the service',
    labelNames:['method']
 }) 
/*Function 2  to start metric collection */
 export var startCollection=function(){
    logger.info(" Metrics can be checked out at /metrics");
    this.promInterval=promClient.collectDefaultMetrics(); } 

/*THis function 3 increments the counters executed */
 export var requestCounters=function(req:any,res:any,next:any){
    if(req.path!='metrics'){
        numOfRequests.inc({method:req.method});
        totalPathsTakesn.inc({path:req.path});
   }   next();} 
//Function 4: start collecting metrics 
export var startCollection=function(){
  logger.info(" Metrics can be checked out at /metrics");
    this.promInterval=promClient.collectDefaultMetrics();} 
```

看一下前面代码中提到的以下函数：

+   第一个函数启动一个新的计数器变量

+   第二个功能启动 Prometheus 指标

+   第三个功能是一个中间件，用于增加请求的数量

+   除了指标路由之外的功能计数器

1.  接下来，我们添加指标路由：

```ts
@Controller('/metrics')
 export class MetricsRoute{
    @Get('/')
    async getMetrics(@Req() req:any,@Res() res:any):Promise<any> {
        res.set('Content-Type', Register.contentType);
        res.end(Register.metrics());   };} 
```

1.  接下来，我们在`express`应用程序中注入中间件。在`express.ts`中，只需添加以下 LOC：

```ts
..
this.app.use(requestCounters);
this.app.use(responseCounters)
..
startCollection()
```

1.  Node.js 设置完成。现在是启动 Prometheus 的时候了。创建一个名为`prometheus-data`的文件夹，在其中创建一个`yml 配置`文件：

```ts
Scrape_configs:
 - job_name: 'prometheus-demo'
   scrape_interval: 5s
   Static_configs:
     - targets: ['10.0.2.15:4200']
       Labels:
         service: 'demo-microservice'
         group: 'production'
```

1.  通过运行以下命令来启动 Docker 进程：

```ts
sudo docker run -p 9090:9090 -v /home/parth/Desktop/prometheus-grafana/prometheus-data/prometheus.yml prom/prometheus
```

1.  您的 Prometheus 应该已经启动并运行，并且您应该看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/1ed18efc-4bcd-4457-8476-90bb1f3002de.png)

Prom 仪表板

1.  在应用程序上执行一些操作，或者使用一些压力测试工具，如 JMeter 或[`www.npmjs.com/package/loadtest`](https://www.npmjs.com/package/loadtest)。然后打开 Prometheus，在查询 shell 中写入`sum(numOfRequests)`。您将能够看到实时图形和结果。这些结果与我们访问`<server_url>/metrics`时看到的结果相同。尝试使用以下查询来查看 Node.js 内存使用情况`avg(nodejs_external_memory_bytes / 1024 / 1024) by (service)`。

1.  Prometheus 很棒，但不能用作仪表板。因此，我们使用 Grafana，它具有出色的可插拔可视化平台功能。它具有内置的 Prometheus 数据源支持。输入以下命令以打开 Grafana 的 Docker 镜像：

```ts
docker run -i -p 3000:3000 grafana/grafana
```

一旦启动，转到`localhost:3000`，并在用户名/密码中添加`admin/admin`以登录。

1.  登录后，添加一个类型为 Prometheus 的数据源（打开“添加数据源”屏幕），并在 HTTP URL（您的 Prometheus 运行 URL）中输入 IP 地址：`9090`，在“访问”文本框中输入“服务器（默认）”（您访问 Prometheus 的方式），以配置 Prometheus 作为数据源。单击保存并测试以确认设置是否有效。您可以查看以下屏幕截图以更好地理解：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/c0b1f294-7cad-4351-a6f3-0873375f7fda.png)

Grafana

1.  一旦配置了数据源，您可以通过 GUI 工具自定义图形或其他内容，并设计自己的自定义仪表板。它将如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ts-msvc/img/907fdaa8-2b11-4945-abfd-ec8e210eb8cc.png)

Grafana

Prometheus 不仅是监控单个 Node.js 应用程序的强大工具，还可以在多语言环境中使用。使用 Grafana，您可以创建最适合您需求的仪表板。

这些是在 Node.js 监控部署中使用的重要工具。还有其他工具，但整合它们需要多语言环境。例如，[Simian Army](https://github.com/Netflix/SimianArmy/wiki/Chaos-Monkey)。它被 Netflix 广泛使用和推广，用于处理各种云计算挑战。它构建了各种类猴工具来维护网络健康，处理流量，并定位安全问题。

# 可投入生产的微服务标准

我们将快速总结一个可投入生产的微服务及其标准：

+   一个可投入生产的微服务对服务请求是可靠和稳定的：

+   它遵循符合 12 因素应用标准的标准开发周期（回顾第一章，*揭秘微服务*）

+   它的代码经过严格的测试，包括 linter、单元测试用例、集成、合同和端到端测试用例

+   它使用 CI/CD 流水线和增量构建策略

+   在服务失败的情况下，有备份、替代、回退和缓存

+   它具有符合标准的稳定的服务注册和发现过程

+   一个可投入生产的微服务是可扩展和高可用的：

+   它根据任何时间到来的负载自动扩展

+   它有效利用硬件资源，不会阻塞资源池

+   它的依赖随着应用程序的规模而扩展

+   它的流量可以根据需要重新路由

+   它以高性能的非阻塞和最好是异步的反应方式处理任务和进程

+   一个可以立即投入生产的微服务应该准备好应对任何未经准备的灾难：

+   它没有任何单点故障

+   它经过足够的代码测试和负载测试来测试其弹性

+   故障检测，阻止故障级联，以及故障修复都已经自动化，并且具备自动扩展能力

+   一个可以立即投入生产的微服务应该得到适当的监控：

+   它不仅在微服务级别不断监控其识别的关键指标（自定义指标，错误，内存占用等），还扩展到主机和基础设施级别

+   它有一个易于解释的仪表板，并且具有所有重要的关键指标（你打赌，PM2 是我们唯一的选择）

+   通过信号提供阈值（Prometheus 和时间序列查询）定义可操作的警报

+   一个可以立即投入生产的微服务应该有文档支持：

+   通过 Swagger 等工具生成的全面文档

+   架构经常审计和审查，以支持多语言环境

# 总结

在本章中，我们了解了部署过程。我们看到了一些上线标准，部署流水线，并最终熟悉了 Docker。我们看到了一些 Docker 命令，并熟悉了 Docker 化的世界。然后，我们看到了处理大型分布式微服务时涉及的一些日志记录和监控方面的挑战。我们探索了各种日志记录的解决方案，并实施了使用著名的 ELK 堆栈的自定义集中式日志记录解决方案。在本章的后半部分，我们看到了一些监控工具，比如 keymetrics 和 Prometheus。

下一章将探讨我们产品的最后部分：安全性和可扩展性。我们将看到如何保护我们的 Node.js 应用程序免受暴力攻击，以及我们的安全计划应该是什么。然后，我们将研究可扩展性，并通过 AWS 实现微服务的自动扩展。
