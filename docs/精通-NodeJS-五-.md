# 精通 NodeJS（五）

> 原文：[`zh.annas-archive.org/md5/54EB7E80445F684EF94B4738A0764C40`](https://zh.annas-archive.org/md5/54EB7E80445F684EF94B4738A0764C40)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：微服务

让每个人都打扫自己门前的雪，那么整个世界都会变得干净。

- 歌德

随着软件变得更加复杂，任何一个人，甚至一个团队，都无法完全了解整个架构。互联网的兴起促进了“前端”（一台计算机上运行 JavaScript、CSS、HTML 的浏览器）和“后端”（另一台计算机运行数据库和 HTTP 服务器）的概念，在单个服务器上统一交付一个产品——网页。用户可能会点击一个按钮，服务器会发出一个调用，该服务器可能会检查数据库，并最终交付一个 HTML 页面。

速度已经加快。现代用户期望功能强大且高度互动的移动应用程序能够以低成本进行娱乐或推动业务，并进行定期更新。现在，一个人可以创建一个在几个月内获得数百万用户的应用程序。从一个人到在几个月甚至几年内支持数百万并发用户的公司规模扩展，需要高效的团队和工程管理。

如今的基于网络的应用程序由几个独立的子系统组成，它们必须合作来满足更大系统的业务或其他要求。例如，许多 Web 应用程序将呈现基于浏览器的界面，由一个或多个库和/或 UI 框架组成，将用户操作转换为在手机、微控制器和笔记本电脑上运行的 JavaScript 控制器发出的正式网络请求，最终与执行用不同语言编程的业务逻辑单元的任意数量的服务器通信，这些服务器可能共享一个或多个数据库，甚至跨多个数据中心，它们本身会发起和协调更长的一系列请求到云 API 或其他服务器等等。

如今，任何复杂的软件很少仅限于一台机器或单一代码库。在本章中，我们将探讨将独立的组件组合成分布式架构的最新流行技术，每个组件都是一个小的、明确定义的、可热重载的服务，或者称为微服务。微服务允许您重连、重写、重用和重新部署应用程序的模块化部分，使变更更容易。

# 为什么要使用微服务？

将较大的系统构建成较小的专用单元并不是一个新的想法。面向对象编程遵循相同的原则。Unix 就是这样构建的。支持可组合网络软件的架构（CORBA、WebObjects、NetBeans）是几十年前的想法。新的是网络软件带来的利润规模。几乎每个业务领域的客户都需要新的软件和新的功能，软件开发人员不断根据不断变化的市场条件交付和/或完善这些功能。微服务实际上是一个管理理念，其目标是减少将业务/客户需求变化反映到代码中所需的时间。目标是降低变更成本。

构建软件没有绝对的“正确方式”，每种语言设计都偏向于一个或几个关键原则，特别是指导系统如何扩展的原则，通常会影响部署方式。Node 社区的一些关键原则——由小程序组成的模块化系统，事件驱动，I/O 聚焦，网络聚焦——与支持微服务的原则密切相关：

1.  一个系统应该被分解成许多小服务，每个服务只做一件事，而不是更多。这有助于清晰度。

1.  支持服务的代码应该简短而简单。Node 社区的一个常见指导原则是将程序限制在大约 100 行代码附近。这有助于可维护性。

1.  没有服务应该依赖于另一个服务的存在，甚至不应该知道其他服务的存在。服务是解耦的。这有助于可扩展性、清晰度和可维护性。

1.  数据模型应该是分散的，一个常见（但不是必需的）微服务模式是每个服务维护自己的数据库或类似模型。服务是无状态的。这加强了（3）。

1.  独立的服务易于复制（或删除）。在微服务架构中，扩展（双向）是一个自然的特性，因为可以根据需要添加或删除新的*节点*。这也使得轻松进行实验，可以测试原型服务，测试或临时部署新功能等。

1.  独立的无状态服务可以独立替换或升级（或降级），而不受它们所属系统的状态的影响。这打开了更加专注、离散的部署和重构的可能性。

1.  失败是不可避免的，因此系统应设计成能够优雅地失败。局部化故障点（1, 2），隔离故障（3, 4），并实施恢复机制（当错误边界明确定义、小且非关键时更容易），通过减少不可靠性的范围来促进健壮性。

1.  测试对于任何非平凡的系统都是必不可少的。明确简单的无状态服务易于测试。测试的一个关键方面是模拟——*存根*或*模拟*服务，以测试服务的互操作性。清晰界定的服务也易于模拟，因此可以智能地组合成可测试的系统。

这个想法很简单：更小的服务更容易单独思考，鼓励规范的正确性（几乎没有灰色地带）和 API 的清晰性（受限的输出集遵循受限的输入集）。作为无状态和解耦的服务，有助于系统的可组合性，有助于扩展和可维护性，使它们更容易部署。此外，这种类型的系统可以进行非常精确、离散的监控。

有了这个大致的草图，让我们回到过去，调查一些基础架构模式，比如“3 层”架构，以及它们的特点如何导致了*微服务*的概念。将这一进展带到现在，然后我们将看看现代网络应用程序的不可思议的规模如何迫使重新构想经典的客户端->服务器->数据库设置，这个新世界通常最好由微服务组成。

构建基于微服务的 Web API 时，拥有能够精确控制处理调用、标头、POST 主体、响应等的工具将非常有用，特别是在调试时。我建议安装**Postman**（[`www.getpostman.com/`](https://www.getpostman.com/)），以及浏览器的扩展程序，可以“美化”JSON 对象。对于 Chrome 来说，一个很好的选择是**JSON Formatter**（[`chrome.google.com/webstore/detail/json-formatter/bcjindcccaagfpapjjmafapmmgkkhgoa?hl=en`](https://chrome.google.com/webstore/detail/json-formatter/bcjindcccaagfpapjjmafapmmgkkhgoa?hl=en)）。

# 从 3 层到 4 层

要了解微服务如何改进您的 Node 应用程序，您必须了解它们旨在解决的问题，以及以前如何解决这些问题。重要的是要知道*微服务*导向架构可能适用的*地方*，以及*为什么*这样的变化将帮助您。让我们看看多层分布式网络架构是如何随着时间的推移发展的。

# 单体

这是一个单体：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/474961f2-296d-4989-890e-c8d86d0d938f.jpg)

它很大，是一个整体，是垂直增长的。可能很难在没有巨大的努力、巨大的危险和巨大的成本的情况下重新塑造或修改。当有人将架构描述为*单片式*时，他们使用前面的隐喻来暗示某种非常庞大、不可移动的东西，以至于使试图改进它或全面调查其全部组成部分的人望而却步。

考虑一个简单的应用，比如一个*待办*清单。清单管理器需要`创建`、`添加`、`删除`和其他改变清单的功能。该应用的代码可能类似于这样的伪代码：

```js
let orm = require('some-orm');

module.exports = {
  create: list  => orm.createList(list),
  add: (list, item) => List(list).insert(new Item(item)),
  delete: (list, item) => List(list).delete(item)
};
```

这个例子展示了单体设计思维。数据在同一台机器上，UI 控制器和进程逻辑在同一上下文中（封闭的 Node 模块），功能在同一个文件和同一个操作系统进程中。你不需要支持微服务来理解，随着用户账户、草稿和媒体附件、共享、多设备同步和其他功能被添加到你的待办应用中，最初的单一的、单体化的存储所有应用逻辑的仓库变得过于密集，需要被分解成多个部分。

如果你将这些函数中的每一个都分解成一个独立的进程，在自己的内存空间中运行，纯粹且不依赖于任何其他进程，以至于可以更新、关闭、复制、部署、测试，甚至替换而不对系统的任何其他部分产生影响，那么微服务就是从这种思维方式中产生的。

构建软件时，使用标准的面向对象编程，或者将所有函数或结构都放在一个文件或一小组文件中，期望软件在单台机器上运行是完全可以的。这种架构模型可能适用于大多数人；在现代硬件上，运行简单的 Node 服务器的单核机器可能能够处理数千个并发用户执行非平凡的、数据库驱动的任务。通过增加更多的核心或内存来扩展垂直架构来扩展不断增长的应用程序是完全可以的。通过启动几台已经垂直扩展的服务器并在它们之间平衡负载来扩展架构也是可以的。这种策略仍然被一些价值数十亿美元的公司使用。

如果构建单体架构是符合你需求的正确选择，那是可以的。在其他时候，微服务可能是正确的选择。你可能不需要使用去中心化的数据源；当服务发生变化时，你可能不需要*热重载*。广泛使用的数据库 MYSQL 通常是垂直扩展的。当限制被推动时，只需向数据库服务器添加更多的处理核心、内存和存储空间，或者创建同一数据库的多个副本并在它们之间平衡请求。这种单体架构易于理解，通常是有弹性的。

垂直扩展架构（单体架构）的优势是什么？：

+   **测试和调试**：应用程序中发生的事情始于应用程序本身，独立于随机网络效应。这在测试和调试时可能会有所帮助。

+   **强一致性**：持久的本地数据库连接可以帮助保证事务完整性，包括回滚。分布式数据库，特别是被许多客户端并发访问的数据库，要保持同步要困难得多，并且通常被描述为*最终一致*，这可能是一个问题，特别是如果你是一家银行。

+   **简单性**：一个设计良好的应用，例如一个在同一逻辑空间内与单个数据库绑定的单个 REST API，可以很容易地描述，并且是可预测的。通常，一个人可以理解整个系统，甚至可以独自运行它！这是一个非常重要的优势，特别是在员工入职速度增加和个人创业机会方面。

+   **线性扩展**：如果可能的话，通过在单台机器上加倍内存容量来加倍容量是一个非常简单的升级。在某些时候，这种解决方案可能不够用，但这一点可能比你想象的要远得多。相对容易预测增加负载的成本和扩展系统所需的步骤。

一些公司或开发者将遇到绝对需要分布式架构的规模。一些聪明的数据对象设计和通过单个数据库相关的组件化 UI，设计良好并且维护良好，可能足够长时间，甚至永远。在许多方面，流行的 Ruby on Rails 框架继续支持单体和集成系统的价值，这是其创始人 David Heinemeier Hansson 在[`rubyonrails.org/doctrine/#integrated-systems`](http://rubyonrails.org/doctrine/#integrated-systems)上强烈主张的立场。

# 从单片到三层架构

可以说，现在很少有人真正构建单片应用程序。人们现在所谓的单片通常是一个三层应用程序，具体化了以下概念层：

+   表示层：客户端请求、查看和修改信息的接口。通常与应用程序层通信。

+   应用程序层：连接表示层和数据层的逻辑

+   数据层：信息持久化和组织

一个 Node 开发者可能会认识到，应用程序由一个客户端框架（如 React）（表示层）组成，由使用 Express 构建的应用程序层提供服务，通过某种连接器与 MongoDB 数据库通信，例如 Mongoose。这些是 LAMP 堆栈，MEAN 堆栈。系统架构师很久以来就知道将应用程序分离成不同的系统是一种明智的策略。在许多方面，这种架构反映了模型视图控制（MVC）模型，其中 M=数据，V=表示，C=应用程序。

# 这种架构是如何产生的？

首先，人们认识到系统中有非常明显的应该分开理解的部分。基于浏览器的 UI 与您的数据库或 Web 服务器无关。它可能通过各种抽象层来反映您的数据库结构（例如，通过兴趣链接的个人资料显示），但这种系统特性最终是一个设计决策，而不是一个必要条件。独立于布局网格或交互组件维护和更新您的数据库是有道理的。不幸的是，这些不同的东西可能会因为懒惰的设计或快节奏的商业环境的变化而纠缠在一起，还有其他原因。

其次，当更改一个层的一部分最终需要重新测试整个系统时，快速、持续的部署和集成就会变得更加困难。集成测试必须要么涉及真实系统，要么创建人工模拟，两者都不可靠，都可能导致破坏性结果。同样，部署是整体的——即使在概念上是不同的，实际上每个部分都与其他部分紧密相连，每个部分的完整性都必须通过验证整体的完整性来验证。庞大的测试套件反映了它们试图覆盖的应用程序设计的巨大和密集。

专注于确切的三层使弹性变得困难。新的数据模型、功能、服务，甚至可能是一次性的 UI 添加（例如来自 Facebook 的完全独立的登录系统）必须在三个层之间进行链接，并且必须仔细地（有些是人为地）进行与许多或所有现有数据模型、功能、业务逻辑、UI 的集成。随着新的缓存机制（CDN）和 API 驱动的开发的出现，三层系统的人为性开始让开发人员感到沮丧。

# 面向服务的体系结构

微服务的概念在很大程度上是对围绕面向服务的体系结构（SOA）的想法的改进和重新定义，维基百科对此的定义如下：

<q>“[SOA]是一种软件设计风格，应用组件通过网络上的通信协议向其他组件提供服务。...服务是可以远程访问并独立操作和更新的离散功能单元，例如在线检索信用卡对账单。”</q>

面向服务的架构在明确定义功能时非常有意义。如果您正在运行在线商店，您可能希望将搜索功能和付款功能与注册系统和客户端 UI 服务器分开。我们可以看到这里的基本思想是创建逻辑上自包含并通过网络访问的功能——其他系统组件（包括服务）可以使用而不会相互冲突。

将类似功能分离为单独的服务是对 3 层架构的常见调整，在该架构中，服务器上的业务逻辑可能将其职责委托给第三方 API。例如，一个身份管理服务如**Auth0**可能用于管理用户帐户，而不是将其本地存储在数据库中。这意味着登录的业务逻辑作为外部服务的代理。财务交易，如销售，通常被委托给外部提供者，日志收集和存储也是如此。对于可能将其服务作为 API 提供的公司，整个 API 管理可能被委托给云服务，如 Swagger 或 Apiary。

可能是由于架构趋势向服务的方向发展，由第三方服务管理曾经在现场功能上的功能（如缓存和其他 API），一种通常称为“4 层架构”的新思想引起了系统架构师的关注。

# 4 层和微服务

现代分布式应用程序开发的最近几年已经形成了一种有利于扩展的模式共识。首先让我们考虑一下“4 层架构”通常指的是什么，然后再看微服务是如何定义这类系统设计的。

4 层架构扩展和扩展了 3 层架构：

+   **层 1：** 3 层架构中的数据层被**服务**层取代。这种思路很简单：数据以如此之大的规模、以如此多种不同的方式、通过如此多种不同的技术存储，并且在质量和类型上变化如此之快，以至于“单一真相来源”的概念，比如单一数据库，已经不再可行。数据通过抽象接口公开，其内部设计（调用 Redis 数据库和/或从 Gmail 收取收件箱和/或从政府数据库读取天气数据）是一个“黑匣子”，只需返回预期格式的数据。

+   **层 2：** 4 层架构引入了**聚合**层的概念。正如数据现在被分解为服务（1），业务逻辑也被隔离到单独的服务中。正如我们稍后将在讨论 Lambda 架构时看到的，获取数据或调用*子例程*的方式已经模糊成了一个通用的 API 驱动模型，其中具有一致接口的单独服务生成协议感知数据。这一层组装和转换数据，将聚合的源数据增加和过滤成以结构化、可预测的方式建模的数据。这一层可能被称为*后端*或应用层。这是开发人员编程数据流通道的地方，按照约定（编程）的协议。通常，我们希望在这里生成结构化数据。

+   其余层是通过将表示层分为两个部分来创建的：

+   **第三层：** **交付**层：此层意识到客户端配置文件（移动设备、桌面、物联网等），将聚合层提供的数据转换为特定于客户端的格式。缓存数据可以通过 CDN 或其他方式在此处获取。在这里可能会选择要插入*网页*的广告。此层负责优化从聚合层接收到的数据，以适应个别用户。这一层通常可以完全自动化。

+   **第四层：** **客户端**层：此层定制了交付层通常为特定客户返回的内容。这可以是为移动设备呈现数据流（可能是响应式 CSS 结构或特定设备的本机格式），也可以是个性化视图的反映（仅图像或语言翻译）。在这里，相同的数据源可以与特定的业务合作伙伴对齐，符合**SLA（服务级别协议）**或其他业务功能。

显著的变化是将呈现层分成两个部分。Node 经常出现在交付层，代表客户端查询聚合层，定制从聚合层接收到的数据响应给客户端。

总的来说，我们已经转向了一个架构，其中不再期望个别服务以任何特定方式反映调用者的需求，就像 Express 服务器中的面向浏览器的模板引擎可能会有的那样。服务无需共享相同的技术或编程语言，甚至不需要相同的操作系统版本或类型。架构师们相反宣布了一定类型的拓扑结构，具有明确定义的通信点和协议，通常分布在：1）数据源，2）数据聚合器，3）数据整形器和 4）数据显示器。

# 部署微服务

在本节中，我们将考虑微服务的几种变体，看一看开发人员如何使用 Node 进行微服务的一些常见方式。我们将从**Seneca**开始，这是一个用于 Node 的微服务框架。然后，我们将继续使用**Amazon Lambda**开发基于云的微服务。从那里，我们将尝试使用**Docker**容器模拟一个**Kubernetes**集群，探索现代容器化微服务编排。

# 使用 Seneca 的微服务

Seneca 是一个基于 Node 的微服务构建工具包，可以帮助您将代码组织成由模式触发的不同操作。Seneca 应用程序由可以接受 JSON 消息并可选返回一些 JSON 的服务组成。服务注册对具有特定特征的消息感兴趣。例如，每当广播显示`{ cmd: "doSomething" }`模式的 JSON 消息时，服务可能会运行。

首先，让我们创建一个响应三种模式的服务，其中一种模式返回“Hello!”，另外两种模式是不同的说“Goodbye!”的方式。

创建一个名为`hellogoodbye.js`的文件，其中包含以下代码：

```js
// hellogoodbye.js
const seneca = require('seneca')({ log: 'silent' });
const clientHello = seneca.client(8080);
const clientGoodbye = seneca.client(8081);

seneca
.add({
role: 'hello',
cmd:'sayHello'
}, (args, done) => done(null, {message: "Hello!"}))
.listen(8082);

seneca
.add({
role: 'goodbye',
cmd:'sayGoodbye'
}, (args, done) => done(null, {message: "Goodbye"}))
.add({
role: 'goodbye',
cmd:'reallySayGoodbye'
}, (args, done) => done(null, {message: "Goodbye!!"}))
.listen(8083);

clientHello.act({
role: 'hello',
cmd: 'sayHello'
}, (err, result) => console.log(result.message));

clientGoodbye.act({
role: 'goodbye',
cmd: 'sayGoodbye'
}, (err, result) => console.log(result.message));

clientGoodbye.act({
role: 'goodbye',
cmd: 'reallySayGoodbye'
}, (err, result) => console.log(result.message));
```

Seneca 的工作原理是服务客户端监听特定的命令模式，并根据模式匹配将其路由到正确的处理程序。我们的第一项工作是设置两个 Seneca 服务客户端，监听端口`8080`和`8081`。可以看到服务已经被组织成两个组，一个是“hello 服务”有一个方法，另一个是“goodbye 服务”有另一个方法。现在我们需要向这些服务添加操作。为此，我们需要告诉 Seneca 在进行匹配特定模式的服务调用时如何操作，这里使用特定的对象键进行定义。如何定义您的服务对象是开放的，但“cmd”和“role”模式是常见的——它可以帮助您创建逻辑组和标准的命令调用签名。我们将在接下来的示例中使用该模式。

考虑到上述代码，我们看到当收到一个 JSON 对象，其中`cmd`字段设置为`sayHello`，`role`为`hello`时，服务处理程序应该返回`{ message: "Hello!" }`。 "goodbye"角色方法同样被定义。在文件底部，您可以看到我们如何可以通过 Node 直接调用这些服务。很容易想象这些服务定义如何可以分解成几个模块导出到单独的文件中，根据需要动态导入，并以有组织的方式组合应用程序（这是微服务架构的目标）。

为了摆脱显示的日志数据，您可以使用`require('seneca')({ log: 'silent' })`来初始化您的 Seneca 实例。

由于 Seneca 服务默认监听 HTTP，您可以通过直接调用 HTTP，在`/act`路由上进行操作，从而实现相同的结果：

```js
curl -d "{\"cmd\":\"sayHello\",\"role\":\"hello\"}" http://localhost:8082/act
// {"message":"Hello!"}
```

这种自动的 HTTP 接口为我们提供了可自动发现的网络服务，这非常方便。我们已经可以感受到微服务模式：简单、独立、小的功能块，使用标准的网络数据模式进行通信。Seneca 为我们提供了免费的编程和网络接口，这是一个额外的好处。

一旦开始创建大量的服务，就会变得难以跟踪哪个服务组在哪个端口上运行。服务发现是微服务架构引入的一个困难的新问题。Seneca 通过其**mesh**插件解决了这个问题，该插件将服务发现添加到您的 Seneca 集群中。让我们创建一个简单的计算器服务来演示。我们将创建两个服务，每个服务监听不同的端口，一个执行加法，另一个执行减法，以及一个基本服务来实例化网格。最后，我们将创建一个简单的脚本，使用不需要知道其位置的服务执行加法/减法操作，通过网格。

此示例的代码位于您的代码包中的`/seneca`文件夹中。首先，您需要安装两个模块：

```js
npm i seneca-balance-client seneca-mesh
```

现在，我们创建一个基本节点，将启用网格：

```js
// base.js
require('seneca')().use('mesh', {
  base: true
});
```

一旦启动了这个节点，其他服务一旦连接到网格，就会自动被发现。

`add`服务块如下所示：

```js
// add.js
require('seneca')()
.add({
  role: 'calculator',
  cmd: 'add'
}, (args, done) => {
  let result = args.operands[0] + args.operands[1];
  done(null, {
    result : result
  })
})
.use('mesh', {
  pin: {
    role: 'calculator',
    cmd: 'add'
  }
})
.listen({
  host: 'localhost',
  port: 8080
});
```

（**subtract**服务看起来完全相同，只是更改了它使用的数学运算符，当然它的`cmd`将是“subtract”）。

使用熟悉的角色/cmd 模式，我们将`add`命令附加到`calculator`组，类似于我们在之前的示例中定义“hello”服务的方式，具有执行加法操作的处理程序。

我们还指示我们的服务`listen`在本地主机上的特定端口接收调用，就像我们通常做的那样。新的是我们使用`use`网格网络，使用`pin`属性指示此服务将响应的角色和 cmd，使其在网格中可发现。

进入您的代码包中的`/seneca`文件夹，并在单独的终端中按照以下顺序启动以下三个文件：`base.js`->`add.js`->`subtract.js`。我们的计算器的逻辑单元已经独立设置并独立运行，这是微服务的一般目标。最后一步是与它们进行交互，我们将使用以下`calculator.js`文件：

```js
// calculator.js
require('seneca')({ log: 'silent' })
.use('mesh')
.ready(function() {

  let seneca = this;

  seneca.act({
    role: 'calculator',
    cmd: 'add',
    operands: [7,3]
  }, (err, op) => console.log(`Addition result -> ${op.result}`));

  seneca.act({
    role: 'calculator',
    cmd:'subtract',
    operands: [7,3]
  }, (err, op) => console.log(`Subtraction result -> ${op.result}`));
});
```

除了在 Seneca 的`ready`处理程序中运行我们的操作（这是一个有用的做法），当然还有我们对`mesh`的`use`，`seneca.act`语句看起来与我们之前使用的“hello”操作一样，不是吗？它们是相同的，除了一个重要的细节：我们没有使用`.listen(<port>)`方法！不需要像在`hellogoodbye.js`示例中那样创建绑定到特定端口的新 Seneca 客户端，因为网格网络服务是自动发现的。我们可以简单地进行调用，而不需要知道服务存在于哪个端口。继续运行上述代码。您应该会看到以下结果：

```js
Addition result -> 10
Subtraction result -> 4
```

这样可以提供很大的灵活性。通过以这种方式构建您的计算器，每个操作都可以被隔离到自己的服务中，并且您可以根据需要添加或删除功能，而不会影响整个程序。如果某个服务出现错误，您可以修复并替换它，而不会停止整个计算器应用程序。如果某个操作需要更强大的硬件或更多内存，您可以将其转移到自己的服务器上，而不会停止计算器应用程序或更改应用程序逻辑。很容易看出，与它们都耦合到一个集中的服务管理器相比，串联数据库、身份验证、事务、映射和其他服务可以更容易地进行建模、部署、扩展、监视和维护。

# 无服务器应用程序

从这些分布式系统的设计中产生的抽象，主要建立在微服务上，暗示了一个自然的下一步。为什么传统意义上还需要服务器？服务器是设计在单体时代的大型、强大的机器。如果我们的思维是以小型、资源节约、独立于周围环境的行为者为基础，那么我们应该部署微服务到“微服务器”上吗？这种思路导致了一个革命性的想法：AWS Lambda。

# AWS Lambda

亚马逊的 AWS Lambda 技术的引入推动了我们今天所拥有的无服务器运动。亚马逊这样描述 Lambda：

"AWS Lambda 允许您在不需要预配或管理服务器的情况下运行代码...使用 Lambda，您可以为几乎任何类型的应用程序或后端服务运行代码-而无需进行任何管理。只需上传您的代码，Lambda 会处理运行和扩展您的代码所需的一切。您可以设置代码自动从其他 AWS 服务触发或直接从任何 Web 或移动应用程序调用它。"

Lambda 是一种技术，允许您创建由 JavaScript 编写的微服务组成的无限可扩展的计算云。您不再管理服务器，只管理函数（Lambda 函数）。扩展的成本是根据*使用*而不是*计数*来衡量的。调用 1 次 Lambda 服务的成本比调用每个 9 次 Lambda 服务一次要高。同样，您的服务可以处于空闲状态，从不被调用，而不会产生任何费用。

Lambda 函数是功能性虚拟机。Lambda 函数本质上是一个容器化的 Node 应用程序，可以自动构建和部署，包括底层服务和基础设施的安全更新和进一步维护。您永远不需要管理 Lambda 函数，只需编写它们执行的代码。

另一方面，您牺牲了在服务器架构上开发提供的一些灵活性。在撰写本文时，每个 Lambda 函数的限制如下：

| 资源 | 限制 |
| --- | --- |
| 内存分配范围 | 最小= 128 MB / 最大= 1536 MB（每次增加 64 MB）。如果超过最大内存使用量，函数调用将被终止。 |
| 临时磁盘容量（"/tmp"空间） | 512 MB |
| 文件描述符数量 | 1,024 |
| 进程和线程数量（总和） | 1,024 |
| 每个请求的最大执行持续时间 | 300 秒 |
| 调用请求体有效负载大小（请求响应/同步调用） | 6 MB |
| 调用请求体有效负载大小（事件/异步调用） | 128 K |

在设计应用程序时，需要牢记这些限制。通常，Lambda 函数不应依赖持久性，应做好一件事，并且快速完成。这些限制还意味着您不能在 Lambda 函数内部启动本地数据库或其他进程应用程序。

Lambda 发布时，它专门设计用于 Node；您可以通过 Node 运行时使用 JavaScript 编写 Lambda 函数。这一事实至少表明了 Node 对于现代应用程序开发的重要性。虽然现在支持其他语言，但 Lambda 仍将 Node 视为一流公民。在本节中，我们将使用 Lambda 计算云开发一个应用程序。

虽然与 Lambda 的设置过程现在比项目首次发布时要容易得多，但您仍然需要构建大量自动样板，并且需要进行大量手动工作来进行更改。因此，在 Node 生态系统中出现了许多非常高质量的 Lambda 专注的“无服务器”框架。以下是一些主要的框架：

+   Serverless: [`github.com/serverless/serverless`](https://github.com/serverless/serverless)

+   Apex: [`github.com/apex/apex`](https://github.com/apex/apex)

+   Claudia: [`github.com/claudiajs/claudia`](https://github.com/claudiajs/claudia)

在接下来的示例中，我们将使用`claudia`，它设计良好、文档完善、维护良好，并且易于使用。`claudia`的开发者是这样说的：

“……如果您想构建简单的服务并使用 AWS Lambda 运行它们，而且您希望找到一个低开销、易于入门的工具，并且只想使用 Node.js 运行时，Claudia 是一个不错的选择。如果您想要导出 SDK，需要对服务的分发、分配或发现进行精细控制，需要支持不同的运行时等等，那么请使用其他工具。”

**API 网关**是一个完全托管的 AWS 服务，“使开发人员能够轻松创建、发布、维护、监控和保护任何规模的 API”。我们现在将使用 Claudia 和 AWS API 网关来组装一个由 Lambda 驱动的微服务的可扩展 Web 服务器。

# 使用 Claudia 和 API 网关进行扩展

首先，您需要在 Amazon Web Services（AWS）[`aws.amazon.com`](https://aws.amazon.com)创建一个开发者账户。这个账户设置是免费的。此外，大多数 AWS 服务都有非常慷慨的免费使用额度，在这些限制内，您可以在学习和开发过程中使用 AWS 而不产生任何费用。使用 Lambda，每个月的前一百万个请求是免费的。

创建开发者账户后，登录到您的仪表板，然后从“服务”选项卡中选择 IAM。现在，您将添加一个用户，我们将在这些示例中使用。Claudia 需要权限与您的 AWS 账户通信。通常情况下，您不希望在应用程序中使用根账户权限，这应该被理解为您账户的“子用户”。AWS 提供了一个**身份和访问管理（IAM）**服务来帮助处理这个问题。让我们创建一个具有 IAM 完全访问权限、Lambda 完全访问权限和 API 网关管理员权限的 AWS 配置文件。

从侧边栏中，选择用户，然后点击“添加用户”：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/c928b713-abb6-44ae-8d50-80fa5265a5a4.png)

如上所示，创建一个名为`claudia`的新用户，为该用户提供编程访问权限。

完成后，点击“下一步：权限”按钮。现在，我们需要将此 IAM 账户附加到 Lambda 和 API 网关服务，并赋予它管理员权限：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/f0224d5e-a147-4472-8fdc-491c73f9d712.png)

在选择“直接附加现有策略”后，您将看到下面出现一个长长的选项清单。为`claudia`用户选择以下三个权限：AdministratorAccess、AmazonAPIGatewayAdministrator，当然还有 AWSLambdaFullAccess。

点击“审核”后，您应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/6e87983e-5f8c-4036-947a-d62012181666.png)

好的。点击“创建用户”，并复制提供的访问密钥 ID 和秘密访问密钥（稍后会用到）。现在，您已经准备好使用`claudia`部署 Lambda 函数了。

# 安装 claudia 并部署服务

要开始安装`claudia`模块，请输入以下命令：

```js
npm install claudia -g
```

现在，您应该存储刚刚为`claudia`用户创建的凭证。这里的一个好模式是在您的主目录中存储一个 AWS 配置文件（在 OSX 上，这将是`/Users/<yoursystemusername>`）。一旦进入您的主目录，创建`.aws/credentials`目录和文件，并使用您的 IAM 用户密钥：

```js
[claudia] 
aws_access_key_id = YOUR_ACCESS_KEY 
aws_secret_access_key = YOUR_ACCESS_SECRET
```

在这里，我们指示`claudia`是 AWS 配置文件名称，针对这些 IAM 凭证。当我们运行部署时，AWS 将被告知此配置文件和凭证。

现在，让我们创建一个可通过网络访问的 HTTP 端点，返回字符串“Hello from AWS!”。

创建一个新目录，并使用`npm init`初始化一个`npm`包，使用任何您喜欢的名称。要使用 AWS API Gateway，我们还需要安装`claudia`的扩展：

```js
npm install claudia-api-builder
```

接下来，将以下`app.js`文件添加到此目录：

```js
const ApiBuilder = require('claudia-api-builder');
const api = new ApiBuilder();

module.exports = api;

api.get('/hello', function () {
    return 'Hello from AWS!';
});
```

使用`claudia` `ApiBuilder`，我们将一个 Lambda 函数附加到`/hello`路由上处理 GET 请求。令人惊讶的是，我们已经完成了！要部署，请在终端中输入以下内容：

```js
AWS_PROFILE=claudia claudia create --region us-east-1 --api-module app
```

`AWS_PROFILE`环境变量引用了我们凭证文件中的`[claudia]`配置文件标识符，并且我们使用`--region`标志来建立部署区域。

如果一切顺利，您的端点将被部署，并且将返回类似以下的信息：

```js
{
  "lambda": {
    "role": "claudiaapi-executor",
    "name": "claudiaapi",
    "region": "us-east-1"
  },
  "api": {
    "id": "s8r80rsu22",
    "module": "app",
    "url": "https://s8r80rsu22.execute-api.us-east-1.amazonaws.com/latest"
  }
}
```

返回的 URL 指向我们的 API 网关。现在，我们需要添加我们 Lambda 函数的名称，该名称在我们之前定义的 GET 处理程序中设置为`'hello'`：

```js
api.get('/hello', function () ...
```

复制并粘贴返回的 URL 到浏览器中，并添加您的 Lambda 函数的名称：

```js
https://s8r80rsu22.execute-api.us-east-1.amazonaws.com/latest/hello
```

您将看到以下消息：

```js
Hello from AWS!
```

这很容易。更新函数同样容易。返回到代码并更改函数返回的字符串消息，然后运行：

```js
AWS_PROFILE=claudia claudia update
```

成功时将返回一个 JSON 对象，指示有关函数的代码大小和其他有用信息。继续在浏览器中重新加载端点，您将看到更新的消息。这些是零停机时间更新——您的服务在部署新代码时永远不会停止工作。在这里，我们满足了创建“独立的，无状态的服务可以独立地替换或升级（或降级）的关键目标，而不管它们所形成的任何系统的状态如何”。

现在，您可以通过返回 AWS 仪表板并访问 Lambda 服务来验证 Lambda 函数的存在：

![

我们可以看到列出的包名称（`claudiaapi`）和我们正在使用的 Node 运行时（在撰写本文时 AWS 上最高可用的版本）。如果单击函数，您将看到 Lambda 函数的管理页面，包括其代码以及用于管理最大执行时间和内存限制的界面。

将`app.js`中的处理程序函数更改为以下内容：

```js
api.get('/hello', function (request, context, callback) {
    return request;
});
```

您将看到三个新参数传递给`handler`，`request`，`context`和`callback`。`context`参数包含有关此调用的 Lambda 上下文的有用信息，例如调用 ID，被调用函数的名称等。有用的是，`claudia`在传递的`request`对象的`lambdaContext`键中镜像 Lambda 上下文。因此，使用`claudia`时，您只需要处理`request`参数，这简化了事情。

要了解有关 Lambda 事件上下文的更多信息，请参阅：[`docs.aws.amazon.com/lambda/latest/dg/nodejs-prog-model-context.html`](http://docs.aws.amazon.com/lambda/latest/dg/nodejs-prog-model-context.html)。

现在，使用`claudia update`更新您的 Lambda 函数，并检查 URL。您应该看到返回大量 JSON 数据，这是您可以使用的请求事件信息的总和。有关此数据对象的更多信息，请访问：[`github.com/claudiajs/claudia-api-builder/blob/master/docs/api.md#the-request-object`](https://github.com/claudiajs/claudia-api-builder/blob/master/docs/api.md#the-request-object)。

您可以在[`github.com/anaibol/awesome-serverless`](https://github.com/anaibol/awesome-serverless)找到一些有关无服务器开发信息和链接的有趣集合。

# 容器化的微服务

亚马逊 AWS 基础设施能够创建像 Lambda 这样的服务，因为他们的工程师在客户创建另一个云函数或 API 时不再提供硬件（即新的物理服务器）。相反，他们提供轻量级的虚拟机（VM）。当您注册时，没有人会将一个大的新金属箱放到机架上。软件是新的硬件。

容器的目标是提供与虚拟化服务器提供的相同的一般架构思想和优势——大规模生产虚拟化的独立机器。主要区别在于，虽然虚拟机提供自己的操作系统（通常称为**Hypervisor**），但容器需要主机操作系统提供实际的内核服务（例如文件系统、其他设备以及资源管理和调度），因为它们不需要携带自己的操作系统，而是寄生在主机操作系统上，容器非常轻便，使用更少的（主机）资源，并且能够更快地启动。在本节中，我们将介绍任何开发人员如何使用领先的容器技术 Docker 来廉价地制造和管理许多虚拟化服务器。

这是一个关于虚拟环境之间区别的很好的 StackOverflow 讨论：[`stackoverflow.com/questions/16047306/how-is-docker-different-from-a-normal-virtual-machine`](https://stackoverflow.com/questions/16047306/how-is-docker-different-from-a-normal-virtual-machine)。

Docker 网站（[`www.docker.com/`](http://www.docker.com/)）上的这张图片提供了一些关于 Docker 团队如何以及为什么他们认为他们的技术适合未来应用程序开发的信息：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/b059cb0b-cc0d-4ed2-b400-361e6bc1b0c7.png)

回顾我们对 4 层架构的讨论，我们可以看到开发人员问自己一个问题：如果我的应用程序由许多在云中独立开发、测试、部署和管理的通信服务组成，那么我们是否可以用“本地”服务做同样的事情，并为每个服务提供独立的容器，以便可以独立开发、测试、部署等？减少实施变更成本是容器化和微服务的目标。一个容器生成一个本地化的、独立的服务，具有受保护的本地内存，可以快速启动和重新启动，单独测试，并且可以静默失败，完全适合微服务架构：

+   明确定义的责任领域

+   隔离的依赖和状态

+   进程是可丢弃的

+   轻量级且易于启动和复制

+   优雅的终止，零应用程序停机时间

+   可以独立测试

+   可以独立监视

# 开始使用 Docker

Docker 生态系统有三个主要组件。文档中是这样说的：

+   Docker 容器。 Docker 容器包含应用程序运行所需的一切。每个容器都是从 Docker 镜像创建的。Docker 容器可以运行、启动、停止、移动和删除。每个容器都是一个独立和安全的应用程序平台。您可以将 Docker 容器视为 Docker 框架的运行部分。

+   Docker 镜像。 Docker 镜像是一个模板，例如，一个安装了 Apache 和您的 Web 应用程序的 Ubuntu 操作系统。 Docker 容器是从镜像启动的。Docker 提供了一种简单的方法来构建新的镜像或更新现有的镜像。您可以将 Docker 镜像视为 Docker 框架的构建部分。

+   **Docker 注册表**。Docker 注册表保存镜像。这些是公共（或私有！）存储，你可以上传或下载镜像。这些镜像可以是你自己创建的，也可以使用其他人之前创建的镜像。你可以将 Docker 注册表视为 Docker 框架的共享部分。你可以创建应用程序的镜像，以在任意数量的隔离容器中运行，并与其他人共享这些镜像。最受欢迎的是**Docker Hub**（[`hub.docker.com/`](https://hub.docker.com/)），但你也可以自己操作。

将 Node 应用程序组合成许多独立的进程的概念自然与 Docker 背后的哲学相吻合。Docker 容器是沙箱化的，无法在没有你的知识的情况下在其主机上执行指令。然而，它们可以向它们的主机操作系统公开一个端口，从而允许许多独立的虚拟容器链接到一个更大的应用程序中。

学习一下如何找到关于你的操作系统的信息，哪些端口正在使用，由哪些进程使用等是个好主意。我们之前提到过 HTOP，你应该至少熟悉一下如何收集网络统计信息——大多数操作系统都提供了`netstat`实用程序，用于发现哪些端口是打开的，谁在监听它们。例如，`netstat -an | grep -i "listen"`。

下载并安装**Docker 社区版**（[`www.docker.com/community-edition`](https://www.docker.com/community-edition)）或**Docker 工具箱**（[`docs.docker.com/toolbox/overview/`](https://docs.docker.com/toolbox/overview/)）。可以在以下网址找到两者之间的比较：[`docs.docker.com/docker-for-mac/docker-toolbox/`](https://docs.docker.com/docker-for-mac/docker-toolbox/)。如果你使用工具箱，在提示时选择 Docker Quickstart Terminal，这将在你的系统上生成一个终端并安装必要的组件。安装过程可能需要一段时间，所以不要惊慌！完成后，你应该在终端中看到类似以下的内容：

```js
docker is configured to use the default machine with IP 192.158.59.101
```

请注意 Docker 机器的名称是"default"。

为了了解镜像是如何工作的，运行`docker run hello-world`命令。你应该看到机器拉取一个镜像并将其容器化——正在发生的详细信息将被打印出来。如果现在运行`docker images`命令，你会看到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/16dc8107-f6a1-46e7-9566-86da2260fe2e.png)

这个命令将告诉你一些关于你的 Docker 安装的信息：`docker info`。

Docker 容器运行你的应用程序的镜像。当然，你可以自己创建这些镜像，但现有的镜像生态系统也存在着大量的镜像。让我们创建一个运行 Express 的 Node 服务器的自己的镜像。

首先，我们需要构建一个要运行的应用程序。创建一个文件夹来放置你的应用程序文件。在该文件夹中，创建一个`/app`文件夹；这是我们将放置服务器文件的地方。与所有 Node 应用程序一样，我们需要创建一个`package.json`文件。进入`/app`文件夹并运行`npm init`，给这个包一个名字"docker-example"。然后，用`npm i express`安装 Express。

现在，创建一个简单的 Express 服务器并将其保存到`app/index.js`中：

```js
// index.js
const express = require('express');
const port = 8087;
const app = express();
const message = `Service #${Date.now()} responding`;
app.get('/', (req, res) => {
    res.send(message);
});
app.listen(port, () => console.log(`Running on http://localhost:${port}`));
```

继续启动服务器：

```js
> node app.js
// Running on http://localhost:8087
```

现在，你可以将浏览器指向端口`8087`的主机，看到类似`Service #1513534970093 responding`的唯一消息显示。很好。创建一个唯一消息（通过`Date.now()`）是有原因的，当我们讨论服务扩展时，这将更有意义。现在，让我们使用 Docker 将这些文件构建成一个容器。

# 创建一个 Dockerfile

我们的目标是描述此应用程序在其中执行的环境，以便 Docker 可以在容器中复制该环境。此外，我们希望将我们应用程序的源文件添加到这个新的虚拟化环境中运行。换句话说，Docker 可以充当构建器，遵循您提供的关于如何构建应用程序图像的指令。

首先，您应该有一个包含应用程序文件的文件夹。这是您的源代码存储库，您的 docker 图像将在其中构建。如前所述，Dockerfile 是用于构建应用程序的指令列表。Dockerfile 描述了构建过程。您通常会在 Dockerfile 中声明容器将运行的操作系统版本，以及您可能需要完成的任何操作系统安装，例如 Node。

创建一个`Dockerfile`文件（无扩展名）：

```js
# Dockerfile
FROM node:9
LABEL maintainer="your@email.com"
ENV NODE_ENV=development
WORKDIR /app
COPY ./app .
RUN npm i
EXPOSE 8087
CMD [ "npm", "start" ]
```

您在此文件中看到各种指令，并且还有一些其他指令可用于更复杂的构建。我们将从简单开始。要深入了解 Dockerfile，可以通过完整的文档运行：[`docs.docker.com/engine/reference/builder/`](https://docs.docker.com/engine/reference/builder/)。

`FROM`指令用于设置您将构建的基本图像。我们将基于`node:9`构建，这是包含最新 Node 的图像。更复杂的图像通常包括在此处，通常围绕常见模式构建。例如，此图像实现了**MEAN（Mongo Express Angular Node）**堆栈：[`hub.docker.com/r/meanjs/mean/`](https://hub.docker.com/r/meanjs/mean/)。`FROM`应该是 Dockerfile 中的第一个指令。

您可以通过`LABEL`为图像设置（可选的）元数据。可以有多个`LABEL`声明。这对于版本管理、信用等非常有用。我们还为 Node 进程设置了一些环境变量（`ENV`），如您在`process.env`中所期望的那样。

我们为应用程序指定工作目录（`WORKDIR`），并将我们机器上的所有本地文件`COPY`到容器的文件系统中；容器是隔离的，无法访问自身以外的文件系统，因此我们需要从我们的文件系统构建其文件系统。

现在，我们建立启动指令。`RUN npm i`安装`package.json`，`EXPOSE`我们服务器运行的端口（`8087`）到外部世界（再次，容器是隔离的，没有权限的情况下无法暴露内部端口），并运行命令（`CMD`）`npm start`。您可以设置多个`RUN`和`CMD`指令，以启动应用程序所需的任何内容。

我们现在准备构建和运行容器。

# 运行容器

在包含 Dockerfile 的目录中运行以下命令：

`docker build -t mastering-docker .`（注意末尾的句点）。

Docker 现在将获取所有基本依赖项并根据您的指令构建图像：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/90224448-516e-4071-b6f7-c67b93255a3a.png)

您刚刚创建了您的第一个 Docker 图像！要查看您的图像，请使用`docker images`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/fedf510f-94b0-49f4-940e-54b251fbb325.png)

在这里，我们看到我们创建的图像`mastering-docker`，以及我们的图像基于的图像`node:9`。请注意冒号是用于创建图像的标记版本 -- 我们最终使用的是**node**图像标记为**9**。稍后再讨论版本控制。

下一步是将图像容器化并运行。使用此命令：

```js
docker run -p 8088:8087 -d mastering-docker
```

如果一切顺利，您将能够使用`docker ps`命令列出正在运行的 Docker 进程：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/0ccc76ea-dc15-4093-b26e-094bd36abb94.png)

回想一下`EXPOSE 8087`指令？我们需要将容器暴露的端口映射到本地操作系统网络接口，我们在运行命令中使用`-p 8088:8087`标记了这个映射，我们可以在上面的屏幕截图中看到`PORTS`下的映射。

`-d`标志指示 Docker 我们想要以分离模式运行容器。这可能是您想要做的，将容器在后台运行。没有这个标志，当您终止终端会话时，容器将终止。

您现在正在一个完全与本地机器隔离的容器中运行一个 Node 服务器。通过在浏览器中导航到`localhost:8088`来尝试它。能够构建完全隔离的构建，具有完全不同的操作系统、数据库、软件版本等，然后知道您可以将完全相同的容器部署到数据中心而不改变任何内容，这是非常棒的。

以下是一些更有用的命令：

+   删除一个容器：`docker rm <containerid>`

+   删除所有容器：`docker rm $(docker ps -a -q)`

+   删除一个镜像：`docker rmi <imageid>`

+   删除所有镜像：`docker rmi $(docker images -q)`

+   停止或启动一个容器：`docker stop (或 start) <containerid>`

# 使用 Kubernetes 编排容器

基于微服务的架构由独立的服务组成。我们刚刚看到容器如何用于隔离不同的服务。现在，问题是如何管理和协调这 10、20、100、1,000 个服务容器？“手动”似乎不是正确的方法。Kubernetes 自动化容器编排，帮助您处理部署、扩展和集群健康的问题。由 Google 开发，它是一种成熟的技术，用于在 Google 自己的庞大数据中心中编排数百万个容器。

我们将安装一个名为 Minikube 的应用程序，它在本地机器的 VM 中运行一个单节点 Kubernetes 集群，因此您可以在部署之前在本地测试开发 Kubernetes 集群。由于您在本地进行的集群配置与“真实”的 Kubernetes 集群镜像，一旦满意，您可以在生产环境中部署您的定义而不需要进行任何更改。

# 创建一个基本的 Kubernetes 集群

您将需要某种 VM 驱动程序来运行 Minikube，默认情况下，Minikube 使用 VirtualBox。您可以在以下网址找到安装说明：[`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads)。VirtualBox 作为免费的 hypervisor 独立存在，用于支持其他有用的开发人员工具，如 Vagrant。

现在，我们将安装 kubectl（将其视为“Kube Control”），即 Kubernetes 命令行界面。请按照以下说明操作：[`kubernetes.io/docs/tasks/tools/install-kubectl/`](https://kubernetes.io/docs/tasks/tools/install-kubectl/)。

最后，我们安装 Minikube：[`kubernetes.io/docs/tasks/tools/install-minikube/`](https://kubernetes.io/docs/tasks/tools/install-minikube/)。

使用`minikube start`启动集群（这可能需要一段时间，所以请耐心等待）。输出足够描述：您将启动一个虚拟机，获取一个 IP 地址，并构建一个 Kubernetes 集群。输出应该以类似“Kubectl is now configured to use the cluster”的内容结束。您可以随时使用`minikube status`检查其状态：

```js
minikube: Running
cluster: Running
kubectl: Correctly Configured: pointing to minikube-vm at 192.160.80.100
```

要查看 kubectl 是否配置为与 Minikube 通信，请尝试`kubectl get nodes`，这应该显示 Minkube 机器'minikube'处于'就绪'状态。

此虚拟机是通过 VirtualBox 运行的。在您的机器上打开 Virtualbox Manager。您应该会看到列出了名为"minikube"的机器。如果是这样，太好了；Kubernetes 集群正在您的机器上运行！

您可以使用 Minikube 测试不同的 Kubernetes 版本。要获取可用版本，请运行`minikube get-k8s-versions`。一旦有了版本，使用`minikube start --kubernetes-version v1.8.0`在该版本上启动 Minikube。

现在，我们将使用 Kubernetes 来部署我们之前使用 Docker 容器化的“hello world”服务器。有用的是，Minikube 管理自己的 Docker 守护程序和本地存储库。我们将使用它来构建接下来的内容。首先，使用`eval $(minikube docker-env)`链接到 Minikube 的 Docker。当您想要将控制权返回到主机 Docker 守护程序时，请尝试`eval $(minikube docker-env -u)`。

返回到包含我们服务器的文件夹并构建我们的 Docker 镜像（注意末尾的点）：

```js
docker build -t mastering-kube:v1 .
```

当该过程完成后，您应该在终端中看到类似这样的显示：

```js
Successfully built 754d44e83976
Successfully tagged mastering-kube:v1
```

你可能已经注意到我们的镜像名称上有 `:v1` 后缀。我们在 Dockerfile 中声明 Node 时就看到了这一点（还记得 `FROM Node:9` 指令吗）？如果你运行 `docker images`，你会看到标签被应用了：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/190bd58c-f298-4e14-9430-2cb4be0b265f.png)

以后，如果我们想要发布 mastering-kube 的新版本，我们只需使用新标签构建，这将创建一个独立的镜像。这是您随着时间管理容器镜像版本的方法。

现在，让我们使用该镜像启动一个容器，并将其**部署**到我们的 Kubernetes 集群中：

```js
kubectl run kubernetes-demo --image=mastering-kube:v1
```

在这里，我们声明了一个名为 `kubernetes-demo` 的新部署，应该导入版本为 `v1` 的 `mastering-kube` 镜像。如果一切正常，您应该在终端中看到部署 "kubernetes-demo" 已创建。您可以使用 `kubectl get deployments` 列出部署：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/25b518d0-d72b-4619-92dd-3650d4d7a9cf.png)

我们刚刚在 Kubernetes 集群中部署了一个单个 **Pod**。Pod 是 Kubernetes 的基本组织单元，它们是容器的抽象包装。Pod 可能包含一个或多个容器。Kubernetes 管理 Pod，Pod 管理它们自己的容器。每个 Pod 都有自己的 IP 地址，并且与其他 Pod 隔离，但是 Pod 中的容器之间不相互隔离（例如，它们可以通过 `localhost` 进行通信）。

Pod 提供了一个抽象，即在某个地方（本地、AWS、数据中心）运行的单个机器，以及在该单个机器上运行的所有容器。通过这种方式，您可以在云中的不同位置运行 Pod 的单个 Kubernetes 集群。Kubernetes 是跨不同位置的机器主机的抽象，它可以让您编排它们的行为，而不管它们是托管在 AWS 上的 VM 还是您办公室的笔记本电脑，就像您可能使用 ORM 来抽象数据库细节一样，让您可以自由更改部署的技术组成，而不必更改配置文件。

使用 `kubectl get pods` 命令，您现在应该看到类似这样的内容：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/fbda1b0e-1fa8-4d9b-a7e0-33b86dbdb59c.png)

最后一步是将此部署的 Pod 作为服务暴露出来。运行此命令：

```js
kubectl expose deployment kubernetes-demo --port=8087 --type=LoadBalancer
```

如果成功，您应该看到消息服务 "kubernetes-demo" 已暴露。要查看服务，请使用 `kubectl get services`：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/311e19b0-e547-40f3-9ab4-bbacd6ad240e.png)

注意我们是如何创建一个负载均衡类型的部署的，暴露了一个映射到我们的 mastering-kube 服务（容器）的 Kubernetes 服务，可以通过为这个部署的 Pod 分配的唯一 IP 进行访问。让我们找到那个 URL：

```js
minikube service kubernetes-demo --url
```

您应该收到一个 URL（注意 Kubernetes 正在运行自己的 DNS），并浏览到该 URL，您应该看到类似这样的消息：

```js
Service #1513534970093 responding
```

通过 Minikube，您可以在一个步骤中在浏览器中启动您的服务：`minikube service kubernetes-demo`。

很好。然而，Kubernetes 的真正魔力在于部署如何扩展和响应网络条件。

回想一下这个部署是负载均衡的，让我们在同一个 Pod 中创建多个共享负载的容器（不太像你可能会使用 Node 的 Cluster 模块来平衡负载的方式）。运行以下命令：

```js
kubectl scale deployment kubernetes-demo --replicas=4
```

您应该收到消息部署 "kubernetes-demo" 已扩展。让我们确保这是真的。再次运行 `kubectl get pods`。您应该看到我们的部署已经自动扩展了它平衡的 Pod 数量：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/9aa52dae-635a-44a4-a28a-fe1636e5fe9a.png)

这很容易。让我们进行一个快速测试，以证明负载正在跨多个容器进行平衡。我们将使用 **AB（Apache Bench）** 进行快速基准测试和响应显示。使用以下命令针对我们的服务 URL 进行测试（用你本地服务的 URL 替换 URL）：

```js
ab -n 100 -c 10 -v 2 http://192.168.99.100:31769/
```

上面的所有内容都是为了模拟对我们的服务器的 100 次调用，这是为了检查它是否如预期般响应。我们将收到类似以下的输出：

```js
Service #1513614868094 responding
LOG: header received:
 HTTP/1.1 200 OK
X-Powered-By: Express
...
Connection: close

Service #1513614581591 responding
...

Service #1513614867927 responding
...
```

请记住，我们已经在 4 个容器之间进行了缩放的服务器有一个带有唯一时间戳的常量消息：

```js
// Per-server unique message
const message = `Service #${Date.now()} responding`; 

app.get('/', (req, res) => {
    res.send(message);
});
```

`ab`返回的响应差异证明了对一个端点的调用是在多个服务器/容器之间进行负载均衡的。

如果你发现 Minikube 处于奇怪或不平衡的状态，只需清除它的主目录并重新安装。例如：`rm -rf ~/.minikube; minikube start`。你也可以使用`minikube delete`完全删除 Kubernetes 集群。

虽然命令行工具非常有用，但你也可以访问 Kubernetes 集群的仪表板。你可以通过在终端中输入`kubectl proxy`来启动一个仪表板来监视你的集群。你会看到类似于这样的显示：`Starting to serve on 127.0.0.1:8001`。这指向仪表板服务器。在浏览器中打开这个服务器上的`/ui`路径（`127.0.0.1:8001/ui`），你应该会看到一个完整描述你的集群的 UI：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/fd87bab9-33d3-4452-b267-d953131fef11.png)

在这里，我们可以看到所有的 pod、状态等，特别是我们的 Pod 容器的 4/4 缩放。在本章的后面，我们将更深入地了解如何使用仪表板来检查正在运行的集群。

Minikube 提供了一个快捷方式，可以自动打开这个仪表板：`minikube dashboard`。

现在，让我们看一下如何使用**YAML（尚未标记语言）**来创建 Pod 声明，避免我们一直在做的手动配置，并简化后续的部署。

# 声明 Pod 部署

在本节中，我们将创建一个具有三个容器的 Pod，演示使用 YAML 文件管理配置声明如何简化部署过程，以及同一 Pod 中的容器如何相互通信。

在你的代码包中，将有一个名为`/kubernetes`的目录，其布局如下：

```js
/kubernetes
 /rerouter /responder three-containers.yaml
```

每个目录定义了一个 Docker 容器，该容器定义了一个 Express 服务器，将成为这个 Pod 中的容器。我们将把这些视为单独的服务，并演示它们如何通过`localhost`相互通信。

首先，让我们看一下 YAML 文件：

```js
apiVersion: v1
kind: Pod
metadata:
  name: three-containers
spec:
  restartPolicy: OnFailure
  volumes:
  - name: shared-data
    emptyDir: {}

  containers:
  - name: service-rerouter
    image: rerouter:v1
    volumeMounts:
    - name: shared-data
      mountPath: /app/public

  - name: service-responder
    image: responder:v1

  - name: service-os
    image: debian
    volumeMounts:
    - name: shared-data
      mountPath: /pod-data
    command: ["/bin/sh"]
    args: ["-c", "echo Another service wrote this! > /pod-data/index.html"]
```

这个清单是一个`kind`（`Pod`）的清单，具有一个定义了三个`containers`的`spec`，一个共享的`volume`（稍后会详细介绍），以及一个`restartPolicy`，表明只有在容器以失败代码退出时才应重新启动容器。

当容器需要共享数据时，就会使用卷。在容器内部，数据存储是暂时的——如果容器重新启动，那些数据就会丢失。共享卷是在 Pod 内部容器之外保存的，因此可以通过容器的重新启动和崩溃来持久保存数据。更重要的是，单个 Pod 中的许多容器可以写入和读取共享卷，从而创建一个共享的数据空间。我们的服务将使用这个卷作为共享文件系统，希望使用它的容器可以添加一个挂载路径——我们马上就会看到它是如何工作的。有关卷的更多信息，请访问：[`kubernetes.io/docs/concepts/storage/volumes/`](https://kubernetes.io/docs/concepts/storage/volumes/)。

首先，进入`/rerouter`文件夹并构建 docker 镜像：`docker build -t rerouter:v1 .`。请注意，在上面的 Pod 清单中列出了这个镜像：

```js
image: rerouter:v1
```

这个容器的`name`是`service-rerouter`，它提供了一个处理两个路由的 Express 服务器：

1.  当调用根路由（`/`）时，它将在`/public`目录中查找一个`index.html`文件。

1.  当调用`/rerouter`时，它将把用户重定向到这个 Pod 中的另一个服务，即监听端口`8086`的服务：

```js
const express = require('express');
const port = 8087;
const app = express();

app.use(express.static('public'));

app.get('/rerouter', (req, res) => {
    res.redirect('http://localhost:8086/oneroute');
});

app.listen(port, () => console.log(`Running on http://localhost:${port}`)); 
```

如果您查看`service-rerouter`的声明，您会看到它已经挂载到路径`/app/public`上的共享卷。此 Pod 中的任何容器现在都可以写入共享卷，它写入的内容将最终出现在此容器的`/public`文件夹中（可用作提供静态文件）。我们创建了一个容器服务，就是这样：

```js
- name: service-os
    image: debian
    volumeMounts:
    - name: shared-data
      mountPath: /pod-data
    command: ["/bin/sh"]
    args: ["-c", "echo Another service wrote this! > /pod-data/index.html"]
```

`service-os`容器将包含 Debian 操作系统，并将共享卷挂载到路径`/pod-data`。现在，任何写入文件系统的操作实际上都将写入此共享卷。使用系统 shell（`/bin/sh`），当此容器启动时，它将向共享卷`echo`一个`index.html`文件，其中包含“另一个服务写了这个！”的内容。由于此容器在回显后没有其他事情要做，它将终止。因此，我们将重启策略设置为仅在失败时重启 - 我们不希望此容器不断重启。添加终止的“辅助”服务，这些服务有助于构建 Pod 容器，然后退出的模式对于 Kubernetes 部署是常见的。

请记住，`service-rerouter`还声明了它的卷挂载`shared-data`在路径`/app/public`上，`service-os`生成的`index.html`文件现在将出现在该文件夹中，可用于提供服务：

```js
- name: service-rerouter
  image: rerouter:v1
  volumeMounts:
  - name: shared-data
    mountPath: /app/public
```

继续并为`/responder`文件夹中的应用程序构建 docker 镜像，就像您为`/rerouter`一样。`service-responder`容器解析单个路由`/oneroute`，返回一个简单的消息：

```js
const express = require('express');
const port = 8086;
const app = express();
app.get('/oneroute', (req, res) => {
    res.send('\nThe routing worked!\n\n');
});
app.listen(port, () => console.log(`Running on http://localhost:${port}`));
```

此容器将用于演示`service-rerouter`如何跨（共享的）`localhost`重定向 Kubernetes 为此 Pod 设置的 HTTP 请求。由于`service-responder`绑定在端口`8086`上，`service-rerouter`（在端口`8087`上运行）可以通过 localhost 路由到它：

```js
// rerouter/app/index.js
res.redirect('http://localhost:8086/oneroute');
```

因此，我们已经展示了 Pod 内的容器如何共享共同的网络和数据卷。假设您已成功构建了`rerouter:v1`和`responder:v1`的 Docker 镜像，请使用以下命令执行 Pod 清单：

```js
kubectl create -f three-containers.yaml
```

您应该看到创建的 Pod“three-containers”。使用`minikube dashboard`打开仪表板。您应该看到 three-containers Pod：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/a053b0b1-2e87-4362-a8bb-fedf0e1dff03.png)

单击 three-containers 以显示描述：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/452ed631-cd9c-473f-a382-9938e77695d4.png)

很好，一切都在运行。现在，让我们通过连接到我们的容器来验证一切是否正常。

获取`service-router`的 shell：

```js
kubectl exec -it three-containers -c service-rerouter -- /bin/bash
```

安装 curl：

```js
apt-get install curl
```

您的工作目录应该有一个`/public`文件夹。里面应该有一个`index.html`文件，由`service-os`容器创建。获取该文件的内容：`cat public/index.html`。如果一切正常，您应该看到消息“另一个服务写了这个！”，您会记得这是`service-os`服务创建的，通过共享卷 - `public/index.html`文件，`service-rerouter`将提供服务。

现在，让我们调用`/rerouter`路由，它应该重定向到`localhost:8086/oneroute/`上的`service-responder`服务器，并接收其响应“路由服务正常工作！”：

```js
curl -L http://localhost:8087/rerouter
```

这演示了同一 Pod 中的容器如何通过本地主机跨端口范围进行通信，就像它们所包含的 Pod 是单个主机一样。

Mesos 是编排的另一个选择（[`mesos.apache.org/`](http://mesos.apache.org/)），CoreOS 也是：[`coreos.com/`](https://coreos.com/)

这只是 Docker 和 Kubernetes 如何部署以简化扩展的表面。特别是在微服务架构上。您可以通过声明性清单进一步编排整个舰队的服务和部署。例如，很容易看出我们之前设计的 Seneca 微服务如何适应 Pods。现在您可以抽象出个别服务器的实现细节，并开始以声明方式思考，简单地描述您所期望的部署拓扑（副本、卷、恢复行为等），并让 Kubernetes 将其变为现实，这比命令式地微观管理成千上万的服务要好得多。

# 摘要

在本章中，我们深入研究了各种架构模式，从单体到 4 层。在这个过程中，我们开始考虑如何从微服务构建高度动态的应用程序，探索它们在可扩展性、灵活性和可维护性方面的一般优势。我们看了看微服务的 Seneca 框架，其基于模式的执行模型易于构建和遵循，特别是在与自动发现的网格服务的优势相结合时。跳入完全分布式模式，我们使用 Claudia 部署了无服务器 Lambda 函数，使用 API-Gateway 将 RESTful API 推送到 AWS 云中，始终可用并且成本低廉地实现了几乎无限的扩展。通过 Docker 和 Kubernetes（在 Minikube 的帮助下），我们深入探讨了如何构建独立虚拟机的集群，声明和部署容器的 Pods，以满足需求。

在本书的下一章，我们将学习软件开发人员可能最重要的技能：如何测试和调试您的代码。现在我们已经学会将应用程序的逻辑部分分离成独立的部分，我们可以开始探索这种设计在测试方面的优势，无论是在抽象的测试工具中还是在实际的代码情况中。


# 第十章：测试您的应用程序

“当地形与地图不符时，请相信地形。”

- 瑞士军刀手册

由于 Node 是由一个完全致力于代码共享的社区构建的，模块之间的互操作性非常重要，因此毫不奇怪的是，在 Node 的生态系统中，代码测试工具和框架在创立后不久就进入了。事实上，通常吝啬的核心 Node 团队很早就添加了`assert`模块，这表明他们认识到测试是开发过程的基本部分。

测试不仅仅是一个检测错误和修复缺陷的过程。例如，测试驱动开发坚持在任何代码存在之前进行测试！一般来说，测试是在软件中对现有行为和期望行为进行比较的过程，其中新信息不断地反馈到过程中。在这个意义上，测试涉及对期望进行建模，并验证单个功能、组成单元和实现路径是否满足每个利益相关者的期望，无论是在组织内部还是超出组织范围。

因此，测试也是关于管理风险。通过这种方式，异常可以被识别和量化，而地形中的颠簸现在可以有用地影响我们对地图的当前理解，从而缺陷的数量减少，我们的信心提高。测试帮助我们衡量何时完成。

在本章中，我们将专注于一些已知和有用的测试 Node 应用程序的模式，调查用于代码完整性测试的原生 Node 工具，使用 Mocha 框架进行一般测试，以及无头浏览器测试，最后一种允许在 Node 环境中测试基于浏览器的 JavaScript。我们还将看看测试的另一面——调试——并将两者结合起来。

当您阅读本章时，牢记将测试哲学融入项目可能很难做到。编写正确的测试比编写一些测试更困难。测试正确的事情比测试所有事情更困难（完整的代码覆盖很少意味着什么都不会出错）。一个好的测试策略应该尽早实施——这是您开始下一个 Node 项目时需要考虑的事情。

# 为什么测试很重要

一个好的测试策略通过积累证据和增加清晰度来建立信心。在公司内部，这可能意味着某些执行业务策略的标准已经得到满足，从而允许发布新的服务或产品。项目团队内的开发人员获得了一个自动的法官，确认或否认提交到代码库的更改是否合理。有了一个良好的测试框架，重构就不再危险；曾经对具有新想法的开发人员施加负面压力的“如果你破坏了它，你就拥有它”的警告不再那么可怕。有了一个良好的版本控制系统和测试/发布流程，任何破坏性的更改都可以在没有负面影响的情况下回滚，释放好奇心和实验精神。

三种常见的测试类型是：单元测试、功能测试和集成测试。虽然我们在本章的目标不是提出关于如何测试应用程序的一般理论，但简要总结单元测试、功能测试和集成测试是有用的，团队的哪些成员对每种测试最感兴趣，以及我们如何构建（或拆分）一个可测试的代码库。

# 单元测试

**单元测试**关注系统行为的单元。每个被测试的单元应该封装一个非常小的代码路径集，没有纠缠。当一个单元测试失败时，这应该理想地表明整体功能的一个孤立部分出现了问题。如果一个程序有一组明确定义的单元测试，整个程序的目的和预期行为应该很容易理解。单元测试对系统的小部分应用了有限的视角，不关心这些部分如何被包装成更大的功能块。

一个示例单元测试可以这样描述：当`123`值传递给“validate_phone_number（）”方法时，测试应该返回 false。对于这个单元的功能没有困惑，程序员可以放心使用它。

单元测试通常由程序员编写和阅读。类方法是良好的单元测试候选者，其他服务端点的输入签名稳定且被充分理解，预期输出可以被准确验证。通常假定单元测试运行速度快。如果一个单元测试执行时间很长，很可能是被测试的代码比应该的复杂。

单元测试不关心函数或方法将如何接收其输入，或者它将如何在一般情况下被使用。对于`add`方法的测试不应该关心该方法是否将被用于计算器或其他地方，它应该简单地测试两个整数输入（3,4）是否会导致该单元产生正确的结果（7）。单元测试不关心它在依赖树中的位置。因此，单元测试通常会*模拟*或*存根*数据源，例如将两个示例整数传递给`add`方法。只要输入是典型的，它们不必是实际的。此外，良好的单元测试是可靠的：不受外部依赖的影响，它们应该保持有效，无论周围的系统如何变化。

单元测试只确认单个实体在隔离状态下工作。测试单元能否在组合时良好工作是功能测试的目的。

# 功能测试

在单元测试关注特定行为的同时，**功能测试**旨在验证功能的各个部分。根词*function*的模棱两可，特别是对程序员来说，可能会导致混淆，即*单元测试*被称为*功能测试*，反之亦然。功能测试将许多单元组合成一个功能体，例如*当用户输入用户名和密码并点击发送时，该用户将被登录到系统*。我们很容易看到这个功能组将包括许多单元测试，一个用于验证用户名，一个用于处理按钮点击，等等。

功能测试通常是应用程序中某个特定领域的负责人关心的事情。虽然程序员和开发人员将继续实施这些测试，但产品经理或类似的利益相关者通常会设计它们（并在它们失败时抱怨）。这些测试在很大程度上检查较大的产品规格是否得到满足，而不是技术上的正确性。

前面给出的`validate_phone_number`的示例单元测试可能构成一个功能测试的一部分，描述如下：当用户输入错误的电话号码时，在该用户的国家显示一个描述正确格式的帮助消息。一个应用程序会帮助那些在电话号码上犯错误的用户，这是一个非常抽象的努力，与简单验证电话号码这样的技术实体完全不同。功能测试可以被认为是一些单元的抽象模型，它们如何一起满足产品需求。

由于功能测试是针对许多单元的组合进行的，因此可以预期，与孤立的单元测试不同，执行它们将涉及混合来自任意数量的外部对象或系统的关注点。在前面的登录示例中，我们看到一个相对简单的功能测试如何涉及数据库、UI、安全性和其他应用层。由于它的组合更复杂，功能测试花费的时间比单元测试多一点是可以接受的。功能测试预计变化不如单元测试频繁，因此功能的变化通常代表主要发布，而不是通常表示较小变化的单元测试修改。

请注意，与单元测试一样，功能测试本身与功能组在整个应用程序中的关系无关。因此，可以使用模拟数据作为运行功能测试的上下文，因为功能组本身不关心其对一般应用程序状态的影响，这是集成测试的领域。

# 集成测试

**集成测试**确保整个系统正确连接在一起，以便用户感觉应用程序正常工作。因此，集成测试通常验证整个应用程序的预期功能，或者验证一组重要产品功能中的一个。

集成测试与讨论中的其他测试类型最重要的区别在于，集成测试应在真实环境中执行，使用真实数据库和实际域数据，在服务器和其他系统上模拟目标生产环境。这样，集成测试很容易破坏以前通过的单元和功能测试。

例如，对于`validate_phone_number`的单元测试可能会通过像`555-123-4567`这样的输入，但在集成测试中，它将无法通过一些真实（且有效）的系统数据，比如`555.123.4567`。同样，功能测试可能成功测试理想系统打开帮助对话框的能力，但当与新的浏览器或其他运行时集成时，发现无法实现预期的功能。一个在单个本地文件系统上运行良好的应用程序，在分布式文件系统上运行时可能会失败。

由于增加了这种复杂性，系统架构师——能够对系统正确性应用更高层次的视角的团队成员——通常设计集成测试。这些测试可以发现孤立测试无法识别的连接错误。毫不奇怪，集成测试通常需要很长时间才能运行，通常设计为不仅运行简单场景，而且模拟预期的高负载、真实环境。

# 本地节点测试和调试工具

自从诞生以来，对经过测试的代码的偏好一直是 Node 社区理念的一部分，这反映在大多数流行的 Node 模块，甚至简单的模块，都附带了测试套件。而在许多年里，没有可用的测试工具，JavaScript 在浏览器端的开发一直备受困扰，而相对年轻的 Node 分发包含了许多测试工具。也许正因为如此，为 Node 开发了许多成熟且易于使用的第三方测试框架。这使得开发人员没有借口编写未经测试的代码！让我们来看看一些用于调试和测试 Node 程序的提供的工具。

# 写入控制台

控制台输出是最基本的测试和调试工具，提供了一个快速查看脚本中发生情况的方式。全局可访问的`console.log`通常用于调试。

Node 已经丰富了标准输出机制，增加了更多有用的方法，比如`console.error(String, String…)`，它将参数打印到`stderr`而不是`stdout`，以及`console.dir(Object)`，它在提供的对象上运行`util.inspect`（参见下文）并将结果写入`stdout`。

当开发人员想要跟踪代码执行所需时间时，通常会看到以下模式：

```js
let start = new Date().getTime();
for (x = 0; x < 1000; x++) {
  measureTheSpeedOfThisFunction();
}
console.log(new Date().getTime() - start);
// A time, in milliseconds 
```

`console.time`和`console.timeEnd`方法标准化了这种模式：

```js
 console.time('Add 1000000 records');
 let rec = [];
 for (let i = 0; i < 1000000; i++) {
     rec.push(1);
 }
 console.timeEnd('Add 1000000 records');
 //  > Add 1000000 records: 59ms
```

确保将相同的标签传递给`timeEnd()`，以便 Node 可以找到您使用`time()`开始的测量。Node 将秒表结果打印到`stdout`。在本章后面讨论断言模块和执行堆栈跟踪时，我们将看到其他特殊的控制台方法。

# 格式化控制台输出

在记录简单字符串时，上述方法都非常有用。更常见的是，有用的日志数据可能需要进行格式化，可以通过将几个值组合成单个字符串，或者通过整齐地显示复杂的数据对象来处理。`util.format`和`util.inspect`方法可以用来处理这些情况。

# `util.format(format，[arg，arg…])`方法

此方法允许将格式化字符串组成占位符，每个占位符都捕获并显示传递的附加值。考虑以下示例：

```js
> util.format('%s:%s', 'foo','bar')
 'foo:bar' 
```

在这里，我们看到两个占位符（以`％`为前缀）按顺序被传递的参数替换。占位符期望以下三种类型的值之一：

+   `％s`：字符串

+   `％d`：数字，可以是整数或浮点数

+   `％j`：JSON 对象

如果发送的参数数量多于占位符数量，则额外的参数将通过`util.inspect()`转换为字符串，并连接到输出的末尾，用空格分隔：

```js
> util.format('%s:%s', 'foo', 'bar', 'baz');
 'foo:bar baz' 
```

如果没有发送格式化字符串，则参数将被简单地转换为字符串并用空格分隔连接。

# `util.inspect(object，[options])`方法

当需要对象的字符串表示时，请使用此方法。通过设置各种选项，可以控制输出的外观：

+   `showHidden`：默认为 false。如果为 true，则会显示对象的不可枚举属性。

+   `depth`：对象定义（例如 JSON 对象）可以被深度嵌套。默认情况下，`util.inspect`只会遍历对象的两个级别。使用此选项来增加（或减少）深度。

+   `colors`：允许对输出进行着色（请查看以下代码片段）。

+   `customInspect`：如果正在处理的对象定义了`inspect`方法，则将使用该方法的输出，而不是 Node 的默认`stringification`方法（参见以下代码片段）。默认为 true。

设置自定义检查器：

```js
const util = require('util');
let obj = function() {
   this.foo = 'bar';
};
obj.prototype.inspect = function() {
   return "CUSTOM INSPECTOR";
};
console.log(util.inspect(new obj));
// CUSTOM INSPECTOR
console.log(util.inspect(new obj, { customInspect: false }));
// { foo: 'bar' }
```

当记录复杂对象或对象的值过大以至于使控制台输出无法阅读时，这可能非常有用。如果您的 shell 在终端中显示漂亮的颜色，如果颜色设置为 true，`util.inspect`也会显示漂亮的颜色。您甚至可以自定义颜色以及它们的使用方式。默认情况下，颜色只表示数据类型。

以下是默认设置，如在`util.inspect.styles`中设置的：

```js
{
   number: 'yellow',
   boolean: 'yellow',
   string: 'green',
   date: 'magenta',
   regexp: 'red'
   null: 'bold',
   undefined: 'grey',
   special: 'cyan',
 } 
```

在上述代码中，Node 以青色显示特殊类别中的函数。这些默认颜色分配可以与`util.inspect.colors`对象中存储的支持的 ANSI 颜色代码之一进行交换：粗体，斜体，下划线，反向，白色，灰色，黑色，蓝色，青色，绿色，品红色，红色和黄色。例如，要将对象的数字值显示为绿色而不是默认的黄色，请使用以下代码：

```js
 util.inspect.styles.number = "green";
 console.log(util.inspect([1,2,4,5,6], {colors: true}));
 // [1,2,3,4,5,6] Numbers are in green
```

# Node 调试器

大多数开发人员都使用 IDE 进行开发。所有良好的开发环境的一个关键特性是可以访问调试器，它允许在程序中设置断点，以便在需要检查状态或运行时的其他方面的地方进行检查。

V8 带有一个强大的调试器（通常用于 Google Chrome 浏览器的开发者工具面板），并且此调试器可供 Node 访问。它是使用 inspect 指令调用的：

```js
> node inspect somescript.js 
```

现在可以在节点程序中实现简单的逐步调试和检查。考虑以下程序：

```js
// debug-sample.js
setTimeout(() => {
  let dummyVar = 123;
  debugger;
  console.log('world');
}, 1000);
console.log('hello'); 
```

`dummyVar`一会儿就会有意义。现在注意`debugger`指令。在没有该行的情况下执行此程序会像您期望的那样运行：打印`hello`，等待一秒，然后打印`world`。有了调试器指令，运行 inspect 会产生这样的结果：

```js
> node inspect debug-sample.js
< Debugger listening on ws://127.0.0.1:9229/b3f76643-9464-41d0-943a-d4102450467e
< For help see https://nodejs.org/en/docs/inspector
< Debugger attached.
Break on start in debug-sample.js:1
> 1 (function (exports, require, module, __filename, __dirname) { setTimeout(() => {
 2 let dummyVar = 123;
 3 debugger;
debug>
```

调试器指令创建一个断点，一旦命中，Node 会给我们一个 CLI 来执行一些标准的调试命令：

+   `cont`或`c`：从上一个断点继续执行，直到下一个断点

+   `step`或`s`：步进，即继续运行直到命中新的源行（或断点），然后将控制返回给调试器

+   `next`或`n`：与`step`相同，但在新的源行上进行的函数调用会在不停止的情况下执行

+   `out`或`o`：跳出，即执行当前函数的其余部分并返回到父函数

+   `backtrace`或`bt`：跟踪到当前执行帧的步骤

+   `setBreakpoint()`或`sb()`：在当前行设置断点

+   `setBreakpoint(Integer)`或`sb(Integer)`：在指定行设置断点

在指定的行

+   `clearBreakpoint()`或`cb()`：清除当前行的断点

+   `clearBreakpoint(Integer)`或`cb(Integer)`：清除断点

在指定的行

+   `run`：如果调试器的脚本已终止，这将重新启动它

+   `restart`：终止并重新启动脚本

+   `pause`或`p`：暂停运行的代码

+   `kill`：终止正在运行的脚本

+   `quit`：退出调试器

+   `version`：显示 V8 版本

+   `scripts`：列出所有加载的脚本

重复上次的调试器命令，只需在键盘上按*Enter*。你的腕管道会感谢你。

回到我们正在调试的脚本：在调试器中输入`cont`将产生以下输出：

```js
...
debug> cont
< hello // A pause will now occur because of setTimeout
break in debug-sample.js:3
 1 (function (exports, require, module, __filename, __dirname) { setTimeout(() => {
 2 let dummyVar = 123;
> 3 debugger;
 4 console.log('world');
 5 }, 1000);
debug>
```

现在我们停在第 3 行的调试器语句处（注意尖括号）。例如，如果现在输入`next`（或`n`），调试器将跳到下一条指令并停在`console.log('world')`处。

在断点处通常有用进行一些状态检查，比如变量的值。您可以从调试器中跳转到**repl**以执行此操作。目前，我们在`debugger`语句处暂停。如果我们想要检查`dummyVar`的值怎么办？

```js
debug> repl
Press Ctrl + C to leave debug repl
> dummyVar
123
```

作为一个实验，再次运行脚本，使用`next`而不是`cont`，在最后一个上下文执行之前。不断按 Enter（重复上次的命令），尝试跟踪正在执行的代码。几步之后，您会注意到`timers.js`脚本将被引入到这个执行上下文中，并且您会看到类似以下的内容：

```js
debug> next
break in timers.js:307
 305 threw = false;
 306 } finally {
>307 if (timerAsyncId !== null) {
 308 if (!threw)
 309 emitAfter(timerAsyncId);
debug>
```

在这一点上在调试器中运行`scripts`命令，列出当前加载的脚本。您会看到类似这样的内容：

```js
debug> scripts
* 39: timers.js <native>
71: debug-sample.js
```

尝试使用强大的 V8 调试器来暂停、检查和在 Node 程序中进行导航的各种方法。除了常见的调试需求外，调试器在执行代码时以深层次显示 Node 的操作非常出色。

在本章的后面，我们将回顾其他可用于 Node 开发人员的调试和测试技术和工具。现在，让我们考虑`assert`模块，以及如何使用 Node 提供的这个本地测试框架。

# assert 模块

Node 的`assert`模块用于简单的单元测试。在许多情况下，它足以作为测试的基本脚手架，或者用作测试框架（如 Mocha，稍后我们将看到）的断言库。使用起来很简单：我们想要断言某些事情的真实性，并在我们的断言不为真时抛出错误。考虑这个例子：

```js
> require('assert').equal(1,2,'Not equal!')
AssertionError [ERR_ASSERTION]: Not equal!
>
```

如果断言为真（两个值相等），则不会返回任何内容：

```js
> require('assert').equal(1,1,"Not equal!")
undefined
```

遵循 UNIX 的沉默规则（当程序没有令人惊讶、有趣或有用的内容时，它应该保持沉默），断言只有在断言失败时才返回一个值。返回的值可以使用可选的消息参数进行自定义，就像前面的部分所示的那样。

`assert`模块 API 由一组具有相同调用签名的比较操作组成：实际值，期望值和可选消息（在比较失败时显示）。还提供了作为快捷方式或处理特殊情况的替代方法。

必须区分身份比较（`===`）和相等比较（`==`），前者通常被称为严格相等比较（就像在`assert`API 中一样）。由于 JavaScript 采用动态类型，当使用`==`相等运算符比较不同类型的两个值时，会尝试强制（或转换）一个值为另一个值，一种通用的操作。看看这个例子：

```js
1 == "1" // true
false == "0" // true
false == null // false
```

请注意，使用身份比较时结果更可预测：

```js
1 === "1" // false
false === "0" // false
false === null // false
```

要记住的是，在比较之前，`===`运算符不执行类型强制转换，而相等运算符在类型强制转换后进行比较。

将字符串和数字相等使 JavaScript 成为新手编程的宽容语言，并且很快，创建了一个错误，现在更有经验的程序员无意中隐藏在更大的代码库中。像*Brendan Eich*这样的语言作者做出这样的决定，并且很少能够在以后改变如此基本的行为，他们必须通过无休止的争论和争议来捍卫他们的决定，因为程序员们因此而抨击和赞扬他们的语言。

此外，因为对象可能包含相同的值但不是由相同的构造函数派生，因此具有相同值的两个对象的身份是不同的；身份要求两个操作数引用同一对象：

```js
let a = function(){};
let b = new a;
let c = new a;
let d = b;
console.log(a == function(){}) // false
console.log(b == c) // false
console.log(b == d) // true
console.log(b.constructor === c.constructor); // true
```

最后，深度相等的概念用于对象比较，其中身份不需要完全相同。如果两个对象都拥有相同数量的自有属性，相同的原型，相同的键集（尽管不一定是相同的顺序），并且每个属性的值是等效的（而不是相同的），则两个对象是深度相等的：

```js
const assert = require('assert');
let a = [1,2,3];
let b = [1,2,3];
assert.deepEqual(a, b); // passes, so nothing is output
assert.strictEqual(a, b); // throws Assertion error
```

通过设计一些断言测试来测试您对值如何相互理解的假设是很有用的。结果可能会让您感到惊讶。

以下是 Node 的 assert 模块中的函数，根据您可能使用它们的方式进行组织：

```js
equal            notEqual
strictEqual      notStrictEqual
deepEqual        notDeepEqual
deepStrictEqual  notDeepStrictEqual
ok
ifError
fail
throws           doesNotThrow
```

使用带有相等名称的断言函数遵循与`==`运算符相同的规则，而严格相等就像使用`===`一样。此外，选择一个标题中带有深度的函数，或者不带，以选择我们之前探索的所需行为。最简单的函数`assert.ok`，如果您自己编写逻辑来等同，可能就是您所需要的全部。

Node 的异步函数将错误对象返回给您的回调函数。将此对象传递给`assert.ifError(e)`，如果`e`被定义，`ifError`将抛出它。当执行已经到达代码中不应该执行的部分时，使用`assert.fail()`是最有用的。当异常被`try`/`catch`块捕获时，这是最有用的：

```js
// assertthrows.js
const assert = require('assert');
try {
   assert.fail(1,2,'Bad!','NOT EQ') 
} catch(e) { 
   console.log(e);
}
```

运行上述代码会产生以下输出：

```js
{ AssertionError [ERR_ASSERTION]: Bad!
 at Object.<anonymous> (/Users/sandro/Desktop/clients/ME/writing/Mastering_V2/chapter_ten/code/assertthrows.js:4:9)
 at Module._compile (module.js:660:30)
 ...
 at bootstrap_node.js:618:3
   generatedMessage: false,
 name: 'AssertionError [ERR_ASSERTION]',
 code: 'ERR_ASSERTION',
 actual: 1,
 expected: 2,
 operator: 'NOT EQ' }
```

控制台 API 中提供了用于记录断言结果的快捷方法：

```js
> repl
> console.assert(1 == 2, 'Nope!')
AssertionError [ERR_ASSERTION]: Nope!
```

或者，您可以使用`assert.throws`和`assert.doesNotThrow`确认函数始终抛出或从不抛出。

有关 JavaScript 中比较的详细解释，请参阅：[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Comparison_Operators`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Comparison_Operators) [Node 的 assert 模块受 CommonJS 测试规范的强烈影响，该规范可以在以下网址找到：](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Comparison_Operators) [`wiki.commonjs.org/wiki/Unit_Testing`](http://wiki.commonjs.org/wiki/Unit_Testing)[.](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Comparison_Operators)

# 沙箱

在某些情况下，您可能希望在一个单独且更有限的上下文中运行脚本，使其与较大应用程序的范围隔离开来。对于这些情况，Node 提供了`vm`模块，一个沙盒环境，包括一个新的 V8 实例和一个用于运行脚本块的有限执行上下文：

```js
const vm = require('vm');
let sandbox = {
    count: 2
};
let suspectCode = '++count;';
vm.runInNewContext(suspectCode, sandbox);
console.log(sandbox);
// { count: 3 }
```

在这里，我们看到提供的沙盒成为提供的脚本的局部执行范围。运行的脚本只能在提供的沙盒对象中操作，并且甚至被拒绝访问标准的 Node 全局对象，例如正在运行的进程，我们可以通过更改前面的代码来进行演示：

```js
suspectCode = '++count; process.exit()';
vm.runInNewContext(suspectCode, sandbox);

// evalmachine.<anonymous>:1
// ++count; process.exit()
//          ^
//
// ReferenceError: process is not defined
// at evalmachine.<anonymous>:1:10
// at ContextifyScript.Script.runInContext (vm.js:59:29)
// ...
```

该模块不能保证完全安全的*监狱*，以便可以安全地执行完全不受信任的代码。如果有这种需求，请考虑以适当的系统级权限运行一个单独的进程。由于`vm`会启动一个新的 V8 实例，每次调用都会耗费一些毫秒的启动时间和大约两兆字节的内存。只有在值得这种性能成本的情况下才使用`vm`。

为了测试代码，`vm`模块可以非常有效，特别是在强制代码在有限上下文中运行的能力方面。例如，在执行单元测试时，可以创建一个特殊的环境，并使用模拟环境中的模拟数据来测试脚本。这比创建一个带有虚假数据的人工调用上下文要好。此外，这种沙盒化将允许更好地控制新代码的执行上下文，提供良好的内存泄漏保护和其他在测试过程中可能出现的意外冲突。

# 区分局部范围和执行上下文

在进一步介绍示例之前，我们需要区分进程的局部范围和其执行上下文。这种区分有助于理解两个主要`vm`方法之间的区别：`vm.runInThisContext`和`vm.runInNewContext`。

在任何时候，V8 可能有一个或更可能是几个执行上下文。这些上下文充当单独的容器，V8 可以在其中执行一些更多的 JavaScript。在使用 Chrome 时，您可以将这些执行上下文视为导航到不同网站的不同标签页。

一个站点上的脚本无法看到或干扰另一个站点上的脚本。Node 进程的执行上下文代表 V8 中的运行时上下文，包括本地 Node 方法和其他全局对象（process、console、setTimeout 等）。

通过`vm.runInNewContext`执行的脚本无法访问任何范围；它的上下文限制在之前传递给它的沙盒对象中。

通过`vm.runInThisContext`执行的脚本可以访问 Node 进程的全局执行范围，但无法访问局部范围。我们可以通过以下方式进行演示：

```js
const vm = require('vm');

global.x = 1; // global scope
let y = 1; // local scope

vm.runInThisContext('x = 2; y = 3');
console.log(x, y); // 2, 1 <- only global is changed

eval('x = 3; y = 4');
console.log(x, y); // 3, 4 <- eval changes x, y
```

因此，脚本是通过`vm`在上下文中运行的。

预编译上下文和脚本通常很有用，特别是当每个都将被重复使用时。使用`vm.createContext([sandbox])`来编译一个执行上下文，并传入一个键/值映射。在下一节中，我们将看看如何将这些上下文应用于预编译的脚本。

# 使用编译上下文

收到 JavaScript 代码字符串后，V8 编译器将尽力将代码优化为更高效的编译版本。每次`vm`上下文方法接收代码字符串时，都必须进行这个编译步骤。如果您的代码不会改变并且至少被重用一次，最好使用`new vm.Script(code, [filename])`来编译它一次。

我们可以在从`runInThisContext`和`runInNewContext`继承的上下文中执行这些编译后的脚本。在这里，我们在两个上下文中运行编译后的脚本，演示了`x`和`y`变量被递增存在于完全隔离的范围中：

```js
const vm = require('vm');

global.x = 0;
global.y = 0;

let script = new vm.Script('++x, ++y;');
let emulation = vm.createContext({ x:0, y:0 });

for (let i = 0; i < 1000; i++) {
   script.runInThisContext(); // using global
   script.runInNewContext(emulation); // using own context
}

console.log(x, y); // 1000 1000
console.log(emulation.x, emulation.y); // 1000 1000
```

如果两个脚本都修改了相同的上下文中的`x`和`y`，输出将会是`2000 2000`。

请注意，如果`runInNewContext`脚本没有传递仿真层（沙盒），它将抛出`ReferenceError: x is not defined`，既不能访问本地变量也不能访问全局变量`x`和`y`的值。试一下。

现在我们已经了解了断言和创建测试上下文的一些内容，让我们使用一些常见的测试框架和工具编写一些真正的测试。

# 使用 Mocha、Chai 和 Sinon 进行测试

为您的代码编写测试的一个巨大好处是，您将被迫思考您编写的代码是如何工作的。难以编写的测试可能表明难以理解的代码。

另一方面，通过良好的测试实现全面覆盖，有助于他人（和您）了解应用程序的工作原理。在本节中，我们将看看如何使用测试运行器**Mocha**来描述您的测试，使用**Chai**作为其断言库，并在需要对测试进行模拟时使用**Sinon**。我们将使用**redis**来演示如何针对模拟数据集创建测试（而不是针对生产数据库进行测试，这当然是一个坏主意）。我们将使用**npm**作为测试脚本运行器。

首先，设置以下文件夹结构：

```js
/testing

/scripts

/spec
```

现在，在`/testing`文件夹中使用`npm init`初始化一个`package.json`文件。您可以在提示时只需按*Enter*，但当要求测试命令时，请输入以下内容：

```js
mocha ./spec --require ./spec/helpers/chai.js --reporter spec
```

这为我们的项目设置了我们将需要的模块的导入。稍后我们将讨论 Chai 的作用。现在，可以说在这个测试命令中，Mocha 被引用为依赖信息的配置文件。

继续安装所需的库到这个包中：

```js
npm install --save-dev mocha chai sinon redis
```

`/scripts`文件夹将包含我们将要测试的 JavaScript。`/spec`文件夹将包含配置和测试文件。

随着我们的进展，这将变得更有意义。现在，要认识到对 npm 的`test`属性的分配表明我们将使用 Mocha 进行测试，Mocha 的测试报告将是`spec`类型，并且测试将存在于`/spec`目录中。我们还需要一个 Chai 的配置文件，这将在我们继续进行时进行解释。重要的是，这现在已经在 npm 中创建了一个脚本声明，允许您使用`npm test`命令运行测试套件。在接下来的开发中，每当需要运行我们将要开发的 Mocha 测试时，请使用该命令。

# Mocha

Mocha 是一个测试运行器，不关心测试断言本身。Mocha 用于组织和运行您的测试，主要通过使用`describe`和`it`操作符。概括地说，Mocha 测试看起来像这样：

```js
describe("Test of Utility Class", function() {
  it("should return a date", function(){
   // Test date function somehow and assert success or failure
  });
  it("should return JSON", function() {
   // Test running some string through #parse 
  });
});
```

正如您所看到的，Mocha 测试套件留下了测试如何描述和组织的空间，并且不假设测试断言的设计方式。它是您测试的组织工具，另外还旨在生成可读的测试定义。

您可以设置同步运行的测试，如前面所述，也可以使用传递给所有回调的完成处理程序异步运行：

```js
describe("An asynchronous test", () => { 
  it("Runs an async function", done => { 
    // Run async test, and when finished call... done(); 
  }); 
}); 
```

块也可以嵌套：

```js
describe("Main block", () => { 
  describe("Sub block", () => { 
    it("Runs an async function", () => { 
      // A test running in sub block 
    }); 
  }); 
  it("Runs an async function", () => { 
    // A test running in main block 
  }); 
});
```

最后，Mocha 提供了*hooks*，使您能够在测试之前和/或之后运行一些代码：

+   `beforeEach()`在描述块中的每个测试之前运行

+   `afterEach()`在描述块中的每个测试之后运行

+   `before()`在任何测试之前运行一次代码-在任何`beforeEach`运行之前

+   `after()`在所有测试运行后运行一次代码-在任何`afterEach`运行之后

通常，这些用于设置测试上下文，例如在测试之前创建一些变量并在其他一些测试之前清理它们。这个简单的工具集足够表达大多数测试需求。此外，Mocha 提供了各种测试报告程序，提供不同格式的结果。随着我们构建一些真实的测试场景，我们将在后面看到这些。

# Chai

正如我们之前在 Node 的原生断言模块中看到的，基本上，测试涉及断言我们期望某些代码块执行的内容，执行该代码，并检查我们的期望是否得到满足。Chai 是一个断言库，提供了更具表现力的语法，提供了三种断言样式：`expect`、`should`和`assert`。我们将使用 Chai 来提供断言（测试），并将其包装在 Mocha 的`it`语句中，更青睐`expect`样式的断言。

请注意，虽然`Chai.assert`是模仿核心 Node 断言语法的，但 Chai 通过附加方法来增强对象。

首先，我们将创建一个配置文件`chai.js`：

```js
let chai = require('chai');

chai.config.includeStack = true;
global.sinon = require('sinon');
global.expect = chai.expect;
global.AssertionError = chai.AssertionError;
global.Assertion = chai.Assertion;
```

将此文件放在`/spec/helpers`文件夹中。这将告诉 Chai 显示任何错误的完整堆栈跟踪，并将`expect`断言样式公开为全局。同样，Sinon 也被公开为全局（更多关于 Sinon 的内容将在下一节中介绍）。这个文件将增强 Mocha 测试运行上下文，以便我们可以在每个测试文件中使用这些工具而不必重新声明它们。`expect`样式的断言读起来像一个句子，由*to*、*be*、*is*等单词组成。考虑以下例子：

```js
expect('hello').to.be.a('string') 
expect({ foo: 'bar' }).to.have.property('foo') 
expect({ foo: 'bar' }).to.deep.equal({ foo: 'bar' }); 
expect(true).to.not.be.false 
expect(1).to.not.be.true 
expect(5).to.be.at.least(10) // fails
```

要探索在创建期望测试链时可用的广泛单词列表，请查阅完整文档：[`chaijs.com/api/bdd/`](http://chaijs.com/api/bdd/)。正如前面所述，Mocha 对于如何创建断言并没有意见。我们将在接下来的测试中使用`expect`来创建断言。

考虑测试以下对象中的 capitalize 函数：

```js
let Capitalizer = () => {
  this.capitalize = str => { 
    return str.split('').map(char => { 
      return char.toUpperCase(); 
    }).join(''); 
  }; 
};
```

我们可能会这样做：

```js
describe('Testing Capitalization', () => { 
  let capitalizer = new Capitalizer(); 
  it('capitalizes a string', () => {
    let result = capitalizer.capitalize('foobar'); 
    expect(result).to.be.a('string').and.equal('FOOBAR'); 
  }); 
});
```

这个 Chai 断言将是真的，Mocha 也会报告相同的结果。您将用这些描述和断言块构建整个测试套件。

接下来，我们将看看如何将 Sinon 添加到我们的测试过程中。

# Sinon

在测试环境中，您通常在模拟生产环境的现实情况，因为访问真实用户、数据或其他实时系统是不安全或不可取的。因此，能够模拟环境是测试的一个重要部分。此外，您通常希望检查的不仅仅是调用结果；您可能还想测试给定函数是否在正确的上下文中被调用或使用正确的示例。Sinon 是一个帮助您模拟外部服务、模拟函数、跟踪函数调用等的工具。

sinon-chai 模块在[`github.com/domenic/sinon-chai`](https://github.com/domenic/sinon-chai)上扩展了 Chai 的 Sinon 断言。

关键的 Sinon 技术是间谍、存根和模拟。此外，您可以设置虚假计时器，创建虚假服务器等等（访问：[`sinonjs.org/`](http://sinonjs.org/)）。本节重点介绍前三者。让我们看看每个的一些例子。

# 间谍

来自 Sinon 文档：

“测试间谍是一个记录其所有调用的参数、返回值、this 的值和抛出的异常（如果有的话）的函数。测试间谍可以是一个匿名函数，也可以包装一个现有函数。”

间谍收集了它正在跟踪的函数的信息。看看这个例子：

```js
const sinon = require('sinon'); 

let argA = "foo"; 
let argB = "bar"; 
let callback = sinon.spy(); 

callback(argA); 
callback(argB); 

console.log(
  callback.called, 
  callback.callCount, 
  callback.calledWith(argA), 
  callback.calledWith(argB), 
  callback.calledWith('baz')
);
```

这将记录以下内容：

```js
true 
2 
true 
true 
false
```

间谍被叫了两次；一次用`foo`，一次用`bar`，从未用过`baz`。如果你正在测试某个函数是否被调用和/或测试它接收到的参数，间谍是你的一个很好的测试工具。

假设我们想测试我们的代码是否正确连接到 Redis 的发布/订阅功能：

```js
const redis = require("redis"); 
const client1 = redis.createClient(); 
const client2 = redis.createClient(); 

// Testing this
function nowPublish(channel, msg) { 
  client2.publish(channel, msg); 
}; 
describe('Testing pub/sub', function() { 
  before(function() { 
    sinon.spy(client1, "subscribe"); 
  }); 
  after(function() { 
    client1.subscribe.restore(); 
  }); 

  it('tests that #subscribe works', () => { 
    client1.subscribe("channel");
    expect(client1.subscribe.calledOnce); 
  }); 
  it('tests that #nowPublish works', done => { 
    let callback = sinon.spy(); 
    client1.subscribe('channel', callback); 
    client1.on('subscribe', () => { 
      nowPublish('channel', 'message'); 
        expect(callback.calledWith('message')); 
        expect(client1.subscribe.calledTwice); 
        done(); 
    }); 
  }); 
});
```

在这个例子中，我们在 spy 和 Mocha 中做了更多。 我们使用 spy 代理 client1 的原生 subscribe 方法，重要的是在 Mocha 的 before 和 after 方法中设置和拆卸 spy 代理（恢复原始功能）。 Chai 断言证明`subscribe`和`nowPublish`都正常运行，并且接收到正确的参数。 有关间谍的更多信息可以在以下网址找到：[`sinonjs.org/releases/v4.1.2/spies`](http://sinonjs.org/releases/v4.1.2/spies)。

# 存根

测试存根是具有预编程行为的函数（间谍）。 它们支持完整的测试间谍 API，以及可用于更改存根行为的方法。 存根在用作间谍时，可以包装现有函数，以便可以伪造该函数的行为（而不仅仅是记录函数执行，就像我们之前在间谍中看到的那样）。

假设您的应用程序中有一些功能会调用一些 HTTP 端点。 代码可能是这样的：

```js
http.get("http://www.example.org", res => { 
  console.log(`Got status: ${res.statusCode}`); 
}).on('error', e => { 
  console.log(`Got error: ${e.message}`); 
});
```

成功时，调用将记录`Got status: 200`。 如果端点不可用，您将看到类似`Got error: getaddrinfo ENOTFOUND`的内容。

您可能需要测试应用程序处理替代状态代码以及明确错误的能力。 您可能无法强制端点发出这些代码，但是如果发生这种情况，您必须为它们做好准备。 存根在这里非常有用，可以创建合成响应，以便可以全面地测试响应处理程序。

我们可以使用存根来模拟响应，而不实际调用`http.get`方法：

```js
const http = require('http'); 
const sinon = require('sinon'); 

sinon.stub(http, 'get').yields({ 
  statusCode: 404 
}); 

// This URL is never actually called 
http.get("http://www.example.org", res => { 
  console.log(`Got response: ${res.statusCode}`); 
  http.get.restore(); 
})
```

这个存根通过包装原始方法来产生模拟响应，但实际上从未调用原始方法，导致从通常返回状态代码`200`的调用中返回`404`。 重要的是，注意我们在完成后如何`restore`存根方法到其原始状态。

例如，以下*伪*代码描述了一个模块，该模块进行 HTTP 调用，解析响应，并在一切正常时返回`'handled'`，在 HTTP 响应意外时返回`'not handled'`：

```js
const http = require('http'); 
module.exports = function() => { 
  this.makeCall = (url, cb) => { 
    http.get(url, res => { 
      cb(this.parseResponse(res)); 
    }) 
  } 
  this.parseResponse = res => { 
    if(!res.statusCode) { 
      throw new Error('No status code present'); 
    }
    switch(res.statusCode) { 
      case 200: 
        return 'handled'; 
        break; 
      case 404: 
        return 'handled'; 
        break; 
      default: 
        return 'not handled'; break; 
    } 
  } 
}
```

以下的 Mocha 测试确保`Caller.parseReponse`方法可以处理我们需要处理的所有响应代码，使用存根来模拟整个预期的响应范围：

```js
let Caller = require('../scripts/Caller.js'); 
describe('Testing endpoint responses', function() { 
  let caller = new Caller(); 
  function setTestForCode(code) { 
    return done => { 
      sinon.stub(caller, 'makeCall').yields(caller.parseResponse({ 
        statusCode: code 
      })); 
      caller.makeCall('anyURLWillDo', h => { 
        expect(h).to.be.a('string').and.equal('handled'); 
        done(); 
      }); 
    } 
  } 
  afterEach(() => caller.makeCall.restore()); 

  it('Tests 200 handling', setTestForCode(200)); 
  it('Tests 404 handling', setTestForCode(404)); 
  it('Tests 403 handling', setTestForCode(403)); 
});
```

通过代理原始的`makeCall`方法，我们可以测试`parseResponse`对一系列状态代码的处理，而无需强制远程网络行为。 请注意，前面的测试应该失败（没有`403`代码的处理程序），这个测试的输出应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/1cb086b1-72f3-46bb-af64-53c20ddb1fa7.png)

存根的完整 API 可以在以下网址查看：[`sinonjs.org/releases/v4.1.2/stubs/`](http://sinonjs.org/releases/v4.1.2/stubs/)。

# 模拟

模拟（和模拟期望）是具有预编程行为（如存根）和预编程期望的虚假方法（如间谍）。 如果未按预期使用模拟，模拟将使您的测试失败。 模拟可以用来检查被测试单元的正确使用，而不是在事后检查期望，它们强制执行实现细节。

在下面的示例中，我们检查特定函数被调用的次数，以及它是否以特定的预期参数被调用。 具体来说，我们再次使用模拟来测试 Utilities 的`capitalize`方法：

```js
const sinon = require('sinon'); 
let Capitalizer = require('../scripts/Capitalizer.js'); 
let capitalizer = new Capitalizer(); 

let arr = ['a','b','c','d','e']; 
let mock = sinon.mock(capitalizer); 

// Expectations 
mock.expects("capitalize").exactly(5).withArgs.apply(sinon, arr); 
// Reality
arr.map(capitalizer.capitalize);
// Verification
console.log(mock.verify());

// true
```

在`utilities`上设置模拟之后，我们将一个五元素数组映射到`capitalize`，期望`capitalize`被调用五次，数组的元素作为参数（使用`apply`将数组展开为单独的参数）。 然后检查名为`mock.verify`的方法，以查看我们的期望是否得到满足。 和往常一样，在完成后，我们使用`mock.restore`取消包装 utilities 对象。 您应该在终端中看到 true 被记录。

现在，从被测试的数组中删除一个元素，使期望受挫。当您再次运行测试时，您应该在输出的顶部附近看到以下内容：

```js
ExpectationError: Expected capitalize([...]) 5 times (called 4 times)
```

这应该澄清模拟旨在产生的测试结果类型。

请注意，模拟的函数不会执行；`mock`会覆盖其目标。在前面的示例中，没有任何数组成员会通过`capitalize`运行。

让我们重新审视我们之前使用模拟测试 Redis `pub/sub`的示例：

```js
const redis = require("redis"); 
const client = redis.createClient(); 

describe('Mocking pub/sub', function() { 
  let mock = sinon.mock(client); 
  mock.expects('subscribe').withExactArgs('channel').once(); 
  it('tests that #subscribe is being called correctly', function() { 
    client.subscribe('channel'); 
    expect(mock.verify()).to.be.true; 
  }); 
});
```

与其检查结论，我们在这里断言我们的期望，即模拟的`subscribe`方法将仅接收一次确切的参数通道。Mocha 期望`mock.verify`返回`true`。要使此测试失败，添加一行`client.subscribe('channel')`，产生类似以下的内容：

```js
ExpectationError: Unexpected call: subscribe(channel)
```

有关如何使用模拟的更多信息，请访问：[`sinonjs.org/releases/v4.1.2/mocks/`](http://sinonjs.org/releases/v4.1.2/mocks/)。

# 使用 Nightmare 和 Puppeteer 进行无头测试

测试 UI 是否有效的一种方法是支付几个人通过浏览器与网站进行交互，并报告他们发现的任何错误。这可能会变得非常昂贵，最终也不可靠。此外，这需要将潜在失败的代码投入生产以进行测试。最好在发布任何内容“到野外”之前，测试浏览器视图是否在测试过程本身中正确呈现。

一个被剥夺了按钮和其他控件的浏览器，本质上是一个验证和运行 JavaScript、HTML 和 CSS，并创建视图的程序。验证的 HTML 在您的屏幕上呈现出来只是人类只能用眼睛看到的结果。机器可以解释编译代码的逻辑，并查看与该代码的交互结果，而无需视觉组件。也许是因为眼睛通常在头部，由服务器上的机器运行的浏览器通常被称为无头浏览器。

我们将看一下两个无头浏览器测试自动化库：**Nightmare** ([`github.com/segmentio/nightmare`](https://github.com/segmentio/nightmare)) 和 **Puppeteer** ([`github.com/GoogleChrome/puppeteer`](https://github.com/GoogleChrome/puppeteer))。Nightmare 使用**Electron**作为其浏览器环境，而 Puppeteer 使用无头**Chromium**。它们都为您提供了一个可编写脚本的环境，围绕浏览器上下文，使您能够对该*页面*进行各种操作，例如抓取屏幕截图，填写并提交表单，或者根据 CSS 选择器从页面中提取一些内容。与我们之前的工作保持一致，我们还将学习如何使用 Mocha 和 Chai 来利用这些无头浏览器测试。

让我们熟悉这两个工具，然后看看它们如何集成到您的测试环境中。

# Nightmare

Nightmare 为处理 Web 内容提供了一个非常富有表现力的 API。让我们立即使用一个示例 Mocha 测试来验证网页的文档标题：

```js
const Nightmare = require('nightmare');

describe(`Nightmare`, function() {
  let nightmare;

  beforeEach(() => nightmare = Nightmare({
    show: false
  }));

  afterEach(function(done) {
    nightmare.end(done);
  });

  it(`Title should be 'Example Domain'`, function(done) {
    nightmare
    .goto('http://example.org')
    .title()
    .then(title => expect(title).to.equal(`Example Domain`))
    .then(() => done())
    .catch(done);
  });
});
```

在这里，我们使用 Mocha 的`beforeEach`和`afterEach`来预期许多测试块，为每个测试创建一个新的 Nightmare 实例，并通过`nightmare.end`自动清理这些实例。您不一定要这样做，但这是一个有用的*样板*。Nightmare 接受一个反映 Electron 的**BrowserWindow**选项的配置对象 ([`github.com/electron/electron/blob/master/docs/api/browser-window.md#new-browserwindowoptions`](https://github.com/electron/electron/blob/master/docs/api/browser-window.md#new-browserwindowoptions))，在这里，我们使用`show`属性，使渲染实例可见——视图*弹出*在您的屏幕上，以便您可以观看页面的操作。特别是在进行导航和 UI 交互的测试中，看到这些操作是很有用的。在这里和接下来的测试中尝试一下。

这个测试很容易阅读。在这里，我们简单地前往一个 URL，获取该页面的标题，并进行断言以测试我们是否有正确的标题。请注意，Nightmare 被设计为与 Promises 原生地配合工作，你看到的`Promise`链是基于 Node 原生的 Promises 构建的。如果你想使用另一个`Promise`库，你可以这样做：

```js
const bbNightmare = Nightmare({
  Promise: require('bluebird')
});

bbNightmare.goto(...)
```

与页面交互是无头浏览器测试的必不可少的部分，让你编写自动运行的 UI 测试。例如，你可能想测试你的应用程序的登录页面，或者当提交时搜索输入返回正确的结果和正确的顺序。让我们向这个套件添加另一个测试，一个在 Yahoo 上搜索 Nightmare 主页并查询链接文本的测试：

```js
it('Yahoo search should find Nightmare homepage', done => {
    nightmare
    .goto('http://www.yahoo.com')
    .type('form[action*="/search"] [name=p]', 'nightmare.js')
    .click('form[action*="/search"] [type=submit]')
    .wait('#main')
    .evaluate(() => document.querySelector('#main .searchCenterMiddle a').href)
    .then(result => expect(result).to.equal(`http://www.nightmarejs.org/`))
    .then(() => done())
    .catch(done);
})
```

你可以看到这是如何工作的。使用 CSS 选择器在 Yahoo 的首页上找到搜索框，输入`'nightmare.js'`并点击提交按钮提交表单。等待一个新的元素`#main`出现，表示结果页面已经被渲染。然后我们创建一个`evaluate`块，它将在浏览器范围内执行。这是一个进行自定义 DOM 选择和操作的好地方。在这里，我们找到第一个链接，并检查它是否是我们期望的链接。这个简单的模式可以很容易地修改为点击你网站上的链接以确保链接正常工作，或者在结果页面上运行几个选择器以确保正确的结果被传递。

在你的测试中，你可能会发现重复的模式。想象一下，从选择器定位的链接中提取文本是你测试中的常见模式。Nightmare 允许你将这些转化为自定义操作。让我们在 Nightmare 上创建一个自定义的`getLinkText`操作，并在我们的测试中使用它。首先，在实例化 Nightmare 之前，定义一个新的`action`：

```js
Nightmare.action('getLinkText', function(selector, done) {
    // `this` is the nightmare instance
    this.evaluate_now(selector => {
        return document.querySelector(selector).href;
    }, done, selector)
});
```

现在，用我们自定义操作的调用替换原始的 evaluate 指令：

```js
...
.wait('#main')
.getLinkText('#main .searchCenterMiddle a') // Call action
...
```

我们只是将我们的原始指令转换为一个操作块，使用自定义的名称和函数签名，并从我们的测试链中调用它。虽然这个例子是人为的，但很容易想象更复杂的操作，甚至是你的工程师可能会利用的操作库，作为一种测试的*编程语言*。请注意，在操作中使用`evaluate_now`而不是`evaluate`。Nightmare 将排队`evaluate`指令，而我们的操作已经被排队（作为原始测试链的一部分），我们希望立即在我们的操作中评估该命令，而不是重新排队。

有关 Nightmare 的更多信息，请访问：[`github.com/segmentio/nightmare#api`](https://github.com/segmentio/nightmare#api)。

# Puppeteer

Puppeteer 是一个全新的 Google 项目，专注于使用 Chromium 引擎创建浏览器测试 API。该团队正在积极地针对最新的 Node 版本，利用 Chromium 引擎的所有最新功能（访问：[`github.com/GoogleChrome/puppeteer/issues/316`](https://github.com/GoogleChrome/puppeteer/issues/316)）。特别是，它旨在鼓励在编写测试时使用 async/await 模式。

以下是之前使用 Puppeteer 编写的文档标题示例：

```js
it(`Title should be 'Example Domain'`, async function() {
    let browser = await puppeteer.launch({
        headless: true
    });

    let page = await browser.newPage();
    await page.goto(`http://example.org`);
    let title = await page.title();
    await browser.close();

    expect(title).to.equal(`Example Domain`);
});
```

请注意`async`函数包装器。这种模式非常紧凑，考虑到测试经常必须在浏览器上下文中跳进跳出，`async`/`await`在这里感觉很合适。我们还可以看到 Puppeteer API 受到 Nightmare API 的影响。与 Nightmare 一样，Puppeteer 接受一个配置对象：[`github.com/GoogleChrome/puppeteer/blob/master/docs/api.md#puppeteerlaunchoptions`](https://github.com/GoogleChrome/puppeteer/blob/master/docs/api.md#puppeteerlaunchoptions)。Nightmare 的`show`的等价物是`headless`，它将 Chrome 置于无头模式。重写前面的 Nightmare 雅虎搜索示例为 Puppeteer 可能是一个很好的练习。完整的文档可在此处找到：[`github.com/GoogleChrome/puppeteer/blob/master/docs/api.md`](https://github.com/GoogleChrome/puppeteer/blob/master/docs/api.md)。

以下是一个使用 Puppeteer 读取 NYTimes、拦截图像渲染调用并取消它们，然后对无图像页面进行截图并将其写入本地文件系统的 Mocha 测试：

```js
it(`Should create an imageless screenshot`, async function() {

    let savePath = './news.png';
    const browser = await puppeteer.launch({
        headless: true
    });

    const page = await browser.newPage();
    await page.setRequestInterception(true);
    page.on('request', request => {
        if (request.resourceType === 'image') {
            request.abort();
        }
        else {
            request.continue();
        }
    });
    await page.goto('http://www.nytimes.com');
    await page.screenshot({
        path: savePath,
        fullPage: true
    });
    await browser.close();

    expect(fs.existsSync(savePath)).to.equal(true);
});
```

要创建 PDF，您只需用以下内容替换`screenshot`部分：

```js
savePath = './news.pdf';
await page.pdf({path: savePath});
```

开发人员经常构建测试套件，以在各种移动设备尺寸上对同一页面进行截图，甚至进行视觉差异检查，以检查您的网站是否在所有情况下都正确渲染（例如，[`github.com/mapbox/pixelmatch`](https://github.com/mapbox/pixelmatch)）。您甚至可以创建一个服务，选择几个 URL 的片段并将它们组合成一个单独的 PDF 报告。

Navalia 是另一个具有有趣的使用无头 Chrome API 进行测试的新框架；您可以在此处找到它：[`github.com/joelgriffith/navalia`](https://github.com/joelgriffith/navalia)。

现在，您应该有足够的信息来开始为您的应用程序实施 UI 测试。一些超现代的应用程序甚至涉及在 AWS Lambda 上运行 Chromium（参见第九章，*微服务*），让您*外包*您的测试工作。Nightmare 和 Puppeteer 都是现代化、维护良好、有文档的项目，非常适合 Node 测试生态系统。

现在，让我们深入了解一下当 Node 进程运行时*幕后发生了什么*，以及在测试和调试时如何更加精确。

# 测试地形

测试 Node 也可能需要更科学、更实验性的努力。例如，内存泄漏是臭名昭著的难以追踪的 bug。您将需要强大的进程分析工具来取样、测试场景，并了解问题的根源。如果您正在设计一个必须处理大量数据的日志分析和总结工具，您可能需要测试各种解析算法并排名它们的 CPU/内存使用情况。无论是测试现有的流程还是作为软件工程师，收集资源使用信息都很重要。本节将讨论如何对运行中的进程进行数据快照，并如何从中提取有用的信息。

Node 已经本地提供了一些进程信息。基本跟踪 Node 进程使用了多少内存很容易通过`process.memoryUsage()`获取：

```js
{
  rss: 23744512,
  heapTotal: 7708672,
  heapUsed: 5011728,
  external: 12021 
}
```

你可以编写脚本来监视这些数字，也许在内存分配超过某个预定阈值时发出警告。有许多公司提供这样的监控服务，比如**Keymetrics**（[`keymetrics.io`](https://keymetrics.io)），他们是 PM2 的制造商和维护者。还有像**node-report**（[`github.com/nodejs/node-report`](https://github.com/nodejs/node-report)）这样的模块，它提供了一个很好的方式，在进程崩溃、系统信号或其他原因终止时生成系统报告。伟大的模块**memeye**（[`github.com/JerryC8080/Memeye`](https://github.com/JerryC8080/Memeye)）使得创建显示这种系统数据的基于浏览器的仪表板变得容易。

Node 进程有几个原生信息源。请访问文档：[`nodejs.org/api/process.html`](https://nodejs.org/api/process.html)。

让我们首先学习如何收集更广泛的内存使用统计信息，对运行中的进程进行分析，收集关键的 V8 性能数据概要等等。

# 测试进程、内存和 CPU

Node 有原生工具，可以让你对运行中的 V8 进程进行分析。这些是带有摘要的快照，捕获了 V8 在编译进程时对待进程的统计信息，以及在有选择地优化*热*代码时所做的操作和决策的类型。当尝试追踪例如一个函数运行缓慢的原因时，这是一个强大的调试技术。

任何 Node 进程都可以通过简单地传递`--prof`（用于 profile 的标志）来生成 V8 日志。让我们用一个例子来看 V8 进程分析是如何工作的。阅读大型日志文件是 Node 开发人员将遇到的一个相当复杂且常见的任务。让我们创建一个日志读取器并检查其性能。

# 进程分析

在你的代码包中，本章的`/profiling`目录下将有一个`logreader.js`文件。这只是读取代码包中也有的`dummy.log`文件。这是一个如何使用`stream.Transform`处理大型文件的很好的例子：

```js
const fs = require('fs');
const stream = require('stream');
let lineReader = new stream.Transform({ 
   objectMode: true 
});

lineReader._transform = function $transform(chunk, encoding, done) {
   let data = chunk.toString();
   if(this._lastLine) {
      data = this._lastLine + data;
   }
   let lines = data.split('\n');
   this._lastLine = lines.pop();
   lines.forEach(line => this.push(line));
   done();
};

lineReader._flush = function $flush(done) {
     if(this._lastLine) {
       this.push(this._lastLine);
     }
     this._lastLine = null;
     done();
};

lineReader.on('readable', function $reader() {
   let line;
   while(line = this.read()) {
      console.log(line);
   }
});

fs.createReadStream('./dummy.log').pipe(lineReader);
```

需要注意的重要事情是，主要函数已经被命名，并以$为前缀。这通常是一个很好的做法——你应该总是给你的函数命名，原因特别与调试相关。我们希望这些名称出现在我们即将生成的报告中。

要生成一个 v8 日志，可以使用`--prof`参数运行此脚本：

```js
node --prof logreader.js
```

现在你应该在当前工作目录中看到一个名为`isolate-0x103000000-v8.log`的 V8 日志文件。继续看一下它——日志有点令人生畏，但如果你搜索一下，比如`$reader`，你会发现 V8 是如何记录它对调用堆栈和编译工作的结构的实例。不过，这显然不是为人类阅读而设计的。

通过对该日志运行以下命令，可以创建这个 profile 的一个更有用的摘要：

```js
node --prof-process isolate-0x103000000-v8.log > profile
```

几秒钟后，进程将完成，目录中将存在一个新文件，名为 profile。继续打开它。里面有很多信息，深入研究所有含义远远超出了本章的范围。尽管如此，你应该能看到摘要清晰地总结了关键的 V8 活动，用 ticks 来衡量（还记得我们在第二章中关于事件循环的讨论吗，*理解异步事件驱动编程*？）。例如，考虑这一行：

```js
8   50.0%    LazyCompile: *$reader /../profiling/logreader.js:26:43
```

在这里，我们可以看到`$reader`消耗了 8 个 ticks，进行了懒编译，并且被优化了（*）。如果它没有被优化，它将被标记为波浪线（~）。如果你发现一个未优化的文件消耗了大量的 ticks，你可能会尝试以最佳方式重写它。这可以是解决应用程序堆栈中较慢部分的强大方式。

# 堆转储

正如我们之前学到的，堆本质上是对内存的大量分配，在这种特定情况下，它是分配给 V8 进程的内存。通过检查内存的使用情况，你可以追踪内存泄漏等问题，或者简单地找出内存使用最多的地方，并根据需要对代码进行调整。

用于获取堆转储的事实模块是`heapdump`（[`github.com/bnoordhuis/node-heapdump`](https://github.com/bnoordhuis/node-heapdump)），由自项目开始以来一直是核心 Node 开发者的*Ben Noordhuis*创建。

继续安装该模块并创建一个包含以下代码的新文件：

```js
// heapdumper.js
const path = require('path');
const heapdump = require('heapdump');

heapdump.writeSnapshot(path.join(__dirname, `${Date.now()}.heapsnapshot`));
```

运行该文件。你会发现生成了一个名为`1512180093208.heapsnapshot`的文件。这不是一个可读的文件，但它包含了重建堆使用情况视图所需的一切。你只需要正确的可视化软件。幸运的是，你可以使用 Chrome 浏览器来做到这一点。

打开 Chrome DevTools。转到内存选项卡。你会看到一个选项来加载堆转储：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/249e4621-461b-4d75-929b-8aab7bb4b670.png)

加载刚刚创建的文件（注意，它**必须**有`.heapsnapshot`扩展名）。加载后，点击堆图标，你会看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/c58b06f1-e7a0-4dd4-a6b4-ff0cf3fe1a3a.png)

点击 Summary 以激活下拉菜单，并选择 Statistics。现在你会看到类似以下的图表：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/4b9a689f-4679-430d-a0a2-1e14c0eb66e5.png)

熟悉如何读取堆转储是对任何 Node 开发者有用的技能。要了解内存分配的好介绍，请尝试：[`developer.chrome.com/devtools/docs/memory-analysis-101`](https://developer.chrome.com/devtools/docs/memory-analysis-101)。运行 Chrome DevTools UI 的源代码是开放和免费的，[`github.com/ChromeDevTools/devtools-frontend`](https://github.com/ChromeDevTools/devtools-frontend)，协议本身也是如此。想想你可能如何定期对运行中的进程进行堆转储，并使用 DevTools 测试系统健康状况，无论是我们演示的方式还是通过自定义构建。

虽然我们在演示中使用 Chrome，其他工具也可以*连接到*这个协议。查看[`nodejs.org/en/docs/inspector/`](https://nodejs.org/en/docs/inspector/)和[`github.com/ChromeDevTools/awesome-chrome-devtools#chrome-devtools-protocol`](https://github.com/ChromeDevTools/awesome-chrome-devtools#chrome-devtools-protocol)。

Chrome DevTools 有更多对开发者有用的功能。现在让我们来看看这些功能。

# 将 Node 连接到 Chrome DevTools

Chrome 调试协议最近与 Node 核心*集成*（[`github.com/nodejs/node/pull/6792`](https://github.com/nodejs/node/pull/6792)），这意味着现在可以使用 Chrome DevTools（和其他工具）调试运行中的 Node 进程。这不仅包括观察内存分配，还包括收集 CPU 使用情况的实时反馈，以及直接调试您的活动代码——例如添加断点和检查当前变量值。这是专业 Node 开发者的重要调试和测试工具。让我们深入了解一下。

为了演示目的，我们将创建一个执行一些重要工作的快速服务器：

```js
// server.js
const Express = require('express');
let app = Express();

function $alloc() {
    Buffer.alloc(1e6, 'Z');
}

app.get('/', function $serverHandler(req, res) => {

    let d = 100;
    while(d--){ $alloc() }

    res.status(200).send(`I'm done`);
})

app.listen(8080);
```

注意`$alloc`和`$serverHandler`的命名函数；这些函数名将用于跟踪我们的进程。现在，我们将启动该服务器，但使用一个特殊的`--inspect`标志指示 Node 我们计划检查（调试）该进程：

```js
node --inspect server.js
```

你应该看到类似以下的显示：

```js
Debugger listening on ws://127.0.0.1:9229/bc4d2b60-0d01-4a66-ad49-2e990fa42f4e
For help see https://nodejs.org/en/docs/inspector
```

看起来调试器是激活的。要查看它，打开 Chrome 浏览器并输入以下内容：

```js
chrome://inspect
```

你应该看到你启动的进程被列出。你可以检查该进程，或者通过点击 Open dedicated DevTools for Node 加载一个活动的调试屏幕，从现在开始，它将附加到你使用`--inspect`启动的任何 Node 进程。

# CPU 分析

在另一个浏览器窗口中打开并导航到我们的测试服务器`localhost:8080`。您应该会看到显示“我完成了”（如果没有，请返回并启动`server.js`，如之前所述）。保持打开；您将很快重新加载此页面。

在调试器 UI 中点击“Memory”，您会看到之前的界面。这是我们之前看到的调试器的*独立*版本。

现在，点击“Profiler”，这是调试 CPU 行为（特别是执行时间）的界面，然后点击“开始”。返回到浏览器并重新加载“我完成了”页面几次。返回调试器并点击“停止”。您应该会看到类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/e807cf50-37d7-4bb0-83fe-98b03f61c73e.png)

请注意三个较大的*块*，这些块是由我们的服务器处理程序的三次运行生成的。使用鼠标，选择其中一个块并放大：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/95871298-4bd1-4a04-a930-08badabaf7f6.png)

在这里，我们看到了处理我们请求时 V8 活动的全面分解。还记得`$alloc`吗？通过将鼠标悬停在其时间轴上，您可以检查它消耗的总 CPU 时间。如果我们放大到右下角的 send 部分，我们还可以看到我们的服务器执行 HTTP 响应花费了 1.9 毫秒： 

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/a1cc07bd-0a5d-4761-b1bb-dac482f2f154.png)

玩弄一下这个界面。除了帮助您找到和调试应用程序中较慢的部分之外，在开发测试时，您还可以使用此工具来创建对*正常*运行预期行为的心理地图，并设计健康测试。例如，您的一个测试可能会调用特定的路由处理程序，并根据一些预定的最大执行时间阈值来判断成功或失败。如果这些测试*总是开启*，定期探测您的实时应用程序，它们甚至可能触发自动限流行为、日志条目或向工程团队发送紧急电子邮件。

# 实时调试

也许，这个界面最强大的功能是它能够直接调试运行中的代码，并测试实时应用程序的状态。在调试器中点击“Sources”。这是实际*脚本*组成 Node 进程的界面。您应该会看到我们的`server.js`文件的*挂载*版本：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/04271b8b-7ec7-4c54-9066-777b61b9e09f.png)

有趣的事实：在这里，您可以看到 Node 如何实际包装您的模块，以便全局`exports`，`require`，`module`，`__filename`和`__dirname`变量对您可用。

让我们在第 11 行设置一个断点。只需点击数字；您应该会看到这个：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/6d1e61e6-7b08-4c4d-8a76-41ccb91d82b6.png)

还记得我们之前关于 Node 调试器的讨论吗？同样的原则也适用于这里；我们将能够使用这个界面来逐步执行代码，定期停止执行，并检查应用程序状态。

为了演示，让我们导致这段代码在我们的服务器上执行。返回到您的浏览器并重新加载`localhost:8080`，调用路由并最终触发您刚刚设置的断点。调试器界面应该会弹出，并且看起来会像这样：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/ms-node/img/b86f93b5-59e6-4931-9dca-859e587007b5.png)

除了清楚地指示我们所在的位置（在`$serverHandler`函数内的行号），界面还有用地显示了`while`循环的当前迭代中`d`的值。还记得我们之前关于 Node 调试器的讨论吗？同样的原则也适用于这里。如果您将鼠标悬停在右侧的调试控件图标上，您会看到第二个是*步进*功能。我们在一个循环中；让我们步进到下一个迭代。继续点击步进几次。您是否注意到在您通过这个循环时`d`的值是如何更新的？

如果您探索右侧的界面，您可以深入了解程序的当前状态，全面分解所有作用域变量、全局引用等。通过使用*step into*控制，您可以观察每个请求通过执行堆栈的进展，跟踪 Node 运行时的执行过程。您将受益于这个练习，并更清楚地了解您的代码（以及 Node 的工作原理）。这将帮助您成为更好的测试编写者。

有一个 Chrome 插件，使与检查的 Node 进程交互变得简单，只需点一下鼠标即可；它可以在以下链接找到：[`chrome.google.com/webstore/detail/nodejs-v8-inspector-manag/gnhhdgbaldcilmgcpfddgdbkhjohddkj`](https://chrome.google.com/webstore/detail/nodejs-v8-inspector-manag/gnhhdgbaldcilmgcpfddgdbkhjohddkj)。

*Mathias Buus*创建了一个有趣的工具，为那些罕见但令人抓狂的进程不在预期结束时提供了非常有用的调试信息，您可以在以下链接找到它：[`github.com/mafintosh/why-is-node-running`](https://github.com/mafintosh/why-is-node-running)。

*Matteo Collina*的出色的`loopbench` ([`github.com/mcollina/loopbench`](https://github.com/mcollina/loopbench)) 及其针对 Node 服务器的打包版本 ([`github.com/davidmarkclements/overload-protection`](https://github.com/davidmarkclements/overload-protection)) 不仅可用于提供测试和调试信息，还可用于开发智能、自我调节的服务器，当运行过热时会自动卸载（或重定向）负载，这是独立、联网节点的分布式应用架构中的一个很好的特性。

# 摘要

Node 社区从一开始就支持测试，并为开发人员提供了许多测试框架和本地工具。在本章中，我们探讨了为什么测试对现代软件开发如此重要，以及有关功能、单元和集成测试的一些内容，它们是什么，以及如何使用它们。通过 vm 模块，我们学习了如何为测试 JavaScript 程序创建特殊的上下文，并在此过程中掌握了一些用于沙盒化不受信任代码的技巧。

此外，我们学习了如何使用丰富的 Node 测试和错误处理工具，从更具表现力的控制台日志记录到 Mocha 和 Sinon 的模拟，再到一行追踪和调试堆和实时代码。最后，我们学习了两种不同的无头浏览器测试库，学习了每种测试可能的两种方式，以及这些虚拟浏览器如何与其他测试环境集成。

现在您可以测试您的代码，去尝试 Node 的强大功能。
