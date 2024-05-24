# Docker Windows 教程（二）

> 原文：[`zh.annas-archive.org/md5/51C8B846C280D9811810C638FA10FD64`](https://zh.annas-archive.org/md5/51C8B846C280D9811810C638FA10FD64)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第二部分：设计和构建容器化解决方案

Docker 让您以新的方式设计和构建应用程序。在本节中，您将学习如何使用容器来思考应用程序架构，以及如何使用 Docker 来运行分布式应用程序。

本节包括以下章节：

+   第五章，采用容器优先解决方案设计

+   第六章，使用 Docker Compose 组织分布式解决方案

+   第七章，使用 Docker Swarm 编排分布式解决方案


# 第五章：采用容器优先解决方案设计

将 Docker 作为应用程序平台带来明显的运营优势。容器比虚拟机更轻，但仍提供隔离，因此您可以在更少的硬件上运行更多的工作负载。所有这些工作负载在 Docker 中具有相同的形状，因此运维团队可以以相同的方式管理.NET、Java、Go 和 Node.js 应用程序。Docker 平台在应用程序架构方面也有好处。在本章中，我将探讨容器优先解决方案设计如何帮助您向应用程序添加功能，具有高质量和低风险。

在本章中，我将回到 NerdDinner，从我在第三章中离开的地方继续。NerdDinner 是一个传统的.NET 应用程序，是一个单片设计，组件之间耦合紧密，所有通信都是同步的。没有单元测试、集成测试或端到端测试。NerdDinner 就像其他数百万个.NET 应用程序一样——它可能具有用户需要的功能，但修改起来困难且危险。将这样的应用程序移至 Docker 可以让您采取不同的方法来修改或添加功能。

Docker 平台的两个方面将改变您对解决方案设计的思考方式。首先，网络、服务发现和负载平衡意味着您可以将应用程序分布到多个组件中，每个组件都在容器中运行，可以独立移动、扩展和升级。其次，Docker Hub 和其他注册表上可用的生产级软件范围不断扩大，这意味着您可以为许多通用服务使用现成的软件，并以与自己的组件相同的方式管理它们。这使您有自由设计更好的解决方案，而不受基础设施或技术限制。

在本章中，我将向您展示如何通过采用容器优先设计来现代化传统的.NET 应用程序：

+   NerdDinner 的设计目标

+   在 Docker 中运行消息队列

+   开始多容器解决方案

+   现代化遗留应用程序

+   在容器中添加新功能

+   从单体到分布式解决方案

# 技术要求

要跟着示例进行操作，您需要在 Windows 10 上运行 Docker，并更新到 18.09 版，或者在 Windows Server 2019 上运行。本章的代码可在[`github.com/sixeyed/docker-on-windows/tree/second-edition/ch05`](https://github.com/sixeyed/docker-on-windows/tree/second-edition/ch05)上找到。

# NerdDinner 的设计目标

在第三章中，*开发 Docker 化的.NET Framework 和.NET Core 应用程序*，我将 NerdDinner 首页提取到一个单独的组件中，这样可以快速交付 UI 更改。现在我要做一些更根本的改变，分解传统的应用程序并现代化架构。

我将首先查看 Web 应用程序中的性能问题。NerdDinner 中的数据层使用**Entity Framework**（**EF**），所有数据库访问都是同步的。网站的大量流量将创建大量打开的连接到 SQL Server 并运行大量查询。随着负载的增加，性能将恶化，直到查询超时或连接池被耗尽，网站将向用户显示错误。

改进的一种方式是使所有数据访问方法都是`async`，但这是一种侵入性的改变——所有控制器操作也需要变成`async`，而且没有自动化的测试套件来验证这样一系列的改变。另外，我可以添加一个用于数据检索的缓存，这样`GET`请求将命中缓存而不是数据库。这也是一个复杂的改变，我需要让缓存数据保持足够长的时间，以便缓存命中的可能性较大，同时在数据更改时保持缓存同步。同样，缺乏测试意味着这样的复杂改变很难验证，因此这也是一种风险的方法。

如果我实施这些复杂的改变，很难估计好处。如果所有数据访问都转移到异步方法，这会使网站运行更快，并使其能够处理更多的流量吗？如果我可以集成一个高效的缓存，使读取数据从数据库中移开，这会提高整体性能吗？这些好处很难量化，直到你实际进行了改变，当你可能会发现改进并不能证明投资的价值。

采用以容器为先的方法，可以以不同的方式来看待设计。如果您确定了一个功能，它会进行昂贵的数据库调用，但不需要同步运行，您可以将数据库代码移动到一个单独的组件中。然后，您可以在组件之间使用异步消息传递，从主 Web 应用程序发布事件到消息队列，并在新组件中对事件消息进行操作。使用 Docker，这些组件中的每一个都将在一个或多个容器中运行：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/ddfe4194-1d38-4f65-b62d-874a61c97120.png)

如果我只专注于一个功能，那么我可以快速实现变化。这种设计没有其他方法的缺点，并且有许多好处：

+   这是一个有针对性的变化，只有一个控制器动作在主应用程序中发生了变化

+   新的消息处理程序组件小而高度内聚，因此很容易进行测试

+   Web 层和数据层是解耦的，因此它们可以独立扩展

+   我正在将工作从 Web 应用程序中移出，这样我们就可以确保性能得到改善

还有其他优点。新组件完全独立于原始应用程序；它只需要监听事件消息并对其进行操作。您可以使用.NET、.NET Core 或任何其他技术堆栈来处理消息；您不需要受限于单一堆栈。您还可以通过添加监听这些事件的新处理程序，以后添加其他功能。

# Docker 化 NerdDinner 的配置

NerdDinner 使用`Web.config`进行配置 - 既用于应用程序配置值（在发布之间保持不变）又用于在不同环境之间变化的环境配置值。配置文件被嵌入到发布包中，这使得更改变得尴尬。在第三章中，*开发 Docker 化的.NET Framework 和.NET Core 应用程序*，我将`Web.config`中的`appSettings`和`connectionStrings`部分拆分成单独的文件；这样做可以让我运行一个包含不同配置文件的容器，通过附加包含不同配置文件的卷。

不过，有不同类型的配置，而挂载卷对开发人员来说是一个相当沉重的选项。对于您希望在不更改代码的情况下切换的功能设置来说是很好的——像`UnobtrusiveJavaScriptEnabled`这样的设置应该放在配置文件中。但是对于每个环境和每个开发人员都会更改的设置——比如`BingMapsKey`——应该有一种更简单的设置方式。

理想情况下，您希望有多层配置，可以从文件中读取，但也可以使用环境变量覆盖值。这就是.NET Core 中配置系统的工作方式，因为.NET Core 中的配置包实际上是.NET Standard 库，它们也可以用于经典的.NET Framework 项目。

为了迎接即将到来的更大变化，我已经更新了本章的代码，使用.NET Core 配置模型来设置所有环境配置，如下所示。之前的文件`appSettings.config`和`connectionStrings.config`已经迁移到新的 JSON 配置样式`appsettings.json`中：

```
{
  "Homepage": {
    "Url": "http://nerd-dinner-hompage"
  },
  "ConnectionStrings": {
    "UsersContext": "Data Source=nerd-dinner-db...",
    "NerdDinnerContext": "Data Source=nerd-dinner-db..."
  },
  "Apis": {    
    "IpInfoDb": {
      "Key": ""
    },
    "BingMaps": {
      "Key": ""
    }      
  }
}
```

JSON 格式更易于阅读，因为它包含嵌套对象，您可以将类似的设置分组在一起，我已经在`Apis`对象中这样做了。我可以通过访问当前配置对象的`Apis:BingMaps:Key`键在我的代码中获取 Bing Maps API 密钥。我仍然将配置文件存储在一个单独的目录中，所以我可以使用卷来覆盖整个文件，但我也设置了配置来使用环境变量。这意味着如果设置了一个名为`Apis:BingMaps:Key`的环境变量，那么该变量的值将覆盖 JSON 文件中的值。在我的代码中，我只需引用配置键，而在运行时，.NET Core 会从环境变量或配置文件中获取它。

这种方法让我可以在 JSON 文件中为数据库连接字符串使用默认值，这样当开发人员启动数据库和 Web 容器时，应用程序就可以使用，而无需指定任何环境变量。不过，该应用程序并非 100%功能完善，因为 Bing Maps 和 IP 地理位置服务需要 API 密钥。这些是有速率限制的服务，因此您可能需要为每个开发人员和每个环境设置不同的密钥，这可以在 Web 容器中使用环境变量来设置。

为了使环境值更安全，Docker 允许您从文件中加载它们，而不是在`docker container run`命令中以纯文本指定它们。将值隔离在文件中意味着文件本身可以被保护，只有管理员和 Docker 服务帐户才能访问它。环境文件是一个简单的文本格式，每个环境变量写成键值对的一行。对于 web 容器，我的环境文件包含了秘密 API 密钥：

```
Apis:BingMaps:Key=[your-key-here]
Apis:IpInfoDb:Key=[your-key-here]
```

要运行容器并将文件内容加载为环境变量，您可以使用`--env-file`选项。

环境值仍然不安全。如果有人获得了对您的应用程序的访问权限，他们可以打印出所有的环境变量并获取您的 API 密钥。我正在使用 JSON 文件以及环境变量的方法意味着我可以在生产中使用相同的应用程序镜像，使用 Docker secrets 进行配置 - 这是安全的。

我已经将这些更改打包到了 NerdDinner Docker 镜像的新版本中，您可以在`dockeronwindows/ch05-nerd-dinner-web:2e`找到。与第三章中的其他示例一样，《开发 Docker 化的.NET Framework 和.NET Core 应用程序》，Dockerfile 使用引导脚本作为入口点，将环境变量提升到机器级别，以便 ASP.NET 应用程序可以读取它们。

NerdDinner 网站的新版本在 Docker 中运行的命令是：

```
docker container run -d -P `
 --name nerd-dinner-web `
 --env-file api-keys.env `
 dockeronwindows/ch05-nerd-dinner-web:2e
```

应用程序需要其他组件才能正确启动。我有一个 PowerShell 脚本，它以正确的顺序和选项启动容器，但到本章结束时，这个脚本将变得笨拙。在下一章中，当我研究 Docker Compose 时，我会解决这个问题。

# 拆分创建晚餐功能

在`DinnerController`类中，`Create`操作是一个相对昂贵的数据库操作，不需要是同步的。这个特性很适合拆分成一个单独的组件。我可以从 web 应用程序发布消息，而不是在用户等待时将其保存到数据库中 - 如果网站负载很高，消息可能会在队列中等待几秒甚至几分钟才能被处理，但对用户的响应几乎是即时的。

有两件工作需要做，将该功能拆分为一个新组件。Web 应用程序需要在创建晚餐时向队列发布消息，消息处理程序需要在队列上监听并在接收到消息时保存晚餐。在 NerdDinner 中，还有更多的工作要做，因为现有的代码库既是物理单体，也是逻辑单体——只有一个包含所有内容的 Visual Studio 项目，所有的模型定义以及 UI 代码。

在本章的源代码中，我添加了一个名为`NerdDinner.Model`的新的.NET 程序集项目到解决方案中，并将 EF 类移动到该项目中，以便它们可以在 Web 应用程序和消息处理程序之间共享。模型项目针对完整的.NET Framework 而不是.NET Core，所以我可以直接使用现有的代码，而不需要为了这个功能更改而引入 EF 的升级。这个选择也限制了消息处理程序也必须是一个完整的.NET Framework 应用程序。

还有一个共享的程序集项目来隔离`NerdDinner.Messaging`中的消息队列代码。我将使用 NATS 消息系统，这是一个高性能的开源消息队列。NuGet 上有一个针对.NET Standard 的 NATS 客户端包，所以它可以在.NET Framework 和.NET Core 中使用，我的消息项目也有相同的客户端包。这意味着我可以灵活地编写不使用 EF 模型的其他消息处理程序，可以使用.NET Core。

在模型项目中，`Dinner`类的原始定义被大量的 EF 和 MVC 代码污染，以捕获验证和存储行为，比如`Description`属性的以下定义：

```
[Required(ErrorMessage = "Description is required")]
[StringLength(256, ErrorMessage = "Description may not be longer than 256 characters")]
[DataType(DataType.MultilineText)]
public string Description { get; set; }
```

这个类应该是一个简单的 POCO 定义，但是这些属性意味着模型定义不具有可移植性，因为任何消费者也需要引用 EF 和 MVC。为了避免这种情况，在消息项目中，我定义了一个简单的`Dinner`实体，没有任何这些属性，这个类是我用来在消息中发送晚餐信息的。我可以使用`AutoMapper` NuGet 包在`Dinner`类定义之间进行转换，因为属性基本上是相同的。

这是你会在许多旧项目中找到的挑战类型 - 没有明确的关注点分离，因此分解功能并不简单。您可以采取这种方法，将共享组件隔离到新的库项目中。这样重构代码库，而不会从根本上改变其逻辑，这将有助于现代化应用程序。

`DinnersController`类的`Create`方法中的主要代码现在将晚餐模型映射到干净的`Dinner`实体，并发布事件，而不是写入数据库：

```
if (ModelState.IsValid)
{
  dinner.HostedBy = User.Identity.Name;
  var eventMessage = new DinnerCreatedEvent
  {
    Dinner = Mapper.Map<entities.Dinner>(dinner),
    CreatedAt = DateTime.UtcNow
  };
  MessageQueue.Publish(eventMessage);
  return RedirectToAction("Index");
}
```

这是一种“发出即忘记”的消息模式。Web 应用程序是生产者，发布事件消息。生产者不等待响应，也不知道哪些组件 - 如果有的话 - 将消耗消息并对其进行操作。它松散耦合且快速，并且将传递消息的责任放在消息队列上，这正是应该的地方。

监听此事件消息的是一个新的.NET Framework 控制台项目，位于`NerdDinner.MessageHandlers.CreateDinner`中。控制台应用程序的`Main`方法使用共享的消息项目打开与消息队列的连接，并订阅这些创建晚餐事件消息。当接收到消息时，处理程序将消息中的`Dinner`实体映射回晚餐模型，并使用从`DinnersController`类中原始实现中取出的代码将模型保存到数据库中（并进行了一些整理）：

```
var dinner = Mapper.Map<models.Dinner>(eventMessage.Dinner);
using (var db = new NerdDinnerContext())
{
  dinner.RSVPs = new List<RSVP>
  {
    new RSVP
    {
      AttendeeName = dinner.HostedBy
    }
  };
  db.Dinners.Add(dinner);
  db.SaveChanges();
}
```

现在，消息处理程序可以打包到自己的 Docker 镜像中，并在网站容器旁边的容器中运行。

# 在 Docker 中打包.NET 控制台应用程序

控制台应用程序很容易构建为 Docker 的良好组件。应用程序的编译可执行文件将是 Docker 启动和监视的主要进程，因此您只需要利用控制台进行日志记录，并且可以使用文件和环境变量进行配置。

对于我的消息处理程序，我正在使用一个稍有不同模式的 Dockerfile。我有一个单独的镜像用于构建阶段，我用它来编译整个解决方案 - 包括 Web 项目和我添加的新项目。一旦您看到所有新组件，我将在本章后面详细介绍构建者镜像。

构建者编译解决方案，控制台应用程序的 Dockerfile 引用`dockeronwindows/ch05-nerd-dinner-builder:2e`镜像以复制编译的二进制文件。整个 Dockerfile 非常简单：

```
# escape=` FROM mcr.microsoft.com/windows/servercore:ltsc2019 CMD ["NerdDinner.MessageHandlers.SaveDinner.exe"]

WORKDIR C:\save-handler
COPY --from=dockeronwindows/ch05-nerd-dinner-builder:2e `
     C:\src\NerdDinner.MessageHandlers.SaveDinner\obj\Release\ . 
```

`COPY`指令中的`from`参数指定文件的来源。它可以是多阶段构建中的另一个阶段，或者—就像在这个例子中—本地机器或注册表中的现有镜像。

新的消息处理程序需要访问消息队列和数据库，每个连接字符串都在项目的`appsettings.json`文件中。控制台应用程序使用与 NerdDinner web 应用程序相同的`Config`类，该类从 JSON 文件加载默认值，并可以从环境变量中覆盖它们。

在 Dockerfile 中，`CMD`指令中的入口点是控制台可执行文件，因此只要控制台应用程序在运行，容器就会保持运行。消息队列的监听器在单独的线程上异步运行到主应用程序。当收到消息时，处理程序代码将触发，因此不需要轮询队列，应用程序运行非常高效。

使用`ManualResetEvent`对象可以简单地使控制台应用程序无限期地保持运行。在`Main`方法中，我等待一个永远不会发生的重置事件，因此程序会继续运行：

```
class Program
{
  private static ManualResetEvent _ResetEvent = new ManualResetEvent(false);

  static void Main(string[] args)
  {
    // set up message listener
    _ResetEvent.WaitOne();
  }
}
```

这是保持.NET Framework 或.NET Core 控制台应用程序保持活动状态的一种简单有效的方法。当我启动一个消息处理程序容器时，它将在后台保持运行并监听消息，直到容器停止。

# 在 Docker 中运行消息队列

现在 Web 应用程序发布消息，处理程序监听这些消息，因此我需要的最后一个组件是一个消息队列来连接这两者。队列需要与解决方案的其余部分具有相同的可用性水平，因此它们是在 Docker 容器中运行的良好候选项。在部署在许多服务器上的分布式解决方案中，队列可以跨多个容器进行集群，以提高性能和冗余性。

您选择的消息传递技术取决于您需要的功能，但在.NET 客户端库中有很多选择。**Microsoft Message Queue**（**MSMQ**）是本机 Windows 队列，**RabbitMQ**是一个流行的开源队列，支持持久化消息，**NATS**是一个开源的内存队列，性能非常高。

NATS 消息传递的高吞吐量和低延迟使其成为在容器之间通信的良好选择，并且在 Docker Hub 上有一个官方的 NATS 镜像。NATS 是一个跨平台的 Go 应用程序，Docker 镜像有 Linux、Windows Server Core 和 Nano Server 的变体。

在撰写本文时，NATS 团队仅在 Docker Hub 上发布了 Windows Server 2016 的镜像。很快将有 Windows Server 2019 镜像，但我已经为本章构建了自己的镜像。查看`dockeronwindows/ch05-nats:2e`的 Dockerfile，您将看到如何轻松地在自己的镜像中使用官方镜像的内容。

您可以像运行其他容器一样运行 NATS 消息队列。Docker 镜像公开了端口`4222`，这是客户端用来连接队列的端口，但除非您想要在 Docker 容器外部发送消息到 NATS，否则您不需要发布该端口。同一网络中的容器始终可以访问彼此的端口，它们只需要被发布以使它们在 Docker 外部可用。NerdDinner Web 应用程序和消息处理程序正在使用服务器名称`message-queue`来连接 NATS，因此需要使用该容器名称：

```
docker container run --detach `
 --name message-queue `
 dockeronwindows/ch05-nats:2e
```

NATS 服务器应用程序将消息记录到控制台，以便 Docker 收集日志条目。当容器正在运行时，您可以使用`docker container logs`来验证队列是否正在监听：

```
> docker container logs message-queue
[7996] 2019/02/09 15:40:05.857320 [INF] Starting nats-server version 1.4.1
[7996] 2019/02/09 15:40:05.858318 [INF] Git commit [3e64f0b]
[7996] 2019/02/09 15:40:05.859317 [INF] Starting http monitor on 0.0.0.0:8222
[7996] 2019/02/09 15:40:05.859317 [INF] Listening for client connections on 0.0.0.0:4222
[7996] 2019/02/09 15:40:05.859317 [INF] Server is ready
[7996] 2019/02/09 15:40:05.948151 [INF] Listening for route connections on 0.0.0.0:6222
```

消息队列是一个基础架构级组件，不依赖于其他组件。它可以在其他容器之前启动，并且在应用程序容器停止或升级时保持运行。

# 启动多容器解决方案

随着您对 Docker 的更多使用，您的解决方案将分布在更多的容器中 - 无论是运行自己从单体中拆分出来的自定义代码，还是来自 Docker Hub 或第三方注册表的可靠的第三方软件。

NerdDinner 现在跨越了五个容器运行 - SQL Server，原始 Web 应用程序，新的主页，NATS 消息队列和消息处理程序。容器之间存在依赖关系，它们需要以正确的顺序启动并使用正确的名称创建，以便组件可以使用 Docker 的服务发现找到它们。

在下一章中，我将使用 Docker Compose 来声明性地映射这些依赖关系。目前，我有一个名为`ch05-run-nerd-dinner_part-1.ps1`的 PowerShell 脚本，它明确地使用正确的配置启动容器：

```
docker container run -d `
  --name message-queue `
 dockeronwindows/ch05-nats:2e;

docker container run -d -p 1433  `
  --name nerd-dinner-db `
  -v C:\databases\nd:C:\data  `
 dockeronwindows/ch03-nerd-dinner-db:2e; docker container run -d `
  --name nerd-dinner-save-handler  `
 dockeronwindows/ch05-nerd-dinner-save-handler:2e; docker container run -d `
  --name nerd-dinner-homepage `
 dockeronwindows/ch03-nerd-dinner-homepage:2e; docker container run -d -p 80  `
  --name nerd-dinner-web `
  --env-file api-keys.env `
 dockeronwindows/ch05-nerd-dinner-web:2e;
```

在这个脚本中，我正在使用第三章中的 SQL 数据库和主页图像，*开发 Docker 化的.NET Framework 和.NET Core 应用程序*——这些组件没有改变，所以它们可以与新组件一起运行。如果您想要自己运行具有完整功能的应用程序，您需要在文件`api-keys.env`中填写自己的 API 密钥。您需要注册 Bing Maps API 和 IP 信息数据库。您可以在没有这些密钥的情况下运行应用程序，但不是所有功能都会正常工作。

当我使用自己设置的 API 密钥运行脚本并检查 Web 容器以获取端口时，我可以浏览应用程序。现在，NerdDinner 是一个功能齐全的版本。我可以登录并完成创建晚餐表单，包括地图集成：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/68a1f0a6-8a3f-42ff-b0e0-aeb43fe1b36e.png)

当我提交表单时，Web 应用程序会向队列发布事件消息。这是一个非常廉价的操作，所以 Web 应用程序几乎立即返回给用户。控制台应用程序在监听消息，它运行在不同的容器中——可能在不同的主机上。它接收消息并处理它。处理程序将活动记录到控制台，以便管理员用户可以使用`docker container logs`来监视它：

```
> docker container logs nerd-dinner-save-handler

Connecting to message queue url: nats://message-queue:4222
Listening on subject: events.dinner.created, queue: save-dinner-handler
Received message, subject: events.dinner.created
Saving new dinner, created at: 2/10/2019 8:22:16 PM; event ID: a6340c95-3629-4c0c-9a11-8a0bce8e6d91
Dinner saved. Dinner ID: 1; event ID: a6340c95-3629-4c0c-9a11-8a0bce8e6d91
```

创建晚餐功能的功能是相同的——用户输入的数据保存到 SQL Server——用户体验也是相同的，但是这个功能的可扩展性得到了极大的改善。为容器设计让我可以将持久性代码提取到一个新的组件中，知道该组件可以部署在与现有解决方案相同的基础设施上，并且如果应用程序部署在集群上，它将继承现有的可扩展性和故障转移级别。

我可以依赖 Docker 平台并依赖一个新的核心组件：消息队列。队列技术本身是企业级软件，能够每秒处理数十万条消息。NATS 是免费的开源软件，可以直接在 Docker Hub 上使用，作为一个容器运行并连接到 Docker 网络中的其他容器。

到目前为止，我已经使用了以容器为先的设计和 Docker 的强大功能来现代化 NerdDinner 的一部分。针对单个功能意味着我可以在仅测试已更改的功能后，自信地发布这个新版本。如果我想要为创建晚餐功能添加审计，我只需更新消息处理程序，而不需要对 Web 应用进行完整的回归测试，因为该组件不会被更新。

以容器为先的设计也为我提供了一个基础，可以用来现代化传统应用程序的架构并添加新功能。

# 现代化传统应用程序

将后端功能拆分是开始分解传统单体应用的好方法。将消息队列添加到部署中，使其成为一种模式，您可以重复使用任何受益于异步的功能。还有其他分解单体应用的模式。如果我们暴露一个 REST API 并将前端移动到模块化 UI，并使用反向代理在不同组件之间进行路由，我们就可以真正开始现代化 NerdDinner。我们可以用 Docker 做到这一切。

# 添加 REST API 以公开数据

传统应用程序通常最终成为无法在应用程序外部访问的数据存储。如果这些数据可以访问，它们对其他应用程序或业务合作伙伴将非常有价值。NerdDinner 是一个很好的例子——它是在单页面应用程序时代之前设计和构建的，其中 UI 逻辑与业务逻辑分离，并通过 REST API 公开。NerdDinner 保留其数据；除非通过 NerdDinner UI，否则无法查看晚餐列表。

在 Docker 容器中运行一个简单的 REST API 可以轻松解锁传统数据。它不需要复杂的交付：您可以首先识别传统应用程序中有用于其他业务部门或外部消费者的单个数据集。然后，将该数据集的加载逻辑简单提取到一个单独的功能中，并将其部署为只读 API。当有需求时，您可以逐步向 API 添加更多功能，无需在第一个发布中实现整个服务目录。

NerdDinner 的主要数据集是晚餐列表，我已经构建了一个 ASP.NET Core REST API 来在只读的`GET`请求中公开所有的晚餐。这一章的代码在`NerdDinner.DinnerApi`项目中，它是一个非常简单的实现。因为我已经将核心实体定义从主`NerdDinner`项目中拆分出来，所以我可以从 API 中公开现有的契约，并在项目内使用任何我喜欢的数据访问技术。

我选择使用 Dapper，它是一个为.NET Standard 构建的快速直观的对象关系映射器，因此它可以与.NET Framework 和.NET Core 应用程序一起使用。Dapper 使用基于约定的映射；你提供一个 SQL 语句和一个目标类类型，它执行数据库查询并将结果映射到对象。从现有表中加载晚餐数据并将其映射到共享的`Dinner`对象的代码非常简单。

```
protected  override  string  GetAllSqlQuery  =>  "SELECT *, Location.Lat as Latitude... FROM Dinners"; public  override  IEnumerable<Dinner> GetAll()
{ _logger.LogDebug("GetAll - executing SQL query: '{0}'", GetAllSqlQuery); using (IDbConnection  dbConnection  =  Connection)
  { dbConnection.Open(); return  dbConnection.Query<Dinner, Coordinates, Dinner>( GetAllSqlQuery, 
      (dinner,coordinates) => { dinner.Coordinates  =  coordinates; return  dinner;
      }, splitOn: "LocationId");
   }
}
```

在 API 控制器类中调用了`GetAll`方法，其余的代码是通常的 ASP.NET Core 设置。

Dapper 通常比这个例子更容易使用，但当你需要时它可以让你进行一些手动映射，这就是我在这里所做的。NerdDinner 使用 SQL Server 位置数据类型来存储晚餐的举办地点。这映射到.NET 的`DbGeography`类型，但这种类型在.NET Standard 中不存在。如果你浏览`第五章`中的代码，你会看到我在几个地方映射了`DbGeography`和我的自定义`Coordinates`类型，如果你遇到类似的问题，你就需要这样做。

我已经修改了原始的 NerdDinner web 应用程序，使其在`DinnersController`类中获取晚餐列表时使用这个新的 API。我通过配置设置`DinnerApi:Enabled`使用了一个功能标志，这样应用程序可以使用 API 作为数据源，或直接从数据库查询。这让我可以分阶段地推出这个功能：

```
if (bool.Parse(Config.Current["DinnerApi:Enabled"]))
{
  var  client  =  new  RestClient(Config.Current["DinnerApi:Url"]);
  var  request  =  new  RestRequest("dinners");
  var  response  =  client.Execute<List<Dinner>>(request);
  var  dinners  =  response.Data.Where(d  =>  d.EventDate  >=  DateTime.Now).OrderBy(d  =>  d.EventDate);
  return  View(dinners.ToPagedList(pageIndex, PageSize)); } else {
  var  dinners  =  db.Dinners.Where(d  =>  d.EventDate  >=  DateTime.Now).OrderBy(d  =>  d.EventDate);
  return  View(dinners.ToPagedList(pageIndex, PageSize)); }
```

新的 API 被打包到名为`dockeronwindows/ch05-nerd-dinner-api`的 Docker 镜像中。这个 Dockerfile 非常简单；它只是从名为`microsoft/dotnet:2.1-aspnetcore-runtime-nanoserver-1809`的官方 ASP.NET Core 基础镜像开始，并复制编译后的 API 代码进去。

我可以在 Docker 容器中运行 API 作为内部组件，由 NerdDinner web 容器使用，但不对外公开，或者我可以在 API 容器上发布一个端口，并使其在 Docker 网络之外可用。对于公共 REST API 来说，使用自定义端口是不寻常的，消费者期望在端口`80`上访问 HTTP 和端口`443`上访问 HTTPS。我可以向我的解决方案添加一个组件，让我可以为所有服务使用标准端口集，并将传入的请求路由到不同的容器中——这就是所谓的**反向代理**。

# 使用反向代理在容器之间路由 HTTP 请求

反向代理是一个非常有用的技术，无论您是在考虑构建新的微服务架构还是现代化传统的单体架构。反向代理只是一个 HTTP 服务器，它接收来自外部世界的所有传入网络流量，从另一个 HTTP 服务器获取内容，并将其返回给客户端。在 Docker 中，反向代理在一个带有发布端口的容器中运行，并代理来自其他没有发布端口的容器的流量。

这是 UI 和 API 容器的架构，反向代理已经就位：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/c25f793f-b5b8-4a2c-99da-5fe28361943e.png)

所有传入流量的路由规则都在代理容器中。它将被配置为从`nerd-dinner-homepage`容器加载主页位置`/`的请求；以路径`/api`开头的请求将从`nerd-dinner-api`容器加载，而其他任何请求将从`nerd-dinner-web`容器中的原始应用加载。

重要的是要意识到代理不会将客户端重定向到其他服务。代理是客户端连接的唯一端点。代理代表客户端向实际服务发出 HTTP 请求，使用容器的主机名。

反向代理不仅可以路由请求。所有流量都通过反向代理，因此它可以是应用 SSL 终止和 HTTP 缓存的层。您甚至可以在反向代理中构建安全性，将其用于身份验证和作为 Web 应用程序防火墙，保护您免受常见攻击，如 SQL 注入。这对于传统应用程序尤其有吸引力。您可以在代理层中进行性能和安全改进，将原始应用程序作为容器中的内部组件，除非通过代理，否则无法访问。

反向代理有许多技术选项。Nginx 和 HAProxy 是 Linux 世界中受欢迎的选项，它们也可以在 Windows 容器中使用。您甚至可以将 IIS 实现为反向代理，将其运行在一个单独的容器中，并使用 URL 重写模块设置所有路由规则。这些选项功能强大，但需要相当多的配置才能运行起来。我将使用一个名为 Traefik 的反向代理，它是专为在云原生应用程序中运行的容器而构建的，并且它从 Docker 中获取所需的配置。

# 使用 Traefik 代理来自 Docker 容器的流量

Traefik 是一个快速、强大且易于使用的反向代理。您可以在一个容器中运行它，并发布 HTTP（或 HTTPS）端口，并配置容器以侦听来自 Docker Engine API 的事件：

```
docker container run -d -P  `
  --volume \\.\pipe\docker_engine:\\.\pipe\docker_engine `
 sixeyed/traefik:v1.7.8-windowsservercore-ltsc2019 `
  --docker --docker.endpoint=npipe:////./pipe/docker_engine
```

Traefik 是 Docker Hub 上的官方镜像，但与 NATS 一样，唯一可用的 Windows 镜像是基于 Windows Server 2016 的。我在这里使用自己的镜像，基于 Windows Server 2019。Dockerfile 在我的 GitHub 上的`sixeyed/dockerfiles-windows`存储库中，但在使用我的镜像之前，您应该检查 Docker Hub，看看官方 Traefik 镜像是否有 2019 变体。

您之前见过`volume`选项-它用于将主机上的文件系统目录挂载到容器中。在这里，我使用它来挂载一个名为`docker_engine`的 Windows**命名管道**。管道是客户端-服务器通信的一种网络方法。Docker CLI 和 Docker API 支持 TCP/IP 和命名管道上的连接。像这样挂载一个管道让容器可以查询 Docker API，而无需知道容器运行的主机的 IP 地址。

Traefik 通过命名管道连接订阅来自 Docker API 的事件流，使用`docker.endpoint`选项中的连接详细信息。当容器被创建或移除时，Traefik 将从 Docker 那里收到通知，并使用这些事件中的数据来构建自己的路由映射。

当您运行 Traefik 时，您可以使用标签创建应用程序容器，告诉 Traefik 应该将哪些请求路由到哪些容器。标签只是在创建容器时可以应用的键值对。它们会在来自 Docker 的事件流中显示。Traefik 使用带有前缀`traefik.frontend`的标签来构建其路由规则。这就是我如何通过 Traefik 运行具有路由的 API 容器：

```
docker container run -d `
  --name nerd-dinner-api `
  -l "traefik.frontend.rule=Host:api.nerddinner.local"  `  dockeronwindows/ch05-nerd-dinner-api:2e;
```

Docker 创建名为`nerd-dinner-api`的容器，然后发布一个包含新容器详细信息的事件。Traefik 接收到该事件后，会在其路由映射中添加一条规则。任何进入 Traefik 的带有 HTTP `Host` 头部`api.nerddinner.local`的请求都将从 API 容器中进行代理。API 容器不会发布任何端口 - 反向代理是唯一可公开访问的组件。

Traefik 具有非常丰富的路由规则集，可以使用 HTTP 请求的不同部分 - 主机、路径、标头和查询字符串。您可以使用 Traefik 的规则将任何内容从通配符字符串映射到非常具体的 URL。Traefik 还可以执行更多操作，如负载平衡和 SSL 终止。文档可以在[`traefik.io`](https://traefik.io)找到。

使用类似的规则，我可以部署 NerdDinner 的新版本，并让所有前端容器都由 Traefik 进行代理。脚本`ch05-run-nerd-dinner_part-2.ps1`是一个升级版本，首先删除现有的 web 容器：

```
docker container rm -f nerd-dinner-homepage docker container rm -f nerd-dinner-web
```

标签和环境变量在容器创建时被应用，并在容器的生命周期内持续存在。您无法更改现有容器上的这些值；您需要将其删除并创建一个新的容器。我想要为 Traefik 运行 NerdDinner 网站和主页容器，并为其添加标签，因此我需要替换现有的容器。脚本的其余部分启动 Traefik，用新配置替换 web 容器，并启动 API 容器：

```
docker container run -d -p 80:80  `
  -v \\.\pipe\docker_engine:\\.\pipe\docker_engine `
 sixeyed/traefik:v1.7.8-windowsservercore-ltsc2019 `
  --api --docker --docker.endpoint=npipe:////./pipe/docker_engine  docker container run -d `
  --name nerd-dinner-homepage ` -l "traefik.frontend.rule=Path:/,/css/site.css"  `   -l "traefik.frontend.priority=10"  `
 dockeronwindows/ch03-nerd-dinner-homepage:2e;

docker container run -d `
  --name nerd-dinner-web `
  --env-file api-keys.env `
  -l "traefik.frontend.rule=PathPrefix:/"  `
  -l "traefik.frontend.priority=1"  `   -e "DinnerApi:Enabled=true"  `
 dockeronwindows/ch05-nerd-dinner-web:2e; docker container run -d `
  --name nerd-dinner-api ` -l "traefik.frontend.rule=PathPrefix:/api"  `
  -l "traefik.frontend.priority=5"  `
 dockeronwindows/ch05-nerd-dinner-api:2e;
```

现在当我加载 NerdDinner 网站时，我将浏览到端口`80`上的 Traefik 容器。我正在使用`Host`头路由规则，所以我会在浏览器中输入`http://nerddinner.local`。这是一个本地开发环境，所以我已经将这些值添加到了我的`hosts`文件中（在测试和生产环境中，将有一个真正的 DNS 系统解析主机名）：

```
127.0.0.1  nerddinner.local
127.0.0.1  api.nerddinner.local
```

对于路径`/`的主页请求是从主页容器代理的，并且我还为 CSS 文件指定了一个路由路径，这样我就可以看到包含样式的新主页：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/a2acc8e6-3888-4052-b7ee-991a945b7e29.png)

这个响应是由主页容器生成的，但是由 Traefik 代理。我可以浏览到`api.nerddinner.local`，并从新的 REST API 容器中以 JSON 格式看到所有晚宴的信息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/7c905e8a-1c7a-402a-87be-8afb6fa9c156.png)

原始的 NerdDinner 应用程序仍然以相同的方式工作，但是当我浏览到`/Dinners`时，显示的晚宴列表是从 API 中获取的，而不是直接从数据库中获取的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/4c9a8b38-967c-4e76-921a-b5f648d91eb8.png)

制定代理的路由规则是将单体应用程序分解为多个前端容器的较难部分之一。微服务应用程序在这方面往往更容易，因为它们被设计为在不同的域路径上运行的不同关注点。当您开始将 UI 功能路由到它们自己的容器时，您需要对 Traefik 的规则和正则表达式有很好的理解。

容器优先设计使我能够在不完全重写的情况下现代化 NerdDinner 的架构。我正在使用企业级开源软件和 Docker 来支持以下三种分解单体的模式：

+   通过在消息队列上发布和订阅事件使功能异步化

+   使用简单的现代技术栈通过 REST API 公开数据

+   将前端功能拆分到多个容器中，并通过反向代理在它们之间进行路由

现在，我可以更加灵活地提供功能改进，因为我不总是需要对整个应用程序进行回归测试。我还有一些从关键用户活动中发布的事件，这是迈向事件驱动架构的一步。这让我可以在不更改任何现有代码的情况下添加全新的功能。

# 在容器中添加新功能

将单体架构分解为小组件并现代化架构具有有益的副作用。我采取的方法已经为一个功能引入了事件发布。我可以在此基础上构建新功能，再次采用以容器为先的方法。

在 NerdDinner 中，有一个单一的数据存储，即存储在 SQL Server 中的事务性数据库。这对于为网站提供服务是可以的，但在涉及用户界面功能（如报告）时有限。没有用户友好的方式来搜索数据，构建仪表板或启用自助式报告。

解决这个问题的理想方案是添加一个次要数据存储，即报告数据库，使用提供自助式分析的技术。如果没有 Docker，这将是一个重大项目，需要重新设计或额外的基础设施或两者兼而有之。有了 Docker，我可以让现有应用程序保持不变，并在现有服务器上运行容器中添加新功能。

Elasticsearch 是另一个企业级开源项目，可以作为 Docker Hub 上的官方镜像使用。Elasticsearch 是一个完整的搜索文档数据存储，作为报告数据库运行良好，还有伴随产品 Kibana，提供用户友好的 Web 前端。

我可以通过在与其他容器相同的网络中在容器中运行 Elasticsearch 和 Kibana，为 NerdDinner 中创建的晚餐添加自助式分析。当前解决方案已经发布了晚餐详情的事件，因此要将晚餐添加到报告数据库中，我需要构建一个新的消息处理程序，订阅现有事件并将详情保存在 Elasticsearch 中。

当新的报告功能准备就绪时，可以将其部署到生产环境，而无需对正在运行的应用程序进行任何更改。零停机部署是容器优先设计的另一个好处。功能被构建为以解耦单元运行，因此可以启动或升级单个容器而不影响其他容器。

对于下一个功能，我将添加一个与解决方案的其余部分独立的新消息处理程序。如果我需要替换保存晚餐处理程序的实现，我也可以使用消息队列在替换处理程序时缓冲事件，实现零停机。

# 使用 Elasticsearch 与 Docker 和.NET。

Elasticsearch 是一种非常有用的技术，值得稍微详细地了解一下。它是一个 Java 应用程序，但在 Docker 中运行时，你可以将其视为一个黑盒子，并以与所有其他 Docker 工作负载相同的方式进行管理——你不需要安装 Java 或配置 JDK。Elasticsearch 提供了一个 REST API 用于写入、读取和搜索数据，并且所有主要语言都有 API 的客户端包装器可用。

Elasticsearch 中的数据以 JSON 文档的形式存储，每个文档都可以完全索引，这样你就可以在任何字段中搜索任何值。它是一个可以在许多节点上运行的集群技术，用于扩展和弹性。在 Docker 中，你可以在单独的容器中运行每个节点，并将它们分布在服务器群中，以获得规模和弹性，但同时也能获得 Docker 的部署和管理的便利性。

与任何有状态的工作负载一样，Elasticsearch 也需要考虑存储方面的问题——在开发中，你可以将数据保存在容器内，这样当容器被替换时，你就可以从一个新的数据库开始。在测试环境中，你可以使用一个 Docker 卷挂载到主机上的驱动器文件夹，以便在容器外保持持久存储。在生产环境中，你可以使用一个带有驱动程序的卷，用于本地存储阵列或云存储服务。

Docker Hub 上有一个官方的 Elasticsearch 镜像，但目前只有 Linux 变体。我在 Docker Hub 上有自己的镜像，将 Elasticsearch 打包成了一个 Windows Server 2019 的 Docker 镜像。在 Docker 中运行 Elasticsearch 与启动任何容器是一样的。这个命令暴露了端口`9200`，这是 REST API 的默认端口。

```
 docker container run -d -p 9200 `
 --name elasticsearch ` --env ES_JAVA_OPTS='-Xms512m -Xmx512m' `
 sixeyed/elasticsearch:5.6.11-windowsservercore-ltsc2019
```

Elasticsearch 是一个占用内存很多的应用程序，默认情况下在启动时会分配 2GB 的系统内存。在开发环境中，我不需要那么多的内存来运行数据库。我可以通过设置`ES_JAVA_OPTS`环境变量来配置这个。在这个命令中，我将 Elasticsearch 限制在 512MB 的内存中。

Elasticsearch 是一个跨平台的应用程序，就像 NATS 一样。Windows 没有官方的 Elasticsearch 镜像，但你可以在 GitHub 的`sixeyed/dockerfiles-windows`仓库中查看我的 Dockerfile。你会看到我使用了基于 Windows Server Core 2019 的官方 OpenJDK Java 镜像来构建我的 Elasticsearch 镜像。

有一个名为**NEST**的 Elasticsearch NuGet 包，它是用于读写数据的 API 客户端，面向.NET Framework 和.NET Core。我在一个新的.NET Core 控制台项目`NerdDinner.MessageHandlers.IndexDinner`中使用这个包。新的控制台应用程序监听来自 NATS 的 dinner-created 事件消息，并将 dinner 详情作为文档写入 Elasticsearch。

连接到消息队列并订阅消息的代码与现有消息处理程序相同。我有一个新的`Dinner`类，它代表 Elasticsearch 文档，因此消息处理程序代码将`Dinner`实体映射到 dinner 文档并将其保存在 Elasticsearch 中：

```
var eventMessage = MessageHelper.FromData<DinnerCreatedEvent>(e.Message.Data);
var dinner = Mapper.Map<documents.Dinner>(eventMessage.Dinner);
var  node  =  new  Uri(Config.Current["Elasticsearch:Url"]);
var client = new ElasticClient(node);
client.Index(dinner, idx => idx.Index("dinners"));
```

Elasticsearch 将在一个容器中运行，新的文档消息处理程序将在一个容器中运行，都在与 NerdDinner 解决方案的其余部分相同的 Docker 网络中。我可以在现有解决方案运行时启动新的容器，因为 Web 应用程序或 SQL Server 消息处理程序没有任何更改。使用 Docker 添加这个新功能是零停机部署。

Elasticsearch 消息处理程序不依赖于 EF 或任何旧代码，就像新的 REST API 一样。我利用了这一点，在.NET Core 中编写这些应用程序，这使我可以在 Linux 或 Windows 主机上的 Docker 容器中运行它们。我的 Visual Studio 解决方案现在有.NET Framework、.NET Standard 和.NET Core 项目。代码库的部分代码在.NET Framework 和.NET Core 应用程序项目之间共享。我可以为每个应用程序的 Dockerfile 使用多阶段构建，但在较大的项目中可能会引发问题。

大型.NET 代码库往往采用多解决方案方法，其中一个主解决方案包含 CI 服务器中使用的所有项目，并且应用程序的每个区域都有不同的`.sln`文件，每个文件都有一部分项目。这样可以让不同的团队在不必加载数百万行代码到 Visual Studio 的情况下处理他们的代码库的一部分。这节省了很多开发人员的时间，但也引入了一个风险，即对共享组件的更改可能会破坏另一个团队的构建。

如果您将所有组件都迁移到多阶段构建，那么当您迁移到 Docker 时，仍可能遇到这个问题。在这种情况下，您可以使用另一种方法，在其中在单个 Dockerfile 中构建所有代码，就像 Visual Studio 的旧主解决方案一样。

# 在 Docker 中构建混合.NET Framework 和.NET Core 解决方案

到目前为止，您所看到的多阶段构建都使用了 Docker Hub 上的`microsoft/dotnet-framework:4.7.2-sdk`图像或`microsoft/dotnet:2.2-sdk`图像。这些图像提供了相关的.NET 运行时，以及用于还原包、编译源代码和发布应用程序的 SDK 组件。

.NET Framework 4.7.2 图像还包含.NET Core 2.1 SDK，因此如果您使用这些版本（或更早版本），则可以在同一个 Dockerfile 中构建.NET Framework 和.NET Core 应用程序。

在本书的第一版中，没有官方图像同时包含.NET Framework 和.NET Core SDK，因此我向您展示了如何使用非常复杂的 Dockerfile 自己构建图像，并进行了大量的 Chocolatey 安装。我还写道，“*我期望 MSBuild 和.NET Core 的后续版本将具有集成工具，因此管理多个工具链的复杂性将消失，”*我很高兴地说，现在我们就在这个阶段，微软正在为我们管理这些工具链。

# 编译混合 NerdDinner 解决方案

在本章中，我采用了一种不同的方法来构建 NerdDinner，这种方法与 CI 流程很好地契合，如果您正在混合使用.NET Core 和.NET Framework 项目（我在第十章中使用 Docker 进行 CI 和 CD，*使用 Docker 打造持续部署流水线*）。我将在一个图像中编译整个解决方案，并将该图像用作应用程序 Dockerfile 中二进制文件的来源。

以下图表显示了 SDK 和构建器图像如何用于打包本章的应用程序图像：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/747a90e4-03ad-417c-ab18-06b37344e7ef.png)

构建解决方案所需的所有工具都在 Microsoft 的 SDK 中，因此`dockeronwindows/ch05-nerd-dinner-builder:2e`的 Dockerfile 很简单。它从 SDK 开始，复制解决方案的源树，并还原依赖项：

```
# escape=` FROM microsoft/dotnet-framework:4.7.2-sdk-windowsservercore-ltsc2019 AS builder WORKDIR C:\src COPY src . RUN nuget restore
```

这会为 NerdDinner 解决方案文件运行`nuget restore`。这将为所有项目还原所有.NET Framework、.NET Standard 和.NET Core 引用。最后一条指令构建每个应用程序项目，指定项目文件和它们各自的单独输出路径：

```
RUN msbuild ...\NerdDinner.csproj /p:OutputPath=c:\nerd-dinner-web; ` msbuild ...\NerdDinner.MessageHandlers.SaveDinner.csproj /p:OutputPath=c:\save-handler; `
    dotnet publish -o C:\index-handler ...\NerdDinner.MessageHandlers.IndexDinner.csproj; `
    dotnet publish -o C:\dinner-api ...\NerdDinner.DinnerApi.csproj
```

你可以只运行`msbuild`来处理整个解决方案文件，但这只会生成已编译的二进制文件，而不是完全发布的目录。这种方法意味着每个应用程序都已经准备好进行打包发布，并且输出位于构建图像中的已知位置。这也意味着整个应用程序是从相同的源代码集编译的，因此您将发现应用程序之间的依赖关系中的任何破坏问题。

这种方法的缺点是它没有充分利用 Docker 缓存。整个源树被复制到映像中作为第一步。每当有代码更改时，构建将更新软件包，即使软件包引用没有更改。您可以以不同的方式编写此构建器，首先复制`.sln`、`.csproj`和`package.config`文件进行还原阶段，然后复制其余源进行构建阶段。

这将为您提供软件包缓存和更快的构建速度，但代价是更脆弱的 Dockerfile - 每次添加或删除项目时都需要编辑初始文件列表。

您可以选择最适合您流程的方法。在比这更复杂的解决方案中，开发人员可能会从 Visual Studio 构建和运行应用程序，然后只构建 Docker 映像以在提交代码之前运行测试。在这种情况下，较慢的 Docker 映像构建不是问题（我在第十一章中讨论了在开发过程中在 Docker 中运行应用程序的选项，*调试和检测应用程序容器*）。

关于构建此映像的方式有一个不同之处。Dockerfile 复制了`src`文件夹，该文件夹比 Dockerfile 所在的文件夹高一级。为了确保`src`文件夹包含在 Docker 上下文中，我需要从`ch05`文件夹运行`build image`命令，并使用`--file`选项指定 Dockerfile 的路径：

```
docker image build `
 --tag dockeronwindows/ch05-nerd-dinner-builder `
 --file ch05-nerd-dinner-builder\Dockerfile .
```

构建映像会编译和打包所有项目，因此我可以将该映像用作应用程序 Dockerfiles 中发布输出的源。我只需要构建构建器一次，然后就可以用它来构建所有其他映像。

# 在 Docker 中打包.NET Core 控制台应用程序

在第三章中，《开发 Docker 化的.NET Framework 和.NET Core 应用程序》，我将替换 NerdDinner 首页的 ASP.NET Core Web 应用程序构建为 REST API 和 Elasticsearch 消息处理程序作为.NET Core 应用程序。这些可以打包为 Docker 镜像，使用 Docker Hub 上`microsoft/dotnet`镜像的变体。

REST API 的 Dockerfile `dockeronwindows/ch05-nerd-dinner-api:2e`非常简单：它只是设置容器环境，然后从构建图像中复制发布的应用程序：

```
# escape=` FROM microsoft/dotnet:2.1-aspnetcore-runtime-nanoserver-1809 EXPOSE 80 WORKDIR /dinner-api ENTRYPOINT ["dotnet", "NerdDinner.DinnerApi.dll"] COPY --from=dockeronwindows/ch05-nerd-dinner-builder:2e C:\dinner-api .
```

消息处理程序的 Dockerfile `dockeronwindows/ch05-nerd-dinner-index-handler:2e`更简单——这是一个.NET Core 控制台应用程序，因此不需要暴露端口：

```
# escape=` FROM microsoft/dotnet:2.1-runtime-nanoserver-1809 CMD ["dotnet", "NerdDinner.MessageHandlers.IndexDinner.dll"] WORKDIR /index-handler COPY --from=dockeronwindows/ch05-nerd-dinner-builder:2e C:\index-handler .
```

内容与用于 SQL Server 消息处理程序的.NET Framework 控制台应用程序非常相似。不同之处在于`FROM`图像；在这里，我使用.NET Core 运行时图像和`CMD`指令，这里运行控制台应用程序 DLL 的是`dotnet`命令。两个消息处理程序都使用构建图像作为复制编译应用程序的来源，然后设置它们需要的环境变量和启动命令。

.NET Core 应用程序都捆绑了`appsettings.json`中的默认配置值，可以使用环境变量在容器运行时进行覆盖。这些配置包括消息队列和 Elasticsearch API 的 URL，以及 SQL Server 数据库的连接字符串。启动命令运行.NET Core 应用程序。ASP.NET Core 应用程序会一直在前台运行，直到应用程序停止。消息处理程序的.NET Core 控制台应用程序会使用`ManualResetEvent`对象在前台保持活动状态。两者都会将日志条目写入控制台，因此它们与 Docker 集成良好。

当索引处理程序应用程序运行时，它将监听来自 NATS 的消息，主题为 dinner-created。当从 Web 应用程序发布事件时，NATS 将向每个订阅者发送副本，因此 SQL Server 保存处理程序和 Elasticsearch 索引处理程序都将获得事件的副本。事件消息包含足够的细节，以便两个处理程序运行。如果将来的功能需要更多细节，那么 Web 应用程序可以发布带有附加信息的事件的新版本，但现有的消息处理程序将不需要更改。

运行另一个带有 Kibana 的容器将完成此功能，并为 NerdDinner 添加自助式分析。

# 使用 Kibana 提供分析

Kibana 是 Elasticsearch 的开源 Web 前端，为您提供了用于分析的可视化和搜索特定数据的能力。它由 Elasticsearch 背后的公司制作，并且被广泛使用，因为它提供了一个用户友好的方式来浏览大量的数据。您可以交互式地探索数据，而高级用户可以构建全面的仪表板与他人分享。

Kibana 的最新版本是一个 Node.js 应用程序，因此像 Elasticsearch 和 NATS 一样，它是一个跨平台应用程序。Docker Hub 上有一个官方的 Linux 和变体镜像，我已经基于 Windows Server 2019 打包了自己的镜像。Kibana 镜像使用了与消息处理器中使用的相同的基于约定的方法构建：它期望连接到默认 API 端口`9200`上名为`elasticsearch`的容器。

在本章的源代码目录中，有第二个 PowerShell 脚本，用于部署此功能的容器。名为`ch05-run-nerd-dinner_part-3.ps1`的脚本启动了额外的 Elasticsearch、Kibana 和索引处理器容器，并假定其他组件已经从 part-1 和 part-2 脚本中运行：

```
 docker container run -d `
  --name elasticsearch `
  --env ES_JAVA_OPTS='-Xms512m -Xmx512m'  `
 sixeyed/elasticsearch:5.6.11-windowsservercore-ltsc2019; docker container run -d `
  --name kibana `
  -l "traefik.frontend.rule=Host:kibana.nerddinner.local"  `
 sixeyed/kibana:5.6.11-windowsservercore-ltsc2019; docker container run -d `
  --name nerd-dinner-index-handler `
 dockeronwindows/ch05-nerd-dinner-index-handler:2e; 
```

Kibana 容器带有 Traefik 的前端规则。默认情况下，Kibana 监听端口`5601`，但在我的设置中，我将能够在端口`80`上使用`kibana.nerddinner.local`域名访问它，我已经将其添加到我的`hosts`文件中，Traefik 将代理 UI。

整个堆栈现在正在运行。当我添加一个新的晚餐时，我将看到来自消息处理器容器的日志，显示数据现在正在保存到 Elasticsearch，以及 SQL Server：

```
> docker container logs nerd-dinner-save-handler
Connecting to message queue url: nats://message-queue:4222
Listening on subject: events.dinner.created, queue: save-dinner-handler
Received message, subject: events.dinner.created
Saving new dinner, created at: 2/11/2019 10:18:32 PM; event ID: 9919cd1e-2b0b-41c7-8019-b2243e81a412
Dinner saved. Dinner ID: 2; event ID: 9919cd1e-2b0b-41c7-8019-b2243e81a412

> docker container logs nerd-dinner-index-handler
Connecting to message queue url: nats://message-queue:4222
Listening on subject: events.dinner.created, queue: index-dinner-handler
Received message, subject: events.dinner.created
Indexing new dinner, created at: 2/11/2019 10:18:32 PM; event ID: 9919cd1e-2b0b-41c7-8019-b2243e81a412
```

Kibana 由 Traefik 代理，所以我只需要浏览到`kibana.nerddinner.local`。启动屏幕唯一需要的配置是文档集合的名称，Elasticsearch 称之为索引。在这种情况下，索引被称为**dinners**。我已经使用消息处理器添加了一个文档，以便 Kibana 可以访问 Elasticsearch 元数据以确定文档中的字段：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/e12648b2-f748-4981-a941-a9ca1de192e9.png)

现在创建的每个晚餐都将保存在原始的事务性数据库 SQL Server 中，也会保存在新的报告数据库 Elasticsearch 中。用户可以对聚合数据创建可视化，寻找热门时间或地点的模式，并且可以搜索特定的晚餐详情并检索特定文档：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/7f7fed5f-7a23-4f37-bbea-8747c53e1135.png)Elasticsearch 和 Kibana 是非常强大的软件系统。 Docker 使它们对一大批新用户可用。我不会在本书中进一步详细介绍它们，但它们是受欢迎的组件，有很多在线资源，如果您想了解更多，可以搜索。

# 从单体架构到分布式解决方案

NerdDinner 已经从传统的单体架构发展为一个易于扩展、易于扩展的解决方案，运行在现代应用程序平台上，使用现代设计模式。这是一个快速且低风险的演变，由 Docker 平台和以容器为先的设计推动。

该项目开始将 NerdDinner 迁移到 Docker，运行一个容器用于 Web 应用程序，另一个用于 SQL Server 数据库。现在我有十个组件在容器中运行。其中五个运行我的自定义代码：

+   原始的 ASP.NET NerdDinner Web 应用程序

+   新的 ASP.NET Core Web 首页

+   新的.NET Framework save-dinner 消息处理程序

+   新的.NET Core index-dinner 消息处理程序

+   新的 ASP.NET Core 晚餐 API

有四种企业级开源技术：

+   Traefik 反向代理

+   NATS 消息队列

+   Elasticsearch 文档数据库

+   Kibana 分析 UI

最后是 SQL Server Express，在生产中免费使用。每个组件都在轻量级的 Docker 容器中运行，并且每个组件都能够独立部署，以便它们可以遵循自己的发布节奏：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/810be7f9-9933-4e95-8b15-0a730684c67a.png)

Docker 的一个巨大好处是其庞大的打包软件库，可供您添加到解决方案中。 Docker Hub 上的官方镜像已经经过社区多年的尝试和信任。 Docker Hub 上的认证镜像提供了商业软件，保证在 Docker Enterprise 上能够正确运行。

越来越多的软件包以易于消费的 Docker 镜像形式提供给 Windows，使您有能力在不需要大量开发的情况下为您的应用程序添加功能。

NerdDinner 堆栈中的新自定义组件是消息处理程序和 REST API，所有这些都是包含大约 100 行代码的简单应用程序。save-dinner 处理程序使用了 Web 应用程序的原始代码，并使用了我重构为自己的项目以实现重用的 EF 模型。index dinner 处理程序和 REST API 使用了.NET Core 中的全新代码，这使得它在运行时更高效和可移植，但在构建时，所有项目都在一个单一的 Visual Studio 解决方案中。

以容器为先的方法是将功能分解为离散的组件，并设计这些组件以在容器中运行，无论是作为你自己编写的小型自定义应用程序，还是作为 Docker Hub 上的现成镜像。这种以功能为驱动的方法意味着你专注于对项目利益相关者有价值的领域：

+   对于业务来说，这是因为它为他们提供了新的功能或更频繁的发布

+   对于运维来说，因为它使应用程序更具弹性和更易于维护

+   对开发团队来说，因为它解决了技术债务并允许更大的架构自由

# 管理构建和部署依赖。

在当前的演进中，NerdDinner 有一个结构良好、逻辑清晰的架构，但实际上它有很多依赖。以容器为先的设计方法给了我技术栈的自由，但这可能会导致许多新技术。如果你在这个阶段加入项目并希望在 Docker 之外本地运行应用程序，你需要以下内容：

+   Visual Studio 2017

+   .NET Core 2.1 运行时和 SDK

+   IIS 和 ASP.NET 4.7.2

+   SQL Server

+   Traefik、NATS、Elasticsearch 和 Kibana

如果你加入了这个项目并且在 Windows 10 上安装了 Docker Desktop，你就不需要这些依赖。当你克隆了源代码后，你可以使用 Docker 构建和运行整个应用程序堆栈。你甚至可以使用 Docker 和轻量级编辑器（如 VS Code）开发和调试解决方案，甚至不需要依赖 Visual Studio。

这也使得持续集成非常容易：你的构建服务器只需要安装 Docker 来构建和打包解决方案。你可以使用一次性构建服务器，在排队构建时启动一个虚拟机，然后在队列为空时销毁虚拟机。你不需要复杂的虚拟机初始化脚本，只需要一个脚本化的 Docker 安装。你也可以使用云中的托管 CI 服务，因为它们现在都支持 Docker。

在解决方案中仍然存在运行时依赖关系，我目前正在使用一个脚本来管理所有容器的启动选项和正确的顺序。这是一种脆弱和有限的方法——脚本没有逻辑来处理任何故障或允许部分启动，其中一些容器已经在运行。在一个真正的项目中你不会这样做；我只是使用这个脚本让我们可以专注于构建和运行容器。在下一章中，我会向你展示正确的方法，使用 Docker Compose 来定义和运行整个解决方案。

# 总结

在这一章中，我讨论了基于容器的解决方案设计，利用 Docker 平台在设计时轻松而安全地为你的应用程序添加功能。我描述了一种面向特性的方法，用于现代化现有软件项目，最大限度地提高投资回报，并清晰地展示其进展情况。

基于容器的功能优先方法让你可以使用来自 Docker Hub 的生产级软件来为你的解决方案增加功能，使用官方和认证的高质量精心策划的镜像。你可以添加这些现成的组件，并专注于构建小型定制组件来完成功能。你的应用程序将逐渐演变为松散耦合，以便每个单独的元素都可以拥有最合适的发布周期。

在这一章中，开发速度已经超过了运维，所以我们目前拥有一个良好架构的解决方案，但部署起来很脆弱。在下一章中，我会介绍 Docker Compose，它提供了一种清晰和统一的方式来描述和管理多容器解决方案。


# 第六章：使用 Docker Compose 组织分布式解决方案

软件的交付是 Docker 平台的一个重要组成部分。Docker Hub 上的官方存储库使得使用经过验证的组件设计分布式解决方案变得容易。在上一章中，我向你展示了如何将这些组件集成到你自己的解决方案中，采用了以容器为先的设计方法。最终结果是一个具有多个运动部件的分布式解决方案。在本章中，你将学习如何将所有这些运动部件组织成一个单元，使用 Docker Compose。

Docker Compose 是 Docker，Inc.的另一个开源产品，它扩展了 Docker 生态系统。Docker 命令行界面（CLI）和 Docker API 在单个资源上工作，比如镜像和容器。Docker Compose 在更高的级别上工作，涉及服务和应用程序。一个应用程序是一个由一个或多个服务组成的单个单元，在运行时作为容器部署。你可以使用 Docker Compose 来定义应用程序的所有资源-服务、网络、卷和其他 Docker 对象-以及它们之间的依赖关系。

Docker Compose 有两个部分。设计时元素使用 YAML 规范在标记文件中捕获应用程序定义，而在运行时，Docker Compose 可以从 YAML 文件管理应用程序。我们将在本章中涵盖这两个部分：

+   使用 Docker Compose 定义应用程序

+   使用 Docker Compose 管理应用程序

+   配置应用程序环境

Docker Compose 是作为 Docker Desktop 在 Windows 上的一部分安装的。如果你使用 PowerShell 安装程序在 Windows Server 上安装 Docker，那就不会得到 Docker Compose。你可以从 GitHub 的发布页面`docker/compose`上下载它。

# 技术要求

你需要在 Windows 10 上运行 Docker，更新到 18.09 版，或者在 Windows Server 2019 上运行，以便跟随示例。本章的代码可在[`github.com/sixeyed/docker-on-windows/tree/second-edition/ch06`](https://github.com/sixeyed/docker-on-windows/tree/second-edition/ch06)上找到。

# 使用 Docker Compose 定义应用程序

Docker Compose 文件格式非常简单。YAML 是一种人类可读的标记语言，Compose 文件规范捕获了您的应用程序配置，使用与 Docker CLI 相同的选项名称。在 Compose 文件中，您定义组成应用程序的服务、网络和卷。网络和卷是您在 Docker 引擎中使用的相同概念。服务是容器的抽象。

容器是组件的单个实例，可以是从 Web 应用到消息处理程序的任何内容。服务可以是同一组件的多个实例，在不同的容器中运行，都使用相同的 Docker 镜像和相同的运行时选项。您可以在用于 Web 应用程序的服务中有三个容器，在用于消息处理程序的服务中有两个容器：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/350dcfa9-dead-4008-84d7-0c4d7e999a8e.png)

*服务*就像是从图像运行容器的模板，具有已知配置。使用服务，您可以扩展应用程序的组件——从相同图像运行多个容器，并将它们配置和管理为单个单元。服务不在独立的 Docker 引擎中使用，但它们在 Docker Compose 中使用，并且在运行 Docker Swarm 模式的 Docker 引擎集群中也使用（我将在下一章第七章中介绍，*使用 Docker Swarm 编排分布式解决方案*）。

Docker 为服务提供了与容器相同的可发现性。消费者通过名称访问服务，Docker 可以在服务中的多个容器之间负载均衡请求。服务中的实例数量对消费者是透明的；他们总是引用服务名称，并且流量始终由 Docker 定向到单个容器。

在本章中，我将使用 Docker Compose 来组织我在上一章中构建的分布式解决方案，用可靠且适用于生产的 Docker Compose 文件替换脆弱的`docker container run` PowerShell 脚本。

# 捕获服务定义

服务可以在 Compose 文件中以任何顺序定义。为了更容易阅读，我更喜欢从最简单的服务开始，这些服务没有依赖关系——**基础设施组件**，如消息队列、反向代理和数据库。

Docker Compose 文件通常被称为`docker-compose.yml`，并且以 API 版本的明确声明开头；最新版本是 3.7。应用程序资源在顶层定义 - 这是一个模板 Compose 文件，包含了服务、网络和卷的部分：

```
 version: '3.7'

  services:
    ...

  networks:
    ...

  volumes:
    ...
```

Docker Compose 规范在 Docker 网站[`docs.docker.com/compose/compose-file/`](https://docs.docker.com/compose/compose-file/)上有文档。这列出了所有支持的版本的完整规范，以及版本之间的更改。

所有资源都需要一个唯一的名称，名称是资源引用其他资源的方式。服务可能依赖于网络、卷和其他服务，所有这些都通过名称来捕获。每个资源的配置都在自己的部分中，可用的属性与 Docker CLI 中相应的`create`命令大致相同，比如`docker network create`和`docker volume create`。

在本章中，我将为分布式 NerdDinner 应用程序构建一个 Compose 文件，并向您展示如何使用 Docker Compose 来管理应用程序。我将首先从常见服务开始我的 Compose 文件。

# 定义基础设施服务

我拥有的最简单的服务是消息队列**NATS**，它没有任何依赖关系。每个服务都需要一个名称和一个镜像名称来启动容器。可选地，您可以包括您在`docker container run`中使用的参数。对于 NATS 消息队列，我添加了一个网络名称，这意味着为此服务创建的任何容器都将连接到`nd-net`网络：

```
message-queue:
  image: dockeronwindows/ch05-nats:2e
 networks:
 - nd-net 
```

在这个服务定义中，我拥有启动消息队列容器所需的所有参数：

+   `message-queue`是服务的名称。这将成为其他服务访问 NATS 的 DNS 条目。

+   `image`是启动容器的完整镜像名称。在这种情况下，它是我从 Docker Hub 的官方 NATS 镜像中获取的我的 Windows Server 2019 变体，但您也可以通过在镜像名称中包含注册表域来使用来自私有注册表的镜像。

+   `networks`是连接容器启动时要连接到的网络列表。此服务连接到一个名为`nd-net`的网络。这将是此应用程序中所有服务使用的 Docker 网络。稍后在 Docker Compose 文件中，我将明确捕获网络的详细信息。

我没有为 NATS 服务发布任何端口。消息队列仅在其他容器内部使用。在 Docker 网络中，容器可以访问其他容器上的端口，而无需将它们发布到主机上。这使得消息队列安全，因为它只能通过相同网络中的其他容器通过 Docker 平台访问。没有外部服务器，也没有在服务器上运行的应用程序可以访问消息队列。

# Elasticsearch

下一个基础设施服务是 Elasticsearch，它也不依赖于其他服务。它将被消息处理程序使用，该处理程序还使用 NATS 消息队列，因此我需要将所有这些服务加入到相同的 Docker 网络中。对于 Elasticsearch，我还希望限制其使用的内存量，并使用卷来存储数据，以便它存储在容器之外：

```
  elasticsearch:
  image: sixeyed/elasticsearch:5.6.11-windowsservercore-ltsc2019
 environment: 
  - ES_JAVA_OPTS=-Xms512m -Xmx512m
  volumes:
     - **es-data:C:\data
   networks:
    - nd-net
```

在这里，`elasticsearch`是服务的名称，`sixeyed/elasticsearch`是镜像的名称，这是我在 Docker Hub 上的公共镜像。我将服务连接到相同的`nd-net`网络，并且还挂载一个卷到容器中的已知位置。当 Elasticsearch 将数据写入容器上的`C:\data`时，实际上会存储在一个卷中。

就像网络一样，卷在 Docker Compose 文件中是一流资源。对于 Elasticsearch，我正在将一个名为`es-data`的卷映射到容器中的数据位置。我将稍后在 Compose 文件中指定`es-data`卷应该如何创建。

# Traefik

接下来是反向代理 Traefik。代理从标签中构建其路由规则，当容器创建时，它需要连接到 Docker API：

```
reverse-proxy:
  image: sixeyed/traefik:v1.7.8-windowsservercore-ltsc2019
  command: --docker --docker.endpoint=npipe:////./pipe/docker_engine --api
 ports:
   - **"80:80"
 - "8080:8080"
  volumes: - type: npipe source: \\.\pipe\docker_engine target: \\.\pipe\docker_engine 
  networks:
   - nd-net
```

Traefik 容器发布到主机上的端口`80`，连接到应用程序网络，并使用卷用于 Docker API 命名管道。这些是我在使用`docker container run`启动 Traefik 时使用的相同选项；通常，您可以将运行命令复制到 Docker Compose 文件中。

端口发布在 Docker Compose 中与在运行容器时相同。您指定要发布的容器端口和应该发布到哪个主机端口，因此 Docker 会将传入的主机流量路由到容器。`ports`部分允许多个映射，并且如果有特定要求，您可以选择指定 TCP 或 UDP 协议。

我还发布了端口`8080`，并在 Traefik 配置中使用了`--api`标志。这使我可以访问 Traefik 的仪表板，我可以在那里查看 Traefik 配置的所有路由规则。这在非生产环境中很有用，可以检查代理规则是否正确，但在生产环境中，这不是您希望公开的东西。

Docker Compose 还支持扩展定义，我正在使用`volume`规范。我将卷的类型、源和目标拆分成不同的行，而不是使用单行来定义卷挂载。这是可选的，但它使文件更容易阅读。

# Kibana

**Kibana**是第一个依赖于其他服务的服务——它需要 Elasticsearch 运行，以便它可以连接到数据库。Docker Compose 不会对创建容器的顺序做出任何保证，因此如果服务之间存在启动依赖关系，您需要在服务定义中捕获该依赖关系：

```
kibana:
  image: sixeyed/kibana:5.6.11-windowsservercore-ltsc2019
  labels:
   - "traefik.frontend.rule=Host:kibana.nerddinner.local"
   depends_on:
   - elasticsearch  networks:
   - nd-net
```

`depends_on`属性显示了如何捕获服务之间的依赖关系。在这种情况下，Kibana 依赖于 Elasticsearch，因此 Docker 将确保在启动`kibana`服务之前，`elasticsearch`服务已经启动并运行。

像这样捕获依赖关系对于在单台机器上运行分布式应用程序是可以的，但它不具有可扩展性。当您在集群中运行时，您希望编排器来管理分发工作负载。如果您有显式依赖关系，它无法有效地执行此操作，因为它需要确保所有运行依赖服务的容器在启动消费容器之前都是健康的。在我们看 Docker Swarm 时，我们将看到更好的管理依赖关系的方法。

Kibana 将由 Traefik 代理，但 Kibana 之前不需要运行 Traefik。当 Traefik 启动时，它会从 Docker API 获取正在运行的容器列表，以构建其初始路由映射。然后，它订阅来自 Docker 的事件流，以在创建或删除容器时更新路由规则。因此，Traefik 可以在 web 容器之前或之后启动。

`kibana`服务的容器也连接到应用程序网络。在另一种配置中，我可以有单独的后端和前端网络。所有基础设施服务都将连接到后端网络，而面向公众的服务将连接到后端和前端网络。这两个都是 Docker 网络，但将它们分开可以让我灵活地配置网络。

# 配置应用程序服务

到目前为止，我指定的基础设施服务并不需要太多的应用程序级配置。我已经使用网络、卷和端口配置了容器与 Docker 平台之间的集成点，但应用程序使用了内置到每个 Docker 镜像中的配置。

Kibana 镜像按照惯例使用主机名`elasticsearch`连接到 Elasticsearch，这是我在 Docker Compose 文件中使用的服务名称，以支持该惯例。Docker 平台将任何对`elasticsearch`主机名的请求路由到该服务，如果有多个运行该服务的容器，则在容器之间进行负载均衡，因此 Kibana 将能够在预期的域名找到 Elasticsearch。

我的自定义应用程序需要指定配置设置，我可以在 Compose 文件中使用环境变量来包含这些设置。在 Compose 文件中为服务定义环境变量会为运行该服务的每个容器设置这些环境变量。

index-dinner 消息处理程序服务订阅 NATS 消息队列并在 Elasticsearch 中插入文档，因此它需要连接到相同的 Docker 网络，并且还依赖于这些服务。我可以在 Compose 文件中捕获这些依赖关系，并指定应用程序的配置。

```
nerd-dinner-index-handler:
  image: dockeronwindows/ch05-nerd-dinner-index-handler:2e
  environment:
   - Elasticsearch:Url=http://elasticsearch:9200
   - **MessageQueue:Url=nats://message-queue:4222
  depends_on:
   - elasticsearch
   - message-queue
  networks:
   - nd-net
```

在这里，我使用`environment`部分来指定两个环境变量——每个都有一个键值对——来配置消息队列和 Elasticsearch 的 URL。这实际上是默认值内置到消息处理程序镜像中的，所以我不需要在 Compose 文件中包含它们，但明确设置它们可能会有用。

您可以将 Compose 文件视为分布式解决方案的完整部署指南。如果您明确指定环境值，可以清楚地了解可用的配置选项，但这会使您的 Compose 文件变得不太可管理。

将配置变量存储为明文对于简单的应用程序设置来说是可以的，但对于敏感值，最好使用单独的环境文件，这是我在上一章中使用的方法。这也受到 Compose 文件格式的支持。对于数据库服务，我可以使用一个环境文件来指定管理员密码，使用`env-file`属性：

```
nerd-dinner-db:
  image: dockeronwindows/ch03-nerd-dinner-db:2e
 env_file:
   - **db-credentials.env
  volumes:
   - db-data:C:\data
  networks:
   - nd-net
```

当数据库服务启动时，Docker 将从名为`db-credentials.env`的文件中设置环境变量。我使用了相对路径，所以该文件需要与 Compose 文件在同一位置。与之前一样，该文件的内容是每个环境变量一行的键值对。在这个文件中，我包括了应用程序的连接字符串，以及数据库的密码，所以凭据都在一个地方：

```
sa_password=4jsZedB32!iSm__
ConnectionStrings:UsersContext=Data Source=nerd-dinner-db,1433;Initial Catalog=NerdDinner...
ConnectionStrings:NerdDinnerContext=Data Source=nerd-dinner-db,1433;Initial Catalog=NerdDinner...
```

敏感数据仍然是明文的，但通过将其隔离到一个单独的文件中，我可以做两件事：

+   首先，我可以保护文件以限制访问。

+   其次，我可以利用服务配置与应用程序定义的分离，并在不同环境中使用相同的 Docker Compose 文件，替换不同的环境文件。

环境变量即使你保护文件访问也不安全。当你检查一个容器时，你可以查看环境变量的值，所以任何有 Docker API 访问权限的人都可以读取这些数据。对于诸如密码和 API 密钥之类的敏感数据，你应该在 Docker Swarm 中使用 Docker secrets，这将在下一章中介绍。

对于 save-dinner 消息处理程序，我可以利用相同的环境文件来获取数据库凭据。处理程序依赖于消息队列和数据库服务，但在这个定义中没有新的属性：

```
nerd-dinner-save-handler:
  image: dockeronwindows/ch05-nerd-dinner-save-handler:2e
  depends_on:
   - nerd-dinner-db
   - message-queue
  env_file:
   - db-credentials.env
  networks:
   - nd-net
```

接下来是我的前端服务，它们由 Traefik 代理——REST API、新的主页和传统的 NerdDinner 网页应用。REST API 使用相同的凭据文件来配置 SQL Server 连接，并包括 Traefik 路由规则：

```
nerd-dinner-api:
  image: dockeronwindows/ch05-nerd-dinner-api:2e
  labels:
   - "traefik.frontend.rule=Host:api.nerddinner.local"
  env_file:
   - db-credentials.env
  networks:
   - nd-net
```

主页包括 Traefik 路由规则，还有一个高优先级值，以确保在 NerdDinner 网页应用使用的更一般的规则之前评估此规则：

```
nerd-dinner-homepage:
  image: dockeronwindows/ch03-nerd-dinner-homepage:2e
  labels:
   - "traefik.frontend.rule=Host:nerddinner.local;Path:/,/css/site.css"
   - "traefik.frontend.priority=10"
  networks:
   - nd-net
```

最后一个服务是网站本身。在这里，我正在使用环境变量和环境文件的组合。通常在各个环境中保持一致的变量值可以明确地说明配置，我正在为功能标志做到这一点。敏感数据可以从单独的文件中读取，本例中包含数据库凭据和 API 密钥：

```
nerd-dinner-web:
  image: dockeronwindows/ch05-nerd-dinner-web:2e
  labels:
   - "traefik.frontend.rule=Host:nerddinner.local;PathPrefix:/"
   - "traefik.frontend.priority=1"
 environment: 
   - HomePage:Enabled=false
   - DinnerApi:Enabled=true
  env_file:
   - api-keys.env
   - **db-credentials.env
  depends_on:
   - nerd-dinner-db
   - message-queue
  networks:
    - nd-net
```

网站容器不需要对外公开，因此不需要发布端口。应用程序需要访问其他服务，因此连接到同一个网络。

所有服务现在都已配置好，所以我只需要指定网络和卷资源，以完成 Compose 文件。

# 指定应用程序资源

Docker Compose 将网络和卷的定义与服务的定义分开，这允许在环境之间灵活性。我将在本章后面介绍这种灵活性，但为了完成 NerdDinner Compose 文件，我将从最简单的方法开始，使用默认值。

我的 Compose 文件中的所有服务都使用一个名为`nd-net`的网络，需要在 Compose 文件中指定。Docker 网络是隔离应用程序的好方法。您可以有几个解决方案都使用 Elasticsearch，但具有不同的 SLA 和存储要求。如果每个应用程序都有一个单独的网络，您可以在不同的 Docker 网络中运行单独配置的 Elasticsearch 服务，但所有都命名为`elasticsearch`。这保持了预期的约定，但通过网络进行隔离，因此服务只能看到其自己网络中的 Elasticsearch 实例。

Docker Compose 可以在运行时创建网络，或者您可以定义资源以使用主机上已经存在的外部网络。这个 NerdDinner 网络的规范使用了 Docker 在安装时创建的默认`nat`网络，因此这个设置将适用于所有标准的 Docker 主机：

```
networks:
  nd-net:
   external:
     name: nat
```

卷也需要指定。我的两个有状态服务，Elasticsearch 和 SQL Server，都使用命名卷进行数据存储：分别是`es-data`和`nd-data`。与其他网络一样，卷可以被指定为外部，因此 Docker Compose 将使用现有卷。Docker 不会创建任何默认卷，因此如果我使用外部卷，我需要在每个主机上运行应用程序之前创建它。相反，我将指定卷而不带任何选项，这样 Docker Compose 将为我创建它们：

```
volumes:
  es-data:
  db-data:
```

这些卷将在主机上存储数据，而不是在容器的可写层中。它们不是主机挂载的卷，因此尽管数据存储在本地磁盘上，但我没有指定位置。每个卷将在 Docker 数据目录`C:\ProgramData\Docker`中写入其数据。我将在本章后面看一下如何管理这些卷。

我的 Compose 文件已经指定了服务、网络和卷，所以它已经准备就绪。完整文件在本章的源代码`ch06\ch06-docker-compose`中。

# 使用 Docker Compose 管理应用程序

Docker Compose 提供了与 Docker CLI 类似的界面。`docker-compose`命令使用一些相同的命令名称和参数来支持其功能，这是完整 Docker CLI 功能的子集。当您通过 Compose CLI 运行命令时，它会向 Docker 引擎发送请求，以对 Compose 文件中的资源进行操作。

Docker Compose 文件是应用程序的期望状态。当您运行`docker-compose`命令时，它会将 Compose 文件与 Docker 中已经存在的对象进行比较，并进行任何必要的更改以达到期望的状态。这可能包括停止容器、启动容器或创建卷。

Compose 将 Compose 文件中的所有资源视为单个应用程序，并为了消除在同一主机上运行的应用程序的歧义，运行时会向为应用程序创建的所有资源添加项目名称。当您通过 Compose 运行应用程序，然后查看在主机上运行的容器时，您不会看到一个名称完全匹配服务名称的容器。Compose 会向容器名称添加项目名称和索引，以支持服务中的多个容器，但这不会影响 Docker 的 DNS 系统，因此容器仍然通过服务名称相互访问。

# 运行应用程序

我在`ch06-docker-compose`目录中有 NerdDinner 的第一个 Compose 文件，该目录还包含环境变量文件。从该目录，我可以使用单个`docker-compose`命令启动整个应用程序：

```
> docker-compose up -d
Creating ch06-docker-compose_message-queue_1        ... done
Creating ch06-docker-compose_nerd-dinner-api_1      ... done
Creating ch06-docker-compose_nerd-dinner-db_1            ... done
Creating ch06-docker-compose_nerd-dinner-homepage_1 ... done
Creating ch06-docker-compose_elasticsearch_1        ... done
Creating ch06-docker-compose_reverse-proxy_1        ... done
Creating ch06-docker-compose_kibana_1                    ... done
Creating ch06-docker-compose_nerd-dinner-index-handler_1 ... done
Creating ch06-docker-compose_nerd-dinner-web_1           ... done
Creating ch06-docker-compose_nerd-dinner-save-handler_1  ... done
```

让我们看一下前面命令的描述：

+   `up`命令用于启动应用程序，创建网络、卷和运行容器。

+   `-d`选项在后台运行所有容器，与`docker container run`中的`--detach`选项相同。

您可以看到 Docker Compose 遵守服务的`depends_on`设置。任何作为其他服务依赖项的服务都会首先创建。没有任何依赖项的服务将以随机顺序创建。在这种情况下，`message-queue`服务首先创建，因为许多其他服务依赖于它，而`nerd-dinner-web`和`nerd-dinner-save-handler`服务是最后创建的，因为它们有最多的依赖项。

输出中的名称是各个容器的名称，命名格式为`{project}_{service}_{index}`。每个服务只有一个运行的容器，这是默认的，所以索引都是`1`。项目名称是我运行`compose`命令的目录名称的经过清理的版本。

当您运行`docker-compose up`命令并完成后，您可以使用 Docker Compose 或标准的 Docker CLI 来管理容器。这些容器只是普通的 Docker 容器，compose 使用一些额外的元数据来将它们作为一个整体单元进行管理。列出容器会显示由`compose`创建的所有服务容器：

```
> docker container ls
CONTAINER ID   IMAGE                                      COMMAND                     
c992051ba468   dockeronwindows/ch05-nerd-dinner-web:2e   "powershell powershe…"
78f5ec045948   dockeronwindows/ch05-nerd-dinner-save-handler:2e          "NerdDinner.MessageH…"      
df6de70f61df  dockeronwindows/ch05-nerd-dinner-index-handler:2e  "dotnet NerdDinner.M…"      
ca169dd1d2f7  sixeyed/kibana:5.6.11-windowsservercore-ltsc2019   "powershell ./init.p…"      
b490263a6590  dockeronwindows/ch03-nerd-dinner-db:2e             "powershell -Command…"      
82055c7bfb05  sixeyed/elasticsearch:5.6.11-windowsservercore-ltsc2019   "cmd /S /C \".\\bin\\el…"   
22e2d5b8e1fa  dockeronwindows/ch03-nerd-dinner-homepage:2e       "dotnet NerdDinner.H…"     
 058248e7998c dockeronwindows/ch05-nerd-dinner-api:2e            "dotnet NerdDinner.D…"      
47a9e4d91682  sixeyed/traefik:v1.7.8-windowsservercore-ltsc2019  "/traefik --docker -…"      
cfd1ef3f5414  dockeronwindows/ch05-nats:2e              "gnatsd -c gnatsd.co…"
... 
```

运行 Traefik 的容器将端口`80`发布到本地计算机，并且我的 hosts 文件中有本地 NerdDinner 域的条目。NerdDinner 应用程序及其新首页、REST API 和 Kibana 分析将按预期运行，因为所有配置都包含在 Compose 文件中，并且所有组件都由 Docker Compose 启动。

这是 Compose 文件格式中最强大的功能之一。该文件包含了运行应用程序的完整规范，任何人都可以使用它来运行您的应用程序。在这种情况下，所有组件都使用 Docker Hub 上的公共 Docker 镜像，因此任何人都可以从这个 Compose 文件启动应用程序。您只需要 Docker 和 Docker Compose 来运行 NerdDinner，它现在是一个包含.NET Framework、.NET Core、Java、Go 和 Node.js 组件的分布式应用程序。

# 扩展应用程序服务

Docker Compose 让您轻松地扩展服务，向正在运行的服务添加或删除容器。当一个服务使用多个容器运行时，它仍然可以被网络中的其他服务访问。消费者使用服务名称进行发现，Docker 中的 DNS 服务器会在所有服务的容器之间平衡请求。

然而，添加更多的容器并不会自动为您的服务提供规模和弹性；这取决于运行服务的应用程序。只是向 SQL 数据库服务添加另一个容器并不会自动给您提供 SQL Server 故障转移集群，因为 SQL Server 需要显式配置故障转移。如果您添加另一个容器，您将只有两个具有单独数据存储的不同数据库实例。

Web 应用程序通常在设计时支持横向扩展时可以很好地扩展。无状态应用程序可以在任意数量的容器中运行，因为任何容器都可以处理任何请求。但是，如果您的应用程序在本地维护会话状态，则来自同一用户的请求需要由同一服务处理，这将阻止您在许多容器之间进行负载平衡，除非您使用粘性会话。

将端口发布到主机的服务，如果它们在单个 Docker 引擎上运行，则无法扩展。端口只能有一个操作系统进程在其上监听，对于 Docker 也是如此——您不能将相同的主机端口映射到多个容器端口。在具有多个主机的 Docker Swarm 上，您可以扩展具有发布端口的服务，Docker 将在不同的主机上运行每个容器。

在 NerdDinner 中，消息处理程序是真正无状态的组件。它们从包含它们所需的所有信息的队列中接收消息，然后对其进行处理。NATS 支持在同一消息队列上对订阅者进行分组，这意味着我可以运行几个包含 save-dinner 处理程序的容器，并且 NATS 将确保只有一个处理程序获得每条消息的副本，因此我不会有重复的消息处理。消息处理程序中的代码已经利用了这一点。

扩展消息处理程序是我在高峰时期可以做的事情，以增加消息处理的吞吐量。我可以使用`up`命令和`--scale`选项来做到这一点，指定服务名称和所需的实例数量：

```
> docker-compose up -d --scale nerd-dinner-save-handler=3

ch06-docker-compose_elasticsearch_1 is up-to-date
ch06-docker-compose_nerd-dinner-homepage_1 is up-to-date
ch06-docker-compose_message-queue_1 is up-to-date
ch06-docker-compose_nerd-dinner-db_1 is up-to-date
ch06-docker-compose_reverse-proxy_1 is up-to-date
ch06-docker-compose_nerd-dinner-api_1 is up-to-date
Starting ch06-docker-compose_nerd-dinner-save-handler_1 ...
ch06-docker-compose_kibana_1 is up-to-date
ch06-docker-compose_nerd-dinner-web_1 is up-to-date
Creating ch06-docker-compose_nerd-dinner-save-handler_2 ... done
Creating ch06-docker-compose_nerd-dinner-save-handler_3 ... done
```

Docker Compose 将运行应用程序的状态与 Compose 文件中的配置和命令中指定的覆盖进行比较。在这种情况下，除了 save-dinner 处理程序之外，所有服务都保持不变，因此它们被列为`up-to-date`。save-handler 具有新的服务级别，因此 Docker Compose 创建了两个更多的容器。

有三个 save-message 处理程序实例运行时，它们以循环方式共享传入消息负载。这是增加规模的好方法。处理程序同时处理消息并写入 SQL 数据库，这增加了保存的吞吐量并减少了处理消息所需的时间。但对于写入 SQL Server 的进程数量仍然有严格的限制，因此数据库不会成为此功能的瓶颈。

我可以通过 web 应用程序创建多个晚餐，当事件消息被发布时，消息处理程序将共享负载。我可以在日志中看到不同的处理程序处理不同的消息，并且没有重复处理事件：

```
> docker container logs ch06-docker-compose_nerd-dinner-save-handler_1
Connecting to message queue url: nats://message-queue:4222
Listening on subject: events.dinner.created, queue: save-dinner-handler
Received message, subject: events.dinner.created
Saving new dinner, created at: 2/12/2019 11:22:47 AM; event ID: 60f8b653-f456-4bb1-9ccd-1253e9a222b6
Dinner saved. Dinner ID: 1; event ID: 60f8b653-f456-4bb1-9ccd-1253e9a222b6
...

> docker container logs ch06-docker-compose_nerd-dinner-save-handler_2
Connecting to message queue url: nats://message-queue:4222
Listening on subject: events.dinner.created, queue: save-dinner-handler
Received message, subject: events.dinner.created
Saving new dinner, created at: 2/12/2019 11:25:00 AM; event ID: 5f6d017e-a66b-4887-8fd5-ac053a639a6d
Dinner saved. Dinner ID: 5; event ID: 5f6d017e-a66b-4887-8fd5-ac053a639a6d

> docker container logs ch06-docker-compose_nerd-dinner-save-handler_3
Connecting to message queue url: nats://message-queue:4222
Listening on subject: events.dinner.created, queue: save-dinner-handler
Received message, subject: events.dinner.created
Saving new dinner, created at: 2/12/2019 11:24:55 AM; event ID: 8789179b-c947-41ad-a0e4-6bde7a1f2614
Dinner saved. Dinner ID: 4; event ID: 8789179b-c947-41ad-a0e4-6bde7a1f2614
```

我正在单个 Docker 引擎上运行，所以无法扩展 Traefik 服务，因为只能发布一个容器到端口`80`。但我可以扩展 Traefik 代理的前端容器，这是测试我的应用程序在扩展到多个实例时是否正常工作的好方法。我将再添加两个原始 NerdDinner web 应用程序的实例：

```
> docker-compose up -d --scale nerd-dinner-web=3
ch06-docker-compose_message-queue_1 is up-to-date
...
Stopping and removing ch06-docker-compose_nerd-dinner-save-handler_2 ... done
Stopping and removing ch06-docker-compose_nerd-dinner-save-handler_3 ... done
Creating ch06-docker-compose_nerd-dinner-web_2                       ... done
Creating ch06-docker-compose_nerd-dinner-web_3                       ... done
Starting ch06-docker-compose_nerd-dinner-save-handler_1              ... done
```

仔细看这个输出——发生了一些正确的事情，但并不是我想要的。Compose 已经创建了两个新的 NerdDinner web 容器，以满足我指定的规模为 3，但它也停止并移除了两个 save-handler 容器。

这是因为 Compose 隐式地使用我的`docker-compose.yml`文件作为应用程序定义，该文件使用每个服务的单个实例。然后它从 web 服务的命令中添加了规模值，并构建了一个期望的状态，即每个服务应该有一个正在运行的容器，除了 web 服务应该有三个。它发现 web 服务只有一个容器，所以创建了另外两个。它发现 save-handler 有三个容器，所以移除了两个。

混合 Compose 文件定义和命令的更改是不推荐的，正是因为这种情况。Compose 文件本身应该是应用程序的期望状态。但在这种情况下，您无法在 Compose 文件中指定规模选项（在旧版本中可以，但从规范的 v3 开始不行），因此您需要显式地为所有服务添加规模级别：

```
docker-compose up -d --scale nerd-dinner-web=3 --scale nerd-dinner-save-handler=3
```

现在我有三个 save-handler 容器，它们正在共享消息队列的工作，还有三个 web 容器。Traefik 将在这三个 web 容器之间负载均衡请求。我可以从 Traefik 仪表板上检查该配置，我已经发布在端口`8080`上：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/dc786f47-93ea-4ef3-a5dc-2bb67d24bacd.png)

Traefik 在左侧以蓝色框显示前端路由规则，以绿色框显示它们映射到的后端服务。对于`nerddinner.local`有一个路径前缀为`/`的前端路由规则，它将所有流量发送到`nerd-dinner-web`后端（除了首页，它有不同的规则）。后端显示有三个列出的服务器，它们是我用 Docker Compose 扩展的三个容器。`172.20.*.*`服务器地址是 Docker 网络上的内部 IP 地址，容器可以用来通信。

我可以浏览 NerdDinner 应用程序，并且它可以正确运行，Traefik 会在后端容器之间负载均衡请求。但是，一旦我尝试登录，我会发现 NerdDinner 并不是设计为扩展到多个实例：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/3819e3df-ac67-4493-9326-587e96033019.png)

该错误消息告诉我，NerdDinner 希望一个用户的所有请求都由 web 应用程序的同一实例处理。Traefik 支持粘性会话，正是为了解决这种情况，因此要解决这个问题，我只需要在 Compose 文件中的 web 服务定义中添加一个新的标签。这将为 NerdDinner 后端启用粘性会话：

```
nerd-dinner-web:
  image: dockeronwindows/ch05-nerd-dinner-web:2e
  labels:
   - "traefik.frontend.rule=Host:nerddinner.local;PathPrefix:/"
   - "traefik.frontend.priority=1"
   - "traefik.backend.loadbalancer.stickiness=true"
```

现在我可以再次部署，确保包括我的规模参数：

```
> docker-compose up -d --scale nerd-dinner-web=3 --scale nerd-dinner-save-handler=3
ch06-docker-compose_message-queue_1 is up-to-date
...
Recreating ch06-docker-compose_nerd-dinner-web_1 ... done
Recreating ch06-docker-compose_nerd-dinner-web_2 ... done
Recreating ch06-docker-compose_nerd-dinner-web_3 ... done
```

Compose 重新创建 web 服务容器，删除旧容器，并使用新配置启动新容器。现在，Traefik 正在使用粘性会话，因此我的浏览器会话中的每个请求都将发送到相同的容器。Traefik 使用自定义 cookie 来实现这一点，该 cookie 指定请求应路由到的容器 IP 地址：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/d8aba133-97bc-4aa2-bdea-94bf34bd68d6.png)

在这种情况下，cookie 被称为`_d18b8`，它会将所有我的请求定向到具有 IP 地址`172.20.26.74`的容器。

在规模运行时发现问题以前只会发生在测试环境，甚至在生产环境中。在 Docker 中运行所有内容意味着我可以在我的开发笔记本上测试应用程序的功能，以便在发布之前发现这些问题。使用现代技术，如 Traefik，也意味着有很好的方法来解决这些问题，而无需更改我的传统应用程序。

# 停止和启动应用程序服务

Docker Compose 中有几个管理容器生命周期的命令。重要的是要理解选项之间的区别，以免意外删除资源。

`up`和`down`命令是启动和停止整个应用程序的粗糙工具。`up`命令创建 Compose 文件中指定的任何不存在的资源，并为所有服务创建和启动容器。`down`命令则相反-它停止任何正在运行的容器并删除应用程序资源。如果是由 Docker Compose 创建的容器和网络，则会被删除，但卷不会被删除-因此您拥有的任何应用程序数据都将被保留。

`stop`命令只是停止所有正在运行的容器，而不会删除它们或其他资源。停止容器会以优雅的方式结束运行的进程。可以使用`start`再次启动已停止的应用程序容器，它会在现有容器中运行入口点程序。

停止的容器保留其所有配置和数据，但它们不使用任何计算资源。启动和停止容器是在多个项目上工作时切换上下文的非常有效的方式。如果我在 NerdDinner 上开发，当另一个工作作为优先级而来时，我可以停止整个 NerdDinner 应用程序来释放我的开发环境：

```
> docker-compose stop
Stopping ch06-docker-compose_nerd-dinner-web_2           ... done
Stopping ch06-docker-compose_nerd-dinner-web_1           ... done
Stopping ch06-docker-compose_nerd-dinner-web_3           ... done
Stopping ch06-docker-compose_nerd-dinner-save-handler_3  ... done
Stopping ch06-docker-compose_nerd-dinner-save-handler_2  ... done
Stopping ch06-docker-compose_nerd-dinner-save-handler_1  ... done
Stopping ch06-docker-compose_nerd-dinner-index-handler_1 ... done
Stopping ch06-docker-compose_kibana_1                    ... done
Stopping ch06-docker-compose_reverse-proxy_1             ... done
Stopping ch06-docker-compose_nerd-dinner-homepage_1      ... done
Stopping ch06-docker-compose_nerd-dinner-db_1            ... done
Stopping ch06-docker-compose_nerd-dinner-api_1           ... done
Stopping ch06-docker-compose_elasticsearch_1             ... done
Stopping ch06-docker-compose_message-queue_1             ... done
```

现在我没有运行的容器，我可以切换到另一个项目。当工作完成时，我可以通过运行`docker-compose start`再次启动 NerdDinner。

您还可以通过指定名称来停止单个服务，如果您想测试应用程序如何处理故障，这将非常有用。我可以通过停止 Elasticsearch 服务来检查索引晚餐处理程序在无法访问 Elasticsearch 时的行为：

```
> docker-compose stop elasticsearch
Stopping ch06-docker-compose_elasticsearch_1 ... done
```

所有这些命令都是通过将 Compose 文件与在 Docker 中运行的服务进行比较来处理的。你需要访问 Docker Compose 文件才能运行任何 Docker Compose 命令。这是在单个主机上使用 Docker Compose 运行应用程序的最大缺点之一。另一种选择是使用相同的 Compose 文件，但将其部署为 Docker Swarm 的堆栈，我将在下一章中介绍。

`stop`和`start`命令使用 Compose 文件，但它们作用于当前存在的容器，而不仅仅是 Compose 文件中的定义。因此，如果你扩展了一个服务，然后停止整个应用程序，然后再次启动它——你仍然会拥有你扩展的所有容器。只有`up`命令使用 Compose 文件将应用程序重置为所需的状态。

# 升级应用程序服务

如果你从同一个 Compose 文件重复运行`docker compose up`，在第一次运行之后不会进行任何更改。Docker Compose 会将 Compose 文件中的配置与运行时的活动容器进行比较，并且不会更改资源，除非定义已经改变。这意味着你可以使用 Docker Compose 来管理应用程序的升级。

我的 Compose 文件目前正在使用我在第三章中构建的数据库服务的镜像，*开发 Docker 化的.NET Framework 和.NET Core 应用程序*，标记为`dockeronwindows/ch03-nerd-dinner-db:2e`。对于本章，我已经在数据库架构中添加了审计字段，并构建了一个新版本的数据库镜像，标记为`dockeronwindows/ch06-nerd-dinner-db:2e`。

我在同一个`ch06-docker-compose`目录中有第二个 Compose 文件，名为`docker-compose-db-upgrade.yml`。升级文件不是完整的应用程序定义；它只包含数据库服务定义的一个部分，使用新的镜像标签：

```
version: '3.7' services:
  nerd-dinner-db:
  image: dockeronwindows/ch06-nerd-dinner-db:2e
```

Docker Compose 支持覆盖文件。你可以运行`docker-compose`命令并将多个 Compose 文件作为参数传递。Compose 将按照命令中指定的顺序从左到右将所有文件合并在一起。覆盖文件可以用于向应用程序定义添加新的部分，或者可以替换现有的值。

当应用程序正在运行时，我可以再次执行`docker compose up`，同时指定原始 Compose 文件和`db-upgrade`覆盖文件：

```
> docker-compose `
   -f docker-compose.yml `
   -f docker-compose-db-upgrade.yml `
  up -d 
ch06-docker-compose_reverse-proxy_1 is up-to-date
ch06-docker-compose_nerd-dinner-homepage_1 is up-to-date
ch06-docker-compose_elasticsearch_1 is up-to-date
ch06-docker-compose_message-queue_1 is up-to-date
ch06-docker-compose_kibana_1 is up-to-date
Recreating ch06-docker-compose_nerd-dinner-db_1 ... done
Recreating ch06-docker-compose_nerd-dinner-web_1          ... done
Recreating ch06-docker-compose_nerd-dinner-save-handler_1 ... done
Recreating ch06-docker-compose_nerd-dinner-api_1          ... done
```

该命令使用`db-upgrade`文件作为主`docker-compose.yml`文件的覆盖。Docker Compose 将它们合并在一起，因此最终的服务定义包含原始文件中的所有值，除了来自覆盖的镜像规范。新的服务定义与 Docker 中正在运行的内容不匹配，因此 Compose 重新创建数据库服务。

Docker Compose 通过移除旧容器并启动新容器来重新创建服务，使用新的镜像规范。不依赖于数据库的服务保持不变，日志条目为`up-to-date`，任何依赖于数据库的服务在新的数据库容器运行后也会被重新创建。

我的数据库容器使用了我在第三章中描述的模式，使用卷存储数据和一个脚本，可以在容器被替换时升级数据库模式。在 Compose 文件中，我使用了一个名为`db-data`的卷的默认定义，因此 Docker Compose 为我创建了它。就像 Compose 创建的容器一样，卷是标准的 Docker 资源，可以使用 Docker CLI 进行管理。`docker volume ls`列出主机上的所有卷：

```
> docker volume ls

DRIVER  VOLUME NAME
local   ch06-docker-compose_db-data
local   ch06-docker-compose_es-data
```

我有两个卷用于我的 NerdDinner 部署。它们都使用本地驱动程序，这意味着数据存储在本地磁盘上。我可以检查 SQL Server 卷，看看数据在主机上的物理存储位置（在`Mountpoint`属性中），然后检查内容以查看数据库文件：

```
> docker volume inspect -f '{{ .Mountpoint }}' ch06-docker-compose_db-data
C:\ProgramData\docker\volumes\ch06-docker-compose_db-data\_data

> ls C:\ProgramData\docker\volumes\ch06-docker-compose_db-data\_data

    Directory: C:\ProgramData\docker\volumes\ch06-docker-compose_db-data\_data

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       12/02/2019     13:47        8388608 NerdDinner_Primary.ldf
-a----       12/02/2019     13:47        8388608 NerdDinner_Primary.mdf
```

卷存储在容器之外，因此当 Docker Compose 移除旧容器数据库时，所有数据都得到保留。新的数据库镜像捆绑了一个 Dacpac，并配置为对现有数据文件进行模式升级，方式与第三章中的 SQL Server 数据库相同，*开发 Docker 化的.NET Framework 和.NET Core 应用*。

新容器启动后，我可以检查日志，看到新容器从卷中附加了数据库文件，然后修改了 Dinners 表以添加新的审计列：

```
> docker container logs ch06-docker-compose_nerd-dinner-db_1

VERBOSE: Starting SQL Server
VERBOSE: Changing SA login credentials
VERBOSE: Data files exist - will attach and upgrade database
Generating publish script for database 'NerdDinner' on server '.\SQLEXPRESS'.
Successfully generated script to file C:\init\deploy.sql.
VERBOSE: Changed database context to 'NerdDinner'.
VERBOSE: Altering [dbo].[Dinners]...
VERBOSE: Update complete.
VERBOSE: Deployed NerdDinner database, data files at: C:\data
```

新的审计列在更新行时添加了时间戳，因此现在当我通过 Web UI 创建晚餐时，我可以看到数据库中上次更新行的时间。在我的开发环境中，我还没有为客户端连接发布 SQL Server 端口，但我可以运行`docker container inspect`来获取容器的本地 IP 地址。然后我可以直接连接我的 SQL 客户端到容器并运行查询以查看新的审计时间戳：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/eb36d243-f04d-4ed7-a10c-cad9ea1d5188.png)

Docker Compose 寻找资源及其定义之间的任何差异，而不仅仅是 Docker 镜像的名称。如果更改环境变量、端口映射、卷设置或任何其他配置，Docker Compose 将删除或创建资源，以将运行的应用程序带到所需的状态。

修改 Compose 文件以运行应用程序时需要小心。如果从文件中删除正在运行的服务的定义，Docker Compose 将不会识别现有的服务容器是应用程序的一部分，因此它们不会包含在差异检查中。您可能会遇到孤立的服务容器。

# 监视应用程序容器

将分布式应用程序视为单个单元可以更容易地监视和跟踪问题。Docker Compose 提供了自己的`top`和`logs`命令，这些命令可以在应用程序服务的所有容器上运行，并显示收集的结果。

要检查所有组件的内存和 CPU 使用情况，请运行`docker-compose top`：

```
> docker-compose top

ch06-docker-compose_elasticsearch_1
Name          PID     CPU            Private Working Set
---------------------------------------------------------
smss.exe      21380   00:00:00.046   368.6kB
csrss.exe     11232   00:00:00.359   1.118MB
wininit.exe   16328   00:00:00.093   1.196MB
services.exe  15180   00:00:00.359   1.831MB
lsass.exe     12368   00:00:01.156   3.965MB
svchost.exe   18424   00:00:00.156   1.626MB
...
```

容器按名称按字母顺序列出，每个容器中的进程没有特定的顺序列出。无法更改排序方式，因此无法首先显示最密集的进程所在的最努力工作的容器，但结果是以纯文本形式呈现的，因此可以在 PowerShell 中对其进行操作。

要查看所有容器的日志条目，请运行`docker-compose logs`：

```
> docker-compose logs
Attaching to ch06-docker-compose_nerd-dinner-web_1, ch06-docker-compose_nerd-dinner-save-handler_1, ch06-docker-compose_nerd-dinner-api_1, ch06-docker-compose_nerd-dinner-db_1, ch06-docker-compose_kibana_1, ch06-docker-compose_nerd-dinner-index-handler_1, ch06-docker-compose_reverse-proxy_1, ch06-docker-compose_elasticsearch_1, ch06-docker-compose_nerd-dinner-homepage_1, ch06-docker-compose_message-queue_1

nerd-dinner-web_1   | 2019-02-12 13:47:11 W3SVC1002144328 127.0.0.1 GET / - 80 - 127.0.0.1 Mozilla/5.0+(Windows+NT;+Windows+NT+10.0;+en-US)+WindowsPowerShell/5.1.17763.134 - 200 0 0 7473
nerd-dinner-web_1   | 2019-02-12 13:47:14 W3SVC1002144328 ::1 GET / - 80 - ::1 Mozilla/5.0+(Windows+NT;+Windows+NT+10.0;+en-US)+WindowsPowerShell/5.1.17763.134 - 200 0 0 9718
...
```

在屏幕上，容器名称以颜色编码，因此您可以轻松区分来自不同组件的条目。通过 Docker Compose 阅读日志的一个优势是，它显示所有容器的输出，即使组件显示错误并且容器已停止。这些错误消息对于在上下文中查看很有用-您可能会看到一个组件在另一个组件记录其已启动之前抛出连接错误，这可能突出了 Compose 文件中缺少的依赖关系。

Docker Compose 显示所有服务容器的所有日志条目，因此输出可能很多。您可以使用`--tail`选项限制输出，将输出限制为每个容器的指定数量的最近日志条目。

这些命令在开发或在单个服务器上运行少量容器的低规模项目中非常有用。对于在 Docker Swarm 上运行的跨多个主机的大型项目，它不具备可扩展性。对于这些项目，您需要以容器为中心的管理和监控，我将在第八章中进行演示，*管理和监控 Docker 化解决方案*。

# 管理应用程序图像

Docker Compose 可以管理 Docker 图像，以及容器。在 Compose 文件中，您可以包括属性，告诉 Docker Compose 如何构建您的图像。您可以指定要发送到 Docker 服务的构建上下文的位置，这是所有应用程序内容的根文件夹，以及 Dockerfile 的位置。

上下文路径是相对于 Compose 文件的位置，而 Dockerfile 路径是相对于上下文的。这对于复杂的源树非常有用，比如本书的演示源，其中每个图像的上下文位于不同的文件夹中。在`ch06-docker-compose-build`文件夹中，我有一个完整的 Compose 文件，其中包含了应用程序规范，包括指定的构建属性。

这是我为我的图像指定构建细节的方式：

```
nerd-dinner-db:
  image: dockeronwindows/ch06-nerd-dinner-db:2e
 build:
    context: ../ch06-nerd-dinner-db
    dockerfile: **./Dockerfile** ...
nerd-dinner-save-handler: image: dockeronwindows/ch05-nerd-dinner-save-handler:2e build: context: ../../ch05 dockerfile: ./ch05-nerd-dinner-save-handler/Dockerfile
```

当您运行`docker-compose build`时，任何具有指定`build`属性的服务将被构建并标记为`image`属性中的名称。构建过程使用正常的 Docker API，因此仍然使用图像层缓存，只重新构建更改的层。向 Compose 文件添加构建细节是构建所有应用程序图像的一种非常有效的方式，也是捕获图像构建方式的中心位置。

Docker Compose 的另一个有用功能是能够管理整个图像组。本章的 Compose 文件使用的图像都是在 Docker Hub 上公开可用的，因此您可以使用`docker-compose up`运行完整的应用程序，但第一次运行时，所有图像都将被下载，这将需要一些时间。您可以在使用`docker-compose pull`之前预加载图像，这将拉取所有图像：

```
> docker-compose pull
Pulling message-queue             ... done
Pulling elasticsearch             ... done
Pulling reverse-proxy             ... done
Pulling kibana                    ... done
Pulling nerd-dinner-db            ... done
Pulling nerd-dinner-save-handler  ... done
Pulling nerd-dinner-index-handler ... done
Pulling nerd-dinner-api           ... done
Pulling nerd-dinner-homepage      ... done
Pulling nerd-dinner-web           ... done
```

同样，您可以使用`docker-compose push`将图像上传到远程存储库。对于这两个命令，Docker Compose 使用最近`docker login`命令的经过身份验证的用户。如果您的 Compose 文件包含您无权推送的图像，这些推送将失败。对于您有写入权限的任何存储库，无论是在 Docker Hub 还是私有注册表中，这些图像都将被推送。

# 配置应用程序环境

当您在 Docker Compose 中定义应用程序时，您有一个描述应用程序所有组件和它们之间集成点的单个工件。这通常被称为**应用程序清单**，它是列出应用程序所有部分的文档。就像 Dockerfile 明确定义了安装和配置软件的步骤一样，Docker Compose 文件明确定义了部署整个解决方案的步骤。

Docker Compose 还允许您捕获可以部署到不同环境的应用程序定义，因此您的 Compose 文件可以在整个部署流程中使用。通常，环境之间存在差异，无论是在基础设施设置还是应用程序设置方面。Docker Compose 为您提供了两种选项来管理这些环境差异——使用外部资源或使用覆盖文件。

基础设施通常在生产和非生产环境之间有所不同，这影响了 Docker 应用程序中的卷和网络。在开发笔记本电脑上，您的数据库卷可能映射到本地磁盘上的已知位置，您会定期清理它。在生产环境中，您可以为共享存储硬件设备使用卷插件。同样，对于网络，生产环境可能需要明确指定子网范围，而这在开发中并不是一个问题。

Docker Compose 允许您将资源指定为 Compose 文件之外的资源，因此应用程序将使用已经存在的资源。这些资源需要事先创建，但这意味着每个环境可以被不同配置，但仍然使用相同的 Compose 文件。

Compose 还支持另一种方法，即在不同的 Compose 文件中明确捕获每个环境的资源配置，并在运行应用程序时使用多个 Compose 文件。我将演示这两种选项。与其他设计决策一样，Docker 不会强加特定的实践，您可以使用最适合您流程的任何方法。

# 指定外部资源

Compose 文件中的卷和网络定义遵循与服务定义相同的模式——每个资源都有名称，并且可以使用与相关的`docker ... create`命令中可用的相同选项进行配置。Compose 文件中有一个额外的选项，可以指向现有资源。

为了使用现有卷来存储我的 SQL Server 和 Elasticsearch 数据，我需要指定`external`属性，以及可选的资源名称。在`ch06-docker-compose-external`目录中，我的 Docker Compose 文件具有这些卷定义：

```
volumes:
  es-data:
 external: 
      name: nerd-dinner-elasticsearch-data

  db-data:
 external: 
      name: nerd-dinner-database-data
```

声明外部资源后，我不能只使用`docker-compose up`来运行应用程序。Compose 不会创建定义为外部的卷；它们需要在应用程序启动之前存在。而且这些卷是服务所必需的，因此 Docker Compose 也不会创建任何容器。相反，您会看到一个错误消息：

```
> docker-compose up -d

ERROR: Volume nerd-dinner-elasticsearch-data declared as external, but could not be found. Please create the volume manually using `docker volume create --name=nerd-dinner-elasticsearch-data` and try again.
```

错误消息告诉您需要运行的命令来创建缺失的资源。这将使用默认配置创建基本卷，这将允许 Docker Compose 启动应用程序：

```
docker volume create --name nerd-dinner-elasticsearch-data
docker volume create --name nerd-dinner-database-data
```

Docker 允许您使用不同的配置选项创建卷，因此您可以指定显式的挂载点，例如 RAID 阵列或 NFS 共享。Windows 目前不支持本地驱动器的选项，但您可以使用映射驱动器作为解决方法。还有其他类型存储的驱动程序——使用云服务的卷插件，例如 Azure 存储，以及企业存储单元，例如 HPE 3PAR。

可以使用相同的方法来指定网络作为外部资源。在我的 Compose 文件中，我最初使用默认的`nat`网络，但在这个 Compose 文件中，我为应用程序指定了一个自定义的外部网络：

```
networks:
  nd-net:
    external:
 name: nerd-dinner-network
```

Windows 上的 Docker 有几个网络选项。默认和最简单的是网络地址转换，使用`nat`网络。这个驱动器将容器与物理网络隔离，每个容器在 Docker 管理的子网中都有自己的 IP 地址。在主机上，您可以通过它们的 IP 地址访问容器，但在主机外部，您只能通过发布的端口访问容器。

您可以使用`nat`驱动程序创建其他网络，或者您还可以使用其他驱动程序进行不同的网络配置：

+   `transparent`驱动器，为每个容器提供物理路由器提供的 IP 地址

+   `l2bridge`驱动器，用于在物理网络上指定静态容器 IP 地址

+   `overlay`驱动器，用于在 Docker Swarm 中运行分布式应用程序

对于我在单个服务器上使用 Traefik 的设置，`nat`是最佳选项，因此我将为我的应用程序创建一个自定义网络：

```
docker network create -d nat nerd-dinner-network
```

当容器启动时，我可以使用我在`hosts`文件中设置的`nerddinner.local`域来访问 Traefik。

使用外部资源可以让您拥有一个单一的 Docker Compose 文件，该文件用于每个环境，网络和卷资源的实际实现在不同环境之间有所不同。开发人员可以使用基本的存储和网络选项，在生产环境中，运维团队可以部署更复杂的基础设施。

# 使用 Docker Compose 覆盖

资源并不是环境之间唯一变化的东西。您还将有不同的配置设置，不同的发布端口，不同的容器健康检查设置等。对于每个环境拥有完全不同的 Docker Compose 文件可能很诱人，但这是您应该努力避免的事情。

拥有多个 Compose 文件意味着额外的开销来保持它们同步 - 更重要的是，如果它们不保持同步，环境漂移的风险。使用 Docker Compose 覆盖可以解决这个问题，并且意味着每个环境的要求都是明确说明的。

Docker Compose 默认寻找名为`docker-compose.yml`和`docker-compose.override.yml`的文件，如果两者都找到，它将使用覆盖文件来添加或替换主 Docker Compose 文件中的定义的部分。当您运行 Docker Compose CLI 时，可以传递其他文件以组合整个应用程序规范。这使您可以将核心解决方案定义保存在一个文件中，并在其他文件中具有明确的环境相关覆盖。

在`ch06-docker-compose-override`文件夹中，我采取了这种方法。核心的`docker-compose.yml`文件包含了描述解决方案结构和运行开发环境的环境配置的服务定义。在同一个文件夹中有三个覆盖文件：

+   `docker-compose.test.yml`添加了用于测试环境的配置设置。

+   `docker-compose.production.yml`添加了用于生产环境的配置设置。

+   `docker-compose.build.yml`添加了用于构建图像的配置设置。

标准的`docker-compose.yml`文件可以单独使用，它会正常工作。这很重要，以确保部署过程不会给开发人员带来困难。在主文件中指定开发设置意味着开发人员只需运行`docker-compose up -d`，因为他们不需要了解任何关于覆盖的信息就可以开始工作。

这是`docker-compose.yml`中的反向代理配置，并且设置为发布随机端口并启动 Traefik 仪表板：

```
reverse-proxy:
  image: sixeyed/traefik:v1.7.8-windowsservercore-ltsc2019
  command: --docker --docker.endpoint=npipe:////./pipe/docker_engine --api
  ports:
   - "80"
   - "8080"
  volumes:
   - type: npipe
      source: \\.\pipe\docker_engine 
      target: \\.\pipe\docker_engine  networks:
  - nd-net
```

这对于可能正在为其他应用程序使用端口`80`的开发人员以及希望深入了解仪表板以查看 Traefik 的路由规则的开发人员非常有用。`test`覆盖文件将端口定义更改为在主机服务器上使用`80`和`8080`，但仪表板仍然暴露，因此命令部分保持不变：

```
reverse-proxy:
  ports:
   - "80:80"
   - "8080:8080"
```

`production`覆盖更改了启动命令，删除了命令中的`--api`标志，因此仪表板不会运行，它只发布端口`80`：

```
reverse-proxy:
  command: --docker --docker.endpoint=npipe:////./pipe/docker_engine
  ports:
   - "80:80"
```

服务配置的其余部分，要使用的图像，Docker Engine 命名管道的卷挂载和要连接的网络在每个环境中都是相同的，因此覆盖文件不需要指定它们。

另一个例子是新的主页，其中包含了 Traefik 标签中的 URL 的域名。这是特定于环境的，在开发 Docker Compose 文件中，它被设置为使用`nerddinner.local`：

```
nerd-dinner-homepage:
  image: dockeronwindows/ch03-nerd-dinner-homepage:2e
  labels:
   - "traefik.frontend.rule=Host:nerddinner.local;Path:/,/css/site.css"
   - "traefik.frontend.priority=10"
  networks:
   - nd-net
```

在`test`覆盖文件中，域是`nerd-dinner.test`：

```
nerd-dinner-homepage:
  labels:
   - "traefik.frontend.rule=Host:nerd-dinner.test;Path:/,/css/site.css"
   - "traefik.frontend.priority=10"
```

在生产中，是`nerd-dinner.com`：

```
nerd-dinner-homepage:
  labels:
 - "traefik.frontend.rule=Host:nerd-dinner.com;Path:/,/css/site.css"
 - "traefik.frontend.priority=10"
```

在每个环境中，其余配置都是相同的，因此覆盖文件只指定新标签。

Docker Compose 在添加覆盖时不会合并列表的内容；新列表完全替换旧列表。这就是为什么每个文件中都有`traefik.frontend.priority`标签，因此您不能只在覆盖文件中的标签中有前端规则值，因为优先级值不会从主文件中的标签中合并过来。

在覆盖文件中捕获了测试环境中的其他差异：

+   SQL Server 和 Elasticsearch 端口被发布，以帮助故障排除。

+   数据库的卷从服务器上的`E:`驱动器上的路径挂载，这是服务器上的 RAID 阵列。

+   Traefik 规则都使用`nerd-dinner.test`域。

+   应用程序网络被指定为外部，以允许管理员创建他们自己的网络配置。

这些在生产覆盖文件中又有所不同：

+   SQL Server 和 Elasticsearch 端口不被发布，以保持它们作为私有组件。

+   数据库的卷被指定为外部，因此管理员可以配置他们自己的存储。

+   Traefik 规则都使用`nerd-dinner.com`域。

+   应用程序网络被指定为外部，允许管理员创建他们自己的网络配置。

部署到任何环境都可以简单地运行`docker-compose up`，指定要使用的覆盖文件：

```
docker-compose `
  -f docker-compose.yml `
  -f docker-compose.production.yml `
 up -d
```

这种方法是保持 Docker Compose 文件简单的好方法，并在单独的文件中捕获所有可变环境设置。甚至可以组合几个 Docker Compose 文件。如果有多个共享许多共同点的测试环境，可以在基本 Compose 文件中定义应用程序设置，在一个覆盖文件中共享测试配置，并在另一个覆盖文件中定义每个特定的测试环境。

# 总结

在本章中，我介绍了 Docker Compose，这是用于组织分布式 Docker 解决方案的工具。使用 Compose，您可以明确定义解决方案的所有组件、组件的配置以及它们之间的关系，格式简单、清晰。

Compose 文件让您将所有应用程序容器作为单个单元进行管理。您在本章中学习了如何使用`docker-compose`命令行来启动和关闭应用程序，创建所有资源并启动或停止容器。您还了解到，您可以使用 Docker Compose 来扩展组件或发布升级到您的解决方案。

Docker Compose 是定义复杂解决方案的强大工具。Compose 文件有效地取代了冗长的部署文档，并完全描述了应用程序的每个部分。通过外部资源和 Compose 覆盖，甚至可以捕获环境之间的差异，并构建一组 YAML 文件，用于驱动整个部署流水线。

Docker Compose 的局限性在于它是一个客户端工具。`docker-compose`命令需要访问 Compose 文件来执行任何命令。资源被逻辑地分组成一个单一的应用程序，但这只发生在 Compose 文件中。Docker 引擎只看到一组资源；它不认为它们是同一个应用程序的一部分。Docker Compose 也仅限于单节点 Docker 部署。

在下一章中，我将继续讲解集群化的 Docker 部署，多个节点在 Docker Swarm 中运行。在生产环境中，这为您提供了高可用性和可扩展性。Docker Swarm 是容器解决方案的强大编排器，非常易于使用。它还支持 Compose 文件格式，因此您可以使用现有的 Compose 文件部署应用程序，但 Docker 将逻辑架构存储在 Swarm 中，无需 Compose 文件即可管理应用程序。


# 第七章：使用 Docker Swarm 编排分布式解决方案

您可以在单台 PC 上运行 Docker，这是我在本书中迄今为止所做的，也是您在开发和基本测试环境中使用 Docker 的方式。在更高级的测试环境和生产环境中，单个服务器是不合适的。为了实现高可用性并为您提供扩展解决方案的灵活性，您需要多台作为集群运行的服务器。Docker 在平台中内置了集群支持，您可以使用 Docker Swarm 模式将多个 Docker 主机连接在一起。

到目前为止，您学到的所有概念（镜像、容器、注册表、网络、卷和服务）在集群模式下仍然适用。Docker Swarm 是一个编排层。它提供与独立的 Docker 引擎相同的 API，还具有额外的功能来管理分布式计算的各个方面。当您在集群模式下运行服务时，Docker 会确定在哪些主机上运行容器；它管理不同主机上容器之间的安全通信，并监视主机。如果集群中的服务器宕机，Docker 会安排它正在运行的容器在不同的主机上启动，以维持应用程序的服务水平。

自 2015 年发布的 Docker 1.12 版本以来，集群模式一直可用，并提供经过生产硬化的企业级服务编排。集群中的所有通信都使用相互 TLS 进行安全保护，因此节点之间的网络流量始终是加密的。您可以安全地在集群中存储应用程序机密，并且 Docker 只向那些需要访问的容器提供它们。集群是可扩展的，因此您可以轻松添加节点以增加容量，或者移除节点进行维护。Docker 还可以在集群模式下运行自动滚动服务更新，因此您可以在零停机的情况下升级应用程序。

在本章中，我将设置一个 Docker Swarm，并在多个节点上运行 NerdDinner。我将首先创建单个服务，然后转而从 Compose 文件部署整个堆栈。您将学习以下内容：

+   创建集群和管理节点

+   在集群模式下创建和管理服务

+   在 Docker Swarm 中管理应用程序配置

+   将堆栈部署到 Docker Swarm

+   无停机部署更新

# 技术要求

您需要在 Windows 10 更新 18.09 或 Windows Server 2019 上运行 Docker 才能跟随示例。本章的代码可在[`github.com/sixeyed/docker-on-windows/tree/second-edition/ch07`](https://github.com/sixeyed/docker-on-windows/tree/second-edition/ch07)找到。

# 创建一个群集并管理节点

Docker Swarm 模式使用具有管理者和工作者高可用性的管理者-工作者架构。管理者面向管理员，您可以使用活动管理者来管理集群和运行在集群上的资源。工作者面向用户，并且他们运行您的应用程序服务的容器。

群集管理者也可以运行您的应用程序的容器，这在管理者-工作者架构中是不寻常的。管理小型群集的开销相对较低，因此如果您有 10 个节点，其中 3 个是管理者，管理者也可以运行一部分应用程序工作负载（但在生产环境中，您需要意识到在它们上运行大量应用程序工作负载可能会使管理者计算资源不足的风险）。

您可以在同一个群集中拥有 Windows 和 Linux 节点的混合，这是管理混合工作负载的好方法。建议所有节点运行相同版本的 Docker，但可以是 Docker CE 或 Docker Enterprise——Docker Swarm 功能内置于核心 Docker 引擎中。

许多在生产中运行 Docker 的企业都有一个具有 Linux 节点作为管理者的群集，以及 Windows 和 Linux 节点混合作为工作者。这意味着您可以在单个集群中使用节点操作系统的最低成本选项来运行 Windows 和 Linux 应用程序容器。

# 初始化群集

群集可以是任何规模。您可以在笔记本电脑上运行单节点群集来测试功能，也可以扩展到数千个节点。您可以通过使用`docker swarm init`命令来初始化群集：

```
> docker swarm init --listen-addr 192.168.2.214 --advertise-addr 192.168.2.214
Swarm initialized: current node (jea4p57ajjalioqokvmu82q6y) is now a manager.

To add a worker to this swarm, run the following command:

    docker swarm join --token SWMTKN-1-37p6ufk5jku6tndotqlcy1w54grx5tvxb3rxphj8xkdn9lbeml-3w7e8hxfzzpt2fbf340d8phia 192.168.2.214:2377

To add a manager to this swarm, run 'docker swarm join-token manager' and follow the instructions.
```

这将创建一个具有单个节点的群集——即您运行命令的 Docker 引擎，并且该节点将成为群集管理器。我的机器有多个 IP 地址，因此我已经指定了`listen-addr`和`advertise-addr`选项，告诉 Docker 要使用哪个网络接口进行群集通信。始终指定 IP 地址并为管理节点使用静态地址是一个良好的做法。

您可以使用内部私有网络来保护您的集群，以便通信不在公共网络上。您甚至可以完全将管理节点保持在公共网络之外。只有具有面向公共的工作负载的工作节点需要连接到公共网络，除了内部网络之外-如果您正在使用负载均衡器作为基础架构的公共入口点，甚至可以避免这种情况。

# 将工作节点添加到集群

`docker swarm init`的输出告诉您如何通过加入其他节点来扩展集群。节点只能属于一个集群，并且要加入，它们需要使用加入令牌。该令牌可以防止恶意节点加入您的集群，如果网络受到损害，因此您需要将其视为安全秘密。节点可以作为工作节点或管理节点加入，并且每个节点都有不同的令牌。您可以使用`docker swarm join-token`命令查看和旋转令牌。

在运行相同版本的 Docker 的第二台机器上，我可以运行`swarm join`命令加入集群：

```
> docker swarm join `
   --token SWMTKN-1-37p6ufk5jku6tndotqlcy1w54grx5tvxb3rxphj8xkdn9lbeml-3w7e8hxfzzpt2fbf340d8phia `
   192.168.2.214:2377 
This node joined a swarm as a worker.
```

现在我的 Docker 主机正在运行在集群模式下，当我连接到管理节点时，我可以使用更多的命令。`docker node`命令管理集群中的节点，因此我可以列出集群中的所有节点，并使用`docker node ls`查看它们的当前状态：

```
> docker node ls
ID    HOSTNAME    STATUS   AVAILABILITY  MANAGER STATUS  ENGINE VERSION
h2ripnp8hvtydewpf5h62ja7u  win2019-02      Ready Active         18.09.2
jea4p57ajjalioqokvmu82q6y * win2019-dev-02 Ready Active Leader  18.09.2
```

`状态`值告诉您节点是否在线在集群中，`可用性`值告诉您节点是否能够运行容器。`管理节点状态`字段有三个选项：

+   `领导者`：控制集群的活跃管理节点。

+   `可达`：备用管理节点；如果当前领导者宕机，它可以成为领导者。

+   `无值`：工作节点。

多个管理节点支持高可用性。Docker Swarm 使用 Raft 协议在当前领导者丢失时选举新领导者，因此具有奇数个管理节点，您的集群可以在硬件故障时生存。对于生产环境，您应该有三个管理节点，这就是您所需要的，即使对于具有数百个工作节点的大型集群也是如此。

工作节点不会自动晋升为管理节点，因此如果所有管理节点丢失，那么您将无法管理集群。在这种情况下，工作节点上的容器继续运行，但没有管理节点来监视工作节点或您正在运行的服务。

# 晋升和删除集群节点

您可以使用`docker node promote`将工作节点转换为管理节点，并使用`docker node demote`将管理节点转换为工作节点；这些是您在管理节点上运行的命令。

要离开 Swarm，您需要在节点本身上运行`docker swarm leave`命令：

```
> docker swarm leave
Node left the swarm.
```

如果您有单节点 Swarm，您可以使用相同的命令退出 Swarm 模式，但是您需要使用`--force`标志，因为这实际上将您从 Swarm 模式切换回单个 Docker Engine 模式。

`docker swarm`和`docker node`命令管理着 Swarm。当您在 Swarm 模式下运行时，您将使用特定于 Swarm 的命令来管理容器工作负载。

您将看到关于*Docker Swarm*和*Swarm 模式*的引用。从技术上讲，它们是不同的东西。Docker Swarm 是一个早期的编排器，后来被构建到 Docker Engine 中作为 Swarm 模式。*经典*的 Docker Swarm 只在 Linux 上运行，因此当您谈论带有 Windows 节点的 Swarm 时，它总是 Swarm 模式，但通常被称为 Docker Swarm。

# 在云中运行 Docker Swarm

Docker 具有最小的基础设施要求，因此您可以轻松在任何云中快速启动 Docker 主机或集群 Docker Swarm。要大规模运行 Windows 容器，您只需要能够运行 Windows Server 虚拟机并将它们连接到网络。

云是运行 Docker 的好地方，而 Docker 是迁移到云的好方法。Docker 为您提供了现代应用程序平台的强大功能，而不受**平台即服务**（**PaaS**）产品的限制。PaaS 选项通常具有专有的部署系统、代码中的专有集成，并且开发人员体验不会使用相同的运行时。

Docker 允许您打包应用程序并以便携方式定义解决方案结构，这样可以在任何机器和任何云上以相同的方式运行。您可以使用所有云提供商支持的基本**基础设施即服务**（**IaaS**）服务，并在每个环境中实现一致的部署、管理和运行时体验。

主要的云还提供托管的容器服务，但这些服务已经集中在 Kubernetes 上——Azure 上的 AKS，Amazon Web Services 上的 EKS 和 Google Cloud 上的 GKE。在撰写本文时，它们都是 100%的 Linux 产品。对于 Kubernetes 的 Windows 支持正在积极开发中，一旦支持，云服务将开始提供 Windows 支持，但 Kubernetes 比 Swarm 更复杂，我不会在这里涵盖它。

在云中部署 Docker Swarm 的最简单方法之一是使用 Terraform，这是一种强大的基础设施即代码（IaC）技术，通常比云提供商自己的模板语言或脚本工具更容易使用。通过几十行配置，您可以定义管理节点和工作节点的虚拟机，以及网络设置、负载均衡器和任何其他所需的服务。

# Docker 认证基础设施

Docker 使用 Terraform 来支持 Docker 认证基础设施（DCI），这是一个用于在主要云提供商和主要本地虚拟化工具上部署 Docker 企业的单一工具。它使用每个提供商的相关服务来设置 Docker 企业平台的企业级部署，包括通用控制平面和 Docker 可信注册表。

DCI 在 Docker 的一系列参考架构指南中有详细介绍，可在 Docker 成功中心（[`success.docker.com`](https://success.docker.com)）找到。这个网站值得收藏，你还可以在那里找到关于现代化传统应用程序的指南，以及有关容器中日志记录、监控、存储和网络的最佳实践文档。

# 在 swarm 模式下创建和管理服务

在上一章中，您看到了如何使用 Docker Compose 来组织分布式解决方案。在 Compose 文件中，您可以使用网络将应用程序的各个部分定义为服务并将它们连接在一起。在 swarm 模式中，使用相同的 Docker Compose 文件格式和相同的服务概念。在 swarm 模式中，构成服务的容器被称为副本。您可以使用 Docker 命令行在 swarm 上创建服务，而 swarm 管理器会在 swarm 节点上作为容器运行副本。

我将通过创建服务来部署 NerdDinner 堆栈。所有服务将在我的集群上的同一个 Docker 网络中运行。在 swarm 模式下，Docker 有一种特殊类型的网络称为覆盖网络。覆盖网络是跨多个物理主机的虚拟网络，因此运行在一个 swarm 节点上的容器可以访问在另一个节点上运行的容器。服务发现的工作方式也是一样的：容器通过服务名称相互访问，Docker 的 DNS 服务器将它们指向一个容器。

要创建覆盖网络，您需要指定要使用的驱动程序并给网络命名。Docker CLI 将返回新网络的 ID，就像其他资源一样：

```
> docker network create --driver overlay nd-swarm
206teuqo1v14m3o88p99jklrn
```

您可以列出网络，您会看到新网络使用覆盖驱动程序，并且范围限定为群集，这意味着使用此网络的任何容器都可以相互通信，无论它们在哪个节点上运行：

```
> docker network ls
NETWORK ID          NAME                DRIVER              SCOPE
osuduab0ge73        ingress             overlay             swarm
5176f181eee8        nat                 nat                 local
206teuqo1v14        nd-swarm            overlay             swarm
```

这里的输出还显示了默认的`nat`网络，它具有本地范围，因此容器只能在同一主机上相互访问。在群集模式下创建的另一个网络称为`ingress`，这是具有发布端口的服务的默认网络。

我将使用新网络来部署 NerdDinner 服务，因为这将使我的应用与群集中将使用自己网络的其他应用隔离开来。我将在本章后面使用 Docker Compose 文件来部署整个解决方案，但我将首先通过手动使用`docker service create`命令来创建服务，以便您可以看到服务与容器的不同之处。这是如何在 Docker Swarm 中将 NATS 消息队列部署为服务的方法：

```
docker service create `   --network nd-swarm `
  --name message-queue ` dockeronwindows/ch05-nats:2e 
```

`docker service create`的必需选项除了镜像名称外，但对于分布式应用程序，您需要指定以下内容：

+   `network`：要连接到服务容器的 Docker 网络

+   `name`：用作其他组件 DNS 条目的服务名称

Docker 支持容器的不同类型的 DNS 解析。默认值是虚拟 IP `vip` 模式，您应该使用它，因为它是最高性能的。 `vip` 模式仅支持从 Windows Server 2019 开始，因此对于较早版本，您将看到端点模式设置为`dnsrr`的示例。这是 DNS 轮询模式，效率较低，并且可能会在客户端缓存 DNS 响应时引起问题，因此除非必须与 Windows Server 2016 上的容器一起工作，否则应避免使用它。

您可以从连接到群集管理器的 Docker CLI 中运行`service create`命令。管理器查看群集中的所有节点，并确定哪些节点有能力运行副本，然后安排任务在节点上创建为容器。默认副本级别为*one*，因此此命令只创建一个容器，但它可以在群集中的任何节点上运行。

`docker service ps`显示正在运行服务的副本，包括托管每个容器的节点的名称：

```
> docker service ps message-queue
ID    NAME      IMAGE     NODE  DESIRED  STATE  CURRENT    STATE
xr2vyzhtlpn5 message-queue.1  dockeronwindows/ch05-nats:2e  win2019-02  Running        Running
```

在这种情况下，经理已经安排了一个容器在节点`win2019-02`上运行，这是我集群中唯一的工作节点。看起来如果我直接在该节点上运行 Docker 容器，我会得到相同的结果，但是将其作为 Docker Swarm 服务运行给了我编排的所有额外好处：

+   **应用程序可靠性**：如果此容器停止，经理将安排立即启动替代容器。

+   **基础设施可靠性**：如果工作节点宕机，经理将安排在不同节点上运行新的容器。

+   **可发现性**：该容器连接到一个覆盖网络，因此可以使用服务名称与在其他节点上运行的容器进行通信（Windows 容器甚至可以与同一集群中运行的 Linux 容器进行通信，反之亦然）。

在 Docker Swarm 中运行服务比在单个 Docker 服务器上运行容器有更多的好处，包括安全性、可扩展性和可靠的应用程序更新。我将在本章中涵盖它们。

在源代码存储库中，`ch07-create-services`文件夹中有一个脚本，按正确的顺序启动 NerdDinner 的所有服务。每个`service create`命令的选项相当于第六章中 Compose 文件的服务定义，*使用 Docker Compose 组织分布式解决方案*。前端服务和 Traefik 反向代理中只有一些差异。

Traefik 在 Docker Swarm 中运行得很好——它连接到 Docker API 来构建其前端路由映射，并且以与在单个运行 Docker Engine 的服务器上完全相同的方式代理来自后端容器的内容。要在 swarm 模式下向 Traefik 注册服务，您还需要告诉 Traefik 容器中的应用程序使用的端口，因为它无法自行确定。REST API 服务定义添加了`traefik.port`标签：

```
docker service create `   --network nd-swarm `
  --env-file db-credentials.env `
  --name nerd-dinner-api `
  --label "traefik.frontend.rule=Host:api.nerddinner.swarm"  `
  --label "traefik.port=80"  `
 dockeronwindows/ch05-nerd-dinner-api:2e
```

Traefik 本身是在 swarm 模式下创建的最复杂的服务，具有一些额外的选项：

```
docker service create `
  --detach=true `
  --network nd-swarm ` --constraint=node.role==manager `  --publish 80:80  --publish 8080:8080  `
  --mount type=bind,source=C:\certs\client,target=C:\certs `
  --name reverse-proxy `
 sixeyed/traefik:v1.7.8-windowsservercore-ltsc2019 `
  --docker --docker.swarmMode --docker.watch `
  --docker.endpoint=tcp://win2019-dev-02:2376  ` --docker.tls.ca=/certs/ca.pem `
  --docker.tls.cert=/certs/cert.pem `
  --docker.tls.key=/certs/key.pem `
  --api
```

你只能从运行在管理节点上的 Docker API 获取有关集群服务的信息，这就是为什么你需要将 Docker CLI 连接到管理节点以处理集群资源。服务的`constraint`选项确保 Docker 只会将容器调度到满足约束条件的节点上运行。在这种情况下，服务副本只会在管理节点上运行。这不是唯一的选择 - 如果你已经配置了对 Docker API 的安全远程访问，你可以在工作节点上运行 Traefik。

为了将 Traefik 连接到 Docker API，我以前使用卷来挂载 Windows 命名的*pipe*，但是这个功能在 Docker Swarm 中还不支持。所以，我改用 TCP 连接到 API，指定管理者的 DNS 名称`win2019-dev-02`。我已经用 TLS 保护了我的 Docker 引擎（就像我在第一章中解释的那样，在 Windows 上使用 Docker 入门），所以我还提供了客户端证书来安全地使用连接。证书存储在我的管理节点上的`C:\certs\client`中，我将其挂载为容器内的一个目录。

*服务挂载的命名管道支持*意味着你可以使用挂载管道的方法，这样做更容易，因为你不需要指定管理者的主机名，或者提供 TLS 证书。这个功能计划在 Docker 19.03 中推出，并且可能在你阅读本书时已经可用。Docker 的好处在于它是由开源组件构建的，因此诸如此类的功能都是公开讨论的 - [`github.com/moby/moby/issues/34795`](https://github.com/moby/moby/issues/34795)会告诉你背景和当前状态。

当我在我的集群上运行脚本时，我会得到一个服务 ID 列表作为输出：

```
> .\ch07-run-nerd-dinner.ps1
206teuqo1v14m3o88p99jklrn
vqnncr7c9ni75ntiwajcg05ym
2pzc8c5rahn25l7we3bzqkqfo
44xsmox6d8m480sok0l4b6d80
u0uhwiakbdf6j6yemuy6ey66p
v9ujwac67u49yenxk1albw4bt
s30phoip8ucfja45th5olea48
24ivvj205dti51jsigneq3z8q
beakbbv67shh0jhtolr35vg9r
sc2yzqvf42z4l88d3w31ojp1c
vx3zyxx2rubehee9p0bov4jio
rl5irw1w933tz9b5cmxyyrthn
```

现在我可以用`docker service ls`看到所有正在运行的服务：

```
> docker service ls
ID           NAME          MODE       REPLICAS            IMAGE 
8bme2svun122 message-queue             replicated 1/1      nats:nanoserver
deevh117z4jg nerd-dinner-homepage      replicated 1/1      dockeronwindows/ch03-nerd-dinner-homepage...
lxwfb5s9erq6 nerd-dinner-db            replicated 1/1      dockeronwindows/ch06-nerd-dinner-db:latest
ol7u97cpwdcn nerd-dinner-index-handler replicated 1/1      dockeronwindows/ch05-nerd-dinner-index...
rrgn4n3pecgf elasticsearch             replicated 1/1      sixeyed/elasticsearch:nanoserver
w7d7svtq2k5k nerd-dinner-save-handler  replicated 1/1      dockeronwindows/ch05-nerd-dinner-save...
ydzb1z1af88g nerd-dinner-web           replicated 1/1      dockeronwindows/ch05-nerd-dinner-web:latest
ywrz3ecxvkii kibana                    replicated 1/1      sixeyed/kibana:nanoserver
```

每个服务都列出了一个`1/1`的副本状态，这意味着一个副本正在运行，而请求的服务级别是一个副本。这是用于运行服务的容器数量。Swarm 模式支持两种类型的分布式服务：复制和全局。默认情况下，分布式服务只有一个副本，这意味着在集群上只有一个容器。我的脚本中的`service create`命令没有指定副本计数，所以它们都使用默认值*one*。

# 跨多个容器运行服务

复制的服务是你如何在集群模式下扩展的方式，你可以更新正在运行的服务来添加或删除容器。与 Docker Compose 不同，你不需要一个定义每个服务期望状态的 Compose 文件；这些细节已经存储在集群中，来自`docker service create`命令。要添加更多的消息处理程序，我使用`docker service scale`，传递一个或多个服务的名称和期望的服务级别：

```
> docker service scale nerd-dinner-save-handler=3
nerd-dinner-save-handler scaled to 3
overall progress: 1 out of 3 tasks
1/3: starting  [============================================>      ]
2/3: starting  [============================================>      ]
3/3: running   [==================================================>]
```

消息处理程序服务是使用默认的单个副本创建的，因此这将添加两个容器来共享 SQL Server 处理程序服务的工作。在多节点集群中，管理器可以安排容器在任何具有容量的节点上运行。我不需要知道或关心哪个服务器实际上在运行容器，但我可以通过`docker service ps`深入了解服务列表，看看容器在哪里运行：

```
> docker service ps nerd-dinner-save-handler
ID      NAME    IMAGE  NODE            DESIRED STATE  CURRENT STATE 
sbt4c2jof0h2  nerd-dinner-save-handler.1 dockeronwindows/ch05-nerd-dinner-save-handler:2e    win2019-dev-02      Running             Running 23 minutes ago
bibmh984gdr9  nerd-dinner-save-handler.2 dockeronwindows/ch05-nerd-dinner-save-handler:2e    win2019-dev-02      Running             Running 3 minutes ago
3lkz3if1vf8d  nerd-dinner-save-handler.3 dockeronwindows/ch05-nerd-dinner-save-handler:2e   win2019-02           Running             Running 3 minutes ago
```

在这种情况下，我正在运行一个双节点集群，副本分布在节点`win2019-dev-02`和`win2019-02`之间。集群模式将服务进程称为副本，但它们实际上只是容器。你可以登录到集群的节点，并像往常一样使用`docker ps`、`docker logs`和`docker top`命令管理服务容器。

通常情况下，你不会这样做。运行副本的节点只是由集群为你管理的黑匣子；你通过管理节点与你的服务一起工作。就像 Docker Compose 为服务提供了日志的整合视图一样，你可以通过连接到集群管理器的 Docker CLI 获得相同的视图：

```
PS> docker service logs nerd-dinner-save-handler
nerd-dinner-save-handler.1.sbt4c2jof0h2@win2019-dev-02
    | Connecting to message queue url: nats://message-queue:4222
nerd-dinner-save-handler.1.sbt4c2jof0h2@win2019-dev-02
    | Listening on subject: events.dinner.created, queue: save-dinner-handler
nerd-dinner-save-handler.2.bibmh984gdr9@win2019-dev-02
    | Connecting to message queue url: nats://message-queue:4222
nerd-dinner-save-handler.2.bibmh984gdr9@win2019-dev-02
    | Listening on subject: events.dinner.created, queue: save-dinner-handler
...
```

副本是集群为服务提供容错的方式。当你使用`docker service create`、`docker service update`或`docker service scale`命令为服务指定副本级别时，该值将记录在集群中。管理节点监视服务的所有任务。如果容器停止并且运行服务的数量低于期望的副本级别，新任务将被安排以替换停止的容器。在本章后面，我将演示当我在多节点集群上运行相同的解决方案时，我可以从集群中取出一个节点，而不会造成任何服务的丢失。

# 全局服务

替代复制服务的选择是全局服务。在某些情况下，您可能希望同一个服务在集群的每个节点上作为单个容器运行。为此，您可以以全局模式运行服务——Docker 在每个节点上精确安排一个任务，并且任何加入的新节点也将安排一个任务。

全局服务对于具有许多服务使用的组件的高可用性可能很有用，但是再次强调，并不是通过运行许多实例来获得集群化的应用程序。NATS 消息队列可以在多台服务器上作为集群运行，并且可以作为全局服务运行的一个很好的候选。但是，要将 NATS 作为集群运行，每个实例都需要知道其他实例的地址，这与 Docker Engine 分配的动态虚拟 IP 地址不兼容。

相反，我可以将我的 Elasticsearch 消息处理程序作为全局服务运行，因此每个节点都将运行一个消息处理程序的实例。您无法更改正在运行的服务的模式，因此首先需要删除原始服务。

```
> docker service rm nerd-dinner-index-handler
nerd-dinner-index-handler 
```

然后，我可以创建一个新的全局服务。

```
> docker service create `
>>  --mode=global `
>>  --network nd-swarm `
>>  --name nerd-dinner-index-handler `
>>  dockeronwindows/ch05-nerd-dinner-index-handler:2e;
q0c20sx5y25xxf0xqu5khylh7
overall progress: 2 out of 2 tasks
h2ripnp8hvty: running   [==================================================>]
jea4p57ajjal: running   [==================================================>]
verify: Service converged 
```

现在我在集群中的每个节点上都有一个任务在运行，如果节点被添加到集群中，任务的总数将增加，如果节点被移除，任务的总数将减少。这对于您想要分发以实现容错的服务可能很有用，并且您希望服务的总容量与集群的大小成比例。

全局服务在监控和审计功能中也很有用。如果您有诸如 Splunk 之类的集中式监控系统，或者正在使用 Elasticsearch Beats 进行基础设施数据捕获，您可以将代理作为全局服务在每个节点上运行。

通过全局和复制服务，Docker Swarm 提供了扩展应用程序和维护指定服务水平的基础设施。如果您有固定大小的集群但可变的工作负载，这对于本地部署非常有效。您可以根据需求扩展应用程序组件，只要它们不都需要在同一时间进行峰值处理。在云中，您有更多的灵活性，可以通过向集群添加新节点来增加集群的总容量，从而更广泛地扩展应用程序服务。

在许多实例中扩展运行应用程序通常会增加复杂性 - 您需要一种注册所有活动实例的方式，一种在它们之间共享负载的方式，以及一种监视所有实例的方式，以便如果有任何实例失败，它们不会有任何负载发送到它们。这一切都是 Docker Swarm 中内置的功能，它透明地提供服务发现、负载均衡、容错和自愈应用程序的基础设施。

# Swarm 模式中的负载均衡和扩展

Docker 使用 DNS 进行服务发现，因此容器可以通过标准网络找到彼此。应用程序在其客户端连接配置中使用服务器名称，当应用程序进行 DNS 查询以找到目标时，Docker 会响应容器的 IP 地址。在 Docker Swarm 中也是一样的，当您的目标**服务器**名称实际上可能是在集群中运行着数十个副本的 Docker 服务的名称。

Docker 有两种方式来管理具有多个副本的服务的 DNS 响应。默认情况下是使用**VIP**：虚拟 IP 地址。Docker 为服务使用单个 IP 地址，并依赖于主机操作系统中的网络堆栈将 VIP 上的请求路由到实际的容器。VIP 负责负载均衡和健康。请求被分享给服务中的所有健康容器。这个功能在 Linux 中已经存在很久了，在 Windows Server 2019 中是新功能。

VIP 的替代方案是**DNSRR**：**DNS 轮询**，您可以在服务配置中的`endpoint_mode`设置中指定。DNSRR 返回服务中所有健康容器的 IP 地址列表，并且列表的顺序会轮换以提供负载均衡。在 Windows Server 2019 之前，DNSRR 是 Windows 容器的唯一选项，并且您会在许多示例中看到它，但 VIP 是更好的选择。客户端有缓存 DNS 查询响应的倾向。使用 DNSRR，您可以更新一个服务并发现客户端已经缓存了一个已被替换的旧容器的 IP 地址，因此它们的连接失败。这在 VIP 中不会发生，在 VIP 中，DNS 响应中有一个单一的 IP 地址，客户端可以安全地缓存它，因为它总是会路由到一个健康的容器。

Docker Swarm 负责在服务副本之间负载平衡网络流量，但它也负责负载平衡进入集群的外部流量。在新的 NerdDinner 架构中，只有一个组件是公开访问的——Traefik 反向代理。我们知道一个端口在一台机器上只能被一个进程使用，所以这意味着我们只能将代理服务扩展到集群中每个节点的最大一个容器。但是 Docker Swarm 允许我们过度或不足地提供服务，使用机器上的相同端口来处理零个或多个副本。

附加到覆盖网络的集群服务在发布端口时与标准容器的行为不同。集群中的每个节点都监听发布的端口，当接收到流量时，它会被定向到一个健康的容器。该容器可以在接收请求的节点上运行，也可以在不同的节点上运行。

在这个例子中，客户端在 Docker Swarm 中运行的服务的标准端口`80`上进行了 HTTP GET 请求：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/f379e589-aa28-4882-9d1f-d8aa739e6e2f.png)

1.  客户端请求到达一个没有运行任何服务副本的节点。该节点没有在端口`80`上监听的容器，因此无法直接处理请求。

1.  接收节点将请求转发到集群中另一个具有在端口`80`上监听的容器的节点——这对原始客户端来说是不可见的。

1.  新节点将请求转发到正在运行的容器，该容器处理请求并发送响应。

这被称为**入口网络**，它是一个非常强大的功能。这意味着您可以在大型集群上运行低规模的服务，或者在小型集群上运行高规模的服务，它们将以相同的方式工作。如果服务的副本少于集群中的节点数，这不是问题，因为 Docker 会透明地将请求发送到另一个节点。如果服务的副本多于节点数，这也不是问题，因为每个节点都可以处理请求，Docker 会在节点上的容器之间负载平衡流量。

Docker Swarm 中的网络是一个值得详细了解的主题，因为它将帮助您设计和交付可扩展和具有弹性的系统。我编写了一门名为**在 Docker Swarm 模式集群中管理负载平衡和扩展**的 Pluralsight 课程，涵盖了 Linux 和 Windows 容器的所有关键主题。

负载均衡和服务发现都基于健康的容器，并且这是 Docker Swarm 的一个功能，不需要我进行任何特殊设置。在群集模式下运行的服务默认为 VIP 服务发现和用于发布端口的入口网络。当我在 Docker Swarm 中运行 NerdDinner 时，我不需要对我的部署进行任何更改，就可以在生产环境中获得高可用性和扩展性，并且可以专注于自己应用程序的配置。

# 在 Docker Swarm 中管理应用程序配置

我在第五章中花了一些时间，*采用基于容器的解决方案设计*，为 NerdDinner 堆栈构建了一个灵活的配置系统。其中的核心原则是将开发的默认配置捆绑到每个镜像中，但允许在运行容器时覆盖设置。这意味着我们将在每个环境中使用相同的 Docker 镜像，只是交换配置设置以更改行为。

这适用于单个 Docker 引擎，我可以使用环境变量来覆盖单个设置，并使用卷挂载来替换整个配置文件。在 Docker Swarm 中，您可以使用 Docker 配置对象和 Docker 秘密来存储可以传递给容器的群集中的数据。这比使用环境变量和文件更加整洁地处理配置和敏感数据，但这意味着我在每个环境中仍然使用相同的 Docker 镜像。

# 在 Docker 配置对象中存储配置

在群集模式中有几种新资源 - 除了节点和服务外，还有堆栈、秘密和配置。配置对象只是在群集中创建的文本文件，并在服务容器内部作为文件出现。它们是管理配置设置的绝佳方式，因为它们为您提供了一个存储所有应用程序设置的单一位置。

您可以以两种方式使用配置对象。您可以使用`docker config`命令创建和管理它们，并在 Docker 服务命令和 Docker Compose 文件中使其对服务可用。这种清晰的分离意味着您的应用程序定义与配置分开 - 定义在任何地方都是相同的，而配置是由 Docker 从环境中加载的。

Docker 将配置对象表面化为容器内的文本文件，位于您指定的路径，因此您可以在 swarm 中拥有一个名为`my-app-config`的秘密，显示为`C:\my-app\config\appSettings.config`。Docker 不关心文件内容，因此它可以是 XML、JSON、键值对或其他任何内容。由您的应用程序实际执行文件的操作，这可以是使用完整文件作为配置，或将文件内容与 Docker 镜像中内置的一些默认配置合并。

在我现代化 NerdDinner 时，我已经为我的应用程序设置转移到了.NET Core 配置框架。我在组成 NerdDinner 的所有.NET Framework 和.NET Core 应用程序中都使用相同的`Config`类。`Config`类为配置提供程序添加了自定义文件位置：

```
public  static  IConfigurationBuilder  AddProviders(IConfigurationBuilder  config) {
  return  config.AddJsonFile("config/appsettings.json")
               .AddEnvironmentVariables()
               .AddJsonFile("config/config.json", optional: true)
               .AddJsonFile("config/secrets.json", optional: true); } 
```

配置提供程序按优先顺序倒序列出。首先，它们从应用程序镜像的`config/appsettings.json`文件中加载。然后，合并任何环境变量-添加新键，或替换现有键的值。接下来，如果路径`config/config.json`处存在文件，则其内容将被合并-覆盖任何现有设置。最后，如果路径`config/secrets.json`处存在文件，则其值将被合并。

这种模式让我可以使用一系列配置源。应用程序的默认值都存在于 Docker 镜像中。在运行时，用户可以使用环境变量或环境变量文件指定覆盖值-这对于在单个 Docker 主机上工作的开发人员来说很容易。在集群环境中，部署可以使用 Docker 配置对象和秘密，这将覆盖默认值和任何环境变量。

举个简单的例子，我可以更改新 REST API 的日志级别。在 Docker 镜像的`appsettings.json`文件中，日志级别设置为`Warning`。每次有`GET`请求时，应用程序都会写入信息级别的日志，因此如果我在配置中更改日志级别，我将能够看到这些日志条目。

我想要在名为`nerd-dinner-api-config.json`的文件中使用我想要的设置：

```
{
  "Logging": {
  "LogLevel": {
   "Default": "Information"
  } 
} }
```

首先，我需要将其存储为 swarm 中的配置对象，因此容器不需要访问原始文件。我使用`docker config create`来实现这一点，给对象一个名称和配置源的路径。

```
docker config create nerd-dinner-api-config .\configs\nerd-dinner-api-config.json
```

您只需要在创建配置对象时访问该文件。现在数据存储在 swarm 中。swarm 中的任何节点都可以获取配置数据并将其提供给容器，任何具有对 Docker Engine 访问权限的人都可以查看配置数据，而无需该源文件。`docker config inspect`会显示配置对象的内容。

```
> docker config inspect --pretty nerd-dinner-api-config
ID:                     yongm92k597gxfsn3q0yhnvtb
Name:                   nerd-dinner-api-config
Created at:             2019-02-13 22:09:04.3214402 +0000 utc
Updated at:             2019-02-13 22:09:04.3214402 +0000 utc
Data:
{
 "Logging": {
 "LogLevel": {
 "Default": "Information"
    }
 }
}
```

您可以通过检查来查看配置对象的纯文本值。这对于故障排除应用程序问题非常有用，但对于安全性来说不好——您应该始终使用 Docker secrets 来存储敏感配置值，而不是配置对象。

# 在 swarm 服务中使用 Docker 配置对象

在创建服务时，您可以使用`--config`选项将配置对象提供给容器。然后，您应该能够直接在应用程序中使用它们，但可能会有一个陷阱。当将配置对象作为文件呈现给容器时，它们受到保护，只有管理帐户才能读取它们。如果您的应用程序以最低特权用户身份运行，它可以看到配置文件，但无法读取它。这是一个安全功能，旨在在某人获得对容器中文件系统的访问权限时保护您的配置文件。

在 Linux 容器中情况就不同了，您可以指定在容器内具有文件所有权的用户 ID，因此可以让最低特权帐户访问该文件。Windows 容器不支持该功能，但 Windows 容器正在不断发展，以实现与 Linux 容器功能完备，因此这应该会在未来的版本中实现。在撰写本文时，要使用配置对象，应用程序需要以管理员帐户或具有本地系统访问权限的帐户运行。

以提升的权限运行应用程序在安全角度不是一个好主意，但当您在容器中运行时，这就不那么值得关注了。我在《第九章》中涵盖了这一点，*了解 Docker 的安全风险和好处*。

我已经更新了来自《第五章》*采用基于容器的解决方案设计*的 REST API 的 Dockerfile，以使用容器中的内置管理员帐户：

```
# escape=` FROM microsoft/dotnet:2.1-aspnetcore-runtime-nanoserver-1809 EXPOSE 80 WORKDIR /dinner-api ENTRYPOINT ["dotnet", "NerdDinner.DinnerApi.dll"] USER ContainerAdministrator COPY --from=dockeronwindows/ch05-nerd-dinner-builder:2e C:\dinner-api .
```

改变的只是`USER`指令，它设置了 Dockerfile 的其余部分和容器启动的用户。代码完全相同：我仍然使用来自第五章的构建器镜像，*采用面向容器的解决方案设计*。我已将此新镜像构建为`dockeronwindows/ch07-nerd-dinner-api:2e`，并且可以升级正在运行的 API 服务并应用新配置与`docker service update`：

```
docker service update `
  --config-add src=nerd-dinner-api-config,target=C:\dinner-api\config\config.json `
  --image dockeronwindows/ch07-nerd-dinner-api:2e  `
 nerd-dinner-api;
```

更新服务将正在运行的副本替换为新配置，在本例中，使用新镜像并应用配置对象。现在，当我对 REST API 进行`GET`请求时，它会以信息级别记录日志，并且我可以在服务日志中看到更多细节：

```
> docker service logs nerd-dinner-api
nerd-dinner-api.1.cjurm8tg1lmj@win2019-02    | Hosting environment: Production
nerd-dinner-api.1.cjurm8tg1lmj@win2019-02    | Content root path: C:\dinner-api
nerd-dinner-api.1.cjurm8tg1lmj@win2019-02    | Now listening on: http://[::]:80
nerd-dinner-api.1.cjurm8tg1lmj@win2019-02    | Application started. Press Ctrl+C to shut down.
nerd-dinner-api.1.cjurm8tg1lmj@win2019-02    | info: Microsoft.AspNetCore.Hosting.Internal.WebHost[1]
nerd-dinner-api.1.cjurm8tg1lmj@win2019-02    |       Request starting HTTP/1.1 GET http://api.nerddinner.swarm/api/dinners
nerd-dinner-api.1.cjurm8tg1lmj@win2019-02    | info: Microsoft.AspNetCore.Mvc.Internal.ControllerActionInvoker[1]
nerd-dinner-api.1.cjurm8tg1lmj@win2019-02    |       Route matched with {action = "Get", controller = "Dinners"}. Executing action NerdDinner.DinnerApi.Controllers.DinnersController.Get (NerdDinner.DinnerApi)
```

您可以使用此方法来处理在不同环境之间更改的功能标志和行为设置。这是一种非常灵活的应用程序配置方法。使用单个 Docker 引擎的开发人员可以使用镜像中的默认设置运行容器，或者使用环境变量覆盖它们，或者通过挂载本地卷替换整个配置文件。在使用 Docker Swarm 的测试和生产环境中，管理员可以使用配置对象集中管理配置，而在每个环境中仍然使用完全相同的 Docker 镜像。

# 在 Docker secrets 中存储敏感数据

Swarm 模式本质上是安全的。所有节点之间的通信都是加密的，并且 swarm 提供了分布在管理节点之间的加密数据存储。您可以将此存储用于应用程序**秘密**。秘密的工作方式与配置对象完全相同-您在 swarm 中创建它们，然后使它们对服务可用。不同之处在于，秘密在 swarm 的数据存储中是加密的，并且在从管理节点到工作节点的传输中也是加密的。它只在运行副本的容器内解密，然后以与配置对象相同的方式作为文件显示。

秘密是通过名称和秘密内容创建的，可以从文件中读取或输入到命令行中。我打算将我的敏感数据移动到 secrets 中，首先是 SQL Server 管理员帐户密码。在`ch07-app-config`文件夹中，我有一个名为`secrets`的文件夹，其中包含数据库密码的秘密文件。我将使用它来安全地存储密码在 swarm 中，但在数据库镜像支持秘密之前，我需要对其进行一些工作。

我将最新的 SQL Server 数据库架构打包到 Docker 镜像`dockeronwindows/ch06-nerd-dinner-db`中。该映像使用环境变量来设置管理员密码，这对开发人员来说很好，但在测试环境中不太好，因为您希望限制访问。我为本章准备了一个更新的版本，其中包括用于数据库的更新的 Dockerfile 和启动脚本，因此我可以从秘密文件中读取密码。

在`ch07-nerd-dinner-db`的`InitializeDatabase.ps1`脚本中，我添加了一个名为`sa_password_path`的新参数，并添加了一些简单的逻辑，以从文件中读取密码，如果该路径中存在文件：

```
if ($sa_password_path  -and (Test-Path  $sa_password_path)) {
  $password  =  Get-Content  -Raw $sa_password_path
  if ($password) {
    $sa_password  =  $password
    Write-Verbose  "Using SA password from secret file: $sa_password_path" }
```

这是一种完全不同的方法，与 REST API 中采用的方法相反。应用程序对配置有自己的期望，您需要将其与 Docker 的方法整合起来，以在文件中显示配置数据。在大多数情况下，您可以在 Dockerfile 中完成所有操作，因此不需要更改代码直接从文件中读取配置。

Dockerfile 使用具有密码文件路径的默认值的环境变量：

```
ENV sa_password_path="C:\secrets\sa-password"
```

这仍然支持以不同方式运行数据库。开发人员可以在不指定任何配置设置的情况下运行它，并且它将使用内置于映像中的默认密码，这与应用程序映像的连接字符串中的相同默认密码相同。在集群环境中，管理员可以单独创建秘密，而无需部署应用程序，并安全地访问数据库容器。

我需要创建秘密，然后更新数据库服务以使用秘密和应用密码的新映像：

```
docker secret create nerd-dinner-db-sa-password .\secrets\nerd-dinner-db-sa-password.txt; docker service update `
  --secret-add src=nerd-dinner-db-sa-password,target=C:\secrets\sa-password `
  --image dockeronwindows/ch07-nerd-dinner-db:2e  `
 nerd-dinner-db;
```

现在数据库正在使用由 Docker Swarm 保护的强密码。可以访问 Docker 引擎的用户无法看到秘密的内容，因为它只在明确使用秘密的服务的容器内解密。我可以检查秘密，但我只能看到元数据：

```
> docker secret inspect --pretty nerd-dinner-db-sa-password
ID:              u2zsrjouhicjnn1fwo5x8jqpk
Name:              nerd-dinner-db-sa-password
Driver:
Created at:        2019-02-14 10:33:04.0575536 +0000 utc
Updated at:        2019-02-14 10:33:04.0575536 +0000 utc
```

现在我的应用程序出现了问题，因为我已更新了数据库密码，但没有更新使用数据库的应用程序中的连接字符串。这是通过向 Docker Swarm 发出命令来管理分布式应用程序的危险。相反，您应该使用 Docker Compose 文件以声明方式管理应用程序，定义所有服务和其他资源，并将它们部署为 Docker 堆栈。

# 将堆栈部署到 Docker Swarm

Docker Swarm 中的堆栈解决了在单个主机上使用 Docker Compose 或在 Docker Swarm 上手动创建服务的限制。您可以从 Compose 文件创建堆栈，并且 Docker 将堆栈服务的所有元数据存储在 Swarm 中。这意味着 Docker 知道这组资源代表一个应用程序，您可以在任何 Docker 客户端上管理服务，而无需 Compose 文件。

*堆栈*是对构成您的应用程序的所有对象的抽象。它包含服务、卷和网络，就像标准的 Docker Compose 文件一样，但它还支持 Docker Swarm 对象——配置和密码——以及用于在规模上运行应用程序的附加部署设置。

堆栈甚至可以抽象出您正在使用的编排器。Docker Enterprise 同时支持 Docker Swarm 和 Kubernetes 在同一集群上，并且您可以使用简单的 Docker Compose 格式和 Docker CLI 将应用程序部署和管理为堆栈到任一编排器。

# 使用 Docker Compose 文件定义堆栈

Docker Compose 文件模式已经从支持单个 Docker 主机上的客户端部署发展到 Docker Swarm 上的堆栈部署。不同的属性集在不同的场景中是相关的，并且工具会强制执行。Docker Compose 将忽略仅适用于堆栈部署的属性，而 Docker Swarm 将忽略仅适用于单节点部署的属性。

我可以利用多个 Compose 文件来实现这一点，在一个文件中定义应用程序的基本设置，在一个覆盖文件中添加本地设置，并在另一个覆盖文件中添加 Swarm 设置。我已经在`ch07-docker-compose`文件夹中的 Compose 文件中这样做了。`docker-compose.yml`中的核心服务定义现在非常简单，它们只包括适用于每种部署模式的属性。甚至 Traefik 的反向代理定义也很简单：

```
reverse-proxy:
  image: sixeyed/traefik:v1.7.8-windowsservercore-ltsc2019
  networks:
 - nd-net 
```

在`docker-compose.local.yml`覆盖文件中，我添加了在我的笔记本电脑上开发应用程序和使用 Docker Compose 部署时相关的属性。对于 Traefik，我需要配置要运行的命令以及要发布的端口，并挂载一个用于 Docker Engine 命名管道的卷：

```
reverse-proxy:
  command: --docker --docker.endpoint=npipe:////./pipe/docker_engine --api
  ports:
  - "80"
  - "8080"
  volumes:
  - type: npipe
     source: \\.\pipe\docker_engine
     target: \\.\pipe\docker_engine 
```

在 `docker-compose.swarm.yml` 覆盖文件中，我有一个属性，当我在集群化的 Docker Swarm 环境中运行时应用——这可能是测试中的两节点 swarm 和生产中的 200 节点 swarm；Compose 文件将是相同的。 我设置了 Traefik 命令以使用 TCP 连接到 swarm 管理器，并且我正在使用 secrets 在 swarm 中存储 TLS 证书：

```
reverse-proxy:
  command: --docker --docker.swarmMode --docker.watch --docker.endpoint=tcp://win2019-dev-02:2376  
           --docker.tls.ca=/certs/ca.pem --docker.tls.cert=/certs/cert.pem ...
  ports:
   - "80:80"
   - "8080:8080"
  secrets:
   - source: docker-client-ca
      target: C:\certs\ca.pem
   - source: docker-client-cert
      target: C:\certs\cert.pem - source: docker-client-key target: C:\certs\key.pem
  deploy:
   placement:
     constraints:
      - node.role == manager
```

这个应用程序清单的唯一不可移植部分是我的 swarm 管理器的 DNS 名称 `win2019-dev-02`。 我在第六章中解释过，*使用 Docker Compose 组织分布式解决方案*，在 swarm 模式下还不能挂载命名管道，但很快就会推出。 当该功能到来时，我可以在 swarm 模式下像在单个 Docker 引擎上一样使用命名管道来使用 Traefik，并且我的 Compose 文件将在任何 Docker 集群上运行。

其余服务的模式相同：`compose.yml` 中有基本定义，本地文件中有开发人员的一组覆盖，以及一组替代覆盖在 swarm 文件中。 核心 Compose 文件不能单独使用，因为它没有指定的所有配置，这与第六章中的不同，*使用 Docker Compose 组织分布式解决方案*，我的 Docker Compose 文件是为开发设置的。 您可以使用最适合您的任何方法，但这种方式的优势在于每个环境的设置都在其自己的覆盖文件中。

有几个值得更详细查看的服务选项。 REST API 在核心 Compose 文件中定义，只需图像和网络设置。 本地覆盖添加了用于向代理注册 API 的标签，并且还捕获了对数据库服务的依赖关系：

```
nerd-dinner-api:
  depends_on:
   - nerd-dinner-db
  labels:
   - "traefik.frontend.rule=Host:api.nerddinner.local"
```

Swarm 模式不支持 `depends_on` 属性。 当您部署堆栈时，无法保证服务将以何种顺序启动。 如果您的应用程序组件具有 `retry` 逻辑以解决任何依赖关系，那么服务启动顺序就无关紧要。 如果您的组件不具有弹性，并且在无法访问依赖项时崩溃，那么 Docker 将重新启动失败的容器，并且经过几次重试后应用程序应该准备就绪。

传统应用程序通常缺乏弹性，它们假设它们的依赖始终可用并能立即响应。如果您转移到云服务，容器也是如此。Docker 将不断替换失败的容器，但即使对传统应用程序，您也可以通过在 Dockerfile 中构建启动检查和健康检查来增加弹性。

Swarm 定义添加了秘密和配置设置，容器标签的应用方式也有所不同。

```
nerd-dinner-api:
  configs:
   - source: nerd-dinner-api-config
      target: C:\dinner-api\config\config.json
  secrets:
   - source: nerd-dinner-api-secrets
      target: C:\dinner-api\config\secrets.json
  deploy:
  replicas: 2  labels:
     - "traefik.frontend.rule=Host:api.nerddinner.swarm"
     - "traefik.port=80" 
```

配置和秘密只适用于 Swarm 模式，但可以在任何 Compose 文件中包含它们——当您在单个 Docker 引擎上运行时，Docker Compose 会忽略它们。`deploy`部分也只适用于 Swarm 模式，它捕获了副本的基础架构设置。在这里，我有一个副本计数为 2，这意味着 Swarm 将为此服务运行两个容器。我还在`deploy`部分下有 Traefik 的标签，这确保了标签被应用到容器上，而不是服务本身。

Docker 使用标签来注释任何类型的对象——卷、节点、服务、秘密、容器和任何其他 Docker 资源都可以添加或删除标签，并且它们以键值对的形式暴露在 Docker Engine API 中。Traefik 只查找容器标签，这些标签在 Compose 文件的`deploy`部分中在 Swarm 模式下应用。如果您直接在服务部分下有标签，那么它们将被添加到服务而不是容器。在这种情况下，这意味着容器上没有标签，因此 Traefik 不会注册任何路由。

# 在 Docker Compose 文件中定义 Swarm 资源

在本章中，核心的`docker-compose.yml`文件只包含一个`services`部分；没有指定其他资源。这是因为我的应用程序的资源在单个 Docker 引擎部署和 Docker Swarm 之间都是不同的。

本地覆盖文件使用现有的`nat`网络，并对 SQL Server 和 Elasticsearch 使用默认规范的卷。

```
networks:
  nd-net:
    external:
      name: nat volumes:
  ch07-es-data: ch07-db-data:
```

Swarm 覆盖将所有服务附加到的相同`nd-net`网络映射为一个名为`nd-swarm`的外部网络，这个网络需要在我部署此堆栈之前存在。

```
networks:
  nd-net:
    external:
      name: nd-swarm
```

在集群覆盖中没有定义卷。在集群模式下，您可以像在单个 Docker 引擎上使用卷一样使用它们，但您可以选择使用不同的驱动程序，并将存储设备连接到数据中心或云存储服务以连接到您的容器卷。

Docker 中的存储本身就是一个完整的主题。我在我的 Pluralsight 课程**在 Docker 中处理数据和有状态应用程序**中详细介绍了它。在那门课程中，我演示了如何在桌面上以及在 Docker Swarm 中以高可用性和规模的方式运行有状态的应用程序和数据库。

在集群覆盖文件中有另外两个部分，涵盖了我的应用程序配置：

```
configs: nerd-dinner-api-config: external: true
  nerd-dinner-config: 
    external: true

secrets:
  nerd-dinner-db-sa-password:
    external: true nerd-dinner-save-handler-secrets: external: true nerd-dinner-api-secrets: external: true nerd-dinner-secrets: external: true
```

如果您看到这些并认为这是很多需要管理的`configs`和`secrets`，请记住，这些是您的应用程序无论在哪个平台上都需要的配置数据。Docker 的优势在于所有这些设置都被集中存储和管理，并且如果它们包含敏感数据，您可以选择安全地存储和传输它们。

我的所有配置和秘密对象都被定义为外部资源，因此它们需要在集群中存在才能部署我的应用程序。在`ch07-docker-stack`目录中有一个名为`apply-configuration.ps1`的脚本，其中包含所有的`docker config create`和`docker secret create`命令：

```
> .\apply-configuration.ps1
ntkafttcxvf5zjea9axuwa6u9
razlhn81s50wrqojwflbak6qx
npg65f4g8aahezqt14et3m31l
ptofylkbxcouag0hqa942dosz
dwtn1q0idjz6apbox1kh512ns
reecdwj5lvkeugm1v5xy8dtvb
nyjx9jd4yzddgrb2nhwvqjgri
b3kk0hkzykiyjnmknea64e3dk
q1l5yp025tqnr6fd97miwii8f
```

输出是新对象 ID 的列表。现在所有资源都存在，我可以将我的应用程序部署为一个堆栈。

# 从 Docker Compose 文件部署集群堆栈

我可以通过在开发笔记本上指定多个 Compose 文件（核心文件和本地覆盖）来使用 Docker Compose 部署应用程序。在集群模式下，您使用标准的`docker`命令，而不是`docker-compose`来部署堆栈。Docker CLI 不支持堆栈部署的多个文件，但我可以使用 Docker Compose 将源文件合并成一个单独的堆栈文件。这个命令从两个 Compose 文件中生成一个名为`docker-stack.yml`的单个 Compose 文件，用于堆栈部署：

```
docker-compose -f docker-compose.yml -f docker-compose.swarm.yml config > docker-stack.yml
```

Docker Compose 合并输入文件并检查输出配置是否有效。我将输出保存在一个名为`docker-stack.yml`的文件中。这是一个额外的步骤，可以轻松地融入到您的部署流程中。现在我可以使用包含核心服务描述、秘密和部署配置的堆栈文件在集群上部署我的堆栈。

您可以使用单个命令`docker stack deploy`从 Compose 文件中部署堆栈。您需要传递 Compose 文件的位置和堆栈的名称，然后 Docker 将创建 Compose 文件中的所有资源：

```
> docker stack deploy --compose-file docker-stack.yml nerd-dinner
Creating service nerd-dinner_message-queue
Creating service nerd-dinner_elasticsearch
Creating service nerd-dinner_nerd-dinner-api
Creating service nerd-dinner_kibana
Creating service nerd-dinner_nerd-dinner-index-handler
Creating service nerd-dinner_nerd-dinner-save-handler
Creating service nerd-dinner_reverse-proxy
Creating service nerd-dinner_nerd-dinner-web
Creating service nerd-dinner_nerd-dinner-homepage
Creating service nerd-dinner_nerd-dinner-db
```

结果是一组资源被逻辑地组合在一起形成堆栈。与 Docker Compose 不同，后者依赖命名约定和标签来识别分组，堆栈在 Docker 中是一等公民。我可以列出所有堆栈，这给我基本的细节——堆栈名称和堆栈中的服务数量：

```
> docker stack ls
NAME                SERVICES            ORCHESTRATOR
nerd-dinner         10                  Swarm
```

我的堆栈中有 10 个服务，从一个包含 137 行 YAML 的单个 Docker Compose 文件部署。对于这样一个复杂的系统来说，这是一个很小的配置量：两个数据库，一个反向代理，多个前端，一个 RESTful API，一个消息队列和多个消息处理程序。这样大小的系统通常需要一个运行数百页的 Word 部署文档，并且需要一个周末的手动工作来运行所有步骤。我只用了一个命令来部署这个系统。

我还可以深入了解运行堆栈的容器的状态和它们所在的节点，使用`docker stack ps`，或者使用`docker stack services`来获得堆栈中服务的更高级视图。

```
> docker stack services nerd-dinner
ID              NAME       MODE        REPLICAS        IMAGE
3qc43h4djaau  nerd-dinner_nerd-dinner-homepage       replicated  2/2       dockeronwindows/ch03...
51xrosstjd79  nerd-dinner_message-queue              replicated  1/1       dockeronwindows/ch05...
820a4quahjlk  nerd-dinner_elasticsearch              replicated  1/1       sixeyed/elasticsearch...
eeuxydk6y8vp  nerd-dinner_nerd-dinner-web            replicated  2/2       dockeronwindows/ch07...
jlr7n6minp1v  nerd-dinner_nerd-dinner-index-handler  replicated  2/2       dockeronwindows/ch05...
lr8u7uoqx3f8  nerd-dinner_nerd-dinner-save-handler   replicated  3/3       dockeronwindows/ch05...
pv0f37xbmz7h  nerd-dinner_reverse-proxy              replicated  1/1       sixeyed/traefik...
qjg0262j8hwl  nerd-dinner_nerd-dinner-db             replicated  1/1       dokeronwindows/ch07...
va4bom13tp71  nerd-dinner_kibana                     replicated  1/1       sixeyed/kibana...
vqdaxm6rag96  nerd-dinner_nerd-dinner-api            replicated  2/2       dockeronwindows/ch07...
```

这里的输出显示我有多个副本运行前端容器和消息处理程序。总共，在我的两节点集群上有 15 个容器在运行，这是两个虚拟机，总共有四个 CPU 核心和 8GB 的 RAM。在空闲时，容器使用的计算资源很少，我有足够的容量来运行额外的堆栈。我甚至可以部署相同堆栈的副本，为代理使用不同的端口，然后我可以在相同的硬件上运行两个完全独立的测试环境。

将服务分组到堆栈中可以更轻松地管理应用程序，特别是当您有多个应用程序在运行，每个应用程序中有多个服务时。堆栈是对一组 Docker 资源的抽象，但您仍然可以直接管理单个资源。如果我运行`docker service rm`，它将删除一个服务，即使该服务是堆栈的一部分。当我再次运行`docker stack deploy`时，Docker 会发现堆栈中缺少一个服务，并重新创建它。

当涉及到使用新的镜像版本或更改服务属性来更新应用程序时，您可以采取命令式方法直接修改服务，或者通过修改堆栈文件并再次部署来保持声明性。Docker 不会强加给您任何流程，但最好保持声明性，并将 Compose 文件用作唯一的真相来源。

我可以通过在堆栈文件的部署部分添加`replicas: 2`并再次部署它，或者通过运行`docker service update --replicas=2 nerd-dinner_nerd-dinner-save-handler`来扩展解决方案中的消息处理程序。如果我更新了服务但没有同时更改堆栈文件，那么下次部署堆栈时，我的处理程序将减少到一个副本。堆栈文件被视为期望的最终状态，如果当前状态偏离了，那么在再次部署时将进行纠正。

使用声明性方法意味着您始终在 Docker Compose 文件中进行这些更改，并通过再次部署堆栈来更新应用程序。Compose 文件与您的 Dockerfiles 和应用程序源代码一起保存在源代码控制中，因此它们可以进行版本控制、比较和标记。这意味着当您拉取应用程序的任何特定版本的源代码时，您将拥有构建和部署所需的一切。

秘密和配置是例外，您应该将它们保存在比中央源代码库更安全的位置，并且只有管理员用户才能访问明文。Compose 文件只是引用外部秘密，因此您可以在源代码控制中获得应用程序清单的唯一真相来源的好处，而敏感数据则保留在外部。

在开发和测试环境中运行单个节点或双节点集群是可以的。我可以将完整的 NerdDinner 套件作为一个堆栈运行，验证堆栈文件是否正确定义，并且可以扩展和缩小以检查应用程序的行为。这并不会给我带来高可用性，因为集群只有一个管理节点，所以如果管理节点下线，那么我就无法管理堆栈。在数据中心，您可以运行一个拥有数百个节点的集群，并且通过三个管理节点获得完整的高可用性。

您可以在云中运行它，构建具有更高可用性和规模弹性的群集。所有主要的云运营商都支持其 IaaS 服务中的 Docker，因此您可以轻松地启动预安装了 Docker 的 Linux 和 Windows VM，并使用本章中所见的简单命令将它们加入到群集中。

Docker Swarm 不仅仅是在集群中规模化运行应用程序。在多个节点上运行使我具有高可用性，因此在发生故障时我的应用程序可以继续运行，并且我可以利用它来支持应用程序生命周期，实现零停机滚动更新和自动回滚。

# 无停机部署更新

Docker Swarm 具有两个功能，可以在不影响应用程序的情况下更新整个堆栈-滚动更新和节点排空。滚动更新在您有一个组件的新版本要发布时，用新图像的新实例替换应用程序容器。更新是分阶段进行的，因此只要您有多个副本，就会始终有任务在运行以提供请求，同时其他任务正在升级。

应用程序更新将频繁发生，但您还需要定期更新主机，无论是升级 Docker 还是应用 Windows 补丁。Docker Swarm 支持排空节点，这意味着在节点上运行的所有容器都将停止，并且不会再安排更多容器。如果在排空节点时服务的副本级别下降，任务将在其他节点上启动。当节点排空时，您可以更新主机，然后将其加入到群集中。

我将通过覆盖这两种情况来完成本章。

# 更新应用程序服务

我在 Docker Swarm 上运行我的堆栈，现在我要部署一个应用程序更新-一个具有重新设计的 UI 的新主页组件，这是一个很好的、容易验证的变化。我已经构建了`dockeronwindows/ch07-nerd-dinner-homepage:2e`。为了进行更新，我有一个新的 Docker Compose 覆盖文件，其中只包含现有服务的新图像名称：

```
version: '3.7' services:
  nerd-dinner-homepage:
    image: dockeronwindows/ch07-nerd-dinner-homepage:2e
```

在正常发布中，您不会使用覆盖文件来更新一个服务。您将更新核心 Docker Compose 文件中的图像标签，并将文件保存在源代码控制中。我使用覆盖文件是为了更容易地跟随本章的示例。

此更新有两个步骤。首先，我需要通过组合 Compose 文件和所有覆盖文件来生成新的应用程序清单：

```
docker-compose `
  -f docker-compose.yml `
  -f docker-compose.swarm.yml `
 -f new-homepage.yml `
 config > docker-stack-2.yml
```

现在我可以部署这个堆栈：

```
> docker stack deploy -c .\docker-stack-2.yml nerd-dinner
Updating service nerd-dinner_nerd-dinner-save-handler (id: 0697sstia35s7mm3wo6q5t8nu)
Updating service nerd-dinner_nerd-dinner-homepage (id: v555zpu00rwu734l2zpi6rwz3)
Updating service nerd-dinner_reverse-proxy (id: kchmkm86wk7d13eoj9t26w1hw)
Updating service nerd-dinner_message-queue (id: jlzt6svohv1bo4og0cbx4y5ac)
Updating service nerd-dinner_nerd-dinner-api (id: xhlzf3kftw49lx9f8uemhv0mo)
Updating service nerd-dinner_elasticsearch (id: 126s2u0j78k1c9tt9htdkup8x)
Updating service nerd-dinner_nerd-dinner-index-handler (id: zd651rohewgr3waud6kfvv7o0)
Updating service nerd-dinner_nerd-dinner-web (id: yq6c51bzrnrfkbwqv02k8shvr)
Updating service nerd-dinner_nerd-dinner-db (id: wilnzl0jp1n7ey7kgjyjak32q)
Updating service nerd-dinner_kibana (id: uugw7yfaza84k958oyg45cznp)
```

命令输出显示所有服务都在 `Updating`，但 Docker Swarm 只会实际更改 Compose 文件中期望状态与运行状态不同的服务。在这个部署中，它将使用 Compose 文件中的新镜像名称更新主页服务。

更新对您要升级的镜像没有任何限制。它不需要是同一存储库名称的新标签；它可以是完全不同的镜像。这是非常灵活的，但这意味着您需要小心，不要意外地用新版本的 Web 应用程序更新您的消息处理程序，反之亦然。

Docker 一次更新一个容器，您可以配置更新之间的延迟间隔以及更新失败时要采取的行为。在更新过程中，我可以运行 `docker service ps` 命令，并看到原始容器处于 `Shutdown` 状态，替换容器处于 `Running` 或 `Starting` 状态：

```
> docker service ps nerd-dinner_nerd-dinner-homepage
ID    NAME   IMAGE   NODE  DESIRED STATE CURRENT STATE ERROR  PORTS
is12l1gz2w72 nerd-dinner_nerd-dinner-homepage.1 win2019-02          Running Running about a minute ago
uu0s3ihzp4lk \_ nerd-dinner_nerd-dinner-homepage.1 win2019-02       Shutdown Shutdown 2 minutes ago
0ruzheqp29z1 nerd-dinner_nerd-dinner-homepage.2 win2019-dev-02      Running Running 2 minutes ago
5ivddeffrkjj \_ nerd-dinner_nerd-dinner-homepage.2 win2019-dev-02   Shutdown  Shutdown 2 minutes ago
```

新的 NerdDinner 主页应用程序的 Dockerfile 具有健康检查，Docker 会等到新容器的健康检查通过后才会继续替换下一个容器。在滚动更新期间，一些用户将看到旧的主页，而一些用户将看到时尚的新主页：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/c490a14f-6719-4859-8377-c5232d8783cd.png)

Traefik 与主页容器之间的通信使用 VIP 网络，因此它只会将流量发送到运行容器的主机 - 用户将从已更新并运行 `ch07` 镜像的容器或者即将更新并运行 `ch03` 镜像的容器中获得响应。如果这是一个高流量的应用程序，我需要确保服务中有足够的容量，这样当一个任务正在更新时，剩余的任务可以处理负载。

滚动更新可以实现零停机时间，但这并不一定意味着您的应用程序在更新期间将正常运行。这个过程只适用于无状态应用程序 - 如果任务存储任何会话状态，那么用户体验将受到影响。当包含状态的容器被替换时，状态将丢失。如果您有有状态的应用程序，您需要计划一个更谨慎的升级过程 - 或者最好是将这些组件现代化，以便在容器中运行的共享组件中存储状态。

# 服务更新回滚

在群集模式下更新服务时，群集会存储先前部署的配置。如果您发现发布存在问题，可以使用单个命令回滚到先前的状态：

```
> docker service update --rollback nerd-dinner_nerd-dinner-homepage
nerd-dinner_nerd-dinner-homepage
```

回滚是服务更新的一种特殊形式。`rollback`标志不是传递任务要更新的镜像名称，而是对服务使用的先前镜像进行滚动更新。同样，回滚是一次只更新一个任务，因此这是一个零停机过程。无论您如何应用更新，都可以使用此命令回滚到之前的状态，无论您是使用`docker stack deploy`还是`docker service update`。

回滚是少数几种情况之一，您可能希望使用命令式命令来管理应用程序，而不是声明式的 Docker Compose 文件。如果您发现服务更新存在问题，只需使用单个命令即可将其回滚到先前状态，这非常棒。

服务更新仅保留一个先前的服务配置用于回滚。如果您从版本 1 更新到版本 2，然后再更新到版本 3，版本 1 的配置将丢失。您可以从版本 3 回滚到版本 2，但如果再次从版本 2 回滚，将回到先前的版本，这将使您在版本 3 之间循环。

# 配置更新行为

对于大规模部署，可以更改默认的更新行为，以便更快地完成滚动更新，或者运行更保守的滚动更新策略。默认行为是一次只更新一个任务，任务更新之间没有延迟，如果任务更新失败，则暂停滚动更新。可以使用三个参数覆盖配置：

+   `update-parallelism`：同时更新的任务数量

+   `update-delay`：任务更新之间等待的时间段；可以指定为小时、分钟和秒

+   `update-failure-action`：如果任务更新失败，要采取的操作，是继续还是停止滚动更新

您可以在 Dockerfile 中指定默认参数，以便将其嵌入到镜像中，或者在 Compose 文件中指定默认参数，以便在部署时或使用服务命令时设置。对于 NerdDinner 的生产部署，我可能有九个 SQL 消息处理程序实例，Compose 文件中的`update_config`设置为以三个为一批进行更新，并设置为 10 秒的延迟：

```
nerd-dinner-save-handler:
  deploy:
  replicas: 9
  update_config:
    parallelism: 3
    delay: 10s
...
```

服务的更新配置也可以通过`docker service update`命令进行更改，因此您可以修改更新参数并通过单个命令启动滚动升级。

健康检查在服务更新中尤为重要。如果服务更新中的新任务健康检查失败，这可能意味着镜像存在问题。完成部署可能导致 100%的不健康任务和一个破损的应用程序。默认的更新配置可以防止这种情况发生，因此如果更新的任务没有进入运行状态，部署将被暂停。更新将不会继续进行，但这比拥有一个破损的更新应用程序要好。

# 更新集群节点

应用程序更新是更新例程的一部分，主机更新是另一部分。您的 Windows Docker 主机应该运行一个最小的操作系统，最好是 Windows Server 2019 Core。这个版本没有用户界面，因此更新的表面积要小得多，但仍然会有一些需要重新启动的 Windows 更新。

重新启动服务器是一个侵入性的过程——它会停止 Docker Engine Windows 服务，杀死所有正在运行的容器。出于同样的原因，升级 Docker 同样具有侵入性：这意味着需要重新启动 Docker Engine。在集群模式中，您可以通过在更新期间将节点从服务中移除来管理此过程，而不会影响服务水平。

我将用我的集群来展示这一点。如果我需要在`win2019-02`上工作，我可以通过`docker node update`优雅地重新安排它正在运行的任务，将其置于排水模式：

```
> docker node update --availability drain win2019-02
win-node02
```

将节点置于排水模式意味着所有容器都将被停止，由于这些是服务任务容器，它们将在其他节点上被新容器替换。当排水完成时，`win-node02`上将没有正在运行的任务：它们都已经被关闭。您可以看到任务已被故意关闭，因为“关闭”被列为期望状态：

```
> docker node ps win2019-02
ID   NAME  NODE         DESIRED STATE         CURRENT                STATE              
kjqr0b0kxoah  nerd-dinner_nerd-dinner-homepage.1      win2019-02     Shutdown Shutdown 48 seconds ago
is12l1gz2w72 \_ nerd-dinner_nerd-dinner-homepage.1    win2019-02     Shutdown Shutdown 8 minutes ago
xdbsme89swha nerd-dinner_nerd-dinner-index-handler.1  win2019-02     Shutdown Shutdown 49 seconds ago
j3ftk04x1e9j  nerd-dinner_nerd-dinner-db.1            win2019-02     Shutdown 
Shutdown 47 seconds ago
luh79mmmtwca   nerd-dinner_nerd-dinner-api.1          win2019-02     Shutdown Shutdown 47 seconds ago
... 
```

我可以检查服务列表，并看到每个服务仍然处于所需的副本级别：

```
> docker service ls
ID              NAME                                 MODE          REPLICAS   
126s2u0j78k1  nerd-dinner_elasticsearch            replicated       1/1 
uugw7yfaza84  nerd-dinner_kibana                   replicated       1/1 
jlzt6svohv1b  nerd-dinner_message-queue            replicated       1/1 
xhlzf3kftw49  nerd-dinner_nerd-dinner-api          replicated       2/2  
wilnzl0jp1n7  nerd-dinner_nerd-dinner-db           replicated       1/1   
v555zpu00rwu nerd-dinner_nerd-dinner-homepage      replicated       2/2
zd651rohewgr nerd-dinner_nerd-dinner-index-handler replicated       2/2  
0697sstia35s nerd-dinner_nerd-dinner-save-handler  replicated       3/3
yq6c51bzrnrf nerd-dinner_nerd-dinner-web           replicated       2/2 
kchmkm86wk7d nerd-dinner_reverse-proxy             replicated       1/1 
```

集群已经创建了新的容器来替换在`win2019-02`上运行的副本。实际上，现在所有的副本都在单个节点上运行，但通过入口网络和 VIP 负载平衡，应用程序仍然以相同的方式工作。Docker Engine 仍然以排水模式运行，因此如果任何外部流量到达排水节点，它们仍然会将其转发到活动节点上的容器。

处于排水模式的节点被视为不可用，因此如果群需要安排新任务，则不会分配任何任务给排水节点。`win-node02`现在有效地停用了，所以我可以登录并使用`sconfig`工具运行 Windows 更新，或者更新 Docker Engine。

更新节点可能意味着重新启动 Docker Engine 或重新启动服务器。完成后，我可以使用另一个`docker node update`命令将服务器重新上线到群中：

```
docker node update --availability active win2019-02
```

这使得节点再次可用。当节点加入群时，Docker 不会自动重新平衡运行的服务，因此所有容器仍然留在`win2019-dev02`上，即使`win-node02`再次可用并且容量更大。

在高吞吐量环境中，服务经常启动、停止和扩展，加入群的任何节点很快就会运行其份额的任务。在更静态的环境中，您可以通过运行 Docker 服务`update --force`来手动重新平衡服务。这不会更改服务的配置，但它会替换所有副本，并在安排新容器运行时使用所有活动节点。

这是一种破坏性的行为，因为它迫使 Docker 停止健康的容器。您需要确信如果强制重新平衡不会影响应用程序的可用性。Docker 无法保证不知道您的应用程序的架构，这就是为什么当节点加入群时服务不会自动重新平衡。

Swarm 模式使您有权更新应用程序的任何组件和运行群的节点，而无需任何停机时间。在更新期间，您可能需要在群中委托额外的节点，以确保您有足够的容量来覆盖被停用的节点，但之后可以将其移除。您无需任何额外的工具即可进行滚动更新、自动回滚和路由到健康容器——这一切都内置在 Docker 中。

# 混合主机在混合群中

Swarm 模式的另一个功能使其非常强大。群中的节点使用 Docker API 进行通信，而 API 是跨平台的，这意味着您可以在单个群中运行混合的 Windows 和 Linux 服务器。Docker 还可以在不同的 CPU 架构上运行，因此您可以将传统的 64 位 Intel 服务器与高效的新 ARM 板混合使用。

Linux 不是本书的重点，但我会简要介绍混合群集，因为它们开启了新的可能性范围。混合群集可以将 Linux 和 Windows 节点作为管理节点和工作节点。您可以使用完全相同的 Docker CLI 以相同的方式管理节点和它们运行的服务。

混合群集的一个用例是在 Linux 上运行您的管理节点，以减少许可成本或如果您的群集在云中运行则减少运行成本。生产群集将需要至少三个管理节点。即使您的所有工作负载都是基于 Windows 的，也可能更具成本效益地运行 Linux 节点作为管理节点 - 如果有这个选项的话 - 并将 Windows 节点保留给用户工作负载。

另一个用例是用于混合工作负载。我的 NerdDinner 解决方案使用的是作为 Linux Docker 镜像可用的开源软件，但我不得不自己为 Windows Server 2019 容器打包。我可以将任何跨平台组件迁移到混合群集中的 Linux 容器中运行。这可能是来自第五章的.NET Core 组件，以及 Traefik、NATS 消息队列、Elasticsearch、Kibana，甚至 SQL Server。Linux 镜像通常比 Windows 镜像小得多，更轻巧，因此您应该能够以更高的密度运行，将更多的容器打包到每个主机上。

混合群集的巨大好处在于，您可以以相同的方式从相同的用户界面管理所有这些组件。您可以将本地的 Docker CLI 连接到群集管理器，并使用完全相同的命令管理 Linux 上的 Traefik 代理和 Windows 上的 ASP.NET 应用程序。

# 总结

本章主要介绍了 Docker Swarm 模式，这是内置在 Docker 中的本地集群选项。您学会了如何创建一个群集，如何添加和删除群集节点，以及如何在连接了覆盖网络的群集上部署服务。我展示了您必须为高可用性创建服务，并讨论了如何使用配置和秘密在群集中安全存储敏感的应用程序数据。

您可以使用 Compose 文件将应用程序部署为群集上的堆栈，这样可以非常容易地对应用程序组件进行分组和管理。我演示了在单节点群集和多节点群集上的堆栈部署 - 对于具有数百个节点的群集，流程是相同的。

Docker Swarm 中的高可用性意味着您可以在没有停机时间的情况下执行应用程序更新和回滚。甚至在需要更新 Windows 或 Docker 时，您也可以将节点停用，仍然可以在剩余节点上以相同的服务水平运行您的应用程序。

在下一章中，我将更仔细地研究 docker 化解决方案的管理选项。我将首先看看如何使用现有的管理工具来管理在 Docker 中运行的应用程序。然后，我将继续使用 Docker Enterprise 在生产环境中管理 swarms。
