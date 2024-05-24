# Spring5 软件架构（三）

> 原文：[`zh.annas-archive.org/md5/45D5A800E85F86FC16332EEEF23286B1`](https://zh.annas-archive.org/md5/45D5A800E85F86FC16332EEEF23286B1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：微服务

我们不断寻找新的方法来创建软件系统，以满足既支持他们业务需求的应用程序的满意客户，又受到尖端技术挑战的开发人员。满足这两种目标用户的平衡很重要；这使我们能够实现业务目标，避免失去技术娴熟的开发人员。

另一方面，作为开发人员，我们也在努力创建模块和专门的库，以满足特定的技术或业务需求。稍后，我们将在不同的项目中重用这些模块和库，以符合“不要重复自己”（DRY）原则。

以这个介绍作为出发点，我们将回顾微服务架构如何解决这些问题以及更多内容。在本章中，我们将讨论以下主题：

+   微服务原则

+   建模微服务

+   +   如何使用 Spring Cloud 实现微服务：

+   支持动态配置

+   启用服务发现和注册

+   边缘服务

+   断路器模式和 Hystrix

# 微服务原则

在网上有很多微服务的定义。经常出现的一个是以下内容：

“微服务是小型且自主的服务，能够良好地协同工作。”

让我们从这个定义开始，更详细地了解它的含义。

# 大小

微服务一词中包含“微”这个词，让我们认为服务的大小必须非常小。然而，几乎不可能使用诸如代码行数、文件数量或特定可部署工件的大小等指标来定义服务的正确大小。相反，使用以下想法要简单得多：

“一个服务应专注于做好一件事。”

- Sam Newman

那“一件事”可以被视为一个业务领域。例如，如果您正在为在线商店构建系统，它们可能涵盖以下业务领域：

+   客户管理

+   产品目录

+   购物车

+   订单

这个想法是构建一个能够满足特定业务领域所有需求的服务。最终，当业务领域变得太大，无法仅作为一个微服务处理时，您可能还会将一个服务拆分为其他微服务。

# 自主的

自主性在谈论微服务时非常重要。微服务应该有能力独立于其周围的其他服务进行更改和演变。

验证微服务是否足够自主的最佳方法是对其进行更改并部署服务的新版本。部署过程不应要求您修改除服务本身之外的任何内容。如果在部署过程中需要重新启动其他服务或其他任何内容，您应考虑消除这些额外步骤的方法。另一方面，服务的自主性也与构建它的团队的组织有关。我们将在本章后面详细讨论这一点。

# 良好协同工作

在孤立地构建不相互交互的系统是不可能的。即使我们正在构建不同业务领域需求的独立服务，最终我们也需要使它们作为一个整体进行交互，以满足业务需求。这种交互是通过使用应用程序编程接口（API）来实现的。

“API 是程序员可以用来创建软件或与外部系统交互的一组命令、函数、协议和对象。它为开发人员提供了执行常见操作的标准命令，因此他们不必从头编写代码。”

- API 定义来自 https://techterms.com/definition/api

单片应用程序往往进行数据库集成。这是应该尽量避免的事情；任何所需的服务之间的交互应该只使用提供的服务 API 来完成。

# 优势

微服务提供了许多值得了解的优势，以了解公司可能如何受益。最常见的优势如下：

+   符合单一责任原则

+   持续发布

+   独立可伸缩性

+   增加对新技术的采用

# 符合单一责任原则

使用微服务涉及创建单独的组件。每个组件都设计为解决特定的业务领域模型。因此，该领域模型定义了服务的单一责任。服务不应违反其限制，并且应该使用其他微服务提供的 API 请求任何超出其范围的信息。每个微服务应该暴露一个 API，其中包含所有必需的功能，以允许其他微服务从中获取信息。

# 持续发布

由于大型的单片应用程序处理许多业务领域模型，它们由大量的源代码和配置文件组成。这会产生需要大量时间才能部署的大型构件。此外，大型单片应用程序通常涉及分布在世界各地的大型团队，这使得沟通困难。在开发新功能或修复应用程序中的错误时，这会成为一个问题。微服务能够轻松解决这个问题，因为一个团队将负责一个或多个服务，并且一个服务很少由多个团队编写。这意味着新版本可以在团队内计划，这使得他们能够更快更频繁地推出新版本。

此外，即使代码中的最小更改也需要部署大型构件，这使得整个应用程序在部署过程中不可用。然而，对于微服务，只需部署具有漏洞修补程序或新功能的服务。部署速度快，不会影响其他服务。

# 独立可伸缩性

如果我们需要扩展一个单片应用程序，整个系统应该部署在不同的服务器上。服务器应该非常强大，以使应用程序能够良好运行。并非所有功能都具有相同的流量，但由于所有代码都打包为单个构件，因此无法仅扩展所需的功能。使用微服务，我们有自由只扩展我们需要的部分。通常可以找到云提供商提供通过按需提供更多服务器或在需要时自动添加更多资源来扩展应用程序的机会。

# 新技术的增加采用

并非所有业务领域模型都是相等的，这就是为什么需要不同的技术集。由于一个微服务只应处理一个领域模型的需求，因此不同的服务可以轻松采用不同的技术。通常可以找到公司使用不同的编程语言、框架、云提供商和数据库来编写他们的微服务。此外，我们有能力为小型应用程序尝试新技术，然后可以在其他地方使用。由于采用新技术，公司最终会拥有异构应用程序，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/442ed02e-81a5-4135-999c-05b281bb3aba.png)

异构应用程序使我们能够使用正确的技术集创建专门的系统来解决特定的业务需求。因此，我们最终会拥有易于部署和独立扩展的小构件。

# 缺点

尽管微服务具有我们之前列出的所有优点，但重要的是要理解它们也有一些缺点。让我们回顾一下这些，并考虑如何处理它们：

+   选择太多

+   一开始慢

+   监控

+   事务和最终一致性

# 选择太多

由于您有机会选择要使用哪种技术构建微服务，您可能会因为可用选项的广泛多样而感到不知所措。这可以通过仅使用少量新技术而不是一次性尝试将它们全部整合来解决。

# 一开始慢

在采用微服务的过程中，您必须构建整个生态系统以使它们运行。您需要寻找连接分布式系统、保护它们并使它们作为一个整体运行的新方法。编写一个应用程序来完成所有这些工作更容易。然而，几个月后，其他微服务将重复使用您一开始投入的所有工作，这意味着流程速度显著加快。要充分利用这种创建系统的方式，重要的是尝试新的部署应用程序的方式，使其按需扩展，监控和记录它们。还重要的是审查处理业务核心的微服务的功能。这些系统有时最终成为半单体应用，应该拆分以便更容易管理。

# 监控

监控单个应用比监控许多不同服务的实例更容易。重要的是创建仪表板和自动化工具，提供指标以使这项任务更容易完成。当出现新错误时，很难弄清楚问题出在哪里。应该使用良好的日志跟踪机制来确定应用的哪个服务未按预期工作。这意味着您不必分析所有服务。

# 事务和最终一致性

尽管大型单体应用有着明确定义的事务边界，而且我们在编写微服务时经常使用两阶段提交等技术，但我们必须以另一种方式来满足这些要求。

我们应该记住，每个微服务都拥有自己的数据存储，并且我们应该仅使用它们的 API 来访问它们的数据。保持数据最新并在操作不符合预期时使用补偿事务是很重要的。当我们编写单体应用时，许多操作作为单个事务执行。对于微服务，我们需要重新思考操作和事务，使它们适应每个微服务的边界。

# 建模微服务

作为开发人员，我们总是试图创建可重用的组件来与系统或服务交互，以避免重复编写代码。到目前为止，我们构建的大多数单体应用都遵循了三层架构模式，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/01da1f47-1a59-4f7a-b61b-761ce7deb621.png)

三层架构

当需要对使用此模型构建的应用进行更改时，通常需要修改所有三层。根据应用程序的创建方式，可能需要进行多次部署。此外，由于大型单体应用共享许多功能，通常会发现有多个团队在其上工作，这使得它们更难快速发展。有时，专门的团队会在特定层上工作，因为这些层由许多组件组成。通过这种方式，可以水平应用更改以使应用程序增长和发展。

使用微服务，应用程序在特定业务领域周围建模，因此应用程序在垂直方向上发展。以下图表显示了在线商店应用程序的一些微服务：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/6e0cad3b-c090-41a7-bcdc-7a268937aeab.png)

微服务图表

这些名称本身就解释了微服务的意图和相关功能集合。仅通过阅读名称，任何人都可以理解它们的功能；如何执行任务以及它们如何实现在这一点上是无关紧要的。由于这些服务围绕着一个明确定义的业务领域构建，当需要进行新更改时，只有一个服务应该被修改。由于不止一个团队应该在一个微服务上工作，与大型单体相比，使它们发展变得更容易。负责服务的团队深刻了解特定服务的工作方式以及如何使其发展。

负责微服务的团队由该服务业务领域的专家组成，但不擅长其周围其他服务的技术。毕竟，技术选择包括细节；服务的主要动机是业务领域。

# 加速

我们在本章前面提到，基于微服务开发应用程序在开始阶段是一个耗时的过程，因为您从头开始。无论您是开始一个新项目还是将现有的遗留应用程序拆分为单独的微服务，您都必须完成将应用程序从开发到生产的所有必要步骤。

# 加速开发过程

让我们从开发阶段开始。当您在旧应用程序上工作时，通常在编写第一行代码之前，您必须经历以下步骤：

1.  在本地机器上安装所需的工具。

1.  设置所有必需的依赖项。

1.  创建一个或多个配置文件。

1.  发现所有未列入文档的缺失部分。

1.  加载测试数据。

1.  运行应用程序。

现在，假设您是作为一个团队的一部分，拥有用不同编程语言编写并使用不同数据库技术的许多微服务。您能想象在编写第一行代码之前需要多少努力吗？

使用微服务应该能够为您提供更快的解决方案，但所需的所有设置使其在最初变得更慢。对于大型单片应用程序，您只需要设置一个环境，但对于异构应用程序，您将需要设置许多不同的环境。为了有效地解决这个问题，您需要拥抱自动化文化。您可以运行脚本来代替手动执行所有上述步骤。这样，每当您想要在不同的项目上工作时，您只需要执行脚本，而不是重复列出的所有步骤。

市场上有一些非常酷的工具，比如 Nanobox（https://nanobox.io）、Docker Compose（https://docs.docker.com/compose/）和 Vagrant（https://www.vagrantup.com）。这些工具可以通过运行单个命令提供类似于生产环境的环境，从而帮助您。

采用前面提到的工具将对开发团队的生产力产生巨大影响。您不希望开发人员浪费时间提供自己的环境；相反，您希望他们编写代码为产品添加新功能。

# 拥抱测试

让我们谈谈编写代码的过程。当我们在大型单体上工作时，每次发布新功能或错误修复时都需要通知许多人。在极端情况下，QA 团队需要自行检查整个环境，以确保新更改不会影响应用程序的现有功能。想象一下为多个微服务的每次发布重复执行此任务会耗费多少时间。因此，您需要将测试作为开发过程的必要部分。

有许多不同级别的测试。让我们来看一下 Jason Huggins 在 2005 年引入的金字塔测试，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/6c7dbaa5-4d0c-4e3d-a378-6efdaf5a0fcb.png)

金字塔测试

金字塔底部的测试很容易且快速编写和执行。运行单元测试只需要几分钟，对验证隔离的代码片段是否按预期工作很有用。另一方面，集成测试对验证代码在与数据库、第三方应用程序或其他微服务交互时是否正常工作很有用。这些测试需要几十分钟才能运行。最后，端到端（e2e）测试帮助您验证代码是否符合最终用户的预期。如果你正在编写一个 REST API，e2e 测试将使用不同的数据验证 API 的 HTTP 响应代码。这些测试通常很慢，而且它们一直在变化。

理想情况下，所有新功能都应该经过所有这些测试，以验证您的代码在进入生产之前是否按预期工作。你写的测试越多，你就会获得越多的信心。毕竟，如果你覆盖了所有可能的情况，还会出什么问题呢？此外，Michael Bryzek 提出了在生产中进行测试的想法（有关更多信息，请参见[`www.infoq.com/podcasts/Michael-Bryzek-testing-in-production`](https://www.infoq.com/podcasts/Michael-Bryzek-testing-in-production)）。这有助于您通过定期执行自动化任务或机器人来评估您的服务是否正常运行，以在生产中运行系统的关键部分。

# 投入生产

你必须以与自动化开发环境相同的方式自动化生产环境。如今，公司普遍使用云提供商部署其系统，并使用 API 驱动工具提供服务器。

安装操作系统并添加所需的依赖项以使应用程序工作必须自动化。如果要提供多台服务器，只需多次执行相同的脚本。Docker、Puppet 和 Chef 等技术可以帮助你做到这一点。使用代码提供环境的间接好处是，你将拥有使应用程序工作所需的所有依赖项的完美文档。随着时间的推移，这些脚本可以得到改进。它们存储在版本控制系统中，这样就很容易跟踪对它们所做的每一次更改。我们将在第十一章 *DevOps 和发布管理*中进一步讨论这一点。

# 实施微服务

现在我们对微服务的定义和用途有了很好的理解，我们将开始学习如何使用 Spring Framework 实施微服务架构。在接下来的几节中，我们将看一些到目前为止还没有涉及的重要概念。最好从实际角度来接触这些概念，以便更容易理解。

# 动态配置

我们都曾经在使用不同配置文件或相关元数据的应用程序上工作，以允许你指定使应用程序工作的配置参数。当我们谈论微服务时，我们需要以不同的方式来处理这个配置过程。我们应该避免配置文件，而是采用由 Heroku 提出的十二要素应用程序配置风格（在[`12factor.net`](https://12factor.net)中概述）。当我们使用这种配置风格时，我们希望将每个环境中不同的属性外部化，并使其易于创建和更改。

默认情况下，Spring Boot 应用程序可以使用命令行参数、JNDI 名称或环境变量工作。Spring Boot 还提供了使用`.properties`或`.yaml`配置文件的能力。为了以安全的方式处理配置变量，Spring Boot 引入了`@ConfigurationProperties`注释，它允许您将属性映射到**普通的 Java 对象**（**POJOs**）。应用程序启动时，它会检查所有配置是否已提供、格式是否正确，并符合`@Valid`注释要求的需求。让我们看看这个映射是如何工作的。

假设您的应用程序中有以下`application.yaml`文件：

```java
middleware:
  apiKey: ABCD-1234
  port: 8081

event-bus:
  domain: event-bus.api.com
  protocol: http
```

现在，让我们使用`@ConfigurationProperties`注释将这些变量映射到两个不同的 POJO 中。让我们从给定的中间件配置开始：

```java
@Data
@Component
@ConfigurationProperties("middleware")
public class Middleware 
{
  private String apiKey;
  private int port;
}
```

以下代码片段代表了`eventBus`配置部分所需的类：

```java
@Data
@Component
@ConfigurationProperties("event-bus")
public class EventBus 
{
  private String domain;
  private String protocol;
}
```

使用 lombok 的`@Data`注释来避免编写标准访问器方法。现在，您可以打印这些类的`.toString()`结果，并且您将在控制台中看到以下输出：

```java
EventBus(domain=event-bus.api.com, protocol=http)
Middleware(apiKey=ABCD-1234, port=8081)
```

将所有这些配置变量硬编码可能很有用。这意味着当您想要在另一个环境中部署应用程序时，您可以通过提供额外的参数来简单地覆盖它们，如下所示：

```java
$ java -Dmiddleware.port=9091 -jar target/configuration-demo-0.0.1-SNAPSHOT.jar
```

在运行`.jar`文件之前，我们在文件中覆盖了一个配置变量，因此您将得到如下所示的输出：

```java
EventBus(domain=event-bus.api.com, protocol=http)
Middleware(apiKey=ABCD-1234, port=9091)
```

尽管这种配置很容易实现，但对于微服务或一般的现代应用程序来说还不够好。首先，在应用任何更改后，您需要重新启动应用程序，这是不可取的。最糟糕的是，您无法跟踪您所应用的更改。这意味着如果提供了环境变量，就无法知道是谁提供的。为了解决这个问题，Spring 提供了一种集中所有配置的方法，使用 Spring Cloud 配置服务器。

该服务器提供了一种集中、记录和安全的方式来存储配置值。由于它将所有配置值存储在可以是本地或远程的 Git 存储库中，因此您将免费获得与版本控制系统相关的所有好处。

# 实施配置服务器

Spring Cloud 配置服务器是建立在常规 Spring Boot 应用程序之上的。您只需要添加以下附加依赖项：

```java
compile('org.springframework.cloud:spring-cloud-config-server')
```

添加依赖项后，您需要使用应用程序中的附加注释来激活配置服务器，如下面的代码所示：

```java
@SpringBootApplication
@EnableConfigServer
public class ConfigServerApplication 
{
  public static void main(String[] args) 
  {
    SpringApplication.run(ConfigServerApplication.class, args);
  }
}
```

最后，您需要提供存储微服务配置的 Git 存储库 URL，存储在`application.yaml`文件中，如下所示：

```java
spring:
  cloud:
    config:
      server:
        git:
          uri: https://github.com/enriquezrene/spring-architectures-config-server.git
```

前面的 Git 存储库有单独的配置文件来管理每个微服务的配置。例如，`configuration-demo.properties`文件用于管理配置演示微服务的配置。

# 实施配置客户端

配置客户端是常规的 Spring Boot 应用程序。您只需要提供服务器配置 URI 以读取集中配置，如下所示：

```java
spring:
  application:
 name: configuration-demo
  cloud:
    config:
 uri: http://localhost:9000
```

以下代码片段显示了一个 REST 端点，读取集中配置并将读取的值作为自己的响应提供：

```java
@RestController
@RefreshScope
public class ConfigurationDemoController {

 @Value("${configuration.dynamicValue}")
    private String dynamicValue;

    @GetMapping(path = "/dynamic-value")
    public ResponseEntity<String> readDynamicValue() {
        return new ResponseEntity<>(this.dynamicValue, HttpStatus.OK);
    }
}
```

以下屏幕截图显示了存储在 Git 存储库中的配置文件：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/f41e5b6e-ec7e-45fb-b14b-8461c1d5e3e4.png)

存储在 Git 存储库中的配置文件

一旦您对前面的端点执行请求，它将产生以下输出：

```java
$ curl http://localhost:8080/dynamic-value 
Old Dynamic Value
```

更改存储在 Git 中的文件中的配置变量的值，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/92a82e19-3a7a-44fc-98ef-4ec55933662c.png)

应用更改后的配置文件

如果您访问端点，将检索到与之前相同的输出。为了重新加载配置，您需要通过使用`POST`请求命中`/refresh`端点来重新加载配置变量，如下代码所示：

```java
$ curl -X POST http://localhost:8080/actuator/refresh
["config.client.version","configuration.dynamicValue"]
```

重新加载配置后，端点将使用新提供的值提供响应，如下输出所示：

```java
$ curl http://localhost:8080/dynamic-value
New Dynamic Value
```

# 服务发现和注册

过去，我们的应用程序存在于单个物理服务器上，应用程序与实施它的后端之间存在 1:1 的关系。在这种情况下，查找服务非常简单：您只需要知道服务器的 IP 地址或相关的 DNS 名称。

后来，应用程序被分布，这意味着它们存在于许多物理服务器上以提供高可用性。在这种情况下，服务与后端服务器之间存在 1:*N*的关系，其中*N*可以表示多个。传入请求使用负载均衡器进行管理，以在可用服务器之间路由请求。

当物理服务器被虚拟机替换时，使用相同的方法。负载均衡器需要一些配置来注册新的可用服务器并正确路由请求。这项任务过去由运维团队执行。

今天，常见的是在容器中部署应用程序，我们将在第十章中进一步讨论，*容器化您的应用程序*。容器每毫秒都在不断提供和销毁，因此手动注册新服务器是不可能的任务，必须自动化。为此，Netflix 创建了一个名为 Eureka 的项目。

# 介绍 Eureka

Eureka 是一个允许您自动发现和注册服务器的工具。您可以将其视为一个电话目录，其中所有服务都注册了。它有助于避免在服务器之间建立直接通信。例如，假设您有三个服务，它们都相互交互。使它们作为一个整体工作的唯一方法是指定服务器或其负载均衡器的 IP 地址和端口，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/e1c9b79a-b9e3-4659-8b69-8ba590c91a23.png)

服务相互交互

如前图所示，交互直接发生在服务器或它们的负载均衡器之间。当添加新服务器时，应手动或使用现有的自动化机制在负载均衡器中注册它。此外，使用 Eureka，您可以使用在其上注册的服务名称建立通信。以下图表显示了相同的交互如何与 Eureka 一起工作：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/ae639f43-2562-4a8d-ad5c-c629b24571a1.png)

使用 Eureka 注册的服务

这意味着当您需要在服务之间建立通信时，您只需要提供名称而不是 IP 地址和端口。当一个服务有多个实例可用时，Eureka 也将作为负载均衡器工作。

# 实现 Netflix Eureka 服务注册表

由于 Eureka 是为了允许与 Spring Boot 平稳集成而创建的，因此可以通过添加以下依赖项来简单实现服务注册表：

```java
compile
 ('org.springframework.cloud:spring-cloud-starter-netflix-eureka-server')
```

`application`类也应该被修改，以指示应用程序将作为 Eureka 服务器工作，如下所示：

```java
@EnableEurekaServer
@SpringBootApplication
public class ServiceRegistryApplication 
{
  public static void main(String[] args) 
  {
    SpringApplication.run(ServiceRegistryApplication.class, args);
  }
}
```

运行应用程序后，您可以在`http://localhost:8901/`看到 Web 控制台，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/5ea2fea4-1bdc-4882-bfc1-e16b8f311f2e.png)

Eureka Web 控制台

# 实现服务注册表客户端

之前，我们提到过负载均衡器曾经用于通过使用多个服务器作为后端来提供高可伸缩性。Eureka 以相同的方式工作，但主要好处是当服务器的更多实例被提供时，您不需要在服务注册表中添加任何配置。相反，每个实例都应让 Eureka 知道它想要注册。

注册新服务非常简单。您只需要包含以下依赖项：

```java
compile
 ('org.springframework.cloud:spring-cloud-starter-netflix-eureka-client')
```

服务应用程序类应包括一个附加的注解，如下所示：

```java
@EnableDiscoveryClient
@SpringBootApplication
public class MoviesServiceApplication 
{
  public static void main(String[] args) 
  {
    SpringApplication.run(MoviesServiceApplication.class, args);
  }
}
```

最后，您需要在`application.properties`文件中指定 Eureka 服务器 URI，如下所示：

```java
# This name will appear in Eureka
spring.application.name=movies-service
eureka.client.serviceUrl.defaultZone=http://localhost:8901/eureka
```

运行此 Spring Boot 应用程序后，它将自动在 Eureka 中注册。您可以通过刷新 Eureka Web 控制台来验证这一点。您将看到服务已注册，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/784bdd55-5354-4bc4-9e78-1b3e24bfc6fc.png)

Eureka 中注册的实例

一旦服务注册，您将希望消费它们。使用 Netflix Ribbon 是消费服务的最简单方式之一。

# Netflix Ribbon

Ribbon 是一个客户端负载均衡解决方案，与 Spring Cloud 生态系统无缝集成。它可以通过指定服务名称来消费使用 Eureka 暴露的服务。由于所有服务器实例都在 Eureka 中注册，它将选择其中一个来执行请求。

假设我们有另一个名为`cinema-service`的服务。假设该服务有一个端点，可以用来按 ID 查询电影院。作为电影院负载的一部分，我们希望包括`movies-service`中所有可用的电影。

首先，我们需要添加以下依赖项：

```java
compile('org.springframework.cloud:spring-cloud-starter-netflix-ribbon')
```

然后，作为`application`类的一部分，我们需要创建一个新的`RestTemplate` bean，以便注入以消费 Eureka 中可用的服务：

```java
@EnableDiscoveryClient
@SpringBootApplication
public class CinemaServiceApplication 
{
  public static void main(String[] args) 
  {
    SpringApplication.run(CinemaServiceApplication.class, args);
  }
 @LoadBalanced
  @Bean
  RestTemplate restTemplate() 
  {
 return new RestTemplate();
  }
}
```

`RestTemplate`短语是用于消费 RESTful web 服务的客户端。它可以执行对`movies-service`的请求如下：

```java
@RestController
public class CinemasController 
{
  private final CinemaRepository cinemaRepository;
 private final RestTemplate restTemplate;
  public CinemasController(CinemaRepository cinemaRepository,
  RestTemplate restTemplate) 
  {
    this.cinemaRepository = cinemaRepository;
 this.restTemplate = restTemplate;
  }
  @GetMapping("/cinemas/{cinemaId}/movies")
  public ResponseEntity<Cinema> queryCinemaMovies   
  (@PathVariable("cinemaId") Integer cinemaId) 
  {
    Cinema cinema = cinemaRepository.findById(cinemaId).get();
    Movie[] movies = restTemplate
    .getForObject(
 "http://movies-service/movies", Movie[].class);
    cinema.setAvailableMovies(movies);
    return new ResponseEntity<>(cinema, HttpStatus.OK);
  }
}
```

请注意服务名称的指定方式，我们不必提供任何其他信息，如 IP 地址或端口。这很好，因为在新服务器按需创建和销毁时，确定这些信息将是不可能的。

# 边缘服务

边缘服务是一个中间组件，对外部世界和下游服务都是可见的。它作为一个网关，允许周围所有服务之间的交互。以下图表显示了边缘服务的使用方式：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/a6d4231e-c5b5-4c63-9916-65351fb64aab.png)

边缘服务

请注意，所有传入请求都直接指向边缘服务，后者将稍后查找正确的服务以正确重定向请求。

边缘服务以不同的方式使用，根据周围的服务添加额外的行为或功能。最常见的例子是跨域资源共享（CORS）([`developer.mozilla.org/en-US/docs/Web/HTTP/CORS`](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS))过滤器。您可以向边缘服务添加 CORS 过滤器，这意味着下游服务不需要实现任何内容。假设我们**只**想允许来自域**abc.com**的传入请求。我们可以将此逻辑作为边缘服务的一部分实现，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/44c5a40f-277c-4153-9fc7-4f8b786940f9.png)

使用边缘服务的 CORS 过滤器

在这里，我们可以看到所有逻辑只添加在一个地方，下游服务不必实现任何内容来管理所需的行为。

边缘服务还用于许多其他需求，我们将在下一节讨论。市场上有许多不同的边缘服务实现。在下一节中，我们将讨论 Netflix 的 Zuul，因为它与 Spring Cloud 集成得很顺畅。

# 介绍 Zuul

Zuul 是 Netflix 创建的边缘服务，其功能基于过滤器。Zuul 过滤器遵循拦截器过滤器模式（如[`www.oracle.com/technetwork/java/interceptingfilter-142169.html`](http://www.oracle.com/technetwork/java/interceptingfilter-142169.html)中所述）。使用过滤器，您可以在路由过程中对 HTTP 请求和响应执行一系列操作。

Zuul 是一个来自电影的门卫的名字（请参阅[`ghostbusters.wikia.com/wiki/Zuul`](http://ghostbusters.wikia.com/wiki/Zuul)了解更多详情），它确切地代表了这个项目的功能，即门卫的功能。

您可以在四个阶段应用过滤器，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/17767e7f-7cd0-417a-933f-62bed7f88750.png)

Zuul 过滤器

让我们回顾一下这些阶段：

+   **pre**：在请求被处理之前

+   **route**：在将请求路由到服务时

+   **post**：在请求被处理后

+   **error**：当请求发生错误时

使用这些阶段，您可以编写自己的过滤器来处理不同的需求。`pre`阶段的一些常见用途如下：

+   认证

+   授权

+   速率限制

+   请求正文中的翻译和转换操作

+   自定义标头注入

+   适配器

`route`阶段的一些常见过滤器用途如下：

+   金丝雀发布

+   代理

一旦一个请求被微服务处理，就会有两种情况：

+   处理成功

+   请求处理过程中发生错误

如果请求成功，将执行与`post`阶段相关的所有过滤器。在此阶段执行的一些常见过滤器用途如下：

+   响应有效负载中的翻译和转换操作

+   存储与业务本身相关的度量标准

另一方面，当请求处理过程中发生错误时，所有`error`过滤器都将被执行。此阶段过滤器的一些常见用途如下：

+   保存请求的相关元数据

+   出于安全原因，从响应中删除技术细节

上述观点只是每个阶段过滤器的一些常见用途。在编写针对您需求的过滤器时，请考虑您自己的业务。

为了编写一个 Zuul 过滤器，应该扩展`ZuulFilter`类。这个类有以下四个需要实现的抽象方法：

```java
public abstract class ZuulFilter 
implements IZuulFilter, Comparable<ZuulFilter> 
{
  public abstract String filterType();
  public abstract int filterOrder();
 public abstract boolean shouldFilter();
  public abstract Object run() throws ZuulException;
  ...
}
```

粗体显示的两个方法并不是直接在`ZuulFilter`类中声明的，而是从`IZuulFilter`接口继承而来，这个接口是由这个类实现的。

让我们回顾一下这些方法，以了解 Zuul 过滤器的工作原理。

首先，您有`filterType`方法，需要在其中指定要执行当前过滤器的阶段。该方法的有效值如下：

+   `pre`

+   `post`

+   `route`

+   `error`

您可以自己编写上述值，但最好使用`FilterConstant`类，如下所示：

```java
@Override
public String filterType() 
{
  return FilterConstants.PRE_TYPE;
}
```

所有阶段都列在我们之前提到的类中：

```java
public class FilterConstants 
{ 
  ...
  public static final String ERROR_TYPE = "error";
  public static final String POST_TYPE = "post";
  public static final String PRE_TYPE = "pre";
  public static final String ROUTE_TYPE = "route";
}
```

`filterOrder`方法用于定义将执行过滤器的顺序。每个阶段通常有多个过滤器，因此通过使用该方法，可以为每个过滤器配置所需的顺序。最高值表示执行顺序较低。

通过使用`org.springframework.core.Ordered`接口，可以轻松配置执行顺序，该接口有两个值可用作参考：

```java
package org.springframework.core;
public interface Ordered 
{
  int HIGHEST_PRECEDENCE = -2147483648;
  int LOWEST_PRECEDENCE = 2147483647;
  ...
}
```

`shouldFilter`方法用于确定是否应执行过滤逻辑。在这个方法中，你可以使用`RequestContext`类来访问请求信息，如下所示：

```java
RequestContext ctx = RequestContext.getCurrentContext();
// do something with ctx 
```

这个方法应该返回一个布尔值，指示是否应执行`run`方法。

最后，`run`方法包含在过滤器中应用的逻辑。在这个方法中，你也可以使用`RequestContext`类来执行所需的逻辑。

例如，让我们使用之前实现的端点来查询电影院放映的电影：

```java
curl http://localhost:8701/cinemas-service/cinemas/1/movies
```

以下是一个简单的实现，用于打印请求的方法和 URL：

```java
@Override
public Object run() throws ZuulException {
    RequestContext ctx = RequestContext.getCurrentContext();
    HttpServletRequest request = ctx.getRequest();
    log.info("Requested Method: {}", request.getMethod());
    log.info("Requested URL: {}", request.getRequestURL());
    return null;
}
```

一旦请求被处理，你将得到以下输出：

```java
PRE FILTER
Requested Method: GET
Requested URL: http://localhost:8701/cinemas-service/cinemas/1/movies
```

# CAP 定理

在 2000 年的**分布式计算原理研讨会**（**SPDC**）上，Eric Brewer 提出了以下理论：

“一个共享数据系统不可能同时提供这三个属性中的两个以上（一致性、高可用性和分区容错）。”

- Eric Brewer

让我们来回顾一下这三个属性。

# 一致性

一个一致的系统能够在每次后续操作中报告其当前状态，直到状态被外部代理显式更改。换句话说，每个`read`操作应该检索到上次写入的数据。

# 高可用性

高可用性指的是系统在从外部代理检索任何请求时始终能够提供有效的响应能力。在理想的情况下，系统应该始终能够处理传入的请求，从不产生错误。至少应该以对用户不可感知的方式处理它们。

# 分区容错

一个分区容错的分布式系统应该始终保持运行，即使与其节点之一的通信无法建立。

Brewer 的理论可以应用于任何分布式系统。由于微服务架构是基于分布式计算概念的，这意味着这个理论也适用于它们。

尽管理论表明系统无法同时实现所有三个属性，我们应该构建能够优雅处理故障的系统。这就是断路器模式可以应用的地方。

# 断路器

断路器模式旨在处理系统与其他运行在不同进程中的系统进行远程调用时产生的故障。该模式的主要思想是用一个能够监视故障并产生成功响应的对象来包装调用，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/084f7ab6-ed84-41c0-871d-1d552f66326f.png)

断路器模式

请注意，断路器模式在无法与目标服务建立连接时提供替代响应。让我们看看如何使用 Hystrix 来实现这种模式并将其纳入我们的应用程序。

# Hystrix

Hystrix 是 Netflix 于 2011 年创建的一个库。它是为了处理与外部服务交互时的延迟和连接问题而创建的。Hystrix 的主要目的是在通信问题发生时提供一种替代方法来执行。它可以这样实现：

```java
@Service
public class MoviesService {

    private final RestTemplate restTemplate;

    public MoviesService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @HystrixCommand(fallbackMethod = "emptyMoviesArray")
    public Movie[] getMovies(){
        return restTemplate.getForObject
            ("http://movies-service/movies", Movie[].class);
    }

    public Movie[] emptyMoviesArray(){
        Movie movie = new Movie();
        movie.setId(-1);
        movie.setName("Coming soon");
        return new Movie[]{movie};
    }
}
```

注意`getMovies`方法如何尝试与另一个服务交互以获取电影列表。该方法用`@HystrixCommand(fallbackMethod = "emptyMoviesArray")`进行了注释。`fallbackMethod`值指示在与其他服务通信期间发生错误时要使用的替代方法。在这种情况下，替代方法提供了一个硬编码的电影数组。这样，你可以在需要与外部服务交互时避免级联故障。通过优雅地处理故障，这为最终用户提供了更好的体验。

# 摘要

在本章中，我们讨论了微服务的原则、优势和缺点。之后，我们学习了如何对微服务进行建模，并讨论了一些与分布式计算相关的重要概念，这些概念是这种架构风格固有的。最后，我们回顾了 CAP 定理以及如何在与其他服务交互时优雅地处理故障。在下一章中，我们将探讨无服务器架构风格，这也可以作为您的微服务环境的一部分进行集成。


# 第九章：无服务器架构

无服务器架构正在成为 IT 系统构建中的一种流行趋势。因此，人们经常讨论亚马逊网络服务（AWS）、谷歌云和微软 Azure 等云提供商。

在本章中，我们将探讨无服务器架构的含义，以及这种新的构建系统的方式如何帮助我们在更短的时间内满足业务需求，从而减少构建业务解决方案所需的工作量。我们还将看看如何利用现成的第三方服务和实现自定义功能，从而创建可以部署在云上的无状态函数，从而大大减少到达生产所需的时间。

在本章中，我们将涵盖以下主题：

+   无服务器架构简介

+   基础设施和文件存储

+   好处和陷阱

+   后端即服务

+   函数即服务

+   对无服务器架构的担忧：

+   供应商锁定问题

+   安全问题

+   框架支持

+   故障排除

+   无服务器架构的示例和常见用途

+   使用无服务器架构实施应用程序：

+   如何使用 Spring 编写函数

+   使用 AWS Lambda 和 Azure 的适配器

# 无服务器架构简介

无服务器架构是通过亚马逊的倡议诞生的。该公司希望推广一个开发团队可以自主、小型和自我管理的环境，使其能够从编写代码到在生产环境中交付和交付整个软件开发周期。

无服务器架构有时被误解为部署软件系统而无需物理服务器的概念。要理解这个想法，您可以查看 Martin Fowler 的博客中对无服务器的定义：

“重要的是要理解，无服务器架构是开发人员将业务逻辑编码为函数的方法，忘记了服务器的配置和扩展问题，其中逻辑将被执行。”

- [`martinfowler.com/articles/serverless.html`](https://martinfowler.com/articles/serverless.html)

无服务器和 FaaS 的常见示例包括：

+   认证

+   短信通知

+   电子邮件服务

另一方面，在无服务器的世界中，通常会创建应用程序，其中采用第三方服务作为系统的一部分（而不是从头开始创建服务）。这些服务通常被称为后端即服务（BaaS）或移动后端即服务（MBaaS）。

采用相同的方法，我们可以将自定义业务逻辑编码为可以部署在云上的函数。这些服务被称为函数即服务（FaaS）。

以下图表说明了第三方服务和自定义功能是如何被不同的软件系统创建、部署和消费的：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/2a9521c5-ac3c-4b18-a3aa-55abc5441088.png)

第三方服务和自定义功能

# 基础设施和文件存储

基础设施和文件存储也被视为无服务器，因为拥有系统的业务（或个人）不必购买、租用或配置服务器或虚拟机来使用它们。

作为开发人员，如果我们采用老式方法（使用本地环境提供所有基础设施），我们必须为我们想要部署软件系统的每个环境设置所有软件和硬件要求。这个配置过程必须在所有环境中重复进行，直到我们进入生产阶段，在这一点上，我们必须处理其他功能，如扩展和监控。在许多情况下，我们的基础设施将被低效利用，这是一种浪费金钱的行为，因为我们购买了强大的服务器来部署不需要太多资源的应用程序。

# 好处和陷阱

采用无服务器架构方法创建应用程序为我们提供了许多好处，但也有一些缺点需要解决。让我们先来回顾一下好处：

+   使用无服务器架构的开发人员可以主要专注于代码，可以忘记与服务器供应有关的一切，这是云提供商自己处理的任务。

+   代码的扩展是短暂的，意味着它可以根据检索的请求数量进行扩展和启动或关闭。

+   根据定义，用于编写业务逻辑的所有功能必须是无状态的，因此松散耦合。这样，任务就可以专注于明确定义的责任。

+   功能可以通过事件异步触发。

+   我们只需支付所消耗的计算时间。

+   这些功能的功能是基于事件驱动模型的。

+   开发者可以以透明的方式实现无限扩展。

另一方面，也存在一些缺点：

+   缺乏可用作参考的文档和展示

+   当需要同时使用多个服务时引入的延迟问题

+   某些功能仅在特定的云服务提供商中可用。

+   供应商锁定

为了解决供应商锁定的问题，强烈建议在无服务器架构的一部分使用**多云**方法。多云策略涉及使用多个云提供商。这很重要，因为通过它，我们可以利用不同供应商和不同产品的优势。例如，Google 提供了出色的机器学习服务，AWS 提供了各种标准服务，微软 Azure 为远程调试等功能提供了出色的功能。另一方面，云无关的策略建议我们尽可能避免依赖特定的云提供商，以便在需要时自由部署系统。然而，这将很难实现，因为这意味着以更通用的方式设计系统，忽略提供额外优势的特定供应商功能。

# 后端即服务

使用 BaaS 方法的最简单情景是创建**单页应用程序**（**SPA**）或与云中可用服务交互的移动应用程序。

通常可以找到应用程序，其中认证过程委托给第三方服务，使用标准协议（如 OAuth），将信息持久存储在云数据库（如 Google Firebase），或通过短信服务（如 Twilio）发送通知。

BaaS 可以帮助我们解决一些问题，以便我们可以在不必担心应用程序的服务器或虚拟机的情况下部署到生产环境。此外，BaaS 还为我们提供了整个基础设施和节点，例如以下内容：

+   负载均衡器

+   数据库用于存储我们的数据（NoSQL 或 RDBMS）

+   文件系统

+   队列服务器

BaaS 还满足以下要求：

+   备份

+   复制

+   补丁

+   规模

+   高可用性

另一方面，BaaS 也增加了作为服务的新产品的诞生，包括以下内容：

+   **Firebase**：这为我们提供了分析、数据库、消息传递和崩溃报告等功能

+   **Amazon DynamoDB**：这个键值存储是非关系型数据库

+   **Azure Cosmos DB**：这是一个全球分布的多模型数据库服务

随着所有这些变化和新工具，我们必须接受一种新的思维方式，并打破构建应用程序的范式。由于无服务器是一种新技术，建议进行实验，从使用应用程序的一小部分开始。想想您当前应用程序中的三个例子，这些例子使用无服务器方法进行重构将会很有趣。现在，与您的团队商讨并组织一个架构对抗（http://architecturalclash.org/）研讨会，以确定您的想法是否可行。

# 函数即服务

自 2014 年以来，AWS Lambda 的使用越来越受欢迎。在某些情况下，甚至可以使用 FaaS 方法构建整个应用程序；在其他情况下，该方法用于解决特定要求。

函数形式部署的代码在事件发生时被执行。一旦事件发生，代码被执行，然后函数被关闭。因此，函数本质上是无状态的，因为没有状态或上下文可以与其他应用程序共享。

FaaS 是短暂的，意味着当需要执行函数时，云提供商将自动使用与函数相关的元数据来提供环境。这将根据处理需求进行扩展，并且一旦处理完成，执行环境将被销毁，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/9b51d091-c38d-4713-88ff-3f1775474b06.png)

短暂的 FaaS 过程

使用 FaaS 方法实现代码将为您提供以下好处：

+   您不必担心主机配置

+   透明的按需扩展

+   自动启动/关闭

+   您只需为您使用的部分付费

# 关于无服务器架构的担忧

新的技术趋势有时会产生韧性和担忧，但它们也提供了实验和为应用程序和业务获益的机会。

服务器无架构涉及的最常见问题如下：

+   供应商锁定

+   安全性

+   框架支持

+   故障排除

# 供应商锁定

在供应商锁定方面，主要问题是无法将新服务作为供应商的无服务器架构的一部分。这个问题归结为对与云提供商绑定的恐惧。

建议尽可能使用您选择的云提供商的许多功能。您可以通过开始一个试点并评估云提供商来做到这一点；在将更多代码移至云之前，一定要创建一个利弊评估。

不要因为这个问题而放弃使用无服务器架构。相反，建议开始一个概念验证并评估云提供商。无服务器是一种新技术，将随着时间的推移而发展，有办法保持 FaaS 的独立性，例如使用 Spring Cloud 功能。我们将在本章的后面部分的一个示例中进行这方面的工作。

最后，您应该明白，从一个供应商转移到另一个供应商（从云到云）并不像过去（当我们将应用程序或传统代码转移到本地环境时）那么困难。

# 安全性

安全性是一个关键问题，与应用程序的架构无关，无服务器也不例外。由于我们在云中创建函数作为服务，我们需要在我们的身份验证、执行授权和 OWASP 方面小心。然而，在这种情况下，云提供商（如 AWS 或 Azure）为我们提供了开箱即用的指南和实践，以减少我们的担忧。

在无服务器中需要考虑的另一个安全问题是缺乏明确定义的安全边界。换句话说，当一个函数的安全边界结束并且另一个函数开始时，不同的云提供商提供不同的方法来使这些函数作为一个整体工作；例如，AWS 通过使用称为 API 网关的服务来实现这一点。这个 API 用于编排和组合创建的 FaaS。另一方面，正如一切都是短暂的一样，许多这些问题可能会消失，因为 FaaS 中的短暂概念是每次调用 FaaS 时都会创建、运行和销毁函数的请求都是隔离的。

为了澄清任何疑虑，我们将开始将部分代码移动到无服务器/函数即服务，创建一个实验性的开发，并在对该概念更有信心时逐步增加。

# 框架支持

有几个框架正在努力创建开发无服务器架构的环境，而不依赖于云提供商。根据我的经验，最好创建函数作为服务，尽可能地利用云平台。由于函数是具有清晰输入或输出的小段代码，最好使用您感到舒适的语言和技术，甚至尝试新技术或编程语言，以确定它们的优劣。

在这个阶段，无服务器支持多种语言来构建函数。目前，部署 FaaS 的最常见选项如下：

+   AWS Lamba

+   Azure 函数

+   Google 函数

Java 开发人员的一个好处是，大多数云提供商都支持 Java 作为一种编程语言来部署函数。此外，Spring Framework 有一个名为 Spring Functions 的项目，可以用来编写函数；我们将在本章后面使用这个项目来实现一些功能。

使用 Spring Functions 的一个好处是，我们可以在本地机器上开发和测试我们的代码，然后使用适配器包装代码，以便在云提供商上部署它。

# 故障排除

一旦应用程序（或在本例中的函数）部署到生产环境中，需要考虑的关键方面之一是如何跟踪、查找和修复错误。对于无服务器来说，这可能会很棘手，因为我们正在处理一个更为分隔的场景，我们的系统有一些未分成服务和微服务的小部分。几个函数是逻辑和代码的小部分。为了解决这个问题，每个云提供商都有工具来监视和跟踪函数，处理短暂环境中的错误。如果我们组合了几个函数的逻辑，我们将不得不应用聚合日志记录等技术，并使用工具来收集与执行的代码相关的信息。我们将在第十二章中审查一些处理这个概念的技术，*监控*。

# 示例和常见用例

即使无服务器架构为我们提供了许多好处，这些好处也不能应用于所有情况。当应用程序同时使用传统服务器（本地或基于云的）部署的后端和用于特定需求的 FaaS 或第三方服务时，使用混合模型是非常常见的。

无服务器架构可以应用于以下一些常见场景：

+   处理 webhooks

+   应该在特定情况下安排或触发的任务或工作

+   数据转换，例如：

+   图像处理、压缩或转换

+   语音数据转录成文本，比如 Alexa 或 Cortana

+   基于移动后端作为服务方法的移动应用程序的某种逻辑

+   单页应用程序

+   聊天机器人

另一方面，无服务器架构不适用于以下情况：

+   需要大量资源（如 CPU 和内存）的长时间运行的进程

+   任何阻塞进程

# 采用无服务器架构为 SPA 提供支持

**单页应用程序（SPA）**为采用无服务器架构方法提供了最适合的场景之一。毕竟，它们不涉及太多编码的业务逻辑，它们主要提供和消费由其他地方部署的服务提供的内容。

例如，假设我们需要构建一个应用程序来向用户发送世界杯比赛结果。在这个例子中，我们需要满足以下要求：

+   认证

+   数据存储

+   通知机制

采用无服务器架构方法，这些要求可以由以下服务提供商解决：

+   **认证**：Google OAuth

+   **数据存储**：Google Firebase

+   **通知机制**：

+   短信，使用 Twilio

+   电子邮件，使用 SparkPost

以下图表说明了如何将前述服务（Google OAuth、Firebase、Twilo 和 SparkPost）作为应用程序的一部分使用：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/72855d45-d8aa-4459-aed9-b2b8d8f7c805.png)

集成不同的第三方应用程序

前面的图表显示了一些最知名的服务提供商，但在互联网上还有很多其他选择。

前述服务的一个好处是它们都提供了一个可以直接从 SPA 中使用的 SDK 或库，包括常见的 JavaScript 库，如 Angular。

# 使用 Spring Cloud Functions 实现 FaaS

在 Spring 项目的支持下，您会发现 Spring Cloud Function 项目（[`cloud.spring.io/spring-cloud-function/`](https://cloud.spring.io/spring-cloud-function/)），它旨在使用无服务器架构模型实现应用程序。

使用 Spring Cloud Function，我们可以编写可以在支持 FaaS 的不同云提供商上启动的函数。无需从头学习新东西，因为 Spring Framework 的所有核心概念和主要功能，如自动配置、依赖注入和内置指标，都以相同的方式应用。

一旦函数编码完成，它可以部署为 Web 端点、流处理器，或者简单的任务，这些任务由特定事件触发或通过调度程序触发。

通过 SPA 的一个例子，我们可以使用第三方服务、现有的 REST API 和自定义函数来实现一个应用程序。以下图表说明了如何使用前面提到的所有选项来创建一个应用程序：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/b25759bc-4d9f-4662-8f0a-5eb4b4059b00.png)

将 FaaS 集成到应用程序中

让我们来看看前面图表中的组件是如何工作的：

+   认证由第三方服务提供

+   应用程序使用驻留在 REST API 中的业务逻辑

+   自定义函数可以作为 SPA 的一部分使用

以下图表说明了函数的工作原理：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/031689ad-d967-430b-ba3a-5fb17771f1a2.png)

函数即服务

让我们来回顾图表的每个部分：

+   函数提供了一种使用事件驱动编程模型的方式。

+   我们可以以对开发人员透明的方式进行无限扩展。这种扩展将由我们用来部署函数的平台处理。

+   最后，我们只需支付函数在执行过程中消耗的时间和资源。

# 使用 Spring 的函数

Spring Cloud Function 为我们带来了四个主要功能，详细描述在官方文档中（[`github.com/spring-cloud/spring-cloud-function`](https://github.com/spring-cloud/spring-cloud-function)），这里值得一提：

+   它提供了包装`@Beans`类型的函数、消费者和供应商的能力。这使得可以将功能公开为 HTTP 端点，并通过监听器或发布者进行流消息传递，使用消息代理如 RabbitMQ、ActiveMQ 或 Kafka。

+   它提供了编译的字符串，这些字符串将被包装为函数体。

+   我们可以部署一个带有我们的函数的 JAR 文件，带有一个独立的类加载器，它将在单个 Java 虚拟机上运行。

+   它为支持无服务器架构的不同云提供商提供适配器，例如以下：

+   AWS Lambda

+   Open Whisk

+   Azure

# 编写示例

现在，我们将创建一个掩码银行帐户号码的函数。让我们从头开始创建一个新的 Spring Boot 应用程序，使用 Spring Initializr 网站（[`start.spring.io`](https://start.spring.io)）：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/5619b314-f7dd-441d-8b7e-58b911dac1ea.png)

Spring Initializr 网站

目前，作为项目的一部分，不需要包含额外的依赖项。项目结构非常简单，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/a3436649-226c-4e1e-81d8-212a23d10aae.png)

为了使用 Spring 编写函数，我们必须将 Spring Cloud Function 项目作为依赖项包含进来；首先，让我们添加一些属性来指定我们将要使用的版本，如下所示：

```java
  <parent>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-parent</artifactId>
 <version>1.5.11.RELEASE</version>
      <relativePath/>
   </parent>

   <properties>
      <project.build.sourceEncoding>UTF-
      8</project.build.sourceEncoding>
      <project.reporting.outputEncoding>UTF-
      8</project.reporting.outputEncoding>
      <java.version>1.8</java.version>
      <spring-cloud-function.version>
        1.0.0.BUILD-SNAPSHOT
      </spring-cloud-function.version>
 <reactor.version>3.1.2.RELEASE</reactor.version>
 <wrapper.version>1.0.9.RELEASE</wrapper.version>
   </properties>
```

请注意，我们将将 Spring 版本降级为 1.5.11 RELEASE，因为 Spring Cloud Function 目前尚未准备好在 Spring Boot 2 中使用。

现在，我们将添加依赖项，如下所示：

```java
<dependency>
  <groupId>org.springframework.cloud</groupId>
  <artifactId>spring-cloud-starter-function-web</artifactId>
</dependency>
<dependency>
  <groupId>org.springframework.cloud</groupId>
  <artifactId>spring-cloud-function-compiler</artifactId>
</dependency>

```

然后，我们必须在依赖管理部分中添加一个条目，以便 Maven 自动解析所有传递依赖项：

```java
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.springframework.cloud</groupId>
      <artifactId>spring-cloud-function-dependencies</artifactId>
      <version>${spring-cloud-function.version}</version>
      <type>pom</type>
      <scope>import</scope>
    </dependency>
  </dependencies>
</dependencyManagement>
```

最后，我们将包含一些插件，这些插件将允许我们通过将以下条目添加为`pom.xml`文件的一部分来包装编码的函数：

```java
<build>
  <plugins>
    <plugin>
      <groupId>org.apache.maven.plugins</groupId>
      <artifactId>maven-deploy-plugin</artifactId>
      <configuration>
        <skip>true</skip>
      </configuration>
    </plugin>
    <plugin>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-maven-plugin</artifactId>
      <dependencies>
        <dependency>
          <groupId>org.springframework.boot.experimental</groupId>
          <artifactId>spring-boot-thin-layout</artifactId>
          <version>${wrapper.version}</version>
        </dependency>
      </dependencies>
    </plugin>
  </plugins>
</build>

```

现在，我们已经准备好实现一个掩码帐户号码的函数。让我们回顾以下代码片段：

```java
package com.packtpub.maskaccounts;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.function.context.FunctionScan;
import org.springframework.context.annotation.Bean;
import reactor.core.publisher.Flux;

import java.util.function.Function;

@FunctionScan
@SpringBootApplication
public class MaskAccountsApplication 
{
  public static void main(String[] args) {
    SpringApplication.run(MaskAccountsApplication.class, args);
  }

  @Bean
  public Function<Flux<String>, Flux<String>> maskAccounts() 
  {
 return flux -> 
    {
 return flux
      .map(value -> 
        value.replaceAll("\\w(?=\\w{4})", "*")
      );
 };
 }
}
```

`@FunctionScan`注释用于允许 Spring Function 适配器找到将部署为云提供商中的函数的 bean。

一旦函数编码完成，我们将使用`application.properties`文件进行注册，如下所示：

```java
spring.cloud.function.stream.default-route: maskAccounts
spring.cloud.function.scan.packages: com.packtpub.maskaccounts
```

现在，是时候使用以下步骤在本地执行函数了：

1.  生成 artifact：

```java
$ mvn install
```

1.  执行生成的 artifact：

```java
$ java -jar target/mask-accounts-0.0.1-SNAPSHOT.jar
```

现在，您应该看到类似以下的输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/72edff3a-1d89-4adc-8184-d35a64d8f2b8.png)

控制台输出

让我们尝试使用以下`CURL`命令执行函数：

```java
$ curl -H "Content-Type: text/plain" http://localhost:8080/maskAccounts -d 37567979
%****7979
```

因此，我们将获得一个掩码帐户号码：`****7979`。

在下一节中，我们将回顾如何使用不同的云提供商部署函数。

为了在任何云提供商上创建帐户，例如 AWS 或 Azure，您将需要信用卡或借记卡，即使提供商提供免费套餐也是如此。

# 适配器

Spring Cloud Function 为不同的云提供商提供适配器，以便使用函数部署编码的业务逻辑。目前，有以下云提供商的适配器：

+   AWS Lambda

+   Azure

+   Apache OpenWhisk

在下一节中，我们将介绍如何使用这些适配器。

# AWS Lambda 适配器

该项目旨在允许部署使用 Spring Cloud Function 的应用程序到 AWS Lambda（[`aws.amazon.com/lambda/`](https://aws.amazon.com/lambda/)）。

该适配器是 Spring Cloud Function 应用程序的一层，它使我们能够将我们的函数部署到 AWS 中。

您可以在 GitHub 上找到项目的源代码，链接如下：[`github.com/spring-cloud/spring-cloud-function/tree/master/spring-cloud-function-adapters/spring-cloud-function-adapter-aws`](https://github.com/spring-cloud/spring-cloud-function/tree/master/spring-cloud-function-adapters/spring-cloud-function-adapter-aws)

在使用 AWS Lambda 适配器之前，我们必须将其添加为项目的依赖项。让我们首先在`pom.xml`文件中定义一些属性：

```java
<aws-lambda-events.version>
    2.0.2
</aws-lambda-events.version>
<spring-cloud-stream-servlet.version>
    1.0.0.BUILD-SNAPSHOT
</spring-cloud-stream-servlet.version>
<start-class>
    com.packtpub.maskaccounts.MaskAccountsApplication
</start-class>
```

现在，我们必须为 AWS 添加所需的依赖项：

```java
<dependency>
      <groupId>org.springframework.cloud</groupId>
      <artifactId>spring-cloud-function-adapter-aws</artifactId>
</dependency>
<dependency>
      <groupId>com.amazonaws</groupId>
      <artifactId>aws-lambda-java-events</artifactId>
      <version>${aws-lambda-events.version}</version>
      <scope>provided</scope>
    </dependency>
<dependency>
      <groupId>com.amazonaws</groupId>
      <artifactId>aws-lambda-java-core</artifactId>
      <version>1.1.0</version>
      <scope>provided</scope>
</dependency>
```

现在，将其添加到`dependency`管理部分，如下所示：

```java
<dependency>
  <groupId>org.springframework.cloud</groupId>
  <artifactId>spring-cloud-stream-binder-servlet</artifactId>
  <version>${spring-cloud-stream-servlet.version}</version>
</dependency>
```

最后，将其添加到`plugin`部分，如下所示：

```java
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-shade-plugin</artifactId>
  <configuration>
    <createDependencyReducedPom>false</createDependencyReducedPom>
    <shadedArtifactAttached>true</shadedArtifactAttached>
    <shadedClassifierName>aws</shadedClassifierName>
  </configuration>
</plugin>
```

接下来，我们将编写一个作为 AWS 适配器工作的类。该适配器应该扩展`SpringBootRequestHandler`类，如下所示：

```java
package com.packtpub.maskaccounts;

public class Handler 
    extends SpringBootRequestHandler<Flux<String>, Flux<String>> {

}
```

一旦适配器编写完成，我们将需要修改先前实现的函数作为`MaskAccountsApplication.java`文件的一部分。在这里，我们将更改方法的名称为`function`，函数的输入和输出将是具有 setter 和 getter 的**普通旧 Java 对象（POJOs）**，如下所示：

```java
package com.packtpub.maskaccounts;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.function.context.FunctionScan;
import org.springframework.context.annotation.Bean;

import java.util.function.Function;

@FunctionScan
@SpringBootApplication
public class MaskAccountsApplication {

    public static void main(String[] args) {
        SpringApplication.run(MaskAccountsApplication.class, args);
    }

    @Bean
    public Function<In, Out> function() {
            return value -> new Out(value.mask());
    }
}

class In {

    private String value;

    In() {
    }

    public In(String value) {
        this.value = value;
    }

    public String mask() {
        return value.replaceAll("\\w(?=\\w{4})", "*");
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}

class Out {

    private String value;

    Out() {
    }

    public Out(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
```

为了包装编码的函数，我们必须创建一个 JAR 文件，使用以下 Maven 目标：

```java
$ mvn clean package
```

一旦 JAR 文件创建完成，我们可以使用 AWS 提供的**命令行界面（CLI）**（[`aws.amazon.com/cli/`](https://aws.amazon.com/cli/)）上传生成的 JAR 文件，运行以下命令：

```java
$ aws lambda create-function --function-name maskAccounts --role arn:aws:iam::[USERID]:role/service-role/[ROLE] --zip-file fileb://target/mask-accounts-aws-0.0.1-SNAPSHOT-aws.jar --handler org.springframework.cloud.function.adapter.aws.SpringBootStreamHandler --description "Spring Cloud Function Adapter for packt Mastering Architecting Spring 5" --runtime java8 --region us-east-1 --timeout 30 --memory-size 1024 --publish
```

`[USERID]`引用基于您的 AWS 账户和`[ROLE]`引用。如果您对如何创建 AWS 账户有任何疑问，请访问[`aws.amazon.com/premiumsupport/knowledge-center/create-and-activate-aws-account/`](https://aws.amazon.com/premiumsupport/knowledge-center/create-and-activate-aws-account/)。 

有关 AWS lambda `create-function`的更多信息，请参阅[`docs.aws.amazon.com/cli/latest/reference/lambda/create-function.html`](https://docs.aws.amazon.com/cli/latest/reference/lambda/create-function.html)。

如果您没有设置 AWS 账户的凭据，您将收到一个错误消息，指出*无法找到凭据。*您可以通过运行`aws configure`命令来配置凭据。

不要忘记，您需要创建一个具有权限运行 AWS Lambda 的角色的 AWS 用户。

一旦函数成功部署，您将在控制台中看到类似以下的输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/57d6acad-a6b3-4bc5-b37f-4a64f0b6bfb8.png)

输出处理

最近部署的函数现在将在 AWS Lambda 控制台中列出，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/497b329e-d515-4d71-bfa6-988174f78986.png)

AWS Lambda 控制台

如果您在 Web 控制台中看不到最近部署的函数，则必须检查创建函数的位置。在本例中，我们使用`us-east-1`地区，这意味着函数部署在北弗吉尼亚。您可以在 AWS Lambda 控制台顶部的名称旁边检查此值。

最后，我们将在 AWS Lambda 控制台中测试我们的结果。在测试部分，创建一些输入以进行蒙版处理，如下所示：

```java
{"value": "37567979"}
```

预期结果如下：

```java
{"value": "****7979"}
```

在 AWS 控制台中，您将看到以下结果：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/94c8f09d-15a3-4f65-a962-5996869afc54.png)

maskAccount 函数的 AWS 控制台测试结果

# Azure 适配器

在本节中，我们将回顾如何将先前编码的函数部署到 Azure，这是 Microsoft 支持的云提供商。Azure 通过使用 Microsoft Azure Functions（[`azure.microsoft.com/en-us/services/functions/`](https://azure.microsoft.com/en-us/services/functions/)）支持函数。

Azure 适配器是在 Spring Cloud Function 项目上编写的一层。您可以在 GitHub 上找到该项目的源代码（[`github.com/spring-cloud/spring-cloud-function/tree/master/spring-cloud-function-adapters/spring-cloud-function-adapter-azure`](https://github.com/spring-cloud/spring-cloud-function/tree/master/spring-cloud-function-adapters/spring-cloud-function-adapter-azure)）。

让我们首先将以下属性添加为`pom.xml`文件的一部分，在属性部分：

```java
<functionAppName>function-mask-account-azure</functionAppName><functionAppRegion>westus</functionAppRegion>
<start-class>
    com.packtpub.maskaccounts.MaskAccountsApplication
</start-class>
```

现在，让我们添加此适配器所需的依赖项，如下所示：

```java
<dependency>
  <groupId>org.springframework.cloud</groupId>
  <artifactId>spring-cloud-function-adapter-azure</artifactId>
</dependency>
<dependency>
  <groupId>org.springframework.cloud</groupId>
  <artifactId>spring-cloud-starter-function-web</artifactId>
  <scope>provided</scope>
</dependency>
<dependency>
  <groupId>com.microsoft.azure</groupId>
  <artifactId>azure-functions-java-core</artifactId>
  <version>1.0.0-beta-2</version>
  <scope>provided</scope>
</dependency>
```

然后，我们将添加一些插件以允许适配器工作，如下所示：

```java
<plugin>
  <groupId>com.microsoft.azure</groupId>
  <artifactId>azure-functions-maven-plugin</artifactId>
  <configuration>
    <resourceGroup>java-functions-group</resourceGroup>
    <appName>${functionAppName}</appName>
    <region>${functionAppRegion}</region>
    <appSettings>
      <property>
        <name>FUNCTIONS_EXTENSION_VERSION</name>
        <value>beta</value>
      </property>
    </appSettings>
  </configuration>
</plugin>
<plugin>
  <artifactId>maven-resources-plugin</artifactId>
  <executions>
    <execution>
      <id>copy-resources</id>
      <phase>package</phase>
      <goals>
        <goal>copy-resources</goal>
      </goals>
      <configuration>
        <overwrite>true</overwrite>
        <outputDirectory>${project.build.directory}/azure-
        functions/${functionAppName}
        </outputDirectory>
        <resources>
          <resource>
            <directory>${project.basedir}/src/main/azure</directory>
            <includes>
              <include>**</include>
            </includes>
          </resource>
        </resources>
      </configuration>
    </execution>
  </executions>
</plugin>
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-shade-plugin</artifactId>
  <configuration>
    <createDependencyReducedPom>false</createDependencyReducedPom>
    <shadedArtifactAttached>true</shadedArtifactAttached>
    <shadedClassifierName>azure</shadedClassifierName>
    <outputDirectory>${project.build.directory}/azure-
    functions/${functionAppName}</outputDirectory>
  </configuration>
</plugin>
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-assembly-plugin</artifactId>
  <executions>
    <execution>
      <id>azure</id>
      <phase>package</phase>
      <goals>
        <goal>single</goal>
      </goals>
      <inherited>false</inherited>
      <configuration>
        <attach>false</attach>
        <descriptor>${basedir}/src/assembly/azure.xml</descriptor>
        <outputDirectory>${project.build.directory}/azure- 
        functions</outputDirectory>
        <appendAssemblyId>false</appendAssemblyId>
        <finalName>${functionAppName}</finalName>
      </configuration>
    </execution>
  </executions>
</plugin>
```

最后，我们将创建一个适配器，该适配器应该扩展自`AzureSpringBootRequestHandler`类。扩展类将为我们提供输入和输出类型，使 Azure 函数能够检查类并执行任何 JSON 转换以消耗/生成数据：

```java
public class Handler 
    extends AzureSpringBootRequestHandler<Flux<String>,Flux<String>> {

    public Flux<String> execute
                    (Flux<String>in, ExecutionContext context) {
        return handleRequest(in, context);
    }
}
```

现在，我们将修改`MaskAccountsApplication.java`文件中的编码函数；我们将更改函数的输入和输出，以便使用具有 setter 和 getter 的普通旧 Java 对象：

```java
package com.packtpub.maskaccounts;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.function.context.FunctionScan;
import org.springframework.context.annotation.Bean;

import java.util.function.Function;

@FunctionScan
@SpringBootApplication
public class MaskAccountsApplication {

    public static void main(String[] args) {
        SpringApplication.run(MaskAccountsApplication.class, args);
    }

    @Bean
    public Function<In, Out> maskAccount() {
            return value -> new Out(value.mask());
    }
}

class In {

    private String value;

    In() {
    }

    public In(String value) {
        this.value = value;
    }

    public String mask() {
        return value.replaceAll("\\w(?=\\w{4})", "*");
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}

class Out {

    private String value;

    Out() {
    }

    public Out(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
```

然后我们必须为 Azure 工具创建一个 JSON 配置，因此我们将在`src/main`文件夹后面的新文件夹中创建一个名为`function.json`的 JSON 文件，文件名为函数（`maskAccount`）。此文件将用于让 Azure 了解我们要部署的函数，通过指定将用作入口点的 Java 类。`src`文件夹应如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/7d28f945-e2ae-4bfe-be18-6615a4c454bc.png)

`function.json`文件的内容将如下所示：

```java
{
   "scriptFile": "../mask-accounts-azure-1.0.0.BUILD-SNAPSHOT-azure.jar",
   "entryPoint": "com.packtpub.maskaccounts.Handler.execute",
"bindings": [
 {
 "type": "httpTrigger",
 "name": "in",
 "direction": "in",
 "authLevel": "anonymous",
 "methods": [
 "get",
 "post"
 ]
 },
 {
 "type": "http",
 "name": "$return",
 "direction": "out"
 }
 ],
 "disabled": false
}
```

可以使用 Maven 插件为非 Spring 函数创建 JSON 文件，但是该工具与当前版本的适配器不兼容。

在生成将要部署的构件之前，我们必须创建一个`assembly`文件，这是我们正在使用的 Azure Maven 插件所需的。

`assembly`文件应放在`src/assembly`目录中；文件将被命名为`azure.xml`，并包含以下内容：

```java
<assembly
   xmlns="http://maven.apache.org/plugins/maven-assembly-plugin/assembly/1.1.3"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="http://maven.apache.org/plugins/maven-assembly-plugin/assembly/1.1.3 http://maven.apache.org/xsd/assembly-1.1.3.xsd">
   <id>azure</id>
   <formats>
      <format>zip</format>
   </formats>
   <baseDirectory></baseDirectory>
   <fileSets>
      <fileSet>
         <directory>${project.build.directory}/azure-functions/${functionAppName}</directory>
         <outputDirectory></outputDirectory>
         <includes>
            <include>*-azure.jar</include>
            <include>**/*.json</include>
         </includes>
      </fileSet>
   </fileSets>
</assembly>
```

现在，可以使用以下 Maven 目标创建 JAR 文件：

```java
$ mvn clean package
```

该函数可以在本地部署进行测试，通过使用以下命令将 JAR 文件作为常规 Java 应用程序运行：

```java
$ java -jar target/mask-accounts-azure-0.0.1-SNAPSHOT.jar
```

然后您将看到应用程序正在运行，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/fe28fac1-dd85-46d3-9921-855ee63b06f2.png)

本地运行的 Spring 应用程序的输出

让我们尝试使用以下`curl`命令来测试该功能：

```java
$ curl -H "Content-Type: text/plain" localhost:8080/maskAccount -d '{"value": "37567979"}'
```

您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/1bec9055-4f45-4f7b-aaf2-a005b7643f36.png)

或者，我们可以使用 Azure Functions Core Tools 将我们的函数部署到 Azure。

要做到这一点，首先，您必须使用提供在[`github.com/azure/azure-functions-core-tools#installing`](https://github.com/azure/azure-functions-core-tools#installing)上的信息安装所有所需的工具。安装了所需的工具后，您可以使用终端中的以下命令登录到 Azure：

```java
$ az login
```

在输入了您的凭据之后，您将在控制台上看到以下输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/683acc84-c48f-4b65-a0c9-4ea33ab015eb.png)

将编码的函数部署到 Azure 非常简单；您只需执行以下 Maven 命令：

```java
$ mvn azure-functions:deploy
```

现在，您可以使用以下`curl`命令尝试部署的函数：

```java
$ curl https://<azure-function-url-from-the-log>/api/maskAccount -d '{"value": "37567979"}'
```

`<azure-function-url-from-the-log>`是在运行`mvn azure-functions:deploy`命令后获得的 URL。例如，在以下屏幕截图中，您可以看到`https://function-mask-account-azure.azurewebsites.net/`URL：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/c3e9e981-a55c-4bd2-9b70-7461ebc86e42.png)

执行`curl`命令后，收到的输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/6028e45a-7c53-484f-abf8-a551e65a7c10.png)

输出处理

我们还可以在 Azure Functions 控制台上测试相同的函数，就像我们在 AWS Lambda 上做的那样。

# 总结

在本章中，我们讨论了无服务器架构背后的概念。您了解了如何使用 Spring Cloud Functions 实现函数，并且我们回顾了可以用于在不同云提供商（如 AWS Lambda 和 Microsoft Azure Functions）部署函数的适配器。

在下一章中，我们将描述容器是什么，以及您如何使用它们来容器化应用程序。


# 第十章：将应用程序容器化

容器正在成为软件开发的关键因素之一，改变了开发人员编写和部署 IT 系统的方式。主要用于解决与设置环境相关的问题。

当你需要管理多个容器和多实例环境时，使用容器可能会让人感到不知所措。然而，一些非常酷的工具已经发布，旨在完成这些容器编排任务。在本章中，我们将一起看看这些工具，以及以下主题：

+   **容器**：

+   基本概念

+   基本命令

+   构建你自己的镜像

+   **容器化应用程序**：Docker Gradle 插件

+   **注册表**：发布镜像

+   **配置多容器环境**：Docker Compose

+   **使用 Kubernetes 进行容器编排**：

+   Pods

+   标签

+   复制控制器

+   服务

# 容器

容器提供了一种轻量级的虚拟化方法，它提供了应用程序运行所需的最低限度。在过去，虚拟机曾经是设置环境和运行应用程序的主要选择。然而，它们需要完整的操作系统才能工作。另一方面，容器重用主机操作系统来运行和配置所需的环境。让我们通过查看下图来更多地了解这个概念：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/efbb30f8-49cd-4d73-b325-67db986da2ca.png)

虚拟机和容器

在上图中，我们可以看到左侧是**虚拟机**（**VMs**），右侧是**容器**。让我们从学习虚拟机是如何工作开始。

虚拟机需要使用分配给虚拟机的硬件的自己的操作系统，这由 hypervisor 支持。上图显示了三个虚拟机，这意味着我们需要安装三个操作系统，每个虚拟机一个。当你在虚拟机中运行应用程序时，你必须考虑应用程序和操作系统将消耗的资源。

另一方面，容器使用主机操作系统提供的内核，还使用虚拟内存支持来隔离所有容器的基本服务。在这种情况下，不需要为每个容器安装整个操作系统；这是一种在内存和存储使用方面非常有效的方法。当你使用容器运行应用程序时，你只需要考虑应用程序消耗的资源。

容器体积小，可以用几十兆来衡量，只需要几秒钟就可以被配置。相比之下，虚拟机的体积以几十 GB 来衡量，但它们甚至需要几分钟才能开始工作。你还需要考虑操作系统许可证费用——当你使用虚拟机时，你必须为每个安装的操作系统付费。使用容器时，你只需要一个操作系统，所有容器都将使用它来运行。

市场上目前有不同的容器可用，但 Docker 是目前最流行的实现。因此，我们将选择这个选项来解释本章中的所有概念。

# 基本概念

在本节中，我们将回顾一些基本概念和命令，这些命令你在日常使用中会经常用到。这应该有助于你理解本章的其余内容。

# 容器和镜像

谈到 Docker 时，人们经常使用*容器*和*镜像*这两个术语。这两个术语之间的区别很简单：容器是镜像的一个实例，而镜像是一个不可变的文件，本质上是容器的快照。从**面向对象编程**（**OOP**）的角度来看，我们可以说镜像就像类，容器是这些类的实例。例如，假设你有一个由 CentOS 和 Java 8 组成的 Docker 镜像。使用这个镜像，你可以创建一个容器来运行一个 Spring Boot 应用程序，另一个容器来运行一个 JEE 应用程序，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/1c98cbae-61e1-45f2-9857-9b537399823a.png)

Docker 镜像和容器

# 基本命令

Docker 有一大堆命令来执行使用容器和镜像的不同操作。然而，并不需要熟悉所有这些命令。我们现在将回顾一些你需要了解的最常用的命令。

# 运行容器

我们之前提到过，容器是镜像的实例。当你想要运行一个 Docker 容器时，你可以使用以下命令：

```java
docker run IMAGE_NAME
```

互联网上有大量的 Docker 镜像可用。在创建自定义镜像之前，你应该首先查看 Docker Hub 上可用的镜像列表（[`hub.docker.com/`](https://hub.docker.com/)）。

Docker Hub 是一个基于云的注册服务，允许你链接到代码仓库，构建你的镜像并对其进行测试。它还存储手动推送的镜像，并链接到 Docker Cloud，以便你可以将镜像部署到你的主机上。Docker Hub 为容器和镜像的发现、分发和变更管理；用户和团队协作；以及整个开发流程中的工作流自动化提供了一个集中的资源。

让我们假设你想要使用`nginx`运行一个容器。在这种情况下，你只需要在终端中执行以下命令：

```java
docker run nginx
```

运行这个命令后，Docker 将尝试在本地找到镜像。如果它找不到，它将在所有可用的注册表中查找镜像（我们稍后会谈论注册表）。在我们的情况下，这是 Docker Hub。你在终端中应该看到的第一件事是类似于以下内容的输出：

```java
⋊> ~ docker run nginx
 Unable to find image 'nginx:latest' locally
 latest: Pulling from library/nginx
 f2aa67a397c4: Downloading [==================================> ] 15.74MB/22.5MB
 3c091c23e29d: Downloading [=======> ] 3.206MB/22.11MB
 4a99993b8636: Download complete
```

执行这个操作后，你将得到一个类似于`d38bbaffa51cdd360761d0f919f924be3568fd96d7c9a80e7122db637cb8f374`的字符串，它代表了镜像 ID。

一些用于运行容器的有用标志如下：

+   `-d`标志将镜像作为守护进程运行

+   `-p`标志将镜像端口连接到主机

例如，以下命令可以让你将`nginx`作为守护进程运行，并将容器的端口`80`映射到主机的端口`32888`：

```java
docker run -p 32888:80 -d nginx
```

现在你将再次控制终端，并且你可以在`http://localhost:32888/`URL 中看到`nginx`的主页，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/17afc51c-8e5b-4a5d-9f68-ef64d827257a.png)

Nginx 主页

容器只包含软件和服务，这些软件和服务对它们的工作是绝对必要的，这就是为什么你会发现它们甚至不包括 SSH 入口。如果你想进入一个容器，你可以使用`-it`标志，在容器内执行命令如下：

```java
⋊> ~ docker run -it nginx /bin/bash
# Now you're inside the container here
root@0c546aef5ad9:/#
```

# 使用容器

如果你有兴趣检查主机上运行的所有容器，你可以使用以下`ps`命令：

```java
docker ps
```

上面的命令将列出主机上运行的所有容器。如果你还想检查那些没有运行的镜像，你可以使用`-a`标志。执行上面的命令后，你将在终端中得到一个类似于以下截图的输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/2483fdc5-fbe5-4f4f-9d8a-578119d6b16f.png)

Docker ps 命令输出

前面截图的第一列解释了以下列表中的信息。这个输出中最有用的部分是 CONTAINER ID，它可以用来执行以下操作：

+   重新启动容器：

```java
docker restart <CONTAINER ID> 
```

+   停止容器：

```java
docker stop <CONTAINER ID> 
```

+   启动容器：

```java
docker start <CONTAINER ID> 
```

+   删除容器：

```java
docker rm <CONTAINER ID>
```

这些是最常用的命令，它们提供了你在使用 Docker 容器时所需要的一切。

# 使用镜像

Docker 还有一些命令，允许你的系统与镜像一起工作。最常用的命令如下：

+   列出主机上所有可用的镜像：

```java
⋊> ~ docker images
REPOSITORY TAG IMAGE ID CREATED SIZE
nginx latest ae513a47849c 4 weeks ago 109MB
```

+   删除镜像：

```java
⋊> ~ docker rmi nginx
Untagged: nginx:latest
Untagged: nginx@sha256:0fb320e2a1b1620b4905facb3447e3d84ad36da0b2c8aa8fe3a5a81d1187b884
Deleted: sha256:ae513a47849c895a155ddfb868d6ba247f60240ec8495482eca74c4a2c13a881
Deleted: sha256:160a8bd939a9421818f499ba4fbfaca3dd5c86ad7a6b97b6889149fd39bd91dd
Deleted: sha256:f246685cc80c2faa655ba1ec9f0a35d44e52b6f83863dc16f46c5bca149bfefc
Deleted: sha256:d626a8ad97a1f9c1f2c4db3814751ada64f60aed927764a3f994fcd88363b659
```

+   下载镜像：

```java
⋊> ~ docker pull <IMAGE NAME>
```

# 构建你自己的镜像

在互联网上，我们可以找到许多准备好使用的 Docker 镜像。这些镜像是使用一个名为 Dockerfile 的配置文件创建的，它包含了为容器进行配置的所有指令。

作为这个文件的一部分，你会发现以下常用命令：

+   `FROM`

+   `MAINTAINER`

+   `RUN`

+   `ENV`

+   `EXPOSE`

+   `CMD`

让我们逐个审查所有这些命令，以了解它们的工作原理。

# FROM 命令

`FROM`命令用于指定 Dockerfile 将用于构建新镜像的基础 Docker 镜像。例如，如果您想基于 Debian 创建自定义镜像，您应该在文件中添加以下行：

```java
FROM debian:stretch-slim 
```

# MAINTAINER 命令

`MAINTAINER`命令完全用于文档目的，其中包含了 Dockerfile 的作者姓名以及他们的电子邮件，如下所示：

```java
MAINTAINER  Your Name <your@email.com>
```

# RUN 命令

Dockerfile 通常有多个`RUN`命令作为其一部分。这些命令旨在作为系统 bash 命令的一部分执行，并主要用于安装软件包。例如，以下`RUN`命令用于安装 Java 8：

```java
RUN \ 
 echo oracle-java8-installer shared/accepted-oracle-license-v1-1 
 select true | debconf-set-selections && \ 
 add-apt-repository -y ppa:webupd8team/java && \ 
 apt-get update && \ 
 apt-get install -y oracle-java8-installer && \ 
 rm -rf /var/lib/apt/lists/* && \ 
 rm -rf /var/cache/oracle-jdk8-installer
```

上述命令取自名为`oracle-java8`的镜像提供的 Dockerfile（[`github.com/dockerfile/java/blob/master/oracle-java8/Dockerfile`](https://github.com/dockerfile/java/blob/master/oracle-java8/Dockerfile)）。

这个命令很容易阅读，每一行描述了安装过程是如何进行的。最后两行从容器中删除了一些不再需要的目录。

所有安装都是作为单行完成的，因为每个`RUN`命令生成一个新的层。例如，在`RUN`命令中，我们可以看到一次执行了六条指令。如果我们逐条运行这些指令，最终会得到六个镜像，每个镜像都包含了基础镜像以及执行的`RUN`命令。我们不会在本书中详细讨论层，但如果您感到好奇，我强烈鼓励您阅读有关它们的内容：[`docs.docker.com/storage/storagedriver/#images-and-layers`](https://docs.docker.com/storage/storagedriver/#images-and-layers)。

# ENV 命令

`ENV`命令用于在系统中创建环境变量。以下`ENV`命令作为前面提到的 Dockerfile 的一部分，用于定义`JAVA_HOME`变量：

```java
ENV JAVA_HOME /usr/lib/jvm/java-8-oracle
```

# EXPOSE 命令

`EXPOSE`命令定义了我们将从容器中公开的端口。例如，如果您想公开端口`80`和`32777`，您需要在 Dockerfile 中添加以下行：

```java
EXPOSE 80 32777
```

# CMD 命令

`CMD`命令用于指定容器启动后应执行的命令。例如，如果要使用标准的`java -jar`命令运行 Java 应用程序，需要在文件中添加以下行：

```java
CMD java - jar your-application.jar
```

完成 Dockerfile 后，应该运行`build`命令在本地创建镜像，如下所示：

```java
docker build -t <docker-image-name>
```

# 容器化应用程序

一个 docker 化的应用程序是一个基本的可部署单元，可以作为整个应用程序生态系统的一部分进行集成。当您将应用程序 docker 化时，您将不得不创建自己的 Dockerfile，并包含所有必需的指令来使您的应用程序工作。

在上一节中，我们提到，可以使用`FROM`命令使用现有的基础镜像创建一个容器。您还可以复制基础镜像的 Dockerfile 内容，但这种做法是不鼓励的，因为在创建镜像时已经编写了代码，复制代码是没有意义的。

强烈建议您在 DockerHub 中找到官方镜像。由于 Dockerfile 可用，您应该始终阅读它以避免安全问题，并充分了解镜像的工作原理。

在将应用程序 docker 化之前，重要的是要使系统使用环境变量而不是配置文件。这样，您可以创建可以被其他应用程序重用的镜像。使用 Spring Framework 的最大优势之一是能够使用不同的方法来配置您的应用程序。这是我们在第八章中所做的，*微服务*，当时我们使用配置服务器来集中所有应用程序配置。Spring 使我们能够使用本地配置文件作为应用程序的一部分，并且我们可以稍后使用环境变量覆盖这些配置值。

现在让我们看看如何将 Spring Boot 应用程序 docker 化。

在第一步中，我们将创建 Dockerfile 来运行我们的应用程序。该文件的内容如下所示：

```java
FROM java:8 
WORKDIR / 
ARG JAR_FILE 
COPY ${JAR_FILE} app.jar 
EXPOSE 8080 
ENTRYPOINT ["java","-jar","app.jar"]
```

让我们简要回顾一下 Dockerfile 中列出的命令：

| **命令** | **描述** |
| --- | --- |
| `FROM java:8` | 使用基本的`java:8`镜像 |
| `WORKDIR` | 镜像文件系统中的默认目录 |
| `ARG` | 我们将使用一个参数来指定 JAR 文件 |
| `COPY` | 提供的文件将被复制到容器中作为`app.jar` |
| `EXPOSE` | 容器的端口 8080 被暴露 |
| `ENTRYPOINT` | 在容器内运行 Java 应用程序 |

这个 Dockerfile 应该位于项目的根目录。以下截图显示了项目的布局：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/141a309e-e383-4ccb-9b89-c71f6836b836.png)

项目布局

应用程序 JAR 位于`PROJECT/build/libs`目录下。通过使用 Gradle wrapper 运行`bootRepackage`任务生成此构件，如下所示：

```java
./gradlew clean bootRepackage
```

一旦构件被创建，就该是时候通过运行以下命令来创建 Docker 镜像了：

```java
$ docker build -t spring-boot:1.0 . --build-arg JAR_FILE=build/libs/banking-app-1.0.jar
```

一旦命令完成，镜像应该存在于本地。您可以通过运行`docker images`命令来检查：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/d7b2c033-fc34-4564-a8ae-af112d207844.png)

Docker 镜像控制台输出

请注意，`java`镜像也存在。这是在`spring-boot`镜像构建过程中下载的。然后，我们可以通过运行以下命令创建一个使用最近创建的镜像的容器：

```java
$ docker run -p 8081:8080 -d --name banking-app spring-boot:1.0
```

您现在可以访问部署在容器中的应用程序，网址为`http://localhost:8081/index`。以下截图显示了这个应用程序：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/4a077f67-7dce-4056-be8e-67ba79b15389.png)

应用程序部署在容器中

镜像的构建过程可以并且应该使用您喜欢的构建工具进行自动化。Gradle 和 Maven 都有插件可以作为应用程序的一部分集成。让我们看看如何为这个任务集成 Gradle 插件。

# Docker Gradle 插件

即使生成 Docker 镜像时，使用 Docker 命令并不难或复杂；尽可能自动化所有这些步骤总是一个好主意。Docker Gradle 插件非常有用，可以完成这个任务。让我们学习如何将其作为应用程序的一部分。

首先，我们需要在`buildscript`部分内包含包含插件的仓库和插件本身作为依赖项，如下所示：

```java
buildscript 
{
  ...
  repositories 
  {
    ...
    maven 
    {
      url "https://plugins.gradle.org/m2/"
    }
  }
  dependencies 
  {
    ...
    classpath('gradle.plugin.com.palantir.gradle.docker:gradledocker:
    0.13.0')
  }
}
```

稍后，插件应该以与任何其他插件相同的方式应用到项目中——使用其 ID。这在以下代码中显示：

```java
apply plugin: 'com.palantir.docker'
```

可以使用官方文档中描述的参数来自定义镜像构建过程，网址为[`github.com/palantir/gradle-docker`](https://github.com/palantir/gradle-docker)。为了简化，我们只会在`docker`块中指定所需的镜像名称，如下所示：

```java
docker 
{
  name "enriquezrene/spring-boot-${jar.baseName}:${version}"
  files jar.archivePath
  buildArgs(['JAR_FILE': "${jar.archiveName}"])
}
```

正如你可能已经注意到的那样，我们现在正在使用`build.gradle`文件中可用的变量，比如生成的 JAR 名称及其版本。

现在插件已经完全集成到项目中，您可以通过运行以下 Gradle 任务来构建镜像：

```java
$ ./gradlew build docker
```

您还可以检查最近创建的镜像，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/123cf284-aece-4007-864b-8f9c63cd0fbc.png)

docker 镜像控制台输出

将所有这些步骤自动化是个好主意，因为这提供了可以在将来改进的免费文档。

# 注册表

正如我们所见，Docker 帮助我们复制用于部署应用程序的设置，但它也帮助我们分发应用程序以在不同环境中使用。可以使用注册表执行此任务。

注册表是负责托管和分发 Docker 镜像的服务。Docker 使用的默认注册表是 Docker Hub。市场上还有其他可用作 Docker 注册表的选项，包括以下内容：

+   Quay

+   Google 容器注册表

+   AWS 容器注册表

Docker Hub 非常受欢迎，因为它以您甚至都没有注意到的方式工作。例如，如果您正在创建一个容器，而本地存储库中不存在该镜像，它将自动从 Docker Hub 下载该镜像。所有现有的镜像都是由其他人创建并发布在这些注册表中。同样，我们可以发布我们自己的镜像，以便通过私有存储库使其对组织内的其他人可用。或者，您也可以将它们发布在公共存储库中。您还可以使用诸如 Nexus、JFrog 等解决方案在自己的硬件上自行托管 Docker 注册表。

Docker Hub 有一个免费计划，允许您创建无限数量的公共存储库和一个私有存储库。如果需要，它还提供另一个计划，可以让您拥有更多的私有存储库。我们使用 Docker Hub 来处理 Docker，就像我们使用 GitHub 来处理 Git 存储库一样。

# 发布镜像

要在 Docker Hub 中发布 Docker 镜像，您需要创建一个帐户，然后使用终端和`docker login`命令登录 Docker Hub。输入凭据后，您应该在终端中看到类似以下代码的输出：

```java
$ docker login 
Login with your Docker ID to push and pull images from Docker Hub. If you don't have a Docker ID, head over to https://hub.docker.com to create one.
Username: enriquezrene
Password:
Login Succeeded
```

现在您已登录，可以使用`docker push`命令将镜像推送到注册表，如下代码所示：

```java
$ docker push <docker-hub-username/docker-image:tag-version>
```

当未指定标签版本时，默认使用`latest`值。在我们的情况下，应该对`build.gradle`文件进行一些小的更改，以附加 Docker Hub 所需的`docker-hub-username`前缀，如下代码所示：

```java
docker 
{
  name "enriquezrene/spring-boot-${jar.baseName}:${version}"
  files jar.archivePath
  buildArgs(['JAR_FILE': "${jar.archiveName}"])
}
```

再次生成镜像后，您应该使用`docker login`命令从终端登录 Docker Hub，稍后可以推送镜像，如下代码所示：

```java
# Login into Docker Hub
$ docker login
Login with your Docker ID to push and pull images from Docker Hub. If you don't have a Docker ID, head over to https://hub.docker.com to create one.
Username: <username>
Password: <password>
Login Succeeded
# Push the image
$ docker push enriquezrene/spring-boot-banking-app:1.0
```

镜像推送后，您可以通过输入以下命令在任何其他计算机上拉取并运行容器：

```java
$ docker run enriquezrene/spring-boot:1.0
```

这将从 Docker Hub 下载镜像并在本地运行应用程序。同样，我们可以重复此过程在任何其他计算机上部署应用程序。

以下屏幕截图显示了在 Docker Hub 上推送的镜像的外观：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/3ba70773-de9d-4ab6-bdd4-aa42efdec445.png)

Docker 镜像推送到 Docker Hub

应该使用持续集成服务器自动化`push`命令。一个好主意是在分支合并到`master`标签或在版本控制系统中创建新标签时执行此命令。您应该始终避免使用默认的`latest`标签值。相反，您应该使用自动过程自己创建版本号，就像我们在上一节中使用 Gradle 插件所做的那样。

集成插件还具有使用`dockerPush` Gradle 任务推送镜像的功能。

# 为多容器环境进行配置

当我们使用分布式应用程序时，我们面临的最大问题之一是难以提供应用程序工作所需的所有依赖关系。例如，假设您正在开发一个将信息存储在 MySQL 数据库中并使用 RabbitMQ 发送消息的应用程序，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/e15db607-8afa-403e-b7c1-656a45b83ef9.png)

具有 RabbitMQ 和 MySQL 依赖项的应用程序

在这种情况下，如果团队中的所有开发人员都希望在本地使整个环境工作，他们都需要在他们的计算机上安装 MySQL 和 RabbitMQ。

安装一些工具并不难，但一旦您的应用程序开始有越来越多的依赖关系，这项任务就变成了一场噩梦。这正是 Docker Compose 要解决的问题。

# Docker Compose

Docker Compose 是一个工具，它允许您定义和执行多容器 Docker 环境。这意味着您应用程序中的每个依赖都将被容器化并由此工具管理。Docker Compose 诞生于一个名为**FIG**的独立开源项目，后来作为 Docker 家族的一部分进行了整合。目前，最新的 Compose 版本是 2.4。

在上面的例子中，您需要运行一些额外的服务：MySQL 和 RabbitMQ。

使用 Docker Compose 时，您可以在`docker-compose.yaml`文件中构建应用程序服务，然后使用此配置文件启动和停止所有这些服务，而不是逐个安装上述服务。这个配置文件使用了易于理解的 YAML 语法。

获取 RabbitMQ 和 MySQL 服务在本地运行所需的配置文件内容如下：

```java
mysql:
 image: mysql
 ports:
 - "3306:3306"
 environment:
 - MYSQL_ROOT_PASSWORD=my-password

rabbitmq:
 image: rabbitmq:management
 ports:
 - "5672:5672"
 - "15672:15672"
```

同样，我们可以在配置文件中添加尽可能多的服务。`docker-compose.yaml`文件的用例是不言自明的，值得一提的是，该文件具有特定的配置，这些配置在 Dockerfile 中没有定义，比如端口映射。运行这个文件并不难：您只需要使用 Docker Compose 中的`up`命令，就像下面的代码所示：

```java
$ docker-compose up
```

作为一个良好的实践，建议您在项目中提供一个`docker-compose.yaml`文件。这样，团队成员可以轻松地进行配置。

# 连接容器

当您运行分布式应用程序时，您必须连接不同的服务以使它们一起工作。为了满足这个要求，您需要知道服务的主机名或 IP 地址，以及其他配置变量。服务的可用顺序也很重要。让我们考虑以下简单的应用程序：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/b81c4411-573a-4cfa-9dc1-53d66ddb9ede.png)

服务依赖关系

上面的图表示了最简单的应用程序；它只依赖于一个数据库服务器。在这个例子中，应用程序需要一些数据库配置参数，比如 IP 地址、端口等。当然，在启动应用程序之前，数据库服务应该是可用的；否则，应用程序将无法启动。

为了解决这个简单的需求，您可以在您的`docker-compose.yaml`文件中使用以下两个选项：

+   `links`

+   `depends_on`

# links

`links`选项可以用来通过它们的名称连接各种容器。这样，您根本不需要知道它们的主机名或 IP 地址。

# depends_on

使用`depends_on`选项，您可以指定服务启动的顺序。如果需要，一个服务可以依赖于多个服务。

让我们来看一下以下使用了这两个选项的`docker-compose.yaml`文件：

```java
version: '3.1'
services:
    database:
        image: mysql:5
        ports:
            - "3306:3306"
        volumes:
          # Use this option to persist the MySQL data in a shared 
          volume.
            - db-data:/host/absolute/path/.mysql
        environment:
            - MYSQL_ROOT_PASSWORD=example
            - MYSQL_DATABASE=demo

    application:
        image: enriquezrene/docker-compose-banking-app:1.0
        ports:
            - "8081:8080"
 depends_on:
            - database
        environment:
            - spring.datasource.url=jdbc:mysql://database:3306/demo
            - spring.datasource.password=example
 links:
            - database

volumes:
 db-data:
```

上述代码中的`depends_on`和`links`选项已经用粗体标出。从这可以很容易地理解，应用程序在数据库服务器启动后连接到数据库。

`enriquezrene/docker-compose-banking-app: 1.0` 镜像中有一个运行在其中的 Spring Boot 应用程序。作为这个应用程序的一部分，我们有一个名为`application.properties`的配置文件，内容如下：

```java
spring.thymeleaf.cache=false
spring.jpa.hibernate.ddl-auto=create-drop
spring.datasource.username=root
spring.datasource.url=jdbc:mysql://localhost:3306/demo
spring.datasource.password=root
```

您可能会注意到密码和数据源 URL 参数已经提供。但是，Spring 提供了使用环境变量覆盖这些配置的能力，就像我们在`docker-compose.yaml`文件中所做的那样。

Docker Compose 易于使用，并且具有与 Docker 相同的选项。让我们快速回顾一些命令，以便开始使用它。

这个命令允许我们启动配置文件中列出的所有容器：

```java
docker-compose up
```

`up`命令还允许使用`-d`标志将所有进程作为守护进程运行。如果您愿意，您可以从`docker-compose.yaml`文件中只启动一个服务，指定服务名称。假设我们只想运行数据库服务器。允许您执行此操作的命令如下：

```java
$ docker-compose up database
```

这样，您可以为 Docker Compose 中可用的其他命令指定服务名称。

一旦服务启动，您可以使用以下命令列出所有正在运行的容器：

```java
$ docker-compose ps
```

如果您想停止所有已启动的命令，您需要使用以下命令：

```java
$ docker-compose stop
```

Docker Compose 由一大堆命令组成。要获取完整的参考资料，您可以访问[`docs.docker.com/compose/reference/`](https://docs.docker.com/compose/reference/)。

# 使用 Kubernetes 进行容器编排

Kubernetes 为使用 Docker 容器的环境引入了一套新的概念。我们可以说 Kubernetes 在生产中做的是 Docker Compose 在开发中做的，但实际上远不止于此。Kubernetes 是一个开源系统，最初是为 Google Cloud Engine 创建的，但您可以在 AWS 或任何其他云提供商中使用它。它旨在远程管理不同环境中的 Docker 集群。

Kubernetes 引入了以下主要概念：

+   Pods

+   复制控制器

+   服务

+   标签

# Pod

pod 是 Kubernetes 引入的一个新概念。一个 pod 由一组相关的容器组成，代表一个特定的应用程序。这是 Kubernetes 中最基本的单位；您不必一直考虑容器，因为在这里您应该专注于 pod。

让我们考虑一个名为 XYZ 的应用程序，它将其信息存储在一个数据库中，该数据库提供了一个 REST API，该 API 由其 UI 使用，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/a2b2a568-cd2b-4886-8715-3af7e5e93232.png)

带有其依赖项的 XYZ 应用程序

很明显，我们需要三个单独的服务来使这个应用程序工作。如果我们在处理 Docker，我们会说我们需要三个不同的容器，但从 Kubernetes 的角度来看，所有这三个容器代表一个单独的 pod。这种抽象使我们能够更轻松地管理分布式应用程序。为了创建一个 pod 定义，您应该创建一个描述 pod 中所有容器的`.yaml`文件。我们之前提到的 XYZ 应用程序的示例描述在以下代码中：

```java
apiVersion: v1
kind: Pod
metadata:
    name: application-xyz
spec:
    containers:
        - name: nginx
          image: nginx
          ports:
            - containerPort: 80 

        - name: database
          image: mysql
          volumeMounts:
            - name: mysql-data
              mountPath: /path

        - name: api
          image: <your-api-image>
```

创建文件后，您可以使用以下 Kubernetes 命令执行 pod：

```java
kubectl create -f <file-name.yaml>
```

# 标签

一旦组织内的应用程序数量增加，管理所有这些应用程序往往会成为一场噩梦。想象一下，您只有十五个微服务和两个环境：一个用于暂存，另一个用于生产。在这种情况下，要识别所有正在运行的 pod 将会非常困难，您需要记住所有 pod 名称以查询它们的状态。

标签旨在使此任务更容易。您可以使用它们为 pod 打上易于记忆的标签名称，并且对您来说是有意义的。由于标签是键-值对，您有机会使用任何您想要的内容，包括`environment:<environment-name>`。让我们来看看下面的`application-xyz-pod.yaml`示例文件：

```java
apiVersion: v1
kind: Pod
metadata:
    name: application-xyz
 labels:
 environment:production
 otherLabelName: otherLabelValue
spec:
    containers:
        - name: nginx
          image: nginx
          ports:
            - containerPort: 80 

        - name: database
          image: mysql
          volumeMounts:
            - name: mysql-data
              mountPath: /path

        - name: api
          image: <your-api-image>
```

粗体中的代码显示了标签如何创建。在这里，您可以添加尽可能多的标签。让我们使用以下命令创建这个 pod：

```java
kubectl create -f application-xyz-pod.yaml 
```

一旦 pod 被创建，您可以使用以下命令使用标签查找它：

```java
kubectl get pod -l environment=production
```

# 复制控制器

乍一看，人们可能会认为我们应该关心 pod，但 Kubernetes 建议使用另一个称为复制控制器的抽象。

在生产中永远不会运行一个 pod 实例。相反，您将运行许多 pod 以提供高可用性并支持所有流量。复制控制器旨在确保指定数量的 pod 正在运行。在野外运行服务通常会出现问题，有时主机会崩溃，导致一个或多个 pod 不可用。复制控制器会不断监视系统以查找此类问题，当一个 pod 崩溃时，它会自动为此 pod 创建一个新的副本，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sw-arch-spr5/img/aae89f3e-0546-4a1d-a0ff-c5ef41832e09.png)

复制服务和 pod

复制控制器也对推出新的应用程序版本很有用。您可以轻松关闭与特定副本关联的所有 pod，然后打开新的 pod。

让我们来看看下面的文件，它展示了一个复制控制器的示例：

```java
apiVersion: v1
kind: ReplicationController
metadata:
    name: application-xyz-rc
spec:
    replicas: 3
    selector:
 tier:front-end    template:
        metadata: 
            label:
                env:production
        spec:
            containers:             
               ...
```

该文件的内容与 pod 非常相似；主要区别在于指定的 Docker 服务的种类。在这种情况下，它使用了`ReplicaController`值。稍后，我们将定义所需的副本数量，并且选择器部分可以用来指定标签。

使用此文件，可以通过运行`kubectl create`命令来创建副本，如下所示：

```java
kubectl create -f application-xyz-rc.yaml 
```

您可以验证在需要时如何创建 pod。您可以使用以下命令删除一个 pod：

```java
kubectl delete pod <pod-name>
```

然后，您可以使用以下命令查询可用的 pod：

```java
kubectl get pod
```

# 服务

在生产中通常会有许多复制服务来提供良好的用户体验。然而，无论此过程涉及多少主机或图像，我们都需要为所有这些功能提供一个唯一的入口点：这就是 Kubernetes 服务的目的。

Kubernetes 服务充当特定应用程序的端点和负载均衡器。由于服务位于一组复制的 pod 的前面，它将在所有可用的实例之间分发流量。

请记住，pod 和 Docker 容器是短暂的，我们不能依赖它们的 IP 地址。这就是为什么 Kubernetes 服务对于持续提供服务非常重要。

让我们看一个 Kubernetes 服务的配置文件示例：

```java
apiVersion: v1
kind: Service
metadata:
    name: application-xyz-service
spec:
    ports: 
        port:80
        targetPort: 80
        protocol: TCP
    selector:
 tier:front-end
```

第 2 行的`kind`配置条目具有一个新值—在本例中，该值为`Service`。选择器指示与此服务关联的副本容器，其余的配置参数都是不言自明的。使用此文件，您可以使用`kubectl create`命令如下：

```java
kubectl create -f application-xyz-service.yaml
```

此外，如果您不想为服务创建文件，可以直接使用以下命令公开现有的复制控制器：

```java
kubectl expose rc application-xyz-rc
```

# 总结

在本章中，我们开始回顾容器的基本概念以及它们如何应用于 Docker，这是用于容器化应用程序的最流行的产品之一。

然后，我们学习了如何自动化这个过程，并将其作为 Java 应用程序构建过程的一部分，使用 Gradle 作为构建工具。自动化背后的主要意图是为了与 DevOps 原则保持一致；我们将在下一章节详细讨论 DevOps。在本章末尾，我们看了其他 Docker 工具，它们可以自动化开发环境中的配置过程，并学习了 Kubernetes 以及它在生产环境中的应用。在下一章中，我们将回顾 DevOps 和发布管理的概念。
