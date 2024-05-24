# 精通 Java9 微服务（四）

> 原文：[`zh.annas-archive.org/md5/EB1A7415EF02ADBBA3AE87C35F6AF10F`](https://zh.annas-archive.org/md5/EB1A7415EF02ADBBA3AE87C35F6AF10F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：最佳实践和通用原则

在你为了获得开发微服务样本项目的经验而付出了艰辛努力之后，你可能会想知道如何避免常见错误并改进开发基于微服务的产品和服务的过程。我们可以遵循这些原则或指南来简化微服务开发的过程并避免/减少潜在的限制。我们将在本章重点关注这些关键概念。

本章分为以下三个部分：

+   概述和心态

+   最佳实践和原则

+   微服务框架和工具

# 概述和心态

你可以在新旧产品和服务的背景下实现微服务-based 设计。与认为从头开始开发和设计新系统比修改一个已经在运行的现有系统更容易的观点相反，每种方法都有其各自的挑战和优点。

例如，由于新产品或服务不存在现有的系统设计，你有自由和灵活性去设计系统，而不必考虑其影响。然而，你对于新系统的功能和系统要求并不清晰，因为这些随着时间成熟并逐渐成形。另一方面，对于成熟的产品和服务，你对功能和系统要求有详细的知识和信息。然而，你有一个挑战，那就是减轻设计更改带来的风险影响。因此，当涉及到将生产系统从单体应用更新为微服务时，你需要比如果你正在构建一个系统时计划得更好。

从零开始。

有经验的成功的软件设计专家和架构师总是评估利弊，并且对现有运行系统做任何更改时都持谨慎态度。绝不应该仅仅因为某种设计可能很酷或者时髦就对其进行更改。因此，如果你想将现有生产系统的设计更新为微服务，在做出这个决定之前你需要评估所有的利弊。

我相信单体系统提供一个很好的平台升级到成功的微服务设计。显然，我们这里不讨论成本。你对现有系统和功能有足够的了解，这使你能够将现有系统分割并基于功能以及这些如何相互交互构建微服务。另外，如果你的单体产品已经以某种方式模块化，那么通过暴露 API 而不是**应用程序二进制接口**（**ABI**）直接转换微服务可能是实现微服务架构的最简单方式。成功的基于微服务的系统更依赖于微服务和它们之间的交互协议，而不是其他任何东西。

说到这里，并不意味着如果您从头开始，就不能拥有一个成功的基于微服务的系统。然而，建议基于单体设计的新项目，这为您提供了系统的视角和理解功能。它允许您快速找到瓶颈，并指导您识别任何可以用微服务开发的有潜力的特性。在这里，我们没有讨论项目的规模，这是另一个重要的因素。我们将在下一节中讨论这一点。

在当今的云计算时代和敏捷开发世界中，从任何更改到更改上线通常只需要一个小时。在当今竞争激烈的环境中，每个组织都希望拥有快速将功能交付给用户的优势。持续开发、集成和部署是生产交付过程的一部分，这是一个完全自动化的过程。

如果您提供基于云的产品或服务，那么基于微服务的系统使团队能够敏捷地响应修复任何问题或向用户提供新功能。

因此，在决定从头开始一个新的基于微服务的项目，或者计划将现有单体系统的设计升级为基于微服务的系统之前，您需要评估所有的利弊。您必须倾听并理解团队分享的不同想法和观点，并采取谨慎的方法。

最后，我想分享拥有更好的流程和高效系统对于成功生产系统的重要性。拥有基于微服务的系统并不能保证成功的生产系统，而单体应用程序并不意味着在今天这个时代你不能拥有一个成功的生产系统。Netflix，一个基于微服务的云视频租赁服务，和 Etsy，一个单体电子商务平台，都是成功生产系统的例子（在章节的*参考文献*部分，您可以看到一个有趣的 Twitter 讨论链接）。因此，流程和敏捷也是成功生产系统的关键。

# 最佳实践和原则

正如我们在第一章所学习到的，微服务是一种实现**面向服务架构**（**SOA**）的轻量级风格。除此之外，微服务并没有严格定义，这给了你开发微服务的灵活性，按照你想要的和需求来开发。同时，你需要确保遵循一些标准实践和原则，使你的工作更容易，并成功实施基于微服务的架构。

# 纳米服务、规模和单体

您项目中的每个微服务都应该体积小，并执行一个功能或特性（例如，用户管理），独立到足以自行执行该功能。

来自 Mike Gancarz（设计 X Window 系统的成员）的以下两句话，定义了 Unix 哲学的一个首要原则，也适用于微服务范式：

“小即是美。”

“让每个程序做好一件事。”

现在，我们如何定义在今天这个时代的大小，当你有一个框架（例如 Finangle）来减少**代码行数**（**LOC**）时？此外，许多现代语言，如 Python 和 Erlang，都较为简洁。这使得决定是否要将此代码微服务化变得困难。

显然，你可能为少量的代码行实现一个微服务；这实际上不是一个微服务，而是一个纳米服务。

Arnon Rotem-Gal-Oz 将纳米服务定义如下：

“纳米服务是一个反模式，其中服务过于细粒度。纳米服务是一个其开销（通信、维护等）超过其效用的服务。”

因此，基于功能设计微服务总是有意义的。领域驱动设计使在领域层面定义功能变得更容易。

如前所述，您项目的规模是在决定是否实施微服务或确定您想要为项目拥有的微服务数量时的一个关键因素。在一个简单的小型项目中，使用单体架构是有意义的。例如，基于我们在第三章学到的领域设计，*领域驱动设计*，你会清楚地了解你的功能性需求，并使事实可用以绘制各种功能或特性之间的边界。例如，在我们已经实施的示例项目（在线表格预订系统；OTRS）中，只要你不希望向客户暴露 API，或者你不想将其作为 SaaS 使用，或者在你做出决定之前有许多类似的参数需要评估，使用单体设计开发相同的项目是非常容易的。

您可以稍后将在单体项目中迁移到微服务设计，当时机到来时。因此，重要的是您应该以模块化方式开发单体项目，并在每个层次和层面上实现松耦合，并确保不同功能和特性之间有预定义的接触点和边界。此外，您的数据源（如数据库）应相应地设计。即使您不打算将项目迁移到基于微服务的系统，这也将使故障修复和功能改进更容易实施。

关注前面的点将减轻您在迁移到微服务时可能遇到的任何可能的困难。

通常，大型或复杂的项目应该使用基于微服务的架构进行开发，因为它提供了许多优势，如前几章所讨论的。

我甚至建议将你的初始项目开发为单块应用；一旦你更好地理解了项目的功能和项目复杂性，然后你再将其迁移到微服务。理想情况下，一个开发好的初始原型应该为你提供功能边界，这将使你能够做出正确的选择。

# 持续集成和部署

你必须有一个持续集成和部署的过程。它让你能够更快地交付更改并尽早发现错误。因此，每个服务应该有自己的集成和部署过程。此外，它必须是自动化的。有许多工具可供选择，如 Teamcity、Jenkins 等，这些工具被广泛使用。它帮助你自动化构建过程——这可以尽早捕获构建失败，特别是当你将你的更改与主分支（如任何发布分支/标签或主分支）集成时。

你还可以将你的测试集成到每个自动化集成和部署过程中。**集成测试**测试系统的不同部分之间的交互，如两个接口（API 提供者和消费者）之间，或系统中的不同组件或模块之间，如 DAO 和数据库之间等。集成测试很重要，因为它测试模块之间的接口。首先，在孤立状态下测试单个模块。然后，执行集成测试以检查组合行为并验证需求是否正确实现。因此，在微服务中，集成测试是验证 API 的关键工具。我们将在下一节中详细介绍这一点。

最后，你可以在 CD（持续部署）机器上看到主分支的最新更改，该过程在这里部署构建。

这个过程并不会到此结束：你可以创建一个容器，比如 Docker，然后将其交给你的 WebOps 团队，或者有一个单独的过程，将其送到一个配置好的位置或者部署到 WebOps 阶段环境。从这里，一旦得到指定权限的批准，它就可以直接部署到你的生产系统。

# 系统/端到端测试自动化

测试是任何产品和服务的交付中的一个非常重要的部分。你不希望向客户交付有缺陷的应用程序。在过去，当瀑布模型流行时，一个组织在向客户交付之前，测试阶段通常需要 1 到 6 个月或更长时间。近年来，在敏捷过程变得流行之后，更加重视自动化。与先前的点测试类似，自动化也是强制性的。

无论你是否遵循**测试驱动开发**（**TDD**），我们必须要有系统或端到端的自动化测试。测试你的业务场景非常重要，端到端测试也同样如此，它可能从你的 REST 调用开始，到数据库检查，或者从 UI 应用程序开始，到数据库检查。

如果你有公开的 API，测试你的 API 也很重要。

这样做可以确保任何更改都不会破坏任何功能，并确保无缝、无 bug 的生产交付。如上节所述，每个模块都通过单元测试进行隔离测试，以检查一切是否按预期工作，然后在不同模块之间执行集成测试，以检查预期的组合行为并验证需求是否正确实现。集成测试后，执行功能测试，以验证功能和特性需求。

所以，如果单元测试确保孤立状态下单个模块运行良好，那么集成测试确保不同模块之间的交互按预期工作。如果单元测试正常工作，那么集成测试失败的概率大大降低。同样，集成测试确保功能测试很可能成功。

假设我们总是保持所有类型的测试更新，无论是单元级测试还是端到端的测试场景。

# 自我监控和日志记录

一个微服务应当提供关于自身及其所依赖的各种资源状态的服务信息。服务信息包括诸如处理请求的平均、最小和最大时间、成功和失败的请求数量、能够追踪请求、内存使用情况等统计数据。

在 2015 年的 Glue Conference（Glue Con）上，Adrian Cockcroft 强调了几个对于监控微服务非常重要的实践。其中大多数对于任何监控系统都是有效的：

+   在分析指标意义的代码上花费更多时间，而不是在收集、移动、存储和显示指标的代码上。这不仅有助于提高生产力，还提供重要的参数来微调微服务并提高系统效率。想法是开发更多的分析工具，而不是开发更多的监控工具。

+   显示延迟的指标需要小于人类的注意力跨度。这意味着根据 Adrian 的说法，小于 10 秒。

+   验证您的测量系统具有足够的准确性和精度。收集响应时间的直方图。

+   准确的数据使决策更快，并允许您进行微调，直到达到精确度级别。他还建议，最好显示响应时间的图表是直方图。

+   监控系统需要比被监控的系统更具可用性和可扩展性。

+   这个说法说明了一切：你不能依赖一个本身不稳定或不是 24/7 可用的系统。

+   针对分布式、短暂、云原生、容器化的微服务进行优化。

+   将指标适合模型以理解关系。

监控是微服务架构的关键组成部分。根据项目规模，你可能会有几十个到几千个微服务（对于一个大企业的重大项目来说确实如此）。即使是为了扩展和高可用性，组织也会为每个微服务创建一个集群或负载均衡的池/容器，甚至根据版本为每个微服务创建单独的池。最终，这增加了你需要监控的资源数量，包括每个微服务实例。此外，重要的是你有一个流程，以便在任何事情出错时立即知道，或者更好的是，在事情出错之前收到警告通知。因此，构建和使用微服务架构的有效和高效的监控至关重要。Netflix 使用诸如 Netflix Atlas（处理 12 亿个指标的实时运营监控）、Security Monkey（用于监控基于 AWS 环境的网络安全）、Scumblr（情报收集工具）和 FIDO（用于分析事件和自动事件报告）等工具进行安全监控。

日志是微服务中不应忽视的重要方面。有效的日志记录至关重要。由于可能有 10 个或更多的微服务，管理日志记录是一项巨大的任务。

对于我们的示例项目，我们使用了**映射诊断上下文**（**MDC**）日志记录，这在某种程度上足以满足单个微服务的日志记录。然而，我们还需要整个系统或集中日志记录的日志记录。我们还需要日志的聚合统计数据。有一些工具可以完成这项工作，例如 Loggly 或 Logspout。

请求和生成的相关事件为您提供了请求的整体视图。对于任何事件和请求的跟踪，将事件和请求与服务 ID 和请求 ID 分别关联非常重要。你还可以将事件的内容，如消息、严重性、类名等，与服务 ID 相关联。

# 每个微服务单独的数据存储

如果你还记得，微服务最重要的特征之一是你可以了解微服务如何与其他微服务隔离运行，最常见的是作为独立的应用程序。

遵循这一规则，建议你不要在多个微服务之间使用相同的数据库或任何其他数据存储。在大型项目中，你可能有不同的团队在同一个项目中工作，你希望每个微服务都能选择最适合自己的数据库。

现在，这也带来了一些挑战。

例如，以下内容与可能在同一项目中工作在不同微服务上的团队相关，如果该项目共享相同的数据库结构。一种可能性是，一个微服务的更改可能会影响另一个微服务的模型。在这种情况下，一个更改可能会影响依赖性微服务，所以你还需要更改依赖性模型结构。

为了解决这个问题，微服务应该基于一个 API 驱动的平台进行开发。每个微服务都会暴露出自己的 API，其他微服务可以消费这些 API。因此，你还需要开发 API，这是不同微服务集成的必要条件。

同样，由于不同的数据存储，实际项目数据也分布在多个数据存储中，这使得数据管理更加复杂，因为不同的存储系统更容易失去同步或变得不一致，外键也可能意外地改变。为了解决这个问题，你需要使用**主数据管理**（**MDM**）工具。MDM 工具在后台运行，如果发现任何不一致性，会进行修复。对于 OTRS 示例，它可能会检查存储预订请求 ID 的每个数据库，以验证它们中都存在相同的 ID（换句话说，任何数据库中都没有缺失或额外的 ID）。市场上的 MDM 工具包括 Informatica、IBM MDM 高级版、Oracle Siebel UCM、Postgres（主流复制）、mariadb（主/主配置）等。

如果现有的产品都不符合你的要求，或者你对任何专有产品都不感兴趣，那么你可以自己编写。目前，API 驱动的开发和平台减少了这种复杂性；因此，微服务沿着 API 平台开发是非常重要的。

# 交易边界

我们在第三章中讨论了领域驱动设计概念，*领域驱动设计*。如果你没有完全掌握它，请复习这一部分，因为它能让你从垂直角度理解状态。由于我们关注的是基于微服务的设计，结果是我们有一个系统系统，每个微服务代表一个系统。在这种环境中，在任何给定时间找到整个系统的状态是非常具有挑战性的。如果你熟悉分布式应用，那么你可能会在这种环境中对状态感到舒适。

确立交易边界非常重要，这些边界描述了在任何给定时间哪个微服务拥有一个消息。你需要一种或一种参与事务、交易路由、错误处理程序、幂等消费者和补偿操作的方式。确保跨异质系统的一致性行为并非易事，但市场上有一些工具可以为你完成这项工作。

例如，Camel 具有出色的事务功能，可以帮助开发者轻松创建具有事务行为的服务。

# 微服务框架和工具

最好还是不要重新发明轮子。因此，我们想探讨一下市场上已经有哪些工具，并提供使微服务开发和部署更简单的平台、框架和特性。

在整个书籍中，我们广泛使用了 Spring Cloud，原因相同：它提供了构建微服务所需的所有工具和平台。Spring Cloud 使用 Netflix **开源软件**（**OSS**）。让我们来探索一下 Netflix OSS——一个完整的套餐。

我还添加了关于每个工具如何帮助构建良好的微服务架构的简要概述。

# Netflix 开源软件（OSS）

Netflix OSS 中心是 Java 基础微服务开源项目中最受欢迎和广泛使用的开源软件。世界上最成功的视频租赁服务依赖于它。Netflix 有超过 4000 万用户，并在全球范围内使用。Netflix 是一个纯基于云的解决方案，基于微服务架构开发。可以说，每当有人谈论微服务时，Netflix 是首先出现在脑海中的名字。让我们讨论它提供的各种工具。在开发示例 OTRS 应用程序时，我们已经讨论了许多工具。然而，还有一些我们没有探索过。在这里，我们只对每个工具进行概述，而不是深入讨论。这将为您提供微服务架构的实用特性和在云中使用它的整体概念。

# 构建 - Nebula

Netflix Nebula 是一组使您使用 Gradle（类似 Maven 的构建工具）构建微服务变得更加容易的 Gradle 插件。对于我们的示例项目，我们使用了 Maven，因此我们在这本书中没有机会探索 Nebula。然而，探索它是很有趣的。对于开发人员来说，Nebula 最重要的功能是消除了 Gradle 构建文件中的样板代码，这使得开发者可以专注于编码。

拥有一个好的构建环境，特别是 CI/CD（持续集成和持续部署）对于微服务开发和与敏捷开发保持一致是必须的。Netflix Nebula 使您的构建变得更容易、更高效。

# 部署和交付 - Spinnaker 与 Aminator

一旦您的构建准备好，您希望将该构建移动到 **亚马逊网络服务**（**AWS**）EC2。Aminator 创建并打包构建的镜像，形式为 **亚马逊机器镜像**（**AMI**）。Spinnaker 然后将这些 AMI 部署到 AWS。

Spinnaker 是一个高速度和效率的持续交付平台，用于发布代码更改。Spinnaker 还支持其他云服务，例如 Google 计算机引擎和 Cloud Foundry。

如果你想将最新的微服务构建部署到例如 EC2 的云环境中，Spinnaker 和 Aminator 可以帮助你以自主的方式完成。

# 服务注册和发现 - Eureka

如我们在本书中所探讨的，Eureka 提供了一个负责微服务注册和发现的服务。除此之外，Eureka 还用于负载均衡中间层（托管不同微服务的进程）。Netflix 也使用 Eureka，以及其他工具，如 Cassandra 或 memcached，以提高其整体可用性。

微服务架构中必须要有服务注册与发现。Eureka 就是为此目的而设计的。请参阅第四章，*实现微服务*，以获取有关 Eureka 的更多信息。

# 服务通信 - Ribbon

如果进程间或服务间没有通信，微服务架构就毫无用处。Ribbon 应用提供了这一特性。Ribbon 与 Eureka 一起实现负载均衡，与 Hystrix 一起实现故障容忍或断路器操作。

Ribbon 还支持除了 HTTP 以外的 TCP 和 UDP 协议，并提供这些协议支持异步和响应式模型。它还提供了缓存和批量处理功能。

由于您将在项目中拥有许多微服务，您需要一种使用进程间或服务间通信处理信息的方法。Netflix 为这一目的提供了 Ribbon 工具。

# 断路器 - Hystrix

Hystrix 工具用于断路器操作，即延迟和故障容忍。因此，Hystrix 阻止级联失败。Hystrix 执行实时操作，监控服务和属性变化，并支持并发。

断路器或故障容忍是任何项目的重要概念，包括微服务。一个微服务的失败不应该使您的整个系统停止；为了防止这种情况发生，并在失败时向客户提供有意义的信息，这是 Netflix Hystrix 的职责。

# 边缘（代理）服务器 - Zuul

Zuul 是一个边缘服务器或代理服务器，为 UI 客户端、Android/iOS 应用程序或任何第三方消费者提供 API。从概念上讲，它是外部应用程序的门户。

Zuul 允许动态路由和监控请求。它还执行安全操作，如身份验证。它可以识别每个资源的身份验证要求，并拒绝任何不满足它们的请求。

您需要一个边缘服务器或 API 网关来处理您的微服务。Netflix Zuul 提供了这一特性。请参阅第五章，*部署与测试*，以获取更多信息。

# 操作监控 - Atlas

Atlas 是一个操作监控工具，提供近实时的时间序列数据维度信息。它捕获操作智能，提供系统内部当前发生情况的图片。它具有内存数据存储功能，允许它快速收集和报告大量指标。目前，它为 Netflix 处理了 13 亿个指标。

Atlas 是一个可扩展的工具。这就是为什么它现在可以处理 13 亿个指标，而几年前只有 100 万个指标。Atlas 不仅在读取数据方面提供可扩展性，而且在作为图表请求一部分进行聚合方面也提供可扩展性。

Atlas 使用了 Netflix Spectator 库来记录维度时间序列数据。

一旦你在云环境中部署了微服务，你就需要有一个监控系统来跟踪和监控所有的微服务。Netflix Atlas 为你完成了这项工作。

# 可靠性监控服务 - Simian Army

在云环境中，没有任何单一组件能保证 100% 的正常运行时间。因此，成功的微服务架构的要求是在一个云组件失败的情况下使整个系统可用。Netflix 开发了一个名为 Simian Army 的工具来避免系统失败。Simian Army 保持了云环境的安全、安全和高可用性。为了实现高可用性和安全性，它使用了各种服务（猴子）在云中产生各种故障、检测异常情况，并测试云应对这些挑战的能力。

它使用了以下服务（猴子），这些服务来自 Netflix 的博客：

+   **Chaos Monkey**：Chaos Monkey 是一个服务，它识别出一组系统，并在一组中的一个系统随机终止。该服务在受控的时间和间隔内运行。Chaos Monkey 只在正常工作时间运行，目的是让工程师保持警觉并能够响应。

+   **Janitor Monkey**：Janitor Monkey 是一个在 AWS 云中运行的服务，寻找未使用的资源进行清理。它可以扩展到与其他云提供商和云资源一起工作。服务的日程是可配置的。Janitor Monkey 通过对其应用一组规则来确定资源是否应该成为清理候选资源。如果任何规则确定资源是清理候选资源，Janitor Monkey 将标记该资源，并安排一个时间进行清理。在特殊情况下，在 Janitor Monkey 删除资源之前，你想保留一个未使用的资源更长时间，资源所有者会在清理时间前 configurable 天收到通知。

+   **Conformity Monkey**：Conformity Monkey 是一个在 AWS 云中运行的服务，寻找不符合最佳实践预定义规则的实例。它可以扩展到与其他云提供商和云资源一起工作。服务的日程是可配置的。如果任何规则确定该实例不符合，猴子会向实例所有者发送电子邮件通知。在某些特殊情况下，你可能想忽略特定的一致性规则的警告。

+   **安全猴**：安全猴监控 AWS 账户中的策略更改和对不安全配置的警报。安全猴的主要目的是安全，尽管它也是一个跟踪潜在问题的有用工具，因为它本质上是一个变更跟踪系统。

成功的微服务架构确保你的系统始终运行，单个云组件的故障不应该导致整个系统失败。Simian Army 使用许多服务来实现高可用性。

# AWS 资源监控 - Edda

在云环境中，一切都是动态的。例如，虚拟主机实例经常变化，IP 地址可能被各种应用程序重复使用，或者发生防火墙等相关变化。

Edda 是一个跟踪这些动态 AWS 资源的服务的服务。Netflix 将其命名为 Edda（意为*北欧神话传说*），因为它记录了云管理和部署的传说。Edda 使用 AWS API 轮询 AWS 资源并记录结果。这些记录允许你搜索并查看云如何随时间变化。例如，如果 API 服务器的任何主机出现问题，那么你需要找出那个主机是哪个团队负责的。

它提供以下功能：

+   **动态查询**：Edda 提供了 REST API，并支持矩阵参数，提供字段选择器，让你只检索所需的数据。

+   **历史**/变更：Edda 维护了所有 AWS 资源的历史记录。这些信息有助于分析停机的原因和影响。Edda 还可以提供关于资源当前和历史信息的不同的视图。在撰写本文时，它将信息存储在 MongoDB 中。

+   **配置**：Edda 支持许多配置选项。通常，你可以从多个账户和多个区域轮询信息，并可以使用账户和区域的组合来指定位点。同样，它为 AWS、Crawler、Elector 和 MongoDB 提供不同的配置。

如果你正在使用 AWS 来托管基于微服务的产品，那么 Edda 起到了监控 AWS 资源的作用。

# 主机上性能监控 - Vector

Vector 是一个静态的网页应用程序，在网页浏览器内运行。它允许监控安装了**性能共乘**（**PCP**）的主机的表现。Vector 支持 PCP 3.10+ 版本。PCP 收集指标并将其提供给 Vector。

它提供高分辨率的即时指标。这有助于工程师了解系统如何表现，并正确诊断性能问题。

Vector 是一个帮助你监控远程主机性能的工具。

# 分布式配置管理 - Archaius

Archaius 是一个分布式配置管理工具，它允许你执行以下操作：

+   使用动态和类型化的属性。

+   执行线程安全的配置操作。

+   使用轮询框架检查属性变更。

+   在配置的有序层次结构中使用回调机制。

+   使用 JConsole 检查并操作属性，因为 Archaius 提供了 JMX MBean。

+   当您有一个基于微服务的产品时，需要一个好的配置管理工具。Archaius 帮助在分布式环境中配置不同类型的属性。

# Apache Mesos 调度器 - Fenzo

Fenzo 是 Apache Mesos 框架的 Java 编写的调度库。Apache Mesos 框架匹配并分配资源给待处理任务。以下是其关键特性：

+   它支持长期运行的服务风格任务和批量任务。

+   它可以自动扩展执行主机集群，基于资源需求。

+   它支持插件，您可以根据需求创建。

+   您可以监控资源分配失败，这使您能够调试根本原因。

# 成本和云利用率 - Ice

Ice 从成本和使用角度提供了云资源的鸟瞰视图。它提供了关于为不同团队提供的最新云资源配置信息，这对于优化云资源的使用非常有价值。

Ice 是一个 grail 项目。用户与 Ice UI 组件交互，该组件显示通过 Ice reader 组件发送的信息。reader 从由 Ice processor 组件生成的数据中获取信息。Ice processor 组件从详细的云账单文件中读取数据信息，并将其转换为 Ice reader 组件可读取的数据。

# 其他安全工具 - Scumblr 和 FIDO

与 Security Monkey 一起，Netflix OSS 还利用了 Scumblr 和完全集成的防御操作（FIDO）工具。

为了跟踪并保护您的微服务免受常规威胁和攻击，您需要一种自动化的方式来确保并监控您的微服务。Netflix Scumblr 和 FIDO 为您完成这项工作。

# Scumblr

Scumblr 是一个基于 Ruby on Rails 的 Web 应用程序，允许您执行定期搜索，并针对识别的结果存储/采取行动。基本上，它收集情报，利用互联网范围内的针对性搜索浮出具体的安全问题以供调查。

Scumblr 利用 Workflowable 宝石允许为不同类型的结果设置灵活的工作流程。Scumblr 搜索使用称为“搜索提供者”的插件。它检查异常，例如以下异常。由于它是可扩展的，您可以添加尽可能多的异常：

+   妥协的凭据

+   漏洞/黑客讨论

+   攻击讨论

+   与安全相关的社交媒体讨论

# 完全集成的防御操作（FIDO）

FIDO 是一个安全编排框架，用于分析事件和自动化事件响应。它通过评估、评估和响应恶意软件来自动化事件响应过程。FIDO 的主要目的是处理评估当今安全堆栈中威胁和它们生成的大量警报所需的大量手动工作。

作为一个编排平台，FIDO 可以通过大幅减少检测、通知和响应网络攻击所需的手动努力，使您现有的安全工具更高效、更准确地使用。有关更多信息，您可以参考以下链接：

+   [`github.com/Netflix/Fido`](https://github.com/Netflix/Fido)

+   [`github.com/Netflix`](https://github.com/Netflix)

# 参考文献

+   单片式（Etsy）与微服务（Netflix）的 Twitter 讨论：[`twitter.com/adrianco/status/441169921863860225`](https://twitter.com/adrianco/status/441169921863860225)

+   由 Adrian Cockcroft 所做的《监控微服务和容器》演讲：[`www.slideshare.net/adriancockcroft/gluecon-monitoring-microservices-and-containers-a-challenge`](http://www.slideshare.net/adriancockcroft/gluecon-monitoring-microservices-and-containers-a-challenge)

+   纳米服务反模式：[`arnon.me/2014/03/services-microservices-nanoservices/`](http://arnon.me/2014/03/services-microservices-nanoservices/)

+   Apache Camel 用于微服务架构：[`www.javacodegeeks.com/2014/09/apache-camel-for-micro%C2%ADservice-architectures.html`](https://www.javacodegeeks.com/2014/09/apache-camel-for-micro%C2%ADservice-architectures.html)

+   Teamcity: [`www.jetbrains.com/teamcity/`](https://www.jetbrains.com/teamcity/)

+   Jenkins: [`jenkins-ci.org/`](https://jenkins-ci.org/)

+   Loggly: [`www.loggly.com/`](https://www.loggly.com/)

# 总结

在本章中，我们探讨了各种最适合微服务基础产品和服务最佳实践和原则。微服务架构是云环境的结果，与基于本地的大型单片系统相比，其应用越来越广泛。我们已经确定了几个与大小、敏捷性和测试有关的原则，这些原则对于成功实施至关重要。

我们已经对 Netflix OSS 使用的各种工具有了概述，这些工具是实现微服务架构基础产品和服务所需的各种关键特性。Netflix 提供视频租赁服务，成功使用了相同的工具。

在下一章中，读者可能会遇到问题，可能会困在这些问题上。本章解释了在微服务开发过程中遇到的常见问题及其解决方案。


# 第十章：故障排除指南

我们已经走了这么远，我相信您享受这段具有挑战性和快乐的学习旅程中的每一个时刻。我不会说这本书在此章节后结束，而是您正在完成第一个里程碑。这个里程碑为基于微服务设计的云学习和新范式实施打开了大门。我想再次确认集成测试是测试微服务和 API 之间交互的重要方法。在您处理在线表格预订系统（OTRS）的示例应用程序时，我相信您遇到了许多挑战，尤其是在调试应用程序时。在这里，我们将介绍一些可以帮助您排除部署应用程序、Docker 容器和宿主机的故障的最佳实践和工具。

本章涵盖以下三个主题：

+   日志记录和 ELK 栈

+   使用 Zipkin 和 Sleuth 进行服务调用时使用相关 ID

+   依赖关系和版本

# 日志记录和 ELK 栈

您能想象在生产系统上不查看日志的情况下调试任何问题吗？简单地说，不能，因为回到过去将会很困难。因此，我们需要日志记录。日志还为我们提供了关于系统的警告信号，如果它们是这样设计和编码的话。日志记录和日志分析是排除任何问题的重要步骤，也是提高吞吐量、扩展能力和监控系统健康状况的重要步骤。因此，拥有一个非常好的日志平台和策略将使调试变得有效。日志是软件开发初期最重要的关键组成部分之一。

微服务通常使用如 Docker 之类的图像容器进行部署，这些容器提供有助于您读取部署在容器内的服务日志的命令。Docker 和 Docker Compose 提供命令以分别流式传输容器内运行服务和所有容器的日志输出。请参阅以下 Docker 和 Docker Compose 的`logs`命令：

**Docker 日志命令：** **用法：** `docker logs [OPTIONS] <CONTAINER NAME>`  **获取容器的日志：**

`**-f, --follow 跟随日志输出**`

`**--help 打印用法**`

`**--since="" 自时间戳以来显示日志**`

`**-t, --timestamps 显示时间戳**`

`**--tail="all" 显示日志末尾的行数**`

**Docker Compose 日志命令：** `**用法：docker-compose logs [options] [SERVICE...]**`

**选项：**

`**--no-color 产生单色输出**`

`**-f, --follow 跟随日志输出**`

`**-t, --timestamps 显示时间戳**`

`**--tail 显示每个容器日志末尾的行数**

**[SERVICES...] 代表容器的服务 - 你可以指定多个**`

这些命令帮助你探索运行在容器中的微服务和其它进程的日志。正如你所看到的，当你有很多服务时，使用上述命令将是一个挑战性的任务。例如，如果你有数十个或数百个微服务，跟踪每个微服务的日志将非常困难。同样，你可以想象，即使没有容器，单独监控日志也会非常困难。因此，你可以想象探索和关联数十到数百个容器的日志有多么困难。这是耗时的，并且几乎没有任何价值。

因此，像 ELK 堆栈这样的日志聚合和可视化工具就派上用场了。它将用于集中日志。我们将在下一节中探讨这一点。

# 简要概述

**Elasticsearch、Logstash、Kibana**（**ELK**）堆栈是一系列执行日志聚合、分析、可视化和监控的工具。ELK 堆栈提供了一个完整的日志平台，允许你分析、可视化和监控所有日志，包括各种产品日志和系统日志。如果你已经了解 ELK 堆栈，请跳到下一节。在这里，我们将简要介绍 ELK 堆栈中的每个工具：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/87defb1f-0f40-4d90-8f8d-0be85aaf64c6.png)

ELK 概览（来源：elastic.co）

# Elasticsearch

Elasticsearch 是最受欢迎的企业级全文搜索引擎之一。它是开源软件。它是可分发的，并支持多租户。单个 Elasticsearch 服务器存储多个索引（每个索引代表一个数据库），单个查询可以搜索多个索引的数据。它是一个分布式搜索引擎，并支持集群。

它易于扩展，可以提供接近实时的搜索，延迟仅为 1 秒。它使用 Java 编写，依赖于 Apache Lucene。Apache Lucene 也是免费和开源的，它为 Elasticsearch 提供了核心，也被称为信息检索软件库。

Elasticsearch API 广泛且详尽。Elasticsearch 提供基于 JSON 的架构，占用更少的存储，并以 JSON 的形式表示数据模型。Elasticsearch API 使用 JSON 文档进行 HTTP 请求和响应。

# Logstash

Logstash 是一个具有实时流水线功能的开源数据收集引擎。简单来说，它收集、解析、处理和存储数据。由于 Logstash 具有数据流水线功能，它帮助你处理来自各种系统的各种事件数据，如日志。Logstash 作为一个代理运行，收集数据、解析数据、过滤数据，并将输出发送到指定应用，如 Elasticsearch，或简单的控制台标准输出。

它还拥有一个非常好的插件生态系统（图片来源于[www.elastic.co](http://www.elastic.co)：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/d8951d1d-10a5-4118-bf8d-6a6174fb9975.jpg)

Logstash 生态系统

# Kibana

Kibana 是一个开源的分析与可视化网页应用程序。它被设计用来与 Elasticsearch 协同工作。你使用 Kibana 来搜索、查看与交互存储在 Elasticsearch 索引中的数据。

这是一个基于浏览器的网络应用程序，让你执行高级数据分析并在各种图表、表格和地图中可视化你的数据。此外，它是一个零配置应用程序。因此，安装后既不需要编写任何代码，也不需要额外的基础设施。

# ELK 栈设置

通常，这些工具是单独安装，然后配置成相互通信。这些组件的安装相当直接。从指定位置下载可安装的工件，并按照下一节中的安装步骤进行操作。

下面提供的安装步骤是基本设置的一部分，这是你想要运行的 ELK 栈所必需的。由于这个安装是在我的本地主机上完成的，所以我使用了主机 localhost。它可以很容易地用你想要的任何相应的主机名来替换。

# 安装 Elasticsearch

要安装 Elasticsearch，我们可以使用 Elasticsearch 的 Docker 镜像：

```java
docker pull docker.elastic.co/elasticsearch/elasticsearch:5.5.1 
```

我们也可以按照以下步骤安装 Elasticsearch：

1.  从[`www.elastic.co/downloads/elasticsearch`](https://www.elastic.co/downloads/elasticsearch)下载最新的 Elasticsearch 分发版。

1.  将它解压到系统中的所需位置。

1.  确保安装了最新版本的 Java，并且`JAVA_HOME`环境变量已设置。

1.  前往 Elasticsearch 的主页并运行`bin/elasticsearch`，在基于 Unix 的系统上，以及在 Windows 上运行`bin/elasticsearch.bat`。

1.  打开任何浏览器并输入`http://localhost:9200/`。成功安装后，它应该会为你提供一个类似于以下的 JSON 对象：

```java
{ 
  "name" : "Leech", 
  "cluster_name" : "elasticsearch", 
  "version" : { 
    "number" : "2.3.1", 
    "build_hash" : "bd980929010aef404e7cb0843e61d0665269fc39", 
    "build_timestamp" : "2016-04-04T12:25:05Z", 
    "build_snapshot" : false, 
    "lucene_version" : "5.5.0" 
  }, 
  "tagline" : "You Know, for Search" 
}
```

默认情况下，GUI 并没有安装。你可以通过从`bin`目录执行以下命令来安装，确保系统连接到互联网：

```java
  plugin -install mobz/elasticsearch-head

```

1.  如果你正在使用 Elasticsearch 镜像，那么就运行 Docker 镜像（稍后，我们将使用`docker-compose`一起运行 ELK 栈）。

1.  现在，你可以通过 URL`http://localhost:9200/_plugin/head/`访问 GUI 界面。你可以将`localhost`和`9200`替换为你的主机名和端口号。

# 安装 Logstash

要安装 Logstash，我们可以使用 Logstash 的 Docker 镜像：

```java
docker pull docker.elastic.co/logstash/logstash:5.5.1 
```

我们也可以通过执行以下步骤来安装 Logstash：

1.  从[`www.elastic.co/downloads/logstash`](https://www.elastic.co/downloads/logstash)下载最新的 Logstash 分发版。

1.  将它解压到系统中的所需位置。

    准备一个配置文件，如下所示。它指示 Logstash 从给定文件中读取输入并将其传递给 Elasticsearch（请参阅下面的`config`文件；Elasticsearch 由 localhost 和`9200`端口表示）。这是最简单的配置文件。要添加过滤器并了解更多关于 Logstash 的信息，你可以探索可用的 Logstash 参考文档[`www.elastic.co/guide/en/logstash/current/index.html`](https://www.elastic.co/guide/en/logstash/current/index.html)。

正如你所看到的，OTRS 的`service`日志和`edge-server`日志作为输入添加了。同样地，你也可以添加其他微服务的日志文件。

```java
input { 
  ### OTRS ### 
  file { 
    path => "\logs\otrs-service.log" 
    type => "otrs-api" 
    codec => "json" 
    start_position => "beginning" 
  } 

  ### edge ### 
  file { 
    path => "/logs/edge-server.log" 
    type => "edge-server" 
    codec => "json" 
  } 
} 

output { 
  stdout { 
    codec => rubydebug 
  } 
  elasticsearch { 
    hosts => "localhost:9200" 
  } 
} 
```

1.  在 Unix-based 系统上，前往 Logstash 主目录并运行`bin/logstash agent -f logstash.conf`，在 Windows 上，运行`bin/logstash.bat agent -f logstash.conf`。在这里，Logstash 使用`agent`命令执行。Logstash 代理从配置文件中提供的输入字段中的源收集数据，并将输出发送到 Elasticsearch。在这里，我们没有使用过滤器，因为否则它可能会在将数据提供给 Elasticsearch 之前处理输入数据。

同样地，你可以使用下载的 Docker 镜像来运行 Logstash（稍后，我们将使用`docker-compose`来一起运行 ELK 栈）。

# 安装 Kibana

要安装 Kibana，我们可以使用 Kibana 的 Docker 镜像：

```java
docker pull docker.elastic.co/kibana/kibana:5.5.1 
```

我们还可以通过执行以下步骤来安装 Kibana 网页应用程序：

1.  从[`www.elastic.co/downloads/kibana`](https://www.elastic.co/downloads/kibana)下载最新的 Kibana 分发版。

1.  将其解压到系统中的所需位置。

1.  打开 Kibana 主目录下的配置文件`config/kibana.yml`，并将`elasticsearch.url`指向之前配置的 Elasticsearch 实例。

```java
   elasticsearch.url: "http://localhost:9200"
```

1.  在 Unix-based 系统上，前往 Kibana 主目录并运行`bin/kibana agent -f logstash.conf`，在 Windows 上，运行`bin/kibana.bat agent -f logstash.conf`。

1.  如果你使用的是 Kibana 的 Docker 镜像，那么你可以运行 Docker 镜像（稍后，我们将使用 docker-compose 来一起运行 ELK 栈）。

1.  现在，你可以通过 URL`http://localhost:5601/`从你的浏览器访问 Kibana 应用。

    要了解更多关于 Kibana 的信息，请探索 Kibana 参考文档[`www.elastic.co/guide/en/kibana/current/getting-started.html`](https://www.elastic.co/guide/en/kibana/current/getting-started.html)。

正如我们遵循前面的步骤，你可能已经注意到它需要一些努力。如果你想要避免手动设置，你可以 Docker 化它。如果你不想花精力创建 ELK 栈的 Docker 容器，你可以在 Docker Hub 上选择一个。在 Docker Hub 上，有许多现成的 ELK 栈 Docker 镜像。你可以尝试不同的 ELK 容器，选择最适合你的那个。`willdurand/elk`是最受欢迎的容器，启动简单，与 Docker Compose 配合良好。

# 使用 Docker Compose 运行 ELK 栈

截至撰写本节时，elastic.co 自己的 Docker 仓库中可用的 ELK 镜像默认启用了 XPack 包。将来，这可能成为可选的。根据 ELK 镜像中 XPack 的可用性，您可以修改`docker-compose-elk.yml` `docker-compose`文件：

```java
version: '2' 

services: 
  elasticsearch: 
    image: docker.elastic.co/elasticsearch/elasticsearch:5.5.1 
    ports: 
      - "9200:9200" 
      - "9300:9300" 
    environment: 
      ES_JAVA_OPTS: "-Xmx256m -Xms256m" 
      xpack.security.enabled: "false" 
      xpack.monitoring.enabled: "false" 
      # below is required for running in dev mode. For prod mode remove them and vm_max_map_count kernel setting needs to be set to at least 262144 
      http.host: "0.0.0.0" 
      transport.host: "127.0.0.1" 
    networks: 
      - elk 

  logstash: 
    image: docker.elastic.co/logstash/logstash:5.5.1 
    #volumes: 
    #  - ~/pipeline:/usr/share/logstash/pipeline 
    #  windows manually copy to docker cp pipleline/logstash.conf 305321857e9f:/usr/share/logstash/pipeline. restart container after that 
    ports: 
      - "5001:5001" 
    environment: 
      LS_JAVA_OPTS: "-Xmx256m -Xms256m" 
      xpack.monitoring.enabled: "false" 
      xpack.monitoring.elasticsearch.url: "http://192.168.99.100:9200" 
      command: logstash -e 'input { tcp { port => 5001 codec => "json" } } output { elasticsearch { hosts => "192.168.99.100" index => "mmj" } }' 
    networks: 
      - elk 
    depends_on: 
      - elasticsearch 

  kibana: 
    image: docker.elastic.co/kibana/kibana:5.5.1 
    ports: 
      - "5601:5601" 
    environment: 
      xpack.security.enabled: "false" 
      xpack.reporting.enabled: "false" 
      xpack.monitoring.enabled: "false" 
    networks: 
      - elk 
    depends_on: 
      - elasticsearch 

networks: 
  elk: 
    driver: bridge 

```

一旦保存了 ELK Docker Compose 文件，您可以使用以下命令运行 ELK 堆栈（该命令从包含 Docker Compose 文件的目录运行）：

```java
docker-compose -f docker-compose-elk.yml up -d 
```

前一条命令的输出如以下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/c32104c2-3d7a-4822-a5f1-15d7e7be0b52.png)

使用 Docker Compose 运行 ELK 堆栈

如果不使用卷，环境管道将无法工作。对于像 Windows 7 这样的 Windows 环境，通常很难配置卷，您可以将管道 CONF 文件复制到容器内并重新启动 Logstash 容器：

```java
docker cp pipleline/logstash.conf <logstash container id>:/usr/share/logstash/pipeline 
```

在复制`pipeline/logstash.conf`管道 CONF 文件后，请重新启动 Logstash 容器：

```java
input { 
  tcp { 
    port => 5001 
    codec => "json" 
  } 
} 

output { 
  elasticsearch { 
    hosts => "elasticsearch:9200" 
  } 
} 
```

# 将日志推送到 ELK 堆栈

我们已经完成了使 ELK 堆栈可供消费的工作。现在，Logstash 只需要一个可以被 Elasticsearch 索引的日志流。一旦创建了日志的 Elasticsearch 索引，就可以在 Kibana 仪表板上访问和处理日志。

为了将日志推送到 Logstash，我们需要在我们的服务代码中进行以下更改。我们需要在 OTRS 服务中添加 logback 和 logstash-logback 编码器依赖项。

在`pom.xml`文件中添加以下依赖项：

```java
... 
<dependency> 
    <groupId>net.logstash.logback</groupId> 
    <artifactId>logstash-logback-encoder</artifactId> 
    <version>4.6</version> 
</dependency> 
<dependency> 
    <groupId>ch.qos.logback</groupId> 
    <artifactId>logback-core</artifactId> 
    <version>1.1.9</version> 
</dependency> 
... 
```

我们还需要通过向`src/main/resources`添加`logback.xml`来配置 logback。

`logback.xml`文件将看起来像这样：

```java
<?xml version="1.0" encoding="UTF-8"?> 
<configuration debug="true"> 
    <appender name="stash" class="net.logstash.logback.appender.LogstashTcpSocketAppender"> 
        <destination>192.168.99.100:5001</destination> 
        <!-- encoder is required --> 
        <encoder class="net.logstash.logback.encoder.LogstashEncoder" /> 
        <keepAliveDuration>5 minutes</keepAliveDuration> 
    </appender> 
    <appender name="stdout" class="ch.qos.logback.core.ConsoleAppender"> 
        <encoder> 
            <pattern>%d{HH:mm:ss.SSS} [%thread, %X{X-B3-TraceId:-},%X{X-B3-SpanId:-}] %-5level %logger{36} - %msg%n</pattern> 
        </encoder> 
    </appender> 

    <property name="spring.application.name" value="nameOfService" scope="context"/> 

    <root level="INFO"> 
        <appender-ref ref="stash" /> 
        <appender-ref ref="stdout" /> 
    </root> 

    <shutdownHook class="ch.qos.logback.core.hook.DelayingShutdownHook"/> 
</configuration>
```

这里，目标是在`192.168.99.100:5001`上，那里托管 Logstash；根据您的配置，您可以进行更改。对于编码器，使用了`net.logstash.logback.encoder.LogstashEncoder`类。`spring.application.name`属性的值应设置为配置的服务。同样，添加了一个关闭钩子，以便在服务停止时，应释放和清理所有资源。

您希望在 ELK 堆栈可用后启动服务，以便服务可以将日志推送到 Logstash。

一旦 ELK 堆栈和服务启动，您可以检查 ELK 堆栈以查看日志。您希望在启动 ELK 堆栈后等待几分钟，然后访问以下 URL（根据您的配置替换 IP）。

为了检查 Elasticsearch 是否启动，请访问以下 URL：

```java
http://192.168.99.100:9200/  
```

为了检查是否已创建索引，请访问以下任一 URL：

```java
http://192.168.99.100:9200/_cat/indices?v 
http://192.168.99.100:9200/_aliases?pretty 
```

一旦完成了 Logstash 索引（您可能有一些服务端点来生成一些日志），请访问 Kibana：

```java
http://192.168.99.100:5601/ 
```

# ELK 堆栈实现的技巧

以下是一些实施 ELK 堆栈的有用技巧：

+   为了避免任何数据丢失并处理输入负载的突然激增，建议在 Logstash 和 Elasticsearch 之间使用如 Redis 或 RabbitMQ 之类的代理。

+   如果你使用集群，为 Elasticsearch 使用奇数个节点，以防止分脑问题。

+   在 Elasticsearch 中，总是为给定数据使用适当的字段类型。这将允许您执行不同的检查；例如，`int`字段类型将允许您执行`("http_status:<400")`或`("http_status:=200")`。同样，其他字段类型也允许您执行类似的检查。

# 为服务调用使用关联 ID

当你调用任何 REST 端点时，如果出现任何问题，很难追踪问题和其根本原因，因为每个调用都是对服务器的调用，这个调用可能调用另一个，依此类推。这使得很难弄清楚特定请求是如何转换的以及它调用了什么。通常，由一个服务引起的问题可能会在其他服务上产生连锁反应，或者可能导致其他服务操作失败。这很难追踪，可能需要巨大的努力。如果是单体结构，你知道你在正确的方向上，但是微服务使得难以理解问题的来源以及你应该获取数据的位置。

# 让我们看看我们如何解决这个问题

通过在所有调用中传递关联 ID，它允许您轻松跟踪每个请求和跟踪路由。每个请求都将有其唯一的关联 ID。因此，当我们调试任何问题时，关联 ID 是我们的起点。我们可以跟随它，在这个过程中，我们可以找出哪里出了问题。

关联 ID 需要一些额外的开发工作，但这是值得的努力，因为它在长远中帮助很大。当请求在不同微服务之间传递时，你将能够看到所有交互以及哪个服务存在问题。

这不是为微服务发明的新东西。这个模式已经被许多流行产品使用，例如微软 SharePoint。

# 使用 Zipkin 和 Sleuth 进行跟踪

对于 OTRS 应用程序，我们将利用 Zipkin 和 Sleuth 进行跟踪。它提供了跟踪 ID 和跨度 ID 以及一个漂亮的 UI 来跟踪请求。更重要的是，您可以在 Zipkin 中找到每个请求所花费的时间，并允许您深入挖掘以找出响应请求耗时最长的请求。

在下面的截图中，你可以看到餐厅`findById` API 调用所花费的时间以及同一请求的跟踪 ID。它还显示了跨度 ID：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/b2422251-7e3e-4319-947a-3d747347f8b8.png)

餐厅`findById` API 调用的总时间和跟踪 ID

我们将遵循以下步骤来配置 OTRS 服务中的 Zipkin 和 Sleuth。

你只需要向跟踪和请求跟踪中添加 Sleuth 和 Sleuth-Zipkin 依赖项：

```java
<dependency> 
    <groupId>org.springframework.cloud</groupId> 
    <artifactId>spring-cloud-starter-sleuth</artifactId> 
</dependency> 
<dependency> 
    <groupId>org.springframework.cloud</groupId> 
    <artifactId>spring-cloud-sleuth-zipkin</artifactId> 
</dependency> 
```

访问 Zipkin 仪表板，找出不同请求所花费的时间。如果默认端口已更改，请替换端口。请确保在使用 Zipkin 之前服务已经启动：

```java
http://<zipkin host name>:9411/zipkin/ 
```

现在，如果 ELK 栈已经配置并运行，那么你可以使用这个跟踪 ID 在 Kibana 中找到相应的日志，如下面的屏幕截图所示。Kibana 中有一个 X-B3-TraceId 字段，用于根据跟踪 ID 过滤日志：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/04a4d229-71fa-4d6d-97b5-0289e3e650cd.png)Kibana 仪表板 - 根据请求跟踪 ID 搜索

# 依赖关系和版本

在产品开发中，我们面临的两个常见问题是循环依赖和 API 版本。我们将讨论它们在微服务架构中的情况。

# 循环依赖及其影响

通常，单体架构有一个典型的层次模型，而微服务携带图模型。因此，微服务可能会有循环依赖。

因此，对微服务关系进行依赖检查是必要的。

让我们来看看以下两个案例：

+   如果你在你的微服务之间有一个依赖循环，当某个事务可能卡在循环中时，你的分布式栈可能会遇到溢出错误。例如，当一个人在预订餐厅的桌子时。在这种情况下，餐厅需要知道这个人（`findBookedUser`），而这个人需要知道在某个时间点的餐厅（`findBookedRestaurant`）。如果设计不当，这些服务可能会相互调用形成循环。结果可能是由 JVM 产生的栈溢出。

+   如果两个服务共享一个依赖项，而你以可能影响它们的方式更新那个其他服务的 API，你需要一次性更新所有三个。这会引发一些问题，比如你应该先更新哪一个？此外，你如何使这个过渡变得安全？

# 在设计系统时分析依赖关系

因此，在设计微服务时，确立不同服务之间的适当关系以避免任何循环依赖是非常重要的。

这是一个设计问题，必须加以解决，即使这需要对代码进行重构。

# 维护不同版本

当你拥有更多服务时，这意味着每个服务都有不同的发布周期，这通过引入不同版本的服务增加了这种复杂性，因为同样的 REST 服务会有不同的版本。当解决方案在一个版本中消失，在更高版本中回归时，重现问题将变得非常困难。

# 让我们进一步探索

API 的版本化很重要，因为随着时间的推移，API 会发生变化。你的知识和经验会随着时间而提高，这会导致 API 的变化。改变 API 可能会破坏现有的客户端集成。

因此，有许多方法可以管理 API 版本。其中一种方法是使用我们在本书中使用的路径版本；还有一些人使用 HTTP 头。HTTP 头可能是一个自定义请求头，或者您可以使用`Accept Header`来表示调用 API 的版本。有关如何使用 HTTP 头处理版本的信息，请参阅 Bhakti Mehta 著，Packt 出版社出版的*RESTful Java Patterns and Best Practices*： [`www.packtpub.com/application-development/restful-java-patterns-and-best-practices`](https://www.packtpub.com/application-development/restful-java-patterns-and-best-practices)。

在排查任何问题时，让微服务在日志中产生版本号非常重要。此外，理想情况下，您应该避免任何微服务版本过多的实例。

# 参考文献

以下链接将提供更多信息：

+   Elasticsearch: [`www.elastic.co/products/elasticsearch`](https://www.elastic.co/products/elasticsearch)

+   Logstash: [`www.elastic.co/products/logstash`](https://www.elastic.co/products/logstash)

+   Kibana: [`www.elastic.co/products/kibana`](https://www.elastic.co/products/kibana)

+   `willdurand/elk`：ELK Docker 镜像

+   *精通 Elasticsearch - 第二版*: [`www.packtpub.com/web-development/mastering-elasticsearch-second-edition`](https://www.packtpub.com/web-development/mastering-elasticsearch-second-edition)

# 总结

在本章中，我们探讨了 ELK 堆栈的概述和安装。在 ELK 堆栈中，Elasticsearch 用于存储来自 Kibana 的日志和服务查询。Logstash 是运行在您希望收集日志的每个服务器上的代理。Logstash 读取日志，过滤/转换它们，并将它们提供给 Elasticsearch。Kibana 从 Elasticsearch 中读取/查询数据，并以表格或图形可视化的形式呈现它们。

我们也非常理解在排查问题时拥有关联 ID 的实用性。在本章末尾，我们也发现了某些微服务设计的一些不足。由于在本书中涵盖所有与微服务相关的主题具有挑战性，因此我尽可能地包含尽可能多的相关信息，并配有精确的章节和参考文献，这使您能够进一步探索。现在，我希望让您开始在您的工作场所或个人项目中实施本章学到的概念。这不仅能为您提供实践经验，还可能使您掌握微服务。此外，您还将能够参加当地的技术聚会和会议。


# 第十一章：将单体应用迁移到基于微服务的应用

我们已经到了这本书的最后一章，我希望你已经享受并掌握了完整的微服务（除了数据库）开发。我试图涵盖所有必要的主题，为你提供一个微服务为基础的生产应用程序的全面视角，并允许你进行更多的探索。既然你已经了解了微服务架构和设计，你就可以很容易地区分单体应用和微服务应用，并识别出将单体应用迁移到微服务应用需要做的工作。

在本章中，我们将讨论将单体应用重构为基于微服务的应用。我假设一个现有的单体应用已经被部署并正在被客户使用。在本章结束时，你将了解可以将单体迁移到微服务的不同方法和策略。

本章涵盖以下主题：

+   你需要迁移吗？

+   成功迁移的方法和关键

# 你需要迁移吗？

这是你应该为你的迁移设定基调的第一个问题。你真的需要将现有的应用程序迁移到基于微服务的架构吗？它带来了哪些好处？后果是什么？我们如何支持现有的本地客户？现有客户是否支持并承担迁移到微服务的成本？我需要从头开始写代码吗？数据将如何迁移到新的基于微服务的系统？迁移的时间表是什么？现有团队是否有能力快速带来这种变化？我们是否可以接受在迁移期间的新功能变化？我们的流程是否能够适应迁移？等等。我相信你们脑海中会有很多类似的问题。我希望，从所有之前的章节中，你可能已经获得了关于微服务系统所需工作的良好知识。

在所有利弊之后，你的团队将决定迁移。如果答案是肯定的，本章将帮助你了解迁移的下一步。

# 云服务与本地部署，还是两者都提供？

你的现有产品是对云解决方案、本地解决方案，还是提供云和本地解决方案，或者你想开始提供云解决方案与本地解决方案。你的方法将基于你提供的解决方案类型。

# 仅限云解决方案

如果你提供云服务，那么你的迁移任务比其他两种解决方案要容易。话说回来，这并不意味着它会一帆风顺。你将完全控制迁移。你有权不考虑迁移对客户的直接影响。云客户只需使用解决方案，而不关心它是如何实现或托管的。我假设没有 API 或 SDK 的更改，显然，迁移不应涉及任何功能更改。仅在云上进行微服务迁移具有使用平稳渐进迁移的优势。这意味着你首先转换 UI 应用程序，然后是一个 API/服务，然后是下一个，依此类推。请注意，你掌控着局面。

# 仅本地服务解决方案

本地解决方案部署在客户的基础设施上。除此之外，你可能有许多客户在其基础设施上部署了不同版本的产品。你无法完全控制这些部署。你需要与客户合作，需要团队共同努力才能实现成功的迁移。

此外，在接触客户之前，你应该准备好一个完整的迁移解决方案。如果你的产品有不同版本，这会变得尤为困难。我建议只提供最新版本的迁移，而在你开发迁移时，只允许客户进行安全性和修补操作。是的，你不应该提供任何新功能。

# 云服务和本地服务

如果你的应用程序同时提供云服务和本地服务，那么将本地解决方案迁移到微服务可以与云服务同步进行，反之亦然。这意味着如果你在迁移一个方面付出了努力，你可以在另一个方面复制同样的成果。因此，除了之前提到的云或本地迁移挑战外，还需要在其他环境中进行复制。另外，有时本地客户可能有自己的定制化需求。在迁移时也需要考虑到这些需求。在这里，你应该首先将自有的云解决方案迁移到微服务，之后再复制到本地环境。

将生产/解决方案仅基于本地部署，但你想开始云部署；这是最具挑战性的。你预计要按照我的微服务设计迁移现有代码，同时确保它也支持现有的本地部署。有时，这可能是遗留技术堆栈，或者现有代码甚至可能是使用某些自有专有技术（如协议）编写的。现有设计可能不够灵活，无法拆分为微服务。这种迁移最具挑战性。应该逐步将本地解决方案迁移到微服务，首先分离 UI 应用程序并提供与 UI 应用程序交互的外部 API。如果 API 已经存在，或者你的应用程序已经分为独立的 UI 应用程序，相信我，这为迁移减轻了大量的负担。然后，你可以专注于迁移服务器端代码，包括为 UI 应用程序开发的 API。你可能会问为什么我们不能一起迁移所有 UI 应用程序、API 和服务器代码。是的，你可以这样做。但是，逐步迁移会给你带来确定性、信心和快速的失败/学习。毕竟，敏捷开发就是关于逐步开发。

如果你的现有代码不是模块化的，或者包含大量的遗留代码，那么我建议你首先重构它并使其模块化。这将使你的任务变得容易。说到这里，应该逐个模块进行。在将代码迁移到纯微服务之前，尽可能多地分解和重构代码。

我们将讨论一些方法，这些方法可能有助于你将大型复杂的单体应用程序重构为微服务。

# 成功迁移的方法和关键

软件现代化已经进行了很多年。为了成功进行软件现代化（迁移），已经做了大量工作。你会发现研究所有成功软件现代化的最佳实践和原则很有用。在本章中，我们将具体讨论微服务架构的软件现代化。

# 逐步迁移

你应该以渐进的方式将单体应用转换为微服务。你不应该一次性开始整个代码的全功能迁移。这会纠缠风险-回报比率并增加失败的可能性。它还增加了过渡时间（因此是成本）的可能性。你可能想将你的代码分成不同的模块，然后逐一开始转换每个模块。很可能你可能会想从头重新编写一些模块，如果现有代码紧密耦合且过于复杂难以重构，这就应该做。但是，从头开始编写完整的解决方案是大忌。你应该避免这样做。它增加了成本、迁移的时间以及失败的可能性。

# 过程自动化和工具设置

敏捷方法与微服务紧密合作。您可以使用任何敏捷过程，如 Scrum 和 Kanban，以及现代开发过程，如测试驱动开发或同行编程，进行增量开发。对于基于微服务的环境，流程自动化是必不可少的。您应该实施自动化的持续集成/持续部署和测试自动化。如果交付物的容器化还没有在 CI/CD 管道中完成，那么您应该去做。它使新开发的微服务能够与现有系统或其他新微服务成功集成。

在开始您的第一个微服务转型之前，您可能需要同时或先设置服务发现、服务网关、配置服务器或任何基于事件的系统。

# 试点项目

我在微服务迁移中观察到的另一个问题是，从一开始就完全不同模块的开发。理想情况下，一个小团队应该进行试点项目，将现有模块中的任何一个转换为微服务。一旦成功，相同的方法可以复制到其他模块。如果您同时开始各种模块的迁移，那么您可能在所有微服务中重复同样的错误。这增加了失败的风险和转型的持续时间。

成功迁移的团队提供了成功开发模块及其与现有单体应用程序集成的途径。如果您成功地一个接一个地将每个模块转换为微服务，那么在某个时候，您将拥有一个基于微服务的应用程序，而不是一个单体应用程序。

# 独立的用户界面应用程序

如果您已经有了消耗 API 的独立用户界面应用程序，那么您距离成功的迁移已经不远了。如果不是这样，这应该是第一步，将用户界面与服务器代码分离。UI 应用程序将消耗 API。如果现有应用程序没有应该被 UI 应用程序消耗的 API，那么您应该在现有代码之上编写包装 API。

请查看以下图表，反映 UI 应用程序迁移之前的呈现层：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/59d116bf-c7db-4216-9203-33f56b466a98.png)

在 UI 应用程序迁移之前

以下图表反映了 UI 应用程序迁移后的呈现层：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/56cc418e-1d2e-4987-be74-eb62894213fc.png)

UI 应用程序迁移后

您可以看到，以前，UI 被包含在单体应用程序中，与业务逻辑和 DAO 一起。迁移后，UI 应用程序从单体应用程序中分离出来，并使用 API 与服务器代码通信。REST 是实现 API 的标准，可以在现有代码之上编写。

# 将模块迁移到微服务

现在，你有一个服务器端的单体应用程序和一个或多个 UI 应用程序。这为你提供了另一个优势，即在分离模块的同时消费 API，从而分离现有的单体应用程序。例如，在分离 UI 应用程序后，你可能将其中一个模块转换为微服务。一旦 UI 应用程序成功测试，与该模块相关的 API 调用可以路由到新转换的模块，而不是现有的单体 API。如图所示，当调用 API `GET/customer/1` 时，网络`网关`可以将请求路由到`客户微服务`，而不是`单体`应用程序。

你还可以通过比较单体和微服务模块的响应，在将基于微服务的 API 上线之前，在生产环境中进行测试。一旦我们得到一致的匹配响应，我们可以确信转换已经成功完成，并且 API 调用可以迁移到重构模块的 API。如图所示，当调用客户 API 时，部署了一个组件，该组件会调用一个新的客户微服务。然后，它比较了两次调用的响应并存储结果。这些结果可以进行分析，并对任何不一致性进行修复。当新转换的微服务的响应与现有的单体响应相匹配时，你可以停止将调用路由到现有的单体应用程序，并用新的微服务替换它。

采用这种方法，你可以将模块一个接一个地迁移到微服务，并在某个时刻，你可以将所有的单体模块迁移到微服务。

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/237764f3-242b-43bc-8fb1-33eac8744c1c.png)

API 路由、比较和迁移

# 如何在迁移过程中容纳新功能

在迁移的理想场景中应避免添加新功能。只允许重要的修复和安全更改。然而，如果迫切需要实现一个新功能，那么它应该在一个单独的微服务中开发，或者以现有的单体代码模块化的方式开发，使其与现有代码的分离更容易。

例如，如果你确实需要在`客户`模块中添加一个新功能，而这个功能不依赖于其他模块，你只需创建一个新的客户微服务，并将其用于特定的 API 调用，无论是对外部世界还是通过其他模块。是否使用 REST 调用或事件进行进程间通信，由你自己决定。

同样，如果您需要一个具有依赖关系的新功能（例如，一个新客户功能依赖于预订功能）并且它没有被暴露为 UI 或服务 API 的 API，那么它仍然可以作为独立的微服务开发，如下面的图表所示。`customer`模块调用一个新开发的微服务，然后它调用`booking`模块进行请求处理，并将响应返回到`customer`模块。在这里，用于进程间通信的可以是 REST 或事件。

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-msvc-java9/img/2acbdfb7-53ea-4a58-8739-5c945ff95560.png)

实现一个新模块作为微服务，调用另一个模块

# 参考文献

阅读以下书籍以获取有关代码重构和领域驱动设计的更多信息：

+   《重构：改善现有代码的设计》马丁·福勒

+   《领域驱动设计》埃里克·J·埃文斯

# 总结

软件现代化是前进的道路，在当前环境中，因为一切都被迁移到云，以及资源力量和容量的增加方式，基于设计的微服务比其他任何东西都更合适。我们讨论了云和本地解决方案的组合以及将这些转换为微服务的挑战。

我们还讨论了为什么渐进式开发方法在单体应用迁移到微服务方面是首选。我们谈论了成功迁移到微服务所需的各种方法和实践。
