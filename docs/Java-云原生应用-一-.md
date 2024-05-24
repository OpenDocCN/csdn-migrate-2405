# Java 云原生应用（一）

> 原文：[`zh.annas-archive.org/md5/3AA62EAF8E1B76B168545ED8887A16CF`](https://zh.annas-archive.org/md5/3AA62EAF8E1B76B168545ED8887A16CF)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

在部署图中，使用云的形状来描述防火墙外的互联网。直到我读了尼古拉斯·G·卡尔的《大转变》之后，我才意识到云的全部潜力和即将到来的事情。快进 10 年，现在我们在绘制云形状围绕整个系统时不再犹豫，以描述云无处不在。云原生对初创公司来说是很自然的，但对许多企业来说，这仍然是一片未知的领域。只是进行搬迁并不是云的正确使用方式，尽管这可能是大多数大型公司为了减轻其数据中心的负担或避免租约延期而做的第一件事。云的力量在于我们能够构建基于云原生架构的业务关键应用程序，可以推动变革性价值。因此，我一直鼓励我的团队学习如何在云上设计和构建更智能的应用程序。

Munish、Ajay 和 Shyam 是核心团队的一部分，他们一直在研究和应用新兴技术，利用它们来解决业务问题。他们是企业数字化转型的领先专家和顾问，专注于使用微服务和新兴技术（如响应式框架、开源和容器技术（Docker 和 Kubernetes）等）的分布式系统。因此，我鼓励他们撰写这本书，以便让下一代开发人员能够快速启动他们的云原生应用程序之旅。

这本书采用了一种循序渐进的方法来理解、设计和编写云应用程序。作者带领你进行一次学习之旅，从概念开始，然后构建一个小型的 REST 服务，然后逐步增强服务以实现云原生。他们涵盖了云特定细微差别的各个方面，比如如何在分布式架构中发现服务以及服务发现工具所起的作用。您还将学习如何将应用程序迁移到公共云提供商——AWS 和 Azure。该书涵盖了 AWS Lamda 和 Cloud Functions 等无服务器计算模型。

我鼓励您充分利用这本书，引领您在云上应用开发之旅。

Hari Kishan Burle

副总裁兼全球架构服务负责人

Wipro 有限公司


# 第一章：贡献者

# 本书涵盖了什么

第一章，*云原生简介*，介绍了云原生应用程序的什么和为什么：是什么驱使应用程序转移到云端？为什么云开发和部署与常规应用程序不同？什么是 12 要素应用程序？

第二章，*编写您的第一个云原生应用程序*，介绍了使用微服务方法进行应用程序设计的核心概念。然后展示了一个样本的`product`服务，随着书中讨论的进行，它将被增强。您将学习如何使用 Spring Boot 进行微服务应用程序开发，并了解用于构建云原生应用程序的微服务原则。

第三章，*设计您的云原生应用程序*，涵盖了设计云原生应用程序时的一些高级架构考虑因素。它包括事件驱动架构、使用编排进行解耦，以及使用**领域驱动设计**（**DDD**）概念，如有界上下文。您将了解在云上开发和使用面向消费者友好的 API 来前端化应用程序的架构模式和考虑因素，而不是以系统为中心的服务定义。

第四章，*扩展您的云原生应用程序*，深入探讨了使用各种堆栈、原则和支持组件创建应用程序。它涵盖了在实现服务时的模式。本章重点介绍了差异化方面，如错误处理和**命令查询响应分离**（**CQRS**）和缓存等模式，这些模式对云开发有重大影响。

第五章，*测试云原生应用程序*，深入探讨了如何测试您的微服务以及如何使用**行为驱动开发**编写测试。

第六章，*云原生应用部署*，深入探讨了微服务的部署模型，包括如何将应用程序打包到 Docker 容器中，并设置 CI/CD 流水线。

第七章，*云原生应用程序运行时*，涵盖了服务的运行时方面。我们将介绍如何将配置外部化到配置服务器，并由 Zuul（Edge）前端化。我们将研究 Pivotal Cloud Foundry 并在 PCF Dev 上部署我们的服务。我们还将涵盖容器编排。

第八章，*平台部署 - AWS*，描述了 AWS 环境，并讨论了使用早期章节中讨论的概念（注册表、配置、日志聚合和异步消息传递）进行云开发的 AWS 特定工具。

第九章，*平台部署 - Azure*，描述了 Azure 环境，并讨论了用于进行云开发的 Azure 特定工具（包括 Service Fabric 和 Cloud Functions）。

第十章，*作为服务集成*，讨论了各种类型的 XaaS，包括 IaaS、PaaS、iPaaS 和 DBaaS，以及如何将基础设施元素暴露为服务。在云原生模式下，您的应用程序可能正在集成社交媒体 API 或 PaaS API，或者您可以托管其他应用程序将使用的服务。本章涵盖了如何连接/使用其他外部服务或提供此类服务。

第十一章，*API 设计最佳实践*，讨论了如何设计以消费者为中心的细粒度和功能导向的 API。它还讨论了 API 设计中的各种最佳实践，比如在 API 层级还是在服务中进行编排，如何创建 API 的免费版本，如何在 API 层面解决特定渠道的问题，以使服务保持渠道无关，以及 API 设计中的安全性方面。

第十二章，*数字化转型*，涵盖了云开发对企业现有格局的影响，以及如何实现转型迈向数字化企业。

# 关于作者

**Ajay Mahajan**是 Wipro Technologies 的杰出技术人员（DMTS），目前担任零售垂直领域的首席技术专家。在他目前的角色中，他帮助客户采用云原生和数字架构来开发下一代零售应用程序。他曾与欧洲和美国的零售和银行客户合作开发大规模的关键任务系统。在过去 19 年的 Java 平台工作中，他见证了企业 Java 从 Netscape 应用服务器到 servlets/JSP，JEE，Spring，以及现在的云和微服务的演变。

这本书中的许多想法、最佳实践和模式都源自我们在新兴技术领域的工作，该工作由 Aravind Ajad Yarra 领导。我特别感谢共同作者 Shyam，他是我遇到的最有才华的技术人员。特别感谢 Munish 对本书结构和内容的头脑风暴。我要感谢 Hari Burle，他的鼓励和指导帮助我专注于这本书。

**Munish Kumar Gupta**是 Visa 的首席系统架构师。他的日常工作涉及具有严格非功能性要求的应用程序解决方案架构、应用程序性能工程、应用程序基础设施管理，以及探索尖端开源技术在企业中的可采用性。他是*Akka Essentials*的作者。他对软件编程和工艺非常热衷。他在技术趋势、应用程序性能工程和 Akka 方面撰写博客。

我必须首先感谢我的妻子 Kompal。她督促我继续写作，现在我有了第二本书。感谢 Packt 团队的每个人对我的帮助。特别感谢 Zeeyan、Nitin 和 Romy。

**Shyam Sundar**是 Wipro Technologies 位于班加罗尔的高级架构师。他是 Wipro 新兴技术架构组的一员。他负责帮助团队在项目中采用新兴技术。他主要关注客户端和云技术。他是一个终身学习者，非常关心软件工艺。他不断尝试新的工具和技术，以改善开发体验。

我首先要感谢我的共同作者 Ajay 和 Munish，让我与他们一起踏上这不可思议的旅程。作为一个更习惯于用代码而不是文字表达自己的人，Ajay 和 Munish 给了我很多关于如何构建内容和简化概念的深思熟虑的建议。我还必须感谢我的老板 Aravind Ajad Yarra，他一直支持和鼓励我。

# 关于审阅者

Andreas Olsson 是 Java 和 Spring 培训师，专门从事云原生解决方案。他自 2001 年以来一直是 Java 开发人员，并于 2004 年开始使用 Spring。在设计应用程序架构时，他通常会在 Spring 生态系统中找到解决方案。2011 年，云原生平台开始出现时，他成立了自己的公司，自那时起一直是云原生的爱好者。Andreas 居住在瑞典，目前在国际上担任培训师。他是一名经过认证的 Java 和 Spring 专业人员，非常喜欢每天学习新东西。

# Packt 正在寻找像您这样的作者

如果您有兴趣成为 Packt 的作者，请访问[authors.packtpub.com](http://authors.packtpub.com)并立即申请。我们已经与成千上万的开发人员和技术专业人士合作，就像您一样，帮助他们与全球技术社区分享见解。您可以进行一般申请，申请我们正在招聘作者的特定热门主题，或者提交您自己的想法。

# 目录

1.  标题页

1.  版权和鸣谢

1.  Java 中的云原生应用程序

1.  致谢

1.  Packt 升级

1.  为什么订阅？

1.  PacktPub.com

1.  前言

1.  贡献者

1.  关于作者

1.  关于审阅者

1.  Packt 正在寻找像您这样的作者

1.  前言

1.  这本书是为谁准备的

1.  本书涵盖了什么

1.  充分利用本书

1.  下载示例代码文件

1.  下载彩色图像

1.  使用的约定

1.  联系我们

1.  评论

1.  云原生简介

1.  为什么选择云原生？

1.  什么是云原生？

1.  提升和转移

1.  本地化

1.  无服务器化

1.  云原生和微服务

1.  12 要素应用程序

1.  微服务启用服务生态系统

1.  微服务采用

1.  单体转换

1.  总结

1.  编写您的第一个云原生应用程序

1.  设置您的开发人员工具箱

1.  获取 IDE

1.  设置互联网连接

1.  了解开发生命周期

1.  要求/用户故事

1.  架构

1.  设计

1.  测试和开发

1.  构建和部署

1.  选择框架

1.  Dropwizard

1.  Vert.x

1.  Spring Boot

1.  编写产品服务

1.  创建 Maven 项目

1.  编写 Spring Boot 应用程序类

1.  编写服务和域对象

1.  运行服务

1.  在浏览器上测试服务

1.  创建可部署的

1.  启用云原生行为

1.  外部配置

1.  计量您的服务

1.  服务注册和发现

1.  运行服务注册表

1.  注册产品服务

1.  创建产品客户端

1.  看查找操作

1.  总结

1.  设计您的云原生应用程序

1.  三重奏 - REST、HTTP 和 JSON

1.  API 的崛起和流行

1.  API 网关的作用

1.  API 网关的好处

1.  应用程序解耦

1.  有界上下文/领域驱动设计

1.  分类为上游/下游服务

1.  业务事件

1.  微服务识别

1.  微服务和面向服务的架构（SOA）之间的区别

1.  服务粒度

1.  微服务设计准则

1.  设计和部署模式

1.  设计模式

1.  内容聚合模式

1.  客户端聚合

1.  API 聚合

1.  微服务聚合

1.  数据库聚合

1.  协调模式

1.  业务流程管理（BPM）

1.  复合服务

1.  为什么要使用复合服务？

1.  微服务协调的能力

1.  协调模型

1.  异步并行

1.  异步顺序

1.  使用请求/响应进行编排

1.  折叠微服务

1.  部署模式

1.  WAR 文件中的多个服务

1.  利弊

1.  适用性

1.  每个 WAR/EAR 服务

1.  利弊

1.  适用性

1.  每个进程的服务

1.  利弊

1.  适用性

1.  每个 Docker 容器的服务

1.  利弊

1.  适用性

1.  每个 VM 的服务

1.  利弊

1.  适用性

1.  每个主机的服务

1.  利弊

1.  适用性

1.  发布模式

1.  微服务的数据架构

1.  命令查询责任分离（CQRS）

1.  复制数据

1.  好处

1.  缺点

1.  适合目的

1.  安全的作用

1.  摘要

1.  扩展您的云原生应用程序

1.  实施获取服务

1.  简单的产品表

1.  运行服务

1.  传统数据库的局限性

1.  缓存

1.  本地缓存

1.  在幕后

1.  本地缓存的局限性

1.  分布式缓存

1.  应用 CQRS 以分离数据模型和服务

1.  关系数据库上的物化视图

1.  Elasticsearch 和文档数据库

1.  为什么不仅使用文档数据库或 Elasticsearch？

1.  核心产品服务在文档数据库上

1.  准备好使用测试数据的 MongoDB

1.  创建产品服务

1.  拆分服务

1.  产品搜索服务

1.  准备好使用测试数据的 Elasticsearch

1.  创建产品搜索服务

1.  数据更新服务

1.  REST 约定

1.  插入产品

1.  测试

1.  更新产品

1.  测试

1.  删除产品

1.  测试

1.  缓存失效

1.  验证和错误消息

1.  格式验证

1.  数据验证

1.  业务验证

1.  异常和错误消息

1.  CQRS 的数据更新

1.  异步消息传递

1.  启动 ActiveMQ

1.  创建主题

1.  Golden source update

1.  服务方法

1.  数据更新时触发事件

1.  使用 Spring JMSTemplate 发送消息

1.  查询模型更新

1.  插入、更新和删除方法

1.  端到端测试 CQRS 更新场景

1.  摘要

1.  测试云原生应用

1.  在开发之前编写测试用例

1.  TDD

1.  BDD

1.  测试模式

1.  A/B 测试

1.  测试替身

1.  测试存根

1.  模拟对象

1.  模拟 API

1.  测试类型

1.  单元测试

1.  集成测试

1.  负载测试

1.  回归测试

1.  确保代码审查和覆盖率

1.  测试产品服务

1.  通过 Cucumber 进行 BDD

1.  为什么选择 Cucumber?

1.  Cucumber 是如何工作的？

1.  Spring Boot 测试

1.  使用 JaCoCo 进行代码覆盖

1.  集成 JaCoCo

1.  摘要

1.  云原生应用部署

1.  部署模型

1.  虚拟化

1.  PaaS

1.  容器

1.  Docker

1.  构建 Docker 镜像

1.  Eureka 服务器

1.  产品 API

1.  连接到外部的 Postgres 容器

1.  部署模式

1.  蓝绿部署

1.  金丝雀部署

1.  暗部署

1.  应用 CI/CD 进行自动化

1.  摘要

1.  云原生应用运行时

1.  运行时的需求

1.  实现运行时参考架构

1.  服务注册表

1.  配置服务器

1.  配置服务器的服务器部分

1.  配置客户端

1.  刷新属性

1.  微服务前端

1.  Netflix Zuul

1.  幕后发生了什么

1.  同时运行它们

1.  Kubernetes - 容器编排

1.  Kubernetes 架构和服务

1.  Minikube

1.  在 Kubernetes 中运行产品服务

1.  平台即服务（PaaS）

1.  PaaS 的案例

1.  Cloud Foundry

1.  组织、账户和空间的概念

1.  Cloud Foundry 实现的需求

1.  Pivotal Cloud Foundry (PCF)

1.  PCF 组件

1.  PCF Dev

1.  安装

1.  启动 PCF Dev

1.  在 PCF 上创建 MySQL 服务

1.  在 PCF Dev 上运行产品服务

1.  部署到 Cloud Foundry

1.  摘要

1.  平台部署 - AWS

1.  AWS 平台

1.  AWS 平台部署选项

1.  将 Spring Boot API 部署到 Beanstalk

1.  部署可运行的 JAR

1.  部署 Docker 容器

1.  将 Spring Boot 应用程序部署到弹性容器服务

1.  部署到 AWS Lambda

1.  摘要

1.  平台部署 - Azure

1.  Azure 平台

1.  Azure 平台部署选项

1.  将 Spring Boot API 部署到 Azure App Service

1.  将 Docker 容器部署到 Azure 容器服务

1.  将 Spring Boot API 部署到 Azure Service Fabric

1.  基本环境设置

1.  打包产品 API 应用程序

1.  启动 Service Fabric 集群

1.  将产品 API 应用程序部署到 Service Fabric 集群

1.  连接到本地集群

1.  连接到 Service Fabric party 集群

1.  Azure 云函数

1.  环境设置

1.  创建新的 Java 函数项目

1.  构建和运行 Java 函数

1.  深入代码

1.  摘要

1.  作为服务集成

1.  XaaS

1.  构建 XaaS 时的关键设计问题

1.  与第三方 API 集成

1.  摘要

1.  API 设计最佳实践

1.  API 设计关注点

1.  API 资源识别

1.  系统 API

1.  过程 API

1.  通道 API

1.  API 设计指南

1.  命名和关联

1.  资源的基本 URL

1.  处理错误

1.  版本控制

1.  分页

1.  属性

1.  数据格式

1.  客户端支持有限的 HTTP 方法

1.  身份验证和授权

1.  端点重定向

1.  内容协商

1.  安全

1.  API 建模

1.  开放 API

1.  RESTful API 建模语言（RAML）

1.  API 网关部署模型

1.  摘要

1.  数字转型

1.  应用程序组合理性化

1.  投资组合分析 - 业务和技术参数

1.  退休

1.  保留

1.  巩固

1.  转换

1.  单体应用转换为分布式云原生应用

1.  将单体应用转换为分布式应用

1.  客户旅程映射到领域驱动设计

1.  定义架构跑道

1.  开发者构建

1.  打破单体应用

1.  将所有内容整合在一起

1.  构建自己的平台服务（控制与委托）

1.  摘要

1.  您可能喜欢的其他书籍

1.  留下评论-让其他读者知道您的想法


# 第二章：云原生简介

云计算的出现和移动设备的普及导致了消费者面向公司（如亚马逊、Netflix、优步、谷歌和 Airbnb）的崛起，它们重新定义了整个客户体验。这些公司在云上构建了它们的应用程序（包括 Web 和移动界面），利用功能或服务，使它们能够根据需求进行扩展或缩减，随时可用，并准备好处理各个层面的故障。

传统企业正在关注这些面向消费者的公司，并希望采纳它们的一些最佳实践。他们这样做是为了帮助扩展他们快速发展的企业应用程序，使它们能够利用云的弹性和可伸缩性。

在我们深入了解云原生之前，让我们看看这一章节包含什么。本章将涵盖以下主题：

+   为什么要采用云原生？

+   什么是云原生？

+   12 要素应用简介

+   为什么要从单片应用迁移到基于分布式微服务的应用程序？

+   构建基于分布式微服务的应用程序的优势

# 为什么要采用云原生？

让我们看看以下几点，以了解为什么我们需要采用云原生：

+   云采用的第一波浪潮是关于成本节约和业务敏捷性（特别是基础设施供应和廉价存储）。随着云的不断普及，企业开始发现基础设施即服务（IaaS）和平台即服务（PaaS）服务以及它们在构建应用程序中的利用，这些应用程序利用了云的弹性和可伸缩性，同时接受了云平台固有的故障。

+   许多企业正在数字化倡议领域采用绿地设计和微服务的开发。在处理物联网（IoT）、移动设备、SaaS 集成和在线业务模式时，企业正在与市场上的利基玩家合作。这些新时代的商业模式被设计和开发为企业端的创新系统。这些模型被迅速迭代，以识别和挖掘客户的需求、他们的偏好、什么有效，什么无效。

+   企业还在基于其产品线开发数字服务。产品通过物联网得到增强，使其能够发出有关产品性能的数据。这些数据被汇总和分析，以发现预测性维护、使用模式和外部因素等模式。来自客户的数据被汇总和聚合，以构建产品增强和新功能的新模型。许多这些新数字服务使用云原生模型。

+   这些现代数字解决方案使用来自各种提供商的 API，例如用于位置的谷歌地图，用于身份验证的 Facebook/谷歌，以及用于社交协作的 Facebook/Twitter。将所有这些 API 与企业业务的功能和功能结合起来，使它们能够为客户构建独特的建议。所有这些集成都是在 API 级别进行的。移动应用程序不是为数十亿用户而设计的，而是为数百万用户而设计的。这意味着随着负载的增加，底层应用程序功能应该能够扩展，以为客户提供无缝的体验。

+   企业扩展资源的一种方式是在负载增加或出现故障时进行服务/环境供应的繁重工作。另一种方式是将底层服务的繁重工作转移到云平台提供商。这是构建云原生应用程序的甜蜜点，利用云提供商的平台服务使企业能够卸载可伸缩性的关键方面，并专注于价值生成部分。

# 什么是云原生？

当应用程序被设计和架构以利用云计算平台支持的基础 IaaS 和 PaaS 服务时，它们被称为云原生应用。

这意味着构建可靠的系统应用，如五个九（99.999%），在三个九（99.9%）的基础设施和应用组件上运行。我们需要设计我们的应用组件来处理故障。为了处理这样的故障，我们需要一个结构化的可扩展性和可用性方法。为了支持应用程序的整个规模，所有部分都需要自动化。

云采用通常是一系列步骤，企业在开始构建云原生应用之前开始探索服务。采用始于将 Dev/Test 环境迁移到云中，业务和开发人员社区对快速配置是关键需求。一旦企业度过环境配置阶段，下一步/模型是企业应用迁移到云原生模型，将在以下部分讨论。

# 举起和转移

传统上，企业开始其云计算之旅是通过 IaaS 服务。他们将业务应用工作负载从本地数据中心转移到云计算平台上的相应租用容量。这是云计算平台采用的第一波浪潮，企业从资本支出模式转变为运营支出模式。

IaaS，顾名思义，专注于基础设施——计算节点、网络和存储。在这种模式下，企业可以利用云的弹性，根据需求或负载来增加或减少计算节点。虚拟机（VM）抽象出底层硬件，并提供了通过几次点击来扩展或缩减 VM 数量的能力。

企业通常在第一波浪潮中使用 IaaS，原因如下：

+   资源的可变性：随意添加/删除资源的能力，从而实现更多的业务敏捷性

+   实用模型：IaaS 提供按小时租用的基本资源，更具可预测性和运营支出模式

# 原生应用

一旦企业开始对 IaaS 感到满意，下一波采用的浪潮就是采用 PaaS 作为应用工作负载的一部分。在这个阶段，企业开始发现具有以下好处的服务：

+   平台服务替换：这涉及识别企业的潜在平台特性，举起和转移工作负载，并用云提供商的等效平台服务替换。例如：

+   用云提供商提供的排队系统（如 AWS SQS）替换应用消息系统

+   用等效的托管数据服务（如 AWS RDS）替换数据存储或关系数据库管理系统（RDMBS）

+   用托管目录或安全服务（如 AWS Directory 和 AWS IAM）替换安全或目录服务

+   这些服务使企业摆脱所有运营工作，如数据存储备份、可用性、可扩展性和冗余，并用提供所有这些功能的托管服务替换它们

+   应用服务替换：企业发现可以替换其自有平台或实用服务的新服务。例如：

+   用云提供商的等效 DevOps 服务（如 AWS CodePipeline、AWS CodeCommit 或 AWS CodeDeploy）替换构建和发布服务或产品

+   用等效的应用平台服务（如 AWS API Gateway、AWS SWF 和 AWS SES）替换应用服务或产品

+   用等效的应用分析服务（如 AWS Data Pipeline 和 AWS EMR）替换分析工作负载服务

一旦应用程序开始采用平台服务，应用程序开始抽象出**商业现成**（**COTS**）产品提供的功能或功能（如消息传递、通知、安全、工作流和 API 网关），并用等效的功能平台服务替换它们。例如，不再托管和运行消息传递 IaaS，转向等效的平台服务意味着转向一种模式，您只支付发送的消息数量，而不会产生任何额外的运营成本。这种模式带来了显著的节省，因为您从租用和运营产品转向了仅在利用时租用产品的模式。

# 走向无服务器

一旦企业采用 PaaS 构建应用程序，下一步就是将应用程序逻辑抽象为一系列较小的函数并部署它们。这些函数作为对用户或代理的事件的反应而被调用，这导致这些函数计算传入的事件并返回结果。这是最高级别的抽象，应用程序已被划分为一系列函数，这些函数独立部署。这些函数使用异步通信模型相互通信。云计算平台提供了 AWS Lambda 和 Azure Functions 等功能，用于实现无服务器化。

# 云原生和微服务

为了实现 IaaS 和 PaaS 服务的采用，需要对应用程序的设计和架构进行改变。

在基础平台（即：应用服务器）上设计企业应用程序的模式意味着应用程序的可伸缩性和可用性的重要工作是平台的责任。企业开发人员将专注于使用标准化的 JEE 模式和开发组件（展示、业务、数据和集成）来构建完全功能和事务性的应用程序。应用程序的可伸缩性受到底层平台能力（节点集群和分布式缓存）的限制：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/f53ab4c9-06ae-4c48-b412-f2b2da4d6fe1.png)

单片应用程序

作为单片应用程序构建的业务应用程序通常具有以下特征：

+   整个应用程序逻辑被打包成一个单独的 EAR 文件

+   应用程序的重用是通过共享 JAR 文件实现的

+   应用程序的更改通常提前数月计划，通常是每个季度进行一次大规模推动

+   有一个数据库包含了整个应用程序的架构

+   有成千上万的测试用例表示回归的数量

+   应用程序的设计、开发和部署需要多个团队之间的协调和重大的管理

随着社交互动和移动用户的出现，应用程序用户和数据的规模开始呈指数级增长。企业很快发现，平台在以下问题方面成为了瓶颈：

+   **业务敏捷性**：由于应用程序的单片结构，管理应用程序平台和不断更改功能/功能的运营成本受到了阻碍。即使是一个小的功能更改，整个回归测试和在服务器集群上的部署周期也在影响创新的整体速度。

移动革命意味着问题不仅仅存在于渠道层，而且还渗透到集成和记录系统层。除非企业跨越这些层面解决问题，否则在市场上创新和竞争的能力将受到威胁。

+   **成本**：为了满足增加的需求，IT 运营团队不断添加新的服务器实例来处理负载。然而，随着每个新实例的增加，复杂性和许可成本（取决于核心数）也在增加。与世界上的 Facebook 不同，企业每用户成本随着每个用户的获取而增加。

此时，企业开始关注开源产品以及消费者面向公司如何构建现代应用程序，为数百万用户提供服务，处理 PB 级数据，并部署到云端。

面向消费者的公司在其生命周期的早期就遇到了这些障碍。大量的创新导致了新的开源产品的设计和开发，以及云计算的设计模式。

在这种情况下，**面向服务的架构**（SOA）的整个前提被重新审视，企业调查了应用架构如何采用设计自治服务的原则，这些服务是隔离的、离散的，并且可以与其他服务集成和组合。这导致了微服务模型的兴起，它与云服务模型非常适配和整合，其中一切都作为服务和 HTTP 端点可用。

微服务是用于构建灵活、可独立部署的软件系统的面向服务架构（SOA）的专业化和实现方法

- 维基百科

微服务是设计和开发的，考虑到一个业务应用可以通过组合这些服务来构建。微服务围绕以下原则设计：

+   **单一责任原则**：每个微服务只实现有界域上下文中的一个业务责任。从软件角度来看，系统需要分解为多个组件，其中每个组件都成为一个微服务。微服务必须轻量级，以便实现更小的内存占用和更快的启动时间。

+   **无共享**：微服务是自治的、自包含的、无状态的，并通过基于容器的封装模型管理服务状态（内存/存储）。私有数据由一个服务管理，没有其他服务对数据的争用。无状态的微服务比有状态的微服务更容易扩展和启动更快，因为在关闭时没有状态需要备份或在启动时激活。

+   **反应式**：这适用于具有并发负载或较长响应时间的微服务。异步通信和回调模型允许资源的最佳利用，从而提高微服务的可用性和吞吐量。

+   **外部化配置**：这将配置外部化到配置服务器中，以便可以按环境维护它们的分层结构。

+   **一致性**：服务应该按照编码标准和命名约定指南以一致的风格编写。

+   **韧性**：服务应该处理由技术原因（连接和运行时）和业务原因（无效输入）引起的异常，并且不会崩溃。诸如断路器和批量标头之类的模式有助于隔离和遏制故障。

+   **良好的公民**：微服务应通过 JMX API 或 HTTP API 报告它们的使用统计信息，它们被访问的次数，它们的平均响应时间等。

+   **版本化**：微服务可能需要支持不同客户的多个版本，直到所有客户迁移到更高版本。在支持新功能和修复错误方面，应该有明确的版本策略。

+   **独立部署**：每个微服务都应该可以独立部署，而不会损害应用程序的完整性：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/72b4e6bd-7d1f-4014-a53a-d6901cb5c139.png)

从单片到基于微服务的应用程序的转变

微服务的设计、开发和部署考虑在后续章节中详细介绍。我们将看到如何为电子商务产品构建服务。我相信每个人都对电子商务非常熟悉，并且会很容易理解产品需求。

# 12 要素应用

为了构建一个可以在云提供商之间部署的分布式、基于微服务的应用程序，Heroku 的工程师提出了需要由任何现代云原生应用程序实施的 12 个因素：

+   **单一代码库**：应用程序必须有一个代码库，每个应用程序（即：微服务）都可以在多个环境（开发、测试、暂存和生产环境）中部署。两个微服务不共享相同的代码库。这种模式允许灵活更改和部署服务，而不会影响应用程序的其他部分。

+   **依赖关系**：应用程序必须明确声明其代码依赖关系，并将它们添加到应用程序或微服务中。这些依赖关系被打包为微服务 JAR/WAR 文件的一部分。这有助于隔离微服务之间的依赖关系，并减少同一 JAR 的多个版本带来的任何副作用。

+   **配置**：应用程序配置数据被移出应用程序或微服务，并通过配置管理工具进行外部化。应用程序或微服务将根据其运行的环境选择配置，从而允许相同的部署单元在各个环境中传播。

+   **后备服务**：所有外部资源访问都应该是可寻址的 URL。例如，SMTP URL、数据库 URL、服务 HTTP URL、队列 URL 和 TCP URL。这允许 URL 被外部化到配置中，并为每个环境进行管理。

+   **构建、发布和运行**：整个构建、发布和运行过程被视为三个独立的步骤。这意味着作为构建的一部分，应用程序被构建为一个不可变的实体。这个不可变的实体将根据环境（开发、测试、暂存或生产）选择相关的配置来运行进程。

+   **进程**：微服务建立在并遵循共享无状态模型。这意味着服务是无状态的，状态被外部化到缓存或数据存储中。这允许无缝扩展，并允许负载均衡或代理将请求发送到服务的任何实例。

+   **端口绑定**：微服务是在容器内构建的。服务将通过端口（包括 HTTP）导出和绑定所有其接口。

+   **并发性**：微服务进程是按比例扩展的，这意味着为了处理增加的流量，会向环境中添加更多的微服务进程。在微服务进程内部，可以利用反应式模型来优化资源利用率。

+   **可处置性**：构建微服务的想法是将其作为不可变的，具有单一职责，以最大程度地提高鲁棒性和更快的启动时间。不可变性也有助于服务的可处置性。

+   **开发/生产一致性**：应用程序生命周期中的环境（DEV、TEST、STAGING 和 PROD）尽量保持相似，以避免后续出现任何意外。

+   **日志**：在不可变的微服务实例中，作为服务处理的一部分生成的日志是状态的候选者。这些日志应被视为事件流，并推送到日志聚合基础设施。

+   **管理进程**：微服务实例是长时间运行的进程，除非它们被终止或替换为更新版本。所有其他管理和管理任务都被视为一次性进程：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/19bbfa55-0a53-4117-8985-c5c180400105.png)

12 要素应用

遵循 12 要素的应用程序不对外部环境做任何假设，这使它们可以部署在任何云提供商平台上。这允许在各种环境中运行相同的工具/流程/脚本，并以一致的方式部署分布式微服务应用程序。

# 微服务启用的服务生态系统

为了成功运行微服务，需要一些必要的启用组件/服务。这些启用服务可以被标记为 PaaS，用于支持微服务的构建、发布、部署和运行。

在云原生模型的情况下，这些服务可以作为云提供商自身的 PaaS 服务提供：

+   **服务发现**：当应用程序被分解为微服务模型时，一个典型的应用程序可能由数百个微服务组成。每个微服务运行多个实例，很快就会有成千上万个微服务实例在运行。为了发现服务端点，有必要有一个可以查询的服务注册表，以发现所有微服务实例。此外，服务注册表跟踪每个服务实例的心跳，以确保所有服务都正常运行。

此外，服务注册表有助于在服务实例之间实现负载均衡请求。我们可以有两种负载均衡模型：

+   客户端负载均衡：

+   服务消费者向注册表请求服务实例

+   服务注册表返回服务运行的服务列表

+   服务器端负载均衡：

+   服务端点被 Nginx、API 网关或其他反向代理隐藏

这个领域的典型产品有 Consul 和 Zookeeper：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/66a2ed6f-2799-421e-9bcf-2a56a9b53a21.png)

服务注册表

+   **配置服务器**：微服务需要用多个参数初始化（例如，数据库 URL、队列 URL、功能参数和依赖标志）。在文件或环境变量中管理超过一定数量的属性可能变得难以控制。为了跨环境管理这些属性，所有这些配置都在配置服务器上进行外部管理。在启动时，微服务将通过调用配置服务器上的 API 加载属性。

微服务还使用监听器来监听配置服务器上属性的任何更改。微服务可以立即捕获属性的运行时更改。这些属性通常被分类为多个级别：

+   **特定于服务的属性**：保存与微服务相关的所有属性

+   **共享属性**：保存可能在服务之间共享的属性

+   **公共属性**：保存在服务之间共同的属性

配置服务器可以将这些属性备份到源代码控制系统中。这个领域的典型产品有 Consul、Netflix Archaius 和 Spring Cloud Config 服务器：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/f4fd4652-eb3e-4dcb-b7bc-e1f3bf68b0b7.png)

配置服务器

+   **服务管理/监控**：一个普通的业务应用程序通常会被分解成大约 400 个微服务。即使我们运行了两到三个实例的这些微服务，我们也将需要管理超过 1,000 个微服务实例。如果没有自动化模型，管理/监控这些服务将成为一个运营挑战。以下是需要被管理和监控的关键指标：

+   **服务健康**：每个服务都需要发布其健康状态。这些需要被管理/跟踪以识别慢或死亡的服务。

+   **服务指标**：每个服务还发布吞吐量指标数据，如 HTTP 请求/响应的数量、请求/响应大小和响应延迟。

+   **进程信息**：每个服务将发布 JVM 指标数据（如堆利用率、线程数和进程状态），通常作为 Java VisualVM 的一部分。

+   **作为流记录事件**：每个服务也可以将日志事件发布为一组流事件。

所有这些信息都是从服务中提取出来的，并结合在一起来管理和监控应用服务的景观。需要进行两种类型的分析——事件相关性和纠正决策。警报和执行服务是作为服务监控系统的一部分构建的。例如，如果需要维护一定数量的服务实例，而数量减少（由于健康检查导致服务不可用），那么执行服务可以将该事件视为添加另一个相同服务实例的指示器。

此外，为了跟踪服务调用流程通过微服务模型，有第三方软件可用于帮助创建请求标识并跟踪服务调用如何通过微服务流动。这种软件通常会将代理部署到容器上，将它们编织到服务中并跟踪服务指标：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/38d5af25-d188-4fc3-8b4d-c7bb2f3e5f65.png)

服务指标

+   **容器管理/编排**：微服务环境的另一个关键基础设施部分是容器管理和编排。服务通常打包在容器中，并部署在 PaaS 环境中。环境可以基于 OpenShift 模型、Cloud Foundry 模型或纯 VM 模型，具体取决于它们是部署在私有云还是公共云上。为了部署和管理容器之间的依赖关系，需要容器管理和编排软件。通常，它应该能够理解容器之间的相互依赖关系，并将容器部署为一个应用程序。例如，如果应用程序有四个部分——一个用于 UI，两个用于业务服务，一个用于数据存储——那么所有这些容器应该被标记在一起，并作为一个单元部署，注入相互依赖和正确的实例化顺序。

+   **日志聚合**：12 个因素之一是将日志视为事件流。容器应该是无状态的。日志语句通常是需要在容器的生命周期之外持久化的有状态事件。因此，来自容器的所有日志都被视为可以推送/拉取到集中日志存储库的事件流。所有日志都被聚合，可以对这些日志运行各种模型以获取各种警报。人们可以通过这些日志跟踪安全和故障事件，这些事件可以反馈到服务管理/监控系统以进行进一步的操作：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/0f67dc59-ae15-4183-bdf8-04f99e7c4aea.png)

日志聚合

+   **API 网关/管理**：服务应该是简单的，并遵循单一责任模型。问题是：谁来处理其他关注点，比如服务认证、服务计量、服务限流、服务负载平衡和服务免费/付费模型？这就是 API 网关或管理软件出现的地方。API 网关代表微服务处理所有这些关注点。API 网关提供了多种管理服务端点的选项，还可以提供转换、路由和调解能力。与典型的企业服务总线相比，API 网关更轻量级。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/fbc8c9bf-8bcc-4edd-844e-7b39dff07a53.png)

API 管理网关

+   **DevOps**：另一个关键方面是持续集成/部署管道，以及需要设置基于微服务的应用程序的自动化操作。开发人员编写代码时，它经历一系列需要自动化的步骤，并与门控标准进行映射，以允许发布经过回归测试的代码：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/91ab3f51-789e-4385-9251-8e3c182239cc.png)

开发生命周期

# 微服务采用

企业内的微服务采用受到数字转型的共同主题的推动，无论他们是要重新架构现有的单片应用程序以增加业务敏捷性和减少技术债务，还是要开发允许他们快速创新和尝试不同业务模式的全新应用程序。

# 整体转型

企业一直在运行基于 JEE 原则构建的通道应用程序，运行在应用服务器集群上。这些应用程序多年来积累了大量技术债务，并成为一个主要问题——庞大、笨重，难以不断变化。

随着商业环境竞争的加剧和渠道的增加，企业正在寻求更快的创新，并提供无缝的客户体验。另一方面，他们不希望放弃现有应用程序的投资。

在这种情况下，企业正在进行多个项目，将现有应用程序重构和重新架构为现代、分布式、基于微服务的模型，以提供快速迭代的货币化，并具有未来的保障。

企业正在以双管齐下的方式解决这个问题：

1.  建立提供核心生态系统作为一组服务来部署和运行微服务的基础平台。这些服务包括配置管理、服务发现、弹性计算、容器管理、安全、管理和监控、DevOps 管道等。企业通常在使用公共云和建立私有云之间权衡。云平台的选择取决于所涉及的行业和企业战略的成熟度。

1.  第二种方法是逐步削减整体应用程序，一次一个功能模块，将核心业务逻辑迁移到微服务模型。GUI 部分则单独迁移到使用 AngularJS 和 ReactJS 等框架的 SPA 模型。例如，许多电子商务企业已将其目录和搜索服务迁移到弹性云提供商。只有当客户点击结账时，他们才将客户带到内部数据中心。

一旦企业建立了关于平台服务的生态系统，增加更多基于微服务的功能变得容易，为业务敏捷性和创新提供所需的推动力。

我们将在第十二章中更详细地介绍数字转型，“数字转型”。

# 摘要

在本章中，我们介绍了什么是云原生编程以及为什么要选择它。我们看到了企业在云原生应用方面的各种采用模型。我们介绍了分布式应用的 12 个因素，以及微服务设计在云原生启用中的使用。我们介绍了构建基于微服务的应用程序的启用生态系统。

随着我们在本书中的进展，我们将介绍如何设计，构建和运行您的云原生应用程序。我们还将介绍使用两个云提供商平台（AWS 和 Azure）进行云原生应用程序开发。我们将利用它们的平台服务来构建云原生应用程序。

我们还将介绍云原生应用程序的运营方面——DevOps、部署、监控和管理。最后，我们将介绍如何将现有的单片应用程序转变为现代分布式云原生应用程序。在下一章中，我们将直接开始创建我们的第一个云原生应用程序。


# 第三章：编写您的第一个云原生应用程序

本章将介绍构建第一个云原生应用程序的基本要素。我们将采取最少的步骤，在我们的开发环境中运行一个微服务。

如果您是一名有经验的 Java 开发人员，使用 Eclipse 等 IDE，您会发现自己置身熟悉的领域。尽管大部分内容与构建传统应用程序相似，但也有一些细微差别，我们将在本章中讨论并在最后进行总结。

开始开发的设置步骤将根据开发人员的类型而有所不同：

+   对于业余爱好者、自由职业者或在家工作的开发人员，可以自由访问互联网，云开发相对简单。

+   对于在封闭环境中为客户或业务团队开发项目的企业开发人员，并且必须通过代理访问互联网，您需要遵循企业开发指南。您将受到在下载、运行和配置方面的限制。话虽如此，作为这种类型的开发人员的好处是您并不孤单。您有团队和同事的支持，他们可以通过非正式的帮助或维基文档提供正式的帮助。

在本章结束时，您将在自己的机器上运行一个云原生微服务。为了达到这个目标，我们将涵盖以下主题：

+   开发者的工具箱和生态系统

+   互联网连接

+   开发生命周期

+   框架选择

+   编写云原生微服务

+   启用一些云原生行为

+   审查云开发的关键方面

# 设置您的开发者工具箱

对于任何职业来说，工具都非常重要，编码也是如此。在编写一行代码之前，我们需要准备好正确的设备。

# 获取一个 IDE

**集成开发环境**（**IDE**）不仅仅是一个代码编辑器；它还包括自动完成、语法、格式化等工具，以及搜索和替换等其他杂项功能。IDE 具有高级功能，如重构、构建、测试和在运行时容器的帮助下运行程序。

流行的 IDE 包括 Eclipse、IntelliJ IDEA 和 NetBeans。在这三者中，Eclipse 是最受欢迎的开源 Java IDE。它拥有庞大的社区，并经常更新。它具有工作区和可扩展的插件系统。在各种语言中应用程序的开发潜力是无限的。基于 Eclipse 的其他一些开发 IDE 包括以下内容：

+   如果您只打算进行 Spring 开发，那么称为**Spring Tool Suite**（**STS**）的 Eclipse 衍生产品是一个不错的选择。

+   还有一些云 IDE，比如被誉为下一代 Eclipse 的 Eclipse Che。它不需要任何安装。您可以在连接到 Che 服务器的浏览器中进行开发，该服务器在 Docker 容器中远程构建工作区（包含库、运行时和依赖项）。因此，您可以从任何机器进行开发，任何人都可以通过一个 URL 为您的项目做出贡献。如果您认为这很酷，并且需要一个与位置和机器无关的开发环境，请试一试。

为了这本书的目的，让我们坚持使用基本且非常受欢迎的 Eclipse。在撰写本书时，当前版本是 Neon。庞大的社区和可配置的插件支持使其成为云基 Java 开发的首选 IDE。

从以下网址下载最新版本：[`www.eclipse.org/`](https://www.eclipse.org/)。假设您已安装了 JDK 8 或更高版本，Eclipse 应该可以正常启动。

配置一个将存储项目文件和设置的工作区：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/d05a49d3-1c19-438f-afdd-9759f8202244.png)

当您点击确定时，Eclipse IDE 应该会打开。Eclipse Neon 将自动为您获取我们开发所需的两个重要插件：

+   **Git 客户端**：这将允许我们连接到 Git 源代码控制存储库。本书假设您使用 Git，因为它很受欢迎并且功能强大，但在企业中还有许多旧的选项，如 Subversion 和 Perforce。如果您使用其他选项，请按照您的项目团队或团队 wiki 中给出的开发人员设置说明下载相应的插件。如果这些说明不存在，请要求为新团队成员建立一个。

+   **Maven 支持**：Maven 和 Gradle 都是很好的项目管理和配置工具。它们有助于诸如获取依赖项、编译、构建等任务。我们选择 Maven 是因为它在企业中的成熟度。

如果你第一次接触这两个工具，请通过阅读它们各自的网站来熟悉它们。

# 建立互联网连接

如果您在企业中工作并且必须通过代理访问互联网，根据您的企业政策限制您的操作，这可能会很麻烦。

对于我们的开发目的，我们需要以下互联网连接：

+   下载依赖库，如 Log4j 和 Spring，这些库被配置为 Maven 存储库的一部分。这是一次性活动，因为一旦下载，这些库就成为本地 Maven 存储库的一部分。如果您的组织有一个存储库，您需要进行配置。

+   随着我们样例应用的发展，从市场中获取 Eclipse 插件。

+   您的程序调用了公共云中的服务或 API。

对于编写我们的第一个服务，只有第一个点很重要。请获取您的代理详细信息，并在主菜单的 Maven 设置中进行配置，路径为 Windows | Preferences。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/d9570efd-e76c-4132-9c6e-bbc5d2386b57.png)

对`settings.xml`文件进行更改，添加代理部分：

```java
<proxies> 
   <proxy>
      <id>myproxy</id>
      <active>true</active> 
      <protocol>http</protocol> 
      <host>proxy.yourorg.com</host> 
      <port>8080</port> 
      <username>mahajan</username> 
      <password>****</password> 
      <nonProxyHosts>localhost,127.0.0.1</nonProxyHosts> 
    </proxy> 
    <proxy> 
      <id>myproxy1</id> 
      <active>true</active> 
      <protocol>https</protocol> 
      <host> proxy.yourorg.com</host> 
      <port>8080</port> 
      <username>mahajan</username> 
      <password>****</password> 
      <nonProxyHosts>localhost,127.0.0.1</nonProxyHosts> 
    </proxy> 
```

保存文件并重新启动 Eclipse。当我们创建一个项目时，我们将知道它是否起作用。

# 了解开发生命周期

专业软件编写经历各种阶段。在接下来的章节中，我们将讨论在开发应用程序时将遵循的各个阶段。

# 需求/用户故事

在开始任何编码或设计之前，了解要解决的问题陈述是很重要的。敏捷开发方法建议将整个项目分解为模块和服务，然后逐步实现一些功能作为用户故事。其思想是获得一个**最小可行产品**（MVP），然后不断添加功能。

我们要解决的问题是电子商务领域。由于在线购物，我们大多数人都熟悉电子商务作为消费者。现在是时候来看看它的内部运作了。

起点是一个`product`服务，它执行以下操作：

+   根据产品 ID 返回产品的详细信息

+   获取给定产品类别的产品 ID 列表

# 架构

本书的后面有专门的章节来讨论这个问题。简而言之，一旦需求确定，架构就是关于做出关键决策并创建需求实现蓝图的过程，而设计则是关于合同和机制来实现这些决策。对于云原生开发，我们决定实施微服务架构。

微服务架构范式建议使用包含功能单元的较小部署单元。因此，我们的`product`服务将运行自己的进程并拥有自己的运行时。这使得更容易打包整个运行时，并将其从开发环境带到测试环境，然后再到生产环境，并保持一致的行为。每个`product`服务将在服务注册表中注册自己，以便其他服务可以发现它。我们将在后面讨论技术选择。

# 设计

设计深入探讨了服务的接口和实现决策。`product`服务将具有一个简单的接口，接受产品 ID 并返回一个 Java 对象。如果在存储库中找不到产品，可以决定返回异常或空产品。访问被记录下来，记录了服务被访问的次数和所花费的时间。这些都是设计决策。

我们将在后面的章节中详细讨论特定于云开发的架构和设计原则。

# 测试和开发

在任何现代企业软件开发中，测试都不是事后或开发后的活动。它是通过诸如**测试驱动开发**（**TDD**）和**行为驱动开发**（**BDD**）等概念与开发同时进行或在开发之前进行的。首先编写测试用例，最初失败。然后编写足够的代码来通过测试用例。这个概念对于产品未来迭代中的回归测试非常重要，并与后面讨论的**持续集成**（**CI**）和**持续交付**（**CD**）概念完美融合。

# 构建和部署

构建和部署是从源代码创建部署单元并将其放入目标运行时环境的步骤。开发人员在 IDE 中执行大部分步骤。然而，根据 CI 原则，集成服务器进行编译、自动化测试用例执行、构建部署单元，并将其部署到目标运行时环境。

在云环境中，可部署单元部署在虚拟环境中，如**虚拟机**（**VM**）或容器中。作为部署的一部分，将必要的运行时和依赖项包含在构建过程中非常重要。这与将`.war`或`.ear`放入每个环境中运行的应用服务器的传统过程不同。将所有依赖项包含在可部署单元中使其在不同环境中完整和一致。这减少了出现错误的机会，即服务器上的依赖项与开发人员本地机器上的依赖项不匹配。

# 选择框架

在了解了基础知识之后，让我们编写我们的`product`服务。在 IDE 设置之后，下一步是选择一个框架来编写服务。微服务架构提出了一些有趣的设计考虑，这将帮助我们选择框架：

+   **轻量级运行时**：服务应该体积小，部署快速

+   **高弹性**：应该支持诸如断路器和超时等模式

+   **可测量和可监控**：应该捕获指标并公开钩子供监控代理使用

+   **高效**：应该避免阻塞资源，在负载增加的情况下实现高可伸缩性和弹性

可以在以下网址找到一个很好的比较：[`cdelmas.github.io/2015/11/01/A-comparison-of-Microservices-Frameworks.html`](https://cdelmas.github.io/2015/11/01/A-comparison-of-Microservices-Frameworks.html)。在 Java 领域，有三个框架正在变得流行，符合前述要求：Dropwizard，Vert.x 和 Spring Boot。

# Dropwizard

Dropwizard 是最早推广 fat JAR 概念的框架之一，通过将容器运行时与所有依赖项和库一起放入部署单元，而不是将部署单元放入容器。它整合了 Jetty 用于 HTTP，Jackson 用于 JSON，Jersey 用于 REST 和 Metrics 等库，创建了一个完美的组合来构建 RESTful web 服务。它是早期用于微服务开发的框架之一。

它的选择，如 JDBI，Freemarker 和 Moustache，可能对一些希望在实现选择上灵活的组织来说有所限制。

# Vert.x

Vert.x 是一个出色的框架，用于构建不会阻塞资源（线程）的反应式应用程序，因此非常可伸缩和弹性，因此具有弹性。它是一个相对较新的框架（在 3.0 版本中进行了重大升级）。

然而，它的响应式编程模型在行业中并不十分流行，因此它只是在获得采用，特别是对于需要非常高的弹性和可伸缩性的用例。

# Spring Boot

Spring Boot 正在迅速成为构建云原生微服务的 Java 框架中最受欢迎的。以下是一些很好的理由：

+   它建立在 Spring 和 Spring MVC 的基础上，这在企业中已经很受欢迎

+   与 Dropwizard 一样，它汇集了最合理的默认值，并采用了一种偏向的方法来组装所需的服务依赖项，减少了配置所需的 XML

+   它可以直接集成 Spring Cloud，提供诸如 Hystrix 和 Ribbon 之类的有用库，用于云部署所需的分布式服务开发

+   它的学习曲线较低；您可以在几分钟内开始（接下来我们将看到）

+   它有 40 多个起始 Maven **项目对象模型（POMs）**的概念，为选择和开发应用程序提供了很好的灵活性

Spring Boot 适用于适合云原生部署的各种工作负载，因此对于大多数用例来说是一个很好的首选。

现在让我们开始编写一个 Spring Boot 服务。

# 编写产品服务

为了简单起见，我们的`product`服务有两个功能：

+   `List<int> getProducts(int categoryId)`

+   `Product getProduct(int prodId)`

这两种方法的意图非常明确。第一个返回给定类别 ID 的产品 ID 列表，第二个返回给定产品 ID 的产品详细信息（作为对象）。

# 服务注册和发现

服务注册和发现为什么重要？到目前为止，我们一直通过其 URL 调用服务，其中包括 IP 地址，例如`http://localhost:8080/prod`，因此我们期望服务在该地址运行。即使我们可能替换测试和生产 URL，调用特定 IP 地址和端口的服务步骤仍然是静态的。

然而，在云环境中，事情变化很快。如果服务在给定的 IP 上停机，它可以在不同的 IP 地址上启动，因为它在某个容器上启动。虽然我们可以通过虚拟 IP 和反向代理来缓解这一问题，但最好在服务调用时动态查找服务，然后在 IP 地址上调用服务。查找地址可以在客户端中缓存，因此不需要为每个服务调用执行动态查找。

在这种情况下，注册表（称为服务注册表）很有帮助。当服务启动时，它会在注册表中注册自己。注册表和服务之间也有心跳，以确保注册表中只保留活动的服务。如果心跳停止，注册表将注销该服务实例。

对于这个快速入门，我们将使用 Spring Cloud Netflix，它与 Spring Boot 很好地集成。现在我们需要三个组件：

+   **产品服务**：我们已经编写了这个

+   **服务注册表**：我们将使用 Eureka，它是 Spring Cloud 的一部分

+   **服务客户端**：我们将编写一个简单的客户端来调用我们的服务，而不是直接通过浏览器调用

# 创建一个 Maven 项目

打开您的 IDE（Eclipse Neon 或其他），然后按以下步骤创建一个新的 Maven 项目：

1.  在 Package Explorer 上右键单击，然后选择 New 和 Project...，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/681949d8-038d-4675-9be2-8e5a65d86c5a.png)

1.  选择 Maven 项目：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/9fe14540-94a8-4cd4-b7fe-156e2d293869.png)

1.  在向导的下一个窗口中，选择创建一个简单的项目。

1.  下一个对话框将要求输入许多参数。其中，Group Id（你的项目名称）和 Artifact Id（应用程序或服务名称）很重要。选择合理的名称，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/1c3962d4-41d2-4a1f-9fda-56f35f23a737.png)

1.  选择完成。你应该看到以下结构：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/f7096253-de5c-4104-ac43-57ab9881fb77.png)

如果 JRE System Library [JavaSE-1.6]不存在，或者你有一个更新的版本，去项目属性中编辑它，选择你的 Eclipse 配置的版本。你可以通过右键单击 JRE System Library [JavaSE-1.6]来改变属性。这是调整 JRE System Library 到 1.8 后的截图。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/43dfa29c-079f-4a17-b400-375158b121f4.png)

1.  现在，你有一个干净的板面。打开 Maven 文件`pom.xml`，并添加一个依赖项`spring-boot-starter-web`。这将告诉 Spring Boot 配置这个项目以获取 web 开发的库：

```java
<project xmlns.... 
  <modelVersion>4.0.0</modelVersion> 
  <parent> 
    <groupId>org.springframework.boot</groupId> 
    <artifactId>spring-boot-starter-parent</artifactId> 
    <version>1.4.3.RELEASE</version> 
  </parent> 
  <groupId>com.mycompany.petstore</groupId> 
  <artifactId>product</artifactId> 
  <version>0.0.1-SNAPSHOT</version>    
<dependencies> 
    <dependency> 
        <groupId>org.springframework.boot</groupId> 
        <artifactId>spring-boot-starter-web</artifactId> 
    </dependency> 
</dependencies> 
</project> 
```

保存这个 POM 文件时，你的 IDE 将构建工作区并下载依赖的库，假设你的互联网连接正常（直接或通过之前配置的代理），你已经准备好开发服务了。

# 编写一个 Spring Boot 应用程序类

这个类包含了执行开始的主方法。这个主方法将引导 Spring Boot 应用程序，查看配置，并启动相应的捆绑容器，比如 Tomcat，如果执行 web 服务：

```java
package com.mycompany.product;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;

@SpringBootApplication
public class ProductSpringApp {
  publicstaticvoid main(String[] args) throws Exception {
    SpringApplication.run(ProductSpringApp.class, args);
    }
  } 
```

注意注解`@SpringBootApplication`。

`@SpringBootApplication`注解等同于使用`@Configuration`，`@EnableAutoConfiguration`和`@ComponentScan`，它们分别执行以下操作：

+   `@Configuration`：这是一个核心的 Spring 注解。它告诉 Spring 这个类是`Bean`定义的来源。

+   `@EnableAutoConfiguration`：这个注解告诉 Spring Boot 根据你添加的 JAR 依赖来猜测你想要如何配置 Spring。我们添加了 starter web，因此应用程序将被视为 Spring MVC web 应用程序。

+   `@ComponentScan`：这个注解告诉 Spring 扫描任何组件，例如我们将要编写的`RestController`。注意扫描发生在当前和子包中。因此，拥有这个组件扫描的类应该在包层次结构的顶部。

# 编写服务和领域对象

Spring Boot 中的注解使得提取参数和路径变量并执行服务变得容易。现在，让我们模拟响应，而不是从数据库中获取数据。

创建一个简单的 Java 实体，称为`Product`类。目前，它是一个简单的**POJO**类，有三个字段：

```java
publicclass Product {
  privateint id = 1 ;
  private String name = "Oranges " ;
  privateint catId = 2 ;
```

添加获取器和设置器方法以及接受产品 ID 的构造函数：

```java
  public Product(int id) {
    this.id = id;
    }
```

另外，添加一个空的构造函数，将在后面由服务客户端使用：

```java
  public Product() {
   } 
```

然后，编写`ProductService`类如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/e48d02a3-1d11-4c87-b0f6-933b6155d8a2.png)

# 运行服务

有许多方法可以运行服务。

右键单击项目，选择 Run As | Maven build，并配置 Run Configurations 来执行`spring-boot:run`目标如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/517a372f-2512-46ef-8db3-44f2e63bac93.png)

点击运行，如果互联网连接和配置正常，你将看到以下控制台输出：

```java
[INFO] Building product 0.0.1-SNAPSHOT 
... 
[INFO] Changes detected - recompiling the module! 
[INFO] Compiling 3 source files to C:Appswkneonproducttargetclasses 
... 
 :: Spring Boot ::        (v1.4.3.RELEASE) 

2016-10-28 13:41:16.714  INFO 2532 --- [           main] com.mycompany.product.ProductSpringApp   : Starting ProductSpringApp on L-156025577 with PID 2532 (C:Appswkneonproducttargetclasses started by MAHAJAN in C:Appswkneonproduct) 
... 
2016-10-28 13:41:19.892  INFO 2532 --- [           main] s.b.c.e.t.TomcatEmbeddedServletContainer : Tomcat initialized with port(s): 8080 (http) 
... 
2016-10-28 13:41:21.201  INFO 2532 --- [           main] s.w.s.m.m.a.RequestMappingHandlerMapping : Mapped "{[/product/{id}]}" onto com.mycompany.product.Product com.mycompany.product.ProductService.getProduct(int) 
2016-10-28 13:41:21.202  INFO 2532 --- [           main] s.w.s.m.m.a.RequestMappingHandlerMapping : Mapped "{[/productIds]}" onto java.util.List<java.lang.Integer> com.mycompany.product.ProductService.getProductIds(int) 
... 
... 
2016-10-28 13:41:21.915  INFO 2532 --- [           main] s.b.c.e.t.TomcatEmbeddedServletContainer : Tomcat started on port(s): 8080 (http) 
2016-10-28 13:41:21.922  INFO 2532 --- [           main] com.mycompany.product.ProductSpringApp   : Started ProductSpringApp in 6.203 seconds (JVM running for 14.199) 
```

注意 Maven 执行的阶段：

1.  首先，Maven 任务编译所有的 Java 文件。目前我们有三个简单的 Java 类。

1.  下一步将其作为一个应用程序运行，其中一个 Tomcat 实例启动。

1.  注意将 URL `/product/`和`/productIds`映射到`Bean`方法。

1.  Tomcat 监听端口`8080`以接收服务请求。

你也可以通过在 Package Explorer 中右键单击具有主方法的类（`ProductSpringApp`）然后选择 Run As | Java Application 来运行服务。

# 在浏览器上测试服务

打开浏览器，访问以下 URL：`http://localhost:8080/product/1`。

你应该得到以下响应：

```java
{"id":1,"name":"Oranges ","catId":2}
```

现在，尝试另一个服务（URL—`http://localhost:8080/productIds`）。你得到什么响应？一个错误，如下所示：

```java
    There was an unexpected error (type=Bad Request, status=400).
    Required int parameter 'id' is not present
```

你能猜到为什么吗？这是因为你写的服务定义有一个期望请求参数的方法：

```java
@RequestMapping("/productIds")
List<Integer> getProductIds(@RequestParam("id") int id) {
```

因此，URL 需要一个`id`，由于你没有提供它，所以会出错。

给出参数，再次尝试  `http://localhost:8080/productIds?id=5`。

现在你会得到一个正确的响应：

```java
[6,7,8]
```

# 创建可部署文件

我们不打算在 Eclipse 上运行我们的服务。我们想要在服务器上部署它。有两种选择：

+   创建一个 WAR 文件，并将其部署到 Tomcat 或任何其他 Web 容器中。这是传统的方法。

+   创建一个包含运行时（Tomcat）的 JAR，这样你只需要 Java 来执行服务。

在云应用程序开发中，第二个选项，也称为 fat JAR 或 uber JAR，因以下原因而变得流行：

+   可部署文件是自包含的，具有其所需的所有依赖项。这减少了环境不匹配的可能性，因为可部署单元被部署到开发、测试、UAT 和生产环境。如果在开发中工作，它很可能会在所有其他环境中工作。

+   部署服务的主机、服务器或容器不需要预安装应用服务器或 servlet 引擎。只需一个基本的 JRE 就足够了。

让我们看看创建 JAR 文件并运行它的步骤。

包括 POM 文件的以下依赖项：

```java
<build><plugins><plugin> 
            <groupId>org.springframework.boot</groupId> 
            <artifactId>spring-boot-maven-plugin</artifactId> 
</plugin></plugins></build> 
```

现在，通过在资源管理器中右键单击项目并选择 Run As | Maven Install 来运行它。

你将在项目文件夹结构的目标目录中看到`product-0.0.1-SNAPSHOT.jar`。

导航到`product`文件夹，以便在命令行中看到目标目录，然后通过 Java 命令运行 JAR，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/43947a81-a87d-47cb-832f-a0a4ecb0893c.png)

你将看到 Tomcat 在启动结束时监听端口。再次通过浏览器测试。里程碑达成。

# 启用云原生行为

我们刚刚开发了一个基本的服务，有两个 API 响应请求。让我们添加一些功能，使其成为一个良好的云服务。我们将讨论以下内容：

+   外部化配置

+   仪器化—健康和指标

+   服务注册和发现

# 外部化配置

配置可以是在环境或生产部署之间可能不同的任何属性。典型的例子是队列和主题名称、端口、URL、连接和池属性等。

可部署文件不应该包含配置。配置应该从外部注入。这使得可部署单元在生命周期的各个阶段（如开发、QA 和 UAT）中是不可变的。

假设我们必须在不同的环境中运行我们的`product`服务，其中 URL 区分环境。因此，我们在请求映射中做的小改变如下：

```java
@RequestMapping("/${env}product/{id}")
Product getProduct(@PathVariable("id") int id) {
```

我们可以以各种方式注入这个变量。一旦注入，该值在部署的生命周期内不应该改变。最简单的方法是通过命令行参数传递。打开运行配置对话框，在参数中添加命令行参数`-env=dev/`，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/c0613d40-8b94-4e8b-8f03-81ba4ddbd6cc.png)

现在，运行配置。在启动过程中，你会发现值被替换在日志声明中，如下所示：

```java
... Mapped "{[/dev/product/{id}]}" onto com.mycompany.product.Product com.mycompany.product.ProductService.getProduct(int) 
```

配置也可以通过配置文件、数据库、操作系统环境属性等提供。

Spring 应用程序通常使用`application.properties`来存储一些属性，如端口号。最近，YAML，它是 JSON 的超集，由于属性的分层定义，变得更加流行。

在应用程序的`/product/src/main/resources`文件夹中创建一个`application.yml`文件，并输入以下内容：

```java
server: 
  port: 8081 
```

这告诉`product`服务在端口`8081`上运行，而不是默认的`8080`。这个概念进一步扩展到配置文件。因此，可以通过加载特定于配置文件的配置来加载不同的配置文件。

Spring Cloud Config 作为一个项目很好地处理了这个问题。它使用`bootstrap.yml`文件来启动应用程序，并加载配置的名称和详细信息。因此，`bootstrap.yml`包含应用程序名称和配置服务器详细信息，然后加载相应的配置文件。

在应用程序的`resources`文件夹中创建一个`bootstrap.yml`文件，并输入以下内容：

```java
spring: 
  application: 
    name: product 
```

当我们讨论服务注册时，我们将回到这些文件。

# 计量您的服务

仪器化对于云应用程序非常重要。您的服务应该公开健康检查和指标，以便更好地进行监控。Spring Boot 通过`actuator`模块更容易进行仪器化。

在 POM 中包含以下内容：

```java
    <dependency> 
        <groupId>org.springframework.boot</groupId> 
        <artifactId>spring-boot-starter-actuator</artifactId> 
    </dependency> 
```

运行服务。在启动过程中，您将看到创建了许多映射。

您可以直接访问这些 URL（例如`http://localhost:8080/env`）并查看显示的信息：

```java
{ 
  "profiles": [], 
  "server.ports": { 
    "local.server.port": 8082 
  }, 
  "commandLineArgs": { 
    "env": "dev/" 
  }, 
  "servletContextInitParams": {}, 
  "systemProperties": { 
    "java.runtime.name": "Java(TM) SE Runtime Environment", 
    "sun.boot.library.path": "C:\Program Files\Java\jdk1.8.0_73\jrebin", 
    "java.vm.version": "25.73-b02", 
    "java.vm.vendor": "Oracle Corporation", 
    "java.vendor.url": "http://java.oracle.com/", 
    "path.separator": ";", 
    "java.vm.name": "Java HotSpot(TM) 64-Bit Server VM", 
    "file.encoding.pkg": "sun.io", 
    "user.country": "IN", 
    "user.script": "", 
    "sun.java.launcher": "SUN_STANDARD", 
    "sun.os.patch.level": "Service Pack 1", 
    "PID": "9332", 
    "java.vm.specification.name": "Java Virtual Machine Specification", 
    "user.dir": "C:\Apps\wkneon\product", 
```

指标尤其有趣（`http://localhost:8080/metrics`）：

```java
{ 
  "mem": 353416, 
  "mem.free": 216921, 
  "processors": 4, 
  "instance.uptime": 624968, 
  "uptime": 642521, 
... 
  "gauge.servo.response.dev.product.id": 5, 
... 
   threads.peak": 38, 
  "threads.daemon": 35, 
  "threads.totalStarted": 45, 
  "threads": 37, 
... 
```

信息包括计数器和量规，用于存储服务被访问的次数和响应时间。

# 运行服务注册表

Consul 和 Eureka 是两个流行的动态服务注册表。它们在心跳方法和基于代理的操作方面存在微妙的概念差异，但注册表的基本概念是相似的。注册表的选择将受企业的需求和决策的驱动。对于我们的示例，让我们继续使用 Spring Boot 和 Spring Cloud 生态系统，并为此示例使用 Eureka。Spring Cloud 包括 Spring Cloud Netflix，它支持 Eureka 注册表。

执行以下步骤以运行服务注册表：

1.  创建一个新的 Maven 项目，`artifactId`为`eureka-server`。

1.  编辑 POM 文件并添加以下内容：

+   父级为`spring-boot-starter-parent`

+   依赖于`eureka-server`为`spring-cloud-starter-eureka-server`

+   `dependencyManagement`为`spring-cloud-netflix`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/432ff7ef-5eb6-4cc5-9810-9280b967d0e7.png)

1.  创建一个类似于我们为`product`项目创建的应用程序类。注意注解。注解`@EnableEurekaServer`将 Eureka 作为服务启动：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/f1c9c5e9-be4a-4332-8242-c5a24e496291.png)

1.  在应用程序的`/product/src/main/resources`文件夹中创建一个`application.yml`文件，并输入以下内容：

```java
server: 
  port: 8761 
```

1.  在应用程序的`resources`文件夹中创建一个`bootstrap.yml`文件，并输入以下内容：

```java
spring: 
  application: 
    name: eureka 
```

1.  构建`eureka-server` Maven 项目（就像我们为`product`做的那样），然后运行它。

1.  除了一些连接错误（稍后会详细介绍），您应该看到以下 Tomcat 启动消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/aa53f30d-18e5-46f3-b83d-342370af2aec.png)

启动完成后，访问`localhost:8761`上的 Eureka 服务器，并检查是否出现以下页面：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/be32fc66-1a70-47a3-bad5-8d633506d118.png)

查看前面截图中的圈定部分。当前注册到 Eureka 的实例是`EUREKA`本身。我们可以稍后更正这一点。现在，让我们专注于将我们的`product`服务注册到这个 Eureka 服务注册表。

# 注册产品服务

`product`服务启动并监听端口`8081`以接收`product`服务请求。现在，我们将添加必要的指示，以便服务实例将自身注册到 Eureka 注册表中。由于 Spring Boot，我们只需要进行一些配置和注解：

1.  在`product`服务 POM 中添加`dependencyManagement`部分，依赖于`spring-cloud-netflix`和现有依赖项部分中的`spring-cloud-starter-eureka`如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/582a3747-c882-43dd-a428-9c5e34411f9b.png)

1.  `product`服务会在特定间隔内不断更新其租约。通过在`application.yml`中明确定义一个条目，将其减少到 5 秒：

```java
server: 
  port: 8081 

eureka: 
  instance: 
    leaseRenewalIntervalInSeconds: 5
```

1.  在`product`项目的启动应用程序类中包含`@EnableDiscoveryClient`注解，换句话说，`ProductSpringApp`。`@EnableDiscoveryClient`注解激活 Netflix Eureka `DiscoveryClient`实现，因为这是我们在 POM 文件中定义的。还有其他实现适用于其他服务注册表，如 HashiCorp Consul 或 Apache Zookeeper：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/397e1c42-3d6c-424c-9012-305e71f783ae.png)

1.  现在，像以前一样启动`product`服务：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/8e4e43cc-a802-441d-b9ba-0f169af84c0c.png)

在`product`服务初始化结束时，您将看到注册服务到 Eureka 服务器的日志声明。

要检查`product`服务是否已注册，请刷新您刚访问的 Eureka 服务器页面：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/2c653d48-c5d6-4702-83bf-e03c58e5131b.png)

还要留意 Eureka 日志。您会发现`product`服务的租约续订日志声明。

# 创建产品客户端

我们已经创建了一个动态产品注册表，甚至注册了我们的服务。现在，让我们使用这个查找来访问`product`服务。

我们将使用 Netflix Ribbon 项目，该项目提供了负载均衡器以及从服务注册表中查找地址的功能。Spring Cloud 使配置和使用这一切变得更加容易。

现在，让我们在与服务本身相同的项目中运行客户端。客户端将在 Eureka 中查找产品定义后，向服务发出 HTTP 调用。所有这些都将由 Ribbon 库完成，我们只需将其用作端点：

1.  在`product`项目的 Maven POM 中添加依赖如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/a120da92-e357-4c87-a464-4497467711cd.png)

1.  创建一个`ProductClient`类，它简单地监听`/client`，然后在进行查找后将请求转发到实际的`product`服务：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/a9340beb-00a1-47e4-b71f-2fd7ebcb4681.png)

URL 构造`http://PRODUCT/`将在运行时由 Ribbon 进行翻译。我们没有提供服务的 IP 地址。

1.  `restTemplate`通过自动装配在这里注入。但是，在最新的 Spring 版本中需要初始化它。因此，在主应用程序类中声明如下，这也充当配置类：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/da08bf22-4652-47b9-bdc4-29a5a359104e.png)

`@LoadBalanced`注解告诉 Spring 使用 Ribbon 负载均衡器（因为 Ribbon 在类路径中由 Maven 提供）。

# 查看查找的实际操作

现在，我们已经准备好运行产品客户端了。简而言之，在这个阶段，我们有一个 Eureka 服务器项目和一个具有以下结构的`product`项目：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/e6bb7836-fac8-4b95-a37b-c562d0d4fd4c.png)

让我们花几分钟时间来回顾一下我们做了什么：

1.  我们创建了一个 Maven 项目并定义了启动器和依赖项。

1.  我们为引导和应用程序属性创建了 YML 文件。

1.  我们创建了包含主方法的`ProductSpringApp`类，这是应用程序的起点。

1.  对于`product`项目，我们有以下类：

+   `Product`：我们稍后将增强的领域或实体

+   `ProductService`：负责实现服务和 API 的微服务

+   `ProductClient`：用于测试服务查找的客户端

现在，让我们看看它的实际操作：

1.  运行`EurekaApplication`类（或在`eureka-server`项目上运行 Maven 构建）。观察日志中的最后几行：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/9624f0d6-6e69-49df-9d35-0988accb12c2.png)

1.  运行`ProductSpringApp`类（或在`product`项目上运行 Maven 构建）。注意日志中的最后几行：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/57e4b508-31d3-4563-985e-2fa5b451d62e.png)

1.  直接访问`product`服务：`http://localhost:8081/dev/product/4`。

您将看到以下响应：

```java
{"id":4,"name":"Oranges ","catId":2}
```

1.  现在，访问客户端 URL，`http://localhost:8081/client/4`，它会从服务注册表中查找`product`服务并将其指向相应的`product`服务。

您将看到以下响应：

```java
 {"id":4,"name":"Oranges ","catId":2}
```

您可能会看到内部服务器错误（`PRODUCT`没有可用实例）。这可能发生在心跳完成并且地址被 Ribbon 负载均衡器重新选择时。等待几秒钟，直到注册表更新，然后再试一次。

在获取此响应的过程中发生了很多事情：

1.  处理`/client/4`的 HTTP 请求是由`ProductClient`类中的`getProduct`方法处理的。

1.  它从 Eureka 注册表中查找了该服务。这就是我们找到的日志语句如下：

```java
c.n.l.DynamicServerListLoadBalancer: Using serverListUpdater PollinServerListUpdater
c.netflix.config.ChainedDynamicProperty: Flipping property: PRODUCT.ribbon.ActiveConnectionsLimit to use NEXT property: niws.loadbalancer
c.n.l.DynamicServerListLoadBalancer: DynamicServerListLoadBalancer for client PRODUCT intiated: DynamicServerListLoadBalancer:
```

1.  在进行查找后，它通过 Ribbon 负载均衡器库将请求转发到实际的`ProductService`。

这只是一个客户端通过动态查找调用服务的简单机制。在后面的章节中，我们将添加功能，使其在从数据库获取数据方面具有弹性和功能性。

# 摘要

让我们回顾一下到目前为止我们讨论过的云应用程序的关键概念。通过在 servlet 引擎上运行并在不到 15 秒内启动，我们使我们的应用程序变得**轻量级**。我们的应用程序是**自包含**的，因为 fat JAR 包含了运行我们的服务所需的所有库。我们只需要一个 JVM 来运行这个 JAR 文件。它通过从命令行注入环境和从`application.yml`和`bootstrap.yml`中注入属性，实现了**外部化配置**（在某种程度上）。我们将在第七章 *Cloud-Native Application Runtime*中更深入地研究外部化的下一阶段。Spring 执行器帮助捕获所有指标，并使它们的 URL 可供使用，从而实现了**仪表化**。**位置抽象**是由 Eureka 实现的。

在接下来的章节中，我们将通过向其添加数据层和弹性，以及添加缓存行为和其他我们在本章中跳过的增强功能，来增强此服务。


# 第四章：设计您的云原生应用程序

在本章中，我们暂停应用程序开发，退一步看设计云应用的整体情况。正如在第一章中所看到的，云中的应用比我们迄今为止开发的传统企业应用有更多独特的挑战。此外，敏捷的业务需求必须在不牺牲性能、稳定性和弹性的情况下得到满足。因此，看待第一原则变得重要。

在第一章中，我们看到了云环境和传统企业之间的差异，以及 DevOps、12 因素应用程序、微服务和生态系统的概念是如何重要的。在这里，我们将看一下各种原则和技术，使我们能够设计健壮、可扩展和敏捷的应用程序。

我们将涵盖的一些领域包括使用 REST、HTTP 和 JSON 构建 API 的主导地位，API 网关的作用，如何解耦应用程序，如何识别微服务，各种微服务设计指南，数据架构的作用，以及在设计 API 时安全性的作用。

我们将在本章中涵盖以下主题：

+   REST、HTTP 和 JSON 的流行

+   API 的兴起和流行

+   API 网关的角色

+   解耦-需要更小的应用边界

+   微服务识别

+   微服务设计指南

+   微服务模式

+   数据架构

+   安全角色

# 三者-REST、HTTP 和 JSON

网络使得 HTTP 变得非常流行，并成为访问互联网内容的事实集成机制。有趣的是，这项技术在依赖本地和二进制协议（如 RMI 和 CORBA）进行应用程序访问的应用程序中并不是非常流行。

当社交消费公司（如 Google、Amazon、Facebook 和 Twitter）开始发布 API 以连接/集成其产品时，跨网络的集成的事实标准变成了 HTTP/REST。社交消费公司开始投资于平台，以吸引开发人员开发各种应用程序，从而导致依赖 HTTP 作为协议的应用程序的大量增加。

浏览器端的应用程序是 HTML 和 JavaScript 的混合。从服务器返回的信息或其他应用程序需要以简单和可用的格式。 JavaScript 支持数据操作，最适合的数据格式是**JavaScript 对象表示**（**JSON**）。

REST 是一种状态表示风格，提供了一种处理 HTTP 交换的方式。 REST 有很多优势：

+   利用 HTTP 协议标准，为 WWW 上的任何事物提供了巨大的优势

+   隔离对实体的访问（`GET`/`PUT`/`POST`/`DELETE`）的机制，同时利用相同的 HTTP 请求模型

+   支持 JSON 作为数据格式

REST 与 JSON 已经成为主导模型，超过了 SOAP/XML 模型。根据可编程 Web 的统计数据：

73%的可编程 Web API 使用 REST。 SOAP 远远落后，但在 17%的 API 中仍有所体现。

让我们来看一些 REST/JSON 模型受欢迎的高级原因：

+   SOAP 的契约优先方法使得制作 Web 服务变得困难。

+   与 REST 相比，SOAP 更复杂，学习曲线更陡。

+   与 SOAP 相比，REST 更轻量级，不会像 SOAP 那样占用带宽。

+   在 Java 世界之外，对 SOAP 的支持有限，主要将 SOAP 局限于企业世界。

+   客户端上的 XML 解析需要大量内存和计算资源，这不适合移动世界。

+   XML 模式/标记提供了结构定义和验证模型，但需要额外的解析。 JSON 具有松散的语法，允许对数据模型进行快速迭代。

今天，现实是 REST/JSON 已经成为跨编程语言集成的标准，为通过互联网集成 API 提供了一种简单易行的方式。

# API 的兴起和流行

**应用程序编程接口**（**API**）提供了一个标准的接口或契约，以通过互联网消费其服务。API 定义了输入和输出的结构，并在 API 版本的整个生命周期内保持不变。

API 是客户端层和企业之间的契约。它们是面向消费者的，即由客户端设计，并且将服务实现细节从客户端抽象出来。

回到社交消费者公司的出现，创建新的应用程序并不意味着从头开始。例如，如果我的应用程序需要使用地理地图，我可以利用 Google 地图 API 并在此基础上构建我的应用程序。同样，我可以利用 OAuth 而不是构建自己的身份验证模型，并使用 Google、Facebook 或 Twitter 作为一些 OAuth 提供者。

将一个可重复但通常复杂的功能作为可重用服务提供的整个模型，导致开发人员开始使用这些现有的 API 构建应用程序，从而提高了开发人员的生产力，并推动了现代应用程序或移动应用程序经济的发展。

公司开始寻求是否可以将 API 商品化，这意味着多家公司正在编写/发布提供类似功能的 API。这导致了 API 的民主化，使任何人都可以访问功能/函数。

API 的整个民主化意味着，突然之间，每个流程或功能都可以作为一组 API 来提供，可以编排或编排以构建新的功能。以前需要几个月甚至几年的时间，现在只需要几周甚至几天。所有这些生产力意味着更短的开发周期，允许快速迭代提供新的创新功能。

今天，各种类型的 API 都可以使用：从 Facebook、Google 和 Twitter 等社交公司到 Salesforce、NetSuite 和 PaaS/IaaS 提供商，如 AWS、Azure、**Google Cloud Engine**（**GCE**）等，它们都提供从提供虚拟机到数据库实例，再到 Watson、AWS AI 和 Azure ML 等 AI 提供商的功能。

# API 网关的作用

API 网关是一个单一的接口，它在重定向到内部服务器之前处理所有传入的请求。API 网关通常提供以下功能：

+   将传入流量路由到提供者的数据中心/云中托管的适当服务。提供反向代理模型，限制提供者数据中心/云中托管的各种 API 和服务的暴露。

+   过滤来自各种渠道的所有传入流量——Web、移动等。

+   实施安全机制（如 OAuth）来验证和记录服务的使用情况。

+   提供了对某些服务的流量控制和限制能力。

+   在服务消费者和提供者之间转换数据。

+   提供一个或多个 API，映射到底层的服务提供者。例如，对于不同类型的消费者——移动、Web、付费服务或免费服务，相同的底层服务可以分成多个自定义 API，暴露给不同的消费者，以便消费者只看到它需要的功能：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/5215f408-cc6f-4926-ad6a-70890fc44f04.jpg)

# API 网关的好处

使用 API 网关提供以下好处：

+   **关注点分离**：在应用程序端将微服务提供者与服务消费者隔离开来。这允许将应用程序层与服务请求客户端分离。

+   面向消费者：API 网关为大量的 API 和微服务提供了一个统一的中心。这使得消费者可以专注于 API 的实用性，而不是寻找服务的托管位置，管理服务请求限制，安全性等。

+   面向 API：根据客户端的类型和所需的协议提供最佳的 API。

+   编排：提供了将多个服务调用编排成一个 API 调用的能力，从而简化了客户端的逻辑。现在，它可以调用一个 API 而不是调用多个服务。较少的请求意味着较少的调用开销，从而提高了消费者的整体体验。API 网关对移动应用程序至关重要。

+   监控：API 网关还提供了监控 API 调用的能力，从而使企业能够评估 API 的成功和使用情况。

除了总体利益外，API 网关为整体拼图增加了更多的部分。这意味着需要管理更多的基础设施、更多的配置、更多的故障点和额外的请求跳转。因此，除非利益超过了缺点，否则需要仔细审查 API 网关的使用，以满足业务需求和利益。

接下来，我们将看到将应用程序功能拆分为一组 API 或微服务的过程。

# 应用程序解耦

传统的应用程序开发模型，将所有功能和功能捆绑在一个称为单体应用程序的大型包中，由于多种原因而变得不太受欢迎。单体应用程序以功能和逻辑的形式承担了太多的责任。正是这一特征使它们具有高耦合和低内聚。单体应用程序中的重用因子往往较低，因为功能的一部分无法与其余的功能和逻辑分离。

当我们开始拆分单体功能或设计新应用程序时，重点需要放在定义服务边界上。定义正确的服务边界及其相关的交互是导致高内聚和低耦合模型的关键。

问题是，应用程序应该根据什么基础被解耦为服务，并定义服务边界？

# 有界上下文/领域驱动设计

作为应用程序设计的一部分，业务领域需要被拆分为更小的子领域或业务能力。我们需要仔细审查业务实体及其属性，以定义服务边界。例如，在客户 ID 实体的情况下，客户的地址可能是客户的一部分。在应用程序的上下文中，地址维护可能是一个单独的活动，可能需要单独处理。同样，个性化可能需要客户偏好或购物习惯。在这种情况下，个性化引擎更感兴趣这一系列属性。

我们应该组合一个包含所有属性的大型客户服务，还是可以根据业务派生的不同视角进行划分？这些不同的视角导致了领域驱动设计中有界上下文的定义。

有界上下文是一种领域驱动设计范式，有助于添加一个接缝并创建服务组。有界上下文在解决方案空间中工作，表明服务相关并属于一个共同的功能域。它是由一个团队根据反向康威定律与一个业务单元一起构建的。有界上下文可以通过以下方式与其他服务/业务能力进行通信：

+   暴露内部 API 或服务

+   在事件总线上发出事件

有界上下文可以拥有自己的数据存储，服务共用，或采用每个服务一个数据存储的范式。

每个有界上下文都有自己的生命周期，并形成一个产品。团队围绕这些有界上下文组织，并全权负责服务的全栈实现。团队是跨职能的，并从开发、测试、用户体验、数据库、部署和项目管理中带来技能。每个产品可能会被拆分成较小的服务集，它们之间异步通信。请记住，重点不是一组功能，而是业务能力。

我们开始围绕业务能力构建我们的服务。服务拥有其业务数据和功能。服务是这些数据的主人，其他服务不能拥有该服务的任何数据。

# 上游/下游服务的分类

另一种拆分应用系统的方法是通过上游和下游数据流模型对其进行分类。系统中的核心实体包括上游服务。这些上游服务会触发事件，下游服务会订阅这些事件以增强其功能。这旨在解耦系统，并有助于提高整体业务敏捷性。这与反应式架构概念相吻合，也被称为事件驱动架构。

让我们以电子商务应用程序为例，其中核心实体是客户和产品。订单服务依赖于核心实体客户和产品的信息。接下来，我们正在构建为客户提供推荐和个性化服务的服务。推荐和个性化服务依赖于核心实体客户、产品和订单的数据。当核心实体发生变化时，变化会被发布。这些变化会被推荐和个性化服务接收，它们会使用额外的属性来提供相关服务。推荐和个性化服务是这些服务的下游服务。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/6188e3d5-a83d-41a7-a81e-9ae52fde7529.jpg)

将业务能力分类为上游和下游的模型有助于定义服务之间的依赖关系，并改变上游服务对下游服务的影响。

# 业务事件

随着系统的发展，服务将开始聚集成自然的盟友。这意味着找出服务是否依赖于类似的数据元素或提供重叠/配角功能，并且可能成为同一有界上下文的一部分。

在同一领域内工作的有界上下文服务可能需要依赖于主服务以实现准确的功能。这可能意味着一些主服务数据属性需要提供给相关的有界上下文服务。例如，在我们之前的例子中，我们谈到了客户偏好。现在，这些偏好可能需要映射到客户的位置（地址）。在这种情况下，客户偏好是否需要每次调用客户地址服务来构建偏好，还是可以将相关属性复制到自己的领域中？在不重复数据的情况下，这两个服务开始紧密耦合，导致双向通信模型。为了打破这种紧密耦合，我们允许客户偏好服务使用事件来缓存或复制相关的客户属性。这种异步模型打破了服务之间的时间紧密耦合。每当客户地址发生变化时，服务都会发布一个业务事件进行必要的更改。客户偏好服务会订阅这个变化，以更新其偏好模型。

这种异步模型使我们能够确保：

+   数据所有权仍然清晰。对数据的任何更改都会通知依赖服务。允许依赖服务保存或复制数据，但不更改本地副本，除非更新主副本（黄金源原则）。依赖服务仅存储所需和功能相关的数据子集（需要知道原则）。

+   异步业务事件导致服务之间的低耦合。核心服务的更改会导致事件。事件向下游传递给感兴趣的依赖服务。唯一的依赖是发布的业务事件的格式。

+   下游服务遵循最终一致性原则；所有业务事件都以顺序方式存储，以构建/状态一个较晚的时间（事件源/CQRS）。查询模型可以与记录系统不同。

+   业务事件的异步模型也促进了编排而不是管弦乐，从而导致了松散耦合的系统/服务。

有时，当团队开始一个新产品时，可能无法事先定义界限上下文或服务分解。因此，团队开始构建应用程序作为一个单片应用程序，通过将其功能公开为一组服务。随着团队实施更多的故事，他们可以确定功能的部分，这些功能以快速的速度变化（通常是体验或渠道服务）与变化缓慢的部分（通常是核心服务或实体服务）。

团队可以开始将服务分为两类——体验和系统服务。系统服务可以进一步围绕实体和相互关系进行分组。体验服务映射到客户旅程。团队通常会有冲刺来清理/重构代码，以清除每个周期积累的技术债务。

那么，下一个问题是，什么标识一个服务为微服务？

# 微服务识别

微服务的名称并不一定意味着服务必须体积小。但它具有以下特点：

+   单一责任原则：这是微服务的核心设计原则。它们应该完成一个业务任务单元并完全完成它。如果耦合度低，服务将更容易修改和部署，甚至完全替换。

+   粒度：微服务的粒度包含在单个功能域、单个数据域及其直接依赖、自包含的打包和技术域的交集中。

+   界限：服务应该可以访问其界限上下文中由同一团队管理的资源。但是，它不应直接访问其他模块的资源，如缓存和数据库。如果服务需要访问其他模块，应通过内部 API 或服务层进行。这有助于减少耦合并促进敏捷性。

+   独立：每个微服务都是独立开发、测试和部署的，在其自己的源中。它可以使用第三方或共享库。

# 微服务和服务导向架构（SOA）之间的区别

以下是微服务和服务导向架构（SOA）之间的区别：

+   服务执行整个业务工作单元。例如，如果一个服务需要客户或产品数据，最好将其存储在服务数据存储中。通常，不需要通过 ESB 获取客户记录。

+   服务有自己的私有数据库或仅在其界限上下文中共享的数据库，并且可以存储为服务业务工作单元提供所需的信息。

+   服务是一个智能端点，通常通过 Swagger 或类似的存储库中的合同定义公开 REST 接口。一些被其他部门或客户使用的服务通过 API 平台公开。

# 服务粒度

以下是服务的类型：

+   **原子或系统服务**：这些服务执行单元级别的工作，并且足以通过引用数据库或下游源来服务请求。

+   **复合或过程服务**：这些服务依赖于两个或多个原子服务之间的协调。通常情况下，除非业务案例已经涉及使用现有的原子服务，否则不鼓励使用复合微服务。例如，从储蓄账户进行信用卡支付需要调用两个服务，一个是借记储蓄账户，另一个是贷记信用卡账户。复合微服务还引入了固有的复杂性，例如在分布式场景中难以处理的状态管理和事务。

+   **体验服务**：这些服务与客户旅程相关，并部署在基础架构的边缘。这些服务处理来自移动和 Web 应用程序的请求。这些服务通过使用诸如 API 网关之类的工具，通过反向代理公开。

# 微服务设计指南

整个微服务的概念是关于关注点的分离。这需要在具有不同责任的服务之间进行逻辑和架构上的分离。以下是设计微服务的一些建议。

这些指南符合 Heroku 工程师提出的 12 因素应用程序指南。

+   **轻量级**：微服务必须轻量级，以便实现更小的内存占用和更快的启动时间。这有助于更快的 MTTR，并允许服务部署在更小的运行时实例上，因此在水平方面更好地扩展。与重型运行时（如应用服务器）相比，更适合的是较小的运行时，如 Tomcat、Netty、Node.js 和 Undertow。此外，服务应该使用轻量级文本格式（如 JSON）或二进制格式（如 Avro、Thrift 或 Protocol Buffers）交换数据。

+   **响应式**：这适用于具有高并发负载或稍长的响应时间的服务。典型的服务器实现会阻塞线程以执行命令式编程风格。由于微服务可能依赖于其他微服务或 I/O 资源（如数据库），阻塞线程可能会增加操作系统的开销。响应式风格采用非阻塞 I/O，使用回调处理程序，并对事件做出反应。这不会阻塞线程，因此可以更好地增加微服务的可伸缩性和负载处理特性。例如，数据库驱动程序已开始支持响应式范例，比如 MongoDB 响应式流 Java 驱动程序。

+   **无状态**：无状态服务具有更好的扩展性和更快的启动速度，因为在关闭或启动时不需要在磁盘上存储状态。它们也更具弹性，因为终止服务不会导致数据丢失。无状态也是朝着轻量级的一步。如果需要状态，服务可以将状态存储委托给高速持久（键值）存储，或者将其保存在分布式缓存中。

+   **原子性**：这是微服务的核心设计原则。如果服务足够小并且执行可以独立完成的最小业务单元，那么它们应该易于更改、测试和部署。如果耦合度低，服务将更容易修改和独立部署。可能需要根据需要使用复合微服务，但设计应该受到限制。

+   **外部化配置**：传统上，典型的应用程序属性和配置是作为配置文件进行管理的。鉴于微服务的多个和大规模部署，随着服务规模的增加，这种做法将变得繁琐。因此，最好将配置外部化到配置服务器中，以便可以按环境在分层结构中进行维护。诸如热更改之类的功能也可以更容易地同时反映多个服务。

+   **一致性**：服务应该按照编码标准和命名约定指南以一致的风格编写。常见关注点，如序列化、REST、异常处理、日志记录、配置、属性访问、计量、监控、供应、验证和数据访问应该通过可重用资产、注释等一致地完成。另一个团队的开发人员应该更容易理解服务的意图和操作。 

+   **具有弹性**：服务应该处理由技术原因（连接性、运行时）和业务原因（无效输入）引起的异常，并且不会崩溃。它们应该使用超时和断路器等模式来确保故障得到谨慎处理。

+   **良好的服务对象**：通过 JMX API 报告其使用统计数据、访问次数、平均响应时间等，并/或通过库发布到中央监控基础设施、日志审计、错误和业务事件中。通过健康检查接口公开其状态，例如 Spring Actuator 所做的那样。

+   **版本化**：微服务可能需要支持不同客户端的多个版本，直到所有客户端迁移到更高版本。因此，部署和 URL 应该支持语义版本控制，即 X.X.X。

此外，微服务还需要利用通常在企业级别构建的额外能力，比如：

+   **动态服务注册表**：微服务在启动时会向服务注册表注册自己。

+   **日志聚合**：微服务生成的日志可以被聚合起来进行集中分析和故障排除。日志聚合是一个独立的基础设施，通常建立为异步模型。产品如 Splunk 和 ELK Stack 与事件流（如 Kafka）一起被用来构建/部署日志聚合系统。

+   **外部配置**：微服务可以从外部配置（如 Consul 和 Zookeeper）中获取参数和属性以初始化和运行。

+   **供应和自动扩展**：如果 PaaS 环境检测到需要根据传入负载启动额外实例、某些服务失败或未及时响应，则服务将自动启动。

+   **API 网关**：微服务接口可以通过 API 网关向客户端或其他部门公开，提供抽象、安全性、限流和服务聚合。

在我们开始构建和部署服务时，我们将在后续章节中涵盖所有服务设计指南。

# 设计和部署模式

在您开始设计应用程序时，您需要了解各种服务设计和集成模式。

# 设计模式

微服务设计模式可以根据所解决的问题进行多种分类。最常见的分类和相关模式将在以下部分讨论。

# 内容聚合模式

随着微服务和有界上下文，内容聚合有了额外的责任。客户端可能需要跨多个领域或业务领域（或在解决方案术语中，有界上下文）获取信息。所需的内容可能无法由一个服务提供。这些模式有助于识别和建模体验服务类别。因此，有各种聚合模式可以应用。

# 客户端聚合

最后一英里的聚合。这适用于 Web 浏览器或合理的*处理能力*用户界面，它显示来自各个领域的内容。这种模式通常用于聚合各种主题领域的主页。此外，这是亚马逊广泛使用的模式。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/b012f926-e78e-4ed4-852f-7da40ffff847.jpg)

**好处**

使用客户端模式进行聚合的好处如下：

+   服务层的解耦方法。更容易实现每个单独服务的灵活性和可维护性。

+   在 UI 层面，感知性能更快，因为请求可以并行运行，以填充屏幕上的各个区域。当有更高的带宽可用于并行获取数据时，效果更好。

**权衡**

与客户端模式相关的权衡如下：

+   需要复杂的用户界面处理能力，如 Ajax 和单页面应用程序。

+   聚合的知识暴露在 UI 层，因此，如果类似的输出被作为数据集提供给第三方，就需要进行聚合。

# API 聚合

在门上进行聚合。这适用于不想了解聚合细节的移动或第三方用例，而是希望在单个请求中期望一个数据结构。API 网关被设计用于进行此聚合，然后向客户端公开统一的服务。如果在内容聚合期间不需要显示任何数据部分，API 网关也可以选择消除这些数据部分：

！[](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/6350e60c-8796-421c-854a-487e27090da7.jpg)

**好处**

使用 API 聚合模式的好处如下：

+   API 网关将客户端与个别服务的细节抽象出来。因此，它可以在不影响客户端层的情况下灵活更改服务。

+   在带宽受限的情况下更好，不适合运行并行 HTTP 请求的情况。

+   在 UI 处理受限的情况下更好，处理能力可能不足以进行并发页面生成。

**权衡**

与 API 聚合模式相关的权衡如下：

+   在有足够带宽的情况下，此选项的延迟高于客户端的聚合。这是因为 API 网关在发送数据给客户端之前需要等待所有内容被聚合。

# 微服务聚合

业务层的聚合。在这种方法中，一个微服务聚合来自各个组成微服务的响应。如果在聚合数据时需要应用任何实时业务逻辑，这种模式非常有用。例如，显示跨各种业务的客户持有总价值：

！[](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/2a298f28-adc3-4fa9-890d-e21915cb946c.jpg)

**好处**

使用微服务聚合模式的好处如下：

+   对聚合的更精细控制。此外，还有可能根据聚合数据应用业务逻辑。因此，提供了更丰富的内容聚合能力。

+   对 API 网关能力的依赖较低。

**权衡**

与微服务聚合模式相关的权衡如下：

+   由于引入了额外的步骤，延迟更低，代码更多。

+   失败或出错的机会更多。来自微服务的并行聚合将需要诸如响应式或回调机制等复杂的代码。

# 数据库聚合

数据层的聚合。在这种方法中，数据被预先聚合到一个**运营数据存储**（**ODS**）中，通常是文档数据库。这种方法对于存在额外业务推断的情况非常有用，这些推断很难通过微服务实时计算，因此可以由分析引擎预先计算：

！[](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/bf820d8a-153c-4fe8-b19b-349ca501f6e3.jpg)

**好处**

使用数据库聚合模式的好处如下：

+   通过分析作业对数据进行额外丰富。例如，在基于 ODS 中聚合的客户投资组合的客户 360°视图中，可以应用额外的分析来实现**下一步最佳行动**（**NBA**）场景。

+   与早期方法相比更灵活和功能更强，对数据模型可以进行更精细的控制。

**权衡**

与数据库聚合模式相关的权衡如下：

+   更高的复杂性

+   数据重复和更多的数据存储需求

+   需要额外的 ETL 或**变更数据捕获**（**CDC**）工具来将数据从记录系统发送到中央 ODS 存储

# 协调模式

理想情况下，微服务应该能够执行业务工作单元。然而，在某些业务场景中，微服务必须利用其他服务作为依赖项或组合。例如，考虑首先从储蓄账户借记，然后向信用卡账户贷记的信用卡支付。在这种情况下，两个基础服务，如借记和贷记，可以由各自的储蓄账户和信用卡领域公开，并且它们之间需要协调。

# 业务流程管理（BPM）

涉及长时间运行过程的复杂协调最好由 BPM 完成。企业可能已经拥有 BPM 产品。然而，对于简单的两步或三步协调，BPM 可能过于复杂。

# 复合服务

指导方针是对于低复杂度（或简单）但高容量的协调使用复合服务。在讨论的其余部分，这样的协调可以被称为微流程。

# 为什么使用复合服务？

在微服务架构中，服务定义的实现是通过较小的可部署单元而不是在应用服务器中运行的大型单体应用程序来完成的。这使得服务更容易编写，更快更改和测试，以及更快部署。但这也为跨两个或多个微服务的微流程，甚至跨多个有界上下文的微流程带来了挑战。在单体应用程序中，这样的微流程可以作为单个事务在单个可部署单元中部署的两个模块之间的协调。在微服务架构中，分布式事务是不鼓励的，因此，微流程必须使用组合方法来解决。

# 微服务协调的能力

本节列出了复合服务所需的能力：

+   **状态管理**：通常需要状态管理器组件来管理它协调的服务的输出状态。这种状态将需要保存在对**服务器端状态管理**（**SSM**）故障免疫的持久存储中。另一个 SSM 实例应该能够检索状态并从上次离开的地方开始。

+   **事务控制**：微服务会影响事务边界。现在，对单个事务中的两个方法进行两个独立的函数调用，现在变成了通过复合服务进行两个独立的服务调用。有两种方法来处理这种情况。

+   **分布式事务**：这些支持两阶段提交协议。它们不具有可伸缩性，会增加延迟和死锁情况，并且需要昂贵的产品和基础设施来支持它们。它们可能不受选定协议的支持，例如 REST 或消息传递。这种风格的好处是系统始终处于一致的状态。

+   **补偿事务**：在这种情况下，事务控制是通过运行功能性反向事务来实现，而不是尝试回滚到较早的事务。这是一种更解耦的，因此可扩展的方法。

由于技术产品要求的简化，我们建议使用补偿事务而不是分布式事务。

+   **邮件服务调度**：原子服务调用可能会成功，也就是说，当组成服务成功完成其工作时；或者失败，当协调服务之一未响应或由于技术或功能错误而在处理中失败时。复合服务将需要获取已完成服务的响应，并决定下一步的行动。

+   **超时处理**：在启动微流程时启动计时器。如果服务在启动微流程后的特定时间内没有响应，则触发一个事件发送到事件总线。

+   **可配置性**：SSM 组件的多个实例将运行以满足各种微流程。在每个微流程中，服务协调、计时器和操作都会有所不同。因此，提供一个可以对计时器、补偿事务和后处理操作进行参数化配置的框架非常重要。

# 协调模型

我们将讨论复合服务微流程的以下协调样式。

# 异步并行

复合服务异步地启动对组成原子服务的服务调用，然后监听服务响应。如果任一服务失败，它会向另一个服务发送补偿事务。

这类似于 EIP 的散射-聚集或组合消息处理器模式：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/e0536935-ad8e-4c6e-81b2-f071cd6a3f31.jpg)

# 异步顺序

在管道处理中，复合服务按顺序向原子服务发送消息。它在调用下一个服务之前等待前一个服务返回成功。如果任何一个服务失败，那么复合服务将向先前成功的服务发送补偿事务。这类似于 EIP 中的过程管理器模式：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/70b88b81-c1d8-4343-9436-a0291742dc0c.jpg)

# 使用请求/响应进行编排

与前面的部分类似，但是以请求/响应和同步方式进行，而不是异步消息传递。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/3730ee35-9058-4174-931c-36a88e596599.jpg)

# 合并微服务

当复合服务与其组成微服务之间存在耦合时，可以将服务合并并作为单个组件运行。例如，可以通过账户服务实现资金转移，额外的`transferFunds`方法接受`fromAcc`、`toAcc`和资金金额。然后，它可以作为单个事务的一部分发出`debit`和`credit`方法调用。然而，这种方法需要经过充分考虑后才能决定。缺点包括耦合部署信用卡和储蓄领域的借记和贷记服务：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/eb3a11c8-fbb0-4660-b108-c5e79c1cbfcc.jpg)

# 部署模式

微服务试图解决单体应用程序的问题，如依赖关系，并通过具有单独的可部署单元来实现敏捷性。我们可以以各种风格将微服务部署到目标运行时。这些选项按照隔离度（好）和成本（坏）的增加顺序进行描述。

# 每个 WAR 文件中的多个服务

尽管开发可能是以微服务风格进行的（为服务单独的代码库，不同的团队负责不同的服务），但部署基本上遵循单体应用程序的风格：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/f48fa51a-45b9-43f8-8dd5-9ce28884b1af.jpg)

# 利弊

与完全的单体应用程序风格相比，唯一的好处是由于有单独的代码库和较少的依赖关系，对通用代码元素的依赖较低。然而，它并不提供服务行为之间的运行时隔离，因此没有真正的微服务架构模型的好处，如独立发布、扩展单个服务或限制一个服务问题对其他服务的影响。

# 适用性

这并不是很有用的情况，因为它并不提供运行时隔离。然而，它可能是释放完全分离的中间步骤。

# 每个 WAR/EAR 的服务

该模型将服务的构建过程分离，以创建每个服务的单独`.war`/`.ear`文件。然而，它们最终被部署到同一个 Web 容器或应用服务器中：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/c52a556c-117e-49b5-9ab9-f38453782e33.jpg)

# 利弊

这种风格通过将每个服务的构建过程分开来创建可部署单元，进一步提高了隔离。然而，由于它们部署在同一个 Web 容器或应用服务器上，它们共享相同的进程。因此，服务之间没有运行时隔离。

# 适用性

一些团队可能会在目标部署上遇到约束，使用与单体风格开发中使用的相同软件或硬件。在这种情况下，这种部署风格是合适的，因为团队仍然可以独立开发，而不会互相干扰，但在部署到传统生产基础设施时，他们将不得不与其他团队协调发布。

# 每个进程的服务

这种风格使用了之前讨论过的 fat JAR 的概念，将应用服务器或 Web 容器作为部署单元的一部分。因此，目标运行环境只需要一个 JVM 来运行服务。Dropwizard 和 Spring Boot 框架鼓励这种类型的部署构建。我们还在第二章中看到了创建这样一个部署单元的示例，*编写您的第一个云原生应用程序*：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/c8fe032a-2988-45d1-a845-256cfb2f8eba.jpg)

# 好处和权衡

与每个进程风格相关的服务的好处和权衡如下：

+   这种方法有助于分离服务运行的运行时进程。因此，它在服务之间创建了隔离，这样一个进程中的内存泄漏或 fat 异常不会在一定程度上影响其他服务。

+   这允许有选择地扩展服务，允许在现有硬件上部署更多的服务，与其他服务相比。

+   它还给团队自由，可以根据特定用例或团队需求使用不同的应用服务器/ Web 容器。

+   然而，它无法阻止任何一个服务占用系统资源（如 CPU、I/O 和内存），从而影响其他服务的性能。

+   它还减少了运维团队对运行时的控制，因为在这种模型中没有中央 Web 容器或应用服务器。

+   这种风格需要良好的治理来限制部署环境的变化，并且需要有实质性的用例来支持分歧。

# 适用性

这种风格为那些受限于使用现有生产基础设施并且尚未拥有 Docker 容器或小型 VM 配置的团队提供了最佳折衷方案。

# 每个 Docker 容器的服务

在这种风格中，服务以一个带有必要先决条件（如 JVM）的 Docker 容器中的 fat JAR 部署。它比 Linux 容器技术提供的隔离更高一步：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/7f1a6c81-2592-44fa-8dc1-e9c7150e9978.jpg)

# 好处和权衡

与每个 Docker 容器风格相关的服务的好处和权衡如下：

+   Linux 容器技术限制了服务的 CPU 和内存消耗，同时提供了网络和文件访问隔离。这种隔离程度对许多服务来说是足够的。

+   容器从镜像启动速度快。因此，可以非常快速地生成基于应用程序或服务镜像的新容器，以满足应用程序的波动需求。

+   容器可以通过各种编排机制进行编排，例如 Kubernetes、Swarm 和 DC/OS，以便根据明确定义的应用蓝图自动创建整个应用程序配置。

+   与之前的风格一样，可以在容器中运行各种服务技术。例如，除了 Java 服务外，还可以运行 Node.js 服务，因为容器镜像将位于操作系统级别，因此可以由编排框架无缝启动。

+   容器在资源需求方面的开销比虚拟机低得多，因为它们更轻量级。因此，与在自己的虚拟机中运行每个服务相比，它们更便宜。

+   然而，容器重用主机系统的内核。因此，无法在容器技术上运行需要不同操作系统的工作负载，例如 Windows 或 Solaris。

# 适用性

这种部署风格在隔离和成本之间取得了很好的平衡。这是推荐的风格，适用于大多数服务部署。

# 每个虚拟机一个服务

在这种风格中，fat JAR 直接部署在虚拟机上，就像*每个进程一个服务*部分一样。然而，在这里，每个虚拟机只部署一个服务。这确保了该服务与其他服务完全隔离。

部署是通过诸如 Chef 和 Puppet 等工具自动化的，这些工具可以获取基础镜像（例如已安装 Java）然后运行一系列步骤在虚拟机上安装应用程序 JAR 和其他实用程序：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/297b14b8-8750-453a-9710-d2145cab55a1.png)

# 优点和权衡

与每个虚拟机一个服务风格相关的优点和权衡如下：

+   如果有任何需要完全 OS 级别隔离的用例，那么这种风格是合适的

+   这种风格还允许我们在虚拟机上混合完全不同的工作负载，例如 Linux、Windows 和 Solaris

+   然而，与前一种风格相比，这种风格更加资源密集，启动速度更慢，因为虚拟机包括完整的客户操作系统启动

+   因此，与之前的选项相比，它的成本效率较低

# 适用性

这种部署风格倾向于增加成本。这是推荐的风格，适用于云镜像部署，例如创建**Amazon Machine Images**（**AMI**）。

# 每个主机一个服务

这将隔离从虚拟机的 hypervisor（对于虚拟机）提升到硬件级别，通过在不同的物理主机上部署服务。可以使用微服务器或专门的设备概念来实现这一目的。

# 优点和权衡

与每个主机一个服务风格相关的优点和权衡如下：

+   硬件（如处理器、内存和 I/O）可以完全调整到服务的用例。英特尔提供了一系列微服务器，针对特定任务进行了调整，例如图形处理、Web 内容服务等。

+   这种解决方案可以实现非常高的组件密度。

+   这种部署风格适用于非常少数需要从硬件级别隔离或专门硬件需求中受益的用例。

+   这是一种成熟的技术，因此目前还没有很多数据中心云提供商提供。然而，到本书出版时，它将已经成熟。

# 适用性

这种部署风格非常罕见，因为很少有用例需要这种高级别的隔离或专门的硬件要求。Web 内容或图形处理的设备是一些受益于这种部署风格的专门用例。

# 发布模式

以下是服务中使用的不同发布模式：

+   **Fat JAR**：如第二章中所讨论的，*编写您的第一个云原生应用程序*，fat JAR 有助于将 Web 容器与可部署内容捆绑在一起。这确保了在开发、测试和生产环境中部署版本之间没有不一致。

+   **蓝绿部署**：这种模式建议维护两个相同的生产环境。新版本发布到一个未使用的环境，比如绿色环境。从路由器切换流量到绿色部署。如果成功，绿色环境将成为新的生产环境，蓝色环境可以被停用。如果出现问题，回滚更容易。下一个周期将以相反的方式进行，部署到蓝色环境，因此在两个环境之间交替。存在一些挑战，比如数据库升级。对于异步微服务，可以使用这种技术来发布一个微服务或一组具有不同输入队列的微服务。从连接参数加载的配置决定将请求消息放入一个队列还是另一个队列。

+   **语义化版本控制**：语义化版本控制是关于使用版本号发布软件，以及它们如何改变底层代码的含义，以及从一个版本到下一个版本进行了什么修改。有关更多详细信息，请参阅[`semver.org/`](http://semver.org/)。在异步微服务中，使用每个微服务一个输入队列的类似策略适用。然而，在这种情况下，两个服务都是活动的，一个用于传统的服务，一个用于新的更改。根据请求，可以使用基于内容的路由模式来切换队列以发送请求。

+   **金丝雀发布**：这种模式用于向一小部分用户引入变更，使用选择一组客户的路由逻辑来实现。在异步服务方面，可以通过两组输入队列来处理，重定向逻辑现在决定将请求消息放入哪个队列。

+   **不可变服务器/不可变交付**：不可变服务器和不可变交付是相关的。其目的是从配置管理存储库自动构建服务器（虚拟机或容器）及其软件和应用程序。构建后，它不会被改变，即使在从一个环境移动到另一个环境时也不会改变。只有配置参数通过环境、JNDI 或独立的配置服务器注入，比如 Consul 或使用 Git。这确保在生产部署中没有未记录在版本控制系统中的临时更改。

+   **功能切换**：这允许在生产中发布的功能从一些配置设置中切换开或关。这个切换通常在前端或 API 网关实现，以便可以对服务/功能的最终用户可见或不可见。这种模式对于暗黑发布能力非常有用，这将在接下来的部分中讨论。

+   **暗黑发布**：由 Facebook 推广。暗黑发布意味着在计划发布之前很长时间将服务/能力发布到生产中。这为在生产环境中测试集成点和复杂服务提供了机会。只有前端或 API 的更改使用了之前讨论的金丝雀发布和功能切换。

# 微服务的数据架构

微服务的一个关键设计理念是有界上下文和管理数据存储的服务。在有界上下文中，多个服务可能访问一个共同的数据存储，或者采用每个服务一个数据存储的范式。

由于可能有多个服务实例在运行，我们如何确保数据读取/更新操作不会导致资源死锁？

# 命令查询职责分离（CQRS）

CQRS 引入了一个有趣的范例，挑战了使用相同数据存储来创建/更新和查询系统的传统思想。其思想是将改变系统状态的命令与幂等的查询分开。物化视图就是这种模式的一个例子。这种分离还提供了使用不同的数据模型进行更新和查询的灵活性。例如，关系模型可以用于更新，但从更新生成的事件可以用于更新更适合读取的缓存或文档数据库。

用户请求可以广泛分类为两部分，即改变系统状态的命令和为用户获取系统状态的查询。对于命令处理，参与系统收集足够的业务数据，以便可以调用系统记录上的相应服务来执行命令。对于查询，参与系统可以选择要么调用系统记录，要么从专为读取工作负载而设计的本地存储获取信息。这种策略的分离可以产生巨大的好处，例如减少对系统记录的负载和减少延迟：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/c93f51b6-b83a-48e0-82f8-bc87cf924514.jpg)

CQRS 模式有助于利用旧的记录系统以及较新的文档数据库和缓存。我们将在下一章中介绍如何在您的服务中实现 CQRS。

# 数据重复

在有界上下文内，服务是数据的监护人。但是如果另一个服务需要您数据的子集怎么办？一些可能出现的问题/解决方案如下：

+   我应该调用服务来获取那些数据吗？

+   服务之间的通信增加

+   两个服务之间的紧密耦合

+   我可以直接从另一个有界上下文中访问数据存储吗？

+   打破了有界上下文模型

那么，另一个服务（驻留在另一个有界上下文中）如何访问数据的子集？（例如，在个性化服务中需要客户的地址属性（来自客户服务）。）

在这种情况下，最好的方法是从主域中复制数据。所需的更改由主域发布为事件，任何对这些更改感兴趣的域都会订阅这些事件。事件从事件总线中获取，并且使用事件中的数据来更新重复数据存储中的更改：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/6bcb5d57-6147-4089-91aa-1730ea807be3.jpg)

# 好处

复制数据的好处如下：

+   有助于解耦服务边界

+   包含数据的业务事件是服务之间唯一的关系

+   有助于避免跨边界的昂贵分布式事务模型

+   允许我们在不妨碍系统其他部分进展的情况下对服务边界进行更改

+   我们可以决定希望多快或多慢地看到外部世界的其余部分，并最终变得一致

+   使用适合我们服务模型的技术在我们自己的数据库中存储数据的能力

+   灵活性使我们能够对架构/数据库进行更改

+   使我们变得更具可伸缩性、容错性和灵活性

# 缺点

复制数据相关的缺点如下：

+   大量数据更改可能意味着两端需要更强大的基础设施，并且处理丢失事件的能力需要事件的持久性

+   导致最终一致性模型

+   复杂的系统，非常难以调试

# 适用于特定目的

有界上下文模型意味着所包含的数据只能通过定义的服务接口或 API 进行修改。这意味着实际的模式或用于存储数据的存储技术对 API 功能没有影响。这使我们有可能使用适合特定目的的数据存储。如果我们正在构建搜索功能，并且内存数据存储对于给定的业务需求更合适，我们可以继续使用它。

由于数据访问受服务 API 的管理，数据存储的选择和结构对实际服务消费者来说并不重要：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cld-ntv-app-java/img/4d5744e3-2db6-470b-9e66-1f0c55d6aef7.jpg)

服务 API 模型还提供了灵活性，可以在不影响其他消费服务的情况下从一个数据存储转移到另一个数据存储，只要服务契约得到维护。Martin Fowler 将其称为多语言持久性。

# 安全性的作用

随着微服务的普及，管理这些服务的安全性的挑战变得更加困难。除了**开放式 Web 应用安全项目**（**OWASP**）十大网络漏洞之外，还需要回答一些问题，例如：

+   服务在服务调用之前是否需要客户端进行身份验证（例如 OAuth）？

+   客户端是否可以调用任何服务，还是只能调用其被授权的服务？

+   服务是否知道请求的发起客户端的身份，并且是否将其传递给下游服务？下游服务是否有机制来验证其调用的授权？

+   服务之间的流量调用是否安全（HTTPS）？

+   我们如何验证来自经过身份验证的用户的请求是否未被篡改？

+   我们如何检测并拒绝请求的重放？

在分布式微服务模型中，我们需要控制和限制调用方的特权，以及在安全漏洞的情况下每次调用可访问的数据量（最小特权）。大量的微服务和支持数据库意味着存在需要保护的大攻击面。服务之间的服务器加固变成了保护网络的重要和关键活动。监控服务访问并对威胁进行建模非常重要，以分解我们最脆弱的流程并集中精力进行防范。我们将看到 API 网关在解决一些安全问题方面的作用。

# 总结

这让我们得出了云应用程序的设计原则的结论。在本章中，您了解了 API 受欢迎的原因，如何解耦您的单体应用程序，以及微服务设计的各种模式和数据架构原则。我们还看到了微服务中安全性的作用以及 API 网关的作用。

在下一章中，我们将以第二章中的示例，*编写您的第一个云原生应用程序*，并开始添加更多内容，使其更适合生产。我们将添加数据访问，缓存选项及其考虑因素，应用 CQRS 和错误处理。
