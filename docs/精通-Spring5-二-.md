# 精通 Spring5（二）

> 原文：[`zh.annas-archive.org/md5/73290E1F786F5BAA832E07A902070E3F`](https://zh.annas-archive.org/md5/73290E1F786F5BAA832E07A902070E3F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：向微服务和云原生应用的演进

在过去的十年中，Spring 框架已经发展成为开发 Java 企业应用程序的最流行框架。Spring 框架使开发松耦合、可测试的应用程序变得容易。它简化了横切关注点的实现。

然而，今天的世界与十年前大不相同。随着时间的推移，应用程序变得庞大而难以管理。由于这些问题，新的架构开始演变。最近的热词是 RESTful 服务、微服务和云原生应用程序。

在本章中，我们将从回顾 Spring 框架在过去十年中解决的问题开始。我们将了解**单片应用程序**的问题，并介绍更小、独立部署的组件的世界。

我们将探讨为什么世界正在向微服务和云原生应用程序发展。我们将结束本章，看看 Spring 框架和 Spring 项目如何发展以解决当今的问题。

本章将涵盖以下主题：

+   基于 Spring 的典型应用程序架构

+   Spring 框架在过去十年中解决的问题

+   我们开发应用程序时的目标是什么？

+   单片应用程序存在哪些挑战？

+   什么是微服务？

+   微服务的优势是什么？

+   微服务存在哪些挑战？

+   有哪些好的实践可以帮助将微服务部署到云中？

+   有哪些 Spring 项目可以帮助我们开发微服务和云原生应用程序？

# 具有 Spring 的典型 Web 应用程序架构

在过去的十五年中，Spring 一直是连接 Java 企业应用程序的首选框架。应用程序使用分层架构，所有横切关注点都使用面向方面的编程进行管理。以下图表显示了使用 Spring 开发的 Web 应用程序的典型架构：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/14f46f15-3f3d-47c6-b9da-b8094b076498.png)

这样的应用程序中的典型层在这里列出。我们将把横切关注点列为一个单独的层，尽管在现实中，它们适用于所有层：

+   **Web 层**：通常负责控制 Web 应用程序流程（控制器和/或前端控制器）并呈现视图。

+   **业务层**：这是您的所有业务逻辑所在。大多数应用程序从业务层开始进行事务管理。

+   **数据层**：它还负责与数据库通信。这负责将 Java 对象中的数据持久化/检索到数据库中的表中。

+   **集成层**：应用程序与其他应用程序通信，可以通过队列或调用 Web 服务来实现。集成层与其他应用程序建立这样的连接。

+   **横切关注点**：这些是跨不同层的关注点--日志记录、安全性、事务管理等。由于 Spring IoC 容器管理 bean，它可以通过**面向方面的编程**（**AOP**）在 bean 周围编织这些关注点。

让我们更详细地讨论每个层和使用的框架。 

# Web 层

Web 层取决于您希望如何向最终用户公开业务逻辑。它是 Web 应用程序吗？还是您正在公开 RESTful Web 服务？

# Web 应用程序-呈现 HTML 视图

这些 Web 应用程序使用 Web MVC 框架，如 Spring MVC 或 Struts。视图可以使用 JSP、JSF 或基于模板的框架（如 Freemarker）进行呈现。

# RESTful 服务

用于开发 RESTful Web 服务的两种典型方法：

+   **JAX-RS**：用于 REST 服务的 Java API。这是 Java EE 规范的标准。Jersey 是参考实现。

+   **Spring MVC 或 Spring REST**：Restful 服务也可以使用 Spring MVC 开发。

Spring MVC 没有实现 JAX-RS，因此选择比较棘手。JAX-RS 是一个 Java EE 标准。但是 Spring MVC 更具创新性，更有可能帮助您更快地构建新功能。

# 业务层

业务层通常包含应用程序中的所有业务逻辑。在这一层中，使用 Spring 框架来连接 bean。

这也是事务管理边界开始的地方。事务管理可以使用 Spring AOP 或 AspectJ 来实现。十年前，**企业 Java Bean**（**EJB**）是实现业务层的最流行方法。由于其轻量级特性，Spring 现在是业务层的首选框架。

EJB3 比 EJB2 简单得多。然而，EJB3 发现很难赶上 Spring 失去的地位。

# 数据层

大多数应用程序与数据库通信。数据层负责将 Java 对象的数据存储到数据库中，反之亦然。以下是构建数据层的最流行方法：

+   **JPA**：**Java 持久化 API**帮助您将 Java 对象（POJOs）映射到数据库表。Hibernate 是 JPA 最流行的实现。JPA 通常适用于所有事务性应用程序。JPA 不是批处理和报告应用程序的最佳选择。

+   **MyBatis**：MyBatis（以前是 iBatis）是一个简单的数据映射框架。正如其网站（[`www.mybatis.org/mybatis-3/`](http://www.mybatis.org/mybatis-3/)）所说，*MyBatis 是一个支持自定义 SQL、存储过程和高级映射的一流持久化框架。MyBatis 几乎消除了所有的 JDBC 代码和手动设置参数以及检索结果*。MyBatis 可以考虑用于更常用 SQL 和存储过程的批处理和报告应用程序。

+   **Spring JDBC**：JDBC 和 Spring JDBC 不再那么常用。

我们将在《第八章》*Spring Data*中详细讨论 JDBC、Spring JDBC、MyBatis 和 JPA 的优缺点。

# 集成层

集成层通常是我们与其他应用程序交流的地方。可能有其他应用程序通过 HTTP（Web）或 MQ 公开 SOAP 或 RESTful 服务。

+   Spring JMS 通常用于在队列或服务总线上发送或接收消息。

+   Spring MVC RestTemplate 可用于调用 RESTful 服务。

+   Spring WS 可用于调用基于 SOAP 的 Web 服务。

+   Spring Integration 提供了一个更高级的抽象层，用于构建企业集成解决方案。它通过清晰地分离应用程序和集成代码的关注点，实现了可测试性。它支持所有流行的企业集成模式。我们将在《第十章》*Spring Cloud Data Flow*中更多地讨论 Spring Integration。

# 横切关注点

横切关注点是通常适用于应用程序的多个层的关注点--日志记录、安全性和事务管理等。让我们快速讨论其中一些：

+   **日志记录**：可以使用面向方面的编程（Spring AOP 或 AspectJ）在多个层实现审计日志记录。

+   **安全性**：通常使用 Spring Security 框架来实现安全性。正如前一章所讨论的，Spring Security 使安全性的实现变得非常简单。

+   **事务管理**：Spring 框架为事务管理提供了一致的抽象。更重要的是，Spring 框架为声明式事务管理提供了很好的支持。以下是 Spring 框架支持的一些事务 API：

+   **Java 事务 API**（**JTA**）是事务管理的标准。它是 Java EE 规范的一部分。

+   JDBC。

+   JPA（包括 Hibernate）。

+   错误处理：Spring 提供的大多数抽象使用未检查的异常，因此除非业务逻辑需要，否则在暴露给客户（用户或其他应用程序）的层中实现错误处理就足够了。Spring MVC 提供了 Controller Advice 来实现整个应用程序中一致的错误处理。

Spring 框架在应用程序架构中扮演着重要角色。Spring IoC 用于将不同层中的 bean 连接在一起。Spring AOP 用于在 bean 周围编织交叉关注点。除此之外，Spring 还与不同层的框架提供了很好的集成。

在接下来的部分中，我们将快速回顾 Spring 在过去十年左右解决的一些重要问题。

# Spring 解决的问题

Spring 是连接企业 Java 应用程序的首选框架。它解决了自 EJB2 以来企业 Java 应用程序面临的许多问题。以下是其中的一些：

+   松耦合和可测试性

+   管道代码

+   轻量级架构

+   架构灵活性

+   简化交叉关注点的实现

+   最佳的免费设计模式

# 松耦合和可测试性

通过依赖注入，Spring 实现了类之间的松耦合。虽然松耦合对于长期应用的可维护性是有益的，但首先实现的好处是它带来的可测试性。

在 Spring 之前，Java EE（或当时称为 J2EE）并不擅长可测试性。测试 EJB2 应用程序的唯一方法是在容器中运行它们。对它们进行单元测试非常困难。

这正是 Spring 框架要解决的问题。正如我们在前面的章节中看到的，如果使用 Spring 来连接对象，编写单元测试会变得更容易。我们可以轻松地存根或模拟依赖项并将它们连接到对象中。

# 管道代码

20 世纪 90 年代末和 21 世纪初到中期的开发人员会熟悉必须编写大量管道代码来执行通过 JDBC 进行简单查询并将结果填充到 Java 对象中的情况。你必须执行 Java 命名和目录接口（JNDI）查找，获取连接并填充结果。这导致了重复的代码。通常，问题在每个方法中都会重复出现异常处理代码。而且这个问题并不仅限于 JDBC。

Spring 框架解决的问题之一是通过消除所有管道代码。通过 Spring JDBC、Spring JMS 和其他抽象，开发人员可以专注于编写业务逻辑。Spring 框架处理了繁琐的细节。

# 轻量级架构

使用 EJB 使应用程序变得复杂，并非所有应用程序都需要那种复杂性。Spring 提供了一种简化、轻量级的应用程序开发方式。如果需要分发，可以随后添加。

# 架构灵活性

Spring 框架用于在不同层中连接应用程序中的对象。尽管它一直存在，但 Spring 框架并没有限制应用架构师和开发人员的灵活性或选择框架的选择。以下是一些示例：

+   Spring 框架在 Web 层提供了很大的灵活性。如果你想使用 Struts 或 Struts 2 而不是 Spring MVC，是可以配置的。你可以选择与更广泛的视图和模板框架集成。

+   另一个很好的例子是数据层，你可以通过 JPA、JDBC 和映射框架（如 MyBatis）来连接。

# 简化交叉关注点的实现

当 Spring 框架用于管理 bean 时，Spring IoC 容器管理 bean 的生命周期——创建、使用、自动连接和销毁。这使得更容易在 bean 周围编织额外的功能，比如交叉关注点。

# 免费的设计模式

Spring Framework 默认鼓励使用许多设计模式。一些例子如下：

+   **依赖注入或控制反转**：这是 Spring Framework 建立的基本设计模式。它实现了松散耦合和可测试性。

+   **单例**：所有 Spring bean 默认都是单例。

+   **工厂模式**：使用 bean 工厂来实例化 bean 是工厂模式的一个很好的例子。

+   **前端控制器**：Spring MVC 使用 DispatcherServlet 作为前端控制器。因此，当我们使用 Spring MVC 开发应用程序时，我们使用前端控制器模式。

+   **模板方法**：帮助我们避免样板代码。许多基于 Spring 的类--JdbcTemplate 和 JmsTemplate--都是这种模式的实现。

# 应用程序开发目标

在我们转向 REST 服务、微服务和云原生应用程序的概念之前，让我们花些时间了解我们开发应用程序时的共同目标。了解这些目标将有助于我们理解为什么应用程序正在向微服务架构转变。

首先，我们应该记住，软件行业仍然是一个相对年轻的行业。在我十五年的软件开发、设计和架构经验中，一直有一件事是不变的，那就是事物的变化。今天的需求不是明天的需求。今天的技术不是明天我们将使用的技术。虽然我们可以尝试预测未来会发生什么，但我们经常是错误的。

在软件开发的最初几十年中，我们做的一件事是为未来构建软件系统。设计和架构被复杂化，以应对未来的需求。

在过去的十年中，随着**敏捷**和**极限编程**，重点转向了**精益**和构建足够好的系统，遵循基本的设计原则。重点转向了演进式设计。思考过程是这样的：**如果一个系统对今天的需求有良好的设计，并且不断发展并且有良好的测试，它可以很容易地重构以满足明天的需求**。

虽然我们不知道我们的方向，但我们知道在开发应用程序时的大部分目标并没有改变。

对于大量应用程序的软件开发的关键目标可以用“规模上的速度和安全”来描述。

我们将在下一节中讨论这些元素。

# 速度

交付新需求和创新的速度越来越成为一个关键的区分因素。快速开发（编码和测试）已经不够了。快速交付（到生产环境）变得很重要。现在已经普遍认识到，世界上最好的软件组织每天多次将软件交付到生产环境。

技术和商业环境是不断变化和不断发展的。关键问题是“一个应用程序能够多快地适应这些变化？”。这里强调了技术和商业环境中的一些重要变化：

+   新的编程语言

+   Go

+   Scala

+   闭包

+   新的编程范式

+   函数式编程

+   响应式编程

+   新框架

+   新工具

+   开发

+   代码质量

+   自动化测试

+   部署

+   容器化

+   新的流程和实践

+   敏捷

+   测试驱动开发

+   行为驱动开发

+   持续集成

+   持续交付

+   DevOps

+   新设备和机会

+   移动

+   云

# 安全

速度没有安全有什么用？谁会想要乘坐一辆可以以每小时 300 英里的速度行驶但没有适当安全功能的汽车呢？

让我们考虑一个安全应用程序的几个特点：

# 可靠性

可靠性是系统功能的准确度的度量。

要问的关键问题如下：

+   系统是否满足其功能要求？

+   在不同的发布阶段泄漏了多少缺陷？

# 可用性

大多数外部面向客户的应用程序都希望全天候可用。可用性是衡量应用程序对最终用户可用的时间百分比。

# 安全性

应用程序和数据的安全对组织的成功至关重要。应该有明确的程序进行身份验证（你是你声称的那个人吗？）、授权（用户有什么访问权限？）和数据保护（接收或发送的数据是否准确？数据是否安全，不会被意外用户拦截？）。

我们将在《第六章》中更多地讨论如何使用 Spring Security 实现安全性，*扩展微服务*。

# 性能

如果一个 Web 应用程序在几秒内没有响应，你的应用程序的用户很有可能会感到失望。性能通常指的是系统在为定义数量的用户提供约定的响应时间的能力。

# 高弹性

随着应用程序变得分布式，故障的概率增加。应用程序在出现局部故障或中断的情况下会如何反应？它能否在完全崩溃的情况下提供基本操作？

应用程序在出现意外故障时提供最低限度的服务水平的行为被称为弹性。

随着越来越多的应用程序向云迁移，应用程序的弹性变得重要。

我们将在《第九章》中讨论如何使用*Spring Cloud 和 Spring Data Flow*构建高度弹性的微服务，*Spring Cloud*和《第十章》*Spring Cloud Data Flow*。

# 可伸缩性

可伸缩性是衡量应用在其可用资源被扩展时的反应能力。如果一个应用程序在给定基础设施支持 10,000 用户，它能否在双倍基础设施的情况下支持至少 20,000 用户？

如果一个 Web 应用程序在几秒内没有响应，你的应用程序的用户很有可能会感到失望。性能通常指的是系统在为定义数量的用户提供约定的响应时间的能力。

在云的世界中，应用程序的可伸缩性变得更加重要。很难猜测一个创业公司可能会有多成功。Twitter 或 Facebook 在孵化时可能没有预料到这样的成功。他们的成功在很大程度上取决于他们如何能够适应用户基数的多倍增长而不影响性能。

我们将在《第九章》中讨论如何使用 Spring Cloud 和 Spring Data Flow 构建高度可伸缩的微服务，*Spring Cloud*和《第十章》*Spring Cloud Data Flow*。

# 单体应用的挑战

在过去的几年里，除了与几个小应用程序一起工作，我还有机会在不同领域的四个不同的单体应用程序上工作--保险、银行和医疗保健。所有这些应用程序都面临着非常相似的挑战。在本节中，我们将首先看一下单体应用的特征，然后再看看它们带来的挑战。

首先：什么是单体应用？一个有很多代码的应用--可能超过 10 万行代码？是的。

对我来说，单体应用是那些在将发布推向生产环境时面临巨大挑战的应用。属于这一类别的应用有许多用户需求是迫切需要的，但这些应用可能每隔几个月才能发布新功能。有些应用甚至每季度发布一次功能，有时甚至少至一年两次。

通常，所有的单体应用都具有这些特征：

+   **体积庞大**：大多数这些单片应用有超过 10 万行的代码。有些代码库超过 100 万行代码。

+   **团队庞大**：团队规模可能从 20 到 300 不等。

+   **多种做同一件事的方式**：由于团队庞大，存在沟通障碍。这导致应用程序不同部分对同一问题有多种解决方案。

+   **缺乏自动化测试**：大多数这些应用几乎没有单元测试，也完全缺乏集成测试。这些应用高度依赖手动测试。

由于这些特点，这些单片应用面临许多挑战。

# 发布周期长

在单片的一个部分进行代码更改可能会影响单片的其他部分。大多数代码更改都需要完整的回归周期。这导致发布周期很长。

由于缺乏自动化测试，这些应用依赖手动测试来发现缺陷。将功能上线是一个重大挑战。

# 难以扩展

通常，大多数单片应用不是云原生的，这意味着它们不容易部署在云上。它们依赖手动安装和手动配置。通常在将新应用实例添加到集群之前，运维团队需要投入大量工作。这使得扩展规模成为一个重大挑战。

另一个重要的挑战是大型数据库。通常，单片应用的数据库容量达到**TB**级别。当扩展规模时，数据库成为瓶颈。

# 调整新技术

大多数单片应用使用旧技术。将新技术添加到单片中只会使其更难以维护。架构师和开发人员不愿引入任何新技术。

# 调整新方法

敏捷等新方法需要小型（四至七人的团队）。单片的重要问题是：我们如何防止团队互相干扰？我们如何创建能够使团队独立工作的岛屿？这是一个难以解决的挑战。

# 现代开发实践的调整

现代开发实践，如**测试驱动开发**（**TDD**）、**行为驱动开发**（**BDD**）需要松耦合、可测试的架构。如果单片应用具有紧密耦合的层和框架，很难进行单元测试。这使得调整现代开发实践具有挑战性。

# 了解微服务

单片应用的挑战导致组织寻找解决方案。我们如何能够更频繁地上线更多功能？

许多组织尝试了不同的架构和实践来寻找解决方案。

在过去几年中，所有成功做到这一点的组织中出现了一个共同模式。从中产生了一种被称为**微服务架构**的架构风格。

正如 Sam Newman 在《构建微服务》一书中所说：许多组织发现，通过拥抱细粒度、微服务架构，他们可以更快地交付软件并采用更新的技术。

# 什么是微服务？

我在软件中喜欢的一个原则是*保持小型*。无论你在谈论什么，这个原则都适用——变量的范围、方法、类、包或组件的大小。你希望所有这些都尽可能小。

微服务是这一原则的简单延伸。它是一种专注于构建小型基于能力的独立可部署服务的架构风格。

没有一个单一的微服务定义。我们将看一些流行的定义：

“微服务是小型、自治的服务，彼此协同工作”

- Sam Newman，Thoughtworks

“松耦合的面向服务的架构与有界上下文”

- Adrian Cockcroft, Battery Ventures

“微服务是有界范围内的独立部署组件，通过基于消息的通信支持互操作性。微服务架构是一种由能力对齐的微服务组成的高度自动化、可演进的软件系统的工程风格”在《微服务架构》一书中

- Irakli Nadareishvili, ‎Ronnie Mitra, ‎Matt McLarty

虽然没有公认的定义，但所有微服务定义中通常具有一些特征。在我们看微服务的特征之前，我们将尝试了解整体情况-我们将看看没有微服务的架构与使用微服务的架构相比如何。

# 微服务架构

单体应用程序-即使是模块化的-也有一个可部署的单元。下图显示了一个具有三个模块的单体应用程序的示例，模块 1、2 和 3。这些模块可以是单体应用程序的一部分的业务能力。在购物应用程序中，其中一个模块可能是产品推荐。

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/55f0018d-98ab-4e04-832f-a78c693e8f53.png)

以下图显示了使用微服务架构开发的前一个单体应用程序的样子：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/ea2b1e73-54dd-4612-8346-d95ee4392fef.png)

需要注意的一些重要事项如下：

+   模块是基于业务能力进行识别的。模块提供了什么功能？

+   每个模块都可以独立部署。在下面的示例中，模块 1、2 和 3 是单独的可部署单元。如果模块 3 的业务功能发生变化，我们可以单独构建和部署模块 3。

# 微服务特征

在前一节中，我们看了一个微服务架构的例子。对于成功适应微服务架构风格的组织的经验评估表明，团队和架构共享了一些特征。让我们看看其中一些：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/c29a5bb1-1fcc-42eb-b70a-318000004230.png)

# 小型和轻量级微服务

良好的微服务提供了业务能力。理想情况下，微服务应遵循“单一责任原则”。因此，微服务通常规模较小。通常，我使用的一个经验法则是应该能够在 5 分钟内构建和部署一个微服务。如果构建和部署需要更长时间，很可能正在构建一个比推荐的微服务更大的服务。

一些小型和轻量级微服务的例子如下：

+   产品推荐服务

+   电子邮件通知服务

+   购物车服务

# 基于消息的通信的互操作性

微服务的关键重点是互操作性-使用不同技术之间的系统通信。实现互操作性的最佳方式是使用基于消息的通信。

# 能力对齐的微服务

微服务必须有清晰的边界是至关重要的。通常，每个微服务都有一个单一的业务能力，它能够很好地提供。团队发现成功地采用了 Eric J Evans 在《领域驱动设计》一书中提出的“有界上下文”概念。

基本上，对于大型系统来说，创建一个领域模型非常困难。Evans 谈到了将系统拆分为不同的有界上下文。确定正确的有界上下文是微服务架构成功的关键。

# 独立部署单元

每个微服务都可以单独构建和部署。在前面讨论的示例中，模块 1、2 和 3 可以分别构建和部署。

# 无状态

理想的微服务没有状态。它不在请求之间存储任何信息。创建响应所需的所有信息都包含在请求中。

# 自动化构建和发布过程

微服务具有自动化的构建和发布流程。看一下下面的图。它展示了微服务的简单构建和发布流程：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/de250ec2-6ae1-4f5c-936e-0d9a760ac053.png)

当一个微服务被构建和发布时，微服务的一个版本被存储在仓库中。部署工具有能力从仓库中选择正确的微服务版本，将其与特定环境所需的配置（来自配置仓库）匹配，并将微服务部署到特定环境中。

一些团队进一步将微服务包与运行微服务所需的基础设施结合起来。部署工具将复制此映像，并将其与特定环境的配置匹配以创建环境。

# 事件驱动架构

微服务通常采用事件驱动架构构建。让我们考虑一个简单的例子。每当有新客户注册时，需要执行三件事：

+   将客户信息存储到数据库中

+   发送欢迎套件

+   发送电子邮件通知

让我们看看设计这个的两种不同方法。

# 方法 1 - 顺序方法

让我们考虑三个服务--`CustomerInformationService`、`MailService`和`EmailService`，它们可以提供前面列出的功能。我们可以使用以下步骤创建`NewCustomerService`：

1.  调用`CustomerInformationService`将客户信息保存到数据库中。

1.  调用`MailService`发送欢迎套件。

1.  调用`EmailService`发送电子邮件通知。

`NewCustomerService`成为所有业务逻辑的中心。想象一下，如果我们在创建新客户时需要做更多的事情。所有这些逻辑将开始累积并使`NewCustomerService`变得臃肿。

# 方法 2 - 事件驱动方法

在这种方法中，我们使用消息代理。`NewCustomerService`将创建一个新事件并将其发布到消息代理。下图显示了一个高层表示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/38848057-d17b-462d-a224-4ee1b659f944.png)

三个服务--`CustomerInformationService`、`MailService`和`EmailService`--将在消息代理上监听新事件。当它们看到新的客户事件时，它们会处理它并执行该特定服务的功能。

事件驱动方法的关键优势在于没有所有业务逻辑的集中磁铁。添加新功能更容易。我们可以创建一个新服务来监听消息代理上的事件。还有一点需要注意的是，我们不需要对任何现有服务进行更改。

# 独立团队

开发微服务的团队通常是独立的。它包含了开发、测试和部署微服务所需的所有技能。它还负责在生产中支持微服务。

# 微服务优势

微服务有几个优势。它们有助于跟上技术并更快地为您的客户提供解决方案。

# 更快的上市时间

更快的上市时间是确定组织成功的关键因素之一。

微服务架构涉及创建小型、独立部署的组件。微服务的增强更容易，更不脆弱，因为每个微服务都专注于单一的业务能力。流程中的所有步骤--构建、发布、部署、测试、配置管理和监控--都是自动化的。由于微服务的责任是有界的，因此可以编写出色的自动化单元和集成测试。

所有这些因素导致应用程序能够更快地对客户需求做出反应。

# 技术演进

每天都有新的语言、框架、实践和自动化可能性出现。应用程序架构必须具备灵活性，以适应新的可能性。以下图显示了不同服务是如何使用不同技术开发的：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/6360b071-e610-4a12-a742-6e8534da43e5.png)

微服务架构涉及创建小型服务。在某些边界内，大多数组织都允许个体团队做出一些技术决策。这使团队能够尝试新技术并更快地创新。这有助于应用程序适应并与技术的演进保持一致。

# 可用性和扩展性

应用程序的不同部分的负载通常非常不同。例如，在航班预订应用程序的情况下，顾客通常在决定是否预订航班之前进行多次搜索。搜索模块的负载通常会比预订模块的负载多很多倍。微服务架构提供了设置多个搜索服务实例和少量预订服务实例的灵活性。

以下图显示了如何根据负载扩展特定微服务：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/f71c83f5-dfe6-44c3-9914-e031e7e9ee2e.png)

微服务**2**和**3**共享一个盒子（部署环境）。负载更大的微服务**1**被部署到多个盒子中。

另一个例子是初创公司的需求。当初创公司开始运营时，他们通常不知道自己可能会增长到何种程度。如果应用程序的需求增长得非常快会发生什么？如果他们采用微服务架构，它可以使他们在需要时更好地扩展。

# 团队动态

敏捷等开发方法倡导小型、独立的团队。由于微服务很小，围绕它们建立小团队是可能的。团队是跨职能的，对特定微服务拥有端到端的所有权。

微服务架构非常适合敏捷和其他现代开发方法。

# 微服务挑战

微服务架构具有显著的优势。但是，也存在显著的挑战。确定微服务的边界是一个具有挑战性但重要的决定。由于微服务很小，在大型企业中可能会有数百个微服务，因此具有良好的自动化和可见性至关重要。

# 自动化需求增加

使用微服务架构，你将一个大型应用程序拆分成多个微服务，因此构建、发布和部署的数量会成倍增加。对于这些步骤采用手动流程将非常低效。

测试自动化对于实现更快的上市时间至关重要。团队应该专注于识别可能出现的自动化可能性。

# 定义子系统的边界

微服务应该是智能的。它们不是弱的 CRUD 服务。它们应该模拟系统的业务能力。它们在一个有界上下文中拥有所有的业务逻辑。话虽如此，微服务不应该很大。决定微服务的边界是一个挑战。第一次确定正确的边界可能会很困难。团队对业务上下文的了解越多，知识就会流入架构中，并确定新的边界。通常，找到微服务的正确边界是一个演进的过程。

以下是需要注意的几个重要点：

+   松耦合和高内聚对于任何编程和架构决策都是基本的。当系统松耦合时，对一个部分的更改不应该需要其他部分的更改。

+   有界上下文代表着具体业务能力的自治业务模块。

正如 Sam Newman 在书中所说的“构建微服务--”：“通过明确的边界强制执行特定的责任”。始终思考，“我们为域的其他部分提供了哪些能力？”。

# 可见性和监控

使用微服务，一个应用程序被拆分成多个微服务。为了征服与多个微服务和异步基于事件的协作相关的复杂性，具有良好的可见性是很重要的。

确保高可用性意味着每个微服务都应该受到监控。自动化的微服务健康管理变得很重要。

调试问题需要洞察多个微服务背后发生的情况。通常使用集中日志记录，从不同微服务中聚合日志和指标。需要使用诸如关联 ID 之类的机制来隔离和调试问题。

# 容错性

假设我们正在构建一个购物应用程序。如果推荐微服务宕机会发生什么？应用程序如何反应？会完全崩溃吗？还是会让顾客继续购物？随着我们适应微服务架构，这种情况会更加频繁发生。

随着我们将服务变得更小，服务宕机的可能性增加。应用程序如何应对这些情况成为一个重要问题。在前面的例子中，一个容错应用程序会显示一些默认的推荐，同时让顾客继续购物。

随着我们进入微服务架构，应用程序应该更具有容错性。应用程序应该能够在服务宕机时提供降级行为。

# 最终一致性

在组织中，微服务之间的一定程度的一致性是很重要的。微服务之间的一致性使得整个组织能够在开发、测试、发布、部署和运营过程中实现类似的流程。这使得不同的开发人员和测试人员在跨团队移动时能够保持高效。在一定程度上保持灵活性，而不是过于死板，以避免扼杀创新，这是很重要的。

# 共享能力（企业级）

让我们看看在企业级必须标准化的一些能力。

+   **硬件**：我们使用什么硬件？我们使用云吗？

+   **代码管理**：我们使用什么版本控制系统？我们在分支和提交代码方面的做法是什么？

+   **构建和部署**：我们如何构建？我们使用什么工具来自动化部署？

+   **数据存储**：我们使用什么类型的数据存储？

+   **服务编排**：我们如何编排服务？我们使用什么样的消息代理？

+   **安全和身份**：我们如何对用户和服务进行身份验证和授权？

+   **系统可见性和监控**：我们如何监控我们的服务？我们如何在整个系统中提供故障隔离？

# 运维团队需求增加

随着我们进入微服务世界，运维团队的责任发生了明显的转变。责任转移到识别自动化机会，而不是手动操作，比如执行发布和部署。

随着多个微服务和系统不同部分之间通信的增加，运维团队变得至关重要。重要的是在初始阶段就将运维团队纳入团队，以便他们能够找到简化运维的解决方案。

# 云原生应用

云正在改变世界。出现了以前从未可能的许多可能性。组织能够按需提供计算、网络和存储设备。这在许多行业中有很高的潜力来降低成本。

考虑零售行业，在某些时段需求很高（黑色星期五，假日季等）。为什么他们要在整年都支付硬件费用，而不是按需提供呢？

虽然我们希望从云的可能性中受益，但这些可能性受到架构和应用程序性质的限制。

我们如何构建可以轻松部署到云上的应用程序？这就是云原生应用程序的作用。

云原生应用程序是那些可以轻松部署到云上的应用程序。这些应用程序共享一些共同的特征。我们将首先看一下 Twelve-Factor 应用程序--云原生应用程序中常见模式的组合。

# Twelve-Factor 应用程序

Twelve-Factor 应用程序是由 Heroku 的工程师的经验演变而来的。这是一份在云原生应用程序架构中使用的模式列表。

重要的是要注意，这里的应用程序是指一个单独的可部署单元。基本上，每个微服务都是一个应用程序（因为每个微服务都可以独立部署）。

# 维护一个代码库

每个应用程序在修订控制中有一个代码库。可以部署应用程序的多个环境。但是，所有这些环境都使用来自单个代码库的代码。一个反模式的例子是从多个代码库构建可部署的应用程序。

# 依赖项

所有依赖项必须明确声明和隔离。典型的 Java 应用程序使用构建管理工具，如 Maven 和 Gradle 来隔离和跟踪依赖项。

下图显示了典型的 Java 应用程序使用 Maven 管理依赖项：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/8e22e887-9a41-4542-880d-0bd0d8861a08.png)

下图显示了 `pom.xml`，其中管理了 Java 应用程序的依赖项：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/4500d394-7dd1-4681-b0ea-5f6fa3a2d815.png)

# 配置

所有应用程序的配置在不同环境之间都有所不同。配置可以在多个位置找到；应用程序代码、属性文件、数据库、环境变量、JNDI 和系统变量都是一些例子。

Twelve-Factor 应用程序

应用程序应在环境中存储配置。虽然在 Twelve-Factor 应用程序中建议使用环境变量来管理配置，但对于更复杂的系统，应考虑其他替代方案，例如为应用程序配置建立一个集中存储库。

无论使用何种机制，我们建议您执行以下操作：

在应用程序代码之外管理配置（独立于应用程序的可部署单元）

使用标准化的配置方式

# 后备服务

应用程序依赖于其他可用的服务--数据存储和外部服务等。Twelve-Factor 应用程序将后备服务视为附加资源。后备服务通常通过外部配置声明。

与后备服务的松耦合具有许多优势，包括能够优雅地处理后备服务的中断。

# 构建、发布、运行

构建、发布和运行阶段的描述如下。我们应该在这三个阶段之间保持清晰的分离：

+   **构建**：从代码创建可执行包（EAR、WAR 或 JAR），以及可以部署到多个环境的依赖项

+   **发布**：将可执行包与特定环境配置结合起来，在环境中部署

+   **运行**：使用特定发布在执行环境中运行应用程序

以下截图突出显示了构建和发布阶段：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/01ede5e0-7a64-46c7-8474-66b8abc6a0ea.png)

一个反模式是构建针对每个环境特定的单独可执行包。

# 无状态

Twelve-Factor 应用程序没有状态。它需要的所有数据都存储在持久存储中。

粘性会话是一种反模式。

# 端口绑定

Twelve-Factor 应用程序通过端口绑定公开所有服务。虽然可能有其他机制来公开服务，但这些机制是依赖于实现的。端口绑定可以完全控制接收和处理消息，无论应用程序部署在何处。

# 并发

十二要素应用通过水平扩展实现更多的并发。垂直扩展有其限制。水平扩展提供了无限扩展的机会。

# 可处置性

十二要素应用应该促进弹性扩展。因此，它们应该是可处置的。它们可以在需要时启动和停止。

十二要素应用应该做到以下几点：

+   具有最小的启动时间。长时间的启动意味着应用程序在能够接受请求之前有很长的延迟。

+   优雅地关闭。

+   优雅地处理硬件故障。

# 环境一致性

所有环境——开发、测试、暂存和生产——应该是相似的。它们应该使用相同的流程和工具。通过持续部署，它们应该非常频繁地具有相似的代码。这使得查找和修复问题更容易。

# 日志作为事件流

对于十二要素应用来说，可见性至关重要。由于应用部署在云上并且自动扩展，重要的是你能够集中查看应用程序不同实例中发生的情况。

将所有日志视为流使得可以将日志流路由到不同的目的地以进行查看和存档。这个流可以用于调试问题、执行分析，并基于错误模式创建警报系统。

# 没有管理流程的区别

十二要素应用将管理任务（迁移、脚本）视为正常应用程序流程的一部分。

# Spring 项目

随着世界朝着云原生应用和微服务迈进，Spring 项目也紧随其后。有许多新的 Spring 项目——Spring Boot、Spring Cloud 等，解决了新兴世界的问题。

# Spring Boot

在单体架构时代，我们有时间为应用程序设置框架的奢侈。然而，在微服务时代，我们希望更快地创建单独的组件。Spring Boot 项目旨在解决这个问题。

正如官方网站强调的那样，Spring Boot 使得创建独立的、生产级别的基于 Spring 的应用程序变得容易，你可以*直接运行*。我们对 Spring 平台和第三方库采取了一种有主见的观点，这样你就可以尽量少地开始。

Spring Boot 旨在采取一种有主见的观点——基本上为我们做出许多决定——以开发基于 Spring 的项目。

在接下来的几章中，我们将看看 Spring Boot 以及不同的功能，使我们能够更快地创建适用于生产的应用程序。

# Spring Cloud

Spring Cloud 旨在为在云上构建系统时遇到的一些常见模式提供解决方案：

+   **配置管理**：正如我们在十二要素应用部分讨论的那样，管理配置是开发云原生应用的重要部分。Spring Cloud 为微服务提供了一个名为 Spring Cloud Config 的集中式配置管理解决方案。

+   **服务发现**：服务发现促进了服务之间的松耦合。Spring Cloud 与流行的服务发现选项（如 Eureka、ZooKeeper 和 Consul）集成。

+   **断路器**：云原生应用必须具有容错能力。它们应该能够优雅地处理后端服务的故障。断路器在故障时提供默认的最小服务起着关键作用。Spring Cloud 与 Netflix Hystrix 容错库集成。

+   **API 网关**：API 网关提供集中的聚合、路由和缓存服务。Spring Cloud 与 API 网关库 Netflix Zuul 集成。

# 总结

在本章中，我们看到了世界是如何向微服务和云原生应用发展的。我们了解到 Spring 框架和项目如何发展以满足当今世界的需求，例如 Spring Boot、Spring Cloud 和 Spring Data 等项目。

在下一章中，我们将开始关注 Spring Boot。我们将看看 Spring Boot 如何简化微服务的开发。

Spring 框架 1.0 的第一个版本于 2004 年 3 月发布。十五年多来，Spring 框架一直是构建 Java 应用程序的首选框架。

在相对年轻和充满活力的 Java 框架世界中，十年是很长的时间。

在本章中，我们将开始了解 Spring 框架的核心特性。我们将看看 Spring 框架为何变得受欢迎以及如何适应保持首选框架。在快速了解 Spring 框架的重要模块后，我们将进入 Spring 项目的世界。最后，我们将看看 Spring 框架 5.0 中的新功能。

本章将回答以下问题：

+   Spring 框架为何受欢迎？

+   Spring 框架如何适应应用架构的演变？

+   Spring 框架中的重要模块是什么？

+   Spring 框架在 Spring 项目的伞下适用于哪里？

+   Spring 框架 5.0 中的新功能是什么？

# Spring 框架

Spring 网站（[`projects.spring.io/spring-framework/`](https://projects.spring.io/spring-framework/)）将 Spring 框架定义如下：*Spring 框架为现代基于 Java 的企业应用程序提供了全面的编程和配置模型*。

Spring 框架用于连接企业 Java 应用程序。Spring 框架的主要目的是处理连接应用程序不同部分所需的所有技术细节。这使程序员能够专注于他们的工作核心--编写业务逻辑。

# EJB 的问题

Spring 框架于 2004 年 3 月发布。当 Spring 框架的第一个版本发布时，开发企业应用程序的流行方式是使用 EJB 2.1。

开发和部署 EJB 是一个繁琐的过程。虽然 EJB 使组件的分发变得更容易，但开发、单元测试和部署它们并不容易。EJB 的初始版本（1.0、2.0、2.1）具有复杂的应用程序接口（API），导致人们认为（在大多数应用程序中是真的）引入的复杂性远远超过了好处：

+   难以进行单元测试。实际上，在 EJB 容器外进行测试很困难。

+   需要实现多个接口，其中包含许多不必要的方法。

+   繁琐和乏味的异常处理。

+   不方便的部署描述符。

Spring 框架被引入作为一个轻量级框架，旨在简化开发 Java EE 应用程序。

# Spring 框架为什么受欢迎？

Spring 框架的第一个版本于 2004 年 3 月发布。在随后的十五年中，Spring 框架的使用和受欢迎程度不断增长。

Spring 框架受欢迎的重要原因如下：

+   简化单元测试--由于依赖注入

+   减少了管道代码

+   架构灵活性

+   跟上时代的变化

让我们详细讨论每一个。

# 简化单元测试

早期版本的 EJB 非常难以进行单元测试。事实上，很难在容器外运行 EJB（截至 2.1 版本）。测试它们的唯一方法是在容器中部署它们。

Spring 框架引入了依赖注入的概念。我们将在第二章“依赖注入”中详细讨论依赖注入。

依赖注入通过轻松替换依赖项为其模拟使单元测试变得容易。我们不需要部署整个应用程序来进行单元测试。

简化单元测试具有多重好处：

+   程序员更加高效

+   缺陷被更早地发现，因此修复成本更低

+   应用程序具有自动化单元测试，可以在持续集成构建中运行，以防止未来的缺陷

# 减少管道代码

在 Spring Framework 之前，典型的 J2EE（或现在称为 Java EE）应用程序包含大量的管道代码。例如：获取数据库连接、异常处理代码、事务管理代码、日志记录代码等等。

让我们看一个使用准备语句执行查询的简单例子：

```java
    PreparedStatement st = null;
    try {
          st = conn.prepareStatement(INSERT_TODO_QUERY);
          st.setString(1, bean.getDescription());
          st.setBoolean(2, bean.isDone());
          st.execute();
        } 
    catch (SQLException e) {
          logger.error("Failed : " + INSERT_TODO_QUERY, e);
     } finally {
                if (st != null) {
           try {
           st.close();
          } catch (SQLException e) {
           // Ignore - nothing to do..
          }
       }
     }
```

在前面的例子中，有四行业务逻辑和超过 10 行的管道代码。

使用 Spring Framework，相同的逻辑可以应用在几行代码中：

```java
    jdbcTemplate.update(INSERT_TODO_QUERY, 
    bean.getDescription(), bean.isDone());
```

# Spring Framework 是如何做到这一点的呢？

在前面的例子中，Spring JDBC（以及 Spring 总体）将大多数已检查异常转换为未检查异常。通常，当查询失败时，我们除了关闭语句并使事务失败之外，没有太多可以做的事情。我们可以集中处理异常并使用 Spring **面向切面编程**（**AOP**）进行注入，而不是在每个方法中实现异常处理。

Spring JDBC 消除了创建所有涉及获取连接、创建准备语句等管道代码的需要。`jdbcTemplate`类可以在 Spring 上下文中创建，并在需要时注入到**数据访问对象**（**DAO**）类中。

与前面的例子类似，Spring JMS、Spring AOP 和其他 Spring 模块有助于减少大量的管道代码。

Spring Framework 让程序员专注于程序员的主要工作--编写业务逻辑。

避免所有管道代码还有另一个很大的好处--减少代码重复。由于所有事务管理、异常处理等代码（通常是所有横切关注点）都在一个地方实现，因此更容易维护。

# 架构灵活性

Spring Framework 是模块化的。它是建立在核心 Spring 模块之上的一组独立模块。大多数 Spring 模块都是独立的--您可以使用其中一个而不必使用其他模块。

让我们看几个例子：

+   在 Web 层，Spring 提供了自己的框架--Spring MVC。但是，Spring 对 Struts、Vaadin、JSF 或您选择的任何 Web 框架都有很好的支持。

+   Spring Beans 可以为您的业务逻辑提供轻量级实现。但是，Spring 也可以与 EJB 集成。

+   在数据层，Spring 通过其 Spring JDBC 模块简化了 JDBC。但是，Spring 对您喜欢的任何数据层框架--JPA、Hibernate（带有或不带有 JPA）或 iBatis 都有很好的支持。

+   您可以选择使用 Spring AOP 实现横切关注点（日志记录、事务管理、安全等）。或者，您可以集成一个完整的 AOP 实现，比如 AspectJ。

Spring Framework 不想成为万能工具。在专注于减少应用程序不同部分之间的耦合并使它们可测试的核心工作的同时，Spring 与您选择的框架进行了很好的集成。这意味着您在架构上有灵活性--如果您不想使用特定的框架，可以轻松地用另一个替换它。

# 跟上时代的变化

Spring Framework 的第一个版本专注于使应用程序可测试。然而，随着时间的推移，出现了新的挑战。Spring Framework 设法通过提供的灵活性和模块来不断发展并保持领先地位。以下列举了一些例子：

+   注解是在 Java 5 中引入的。Spring Framework（版本 2.5 - 2007 年 11 月）在引入基于注解的 Spring MVC 控制器模型方面领先于 Java EE。使用 Java EE 的开发人员必须等到 Java EE 6（2009 年 12 月 - 2 年后）才能获得可比较的功能。

+   Spring Framework 在 Java EE 之前引入了许多抽象概念，以使应用程序与特定实现解耦。 缓存 API 就是一个例子。 Spring 在 Spring 3.1 中提供了透明的缓存支持。 Java EE 推出了*JSR-107*用于 JCache（2014 年）--Spring 4.1 提供了对其的支持。

Spring 带来的另一个重要事项是 Spring 项目的总称。 Spring Framework 只是 Spring 项目下的众多项目之一。 我们将在单独的部分讨论不同的 Spring 项目。 以下示例说明了 Spring 如何通过新的 Spring 项目保持领先地位：

+   **Spring Batch**定义了构建 Java 批处理应用程序的新方法。 我们不得不等到 Java EE 7（2013 年 6 月）才有了 Java EE 中可比的批处理应用程序规范。

+   随着架构向云和微服务发展，Spring 推出了新的面向云的 Spring 项目。 Spring Cloud 有助于简化微服务的开发和部署。 Spring Cloud Data Flow 提供了围绕微服务应用程序的编排。

# Spring 模块

Spring Framework 的模块化是其广泛使用的最重要原因之一。 Spring Framework 非常模块化，有 20 多个不同的模块--具有明确定义的边界。

下图显示了不同的 Spring 模块--按照它们通常在应用程序中使用的层进行组织：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/05c2894a-a465-4c3a-88f4-ad2a4931bab7.png)

我们将从讨论 Spring 核心容器开始，然后再讨论其他模块，这些模块按照它们通常在应用程序层中使用的方式进行分组。

# Spring 核心容器

Spring Core Container 提供了 Spring Framework 的核心功能--依赖注入，**IoC**（控制反转）容器和应用程序上下文。 我们将在第二章“依赖注入”中更多地了解 DI 和 IoC 容器。

重要的核心 Spring 模块列在以下表中：

| **模块/构件** | **用途** |
| --- | --- |
| spring-core | 其他 Spring 模块使用的实用程序。 |
| spring-beans | 支持 Spring beans。 与 spring-core 结合使用，提供了 Spring Framework 的核心功能--依赖注入。 包括 BeanFactory 的实现。 |
| spring-context | 实现了 ApplicationContext，它扩展了 BeanFactory，并提供了加载资源和国际化等支持。 |
| spring-expression | 扩展了 JSP 的**EL**（表达式语言）并提供了一种用于访问和操作 bean 属性（包括数组和集合）的语言。 |

# 横切关注点

横切关注点适用于所有应用程序层--包括日志记录和安全性等。 **AOP**通常用于实现横切关注点。

单元测试和集成测试属于这个类别，因为它们适用于所有层。

与横切关注点相关的重要 Spring 模块列在以下表中：

| **模块/构件** | **用途** |
| --- | --- |
| spring-aop | 提供面向方面的编程的基本支持--具有方法拦截器和切入点。 |
| spring-aspects | 提供与最受欢迎和功能齐全的 AOP 框架 AspectJ 的集成。 |
| spring-instrument | 提供基本的仪器支持。 |
| spring-test | 提供基本的单元测试和集成测试支持。 |

# Web

Spring 除了与流行的 Web 框架（如 Struts）提供良好的集成外，还提供了自己的 MVC 框架 Spring MVC。

重要的构件/模块列在以下表中：

+   **spring-web**: 提供基本的网络功能，如多部分文件上传。 提供与其他 Web 框架（如 Struts）集成的支持。

+   **spring-webmvc**: 提供了一个功能齐全的 Web MVC 框架--Spring MVC，其中包括实现 REST 服务的功能。

我们将在第三章*使用 Spring MVC 构建 Web 应用程序*和第五章*使用 Spring Boot 构建微服务*中介绍 Spring MVC 并开发 Web 应用程序和 REST 服务。

# 业务

业务层专注于执行应用程序的业务逻辑。使用 Spring，业务逻辑通常在**普通的旧 Java 对象**（**POJO**）中实现。

**Spring Transactions** (**spring-tx**)为 POJO 和其他类提供声明式事务管理。

# 数据

应用程序中的数据层通常与数据库和/或外部接口通信。

以下是与数据层相关的一些重要的 Spring 模块：

| **模块/构件** | **用途** |
| --- | --- |
| spring-jdbc | 提供对 JDBC 的抽象，避免样板代码。 |
| spring-orm | 与 ORM 框架和规范集成--包括 JPA 和 Hibernate 等。 |
| spring-oxm | 提供对象到 XML 映射集成。支持诸如 JAXB、Castor 等框架。 |
| spring-jms | 提供对 JMS 的抽象，避免样板代码。 |

# Spring 项目

虽然 Spring 框架为企业应用程序的核心功能（DI、Web、数据）提供了基础，但其他 Spring 项目探索了企业领域的集成和解决其他问题的解决方案--部署、云端、大数据、批处理和安全等。

以下是一些重要的 Spring 项目：

+   Spring Boot

+   Spring Cloud

+   Spring Data

+   Spring Batch

+   Spring Security

+   Spring HATEOAS

# Spring Boot

在开发微服务和 Web 应用程序时遇到的一些挑战如下：

+   做框架选择和决定兼容的框架版本

+   提供外部化配置的机制--可以从一个环境更改为另一个环境的属性

+   健康检查和监控--如果应用程序的特定部分宕机，则提供警报

+   决定部署环境并为其配置应用程序

Spring Boot 通过采取*主观的观点*来解决所有这些问题。

我们将在两章中深入研究 Spring Boot--第五章，*使用 Spring Boot 构建微服务*和第七章，*高级 Spring Boot 功能*。

# Spring Cloud

可以毫不夸张地说*世界正在向云端迁移*。

云原生微服务和应用程序是当今的趋势。我们将在第四章*向微服务和云原生应用程序的演变*中详细讨论这一点。

Spring 正在快速迈向使云端应用程序开发更简单的方向。

Spring Cloud 为分布式系统中的常见模式提供解决方案。Spring Cloud 使开发人员能够快速创建实现常见模式的应用程序。Spring Cloud 中实现的一些常见模式如下所示：

+   配置管理

+   服务发现

+   断路器

+   智能路由

我们将在第九章中更详细地讨论 Spring Cloud 及其各种功能，*Spring Cloud*。

# Spring Data

当今世界有多个数据来源--SQL（关系型）和各种 NOSQL 数据库。Spring Data 试图为所有这些不同类型的数据库提供一致的数据访问方法。

Spring Data 提供与各种规范和/或数据存储的集成：

+   JPA

+   MongoDB

+   Redis

+   Solr

+   Gemfire

+   Apache Cassandra

以下是一些重要特性：

+   通过从方法名称确定查询来提供对存储库和对象映射的抽象

+   简单的 Spring 集成

+   与 Spring MVC 控制器集成

+   高级自动审计功能--创建者、创建日期、最后更改者和最后更改日期

我们将在第八章中更详细地讨论 Spring Data，*Spring Data*。

# Spring Batch

今天的企业应用程序使用批处理程序处理大量数据。这些应用程序的需求非常相似。Spring Batch 为具有高性能要求的高容量批处理程序提供解决方案。

Spring Batch 中的重要功能如下：

+   启动、停止和重新启动作业的能力，包括重新启动失败的作业从失败的地方重新开始

+   处理数据的能力

+   重试步骤或在失败时跳过步骤的能力

+   基于 Web 的管理界面

# Spring Security

**身份验证**是识别用户的过程。**授权**是确保用户有权访问资源执行已识别的操作的过程。

身份验证和授权是企业应用程序的关键部分，包括 Web 应用程序和 Web 服务。Spring Security 为基于 Java 的应用程序提供声明性身份验证和授权。

Spring Security 中的重要功能如下：

+   简化的身份验证和授权

+   与 Spring MVC 和 Servlet API 的良好集成

+   支持防止常见的安全攻击--**跨站请求伪造**（**CSRF**）和会话固定

+   可用于与 SAML 和 LDAP 集成的模块

我们将在第三章中讨论如何使用 Spring Security 保护 Web 应用程序，*使用 Spring MVC 构建 Web 应用程序*。

我们将在《第六章》中讨论如何使用 Spring Security 来保护基本和 OAuth 身份验证机制的 REST 服务，*扩展微服务*。

# Spring HATEOAS

**HATEOAS**代表**超媒体作为应用程序状态的引擎**。尽管听起来很复杂，但它是一个非常简单的概念。它的主要目的是将服务器（服务提供者）与客户端（服务消费者）解耦。

服务提供者向服务消费者提供有关资源上可以执行的其他操作的信息。

Spring HATEOAS 提供了 HATEOAS 实现，特别是针对使用 Spring MVC 实现的 REST 服务。

Spring HATEOAS 中的重要功能如下：

+   简化指向服务方法的链接的定义，使链接更加稳固

+   支持 JAXB（基于 XML）和 JSON 集成

+   对服务消费者（客户端）的支持

我们将在《第六章》中讨论如何使用 HATEOAS，*扩展微服务*。

# Spring Framework 5.0 中的新功能

Spring Framework 5.0 是 Spring Framework 的首次重大升级，距离 Spring Framework 4.0 已经有将近四年的时间。在这段时间内，Spring Boot 项目的主要发展之一就是 Spring Boot 项目的发展。我们将在下一节中讨论 Spring Boot 2.0 中的新功能。

Spring Framework 5.0 最大的特性之一是**响应式编程**。Spring Framework 5.0 具有核心响应式编程功能，并且支持响应式端点。重要变化的列表包括以下内容：

+   基线升级

+   JDK 9 运行时兼容性

+   在 Spring Framework 代码中使用 JDK 8 功能

+   响应式编程支持

+   功能性的 Web 框架

+   Jigsaw 中的 Java 模块化

+   Kotlin 支持

+   删除的功能

# 基线升级

Spring Framework 5.0 具有 JDK 8 和 Java EE 7 基线。基本上，这意味着不再支持以前的 JDK 和 Java EE 版本。

Spring Framework 5.0 的一些重要基线 Java EE 7 规范如下所示：

+   Servlet 3.1

+   JMS 2.0

+   JPA 2.1

+   JAX-RS 2.0

+   Bean Validation 1.1

许多 Java 框架的最低支持版本发生了许多变化。以下列表包含一些知名框架的最低支持版本：

+   Hibernate 5

+   Jackson 2.6

+   EhCache 2.10

+   JUnit 5

+   Tiles 3

以下列表显示了支持的服务器版本：

+   Tomcat 8.5+

+   Jetty 9.4+

+   WildFly 10+

+   Netty 4.1+（用于使用 Spring Web Flux 进行 Web 响应式编程）

+   Undertow 1.4+（用于使用 Spring Web Flux 进行 Web 响应式编程）

使用之前版本的任何上述规范/框架的应用程序在使用 Spring Framework 5.0 之前，至少需要升级到前面列出的版本。

# JDK 9 运行时兼容性

预计 JDK 9 将于 2017 年中期发布。Spring Framework 5.0 预计将与 JDK 9 具有运行时兼容性。

# 在 Spring Framework 代码中使用 JDK 8 的特性

Spring Framework 4.x 的基线版本是 Java SE 6。这意味着它支持 Java 6、7 和 8。必须支持 Java SE 6 和 7 会对 Spring Framework 代码造成限制。框架代码不能使用 Java 8 的任何新功能。因此，尽管世界其他地方升级到了 Java 8，Spring Framework 中的代码（至少是主要部分）仍受限于使用较早版本的 Java。

在 Spring Framework 5.0 中，基线版本是 Java 8。Spring Framework 代码现在已升级以使用 Java 8 的新功能。这将导致更易读和更高性能的框架代码。其中使用的一些 Java 8 特性如下：

+   核心 Spring 接口中的 Java 8 默认方法

+   基于 Java 8 反射增强的内部代码改进

+   在框架代码中使用函数式编程--lambda 和 streams

# 响应式编程支持

响应式编程是 Spring Framework 5.0 最重要的特性之一。

微服务架构通常建立在基于事件的通信之上。应用程序被构建为对事件（或消息）做出反应。

响应式编程提供了一种专注于构建对事件做出反应的应用程序的替代编程风格。

虽然 Java 8 没有内置对响应式编程的支持，但有许多框架提供了对响应式编程的支持：

+   **Reactive Streams**：语言中立的尝试定义响应式 API。

+   **Reactor**：由 Spring Pivotal 团队提供的 Reactive Streams 的 Java 实现。

+   **Spring WebFlux**：支持基于响应式编程的 Web 应用程序开发。提供类似于 Spring MVC 的编程模型。

我们将在第十一章中讨论响应式编程以及如何在 Spring Web Flux 中实现它，*响应式编程*。

# 功能性 Web 框架

基于响应式特性，Spring 5 还提供了一个功能性的 Web 框架。

功能性 Web 框架提供了使用函数式编程风格定义端点的功能。下面是一个简单的 hello world 示例：

```java
    RouterFunction<String> route =
    route(GET("/hello-world"),
    request -> Response.ok().body(fromObject("Hello World")));
```

功能性 Web 框架还可以用于定义更复杂的路由，如下面的示例所示：

```java
    RouterFunction<?> route = route(GET("/todos/{id}"),
    request -> {
       Mono<Todo> todo = Mono.justOrEmpty(request.pathVariable("id"))
       .map(Integer::valueOf)
       .then(repository::getTodo);
       return Response.ok().body(fromPublisher(todo, Todo.class));
      })
     .and(route(GET("/todos"),
     request -> {
       Flux<Todo> people = repository.allTodos();
       return Response.ok().body(fromPublisher(people, Todo.class));
     }))
    .and(route(POST("/todos"),
    request -> {
      Mono<Todo> todo = request.body(toMono(Todo.class));
      return Response.ok().build(repository.saveTodo(todo));
    }));
```

需要注意的一些重要事项如下：

+   `RouterFunction`评估匹配条件以将请求路由到适当的处理程序函数

+   我们正在定义三个端点，两个 GET 和一个 POST，并将它们映射到不同的处理程序函数

我们将在第十一章中更详细地讨论 Mono 和 Flux，*响应式编程*。

# 使用 Jigsaw 的 Java 模块化

直到 Java 8，Java 平台并不是模块化的。由此产生了一些重要问题：

+   **平台膨胀**：在过去的几十年里，Java 模块化并不是一个令人担忧的问题。然而，随着**物联网**（**IOT**）和新的轻量级平台如 Node.js 的出现，迫切需要解决 Java 平台的膨胀问题。（JDK 的初始版本小于 10MB。最近的 JDK 版本需要超过 200MB。）

+   **JAR 地狱**：另一个重要问题是 JAR 地狱的问题。当 Java ClassLoader 找到一个类时，它不会查看是否有其他可用的类定义。它会立即加载找到的第一个类。如果应用程序的两个不同部分需要来自不同 JAR 的相同类，它们无法指定要从哪个 JAR 加载类。

**开放系统网关倡议**（OSGi）是 1999 年开始的倡议之一，旨在为 Java 应用程序带来模块化。

每个模块（称为捆绑包）定义如下：

+   **导入**：模块使用的其他捆绑包

+   **导出**：此捆绑包导出的包

每个模块都可以有自己的生命周期。它可以独立安装、启动和停止。

Jigsaw 是 Java 社区进程（JCP）的一个倡议，从 Java 7 开始，旨在为 Java 带来模块化。它有两个主要目标：

+   为 JDK 定义和实现模块化结构

+   为构建在 Java 平台上的应用程序定义模块系统

Jigsaw 预计将成为 Java 9 的一部分，Spring Framework 5.0 预计将包括对 Jigsaw 模块的基本支持。

# Kotlin 支持

Kotlin 是一种静态类型的 JVM 语言，可以编写富有表现力、简短和可读的代码。Spring Framework 5.0 对 Kotlin 有很好的支持。

考虑一个简单的 Kotlin 程序，演示一个数据类，如下所示：

```java
    import java.util.*
    data class Todo(var description: String, var name: String, var  
    targetDate : Date)
    fun main(args: Array<String>) {
      var todo = Todo("Learn Spring Boot", "Jack", Date())
      println(todo)
        //Todo(description=Learn Spring Boot, name=Jack, 
        //targetDate=Mon May 22 04:26:22 UTC 2017)
      var todo2 = todo.copy(name = "Jill")
      println(todo2)
         //Todo(description=Learn Spring Boot, name=Jill, 
         //targetDate=Mon May 22 04:26:22 UTC 2017)
      var todo3 = todo.copy()
      println(todo3.equals(todo)) //true
    }  
```

在不到 10 行代码的情况下，我们创建并测试了一个具有三个属性和以下函数的数据 bean：

+   `equals()`

+   `hashCode()`

+   `toString()`

+   `copy()`

Kotlin 是强类型的。但是不需要明确指定每个变量的类型：

```java
    val arrayList = arrayListOf("Item1", "Item2", "Item3") 
    // Type is ArrayList
```

命名参数允许您在调用方法时指定参数的名称，从而使代码更易读：

```java
    var todo = Todo(description = "Learn Spring Boot", 
    name = "Jack", targetDate = Date())
```

Kotlin 通过提供默认变量（`it`）和诸如 `take`、`drop` 等方法，使函数式编程更简单：

```java
    var first3TodosOfJack = students.filter { it.name == "Jack"   
     }.take(3)
```

您还可以在 Kotlin 中为参数指定默认值：

```java
    import java.util.*
    data class Todo(var description: String, var name: String, var
    targetDate : Date = Date())
    fun main(args: Array<String>) {
      var todo = Todo(description = "Learn Spring Boot", name = "Jack")
    }
```

凭借其简洁和表达力的特点，我们期望 Kotlin 成为一个需要学习的语言。

我们将在第十三章《在 Spring 中使用 Kotlin》中更多地讨论 Kotlin。

# 已删除的功能

Spring Framework 5 是一个重要的 Spring 发布版本，基线版本大幅增加。随着 Java、Java EE 和其他一些框架的基线版本增加，Spring Framework 5 移除了对一些框架的支持：

+   Portlet

+   Velocity

+   JasperReports

+   XMLBeans

+   JDO

+   Guava

如果您使用了上述任何框架，建议您计划迁移并继续使用支持到 2019 年的 Spring Framework 4.3。

# Spring Boot 2.0 新功能

Spring Boot 的第一个版本于 2014 年发布。以下是 Spring Boot 2.0 中预期的一些重要更新：

+   基线 JDK 版本是 Java 8

+   基线 Spring 版本是 Spring Framework 5.0

+   Spring Boot 2.0 具有对 WebFlux 的响应式 Web 编程的支持

一些重要框架的最低支持版本如下所列：

+   Jetty 9.4

+   Tomcat 8.5

+   Hibernate 5.2

+   Gradle 3.4

我们将在第五章《使用 Spring Boot 构建微服务》和第七章《高级 Spring Boot 功能》中广泛讨论 Spring Boot。

# 摘要

在过去的十五年中，Spring Framework 显著改善了开发 Java 企业应用程序的体验。Spring Framework 5.0 带来了许多功能，同时显著提高了基线。

在接下来的章节中，我们将介绍依赖注入，并了解如何使用 Spring MVC 开发 Web 应用程序。之后，我们将进入微服务的世界。在第五章《使用 Spring Boot 构建微服务》、第六章《扩展微服务》和第七章《高级 Spring Boot 功能》中，我们将介绍 Spring Boot 如何简化微服务的创建。然后我们将把注意力转向使用 Spring Cloud 和 Spring Cloud Data Flow 在云中构建应用程序。


# 第五章：使用 Spring Boot 构建微服务

正如我们在上一章中讨论的，我们正在朝着具有更小、可以独立部署的微服务的架构发展。这意味着将会开发大量更小的微服务。

一个重要的结果是，我们需要能够快速上手并运行新组件。

Spring Boot 旨在解决快速启动新组件的问题。在本章中，我们将开始了解 Spring Boot 带来的能力。我们将回答以下问题：

+   为什么选择 Spring Boot？

+   Spring Boot 提供了哪些功能？

+   什么是自动配置？

+   Spring Boot 不是什么？

+   当您使用 Spring Boot 时，后台会发生什么？

+   如何使用 Spring Initializr 创建新的 Spring Boot 项目？

+   如何使用 Spring Boot 创建基本的 RESTful 服务？

# 什么是 Spring Boot？

首先，让我们开始澄清关于 Spring Boot 的一些误解：

+   Spring Boot 不是一个代码生成框架。它不会生成任何代码。

+   Spring Boot 既不是应用服务器，也不是 Web 服务器。它与不同范围的应用程序和 Web 服务器集成良好。

+   Spring Boot 不实现任何特定的框架或规范。

这些问题仍然存在：

+   什么是 Spring Boot？

+   为什么在过去几年中变得如此流行？

为了回答这些问题，让我们构建一个快速的示例。让我们考虑一个您想要快速原型的示例应用程序。

# 为微服务快速创建原型

假设我们想要使用 Spring MVC 构建一个微服务，并使用 JPA（使用 Hibernate 作为实现）来连接数据库。

让我们考虑设置这样一个应用程序的步骤：

1.  决定使用哪个版本的 Spring MVC、JPA 和 Hibernate。

1.  设置 Spring 上下文以将所有不同的层连接在一起。

1.  使用 Spring MVC 设置 Web 层（包括 Spring MVC 配置）：

+   为 DispatcherServlet、处理程序、解析器、视图解析器等配置 bean

1.  在数据层设置 Hibernate：

+   为 SessionFactory、数据源等配置 bean

1.  决定并实现如何存储应用程序配置，这在不同环境之间会有所不同。

1.  决定您希望如何进行单元测试。

1.  决定并实现您的事务管理策略。

1.  决定并实现如何实现安全性。

1.  设置您的日志框架。

1.  决定并实现您希望如何在生产中监视应用程序。

1.  决定并实现一个度量管理系统，以提供有关应用程序的统计信息。

1.  决定并实现如何将应用程序部署到 Web 或应用程序服务器。

至少有几个提到的步骤必须在我们开始构建业务逻辑之前完成。这可能需要至少几周的时间。

当我们构建微服务时，我们希望能够快速启动。所有前面的步骤都不会使开发微服务变得容易。这就是 Spring Boot 旨在解决的问题。

以下引用是从 Spring Boot 网站中提取的（[`docs.spring.io/spring-boot/docs/current-SNAPSHOT/reference/htmlsingle/#boot-documentation`](http://docs.spring.io/spring-boot/docs/current-SNAPSHOT/reference/htmlsingle/#boot-documentation)）：

Spring Boot 使得创建独立的、生产级别的基于 Spring 的应用程序变得容易，您可以“只需运行”。我们对 Spring 平台和第三方库持有一种看法，因此您可以尽量少地开始。大多数 Spring Boot 应用程序几乎不需要 Spring 配置。

Spring Boot 使开发人员能够专注于微服务背后的业务逻辑。它旨在处理开发微服务涉及的所有琐碎技术细节。

# 主要目标

Spring Boot 的主要目标如下：

+   快速启动基于 Spring 的项目。

+   持有观点。根据常见用法进行默认假设。提供配置选项以处理与默认值不同的偏差。

+   提供了各种非功能特性。

+   不要使用代码生成，避免使用大量的 XML 配置。

# 非功能特性

Spring Boot 提供的一些非功能特性如下：

+   默认处理各种框架、服务器和规范的版本控制和配置

+   应用程序安全的默认选项

+   默认应用程序指标，并有扩展的可能性

+   使用健康检查进行基本应用程序监控

+   多种外部化配置选项

# Spring Boot Hello World

我们将从本章开始构建我们的第一个 Spring Boot 应用程序。我们将使用 Maven 来管理依赖项。

启动 Spring Boot 应用程序涉及以下步骤：

1.  在您的`pom.xml`文件中配置`spring-boot-starter-parent`。

1.  使用所需的起始项目配置`pom.xml`文件。

1.  配置`spring-boot-maven-plugin`以便能够运行应用程序。

1.  创建您的第一个 Spring Boot 启动类。

让我们从第 1 步开始：配置起始项目。

# 配置 spring-boot-starter-parent

让我们从一个简单的带有`spring-boot-starter-parent`的`pom.xml`文件开始：

```java
    <project 

     xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
     http://maven.apache.org/xsd/maven-4.0.0.xsd">   
    <modelVersion>4.0.0</modelVersion> 
    <groupId>com.mastering.spring</groupId> 
    <artifactId>springboot-example</artifactId> 
    <version>0.0.1-SNAPSHOT</version> 
    <name>First Spring Boot Example</name> 
    <packaging>war</packaging>
    <parent> 
      <groupId>org.springframework.boot</groupId> 
      <artifactId>spring-boot-starter-parent</artifactId>  
      <version>2.0.0.M1</version>
    </parent>
    <properties> 
      <java.version>1.8</java.version> 
    </properties>

   <repositories>
    <repository>
      <id>spring-milestones</id>
      <name>Spring Milestones</name>
      <url>https://repo.spring.io/milestone</url>
      <snapshots>
        <enabled>false</enabled>
      </snapshots>
    </repository>
   </repositories>

   <pluginRepositories>
    <pluginRepository>
      <id>spring-milestones</id>
      <name>Spring Milestones</name>
      <url>https://repo.spring.io/milestone</url>
        <snapshots>
          <enabled>false</enabled>
        </snapshots>
     </pluginRepository>
    </pluginRepositories>

</project>
```

第一个问题是：为什么我们需要`spring-boot-starter-parent`？

`spring-boot-starter-parent`依赖项包含要使用的 Java 的默认版本，Spring Boot 使用的依赖项的默认版本以及 Maven 插件的默认配置。

`spring-boot-starter-parent`依赖是为基于 Spring Boot 的应用程序提供依赖项和插件管理的父 POM。

让我们看一下`spring-boot-starter-parent`内部的一些代码，以更深入地了解`spring-boot-starter-parent`。

# spring-boot-starter-parent

`spring-boot-starter-parent`依赖项继承自顶部 POM 中定义的`spring-boot-dependencies`。以下代码片段显示了从`spring-boot-starter-parent`中提取的内容：

```java
    <parent>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-dependencies</artifactId>
      <version>2.0.0.M1</version>
      <relativePath>../../spring-boot-dependencies</relativePath>
   </parent>
```

`spring-boot-dependencies`为 Spring Boot 使用的所有依赖项提供了默认的依赖项管理。以下代码显示了在`spring-boot-dependencies`中配置的各种依赖项的不同版本：

```java
<activemq.version>5.13.4</activemq.version>
<aspectj.version>1.8.9</aspectj.version>
<ehcache.version>2.10.2.2.21</ehcache.version>
<elasticsearch.version>2.3.4</elasticsearch.version>
<gson.version>2.7</gson.version>
<h2.version>1.4.192</h2.version>
<hazelcast.version>3.6.4</hazelcast.version>
<hibernate.version>5.0.9.Final</hibernate.version>
<hibernate-validator.version>5.2.4.Final</hibernate
  validator.version>
<hsqldb.version>2.3.3</hsqldb.version>
<htmlunit.version>2.21</htmlunit.version>
<jackson.version>2.8.1</jackson.version>
<jersey.version>2.23.1</jersey.version>
<jetty.version>9.3.11.v20160721</jetty.version>
<junit.version>4.12</junit.version>
<mockito.version>1.10.19</mockito.version>
<selenium.version>2.53.1</selenium.version>
<servlet-api.version>3.1.0</servlet-api.version>
<spring.version>4.3.2.RELEASE</spring.version>
<spring-amqp.version>1.6.1.RELEASE</spring-amqp.version>
<spring-batch.version>3.0.7.RELEASE</spring-batch.version>
<spring-data-releasetrain.version>Hopper-SR2</spring-
  data-releasetrain.version>
<spring-hateoas.version>0.20.0.RELEASE</spring-hateoas.version>
<spring-restdocs.version>1.1.1.RELEASE</spring-restdocs.version>
<spring-security.version>4.1.1.RELEASE</spring-security.version>
<spring-session.version>1.2.1.RELEASE</spring-session.version>
<spring-ws.version>2.3.0.RELEASE</spring-ws.version>
<thymeleaf.version>2.1.5.RELEASE</thymeleaf.version>
<tomcat.version>8.5.4</tomcat.version>
<xml-apis.version>1.4.01</xml-apis.version>
```

如果我们想要覆盖特定依赖项的版本，可以通过在我们应用程序的`pom.xml`文件中提供正确名称的属性来实现。以下代码片段显示了配置我们的应用程序以使用 Mockito 的 1.10.20 版本的示例：

```java
    <properties>
     <mockito.version>1.10.20</mockito.version>
    </properties>
```

以下是`spring-boot-starter-parent`中定义的一些其他内容：

+   默认的 Java 版本为`<java.version>1.8</java.version>`

+   Maven 插件的默认配置：

+   `maven-failsafe-plugin`

+   `maven-surefire-plugin`

+   `git-commit-id-plugin`

不同版本框架之间的兼容性是开发人员面临的主要问题之一。我如何找到与特定版本 Spring 兼容的最新 Spring Session 版本？通常的答案是阅读文档。但是，如果我们使用 Spring Boot，这就变得简单了，因为有了`spring-boot-starter-parent`。如果我们想升级到更新的 Spring 版本，我们只需要找到该 Spring 版本的`spring-boot-starter-parent`依赖项。一旦我们升级我们的应用程序以使用该特定版本的`spring-boot-starter-parent`，我们将所有其他依赖项升级到与新 Spring 版本兼容的版本。开发人员少了一个问题要处理。总是让我很开心。

# 使用所需的起始项目配置 pom.xml

每当我们想要在 Spring Boot 中构建应用程序时，我们需要开始寻找起始项目。让我们专注于理解什么是起始项目。

# 理解起始项目

启动器是为不同目的定制的简化的依赖描述符。例如，`spring-boot-starter-web`是用于构建 Web 应用程序（包括使用 Spring MVC 的 RESTful）的启动器。它使用 Tomcat 作为默认的嵌入式容器。如果我想使用 Spring MVC 开发 Web 应用程序，我们只需要在依赖项中包含`spring-boot-starter-web`，就会自动预配置如下内容：

+   Spring MVC

+   兼容的 jackson-databind 版本（用于绑定）和 hibernate-validator 版本（用于表单验证）

+   `spring-boot-starter-tomcat`（Tomcat 的启动项目）

以下代码片段显示了在`spring-boot-starter-web`中配置的一些依赖项：

```java
    <dependencies>
        <dependency>
          <groupId>org.springframework.boot</groupId>
          <artifactId>spring-boot-starter</artifactId>
        </dependency>
        <dependency>
          <groupId>org.springframework.boot</groupId>
          <artifactId>spring-boot-starter-tomcat</artifactId>
        </dependency>
        <dependency>
          <groupId>org.hibernate</groupId>
          <artifactId>hibernate-validator</artifactId>
        </dependency>
        <dependency>
          <groupId>com.fasterxml.jackson.core</groupId>
          <artifactId>jackson-databind</artifactId>
        </dependency>
        <dependency>
          <groupId>org.springframework</groupId>
          <artifactId>spring-web</artifactId>
        </dependency>
        <dependency>
          <groupId>org.springframework</groupId>
          <artifactId>spring-webmvc</artifactId>
       </dependency>
    </dependencies>
```

正如我们在前面的代码片段中所看到的

`spring-boot-starter-web`，我们得到了许多自动配置的框架。

对于我们想要构建的 Web 应用程序，我们还希望进行一些良好的单元测试并将其部署在 Tomcat 上。以下代码片段显示了我们需要的不同启动器依赖项。我们需要将其添加到我们的`pom.xml`文件中：

```java
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
     <dependency>
       <groupId>org.springframework.boot</groupId>
       <artifactId>spring-boot-starter-tomcat</artifactId>
       <scope>provided</scope>
     </dependency>
    </dependencies>
```

我们添加了三个启动项目：

+   我们已经讨论了`spring-boot-starter-web`。它为我们提供了构建使用 Spring MVC 的 Web 应用程序所需的框架。

+   `spring-boot-starter-test`依赖项提供了所需的单元测试框架：

+   **JUnit**：基本的单元测试框架

+   **Mockito**：用于模拟

+   **Hamcrest**，**AssertJ**：用于可读的断言

+   **Spring Test**：用于基于 spring-context 的应用程序的单元测试框架

+   `spring-boot-starter-tomcat`依赖是运行 Web 应用程序的默认值。我们为了清晰起见包含它。`spring-boot-starter-tomcat`是使用 Tomcat 作为嵌入式 servlet 容器的启动器。

我们现在已经配置了我们的`pom.xml`文件，其中包含了启动器父级和所需的启动器项目。现在让我们添加`spring-boot-maven-plugin`，这将使我们能够运行 Spring Boot 应用程序。

# 配置 spring-boot-maven-plugin

当我们使用 Spring Boot 构建应用程序时，可能会出现几种情况：

+   我们希望在原地运行应用程序，而不需要构建 JAR 或 WAR

+   我们希望为以后部署构建一个 JAR 和一个 WAR

`spring-boot-maven-plugin`依赖项为上述两种情况提供了功能。以下代码片段显示了如何在应用程序中配置`spring-boot-maven-plugin`：

```java
    <build>
     <plugins>
      <plugin>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-maven-plugin</artifactId>
      </plugin>
     </plugins>
    </build>
```

`spring-boot-maven-plugin`依赖项为 Spring Boot 应用程序提供了几个目标。最受欢迎的目标是 run（可以在项目的根文件夹中的命令提示符上执行`mvn spring-boot:run`）。

# 创建您的第一个 Spring Boot 启动类

以下类说明了如何创建一个简单的 Spring Boot 启动类。它使用`SpringApplication`类的静态 run 方法，如下面的代码片段所示：

```java
    package com.mastering.spring.springboot; 
    import org.springframework.boot.SpringApplication; 
    import org.springframework.boot.
    autoconfigure.SpringBootApplication; 
    import org.springframework.context.ApplicationContext; 
    @SpringBootApplication public class Application {
       public static void main(String[] args)
        { 
         ApplicationContext ctx = SpringApplication.run 
         (Application.class,args); 
        }
     }
```

前面的代码是一个简单的 Java `main`方法，执行`SpringApplication`类上的静态`run`方法。

# SpringApplication 类

`SpringApplication`类可用于从 Java `main`方法引导和启动 Spring 应用程序。

以下是 Spring Boot 应用程序引导时通常执行的步骤：

1.  创建 Spring 的`ApplicationContext`实例。

1.  启用接受命令行参数并将它们公开为 Spring 属性的功能。

1.  根据配置加载所有 Spring bean。

# `@SpringBootApplication`注解

`@SpringBootApplication`注解是三个注解的快捷方式：

+   `@Configuration`：指示这是一个 Spring 应用程序上下文配置文件。

+   `@EnableAutoConfiguration`：启用自动配置，这是 Spring Boot 的一个重要特性。我们将在后面的单独部分讨论自动配置。

+   `@ComponentScan`：启用在此类的包和所有子包中扫描 Spring bean。

# 运行我们的 Hello World 应用程序

我们可以以多种方式运行 Hello World 应用程序。让我们从最简单的选项开始运行--作为 Java 应用程序运行。在您的 IDE 中，右键单击应用程序类，并将其作为 Java 应用程序运行。以下截图显示了运行我们的`Hello World`应用程序的一些日志：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/a6a0b877-9c74-4923-a170-15a6b785f429.png)

以下是需要注意的关键事项：

+   Tomcat 服务器在端口 8080 上启动--`Tomcat started on port(s): 8080 (http)`。

+   DispatcherServlet 已配置。这意味着 Spring MVC 框架已准备好接受请求--`Mapping servlet: 'dispatcherServlet' to [/]`。

+   默认启用四个过滤器--`characterEncodingFilter`，`hiddenHttpMethodFilter`，`httpPutFormContentFilter`和`requestContextFilter`

+   已配置默认错误页面--`Mapped "{[/error]}" onto public org.springframework.http.ResponseEntity<java.util.Map<java.lang.String, java.lang.Object>> org.springframework.boot.autoconfigure.web.BasicErrorController.error(javax.servlet.http.HttpServletRequest)`

+   WebJars 已自动配置。正如我们在第三章*使用 Spring MVC 构建 Web 应用程序*中讨论的那样，WebJars 可以为静态依赖项（如 Bootstrap 和 query）提供依赖项管理--`Mapped URL path [/webjars/**] onto handler of type [class org.springframework.web.servlet.resource.ResourceHttpRequestHandler]`

以下截图显示了当前应用程序布局。我们只有两个文件，`pom.xml`和`Application.java`：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/e655ff16-7ab2-4315-a699-feb964551b5c.png)

通过一个简单的`pom.xml`文件和一个 Java 类，我们能够启动 Spring MVC 应用程序，并具有前述所有功能。关于 Spring Boot 最重要的是要了解后台发生了什么。理解前述启动日志是第一步。让我们看一下 Maven 依赖项，以获得更深入的了解。

以下截图显示了在我们创建的`pom.xml`文件中配置的基本配置的一些依赖项：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/0e30c01a-0fd3-4d2f-8705-277e5c29045a.png)

Spring Boot 做了很多魔术。一旦您配置并运行了应用程序，我建议您尝试玩耍，以获得更深入的理解，这在您调试问题时将会很有用。

正如蜘蛛侠所说，<q>伴随着强大的力量，也伴随着巨大的责任</q>。这在 Spring Boot 的情况下绝对是真实的。在未来的时间里，最好的 Spring Boot 开发人员将是那些了解后台发生情况的人--依赖项和自动配置。

# 自动配置

为了让我们更好地理解自动配置，让我们扩展我们的应用程序类，包括更多的代码行：

```java
    ApplicationContext ctx = SpringApplication.run(Application.class, 
     args);
    String[] beanNames = ctx.getBeanDefinitionNames();
    Arrays.sort(beanNames);

   for (String beanName : beanNames) {
     System.out.println(beanName);
    }
```

我们获取在 Spring 应用程序上下文中定义的所有 bean，并打印它们的名称。当`Application.java`作为 Java 程序运行时，它会打印出 bean 的列表，如下面的输出所示：

```java
application
basicErrorController
beanNameHandlerMapping
beanNameViewResolver
characterEncodingFilter
conventionErrorViewResolver
defaultServletHandlerMapping
defaultViewResolver
dispatcherServlet
dispatcherServletRegistration
duplicateServerPropertiesDetector
embeddedServletContainerCustomizerBeanPostProcessor
error
errorAttributes
errorPageCustomizer
errorPageRegistrarBeanPostProcessor
faviconHandlerMapping
faviconRequestHandler
handlerExceptionResolver
hiddenHttpMethodFilter
httpPutFormContentFilter
httpRequestHandlerAdapter
jacksonObjectMapper
jacksonObjectMapperBuilder
jsonComponentModule
localeCharsetMappingsCustomizer
mappingJackson2HttpMessageConverter
mbeanExporter
mbeanServer
messageConverters
multipartConfigElement
multipartResolver
mvcContentNegotiationManager
mvcConversionService
mvcPathMatcher
mvcResourceUrlProvider
mvcUriComponentsContributor
mvcUrlPathHelper
mvcValidator
mvcViewResolver
objectNamingStrategy
autoconfigure.AutoConfigurationPackages
autoconfigure.PropertyPlaceholderAutoConfiguration
autoconfigure.condition.BeanTypeRegistry
autoconfigure.context.ConfigurationPropertiesAutoConfiguration
autoconfigure.info.ProjectInfoAutoConfiguration
autoconfigure.internalCachingMetadataReaderFactory
autoconfigure.jackson.JacksonAutoConfiguration
autoconfigure.jackson.JacksonAutoConfiguration$Jackson2ObjectMapperBuilderCustomizerConfiguration
autoconfigure.jackson.JacksonAutoConfiguration$JacksonObjectMapperBuilderConfiguration
autoconfigure.jackson.JacksonAutoConfiguration$JacksonObjectMapperConfiguration
autoconfigure.jmx.JmxAutoConfiguration
autoconfigure.web.DispatcherServletAutoConfiguration
autoconfigure.web.DispatcherServletAutoConfiguration$DispatcherServletConfiguration
autoconfigure.web.DispatcherServletAutoConfiguration$DispatcherServletRegistrationConfiguration
autoconfigure.web.EmbeddedServletContainerAutoConfiguration
autoconfigure.web.EmbeddedServletContainerAutoConfiguration$EmbeddedTomcat
autoconfigure.web.ErrorMvcAutoConfiguration
autoconfigure.web.ErrorMvcAutoConfiguration$WhitelabelErrorViewConfiguration
autoconfigure.web.HttpEncodingAutoConfiguration
autoconfigure.web.HttpMessageConvertersAutoConfiguration
autoconfigure.web.HttpMessageConvertersAutoConfiguration$StringHttpMessageConverterConfiguration
autoconfigure.web.JacksonHttpMessageConvertersConfiguration
autoconfigure.web.JacksonHttpMessageConvertersConfiguration$MappingJackson2HttpMessageConverterConfiguration
autoconfigure.web.MultipartAutoConfiguration
autoconfigure.web.ServerPropertiesAutoConfiguration
autoconfigure.web.WebClientAutoConfiguration
autoconfigure.web.WebClientAutoConfiguration$RestTemplateConfiguration
autoconfigure.web.WebMvcAutoConfiguration
autoconfigure.web.WebMvcAutoConfiguration$EnableWebMvcConfiguration
autoconfigure.web.WebMvcAutoConfiguration$WebMvcAutoConfigurationAdapter
autoconfigure.web.WebMvcAutoConfiguration$WebMvcAutoConfigurationAdapter$FaviconConfiguration
autoconfigure.websocket.WebSocketAutoConfiguration
autoconfigure.websocket.WebSocketAutoConfiguration$TomcatWebSocketConfiguration
context.properties.ConfigurationPropertiesBindingPostProcessor
context.properties.ConfigurationPropertiesBindingPostProcessor.store
annotation.ConfigurationClassPostProcessor.enhancedConfigurationProcessor
annotation.ConfigurationClassPostProcessor.importAwareProcessor
annotation.internalAutowiredAnnotationProcessor
annotation.internalCommonAnnotationProcessor
annotation.internalConfigurationAnnotationProcessor
annotation.internalRequiredAnnotationProcessor
event.internalEventListenerFactory
event.internalEventListenerProcessor
preserveErrorControllerTargetClassPostProcessor
propertySourcesPlaceholderConfigurer
requestContextFilter
requestMappingHandlerAdapter
requestMappingHandlerMapping
resourceHandlerMapping
restTemplateBuilder
serverProperties
simpleControllerHandlerAdapter
spring.http.encoding-autoconfigure.web.HttpEncodingProperties
spring.http.multipart-autoconfigure.web.MultipartProperties
spring.info-autoconfigure.info.ProjectInfoProperties
spring.jackson-autoconfigure.jackson.JacksonProperties
spring.mvc-autoconfigure.web.WebMvcProperties
spring.resources-autoconfigure.web.ResourceProperties
standardJacksonObjectMapperBuilderCustomizer
stringHttpMessageConverter
tomcatEmbeddedServletContainerFactory
viewControllerHandlerMapping
viewResolver
websocketContainerCustomizer
```

需要考虑的重要事项如下：

+   这些 bean 在哪里定义？

+   这些 bean 是如何创建的？

这就是 Spring 自动配置的魔力。

每当我们向 Spring Boot 项目添加新的依赖项时，Spring Boot 自动配置会自动尝试根据依赖项配置 bean。

例如，当我们在`spring-boot-starter-web`中添加依赖项时，将自动配置以下 bean：

+   `basicErrorController`，`handlerExceptionResolver`：基本异常处理。当异常发生时，显示默认错误页面。

+   `beanNameHandlerMapping`：用于解析到处理程序（控制器）的路径。

+   `characterEncodingFilter`：提供默认的字符编码 UTF-8。

+   `dispatcherServlet`：DispatcherServlet 是 Spring MVC 应用程序的前端控制器。

+   `jacksonObjectMapper`：在 REST 服务中将对象转换为 JSON 和 JSON 转换为对象。

+   `messageConverters`：默认消息转换器，用于将对象转换为 XML 或 JSON，反之亦然。

+   `multipartResolver`：提供了在 Web 应用程序中上传文件的支持。

+   `mvcValidator`：支持对 HTTP 请求进行验证。

+   `viewResolver`：将逻辑视图名称解析为物理视图。

+   `propertySourcesPlaceholderConfigurer`：支持应用配置的外部化。

+   `requestContextFilter`：为请求默认过滤器。

+   `restTemplateBuilder`：用于调用 REST 服务。

+   `tomcatEmbeddedServletContainerFactory`：Tomcat 是 Spring Boot 基于 Web 应用程序的默认嵌入式 Servlet 容器。

在下一节中，让我们看一些起始项目和它们提供的自动配置。

# Starter 项目

以下表格显示了 Spring Boot 提供的一些重要的起始项目：

| **Starter** | **描述** |
| --- | --- |
| `spring-boot-starter-web-services` | 这是一个用于开发基于 XML 的 Web 服务的起始项目。 |
| `spring-boot-starter-web` | 这是一个用于构建基于 Spring MVC 的 Web 应用程序或 RESTful 应用程序的起始项目。它使用 Tomcat 作为默认的嵌入式 Servlet 容器。 |
| `spring-boot-starter-activemq` | 这支持在 ActiveMQ 上使用 JMS 进行基于消息的通信。 |
| `spring-boot-starter-integration` | 这支持 Spring Integration Framework，提供了企业集成模式的实现。 |
| `spring-boot-starter-test` | 这提供了对各种单元测试框架的支持，如 JUnit、Mockito 和 Hamcrest matchers。 |
| `spring-boot-starter-jdbc` | 这提供了使用 Spring JDBC 的支持。它默认配置了 Tomcat JDBC 连接池。 |
| `spring-boot-starter-validation` | 这提供了对 Java Bean 验证 API 的支持。它的默认实现是 hibernate-validator。 |
| `spring-boot-starter-hateoas` | HATEOAS 代表超媒体作为应用程序状态的引擎。使用 HATEOAS 的 RESTful 服务返回与当前上下文相关的附加资源的链接。 |
| `spring-boot-starter-jersey` | JAX-RS 是开发 REST API 的 Java EE 标准。Jersey 是默认实现。这个起始项目提供了构建基于 JAX-RS 的 REST API 的支持。 |
| `spring-boot-starter-websocket` | HTTP 是无状态的。WebSockets 允许您在服务器和浏览器之间保持连接。这个起始项目提供了对 Spring WebSockets 的支持。 |
| `spring-boot-starter-aop` | 这提供了面向切面编程的支持。它还提供了对高级面向切面编程的 AspectJ 的支持。 |
| `spring-boot-starter-amqp` | 以 RabbitMQ 为默认，这个起始项目提供了使用 AMQP 进行消息传递的支持。 |
| `spring-boot-starter-security` | 这个起始项目启用了 Spring Security 的自动配置。 |
| `spring-boot-starter-data-jpa` | 这提供了对 Spring Data JPA 的支持。其默认实现是 Hibernate。 |
| `spring-boot-starter` | 这是 Spring Boot 应用程序的基本起始项目。它提供了自动配置和日志记录的支持。 |
| `spring-boot-starter-batch` | 这提供了使用 Spring Batch 开发批处理应用程序的支持。 |
| `spring-boot-starter-cache` | 这是使用 Spring Framework 进行缓存的基本支持。 |
| `spring-boot-starter-data-rest` | 这是使用 Spring Data REST 公开 REST 服务的支持。 |

到目前为止，我们已经建立了一个基本的 Web 应用程序，并了解了与 Spring Boot 相关的一些重要概念：

+   自动配置

+   Starter 项目

+   `spring-boot-maven-plugin`

+   `spring-boot-starter-parent`

+   注解`@SpringBootApplication`

现在让我们把重点转移到理解 REST 是什么，并构建一个 REST 服务。

# REST 是什么？

**表述状态转移**（**REST**）基本上是 Web 的一种架构风格。REST 指定了一组约束。这些约束确保客户端（服务消费者和浏览器）可以以灵活的方式与服务器交互。

让我们首先了解一些常见的术语：

+   **服务器**：服务提供者。提供可以被客户端消费的服务。

+   **客户端**：服务的消费者。可以是浏览器或其他系统。

+   **资源**：任何信息都可以是资源：一个人，一张图片，一个视频，或者你想要销售的产品。

+   **表示**：资源可以以特定的方式表示。例如，产品资源可以使用 JSON、XML 或 HTML 表示。不同的客户端可能会请求资源的不同表示。

以下列出了一些重要的 REST 约束：

+   **客户端-服务器**：应该有一个服务器（服务提供者）和一个客户端（服务消费者）。这使得服务器和客户端可以独立地发展，从而实现松耦合。

+   **无状态**：每个服务应该是无状态的。后续的请求不应依赖于从先前请求中临时存储的某些数据。消息应该是自描述的。

+   **统一接口**：每个资源都有一个资源标识符。在 Web 服务的情况下，我们使用这个 URI 示例：`/users/Jack/todos/1`。在这个 URI 中，Jack 是用户的名字。`1`是我们想要检索的待办事项的 ID。

+   **可缓存**：服务响应应该是可缓存的。每个响应都应指示它是否可缓存。

+   **分层系统**：服务的消费者不应假定与服务提供者直接连接。由于请求可以被缓存，客户端可能会从中间层获取缓存的响应。

+   **通过表示来操作资源**：一个资源可以有多种表示。应该可以通过任何这些表示的消息来修改资源。

+   **超媒体作为应用状态的引擎**（**HATEOAS**）：RESTful 应用的消费者应该只知道一个固定的服务 URL。所有后续的资源都应该可以从资源表示中包含的链接中发现。

以下是带有 HATEOAS 链接的示例响应。这是对检索所有待办事项的请求的响应：

```java
    {  
    "_embedded":{ 
    "todos":[  
            {  
               "user":"Jill",
               "desc":"Learn Hibernate",
               "done":false,
               "_links":{  
                 "self":{  
                        "href":"http://localhost:8080/todos/1"
                  },
                    "todo":{  
                        "href":"http://localhost:8080/todos/1"
                    }
                }
           }
        ]
     },
    "_links":{  
        "self":{  
            "href":"http://localhost:8080/todos"
        },
        "profile":{  
            "href":"http://localhost:8080/profile/todos"
        },
        "search":{  
            "href":"http://localhost:8080/todos/search"
        }
      }
    }
```

前面的响应包括以下链接：

+   特定的待办事项（`http://localhost:8080/todos/1`）

+   搜索资源（`http://localhost:8080/todos/search`）

如果服务的消费者想要进行搜索，它可以从响应中获取搜索 URL 并将搜索请求发送到该 URL。这将减少服务提供者和服务消费者之间的耦合。

我们开发的初始服务不会遵循所有这些约束。随着我们进入下一章，我们将向您介绍这些约束的细节，并将它们添加到服务中，使其更具有 RESTful 特性。

# 第一个 REST 服务

让我们从创建一个简单的 REST 服务返回欢迎消息开始。我们将创建一个简单的 POJO `WelcomeBean`类，其中包含一个名为 message 的成员字段和一个参数构造函数，如下面的代码片段所示：

```java
    package com.mastering.spring.springboot.bean;

    public class WelcomeBean {
      private String message;

       public WelcomeBean(String message) {
         super();
         this.message = message;
       }

      public String getMessage() {
        return message;
      }
    }
```

# 返回字符串的简单方法

让我们从创建一个简单的 REST 控制器方法返回一个字符串开始：

```java
    @RestController
    public class BasicController {
      @GetMapping("/welcome")
      public String welcome() {
        return "Hello World";
      }
    }
```

以下是一些需要注意的重要事项：

+   `@RestController`：`@RestController`注解提供了`@ResponseBody`和`@Controller`注解的组合。这通常用于创建 REST 控制器。

+   `@GetMapping("welcome")`：`@GetMapping`是`@RequestMapping(method = RequestMethod.GET)`的快捷方式。这个注解是一个可读性更好的替代方法。带有这个注解的方法将处理对`welcome` URI 的 Get 请求。

如果我们将`Application.java`作为 Java 应用程序运行，它将启动嵌入式的 Tomcat 容器。我们可以在浏览器中打开 URL，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/a3e4c6eb-ad9e-40c3-b8a5-88b1be0bbf7b.png)

# 单元测试

让我们快速编写一个单元测试来测试前面的`controller`方法：

```java
    @RunWith(SpringRunner.class)
    @WebMvcTest(BasicController.class)
    public class BasicControllerTest {

      @Autowired
      private MockMvc mvc;

      @Test
      public void welcome() throws Exception {
        mvc.perform(
        MockMvcRequestBuilders.get("/welcome")
       .accept(MediaType.APPLICATION_JSON))
       .andExpect(status().isOk())
       .andExpect(content().string(
       equalTo("Hello World")));
      }
    }
```

在前面的单元测试中，我们将使用`BasicController`启动一个 Mock MVC 实例。以下是一些需要注意的事项：

+   `@RunWith(SpringRunner.class)`: SpringRunner 是`SpringJUnit4ClassRunner`注解的快捷方式。这为单元测试启动了一个简单的 Spring 上下文。

+   `@WebMvcTest(BasicController.class)`: 这个注解可以与 SpringRunner 一起使用，用于编写 Spring MVC 控制器的简单测试。这将只加载使用 Spring-MVC 相关注解注释的 bean。在这个例子中，我们正在启动一个 Web MVC 测试上下文，测试的类是 BasicController。

+   `@Autowired private MockMvc mvc`: 自动装配可以用于发出请求的 MockMvc bean。

+   `mvc.perform(MockMvcRequestBuilders.get("/welcome").accept(MediaType.APPLICATION_JSON))`: 使用`Accept`头值`application/json`执行对`/welcome`的请求。

+   `andExpect(status().isOk())`: 期望响应的状态为 200（成功）。

+   `andExpect(content().string(equalTo("Hello World")))`: 期望响应的内容等于"Hello World"。

# 集成测试

当我们进行集成测试时，我们希望启动嵌入式服务器，并加载所有配置的控制器和 bean。这段代码片段展示了我们如何创建一个简单的集成测试：

```java
    @RunWith(SpringRunner.class)
    @SpringBootTest(classes = Application.class, 
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
    public class BasicControllerIT {

      private static final String LOCAL_HOST = 
      "http://localhost:";

      @LocalServerPort
      private int port;

      private TestRestTemplate template = new TestRestTemplate();

      @Test
      public void welcome() throws Exception {
        ResponseEntity<String> response = template
       .getForEntity(createURL("/welcome"), String.class);
        assertThat(response.getBody(), equalTo("Hello World"));
       }

      private String createURL(String uri) {
        return LOCAL_HOST + port + uri;
      }
    }
```

需要注意的一些重要事项如下：

+   `@SpringBootTest(classes = Application.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)`: 提供了在 Spring TestContext 之上的额外功能。提供支持以配置端口来完全运行容器和 TestRestTemplate（执行请求）。

+   `@LocalServerPort private int port`: `SpringBootTest`会确保容器运行的端口被自动装配到端口变量中。

+   `private String createURL(String uri)`: 用于将本地主机 URL 和端口附加到 URI 以创建完整 URL 的方法。

+   `private TestRestTemplate template = new TestRestTemplate()`: `TestRestTemplate`通常用于集成测试。它提供了在 RestTemplate 之上的额外功能，在集成测试环境中特别有用。它不会遵循重定向，这样我们就可以断言响应位置。

+   `template.getForEntity(createURL("/welcome"), String.class)`: 执行对给定 URI 的 get 请求。

+   `assertThat(response.getBody(), equalTo("Hello World"))`: 断言响应主体内容为"Hello World"。

# 返回对象的简单 REST 方法

在前面的方法中，我们返回了一个字符串。让我们创建一个返回正确的 JSON 响应的方法。看一下下面的方法：

```java
    @GetMapping("/welcome-with-object")
    public WelcomeBean welcomeWithObject() {
      return new WelcomeBean("Hello World");
    }
```

这个先前的方法返回一个简单的`WelcomeBean`，它初始化了一个消息："Hello World"。

# 执行请求

让我们发送一个测试请求，看看我们得到什么响应。下面的截图显示了输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/40d5ea71-69db-451d-80f6-92736cb39929.png)

`http://localhost:8080/welcome-with-object` URL 的响应如下所示：

```java
    {"message":"Hello World"}
```

需要回答的问题是：我们返回的`WelcomeBean`对象是如何转换为 JSON 的？

再次，这是 Spring Boot 自动配置的魔力。如果 Jackson 在应用程序的类路径上，Spring Boot 会自动配置默认的对象到 JSON（反之亦然）转换器的实例。

# 单元测试

让我们快速编写一个单元测试，检查 JSON 响应。让我们将测试添加到`BasicControllerTest`中：

```java
    @Test
    public void welcomeWithObject() throws Exception {
      mvc.perform(
       MockMvcRequestBuilders.get("/welcome-with-object")
      .accept(MediaType.APPLICATION_JSON))
      .andExpect(status().isOk())
      .andExpect(content().string(containsString("Hello World")));
    }
```

这个测试与之前的单元测试非常相似，只是我们使用`containsString`来检查内容是否包含子字符串"Hello World"。稍后我们将学习如何编写正确的 JSON 测试。

# 集成测试

让我们把注意力转移到编写一个集成测试。让我们向`BasicControllerIT`中添加一个方法，如下面的代码片段所示：

```java
    @Test
    public void welcomeWithObject() throws Exception {
      ResponseEntity<String> response = 
      template.getForEntity(createURL("/welcome-with-object"), 
      String.class);
      assertThat(response.getBody(), 
      containsString("Hello World"));
    }
```

这个方法与之前的集成测试类似，只是我们使用`String`方法来断言子字符串。

# 带有路径变量的 Get 方法

让我们把注意力转移到路径变量上。路径变量用于将 URI 中的值绑定到控制器方法上的变量。在以下示例中，我们希望对名称进行参数化，以便我们可以使用名称定制欢迎消息：

```java
    private static final String helloWorldTemplate = "Hello World, 
    %s!";

   @GetMapping("/welcome-with-parameter/name/{name}")
   public WelcomeBean welcomeWithParameter(@PathVariable String name) 
    {
       return new WelcomeBean(String.format(helloWorldTemplate, name));
    }
```

需要注意的几个重要事项如下：

+   `@GetMapping("/welcome-with-parameter/name/{name}")`：`{name}`表示这个值将是变量。我们可以在 URI 中有多个变量模板。

+   `welcomeWithParameter(@PathVariable String name)`：`@PathVariable`确保从 URI 中的变量值绑定到变量名称。

+   `String.format(helloWorldTemplate, name)`：一个简单的字符串格式，用名称替换模板中的`%s`。

# 执行请求

让我们发送一个测试请求，看看我们得到什么响应。以下截图显示了响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/d1ec666d-e2ec-4a15-9a46-5babdcddbf66.png)

`http://localhost:8080/welcome-with-parameter/name/Buddy` URL 的响应如下：

```java
    {"message":"Hello World, Buddy!"}
```

如预期，URI 中的名称用于形成响应中的消息。

# 单元测试

让我们快速为前面的方法编写一个单元测试。我们希望将名称作为 URI 的一部分传递，并检查响应是否包含名称。以下代码显示了我们如何做到这一点：

```java
    @Test
    public void welcomeWithParameter() throws Exception {
      mvc.perform(
      MockMvcRequestBuilders.get("/welcome-with-parameter/name/Buddy")
     .accept(MediaType.APPLICATION_JSON))
     .andExpect(status().isOk())
     .andExpect(
     content().string(containsString("Hello World, Buddy")));
    }
```

需要注意的几个重要事项如下：

+   `MockMvcRequestBuilders.get("/welcome-with-parameter/name/Buddy")`：这与 URI 中的变量模板匹配。我们传入名称`Buddy`。

+   `.andExpect(content().string(containsString("Hello World, Buddy”)))`：我们期望响应包含带有名称的消息。

# 集成测试

前面方法的集成测试非常简单。看一下以下测试方法：

```java
    @Test
    public void welcomeWithParameter() throws Exception {
      ResponseEntity<String> response = 
      template.getForEntity(
      createURL("/welcome-with-parameter/name/Buddy"), String.class);
      assertThat(response.getBody(), 
      containsString("Hello World, Buddy"));
    }
```

需要注意的几个重要事项如下：

+   `createURL("/welcome-with-parameter/name/Buddy")`：这与 URI 中的变量模板匹配。我们传入名称 Buddy。

+   `assertThat(response.getBody(), containsString("Hello World, Buddy”))`：我们期望响应包含带有名称的消息。

在本节中，我们看了使用 Spring Boot 创建简单 REST 服务的基础知识。我们还确保我们有良好的单元测试和集成测试。虽然这些都非常基础，但它们为我们在下一节中构建更复杂的 REST 服务奠定了基础。

我们实施的单元测试和集成测试可以使用 JSON 比较而不是简单的子字符串比较来进行更好的断言。我们将在下一节中为我们创建的 REST 服务编写的测试中专注于这一点。

# 创建待办事项资源

我们将专注于为基本待办事项管理系统创建 REST 服务。我们将为以下内容创建服务：

+   检索给定用户的待办事项列表

+   检索特定待办事项的详细信息

+   为用户创建待办事项

# 请求方法、操作和 URI

REST 服务的最佳实践之一是根据我们执行的操作使用适当的 HTTP 请求方法。在我们暴露的服务中，我们使用了`GET`方法，因为我们专注于读取数据的服务。

以下表格显示了基于我们执行的操作的适当 HTTP 请求方法：

| **HTTP 请求方法** | **操作** |
| --- | --- |
| `GET` | 读取--检索资源的详细信息 |
| `POST` | 创建--创建新项目或资源 |
| `PUT` | 更新/替换 |
| `PATCH` | 更新/修改资源的一部分 |
| `DELETE` | 删除 |

让我们快速将我们要创建的服务映射到适当的请求方法：

+   **检索给定用户的待办事项列表**：这是`读取`。我们将使用`GET`。我们将使用 URI：`/users/{name}/todos`。另一个良好的实践是在 URI 中对静态内容使用复数形式：users，todo 等。这会导致更可读的 URI。

+   **检索特定待办事项的详细信息**：同样，我们将使用`GET`。我们将使用 URI `/users/{name}/todos/{id}`。您可以看到这与我们之前为待办事项列表决定的 URI 是一致的。

+   **为用户创建待办事项**：对于创建操作，建议的 HTTP 请求方法是`POST`。要创建一个新的待办事项，我们将发布到`URI /users/{name}/todos`。

# Beans and services

为了能够检索和存储待办事项的详细信息，我们需要一个 Todo bean 和一个用于检索和存储详细信息的服务。

让我们创建一个 Todo Bean：

```java
    public class Todo {
      private int id;
      private String user;

      private String desc;

      private Date targetDate;
      private boolean isDone;

      public Todo() {}

      public Todo(int id, String user, String desc, 
      Date targetDate, boolean isDone) { 
        super();
        this.id = id;
        this.user = user;
        this.desc = desc;
        this.targetDate = targetDate;
        this.isDone = isDone;
      }

       //ALL Getters
    }
```

我们创建了一个简单的 Todo bean，其中包含 ID、用户名称、待办事项描述、待办事项目标日期和完成状态指示器。我们为所有字段添加了构造函数和 getter。

现在让我们添加`TodoService`：

```java
   @Service
   public class TodoService {
     private static List<Todo> todos = new ArrayList<Todo>();
     private static int todoCount = 3;

     static {
       todos.add(new Todo(1, "Jack", "Learn Spring MVC", 
       new Date(), false));
       todos.add(new Todo(2, "Jack", "Learn Struts", new Date(), 
       false));
       todos.add(new Todo(3, "Jill", "Learn Hibernate", new Date(), 
       false));
      }

     public List<Todo> retrieveTodos(String user) {
       List<Todo> filteredTodos = new ArrayList<Todo>();
       for (Todo todo : todos) {
         if (todo.getUser().equals(user))
         filteredTodos.add(todo);
        }
      return filteredTodos;
     }

    public Todo addTodo(String name, String desc, 
    Date targetDate, boolean isDone) {
      Todo todo = new Todo(++todoCount, name, desc, targetDate, 
      isDone);
      todos.add(todo);
      return todo;
    }

    public Todo retrieveTodo(int id) {
      for (Todo todo : todos) {
      if (todo.getId() == id)
        return todo;
      }
      return null;
     }
   }
```

需要注意的快速事项如下：

+   为了保持简单，该服务不与数据库通信。它维护一个待办事项的内存数组列表。该列表使用静态初始化程序进行初始化。

+   我们公开了一些简单的检索方法和一个添加待办事项的方法。

现在我们的服务和 bean 已经准备好了，我们可以创建我们的第一个服务来为用户检索待办事项列表。

# 检索待办事项列表

我们将创建一个名为`TodoController`的新`RestController`注解。检索待办事项方法的代码如下所示：

```java
    @RestController
    public class TodoController {
     @Autowired
     private TodoService todoService;

     @GetMapping("/users/{name}/todos")
     public List<Todo> retrieveTodos(@PathVariable String name) {
       return todoService.retrieveTodos(name);
     }
    }
```

需要注意的一些事项如下：

+   我们使用`@Autowired`注解自动装配了待办事项服务

+   我们使用`@GetMapping`注解将`"/users/{name}/todos"` URI 的 Get 请求映射到`retrieveTodos`方法

# 执行服务

让我们发送一个测试请求，看看我们将得到什么响应。下图显示了输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/3eee8995-485d-414b-bd47-f0aec4e91d9f.png)

`http://localhost:8080/users/Jack/todos`的响应如下：

```java
   [
    {"id":1,"user":"Jack","desc":"Learn Spring    
     MVC","targetDate":1481607268779,"done":false},  
    {"id":2,"user":"Jack","desc":"Learn 
    Struts","targetDate":1481607268779, "done":false}
   ]
```

# 单元测试

用于单元测试`TodoController`类的代码如下所示：

```java
   @RunWith(SpringRunner.class)
   @WebMvcTest(TodoController.class)
   public class TodoControllerTest {

    @Autowired
    private MockMvc mvc;

    @MockBean
    private TodoService service;

    @Test
    public void retrieveTodos() throws Exception {
     List<Todo> mockList = Arrays.asList(new Todo(1, "Jack",
     "Learn Spring MVC", new Date(), false), new Todo(2, "Jack",
     "Learn Struts", new Date(), false));

     when(service.retrieveTodos(anyString())).thenReturn(mockList);

     MvcResult result = mvc
    .perform(MockMvcRequestBuilders.get("/users
    /Jack/todos").accept(MediaType.APPLICATION_JSON))
    .andExpect(status().isOk()).andReturn();

    String expected = "["
     + "{id:1,user:Jack,desc:\"Learn Spring MVC\",done:false}" +","
     + "{id:2,user:Jack,desc:\"Learn Struts\",done:false}" + "]";

     JSONAssert.assertEquals(expected, result.getResponse()
      .getContentAsString(), false);
     }
    }
```

一些重要的事情需要注意：

+   我们正在编写一个单元测试。因此，我们只想测试`TodoController`类中的逻辑。因此，我们使用`@WebMvcTest(TodoController.class)`初始化一个仅包含`TodoController`类的 Mock MVC 框架。

+   `@MockBean private TodoService service`：我们使用`@MockBean`注解模拟了 TodoService。在使用 SpringRunner 运行的测试类中，使用`@MockBean`定义的 bean 将被使用 Mockito 框架创建的模拟对象替换。

+   `when(service.retrieveTodos(anyString())).thenReturn(mockList)`：我们模拟了 retrieveTodos 服务方法以返回模拟列表。

+   `MvcResult result = ..`：我们将请求的结果接受到一个 MvcResult 变量中，以便我们可以对响应执行断言。

+   `JSONAssert.assertEquals(expected, result.getResponse().getContentAsString(), false)`: JSONAssert 是一个非常有用的框架，用于对 JSON 执行断言。它将响应文本与期望值进行比较。JSONAssert 足够智能，可以忽略未指定的值。另一个优点是在断言失败时提供清晰的失败消息。最后一个参数 false 表示使用非严格模式。如果将其更改为 true，则期望值应与结果完全匹配。

# 集成测试

用于对`TodoController`类执行集成测试的代码如下所示。它启动了整个 Spring 上下文，其中定义了所有控制器和 bean：

```java
   @RunWith(SpringJUnit4ClassRunner.class)
   @SpringBootTest(classes = Application.class, webEnvironment =     
   SpringBootTest.WebEnvironment.RANDOM_PORT)
   public class TodoControllerIT {

    @LocalServerPort
    private int port;

    private TestRestTemplate template = new TestRestTemplate();

    @Test
    public void retrieveTodos() throws Exception {
     String expected = "["
     + "{id:1,user:Jack,desc:\"Learn Spring MVC\",done:false}" + ","
     + "{id:2,user:Jack,desc:\"Learn Struts\",done:false}" + "]";

     String uri = "/users/Jack/todos";

     ResponseEntity<String> response =
     template.getForEntity(createUrl(uri), String.class);

     JSONAssert.assertEquals(expected, response.getBody(), false);
    }

     private String createUrl(String uri) {
     return "http://localhost:" + port + uri;
    }
  }
```

这个测试与`BasicController`的集成测试非常相似，只是我们使用`JSONAssert`来断言响应。

# 检索特定待办事项的详细信息

现在我们将添加检索特定待办事项的方法：

```java
    @GetMapping(path = "/users/{name}/todos/{id}")
    public Todo retrieveTodo(@PathVariable String name, @PathVariable 
    int id) {
      return todoService.retrieveTodo(id);
    }
```

需要注意的一些事项如下：

+   映射的 URI 是`/users/{name}/todos/{id}`

+   我们为`name`和`id`定义了两个路径变量

# 执行服务

让我们发送一个测试请求，看看我们将得到什么响应，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/9aa9de2d-c774-4c1c-879c-1b421738da2b.png)

`http://localhost:8080/users/Jack/todos/1`的响应如下所示：

```java
    {"id":1,"user":"Jack","desc":"Learn Spring MVC", 
    "targetDate":1481607268779,"done":false}
```

# 单元测试

对`retrieveTodo`进行单元测试的代码如下：

```java
     @Test
     public void retrieveTodo() throws Exception {
       Todo mockTodo = new Todo(1, "Jack", "Learn Spring MVC", 
       new Date(), false);

       when(service.retrieveTodo(anyInt())).thenReturn(mockTodo);

       MvcResult result = mvc.perform(
       MockMvcRequestBuilders.get("/users/Jack/todos/1")
       .accept(MediaType.APPLICATION_JSON))
       .andExpect(status().isOk()).andReturn();

       String expected = "{id:1,user:Jack,desc:\"Learn Spring
       MVC\",done:false}";

      JSONAssert.assertEquals(expected, 
       result.getResponse().getContentAsString(), false);

     }
```

需要注意的几个重要事项如下：

+   `when(service.retrieveTodo(anyInt())).thenReturn(mockTodo)`：我们正在模拟 retrieveTodo 服务方法返回模拟的待办事项。

+   `MvcResult result = ..`：我们将请求的结果接受到 MvcResult 变量中，以便我们对响应执行断言。

+   `JSONAssert.assertEquals(expected, result.getResponse().getContentAsString(), false)`：断言结果是否符合预期。

# 集成测试

在以下代码片段中显示了对`TodoController`中的`retrieveTodos`进行集成测试的代码。这将添加到`TodoControllerIT`类中：

```java
     @Test
     public void retrieveTodo() throws Exception {
       String expected = "{id:1,user:Jack,desc:\"Learn Spring   
       MVC\",done:false}";
       ResponseEntity<String> response = template.getForEntity(
       createUrl("/users/Jack/todos/1"), String.class);
       JSONAssert.assertEquals(expected, response.getBody(), false);
     }
```

# 添加待办事项

现在我们将添加创建新待办事项的方法。用于创建的 HTTP 方法是`Post`。我们将发布到`"/users/{name}/todos"` URI：

```java
    @PostMapping("/users/{name}/todos")
    ResponseEntity<?> add(@PathVariable String name,
    @RequestBody Todo todo) { 
      Todo createdTodo = todoService.addTodo(name, todo.getDesc(),
      todo.getTargetDate(), todo.isDone());
      if (createdTodo == null) {
         return ResponseEntity.noContent().build();
      }

     URI location = ServletUriComponentsBuilder.fromCurrentRequest()

    .path("/{id}").buildAndExpand(createdTodo.getId()).toUri();
    return ResponseEntity.created(location).build();
   }
```

需要注意的几件事如下：

+   `@PostMapping("/users/{name}/todos")`：`@PostMapping`注解将`add()`方法映射到具有`POST`方法的 HTTP 请求。

+   `ResponseEntity<?> add(@PathVariable String name, @RequestBody Todo todo)`：HTTP POST 请求应该理想地返回创建资源的 URI。我们使用`ResourceEntity`来实现这一点。`@RequestBody`将请求的正文直接绑定到 bean。

+   `ResponseEntity.noContent().build()`：用于返回资源创建失败的情况。

+   `ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}").buildAndExpand(createdTodo.getId()).toUri()`：形成可以在响应中返回的已创建资源的 URI。

+   `ResponseEntity.created(location).build()`：返回`201(CREATED)`状态，并附带资源的链接。

# Postman

如果您使用的是 Mac，您可能还想尝试 Paw 应用程序。

让我们发送一个测试请求，看看我们得到什么响应。以下截图显示了响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/4e7d4629-6213-4a71-a769-9579f3e87b9f.png)

我们将使用 Postman 应用程序与 REST 服务进行交互。您可以从网站[`www.getpostman.com/`](https://www.getpostman.com/)安装它。它适用于 Windows 和 Mac。还提供 Google Chrome 插件。

# 执行 POST 服务

使用`POST`创建新的待办事项，我们需要在请求的正文中包含待办事项的 JSON。以下截图显示了我们如何使用 Postman 应用程序创建请求以及执行请求后的响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/dd150c03-a64e-40d0-8ff7-603c781e3b82.png)

需要注意的几个重要事项如下：

+   我们正在发送 POST 请求。因此，我们从左上角的下拉菜单中选择 POST。

+   要将 Todo JSON 作为请求正文的一部分发送，我们在 Body 选项卡中选择原始选项（用蓝点标出）。我们选择 JSON（`application/json`）作为内容类型。

+   一旦请求成功执行，您可以在屏幕中间的栏中看到请求的状态：状态：201 已创建。

+   位置是`http://localhost:8080/users/Jack/todos/5`。这是在响应中收到的新创建的待办事项的 URI。

`http://localhost:8080/users/Jack/todos`的请求的完整细节如下所示：

```java
    Header
    Content-Type:application/json

   Body
    {
      "user": "Jack",
      "desc": "Learn Spring Boot",
       "done": false
     }
```

# 单元测试

对创建的待办事项进行单元测试的代码如下所示：

```java
    @Test
    public void createTodo() throws Exception {
     Todo mockTodo = new Todo(CREATED_TODO_ID, "Jack", 
     "Learn Spring MVC", new Date(), false);
     String todo = "{"user":"Jack","desc":"Learn Spring MVC",     
     "done":false}";

    when(service.addTodo(anyString(), anyString(),   
    isNull(),anyBoolean()))
    .thenReturn(mockTodo);

   mvc
    .perform(MockMvcRequestBuilders.post("/users/Jack/todos")
    .content(todo)
    .contentType(MediaType.APPLICATION_JSON)
    )
    .andExpect(status().isCreated())
    .andExpect(
      header().string("location",containsString("/users/Jack/todos/"
     + CREATED_TODO_ID)));
   }
```

需要注意的几个重要事项如下：

+   `String todo = "{"user":"Jack","desc":"Learn Spring MVC","done":false}"`：要发布到创建待办事项服务的 Todo 内容。

+   `when(service.addTodo(anyString(), anyString(), isNull(), anyBoolean())).thenReturn(mockTodo)`：模拟服务返回一个虚拟的待办事项。

+   `MockMvcRequestBuilders.post("/users/Jack/todos").content(todo).contentType(MediaType.APPLICATION_JSON))`：使用给定的内容类型创建给定 URI 的 POST。

+   `andExpect(status().isCreated())`：期望状态为已创建。

+   `andExpect(header().string("location",containsString("/users/Jack/todos/" + CREATED_TODO_ID)))`: 期望标头包含创建资源的 URI 的`location`。

# 集成测试

在`TodoController`中执行对创建的 todo 的集成测试的代码如下所示。这将添加到`TodoControllerIT`类中，如下所示：

```java
    @Test
    public void addTodo() throws Exception {
      Todo todo = new Todo(-1, "Jill", "Learn Hibernate", new Date(),  
      false);
      URI location = template
     .postForLocation(createUrl("/users/Jill/todos"),todo);
      assertThat(location.getPath(), 
      containsString("/users/Jill/todos/4"));
    }
```

还有一些重要的事项需要注意：

+   `URI location = template.postForLocation(createUrl("/users/Jill/todos"), todo)`: `postForLocation`是一个实用方法，特别适用于测试，用于创建新资源。我们正在将 todo 发布到给定的 URI，并从标头中获取位置。

+   `assertThat(location.getPath(), containsString("/users/Jill/todos/4"))`: 断言位置包含到新创建资源的路径。

# Spring Initializr

您想要自动生成 Spring Boot 项目吗？您想要快速开始开发您的应用程序吗？Spring Initializr 就是答案。

Spring Initializr 托管在[`start.spring.io`](http://start.spring.io)。以下截图显示了网站的外观：

***![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/aebe0da6-f812-409d-94b2-c11f40ad574a.png)***

Spring Initializr 在创建项目时提供了很大的灵活性。您可以选择以下选项：

+   选择您的构建工具：Maven 或 Gradle。

+   选择您要使用的 Spring Boot 版本。

+   为您的组件配置 Group ID 和 Artifact ID。

+   选择您的项目所需的启动器（依赖项）。您可以单击屏幕底部的链接“切换到完整版本”来查看您可以选择的所有启动器项目。

+   选择如何打包您的组件：JAR 或 WAR。

+   选择您要使用的 Java 版本。

+   选择要使用的 JVM 语言。

当您展开（单击链接）到完整版本时，Spring Initializr 提供的一些选项如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/df21a0ab-8ee6-4b69-ad86-db4f5206184b.png)

# 创建您的第一个 Spring Initializr 项目

我们将使用完整版本并输入值，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/064b95c0-d6ec-4b51-8315-3bddedeb0431.png)

需要注意的事项如下：

+   构建工具：`Maven`

+   Spring Boot 版本：选择最新可用的版本

+   Group：`com.mastering.spring`

+   Artifact: `first-spring-initializr`

+   选择的依赖项：选择`Web, JPA, Actuator and Dev Tools`。在文本框中输入每个依赖项，然后按*Enter*选择它们。我们将在下一节中了解有关 Actuator 和 Dev Tools 的更多信息

+   Java 版本：`1.8`

继续并单击生成项目按钮。这将创建一个`.zip`文件，您可以将其下载到您的计算机上。

以下截图显示了创建的项目的结构：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/ef3d2f76-c0ba-4fbe-9855-5266a920c53b.png)

现在我们将此项目导入到您的 IDE 中。在 Eclipse 中，您可以执行以下步骤：

1.  启动 Eclipse。

1.  导航到文件|导入。

1.  选择现有的 Maven 项目。

1.  浏览并选择 Maven 项目的根目录（包含`pom.xml`文件的目录）。

1.  继续使用默认值，然后单击完成。

这将把项目导入到 Eclipse 中。以下截图显示了 Eclipse 中项目的结构：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/eb2f4b68-7e2b-4233-a748-192b28282c91.png)

让我们来看一下生成项目中的一些重要文件。

# pom.xml

以下代码片段显示了声明的依赖项：

```java
<dependencies> <dependency> <groupId>org.springframework.boot</groupId> <artifactId>spring-boot-starter-web</artifactId> </dependency> <dependency> <groupId>org.springframework.boot</groupId> <artifactId>spring-boot-starter-data-jpa</artifactId> </dependency> <dependency> <groupId>org.springframework.boot</groupId> <artifactId>spring-boot-starter-actuator</artifactId> </dependency> <dependency> <groupId>org.springframework.boot</groupId> <artifactId>spring-boot-devtools</artifactId> <scope>runtime</scope> </dependency> <dependency> <groupId>org.springframework.boot</groupId> <artifactId>spring-boot-starter-test</artifactId> <scope>test</scope> </dependency> </dependencies>
```

还有一些其他重要的观察结果如下：

+   此组件的打包为`.jar`

+   `org.springframework.boot:spring-boot-starter-parent`被声明为父 POM

+   `<java.version>1.8</java.version>`: Java 版本为 1.8

+   Spring Boot Maven 插件(`org.springframework.boot:spring-boot-maven-plugin`)被配置为插件

# FirstSpringInitializrApplication.java 类

`FirstSpringInitializrApplication.java`是 Spring Boot 的启动器：

```java
    package com.mastering.spring;
    import org.springframework.boot.SpringApplication;
    import org.springframework.boot.autoconfigure
    .SpringBootApplication;

    @SpringBootApplication
    public class FirstSpringInitializrApplication {
       public static void main(String[] args) {
        SpringApplication.run(FirstSpringInitializrApplication.class,   
        args);
      }
    }
```

# FirstSpringInitializrApplicationTests 类

`FirstSpringInitializrApplicationTests`包含了可以用来开始编写测试的基本上下文，当我们开始开发应用程序时：

```java
    package com.mastering.spring;
    import org.junit.Test;
    import org.junit.runner.RunWith;
    import org.springframework.boot.test.context.SpringBootTest;
    import org.springframework.test.context.junit4.SpringRunner;

    @RunWith(SpringRunner.class)
    @SpringBootTest
    public class FirstSpringInitializrApplicationTests {

      @Test
      public void contextLoads() {
      }
   }
```

# 快速了解自动配置

自动配置是 Spring Boot 最重要的功能之一。在本节中，我们将快速了解 Spring Boot 自动配置的工作原理。

大部分 Spring Boot 自动配置的魔力来自于`spring-boot-autoconfigure-{version}.jar`。当我们启动任何 Spring Boot 应用程序时，会自动配置许多 bean。这是如何发生的？

以下截图显示了来自`spring-boot-autoconfigure-{version}.jar`的`spring.factories`的摘录。出于空间的考虑，我们已经过滤掉了一些配置：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/1c3c6692-d315-4041-b6d5-a57aec4e75ee.png)

每当启动 Spring Boot 应用程序时，上述自动配置类的列表都会运行。让我们快速看一下其中一个：

`org.springframework.boot.autoconfigure.web.WebMvcAutoConfiguration`。

这是一个小片段：

```java
@Configuration
@ConditionalOnWebApplication
@ConditionalOnClass({ Servlet.class, DispatcherServlet.class,
WebMvcConfigurerAdapter.class })
@ConditionalOnMissingBean(WebMvcConfigurationSupport.class)
@AutoConfigureOrder(Ordered.HIGHEST_PRECEDENCE + 10)
@AutoConfigureAfter(DispatcherServletAutoConfiguration.class)
public class WebMvcAutoConfiguration {
```

一些重要的要点如下：

+   `@ConditionalOnClass({ Servlet.class, DispatcherServlet.class, WebMvcConfigurerAdapter.class })`：如果类路径中有提到的任何类，则启用此自动配置。当我们添加 web 启动器项目时，会带入所有这些类的依赖项。因此，此自动配置将被启用。

+   `@ConditionalOnMissingBean(WebMvcConfigurationSupport.class)`: 只有在应用程序没有明确声明`WebMvcConfigurationSupport.class`类的 bean 时，才启用此自动配置。

+   `@AutoConfigureOrder(Ordered.HIGHEST_PRECEDENCE + 10)`: 这指定了这个特定自动配置的优先级。

让我们看另一个小片段，显示了同一类中的一个方法：

```java
    @Bean
    @ConditionalOnBean(ViewResolver.class)
    @ConditionalOnMissingBean(name = "viewResolver", 
    value = ContentNegotiatingViewResolver.class)
    public ContentNegotiatingViewResolver 
    viewResolver(BeanFactory beanFactory) {
      ContentNegotiatingViewResolver resolver = new 
      ContentNegotiatingViewResolver();
      resolver.setContentNegotiationManager
      (beanFactory.getBean(ContentNegotiationManager.class));
      resolver.setOrder(Ordered.HIGHEST_PRECEDENCE);
      return resolver;
     }
```

视图解析器是由`WebMvcAutoConfiguration`类配置的 bean 之一。上述片段确保如果应用程序没有提供视图解析器，则 Spring Boot 会自动配置默认的视图解析器。以下是一些重要要点：

+   `@ConditionalOnBean(ViewResolver.class)`: 如果`ViewResolver.class`在类路径上，则创建此 bean

+   `@ConditionalOnMissingBean(name = "viewResolver", value = ContentNegotiatingViewResolver.class)`: 如果没有明确声明名称为`viewResolver`且类型为`ContentNegotiatingViewResolver.class`的 bean，则创建此 bean。

+   方法的其余部分在视图解析器中配置

总之，所有自动配置逻辑都在 Spring Boot 应用程序启动时执行。如果类路径上有特定依赖项或启动器项目的特定类可用，则会执行自动配置类。这些自动配置类查看已经配置的 bean。根据现有的 bean，它们启用默认 bean 的创建。

# 总结

Spring Boot 使得开发基于 Spring 的应用程序变得容易。它使我们能够从项目的第一天起创建生产就绪的应用程序。

在本章中，我们介绍了 Spring Boot 和 REST 服务的基础知识。我们讨论了 Spring Boot 的不同特性，并创建了一些带有很好测试的 REST 服务。我们通过深入了解自动配置来了解后台发生了什么。

在下一章中，我们将把注意力转向为 REST 服务添加更多功能。
