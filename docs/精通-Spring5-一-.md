# 精通 Spring5（一）

> 原文：[`zh.annas-archive.org/md5/73290E1F786F5BAA832E07A902070E3F`](https://zh.annas-archive.org/md5/73290E1F786F5BAA832E07A902070E3F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Spring 5.0 即将推出，将带来许多新的令人兴奋的功能，将改变我们迄今为止使用该框架的方式。本书将向您展示这一演变——从解决可测试应用程序的问题到在云端构建分布式应用程序。

本书以介绍 Spring 5.0 的新功能开始，并向您展示如何使用 Spring MVC 构建应用程序。然后，您将深入了解如何使用 Spring Framework 构建和扩展微服务。您还将了解如何构建和部署云应用程序。您将意识到应用程序架构是如何从单体架构演变为围绕微服务构建的。还将涵盖 Spring Boot 的高级功能，并通过强大的示例展示。

通过本书，您将掌握使用 Spring Framework 开发应用程序的知识和最佳实践。

# 本书涵盖内容

第一章《Evolution to Spring Framework 5.0》带您了解 Spring Framework 的演变，从最初的版本到 Spring 5.0。最初，Spring 被用来使用依赖注入和核心模块开发可测试的应用程序。最近的 Spring 项目，如 Spring Boot、Spring Cloud、Spring Cloud Data Flow，涉及应用程序基础设施和将应用程序迁移到云端。我们将概述不同的 Spring 模块和项目。

第二章《Dependency Injection》深入探讨了依赖注入。我们将看看 Spring 中可用的不同类型的依赖注入方法，以及自动装配如何简化您的生活。我们还将快速了解单元测试。

第三章《使用 Spring MVC 构建 Web 应用程序》快速概述了使用 Spring MVC 构建 Web 应用程序。

第四章《演变为微服务和云原生应用程序》解释了过去十年应用程序架构的演变。我们将了解为什么需要微服务和云原生应用程序，并快速概述帮助我们构建云原生应用程序的不同 Spring 项目。

第五章《使用 Spring Boot 构建微服务》讨论了 Spring Boot 如何简化创建生产级 Spring 应用程序的复杂性。它使得使用基于 Spring 的项目变得更加容易，并提供了与第三方库的轻松集成。在本章中，我们将带领学生一起使用 Spring Boot。我们将从实现基本的 Web 服务开始，然后逐步添加缓存、异常处理、HATEOAS 和国际化，同时利用 Spring Framework 的不同功能。

第六章《扩展微服务》专注于为我们在第四章中构建的微服务添加更多高级功能。

第七章《Spring Boot 高级功能》介绍了 Spring Boot 的高级功能。您将学习如何使用 Spring Boot Actuator 监视微服务。然后，您将把微服务部署到云端。您还将学习如何使用 Spring Boot 提供的开发者工具更有效地开发。

第八章《Spring Data》讨论了 Spring Data 模块。我们将开发简单的应用程序，将 Spring 与 JPA 和大数据技术集成在一起。

第九章《Spring Cloud》讨论了云中的分布式系统存在的常见问题，包括配置管理、服务发现、断路器和智能路由。在本章中，您将了解 Spring Cloud 如何帮助您为这些常见模式开发解决方案。这些解决方案应该在云端和开发人员的本地系统上都能很好地运行。

第十章《Spring Cloud 数据流》讨论了 Spring Cloud 数据流，它提供了一系列关于基于微服务的分布式流式处理和批处理数据管道的模式和最佳实践。在本章中，我们将了解 Spring Cloud 数据流的基础知识，并使用它构建基本的数据流使用案例。

第十一章《响应式编程》探讨了使用异步数据流进行编程。在本章中，我们将了解响应式编程，并快速了解 Spring Framework 提供的功能。

第十二章《Spring 最佳实践》帮助您了解与单元测试、集成测试、维护 Spring 配置等相关的 Spring 企业应用程序开发的最佳实践。

第十三章《在 Spring 中使用 Kotlin》向您介绍了一种快速流行的 JVM 语言——Kotlin。我们将讨论如何在 Eclipse 中设置 Kotlin 项目。我们将使用 Kotlin 创建一个新的 Spring Boot 项目，并实现一些基本的服务，并进行单元测试和集成测试。

# 本书所需内容

为了能够运行本书中的示例，您需要以下工具：

+   Java 8

+   Eclipse IDE

+   Postman

我们将使用嵌入到 Eclipse IDE 中的 Maven 来下载所有需要的依赖项。

# 本书适合对象

本书适用于有经验的 Java 开发人员，他们了解 Spring 的基础知识，并希望学习如何使用 Spring Boot 构建应用程序并将其部署到云端。

# 惯例

在本书中，您会发现一些区分不同类型信息的文本样式。以下是一些这些样式的示例及其含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL 和用户输入显示如下："在您的`pom.xml`文件中配置`spring-boot-starter-parent`"。

代码块设置如下：

```java
<properties>
  <mockito.version>1.10.20</mockito.version>
</properties>
```

任何命令行输入或输出都以以下方式编写：

```java
mvn clean install
```

**新术语**和**重要词汇**以粗体显示。您在屏幕上看到的词语，例如菜单或对话框中的词语，会在文本中以这种方式出现："提供详细信息并单击生成项目"。

警告或重要说明会出现在这样的框中。

提示和技巧会以这种方式出现。


# 第一章：Spring Framework 5.0 的演变

Spring Framework 1.0 的第一个版本于 2004 年 3 月发布。在十五年多的时间里，Spring Framework 一直是构建 Java 应用程序的首选框架。

在 Java 框架相对年轻和动态的世界中，十年是很长的时间。

在本章中，我们将从理解 Spring Framework 的核心特性开始。我们将看看 Spring Framework 为什么变得受欢迎以及它如何适应以保持首选框架。在快速了解 Spring Framework 中的重要模块之后，我们将进入 Spring 项目的世界。我们将通过查看 Spring Framework 5.0 中的新功能来结束本章。

本章将回答以下问题：

+   Spring Framework 为什么受欢迎？

+   Spring Framework 如何适应应用程序架构的演变？

+   Spring Framework 中的重要模块是什么？

+   Spring Framework 在 Spring 项目的伞下适用于哪些方面？

+   Spring Framework 5.0 中的新功能是什么？

# Spring Framework

Spring 网站（[`projects.spring.io/spring-framework/`](https://projects.spring.io/spring-framework/)）对 Spring Framework 的定义如下：*Spring Framework 为现代基于 Java 的企业应用程序提供了全面的编程和配置模型*。

Spring Framework 用于连接企业 Java 应用程序。Spring Framework 的主要目标是处理连接应用程序不同部分所需的所有技术细节。这使程序员可以专注于他们的工作核心--编写业务逻辑。

# EJB 的问题

Spring Framework 于 2004 年 3 月发布。在 Spring Framework 的第一个版本发布时，开发企业应用程序的流行方式是使用 EJB 2.1。

开发和部署 EJB 是一个繁琐的过程。虽然 EJB 使组件的分发变得更容易，但开发、单元测试和部署它们并不容易。EJB 的初始版本（1.0、2.0、2.1）具有复杂的应用程序接口（API），导致人们（在大多数应用程序中是真的）认为引入的复杂性远远超过了好处：

+   难以进行单元测试。实际上，在 EJB 容器之外进行测试也很困难。

+   需要实现多个接口，具有许多不必要的方法。

+   繁琐和乏味的异常处理。

+   不方便的部署描述符。

Spring Framework 最初是作为一个旨在简化开发 Java EE 应用程序的轻量级框架而推出的。

# Spring Framework 为什么受欢迎？

Spring Framework 的第一个版本于 2004 年 3 月发布。在随后的十五年中，Spring Framework 的使用和受欢迎程度只增不减。

Spring Framework 受欢迎的重要原因如下：

+   简化单元测试--因为依赖注入

+   减少样板代码

+   架构灵活性

+   跟上时代的变化

让我们详细讨论每一个。

# 简化单元测试

早期版本的 EJB 非常难以进行单元测试。事实上，很难在容器之外运行 EJB（截至 2.1 版本）。测试它们的唯一方法是将它们部署在容器中。

Spring Framework 引入了“依赖注入”的概念。我们将在第二章“依赖注入”中详细讨论依赖注入。

依赖注入使得单元测试变得容易，可以通过将依赖项替换为它们的模拟来进行单元测试。我们不需要部署整个应用程序来进行单元测试。

简化单元测试有多重好处：

+   程序员更加高效

+   缺陷可以更早地发现，因此修复成本更低

+   应用程序具有自动化的单元测试，可以在持续集成构建中运行，以防止未来的缺陷

# 减少样板代码

在 Spring Framework 之前，典型的 J2EE（或现在称为 Java EE）应用程序包含大量的管道代码。例如：获取数据库连接、异常处理代码、事务管理代码、日志记录代码等等。

让我们看一个使用预编译语句执行查询的简单例子：

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

在前面的例子中，有四行业务逻辑和超过 10 行管道代码。

使用 Spring Framework，相同的逻辑可以应用在几行代码中：

```java
    jdbcTemplate.update(INSERT_TODO_QUERY, 
    bean.getDescription(), bean.isDone());
```

# Spring Framework 是如何做到这一点的？

在前面的例子中，Spring JDBC（以及 Spring 总体）将大多数已检查异常转换为未检查异常。通常，当查询失败时，我们无法做太多事情 - 除了关闭语句并使事务失败。我们可以在每个方法中实现异常处理，也可以使用 Spring **面向方面的编程**（**AOP**）进行集中式异常处理并将其注入。

Spring JDBC 消除了创建所有涉及获取连接、创建预编译语句等管道代码的需要。`jdbcTemplate`类可以在 Spring 上下文中创建，并在需要时注入到**数据访问对象**（**DAO**）类中。

与前面的例子类似，Spring JMS、Spring AOP 和其他 Spring 模块有助于减少大量的管道代码。

Spring Framework 让程序员专注于程序员的主要工作 - 编写业务逻辑。

避免所有管道代码还有另一个很大的好处 - 减少代码重复。由于所有事务管理、异常处理等代码（通常是所有横切关注点）都在一个地方实现，因此更容易维护。

# 架构灵活性

Spring Framework 是模块化的。它是建立在核心 Spring 模块之上的一组独立模块。大多数 Spring 模块都是独立的 - 您可以使用其中一个而无需使用其他模块。

让我们看几个例子：

+   在 Web 层，Spring 提供了自己的框架 - Spring MVC。但是，Spring 对 Struts、Vaadin、JSF 或您选择的任何 Web 框架都有很好的支持。

+   Spring Beans 可以为您的业务逻辑提供轻量级实现。但是，Spring 也可以与 EJB 集成。

+   在数据层，Spring 通过其 Spring JDBC 模块简化了 JDBC。但是，Spring 对您喜欢的任何首选数据层框架（JPA、Hibernate（带或不带 JPA）或 iBatis）都有很好的支持。

+   您可以选择使用 Spring AOP 来实现横切关注点（日志记录、事务管理、安全等），或者可以集成一个完整的 AOP 实现，比如 AspectJ。

Spring Framework 不希望成为万能工具。在专注于减少应用程序不同部分之间的耦合并使它们可测试的核心工作的同时，Spring 与您选择的框架集成得很好。这意味着您在架构上有灵活性 - 如果您不想使用特定框架，可以轻松地用另一个替换它。

# 跟上时代的变化

Spring Framework 的第一个版本专注于使应用程序可测试。然而，随着时间的推移，出现了新的挑战。Spring Framework 设法演变并保持领先地位，提供了灵活性和模块。以下列举了一些例子：

+   注解是在 Java 5 中引入的。Spring Framework（2.5 版 - 2007 年 11 月）在引入基于注解的 Spring MVC 控制器模型方面领先于 Java EE。使用 Java EE 的开发人员必须等到 Java EE 6（2009 年 12 月 - 2 年后）才能获得类似的功能。

+   Spring 框架在 Java EE 之前引入了许多抽象概念，以使应用程序与特定实现解耦。缓存 API 就是一个例子。Spring 在 Spring 3.1 中提供了透明的缓存支持。Java EE 在 2014 年提出了*JSR-107*用于 JCache——Spring 4.1 提供了对其的支持。

Spring 带来的另一个重要的东西是 Spring 项目的总称。Spring 框架只是 Spring 项目下的众多项目之一。我们将在单独的部分讨论不同的 Spring 项目。以下示例说明了 Spring 如何通过新的 Spring 项目保持领先地位：

+   **Spring Batch**定义了构建 Java 批处理应用程序的新方法。直到 Java EE 7（2013 年 6 月）我们才有了 Java EE 中可比较的批处理应用程序规范。

+   随着架构向云和微服务发展，Spring 推出了新的面向云的 Spring 项目。Spring Cloud 有助于简化微服务的开发和部署。Spring Cloud Data Flow 提供了对微服务应用程序的编排。

# Spring 模块

Spring 框架的模块化是其广泛使用的最重要原因之一。Spring 框架非常模块化，有 20 多个不同的模块，具有明确定义的边界。

下图显示了不同的 Spring 模块——按照它们通常在应用程序中使用的层进行组织：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/36fbd771-549b-4734-8d96-e306af3b5a43.png)

我们将从讨论 Spring 核心容器开始，然后再讨论其他按照它们通常在应用程序层中使用的模块分组的模块。

# Spring 核心容器

Spring 核心容器提供了 Spring 框架的核心功能——依赖注入、**IoC**（控制反转）容器和应用程序上下文。我们将在第二章“依赖注入”中更多地了解 DI 和 IoC 容器。

重要的核心 Spring 模块列在下表中：

| **模块/构件** | **用途** |
| --- | --- |
| spring-core | 其他 Spring 模块使用的实用工具。 |
| spring-beans | 支持 Spring beans。与 spring-core 结合使用，提供了 Spring 框架的核心功能——依赖注入。包括 BeanFactory 的实现。 |
| spring-context | 实现了 ApplicationContext，它扩展了 BeanFactory 并提供了加载资源和国际化等支持。 |
| spring-expression | 扩展了**EL**（来自 JSP 的表达式语言）并提供了一种用于访问和操作 bean 属性（包括数组和集合）的语言。 |

# 横切关注点

横切关注点适用于所有应用程序层——包括日志记录和安全性等。**AOP**通常用于实现横切关注点。

单元测试和集成测试属于这一类，因为它们适用于所有层。

与横切关注点相关的重要 Spring 模块如下所示：

| **模块/构件** | **用途** |
| --- | --- |
| spring-aop | 提供面向切面编程的基本支持——包括方法拦截器和切入点。 |
| spring-aspects | 提供与最流行和功能齐全的 AOP 框架 AspectJ 的集成。 |
| spring-instrument | 提供基本的仪器支持。 |
| spring-test | 提供对单元测试和集成测试的基本支持。 |

# Web

Spring 提供了自己的 MVC 框架，Spring MVC，除了与流行的 Web 框架（如 Struts）进行良好的集成。

重要的构件/模块如下所示：

+   **spring-web**：提供基本的 Web 功能，如多部分文件上传。提供与其他 Web 框架（如 Struts）的集成支持。

+   **spring-webmvc**：提供了一个功能齐全的 Web MVC 框架——Spring MVC，其中包括实现 REST 服务的功能。

我们将在第三章*使用 Spring MVC 构建 Web 应用程序*和第五章*使用 Spring Boot 构建微服务*中详细介绍 Spring MVC 并开发 Web 应用程序和 REST 服务。

# 业务

业务层专注于执行应用程序的业务逻辑。在 Spring 中，业务逻辑通常是在**普通的旧 Java 对象**（**POJO**）中实现的。

**Spring 事务**（**spring-tx**）为 POJO 和其他类提供声明式事务管理。

# 数据

应用程序中的数据层通常与数据库和/或外部接口进行通信。

以下表格列出了与数据层相关的一些重要的 Spring 模块：

| **模块/组件** | **用途** |
| --- | --- |
| spring-jdbc | 提供对 JDBC 的抽象，避免样板代码。 |
| spring-orm | 与 ORM 框架和规范集成--包括 JPA 和 Hibernate 等。 |
| spring-oxm | 提供对象到 XML 映射集成。支持 JAXB、Castor 等框架。 |
| spring-jms | 提供对 JMS 的抽象，避免样板代码。 |

# Spring 项目

虽然 Spring 框架为企业应用程序的核心功能（DI、Web、数据）提供了基础，但其他 Spring 项目探索了企业领域中的集成和解决方案--部署、云、大数据、批处理和安全等。

以下列出了一些重要的 Spring 项目：

+   Spring Boot

+   Spring Cloud

+   Spring Data

+   Spring Batch

+   Spring 安全

+   Spring HATEOAS

# Spring Boot

在开发微服务和 Web 应用程序时遇到的一些挑战如下：

+   制定框架选择和决定兼容的框架版本

+   提供外部化配置的机制--可以从一个环境更改为另一个环境的属性

+   健康检查和监控--如果应用程序的特定部分宕机，则提供警报

+   决定部署环境并为其配置应用程序

Spring Boot 通过采取*主观的观点*来解决所有这些问题。

我们将在两章中深入研究 Spring Boot--第五章*使用 Spring Boot 构建微服务*和第七章*高级 Spring Boot 功能*。

# Spring Cloud

可以毫不夸张地说*世界正在向云端迁移*。

云原生微服务和应用程序是当今的趋势。我们将在第四章*向微服务和云原生应用的演进*中详细讨论这一点。

Spring 正在迅速迈向使应用程序在云中开发变得更简单的方向，Spring Cloud 正在朝着这个方向迈进。

Spring Cloud 为分布式系统中的常见模式提供解决方案。Spring Cloud 使开发人员能够快速创建实现常见模式的应用程序。Spring Cloud 中实现的一些常见模式如下所示：

+   配置管理

+   服务发现

+   断路器

+   智能路由

我们将在第九章中更详细地讨论 Spring Cloud 及其各种功能，*Spring Cloud*。

# Spring Data

当今世界存在多个数据源--SQL（关系型）和各种 NOSQL 数据库。Spring Data 试图为所有这些不同类型的数据库提供一致的数据访问方法。

Spring Data 提供与各种规范和/或数据存储的集成：

+   JPA

+   MongoDB

+   Redis

+   Solr

+   宝石缓存

+   Apache Cassandra

以下列出了一些重要的特性：

+   通过从方法名称确定查询，提供关于存储库和对象映射的抽象

+   简单的 Spring 集成

+   与 Spring MVC 控制器的集成

+   高级自动审计功能--创建者、创建日期、最后更改者和最后更改日期

我们将在第八章中更详细地讨论 Spring Data，*Spring Data*。

# Spring Batch

今天的企业应用程序使用批处理程序处理大量数据。这些应用程序的需求非常相似。Spring Batch 提供了解决高性能要求的高容量批处理程序的解决方案。

Spring Batch 中的重要功能如下：

+   启动、停止和重新启动作业的能力--包括从失败点重新启动失败的作业的能力

+   处理数据块的能力

+   重试步骤或在失败时跳过步骤的能力

+   基于 Web 的管理界面

# Spring Security

**认证**是识别用户的过程。**授权**是确保用户有权访问资源执行已识别操作的过程。

认证和授权是企业应用程序的关键部分，包括 Web 应用程序和 Web 服务。Spring Security 为基于 Java 的应用程序提供声明性认证和授权。

Spring Security 中的重要功能如下：

+   简化的认证和授权

+   与 Spring MVC 和 Servlet API 的良好集成

+   防止常见安全攻击的支持--**跨站请求伪造**（**CSRF**）和会话固定

+   可用于与 SAML 和 LDAP 集成的模块

我们将在第三章中讨论如何使用 Spring Security 保护 Web 应用程序，*使用 Spring MVC 构建 Web 应用程序*。

我们将在第六章中讨论如何使用 Spring Security 保护基本的和 OAuth 身份验证机制的 REST 服务，*扩展微服务*。

# Spring HATEOAS

**HATEOAS**代表**超媒体作为应用程序状态的引擎**。尽管听起来复杂，但它是一个非常简单的概念。它的主要目的是解耦服务器（服务提供者）和客户端（服务消费者）。

服务提供者向服务消费者提供有关资源上可以执行的其他操作的信息。

Spring HATEOAS 提供了 HATEOAS 实现--特别是针对使用 Spring MVC 实现的 REST 服务。

Spring HATEOAS 中的重要功能如下：

+   简化了指向服务方法的链接的定义，使链接更加稳固

+   支持 JAXB（基于 XML）和 JSON 集成

+   支持服务消费者（客户端）

我们将在第六章中讨论如何在*扩展微服务*中使用 HATEOAS。

# Spring Framework 5.0 中的新功能

Spring Framework 5.0 是 Spring Framework 的首次重大升级，距离 Spring Framework 4.0 差不多四年。在这段时间内，Spring Boot 项目的主要发展之一就是演变。我们将在下一节讨论 Spring Boot 2.0 的新功能。

Spring Framework 5.0 最大的特点之一是**响应式编程**。Spring Framework 5.0 提供了核心响应式编程功能和对响应式端点的支持。重要变化的列表包括以下内容：

+   基线升级

+   JDK 9 运行时兼容性

+   在 Spring Framework 代码中使用 JDK 8 功能的能力

+   响应式编程支持

+   功能性 Web 框架

+   Jigsaw 的 Java 模块化

+   Kotlin 支持

+   删除的功能

# 基线升级

Spring Framework 5.0 具有 JDK 8 和 Java EE 7 基线。基本上，这意味着不再支持以前的 JDK 和 Java EE 版本。

Spring Framework 5.0 的重要基线 Java EE 7 规范如下：

+   Servlet 3.1

+   JMS 2.0

+   JPA 2.1

+   JAX-RS 2.0

+   Bean Validation 1.1

多个 Java 框架的最低支持版本发生了许多变化。以下列表包含一些知名框架的最低支持版本：

+   Hibernate 5

+   Jackson 2.6

+   EhCache 2.10

+   JUnit 5

+   Tiles 3

以下列表显示了支持的服务器版本：

+   Tomcat 8.5+

+   Jetty 9.4+

+   WildFly 10+

+   Netty 4.1+（用于 Spring Web Flux 的 Web 响应式编程）

+   Undertow 1.4+（用于使用 Spring Web Flux 进行 Web 响应式编程）

使用之前版本的任何规范/框架的应用程序在使用 Spring Framework 5.0 之前，至少需要升级到前面列出的版本。

# JDK 9 运行时兼容性

预计 JDK 9 将于 2017 年中期发布。Spring Framework 5.0 预计将与 JDK 9 具有运行时兼容性。

# 在 Spring Framework 代码中使用 JDK 8 特性

Spring Framework 4.x 的基线版本是 Java SE 6。这意味着它支持 Java 6、7 和 8。必须支持 Java SE 6 和 7 对 Spring Framework 代码施加了限制。框架代码无法使用 Java 8 的任何新特性。因此，虽然世界其他地方已经升级到 Java 8，Spring Framework 中的代码（至少是主要部分）仍受限于使用较早版本的 Java。

Spring Framework 5.0 的基线版本是 Java 8。Spring Framework 代码现在已升级以使用 Java 8 的新特性。这将导致更可读和更高性能的框架代码。使用的一些 Java 8 特性如下：

+   核心 Spring 接口中的 Java 8 默认方法

+   基于 Java 8 反射增强的内部代码改进

+   在框架代码中使用函数式编程--lambda 和流

# 响应式编程支持

响应式编程是 Spring Framework 5.0 最重要的特性之一。

微服务架构通常是围绕基于事件的通信构建的。应用程序被构建为对事件（或消息）做出反应。

响应式编程提供了一种专注于构建对事件做出反应的应用程序的替代编程风格。

虽然 Java 8 没有内置对响应式编程的支持，但有许多框架提供了对响应式编程的支持：

+   **响应式流**：语言中立的尝试定义响应式 API。

+   **Reactor**：由 Spring Pivotal 团队提供的 Reactive Streams 的 Java 实现。

+   **Spring WebFlux**：基于响应式编程开发 Web 应用程序的框架。提供类似于 Spring MVC 的编程模型。

我们将在《响应式编程》的第十一章中讨论响应式编程以及如何在 Spring Web Flux 中实现它。

# 功能性 Web 框架

在响应式特性的基础上，Spring 5 还提供了一个功能性 Web 框架。

功能性 Web 框架提供了使用函数式编程风格定义端点的功能。这里展示了一个简单的 hello world 示例：

```java
    RouterFunction<String> route =
    route(GET("/hello-world"),
    request -> Response.ok().body(fromObject("Hello World")));
```

功能性 Web 框架还可以用于定义更复杂的路由，如下例所示：

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

我们将在《响应式编程》的第十一章中更详细地讨论 Mono 和 Flux。

# 使用 Jigsaw 的 Java 模块化

直到 Java 8 之前，Java 平台并不是模块化的。由此产生了一些重要问题：

+   **平台膨胀**：在过去的几十年中，Java 模块化并不是一个令人担忧的问题。然而，随着**物联网**（**IOT**）和新的轻量级平台如 Node.js 的出现，迫切需要解决 Java 平台的膨胀问题。（JDK 的初始版本小于 10MB。最近的 JDK 版本需要超过 200MB。）

+   **JAR Hell**：另一个重要问题是 JAR Hell 的问题。当 Java ClassLoader 找到一个类时，它不会查看是否有其他可用于该类的定义。它会立即加载找到的第一个类。如果应用程序的两个不同部分需要来自不同 JAR 的相同类，它们无法指定必须从哪个 JAR 加载该类。

**开放系统网关倡议**（**OSGi**）是 1999 年开始的倡议之一，旨在将模块化引入 Java 应用程序。

每个模块（称为捆绑包）定义如下：

+   **imports**: 模块使用的其他捆绑包

+   **exports**: 此捆绑包导出的包

每个模块都可以有自己的生命周期。它可以独立安装、启动和停止。

Jigsaw 是**Java 社区进程**（**JCP**）下的一个倡议，从 Java 7 开始，旨在将模块化引入 Java。它有两个主要目标：

+   为 JDK 定义和实现模块化结构

+   为构建在 Java 平台上的应用程序定义模块系统

预计 Jigsaw 将成为 Java 9 的一部分，Spring Framework 5.0 预计将包括对 Jigsaw 模块的基本支持。

# Kotlin 支持

Kotlin 是一种静态类型的 JVM 语言，可以编写富有表现力、简短和可读的代码。Spring Framework 5.0 对 Kotlin 有很好的支持。

考虑一个简单的 Kotlin 程序，演示如下所示的数据类：

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

在不到 10 行的代码中，我们创建并测试了一个具有三个属性和以下功能的数据 bean：

+   `equals()`

+   `hashCode()`

+   `toString()`

+   `copy()`

Kotlin 是强类型的。但是不需要显式指定每个变量的类型：

```java
    val arrayList = arrayListOf("Item1", "Item2", "Item3") 
    // Type is ArrayList
```

命名参数允许您在调用方法时指定参数的名称，从而使代码更易读：

```java
    var todo = Todo(description = "Learn Spring Boot", 
    name = "Jack", targetDate = Date())
```

Kotlin 通过提供默认变量（`it`）和诸如`take`、`drop`等方法来简化函数式编程：

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

凭借其使代码简洁和表达力的所有功能，我们期望 Kotlin 成为要学习的语言。

我们将在第十三章“在 Spring 中使用 Kotlin”中更多地讨论 Kotlin。

# 已删除的功能

Spring Framework 5 是一个主要的 Spring 版本，基线版本大幅增加。随着 Java、Java EE 和其他一些框架的基线版本的增加，Spring Framework 5 取消了对一些框架的支持：

+   Portlet

+   Velocity

+   JasperReports

+   XMLBeans

+   JDO

+   Guava

如果您使用了上述任何框架，建议您计划迁移并继续使用直到 2019 年支持的 Spring Framework 4.3。

# Spring Boot 2.0 的新功能

Spring Boot 的第一个版本于 2014 年发布。以下是预计在 Spring Boot 2.0 中的一些重要更新：

+   基线 JDK 版本是 Java 8

+   Spring Framework 5.0 的基线版本是 Spring Framework 5.0

+   Spring Boot 2.0 支持使用 WebFlux 进行响应式 Web 编程

一些重要框架的最低支持版本如下所示：

+   Jetty 9.4

+   Tomcat 8.5

+   Hibernate 5.2

+   Gradle 3.4

我们将在第五章“使用 Spring Boot 构建微服务”和第七章“高级 Spring Boot 功能”中广泛讨论 Spring Boot。

# 摘要

在过去的十五年中，Spring Framework 显着改善了开发 Java 企业应用程序的体验。Spring Framework 5.0 带来了许多功能，同时显着增加了基线。

在随后的章节中，我们将介绍依赖注入，并了解如何使用 Spring MVC 开发 Web 应用程序。之后，我们将进入微服务的世界。在第五章“使用 Spring Boot 构建微服务”、第六章“扩展微服务”和第七章“高级 Spring Boot 功能”中，我们将介绍 Spring Boot 如何简化微服务的创建。然后，我们将把注意力转向使用 Spring Cloud 和 Spring Cloud Data Flow 在云中构建应用程序。


# 第二章：依赖注入

我们编写的任何 Java 类都依赖于其他类。类依赖的其他类是其依赖项。如果一个类直接创建依赖项的实例，它们之间建立了紧耦合。使用 Spring，创建和连接对象的责任被一个称为**IoC 容器**的新组件接管。类定义依赖关系，Spring 的**控制反转**（**IoC**）容器创建对象并将依赖项连接在一起。这个革命性的概念，即创建和连接依赖项的控制被容器接管，被称为 IoC 或**依赖注入**（**DI**）。

在本章中，我们首先探讨了 DI 的需求。我们使用一个简单的例子来说明 DI 的用法。我们将了解 DI 的重要优势--更容易维护，耦合度更低和改进的可测试性。我们将探索 Spring 中的 DI 选项。我们将结束本章，看一下 Java 的标准 DI 规范**上下文和依赖注入**（**CDI**）以及 Spring 如何支持它。

本章将回答以下问题：

+   什么是依赖注入？

+   依赖注入的正确使用如何使应用程序可测试？

+   Spring 如何使用注解实现 DI？

+   什么是组件扫描？

+   Java 和 XML 应用上下文之间有什么区别？

+   如何为 Spring 上下文创建单元测试？

+   模拟如何使单元测试更简单？

+   不同的 bean 作用域是什么？

+   什么是 CDI 以及 Spring 如何支持 CDI？

# 理解依赖注入

我们将看一个例子来理解依赖注入。我们将编写一个简单的业务服务，与一个数据服务交互。我们将使代码可测试，并看到正确使用 DI 如何使代码可测试。

以下是我们将遵循的步骤顺序：

1.  编写一个业务服务与数据服务交互的简单示例。当业务服务直接创建数据服务的实例时，它们之间是紧密耦合的。单元测试将会很困难。

1.  通过将创建数据服务的责任移出业务服务，使代码松耦合。

1.  引入 Spring IoC 容器来实例化 bean 并将它们连接在一起。

1.  探索 Spring 提供的 XML 和 Java 配置选项。

1.  探索 Spring 单元测试选项。

1.  使用模拟编写真正的单元测试。

# 理解依赖关系

我们将从编写一个简单的例子开始；一个业务服务与另一个数据服务交互。大多数 Java 类依赖于其他类。这些被称为该类的**依赖项**。

看一个示例类`BusinessServiceImpl`，如下所示：

```java
    public class BusinessServiceImpl { 
      public long calculateSum(User user) { 
        DataServiceImpl dataService = new DataServiceImpl(); 
        long sum = 0; 
        for (Data data : dataService.retrieveData(user)) { 
          sum += data.getValue(); 
        } 
        return sum; 
      }
    }
```

通常，所有设计良好的应用程序都有多个层。每个层都有明确定义的责任。业务层包含业务逻辑。数据层与外部接口和/或数据库交互以获取数据。在前面的例子中，`DataServiceImpl`类从数据库中获取与用户相关的一些数据。`BusinessServiceImpl`类是一个典型的业务服务，与数据服务`DataServiceImpl`交互获取数据，并在其上添加业务逻辑（在本例中，业务逻辑非常简单：计算数据服务返回的数据的总和）。

`BusinessServiceImpl`依赖于`DataServiceImpl`。因此，`DataServiceImpl`是`BusinessServiceImpl`的一个依赖项。

关注`BusinessServiceImpl`如何创建`DataServiceImpl`的实例。

```java
    DataServiceImpl dataService = new DataServiceImpl();
```

`BusinessServiceImpl`自己创建一个实例。这是紧耦合。

想一想单元测试；如何在不涉及（或实例化）`DataServiceImpl`类的情况下对`BusinessServiceImpl`类进行单元测试？这很困难。人们可能需要做复杂的事情，比如使用反射来编写单元测试。因此，前面的代码是不可测试的。

当您可以轻松地为代码编写简单的单元测试时，代码（方法、一组方法或类）就是可测试的。单元测试中使用的方法之一是模拟依赖关系。我们将稍后更详细地讨论模拟。

这是一个需要思考的问题：我们如何使前面的代码可测试？我们如何减少`BusinessServiceImpl`和`DataServiceImpl`之间的紧耦合？

我们可以做的第一件事是为`DataServiceImpl`创建一个接口。我们可以在`BusinessServiceImpl`中使用`DataServiceImpl`的新创建接口，而不是直接使用该类。

以下代码显示了如何创建一个接口：

```java
    public interface DataService { 
     List<Data> retrieveData(User user); 
    }
```

让我们更新`BusinessServiceImpl`中的代码以使用接口：

```java
    DataService dataService = new DataServiceImpl();
```

使用接口有助于创建松散耦合的代码。我们可以将任何接口实现替换为一个明确定义的依赖关系。

例如，考虑一个需要进行一些排序的业务服务。

第一个选项是直接在代码中使用排序算法，例如冒泡排序。第二个选项是为排序算法创建一个接口并使用该接口。具体的算法可以稍后连接。在第一个选项中，当我们需要更改算法时，我们需要更改代码。在第二个选项中，我们只需要更改连接。

我们现在使用`DataService`接口，但`BusinessServiceImpl`仍然紧密耦合，因为它创建了`DataServiceImpl`的实例。我们如何解决这个问题？

`BusinessServiceImpl`不自己创建`DataServiceImpl`的实例怎么样？我们可以在其他地方创建`DataServiceImpl`的实例（稍后我们将讨论谁将创建实例）并将其提供给`BusinessServiceImpl`吗？

为了实现这一点，我们将更新`BusinessServiceImpl`中的代码，为`DataService`添加一个 setter。`calculateSum`方法也更新为使用此引用。更新后的代码如下：

```java
    public class BusinessServiceImpl { 
      private DataService dataService; 
      public long calculateSum(User user) { 
        long sum = 0; 
        for (Data data : dataService.retrieveData(user)) { 
          sum += data.getValue(); 
         } 
        return sum; 
       } 
      public void setDataService(DataService dataService) { 
        this.dataService = dataService; 
       } 
    }
```

除了为数据服务创建一个 setter 之外，我们还可以创建一个接受数据服务作为参数的`BusinessServiceImpl`构造函数。这称为**构造函数注入**。

您可以看到`BusinessServiceImpl`现在可以与`DataService`的任何实现一起工作。它与特定实现`DataServiceImpl`没有紧密耦合。

为了使代码更加松散耦合（在开始编写测试时），让我们为`BusinessService`创建一个接口，并更新`BusinessServiceImpl`以实现该接口：

```java
    public interface BusinessService { 
      long calculateSum(User user); 
    } 
    public class BusinessServiceImpl implements BusinessService { 
      //.... Rest of code.. 
    }
```

现在我们已经减少了耦合，但仍然有一个问题；谁负责创建`DataServiceImpl`类的实例并将其连接到`BusinessServiceImpl`类？

这正是 Spring IoC 容器发挥作用的地方。

# Spring IoC 容器

Spring IoC 容器根据应用程序开发人员创建的配置设置创建 bean 并将它们连接在一起。

需要回答以下问题：

+   问题 1：Spring IoC 容器如何知道要创建哪些 bean？具体来说，Spring IoC 容器如何知道要为`BusinessServiceImpl`和`DataServiceImpl`类创建 bean？

+   问题 2：Spring IoC 容器如何知道如何将 bean 连接在一起？具体来说，Spring IoC 容器如何知道将`DataServiceImpl`类的实例注入`BusinessServiceImpl`类？

+   问题 3：Spring IoC 容器如何知道在哪里搜索 bean？在类路径中搜索所有包并不高效。

在我们专注于创建容器之前，让我们先专注于问题 1 和 2；如何定义需要创建哪些 bean 以及如何将它们连接在一起。

# 定义 bean 和装配

让我们先解决第一个问题；Spring IoC 容器如何知道要创建哪些 bean？

我们需要告诉 Spring IoC 容器要创建哪些 bean。这可以通过在需要创建 bean 的类上使用`@Repository`或`@Component`或`@Service`注解来完成。所有这些注解告诉 Spring 框架在定义这些注解的特定类中创建 bean。

`@Component`注解是定义 Spring bean 的最通用方式。其他注解具有更具体的上下文。`@Service`注解用于业务服务组件。`@Repository`注解用于**数据访问对象**（**DAO**）组件。

我们在`DataServiceImpl`上使用`@Repository`注解，因为它与从数据库获取数据有关。我们在`BusinessServiceImpl`类上使用`@Service`注解，因为它是一个业务服务：

```java
    @Repository 
    public class DataServiceImpl implements DataService 
    @Service 
    public class BusinessServiceImpl implements BusinessService
```

现在让我们把注意力转移到第二个问题上--Spring IoC 容器如何知道如何将 bean 装配在一起？`DataServiceImpl`类的 bean 需要注入到`BusinessServiceImpl`类的 bean 中。

我们可以通过在`BusinessServiceImpl`类中的`DataService`接口的实例变量上指定一个`@Autowired`注解来实现这一点：

```java
    public class BusinessServiceImpl { 
      @Autowired 
      private DataService dataService;
```

现在我们已经定义了 bean 和它们的装配，为了测试这一点，我们需要一个`DataService`的实现。我们将创建一个简单的、硬编码的实现。`DataServiceImpl`返回一些数据：

```java
    @Repository 
    public class DataServiceImpl implements DataService { 
      public List<Data> retrieveData(User user) { 
        return Arrays.asList(new Data(10), new Data(20)); 
      } 
    }
```

现在我们已经定义了我们的 bean 和依赖关系，让我们专注于如何创建和运行 Spring IoC 容器。

# 创建 Spring IoC 容器

创建 Spring IoC 容器有两种方式：

+   Bean 工厂

+   应用程序上下文

Bean 工厂是所有 Spring IoC 功能的基础--bean 的生命周期和装配。应用程序上下文基本上是 Bean 工厂的超集，具有在企业环境中通常需要的附加功能。Spring 建议在所有情况下使用应用程序上下文，除非应用程序上下文消耗的额外几 KB 内存是关键的。

让我们使用应用程序上下文来创建一个 Spring IoC 容器。我们可以使用 Java 配置或 XML 配置来创建应用程序上下文。让我们首先使用 Java 应用程序配置。

# 应用程序上下文的 Java 配置

以下示例显示了如何创建一个简单的 Java 上下文配置：

```java
    @Configuration 
    class SpringContext { 
    }
```

关键是`@Configuration`注解。这就是定义这个为 Spring 配置的地方。

还有一个问题；Spring IoC 容器如何知道在哪里搜索 bean？

我们需要告诉 Spring IoC 容器要搜索的包，通过定义一个组件扫描。让我们在之前的 Java 配置定义中添加一个组件扫描：

```java
    @Configuration 
    @ComponentScan(basePackages = { "com.mastering.spring" }) 
     class SpringContext { 
     }
```

我们已经为`com.mastering.spring`包定义了一个组件扫描。它展示了我们到目前为止讨论的所有类是如何组织的。到目前为止，我们定义的所有类都按如下方式存在于这个包中：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/68af0511-85af-4771-aa06-4611895098dc.png)

# 快速回顾

让我们花一点时间回顾一下我们到目前为止所做的一切，以使这个例子工作起来：

+   我们已经定义了一个 Spring 配置类`SpringContext`，带有`@Configuration`注解和一个对`com.mastering.spring`包的组件扫描

+   我们有一些文件（在前面的包中）：

+   `BusinessServiceImpl`带有`@Service`注解

+   `DataServiceImpl`带有`@Repository`注解

+   `BusinessServiceImpl`在`DataService`的实例上有`@Autowired`注解

当我们启动一个 Spring 上下文时，将会发生以下事情：

+   它将扫描`com.mastering.spring`包，并找到`BusinessServiceImpl`和`DataServiceImpl`的 bean。

+   `DataServiceImpl`没有任何依赖。因此，将创建`DataServiceImpl`的 bean。

+   `BusinessServiceImpl`依赖于`DataService`。`DataServiceImpl`是`DataService`接口的实现。因此，它符合自动装配的条件。因此，为`BusinessServiceImpl`创建了一个 bean，并且为`DataServiceImpl`创建的 bean 通过 setter 自动装配到它。

# 使用 Java 配置启动应用程序上下文

以下程序显示了如何启动 Java 上下文；我们使用主方法使用`AnnotationConfigApplicationContext`启动应用程序上下文：

```java
    public class LaunchJavaContext { 
      private static final User DUMMY_USER = new User("dummy"); 
      public static Logger logger =  
      Logger.getLogger(LaunchJavaContext.class); 
      public static void main(String[] args) { 
        ApplicationContext context = new 
        AnnotationConfigApplicationContext( 
        SpringContext.class); 
        BusinessService service = 
        context.getBean(BusinessService.class); 
        logger.debug(service.calculateSum(DUMMY_USER)); 
      } 
     }
```

以下代码行创建应用程序上下文。我们希望基于 Java 配置创建应用程序上下文。因此，我们使用`AnnotationConfigApplicationContext`：

```java
    ApplicationContext context = new 
    AnnotationConfigApplicationContext( 
      SpringContext.class);
```

一旦上下文启动，我们将需要获取业务服务 bean。我们使用`getBean`方法，传递 bean 的类型（`BusinessService.class`）作为参数：

```java
    BusinessService service = context.getBean(BusinessService.class );
```

我们已准备好通过运行`LaunchJavaContext`程序来启动应用程序上下文。

# 控制台日志

以下是使用`LaunchJavaContext`启动上下文后日志中的一些重要语句。让我们快速查看日志，以深入了解 Spring 正在做什么：

前几行显示了组件扫描的操作：

```java
Looking for matching resources in directory tree [/target/classes/com/mastering/spring]

Identified candidate component class: file [/in28Minutes/Workspaces/SpringTutorial/mastering-spring-example-1/target/classes/com/mastering/spring/business/BusinessServiceImpl.class]

Identified candidate component class: file [/in28Minutes/Workspaces/SpringTutorial/mastering-spring-example-1/target/classes/com/mastering/spring/data/DataServiceImpl.class]

defining beans [******OTHERS*****,businessServiceImpl,dataServiceImpl];
```

Spring 现在开始创建 bean。它从`businessServiceImpl`开始，但它有一个自动装配的依赖项：

```java
Creating instance of bean 'businessServiceImpl'Registered injected element on class [com.mastering.spring.business.BusinessServiceImpl]: AutowiredFieldElement for private com.mastering.spring.data.DataService com.mastering.spring.business.BusinessServiceImpl.dataService 

Processing injected element of bean 'businessServiceImpl': AutowiredFieldElement for private com.mastering.spring.data.DataService com.mastering.spring.business.BusinessServiceImpl.dataService
```

Spring 继续移动到`dataServiceImpl`并为其创建一个实例：

```java
Creating instance of bean 'dataServiceImpl'
Finished creating instance of bean 'dataServiceImpl'
```

Spring 将`dataServiceImpl`自动装配到`businessServiceImpl`：

```java
Autowiring by type from bean name 'businessServiceImpl' to bean named 'dataServiceImpl'
Finished creating instance of bean 'businessServiceImpl'
```

# 应用程序上下文的 XML 配置

在上一个示例中，我们使用了 Spring Java 配置来启动应用程序上下文。Spring 也支持 XML 配置。

以下示例显示了如何使用 XML 配置启动应用程序上下文。这将有两个步骤：

+   定义 XML Spring 配置

+   使用 XML 配置启动应用程序上下文

# 定义 XML Spring 配置

以下示例显示了典型的 XML Spring 配置。此配置文件在`src/main/resources`目录中创建，名称为`BusinessApplicationContext.xml`：

```java
    <?xml version="1.0" encoding="UTF-8" standalone="no"?> 
    <beans>  <!-Namespace definitions removed--> 
      <context:component-scan base-package ="com.mastering.spring"/> 
    </beans>
```

使用`context:component-scan`定义组件扫描。

# 使用 XML 配置启动应用程序上下文

以下程序显示了如何使用 XML 配置启动应用程序上下文。我们使用主方法使用`ClassPathXmlApplicationContext`启动应用程序上下文：

```java
    public class LaunchXmlContext { 
      private static final User DUMMY_USER = new User("dummy"); 
      public static Logger logger = 
      Logger.getLogger(LaunchJavaContext.class); 
      public static void main(String[] args) { 
         ApplicationContext context = new
         ClassPathXmlApplicationContext( 
         "BusinessApplicationContext.xml"); 
         BusinessService service =
         context.getBean(BusinessService.class); 
         logger.debug(service.calculateSum(DUMMY_USER)); 
        } 
     }
```

以下代码行创建应用程序上下文。我们希望基于 XML 配置创建应用程序上下文。因此，我们使用`ClassPathXmlApplicationContext`创建应用程序上下文：`AnnotationConfigApplicationContext`。

```java
    ApplicationContext context = new 
    ClassPathXmlApplicationContext (SpringContext.class);
```

一旦上下文启动，我们将需要获取对业务服务 bean 的引用。这与我们使用 Java 配置所做的非常相似。我们使用`getBean`方法，传递 bean 的类型（`BusinessService.class`）作为参数。

我们可以继续运行`LaunchXmlContext`类。您会注意到，我们得到的输出与使用 Java 配置运行上下文时非常相似。

# 使用 Spring 上下文编写 JUnit

在前面的部分中，我们看了如何从主方法启动 Spring 上下文。现在让我们将注意力转向从单元测试中启动 Spring 上下文。

我们可以使用`SpringJUnit4ClassRunner.class`作为运行器来启动 Spring 上下文：

```java
    @RunWith(SpringJUnit4ClassRunner.class)
```

我们需要提供上下文配置的位置。我们将使用之前创建的 XML 配置。以下是您可以声明的方式：

```java
    @ContextConfiguration(locations = {  
    "/BusinessApplicationContext.xml" })
```

我们可以使用`@Autowired`注解将上下文中的 bean 自动装配到测试中。BusinessService 是按类型自动装配的：

```java
    @Autowired 
    private BusinessService service;
```

目前，已经自动装配的`DataServiceImpl`返回`Arrays.asList(new Data(10)`，`new Data(20))`。`BusinessServiceImpl`计算和返回`10`+`20`的和`30`。我们将使用`assertEquals`在测试方法中断言`30`：

```java
    long sum = service.calculateSum(DUMMY_USER); 
    assertEquals(30, sum);
```

为什么我们在书中这么早介绍单元测试？

实际上，我们认为我们已经迟了。理想情况下，我们会喜欢使用**测试驱动开发**（**TDD**）并在编写代码之前编写测试。根据我的经验，进行 TDD 会导致简单、可维护和可测试的代码。

单元测试有许多优点：

+   对未来缺陷的安全网

+   早期发现缺陷

+   遵循 TDD 会导致更好的设计

+   良好编写的测试充当代码和功能的文档--特别是使用 BDD Given-When-Then 风格编写的测试

我们将编写的第一个测试实际上并不是一个单元测试。我们将在这个测试中加载所有的 bean。下一个使用模拟编写的测试将是一个真正的单元测试，其中被单元测试的功能是正在编写的特定代码单元。

测试的完整列表如下；它有一个测试方法：

```java
    @RunWith(SpringJUnit4ClassRunner.class) 
    @ContextConfiguration(locations = {
      "/BusinessApplicationContext.xml" }) 
       public class BusinessServiceJavaContextTest { 
       private static final User DUMMY_USER = new User("dummy"); 
       @Autowired 
       private BusinessService service; 

       @Test 
       public void testCalculateSum() { 
         long sum = service.calculateSum(DUMMY_USER); 
         assertEquals(30, sum); 
        } 
     }
```

我们编写的**JUnit**存在一个问题。它不是一个真正的单元测试。这个测试使用了`DataServiceImpl`的真实（几乎）实现进行 JUnit 测试。因此，我们实际上正在测试`BusinessServiceImpl`和`DataServiceImpl`的功能。这不是单元测试。

现在的问题是；如何在不使用`DataService`的真实实现的情况下对`BusinessServiceImpl`进行单元测试？

有两个选项：

+   创建数据服务的存根实现，在`src\test\java`文件夹中提供一些虚拟数据。使用单独的测试上下文配置来自动装配存根实现，而不是真正的`DataServiceImpl`类。

+   创建一个`DataService`的模拟并将其自动装配到`BusinessServiceImpl`中。

创建存根实现意味着创建一个额外的类和一个额外的上下文。存根变得更难维护，因为我们需要更多的数据变化来进行单元测试。

在下一节中，我们将探讨使用模拟进行单元测试的第二个选项。随着模拟框架（特别是 Mockito）在过去几年中的进步，您将看到我们甚至不需要启动 Spring 上下文来执行单元测试。

# 使用模拟进行单元测试

让我们从理解模拟开始。模拟是创建模拟真实对象行为的对象。在前面的例子中，在单元测试中，我们希望模拟`DataService`的行为。

与存根不同，模拟可以在运行时动态创建。我们将使用最流行的模拟框架 Mockito。要了解有关 Mockito 的更多信息，我们建议查看[`github.com/mockito/mockito/wiki/FAQ`](https://github.com/mockito/mockito/wiki/FAQ)上的 Mockito 常见问题解答。

我们将创建一个`DataService`的模拟。使用 Mockito 创建模拟有多种方法。让我们使用其中最简单的方法--注解。我们使用`@Mock`注解来创建`DataService`的模拟：

```java
    @Mock 
    private DataService dataService;
```

创建模拟后，我们需要将其注入到被测试的类`BusinessServiceImpl`中。我们使用`@InjectMocks`注解来实现：

```java
    @InjectMocks 
    private BusinessService service = 
    new BusinessServiceImpl();
```

在测试方法中，我们将需要存根模拟服务以提供我们想要提供的数据。有多种方法。我们将使用 Mockito 提供的 BDD 风格方法来模拟`retrieveData`方法：

```java
    BDDMockito.given(dataService.retrieveData(
      Matchers.any(User.class))) 
      .willReturn(Arrays.asList(new Data(10),  
      new Data(15), new Data(25)));
```

在前面的代码中我们定义的是所谓的存根。与 Mockito 的任何东西一样，这是非常易读的。当在`dataService`模拟上调用`retrieveData`方法并传入任何`User`类型的对象时，它将返回一个具有指定值的三个项目的列表。

当我们使用 Mockito 注解时，我们需要使用特定的 JUnit 运行器，即`MockitoJunitRunner`。`MockitoJunitRunner`有助于保持测试代码的清晰，并在测试失败时提供清晰的调试信息。`MockitoJunitRunner`在执行每个测试方法后初始化带有`@Mock`注解的 bean，并验证框架的使用。

```java
    @RunWith(MockitoJUnitRunner.class)
```

测试的完整列表如下。它有一个测试方法：

```java
    @RunWith(MockitoJUnitRunner.class) 
    public class BusinessServiceMockitoTest { 
      private static final User DUMMY_USER = new User("dummy");
       @Mock 
      private DataService dataService; 
      @InjectMocks 
      private BusinessService service =  
      new BusinessServiceImpl(); 
      @Test 
      public void testCalculateSum() { 
        BDDMockito.given(dataService.retrieveData( 
        Matchers.any(User.class))) 
        .willReturn( 
           Arrays.asList(new Data(10),  
           new Data(15), new Data(25))); 
           long sum = service.calculateSum(DUMMY_USER); 
           assertEquals(10 + 15 + 25, sum); 
       } 
     }
```

# 容器管理的 bean

与其类自己创建其依赖项，我们之前的示例中看到了 Spring IoC 容器如何接管管理 bean 及其依赖项的责任。由容器管理的 bean 称为**容器管理的 bean**。

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/871f784e-c0d0-49c9-a749-dfe125835f77.png)

将 bean 的创建和管理委托给容器有许多优点。其中一些列举如下：

+   由于类不负责创建依赖项，它们之间松耦合且易于测试。这导致了良好的设计和较少的缺陷。

+   由于容器管理 bean，可以以更通用的方式引入围绕 bean 的一些钩子。诸如日志记录、缓存、事务管理和异常处理等横切关注点可以使用**面向方面的编程**（**AOP**）围绕这些 bean 进行编织。这导致了更易于维护的代码。

# 依赖注入类型

在前面的示例中，我们使用了 setter 方法来注入依赖项。经常使用的两种依赖注入类型是：

+   setter 注入

+   构造函数注入

# setter 注入

setter 注入用于通过 setter 方法注入依赖项。在以下示例中，`DataService`的实例使用了 setter 注入：

```java
    public class BusinessServiceImpl { 
      private DataService dataService; 
      @Autowired 
      public void setDataService(DataService dataService) { 
        this.dataService = dataService; 
      } 
    }
```

实际上，为了使用 setter 注入，甚至不需要声明 setter 方法。如果在变量上指定了`@Autowired`，Spring 会自动使用 setter 注入。因此，以下代码就是您为`DataService`进行 setter 注入所需要的全部内容：

```java
    public class BusinessServiceImpl { 
      @Autowired 
      private DataService dataService; 
    }
```

# 构造函数注入

构造函数注入，另一方面，使用构造函数来注入依赖项。以下代码显示了如何在`DataService`中使用构造函数进行注入：

```java
    public class BusinessServiceImpl { 
      private DataService dataService; 
      @Autowired 
      public BusinessServiceImpl(DataService dataService) { 
        super(); 
        this.dataService = dataService; 
      } 
    }
```

当您运行具有前面`BusinessServiceImpl`实现的代码时，您将在日志中看到此语句，断言使用构造函数进行了自动装配：

```java
    Autowiring by type from bean name 'businessServiceImpl' via 
    constructor to bean named 'dataServiceImpl'
```

# 构造函数与 setter 注入

最初，在基于 XML 的应用程序上下文中，我们使用构造函数注入来处理强制依赖项，使用 setter 注入来处理非强制依赖项。

然而，需要注意的一点是，当我们在字段或方法上使用`@Autowired`时，默认情况下依赖项是必需的。如果没有可用于`@Autowired`字段的候选项，自动装配将失败并抛出异常。因此，在 Java 应用程序上下文中，选择并不那么明显。

使用 setter 注入会导致对象在创建过程中状态发生变化。对于不可变对象的粉丝来说，构造函数注入可能是更好的选择。有时使用 setter 注入可能会隐藏一个类具有大量依赖项的事实。使用构造函数注入会使这一点显而易见，因为构造函数的大小会增加。

# Spring bean 作用域

Spring bean 可以创建多种作用域。默认作用域是单例模式。

由于单例 bean 只有一个实例，因此不能包含特定于请求的任何数据。

可以在任何 Spring bean 上使用`@Scope`注解来提供作用域：

```java
    @Service 
    @Scope("singleton") 
    public class BusinessServiceImpl implements BusinessService
```

以下表格显示了可用于 bean 的不同作用域类型：

| **作用域** | **用途** |
| --- | --- |
| `Singleton` | 默认情况下，所有 bean 都是单例作用域。每个 Spring IoC 容器实例只使用一次这样的 bean 实例。即使有多个对 bean 的引用，它也只在容器中创建一次。单个实例被缓存并用于使用此 bean 的所有后续请求。重要的是要指出，Spring 单例作用域是一个 Spring 容器中的一个对象。如果在单个 JVM 中有多个 Spring 容器，则可以有多个相同 bean 的实例。因此，Spring 单例作用域与典型的单例定义有些不同。 |
| `Prototype` | 每次从 Spring 容器请求 bean 时都会创建一个新实例。如果 bean 包含状态，建议您为其使用原型范围。 |
| `request` | 仅在 Spring Web 上下文中可用。为每个 HTTP 请求创建一个 bean 的新实例。一旦请求处理完成，bean 就会被丢弃。适用于保存特定于单个请求的数据的 bean。 |
| `session` | 仅在 Spring Web 上下文中可用。为每个 HTTP 会话创建一个 bean 的新实例。适用于特定于单个用户的数据，例如 Web 应用程序中的用户权限。 |
| `application` | 仅在 Spring Web 上下文中可用。每个 Web 应用程序一个 bean 实例。适用于特定环境的应用程序配置等内容。 |

# Java 与 XML 配置

随着 Java 5 中注解的出现，基于 Java 的配置在基于 Spring 的应用程序中得到了广泛使用。如果必须在基于 Java 的配置和基于 XML 的配置之间进行选择，应该做出什么样的选择？

Spring 对基于 Java 和基于 XML 的配置提供了同样良好的支持。因此，选择权在于程序员及其团队。无论做出何种选择，都很重要的是在团队和项目之间保持一致。在做出选择时，可能需要考虑以下一些事项：

+   注解导致 bean 定义更短、更简单。

+   注解比基于 XML 的配置更接近其适用的代码。

+   使用注解的类不再是简单的 POJO，因为它们使用了特定于框架的注解。

+   使用注解时出现自动装配问题可能很难解决，因为连线不再是集中的，也没有明确声明。

+   如果它被打包在应用程序包装之外--WAR 或 EAR，使用 Spring 上下文 XML 可能会有更灵活的连线优势。这将使我们能够为集成测试设置不同的设置，例如。

# 深入了解@Autowired 注解

当在依赖项上使用`@Autowired`时，应用程序上下文会搜索匹配的依赖项。默认情况下，所有自动装配的依赖项都是必需的。

可能的结果如下：

+   **找到一个匹配项**：这就是你要找的依赖项

+   **找到多个匹配项**：自动装配失败

+   **找不到匹配项**：自动装配失败

可以通过两种方式解决找到多个候选项的情况：

+   使用`@Primary`注解标记其中一个候选项作为要使用的候选项

+   使用`@Qualifier`进一步限定自动装配

# @Primary 注解

当在 bean 上使用`@Primary`注解时，它将成为在自动装配特定依赖项时可用的多个候选项中的主要候选项。

在以下示例中，有两种排序算法可用：`QuickSort`和`MergeSort`。如果组件扫描找到它们两个，`QuickSort`将用于在`SortingAlgorithm`上连线任何依赖项，因为有`@Primary`注解：

```java
    interface SortingAlgorithm { 
    } 
    @Component 
    class MergeSort implements SortingAlgorithm { 
      // Class code here 
    } 
   @Component 
   @Primary 
   class QuickSort implements SortingAlgorithm { 
     // Class code here 
   }
```

# @Qualifier 注解

`@Qualifier`注解可用于给出对 Spring bean 的引用。该引用可用于限定需要自动装配的依赖项。

在以下示例中，有两种排序算法可用：`QuickSort`和`MergeSort`。但由于`SomeService`类中使用了`@Qualifier("mergesort")`，因此`MergeSort`成为了自动装配选定的候选依赖项，因为它也在其上定义了`mergesort`限定符。

```java
    @Component 
    @Qualifier("mergesort") 
    class MergeSort implements SortingAlgorithm { 
      // Class code here 
    } 
    @Component 
    class QuickSort implements SortingAlgorithm { 
     // Class code here 
    } 
    @Component 
    class SomeService { 
      @Autowired 
      @Qualifier("mergesort") 
      SortingAlgorithm algorithm; 
    }
```

# 其他重要的 Spring 注解

Spring 在定义 bean 和管理 bean 的生命周期方面提供了很大的灵活性。还有一些其他重要的 Spring 注解，我们将在下表中讨论。

| **注解** | **用途** |
| --- | --- |
| `@ScopedProxy` | 有时，我们需要将一个请求或会话作用域的 bean 注入到单例作用域的 bean 中。在这种情况下，`@ScopedProxy`注解提供了一个智能代理，可以注入到单例作用域的 bean 中。 |

`@Component`、`@Service`、`@Controller`、`@Repository` | `@Component`是定义 Spring bean 的最通用方式。其他注解与它们关联的上下文更具体。

+   `@Service` 用于业务服务层

+   `@Repository` 用于**数据访问对象**（**DAO**）

+   `@Controller` 用于表示组件

|

| `@PostConstruct` | 在任何 Spring bean 上，可以使用`@PostConstruct`注解提供一个 post construct 方法。这个方法在 bean 完全初始化了依赖项后被调用。这将在 bean 生命周期中只被调用一次。 |
| --- | --- |
| `@PreDestroy` | 在任何 Spring bean 上，可以使用`@PreDestroy`注解提供一个 predestroy 方法。这个方法在 bean 从容器中移除之前被调用。这可以用来释放 bean 持有的任何资源。 |

# 探索上下文和依赖注入

CDI 是 Java EE 将 DI 引入到 Java EE 的尝试。虽然不像 Spring 那样功能齐全，但 CDI 旨在标准化 DI 的基本方式。Spring 支持*JSR-330*中定义的标准注解。在大多数情况下，这些注解与 Spring 注解的处理方式相同。

在我们使用 CDI 之前，我们需要确保已经包含了 CDI jar 的依赖项。以下是代码片段：

```java
    <dependency> 
      <groupId>javax.inject</groupId> 
      <artifactId>javax.inject</artifactId> 
      <version>1</version> 
    </dependency>
```

在这个表中，让我们比较一下 CDI 注解和 Spring Framework 提供的注解。应该注意的是，`@Value`、`@Required`和`@Lazy` Spring 注解没有等价的 CDI 注解。

| **CDI 注解** | **与 Spring 注解的比较** |
| --- | --- |
| `@Inject` | 类似于`@Autowired`。一个微不足道的区别是`@Inject`上没有 required 属性。 |
| `@Named` | `@Named`类似于`@Component`。用于标识命名组件。此外，`@Named`也可以用于类似于`@Qualifier` Spring 注解的 bean 限定。在一个依赖项的自动装配中有多个候选项可用时，这是很有用的。 |
| `@Singleton` | 类似于 Spring 注解`@Scope`("singleton")。 |
| `@Qualifier` | 与 Spring 中同名的注解类似--`@Qualifier` |

# CDI 的一个例子

当我们使用 CDI 时，不同类上的注解看起来是这样的。在如何创建和启动 Spring 应用上下文方面没有变化。

CDI 对`@Repository`、`@Controller`、`@Service`和`@Component`没有区别。我们使用`@Named`代替所有前面的注解。

在示例中，我们对`DataServiceImpl`和`BusinessServiceImpl`使用了`@Named`。我们使用`@Inject`将`dataService`注入到`BusinessServiceImpl`中（而不是使用`@Autowired`）：

```java
    @Named //Instead of @Repository 
    public class DataServiceImpl implements DataService 
    @Named //Instead of @Service 
    public class BusinessServiceImpl { 
       @Inject //Instead of @Autowired 
       private DataService dataService;
```

# 总结

依赖注入（或 IoC）是 Spring 的关键特性。它使代码松散耦合且可测试。理解 DI 是充分利用 Spring Framework 的关键。

在本章中，我们深入研究了 DI 和 Spring Framework 提供的选项。我们还看了编写可测试代码的示例，并编写了一些单元测试。

在下一章中，我们将把注意力转向 Spring MVC，这是最流行的 Java Web MVC 框架。我们将探讨 Spring MVC 如何使 Web 应用程序的开发更加简单。


# 第三章：使用 Spring MVC 构建 Web 应用程序

Spring MVC 是用于开发 Java Web 应用程序的最流行的 Web 框架。Spring MVC 的优势在于其清晰的、松散耦合的架构。通过对控制器、处理程序映射、视图解析器和**普通的 Java 对象**（**POJO**）命令 bean 的角色进行清晰定义，Spring MVC 利用了所有核心 Spring 功能--如依赖注入和自动装配--使得创建 Web 应用程序变得简单。它支持多种视图技术，也具有可扩展性。

虽然 Spring MVC 可以用于创建 REST 服务，但我们将在第五章中讨论*使用 Spring Boot 构建微服务*。

在本章中，我们将重点介绍 Spring MVC 的基础知识，并提供简单的示例。

在本章中，我们将涵盖以下主题：

+   Spring MVC 架构

+   DispatcherServlet、视图解析器、处理程序映射和控制器所扮演的角色

+   模型属性和会话属性

+   表单绑定和验证

+   与 Bootstrap 集成

+   Spring 安全的基础知识

+   为控制器编写简单的单元测试

# Java Web 应用程序架构

在过去的几十年里，我们开发 Java Web 应用程序的方式已经发生了变化。我们将讨论开发 Java Web 应用程序的不同架构方法，并看看 Spring MVC 适用于哪些方面：

+   模型 1 架构

+   模型 2 或 MVC 架构

+   带有前端控制器的模型 2

# 模型 1 架构

模型 1 架构是用于开发基于 Java 的 Web 应用程序的初始架构风格之一。一些重要的细节如下：

+   JSP 页面直接处理来自浏览器的请求

+   JSP 页面使用包含简单 Java bean 的模型

+   在这种架构风格的一些应用中，甚至 JSP 执行了对数据库的查询

+   JSP 还处理流程逻辑：下一个要显示的页面

以下图片代表典型的模型 1 架构：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/a74fb9ad-d01d-4d70-93fa-f980215c48f1.png)

这种方法存在许多缺点，导致快速搁置和其他架构的演变。以下是一些重要的缺点：

+   **几乎没有关注点分离**：JSP 负责检索数据，显示数据，决定下一个要显示的页面（流程），有时甚至包括业务逻辑

+   **复杂的 JSP**：因为 JSP 处理了很多逻辑，它们很庞大且难以维护

# 模型 2 架构

模型 2 架构出现是为了解决处理多个责任的复杂 JSP 所涉及的复杂性。这构成了 MVC 架构风格的基础。以下图片代表典型的模型 2 架构：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/cfce1c1a-1aa9-400d-b641-4bc8a2f4c0a0.png)

模型 2 架构在模型、视图和控制器之间有明确的角色分离。这导致了更易维护的应用程序。一些重要的细节如下：

+   **模型**：表示用于生成视图的数据。

+   **视图**：使用模型来呈现屏幕。

+   **控制器**：控制流程。从浏览器获取请求，填充模型并重定向到视图。示例是前面图中的**Servlet1**和**Servlet2**。

# 模型 2 前端控制器架构

在模型 2 架构的基本版本中，浏览器的请求直接由不同的 servlet（或控制器）处理。在许多业务场景中，我们希望在处理请求之前在 servlet 中执行一些常见的操作。例如，确保已登录的用户有权执行请求。这是一个常见的功能，您不希望在每个 servlet 中实现。

在模型 2**前端控制器**架构中，所有请求都流入一个称为前端控制器的单个控制器。

下面的图片代表典型的模型 2 前端控制器架构：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/8afb2351-2192-4dac-8589-b197a1ff401b.png)

以下是典型前端控制器的一些职责： 

+   它决定了哪个控制器执行请求

+   它决定了要渲染哪个视图

+   它提供了添加更多常见功能的规定

+   Spring MVC 使用带有 Front Controller 的 MVC 模式。前端控制器称为**DispatcherServlet**。我们稍后将讨论 DispatcherServlet。

# 基本流程

Spring MVC 使用了修改版的 Model 2 Front Controller 架构。在我们深入了解 Spring MVC 的工作原理之前，我们将专注于使用 Spring MVC 创建一些简单的 Web 流程。在本节中，我们将使用 Spring MVC 创建六种典型的 Web 应用程序流程。流程如下所示：

+   **流程 1**：没有视图的控制器；自己提供内容

+   **流程 2**：带有视图（JSP）的控制器

+   **流程 3**：带有视图并使用 ModelMap 的控制器

+   **流程 4**：带有视图并使用 ModelAndView 的控制器

+   **流程 5**：简单表单的控制器

+   **流程 6**：带有验证的简单表单的控制器

在每个流程结束时，我们将讨论如何对控制器进行单元测试。

# 基本设置

在我们开始第一个流程之前，我们需要设置应用程序以使用 Spring MVC。在下一节中，我们将开始了解如何在 Web 应用程序中设置 Spring MVC。

我们使用 Maven 来管理我们的依赖关系。设置一个简单的 Web 应用程序涉及以下步骤：

1.  添加 Spring MVC 的依赖。

1.  将 DispatcherServlet 添加到`web.xml`中。

1.  创建一个 Spring 应用上下文。

# 添加 Spring MVC 的依赖

让我们从在`pom.xml`中添加 Spring MVC 依赖开始。以下代码显示了要添加的依赖项。由于我们使用 Spring BOM，我们不需要指定 artifact 版本：

```java
    <dependency> 
      <groupId>org.springframework</groupId> 
      <artifactId>spring-webmvc</artifactId> 
    </dependency>
```

DispatcherServlet 是 Front Controller 模式的一种实现。Spring MVC 的任何请求都将由前端控制器 DispatcherServlet 处理。

# 将 DispatcherServlet 添加到 web.xml

为了实现这一点，我们需要将 DispatcherServlet 添加到`web.xml`中。让我们看看如何做到这一点：

```java
    <servlet> 
      <servlet-name>spring-mvc-dispatcher-servlet</servlet-name>    
      <servlet-class> 
        org.springframework.web.servlet.DispatcherServlet 
      </servlet-class> 
      <init-param> 
        <param-name>contextConfigLocation</param-name> 
        <param-value>/WEB-INF/user-web-context.xml</param-value> 
      </init-param> 
        <load-on-startup>1</load-on-startup> 
    </servlet> 
    <servlet-mapping> 
      <servlet-name>spring-mvc-dispatcher-servlet</servlet-name> 
      <url-pattern>/</url-pattern> 
    </servlet-mapping>
```

第一部分是定义一个 servlet。我们还定义了一个上下文配置位置，`/WEB-INF/user-web-context.xml`。我们将在下一步中定义一个 Spring 上下文。在第二部分中，我们正在定义一个 servlet 映射。我们正在将 URL `/`映射到 DispatcherServlet。因此，所有请求都将由 DispatcherServlet 处理。

# 创建 Spring 上下文

现在我们在`web.xml`中定义了 DispatcherServlet，我们可以继续创建我们的 Spring 上下文。最初，我们将创建一个非常简单的上下文，而不是真正定义任何具体内容：

```java
    <beans > <!-Schema Definition removed --> 
       <context:component-scan  
       base-package="com.mastering.spring.springmvc"  /> 
       <mvc:annotation-driven /> 
    </beans>
```

我们正在为`com.mastering.spring.springmvc`包定义一个组件扫描，以便在此包中创建和自动装配所有的 bean 和控制器。

使用`<mvc:annotation-driven/>`初始化了 Spring MVC 支持的许多功能，例如：

+   请求映射

+   异常处理

+   数据绑定和验证

+   当使用`@RequestBody`注解时，自动转换（例如 JSON）

这就是我们需要设置 Spring MVC 应用程序的所有设置。我们已经准备好开始第一个流程了。

# 流程 1 - 没有视图的简单控制器流程

让我们从一个简单的流程开始，通过在屏幕上显示一些简单的文本来输出 Spring MVC 控制器的内容。

# 创建一个 Spring MVC 控制器

让我们创建一个简单的 Spring MVC 控制器，如下所示：

```java
    @Controller 
    public class BasicController { 
      @RequestMapping(value = "/welcome") 
      @ResponseBody 
    public String welcome() { 
      return "Welcome to Spring MVC"; 
     } 
   }
```

这里需要注意的一些重要事项如下：

+   `@Controller`：这定义了一个 Spring MVC 控制器，可以包含请求映射--将 URL 映射到控制器方法。

+   `@RequestMapping(value = "/welcome")`：这定义了 URL `/welcome`到`welcome`方法的映射。当浏览器发送请求到`/welcome`时，Spring MVC 会执行`welcome`方法。

+   `@ResponseBody`：在这个特定的上下文中，`welcome`方法返回的文本被发送到浏览器作为响应内容。`@ResponseBody`做了很多魔术--特别是在 REST 服务的上下文中。我们将在第五章中讨论这个问题，*使用 Spring Boot 构建微服务*。

# 运行 Web 应用程序

我们使用 Maven 和 Tomcat 7 来运行这个 Web 应用程序。

Tomcat 7 服务器默认在 8080 端口启动。

我们可以通过调用`mvn tomcat7:run`命令来运行服务器。

当在浏览器上访问`http://localhost:8080/welcome`URL 时，屏幕上的显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/fa4a0b7a-e415-4331-a0e3-707430ee9550.png)

# 单元测试

单元测试是开发可维护应用程序的一个非常重要的部分。我们将使用 Spring MVC Mock 框架来对本章中编写的控制器进行单元测试。我们将添加 Spring 测试框架的依赖来使用 Spring MVC Mock 框架：

```java
    <dependency> 
      <groupId>org.springframework</groupId> 
      <artifactId>spring-test</artifactId> 
      <scope>test</scope> 
    </dependency>
```

我们将采取以下方法：

1.  设置要测试的控制器。

1.  编写测试方法。

# 设置要测试的控制器

我们要测试的控制器是`BasicController`。创建单元测试的约定是类名后缀为`Test`。我们将创建一个名为`BasicControllerTest`的测试类。

基本设置如下所示：

```java
    public class BasicControllerTest { 
      private MockMvc mockMvc; 
      @Before 
      public void setup() { 
        this.mockMvc = MockMvcBuilders.standaloneSetup( 
        new BasicController()) 
        .build(); 
      } 
     }
```

需要注意的一些重要事项如下：

+   `mockMvc`：这个变量可以在不同的测试中使用。因此，我们定义了`MockMvc`类的一个实例变量。

+   `@Before setup`：这个方法在每个测试之前运行，以初始化`MockMvc`。

+   `MockMvcBuilders.standaloneSetup(new BasicController()).build()`：这行代码构建了一个`MockMvc`实例。它初始化 DispatcherServlet 来为配置的控制器（在这个例子中是`BasicController`）提供请求服务。

# 编写测试方法

完整的`Test`方法如下所示：

```java
    @Test 
    public void basicTest() throws Exception { 
      this.mockMvc 
      .perform( 
      get("/welcome") 
      .accept(MediaType.parseMediaType 
      ("application/html;charset=UTF-8"))) 
      .andExpect(status().isOk()) 
      .andExpect( content().contentType 
      ("application/html;charset=UTF-8")) 
      .andExpect(content(). 
       string("Welcome to Spring MVC")); 
    }
```

需要注意的一些重要事项如下：

+   `MockMvc` `mockMvc.perform`：这个方法执行请求并返回一个 ResultActions 的实例，允许链式调用。在这个例子中，我们正在链接 andExpect 调用来检查期望。

+   `get("/welcome").accept(MediaType.parseMediaType("application/html;charset=UTF-8"))`：这创建了一个接受`application/html`媒体类型响应的 HTTP get 请求。

+   `andExpect`：这个方法用于检查期望。如果期望没有被满足，这个方法将使测试失败。

+   `status().isOk()`：这使用 ResultMatcher 来检查响应状态是否是成功请求的状态-200。

+   `content().contentType("application/html;charset=UTF-8"))`：这使用 ResultMatcher 来检查响应的内容类型是否与指定的内容类型相匹配。

+   `content().string("Welcome to Spring MVC")`：这使用 ResultMatcher 来检查响应内容是否包含指定的字符串。

# 流程 2 - 带有视图的简单控制器流程

在前面的流程中，要在浏览器上显示的文本是在控制器中硬编码的。这不是一个好的做法。在浏览器上显示的内容通常是从视图生成的。最常用的选项是 JSP。

在这个流程中，让我们从控制器重定向到一个视图。

# Spring MVC 控制器

与前面的例子类似，让我们创建一个简单的控制器。考虑一个控制器的例子：

```java
    @Controller 
    public class BasicViewController { 
      @RequestMapping(value = "/welcome-view") 
      public String welcome() { 
        return "welcome"; 
       } 
    }
```

需要注意的一些重要事项如下：

+   `@RequestMapping(value = "/welcome-view")`：我们正在映射一个 URL`/welcome-view`。

+   `public String welcome()`：这个方法上没有`@RequestBody`注解。所以，Spring MVC 尝试将返回的字符串`welcome`与一个视图匹配。

# 创建一个视图-JSP

让我们在`src/main/webapp/WEB-INF/views/welcome.jsp`文件夹中创建`welcome.jsp`，内容如下：

```java
    <html> 
      <head> 
        <title>Welcome</title> 
      </head> 
      <body> 
        <p>Welcome! This is coming from a view - a JSP</p> 
      </body> 
    </html>
```

这是一个简单的 HTML，包含头部、主体和主体中的一些文本。

Spring MVC 必须将从`welcome`方法返回的字符串映射到`/WEB-INF/views/welcome.jsp`的实际 JSP。这个魔术是如何发生的呢？

# 视图解析器

视图解析器将视图名称解析为实际的 JSP 页面。

此示例中的视图名称为`welcome`，我们希望它解析为`/WEB-INF/views/welcome.jsp`。

可以在 spring 上下文`/WEB-INF/user-web-context.xml`中配置视图解析器。以下是代码片段：

```java
    <bean class="org.springframework.web.
    servlet.view.InternalResourceViewResolver"> 
     <property name="prefix"> 
       <value>/WEB-INF/views/</value> 
     </property> 
     <property name="suffix"> 
       <value>.jsp</value> 
     </property> 
    </bean>
```

需要注意的几个重要点：

+   `org.springframework.web.servlet.view.InternalResourceViewResolver`：支持 JSP 的视图解析器。通常使用`JstlView`。它还支持使用`TilesView`的 tiles。

+   `<property name="prefix"> <value>/WEB-INF/views/</value> </property><property name="suffix"> <value>.jsp</value> </property>`：将前缀和后缀映射到视图解析器使用的值。视图解析器从控制器方法中获取字符串并解析为视图：`prefix` + viewname + `suffix`。因此，视图名称 welcome 解析为`/WEB-INF/views/welcome.jsp`。

以下是当 URL 被访问时屏幕上的截图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/5b609f94-2dc2-4d2f-9c2e-30483d38677e.png)

# 单元测试

MockMvc 框架的独立设置创建了 DispatcherServlet 所需的最低基础设施。如果提供了视图解析器，它可以执行视图解析。但是，它不会执行视图。因此，在独立设置的单元测试中，我们无法验证视图的内容。但是，我们可以检查是否传递了正确的视图。

在这个单元测试中，我们想要设置`BasicViewController`，执行一个对`/welcome-view`的 get 请求，并检查返回的视图名称是否为`welcome`。在以后的部分中，我们将讨论如何执行集成测试，包括视图的渲染。就这个测试而言，我们将限制我们的范围以验证视图名称。

# 设置要测试的控制器

这一步与之前的流程非常相似。我们想要测试`BasicViewController`。我们使用`BasicViewController`实例化 MockMvc。我们还配置了一个简单的视图解析器：

```java
    public class BasicViewControllerTest { 
      private MockMvc mockMvc; 
      @Before 
      public void setup() { 
        this.mockMvc = MockMvcBuilders.standaloneSetup 
        (new BasicViewController()) 
        .setViewResolvers(viewResolver()).build(); 
       } 
      private ViewResolver viewResolver() { 
        InternalResourceViewResolver viewResolver =  
        new InternalResourceViewResolver(); 
        viewResolver.setViewClass(JstlView.class); 
        viewResolver.setPrefix("/WEB-INF/jsp/"); 
        viewResolver.setSuffix(".jsp"); 
       return viewResolver; 
      } 
    }
```

# 编写测试方法

完整的测试方法如下所示：

```java
    @Test 
    public void testWelcomeView() throws Exception { 
      this.mockMvc 
      .perform(get("/welcome-view") 
      .accept(MediaType.parseMediaType( 
      "application/html;charset=UTF-8"))) 
      .andExpect(view().name("welcome")); 
    }
```

需要注意的几个重要事项如下：

+   `get("/welcome-model-view")`：执行对指定 URL 的 get 请求

+   `view().name("welcome")`：使用 Result Matcher 来检查返回的视图名称是否与指定的相同

# 流程 3 - 控制器重定向到具有模型的视图

通常，为了生成视图，我们需要向其传递一些数据。在 Spring MVC 中，可以使用模型将数据传递给视图。在这个流程中，我们将使用一个简单的属性设置模型，并在视图中使用该属性。

# Spring MVC 控制器

让我们创建一个简单的控制器。考虑以下示例控制器：

```java
    @Controller 
    public class BasicModelMapController { 
      @RequestMapping(value = "/welcome-model-map") 
      public String welcome(ModelMap model) { 
        model.put("name", "XYZ"); 
      return "welcome-model-map"; 
     } 
   }
```

需要注意的几个重要事项如下：

+   `@RequestMapping(value = "/welcome-model-map")`：映射的 URI 为`/welcome-model-map`。

+   `public String welcome(ModelMap model)`：添加的新参数是`ModelMap model`。Spring MVC 将实例化一个模型，并使其对此方法可用。放入模型中的属性将可以在视图中使用。

+   `model.put("name", "XYZ")`：向模型中添加一个名为`name`值为`XYZ`的属性。

# 创建一个视图

让我们使用在控制器中设置的模型属性`name`创建一个视图。让我们在`WEB-INF/views/welcome-model-map.jsp`路径下创建一个简单的 JSP：

```java
    Welcome ${name}! This is coming from a model-map - a JSP
```

需要注意的一件事是：

+   `${name}`：使用**表达式语言**（**EL**）语法来访问模型中的属性。

以下是当 URL 被访问时屏幕上的截图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/c46d8dab-18e6-4964-9122-95ecebdee805.png)

# 单元测试

在这个单元测试中，我们想要设置`BasicModelMapController`，执行一个对`/welcome-model-map`的 get 请求，并检查模型是否具有预期的属性，以及返回的视图名称是否符合预期。

# 设置要测试的控制器

这一步与上一个流程非常相似。我们使用`BasicModelMapController`实例化 Mock MVC：

```java
    this.mockMvc = MockMvcBuilders.standaloneSetup 
      (new BasicModelMapController()) 
      .setViewResolvers(viewResolver()).build();
```

# 编写测试方法

完整的测试方法如下所示：

```java
    @Test 
    public void basicTest() throws Exception { 
      this.mockMvc 
      .perform( 
      get("/welcome-model-map") 
      .accept(MediaType.parseMediaType 
      ("application/html;charset=UTF-8"))) 
      .andExpect(model().attribute("name", "XYZ")) 
      .andExpect(view().name("welcome-model-map")); 
    }
```

需要注意的几个重要事项：

+   `get("/welcome-model-map")`：执行对指定 URL 的`get`请求

+   `model().attribute("name", "XYZ")`：结果匹配器，用于检查模型是否包含指定属性**name**和指定值**XYZ**

+   `view().name("welcome-model-map")`：结果匹配器，用于检查返回的视图名称是否与指定的相同

# 流程 4 - 控制器重定向到带有 ModelAndView 的视图

在上一个流程中，我们返回了一个视图名称，并在模型中填充了要在视图中使用的属性。Spring MVC 提供了一种使用`ModelAndView`的替代方法。控制器方法可以返回一个带有视图名称和模型中适当属性的`ModelAndView`对象。在这个流程中，我们将探讨这种替代方法。

# Spring MVC 控制器

看一下下面的控制器：

```java
    @Controller 
    public class BasicModelViewController { 
     @RequestMapping(value = "/welcome-model-view") 
      public ModelAndView welcome(ModelMap model) { 
        model.put("name", "XYZ"); 
        return new ModelAndView("welcome-model-view", model); 
      } 
   }
```

需要注意的几个重要事项如下：

+   `@RequestMapping(value = "/welcome-model-view")`：映射的 URI 是`/welcome-model-view`。

+   `public ModelAndView welcome(ModelMap model)`：请注意，返回值不再是 String。它是`ModelAndView`。

+   `return new ModelAndView("welcome-model-view", model)`：使用适当的视图名称和模型创建`ModelAndView`对象。

# 创建一个视图

让我们使用在控制器中设置的模型属性`name`创建一个视图。在`/WEB-INF/views/welcome-model-view.jsp`路径下创建一个简单的 JSP：

```java
    Welcome ${name}! This is coming from a model-view - a JSP
```

当 URL 被访问时，屏幕上会显示如下截图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/9f4dccc1-4ac3-4fa6-9f46-c2bc20e0c77c.png)

# 单元测试

对于这个流程的单元测试与上一个流程类似。我们需要检查是否返回了预期的视图名称。

# 流程 5 - 控制器重定向到带有表单的视图

现在让我们把注意力转移到创建一个简单的表单，以从用户那里获取输入。

需要以下步骤：

+   创建一个简单的 POJO。我们想创建一个用户。我们将创建一个 POJO 用户。

+   创建一对控制器方法——一个用于显示表单，另一个用于捕获表单中输入的详细信息。

+   创建一个带有表单的简单视图。

# 创建一个命令或表单备份对象

POJO 代表普通的旧 Java 对象。通常用于表示遵循典型 JavaBean 约定的 bean。通常，它包含具有 getter 和 setter 的私有成员变量和一个无参数构造函数。

我们将创建一个简单的 POJO 作为命令对象。类的重要部分列在下面：

```java
    public class User { 
      private String guid; 
      private String name; 
      private String userId; 
      private String password; 
      private String password2; 
      //Constructor 
      //Getters and Setters   
      //toString 
    }
```

需要注意的几个重要事项如下：

+   这个类没有任何注释或与 Spring 相关的映射。任何 bean 都可以充当表单备份对象。

+   我们将在表单中捕获`name`、`用户 ID`和`密码`。我们有一个密码确认字段`password2`和唯一标识符字段 guid。

+   为简洁起见，构造函数、getter、setter 和 toString 方法未显示。

# 显示表单的控制器方法

让我们从创建一个带有记录器的简单控制器开始：

```java
    @Controller 
    public class UserController { 
      private Log logger = LogFactory.getLog 
      (UserController.class); 
     }
```

让我们在控制器中添加以下方法：

```java
    @RequestMapping(value = "/create-user",  
    method = RequestMethod.GET) 
    public String showCreateUserPage(ModelMap model) { 
      model.addAttribute("user", new User()); 
      return "user"; 
   }
```

需要注意的重要事项如下：

+   `@RequestMapping(value = "/create-user", method = RequestMethod.GET)`：我们正在映射一个`/create-user` URI。这是第一次使用 method 属性指定`Request`方法。此方法仅在 HTTP Get 请求时调用。HTTP `Get`请求通常用于显示表单。这不会被其他类型的 HTTP 请求调用，比如 Post。

+   `public String showCreateUserPage(ModelMap model)`：这是一个典型的控制方法。

+   `model.addAttribute("user", new User())`：这用于使用空表单备份对象设置模型。

# 创建带有表单的视图

Java Server Pages 是 Spring Framework 支持的视图技术之一。Spring Framework 通过提供标签库，使得使用 JSP 轻松创建视图变得容易。这包括各种表单元素、绑定、验证、设置主题和国际化消息的标签。在本例中，我们将使用 Spring MVC 标签库以及标准的 JSTL 标签库来创建我们的视图。

让我们从创建`/WEB-INF/views/user.jsp`文件开始。

首先，让我们添加要使用的标签库的引用：

```java
    <%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%> 
    <%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt"%> 
    <%@ taglib uri="http://www.springframework.org/tags/form"  
      prefix="form"%> 
    <%@ taglib uri="http://www.springframework.org/tags"
      prefix="spring"%>
```

前两个条目是 JSTL 核心和格式化标签库。我们将广泛使用 Spring 表单标签。我们提供一个`prefix`作为引用标签的快捷方式。

让我们先创建一个只有一个字段的表单：

```java
    <form:form method="post" modelAttribute="user"> 
     <fieldset> 
       <form:label path="name">Name</form:label> 
       <form:input path="name"  
       type="text" required="required" /> 
     </fieldset> 
   </form:form>
```

需要注意的重要事项如下：

+   `<form:form method="post" modelAttribute="user">`：这是 Spring 表单标签库中的`form`标签。指定了两个属性。表单中的数据使用 post 方法发送。第二个属性`modelAttribute`指定了模型中充当表单后备对象的属性。在模型中，我们添加了一个名为 user 的属性。我们使用该属性作为`modelAttribute`。

+   `<fieldset>`：这是 HTML 元素，用于对一组相关控件（标签、表单字段和验证消息）进行分组。

+   `<form:label path="name">Name</form:label>`：这是 Spring 表单标签，用于显示标签。path 属性指定了该标签应用于的字段名称（来自 bean）。

+   `<form:input path="name" type="text" required="required" />`：这是 Spring 表单标签，用于创建文本输入字段。`path`属性指定了该输入字段要映射到的 bean 中的字段名称。required 属性表示这是一个`required`字段。

当我们使用 Spring 表单标签时，表单后备对象（`modelAttribute="user"`）中的值会自动绑定到表单上，并且在提交表单时，表单中的值会自动绑定到表单后备对象上。

包括名称和用户 ID 字段在内的更完整的表单标签列表如下：

```java
    <form:form method="post" modelAttribute="user"> 
    <form:hidden path="guid" /> 
    <fieldset> 
      <form:label path="name">Name</form:label> 
      <form:input path="name"  
       type="text" required="required" /> 
    </fieldset> 
    <fieldset> 
      <form:label path="userId">User Id</form:label> 
      <form:input path="userId"  
       type="text" required="required" /> 
    </fieldset> 
    <!-password and password2 fields not shown for brewity--> 
    <input class="btn btn-success" type="submit" value="Submit" /> 
    </form:form>
```

# 控制器获取方法来处理表单提交

当用户提交表单时，浏览器会发送一个 HTTP **POST**请求。现在让我们创建一个方法来处理这个请求。为了保持简单，我们将记录表单对象的内容。该方法的完整列表如下：

```java
    @RequestMapping(value = "/create-user", method = 
    RequestMethod.POST) 
    public String addTodo(User user) { 
      logger.info("user details " + user); 
      return "redirect:list-users"; 
    }
```

一些重要的细节如下：

+   `@RequestMapping(value = "/create-user", method = RequestMethod.POST)`：由于我们要处理表单提交，我们使用`RequestMethod.POST`方法。

+   `public String addTodo(User user)`：我们使用表单后备对象作为参数。Spring MVC 将自动将表单中的值绑定到表单后备对象。

+   `logger.info("user details " + user)`：记录用户的详细信息。

+   返回`redirect:list-users`：通常，在提交表单后，我们会将数据库的详细信息保存并将用户重定向到不同的页面。在这里，我们将用户重定向到`/list-users`。当我们使用`redirect`时，Spring MVC 会发送一个带有状态`302`的 HTTP 响应；也就是说，`REDIRECT`到新的 URL。浏览器在处理`302`响应时，会将用户重定向到新的 URL。虽然`POST`/`REDIRECT`/`GET`模式并不是解决重复表单提交问题的完美方法，但它确实减少了发生的次数，特别是在视图渲染后发生的次数。

列出用户的代码非常简单，如下所示：

```java
    @RequestMapping(value = "/list-users",  
    method = RequestMethod.GET) 
    public String showAllUsers() { 
      return "list-users"; 
    }
```

# 单元测试

当我们在下一个流程中添加验证时，我们将讨论单元测试。

# 流程 6 - 在上一个流程中添加验证

在上一个流程中，我们添加了一个表单。但是，我们没有验证表单中的值。虽然我们可以编写 JavaScript 来验证表单内容，但在服务器上进行验证总是更安全的。在本流程中，让我们使用 Spring MVC 在服务器端对我们之前创建的表单添加验证。

Spring MVC 与 Bean Validation API 提供了很好的集成。 *JSR 303*和*JSR 349*分别定义了 Bean Validation API 的规范（版本 1.0 和 1.1），而 Hibernate Validator 是参考实现。

# Hibernate Validator 依赖

让我们从将 Hibernate Validator 添加到我们的项目`pom.xml`开始：

```java
    <dependency> 
      <groupId>org.hibernate</groupId> 
      <artifactId>hibernate-validator</artifactId> 
      <version>5.0.2.Final</version> 
    </dependency>
```

# Bean 上的简单验证

Bean Validation API 指定了可以在 bean 的属性上指定的一些验证。看一下以下列表：

```java
   @Size(min = 6, message = "Enter at least 6 characters") 
   private String name; 
   @Size(min = 6, message = "Enter at least 6 characters") 
   private String userId; 
   @Size(min = 8, message = "Enter at least 8 characters") 
   private String password; 
   @Size(min = 8, message = "Enter at least 8 characters") 
   private String password2;
```

需要注意的一件重要的事情如下：

+   `@Size(min = 6, message = "Enter at least 6 characters")`：指定字段至少应有六个字符。如果验证未通过，则使用消息属性中的文本作为验证错误消息。

使用 Bean Validation 可以执行的其他验证如下：

+   `@NotNull`：它不应为 null

+   `@Size(min =5, max = 50)`：最大 50 个字符，最小 5 个字符。

+   `@Past`：应该是过去的日期

+   `@Future`：应该是未来的日期

+   `@Pattern`：应该匹配提供的正则表达式

+   `@Max`：字段的最大值

+   `@Min`：字段的最小值

现在让我们专注于使控制器方法在提交时验证表单。完整的方法列表如下：

```java
    @RequestMapping(value = "/create-user-with-validation",  
    method = RequestMethod.POST) 
    public String addTodo(@Valid User user, BindingResult result) { 
      if (result.hasErrors()) { 
        return "user"; 
       } 
      logger.info("user details " + user); 
      return "redirect:list-users"; 
    }
```

以下是一些重要的事项：

+   `public String addTodo(@Valid User user, BindingResult result)`：当使用`@Valid`注释时，Spring MVC 验证 bean。验证的结果在`BindingResult`实例 result 中可用。

+   `if (result.hasErrors())`：检查是否有任何验证错误。

+   `return "user"`：如果有验证错误，我们将用户发送回用户页面。

我们需要增强`user.jsp`以在验证错误时显示验证消息。其中一个字段的完整列表如下所示。其他字段也必须类似地更新：

```java
    <fieldset> 
      <form:label path="name">Name</form:label> 
      <form:input path="name" type="text" required="required" /> 
      <form:errors path="name" cssClass="text-warning"/> 
    </fieldset>
```

`<form:errors path="name" cssClass="text-warning"/>`：这是 Spring 表单标签，用于显示与指定路径中的字段名称相关的错误。我们还可以分配用于显示验证错误的 CSS 类。

# 自定义验证

可以使用`@AssertTrue`注释实现更复杂的自定义验证。以下是添加到`User`类的示例方法列表：

```java
    @AssertTrue(message = "Password fields don't match") 
    private boolean isValid() { 
      return this.password.equals(this.password2); 
    }
```

`@AssertTrue(message = "Password fields don't match")`是在验证失败时要显示的消息。

可以在这些方法中实现具有多个字段的复杂验证逻辑。

# 单元测试

此部分的单元测试重点是检查验证错误。我们将为一个空表单编写一个测试，触发四个验证错误。

# 控制器设置

控制器设置非常简单：

```java
    this.mockMvc = MockMvcBuilders.standaloneSetup( 
    new UserValidationController()).build();
```

# 测试方法

完整的`Test`方法如下所示：

```java
    @Test 
    public void basicTest_WithAllValidationErrors() throws Exception { 
      this.mockMvc 
        .perform( 
           post("/create-user-with-validation") 
           .accept(MediaType.parseMediaType( 
           "application/html;charset=UTF-8"))) 
           .andExpect(status().isOk()) 
           .andExpect(model().errorCount(4)) 
           .andExpect(model().attributeHasFieldErrorCode 
           ("user", "name", "Size")); 
    }
```

这里需要注意的一些要点如下：

+   `post("/create-user-with-validation")`：创建到指定 URI 的 HTTP `POST`请求。由于我们没有传递任何请求参数，所有属性都为 null。这将触发验证错误。

+   `model().errorCount(4)`：检查模型上是否有四个验证错误。

+   `model().attributeHasFieldErrorCode("user", "name", "Size")`：检查`user`属性是否具有名为`Size`的验证错误的`name`字段。

# Spring MVC 概述

现在我们已经看了 Spring MVC 的一些基本流程，我们将把注意力转向理解这些流程是如何工作的。Spring MVC 是如何实现魔术的？

# 重要特性

在处理不同的流程时，我们看了 Spring MVC 框架的一些重要特性。这些包括以下内容：

+   具有明确定义的独立角色的松散耦合架构。

+   高度灵活的控制器方法定义。控制器方法可以具有各种参数和返回值。这使程序员可以灵活选择满足其需求的定义。

+   允许重用域对象作为表单后备对象。减少了需要单独的表单对象。

+   带有本地化支持的内置标签库（Spring，spring-form）。

+   Model 使用具有键值对的 HashMap。允许与多个视图技术集成。

+   灵活的绑定。绑定时的类型不匹配可以作为验证错误而不是运行时错误来处理。

+   模拟 MVC 框架以对控制器进行单元测试。

# 它是如何工作的

Spring MVC 架构中的关键组件如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/e7d21789-55e6-4613-802e-632509dc37b3.png)

让我们看一个示例流程，并了解执行流程涉及的不同步骤。我们将采取流程**4**，返回`ModelAndView`作为具体示例。流程**4**的 URL 是`http://localhost:8080/welcome-model-view`。不同的步骤详细说明如下：

1.  浏览器向特定 URL 发出请求。DispatcherServlet 是前端控制器，处理所有请求。因此，它接收请求。

1.  Dispatcher Servlet 查看 URI（在示例中为`/welcome-model-view`），并需要确定正确的控制器来处理它。为了帮助找到正确的控制器，它与处理程序映射进行通信。

1.  处理程序映射返回处理请求的特定处理程序方法（在示例中，`BasicModelViewController`中的`welcome`方法）。

1.  DispatcherServlet 调用特定的处理程序方法（`public ModelAndView welcome(ModelMap model)`）。

1.  处理程序方法返回模型和视图。在这个例子中，返回了 ModelAndView 对象。

1.  DispatcherServlet 具有逻辑视图名称（来自 ModelAndView；在这个例子中是`welcome-model-view`）。它需要找出如何确定物理视图名称。它检查是否有任何可用的视图解析器。它找到了配置的视图解析器（`org.springframework.web.servlet.view.InternalResourceViewResolver`）。它调用视图解析器，将逻辑视图名称（在这个例子中是`welcome-model-view`）作为输入。

1.  View 解析器执行逻辑以将逻辑视图名称映射到物理视图名称。在这个例子中，`welcome-model-view`被翻译为`/WEB-INF/views/welcome-model-view.jsp`。

1.  DispatcherServlet 执行 View。它还使 Model 可用于 View。

1.  View 将返回要发送回 DispatcherServlet 的内容。

1.  DispatcherServlet 将响应发送回浏览器。

# Spring MVC 背后的重要概念

现在我们已经完成了一个 Spring MVC 示例，我们准备理解 Spring MVC 背后的重要概念。

# RequestMapping

正如我们在之前的示例中讨论的，`RequestMapping`用于将 URI 映射到 Controller 或 Controller 方法。它可以在类和/或方法级别完成。可选的方法参数允许我们将方法映射到特定的请求方法（`GET`，`POST`等）。

# 请求映射的示例

即将出现的几个示例将说明各种变化。

# 示例 1

在以下示例中，`showPage`方法中只有一个`RequestMapping`。`showPage`方法将映射到`GET`，`POST`和 URI`/show-page`的任何其他请求类型：

```java
    @Controller 
    public class UserController { 
      @RequestMapping(value = "/show-page") 
      public String showPage() { 
        /* Some code */ 
       } 
    }
```

# 示例 2

在以下示例中，定义了一个`RequestMapping`--`RequestMethod.GET`的方法。`showPage`方法将仅映射到 URI`/show-page`的`GET`请求。所有其他请求方法类型都会抛出“方法不受支持异常”：

```java
    @Controller 
    public class UserController { 
      @RequestMapping(value = "/show-page" , method = 
      RequestMethod.GET) 
      public String showPage() { 
        /* Some code */ 
       } 
    }
```

# 示例 3

在以下示例中，有两个`RequestMapping`方法--一个在类中，另一个在方法中。使用两种`RequestMapping`方法的组合来确定 URI。`showPage`方法将仅映射到 URI`/user/show-page`的`GET`请求：

```java
    @Controller 
    @RequestMapping("/user") 
    public class UserController { 
      @RequestMapping(value = "/show-page" , method =   
       RequestMethod.GET) 
       public String showPage() { 
         /* Some code */ 
       } 
    }
```

# 请求映射方法-支持的方法参数

以下是在具有 RequestMapping 的 Controller 方法中支持的一些参数类型：

| **参数类型/注释** | **用途** |
| --- | --- |
| `java.util.Map` / `org.springframework.ui.Model` / `org.springframework.ui.ModelMap` | 作为模型（MVC），用于容纳暴露给视图的值。 |
| 命令或表单对象 | 用于将请求参数绑定到 bean。还支持验证。 |
| `org.springframework.validation.Errors` / `org.springframework.validation.BindingResult` | 验证命令或表单对象的结果（表单对象应该是前一个方法参数）。 |
| `@PreDestroy` | 在任何 Spring bean 上，可以使用`@PreDestroy`注解提供预销毁方法。该方法在 bean 从容器中移除之前调用。它可以用于释放 bean 持有的任何资源。 |
| `@RequestParam` | 访问特定 HTTP 请求参数的注解。 |
| `@RequestHeader` | 访问特定 HTTP 请求头的注解。 |
| `@SessionAttribute` | 访问 HTTP 会话中的属性的注解。 |
| `@RequestAttribute` | 访问特定 HTTP 请求属性的注解。 |
| `@PathVariable` | 允许从 URI 模板中访问变量的注解。`/owner/{ownerId}`。当我们讨论微服务时，我们将深入研究这个问题。 |

# RequestMapping 方法-支持的返回类型

`RequestMapping`方法支持各种返回类型。从概念上讲，请求映射方法应该回答两个问题：

+   视图是什么？

+   视图需要什么模型？

然而，使用 Spring MVC 时，视图和模型不一定需要始终明确声明：

+   如果视图没有明确定义为返回类型的一部分，则它是隐式定义的。

+   同样，任何模型对象始终按照以下规则进行丰富。

Spring MVC 使用简单的规则来确定确切的视图和模型。以下列出了一些重要的规则：

+   **模型的隐式丰富**：如果模型是返回类型的一部分，则它将与命令对象（包括命令对象验证的结果）一起丰富。此外，带有`@ModelAttribute`注解的方法的结果也会添加到模型中。

+   **视图的隐式确定**：如果返回类型中没有视图名称，则使用`DefaultRequestToViewNameTranslator`确定。默认情况下，`DefaultRequestToViewNameTranslator`会从 URI 中删除前导和尾随斜杠以及文件扩展名；例如，`display.html`变成了 display。

以下是在带有请求映射的控制器方法上支持的一些返回类型：

| **返回类型** | **发生了什么？** |
| --- | --- |
| ModelAndView | 该对象包括对模型和视图名称的引用。 |
| 模型 | 只返回模型。视图名称使用`DefaultRequestToViewNameTranslator`确定。 |
| Map | 一个简单的映射来暴露模型。 |
| 视图 | 隐式定义模型的视图。 |
| String | 视图名称的引用。 |

# 视图解析

Spring MVC 提供非常灵活的视图解析。它提供多个视图选项：

+   与 JSP、Freemarker 集成。

+   多种视图解析策略。以下列出了其中一些：

+   `XmlViewResolver`：基于外部 XML 配置的视图解析

+   `ResourceBundleViewResolver`：基于属性文件的视图解析

+   `UrlBasedViewResolver`：将逻辑视图名称直接映射到 URL

+   `ContentNegotiatingViewResolver`：根据接受请求头委托给其他视图解析器

+   支持显式定义首选顺序的视图解析器的链接。

+   使用内容协商直接生成 XML、JSON 和 Atom。

# 配置 JSP 视图解析器

以下示例显示了配置 JSP 视图解析器使用`InternalResourceViewResolver`的常用方法。使用`JstlView`，通过配置的前缀和后缀确定逻辑视图名称的物理视图名称：

```java
    <bean id="jspViewResolver" class=  
      "org.springframework.web.servlet.view.
      InternalResourceViewResolver"> 
      <property name="viewClass"  
        value="org.springframework.web.servlet.view.JstlView"/> 
      <property name="prefix" value="/WEB-INF/jsp/"/> 
      <property name="suffix" value=".jsp"/> 
    </bean>
```

还有其他使用属性和 XML 文件进行映射的方法。

# 配置 Freemarker

以下示例显示了配置 Freemarker 视图解析器的典型方法。

首先，`freemarkerConfig` bean 用于加载 Freemarker 模板：

```java
    <bean id="freemarkerConfig"
      class="org.springframework.web.servlet.view.
      freemarker.FreeMarkerConfigurer"> 
      <property name="templateLoaderPath" value="/WEB-
      INF/freemarker/"/> 
    </bean>
```

以下是如何配置 Freemarker 视图解析器的 bean 定义：

```java
    <bean id="freemarkerViewResolver"  
     class="org.springframework.web.servlet.view.
     freemarker.FreeMarkerViewResolver"> 
       <property name="cache" value="true"/> 
       <property name="prefix" value=""/> 
       <property name="suffix" value=".ftl"/> 
    </bean>
```

与 JSP 一样，视图解析可以使用属性或 XML 文件来定义。

# 处理程序映射和拦截器

在 Spring 2.5 之前的版本（在支持注解之前），URL 和控制器（也称为处理程序）之间的映射是使用称为处理程序映射的东西来表达的。今天几乎是一个历史事实。注解的使用消除了对显式处理程序映射的需求。

HandlerInterceptors 可用于拦截对处理程序（或**控制器**）的请求。有时，您希望在请求之前和之后进行一些处理。您可能希望记录请求和响应的内容，或者您可能想找出特定请求花费了多少时间。

创建 HandlerInterceptor 有两个步骤：

1.  定义 HandlerInterceptor。

1.  将 HandlerInterceptor 映射到要拦截的特定处理程序。

# 定义 HandlerInterceptor

以下是您可以在`HandlerInterceptorAdapter`中重写的方法：

+   `public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)`: 在调用处理程序方法之前调用

+   `public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView)`: 在调用处理程序方法后调用

+   `public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex)`: 在请求处理完成后调用

以下示例实现显示了如何创建 HandlerInterceptor。让我们从创建一个扩展`HandlerInterceptorAdapter`的新类开始：

```java
    public class HandlerTimeLoggingInterceptor extends 
    HandlerInterceptorAdapter {
```

`preHandle`方法在调用处理程序之前被调用。让我们在请求上放置一个属性，指示处理程序调用的开始时间：

```java
    @Override 
    public boolean preHandle(HttpServletRequest request, 
      HttpServletResponse response, Object handler) throws Exception { 
      request.setAttribute( 
      "startTime", System.currentTimeMillis()); 
      return true; 
    }
```

`postHandle`方法在调用处理程序后被调用。让我们在请求上放置一个属性，指示处理程序调用的结束时间：

```java
    @Override 
    public void postHandle(HttpServletRequest request, 
    HttpServletResponse response, Object handler, 
    ModelAndView modelAndView) throws Exception { 
       request.setAttribute( 
       "endTime", System.currentTimeMillis()); 
     }
```

`afterCompletion`方法在请求处理完成后被调用。我们将使用我们之前设置到请求中的属性来识别处理程序中花费的时间：

```java
    @Override 
    public void afterCompletion(HttpServletRequest request, 
    HttpServletResponse response, Object handler, Exception ex) 
    throws Exception { 
      long startTime = (Long) request.getAttribute("startTime"); 
      long endTime = (Long) request.getAttribute("endTime"); 
      logger.info("Time Spent in Handler in ms : "  
      + (endTime - startTime)); 
    }
```

# 将 HandlerInterceptor 映射到处理程序

HandlerInterceptors 可以映射到您希望拦截的特定 URL。以下示例显示了一个示例 XML 上下文配置。默认情况下，拦截器将拦截所有处理程序（**控制器**）：

```java
    <mvc:interceptors> 
      <bean class="com.mastering.spring.springmvc.
      controller.interceptor.HandlerTimeLoggingInterceptor" /> 
    </mvc:interceptors>
```

我们可以配置精确的 URI 进行拦截。在下面的示例中，除了以`/secure/`开头的 URI 映射的处理程序之外，所有处理程序都会被拦截：

```java
    <mvc:interceptors> 
      <mapping path="/**"/> 
      <exclude-mapping path="/secure/**"/> 
      <bean class="com.mastering.spring.springmvc.
       controller.interceptor.HandlerTimeLoggingInterceptor" /> 
    </mvc:interceptors>
```

# 模型属性

常见的 Web 表单包含许多下拉值--州的列表，国家的列表等等。这些值列表需要在模型中可用，以便视图可以显示列表。这些常见的东西通常使用标有`@ModelAttribute`注解的方法填充到模型中。

有两种可能的变体。在下面的示例中，该方法返回需要放入模型中的对象：

```java
    @ModelAttribute 
    public List<State> populateStateList() { 
      return stateService.findStates(); 
     }
```

这个示例中的方法用于向模型添加多个属性：

```java
    @ModelAttribute 
    public void populateStateAndCountryList() { 
      model.addAttribute(stateService.findStates()); 
      model.addAttribute(countryService.findCountries()); 
     }
```

需要注意的重要事项是，可以标记为`@ModelAttribute`注解的方法数量没有限制。

使用 Controller Advice 可以使模型属性在多个控制器中变得通用。我们将在本节后面讨论 Controller Advice。

# 会话属性

到目前为止，我们讨论的所有属性和值都是在单个请求中使用的。但是，可能存在值（例如特定的 Web 用户配置）在请求之间不会发生变化。这些类型的值通常将存储在 HTTP 会话中。Spring MVC 提供了一个简单的类型级别（类级别）注释`@SessionAttributes`，用于指定要存储在会话中的属性。

看一下以下示例：

```java
    @Controller 
    @SessionAttributes("exampleSessionAttribute") 
    public class LoginController {
```

# 将属性放入会话中

一旦我们在`@SessionAttributes`注释中定义了一个属性，如果将相同的属性添加到模型中，它将自动添加到会话中。

在前面的示例中，如果我们将一个名为`exampleSessionAttribute`的属性放入模型中，它将自动存储到会话对话状态中：

```java
    model.put("exampleSessionAttribute", sessionValue);
```

# 从会话中读取属性

首先在类型级别指定`@SessionAttributes`注释，然后可以在其他控制器中访问此值：

```java
    @Controller 
    @SessionAttributes("exampleSessionAttribute") 
    public class SomeOtherController {
```

会话属性的值将直接提供给所有模型对象。因此，可以从模型中访问：

```java
   Value sessionValue =(Value)model.get("exampleSessionAttribute");
```

# 从会话中删除属性

当不再需要会话中的值时，将其从会话中删除非常重要。我们可以通过两种方式从会话对话状态中删除值。第一种方式在以下代码片段中进行了演示。它使用`WebRequest`类中可用的`removeAttribute`方法：

```java
    @RequestMapping(value="/some-method",method = RequestMethod.GET) 
    public String someMethod(/*Other Parameters*/  
    WebRequest request, SessionStatus status) { 
      status.setComplete(); 
      request.removeAttribute("exampleSessionAttribute",
      WebRequest.SCOPE_SESSION); 
       //Other Logic
    }
```

此示例显示了使用`SessionAttributeStore`中的`cleanUpAttribute`方法的第二种方法：

```java
    @RequestMapping(value = "/some-other-method",  
    method = RequestMethod.GET) 
    public String someOtherMethod(/*Other Parameters*/ 
    SessionAttributeStore store, SessionStatus status) { 
      status.setComplete(); 
      store.cleanupAttribute(request, "exampleSessionAttribute"); 
      //Other Logic 
    }
```

# InitBinders

典型的 Web 表单包含日期、货币和金额。表单中的值需要绑定到表单后端对象。可以使用`@InitBinder`注释引入绑定发生的自定义。

可以使用 Handler Advice 在特定控制器或一组控制器中进行自定义。此示例显示了如何设置用于表单绑定的默认日期格式：

```java
    @InitBinder 
    protected void initBinder(WebDataBinder binder) { 
      SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy"); 
      binder.registerCustomEditor(Date.class, new CustomDateEditor( 
      dateFormat, false)); 
    }
```

# @ControllerAdvice 注释

我们在控制器级别定义的一些功能可能在整个应用程序中是通用的。例如，我们可能希望在整个应用程序中使用相同的日期格式。因此，我们之前定义的`@InitBinder`可以适用于整个应用程序。我们如何实现？`@ControllerAdvice`可以帮助我们使功能在默认情况下在所有请求映射中通用。

例如，考虑此处列出的 Controller 建议示例。我们在类上使用`@ControllerAdvice`注释，并在此类中使用`@InitBinder`定义方法。默认情况下，此方法中定义的绑定适用于所有请求映射：

```java
    @ControllerAdvice 
    public class DateBindingControllerAdvice { 
      @InitBinder 
      protected void initBinder(WebDataBinder binder) { 
        SimpleDateFormat dateFormat = new  
        SimpleDateFormat("dd/MM/yyyy"); 
        binder.registerCustomEditor(Date.class,  
        new CustomDateEditor( 
          dateFormat, false)); 
        } 
     }
```

Controller 建议还可以用于定义公共模型属性（`@ModelAttribute`）和公共异常处理（`@ExceptionHandler`）。您只需要创建带有适当注释的方法。我们将在下一节讨论异常处理。

# Spring MVC - 高级功能

在本节中，我们将讨论与 Spring MVC 相关的高级功能，包括以下内容：

+   如何为 Web 应用程序实现通用异常处理？

+   如何国际化消息？

+   如何编写集成测试？

+   如何公开静态内容并与前端框架（如 Bootstrap）集成？

+   如何使用 Spring Security 保护我们的 Web 应用程序？

# 异常处理

异常处理是任何应用程序的关键部分之一。在整个应用程序中拥有一致的异常处理策略非常重要。一个流行的误解是，只有糟糕的应用程序才需要异常处理。事实并非如此。即使设计良好、编写良好的应用程序也需要良好的异常处理。

在 Spring Framework 出现之前，由于受检异常的广泛使用，需要在应用程序代码中处理异常处理代码。例如，大多数 JDBC 方法抛出受检异常，需要在每个方法中使用 try catch 来处理异常（除非您希望声明该方法抛出 JDBC 异常）。使用 Spring Framework，大多数异常都变成了未经检查的异常。这确保除非需要特定的异常处理，否则可以在整个应用程序中通用地处理异常。

在本节中，我们将看一下异常处理的几个示例实现：

+   所有控制器中的通用异常处理

+   控制器的特定异常处理

# 跨控制器的通用异常处理

Controller Advice 也可以用于实现跨控制器的通用异常处理。

看一下以下代码：

```java
    @ControllerAdvice 
    public class ExceptionController { 
      private Log logger =  
      LogFactory.getLog(ExceptionController.class); 
      @ExceptionHandler(value = Exception.class) 
      public ModelAndView handleException 
      (HttpServletRequest request, Exception ex) { 
         logger.error("Request " + request.getRequestURL() 
         + " Threw an Exception", ex); 
         ModelAndView mav = new ModelAndView(); 
         mav.addObject("exception", ex); 
         mav.addObject("url", request.getRequestURL()); 
         mav.setViewName("common/spring-mvc-error"); 
         return mav; 
        } 
     }
```

以下是一些需要注意的事项：

+   `@ControllerAdvice`：Controller Advice，默认情况下适用于所有控制器。

+   `@ExceptionHandler(value = Exception.class)`：当控制器中抛出指定类型（`Exception.class`）或子类型的异常时，将调用带有此注解的任何方法。

+   `public ModelAndView handleException (HttpServletRequest request, Exception ex)`：抛出的异常被注入到 Exception 变量中。该方法声明为 ModelAndView 返回类型，以便能够返回一个带有异常详细信息和异常视图的模型。

+   `mav.addObject("exception", ex)`：将异常添加到模型中，以便在视图中显示异常详细信息。

+   `mav.setViewName("common/spring-mvc-error")`：异常视图。

# 错误视图

每当发生异常时，`ExceptionController`在填充模型的异常详细信息后将用户重定向到`ExceptionController`的 spring-mvc-error 视图。以下代码片段显示了完整的 jsp`/WEB-INF/views/common/spring-mvc-error.jsp`：

```java
    <%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%> 
    <%@page isErrorPage="true"%> 
    <h1>Error Page</h1> 
     URL: ${url} 
    <BR /> 
    Exception: ${exception.message} 
   <c:forEach items="${exception.stackTrace}"  
      var="exceptionStackTrace">     
      ${exceptionStackTrace}  
   </c:forEach>
```

重要注意事项如下：

+   `URL: ${url}`：显示模型中的 URL。

+   `Exception: ${exception.message}`：显示异常消息。异常是从`ExceptionController`中填充到模型中的。

+   `forEach around ${exceptionStackTrace}`：显示特定于`ExceptionController`的异常处理的堆栈跟踪。

# 控制器中的特定异常处理

在某些情况下，控制器需要特定的异常处理。可以通过实现一个带有`@ExceptionHandler(value = Exception.class)`注解的方法来轻松处理这种情况。

如果只需要针对特定异常进行特定异常处理，则可以将特定异常类提供为注解的 value 属性的值。

# 国际化

当我们开发应用程序时，希望它们能够在多个区域设置中使用。您希望根据用户的位置和语言定制向用户显示的文本。这称为**国际化**。国际化，`i18n`，也称为**本地化**。

可以使用两种方法实现：

+   `SessionLocaleResolver`

+   `CookieLocaleResolver`

在`SessionLocaleResolver`的情况下，用户选择的区域设置存储在用户会话中，因此仅对用户会话有效。但是，在`CookieLocaleResolver`的情况下，选择的区域设置存储为 cookie。

# 消息包设置

首先，让我们设置一个消息绑定器。来自 spring 上下文的代码片段如下：

```java
    <bean id="messageSource"  class=  
      "org.springframework.context.support.
      ReloadableResourceBundleMessageSource"> 
      <property name="basename" value="classpath:messages" /> 
      <property name="defaultEncoding" value="UTF-8" /> 
    </bean>
```

重要注意事项如下：

+   `class="org.springframework.context.support.ReloadableResourceBundleMessageSource"`：我们正在配置一个可重新加载的资源包。通过 cacheSeconds 设置支持重新加载属性。

+   `<property name="basename" value="classpath:messages" />`：配置从`messages.properties`和`messages_{locale}.properties`文件中加载属性。我们将很快讨论语言环境。

让我们配置一些属性文件，并使它们在`src/main/resources`文件夹中可用：

```java
    message_en.properties 
    welcome.caption=Welcome in English 
    message_fr.properties 
    welcome.caption=Bienvenue - Welcome in French
```

我们可以使用`spring:message`标签在视图中显示来自消息包的消息：

```java
    <spring:message code="welcome.caption" />
```

# 配置 SessionLocaleResolver

配置`SessionLocaleResolver`有两个部分。第一个是配置`localeResolver`。第二个是配置拦截器来处理语言环境的更改：

```java
    <bean id="springMVCLocaleResolver" 
      class="org.springframework.web.servlet.i18n.
      SessionLocaleResolver"> 
      <property name="defaultLocale" value="en" /> 
    </bean> 
    <mvc:interceptors> 
      <bean id="springMVCLocaleChangeInterceptor" 
      class="org.springframework.web.servlet.
      i18n.LocaleChangeInterceptor"> 
        <property name="paramName" value="language" /> 
      </bean> 
    </mvc:interceptors>
```

需要注意的重要事项如下：

+   `<property name="defaultLocale" value="en" />`：默认情况下使用`en`语言环境。

+   `<mvc:interceptors>`：`LocaleChangeInterceptor`被配置为 HandlerInterceptor。它将拦截所有处理程序请求并检查语言环境。

+   `<property name="paramName" value="language" />`：`LocaleChangeInterceptor`被配置为使用名为 language 的请求参数来指示语言环境。因此，任何`http://server/uri?language={locale}`格式的 URL 都会触发语言环境的更改。

+   如果您在任何 URL 后附加`language=en`，则会在会话期间使用`en`语言环境。如果您在任何 URL 后附加`language=fr`，则会使用法语语言环境。

# 配置 CookieLocaleResolver

在以下示例中，我们使用`CookieLocaleResolver`：

```java
    <bean id="localeResolver" 
     class="org.springframework.web.servlet.
     i18n.CookieLocaleResolver"> 
       <property name="defaultLocale" value="en" /> 
       <property name="cookieName" value="userLocaleCookie"/> 
       <property name="cookieMaxAge" value="7200"/> 
    </bean>
```

需要注意的重要事项如下：

+   `<property name="cookieName" value="userLocaleCookie"/>`：存储在浏览器中的 cookie 的名称将是`userLocaleCookie`。

+   `<property name="cookieMaxAge" value="7200"/>`：cookie 的生存期为 2 小时（`7200`秒）。

+   由于我们在前一个示例中使用了`LocaleChangeInterceptor`，如果您在任何 URL 后附加`language=en`，则会在 2 小时内（或直到语言环境更改）使用`en`语言环境。如果您在任何 URL 后附加`language=fr`，则会在 2 小时内（或直到语言环境更改）使用法语语言环境。

# 集成测试 Spring 控制器

在我们讨论的流程中，我们考虑使用真正的单元测试--只加载正在测试的特定控制器。

另一种可能性是加载整个 Spring 上下文。但是，这将更多地是一个集成测试，因为我们将加载整个上下文。以下代码向您展示了如何启动 Spring 上下文，启动所有控制器：

```java
    @RunWith(SpringRunner.class) 
    @WebAppConfiguration 
    @ContextConfiguration("file:src/main/webapp/
    WEB-INF/user-web-context.xml") 
    public class BasicControllerSpringConfigurationIT { 
      private MockMvc mockMvc; 
      @Autowired 
      private WebApplicationContext wac; 
      @Before 
      public void setup() { 
        this.mockMvc =  
        MockMvcBuilders.webAppContextSetup 
        (this.wac).build(); 
      } 
       @Test 
       public void basicTest() throws Exception { 
        this.mockMvc 
        .perform( 
           get("/welcome") 
          .accept(MediaType.parseMediaType 
          ("application/html;charset=UTF-8"))) 
          .andExpect(status().isOk()) 
          .andExpect(content().string 
          ("Welcome to Spring MVC")); 
        } 
      }
```

需要注意的一些事项如下：

+   `@RunWith(SpringRunner.class)`：`SpringRunner`帮助我们启动 Spring 上下文。

+   `@WebAppConfiguration`：用于使用 Spring MVC 启动 Web 应用程序上下文

+   `@ContextConfiguration("file:src/main/webapp/WEB-INF/user-web-context.xml")`：指定 spring 上下文 XML 的位置。

+   `this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build()`：在之前的示例中，我们使用了独立设置。但是，在这个示例中，我们想要启动整个 Web 应用程序。因此，我们使用`webAppContextSetup`。

+   测试的执行与我们之前的测试非常相似。

# 提供静态资源

如今，大多数团队都有专门的团队提供前端和后端内容。前端使用现代的 JavaScript 框架开发，如 AngularJs，Backbone 等。后端是通过基于 Spring MVC 等框架构建的 Web 应用程序或 REST 服务。

随着前端框架的发展，找到正确的解决方案来版本化和交付前端静态内容非常重要。

以下是 Spring MVC 框架提供的一些重要功能：

+   他们从 Web 应用程序根目录中的文件夹中公开静态内容

+   它们启用了缓存

+   他们启用了静态内容的 GZip 压缩

# 公开静态内容

Web 应用程序通常具有大量静态内容。Spring MVC 提供了从 Web 应用程序根目录中的文件夹或类路径上的位置公开静态内容的选项。以下代码片段显示了 war 中的内容可以公开为静态内容：

```java
    <mvc:resources  
    mapping="/resources/**"  
    location="/static-resources/"/>
```

需要注意的事项如下：

+   `location="/static-resources/"`：位置指定 war 或类路径中要公开为静态内容的文件夹。在此示例中，我们希望将根目录中`static-resources`文件夹中的所有内容公开为静态内容。我们可以指定多个逗号分隔的值以在相同的外部 URI 下公开多个文件夹。

+   `mapping="/resources/**"`：映射指定外部 URI 路径。因此，静态资源文件夹中名为`app.css`的 CSS 文件可以使用`/resources/app.css` URI 进行访问。

相同配置的完整 Java 配置在此处显示：

```java
    @Configuration 
    @EnableWebMvc 
    public class WebConfig extends WebMvcConfigurerAdapter { 
      @Override 
      public void addResourceHandlers 
     (ResourceHandlerRegistry registry) { 
        registry 
       .addResourceHandler("/static-resources/**") 
       .addResourceLocations("/static-resources/"); 
      } 
    }
```

# 缓存静态内容

可以启用静态资源的缓存以提高性能。浏览器将缓存为指定时间段提供的资源。可以使用`cache-period`属性或`setCachePeriod`方法来指定基于使用的配置类型的缓存间隔（以秒为单位）。以下代码片段显示了详细信息：

这是 Java 配置：

```java
    registry 
   .addResourceHandler("/resources/**") 
   .addResourceLocations("/static-resources/") 
   .setCachePeriod(365 * 24 * 60 * 60);
```

这是 XML 配置：

```java
    <mvc:resources  
     mapping="/resources/**"  
     location="/static-resources/"  
     cache-period="365 * 24 * 60 * 60"/>
```

将发送`Cache-Control: max-age={specified-max-age}`响应头到浏览器。

# 启用静态内容的 GZip 压缩

压缩响应是使 Web 应用程序更快的一种简单方法。所有现代浏览器都支持 GZip 压缩。可以发送压缩文件作为响应，而不是发送完整的静态内容文件。浏览器将解压并使用静态内容。

浏览器可以指定它可以接受压缩内容的请求头。如果服务器支持，它可以传递压缩内容-再次标记为响应头。

浏览器发送的请求头如下：

```java
Accept-Encoding: gzip, deflate
```

来自 Web 应用程序的响应头如下：

```java
Content-Encoding: gzip
```

以下代码片段显示了如何添加 Gzip 解析器以提供压缩的静态内容：

```java
    registry 
      .addResourceHandler("/resources/**") 
      .addResourceLocations("/static-resources/") 
      .setCachePeriod(365 * 24 * 60 * 60) 
      .resourceChain(true) 
      .addResolver(new GzipResourceResolver()) 
      .addResolver(new PathResourceResolver()); 
```

需要注意的事项如下：

+   `resourceChain(true)`：我们希望启用 Gzip 压缩，但希望在请求完整文件时返回完整文件。因此，我们使用资源链（资源解析器的链接）。

+   `addResolver(new PathResourceResolver()): PathResourceResolver`：这是默认解析器。它根据配置的资源处理程序和位置进行解析。

+   `addResolver(new GzipResourceResolver()): GzipResourceResolver`：当请求时启用 Gzip 压缩。

# 将 Spring MVC 与 Bootstrap 集成

在 Web 应用程序中使用 Bootstrap 的一种方法是下载 JavaScript 和 CSS 文件，并将它们放在各自的文件夹中。但是，这意味着每次有新版本的 Bootstrap 时，我们都需要下载并将其作为源代码的一部分提供。问题是这样的-是否有办法可以通过 Maven 等依赖管理引入 Bootstrap 或任何其他静态（JS 或 CSS）库？

答案是 WebJars。WebJars 是打包成 JAR 文件的客户端 JS 或 CSS 库。我们可以使用 Java 构建工具（Maven 或 Gradle）来下载并使它们可用于应用程序。最大的优势是 WebJars 可以解析传递依赖关系。

现在让我们使用 Bootstrap WebJar 并将其包含在我们的 Web 应用程序中。涉及的步骤如下：

+   将 Bootstrap WebJars 作为 Maven 依赖项添加

+   配置 Spring MVC 资源处理程序以从 WebJar 提供静态内容

+   在 JSP 中使用 Bootstrap 资源（CSS 和 JS）

# Bootstrap WebJar 作为 Maven 依赖项

让我们将其添加到`pom.xml`文件中：

```java
    <dependency> 
      <groupId>org.webjars</groupId> 
      <artifactId>bootstrap</artifactId> 
      <version>3.3.6</version> 
    </dependency>
```

# 配置 Spring MVC 资源处理程序以提供 WebJar 静态内容

这很简单。我们需要将以下映射添加到 spring 上下文中：

```java
    <mvc:resources mapping="/webjars/**" location="/webjars/"/>
```

通过此配置，`ResourceHttpRequestHandler`使来自 WebJars 的内容可用作静态内容。

如静态内容部分所讨论的，如果我们想要缓存内容，我们可以特别缓存一段时间。

# 在 JSP 中使用引导资源

我们可以像 JSP 中的其他静态资源一样添加引导资源：

```java
    <script src= 
     "webjars/bootstrap/3.3.6/js/bootstrap.min.js"> 
    </script> 
   <link  
    href="webjars/bootstrap/3.3.6/css/bootstrap.min.css" 
    rel="stylesheet">
```

# Spring Security

Web 应用程序的关键部分是身份验证和授权。身份验证是建立用户身份的过程，验证用户是否是他/她声称的人。授权是检查用户是否有权执行特定操作。授权指定用户的访问权限。用户能否查看页面？用户能否编辑页面？用户能否删除页面？

最佳实践是在应用程序的每个页面上强制进行身份验证和授权。在执行对 Web 应用程序的任何请求之前，应验证用户凭据和授权。

Spring Security 为 Java EE 企业应用程序提供了全面的安全解决方案。虽然为基于 Spring（和基于 Spring MVC 的）应用程序提供了很好的支持，但它也可以与其他框架集成。

以下列表突出显示了 Spring Security 支持的广泛范围的身份验证机制中的一些：

+   **基于表单的身份验证**：基本应用程序的简单集成

+   **LDAP**：通常在大多数企业应用程序中使用

+   **Java 身份验证和授权服务（JAAS）**：身份验证和授权标准；Java EE 标准规范的一部分

+   容器管理的身份验证

+   自定义身份验证系统

让我们考虑一个简单的示例，在简单的 Web 应用程序上启用 Spring Security。我们将使用内存配置。

涉及的步骤如下：

1.  添加 Spring Security 依赖。

1.  配置拦截所有请求。

1.  配置 Spring Security。

1.  添加注销功能。

# 添加 Spring Security 依赖

我们将从向`pom.xml`添加 Spring Security 依赖开始：

```java
    <dependency> 
      <groupId>org.springframework.security</groupId> 
      <artifactId>spring-security-web</artifactId> 
    </dependency> 
    <dependency> 
      <groupId>org.springframework.security</groupId> 
      <artifactId>spring-security-config</artifactId> 
    </dependency>
```

添加的依赖是`spring-security-web`和`spring-security-config`。

# 配置过滤器以拦截所有请求

在实施安全性时的最佳实践是验证所有传入请求。我们希望我们的安全框架查看传入请求，对用户进行身份验证，并仅在用户有权执行操作时才允许执行操作。我们将使用过滤器拦截和验证请求。以下示例显示了更多细节。

我们希望配置 Spring Security 拦截对 Web 应用程序的所有请求。我们将使用一个过滤器`DelegatingFilterProxy`，它委托给一个 Spring 管理的 bean`FilterChainProxy`：

```java
    <filter> 
      <filter-name>springSecurityFilterChain</filter-name> 
      <filter-class> 
        org.springframework.web.filter.DelegatingFilterProxy 
      </filter-class> 
    </filter> 
    <filter-mapping> 
      <filter-name>springSecurityFilterChain</filter-name> 
      <url-pattern>/*</url-pattern> 
    </filter-mapping>
```

现在，所有对我们 Web 应用程序的请求都将通过过滤器。但是，我们尚未配置与安全相关的任何内容。让我们使用一个简单的 Java 配置示例：

```java
    @Configuration 
    @EnableWebSecurity 
    public class SecurityConfiguration extends  
    WebSecurityConfigurerAdapter { 
      @Autowired 
      public void configureGlobalSecurity 
      (AuthenticationManagerBuilder auth) throws Exception { 
      auth 
      .inMemoryAuthentication() 
      .withUser("firstuser").password("password1") 
      .roles("USER", "ADMIN"); 
     } 
     @Override 
     protected void configure(HttpSecurity http)  
     throws Exception { 
       http 
      .authorizeRequests() 
      .antMatchers("/login").permitAll() 
      .antMatchers("/*secure*/**") 
      .access("hasRole('USER')") 
      .and().formLogin(); 
      } 
    }
```

需要注意的事项如下：

+   `@EnableWebSecurity`：此注解使任何配置类能够包含 Spring 配置的定义。在这种特定情况下，我们重写了一些方法，以提供我们特定的 Spring MVC 配置。

+   `WebSecurityConfigurerAdapter`：此类提供了创建 Spring 配置（`WebSecurityConfigurer`）的基类。

+   `protected void configure(HttpSecurity http)`: 此方法为不同 URL 提供安全需求。

+   `antMatchers("/*secure*/**").access("hasRole('USER')"`: 您需要具有用户角色才能访问包含子字符串`secure`的任何 URL。

+   `antMatchers("/login").permitAll()`: 允许所有用户访问登录页面。

+   `public void configureGlobalSecurity(AuthenticationManagerBuilder auth)`: 在此示例中，我们使用内存身份验证。这可以用于连接到数据库（`auth.jdbcAuthentication()`），或 LDAP（`auth.ldapAuthentication()`），或自定义身份验证提供程序（扩展`AuthenticationProvider`创建）。

+   `withUser("firstuser").password("password1")`: 配置内存中有效的用户 ID 和密码组合。

+   `.roles("USER", "ADMIN")`: 为用户分配角色。

当我们尝试访问任何安全的 URL 时，我们将被重定向到登录页面。Spring Security 提供了自定义逻辑页面以及重定向的方式。只有具有正确角色的经过认证的用户才能访问受保护的应用程序页面。

# 注销

Spring Security 提供了功能，使用户能够注销并被重定向到指定页面。`LogoutController`的 URI 通常映射到 UI 中的注销链接。`LogoutController`的完整列表如下：

```java
    @Controller 
    public class LogoutController { 
      @RequestMapping(value = "/secure/logout",  
      method = RequestMethod.GET) 
      public String logout(HttpServletRequest request, 
      HttpServletResponse response) { 
        Authentication auth =  
        SecurityContextHolder.getContext() 
        .getAuthentication(); 
        if (auth != null) { 
            new SecurityContextLogoutHandler() 
           .logout(request, response, auth); 
            request.getSession().invalidate(); 
          } 
        return "redirect:/secure/welcome"; 
       } 
     }
```

需要注意的是：

+   `if (auth != null)`: 如果有有效的认证，那么结束会话

+   `new SecurityContextLogoutHandler().logout(request, response, auth)`: `SecurityContextLogoutHandler`通过从`SecurityContextHolder`中删除认证信息来执行注销

+   `return "redirect:/secure/welcome"`: 重定向到安全的欢迎页面

# 总结

在本章中，我们讨论了使用 Spring MVC 开发 Web 应用程序的基础知识。我们还讨论了实现异常处理、国际化以及使用 Spring Security 保护我们的应用程序。

Spring MVC 也可以用来构建 REST 服务。我们将在接下来的章节中讨论与 REST 服务相关的内容。

在下一章中，我们将把注意力转向微服务。我们将尝试理解为什么世界对微服务如此关注。我们还将探讨应用程序成为云原生的重要性。
