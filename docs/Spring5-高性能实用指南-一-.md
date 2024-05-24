# Spring5 高性能实用指南（一）

> 原文：[`zh.annas-archive.org/md5/40194AF6586468BFD8652280B650BA1F`](https://zh.annas-archive.org/md5/40194AF6586468BFD8652280B650BA1F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

这本书的使命是向开发人员介绍应用程序监控和性能调优，以创建高性能的应用程序。该书从 Spring Framework 的基本细节开始，包括各种 Spring 模块和项目、Spring bean 和 BeanFactory 实现，以及面向方面的编程。它还探讨了 Spring Framework 作为 IoC bean 容器。我们将讨论 Spring MVC，这是一个常用的 Spring 模块，用于详细构建用户界面，包括 Spring Security 身份验证部分和无状态 API。这本书还强调了构建与关系数据库交互的优化 Spring 应用程序的重要性。然后，我们将通过一些高级的访问数据库的方式，使用对象关系映射（ORM）框架，如 Hibernate。该书继续介绍了 Spring Boot 和反应式编程等新 Spring 功能的细节，并提出了最佳实践建议。该书的一个重要方面是它专注于构建高性能的应用程序。该书的后半部分包括应用程序监控、性能优化、JVM 内部和垃圾收集优化的细节。最后，解释了如何构建微服务，以帮助您了解在该过程中面临的挑战以及如何监视其性能。

# 第五章《理解 Spring 数据库交互》帮助我们了解 Spring Framework 与数据库交互。然后介绍了 Spring 事务管理和最佳连接池配置。最后，介绍了数据库设计的最佳实践。

这本书适合想要构建高性能应用程序并在生产和开发中更多地控制应用程序性能的 Spring 开发人员。这本书要求开发人员对 Java、Maven 和 Eclipse 有一定的了解。

# 这本书涵盖了什么

第一章《探索 Spring 概念》侧重于清晰理解 Spring Framework 的核心特性。它简要概述了 Spring 模块，并探讨了不同 Spring 项目的集成，并清晰解释了 Spring IoC 容器。最后，介绍了 Spring 5.0 的新功能。

第二章《Spring 最佳实践和 Bean 装配配置》探讨了使用 Java、XML 和注解进行不同的 bean 装配配置。该章还帮助我们了解在 bean 装配配置方面的不同最佳实践。它还帮助我们了解不同配置的性能评估，以及依赖注入的陷阱。

第三章《调优面向方面的编程》探讨了 Spring 面向方面的编程（AOP）模块及其各种术语的概念。它还涵盖了代理的概念。最后，介绍了使用 Spring AOP 模块实现质量和性能的最佳实践。

第四章《Spring MVC 优化》首先清楚地介绍了 Spring MVC 模块以及不同的 Spring MVC 配置方法。它还涵盖了 Spring 中的异步处理概念。然后解释了 Spring Security 配置和无状态 API 的身份验证部分。最后，介绍了 Tomcat 与 JMX 的监控部分，以及 Spring MVC 性能改进。

这本书适合谁

第六章《Hibernate 性能调优和缓存》描述了使用 ORM 框架（如 Hibernate）访问数据库的一些高级方式。最后，解释了如何使用 Spring Data 消除实现数据访问对象（DAO）接口的样板代码。

第七章，*优化 Spring 消息传递*，首先探讨了 Spring 消息传递的概念及其优势。然后详细介绍了在 Spring 应用程序中使用 RabbitMQ 进行消息传递的配置。最后，描述了提高性能和可伸缩性以最大化吞吐量的参数。

第八章，*多线程和并发编程*，介绍了 Java 线程的核心概念和高级线程支持。还介绍了 Java 线程池的概念以提高性能。最后，将探讨使用线程进行 Spring 事务管理以及编程线程的各种最佳实践。

第九章，*性能分析和日志记录*，专注于性能分析和日志记录的概念。本章首先定义了性能分析和日志记录以及它们如何有助于评估应用程序的性能。在本章的后半部分，重点将是学习可以用于研究应用程序性能的软件工具。

第十章，*应用性能优化*，专注于优化应用程序性能。还介绍了识别性能问题症状、性能调优生命周期和 Spring 中的 JMX 支持的详细信息。

第十一章，*JVM 内部*，介绍了 JVM 的内部结构和调优 JVM 以实现高性能的内容。还涵盖了与内存泄漏相关的主题以及与垃圾回收相关的常见误解，然后讨论了不同的垃圾回收方法及其重要性。

第十二章，*Spring Boot 微服务性能调优*，介绍了 Spring Boot 微服务及其性能调优的概念。还清楚地描述了如何使用执行器和健康检查来监视 Spring Boot 应用程序。还涵盖了不同的技术，以调优 Spring Boot 应用程序的性能。

# 充分利用本书

本书要求开发人员对 Java、Maven 和 Eclipse 有一定的了解。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，文件将直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩软件解压文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-High-Performance-with-Spring-5`](https://github.com/PacktPublishing/Hands-On-High-Performance-with-Spring-5)。如果代码有更新，将在现有的 GitHub 存储库中更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。快去看看吧！

# 下载彩色图片

我们还提供了一份 PDF 文件，其中包含本书中使用的截图/图表的彩色图片。您可以从[`www.packtpub.com/sites/default/files/downloads/HandsOnHighPerformancewithSpring5_ColorImages.pdf.`](https://www.packtpub.com/sites/default/files/downloads/HandsOnHighPerformancewithSpring5_ColorImages.pdf)下载。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码单词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄。这是一个例子：“为了避免`LazyInitializationException`，解决方案之一是在视图中打开会话。”

一块代码设置如下：

```java
PreparedStatement st = null;
try {
    st = conn.prepareStatement(INSERT_ACCOUNT_QUERY);
    st.setString(1, bean.getAccountName());
    st.setInt(2, bean.getAccountNumber());
    st.execute();
}
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目以粗体显示：

```java
@Configuration
@EnableTransactionManagement
@PropertySource({ "classpath:persistence-hibernate.properties" })
@ComponentScan({ "com.packt.springhighperformance.ch6.bankingapp" })
    @EnableJpaRepositories(basePackages = "com.packt.springhighperformance.ch6.bankingapp.repository")
public class PersistenceJPAConfig {

}
```

任何命令行输入或输出都是这样写的：

```java
curl -sL --connect-timeout 1 -i http://localhost:8080/authentication-cache/secure/login -H "Authorization: Basic Y3VzdDAwMTpUZXN0QDEyMw=="
```

**粗体**：表示新术语，重要单词，或者您在屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“在应用程序窗口内，我们可以看到一个用于本地节点的菜单。”

警告或重要提示看起来像这样。

提示和技巧看起来像这样。


# 第一章：探索 Spring 概念

Spring Framework 提供了广泛的支持，用于管理大型企业 Java 应用程序，并解决企业应用程序开发的复杂性。Spring 为现代企业应用程序提供了完整的 API 和配置模型，因此程序员只需专注于应用程序的业务逻辑。

Spring Framework 作为一个轻量级框架，旨在提供一种简化 Java 企业应用程序开发的方式。

本章将帮助您更好地了解 Spring Framework 的核心特性。我们将从介绍 Spring Framework 开始。本章还将让您清楚地了解 Spring Framework 的每个主要模块。在快速了解 Spring Framework 中的重要模块之后，我们将深入了解 Spring 项目的世界。我们还将清楚地了解 Spring 的控制反转（IoC）容器。最后，我们将看一下 Spring 5.0 中引入的新功能和增强功能。

在本章中，我们将讨论以下主题：

+   介绍 Spring Framework

+   理解 Spring 模块

+   Spring 项目

+   Spring IoC 容器

+   Spring Framework 5.0 中的新功能

# 介绍 Spring Framework

Spring Framework 是最受欢迎的开源 Java 应用程序框架和 IoC 容器之一。Spring 最初由 Rod Johnson 和 Jurgen Holler 开发。Spring Framework 的第一个里程碑版本于 2004 年 3 月发布。尽管已经过去了十五年，Spring Framework 仍然是构建任何 Java 应用程序的首选框架。

Spring 框架为开发企业级 Java 应用程序提供了全面的基础设施支持。因此，开发人员不需要担心应用程序的基础设施；他们可以专注于应用程序的业务逻辑，而不是处理应用程序的配置。

Spring Framework 处理所有基础设施、配置和元配置文件，无论是基于 Java 还是基于 XML。因此，这个框架为您提供了更多的灵活性，可以使用普通的 Java 对象（POJO）编程模型而不是侵入式编程模型来构建应用程序。

Spring IoC 容器通过整合应用程序的各种组件来构建整个框架的核心。Spring 的 Model-View-Controller（MVC）组件可用于构建非常灵活的 Web 层。IoC 容器简化了使用 POJOs 开发业务层。

# EJB 的问题

在早期，程序员很难管理企业应用程序，因为企业 Java 技术如 Enterprise JavaBeans（EJB）对程序员提供企业解决方案的负担很重。

当 EJB 技术首次宣布时，它提供了一个分布式组件模型，允许开发人员只关注系统的业务方面，而忽略中间件的要求，如组件的连接、事务管理、持久性操作、安全性、资源池、线程、分发、远程等等；然而，开发、单元测试和部署 EJB 应用程序是一个非常繁琐的过程。在使用 EJB 时，面临以下一些复杂性：

+   强制实现不必要的接口和方法

+   使单元测试变得困难，特别是在 EJB 容器之外

+   管理部署描述符中的不便之处

+   繁琐的异常处理

当时，Spring 被引入作为 EJB 的一种替代技术，因为与其他现有的 Java 技术相比，Spring 提供了非常简单、更精简和更轻量级的编程模型。Spring 使得克服之前的复杂性成为可能，并且通过使用许多可用的设计模式，避免了使用其他更重的企业技术。Spring 框架专注于 POJO 编程模型而不是侵入式编程模型。这个模型为 Spring 框架提供了简单性。它还赋予了诸如**依赖注入**（**DI**）模式和**面向切面编程**（**AOP**）等概念，使用代理模式和装饰器模式。

# 使用 POJO 简化实现

POJO 编程模型最重要的优势是应用类的编码非常快速和简单。这是因为类不需要依赖于任何特定的 API，实现任何特殊的接口，或者扩展特定的框架类。直到真正需要它们之前，您不必创建任何特殊的回调方法。

# Spring 框架的好处

Spring 框架的重要好处如下：

+   无需重新发明轮子

+   易于单元测试

+   减少实现代码

+   控制反转和 API

+   事务管理的一致性

+   模块化架构

+   与时俱进

让我们详细讨论每一个。

# 无需重新发明轮子

无需重新发明轮子是开发人员可以从 Spring 框架中获得的最重要的好处之一。它促进了众所周知的技术、ORM 框架、日志框架、JEE、JDK 定时器、Quartz 等的实际使用。因此，开发人员不需要学习任何新的技术或框架。

它促进了良好的编程实践，例如使用接口而不是类进行编程。Spring 使开发人员能够使用 POJO 和**Plain Old Java Interface**（**POJI**）模型编程开发企业应用程序。

# 易于单元测试

如果您想测试使用 Spring 开发的应用程序，这是相当容易的。这背后的主要原因是这个框架中有环境相关的代码。早期版本的 EJB 非常难以进行单元测试。甚至在容器外运行 EJB（截至 2.1 版本）都很困难。测试它们的唯一方法是将它们部署到容器中。

Spring 框架引入了 DI 概念。我们将在第二章中详细讨论 DI，*Spring 最佳实践和 Bean 布线配置*。DI 使得单元测试成为可能。这是通过用它们的模拟替换依赖项来完成的。整个应用程序不需要部署进行单元测试。

单元测试有多个好处：

+   提高程序员的生产力

+   在较早的阶段检测缺陷，从而节省修复它们的成本

+   通过在**持续集成**（**CI**）构建中自动化单元测试来预防未来的缺陷

# 减少实现代码

所有应用程序类都是简单的 POJO 类；Spring 不是侵入式的。对于大多数用例，它不需要您扩展框架类或实现框架接口。Spring 应用程序不需要 Jakarta EE 应用服务器，但可以部署在其中。

在 Spring 框架之前，典型的 J2EE 应用程序包含了大量的管道代码。例如：

+   获取数据库连接的代码

+   处理异常的代码

+   事务管理代码

+   日志代码等等

让我们看一个使用`PreparedStatement`执行查询的简单示例：

```java
PreparedStatement st = null;
try {
    st = conn.prepareStatement(INSERT_ACCOUNT_QUERY);
    st.setString(1, bean.getAccountName());
    st.setInt(2, bean.getAccountNumber());
    st.execute();
}
catch (SQLException e) {
    logger.error("Failed : " + INSERT_ACCOUNT_QUERY, e);
} finally {
    if (st != null) {
        try {
            st.close();
        } catch (SQLException e) {
            logger.log(Level.SEVERE, INSERT_ACCOUNT_QUERY, e);
        }
    }
}
```

在上面的示例中，有四行业务逻辑和超过 10 行的管道代码。使用 Spring 框架可以在几行代码中应用相同的逻辑，如下所示：

```java
jdbcTemplate.update(INSERT_ACCOUNT_QUERY,
bean.getAccountName(), bean.getAccountNumber());
```

使用 Spring，可以将 Java 方法作为请求处理程序方法或远程方法，就像处理 servlet API 的 servlet 容器的`service()`方法一样，但无需处理 servlet API。它支持基于 XML 和基于注解的配置。

Spring 使您可以使用本地 Java 方法作为消息处理程序方法，而无需在应用程序中使用 Java 消息服务（JMS）API。Spring 充当应用程序对象的容器。您的对象不必担心找到并建立彼此之间的连接。Spring 还使您可以使用本地 Java 方法作为管理操作，而无需在应用程序中使用 Java 管理扩展（JMX）API。

# 控制反转和 API

Spring 还帮助开发人员摆脱编写单独的编译单元或单独的类加载器来处理异常的必要性。Spring 将技术相关的异常，特别是由 Java 数据库连接（JDBC）、Hibernate 或 Java 数据对象（JDO）抛出的异常转换为未经检查的一致异常。Spring 通过控制反转和 API 来实现这一神奇的功能。

此外，它使用 IoC 进行 DI，这意味着可以正常配置方面。如果要添加自己的行为，需要扩展框架的类或插入自己的类。这种架构的优势如下所示：

+   将任务的执行与其实现解耦

+   更容易在不同实现之间切换

+   程序的更大模块化

+   通过隔离组件或模拟组件，更容易测试程序

+   依赖关系并允许组件通过合同进行通信

# 事务管理的一致性

Spring 还提供了对事务管理的支持，保证一致性。它提供了一种简单灵活的方式，可以为小型应用配置本地事务，也可以为大型应用使用 Java 事务 API（JTA）配置全局事务。因此，我们不需要使用任何第三方事务 API 来执行数据库事务；Spring 将通过事务管理功能来处理它。

# 模块化架构

Spring 提供了一个模块化架构，帮助开发人员识别要使用和要忽略的包或类。因此，以这种方式，我们可以只保留真正需要的内容。这样即使有很多包或类，也可以轻松识别和利用可用的包或类。

Spring 是一个强大的框架，解决了 Jakarta EE 中的许多常见问题。它包括支持管理业务对象并将其服务暴露给表示层组件。

Spring 实例化 bean 并将对象的依赖项注入到应用程序中，它充当 bean 的生命周期管理器。

# 与时俱进

当 Spring Framework 的第一个版本构建时，其主要重点是使应用程序可测试。后续版本也面临新的挑战，但 Spring Framework 设法发展并保持领先，并与提供的架构灵活性和模块保持一致。以下是一些示例：

+   Spring Framework 在 Jakarta EE 之前引入了许多抽象，以使应用程序与特定实现解耦。

+   Spring Framework 还在 Spring 3.1 中提供了透明的缓存支持

+   Jakarta EE 在 2014 年引入了 JSR-107 用于 JCache，因此在 Spring 4.1 中提供了它

Spring 参与的另一个重大发展是提供不同的 Spring 项目。Spring Framework 只是 Spring 项目中的众多项目之一。以下示例说明了 Spring Framework 如何保持与 Spring 项目的最新状态：

+   随着架构向云和微服务发展，Spring 推出了面向云的新 Spring 项目。Spring Cloud 项目简化了微服务的开发和部署。

+   通过 Spring 框架引入了一种新的方法来构建 Java 批处理应用程序，即 Spring Batch 项目。

在下一节中，我们将深入探讨不同的 Spring 框架模块。

# 了解 Spring 模块

Spring 提供了一种模块化的架构，这是 Spring 框架受欢迎的最重要原因之一。其分层架构使得可以轻松无忧地集成其他框架。这些模块提供了开发企业应用程序所需的一切。Spring 框架分为 20 个不同的模块，这些模块建立在其核心容器之上。

以下图表说明了以分层架构组织的不同 Spring 模块：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/a1a68982-99fd-4f80-9c50-910d04a97854.jpg)

Spring 框架模块

我们将从讨论核心容器开始，然后再讨论其他模块。

# 核心容器

Spring 核心容器提供了 Spring 框架的核心功能，即核心、Bean、上下文和表达式语言，其详细信息如下：

| **Artifact** | **Module Usage** |
| --- | --- |
| `spring-core` | 该模块为其他模块使用的所有实用程序提供便利，还提供了一种管理不同 bean 生命周期操作的方式。 |
| `spring-beans` | 该模块主要用于解耦代码依赖于实际业务逻辑，并使用 DI 和 IoC 功能消除了单例类的使用。 |
| `spring-context` | 该模块提供国际化和资源加载等功能，并支持 Java EE 功能，如 EJB、JMS 和远程调用。 |
| `spring-expression` | 该模块提供了在运行时访问 bean 属性的支持，并允许我们操纵它们。 |

# 横切关注点

横切关注点适用于应用程序的所有层，包括日志记录和安全性等。与横切关注点相关的重要 Spring 模块如下：

| **Artifact** | **Module Usage** |
| --- | --- |
| `spring-aop` | 该模块主要用于执行系统中各个部分共同的任务，如事务管理、日志记录和安全性。为了实现这一点，我们可以实现方法拦截器和切入点。 |
| `spring-aspects` | 该模块用于集成任何自定义对象类型。使用 AspectJ 是可能的，该模块的主要用途是集成容器无法控制的对象。 |
| `spring-instrument` | 该模块用于测量应用程序的性能，并使用跟踪信息进行错误诊断。 |
| `spring-test` | 该模块用于在 Spring 应用程序中集成测试支持。 |

# 数据访问/集成

数据访问/集成层在应用程序中与数据库和/或外部接口交互。它包括 JDBC、ORM、OXM、JMS 和事务模块。这些模块是`spring-jdbc`、`spring-orm`、`spring-oxm`、`spring-jms`和`spring-tx`。

# Web

Web 层包含 Web、Web-MVC、Web-Socket 和其他 Web-Portlet 模块。各自的模块名称为`spring-web`、`spring-webmvc`、`spring-websocket`、`spring-webmvc-portlet`。

在下一节中，我们将介绍不同类型的 Spring 项目。

# Spring 项目

Spring 框架为不同的基础设施需求提供了不同类型的项目，并帮助探索企业应用程序中的其他问题的解决方案：部署、云、大数据和安全性等。

一些重要的 Spring 项目列举如下：

+   Spring Boot

+   Spring 数据

+   Spring Batch

+   Spring Cloud

+   Spring 安全

+   Spring HATEOAS

让我们详细讨论它们。

# Spring Boot

Spring Boot 支持创建独立的、生产级的、基于 Spring 的应用程序，只需运行即可。

Spring Boot 还提供了一些开箱即用的功能，通过对应用程序开发的一种主观观点：

+   提供开发独立 Spring 应用程序的支持

+   直接嵌入 Tomcat、Jetty 或 Undertow，无需部署 WAR 文件

+   允许我们将配置外部化，以便在不同环境中使用相同的应用程序代码

+   通过提供主观的起始 POM 简化 Maven 配置

+   消除了代码生成和 XML 配置的需求

+   提供用于生产特性的支持，如度量、健康检查和应用程序监控

我们将在第十二章中深入研究 Spring Boot，*Spring Boot 微服务性能调优*。

# Spring Data

**Spring Data**项目的主要目标是为访问数据和其他特殊功能提供一个易于使用和一致的基于 Spring 的模型，以操作基于 SQL 和 NoSQL 的数据存储。它还试图提供一种简单的方式来使用数据访问技术、映射-减少框架、关系和非关系数据库以及基于云的数据服务。

一些重要特性如下：

+   提供与自定义存储库代码集成的支持

+   通过使用存储库和对象映射抽象，通过使用存储库方法名称派生动态查询

+   与 Spring MVC 控制器的高级集成支持

+   对透明审计功能的高级支持，如创建者、创建日期、最后更改者和最后更改日期

+   跨存储持久性的实验性集成支持

Spring Data 为以下数据源提供集成支持：

+   JPA

+   JDBC

+   LDAP

+   MongoDB

+   Gemfire

+   REST

+   Redis

+   Apache Cassandra

+   Apache Solr

# Spring Batch

Spring Batch 有助于处理大量记录，包括日志/跟踪、事务管理、作业处理统计、作业重启、跳过和资源管理，通过提供可重用的功能。它还提供了更高级的技术服务和功能，可以使用优化和分区技术实现极高容量和高性能的批处理作业。

Spring Batch 的重要特性如下：

+   以块的方式处理数据的能力

+   启动、停止和重新启动作业的能力，包括在作业失败的情况下从失败点重新启动

+   重试步骤或在失败时跳过步骤的能力

+   基于 Web 的管理界面

# Spring Cloud

可以说*世界正在向云端迁移*。

**Spring Cloud**为开发人员提供了构建分布式系统中常见模式的工具。Spring Cloud 使开发人员能够快速构建服务和应用程序，实现在任何分布式环境中工作的常见模式。

Spring Cloud 中实现的一些常见模式如下：

+   分布式配置

+   服务注册和发现

+   断路器

+   负载平衡

+   智能路由

+   分布式消息传递

+   全局锁

# Spring Security

身份验证和授权是企业应用程序的重要部分，包括 Web 应用程序和 Web 服务。**Spring** **Security**是一个功能强大且高度可定制的身份验证和访问控制框架。Spring Security 专注于为 Java 应用程序提供声明式的身份验证和授权。

Spring Security 的重要特性如下：

+   全面支持身份验证和授权

+   与 Servlet API 和 Spring MVC 的集成支持良好

+   模块支持与**安全断言标记语言**（**SAML**）和**轻量级目录访问协议**（**LDAP**）集成

+   提供对常见安全攻击的支持，如**跨站请求伪造**（**CSRF**）、会话固定、点击劫持等

我们将在第四章中讨论如何使用 Spring Security 保护 Web 应用程序，*Spring MVC 优化*。

# Spring HATEOAS

**超媒体作为应用状态引擎**（**HATEOAS**）的主要目的是解耦服务器（服务提供者）和客户端（服务消费者）。服务器向客户端提供有关可以在资源上执行的其他可能操作的信息。

Spring HATEOAS 提供了一个 HATEOAS 实现，特别适用于使用 Spring MVC 实现的**表述状态转移**（**REST**）服务。

Spring HATEOAS 具有以下重要特性：

+   简化的链接定义，指向服务方法，使得链接更加健壮

+   支持 JSON 和 JAXB（基于 XML）集成

+   支持超媒体格式，如**超文本应用语言**（**HAL**）

在下一节中，我们将了解 Spring 的 IoC 容器的机制。

# Spring 的 IoC 容器

Spring 的**IoC 容器**是 Spring 架构的核心模块。IoC 也被称为 DI。这是一种设计模式，它消除了代码对提供应用程序管理和测试的依赖性。在 DI 中，对象本身通过构造函数参数、工厂方法的参数或在创建或从工厂方法返回对象实例后设置的属性来描述它们与其他对象的依赖关系。

然后容器负责在创建 bean 时注入这些依赖关系。这个过程基本上是 bean 本身控制其依赖项的实例化或位置的逆过程（因此被称为 IoC），通过使用类的直接构造或机制。

Spring 框架的 IoC 容器有两个主要的基本包：`org.springframework.beans`和`org.springframework.context`。`BeanFactory`接口提供了一些高级配置机制，用于管理任何类型的对象。`ApplicationContext`包括了所有`BeanFactory`的功能，并且作为它的子接口。事实上，`ApplicationContext`也比`BeanFactory`更推荐，并提供了更多的支持基础设施，使得：更容易集成 Spring 的 AOP 特性和事务；消息资源处理方面的国际化和事件发布；以及应用层特定的上下文，比如用于 Web 应用程序的`WebApplicationContext`。

接口`org.springframework.context.ApplicationContext`被表示为 Spring IoC 容器，它完全控制 bean 的生命周期，并负责实例化、配置和组装 bean。

容器通过扫描 bean 配置元数据来获取实例化、配置和组装的所有指令。配置元数据可以用以下方法表示：

+   基于 XML 的配置

+   基于注解的配置

+   基于 Java 的配置

我们将在第二章中更详细地学习这些方法，*Spring 最佳实践和 Bean 配置*。

以下图表代表了**Spring 容器**向创建完全配置的应用程序的过程的简单表示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/e59e8c91-5ae5-4977-a721-ced135b86944.jpg)

Spring IoC 容器

以下示例显示了基于 XML 的配置元数据的基本结构：

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans 

 xsi:schemaLocation="http://www.springframework.org/schema/beans
 http://www.springframework.org/schema/beans/spring-beans.xsd">

 <!-- All the bean configuration goes here -->
<bean id="..." class="...">

</bean>

<!-- more bean definitions go here -->

</beans>
```

`id`属性是一个字符串，用于标识单个`bean`定义。`class`属性定义了`bean`的类型，并使用了完全限定的`class`名称。`id`属性的值指的是协作对象。

# 什么是 Spring bean？

您可以将**Spring bean**视为由 Spring IoC 容器实例化、配置和管理的简单 Java 对象。它被称为 bean 而不是对象或组件，因为它是对框架起源的复杂和沉重的企业 JavaBeans 的替代。我们将在第二章中学习更多关于 Spring bean 实例化方法的内容，*Spring 最佳实践和 bean 装配配置*。

# 实例化 Spring 容器

用于创建 bean 实例，我们首先需要通过读取配置元数据来实例化 Spring IoC 容器。在初始化 IoC 容器之后，我们可以使用 bean 名称或 ID 获取 bean 实例。

Spring 提供了两种类型的 IoC 容器实现：

+   `BeanFactory`

+   `ApplicationContext`

# BeanFactory

`BeanFactory`容器充当最简单的容器，提供了对 DI 的基本支持，它由`org.springframework.beans.factory.BeanFactory`接口定义。`BeanFactory`负责在对象之间获取、配置和组装依赖关系。`BeanFactory`主要充当对象池，通过配置管理对象的创建和销毁。`BeanFactory`最受欢迎和有用的实现是`org.springframework.context.support.ClassPathXmlApplicationContext`。`ClassPathXmlApplicationContext`使用 XML 配置元数据来创建一个完全配置的应用程序。

以下示例定义了一个简单的`HelloWorld`应用程序，使用`ClassPathXmlApplicationContext`。`Beans.xml`的内容如下：

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans 

  xsi:schemaLocation="http://www.springframework.org/schema/beans
  http://www.springframework.org/schema/beans/spring-beans.xsd">

  <bean id="bankAccount" 
    class="com.packt.springhighperformance.ch1.bankingapp.BankAccount">
    <property name="accountType" value="Savings Bank Account" />
  </bean>
</beans>
```

前面的 XML 代码表示了`bean` XML 配置的内容。它配置了一个单独的`bean`，其中有一个带有`name`消息的属性。该属性有一个默认的`value`设置。

现在，以下 Java 类表示在前面的 XML 中配置的`bean`。

让我们来看看`HelloWorld.java`：

```java
package com.packt.springhighperformance.ch1.bankingapp;

public class BankAccount {
  private String accountType;

  public void setAccountType(String accountType) {
    this.accountType = accountType;
  }

  public String getAccountType() {
    return this.accountType;
  }
}
```

最后，我们需要使用`ClassPathXmlApplicationContext`来创建`HelloWorld` bean，并调用创建的 Spring bean 中的方法。

`Main.java`如下所示：

```java
package com.packt.springhighperformance.ch1.bankingapp;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.context.
support.ClassPathXmlApplicationContext;

public class Main {

  private static final Logger LOGGER = Logger.getLogger(Main.class);

  @SuppressWarnings("resource")
  public static void main(String[] args) {
    BeanFactory beanFactory = new 
    ClassPathXmlApplicationContext("Beans.xml");
    BankAccount obj = (BankAccount) beanFactory.getBean("bankAccount");
    LOGGER.info(obj.getAccountType());
  }
}

```

# ApplicationContext

`ApplicationContext`容器提供了使用`BeanFactory`方法访问应用程序组件的支持。这包括`BeanFactory`的所有功能。此外，`ApplicationContext`还可以执行更多的企业功能，如事务、AOP、从属性文件解析文本消息以及将应用程序事件推送给感兴趣的监听器。它还具有将事件发布给已注册监听器的能力。

`ApplicationContext`的最常用的实现是`FileSystemXmlApplicationContext`、`ClassPathXmlApplicationContext`和`AnnotationConfigApplicationContext`。

Spring 还为我们提供了`ApplicationContext`接口的 Web-aware 实现，如下所示：

+   `XmlWebApplicationContext`

+   `AnnotationConfigWebApplicationContext`

我们可以使用这些实现中的任何一个来将 bean 加载到`BeanFactory`中；这取决于我们的应用程序配置文件的位置。例如，如果我们想要从文件系统中的特定位置加载我们的配置文件`Beans.xml`，我们可以使用`FileSystemXmlApplicationContext`类，该类在文件系统中的特定位置查找配置文件`Beans.xml`：

```java
ApplicationContext context = new
FileSystemXmlApplicationContext("E:/Spring/Beans.xml");
```

如果我们想要从应用程序的类路径加载我们的配置文件`Beans.xml`，我们可以使用 Spring 提供的`ClassPathXmlApplicationContext`类。这个类在类路径中的任何地方，包括 JAR 文件中，查找配置文件`Beans.xml`：

```java
ApplicationContext context = new
ClassPathXmlApplicationContext("Beans.xml");
```

如果您使用 Java 配置而不是 XML 配置，您可以使用`AnnotationConfigApplicationContext`：

```java
ApplicationContext context = new
AnnotationConfigApplicationContext(AppConfig.class);
```

加载配置文件并获取`ApplicationContext`之后，我们可以通过调用`ApplicationContext`的`getBean()`方法从 Spring 容器中获取 bean：

```java
BankAccountService bankAccountService =
context.getBean(BankAccountService.class);
```

在下面的部分，我们将学习 Spring bean 的生命周期，以及 Spring 容器如何对 Spring bean 做出反应以创建和管理它。

# Spring bean 生命周期

工厂方法设计模式被 Spring `ApplicationContext`用来按照给定的配置在容器中正确顺序创建 Spring bean。因此，Spring 容器负责管理 bean 的生命周期，从创建到销毁。在普通的 Java 应用程序中，使用 Java 的`new`关键字来实例化 bean，然后就可以使用了。一旦 bean 不再使用，就可以进行垃圾回收。但是在 Spring 容器中，bean 的生命周期更加复杂。

以下图表说明了典型 Spring bean 的生命周期：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/5f0cc18b-e6fe-4d9c-8522-881ca5674560.jpg)

Spring bean 生命周期

在下一节中，我们将看到 Spring Framework 5.0 的新功能。

# Spring Framework 5.0 的新功能

**Spring Framework 5.0**是 Spring Framework 在 4.0 版本之后近四年的第一个重大升级。在这段时间内，最重要的发展之一就是 Spring Boot 项目的发展。我们将在下一节讨论 Spring Boot 2.0 的新功能。Spring Framework 5.0 最大的特点之一是**响应式编程**。

Spring Framework 5.0 具有核心响应式编程功能和对响应式端点的支持。重要变化的列表包括以下内容：

+   基线升级

+   响应式编程支持

+   核心功能升级

+   Spring Web MVC 升级

+   Spring 的新功能性 Web 框架**WebFlux**

+   模块化支持

+   Kotlin 语言支持

+   改进的测试支持

+   弃用或废弃的功能

我们将在接下来的部分详细讨论这些变化。

# 基线升级

整个 Spring Framework 5.0 都有一个 JDK 8 和 Jakarta EE 7 的基线。基本上，这意味着要在 Spring Framework 5.0 上工作，Java 8 是最低要求。

Spring Framework 5.0 的一些重要的基线 Jakarta EE 7 规范如下：

+   Spring Framework 5.0 的代码基于 Java 8 的源代码级别。因此，使用推断泛型、lambda 等提高了代码的可读性。它还具有对 Java 8 特性的条件支持的代码稳定性。

+   Spring Framework 需要至少 Jakarta EE 7 API 级别才能运行任何 Spring Framework 5.0 应用程序。它需要 Servlet 3.1、Bean Validation 1.1、JPA 2.1 和 JMS 2.0。

+   开发和部署过程完全兼容 JDK 9，具体如下：

+   与类路径和模块路径兼容，具有稳定的自动模块名称

+   Spring Framework 的构建和测试套件也在 JDK 9 上通过，并且默认情况下可以在 JDK 8 上运行

# 响应式编程支持

响应式编程模型是 Spring 5.0 最令人兴奋的特性之一。Spring 5.0 框架基于响应式基础，完全是异步和非阻塞的。新的事件循环执行模型可以使用少量线程进行垂直扩展。

该框架获取了反应式流以提供在反应式组件管道中传递**背压**的系统。背压是一个确保消费者不会被来自不同生产者的数据压倒的概念。

虽然 Java 8 没有内置对响应式编程的支持，但有许多框架提供对响应式编程的支持：

+   **Reactive Streams**：语言中立的尝试定义响应式 API

+   **Reactor**：由 Spring Pivotal 团队提供的 Reactive Streams 的 Java 实现

+   **Spring WebFlux**：基于响应式编程开发 Web 应用程序；提供类似于 Spring MVC 的编程模型

# 核心功能升级

作为 Java 8 引入的新功能的一部分，Spring Framework 5.0 的核心已经进行了修订，提供了以下一些关键功能：

+   Java 8 反射增强包括在 Spring Framework 5.0 中高效地访问方法参数的功能。

+   在 Spring Core 接口中提供对 Java 8 默认方法的选择性声明支持。

+   支持@Nullable 和@NotNull 注释，以明确标记可为空参数和返回值。这消除了运行时的 NullPointerExceptions 的原因，并使我们能够在编译时处理空值。

对于日志记录方面，Spring Framework 5.0 提供了 Commons Logging Bridge 模块的开箱即用支持，命名为 spring-jcl，而不是标准的 Commons Logging。此外，这个新版本将能够检测 Log4j 2.x，Simple Logging Facade for Java（SLF4J），JUL（java.util.logging）等，无需任何额外的修改。

它还通过为 getFile 方法提供 isFile 指示符，支持 Resource 抽象。

# Spring Web MVC 升级

Spring 5.0 完全支持 Spring 提供的 Filter 实现中的 Servlet 3.1 签名。它还为 Spring MVC 控制器方法中的 Servlet 4.0 PushBuilder 参数提供支持。

Spring 5.0 还通过 MediaTypeFactory 委托提供了对常见媒体类型的统一支持，包括使用 Java Activation Framework。

新的 ParsingPathMatcher 将作为 AntPathMatcher 的替代，具有更高效的解析和扩展语法。

Spring 5.0 还将提供对 ResponseStatusException 的支持，作为@ResponseStatus 的编程替代。

# Spring 的新功能性 Web 框架-WebFlux

为了支持响应式 HTTP 和 WebSocket 客户端，Spring Framework 5.0 提供了 spring-webflux 模块。Spring Framework 5.0 还为在服务器上运行的响应式 Web 应用程序提供了对 REST、HTML 和 WebSocket 风格交互的支持。

在 spring-webflux 中，服务器端有两种主要的编程模型：

+   支持@Controller 注释，包括其他 Spring MVC 注释

+   提供对 Java 8 Lambda 的函数式风格路由和处理支持

Spring spring-webflux 还提供了对 WebClient 的支持，它是响应式和非阻塞的，作为 RestTemplate 的替代。

# 模块化支持

模块化框架在 Java 平台上很受欢迎。从 Java 9 开始，Java 平台变得模块化，有助于消除封装中的缺陷。

有一些问题导致了模块化支持，如下所述：

+   Java 平台大小：在过去的几十年里，Java 不需要添加模块化支持。但是市场上有许多新的轻量级平台，如物联网（IoT）和 Node.js。因此，迫切需要减小 JDK 版本的大小，因为初始版本的 JDK 大小不到 10MB，而最近的版本需要超过 200MB。

+   ClassLoader 困难：当 Java ClassLoader 搜索类时，它将选择周围的类定义，并立即加载第一个可用的类。因此，如果在不同的 JAR 中有相同的类可用，那么 ClassLoader 无法指定要加载类的 JAR。

为了使 Java 应用程序模块化，Open System Gateway initiative (OSGi)是将模块化引入 Java 平台的倡议之一。在 OSGi 中，每个模块被表示为一个 bundle。每个 bundle 都有自己的生命周期，具有不同的状态，如已安装、已启动和已停止。

Jigsaw 项目是 Java 社区流程（JCP）的主要动力，旨在将模块化引入 Java。其主要目的是为 JDK 定义和实现模块化结构，并为 Java 应用程序定义模块系统。

# Kotlin 语言支持

Spring Framework 5.0 引入了静态类型的 JVM 语言支持**Kotlin 语言** ([`kotlinlang.org/`](https://kotlinlang.org/))，它使得代码简短、可读且表达力强。Kotlin 基本上是一种运行在 JVM 之上的面向对象的语言，也支持函数式编程风格。

有了 Kotlin 支持，我们可以深入了解函数式 Spring 编程，特别是对于函数式 Web 端点和 bean 注册。

在 Spring Framework 5.0 中，我们可以编写干净可读的 Kotlin 代码用于 Web 功能 API，如下所示：

```java
{
    ("/bank" and accept(TEXT_HTML)).nest {
        GET("/", bankHandler::findAllView)
        GET("/{customer}", bankHandler::findOneView)
    }
    ("/api/account" and accept(APPLICATION_JSON)).nest {
        GET("/", accountApiHandler::findAll)
        GET("/{id}", accountApiHandler::findOne)
    }
}
```

在 Spring 5.0 版本中，Kotlin 的空安全支持也提供了使用`@NonNull`、`@Nullable`、`@NonNullApi`和`@NonNullFields`注解的指示，来自`org.springframework.lang`包。

还有一些新添加的 Kotlin 扩展，基本上是为现有的 Spring API 添加了函数扩展。例如，来自`org.springframework.beans.factory`包的扩展`fun <T : Any> BeanFactory.getBean(): T`为`org.springframework.beans.factory.BeanFactory`添加了支持，可以通过指定 bean 类型作为 Kotlin 的 reified 类型参数来搜索 bean，而无需类参数：

```java
@Autowired
lateinit var beanFactory : BeanFactory

@PostConstruct
fun init() {
 val bankRepository = beanFactory.getBean<BankRepository>()

}
```

还可以在`org.springframework.ui`中找到另一个扩展，它提供了操作符重载支持，以向`model`接口添加类似数组的 getter 和 setter：

```java
model["customerType"] = "Premium"
```

# 改进的测试支持

在测试方面，Spring Framework 5.0 同样支持 JUnit Jupiter ([`junit.org/junit5/docs/current/user-guide/`](https://junit.org/junit5/docs/current/user-guide/))。它有助于在 JUnit 5 中编写测试和扩展。它还提供了一个测试引擎来运行基于 Jupiter 构建的测试，关于 Spring 的方面，还提供了一个编程和扩展模型。

Spring Framework 5.0 还支持 Spring `TestContext` Framework 中的并行测试执行。对于 Spring WebFlux，`spring-test`还包括对`WebTestClient`的支持，以整合对响应式编程模型的测试支持。

没有必要为测试场景运行服务器。通过使用新的`WebTestClient`，类似于`MockMvc`，`WebTestClient`可以直接绑定到 WebFlux 服务器基础设施，使用模拟请求和响应。

# 已删除或弃用的功能

在 Spring 5.0 中，一些包已经在 API 级别被删除或弃用。`spring-aspects`模块的`mock.staticmock`包不再可用。`BeanFactoryLocator`也不再可用，以及`bean.factory.access`包。`NativeJdbcExtractor`也不再可用，以及`jdbc.support.nativejdbc`包。`web.view.tiles2`、`orm.hibernate3`和`orm.hibernate4`包也被 Tiles 3 和 Hibernate 5 所取代。

Spring 5 中不再支持许多其他捆绑包，如 JasperReports、Portlet、Velocity、JDO、Guava、XMLBeans。如果您正在使用上述任何捆绑包，建议保持在 Spring Framework 4.3.x 上。

# 总结

在本章中，我们对 Spring Framework 的核心特性有了清晰的了解。我们还涵盖了不同类型的 Spring 模块。之后，我们了解了 Spring Framework 中不同类型的项目。我们还理解了 Spring IoC 容器的机制。在本章的最后，我们看了 Spring 5.0 中引入的新特性和增强功能。

在下一章中，我们将详细了解 DI 的概念。我们还将涵盖使用 DI 的不同类型的配置，包括性能评估。最后，我们将了解 DI 的陷阱。


# 第二章：Spring 最佳实践和 Bean 配置

在上一章中，我们了解了 Spring 框架如何实现**控制反转**（**IoC**）原则。Spring IoC 是实现对象依赖关系的松耦合的机制。Spring IoC 容器是将依赖注入到对象中并使其准备好供我们使用的程序。Spring IoC 也被称为依赖注入。在 Spring 中，您的应用程序的对象由 Spring IoC 容器管理，也被称为**bean**。Bean 是由 Spring IoC 容器实例化、组装和管理的对象。因此，Spring 容器负责在您的应用程序中创建 bean，并通过依赖注入协调这些对象之间的关系。但是，开发人员有责任告诉 Spring 要创建哪些 bean 以及如何配置它们。在传达 bean 的装配配置时，Spring 非常灵活，提供不同的配置方式。

在本章中，我们首先开始探索不同的 bean 装配配置。这包括使用 Java、XML 和注解进行配置，以及学习 bean 装配配置的不同最佳实践。我们还将了解不同配置的性能评估，以及依赖注入的缺陷。

本章将涵盖以下主题：

+   依赖注入配置

+   不同配置的性能评估

+   依赖注入的缺陷

# 依赖注入配置

在任何应用程序中，对象与其他对象协作执行一些有用的任务。在任何应用程序中，一个对象与另一个对象之间的关系会创建依赖关系，这种对象之间的依赖关系会在应用程序中创建紧耦合的编程。Spring 为我们提供了一种机制，将紧耦合的编程转换为松耦合的编程。这种机制称为**依赖注入**（**DI**）。DI 是一种描述如何创建松耦合类的概念或设计模式，其中对象以一种方式设计，它们从其他代码片段接收对象的实例，而不是在内部构造它们。这意味着对象在运行时获得它们的依赖关系，而不是在编译时。因此，通过 DI，我们可以获得一个解耦的结构，为我们提供了简化的测试、更大的可重用性和更好的可维护性。

在接下来的章节中，我们将学习不同类型的 DI 配置，您可以根据业务需求在应用程序的任何配置中使用这些配置。

# 依赖注入模式的类型

在 Spring 中，进行以下类型的 DI：

+   基于构造函数的依赖注入

+   基于 setter 的依赖注入

+   基于字段的依赖注入

我们将在接下来的章节中了解更多相关内容。

# 基于构造函数的依赖注入

**基于构造函数的依赖注入**是一种设计模式，用于解决依赖对象的依赖关系。在基于构造函数的依赖注入中，使用构造函数来注入依赖对象。当容器调用带有一定数量参数的构造函数时，就完成了这个过程。

让我们看一个基于构造函数的 DI 的例子。在以下代码中，我们展示了如何在`BankingService`类中使用构造函数来注入`CustomerService`对象：

```java
@Component
public class BankingService {

  private CustomerService customerService;

  // Constructor based Dependency Injection
  @Autowired
  public BankingService(CustomerService customerService) {
    this.customerService = customerService;
  }

  public void showCustomerAccountBalance() {
    customerService.showCustomerAccountBalance();
  }

}
```

以下是另一个依赖类文件`CustomerServiceImpl.java`的内容：

```java
public class CustomerServiceImpl implements CustomerService {

  @Override
  public void showCustomerAccountBalance() {
    System.out.println("This is call customer services");
  }
}

```

`CustomerService.java`接口的内容如下：

```java
public interface CustomerService {  
  public void showCustomerAccountBalance(); 
}
```

# 构造函数 DI 的优势

以下是在 Spring 应用程序中使用基于构造函数的 DI 的优势：

+   适用于必需的依赖关系。在基于构造函数的依赖注入中，您可以确保对象在构造时已经准备好供使用。

+   代码结构非常紧凑且易于理解。

+   当您需要一个不可变对象时，通过基于构造函数的依赖，您可以确保获得对象的不可变性。

# 构造函数 DI 的缺点

构造函数注入的唯一缺点是可能会导致对象之间的**循环依赖**。循环依赖意味着两个对象彼此依赖。为了解决这个问题，我们应该使用设置器注入而不是构造函数注入。

让我们看一种在 Spring 中不同类型的 DI，即基于设置器的注入。

# 设置器 DI

在基于构造函数的 DI 中，我们看到一个依赖对象通过构造函数参数注入。在基于设置器的 DI 中，依赖对象是由依赖类中的设置器方法提供的。通过在容器中调用`no-args`构造函数后，在 bean 上调用设置器方法来实现设置器 DI。

在下面的代码中，我们展示了如何在`BankingService`类中使用一个设置器方法来注入`CustomerService`对象：

```java
@Component
public class BankingService {

  private CustomerService customerService;  

  // Setter-based Dependency Injection
  @Autowired
  public void setCustomerService(CustomerService customerService) {
  this.customerService = customerService;
  }

  public void showCustomerAccountBalance() {
    customerService.showCustomerAccountBalance();
  }

}
```

# 设置器 DI 的优势

以下是在您的 Spring 应用程序中设置器 DI 的优势：

+   它比构造函数注入更可读。

+   这对于非强制性的依赖是有用的。

+   它解决了应用程序中的循环依赖问题。

+   它帮助我们只在需要时注入依赖关系。

+   可以重新注入依赖关系。这在基于构造函数的注入中是不可能的。

# 设置器 DI 的缺点

尽管基于设置器的 DI 优先级高于基于构造函数的 DI，但前者的缺点如下：

+   在设置器 DI 中，不能保证依赖关系会被注入。

+   可以使用设置器 DI 来覆盖另一个依赖关系。这可能会在 Spring 应用程序中引起安全问题。

# 基于字段的 DI

在前面的章节中，我们看到了如何在我们的应用程序中使用基于构造函数和基于设置器的依赖关系。在下面的示例中，我们将看到基于字段的 DI。实际上，基于字段的 DI 易于使用，并且与其他两种注入方法相比，代码更清晰；然而，它也有一些严重的折衷，通常应该避免使用。

让我们看一下基于字段的 DI 的以下示例。在下面的代码中，我们将看到如何在`BankingService`类中使用字段来注入`CustomerService`对象：

```java
@Component
public class BankingService {

  //Field based Dependency Injection
  @Autowired
  private CustomerService customerService;

  public void showCustomerAccountBalance() {
    customerService.showCustomerAccountBalance();
  }

}
```

正如我们讨论过的，这种类型的 DI 有利于消除基于设置器或构造函数的依赖的混乱代码，但它也有许多缺点，比如依赖关系对外部是不可见的。在基于构造函数和基于设置器的依赖关系中，类明确地使用`public`接口或设置器方法来暴露这些依赖关系。在基于字段的 DI 中，类本质上是在对外部世界隐藏依赖关系。另一个困难是字段注入不能用于为 final/不可变字段分配依赖关系，因为这些字段必须在类实例化时实例化。

一般来说，Spring 不鼓励使用基于字段的依赖。

以下是我们迄今为止学到的不同类型的 DI 的图表：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/bea0510f-e8d3-431c-b814-6f80cd876106.jpg)

# 构造函数与设置器注入

正如我们所看到的，Spring 支持三种 DI 方法；然而，Spring 不推荐使用基于字段的依赖。因此，基于构造函数和基于设置器的 DI 是在应用程序中注入 bean 的标准方式。构造函数或设置器方法的选择取决于您的应用程序要求。在这个表中，我们将看到构造函数和设置器注入的不同用例，以及一些最佳实践，这将帮助我们决定何时使用设置器注入而不是构造函数注入，反之亦然：

| **构造函数注入** | **设置器注入** |
| --- | --- |
| 依赖关系是强制性时的最佳选择。 | 依赖关系不是强制性时的合适选择。 |
| 构造函数注入使得 bean 类对象是不可变的。 | 设置器注入使得 bean 类对象是可变的。 |
| 构造函数注入无法覆盖 setter 注入的值。 | 当我们同时为同一属性使用构造函数和 setter 注入时，setter 注入会覆盖构造函数注入。 |
| 部分依赖在构造函数注入中是不可能的，因为我们必须在构造函数中传递所有参数，否则会出错。 | 部分依赖在 setter 注入中是可能的。假设我们有三个依赖，比如`int`，`string`和`long`，那么借助 setter 注入，我们可以只注入所需的依赖；其他依赖将被视为这些原始类型的默认值。 |
| 在对象之间创建循环依赖。 | 解决应用程序中的循环依赖问题。在循环依赖的情况下，最好使用 setter 而不是构造函数注入。 |

# 使用 Spring 配置 DI

在本节中，我们将学习不同类型的配置 DI 的过程。以下图表是配置过程在 Spring 中如何工作的高级视图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/e100f5df-acc2-4ed3-aed8-c99f18d498a0.jpg)

根据前面的图表，Spring 容器负责在您的应用程序中创建 bean，并通过 DI 模式建立这些 bean 之间的关系；但是，正如我们之前讨论的，开发人员有责任通过元数据告诉 Spring 容器如何创建 bean 以及如何将它们连接在一起。

以下是配置应用程序元数据的三种技术：

+   基于 XML 的配置：显式配置

+   基于 Java 的配置：显式配置

+   基于注解的配置：隐式配置

在 Spring 框架中，有前述三种配置机制可用，但您必须使用其中一种配置过程来连接您的 bean。在下一节中，我们将详细了解每种配置技术的示例，并看到在每种情况或条件下哪种技术更适合；但是，您可以使用最适合您的任何技术或方法。

现在让我们详细了解基于 XML 的配置中的 DI 模式。

# 基于 XML 的配置

**基于 XML 的配置**自 Spring 开始以来一直是主要的配置技术。在本节中，我们将看到与 DI 模式中讨论的相同示例，并看到如何通过基于 XML 的配置在`BankingService`类中注入`CustomerService`对象。

对于基于 XML 的配置，我们需要创建一个带有`<beans>`元素的`applicationContext.xml`文件。Spring 容器必须能够管理应用程序中的一个或多个 bean。使用顶级`<beans>`元素内部的`<bean>`元素来描述 bean。

以下是`applicationContext.xml`文件的内容：

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans 

  xsi:schemaLocation="http://www.springframework.org/schema/beans
  http://www.springframework.org/schema/beans/spring-beans.xsd">

    <!-- Bean Configuration definition describe here -->
    <bean class=""/>

</beans> 
```

前面的 XML 文件是基于 XML 的配置元数据的基本结构，我们需要在其中定义我们的 bean 配置。正如我们之前学到的，我们的 bean 配置模式可能是基于构造函数或基于 setter 的，具体取决于应用程序的要求。现在，我们将逐个看看如何使用这两种设计模式配置 bean。

以下是基于 XML 的构造函数 DI 的示例：

```java
<!-- CustomerServiceImpl Bean -->
<bean id="customerService"    class="com.packt.springhighperformance.ch2.bankingapp.service.Impl.CustomerServiceImpl" />

<!-- Inject customerService via constructor argument -->
<bean id="bankingService"
class="com.packt.springhighperformance.ch2.bankingapp.model.BankingService">
<constructor-arg ref="customerService" />
</bean>
```

在前面的例子中，我们使用构造函数 DI 模式在`BankingServices`类中注入了`CustomerService`对象。`</constructor-arg>`元素的`ref`属性用于传递`CustomerServiceImpl`对象的引用。

以下是基于 XML 的 setter 注入 DI 的示例：

```java
<!-- CustomerServiceImpl Bean -->
<bean id="customerService"    class="com.packt.springhighperformance.ch2.bankingapp.service.Impl.CustomerServiceImpl" />

<!-- Inject customerService via setter method -->
<bean id="bankingService" class="com.packt.springhighperformance.ch2.bankingapp.model.BankingService"> 
<property name="customerService" ref="customerService"></property></bean>
```

`</property>`元素的`ref`属性用于将`CustomerServiceImpl`对象的引用传递给 setter 方法。

以下是`MainApp.java`文件的内容：

```java
public class MainApp {

public static void main(String[] args) {
    @SuppressWarnings("resource")
    ApplicationContext context = new               
    ClassPathXmlApplicationContext("applicationContext.xml");
    BankingService bankingService = 
    context.getBean("bankingService",                            
    BankingService.class);
    bankingService.showCustomerAccountBalance(); 
  }
}
```

# 基于 Java 的配置

在上一节中，我们看到了如何使用基于 XML 的配置来配置 bean。在本节中，我们将看到基于 Java 的配置。与 XML 相同，基于 Java 的配置也是显式地注入依赖关系。以下示例定义了 Spring bean 及其依赖关系：

```java
@Configuration
public class AppConfig { 

  @Bean
  public CustomerService showCustomerAccountBalance() {
    return new CustomerService();
  }

  @Bean
  public BankingService getBankingService() {
    return new BankingService();
  }  
}
```

在基于 Java 的配置中，我们必须使用`@Configuration`对类进行注解，并且可以使用`@Bean`注解来声明 bean。前面的基于 Java 的配置示例等同于基于 XML 的配置，如下所示：

```java
<beans>
<bean id="customerService"   class="com.packt.springhighperformance.ch2.bankingapp.service.Impl.CustomerServiceImpl" /> 

<bean id="bankingService"
class="com.packt.springhighperformance.ch2.bankingapp.model.BankingService/">
</beans>
```

之前的`AppConfig`类使用了`@Configuration`注解，描述了它是应用程序的配置类，包含有关 bean 定义的详细信息。该方法使用`@Bean`注解进行注解，以描述它负责实例化、配置和初始化一个新的 bean，由 Spring IoC 容器进行管理。在 Spring 容器中，每个 bean 都有一个唯一的 ID。无论哪个方法使用了`@Bean`注解，那么默认情况下该方法名称将是 bean 的 ID；但是，您也可以使用`@Bean`注解的`name`属性来覆盖该默认行为，如下所示：

```java
@Bean(name="myBean")
  public CustomerService showCustomerAccountBalance() {
    return new CustomerService();
  }
```

Spring 应用程序上下文将加载`AppConfig`文件并为应用程序创建 bean。

以下是`MainApp.java`文件：

```java
public class MainApp {

  public static void main(String[] args) {
    AnnotationConfigApplicationContext context = new                                                 
    AnnotationConfigApplicationContext(AppConfig.class);
    BankingService bankingService = 
    context.getBean(BankingService.class);
    bankingService.showCustomerAccountBalance();
    context.close();     
  }
}
```

# 基于注解的配置

在上一节中，我们看到了两种 bean 配置技术，即基于 Java 和基于 XML 的。这两种技术都是显式地注入依赖关系。在基于 Java 的配置中，我们在`AppConfig` Java 文件中使用`@Bean`注解的方法，而在基于 XML 的配置中，我们在 XML 配置文件中使用`<bean>`元素标签。**基于注解的配置**是另一种创建 bean 的方式，我们可以通过在相关类、方法或字段声明上使用注解，将 bean 配置移到组件类本身。在这里，我们将看看如何通过注解配置 bean，以及 Spring Framework 中提供的不同注解。

Spring 中默认情况下关闭了基于注解的配置，因此首先，您必须通过在 Spring XML 文件中输入`<context:annotation-config/>`元素来打开它。添加后，您就可以在代码中使用注解了。

在`applicationContext.xml`中需要进行的更改（因为我们在之前的部分中使用了它）如下所示：

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans 

xsi:schemaLocation="http://www.springframework.org/schema/beans
http://www.springframework.org/schema/beans/spring-beans.xsd
http://www.springframework.org/schema/context
http://www.springframework.org/schema/context/spring-context.xsd">

<!-- Enable Annotation based configuration -->
<context:annotation-config />
<context:component-scan base-package="com.packt.springhighperformance.ch2.bankingapp.model"/><context:component-scan base- package="com.packt.springhighperformance.ch2.bankingapp.service"/>

<!-- Bean Configuration definition describe here -->
<bean class=""/>

</beans>
```

基于 XML 的配置将覆盖注解，因为基于 XML 的配置将在注解之后进行注入。

之前的基于 XML 的配置显示，一旦配置了`<context:annotation-config/>`元素，就表示开始对代码进行注解。Spring 应该自动扫描在`<context:component-scan base-package=".." />`中定义的包，并根据模式识别 bean 并进行连线。让我们了解一些重要的注解以及它们的工作原理。

# @Autowired 注解

`@Autowired`注解隐式地注入对象依赖。我们可以在基于构造函数、setter 和字段的依赖模式上使用`@Autowired`注解。`@Autowired`注解表示应该为此 bean 执行自动装配。

让我们看一个在基于构造函数的依赖注入上使用`@Autowired`注解的例子：

```java
public class BankingService {  

  private CustomerService customerService;

  @Autowired
  public BankingService(CustomerService customerService) {
    this.customerService = customerService;
  }
  ......
}
```

在前面的例子中，我们有一个`BankingService`，它依赖于`CustomerService`。它的构造函数使用`@Autowired`进行注解，表示 Spring 使用带注解的构造函数实例化`BankingService` bean，并将`CustomerService` bean 作为`BankingService` bean 的依赖项。

自 Spring 4.3 以来，对于只有一个构造函数的类，`@Autowired`注解变得可选。在前面的例子中，如果您跳过了`@Autowired`注解，Spring 仍然会注入`CustomerService`类的实例。

让我们看一个在基于 setter 的依赖注入上使用`@Autowired`注解的例子：

```java
public class BankingService {

  private CustomerService customerService; 

  @Autowired
  public void setCustomerService(CustomerService customerService) {
```

```java
    this.customerService = customerService;
  }
  ......
}
```

在前面的例子中，我们看到 setter 方法`setCustomerService`被`@Autowired`注解标记。在这里，注解通过类型解析依赖关系。`@Autowire`注解可以用于任何传统的 setter 方法。

让我们看一个在基于字段的依赖上使用`@Autowired`注解的例子：

```java
public class BankingService {

  @Autowired
  private CustomerService customerService; 

}
```

根据前面的例子，我们可以看到`@Autowire`注解可以添加在公共和私有属性上。Spring 在属性上添加时使用反射 API 来注入依赖项，这就是私有属性也可以被注解的原因。

# @Autowired with required = false

默认情况下，`@Autowired`注解意味着依赖是必需的。这意味着在未解析依赖项时将抛出异常。您可以使用`@Autowired`的`(required=false)`选项覆盖默认行为。让我们看下面的代码：

```java
public class BankingService {

  private CustomerService customerService; 

  @Autowired (required=false)
  public void setCustomerService(CustomerService customerService) {
    this.customerService = customerService;
  }
  ......
}
```

在前面的代码中，如果我们将`required`值设置为`false`，那么在 bean 连线时，如果依赖项未解析，Spring 将保留 bean 未连接。根据 Spring 的最佳实践，我们应该避免将`required`设置为`false`，除非绝对需要。

# @Primary 注解

在 Spring 框架中，默认情况下，DI 是按类型完成的，这意味着当存在多个具有相同类型的依赖项时，将抛出`NoUniqueBeanDefinitionException`异常。这表明 Spring 容器无法选择要注入的 bean，因为有多个合格的候选项。在这种情况下，我们可以使用`@Primary`注解并控制选择过程。让我们看下面的代码：

```java
public interface CustomerService {  
  public void customerService(); 
}

@Component
public class AccountService implements CustomerService {
      ....
}
@Component
@Primary
public class BankingService implements CustomerService { 
     ....
}
```

在前面的例子中，有两个客户服务可用：`BankingService`和`AccountService`。由于`@Primary`注解，组件只能使用`BankingService`来连线`CustomerService`的依赖项。

# @Qualifier 注解

使用`@Primary`处理多个自动装配候选项在只能确定一个主要候选项的情况下更有效。`@Qualifier`注解在选择过程中给予更多控制。它允许您给出与特定 bean 类型相关联的引用。该引用可用于限定需要自动装配的依赖项。让我们看下面的代码：

```java
@Component
public class AccountService implements CustomerService {

}
@Component
@Qualifier("BankingService")
public class BankingService implements CustomerService { 

}

@Component
public class SomeService {

  private CustomerService customerService;

  @Autowired
  @Qualifier("bankingservice")
  public BankingService(CustomerService customerService) {
    this.customerService = customerService;
  }
  .....
}
```

在前面的例子中，有两个客户服务可用：`BankingService`和`AccountService`；但是，由于在`SomeService`类中使用了`@Qualifier("bankingservice")`，`BankingService`将被选中进行自动连线。

# 使用原型注解自动检测 bean

在前一节中，我们了解了`@Autowired`注解只处理连线。您仍然必须定义 bean 本身，以便容器知道它们并为您注入它们。Spring 框架为我们提供了一些特殊的注解。这些注解用于在应用程序上下文中自动创建 Spring bean。因此，无需使用基于 XML 或基于 Java 的配置显式配置 bean。

以下是 Spring 中的原型注解：

+   @Component

+   @Service

+   @Repository

+   @Controller

让我们看一下以下`CustomerService`实现类。它的实现被注解为`@Component`。请参考以下代码：

```java
@Component
public class CustomerServiceImpl implements CustomerService {

  @Override
  public void customerService() {
    System.out.println("This is call customer services");

  }

}
```

在前面的代码中，`CustomerServiceImpl`类被`@Component`注解标记。这意味着被标记为`@Component`注解的类被视为 bean，并且 Spring 的组件扫描机制扫描该类，创建该类的 bean，并将其拉入应用程序上下文。因此，无需显式配置该类作为 bean，因为 bean 是使用 XML 或 Java 自动创建的。Spring 自动创建`CustomerServiceImpl`类的 bean，因为它被`@Component`注解标记。

在 Spring 中，`@Service`、`@Repository`和`@Controller`是`@Component`注解的元注解。从技术上讲，所有注解都是相同的，并提供相同的结果，例如在 Spring 上下文中创建一个 bean；但是我们应该在应用程序的不同层次使用更具体的注解，因为它更好地指定了意图，并且将来可能会依赖于其他行为。

以下图表描述了具有适当层的原型注解：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/0e80ec68-52cd-4858-ab10-860971c21d6e.jpg)

根据前面的例子，`@Component`足以创建`CustomerService`的 bean。但是`CustomerService`是一个服务层类，因此根据 bean 配置最佳实践，我们应该使用`@Services`而不是通用的`@Component`注解。让我们看一下相同类的以下代码，该类使用了`@Service`注解：

```java
@Service
public class CustomerServiceImpl implements CustomerService {

  @Override
  public void customerService() {
    System.out.println("This is call customer services");
  }

}
```

让我们看一个`@Repository`注解的另一个例子：

```java
@Repository
public class JdbcCustomerRepository implements CustomerRepository {

}
```

在前面的例子中，该类被注解为`@Repository`，因为`CustomerRepository`接口在应用程序的**数据访问对象**（**DAO**）层中起作用。根据 bean 配置最佳实践，我们使用了`@Repository`注解而不是`@Component`注解。

在现实场景中，您可能会很少遇到需要使用`@Component`注解的情况。大多数情况下，您将使用`@Controller`、`@Service`和`@Repository`注解。当您的类不属于服务、控制器、DAO 三类时，应该使用`@Component`。

# @ComponentScan 注解

Spring 需要知道哪些包包含 Spring bean，否则，您将需要逐个注册每个 bean。这就是`@ComponentScan`的用途。在 Spring 中，默认情况下不启用组件扫描。我们需要使用`@ComponentScan`注解来启用它。此注解与`@Configuration`注解一起使用，以便 Spring 知道要扫描的包，并从中创建 bean。让我们看一个简单的`@ComponentScan`的例子：

```java
@Configuration
@ComponentScan(basePackages="com.packt.springhighperformance.ch2.bankingapp.model")
public class AppConfig {

}
```

在`@ComponentScan`注解中，如果未定义`basePackages`属性，则扫描将从声明此注解的类的包中进行。在前面的例子中，Spring 将扫描`com.packt.springhighperformance.ch2.bankingapp.model`的所有类，以及该包的子包。`basePackages`属性可以接受一个字符串数组，这意味着我们可以定义多个基本包来扫描应用程序中的组件类。让我们看一个如何在`basePackage`属性中声明多个包的例子：

```java
@Configuration
@ComponentScan(basePackages={"com.packt.springhighperformance.ch2.bankingapp.model","com.packt.springhighperformance.ch2.bankingapp.service"})
public class AppConfig {

}
```

# @Lazy 注解

默认情况下，所有自动装配的依赖项都会在启动时创建和初始化，这意味着 Spring IoC 容器会在应用程序启动时创建所有 bean；但是，我们可以使用`@Lazy`注解来控制这种预初始化的 bean。

`@Lazy`注解可以用于任何直接或间接使用`@Component`注解的类，或者用于使用`@Bean`注解的方法。当我们使用`@Lazy`注解时，这意味着只有在首次请求时才会创建和初始化 bean。

我们知道注解需要的代码较少，因为我们不需要显式编写代码来注入依赖项。它还有助于减少开发时间。尽管注解提供了许多优点，但它也有缺点。

注解的缺点如下：

+   比显式连线文档少

+   如果程序中有很多依赖项，那么使用 bean 的`autowire`属性来查找它是很困难的。

+   注解使调试过程变得困难

+   在存在歧义的情况下可能会产生意外结果

+   注解可以被显式配置（如 Java 或 XML）覆盖

# Spring bean 作用域

在前一节中，我们学习了各种 DI 模式，以及如何在 Spring 容器中创建 bean。我们还学习了各种 DI 配置，如 XML、Java 和注解。在本节中，我们将更详细地了解 Spring 容器中可用的 bean 生命周期和范围。Spring 容器允许我们在配置级别控制 bean。这是一种非常灵活的方式，可以在配置级别定义对象范围，而不是在 Java 类级别。在 Spring 中，通过定义`scope`属性来控制 bean 的行为，该属性定义了要创建和返回的对象类型。当您描述`<bean>`时，可以为该 bean 定义`scope`。bean `scope`描述了 bean 在使用的上下文中的生命周期和可见性。在本节中，我们将看到 Spring Framework 中不同类型的 bean `scope`。

以下是在基于 XML 的配置中定义 bean `scope`的示例：

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans 

xsi:schemaLocation="http://www.springframework.org/schema/beans
http://www.springframework.org/schema/beans/spring-beans.xsd">

<!-- Here scope is not defined, it assume default value 'singleton'.
    It creates only one instance per spring IOC. -->
<bean id="customerService" class="com.packt.springhighperformance.ch2.bankingapp.service.Impl.CustomerServiceImpl" />

<!-- Here scope is prototype, it creates and returns bankingService object for  every call-->
<bean id="bankingService"   class="com.packt.springhighperformance.ch2.bankingapp.model.BankingService" scope="prototype">

<bean id="accountService" class="com.packt.springhighperformance.ch2.bankingapp.model.AccountService" scope="singleton">

</beans>
```

以下是使用`@Scope`注解定义 bean `scope`的示例：

```java
@Configuration
public class AppConfig { 

  @Bean
  @Scope("singleton")
  public CustomerService showCustomerAccountBalance() {
    return new CustomerServiceImpl();

  }
}
```

我们也可以以以下方式使用常量而不是字符串值：

```java
@Scope(value = ConfigurableBeanFactory.SCOPE_SINGLETON)
@Scope(value = ConfigurableBeanFactory.SCOPE_PROTOTYPE)
```

以下是 Spring Framework 中可用的 bean 范围：

+   `singleton` bean `scope`：正如我们在之前的 XML 配置的 bean 示例中看到的，如果在配置中未定义`scope`，那么 Spring 容器将`scope`视为`singleton`。Spring IoC 容器仅创建对象的一个单一实例，即使有多个对 bean 的引用。Spring 将所有`singleton` bean 实例存储在缓存中，对该命名 bean 的所有后续请求都返回缓存对象。需要理解的是，Spring bean `singleton` `scope`与我们在 Java 中使用的典型`singleton`设计模式有些不同。在 Spring `singleton` `scope`中，每个 Spring 容器创建一个 bean 对象，这意味着如果单个 JVM 中有多个 Spring 容器，则将创建该 bean 的多个实例。

+   `prototype` bean `scope`：当`scope`设置为`prototype`时，Spring IoC 容器在每次请求 bean 时都会创建对象的新 bean 实例。通常使用原型作用域的 bean 用于有状态的 bean。

通常，对于所有有状态的 bean 使用`prototype` `scope`，对于无状态的 bean 使用`singleton` `scope`。

+   `request` bean `scope`：`request` bean `scope`仅在 Web 应用程序上下文中可用。`request` `scope`为每个 HTTP 请求创建一个 bean 实例。一旦请求处理完成，bean 就会被丢弃。

+   `session` bean `scope`：`session` bean `scope`仅在 Web 应用程序上下文中可用。`session` `scope`为每个 HTTP 会话创建一个 bean 实例。

+   `application` bean `scope`：`application` bean `scope`仅在 Web 应用程序上下文中可用。`application` `scope`为每个 Web 应用程序创建一个 bean 实例。

# 使用不同配置进行性能评估

在本节中，我们将学习不同类型的 bean 配置如何影响应用程序性能，还将看到 bean 配置的最佳实践。

让我们看看`@ComponentScan`注解配置如何影响 Spring 应用程序的启动时间：

```java
@ComponentScan (( {{ "org", "com" }} ))
```

根据前面的配置，Spring 将扫描`com`和`org`的所有包，因此应用程序的启动时间将增加。因此，我们应该只扫描那些具有注释类的包，因为未注释的类将花费时间进行扫描。我们应该只使用一个`@ComponentScan`，并列出所有包，如下所示：

```java
@ComponentScan(basePackages={"com.packt.springhighperformance.ch2.bankingapp.model","com.packt.springhighperformance.ch2.bankingapp.service"})
```

前面的配置被认为是定义`@ComponentScan`注解的最佳实践。我们应该指定哪些包作为`basePackage`属性具有注释类。这将减少应用程序的启动时间。

# 延迟加载与预加载

**延迟加载**确保在请求时动态加载 bean，而**预加载**确保在使用之前加载 bean。Spring IoC 容器默认使用预加载。因此，在启动时加载所有类，即使它们没有被使用，也不是一个明智的决定，因为一些 Java 实例会消耗大量资源。我们应该根据应用程序的需求使用所需的方法。

如果我们需要尽可能快地加载我们的应用程序，那么选择延迟加载。如果我们需要尽可能快地运行我们的应用程序并更快地响应客户端请求，那么选择预加载。

# 单例与原型 bean

在 Spring 中，默认情况下，所有定义的 bean 都是`singleton`；但是，我们可以更改默认行为并使我们的 bean 成为`prototype`。当 bean 的`scope`设置为`prototype`时，Spring IoC 容器在每次请求 bean 时创建一个新的 bean 实例。原型 bean 在创建时会对性能造成影响，因此当一个`prototype` bean 使用资源（如网络和数据库连接）时，应完全避免；或者谨慎设计操作。

# Spring bean 配置最佳实践

在本节中，我们将看到 Spring 配置 bean 的一些最佳实践：

+   使用 ID 作为 bean 标识符：

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans 

xsi:schemaLocation="http://www.springframework.org/schema/beans
http://www.springframework.org/schema/beans/spring-beans.xsd">

    <!-- Bean Configuration definition describe here -->
    <bean id="xxx" name="xxx" class=""/>

</beans>
```

在前面的例子中，我们使用`id`或`name`来标识 bean。我们应该使用`id`来选择 bean 而不是`name`。通常，它既不增加可读性也不提高性能，但这只是一个行业标准实践，我们需要遵循。

+   在构造函数参数匹配时，优先使用`type`而不是`index`。带有`index`属性的构造函数参数如下所示：

```java
<constructor-arg index="0" value="abc"/>
<constructor-arg index="1" value="100"/>
```

+   构造函数参数带有`type`属性，如下所示：

```java
<constructor-arg type="java.lang.String"
value="abc"/>
<constructor-arg type="int" value="100"/>
```

根据前面的例子，我们可以使用`index`或`type`作为构造函数参数。在构造函数参数中最好使用`type`属性而不是`index`，因为它更易读且更少出错。但有时，基于类型的参数可能会在构造函数有多个相同类型的参数时创建歧义问题。在这种情况下，我们需要使用`index`或基于名称的参数。

+   在开发阶段使用依赖检查：在 bean 定义中，我们应该使用`dependency-check`属性。它确保容器执行显式的依赖验证。当一个 bean 的所有或部分属性必须显式设置或通过自动装配时，它是有用的。

+   不要在 Spring 模式引用中指定版本号：在 Spring 配置文件中，我们指定不同 Spring 模块的模式引用。在模式引用中，我们提到 XML 命名空间及其版本号。在配置文件中指定版本号不是强制性的，因此您可以跳过它。事实上，您应该始终跳过它。将其视为一种最佳实践。Spring 会自动从项目依赖项（`jars`）中选择最高版本。典型的 Spring 配置文件如下所示：

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans 

xsi:schemaLocation="http://www.springframework.org/schema/beans
http://www.springframework.org/schema/beans/spring-beans-3.0.xsd">

    <!-- Bean Configuration definition describe here -->
    <bean class=""/>

</beans>
```

根据最佳实践，可以这样编写：

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans 

xsi:schemaLocation="http://www.springframework.org/schema/beans
http://www.springframework.org/schema/beans/spring-beans.xsd">

    <!-- Bean Configuration definition describe here -->
    <bean class=""/>

</beans>
```

为每个配置文件添加一个头部注释；最好添加一个描述配置文件中定义的 bean 的配置文件头部。`description`标签的代码如下：

```java
<beans>
<description>
This file defines customer service
related beans and it depends on
accountServices.xml, which provides
service bean templates...
</description>
...
</beans>
```

`description`标签的优点是一些工具可以从这个标签中获取描述，以帮助您在其他地方使用。

# DI 陷阱

众所周知，在 Spring 应用程序中有三种 DI 模式：构造函数、setter 和基于字段。每种类型都有不同的优缺点。只有基于字段的 DI 是一种错误的方法，甚至 Spring 也不推荐使用。

以下是基于字段的注入的示例：

```java
@Autowired
private ABean aBean;
```

根据 Spring bean 最佳实践，我们不应该在 Spring 应用程序中使用基于字段的依赖。主要原因是没有 Spring 上下文无法进行测试。由于我们无法从外部提供依赖，因此无法独立实例化对象。在我看来，这是基于字段的注入唯一的问题。

正如我们在前面的部分中学到的，基于构造函数的依赖更适合于必填字段，并且我们可以确保对象的不可变性；然而，基于构造函数的依赖的主要缺点是它在应用程序中创建循环依赖，并且根据 Spring 文档，*通常建议不要依赖 bean 之间的循环依赖*。因此，现在我们有类似的问题，*为什么不依赖循环依赖？*和*如果我们的应用程序中有循环依赖会发生什么？*。因此，对这些问题的答案是它可能会产生两个重大且不幸的潜在问题。让我们讨论一下。

# 第一个潜在问题

当您调用`ListableBeanFactory.getBeansOfType()`方法时，您无法确定将返回哪些 bean。让我们看一下`DefaultListableBeanFactory.java`类中`getBeansOfType()`方法的代码：

```java
@Override
@SuppressWarnings("unchecked")
public <T> Map<String, T> getBeansOfType(@Nullable Class<T> type, boolean includeNonSingletons, boolean allowEagerInit)
      throws BeansException {

      ......

      if (exBeanName != null && isCurrentlyInCreation(exBeanName)) {
        if (this.logger.isDebugEnabled()) {
          this.logger.debug("Ignoring match to currently created bean 
          '" + 
          exBeanName + "': " +
          ex.getMessage());
        }
        onSuppressedException(ex);
        // Ignore: indicates a circular reference when auto wiring 
        constructors.
        // We want to find matches other than the currently created 
        bean itself.
        continue;
      }

      ......

}
```

在上面的代码中，您可以看到`getBeansOfType()`方法在创建中默默地跳过 bean，并且只返回那些已经存在的。因此，当 bean 之间存在循环依赖时，在容器启动期间不建议使用`getBeansOfType()`方法。这是因为，根据上面的代码，如果您没有使用`DEBUG`或`TRACE`日志级别，那么您的日志中将没有任何信息表明 Spring 跳过了正在创建的特定 bean。

让我们看看前面的潜在问题以及以下示例。根据以下图表，我们有三个 bean，`Account`、`Customer`和`Bank`，它们之间存在循环依赖：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/b0560f4b-859f-43c4-9123-049775d2d115.jpg)

根据前面的图表，以下是`Account`、`Customer`和`Bank`类：

```java
@Component
public class Account {

  private static final Logger LOGGER = Logger.getLogger(Account.class);

  static {
    LOGGER.info("Account | Class loaded");
  }

  @Autowired
  public Account(ListableBeanFactory beanFactory) {
    LOGGER.info("Account | Constructor");
    LOGGER.info("Constructor (Customer?): {}" + 
    beanFactory.getBeansOfType(Customer.class).keySet());
    LOGGER.info("Constructor (Bank?): {}" + 
    beanFactory.getBeansOfType(Bank.class).keySet());
  }

}

@Component
public class Customer {

  private static final Logger LOGGER = Logger.getLogger(Customer.class);

  static {
    LOGGER.info("Customer | Class loaded");
  }

  @Autowired
  public Customer(ListableBeanFactory beanFactory) {
    LOGGER.info("Customer | Constructor");
    LOGGER.info("Account (Account?): {}" + 
    beanFactory.getBeansOfType(Account.class).keySet());
    LOGGER.info("Constructor (Bank?): {}" + 
    beanFactory.getBeansOfType(Bank.class).keySet());
  }

}

@Component
public class Bank {

  private static final Logger LOGGER = Logger.getLogger(Bank.class);

  static {
    LOGGER.info("Bank | Class loaded");
  }

  public Bank() {
    LOGGER.info("Bank | Constructor");
  }

}
```

以下是`Main`类：

```java
public class MainApp {

  public static void main(String[] args) {
    AnnotationConfigApplicationContext context = new 
    AnnotationConfigApplicationContext(AppConfig.class);
    Account account = context.getBean(Account.class);
    context.close();
  }
}
```

以下是日志，我们可以展示 Spring 如何内部加载 bean 并解析类：

```java
Account | Class loaded
Account | Constructor
Customer | Class loaded
Customer | Constructor
Account (Account?): {}[]
Bank | Class loaded
Bank | Constructor
Constructor (Bank?): {}[bank]
Constructor (Customer?): {}[customer]
Constructor (Bank?): {}[bank]
```

Spring Framework 首先加载`Account`并尝试实例化一个 bean；然而，在运行`getBeansOfType(Customer.class)`时，它发现了`Customer`，因此继续加载和实例化那个。在`Customer`内部，我们可以立即发现问题：当`Customer`要求`beanFactory.getBeansOfType(Account.class)`时，它得不到结果(`[]`)。Spring 会默默地忽略`Account`，因为它当前正在创建。您可以在这里看到，在加载`Bank`之后，一切都如预期那样。

现在我们可以理解，在有循环依赖时，我们无法预测`getBeansOfType()`方法的输出。然而，我们可以通过正确使用 DI 来避免它。在循环依赖中，`getBeansOfType()`根据因素给出不同的结果，我们对此没有任何控制。

# 第二个潜在问题（带 AOP）

我们将在下一章中详细学习 AOP。现在，我们不会详细介绍这个潜在问题。我只是想让你明白，如果你在一个 bean 上有`Aspect`，那么请确保 bean 之间没有循环依赖；否则，Spring 将创建该 bean 的两个实例，一个没有`Aspect`，另一个有适当的方面，而不通知您。

# 总结

在本章中，我们学习了 DI，这是 Spring Framework 的关键特性。DI 帮助我们使我们的代码松散耦合和可测试。我们学习了各种 DI 模式，包括基于构造函数、setter 和字段的模式。根据我们的需求，我们可以在我们的应用程序中使用任何 DI 模式，因为每种类型都有其自己的优缺点。

我们还学习了如何显式和隐式地配置 DI。我们可以使用基于 XML 和基于 Java 的配置显式地注入依赖关系。注解用于隐式地注入依赖关系。Spring 为我们提供了一种特殊类型的注解，称为**原型注解**。Spring 将自动注册用原型注解注释的类。这使得该类可以在其他类中进行 DI，并且对于构建我们的应用程序至关重要。

在下一章中，我们将看一下 Spring AOP 模块。AOP 是一个强大的编程模型，可以帮助我们实现可重用的代码。


# 第三章：调整面向切面编程

在上一章中，我们深入研究了 Spring 的一个关键特性：依赖注入（IoC 容器）。DI 是一种企业设计模式，使对象与其所需的依赖关系解耦。我们了解了 Spring 的 bean 装配配置和实现最佳实践以实现最佳结果。

在继续了解 Spring 的核心特性的同时，在本章中，我们将讨论**面向切面编程**（**AOP**）。我们已经了解到 DI 促进了编程到接口和应用对象的解耦，而 AOP 有助于实现业务逻辑和横切关注点的解耦。**横切关注点**是应用程序部分或整个应用程序适用的关注点，例如安全、日志记录和缓存，在几乎每个模块中都需要。AOP 和 AspectJ 有助于实现这些横切关注点。在本章中，我们将讨论以下主题：

+   AOP 概念

+   AOP 代理

+   Spring AOP 方法进行性能分析

+   AOP 与 AspectJ 比较

+   AOP 最佳编程实践

# AOP 概念

在本节中，我们将看看如果只使用**面向对象编程**（**OOP**）范例，我们将面临哪些问题。然后我们将了解 AOP 如何解决这些问题。我们将深入了解 AOP 的概念和实现 AOP 概念的方法。

# OOP 的局限性

借助 OOP 的基本原理和设计模式，应用程序开发被划分为功能组。OOP 协议使许多事情变得简单和有用，例如引入接口，我们可以实现松耦合设计，封装，我们可以隐藏对象数据，继承-通过类扩展功能，我们可以重用工作。

随着系统的增长，OOP 的这些优势也增加了复杂性。随着复杂性的增加，维护成本和失败的机会也增加。为了解决这个问题，将功能模块化为更简单和更易管理的模块有助于减少复杂性。

为了模块化系统，我们开始遵循将应用程序划分为不同逻辑层的做法，例如表示层、服务层和数据层。然而，即使将功能划分为不同层，仍然有一些功能在所有层中都是必需的，例如安全、日志记录、缓存和性能监控。这些功能被称为**横切关注点**。

如果我们使用继承来实现这些横切关注点，将违反 SOLID 原则的单一责任，并增加对象层次结构。如果我们使用组合来实现它们，将会更加复杂。因此，使用 OOP 实现横切关注点会导致两个问题：

+   代码交织

+   代码分散

让我们更深入地讨论这些问题。

# 代码交织

**代码交织**意味着混合横切关注点和业务逻辑，从而导致紧耦合。让我们看下面的图表来理解代码交织：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/67377d05-09ec-425d-840a-a338a3cd835e.jpg)

代码交织

前面的图表说明了我们在服务实现中将事务和安全代码与业务逻辑混合在一起。通过这样的实现，代码的可重用性降低，维护性下降，并且违反了单一责任原则。

# 代码分散

代码分散意味着横切关注点在应用程序的所有模块中都是重复的。让我们看下面的例子来理解代码分散：

```java
public class TransferServiceImpl implements TransferService {
  public void transfer(Account source, Account dest, Double amount) {
    //permission check
    if (!hasPermission(user) {
      throw new AuthorizationException();
    }
  }
}

public class AccountServiceImpl implements AccountService {
  public void withdraw(Account userAccount, Double amount) {
    //Permission check
    if (!hasPermission(user) {
      throw new AuthorizationException();
    }
}
```

正如我们在前面的代码示例中看到的，权限检查（安全性）是我们的横切关注点，在所有服务中都是重复的。

这些代码交织和代码分散的问题通过 AOP 得到解决，但是如何呢？我们很快就会看到。

# AOP-问题解决者

我们已经在前面的部分中看到，使用 OOP 会导致代码交织和分散。使用 AOP，我们可以实现以下目标/好处：

+   模块化横切关注

+   模块解耦

+   消除模块依赖的横切关注

Spring AOP 允许我们将横切关注逻辑与业务逻辑分开，这样我们就可以专注于应用的主要逻辑。为了帮助我们进行这种分离，Spring 提供了`Aspects`，这是一个普通的类，我们可以在其中实现我们的横切关注逻辑。Spring 提供了将这些`Aspects`注入到我们应用的正确位置的方法，而不会将它们与业务逻辑混合在一起。我们将在接下来的部分中更多地了解`Aspects`，如何实现它以及如何应用它。

这个图表说明了 Spring AOP：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/8ea23ba5-9b75-4ba8-9313-bf441b95b1da.jpg)

AOP 如何解决代码交织

# Spring AOP 术语和概念

AOP，就像每种技术一样，有自己的术语。它有自己的词汇。Spring 在其 Spring AOP 模块中使用 AOP 范式。但是，Spring AOP 有其自己的术语，这些术语是特定于 Spring 的。为了理解 Spring AOP 术语，让我们看一下以下图表：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/0fd2ee17-3144-487c-b6e7-a54fbb852387.jpg)

Spring AOP 术语和概念

让我们了解前面图表中提到的 Spring AOP 的每个概念：

+   **连接点**：程序执行中定义的点。这个执行可以是方法调用、异常处理、类初始化或对象实例化。Spring AOP 仅支持方法调用。如果我们想要除了方法调用之外的连接点，我们可以同时使用 Spring 和 AspectJ。我们将在本章后面介绍 AspectJ。

+   **建议**：在连接点上需要做什么的定义。不同类型的建议包括`@Before`、`@After`、`@Around`、`@AfterThrowing`和`@AfterReturning`。我们将在*建议类型*部分看到它们的实际应用。

+   **切入点**：用于定义必须执行的建议的连接点集合。建议不一定适用于所有连接点，因此切入点可以对我们应用中要执行的建议进行精细控制。切入点使用表达式定义，Spring 使用 AspectJ 切入点表达式语言。我们很快就会看到如何做到这一点。

+   **切面**：建议和切入点的组合，定义了应用中的逻辑以及应该在哪里执行。切面是使用带有`@Aspect`注解的常规类来实现的。这个注解来自 Spring AspectJ 支持。

这太多理论了，不是吗？现在，让我们深入了解如何在实际编程中应用这些 Spring AOP 概念。您可能已经在项目中实现了这些 AOP 概念；但是，您知道为什么需要它吗？不知道，所以现在您知道为什么我们需要 Spring AOP 了。

自从 Spring 2.0 以来，AOP 的实现变得更简单，使用了 AspectJ 切入点语言，可以在基于模式的方法（XML）或注解中定义。我们将在本章的后续部分讨论 Spring 2.0 的 AspectJ 支持和注解。

# 定义切入点

正如我们之前学到的，切入点定义了建议应该应用的位置。Spring AOP 使用 AspectJ 的表达式语言来定义建议应该应用的位置。以下是 Spring AOP 支持的一组切入点设计器：

| **设计器** | **描述** |
| --- | --- |
| `execution` | 它限制匹配只在方法执行时的连接点中进行。 |
| `within` | 它限制匹配只在特定类型的连接点中进行。例如：`within(com.packt.springhighperformance.ch3.TransferService)`。 |
| `args` | 它限制匹配只在参数为给定类型的连接点中进行。例如：`args(account,..)`。 |
| `this` | 它将匹配限制在 bean 引用或 Spring 代理对象是给定类型的实例的连接点。例如：`this(com.packt.springhighperformance.ch3.TransferService)`。 |
| `target` | 它将匹配限制在目标对象是给定类型实例的连接点。例如：`target(com.packt.springhighperformance.ch3.TransferService)`。 |
| `@within` | 它将匹配限制在声明类型具有给定类型注解的连接点。例如：`@within(org.springframework.transaction.annotation.Transactional)`。 |
| `@target` | 它将匹配限制在目标对象具有给定类型注解的连接点。例如：`@target(org.springframework.transaction.annotation.Transactional)`。 |
| `@args` | 它将匹配限制在传递的实际参数类型具有给定类型注解的连接点。例如：`@args(com.packt.springhighperformance.ch3.Lockable)`。 |
| `@annotation` | 它将匹配限制在执行方法具有给定注解的连接点。例如：`@annotation(org.springframework.transaction.annotation.Transactional)`。 |

让我们看看如何使用`execution`指示符编写切入点表达式：

+   使用`execution(<method-pattern>)`：匹配模式的方法将被 advised。以下是方法模式：

```java
[Modifiers] ReturnType [ClassType]
MethodName ([Arguments]) [throws ExceptionType]
```

+   要通过连接其他切入点来创建复合切入点，我们可以使用`&&`、`||`和`!`运算符（分别表示 AND、OR 和 NOT）。

在前面的方法模式中，方括号`[ ]`中定义的内容是可选的。没有`[ ]`的值是必须定义的。

以下图表将说明使用`execution`指示符的切入点表达式，以便在执行`findAccountById()`方法时应用 advice：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/1f9aa8b5-8a9b-4ee7-b5b9-e7e8ab78d487.jpg)

执行连接点模式

# advice 的类型

在前面的部分，我们学习了 AOP 的不同术语以及如何定义切入点表达式。在本节中，我们将学习 Spring AOP 中不同类型的 advice：

+   `@Before`：这个 advice 在连接点之前执行，并且在`aspect`中使用`@Before`注解进行定义。声明如下代码所示：

```java
@Pointcut("execution(* com.packt.springhighperformance.ch03.bankingapp.service.TransferService.transfer(..))")
public void transfer() {}

@Before("transfer()")
public void beforeTransfer(JoinPoint joinPoint){
  LOGGGER.info("validate account balance before transferring amount");
}
```

如果`@Before`方法抛出异常，`transfer`目标方法将不会被调用。这是`@Before` advice 的有效用法。

+   `@After`：这个 advice 在连接点（方法）退出/返回时执行，无论是正常返回还是有异常。要声明这个 advice，使用`@After`注解。声明如下代码所示：

```java
@Pointcut("execution(* com.packt.springhighperformance.ch03.bankingapp.service.TransferService.transfer(..))")
public void transfer() {}

@After("transfer()")
public void afterTransfer(JoinPoint joinPoint){
  LOGGGER.info("Successfully transferred from source account to dest     
  account");
}
```

+   `@AfterReturning`：正如我们在`@After` advice 中所知，无论连接点正常退出还是有异常，advice 都会执行。现在，如果我们只想在匹配的方法正常返回后运行 advice，怎么办？那么我们需要`@AfterReturning`。有时我们需要根据方法返回的值执行一些操作。在这些情况下，我们可以使用`@AfterReturning`注解。声明如下代码所示：

```java
@Pointcut("execution(* com.packt.springhighperformance.ch03.bankingapp.service.TransferService.transfer(..))")
public void transfer() {}

@AfterReturning(pointcut="transfer() and args(source, dest, amount)", returning="isTransferSuccessful" )
public void afterTransferReturns(JoinPoint joinPoint, Account source, Account dest, Double amount, boolean isTransferSuccessful){
  if(isTransferSuccessful){
    LOGGGER.info("Amount transferred successfully ");
    //find remaining balance of source account
  }
}
```

+   `@AfterThrowing`：当表达式中的匹配方法抛出异常时，将调用这个 advice。当我们想要在抛出特定类型的异常时采取某些操作，或者我们想要跟踪方法执行以纠正错误时，这是很有用的。它使用`@AfterThrowing`注解声明，如下代码所示：

```java
@Pointcut("execution(* com.packt.springhighperformance.ch03.bankingapp.service.TransferService.transfer(..))")
public void transfer() {}

@AfterThrowing(pointcut = "transfer()", throwing = "minimumAmountException")
public void exceptionFromTransfer(JoinPoint joinPoint, MinimumAmountException minimumAmountException) {
  LOGGGER.info("Exception thrown from transfer method: " +         
  minimumAmountException.getMessage());
}
```

类似于`@AfterThrowing` `returning`属性，`@AfterThrowing` advice 中的`throwing`属性必须与 advice 方法中的参数名称匹配。`throwing`属性将匹配那些抛出指定类型异常的方法执行。

+   `@Around`**：**应用于匹配方法周围的最后一个建议。这意味着它是我们之前看到的 `@Before` 和 `@After` 建议的组合。但是，`@Around` 建议比 `@Before` 和 `@After` 更强大。它更强大，因为它可以决定是否继续到连接点方法或返回自己的值或抛出异常。`@Around` 建议可以与 `@Around` 注解一起使用。`@Around` 建议中建议方法的第一个参数应该是 `ProceedingJoinPoint`。以下是如何使用 `@Around` 建议的代码示例：

```java
@Pointcut("execution(* com.packt.springhighperformance.ch03.bankingapp.service.TransferService.transfer(..))")
public void transfer() {}

@Around("transfer()")
public boolean aroundTransfer(ProceedingJoinPoint proceedingJoinPoint){
  LOGGER.info("Inside Around advice, before calling transfer method ");
  boolean isTransferSuccessful = false;
  try {
    isTransferSuccessful = (Boolean)proceedingJoinPoint.proceed();
  } catch (Throwable e) {
    LOGGER.error(e.getMessage(), e);
  }
  LOGGER.info("Inside Around advice, after returning from transfer 
  method");
  return isTransferSuccessful;
}
```

我们可以在 `@Around` 建议的主体内部一次、多次或根本不调用 `proceed`。

# Aspect 实例化模型

默认情况下，声明的 `aspect` 是 `singleton`，因此每个类加载器（而不是每个 JVM）只会有一个 `aspect` 实例。我们的 `aspect` 实例只有在类加载器被垃圾回收时才会被销毁。

如果我们需要让我们的 `aspect` 具有私有属性来保存与类实例相关的数据，那么 `aspect` 需要是有状态的。为此，Spring 与其 AspectJ 支持提供了使用 `perthis` 和 `pertarget` 实例化模型的方法。AspectJ 是一个独立的库，除了 `perthis` 和 `pertarget` 之外，还有其他实例化模型，如 `percflow`、`percflowbelow` 和 `pertypewithin`，这些在 Spring 的 AspectJ 支持中不受支持。

要使用 `perthis` 创建一个有状态的 `aspect`，我们需要在我们的 `@Aspect` 声明中声明 `perthis` 如下：

```java
@Aspect("perthis(com.packt.springhighperformance.ch03.bankingapp.service.TransferService.transfer())")
public class TransferAspect {
//Add your per instance attributes holding private data
//Define your advice methods
}
```

一旦我们用 `perthis` 子句声明了我们的 `@Aspect`，将为每个执行 `transfer` 方法的唯一 `TransferService` 对象创建一个 `aspect` 实例（通过切入点表达式匹配的 `this` 绑定到的每个唯一对象）。当 `TransferService` 对象超出范围时，`aspect` 实例也会超出范围。

`pertarget` 与 `perthis` 的工作方式相同；但是，在 `pertarget` 中，它会在切入点表达式匹配的连接点上为每个唯一的目标对象创建一个 `aspect` 实例。

现在你可能想知道 Spring 是如何应用建议而不是从业务逻辑类到横切关注类（`Aspects`）进行调用的。答案是，Spring 使用代理模式来实现这一点。它通过创建代理对象将你的 `Aspects` 编织到目标对象中。让我们在下一节详细看一下 Spring AOP 代理。

# AOP 代理

正是代理模式使得 Spring AOP 能够将横切关注从核心应用程序的业务逻辑或功能中解耦出来。代理模式是一种结构设计模式，包含在《四人组》（**GoF**）的一本书中。在实践中，代理模式通过创建不同的对象包装原始对象，而不改变原始对象的行为，以允许拦截其方法调用，外部世界会感觉他们正在与原始对象交互，而不是代理。

# JDK 动态代理和 CGLIB 代理

Spring AOP 中的代理可以通过两种方式创建：

+   JDK 代理（动态代理）：JDK 代理通过实现目标对象的接口并委托方法调用来创建新的代理对象

+   CGLIB 代理：CGLIB 代理通过扩展目标对象并委托方法调用来创建新的代理对象

让我们看看这些代理机制以及它们在下表中的区别：

| **JDK 代理** | **CGLIB 代理** |
| --- | --- |
| 它内置在 JDK 中。 | 它是一个自定义开发的库。 |
| JDK 代理在接口上工作。 | CGLIB 代理在子类上工作。当接口不存在时使用。 |
| 它将代理所有接口。 | 当方法和类都是 final 时无法工作。 |

从 Spring 3.2 开始，CGLIB 库已经打包到 Spring Core 中，因此在我们的应用程序中不需要单独包含这个库。

从 Spring 4.0 开始，代理对象的构造函数将不会被调用两次，因为 CGLIB 代理实例将通过 Objenesis 创建。

默认情况下，如果目标对象的类实现了接口，则 Spring 将尝试使用 JDK 动态代理；如果目标对象的类没有实现任何接口，则 Spring 将使用 CGLIB 库创建代理。

如果目标对象的类实现了一个接口，并且作为一个具体类注入到另一个 bean 中，那么 Spring 将抛出异常：`NoSuchBeanDefinitionException`。解决这个问题的方法要么通过接口注入（这是最佳实践），要么用`Scope(proxyMode=ScopedProxyMode.TARGET_CLASS)`注解注入。然后 Spring 将使用 CGLIB 代理创建代理对象。这个配置禁用了 Spring 使用 JDK 代理。Spring 将始终扩展具体类，即使注入了一个接口。CGLIB 代理使用装饰器模式通过创建代理来将建议编织到目标对象中：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-hiperf-spr5/img/39e2351e-1d2b-4566-aa34-d6d2266ad700.jpg)

JDK 动态代理和 CGLIB 代理

创建代理将能够将所有调用委托给拦截器（建议）。但是，一旦方法调用到达目标对象，目标对象内部的任何方法调用都不会被拦截。因此，对象引用内的任何方法调用都不会导致任何建议执行。为了解决这个问题，要么重构代码，使直接自我调用不会发生，要么使用 AspectJ 编织。为了在 Spring 中解决这个问题，我们需要将`expose a proxy`属性设置为 true，并使用`AopContext.currentProxy()`进行自我调用。

Spring 建议尽可能使用 JDK 代理。因此，尽量在应用程序的几乎所有地方实现抽象层，这样当接口可用且我们没有明确设置为仅使用 CGLIB 代理时，将应用 JDK 代理。

# ProxyFactoryBean

Spring 提供了一种经典的方式来手动创建对象的代理，使用`ProxyFactoryBean`，它将创建一个 AOP 代理包装目标对象。`ProxyFactoryBean`提供了一种设置建议和建议者的方法，最终合并到 AOP 代理中。从 Spring 中所有 AOP 代理工厂继承的`org.springframework.aop.framework.ProxyConfig`超类的关键属性如下：

+   `proxyTargetClass`：如果为 true，则仅使用 CGLIB 创建代理。如果未设置，则如果目标类实现了接口，则使用 JDK 代理创建代理；否则，将使用 CGLIB 创建代理。

+   `optimize`：对于 CGLIB 代理，这指示代理应用一些激进的优化。目前，JDK 代理不支持这一点。这需要明智地使用。

+   `冻结`：如果代理设置为`冻结`，则不允许对配置进行更改。当我们不希望调用者在代理创建后修改代理时，这是很有用的。这用于优化。此属性的默认值为`false`。

+   `exposeProxy`：将此属性设置为 true 确定当前代理是否应该暴露给`ThreadLocal`。如果暴露给`ThreadLocal`，则目标可以使用`AopContext.currentProxy()`方法进行方法的自我调用。

# ProxyFactoryBean 的作用

我们将定义一个常规的 Spring bean 作为目标 bean，比如`TransferService`，然后，使用`ProxyFactoryBean`，我们将创建一个代理，该代理将被我们的应用程序访问。为了对`TransferService`的`transfer`方法进行建议，我们将使用`AspectJExpressionPointcut`设置切点表达式，并创建拦截器，然后将其设置到`DefaultPointcutAdvisor`中创建建议者。

目标对象或 bean 如下：

```java
public class TransferServiceImpl implements TransferService {
  private static final Logger LOGGER =     
  Logger.getLogger(TransferServiceImpl.class);

  @Override
  public boolean transfer(Account source, Account dest, Double amount) {
    // transfer amount from source account to dest account
    LOGGER.info("Transferring " + amount + " from " + 
    source.getAccountName() + " 
    to " +   dest.getAccountName());
    ((TransferService)
    (AopContext.currentProxy())).checkBalance(source);
    return true;
  }

  @Override
  public double checkBalance(Account a) {
    return 0;
  }
}
```

以下代码是方法拦截器或建议：

```java
public class TransferInterceptor implements MethodBeforeAdvice{

   private static final Logger LOGGER =  
   Logger.getLogger(TransferInterceptor.class);

 @Override
 public void before(Method arg0, Object[] arg1, Object arg2) throws   
 Throwable {
    LOGGER.info("transfer intercepted");
 }
}
```

Spring 配置如下：

```java
@Configuration
public class ProxyFactoryBeanConfig {

  @Bean
  public Advisor transferServiceAdvisor() {
      AspectJExpressionPointcut pointcut = new 
      AspectJExpressionPointcut();
      pointcut.setExpression("execution(* 
      com.packt.springhighperformance.ch03.bankingapp.service
      .TransferService.checkBalance(..))");
      return new DefaultPointcutAdvisor(pointcut, new 
      TransferInterceptor());
  }

  @Bean
  public ProxyFactoryBean transferService(){
    ProxyFactoryBean proxyFactoryBean = new ProxyFactoryBean();
    proxyFactoryBean.setTarget(new TransferServiceImpl());
    proxyFactoryBean.addAdvisor(transferServiceAdvisor());
    proxyFactoryBean.setExposeProxy(true);
    return proxyFactoryBean;
  }
}
```

在前面的代码示例中，我们没有单独定义`TransferService`作为 Spring bean。我们创建了`TransferService`的匿名 bean，然后使用`ProxyFactoryBean`创建了它的代理。这样做的好处是`TransferService`类型只有一个对象，没有人可以获得未经建议的对象。这也减少了如果我们想要使用 Spring IoC 将此 bean 连接到任何其他 bean 时的歧义。

使用`ProxyFactoryBean`，我们可以配置 AOP 代理，提供了编程方法的所有灵活性，而不需要我们的应用进行 AOP 配置。

最好使用声明性的代理配置方法，而不是编程方法，除非我们需要在运行时执行操作或者想要获得细粒度的控制。

# 性能 JDK 动态代理与 CGLIB 代理

我们了解了代理的用途。根据 GoF 书籍《设计模式：可复用面向对象软件的元素》，代理是另一个对象的占位符，用于控制对它的访问。由于代理位于调用对象和真实对象之间，它可以决定是否阻止对真实（或目标）对象的调用，或者在调用目标对象之前执行一些操作。

许多对象关系映射器使用代理模式来实现一种行为，该行为可以防止数据在实际需要之前被加载。有时这被称为**延迟加载**。Spring 也使用代理来开发一些功能，比如事务管理、安全性、缓存和 AOP 框架。

由于代理对象是在运行时由 JDK 代理或 CGLIB 库创建的额外对象，并位于调用对象和目标对象之间，它将增加对普通方法调用的一些开销。

让我们找出代理对普通方法调用增加了多少开销。

以下片段显示了 CGLIB 代理的 Spring 基于 Java 的配置类：

```java
@EnableAspectJAutoProxy
@Configuration
public class CGLIBProxyAppConfig {

  @Bean
  @Scope(proxyMode=ScopedProxyMode.TARGET_CLASS)
  public TransferService transferService(){
    return new TransferServiceImpl();
  }
}
```

JDK 代理的 Spring 基于 Java 的配置类如下：

```java
@Configuration
@EnableAspectJAutoProxy
public class JDKProxyAppConfig {

 @Bean
 @Scope(proxyMode=ScopedProxyMode.INTERFACES)
 public TransferService transferService(){
 return new TransferServiceImpl();
 }
}
```

JUnit 类如下：

```java
public class TestSpringProxyOverhead {
  private static final Logger LOGGER = 
  Logger.getLogger(TestSpringProxyOverhead.class);

  @Test
  public void checkProxyPerformance() {
    int countofObjects = 3000;
    TransferServiceImpl[] unproxiedClasses = new 
    TransferServiceImpl[countofObjects];
    for (int i = 0; i < countofObjects; i++) {
      unproxiedClasses[i] = new TransferServiceImpl();
    }

    TransferService[] cglibProxyClasses = new     
    TransferService[countofObjects];
    TransferService transferService = null;
    for (int i = 0; i < countofObjects; i++) {
      transferService = new 
      AnnotationConfigApplicationContext(CGLIBProxyAppConfig.class)
      .getBean(TransferService.class);
      cglibProxyClasses[i] = transferService;
    }

    TransferService[] jdkProxyClasses = new 
    TransferService[countofObjects];
    for (int i = 0; i < countofObjects; i++) {
      transferService = new 
      AnnotationConfigApplicationContext(JDKProxyAppConfig.class)
      .getBean(TransferService.class);
      jdkProxyClasses[i] = transferService;
    }

    long timeTookForUnproxiedObjects = 
    invokeTargetObjects(countofObjects, 
    unproxiedClasses);
    displayResults("Unproxied", timeTookForUnproxiedObjects);

    long timeTookForJdkProxiedObjects = 
    invokeTargetObjects(countofObjects, 
    jdkProxyClasses);
    displayResults("Proxy", timeTookForJdkProxiedObjects);

    long timeTookForCglibProxiedObjects = 
    invokeTargetObjects(countofObjects, 
    cglibProxyClasses);
    displayResults("cglib", timeTookForCglibProxiedObjects);

  }

  private void displayResults(String label, long timeTook) {
  LOGGER.info(label + ": " + timeTook + "(ns) " + (timeTook / 1000000) 
  + "(ms)");
  }

  private long invokeTargetObjects(int countofObjects, 
  TransferService[] classes) {
    long start = System.nanoTime();
    Account source = new Account(123456, "Account1");
    Account dest = new Account(987654, "Account2");
    for (int i = 0; i < countofObjects; i++) {
      classes[i].transfer(source, dest, 100);
    }
    long end = System.nanoTime();
    long execution = end - start;
    return execution;
  }
}
```

开销时间根据硬件工具（如 CPU 和内存）而异。以下是我们将获得的输出类型：

```java
2018-02-06 22:05:01 INFO TestSpringProxyOverhead:52 - Unproxied: 155897(ns) 0(ms)
2018-02-06 22:05:01 INFO TestSpringProxyOverhead:52 - Proxy: 23215161(ns) 23(ms)
2018-02-06 22:05:01 INFO TestSpringProxyOverhead:52 - cglib: 30276077(ns) 30(ms)
```

我们可以使用诸如 Google 的 Caliper（[`github.com/google/caliper`](https://github.com/google/caliper)）或**Java 微基准测试工具**（**JMH**）（[`openjdk.java.net/projects/code-tools/jmh/`](http://openjdk.java.net/projects/code-tools/jmh/)）等工具进行基准测试。使用不同的工具和场景进行了许多性能测试，得到了不同的结果。一些测试显示 CGLIB 比 JDK 代理更快，而另一些测试得到了其他结果。如果我们测试 AspectJ，这是本章稍后将讨论的内容，性能仍然优于 JDK 代理和 CGLIB 代理，因为它使用了字节码编织机制而不是代理对象。

这里的问题是我们是否真的需要担心我们看到的开销？答案既是肯定的，也是否定的。我们将讨论这两个答案。

我们不必真正担心开销，因为代理增加的时间微不足道，而 AOP 或代理模式提供的好处很大。我们已经在本章的前几节中看到了 AOP 的好处，比如事务管理、安全性、延迟加载或任何横切的东西，但通过代码简化、集中管理或代码维护。

此外，当我们的应用程序有**服务级别协议**（**SLA**）以毫秒交付，或者我们的应用程序有非常高的并发请求或负载时，我们还需要担心开销。在这种情况下，每花费一毫秒对我们的应用程序都很重要。但是，我们仍然需要在我们的应用程序中使用 AOP 来实现横切关注点。因此，我们需要在这里注意正确的 AOP 配置，避免不必要的扫描对象以获取建议，配置我们想要建议的确切连接点，并避免通过 AOP 实现细粒度要求。对于细粒度要求，用户可以使用 AspectJ（字节码编织方法）。

因此，经验法则是，使用 AOP 来实现横切关注点并利用其优势。但是，要谨慎实施，并使用正确的配置，不会通过对每个操作应用建议或代理来降低系统性能。

# 缓存

为了提高应用程序的性能，缓存重操作是不可避免的。Spring 3.1 添加了一个名为**caching**的优秀抽象层，帮助放弃所有自定义实现的`aspects`，装饰器和注入到与缓存相关的业务逻辑中的代码。

Spring 使用 AOP 概念将缓存应用于 Spring bean 的方法；我们在本章的*AOP 概念*部分学习了它。Spring 会创建 Spring bean 的代理，其中方法被注释为缓存。

为了利用 Spring 的缓存抽象层的好处，只需使用`@Cacheable`注释重的重方法。此外，我们需要通过在配置类上注释`@EnableCaching`来通知我们的应用程序方法已被缓存。以下是缓存方法的示例：

```java
@Cacheable("accounts")
public Account findAccountById(int accountId){
```

`@Cacheable`注释具有以下属性：

+   `value`：缓存的名称

+   `key`：每个缓存项的缓存键

+   `condition`：根据**Spring 表达式语言**（**SpEL**）表达式的评估来定义是否应用缓存

+   `unless`：这是另一个用 SpEL 编写的条件，如果为真，则阻止返回值被缓存

以下是 Spring 提供的与缓存相关的其他注释：

+   `@CachePut`：它将允许方法执行并更新缓存

+   `@CacheEvict`：它将从缓存中删除陈旧的数据

+   `@Caching`：它允许您在同一方法上组合多个注释`@Cacheable`，`@CachePut`和`@CacheEvict`

+   `@CacheConfig`：它允许我们在整个类上注释，而不是在每个方法上重复

我们可以在检索数据的方法上使用`@Cacheable`，并在执行插入以更新缓存的方法上使用`@CachePut`。代码示例如下：

```java
@Cacheable("accounts" key="#accountId")
public Account findAccountById(int accountId){

@CachePut("accounts" key="#account.accountId")
public Account createAccount(Account account){
```

对方法进行注释以缓存数据不会存储数据；为此，我们需要实现或提供`CacheManager`。Spring 默认情况下在`org.springframework.cache`包中提供了一些缓存管理器，其中之一是`SimpleCacheManager`。`CacheManager`代码示例如下：

```java
@Bean
public CacheManager cacheManager() {
  CacheManager cacheManager = new SimpleCacheManager();
  cacheManager.setCaches(Arrays.asList(new     
  ConcurrentMapCache("accounts"));
  return cacheManager;
}
```

Spring 还提供支持，以集成以下第三方缓存管理器：

+   EhCache

+   Guava

+   Caffeine

+   Redis

+   Hazelcast

+   您的自定义缓存

# AOP 方法分析

应用程序可以有许多业务方法。由于一些实现问题，一些方法需要时间，我们希望测量这些方法花费了多少时间，我们可能还想分析方法参数。Spring AOP 提供了一种执行方法分析的方法，而不触及业务方法。让我们看看如何做到这一点。

# PerformanceMonitorInterceptor

让我们看看如何对我们的方法执行进行分析或监视。这是通过 Spring AOP 提供的`PerformanceMonitorInterceptor`类的简单选项来完成的。

正如我们所了解的，Spring AOP 允许在应用程序中通过拦截一个或多个方法的执行来定义横切关注点，以添加额外功能，而不触及核心业务类。

Spring AOP 中的`PerformanceMonitorInterceptor`类是一个拦截器，可以绑定到任何自定义方法以在同一时间执行。该类使用`StopWatch`实例来记录方法执行的开始和结束时间。

让我们监视`TransferService`的`transfer`方法。以下是`TransferService`的代码：

```java
public class TransferServiceImpl implements TransferService {

  private static final Logger LOGGER = 
  LogManager.getLogger(TransferServiceImpl.class);

  @Override
  public boolean transfer(Account source, Account dest, int amount) {
    // transfer amount from source account to dest account
    LOGGER.info("Transferring " + amount + " from " + 
    source.getAccountName() + " 
    to " + dest.getAccountName());
    try {
      Thread.sleep(5000);
    } catch (InterruptedException e) {
      LOGGER.error(e);
    }
    return true;
  }
}
```

以下代码是`@Pointcut`，用于使用 Spring 拦截器监视建议方法：

```java
@Aspect 
public class TransferMonitoringAspect {

    @Pointcut("execution(*          
    com.packt.springhighperformance.ch03.bankingapp.service
    .TransferService.transfer(..))")
    public void transfer() { }
}
```

以下代码是 advisor 类：

```java
public class PerformanceMonitorAdvisor extends DefaultPointcutAdvisor {

 private static final long serialVersionUID = -3049371771366224728L;

 public PerformanceMonitorAdvisor(PerformanceMonitorInterceptor 
 performanceMonitorInterceptor) {
 AspectJExpressionPointcut pointcut = new AspectJExpressionPointcut();
 pointcut.setExpression(
 "com.packt.springhighperformance.ch03.bankingapp.aspect.TransferMonito  ringAspect.transfer()");
 this.setPointcut(pointcut);
 this.setAdvice(performanceMonitorInterceptor);
 }
}
```

以下代码是 Spring Java 配置类：

```java
@EnableAspectJAutoProxy
@Configuration
public class PerformanceInterceptorAppConfig {
  @Bean
  public TransferService transferService() {
    return new TransferServiceImpl();
  }

  @Bean
  public PerformanceMonitorInterceptor performanceMonitorInterceptor() {
    return new PerformanceMonitorInterceptor(true);
  }

  @Bean
  public TransferMonitoringAspect transferAspect() {
    return new TransferMonitoringAspect();
  }

  @Bean
  public PerformanceMonitorAdvisor performanceMonitorAdvisor() {
    return new 
    PerformanceMonitorAdvisor(performanceMonitorInterceptor());
  }
}
```

Pointcut 表达式标识我们想要拦截的方法。我们已经将`PerformanceMonitorInterceptor`定义为一个 bean，然后创建了`PerformanceMonitorAdvisor`来将切入点与拦截器关联起来。

在我们的`Appconfig`中，我们使用`@EnableAspectJAutoProxy`注解来为我们的 bean 启用 AspectJ 支持，以自动创建代理。

要使`PerformanceMonitorInterceptor`起作用，我们需要将目标对象`TransferServiceImpl`的日志级别设置为`TRACE`级别，因为这是它记录消息的级别。

对于每次执行`transfer`方法，我们将在控制台日志中看到`TRACE`消息：

```java
2018-02-07 22:14:53 TRACE TransferServiceImpl:222 - StopWatch 'com.packt.springhighperformance.ch03.bankingapp.service.TransferService.transfer': running time (millis) = 5000
```

# 自定义监视拦截器

`PerformanceMonitorInterceptor`是监视我们方法执行时间的一种非常基本和简单的方式。然而，大多数情况下，我们需要更加受控的方式来监视方法及其参数。为此，我们可以通过扩展`AbstractMonitoringInterceptor`或编写环绕建议或自定义注解来实现我们的自定义拦截器。在这里，我们将编写一个扩展`AbstractMonitoringInterceptor`的自定义拦截器。

让我们扩展`AbstractMonitoringInterceptor`类，并重写`invokeUnderTrace`方法来记录方法的`start`、`end`和持续时间。如果方法执行时间超过`5`毫秒，我们还可以记录警告。以下是自定义监视拦截器的代码示例：

```java
public class CustomPerformanceMonitorInterceptor extends AbstractMonitoringInterceptor {

    private static final long serialVersionUID = -4060921270422590121L;
    public CustomPerformanceMonitorInterceptor() {
    }

    public CustomPerformanceMonitorInterceptor(boolean 
    useDynamicLogger) {
            setUseDynamicLogger(useDynamicLogger);
    }

    @Override
    protected Object invokeUnderTrace(MethodInvocation invocation, Log 
    log) 
      throws Throwable {
        String name = createInvocationTraceName(invocation);
        long start = System.currentTimeMillis();
        log.info("Method " + name + " execution started at:" + new 
        Date());
        try {
            return invocation.proceed();
        }
        finally {
            long end = System.currentTimeMillis();
            long time = end - start;
            log.info("Method "+name+" execution lasted:"+time+" ms");
            log.info("Method "+name+" execution ended at:"+new Date());

            if (time > 5){
                log.warn("Method execution took longer than 5 ms!");
            } 
        }
    }
}
```

在基本的`PerformanceMonitorInterceptor`中看到的每一步都是相同的，只是用`CustomPerformanceMonitorInterceptor`替换`PerformanceMonitorInterceptor`。

生成以下输出：

```java
2018-02-07 22:23:44 INFO TransferServiceImpl:32 - Method com.packt.springhighperformance.ch03.bankingapp.service.TransferService.transfer execution lasted:5001 ms
2018-02-07 22:23:44 INFO TransferServiceImpl:33 - Method com.packt.springhighperformance.ch03.bankingapp.service.TransferService.transfer execution ended at:Wed Feb 07 22:23:44 EST 2018
2018-02-07 22:23:44 WARN TransferServiceImpl:36 - Method execution took longer than 5 ms!
```

# Spring AOP 与 AspectJ

到目前为止，我们已经看到了使用代理模式和运行时织入的 AOP。现在让我们看看编译时和加载时织入的 AOP。

# 什么是 AspectJ？

正如我们从本章的开头所知，AOP 是一种编程范式，通过将横切关注点的实现分离来帮助解耦我们的代码。AspectJ 是 AOP 的原始实现，它使用 Java 编程语言的扩展来实现关注点和横切关注点的编织。

为了在我们的项目中启用 AspectJ，我们需要 AspectJ 库，AspectJ 根据其用途提供了不同的库。可以在[`mvnrepository.com/artifact/org.aspectj`](https://mvnrepository.com/artifact/org.aspectj)找到所有的库。

在 AspectJ 中，`Aspects`将在扩展名为`.aj`的文件中创建。以下是`TransferAspect.aj`文件的示例：

```java
public aspect TransferAspect {
    pointcut callTransfer(Account acc1, Account acc2, int amount) : 
     call(public * TransferService.transfer(..));

    boolean around(Account acc1, Account acc2, int amount) : 
      callTransfer(acc1, acc2,amount) {
        if (acc1.balance < amount) {
            return false;
        }
        return proceed(acc1, acc2,amount);
    }
}
```

要启用编译时织入，当我们既有`aspect`代码又有我们想要织入`aspects`的代码时，使用 Maven 插件如下：

```java
<plugin>
    <groupId>org.codehaus.mojo</groupId>
    <artifactId>aspectj-maven-plugin</artifactId>
    <version>1.11</version>
    <configuration>
        <complianceLevel>1.8</complianceLevel>
        <source>1.8</source>
        <target>1.8</target>
        <showWeaveInfo>true</showWeaveInfo>
        <verbose>true</verbose>
        <Xlint>ignore</Xlint>
        <encoding>UTF-8 </encoding>
    </configuration>
    <executions>
        <execution>
            <goals>
                <!-- use this goal to weave all your main classes -->
                <goal>compile</goal>
                <!-- use this goal to weave all your test classes -->
                <goal>test-compile</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

要执行编译后织入，当我们想要织入现有的类文件和 JAR 文件时，使用 Mojo 的 AspectJ Maven 插件如下。我们引用的 artifact 或 JAR 文件必须在 Maven 项目的`<dependencies/>`中列出，并在 AspectJ Maven 插件的`<configuration>`中列出为`<weaveDependencies/>`。以下是如何定义织入依赖项的 Maven 示例：

```java
<configuration>
    <weaveDependencies>
        <weaveDependency> 
            <groupId>org.agroup</groupId>
            <artifactId>to-weave</artifactId>
        </weaveDependency>
        <weaveDependency>
            <groupId>org.anothergroup</groupId>
            <artifactId>gen</artifactId>
        </weaveDependency>
    </weaveDependencies>
</configuration>
```

要执行**加载时织入**（**LTW**），当我们想要推迟我们的织入直到类加载器加载类文件时，我们需要一个织入代理；使用 Maven 插件如下：

```java
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-surefire-plugin</artifactId>
    <version>2.20.1</version>
    <configuration>
        <argLine>
            -javaagent:"${settings.localRepository}"/org/aspectj/
            aspectjweaver/${aspectj.version}/
            aspectjweaver-${aspectj.version}.jar
        </argLine>
        <useSystemClassLoader>true</useSystemClassLoader>
        <forkMode>always</forkMode>
    </configuration>
</plugin>
```

对于 LTW，它在`META-INF`文件夹下的类路径中查找`aop.xml`。文件包含如下的`aspect`和`weaver`标签：

```java
<aspectj>
    <aspects>
        <aspect name="com.packt.springhighperformance.ch3.bankingapp.
        aspectj.TransferAspect"/>
        <weaver options="-verbose -showWeaveInfo">
            <include         
            within="com.packt.springhighperformance.ch3.bankingapp
            .service.impl.TransferServiceImpl"/>
        </weaver>
    </aspects>
</aspectj>
```

这只是一个关于如何在项目中启用 AspectJ 的介绍。

# Spring AOP 和 AspectJ 之间的区别

让我们来看看 Spring AOP（运行时织入）和 AspectJ（编译时和 LTW）之间的区别。

# 能力和目标

Spring AOP 提供了一个简单的 AOP 实现，使用代理模式和装饰器模式来实现横切关注点。它不被认为是一个完整的 AOP 解决方案，Spring 可以应用于由 Spring 容器管理的 bean。

AspectJ 是最初的 AOP 技术，旨在提供完整的 AOP 解决方案。它比 Spring AOP 更健壮，但也更复杂。AspectJ 的好处是可以应用于所有领域对象。

# 织入

Spring AOP 和 AspectJ 都使用不同类型的织入，根据它们的织入机制，它们在性能和易用性方面的行为是不同的。

为了在应用程序执行期间执行我们的`aspects`的运行时织入，Spring 使用 JDK 动态代理或 CGLIB 代理创建目标对象的代理，这是我们之前讨论过的。

与 Spring AOP 的运行时织入相反，AspectJ 在编译时或类加载时执行织入。我们已经在前面的部分看到了不同类型的 AspectJ 织入。

# 连接点

由于 Spring AOP 创建目标类或对象的代理来应用横切关注点（`Aspects`），它需要对目标类或对象进行子类化。正如我们已经知道的，通过子类化，Spring AOP 无法在最终或静态的类或方法上应用横切关注点。

另一方面，AspectJ 通过字节码织入将横切关注点编织到实际代码中，因此它不需要对目标类或对象进行子类化。

# 简单性

在 Spring AOP 中，`Aspects`的运行时织入将由容器在启动时执行，因此它与我们的构建过程无缝集成。

另一方面，在 AspectJ 中，除非我们在后期编译或在 LTW 中执行此操作，否则我们必须使用额外的编译器（`ajc`）。因此，Spring 比 AspectJ 更简单、更易管理。

使用 Spring AOP，我们无法使用或应用 AOP 的全部功能，因为 Spring AOP 是基于代理的，只能应用于 Spring 管理的 bean。

AspectJ 基于字节码织入，这意味着它修改了我们的代码，因此它使我们能够在应用程序的任何 bean 上使用 AOP 的全部功能。

# 性能

从性能的角度来看，编译时织入比运行时织入更快。Spring AOP 是基于代理的框架，因此它在运行时为代理创建额外的对象，并且每个`aspect`有更多的方法调用，这对性能产生负面影响。

另一方面，AspectJ 在应用程序启动之前将`aspects`编织到主代码中，因此没有额外的运行时开销。互联网上有可用的基准测试表明，AspectJ 比 Spring AOP 快得多。

并不是说一个框架比另一个更好。选择将基于需求和许多不同因素，例如开销、简单性、可管理性/可维护性、复杂性和学习曲线。如果我们使用较少的`aspects`，并且除了 Spring bean 或方法执行之外没有应用`aspect`的需求，那么 Spring AOP 和 AspectJ 之间的性能差异是微不足道的。我们也可以同时使用 AspectJ 和 Spring AOP 来实现我们的需求。

# Spring 中的 AspectJ

Spring 提供了小型库，以将 AspectJ `aspects`集成到 Spring 项目中。这个库被命名为`spring-aspects.jar`。正如我们从之前的讨论中了解到的，Spring 只允许在 Spring bean 上进行依赖注入或 AOP 建议。使用这个小库的 Spring 的 AspectJ 支持，我们可以为 Spring 驱动的配置启用在容器外创建的任何对象。只需用`@Configurable`注释外部对象。用`@Configurable`注释非 Spring bean 将需要`spring-aspects.jar`中的`AnnotationBeanConfigurerAspect`。Spring 需要的`AnnotationBeanConfigurerAspect`配置可以通过用`@EnableSpringConfigured`注释我们的配置 Java 配置类来完成。

Spring 提供了一种更精细的方式来启用**加载时织入**（**LTW**），通过启用每个类加载器基础。这在将大型或多个应用程序部署到单个 JVM 环境时提供了更精细的控制。

要在 Spring 中使用 LTW，我们需要像在*AOP 概念*部分中实现的那样实现我们的`aspect`或建议，并且根据 AspectJ 概念，我们需要在`META-INF`文件夹中创建`aop.xml`，如下所示：

```java
<!DOCTYPE aspectj PUBLIC "-//AspectJ//DTD//EN" "http://www.eclipse.org/aspectj/dtd/aspectj.dtd">
<aspectj>
    <weaver>
        <!-- only weave classes in our application-specific packages --
        >
        <include within="com.packt.springhighperformance.ch3.bankingapp
        .service.impl.TransferServiceImpl"/>
        <include within="com.packt.springhighperformance.ch3.bankingapp
        .aspects.TransferServiceAspect"/>
    </weaver>
    <aspects>
        <!-- weave in just this aspect -->
        <aspect name="com.packt.springhighperformance.ch3.bankingapp
        .aspects.TransferServiceAspect"/>
    </aspects>
</aspectj>
```

我们需要做的最后一件事是用`@EnableLoadTimeWeaving`注释我们基于 Java 的 Spring 配置。我们需要在服务器启动脚本中添加`-javaagent:path/to/org.springframework.instrument-{version}.jar`。

# AOP 最佳编程实践

我们已经了解了为什么需要在我们的应用程序中使用 AOP。我们详细了解了它的概念以及如何使用它。让我们看看在我们的应用程序中使用 AOP 时应该遵循哪些最佳实践。

# 切入点表达式

我们在 AOP 方面学习了切入点。现在让我们看看在使用切入点时应该注意什么：

+   Spring 与 AspectJ 在编译期间处理切入点，并尝试匹配和优化匹配性能。然而，检查代码和匹配（静态或动态）将是一个昂贵的过程。因此，为了实现最佳性能，要三思而后行，尽量缩小我们想要实现的搜索或匹配标准。

+   我们在本章中早些时候学习的所有指示符分为三类：

+   方法签名模式：`execution`，`get`，`set`，`call`，`handler`

+   类型签名模式：`within`，`withincode`

+   上下文签名模式：`this`，`target`，`@annotation`

+   为了实现良好的性能，编写切入点应至少包括方法和类型签名模式。如果只使用方法或类型模式进行匹配，可能不会起作用；然而，始终建议将方法和类型签名结合在一起。类型签名非常快速，通过快速排除无法进一步处理的连接点，缩小了搜索空间。

+   在空方法上声明切入点，并通过其空方法名称引用这些切入点（命名切入点），这样在表达式发生任何更改时，我们只需要在一个地方进行更改。

+   建议声明小命名的切入点，并通过名称组合它们来构建复杂的切入点。按名称引用切入点将遵循默认的 Java 方法可见性规则。以下是定义小切入点并将它们连接的代码示例：

```java
@Pointcut("execution(public * *(..))")
private void anyPublicMethod() {}

@Pointcut("within(com.packt.springhighperformance.ch3.bankingapp.TransferService..*)")
private void transfer() {}

@Pointcut("anyPublicMethod() && transfer()")
private void transferOperation() {}

```

+   尽量在切入点不共享时为其创建匿名 bean，以避免应用程序直接访问。

+   尽量使用静态切入点，其中不需要匹配参数。这些更快，并且在首次调用方法时由 Spring 缓存。动态切入点成本高，因为它们在每次方法调用时进行评估，因为无法进行缓存，参数会有所不同。

# 建议顺序

现在我们知道如何编写建议以及如何创建`Aspect`。让我们看看建议顺序如何帮助我们在同一连接点上有多个建议时优先考虑我们的建议：

+   假设我们在不同的 aspects 中编写了两个 before 或 after advice，并且两者都希望在相同的连接点运行。在这种情况下，advice 的执行顺序将基于在类执行中哪个 aspect 先出现。为了避免这种情况并依次应用我们的 advice，Spring 提供了一种方法来指定执行顺序，即通过一个 aspect 实现`Ordered`接口或应用`@Order`注解。顺序的值越低，优先级越高。

+   在声明 advice 时，始终使用最不强大的 advice 形式；例如，如果一个简单的 before advice 可以实现我们的要求，我们就不应该使用 around advice。

# AOP 代理的最佳实践

我们了解了 AOP 代理以及 AOP 代理的工作原理。我们了解了 Spring AOP 中不同类型的代理。在实现 Spring 中的 AOP 代理时，应遵循以下最佳实践：

+   除非我们需要在运行时执行操作或者想要对代理进行细粒度控制，否则使用声明式代理配置而不是编程方法。

+   Spring 在可能的情况下建议使用 JDK 动态代理而不是 CGLIB 代理。如果我们从头开始构建我们的应用程序，并且没有要创建第三方 API 的代理的要求，实现抽象层以松散耦合实现，使用接口并让 Spring 使用 JDK 动态代理机制来创建代理。

+   在 CGLIB 代理的情况下，确保方法不是`final`，因为`final`方法无法被覆盖，因此也无法被 advised。

+   根据 Spring 的说法，`aspects`本身不可能成为其他`aspects`的 advice 目标。对于这种情况有解决方法；将`aspect`方法移动到一个新的 Spring bean 上，并用`@Component`进行注释，将这个新的 Spring bean 自动装配到`aspect`，然后调用被 advised 的方法。`MethodProfilingAspect`是在`com.packt.springhighperformance.ch3.bankingapp`下定义一个切入点的`aspect`：

```java
@Aspect
public class MethodProfilingAspect {

  @Around("execution(* 
  com.packt.springhighperformance.ch3.bankingapp.*.*(..))")
  public Object log(ProceedingJoinPoint joinPoint){
    System.out.println("Before 
    Around"+joinPoint.getTarget().getClass().getName());
    Object retVal = null;
    try {
       retVal = joinPoint.proceed();
    } catch (Throwable e) {
      e.printStackTrace();
    }
    System.out.println("After 
    Around"+joinPoint.getTarget().getClass().getName());
    return retVal;
  }
```

+   以下的`ValidatingAspect`是在`com.packt.springhighperformance.ch3.bankapp`包下定义的`aspect`，但是`MethodProfilingAspect`不建议调用`validate`方法：

```java
@Aspect
public class ValidatingAspect {

 @Autowired
 private ValidateService validateService;

 @Before("execution(*   
 com.packt.springhighperformance.ch3.bankingapp.TransferService.tran
 sfe  r(..))")
 public void validate(JoinPoint jp){
 validateService.validateAccountNumber();
 }
}
```

+   通过创建一个带有`@Component`注解的单独类并实现`validate`方法来解决这个问题。这个类将是一个 Spring 管理的 bean，并且会被 advised：

```java
@Component
public class ValidateDefault{

  @Autowired
  private ValidateService validateService;
  public void validate(JoinPoint jp){
        validateService.validateAccountNumber();
    }
}
```

+   以下的`ValidatingAspect`代码注入了`ValidateDefault` Spring bean 并调用了`validate`方法：

```java
@Aspect
public class ValidatingAspect {

 @Autowired
 private ValidateDefault validateDefault;

 @Before("execution(* com.packt.springhighperformance.ch3.bankingapp.TransferService.transfer(..))")
 public void validate(JoinPoint jp){

```

```java
 validateDefault.validate(jp);
 }
}
```

永远不要通过 AOP 实现细粒度的要求，也不要对 Spring 管理的 bean 类使用`@Configurable`，否则会导致双重初始化，一次是通过容器，一次是通过 aspect。

# 缓存

我们已经看到了如何通过缓存来提高应用程序的性能。在 Spring 中实现缓存时应遵循以下最佳实践：

+   Spring 缓存注解应该用在具体类上，而不是接口上。如果选择使用`proxy-target-class="true"`，缓存将不起作用，因为接口的 Java 注解无法继承。

+   尽量不要在同一个方法上同时使用`@Cacheable`和`@CachePut`。

+   不要缓存非常低级的方法，比如 CPU 密集型和内存计算。在这些情况下，Spring 的缓存可能过度。

# 总结

在本章中，我们看了 Spring AOP 模块。AOP 是一种强大的编程范式，它补充了面向对象编程。AOP 帮助我们将横切关注点与业务逻辑解耦，并在处理业务需求时只关注业务逻辑。解耦的横切关注点有助于实现可重用的代码。

我们学习了 AOP 的概念、术语以及如何实现建议。我们了解了代理和 Spring AOP 如何使用代理模式实现。我们学习了在使用 Spring AOP 时应遵循的最佳实践，以实现更好的质量和性能。

在下一章中，我们将学习关于 Spring MVC。Spring Web MVC 提供了一个基于 MVC 的 Web 框架。使用 Spring Web MVC 作为 Web 框架使我们能够开发松耦合的 Web 应用程序，并且可以编写测试用例而不使用请求和响应对象。我们将看到如何优化 Spring MVC 实现，以利用异步方法特性、多线程和身份验证缓存来实现更好的结果。
