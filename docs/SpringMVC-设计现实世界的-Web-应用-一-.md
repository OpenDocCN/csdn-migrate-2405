# SpringMVC：设计现实世界的 Web 应用（一）

> 原文：[`zh.annas-archive.org/md5/AB3510E97B9E20602840C849773D49C6`](https://zh.annas-archive.org/md5/AB3510E97B9E20602840C849773D49C6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

在一个所有应用程序彼此连接的世界中，我们需要与社交媒体互动，以推广我们的产品和复杂系统，为用户提供巨大的价值。直到最近，所有这些对于 Java 开发人员来说都是遥远而复杂的世界。随着 Spring Boot 的诞生和云平台的民主化，我们现在可以创建令人惊叹的应用程序，并在记录时间内使其可供所有人使用，而不需要花一分钱。Spring 的目标是简化企业应用程序开发。

在这个学习路径中，我们将从头开始构建一个有用的 Web 应用程序。一个具有许多精彩功能的应用程序，例如国际化、表单验证、分布式会话和缓存、社交登录、多线程编程等等。它涵盖了 Spring Framework 最重要的概念和特性，以及一些对于构建现代 Web 应用程序必不可少的关键子项目。

如果这听起来对您来说很有趣，那么我们就不要浪费更多时间，开始吧！

# 这个学习路径涵盖了什么

模块 1，《Spring 基础知识》，向您展示如何使用 Spring 开发自己的完整应用程序。它包括现实世界的例子，还将帮助您使用 WebSocket 进行全双工实时通信。您将深入了解如何利用 Spring 表达式语言在应用程序中提高可维护性的能力。它还涵盖了 Spring MVC、WebSocket 技术、Spring Data 和具有各种认证和授权机制的 Spring Security 的广度和深度。

模块 2，《Spring MVC Cookbook》，教您如何处理 Spring MVC 的产品设计，并进一步开发响应式前端。您将通过微服务原则驱动的关注点分离进行学习。它还向您展示如何配置您的实体以反映您的领域需求，并发现 Spring Data 存储库。最后，您将学习如何设置和组织不同级别的自动化测试，包括日志记录和监控。

模块 3，《精通 Spring MVC 4》，带您从开发自己的 Web 应用程序到将其上传到云端。从您自己的项目开始，您将开发一个高级交互式应用程序，可以处理文件上传以及复杂的 URL，您将深入了解 Spring MVC 的内部工作原理和现代 Web 架构的原则。最后，您将看到如何在发布到云端之前保护您的应用程序。

# 您需要为此学习路径做些什么

对于这个学习路径，要求如下。

软件：

+   Windows、Linux 或 Mac OS X

+   Java 8

+   Maven 3.x

+   任何 Java Web 服务器（Apache Tomcat v8.0）

+   Node.js

+   Ember CLI

+   GIT（v2.6.3+）

+   Apache HTTP 服务器（v2.4+）

+   RabbitMQ 服务器（v3.5.4+）

+   Redis 服务器（v3+）

硬件：

+   至少 2GB 的 RAM

+   至少 500MB 的可用空间

# 这个学习路径适合谁

这个学习路径适用于想要利用 Spring MVC 及其特性构建 Web 应用程序的 Java 开发人员。它的目的是向开发人员介绍 Spring 编程的基础知识，然后将他们的 Web 开发技能扩展到更高级别的 Spring 功能。


# 第一部分：Spring 基础知识

*使用 Spring 框架和面向方面的编程构建关键任务的企业应用程序*



# 第一章：开始使用 Spring Core

Spring 框架是企业 Java 中最受信任和广泛使用的应用程序开发框架。最初作为复杂 J2EE 的简单轻量级替代方案引入，Spring 现在已经发展成为一个真正现代的应用程序开发平台。Spring 及其子项目为端到端应用程序开发提供了出色的基础，具有甚至超过最新 Java EE 提供的功能，如移动开发、社交网络和大数据，除了传统的 Java web、服务器端或独立应用程序。自诞生以来已经超过十年，Spring 继续激发全球范围内的技术和技术人员。

尽管 Spring 极大地简化了 Java 开发，但软件开发人员和架构师仍需要深入了解其核心概念和特性，以便推断出 Spring 家族的最佳用法。Spring 提供给复杂的 Java 开发带来的简单性是其提供的优秀 API 和模块形式的智能抽象的结果。Spring 组件解除了开发人员对常见技术和基础设施管道任务的所有技术复杂性和繁重工作。正如官方 Spring 文档所说，Spring 提供了全面的基础设施支持，以便您可以专注于您的应用程序。

本书试图使您的 Spring 学习更加轻松和愉快。

本章为您提供了 Spring 框架核心的坚实基础，引导您了解其核心概念、组件和模块，并附有相关的示例代码片段，以说明每个功能的最佳和最实用的用法，以解决您的日常编程问题。

在本章中，我们将涵盖以下主题：

+   Spring 的景观

+   设置开发环境

+   您的第一个 Spring 应用程序

+   核心概念

+   IoC（控制反转）容器

+   详细介绍 bean

+   使用 bean 定义配置文件

+   处理资源

+   SpEL（Spring 表达式语言）

+   面向方面的编程

# Spring 的景观

Spring 涵盖了由不同类型的应用程序处理的各种技术方面，从简单的独立 Java 应用程序到您可以想象的最复杂的、关键任务的分布式企业系统。与大多数其他开源或专有框架不同，它专注于特定技术关注点，如 Web、消息传递或远程调用，Spring 成功地涵盖了几乎所有业务应用程序的技术方面。在大多数情况下，Spring 利用和集成了经过验证的现有框架，而不是重新发明解决方案，以实现端到端的覆盖。Spring 高度模块化，因此，它非侵入性地允许您挑选您需要的模块或功能，以成为 JVM 上所有开发需求的一站式商店。

整个 Spring 框架组合分为三个主要元素：

+   Spring 框架

+   Spring 工具套件

+   Spring 子项目

Spring 不断改进，并且随着每个新版本变得越来越模块化，以便您可以只使用所需的模块。

### 注意

本书基于 Spring 4 版本。

## Spring 框架模块

核心 Spring 框架为 Java 开发提供了基本的基础设施，构建在其核心的**控制反转**（**IoC**）容器之上。IoC 容器是为应用程序提供**依赖注入**（**DI**）的基础设施。依赖注入和 IoC 容器的概念将在本章后面详细解释。核心 Spring 框架分为以下模块，提供一系列服务：

| 模块 | 摘要 |
| --- | --- |
| 核心容器 | 提供 IoC 和依赖注入功能。 |
| AOP 和仪器 | 为 Spring 应用程序中的横切关注点提供符合 AOP Alliance 标准的特性。 |
| 消息 | 为基于消息的应用程序提供了 Spring Integration 项目上的消息抽象。 |
| 数据访问/集成 | 数据访问/集成层包括 JDBC、ORM、OXM、JMS 和事务模块。 |
| Web | Spring MVC、web socket 和 portlet API 上的 Web 技术抽象。 |
| 测试 | 使用 JUnit 和 TestNG 框架支持单元测试和集成测试。 |

## Spring 工具套件（STS）

STS 是基于 Eclipse 的 Spring 开发**IDE**（**集成开发环境**）。你可以从[`spring.io/tools/sts/all`](http://spring.io/tools/sts/all)下载预打包的 STS，或者从同一位置的更新站点更新现有的 Eclipse 安装。STS 为 Spring 开发提供了各种高生产力的功能。实际上，Java 开发人员可以使用他们选择的任何 IDE。几乎所有的 Java IDE 都支持 Spring 开发，并且大多数都有可用于 Spring 的插件。

## Spring 子项目

Spring 有许多子项目，解决各种应用基础设施需求。从配置到安全，从 Web 应用到大数据，从生产力到**企业应用集成**（**EAI**），无论你的技术痛点是什么，你都会发现一个 Spring 项目来帮助你进行应用开发。Spring 项目位于[`spring.io/projects`](http://spring.io/projects)。

你可能立即发现有用的一些显著项目包括 Spring Data（JPA、Mongo、Redis 等）、Spring Security、Spring Web Services、Spring Integration、Spring for Android 和 Spring Boot。

# Spring 框架背后的设计概念

Spring 框架的设计受到一系列设计模式和最佳实践的启发，这些设计模式和框架已经在行业中发展，以解决面向对象编程的复杂性，包括：

+   简单、非侵入式、轻量级的**POJO**（**Plain Old Java Objects**）编程，无需复杂的应用服务器

+   通过应用*面向接口编程*和*组合优于继承*的概念来实现松耦合的依赖关系，这些是设计模式和框架的基本设计原则

+   由对象组成的高度可配置系统，具有外部化的依赖注入

+   模板化的抽象以消除重复的样板代码

+   声明性地编织横切关注点，而不污染业务组件

Spring 将已建立的设计原则和模式实现到其优雅的组件中，并促进它们作为 Spring 构建的应用程序的默认设计方法。这种非侵入式的方法让你能够构建松耦合的组件和以清晰、模块化的代码编写的对象组成的健壮且易于维护的系统。Spring 框架的组件、模板和库实现了本章前面解释的目标和概念，让你可以专注于核心业务逻辑。

# 设置开发环境

Spring 项目通常是基于 Maven、Gradle 或 Ivy（这些是构建自动化和依赖管理工具）的 Java 项目创建的。你可以使用 STS 或带有 Spring 工具支持的 Eclipse 轻松创建基于 Maven 的 Spring 项目。你需要确保你的`pom.xml`（Maven 配置）文件至少包含对`spring-context`的依赖：

```java
<dependencies>
  <dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-context</artifactId>
    <version>${spring-framework.version}</version>
  </dependency>
  ...
</dependencies>
```

当然，你应该根据项目类型和要求向模块添加进一步的依赖，比如`spring-tx`、`spring-data-jpa`、`spring-webmvc`和`hibernate`。

除非你明确指定存储库位置，否则你的项目将使用 Maven 的中央存储库。或者，你可以在`pom.xml`文件中指定 Spring 的官方 Maven 存储库（例如，用于里程碑和快照）：

```java
<repositories>
    <repository>
        <id>io.spring.repo.maven.milestone</id>
        <url>http://repo.spring.io/milestone/</url>
        <snapshots><enabled>false</enabled></snapshots>
    </repository>
</repositories>
```

您可以根据需要使用 Spring 的`release`、`milestone`和`snapshot`仓库。

如果你使用 Gradle 作为你的构建系统，你可以在`build.gradle`文件中声明你的依赖关系，如下所示：

```java
dependencies {
    compile('org.springframework:spring-context')
    compile('org.springframework:spring-tx')
    compile('org.hibernate:hibernate-entitymanager')
    testCompile('junit:junit')
}
```

如果你喜欢使用 Ivy 依赖管理工具，那么你的 Spring 依赖配置将如下所示：

```java
<dependency org="org.springframework"
    name="spring-core" rev="4.2.0.RC3" conf="compile->runtime"/>
```

# 你的第一个 Spring 应用程序

现在让我们从一个非常简单的 Spring 应用程序开始。这个应用程序只是用欢迎消息向用户打招呼。从技术上讲，它演示了如何配置一个 Spring `ApplicationContext`（IoC 容器），其中只有一个 bean，并在应用程序中调用该 bean 的方法。该应用程序有四个部分（当然还有项目构建文件）：

+   `GreetingService.java`：一个 Java 接口—只有一个方法

+   `GreetingServiceImpl.java`：`GreetingService`的简单实现

+   `Application.java`：带有`main`方法的应用程序

+   `application-context.xml`：您的应用程序的 Spring 配置文件

以下是你的应用程序的服务组件。服务实现只是向日志记录器打印一个问候消息：

```java
interface GreetingService {
   void greet(String message);
}

public class GreetingServiceImpl implements GreetingService {
   Logger logger = LoggerFactory.getLogger(GreetingService.class);

   public void greet(String message) {
      logger.info("Greetings! " + message);
   }
}
```

现在让我们来看一下`application-context.xml`文件，这是你的 Spring 配置文件，在这里你可以在下面的清单中注册`GreetingService`作为 Spring bean：

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans 

   xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
   <bean id="Greeter"
      class="com.springessentialsbook.chapter1.GreetingServiceImpl">
   </bean>
</beans>
```

最后，你可以从你的 Spring 应用程序中调用`GreetingService.greet()`方法，如下面的代码所示：

```java
public class Application {

   public static void main(String[] args) {
      ApplicationContext context = new ClassPathXmlApplicationContext(new String[] {"application-context.xml"});
      GreetingService greeter = (GreetingService) context.getBean("Greeter");
     greeter.greet("I am your first Spring bean instance, configured purely with XML metadata. I am resolved by name.");
   }
}
```

我们将从这个非常简单且相当自解释的应用程序开始，探索并征服强大的 Spring 框架。我们将在接下来的章节中讨论和详细说明这个应用程序背后的概念，以及更多内容。

## 控制反转解释

IoC 是一种设计原则，它将面向对象程序的对象与它们的依赖关系（协作者）解耦，也就是说，它们所使用的对象。通常，这种解耦是通过将对象创建和依赖注入的责任外部化到外部组件（如 IoC 容器）来实现的。

这个概念经常被比作好莱坞原则，“不要打电话给我们，我们会打电话给你。”在编程世界中，它建议主程序（或组件）不要自己实例化它的依赖关系，而是让一个组装器来完成这项工作。

这立即将程序与紧密耦合的依赖关系造成的许多问题解耦，并让程序员能够快速使用抽象依赖关系（*按接口编程*）开发他们的代码。稍后，在运行时，外部实体，如 IoC 容器，解析它们在某处指定的具体实现，并在运行时注入它们。

你可以在我们刚刚看到的示例中看到这个概念的实现。你的主程序（`Application.java`）不是实例化`GreetingService`依赖关系；它只是请求`ApplicationContext`（IoC 容器）返回一个实例。在编写`Application.java`时，开发人员不需要考虑`GreetingService`接口实际上是如何实现的。Spring `ApplicationContext`负责对象的创建，并在运行时透明地注入任何其他功能，保持应用程序代码的清晰。

由 IoC 容器管理的对象不会自己控制它们的依赖关系的创建和解析；相反，这种控制被转移给了容器本身；因此有了“控制反转”的术语。

IoC 容器根据配置组装应用程序的组件。它处理受管对象的生命周期。

# 依赖注入

依赖注入是控制反转的一种特定形式。它是一种更加正式的设计模式，对象的依赖关系是由组装器注入的。DI 通常以三种主要风格进行：构造函数注入、属性（setter）注入，或者有时接口注入。IoC 和 DI 经常可以互换使用。

DI 提供了几个好处，包括有效解耦依赖关系、更清晰的代码和增强的可测试性。

## Spring IoC 容器

Spring 的核心模块，`spring-core`、`spring-beans`、`spring-context`、`spring-context-support`和`spring-expression`，共同组成了核心容器。Spring IoC 容器被设计为以下接口的实现：

+   `org.springframework.beans.factory.BeanFactory`

+   `org.springframework.context.ApplicationContext`

`BeanFactory`接口提供了配置框架和基本功能，而`ApplicationContext`作为`BeanFactory`的扩展，添加了更多的企业特定功能，例如更容易集成 Spring 的 AOP 功能、消息资源处理（用于国际化）和事件发布。

Spring 为各种上下文提供了几种`ApplicationContext`的具体实现。以下表列出了其中最受欢迎的几种：

| 应用上下文 | 典型的应用程序类型 |
| --- | --- |
| `ClassPathXmlApplicationContext` | 独立 |
| `AnnotationConfigApplicationContext` | 独立 |
| `FileSystemXmlApplicationContext` | 独立 |
| `GenericWebApplicationContext` | Web |
| `XmlWebApplicationContext` | Web |
| `XmlPortletApplicationContext` | Web portlet |

在 Spring 中，由 IoC 容器管理的对象称为**bean**。IoC 容器处理 Spring bean 的组装和生命周期。Bean 在容器消耗的配置元数据中定义，容器实例化和组装它们以组成您的应用程序。

## 配置元数据

Spring 支持三种形式的配置元数据来配置您的 bean：

+   基于 XML 的配置元数据

+   基于注解的配置元数据

+   基于 Java 的配置元数据

您在之前看到的示例代码清单使用了基于 XML 的配置元数据。您可以在单个应用程序中随时混合和匹配不同形式的元数据。例如，您可以定义主要元数据为根 XML 文件，该文件组合了一组基于注解的元数据，这些元数据反过来定义了来自不同层的 bean。

### 基于 XML 的配置元数据

在之前的 Spring 应用程序示例中看到的`application-context.xml`文件是基于 XML 的配置元数据的一个非常简单的示例。Bean 被配置为顶级`<beans>`元素内的`<bean/>`元素。

代表服务层（核心业务逻辑，也称为**Service**类）、数据访问对象（**DAOs**）、管理的网络后备 bean（如 Struts 操作实例和 JSF 管理的 bean）、基础设施对象（如 Hibernate 会话工厂和 JMS 队列）等等，都是 Spring bean 的绝佳候选对象。细粒度的领域对象通常不被配置为 Spring bean，因为通常是 DAO 和业务逻辑的责任来创建和加载领域对象——Hibernate 实体是典型的例子。

您可以创建一个合并（根）`ApplicationContext` XML 文件，导入表示应用程序各层的其他 XML 文件：

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans ...>

   <import resource="/xml-data-access-objects.xml"/>
   <import resource="/xml-services.xml"/>
   <import resource="/web-beans.xml"/>
   <import resource="/rest-endpoints.xml"/>
...
   <bean id="systemSettings" class="com...SystemSettings">
</beans>
```

### 基于注解的配置元数据

这种方法依赖于字节码元数据来连接组件，而不是基于 XML 的尖括号声明。Bean 的配置是在 bean 本身的源级别上定义的，以类、字段或方法级别的注解形式。

让我们来看一个通过源级别注解配置的最简单的 Spring bean：

```java
@Component("Greeter")
public class GreetingServiceImpl implements GreetingService {

   Logger logger = LoggerFactory.getLogger(GreetingService.class);

   public void greet(String message) {
      logger.info("Greetings! " + message);
   }
}
```

这只是与*您的第一个 Spring 应用程序*部分中显示的相同的`GreetingServiceImpl`的带注释版本，在那里它纯粹以 XML 形式在`application-context.xml`文件中配置。在前面的清单中，注解`@Component`使其成为 Spring bean。现在，它不需要在 XML 中定义，但您应该指示您的`ApplicationContext`考虑注解，如下面的代码所示：

```java
<context:component-scan base-package="com.springessentialsbook"/>
```

在您的`application-context.xml`文件中的此代码片段会强制`ApplicationContext`扫描整个应用程序，包括其所有依赖项，甚至包括 JAR 文件中的组件，这些组件被注释为 Spring bean 的各种原型，例如`@Component`，`@Service`，`@Repository`和`@Controller`。除了组件扫描，`ApplicationContext`还会查找该 bean 中的所有注释，包括类、属性、构造函数和方法级别（包括 setter 方法），以便在启动时将依赖项和其他行为注入到您的 bean 中。

注意，如果您为`base-package`属性提供了更广泛的包名称，组件扫描可能会耗费时间；建议提供更具体的包名称进行扫描（例如，一组逗号分隔的包名称），以便更好地控制。您甚至可以使用`<context:include-filter/>`和`<context:exclude-filter/>`进一步缩小组件扫描的范围。

启用注释配置的另一个简单指令是`<context:annotation-config/>`。它只会查找应用程序上下文中注册的 bean 上的注释，不会检测组件，而如果您使用`<context:component-scan/>`，它会处理组件扫描和其他注释，这将在本章后面进行介绍，因此您不需要显式声明`<context:annotation-config/>`。因此，基于注释的配置的最佳方法是使用`<context:annotation-config/>`。

### 基于 XML 与基于注释的配置

基于 XML 的配置与基于注释的配置相比具有一些优势。最大的优势是所有 bean 定义都在一个地方，而不是分散在许多类甚至 JAR 依赖项中。XML 允许您拆分元数据文件，然后使用`<import/>`将它们组合起来。使用 XML，您可以配置任何类，包括 Spring bean 等第三方类，并将依赖项和其他服务注入其中，这在注释的情况下是不可能的。此外，您可以将同一类定义为多个不同的 bean，每个 bean 具有不同的名称、依赖项、配置等。

基于注释的元数据也比 XML 配置具有一些优势。它更简洁，更容易开发和维护，因为您的注释和 DI 就在源代码中。关于类的所有信息都在一个地方。

对于更大的应用程序，最佳选择是混合方法，其中更可重用的 bean（在多个项目之间共享的库）和第三方组件在 XML 中进行配置，而范围较小的 bean 则进行注释。

### 组件原型注释

Spring 为代表各种角色的 bean 提供了更多的组件原型。主要的原型是`@Component`，其他所有原型都是其更具体用例的特殊化：

| 原型 | 描述 |
| --- | --- |
| `@Component` | 所有 Spring 管理的组件（bean）的通用类型。 |
| `@Service` | 服务层组件的标记元注释。目前，Spring 将其视为`@Component`，没有特殊功能。 |
| `@Repository` | 用作持久化层中的 DAO。Spring Data 库提供了额外的功能。 |
| `@Controller` | 处理 Web MVC 端点，以处理映射到特定 URL 的 HTTP 请求。 |
| `@RestController` | 用于 RESTful Web 服务的专用控制器，属于 Web MVC 的一部分。它是一个元注释，结合了`@Controller`和`@ResponseBody`。 |

可以通过从头开始定义元注释或组合现有注释来创建自定义原型。

### 基于 Java 的配置元数据

从 Spring 3.0 开始，您可以纯粹在 Java 类中配置 Spring 元数据，完全避免任何 XML 配置，同时增强基于注解的元数据。您可以在任何 Java 类上用`@Configuration`注解进行注解，并在工厂方法上用`@Configuration`注解进行注解，该工厂方法实例化`@Component`注解或任何其他专门的 bean 来定义应用程序上下文。让我们看一个简单的例子：

```java
@Configuration
@ComponentScan(basePackages = "com.springessentialsbook")
public class SpringJavaConfigurator {

    @Autowired
    private GreetingService greeter;

    @Autowired
    private BannerService banner;

    @Bean
    public BannerService createBanner() {
        return new BannerService();
    }

    public BannerService getBanner() {
        return this.banner;
    }

    public void run() {
        this.banner.displayBanner();
        this.greeter.greet("I am the Greeter Spring bean, configured with Java Configuration.");
    }
}
```

在`SpringJavaConfigurator.java`中，Java 配置类配置 Spring bean，替换了`application-context.xml`文件。您的 Spring 应用程序可以直接依赖于这个`Configuration`类来加载`ApplicationContext`。

通常，您使用`AnnotationConfigApplication`实例来实例化应用程序上下文：

```java
ApplicationContext ctx = new AnnotationConfigApplicationContext(
  SpringJavaConfigurator.class);
SpringJavaConfigurator app = ctx.getBean(SpringJavaConfigurator.class);
app.run();
BannerService banner = ctx.getBean(BannerService.class);
banner.displayBanner();
```

当`@Configuration`类作为构造函数参数提供时，`@Configuration`类本身将被注册为 bean 定义，类中声明的所有`@Bean`方法也将被注册为 bean 定义。Spring 将扫描整个项目及其依赖项，寻找`@Component`或其特殊化（之前列出的其他原型），将`@ComponentScan(basePackages = "…")`中提供的参数值与所有其他相关注解进行匹配，并构建应用程序上下文。

JavaConfig 元数据的优势在于您可以对 Spring 配置进行编程控制，同时将整个 DI 和 bean 配置分离到单独的 Java 类中。使用 JavaConfig，您可以消除管理许多 XML 文件的复杂性。您可以在开发过程中尽早检测到任何配置问题，因为 JavaConfig 在编译时就会失败，而在 XML 的情况下，您只能在应用程序启动时了解配置问题。

### JSR 330 标准注解

除了 Spring 特定的注解外，Spring 还支持 JSR 330 标准注解用于 DI，从 Spring 3.0 开始。您只需要在 Maven 或 Gradle 配置中包含`javax.inject`构件。

JSR 330 标准注解在 Spring 中有以下等价物：

| Spring | JSR-330 (javax.inject.*) | 目标级别/用法 |
| --- | --- | --- |
| `@Component` | `@Named` | 类型（类） |
| `@Autowired` | `@Inject` | 属性和 setter 方法 |
| `@Qualifier` | `@Named` | 类型、属性和 setter 方法 |
| `@Scope("singleton")` | `@Singleton` | 用于 bean 声明的元注解 |

虽然 Spring bean 的默认作用域是`singleton`，但 JSR 330 的默认作用域类似于 Spring 的`prototype`。但是，为了保持一致，Spring 将 Spring 中的 JSR 330 注解的 bean 视为`singleton`，除非使用`@Scope("..")`显式声明为 prototype。

JSR 330 没有一些基于 Spring 的 DI 注解的等价物，例如`@Value`，`@Required`和`@Lazy`。我们将在本章后面更多地讨论 bean 作用域。

# 详细的 bean

Spring 应用程序由一组 bean 组成，这些 bean 执行特定于应用程序层的功能，并由 IoC 容器管理。您可以使用 XML、注解或 JavaConfig 的配置元数据定义您的 bean。

### 注意

Spring bean 的默认作用域是`singleton`。这意味着单个实例在应用程序中的任何位置之间共享。要注意在`singleton`类中保持状态（类级数据），因为一个客户端设置的值将对所有其他客户端可见。这种`singleton`类的最佳用例是无状态服务。

Bean 通过`id`属性唯一标识，也可以通过 bean 定义中提供的任何值（逗号、分号或空格分隔）的`name`属性，甚至作为`alias`定义。您可以在应用程序中的任何位置引用 bean，使用`id`或在 bean 定义中指定的任何名称或别名。

并不总是必须为 bean 提供`id`或名称。如果没有提供，Spring 将为其生成一个唯一的 bean 名称；但是，如果您想要用名称或`id`引用它，那么您必须提供一个。

如果没有提供`id`或名称，Spring 将尝试按类型自动装配 bean。这意味着`ApplicationContext`将尝试匹配具有相同类型或实现的 bean，如果它是一个接口。

如果一个 bean 是该类型的唯一注册 bean，或者标记为`@Primary`（对于 XML 为`primary="true"`），则可以按类型引用该 bean。通常，对于嵌套的 bean 定义和自动装配的协作者，除非您在定义之外引用它，否则不需要定义名称。

您可以使用`<alias/>`标签在 bean 定义之外为 bean 创建别名，如下所示：

```java
<alias name="fromName" alias="toName"/>
```

## Bean 定义

您定义的用于描述 bean 的 bean 定义对象具有以下元数据：

| 属性 | 描述 |
| --- | --- |
| `class` | bean 的完全限定类名。 |
| `id` | bean 的唯一标识符。 |
| `name` | 一个或多个由逗号、分号或空格分隔的唯一名称。通常，`id`和名称将是相同的，您可以提供其中一个。列表中的其他名称将成为别名。 |
| `parent` | 从父 bean 定义继承配置数据的父 bean。 |
| `scope` | 这决定了对象的范围。Spring bean 的默认范围是`singleton`。这意味着在调用之间共享单个实例。我们将在后面讨论更多关于 bean 范围的内容。 |
| `constructor args` | 用于基于构造函数的 DI 的 bean 引用或名称。 |
| `properties` | 用于基于 setter 的 DI 的值或引用。 |
| `autowire`模式 | 指示 bean 是否以及如何自动装配与协作者的关系。自动装配将在后面讨论。 |
| `primary` | 这表示在发现多个匹配项时，bean 应被视为主要的自动装配候选项。 |
| `depends-on` | 这会强制在此 bean 之前实例化依赖的 bean。 |
| `lazy-init` | 如果为 true，则在首次请求时创建 bean 实例。 |
| `init-method` | 初始化回调方法。这是一个没有`args void`方法，将在实例创建后调用的方法。 |
| `destroy-method` | 销毁回调方法。这是一个没有`args void`方法，将在销毁之前调用的方法。 |
| `factory-method` | bean 本身上的静态实例工厂方法，除非提供了`factory-bean`。 |
| `factory-bean` | 作为此 bean 的实例工厂的另一个 bean 引用。通常与`factory-method`属性一起使用。 |

让我们看一个 XML 形式的示例 bean 定义：

```java
<bean id="xmlTaskService" class="com...XmlDefinedTaskService"
init-method="init" destroy-method="cleanup">
   <constructor-arg ref="userService"/>
   <constructor-arg>
      <bean class="com...TaskInMemoryDAO"></bean>
   </constructor-arg>
</bean>
```

在这个示例的`application-context`文件中，bean `xmlTaskService`是通过构造函数进行自动装配的，也就是说，依赖项是通过构造函数注入的。第一个构造函数参数是指现有的 bean 定义，第二个是一个没有`id`的内联 bean 定义。该 bean 具有`init-method`和`destroy-method`指向其自己的方法。

现在，让我们来看一个带有稍微不同特性的注释 bean：

```java
@Service
public class AnnotatedTaskService implements TaskService {

...
   @Autowired
   private UserService userService;

   @Autowired
   private TaskDAO taskDAO;

   @PostConstruct
   public void init() {
      logger.debug(this.getClass().getName() + " started!");
   }

   @PreDestroy
   public void cleanup() {
      logger.debug(this.getClass().getName() + " is about to destroy!");
   }

   public Task createTask(String name, int priority, int createdByuserId, int assigneeUserId) {
      Task task = new Task(name, priority, "Open",
         userService.findById(createdByuserId), null,
         userService.findById(assigneeUserId));
      taskDAO.createTask(task);
      logger.info("Task created: " + task);
      return task;
   }
...
}
```

这个`@Service` bean 在其字段（属性）上使用`@Autowired`注解自动装配其依赖项。请注意`@PostConstruct`和`@PreDestroy`注解，这是之前的 XML bean 定义示例中`init-method`和`destroy-method`的等价物。这些不是 Spring 特定的，而是 JSR 250 注解。它们与 Spring 非常配合。

## 实例化 bean

Bean 定义是实例化 bean 实例的配方。根据`scope`、`lazy`和`depends-on`等元数据属性，Spring 框架决定何时以及如何创建实例。我们将在后面详细讨论。在这里，让我们看一下实例创建的“如何”。

### 使用构造函数

任何具有或不具有构造函数参数但没有`factory-method`的 bean 定义都是通过其自己的构造函数实例化，使用`new`运算符：

```java
<bean id="greeter" class="com...GreetingBean"></bean>
```

现在让我们看一个带有默认基于构造函数实例化的注释`@Component`：

```java
@Component("greeter")
public class GreetingService {
...
}
```

### 具有静态工厂方法

在这种情况下，将调用同一类中标记为`factory-method`的静态方法来创建一个实例：

```java
<bean id="Greeter" class="...GreetingBean" factory-method="newInstance"></bean>
```

使用 Java 配置时，您可以使用`@Bean`注解而不是工厂方法：

```java
@Configuration
@ComponentScan(basePackages = "com.springessentialsbook")
public class SpringJavaConfigurator {
...
   @Bean
   public BannerService createBanner() {
      return new BannerServiceImpl();
   }
...
}
```

### 使用实例工厂方法

在这种情况下，bean 定义不需要 class 属性，但您可以指定`factory-bean`属性，这是另一个 bean，其中一个非静态方法作为`factory-method`：

```java
<bean id="greeter"  factory-bean="serviceFactory" factory-method="createGreeter"/>
<bean id="serviceFactory"  class="...ServiceFactory">
<!— ... Dependencies ... -->
</bean>
```

## 注入 bean 依赖

IoC 容器的主要目的是在将对象（bean）返回给调用实例的客户端之前解析对象（bean）的依赖关系。Spring 根据 bean 配置透明地执行此操作。当客户端接收 bean 时，除非指定为不需要（`@Autowired(required = false)`），否则所有依赖项都已解析，并且可以立即使用。

Spring 支持两种主要的 DI 变体 - 基于构造函数和基于 setter 的 DI - 开箱即用。

### 基于构造函数的依赖注入

在基于构造函数的 DI 中，将依赖项注入到 bean 作为构造函数参数。基本上，容器调用定义的构造函数，传递参数的解析值。最佳实践是通过构造函数解析强制依赖项。让我们看一个简单的 POJO `@Service`类的示例，这是基于构造函数的 DI 的一个准备好的候选者：

```java
public class SimpleTaskService implements TaskService {
...
   private UserService userService;
   private TaskDAO taskDAO;

   public SimpleTaskService(UserService userService, TaskDAO taskDAO) {
      this.userService = userService;
      this.taskDAO = taskDAO;
   }
...
}
```

现在，让我们在 XML 中将其定义为 Spring bean：

```java
<bean id="taskService" class="com...SimpleTaskService"">
   <constructor-arg ref="userService" />
   <constructor-arg ref="taskDAO"/>
</bean>
```

Spring 容器通过构造函数解析依赖项的类型。对于前面的示例，您不需要传递参数的索引或类型，因为它们是复杂类型。

然而，如果您的构造函数具有简单类型，例如基本类型（`int`，`long`和`boolean`），基本包装类型（`java.lang.Integer`，`Long`等）或`String`，可能会出现类型和索引的歧义。在这种情况下，您可以显式指定每个参数的类型和索引，以帮助容器匹配参数，如下所示：

```java
<bean id="systemSettings" class="com...SystemSettings">
   <constructor-arg index="0" type="int" value="5"/>
   <constructor-arg index="1" type="java.lang.String" value="dd/mm/yyyy"/>
   <constructor-arg index="2" type="java.lang.String" value="Taskify!"/>
</bean>
```

记住，索引编号从零开始。基于 setter 的注入也是如此。

### 基于 setter 的依赖注入

在构造函数（带或不带`args`）被调用后，容器会调用您的 bean 的 setter 方法。让我们看看如果依赖项通过 setter 方法注入，假设`SystemSettings`现在有一个`no-args`构造函数，那么前面的`SystemSettings`的 bean 定义会是什么样子：

```java
<bean id="systemSettings" class="com...SystemSettings">
   <property name="openUserTasksMaxLimit" value="5"/>
   <property name="systemDateFormat" value="dd/mm/yyyy"/>
   <property name="appDisplayName" value="Taskify!"/>
</bean>
```

Spring 在`ApplicationContext`启动时验证 bean 定义，并在配置错误的情况下失败并提供适当的消息。给定给内置类型的属性的字符串值，例如`int`，`long`，`String`和`boolean`，在创建 bean 实例时会自动转换和注入。

## 基于构造函数或基于 setter 的 DI - 哪种更好？

这些 DI 方法中哪种更好纯粹取决于您的场景和一些要求。以下最佳实践可能提供指导：

1.  对于强制依赖项，请使用基于构造函数的 DI，以便在首次调用时准备好使用您的 bean。

1.  当您的构造函数被填充了大量的参数时，这是一种比喻性的糟糕代码味道。是时候将您的 bean 分解成更小的单元以便于维护。

1.  仅在可选依赖项或需要稍后重新注入依赖项时使用基于 setter 的 DI，也许使用 JMX。

1.  避免循环依赖，当您的 bean（bean A）的依赖项（例如，bean B）直接或间接地再次依赖于相同的 bean（bean A），并且所有涉及的 bean 都使用基于构造函数的 DI 时。您可以在这里使用基于 setter 的 DI。

1.  您可以为同一个 bean 混合使用基于构造函数和基于 setter 的 DI，考虑到强制、可选和循环依赖。

在典型的 Spring 应用程序中，您可以看到使用两种方法注入依赖项，但这取决于情况，考虑到前面的准则。

## 使用命名空间快捷方式使 bean 定义更清晰

您可以使用`p:(property)`和`c:(constructor)`命名空间使 bean 定义更清晰、更具表现力，如下所示。`p`命名空间使您能够使用`<bean/>`元素的属性来描述您的属性值（或协作 bean 引用），而不是嵌套的`<property/>`元素，而`c`命名空间允许您将构造函数`args`声明为`<bean/>`元素的属性：

```java
<beans     xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd http://www.springframework.org/schema/context/spring-context.xsd">

   <bean id="p-taskService" class="com...SimpleTaskService" c:userService-ref="userService" c:taskDAO-ref="taskDAO"/>

   <bean id="p-systemSettings" class="com...SystemSettings"
      p:openUserTasksMaxLimit="5"
      p:systemDateFormat"dd/mm/yyyy"
      p:appDisplayName="Taskify!"/>
</beans>
```

前面列表中的 bean 定义更清晰，但更具表现力。`c:`和`p:`命名空间都遵循相同的约定。在使用`<bean/>`元素之前，您需要在 XML 根元素(`<beans/>`)中声明两者。请注意，您需要使用`-ref`后缀来引用 bean。

## 将列表作为依赖项连接

偶尔，我们需要将静态数据集注入为 bean 的依赖项。Spring 提供了一种自然的方法来连接列表。看看这个例子：

```java
<bean id="systemSettings" class="com...SystemSettings">
. . .
  <constructor-arg>
    <list>
      <value>admin@taskify.ae</value>
      <value>it@taskify.ae</value>
      <value>devops@taskify.ae</value>
    </list>
  </constructor-arg>
</bean>
```

上面的例子简单地连接了一个`java.util.List<String>`。如果您的列表包含一组 bean，您可以将`<value>`替换为`<ref>`或`<bean>`。

## 将 Map 作为依赖项连接

您也可以以类似的方式注入`java.util.Map`实例。看看这个例子：

```java
<bean id="systemSettings" class="com...SystemSettings">
. . .
  <property name="emails">
    <map>
      <entry key="admin" value="admin@taskify.ae"></entry>
      <entry key="it" value="it@taskify.ae"></entry>
      <entry key="devops" value="devops@taskify.ae"></entry>
    </map>
  </property>
</bean>
```

您可以将 bean 注入为值，将`<value>`替换为`<ref>`或`<bean>`。

## 自动装配依赖项

Spring 可以通过检查`ApplicationContext`中存在的 bean 定义来自动装配 bean 的依赖项，如果您指定了自动装配模式。在 XML 中，您可以指定`<bean/>`元素的`autowire`属性。或者，您可以使用`@Autowired`注解来自动装配依赖项。Spring 支持四种自动装配模式：`no`、`byName`、`byType`和`constructor`。

### 注意

Spring bean 的默认自动装配是`byType`。如果您正在自动装配一个接口，Spring 将尝试找到配置为 Spring bean 的该接口的实现。如果有多个，Spring 将查找配置的`primary`属性来解决；如果找不到，它将失败，并抱怨模糊的 bean 定义。

以下是自动装配构造函数参数的示例：

```java
@Service
public class AnnotatedTaskService implements TaskService {
...
   @Autowired
   public AnnotatedTaskService(UserService userService, TaskDAO taskDAO) {
      this.userService = userService;
      this.taskDAO = taskDAO;
   }
...
}
```

或者，您可以在字段级别进行自动装配，如下所示：

```java
@Service
public class AnnotatedTaskService implements TaskService {
...
   @Autowired
   private UserService userService;
   @Autowired
   private TaskDAO taskDAO;
...
}
```

自动装配可以通过`@Qualifier`注解和 required 属性进行微调：

```java
@Autowired(required = true)
@Qualifier("taskDAO")
private UserService userService;
```

您也可以在构造函数级别使用`@Qualifier`：

```java
@Autowired
public AnnotatedTaskService(@Qualifier("userService") UserService userService, @Qualifier("taskDAO") TaskDAO taskDAO) {
   this.userService = userService;
   this.taskDAO = taskDAO;
}
```

## Bean 范围

在定义一个带有其依赖项和其他配置值的 bean 时，您可以选择在 bean 定义中指定 bean 的范围。范围决定了 bean 的生命周期。Spring 提供了六种内置的范围，并支持创建自定义范围。如果没有明确指定，bean 将假定为`singleton`范围，这是默认范围。以下表列出了内置的 Spring 范围：

| 范围 | 描述 |
| --- | --- |
| `singleton` | 这确保容器内只有一个实例。这是默认范围。 |
| `prototype` | 每次请求 bean 时都会创建一个新实例。 |
| `request` | 具有每个新 HTTP 请求的生命周期。 |
| `session` | 具有每个新 HTTP 会话的生命周期。 |
| `globalSession` | 在 portlet 环境中具有 HTTP 会话的范围。 |
| `application` | 具有`ServletContext`的生命周期。对于`ServletContext`来说是`singleton`。 |

虽然`singleton`和`prototype`在所有环境中都适用，但 request、session 和 application 只在 web 环境中适用。`globalSession`范围适用于 portlet 环境。

在 XML bean 定义中，范围是通过`<bean/>`元素的`scope`属性设置的：

```java
<bean id="userPreferences" class="com...UserPreferences" scope="session">... </bean>
```

您可以将 bean 作用域注释为@Component 或其派生类，例如@Service 和@Bean，如下列表所示：

```java
@Component
@Scope("request")
public class TaskSearch {...}
```

通常，服务类和 Spring 数据存储库被声明为`singleton`，因为它们根据最佳实践构建为无状态。

## 使用作用域 bean 进行依赖注入

不同作用域的 bean 可以在配置元数据中作为协作者进行连接。例如，如果您将会话作用域的 bean 作为`singleton`的依赖项，并且面临一致性问题，那么会话作用域的 bean 的第一个实例将在所有用户之间共享。这可以通过在作用域 bean 的位置使用作用域代理来解决：

```java
<bean id="userPreferences" class="com...UserPreferences" scope="session">
   <aop:scoped-proxy />
</bean>
<bean id="taskService" class="com...TaskService">
   <constructor-arg ref="userPreferences"/>
</bean>
```

每次注入作用域 bean 时，Spring 都会在 bean 周围创建一个新的 AOP 代理，以便从确切的作用域中选择实例。前述列表的注释版本将如下所示：

```java
@Component
@Scope(value = "session", proxyMode = ScopedProxyMode.TARGET_CLASS)
public class UserPreferences { ... }

public class AnnotatedTaskService implements TaskService {
...
   @Autowired
   private UserPreferences userPreferences;
...
}
```

## 创建自定义作用域

有时，Spring 提供的作用域不足以满足您的特定需求。Spring 允许您为您的场景创建自定义作用域。例如，如果您想在整个业务流程中保留一些信息，您将需要创建一个新的流程作用域。以下步骤将帮助您实现这一目标：

1.  创建一个扩展`org.springframework.beans.factory.config.Scope`的 Java 类。

1.  在应用程序上下文（XML 或注释）中定义为 Spring bean。

1.  使用`CustomScopeConfigurer`在 XML 中以编程方式或注册作用域 bean 到您的`ApplicationContext`。

# 连接到 bean 生命周期

在企业应用程序开发中，开发人员通常希望在业务服务的构建之后和销毁之前执行一些额外的功能。Spring 提供了多种与 bean 生命周期中这些阶段交互的方法。

## 实现 InitializingBean 和 DisposableBean

Spring IoC 容器在任何 Spring bean 上调用`org.springframework.beans.factory.InitializingBean`的`afterPropertiesSet()`和`org.springframework.beans.factory.DisposableBean`的`destroy()`回调方法并实现它们：

```java
public class UserServiceImpl implements UserService, InitializingBean, DisposableBean {
...
   @Override
   public void afterPropertiesSet() throws Exception {
      logger.debug(this + ".afterPropertiesSet() invoked!");
      // Your initialization code goes here..
   }

   @Override
   public void destroy() throws Exception {
      logger.debug(this + ".destroy() invoked!");
      // Your cleanup code goes here..
   }
...
}
```

## 在@Component 上注释@PostConstruct 和@PreDestroy

Spring 支持在注释支持的环境中的任何 Spring bean 上使用 JSR 250 `@PostConstruct`和`@PreDestroy`注释，如下所示。Spring 鼓励使用这种方法而不是实现 Spring 特定的接口，如前一节所述：

```java
@Service
public class AnnotatedTaskService implements TaskService {
...
   @PostConstruct
   public void init() {
      logger.debug(this.getClass().getName() + " started!");
   }

   @PreDestroy
   public void cleanup() {
      logger.debug(this.getClass().getName() + " is about to destroy!");
   }
...
}
```

## <bean/>的 init-method 和 destroy-method 属性

如果您只使用 XML bean 配置元数据，则最佳选择是在<bean/>标签上声明`init-method`和`destroy-method`属性：

```java
<bean id="xmlTaskService" class="com...XmlDefinedTaskService" init-method="init" destroy-method="cleanup">
...
</bean>
```

# 容器级别的默认 init-method 和 default-destroy-method

您甚至可以设置容器级别的默认`init`和`destroy`方法，这样您就不需要为每个 bean 设置它。只有在 bean 存在时，容器才会调用这些方法：

```java
<beans default-init-method="init" default-destroy-method="cleanup">
...
</beans>
```

# 使用 bean 定义配置文件

对于商业项目，通常需要能够维护两个或更多特定于环境的配置和 bean，只在相应的环境中选择性地激活。例如，数据源、电子邮件服务器和安全设置等对象可能在开发、测试和生产环境中不同。您希望在不触及应用程序代码的情况下以外部方式声明地切换它们。开发人员传统上会编写复杂的脚本和属性文件，使用单独的构建来完成这项工作。Spring 在这里通过使用 bean 定义配置文件和属性的环境抽象来拯救您。

Bean 定义配置文件是一种通过该机制为不同环境配置应用程序上下文的方法。您可以在 XML 中或使用注释将 bean 定义分组到命名配置文件下，并在每个环境中激活一个或多个配置文件。如果您没有明确指定，可以设置默认配置文件以启用。

让我们看一下以下示例列表，该列表配置了开发和生产环境的数据源：

```java
@Configuration
@ComponentScan(basePackages = "com.springessentialsbook")
public class ProfileConfigurator {

   @Bean
   @Profile("dev")
   public DataSource devDataSource() {
      return new EmbeddedDatabaseBuilder()
         .setType(EmbeddedDatabaseType.HSQL) .addScript("scripts/tasks-system-schema.sql") .addScript("scripts/tasks-master-data.sql") .build();
   }
   @Bean
   @Profile("prod")
   public DataSource productionDataSource() throws Exception {
      Context ctx = new InitialContext();
      return (DataSource) ctx.lookup("java:comp/env/jdbc/datasource/tasks");
   }
}
```

实际上，对于生产环境，将此配置文件外部化为 XML 会是一个更好的主意，您可以允许您的 DevOps 团队为不同的环境修改它，并禁止他们触及您的 Java 代码。XML 配置将如下所示：

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans 

  xsi:schemaLocation="...">
  <!-- other bean definitions -->
  <beans profile="dev">
    <jdbc:embedded-database id="dataSource">
      <jdbc:script location="classpath:scripts/tasks-system-schema.sql"/>
      <jdbc:script location="classpath:scripts/tasks-master-data.sql"/>
    </jdbc:embedded-database>
  </beans>

  <beans profile="production">
    <jee:jndi-lookup id="dataSource" jndi-name="java:comp/env/jdbc/datasource"/>
  </beans>
</beans>
```

您可以创建尽可能多的配置文件；每个开发人员通常会维护自己的配置文件，配置文件以其自己的名称命名，例如`@Profile("mary")`。您也可以同时激活多个配置文件；这取决于您如何组织它们，以避免冲突或在配置文件之间重复定义 bean。

现在您可以在每个（`dev`、`test`或`prod`）环境中根据需要激活一个或多个配置文件，使用以下任一方法：

1.  以编程方式调用`ctx.getEnvironment().setActiveProfiles("p1", "p2", ..)`。

1.  将属性`spring.profile.active`设置为以逗号分隔的配置文件名作为值的环境变量、JVM 系统属性或`web.xml`中的 Servlet 上下文参数。

1.  在启动应用程序时，将`-Dspring.profile.active="p1,p2, .."`添加为命令行或 Java 参数。

# 将属性注入 Spring 环境

除了使用配置文件分离环境特定配置之外，您仍然需要将许多属性外部化，例如数据库 URL、电子邮件和日期格式，以便更轻松地处理。然后这些属性要么直接注入到 bean 中，要么在运行时由 bean 从环境中读取。Spring 的环境抽象与`@PropertySource`注解使这在 Spring 应用程序中成为可能。

`@PropertySource`注解提供了一个方便和声明性的机制，用于向 Spring 的环境添加`PropertySource`。

```java
@Configuration
@PropertySource("classpath:application.properties")
@ComponentScan(basePackages = "com.springessentialsbook")
public class SpringJavaConfigurator {
...
   @Autowired
   @Lazy
   private SystemSettings systemSettings;

   @Autowired
   private Environment env;

   @Bean
   public SystemSettings getSystemSettings() {
      String dateFormat = env.getProperty("system.date-format");
      String appDisplayName = env.getProperty("app.displayname");

      return new SystemSettings(dateFormat, appDisplayName);
   }
…
}
```

# 使用`PropertyPlaceholderConfigurer`外部化属性

`PropertyPlaceholderConfigurer`是另一个方便的实用程序，用于将 bean 定义中的属性值外部化到使用标准`java.util.Properties`格式的单独文件中。它将 XML bean 定义中的占位符替换为配置的属性文件中的匹配属性值，如下所示。这是外部化配置文件的最佳方式，例如数据源配置、电子邮件设置等。DevOps 团队将只编辑这些属性文件，而不会影响您的代码：

```java
<bean class="org.springframework.beans.factory.config.PropertyPlaceholderConfigurer">
    <property name="locations" value="classpath:datasource.properties"/>
</bean>

<bean id="dataSource" destroy-method="close"
        class="org.apache.commons.dbcp.BasicDataSource">
    <property name="driverClassName" value="${jdbc.driverClassName}"/>
    <property name="url" value="${jdbc.url}"/>
    <property name="username" value="${jdbc.username}"/>
    <property name="password" value="${jdbc.password}"/>
</bean>
```

以下是`PropertyPlaceholder`的另一个更简单的声明：

```java
<context:property-placeholder location="classpath:datasource.properties"/>
```

# 处理资源

Spring Framework 提供了出色的支持，用于访问低级资源，从而解决了 Java 标准`java.net.URL`和标准处理程序的许多限制。`org.springframework.core.io.Resource`包及其许多具体实现构成了 Spring Framework 强大资源处理的坚实基础。

Spring 本身广泛使用资源抽象，在许多`ApplicationContext`的实现中——在自己的代码中作为通用实用类使用资源是非常有用的。您将在 Spring 的开箱即用资源实现中找到以下资源实现：

| 资源实现 | 描述 |
| --- | --- |
| `UrlResource` | 它包装了`java.net.URL`，用于访问可以通过 URL 访问的任何内容，例如文件（`file:///`）、HTTP 目标（`http://`）和 FTP 目标（`ftp://`）。 |
| `ClassPathResource` | 用于使用前缀`classpath:`从类路径访问任何资源。 |
| `FileSystemResource` | 这是`java.io.File`的资源实现。 |
| `ServletContextResource` | 这是从父 bean 定义继承配置数据的父 bean。 |
| `InputStreamResource` | 这是给定`InputStream`的资源实现。 |

通常，您不会直接实例化这些资源；相反，您可以使用`ResourceLoader`接口来为您完成这项工作。所有的`ApplicationContext`都实现了`ResourceLoader`接口；因此，任何`ApplicationContext`都可以用来获取资源实例。其代码如下：

```java
ApplicationContext context = new ClassPathXmlApplicationContext(new String[] {"application-context.xml"});
Resource classPathResource = ctx.getResource("classpath:scripts/tasks-schema.sql");

Resource fileResource = ctx.getResource("file:///scripts/master-data.sql");

Resource urlResource = ctx.getResource("http://country.io/names.json");
```

您可以通过简单地将资源的文件名或 URL 作为参数传递来将资源注入到您的 bean 中，如下所示。`ApplicationContext`，它是一个`ResourceLoader`接口，将根据您提供的 URL 创建适当的资源实现的实例：

```java
@Value("http://country.io/names.json")
private Resource countriesResource;
```

以下是注入资源的 XML 版本：

```java
<property name="countriesResource" value="http://country.io/names.json"/>
```

# Spring 表达式语言

表达式语言通常用于简单的脚本编写，以在非面向对象的上下文中操作对象图。例如，如果我们想要从 JSP，XML 或 XHTML 页面读取数据或调用 Java 对象的方法，JSP EL 和**统一表达式语言（UEL）**就派上用场了。这些表达式语言允许页面作者以简单易用的方式访问外部数据对象，与基于标签的语言（如 XML 和 HTML）兼容。

**Spring 表达式语言**（**SpEL**），其语言语法类似于 UEL，是一个用于在运行时查询和操作对象图的强大表达式语言。它提供了额外的功能，最显著的是方法调用和基本的字符串模板功能。

SpEL 可以在 Spring 系列项目以及许多与 Spring 集成的技术中广泛使用。它可以直接在 Spring 配置元数据文件中使用，无论是在 XML 中还是在 Java 注解中，都可以使用`#{expression-string}`的形式。当与相应的技术（如 JSF，JSP 和 Thymeleaf）集成时，您可以在许多视图技术中使用 SpEL，例如 JSP，XML 和 XHTML。

## SpEL 功能

SpEL 表达式语言支持以下功能：

+   布尔，关系和三元运算符

+   正则表达式和类表达式

+   访问属性，数组，列表和映射

+   方法和构造函数调用

+   变量，赋值和 bean 引用

+   数组构造，内联列表和映射

+   用户定义的函数和模板表达式

+   集合，投影和选择

## SpEL 注解支持

SpEL 可以用来指定字段，方法和方法或构造函数参数的默认值，使用`@Value`注解。以下示例清单包含了一些在字段级别使用 SpEL 表达式的优秀用法：

```java
@Component
@Scope("prototype")
public class TaskSnapShot {

   Value("#{taskService.findAllTasks().size()}")
   private String totalTasks;

   @Value("#{taskService.findAllTasks()}")
   private List<Task> taskList;

   @Value("#{ new java.util.Date()}")
   private Date reportTime;

   @Value("#{taskService.findAllTasks().?[status == 'Open']}")
   private List<Task> openTasks;
...

}
```

相同的方法也可以用于 XML bean 定义。

## SpEL API

通常，大多数用户使用 SpEL 来评估嵌入在 XML，XHTML 或注解中的表达式。虽然 SpEL 作为 Spring 组合中表达式评估的基础，但它也可以在非 Spring 环境中使用 SpEL API 独立使用。SpEL API 提供了引导基础设施，以在任何环境中以编程方式使用 SpEL。

SpEL API 的类和接口位于`org.springframework.expression`的（子）包中。它们提供了规范和默认的 SpEL 实现，可以直接使用或扩展。

以下接口和类构成了 SpEL API 的基础：

| 类/接口 | 描述 |
| --- | --- |
| `Expression` | 表达式的规范，能够独立于任何语言（如 OGNL 或 UEL）对上下文对象进行评估。它封装了先前解析的表达式字符串的细节。 |
| `SpelExpression` | 一个符合 SpEL 的，已解析的表达式，可以独立评估或在指定上下文中使用。 |
| `ExpressionParser` | 解析表达式字符串（模板以及标准表达式字符串）为可以评估的编译表达式。 |
| `SpelExpressionParser` | SpEL 解析器。实例可重用且线程安全。 |
| `EvaluationContext` | 表达式在评估上下文中执行，当在表达式评估过程中遇到引用时会解析引用。 |
| `StandardEvaluationContext` | 默认的`EvaluationContext`实现，使用反射来解析对象的属性/方法/字段。如果这对你的使用不够，你可以扩展这个类来注册自定义的`ConstructorResolver`、`MethodResolver`和`PropertyAccessor`对象，并重新定义 SpEL 如何评估表达式。 |
| `SpelCompiler` | 编译常规解析表达式，而不是解释形式到包含字节码的类进行评估。这是一种更快的方法，但仍处于早期阶段，截至 Spring 4.1，它尚不支持每种类型的表达式。 |

让我们来看一个使用 SpEL API 评估表达式的例子：

```java
@Component
public class TaskSnapshotBuilder {

   @Autowired
   private TaskService taskService;

   public TaskSnapShot buildTaskSnapShot() {
      TaskSnapShot snapshot = new TaskSnapShot();

      ExpressionParser parser = new SpelExpressionParser();
      EvaluationContext context = new StandardEvaluationContext(taskService);
      Expression exp = parser.parseExpression("findAllTasks().size()");
      snapshot.setTotalTasks(exp.getValue(context).toString());

      exp = parser.parseExpression("findAllTasks()");
      snapshot.setTaskList((List<Task>)exp.getValue(context));

      exp = parser.parseExpression("new java.util.Date()");
      snapshot.setReportTime((Date)exp.getValue(context));

      exp = parser.parseExpression("findAllTasks().?[status == 'Open']");
      snapshot.setOpenTasks((List<Task>)exp.getValue(context));

      return snapshot;
   }

}
```

在正常情况下，在 Spring 应用程序中通常不需要直接使用 SpEL API；使用注解或 XML bean 定义的 SpEL 会是更好的选择。SpEL API 主要用于在运行时动态加载外部业务规则。

# 面向切面编程

大多数软件应用程序通常都有一些次要但至关重要的功能，比如安全、事务和审计日志，跨越多个逻辑模块。最好不要将这些横切关注点混合在核心业务逻辑中。**面向切面编程**（**AOP**）可以帮助你实现这一点。

**面向对象编程**（**OOP**）是关于将复杂软件程序模块化，对象是持有核心业务逻辑和数据的基本单元。AOP 是为了在不污染原始对象结构的情况下，在应用程序的模块之间透明地添加更复杂的功能。AOP 将横切关注点编织到程序中，无论是在编译时还是运行时，而不修改基本代码本身。AOP 让面向对象的程序保持干净，只关注核心业务问题。

## 静态和动态 AOP

在 AOP 中，框架会将横切关注点透明地编织到主程序中。这种编织过程有两种不同的方式：静态和动态。在静态 AOP 的情况下，正如其名称所示，切面直接编译到静态文件中，即在编译时编译为 Java 字节码。这种方法性能更好，因为在运行时没有特殊的拦截。但缺点是每次更改代码都需要重新编译整个应用程序。AspectJ 是最全面的 AOP 实现之一，提供了切面的编译时编织。

在动态 AOP 的情况下，编织过程是在运行时动态执行的。不同的框架实现方式不同，但最常见的方式是使用代理或包装器来为被建议的对象允许根据需要调用建议。这是一种更灵活的方法，因为你可以根据数据在运行时应用具有不同行为的 AOP，而这在静态 AOP 的情况下是不可能的。如果使用 XML 文件定义 AOP 构造（基于模式的方法），则无需重新编译主应用程序代码。动态 AOP 的缺点是由于额外的运行时处理而导致的非常微不足道的性能损失。

Spring AOP 是基于代理的，即它遵循动态 AOP 的方式。Spring 提供了与 AspectJ 集成以使用静态 AOP 的功能。

## AOP 概念和术语

理解 AOP 概念和术语为 AOP 提供了一个很好的起点；它帮助你想象 AOP 可以在应用程序中的哪些地方以及如何应用。

+   **切面**：横跨多个类或模块的关注点。事务和安全是例子。Spring 事务是作为切面实现的。

+   **连接点**：程序执行过程中要插入额外逻辑的点，使用 AOP。方法执行和类实例化是例子。

+   建议：在特定连接点执行的切面（代码或方法）采取的行动。不同类型的建议包括`before`、`after`和`around`建议。通常，一个切面有一个或多个建议。

+   切入点：定义或匹配一组连接点的表达式。与切入点相关联的建议在匹配的任何连接点上执行。Spring 默认支持 AspectJ 切入点表达语言。例如，`execution(* com.xyz.service.*.*(..))`。

+   目标对象：被建议的对象。如果使用动态 AOP，这将是一个代理对象。

+   编织：在编译时、加载时或运行时将切面插入目标对象，使其在建议时。AspectJ 支持编译时织入，Spring 在运行时进行编织。

+   引入：向被建议的对象添加新方法或字段的过程，无论是否使其实现接口。

## Spring AOP - 定义和配置样式

Spring 提供了基于代理的 AOP 的动态实现，纯粹在 Java 中开发。它既不需要像 AspectJ 那样特殊的编译过程，也不控制类加载器层次结构，因此可以部署在任何 Servlet 容器或应用服务器中。

尽管不像 AspectJ 那样是一个完整的 AOP 框架，Spring 提供了 AOP 大多数常见特性的简单易用的抽象。它仅支持方法执行连接点；字段拦截未实现。Spring 与 AspectJ 紧密集成，如果您想要建议非常精细的切面定向，Spring AOP 没有涵盖的部分，可以通过添加更多的 AspectJ 特定功能来扩展而不破坏核心 Spring AOP API。

Spring AOP 默认使用标准 JDK 动态代理进行切面定向。JDK 动态代理允许代理任何接口（或一组接口）。如果要代理类而不是接口，可以切换到 CGLIB 代理。如果目标对象没有实现接口，Spring 会自动切换到使用 CGLIB。

从 Spring 2.0 开始，您可以遵循基于模式的方法或`@AspectJ`注释样式来编写自定义切面。这两种样式都提供了完全类型化的建议和使用 AspectJ 切入点语言，同时仍然使用 Spring AOP 进行编织。

## XML 基于模式的 AOP

使用基于模式的 AOP 时，需要将`aop`命名空间标签导入到您的`application-context`文件中，如下所示：

```java
<beans 

    xsi:schemaLocation="
        http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd
        http://www.springframework.org/schema/aop http://www.springframework.org/schema/aop/spring-aop.xsd">
<!-- bean definitions here -->
</beans>
```

## @AspectJ 基于注释的 AOP

`@AspectJ`指的是将切面声明为常规 Java 类并进行注释的风格。Spring 解释相同的注释作为 AspectJ 5，使用由 AspectJ 提供的库进行切入点解析和匹配。Spring AOP 不依赖于 AspectJ 编译器或织入器。

使用`@AspectJ`注释样式时，首先需要在 Spring 配置中启用`@AspectJ`支持，无论是在 XML 还是 Java 配置中。此外，您需要确保在类路径中添加`aspectjweaver.jar`。在 Java `@Configuration`注释中添加`@EnableAspectJAutoProxy`注释将在项目中启用`@AspectJ`支持：

```java
@Configuration
@ComponentScan(basePackages = "com.springessentialsbook")
@EnableAspectJAutoProxy
public class AOPJavaConfigurator {
...
}
```

或者，如果您使用基于 XML 的配置，可以通过在您的`application-context`文件中添加`<aop:aspectj-autoproxy/>`元素来启用`@AspectJ`支持。

## 声明@Aspect 注释

您的切面是一个简单的 POJO，可以使用`@Aspect`（`org.aspectj.lang.annotation.Aspect`）进行注释，或者在`application-context` XML 文件的`<aop:config>`部分下声明为`<aop:aspect/>`。请记住，标记为`@Aspect`的类应该在应用程序上下文 XML 文件中使用注释或`<bean/>`声明声明为 Spring bean。

这是一个带注释的切面，一个 Spring 组件被注释为`@Aspect`：

```java
@Component("auditLoggerAspect")
@Aspect
public class AuditLoggerAspect {
...
}
```

请注意，`@Aspect`也是一个 Spring bean。它可以是`@Component`的任何专业化。

现在，让我们看一下 Aspect 声明的 XML 替代方案：

```java
<aop:config>
   <aop:aspect id="audLogAspect" ref="auditLoggerAspect">
</aop:config>
<bean id="auditLoggerAspect" class="com...AuditLoggerAspect"/>
```

Aspect 可能具有方法和字段，就像任何其他类一样。它们还可以包含切入点、advice 和 introduction（inter-type）声明。Aspect 本身不能成为其他 Aspect 的 Advice 的目标；它们被排除在自动代理之外。

### 切入点

切入点由两部分组成，如下面的代码片段所示：一个方法签名（在`Aspect`类中具有`void`返回类型的空方法）和一个表达式，匹配我们感兴趣的确切方法执行。请记住，Spring AOP 仅支持方法执行连接点：

```java
@Pointcut("execution(* com.springessentialsbook.service.TaskService.createTask(..))") //Pointcut expression
private void createTaskPointCut() {} //Signature
```

切入点表达式遵循标准的 AspectJ 格式。您可以参考 AspectJ 切入点表达式参考以获取详细的语法。下一节将为您构建 Spring AOP 的切入点提供坚实的基础。

#### 切入点设计器

Spring AOP 仅支持原始 AspectJ **切入点设计器**（**PCDs**）的子集，用于切入点表达式，如下表所示：

| PCD | 描述 |
| --- | --- |
| `execution` | 方法执行连接点；Spring AOP 的默认 PCD |
| `within` | 匹配一系列类型、包等中的方法 |
| `this` | 匹配给定类型的代理实例 |
| `target` | 与给定类型匹配目标对象 |
| `args` | 匹配具有给定参数类型的方法 |
| `@target` | 匹配具有给定注解的类的方法 |
| `@args` | 匹配具有给定注解的参数（s）的方法 |
| `@within` | 匹配具有给定注解的类型内的方法 |
| `@annotation` | 匹配具有给定注解的方法 |

除了上表之外，Spring 还支持额外的非 AspectJ PCD，`bean`，它可用于直接引用 Spring bean 或使用逗号分隔的 bean 列表`bean(idsOrNamesOfBean)`。

请注意，由于 Spring AOP 的代理性质，切入点仅拦截`public`方法。如果您想要拦截`protected`和`private`方法甚至构造函数，请考虑使用 AspectJ 编织（与 Spring 集成）。

#### 切入点示例

切入点表达式可以使用`&&`、`||`和`!`进行组合。您也可以通过名称引用切入点表达式。让我们看一些例子：

```java
@Pointcut("execution(* com.taskify.service.*.*(..))")
private void allServiceMethods() {}

@Pointcut("execution(public * *(..))")
private void anyPublicOperation() {}

@Pointcut("anyPublicOperation() && allServiceMethods()")
private void allPublicServiceMethods() {}

@Pointcut("within(com.taskify.service..*)")
private void allServiceClasses() {}

@Pointcut("execution(* set*(..))")
private void allSetMethods() {}

@Pointcut("execution(* com.taskify.service.TaskService.*(..))")
private void allTaskServiceMethods() {}

@Pointcut("target(com.taskify.service.TaskService)")
private void allTaskServiceImplMethods() {} 

@Pointcut("@within(org.springframework.transaction.annotation.Transactional)")
private void allTransactionalObjectMethods() {}

@Pointcut("@annotation(org.springframework.transaction.annotation.Transactional)")
private void allTransactionalAnnotatedMethods() {}

@Pointcut("bean(simpleTaskService)")
private void allSimpleTaskServiceBeanMethods() {}
```

点切定义的 XML 版本如下：

```java
<aop:config>
  ...
   <aop:pointcut id="allTaskServicePointCut"
         expression="execution(*com.taskify.service..TaskService.*(..))"/>
</aop:config>
```

### Advices

Advice 是在切入点表达式匹配的方法执行之前、之后或周围注入的操作。与 Advice 相关联的切入点表达式可以是上面示例中列出的命名或定义的切入点，也可以是在适当位置声明的切入点表达式，即，advice 和切入点可以一起声明。

让我们看一个引用名为`Pointcut`的切入点表达式的 Advice 的示例：

```java
@Pointcut("execution(* com.taskify.service.TaskService.*(..))")
private void allTaskServiceMethods() {}

@Before("allTaskServiceMethods()")
private void logBeforeAllTaskServiceMethods() {
  logger.info("*** logBeforeAllTaskServiceMethods invoked ! ***");
}
```

以下代码清单将连接点和 Advice 结合在一起。这是最常见的方法：

```java
@After("execution(* com.taskigy.service.TaskService.*(..))")
private void logAfterAllTaskServiceMethods() {
  logger.info("***logAfterAllTaskServiceMethods invoked ! ***");
}
```

下表列出了可用的 Advice 注释：

| Advice 注释 | 描述 |
| --- | --- |
| `@Before` | 方法执行前运行。 |
| `@After` | 方法退出后运行（最终）。 |
| `@AfterReturning` | 方法返回时运行，没有异常。您可以将返回值与 Advice 绑定为方法参数。 |
| `@AfterThrowing` | 方法通过抛出异常退出后运行。您可以将异常与 Advice 绑定为方法参数。 |
| `@Around` | 目标方法实际上在此 Advice 中运行。它允许您在 Advice 方法内部操纵方法执行。 |

#### @Around Advice

`@Around` Advice 可以更好地控制方法的执行，因为拦截的方法实际上在 Advice 方法内部运行。Advice 的第一个参数必须是`ProceedingJoinPoint`。您需要在 Advice 主体内调用`ProceedingJoinPoint`的`proceed()`方法，以执行目标方法；否则，方法将不会被调用。在方法执行返回给您并返回给您的 Advice 后，不要忘记在 Advice 方法中返回结果。看一个`@Around` advice 的示例：

```java
@Around("execution(* com.taskify.service.**.find*(..))")
private Object profileServiceFindAdvice(ProceedingJoinPoint jPoint) throws Throwable {
    Date startTime = new Date();
    Object result = jPoint.proceed(jPoint.getArgs());
    Date endTime = new Date();
    logger.info("Time taken to execute operation: " + jPoint.getSignature() + " is " + (endTime.getTime() - startTime.getTime()) + " ms");
    return result;
}
```

#### 访问 Advice 参数

有两种不同的方法可以在 Advice 方法中访问您正在建议的方法的参数：

+   将连接点声明为第一个参数

+   在切入点定义中绑定`args`

让我们看看第一种方法：

```java
@Before("execution(* com.taskify.service.TaskService.createTask(..)")
private void logBeforeCreateTaskAdvice(JoinPoint joinpoint) {
   logger.info("***logBeforeCreateTaskAdvice invoked ! ***");
   logger.info("args = " + Arrays.asList(joinpoint.getArgs()));
}
```

您可以看到`joinpoint.getArgs()`返回拦截方法传递的所有参数的`Object[]`。现在，让我们看看如何将命名参数绑定到 Advice 方法：

```java
@Before("createTaskPointCut() and args(name, priority, createdByuserId, assigneeUserId)")
private void logBeforeCreateTaskAdvice(String name, int priority, int createdByuserId, int assigneeUserId) {

  logger.info("name = " + name + "; priority = " + priority + ";
  createdByuserId = " + createdByuserId);
}
```

请注意，`joinpoint`表达式通过名称匹配参数。您可以在方法签名中将`joinpoint`对象作为可选的第一个参数，而不在表达式中指定它：这样您将同时拥有`joinpoint`和参数，从而实现更多的操作。

# 使用 Spring 进行测试

可测试性的程度显示了任何框架的优雅和成熟程度。一个更可测试的系统更易于维护。Spring 框架为应用程序的端到端测试提供了全面的支持，包括单元测试和集成测试。Spring 推广**测试驱动开发**（**TDD**），促进集成测试，并倡导一套最佳实践来测试 bean。这是使用 Spring 构建严肃应用程序的另一个令人信服的理由。

Spring bean 基于 POJO 的编程模型和松耦合的特性使得即使没有 Spring 在中间，也更容易参与 JUnit 和 TestNG 测试。此外，Spring 提供了许多测试支持组件、实用工具和模拟对象，以使测试更容易。

## 模拟对象

Spring 提供了许多容器特定组件的模拟实现，以便可以在服务器或容器环境之外测试 bean。`MockEnvironment`和`MockPropertySource`对于测试依赖于环境的 bean 非常有用。为了测试依赖于 HTTP 通信的 bean，Spring 在`org.springframework.mock.http`和`org.springframework.mock.http.client`包中提供了客户端和服务器端的模拟类。

另一组有用的类可以在`org.springframework.mock.jndi`中找到，用于运行依赖于 JNDI 资源的测试套件。`org.springframework.mock.web`包含基于 Servlet 3.0 的 Web 组件的模拟对象，如 Web 上下文、过滤器、控制器和异步请求处理。

## 单元测试和集成测试实用工具

Spring 提供了一些通用和特定上下文的单元测试和集成测试的实用工具。`org.springframework.test.util`包含一组实用类，用于各种测试目的，包括反射、AOP、JSON 和 XML 操作。`org.springframework.test.web`及其嵌套子目录中的类包含了一套全面的实用类，用于测试依赖于 Web 环境的 bean。另一组用于`ApplicationContext`特定用途的实用类可以在`org.springframework.test.context`及其子包中找到。它们的支持包括在测试环境中加载和缓存 Web、Portlet 或应用程序上下文；解析配置文件；加载属性源和 SQL 脚本；管理测试环境的事务等等。

在前面列出的包下的支持类和注解有助于轻松自然地测试 Spring 应用程序。对 Spring 测试支持的全面讨论超出了本书的范围。然而，了解 Spring 对单元测试和集成测试的全面支持对于使用 Spring 开发优雅的代码和可维护的应用程序至关重要。

# 摘要

在本章中，我们成功地涵盖了核心 Spring Framework 的所有主要技术和概念。我们现在能够开发由强大的 Spring IoC 容器中松耦合的 bean 组成的健壮的独立 Spring 应用程序。我们知道如何使用 Spring AOP 的非常灵活的切入点表达式在应用程序的不同层之间透明地应用横切关注点。我们可以使用 Spring Expression Language 操纵 Spring bean，这有助于保持代码清晰和易于维护。我们学会了使用 bean 定义配置文件和属性文件来维护多个特定于环境的 bean 配置。现在，我们已经准备好进行专业的 Spring 开发了。

本章提供的源代码包含了多个 Spring 项目，演示了配置 Spring 以及使用场景的不同方式。本章列出的示例都是从这些项目中提取出来的。

在下一章中，我们将探索 Spring Web 模块，在基于 Web 的环境中利用本章学到的知识。本章学到的主题将成为接下来章节中所有高级主题的基础。



# 第二章：使用 Spring Web MVC 构建 Web 层

Web 应用程序开发是企业系统的一个主要关注领域。在云和大数据时代，Web 应用程序承受着越来越多的并发用户访问的巨大压力，这些用户来自多种设备，如手机、平板以及传统的桌面 Web 浏览器。现代 Web 应用程序必须满足一系列新的非功能性需求，如可伸缩性、性能、生产力、响应性和多设备支持。

Spring MVC 是 Spring 的一个 Web 框架，从头开始完美构建，以解决现代 Web 应用程序的问题。作为一个轻量级高性能的 Web 框架，Spring MVC 旨在从一开始就具有高生产力，灵活，并且能够适应各种视图技术。作为强大的 Spring Framework 的一部分，它与所有 Java EE 技术和其他开源框架都很好地集成。就像 Spring 系列下的任何技术一样，Spring MVC 也通过一组明确定义的注解、命名空间 XML 标签和 Web 支持组件来促进 POJO 编程。

本章向您介绍了 Spring MVC 及其强大的功能，描述了如何设置它，并指导您如何使用相关示例进行高级用法、配置和优化。在这些示例中，我们将主要使用注解以简化操作。在本章结束时，您将能够使用 Spring MVC 构建具有基于 HTML 的用户界面以及具有 JSON 和 XML 格式的 RESTful API 的 Web 应用程序。

# Spring MVC 的特点

Spring MVC 捆绑了一套引人注目的功能和优势，超过了竞争对手的 Web 技术。了解这些将有助于您决定是否选择 Spring MVC 来满足您的需求。以下列表涵盖了大部分内容：

+   简单的配置和与 Spring Framework 的本地集成，利用 Spring 和其他开源库的强大功能

+   基于 Java Web 技术构建，如 Servlets、JSP 和 JSTL，并且可以部署到任何标准的 Servlet 容器中，比如 Tomcat

+   基于**模型-视图-控制器**（**MVC**）架构模式实现，使用简单的注解和命名空间 XML 标签清晰地分离关注点

+   对 MVC 组件的约定优于配置的显式支持

+   支持大量的视图技术，如 JSP、Thymeleaf、Handlebars、Velocity、FreeMarker、PDF、Excel 和 JasperReports

+   声明性输入验证、数据绑定和异常处理

+   灵活的 URL 映射，自动将请求和响应转换为各种格式，如 JSON、XML 和 HTML

+   支持非阻塞异步请求处理和 HTTP 流式传输

+   支持国际化、主题和多部分文件上传

+   与 Spring Security 的轻松集成和全面的可测试性

+   增加性能的 HTTP 缓存

+   一个简单而强大的 JSP 标签库

Spring MVC 的杰出之处在于其简单的编程模型，这是从核心 Spring 框架本身继承的特性。熟悉任何标准 Web 框架的开发人员会发现 Spring MVC 非常熟悉和易于学习。

# 模型-视图-控制器模式

MVC 是一种广泛用于构建交互式 Web 和桌面应用程序的成熟的架构模式。在大多数软件平台上有许多实现这种模式的框架。MVC 将应用程序分为三个核心元素，实际上代表层，分离这三个核心元素之间的关注点，并定义它们如何相互通信。

![模型-视图-控制器模式](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00781.jpeg)

**Model**表示数据，**View**显示**Model**，**Controller**处理用户操作。模型可以是任何数据，包括存储在数据库中的数据。它通常表示具有彼此清晰定义关系的域对象集合。根据应用程序的设计，一个**Model**可以在多个视图中显示。

**Controller**充当**View**和**Model**之间的中介。它通常具有一组处理程序，用于视图生成的每个事件。**Controller**将用户操作委托给适当的处理程序，然后最终重定向到另一个视图，以显示该操作的结果。

由于不同技术平台上的框架以不同的方式使用 MVC 模式，因此有许多 MVC 模式的实现。Spring MVC 以最简单和最少侵入性的方式实现了它，并自然地将其与核心 Spring 框架集成在一起。

# 您的第一个 Spring MVC 应用程序

让我们开始创建一个非常简单的 Spring MVC Web 应用程序。为了学习的目的，我们将开发*Taskify*的 Web 版本，这是我们在第一章中开始的任务管理系统，*开始使用 Spring Core*。本章中的示例使用**Spring Tool Suite**（**STS**）作为 IDE，但您也可以使用您喜欢的 IDE，如 IntelliJ 和 NetBeans。几乎所有的 Java IDE 都支持 Spring 开发；它们中的大多数都有插件来管理 Spring 项目和构件。

首先，按照以下步骤进行；然后，我们将探索代码：

1.  打开 STS 或 Eclipse→创建一个新项目→输入项目名称→选择一个模板，要么是**Spring MVC 项目**，要么是**简单的 Spring Web Maven**→指定顶级包名称→完成。您的项目结构将被生成。

1.  确保您的`pom.xml`文件包含`spring-context`、`spring-mvc`、`servlet-api`、`jsp-api`和`jstl`库的 Maven 依赖项。请注意，只有在使用 JSP 作为视图技术时，才需要`jsp-api`和`jstl`。

1.  如果尚未生成，请在`WEB-INF`下创建`web.xml`，内容如下：

```java
<?xml version="1.0" encoding="UTF-8"?>
<web-app 

  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
  http://xmlns.jcp.org/xml/ns/javaee/web-app_3_1.xsd" version="3.1">
<!-- \ Root Container shared by Servlets and Filters -->
  <context-param>
    <param-name>contextConfigLocation</param-name>
    <param-value>/WEB-INF/spring/root-context.xml</param-value>
  </context-param>

<!-- Loads Spring Container shared by all Servlets and Filters -->
  <listener>
    <listener-class>
      org.springframework.web.context.ContextLoaderListener
    </listener-class>
  </listener>

  <!-- Processes application requests -->
  <servlet>
    <servlet-name>appServlet</servlet-name>
    <servlet-class>
      org.springframework.web.servlet.DispatcherServlet
    </servlet-class>
    <init-param>
      <param-name>contextConfigLocation</param-name>
      <param-value>/WEB-INF/spring/servlet-context.xml</param-value>
    </init-param>
    <load-on-startup>1</load-on-startup>
  </servlet>

  <servlet-mapping>
    <servlet-name>appServlet</servlet-name>
    <url-pattern>/</url-pattern>
  </servlet-mapping>
</web-app>
```

1.  如果尚未生成，请创建一个`root-context.xml`文件，内容如下：

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans 

  xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">

  <!-- Root Context: defines all shared beans go here -->
</beans>
```

1.  如果尚未生成，请创建一个`servlet-context.xml`文件，内容如下：

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans:beans  ...>

  <!-- Enables the Spring MVC @Controller programming model -->
  <annotation-driven />
  <context:component-scan base package="com.taskify"/>

  <!-- Handles HTTP GET requests for /resources/** by serving up static resources in ${webappRoot}/resources directory -->
  <resources mapping="/resources/**" location="/resources/" />

  <!-- Resolves views selected for rendering by @Controllers to
      .jsp resources in the /WEB-INF/views directory -->
  <beans:bean class=
  "org.springframework.web.servlet.view.InternalResourceViewResolver">
    <beans:property name="prefix" value="/WEB-INF/views/" />
    <beans:property name="suffix" value=".jsp" />
  </beans:bean>
</beans:beans>
```

1.  现在，在`com.taskify.web.controllers`包下创建一个名为`HomeController`的 Java 类，内容如下：

```java
@Controller
public class HomeController {
  private static final Logger logger = LoggerFactory.getLogger(HomeController.class);
  @Autowired
  private TaskService taskService;
  // Simply selects the home view to render by returning // name.
  @RequestMapping(value = "/", method = RequestMethod.GET)
  public String home(Locale locale, Model model) {
    logger.info("Welcome to Taskify! Locale is {}.", locale);
    model.addAttribute("totalTasks",
    taskService.findAllTasksCount() );
    model.addAttribute("totalOpenTasks", taskService.findAllOpenTasksCount() );
    return "home";
  }
}
```

1.  在`~WEB-INF/views`下创建一个名为`home.jsp`的 JSP 视图，内容如下：

```java
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ page session="false"%>
<html>
  <head>
    <jsp:include page="/WEB-INF/views/theme.jsp"></jsp:include>
    <title>Taskify :: Home</title>
  </head>
  <body>
    <jsp:include page="/WEB-INF/views/navbar.jsp"></jsp:include>
    <div class="container">
      <h1>Welcome to Taskify!</h1><hr />
      <P>There are ${totalOpenTasks}(${totalTasks}) open tasks.</P>
    </div>
  </body>
</html>
```

1.  确保您的项目中有`TaskService`类（从第一章中复制），以及它的具体实现，其中实现了`findAllTasksCount()`和`findAllOpenTasksCount()`方法。

1.  现在您的项目已准备就绪，请确保已安装并配置了 Apache Tomcat（或其他任何）服务器与您的 IDE。您可以从[`tomcat.apache.org/`](http://tomcat.apache.org/)下载 Tomcat 并在您的 PC 上安装。

1.  STS 和 Eclipse 允许您通过右键单击**Run As** → **Run on Server**从 IDE 中运行 Java Web 应用程序。解决所有错误（如果有），然后再次运行。

1.  您应该看到您的 Web 应用程序的主屏幕（在`http://localhost:8080/chapter2/`），如下所示：![您的第一个 Spring MVC 应用程序](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00782.jpeg)

# 设置 Spring MVC 应用程序

让我们通过分析前一节*您的第一个 Spring MVC 应用程序*中列出的应用程序构件来弄清楚 Spring MVC Web 应用程序是如何配置的。它包含了构建 Spring MVC Web 应用程序所需的所有必要构件。

## Spring MVC 应用程序的项目结构

创建项目结构和必要的构件的最简单方法是使用 STS 创建 Spring MVC 项目，如前一节所述。或者，您可以使用各种在线存储库中提供的 Maven 原型之一。STS 使用这样一个捆绑的原型。以下是在 STS 中查看的 Spring MVC 应用程序的典型项目结构：

![Spring MVC 应用程序的项目结构](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00783.jpeg)

该结构代表一个单一 WAR Web 应用程序，其中所有服务和数据访问组件与 Web 控制器共存。在更大的应用程序中，许多这样的组件可能是不同 JAR 库项目的一部分，可以在多个 Web 应用程序之间共享，然后作为 Maven 依赖项添加到消费 Web 应用程序中，并使用`<import/>`标签或注释配置将其导入到 Web 应用程序上下文 XML 文件中的 bean。

现在，让我们详细检查*您的第一个 Spring MVC 应用程序*中列出的每个构件。

## web.xml 文件-使 web 应用程序 Spring 化

`web.xml`文件是标准的 Java Web 描述符，其中注册了构成 Java Web 应用程序的基本 Web 组件，这些组件与 Servlet 容器一起使用。在这里配置了`ServletContextListener`和`ServletFilter`组件。

Spring MVC 应用程序也在`web.xml`中配置和引导。在`web.xml`示例中，`ContextLoaderListener`注册为`ServletContextListener`，引导 Spring 的根`WebApplicationContext`。在上一章中，我们看到了一个简单的控制台应用程序如何在主方法内部使用`ClassPathXmlApplicationContext`引导 Spring 上下文。在 Web 应用程序的情况下，遵循`ContextLoaderListener`加载`WebApplicationContext`。请记住，Spring MVC 应用程序不仅仅是另一个基于 Servlet 的应用程序，而是 Spring 集成在 Web 上下文中。

```java
   <listener>
      <listener-class>
         org.springframework.web.context.ContextLoaderListener
      </listener-class>
   </listener>
```

以下监听器查找`context-param`标签`contextConfigLocation`，这是 Spring 根 bean 定义 XML 文件的位置，如前面的`web.xml`文件中所示：

```java
<context-param>
   <param-name>contextConfigLocation</param-name>
   <param-value>/WEB-INF/spring/root-context.xml</param-value>
</context-param>
```

在`web.xml`文件中配置的下一个非常重要的 Spring 组件是`DispatcherServlet`，它是 Spring MVC 应用程序的集中入口点，将每个请求映射到适当的处理程序。`DispatcherServlet`是前端控制器设计模式的实现，它是应用程序中所有 HTTP 请求的单一集中入口点。它内部将它们委托给请求类型的实际处理程序。以下是先前`web.xml`列表中的摘录：

```java
<servlet>
   <servlet-name>appServlet</servlet-name>
   <servlet-class>
      org.springframework.web.servlet.DispatcherServlet
   </servlet-class>
   <init-param>
      <param-name>contextConfigLocation</param-name>
      <param-value>
         /WEB-INF/spring/appServlet/servlet-context.xml
      </param-value>
   </init-param>
   <load-on-startup>1</load-on-startup>
</servlet>

<servlet-mapping>
   <servlet-name>appServlet</servlet-name>
   <url-pattern>/</url-pattern>
</servlet-mapping>
```

`DispatcherServlet`的前面 Servlet 注册将根 URL 映射到`DispatcherServlet`，以便每个进入服务器的 HTTP 请求都将首先由`DispatcherServlet`处理。此外，它指定了此 Servlet 的 Spring 应用程序上下文文件的位置。

### 注意

您的应用程序可以具有任意数量的`DispatcherServlet`定义，具有唯一的 Servlet 名称，具体取决于您希望根据功能模块在逻辑上如何划分 URL 子上下文。大多数应用程序只会定义一个`DispatcherServlet`。

## Spring MVC 应用程序中的 ApplicationContext 文件

Spring MVC 应用程序只是具有 Spring 本地集成的基于 Servlet 的 Web MVC 实现。因此，它需要像任何其他 Spring 应用程序一样的 Spring 豆子定义，正如我们在前一章中所看到的。在 Spring MVC 应用程序的情况下，除了应用程序特定的豆子之外，还会有一些特定于框架的豆子在上下文中注册。

为了将豆子组织在不同的逻辑类别下，例如特定于 Web 的（`DispatcherServlet`）以及共享的豆子，可以使用多个豆子定义。例如，`DispatcherServlet`可以有自己的应用程序上下文文件，其中定义了帮助其处理的豆子（仅适用于 Web 上下文），还可以有一个根应用程序上下文文件，其中定义了不特定于 Web 层但在许多层之间共享的豆子。

在之前章节列出的示例中，作为*您的第一个 Spring MVC 应用程序*的一部分，您可以看到两个 Spring 豆子定义 XML 文件，`root-context.xml`和`servlet-context.xml`。`root-context.xml`文件代表通过`ContextLoaderListener`加载的根`WebApplicationContext`。这是您定义或导入共享豆子的地方，例如服务豆子和数据访问对象。

`servlet-context.xml`文件在启动时由`DispatcherServlet`加载。文件名`servlet-context.xml`是示例清单中明确给出的文件名。默认情况下，`DispatcherServlet`会寻找具有模式`[servlet-name]-servlet.xml`的 XML 豆子定义文件，也就是说，如果没有明确指定，`appServlet`将在`WEB-INF`文件夹的根目录中寻找名为`appServlet-servlet.xml`的文件。通常，此文件包含控制此 Servlet 行为的豆子定义。例如，您可以在文件`servlet-context.xml`中看到资源和视图解析器豆子定义。您可以看到示例清单中配置的视图解析器仅支持 JSP 视图。

## HomeController - 主屏幕的@Controller

`HomeController`是一个带有`@Controller`注释的简单 POJO。此注释将其注册为具有一组注释处理程序方法的 Web 控制器。它可以在类级别具有`@RequestMapping`注释，以指示其中所有处理程序方法的根 URL。`home()`方法是根 URL `http://<context-root>/`的请求处理程序。

由于`@Controller`注释是另一个 Spring 豆子，因此您可以将任何其他豆子注入其中作为依赖项。示例清单显示`HomeController`具有对`TaskService`的自动装配依赖项。在`home()`方法中，调用了`TaskService`方法，最后，将返回值设置为`Model`属性，以供请求的后续部分使用并在视图中使用。

您的应用程序将有许多这样的控制器，用于服务相关 URL 端点的组。将`HomeController`视为您的基本示例。一个控制器可以有多个处理请求的方法，用于服务不同的 URL。

## home.jsp 文件 - 登陆屏幕

`home.jsp`文件是根（`/`）URL 的视图工件。请注意`Model`属性如何在 JSP 视图中绑定：

```java
<P>There are ${totalOpenTasks}(${totalTasks}) open tasks.</P>
```

## 处理传入请求

任何命中应用程序根 URL 的请求首先由`DispatcherServlet`接收，然后将其委托给`HomeController.home()`，该方法处理请求并返回视图名称（在本例中为`home`）。然后，`DispatcherServlet`根据在`servlet-context.xml`中指定的资源和视图配置选择`home.jsp`文件并进行渲染，传递在`HomeController.home()`中创建的模型实例的属性。

# Spring MVC 的架构和组件

通过您的第一个 Spring MVC 应用程序后，现在是时候从架构的角度来看 Spring MVC 应用程序了。

![Spring MVC 的架构和组件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00784.jpeg)

Spring MVC 组件

顾名思义，Spring MVC 遵循着著名的 MVC 架构模式。这种模式通过将责任分为三个主要角色来确保关注点的分离：

+   **模型**：代表数据和业务逻辑

+   **视图**：代表呈现

+   **控制器**：处理客户端请求并将其委托给视图以返回给客户端进行呈现

我们在这里谈论的“模型”不一定是持久数据（数据模型）本身；相反，它代表了客户端和服务器应用程序的不同层之间传递的信息，这些信息构成了任何系统的基本构件。

除了“模型”、“视图”和“控制器”组件之外，`DispatcherServlet`在 Spring MVC 架构中也扮演着至关重要的角色。它充当了前端控制器，这是许多 MVC 框架采用的流行 J2EE 设计模式。实际上，`DispatcherServlet`不仅仅是一个前端控制器。这将在下一节中详细解释。

在 Spring MVC 应用程序中，`DispatcherServlet`首先接收通过 HTTP 命中服务器的客户端请求的 URL。通过`HandlerMapping`配置的帮助，`DispatcherServlet`根据 URL 模式找到适当的**控制器**方法，并将请求委托给它。控制器处理请求，可选地填充**模型**对象，并返回要呈现的**视图**的名称。`DispatcherServlet`然后选择**视图**并将其呈现回客户端，将**模型**的属性应用于**视图**中的占位符。

前面段落提到的只是 Spring MVC 的典型请求处理流程。然而，它非常灵活，有很多选项来支持不同类型的视图技术和输入输出结构和格式，包括文件、流等等。我们将在接下来的部分中更详细地探讨它们。

# 解释了 DispatcherServlet

`DispatcherServlet`是任何 Spring MVC 应用程序的入口。它继承自`javax.servlet.http.HttpServlet`，通常在`web.xml`文件中进行声明式配置。虽然您可以有多个具有唯一 URL 模式的`DispatcherServlet`的定义，但大多数 Spring MVC 应用程序只有一个`DispatcherServlet`，其`context-root` URL（`/`），也就是说，所有请求都将由`DispatcherServlet`处理。

从 Servlet 3.0 开始，除了在`web.xml`文件中进行声明式配置外，`DispatcherServlet`还可以通过实现或扩展 Spring 提供的这三个支持类之一来进行编程配置：

+   `WebAppInitializer`接口

+   `AbstractDispatcherServletInitializer`抽象类

+   `AbstractAnnotationConfigDispatcherServletInitializer`抽象类

以下代码清单演示了如何直接在应用程序中实现`WebAppInitializer`：

```java
public class ApplicationInitializer implements WebApplicationInitializer {

  private static final Logger logger = LoggerFactory.getLogger(ApplicationInitializer.class);

  @Override
  public void onStartup(ServletContext servletContext) throws ServletException {

    logger.info("===== Application is starting up! ========");
    XmlWebApplicationContext appContext = new XmlWebApplicationContext();
    appContext.setConfigLocation("/WEB- INF/spring/appServlet/servlet- context.xml");

    ServletRegistration.Dynamic registration = servletContext.addServlet("rootDispatcher", new DispatcherServlet(appContext));
    registration.setLoadOnStartup(1);
    registration.addMapping("/");
  }
```

## WebApplicationContext - Web 的 ApplicationContext

`DispatcherServlet`使用了一个名为`WebApplicationContext`的专门的`ApplicationContext`，具有许多 web 请求处理功能。它知道它关联的是哪个`ServletContext`，并且还能够解析主题。这个接口有具体的实现，用于特定的上下文，比如 XML，`@Configuration`注解的类和 portlet。默认情况下，`DispatcherServlet`使用`XMLWebApplicationContext`。当`DispatcherServlet`加载时，它会查找`WebApplicationContext`的 bean 配置文件并对其进行初始化。

`WebApplicationContext`对象是分层的。每个 Spring MVC 应用程序都有一个根`ApplicationContext`（可以在`web.xml`文件中的`context-param`标签中配置为`contextConfigLocation`），每个 Servlet，包括`DispatcherServlet`，都有自己的子上下文（可以通过自己的`init-param`，`contextConfigLocation`进行配置）。理想情况下，Servlet 特定的子上下文具有自定义该 Servlet 的 bean，而根`ApplicationContext`具有所有共享的 bean。

## 支持 DispatcherServlet 的 bean 及其角色

收到 web 请求后，`DispatcherServlet`在请求处理的过程中依次执行一系列操作，借助一组支持 bean 的帮助。此表列出了这些特殊 bean 及其职责：

| Bean | 职责 |
| --- | --- |
| `HandlerMapping` | 将传入的 web 请求映射到处理程序和前后处理器 |
| `HandlerAdapter` | 调用解析参数和依赖项的处理程序，例如 URL 映射控制器方法端点的注释参数 |
| `HandlerExceptionResolver` | 允许以编程方式处理异常并将异常映射到视图 |
| `ViewResolver` | 将逻辑视图名称解析为视图实例 |
| `LocaleResolver` | 解析客户端的区域设置以实现国际化 |
| `LocaleContextResolver` | `LocaleResolver`的更丰富的扩展，带有时区信息 |
| `ThemeResolver` | 解析应用程序中配置的主题，以增强用户体验 |
| `MultipartResolver` | 处理 HTTP 请求中的多部分文件上传 |
| `FlashMapManager` | 管理 FlashMap 实例，用于在重定向的请求之间存储临时 Flash 属性 |

`DispatcherServlet`非常灵活；我们甚至可以为所有这些 bean 创建和配置自定义实现。但是，Spring MVC 默认提供了一组很好的实现，因此除非绝对需要，否则您不需要自定义或提供自己的实现。这些默认实现可以在`org.springframework.web.servlet.DispatcherServlet.properties`中找到。如果您用自己的实现覆盖了这些 bean 中的任何一个，您的实现将覆盖默认值。

# 详细的控制器

控制器，其方法带有`@RequestMapping`注解，处理 web 请求。它们以多种形式接受输入数据，并将其转换为`Model`属性，以供视图消费，然后显示给客户端。它们将用户连接到服务层 bean，其中定义了应用程序行为。

Spring MVC 中的控制器具有以下签名：

```java
public interface Controller {

   ModelAndView handleRequest(HttpServletRequest request, HttpServletResponse response) throws Exception;
}
```

控制器被设计为一个接口，允许您创建任何类型的实现。从 Spring 版本 2.5 开始，您可以通过使用`@Controller`对任何类进行注释，将其转换为控制器。这使您无需实现任何特定的接口或扩展特定于框架的类：

```java
@Controller
public class HomeController {

   @RequestMapping(value = "/", method = RequestMethod.GET)
   public String home(Model model) {
      logger.info("Welcome to Taskify", locale);
      return "home";
   }
}
```

`@Controller`注解将给定类指定为控制器的角色。Spring MVC 应用程序会自动检测其类路径中的所有控制器，并在启用组件扫描时将它们注册到`WebApplicationContext`中，如下所示：

```java
<context:component-scan base-package="com.taskify" />
```

`@Controller`，`@RequestMapping`和一组其他注解构成了 Spring MVC 的基础。这些注解允许控制器具有灵活的方法名称和签名。我们将在下一节中详细探讨它们。

## 使用@RequestMapping 映射请求 URL

`@RequestMapping`注解将请求 URL 映射到整个`@Controller`类或其处理程序方法。它可以应用于类级别和方法级别。通常，您将类级别的@RequestMapping 注解应用于映射一组相关的 URL，例如具有多个操作的表单，而方法级别的@RequestMapping 注解用于特定操作，例如创建、读取、更新、删除、上传和下载。让我们来看一个典型的基于表单的控制器，其中包含纯 REST 模型的各种操作（`GET`，`POST`，`PUT`和`DELETE`）：

```java
@Controller
@RequestMapping("/users")
public class UserController {

   @Autowired
   private UserService userService;

   @RequestMapping(method = RequestMethod.GET)
   public String listAllUsers(Locale locale, Model model) {
      model.addAttribute("users", userService.findAllUsers());
      return "user/list";
   }

   @RequestMapping(path = "/new", method = RequestMethod.GET)
   public String newUserForm(Model model) {
      User user = new User();
      user.setDateOfBirth(new Date());
      model.addAttribute("user", user);
      return "user/new";
   }

   @RequestMapping(path = "/new", method = RequestMethod.POST)
   public String saveNewUser(@ModelAttribute("user") User user, Model model) {
      userService.createNewUser(user);
      return "redirect:/user";
   }
   @RequestMapping(path = "/{id}", method = RequestMethod.GET)
   public ModelAndView viewUser(@PathVariable("id") Long id) {
      return new ModelAndView("user/view").addObject("user", userService.findById(id));
   }

   @RequestMapping(path = "/{id}/edit", method = RequestMethod.GET)
   public String editUser(@PathVariable("id") Long id, Model model) {
      model.addAttribute("user", userService.findById(id));
      return "user/edit";
   }

   @RequestMapping(path = "/{id}", method = RequestMethod.PUT)
   public String updateUser(@PathVariable("id") Long id, @ModelAttribute("user") User user, Model model) {
      userService.updateUser(user);
      model.addAttribute("user", userService.findById(user.getId()));
      return "redirect:/user/" + id;
   }

   @RequestMapping(path = "/{id}", method = RequestMethod.DELETE)
   public String deleteUser(@PathVariable("id") Long id, Model model) {
      User existingUser = userService.findById(id);
      userService.deleteUser(existingUser);
      return "redirect:/user";
   }
}
```

在上述代码中列出的`UserController`具有作为请求处理程序的方法，用于表示对用户实体进行 CRUD 操作的 URL，并借助`UserService`作为依赖项注入到控制器中。由于这个控制器是基于 Web 视图的，处理程序方法填充模型并返回视图名称或`ModelAndView`对象以供进一步显示。最后两个处理程序方法`updateUser()`和`deleteUser()`在返回响应后重定向请求。它们在最后执行 URL 重定向，将响应返回给客户端。

请注意，`UserController`有一个根 URL（`/user`），处理程序方法具有更窄的映射，使用 HTTP 方法的组合。它们由以下表中看到的确切 URL 调用：

| URL | 处理程序方法 | HTTP 方法 | 匹配的 URL（示例） |
| --- | --- | --- | --- |
| `/` | `listAllUsers` | `GET` | `http://localhost:8080/user` |
| `/new` | `newuserForm` | `GET` | `http://localhost:8080/user/new` |
| `/new` | `saveNewUser` | `POST` | `http://localhost:8080/user/new` |
| `/{id}` | `viewUser` | `GET` | `http://localhost:8080/user/123` |
| `/{id}/edit` | `editUser` | `GET` | `http://localhost:8080/user/123/edit` |
| `/{id}` | `updateUser` | `PUT` | `http://localhost:8080/user/123` |
| `/{id}` | `deleteUser` | `DELETE` | `http://localhost:8080/user/123` |

默认情况下支持`GET`和`POST`方法，与 HTML（因此浏览器）对其他两种方法的有限支持一致。但是，要使`PUT`和`DELETE`方法工作，您需要在`web.xml`文件中注册`HiddenHttpMethodFilter`。使用以下代码：

```java
<filter>
   <filter-name>httpMethodFilter</filter-name>
   <filter-class>org.springframework.web.filter. HiddenHttpMethodFilter</filter-class>
</filter>

<filter-mapping>
   <filter-name>httpMethodFilter</filter-name>
   <servlet-name>rootDispatcher</servlet-name>
</filter-mapping>
```

`HiddenHttpMethodFilter`即使在没有 Spring MVC 的情况下也可以工作；您可以将其与任何 Java Web 框架甚至纯 Servlet 应用程序一起使用。

## 带有@PathVariable 注解的 URI 模板模式

在上述代码中的示例`UserController`列表中，您可能已经注意到处理请求时使用变量名称替换为值的模板化 URL 模式。例如：

```java
@RequestMapping(path = "/{id}/edit", method = RequestMethod.GET)
public String editUser(@PathVariable("id") Long id, Model mdl) { … }
```

在这里，模板变量`id`被映射到`@PathVariable`注解。它被包含在大括号中，并被注释为映射的方法参数。URL 可以有任意数量的路径变量。它们支持正则表达式以及 Apache Ant 风格的路径模式。它们帮助您在经典的 REST 模型中构建完美的 URI 端点。

## 使用@RequestParam 注解绑定参数

与 URI 字符串内联的请求参数可以使用@RequestParam 注解与方法参数进行映射。请参阅`TaskController`中的以下摘录：

```java
@Controller
public class TaskController {
...
   @RequestMapping(path = "/tasks", method = RequestMethod.GET)
   public String list(@RequestParam(name = "status", required = false) String status, Model model) {
      model.addAttribute("status", status);
      model.addAttribute("tasks", taskService.findAllTasks(status));
      return "task/list";
   }
...
}
```

调用上述处理程序的典型 URL 是`http:<context-root>/tasks?status=Open`。

`@RequestParam`有四个属性：`name`，`required`，`value`和`defaultValue`。`name`是一个必需的属性，其他所有属性都是可选的。默认情况下，所有请求参数都需要设置为`true`，除非您将它们指定为`false`。Spring 会自动将@RequestParam 的值转换为参数类型。

## 请求处理程序方法参数

`@RequestMapping`方法可以具有灵活的方法签名；支持混合框架，自定义对象和注解。如果在方法参数中找到，它们将在请求处理期间自动注入。以下是一些受支持的框架类和注解的列表；请参阅 Spring 官方文档或`RequestMapping`的 Javadoc 以获取完整列表。

| 支持的类 | 注解 |
| --- | --- |
| `javax.servlet.ServletRequest` | `@PathVariable` |
| `javax.servlet.ServletRequest` | `@RequestVariable` |
| `javax.servlet.http.HttpSession` | `@RequestParam` |
| `org.springframework.ui.Model` | `@RequestHeader` |
| `org.springframework.validation.BindingResult` | `@RequestBody` |
| `Java.util.Map` | `@RequestPart` |
| `Java.io.InputStream` | `@InitBinder` |

虽然框架类不需要任何特定的注解，但自定义类通常需要在处理程序适配器中伴随受支持的注解之一，以将传入的 Web 请求对象转换/格式化为类实例。

## 请求处理程序方法返回类型

与灵活的参数类型类似，由`@RequestMapping`注解的方法可以具有自定义类型（通常注释为`@ResponseBody`）或许多受支持的框架类之一。以下列表包含许多受支持的类型之一：

+   `org.springframework.web.servlet.ModelAndView`

+   `org.springframework.ui.Model`

+   `java.util.Map`

+   `org.springframework.web.servlet.View`

+   `java.lang.String`

+   `void`

+   `java.util.concurrent.Callable<?>`

+   `org.springframework.http.HttpEntity`

## 设置模型属性

`Model`属性用于视图的显示和与表单元素的绑定。它们可以在控制器和处理程序方法级别设置。

任何具有非 void 返回类型的方法都可以被注释为`@ModelAttribute`，以使方法返回类型成为由声明的 Controller 解析的所有视图的`Model`属性。看一个例子：

```java
@ModelAttribute(value = "users")
public List<User> getUsersList() {
   return userService.findAllUsers();
}
```

特定于视图的模型属性在视图解析的处理程序方法内设置。以下是一个例子：

```java
@RequestMapping(path = "/tasks/new", method = RequestMethod.GET)
public String newTaskForm(Model model) {
   model.addAttribute("task", new Task());
   return "task/new";
}
```

## 为 JSON 和 XML 媒体构建 RESTful 服务

Web 应用程序通常需要将其一些服务公开为 Web API，使用 XML 或 JSON 数据格式，或两者兼而有之，以供浏览器以及移动设备和平板电脑的 AJAX 请求消费。

**REpresentational State Transfer** (**REST**), 是一种建立与原生 Web 协议和方法一致的 Web API 的已建立的架构风格。使用 REST，数据被表示为资源，可以使用 HTTP 的无状态协议通过 URI 访问和操作。REST 坚持使用 HTTP 方法`POST`，`GET`，`PUT`和`DELETE`来映射对资源的创建，读取，更新和删除操作（CRUD）。

Spring MVC 非常容易构建简单的 API 端点，以消费和生成不同的媒体类型，如文本，JSON 和 XML。`@Controller`注解中的请求处理程序方法可以使用以下两个步骤接受 JSON，XML 或任何其他媒体类型：

1.  在`RequestMapping`方法中将属性`consumes`设置为适当的媒体类型（例如`consumes = {"text/plain", "application/json"})`。

1.  使用`@RequestBody`注释所需类型的方法参数。Web 请求应包含在步骤 1（`consumes`；JSON，XML 等）中提到的格式的数据，并在处理期间由`HttpMessageConverter`解析为此类型。

类似地，请求处理程序方法可以使用以下两个步骤生成 JSON，XML 或任何其他媒体类型：

1.  在`RequestMapping`方法中将属性`produces`设置为适当的媒体类型（例如`consumes = {"text/plain", "application/json"})`。

1.  在处理程序方法的返回类型或方法声明本身（紧邻`@RequestMapping`）旁边使用`@ResponseBody`进行注解。处理程序将返回值转换为`RequestMapping`中指定的数据格式。

`RequestMapping`的`consumes`和`produces`属性将主映射缩小到给定的媒体类型（例如`consumes = "application/xml"`）或一系列媒体类型（例如`consumes = {"text/plain", "application/json"}`）。

除了属性之外，确保`pom.xml`文件中存在以下库：

```java
<dependency>
   <groupId>com.fasterxml.jackson.core</groupId>
   <artifactId>jackson-databind</artifactId>
   <version>2.6.2</version>
</dependency>
```

以下是一个接受 JSON 请求并返回 JSON 响应的示例处理程序方法：

```java
@RequestMapping(path = "/tasks/new.json", method=RequestMethod.POST, consumes = "application/json", produces = "application/json")
@ResponseBody
public CreateTaskResponse createNewTaskJSON(@RequestBody CreateTaskRequest createRequest) {
   Task task = new Task();
   task.setName(createRequest.getTaskName());
   ...
   return new CreateTaskResponse(taskService.createTask(task));
}
```

这个处理程序方法期望带有 JSON 内容的 web 请求：

```java
{
   "taskName":"Project estimation",
   "priority": 2,
   "creatorId": 1,
   "assigneeId": 2,
   "comments": "Involve the team in the process"
}
```

现在，同样的方法可以稍作修改以支持 XML 内容，`consumes`和`produces`。看一下以下清单：

```java
@RequestMapping(path = "/tasks/new.xml", method = RequestMethod.POST, consumes = "application/xml", produces = "application/xml")
@ResponseBody
public CreateTaskResponse createNewTaskXML(@RequestBody CreateTaskRequest createRequest) {
   Task task = new Task()
   task.setName(createRequest.getTaskName());
   . . .
   return new CreateTaskResponse(taskService.createTask(task));
}
```

确保在`RequestBody`和`ResponseBody`类型的根部分（在这种情况下是`CreateTaskRequest`和`CreateTaskResponse`）存在 JAXB 注解`@XmlRootElement`。

您可以通过向处理程序 URI 发送以下内容的 web 请求来调用前面的 XML 处理程序：

```java
<CreateTaskRequest>
   <taskName>Estimate the project</taskName>
   <priority>2</priority>
   <creatorId>1</creatorId>
   <assigneeId>2</assigneeId>
   <comments>Involve the team in the process</comments>
</CreateTaskRequest>
```

## 使用 RestController 构建 RESTful 服务

`RestController`是一个方便的构建 REST API 端点的约定，可以提供自定义媒体类型，比如 JSON 或 XML。它将`@Controller`与`@ResponseBody`结合在一起，也就是说，在处理程序方法中不需要注解`@ResponseBody`。`@RequestMapping`方法默认假定`@ResponseBody`语义。

让我们看看当 JSON 处理程序方法成为`@RestController`注解的一部分时是什么样子：

```java
@RestController
public class TaskRestController {
   . . .
  @RequestMapping(path="/api/tasks/new.json", method=RequestMethod.POST, consumes="application/json",produces= "application/json")
  public CreateTaskResponse createNewTaskJSON(@RequestBody CreateTaskRequest createRequest) {
    Task task = new Task();
    task.setName(createRequest.getTaskName());
    . . .
    return new CreateTaskResponse(taskService.createTask(task));
  }}
}
```

请注意，映射中唯一的区别是缺少`@ResponseBody`注解。最佳实践是在 REST 控制器内定义 REST API。

# Spring MVC 中的异步请求处理

在 API、AJAX 客户端和设备的时代，Web 服务器的流量呈指数增长。找到使服务器更具可伸缩性的方法是服务器供应商面临的持续挑战。传统的**每个 HTTP 连接一个线程**策略对于更多并发用户访问并不具备良好的可伸缩性。在这种模型中，每个请求都会阻塞 Servlet 容器分配的线程池中的一个线程，直到请求完全处理完毕（到目前为止所示的示例都遵循这种模型）。当 AJAX 客户端（其中一个屏幕经常会发出多个并发连接请求）与长时间运行的进程结合在一起时，由于线程饥饿问题，服务器很容易因为没有空闲线程可用而耗尽。这使得应用程序在负载增加时不可用。

异步 HTTP 请求处理是一种利用 Java 平台 NIO API 的非阻塞 I/O 能力的技术。在这种模型中，服务器线程在整个请求处理过程中不会一直附加到持久的 HTTP 连接上。一旦接收到请求，Servlet 容器就会释放容器线程，并将进一步处理委托给另一个应用程序（在这种情况下是 Spring）管理的线程，以便容器线程可以自由地为新的传入请求提供服务。这种非阻塞请求处理模型节省了大量服务器资源，并稳定地增加了服务器的可伸缩性。

Servlet 3.0 引入了异步处理支持，Spring 从 Spring 3.2 开始实现了这种支持。截至 4.2，Spring 提供了两种定义异步请求处理程序的简单方法：

+   返回`java.util.concurrent.Callable`实例而不是值，并在`Callable`的`call`方法中生成实际的返回值，也就是由 Spring 管理的线程，而不是 Servlet 容器。

+   返回 Spring 特定的`DeferredResult`类型的实例，并在任何其他线程或外部事件中生成实际的返回值，比如 JMS 或 Quartz 调度程序

这两种方法都会尽早释放容器线程，并使用外部线程异步地继续长时间运行的事务。让我们来看一个使用`Callable`的示例：

```java
@RequestMapping(path="/tasks/new.xml",method= RequestMethod.POST, consumes = "application/xml", produces = "application/xml")
@ResponseBody
public Callable<CreateTaskResponse> createNewTaskXMLAsyncCallable( @RequestBody CreateTaskRequest createRequest) {
   return new Callable<CreateTaskResponse>() {

      @Override
      public CreateTaskResponse call() throws Exception {
         Task task = new Task();
         task.setName(createRequest.getTaskName());
         . . .
         Task persistedTask = taskService.createTask(task);
         // Send an email here...
         // Send some push notifications here...
         . . .
         return new CreateTaskResponse(persistedTask);
      }
   };
}
```

在这种方法中，您可以看到处理程序方法在收到请求后立即返回`Callable`对象，而不等待`Callable.call()`方法执行。Spring MVC 使用`TaskExecutor`在另一个线程中调用`call()`方法，并在`call()`方法返回值后将响应分派回 Servlet 容器。

以下是如何使用`DeferredResult`的示例：

```java
@RequestMapping(path = "/tasks/new-async-deferred.json", method = RequestMethod.POST, consumes = "application/json", produces = "application/json")
@ResponseBody
public DeferredResult<CreateTaskResponse> createNewTaskJSONAsyncDeferredResult( @RequestBody CreateTaskRequest createRequest) {

   DeferredResult<CreateTaskResponse> defResult = new DeferredResult<>();
   CompletableFuture.runAsync(new Runnable() {
      @Override
      public void run() {
         Task task = new Task();
         task.setName(createRequest.getTaskName());
         . . .
         Task persistedTask = taskService.createTask(task);
         // Send an email here...
         // Send some push notifications here...
         defResult.setResult(newCreateTaskResponse(persistedTask));
      }
   });
   return deferredResult;
}
```

请记住，您必须在`DispatcherServlet`以及在`web.xml`文件（或者您定义它们的任何地方，也许是在 JavaConfig 类中）中声明的所有 Servlet 过滤器中启用异步处理支持，才能使其工作。以下代码显示了如何在`web.xml`中设置它：

```java
<servlet>
   <servlet-name>appServlet</servlet-name>
   <servlet-class>
      org.springframework.web.servlet.DispatcherServlet</servlet-class>
   . . .
   <async-supported>true</async-supported>
</servlet>
```

您可以根据自己的方便选择前面提到的任何方法来启用异步处理。考虑为了高可伸缩性和性能，设计所有非平凡的服务都能异步工作。

# 处理视图

Spring MVC 提供了一个非常灵活的视图解析机制，它与 MVC 框架的其他元素完全解耦。它不会强迫您使用特定的视图技术；相反，它使您更容易使用您自己喜欢的技术。它甚至允许您在视图层混合和匹配多种技术。Spring MVC 提供了对 JPS、XSLT 和 Velocity 视图的开箱即用支持。

## 解析视图

在典型的 Spring MVC 应用程序中，开发人员选择自己喜欢的视图技术，并相应地使用解析使用该技术构建的视图的`ViewResolver`。

在 Spring MVC 应用程序中负责解析视图的组件是`org.springframework.web.servlet.ViewResolver`。它将逻辑视图名称映射到物理视图资源和所选择的视图技术。

控制器的所有请求处理方法必须通过返回视图名称、视图对象或`ModelAndView`对象来解析逻辑视图名称。`org.springframework.web.servlet.View`对象准备`HttpRequest`以消费所选择的视图技术。

Spring MVC 提供了一组方便的视图解析器，可以直接使用：

| ViewResolver | Description |
| --- | --- |
| `AbstractCachingViewResolver` | 这是`ViewResolver`实现的一个方便的基类。为了更好的性能，它会在解析视图对象后缓存视图对象。 |
| `XmlViewResolver` | 这个解析器使用专用 XML 文件中的 bean 定义来解析视图定义。该文件由资源位置指定。默认情况下，它位于`WEB-INF/views.xml`。 |
| `ResourceBundleViewResolver` | 这个解析器使用`ResourceBundle`中指定的 bean 定义来定义视图。默认的基本名称是`views.properties`。 |
| `UrlBasedViewResolver` | 这个解析器用于解析具有匹配 URL 中物理资源的视图名称。它的两个支持属性，前缀和后缀，帮助定位资源。 |
| `InternalResourceViewResolver` | 这个解析器用于解析带有 JSTL 支持的 Servlets 和 JSPs。它是`UrlBasedViewResolver`的子类。 |
| `VelocityViewResolver` | 这个解析器用于解析 Velocity 模板，是`UrlBasedViewResolver`的子类。 |
| `FreeMarkerViewResolver` | 这个解析器用于解析 FreeMarker 模板。它是`UrlBasedViewResolver`的子类。 |
| `JasperReportsViewResolver` | 这个解析器用于解析不同格式的 JasperReport 视图，比如 CSV、HTML、XLS 和 XLSX。 |
| `TilesViewResolver` | 这个解析器用于解析版本 2 和 3 的 Tiles 视图。 |

本章的示例应用程序使用`UrlBasedViewResolver`来解析 JSP 视图。当您在 Web 应用程序中使用多个视图技术时，您可以使用`ResourceBundleViewResolver`。

## 解析 JSP 视图

**Java Server Pages** (**JSP**), 是 Java EE 的主要网页模板技术，是一种简单易用的工具，用于基于 JVM 的动态网页内容的快速开发。建立在 Servlet 技术之上，JSP 可以直接访问整个 Java API。JSP 通过允许用户以自然的 HTML 格式设计网页，然后在脚本块中嵌入所需的 Java 代码，大大简化了网页作者的工作。

**Java Server Pages Tag Library** (**JSTL**) 是一组标准化的类似 HTML 标签，非常适用于 JSP 页面。JSTL 消除了在 JSP 页面中混合 Java 代码的需要，因此使得 JSP 页面更加清洁和易于编写。

Spring MVC 使用 `InternalResourceViewResolver` 解析 JSP 页面。在前面的部分 *Your first Spring MVC application* 中，我们已经为 JSP 配置了 `ViewResolver` 类。

```java
<beans:bean class="org.springframework.web.servlet.view.InternalResourceViewResolver">
  <beans:property name="prefix" value="/WEB-INF/views/" />
  <beans:property name="suffix" value=".jsp" />
</beans:bean>
```

Spring MVC 建议将视图文件（在这种情况下是 JSP）放在 `WEB-INF` 目录下，以避免直接客户端访问。`ViewResolver` 会从物理位置发现视图文件，并在解析后默认缓存它们，这有助于提高性能。

## 使用 JSTL 在 JSP 页面中绑定 Model 属性

视图可以访问从关联处理程序方法和控制器设置的 `Model` 属性。这些 `Model` 属性可以在 JSP 视图中使用 JSTL 显示。在下面的示例中，使用 JSTL 列出了 `Model` 属性 `tasks`：

```java
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
...
<table class="table table-hover">
  <thead>
    <tr>
      <th>ID</th>
      <th>Task</th>
      <th>Status</th>
      <th>Priority</th>
      <th>Created By</th>
      <th>Assigned To</th>
    </tr>
  </thead>
  <tbody>
    <c:if test="${not empty tasks}">
      <c:forEach var="task" items="${tasks}">
        <tr>
          <td>
            <a href='<c:url value="/tasks/${task.id}"/>'>${task.id}</a>
          </td>
          <td>${task.name}</td>
          <td>${task.status}</td>
          <td>${task.priority}</td>
          <td>${task.createdBy.name}</td>
          <td>${task.assignee.name}</td>
        </tr>
      </c:forEach>
    </c:if>
  </tbody>
</table>
...
```

您可能已经注意到了在前面 JSP 提取的 `/tasks/list.jsp` 视图中声明和使用 JSTL 标签。以下是在浏览器中以适当样式呈现的方式：

![使用 JSTL 在 JSP 页面中绑定 Model 属性](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00785.jpeg)

# Spring 和 Spring 表单标签库

Spring 捆绑了一组标签，用于更轻松地编写普通 JSP 页面和 JSP 表单，分别在 `spring.tld` 和 `spring-form.tld` 中定义。`spring.tld` 描述了常用于 JSP 页面的通用目的的 JSP 标签，列在以下表中：

| Spring tag | Description |
| --- | --- |
| `<spring:bind/>` | 这允许绑定在本地声明的 bean 或 `Model` 属性的绑定路径中的属性，并为封闭的主体内容提供 `BindStatus` 对象。 |
| `<spring:escapeBody/>` | 这为主体应用了 HTML 转义和 JavaScript 转义。 |
| `<spring:hasBindErrors/>` | 如果存在绑定错误，则提供错误实例。 |
| `<spring:htmlEscape/>` | 这为当前 JSP 页面设置了 HTML 转义值。 |
| `<spring:message/>` | 这会显示给定代码的消息，通常是从资源包中解析出来的。 |
| `<spring:nestedPath/>` | 这将 `ModelAttribute` 的嵌套路径设置为 `<spring:bind/>` 标签内部的标签。 |
| `<spring:theme/>` | 这使用给定代码加载主题资源。 |
| `<spring:transform/>` | 这会转换 `<spring:bind/>` 标签内部的属性，并将它们导出到给定范围的变量中。 |
| `<spring:url/>` | 这会使用 URI 模板变量创建一个 URL。它是基于 JSTL `c:url` 标签建模的。 |
| `<spring:eval/>` | 这会评估 SpEL 表达式。 |

Spring `form` 标签为 HTML 表单提供数据绑定。它们与控制器中的请求处理程序紧密集成。通常，它们代表名称相似的 HTML `form` 元素，并共享常见属性：

| Form tag | Sample |
| --- | --- |
| `<form:input/>` | `<form:input path="name" placeholder="任务名称"/>` |
| `<form:textarea/>` | `<form:textarea path="comments" id="txtComments" rows="5" cols="30" />` |
| `<form:select/>``<form:option/>` and`<form:options/>` | `<form:select path="createdBy" id="selectCreatedBy">``<form:option value="-1" label="选择"/>``<form:options items="${users}" itemValue="id" itemLabel="name" />``</form:select>` |
| `<form:label/>` | `<form:label for="txtTaskName" path="name">任务名称</form:label>` |
| `<form:hidden/>>` | `<form:hidden path="taskId" id="hdnTaskId"/>` |
| `<form:password/>` | `<form:password path="userPassword"/>` |
| `<form:radiobutton/>` | `<form:radiobutton path="sex" value="Male"/>` |
| `<form:radiobuttons/>` | `<form:radiobuttons path="sex" items="${sexOptions}"/>` |
| `<form:checkbox/>` | `<form:checkbox path="task.priority" value="1"/>` |
| `<form:checkboxes/>` | `<form:checkboxes path="task.priority" value="${taskPriorities}"/>` |
| `<form:password/>` | `<form:password path="password" />` |
| `<form:errors/>` | `<form:errors path="createdBy.id" />` |

# 在 JSP 中组合表单

Spring 表单可以在 JSP 页面中使用`<spring>`和`<form>`标签进行组合。为了举例说明，让我们看一个使用 Spring 和 form 标签库以及 JSTL 的 JSP 表单。以下是`views/task/new.jsp`的简化版本：

```java
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form"%>
...
<form:form action="new" method="post" commandName="task">
  <spring:bind path="name">
    <div class="form-group${status.error ? ' has-error' : ''}">
      <label for="txtTaskName">Task-name</label>
      <form:input path="name" class="form-control" id="txtTaskName" placeholder="Task Name" />
      <form:errors path="name" cssClass="control-label" />
    </div>
  </spring:bind>
  <div class="form-group">
    <label for="txtComments">Comments</label>
    <form:textarea path="comments" class="form-control" id="txtComments" placeholder="Comments" rows="5" cols="30" />
  </div>
  <spring:bind path="createdBy.id">
    <div class="form-group${status.error ? ' has-error' : ''}">
      <label for=" slCrtBy ">Created By</label>
      <form:select path="createdBy" id="slCrtBy" class="form-control">
        <form:option value="-1" label="-- Select --">
        </form:option>
        <form:options items="${users}" itemValue="id" itemLabel="name" />
      </form:select>
      <form:errors path="createdBy.id" cssClass="control-label" />
    </div>
  </spring:bind>
  <button type="submit" class="btn btn-success">Save</button>
  <a href='<c:url value="/tasks"/>' class="btn btn-primary">Cancel</a>
</form:form>
```

如前面的代码清单所示，您必须在使用 Spring 表单标签之前，在 JSP 页面的顶部声明 JSTL、Spring 和 form 标签库指令。

所有`<form>`元素都应该在`<form:form/>`容器元素内。`<form:form/>`的`commandName`属性值将`Model`属性与控制器的处理方法中的名称绑定。解析前述 JSP 表单的处理方法如下所示：

```java
@RequestMapping(path = "/tasks/new", method = RequestMethod.GET)
public String newTaskForm(Model model) {
   model.addAttribute("task", new Task());
   model.addAttribute("priorities", priorities); // This is a collection
   model.addAttribute("users", userService.findAllUsers());
   return "task/new";
}
```

注意`Model`属性`task`，它与 JSP 页面中的`<form:form/>`标签绑定。表单提交到以下处理方法，该方法再次将`Task`对象序列化以进行持久化：

```java
@RequestMapping(path = "/tasks/new", method = RequestMethod.POST)
public String createNewTask(@ModelAttribute("task") @Valid Task task, BindingResult result, Model model) {
   if(result.hasErrors()) {
      return "task/new";
   } else {
      taskService.createTask(task);
      return "redirect:/tasks";
   }
}
```

# 验证表单

Spring MVC 使用 Spring 的`Validator`框架使表单验证变得更加容易。您可能已经注意到了前一节中列出的处理方法中的`@Valid`注解和`BindingResult.hasErrors()`方法调用的使用。它们是验证框架的一部分。

让我们按照以下步骤为`Task`对象创建一个验证器：

1.  在构建文件（`pom.xml`）中添加 Validation API 的 Maven 依赖项，`javax.validation`。

1.  确保在 bean 定义中为`validation-errors`属性文件定义了`MessageSourceBean`：

```java
<beans:bean id="messageSource" class="org.springframework.context.
support.ReloadableResourceBundleMessageSource">
   <beans:property name="defaultEncoding" value="UTF-8" />
   <beans:property name="basenames" value="classpath:validation-errors" />
</beans:bean>
```

1.  确保在根资源位置有一个名为`validation-errors.properties`的文件，并包含以下示例内容。您可以根据需要添加任意数量的错误消息。

```java
error.invalid={0} is in invalid format.
error.required={0} is required.
```

1.  创建`Validator`类`TaskValidator`：

```java
public class TaskValidator implements Validator {

   @Override
   public boolean supports(Class<?> clazz) {
      return clazz.isAssignableFrom(Task.class);
   }

   @Override
   public void validate(Object target, Errors errors) {
      Task task = (Task) target;
      ValidationUtils.rejectIfEmptyOrWhitespace(errors, "name", "error.required", new Object[] { "Task name" });
      ValidationUtils.rejectIfEmpty(errors, "createdBy.id", "error.required", new Object[] { "Created user" });
   }
}
```

1.  使用`InitBinder`在`TaskController`类中注册`TaskValidator`类：

```java
@InitBinder("task")
public void initBinder(WebDataBinder binder) {
   binder.addValidators(new TaskValidator());
}
```

1.  在处理方法中，使用`javax.validation.Valid`的`@Valid`注解注释`ModelAttribute`。

1.  在请求处理方法中处理验证错误，就像前一节中列出的`createNewTask()`方法一样。

1.  为您正在验证的每个表单字段添加一个`<form:errors/>`标签，就像`/tasks/new.jsp`文件中所示的那样。

在验证错误的情况下，表单将如下所示：

![Validating forms](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprmvc-dsn-rw-webapp/img/image00786.jpeg)

# 处理文件上传

大多数 Web 应用程序都需要多部分文件上传功能。Spring MVC 使得处理这个繁琐的功能变得非常容易。它提供了两个内置的`MultiPartResolvers`实现：`CommonsMulipartResolver`用于 Apache Commons FileUpload 和`StandardServletMultipartResolver`用于 Servlet 3.0 API。

由于大多数现代 Web 应用程序使用 Servlet 3.0 容器，让我们看看如何使用`StandardServletMultipartResolver`处理文件上传功能，以下是一个示例：

1.  在`servlet-context.xml`文件中注册您的`MultipartResolver`（或者如果您使用 Java 配置，则以编程方式添加它）：

```java
<beans:bean id="multipartResolver" class="org.springframework.web.multipart.support.StandardServletMultipartResolver">
</beans:bean>
```

1.  在`web.xml`（或 JavaConfig）文件中为您的`DispatcherServlet`添加多部分配置支持：

```java
<servlet>
  <servlet-name>appServlet</servlet-name>
...
  <multipart-config>
    <location>/tmp/servlet-uploads</location>
    <max-file-size>20848820</max-file-size>
    <max-request-size>418018841</max-request-size>
    <file-size-threshold>1048576</file-size-threshold>
  </multipart-config>
</servlet>
```

1.  确保您在上一节中提供的位置确实存在。如果不存在，请创建该目录。

1.  创建带有输入文件元素的 Web 表单。此示例 JSP 片段上传用户的个人资料图片：

```java
<form:form action="../${user.id}/profileForm" method="post" enctype="multipart/form-data">
   <div class="form-group">
      <label for="txtUserName">Choose File</label>
      <input type="file" name="profileImage"/>
   </div>
   <button type="submit" class="btn btn-success">Upload</button>
   <a href="../${user.id}" class="btn btn-primary">Cancel</a>
</form:form>
```

1.  在控制器中创建请求处理方法：

```java
@RequestMapping(path = "/{userId}/profileForm", method = RequestMethod.POST)
public String uploadProfileImage(@PathVariable("userId") Long userId, @RequestParam("profileImage") MultipartFile file) throws IOException {

   User user = userService.findById(userId);
   String rootDir = FILE_ROOT_DIR + "/" + user.getId();

   if (!file.isEmpty()) {
      java.io.File fileDir = new java.io.File(fileSaveDirectory);
      if (!fileDir.exists()) {
         fileDir.mkdirs();
      }
      FileCopyUtils.copy(file.getBytes(), new java.io.File(rootDir  + "/" + file.getOriginalFilename()));

      File profileImageFile = this.userService.addProfileImage(userId, file.getOriginalFilename());
   }
   return "redirect:/users/" + userId;
}
```

# 解析 Thymeleaf 视图

Thymeleaf 是一个基于 Java 的 XML/HTML/HTML5 模板引擎库，用于构建 Web 应用程序。它允许更快地处理模板，并由于解析视图文件的智能缓存而提高性能。请参考官方的 Thymeleaf 文档了解 Thymeleaf 页面编写。

您需要在 Maven 依赖项中添加 Thymeleaf 和 Spring（`org.thymeleaf`）才能在项目中使用 Thymeleaf。可以使用以下代码片段在项目中解析 Thymeleaf 视图：

```java
<beans:bean class="org.thymeleaf.spring4.view.ThymeleafViewResolver">
   <beans:property name="templateEngine" ref="templateEngine" />
   <beans:property name="order" value="1" />
   <beans:property name="viewNames" value="*.html,*.xhtml" />
</beans:bean>

<beans:bean id="templateResolver" class= "org.thymeleaf.templateresolver.ServletContextTemplateResolver">
   <beans:property name="prefix" value="/WEB-INF/templates/" />
   <beans:property name="suffix" value=".html" />
   <beans:property name="templateMode" value="HTML5" />
</beans:bean>

<beans:bean id="templateEngine" class="org.thymeleaf.spring4.SpringTemplateEngine">
   <beans:property name="templateResolver" ref="templateResolver" />
</beans:bean>
```

# 更多视图技术

Spring MVC 支持一组令人印象深刻的视图技术；在项目中添加正确的 Maven 依赖项后，您可以使用其中任何一个。Spring 为大多数视图技术提供了开箱即用的视图解析器。以下是 Spring MVC 支持的其他视图技术列表：

+   Velocity 和 FreeMarker

+   Groovy 标记模板

+   JavaScript 模板（在 Nashhorn 上）：Handlebars、Mustache、ReactJS 和 EJS

+   JRuby 上的 ERB 模板和 Jython 上的 String 模板

+   XML 视图和 XSLT（内置）

+   Tiles

+   PDF（iText）和 Excel（Apache POI）

+   JasperReports

+   Feed 视图

在大多数情况下，您需要在同一个应用程序中混合和匹配视图技术。例如，您可能会在普通 HTML 屏幕上使用 JSP，但仍然需要 JasperReports 来报告屏幕，并可能需要将一些报告下载为 PDF 和 Excel 文件。使用 Spring MVC 可以确保所有这些功能可以轻松集成。

# 总结

在本章中，我们学习了如何使用 Spring MVC 构建高度可扩展和动态的 Web 应用程序。从设置项目和配置`WebApplicationContext`以适当的分层开始，我们探索了设计控制器的不同方式，并为 Web 和 API 端点映射请求处理程序，包括异步处理和多部分文件上传，使用易于配置的组件。现在，我们可以使用`<spring>`和`<form>`标签组合美丽的 JSP 页面，并使用验证 API 启用表单验证。

到目前为止，我们一直在内存中保存数据，而不用担心将其持久化在某个地方。在下一章中，我们将深入企业应用程序开发的数据层，学习有关 ACID 事务的各种数据访问和持久化机制，包括有和没有 ACID 事务。从这一点开始，我们将处理更严重的问题。

