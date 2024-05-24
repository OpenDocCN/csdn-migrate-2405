# Spring5 学习手册（一）

> 原文：[`zh.annas-archive.org/md5/6DF1C981F26DA121DCB8C1B33E7DE022`](https://zh.annas-archive.org/md5/6DF1C981F26DA121DCB8C1B33E7DE022)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 第一章。Spring 概览

*Spring，传统 J2EE 的冬天之后的新起点*，这就是 Spring 框架的真正含义。是处理 Java 企业应用程序中众多复杂模块相互协作开发的最问题解决方案。Spring 不是传统 Java 开发的替代品，而是公司应对当今竞争激烈、快速发展的市场的可靠解决方案，同时不让开发者紧密依赖于 Spring API。

在本主题中，我们将涉及以下几点：

+   Spring 框架简介

+   Spring 在企业应用程序开发中解决的问题

+   Spring 路线图

+   Spring 5.0 的新特性

## spring 框架简介

引言

罗德·约翰逊是澳大利亚计算机专家，也是 SpringSource 的联合创始人。《J2EE 设计和发展一对一专家》于 2002 年 11 月由他出版。这本书包含大约 30000 行代码，其中包括框架的基本概念，如**控制反转**（**IoC**）和**依赖注入**（**DI**）。这部分代码被称为 interface21。他写这部分代码的初衷只是为了方便开发者工作，或者作为他们自己开发的基石。他从未想过开发任何框架或类似的东西。在 Wrox 论坛上，关于代码、其改进和其他许多事情进行了长时间的讨论。论坛上的两位读者尤尔根·霍勒和扬·卡罗夫提出了将代码作为新框架基础的想法。这是扬的理由，*Spring，传统 J2EE 的冬天之后的新起点*，他将框架命名为 Spring 框架。该项目于 2003 年 6 月公开，并朝着 1.0 版本迈进。此后，为了支持市场上的技术，发生了许多变化和升级。本书关注的是最新版本 5.0。在接下来的几页中，我们将介绍这个版本中添加的新特性。在随后的页面中，我们将介绍如何将最新特性应用于您的应用程序，以及作为开发人员如何充分利用这些特性。

## Spring 解决的问题

引言

Java 平台是一个长期、复杂、可扩展、积极进取并快速发展的平台。应用程序开发在特定的版本上进行。为了保持最新的标准和与之相适应，这些应用程序需要不断升级到最新版本。这些应用程序有大量的类相互交互，复用 API 以充分发挥其优势，使应用程序运行顺畅。但这导致了 AS 的许多常见问题。

### 可扩展性

市场上的每项技术，无论是硬件还是软件，其增长和发展的速度都非常快。几年前开发的应用程序可能会因为这些领域的增长而变得过时。市场的要求如此之高，以至于开发者需要不断更新应用程序。这意味着我们今天开发的任何应用程序都应能在不影响现有运行的情况下，处理未来的需求和增长。应用程序的可扩展性是处理或支持工作负载的增加，以适应不断增长的环境，而不是替换它们。应用程序能够支持因用户数量增加而增加的网站流量，这是一个非常简单的例子，说明应用程序是可扩展的。由于代码紧密耦合，使其可扩展成为一个问题。

### 管道代码

让我们以在 Tomcat 环境中配置 DataSource 为例。现在开发者想要在应用程序中使用这个配置的 DataSource。我们会做什么？是的，我们会进行 JNDI 查找以获取 DataSource。为了处理 JDBC，我们将获取资源并在`try catch`中释放。像我们在这里讨论的`try catch`，计算机间的通信，集合等都是必要的，但不是特定于应用程序的，这些是管道代码。管道代码增加了代码的长度，并使调试变得复杂。

### 样板代码

我们在进行 JDBC 时如何获取连接？我们需要注册 Driver 类，并在 DriverManager 上调用`getConnection()`方法以获取连接对象。这些步骤有其他替代方案吗？实际上没有！无论何时，无论在哪里进行 JDBC，这些相同的步骤每次都必须重复。这种重复的代码，开发者在不同地方编写的代码块，少量或没有修改以实现某些任务，称为样板代码。样板代码使 Java 开发变得不必要地更长和更复杂。

### 无法避免的非功能性代码

无论何时进行应用程序开发，开发者都会专注于业务逻辑、外观和要实现的数据持久性。但除了这些事情，开发者还会深入思考如何管理事务，如何处理网站上的增加负载，如何使应用程序安全等问题。如果我们仔细观察，这些事情并不是应用程序的核心关注点，但它们却是无法避免的。这种不处理业务逻辑（功能性）需求，但对维护、故障排除、应用程序安全等重要的代码称为非功能性代码。在大多数 Java 应用程序中，开发者经常不得不编写非功能性代码。这导致对业务逻辑开发产生了偏见。

### 单元测试应用程序

让我们来看一个例子。我们希望测试一段将数据保存到数据库中的代码。这里测试数据库不是我们的目的，我们只是想确定我们编写的代码是否正常工作。企业级 Java 应用程序由许多相互依赖的类组成。由于对象之间存在依赖，因此进行测试变得困难。

Spring 主要解决了这些问题，并提供了一个非常强大而又简单的解决方案，

### 基于 POJO 的开发

类是应用程序开发的基本结构。如果类被扩展或实现了框架的接口，由于它们与 API 紧密耦合，因此复用变得困难。**普通老式 Java 对象**（**POJO**）在 Java 应用程序开发中非常著名且经常使用。与 Struts 和 EJB 不同，Spring 不会强制开发者编写导入或扩展 Spring API 的代码。Spring 最好的地方在于，开发者可以编写通常不依赖于框架的代码，为此，POJO 是首选。POJO 支持松耦合的模块，这些模块可复用且易于测试。

### 注意

Spring 框架之所以被称为非侵入性，是因为它不会强制开发者使用 API 类或接口，并允许开发松耦合的应用程序。

### 通过依赖注入实现松耦合

耦合度是类与类之间知识的关联程度。当一个类对其他类的设计依赖性较低时，这个类就可以被称为松耦合。松耦合最好通过**接口编程**来实现。在 Spring 框架中，我们可以将类的依赖关系在与代码分离的配置文件中维护。利用 Spring 提供的接口和依赖注入技术，开发者可以编写松耦合的代码（别担心，我们很快就会讨论依赖注入以及如何实现它）。借助松耦合，开发者可以编写出因依赖变化而需要频繁变动的代码。这使得应用程序更加灵活和易于维护。

### 声明式编程

在声明式编程中，代码声明了将要执行什么，而不是如何执行。这与命令式编程完全相反，在命令式编程中，我们需要逐步说明我们将执行什么。声明式编程可以通过 XML 和注解来实现。Spring 框架将所有配置保存在 XML 中，框架可以从中维护 bean 的生命周期。由于 Spring 框架中的开发，从 2.0 版本开始提供了 XML 配置的替代方案，即使用广泛的注解。

### 使用方面和模板减少样板代码

我们刚刚在前几页讨论过，重复的代码是样板代码。样板代码是必要的，如果没有它，提供事务、安全、日志等功能将变得困难。框架提供了解决编写处理此类交叉关注点的 Aspect 的方案，无需将其与业务逻辑代码一起编写。使用 Aspect 有助于减少样板代码，但开发者仍然可以实现相同的效果。框架提供的另一个功能是不同需求的模板。JDBCTemplate、HibernateTemplate 是 Spring 提供的另一个有用的概念，它减少了样板代码。但事实上，你需要等待理解并发现其真正的潜力。

### **分层架构**

与分别提供 Web 持久性解决方案的 Struts 和 Hibernate 不同，Spring 有一系列广泛的模块解决多种企业开发问题。这种分层架构帮助开发者选择一个或多个模块，以一种连贯的方式为他的应用程序编写解决方案。例如，即使不知道框架中有许多其他模块，开发者也可以选择 Web MVC 模块高效处理 Web 请求。

## **Spring 架构**

****

Spring 提供了超过 20 个不同的模块，可以大致归纳为 7 个主要模块，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_01_001.png)

**Spring 模块**

### **核心模块**

#### **核心**

**Spring 核心模块**支持创建 Spring bean 的方法以及向 bean 中注入依赖。它提供了配置 bean 以及如何使用 BeanFactory 和 ApplicationContext 从 Spring 容器获取配置 bean 的方法，用于开发独立应用程序。

#### **Beans**

**Beans 模块**提供了**BeanFactory**，为编程单例提供了替代方案。BeanFactory 是工厂设计模式的实现。

#### **上下文**

这个模块支持诸如 EJB、JMX 和基本远程调用的 Java 企业特性。它支持缓存、Java 邮件和模板引擎（如 Velocity）的第三方库集成。

#### **SpEL**

**Spring 表达式语言（SpEL）**是**统一表达式语言**的扩展，该语言已在 JSP 2.1 规范中指定。SpEL 模块支持设置和获取属性值，使用逻辑和算术运算符配置集合，以及从 Spring IoC 中获取命名变量。

### **数据访问与集成模块**

#### **JDBC（DAO）**

这个模块在 JDBC 之上提供了抽象层。它支持减少通过加载驱动器获取连接对象、获取语句对象等产生的样板代码。它还支持模板，如 JdbcTemplate、HibernateTemplate，以简化开发。

#### **ORM**

对象关系映射（ORM）模块支持与非常流行的框架（如 Hibernate、iBATIS、Java 持久性 API（JPA）、Java 数据对象（JDO））的集成。

#### **OXM**

对象 XML 映射器（OXM）模块支持对象到 XML 的映射和集成，适用于 JAXB、Castor、XStream 等。

#### JMS

此模块提供支持，并为通过消息进行异步集成的 Java 消息服务（JMS）提供 Spring 抽象层。

#### 事务

JDBC 和 ORM 模块处理 Java 应用程序与数据库之间的数据交换。此模块在处理 ORM 和 JDBC 模块时支持事务管理。

### Web MVC 和远程模块

#### Web

此模块支持与其他框架创建的 web 应用程序的集成。使用此模块，开发人员还可以通过 Servlet 监听器开发 web 应用程序。它支持多部分文件上传和请求与响应的处理。它还提供了与 web 相关的远程支持。

#### Servlet

此模块包含 Spring 模型视图控制器（MVC）实现，用于 web 应用程序。使用 Spring MVC，开发人员可以编写处理请求和响应的代码，以开发功能齐全的 web 应用程序。它通过支持处理表单提交来摆脱处理请求和响应的样板代码。

#### 门户

门户模块提供了 MVC 实现，用于支持 Java 门户 API 的门户环境。

### 注意

门户在 Spring 5.0M1 中被移除。如果您想使用门户，则需要使用 4.3 模块。

#### WebSocket

WebSocket 是一种协议，提供客户端与服务器之间的双向通信，已在 Spring 4 中包含。此模块为应用程序提供对 Java WebSocket API 的集成支持。

### 注意

**`Struts 模块`** 此模块包含支持将 Struts 框架集成到 Spring 应用程序中的内容。但在 Spring 3.0 中已弃用。

### AOP 模块

#### AOP

面向方面编程（AOP）模块有助于处理和管理应用程序中的交叉关注点服务，有助于保持代码的清洁。

#### 方面

此模块为 AspectJ 提供了集成支持。

### 仪器模块

#### 仪器

Java 仪器提供了一种创新的方法，通过类加载器帮助从 JVM 访问类并修改其字节码，通过插入自定义代码。此模块支持某些应用服务器的仪器和类加载器实现。

#### 仪器 Tomcat

仪器 Tomcat 模块包含对 Tomcat 的 Spring 仪器支持。

#### 消息传递

消息传递模块提供了对 STOMP 作为 WebSocket 协议的支持。它还有用于路由和处理从客户端接收的 STOMP 消息的注解。

+   Spring 4 中包含了消息传递模块。

### 测试模块

测试模块支持单元以及集成测试，适用于 JUnit 和 TestNG。它还提供创建模拟对象的支持，以简化在隔离环境中进行的测试。

## Spring 还支持哪些底层技术？

***

### 安全模块

如今，仅具有基本功能的应用程序也需要提供良好的多层次安全处理方式。Spring5 支持使用 Spring AOP 的声明式安全机制。

### 批量处理模块

Java 企业应用需要执行批量处理，在没有用户交互的情况下处理大量数据，这在许多商业解决方案中是必需的。以批处理方式处理这些问题是可用的最佳解决方案。Spring 提供了批量处理集成，以开发健壮的应用程序。

### Spring Integration

在企业应用的开发中，应用可能需要与它们进行交互。Spring Integration 是 Spring 核心框架的扩展，通过声明式适配器提供与其他企业应用的集成。消息传递是此类集成中广泛支持的一项。

### 移动模块

广泛使用移动设备为开发打开了新的大门。这个模块是 Spring MVC 的扩展，有助于开发称为 Spring Android Project 的手机网络应用。它还提供检测发起请求的设备类型，并相应地呈现视图。

### LDAP 模块

Spring 的初衷是简化开发并减少 boilerplate 代码。Spring LDAP 模块支持使用模板开发进行简单的 LDAP 集成。

### .NEW 模块

引入了新的模块来支持.NET 平台。ADO.NET、NHibernate、ASP.NET 等模块包含在.NET 模块中，以简化.NET 开发，利用 DI、AOP、松耦合等特性。

## Spring 路线图

* * *

### 1.0 2004 年 3 月

它支持 JDO1.0 和 iBATIS 1.3，并与 Spring 事务管理集成。这个版本支持的功能有，Spring Core、Spring Context、Spring AOP、Spring DAO、Spring ORM 和 Spring web。

### 2.0 2006 年 10 月

Spring 框架增强了 Java5 的支持。它添加了开箱即用的命名空间，如 jee、tx、aop、lang、util，以简化配置。IoC 支持单例和原型等作用域。除了这些作用域，还引入了 HttpSession、集群缓存和请求的作用域。引入了基于注解的配置，如@Transactional、@Required、@PersistenceContext。

### 2.5 2007 年 11 月

在这个版本中，Spring 支持完整的 Java 6 和 Java EE 5 特性，包括 JDBC 4、JavMail 1.4、JTA 1.1、JAX WS 2.0。它还扩展了对基于注解的依赖注入的支持，包括对限定符的支持。引入了一个名为 AspectJ 切点表达式中的 pointcut 元素的新 bean。提供了基于 LoadTimeWeaver 抽象的 AspectJ 加载时间编织的内置支持。为了方便，包含了像 context、jms 这样的自定义命名空间的介绍。测试支持扩展到了 Junit4 和 TestNG。添加了基于注解的 Spring MVC 控制器。它还支持在类路径上自动检测组件，如@Repository、@Service、@Controller 和@Conponent。现在 SimpleJdbcTemplate 支持命名 SQL 参数。包含了认证的 WebSphere 支持。还包括了对 JSR-250 注解的支持，如@Resource、PostConstruct、@PreDestroy。

### 3.0 GA 2009 年 12 月

整个代码已修订以支持 Java 5 特性，如泛型、可变参数。引入了 Spring 表达式语言(SpEL)。还支持 REST web 应用程序的注解。扩展了对许多 Java EE 6 特性的支持，如 JPA 2.0、JSF 2.0。版本 3.0.5 还支持 hibernate 3.6 最终版。

### 3.1GA 2011 年 12 月

在这个版本中，测试支持已升级到 Junit 4.9。还支持在 WebSphere 版本 7 和 8 上进行加载时间编织。

### 4.0 2013 年 12 月

首次全面支持 Java 8 特性。这个版本使用 Java EE 6 作为其基础。使用 Spring 4，现在可以定义使用 Groovy DSL 的外部 bean 配置。开发者现在可以将泛型类型作为一种限定符形式。@Lazy 注解可以用于注入点以及@Bean 定义。为了开发者使用基于 Java 的配置，引入了@Description 注解。引入了@Conditional 注解进行条件过滤。现在，不再需要默认构造函数供 CGLIB 基于的代理类使用。引入了@RestController 以去除对每个@RequestMapping 的@ResponseBody 的需求。包括了 AsynchRestTemplate，它允许非阻塞异步支持 REST 客户端开发。作为新的模型引入了 spring-websocket，以提供对基于 WebSocket 的服务器和客户端之间的双向通信的支持。引入了 spring-messaging 模块以支持 WebSocket 子协议 STOMP。现在可以作为元注解使用大部分来自 spring-test 模块的注解来创建自定义组合注解。org.springframework.mock.web 包中的 mocks 基于 Servlet API 3.0。

### 5.0 M1 Q4 2016

Spring 5M1 将支持 Java8+，但基本上，它旨在跟踪并对 Java9 的新特性提供大量支持。它还将支持响应式编程 Spring 5 将专注于 HTT2.0。它还通过响应式架构关注响应式编程。spring-aspects 中的 mock.staticmock 和 web.view.tiles2 已经被移除。不再支持 Portlet、Velocity、JasperReports、XMLBeans、JDO、Guava。

可以总结如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_01_002.png)

Spring 模块

## 容器-Spring 的心脏

* * *

POJO 开发是 Spring 框架的基石。在 Spring 中配置的 POJO，其对象的实例化、对象组装、对象管理都是由 Spring IoC 容器完成的，称为 bean 或 Spring bean。我们使用 Spring IoC，因为它遵循控制反转的模式。

### 控制反转（IoC）

在每一个 Java 应用程序中，每位开发者做的第一件重要的事情就是获取一个可以在应用程序中使用的对象。一个对象的状况可以在运行时获得，也可能在编译时获得。但是开发者通常在多次使用样板代码时创建对象。当同一个开发者使用 Spring 而不是亲自创建对象时，他将依赖于框架来获取对象。控制反转（IoC）这个术语是因为 Spring 容器将对象创建的责任从开发者那里反转过来。

Spring IoC 容器只是一个术语，Spring 框架提供了两个容器

+   BeanFactory

+   应用程序上下文（ApplicationContext）

### BeanFactory 的历史

BeanFactory 容器提供了基本功能和框架配置。现在，开发者不会倾向于使用 BeanFactory。那么，为什么 BeanFactory 仍然在框架中呢？为什么没有被移除呢？如果没有 BeanFactory，那么替代品是什么？让我们逐一回答这些问题。BeanFactory 在框架中的一个非常简单的答案是为了支持 JDK1.4 的向后兼容性。BeanFactory 提供了 BeanFactoryAware、InitializingBean、DisposableBean 接口，以支持与 Spring 集成的第三方框架的向后兼容性。

#### XMLBeanFactory

当今的企业应用程序开发需求远超过普通开发。开发者将很高兴能得到帮助来管理对象生命周期、注入依赖项或减少 IoC 容器的样板代码。XMLBeanFactory 是 BeanFactory 的常见实现。

让我们实际找出 BeanFactory 容器是如何初始化的：

1.  创建一个名为`Ch01_Container_Initialization`的 Java 应用程序。

1.  按照以下快照添加 jar 包：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_01_003.png)

需要添加的 jar 包

### 注意

确保你使用的是 JRE 1.8，因为它 是 Spring5.0.0.M1 的基础。你可以从...............下载 jar 包。

1.  在`com.ch01.test`包下创建一个名为`TestBeanFactory`的类。

1.  在类路径中创建一个名为`beans_classpath.xml`的 XML 文件，我们可以在以后编写 bean 定义。每个 bean 定义文件都包含对特定 Spring 版本的 beans.xsd 的引用。这个 XML 文件的根标签将是`<beans>`。

XML 文件的基本结构如下：

```java
      <?xml version="1.0" encoding="UTF-8"?> 
        <beans xmlns="http://www.springframework.org/schema/beans" 
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
          xsi:schemaLocation="http://www.springframework.org/schema/beans 
          http://www.springframework.org/schema/beans/spring-beans.xsd"> 
        </beans> 

```

我们的 XML 文件包含上述相同的代码，没有配置任何 bean。

1.  在 main 函数中，让我们写下初始化 bean 工厂的代码，如下所示：

```java
      BeanFactory beanFactory=new XmlBeanFactory( 
        new ClassPathResource("beans_classpath.xml")); 

```

在这里，`bean_classpath.xml`将包含 bean 定义（为了简单起见，我们没有添加任何 bean 定义，我们将在下一章详细介绍）。`ClassPathResource`从类路径加载资源。

1.  有时资源不会在类路径中，而是在文件系统中。以下代码可用于从文件系统加载资源：

```java
      BeanFactory beanFactory=new XmlBeanFactory( 
        new FileSystemResource("d:\\beans_fileSystem.xml")); 

```

1.  我们需要在 D 驱动器上创建`bean_fileSystem.xml`，它将包含与`bean_classpath.xml`相同的内容。完整代码如下：

```java
      public class TestBeanFactory { 
        public static void main(String[] args) { 
          // TODO Auto-generated method stub 
          BeanFactory beanFactory=new XmlBeanFactory(new
            ClassPathResource("beans_classpath.xml"));
          BeanFactory beanFactory1=new XmlBeanFactory(new
            FileSystemResource("d:\\beans_fileSystem.xml")); 
          System.out.println("beanfactory created successfully"); 
        } 
      } 

```

由于我们在这里没有编写任何输出代码，除了 Spring 容器的日志信息外，控制台上不会有任何输出。但以下快照显示了 XML 文件加载并初始化了容器：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_01_004.png)

控制台日志输出

### 注意

BeanFactory 不支持多个配置文件。

### 应用程序上下文：现状

注册 BeanProcessor 和 BeanFactoryPostProcessor 在 AOP 和属性占位符中扮演重要角色，需要显式编写代码，这使得与其配合变得不方便。开发者不想编写支持国际化的代码。处理 AOP 集成的事件发布是不可避免的。Web 应用程序需要具有特定于应用层的内容。对于这些问题，简单的解决方案是扩展 BeanFactory 提供的服务，以支持 ApplicationContext。ApplicationContext 不是 BeanFactory 的替代品，而是针对企业特定解决方案的扩展，以及为 bean 配置提供更多高级机制。

让我们来看看实现。

#### ClassPathXmlApplicationContext

对于独立应用程序，使用 AbstractXmlApplicationContext 的子类。它使用类路径中的配置的 bean XML 文件。如果有多个 XML 配置文件，后来的 bean 定义将覆盖先前的 bean 定义。它提供了编写新 bean 定义以替换先前的定义的优势。

让我们实际找出`ClassPathXmlApplicationContext`容器是如何初始化的。我们将使用相同的`Ch01_Container_Initialization`项目，按照以下步骤进行：

1.  在`com.ch01.test`包下创建一个名为`TestClasspathApplicationContext`的类。

1.  在新的应用程序中，像以前一样在类路径中创建一个名为`beans_classpath.xml`的 XML 文件。

1.  在 main 函数中，让我们写下初始化 bean 工厂的代码，如下所示：

```java
      try { 
        ApplicationContext context=new
          ClassPathXmlApplicationContext("beans_classpath.xml"); 
        System.out.println("container created successfully"); 
      } 
      catch (BeansException e) { 
        // TODO Auto-generated catch block 
        e.printStackTrace(); 
      } 

```

不需要创建 XML 文件，因为我们已经在之前的示例中创建了它。`ClassPathXmlApplicationContext`从类路径加载`bean_classpath.xml`文件，其中包含 bean 定义（为了简单起见，我们没有添加任何 bean 定义，我们将在下一章详细介绍）。

1.  运行应用程序，输出以下内容，表明容器成功创建：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_01_005.png)

控制台输出

1.  在 Java 企业应用程序中，项目可以有多个配置文件，因为这样可以容易地维护和支持模块化。要加载多个 bean 配置文件，我们可以使用以下代码：

```java
      try { 
        ApplicationContext context1 = new 
          ClassPathXmlApplicationContext 
            (new String[]
            {"beans_classpath.xml","beans_classpath1.xml" }); 
       }  
       catch (BeansException e) { 
         // TODO Auto-generated catch block 
         e.printStackTrace(); 
       } 

```

要使用前面的代码行，我们需要在类路径中创建`beans_classpath1.xml`。

#### FileSystemXmlApplicationContext

与 ClassPathXmlApplicationContext 类似，这个类也扩展了 AbstractXmlApplicationContext，用于独立应用程序。但这个类有助于从文件系统加载 bean 的 XML 定义。文件路径相对于当前工作目录。如果指定绝对文件路径，可以使用`file:`作为前缀。它还提供了在有多个 XML 配置的情况下，编写新的 bean 定义以替换之前的定义的优势。

让我们实际找出`ClassPathXmlApplicationContext`容器是如何初始化的。我们将按照以下步骤使用相同的`Ch01_Container_Initialization`项目：

1.  在`com.ch01.test`包下创建一个名为`TestFileSystemApplicationContext`的类。

1.  在之前应用程序中创建的 D 驱动器上创建一个新的 XML 文件`beans_fileSystem.xml`。

1.  在主函数中，让我们写下以下代码来初始化 bean 工厂：

```java
      try { 
        ApplicationContext context=new   
          FileSystemXmlApplicationContext 
          ("d:\\beans_fileSystem.xml"); 
        System.out.println("container created successfully"); 
      } 
      catch (BeansException e) { 
        // TODO Auto-generated catch block 
        e.printStackTrace(); 
      } 

```

`FileSystemXmlApplicationContext`从指定路径加载`bean_fileSystem.xml`文件。

1.  运行应用程序，将给出以下输出，表明容器已成功创建。

上述讨论的项目结构将如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_01_006.png)

项目目录结构

#### WebXmlApplicationContext

`WebXmlApplicationContext`继承了`AbstractRefreshableWebApplicationContext`。我们可以在`applicationContext.xml`中编写与根应用程序上下文相关的上下文定义，并将其放在 WEB-INF 下，因为这是默认的位置，从这里加载上下文定义。`XXX-servlet.xml`文件用于加载控制器定义，正如在 MVC 应用程序中所示。此外，我们可以通过为`context-param`和`init-param`配置`contextConfigLocation`来覆盖默认位置。

## 容器中如何获取 bean？

* * *

是的，如果不从开发方面做任何事情，豆子或豆子对象将无法获得。Spring 管理豆子，但是必须决定要管理什么，并将其传递给容器。Spring 通过 XML 文件配置支持声明式编程。在 XML 文件中配置的豆子定义由容器加载，并使用 org.springframework.beans 在容器中实例化对象和注入属性值。豆子生命周期解释了每个豆子对象从使对象可供应用程序使用直至应用程序不再需要时将其清理并从容器中移除的各个阶段、阶段或活动。我们将在下一章讨论详细的初始化过程。

## 摘要

* * *

本章概述了 Spring 框架。我们讨论了在 Java 企业应用程序开发中遇到的通用问题以及 Spring 框架是如何解决它们的。我们看到了自 Spring 首次进入市场以来每个版本中发生的重大变化。Spring 框架的核心是豆子。我们使用 Spring 来简化容器管理它们的工作。我们详细讨论了两个 Spring 容器 BeanFactory 和 ApplicationContext，以及开发人员如何使用它们。容器参与了豆子生命周期管理的过程。在下一章，我们旨在深入讨论关于豆子状态管理以及一个非常著名的术语依赖注入和豆子生命周期管理。


## 第二章：依赖注入

上一章概述了 Spring 框架是什么以及它如何帮助开发者加快开发速度和简化开发。但是，“如何使用这个框架？”的问题仍然没有答案。在本章中，我们将从所有角度讨论答案，并尝试找出所有可能的答案。本章充满了配置和配置的替代方案。这取决于开发者如何在这些解决方案和应用程序的可用条件及环境设置中展望。我们旨在深入探讨以下几点：

+   我们将从自定义初始化的豆子生命周期管理开始，探讨 InitializingBean、DisposableBean 和 Aware 接口，以及在豆子生命周期中使用@PostConstruct 和@PreDestroy 注解。

+   依赖注入

+   设置器和构造函数依赖注入

+   依赖注入（DI）用于参考、内部豆子、继承和集合

+   豆子作用域以及将作用域配置为单例或原型

+   自动装配及实现自动装配的方法

+   自动装配过程中发生的问题及解决方法

要覆盖的内容很多，所以我们从“豆子的生命周期”开始。

## 豆子的生命周期

* * *

Spring IoC 容器隐藏了容器与豆子之间复杂的通信。以下图表给出了容器维护每个豆子生命周期的步骤的一个大致概念：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_02_001.png)

豆子生命周期

### 加载配置

这是豆子生命周期中最重要的阶段，它启动生命周期过程。容器加载并从豆子配置文件中读取元数据信息，然后开始下一阶段“实例化”。

### 对象创建

Spring 容器使用 Java 反射 API 创建一个豆子的实例。

### 设置豆子名称

每个豆子都在配置中包含一个独特的名称。这个名称可以通过`setBeanName()`方法提供给豆子类。如果豆子类实现了`BeanNameAware`接口，那么它的`setBeanName()`方法会被调用以设置豆子名称。

### 设置豆子工厂

有时豆子类可能需要获取有关加载它的工厂的信息。如果豆子类实现了`BeanFactoryAware`，那么它的`setBeanFactory()`方法将被调用，传递`BeanFactory`实例给它，这可能是一个`ApplicationContext`、`WebApplicationContext`等实例。

### 使用`postProcessBeforeInitialization`进行豆子后处理

在某些场景中，在对象的值得到填充之前需要进行一些预初始化，这无法在配置文件中完成。在这种情况下，如果 BeanPostProcessor 对象执行这个任务。BeanPostProcessor 是一种特殊的 bean，在实例化任何其他 bean 之前被实例化。这些 BeanPostProcessor bean 与容器创建的新实例交互。但是，这将分为两个步骤进行，一次是在属性设置之前，第二次是在属性设置之后。在这个阶段，与 BeanFactory 关联的 BeanPostProcessor，它的 PostProcessorBeforeInitiallization 方法将被调用进行预初始化。

### 属性填充

bean 配置可能指定一些 bean 属性。在这个阶段，所有值都将与在前一阶段初始化的实例相关联。

### 使用 bean 进行初始化

#### 使用 afterPropertiesSet() 方法

可能发生的情况是，配置中的 bean 没有设置所有属性的值。一旦属性得到填充，使用某些业务逻辑或其他方式设置剩余的属性。`InitializingBean` 接口在任务中提供帮助。如果类实现了 `InitializingBean` 接口，其 `afterPropertiesSet()` 方法将调用以设置这些属性。

#### 自定义 init() 方法

尽管 `afterProperties()` 有助于根据某些逻辑对属性进行初始化，但代码与 Spring API 紧密耦合。为了克服这个缺点，有一种方法可以使用自定义初始化方法来初始化 bean。如果开发者编写了自定义 `init` 方法并在 bean 配置中将其配置为 '`init-method`' 属性，容器会调用它。

### 使用 postProcessAfterInitialization 进行 bean 后处理

当属性初始化完成后，BeanPostProcessor 的 `postProcessAfterInitialization()` 方法将被调用进行 `postProcessing`。

### 使用 bean

谢天谢地！！！现在对象的状态定义完美，完全准备好使用。

### 使用销毁 bean 的方法

开发者使用了对象，对象已经完成了它们的任务。现在我们不再需要它们了。为了释放 bean 占用的内存，可以通过以下方式销毁 bean，

#### 使用 destroy() 方法销毁 bean

如果 bean 类实现了 DisposableBean 接口，其 destroy() 方法将被调用以释放内存。它具有与 InitializingBean 相同的缺点。为了克服这个问题，我们确实有自定义的销毁方法。

#### 使用自定义 destroy() 方法进行销毁

也可以编写一个自定义方法来释放内存。当在 bean 配置定义中配置了 'destroy-method' 属性时，它将被调用。

+   在了解了生命周期之后，让我们现在做一些实现，以了解实现观点。

### 案例 1：使用自定义初始化和销毁方法

正如我们在 bean 生命周期中已经讨论过的，这两个方法将使开发者能够编写自己的初始化和销毁方法。由于开发者不受 Spring API 的耦合，他们可以利用这一点选择自己的方法签名。

让我们看看如何逐步将这些方法钩入以供 Spring 容器使用：

1.  创建一个名为 Ch02_Bean_Life_Cycle 的 Java 应用程序，并添加我们在之前项目中完成的 jar。

1.  在 com.ch02.beans 包下创建一个名为 Demo_Custom_Init 的类，如下所示：

```java
      public class Demo_Custom_Init { 
        private String message; 
        private String name; 

        public Demo_Custom_Init() { 
          // TODO Auto-generated constructor stub 
          System.out.println(""constructor gets called for  
            initializing data members in Custom init""); 
          message=""welcome!!!""; 
          name=""no name""; 
        } 

        @Override 
        public String toString() { 
          // TODO Auto-generated method stub 
          return message+""\t""+name; 
        } 
      } 

```

1.  向类中添加一个名为 myInit()的方法，并使用以下代码进行初始化。在这里，我们将'name'转换为大写：

```java
        public void myInit() 
        { 
          name=name.toUpperCase(); 
          System.out.println(""myInit() get called""); 
        } 

```

1.  在类路径创建 bean_lifecycle.xml 文件，以配置类似于之前项目的 bean（参考 Ch01_Container_Initizatization 中的 beans_classpath.xml）。

1.  在此基础上添加 bean 定义如下：

```java
      <?xml version=""1.0"" encoding=""UTF-8""?> 
      <beans xmlns=""http://www.springframework.org/schema/beans"" 
        xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" 
        xsi:schemaLocation= 
          "http://www.springframework.org/schema/beans 
          http://www.springframework.org/schema/beans/
          spring-beans.xsd"> 

        <bean id="obj" class="com.ch02.beans.demo_Custom_Init"></bean> 
      </beans> 

```

每个 bean 必须在`<bean>`标签内配置。

* `<bean>`标签包含许多我们需要配置的属性，其中至少需要两个，如下所示：

+   a. id：指定容器识别其正在管理的对象的确切名称。'id'必须在容器内唯一。命名'id'与 Java 应用程序中的引用类似。

+   b. class：指定容器正在创建和管理哪个对象。class 属性的值必须是完全限定类名，正如我们在上面的配置中所做的那样。

+   在 XML 中配置 bean 定义的语法如下所示：

```java
      <bean id="id_to_use" class="fully_qualified_class_name"></bean>
```

+   XML 配置与 Java 代码相当，

```java
      Demo_Custom_Init obj= new  com.ch02.beans.Demo_Custom_Init();
```

### 注意

开发者可以在配置中使用一些其他属性。我们将在接下来的章节中根据场景逐一介绍它们。

1.  步骤 5 中显示的配置是非常基本的配置，没有向容器提供关于如何初始化属性'name'的信息。让我们通过添加'init-method'属性来修改配置，以指定在实例化后调用以初始化属性的方法名。修改后的代码如下：

```java
      <bean id="obj" class="com.ch02.beans.demo_Custom_Init"
        init- method=""myInit""> 
      </bean> 

```

1.  我们进行初始化的方式，同样我们也可以释放资源。要使用自定义的销毁方法释放资源，我们首先需要在代码中添加如下内容：

```java
      public void destroy() 
      { 
        name=null; 
        System.out.println(""destroy called""); 
      } 

```

1.  在 bean 配置中通过指定 destroy-method 来配置销毁方法，如下面的代码所示：

```java
      <bean id="obj" class="com.ch02.beans.demo_Custom_Init"
        init-method="myInit" destroy-method="destroy"> 
      </bean> 

```

1.  创建一个名为`Test_Demo_Custom_Init`的 Java 程序，并添加 main 函数。像我们在第一章中一样初始化容器。并使用`getBean()`获取`Demo_Custom_Init`的实例，如下所示：

```java
      public static void main(String[] args) { 
        // TODO Auto-generated method stub 
        ApplicationContext context=new
        ClassPathXmlApplicationContext("beans_lifecycle.xml");
        Demo_Custom_Init obj=(Demo_Custom_Init)context.getBean("obj"); 
        System.out.println(obj); 
      } 

```

1.  代码的执行给出了以下输出：

```java
      INFO: Loading XML bean definitions from class path resource 
      [beans_lifecycle.xml] 
      constructor gets called for initializing data members 
      myInit() get called 
      welcome!!!  NO NAME 

```

输出清楚地显示了 bean 的生命周期阶段，包括构造、初始化、使用和销毁。

不要对缺少'destroy called'语句感到惊讶。我们可以使用以下代码优雅地关闭容器：

```java
((AbstractApplicationContext)context).registerShutdownHook(); 

```

在 main 函数中添加上述代码后，甚至'destroy called'也会作为控制台输出出现。

### 案例 2：使用 InitializingBean 提供初始化

我们将使用与案例 1 中开发相同的项目 Ch02_Bean_Life_Cycle。

按照以下步骤操作：

1.  在 com.ch02.beans 包中添加一个实现 InitializingBean 接口的 Demo_InitializingBean 类，如下所示：

```java
      public class Demo_InitializingBean implements InitializingBean { 
         private String message; 
        private String name; 

        public Demo_InitializingBean() { 
          // TODO Auto-generated constructor stub 
          System.out.println(""constructor gets called for   
            initializing data members in demo Initializing bean""); 
          message=""welcome!!!""; 
          name=""no name""; 
        } 
        @Override 
        public String toString() { 
          // TODO Auto-generated method stub 
          return message+""\t""+name; 
        } 
      } 

```

1.  如下所示，覆盖 afterPropertiesSet()方法以处理属性：

```java
      @Override 
      public void afterPropertiesSet() throws Exception { 
        // TODO Auto-generated method stub 
        name=""Mr.""+name.toUpperCase(); 
        System.out.println(""after propertiesSet got called""); 
      } 

```

1.  在 bean_lifecycle.xml 中再添加一个 bean，如下所示：

```java
      <bean id="obj_Initializing"  
        class="com.ch02.beans.Demo_InitializingBean"/> 

```

您可以看到，我们在这里不需要重写任何 init-method 属性，正如我们在案例 1 中所做的那样，因为 afterPropertiesSet()通过回调机制在属性设置后得到调用。

1.  创建一个带有 main 方法的 Test_InitializingBean 类，如以下代码所示：

```java
      public static void main(String[] args) { 
        // TODO Auto-generated method stub 
        ApplicationContext context=new  
        ClassPathXmlApplicationContext(""beans_lifecycle.xml""); 

        Demo_InitializingBean obj=    
          (Demo_InitializingBean)context.getBean(""obj_Initializing""); 
        System.out.println(obj);  
      } 

```

1.  输出执行结果如下所示：

```java
      INFO: Loading XML bean definitions from class path resource 
      [beans_lifecycle.xml] 
      constructor gets called for initializing data members in Custom
        init 
      myInit() get called 
      constructor gets called for initializing data members in demo        initializing bean 
      after propertiesSet got called 
      welcome!!!  Mr.NO NAME 

```

从上面的输出中，下划线的语句与新配置的 bean 无关。但是，由于容器对所有配置的 bean 进行初始化，它也会初始化`Demo_Custom_Init`bean。

### 案例 3：使用 DisposableBean 提供内存释放

我们将使用与案例 1 中开发相同的项目 Ch02_Bean_Life_Cycle。

按照以下步骤操作：

1.  在 com.ch02.beans 包中添加一个实现 DisposableBean 接口的 Demo_DisposableBean 类，如下所示：

```java
      public class Demo_DisposableBean implements DisposableBean { 
         private String message; 
        private String name; 

        public Demo_DisposableBean() { 
          // TODO Auto-generated constructor stub 
          System.out.println("constructor gets called for  
            initializing data members in Disposable Bean"); 
          message="welcome!!!"; 
          name="no name"; 
        } 

        @Override 
        public String toString() { 
          // TODO Auto-generated method stub 
          return message+""\t""+name; 
        } 
      } 

```

1.  如下所示覆盖 destroy()方法以释放内存：

```java
      @Override 
      public void destroy() throws Exception { 
        // TODO Auto-generated method stub 
        System.out.println("destroy from disposable bean get called"); 
        name=null; 
      } 

```

1.  在 bean_lifecycle.xml 中再添加一个 bean，如下所示：

```java
      <bean id="obj_Disposable"    
        class="com.ch02.beans.Demo_DisposableBean"/> 

```

您可以看到，我们在这里不需要重写任何 destroy-method 属性，正如我们在案例 1 中所做的那样。当包含 bean 的容器关闭时，`destroy()`将得到回调。

1.  创建一个带有以下代码的 Test_DisposableBean 类：

```java
      public static void main(String[] args) { 
        // TODO Auto-generated method stub 
        ApplicationContext context=new  
          ClassPathXmlApplicationContext(""beans_lifecycle.xml""); 

        Demo_DisposableBean obj=  
          (Demo_DisposableBean)context.getBean("obj_Disposable"); 
        System.out.println(obj);         
        ((AbstractApplicationContext)context).registerShutdownHook(); 
      } 

```

1.  我们执行主程序后将会得到以下代码：

```java
      INFO: Loading XML bean definitions from class path resource 
      [beans_lifecycle.xml] 
      constructor gets called for initializing data members in Custom
        init 
      myInit() get called 
      constructor gets called for initializing data members in demo         initializing bean 
      after propertiesSet got called 
      constructor gets called for initializing data members in 
        Disposable Bean 
      welcome!!!  no name 
      Sep 09, 2016 10:54:55 AM 
      org.springframework.context.support.
      ClassPathXmlApplicationContext doClose 
      INFO: Closing
      org.springframework.context.support.
      ClassPathXmlApplicationContext@1405ef7: startup date
      [Fri Sep 09  10:54:54 IST 2016]; root of context hierarchy 
      destroy from disposable bean get called destroy called 

```

下划线行来自 Disposable demo 的 destroy()，但正如您所见的，对于 Demo_Custom_Init 类也有自定义的 destroy()方法。

### 案例 4：使 bean 意识到容器

我们将使用与案例 1 中开发相同的项目 Ch02_Bean_Life_Cycle。

按照以下步骤操作：

1.  在 com.ch02.contextaware 包中添加一个实现 ApplicationContextAware 接口的 MyBean 类。

1.  向 bean 类中添加一个 ApplicationContext 类型的数据成员。

1.  覆盖 setApplicationContext()方法。

1.  添加 display()方法以获取一个 bean 并显示其属性。类将如下所示：

```java
      public class MyBean implements ApplicationContextAware { 
        private ApplicationContext context; 

        @Override 
        public void setApplicationContext(ApplicationContext ctx)  
          throws BeansException { 
          // TODO Auto-generated method stub 
          System.out.println(""context set""); 
          this.context=ctx; 
        } 
        public void display() 
        { 
          System.out.println((Demo_InitializingBean) 
            context.getBean(""obj_Initializing"")); 
        } 
      } 

```

在这里，我们访问了一个不是类数据成员且未注入的其他 bean。但代码显示我们仍然可以访问其属性。

1.  在`bean_lifecycle.xml`中再添加一个 bean，如下所示：

```java
      <bean id=""obj_myBean"" class=""com.ch02.contextAware.MyBean""/> 

```

1.  创建一个带有 main 方法的 Test_MyBean 类，如下所示：

```java
      public static void main(String[] args) { 
        // TODO Auto-generated method stub 
        ApplicationContext context=new  
          ClassPathXmlApplicationContext(""beans_lifecycle.xml""); 

        MyBean obj=(MyBean)context.getBean(""obj_myBean""); 
        obj.display(); 
      } 

```

1.  执行后，我们将得到以下输出：

```java
      constructor gets called for initializing data members in Custom
      init 
      myInit() get called 
      constructor gets called for initializing data members in demo        initializing bean 
      after propertiesSet got called 
      constructor gets called for initializing data members in
      Disposable Bean 
      context set 
      welcome!!!  Mr.NO NAME 

```

### 案例 4：使用 BeanPostProcessor。

我们将使用与案例 1 中开发相同的项目 Ch02_Bean_Life_Cycle。

按照以下步骤操作：

1.  在 com.ch02.beans 包中添加一个实现 BeanPostProcessor 的 bean 类 Demo_BeanpostProcessor。

1.  覆盖 postProcessBeforeInitialization()方法。

1.  覆盖 postProcessAfterInitialization()方法。

1.  完整的类定义如下所示：

```java
      public class Demo_BeanPostProcessor implements BeanPostProcessor
      { 
        @Override 
        public Object postProcessBeforeInitialization(Object bean,  
          String beanName) throws BeansException { 
          // TODO Auto-generated method stub 
          System.out.println("initializing bean before init:-    
            "+beanName); 
          return bean; 
        } 

        @Override 
        public Object postProcessAfterInitialization(Object bean,  
          String beanName) throws BeansException { 
          // TODO Auto-generated method stub 
          System.out.println("initializing bean after init:- 
            "+beanName); 
          return bean; 
        } 
      } 

```

1.  在 bean_lifecycle.xml 中再添加一个 bean，如下所示：

```java
      <bean id=""beanPostProcessor""  
        class=""com.ch02.processor.Demo_BeanPostProcessor""/> 

```

1.  创建一个带有 main 方法的`TestBeanPostProcessor`类。我们不必向 bean 请求`beanPostProcessor`，因为它的方法在容器中的每个 bean 的 init 方法前后被调用。

1.  编写测试代码，找出初始化过程中调用方法的顺序，如下所示：

```java
      public class Test_BeanPostProcessor { 
        public static void main(String[] args) { 
          // TODO Auto-generated method stub 
          ApplicationContext context=new  
            ClassPathXmlApplicationContext("beans_lifecycle.xml"); 

          Demo_Custom_Init  
            obj=(Demo_Custom_Init)context.getBean(""obj""); 
          System.out.println(obj); 
        } 
      } 

```

1.  输出结果如下：

```java
      INFO: Loading XML bean definitions from class path resource
        [beans_lifecycle.xml] 
      initializing bean before init:-
      org.springframework.context.event.
      internalEventListenerProcessor 
      initializing bean after init:-
      org.springframework.context.event.internalEventListenerProcessor 
      initializing bean before init:- 
      org.springframework.context.event.internalEventListenerFactory 
      initializing bean after init:-
      org.springframework.context.event.internalEventListenerFactory 
      constructor gets called for initializing data members in Custom
      init 
      initializing bean before init:- obj 
      myInit() get called 
      initializing bean after init:-obj 
      constructor gets called for initializing data members in demo           initializing bean 
      initializing bean before init:- obj_Initializing 
      after propertiesSet got called 
      initializing bean after init:-obj_Initializing 
      constructor gets called for initializing data members in              Disposable Bean 
      initializing bean before init:- obj_Disposable 
      initializing bean after init:-obj_Disposable 
      context set 
      initializing bean before init:- obj_myBean 
      initializing bean after init:-obj_myBean 
      welcome!!!  NO NAME 

```

下划线的陈述是为了从容器中获取我们请求的 bean。但是找出遵循的顺序，如构造函数、`postProcessBeforeInitialization`方法、自定义初始化方法、`postProcessAfterInitialization`。

### 注解

在一个应用中，可以配置多个`BeanPostProcessors`。如果 bean 实现了 Ordered 接口，可以通过设置`order`属性来管理它们的执行顺序。每个`PostBeanProcessor`的作用域是每个容器。

## 使用 JSR-250 注解进行 bean 生命周期管理

* * *

JSR-250 注解在 bean 生命周期中起着至关重要的作用，但我们不会直接跳过去发现它们。这样做可能会导致我们忽略一些非常重要的概念。所以放心，我们会在讨论基于 JSR 的注解时讨论它们。但是，如果您已经了解 Spring，知道 Spring 中注解的使用，并且急于了解@PreDestroy 或@PostConstruct，您可以直接跳到 JSR 注解的主题。

在大型 Java 企业应用的开发中，通过编写较小的代码单元，通常为类，可以简化开发。然后，开发者通过调用彼此的方法来重复使用它们。这种架构非常复杂且难以维护。为了调用另一个类的实例方法，理解其知识是重要的。持有另一个类对象的类被称为容器。容器持有的对象称为被包含对象。现在容器对被包含对象了如指掌。开发者现在会非常高兴，因为现在他们可以轻松地重复使用被包含对象，这简化了他们的开发工作。但现在设计中有一个非常重大的缺陷。这可以通过下面介绍的两个非常著名的术语来很好地解释：

+   **松耦合**：即使被包含对象发生了变化，容器类也不会受到影响。在这种场景下，容器被称为松耦合对象。开发者总是试图编写遵循松耦合的代码。在 Java 中，可以通过接口编程来实现松耦合。接口规定了什么是合同？但它并没有指定谁和如何实现这个合同。容器类对依赖的知识了解较少，使其更加灵活。

+   **紧密耦合**：当被包含对象有代码更改时，容器类需要进行更改。容器与被包含对象紧密耦合，这使得开发变得困难。

### 注解

尽量避免编写紧密耦合的类。

无论是松耦合还是紧耦合，我们都能得到可重用的对象。现在的问题是这些对象将如何创建。在 Java 中，对象创建可以通过两种主要方式实现，如下所示：

+   构造函数调用。

+   工厂提供对象

在抽象层面上，这两种方式看起来很相似，因为最终用户将获得一个对象进行使用。但这并不相同。在工厂中，依赖类负责创建对象，而在构造函数中，构造函数直接被调用。Java 应用程序以对象为中心，围绕对象进行。每个开发者尝试做的第一件事就是正确初始化对象，以便以优雅的方式处理数据和执行操作。创建每个正确初始化的对象有两个步骤：实例创建和状态初始化。由于容器将涉及这两个过程，我们应该对它们有很好的了解。所以让我们从实例创建开始。

## 实例创建

* * *

在 java 中，创建实例有以下两种方式：

+   使用构造函数

+   使用工厂方法

我不会详细说明何时使用哪种方法，因为我们都是 Java 背景，已经读过或听过很多次原因。我们将直接开始讲解如何在 Spring 框架中逐一使用它们。

### 使用构造函数

让我们以汽车为例，来清晰地了解容器是如何通过以下步骤创建汽车对象的：

1.  创建 Java 应用程序 Ch02_Instance_Creation 并添加我们在上一个项目中添加的 jar 文件。

1.  在 com.ch02.beans 包中创建一个 Car 类，具有车牌号、颜色、燃料类型、价格、平均值等数据成员。代码如下：

```java
      class Car{ 
        private String chesis_number, color, fuel_type; 
        private long price; 
        private double average; 

        public Car() { 
          // TODO Auto-generated constructor stub 
          chesis_number=""eng00""; 
          color=""white""; 
          fuel_type=""diesel""; 
          price=570000l; 
          average=12d; 
        } 
      } 

```

1.  在 Car 中添加 show()，如下所示：

```java
      public void show() 
      { 
        System.out.println(""showing car ""+chesis_number+"" having      
          color:-""+color+""and price:-""+price); 
      } 

```

1.  当开发者尝试创建对象时，代码如下：

```java
      Car car_obj=new Car(); 

```

现在我们需要在 XML 文件中配置`BeanDefination`，它代表一个 bean 实例，以便 bean 将由 Spring 容器管理。

1.  在`Classpath`中创建`instance.xml`以配置我们的 Car`BeanDefination`，我们需要按照如下方式进行配置：

```java
      <bean id=""car_obj"" class=""com.ch02.beans.Car""/> 
      </beans> 

```

1.  在默认包中创建带有 main 函数的 TestCar，以获取 bean 并使用业务逻辑。

* 获取 Spring 容器的实例。我们将使用 ClassPathXmlApplicationContext，如容器初始化中所讨论的。

* 从容器中获取 bean 实例。

代码将如下所示：

```java
      public class TestCar { 
        public static void main(String[] args) { 
          // TODO Auto-generated method stub 
          ApplicationContext context=new      
            ClassPathXmlApplicationContext(""instance.xml""); 
          Car car=(Car)context.getBean(""car_obj""); 
          car.show(); 
        }  
      } 

```

输出如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_02_002.png)

图 02

从输出中可以看出，容器使用了默认构造函数来定义值。让我们通过在 Car 中添加默认构造函数来证明它，如下面的代码所示：

```java
public Car() { 
  // TODO Auto-generated constructor stub 
  chesis_number=""eng00""; 
  color=""white""; 
  fuel_type=""diesel""; 
  price=570000l; 
  average=12d; 
} 

```

更新后的输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_02_003.png)

### 使用工厂方法

在 Spring 容器中配置的 bean，其对象是通过实例或静态工厂方法创建的。

#### 使用实例工厂方法

实例创建将通过一个非静态 bean 的方法完成。要使用该方法进行实例创建，必须配置一个 ''factory-method'' 属性。有时，也可能使用其他类来创建实例。 ''factory-bean'' 属性将与 ''factory-method'' 一起配置，以便容器用于实例创建。

让我们按照以下步骤使用工厂方法进行实例创建。我们将使用相同的 Ch02_Instance_Creation。

1.  在 com.ch02.factory 中创建一个名为 CarFactory 的类，代码如下：

```java
      public class CarFactory { 
        private static Car car=new Car(); 

        public Car buildCar() 
        { 
          System.out.println(""building the car ""); 
          return car; 
        } 
      } 

```

`buildCar()`方法将构建一个 Car 实例并返回它。现在，使容器了解使用上述代码的任务将由 bean 定义完成。

1.  在 instance.xml 文件中添加两个 bean，一个用于 CarFactory，另一个用于 Car，如下所示：

```java
      <bean id="car_factory" class="com.ch02.factory.CarFactory" /> 
      <bean id="car_obj_new" factory-bean="car_factory"
        factory-method="buildCar" /> 

```

属性 factory-method 指定了`buildCar`作为从 factory-bean 属性指定的`car_factory`中用于实例创建的方法。这里不需要指定 class 属性。

1.  使用以下代码创建 TestCarFactory 带有 main 函数：

```java
      public static void main(String[] args) { 
        // TODO Auto-generated method stub 
        ApplicationContext context = new    
          ClassPathXmlApplicationContext(""instance.xml""); 
        Car car = (Car) context.getBean(""car_obj_new""); 
        car.show(); 
      } 

```

1.  执行后，将显示以下快照，

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_02_004.png)

#### 使用静态工厂方法

我们可以在类中定义静态方法，该方法返回对象。使用 'factory-method' 属性来指定进行实例创建的方法名称。让我们使用 Ch02_Instance_Creation 项目来使用 factory-method 属性，按照以下步骤进行。

1.  在 com.ch02.service 包中创建一个名为 CarService 的类，如下所示：

```java
      public class CarService { 
        private static CarService carService=new CarService(); 
        private CarService(){} 
        public static CarService createService() 
        { 
          return carService; 
        } 
        public void serve() 
        { 
          System.out.println(""car service""); 
        }  
      } 

```

1.  在 XML 中添加以下配置：

```java
      <bean id="carService" factory-method="createService"       
        class="com.ch02.service.CarService"/> 

```

**'factory-method'**指定了返回实例的方法。

1.  在 TestCarService 中编写测试代码，如下所示：

```java
      public static void main(String[] args) { 
        // TODO Auto-generated method stub 
        ApplicationContext context = new  
          ClassPathXmlApplicationContext(""instance.xml""); 
        CarService carService = (CarService)     
          context.getBean(""carService""); 
        carService.serve(); 
      } 

```

代码执行后，将给出以下快照所示的输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_02_005.png)

实例创建完成后，现在是初始化状态的时候了。Java 开发人员如下初始化状态：

```java
car.setChessis_Number(""as123er""); 
car.setColor(""baker''s chocolate""); 
car.setFuel_Type(""Petrol""); 
car.setPrice(689067L); 
car.setAverage(21); 

```

这里，如果我们改变了数据成员的值，状态也会随之改变。所以很明显，汽车依赖于数据成员的值。但因为我们已经设置了它们的值，它们是代码的一部分，任何更改都需要更改代码或重新部署代码。在依赖注入中，设计是以这种方式完成的，即对象 externally 实现其状态，而不是从一段代码中硬编码它们。

## 依赖注入

* * *

依赖倒置原则指出两个模块之间不应该紧密耦合。模块应该通过抽象依赖，其中不指定依赖的详细信息。依赖倒置原则（DIP）有助于确保松耦合的模块化编程。依赖注入是 DIP 的实现。要了解什么是依赖注入，我们首先必须清楚地了解什么是依赖？

对象的状态由其数据成员的值给出。正如我们所知，这些数据成员可以是原始类型或次要类型。如果数据成员是原始类型，它们直接获得它们的值，而在次要数据类型中，值依赖于该对象的状态。这意味着每当对象初始化发生时，数据成员初始化起着非常重要的作用。换句话说，我们可以说数据成员是对象初始化的依赖关系。将依赖关系的值插入或设置到对象中是依赖注入。

依赖注入有助于实现松耦合的架构。松耦合有助于轻松测试模块。代码及其使用的值被分离，并可以通过中心配置来控制，这使得代码维护变得容易。由于值在外部配置中，代码不受影响，这使得迁移变得容易，且更改最小。

在 Spring 框架中，可以通过以下方式实现依赖注入：

+   设置器注入

+   构造函数注入

上面提到的两种方法是我们可以用于 DI 的方式，但这些可以通过许多其他方式来实现，其中包括：

+   XML 基础配置

+   使用命名空间 ''p'' 的 XML 基础配置

+   注解基础配置

那么让我们开始逐一探索它们

### XML 基础配置

### 设置器注入

对象的依赖关系通过 setter 注入中的 setter 方法来满足。因此，当我们进行 setter 注入时，非常重要的一点是要有一个 bean，其数据成员将通过 setter 方法进行设置。使用 setter 注入的步骤如下：

1.  使用标准的 Java 命名约定声明一个类及其属性。

1.  如下配置 bean 定义 XML 中的 bean：

```java
      <bean id="bean_id" class="fully qualified _class_name"></bean> 

```

1.  上面的配置中的 bean 创建实例。它必须更新以配置属性。

* 每个<property>标签将配置一个数据成员

* 每个<property>标签接受两个值

1. name: ''name''属性指定了开发者想要配置的数据成员的名称。

2. value: ''value''指定了要给数据成员的值。

更新后的配置如下：

```java
      <bean id="bean_id" class="fully qualified _class_name"> 
        <property name="name_of_property" value="value_of_property"> 
      </bean> 

```

如果我们有多个数据成员的值需要设置，我们需要使用多个<property>标签。

1.  从 Spring 容器中获取 bean，然后您就可以使用它。

首先让我们找出如何通过以下步骤使用 setter 注入配置 bean：

1.  创建 Ch02_Dependency_Injection 作为 Java 项目。

1.  添加所有我们在上一章中已经使用的核心 Spring 库。

1.  在 com.ch2.beans 中创建一个 Car 类。您可以参考之前项目（Ch02_Instance_Creation）中的代码。

* 由于我们打算使用 setter 注入来注入依赖项，因此也创建 setter 方法。

* 添加 show()方法。

代码如下：

```java
      public class Car { 
        private String chesis_number, color, fuel_type; 
        private long price; 
        private double average; 

        public void setChesis_number(String chesis_number) { 
          this.chesis_number = chesis_number; 
        } 

        public void setColor(String color) { 
          this.color = color; 
        } 

        public void setFuel_type(String fuel_type) { 
          this.fuel_type = fuel_type; 
        } 

        public void setPrice(long price) { 
          this.price = price; 
        } 

        public void setAverage(double average) { 
          this.average = average; 
        } 

        public void show() { 
          System.out.println("showing car "+chesis_number+" 
            having color:-"+color+"and price:-"+price); 
        } 
      } 

```

### 注意

确保在创建用于在 Spring 容器中配置的类时始终遵循 Bean 命名约定。

可以通过 getter 方法获取对象的状态。因此，开发者通常会添加 getter 和 setter。添加 getter 总是取决于应用程序的业务逻辑：

1.  现在我们需要在 classpath 中的 beans.xml 中配置 bean 定义，表示一个 bean 定义，以便该 bean 将由 Spring 容器管理。配置如下：

```java
      <bean id=""car_obj"" class=""com.ch02.beans.Car"" /> 

```

1.  在上一步骤中，只创建了一个实例，现在我们想要设置它的属性，并通过 setter 注入依赖。代码如下：

```java
      <bean id=""car_obj"" class=""com.ch02.beans.Car""> 
        <property name=""chesis_number"" value=""eng2012"" /> 
        <property name=""color"" value=""baker''s chocolate"" /> 
        <property name=""fule_type"" value=""petrol"" /> 
        <property name=""average"" value=""12.50"" /> 
        <property name=""price"" value=""643800"" /> 
      </bean> 

```

如果我们不想设置任何依赖的值，简单的事情就是不在配置中添加它。

1.  现在我们准备使用 bean。我们需要要求容器提供一个 bean 对象。在默认包中创建一个 TestCar 类，带有 main 函数。由于依赖的外部化，我们不需要更改已经在上面的 TestCar 中完成的 main 代码。代码如下：

```java
      public class TestCar { 
        public static void main(String[] args) { 
          // TODO Auto-generated method stub 
          ApplicationContext context=new   
            ClassPathXmlApplicationContext("beans.xml"); 
          Car car=(Car)context.getBean("car_obj"); 
          car.show(); 
        } 
      } 

```

1.  执行代码后，我们将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_02_006.png)

图中所示的值与我们从配置中设置的相同。

### 构造函数注入

在构造函数注入中，依赖关系将通过构造函数的参数或简单的参数化来实现。让我们开发一个应用程序来使用基于构造函数的依赖注入。

方法 1：没有模糊性

我们将使用以下步骤的同一个项目 Ch02_Dependency_Injection：

1.  为 Car 添加一个参数化构造函数，代码如下：

```java
      public Car(String chesis_number,String color, double average,
        long price, String fuel_type) { 
        // TODO Auto-generated constructor stub 
        this.chesis_number = chesis_number; 
        this.average = average; 
        this.price = price; 
        this.color=color; 
        this.fuel_type=fuel_type; 
      } 

```

### 注意

如果你添加了一个参数化构造函数，并且你想要同时使用 setter 和构造函数注入，你必须添加一个默认构造函数

1.  在 beans.xml 文件中再添加一个 bean，但这次我们不再使用<property>标签，而是使用<constructor-arg>来实现构造函数 DI。代码如下：

```java
      <bean id="car_const" class="com.ch02.beans.Car"> 
        <constructor-arg value=""eng023""></constructor-arg> 
        <constructor-arg value=""green""></constructor-arg> 
        <constructor-arg value=""12""></constructor-arg> 
        <constructor-arg value=""678900""></constructor-arg> 
        <constructor-arg value=""petrol""></constructor-arg> 
      </bean> 

```

1.  在默认包中创建一个 TestCarConstructorDI 类，该类将从容器中接收 Car 对象。代码如下：

```java
      public static void main(String[] args) { 
        // TODO Auto-generated method stub 
        ApplicationContext context=new    
          ClassPathXmlApplicationContext(""instance.xml""); 
        Car car=(Car)context.getBean(""car_const""); 
        car.show(); 
      } 

```

在这里，容器对于每个参数具有不同的数据类型感到满意。但并非每次都是这样。我们可能会遇到构造函数具有多个模糊数据类型的代码。有时我们确实在类中有一个以上的构造函数，并且由于自动向上转型，容器可能会调用意外的构造函数。也可能会发生开发人员只是漏掉了参数的顺序。

#### 方法 2：带有模糊性

1.  让我们在 beans.xml 中添加一个如下的 bean 定义：

```java
      <bean id=""car_const1"" class=""com.ch02.beans.Car""> 
        <constructor-arg value=""eng023""></constructor-arg> 
        <constructor-arg value=""green"" ></constructor-arg> 
        <constructor-arg value=""petrol""></constructor-arg> 
        <constructor-arg value=""12"" ></constructor-arg> 
        <constructor-arg value=""678900""></constructor-arg> 
      </bean> 

```

参数的数量与构造函数定义相匹配，但第三个参数传递的是 fuel_type 值，而不是平均值。不用担心，继续你的旅程，保持信念！

1.  创建 TestConstructor_Ambiguity 以找出参数不匹配时会发生什么。代码如下：

```java
      public static void main(String[] args) { 
        // TODO Auto-generated method stub 
        ApplicationContext context=new    
          ClassPathXmlApplicationContext(""beans.xml""); 
        Car car=(Car)context.getBean(""car_const1""); 
        car.show(); 
      } 

```

1.  执行 main 函数时会给出异常，如下快照所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_02_007.png)

下划线行表达了参数值的歧义。我们可以有两个解决方案：

**你可以改变配置的顺序，以便与构造函数参数相匹配。**

**Spring 通过提供“index”属性提供了便捷的方法来解决构造函数参数的顺序。**

Spring 给出的配置“type”属性的另一种方法。

1.  让我们尝试通过更新 Step 1 的 bean 定义来配置“index”，如下所示：

```java
      <bean id=""car_const1"" class=""com.ch02.beans.Car""> 
        <constructor-arg value=""eng024"" index=""0"">
          </constructor-arg> 
        <constructor-arg value=""yellow"" index=""1"">
          </constructor-arg> 
        <constructor-arg value=""petrol"" index=""4"">
          </constructor-arg> 
        <constructor-arg value=""15"" index=""2"">
          </constructor-arg> 
        <constructor-arg value=""688900"" index=""3"">
          </constructor-arg> 
      </bean> 

```

你会发现我们这次配置了一个额外的属性作为“index”，这将告诉容器哪个值对应哪个参数。“index”总是从“0”开始。我们没有改变配置中属性的顺序。

1.  运行相同的 TestConstructor_Ambiguity。你将没有任何问题地得到你的实例。

### 注意

指定索引是克服歧义的最安全方式，但即使我们可以用“类型”代替索引来解决问题。但是，如果构造函数有两个以上相同数据类型“类型”将无法帮助我们。要在我们的 previous code 中使用 type，我们需要在 XML 文件中更改 bean 定义，如下所示：

在这里我们探讨了设置豆子属性的方法。但是，如果你敏锐地观察我们在这里设置的所有属性都是原始的，但我们甚至可以将次要数据作为数据成员。让我们找出如何借助以下示例来设置次要数据类型的属性。

让我们开发一个 Customer 的示例，它有一个 Address 作为数据成员。为了更好地理解，请按照以下步骤操作：

1.  创建 Java 应用程序，“Ch02_Reference_DI”，并添加与之相关的 jar 文件，就像之前的示例一样。

1.  在 com.ch02.beans 包中创建 Address 类，具有 city_name、build_no、pin_code 作为数据成员。也为它添加 setter 方法。代码如下：

```java
      public class Address { 
        private String city_name; 
        private int build_no; 
        private long pin_code; 

        public void setCity_name(String city_name) { 
          this.city_name = city_name; 
        } 
        public void setBuild_no(int build_no) { 
          this.build_no = build_no; 
        } 
        public void setPin_code(long pin_code) { 
          this.pin_code = pin_code; 
        } 
        @Override 
        public String toString() { 
          // TODO Auto-generated method stub 
          return this.city_name+""\t""+this.pin_code; 
        } 
      } 

```

1.  在 com.ch02.beans 包中创建 Customer，具有 cust_name、cust_id、cust_address。添加 getter 和 setter 方法。代码如下：

```java
      public class Customer { 
        private String cust_name; 
        private int cust_id; 
        private Address cust_address; 
        //getter and setter methods 
      } 

```

你可以很容易地发现 cus_address 是次要数据。

1.  对于配置，在 Classpath 中创建 customer.xml。

1.  在 XML 中我们需要配置两个 bean。第一个 bean 是 Address，第二个是 Customer。首先让我们如下配置 Address bean：

```java
      <bean id=""cust_address "" class=""com.ch02.beans.Address""> 
        <property name=""build_no"" value=""2"" /> 
        <property name=""city_name"" value=""Pune"" /> 
        <property name=""pin_code"" value=""123"" /> 
      </bean> 

```

注意我们在这里使用的 Address 的 id 是“cust_address”，但如果你愿意，你可以使用自己的。

1.  现在，请按照以下代码添加 Customer 的配置：

```java
      <bean id=""customer"" class=""com.ch02.beans.Customer""> 
        <property name=""cust_id"" value=""20"" /> 
        <property name=""cust_name"" value=""bob"" /> 
        <property name=""cust_address"" ref=""cust_address"" /> 
      </bean> 

```

cust_id 和 cust_name 将直接具有值属性。但是，cust_address 不是原始数据，因此我们在这里需要使用“ref”而不是“value”作为属性。

**ref**: “ref”属性用于引用我们需要注入的对象。 “ref”的值是容器中“id”的值。这里我们使用 ref 值作为“cust_address”，因为我们已经为 Address 数据类型声明了一个具有相似 id 的 bean。

1.  现在是测试代码运行情况的时候了。在默认包中添加 TestCustomer，带有 main 方法，使用以下代码从容器中获取 Customer 对象：

```java
      public static void main(String[] args) { 
        // TODO Auto-generated method stub 
        ApplicationContext context=new  
          ClassPathXmlApplicationContext("customer.xml"); 
        Customer customer=(Customer)context.getBean("customer"); 
        System.out.println(customer.getCust_name()+"\t"+ 
          customer.getCust_id()); 
      } 

```

### 注意

开发人员通常会调用 bean 的业务逻辑方法，而不是直接使用数据成员。

1.  执行后，我们将在控制台上得到客户 id 和客户名称。

### 注意

我们甚至可以在这里使用构造函数注入，通过添加参数化构造函数，并使用<constructor-arg>代替<property>标签。如上所述，'value'属性必须替换为'ref'。您可以从 Customer_Constructor_DI.java 找到代码。

### 命名空间'p'用于属性

在之前的某个例子中，我们曾经使用<property>标签来注入属性的值。框架提供了更复杂且替代<property>的'p'命名空间方式。要使用'p'命名空间，开发者必须在配置文件中添加模式 URI [`www.springframework.org/schema/p`](http://www.springframework.org/schema/p)，如下所示：

```java
xmlns:p=""http://www.springframework.org/schma/p""  

```

使用'p'设置属性基本值的语法如下：

```java
p: name_of_property =value_of_the_property_to_set. 

```

设置多个属性时，用空格将它们分隔开。

引用数据类型的语法如下变化：

```java
p: name_of_property-ref =id_of_bean_which_to_inject 

```

让我们在 XML 中使用新的配置。我们将使用与 Ch02_Dependency_Injection 相同的项目结构，只需修改 beans.xml。让我们按照以下步骤创建一个新的应用程序：

1.  创建一个名为 Ch02_DI_using_namespce 的 Java 项目，并将其中的 jar 文件添加进去。

1.  在 com.ch02.beans 包中创建或复制 Car 类。您可以参考 Ch02_Dependency_Injection 的代码。

1.  创建 beans.xml 文件并更新它，以声明命名空间'p'，如下所示。配置文件将如下所示：

```java
      <beans xmlns="http://www.springframework.org/schema/beans"    
        xmlns:p="http://www.springframework.org/schema/p"  
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
        xsi:schemaLocation="http://www.springframework.org/schema/beans
        http://www.springframework.org/schema/beans/spring-beans.xsd"">  
      </beans> 

```

1.  使用命名空间'p'添加 bean 定义，如下所示：

```java
      <bean id="car_obj" class="com.ch02.beans.Car"    
        p:chesis_number="eng2013" p:color="baker's chocolate"    
        p:fuel_type="petrol" p:average="12.50" p:price="750070"> 
      </bean> 

```

1.  创建一个 TestCar 类，以从容器中获取 Car 实例并执行代码。您可以参考 Ch02_Dependency_Injection 项目中的 TestCar.Java。

一旦我们知道了如何设置基本类型，接下来让我们也为引用配置编写代码。我们将使用同一个 DI_using-namespce 项目来开发后续的代码：

1.  复制或创建 Address 类。（参考 Ch02_Reference_DI 中的代码）在 com.ch02.beans 包中。

1.  复制或创建 Customer 类。（参考 Ch02_Reference_DI 中的代码）在 com.ch02.beans 包中。

1.  在 bean.xml 中使用 setter DI 添加一个 Address bean。

1.  使用命名空间'p'添加一个 Customer 的 bean，配置将如下所示：

```java
      <bean id=""customer"" class=""com.ch02.beans.Customer""  
         p:cust_id=""2013"" p:cust_name=""It''s Bob""  
         p:cust_address-ref=""cust_address""> 
      </bean> 

```

您可以看到，这里客户的地址不是基本类型，因此我们不是使用值，而是使用引用作为 p:cust_address ="cust_address"，其中'cust_address'是表示 Address bean 的 id。

1.  创建一个 TestCustomer 类，其中包含以下代码：

```java
      public static void main(String[] args) { 
        // TODO Auto-generated method stub 
        ApplicationContext context=new  
          ClassPathXmlApplicationContext(""beans.xml""); 
        Customer customer=(Customer)context.getBean(""customer""); 
        System.out.println(customer.getCust_name()+""\t""+ 
          customer.getCust_id()); 
      } 

```

1.  代码执行将显示以下输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_02_008.png)

#### 配置内部 bean

bean 定义文件中有多个由容器管理的 bean。我们都知道这些 bean 可以互相复用。这一点令人惊叹，但随之而来的问题是。让我们以顾客的地址为例。可以为地址和顾客进行配置。我们可以使用地址 bean 为另一个顾客吗？是的，我们可以。但是......如果顾客不想分享他的地址并将其保留为私人信息呢？当前的配置是不可能的。但我们有一个替代配置，可以保留地址的私人信息。从 Ch02_Reference_DI 中修改顾客 bean 的配置以使用内部如下：

```java
<bean id=""customer_obj"" class=""com.ch02.beans.Customer""> 
  <property name=""cust_id"" value=""20"" /> 
  <property name=""cust_name"" value=""bob"" /> 
  <property name=""cust_address""> 
    <bean class=""com.ch02.beans.Address""> 
      <property name=""build_no"" value=""2"" /> 
      <property name=""city_name"" value=""Pune"" /> 
      <property name=""pin_code"" value=""123"" /> 
    </bean> 
  </property> 
</bean> 

```

地址 bean 是一个内部 bean，其实例将由 Customer 实例的 address 属性创建并连接。这与 Java 内部类相似。

由于 setter 注入支持内部 bean，它们也由构造函数注入支持。配置如下：

```java
<bean id=""customer_obj_const"" class=""com.ch02.beans.Customer""> 
  <constructor-arg value=""20"" /> 
  <constructor-arg value=""bob"" /> 
  <constructor-arg> 
    <bean id=""cust_address"" class=""com.ch02.beans.Address""> 
      <property name=""build_no"" value=""2"" /> 
      <property name=""city_name"" value=""Pune"" /> 
      <property name=""pin_code"" value=""123"" /> 
    </bean> 
  </constructor-arg> 
</bean> 

```

你可以在中国 Ch02_InnerBeans 项目中找到完整的代码。

#### 继承映射

继承是 Java 的支柱。Spring 支持在 XML 中配置 bean 定义。继承支持是由'parent'属性提供的，它表示缺少的属性可以从父 bean 中使用。使用'parent'在继承中开发 Java 代码时与父类相似。即使它也允许覆盖父 bean 的属性。让我们通过以下步骤找出如何实际使用：

1.  创建一个名为 Ch02_Inheritance 的 Java 项目。

1.  添加 jar 文件。

1.  在 com.ch02.beans 包中创建一个 Student 类，代码如下：

```java
      public class Student { 
        private int rollNo; 
        private String name; 
        // getters and setters 
      } 

```

1.  在 com.ch02.beans 包中创建一个继承自 Student 的`EnggStudent`类：

```java
      public class EnggStudent extends Student { 
        private String branch_code; 
        private String college_code; 
        // getters and setters 
      } 

```

1.  在类路径中创建 student.xml，以配置 student 的 bean，如下所示：

```java
      <bean id=""student"" class=""com.ch02.beans.Student""> 
        <property name=""rollNo"" value=""34"" /> 
        <property name=""name"" value=""Sasha"" /> 
      </bean> 

```

1.  现在该为 EnggStudent 配置 bean 了。首先是一个我们不想要使用的普通配置：

```java
      <bean id=""engg_old"" class=""com.ch02.beans.EnggStudent""> 
        <property name=""rollNo"" value=""34"" /> 
        <property name=""name"" value=""Sasha"" /> 
        <property name=""branch_code"" value=""Comp230"" /> 
        <property name=""college_code"" value=""Clg_Eng_045"" /> 
      </bean> 

```

很明显，我们重复了 rollNo 和 name 的配置。我们不需要通过配置'parent'属性来重复配置，如下所示：

```java
<bean id="engg_new" class="com.ch02.beans.EnggStudent"  
  parent="student"> 
  <property name="branch_code" value="Comp230"/> 
  <property name=""college_code"" value=""Clg_Eng_045"" /> 
</bean> 

```

虽然这里我们跳过了配置 name 和 rollNo 并从'student'bean 中重用它，但如下所示，重写其中的任何一个都是可能的：

```java
<bean id="engg_new1" class="com.ch02.beans.EnggStudent"   
  parent="student"> 
  <property name=""rollNo"" value=""40"" /> 
  <property name=""branch_code"" value=""Comp230"" /> 
  <property name=""college_code"" value=""Clg_Eng_045"" /> 
</bean> 

```

选择权在你，使用哪一个！！

1.  编写带有 main 函数的 TestStudent 如下：

```java
      public static void main(String[] args) { 
        // TODO Auto-generated method stub 
        ApplicationContext context=new  
          ClassPathXmlApplicationContext("student.xml"); 
        //old configuration 
        EnggStudent student_old= 
          (EnggStudent)context.getBean("engg_old"); 
        System.out.println(""with old configuration""); 
        System.out.println(student_old.getName()+ 
          "\t"+student_old.getRollNo()+"\t"+ 
          student_old.getCollege_code()); 
        //new configuration 
        EnggStudent student_new=
          (EnggStudent)context.getBean(""engg_new""); 
        System.out.println(""with new configuration""); 
        System.out.println(student_new.getName()+ 
          "\t"+student_new.getRollNo()+"\t"+ 
          student_new.getCollege_code()); 
        System.out.println(""with new configuration with       
          overridding roll number""); 
        //new configuration with overriding the roll number 
        EnggStudent student_new1=
          (EnggStudent)context.getBean(""engg_new1""); 
        System.out.println(student_new1.getName()+"\t"+ 
          student_new1.getRollNo()+"\t"+ 
          student_new1.getCollege_code()); 
      } 

```

1.  下面的快照显示了控制台输出如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_02_009.png)

1.  开发者可以获得 Student 实例以及 EnggStudent 实例。在某些情况下，我们不希望任何人使用 Student 实例，或者没有人应该能够获得 Student 实例。在这种情况下，在不想公开可用的 bean 实例上配置属性'abstract'。默认情况下，abstract 的值为 false，表示任何人都可以获得 bean 的实例。我们将配置 abstract 为"true"，使其不可用。Student 的更新配置如下：

```java
      <bean id=""student"" class=""com.ch02.beans.Student""    
        abstract=""true""> 
        <property name=""rollNo"" value=""34"" /> 
        <property name=""name"" value=""Sasha"" /> 
      </bean>
```

1.  现在，无论何时有人要求 student bean，BeanIsAbstractException 将被抛出。您可以通过在 TestStudent 中添加以下行来尝试代码：

```java
      System.out.println(""obtaining Student instance""); 
      Student student=(Student)context.getBean(""student""); 

```

1.  在执行时，我们将得到以下堆栈跟踪，它指定了在获取 Student bean 时发生的 bean 创建异常：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_02_010.png)

#### 配置空值

在 Java 中，除非任何数据成员的值没有被设置，否则每个都会得到它们的默认值。引用属性将被定义为 null，基本整数属性将分别被设置为'0'。这些 null 稍后将通过构造函数注入或 setter 注入被覆盖。也可能是开发人员希望保持它为 null，直到某些业务逻辑不会给出计算值或从某些外部资源获取它。无论什么原因，我们想要配置值为 null，只需使用'<null/>'。如以下所示，将 Customer 的地址设置为 null：

```java
<bean id=""customer_obj"" class=""com.ch02.beans.Customer""> 
  <property name=""cust_id"" value=""20"" /> 
  <property name=""cust_name"" value=""bob"" /> 
  <property name=""cust_address""><null/></property> 
</bean> 

```

您可以在 Ch02_InnerBeans 的 customer.xml 中找到配置。

到目前为止，我们已经看到了基本数据类型、引用、空值或内部 bean 的映射。我们非常高兴，但等待一个非常重要的 Java 基本概念——集合框架。是的，我们还需要讨论集合的映射。

#### 配置集合

Java 中的集合框架使得以简化方式处理对象以执行各种操作成为可能，如添加、删除、搜索、排序对象。Set、List、Map、Queue 等接口有许多实现，如 HashSet、ArrayList、TreeMap、PriorityQueue 等，为处理数据提供了手段。我们不会详细讨论选择哪种操作，但我们将会讨论 Spring 支持的不同配置，以注入集合。

**映射列表**

列表是有序的集合，它按数据插入顺序处理数据。它维护插入、删除、通过索引获取数据，其中允许重复元素。ArrayList、LinkedList 是其一些实现。框架支持使用<list>标签配置 List。让我们按照以下步骤开发一个应用程序来配置 List：

1.  创建 Ch02_DI_Collection 作为 Java 项目，并添加 Spring jars。

1.  在 com.ch02.beans 包中创建一个 POJO 类 Book。

* 添加 isbn、book_name、price 和 publication 作为数据成员。

* 添加默认和参数化构造函数。

* 编写.getter 和 setter 方法。

* 由于我们正在处理集合，所以添加`equals()`和`hashCode()`

* 为了显示对象，添加`toString()`

书籍的内容将如下面的代码所示，

```java
      public class Book { 
        private String isbn; 
        private String book_name; 
        private int price; 
        private String publication; 

        public Book() 
        { 
          isbn=""310IND""; 
          book_name=""unknown""; 
          price=300; 
          publication=""publication1""; 
        }       

        public Book(String isbn,String book_name,int price, String  
          publication) 
        { 
          this.isbn=isbn; 
          this.book_name=book_name; 
          this.price=price; 
          this.publication=publication; 
        } 

        @Override 
        public String toString() { 
          // TODO Auto-generated method stub 
          return book_name+""\t""+isbn+""\t""+price+""\t""+publication; 
        } 

        @Override 
        public boolean equals(Object object) { 
          // TODO Auto-generated method stub 
          Book book=(Book)object; 
          return this.isbn.equals(book.getIsbn()); 
        } 

        public int hashCode() { 
          return book_name.length()/2; 
        } 

        // getters and setters 
      } 

```

1.  在 com.ch02.beans 中创建 Library_List，它有一个 Book 列表。编写 displayBooks()以显示书籍列表。代码将是：

```java
      public class Library_List { 
        private List<Book> books; 
        public void displayBooks() 
        { 
          for(Book b:books) 
          { 
            System.out.println(b); 
          } 
        } 
        // getter and setter for books 
      } 

```

1.  在 ClassPath 中创建 books.xml，并向其中添加四个 Book bean。我尝试了以下三种配置：

* 使用 setter DI 创建 book bean。

* 使用构造函数 DI 创建 book bean。

* 使用''p''命名空间创建 book bean。

无需尝试所有组合，你可以跟随其中任何一个。我们已经在之前的演示中使用了它们全部。配置将如下所示：

```java
     <bean id=""book1"" class=""com.ch02.beans.Book""> 
       <property name=""isbn"" value=""20Novel"" /> 
       <property name=""book_name"" value=""princess Sindrella"" /> 
       <property name=""price"" value=""300"" /> 
       <property name=""publication"" value=""Packt-Pub""></property> 
     </bean> 

     <bean id="book2" class="com.ch02.beans.Book"> 
       <constructor-arg value="Java490" /> 
       <constructor-arg value="Core Java" /> 
       <constructor-arg value="300" /> 
       <constructor-arg value="Packt-Pub" /> 
     </bean> 

     <bean id="book3" class="com.ch02.beans.Book"   
       p:isbn="200Autobiography"
       p:book_name="Playing it in my way" p:price="300"  
       p:publication="Packt-Pub"> 
     </bean> 

```

故意第四本书是前三本书中的其中一本的第二份，我们在接下来的几个步骤中发现原因。敬请期待！

1.  在 <list> 配置中添加一个 Library bean：

```java
      <bean id=""library_list"" class=""com.ch02.beans.Library_List""> 
        <property name=""books""> 
          <list> 
            <ref bean=""book1""></ref> 
            <ref bean=""book2""></ref> 
            <ref bean=""book3""></ref> 
            <ref bean=""book3""></ref> 
          </list> 
        </property> 
      </bean> 

```

<list> 包含 <ref> 的列表，用于注入书的列表，其中 'book1'、'book2'、'book3'、'book4' 是我们在第 4 步创建的 bean 的 id。

1.  创建一个带有 main 函数的 TestLibrary_List 以获取 Library 实例和它包含的 Book 列表。代码如下：

```java
      public static void main(String[] args) { 
        // TODO Auto-generated method stub 
        ApplicationContext context=new   
          ClassPathXmlApplicationContext(""books.xml""); 
        Library_List  list=       
          (Library_List)context.getBean(""library_list""); 
        list.displayBooks(); 
      } 

```

1.  执行它以显示书目列表的输出。找到最后两个条目，这表明 List 允许重复元素：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_02_011.png)

**映射集**

Set 接口是一个无序集合，该集合不允许集合中有重复条目。HashSet、TreeSet 是 Set 的实现。Spring 提供了 <set> 标签来配置 Set。让我们使用 Ch02_DI_Collection 项目按照以下步骤添加书的 Set：

1.  在 com.ch02.beans 包中添加 Library_Set 类并声明 Set 的书作为数据成员。为它添加 getter 和 setter。代码如下所示：

```java
      public class Library_Set { 
        HashSet<Book> books; 

        public void displayBooks() 
        { 
          for(Book b:books) 
          { 
            System.out.println(b); 
          } 
        } 
        //getter and setter for books 
      } 

```

1.  在 beans.xml 中为 Library_Set 添加一个 bean，并使用如下 <set> 配置：

```java
      <bean id=""library_set"" class=""com.ch02.beans.Library_Set""> 
        <property name=""books""> 
          <set> 
            <ref bean=""book1""></ref> 
            <ref bean=""book2""></ref> 
            <ref bean=""book3""></ref> 
            <ref bean=""book3""></ref> 
          </set> 
        </property> 
      </bean> 

```

1.  创建一个带有 main 函数的 TestLibrary_Set，如下所示：

```java
      public static void main(String[] args) { 
        // TODO Auto-generated method stub 
        ApplicationContext context=new  
          ClassPathXmlApplicationContext(""books.xml""); 
        Library_Set set=     
          (Library_Set)context.getBean(""library_set""); 
        set.displayBooks();      
      } 

```

1.  执行结果如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_02_012.png)

我们注入了四本图书的对象，但输出中只有三本，所以很明显 Set 不允许重复项。

**映射 Map**

Map 处理具有键值对的对象集合。Map 可以有重复的值，但不允许重复的键。它的实现包括 `TreeMap`、`HashMap` 和 `LinkedHashMap`。

让我们通过以下步骤探索配置 Map：

1.  我们将使用同一个 Ch02_DI_Collection 项目。在 com.ch02.beans 包中创建 Library_Map 类。

1.  在其中添加一个 `<Map<String,Book>` 类型的 `books` 数据成员，并添加相应的 getter 和 setter。不要忘记在其中添加 `displayBooks()`。代码如下所示：

```java
      public class Library_Map { 
        private Map<String,Book> books; 
        //getters and setters 

        public void displayBooks() 
        { 
          Set<Entry<String, Book>> entries=books.entrySet(); 
          for(Entry<String, Book> entry:entries) 
          { 
            System.out.println(entry.getValue()); 
          }    
        }   
      } 

```

1.  如下配置 Map 在 beans.xml 中：

```java
<bean id=""library_map"" class=""com.ch02.beans.Library_Map""> 
    <property name=""books""> 
      <map> 
        <entry key=""20Novel"" value-ref=""book1"" /> 
        <entry key=""200Autobiography"" value-ref=""book3"" /> 
        <entry key=""Java490"" value-ref=""book2"" /> 
      </map> 
    </property> 
  </bean> 

```

与 List 和 Set 不同，Map 需要一个额外的 'key' 属性来指定键。我们这里用书名作为键，但如果你愿意，也可以声明其他东西。只是不要忘记在 Map 中键总是唯一的：

1.  像下面这样编写 TestLibrary_Map 主函数：

```java
      public static void main(String[] args) { 
        // TODO Auto-generated method stub 
        ApplicationContext context=new     
          ClassPathXmlApplicationContext("books.xml"); 
        Library_Map map=  
          (Library_Map)context.getBean("library_map"); 
        map.displayBooks(); 
      } 

```

1.  执行代码以在控制台上显示书目详情。

这里我们为每个条目配置单个对象。但在实际中，一个条目可能包含 List 或 Set 的书。在这种情况下，配置将包含 <entry> 与 <list> 如下：

```java
<bean id=""library_map1"" class=""com.ch02.beans.Library_Map1""> 
    <property name=""books""> 
      <map> 
        <entry key=""20Novel""> 
          <list> 
            <ref bean=""book1""></ref> 
            <ref bean=""book1""></ref> 
          </list> 
        </entry> 
        <entry key=""200Autobiography""> 
          <list> 
            <ref bean=""book3""></ref> 
            <ref bean=""book3""></ref> 
          </list> 
        </entry> 
      </map> 
    </property> 
  </bean> 

```

在上述配置中，每个 ''条目'' 都有一个包含 ''<list>'' 的书名，这显然是我们谈论的是图书目录。Library_Map1.java 和 TestLibrary_Map1.java 的完整代码可以在 Ch02_DI_Collection 中查阅。

**映射属性**

属性也包含键值对的集合，但与 Map 不同，这里键和值都是 String 类型。属性可以从流中保存或读取。

考虑一个拥有多个州作为属性的国家。按照以下步骤找出如何在`beans.xml`中配置属性：

1.  在 com.ch02.beans 包中创建一个 Country 类。

1.  将 name, continent 和 state_capital 声明为数据成员。添加 getters 和 setters。为了显示州首府，添加 printCapital()。代码如下所示：

```java
      public class Country { 
        private String name; 
        private String continent; 
        private Properties state_capitals; 

        // getters and setter  

        public void printCapitals() 
        { 
          for(String state:state_capitals.stringPropertyNames()) 
          {   
            System.out.println(state+"":\t""+ 
              state_capitals.getProperty(state)); 
          } 
        } 
      } 

```

1.  在 beans.xml 中如下配置 Country 的定义：

```java
      <bean id=""country"" class=""com.ch02.beans.Country""> 
        <property name=""name"" value=""India""></property> 
        <property name=""continent"" value=""Asia""></property> 
        <property name=""state_capitals""> 
          <props> 
            <prop key=""Maharashtra"">Mumbai</prop> 
            <prop key=""Goa"">Panji</prop> 
            <prop key=""Punjab"">Chandigad</prop> 
          </props> 
        </property> 
      </bean> 

```

'state_capitals'包含`<props>`配置，以'key'状态名称和'value'其首府作为键值对。

1.  编写带有以下代码的 TestProperties 主函数，

```java
public static void main(String[] args) { 
    // TODO Auto-generated method stub 
    ApplicationContext context=new   
                   ClassPathXmlApplicationContext(""books.xml""); 
    Country country=(Country)context.getBean(""country""); 
    country.printCapitals();; 
   } 

```

1.  输出将如快照所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_02_013.png)

'util'命名空间为开发者在 XML 文件中优雅地配置集合提供了一种手段。使用'util'命名空间，可以配置 List、Map、Set、Properties。要使用'util'命名空间，必须更新[www.springframework.org/schma/util](http://www.springframework.org/schma/util) URI 的架构，如下快照所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_02_014.png)

下划线的行必须添加以在配置中使用'util'命名空间。

使用''util''命名空间的 List 配置将如下所示：

```java
      <bean id=""library_list1"" class=""com.ch02.beans.Library_List""> 
        <property name=""books""> 
          <util:list> 
            <ref bean=""book1""></ref> 
            <ref bean=""book2""></ref> 
            <ref bean=""book3""></ref> 
          </util:list> 
        </property> 
      </bean> 

```

您可以在 books.xml 中找到更新的配置。

我们知道如何获取 bean 以及如何满足它具有的不同类型的依赖关系。bean 配置定义了实例的创建方式及其状态将由注入依赖项来定义。在任何时刻，根据业务逻辑需求，bean 的状态可以更改。但我们还不知道 Spring 容器创建了多少实例，或者如果开发者希望每个请求都使用单个实例该怎么办？或者每个操作都需要不同的实例。实际上我们在谈论“作用域”

#### Bean 作用域

bean 的作用域定义了 Spring 容器将创建多少实例，并使其可供应用程序使用。使用`<bean>`的`scope`属性提供关于实例数量的信息。在了解创建和提供实例的默认过程之前，我们无法前进。这将使“作用域”一词变得清晰，并且还将定义为什么理解“作用域”如此重要。

让我们使用 Ch02_Dependency_Injection 项目来找出容器默认创建多少实例。您可以使用同一个项目，或者可以创建一个新的副本，如下步骤所示。

1.  创建 Ch02_Bean_Scope 作为 Java 项目。

1.  向其添加 Spring jar。

1.  在 com.ch02.beans 包中创建或复制 Car 类。

1.  在类路径中创建 beans.xml，并如下配置'car' bean，

```java
      <bean id=""car"" class=""com.ch02.beans.Car""> 
        <property name=""chesis_number"" value=""eng2012"" /> 
        <property name=""color"" value=""baker''s chocolate"" /> 
        <property name=""fuel_type"" value=""petrol"" /> 
        <property name=""average"" value=""12.50"" /> 
        <property name=""price"" value=""643800"" /> 
      </bean> 

```

作用域与 bean 是如何配置的无关。

1.  创建 TestCar 以如下的方式请求两次'car' bean。不要感到惊讶。我们想找出创建了多少实例。所以让我们开始吧：

```java
      public static void main(String[] args) { 
        // TODO Auto-generated method stub 
        ApplicationContext context=new  
          ClassPathXmlApplicationContext(""beans.xml""); 
        // first request to get the car instance 
        Car car_one=(Car)context.getBean(""car""); 
        car_one.show(); 

        //second request to get the car instance 
        Car car_two=(Car)context.getBean(""car""); 
        car_two.show(); 
      } 

```

代码执行将给出以下输出，

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_02_015.png)

是的，两个对象有相同的值。为什么不呢？我们在 XML 中配置它们。这不会导致我们得出任何结论。让我们进行第二步。

* 使用相同的 TestCar 代码，但这次改变任意一个 car 对象的状态。我们将为“car_one”进行更改，并观察 car_two 会发生什么？car_two 将包含更改后的值还是配置的值？更改后的代码如下：

```java
      public class TestCarNew { 
        public static void main(String[] args) { 
          // TODO Auto-generated method stub 
          ApplicationContext context=new  
            ClassPathXmlApplicationContext(""beans.xml""); 
          // first request to get the car instance 
            Car car_one=(Car)context.getBean(""car""); 
            car_one.show(); 

          //second request to get the car instance 
            Car car_two=(Car)context.getBean(""car""); 
            car_two.show(); 

          System.out.println(""after changing car-one is""); 
          // change average and color of car_one 
          car_one.setAverage(20.20d); 
          car_one.setColor(""white""); 
          car_one.show(); 
          System.out.println(""after changing car-two is""); 
          car_two.show(); 
        } 
      } 

```

执行后，你将得到以下输出。

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_02_016.png)

我们只是改变了 car_one 的状态，但输出显示 car_two 的状态也发生了变化，这证明无论你多少次向容器请求实例，每次都会返回同一个实例。

### 注意

`singleton`是 bean 的默认作用域，意味着每个 Spring 容器有一个实例。

* 保持 TestCarNew 不变，并在 car bean 中配置`scope`属性，如下所示，

```java
<bean id=""car"" class=""com.ch02.beans.Car"" scope=""prototype""> 

```

执行 TestCarNew，你将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_02_017.png)

输出显示，car_one 的状态变化不会改变 car_two 的状态。这意味着，每次从容器中请求 car 实例时，容器都会创建并给予一个新的实例。

### 注意

`prototype`指定每次从容器请求实例时都创建一个新的实例。

以下是一些由 Spring 框架给出的作用域，

+   **请求**：在 Web 应用程序中，默认情况下所有 HTTP 请求都由同一个实例处理，这可能导致处理数据或数据一致性问题。为了确保每个请求都能获得自己全新的实例，请求作用域将会有帮助。

+   **会话**：我们很清楚在 Web 应用程序中处理会话。每个请求创建一个实例，但当多个请求绑定到同一个会话时，每个请求的实例变得杂乱无章，管理数据也是如此。在需要按会话创建实例的情况下，会话作用域是拯救之策。

+   **应用程序**：每个 Web 应用程序都有自己的 ServletContext。应用程序作用域创建每个 ServletContext 的实例。

+   **全局会话**：在 protletContext 中，Spring 配置提供每个全局 HTTPSession 的实例。

+   **WebSocket**：WebSocket 作用域指定每个 WebSocket 创建一个实例。

### 基于注解的配置

从 Spring 2.5 开始，Spring 开始支持基于注解的配置。我们已经讨论了在 Java 中的概念以及如何在 XML 中进行配置？在执行基于注解的配置时，我们会遇到两种类型的配置

+   基于 Spring 的注解

+   基于 JSR 的注解。

#### 基于 Spring 的注解

Spring 提供了许多注解，可以分为管理生命周期、创建 bean 实例、注解配置等类别。让我们逐一找到它们。但在那之前，我们需要知道一个非常重要的事情。bean 定义必须通过在 XML 中配置来注册。现在，为了实现基于注解的配置，bean 注册必须使用 context 命名空间如下进行：

```java
<beans xmlns=""http://www.springframework.org/schema/beans"" 
  xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""  
  xmlns:context=""http://www.springframework.org/schema/context"" 
  xsi:schemaLocation= 
    "http://www.springframework.org/schema/beans 
     http://www.springframework.org/schema/beans/spring-beans.xsd  
     http://www.springframework.org/schema/context  
     http://www.springframework.org/schema/context/spring-context.xsd"> 
<context:annotation-config/> 

```

`<context:annotation-config/>` 使容器考虑 bean 上的注解。

instead of the above configuration one can even go with the following configuration,

```java
<bean calss=""or.springframework.bean.factory.annotation.
  AutowiredAnnotationBeanPostProcessor""/> 

```

让我们开始逐一使用注解来处理不同的场景，如下所示，

##### 注解配置

这些注解是类级注解，它们与 Spring 容器一起注册。以下图表显示了典型注解：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_02_018.png)

我们在应用程序中使用@Component 注解。以 Ch02_Reference_DI 为基础项目，按照以下步骤操作：

1.  创建 Ch02_Demo_Annotation 文件夹以及我们之前添加的所有 jar 文件，然后将 spring-aop.jar 也添加进去。

1.  在 com.ch02.beans 包中创建或复制 Address.java 文件。

1.  在 com.ch02.stereotype.annotation 包中创建或复制 Customer.java 文件。将其重命名为 Customer_Component.java

1.  为其添加默认构造函数，因为我们要参考的代码中没有默认构造函数。代码可以如下所示：

```java
      public Customer_Component() { 
        // TODO Auto-generated constructor stub 
        cust_id=100; 
        cust_name=""cust_name""; 
        cust_address=new Address(); 
        cust_address.setBuild_no(2); 
        cust_address.setCity_name(""Delhi""); 
      } 

```

1.  使用以下方式用 @Component 注解类：

```java
      @Component 
      public class Customer_Component {   } 

```

这里我们配置了一个可自动扫描的组件。默认情况下，这个组件的 id 将是首字母小写的类名。在我们的例子中是 ''customer_Component''。如果我们想要使用自定义的 id，我们可以修改配置以使用 ''myObject'' 作为 bean id，

```java
      @Component(value=""myObject"")  

```

在 XML 中配置它是不必要的，正如我们之前所做的那样。但是我们仍然需要 XML 来进行一些其他配置。

1.  在类路径中创建或复制 customer.xml 文件。

1.  添加以下代码以考虑注解：

```java
      <context:annotation-config/> 

```

我们已经看到了如何配置“context”命名空间。

1.  创建 TestCustomer_Component 组件以获取 Customer_Component 组件的 bean，如下所示，以找出我们配置的输出是什么：

```java
      public class TestCustomer_component { 
        public static void main(String[] args) { 
          // TODO Auto-generated method stub 
          ApplicationContext context = new  
            ClassPathXmlApplicationContext(""customer.xml""); 
          Customer_Component customer = (Customer_Component)  
            context.getBean(""customer_Component""); 
          System.out.println(customer.getCust_name() + ""\t"" +  
          customer.getCust_id() +  
          customer.getCust_address()); 
        } 
      } 

```

执行后，我们将得到以下异常堆栈跟踪，

```java
      Exception in thread "main"  
      org.springframework.beans.factory.NoSuchBeanDefinitionException:
      No bean named ''customer_component'' is defined 

```

1.  如果我们已经做了所有的事情，为什么我们仍然得到异常。原因是使组件自动扫描可用，但忘记告诉容器在哪里扫描注解？让我们配置在哪里扫描组件：

```java
      <context:component-scan  
        base-package=""com.ch02.stereotype.*""> 
      </context:component-scan> 

```

在这里，将扫描 com.ch02.streotype 的所有子包，以查找具有 ''customer_Component'' id 的 bean。

1.  添加配置后，我们将得到以下输出，显示数据成员值：

```java
      INFO: Loading XML bean definitions from class path resource 
      [customer.xml] 
      cust_name 100 Delhi 2
```

同样，我们可以使用其他注解，但我们将逐一在接下来的章节中讨论它们。

##### 注解配置

我们已经深入讨论了 ''auto wiring''，它为我们提供了减少配置和自动发现要注入哪个对象作为 bean 依赖项的便利。 以下是帮助自动注入和解决自动注入问题的注解：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/lrn-spr5/img/image_02_019.png)

让我们使用 Cho2_Demo_Annotation 项目来演示上述注解。

##### Case1. 使用 @Autowired

1.  在 com.ch02.autowiring.annotation 中创建 Customer_Autowired 类。这与我们之前在 stereotype annotations 中创建的 Customer_Component 类似。如果你没有默认客户，不要忘记添加。

1.  在如下所示的 cust_address 字段上添加 @Autowired 注解：

```java
      @Autowired 
      private Address cust_address; 

```

1.  在 customer_new.xml 中如下配置 Address bean：

```java
      <bean id=""cust_address"" class=""com.ch02.beans.Address""> 
        <property name=""build_no"" value=""2"" /> 
        <property name=""city_name"" value=""Pune"" /> 
        <property name=""pin_code"" value=""123"" /> 
      </bean> 

```

1.  创建 TestCustomer_Autowired 以获取 id 为 ''customer_Autowired'' 的 bean：

```java
      public static void main(String[] args) { 
        // TODO Auto-generated method stub 
        ApplicationContext context = new  
          ClassPathXmlApplicationContext(""customer_new.xml""); 
        Customer_Autowired customer = (Customer_Autowired)  
          context.getBean(""customer_Autowired""); 
        System.out.println(customer.getCust_name() + ""\t"" +  
          customer.getCust_id() +  
          customer.getCust_address()); 
      } 

```

1.  在执行时，我们将得到以下控制台输出：

```java
      INFO: Loading XML bean definitions from class path resource
      [customer_new.xml] 
      my name  10  Mumbai  12 

```

##### Case2. 使用 autowired=false

无论开发者多么小心，我们总是遇到依赖项不可用或由于某种原因而没有注入的情况。 这里出现异常是很明显的。 为了摆脱这种强制注入，请将 `'autowired=false`' 添加到 `@Autowired`。

1.  你可以通过删除 customer.xml 中的 cust_address 来尝试这个，运行主程序我们将得到异常：

```java
      Caused by:
      org.springframework.beans.factory.NoSuchBeanDefinitionException:
      No qualifying bean of type [com.ch02.beans.Address] found for
      dependency [com.ch02.beans.Address]: expected at least 1 bean
      which qualifies as autowire candidate for this dependency.
      Dependency annotations:
        {@org.springframework.beans.factory.annotation.Autowired 
      (required=true)} 

```

1.  将 @Autowired 注解更改为：

```java
      @Autowired(required=false) 
      private Address cust_address; 

```

1.  再次重新运行主要功能，我们得到以下输出：

```java
my name 10null
```

null 值表示没有注入地址，但我们这里没有 bean 创建异常。

### 注意

一旦你完成了 required=false 的演示，请撤销我们在这个演示中刚刚所做的所有更改。

##### Case3. 使用 @Qualifier

在某些情况下，我们可能容器中配置了同一类型的多个 bean。 有一个以上的 bean 不是一个问题，除非开发者控制依赖注入。 也可能有不同 id 的依赖项，以及同一类型的多个 bean，但没有匹配的 id。 让我们使用 `@Qualifier` 来解决这些问题。 我们将使用上一步骤中的相同类 `Customer_Autowired`：

1.  将之前创建的 bean cust_address 的 id 重命名为 cust_address1。

1.  像下面这样添加一个 Address 类型的另一个 bean：

```java
      <bean id=""address"" class=""com.ch02.beans.Address""> 
        <property name=""build_no"" value=""2"" /> 
        <property name=""city_name"" value=""Pune"" /> 
        <property name=""pin_code"" value=""123"" /> 
      </bean> 

```

1.  创建 TestCustomer_Autowiring1 以获取以下所示的客户实例：

```java
      public static void main(String[] args) { 
        // TODO Auto-generated method stub 
        ApplicationContext context = new  
          ClassPathXmlApplicationContext(""customer_new.xml""); 
        Customer_Autowired customer = (Customer_Autowired)  
          context.getBean(""customer_Autowired""); 
        System.out.println(customer.getCust_name() + ""\t"" +  
          customer.getCust_id() +  
          customer.getCust_address()); 
      }   

```

1.  在执行时，我们将得到以下异常，指定存在多个可注入的 Address 实例，导致不明确性：

```java
      Caused by: 
      org.springframework.beans.factory.NoUniqueBeanDefinitionException
      :No qualifying bean of type [com.ch02.beans.Address] is defined:
      expected single matching bean but found 2: cust_address1,address 

```

1.  更新数据成员 cust_address 的注解为 @Qualifier，如下所示：

```java
       @Qualifier(value=""address"") 
       private Address cust_address; 

```

我们指定要注入以满足依赖关系的 bean 的 id。 在我们的案例中，id 为 ''address'' 的 bean 将被注入。

1.  执行我们在第 2 步创建的主要功能，以获得以下输出，显示 id 为 'address' 的 bean 注入到 `Customer_Autowried` 中：

```java
      INFO: Loading XML bean definitions from class path resource
        [customer_new.xml] 
      my name  10  Pune  2 

```

##### Case 3. 使用 @Required

在开发代码时，如果未提供正确值或缺少这些值，业务逻辑将失败。因此，必须注入依赖项，无论如何都不能失败。为确保已注入依赖项并准备好使用，请在`@Autowired`注解之后应用`@Required`。它的工作方式与'`autowired=true`'相同。但与它相比，注解只能应用于 setter 方法。如果依赖项不可用，将抛出`BeanInitializationException`。

以下代码清楚地说明了`@Required`的使用：

```java
@Component(value=""cust_required"") 
public class Customer_Annot_Required { 

  private String cust_name; 
  private int cust_id; 

  private Address cust_address; 

  public void setCust_name(String cust_name) { 
    this.cust_name = cust_name; 
  } 

  public void setCust_id(int cust_id) { 
    this.cust_id = cust_id; 
  } 

  @Autowired 
  @Required 
  public void setCust_address(Address cust_address) { 
    this.cust_address = cust_address; 
  } 

  public Customer_Annot_Required() { 
    // TODO Auto-generated constructor stub 
    cust_id=10; 
    cust_name=""my name""; 
  } 
// getter methods 
} 

```

##### 案例 4：作用域管理注解

几页前我们深入讨论了作用域及其使用。我们还看到了如何在 XML 中根据需求管理作用域。通常`@Scope`是类级注解。但它也可以与 Bean 注解一起使用，指示返回实例的作用域。

以下代码表示使用@Scope：

```java
package com.ch02.scope.annotation; 

@Component 
@Scope(scopeName=""prototype"") 
public class Customer_Scope { 

  private String cust_name; 
  private int cust_id; 

  @Autowired   
  @Qualifier(value=""address"") 
  private Address cust_address; 

  public Customer_Scope() { 
    // TODO Auto-generated constructor stub 
    cust_id=10; 
    cust_name=""my name""; 
  } 
//getters and setters 
} 

```

您可以使用以下代码来检查每次是否提供了新的实例：

```java
public class TestCustomer_Scope { 
  public static void main(String[] args) { 
    // TODO Auto-generated method stub 
    ApplicationContext context = new  
      ClassPathXmlApplicationContext(""customer_new.xml""); 
    Customer_Scope customer = (Customer_Scope)  
      context.getBean(""customer_Scope""); 
    System.out.println(customer.getCust_name() + ""\t"" +  
      customer.getCust_id() +    
      customer.getCust_address()); 
    customer.setCust_name(""new name set""); 
    Customer_Scope customer1 = (Customer_Scope)  
      context.getBean(""customer_Scope""); 
    System.out.println(customer1.getCust_name() + ""\t"" +  
      customer1.getCust_id() +  
      customer1.getCust_address()); 
    System.out.println(""after changing name and using prototype  
      scope""); 
    System.out.println(customer.getCust_name() + ""\t"" +  
      customer.getCust_id() +  
      customer.getCust_address()); 
    System.out.println(customer1.getCust_name() + ""\t""     
      + customer1.getCust_id()+   
      customer1.getCust_address()); 
  } 
} 

```

您可以参考 Ch02_Demo_Annotation 中的完整代码。

#### JSR 标准注解

Spring 2.5 支持 JSR-250，而从 3.0 开始，框架开始支持 JSR-330 标准注解，其发现方式与基于 Spring 的注解相同。JSR 提供了用于生命周期管理、bean 配置、自动注入和许多其他需求的注解。让我们逐一讨论它们。

##### 生命周期注解

我们已经足够讨论了 bean 的生命周期以及通过 XML 配置实现它的不同方式。但我们还没有讨论基于注解的。从 Spring 2.5 开始，支持通过`@PostConstruct`和`@PreDestroy`进行生命周期管理，分别提供了`InitializingBean`和 Disposable 接口的替代方案。

**@PostConstruct：**

被@PostConstruct 注解标注的方法将在容器使用默认构造函数实例化 bean 之后调用。这个方法在实例返回之前调用。

**@PreDestroyed：**

被@PreDestroy 注解标注的方法将在 bean 被销毁之前调用，这允许从可能因对象销毁而丢失的资源中恢复值。

让我们按照以下步骤使用它来了解 bean 的生命周期：

1.  在我们已经在使用讨论 bean 生命周期的 Ch02_Bean_Life_Cycle java 项目中添加 Car_JSR 类，位于 com.ch02.beans 包中。

1.  在 Car 类中添加一个 init_car 方法用于初始化汽车，并用@PostConstruct 注解标注，如下所示：

```java
      @PostConstruct 
      public void init_car() 
      { 
         System.out.println(""initializing the car""); 
         price=(long)(price+(price*0.10)); 
      } 

```

1.  在类中添加一个方法，该方法包含汽车销毁的代码，这实际上是资源释放，如下所示：

```java
       @PreDestroy 
       public void destroy_car() 
       {   
         System.out.println(""demolishing the car""); 
       } 

```

1.  添加 beans_new.xml 以配置 bean，不要忘记在应用程序中使用注解的规则。XML 将如下所示：

```java
      <context:annotation-config/> 
        <bean id=""car"" class=""com.ch02.beans.Car""       
          scope=""prototype""> 
          <property name=""chesis_number"" value=""eng2012"" /> 
          <property name=""color"" value=""baker''s chocolate"" /> 
          <property name=""fuel_type"" value=""petrol"" /> 
          <property name=""average"" value=""12.50"" /> 
          <property name=""price"" value=""643800"" /> 
        </bean> 

```

1.  在 TestCar 中添加一个 main 方法，如下所示：

```java
      public static void main(String[] args) { 
        // TODO Auto-generated method stub 
        ApplicationContext context=new           
          ClassPathXmlApplicationContext(""beans.xml""); 
        // first request to get the car instance 
        Car_JSR car_one=(Car_JSR)context.getBean(""car""); 
        car_one.show(); 
      } 

```

1.  执行代码后，我们将得到以下输出，显示调用了 init_car()：

```java
      INFO: Loading XML bean definitions from class path resource
        [beans.xml] 
      initializing the car 
      showing car eng2012 having color:-baker''s chocolate and 
      price:-708180 

```

1.  由于销毁方法将在上下文切换后执行，所以控制台上将不会显示输出。我们可以使用以下代码优雅地关闭容器：

```java
      ((AbstractApplicationContext)context).registerShutdownHook(); 

```

**@Named**

`@Named`注解用于代替应用于类级别的`@Component`。`@Named`注解不提供组合模型，但其扫描方式与`@Component`相同：

```java
@Named 
public class Customer { 

  private String cust_name; 
  private int cust_id; 

  private Address cust_address; 
   //default and parameterize constructor 
   //getters and setters 
} 

```

**@Inject**

`@Inject`用于自动注入依赖项，就像我们为`@Autowired`做的那样。但它不会有`required`属性来指定依赖是可选的。以下代码显示了实现方式：

```java
@Named 
public class Customer { 

  private String cust_name; 
  private int cust_id; 

   @Inject 
  private Address cust_address; 
   // default and parameterized constructor 
   // getters and setters 
} 

```

**@Configuration**

类级别的`@Configuration`注解用于指示类作为 bean 定义的来源，就像我们在`<beans></beans>`标签中的 XML 文件中做的那样。

```java
@Configuration 
public class MyConfiguration { 

// bean configuration will come here 

} 

```

Spring 注解如`@Component`、`@Repository`需要注册到框架中。在 XML 中，通过提供一个`<context:component-scan>`属性 base-package 来启用这些注解的扫描。`@Component-Scan`是启用 Spring stereotypes 注解扫描的替代方案。语法如下所示：

```java
@Component-Scan(basePackage=name_of_base_package) 

```

**@Bean**

`@Bean`与`@Configuration`一起使用，用来声明 bean 定义，就像我们通常在 XML 中的`<bean></bean>`标签中做的那样。它适用于有 bean 定义的方法。代码可以如下所示：

```java
@Configuration 
public class MyConfiguration { 
    @Bean 
    public Customer myCustomer() 
    { 
        Customer customer=new Customer(); 
        customer.setCust_name(""name by config""); 
      return customer; 
   } 
} 

```

要定义从`myCustomer()`返回的 bean，也可以有自定义的 bean id，可以通过：

```java
@Bean(name=""myCustomer"") 

```

注解配置已经取代了 XML。`AnnotationConfigApplicationContext`类帮助以与`ClasspathXmlApplicationContext`相同的方式加载配置。测试类可以写成：

```java
public static void main(String[] args) { 
  ApplicationContext context=new   
     AnnotationConfigApplicationContext(MyConfiguration.class); 
  Customer customer=(Customer)context.getBean(""myCustomer""); 
  System.out.println(customer.getCust_id()+""\t""+ 
    customer.getCust_name()); 
} 

```

你可以参考 Ch02_Demo_JSR_Annot 中的完整代码。

### 注意

XML 提供了一种集中进行 bean 配置的方式。由于依赖项被保持在源代码之外，它们的更改不会影响源代码。此外，在 XML 配置中，源代码不需要重新编译。但是，基于注解的配置直接是源代码的一部分，并且散布在整个应用程序中。这变得去中心化，最终变得难以控制。基于注解注入的值将被 XML 注入覆盖，因为基于注解的注入发生在 XML 注入之前。

### Spring 表达式语言（SpEL）

到目前为止，我们配置了次要类型的值。对于 bean 的连接，我们使用了我们在编译时编写并可用的 XML 配置。但是使用它我们无法配置运行时值。Spring 表达式提供了所需的解决方案，其值将在运行时进行评估。

开发人员可以使用 SpEL 引用其他 bean 并设置字面量值。它提供了一种调用对象的方法和属性的手段。SpEL 可以评估使用数学、关系和逻辑运算符的值。它还支持集合的注入。这与在 JSP 中使用 EL 有些相似。使用 SpEL 的语法是'#{value}'。让我们逐一找出如何在应用程序中使用 SpEL。

#### 使用字面量

在 SpEL 中使用字面量允许开发人员为 bean 的属性设置原始值。虽然在配置中使用字面量并不有趣，但了解如何在表达式中使用确实帮助我们走向复杂的表达式。按照以下步骤了解字面量的使用，

1.  将 Ch02_SpringEL 创建为 Java 应用程序，并添加 Spring 库。

1.  在 com.ch02.beans 中定义 Customer.java，如下所示：

```java
      public class Customer { 
        private String cust_name; 
        private String cust_id; 
        private boolean second_handed; 
        private double prod_price; 
        private String prod_name; 
        // getters and setters 
        // toString() 
      } 

```

1.  在类路径中创建 beans.xml 文件，以如下方式配置客户 bean：

```java
      <bean id=""cust_new"" class=""com.ch02.beans.Customer""> 
        <property name=""cust_name"" value=""Bina"" /> 
        <property name=""cust_id"" value=""#{2}"" /> 
        <property name=""prod_name"" value=""#{''Samsung Fridge''}"" /> 
        <property name=""prod_price"" value=""#{27670.50}"" /> 
        <property name=""second_handed"" value=""#{false}"" /> 
      </bean> 

```

你可以看到 cust_id、prod_price 使用 SpEL 语法配置为'#{ value}'，并为 prod_name 使用单引号指定值。你甚至可以使用双引号指定字符串值。cust_name 已使用旧风格配置。是的，仍然可以同时使用旧风格和 SpEL 设置值。

1.  按照下面的代码添加 TestCustomer.java：

```java
      public static void main(String[] args) { 
        // TODO Auto-generated method stub 
          ApplicationContext context=new     
          ClassPathXmlApplicationContext(""beans.xml""); 
        Customer customer=(Customer)context.getBean(""cust_new""); 
        System.out.println(customer); 
      } 

```

1.  我们将得到如下输出：

```java
      INFO: Loading XML bean definitions from class path resource 
      [beans.xml] 
      Bina has bought Samsung Fridge for Rs 27670.5 

```

#### 使用 bean 引用

在 XML 中配置的每个 bean 都有其唯一的 bean id。这可以用于引用值或使用 SpEL 进行自动装配。按照以下步骤了解如何使用 bean 引用。

1.  在上面的 Ch02_SpringEL 项目中添加新的 POJO 类 Address 和 Customer_Reference，如下所示：

```java
      public class Address { 
        private String city_name; 
        private int build_no; 
        private long pin_code; 

        // getter and setter 
        @Override 
        public String toString() { 
          // TODO Auto-generated method stub 
          return city_name+ "",""+pin_code; 
        } 
      } 
      public class Customer_Reference { 
        private String cust_name; 
        private int cust_id; 
        private Address cust_address; 

        // getter and sertter 

        @Override 
        public String toString() { 
          return cust_name + "" is living at "" + cust_address; 
        } 
      } 

```

1.  在 beans.xml 中添加 Address 和 Customer_Reference bean，如下所示：

```java
      <bean id=""cust_address"" class=""com.ch02.beans.Address""> 
        <property name=""build_no"" value=""2"" /> 
        <property name=""city_name"" value=""Pune"" /> 
        <property name=""pin_code"" value=""123"" /> 
      </bean> 
      <bean id="cust_ref" class=""com.ch02.beans.Customer_Reference""> 
        <property name=""cust_name"" value=""Bina"" /> 
        <property name=""cust_id"" value=""#{2}"" /> 
        <property name=""cust_address"" value=""#{cust_address}"" /> 
      </bean> 

```

注意 cust_address 的初始化方式。将客户地址赋值给 cust_address，这是为 Address 定义的 bean 的 id。

1.  按照第 4 步的方法定义 TestCustomer_Reference，以获取'cust_ref'bean。

1.  执行后，我们将得到如下输出：

```java
      INFO: Loading XML bean definitions from class path resource
      [beans.xml] 
      Bina is living at Pune,123 

```

1.  有时，我们可能希望注入 bean 的某个属性，而不是使用整个 bean，如下所示：

```java
      <bean id="cust_ref_new"class="com.ch02.beans.Customer_Reference"> 
        <property name=""cust_name""  
          value=""#{cust_ref.cust_name.toUpperCase()}"" /> 
        <property name=""cust_id"" value=""#{2}"" /> 
        <property name=""cust_address"" value=""#{cust_address}"" /> 
      </bean> 

```

我们通过从 bean 'cust_ref'借用 cust_name 并将其转换为大写来注入它。

#### 使用数学、逻辑、关系运算符

在某些场景中，依赖项的值需要使用数学、逻辑或关系运算符来定义和放置。你可以找到如何使用它们的演示。

1.  我们将使用前面案例中定义的同一个项目 Ch02_SpringEL。

1.  在 beans.xml 中定义 Customer bean，如下所示：

```java
      <bean id=""cust_calculation"" class="com.ch02.beans.Customer""> 
        <property name="cust_name" value="Bina" /> 
        <property name="cust_id" value="#{2}" /> 
        <property name="prod_name" value="#{''Samsung Fridge''}" /> 
        <property name="prod_price" value="#{27670.50*12.5}" /> 
        <property name="second_handed"  
          value="#{cust_calculation.prod_price > 25000}" /> 
      </bean> 

```

prod_price 的值通过数学运算符在运行时计算，并通过关系运算符评估'second_handed'的值。

1.  编写 TestCustomer_Cal 以获取 cust_calculation 并如下显示其属性：

```java
      public static void main(String[] args) { 
        // TODO Auto-generated method stub 
        ApplicationContext context=new  
          ClassPathXmlApplicationContext(""beans.xml""); 
        Customer customer=    
          (Customer)context.getBean(""cust_calculation""); 
        System.out.println(customer); 
        System.out.println(customer.isSecond_handed()); 
      } 

```

在整个章节中，我们都看到了如何进行配置。但我们忽略了一个非常重要的点——“松耦合”。我们使用的类导致了紧密耦合，而我们知道，通过合同编程可以给开发者提供编写松耦合模块的便利。我们避免在上面的所有示例中使用接口，因为它可能会使它们变得不必要复杂。但在实际的应用程序中，您会在 Spring 的每个阶段发现接口的使用。从下一章节开始，我们将使用编写 Spring 应用程序的标准方式。

## 总结

（此处原文为三个星号，表示空白行）

本章充满了各种配置，不同的方法和替代方案，它们都可以用来完成同一件事情。无论您使用的是 Spring 的 5.0 版本还是更低版本，本章都会在您的学习旅程中提供帮助。在本章中，我们探讨了实例创建和初始化的各种方法。现在，我们已经了解了几乎所有的 Java 概念以及如何使用 XML 和基于注解的方式来配置它们。我们还看到了诸如自动注入、SpEL 等减少配置的方法。我们展示了 Spring 提供的以及 JSR 注解。

现在我们已经准备好将这些内容应用到我们的应用程序中。让我们从数据库处理开始。在下一章节中，我们将了解如何使用 Spring 来处理数据库，以及 Spring 如何帮助我们进行更快的开发。
