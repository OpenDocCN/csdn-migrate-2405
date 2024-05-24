# Spring 集成基础知识（一）

> 原文：[`zh.annas-archive.org/md5/9D4CBB216DD76C0D911041CB2D6145BA`](https://zh.annas-archive.org/md5/9D4CBB216DD76C0D911041CB2D6145BA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

软件一直是企业的 integral 部分，也是其增长的关键贡献者。无论是分析、用户体验、社会营销、决策支持系统，还是其他任何功能领域，软件一直被用来帮助企业实现顺利和高效运作。企业从小开始，随着时间的推移逐渐成长，其软件依赖也是如此。企业应用程序是在一段时间内开发而成的。处理企业软件时，以下方面会带来一定的挑战：

+   它们分布在一批领域内，例如，工资单、库存、报告和社会集成。

+   这些模块中的每一个可能都是独立开发的，并且可能位于不同的平台上，例如，基于 J2EE 栈的员工自我门户、在大型机上的遗留记录管理系统、使用 Salesforce 的 CRM 系统，以及它们专有实现中的一些实时应用程序。

+   这些模块需要相互交互，并与外部系统交互。它们可能需要通过 SOAP 服务或共享文件从外部来源消费数据，或者它们自己必须通过多种数据共享技术之一共享数据。

+   随着软件的衰老，我们需要引入新的平台并替换现有的模块以减轻不断增长的维护成本。一次性替换的策略是不可行的；相反，在过渡过程中应该以同质化方式进行，而不打扰现有模块的稳定性。

这些模块的集成，无论是内部组织还是与外部合作伙伴集成，都是固有复杂的，需要集成异质端点。这是企业应用集成试图解决的情景。**企业集成模式**（**EIP**）是一系列标准企业挑战及其应对方式的集合。Spring Integration 是 EIP 的一种实现，提供了许多 EIP 推荐的现成组件。

# 企业集成挑战如何解决

许多方法已经被尝试以简化集成，同时不牺牲企业至关重要的方面，例如安全性、事务、可用性、可靠性和 so on。随着时间的推移使用的一些著名方法包括**Java Connector Architecture**（**JCA**）、RMI、RPC 和 CORBA 用于平台无关的集成，带有系统适配器的消息代理等等。在幕后，它们试图通过以下一种或多种技术解决集成问题：

+   **共享文件**：这是最简单的方法。系统可以以预定义的格式向文件写入数据，其他端点可以阅读这些文件。可能需要一个适配器来转换两个不同端点之间的格式。让我们考虑一个例子，以前每天都会生成一个 CSV 文件的报告。随着时间的推移，该组织建立了网站，现在需要将报告推送到线上。这该如何实现？最简单的方法是将它倒入由适配器读取并输入到 CMS 系统的文件中。文件系统很简单，但不是最佳解决方案；它不是事务性的。如果某个特定文件损坏了，或者由于网络故障，轮询间隔内文件不可用怎么办？这需要引入一个具有重试机制、过滤能力等许多非功能性方面的复杂系统，如安全访问、归档等等。

+   **共享数据库**：这解决了一些文件系统所解决的问题，如事务性行为、基于角色的访问、性能调优、分布式支持等等。常见的机制是一组连接表——一个应用程序在别人理解的架构中写入数据。另一方面，这引入了紧密耦合；如果架构发生变更，两个系统都需要相应地更新。发展中的应用程序将成为一个挑战，因为它们必须考虑到外部系统限制。集成工作本身可能从一开始就会遇到很多挫折，例如，应用程序数据库供应商提供的 SQL 兼容性问题、数据格式和表中的类型等等。例如，如果一个系统只存储日期，而另一个系统存储带有时间戳的日期，根据需要，至少有一个将必须更改格式。

+   **远程过程调用**：这种机制引入了一个范例，每个系统都可以通过发布合同来提供服务。这些范例可以是一个方法、参数、结果和错误。例如，一个 EJB 服务或一个 SOAP 服务可以暴露出来，为报告模块提供原始数据，并以多种格式呈现。最限制性的方面是同步行为，系统必须等待结果。还有其他挑战，如数据的序列化、网络延迟、模块的性能问题，这些都可能导致整个应用程序崩溃，等等。从安全角度来看，暴露方法和参数会邀请黑客发挥他们的创造力。

+   **消息传递**：它引入了异步模型，其中两个异构模块可以通过数据在预定义的连接上进行交互。最大的优势是解耦——没有任何系统依赖于其他系统的可用性，并且它们可以参与或退出集成，而不会影响其他组件。JMS 是基于消息传递集成的例子。Spring Integration 基于这种范式，其中多个端点连接到一个通道，生产或消费消息，并根据消息中的信息执行进一步的处理。我们将在接下来的章节中介绍通道、端点、消息载荷和其他概念。

即使我们使用了前面提到的某一种技术，企业系统之间也相去甚远，而且它们可能不会一直运行。这使得需要使用中间件来协调这些不同端点之间的可靠通信，这种中间件通常称为**企业服务总线**（**ESB**）。用通俗的话来说，ESB 可以被定义为使异构接口之间能够双向通信的中介。

# 参与者是谁？

如我们之前所讨论的，企业集成的问题复杂多样，许多供应商尝试在他们自己的专有 ESB 框架中解决它——以前，这些领域一直由商业供应商如 Tibco、Vitria、IBM MQSeries、Oracle SOA Suite、Microsoft BizTalk 等主导。随着时间的推移，对于开源框架的需求变得明显，因为小型组织逐渐成长。他们的集成需求有限，而且无法与这些巨头中的任何一个进行前期投资。

除了 Spring Integration 之外，还有一些著名的开源集成框架，如 Camel、Service Mix、Mule ESB、Open ESB 等。对这些框架的全面比较超出了本书的范围，但为了强调 Spring Integration 的简洁性，这里提供了一个另外两个主要开源框架的简要总结：

+   **Mule ESB**：它是一个标准的服务器，解决方案是在其中开发和部署的。Mule 是市场上最突出和最稳定的解决方案之一。需要注意的一点是，它是一个包含应用程序的容器。

+   **Service Mix (SM)**：Apache Service Mix 基于 JAVA 遗留 JBI（Java Business Integration）。Service Mix 试图通过统一 ActiveMQ、Camel、CXF、ODE 和 Karaf 的功能和特性来解决企业集成的几乎所有方面。它提供了一个完整的、企业级就绪的 ESB，专门由 OSGi 提供动力。因为它试图解决很多模块，所以与 Spring Integration 相比，它相当庞大。

# 为什么使用 Spring Integration？

Spring Integration 是一个开源项目，旨在解决集成挑战；它基于 Spring Framework，这是组织中最广泛使用的基于 Java 的框架。它引入了简单的基于 POJO 的编程模型，以支持标准集成模式。

它轻量级；所有它需要的是几个 jar 文件，Maven 目标已经准备好了。快速比较显示 Service Mix 的下载大小约为 55MB，而 Spring Integration 仅为 14MB。

+   Spring Integration 只是一组标准的 Java 库；解决方案部署在应用程序中，而不是将应用程序部署在某些容器中，如 SM 和 Mule 的情况。

对于已经使用 Java 和 Spring 的企业，它简化了集成工作，因为它遵循 Spring 框架相同的习语和模式。

# 本书涵盖内容

第一章, *入门指南*, 解释了如何设置 Eclipse IDE，“Hello World”程序，以及 Spring ROO 如何进一步简化配置方面的介绍。这将帮助克服配置噩梦，并为开发者提供实践经验。

第二章, *消息摄取*, 介绍了消息可以通过哪些通道读取和处理。它描述了点对点和发布-订阅模型，哪种模型最适合给定场景，如何在通道上以解耦的方式处理错误，以及最后如何在内存通道上支持持久化以实现故障转移和恢复解决方案。

第三章, *消息处理*, 解释了如何定义可以对消息应用业务逻辑的组件，介绍了解耦日志记录，可用于审计，并讨论了添加事务行为。

第四章, *消息转换器*, 讲述了处理消息格式，将其转换为同质格式，以及注解如何帮助保持配置的整洁。消息可以以异构格式引入，如 XML、JSON 等，需要转换为系统能理解的格式。

第五章, *消息流*, 将介绍与消息相关的流程方面，例如过滤不符合验证规则的消息，将它们路由到错误分支，分割消息，并将它们重定向到适合其处理的组件—等待不完整载荷，聚合部分消息，最后是业务处理链。

第六章，*与外部系统的集成*，将提供一个实践性的概览，介绍集成点。与外部系统的集成是 Spring Integration 最有趣和强大的方面——与外部系统的交互只需几行配置即可。Spring Integration 引入了适配器、网关和其他组件，使得与文件系统、SQL、NoSQL 持久化存储、HTTP 服务以及其他广泛使用的实体（如不同服务器、社交媒体等）的交互变得轻而易举。

第七章，*与 Spring Batch 的集成*，将介绍如何使用 Spring Integration 和批处理模块来调度、触发和监控批处理作业。

第八章，*测试支持*，将解释如何利用不同组件的可用的模拟，以及要测试什么、测试多少。

第九章，*监控、管理和扩展*，将介绍如何使用 Spring Integration 配置来利用 JMX 获取系统中不同配置组件的性能统计。我们还将探讨扩展 Spring Integration 组件的方法。

第十章，*一个端到端的示例*，提供了一个端到端的实践示例，帮助你回忆不同章节中介绍的概念，并重新确认他们的理解。代码将被推送到社交代码库，如 GitHub，但本章将为用户提供足够的说明来使用它并运行它。

# 本书你需要什么

你需要一个基于 Java 的集成开发环境，推荐使用 Spring STS。需要 JDK 1.6 及以上版本。

# 本书面向谁

本书面向已经熟悉基本 Java 和 Spring 概念的开发者。熟悉企业集成模式的概念会有帮助，但不是强制性的。本书以实践的方式呈现，选择了一个端到端的实例，并在各个章节中实施和解释。本书将为尝试集成方面的初学者提供强有力的伴侣，为已经熟悉这些挑战并在寻找快速样本的开发者提供实践指南。

# 约定

在本书中，你会发现有许多种文本风格，用于区分不同类型的信息。以下是一些这些风格的示例，以及它们的意义解释。

文本中的代码词汇、数据库表名、文件夹名、文件名、文件扩展名、路径名、假网址、用户输入和 Twitter 处理显示如下："通过导航到**文件** | **Spring 项目**创建一个 Spring Integration 项目，如下截图所示："。

代码块如下所示：

```java
<int:channel id="resultPersistenceChannel">
  <int:queue message-store="messageStore"/>
</int:channel>

<int-jdbc:message-store id="messageStore" data-source="someDataSource"/>
```

当我们希望吸引您的注意力到代码块的某个特定部分时，相关的行或项目会被设置为粗体：

```java
public interface ChannelInterceptor {
  Message<?> preSend(Message<?> message, MessageChannel channel);
  void postSend(Message<?> message, MessageChannel channel, boolean sent);
  boolean preReceive(MessageChannel channel);
  Message<?> postReceive(Message<?> message, MessageChannel channel);
```

**新术语**和**重要词汇**以粗体显示。例如，您在屏幕上、菜单或对话框中看到的词汇，在文本中会显示为这样："点击**下一步**按钮会将您带到下一屏"。

### 注意

警告或重要说明会以这样的盒子出现。

### 提示

技巧和窍门会显示成这样。

# 读者反馈

读者反馈对我们来说总是受欢迎的。让我们知道您对这本书的看法——您喜欢或可能不喜欢的地方。读者反馈对我们开发您真正能从中受益的标题非常重要。

要发送一般性反馈，只需发送一封电子邮件到`<feedback@packtpub.com>`，并通过消息主题提及书籍标题。

如果您在某个主题上有专业知识，并且有兴趣撰写或贡献一本书，请查看我们在[www.packtpub.com/authors](http://www.packtpub.com/authors)上的作者指南。

# 客户支持

既然您已经成为 Packt 书籍的骄傲拥有者，我们有很多事情可以帮助您充分利用您的购买。

## 下载示例代码

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)账户中购买的所有 Packt 书籍的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册以便将文件直接通过电子邮件发送给您。代码也可以从[`github.com/cpandey05/siessentials`](https://github.com/cpandey05/siessentials)拉取。

## 错误报告

虽然我们已经竭尽全力确保内容的准确性，但是错误仍然会发生。如果您在我们的某本书中发现错误——可能是文本或代码中的错误——我们将非常感谢您能向我们报告。这样做，您可以避免其他读者遭受挫折，并帮助我们改进本书的后续版本。如果您发现任何错误，请通过访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)报告，选择您的书籍，点击**错误提交** **表单**链接，并输入您错误的详细信息。一旦您的错误得到验证，您的提交将被接受，错误将会上传到我们的网站，或者添加到该标题的错误部分中。任何现有的错误可以通过从[`www.packtpub.com/support`](http://www.packtpub.com/support)选择您的标题来查看。

## 盗版

互联网上侵犯版权材料的问题持续存在，遍布所有媒体。在 Packt，我们非常重视对我们版权和许可的保护。如果您在互联网上以任何形式发现我们作品的非法副本，请立即提供给我们位置地址或网站名称，这样我们才能采取补救措施。

请通过`<copyright@packtpub.com>`联系我们，附上疑似侵权材料的链接。

我们感谢您在保护我们的作者和我们的能力带来有价值内容方面所提供的帮助。

## 问题

如果您在阅读本书的任何方面遇到问题，可以通过`<questions@packtpub.com>`联系我们，我们会尽最大努力解决。


# 第一章：入门

在本章中，我们将设置我们的开发环境，并讨论如何最大限度地利用**SpringSource Tool Suite**（**STS**）。虽然任何流行的 Java 开发 IDE，如*Eclipse*、*intelliJ*、*NetBeans*和其他 IDE 都可以用于开发 Spring Integration 解决方案，但引领 Spring Integration 的公司 Pivotal 建议您使用基于 Eclipse 的**STS**。

# 设置 STS

STS 集成了许多现成的插件、可视化编辑器和其他特性，这些使得开发 Spring 驱动的企业应用变得容易。IDE 的外观和感觉与 Eclipse 非常相似。按照以下步骤安装 STS：

1.  JDK 1.6 及以上是必备条件，请从[`www.oracle.com/technetwork/java/javase/downloads/java-archive-downloads-javase6-419409.html`](http://www.oracle.com/technetwork/java/javase/downloads/java-archive-downloads-javase6-419409.html)下载并安装。

1.  按照文档中的说明设置`JAVA_HOME`属性：[`docs.oracle.com/cd/E19182-01/820-7851/inst_cli_jdk_javahome_t/index.html`](https://docs.oracle.com/cd/E19182-01/820-7851/inst_cli_jdk_javahome_t/index.html)。

1.  从[`spring.io/tools/sts`](http://spring.io/tools/sts)下载 STS。

1.  下载的文件是 ZIP 格式。解压到喜欢的文件夹，就绪。

1.  转到`<安装目录>\sts-bundle\sts-3.6.1.RELEASE`。`STS.exe`文件是启动 IDE 的可执行文件。

1.  这一步是可选的，但可以帮助编辑器高效运行——更改内存分配参数。找到`STS.ini`（与`STS.exe`在同一文件夹中）并将`Xmx`的值更改为 2 GB，例如`Xmx2048m`。

# 创建你的第一个项目

以下步骤将帮助你创建第一个项目：

1.  通过导航到**文件** | **Spring 项目**创建一个 Spring Integration 项目，如图所示：![创建你的第一个项目](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-itg-ess/img/00002.jpeg)

1.  在模板部分，选择**Spring Integration Project - Simple**。提供一个项目名称，例如`sisimple`，如图所示：![创建你的第一个项目](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-itg-ess/img/00003.jpeg)

1.  填写创建基于 Maven 的项目所需的信息，如图所示：![创建你的第一个项目](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-itg-ess/img/00004.jpeg)

1.  点击**完成**，这将创建一个我们提供的名称（`sisimple`）的项目，如图所示：![创建你的第一个项目](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-itg-ess/img/00005.jpeg)

这个项目尽可能简单。下面我们快速看一下生成的 Java 类：

+   `Main.java`：此文件位于路径：`/sisimple/src/main/java/com/chandan/example/si/`。它有主方法，并将用于运行这个示例。从包浏览器中右键点击此文件，然后点击**运行为** | **Java 应用程序**——这将启动程序。这个类有引导 Spring Integration 配置文件并加载其中定义的组件的代码。此外，它还将用户输入转换为大写。

+   `StringConversionService.java`：此文件位于路径：`/sisimple/src/main/java/com/chandan/example/si/service/`。这个服务接口用于将用户输入转换为大写。

+   `spring-integration-context.xml`：此文件位于路径：`/sisimple/src/main/resources/META-INF/spring/integration/`。这是 Spring Integration 的配置文件。它包含了基于 XML 的 Spring Integration 组件的声明。

+   `log4j.xml`：此文件位于路径：`/sisimple/src/main/resources/`。这是`Log4j`的配置文件。可以编辑此文件以控制日志级别、输出器以及其他与日志相关的内容。

+   `StringConversionServiceTest.java`：此文件位于路径：`/sisimple/src/test/java/com/chandan/example/si/`。这是`StringConversionService`的测试文件。这将用于运行针对服务类进行的测试。

+   `pom.xml`：这是用于 rmaven 依赖管理的文件，位于`/sisimple/`目录下。它包含了项目所用到的所有依赖项的条目。

在没有建立起一些理论概念的情况下，就解释这些类和配置文件中的每一个组件可能会有些繁琐和过于提前——我们将随着章节的推进，详细讨论每一个元素。

# STS 视觉编辑器

STS 提供了视觉方式来添加不同的命名空间。定位到`/sisimple/src/main/resources/META-INF/spring/integration/`下的`spring-integration-context.xml`并打开它。这是默认的 Spring 配置文件。点击**命名空间**标签来管理 Spring Integration 的不同命名空间。下面的截图显示了此示例项目的导入命名空间：

![STS 视觉编辑器](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-itg-ess/img/00006.jpeg)

在同一个编辑器中，点击**Integration-graph**标签将打开一个视觉编辑器，可以用来添加、修改或删除 Spring Integration 的端点、通道和其他组件。下面的截图包含了我们示例项目的集成图：

![STS 视觉编辑器](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-itg-ess/img/00007.jpeg)

让我们快速查看一下生成的 Maven POM 文件——总体来说，有三个依赖项；仅有一个是 Spring Integration 的，另外两个是*Junit*和*log4j*，如下面的截图所示：

![STS 视觉编辑器](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-itg-ess/img/00008.jpeg)

# Spring Integration Scala DSL

该项目还处于非常早期的阶段，是一个孵化项目。Scala DSL 不应该与 Scala 中提供的其他 EIP 实现混淆——相反，它是建立在 Spring Integration 之上的，提供基于 DSL 的配置和流程管理。

### 注意

请访问[Spring Integration Scala DSL 官方博客](http://spring.io/blog/2012/03/05/introducing-spring-integration-scala-dsl/)和[GitHub 页面](https://github.com/spring-projects/spring-integration-dsl-groovy)。

# 摘要

在本章中，您学习了如何设置您的 IDE 并创建了一个基本项目。我们还尝试了 STS 的视觉编辑器，并简要介绍了即将到来的 Spring Integration 的 Scala DSL。我们将在后续章节中利用这些知识使用 STS 构建一个引人注目的 Spring Integration 应用程序。

在下一章中，我们将介绍如何在应用程序中摄取消息，然后是如何处理它们。


# 第二章：消息摄取

如*序言*中所述，Spring Integration 是*企业集成模式：设计、构建和部署消息解决方案（Addison Wesley 签名系列）*，*Gregor Hohpe*和*Bobby Woolf*，*Addison-Wesley 专业*的实现。**EIP**（即**企业集成模式**的缩写）定义了许多集成挑战的模式，其中之一就是异构系统之间的消息交换。在本章中，我们将探讨与消息交换相关的模式和概念。

异构端点使用消息进行通信。消息交换主要有三个方面：正在交换的消息、参与通信的端点以及消息传递的媒介。在 EIP 范式中，我们将其定义为消息、消息端点和消息通道。让我们逐一讨论每一个，然后我们再讨论模式。

**消息是什么？**用最简单的术语来说，消息可以被理解为一个可以作为不同组件之间互操作和协作的启动物息。它主要由两部分组成：标题和有效载荷。标题包含元数据，通常需要诸如 ID、时间戳等值，但标题的使用也可以扩展为传递其他值，例如，路由器的通道名，文件组件的文件名等等。有效载荷可以是任何类型：标准 Java 对象、XML 或任何自定义或用户定义的值。它也可以是一个简单的信息共享有效载荷（例如，注册模块可以在新用户注册时通知审计模块），或者它可以是一个命令（例如，管理模块可以指示邮件服务通知所有注册课程的用户），或者它可以是一个事件（例如，在发送所有邮件后，邮件服务将事件返回给管理模块，指示所有邮件已发送，可以进行下一步）。

我们注意到了一个模式；两个组件通过这些消息进行通信——在正式术语中，我们称这些组件为消息端点。同样，我们可以观察到消息端点有两种类型：生产者端点和消费者端点。正如他们的名字所暗示的，一个生产者，比如`注册模块`，在给定示例中生成一个消息，而一个消费者则消耗它——比如给定示例中的`审计模块`。一个端点可以同时是生产者和消费者，例如，一个邮件服务。端点通常是智能组件，可以在将消息传递给下一个子系统之前验证消息，或者可以进行路由、过滤、聚合、转换等操作，以便消息能够符合下一环节的预期格式。

# **与消息通道一起工作**

我们定义了消息，并讨论了消息端点如何处理消息，那么消息通道在哪里呢？消息通道是实现企业应用集成（EAI）设计模式的实现，它解耦了端点。端点不需要了解彼此的类型；它们向通道注册，而通道负责安全地在端点之间传递消息。每个通道都有一个逻辑标识符——它可能是一个唯一的名称或 ID，通过它可以引用和注册。根据通道处理消息的方式，它们可以分为两大类：

+   点对点通道

+   发布-订阅通道

# 通道类型

在开始它们的实现之前，让我们首先看看以下类型的通道：

+   **点对点通道**：维护生产者和消费者之间一对一的关系。这些通道将消息发送给唯一的一个接收者。即使注册了多个接收者，消息也只会发送给其中的一个。这种通道类型可用于并行处理场景，允许多个消费者并行监听消息的可用性，但消息的发送只会针对单个消费者进行！

+   **发布-订阅通道**：这些通道将消息发送给在通道上注册的所有订阅者，从而实现生产者和消费者之间的一对多关系。可以将其比作每个订阅者都有自己的私有通道，在该通道上发送消息的副本。一旦被消费，它就会被丢弃。

让我们摆脱成语，窥视一下 Spring Integration 如何为所有这些组件提供支持——毕竟，这是一本关于 Spring Integration 的书，不是吗！

# Spring 通道实现

Spring Integration 为消息通道定义了一个顶级接口，任何具体的通道实现都应该实现这个接口，如下所示：

```java
public interface MessageChannel {
  boolean send(Message<?> message);
  boolean send(Message<?> message, long timeout);
}
```

`MessageChannel` 接口定义了两个版本的 `send` 方法——一个只接受 `Message` 作为参数，而另一个接受一个额外的参数（`timeout`）。`send` 方法如果在成功发送消息则返回 true；否则，如果在超时或由于某种原因发送失败，它返回 false。

此外，Spring Integration 为 `MessageChannel` 接口提供了一个子类型，以支持两种类型的通道：`PollableChannel` 和 `SubscribableChannel`。以下详细解释了这一点：

+   **可轮询通道**：此通道提供了两个版本的接收接口，一个不带任何参数，另一个提供指定 `timeout` 参数的选项。以下代码片段是接口声明：

    ```java
    public interface PollableChannel extends MessageChannel {
      Message<?> receive();
      Message<?> receive(long timeout);
    }
    ```

+   **可订阅通道**：此接口提供了订阅和取消订阅通道的方法。以下是可订阅通道的接口声明：

    ```java
    public interface SubscribableChannel extends MessageChannel {
      boolean subscribe(MessageHandler handler);
      boolean unsubscribe(MessageHandler handler);
    }
    ```

`MessageHandler`接口的实例作为参数传递给`subscribe`和`unsubscribe`方法。`MessageHandler`接口只暴露了一个方法，即`handleMessage`，用于处理消息：

```java
public interface MessageHandler {
  void handleMessage(Message<?> message) throws MessageException;
}
```

无论何时有消息到达通道，框架都会寻找消息处理器的实现，并将消息传递给实现者的`handleMessage`方法。

尽管 Spring Integration 定义了消息通道接口并允许用户提供自己的实现，但通常并不需要。Spring Integration 提供了许多可以即插即用的通道实现。

# 选择通道

让我们讨论一下 Spring Integration 提供的默认实现以及如何利用它们。

## 发布-订阅通道

这是发布-订阅模型通道的唯一实现。这个通道的主要目的是发送消息到注册的端点；这个通道不能被轮询。它可以如下声明：

```java
<int:publish-subscribe-channel id="pubSubChannel"/>
```

让我们讨论一下此行中的每个元素；本章的示例将使用此元素：

+   `int`：这是一个命名空间，声明了所有 Spring Integration 组件。如在第一章，*入门*中讨论的，Spring Integration 的 STS 可视化编辑器可以用来添加不同的 Spring Integration 命名空间。

+   `publish-subscribe-channel`：这是 Spring 暴露的类型。

+   `Id`：这是通道的唯一名称，通过它来引用通道。

要从代码中引用这些元素，我们可以使用：

```java
public class PubSubExample {
  private ApplicationContext ctx = null;
  private MessageChannel pubSubChannel = null;
  public PubSubChannelTest() {
    ctx = new ClassPathXmlApplicationContext("spring-integration-context.xml");
    pubSubChannel = ctx.getBean("pubSubChannel", MessageChannel.class);
  }
}
```

## 队列通道

还记得古老的数据结构中的队列概念吗？`QueueChannel`采用了相同的概念——它强制实施**先进先出**（**FIFO**）顺序，并且一个消息只能被一个端点消费。即使通道有多个消费者，这也是一种严格的一对一关系；只有一个消息将交付给它们中的一个。在 Spring Integration 中，它可以定义如下：

```java
<int:channel id="queueChannel">
  <queue capacity="50"/>
</int:channel>
```

一旦通道上有消息可用，它就会尝试将消息发送给订阅的消费者。元素`capacity`指示队列中保持未交付消息的最大数量。如果队列已满，这是由`capacity`参数确定的，发送者将被阻塞，直到消息被消费并在队列中腾出更多空间。另外，如果发送者已经指定了超时参数，发送者将等待指定的超时间隔——如果在超时间隔内队列中创建了空间，发送者会将消息放在那里，否则它会丢弃该消息并开始另一个。

### 提示

尽管容量参数是可选的，但绝不能省略；否则，队列将变得无界，可能会导致内存溢出错误。

## 优先级通道

队列强制 FIFO，但如果一个消息需要紧急注意并需要从队列中处理怎么办？例如，一个服务器健康监控服务可能会将健康审计发送到一个*审计服务*，但如果它发送了一个服务器下线事件，它需要紧急处理。这就是`PriorityChannel`派上用场的地方；它可以基于消息的优先级而不是到达顺序来选择消息。消息可以根据以下方式进行优先级排序：

+   通过在每条消息中添加一个`priority`头

+   通过向优先级通道的构造函数提供一个`Comparator<Message<?>>`类型的比较器

### 注意

默认是消息中的`priority`头。

让我们以以下优先级通道示例为例，并在其中注入一个比较器，该比较器将用于决定消息的优先级：

```java
<int:channel id="priorityChannel">
  <int:priority-queue capacity="50"/>
</int:channel>
```

比较器可以按照如下方式注入：

```java
<int:channel id="priorityChannel" datatype="com.example.result">
  <int:priority-queue comparator="resultComparator" capacity="50"/>
</int:channel>
```

## 会合通道

通常，我们希望有一个确认消息确实到达端点的回执。`rendezvousChannel`接口是队列通道的一个子类，用于此目的。生产者和消费者以阻塞模式工作。一旦生产者在通道上发送了一条消息，它就会被阻塞，直到那条消息被消费。同样，消费者在队列中到达一条消息之前也会被阻塞。它可以按照以下方式配置：

```java
<int:channel id="rendezvousChannel"/>
  <int:rendezvous-queue/>
</int:channel>
```

`RendezvousChannel`接口实现了一个零容量队列，这意味着在任何给定时刻，队列中只能存在一个消息。难怪没有容量元素。

## 直接通道

直接通道是 Spring Integration 默认使用的通道类型。

### 提示

当使用没有任何子元素的`<channel/>`元素时，它会创建一个`DirectChannel`实例（一个`SubscribableChannel`）处理器。

多个端点可以订阅直接通道的消息处理器；无论何时生产者将一条消息放在通道上，它都会被交付给订阅端点的唯一一个消息处理器。引入多个订阅者，限制将消息交付给唯一一个处理器，带来了新挑战——如何以及哪个处理器将被选择，如果处理器无法处理消息会发生什么？这就是负载均衡器和故障转移进入情景的地方。可以在该通道上定义一个负载均衡器，采用轮询交付策略：

```java
<int:channel id="newQuestions">
  <dispatcher failover="false" load-balancer="round-robin"/>
</int:channel>
```

这将按轮询方式将消息交付给订阅者。这是 Spring 预定义的唯一策略，但可以使用`interface`定义自定义策略：

```java
public interface LoadBalancingStrategy {
  public Iterator<MessageHandler> getHandlerIterator(
  Message<?> message, List<MessageHandler> handlers);
}
```

以下是一个引入自定义负载均衡器的示例：

```java
<int:channel id="lbChannel">
  <int:dispatcher load-balancer-ref="customLb"/>
</int:channel>

<bean id="customLb" class="com.chandan.CustomLoadBalancingImpl"/>
```

### 提示

**下载示例代码**

您可以在[`www.packtpub.com`](http://www.packtpub.com)下载您购买的所有 Packt 书籍的示例代码文件。如果您在其他地方购买了这本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)注册，以便将文件直接通过电子邮件发送给您。代码也可以从[`github.com/cpandey05/siessentials`](https://github.com/cpandey05/siessentials)拉取。

故障转移（Failover）是一个布尔值。如果将其设置为 true，那么如果第一个处理程序无法处理消息，则将尝试所有后续的处理程序。即使其中一个处理程序成功处理了消息，Spring Integration 也不会报告错误。只有当所有处理程序都失败时，它才会抛出异常。

### 提示

故障转移能力在实现事务传播或回退机制时非常有用。例如，如果数据库服务器失败，尝试在下一个处理程序中使用另一个后端服务器。

## 执行器通道

`ExecutorChannel`接口是一个点对点的消息通道。这非常类似于直接通道，不同之处在于可以使用自定义执行器来分派消息。让我们来看看配置：

```java
<int:channel id="results">
<int:dispatcher task-executor="resultExecutor"/></int:channel>
// define the executor
<bean id=" resultExecutor " class="com.example.ResultExecutor"/>
```

`com.example.ResultExecutor`接口是`java.util.concurrent.Executor`的一个实现。

因为生产者线程将消息传递给执行器实例并退却——消息的消费在执行器线程中处理，所以生产者和消费者之间无法建立事务链接。

就像直接通道一样，可以设置负载均衡策略和故障转移。默认值是启用故障转移的轮询策略：

```java
<int:channel id="results">
<int:dispatcher load-balancer="none" failover="false"
  taskexecutor="resultsExecutor"/>
</int:channel>
```

## 作用域通道

```java
thread scope:
```

```java
<int:channel id="threadScopeChannel" scope="thread">
  <int:queue />
</int:channel>
```

也可以定义自定义作用域，如下：

```java
<bean class="org.springframework.beans.factory.config.CustomScopeConfigurer">
  <property name="scopes">
    <map>
      <entry key="thread" value="org.springframework.context.support.SimpleThreadScope" />
    </map>
  </property>
</bean>
```

这是一个线程作用域通道的示例。如果我们观察到条目，为作用域定义了一个键值对。对于线程来说，键值对是`org.springframework.context.support.SimpleThreadScope`。它可以是任何 Spring 定义的或用户定义的作用域。

### 注意

以下是一些 Spring 实现的其它作用域：

+   `org.springframework.web.context.request.SessionScope`

+   `org.springframework.web.context.support.ServletContextScope`

+   `org.springframework.web.context.request.RequestScope`

+   `org.springframework.web.portlet.context.PortletContextScope`

## 数据类型通道

通道可以限制只接受具有特定类型有效负载的消息，例如数字、字符串或其他自定义类型。代码如下：

```java
<int:channel id="examMarksChannel" datatype="java.lang.Number"/>
```

也可以提供多种类型，如下：

```java
<int:channel id="stringOrNumberChannel" datatype="java.lang.String,java.lang.Number"/>
```

如果消息以除了前面代码中给出的格式以外的格式到达会发生什么？默认情况下，将抛出异常。然而，如果用例需要，我们可以定义转换器，尝试将传入的消息转换为可接受的格式。一个典型的用例是将字符串转换为整数。为了实现这一点，需要定义一个名为`integrationConversionService`的 bean，它是 Spring 的转换服务的实例，如下所示：

```java
public static class StringToIntegerConverter implements Converter<String, Integer> {
  public Integer convert(String source) {
    return Integer.parseInt(source);
  }
}
<int:converter ref="strToInt"/>

<bean id="strToInt" class="com.chandan.StringToIntegerConverter"/>
```

当解析`converter`元素时，如果尚未定义，它将按需创建`integrationConversionService` bean。有了这个转换器，如果一个字符串消息到达定义为整数的通道，将尝试将其转换为整数。

# 通道上的错误处理

Spring Integration 支持同步以及异步消息处理。在同步处理的情况下，根据返回值或通过捕获抛出的异常来处理错误场景相对容易；对于异步处理，事情会更加复杂。Spring 提供了诸如过滤器和中继器之类的组件，可以用来验证消息的有效性并根据那个采取行动。如果它无效，消息可以被路由到无效通道或重试通道。除此之外，Spring 提供了一个全局错误通道以及定义自定义错误通道的能力。以下几点涵盖了适当的错误通道：

+   需要定义一个错误通道。这可以通过以下方式完成：

    ```java
    <int:channel id="invalidMarksErrorChannel">
      <int:queue capacity="500"/>
    </int:channel>
    ```

+   需要添加一个名为`errorChannel`的头部到消息中。这是处理失败时`ErrorMessage`应该路由到的通道的名称。

+   如果消息处理失败，`ErrorMessage`将被发送到由头部`errorChannel`指定的通道。

+   如果消息不包含`errorChanel`头部，`ErrorMessage`将被路由到由 Spring Integration 定义的全局错误通道，即`errorChannel`。这是一个发布-订阅通道：

    ```java
    <int:gateway default-request-channel="questionChannel" service-interface="com.chandan.processQuestion" 
      error-channel="errorChannel"/>
    ```

# 持久化和恢复通道

我们讨论了各种各样的通道，但如果你注意到了，这些都是内存中的。系统崩溃怎么办？没有人想丢失数据。这就是持久`QueueChannel`发挥作用的地方——消息将被备份在由数据源定义的数据库中。如果系统崩溃，然后在恢复时，它将拉取数据库中的所有消息并将它们排队等待处理。这是使用 Spring 中的`MessageGroupStore`实现的。让我们快速看一下配置：

```java
<int:channel id="resultPersistenceChannel">
  <int:queue message-store="messageStore"/>
</int:channel>

<int-jdbc:message-store id="messageStore" data-source="someDataSource"/>
```

在此，消息存储被映射到由`someDataSource`定义的数据库。当消息到达时，现在将首先添加到`MessageStore`中。成功处理后，将从那里删除。

一旦我们谈论数据库，事务就会进入视野。那么如果轮询器配置了事务会怎样呢？在这种情况下，如果消息处理失败，事务将被回滚，消息将不会从队列中删除。

### 注意

如果支持事务行为，消息将在成功处理后从队列中删除。如果某些消息反复失败，随着时间的推移，队列中可能会积累陈旧的消息。必须仔细考虑这种消息的清理策略。

# 通道拦截器

拦截器模式可用于对从通道发送或接收的消息应用业务规则和验证。以下四种拦截器可用：

```java
public interface ChannelInterceptor {
  Message<?> preSend(Message<?> message, MessageChannel channel);
  void postSend(Message<?> message, MessageChannel channel, boolean sent);
  boolean preReceive(MessageChannel channel);
  Message<?> postReceive(Message<?> message, MessageChannel channel);
}
```

以下是由`ChannelInterceptor`接口暴露的方法：

+   `preSend`: 这是在消息发送之前调用的。如果消息被阻止发送，应返回 null 值。

+   `postSend`: 在尝试发送消息之后调用。它表示消息是否成功发送。这可以用于审计目的。

+   `preReceive`: 仅当通道是轮询的时适用，当组件对通道调用`receive()`时调用，但在实际从该通道读取消息之前。它允许实现者决定通道是否可以向调用者返回消息。

+   `postReceive`: 这与`preReceive`类似，仅适用于轮询通道。在从通道读取消息但在将其返回给调用`receive()`的组件之后调用。如果返回 null 值，则没有接收消息。这允许实现者控制轮询器实际接收了什么（如果有的话）。

# 总结

本章内容相对较长，我们讨论了消息通道模式、不同类型的通道以及 Spring 提供的默认通道实现。我们还介绍了负载均衡、故障转移、在消息通道上的错误处理、消息持久化以及添加拦截器。所有这些概念都是构建可靠和可扩展解决方案的核心，我们将在接下来的章节中看到其实际实现，届时我们将讨论 Spring Integration 组件，如服务激活器、网关、延迟器等，这些组件用于处理消息。


# 第三章：消息处理

在第一章，*入门 *，我们讨论了企业集成需求是为了解决异构系统之间互操作通信的问题：它们将如何共享数据，它们将如何理解其他系统的数据，如何处理跨应用程序的交叉问题等等。在第二章中，我们讨论了一个方面，即系统将如何交换数据。通道为数据提供了一个逻辑单位，可以将其投放给其他感兴趣的应用程序。然而，它引入了下一组挑战：如果数据格式其他模块无法理解，或者消息生成与消息消费的速率不同怎么办？让我们以一个例子来看；需要从互联网获取 RSS 源并将其放入数据库以进行报告，以及在邮件系统中发送有关新条目可用性的邮件。它会带来什么挑战？

+   RSS 源是 XML 格式的，而数据库和邮件需要转换成 Java 实体和 Java `MailMessage`格式（假设使用 JPA 和 java 邮件）。这意味着 XML 负载需要转换为下一组端点期望的格式。

+   发送邮件时可能会出现延迟；因此，淹没邮件服务器可能会导致消息丢失，表明需要节流。

+   在消息可以被交给数据库之前，需要增加一些审计信息，如时间戳、登录用户等。

+   可能存在一些无效或不完整的 XML 负载。我们希望丢弃这些负载并重新尝试！

+   邮件服务器可能在源到达时不可用——那时该怎么办？

这些点提供了一个快速了解在两个系统尝试通信时需要照顾到的几个方面。肯定不希望用这么多重逻辑来负载系统，并引入它们之间的紧密耦合。那么，谁来照顾所有这些方面呢？让我们欢迎消息端点。在本章中，我们将介绍以下主题：

+   消息端点

+   网关

+   服务激活器

+   延迟器

+   事务

# 消息端点

在最简单的类比中，**消息端点**是促进两个系统之间交互的启用器——无论是消息的转换、节流、中间业务处理，还是消息成功且无缝地处理所需的任何其他任务。为了满足不同的需求，提供了不同类型的消息端点，例如，*增强器*、*延迟器*、*服务激活器*等。然而，在深入讨论每个具体细节之前，让我们讨论一下端点的广泛分类：

+   **接收器或发送器**：端点可以从信道中接收消息，或者将消息放入信道进行进一步处理。

+   **轮询端点或事件驱动端点**：端点可以从信道中拉取消息，或者可以订阅它。每当有消息可用时，注册的回调方法就会被调用。

+   **单向或双向端点**：单向端点发送或接收消息，但不期望或接收任何确认。Spring Integration 为这类交互提供了信道适配器。双向适配器可以发送、接收和确认消息。Spring Integration 提供了与同步双向通信相同的网关。

+   **入站或出站端点**：出站端点与社交网络、邮件服务器、企业 JMS 等外部系统交互，而入站端点则监听来自外部实体（如邮件连接器、FTP 连接器等）的事件。

Spring Integration 为这些类型提供了所有实现的；让我们探索它们。

# 网关

总是希望实现抽象和松耦合。**消息网关**是一种机制，用于发布可以被系统使用而不暴露底层消息实现的合同。例如，邮件子系统的网关可以暴露发送和接收邮件的方法。内部实现可以使用原始 Java 邮件 API，或可以是 Spring Integration 的适配器，或可能是自定义实现。只要合同不改变，实现可以很容易地切换或增强，而不会影响其他模块。它是更一般的*网关*模式的一种实现。网关可以分为两种类型：*同步*和*异步*。

## 同步网关

让我们快速看看在 Spring Integration 中一个网关的声明看起来像什么，然后再进一步解析以建立我们的理解：

```java
<int:gateway id="feedService" 
  service-interface="com.cpandey.siexample.service.FeedService" 
  default-request-channel="requestChannel" 
  default-reply-channel="replyChannel"/>
```

这段基本代码定义了 Spring 中的一个网关。让我们理解一下前面的声明：

+   `int:gateway`：这是 Spring 框架的网关命名空间。

+   `service-interface`：这是一个由网关发布的接口合同。

+   `default-request-channel`：这是网关放置消息进行处理的信道。

+   `default-reply-channel`：这是网关期望回复的信道。

接口是一个简单的 Java 接口声明：

```java
public interface FeedService {
  FeedEntitycreateFeed(FeedEntity feed);
  List<FeedEntity>readAllFeed();
}
```

我们定义了一个接口，然后定义了通过网关发送和读取消息的通道——但组件用来处理消息并确认它的实现类在哪里？在这里，涉及到一些 Spring Integration 的魔法——当解析这个 XML 时，框架的`GatewayProxyFactoryBean`类会创建这个接口的代理。如果有对声明的网关的服务请求，代理会将消息转发到`default-request-channel`，并会阻塞调用到`default-reply-channel`上有确认可用。前面的声明可以进一步扩展，以每个网关方法调用的通道为单位：

```java
<int:gateway id="feedService" 
  service-interface="com.cpandey.siexample.service.FeedService" 
  <int:method name="createFeed" 
    request-channel="createFeedRequestChannel"/>
  <int:method name="readAllFeed" 
    request-channel="readFeedRequestChannel"/>
</int:gateway>
```

现在当调用`createFeed`方法时，消息将被放入`createFeedRequestChannel`，而对于网关的`readAllFeed`方法，消息将被转发到`readFeedRequestChannel`。等一下——`default-reply-channel`在哪里？回复通道是一个可选参数，如果没有声明，网关会创建一个匿名的点对点回复通道，并将其添加到消息头中，名为`replyChannel`。如果我们需要一个发布-订阅通道，多个端点可以监听，显式声明将会有所帮助。

我们可以很容易地利用 Spring Integration 的注解支持，而不是使用 XML 声明：

```java
public interface FeedService{
  @Gateway(requestChannel="createFeedRequestChannel")
    FeedEntitycreateFeed(FeedEntity feed);
  @Gateway(requestChannel="readFeedRequestChannel")
    List<FeedEntity>readAllFeed();
}
```

## 异步网关

异步网关不期望确认。在将消息放入请求通道后，它们会在回复通道上阻塞等待回复的情况下，转而进行其他处理。Java 语言的`java.util.concurrent.Future`类提供了一种实现这种行为的方法；我们可以定义一个返回`Future`值的网关服务。让我们修改`FeedService`：

```java
public interface FeedService {
  Future<FeedEntity>createFeed(FeedEntity feed);
  Future<List<FeedEntity>>readAllFeed();
}
```

其他一切保持不变，所有的 XML 声明都保持一样。当返回类型更改为`Future`时，Spring 框架的`GatewayProxyFactoryBean`类通过利用`AsyncTaskExecutor`来处理切换到异步模式。

# 服务激活器

**服务激活器**是最简单且最实用的端点之一——一个普通的 Java 类，其方法可以被调用在通道上接收的消息。服务激活器可以选择终止消息处理，或者将其传递到下一个通道进行进一步处理。让我们看一下以下的示例。我们希望在将消息传递到下一个通道之前进行一些验证或业务逻辑。我们可以定义一个 Java 类，并按照如下方式注解它：

```java
@MessageEndpoint
public class PrintFeed {
  @ServiceActivator
  public String upperCase(String input) {
    //Do some business processing before passing the message
    return "Processed Message";
  }
}
```

在我们的 XML 中，我们可以将类附加到一个通道上，以便处理其中的每一个消息：

```java
<int:service-activator input-channel="printFeedChannel" ref="printFeed" output-channel="printFeedChannel" />
```

让我们快速浏览一下前面声明中使用的元素：

+   `@MessageEndpoint`：这个注解告诉 Spring 将一个类作为特定的 Spring bean——一个消息端点。由于我们用`MessageEndpoint`注解了这个调用，所以在 XML 中不需要声明这个 bean。它将在 Spring 的组件扫描中被发现。

+   `@ServiceActivator`：这个注解将一个应该在消息到达通道时调用的方法映射起来。这个消息作为一个参数传递。

+   `int:service-activator`：这是声明 Spring 端点类型的 XML 命名空间。

+   `input-channel`：这是服务激活器将要读取消息的通道。

+   `output-channel`：这是激活器将要倾倒处理过的消息的通道。

+   `ref`：这是执行处理的 bean 的引用。

前面的示例限制了一个类中的单个方法作为`@ServiceActivator`。然而，如果我们想要委派到一个明确的方法——也许根据负载？我们在以下代码中定义服务激活器的方法元素：

```java
<int:service-activator ref="feedDaoService"
  method="printFeed" input-channel="printAllFeedChannel"/>

<int:service-activator ref="feedService" method="readFeed" input-channel="printAllFeedChannel"/>
```

在这两个声明中，服务激活器的引用是相同的，也就是说，作为服务的类是`feedDaoService`，但在不同的场景中调用其不同的方法。

如我们之前提到的，输出通道是可选的。如果方法返回类型是 void，那么它表示消息流已经终止，Spring Integration 对此没有问题。然而，如果消息类型不为 null，输出通道也省略了怎么办？Spring Integration 将尝试一个后备机制——它将尝试在消息中查找名为`replyChannel`的头部。如果`replyChannel`头部的值是`MessageChannel`类型，那么消息将被发送到那个通道。但如果它是一个字符串，那么它将尝试查找具有该名称的通道。如果两者都失败，它将抛出一个`DestinationResolutionException`异常。

服务激活器可以处理哪种类型的消息？方法参数可以是`Message`类型或 Java `Object`类型。如果是`Message`，那么我们可以读取载荷并对其进行处理——但这引入了对 Spring `Message`类型的依赖。一个更好的方法是在前一个示例中声明 Java 类型。Spring Integration 将负责提取载荷并将其转换为声明的对象类型，然后调用服务激活器上的方法。如果类型转换失败，将抛出异常。同样，方法返回的数据将被包裹在一个`Message`对象中，并传递到下一个通道。

有没有没有参数的激活方法呢？有的！这在只关心是否执行了某个操作的场景中非常有用，例如，或许用于审计或报告目的。

# 延迟者

正如我们在介绍部分已经讨论过的，消息的生产率和消费率可能会有所不同——如果消费者变慢了怎么办？由于涉及到外部系统，我们可能无法控制生产消息的速率。这时就需要使用延时器。**延时器**是一个简单的端点，在消息被传递到下一个端点之前引入一个延迟。最值得注意的是，原始发送者既不会被阻塞也不会被减慢；而是，延时器将从通道中选择一个消息，并使用`org.springframework.scheduling.TaskScheduler`实例来安排其在配置间隔后发送到输出通道。让我们写一个简单的延时器：

```java
<int:delayer id="feedDelayer" 
  input-channel="feedInput"
  default-delay="10000" 
  output-channel="feedOutput"/>
```

这个简单的配置将会延迟输入通道向输出通道发送消息 10 秒。

如果我们想延迟每个消息以不同的时间间隔——比如说根据负载大小我们想增加或减少延迟时间，`expression`属性就派上用场了。之前的例子可以修改如下：

```java
<int:delayer id="feedDelayer" 
  input-channel="feedInput"
  default-delay="10000"
  output-channel="feedOutput"
  expression="headers['DELAY_MESSAGE_BY']"/>
```

```java
`int:delayer`: This is the Spring Integration namespace support for the delayer`input-channel`: This is the channel from which messages have to be delayed`default-delay`: This is the default delay duration in milliseconds`output-channel`: This is the channel where messages should be dropped after the delay is over`expression`: This is the expression that is evaluated to get the delay interval for each of the messages based on a set header value
```

延时器通过一定的间隔来延迟消息——如果系统在还有尚未在输出通道上交付的延迟消息时宕机怎么办？我们可以利用`MessageStore`，特别是持久性`MessageStore`接口，如`JdbcMessageStore`。如果使用它，那么系统一旦宕机，所有消息都会被立即持久化。当系统恢复时，所有延迟间隔已到的消息都将立即在输出通道上交付。

# 事务

我们一直在讨论消息端点如何使不同子系统之间能够进行通信。这引发了一个非常关键的问题——那么关于事务呢？它们如何在链上处理？Spring Integration 在事务方面提供了哪些功能？

Spring Integration 本身并不提供对事务的额外支持；相反，它是建立在 Spring 提供的事务支持的基础之上。它只是提供了一些可以用来插入事务行为的钩子。给服务激活器或网关注解上事务注解将支持消息流的事务边界。假设一个用户流程在事务性传播的上下文中启动，并且链中的所有 Spring Integration 组件都注解为事务性的，那么链中任何阶段的失败都将导致回滚。然而，这只有在事务边界没有被破坏的情况下才会发生——简单来说，一切都在一个线程中进行。单线程执行可能会断裂，例如，使用任务执行器创建新线程用例，持有消息的聚合器，以及可能发生超时。以下是一个快速示例，使轮询器具有事务性：

```java
<int-jpa:inbound-channel-adapter 
  channel="readFeedInfo" 
  entity-manager="entityManager"
  auto-startup="true" 
  jpa-query="select f from FeedDetailsf" 
  <int:poller fixed-rate="2000" >
    <int:transactional propagation="REQUIRED" 
      transaction-manager="transactionManager"/> 
  </int:poller>
</int-jpa:inbound-channel-adapter>
```

在这里，`"entity-manager"`、`"transaction-manager"` 等都是标准的 Spring 组件——只是这里使用了来自 Spring Integration 的命名空间，比如 `int-jpa` 和 `int:transactional`，来将它们集成进来。目前，适配器对我们来说并不重要；我们将在后续章节中涵盖所有其他的标签。

那么，有没有一种用例，进程没有在事务中启动，但后来我们想在子系统中引入事务呢？例如，一个批处理作业或轮询器，它在通道上轮询并选择一个文件上传到 FTP 服务器。这里没有事务的传播，但我们希望使这一部分具有事务性，以便在失败时可以重试。Spring Integration 为轮询器提供了事务支持，可以帮助启动事务，以便在轮询器之后的进程可以作为一个单一的工作单元来处理！下面是一个快速示例：

```java
<int:poller max-messages-per-poll="1" fixed-rate="1000"> 
  <int:transactional transaction-manager="transactionManager"
    isolation="DEFAULT"
    propagation="REQUIRED"
    read-only="true"
    timeout="1000"/>
</poller>
```

总结一下，Spring Integration 整合了 Spring 事务支持，并且凭借一点直觉和创造力，它甚至可以扩展到本质上非事务性的系统！

# 总结

在本章中，我们理解了为什么需要消息端点的原因，并发现了一些 Spring Integration 提供的端点。我们介绍了网关如何抽象底层消息实现，使开发者的工作更加简单，服务激活器如何在系统中对消息进行中间处理，以及延时器如何用来调节消息处理速率以匹配生产者和消费者的速度！我们简要提到了事务支持——我们只讨论它是因为它不提供任何新的实现，并且依赖于 Spring 框架的事务支持。

在下一章中，我们将更深入地探讨一个最重要的端点——消息转换器。


# 第四章：消息转换器

上一章的启示是消息端点使两个异构组件之间的握手变得透明和无缝。在本章中，我们将深入研究集成中的一个重要问题——消息的转换，以便它们可以在链中被消费。我们将介绍：

+   消息转换器

+   处理 XML 有效载荷

+   丰富器

+   索赔检查

同一组数据可以被不同的系统在不同的上下文中查看，例如，员工记录被报告系统和财务系统使用。然而，对象的使用将不同。报告系统只是丢弃员工记录——所以即使它以单个字符串的形式获取也没关系。另一方面，工资系统可能需要发送邮件通知、根据州和国家计算税款，以及执行其他功能，这些功能需要员工数据以 POJO 的形式呈现，信息在单独的字段中，例如，姓名、州、国家、电子邮件等。同样，可能存在需要将原始消息中添加附加信息的情况，可能需要进行加密/解密或转换为某种专有格式——这些就是消息转换器发挥作用的场景！

# 引入消息转换器

消息转换器是名为**消息转换器**的企业集成模式（**EIP**）的实现，该模式为**企业集成模式**（**EIP**），它处理端点之间的数据格式对等。这是一种优雅的设计，可以解耦消息生产者和消息消费者——它们都不需要知道对方期望的格式。这几乎与核心 Java 设计原则中的适配器模式一样，它充当生产者和消费者之间的启用器。让我们举一个更通用的例子，我们经常在 Windows 和 Linux 之间传输文件，尽管这两个系统所需格式不同，但底层应用程序负责从一种格式转换到另一种格式。

Spring Integration 提供了许多开箱即用的转换器，同时保留了定义和扩展新转换器的灵活性。它为最常用的消息交换格式提供了广泛支持，如 XML、JSON、集合等。其中，总的来说，当涉及到跨语言和跨平台通信时，XML 是使用最广泛的语言。让我们来探讨 Spring Integration 对 XML 的支持，然后再探索消息转换的其他方面。

# 处理 XML 有效载荷

两个不同的系统可能同意通过 XML 格式进行交互。这意味着每当有 outgoing 通信时，系统的数据结构需要转换为 XML；而在 incoming 消息的情况下，它需要转换为系统能理解的数据结构。我们怎么做到这一点呢？Spring 通过其 **OXM** （**对象到 XML**）框架提供了处理 XML 的第一级支持。通过相应的类—`org.springframework.oxm.Marshaller` 和 `org.springframework.oxm.Unmarshaller` 进行 marshalling 和 unmarshalling。**Marshaller** 将一个对象转换为 XML 流，而 **unmarshaller** 将 XML 流转换为对象。Spring 的对象/XML 映射支持提供了几个实现，支持使用 JAXB、Castor 和 JiBX 等进行 marshalling 和 unmarshalling。Spring Integration 进一步抽象了这一点，并提供了许多开箱即用的组件，帮助处理 XML 有效载荷。其中一些是 *marshalling transformer*, *unmarshalling transformer*, 和 *XPath transformer*。还有像 Xslt transformer、XPath 分割器和 XPath 路由器等，但我们只覆盖最常用的几个。

## marshalling transformer

用于将对象图转换为 XML 格式的 marshalling transformer。可以提供一个可选的结果类型，可以是用户定义的类型，或者是 Spring 内置的两种类型之一：`javax.xml.transform.dom.DOMResult` 或 `org.springframework.xml.transform.StringResult`。

以下是一个 marshalling transformer 的示例：

```java
<int-xml:marshalling-transformer 
  input-channel="feedsMessageChannel" 
  output-channel="feedXMLChannel" 
  marshaller="marshaller" 
  result-type="StringResult" />
```

这里使用的不同元素的说明如下：

+   `int-xml:marshalling-transformer`：这是由 Spring Integration 提供的命名空间支持

+   `input-channel`：这是从中读取消息的通道

+   `output-channel`：这是 transformed messages 将被丢弃的通道

+   `marshaller`：这是用于 marshalling 的 marshaller 实例

+   `result-type`：这是结果应该被 marshalled 的类型

需要一个有效的 marshaller 引用，例如：

```java
<bean id="marshaller" 
  class="org.springframework.oxm.castor.CastorMarshaller"/>
```

这个示例使用了一种 Spring 内置类型，`org.springframework.xml.transform.StringResult` 作为结果类型。如果未指定 `result-type`，则使用默认的 `DOMResult`。这里也可以使用自定义结果类型：

```java
<int-xml:marshalling-transformer 
  input-channel="feedsMessageChannel" 
  output-channel="feedXMLChannel" 
  marshaller="marshaller" 
  result-factory="feedsXMLFactory"/>
```

这里，`feedsXMLFactory` 指的是一个类，它实现了 `org.springframework.integration.xml.result.ResultFactor` 并重写了 `createResult` 方法：

```java
public class FeedsXMLFactory implements ResultFactory {
  public Result createResult(Object payload) {
  //Do some stuff and return a type which implements
  //javax.xml.transform.result
  return //instance of javax.xml.transform.Result.
  }
}
```

## unmarshalling transformer

几乎所有元素都与前面提到的 marshaller 相同，除了 `unmarshaller` 元素，它应该指向 Spring 支持的有效 unmarshaller 定义。

## XPath 转换器

Spring 集成中的 `xpath-transformer` 组件可以用 XPath 表达式来解析 XML：

```java
<int-xml:xpath-transformer input-channel="feedsReadChannel"
  output-channel="feedTransformedChannel"
  xpath-expression="/feeds/@category" />
```

可以使用 `xpath-expression` 标签给出要评估的 XPath 表达式。当 XML 有效载荷到达输入通道时，转换器解析 XPATH 值并将结果放入输出通道。

默认情况下，解析的值被转换为一个带有字符串负载的消息，但如果需要，可以进行简单的转换。Spring 支持以下隐式转换：`BOOLEAN`、`DOM_OBJECT_MODEL`、`NODE`、`NODESET`、`NUMBER`和`STRING`。这些都在`javax.xml.xpath.XPathConstants`中定义，如下所示：

```java
<int-xml:xpath-transformer input-channel="feedsReadChannel" 
  xpath-expression="/feeds/@category"
  evaluation-type=" STRING_RESULT" 
  output-channel=" feedTransformedChannel "/>
```

`evaluation-type`标签用于引入所需的转换。

# 验证 XML 消息

当我们讨论 XML 转换时，提及 XML 负载的验证方面是相关的。预验证 XML 将使系统免于进入错误状态，并且可以在源头采取行动。Spring Integration 通过过滤器提供 XML 验证的支持：

```java
<int-xml:validating-filter 
  id="feedXMLValidator" 
  input-channel="feedsReadChannel" 
  output-channel="feedsWriteChannel" 
  discard-channel="invalidFeedReads" 
  schema-location="classpath:xsd/feeds.xsd" />
```

`schema-location`元素定义了用于验证的 XSD。这是可选的，如果没有这样做，将其设置为默认的`xml-schema`，内部转换为`org.springframework.xml.validation.XmlValidatorFactory#SCHEMA_W3C_XML`。

我们讨论了很多内置转换器，主要处理 XML 负载。除了这些，Spring Integration 为最常见的转换提供了许多开箱即用的转换器，例如：

+   `object-to-string-transformer`

+   `payload-serializing-transformer`

+   `payload-deserializing-transformer`

+   `object-to-map-transformer`

+   `map-to-object-transformer`

+   `json-to-object-transformer`

+   `object-to-json-transformer`等

详细介绍每一个超出了本书的范围，但概念与前面提到的相同。

# 超出默认转换器

Spring 并没有限制我们使用框架提供的转换器，我们可以定义自己的转换器，这是相当直接的。我们只需要定义一个 Java 类，它接受特定输入类型，将其转换为期望的格式并将其放入输出通道。让我们举一个例子，我们想要将我们的 feed 转换为可以写入数据库的格式；我们可以定义一个类，它接受类型为`com.sun.syndication.feed.synd.SyndEntry`的*Message*负载并将其转换为`com.cpandey.siexample.pojo.SoFeed`，这是一个 JPA 实体：

```java
import com.cpandey.siexample.pojo.SoFeed;
import com.sun.syndication.feed.synd.SyndEntry;
public class SoFeedDbTransformer {
  publicSoFeedtransformFeed(Message<SyndEntry> message){
    SyndEntry entry = message.getPayload();
    SoFeed soFeed=new SoFeed();
    soFeed.setTitle(entry.getTitle());
    soFeed.setDescription(entry.getDescription().getValue());
    soFeed.setCategories(entry.getCategories());
    soFeed.setLink(entry.getLink());
    soFeed.setAuthor(entry.getAuthor());
    //For DB return soFeed
    returnsoFeed;
  }
```

转换器可以使用以下代码声明：

```java
<int:transformer ref="feedDbTransformerBean" 
  input-channel="filteredFeedChannel"
  method="transformFeed" 
  output-channel="jdbcChannel"/>
```

```java
`int:transformer`: This provides the XML namespace supported by Spring Integration`ref`: This is used to provide a reference of bean definition, which will act as the transformer`input-channel`: This is the channel from which messages will be picked up by the transformer`output-channel`: This is the channel where messages will be dropped after completing required transformations`method`: This is the method of the class that will have the transformation logic
```

让我们定义`ref`标签所引用的 bean：

```java
<bean id="feedDbTransformerBean" class="com.cpandey.siexample.transformer.SoFeedDbTransformer" />
```

如前所述，这个类有转换所需的方法。这个 bean 可以在转换器之间使用，每个方法可以有独立的转换逻辑。

# 内容丰富器

在启用异构系统之间的交互时，可能需要向消息添加附加信息，以便它能够被下一组消费者成功处理。让我们举一个例子，在一个批处理环境中，可能需要向传入任务附加优先级信息。对于放在文件服务器上供外部消费的消息—应添加一个时间戳，指示文件将被保留的最大时间。可能存在许多这样的场景，传入的消息不完整，需要由下一个端点处理。内容增强器是一种特殊的转换器，可以为消息附加附加信息。在 Spring Integration 的上下文中，消息由两部分组成—头部和消息载荷。Spring Integration 暴露了一种丰富这些组件中任何一个的方法。

## 头部增强器

**头部**在 Spring Integration 中是`MessageHeaders`类的实例，该类又扩展了`Map<String,?>`。头部不过是键值对，其目的是提供关于消息的元数据。添加一个附加的头部是直接的。让我们举一个例子，无论何时我们的系统中的饲料通过 XML 验证，我们将添加一个常数，指示饲料已验证：

```java
<int:header-enricher input-channel="validatedFeedsChannel" 
  output-channel="nextChannelForProcess">
  <int:header name="validated" value="true"/>
</int:header-enricher>
```

```java
`int:header-enricher`: This element provides the Spring Integration XML namespace support for the header enricher`input-channel`: The header for each message on this channel will be enriched`output-channel`: Additional header messages will be dropped on this channel`int:header`: This is used to provide the key-value pair for the header name and header value
```

如果我们想添加一些动态值，比如说一个时间戳，以特定的格式呢？我们可以利用头部增强器的 bean 支持，在 bean 中定义自定义增强：

```java
<int:header-enricher input-channel="feedsInputChannel" 
  output-channel=" nextChannelForProcess "> 
  <int:header name="customtimestamp"
    method="getTimeStamp"
    ref="timeStamp"/>
</int:header-enricher>
```

这里提到的`ref`标签引用的 bean 如下：

```java
<bean id="timeStamp " class="com.cpandey.siexample.TimeStamp"/>
```

实际类的定义如下：

```java
public class TimeStamp {
  public String getTimeStamp (String payload){
    return //a custom time stamp
  }
}
```

除了一个标准的 Java Bean，我们还可以使用 Groovy 脚本来定义自定义增强器：

```java
<int:header-enricher input-channel="feedsInputChannel" 
  output-channel=" nextChannelForProcess ">
  <int:header name="customtimestamp" 
  <int-groovy:script location="="siexample 
    /TimeStampGroovyEnricher.groovy"/>
  </int:header>
</int:header-enricher>
```

还有预定义的头部元素也可以使用；最简单、最常用的是 error-channel：

```java
<int:header-enricher input-channel=" feedsInputChannel " output-channel=" nextChannelForProcess ">
  <int:error-channel ref="feedserrorchannel"/>
</int:header-enricher>
```

## 载荷增强器

**头部增强器**方便地添加元数据信息。如果消息本身不完整怎么办？让我们举一个例子，当一个饲料到达时，根据饲料类别，可能需要获取该类别的元数据，订阅该类别的用户等等。可以使用其他组件，如服务激活器和网关，但为了方便使用，Spring Integration 暴露了载荷增强器。**载荷增强器**就像网关—把消息放到一个通道上，然后期待这个消息的回复。返回的消息将是载荷增强的。例如，假设外部饲料对 Spring 有很多类别，如 Spring-mvc、Spring-boot、Spring-roo 和 Spring-data，但我们的系统只有一个类别—Spring。基于外部类别，我们可以增强载荷以使用单个类别：

```java
<int:enricher id="consolidateCategoryEnricher"
  input-channel="findFeedCatoryChannel"
  request-channel="findInternalCategoryChannel">
  <int:property name="categroy" 
    expression="payload.category"/>
  <int:property name="feedProcessed" 
    value="true" type="java.lang.String"/>
</int:enricher>
```

这里，配置元素意味着以下内容：

+   `int:enricher`：这是用作 Spring Integration 命名空间支持以增强器的。

+   `input-channel`：这是用于增强的数据读取通道。

+   `request-channel`：这是用于丰富数据的数据发送通道。

+   `int:property`：这是一种方便的设置目标有效载荷值的方法。所提到的属性必须在目标实例上“可设置”。它可以是一个**SpEL**（**Spring 表达式语言**）表达式，由`expression`表示，或者可以是一个由值表示的值。

# 索赔检查

我们讨论了头部和内容丰富器的使用——它们增加了额外信息。然而，在某些情况下，隐藏数据可能是有效的用例——最简单的是重载荷。在大多数通道可能只使用子集甚至只是传递时，移动整个消息并不是一个好主意！引入了一个*索赔检查模式*，它建议将数据存储在可访问的存储中，然后只传递指针。需要处理数据的组件可以使用指针检索它。Spring 集成提供了两个组件来实现这一点：*入站索赔检查转换器*和*出站索赔检查转换器*。入站索赔检查转换器可用于存储数据，而出站索赔检查转换器可用于检索数据。

## 入站索赔检查转换器

**入站索赔检查转换器**将消息存储在其消息存储标记中，并将其有效载荷转换为实际消息的指针，如下面的代码片段所示：

```java
<int:claim-check-in id="feedpayloadin"
  input-channel="feedInChannel"
  message-store="feedMessageStore"
  output-channel="feedOutChannel"/>
```

一旦消息存储在消息存储中，它就会生成一个 ID 进行索引，该 ID 成为该消息的索赔检查。转换后的消息是索赔检查，即新的有效载荷，并将发送到输出通道。要检索此消息，需要一个出站索赔检查转换器。

## 出站索赔检查转换器

基于索赔检查，此转换器将指针转换回原始有效载荷，并将其放回输出通道。如果我们想限制索赔一次怎么办？我们可以引入一个布尔值`remove-message`，将其值设置为 true 将在索赔后立即从消息存储中删除消息。默认值为 false。更新后的代码如下所示：

```java
<int:claim-check-out id="checkout"
  input-channel="checkoutChannel"
  message-store="testMessageStore"
  output-channel="output"
  remove-message="true"/>
```

# 总结

我们讨论了消息可以如何被丰富和转换，以便使异构系统与彼此的数据格式解耦。我们还讨论了索赔检查概念，这是转换的一个特例，可以用于性能、安全和其他非功能性方面。

在下一章中，我们将探讨 Spring Integration 提供的更多开箱即用的组件，以帮助消息流。


# 第五章．消息流

我们在上章讨论了消息转换。在转换得到处理之后，在传递到链中的下一个环节之前可能还需要执行其他任务。例如，消息可能需要进行一些分割，或者它们可能是不完整的，需要一些临时存储或排序。在本章中，我们将探讨 Spring Integration 框架为在不同组件之间无缝传递消息提供的开箱即用的功能。我们将在本章涵盖以下主题：

+   路由器

+   过滤器

+   分割器

+   聚合器

+   重新排序器

+   链式处理器

# 路由器

**路由器**是选择消息并将其根据一组预定义的规则传递到不同通道的组件。路由器从不改变消息——它们只是将消息路由/重新路由到下一个目的地。Spring Integration 提供了以下内置路由器：

+   负载类型路由器

+   头部值路由器

+   收件人列表路由器

+   XPath 路由器（XML 模块的一部分）

+   错误消息异常类型路由器

## 负载类型路由器

从前面的代码片段可以看出，根据负载类型，消息被路由到不同的通道。`java.lang.String` 类已被配置为路由到 `jmsChannel`，而 `org.springframework.messaging.Message` 已被配置为路由到 `mailChannel`。以下两个元素已使用：

+   `int:payload-type-router`：这用于为负载类型路由器提供命名空间

+   `int:mapping`：此标签用于提供 Java 对象和通道之间的映射

## 头部值路由器

路由器**不基于消息负载的类型**，而是尝试读取已经设置在负载上的头部信息：

```java
<int:header-value-router 
  input-channel="feedsChannel" 
  header-name="feedtype">
  <int:mapping value="java" channel="javachannel" />
  <int:mapping value="spring" channel="springchannel" />
</int:header-value-router>
```

```java
mapping has not been provided and hence the next channel will be javachannel, indicated by the header-name tag:
```

```java
<int:header-value-router 
  input-channel="feedsChannel" 
  header-name="javachannel"/>
```

## 收件人列表路由器

不要将收件人误认为是用户！在这里，收件人列表指的是可以接收消息的通道列表。它可以与发布-订阅通道用例进行比较，其中预定义的一组通道与路由器“订阅”：

```java
<int:recipient-list-router input-channel="feedsChannel">
  <int:recipient channel="transformFeedChannel"/>
  <int:recipient channel="auditFeedChannel"/>
</int:recipient-list-router>
```

所有在 feeds 通道上传递的消息都将同时在 `transformFeedChannel` 和 `auditFeedChannel` 上传递。使用的元素很简单：

+   `int:recipient-list-router`：这用于为收件人列表路由器提供命名空间

+   `int:recipient`：这用于提供应接收消息的通道名称

## XPath 路由器

在第四章，*消息转换器*中，我们详细讨论了处理 XML 负载的问题，并讨论了基于*XPath*的转换器的示例。XPath 路由器类似——不是基于 XPath 值转换消息，而是将其路由到其中一个通道：

```java
<int-xml:xpath-router input-channel="feedChannel">
  <int-xml:xpath-expression expression="/feed/type"/>
</int-xml:xpath-router>
```

这可以将消息发送到通道或一组通道——表达式的值将决定消息应路由到哪些通道。有一种根据表达式的值将消息路由到特定通道的方法：

```java
<int-xml:xpath-router input-channel="feedChannel">
  <int-xml:xpath-expression expression="/feed/type"/>
  <int-xml:mapping value="java" channel="channelforjava"/>
  <int-xml:mapping value="spring" channel="channelforspring"/>
</int-xml:xpath-router>
```

## 错误消息异常类型路由器

```java
invalidFeedChannel, while for a NullPointerException, it will route to npeFeedChannel:
```

```java
<int:exception-type-router 
  input-channel="feedChannel"
  default-output-channel="defaultChannel">
<int:mapping 
  exception-type="java.lang.IllegalArgumentException" 
  channel="invalidFeedChannel"/>
 <int:mapping
    exception-type="java.lang.NullPointerException"
    channel="npeFeedChannel"/>
</int:exception-type-router>
<int:channel id=" illegalFeedChannel " />
<int:channel id=" npeFeedChannel " />
```

下面是对此代码片段中使用的标签的解释：

+   `int:exception-type-router`：这为异常类型路由器提供了命名空间。

+   `default-output-channel`：如果无法为消息解决任何映射的通道，则指定消息应该被投递到的默认通道。这将在后面详细定义。

+   `int:mapping exception-type`：用于将异常映射到通道名称。

## 默认输出通道

可能存在这样的情况，路由器无法决定消息应该被投递到哪个通道——在这种情况下该怎么办？以下有两种可用选项：

+   **抛出异常**：根据用例，这可以是一个已经被映射到通道的异常，或者异常可以被抛出，在链中向上传播。

+   **定义一个默认输出通道**：正如其名称所示，这是所有无法决定通道投递的消息将被投递的通道。

例如，在前面的代码片段中，默认通道已被指定为：

```java
default-output-channel="defaultChannel"
```

如果异常无法映射到定义的列表，消息将被放入默认通道。

# 使用注解

Spring 的威力在于将简单的 Java 类转换为具体的组件，而不需要扩展或实现外部类。为了定义路由器，我们可以利用框架的`@Router`注解。我们可以在任何方法上注解`@Router`，并可以使用其引用。让我们举一个例子，我们想要根据作者来路由我们的饲料：

```java
@Component
public class AnnotatedFeedsAuthorRouter {
  @Router
  public String feedAuthor(Message<SoFeed > message) {
    SoFeed sf = message.getPayload();
    return sf.getAuthor() ;
  }
}
```

返回值是一个字符串，是作者的名字——必须存在一个同名的通道。或者，我们可以直接返回`MessageChannel`或`MessageChannel`引用的列表。

# 过滤器

消息过滤器是 Spring Integration 组件，作为拦截器并决定是否将消息传递给下一个通道/组件或丢弃它。与决定消息下一个通道的路由器不同，过滤器只做一个*布尔*决定——是否传递。在 Spring Integration 中定义消息过滤器有两种方法：

+   编写一个简单的 Java 类，并指定其方法，决定是否传递消息

+   配置它作为一个消息端点，委托给`MessageSelector`接口的实现

这可以在 XML 中配置，也可以使用注解。

## 使用 Java 类作为过滤器

让我们以使用一个简单的 Java 类作为过滤器为例——这是我们关于饲料的例子的一部分。当饲料进来时，我们尝试验证载荷是否为空——只有通过验证后才将其传递进行进一步处理：

```java
<int:filter 
  input-channel="fetchedFeedChannel" 
  output-channel="filteredFeedChannel" 
  ref="filterSoFeedBean" 
  method="filterFeed"/>
```

标签的解释尽可能简单直观：

+   `int:filter`：用于指定 Spring 框架命名空间的过滤器

+   `input-channel`：消息将从这个通道中选择

+   `output-channel`：如果它们通过过滤条件，消息将被传递到的通道：

+   `ref`：这是对作为过滤器的 Java bean 的引用：

+   `method`：这是作为过滤器的 Java bean 的方法

作为过滤器的 bean 的声明如下：

```java
<bean id="filterSoFeedBean" 
class="com.cpandey.siexample.filter.SoFeedFilter"/>
```

以下代码片段显示了一个具有消息过滤方法的实际 Java 类：

```java
public class SoFeedFilter {
public boolean filterFeed(Message<SyndEntry> message){
  SyndEntry entry = message.getPayload();
  if(entry.getDescription()!=null&&entry.getTitle()!=null){
    return true;
  }
  return false;
}
```

我们还可以决定如果有效载荷不符合过滤条件该怎么办，例如，如果有效载荷为空。在这种情况下，我们可以采取以下两个选项之一：

+   可以抛出一个异常：

+   它可以路由到特定的通道，在那里可以对其采取行动—例如，只需记录失败的 occurrence：

要抛出异常，我们可以使用以下代码片段：

```java
<int:filter 
  input-channel="fetchedFeedChannel" 
  output-channel="filteredFeedChannel" 
  ref="filterSoFeedBean" 
  method="filterFeed" 
  throw-exception-on-rejection="true"/>
```

要记录异常，我们可以使用以下代码片段：

```java
<int:filter 
  input-channel="fetchedFeedChannel" 
  output-channel="filteredFeedChannel" 
  ref="filterSoFeedBean" 
  method="filterFeed" 
  discard-channel="rejectedFeeds"/>
```

在这里，我们在直接通道上使用了一个过滤器并验证了有效载荷。如果验证成功，我们传递了消息；否则，我们通过抛出异常或记录其发生来拒绝消息。过滤器的另一个用例可能是发布-订阅通道—许多端点可以监听一个通道并过滤出他们感兴趣的消息。

我们还可以使用*注解*来定义过滤器。只需在 Java 类的某个方法上使用`@Filter`注解，Spring Integration 就会将其转换为过滤器组件—无需扩展或实现任何额外的引用：

```java
@Component
public class SoFeedFilter {
  @Filter
  //Only process feeds which have value in its title and description
  public boolean filterFeed(Message<SyndEntry> message){
    SyndEntry entry = message.getPayload();
    if(entry.getDescription()!=null&&entry.getTitle()!=null){
      return true;
    }
  return false;
}
```

XML 中的过滤器声明需要更改，无需使用`method`参数：

```java
<int:filter 
  input-channel="fetchedFeedChannel" 
  output-channel="filteredFeedChannel" 
  ref="filterSoFeedBean" />
```

## 将过滤器配置为消息端点：

定义过滤器的另一个选项是使用框架（`MessageSelector`）。Java 类需要实现此接口并重写`accept`方法。每当传递有效载荷时，都会调用`accept`方法，并返回是否传递消息或丢弃它的决定。以下代码片段使用`MessageSelector`修改了前面的示例：

```java
public class SoFeedFilter implements MessageSelector{
public boolean accept(Message<?> message) {
      …
      return true;
    }
  return false;
}
```

在此定义之后，过滤器可以如下声明和使用：

```java
<int:filter 
  input-channel="fetchedFeedChannel" 
  outputchannel="filteredFeedChannel"> 
  <bean class=" com.cpandey.siexample.filter.SoFeedFilter "/>
</int:filter>
```

由于已经声明了 bean 类，因此无需引用标签。

# 分隔符：

分隔符，顾名思义，是用来将消息分成更小的块，然后将这些块发送进行独立处理。分割的原因可能有多个—有效载荷的大小大于下一个端点可接受的尺寸，或者可以并行处理或沿链处理的消息负载部分。有一个聚合器，在聚合之前需要进行一些处理。Spring Integration 提供了一个`splitter`标签。与过滤器一样，分隔符也可以通过扩展框架接口或编写自定义的 POJO 来编写。

让我们先从更简单的一个开始，利用一个简单的 Java 类作为分隔符：

```java
<int:splitter
  ref="splitterSoFeedBean" 
  method="splitAndPublish" 
  input-channel="filteredFeedChannel" 
  output-channel="splitFeedOutputChannel" />

<bean id="splitterSoFeedBean" 
  class="com.cpandey.siexample.splitter.SoFeedSplitter"/>
```

这些元素相当直观：

+   `int:splitter`：这是用于指定过滤器 Spring 框架命名空间的：

+   `ref`: 这是用来提供作为分隔器的 bean 的引用。

+   `method`: 这是在 bean 中指定消息分隔实现的方法。

+   `input-channel`: 这是消息将被读取的通道。

+   `output-channel`: 这是消息将被写入的通道。

充当分隔器的 Java 类：

```java
public class SoFeedSplitter {
  public List<SyndCategoryImpl> plitAndPublish(Message<SyndEntry> message) {
    SyndEntry syndEntry=message.getPayload();
    List<SyndCategoryImpl> categories= syndEntry.getCategories();
    return categories;
  }
}
```

分隔器必须返回一个集合类型，然后从这个集合中一次交付每个项目到下一个端点。如果返回的值不是消息类型，那么在交付之前每个元素都将被包裹在消息类型中。让我们为这个分隔器定义一个服务激活器：

```java
<int:service-activator 
  id="splitChannelSA"
  ref="commonServiceActivator"
  method="printSplitMessage"
  input-channel="splitFeedOutputChannel"/>
```

`printSplitMessage`方法在以下代码片段中定义：

```java
public void printSplitMessage(Message<SyndCategoryImpl> message) {
  if(message!=null){
    System.out.println(message.getPayload());
  }else{
    System.out.println("Message is null");
  }

}
```

我们可以通过使用注解来避免使用`method`标签：

```java
@Splitter
public List<SyndCategoryImpl> splitAndPublish(Message<SyndEntry> message) {
    SyndEntry syndEntry=message.getPayload();
    List<SyndCategoryImpl> categories= syndEntry.getCategories();
    return categories;
  }
```

与过滤器一样，我们也可以使用框架支持来编写我们的分隔器。任何 Java 类都可以扩展`AbstractMessageSplitter`并重写`splitMessage`。之前的示例已经通过以下代码片段中的框架支持进行了修改：

```java
public class SoFeedSplitter extends AbstractMessageSplitter {
  @Override
  protected Object splitMessage(Message<?> message) {
    SyndEntry syndEntry=(SyndEntry)message.getPayload();
    List<SyndCategoryImpl> categories= syndEntry.getCategories();
    return categories;
  }
```

# 聚合器

聚合器是分隔器的对立面——它们合并多个消息并将它们呈现给下一个端点作为一个单一的消息。这是一个非常复杂的操作，所以让我们从一个真实的生活场景开始。一个新闻频道可能有许多记者可以上传文章和相关图片。可能会发生文章的文字比相关的图片更早到达——但文章只有在所有相关的图片也到达后才能发送出版。这个场景提出了很多挑战；部分文章应该存储在某个地方，应该有一种方式将传入的组件与现有的组件相关联，还应该有一种方式来识别消息的完成。聚合器就是用来处理所有这些方面的——其中一些相关概念包括`MessageStore`、`CorrelationStrategy`和`ReleaseStrategy`。让我们从一个代码示例开始，然后深入探讨这些概念的每个方面：

```java
<int:aggregator 
  input-channel="fetchedFeedChannelForAggregatior"
  output-channel="aggregatedFeedChannel"
  ref="aggregatorSoFeedBean"
  method="aggregateAndPublish"
  release-strategy="sofeedCompletionStrategyBean"
  release-strategy-method="checkCompleteness"
  correlation-strategy="soFeedCorrelationStrategyBean"
  correlation-strategy-method="groupFeedsBasedOnCategory"
  message-store="feedsMySqlStore "
  expire-groups-upon-completion="true">
  <int:poller fixed-rate="1000"></int:poller>
</int:aggregator>
```

嗯，一个相当大的声明！为什么不呢——很多东西结合在一起充当聚合器。让我们快速浏览一下所有使用的标签：

+   `int:aggregator`: 这是用来指定 Spring 框架命名空间的聚合器。

+   `input-channel`: 这是消息将被消费的通道。

+   `output-channel`: 这是一个通道，在聚合后，消息将被丢弃。

+   `ref`: 这是用来指定在消息发布时调用的 bean 的方法。

+   `method`: 这是当消息被释放时调用的方法。

+   `release-strategy`: 这是用来指定决定聚合是否完成的方法的 bean。

+   `release-strategy-method`: 这是检查消息完整性的逻辑的方法。

+   `correlation-strategy`: 这是用来指定有消息相关联的方法的 bean。

+   `correlation-strategy-method`：这个方法包含了实际的消息关联逻辑。

+   `message-store`：用于指定消息存储，消息在它们被关联并准备好发布之前暂时存储在这里。这可以是内存（默认）或持久化存储。如果配置了持久化存储，消息传递将在服务器崩溃后继续进行。

可以定义 Java 类作为聚合器，如前所述，`method`和`ref`参数决定当根据`CorrelationStrategy`聚合消息并满足`ReleaseStrategy`后释放时，应调用 bean（由`ref`引用）的哪个方法。在以下示例中，我们只是在将消息传递到链中的下一个消费者之前打印消息：

```java
public class SoFeedAggregator {
  public List<SyndEntry> aggregateAndPublish(List<SyndEntry> messages) {
    //Do some pre-processing before passing on to next channel
    return messages;
  }
}
```

让我们来详细了解一下完成聚合器的三个最重要的组件。

## 关联策略

聚合器需要对消息进行分组——但它将如何决定这些组呢？简单来说，`CorrelationStrategy`决定了如何关联消息。默认情况下，是根据名为`CORRELATION_ID`的头部。所有`CORRELATION_ID`头部值相同的消息将被放在一个括号中。另外，我们可以指定任何 Java 类及其方法来定义自定义关联策略，或者可以扩展 Spring Integration 框架的`CorrelationStrategy`接口来定义它。如果实现了`CorrelationStrategy`接口，那么应该实现`getCorrelationKey()`方法。让我们看看在 feeds 示例中的我们的关联策略：

```java
public class CorrelationStrategy {
  public Object groupFeedsBasedOnCategory(Message<?> message) {
    if(message!=null){
      SyndEntry entry = (SyndEntry)message.getPayload();
      List<SyndCategoryImpl> categories=entry.getCategories();
      if(categories!=null&&categories.size()>0){
        for (SyndCategoryImpl category: categories) {
          //for simplicity, lets consider the first category
          return category.getName();
        }
      }
    }
    return null;
  }
}
```

那么我们是如何关联我们的消息的呢？我们是根据类别名称关联 feeds 的。方法必须返回一个可用于关联消息的对象。如果返回一个用户定义的对象，它必须满足作为映射键的要求，例如定义`hashcode()`和`equals()`。返回值不能为空。

另外，如果我们希望通过扩展框架支持来实现它，那么它看起来就像这样：

```java
public class CorrelationStrategy implements CorrelationStrategy {
  public Object getCorrelationKey(Message<?> message) {
    if(message!=null){
      …
            return category.getName();
          }
        }
      }
      return null;
    }
  }
}
```

## 发布策略

我们一直根据关联策略对消息进行分组——但我们什么时候为下一个组件发布它呢？这由发布策略决定。与关联策略类似，任何 Java POJO 都可以定义发布策略，或者我们可以扩展框架支持。以下是使用 Java POJO 类的示例：

```java
public class CompletionStrategy {
  public boolean checkCompleteness(List<SyndEntry> messages) {
    if(messages!=null){
      if(messages.size()>2){
        return true;
      }
    }
    return false;
  }
}
```

消息的参数必须是集合类型，并且必须返回一个布尔值，指示是否发布累积的消息。为了简单起见，我们只是检查了来自同一类别的消息数量——如果它大于两个，我们就发布消息。

## 消息存储

直到一个聚合消息满足发布条件，聚合器需要暂时存储它们。这就是消息存储发挥作用的地方。消息存储可以分为两种类型：内存存储和持久化存储。默认是内存存储，如果使用这种存储，那么根本不需要声明这个属性。如果需要使用持久化消息存储，那么必须声明，并且将其引用给予`message-store`属性。例如，可以声明一个 mysql 消息存储并如下引用：

```java
<bean id=" feedsMySqlStore " 
  class="org.springframework.integration.jdbc.JdbcMessageStore">
  <property name="dataSource" ref="feedsSqlDataSource"/>
</bean>
```

数据源是 Spring 框架的标准 JDBC 数据源。使用持久化存储的最大优势是可恢复性——如果系统从崩溃中恢复，所有内存中的聚合消息都不会丢失。另一个优势是容量——内存是有限的，它只能容纳有限数量的消息进行聚合，但数据库可以有更大的空间。

# 重排序器

**重排序器**可用于强制对下一个子系统进行有序交付。它会持有消息，直到所有在它之前的编号消息已经被传递。例如，如果消息被编号为 1 到 10，如果编号为 8 的消息比编号为 1 到 7 的消息更早到达，它会将其保存在临时存储中，并且只有在编号为 1 到 7 的消息传递完成后才会交付。消息的`SEQUENCE_NUMBER`头由重排序器用来跟踪序列。它可以被认为是聚合器的一个特例，它基于头值持有消息但不对消息进行任何处理：

```java
<int:resequencer input-channel="fetchedFeedChannelForAggregatior" 
  output-channel="cahinedInputFeedChannel" 
  release-strategy="sofeedResCompletionStrategyBean" 
  release-strategy-method="checkCompleteness" 
  correlation-strategy="soFeedResCorrelationStrategyBean" 
  correlation-strategy-method="groupFeedsBasedOnPublishDate" 
  message-store="messageStore"> 
  <int:poller fixed-rate="1000"></int:poller>
</int:resequencer >
```

正如我们提到的，重排序器可以被认为是聚合器的一个特例——几乎所有标签的意义都相同，除了命名空间声明。

# 链接处理器

我们已经讨论了 Spring Integration 提供的许多处理器，如过滤器、转换器、服务激活器等，这些处理器可以独立地应用于消息——Spring Integration 进一步提供了一种机制来链接这些处理器。`MessageHandler`的一个特殊实现是`MessageHandlerChain`，可以配置为一个单一的消息端点。它是由其他处理器组成的链，接收到的消息简单地按照预定义的顺序委托给配置的处理器。让我们来看一个例子：

```java
<int:chain 
  input-channel="cahinedInputFeedChannel" 
  output-channel="logChannel"> 
  input-channel="cahinedInputFeedChannel" 
  output-channel="logChannel"> 
  <int:filter ref="filterSoFeedBean" 
    method="filterFeed" 
    throw-exception-on-rejection="true"/> 
  <int:header-enricher> 
    <int:header name="test" value="value"/>
  </int:header-enricher>
  <int:service-activator 
    ref="commonServiceActivator" 
    method="chainedFeed"/>
</int:chain>
```

让我们快速创建一个链并验证它。从使用一个过滤器开始，这个过滤器仅仅传递所有消息，下一步在消息中添加一个头，最后在服务激活器中打印出这些头。如果我们能在第二步确认已经添加了头，那么我们就没问题——链已执行！

# 总结

深呼吸一下…这一章内容颇长，我们讨论了 Spring Integration 框架提供的许多创新组件，比如路由器、过滤器和分割器。这些组件都有助于消息在不同端点之间的流动。在下一章中，我们将继续探索 Spring Integration 框架的这些内置功能，但重点将放在适配器上，以与外部系统进行交互，比如连接数据库、从 Twitter 获取推文、向 JMS 队列写入、与 FTP 服务器交互等等——有很多有趣的内容，请继续关注！


# 第六章：与外部系统的集成

在上一章中，我们讨论了帮助系统内部消息流转的 Spring Integration 组件。在本章中，让我们进一步拉动杠杆，看看 Spring Integration 在实际集成挑战方面有什么箱子。我们将涵盖 Spring Integration 对外部组件的支持，并详细介绍以下主题：

+   处理文件

+   FTP/FTPS 上的文件交换

+   社交集成

+   企业消息传递

+   调用和消费 HTTP 端点

+   网络服务

+   数据库集成

+   流式处理

# 处理文件

最常见且原始的通信方式之一就是通过文件。即使在数据库出现之后，文件系统仍未失去其相关性，我们经常需要处理它们——在遗留应用中，用于转储报告、共享位置等等。

那么，在 Java 中如何处理文件呢？获取文件句柄，打开一个流，对其进行操作，然后关闭它。一些琐碎的事情需要 10-15 行代码。但是，如果你忘记关闭流或者引用的文件已经被移除怎么办？代码行会随着我们处理所有角落案例而增加。Spring Integration 对文件支持非常好。它提供了适配器和网关，可以以最少的代码行处理文件读写操作。

## 先决条件

要使用前面提到的文件组件，我们需要以如下方式声明 Spring 命名空间支持和 Maven 入口：

+   命名空间支持可以通过使用以下代码片段添加：

    ```java
    xmlns:int-file 
      ="http://www.springframework.org/schema/integration/file"
    xsi:schemaLocation= 
    "http://www.springframework.org/schema/integration/file http://www.springframework.org/schema/integration/file/spring-integration-file.xsd">
    ```

+   通过使用以下代码片段添加 Maven 入口：

    ```java
    <dependency>
        <groupId>org.springframework.integration</groupId>
        <artifactId>spring-integration-file</artifactId>
        <version>${spring.integration.version}</version>
    </dependency>
    ```

我们现在可以开始编写我们的 Spring Integration 文件组件了。让我们讨论基于两种类型操作的 Spring 文件支持：读取文件和写入文件。

## 读取文件

Spring Integration 提供了一个适配器，可以从目录中读取文件，并将其作为`Message<File>`发布在通道上，供其他消费者消费。让我们看一个片段来了解它是如何配置的：

```java
<int-file:inbound-channel-adapter 
  id="fileAdapter" 
  directory="C:\Chandan\Projects\inputfolderforsi" 
  channel="filesOutputChannel" 
  prevent-duplicates="true" 
  filename-pattern="*.txt">
    <int:poller fixed-rate="1000" />
    <int-file:nio-locker/>
  </int-file:inbound-channel-adapter>
```

前面的配置足以从*目录*读取文件并将其放在指定的*通道*上。让我们看看这些元素：

+   `int-file:inbound-channel-adapter`：这是文件支持的命名空间

+   `directory`：这是要从中读取文件的目录

+   `channel`：这是应该写入文件的通道

+   `prevent-duplicates`：如果启用此选项，则在早期运行中已经拾取的文件不会再次拾取

+   `filename-pattern`：这是应拾取的文件的名字模式

+   `int:poller`：这是应该轮询文件的速度

+   `int-file:nio-locker`：如果有多个消费者，这将锁定文件，以防止同时选择相同的文件

您可能已经意识到，尽管配置简单，但很多事情都在幕后进行，例如防止重复、过滤文件、避免并发访问等。我们将详细讨论这些内容，但在那之前，让我们先看看为这个适配器幕后工作的类。

### 幕后

前一个示例中声明的适配器利用了`FileReadingMessageSource`，这是`MessageSource`的一个实现。它根据目录中的文件创建消息如下：

```java
<bean 
  id="pollableFileSource" 
  class="org.springframework.integration.file.
    FileReadingMessageSource" 
  p:directory="C:\Chandan\Projects\inputfolderforsi" />
```

在 bean 声明级别，我们可以注入过滤器、锁机制等——但由于我们使用 Spring Integration，它免去了我们在 bean 声明级别的工作。相反，我们可以使用 Spring Integration 暴露的适配器。

### 过滤器

过滤器是一个强大的概念，可以用来防止重复，根据名称模式选择文件，自定义读取的文件列表，以及在将所需内容呈现给下一个端点之前执行许多其他拦截。对于大多数常见任务，都有预定义的过滤器，但在 Spring 的精神下，我们也可以有自定义实现，并将它们注入由 Spring Integration 提供的适配器中。过滤器必须是`FileListFilter`的一个实例，默认使用的过滤器是`AcceptOnceFileListFilter`。此过滤器跟踪处理过的文件，但实现是在内存中。这意味着如果服务器在处理文件时重新启动，它将失去对已处理文件的跟踪，并将重新阅读相同的文件。为了解决这个问题，应使用`FileSystemPersistentAcceptOnceFileListFilter`的实例，通过利用`MetadataStore`实现来跟踪处理过的文件。

此外，文件名模式和`Reg Ex`过滤器可供使用，可以根据它们的名称或通过与指定的`Reg Ex`匹配来过滤文件。让我们通过一个快速示例来看看这两个过滤器的使用：

```java
<int-file:inbound-channel-adapter 
  id="filestest1"
  directory="file:${input.directory}"
  filename-pattern="testing*" />

<int-file:inbound-channel-adapter 
  id="filestest2"
  directory="file:${input.directory}"
  filename-regex="testing[0-9]+\.jpg" />
```

假设我们想要一个自定义过滤器，它可以很容易地被定义和使用。代码如下：

```java
public class CustomFilter implements FileListFilter<Feed> {
  public List< Feed > filterFiles(Feed [] feeds) {
    List< Feed > filteredList = new ArrayList< Feed >();
    // implement your filtering logic here
    return filteredList;
  }
}
```

### 防止重复

防止重复是过滤器的一个子集，用于过滤已经选择的文件。使用`prevent-duplicates`，我们可以指示适配器只查找唯一的文件。这里的唯一问题是，重复检查限于会话，因为读者不存储任何状态。如果读者重新启动，它将再次阅读所有文件——即使它们之前已经被阅读过。

### 并发访问

这是企业中具有多个消费者非常常见的用例，我们希望能够维护被消费文件的完整性。我们可以以下面这种方式使用`java.nio`锁来锁定文件，以确保它们不被并发访问：

```java
<int-file:inbound-channel-adapter 
  id="fileReader"
  directory="C:\Chandan\Projects\inputfolderforsi"  
  prevent-duplicates="true">
    <int-file:nio-locker/>
</int-file:inbound-channel-adapter>
```

这段代码并没有限制我们只能使用`java.nio.locker`。 Instead of using the `java.nio` locker, we can provide custom lockers as well:

```java
<int-file:inbound-channel-adapter 
  id="fileAdapter"
  directory="C:\Chandan\Projects\inputfolderforsi" 
  prevent-duplicates="true">
  <int-file:locker ref="customLocker"/>
</int-file:inbound-channel-adapter>
```

### 提示

解锁不是显式的。通过调用`FileLocker.unlock(File file)`来执行解锁；否则，在一段时间内会导致内存泄漏。

## 写文件

Spring Integration 提供了出站适配器，这是入站适配器的对立面。这意味着它从一个通道中消耗文件并将其写入一个目录。内部地，Spring Integration 使用`FileWritingMessageHandler`实例将消息写入文件系统，并且可以使用这个类的实现。这个类可以处理文件、字符串或字节数组有效载荷。像往常一样，没有必要使用低级类；相反，可以 spring 暴露的适配器和网关。让我们将出站适配器连接到写入文件的入站适配器通道：

```java
<int-file:outbound-channel-adapter 
  channel="filesOutputChannel" directory="C:\Chandan\Projects\outputfolderforsi" 
  delete-source-files="true"/>
```

让我们讨论每个元素代表的内容：

+   `int-file:outbound-channel-adapter`：为出站通道适配器提供文件命名空间支持

+   `channel`：这是文件将被写入作为 Spring Integration 消息的通道。

+   `directory`：这是从中选择文件的目录。

+   `delete-source-files`：如果将此设置为真，处理完文件后将会删除这些文件。

在写文件时，我们需要考虑诸如新文件的名字应该是什么，应该写入哪个目录，原始文件应该如何处理等问题。让我们快速触及这些方面。

### 命名文件

默认情况下，当文件写入目录时，文件名将被保留。然而，这可以通过提供`FileNameGenerator`实现来覆盖。这个类负责生成文件名——默认情况下`FileNameGenerator`查找与常量`FileHeaders.FILENAME`匹配的消息头。

### 目标目录

主要有三种方法来定位目标目录：

+   静态地定义一个目录属性，该属性将把每个消息导向一个固定的目录。

+   定义一个目录表达式属性，它应该是一个有效的**Spring 表达式语言**（**SpEL**）表达式。这个表达式对每个消息进行评估，并且可以使用消息头动态指定输出文件目录。该表达式必须解析为字符串或`java.io.File`，并且必须指向有效的目录。

+   最后一个选项是自动创建目录。如果目标目录缺失，它将会自动创建，包括其父目录。这是默认行为；要禁用此功能，将`auto-create-directory`属性设置为`false`。

### 处理现有文件名

如果正在写的文件已经存在怎么办？采取正确的途径是使用`mode`属性。以下四个选项中的一个可用：

+   `REPLACE`：这是默认模式。如果文件已存在，它将被简单地覆盖。

+   `APPEND`：这将把传入文件的内容追加到现有文件中。

+   `FAIL`：如果预期没有重复，应使用此模式。如果文件已存在，这将抛出`MessageHandlingException`。

+   `IGNORE`：如果目标文件存在时不需要采取任何操作，应使用此选项。

到目前为止，我们已经涵盖了文件系统的大多数方面。然而，如果我们想在将消息写入目录之后处理消息呢？Spring Integration 提供了一个出口网关，在这里可能很有用。让我们来看看这个简单的例子：

```java
<int-file:outbound-gateway 
  request-channel="filesOutputChannel"
  reply-channel="filesOutputChannelGateway"
  directory="C:\Chandan\Projects\outputfolderforsi\filegateway"
  mode="REPLACE" delete-source-files="true"/>
```

标签与输出适配器的标签相同；区别在于它将文件放置在由`reply-channel`指定的通道上以供进一步处理。

让我们编写一个简单的服务激活器来处理这些文件：

```java
<int:service-activator 
  id="fileSa" 
  ref="commonServiceActivator"
  method="printFileName" input-channel="filesOutputChannelGateway"/>
```

### 文件转换器

文件转换器用于将从一个文件读取的数据转换为对象，反之亦然。Spring Integration 提供了一些常见的转换器，如文件到字节、文件到字符串等，但我们可以随时扩展框架接口以定义更高级和适当的文件转换器。

让我们用一个快速讨论来结束本节，讨论一些由 spring 提供的隐式文件转换器。让我们从这个例子开始：

```java
<int-file:file-to-bytes-transformer  
  input-channel="input" 
  output-channel="output"
  delete-files="true"/>

<int-file:file-to-string-transformer 
  input-channel="input" 
  output-channel="output"
  delete-files="true" 
  charset="UTF-8"/>
```

如前面的片段所示，Spring Integration 为大多数常见用例提供了隐式转换器，如文件到字节和文件到字符串。转换器不仅限于这两个用例——可以通过实现转换器接口或扩展`AbstractFilePayloadTransformer`来定义自定义转换器。

# FTP/FTPS

**FTP**，或**文件传输协议**，用于跨网络传输文件。FTP 通信由两部分组成：服务器和客户端。客户端与服务器建立会话后，它可以下载或上传文件。Spring Integration 提供了作为客户端的组件，并连接到 FTP 服务器与其通信。那么服务器——它将连接到哪个服务器？如果您有访问任何公共或托管 FTP 服务器的机会，请使用它。否则，尝试本节中示例的最简单方法是设置 FTP 服务器的本地实例。本 book 中的 FTP 设置超出了范围。

## 先决条件

要使用 Spring Integration 组件进行 FTP/FTPS，我们需要在我们的配置文件中添加一个命名空间，然后在`pom.xml`文件中添加 Maven 依赖项。应进行以下操作：

+   可以通过使用以下代码片段添加命名空间支持：

    ```java
    xmlns:int-ftp=
      "http://www.springframework.org/schema/integration/ftp"
    xsi:schemaLocation=
      "http://www.springframework.org/schema/integration/ftp
    http://www.springframework.org/schema/integration/ftp/spring-integration-ftp.xsd"
    ```

+   可以通过使用以下代码片段添加 Maven 条目：

    ```java
      <dependency>
        <groupId>org.springframework.integration</groupId>
        <artifactId>spring-integration-ftp</artifactId>
        <version>${spring.integration.version}</version>
      </dependency>
    ```

一旦命名空间可用并且 JAR 已下载，我们就可以使用这些组件了。如前所述，Spring Integration 的客户端组件需要与 FTP 服务器建立会话。会话的详细信息封装在会话工厂中；让我们看看一个会话工厂配置示例：

```java
<bean id="ftpClientSessionFactory"
  class="org.springframework.integration.ftp.session.DefaultFtpSessionFactory">
  <property name="host" value="localhost"/>
  <property name="port" value="21"/>
  <property name="username" value="testuser"/>
  <property name="password" value="testuser"/>
</bean>
```

`DefaultFtpSessionFactory`类在此处工作，并接受以下参数：

+   运行 FTP 服务器的宿主机。

+   服务器正在运行的端口

+   用户名

+   服务器的密码

会话池为工厂维护，当需要时返回一个实例。Spring 负责验证永远不会返回过期的会话。

## 从 FTP 服务器下载文件

入站适配器可用于从服务器读取文件。最重要的方面是我们在上一节中讨论的会话工厂。以下代码片段配置了一个 FTP 入站适配器，从远程目录下载文件并使其可用于处理：

```java
<int-ftp:inbound-channel-adapter 
  channel="ftpOutputChannel"
  session-factory="ftpClientSessionFactory"
  remote-directory="/"
  local-directory="C:\\Chandan\\Projects\\siexample\\ftp\\ftplocalfolder"
  auto-create-local-directory="true"
  delete-remote-files="true"
  filename-pattern="*.txt"
  local-filename-generator-expression="#this.toLowerCase() + '.trns'">
  <int:poller fixed-rate="1000"/>
</int-ftp:inbound-channel-adapter> 
```

让我们快速浏览一下此代码中使用的标签：

+   `int-ftp:inbound-channel-adapter`：这是 FTP 入站适配器的命名空间支持。

+   `channel`：下载的文件将被作为消息放在这个通道上。

+   `session-factory`：这是一个封装了连接服务器详细信息的工厂实例。

+   `remote-directory`：这是适配器应该监听文件新到达的服务器目录。

+   `local-directory`：这是下载文件应该被倾倒的本地目录。

+   `auto-create-local-directory`：如果启用，如果缺失，将创建本地目录结构。

+   `delete-remote-files`：如果启用，下载成功后将在远程目录上删除文件。这将有助于避免重复处理。

+   `filename-pattern`：这可以用作过滤器，但只有与指定模式匹配的文件才会被下载。

+   `local-filename-generator-expression`：这可以用来自动生成本地文件名。

入站适配器是一个特殊的监听器，监听远程目录上的事件，例如，在创建新文件时触发的事件。此时，它将启动文件传输。它创建一个类型为`Message<File>`的有效负载，并将其放在输出通道上。默认情况下，保留文件名，并在本地目录中创建与远程文件同名的新文件。这可以通过使用`local-filename-generator-expression`来覆盖。

### 未完成文件

在远程服务器上，可能还有一些文件正在被写入的过程中。通常，它们的扩展名是不同的，例如，`filename.actualext.writing`。避免读取未完成文件的最佳方法是使用文件名模式，只复制那些已经完全写入的文件。

## 将文件上传到 FTP 服务器

```java
server's remote directory. The remote server session is determined as usual by the session factory. Make sure the username configured in the session object has the necessary permission to write to the remote directory. The following configuration sets up a FTP adapter that can upload files in the specified directory:
```

```java
  <int-ftp:outbound-channel-adapter channel="ftpOutputChannel"
    remote-directory="/uploadfolder"
    session-factory="ftpClientSessionFactory"
    auto-create-directory="true">
  </int-ftp:outbound-channel-adapter>
```

以下是对使用标签的简要描述：

+   `int-ftp:outbound-channel-adapter`：这是 FTP 出站适配器的命名空间支持。

+   `channel`：这是要写入远程服务器的通道的名称。

+   `remote-directory`：这是文件将被放置的远程目录。会话工厂中配置的用户必须有适当的权限。

+   `session-factory`：这封装了连接 FTP 服务器的详细信息。

+   `auto-create-directory`：如果启用，这将会在远程目录缺失时自动创建，并且给定的用户应该有足够的权限。

通道上的载荷不一定是文件类型；它可以是以下之一：

+   `java.io.File`：一个 Java 文件对象。

+   `byte[]`：这是一个代表文件内容的字节数组。

+   `java.lang.String`：这是代表文件内容的文本。

### 避免部分写入的文件

远程服务器上的文件只有在完全写入时才可用，而不是当它们还是部分写入时。Spring 使用将文件写入临时位置的机制，并且仅在文件完全写入后才发布其可用性。默认情况下，后缀被写入，但可以通过使用`temporary-file-suffix`属性来更改它。可以通过将`use-temporary-file-name`设置为`false`来完全禁用它。

## FTP 出站网关

网关，按定义，是一个双向组件：它接受输入并提供一个用于进一步处理的结果。那么 FTP 的输入和输出是什么？它向 FTP 服务器发出命令并返回命令的结果。以下命令将向服务器发出带有`–l`选项的`ls`命令。结果是一个包含每个文件名的字符串对象的列表，这些文件将被放在`reply-channel`上。代码如下：

```java
<int-ftp:outbound-gateway id="ftpGateway"
    session-factory="ftpClientSessionFactory"
    request-channel="commandInChannel"
    command="ls"
    command-options="-1"
    reply-channel="commandOutChannel"/>
```

标签相当简单：

+   `int-ftp:outbound-gateway`：这是 FTP 出站网关的命名空间支持。

+   `session-factory`：这是用于连接 FTP 服务器的细节的包装器。

+   `command`：这是要发出的命令。

+   `command-options`：这是命令的选项。

+   `reply-channel`：这是命令的响应，放在这个通道上。

## FTPS 支持

为了支持 FTPS，需要做的只是更改工厂类——应使用`org.springframework.integration.ftp.session.DefaultFtpsSessionFactory`的实例。注意`DefaultFtpsSessionFactory`中的`s`。一旦使用这个工厂创建了会话，它就准备好通过安全通道进行通信。以下是安全会话工厂配置的示例：

```java
<bean id="ftpSClientFactory"
  class="org.springframework.integration.ftp.session.DefaultFtpsSessionFactory">
  <property name="host" value="localhost"/>
  <property name="port" value="22"/>
  <property name="username" value="testuser"/>
  <property name="password" value="testuser"/>
</bean>
```

虽然这很显然，但我还是要提醒你，FTP 服务器必须配置为支持安全连接并打开适当的*端口*。

# 社交集成

当今任何应用程序如果它不提供对社交消息的支持就不完整。Spring Integration 为许多社交接口提供内置支持，例如电子邮件、Twitter 提要等等。本节我们将讨论 Twitter 的实现。在 2.1 版本之前，Spring Integration 依赖于 Twitter4J API 进行 Twitter 支持，但现在它利用 Spring 的社交模块进行 Twitter 集成。Spring Integration 提供了一个接口，用于接收和发送推文以及搜索和发布搜索结果的消息。Twitter 使用`oauth`进行身份验证。应用程序必须在开始开发 Twitter 之前进行注册。

## 先决条件

在我们可以在 Spring Integration 示例中使用 Twitter 组件之前，需要完成以下步骤：

+   **Twitter 账户设置：**需要一个 Twitter 账户。执行以下步骤以获取允许用户使用 Twitter API 的密钥：

    1.  访问[`apps.twitter.com/`](https://apps.twitter.com/)。

    1.  登录到您的账户。

    1.  点击**创建新应用**。![先决条件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-itg-ess/img/00009.jpeg)

    1.  输入诸如**应用程序名称**、**描述**、**网站**等信息。所有字段都是自解释的，也提供了适当的帮助。字段**网站**的值不必须是有效的——在正确的格式中输入一个任意的网站名称。![先决条件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-itg-ess/img/00010.jpeg)

    1.  点击**创建您的应用程序**按钮。如果应用程序创建成功，将显示确认消息，并且将出现**应用程序管理**页面，如下所示：![先决条件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-itg-ess/img/00011.jpeg)

    1.  转到**密钥和访问令牌**标签，并记下**应用程序设置**下的**消费者密钥（API 密钥）**和**消费者密钥密钥（API 密钥密钥）**的详细信息，如下面的屏幕截图所示：![先决条件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-itg-ess/img/00012.jpeg)

    1.  你需要额外的访问令牌，这样应用程序才能使用 Twitter 的 API。点击**创建我的访问令牌**；生成这些令牌需要一点时间。一旦生成，记下**访问令牌**和**访问令牌密钥**的值。![先决条件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-itg-ess/img/00013.jpeg)

    1.  转到**权限**标签，并提供**读取、写入**和**访问直接消息**的权限。![先决条件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-itg-ess/img/00014.jpeg)

        完成所有这些步骤后，再加上所需的密钥和访问令牌，我们就可以使用 Twitter 了。让我们将这些信息存储在`twitterauth.properties`属性文件中：

        ```java
        twitter.oauth.apiKey= lnrDlMXSDnJumKLFRym02kHsy
        twitter.oauth.apiSecret= 6wlriIX9ay6w2f6at6XGQ7oNugk6dqNQEAArTsFsAU6RU8F2Td
        twitter.oauth.accessToken= 158239940-FGZHcbIDtdEqkIA77HPcv3uosfFRnUM30hRix9TI
        twitter.oauth.accessTokenSecret= H1oIeiQOlvCtJUiAZaachDEbLRq5m91IbP4bhg1QPRDeh
        ```

正如我提到的，模板封装了所有的值。以下是参数的顺序：

+   `apiKey`

+   `apiSecret`

+   `accessToken`

+   `accessTokenSecret`

所有设置就绪后，我们现在做一些实际的工作：

+   可以通过使用以下代码片段来添加命名空间支持：

    ```java
    <beans xmlns=
      "http://www.springframework.org/schema/beans"
      xmlns:xsi=
      "http://www.w3.org/2001/XMLSchema-instance"
      xmlns:int=
      "http://www.springframework.org/schema/integration"
      xmlns:int-twitter=
      "http://www.springframework.org/schema/integration/twitter"
      xsi:schemaLocation=
      "http://www.springframework.org/schema/integration http://www.springframework.org/schema/integration/spring-integration.xsd
      http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd
      http://www.springframework.org/schema/integration/twitter http://www.springframework.org/schema/integration/twitter/spring-integration-twitter.xsd">
    ```

+   可以通过使用以下代码片段来添加 Maven 入口：

    ```java
    <dependency>
      <groupId>org.springframework.integration</groupId>
      <artifactId>spring-integration-twitter</artifactId>
      <version>${spring.integration.version}</version>
    </dependency>
    ```

## 接收推文

此代码中的组件如下所述：

+   `int-twitter:inbound-channel-adapter`：这是 Twitter 的入站通道适配器的命名空间支持。

+   `twitter-template`：这是最重要的方面。Twitter 模板封装了要使用哪个账户轮询 Twitter 网站。前面代码片段中给出的详细信息是虚构的；它应该用真实的连接参数替换。

+   `channel`: 消息会被投放到这个频道。

这些适配器进一步用于其他应用程序，例如搜索消息、接收直接消息以及接收提到您账户的推文等。让我们快速查看这些适配器的代码片段。我不会深入每个细节；它们与之前讨论的几乎相同。

+   **搜索**：此适配器有助于搜索查询标签中配置的参数的推文。代码如下：

    ```java
    <int-twitter:search-inbound-channel-adapter id="testSearch"
      twitter-template="twitterTemplate"
      query="#springintegration"
      channel="twitterSearchChannel">
    </int-twitter:search-inbound-channel-adapter>
    ```

+   **获取直接消息**：此适配器允许我们接收使用中账户的直接消息（在 Twitter 模板中配置的账户）。代码如下：

    ```java
    <int-twitter:dm-inbound-channel-adapter id="testdirectMessage"
      twitter-template="twiterTemplate"
      channel="twitterDirectMessageChannel">
    </int-twitter:dm-inbound-channel-adapter>
    ```

+   **获取提及消息**：此适配器允许我们通过 `@用户` 标签（在 Twitter 模板中配置的账户）接收提到配置账户的消息。代码如下：

    ```java
    <int-twitter:mentions-inbound-channel-adapter id="testmentionMessage"
      twitter-template="twiterTemplate"
      channel="twitterMentionMessageChannel">
    </int-twitter:mentions-inbound-channel-adapter>
    ```

## 发送推文

Twitter 暴露出站适配器以发送消息。以下是一个示例代码：

```java
  <int-twitter:outbound-channel-adapter
    twitter-template="twitterTemplate"
    channel="twitterSendMessageChannel"/>
```

无论什么消息放在 `twitterSendMessageChannel` 频道上，都会通过此适配器发布推文。与入站网关类似，出站网关也提供发送直接消息的支持。以下是一个出站适配器的简单示例：

```java
<int-twitter:dm-outbound-channel-adapter 
  twitter-template="twitterTemplate" 
  channel="twitterSendDirectMessage"/>
```

任何放在 `twitterSendDirectMessage` 频道上的消息都会直接发送给用户。但是，消息将要发送给哪个用户的名字在哪里？它由消息中的一个头 `TwitterHeaders.DM_TARGET_USER_ID` 决定。这可以通过编程方式填充，或使用丰富器或 SpEL。例如，可以通过以下方式编程添加：

```java
Message message = MessageBuilder.withPayload("Chandan")
  .setHeader(TwitterHeaders.DM_TARGET_USER_ID, "test_id").build();
```

Alternatively, it can be populated by using a header enricher, as follows: 通过使用头丰富器，如下所示：

```java
<int:header-enricher input-channel="twitterIn"
  output-channel="twitterOut">
  <int:header name="twitter_dmTargetUserId" value=" test_id "/>
</int:header-enricher>
```

## Twitter 搜索出站网关

由于网关提供双向窗口，搜索出站网关可用于发出动态搜索命令并接收结果作为集合。如果没有找到结果，集合为空。让我们配置一个搜索出站网关，如下所示：

```java
  <int-twitter:search-outbound-gateway id="twitterSearch"
    request-channel="searchQueryChannel" 
    twitter-template="twitterTemplate" 
    search-args-expression="#springintegration" 
    reply-channel="searchQueryResultChannel"/>
```

以下代码标签的含义：

+   `int-twitter:search-outbound-gateway`: 这是 Twitter 搜索出站网关的命名空间。

+   `request-channel`: 用于将搜索请求发送到这个网关的频道。

+   `twitter-template`：这是 Twitter 模板引用

+   `search-args-expression`：此参数用于查询标签中的搜索

+   `reply-channel`：在这个频道上填充搜索结果。

这让我们有足够的内容开始使用 Spring 框架的社会整合方面。

# 企业消息传递

没有 JMS 的企业景观是不完整的——它是企业集成中最常用的媒介之一。Spring 为此提供了非常好的支持。Spring Integration 在此基础上构建，为接收和消费来自许多中间件代理（如 ActiveMQ、RabbitMQ、Rediss 等）的消息提供了适配器和网关。

Spring Integration 提供入站和出站适配器，用于发送和接收消息，同时还提供了网关，这些网关可以在请求/回复场景中使用。让我们更详细地了解这些实现。预计需要对 JMS 机制及其概念有一个基本了解。在这里甚至连 JMS 的介绍都不可能涵盖。让我们从先决条件开始。

## 先决条件

要使用 Spring Integration 消息组件、命名空间和相关 Maven，应添加以下依赖项：

+   可以通过使用以下代码片段来添加命名空间支持：

    ```java
    xmlns: int-jms= 
      "http://www.springframework.org/schema/integration/jms"
      xsi:schemaLocation="http://www.springframework.org/schema/integration/jms http://www.springframework.org/schema/integration/jms/spring-integration-jms.xsd">
    ```

+   可以通过以下代码片段提供 Maven 入口：

    ```java
    <dependency>
      <groupId>org.springframework.integration</groupId>
      <artifactId>spring-integration-jms</artifactId>
      <version>${spring.integration.version}</version>
    </dependency>
    ```

在添加这两个依赖之后，我们就准备好使用组件了。但在我们可以使用适配器之前，我们必须配置一个底层消息代理。让我们配置 ActiveMQ。在`pom.xml`中添加以下内容：

```java
  <dependency>
    <groupId>org.apache.activemq</groupId>
    <artifactId>activemq-core</artifactId>
    <version>${activemq.version}</version>
    <exclusions>
      <exclusion>
        <artifactId>spring-context</artifactId>
        <groupId>org.springframework</groupId>
      </exclusion>
    </exclusions>
  </dependency>
  <dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-jms</artifactId>
    <version>${spring.version}</version>
    <scope>compile</scope>
  </dependency>
```

在此之后，我们准备创建一个连接工厂和 JMS 队列，这些队列将由适配器用于通信。首先，创建一个会话工厂。正如您将注意到的，这被包裹在 Spring 的`CachingConnectionFactory`中，但底层提供者是 ActiveMQ：

```java
<bean id="connectionFactory" class="org.springframework.jms.connection.CachingConnectionFactory">
  <property name="targetConnectionFactory">
    <bean class="org.apache.activemq.ActiveMQConnectionFactory">
      <property name="brokerURL" value="vm://localhost"/>
    </bean>
  </property>
</bean>
```

让我们创建一个队列，以便用于检索和放置消息：

```java
<bean 
  id="feedInputQueue" 
  class="org.apache.activemq.command.ActiveMQQueue"> 
  <constructor-arg value="queue.input"/>
</bean>
```

现在，我们准备从队列中发送和接收消息。让我们逐一查看每个消息。

## 接收消息——入站适配器

Spring Integration 提供两种接收消息的方式：轮询和事件监听器。它们都基于 Spring 框架对 JMS 的全面支持。轮询适配器使用`JmsTemplate`，而事件驱动适配器使用`MessageListener`。正如名称所示，轮询适配器会不断轮询队列以等待新消息的到来，如果找到消息，则将其放入配置的通道中。另一方面，在事件驱动适配器的情况下，通知配置适配器是服务器的责任。

### 轮询适配器

让我们从一个代码示例开始：

```java
<int-jms:inbound-channel-adapter 
  connection-factory="connectionFactory" 
  destination="feedInputQueue" 
  channel="jmsProcessedChannel"> 
  <int:poller fixed-rate="1000" />
</int-jms:inbound-channel-adapter>
```

```java
`int-jms:inbound-channel-adapter`: This is the namespace support for the JMS inbound adapter`connection-factory`: This is the encapsulation for the underlying JMS provider setup, such as ActiveMQ`destination`: This is the JMS queue where the adapter is listening for incoming messages`channel`: This is the channel on which incoming messages should be put
```

有一个轮询器元素，因此很明显它是一个基于轮询的适配器。它可以通过两种方式之一进行配置：通过提供 JMS 模板或使用连接工厂和目标。我使用了后者的方法。前面的适配器在目标中提到了一个轮询队列，一旦它收到任何消息，它就会将消息放入`channel`属性中配置的通道中。

### 事件驱动的适配器

与轮询适配器类似，事件驱动适配器也需要引用实现`AbstractMessageListenerContainer`接口的类或需要一个连接工厂和目的地。再次，我将使用后一种方法。这是一个示例配置：

```java
<int-jms:message-driven-channel-adapter 
  connection-factory="connectionFactory"
  destination="feedInputQueue"
  channel="jmsProcessedChannel"/>
```

这里没有轮询器子元素。一旦消息到达其目的地，适配器就会被调用，将其放入配置的通道。

## 发送消息——出站适配器

出站适配器将通道上的消息转换为 JMS 消息，并将其放入配置的队列中。为了将 Spring Integration 消息转换为 JMS 消息，出站适配器使用`JmsSendingMessageHandler`。这是一个`MessageHandler`的实现。出站适配器应该使用`JmsTemplate`或与目的地队列一起配置连接工厂。与前面的示例保持一致，我们将采用后一种方法，如下所示：

```java
<int-jms:outbound-channel-adapter
  connection-factory="connectionFactory"
  channel="jmsChannel"
  destination="feedInputQueue"/>
```

这个适配器接收来自`jmsChannel`的 Spring Integration 消息，将其转换为 JMS 消息，并将其放入目标地。

## 网关

网关提供请求/回复行为，而不是单向发送或接收。例如，在发送消息后，我们可能期望有一个回复，或者在接收到消息后我们可能想发送一个确认。

### 入站网关

入站网关在预期请求回复功能时提供了入站适配器的替代方案。入站网关是一个基于事件的实现，监听队列上的消息，将其转换为 Spring `Message`，并将其放入通道。这是一个示例代码：

```java
<int-jms:inbound-gateway 
  request-destination="feedInputQueue"
  request-channel="jmsProcessedChannel"/>
```

然而，这就是入站适配器所做的——甚至配置也很相似，除了命名空间。那么区别在哪里呢？区别在于回复回复目的地。一旦消息放入通道，它将沿着线路传播，在某个阶段会产生一个回复并作为确认发送回来。当入站网关接收到这个回复时，将创建一个 JMS 消息并将其放回回复目的地队列。那么，回复目的地在哪里呢？回复目的地以下列方式之一决定：

1.  原始消息有一个属性`JMSReplyTo`，如果存在，它具有最高的优先级。

1.  入站网关寻找一个配置好的默认回复目的地，它可以作为名称或直接引用通道。为了将通道作为直接引用指定默认回复目的地，应使用 default-reply-destination 标签。

如果网关找不到前面两种方法中的任何一种，它将抛出一个异常。

### 出站网关

在预期有回复的发送消息场景中应使用出站网关。让我们从一个例子开始：

```java
<int-jms:outbound-gateway 
  request-channel="jmsChannel"
  request-destination="feedInputQueue"
  reply-channel="jmsProcessedChannel" />
```

前面的配置将消息发送到`request-destination`。当收到确认时，它可以从配置的`reply-destination`中获取。如果没有配置`reply-destination`，将创建 JMS `TemporaryQueues`。

# HTTP

Spring Integration 提供了访问外部 HTTP 服务以及将 HTTP 服务暴露给外部应用程序的支持。

## 先决条件

让我们添加一个命名空间和相关 Maven 依赖项，以便在我们的应用程序中可以使用 Spring Integration 的 HTTP 组件：

+   可以使用以下代码片段添加命名空间支持：

    ```java
    <beans xmlns=
      "http://www.springframework.org/schema/beans"
      xmlns:xsi=
      "http://www.w3.org/2001/XMLSchema-instance"
      xmlns:int=
      "http://www.springframework.org/schema/integration"
      xmlns:int-http=
      "http://www.springframework.org/schema/integration/http"
      xsi:schemaLocation=
      "http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd
      http://www.springframework.org/schema/integration http://www.springframework.org/schema/integration/spring-integration.xsd
      http://www.springframework.org/schema/integration/http http://www.springframework.org/schema/integration/http/spring-integration-http.xsd">
    ```

+   可以通过以下代码添加 Maven 条目：

    ```java
      <dependency>
        <groupId>org.springframework.integration</groupId>
        <artifactId>spring-integration-http</artifactId>
        <version>${spring.integration.version}</version>
      </dependency>
      <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-webmvc</artifactId>
        <version>${spring.version}</version>
      </dependency>   
    ```

## HTTP 入站网关

入站网关将 HTTP 服务暴露给外部世界，例如，基于 REST 的 Web 服务。应用程序必须部署在 Jetty 或 Tomcat 等 Web 容器中，以便入站适配器或网关正常工作。实现入站组件的最简单方法是使用 Spring 的`HttpRequestHandlerServlet`类，并在`web.xml`文件中定义它。这是一个示例条目：

```java
<servlet>
  <servlet-name>inboundGateway</servlet-name>
  <servlet-class> o.s.web.context.support.HttpRequestHandlerServlet 
  </servlet-class>
</servlet>
```

或者，我们可以使用 spring MVC 支持。这是我们示例中使用的方法；让我们来看看`web.xml`文件：

```java
<?xml version="1.0" encoding="UTF-8"?>
<web-app    xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd" id="WebApp_ID" version="2.5">
  <display-name>testhttpinbound</display-name>
  <servlet>
    <servlet-name>testhttpinbound</servlet-name>
    <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
    <init-param>
      <param-name>contextConfigLocation</param-name>
      <param-value>/WEB-INF/http-inbound-config.xml</param-value>
    </init-param>
    <load-on-startup>1</load-on-startup>
  </servlet>
  <servlet-mapping>
    <servlet-name>testhttpinbound</servlet-name>
    <url-pattern>/*</url-pattern>
  </servlet-mapping>
</web-app>
```

`org.springframework.web.servlet.DispatcherServlet`类是一个标准的 Spring MVC 控制器。请注意配置参数，`http-inbound-config.xml`。这是将包含网关声明的文件：

```java
<int-http:inbound-gateway 
  request-channel="receiveChannel" 
  path="receiveGateway" 
  supported-methods="GET"/>
```

此代码中使用的组件在以下子弹点中解释：

+   `int-http:inbound-gateway`: 这是对 HTML 网关的命名空间支持。

+   `request-channel`: 这会将传入的请求负载放入通道中。

+   `path`：这是对外来请求暴露的路径。

+   `supported-methods`: 这是一个用逗号分隔的支持方法列表，这些方法使用 HTTP 协议。

在以下代码中，服务激活器监听输入通道上的负载并在入站网关发送响应之前对其进行修改：

```java
<int:service-activator 
  input-channel="receiveChannel" 
  expression="payload + ' hmm, you get what you give!!'"/>
```

`HttpMessageConverter`可以用来将`HttpServletRequest`转换为`Messages`。网关元素根据它是否只需要返回一个响应（例如 200 成功）还是需要返回一个带有视图的响应，产生不同的实例。如果响应是一个视图，它产生一个`HttpRequestHandlingController`实例。否则，它产生一个`HandlingMessagingGateway`实例。要渲染视图，可以使用 Spring MVC 支持的任何视图渲染技术。

对于只需要确认请求成功的请求，可以使用适配器而不是网关：

```java
<int-http:inbound-channel-adapter 
  channel="testchannel" 
  supported-methods="GET,POST" 
  name="/test" 
  view-name="testMessageView" />
```

## HTTP 出站网关

出站网关用于调用由外部 HTTP 组件发布的服务。让我们用我们之前的例子来测试这个。创建一个包含入站网关的应用程序 war，并在容器中部署它。我们可以使用以下出站网关示例来调用 HTTP 请求：

```java
<int-http:outbound-gateway 
  request-channel="outboundRequestChannel" url="http://localhost:8080/httpinbound/receiveGateway"
  http-method="GET"
  expected-response-type="java.lang.String"/>
```

此代码中使用的组件在以下子弹点中解释：

+   `int-http:outbound-gateway`: 这是对 HTTP 出站网关的命名空间支持。

+   `channel`: 根据这个通道上的消息，它将尝试击中 URL。

+   `url`：这是对外部 URL 的请求。

+   `http-method`：这指定了在发送请求时应使用哪些 HTTP 方法

+   `expected-response-type`：这是期望的响应类型（默认情况下，它是`String`）

除了网关，还可以使用适配器。唯一的区别是适配器不会在回复通道上发送响应。在幕后，出站适配器使用 Spring 框架的`RestTemplate`。以下代码片段添加了出站适配器：

```java
<int-http:outbound-channel-adapter 
  id="feedAdapter" 
  url=" http://localhost:8080/httpinbound/receiveGateway" 
  channel="feedUpdates" 
  http-method="POST"/>
```

# Web 服务

HTTP 适配器和网关为基于 REST 的 Web 服务提供支持，但 Spring Integration 还支持基于 XML 的 Web 服务，如 SOAP。入站适配器或网关用于创建和暴露 Web 服务端点，而出站适配器或网关用于调用外部服务。Spring Integration 对 Web 服务的支持建立在 spring `ws` 项目之上。我不会涵盖 spring `ws` 或任何特定的 SOAP 细节，如`wsdl`、头部、正文或负载。相反，我们将展示 Spring Integration 封装器。

## 前提条件

可以通过包含以下命名空间和 Maven 依赖项来添加 Web 服务支持：

+   可以使用以下代码片段添加命名空间支持：

    ```java
    <beans xmlns=
      "http://www.springframework.org/schema/beans"
      xmlns:xsi=
      "http://www.w3.org/2001/XMLSchema-instance"
      xmlns:int=
      "http://www.springframework.org/schema/integration"
      xmlns:int-ws=
      "http://www.springframework.org/schema/integration/ws"
      xsi:schemaLocation=
      "http://www.springframework.org/schema/integration/ws http://www.springframework.org/schema/integration/ws/spring-integration-ws.xsd
      http://www.springframework.org/schema/integration http://www.springframework.org/schema/integration/spring-integration.xsd
      http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    ```

+   可以通过以下代码添加 Maven 条目：

    ```java
      <dependency>
        <groupId>org.springframework.integration</groupId>
        <artifactId>spring-integration-xml</artifactId>
        <version>${spring.integration.version}</version>
      </dependency>
      <dependency>
        <groupId>org.springframework.integration</groupId>
        <artifactId>spring-integration-ws</artifactId>
        <version>${spring.integration.version}</version>
      </dependency> 
      <dependency>
        <groupId>com.sun.xml.messaging.saaj</groupId>
        <artifactId>saaj-impl</artifactId>
        <version>${saaj.version}</version>
      </dependency>
      <dependency>
        <groupId>javax.activation</groupId>
        <artifactId>activation</artifactId>
        <version>${javax-activation.version}</version>
      </dependency>
    ```

## 入站网关

入站网关将暴露一个 SOAP 服务以处理外部请求，然后将其转换为消息并发布到通道。需要一个前端控制器来拦截请求并将它们传递给配置的网关；它是`org.springframework.ws.transport.http.MessageDispatcherServlet`的一个实例。这应该在`web.xml`文件中进行配置：

```java
<?xml version="1.0" encoding="ISO-8859-1" standalone="no"?>
<web-app   version="2.4" xsi:schemaLocation="http://java.sun.com/xml/ns/j2ee http://java.sun.com/xml/ns/j2ee/web-app_2_4.xsd">
  <description>ws-inbound-webservice</description>

<servlet> 
  <servlet-name>springwsinbound</servlet-name> 
  <servlet-class>
    org.springframework.ws.transport.http.MessageDispatcherServlet
  </servlet-class>
  <init-param>
    <param-name>contextConfigLocation</param-name>
    <param-value>
      WEB-INF/ws-inbound-config.xml
    </param-value>
  </init-param>
  <load-on-startup>1</load-on-startup>
</servlet>

  <servlet-mapping>
    <servlet-name>springwsinbound</servlet-name>
    <url-pattern>/testwsservice</url-pattern>
  </servlet-mapping>

  <welcome-file-list>
    <welcome-file>index.html</welcome-file>
  </welcome-file-list>

</web-app>
```

必须提供一个`org.springframework.ws.server.EndpointMapping`的实现来将 servlet 与端点之间进行映射。这可以在 Java 配置类或属性文件中进行配置。让我们将其放在属性文件中并将其作为`contextConfigLocation`注入：

```java
<bean class=
  "org.springframework.ws.server.endpoint.mapping.UriEndpointMapping">
  <property name="defaultEndpoint" ref="ws-inbound-gateway"/>
</bean>
```

`org.springframework.ws.server.endpoint.mapping.UriEndpointMapping`类执行 servlet 到`Message`的映射。

之后，我们有服务激活器，它可以改变响应或对其执行一些操作：

```java
  <int:channel id="input"/>

  <int-ws:inbound-gateway 
    id="ws-inbound-gateway" 
request-channel="input"/>

  <int:service-activator 
    input-channel="input">
    <bean class="com.cpandey.siexample.TestWsInbound"/>
  </int:service-activator>
```

## 出站网关

这甚至更容易；出站网关可以接受一个 URI 并调用服务，如下所示：

```java
<int-ws:outbound-gateway
  uri=" http://www.w3schools.com/webservices/tempconvert.asmx"
  request-channel=" fahrenheitChannel" 
  reply-channel="responses" />
```

在前面的代码中，应该在`request-channel`上放置一个有效的 SOAP 负载；这将由网关用来调用配置的服务。响应的负载发布在`reply-channel`上。以下是一个调用前面服务的示例代码片段：

```java
ClassPathXmlApplicationContext context =
  new ClassPathXmlApplicationContext("/META-INF/spring/integration/temperatureConversion.xml");

DestinationResolver<MessageChannel> channelResolver = new BeanFactoryChannelResolver(context);

// Compose the XML message according to the server's schema

String requestXml =
  "<FahrenheitToCelsius 
  xmlns=\"http://www.w3schools.com/webservices/\">" +
  "    <Fahrenheit>90.0</Fahrenheit>" +
  "</FahrenheitToCelsius>";

// Create the Message object
Message<String> message = MessageBuilder.withPayload(requestXml).build();

// Send the Message to the handler's input channel
MessageChannel channel = channelResolver.resolveDestination("fahrenheitChannel");
channel.send(message);
```

# 数据库 SQL

很难想象没有数据库的企业应用程序；它是最古老和最常用的桥接机制之一。Spring Integration 提供了从数据库读取和写入数据库的支持。再次，这种支持是基于 Spring 框架对数据库支持的基础之上的。它提供了入站和出站适配器、网关，甚至还有针对存储过程的特定适配器。让我们来看看其中的一些，其他的可以使用相同的模式。

## 先决条件

在讨论如何使用 Spring Integration 的数据库支持之前，让我们添加必要的命名空间和 Maven 依赖项：

+   可以通过以下代码片段添加命名空间支持：

    ```java
    xmlns:int-jdbc=
    "http://www.springframework.org/schema/integration/jdbc"
    xmlns:jdbc=
    "http://www.springframework.org/schema/jdbc"
    xsi:schemaLocation="
    http://www.springframework.org/schema/integration/jdbc
    http://www.springframework.org/schema/integration/jdbc/spring-integration-jdbc.xsd
    http://www.springframework.org/schema/jdbc http://www.springframework.org/schema/jdbc/spring-jdbc.xsd>
    ```

+   可以通过以下代码片段添加 Maven 入口：

    ```java
      <dependency>
        <groupId>org.springframework.integration</groupId>
        <artifactId>spring-integration-jdbc</artifactId>
        <version>${spring.integration.version}</version>
      </dependency>
    ```

### 数据源

在我们可以使用组件之前，我们需要定义一个数据源。数据源是一个封装数据库连接细节的包装器。以下是一个针对内存数据库 H2 的示例数据源：

```java
<jdbc:embedded-database id="dataSource" type="H2"/>
```

为了简单起见，我将使用一个内存数据库。但这与 Spring Integration 无关；可以为 Spring 支持的任何数据库配置数据源。在`pom.xml`中包含以下依赖项，以使用内存数据库：

```java
  <dependency>
    <groupId>com.h2database</groupId>
    <artifactId>h2</artifactId>
    <version>1.3.168</version>
  </dependency>
```

现在，我们已经准备好了数据源。让我们用一些测试数据来初始化它；再次，Spring 提供了易于使用的组件，可以在几行配置中完成我们的任务：

```java
<jdbc:initialize-database data-source="dataSource" ignore-failures="DROPS">
  <jdbc:script location="classpath:H2DB-DropScript.sql" />
  <jdbc:script location="classpath:H2DB-CreateScript.sql" />
  <jdbc:script location="classpath:H2DB-InsertScript.sql" />
</jdbc:initialize-database>
```

有了前面的配置，我们现在可以探索 Spring 提供的适配器、网关和其他组件。

## 从数据库读取——入站适配器

入站适配器需要一个对`JdbcTemplate`或数据源的引用。我们将坚持使用数据源。它的任务是从数据库中读取数据，并将结果放置在指定的通道上。默认情况下，消息载荷是整个结果集，表示为一个列表。可以通过定义`RowMapper`策略来更改结果集类型，Spring 为此提供了支持：

```java
<int-jdbc:inbound-channel-adapter channel="printSqlResult"
  data-source="dataSource"
  query="select * from PEOPLE where name = 'Chandan'"
  update="update PEOPLE set name = 'ChandanNew' where name = 'Chandan'">
</int-jdbc:inbound-channel-adapter>
```

```java
`int-jdbc:inbound-channel-adapter`: This is the namespace support for the inbound channel adapter`data-source`: This is a reference to the datasource that encapsulates database connection details`query`: This is the query to be fired`update`: This is any update query to be fired that can be used to avoid duplicate processing
```

此配置将连接到数据源中配置的数据库。在我们这个案例中，它是一个内存数据库，即 H2。它将执行查询并发出更新。结果将被放置在配置的通道上。在下一轮轮询周期中，当我们想要过滤掉已经处理过的记录时，更新查询非常有用。

### 事务支持

入站适配器的事务支持可以与轮询器一起包装：

```java
<int-jdbc:inbound-channel-adapter 
  query="somequery"
  channel="testChannel" 
  data-source="dataSource" update="someupdate">
    <int:poller fixed-rate="1000">
      <int:transactional/>
    </int:poller>
</int-jdbc:inbound-channel-adapter>
```

当事务作为轮询器的子元素时，查询和更新将在同一个事务中执行。应该定义一个有效的事务管理器；这与 Spring Integration 无关。相反，应该定义基于 Spring 的实体管理器和事务管理器（这与 Spring Integration 无关；相反，这是标准的 Spring 数据库支持内容）。代码如下：

```java
<bean id="transactionManager" 
  class=
  "org.springframework.orm.jpa.JpaTransactionManager">
  <constructor-arg ref="entityManagerFactory" />
</bean>

<bean id="entityManagerFactory"
  class=
  "org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean">
  <property name="dataSource"          ref="dataSource" />
  <property name="jpaVendorAdapter"    ref="vendorAdaptor"/>
  <property name="packagesToScan"      value="com.cpandey.siexample.pojo"/>
</bean>

<bean id="abstractVendorAdaptor" abstract="true">
  <property name="generateDdl" value="true" />
  <property name="database"    value="H2" />
  <property name="showSql"     value="false"/>
</bean>

<bean id="entityManager" 
  class=
  "org.springframework.orm.jpa.support.SharedEntityManagerBean">
  <property name="entityManagerFactory" ref="entityManagerFactory"/>
</bean>

<bean id="vendorAdaptor" 
  class=
  "org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter"
  parent="abstractVendorAdaptor">
</bean>
```

## 向数据库写入——出站适配器

出站适配器可用于将数据插入数据库；它可以使用通道上的消息来构建查询并执行它。以下代码将添加出站适配器：

```java
<int-jdbc:outbound-channel-adapter 
  channel="printSqlResult"
  data-source="dataSource"
  query="insert into PEOPLE p(ID, NAME, CREATED_DATE_TIME) values(2, :payload[NAME], NOW())">
</int-jdbc:outbound-channel-adapter>
```

此操作从有效负载中提取一个值，并将数据写入数据库。将写入的数据库取决于数据源。

## 入站和出站网关

网关结合了输入和输出适配器功能；它发起一个查询并在回复通道上发布回复：

```java
<int-jdbc:outbound-gateway
  update="insert into PEOPLE (ID, NAME, CREATED_DATE_TIME) values (3, :payload[NAME], NOW())"
  request-channel="insertChannel" 
  reply-channel="printSqlResult" 
  data-source="dataSource" />
```

出站网关需要一个引用，该引用用于决定连接到哪个数据库。

# 流处理

Spring Integration 为流提供了两个隐式组件：一个用于读取流，另一个用于写入流。这个部分很小——让我们快速进入代码！

## 先决条件

首先，让我们添加命名空间和 Maven 依赖项：

+   可以使用以下代码添加命名空间支持：

    ```java
    <?xml version="1.0" encoding="UTF-8"?>
      <beans:beans xmlns:int-stream=
        "http://www.springframework.org/schema/integration/stream"

        xsi:schemaLocation=
        "http://www.springframework.org/schema/beans
        http://www.springframework.org/schema/beans/spring-beans.xsd
        http://www.springframework.org/schema/integration/stream
        http://www.springframework.org/schema/integration/stream/spring-integration-stream.xsd">
    ```

+   Maven 依赖项可以使用以下代码片段添加：

    ```java
      <dependency>
        <groupId>org.springframework.integration</groupId>
        <artifactId>spring-integration-stream</artifactId>
        <version>${spring.integration.version}</version>
      </dependency>
    ```

在前面的包含之后，我们准备好使用适配器了。

## 从流中读取

Spring Integration 提供了一个 STDIN 适配器，该适配器从 `stdin` 读取。这个 `stdin` 是什么？任何写在命令行上的东西，例如 Java 中的 `System.in`。以下代码片段用于添加 STDIN 适配器：

```java
<int-stream:stdin-channel-adapter 
  id="stdin" 
  channel="stdInChannel"/>
```

在这里，`int-stream:stdin-channel-adapter` 是命名空间支持，通道适配器将把写入控制台的消息放进去。

如果我们想要获得一些内部视图，Spring 分别使用 `ByteStreamReadingMessageSource` 或 `CharacterStreamReadingMessageSource`，它们是 `MessageSource` 的实现，以提供适配器功能。`ByteStreamReadingMessageSource` 需要 `InputStream`，而 `CharacterStreamReadingMessageSource` 需要 `Reader`，如下面的代码片段所示：

```java
<bean 
  class=
  "org.springframework.integration.stream.ByteStreamReadingMessageSource">
  <constructor-arg ref="inputStream"/>
</bean>

<bean 
  class="org.springframework.integration.stream.CharacterStreamReadingMessageSource">
    <constructor-arg ref="reader"/>
</bean>
```

## 写入流

Spring 还提供了一个类似的适配器，用于将消息写入控制台：`stdout`。它将通道上收到的任何消息打印到控制台。让我们在前面的代码中插入一个 `stdout` 适配器，输出将被定向到控制台：

```java
<int-stream:stdout-channel-adapter 
  id="stdout" 
  channel="stdInChannel" 
  append-newline="true"/> 
```

`int-stream:stdout-channel-adapter` 是命名空间，适配器将轮询通道中的消息，然后将每个消息打印到控制台。`append-newline` 将添加一个新行到输出。

在幕后，Spring 框架使用 either `ByteStreamWritingMessageHandler` 或 `CharacterStreamWritingMessageHandler`。它们分别需要一个 `OutputStream` 和 `Writer` 的引用：

```java
<bean 
  class="org.springframework.integration.stream.ByteStreamWritingMessageHandler">
  <constructor-arg ref="outputStream"/>
</bean>

<bean 
  class="org.springframework.integration.stream.CharacterStreamWritingMessageHandler">
  <constructor-arg ref="writer"/>
</bean>
```

这是一个很长的章节，我们都应该休息一下了！

# 总结

本章展示了 Spring Integration 在处理复杂集成时提供的简单性和抽象能力，无论是基于文件的、HTTP 的、JMS 的还是其他任何集成机制。不要恐慌；我保证接下来的几章会相对简短，我们将讨论 Spring Integration 的可测试性、性能和管理的主题，最后以一个端到端的示例来结束。在下一章中，我们将介绍如何将 Spring Batch 和 Spring Integration 集成，以充分利用这两个框架的优势。
