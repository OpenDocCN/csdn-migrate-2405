# Eclipse MicroProfile 企业级微服务实用指南（一）

> 原文：[`zh.annas-archive.org/md5/90EEB03D96FBA880C6AA42B87707D53C`](https://zh.annas-archive.org/md5/90EEB03D96FBA880C6AA42B87707D53C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

本书将帮助你了解 Eclipse MicroProfile，这是一个始于 2016 年的开源企业 Java 微服务规范，以及它的背景和历史、它对组织和企业的价值主张、它的社区治理、当前的 Eclipse MicroProfile 子项目（随着开源项目的演变，还会有更多的子项目加入）、它的实现以及它的互操作性。它还将为你提供 Eclipse MicroProfile 的未来发展方向的预览，一个在 Red Hat 的 Thorntail 实现中的 Eclipse MicroProfile 示例应用程序，Red Hat Runtimes 提供的一个运行时，以及关于在混合云和多云环境中运行 Eclipse MicroProfile 的指导和建议。本书将采用逐步的方法帮助你了解 Eclipse MicroProfile 项目和市场上的其实现。

# 本书适合哪些人

本书适合希望创建企业微服务的 Java 开发者。为了更好地利用这本书，你需要熟悉 Java EE 和微服务概念。

# 为了最大化地利用这本书

需要对微服务和企业 Java 有基本了解。其他安装和设置说明将在必要时提供。

# 下载示例代码文件

你可以从[www.packt.com](http://www.packt.com)上你的账户下载本书的示例代码文件。如果你在其他地方购买了这本书，你可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便将文件直接通过电子邮件发送给你。

你可以通过以下步骤下载代码文件：

1.  登录或注册[www.packt.com](http://www.packt.com)。

1.  选择支持标签。

1.  点击代码下载。

1.  在搜索框中输入本书的名称，并按照屏幕上的指示操作。

文件下载后，请确保使用最新版本进行解压缩或提取文件夹：

+   Windows 上的 WinRAR/7-Zip

+   Mac 上的 Zipeg/iZip/UnRarX

+   Linux 上的 7-Zip/PeaZip

本书的代码包也托管在 GitHub 上，地址为：[`github.com/PacktPublishing/Hands-On-Enterprise-Java-Microservices-with-Eclipse-MicroProfile ...`](https://github.com/PacktPublishing/Hands-On-Enterprise-Java-Microservices-with-Eclipse-MicroProfile)

# 下载彩色图片

我们还将提供一个包含本书中使用的屏幕快照/图表的彩色图像的 PDF 文件。你可以在这里下载它：`static.packt-cdn.com/downloads/9781838643102_ColorImages.pdf`。

# 使用的约定

本书中使用了多种文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、假 URL、用户输入和 Twitter 处理。例如："`checks`数组对象类型包括一个必需的`name`和`status`字符串，以及一个可选的包含可选的`key`和`value`对的对象。"

代码块如下所示：

```java
package org.eclipse.microprofile.health;@FunctionalInterfacepublic interface HealthCheck {  HealthCheckResponse call();}
```

任何命令行输入或输出如下所示：

```java
Scotts-iMacPro:jwtprop starksm$ curl http://localhost:8080/jwt/secureHello; echoNot authorized
```

**粗体**：表示新的...

# 联系我们

来自读者的反馈总是受欢迎的。

**一般反馈**：如果你对本书的任何方面有问题，请在消息的主题中提及书名，并发送电子邮件至`customercare@packtpub.com`。

**错误报告**：尽管我们已经采取了每一步来确保我们内容的准确性，但错误仍然会发生。如果你在这本书中发现了错误，我们将非常感激你能向我们报告。请访问[www.packtpub.com/submit/errata](http://www.packtpub.com/submit/errata)，选择你的书，点击错误提交表单链接，并输入详情。

**盗版**：如果你在互联网上以任何形式发现我们作品的非法副本，如果你能提供位置地址或网站名称，我们将不胜感激。请通过`copyright@packt.com`联系我们，并附上材料的链接。

**如果您有兴趣成为作者**：如果您对某个主题有专业知识，并且有兴趣撰写或贡献一本书，请访问[authors.packtpub.com](http://authors.packtpub.com/)。

# 评论

请留下评论。一旦你阅读并使用了这本书，为什么不在这本书购买的网站上留下评论呢？潜在的读者可以看到和使用你的客观意见来做出购买决定，我们 Packt 可以了解你对我们的产品的看法，我们的作者可以看到你对他们书的反馈。谢谢！

关于 Packt 的更多信息，请访问[packt.com](http://www.packt.com/)。


# 第一部分：数字经济中的 MicroProfile

在本部分，您将学习为什么在数字经济中微服务很重要，以及 MicroProfile 如何解决企业 Java 微服务的需求。此外，您还将了解目前组成 MicroProfile 的子项目、它对组织和开发者的价值主张以及其当前的过程和治理（即，事情是如何完成的）。

本部分包含以下章节：

+   第一章，*Eclipse MicroProfile 简介*

+   第二章，*治理和贡献*


# 第一章：Eclipse MicroProfile 介绍

Eclipse MicroProfile 是一套用 Java 编写的微服务规范。这是一个由社区驱动的项目，市场上有很多实现。该项目于 2016 年 6 月首次宣布，继续开发一套适用于现代应用程序开发技术、架构和环境的 Java 微服务常见**应用程序编程接口**（**APIs**）。在本章中，您将了解 Eclipse MicroProfile 的起源和重要性。

本章将涵盖以下主题：

+   企业级 Java 微服务

+   推动数字经济的动力和多速度 IT 的需求

+   介绍 Eclipse MicroProfile

+   MicroProfile...

# 企业级 Java 微服务

应用程序开发不再包括使用运行在你最喜欢的操作系统上的单一高级编程语言。如今，有许多语言、规范、框架、专有和开源软件及工具、底层部署基础设施和开发方法，程序员需要学习这些来开发现代应用程序。在 IT 组织中，开发已经变得多语言化了，也就是说，根据特定项目的需求，会使用多种编程语言。在这个云计算、容器、微服务、反应式编程、12 因子应用程序、无服务器、MINI 服务、多语言环境和等等的时代，开发者现在可以选择合适的工具来完成他们的任务，使他们更加有效和高效。

随着 Java EE 最近更名为 Jakarta EE，作为 Eclipse 基金会的一部分，MicroProfile 将在企业级 Java 的未来中发挥非常重要的作用，因为它与 Jakarta EE 的协同效应以及它可能对其产生影响的潜在方式。

云计算和移动设备的到来，以及开源的加速和物联网（**IoT**）的兴起，催生了数字经济。虽然这为新的市场打开了大门，但也对企业和他们的 IT 组织提出了新的要求，现在要求他们不仅要支持和维护传统的工作负载，还要更快地交付新的应用程序。

许多技术和语言、架构和框架在组织内变得流行，试图应对这些新的需求。其中一个是微服务，特别是企业级 Java 微服务，因为 Java 仍然是 IT 公司中最受欢迎的语言之一。但是什么是企业级 Java 微服务呢？

企业级 Java 微服务具有以下特点：

+   它是用 Java 语言编写的。

+   它可以使用任何 Java 框架。

+   它可以使用任何 Java API。

+   它必须是企业级的；也就是说，要可靠、可用、可扩展、安全、健壮且性能优良。

+   它必须满足微服务架构的特征，如在 [`martinfowler.com/microservices/`](https://martinfowler.com/microservices/) 所列出的那样，具体如下：

    +   通过服务实现组件化

    +   围绕业务能力组织

    +   产品而非项目

    +   智能端点和哑管

    +   去中心化治理

    +   去中心化数据管理

    +   基础设施自动化

    +   设计容错

    +   进化式设计

# 推动数字经济发展的力量

术语**数字经济**和**数字化转型**描述了改变企业需求的四个不同力量的汇聚：移动、云、物联网和开源：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/0c47035f-e6df-4c8c-be4d-0c7bb3f2227c.png)

在互联网出现之前，组织需要实体店铺或电话线来进行业务。互联网的出现和可访问性为组织创造了一个**关键的类别形成时间**的机会。企业开始主要使用互联网作为一个店面或展示，以吸引人们到他们的实体店铺。它也被用于广告目的。

不久之后，企业...

# 多速 IT

尽可能快地实施和交付应用程序并不是一个新的要求。实际上，自从第一台计算机的发明以来，提高效率一直计算机科学家的心头大事。高级编程语言、封装、可重用性、继承、事件驱动设计、SOA、微服务、机器学习和人工智能，都是旨在更快地完成事情的概念。随着每一波新技术的出现，变速箱为软件的开发和交付方式的演变增加了新的速度要求。数字经济又为变速箱增加了一个高速档位。

企业需要适应数字经济的新的要求。他们不仅要创建、运行和支持传统风格的应用程序，还要支持符合数字经济新要求的应用程序。他们必须支持瀑布和 DevOps 流程、混合云基础设施以及 SOA 和微服务架构。

这给 IT 组织带来了许多挑战，这些组织的流程、人员和技术都是为了实现、交付和维护传统风格的应用程序而设计的。许多组织已经开始了他们的数字化转型之旅，或者正准备开始，以应对数字经济带来的挑战。这一旅程包括改变应用程序开发、交付、集成和维护的技术、框架、语言和过程。

无论你称之为双模 IT（[`www.gartner.com/it-glossary/bimodal`](https://www.gartner.com/it-glossary/bimodal)）还是业务技术战略（[`go.forrester.com/wp-content/uploads/Forrester-False-Promise-of-Bimodal-IT.pdf`](https://go.forrester.com/wp-content/uploads/Forrester-False-Promise-of-Bimodal-IT.pdf)），事实是 IT 需要比以往任何时候都更快地满足业务需求，无论是现有还是新应用程序。这意味着 IT 还需要加快现有应用程序的维护和交付，同时专门为新的应用程序采用敏捷方法论。然而，这并不意味着不再使用不同的开发流程、发布周期和支持时间线来处理现有应用程序与新应用程序，这实际上是 IT 的多速度特性。

# 介绍 Eclipse MicroProfile

Java EE 已经成为一个极其成功的平台。Java 社区流程（Java Community Process，JCP）在其近 20 年的历史中，一直是超过 20 个兼容实现的监护人，促成了一个 400 亿美元产业。然而，Oracle 对 Java EE 的管理（无论是否无意）阻碍了创新，尽管其他标准已经发展，但全球 Java 社区和所有主要企业的 CIO 们都渴望在企业内部有一个开放的 Java 标准。

在早期阶段，J2EE 从 J2EE 1.2 迅速发展到 J2EE 1.4，因为该平台需要解决企业的迫切需求。从 2006 年 5 月 Java EE 5 开始，节奏开始变慢...

# MicroProfile 价值主张

对于信任 Java EE 来运行其生产工作负载的客户，Eclipse MicroProfile 为客户提供了企业 Java 微服务的开源、中立规范。Eclipse MicroProfile 使客户能够通过提高敏捷性和可伸缩性、缩短上市时间、提高开发生产力、简化调试和维护以及持续集成和持续部署，更好地满足业务需求。

使用 Eclipse MicroProfile 的客户获得的好处与使用微服务的好处相同。总的来说，根据受人尊敬的软件开发者、作家和演讲者马丁·福勒的说法，微服务提供以下好处([`martinfowler.com/articles/microservice-trade-offs.html`](https://martinfowler.com/articles/microservice-trade-offs.html)):

+   **强模块边界**：微服务加强了模块化结构，这对于大型团队尤为重要。

+   **独立部署**：简单的服务更易于部署，由于它们是自主的，因此在出错时更不可能导致系统故障。

+   **技术多样性**：通过微服务，你可以混合多种语言、开发框架和数据存储技术。

除了微服务的通用优势外，Eclipse MicroProfile 还特别提供了以下优势：

+   **社区协作的优势**：Eclipse MicroProfile 是一个由社区运行的开源项目。没有单一的供应商控制或决定规格说明书的演变和成熟。

+   **实施选择的自由**：许多供应商已将 Eclipse MicroProfile 作为其软件堆栈的一部分实现，客户可以选择最适合其环境的任何实现。

+   **更快的演变**：由于 Eclipse MicroProfile 是一个创新项目，新的和改进的功能经常在时间盒发布的周期内交付。这使得开发人员和客户能够掌握这些功能，并尽早而不是稍后在他们的项目中利用更新。

+   **基于数十年的经验：**不仅规格说明书的主题专家们带来了丰富的经验、专业知识和技能，Eclipse MicroProfile 还利用了在 Java EE API 中经过市场检验和生产验证的功能，它在此基础上构建，为开发者提供了成熟度。

+   **熟悉企业 Java**：Eclipse MicroProfile 建立在熟悉的企业 Java 构造之上，使得企业 Java 开发者易于采用。

+   **无需重新培训**：您的现有企业 Java 开发人员会发现 Eclipse MicroProfile 是他们专业知识的自然进步。学习曲线很小甚至没有。他们将能够利用他们的技能。

+   **互操作性：**不同的 MicroProfile 实现是互操作的，每个实现都为用户提供自由选择一个或结合许多 MicroProfile 实现于应用程序中的能力。

+   **多种使用 API 的方式：**Eclipse MicroProfile API 提供了易于使用的接口，如基于 CDI、程序化、命令行和基于文件（配置 based）的接口。

+   **一套完整的工件：**每个 API 都包括一个**测试兼容性套件**（**TCK**）、Javadoc、可下载的 PDF 文档、API Maven 工件坐标、Git 标签和下载（规格说明书和源代码）。

+   每个 API 特有的许多其他优势。这些在本书的每个 Eclipse MicroProfile 子项目中讨论。

# 总结

在本章中，我们讨论了软件开发的新趋势，包括使用新方法（如微服务、容器、移动和物联网（IoT））的多元语言部署，这些新方法运行在本地和云上；以及在混合或多云环境中。这些趋势要求 Enterprise Java 在微服务世界中进行演变，这就是 MicroProfile 所解决的问题。推动数字经济的四大力量，即云、移动、IoT 和开源，导致了组织需要多速度 IT 部门，这是维护和演变现有应用程序以及利用新技术趋势开发新应用程序的必要条件...

# 问题

1.  企业级 Java 微服务是什么？

1.  推动数字经济的四大力量是什么？

1.  为什么 IT 组织必须以不同的速度开发和维护应用程序？多速度 IT 是什么？

1.  为什么 Java 和 Java EE 对组织仍然重要？

1.  是什么关键原因导致了 MicroProfile 的产生？

1.  哪些 API/规范是 MicroProfile 伞/平台发布的一部分？

1.  哪个版本的 MicroProfile 引入了第一次革命性的变化？

1.  为什么 MicroProfile 对组织有价值？


# 第二章：治理和贡献

Eclipse MicroProfile 由社区成员治理。换句话说，它不是由单一的供应商来治理。此外，它还收到了来自开发者以及来自各种组织、公司和个体贡献者的贡献。该项目以其轻量级的过程和治理而著称，通过这些过程和治理，实现了创新、快速和敏捷。本章中的主题将帮助您了解 MicroProfile 项目的治理，您还将发现如何也能为 MicroProfile 项目做出贡献。

本章将涵盖以下主题：

+   如何治理 Eclipse MicroProfile 项目

+   社区如何协作并为其持续创新做出贡献……

# 当前的 Eclipse MicroProfile 治理

Eclipse MicroProfile 在其运营和决策过程中是透明的，这些过程旨在非常轻量级。治理重点是创建、创新和以协作方式发展规范。

Eclipse MicroProfile 首先是一个 Eclipse 项目，因此，它遵循 Eclipse 的流程。这包括提交者批准、项目发布、知识产权保护、许可证审查流程等。然而，Eclipse 基金会足够灵活，可以让像 MicroProfile 这样的项目提供一些额外的轻量级流程，以便多个规范可以并行推进，并有方法进行跨规范沟通和对齐规范。

其中一个轻量级过程是 Eclipse MicroProfile 的两周一次的 Hangout 会议/通话（其会议 URL 在 [`eclipse.zoom.us/j/949859967`](https://eclipse.zoom.us/j/949859967)，其录音可以在 Eclipse MicroProfile YouTube 频道上找到，该频道地址为 [`www.youtube.com/channel/UC_Uqc8MYFDoCItFIGheMD_w`](https://www.youtube.com/channel/UC_Uqc8MYFDoCItFIGheMD_w)），该会议对社区中的任何人开放，作为一个论坛，讨论与会者提出的话题并做出决定，包括子项目状态、发布内容、发布日期和子项目创建批准等。需要注意的是，尽管 MicroProfile 看起来像一个标准化组织，但它并不是。MicroProfile 是由社区创建的，它以社区确定的速度在不同子项目中进行创新。MicroProfile 定义的规范鼓励多种实现，这与标准化组织的做法类似。然而，MicroProfile 实际上是一个快速发展的开源项目，其源代码就是规范。

社区沟通、讨论和辩论的主要方式是 Eclipse MicroProfile Google 组([`groups.google.com/forum/#!forum/microprofile`](https://groups.google.com/forum/#!forum/microprofile)). 你可以使用你喜欢的网络浏览器在 Google 组中阅读、发布、回答或开始关于任何与 MicroProfile 相关的主题的论坛消息。你还可以使用该组的电子邮件来发起新的论坛消息。任何人都可以发起新的论坛线程来讨论话题，比如要添加到 MicroProfile 的潜在新功能。在社区在论坛上就新想法进行长时间讨论，并且/或者在 MicroProfile Hangout 通话中讨论后，确定值得进一步辩论，社区决定为这个新想法创建一个工作组，并指定一名负责人或一组负责人，他们通常是处理主题的专家，担任其协调员。

需要指出的一点重要方面是，工作组（或子项目）的负责人或负责人并不单独塑造或决定一个规范的演变或包括哪些功能以及不包括哪些功能。他们没有否决权或在关于他们规范的决策中没有最终决定权。通过分享想法、专业知识、过去经验、现有技术的分析以及最佳实践，工作组将提出他们最好的提案。此外，所有未解决的问题需要由社区讨论，并在需要时在两周一次的 Hangout 会议/通话中提出进一步辩论。通过讨论、协作和来自社区的反馈，分析了许多观点，使最佳选项或选项浮出水面。工作组将建立一个重复的每周或每两周一次的会议，该会议记录在 MicroProfile Google 日历中([`calendar.google.com/calendar/embed?src=gbnbc373ga40n0tvbl88nkc3r4%40group.calendar.google.com`](https://calendar.google.com/calendar/embed?src=gbnbc373ga40n0tvbl88nkc3r4%40group.calendar.google.com)). 这包含所有 MicroProfile Hangout 通话、MicroProfile 子项目通话和 MicroProfile 发布日期等信息。

虽然任何人都可以参加这些会议，但通常有一小部分人作为主题专家参与这些通话。在几次会议之后，工作组决定是否将新功能带到 MicroProfile Hangout 通话中讨论其成为 MicroProfile 子项目的提案。

在 MicroProfile Hangout 电话会议中，一个子项目提案可能会被拒绝或接受。应该说，当子项目提案带到 MicroProfile Hangout 电话会议时，是否应该向前推进的讨论大多数已经完成，所以会议上的决定对子项目工作组来说真的不应该感到惊讶。子项目的拒绝并不意味着它不满足一个特定的发展需求，而是对它的目标与推进 MicroProfile 规范的目标不匹配的肯定，该规范的目标是优化企业 Java 微服务架构。

例如，如果一个子项目提案解决了一个与微服务无关的需求，那么这个子项目提案很可能不会作为 MicroProfile 子项目向前推进。子项目的接受意味着它有效地解决了一个需求，丰富了规范，使其朝着优化企业 Java 微服务架构的目标前进。正是在这个时候，子项目变成了一个官方的 MicroProfile API。一旦子项目变成了一个 MicroProfile API，那么就需要决定它是作为一个独立子项目存在于 umbrella 之外，还是作为包含在 umbrella 中的子项目发布。这个过程的高级流程图如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/d7bcf79a-8471-4789-b9ed-0dd423e92624.png)

在撰写本书时，这些都是 Eclipse MicroProfile API/子项目（列出项目负责人）：

| **MicroProfile API/子项目名称** | **子项目负责人** |
| --- | --- |
| **MicroProfile 项目负责人** | 约翰·克莱根和凯文·舒特 |
| **配置** | 姜艾米莉和马克·斯特鲁布伯格 |
| **容错** | 姜艾米莉 |
| 健康检查 | 安托万·萨博-迪兰 |
| **JWT 传播** | 斯科特·斯塔克 |
| **指标** | 海因科·鲁普 |
| **OpenAPI** | 阿图尔·德·马加良埃斯 |
| **OpenTracing** | 帕沃·洛法伊 |
| **Rest 客户端** | 约翰·D·阿门特和安迪·麦克莱恩特 |

Eclipse MicroProfile 遵循一个时间盒式的快速增量发布计划，该计划是公开的，列在 Eclipse 基金会 MicroProfile 项目页面([`projects.eclipse.org/projects/technology.microprofile`](https://projects.eclipse.org/projects/technology.microprofile))上。例如，从 1.x 到 2.x 的主要 Eclipse MicroProfile 发布，包括对 MicroProfile API 的重大更新，可能会引入破坏性变化。次要发布，即点发布，包括小的 API 更新或新的 API，以确定的发布日期为准。目前，MicroProfile 社区的发布窗口每年在二月、六月和十一月，适用于次要和/或主要发布。

# 开放贡献的沙箱方法

为潜在的 MicroProfile 子项目创建的工作组也可能被分配一个沙盒，这是 MicroProfile 社区提供尝试新想法的另一个资源。沙盒仓库是一个位于 [`github.com/eclipse/microprofile-sandbox`](https://github.com/eclipse/microprofile-sandbox) 的 GitHub 仓库，用于孵化想法和代码示例，这些最终将变成新规范的独立仓库。任何人都可以打开拉取请求，并使用沙盒进行新想法的实验，以及分享代码和文档，这些可以作为社区 Google 组、MicroProfile 闲聊电话或工作组会议讨论的一部分。保持您的拉取请求开放...

# 伞状发布与伞状之外的项目

Eclipse MicroProfile 是由一系列具有特定焦点的规范组成。例如，Eclipse MicroProfile Config 规范涵盖了所有与为微服务配置参数相关的内容。一个规范的版本可以作为 Eclipse MicroProfile 的伞状发布的一部分包含在内，或者在伞状之外发布。作为一个具体的例子，Eclipse MicroProfile 2.2 的最新伞状发布，于 2019 年 2 月 12 日发布，包括了以下规范：

+   Eclipse MicroProfile Open Tracing 1.3

+   Eclipse MicroProfile Open API 1.1

+   Eclipse MicroProfile Rest Client 1.2

+   Eclipse MicroProfile Fault Tolerance 2.0

+   Eclipse MicroProfile Config 1.3

+   Eclipse MicroProfile Metrics 1.1

+   Eclipse MicroProfile JWT Propagation 1.1

+   Eclipse MicroProfile Health Check 1.0

+   CDI 2.0

+   JSON-P 1.1

+   JAX-RS 2.1

+   JSON-B 1.0

然而，Eclipse MicroProfile 还有其他一些在非伞状发布中发布的规范。例如，我们在第九章“响应式编程与未来发展”中介绍的 Eclipse MicroProfile Reactive Streams Operators 1.0，就是一个最近在非伞状发布中发布的规范。那么，为什么 MicroProfile 允许在伞状之外的规范呢？原因在于，首先在伞状之外发布，可以为社区和最终用户提供使用和测试新技术的机会，因此在被纳入伞状之前，在真实应用中验证这些技术。

# MicroProfile Starter

MicroProfile Starter 是一个示例源代码生成器，其目标是帮助开发者快速开始使用和利用由社区驱动的开源企业 Java 微服务规范 Eclipse MicroProfile，通过在 Maven 项目中生成可工作的示例代码。

自 2016 年中旬项目创建以来，就有了 MicroProfile Starter 的想法，并在 2016 年 Devoxx BE（2016 年 11 月 7 日那周）上公开讨论。在 MicroProfile Starter 项目发布的前两周里，世界各地的开发者通过这个项目创建了超过 1200 个项目，这是对其在全球范围内采用的一个良好和积极的迹象。

# 快速游览 MicroProfile Starter

让我们快速了解一下 MicroProfile Starter：

1.  当你访问**MicroProfile Starter "Beta"**页面，[`start.microprofile.io/`](https://start.microprofile.io/)，你会看到以下登录页面：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/5bc19663-c627-42b8-a08a-350ce79a877c.png)

对于 Maven 相关的参数，你可以接受默认值（[`maven.apache.org/guides/mini/guide-naming-conventions.html`](https://maven.apache.org/guides/mini/guide-naming-conventions.html)），groupId 和 artifactId，或者按照喜好更改。groupId 参数能唯一标识你的项目，artifactId 是 JAR 文件名，不包含 MicroProfile 版本号。在这个游览中，接受所有默认值。

1.  接下来，从下拉列表中选择 MicroProfile Version：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/1331ec98-e279-496c-ac0a-801886cbfb85.png)

在这个游览中，选择 MicroProfile 版本 MP 2.1。注意，根据你选择的 MicroProfile 版本，示例规格部分列出的规格数量会有所变化。这个数字取决于每个 MicroProfile 伞状发布中包含多少 API。要了解每个版本中包含哪些 API，请参考 MicroProfile 社区演讲（[`docs.google.com/presentation/d/1BYfVqnBIffh-QDIrPyromwc9YSwIbsawGUECSsrSQB0/edit#slide=id.g4ef35057a0_6_205`](https://docs.google.com/presentation/d/1BYfVqnBIffh-QDIrPyromwc9YSwIbsawGUECSsrSQB0/edit#slide=id.g4ef35057a0_6_205)）。

1.  然后，从下拉列表中选择 MicroProfile Server：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/c101fb03-4a50-4586-898c-c49210885448.png)

在这个游览中，选择 Thorntail V2，这是红帽用来实现 Eclipse MicroProfile 规范的开源项目。

1.  保留所有**示例规格**复选框的选择（也就是说，不要取消选中任何复选框）：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/c64b1d4b-bb8c-46bd-a45e-9a4cd9dad36e.png)

这将生成包含 MicroProfile 版本 2.1 中所有 API 的示例工作代码。

1.  使用 MicroProfile Starter 生成示例源代码过程的最后一步是点击 DOWNLOAD 按钮，这将创建一个 ZIP 归档文件。确保将`demo.zip`文件保存到你的本地驱动器上。然后在你的本地驱动器上解压`demo.zip`。内容应如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/560eb505-0fe8-43ce-994c-84a6db717b1f.png)

请注意生成的内容中有一个`readme.md`文件。这个文件包含了如何编译和运行生成代码的说明，这包括一个练习 Eclipse MicroProfile 不同功能的示例网络应用程序。

1.  更改目录到你解压演示项目的位置。在我的情况下，我把它放在了我的`Downloads`目录中：

```java
$ cd Downloads/demo
```

1.  通过输入以下命令编译生成的示例代码：

```java
$ mvn clean package
```

1.  运行微服务：

```java
$ java -jar target/demo-thorntail.jar
```

1.  几秒钟后，你将看到以下消息：

```java
$ INFO  [org.wildfly.swarm] (main) WFSWARM99999: Thorntail is Ready
```

这表明微服务正在运行。

1.  打开你喜欢的网页浏览器，指向`http://localhost:8080/index.html`。

这将打开示例网络应用程序，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/37b7bd6b-1714-437d-aacf-8dd2123ff8cd.png)

1.  要查看 MicroProfile Config 的功能，点击注入的配置值。将打开一个窗口标签，显示以下内容：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/7bf94342-0d9e-43ad-8c5e-0cf0bc67be4a.png)

1.  同样，如果你点击通过查找查看配置值，将显示另一个窗口标签如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/d58d0ff0-17c1-4cf7-8a1c-647dfc6f5e2a.png)

我们之前看到的参数值的*注入值*和*查找值*定义在`./demo/src/main/resources/META-INF/microprofile-config.properties`文件中，如下所示：

```java
$ cat ./src/main/resources/META-INF/microprofile-config.properties
injected.value=Injected value
value=lookup value
```

1.  假设你需要为`value`参数在开发和系统测试之间使用不同的值。你可以通过在启动微服务时传递命令行参数来实现这一点（首先确保按终端窗口上的*Ctrl* + *C*退出运行中的应用程序）：

```java
$ java -jar target/demo-thorntail.jar -Dvalue=hola
```

1.  现在，当你点击通过查找查看配置值时，将显示另一个窗口标签：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/faf2d928-0fb2-49ef-82bc-9a67409b6aa6.png)

请注意，执行此逻辑的源代码位于生成的`./src/main/java/com/example/demo/config/ConfigTestController.java`文件中。

1.  要查看 MicroProfile Fault Tolerance 的功能，点击超时后的回退。将打开一个窗口标签，显示以下内容：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-etp-java-msvc-eclp-mprf/img/dc1dcb42-0d68-4030-b163-186cae70d6bd.png)

有关 MicroProfile Config API 的更多信息，请参阅其文档([`github.com/eclipse/microprofile-config/releases/download/1.3/microprofile-config-spec-1.3.pdf`](https://github.com/eclipse/microprofile-config/releases/download/1.3/microprofile-config-spec-1.3.pdf))。

示例代码演示了`@Fallback`注解与`@Timeout`的组合使用。以下是示例代码：

```java
@Fallback(fallbackMethod = "fallback") // fallback handler
   @Timeout(500)
   @GET
   public String checkTimeout() {
     try {
       Thread.sleep(700L);
     } catch (InterruptedException e) {
       //
     }
     return "Never from normal processing";
   }
   public String fallback() {
   return "Fallback answer due to timeout";
   }
```

`@Timeout`注解指定如果方法执行时间超过 500 毫秒，应抛出超时异常。此注解可以与`@Fallback`一起使用，在这种情况下，当发生超时异常时调用回退处理程序。在前面的示例代码中，超时异常总是发生，因为方法正在执行——即，休眠 700 毫秒，这超过了 500 毫秒。

请注意，执行此逻辑的源代码位于生成的`./src/main/java/com/example/demo/resilient/ResilienceController.java`文件中。

有关 MicroProfile 容错 API 的更多信息，请参阅其文档([`github.com/eclipse/microprofile-opentracing/releases/download/1.2/microprofile-opentracing-spec-1.2.pdf`](https://github.com/eclipse/microprofile-opentracing/releases/download/1.2/microprofile-opentracing-spec-1.2.pdf))。

微 Profile 社区欢迎您提供反馈以及与微 Profile Starter 项目的协作或贡献。要提供反馈，您需要点击 MicroProfile Starter "Beta"页面右上角的“提供反馈”按钮（[`start.microprofile.io/`](https://start.microprofile.io/)）并创建一个问题。

微 Profile Starter 项目会将请求的项目和修复按照里程碑进行分组和优先排序，目标是持续发布。MicroProfile Starter 工作组定期召开会议，如果您想用您的开发技能帮助该项目，请发送电子邮件至`microprofile@googlegroups.com`或加入其 Gitter 频道讨论（[`gitter.im/eclipse/microprofile-starter`](https://gitter.im/eclipse/microprofile-starter)）。项目的信息，包括源代码的位置，可以在[`wiki.eclipse.org/MicroProfile/StarterPage`](https://wiki.eclipse.org/MicroProfile/StarterPage)找到。

# 总结

在本章中，我们学习了 Eclipse 微 Profile 项目的轻量级治理流程，其快速的创新方法，以及如何使用沙盒促进协作和鼓励代码开发和文档。我们还了解了其子项目，这些子项目的领导者，以及它们可以作为独立版本发布，或者作为 Eclipse 微 Profile 伞式发布的一部分发布。

此外，您还了解了 MicroProfile Starter，这是一个 Maven 项目生成工具，提供代码示例，以便开发者可以快速启动他们的 MicroProfile 应用程序。最后，我们简要介绍了如何使用 Eclipse MicroProfile Config 构造轻松修改应用程序的属性...

# 问题

1.  微 Profile 社区的主要沟通方式是什么？

1.  双周一次的 MicroProfile Hangout 电话会议的目标是什么？

1.  子项目（微 Profile 规范）负责人/负责人的角色是什么？

1.  一个新的微 Profile 规范提案遵循的过程是什么？

1.  微 Profile 项目遵循的发布计划是什么？

1.  微 Profile 沙盒的目标是什么？

1.  在伞式/平台 MicroProfile 发布下发布项目和在外部发布的项目有什么区别？

1.  微 Profile Starter 是什么，它提供了哪些好处？


# 第三章：第二节：MicroProfile 的当前功能

本节将介绍项目的功能及其子项目的功能，并提供代码示例。

本节包含以下章节：

+   第三章，*MicroProfile 配置和容错*

+   第四章，*MicroProfile 健康检查和 JWT 传播*

+   第五章，*MicroProfile 指标和 OpenTracing*

+   第六章，*MicroProfile OpenAPI 和类型安全 REST 客户端*


# 第四章：微服务配置和容错

在本章中，我们将首先介绍微服务配置，因为它是其他微服务功能配置的基础，除了应用程序级配置。微服务配置规范提供了一种通用方法，用于从各种来源（属性文件、系统属性、环境变量、数据库等）检索配置。

我们将涵盖的主题包括以下内容：

+   从您的应用程序读取配置

+   为您的应用程序提供额外的配置源

+   提供将普通配置转换为特定于应用程序对象的转换

# 理解 Eclipse 微服务配置

每个应用程序都需要一些外部配置，以使其行为适应其正在运行的运行时平台。这可以从应用程序必须连接到的 HTTP 端点，或者某些内部结构的大小。

这些配置参数也可以来自不同的来源：

+   从操作系统或云原生环境中的容器（通过使用环境变量）

+   从 Java 虚拟机（通过系统属性）

+   从一些外部配置文件（如 Java 属性文件）

+   从其他地方（如 LDAP 服务器、数据库、键值存储等）

一方面，这些配置参数来自许多不同的来源。在...

# 从微服务配置 API 读取配置

微服务配置规范定义了两个对象来读取配置参数的值：

+   使用`Config`对象以编程方式访问配置值

+   `@ConfigProperty`注解用于使用**上下文和依赖注入**（**CDI**）注入配置值

让我们详细讨论它们。

# 配置对象

`org.eclipse.microprofile.config.Config`接口是检索 Java 应用程序中配置的入口点。

获取`Config`实例有两种方法：

1.  第一种（且首选）方法是使用 CDI 将其注入代码中：

```java
@Inject
private Config config;
```

1.  第二种方法是调用静态方法`org.eclipse.microprofile.config.ConfigProvider#getConfig()`，以获取`Config`实例：

```java
Config config = ConfigProvider.getConfig();
```

`Config`接口提供两种检索属性的方法：

+   `getValue(String propertyName, Class propertyType)`：如果配置中不存在该属性，此方法将抛出运行时异常。仅对于**必需**的配置才应使用此方法 ...

# `@ConfigProperty`注解

`@ConfigProperty`注解可用于使用 CDI 将配置值注入 Java 字段或方法参数，如所示：

```java
@Inject
@ConfigProperty(name="my.url")
private URL myURL;
```

`@ConfigProperty`注解可以有一个`defaultValue`，如果在底层的`Config`中找不到配置属性，则用于配置字段：

```java
@Inject
@ConfigProperty(name="my.url", defaultValue="http://localhost/")
private URL myURL;
```

如果未设置`defaultValue`且未找到任何属性，应用程序将抛出`DeploymentException`，因为无法正确配置。

如果一个配置属性可能不存在，可以使用`Optional`，如下面的代码块所示：

```java
@Inject
@ConfigProperty(name="my.url")
private Optional<URL> someUrl; // will be set to Optional.empty if the
                               // property `my.url` cannot be found
```

在读取配置之后，我们需要提供源配置源，这部分将在下一节中介绍。

# 提供配置源

配置源由`ConfigSource`接口表示。除非你想提供在你应用程序中使用的 MicroProfile 实现不可用的配置源，否则你不需要实现这个接口。

如果在多个配置源中找到了一个属性，`Config`将返回`ConfigSource`接口中序号最高的值。

排序`ConfigSource`很重要，因为用户可以提供自定义的`ConfigSource`接口，这除了由 MicroProfile Config 实现提供的默认接口。

# 默认的 ConfigSources

默认情况下，一个 MicroProfile Config 实现必须提供三个配置源：

+   来自 Java 虚拟机系统的属性（序号为`400`）

+   环境变量（序号为`300`）

+   存储在`META-INF/microprofile-config.properties`中的属性（序号为`100`）

配置源的`ordinal`值决定了配置源的优先级。特别是，如果一个属性既在系统属性中定义，又在环境变量中定义，将采用系统属性的值（其序号高于环境变量）。

属性名没有限制。然而，一些操作系统可能会对环境变量的名称施加一些限制（例如，大多数 Unix 壳牌不允许`"."`）。如果您有一个可能从环境变量中配置的属性，您必须相应地命名您的属性。

例如，属性名`my_url`可以由环境变量使用，而`my.url`则不行。

**MicroProfile Config 1.3 新特性** MicroProfile Config 1.3 引入了一个从配置属性名到环境变量的映射规则。这个规则为每个属性名搜索三个环境变量的变体：

+   精确匹配

+   将任何非字母数字字符替换为`_`

+   将任何非字母数字字符替换为`_`并使用大写字母

这意味着，在 Java 应用程序中，我们可以有一个名为`app.auth.url`的属性，并使用`APP_AUTH_URL`环境变量来配置它。

接下来让我们看看另一种配置源。

# 自定义 ConfigSources 实现

在您的应用程序中，可以提供额外的配置源，这些源将由 MicroProfile Config 实现自动添加。

你需要定义一个`org.eclipse.microprofile.config.spi.ConfigSource`的实现，并为它添加一个 Java `ServiceLoader`配置，并将该文件放在你的应用程序归档中作为`META-INF/services/` `org.eclipse.microprofile.config.spi.ConfigSource`。供您参考，以下是一个环境`ConfigSource`实现定义的示例：

```java
package io.packt.sample.config;import java.io.Serializable;import java.util.Collections;import java.util.Map;import org.eclipse.microprofile.config.spi.ConfigSource;public class EnvConfigSource ...
```

# 使用转换器进行高级配置

MicroProfile Config 将从其`ConfigSource`读取 Java `String`对象。然而，它提供了将这些`String`对象转换为应用程序中更具体类型的设施。

例如，我们之前描述的`myUrl`字段是一个`URL`对象。相应的属性`my.url`以`String`对象的形式读取，然后在被注入之前转换为`URL`对象。

如果应用程序使用`Config`对象，MicroProfile Config 实现也将把`String`对象转换为`getValue`和`getOptionalValue`方法的第二个参数传递的类型。这个转换可以使用不同的转换器类型：内置、自动和自定义。我们现在将详细讨论它们。

# 内置转换器

MicroProfile Config 实现为基本类型（`boolean`、`int`、`long`、`byte`、`float`和`double`）及其对应的 Java 类型（例如`Integer`）提供了内置转换器。

它还提供了使用`","`作为项目分隔符在属性值中支持数组的功能。如果`","`必须是项目的一部分，它必须用反斜杠`"\"`转义：

```java
private String[] pets = config.getValue("myPets", String[].class)
```

如果`myPets`属性的值是`dog,cat,dog\\,cat`，存储在`pets`中的数组的元素将是`{"dog", "cat", "dog,cat"}`。

# 自动转换器

MicroProfile Config 还定义了*自动转换器*。如果一个转换器对给定的 Java 类型未知，它将尝试使用三种不同的方法之一将`String`对象转换为它：

+   Java 类型有一个带有`String`参数的公共构造函数。

+   它有一个`public static valueOf(String)`方法。

+   它有一个`public static parse(String)`方法。

这就是`my.url`属性如何从`String`转换为`URL`，因为`java.net.URL`类型有一个`public URL(String)`构造函数。

# 自定义转换器

如果你的应用程序定义了 Java 类型，这些类型不提供自动转换器涵盖的这三个案例，MicroProfile Config 仍然可以使用自定义转换器提供转换，这些转换器扩展了以下定义的`org.eclipse.microprofile.config.spi.Converter`接口：

```java
public interface Converter<T> {
    /**
     * Configure the string value to a specified type
     * @param value the string representation of a property value.
     * @return the converted value or null
     *
     * @throws IllegalArgumentException if the value cannot be converted to        the specified type.
     */
    T convert(String value);
```

你必须编写一个`org.eclipse.microprofile.config.spi.Converter`的实现，然后将其名称添加到`/META-INF/services/org.eclipse.microprofile.config.spi.Converter ...`

# 理解 Eclipse MicroProfile 容错

容错提供了一组工具，通过使代码更具弹性来防止代码失败。其中大多数工具受到了良好的开发实践（如重试或回退）或知名开发模式（如断路器或隔舱）的启发。

容错基于 CDI ，更确切地说，是基于 CDI 拦截器实现。它还依赖于 MicroProfile Config 规范，以允许为容错策略提供外部配置。

规范的主要思想是将业务逻辑与容错样板代码解耦。为了实现这一点，规范定义了拦截器绑定注解，以在方法执行或类上（在这种情况下，所有类方法具有相同的策略）应用容错策略。

容错规范中包含的政策如下：

+   **超时**：这是使用`@Timeout`注解 applied。它在当前操作中添加了超时。

+   **重试**：这是使用`@Retry`注解 applied。它添加了重试行为，并允许对当前操作进行配置。

+   **回退**：这是使用`@Fallback`注解 applied。它定义了在当前操作失败时应执行的代码。

+   ** bulkhead**：这是使用`@Bulkhead`注解 applied。它将当前操作中的故障隔离以保留其他操作的执行。

+   **断路器**：这是使用`@CircuitBreaker`注解 applied。它提供了一个自动快速失败的执行，以防止系统过载。

+   **异步**：这是使用`@Asynchronous`注解 applied。它将当前操作设置为异步（也就是说，代码将异步调用）。

应用这些策略之一或多个就像在需要这些策略的方法（或类）上添加所需的注解一样简单。所以，使用容错是非常简单的。但这种简单性并没有阻止灵活性，感谢所有可用配置参数每个策略。

目前，以下供应商为 Fault Tolerance 规范提供实现：

+   Red Hat in Thorntail and Quarkus

+   IBM in Open Liberty

+   Payara in Payara Server

+   Apache Safeguard for Hammock and TomEE

+   KumuluzEE for KumuluzEE framework

所有这些实现都支持容错，因此支持下一节中描述的相同一组功能。

# MicroProfile Fault Tolerance in action

正如我们刚刚讨论的，Fault Tolerance 规范提供了一组注解，您需要将这些注解应用于类或方法以强制执行容错策略。话虽如此，您必须记住这些注解是拦截器绑定，因此仅适用于 CDI bean。所以，在将容错注解应用于它们或其方法之前，请务必小心地将您的类定义为 CDI beans。

在以下各节中，您将找到每个容错注解的用法示例。

# The @Asynchronous policy

使操作异步就像以下这样简单：

```java
@Asynchronous
public Future<Connection> service() throws InterruptedException {
  Connection conn = new Connection() {
    {
      Thread.sleep(1000);
    }

    @Override
    public String getData() {
      return "service DATA";
    }
 };
 return CompletableFuture.completedFuture(conn);
}
```

唯一的限制是`@Asynchronous`方法必须返回`Future`或`CompletionStage`；否则，实现应该抛出异常。

# `@Retry`策略

如果操作失败，你可以应用重试策略，以便再次调用操作。`@Retry`注解可以像这样应用于类或方法级别：

```java
@Retry(maxRetries = 5, maxDuration= 1000, retryOn = {IOException.class})public void operationToRetry() {  ...}
```

在前一个示例中，操作应该只在发生`IOException`时最多重试五次。如果所有重试的总持续时间超过 1,000 毫秒，则操作将被取消。

# `@Fallback`策略

`@Fallback`注解只能应用于方法；注释类将产生意外结果：

```java
@Retry(maxRetries = 2)
@Fallback(StringFallbackHandler.class)
public String shouldFallback() {
  ...
}
```

在达到重试次数后调用回退方法。在前一个示例中，如果出现错误，方法将重试两次，然后使用回退调用另一段代码——在这个例子中，下面的`StringFallbackHandler`类：

```java
import javax.enterprise.context.ApplicationScoped;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.faulttolerance.ExecutionContext;
import org.eclipse.microprofile.faulttolerance.FallbackHandler;

@ApplicationScoped
public class StringFallbackHandler implements FallbackHandler<String> {
    @ConfigProperty(name="app1.requestFallbackReply", defaultValue = "Unconfigured Default Reply")
    private String replyString;

    @Override
    public String handle(ExecutionContext ec) {
        return replyString;
    }
}
```

可以通过实现`FallbackHandler`接口的类或当前 bean 中的方法定义回退代码（见前一个代码）。在`StringFallbackHandler`代码中，使用了名为`app1.requestFallbackReply`的 MicroProfile Config 属性来外部化应用程序的回退字符串值。

# `@Timeout`策略

`@Timeout`注解可以应用于类或方法，以确保操作不会永远持续：

```java
@Timeout(200)public void operationCouldTimeout() {  ...}
```

在前一个示例中，如果操作持续时间超过 200 毫秒，则将停止操作。

# `@CircuitBreaker`策略

`@CircuitBreaker`注解可以应用于类或方法。电路断路器模式由马丁·福勒引入，旨在通过使其在功能失调时快速失败来保护操作的执行：

```java
@CircuitBreaker(requestVolumeThreshold = 4, failureRatio=0.75, delay = 1000)
public void operationCouldBeShortCircuited(){
  ...
}
```

在前一个示例中，方法应用了`CircuitBreaker`策略。如果在四个连续调用滚动窗口中发生三次（*4 x 0.75*）失败，则电路将被打开。电路将在 1,000 毫秒后保持打开状态，然后回到半开状态。在一个成功的调用之后，电路将再次关闭。

# `@Bulkhead`策略

`@Bulkhead`注解也可以应用于类或方法以强制执行 bulkhead 策略。这种模式通过限制给定方法的同时调用次数来隔离当前操作中的故障，以保留其他操作的执行。

```java
@Bulkhead(4)public void bulkheadedOperation() {  ...}
```

在前一个代码中，这个方法只支持四个同时调用。如果超过四个同时请求进入`bulkheadedOperation`方法，系统将保留第五个及以后的请求，直到四个活动调用之一完成。bulkhead 注解还可以与`@Asynchronous`结合使用，以限制异步中的线程数...

# 微配置中的容错性

正如我们在前几节所看到的，Fault Tolerance 策略是通过使用注解来应用的。对于大多数用例来说，这已经足够了，但对于其他一些情况，这种方法可能不令人满意，因为配置是在源代码级别完成的。

这就是为什么 MicroProfile Fault Tolerance 注解的参数可以通过 MicroProfile Config 进行覆盖的原因。

注解参数可以通过使用以下命名约定来通过配置属性覆盖：`<classname>/<methodname>/<annotation>/<parameter>`。

要覆盖`MyService`类中`doSomething`方法的`@Retry`的`maxDuration`，请像这样设置配置属性：

```java
org.example.microservice.MyService/doSomething/Retry/maxDuration=3000
```

如果需要为特定类配置与特定注解相同的参数值，请使用`<classname>/<annotation>/<parameter>`配置属性进行配置。

例如，使用以下配置属性来覆盖`MyService`类上`@Retry`的所有`maxRetries`为 100：

```java
org.example.microservice.MyService/Retry/maxRetries=100
```

有时，需要为整个微服务（即在部署中所有注解的出现）配置相同的参数值。

在这种情况下，`<annotation>/<parameter>`配置属性将覆盖指定注解的相应参数值。例如，要覆盖所有`@Retry`的`maxRetries`为 30，请指定以下配置属性：

```java
Retry/maxRetries=30
```

这使我们结束了关于 MicroProfile 中的 Fault Tolerance 的讨论。

# 总结

在本章中，我们学习了如何使用 MicroProfile Config 来配置 MicroProfile 应用程序以及 MicroProfile Fault Tolerance 使其更具弹性。

在 MicroProfile Config 中，配置来源可以有很多；一些值来自属性文件，其他来自系统属性或环境变量，但它们都是从 Java 应用程序一致访问的。这些值可能会根据部署环境（例如，测试和生产）而有所不同，但在应用程序代码中这是透明的。

MicroProfile Fault Tolerance 通过在代码中应用特定策略来防止应用程序失败。它带有默认行为，但可以通过 MicroProfile 进行配置...

# 问题

1.  MicroProfile Config 支持哪些默认的配置属性来源？

1.  如果您需要将另一个配置属性源集成在一起，您可以做什么？

1.  只支持字符串类型的属性吗？

1.  将配置属性注入代码是否迫使您为该属性提供值？

1.  假设您有复杂的属性类型。是否有方法将它们集成到 MicroProfile Config 中？

1.  当一个 Fault Tolerance 注解应用于一个类时会发生什么？

1.  真或假：至少有 10 种不同的 Fault Tolerance 策略？

1.  `@Retry`策略是否需要在所有失败上进行重试？

1.  我们是否必须使用应用程序代码中使用的 Fault Tolerance 注解设置？

# 进一步阅读

关于 MicroProfile Config 特性的更多详细信息，可以在[`github.com/eclipse/microprofile-config/releases`](https://github.com/eclipse/microprofile-config/releases)的 MicroProfile Config 规范中找到。关于 MicroProfile Fault Tolerance 特性的更多详细信息，可以在[`github.com/eclipse/microprofile-fault-tolerance/releases`](https://github.com/eclipse/microprofile-fault-tolerance/releases)的 MicroProfile Config 规范中找到。


# 第五章：MicroProfile 健康检查与 JWT 传播

在本章中，我们将介绍健康检查项目及其关注点，它们的构造方式，以及在应用程序中如何使用它们。本章中的代码片段仅供参考。如果您需要一个工作的代码版本，请参考第八章，*一个工作的 Eclipse MicroProfile 代码示例*。

我们将涵盖以下主题：

+   健康检查是什么

+   MicroProfile 健康检查如何暴露健康检查端点和查询该端点的格式

+   如何为您的应用程序编写 MicroProfile 健康检查

+   MicroProfile JWT 传播中令牌的所需格式

+   如何利用 MicroProfile JWT 传播进行安全决策

# 技术要求

要构建和运行本章中的示例，您需要 Maven 3.5+和 Java 8 JDK。本章的代码可以在[`github.com/PacktPublishing/Hands-On-Enterprise-Java-Microservices-with-Eclipse-MicroProfile/tree/master/Chapter04-healthcheck`](https://github.com/PacktPublishing/Hands-On-Enterprise-Java-Microservices-with-Eclipse-MicroProfile/tree/master/Chapter04-healthcheck)和[`github.com/PacktPublishing/Hands-On-Enterprise-Java-Microservices-with-Eclipse-MicroProfile/tree/master/Chapter04-jwtpropagation`](https://github.com/PacktPublishing/Hands-On-Enterprise-Java-Microservices-with-Eclipse-MicroProfile/tree/master/Chapter04-jwtpropagation)找到，分别对应于 MicroProfile 健康检查和 MicroProfile 传播 JWT 部分。

# 理解健康检查以及 MicroProfile 如何处理它们

在云原生架构中，健康检查用于确定计算节点是否存活并准备好执行工作。就绪状态描述了容器启动或滚动更新（即，重新部署）时的状态。在此期间，云平台需要确保没有网络流量路由到该实例，直到它准备好执行工作。

生存性，另一方面，描述运行容器的状态；也就是说，当容器启动或滚动更新（即重新部署）时，它处于就绪状态。在此期间，云平台需要确保没有网络流量路由到该实例，直到它准备好执行工作。

健康检查是与云平台调度程序和应用程序编排框架之间的基本合同。检查程序由应用程序开发者提供，平台使用这些程序来持续确保应用程序或服务的可用性。

微服务健康检查 1.0（MP-HC）支持一个单一的健康检查端点，可以用于活动或就绪检查。微服务健康检查 2.0 计划添加对多个端点的支持，以允许应用程序定义活动和就绪探测器。

微服务健康检查规范详细介绍了两个元素：一个协议以及响应线缆格式部分和一个用于定义响应内容的 Java API。

微服务健康检查（MP-HC）特性的架构被建模为一个由零个或多个逻辑链接在一起的健康检查过程组成的应用程序，这些过程通过`AND`来推导出整体健康检查状态。一个过程代表了一个应用程序定义的检查一个必要条件的操作，它有一个名字、状态，以及可选的关于检查的数据。

# 健康检查协议和线缆格式

微服务健康检查规范定义了支持对逻辑`/health` REST 端点的 HTTP GET 请求的要求，该端点可能返回以下任一代码来表示端点的状态：

+   `200`：它正在运行并且是健康的。

+   `500`：由于未知错误而不健康。

+   `503`：它已经关闭，无法对请求做出响应。

请注意，许多云环境只是将请求返回代码视为成功或失败，所以`500`和`503`代码之间的区别可能无法区分。

`/health`请求的负载必须是一个与下面给出的架构匹配的 JSON 对象（有关 JSON 架构语法的更多信息，请参见[`jsonschema.net/#/`](http://jsonschema.net/#/)）。

下面是...

# 健康检查 Java API

大部分工作由实现微服务健康检查规范的应用程序框架完成。你的任务是通过使用微服务健康检查（MP-HC）API 定义的健康检查过程来决定活动或就绪是如何确定的。

为了实现这一点，你需要通过使用带有`Health`注解的 beans 实现一个或多个`HealthCheck`接口实例来执行健康检查过程。

`HealthCheck`接口如下：

```java
package org.eclipse.microprofile.health;

@FunctionalInterface
public interface HealthCheck {
  HealthCheckResponse call();
}
```

`Health`注解的代码如下：

```java
package org.eclipse.microprofile.health;

import javax.inject.Qualifier;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Qualifier
@Documented
@Retention(RetentionPolicy.RUNTIME)
public @interface Health {
}
```

下面的例子展示了一个表示假设磁盘空间检查状态的`HealthCheck`实现。注意检查将当前的空闲空间作为响应数据的一部分。`HealthCheckResponse`类支持一个构建器接口来填充响应对象。

下面是一个假设的磁盘空间`HealthCheck`过程实现：

```java
import javax.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.health.Health;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;

@Health
@ApplicationScoped
public class CheckDiskspace implements HealthCheck {
  @Override
  public HealthCheckResponse call() {
      return HealthCheckResponse.named("diskspace")
              .withData("free", "780mb")
              .up()
              .build();
  }
}
```

在这个例子中，我们创建了一个名为`diskspace`的健康响应，其状态为`up`，并带有名为`free`的自定义数据，其字符串值为`780mb`。

下面的例子展示了一个表示某些服务端点的健康检查示例。

下面展示了一个假设的服务`HealthCheck`过程实现：

```java
package io.packt.hc.rest;
//ServiceCheck example

import javax.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.health.Health;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;

@Health
@ApplicationScoped
public class ServiceCheck implements HealthCheck {
 public HealthCheckResponse call() {
 return HealthCheckResponse.named("service-check")
 .withData("port", 12345)
 .withData("isSecure", true)
 .withData("hostname", "service.jboss.com")
 .up()
 .build();
 }
}
```

在这个例子中，我们创建了一个名为`service-check`的健康响应，其状态为`up`，并包括了以下附加数据：

+   一个整数值为`12345`的`port`项

+   一个值为`true`的布尔`isSecure`项

+   一个值为`service.jboss.com`的字符串`hostname`项

由 CDI 管理的健康检查由应用程序运行时自动发现和注册。运行时自动暴露一个 HTTP 端点，`/health`，供云平台用来探测您的应用程序状态。您可以通过构建`Chapter04-healthcheck`应用程序并运行它来测试这一点。您将看到以下输出：

```java
Scotts-iMacPro:hc starksm$ mvn package
[INFO] Scanning for projects…
...
Resolving 144 out of 420 artifacts

[INFO] Repackaging .war: /Users/starksm/Dev/JBoss/Microprofile/PacktBook/Chapter04-metricsandhc/hc/target/health-check.war

[INFO] Repackaged .war: /Users/starksm/Dev/JBoss/Microprofile/PacktBook/Chapter04-metricsandhc/hc/target/health-check.war

[INFO] -----------------------------------------------------------------------

[INFO] BUILD SUCCESS

[INFO] -----------------------------------------------------------------------

[INFO] Total time:  7.660 s

[INFO] Finished at: 2019-04-16T21:55:14-07:00

[INFO] -----------------------------------------------------------------------

Scotts-iMacPro:hc starksm$ java -jar target/health-check-thorntail.jar

2019-04-16 21:57:03,305 INFO  [org.wildfly.swarm] (main) THORN0013: Installed fraction: MicroProfile Fault Tolerance - STABLE          io.thorntail:microprofile-fault-tolerance:2.4.0.Final

…

2019-04-16 21:57:07,449 INFO  [org.jboss.as.server] (main) WFLYSRV0010: Deployed "health-check.war" (runtime-name : "health-check.war")

2019-04-16 21:57:07,453 INFO  [org.wildfly.swarm] (main) THORN99999: Thorntail is Ready
```

一旦服务器启动，通过查询健康端点来测试健康检查：

```java
Scotts-iMacPro:Microprofile starksm$ curl -s http://localhost:8080/health | jq
{
 "outcome": "UP",
 "checks": [
   {
     "name": "service-check",
     "state": "UP",
     "data": {
       "hostname": "service.jboss.com",
       "port": 12345,
       "isSecure": true
     }
   },
   {
     "name": "diskspace",
     "state": "UP",
     "data": {
       "free": "780mb"
     }
   }
 ]
}
```

这显示了整体健康状况为`UP`。整体状态是应用程序中找到的所有健康检查程序的逻辑`OR`。在这个例子中，它是我们所看到的两个健康检查程序`diskspace`和`service-check`的`AND`。

# 与云平台的集成

大多数云平台都支持基于 TCP 和 HTTP 的检查。为了将健康检查与您选择的云平台集成，您需要配置云部署，使其指向托管应用程序的节点上的 HTTP 入口点，`/health`。

云平台将调用 HTTP 入口点的`GET`查询；所有注册的检查都将执行，个别检查的总和决定了整体结果。

通常，响应载荷被云平台忽略，它只查看 HTTP 状态码来确定应用程序的存活或就绪状态。成功的成果，`UP`，将被映射到`200`，而`DOWN`将被映射到`503`。

# 人类操作者

JSON 响应载荷的主要用例是提供一种让操作者调查应用程序状态的方式。为了支持这一点，健康检查允许将附加数据附加到健康检查响应中，正如我们在`CheckDiskspace`和`ServiceCheck`示例中所看到的那样。考虑以下片段：

```java
[...]
return HealthCheckResponse
           .named("memory-check")
           .withData("free-heap", "64mb")
           .up()
           .build();
[...]
```

在这里，提供了关于`free-heap`的附加信息，并将成为响应载荷的一部分，正如这个响应片段所示。显示`memory-check`程序内容的 JSON 响应片段如下：

```java
{
...
   "checks": [
       {
           "name": "memory-check",
           "state": "UP",
           "data": {
               "free-heap": "64mb"
           }
       }
   ],
   "outcome": "UP"
}
```

在这里，我们看到`memory-check`程序以其`UP`状态和字符串类型的附加`free-heap`数据项，值为`64mb`。

**Eclipse 资源/GitHub 中 MP-Health 的坐标**：

MP-Health 项目源代码可以在[`github.com/eclipse/microprofile-health`](https://github.com/eclipse/microprofile-health)找到。

# 健康检查响应消息的变化

MicroProfile Health Check 3.0 对健康检查 JSON 响应的消息格式进行了更改。具体来说，字段的成果和状态已经被字段状态所取代。

此外，在健康检查 3.0 版本中，`@Health`限定符已被弃用，而`@Liveness`和`@Readiness`限定符已被引入。对于这两个限定符，还引入了`/health/live`和`/health/ready`端点，分别调用所有存活性和就绪性程序。最后，为了向后兼容，`/health`端点现在会调用所有具有`@Health`、`@Liveness`或`@Readiness`限定符的程序。

是时候讨论 JWT 传播了。

# 在 MicroProfile 中使用 JSON Web Token 传播

一个**JSON Web Token**（**JWT**）是许多不同的基于 web 的安全协议中用于携带安全信息的一种常见格式。然而，JWT 的确切内容以及与已签名 JWT 一起使用的安全算法缺乏标准化。**微服务 JWT**（**MP-JWT**）传播项目规范审视了基于**OpenID Connect**（**OIDC**）的 JWT（[`openid.net/connect/`](http://openid.net/connect/)）规范，并在这些规范的基础上定义了一组需求，以促进基于 MicroProfile 的微服务中 JWT 的互操作性，同时还提供了从 JWT 中访问信息的 API。

有关 OIDC 和 JWT 如何工作的描述，包括应用程序/微服务如何拦截承载令牌，请参阅[`openid.net/connect/`](http://openid.net/connect/)上的*基本客户端实现指南*。

在本节中，您将了解以下内容：

+   为了互操作性，所需的 OIDC 和 JWT 规范中的声明和签名算法

+   使用 JWT 进行**基于角色的访问控制**（**RBAC**）的微服务端点

+   如何使用 MP-JWT API 来访问 JWT 及其声明值

# 互操作性的建议

MP-JWT 作为令牌格式的最大效用取决于身份提供商和服务提供商之间的协议。这意味着负责发行令牌的身份提供商应该能够以服务提供商可以理解的方式发行 MP-JWT 格式的令牌，以便服务提供商可以检查令牌并获取有关主题的信息。MP-JWT 的主要目标如下：

+   它应该可以用作认证令牌。

+   它应该可以用作包含通过组声明间接授予的应用级角色的授权令牌。

+   它支持 IANA JWT 分配（[`www.iana.org/assignments/jwt/jwt.xhtml`](https://www.iana.org/assignments/jwt/jwt.xhtml)）中描述的额外标准声明，以及非标准...

# 必需的 MP-JWT 声明

需要提供支持的 MP-JWT 声明集合包括以下内容：

+   `typ`：此头部参数标识令牌类型，必须是`JWT`。

+   `alg`：此头部算法用于签署 JWT，必须是`RS256`。

+   `kid`：这个头部参数提供了一个提示，关于用哪个公钥签署了 JWT。

+   `iss`：这是令牌的发行者和签名者。

+   `sub`：这标识了 JWT 的主题。

+   `exp`：这标识了 JWT 在或之后过期的时刻，此时 JWT 不得被处理。

+   `iat`：这标识了 JWT 的发行时间，可以用来确定 JWT 的年龄。

+   `jti`：这为 JWT 提供了一个唯一标识符。

+   `upn`：这是 MP-JWT 自定义声明，是指定用户主体名称的首选方式。

+   `groups`：这是 MP-JWT 自定义声明，用于分配给 JWT 主体的组或角色名称列表。

`NumericDate`用于`exp`、`iat`和其他日期相关声明是一个表示从`1970-01-01T00:00:00Z` UTC 直到指定 UTC 日期/时间的 JSON 数值值，忽略闰秒。此外，有关标准声明的更多详细信息可以在 MP-JWT 规范([`github.com/eclipse/microprofile-jwt-auth/releases/tag/1.1.1`](https://github.com/eclipse/microprofile-jwt-auth/releases/tag/1.1.1))和 JSON Web Token RFC([`tools.ietf.org/html/rfc7519`](https://tools.ietf.org/html/rfc7519))中找到。

一个基本的 MP-JWT 的 JSON 示例将是与 MP-JWT 兼容的 JWT 的示例头和载荷，如下所示：

```java
{
    "typ": "JWT",
    "alg": "RS256",
    "kid": "abc-1234567890"
}
{
    "iss": "https://server.example.com",
    "jti": "a-123",
    "exp": 1311281970,
    "iat": 1311280970,
    "sub": "24400320",
    "upn": "jdoe@server.example.com",
    "groups": ["red-group", "green-group", "admin-group", "admin"],
}
{
*** base64 signature not shown ***
}
```

此示例显示了具有`typ=JWT`、`alg=RS256`和`kid=abc-1234567890`的头部。正文包括`iss`、`jti`、`exp`、`iat`、`sub`、`upn`和`groups`声明。

# MP-JWT API 的高级描述

MP-JWT 项目在`org.eclipse.microprofile.jwt`包命名空间下引入了以下 API 接口和类：

+   `JsonWebToken`：这是`java.security.Principal`接口的一个扩展，通过 get 风格的访问器提供所需声明的集合，同时提供对 JWT 中任何声明的通用访问。

+   `Claims`：这是一个封装了所有标准 JWT 相关声明以及描述和返回自`JsonWebToken#getClaim(String)`方法的声明所需 Java 类型的枚举实用类。

+   `Claim`：这是一个用于指示`ClaimValue`注入点的限定注解。

+   `ClaimValue<T>`：这是`java.security.Principal`接口的一个扩展...

# 使用 MP-JWT 的示例代码

MP-JWT API 的基本用法是注入`JsonWebToken`、其`ClaimValue`或两者。在本节中，我们将展示典型用法的代码片段。本书本节代码可在[`github.com/PacktPublishing/Hands-On-Enterprise-Java-Microservices-with-Eclipse-MicroProfile/tree/master/Chapter04-jwtpropagation`](https://github.com/PacktPublishing/Hands-On-Enterprise-Java-Microservices-with-Eclipse-MicroProfile/tree/master/Chapter04-jwtpropagation)找到。

# 注入 JsonWebToken 信息

以下代码示例说明了如何访问传入的 MP-JWT 令牌作为`JsonWebToken`、原始 JWT 令牌字符串、`upn`声明以及与 JAX-RS`SecurityContext`的集成：

```java
package io.pckt.jwt.rest;import javax.annotation.security.DenyAll;import javax.annotation.security.PermitAll;import javax.annotation.security.RolesAllowed;import javax.inject.Inject;import javax.ws.rs.GET;import javax.ws.rs.Path;import javax.ws.rs.Produces;import javax.ws.rs.core.Context;import javax.ws.rs.core.MediaType;import javax.ws.rs.core.SecurityContext;import org.eclipse.microprofile.jwt.Claim;import org.eclipse.microprofile.jwt.Claims;import org.eclipse.microprofile.jwt.JsonWebToken;@Path("/jwt")@DenyAll //1public class ...
```

# 向 JWT 断言值注入

本节中的代码片段说明了 JWT 断言值的注入。我们可以使用几种不同的格式作为注入值。标准断言支持在`Claim#getType`字段和`JsonValue`子类型中定义的对象子类型。自定义断言类型只支持`JsonValue`子类型的注入。

以下代码示例说明了标准`groups`和`iss`断言的注入，以及`customString`、`customInteger`、`customDouble`和`customObject`自定义断言的注入：

```java
package io.pckt.jwt.rest;

import java.util.Set;
import javax.annotation.security.DenyAll;
import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.json.JsonArray;
import javax.json.JsonNumber;
import javax.json.JsonObject;
import javax.json.JsonString;
import javax.ws.rs.GET;
import javax.ws.rs.Path;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.Claims;

@Path("/jwt")
@DenyAll
public class InjectionExampleEndpoint {
    @Inject
    @Claim(standard = Claims.groups)
    Set<String> rolesSet; // 1
    @Inject
    @Claim(standard = Claims.iss)
    String issuer; // 2

    @Inject
    @Claim(standard = Claims.groups)
    JsonArray rolesAsJson; // 3
    @Inject
    @Claim(standard = Claims.iss)
    JsonString issuerAsJson; // 4
    // Custom claims as JsonValue types
    @Inject
    @Claim("customString")
    JsonString customString; // 5
    @Inject
    @Claim("customInteger")
    JsonNumber customInteger; // 6
    @Inject
    @Claim("customDouble")
    JsonNumber customDouble; // 7
    @Inject
    @Claim("customObject")
    JsonObject customObject; // 8

    @GET
    @Path("/printClaims")
    @RolesAllowed("Tester")
    public String printClaims() {
        return String.format("rolesSet=%s\n");
    }
}
```

八个注释注入如下：

1.  将标准`groups`断言作为其默认`Set<String>`类型注入

1.  将标准`iss`断言作为其默认字符串类型注入

1.  将标准`groups`断言作为其默认`JsonArray`类型注入

1.  将标准`iss`断言作为其默认`JsonString`类型注入

1.  向`JsonString`类型的`customString`断言中注入非标准自定义字符串

1.  向`JsonNumber`类型的非标准`customInteger`断言中注入

1.  向`JsonNumber`类型的非标准`customDouble`断言中注入

1.  向`JsonString`类型的`customObject`断言中注入非标准自定义对象

# 配置 JWT 的认证

为了接受 JWT 作为应进行认证并因此受信任的身份，我们需要配置 MP-JWT 功能以验证谁签署了 JWT 以及谁发布了 JWT。这是通过 MP-Config 属性完成的：

+   `mp.jwt.verify.publickey`：这提供了 MP-JWT 签名者的公钥材料，通常以 PKCS8 PEM 格式嵌入。

+   `mp.jwt.verify.issuer`：这指定了 JWT 中`iss`断言的预期值。

本书的一个`microprofile-configuration.properties`文件示例如下：

```java
# MP-JWT Configmp.jwt.verify.publickey=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlivFI8qB4D0y2jy0CfEqFyy46R0o7S8TKpsx5xbHKoU1VWg6QkQm+ntyIv1p4kE1sPEQO73+HY8+Bzs75XwRTYL1BmR1w8J5hmjVWjc6R2BTBGAYRPFRhor3kpM6ni2SPmNNhurEAHw7TaqszP5eUF/F9+KEBWkwVta+PZ37bwqSE4sCb1soZFrVz/UT/LF4tYpuVYt3YbqToZ3pZOZ9AX2o1GCG3xwOjkc4x0W7ezbQZdC9iftPxVHR8irOijJRRjcPDtA6vPKpzLl6CyYnsIYPd99ltwxTHjr3npfv/3Lw50bAkbT4HeLFxTx4flEoZLKO/g0bAoV2uqBhkA9xnQIDAQAB ...
```

# 运行示例

我们查看的示例可以部署到 Thorntail，并通过针对端点的命令行查询来验证预期行为。由于需要对带有安全约束的端点进行认证，因此我们需要一种生成将被 Thorntail 服务器接受的有效 JWT 的方法。

本章代码提供了一个`io.packt.jwt.test.GenerateToken`工具，该工具将由配置在 Thorntail 服务器上的密钥签发的 JWT。JWT 中包含的断言由本章项目的`src/test/resources/JwtClaims.json`文档定义。您使用`mvn exec:java`命令运行该工具，如下所示：

```java
Scotts-iMacPro:jwtprop starksm$ mvn exec:java -Dexec.mainClass=io.packt.jwt.test.GenerateToken -Dexec.classpathScope=test
[INFO] Scanning for projects...
[INFO]
[INFO] ----------------< io.microprofile.jwt:jwt-propagation >-----------------
[INFO] Building JWT Propagation 1.0-SNAPSHOT
[INFO] --------------------------------[ war ]---------------------------------
[INFO]
[INFO] --- exec-maven-plugin:1.6.0:java (default-cli) @ jwt-propagation ---
Setting exp: 1555684338 / Fri Apr 19 07:32:18 PDT 2019
 Added claim: sub, value: 24400320
 Added claim: customIntegerArray, value: [0,1,2,3]
 Added claim: customDoubleArray, value: [0.1,1.1,2.2,3.3,4.4]
 Added claim: iss, value: http://io.packt.jwt
 Added claim: groups, value: 
    ["Echoer","Tester","User","group1","group2"]
 Added claim: preferred_username, value: jdoe
 Added claim: customStringArray, value: ["value0","value1","value2"]
 Added claim: aud, value: [s6BhdRkqt3]
 Added claim: upn, value: jdoe@example.com
 Added claim: customInteger, value: 123456789
 Added claim: auth_time, value: 1555683738
 Added claim: customObject, value: {"my-service":{"roles":["role-in-my-
    service"],"groups":["group1","group2"]},"service-B":{"roles":["role-in-
    B"]},"service-C":{"groups":["groupC","web-tier"]},"scale":0.625}
 Added claim: exp, value: Fri Apr 19 07:32:18 PDT 2019
 Added claim: customDouble, value: 3.141592653589793
 Added claim: iat, value: Fri Apr 19 07:22:18 PDT 2019
 Added claim: jti, value: a-123
 Added claim: customString, value: customStringValue
eyJraWQiOiJcL3ByaXZhdGUta2V5LnBlbSIsInR5cCI6IkpXVCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIyNDQwMDMyMCIsImN1c3RvbUludGVnZXJBcnJheSI6WzAsMSwyLDNdLCJjdXN0b21Eb3VibGVBcnJheSI6WzAuMSwxLjEsMi4yLDMuMyw0LjRdLCJpc3MiOiJodHRwOlwvXC9pby5wYWNrdC5qd3QiLCJncm91cHMiOlsiRWNob2VyIiwiVGVzdGVyIiwiVXNlciIsImdyb3VwMSIsImdyb3VwMiJdLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJqZG9lIiwiY3VzdG9tU3RyaW5nQXJyYXkiOlsidmFsdWUwIiwidmFsdWUxIiwidmFsdWUyIl0sImF1ZCI6InM2QmhkUmtxdDMiLCJ1cG4iOiJqZG9lQGV4YW1wbGUuY29tIiwiY3VzdG9tSW50ZWdlciI6MTIzNDU2Nzg5LCJhdXRoX3RpbWUiOjE1NTU2ODM3MzgsImN1c3RvbU9iamVjdCI6eyJteS1zZXJ2aWNlIjp7InJvbGVzIjpbInJvbGUtaW4tbXktc2VydmljZSJdLCJncm91cHMiOlsiZ3JvdXAxIiwiZ3JvdXAyIl19LCJzZXJ2aWNlLUIiOnsicm9sZXMiOlsicm9sZS1pbi1CIl19LCJzZXJ2aWNlLUMiOnsiZ3JvdXBzIjpbImdyb3VwQyIsIndlYi10aWVyIl19LCJzY2FsZSI6MC42MjV9LCJleHAiOjE1NTU2ODQzMzgsImN1c3RvbURvdWJsZSI6My4xNDE1OTI2NTM1ODk3OTMsImlhdCI6MTU1NTY4MzczOCwianRpIjoiYS0xMjMiLCJjdXN0b21TdHJpbmciOiJjdXN0b21TdHJpbmdWYWx1ZSJ9.bF7CnutcQnA2gTlCRNOp4QMmWTWhwP86cSiPCSxWr8N36FG79YC9Lx0Ugr-Ioo2Zw35z0Z0xEwjAQdKkkKYU9_1GsXiJgfYqzWS-XxEtwhiinD0hUK2qiBcEHcY-ETx-bsJud8_mSlrzEvrJEeX58Xy1Om1FxnjuiqmfBJxNaotxECScDcDMMH-DeA1Z-nrJ3-0sdKNW6QxOxoR_RNrpci1F9y4pg-eYOd8zE4tN_QbT3KkdMm91xPhv7QkKm71pnHxC0H4SmQJVEAX6bxdD5lAzlNYrEMAJyyEgKuJeHTxH8qzM-0FQHzrG3Yhnxax2x3Xd-6JtEbU-_E_3HRxvvw
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  1.339 s
[INFO] Finished at: 2019-04-19T07:22:19-07:00
[INFO] ------------------------------------------------------------------------
```

该工具输出了添加的断言，然后打印出 Base64 编码的 JWT。您将使用这个 JWT 作为`curl`命令行中访问服务器端点的`Authorization: Bearer …`头部的值。

为了启动带有示例端点的 Thorntail 服务器，请进入`Chapter04-jwtpropagation`项目目录，然后运行`mvn`以构建可执行的 JAR：

```java
Scotts-iMacPro:jwtprop starksm$ mvn package
[INFO] Scanning for projects...
[INFO]
[INFO] ----------------< io.microprofile.jwt:jwt-propagation >-----------------
[INFO] Building JWT Propagation 1.0-SNAPSHOT
...
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  8.457 s
[INFO] Finished at: 2019-04-19T08:25:09-07:00
[INFO] ------------------------------------------------------------------------
```

生成的可执行 JAR 位于`target/jwt-propagation-thorntail.jar`。你使用本章的示例部署和`java -jar …`命令启动 Thorntail 服务器：

```java
Scotts-iMacPro:jwtprop starksm$ java -jar target/jwt-propagation-thorntail.jar
2019-04-19 08:27:33,425 INFO  [org.wildfly.swarm] (main) THORN0013: Installed fraction: MicroProfile Fault Tolerance - STABLE          io.thorntail:microprofile-fault-tolerance:2.4.0.Final
2019-04-19 08:27:33,493 INFO  [org.wildfly.swarm] (main) THORN0013: Installed fraction:          Bean Validation - STABLE io.thorntail:bean-validation:2.4.0.Final
2019-04-19 08:27:33,493 INFO  [org.wildfly.swarm] (main) THORN0013: Installed fraction:      MicroProfile Config - STABLE io.thorntail:microprofile-config:2.4.0.Final
2019-04-19 08:27:33,493 INFO  [org.wildfly.swarm] (main) THORN0013: Installed fraction:             Transactions - STABLE io.thorntail:transactions:2.4.0.Final
2019-04-19 08:27:33,494 INFO  [org.wildfly.swarm] (main) THORN0013: Installed fraction:        CDI Configuration - STABLE io.thorntail:cdi-config:2.4.0.Final
2019-04-19 08:27:33,494 INFO  [org.wildfly.swarm] (main) THORN0013: Installed fraction: MicroProfile JWT RBAC Auth - STABLE          io.thorntail:microprofile-jwt:2.4.0.Final
…
2019-04-19 08:27:37,708 INFO  [org.jboss.as.server] (main) WFLYSRV0010: Deployed "jwt-propagation.war" (runtime-name : "jwt-propagation.war")
2019-04-19 08:27:37,713 INFO  [org.wildfly.swarm] (main) THORN99999: Thorntail is Ready
```

在此阶段，我们可以查询服务器端点。有一个端点是我们定义的，不需要任何认证。这是`io.pckt.jwt.rest.SecureEndpoint`类的`jwt/openHello`端点。运行以下命令来验证你的 Thorntail 服务器是否如预期运行：

```java
Scotts-iMacPro:jwtprop starksm$ curl http://localhost:8080/jwt/openHello; echo
Hello[open] user=anonymous, upn=no-upn
```

接下来，尝试受保护的端点。它应该会因为未提供任何授权信息而失败，返回 401 未授权错误：

```java
Scotts-iMacPro:jwtprop starksm$ curl http://localhost:8080/jwt/secureHello; echo
Not authorized
```

现在，我们需要生成一个新的 JWT，并将其与 curl 命令一起在`Authorization`头中传递，让我们试一试。我们将使用 mvn 命令生成的 JWT 在 JWT 环境变量中保存，以简化 curl 命令行：

```java
Scotts-iMacPro:jwtprop starksm$ mvn exec:java -Dexec.mainClass=io.packt.jwt.test.GenerateToken -Dexec.classpathScope=test
[INFO] Scanning for projects...
[INFO]
[INFO] ----------------< io.microprofile.jwt:jwt-propagation >-----------------
[INFO] Building JWT Propagation 1.0-SNAPSHOT
[INFO] --------------------------------[ war ]---------------------------------
[INFO]
[INFO] --- exec-maven-plugin:1.6.0:java (default-cli) @ jwt-propagation ---
Setting exp: 1555688712 / Fri Apr 19 08:45:12 PDT 2019
 Added claim: sub, value: 24400320
 Added claim: customIntegerArray, value: [0,1,2,3]
 Added claim: customDoubleArray, value: [0.1,1.1,2.2,3.3,4.4]
 Added claim: iss, value: http://io.packt.jwt
 Added claim: groups, value: 
    ["Echoer","Tester","User","group1","group2"]
 Added claim: preferred_username, value: jdoe
 Added claim: customStringArray, value: ["value0","value1","value2"]
 Added claim: aud, value: [s6BhdRkqt3]
 Added claim: upn, value: jdoe@example.com
 Added claim: customInteger, value: 123456789
 Added claim: auth_time, value: 1555688112
 Added claim: customObject, value: {"my-service":{"roles":["role-in-my-
    service"],"groups":["group1","group2"]},"service-B":{"roles":["role-in-
    B"]},"service-C":{"groups":["groupC","web-tier"]},"scale":0.625}
 Added claim: exp, value: Fri Apr 19 08:45:12 PDT 2019
 Added claim: customDouble, value: 3.141592653589793
 Added claim: iat, value: Fri Apr 19 08:35:12 PDT 2019
 Added claim: jti, value: a-123
 Added claim: customString, value: customStringValue
eyJraWQiOiJ...
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  1.352 s
[INFO] Finished at: 2019-04-19T08:35:12-07:00
[INFO] ------------------------------------------------------------------------
Scotts-iMacPro:jwtprop starksm$ JWT="eyJraWQiOi..."
Scotts-iMacPro:jwtprop starksm$ curl -H "Authorization: Bearer $JWT" http://localhost:8080/jwt/secureHello; echo
Hello[secure] user=jdoe@example.com, upn=jdoe@example.com, scheme=MP-JWT, isUserRole=true
```

在前面的代码片段中，对于 Windows 用户，请为 Windows 安装一个与 bash 兼容的壳程序；否则，由于`echo`命令错误，你将遇到错误。

这次，查询成功，我们看到用户名`upn`声明值、方案和`isUserInRole("User")`检查都如预期一样。

现在，尝试访问`/jwt/printClaims`端点，该端点说明了标准和非标准声明作为不同类型的注入：

```java
Scotts-iMacPro:jwtprop starksm$ curl -H "Authorization: Bearer $JWT" http://localhost:8080/jwt/printClaims
+++ Standard claims as primitive types
rolesSet=[Echoer, Tester, User, group2, group1]
issuer=http://io.packt.jwt
+++ Standard claims as JSON types
rolesAsJson=["Echoer","Tester","User","group2","group1"]
issuerAsJson="http://io.packt.jwt"
+++ Custom claim JSON types
customString="customStringValue"
customInteger=123456789
customDouble=3.141592653589793
customObject={"my-service":{"roles":["role-in-my-service"],"groups":["group1","group2"]},"service-B":{"roles":["role-in-B"]},"service-C":{"groups":["groupC","web-tier"]},"scale":0.625}
```

请注意，如果你在使用了一段时间后开始遇到`未授权错误`，问题是因为 JWT 已经过期。你需要生成一个新的令牌，或者生成一个有效期更长的令牌。你可以通过向`GenerateToken`工具传入以秒为单位的过期时间来做到这一点。例如，为了生成一个可以使用一小时的令牌，执行以下操作：

```java
Scotts-iMacPro:jwtprop starksm$ mvn exec:java -Dexec.mainClass=io.packt.jwt.test.GenerateToken -Dexec.classpathScope=test -Dexec.args="3600"
[INFO] Scanning for projects...
[INFO]
[INFO] ----------------< io.microprofile.jwt:jwt-propagation >-----------------
[INFO] Building JWT Propagation 1.0-SNAPSHOT
[INFO] --------------------------------[ war ]---------------------------------
[INFO]
[INFO] --- exec-maven-plugin:1.6.0:java (default-cli) @ jwt-propagation ---
Setting exp: 1555692188 / Fri Apr 19 09:43:08 PDT 2019
 Added claim: sub, value: 24400320
 Added claim: customIntegerArray, value: [0,1,2,3]
 Added claim: customDoubleArray, value: [0.1,1.1,2.2,3.3,4.4]
 Added claim: iss, value: http://io.packt.jwt
 Added claim: groups, value: ["Echoer","Tester","User","group1","group2"]
 Added claim: preferred_username, value: jdoe
 Added claim: customStringArray, value: ["value0","value1","value2"]
 Added claim: aud, value: [s6BhdRkqt3]
 Added claim: upn, value: jdoe@example.com
 Added claim: customInteger, value: 123456789
 Added claim: auth_time, value: 1555688588
 Added claim: customObject, value: {"my-service":{"roles":["role-in-my-service"],"groups":["group1","group2"]},"service-B":{"roles":["role-in-B"]},"service-C":{"groups":["groupC","web-tier"]},"scale":0.625}
 Added claim: exp, value: Fri Apr 19 09:43:08 PDT 2019
 Added claim: customDouble, value: 3.141592653589793
 Added claim: iat, value: Fri Apr 19 08:43:08 PDT 2019
 Added claim: jti, value: a-123
 Added claim: customString, value: customStringValue
eyJraWQiOiJcL3ByaXZhdGUta2V5LnBlbSIsInR5cCI6IkpXVCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIyNDQwMDMyMCIsImN1c3RvbUludGVnZXJBcnJheSI6WzAsMSwyLDNdLCJjdXN0b21Eb3VibGVBcnJheSI6WzAuMSwxLjEsMi4yLDMuMyw0LjRdLCJpc3MiOiJodHRwOlwvXC9pby5wYWNrdC5qd3QiLCJncm91cHMiOlsiRWNob2VyIiwiVGVzdGVyIiwiVXNlciIsImdyb3VwMSIsImdyb3VwMiJdLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJqZG9lIiwiY3VzdG9tU3RyaW5nQXJyYXkiOlsidmFsdWUwIiwidmFsdWUxIiwidmFsdWUyIl0sImF1ZCI6InM2QmhkUmtxdDMiLCJ1cG4iOiJqZG9lQGV4YW1wbGUuY29tIiwiY3VzdG9tSW50ZWdlciI6MTIzNDU2Nzg5LCJhdXRoX3RpbWUiOjE1NTU2ODg1ODgsImN1c3RvbU9iamVjdCI6eyJteS1zZXJ2aWNlIjp7InJvbGVzIjpbInJvbGUtaW4tbXktc2VydmljZSJdLCJncm91cHMiOlsiZ3JvdXAxIiwiZ3JvdXAyIl19LCJzZXJ2aWNlLUIiOnsicm9sZXMiOlsicm9sZS1pbi1CIl19LCJzZXJ2aWNlLUMiOnsiZ3JvdXBzIjpbImdyb3VwQyIsIndlYi10aWVyIl19LCJzY2FsZSI6MC42MjV9LCJleHAiOjE1NTU2OTIxODgsImN1c3RvbURvdWJsZSI6My4xNDE1OTI2NTM1ODk3OTMsImlhdCI6MTU1NTY4ODU4OCwianRpIjoiYS0xMjMiLCJjdXN0b21TdHJpbmciOiJjdXN0b21TdHJpbmdWYWx1ZSJ9.Tb8Fet_3NhABc6E5z5N6afwNsxzcZaa9q0eWWLm1AP4HPbJCOA14L275D-jAO42s7yQlHS7sUsi9_nWStDV8MTqoey4PmN2rcnOAaKqCfUiLehcOzg3naUk0AxRykCBO4YIck-qqvlEaZ6q8pVW_2Nfj5wZml2uPDq_X6aVLfxjaRzj2F4OoeKGH51-88yeu7H2THUMNLLPB2MY4Ma0xDUFXVL1TXU49ilOXOWTHAo7wAdqleuZUavtt_ZQfRwCUoI1Y-dltH_WtLdjjYw6aFIeJtsyYCXdqONiP6TqOpfACOXbV_nBYNKpYGn4GMiPsxmpJMU8JAhm-jJzf9Yhq6A
[INFO] -----------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] -----------------------------------------------------------------------
[INFO] Total time:  1.328 s
[INFO] Finished at: 2019-04-19T08:43:08-07:00
[INFO] -----------------------------------------------------------------------
```

这些示例应该能让你对微服务客户端之间的交互以及使用 JWT 来保护微服务端点实现无状态认证和 RBAC（基于角色的访问控制），以及基于 JWT 中声明的定制授权有一个感觉。

# 总结

在本章中，我们学习了 MicroProfile 健康检查和 JWT 传播项目。现在你应该理解了什么是健康检查以及如何添加应用程序特定的检查，这些检查被称为程序。这允许你的微服务在云环境中描述其非琐碎的健康要求。你也应该理解如何使用 JWT 在微服务之上提供认证和授权能力，以控制对端点的访问。你也应该理解如何使用 JWT 中的内容以用户特定方式增强你的微服务。

下一章将介绍 MicroProfile Metrics 和 OpenTracing 特性。这些特性允许你的微服务提供附加信息...

# 问题

1.  马克 wp-hc 协议在所有环境中都有用吗？

1.  一个 MP-HC 响应可以包含任意属性吗？

1.  如果我的应用程序有不同的服务类型需要报告健康状态怎么办？

1.  什么是 JWT（JSON Web Token）？

1.  什么是声明（claim）？

1.  对 JWT 中可以有什么内容有限制吗？

1.  在验证 JWT 时，主要需要经过哪些步骤？

1.  除了安全注解之外，我们还可以如何使用 JWT 来进行授权检查？


# 第六章：MicroProfile Metrics 和 OpenTracing

一旦开发人员编写了代码并将其投入生产，就需要观察代码在做什么，表现如何，以及使用了哪些资源。MicroProfile 为解决这些问题创建了两个规范：Metrics 和（与）OpenTracing 的集成。

从 Metrics 部分开始，我们将讨论以下主题：

+   制定规范的依据

+   启用服务器上指标的暴露格式

+   从您的应用程序内部提供指标

+   使用 Prometheus，一个云原生的时间序列数据库，来检索和分析指标数据

在 OpenTracing 部分，我们将讨论以下内容：

+   跟踪领域简介

+   配置属性...

# MicroProfile Metrics

MicroProfile Metrics 暴露运行服务器的指标数据（通常称为**遥测**），例如 CPU 和内存使用情况，以及线程计数。然后，这些数据通常被输入到图表系统中，以随时间可视化指标或为容量规划目的服务；当然，当值超出预定义的阈值范围时，它们也用于通知 DevOps 人员在阈值范围内。

Java 虚拟机长期以来一直通过 MBeans 和 MBeanServer 暴露数据。Java SE 6 见证了所有虚拟机定义如何从远程进程访问 MBean 服务器的（基于 RMI）远程协议的引入。处理此协议是困难的，并且与今天的基于 HTTP 的交互不符。

另一个痛点是许多全球存在的服务器在不同的名称下暴露不同的属性。因此，设置不同类型服务器的监控并不容易。

MicroProfile 通过一个基于 HTTP 的 API，允许监控代理访问，以及一个 Java API，允许在服务器和 JVM 指标之上导出应用程序特定指标，创建了一个监控规范，解决了这两个问题。

MicroProfile Metrics 正在开发 2.x 版本的规范，其中有一些对 1.x 的破坏性变化。以下部分讨论 1.x - 2.0 中的变化在*MP-Metrics 2.0 中的新特性*部分讨论。

规范定义了指标的三种作用域：

+   基础：这些指标主要是 JVM 统计数据，每个合规的供应商都必须支持。

+   供应商：可选的供应商特定指标，这些指标是不可移植的。

+   应用：来自已部署应用程序的可选指标。Java API 将在*提供应用程序特定指标*部分中展示。

经典 JMX 方法的另一个问题，MicroProfile Metrics 解决了，就是关于指标语义的元数据信息不足。

# 元数据

元数据是 MicroProfile Metrics 中的一个非常重要的部分。虽然暴露一个名为`foo`的指标，其值为`142`是可能的，但这个指标并不具有自描述性。看到这个指标的运营商无法判断这是关于什么的，单位是什么，以及`142`是否是一个好值。

元数据用于提供单位和度量的描述，这样前述的现在可以是`foo: runtime; 142`秒。这现在允许在显示上正确缩放至*两分钟和 22 秒*。而收到与这个度量相关的警报的用户可以理解它指的是某些运行时计时。

# 从服务器检索度量

微 Profile 度量通过一个 REST 接口暴露度量指标，默认情况下，在`/metrics`上下文根下。你可以找到代码在[`github.com/PacktPublishing/Hands-On-Enterprise-Java-Microservices-with-Eclipse-MicroProfile/tree/master/Chapter05-metrics`](https://github.com/PacktPublishing/Hands-On-Enterprise-Java-Microservices-with-Eclipse-MicroProfile/tree/master/Chapter05-metrics)。按照`README.md`文件来构建代码，运行它，并用浏览器访问几遍`[`localhost:8080/book-metrics/hello`](http://localhost:8080/book-metrics/hello)`和`[`localhost:8080/book-metrics`](http://localhost:8080/book-metrics)`端点来生成一些数据。

截至 MicroProfile 1.3/2.0，规范中没有关于保护该端点的任何内容。因此留给个别实现自行处理。

使用这个 REST 接口，很容易检索数据，例如，通过以下`curl`命令：

```java
$ curl http://localhost:8080/metrics
```

这个命令显示了 Prometheus 文本格式（缩写）中的 Metrics 1.x 输出：

```java
# TYPE base:classloader_total_loaded_class_count counter
base:classloader_total_loaded_class_count 13752.0 
# TYPE base:cpu_system_load_average gauge
base:cpu_system_load_average 2.796875
# TYPE base:thread_count counter
base:thread_count 76.0
# TYPE vendor:memory_pool_metaspace_usage_max_bytes gauge
vendor:memory_pool_metaspace_usage_max_bytes 7.0916056E7
# TYPE application:hello_time_rate_per_second gauge
application:hello_time_rate_per_second{app="shop",type="timer"} 
3.169298061424996E-10
# TYPE application:hello_time_one_min_rate_per_second gauge
application:hello_time_one_min_rate_per_second{app="shop",type="timer"} 0.0
[...]
```

如果你没有提供媒体类型，默认输出格式是 Prometheus 文本格式（也可以在浏览器中很好地渲染）。Prometheus 格式向值中的`# TYPE`和`# HELP`行暴露附加元数据。你也可以在前一个示例中看到作用域（基本、供应商和应用程序）是如何被添加到实际度量名称之前的。

另外，通过提供一个`HAccept`头（再次缩写）来检索 JSON 格式的数据是可能的：

```java
$ curl -HAccept:application/json http://localhost:8080/metrics
```

这个命令导致以下输出：

```java
{
 "application" :
 {
 "helloTime" : {
 "p50": 1.4884994E7,
 [...]
 "count": 1,
 "meanRate": 0.06189342578194245
 },
 "getCounted" : 1
 },
 "base" :
 {
 "classloader.totalLoadedClass.count" : 13970,
 "cpu.systemLoadAverage" : 2.572265625,
 "gc.PS Scavenge.time" : 290
 },
 "vendor" :
 {
 "test" : 271,
 "memoryPool.Metaspace.usage.max" : 72016928,
 }
```

在这种情况下，纯净数据被暴露出来；作用域构成了一个顶级层次，相应的度量指标被嵌套在其中。可以通过一个 HTTP `XOPTIONS`调用检索匹配的元数据：

```java
$ curl XOPTIONS -HAccept:application/json http://localhost:8080/metrics
```

输出现在包含元数据作为一个映射：

```java
{
"application" : {
 "helloTime": {
 "unit": "nanoseconds",
 "type": "timer",
 "description": "Timing of the Hello call",
 "tags": "app=shop,type=timer",
 "displayName": "helloTime"
 }
}
[...]
}
```

既然我们已经了解了如何检索不同类型的数据和元数据，我们将快速查看如何限制检索到特定的作用域。

# 访问特定作用域

通过在路径后附加作用域名称，也可以只检索单个作用域的数据。在以下示例中，我们只检索基本作用域的度量指标：

```java
$ curl http://localhost:8080/metrics/base
```

现在只显示基本作用域的度量指标：

```java
# TYPE base:classloader_total_loaded_class_count counterbase:classloader_total_loaded_class_count 13973.0# TYPE base:cpu_system_load_average gaugebase:cpu_system_load_average 1.92236328125
```

在本节中，我们看到了如何从启用了 MicroProfile Metrics 的服务器检索度量。基本和供应商作用域中的度量由服务器预定义。应用程序作用域中的度量可以由用户定义，这是我们将在下一节中探索的内容...

# 提供应用程序特定的度量

应用程序可以选择通过 CDI 编程模型暴露度量数据。这个模型受到了 DropWizard Metrics 的启发，以便更容易将应用程序过渡到 MP-Metrics。它还使用了来自 DropWizard Metrics 的注解，这些注解已经被增强以支持元数据。

让我们从一个例子开始，定义一个计数器然后在代码中递增：

```java
@Inject
@Metric(absolute = true, description = "# calls to /health")
Counter hCount; // This is the counter

@GET
@Path("/health")
public Response getHealth() throws Exception {
    hCount.inc(); // It is increased in the application
    [...]
}
```

在这个例子中，我们通过将计数器注入到`hCount`变量中来注册计数器：

`@Metric`注解提供了额外信息，例如描述，同时也指出名称是变量名而不是额外的包名（`absolute=true`）。

在以下示例中，我们让实现来自动计数。这个实现代表了计数一个方法或 REST 端点的常见用例：

```java
@Counted(absolute=true,
        description="# calls to getCounted",
        monotonic=true)
@GET
@Path("/c")
public String getCounted() {
    return "Counted called";
}
```

`@Counted`的`monotonic`属性表示要不断增加计数器，否则当离开方法时它会减少。

# 更多类型的度量

计数器是唯一可以暴露的度量类型，并且经常需要更复杂的类型，例如，记录方法调用持续时间的分布。

我们快速看一下这些。大多数遵循`@Counted`的模式。

# 仪表器

仪表器是一个值任意上升和下降的度量。仪表器总是由一个提供仪表器值的方法支持：

```java
@Gauge
int provideGaugeValue() {
  return 42;  // The value of the gauge is always 42
}
```

仪表器的值在客户端请求值时计算，就像所有其他值一样。这要求实现仪表器方法非常快，以便调用者不会被阻塞。

# 仪表器

仪表器测量随着时间的推移被装饰方法调用的速率。对于 JAX-RS 端点，这就是每秒的请求数。可以通过注解声明仪表器：

```java
@GET@Path("/m")@Metered(absolute = true)public String getMetered() {  return "Metered called";}
```

当客户端请求从仪表器中数据时，服务器提供平均速率，以及一、五、十五分钟的移动平均值。后者对一些读者来说可能熟悉，来自 Unix/Linux 的`uptime`命令。

# 直方图

直方图是一种度量类型，它样本数据的分布。它主要用于记录被装饰方法执行所需时间的分布。直方图不能像其他类型那样通过专用注解声明，但例如，计时器包含直方图数据。要单独使用直方图，您需要在代码中注册并更新它：

```java
// Register the Histogram
@Inject
@Metric(absolute = true)
private Histogram aHistogram;

// Update with a value from 0 to 10
@GET
@Path("/h")
public String getHistogram() {
  aHistogram.update((int) (Math.random() * 10.0));
  return "Histogram called";
}
```

这种在代码中使用度量的方式对其他类型也是可行的。

# 计时器

计时器基本上是直方图和仪表器的组合，也可以通过注解声明：

```java
@GET@Path("/hello")@Timed(name="helloTime", absolute = true,        description = "Timing of the Hello call",       tags={"type=timer","app=shop"})public String getHelloTimed() {  try {    Thread.sleep((long) (Math.random()*200.0));  } catch (InterruptedException e) {     // We don't care if the sleep is interrupted.  }  return "Hello World";}
```

这个例子中的代码等待一小段时间的随机量，使输出更有趣。

# 标记

标签或标签是组织信息的一种方式。这些在 Docker 和 Kubernetes 中变得流行。在 MicroProfile Metrics 1.x 中，它们会被直接传递到输出中，而不会进一步处理，并不能用来区分指标。MicroProfile Metrics 支持服务器级和每个指标的标签，然后会在输出中合并在一起。

# 服务器级标签

服务器级标签是通过环境变量`MP_METRICS_TAGS`设置的，如下所示：

```java
export MP_METRICS_TAGS=app=myShopjava -jar target/metrics-thorntail.jar
```

这些标签将被添加到服务器中定义的所有指标中，并添加到相应的输出格式中。

所以，在之前的命令下，一个名为`@Counted(absolute=true) int myCount;`的计数器，最终会在 Prometheus 中显示如下：

```java
# TYPE application:my_count counterapplication:my_count{app="myShop"} 0
```

# 每个指标的标签

标签也可以基于每个指标提供：

```java
@Counted(tags=[“version=v1”,”commit=abcde”])
void doSomething() {
  [...]
}
```

这个示例在名为`doSomething`的指标上定义了两个标签，`version=v1`和`commit=abcde`。这些将与全局标签合并用于输出。有了之前的全局标签，输出中就会有三个标签。

在本节中，我们了解了如何向指标添加标签以提供附加元数据。这些可以是全局的，适用于服务器暴露的所有指标，也可以是特定于应用程序的，适用于单个指标。

# 使用 Prometheus 检索指标

既然我们已经了解了暴露的指标以及如何定义我们自己的指标，现在让我们来看看我们如何可以在一个**时间序列数据库**（**TSDB**）中收集它们。为此，我们使用 Prometheus，一个 CNCF（[`www.cncf.io/`](https://www.cncf.io/)）项目，在云原生世界中得到了广泛采用。

您可以从[`prometheus.io`](https://prometheus.io/)下载 Prometheus，或者在 macOS 上通过`brew install prometheus`安装。

一旦下载了 Prometheus，我们需要一个配置文件来定义要抓取的目标，然后可以启动服务器。对于我们来说，我们将使用以下简单的文件：

```java
.Prometheus configuration for a Thorntail Server, prom.ymlscrape_configs:# Configuration to poll from Thorntail- job_name: 'thorntail' ...
```

# 新增于 MP-Metrics 2.0

注意：您在读到这些内容时，MicroProfile Metrics 2.0 可能还没有发布，而且内容可能会根据早期用户/实施者的反馈略有变化。

# 对计数器的更改——引入 ConcurrentGauge

在 Metrics 1.x 中，计数器有两个功能：

+   为了提供一个并发调用次数的测量指标

+   作为一个可以计数提交事务数量的指标，例如

不幸的是，当使用没有指定`monotonic`关键词的注解时，第一种方法是默认的，这是出乎意料的，也让很多用户感到困惑。这种方法的第二个版本也有其问题，因为计数器的值也可以随意减少，这违反了计数器是一个单调递增指标的理解。

因此，度量工作组决定更改计数器的行为，使它们只作为单调递增的指标工作，并将推迟...

# 标记

标签现在也用于区分具有相同名称和类型但不同标签的指标。它们可以用来支持许多指标`result_code`在 REST 端点上，以计算(未)成功的调用次数：

```java
@Inject
@Metric(tags="{code,200}", name="result_code")
Counter result_code_200k;

@Inject
@Metric(tags="{code,500}", name="result_code")
Counter result_code_500;

@GET
@Path("/")
public String getData(String someParam) {

 String result = getSomeData(someParam);
 if (result == null ) {
   result_code_500.inc();
 } else {
   result_code_200.inc();
 }
 return result;
}
```

在底层，指标不再仅按名称和类型进行标识，还按它们的标签进行标识。为此，引入了新的`MetricID`来容纳名称和标签。

# 数据输出格式的变化

在 MicroProfile Metrics 2.0 中引入多标签指标需要对提供给客户端的指标数据格式进行更改。

Prometheus 格式也存在一些不一致之处，因此我们决定以有时不兼容的方式重新设计这些格式：

+   作用域和指标名称之间的冒号(:)分隔符已更改为下划线(_)。

+   Prometheus 输出格式不再需要将 camelCase 转换为 snake_case。

+   垃圾收集器的基础指标格式已更改，现在使用各种垃圾收集器的标签。

请参阅 MicroProfile 2.0 规范中的发布说明：[`github.com/eclipse/microprofile-metrics/releases/tag/2.0 ...`](https://github.com/eclipse/microprofile-metrics/releases/tag/2.0)

# MicroProfile OpenTracing

在微服务构成的现代世界中，一个请求可能会穿过在不同机器、数据中心，甚至地理位置上运行的多个进程。

此类系统的可观测性是一项具有挑战性的任务，但当正确实现时，它允许我们*讲述每个单独请求的故事*，而不是从指标和日志等信号派生出的系统的总体状态。在本章中，我们将向您介绍分布式追踪，并解释 MicroProfile OpenTracing 1.3 中的 OpenTracing 集成。

在前一节中，我们学习了关于指标以及它们如何观察应用程序或每个单独的组件。这些信息无疑非常有价值，并为系统提供了宏观视图，但同时，它很少提到穿越多个组件的每个单独请求。分布式追踪提供了关于请求端到端发生的微观视图，使我们能够回顾性地理解应用程序的每个单独组件的行为。

分布式追踪是基于动作的；换句话说，它记录了系统中的所有与动作相关的信息。例如，它捕获了请求的详细信息及其所有因果相关活动。我们不会详细介绍这种追踪是如何工作的，但简而言之，我们可以得出以下结论：

+   追踪基础架构为每个请求附加了上下文元数据，通常是唯一标识符集合——`traceId`、`spanId`和`parentId`。

+   观测层记录剖析数据并在进程内部及进程之间传播元数据。

+   捕获的剖析数据包含元数据和对先前事件的因果引用。

根据捕获的数据，分布式跟踪系统通常提供以下功能：

+   根本原因分析

+   延迟优化——关键路径分析

+   分布式上下文传播——行李

+   上下文化日志记录

+   服务依赖分析

在我们深入探讨 MicroProfile OpenTracing 之前，让我们简要地看看 OpenTracing，以便我们能更好地理解它提供的 API 是什么。

# OpenTracing 项目

OpenTracing 项目（[`opentracing.io`](https://opentracing.io/)）提供了一个中立的规范[(https://github.com/opentracing/specification)](https://github.com/opentracing/specification)和多语言 API，用于描述分布式事务。中立性很重要，因为在大规模组织中启用分布式跟踪时，代码 instrumentation 是最耗时和最具挑战性的任务。我们想强调的是 OpenTracing 只是一个 API。实际部署将需要一个运行在监控进程内部的 plugged 跟踪器实现，并将数据发送到跟踪系统。

从 API 角度来看，有三个关键概念：跟踪器、跨度、和跨度上下文。跟踪器是应用程序中可用的单例对象，可以用来建模一个...

# 配置属性

OpenTracing 是中立且可以与使用此 API 的任何供应商的跟踪实现配合使用。每个跟踪器实现将配置不同。因此，配置超出了 MicroProfile OpenTracing 规范的范围。然而，规范本身暴露了几个配置属性，以调整跟踪范围或生成数据。配置利用了 MicroProfile Config 规范，为所有支持的配置选项提供了一种一致的方法。

目前，规范暴露了以下内容：

+   `mp.opentracing.server.skip-pattern`：一个跳过模式，用于避免跟踪选定的 REST 端点。

+   `mp.opentracing.server.operation-name-provider`：这指定了服务器跨度操作名称提供程序。可能的值有`http-path`和`class-method`。默认值是`class-method`，它完全使用一个限定类名与方法名拼接；例如，`GET:org.eclipse.Service.get`。`http-path`使用`@Path`注解的值作为操作名称。

# 自动 instrumentation

这里的动机是自动捕获所有关键性能信息，并在运行时之间自动传播跟踪上下文。第二部分尤其重要，因为它确保了跟踪不会中断，我们能够调查端到端的调用。为了成功跟踪，必须在运行时之间的每种通信技术上进行 instrumentation。在 MicroProfile 的情况下，是 JAX-RS 和 MicroProfile Rest Client。

# JAX-RS

微 Profile OpenTracing 自动追踪所有入站的 JAX-RS 端点。然而，JAX-RS 客户端一侧更加复杂，需要调用注册 API，`org.eclipse.microprofile.opentracing.ClientTracingRegistrar.configure(ClientBuilder clientBuilder)`，以添加追踪能力。微 Profile 实现可以为所有客户端接口全局启用追踪；然而，建议使用注册 API 以获得更好的可移植性。

可以通过禁用特定请求的追踪或更改生成的服务器跨度的操作名称来修改默认的追踪行为。有关更多信息，请在本章后面的*配置属性*部分查阅。instrumentation 层自动向每个跨度添加以下请求范围的信息：

+   `http.method`：请求的 HTTP 方法。

+   `http.status_code`：请求的状态代码。

+   `http.url`：请求的 URL。

+   `component`：被 instrumented 组件的名称，`jaxrs`。

+   `span.kind`：客户端或服务器。

+   `error` – `true` 或 `false`。这是可选的，如果存在，instrumentation 还将在跨度日志中添加一个异常作为 `error.object`。

所有这些标签都可以用于通过追踪系统用户界面查询数据，或者它们可以用于许多追踪系统提供数据分析作业。可以通过注入的追踪器实例向当前活动的跨度添加额外元数据。这可以在过滤器中全局执行或在 rest 处理程序中局部执行，如下面的代码示例所示，通过向服务器跨度添加用户代理头（1）：

```java
@Path("/")
public class JaxRsService {
   @Inject
   private io.opentracing.Tracer tracer;

   @GET
   @Path("/hello")
   @Traced(operationName="greeting") (2)
   public String hello(@HeaderParam("user-agent") String userAgent) {
       tracer.activeSpan().setTag("user-agent", userAgent); (1)
   }
}
```

默认情况下，服务器端跨度操作名称为 `http_method:package.className.method`。然而，这可以通过使用 `@Traced` 注解（2）或通过配置属性（参考配置部分）在本地或全局更改。

# 微 Profile Rest Client

如前一部分所述，所有 REST 客户端接口默认情况下都会自动追踪，无需额外的配置。要更改此行为，请将 `@Traced` 注解应用于接口或方法以禁用追踪。当应用于接口时，所有方法都将从追踪中跳过。请注意，追踪上下文不会被传播。因此，如果请求继续到 instrumented runtime，将开始新的追踪。

# 显式 instrumentation

有时，自动 instrumentation 并没有捕获所有关键的计时信息，因此需要额外的追踪点。例如，我们希望追踪业务层的调用或初始化由 OpenTracing 项目提供的三方 instrumentation（[`github.com/opentracing-contrib`](https://github.com/opentracing-contrib)）。

显式地 instrumentation 可以通过三种方式进行：

+   在**上下文和依赖注入**（**CDI**）bean 上添加 `@Traced` 注解。

+   注入追踪器并手动创建跨度。

+   初始化第三方仪器。外部仪器的初始化取决于其自己的初始化要求。MicroProfile 只需要提供一个跟踪器实例，这在之前的要点中已经涵盖。

让我们现在详细讨论这些内容。

# @Traced 注解

MicroProfile OpenTracing 定义了一个`@Traced`注解，可以用于启用 CDI 豆的跟踪，或禁用自动跟踪接口的跟踪。该注解还可以用于重写其他自动跟踪组件的操作名称——JAX-RS 端点。

下面的代码示例显示了如何使用`@Traced`注解来启用 CDI 豆的跟踪。`(1)`为豆定义的所有方法启用跟踪。`(2)`重写了默认操作名称（`package.className.method`）为`get_all_users`。`(3)`禁用了健康方法的跟踪：

```java
@Traced (1)@ApplicationScopedpublic class Service {   @Traced(operationName = "get_all_users") (2)   public void getUsers() {        // business code   } @Traced(false) (3) ...
```

# 跟踪器注入

应用程序可以注入一个`io.opentracing.Tracer`豆，暴露出完整的 OpenTracing API。这允许应用程序开发者利用更高级的使用案例，例如向当前活动的跨度添加元数据，手动创建跨度，使用行李进行上下文传播，或初始化额外的第三方仪器。

下面的代码显示了如何使用跟踪器将数据附加到当前活动的跨度，`(1)`：

```java
@Path("/")
public class Service {
    @Inject
    private Tracer tracer;

    @GET
    @Path("")
    @Produces(MediaType.TEXT_PLAIN)
    public String greeting() {
       tracer.activeSpan()
           .setTag("greeting", "hello"); (1)
       return "hello";
   }
}
```

这可以用于向跨度添加业务相关数据，但也用于记录异常或其他分析信息。

# 使用 Jaeger 进行跟踪

到目前为止，我们只谈论了仪器仪表的不同方面。然而，要运行完整的跟踪基础设施，我们需要一个跟踪后端。在本节中，我们将使用 Jaeger([`www.jaegertracing.io/`](https://www.jaegertracing.io/))来展示收集的跟踪数据如何在跟踪系统中呈现。我们选择 Jaeger 是因为 Thorntail 提供了与 Jaeger 的直接集成。其他供应商可以提供与其他系统的集成，例如 Zipkin 和 Instana。几乎每个跟踪系统都提供了一个类似于甘特图的视图（或时间线）来查看跟踪。这种视图对于跟踪新手来说可能有些令人不知所措，但它是一个分析分布式系统中调用的系统化工具。

下面的屏幕快照显示了...

# 总结

在本章中，我们学习了关于服务器和应用程序的可观测性。

指标，或遥测，可以帮助确定服务器或应用程序的性能特性。MicroProfile 通过 Metrics 规范提供了一种以标准化方式导出指标的方法。应用程序编写者可以使用 MicroProfile Metrics 将他们的数据以注解或通过调用 Metrics API 的方式装饰性地暴露给监控客户端。

本章进一步解释了 MicroProfile 中 OpenTracing 集成如何为通过系统的每个单独事务提供端到端的视图。我们讨论了配置属性，展示了 JAX-RS 的跟踪，最后调查了 Jaeger 系统中的数据。

在下一章，我们将学习如何通过 OpenAPI 文档化（REST）API，并通过类型安全的 REST 客户端调用这些 API。

# 问题

1.  分布式追踪和指标之间的区别是什么？

1.  分布式追踪系统通常提供哪些功能？

1.  在 MicroProfile OpenTracing 中，系统哪些部分会自动被追踪？

1.  MicroProfile OpenTracing 为每个 REST 请求添加了哪些标签？

1.  如何在业务代码中添加显式 instrumentation？

1.  Metrics 中的作用域是什么，它们的理由是什么？

1.  什么决定了 REST 请求到 Metrics API 的输出格式？

1.  用户应用程序中可用的哪些方法可以导出指标？
