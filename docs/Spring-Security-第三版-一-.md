# Spring Security 第三版（一）

> 原文：[`zh.annas-archive.org/md5/3E3DF87F330D174DBAF9E13DAE6DC0C5`](https://zh.annas-archive.org/md5/3E3DF87F330D174DBAF9E13DAE6DC0C5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

欢迎来到 Spring Security 4.2 的世界！我们非常高兴您拥有了这本唯一专门针对 Spring Security 4.2 出版的书籍。在您开始阅读本书之前，我们想向您概述一下本书的组织结构以及如何充分利用它。

阅读完这本书后，您应该对关键的安全概念有所了解，并能够解决大多数需要使用 Spring Security 解决的实际问题。在这个过程中，您将深入了解 Spring Security 的架构，这使您能够处理书中未涵盖的任何意外用例。

本书分为以下四个主要部分：

+   第一部分（第一章，*不安全应用程序的剖析*和第二章，*Spring Security 入门*)提供了 Spring Security 的简介，并让您能够快速开始使用 Spring Security。

+   第二部分（第三章，*自定义认证*，第四章，*基于 JDBC 的认证*，第五章，*使用 Spring Data 的认证*，第六章，*LDAP 目录服务*，第七章，*记住我服务*，第八章，*使用 TLS 的客户端证书认证*，和第九章，*开放给 OAuth 2*)提供了与多种不同认证技术集成的高级指导。

+   第三部分（第十章，*使用中央认证服务的单点登录*，第十一章，*细粒度访问控制*，和第十二章，*访问控制列表*)解释了 Spring Security 的授权支持是如何工作的。

+   最后，最后一部分（第十三章，*自定义授权*，第十四章，*会话管理*，第十五章，*Spring Security 的其他功能*，以及第十六章，*迁移到 Spring Security 4.2*，第十七章，*使用 OAuth 2 和 JSON Web Tokens 的微服务安全*)提供了专门主题的信息和指导，帮助您执行特定任务。

安全是一个非常交织的概念，书中也有很多这样的主题。然而，一旦您阅读了前三章，其他章节相对独立。这意味着您可以轻松地跳过章节，但仍能理解正在发生的事情。我们的目标是提供一个食谱式的指南，即使您通读全书，也能帮助您清楚地理解 Spring Security。

本书通过一个简单的基于 Spring Web MVC 的应用程序来阐述如何解决现实世界的问题。这个应用程序被设计得非常简单直接，并且故意包含非常少的功能——这个应用程序的目标是鼓励你专注于 Spring Security 概念，而不是陷入应用程序开发的复杂性中。如果你花时间回顾示例应用程序的源代码并尝试跟随练习，你将更容易地跟随这本书。在附录的*开始使用 JBCP 日历示例代码*部分，有一些关于入门的技巧。

# 本书涵盖内容

第一章，《不安全应用程序的剖析》，涵盖了我们的日历应用程序的一个假设性安全审计，说明了可以通过适当应用 Spring Security 解决的一些常见问题。你将学习一些基本的安全术语，并回顾一些将示例应用程序启动并运行的先决条件。

第二章，《Spring Security 入门》，展示了 Spring Security 的“Hello World”安装。在本章中，读者将了解一些 Spring Security 最常见的自定义操作。

第三章，《自定义认证》，逐步解释了通过自定义认证基础设施的关键部分来解决现实世界问题，从而了解 Spring Security 的认证架构。通过这些自定义操作，你将了解 Spring Security 认证是如何工作的，以及如何与现有的和新型的认证机制集成。

第四章，《基于 JDBC 的认证》，介绍了使用 Spring Security 内置的 JDBC 支持的数据库认证。然后，我们讨论了如何使用 Spring Security 的新加密模块来保护我们的密码。

第五章，《使用 Spring Data 的认证》，介绍了使用 Spring Security 与 Spring Data JPA 和 Spring Data MongoDB 集成的数据库认证。

第六章，《LDAP 目录服务》，提供了一个关于应用程序与 LDAP 目录服务器集成的指南。

第七章，《记住我服务》，展示了 Spring Security 中记住我功能的用法和如何配置它。我们还探讨了使用它时需要考虑的其他一些额外因素。

第八章，《使用 TLS 的客户端证书认证》，将基于 X.509 证书的认证作为一个清晰的替代方案，适用于某些商业场景，其中管理的证书可以为我们的应用程序增加额外的安全层。

第九章，《开放给 OAuth 2.0》，介绍了 OAuth 2.0 启用的登录和用户属性交换，以及 OAuth 2.0 协议的逻辑流程的高级概述，包括 Spring OAuth 2.0 和 Spring 社交集成。

第十章 10.html，*与中央认证服务集成实现单点登录*，介绍了与中央认证服务（CAS）集成如何为您的 Spring Security 启用应用程序提供单点登录和单点登出支持。它还演示了如何使用无状态服务的 CAS 代理票证支持。

第十一章 11.html，*细粒度访问控制*，涵盖了页面内授权检查（部分页面渲染）和利用 Spring Security 的方法安全功能实现业务层安全。

第十二章 12.html，*访问控制列表*，介绍了使用 Spring Security ACL 模块实现业务对象级安全的基本概念和基本实现-一个具有非常灵活适用性的强大模块，适用于挑战性的业务安全问题。

第十三章 13.html，*自定义授权*，解释了 Spring Security 的授权工作原理，通过编写 Spring Security 授权基础设施的关键部分的自定义实现。

第十四章 14.html，*会话管理*，讨论了 Spring Security 如何管理和保护用户会话。这一章首先解释了会话固定攻击以及 Spring Security 如何防御它们。然后讨论了您可以如何管理已登录的用户以及单个用户可以有多少个并发会话。最后，我们描述了 Spring Security 如何将用户与 HttpSession 相关联以及如何自定义这种行为。

第十五章 15.html，*额外的 Spring Security 功能*，涵盖了其他 Spring Security 功能，包括常见的网络安全漏洞，如跨站脚本攻击（XSS）、跨站请求伪造（CSRF）、同步令牌和点击劫持，以及如何防范它们。

第十六章 16.html，*迁移到 Spring Security 4.2*，提供从 Spring Security 3 迁移的路径，包括显著的配置更改、类和包迁移以及重要的新功能。它还突出了在 Spring Security 4.2 中可以找到的新功能，并提供参考书中的功能示例。

第十七章 17.html，*使用 OAuth 2 和 JSON Web Tokens 的微服务安全*，探讨了微服务架构以及 OAuth 2 和 JWT 在 Spring 基础应用程序中保护微服务的作用。

附录，*附加参考资料*，包含一些与 Spring Security 直接相关性不大的参考资料，但与本书涵盖的主题仍然相关。最重要的是，它包含一个协助运行随书提供的示例代码的章节。

# 您需要什么（本书）

以下列表包含运行随书提供的示例应用程序所需的软件。一些章节有如下附加要求，这些要求在相应的章节中概述：

+   Java 开发工具包 1.8 可从 Oracle 网站下载，网址为 [`www.oracle.com/technetwork/java/javase/downloads/index.html`](http://www.oracle.com/technetwork/java/javase/downloads/index.html)

+   IntelliJ IDEA 2017+ 可从 [`www.jetbrains.com/idea/`](https://www.jetbrains.com/idea/) 下载

+   Spring Tool Suite 3.9.1.RELEASE+ 可从 [`spring.io/tools/sts`](https://spring.io/tools/sts) 下载

# 本书适合谁

如果您是 Java Web 和/或 RESTful Web 服务开发者，并且具有创建 Java 8、Java Web 和/或 RESTful Web 服务应用程序、XML 和 Spring Framework 的基本理解，这本书适合您。您不需要具备任何之前的 Spring Security 经验。

# 约定

在本书中，您会找到多种文本样式，用于区分不同类型的信息。以下是一些这些样式的示例及其含义。文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、假 URL、用户输入和 Twitter 处理方式如下所示："下一步涉及对 `web.xml` 文件进行一系列更新"。代码块如下所示：

```java
 //build.gradle:
    dependencies {
        compile "org.springframework.security:spring-security-  
        config:${springSecurityVersion}"
        compile "org.springframework.security:spring-security- 
        core:${springSecurityVersion}"
        compile "org.springframework.security:spring-security- 
        web:${springSecurityVersion}"
        ...
    }
```

当我们需要引起您对代码块中的特定部分注意时，相关的行或项目将被加粗：

```java
 [default]
 exten => s,1,Dial(Zap/1|30)
 exten => s,2,Voicemail(u100)
 exten => s,102,Voicemail(b100)
 exten => i,1,Voicemail(s0)
```

任何命令行输入或输出如下所示：

```java
$ ./gradlew idea
```

**新术语**和**重要词汇**以粗体显示。

您在屏幕上看到的单词，例如在菜单或对话框中，会在文本中以这种方式出现："在 Microsoft Windows 中，您可以通过右键单击文件并查看其安全属性（属性 | 安全）来查看文件的一些 ACL 功能，如下面的屏幕截图所示"。

警告或重要说明以这种方式出现。

技巧和窍门以这种方式出现。

# 读者反馈

我们的读者提供的反馈总是受欢迎的。告诉我们您对这本书的看法——您喜欢或不喜欢的地方。读者反馈对我们很重要，因为它有助于我们开发出您能真正从中受益的标题。

要向我们提供一般性反馈，只需给`feedback@packtpub.com`发封电子邮件，并在邮件主题中提到书籍的标题。

如果您在某个主题上有专业知识，并且有兴趣撰写或为书籍做出贡献，请查看我们的作者指南 [www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您已经成为 Packt 书籍的自豪拥有者，我们有很多事情可以帮助您充分利用您的购买。

# 下载示例代码

您可以从您在 [`www.packtpub.com`](http://www.packtpub.com/) 的账户上下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问 [`www.packtpub.com/support`](http://www.packtpub.com/support) 并注册，以便将文件直接通过电子邮件发送给您。您可以通过以下步骤下载代码文件：

1.  使用您的电子邮件地址和密码登录或注册我们的网站。

1.  将鼠标指针悬停在顶部的 SUPPORT 标签上。

1.  点击“代码下载与勘误”。

1.  在搜索框中输入书籍的名称。

1.  选择您要下载代码文件的书籍。

1.  从您购买本书的下拉菜单中选择。

1.  点击“代码下载”。

文件下载完成后，请确保使用最新版本解压或提取文件夹：

+   适用于 Windows 的 WinRAR / 7-Zip

+   适用于 Mac 的 Zipeg / iZip / UnRarX

+   适用于 Linux 的 7-Zip / PeaZip

本书的代码包也托管在 GitHub 上，地址为[`github.com/PacktPublishing/Spring-Security-Third-Edition`](https://github.com/PacktPublishing/Spring-Security-Third-Edition/)。我们还有其他来自我们丰富书籍和视频目录的代码包，您可以在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)找到。去看看吧！

# 勘误表

虽然我们已经尽一切努力确保内容的准确性，但错误仍然会发生。如果您在我们的书中发现错误 - 可能是文本或代码中的错误 - 我们非常感谢您能向我们报告。这样做可以节省其他读者的挫折感，并帮助我们改进本书的后续版本。如果您发现任何勘误，请通过访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)报告，选择您的书籍，点击勘误提交表单链接，并输入勘误的详细信息。一旦您的勘误得到验证，您的提交将被接受，勘误将被上传到我们的网站，或添加到该标题的勘误部分现有的勘误列表中。要查看之前提交的勘误，请前往[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，在搜索字段中输入书籍的名称。所需信息将在勘误部分出现。

# 盗版

互联网上的版权材料盗版是一个持续存在的问题，所有媒体都受到影响。 Packt 出版社非常重视我们版权和许可的保护。如果您在互联网上以任何形式发现我们作品的非法副本，请立即提供给我们地址或网站名称，以便我们采取补救措施。请通过`copyright@packtpub.com`联系我们，附上疑似盗版材料的链接。您帮助保护我们的作者和我们提供有价值内容的能力，我们非常感激。

# 问题

如果您在阅读本书的任何方面遇到问题，可以通过`questions@packtpub.com`联系我们，我们会尽力解决问题。


# 第一章：不安全应用程序的解剖

安全性可以说是 21 世纪任何基于 web 的应用程序最关键的架构组件之一。在一个恶意软件、犯罪分子和流氓员工始终存在并积极测试软件漏洞的时代，明智而全面地使用安全性是您将负责的任何项目的关键要素。

本书是为了遵循一种我们认为是解决复杂主题的有用前提的发展模式-以 Spring 4.2 为基础的基于 web 的应用程序，并理解使用 Spring Security 4.2 对其进行安全保护的核心概念和策略。我们通过为每个章节提供完整的 web 应用程序样例代码来补充这种方法。

无论您是否已经使用 Spring Security，或者对将软件的基本使用提升到更复杂的下一个级别感兴趣，您在这本书中都能找到帮助。在本章中，我们将涵盖以下主题：

+   虚构安全审计的结果

+   基于 web 的应用程序的一些常见安全问题

+   几个核心软件安全术语和概念

如果您已经熟悉基本的安全术语，您可以跳到第二章，*开始使用 Spring Security*，我们从框架的基本功能开始使用。

# 安全审计

在你作为**吉姆·鲍勃圆形裤子在线日历**（JBCPCalendar.com）的软件开发人员的工作中，早晨很早，你在喝第一杯咖啡的过程中收到了以下来自你上司的电子邮件：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/51413d3d-040c-4ddb-92d3-5675974fe30f.png)

什么？你在设计应用程序时没有考虑到安全性？实际上，到目前为止，你甚至不确定什么是安全审计。听起来你从安全审计师那里还有很多要学习的！在本章的后部分，我们将回顾什么是审计以及审计的结果。首先，让我们花一点时间检查一下正在审查的应用程序。

# 关于示例应用程序

虽然我们在本书中逐步进行的一个虚构场景，但应用程序的设计和我们对其所做的更改是基于 Spring-based 应用程序的真实世界使用情况。日历应用程序允许用户创建和查看事件：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/3dc74ed3-37c8-48c0-aac1-8659979d294e.png)

在输入新事件的详细信息后，您将看到以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/e20fb523-9636-4b9d-bfc5-d136234b9bdc.png)

应用程序被设计为简单，以便我们可以专注于安全的重要方面，而不是陷入**对象关系映射** (**ORM**)和复杂 UI 技术的细节中。我们期待你会参考附录中的其他补充材料（本书*补充材料*部分）来覆盖作为示例代码一部分提供的一些基本功能。

代码是用 Spring 和 Spring Security 4.2 编写的，但将许多示例适应到 Spring Security 的其他版本相对容易。参考第十六章 16.html、*迁移到 Spring Security 4.2*中的讨论，了解 Spring Security 3 和 4.2 之间的详细变化，以帮助将示例翻译为 Spring Security 4 的语法。

请不要将这个应用程序作为构建真实在线日历应用程序的基础。它故意被构建为简单，并专注于我们在本书中说明的概念和配置。

# JBCP 日历应用程序架构

网络应用程序遵循标准的三层架构，包括 Web、服务和服务访问层，如下面的图表所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/c82c2b5d-2303-47fd-aa94-14d7a8bc4ca5.png)

你可以在附录的*补充材料*部分找到有关 MVC 架构的额外材料。

Web 层封装了 MVC 代码和功能。在这个示例应用程序中，我们将使用 Spring MVC 框架，但我们同样可以轻松地使用**Spring Web Flow** (**SWF**)、**Apache Struts**，甚至是像**Apache Wicket**这样的 Spring 友好的 Web 堆栈。

在典型的利用 Spring Security 的网络应用程序中，Web 层是许多配置和代码增强发生的地方。例如，`EventsController`类用于将 HTTP 请求转换为将事件持久化到数据库中。如果你没有太多 Web 应用程序和 Spring MVC 的经验，仔细审查基线代码并确保你理解它是明智的，在我们进入更复杂的主题之前。再次强调，我们试图使网站尽可能简单，日历应用程序的构建只是为了提供一个合理的标题和轻量级的结构。

你可以在*附录*、*附加参考资料*中找到设置示例应用程序的详细说明。

服务层封装了应用程序的业务逻辑。在我们的示例应用程序中，我们使用`DefaultCalendarService`作为非常轻量级的外观，覆盖数据访问层，以说明关于保护应用程序服务方法的特定要点。服务层还用于在单个方法调用内操作 Spring Security API 和我们的日历 API。我们将在第三章 03.html、*自定义认证*中详细讨论这一点。

在一个典型的 Web 应用程序中，这个层次将包含业务规则验证、业务对象的组合和分解，以及诸如审计的交叉关注点。

数据访问层封装了负责操作数据库表内容的代码。在许多 Spring 应用程序中，这就是您会看到 ORM（如 Hibernate 或 JPA）使用的地方。它向服务层暴露基于对象的 API。在我们的示例应用程序中，我们使用基本的 JDBC 功能来实现对内存中 H2 数据库的持久化。例如，`JdbcEventDao`用于将事件对象保存到数据库中。

在一个典型的 Web 应用程序中，会使用更全面的数据访问解决方案。由于 ORM（对象关系映射），以及更一般的数据访问，对一些开发者来说可能比较困惑，因此这是我们选择尽可能简化清晰明了的区域。

# 应用程序技术

我们努力使应用程序尽可能容易运行，通过专注于几乎每个 Spring 开发者都会在其开发机器上拥有的基本工具和技术。尽管如此，我们还是在附录中提供了*入门*部分，作为补充信息，即*使用 JBCP 日历示例代码入门*。

与示例代码集成的主要方法是提供与 Gradle 兼容的项目。由于许多 IDE 与 Gradle 集成丰富，用户应该能够将代码导入支持 Gradle 的任何 IDE。由于许多开发者使用 Gradle，我们认为这是包装示例的最直接方法。无论您熟悉的开发环境是什么，希望您能找到一种方法来完成这本书中的示例。

许多 IDE 提供 Gradle 工具，可以自动为您下载 Spring 和 Spring Security 4.2 的 Javadoc 和源代码。然而，可能有时这是不可能的。在这种情况下，您需要下载 Spring 4.2 和 Spring Security 4.2 的完整版本。Javadoc 和源代码是顶级的。如果您感到困惑或需要更多信息，示例可以为您提供额外的支持或信心，以帮助您的学习。访问附录中的*补充材料*部分，即*附加参考资料*，以查找有关 Gradle 的额外信息，包括运行示例、获取源代码和 Javadoc，以及不使用 Gradle 构建项目的替代方案。

# 审查审计结果

让我们回到我们的电子邮件，看看审计进展如何。哦哦，结果看起来不太好：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/403f0d84-959f-4e01-bfc9-68d113c2e554.png)

**应用程序审计结果**

这个应用程序表现出以下不安全行为：

+   由于缺乏 URL 保护和一般认证，不经意的权限提升

+   不当或不存在授权使用

+   缺少数据库凭据安全

+   个人身份信息或敏感信息容易访问或未加密

+   由于缺乏 SSL 加密，传输层保护不安全。

+   风险等级：高

我们建议，在这些问题得到解决之前，该应用程序应下线。

哎呀！这个结果对我们公司来说看起来很糟糕。我们最好尽快解决这些问题。

第三方安全专家通常被公司（或其合作伙伴或客户）雇佣，通过结合白帽黑客、源代码审查和与应用程序开发人员和架构师正式或非正式的交谈，审计他们软件安全的效果。

**白帽黑客**或**道德黑客**是由专业人士进行的，他们受雇于公司，指导公司如何更好地保护自己，而不是出于恶意的目的。

通常，安全审计的目的是为了向管理层或客户提供信心，确保已经遵循了基本的安全开发实践，以确保客户数据和系统功能的完整性和安全性。根据软件目标行业的不同，审计员还可能使用行业特定的标准或合规性指标对其进行测试。

在你的职业生涯中某个时候可能会遇到的两个具体安全标准是**支付卡行业数据安全标准**（**PCI DSS**）和**健康保险隐私和责任法案**（**HIPAA**）隐私规则。这两个标准旨在通过结合流程和软件控制来确保特定敏感信息（如信用卡和医疗信息）的安全。许多其他行业和国家有关于敏感信息或**个人可识别信息**（**PII**）类似的规则。不遵循这些标准不仅是不好的实践，还可能在你或你的公司发生安全漏洞时暴露你或你的公司承担重大责任（更不用说坏新闻了）。

收到安全审计的结果可能是一次大开眼界的经历。按照要求改进软件可以是一个自我教育和软件改进的完美机会，并允许您实施导致安全软件的实践和政策。

让我们回顾一下审计员的调查结果，并详细制定一个解决它们的计划。

# 认证

认证是开发安全应用程序时必须深入理解的两个关键安全概念之一（另一个是授权）。**认证**的目的是确定谁正在尝试请求资源。你可能在日常生活中在线和离线环境下对认证熟悉，如下所述：

+   **基于凭证的认证**：当你登录基于网页的邮箱账户时，你很可能会提供你的用户名和密码。邮箱提供商将其用户名与数据库中的已知用户匹配，并验证你的密码与他们的记录相符。这些凭证是邮箱系统用来验证你是系统有效用户的东西。首先，我们将使用这种认证方式来保护 JBCP 日历应用程序的敏感区域。从技术上讲，邮箱系统不仅可以在数据库中检查凭证，还可以在任何地方进行检查，例如，企业目录服务器如**微软活动目录**。本书涵盖了这类集成的大部分内容。

+   **双因素认证**：当你从银行的自动取款机取款时，你需要刷一下你的身份证，并输入你的个人识别码，然后才能取出现金或进行其他交易。这种认证方式与用户名和密码认证相似，不同之处在于用户名编码在卡的磁条上。物理卡片和用户输入的 PIN 码的组合使得银行能够确保你应该有权限访问该账户。密码和物理设备（你的塑料 ATM 卡）的组合是双因素认证的一种普遍形式。在一个专业、注重安全的环境中，这种类型的设备经常用于访问高度安全的系统，尤其是与财务或个人身份信息有关的系统。例如**RSA SecurID**这样的硬件设备，结合基于时间硬件设备和基于服务器的认证软件，使得环境极端难以被妥协。

+   **硬件认证**：早上启动你的车时，你将金属钥匙插入点火器并转动它来启动汽车。虽然这可能感觉与另外两个例子不同，但是钥匙上的凸起和点火开关中的滚珠正确匹配，作为一种硬件认证形式。

实际上有数十种认证方式可以应用于软件和硬件安全问题，每种方式都有其优缺点。我们将在本书的第一半部分回顾这些方法，并将其应用于 Spring Security。我们的应用程序缺乏任何类型的认证，这就是审计包括无意中提升权限风险的原因。

通常，一个软件系统会被划分为两个高层次领域，例如未认证（或匿名）和已认证，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/08cae274-5a44-48c3-8c1e-9878fa0b607f.png)

匿名区域的应用程序功能是独立于用户身份的功能（想想一个在线应用程序的欢迎页面）。

匿名区域不会做以下这些事情：

+   要求用户登录系统或以其他方式识别自己才能使用

+   显示敏感信息，如姓名、地址、信用卡和订单

+   提供操作系统或其数据整体状态的功能

系统的未认证区域旨在供所有人使用，甚至是那些我们尚未明确识别的用户。然而，可能是在这些区域出现了对已识别用户的其他功能（例如，无处不在的`欢迎 {First Name}`文本）。通过使用 Spring Security 标签库，完全支持向已认证用户显示内容的选择性，并在第十一章 *细粒度访问控制* 中进行了介绍。

我们将在第二章 *开始使用 Spring Security* 中解决这个问题，并使用 Spring Security 的自动配置能力实现基于表单的认证。之后，我们将探讨执行认证的各种其他方式（这通常涉及与企业或其他外部认证存储系统的集成）。

# 授权

不当或不存在使用授权

授权是两个核心安全概念中的第二个，对于实现和理解应用程序安全至关重要。**授权**使用在身份验证过程中验证的信息来确定是否应授予对特定资源的访问权限。围绕应用程序的授权模型，授权将应用程序功能和数据分区，以便这些项目的可用性可以通过将特权、功能和数据的组合与用户匹配来控制。我们应用程序在审计此阶段的失败表明应用程序的功能不受用户角色的限制。想象一下，如果你正在运营一个电子商务网站，而查看、取消或修改订单和客户信息的能力对网站上的任何用户都可用！

授权通常涉及以下两个方面，这两个方面结合在一起描述了受保护系统的可访问性：

+   第一个方面是将一个已认证的主体映射到一个或多个权限（通常称为**角色**）。例如，您网站的临时用户可能被视为具有访客权限，而网站管理员可能被分配管理权限。

+   第二个方面是将权限检查分配给系统的受保护资源。这通常在系统开发时完成，要么通过代码中的显式声明，要么通过配置参数。例如，允许查看其他用户事件的屏幕应该只对具有管理权限的用户可用。

一个受保护的资源可能是系统中应基于用户权限而有条件地可用的任何方面。

基于 Web 的应用程序的安全资源可能是个别 Web 页面，网站的整个部分，或个别页面的部分。相反，安全业务资源可能是类上的方法调用或个别业务对象。

你可能想象有一个权限检查，它会检查主体，查找其用户账户，并确定主体是否实际上是管理员。如果这个权限检查确定试图访问受保护区域的主体实际上是管理员，那么请求将会成功。然而，如果主体没有足够的权限，请求应该被拒绝。

让我们 closer look at a particular example of a secured resource, the All Events page. The All Events page requires administrative access (after all, we don't want regular users viewing other users' events), and as such, looks for a certain level of authority in the principal accessing it.

如果我们思考当一个网站管理员试图访问受保护资源时决策可能是如何做出的，我们会想象实际权限与所需权限的检查可以用集合论简洁地表达。我们可能会选择用**维恩**图表示这个决定：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/d707087e-ad79-4d75-8be8-a96cc9e19536.png)

**用户权限**（用户和管理员）和**所需权限**（管理员）之间有一个交集，所以用户被提供访问权限。

与未经授权的用户相比如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/096a10f5-387e-4b85-b339-49ee85fe483a.png)

权限集合是分开的，没有公共元素。所以，用户被拒绝访问页面。因此，我们已经演示了访问资源授权的基本原则。

在现实中，有真实的代码在做这个决定，其结果是用户被授权或拒绝访问请求的保护资源。我们将在第二章，*Spring Security 入门*中讨论基本授权问题，随后在第十二章访问控制列表和第十三章自定义授权中讨论更高级的授权。

# 数据库凭据安全

数据库凭据不安全或容易访问。通过检查应用程序源代码和配置文件，审计员注意到用户密码以明文形式存储在配置文件中，这使得恶意用户能够轻松访问服务器并访问应用程序。

由于应用程序包含个人和财务数据，恶意用户能够访问任何数据可能会使公司面临身份盗窃或篡改的风险。对我们来说，保护访问应用程序所使用的凭据应该是首要任务，并且确保安全的一个关键一步是确保一个失败点不会使整个系统受到威胁。

我们将检查 Spring Security 中用于凭据存储的数据库访问层配置，这在第四章“*基于 JDBC 的认证*”中讨论。在这一章中，我们还将探讨内置技术以提高存储在数据库中的密码的安全性。

# 敏感信息

可识别或敏感信息容易访问或未加密。审计员注意到系统中一些重要且敏感的数据完全是未加密或未在任何地方遮蔽的。幸运的是，有一些简单的设计模式和工具可以让我们安全地保护这些信息，并且 Spring Security 支持基于注解的 AOP。

# 传输层保护

由于缺乏 SSL 加密，存在不安全的传输层保护。

虽然在线应用程序包含私人信息，在现实世界中，没有 SSL 保护的运行是不可想象的，不幸的是，JBCP 日历正是这种情况。SSL 保护确保浏览器客户端与 Web 应用程序服务器之间的通信安全，防止多种篡改和窥探。

在“*Tomcat 中的 HTTPS 设置*”部分，附录中的“*附加参考资料*”中，我们将回顾使用传输层安全作为应用程序安全结构定义的一部分的基本选项。

# 使用 Spring Security 4.2 解决安全问题

Spring Security 4.2 提供了丰富的资源，使得许多常见的安 全实践可以简单地声明或配置。在接下来的章节中，我们将结合源代码和应用程序配置的更改来解决安全审计员提出（还有更多）的所有关注问题，从而确信我们的日历应用程序是安全的。

使用 Spring Security 4.2，我们将能够做出以下更改来增加我们应用程序的安全性：

+   将系统中的用户划分为用户类

+   为用户角色分配授权级别

+   为用户类分配用户角色

+   在全球范围内对应用程序资源应用认证规则

+   在应用程序架构的所有层次上应用授权规则

+   防止旨在操纵或窃取用户会话的常见攻击

# 为什么使用 Spring Security？

Spring Security 存在于 Java 第三方库的宇宙中，填补了 Spring Framework 最初引入时所填补的空白。像**Java Authentication and Authorization Service** (**JAAS**)或**Java EE Security**这样的标准确实提供了一些执行某些认证和授权功能的方法，但 Spring Security 之所以获胜，是因为它以简洁和合理的方式包含了您需要实现端到端应用程序安全解决方案的所有内容。

此外，Spring Security 吸引了许多人，因为它提供了与许多常见企业认证系统的外盒集成；因此，它可以在很少的努力（超出配置）下适应大多数情况。

它被广泛使用，因为没有其他主流框架真正像它这样！

# 总结

在本章中，我们回顾了一个未受保护的 Web 应用程序的常见风险点和示例应用程序的基本架构。我们还讨论了保护应用程序的策略。

在下一章中，我们将探讨如何快速设置 Spring Security 并了解它的工作原理。


# 第二章：开始使用 Spring Security

在本章中，我们将对 Spring Security 应用最小的配置来开始解决我们的第一个发现-由于缺乏 URL 保护而不经意间提升了权限，以及第一章中讨论的安全审计*不安全应用程序的剖析*中的通用认证。然后，我们将在此基础上构建，为我们的用户提供定制化的体验。本章旨在让您开始使用 Spring Security，并为您提供执行任何其他安全相关任务的基础。

在本章中，我们将介绍以下主题：

+   在 JBCP 日历应用程序上实现基本的安全性，使用 Spring Security 中的自动配置选项

+   学习如何定制登录和登出体验

+   配置 Spring Security 以根据 URL 不同地限制访问

+   利用 Spring Security 的表达式基础访问控制

+   使用 Spring Security 中的 JSP 库条件性地显示有关登录用户的基本信息

+   根据用户的角色确定登录后用户的默认位置

# 你好，Spring Security

虽然 Spring Security 的配置可能非常复杂，但该产品的创建者考虑周到，为我们提供了一个非常简单的机制，通过这个机制可以以一个强有力的基础启用软件的大部分功能。从这个基础出发，进一步的配置将允许对应用程序的安全行为进行细粒度的详细控制。

我们将从第一章的*不安全应用程序的剖析*中的未受保护的日历应用程序开始，将其转变为一个使用基本用户名和密码认证的安全网站。这种认证仅仅是为了说明启用我们的 Web 应用程序的 Spring Security 步骤；您将看到这种方法中有明显的缺陷，这将导致我们进行进一步的配置细化。

# 导入示例应用程序

我们鼓励您将`chapter02.00-calendar`项目导入您的 IDE，并通过从本章获取源代码来跟随，如附录*附加参考资料*中的*使用 JBCP 日历示例代码*一节所述。

对于每个章节，您会发现有代表书中检查点的代码多个版本。这使得您可以很容易地将您的作品与正确答案进行比较。在每个章节的开头，我们将导入该章节的第一个版本作为起点。例如，在本章中，我们从`chapter02.00-calendar`开始，第一个检查点将是`chapter02.01-calendar`。在附录*附加参考资料*中，所以一定要查阅它以获取详细信息。

# 更新您的依赖项

第一步是更新项目的依赖关系，以包括必要的 Spring Security JAR 文件。更新从之前导入的示例应用程序中获取的 Gradle `build.gradle`文件，以包括我们将在接下来的几节中使用的 Spring Security JAR 文件。

在整本书中，我们将演示如何使用 Gradle 提供所需的依赖项。`build.gradle`文件位于项目的根目录中，代表构建项目所需的所有内容（包括项目的依赖项）。请记住，Gradle 将为列出的每个依赖项下载传递依赖项。所以，如果您使用另一种机制来管理依赖项，请确保您也包括了传递依赖项。在手动管理依赖项时，了解 Spring Security 参考资料中包括其传递依赖项的列表是有用的。可以在附录中的*补充材料*部分的*附加参考资料*中找到 Spring Security 参考资料的链接。

让我们看一下以下的代码片段：

```java
    build.gradle:
    dependencies {
        compile "org.springframework.security:spring-security-  
        config:${springSecurityVersion}"
        compile "org.springframework.security:spring-security- 
        core:${springSecurityVersion}"
        compile "org.springframework.security:spring-security- 
        web:${springSecurityVersion}"
        ...
    }
```

# 使用 Spring 4.3 和 Spring Security 4.2

Spring 4.2 是一致使用的。我们提供的示例应用程序展示了前一个选项的示例，这意味着您不需要进行任何额外的工作。

在下面的代码中，我们展示了添加到 Gradle `build.gradle`文件的一个示例片段，以利用 Gradle 的依赖管理功能；这确保了整个应用程序中使用正确的 Spring 版本。我们将利用 Spring IO **物料清单**（**BOM**）依赖，这将确保通过 BOM 导入的所有依赖版本正确地一起工作：

```java
    build.gradle
    // Spring Security IO with ensures correct Springframework versions
    dependencyManagement {
         imports {
            mavenBom 'io.spring.platform:platform-bom:Brussels-${springIoVersion}'
        }
    }
    dependencies {
        ...
    }
```

如果您正在使用 Spring Tool Suite，每次更新`build.gradle`文件时，请确保您右键点击项目，导航到 Gradle | 刷新 Gradle 项目，并选择确定以更新所有依赖项。

关于 Gradle 如何处理传递依赖项以及 BOM 的信息，请参考附录中*补充材料*部分列出的 Gradle 文档。

# 实现 Spring Security XML 配置文件

配置过程的下一步是创建一个 Java 配置文件，代表所有用于覆盖标准 Web 请求的 Spring Security 组件。

在`src/main/java/com/packtpub/springsecurity/configuration/`目录下创建一个新的 Java 文件，命名为`SecurityConfig.java`，并包含以下内容。此文件展示了我们应用程序中每个页面对用户登录的要求，提供了一个登录页面，对用户进行了身份验证，并要求登录的用户对每个 URL 元素关联一个名为`USER`的角色：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/
    SecurityConfig.java

    @Configuration
    @EnableWebSecurity
    public class SecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        public void configure(final AuthenticationManagerBuilder auth) throws Exception     
        {
            auth.inMemoryAuthentication().withUser("user1@example.com")
            .password("user1").roles("USER");
        }
        @Override
        protected void configure(final HttpSecurity http) throws Exception {
            http.authorizeRequests()
                    .antMatchers("/**").access("hasRole('USER')")
                    // equivalent to <http auto-config="true">
                    .and().formLogin()
                    .and().httpBasic()
                    .and().logout()
                    // CSRF is enabled by default (will discuss later)
                    .and().csrf().disable();
        }
    }
```

如果你使用的是 Spring Tool Suite，你可以通过按 *F3* 轻松查看 `WebSecurityConfigurerAdapter`。记住，下一个检查点（`chapter02.01-calendar`）有一个可行的解决方案，所以文件也可以从那里复制。

这是确保我们的 Web 应用程序使用最小标准配置安全所需的唯一 Spring Security 配置。这种使用 Spring Security 特定 Java 配置的配置方式被称为**Java 配置**。

让我们花一分钟来分析这个配置，以便我们能了解发生了什么。在 `configure(HttpSecurity)` 方法中，`HttpSecurity` 对象创建了一个 Servlet 过滤器，该过滤器确保当前登录的用户与适当的角色关联。在这个实例中，过滤器将确保用户与 `ROLE_USER` 关联。重要的是要理解，角色的名称是任意的。稍后，我们将创建一个具有 `ROLE_ADMIN` 的用户，并允许此用户访问当前用户无法访问的额外 URL。

在 `configure(AuthenticationManagerBuilder)` 方法中，`AuthenticationManagerBuilder` 对象是 Spring Security 认证用户的方式。在这个实例中，我们使用内存数据存储来比较用户名和密码。

我们给出的例子和解释有些牵强。一个内存中的认证存储在生产环境中是行不通的。然而，它让我们能够快速启动。随着本书的进行，我们将逐步改进对 Spring Security 的理解，同时更新我们的应用程序以使用生产级别的安全配置。

从 Spring 3.1 开始，对 **Java 配置** 的通用支持已添加到 Spring 框架中。自从 Spring Security 3.2 发布以来，就有了 Spring Security Java 配置支持，这使用户能够不使用任何 XML 轻松配置 Spring Security。如果你熟悉第六章 LDAP 目录服务 和 Spring Security 文档，那么你应该会在它和 **Security Java Configuration** 支持之间找到很多相似之处。

# 更新你的 web.xml 文件

接下来的步骤涉及对 `web.xml` 文件进行一系列更新。有些步骤已经完成，因为应用程序已经使用 Spring MVC。然而，我们会回顾这些要求，以确保在您使用不支持 Spring 的应用程序中理解更基本的 Spring 要求。

# ContextLoaderListener 类

更新`web.xml`文件的第一步是删除它，并用`javax.servlet.ServletContainerInitializer`替换它，这是 Servlet 3.0+初始化的首选方法。Spring MVC 提供了`o.s.w.WebApplicationInitializer`接口，利用这一机制。在 Spring MVC 中，首选的方法是扩展`o.s.w.servlet.support.AbstractAnnotationConfigDispatcherServletInitializer`。`WebApplicationInitializer`类是多态的`o.s.w.context.AbstractContextLoaderInitializer`，并使用抽象的`createRootApplicationContext()`方法创建一个根`ApplicationContext`，然后将其委托给`ContextLoaderListener`，后者注册在`ServletContext`实例中，如下代码片段所示：

```java
    //src/main/java/c/p/s/web/configuration/WebAppInitializer

    public class WebAppInitializer extends   
    AbstractAnnotationConfigDispatcherServletInitializer {
        @Override
        protected Class<?>[] getRootConfigClasses() {
            return new Class[] { JavaConfig.class, SecurityConfig.class,    
            DataSourceConfig.class };
        }
        ...
    }
```

更新后的配置现在将从此 WAR 文件的类路径中加载`SecurityConfig.class`。

# ContextLoaderListener 与 DispatcherServlet 对比

`o.s.web.servlet.DispatcherServlet`接口指定了通过`getServletConfigClasses()`方法独立加载的配置类：

```java
    //src/main/java/c/p/s/web/configuration/WebAppInitializer

    public class WebAppInitializer extends     
    AbstractAnnotationConfigDispatcherServletInitializer {
        ...
        @Override
        protected Class<?>[] getServletConfigClasses() {
            return new Class[] { WebMvcConfig.class };
        }
        ...
        @Override
        public void onStartup(final ServletContext servletContext) throws  
        ServletException {
            // Registers DispatcherServlet
            super.onStartup(servletContext);
        }
    }
```

`DispatcherServlet`类创建了`o.s.context.ApplicationContext`，它是根`ApplicationContext`接口的子接口。通常，Spring MVC 特定组件是在`DispatcherServlet`的`ApplicationContext`接口中初始化的，而其余的则是由`ContextLoaderListener`加载的。重要的是要知道，子`ApplicationContext`中的 Bean（如由`DispatcherServlet`创建的）可以引用父`ApplicationContext`中的 Bean（如由`ContextLoaderListener`创建的），但父`ApplicationContext`接口不能引用子`ApplicationContext`中的 Bean。

以下图表说明了**子 Bean**可以引用**根 Bean**，但**根 Bean**不能引用**子 Bean**：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/51f10ca9-eaa2-4b05-a6a9-2cf02949886c.png)

与大多数 Spring Security 的使用场景一样，我们不需要 Spring Security 引用任何 MVC 声明的 Bean。因此，我们决定让`ContextLoaderListener`初始化所有 Spring Security 的配置。

# springSecurityFilterChain 过滤器

下一步是配置`springSecurityFilterChain`以拦截所有请求，通过创建`AbstractSecurityWebApplicationInitializer`的实现。确保`springSecurityFilterChain`首先声明至关重要，以确保在调用任何其他逻辑之前请求是安全的。为了确保`springSecurityFilterChain`首先加载，我们可以使用如下配置中的`@Order(1)`：

```java
    //src/main/java/c/p/s/web/configuration/SecurityWebAppInitializer

    @Order(1)
    public class SecurityWebAppInitializer extends     
 AbstractSecurityWebApplicationInitializer {
        public SecurityWebAppInitializer() {
            super();
        }
    }
```

`SecurityWebAppInitializer`类将自动为应用程序中的每个 URL 注册`springSecurityFilterChain`过滤器，并将添加`ContextLoaderListener`，后者加载`SecurityConfig`。

# DelegatingFilterProxy 类

`o.s.web.filter.DelegatingFilterProxy`类是 Spring Web 提供的 Servlet 过滤器，它将所有工作委派给`ApplicationContext`根目录下的一个 Spring bean，该 bean 必须实现`javax.servlet.Filter`。由于默认情况下是通过名称查找 bean，使用`<filter-name>`值，我们必须确保我们使用`springSecurityFilterChain`作为`<filter-name>`的值。我们可以在以下代码片段中找到`o.s.web.filter.DelegatingFilterProxy`类对于我们`web.xml`文件的工作伪代码：

```java
    public class DelegatingFilterProxy implements Filter {
      void doFilter(request, response, filterChain) {
        Filter delegate = applicationContet.getBean("springSecurityFilterChain")
        delegate.doFilter(request,response,filterChain);
      }
    }
```

# `FilterChainProxy`类

当与 Spring Security 一起使用时，`o.s.web.filter.DelegatingFilterProxy`将委派给 Spring Security 的`o.s.s.web.FilterChainProxy`接口，该接口是在我们的最小`security.xml`文件中创建的。`FilterChainProxy`类允许 Spring Security 条件性地将任意数量的 Servlet 过滤器应用于 Servlet 请求。我们将在书的其余部分了解更多关于 Spring Security 过滤器的内容，以及它们在确保我们的应用程序得到适当保护方面的作用。`FilterChainProxy`的工作伪代码如下：

```java
    public class FilterChainProxy implements Filter {
  void doFilter(request, response, filterChain) {
    // lookup all the Filters for this request
    List<Filter> delegates =       lookupDelegates(request,response)
    // invoke each filter unless the delegate decided to stop
    for delegate in delegates {
      if continue processing
        delegate.doFilter(request,response,filterChain)
    }
    // if all the filters decide it is ok allow the 
    // rest of the application to run
    if continue processing
      filterChain.doFilter(request,response)  }
    }

```

由于`DelegatingFilterProxy`和`FilterChainProxy`都是 Spring Security 的前门，当在 Web 应用程序中使用时，您会在尝试了解发生了什么时添加一个调试点。

# 运行受保护的应用程序

如果您还没有这样做，请重新启动应用程序并访问`http://localhost:8080/`。您将看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/f21bbf6c-69e2-4013-8263-8048fc161cc3.png)

太棒了！我们使用 Spring Security 在应用程序中实现了一个基本的安全层。在此阶段，您应该能够使用`user1@example.com`作为用户和`user1`作为密码登录。您将看到日历欢迎页面，该页面从高层次描述了应用程序在安全性方面的预期。

您的代码现在应该看起来像`chapter02.01-calendar`。

# 常见问题

许多用户在将 Spring Security 首次实现到他们的应用程序时遇到了麻烦。下面列出了一些常见问题和建议。我们希望确保您能够运行示例应用程序并跟随教程！

+   在将 Spring Security 放入应用程序之前，请确保您能够构建和部署应用程序。

+   如有需要，请回顾一些关于您 Servlet 容器的入门示例和文档。

+   通常使用 IDE（如 Eclipse）运行您的 Servlet 容器是最简单的。不仅部署通常是无缝的，控制台日志也易于查看以查找错误。您还可以在战略位置设置断点，以便在异常触发时更好地诊断错误。

+   请确保您使用的 Spring 和 Spring Security 版本匹配，并且没有意外的 Spring JAR 作为您应用程序的一部分残留。如前所述，当使用 Gradle 时，最好在依赖管理部分声明 Spring 依赖项。

# 稍微加工一下

停在这个步骤，思考一下我们刚刚构建的内容。你可能已经注意到了一些明显的问题，这需要一些额外的工作和了解 Spring Security 产品知识，我们的应用程序才能准备好上线。尝试列出一个你认为在安全实现准备好公开面对网站之前需要做的更改清单。

应用 Hello World Spring Security 实现速度之快让人眼花缭乱，并为我们提供了登录页面、用户名和基于密码的认证，以及在我们日历应用程序中自动拦截 URL。然而，自动配置设置提供的与我们最终目标之间的差距如下所述：

+   虽然登录页面很有帮助，但它完全通用，与我们 JBCP 日历应用程序的其余部分看起来不一样。我们应该添加一个与应用程序外观和感觉集成的登录表单。

+   用户没有明显的方式登出。我们已经锁定了应用程序中的所有页面，包括欢迎页面，潜在的用户可能想以匿名方式浏览该页面。我们需要重新定义所需的角色以适应匿名、认证和行政用户。

+   我们没有显示任何上下文信息来告知用户他们已经认证。如果能显示一个类似于欢迎`user1@example.com`的问候语会很好。

+   我们不得不在`SecurityConfig`配置文件中硬编码用户的用户名、密码和角色信息。回想一下我们添加的`configure(AuthenticationManagerBuilder)`方法的这一部分：

```java
        auth.inMemoryAuthentication().withUser("user1@example.com")
        .password("user1").roles("USER");
```

+   你可以看到用户名和密码就在文件里。我们不太可能想要为系统中的每个用户在文件中添加一个新的声明！为了解决这个问题，我们需要用另一种认证方式更新配置。

我们将在本书的第一半中探索不同的认证选项。

# 登出配置

Spring Security 的`HttpSecurity`配置自动添加了对用户登出的支持。所需的所有操作是创建一个指向`/j_spring_security_logout`的链接。然而，我们将演示如何通过执行以下步骤自定义用于用户登出的 URL：

1.  如下更新 Spring Security 配置：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        SecurityConfig.java

        http.authorizeRequests()
        ...
       .logout()
       .logoutUrl("/logout")
       .logoutSuccessUrl("/login?logout");
```

1.  你必须为用户提供一个可以点击的链接以登出。我们将更新`header.html`文件，以便在每一页上出现`Logout`链接：

```java
        //src/main/webapp/WEB-INF/templates/fragments/header.html

        <div id="navbar" ...>
         ...
           <ul class="nav navbar-nav pull-right">
             <li><a id="navLogoutLink" th:href="@{/logout}">
               Logout</a></li>
           </ul>
            ...
        </div>
```

1.  最后一步是更新`login.html`文件，当`logout`参数存在时，显示一条表示登出成功的消息：

```java
        //src/main/webapp/WEB-INF/templates/login.html

        <div th:if="${param.logout != null}" class="alert 
        alert-success"> You have been logged out.</div>
          <label for="username">Username</label>
          ...
```

你的代码现在应该看起来像`chapter02.02-calendar`。

# 页面没有正确重定向。

如果你还没有这么做，重启应用程序并在 Firefox 中访问`http://localhost:8080`；你会看到一个错误，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/4c6fdfaa-ef71-4e5a-aac8-ba674db7d23f.png)

哪里出了问题？问题在于，由于 Spring Security 不再渲染登录页面，我们必须允许所有人（而不仅仅是`USER`角色）访问登录页面。如果不允许访问登录页面，会发生以下情况：

1.  在浏览器中请求欢迎页面。

1.  Spring Security 发现欢迎页面需要`USER`角色，而我们尚未认证，因此它将浏览器重定向到登录页面。

1.  浏览器请求登录页面。

1.  Spring Security 发现登录页面需要`USER`角色，而我们还没有认证，所以它将浏览器重定向到登录页面。

1.  浏览器再次请求登录页面。

1.  Spring Security 发现登录页面需要`USER`角色，如图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/f7a75dc4-9fcf-44ab-be04-4402b50a9123.png)

此过程可能会无限重复。幸运的是，Firefox 意识到发生了太多重定向，停止执行重定向，并显示一个非常有用的错误信息。在下一节中，我们将学习如何通过配置不同的 URL 来修复此错误，这些 URL 根据它们需要的访问权限不同。

# 基于表达式的授权。

你可能已经注意到，允许所有人访问远不如我们期望的简洁。幸运的是，Spring Security 可以利用**Spring 表达式语言**（**SpEL**）来确定用户是否有授权。在下面的代码片段中，你可以看到使用 SpEL 与 Spring Security 时的更新：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/
    SecurityConfig.java

    http.authorizeRequests()
        .antMatchers("/").access("hasAnyRole('ANONYMOUS', 'USER')")
        .antMatchers("/login/*").access("hasAnyRole('ANONYMOUS', 'USER')")
        .antMatchers("/logout/*").access("hasAnyRole('ANONYMOUS', 'USER')")
        .antMatchers("/admin/*").access("hasRole('ADMIN')")
        .antMatchers("/events/").access("hasRole('ADMIN')")
        .antMatchers("/**").access("hasRole('USER')")
```

你可能会注意到`/events/`的安全约束很脆弱。例如，`/events` URL 不受 Spring Security 的保护，以限制`ADMIN`角色。这证明了我们需要确保提供多层次的安全性。我们将在第十一章中利用这种弱点，进行*细粒度访问控制*。

将`access`属性从`hasAnyRole('ANONYMOUS', 'USER')`更改为`permitAll()`可能看起来并不重要，但这只是 Spring Security 表达式强大功能的冰山一角。我们将在书的第二部分更详细地讨论访问控制和 Spring 表达式。运行应用程序以验证更新是否有效。

您的代码现在应该看起来像`chapter02.04-calendar`。

# 有条件地显示认证信息。

目前，我们的应用程序没有关于我们是否登录的任何指示。事实上，它看起来好像我们总是登录，因为`Logout`链接总是显示。在本节中，我们将演示如何使用 Thymeleaf 的 Spring Security 标签库显示认证用户的用户名，并根据条件显示页面的部分内容。我们通过执行以下步骤来实现：

1.  更新您的依赖项，包括`thymeleaf-extras-springsecurity4` JAR 文件。由于我们正在使用 Gradle，我们将在`build.gradle`文件中添加一个新的依赖项声明，如下所示：

```java
        //build.gradle

           dependency{
              ...
              compile 'org.thymeleaf.extras:thymeleaf-
              extras-springsecurity4'
         }
```

1.  接下来，我们需要如下向 Thymeleaf 引擎添加 `SpringSecurityDialect`：

```java
        //src/com/packtpub/springsecurity/web/configuration/
        ThymeleafConfig.java

            @Bean
            public SpringTemplateEngine templateEngine(
             final ServletContextTemplateResolver resolver)   
            {
                SpringTemplateEngine engine = new SpringTemplateEngine();
               engine.setTemplateResolver(resolver);
 engine.setAdditionalDialects(new HashSet<IDialect>() {{ add(new LayoutDialect()); add(new SpringSecurityDialect()); }});                return engine;
            }
```

1.  更新 `header.html` 文件以利用 Spring Security 标签库。你可以按照如下方式找到更新：

```java
        //src/main/webapp/WEB-INF/templates/fragments/header.html

            <html xmlns:th="http://www.thymeleaf.org" 
 xmlns:sec="http://www.thymeleaf.org/thymeleaf- 
            extras-springsecurity4">
            ...
        <div id="navbar" class="collapse navbar-collapse">
            ...
            <ul class="nav navbar-nav pull-right" 
 sec:authorize="isAuthenticated()">
                <li>
                    <p class="navbar-text">Welcome <div class="navbar-text"  
                    th:text="${#authentication.name}">User</div></p>
                </li>
                <li>
                    <a id="navLogoutLink" class="btn btn-default" 
                    role="button" th:href="@{/logout}">Logout</a>
                </li>
                <li>&nbsp;|&nbsp;</li>
            </ul>
            <ul class="nav navbar-nav pull-right" 
 sec:authorize=" ! isAuthenticated()">
                <li><a id="navLoginLink" class="btn btn-default" 
                role="button"  
                th:href="@{/login/form}">Login</a></li>
                <li>&nbsp;|&nbsp;</li>
            </ul>
            ...
```

`sec:authorize` 属性确定用户是否以 `isAuthenticated()` 值认证，并在用户认证时显示 HTML 节点，如果用户没有认证，则隐藏节点。`access` 属性应该非常熟悉，来自 `antMatcher().access()` 元素。实际上，这两个组件都利用了相同的 SpEL 支持。Thymeleaf 标签库中有不使用表达式的属性。然而，使用 SpEL 通常是更受欢迎的方法，因为它更强大。

`sec:authentication` 属性将查找当前的 `o.s.s.core.Authentication` 对象。`property` 属性将找到 `o.s.s.core.Authentication` 对象的 `principal` 属性，在这个例子中是 `o.s.s.core.userdetails.UserDetails`。然后它获取 `UserDetails` 的 `username` 属性并将其渲染到页面。如果这些细节让你感到困惑，不要担心。我们将在第三章 *自定义认证* 中更详细地介绍这一点。

如果你还没有这样做，请重新启动应用程序以查看我们所做的更新。此时，你可能会意识到我们仍在显示我们没有访问权的链接。例如，`user1@example.com` 不应该看到“所有事件”页面的链接。请放心，当我们详细介绍标签时，我们将在第十一章 *细粒度访问控制* 中解决这个问题。

你的代码现在应该看起来像这样：`chapter02.05-calendar`。

# 登录后的行为自定义。

我们已经讨论了如何自定义用户在登录过程中的体验，但有时在登录后自定义行为是必要的。在本节中，我们将讨论 Spring Security 在登录后的行为，并提供一个简单的方法来自定义此行为。

在默认配置中，Spring Security 在成功认证后有两个不同的流程。第一个场景是如果一个用户从未访问过需要认证的资源。在这种情况下，成功登录后，用户将被发送到 `defaultSuccessUrl()` 方法，该方法链接到 `formLogin()` 方法。如果未定义，`defaultSuccessUrl()` 将是应用程序的上下文根。

如果用户在认证之前请求了一个受保护的页面，Spring Security 将使用 `o.s.s.web.savedrequest.RequestCache` 记住在认证之前访问的最后一個受保护的页面。在认证成功后，Spring Security 会将用户发送到在认证之前访问的最后一個受保护的页面。例如，如果一个未认证的用户请求“我的事件”页面，他们将被发送到登录页面。

成功认证后，他们将被发送到之前请求的“我的事件”页面。

一个常见的需求是自定义 Spring Security，使其根据用户的角色发送用户到不同的`defaultSuccessUrl()`方法。让我们来看看如何通过执行以下步骤来实现这一点：

1.  第一步是配置`defaultSuccessUrl()`方法，它在`formLogin()`方法之后链式调用。大胆地更新`security.xml`文件，使用`/default`而不是上下文根：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        SecurityConfig.java

          .formLogin()
                      .loginPage("/login/form")
                      .loginProcessingUrl("/login")
                      .failureUrl("/login/form?error")
                      .usernameParameter("username")
                      .passwordParameter("password")
 .defaultSuccessUrl("/default")                      .permitAll()
```

1.  下一步是创建一个处理`/default`的控制器。在下面的代码中，你会发现一个示例 Spring MVC 控制器`DefaultController`，它演示了如何将管理员重定向到所有事件页面，并将其他用户重定向到欢迎页面。在以下位置创建一个新的文件：

```java
        //src/main/java/com/packtpub/springsecurity/web/controllers/
        DefaultController.java

            // imports omitted
            @Controller 
            public class DefaultController {
           @RequestMapping("/default") 
             public String defaultAfterLogin(HttpServletRequest request) { 
                 if (request.isUserInRole("ADMIN")) { 
                     return "redirect:/events/"; 
                 } 
                 return "redirect:/"; 
             }
        }
```

在 Spring Tool Suite 中，你可以使用*Shift* + *Ctrl* + *O* 来自动添加缺少的导入。

关于`DefaultController`及其工作方式有一点需要注意。首先是 Spring Security 使`HttpServletRequest`参数意识到当前登录的用户。在这个实例中，我们能够不依赖 Spring Security 的任何 API 来检查用户属于哪个角色。这是好的，因为如果 Spring Security 的 API 发生变化，或者我们决定要切换我们的安全实现，我们需要更新的代码就会更少。还应注意的是，尽管我们用 Spring MVC 控制器实现这个控制器，但我们的`defaultSuccessUrl()`方法如果需要，可以由任何控制器实现（例如，Struts，一个标准的 servlet 等）处理。

1.  如果你希望总是去到`defaultSuccessUrl()`方法，你可以利用`defaultSuccessUrl()`方法的第二个参数，这是一个`Boolean`用于始终使用。我们不会在我们的配置中这样做，但你可以如下看到一个例子：

```java
        .defaultSuccessUrl("/default", true)
```

1.  你现在可以尝试一下了。重新启动应用程序并直接转到我的事件页面，然后登录；你会发现你在我的事件页面。

1.  然后，退出并尝试以`user1@example.com`的身份登录。

1.  你应该在欢迎页面。退出并以`admin1@example.com`的身份登录，然后你会被

    被发送到所有事件页面。

你的代码现在应该看起来像`chapter02.06-calendar`。

# 总结

在本章中，我们已经应用了非常基础的 Spring Security 配置，解释了如何自定义用户的登录和登出体验，并演示了如何在我们的网络应用程序中显示基本信息，例如用户名。

在下一章中，我们将讨论 Spring Security 中的认证是如何工作的，以及我们如何可以根据自己的需求来定制它。


# 第三章：自定义认证

在第二章，*使用 Spring Security 入门*，我们展示了如何使用内存中的数据存储来认证用户。在本章中，我们将探讨如何通过将 Spring Security 的认证支持扩展到使用我们现有的 API 集来解决一些常见的世界问题。通过这种探索，我们将了解 Spring Security 用于认证用户所使用的每个构建块。

在本章中，我们将介绍以下主题：

+   利用 Spring Security 的注解和基于 Java 的配置

+   发现如何获取当前登录用户的具体信息

+   在创建新账户后添加登录的能力

+   学习向 Spring Security 指示用户已认证的最简单方法

+   创建自定义`UserDetailsService`和`AuthenticationProvider`实现，以适当地将应用程序的其他部分与 Spring Security 解耦

+   添加基于域的认证，以演示如何使用不仅仅是用户名和密码进行认证

# JBCP 日历架构

在附录中，*附加参考资料*。

由于本章是关于将 Spring Security 与自定义用户和 API 集成的，我们将从对 JBCP 日历应用程序中的域模型的快速介绍开始。

# 日历用户对象

我们的日历应用程序使用一个名为`CalendarUser`的域对象，其中包含有关我们的用户的信息，如下所示：

```java
    //src/main/java/com/packtpub/springsecurity/domain/CalendarUser.java

    public class CalendarUser implements Serializable {
       private Integer id;
       private String firstName;
       private String lastName;
       private String email;
       private String password;
       ... accessor methods omitted ..
    }
```

# 事件对象

我们的应用程序有一个`Event`对象，其中包含有关每个事件的详细信息，如下所示：

```java
    //src/main/java/com/packtpub/springsecurity/domain/Event.java

    public class Event {
       private Integer id;
       private String summary;
       private String description;
       private Calendar when;
       private CalendarUser owner;
       private CalendarUser attendee;
       ... accessor methods omitted ..
    }
```

# 日历服务接口

我们的应用程序包含一个`CalendarService`接口，可以用来访问和存储我们的域对象。`CalendarService`的代码如下：

```java
    //src/main/java/com/packtpub/springsecurity/service/CalendarService.java

    public interface CalendarService {
       CalendarUser getUser(int id);
       CalendarUser findUserByEmail(String email);
       List<CalendarUser> findUsersByEmail(String partialEmail);
       int createUser(CalendarUser user);
       Event getEvent(int eventId);
       int createEvent(Event event);
       List<Event> findForUser(int userId);
       List<Event> getEvents();
    }
```

我们不会讨论`CalendarService`中使用的方法，但它们应该是相当直接的。如果您想了解每个方法的作用，请查阅示例代码中的 Javadoc。

# 用户上下文接口

像大多数应用程序一样，我们的应用程序需要与我们当前登录的用户进行交互。我们创建了一个非常简单的接口，名为`UserContext`，用于管理当前登录的用户，如下所示：

```java
    //src/main/java/com/packtpub/springsecurity/service/UserContext.java

    public interface UserContext {
       CalendarUser getCurrentUser();
       void setCurrentUser(CalendarUser user);
    }
```

这意味着我们的应用程序可以调用`UserContext.getCurrentUser()`来获取当前登录用户的信息。它还可以调用`UserContext.setCurrentUser(CalendarUser)`来指定哪个用户已登录。在本章后面，我们将探讨如何编写实现此接口的实现，该实现使用 Spring Security 访问我们当前的用户并使用`SecurityContextHolder`获取他们的详细信息。

Spring Security 提供了很多不同的方法来验证用户。然而，最终结果是 Spring Security 会将`o.s.s.core.context.SecurityContext`填充为`o.s.s.core.Authentication`。`Authentication`对象代表了我们在认证时收集的所有信息（用户名、密码、角色等）。然后`SecurityContext`接口被设置在`o.s.s.core.context.SecurityContextHolder`接口上。这意味着 Spring Security 和开发者可以使用`SecurityContextHolder`来获取关于当前登录用户的信息。以下是一个获取当前用户名的示例：

```java
    String username = SecurityContextHolder.getContext()
       .getAuthentication()
       .getName();
```

需要注意的是，应该始终对`Authentication`对象进行`null`检查，因为如果用户没有登录，这个对象可能是`null`。

# `SpringSecurityUserContext`接口

当前的`UserContext`实现`UserContextStub`是一个总是返回相同用户的存根。这意味着无论谁登录，My Events 页面都会显示相同的用户。让我们更新我们的应用程序，利用当前 Spring Security 用户的用户名，来确定在 My Events 页面上显示哪些事件。

你应该从`chapter03.00-calendar`中的示例代码开始。

请按照以下步骤操作：

1.  第一步是将`UserContextStub`上的`@Component`属性注释掉，以便我们的应用程序不再使用我们的扫描结果。

`@Component`注解与在`com/packtpub/springsecurity/web/configuration/WebMvcConfig.java`中找到的`@ComponentScan`注解一起使用，用于自动创建 Spring bean，而不是为每个 bean 创建显式的 XML 或 Java 配置。您可以在[`static.springsource.org/spring/docs/current/spring-framework-reference/html/`](http://static.springsource.org/spring/docs/current/spring-framework-reference/html/)中了解更多关于 Spring 扫描类路径的信息。

请查看以下代码片段：

```java
        //src/main/java/com/packtpub/springsecurity/service/UserContextStub.java

        ...
        //@Component
        public class UserContextStub implements UserContext {
        ...
```

1.  下一步是利用`SecurityContext`来获取当前登录的用户。在本章的代码中，我们包含了`SpringSecurityUserContext`，它已经集成了必要的依赖项，但没有任何实际功能。

1.  打开`SpringSecurityUserContext.java`文件，添加`@Component`注解。接下来，替换`getCurrentUser`实现，如下面的代码片段所示：

```java
        //src/main/java/com/packtpub/springsecurity/service/
        SpringSecurityUserContext.java

        @Component
        public class SpringSecurityUserContext implements UserContext {
          private final CalendarService calendarService;
          private final UserDetailsService userDetailsService;
        @Autowired
        public SpringSecurityUserContext(CalendarService calendarService, 
        UserDetailsService userDetailsService) {
           this.calendarService = calendarService;
           this.userDetailsService = userDetailsService;
        }
        public CalendarUser getCurrentUser() {
           SecurityContext context = SecurityContextHolder.getContext();
           Authentication authentication = context.getAuthentication();
           if (authentication == null) {
             return null;
           }
           String email = authentication.getName();
           return calendarService.findUserByEmail(email);
        }
        public void setCurrentUser(CalendarUser user) {
           throw new UnsupportedOperationException();
        }
        }
```

我们的代码从当前 Spring Security 的`Authentication`对象中获取用户名，并利用该用户名通过电子邮件地址查找当前的`CalendarUser`对象。由于我们的 Spring Security 用户名是一个电子邮件地址，因此我们能够使用电子邮件地址将`CalendarUser`与 Spring Security 用户关联起来。请注意，如果我们打算关联账户，通常我们希望能够用我们生成的键来做这件事，而不是可能改变的东西（也就是说，电子邮件地址）。我们遵循只向应用程序返回我们的域对象的良好实践。这确保了我们的应用程序只认识我们的`CalendarUser`对象，从而与 Spring Security 解耦。

这段代码可能看起来与我们使用`sec:authorize="isAuthenticated()"`时出奇地相似。

在第二章*Spring Security 入门*中使用的`tag`属性，来显示当前用户的用户名。实际上，Spring Security 标签库正是像我们在这里一样使用`SecurityContextHolder`。我们本可以使用我们的`UserContext`接口将当前用户放在`HttpServletRequest`上，从而摆脱对 Spring Security 标签库的依赖。

1.  启动应用程序，访问`http://localhost:8080/`，并使用`admin1@example.com`作为用户名和`admin1`作为密码登录。

1.  访问我的事件页面，您将看到只显示当前用户的那些事件，该用户是所有者或参与者。

1.  尝试创建一个新事件；您会观察到事件的所有者现在与登录的用户相关联。

1.  退出应用程序，然后用`user1@example.com`作为用户名和`user1`作为密码重复这些步骤。

您的代码现在应该看起来像`chapter03.01-calendar`。

# 使用 SecurityContextHolder 登录新用户

一个常见的需求是允许用户创建一个新的账户，然后自动登录到应用程序。在本节中，我们将描述最简单的方法来指示用户已认证，通过利用`SecurityContextHolder`。

# 在 Spring Security 中管理用户

在第一章*一个不安全应用程序的剖析*中提供的应用程序，提供了一个创建新的`CalendarUser`对象的机制，因此，在用户注册后，创建我们的`CalendarUser`对象应该相对简单。然而，Spring Security 对`CalendarUser`一无所知。这意味着我们还需要在 Spring Security 中添加一个新的用户。别担心，我们会在本章后面消除对用户双重维护的需要。

Spring Security 提供了一个`o.s.s.provisioning.UserDetailsManager`接口来管理用户。还记得我们的内存中的 Spring Security 配置吗？

```java
    auth.inMemoryAuthentication().
    withUser("user").password("user").roles("USER");
```

`.inMemoryAuthentication()`方法创建了一个名为`o.s.s.provisioning.InMemoryUserDetailsManager`的内存实现`UserDetailsManager`，该实现可以用来创建一个新的 Spring Security 用户。

当从 XML 配置转换为基于 Java 的配置时，Spring Security 中存在一个限制，即 Spring Security DSL 目前不支持暴露多个 bean。关于这个问题已经打开了一个 JIRA，链接为[`jira.spring.io/browse/SPR-13779.`](https://jira.spring.io/browse/SPR-13779)

让我们看看如何通过执行以下步骤来管理 Spring Security 中的用户：

1.  为了通过基于 Java 的配置暴露`UserDetailsManager`，我们需要在`WebSecurityConfigurerAdapter` DSL 之外创建`InMemoryUserDetailsManager`：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        SecurityConfig.java

        @Bean
        @Override
        public UserDetailsManager userDetailsService() {
           InMemoryUserDetailsManager manager = new 
           InMemoryUserDetailsManager();
           manager.createUser(
               User.withUsername("user1@example.com")
                   .password("user1").roles("USER").build());
           manager.createUser(
               User.withUsername("admin1@example.com")
                   .password("admin1").roles("USER", "ADMIN").build());
           return manager;
        }
```

1.  一旦我们在 Spring 配置中暴露了`UserDetailsManager`接口，我们所需要做的就是更新我们现有的`CalendarService`实现，`DefaultCalendarService`，以在 Spring Security 中添加用户。对`DefaultCalendarService.java`文件进行以下更新：

```java
        //src/main/java/com/packtpub/springsecurity/service/
        DefaultCalendarService.java

        public int createUser(CalendarUser user) {
            List<GrantedAuthority> authorities = AuthorityUtils.
            createAuthorityList("ROLE_USER");
            UserDetails userDetails = new User(user.getEmail(),
            user.getPassword(), authorities);
           // create a Spring Security user
           userDetailsManager.createUser(userDetails);
           // create a CalendarUser
           return userDao.createUser(user);
        }
```

1.  为了利用`UserDetailsManager`，我们首先将`CalendarUser`转换为 Spring Security 的`UserDetails`对象。

1.  后来，我们使用`UserDetailsManager`来保存`UserDetails`对象。转换是必要的，因为 Spring Security 不知道如何保存我们的自定义`CalendarUser`对象，所以我们必须将`CalendarUser`映射到 Spring Security 理解的对象。您会注意到`GrantedAuthority`对象对应于我们`SecurityConfig`文件中的`authorities`属性。我们为了简单起见并因为我们的现有系统没有角色概念而硬编码这个值。

# 登录新用户到应用程序

现在我们能够向系统添加新用户，我们需要指示用户已认证。更新`SpringSecurityUserContext`以在 Spring Security 的`SecurityContextHolder`对象上设置当前用户，如下所示：

```java
    //src/main/java/com/packtpub/springsecurity/service/
    SpringSecurityUserContext.java

    public void setCurrentUser(CalendarUser user) {
      UserDetails userDetails = userDetailsService.
      loadUserByUsername(user.getEmail());
      Authentication authentication = new   
      UsernamePasswordAuthenticationToken(userDetails, user.getPassword(),
      userDetails.getAuthorities());
      SecurityContextHolder.getContext().
      setAuthentication(authentication);
    }
```

我们首先执行的步骤是将我们的`CalendarUser`对象转换为 Spring Security 的`UserDetails`对象。这是必要的，因为正如 Spring Security 不知道如何保存我们的自定义`CalendarUser`对象一样，Spring Security 也不理解如何使用我们的自定义`CalendarUser`对象做出安全决策。我们使用 Spring Security 的`o.s.s.core.userdetails.UserDetailsService`接口来获取我们通过`UserDetailsManager`保存的相同的`UserDetails`对象。`UserDetailsService`接口提供了`UserDetailsManager`对象的功能的一个子集，通过用户名查找。

接下来，我们创建一个`UsernamePasswordAuthenticationToken`对象，并将`UserDetails`、密码和`GrantedAuthority`放入其中。最后，我们在`SecurityContextHolder`上设置认证。在 Web 应用程序中，Spring Security 会自动将`SecurityContext`对象与`SecurityContextHolder`中的 HTTP 会话关联起来。

重要的是，Spring Security 不能被指示忽略一个 URL（即使用`permitAll()`方法），正如在第二章《开始使用 Spring Security》中讨论的那样，其中访问或设置了`SecurityContextHolder`。这是因为 Spring Security 将忽略该请求，因此不会为后续请求持久化`SecurityContext`。允许访问使用`SecurityContextHolder`的 URL 的正确方法是指定`antMatchers()`方法的`access`属性（即`antMatchers(¦).permitAll()`）。

值得一提的是，我们本可以直接通过创建一个新的`o.s.s.core.userdetails.User`对象来转换`CalendarUser`，而不是在`UserDetailsService`中查找。例如，下面的代码也可以认证用户：

```java
List<GrantedAuthority> authorities =
AuthorityUtils.createAuthorityList("ROLE_USER");
UserDetails userDetails = new User("username","password",authorities); Authentication authentication = new UsernamePasswordAuthenticationToken ( userDetails,userDetails.getPassword(),userDetails.getAuthorities());
SecurityContextHolder.getContext()
.setAuthentication(authentication);
```

这种方法的优点在于，我们无需再次访问数据存储。在我们这个案例中，数据存储是一个内存中的数据存储，但这也可能是由一个数据库支持的，这可能会带来一些安全风险。这种方法的一个缺点是我们无法复用代码太多。由于这种方法调用不频繁，我们选择复用代码。通常，最佳做法是单独评估每种情况，以确定哪种方法最合适。

# 更新 SignupController

应用程序有一个`SignupController`对象，该对象处理创建新的`CalendarUser`对象的 HTTP 请求。最后一步是更新`SignupController`以创建我们的用户，然后指示他们已经登录。对`SignupController`进行以下更新：

```java
//src/main/java/com/packtpub/springsecurity/web/controllers/
SignupController.java

@RequestMapping(value="/signup/new", method=RequestMethod.POST)
public String signup(@Valid SignupForm signupForm,
BindingResult result, RedirectAttributes redirectAttributes) {
... existing validation ¦
user.setPassword(signupForm.getPassword());
int id = calendarService.createUser(user);
user.setId(id);
userContext.setCurrentUser(user);
redirectAttributes.addFlashAttribute("message", "Success");
return "redirect:/";
}
```

如果你还没有这么做，请重新启动应用程序，访问`http://localhost:8080/`，创建一个新的用户，并查看新用户是否自动登录。

你的代码现在应该看起来像`chapter03.02-calendar`。

# 创建自定义 UserDetailsService 对象

虽然我们能够将我们的领域模型（`CalendarUser`）与 Spring Security 的领域模型（`UserDetails`）关联起来，但我们不得不维护用户的多个表示。为了解决这种双重维护，我们可以实现一个自定义的`UserDetailsService`对象，将我们现有的`CalendarUser`领域模型转换为 Spring Security`UserDetails`接口的实现。通过将我们的`CalendarUser`对象转换为`UserDetails`，Spring Security 可以使用我们的自定义领域模型做出安全决策。这意味着我们将不再需要管理用户的两种不同表示。

# 日历用户详细信息服务类

到目前为止，我们需要两种不同的用户表示：一种用于 Spring Security 做出安全决策，另一种用于我们的应用程序将我们的领域对象关联起来。创建一个名为`CalendarUserDetailsService`的新类，使 Spring Security 意识到我们的`CalendarUser`对象。这将确保 Spring Security 可以根据我们的领域模型做出决策。按照如下方式创建一个名为`CalendarUserDetailsService.java`的新文件：

```java
//src/main/java/com/packtpub/springsecurity/core/userdetails/
CalendarUserDetailsService.java

// imports and package declaration omitted

@Component
public class CalendarUserDetailsService implements
UserDetailsService {
private final CalendarUserDao calendarUserDao;
@Autowired
public CalendarUserDetailsService(CalendarUserDao
   calendarUserDao) {
   this.calendarUserDao = calendarUserDao;
}
public UserDetails loadUserByUsername(String username) throws
   UsernameNotFoundException {
   CalendarUser user = calendarUserDao.findUserByEmail(username);
  if (user == null) {
     throw new UsernameNotFoundException("Invalid
       username/password.");
   }
   Collection<? extends GrantedAuthority> authorities =
     CalendarUserAuthorityUtils.createAuthorities(user);
   return new User(user.getEmail(), user.getPassword(),
     authorities);
}
}
```

在 Spring Tool Suite 中，您可以使用*Shift*+*Ctrl*+*O*快捷键轻松添加缺少的导入。另外，您还可以从下一个检查点（`chapter03.03-calendar`）复制代码。

在这里，我们使用`CalendarUserDao`通过电子邮件地址获取`CalendarUser`。我们确保不返回`null`值；相反，应该抛出`UsernameNotFoundException`异常，因为返回`null`会破坏`UserDetailsService`接口。

然后我们将`CalendarUser`转换为由用户实现的`UserDetails`。

现在我们利用提供的示例代码中提供的工具类`CalendarUserAuthorityUtils`。这将根据电子邮件地址创建`GrantedAuthority`，以便我们可以支持用户和管理员。如果电子邮件地址以`admin`开头，则用户被视为`ROLE_ADMIN, ROLE_USER`。否则，用户被视为`ROLE_USER`。当然，在实际应用程序中我们不会这样做，但正是这种简单性让我们能够专注于本课。

# 配置 UserDetailsService

现在我们已经有一个新的`UserDetailsService`对象，让我们更新 Spring Security 配置以使用它。由于我们利用类路径扫描和`@Component`注解，我们的`CalendarUserDetailsService`类自动添加到 Spring 配置中。这意味着我们只需要更新 Spring Security 以引用我们刚刚创建的`CalendarUserDetailsService`类。我们还可以删除`configure()`和`userDetailsService()`方法，因为我们现在提供了自己的`UserDetailsService`实现。按照如下方式更新`SecurityConfig.java`文件：

```java
//src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

@Override
public void configure(AuthenticationManagerBuilder auth) throws Exception {
    ...
}
@Bean
@Override
public UserDetailsManager userDetailsService() {
    ...
}
```

# 删除对 UserDetailsManager 的引用

我们需要删除在`DefaultCalendarService`中使用`UserDetailsManager`进行同步的代码，该代码将 Spring Security 的`o.s.s.core.userdetails.User`接口和`CalendarUser`同步。首先，由于 Spring Security 现在引用`CalendarUserDetailsService`，所以这段代码是不必要的。其次，由于我们移除了`inMemoryAuthentication()`方法，我们 Spring 配置中没有定义`UserDetailsManager`对象。删除在`DefaultCalendarService`中找到的所有对`UserDetailsManager`的引用。更新将类似于以下示例片段：

```java
//src/main/java/com/packtpub/springsecurity/service/
DefaultCalendarService.java

public class DefaultCalendarService implements CalendarService {
   private final EventDao eventDao;
   private final CalendarUserDao userDao;
   @Autowired
   public DefaultCalendarService(EventDao eventDao,CalendarUserDao userDao) {
       this.eventDao = eventDao;
       this.userDao = userDao;
   }
   ...
   public int createUser(CalendarUser user) {
       return userDao.createUser(user);
   }
}
```

启动应用程序并查看 Spring Security 的内存中`UserDetailsManager`对象已不再必要（我们已将其从我们的`SecurityConfig.java`文件中删除）。

您的代码现在应该看起来像`chapter03.03-calendar`。

# 日历用户详细信息对象

我们已经成功消除了同时管理 Spring Security 用户和我们自己的`CalendarUser`对象的需求。然而，我们仍然需要不断在两者之间进行转换，这很麻烦。相反，我们将创建一个`CalendarUserDetails`对象，该对象可以被称为`UserDetails`和`CalendarUser`。使用以下代码更新`CalendarUserDetailsService`：

```java
//src/main/java/com/packtpub/springsecurity/core/userdetails/
CalendarUserDetailsService.java

public UserDetails loadUserByUsername(String username) throws
UsernameNotFoundException {
...
return new CalendarUserDetails(user);
}
private final class CalendarUserDetails extends CalendarUser 
implements UserDetails {
CalendarUserDetails(CalendarUser user) {
   setId(user.getId());
   setEmail(user.getEmail());
   setFirstName(user.getFirstName());
   setLastName(user.getLastName());
   setPassword(user.getPassword());
}
public Collection<? extends GrantedAuthority>
   getAuthorities() {
   return CalendarUserAuthorityUtils.createAuthorities(this);
}
public String getUsername() {
   return getEmail();
}
public boolean isAccountNonExpired() { return true; }
public boolean isAccountNonLocked() { return true; }
public boolean isCredentialsNonExpired() { return true; }
public boolean isEnabled() { return true; }
}
```

在下一节中，我们将看到我们的应用程序现在可以引用当前`CalendarUser`对象的主体认证。然而，Spring Security 仍然可以将`CalendarUserDetails`视为一个`UserDetails`对象。

# 简化`SpringSecurityUserContext`

我们已经更新了`CalendarUserDetailsService`，使其返回一个扩展了`CalendarUser`并实现了`UserDetails`的`UserDetails`对象。这意味着，我们不需要在两个对象之间进行转换，只需简单地引用一个`CalendarUser`对象。按照以下方式更新`SpringSecurityUserContext`：

```java
public class SpringSecurityUserContext implements UserContext {
public CalendarUser getCurrentUser() {
   SecurityContext context = SecurityContextHolder.getContext();
   Authentication authentication = context.getAuthentication();
   if(authentication == null) {
      return null;
   }
   return (CalendarUser) authentication.getPrincipal();
}

public void setCurrentUser(CalendarUser user) {
   Collection authorities =
     CalendarUserAuthorityUtils.createAuthorities(user);
   Authentication authentication = new      UsernamePasswordAuthenticationToken(user,user.getPassword(), authorities);
   SecurityContextHolder.getContext()
     .setAuthentication(authentication);
}
}
```

更新不再需要使用`CalendarUserDao`或 Spring Security 的`UserDetailsService`接口。还记得我们上一节中的`loadUserByUsername`方法吗？这个方法调用的结果成为认证的主体。由于我们更新的`loadUserByUsername`方法返回一个扩展了`CalendarUser`的对象，我们可以安全地将`Authentication`对象的主体转换为`CalendarUser`。当调用`setCurrentUser`方法时，我们可以将一个`CalendarUser`对象作为主体传递给`UsernamePasswordAuthenticationToken`构造函数。这允许我们在调用`getCurrentUser`方法时仍然将主体转换为`CalendarUser`对象。

# 显示自定义用户属性

现在`CalendarUser`已经填充到 Spring Security 的认证中，我们可以更新我们的 UI 来显示当前用户的姓名，而不是电子邮件地址。使用以下代码更新`header.html`文件：

```java
    //src/main/resources/templates/fragments/header.html

    <ul class="nav navbar-nav pull-right" 
 sec:authorize="isAuthenticated()">
       <li id="greeting">
           <p class="navbar-text">Welcome <div class="navbar-text"   
           th:text="${#authentication.getPrincipal().getName()}">
           User</div></p>
       </li>
```

内部地，`"${#authentication.getPrincipal().getName()}"`标签属性执行以下代码。请注意，高亮显示的值与我们在`header.html`文件中指定的认证标签的`property`属性相关联：

```java
    SecurityContext context = SecurityContextHolder.getContext();
    Authentication authentication = context.getAuthentication();
    CalendarUser user = (CalendarUser) authentication.getPrincipal();
    String firstAndLastName = user.getName();
```

重启应用程序，访问`http://localhost:8080/`，登录以查看更新。 Instead of seeing the current user's email, you should now see their first and last names.（您现在应该看到的是当前用户的姓名，而不是电子邮件地址。）

您的代码现在应该看起来像`chapter03.04-calendar`。

# 创建一个自定义的`AuthenticationProvider`对象

Spring Security 委托一个`AuthenticationProvider`对象来确定用户是否已认证。这意味着我们可以编写自定义的`AuthenticationProvider`实现来告知 Spring Security 如何以不同方式进行认证。好消息是 Spring Security 提供了一些`AuthenticationProvider`对象，所以大多数时候你不需要创建一个。事实上，到目前为止，我们一直在使用 Spring Security 的`o.s.s.authentication.dao.DaoAuthenticationProvider`对象，它比较`UserDetailsService`返回的用户名和密码。

# 日历用户认证提供者

在本文节的其余部分，我们将创建一个名为`CalendarUserAuthenticationProvider`的自定义`AuthenticationProvider`对象，它将替换`CalendarUserDetailsService`。然后，我们将使用`CalendarUserAuthenticationProvider`来考虑一个额外的参数，以支持来自多个域的用户认证。

我们必须使用一个`AuthenticationProvider`对象而不是`UserDetailsService`，因为`UserDetails`接口没有领域参数的概念。

创建一个名为`CalendarUserAuthenticationProvider`的新类，如下所示：

```java
    //src/main/java/com/packtpub/springsecurity/authentication/
    CalendarUserAuthenticationProvider.java

    // ¦ imports omitted ...

    @Component
    public class CalendarUserAuthenticationProvider implements
    AuthenticationProvider {
    private final CalendarService calendarService;
    @Autowired
    public CalendarUserAuthenticationProvider
    (CalendarService    calendarService) {
       this.calendarService = calendarService;
    }
    public Authentication authenticate(Authentication
       authentication) throws AuthenticationException {
           UsernamePasswordAuthenticationToken token =   
           (UsernamePasswordAuthenticationToken) 
       authentication;
       String email = token.getName();
       CalendarUser user = null;
       if(email != null) {
         user = calendarService.findUserByEmail(email);
       }
       if(user == null) {
         throw new UsernameNotFoundException("Invalid
         username/password");
       }
       String password = user.getPassword();
       if(!password.equals(token.getCredentials())) {
         throw new BadCredentialsException("Invalid
         username/password");
       }
       Collection<? extends GrantedAuthority> authorities =
         CalendarUserAuthorityUtils.createAuthorities(user);
       return new UsernamePasswordAuthenticationToken(user, password,
         authorities);
    }
    public boolean supports(Class<?> authentication) {
       return UsernamePasswordAuthenticationToken
         .class.equals(authentication);
     }
    }
```

记得在 Eclipse 中你可以使用*Shift*+*Ctrl*+*O*快捷键轻松添加缺失的导入。另外，你也可以从`chapter03.05-calendar`中复制实现。

在 Spring Security 可以调用`authenticate`方法之前，`supports`方法必须对将要传递进去的`Authentication`类返回`true`。在这个例子中，`AuthenticationProvider`可以认证用户名和密码。我们不接受`UsernamePasswordAuthenticationToken`的子类，因为可能有我们不知道如何验证的额外字段。

`authenticate`方法接受一个代表认证请求的`Authentication`对象作为参数。在实际中，它是我们需要尝试验证的用户输入。如果认证失败，该方法应该抛出一个`o.s.s.core.AuthenticationException`异常。如果认证成功，它应该返回一个包含用户适当的`GrantedAuthority`对象的`Authentication`对象。返回的`Authentication`对象将被设置在`SecurityContextHolder`上。如果无法确定认证，该方法应该返回`null`。

认证请求的第一步是从我们需要的`Authentication`对象中提取信息以认证用户。在我们这个案例中，我们提取用户名并通过电子邮件地址查找`CalendarUser`，就像`CalendarUserDetailsService`所做的那样。如果提供的用户名和密码匹配`CalendarUser`，我们将返回一个带有适当`GrantedAuthority`的`UsernamePasswordAuthenticationToken`对象。否则，我们将抛出一个`AuthenticationException`异常。

还记得登录页面是如何利用`SPRING_SECURITY_LAST_EXCEPTION`解释登录失败的原因吗？`AuthenticationProvider`中抛出的`AuthenticationException`异常的消息是最后一个`AuthenticationException`异常，在登录失败时会在我们的登录页面上显示。

# 配置`CalendarUserAuthenticationProvider`对象

让我们执行以下步骤来配置`CalendarUserAuthenticationProvider`：

1.  更新`SecurityConfig.java`文件以引用我们新创建的`CalendarUserAuthenticationProvider`对象，并删除对`CalendarUserDetailsService`的引用，如下代码片段所示：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        SecurityConfig.java

 @Autowired CalendarUserAuthenticationProvider cuap;        @Override
        public void configure(AuthenticationManagerBuilder auth) 
        throws Exception {
           auth.authenticationProvider(cuap);
        }
```

1.  重启应用程序并确保一切仍然正常工作。作为用户，我们并没有察觉到任何不同。然而，作为开发者，我们知道`CalendarUserDetails`已经不再需要；我们仍然能够显示当前用户的姓名和姓氏，Spring Security 仍然能够利用`CalendarUser`进行认证。

您的代码现在应该看起来像`chapter03.05-calendar`。

# 使用不同参数进行认证

`AuthenticationProvider`的一个优点是它可以接受任何你想要的参数进行认证。例如，也许你的应用程序使用一个随机标识符进行认证，或者也许它是一个多租户应用程序，需要用户名、密码和域名。在下一节中，我们将更新`CalendarUserAuthenticationProvider`以支持多个域名。

域名是一种定义用户范围的方式。例如，如果我们一次性部署了一个应用但多个客户都在使用这个部署，每个客户可能都需要一个名为`admin`的用户。通过在用户对象中添加一个域名，我们可以确保每个用户都是独一无二的，同时还能满足这一需求。

# `DomainUsernamePasswordAuthenticationToken`类

当用户进行认证时，Spring Security 会将一个`Authentication`对象提交给`AuthenticationProvider`，其中包含用户提供的信息。当前的`UsernamePasswordAuthentication`对象只包含用户名和密码字段。创建一个包含`domain`字段的`DomainUsernamePasswordAuthenticationToken`对象，如下代码片段所示：

```java
    //src/main/java/com/packtpub/springsecurity/authentication/
    DomainUsernamePasswordAuthenticationToken.java

    public final class DomainUsernamePasswordAuthenticationToken extends     
    UsernamePasswordAuthenticationToken {
            private final String domain;
            // used for attempting authentication
           public DomainUsernamePasswordAuthenticationToken(String
           principal, String credentials, String domain) {
              super(principal, credentials);
              this.domain = domain;
            } 
    // used for returning to Spring Security after being
    //authenticated
    public DomainUsernamePasswordAuthenticationToken(CalendarUser
       principal, String credentials, String domain,
       Collection<? extends GrantedAuthority> authorities) {
         super(principal, credentials, authorities);
         this.domain = domain;
       }
    public String getDomain() {
       return domain;
    }
    }
```

# 更新`CalendarUserAuthenticationProvider`

接下来让我们看看更新`CalendarUserAuthenticationProvider.java`文件以下步骤：

1.  现在，我们需要更新`CalendarUserAuthenticationProvider`以使用域名字段，如下所示：

```java
        //src/main/java/com/packtpub/springsecurity/authentication/
        CalendarUserAuthenticationProvider.java

        public Authentication authenticate(Authentication authentication) 
        throws AuthenticationException {
             DomainUsernamePasswordAuthenticationToken token =
             (DomainUsernamePasswordAuthenticationToken) authentication;
        String userName = token.getName();
        String domain = token.getDomain();
        String email = userName + "@" + domain;
        ... previous validation of the user and password ...
        return new DomainUsernamePasswordAuthenticationToken(user,
        password, domain, authorities);
        }
        public boolean supports(Class<?> authentication) {
          return DomainUsernamePasswordAuthenticationToken
          .class.equals(authentication);
        }
```

1.  我们首先更新`supports`方法，以便 Spring Security 会将`DomainUsernamePasswordAuthenticationToken`传递到我们的`authenticate`方法中。

1.  然后我们利用域名信息来创建我们的电子邮件地址和进行认证，就像我们之前所做的那样。坦白说，这个例子有些牵强。然而，这个例子能够说明如何使用一个附加参数进行认证。

1.  现在，`CalendarUserAuthenticationProvider`接口可以利用新的域字段了。然而，用户无法指定域。为此，我们必须更新我们的`login.html`文件。

# 在登录页面上添加域

打开`login.html`文件，添加一个名为`domain`的新输入，如下所示：

```java
    //src/main/resources/templates/login.html

    ...
    <label for="username">Username</label>
    <input type="text" id="username" name="username"/>
    <label for="password">Password</label>
    <input type="password" id="password" name="password"/>
    <label for="domain">Domain</label>
    <input type="text" id="domain" name="domain"/>
    ¦
```

现在，当用户尝试登录时，将提交域。然而，Spring Security 不知道如何使用这个域来创建一个`DomainUsernamePasswordAuthenticationToken`对象并将其传递给`AuthenticationProvider`。为了解决这个问题，我们需要创建`DomainUsernamePasswordAuthenticationFilter`。

# `DomainUsernamePasswordAuthenticationFilter`类

Spring Security 提供了一系列作为用户认证控制器的 servlet 过滤器。这些过滤器作为`FilterChainProxy`对象的代理之一，我们在第二章中讨论过，*Spring Security 入门*。以前，`formLogin()`方法指导 Spring Security 使用`o.s.s.web.authentication.UsernamePasswordAuthenticationFilter`作为登录控制器。过滤器的工作是执行以下任务：

+   从 HTTP 请求中获取用户名和密码。

+   使用从 HTTP 请求中获取的信息创建一个`UsernamePasswordAuthenticationToken`对象。

+   请求 Spring Security 验证`UsernamePasswordAuthenticationToken`。

+   如果验证令牌，它将在`SecurityContextHolder`上设置返回的认证，就像我们为新用户注册账户时所做的那样。我们需要扩展`UsernamePasswordAuthenticationFilter`以利用我们新创建的`DoainUsernamePasswordAuthenticationToken`对象。

+   创建一个`DomainUsernamePasswordAuthenticationFilter`对象，如下所示：

```java
        //src/main/java/com/packtpub/springsecurity/web/authentication/
        DomainUsernamePasswordAuthenticationFilter.java

        public final class
        DomainUsernamePasswordAuthenticationFilter extends 
         UsernamePasswordAuthenticationFilter {
        public Authentication attemptAuthentication
        (HttpServletRequest request,HttpServletResponse response) throws
        AuthenticationException {
               if (!request.getMethod().equals("POST")) {
                 throw new AuthenticationServiceException
                 ("Authentication method not supported: " 
                  + request.getMethod());
               }
           String username = obtainUsername(request);
           String password = obtainPassword(request);
           String domain = request.getParameter("domain");
           // authRequest.isAuthenticated() = false since no
           //authorities are specified
           DomainUsernamePasswordAuthenticationToken authRequest
           = new DomainUsernamePasswordAuthenticationToken(username, 
           password, domain);
          setDetails(request, authRequest);
          return this.getAuthenticationManager()
          .authenticate(authRequest);
          }
        }
```

新的`DomainUsernamePasswordAuthenticationFilter`对象将执行以下任务：

+   从`HttpServletRequest`方法获取用户名、密码和域。

+   使用从 HTTP 请求中获取的信息创建我们的`DomainUsernamePasswordAuthenticationToken`对象。

+   请求 Spring Security 验证`DomainUsernamePasswordAuthenticationToken`。工作委托给`CalendarUserAuthenticationProvider`。

+   如果验证令牌，其超类将在`SecurityContextHolder`上设置由`CalendarUserAuthenticationProvider`返回的认证，就像我们在用户创建新账户后进行认证一样。

# 更新我们的配置

现在我们已经创建了所有需要的额外参数的代码，我们需要配置 Spring Security 使其能够意识到这个参数。以下代码片段包括了我们`SecurityConfig.java`文件以支持我们的额外参数所需的必要更新：

```java
//src/main/java/com/packtpub/springsecurity/configuration/
SecurityConfig.java

@Override
protected void configure(final HttpSecurity http) throws Exception {
   http.authorizeRequests()
       ...
       .and().exceptionHandling()
           .accessDeniedPage("/errors/403")
           .authenticationEntryPoint(
               loginUrlAuthenticationEntryPoint())
       .and().formLogin()
           .loginPage("/login/form")
           .loginProcessingUrl("/login")
           .failureUrl("/login/form?error")
           .usernameParameter("username")
           .passwordParameter("password")
           .defaultSuccessUrl("/default", true)
           .permitAll()
         ...
          // Add custom UsernamePasswordAuthenticationFilter
 .addFilterAt( domainUsernamePasswordAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class) ; }
@Bean public DomainUsernamePasswordAuthenticationFilter domainUsernamePasswordAuthenticationFilter()
 throws Exception {   DomainUsernamePasswordAuthenticationFilter dupaf = new DomainUsernamePasswordAuthenticationFilter(
                            super.authenticationManagerBean());
   dupaf.setFilterProcessesUrl("/login");
   dupaf.setUsernameParameter("username");
   dupaf.setPasswordParameter("password");
   dupaf.setAuthenticationSuccessHandler(
           new SavedRequestAwareAuthenticationSuccessHandler(){{
               setDefaultTargetUrl("/default");
           }}
   );
   dupaf.setAuthenticationFailureHandler(
           new SimpleUrlAuthenticationFailureHandler(){{
                setDefaultFailureUrl("/login/form?error");
           }}
);
 dupaf.afterPropertiesSet();
   return dupaf;
}
@Bean public LoginUrlAuthenticationEntryPoint loginUrlAuthenticationEntryPoint(){
   return new LoginUrlAuthenticationEntryPoint("/login/form");
}
```

前一个代码段配置了我们在 Spring Security 配置中的标准 bean。我们展示这个是为了表明它是可以做到的。然而，在本书的其余部分，我们将标准 bean 配置放在自己的文件中，因为这样可以减少配置的冗余。如果你遇到困难，或者不喜欢输入所有这些内容，你可以从 `chapter03.06-calendar` 复制它。

以下是一些配置更新的亮点：

+   我们覆盖了 `defaultAuthenticationEntryPoint`，并添加了对 `o.s.s.web.authentication.LoginUrlAuthenticationEntryPoint` 的引用，它决定了当请求受保护的资源且用户未认证时会发生什么。在我们这个案例中，我们被重定向到了一个登录页面。

+   我们移除了 `formLogin()` 方法，并使用 `.addFilterAt()` 方法将我们的自定义过滤器插入到 `FilterChainProxy` 中。这个位置表示 `FilterChain` 代理的委托考虑的顺序，且不能与另一个过滤器重叠，但可以替换当前位置的过滤器。我们用自定义过滤器替换了 `UsernamePasswordAuthenticationFilter`。

+   我们为我们的自定义过滤器添加了配置，该配置引用了由 `configure(AuthenticationManagerBuilder)` 方法创建的认证管理器。

以下图表供您参考：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/7dcf22b3-a3c3-465c-981e-eadbf92a70c2.png)

现在你可以重新启动应用程序，并尝试以下步骤，如前所示的图表，来理解所有部分是如何组合在一起的：

1.  访问 `http://localhost:8080/events`。

1.  Spring Security 将拦截受保护的 URL 并使用 `LoginUrlAuthenticationEntryPoint` 对象来处理它。

1.  `LoginUrlAuthenticationEntryPoint` 对象将会把用户重定向到登录页面。输入用户名 `admin1`，域名 `example.com`，以及密码 `admin1`。

1.  `DomainUserPasswordAuthenticationFilter` 对象将拦截登录请求的过程。然后它将从 HTTP 请求中获取用户名、域名和密码，并创建一个 `DomainUsernamePasswordAuthenticationToken` 对象。

1.  `DomainUserPasswordAuthenticationFilter` 对象提交 `DomainUsernamePasswordAuthenticationToken` 到 `CalendarUserAuthenticationProvider`。

1.  `CalendarUserAuthenticationProvider` 接口验证 `DomainUsernamePasswordAuthenticationToken`，然后返回一个认证的 `DomainUsernamePasswordAuthenticationToken` 对象（也就是说，`isAuthenticated()` 返回 `true`）。

1.  `DomainUserPasswordAuthenticationFilter` 对象用 `DomainUsernamePasswordAuthenticationToken` 更新 `SecurityContext`，并将其放在 `SecurityContextHolder` 上。

你的代码应该看起来像 `chapter03.06-calendar`。

# 应该使用哪种认证方式？

我们已经介绍了认证的三种主要方法，那么哪一种最好呢？像所有解决方案一样，每种方法都有其优点和缺点。你可以通过参考以下列表来找到特定类型认证的使用情况：

+   `SecurityContextHolder`：直接与`SecurityContextHolder`交互无疑是认证用户的最简单方式。当你正在认证一个新创建的用户或以非传统方式进行认证时，它工作得很好。通过直接使用`SecurityContextHolder`，我们不必与 Spring Security 的许多层进行交互。缺点是我们无法获得 Spring Security 自动提供的一些更高级的功能。例如，如果我们想在登录后把用户发送到之前请求的页面，我们还需要手动将此集成到我们的控制器中。

+   `UserDetailsService`：创建一个自定义的`UserDetailsService`对象是一个简单的机制，它允许 Spring Security 根据我们自定义的领域模型做出安全决策。它还提供了一种机制，以便与其他 Spring Security 特性进行钩接。例如，Spring Security 在使用第七章*记住我服务*中介绍的内置记住我支持时需要`UserDetailsService`。当认证不是基于用户名和密码时，`UserDetailsService`对象不起作用。

+   `AuthenticationProvider`：这是扩展 Spring Security 最灵活的方法。它允许用户使用任何我们希望的参数进行认证。然而，如果我们希望利用如 Spring Security 的记住我等特性，我们仍然需要`UserDetailsService`。

# 总结

本章通过实际问题介绍了 Spring Security 中使用的基本构建块。它还向我们展示了如何通过扩展这些基本构建块使 Spring Security 针对我们的自定义领域对象进行认证。总之，我们了解到`SecurityContextHolder`接口是确定当前用户的核心位置。它不仅可以被开发者用来访问当前用户，还可以设置当前登录的用户。

我们还探讨了如何创建自定义的`UserDetailsService`和`AuthenticationProvider`对象，以及如何使用不仅仅是用户名和密码进行认证。

在下一章中，我们将探讨一些基于 JDBC 的认证的内置支持。


# 第四章：JDBC 基础认证

在上一章中，我们看到了如何扩展 Spring Security 以利用我们的`CalendarDao`接口和现有的领域模型来对用户进行身份验证。在本章中，我们将了解如何使用 Spring Security 的内置 JDBC 支持。为了保持简单，本章的示例代码基于我们在第二章，《使用 Spring Security 入门》中设置的 Spring Security。在本章中，我们将涵盖以下主题：

+   使用 Spring Security 内置的基于 JDBC 的认证支持

+   利用 Spring Security 的基于组授权来简化用户管理

+   学习如何使用 Spring Security 的`UserDetailsManager`接口

+   配置 Spring Security 以利用现有的`CalendarUser`模式对用户进行身份验证

+   学习如何使用 Spring Security 的新加密模块来保护密码

+   使用 Spring Security 的默认 JDBC 认证

如果你的应用程序尚未实现安全功能，或者你的安全基础设施正在使用一个数据库，Spring Security 提供了开箱即用的支持，可以简化你安全需求的解决。Spring Security 为用户、权限和组提供了一个默认模式。如果这还不能满足你的需求，它允许用户查询和管理被自定义。在下一节中，我们将介绍如何使用 Spring Security 设置 JDBC 认证的基本步骤。

# 所需的依赖项

我们的应用程序已经定义了本章所需的所有必要依赖项。然而，如果你正在使用 Spring Security 的 JDBC 支持，你可能会希望在你的`build.gradle`文件中列出以下依赖项。重要的是要强调，你将使用的 JDBC 驱动将取决于你正在使用的哪个数据库。请查阅你的数据库供应商的文档，了解需要为你的数据库安装哪个驱动。

请记住，所有的 Spring 版本需要一致，所有的 Spring Security 版本也需要一致（这包括传递依赖版本）。如果你在自己的应用程序中遇到难以解决的问题，你可以在`build.gradle`中定义依赖管理部分来强制执行这一点，如第二章，《使用 Spring Security 入门》所示。如前所述，使用示例代码时，你不需要担心这个问题，因为我们已经为你设置了必要的依赖项。

下面的代码片段定义了本章所需的依赖项，包括 Spring Security 和 JDBC 依赖项：

```java
    //build.gradle

    dependencies {
    ...
    // Database:
 compile('org.springframework.boot:spring-boot-starter-jdbc') compile('com.h2database:h2')    // Security:
 compile('org.springframework.boot:spring-boot-starter-security') testCompile('org.springframework.security:spring-security-test')       ....
    }
```

# 使用 H2 数据库

这个练习的第一部分涉及设置一个基于 Java 的 H2 关系数据库实例，其中包含 Spring Security 的默认模式。我们将配置 H2 在内存中运行，使用 Spring 的`EmbeddedDatabase`配置特性——一种比

手动设置数据库。你可以在 H2 网站上的[`www.h2database.com/`](http://www.h2database.com/)找到更多信息。

请记住，在我们的示例应用程序中，我们主要使用 H2，因为它的设置非常简单。Spring Security 可以与任何支持 ANSI SQL 的数据库无缝工作。如果你在跟随示例操作，我们鼓励你调整配置并使用你偏好的数据库。由于我们不想让本书的这部分内容专注于数据库设置的复杂性，因此我们选择了便利性而不是现实性作为练习的目的。

# 提供的 JDBC 脚本

我们已经在`src/main/resources/database/h2/`目录下提供了所有用于在 H2 数据库中创建模式和数据的 SQL 文件。所有以`security`为前缀的文件是为了支持 Spring Security 的默认 JDBC 实现。所有以`calendar`为前缀的 SQL 文件是 JBCP 日历应用程序的定制 SQL 文件。希望这能稍微简化样例的运行。如果你在自己的数据库实例中跟随操作，你可能需要调整模式定义语法以适应你的特定数据库。可以在 Spring Security 参考资料中找到其他数据库模式。你可以在书的附录*附加参考资料*中找到指向 Spring Security 参考资料的链接。

# 配置 H2 嵌入式数据库

为了配置 H2 嵌入式数据库，我们需要创建一个`DataSource`并运行 SQL 来创建 Spring Security 的表结构。我们需要更新在启动时加载的 SQL，以包括 Spring Security 的基本模式定义、Spring Security 用户定义以及用户权限映射。你可以在以下代码片段中找到`DataSource`定义和相关更新：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/DataSourceConfig.java

    @Bean
    public DataSource dataSource() {
    return new EmbeddedDatabaseBuilder()
       .setName("dataSource")
 .setType(EmbeddedDatabaseType.H2)       .addScript("/database/h2/calendar-schema.sql")
       .addScript("/database/h2/calendar-data.sql")
 .addScript("/database/h2/security-schema.sql") .addScript("/database/h2/security-users.sql") .addScript("/database/h2/security-user-authorities.sql")       .build();
    }
```

记住，`EmbeddedDatabaseBuilder()`方法只在内存中创建数据库，所以你不会在磁盘上看到任何东西，也无法使用标准工具来查询它。然而，你可以使用嵌入在应用程序中的 H2 控制台与数据库进行交互。你可以通过查看我们应用程序的欢迎页面的说明来学习如何使用它。

# 配置 JDBC UserDetailsManager 实现

我们将修改`SecurityConfig.java`文件，声明我们使用 JDBC`UserDetailsManager`实现，而不是我们在第二章，*开始使用 Spring Security*中配置的 Spring Security 内存中的`UserDetailsService`实现。这是通过简单地更改`UserDetailsManager`声明来完成的，如下所示：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    ¦
    @Bean
    @Override
    public UserDetailsManager userDetailsService() {
 JdbcUserDetailsManager manager = new JdbcUserDetailsManager(); manager.setDataSource(dataSource); return manager;    }
    ¦
```

我们将替换之前的`configure(AuthenticationManagerBuilder)`方法及其所有子元素，使用如前一个代码片段所示的`userDetailsService()`方法。

# 默认的 Spring Security 用户模式

让我们来看看用于初始化数据库的每个 SQL 文件。我们添加的第一个脚本包含了默认的 Spring Security 用户及其权限的架构定义。接下来的脚本已从 Spring Security 的参考资料中改编，列在附录中的*附加参考资料*，以具有明确命名的约束，使故障排除更容易：

```java
    //src/main/resources/database/h2/security-schema.sql

    create table users(
       username varchar(256) not null primary key,
       password varchar(256) not null,
       enabled boolean not null
    );
    create table authorities (
       username varchar(256) not null,
       authority varchar(256) not null,
       constraint fk_authorities_users
           foreign key(username) references users(username)
    );
    create unique index ix_auth_username on authorities (username,authority);
```

# 定义用户

下一个脚本是负责定义我们应用程序中的用户。包含的 SQL 语句创建了到目前为止在整个书中使用的相同用户。该文件还添加了一个额外的用户`disabled1@example.com`，由于我们指示用户为禁用状态，因此该用户将无法登录：

```java
    //src/main/resources/database/h2/security-users.sql

    insert into users (username,password,enabled)
       values ('user1@example.com','user1',1);
    insert into users (username,password,enabled)
       values ('admin1@example.com','admin1',1);
    insert into users (username,password,enabled)
       values ('user2@example.com','admin1',1);
    insert into users (username,password,enabled)
       values ('disabled1@example.com','disabled1',0);
```

# 定义用户权限

您可能已经注意到没有指示用户是管理员还是普通用户。下一个文件指定了用户与相应权限的直接映射。如果一个用户没有映射到权限，Spring Security 将不允许该用户登录：

```java
    //src/main/resources/database/h2/security-user-authorities.sql

    insert into authorities(username,authority)
       values ('user1@example.com','ROLE_USER');
    insert into authorities(username,authority)
      values ('admin1@example.com','ROLE_ADMIN');
    insert into authorities(username,authority)
       values ('admin1@example.com','ROLE_USER');
    insert into authorities(username,authority)
       values ('user2@example.com','ROLE_USER');
    insert into authorities(username,authority)
       values ('disabled1@example.com','ROLE_USER');
```

在将 SQL 添加到嵌入式数据库配置之后，我们应该能够启动应用程序并登录。尝试使用`disabled1@example.com`作为`username`和`disabled1`作为`password`登录新用户。注意 Spring Security 不允许用户登录并提供错误消息`Reason: User is disabled`。

您的代码现在应该看起来像这样：`calendar04.01-calendar`。

# `UserDetailsManager`接口

我们在第三章，*自定义认证*中已经利用了 Spring Security 中的`InMemoryUserDetailsManager`类，在`SpringSecurityUserContext`实现的`UserContext`中查找当前的`CalendarUser`应用程序。这使我们能够确定在查找 My Events 页面的活动时应使用哪个`CalendarUser`。 第三章，*自定义认证*还演示了如何更新`DefaultCalendarService.java`文件以利用`InMemoryUserDetailsManager`，以确保我们创建`CalendarUser`时创建了一个新的 Spring Security 用户。本章正好重用了相同的代码。唯一的区别是`UserDetailsManager`实现由 Spring Security 的`JdbcUserDetailsManager`类支持，该类使用数据库而不是内存数据存储。

`UserDetailsManager`还提供了哪些其他功能？

尽管这些功能通过额外的 JDBC 语句相对容易编写，但 Spring Security 实际上提供了开箱即用的功能，以支持许多常见的**创建、读取、更新和删除**（**CRUD**）操作，这些操作针对 JDBC 数据库中的用户。这对于简单的系统来说很方便，也是一个很好的基础，可以在此基础上构建用户可能有的任何自定义要求：

| **方法** | **描述** |
| --- | --- |
| `void createUser(UserDetails user)` | 它使用给定的`UserDetails`信息创建一个新的用户，包括任何声明的`GrantedAuthority`权威。 |
| `void updateUser(final UserDetails user)` | 它使用给定的`UserDetails`信息更新用户。它更新`GrantedAuthority`并从用户缓存中移除用户。 |
| `void deleteUser(String username)` | 它删除给定用户名的用户，并将用户从用户缓存中移除。 |
| `boolean userExists(String username)` | 它表示是否具有给定用户名的活动用户或非活动用户存在。 |
| `void changePassword(String oldPassword, String newPassword)` | 它更改当前登录用户的密码。为了使操作成功，用户必须提供正确的密码。 |

如果`UserDetailsManager`没有为您的应用程序提供所有必要的方法，您可以扩展该接口以提供这些自定义要求。例如，如果您需要能够在管理视图中列出所有可能用户的权限，您可以编写自己的接口并实现此方法，使其指向与您当前使用的`UserDetailsManager`实现相同的存储库。

# 基于组的访问控制

`JdbcUserDetailsManager`类支持通过将`GrantedAuthority`分组到称为组的逻辑集合中，为用户和`GrantedAuthority`声明之间添加一个间接层的能力。

用户随后被分配一个或多个组，他们的成员资格赋予了一组`GrantedAuthority`声明：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/bfe04baf-36ce-4144-8e17-62bc6ac1423a.png)

正如您在前面的图表中所看到的，这种间接性允许通过简单地将新用户分配到现有组中来为多个用户分配相同的角色集。这与我们迄今为止看到的行为不同，以前我们直接将`GrantedAuthority`分配给个别用户。

这种将常见权限集打包的方法在以下场景中很有帮助：

+   您需要将用户划分为具有组之间一些重叠角色的社区。

+   您想要为某一类用户全局更改授权。例如，如果您有一个供应商组，您可能想要启用或禁用他们对应用程序特定部分的使用。

+   您有很多用户，而且不需要对用户级别的授权进行配置。

除非您的应用程序用户基数非常小，否则您很可能正在使用基于组的访问控制。虽然基于组的访问控制比其他策略稍微复杂一些，但管理用户访问的灵活性和简单性使得这种复杂性是值得的。这种通过组聚合用户权限的间接技术通常被称为**基于组的访问控制**（**GBAC**）。

GBAC 是市场上几乎所有受保护的操作系统或软件包中常见的做法。**微软** **活动目录**（**AD**）是基于大规模 GBAC 的最显著实现之一，这是因为它将 AD 用户分入组并分配给这些组的权限。通过使用 GBAC，大型 AD 基础组织的权限管理变得简单得多。

尝试思考您使用的软件的安全模型-用户、组和权限是如何管理的？安全模型编写方式的优势和劣势是什么？

让我们给 JBCP 日历应用程序增加一个抽象层，并将基于组的授权概念应用于该网站。

# 配置基于组的访问控制

我们将在应用程序中添加两个组：普通用户，我们将其称为`Users`，以及管理用户，我们将其称为`Administrators`。我们的现有账户将通过一个额外的 SQL 脚本与适当的组关联。

# 配置 JdbcUserDetailsManager 以使用组

默认情况下，Spring Security 不使用 GBAC。因此，我们必须指导 Spring Security 启用组的使用。修改`SecurityConfig.java`文件以使用`GROUP_AUTHORITIES_BY_USERNAME_QUERY`，如下所示：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    private static String GROUP_AUTHORITIES_BY_USERNAME_QUERY = " "+
 "select g.id, g.group_name, ga.authority " + "from groups g, group_members gm, " + "group_authorities ga where gm.username = ? " + "and g.id = ga.group_id and g.id = gm.group_id";    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
 auth .jdbcAuthentication() .dataSource(dataSource) .groupAuthoritiesByUsername( GROUP_AUTHORITIES_BY_USERNAME_QUERY );    }
```

# 使用 GBAC JDBC 脚本

接下来，我们需要更新在启动时加载的脚本。我们需要删除`security-user-authorities.sql`映射，以便用户不再通过直接映射来获取他们的权限。然后我们需要添加两个额外的 SQL 脚本。更新`DataSource`bean 配置以加载 GBAC 所需的 SQL，如下所示：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/DataSourceConfig.java

    @Bean
    public DataSource dataSource() {
       return new EmbeddedDatabaseBuilder()
         .setName("dataSource")
         .setType(EmbeddedDatabaseType.H2)
         .addScript("/database/h2/calendar-schema.sql")
         .addScript("/database/h2/calendar-data.sql")
         .addScript("/database/h2/security-schema.sql")
         .addScript("/database/h2/security-users.sql")
 .addScript("/database/h2/security-groups-schema.sql") .addScript("/database/h2/security-groups-mappings.sql")         .build();
    }
```

# 基于组的模式

可能很显然，但我们添加的第一个 SQL 文件包含了对模式的支持以支持基于组的授权的更新。您可以在以下代码片段中找到文件的正文：

```java
    //src/main/resources/database/h2/security-groups-schema.sql

    create table groups (
    id bigint generated by default as identity(start with 0) primary key,
    group_name varchar(256) not null
    );
    create table group_authorities (
      group_id bigint not null,
      authority varchar(256) not null,
      constraint fk_group_authorities_group
      foreign key(group_id) references groups(id)
    );
    create table group_members (
      id bigint generated by default as identity(start with 0) primary key,
      username varchar(256) not null,
      group_id bigint not null,\
```

```java
      constraint fk_group_members_group
      foreign key(group_id) references groups(id)\
    );
```

# 组权限映射

现在我们需要将我们的现有用户映射到组，并将组映射到权限。这在`security-groups-mappings.sql`文件中完成。基于组的映射很方便，因为通常，组织已经有了出于各种原因的逻辑用户组。通过利用现有用户分组，我们可以大大简化我们的配置。这就是间接层如何帮助我们。我们在以下组映射中包括了组定义、组到权限的映射以及几个用户：

```java
    //src/main/resources/database/h2/security-groups-mappings.sql

    -- Create the Groups

    insert into groups(group_name) values ('Users');
    insert into groups(group_name) values ('Administrators');

    -- Map the Groups to Roles

    insert into group_authorities(group_id, authority)
    select id,'ROLE_USER' from groups where group_name='Users';
    insert into group_authorities(group_id, authority)
    select id,'ROLE_USER' from groups where
    group_name='Administrators';
    insert into group_authorities(group_id, authority)
    select id,'ROLE_ADMIN' from groups where
    group_name='Administrators';

    -- Map the users to Groups

    insert into group_members(group_id, username)
    select id,'user1@example.com' from groups where
    group_name='Users';
    insert into group_members(group_id, username)
    select id,'admin1@example.com' from groups where
    group_name='Administrators';
    ...
```

启动应用程序，它将表现得和以前一样；然而，用户和角色之间的额外抽象层简化了大量用户组的管理。

您的代码现在应该看起来像`calendar04.02-calendar`。

# 支持自定义模式

新用户在开始使用 Spring Security 时，通常会通过将 JDBC 用户、组或角色映射适应现有的模式。即使遗留数据库不符合 Spring Security 预期的模式，我们仍然可以配置`JdbcDaoImpl`以与之对应。

现在，我们将更新 Spring Security 的 JDBC 支持，使其使用我们的现有`CalendarUser`数据库以及新的`calendar_authorities`表。

我们可以轻松地更改`JdbcUserDetailsManager`的配置，以利用此架构并覆盖 Spring Security 期望的表定义和列，这些表定义和列是我们用于 JBCP 日历应用程序的。

# 确定正确的 JDBC SQL 查询

`JdbcUserDetailsManager`类有三个 SQL 查询，每个查询都有明确定义的参数和返回的列集合。我们必须根据预期的功能确定我们将分配给这些查询的 SQL。`JdbcUserDetailsManager`中使用的每个 SQL 查询都将其作为登录时呈现的用户名作为唯一参数：

| `**命名空间查询属性名称**` | `**描述**` | `**预期的 SQL 列**` |
| --- | --- | --- |
| `users-by-username-query` | 返回与用户名匹配的一个或多个用户；只使用第一个用户。 | `Username` (`string`)`Password` (`string`)`Enabled` (`Boolean`) |
| `authorities-by-username-query` | 直接向用户返回一个或多个授予的权限。通常在禁用 GBAC 时使用。 | `Username` (`string`)`GrantedAuthority` (`string`) |
| `group-authorities-by-username-query` | 返回通过组成员身份提供给用户的授予权限和组详细信息。当启用 GBAC 时使用。 | `Group Primary Key` (任何)`Group Name` (任何)`GrantedAuthority` (字符串) |

请注意，在某些情况下，返回的列没有被默认的`JdbcUserDetailsManager`实现使用，但它们无论如何都必须返回。

# 更新加载的 SQL 脚本

我们需要初始化具有自定义架构的`DataSource`，而不是使用 Spring Security 的默认架构。按照以下方式更新`DataSourceConfig.java`文件：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/DataSourceConfig.java

    @Bean
    public DataSource dataSource() {
    return new EmbeddedDatabaseBuilder()
       .setName("dataSource")
     .setType(EmbeddedDatabaseType.H2)
       .addScript("/database/h2/calendar-schema.sql")
       .addScript("/database/h2/calendar-data.sql")
 .addScript("/database/h2/calendar-authorities.sql")       .build();
    }
```

请注意，我们已经移除了所有以`security`开头的脚本，并将它们替换为`calendar-authorities.sql`。

# 日历用户权限 SQL

您可以在以下代码片段中查看`CalendarUser`权限映射：

```java
    //src/main/resources/database/h2/calendar-authorities.sql

    create table calendar_user_authorities (
       id bigint identity,
       calendar_user bigint not null,
       authority varchar(256) not null,
    );
    -- user1@example.com
    insert into calendar_user_authorities(calendar_user, authority)
       select id,'ROLE_USER' from calendar_users where
       email='user1@example.com';
    -- admin1@example.com
    insert into calendar_user_authorities(calendar_user, authority)
       select id,'ROLE_ADMIN' from calendar_users where     
       email='admin1@example.com';
    insert into calendar_user_authorities(calendar_user, authority)
       select id,'ROLE_USER' from calendar_users where
       email='admin1@example.com';
    -- user2@example.com
    insert into calendar_user_authorities(calendar_user, authority)
       select id,'ROLE_USER' from calendar_users where
     email='user2@example.com';
```

请注意，我们使用`id`作为外键，这比使用用户名作为外键（如 Spring Security 所做的那样）要好。通过使用`id`作为外键，我们可以允许用户轻松地更改他们的用户名。

# 插入自定义权限

当我们添加一个新的`CalendarUser`类时，我们需要更新`DefaultCalendarService`以使用我们的自定义架构为用户插入权限。这是因为虽然我们重用了用户定义的架构，但我们在现有的应用程序中没有定义自定义权限。按照以下方式更新`DefaultCalendarService`：

```java
    //src/main/java/com/packtpub/springsecurity/service/DefaultCalendarService.java

    import org.springframework.jdbc.core.JdbcOperations;
    ...
    public class DefaultCalendarService implements CalendarService {
       ...
       private final JdbcOperations jdbcOperations;
       @Autowired
          public DefaultCalendarService(EventDao eventDao, 
          CalendarUserDao userDao, JdbcOperations jdbcOperations) {
           ...
           this.jdbcOperations = jdbcOperations;
       }
       ...
       public int createUser(CalendarUser user) {
           int userId = userDao.createUser(user);
           jdbcOperations.update(
             "insert into calendar_user_authorities(calendar_user,authority) 
             values(?,?)", userId, "ROLE_USER");
           return userId;
       }
    }
```

您可能注意到了用于插入我们用户的`JdbcOperations`接口。这是 Spring 提供的一个方便的模板，它有助于管理诸如连接和事务处理之类的样板代码。有关详细信息，请参阅本书附录*附加参考资料*，以找到 Spring 参考资料。

# 配置`JdbcUserDetailsManager`以使用自定义 SQL 查询。

为了使用我们非标准架构的自定义 SQL 查询，我们只需更新我们的`userDetailsService()`方法以包括新的查询。这和启用 GBAC 支持的过程非常相似，只不过我们这次不使用默认的 SQL，而是使用我们修改后的 SQL。注意我们移除了我们旧的`setGroupAuthoritiesByUsernameQuery()`方法调用，因为在这个例子中我们不会使用它，以保持事情的简单性：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

 private static String CUSTOM_USERS_BY_USERNAME_QUERY = ""+ "select email, password, true " + "from calendar_users where email = ?"; private static String CUSTOM_AUTHORITIES_BY_USERNAME_QUERY = ""+ "select cua.id, cua.authority " + "from calendar_users cu, calendar_user_authorities "+ "cua where cu.email = ? "+ "and cu.id = cua.calendar_user";    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth
       .jdbcAuthentication()
       .dataSource(dataSource)
 .usersByUsernameQuery(USERS_BY_USERNAME_QUERY) .authoritiesByUsernameQuery( AUTHORITIES_BY_USERNAME_QUERY );    }
```

这是使用 Spring Security 从现有的非默认架构中读取设置所需的所有配置！启动应用程序并确保一切正常运行。

你的代码现在应该看起来像这样：`calendar04.03-calendar`。

请记住，使用现有架构通常需要扩展`JdbcUserDetailsManager`以支持密码的更改、用户账户的更名和其他用户管理功能。

如果你使用`JdbcUserDetailsManager`来执行用户管理任务，那么这个类中有超过 20 个可以通过配置访问的 SQL 查询。然而，只有三个是可以通过命名空间配置访问的。请参阅 Javadoc 或源代码，以查看`JdbcUserDetailsManager`使用的查询的默认值。

# 配置安全密码。

你可能会记得，在第一章，《不安全应用程序的剖析》，的安全审计中，存储在明文中的密码的安全是审计员的首要任务。实际上，在任何一个安全系统中，密码的安全是验证主体信任和权威性的关键方面。一个完全安全的系统的设计者必须确保密码以恶意用户几乎不可能妥协的方式存储。

以下一般规则应适用于数据库中存储的密码：

+   密码不应当以明文（纯文本）形式存储。

+   用户提供的密码必须与数据库中记录的密码进行比较。

+   不应在用户请求时（即使用户忘记了）向用户提供密码。

对于大多数应用程序来说，最适合这些要求的是单向编码，也就是密码的**哈希**。使用密码学哈希可以提供诸如安全和唯一性等重要特性，这对于正确验证用户非常重要，而且一旦哈希，密码就不能从存储的值中提取。

在大多数安全的应用设计中，当请求时既不需要也不应该检索用户的实际密码，因为在不具备适当额外凭证的情况下向用户提供其密码可能会带来重大的安全风险。相反，大多数应用会提供用户重置密码的能力，要么通过提供额外凭证（如他们的社会安全号码、出生日期、税务 ID 或其他个人信息），要么通过基于电子邮件的系统。

存储其他类型的敏感信息

适用于密码的大部分指南同样适用于其他类型的敏感信息，包括社会安全号码和信用卡信息（尽管根据应用程序，其中一些可能需要解密的能力）。以多种方式存储此类信息，例如，客户的完整 16 位信用卡号码以高度加密的形式存储，但最后四位可能以明文形式存储。作为参考，想想任何显示`XXXX XXXX XXXX 1234`以帮助您识别存储的信用卡的互联网商务网站。

您可能已经在思考，鉴于我们使用 SQL 来为 H2 数据库填充用户这一显然不切实际的方法，我们是如何编码密码的？H2 数据库，或者大多数其他数据库，并没有将加密方法作为内置数据库函数提供。

通常，引导过程（用初始用户和数据填充系统）是通过 SQL 加载和 Java 代码的组合来处理的。根据应用程序的复杂性，这个过程可能会变得非常复杂。

对于 JBCP 日历应用程序，我们将保留`dataSource()`bean 声明和`DataSource`在相应的 SQL 中的代码名称，然后添加一些 SQL，将密码更改为它们的散列值。

# 密码编码器（PasswordEncoder）方法

Spring Security 中的密码散列是由`o.s.s.authentication.encoding.PasswordEncoder`接口的实现定义的。通过`AuthenticationManagerBuilder`元素中的`passwordEncoder()`方法配置密码编码器是简单的，如下所示：

```java
    auth
       .jdbcAuthentication()
       .dataSource(dataSource)
       .usersByUsernameQuery(CUSTOM_USERS_BY_USERNAME_QUERY)
       .authoritiesByUsernameQuery(CUSTOM_AUTHORITIES_BY_USERNAME_QUERY)
 .passwordEncoder(passwordEncoder());
```

您会高兴地了解到，Spring Security 随带有一系列`passwordEncoder`的实现，适用于不同的需求和安全要求。

下面的表格提供了一系列内置实现类及其优点。请注意，所有实现都位于`o.s.s.authentication.encoding`包中：

| **实现类** | **描述** | **哈希值** |
| --- | --- | --- |
| `PlaintextPasswordEncoder` | 它将密码编码为明文；这是默认选项。 | `&lt;p>plaintext` |
| `Md4PasswordEncoderPasswordEncoder` | 这个编码器使用`MD4`散列算法。`MD4`散列算法不是一个安全的算法——不建议使用这个编码器。 | `md4` |
| `Md5PasswordEncoderPassword` | 这个编码器使用`MD5`单向编码算法。 |  |
| `ShaPasswordEncoderPasswordEncoder` | 这个编码器使用`SHA`单向编码算法。此编码器可以支持可配置的编码强度级别。 | `sha``sha-256` |
| `LdapShaPasswordEncoder` | 在与 LDAP 身份验证存储集成时使用的`LdapSha`和`LdapSsha`算法的实现。我们将在第六章，*LDAP 目录服务*中了解更多关于这个算法，届时我们将覆盖 LDAP。 | `{sha}``{ssha}` |

与其他 Spring Security 领域的许多方面一样，也可以通过实现`PasswordEncoder`来引用 bean 定义，以提供更精确的配置，并允许`PasswordEncoder`通过依赖注入与其他 bean 连接。对于 JBCP 日历应用程序，我们需要使用这种 bean 引用方法来哈希新创建用户的密码。

让我们通过以下步骤了解为 JBCP 日历应用程序配置基本密码编码的过程。

# 配置密码编码

配置基本密码编码涉及两个步骤：在 SQL 脚本执行后，将加载到数据库中的密码进行哈希，并确保 Spring Security 配置为与`PasswordEncoder`一起工作。

# 配置 PasswordEncoder 方法

首先，我们将声明一个`PasswordEncoder`实例作为一个普通的 Spring bean，如下所示：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    @Bean
    public ShaPasswordEncoder passwordEncoder(){
       return new ShaPasswordEncoder(256);
    }
```

您会注意到我们使用的是`SHA-256` `PasswordEncoder`实现。这是一个高效的单向加密算法，通常用于密码存储。

# 使 Spring Security 了解 PasswordEncoder 方法

我们需要配置 Spring Security 以引用`PasswordEncoder`，这样它可以在用户登录时对呈现的密码进行编码和比较。只需添加一个`passwordEncoder`方法，并参考我们在上一步定义的 bean ID：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    @Override
    public void configure(AuthenticationManagerBuilder auth) 
    throws Exception {
    auth
       .jdbcAuthentication()
       .dataSource(dataSource)
       .usersByUsernameQuery(CUSTOM_USERS_BY_USERNAME_QUERY)
       .authoritiesByUsernameQuery(
           CUSTOM_AUTHORITIES_BY_USERNAME_QUERY)
 .passwordEncoder(passwordEncoder())     ;
    }
```

如果您在此时尝试应用程序，您会发现之前有效的登录凭据现在被拒绝。这是因为存储在数据库中的密码（使用`calendar-users.sql`脚本加载）不是以与密码编码器匹配的`hash`形式存储。我们需要将存储的密码更新为哈希值。

# 存储密码的哈希

如以下图表所示，当用户提交密码时，Spring Security 哈希提交的密码，然后将其与数据库中的未哈希密码进行比较：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/d954ef32-d7a9-4612-a6d5-8c6711626464.png)

这意味着用户无法登录我们的应用程序。为了解决这个问题，我们将更新在启动时加载的 SQL，以将密码更新为哈希值。如下更新`DataSourceConfig.java`文件：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/DataSourceConfig.java

    @Bean
    public DataSource dataSource() {
    return new EmbeddedDatabaseBuilder()
       .setName("dataSource")
       .setType(EmbeddedDatabaseType.H2)
       .addScript("/database/h2/calendar-schema.sql")
       .addScript("/database/h2/calendar-data.sql")
       .addScript("/database/h2/calendar-authorities.sql")
 .addScript("/database/h2/calendar-sha256.sql")       .build();
    }
```

`calendar-sha256.sql`文件简单地将现有密码更新为其预期的哈希值，如下所示：

```java
   update calendar_users set password =      
   '0a041b9462caa4a31bac3567e0b6e6fd9100787db2ab433d96f6d178cabfce90' 
   where email = 'user1@example.com';
```

我们是如何知道要更新密码的值的？我们已经提供了`o.s.s.authentication.encoding.Sha256PasswordEncoderMain`，以展示如何使用配置的`PasswordEncoder`接口来散列现有的密码。相关代码如下：

```java
    ShaPasswordEncoder encoder = new ShaPasswordEncoder(256); 
    String encodedPassword = encoder.encodePassword(password, null);
```

# 散列新用户的密码

如果我们尝试运行应用程序并创建一个新用户，我们将无法登录。这是因为新创建的用户的密码还没有被散列。我们需要更新`DefaultCalendarService`以散列密码。确保新创建用户的密码被散列，请进行以下更新：

```java
    //src/main/java/com/packtpub/springsecurity/service/DefaultCalendarService.java

    import org.springframework.security.authentication.encoding.PasswordEncoder;
    // other imports omitted
    public class DefaultCalendarService implements CalendarService {
       ...
       private final PasswordEncoder passwordEncoder;
       @Autowired
       public DefaultCalendarService(EventDao eventDao, 
       CalendarUserDao userDao, JdbcOperations jdbcOperations, 
       PasswordEncoder passwordEncoder) {
       ...
       this.passwordEncoder = passwordEncoder;
       }
       ...
       public int createUser(CalendarUser user) {
           String encodedPassword = passwordEncoder.
           encodePassword(user.getPassword(), null);
           user.setPassword(encodedPassword);
```

```java
           ...
          return userId;
       }
    }
```

# 不太安全

启动应用程序。尝试使用`user1`作为密码创建一个新用户。退出应用程序，然后按照欢迎页面的说明打开 H2 控制台并查看所有用户的密码。你注意到新创建用户和`user1@example.com`的散列值是相同的值吗？我们现在发现另一个用户的密码有点令人不安。我们将使用一种名为**加盐**的技术来解决这个问题。

您的代码现在应该看起来像这样：`calendar04.04-calendar`。

你想给密码加些盐吗？如果安全审计员检查数据库中编码的密码，他会发现一些仍然让他担心网站安全的东西。让我们检查以下几个用户的存储用户名和密码值：

| **用户名** | **明文密码** | **散列密码** |
| --- | --- | --- |
| `admin1@example.com` | `admin1` | `25f43b1486ad95a1398e3eeb3d83bc4010015fcc9bed b35b432e00298d5021f7` |
| `user1@example.com` | `user1` | `0a041b9462caa4a31bac3567e0b6e6fd9100787db2ab 433d96f6d178cabfce90` |

这看起来非常安全——加密后的密码显然与原始密码没有任何相似之处。审计员会担心什么？如果我们添加一个新用户，而这个新用户的密码恰好与我们的`user1@example.com`用户相同呢？

| **用户名** | **明文密码** | **散列密码** |
| --- | --- | --- |
| `hacker@example.com` | `user1` | `0a041b9462caa4a31bac3567e0b6e6fd9100787d b2ab433d96f6d178cabfce90` |

现在，请注意`hacker@example.com`用户的加密密码与真实用户完全相同！因此，如果黑客以某种方式获得了读取数据库中加密密码的能力，他们可以将自己的已知密码的加密表示与用户账户的未知密码进行比较，看它们是否相同！如果黑客有权访问执行此分析的自动化工具，他们可能在几小时内就能威胁到用户的账户。

虽然猜测一个密码很困难，但黑客可以提前计算出所有的散列值并将散列值与原始密码的映射存储起来。然后，通过查找散列值来确定原始密码，只需常数时间即可。这是一种名为**彩虹表**的黑客技术。

向加密密码中添加另一层安全性的一个常见且有效的方法是使用**盐值**。盐值是一个第二个明文组件，它在与明文密码连接后进行哈希之前，以确保必须使用两个因素来生成（从而比较）哈希密码值。适当选择的盐值可以保证没有任何两个密码会有相同的哈希值，从而防止了我们审计员所担忧的情况，并避免了多种常见的暴力破解密码技术。

最佳实践的盐值通常属于以下三个类别之一：

+   它们是从与用户相关的某些数据算法生成的，例如用户创建的时间戳

+   它们是随机生成的并以某种形式存储

+   它们与用户密码记录一起明文或双向加密

记住，因为`salt`添加到明文密码中，所以它不能单向加密——应用程序需要能够查找或推导出给定用户记录的适当`salt`值，以便计算密码的`hash`，并与进行身份验证时存储的用户`hash`进行比较。

# 在 Spring Security 中使用盐值

Spring Security 3.1 提供了一个新的加密模块，该模块包含在`spring-security-core`模块中，也可以在`spring-security-crypto`中单独使用。`crypto`模块包含自己的`o.s.s.crypto.password.PasswordEncoder`接口。实际上，使用这个接口是编码密码的首选方法，因为它会使用随机的`salt`来加密密码。在撰写本文时，有以下三个实现`o.s.s.crypto.password.PasswordEncoder`：

| **类** | **描述** |
| --- | --- |
| `o.s.s.crypto.bcrypt.BCryptPasswordEncoder` | 这个类使用`bcrypt`哈希函数。它支持盐值和随时间推移减慢速度的能力，随着技术的改进。这有助于保护免受暴力搜索攻击。 |
| `o.s.s.crypto.password.NoOpPasswordEncoder` | 这个类不进行编码（它以明文形式返回密码）。 |
| `o.s.s.crypto.password.StandardPasswordEncoder` | 这个类使用多次迭代和随机盐值的`SHA-256`。 |

对那些熟悉 Spring Security 3.0 的人来说，`salt`曾经是通过`o.s.s.authentication.dao.SaltSource`提供的。尽管仍然支持，但本书不演示这种机制，因为它不是提供`salt`的首选机制。

# 更新 Spring Security 配置

可以通过更新 Spring Security 配置来实现。删除旧的`ShaPasswordEncoder`编码器，并添加新的`StandardPasswordEncoder`编码器，如下所示：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    @Bean
    public PasswordEncoder passwordEncoder(){
       return new StandardPasswordEncoder();
    }
```

# 迁移现有密码

让我们来看看以下步骤，了解迁移现有密码：

1.  我们需要更新我们现有的密码，使其使用新`PasswordEncoder`类产生的值。如果您想生成自己的密码，可以使用以下代码片段：

```java
        StandardPasswordEncoder encoder = new StandardPasswordEncoder();
        String encodedPassword = encoder.encode("password");
```

1.  删除之前使用的`calendar-sha256.sql`文件，并按照以下方式添加提供的`saltedsha256.sql`文件：

```java
      //src/main/java/com/packtpub/springsecurity/configuration/
      DataSourceConfig.java

      @Bean
      public DataSource dataSource() {
      return new EmbeddedDatabaseBuilder()
         .setName("dataSource")
         .setType(EmbeddedDatabaseType.H2)
         .addScript("/database/h2/calendar-schema.sql")
         .addScript("/database/h2/calendar-data.sql"
         .addScript("/database/h2/calendar-authorities.sql")
 .addScript("/database/h2/calendar-saltedsha256.sql")         .build();
      }
```

# 更新 DefaultCalendarUserService

我们之前定义的`passwordEncoder()`方法足够智能，可以处理新的密码编码器接口。然而，`DefaultCalendarUserService`需要更新到新的接口。对`DefaultCalendarUserService`类进行以下更新：

```java
    //src/main/java/com/packtpub/springsecurity/service/DefaultCalendarService.java

    import org.springframework.security.authentication.encoding.PasswordEncoder;
    import org.springframework.security.crypto.password.PasswordEncoder;

    // other imports omitted

    public class DefaultCalendarService implements CalendarService {
    ...      
    public int createUser(CalendarUser user) {
       String encodedPassword = passwordEncoder.encode(user.getPassword());
       user.setPassword(encodedPassword);
       ...
       return userId;
    }
    }
```

# 尝试使用加盐密码

启动应用程序，尝试使用密码`user1`创建另一个用户。使用 H2 控制台比较新用户的密码，并观察它们是不同的。

您的代码现在应该看起来像这样：`calendar04.05-calendar`。

现在 Spring Security 会生成一个随机的`salt`，然后将其与密码结合后再进行哈希处理。接着，它将这个随机的`salt`添加到明文密码的前面，以便进行密码校验。存储的密码可以总结如下：

```java
    salt = randomsalt()
    hash = hash(salt+originalPassword)
    storedPassword = salt + hash
```

这是对新创建密码进行哈希处理的伪代码。

要验证用户，可以从存储的密码中提取`salt`和`hash`，因为`salt`和`hash`都是固定长度的。然后，可以将提取的`hash`与新的`hash`进行比较，新的`hash`是通过提取的`salt`和输入的密码计算得出的：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/f5227c6d-faf2-4bff-8767-c5134963bee1.png)

以下是对加盐密码进行验证的伪代码：

```java
    storedPassword = datasource.lookupPassword(username)
    salt, expectedHash = extractSaltAndHash(storedPassword)
    actualHash = hash(salt+inputedPassword)
    authenticated = (expectedHash == actualHash)
```

# 总结

在本章中，我们学习了如何使用 Spring Security 内置的 JDBC 支持。具体来说，我们了解到 Spring Security 为新的应用程序提供了一个默认模式。我们还探索了如何实现 GBAC，以及它如何使用户管理变得更容易。

我们还学会了如何将 Spring Security 的 JDBC 支持与现有的数据库集成，以及如何通过哈希处理和使用随机生成的`salt`来保护我们的密码。

在下一章中，我们将探讨**Spring Data**项目以及如何配置 Spring Security 使用**对象关系映射**（**ORM**）来连接 RDBMS，以及文档数据库。
