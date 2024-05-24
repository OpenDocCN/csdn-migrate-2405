# 精通 JUnit5 软件测试（一）

> 原文：[`zh.annas-archive.org/md5/6006963f247d852b0fdc6daf54c18ce5`](https://zh.annas-archive.org/md5/6006963f247d852b0fdc6daf54c18ce5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

人类并非完美的思考者。在撰写本文时，软件工程师是人类。大多数是。因此，编写高质量、有用的软件是一项非常困难的任务。正如我们将在本书中发现的那样，软件测试是软件工程师（即开发人员、程序员或测试人员）进行的最重要的活动之一，以保证软件的质量和信心水平。

JUnit 是 Java 语言中最常用的测试框架，也是软件工程中最显著的框架之一。如今，JUnit 不仅仅是 Java 的单元测试框架。正如我们将发现的那样，它可以用于实现不同类型的测试（如单元测试、集成测试、端到端测试或验收测试），并使用不同的策略（如黑盒或白盒）。

2017 年 9 月 10 日，JUnit 团队发布了 JUnit 5.0.0。本书主要关注这个 JUnit 的新主要版本。正如我们将发现的那样，JUnit 5 对 JUnit 框架进行了完全的重新设计，改进了重要功能，如模块化（JUnit 5 架构完全模块化）、可组合性（JUnit 5 的扩展模型允许以简单的方式集成第三方框架到 JUnit 5 测试生命周期中）、兼容性（JUnit 5 支持在全新的 JUnit 平台中执行 JUnit 3 和 4 的遗留测试）。所有这些都遵循基于 Java 8 的现代编程模型，并符合 Java 9 的规范。

软件工程涉及一个多学科的知识体系，对变革有着强烈的推动力。本书全面审查了与软件测试相关的许多不同方面，主要是从开源的角度（JUnit 从一开始就是开源的）。在本书中，除了学习 JUnit 外，还可以学习如何在开发过程中使用第三方框架和技术，比如 Spring、Mockito、Selenium、Appium、Cucumber、Docker、Android、REST 服务、Hamcrest、Allure、Jenkins、Travis CI、Codecov 或 SonarCube 等。

# 本书涵盖的内容

第一章*，软件质量和 Java 测试的回顾*，对软件质量和测试进行了详细回顾。本章的目标是以易懂的方式澄清这一领域的术语。此外，本章还总结了 JUnit（版本 3 和 4）的历史，以及一些 JUnit 增强器（例如，可以用来扩展 JUnit 的库）。

第二章*，JUnit 5 的新功能*，首先介绍了创建 JUnit 5 版本的动机。然后，本章描述了 JUnit 5 架构的主要组件，即 Platform、Jupiter 和 Vintage。接下来，我们将了解如何运行 JUnit 测试，例如使用不同的构建工具，如 Maven 或 Gradle。最后，本章介绍了 JUnit 5 的扩展模型，允许任何第三方扩展 JUnit 5 的核心功能。

第三章*，JUnit 5 标准测试*，详细描述了新的 JUnit 5 编程模型的基本特性。这个编程模型，连同扩展模型，被称为 Jupiter。在本章中，您将了解基本的测试生命周期、断言、标记和过滤测试、条件测试执行、嵌套和重复测试，以及如何从 JUnit 4 迁移。

第四章*，使用高级 JUnit 功能简化测试*，详细描述了 JUnit 5 的功能，如依赖注入、动态测试、测试接口、测试模板、参数化测试、与 Java 9 的兼容性，以及 JUnit 5.1 的计划功能（在撰写本文时尚未发布）。

第五章*，JUnit 5 与外部框架的集成*，讨论了 JUnit 5 与现有第三方软件的集成。可以通过不同的方式进行此集成。通常，应使用 Jupiter 扩展模型与外部框架进行交互。这适用于 Mockito（一种流行的模拟框架）、Spring（一个旨在基于依赖注入创建企业应用程序的 Java 框架）、Docker（一个容器平台技术）或 Selenium（用于 Web 应用程序的测试框架）。此外，开发人员可以重用 Jupiter 测试生命周期与其他技术进行交互，例如 Android 或 REST 服务。

第六章*，从需求到测试用例*，提供了一套旨在帮助软件测试人员编写有意义的测试用例的最佳实践。考虑需求作为软件测试的基础，本章提供了一个全面的指南，以编写测试，避免典型的错误（反模式和代码异味）。

*第七章，测试管理*，是本书的最后一章，其目标是指导读者了解软件测试活动在一个活跃的软件项目中是如何管理的。为此，本章回顾了诸如**持续集成**（**CI**）、构建服务器（Jenkins、Travis）、测试报告或缺陷跟踪系统等概念。为了结束本书，还提供了一个完整的示例应用程序，以及不同类型的测试（单元测试、集成测试和端到端测试）。

# 您需要为本书做些什么

为了更好地理解本书中提出的概念，强烈建议 fork GitHub 存储库，其中包含本书中提出的代码示例（[`github.com/bonigarcia/mastering-junit5`](https://github.com/bonigarcia/mastering-junit5)）。在作者看来，触摸和玩弄代码对于快速掌握 JUnit 5 测试框架至关重要。正如前面介绍的，本书的最后一章提供了一个完整的应用程序示例，涵盖了本书中一些最重要的主题。这个应用程序（称为*Rate my cat!*）也可以在 GitHub 上找到，位于存储库[`github.com/bonigarcia/rate-my-cat`](https://github.com/bonigarcia/rate-my-cat)中。

为了运行这些示例，您需要 JDK 8 或更高版本。您可以从 Oracle JDK 的网站下载：[`www.oracle.com/technetwork/java/javase/downloads/index.html`](http://www.oracle.com/technetwork/java/javase/downloads/index.html)。此外，强烈建议使用**集成开发环境**（**IDE**）来简化开发和测试过程。正如我们将在本书中发现的那样，在撰写本文时，有两个完全符合 JUnit 5 的 IDE，即：

+   Eclipse 4.7+（Oxygen）：[`eclipse.org/ide/`](https://eclipse.org/ide/)。

+   IntelliJ IDEA 2016.2+：[`www.jetbrains.com/idea/`](https://www.jetbrains.com/idea/)。

如果您更喜欢从命令行运行 JUnit 5，则可以使用两种可能的构建工具：

+   Maven：[`maven.apache.org/`](https://maven.apache.org/)

+   Gradle：[`gradle.org/`](https://gradle.org/)

# 这本书适合谁

本书面向 Java 软件工程师。因此，这部文学作品试图与读者（即 Java）说同样的语言，因此它是由上述公开的 GitHub 存储库上可用的工作代码示例驱动的。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些样式的示例及其含义解释。文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“`@AfterAll`和`@BeforeAll`方法仅执行一次”。

一块代码设置如下：

```java
package io.github.bonigarcia;

import static org.junit.jupiter.api.Assertions.*assertTrue*;

import org.junit.jupiter.api.Test;

class StandardTest {

    @Test
    void verySimpleTest () {
        *assertTrue*(true);
    }

}
```

任何命令行输入或输出都以以下形式编写：

```java
mvn test
```

**新术语**和**重要词汇**显示为粗体，如：“**兼容性**是产品、系统或组件与其他产品交换信息的程度”。

警告或重要提示会以这样的方式出现在框中。

提示和技巧会出现在这样的情况下。

# 读者反馈

我们始终欢迎读者的反馈。请告诉我们您对本书的看法-您喜欢或不喜欢的内容。读者的反馈对我们很重要，因为它有助于我们开发您真正能从中获益的标题。

要向我们发送一般反馈，只需发送电子邮件至`feedback@packtpub.com`，并在消息主题中提及书名。

如果您在某个专业领域有专业知识，并且有兴趣撰写或为书籍做出贡献，请参阅我们的作者指南，网址为[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您是 Packt 书籍的自豪所有者，我们有一些东西可以帮助您充分利用您的购买。

# 下载示例代码

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  使用您的电子邮件地址和密码登录或注册到我们的网站。

1.  将鼠标指针悬停在顶部的“支持”选项卡上。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名。

1.  选择您要下载代码文件的书籍。

1.  从下拉菜单中选择您购买本书的地点。

1.  单击“代码下载”。

下载文件后，请确保使用以下最新版本的软件解压缩文件夹：

+   WinRAR / 7-Zip for Windows

+   Zipeg / iZip / UnRarX for Mac

+   7-Zip / PeaZip for Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/bonigarcia/mastering-junit5`](https://github.com/bonigarcia/mastering-junit5)。我们还有其他丰富书籍和视频代码包可供下载，网址为[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)。快去看看吧！

# 勘误

尽管我们已经尽一切努力确保内容的准确性，但错误确实会发生。如果您在我们的书籍中发现错误-可能是文本或代码中的错误-我们将不胜感激，如果您能向我们报告。通过这样做，您可以帮助其他读者避免挫折，并帮助我们改进本书的后续版本。如果您发现任何勘误，请访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)报告，选择您的书籍，单击“勘误提交表格”链接，并输入您的勘误详情。一旦您的勘误经过验证，您的提交将被接受，并且勘误将被上传到我们的网站或添加到该标题的“勘误”部分下的任何现有勘误列表中。

要查看先前提交的勘误，请访问[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，并在搜索框中输入书名。所需信息将出现在“勘误”部分下。

# 盗版

互联网上侵犯版权材料的盗版是所有媒体都面临的持续问题。在 Packt，我们非常重视保护我们的版权和许可。如果您在互联网上发现我们作品的任何非法副本，请立即向我们提供位置地址或网站名称，以便我们采取补救措施。

请通过`copyright@packtpub.com`与我们联系，并附上涉嫌盗版材料的链接。

我们感谢您在保护我们的作者和我们为您提供有价值内容的能力方面的帮助。

# 问题

如果您对本书的任何方面有问题，可以通过`questions@packtpub.com`与我们联系，我们将尽力解决问题。


# 第一章：软件质量和 Java 测试的回顾

为了从头开始制作一个苹果派，你必须首先创造宇宙。 

*- 卡尔·萨根*

自 1995 年创立以来，著名的测试框架 JUnit 已经走过了很长的路。2017 年 9 月 10 日，项目生命周期中的一个重要里程碑发生了，即发布了 JUnit 5.0.0。在深入了解 JUnit 5 的细节之前，值得回顾一下软件测试的现状，以便了解我们来自何处，以及我们将要去往何处。为此，本章提供了对软件质量、软件测试和 Java 测试背景的高层次回顾。具体来说，本章由三个部分组成：

+   **软件质量**：第一部分回顾了质量工程的现状：质量保证、ISO/IEC-2500、验证和验证（V&V）以及软件缺陷（错误）。

+   **软件测试**：这是最常见的活动，用于保证软件质量并减少软件缺陷的数量。本部分提供了软件测试层次（单元、集成、系统和验收）、方法（黑盒、白盒和非功能性）、自动化和手动软件测试的理论背景。

+   **Java 虚拟机的测试框架**（JVM）：本部分概述了 JUnit 框架的旧版本（即版本 3 和 4）的主要特点。最后，简要描述了替代测试框架和对 JUnit 的增强。

# 软件质量

软件是为特定客户或一般市场开发的计算机程序、相关数据和相关文档的集合。它是现代世界的重要组成部分，在电信、公用事业、商业、文化、娱乐等领域普遍存在。问题*什么是软件质量？*可能会得到不同的答案，取决于涉及从业者在软件系统中的角色。在软件产品或服务中涉及两大主要群体：

+   **消费者**：是使用软件的人。在这个群体中，我们可以区分*客户*（即负责获取软件产品或服务的人）和*用户*（即为各种目的使用软件产品或服务的人）。然而，客户和用户的双重角色是非常普遍的。

+   **生产者**：参与软件产品的开发、管理、维护、营销和服务的人。

消费者的质量期望是软件系统按规定执行有用的功能。对于软件生产商来说，基本的质量问题是通过生产符合服务级别协议（SLA）的软件产品来履行他们的合同义务。著名软件工程师 Roger Pressman 对软件质量的定义包括两个观点：

有效的软件过程以创造有用的产品，并为生产者和使用者提供可衡量的价值。

# 质量工程

质量工程（也称为质量管理）是一个评估、评价和改进软件质量的过程。在质量工程过程中有三大主要活动组：

1.  **质量规划**：这个阶段通过管理项目成本和预算限制来建立整体质量目标。这个质量计划还包括策略，即选择要执行的活动和适当的质量测量以提供反馈和评估。

1.  **质量保证（QA）**：通过规划和执行一系列活动来保证项目生命周期中的软件产品和过程满足其指定的要求，从而提供足够的信心，质量被构建到软件中。主要的 QA 活动是验证和验证，但还有其他活动，如软件质量度量、使用质量标准、配置管理、文档管理或专家意见。

1.  **质量保证后**：这个阶段包括质量量化和改进测量、分析、反馈和后续活动。这些活动的目的是提供产品质量的定量评估和改进机会的识别。

这些阶段在下图中表示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00005.jpeg)

软件质量工程过程

# 需求和规范

需求是质量工程领域的关键主题。需求是确定产品或过程需求的能力、物理特征或质量因素的陈述。需求开发（也称为需求工程）是产生和分析客户、产品和产品组件需求的过程。支持需求开发的一系列程序，包括规划、可追溯性、影响分析、变更管理等，被称为需求管理。软件需求有两种类型：

+   **功能性需求**是产品必须执行的操作，以使其对用户有用。它们源自利益相关者需要做的工作。几乎任何动作，如检查、发布或大多数其他动词都可以是功能性需求。

+   **非功能性需求**是产品必须具有的属性或特性。例如，它们可以描述性能、可用性或安全性等属性。它们通常被称为*质量属性*。

另一个与需求密切相关的重要主题是规范，它是一份文件，以完整、精确、可验证的方式规定了系统的需求、设计、行为或其他特征，通常还包括确定这些规定是否得到满足的程序。

# 质量保证

**质量保证**（**QA**）主要关注定义或选择应用于软件开发过程或软件产品的标准。《软件质量保证》（2004）一书的作者丹尼尔·加林将 QA 定义为：

系统化、计划的一系列行动，以提供足够的信心，使软件系统产品的开发和维护过程符合已建立的规范以及保持进度和在预算范围内运作的管理要求。

质量保证（QA）过程选择 V&V 活动、工具和方法来支持所选的质量标准。V&V 是一组活动，其主要目标是如果产品不符合资格，则阻止产品发货。相比之下，QA 旨在通过在开发和维护过程中引入各种活动来最小化质量成本，以防止错误的原因，检测它们，并在开发的早期阶段纠正它们。因此，QA 大大降低了不合格产品的比率。总的来说，V&V 活动只是 QA 活动的一部分。

# ISO/IEC-25000

已经提出了各种质量标准以适应这些不同的质量视图和期望。标准**ISO/IEC-9126**是软件工程界中最有影响力的标准之一。然而，研究人员和实践者发现了该标准的一些问题和弱点。因此，ISO/IEC-9126 国际标准被**ISO/IEC-25000**系列国际标准**软件产品质量要求和评估**（**SQuaRE**）所取代。本节提供了该标准的高级概述。

ISO/IEC-2500 质量参考模型区分了软件质量的不同视图：

+   **内部质量**：这涉及可以在不执行系统的情况下进行测量的系统属性。

+   **外部质量**：这涉及可以在执行过程中观察到的系统属性。

+   **使用质量**：这涉及消费者在操作和维护系统过程中体验到的属性。

理想情况下，开发（*过程质量*）影响内部质量；然后，内部质量决定外部质量。最后，外部质量决定使用质量。这一链条在下图中描述：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00006.jpeg)

ISO/IEC-2500 产品质量参考模型

ISO/IEC-25000 的质量模型将产品质量模型（即内部和外部属性）分为八个顶层质量特征：*功能适用性*、*性能效率*、*兼容性*、*可用性*、*可靠性*、*安全性*、*可维护性*和*可移植性*。以下定义直接从标准中提取：

+   **功能适用性**：这代表产品或系统在指定条件下使用时提供满足规定和隐含需求的功能程度。

+   **性能效率**：这代表在规定条件下使用的资源量相对于性能的表现。

+   **兼容性**：这是产品、系统或组件能够与其他产品、系统或组件交换信息，并/或执行其所需功能的程度，同时共享相同的硬件或软件环境。

+   **可用性**：这是产品或系统在指定使用环境中由指定用户使用以实现指定目标时的效果、效率和满意度程度。

+   **可靠性**：这是系统、产品或组件在指定条件下在指定时间内执行指定功能的程度。

+   **安全性**：这是产品或系统保护信息和数据的程度，使得人员或其他产品或系统能够获得适合其类型和授权级别的数据访问程度。

+   **可维护性**：这代表产品或系统可以被修改以改进、纠正或适应环境和需求变化的效果和效率程度。

+   **可移植性**：这是系统、产品或组件能够从一个硬件、软件或其他操作或使用环境转移到另一个环境的效果和效率程度。

另一方面，使用质量的属性可以归类为以下五个特征：

+   **有效性**：这是用户实现指定目标的准确性和完整性。

+   **效率**：这是用户实现目标所需的准确性和完整性所耗费的资源。

+   **满意度**：这是在指定使用环境中使用产品或系统时满足用户需求的程度。

+   **免于风险**：这是产品或系统减轻对经济状况、人类生命、健康或环境潜在风险的程度。

+   **上下文覆盖**：这是产品或系统在指定使用环境和初始明确定义的环境以外的环境中能够有效、高效、无风险和满意程度的程度。

# 验证和验证

验证和验证-也称为软件质量控制-涉及评估正在开发的软件是否满足其规范并提供消费者期望的功能。这些检查过程从需求可用开始，并贯穿开发过程的所有阶段。验证与验证不同，尽管它们经常被混淆。

计算机科学杰出教授 Barry Boehm 在 1979 年就表达了它们之间的区别：

+   验证：我们是否正在正确构建产品？验证的目的是检查软件是否满足其规定的功能和非功能要求（即规范）。

+   **验证**：我们是否在构建正确的产品？验证的目的是确保软件满足消费者的期望。由于规范并不总是反映消费者的真实愿望或需求，因此它比验证更为普遍。

V&V 活动包括各种 QA 活动。虽然软件测试在 V&V 中起着极其重要的作用，但其他活动也是必要的。在 V&V 过程中，可以使用两大类系统检查和分析技术：

+   **软件测试**：这是 QA 中最常见的活动。给定一段代码，软件测试（或简单地测试）包括观察一些执行（测试用例）并对其做出裁决。因此，测试是一种基于执行的 QA 活动，因此前提是已实施的软件单元、组件或系统需要进行测试。因此，有时它被称为动态分析。

+   **静态分析**：这是一种不需要执行软件的 V&V 形式。静态分析是针对软件的源表示进行的：规范、设计或程序的模型。也许最常用的是检查和审查，其中一组人员检查规范、设计或程序。还可以使用其他静态分析技术，例如自动化软件分析（检查程序的源代码是否存在已知潜在错误的模式）。

值得注意的是，关于哪些测试构成验证或验证存在着强烈的分歧意见。一些作者认为所有测试都是验证，而验证是在需求被审查和批准时进行的。其他作者认为单元测试和集成测试是验证，而更高级别的测试（例如系统或用户测试）是验证。为了解决这种分歧，V&V 可以被视为一个单一主题，而不是两个单独的主题。

# 软件缺陷

V&V 正确性方面的关键是软件缺陷的概念。术语**缺陷**（也称为*错误*）指的是一般的软件问题。IEEE 标准 610.12 提出了与软件缺陷相关的以下分类：

+   **错误**：产生不正确结果的人为行为。错误可以分为两类：

1.  语法错误（违反所写语言的一个或多个规则的程序语句）。

1.  逻辑错误（不正确的数据字段，超出范围的术语或无效的组合）。

+   **故障**：软件系统中错误的表现被称为故障。例如，不正确的步骤、过程或数据定义。

+   故障：软件系统无法执行其所需功能被称为（系统）故障。

术语“bug”最早是由软件先驱格雷斯·胡珀在 1946 年创造的，当时一只被困在电机计算机的继电器中的飞蛾导致系统故障。在这十年中，术语“debug”也被引入，作为在系统中检测和纠正缺陷的过程。

除了缺陷的这种细粒度之外，还有一个有趣的**事件**，即软件消费者感知到的与故障相关的症状。总的来说，错误、故障、故障和事件是软件缺陷的不同方面。这四个缺陷方面之间存在因果关系。错误可能导致故障注入软件中，故障可能在执行软件时导致故障。最后，当最终用户或客户经历故障时，就会发生事件。可以进行不同的质量保证活动来尽量减少软件系统中的缺陷数量。正如杰夫·田在他的书《软件质量工程》（2005）中所定义的那样，这些替代方案可以分为以下三个通用类别：

+   通过错误修复预防缺陷：例如，使用某些流程和产品标准可以帮助最小化将某些类型的故障注入软件中。

+   通过故障检测和修复减少缺陷：传统的测试和静态分析活动就是这一类别的例子。我们将在本章的内容中发现这些机制的具体类型。

+   缺陷控制通过预防故障：这些活动通常超出软件系统的范围。控制的目标是最小化软件系统故障造成的损害（例如，在反应堆故障时用墙壁来包含放射性材料）。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00007.jpeg)

软件缺陷链和相关的质量保证活动

# 静态分析

对软件片段的静态分析是在不执行代码的情况下进行的。与测试相比，软件分析有几个优点：

1.  在测试过程中，错误可能会隐藏其他错误。这种情况在静态分析中不会发生，因为它不涉及错误之间的相互作用。

1.  不完整的系统版本可以在不增加额外成本的情况下进行静态分析。在测试中，如果程序不完整，就必须开发测试工具。

1.  静态分析可以考虑软件系统的更广泛的质量属性，例如符合标准、可移植性和可维护性。

有不同的方法可以被确定为静态分析：

+   **检查**（1976 年由迈克尔·法根首次提出）是人员检查软件工件，旨在发现和修复软件系统中的故障。所有类型的软件资产都可能被检查，例如规范、设计模型等。检查存在的主要原因不是等待可执行程序的可用性（例如在测试中）才开始进行检查。

+   **审查**是一个过程，其中一组人员检查软件及其相关文档，寻找潜在问题和与标准不符合，以及其他潜在问题或遗漏。如今，在将新代码合并到共享源代码存储库之前，通常会进行审查。通常，审查由团队内的不同人员（**同行审查**）进行。这个过程在时间和精力方面非常昂贵，但另一方面，当正确执行时，它有助于确保高内部代码质量，减少潜在风险。

**审查**是一种特殊形式的审查。根据 IEEE 软件审查标准，审查是一种软件同行审查形式，其中设计师或程序员带领开发团队成员和其他感兴趣的人员浏览软件产品，参与者提出问题并对可能的错误、违反开发标准和其他问题进行评论。

+   **自动化软件分析**使用已知潜在危险的模式来评估源代码。这种技术通常以商业或开源工具和服务的形式提供，通常被称为**lint**或**linter**。这些工具可以定位许多常见的编程错误，在代码被测试之前分析源代码，并识别潜在问题，以便在它们表现为故障之前重新编码。这种 linting 过程的目的是引起代码阅读者对程序中的错误的注意，比如：

1.  数据故障：这可能包括声明但从未使用的变量，两次赋值但在赋值之间从未使用的变量等。

1.  控制故障：这可能包括无法到达的代码或无条件进入循环。

1.  输入/输出故障：这可能包括变量在没有中间赋值的情况下输出两次。

1.  接口故障：这可能包括参数类型不匹配、参数不匹配、函数结果未使用、未调用的函数和过程等。

1.  存储管理故障：这可能包括未分配的指针、指针算术等。

在静态分析和动态测试之间，我们发现了一种特殊的软件评估方式，称为**形式验证**。这种评估提供了检查系统是否按照其正式规范运行的机制。为此，软件被视为一个可以使用逻辑操作证明其正确性的数学实体，结合不同类型的静态和动态评估。如今，由于可扩展性问题，形式方法并不被广泛采用。使用这些技术的项目大多相对较小，比如关键的内核系统。随着系统的增长，开发正式规范和验证所需的工作量也会过分增长。

# 软件测试

软件测试包括对程序在通常无限执行域中合适选择的有限测试用例的动态评估，以检查其行为是否符合预期。这个定义的关键概念如下所示：

+   **动态**：**被测试系统**（**SUT**）使用特定的输入值来查找其行为中的故障。因此，实际的 SUT 应该确保设计和代码是正确的，还有环境，比如库、操作系统和网络支持等等。

+   **有限的**：对于大多数真实程序来说，穷举测试是不可能或不切实际的。它们通常对每个操作有大量允许的输入，还有更多无效或意外的输入，操作序列通常也是无限的。测试人员必须选择一定数量的测试，以便在可用时间内运行这些测试。

+   **选定的**：由于可能的测试集合庞大甚至无限，我们只能运行其中的一小部分，测试的关键挑战在于如何选择最有可能暴露系统故障的测试。

+   **预期的**：在每次测试执行后，必须决定系统的观察行为是否是故障。

软件测试是一个广泛的术语，涵盖了许多不同的概念。在文献中，并没有所有不同测试形式的通用分类。为了清晰起见，在本书中，我们使用三个轴对不同的测试形式进行分类，即测试级别（单元、集成、系统和验收）、测试方法（黑盒、白盒和非功能测试）和测试类型（手动和自动化）。

接下来的章节将提供关于所有这些概念的更多细节，这些概念在以下图表中进行了总结：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00008.jpeg)

软件测试的分类法分为三类：级别、方法和类型

例如，正如我们将会发现的，根据其功能行为执行类中的方法的 JUnit 测试可以被视为自动化的单元黑盒测试。当最终用户使用软件产品来验证其是否按预期工作时，根据之前的分类，我们可以将其视为手动黑盒验收测试。应该注意的是，并非所有这三个轴的可能组合总是有意义的。例如，非功能测试（例如性能）通常是在系统级别自动进行的（手动或在单元级别进行的可能性非常小）。

# 测试级别

根据 SUT 的大小和测试的场景，测试可以在不同的级别进行。在本书中，我们将不同的测试级别分类为四个阶段：

+   **单元测试**：在这里，测试单独的程序单元。单元测试应该专注于对象或方法的功能。

+   **集成测试**：在这里，单元被组合成复合组件。集成测试应该专注于测试组件和接口。

+   **系统测试**：在这里，所有组件都被集成，整个系统被测试。

+   **验收测试**：在这里，消费者决定系统是否准备部署到消费者环境中。它可以被视为由最终用户或客户在系统级进行的高级功能测试。

在许多不同形式的测试中，没有通用的分类。关于测试级别，在本书中，我们使用上述的四个级别分类。然而，文献中还存在其他级别或方法（例如*系统集成测试*或*回归测试*）。在本节的最后部分，我们可以找到对不同测试方法的审查。

前三个级别（单元、集成和系统）通常在软件生命周期的开发阶段进行。这些测试通常由软件工程师的不同角色执行（即程序员、测试人员、质量保证团队等）。这些测试的目标是对系统进行验证。另一方面，第四个级别（验收）是一种用户测试，其中通常涉及潜在或真实用户（验证）。以下图片提供了这些概念的图形描述：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00009.jpeg)

测试级别及其与 V&V 的关系

# 单元测试

单元测试是一种通过测试单个源代码片段来验证该单元的设计和实现是否正确的方法。在单元测试用例中按顺序执行的四个阶段如下：

+   **设置**：测试用例初始化*测试装置*，即 SUT 展示预期行为所需的*之前*图片。

+   **执行**：测试用例与 SUT 进行交互，从中获得一些结果。SUT 通常查询另一个组件，称为**依赖组件**（**DOC**）。

+   **验证**：测试用例使用断言（也称为谓词）确定是否获得了预期的结果。

+   **拆卸**：测试用例拆除测试装置，将 SUT 恢复到初始状态。

这些阶段及其与 SUT 和 DOC 的关系如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00010.jpeg)

单元测试通用结构

单元测试是在单元测试中进行的，即在不与其 DOCs 进行交互的情况下进行。为此，使用*测试替身*来替换 SUT 所依赖的任何组件。有几种类型的测试替身：

+   **虚拟**对象只是满足真实对象的 API，但实际上从未被使用。虚拟对象的典型用例是当它们作为参数传递以满足方法签名时，但然后虚拟对象实际上并未被使用。

+   **伪造**对象用更简单的实现替换真实对象，例如，内存数据库。

+   **存根**对象替换真实对象，提供硬编码的值作为响应。

+   **模拟**对象也替换真实对象，但这次是使用编程期望作为响应。

+   **间谍**对象是部分模拟对象，意味着它的一些方法是使用期望进行编程的，但其他方法使用真实对象的实现。

# 集成测试

集成测试应该暴露接口中的缺陷，以及集成组件或模块之间的交互。有不同的策略来执行集成测试。这些策略描述了要集成单元的顺序，假设这些单元已经分别进行了测试。常见的集成策略示例包括以下内容：

+   **自顶向下集成**：这种策略从主要单元（模块）开始，即程序树的根部。任何被主要单元调用的较低级别模块都应该被测试替身替换。一旦测试人员确信主要单元逻辑是正确的，存根将逐渐被实际代码替换。这个过程将重复进行，直到程序树中的其余较低单元。这种方法的主要优点是缺陷更容易被发现。

+   **自底向上集成**：这种策略从最基本的单元开始测试。较大的子系统是由经过测试的组件组装而成。这种类型的主要优点是不需要测试替身。

+   **临时集成**：组件按照完成的自然顺序进行集成。它允许对系统进行早期测试。通常需要测试替身。

+   **骨干集成**：构建组件的骨架，逐渐集成其他组件。这种方法的主要缺点是骨干的创建可能需要大量工作。

文献中常常提到的另一种策略是**大爆炸集成**。在这种策略中，测试人员等待直到所有或大多数单元都被开发和集成。结果，所有的故障都会同时被发现，使得纠正潜在故障非常困难和耗时。如果可能的话，应该避免使用这种策略。

# 系统测试

开发过程中的系统测试涉及将组件集成以创建系统的一个版本，并测试集成系统。它验证组件是否兼容，正确地进行交互，并在正确的时间传输正确的数据，通常跨越其用户界面。显然，它与集成测试重叠，但这里的区别在于系统测试应该涉及所有系统组件以及最终用户（通常是模拟的）。

还有一种特殊类型的系统测试称为*端到端测试*。在这种方法中，最终用户通常被模拟，即使用自动化技术进行模拟。

# 测试方法

测试方法（或策略）定义了设计测试用例的方式。它们可以基于责任（黑盒），基于实现（白盒），或非功能性。黑盒技术根据被测试项的指定功能设计测试用例。白盒技术依靠源代码分析来开发测试用例。混合技术（灰盒）测试使用基于责任和基于实现的方法设计测试用例。

# 黑盒测试

黑盒测试（也称为功能或行为测试）是基于需求的，不了解内部程序结构或数据。黑盒测试依赖于正在测试的系统或组件的规范来推导测试用例。系统是一个只能通过研究其输入和相关输出来确定其行为的黑盒。有许多具体的黑盒测试技术；以下是一些最著名的技术：

+   系统化测试：这指的是一种完整的测试方法，其中系统被证明完全符合规范，直到测试假设。它仅在限制意义上生成测试用例，即每个域点都是单例子域。在这个类别中，一些最常执行的是等价类划分和边界值分析，以及基于逻辑的技术，如因果图、决策表或成对测试。

+   随机测试：这实际上是系统化测试的对立面-对整个输入域进行抽样。模糊测试是一种黑盒随机测试，它会随机变异格式良好的输入，并对生成的数据进行测试。它会向系统提供随机顺序和/或结构不良的数据，以查看是否发生故障。

+   图形用户界面（GUI）测试：这是确保具有图形界面的软件与用户进行交互的规范的过程。GUI 测试是事件驱动的（例如，鼠标移动或菜单选择），并通过消息或方法调用向底层应用程序代码提供前端。单元级别的 GUI 测试通常在按钮级别使用。系统级别的 GUI 测试会测试系统的事件驱动特性。

+   基于模型的测试（MBT）：这是一种测试策略，其中测试用例部分地源自描述系统下测试对象的模型。MBT 是一种黑盒测试，因为测试是从模型生成的，而模型又源自需求文档。它可以在不同的级别（单元、集成或系统）进行。

+   冒烟测试：这是确保系统关键功能的过程。冒烟测试用例是测试人员在接受构建进行进一步测试之前运行的第一个测试。冒烟测试用例失败意味着软件构建被拒绝。冒烟测试的名称源自电气系统测试，即首次测试是打开开关并查看是否冒烟。

+   理智测试：这是确保系统基本功能的过程。与冒烟测试类似，理智测试是在测试过程开始时执行的，但其目标不同。理智测试旨在确保系统基本功能继续按预期工作（即系统的合理性），然后进行更详尽的测试。

冒烟测试和理智测试通常在软件测试社区中容易混淆。通常认为这两种测试都是为了避免在这些测试失败时浪费精力进行严格的测试，它们的主要区别在于目标（关键功能 vs. 基本功能）。

# 白盒测试

白盒测试（也称为结构测试）基于对应用程序代码内部逻辑的了解。它确定程序代码结构和逻辑是否有错误。只有当测试人员知道程序应该做什么时，白盒测试用例才是准确的。

黑盒测试仅使用规范来识别用例，而白盒测试使用程序源代码（实现）作为测试用例识别的基础。这两种方法结合使用，应该是选择 SUT 的一组良好测试用例所必需的。以下是一些最重要的白盒技术：

+   代码覆盖定义了已经测试的源代码程度，例如以 LOC 百分比的形式。代码覆盖有几个标准：

1.  语句覆盖：代码覆盖粒度。

1.  决策（分支）覆盖：控制结构（例如，if-else）覆盖粒度。

1.  条件覆盖：布尔表达式（真-假）覆盖粒度。

1.  路径覆盖：每个可能的路径覆盖粒度。

1.  功能覆盖：程序功能覆盖粒度。

1.  入口/出口覆盖：调用和返回的覆盖粒度。

+   故障注入是向软件中注入故障以确定某个 SUT 的表现如何的过程。缺陷可以说是传播的，如果是这种情况，它们的影响会在错误存在的状态之外的程序状态中可见（故障变成了失败）。

+   突变测试通过对包含不同、单一且故意插入更改的 SUT 的多个副本运行测试和它们的数据来验证。突变测试有助于识别代码中的遗漏。

# 非功能测试

系统的非功能方面可能需要大量的测试工作。在这一组中，可以找到不同的测试手段，例如，性能测试用于评估 SUT 是否符合指定的性能要求。这些要求通常包括有关时间行为和资源使用的约束。性能测试可以通过单个用户对系统进行操作或多个用户对系统进行操作来测量响应时间。负载测试侧重于增加系统的负载到某个规定或暗示的最大负载，以验证系统能够处理定义的系统边界。体积测试通常被认为是负载测试的同义词，但体积测试侧重于数据。压力测试超出正常操作能力的范围，以至系统失败，识别系统破裂的实际边界。压力测试的目的是观察系统如何失败以及瓶颈在哪里。

安全测试试图确保以下概念：机密性（保护信息不被泄露），完整性（确保信息的正确性），认证（确保用户的身份），授权（确定用户是否被允许接收服务或执行操作），可用性（确保系统在需要时执行其功能），不可否认性（确保否认某个动作发生）。评估系统基础设施安全性的授权尝试通常被称为渗透测试。

可用性测试侧重于发现可能使软件难以使用或导致用户误解输出的用户界面问题。可访问性测试是确保产品符合可访问性（访问系统功能的能力）的技术。

# 测试类型

有两种主要的软件测试方法：

+   **手动测试**：这是由人类进行的评估 SUT 的过程，通常是软件工程师或最终用户。在这种类型的测试中，我们可以找到所谓的*探索性测试*，这是一种人工测试，人类测试人员通过调查和自由评估系统使用其个人感知来评估系统。

+   **自动化测试**：这是评估 SUT 的过程，其中测试过程（测试执行、报告等）是通过专门的软件和基础设施进行的。Elfriede Dustin 在她的书*Implementing Automated Software Testing: How to Save Time and Lower Costs While Raising Quality*（2009）*中定义了**自动化软件测试**（**AST**）为：

应用和实施软件技术贯穿整个软件测试生命周期，目标是提高效率和效果。

AST 的主要好处是：预期的成本节约、缩短的测试持续时间、提高测试的彻底性、提高测试的准确性、改进结果报告以及统计处理，以及随后的报告。

自动化测试通常在构建服务器上在**持续集成**（**CI**）过程的上下文中执行。关于这方面的更多细节在第七章中提供，*测试管理*。

AST 在*框架*内实施时效果最好。测试框架可以被定义为一组抽象概念、过程、程序和环境，其中自动化测试将被设计、创建和实施。这个框架定义包括用于测试创建和实施的物理结构，以及这些组件之间的逻辑交互。

严格来说，框架的定义与我们对库的理解并没有太大的区别。为了更清楚地区分，考虑一下著名的软件工程专家马丁·福勒的以下引用：

库本质上是一组可以调用的函数，这些天通常组织成类。每次调用都会执行一些工作并将控制返回给客户端。框架包含了一些抽象设计，并内置了更多的行为。为了使用它，您需要将您的行为插入到框架的各个位置，要么通过子类化，要么通过插入您自己的类。然后框架的代码在这些点调用您的代码。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00011.jpeg)

库和框架之间的视觉解释

框架在现代软件开发中变得越来越重要。它们提供了软件密集型系统中非常需要的可重用性能力。这样，大型应用程序最终将由相互合作的框架层组成。

# 其他测试方法

正如本节开头介绍的，对于不同形式的测试并没有一个通用的定义。在本节中，我们回顾了一些文献中常见的测试种类，例如当测试过程用于确定系统是否符合其规格时，它被称为*一致性测试*。当向系统引入新功能或功能（我们可以称之为构建）时，测试这个新功能的方式被称为*渐进测试*。此外，为了检查新引入的更改不会影响系统其余部分的正确性，现有的测试用例被执行。这种方法通常被称为*回归测试*。

当系统与任何外部或第三方系统进行交互时，可以进行另一种称为*系统集成测试*的测试。这种测试验证系统是否正确地集成到任何外部系统中。

*用户或客户测试* 是测试过程中的一个阶段，在该阶段用户或客户提供系统测试的输入和建议。*验收测试* 是用户测试的一种类型，但也可以有不同类型的*用户测试*：

+   **Alpha 测试**：这在开发者的站点进行，与软件的消费者一起工作，然后才发布给外部用户或客户。

+   **Beta 测试**：这在客户的站点进行，涉及由一组客户对系统进行测试，他们在自己的位置使用系统并提供反馈，然后系统才会发布给其他客户。

+   **运行测试**：这是由最终用户在其正常操作环境中执行的测试。

最后，*发布测试* 指的是由开发团队之外的一个独立团队对系统的特定发布进行测试的过程。发布测试的主要目标是说服系统的供应商系统足够好以供使用。

# JVM 的测试框架

JUnit 是一个允许创建自动化测试的测试框架。JUnit 的开发始于 1995 年底，由 Kent Beck 和 Erich Gamma 发起。自那时起，该框架的流行度一直在增长。如今，它被广泛认为是测试 Java 应用程序的*事实*标准。

JUnit 旨在成为一个单元测试框架。然而，它不仅可以用于实现单元测试，还可以用于其他类型的测试。正如我们将在本书的内容中发现的那样，根据测试逻辑如何对受测试软件进行测试，使用 JUnit 实现的测试用例可以被视为单元、集成、系统，甚至验收测试。总的来说，我们可以将 JUnit 视为 Java 的多用途测试框架。

# JUnit 3

自 JUnit 3 的早期版本以来，该框架可以与 Java 2 及更高版本一起使用。JUnit3 是开源软件，根据**Common Public License**（**CPL**）版本 1.0 发布，并托管在 SourceForge（[`sourceforge.net/projects/junit/`](https://sourceforge.net/projects/junit/)）上。JUnit 3 的最新版本是 JUnit 3.8.2，于 2007 年 5 月 14 日发布。JUnit 在测试框架的世界中引入的主要要求如下：

1.  应该很容易定义哪些测试将运行。

1.  框架应该能够独立运行所有其他测试。

1.  框架应该能够逐个测试检测和报告错误。

# JUnit 3 中的标准测试

在 JUnit 3 中，为了创建测试用例，我们需要扩展类 `junit.framework.TestCase`。这个基类包括 JUnit 需要自动运行测试的框架代码。然后，我们只需确保方法名遵循 `testXXX()` 模式。这个命名约定使得框架清楚地知道该方法是一个单元测试，并且可以自动运行。

测试生命周期由 `setup()` 和 `tearDown()` 方法控制。`TestCase` 在运行每个测试之前调用 `setup()`，然后在每个测试完成时调用 `teardown()`。将多个测试方法放入同一个测试用例的原因之一是共享相同的测试装置。

最后，为了在测试用例中实现验证阶段，JUnit 3 在名为 `junit.framework.Assert` 的实用类中定义了几个断言方法。以下表总结了该类提供的主要断言：

| **方法** | **描述** |
| --- | --- |
| `assertTrue` | 断言条件为真。如果不是，方法将抛出带有给定消息的 `AssertionFailedError`（如果有的话）。 |
| `assertFalse` | 断言条件为假。如果不是，方法将抛出带有给定消息的 `AssertionFailedError`（如果有的话）。 |
| `assertEquals` | 断言两个对象相等。如果它们不相等，方法将抛出带有给定消息的 `AssertionFailedError`（如果有的话）。 |
| `assertNotNull` | 断言对象不为空。如果为空，方法将抛出带有消息的 `AssertionFailedError`（如果有的话）。 |
| `assertNull` | 断言对象为空。如果不是，则该方法将抛出带有给定消息的`AssertionFailedError`（如果有）。 |
| `assertSame` | 断言两个对象引用同一个对象。如果不是，则该方法将抛出带有给定消息的`AssertionFailedError`（如果有）。 |
| `assertNotSame` | 断言两个对象不引用同一个对象。如果是，则该方法将抛出带有给定消息的`AssertionFailedError`（如果有）。 |
| `fail` | 使测试失败（抛出`AssertionFailedError`），并附上给定的消息（如果有）。 |

下面的类显示了使用 JUnit 3.8.2 实现的简单测试。正如我们所看到的，这个测试用例包含两个测试。在每个测试之前，框架将调用`setUp()`方法，并且在每个测试执行之后，也将调用`tearDown()`方法。这个例子已经编码，使得第一个名为`testSuccess()`的测试正确完成，而第二个名为`testFailure()`的测试以错误结束（断言抛出异常）：

```java
package io.github.bonigarcia;

import junit.framework.TestCase;

public class TestSimple extends TestCase {

    // Phase 1: Setup (for each test)
    protected void setUp() throws Exception {
        System.*out*.println("<Setup>");
    }

    // Test 1: This test is going to succeed
    public void testSuccess() {
        // Phase 2: Simulation of exercise
        int expected = 60;
        int real = 60;
        System.*out*.println("** Test 1 **");

        // Phase 3: Verify
        *assertEquals*(expected + " should be equals to " 
         + real, expected, real);
    }

    // Test 2: This test is going to fail
    public void testFailure() {
        // Phase 2: Simulation of exercise
        int expected = 60;
        int real = 20;
        System.*out*.println("** Test 2 **");

        // Phase 3: Verify
        *assertEquals*(expected + " should be equals to " 
         + real, expected, real);
    }

    // Phase 4: Teardown (for each test)
    protected void tearDown() throws Exception {
        System.*out*.println("</Ending>");
    }

}
```

本书中解释的所有代码示例都可以在 GitHub 存储库[`github.com/bonigarcia/mastering-junit5`](https://github.com/bonigarcia/mastering-junit5)上找到。

# JUnit 3 中的测试执行

JUnit 3 允许通过称为测试运行器的 Java 应用程序运行测试用例。JUnit 3.8.2 提供了三种不同的测试运行器：两种图形化（基于 Swing 和 AWT）和一种可以从命令行使用的文本运行器。JUnit 框架为每个测试提供单独的类加载器，以避免测试之间的副作用。

构建工具（如 Ant 或 Maven）和**集成开发环境**-**IDE**-（如 Eclipse 和 IntelliJ）实现了自己的 JUnit 测试运行器是一种常见做法。

下面的图片显示了当我们使用 JUnit Swing 运行器以及使用 Eclipse 运行相同的测试用例时，先前的测试是什么样子的。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00012.jpeg)

使用图形化 Swing 测试运行器和 Eclipse 测试运行器执行 JUnit 3 测试用例

当 JUnit 中的测试未成功时，可能有两个原因：失败或错误。一方面，失败是由未满足的断言（`Assert`类）引起的。另一方面，错误是测试中未预期的条件，例如被测试软件中的常规异常。

JUnit 3 的另一个重要贡献是测试套件的概念，这是一种方便的方式来分组相关的测试。测试套件是通过 JUnit 类`junit.framework.TestSuite`实现的。这个类，与`TestCase`一样，实现了框架接口`junit.framework.Test`。

下面的图表显示了 JUnit 3 的主要类和方法：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00013.jpeg)

核心 JUnit 3 类

```java
TestSuite object, and then add single test cases using the method addTestSuite():
```

```java
package io.github.bonigarcia;

import junit.framework.Test;
import junit.framework.TestSuite;

public class TestAll {

    public static Test suite() {
        TestSuite suite = new TestSuite("All tests");
        suite.addTestSuite(TestSimple.class);
        suite.addTestSuite(TestMinimal.class);
        return suite;
    }
}
```

稍后可以使用测试运行器执行此测试套件。例如，我们可以使用命令行测试运行器（`junit.textui.TestRunner`）和命令行，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00014.gif)

使用文本测试运行器和命令行执行的测试套件

# JUnit 4

JUnit 4 仍然是一个开源框架，尽管许可证与 JUnit 3 相比发生了变化，从 CPL 更改为**Eclipse Public License**（**EPL**）版本 1.0。JUnit 4 的源代码托管在 GitHub 上（[`github.com/junit-team/junit4/`](https://github.com/junit-team/junit4/)）。

2006 年 2 月 18 日，发布了 JUnit 4.0。它遵循与 JUnit 3 相同的高级指导方针，即轻松定义测试，框架独立运行测试，并且框架检测并报告测试中的错误。

JUnit 4 相对于 JUnit 3 的主要区别之一是 JUnit 4 允许定义测试的方式。在 JUnit 4 中，使用 Java 注解标记方法为测试。因此，JUnit 4 只能用于 Java 5 或更高版本。正如 2006 年 JUnit 4.0 的文档所述：

JUnit 4.0 的架构与早期版本有着很大的不同。现在，不再通过将测试类标记为子类化`junit.framework.TestCase`和通过以'test'开头的名称标记测试方法，而是使用`@Test`注解来标记测试方法。

# JUnit 4 中的标准测试

在 JUnit 4 中，`@Test`注解（包含在`org.junit`包中）表示一个测试。任何公共方法都可以用`@Test`注解来标记为测试方法。

为了设置测试装置，JUnit 4 提供了`@Before`注解。这个注解可以在任何公共方法中使用。同样，任何使用`@After`注解标记的公共方法在每次测试方法执行后执行。JUnit 4 还提供了两个注解来增强测试生命周期：`@BeforeClass`和`@AfterClass`。它们只在每个测试类中执行一次，分别在所有测试之前和之后执行。以下图片描述了 JUnit 4 测试用例的生命周期：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00015.jpeg)

JUnit 4 测试生命周期

`@Before`和`@After`可以应用于任何公共 void 方法。`@AfterClass`和`@BeforeClass`只能应用于公共静态 void 方法。

以下表格总结了迄今为止在 JUnit 3 和 JUnit 4 中看到的主要区别：

| 特性 | JUnit 3 | JUnit 4 |
| --- | --- | --- |
| 测试定义 | `testXXX`模式 | `@Test`注解 |
| 在第一个测试之前运行 | 不支持 | `@BeforeClass`注解 |
| 在所有测试之后运行 | 不支持 | `@AfterClass`注解 |
| 在每个测试之前运行 | 重写`setUp()`方法 | `@Before`注解 |
| 在每个测试之后运行 | 重写`tearDown()`方法 | `@After`注解 |
| 忽略测试 | 不支持 | `@Ignore`注解 |

`org.junit.Assert`类提供了执行断言（谓词）的静态方法。以下是最有用的断言方法：

+   `assertTrue`：如果条件变为 false，则断言失败并抛出`AssertionError`。

+   `assertFalse`：如果条件变为 true，则断言失败并抛出`AssertionError`。

+   `assertNull`：这检查参数是否为空，否则如果参数不为空则抛出`AssertionError`。

+   `assertNotNull`：这检查参数是否不为空；否则，它会抛出`AssertionError`。

+   `assertEquals`：这比较两个对象或原始类型。此外，如果实际值与期望值不匹配，则会抛出`AssertionError`。

+   `assertSame`：这仅支持对象，并使用`==`运算符检查对象引用。

+   `assertNotSame`：这是`assertSame`的相反。

以下代码片段提供了 JUnit 4 测试用例的简单示例。正如我们所看到的，这是与前一节中看到的等效测试用例相同，这次使用 JUnit 4 编程模型，即使用`@Test`注解来标识测试和其他注解（`@AfterAll`，`@After`，`@BeforeAll`，`@Before`）来实现测试生命周期（设置和拆卸测试装置）：

```java
package io.github.bonigarcia;

import static org.junit.Assert.*assertEquals*;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class TestSimple {

    // Phase 1.1: Setup (for all tests)
    @BeforeClass
    public static void setupAll() {
        System.*out*.println("<Setup Class>");
    }

    // Phase 1.2: Setup (for each test)
    @Before
    public void setupTest() {
        System.*out*.println("<Setup Test>");
    }

    // Test 1: This test is going to succeed
    @Test
    public void testSuccess() {
        // Phase 2: Simulation of exercise
        int expected = 60;
        int real = 60;
        System.*out*.println("** Test 1 **");

        // Phase 3: Verify
        *assertEquals*(expected + " should be equals to " 
          + real, expected, real);
    }

    // Test 2: This test is going to fail
    @Test
    public void testFailure() {
        // Phase 2: Simulation of exercise
        int expected = 60;
        int real = 20;
        System.*out*.println("** Test 2 **");

        // Phase 3: Verify
        *assertEquals*(expected + " should be equals to " 
          + real, expected, real);
    }

    // Phase 4.1: Teardown (for each test)
    @After
    public void teardownTest() {
        System.*out*.println("</Ending Test>");
    }

    // Phase 4.2: Teardown (for all test)
    @AfterClass
    public static void teardownClass() {
        System.*out*.println("</Ending Class>");
    }

}
```

# JUnit 4 中的测试执行

测试运行器的概念在 JUnit 4 中也存在，但与 JUnit 3 相比略有改进。在 JUnit 4 中，测试运行器是一个用于管理测试生命周期的 Java 类：实例化，调用设置和拆卸方法，运行测试，处理异常，发送通知等等。默认的 JUnit 4 测试运行器称为`BlockJUnit4ClassRunner`，它实现了 JUnit 4 标准测试用例类模型。

在 JUnit 4 测试用例中使用的测试运行器可以通过简单地使用`@RunWith`注解来更改。JUnit 4 提供了一系列内置的测试运行器，允许更改测试类的性质。在本节中，我们将回顾最重要的运行器。

+   为了运行一组测试（即测试套件），JUnit 4 提供了`Suite`运行器。除了运行器，`Suite.SuiteClasses`类还允许定义属于套件的单个测试类。例如：

```java
 package io.github.bonigarcia;

 import org.junit.runner.RunWith;
 import org.junit.runners.Suite;

     @RunWith(Suite.class)
     @Suite.SuiteClasses({ TestMinimal1.class, TestMinimal2.class })
 public class MySuite {
     }
```

+   参数化测试用于指定将在相同测试逻辑中使用的不同输入数据。为了实现这种类型的测试，JUnit 4 提供了`Parameterized`运行器。要在此类型的测试中定义数据参数，我们需要使用注解`@Parameters`对类的静态方法进行注释。此方法应返回提供测试输入参数的二维数组的`Collection`。现在，将有两种选项将输入数据注入到测试中：

1.  使用构造函数类。

1.  使用注解`@Parameter`对类属性进行注释。

以下代码片段显示了后者的示例：

```java
package io.github.bonigarcia;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collection;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class TestParameterized {

    @Parameter(0)
    public int input1;

    @Parameter(1)
    public int input2;

    @Parameter(2)
    public int sum;

    @Parameters(name = "{index}: input1={0} input2={1} sum={2}?")
    public static Collection<Object[]> data() {
        return Arrays.*asList*(
                new Object[][] { { 1, 1, 2 }, { 2, 2, 4 }, { 3, 3, 9 } });
    }

    @Test
    public void testSum() {
        *assertTrue*(input1 + "+" + input2 + " is not " + sum,
                input1 + input2 == sum);
    }

}
```

在 Eclipse 上执行此测试将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00016.jpeg)

在 Eclipse 中执行参数化测试

+   JUnit 理论是 JUnit 参数化测试的一种替代方法。JUnit 理论预期对所有数据集都为真。因此，在 JUnit 理论中，我们有一个提供数据点的方法（即用于测试的输入值）。然后，我们需要指定一个带有`@Theory`注解的方法，该方法带有参数。类中的理论将使用数据点的每种可能组合执行：

```java
 package io.github.bonigarcia;

 import static org.junit.Assert.assertTrue;

 import org.junit.experimental.theories.DataPoints;
 import org.junit.experimental.theories.Theories;
 import org.junit.experimental.theories.Theory;
 import org.junit.runner.RunWith;

      @RunWith(Theories.class)
 public class MyTheoryTest {

         @DataPoints
         public static int[] positiveIntegers() {
             return new int[] { 1, 10, 100 };
         }

         @Theory
         public void testSum(int a, int b) {
             System.out.println("Checking " + a + "+" + b);
             *assertTrue*(a + b > a);
             *assertTrue*(a + b > b);
         }
     }
```

再次在 Eclipse 中查看此示例的执行：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00017.jpeg)

在 Eclipse 中执行 JUnit 4 理论

# JUnit 4 的高级功能

在 JUnit 4 中引入的最重要的创新之一是使用*规则*。规则允许灵活地添加或重新定义测试类中每个测试方法的行为。通过使用注解`@Rule`将规则包含在测试用例中。此属性的类型应继承 JUnit 接口`org.junit.rulesTestRule`。JUnit 4 中提供了以下规则：

+   `ErrorCollector`：此规则允许在发现第一个问题后继续执行测试

+   `ExpectedException`：此规则允许验证测试是否引发特定异常

+   `ExternalResource`：此规则为在测试之前设置外部资源（文件、套接字、服务器、数据库连接等）并保证在之后拆除的规则提供了一个基类

+   `TestName`：此规则使当前测试名称在测试方法内部可用

+   `TemporaryFolder`：此规则允许创建在测试方法完成时应删除的文件和文件夹

+   `Timeout`：此规则将相同的超时应用于类中的所有测试方法

+   `TestWatcher`：这是一个记录每个通过和失败测试的规则的基类

JUnit 4 的另一个先进功能允许：

+   使用注解`@FixMethodOrder`按给定顺序执行测试。

+   使用 Assume 类创建假设。该类提供许多静态方法，例如`assumeTrue(condition)`、`assumeFalse(condition)`、`assumeNotNull(condition)`和`assumeThat(condition)`。在执行测试之前，JUnit 会检查测试中的假设。如果其中一个假设失败，JUnit 运行器将忽略具有失败假设的测试。

+   JUnit 在`@Test`注解中提供了一个超时值（以毫秒为单位），以确保如果测试运行时间超过指定值，则测试失败。

+   使用测试运行器`Categories`对测试进行分类，并使用注解`Category`对测试方法进行标注以识别测试的类型。

在 GitHub 存储库中可以找到每个先前提到的功能的有意义的示例（[`github.com/bonigarcia/mastering-junit5`](https://github.com/bonigarcia/mastering-junit5)）。

# JUnit 生态系统

JUnit 是 JVM 中最受欢迎的测试框架之一，被认为是软件工程中最有影响力的框架之一。我们可以找到几个库和框架，它们在 JUnit 的基础上提供了额外的功能。这些生态系统增强器的一些示例是：

+   Mockito（[`site.mockito.org/`](http://site.mockito.org/)）：这是一个模拟框架，可以与 JUnit 一起使用。

+   AssertJ（[`joel-costigliola.github.io/assertj/`](http://joel-costigliola.github.io/assertj/)）：这是 Java 的流畅断言库。

+   Hamcrest（[`hamcrest.org/`](http://hamcrest.org/)）：这是具有匹配器的库，可以组合以创建灵活且可读的断言。

+   Cucumber（[`cucumber.io/`](https://cucumber.io/)）：这是允许以**行为驱动开发**（**BDD**）风格编写的自动化验收测试的测试框架。

+   FitNesse（[`www.fitnesse.org/`](http://www.fitnesse.org/)）：这是旨在通过支持系统功能的详细可读描述来支持验收测试的测试框架。

虽然 JUnit 是 JVM 上最大的测试框架，但并非唯一的测试框架。JVM 上还有几个其他测试框架可用。一些例子包括：

+   TestNG（[`testng.org/`](http://testng.org/)）：这是受到 JUnit 和 NUnit 启发的测试框架。

+   Spock（[`spockframework.org/`](http://spockframework.org/)）：这是 Java 和 Groovy 应用程序的测试和规范框架。

+   Jtest（[`www.parasoft.com/product/jtest/`](https://www.parasoft.com/product/jtest/)）：这是由 Parasoft 公司制作和分发的自动化 Java 测试和静态分析框架。

+   Scalatest（[`www.scalatest.org/`](http://www.scalatest.org/)）：这是 Scala、Scala.js（JavaScript）和 Java 应用程序的测试框架。

由于 JUnit，测试已经成为编程的核心部分。因此，在 JVM 边界之外，JUnit 实现的基础测试模型已被移植到所谓的 xUnit 家族的一系列测试框架中。在这个模型中，我们找到了测试用例、运行器、固定装置、套件、测试执行、报告和断言的概念。举几个例子，考虑以下框架。所有这些都属于 xUnit 家族：

+   Google Test（[`github.com/google/googletest`](https://github.com/google/googletest)）：Google 的 C++测试框架。

+   JSUnit（[`www.jsunit.net/`](http://www.jsunit.net/)）：JavaScript 的单元测试框架。

+   Mocha（[`mochajs.org/`](https://mochajs.org/)）：在 Node.js 上运行的单元测试框架。

+   NUnit（[`www.nunit.org/`](https://www.nunit.org/)）：用于 Microsoft.NET 的单元测试框架。

+   PHPUnit（[`phpunit.de/`](https://phpunit.de/)）：PHP 的单元测试框架。

+   SimplyVBUnit（[`simplyvbunit.sourceforge.net/`](http://simplyvbunit.sourceforge.net/)）：VB.NET 的单元测试框架。

+   Unittest（[`docs.python.org/3/library/unittest.html`](https://docs.python.org/3/library/unittest.html)）：Python 的单元测试框架。

# 总结

*软件质量*是软件工程中的关键概念，因为它决定了软件系统满足其要求和用户期望的程度。验证和验证是一组旨在评估软件系统的活动的名称。V&V 的目标是确保软件的质量，同时减少缺陷的数量。V&V 中的两个核心活动是*软件测试*（评估运行中的软件）和*静态分析*（评估软件构件而不执行）。

*自动化软件测试*在过去几十年中取得了最大的进步。在这个领域，*JUnit 框架*占据着重要的地位。JUnit 旨在成为 JVM 的单元框架。如今，事实上 JUnit 是 Java 社区中最流行的测试框架，提供了一个全面的编程模型来创建和执行测试用例。在下一节中，我们将了解框架的新版本 JUnit 5 提供的功能和能力。


# 第二章：JUnit 5 的新功能

那些能够想象任何事情的人，可以创造不可能的事情。

*- 艾伦·图灵*

JUnit 是 JVM 中最重要的测试框架，也是软件工程中最有影响力的框架之一。JUnit 5 是 JUnit 的下一代，其第一个**正式版本**（5.0.0）于 2017 年 9 月 10 日发布。正如我们将了解的那样，JUnit 5 相对于 JUnit 4 来说是一次小革命，提供了全新的架构、编程和扩展模型。本章内容包括以下内容：

+   **通往 JUnit 5**：在第一节中，我们将了解创建 JUnit 的新主要版本的动机（即 JUnit 4 的限制），指导 JUnit 5 开发的设计原则，以及 JUnit 5 开源社区的详细信息。

+   **JUnit 5 架构**：JUnit 5 是一个由三个主要组件组成的模块化框架，分别是 Platform、Jupiter 和 Vintage。

+   **在 JUnit 5 中运行测试**：我们将了解如何使用流行的构建工具（如 Maven 或 Gradle）以及 IDE（如 IntelliJ 或 Eclipse）运行 JUnit 5 测试。

+   **JUnit 5 的扩展模型**：扩展模型允许第三方库和框架通过它们自己的添加来扩展 JUnit 5 的编程模型。

# 通往 JUnit 5

自 2006 年 JUnit 4 首次发布以来，软件测试发生了很大变化。自那时起，不仅 Java 和 JVM 发生了变化，我们的测试需求也变得更加成熟。我们不再只编写单元测试。除了验证单个代码片段外，软件工程师和测试人员还要求其他类型的测试，如集成测试和端到端测试。

此外，我们对测试框架的期望已经增长。如今，我们要求这些框架具有高级功能，比如可扩展性或模块化等。在本节中，我们将了解 JUnit 4 的主要限制，JUnit 5 的愿景以及支持其开发的社区。

# JUnit 5 的动机

根据多项研究，JUnit 4 是 Java 项目中使用最多的库。例如，《GitHub 上排名前 100 的 Java 库》是 OverOps（@overopshq）发布的一份知名报告，OverOps 是一家专注于大规模 Java 和 Scala 代码库的软件分析公司。

在 2017 年的报告中，分析了 GitHub 上排名前 1000 的 Java 项目（按星级）使用的独特 Java 库的导入语句。根据结果，JUnit 4 是 Java 库的无可争议的王者：`org.junit`和`org.junit.runner`包的导入分别位列第一和第二。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00018.jpeg)

GitHub 上排名前 20 的 Java 库

尽管事实如此，JUnit 4 是十多年前创建的一个框架，存在着一些重要的限制，这些限制要求对框架进行完全重新设计。

# 模块化

首先，JUnit 4 不是模块化的。如下图所示，JUnit 4 的架构完全是单片的。JUnit 4 的所有功能都由`junit.jar`依赖提供。因此，JUnit 4 中的不同测试机制，如测试发现和执行，在 JUnit 4 中是紧密耦合的。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00019.jpeg)

JUnit 4 的架构

约翰内斯·林克（Johannes Link）是 JUnit 5 核心团队成员之一，他在 2015 年 8 月 13 日接受 Jax 杂志采访时总结了这个问题（在 JUnit 5 开始时）：

JUnit 作为一个平台的成功阻碍了它作为测试工具的发展。我们要解决的基本问题是通过分离足够强大和稳定的 API 来执行测试用例。

# JUnit 4 运行器

JUnit 4 的运行器 API 也有一个重要的威慑作用。正如在第一章中所描述的，“关于软件质量和 Java 测试的回顾”，在 JUnit 4 中，运行器是用于管理测试生命周期的 Java 类。JUnit 4 中的运行器 API 非常强大，但是有一个重要的缺点：运行器不可组合，也就是说，我们一次只能使用一个运行器。

例如，参数化测试无法与 Spring 测试支持结合使用，因为两个测试都会使用自己的运行器实现。在 Java 中，每个测试用例都使用自己独特的`@RunWith`注解。第一个使用`Parameterized`运行器。

```java
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class MyParameterizedTest {

   @Test
   public void myFirstTest() {
      // my test code
   }

}
```

虽然这个第二个例子使用了`SpringJUnit4ClassRunner`运行器，但由于 JUnit 4 的限制（运行器不可组合），它不能与前一个例子结合使用：

```java
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
public class MySpringTest {

   @Test
   public void yetAnotherTest() {
      // my test code
   }

}
```

# JUnit 4 规则

由于 JUnit 4 中对同一测试类中 JUnit 4 运行器的唯一性的严格限制，JUnit 的 4.7 版本引入了方法级规则的概念，这些规则是测试类中带有`@Rule`注解的字段。这些规则允许通过在执行测试之前和之后执行一些代码来添加或重新定义测试行为。JUnit 4.9 还包括类级别规则的概念，这些规则是在类中的所有测试之前和之后执行的规则。通过使用`@ClassRule`注解静态字段来标识这些规则，如下例所示：

```java
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

public class MyRuleTest {

   @ClassRule
   public static TemporaryFolder temporaryFolder = new TemporaryFolder();

   @Test
   public void anotherTest() {
      // my test code
   }

}
```

虽然规则更简单且大多可组合，但它们也有其他缺点。在使用 JUnit 4 规则进行复杂测试时的主要不便之处在于，我们无法使用单个规则实体来进行方法级和类级的测试。归根结底，这对自定义生命周期管理（在之前/之后的行为）施加了限制。

# JUnit 5 的开始

尽管 JUnit 4 是全球数百万 Java 开发人员的默认测试框架，但没有一位活跃的 JUnit 维护者受雇于其雇主从事这项工作。因此，为了克服 JUnit 4 的缺点，Johannes Link 和 Marc Philipp 于 2015 年 7 月在 Indiegogo（国际众筹网站）上启动了 JUnit Lambda 众筹活动（[`junit.org/junit4/junit-lambda-campaign.html`](http://junit.org/junit4/junit-lambda-campaign.html)）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00020.jpeg)

JUnit Lambda 众筹活动

JUnit Lambda 是该项目的名称，它是当前 JUnit 5 框架的种子。在项目名称中加入 lambda 一词强调了从项目一开始就使用 Java 8 的想法。引用 JUnit Lambda 项目网站：

目标是在 JVM 上为开发人员测试创建一个最新的基础。这包括专注于 Java 8 及以上，以及启用许多不同的测试风格。

JUnit Lambda 众筹活动从 2015 年 7 月持续到 10 月。这是一个成功的活动，从全球 474 个个人和公司筹集了 53,937 欧元。从这一点开始，JUnit 5 的启动团队成立了，加入了来自 Eclipse、Gradle、IntelliJ 或 Spring 的人员。

JUnit Lambda 项目成为 JUnit 5，并且指导开发过程的设计原则如下：

+   模块化：如前所述，JUnit 4 不是模块化的，这会导致一些问题。从一开始，JUnit 5 的架构就是完全模块化的，允许开发人员使用他们需要的框架的特定部分。

+   具有重点在可组合性上的强大扩展模型：可扩展性对于现代测试框架是必不可少的。因此，JUnit 5 应该提供与第三方框架（如 Spring 或 Mockito 等）的无缝集成。

+   API 分离：将测试发现和执行与测试定义分离。

+   与旧版本的兼容性：支持在新的 JUnit 5 平台中执行旧版 Java 3 和 Java 4。

+   用于编写测试的现代编程模型（Java 8）：如今，越来越多的开发人员使用 Java 8 的新功能编写代码，如 lambda 表达式。JUnit 4 是基于 Java 5 构建的，但 JUnit 5 是使用 Java 8 从头开始创建的。

# JUnit 5 社区

JUnit 5 的源代码托管在 GitHub 上（[`github.com/junit-team/junit5`](https://github.com/junit-team/junit5)）。JUnit 5 框架的所有模块都已根据开源许可证 EPL v1.0 发布。有一个例外，即名为`junit-platform-surefire-provider`的模块（稍后描述）已使用 Apache License v2.0 发布。

JUnit 开发路线图（[`github.com/junit-team/junit5/wiki/Roadmap`](https://github.com/junit-team/junit5/wiki/Roadmap)）以及不同发布和里程碑的定义和状态（[`github.com/junit-team/junit5/milestones/`](https://github.com/junit-team/junit5/milestones/)）在 GitHub 上是公开的。以下表格总结了这个路线图：

| 阶段 | 日期 | 发布 |
| --- | --- | --- |
| 0. 众筹 | 2015 年 7 月至 2015 年 10 月 | - |
| 1. 启动 | 2015 年 10 月 20 日至 22 日 | - |
| 2. 第一个原型 | 2015 年 10 月 23 日至 2015 年 11 月底 | - |
| 3. Alpha 版本 | 2016 年 2 月 1 日 | 5.0 Alpha |
| 4. **第一个里程碑** | 2016 年 7 月 9 日 | 5.0 M1：稳定的、有文档的面向 IDE 的 API（启动器 API 和引擎 SPI），动态测试 |
| 5. **额外的里程碑** | 2016 年 7 月 23 日（5.0 M2）2016 年 11 月 30 日（5.0 M3）2017 年 4 月 1 日（5.0 M4）2017 年 7 月 5 日（5.0 M5）2017 年 7 月 16 日（5.0 M6） | 5.0 M2：错误修复和小的改进发布 5.0 M3：JUnit 4 互操作性，额外的发现选择器 5.0 M4：测试模板，重复测试和参数化测试 5.0 M5：动态容器和小的 API 更改 5.0 M6：Java 9 兼容性，场景测试，JUnit Jupiter 的额外扩展 API |
| 6. **发布候选**（**RC**） | 2017 年 7 月 30 日 2017 年 7 月 30 日 2017 年 8 月 23 日 | 5.0 RC1：最终错误修复和文档改进 5.0 RC2：修复 Gradle 对*junit-jupiter-engine*的使用 5.0 RC3：配置参数和错误修复 |
| 7. **正式发布**（**GA**） | 2017 年 9 月 10 日 | 5.0 GA：第一个稳定版本发布 |

JUnit 5 的贡献者不仅仅是开发人员。贡献者还是测试人员、维护者和沟通者。在撰写本文时，GitHub 上最多的 JUnit 5 贡献者是：

+   Sam Brannen（[@sam_brannen](https://twitter.com/sam_brannen)）：Spring Framework 和 JUnit 5 的核心贡献者。Swiftmind 的企业 Java 顾问。Spring 和 JUnit 培训师。会议发言人。

+   Marc Philipp（[@marcphilipp](https://twitter.com/marcphilipp)）：LogMeIn 的高级软件工程师，JUnit 或 Usus 等开源项目的活跃贡献者。会议发言人。

+   Johannes Link（[@johanneslink](https://twitter.com/johanneslink)）：程序员和软件治疗师。JUnit 5 支持者。

+   Matthias Merdes：德国海德堡移动有限公司的首席开发人员。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00021.jpeg)

GitHub 上最多的 JUnit 5 贡献者

以下列表提供了一些在线 JUnit 5 资源：

+   官方网站（[`junit.org/junit5/`](https://twitter.com/hashtag/JUnit5)）。

+   源代码（[`github.com/junit-team/junit5/`](https://github.com/junit-team/junit5/)）。

+   JUnit 5 开发者指南（[`junit.org/junit5/docs/current/user-guide/`](http://junit.org/junit5/docs/current/user-guide/)）。参考文档。

+   JUnit 团队的 Twitter（[`twitter.com/junitteam`](https://twitter.com/junitteam)）。通常，关于 JUnit 5 的推文都标有`#JUnit5`（[`twitter.com/hashtag/JUnit5`](https://twitter.com/hashtag/JUnit5)）。

+   问题（[`github.com/junit-team/junit5/issues`](https://github.com/junit-team/junit5/issues)）。GitHub 上的问题或对额外功能的建议。

+   Stack Overflow 上的问题（[`stackoverflow.com/questions/tagged/junit5`](https://stackoverflow.com/questions/tagged/junit5)）。Stack Overflow 是一个流行的计算机编程问答网站。标签`junit5`应该用于询问关于 JUnit 5 的问题。

+   JUnit 5 JavaDoc（[`junit.org/junit5/docs/current/api/`](http://junit.org/junit5/docs/current/api/)）。

+   JUnit 5 Gitter（[`gitter.im/junit-team/junit5`](https://gitter.im/junit-team/junit5)），这是一个即时通讯和聊天室系统，用于与 JUnit 5 团队成员和其他从业者直接讨论。

+   JVM 的开放测试联盟（[`github.com/ota4j-team/opentest4j`](https://github.com/ota4j-team/opentest4j)）。这是 JUnit 5 团队发起的一个倡议，其目标是为 JVM 上的测试库（JUnit、TestNG、Spock 等）和第三方断言库（Hamcrest、AssertJ 等）提供一个最小的共同基础。其想法是使用一组通用的异常，以便 IDE 和构建工具可以在所有测试场景中以一致的方式支持（到目前为止，JVM 上还没有测试的标准，唯一的共同构建块是 Java 异常`java.lang.AssertionError`）。

# JUnit 5 架构

JUnit 5 框架已经被设计为可以被不同的编程客户端消费。第一组客户端是 Java 测试。这些测试可以基于 JUnit 4（使用旧的测试编程模型的测试）、JUnit 5（使用全新的编程模型的测试）甚至其他类型的 Java 测试（第三方）。第二组客户端是构建工具（如 Maven 或 Gradle）和 IDE（如 IntelliJ 或 Eclipse）。

为了以松散耦合的方式实现所有这些部分的集成，JUnit 5 被设计为模块化的。如下图所示，JUnit 5 框架由三个主要组件组成，称为 Platform、Jupiter 和 Vintage：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00022.jpeg)

JUnit 5 架构：高级组件

JUnit 5 架构的高级组件列举如下：

+   第一个高级组件称为*Jupiter*。它提供了 JUnit 5 框架全新的编程和扩展模型。

+   在 JUnit 5 的核心中，我们找到了 JUnit *Platform*。这个组件旨在成为 JVM 中执行任何测试框架的基础。换句话说，它提供了运行 Jupiter 测试、传统的 JUnit 4 以及第三方测试（例如 Spock、FitNesse 等）的机制。

+   JUnit 5 架构的最后一个高级组件称为*Vintage*。该组件允许在 JUnit 平台上直接运行传统的 JUnit 测试。

让我们更仔细地查看每个组件的细节，以了解它们的内部模块：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00023.jpeg)

JUnit 5 架构：模块

如前图所示，有三种类型的模块：

+   **测试 API**：这些是面向用户（即软件工程师和测试人员）的模块。这些模块为特定的测试引擎提供了编程模型（例如，`junit-jupiter-api`用于 JUnit 5 测试，`junit`用于 JUnit 4 测试）。

+   **测试引擎**：这些模块允许在 JUnit 平台内执行一种测试（Jupiter 测试、传统的 JUnit 4 或其他 Java 测试）。它们是通过扩展通用的*Platform Engine*（`junit-platform-engine`）创建的。

+   **测试启动器**：这些模块为外部构建工具和 IDE 提供了在 JUnit 平台内进行测试发现的能力。这个 API 被工具如 Maven、Gradle、IntelliJ 等所使用，使用`junit-platform-launcher`模块。

由于这种模块化架构，JUnit 框架暴露了一组接口：

+   **API**（**应用程序编程接口**）用于编写测试，*Jupiter API*。这个 API 的详细描述就是所谓的 Jupiter 编程模型，它在本书的第三章*JUnit 5 标准测试*和第四章*使用高级 JUnit 功能简化测试*中有详细描述。

+   **SPI**（**服务提供者接口**）用于发现和执行测试，*Engine SPI*。这个 SPI 通常由测试引擎扩展，最终提供编写测试的编程模型。

+   用于测试发现和执行的 API，*Launcher API*。这个 API 通常由编程客户端（IDE 和构建工具）消耗。

API 和 SPI 都是软件工程师用于特定目的的一组资产（通常是类和接口）。不同之处在于 API 是*调用*，而 SPI 是*扩展*。

# 测试引擎 SPI

测试引擎 SPI 允许在 JVM 之上创建测试执行器。在 JUnit 5 框架中，有两个测试引擎实现：

+   `junit-vintage-engine`：这允许在 JUnit 平台中运行 JUnit 3 和 4 的测试。

+   `junit-jupiter-engine`：这允许在 JUnit 平台中运行 JUnit 5 的测试。

此外，第三方测试库（例如 Spock、TestNG 等）可以通过提供自定义测试引擎来插入 JUnit 平台。为此，这些框架应该通过扩展 JUnit 5 接口`org.junit.platform.engine.TestEngine`来创建自己的测试引擎。为了扩展这个接口，必须重写三个强制性方法：

+   `getId`：测试引擎的唯一标识符。

+   `discover`：查找和过滤测试的逻辑。

+   `execute`：运行先前找到的测试的逻辑。

以下示例提供了自定义测试引擎的框架：

```java
package io.github.bonigarcia;

import org.junit.platform.engine.EngineDiscoveryRequest;
import org.junit.platform.engine.ExecutionRequest;
import org.junit.platform.engine.TestDescriptor;
import org.junit.platform.engine.TestEngine;
import org.junit.platform.engine.UniqueId;
import org.junit.platform.engine.support.descriptor.EngineDescriptor;

public class MyCustomEngine implements TestEngine {

    public static final String *ENGINE_ID* = "my-custom-engine";

    @Override
    public String getId() {
        return *ENGINE_ID*;
    }

    @Override
    public TestDescriptor discover(EngineDiscoveryRequest discoveryRequest,
            UniqueId uniqueId) {
        // Discover test(s) and return a TestDescriptor object
        TestDescriptor testDescriptor = new EngineDescriptor(uniqueId,
                "My test");
        return testDescriptor;
    }

    @Override
    public void execute(ExecutionRequest request) {
        // Use ExecutionRequest to execute TestDescriptor
        TestDescriptor rootTestDescriptor =             
                request.getRootTestDescriptor();
        request.getEngineExecutionListener()
                .executionStarted(rootTestDescriptor);
    }

}
```

社区在 JUnit 5 团队的 GitHub 网站上的维基中维护了一份现有测试引擎的列表（例如 Specsy、Spek 等）：[`github.com/junit-team/junit5/wiki/Third-party-Extensions`](https://github.com/junit-team/junit5/wiki/Third-party-Extensions)。

# 测试启动器 API

JUnit 5 的目标之一是使 JUnit 与其编程客户端（构建工具和 IDE）之间的接口更加强大和稳定。为此目的，已经实现了测试启动器 API。这个 API 被 IDE 和构建工具用于发现、过滤和执行测试。

仔细查看此 API 的细节，我们会发现`LauncherDiscoveryRequest`类，它公开了一个流畅的 API，用于选择测试的位置（例如类、方法或包）。这组测试可以进行过滤，例如使用匹配模式：

```java
import static org.junit.platform.engine.discovery.ClassNameFilter.includeClassNamePatterns;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectClass;
import static org.junit.platform.engine.discovery.DiscoverySelectors.selectPackage;

import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.TestPlan;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;

// Discover and filter tests
LauncherDiscoveryRequest request = LauncherDiscoveryRequestBuilder
     .*request*()
     .*selectors*(*selectPackage*("io.github.bonigarcia"),     
      selectClass(MyTest.class))
     .*filters*(i*ncludeClassNamePatterns*(".*Test")).build();
Launcher launcher = LauncherFactory.create();
TestPlan plan = launcher.discover(request);
```

之后，可以使用`TestExecutionListener`类执行生成的测试套件。这个类也可以用于获取反馈和接收事件：

```java
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;

// Executing tests
TestExecutionListener listener = new SummaryGeneratingListener();
launcher.registerTestExecutionListeners(listener);
launcher.execute(request);
```

# 在 JUnit 5 中运行测试

在撰写本文时，Jupiter 测试可以通过多种方式执行：

+   **使用构建工具**：Maven（在模块`junit-plaform-surefire-provider`中实现）或 Gradle（在模块`junit-platform-gradle-plugin`中实现）。

+   **使用控制台启动器**：一个命令行 Java 应用程序，允许从控制台启动 JUnit 平台。

+   **使用 IDE**：IntelliJ（自 2016.2 版）和 Eclipse（自 4.7 版，Oxygen）。

由于我们将要发现，并且由于 JUnit 5 的模块化架构，我们需要在我们的项目中包含三个依赖项：一个用于测试 API（实现测试），另一个用于测试引擎（运行测试），最后一个用于测试启动器（发现测试）。

# 使用 Maven 进行 Jupiter 测试

为了在 Maven 项目中运行 Jupiter 测试，我们需要正确配置`pom.xml`文件。首先，我们需要将`junit-jupiter-api`模块作为依赖项包含进去。这是为了编写我们的测试，通常使用测试范围：

```java
<dependencies>
   <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter-api</artifactId>
      <version>${junit.jupiter.version}</version>
      <scope>test</scope>
   </dependency>
</dependencies>
```

一般来说，建议使用最新版本的依赖项。为了检查该版本，我们可以在 Maven 中央仓库（[`search.maven.org/`](http://search.maven.org/)）上进行检查。

然后，必须声明`maven-surefire-plugin`。在内部，此插件需要两个依赖项：测试启动器（`junit-platform-surefire-provider`）和测试引擎（`junit-jupiter-engine`）：

```java
<build>
   <plugins>
      <plugin>
         <artifactId>maven-surefire-plugin</artifactId>
         <version>${maven-surefire-plugin.version}</version>
         <dependencies>
             <dependency>
                <groupId>org.junit.platform</groupId>
                <artifactId>junit-platform-surefire-provider</artifactId>
                <version>${junit.platform.version}</version>
            </dependency>
            <dependency>
               <groupId>org.junit.jupiter</groupId>
               <artifactId>junit-jupiter-engine</artifactId>
               <version>${junit.jupiter.version}</version>
            </dependency>
         </dependencies>
      </plugin>
   </plugins>
 </build>
```

本书的所有源代码都可以在 GitHub 存储库[`github.com/bonigarcia/mastering-junit5`](https://github.com/bonigarcia/mastering-junit5)上公开获取。

最后但同样重要的是，我们需要创建一个 Jupiter 测试用例。到目前为止，我们还没有学习如何实现 Jupiter 测试（这部分在第三章中有介绍，JUnit 5 标准测试）。然而，我们在这里执行的测试是演示 JUnit 5 框架执行的最简单的测试。Jupiter 测试在其最小表达形式中只是一个 Java 类，其中的一个（或多个）方法被注释为`@Test`（包`org.junit.jupiter.api`）。以下代码段提供了一个示例：

```java
package io.github.bonigarcia;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class MyFirstJUnit5Test {

   @Test
   void myFirstTest() {
       String message = "1+1 should be equal to 2";
       System.*out*.println(message);
       *assertEquals*(2, 1 + 1, message);
   }

}
```

JUnit 在运行时需要 Java 8（或更高版本）。但是，我们仍然可以测试使用先前版本的 Java 编译的代码。

如下图所示，可以使用命令`mvn test`执行此测试：

！[](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00024.gif)

使用 Maven 运行 Jupiter 测试

# 使用 Gradle 运行 Jupiter 测试

现在，我们将研究相同的示例，但这次使用 Gradle 执行。因此，我们需要配置`build.gradle`文件。在此文件中，我们需要定义：

+   Jupiter API 的依赖项（`junit-jupiter-api`）。

+   测试引擎的依赖项（`junit-jupiter-engine`）。

+   测试启动器的插件（`junit-platform-gradle-plugin`）。

`build.gradle`的完整源代码如下：

```java
buildscript {
   repositories {
      mavenCentral()
   }
   dependencies {
      classpath("org.junit.platform:junit-platform-gradle-plugin:${junitPlatformVersion}")
   }
}
repositories {
   mavenCentral()
}

apply plugin: 'java'
apply plugin: 'eclipse'
apply plugin: 'idea'
apply plugin: 'org.junit.platform.gradle.plugin'

compileTestJava {
   sourceCompatibility = 1.8
   targetCompatibility = 1.8
   options.compilerArgs += '-parameters'
}

dependencies {
   testCompile("org.junit.jupiter:junit-jupiter-api:${junitJupiterVersion}")
   testRuntime("org.junit.jupiter:junit-jupiter-engine:${junitJupiterVersion}")
}
```

我们使用命令`gradle test`来从命令行使用 Gradle 运行我们的 Jupiter 测试：

！[](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00025.gif)

使用 Gradle 运行 Jupiter 测试

# 使用 Maven 运行传统测试

以下是我们想要在 JUnit 平台内运行传统测试（在本例中为 JUnit 4）的图像：

```java
package io.github.bonigarcia;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class LegacyJUnit4Test {

   @Test
   public void myFirstTest() {
      String message = "1+1 should be equal to 2";
      System.*out*.println(message);
      *assertEquals*(message, 2, 1 + 1);
   }

}
```

为此，在 Maven 中，我们首先需要在`pom.xml`中包含旧的 JUnit 4 依赖项，如下所示：

```java
<dependencies>
   <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.12</version>
      <scope>test</scope>
   </dependency>
</dependencies>
```

然后，我们需要包含`maven-surefire-plugin`，使用以下插件的依赖项：测试引擎（`junit-vintage-engine`）和测试启动器（`junit-platform-surefire-provider`）：

```java
<build>
   <plugins>
      <plugin>
         <artifactId>maven-surefire-plugin</artifactId>
         <version>${maven-surefire-plugin.version}</version>
         <dependencies>
            <dependency>
               <groupId>org.junit.platform</groupId>
               <artifactId>junit-platform-surefire-provider</artifactId>
               <version>${junit.platform.version}</version>
            </dependency>
            <dependency>
                <groupId>org.junit.vintage</groupId>
                <artifactId>junit-vintage-engine</artifactId>
                <version>${junit.vintage.version}</version>
            </dependency>
         </dependencies>
      </plugin>
   </plugins>
</build>
```

从命令行执行也将使用命令`mvn test`：

！[](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00026.gif)

使用 Maven 运行传统测试

# 使用 Gradle 运行传统测试

如果我们想要执行之前示例中提到的相同测试（`io.github.bonigarcia.LegacyJUnit4Test`），但这次使用 Gradle，我们需要在`build.gradle`文件中包含以下内容：

+   JUnit 4.12 的依赖项。

+   测试引擎的依赖项（`junit-vintage-engine`）。

+   测试启动器的插件（`junit-platform-gradle-plugin`）。

因此，`build.gradle`的完整源代码如下：

```java
buildscript {
   repositories {
      mavenCentral()
   }
   dependencies {
      classpath("org.junit.platform:junit-platform-gradle-plugin:${junitPlatformVersion}")
   }
}

repositories {
   mavenCentral()
}

apply plugin: 'java'
apply plugin: 'eclipse'
apply plugin: 'idea'
apply plugin: 'org.junit.platform.gradle.plugin'

compileTestJava {
   sourceCompatibility = 1.8
   targetCompatibility = 1.8
   options.compilerArgs += '-parameters'
}

dependencies {
   testCompile("junit:junit:${junitLegacy}")
   testRuntime("org.junit.vintage:junit-vintage-engine:${junitVintageVersion}")
}
```

从命令行执行如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00027.gif)

使用 Gradle 运行传统测试

# 控制台启动器

`ConsoleLauncher`是一个命令行 Java 应用程序，允许从控制台启动 JUnit 平台。例如，它可以用于从命令行运行 Vintage 和 Jupiter 测试。

包含所有依赖项的可执行 JAR 已发布在中央 Maven 仓库的`junit-platform-console-standalone`工件下。独立的控制台启动器可以如下执行：

```java
java -jar junit-platform-console-standalone-version.jar <Options>
```

示例 GitHub 存储库[*junit5-console-launcher*](https://github.com/bonigarcia/mastering-junit5/tree/master/junit5-console-launcher)包含了 Console Launcher 的简单示例。如下图所示，在 Eclipse 中创建了一个运行配置项，运行主类`org.junit.platform.console.ConsoleLauncher`。然后，使用选项`--select-class`和限定类名（在本例中为`io.github.bonigarcia.EmptyTest`）作为参数传递测试类名。之后，我们可以运行应用程序，在 Eclipse 的集成控制台中获取测试结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00028.jpeg)

在 Eclipse 中使用 ConsoleLauncher 的示例

# 在 JUnit 4 中的 Jupiter 测试

JUnit 5 被设计为向前和向后兼容。一方面，Vintage 组件支持在 JUnit 3 和 4 上运行旧代码。另一方面，JUnit 5 提供了一个 JUnit 4 运行器，允许在支持 JUnit 4 但尚未直接支持新的 JUnit Platform 5 的 IDE 和构建系统中运行 JUnit 5。

让我们看一个例子。假设我们想在不支持 JUnit 5 的 IDE 中运行 Jupiter 测试，例如，一个旧版本的 Eclipse。在这种情况下，我们需要用`@RunWith(JUnitPlatform.class)`注解我们的 Jupiter 测试。`JUnitPlatform`运行器是一个基于 JUnit 4 的运行器，它可以在 JUnit 4 环境中运行任何编程模型受支持的测试。因此，我们的测试结果如下：

```java
package io.github.bonigarcia;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

@RunWith(JUnitPlatform.class)
public class JUnit5CompatibleTest {

   @Test 
   void myTest() {
      String message = "1+1 should be equal to 2";
      System.*out*.println(message);
 *assertEquals*(2, 1 + 1, message);
   }

}
```

如果这个测试包含在一个 Maven 项目中，我们的`pom.xml`应该包含以下依赖项：

```java
<dependencies>
   <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter-api</artifactId>
      <version>${junit.jupiter.version}</version>
      <scope>test</scope>
    </dependency>
    <dependency>
       <groupId>org.junit.jupiter</groupId>
       <artifactId>junit-jupiter-engine</artifactId>
       <version>${junit.jupiter.version}</version>
       <scope>test</scope>
     </dependency>
     <dependency>
        <groupId>org.junit.platform</groupId>
        <artifactId>junit-platform-runner</artifactId>
        <version>${junit.platform.version}</version>
        <scope>test</scope>
     </dependency>
 </dependencies>
```

另一方面，对于 Gradle 项目，我们的`build.gradle`如下：

```java
buildscript {
   repositories {
      mavenCentral()
   }
   dependencies {
      classpath("org.junit.platform:junit-platform-gradle-plugin:${junitPlatformVersion}")
   }
}

repositories {
   mavenCentral()
}

apply plugin: 'java'
apply plugin: 'eclipse'
apply plugin: 'idea'
apply plugin: 'org.junit.platform.gradle.plugin'

compileTestJava {
   sourceCompatibility = 1.8
   targetCompatibility = 1.8
   options.compilerArgs += '-parameters'
}

dependencies {
   testCompile("org.junit.jupiter:junit-jupiter-api:${junitJupiterVersion}")
   testRuntime("org.junit.jupiter:junit-jupiter-engine:${junitJupiterVersion}")
   testCompile("org.junit.platform:junit-platform-runner:${junitPlatformVersion}")
}
```

# IntelliJ

IntelliJ 2016.2+是第一个原生支持执行 Jupiter 测试的 IDE。如下图所示，可以使用 IDE 的集成功能执行任何 Jupiter 测试：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00029.jpeg)

在 IntelliJ 2016.2+中运行 Jupiter 测试

# Eclipse

Eclipse 4.7（*Oxygen*）支持 JUnit 5 的 beta 版本。由于这个原因，Eclipse 提供了直接在 Eclipse 中运行 Jupiter 测试的能力，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00030.jpeg)

在 Eclipse 4.7+中运行 Jupiter 测试

此外，Eclipse 4.7（*Oxygen*）提供了一个向导，可以简单地创建 Jupiter 测试，如下面的图片所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00031.jpeg)

在 Eclipse 中创建 Jupiter 测试的向导

# JUnit 5 的扩展模型

如前所述，Jupiter 是 JUnit 5 的新编程模型的名称，详细描述在第三章中，*JUnit 5 标准测试*和第四章，*使用高级 JUnit 功能简化测试*，以及扩展模型。扩展模型允许使用自定义添加扩展 Jupiter 编程模型。由于这一点，第三方框架（如 Spring 或 Mockito 等）可以无缝地与 JUnit 5 实现互操作性。这些框架提供的扩展将在第五章中进行研究，*JUnit 5 与外部框架的集成*。在当前部分，我们分析扩展模型的一般性能以及 JUnit 5 中提供的扩展。

与 JUnit 4 中以前的扩展点相比（即测试运行器和规则），JUnit 5 的扩展模型由一个单一的、连贯的概念组成：**扩展 API**。这个 API 允许任何第三方（工具供应商、开发人员等）扩展 JUnit 5 的核心功能。我们需要了解的第一件事是，Jupiter 中的每个新扩展都实现了一个名为`Extension`的接口。这个接口是一个*标记*接口，也就是说，它是一个没有字段或方法的 Java 接口：

```java
package org.junit.jupiter.api.extension;

import static org.apiguardian.api.API.Status.STABLE;

import org.apiguardian.api.API;

/**
 * Marker interface for all extensions.
 *
 * @since 5.0
 */
@API(status = STABLE, since = "5.0")
public interface Extension {
}
```

为了简化 Jupiter 扩展的创建，JUnit 5 提供了一组扩展点，允许在测试生命周期的不同部分执行自定义代码。下表包含了 Jupiter 中的扩展点摘要，其详细信息将在下一节中介绍：

| **扩展点** | **由想要实现的扩展** |
| --- | --- |
| `TestInstancePostProcessor` | 在测试实例化后提供额外行为 |
| `BeforeAllCallback` | 在测试容器中所有测试被调用之前提供额外行为 |
| `BeforeEachCallback` | 在每个测试被调用前为测试提供额外行为 |
| `BeforeTestExecutionCallback` | 在每个测试执行前立即为测试提供额外行为 |
| `TestExecutionExceptionHandler` | 处理测试执行期间抛出的异常 |
| `AfterAllCallback` | 在所有测试被调用后，为测试容器提供额外行为 |
| `AfterEachCallback` | 在每个测试被调用后为测试提供额外行为 |
| `AfterTestExecutionCallback` | 在每个测试执行后立即为测试提供额外行为 |
| `ExecutionCondition` | 在运行时条件化测试执行 |
| `ParameterResolver` | 在运行时解析参数 |

一旦我们创建了一个扩展，为了使用它，我们需要使用注解 `ExtendWith`。这个注解可以用来注册一个或多个扩展。它可以声明在接口、类、方法、字段，甚至其他注解中：

```java
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

public class MyTest {

   @ExtendWith(MyExtension.class)
   @Test
   public void test() {
     // My test logic
   }

}
```

# 测试生命周期

有一组旨在控制测试生命周期的扩展点。首先，`TestInstancePostProcessor` 可以用于在测试实例化后执行一些逻辑。之后，有不同的扩展来控制测试前阶段：

+   `BeforeAllCallback` 在所有测试之前定义要执行的逻辑。

+   `BeforeEachCallback` 在测试方法之前定义要执行的逻辑。

+   `BeforeTestExecutionCallback` 在测试方法之前定义要执行的逻辑。

同样，还有控制测试后阶段的扩展：

+   `AfterAllCallback` 在所有测试之后定义要执行的逻辑。

+   `AfterEachCallback` 在测试方法之后定义要执行的逻辑。

+   `AfterTestExecutionCallback` 在测试方法之后定义要执行的逻辑。

在 `Before*` 和 `After*` 回调之间，有一个提供收集异常的扩展：`TestExecutionExceptionHandler`。

所有这些回调及其在测试生命周期中的顺序如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00032.jpeg)

扩展回调的生命周期

让我们看一个例子。我们创建了一个名为 `IgnoreIOExceptionExtension` 的扩展，它实现了 `TestExecutionExceptionHandler`。在这个例子中，扩展检查异常是否是 `IOException`。如果是，异常就被丢弃：

```java
package io.github.bonigarcia;

import java.io.IOException;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestExecutionExceptionHandler;

public class IgnoreIOExceptionExtension
   implements TestExecutionExceptionHandler {

   @Override
   public void handleTestExecutionException(ExtensionContext context,
          Throwable throwable) throws Throwable {
      if (throwable instanceof IOException) {
         return;
      }
      throw throwable;
   }

}
```

考虑以下测试类，其中包含两个测试（`@Test`）。第一个用 `@ExtendWith` 和我们自定义的扩展（`IgnoreIOExceptionExtension`）进行了注释：

```java
package io.github.bonigarcia;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

public class ExceptionTest {

   @ExtendWith(IgnoreIOExceptionExtension.class)
   @Test
   public void firstTest() throws IOException {
      throw new IOException("IO Exception");
   }

   @Test
   public void secondTest() throws IOException {
      throw new IOException("My IO Exception");
   }

}
```

在执行这个测试类时，第一个测试成功了，因为 `IOException` 已经被我们的扩展内部处理了。另一方面，第二个测试会失败，因为异常没有被处理。

可以在控制台中看到这个测试类的执行结果。请注意，我们使用 Maven 命令 `mvn test -Dtest=ExceptionTest` 选择要执行的测试：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00033.gif)

忽略异常示例的输出

# 条件扩展点

为了创建根据给定条件激活或停用测试的扩展，JUnit 5 提供了一个条件扩展点，称为 `ExecutionCondition`。下面的代码片段显示了这个扩展点的声明：

```java
package org.junit.jupiter.api.extension;

import static org.apiguardian.api.API.Status.STABLE;

import org.apiguardian.api.API;

@FunctionalInterface
@API(status = STABLE, since = "5.0")
public interface ExecutionCondition extends Extension {
   ConditionEvaluationResult evaluateExecutionCondition         
     ExtensionContext context);

}
```

该扩展可以用于停用容器中的所有测试（可能是一个类）或单个测试（可能是一个测试方法）。该扩展的示例在第三章的*C 条件测试执行*部分中提供，*JUnit 5 标准测试*。

# 依赖注入

`ParameterResolver`扩展提供了方法级别的依赖注入。在这个例子中，我们可以看到如何使用名为`MyParameterResolver`的`ParameterResolver`的自定义实现来在测试方法中注入参数。在代码后面，我们可以看到这个解析器将简单地注入硬编码的字符串参数，值为`my parameter`：

```java
package io.github.bonigarcia;

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;
import org.junit.jupiter.api.extension.ParameterResolver;

public class MyParameterResolver implements ParameterResolver {

    @Override
    public boolean supportsParameter(ParameterContext parameterContext,
            ExtensionContext extensionContext)
            throws ParameterResolutionException {
        return true;
    }

    @Override
    public Object resolveParameter(ParameterContext parameterContext,
            ExtensionContext extensionContext)
            throws ParameterResolutionException {
        return "my parameter";
    }

}
```

然后，这个参数解析器可以像往常一样在测试中使用，声明为`@ExtendWith`注解：

```java
package io.github.bonigarcia;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

public class DependencyInjectionTest {

   @ExtendWith(MyParameterResolver.class)
   @Test
   public void test(Object parameter) {
      System.*out*.println("My parameter " + parameter);
   }
}
```

最后，如果我们执行这个测试（例如使用 Maven 和命令行），我们可以看到注入的参数被记录在标准输出中：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00034.gif)

依赖注入扩展示例的输出

# 第三方扩展

```java
SpringExtension:
```

```java
package org.springframework.test.context.junit.jupiter;

import org.junit.jupiter.api.extension.*;

public class SpringExtension implements BeforeAllCallback,     
   AfterAllCallback,
   TestInstancePostProcessor, BeforeEachCallback, AfterEachCallback,
   BeforeTestExecutionCallback, AfterTestExecutionCallback,
   ParameterResolver {

   @Override
   public void afterTestExecution(TestExtensionContext context) 
    throws Exception {
      // implementation
   }

   // Rest of methods
}
```

JUnit 5 的现有扩展列表（例如 Spring，Selenium，Docker 等）由社区在 JUnit 5 团队的 GitHub 网站的 wiki 中维护：[`github.com/junit-team/junit5/wiki/Third-party-Extensions`](https://github.com/junit-team/junit5/wiki/Third-party-Extensions)。其中一些也在第五章中有详细介绍，*JUnit 5 与外部框架的集成*。

# 总结

本章概述了 JUnit 5 测试框架。由于 JUnit 4 的限制（单片架构，无法组合测试运行器，以及测试规则的限制），需要一个新的主要版本的框架。为了进行实现，JUnit Lambda 项目在 2015 年发起了一场众筹活动。结果，JUnit 5 开发团队诞生了，并于 2017 年 9 月 10 日发布了该框架的 GA 版本。

JUnit 5 被设计为现代化（即从一开始就使用 Java 8 和 Java 9 兼容），并且是模块化的。JUnit 5 内的三个主要组件是：Jupiter（新的编程和扩展模型），Platform（在 JVM 中执行任何测试框架的基础），以及 Vintage（与传统的 JUnit 3 和 4 测试集成）。在撰写本文时，JUnit 5 测试可以使用构建工具（Maven 或 Gradle）以及 IDE（IntelliJ 2016.2+或 Eclipse 4.7+）来执行。

JUnit 5 的扩展模型允许任何第三方扩展其核心功能。为了创建 JUnit 5 扩展，我们需要实现一个或多个 JUnit 扩展点（如`BeforeAllCallback`，`ParameterResolver`或`ExecutionCondition`等），然后使用`@ExtendWith`注解在我们的测试中注册扩展。

在接下来的第三章中，*JUnit 5 标准测试*，我们将学习 Jupiter 编程模型的基础知识。换句话说，我们将学习如何创建标准的 JUnit 5 测试。


# 第三章：JUnit 5 标准测试

言语是廉价的。给我看代码。

*- Linus Torvalds*

JUnit 5 提供了一个全新的编程模型，称为 Jupiter。我们可以将这个编程模型看作是软件工程师和测试人员的 API，允许创建 JUnit 5 测试。这些测试随后在 JUnit 平台上执行。正如我们将要发现的那样，Jupiter 编程模型允许创建许多不同类型的测试。本章介绍了 Jupiter 的基础知识。为此，本章结构如下：

+   **测试生命周期**：在本节中，我们分析了 Jupiter 测试的结构，描述了在 JUnit 5 编程模型中管理测试生命周期的注解。然后，我们了解如何跳过测试，以及如何为测试添加自定义显示名称的注解。

+   **断言**：在本节中，首先我们简要介绍了称为断言（也称为谓词）的验证资产。其次，我们研究了 Jupiter 中如何实现这些断言。最后，我们介绍了一些关于断言的第三方库，提供了一些 Hamcrest 的示例。

+   **标记和过滤测试**：在本节中，首先我们将学习如何为 Jupiter 测试创建标签，即如何在 JUnit 5 中创建标签。然后，我们将学习如何使用 Maven 和 Gradle 来过滤我们的测试。最后，我们将分析如何使用 Jupiter 创建元注解。

+   **条件测试执行**：在本节中，我们将学习如何根据给定条件禁用测试。之后，我们将回顾 Jupiter 中所谓的假设，这是 Jupiter 提供的一个机制，只有在某些条件符合预期时才运行测试。

+   **嵌套测试**：本节介绍了 Jupiter 如何允许表达一组测试之间的关系，称为嵌套测试。

+   **重复测试**：本节回顾了 Jupiter 如何提供重复执行指定次数的测试的能力。

+   **从 JUnit 4 迁移到 JUnit 5**：本节提供了一组关于 JUnit 5 和其直接前身 JUnit 4 之间主要区别的提示。然后，本节介绍了 Jupiter 测试中对几个 JUnit 4 规则的支持。

# 测试生命周期

正如我们在第一章中所看到的，一个单元测试用例由四个阶段组成：

1.  **设置**（可选）：首先，测试初始化测试夹具（在 SUT 的图片之前）。

1.  **练习**：其次，测试与 SUT 进行交互，从中获取一些结果。

1.  **验证**：第三，将来自被测试系统的结果与预期值进行比较，使用一个或多个断言（也称为谓词）。因此，创建了一个测试判决。

1.  **拆卸**（可选）：最后，测试释放测试夹具，将 SUT 恢复到初始状态。

在 JUnit 4 中，有不同的注解来控制这些测试阶段。JUnit 5 遵循相同的方法，即使用 Java 注解来标识 Java 类中的不同方法，实现测试生命周期。在 Jupiter 中，所有这些注解都包含在`org.junit.jupiter.api`包中。

JUnit 的最基本注解是`@Test`，它标识了必须作为测试执行的方法。因此，使用`org.junit.jupiter.api.Test`注解的 Java 方法将被视为测试。这个注解与 JUnit 4 的`@Test`的区别有两个方面。一方面，Jupiter 的`@Test`注解不声明任何属性。在 JUnit 4 中，`@Test`可以声明测试超时（作为长属性，以毫秒为单位的超时时间），另一方面，在 JUnit 5 中，测试类和测试方法都不需要是 public（这是 JUnit 4 中的要求）。

看一下下面的 Java 类。可能，这是我们可以用 Jupiter 创建的最简单的测试用例。它只是一个带有`@Test`注解的方法。测试逻辑（即前面描述的练习和验证阶段）将包含在`myTest`方法中。

```java
package io.github.bonigarcia;

import org.junit.jupiter.api.Test;

class SimpleJUnit5Test {

    @Test
    void mySimpleTest() {
          // My test logic here
    }

}
```

Jupiter 注解（也位于包`org.junit.jupiter.api`中）旨在控制 JUnit 5 测试中的设置和拆卸阶段，如下表所述：

| **JUnit 5 注解** | **描述** | **JUnit 4 的等效** |
| --- | --- | --- |
| `@BeforeEach` | 在当前类中的每个`@Test`之前执行的方法 | `@Before` |
| `@AfterEach` | 在当前类中的每个`@Test`之后执行的方法 | `@After` |
| `@BeforeAll` | 在当前类中的所有`@Test`之前执行的方法 | `@BeforeClass` |
| `@AfterAll` | 在当前类中的所有`@Test`之后执行的方法 | `@AfterClass` |

这些注解（`@BeforeEach`，`@AfterEach`，`@AfterAll`和`@BeforeAll`）注解的方法始终会被继承。

下图描述了这些注解在 Java 类中的执行顺序：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00035.jpeg)

控制测试生命周期的 Jupiter 注解

让我们回到本节开头看到的测试的通用结构。现在，我们能够将 Jupiter 注解映射到测试用例的不同部分，以控制测试生命周期。如下图所示，我们通过使用`@BeforeAll`和`@BeforeEach`注解的方法进行设置阶段。然后，我们在使用`@Test`注解的方法中进行练习和验证阶段。最后，我们在使用`@AfterEach`和`@AfterAll`注解的方法中进行拆卸过程。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00036.jpeg)

单元测试阶段与 Jupiter 注解之间的关系

让我们看一个简单的例子，它在一个单独的 Java 类中使用了所有这些注解。这个例子定义了两个测试（即，使用`@Test`注解的两个方法），并且我们使用`@BeforeAll`，`@BeforeEach`，`@AfterEach`和`@AfterAll`注解为测试生命周期的其余部分定义了额外的方法：

```java
package io.github.bonigarcia;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class LifecycleJUnit5Test {

      @BeforeAll
      static void setupAll() {
            System.*out*.println("Setup ALL TESTS in the class");
      }

      @BeforeEach
      void setup() {
            System.*out*.println("Setup EACH TEST in the class");
      }

      @Test
      void testOne() {
            System.*out*.println("TEST 1");
      }

      @Test
      void testTwo() {
            System.*out*.println("TEST 2");
      }

      @AfterEach
      void teardown() {
            System.*out*.println("Teardown EACH TEST in the class");
      }

      @AfterAll
      static void teardownAll() {
            System.*out*.println("Teardown ALL TESTS in the class");
      }

}
```

如果我们运行这个测试类，首先会执行`@BeforeAll`。然后，两个测试方法将按顺序执行，即先执行第一个，然后执行另一个。在每次执行中，测试之前使用`@BeforeEach`注解的设置方法将在测试之前执行，然后执行`@AfterEach`方法。以下截图显示了使用 Maven 和命令行执行测试的情况：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00037.gif)

控制其生命周期的 Jupiter 测试的执行

# 测试实例生命周期

为了提供隔离的执行，JUnit 5 框架在执行实际测试（即使用`@Test`注解的方法）之前创建一个新的测试实例。这种*每方法*的测试实例生命周期是 Jupiter 测试和其前身（JUnit 3 和 4）的行为。作为新功能，这种默认行为可以在 JUnit 5 中通过简单地使用`@TestInstance(Lifecycle.PER_CLASS)`注解来改变。使用这种模式，测试实例将每个类创建一次，而不是每个测试方法创建一次。

这种*每类*的行为意味着可以将`@BeforeAll`和`@AfterAll`方法声明为非静态的。这对于与一些高级功能一起使用非常有益，比如嵌套测试或默认测试接口（在下一章中解释）。 

总的来说，考虑到扩展回调（如第二章*JUnit 5 中的新功能*中所述的*JUnit 5 的扩展模型*），用户代码和扩展的相对执行顺序如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00038.jpeg)

用户代码和扩展的相对执行顺序

# 跳过测试

Jupiter 注释`@Disabled`（位于包`org.junit.jupiter.api`中）可用于跳过测试。它可以在类级别或方法级别使用。以下示例在方法级别使用注释`@Disabled`，因此强制跳过测试：

```java
package io.github.bonigarcia;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

class DisabledTest {

    @Disabled
    @Test
    void skippedTest() {
    }

}
```

如下截图所示，当我们执行此示例时，测试将被视为已跳过：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00039.gif)

禁用测试方法的控制台输出

在这个例子中，注释`@Disabled`放置在类级别，因此类中包含的所有测试都将被跳过。请注意，通常可以在注释中指定自定义消息，通常包含禁用的原因：

```java
package io.github.bonigarcia;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

@Disabled("All test in this class will be skipped")
class AllDisabledTest {

    @Test
    void skippedTestOne() {
    }

    @Test
    void skippedTestTwo() {
    }

}
```

以下截图显示了在执行测试用例时（在此示例中使用 Maven 和命令行）跳过测试案例的情况：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00040.gif)

禁用测试类的控制台输出

# 显示名称

JUnit 4 基本上通过使用带有`@Test`注释的方法的名称来识别测试。这对测试名称施加了限制，因为这些名称受到在 Java 中声明方法的方式的限制。

为了解决这个问题，Jupiter 提供了声明自定义显示名称（与测试名称不同）的能力。这是通过注释`@DisplayName`完成的。此注释为测试类或测试方法声明了自定义显示名称。此名称将由测试运行器和报告工具显示，并且可以包含空格、特殊字符，甚至表情符号。

看看以下示例。我们使用`@DisplayName`为测试类和类中声明的三个测试方法注释了自定义测试名称：

```java
package io.github.bonigarcia;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("A special test case")
class DisplayNameTest {

    @Test
    @DisplayName("Custom test name containing spaces")
    void testWithDisplayNameContainingSpaces() {
    }

    @Test
    @DisplayName("(╯°Д°)╯")
    void testWithDisplayNameContainingSpecialCharacters() {
    }

    @Test
    @DisplayName("")
    void testWithDisplayNameContainingEmoji() {
    }

}
```

因此，当在符合 JUnit 5 的 IDE 中执行此测试时，我们会看到这些标签。以下图片显示了在 IntelliJ 2016.2+上执行示例的情况：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00042.jpeg)

在 IntelliJ 中使用*@DisplayName*执行测试案例

另一方面，显示名称也可以在 Eclipse 4.7（Oxygen）或更新版本中看到：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00043.jpeg)

在 Eclipse 中使用*@DisplayName*执行测试案例

# 断言

我们知道，测试案例的一般结构由四个阶段组成：设置、执行、验证和拆卸。实际测试发生在第二和第三阶段，当测试逻辑与被测试系统交互时，从中获得某种结果。这个结果在验证阶段与预期结果进行比较。在这个阶段，我们找到了我们所谓的断言。在本节中，我们将更仔细地研究它们。

断言（也称为谓词）是一个`boolean`语句，通常用于推理软件的正确性。从技术角度来看，断言由三部分组成（见列表后的图像）：

1.  首先，我们找到预期值，这些值来自我们称之为测试预言的东西。测试预言是预期输出的可靠来源，例如，系统规范。

1.  其次，我们找到真正的结果，这是由测试对 SUT 进行的练习阶段产生的。

1.  最后，这两个值使用一些逻辑比较器进行比较。这种比较可以通过许多不同的方式进行，例如，我们可以比较对象的身份（相等或不相等），大小（更高或更低的值），等等。结果，我们得到一个测试结论，最终将定义测试是否成功或失败。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00044.jpeg)

断言的示意图

# Jupiter 断言

让我们继续讨论 JUnit 5 编程模型。Jupiter 提供了许多断言方法，例如 JUnit 4 中的方法，并且还添加了一些可以与 Java 8 lambda 一起使用的方法。所有 JUnit Jupiter 断言都是位于`org.junit.jupiter`包中的`Assertions`类中的静态方法。

以下图片显示了这些方法的完整列表：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00045.jpeg)

Jupiter 断言的完整列表（类*org.junit.jupiter.Assertions*）

以下表格回顾了 Jupiter 中不同类型的基本断言：

| **断言** | **描述** |
| --- | --- |
| `fail` | 以给定的消息和/或异常失败测试 |
| `assertTrue` | 断言提供的条件为真 |
| `assertFalse` | 断言提供的条件为假 |
| `assertNull` | 断言提供的对象为 `null` |
| `assertNotNull` | 断言提供的对象不是 `null` |
| `assertEquals` | 断言两个提供的对象相等 |
| `assertArrayEquals` | 断言两个提供的数组相等 |
| `assertIterableEquals` | 断言两个可迭代对象深度相等 |
| `assertLinesMatch` | 断言两个字符串列表相等 |
| `assertNotEquals` | 断言两个提供的对象不相等 |
| `assertSame` | 断言两个对象相同，使用 `==` 进行比较 |
| `assertNotSame` | 断言两个对象不同，使用 `!=` 进行比较 |

对于表中包含的每个断言，都可以提供一个可选的失败消息（String）。这个消息始终是断言方法中的最后一个参数。这与 JUnit 4 有一点小区别，因为在 JUnit 4 中，这个消息是方法调用中的第一个参数。

以下示例显示了一个使用 `assertEquals`、`assertTrue` 和 `assertFalse` 断言的测试。请注意，我们在类的开头导入了静态断言方法，以提高测试逻辑的可读性。在示例中，我们找到了 `assertEquals` 方法，这里比较了两种原始类型（也可以用于对象）。其次，`assertTrue` 方法评估一个 `boolean` 表达式是否为真。第三，`assertFalse` 方法评估一个布尔表达式是否为假。在这种情况下，请注意消息是作为 Lamdba 表达式创建的。这样，断言消息会被懒惰地评估，以避免不必要地构造复杂的消息：

```java
package io.github.bonigarcia;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class StandardAssertionsTest {

    @Test
    void standardAssertions() {
          *assertEquals*(2, 2);
          *assertTrue*(true,
          "The optional assertion message is now the last parameter");
          *assertFalse*(false, () -> "Really " + "expensive " + "message" 
            + ".");
    }

}
```

本节的以下部分将回顾 Jupiter 提供的高级断言：`assertAll`、`assertThrows`、`assertTimeout` 和 `assertTimeoutPreemptively`。

# 断言组

一个重要的 Jupiter 断言是 `assertAll`。这个方法允许同时对不同的断言进行分组。在分组断言中，所有断言都会被执行，任何失败都将一起报告。

方法 `assertAll` 接受 lambda 表达式（`Executable…`）的可变参数或这些表达式的流（`Stream<Executable>`）。可选地，`assertAll` 的第一个参数可以是一个用于标记断言组的字符串消息。

让我们看一个例子。在以下测试中，我们使用 lambda 表达式对一对 `assertEquals` 进行分组：

```java
package io.github.bonigarcia;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class GroupedAssertionsTest {

    @Test
    void groupedAssertions() {
          Address address = new Address("John", "Smith");
          // In a grouped assertion all assertions are executed, and any
          // failures will be reported together.
          *assertAll*("address", () -> *assertEquals*("John", 
          address.getFirstName()),
              () -> *assertEquals*("User", address.getLastName()));
    }

}
```

在执行这个测试时，将评估组中的所有断言。由于第二个断言失败（`lastname` 不匹配），在最终的判决中报告了一个失败，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00046.gif)

分组断言示例的控制台输出

# 断言异常

另一个重要的 Jupiter 断言是 `assertThrows`。这个断言允许验证在一段代码中是否引发了给定的异常。为此，`assertThrows` 方法接受两个参数。首先是预期的异常类，其次是可执行对象（lambda 表达式），其中应该发生异常：

```java
package io.github.bonigarcia;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class ExceptionTest {

    @Test
    void exceptionTesting() {
          Throwable exception = 
            *assertThrows*(IllegalArgumentException.class,
            () -> {
               throw new IllegalArgumentException("a message");});
          *assertEquals*("a message", exception.getMessage());
    }

}
```

这里期望抛出 `IllegalArgumentException`，而这实际上是在这个 lambda 表达式中发生的。下面的截图显示了测试实际上成功了：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00047.gif)

*assertThrows* 示例的控制台输出

# 断言超时

为了评估 JUnit 5 测试中的超时，Jupiter 提供了两个断言：`assertTimeout` 和 `assertTimeoutPreemptively`。一方面，`assertTimeout` 允许我们验证给定操作的超时。在这个断言中，使用标准 Java 包 `java.time` 的 `Duration` 类定义了预期时间。

我们将看到几个运行示例，以阐明这个断言方法的使用。在下面的类中，我们找到两个使用`assertTimeout`的测试。第一个测试旨在成功，因为我们期望给定操作的持续时间少于 2 分钟，而我们在那里什么也没做。另一方面，第二个测试将失败，因为我们期望给定操作的持续时间最多为 10 毫秒，而我们强制它持续 100 毫秒。

```java
package io.github.bonigarcia;

import static java.time.Duration.ofMillis;
import static java.time.Duration.ofMinutes;
import static org.junit.jupiter.api.Assertions.assertTimeout;

import org.junit.jupiter.api.Test;

class TimeoutExceededTest {

    @Test
    void timeoutNotExceeded() {
          *assertTimeout*(*ofMinutes*(2), () -> {
              // Perform task that takes less than 2 minutes
          });
    }

    @Test
    void timeoutExceeded() {
          *assertTimeout*(*ofMillis*(10), () -> {
              Thread.*sleep*(100);
          });
    }
}
```

当我们执行这个测试时，第二个测试被声明为失败，因为超时已经超过了 90 毫秒：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00048.gif)

*assertTimeout*第一个示例的控制台输出

让我们看看使用`assertTimeout`的另外两个测试。在第一个测试中，`assertTimeout`在给定的超时时间内将代码作为 lambda 表达式进行评估，获取其结果。在第二个测试中，`assertTimeout`在给定的超时时间内评估一个方法，获取其结果：

```java
package io.github.bonigarcia;

import static java.time.Duration.ofMinutes;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeout;

import org.junit.jupiter.api.Test;

class TimeoutWithResultOrMethodTest {

    @Test
    void timeoutNotExceededWithResult() {
          String actualResult = *assertTimeout*(*ofMinutes*(1), () -> {
              return "hi there";
          });
          *assertEquals*("hi there", actualResult);
    }

    @Test
    void timeoutNotExceededWithMethod() {
          String actualGreeting = *assertTimeout*(*ofMinutes*(1),
              TimeoutWithResultOrMethodTest::*greeting*);
          *assertEquals*("hello world!", actualGreeting);
    }

    private static String greeting() {
          return "hello world!";
    }

}
```

在这两种情况下，测试所花费的时间都少于预期，因此它们都成功了：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00049.gif)

*assertTimeout*第二个示例的控制台输出

另一个 Jupiter 断言超时的方法称为`assertTimeoutPreemptively`。与`assertTimeout`相比，`assertTimeoutPreemptively`的区别在于`assertTimeoutPreemptively`不会等到操作结束，当超过预期的超时时，执行会被中止。

在这个例子中，测试将失败，因为我们模拟了一个持续 100 毫秒的操作，并且我们定义了 10 毫秒的超时：

```java
package io.github.bonigarcia;

import static java.time.Duration.ofMillis;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import org.junit.jupiter.api.Test;

class TimeoutWithPreemptiveTerminationTest {

      @Test
      void timeoutExceededWithPreemptiveTermination() {
            *assertTimeoutPreemptively*(*ofMillis*(10), () -> {
                 Thread.*sleep*(100);
            });
      }

}
```

在这个例子中，当达到 10 毫秒的超时时，测试立即被声明为失败：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00050.gif)

*assertTimeoutPreemptively*示例的控制台输出

# 第三方断言库

正如我们所见，Jupiter 提供的内置断言已经足够满足许多测试场景。然而，在某些情况下，可能需要更多的额外功能，比如匹配器。在这种情况下，JUnit 团队建议使用以下第三方断言库：

+   Hamcrest（[`hamcrest.org/`](http://hamcrest.org/)）：一个断言框架，用于编写允许以声明方式定义规则的匹配器对象。

+   AssertJ（[`joel-costigliola.github.io/assertj/`](http://joel-costigliola.github.io/assertj/)）：用于 Java 的流畅断言。

+   Truth（[`google.github.io/truth/`](https://google.github.io/truth/)）：一个用于使测试断言和失败消息更易读的断言 Java 库。

在本节中，我们将简要回顾一下 Hamcrest。这个库提供了断言`assertThat`，它允许创建可读性高且高度可配置的断言。方法`assertThat`接受两个参数：第一个是实际对象，第二个是`Matcher`对象。这个匹配器实现了接口`org.hamcrest.Matcher`，并允许对期望进行部分或完全匹配。Hamcrest 提供了不同的匹配器实用程序，比如`is`，`either`，`or`，`not`和`hasItem`。匹配器方法使用了构建器模式，允许组合一个或多个匹配器来构建一个匹配器链。

为了使用 Hamcrest，首先我们需要在项目中导入依赖项。在 Maven 项目中，这意味着我们必须在`pom.xml`文件中包含以下依赖项：

```java
<dependency>
      <groupId>org.hamcrest</groupId>
      <artifactId>hamcrest-core</artifactId>
      <version>${hamcrest.version}</version>
      <scope>test</scope>
</dependency>
```

如果我们使用 Gradle，我们需要在`build.gradle`文件中添加相应的配置：

```java
dependencies {
      testCompile("org.hamcrest:hamcrest-core:${hamcrest}")
}
```

通常情况下，建议使用最新版本的 Hamcrest。我们可以在 Maven 中央网站上检查它（[`search.maven.org/`](http://search.maven.org/)）。

以下示例演示了如何在 Jupiter 测试中使用 Hamcrest。具体来说，这个测试使用了断言`assertThat`，以及匹配器`containsString`，`equalTo`和`notNullValue`：

```java
package io.github.bonigarcia;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.jupiter.api.Test;

class HamcrestTest {

    @Test
    void assertWithHamcrestMatcher() {
          *assertThat*(2 + 1, *equalTo*(3));
          *assertThat*("Foo", *notNullValue*());
          *assertThat*("Hello world", *containsString*("world"));
    }

}
```

如下截图所示，这个测试执行时没有失败：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00051.gif)

使用 Hamcrest 断言库的示例的控制台输出

# 标记和过滤测试

在 JUnit 5 编程模型中，可以通过注解`@Tag`（包`org.junit.jupiter.api`）为测试类和方法打标签。这些标签可以后来用于过滤测试的发现和执行。在下面的示例中，我们看到了在类级别和方法级别使用`@Tag`的情况：

```java
package io.github.bonigarcia;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("simple")
class SimpleTaggingTest {

      @Test
      @Tag("taxes")
      void testingTaxCalculation() {
      }

}
```

从 JUnit 5 M6 开始，标记测试的标签应满足以下语法规则：

+   标签不能为空或空白。

+   修剪的标签（即去除了前导和尾随空格的标签）不得包含空格。

+   修剪的标签不得包含 ISO 控制字符，也不得包含以下保留字符：`,`，`(`，`)`，`&`，`|`和`!`。

# 使用 Maven 过滤测试

正如我们已经知道的，我们需要在 Maven 项目中使用`maven-surefire-plugin`来执行 Jupiter 测试。此外，该插件允许我们以多种方式过滤测试执行：通过 JUnit 5 标签进行过滤，还可以使用`maven-surefire-plugin`的常规包含/排除支持。

为了按标签过滤，应该使用`maven-surefire-plugin`配置的属性`includeTags`和`excludeTags`。让我们看一个示例来演示如何。考虑同一个 Maven 项目中包含的以下测试。一方面，这个类中的所有测试都被标记为`functional`。

```java
package io.github.bonigarcia;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("functional")
class FunctionalTest {

    @Test
    void testOne() {
        System.*out*.println("Functional Test 1");
    }

    @Test
    void testTwo() {
        System.*out*.println("Functional Test 2");
    }

}
```

另一方面，第二个类中的所有测试都被标记为`non-functional`，每个单独的测试也被标记为更多的标签（`performance`，`security`，`usability`等）：

```java
package io.github.bonigarcia;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("non-functional")
class NonFunctionalTest {

    @Test
    @Tag("performance")
    @Tag("load")
    void testOne() {
        System.*out*.println("Non-Functional Test 1 (Performance/Load)");
    }

    @Test
    @Tag("performance")
    @Tag("stress")
    void testTwo() {
        System.*out*.println("Non-Functional Test 2 (Performance/Stress)");
    }

    @Test
    @Tag("security")
    void testThree() {
        System.*out*.println("Non-Functional Test 3 (Security)");
    }

    @Test
    @Tag("usability")
    void testFour() {
        System.*out*.println("Non-Functional Test 4 (Usability)");    }

}
```

如前所述，我们在 Maven 的`pom.xml`文件中使用配置关键字`includeTags`和`excludeTags`。在这个例子中，我们包含了带有标签`functional`的测试，并排除了`non-functional`：

```java
    <build>
        <plugins>
            <plugin>
                <artifactId>maven-surefire-plugin</artifactId>
                <version>${maven-surefire-plugin.version}</version>
                <configuration>
                    <properties>
                        <includeTags>functional</includeTags>
                        <excludeTags>non-functional</excludeTags>
                    </properties>
                </configuration>
                <dependencies>
                    <dependency>
                        <groupId>org.junit.platform</groupId>
                        <artifactId>junit-platform-surefire-provider</artifactId>
                        <version>${junit.platform.version}</version>
                    </dependency>
                    <dependency>
                        <groupId>org.junit.jupiter</groupId>
                        <artifactId>junit-jupiter-engine</artifactId>
                        <version>${junit.jupiter.version}</version>
                    </dependency>
                </dependencies>
            </plugin>
        </plugins>
    </build>
```

结果是，当我们尝试执行项目中的所有测试时，只有两个测试会被执行（带有标签`functional`的测试），其余的测试不被识别为测试：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00052.gif)

通过标签过滤的 Maven 执行

# Maven 常规支持

Maven 插件的常规包含/排除支持仍然可以用于选择由`maven-surefire-plugin`执行的测试。为此，我们使用关键字`includes`和`excludes`来配置插件执行时用于过滤的测试名称模式。请注意，对于包含和排除，可以使用正则表达式来指定测试文件名的模式：

```java
<configuration>
   <includes>
      <include>**/Test*.java</include>
      <include>**/*Test.java</include>
      <include>**/*TestCase.java</include>
   </includes>
</configuration>
<configuration>
   <excludes>
      <exclude>**/TestCircle.java</exclude>
      <exclude>**/TestSquare.java</exclude>
   </excludes>
</configuration>
```

这三个模式，即包含单词*Test*或以*TestCase*结尾的 Java 文件，默认情况下由*maven-surefire 插件*包含。

# 使用 Gradle 过滤测试

现在让我们转到 Gradle。正如我们已经知道的，我们也可以使用 Gradle 来运行 JUnit 5 测试。关于过滤过程，我们可以根据以下选择要执行的测试：

+   测试引擎：使用关键字引擎，我们可以包含或排除要使用的测试引擎（即`junit-jupiter`或`junit-vintage`）。

+   Jupiter 标签：使用关键字`tags`。

+   Java 包：使用关键字`packages`。

+   类名模式：使用关键字`includeClassNamePattern`。

默认情况下，测试计划中包含所有引擎和标签。只应用包含单词`Tests`的类名。让我们看一个工作示例。我们在前一个 Maven 项目中重用相同的测试，但这次是在一个 Gradle 项目中：

```java
junitPlatform {
      filters {
            engines {
                  include 'junit-jupiter'
                  exclude 'junit-vintage'
            }
            tags {
                  include 'non-functional'
                  exclude 'functional'
            }
            packages {
                  include 'io.github.bonigarcia'
                  exclude 'com.others', 'org.others'
            }
            includeClassNamePattern '.*Spec'
            includeClassNamePatterns '.*Test', '.*Tests'
      }
}
```

请注意，我们包含标签`non-functional`并排除`functional`，因此我们执行了四个测试：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00053.gif)

通过标签过滤的 Gradle 执行

# 元注解

本节的最后部分是关于元注释的定义。JUnit Jupiter 注释可以在其他注释的定义中使用（即可以用作元注释）。这意味着我们可以定义自己的组合注释，它将自动继承其元注释的语义。这个特性非常方便，可以通过重用 JUnit 5 注释`@Tag`来创建我们自定义的测试分类。

让我们看一个例子。考虑测试用例的以下分类，其中我们将所有测试分类为功能和非功能，然后在非功能测试下再进行另一级分类：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00054.jpeg)

测试的示例分类（功能和非功能）

有了这个方案，我们将为树结构的叶子创建我们自定义的元注释：`@Functional`，`@Security`，`@Usability`，`@Accessiblity`，`@Load`和`@Stress`。请注意，在每个注释中，我们使用一个或多个`@Tag`注释，具体取决于先前定义的结构。首先，我们可以看到`@Functional`的声明：

```java
package io.github.bonigarcia;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.junit.jupiter.api.Tag;

@Target({ ElementType.***TYPE**, ElementType.**METHOD** })* @Retention(RetentionPolicy.***RUNTIME**)* @Tag("functional")
public @interface Functional {
}
```

然后，我们使用标签`non-functional`和`security`定义注释`@Security`：

```java
package io.github.bonigarcia;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.junit.jupiter.api.Tag;

@Target({ ElementType.***TYPE**, ElementType.**METHOD** })* @Retention(RetentionPolicy.***RUNTIME**)* @Tag("non-functional")
@Tag("security")
public @interface Security {
}
```

同样，我们定义注释`@Load`，但这次标记为`non-functional`，`performance`和`load`：

```java
package io.github.bonigarcia;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.junit.jupiter.api.Tag;

@Target({ ElementType.***TYPE**, ElementType.**METHOD** })* @Retention(RetentionPolicy.***RUNTIME**)* @Tag("non-functional")
@Tag("performance")
@Tag("load")
public @interface Load {
}
```

最后，我们创建注释`@Stress`（带有标签`non-functional`，`performance`和`stress`）：

```java
package io.github.bonigarcia;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.junit.jupiter.api.Tag;

@Target({ ElementType.***TYPE**, ElementType.**METHOD** })* @Retention(RetentionPolicy.***RUNTIME**)* @Tag("non-functional")
@Tag("performance")
@Tag("stress")
public @interface Stress {
}
```

现在，我们可以使用我们的注释来标记（以及稍后过滤）测试。例如，在以下示例中，我们在类级别使用注释`@Functional`：

```java
package io.github.bonigarcia;

import org.junit.jupiter.api.Test;

@Functional
class FunctionalTest {

      @Test
      void testOne() {
            System.*out*.println("Test 1");
      }

      @Test
      void testTwo() {
            System.*out*.println("Test 2");
      }

}
```

我们还可以在方法级别使用注释。在以下测试中，我们使用不同的注释（`@Load`，`@Stress`，`@Security`和`@Accessibility`）对不同的测试（方法）进行注释：

```java
package io.github.bonigarcia;

import org.junit.jupiter.api.Test;

class NonFunctionalTest {

    @Test
    @Load
    void testOne() {
        System.*out*.println("Test 1");
    }

    @Test
    @Stress
    void testTwo() {
        System.*out*.println("Test 2");
    }

    @Test
    @Security
    void testThree() {
        System.*out*.println("Test 3");
    }

    @Test
    @Usability
    void testFour() {
        System.*out*.println("Test 4");    }

}
```

总之，我们可以通过简单地更改包含的标签来过滤测试。一方面，我们可以按标签`functional`进行过滤。请注意，在这种情况下，只有两个测试被执行。以下代码片段显示了使用 Maven 进行此类过滤的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00055.gif)

使用 Maven 和命令行按标签（功能）过滤测试

另一方面，我们也可以使用不同的标签进行过滤，例如`non-functional`。以下图片显示了这种类型的过滤示例，这次使用 Gradle。和往常一样，我们可以通过分叉 GitHub 存储库（[`github.com/bonigarcia/mastering-junit5`](https://github.com/bonigarcia/mastering-junit5)）来玩这些示例：

>![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00056.gif)

使用 Gradle 和命令行按标签（非功能）过滤测试

# 条件测试执行

为了为测试执行建立自定义条件，我们需要使用 JUnit 5 扩展模型（在第二章中介绍，*JUnit 5 的新功能*，在*JUnit 5 的扩展模型*部分引入）。具体来说，我们需要使用名为`ExecutionCondition`的条件扩展点。此扩展可以用于停用类中的所有测试或单个测试。

我们将看到一个工作示例，其中我们创建一个自定义注释来基于操作系统禁用测试。首先，我们创建一个自定义实用枚举来选择一个操作系统（`WINDOWS`，`MAC`，`LINUX`和`OTHER`）：

```java
package io.github.bonigarcia;

public enum Os {
    ***WINDOWS***, ***MAC***, ***LINUX***, ***OTHER***;

    public static Os determine() {
        Os out = ***OTHER***;
        String myOs = System.*getProperty*("os.name").toLowerCase();
        if (myOs.contains("win")) {
            out = ***WINDOWS***;
        } 
        else if (myOs.contains("mac")) {
            out = ***MAC***;
        } 
        else if (myOs.contains("nux")) {
            out = ***LINUX***;
        }
        return out;
    }
}
```

然后，我们创建`ExecutionCondition`的扩展。在这个例子中，通过检查自定义注释`@DisabledOnOs`是否存在来进行评估。当存在注释`@DisabledOnOs`时，操作系统的值将与当前平台进行比较。根据该条件的结果，测试将被禁用或启用。

```java
package io.github.bonigarcia;

import java.lang.reflect.AnnotatedElement;
import java.util.Arrays;
import java.util.Optional;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.platform.commons.util.AnnotationUtils;

public class OsCondition implements ExecutionCondition {

    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(
            ExtensionContext context) {
          Optional<AnnotatedElement> element = context.getElement();
          ConditionEvaluationResult out = ConditionEvaluationResult
                .*enabled*("@DisabledOnOs is not present");
          Optional<DisabledOnOs> disabledOnOs = AnnotationUtils
                .*findAnnotation*(element, DisabledOnOs.class);
          if (disabledOnOs.isPresent()) {
             Os myOs = Os.*determine*();
             if(Arrays.asList(disabledOnOs.get().value())
                 .contains(myOs)) {
             out = ConditionEvaluationResult
               .*disabled*("Test is disabled on " + myOs);
             } 
 else {
               out = ConditionEvaluationResult
                .*enabled*("Test is not disabled on " + myOs);
             }
           }
           System.*out*.println("--> " + out.getReason().get());
           return out;
    }

}
```

此外，我们需要创建我们的自定义注释`@DisabledOnOs`，该注释也使用`@ExtendWith`进行注释，指向我们的扩展点。

```java
package io.github.bonigarcia;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.junit.jupiter.api.extension.ExtendWith;

@Target({ ElementType.*TYPE*, ElementType.*METHOD* })
@Retention(RetentionPolicy.*RUNTIME*)
@ExtendWith(OsCondition.class)
public @interface DisabledOnOs {
    Os[] value();
}
```

最后，我们在 Jupiter 测试中使用我们的注释`@DisabledOnOs`。

```java
import org.junit.jupiter.api.Test;

import static io.github.bonigarcia.Os.*MAC*;
import static io.github.bonigarcia.Os.*LINUX*;

class DisabledOnOsTest {

    @DisabledOnOs({ *MAC*, *LINUX* })
    @Test
    void conditionalTest() {
        System.*out*.println("This test will be disabled on MAC and LINUX");
    }

}
```

如果我们在 Windows 机器上执行此测试，则测试不会被跳过，如下面的快照所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00057.gif)

条件测试示例的执行

# 假设

在本节的这一部分是关于所谓的假设。假设允许我们仅在某些条件符合预期时运行测试。所有 JUnit Jupiter 假设都是位于`org.junit.jupiter`包内的`Assumptions`类中的静态方法。以下截图显示了该类的所有方法：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00058.jpeg)

*org.junit.jupiter.Assumptions*类的方法

一方面，`assumeTrue`和`assumeFalse`方法可用于跳过未满足前提条件的测试。另一方面，`assumingThat`方法用于条件测试中的一部分的执行：

```java
package io.github.bonigarcia;

import static org.junit.jupiter.api.Assertions.*fail*;
import static org.junit.jupiter.api.Assumptions.*assumeFalse*;
import static org.junit.jupiter.api.Assumptions.*assumeTrue*;
import static org.junit.jupiter.api.Assumptions.*assumingThat*;

import org.junit.jupiter.api.Test;

class AssumptionsTest {

    @Test
    void assumeTrueTest() {
        *assumeTrue*(false);
        *fail*("Test 1 failed");
    }

    @Test
    void assumeFalseTest() {
        *assumeFalse*(this::getTrue);
        *fail*("Test 2 failed");
    }

    private boolean getTrue() {
        return true;
    }

    @Test
    void assummingThatTest() {
        *assumingThat*(false, () -> *fail*("Test 3 failed"));
    }

}
```

请注意，在这个示例中，前两个测试（`assumeTrueTest`和`assumeFalseTest`）由于假设条件不满足而被跳过。然而，在`assummingThatTest`测试中，只有测试的这一部分（在这种情况下是一个 lambda 表达式）没有被执行，但整个测试并没有被跳过：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00059.gif)

假设测试示例的执行

# 嵌套测试

嵌套测试使测试编写者能够更多地表达一组测试中的关系和顺序。JUnit 5 使得嵌套测试类变得轻而易举。我们只需要用`@Nested`注解内部类，其中的所有测试方法也将被执行，从顶级类中定义的常规测试到每个内部类中定义的测试。

我们需要考虑的第一件事是，只有非静态嵌套类（即内部类）才能作为`@Nested`测试。嵌套可以任意深入，并且每个测试的设置和拆卸（即`@BeforeEach`和`@AfterEach`方法）都会在嵌套测试中继承。然而，内部类不能定义`@BeforeAll`和`@AfterAll`方法，因为 Java 不允许内部类中有静态成员。然而，可以使用`@TestInstance(Lifecycle.PER_CLASS)`注解在测试类中避免这种限制。正如本章节中的*测试实例生命周期*部分所描述的，该注解强制每个类实例化一个测试实例，而不是每个方法实例化一个测试实例（默认行为）。这样，`@BeforeAll`和`@AfterAll`方法就不需要是静态的，因此可以在嵌套测试中使用。

让我们看一个由一个 Java 类组成的简单示例，该类有两个级别的内部类，即，该类包含两个嵌套的内部类，这些内部类带有`@Nested`注解。正如我们所看到的，该类的三个级别都有测试。请注意，顶级类定义了一个设置方法（`@BeforeEach`），并且第一个嵌套类（在示例中称为`InnerClass1`）也是如此。在顶级类中，我们定义了一个单一的测试（称为`topTest`），并且在每个嵌套类中，我们找到另一个测试（分别称为`innerTest1`和`innerTest2`）：

```java
package io.github.bonigarcia;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class NestTest {

    @BeforeEach
    void setup1() {
        System.*out*.println("Setup 1");
    }

    @Test
    void topTest() {
       System.*out*.println("Test 1");
    }

    @Nested
    class InnerClass1 {

        @BeforeEach
        void setup2() {
            System.*out*.println("Setup 2");
        }

        @Test
        void innerTest1() {
            System.*out*.println("Test 2");
        }

        @Nested
        class InnerClass2 {

            @Test
 void innerTest2() {
                System.*out*.println("Test 3");
            }
        } 
    }

}
```

如果我们执行这个示例，我们可以通过简单地查看控制台跟踪来追踪嵌套测试的执行。请注意，顶级`@BeforeEach`方法（称为`setup1`）总是在每个测试之前执行。因此，在实际测试执行之前，控制台中始终存在`Setup 1`的跟踪。每个测试也会在控制台上写一行。正如我们所看到的，第一个测试记录了`Test 1`。之后，执行了内部类中定义的测试。第一个内部类执行了测试`innerTest1`，但在此之后，顶级类和第一个内部类的设置方法被执行（分别记录了`Setup 1`和`Setup 2`）。

最后，执行了最后一个内部类中定义的测试（`innerTest2`），但通常情况下，在测试之前会执行一系列的设置方法：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00060.gif)

嵌套测试示例的控制台输出

嵌套测试可以与显示名称（即注解`@DisplayName`）一起使用，以帮助生成易读的测试输出。以下示例演示了如何使用。这个类包含了测试栈实现的结构，即*后进先出*（LIFO）集合。该类首先设计了在栈刚实例化时进行测试（方法`isInstantiatedWithNew`）。之后，第一个内部类（`WhenNew`）应该测试栈作为空集合（方法`isEmpty`，`throwsExceptionWhenPopped`和`throwsExceptionWhenPeeked`）。最后，第二个内部类应该测试栈不为空时的情况（方法`isNotEmpty`，`returnElementWhenPopped`和`returnElementWhenPeeked`）：

```java
package io.github.bonigarcia;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("A stack test")

 class StackTest {

     @Test
     @DisplayName("is instantiated")
     void isInstantiated() {
     }

     @Nested
     @DisplayName("when empty")
     class WhenNew {

         @Test
         @DisplayName("is empty")
         void isEmpty() {
         }

         @Test
         @DisplayName("throws Exception when popped")
         void throwsExceptionWhenPopped() {
         }

         @Test
         @DisplayName("throws Exception when peeked")
         void throwsExceptionWhenPeeked() {
         }

         @Nested
         @DisplayName("after pushing an element")
         class AfterPushing {

             @Test
             @DisplayName("it is no longer empty")
             void isNotEmpty() {
             }

             @Test
             @DisplayName("returns the element when popped")
             void returnElementWhenPopped() {
             }

             @Test
             @DisplayName("returns the element when peeked")
             void returnElementWhenPeeked() {
             }

         }
     }
 }
```

这种类型的测试的目的是双重的。一方面，类结构为测试的执行提供了顺序。另一方面，使用`@DisplayName`提高了测试执行的可读性。我们可以看到，当测试在 IDE 中执行时，特别是在 IntelliJ IDEA 中。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00061.jpeg)

在 Intellij IDEA 上使用*@DisplayName*执行嵌套测试

# 重复测试

JUnit Jupiter 提供了通过简单地使用`@RepeatedTest`方法对测试进行指定次数的重复的能力，指定所需的总重复次数。每次重复的测试行为与常规的`@Test`方法完全相同。此外，每次重复的测试都保留相同的生命周期回调（`@BeforeEach`，`@AfterEach`等）。

以下 Java 类包含一个将重复五次的测试：

```java
package io.github.bonigarcia;

import org.junit.jupiter.api.RepeatedTest;

class SimpleRepeatedTest {

    @RepeatedTest(5)
    void test() {
        System.*out*.println("Repeated test");
    }

}
```

由于这个测试只在标准输出中写了一行（`Repeated test`），当在控制台中执行这个测试时，我们会看到这个迹象出现五次：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00062.gif)

在控制台中执行重复测试

除了指定重复次数外，还可以通过`@RepeatedTest`注解的 name 属性为每次重复配置自定义显示名称。显示名称可以是由静态文本和动态占位符组成的模式。目前支持以下内容：

+   `{displayName}`：这是`@RepeatedTest`方法的名称。

+   `{currentRepetition}`：这是当前的重复次数。

+   `{totalRepetitions}`：这是总的重复次数。

以下示例显示了一个类，其中有三个重复测试，其中显示名称使用了`@RepeatedTest`的属性名称：

```java
package io.github.bonigarcia;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.TestInfo;

class TunningDisplayInRepeatedTest {

    @RepeatedTest(value = 2, name = "{displayName} 
    {currentRepetition}/{totalRepetitions}")
    @DisplayName("Repeat!")
    void customDisplayName(TestInfo testInfo) {
        System.*out*.println(testInfo.getDisplayName());
    }

    @RepeatedTest(value = 2, name = RepeatedTest.*LONG_DISPLAY_NAME*)
    @DisplayName("Test using long display name")
    void customDisplayNameWithLongPattern(TestInfo testInfo) {
        System.*out*.println(testInfo.getDisplayName());
    }

    @RepeatedTest(value = 2, name = RepeatedTest.*SHORT_DISPLAY_NAME*)
    @DisplayName("Test using short display name")
    void customDisplayNameWithShortPattern(TestInfo testInfo) {
        System.*out*.println(testInfo.getDisplayName());
    }

}
```

在这个测试中，这些重复测试的显示名称将如下所示：

+   对于测试`customDisplayName`，显示名称将遵循长显示格式：

+   `重复 1 次，共 2 次`。

+   `重复 2 次，共 2 次`。

+   对于测试`customDisplayNameWithLongPattern`，显示名称将遵循长显示格式：

+   `重复！1/2`。

+   `重复！2/2`。

+   对于测试`customDisplayNameWithShortPattern`，此测试中的显示名称将遵循短显示格式：

+   `使用长显示名称的测试::重复 1 次，共 2 次`。

+   `使用长显示名称的测试::重复 2 次，共 2 次`。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00063.gif)

在与*@DisplayName*结合使用的重复测试示例中执行

# 从 JUnit 4 迁移到 JUnit 5

JUnit 5 不支持 JUnit 4 的功能，比如规则和运行器。然而，JUnit 5 通过 JUnit Vintage 测试引擎提供了一个渐进的迁移路径，允许我们在 JUnit 平台上执行传统的测试用例（包括 JUnit 4 和 JUnit 3）。

以下表格可用于总结 JUnit 4 和 5 之间的主要区别：

| **功能** | **JUnit 4** | **JUnit 5** |
| --- | --- | --- |
| 注解包 | `org.junit` | `org.junit.jupiter.api` |
| 声明测试 | `@Test` | `@Test` |
| 所有测试的设置 | `@BeforeClass` | `@BeforeAll` |
| 每个测试的设置 | `@Before` | `@BeforeEach` |
| 每个测试的拆卸 | `@After` | `@AfterEach` |
| 所有测试的拆卸 | `@AfterClass` | `@AfterAll` |
| 标记和过滤 | `@Category` | `@Tag` |
| 禁用测试方法或类 | `@Ignore` | `@Disabled` |
| 嵌套测试 | 不适用 | `@Nested` |
| 重复测试 | 使用自定义规则 | `@Repeated` |
| 动态测试 | 不适用 | `@TestFactory` |
| 测试模板 | 不适用 | `@TestTemaplate` |
| 运行器 | `@RunWith` | 此功能已被扩展模型 (`@ExtendWith`) 取代 |
| 规则 | `@Rule` 和 `@ClassRule` | 此功能已被扩展模型 (`@ExtendWith`) 取代 |

# Jupiter 中的规则支持

如前所述，Jupiter 不原生支持 JUnit 4 规则。然而，JUnit 5 团队意识到 JUnit 4 规则如今在许多测试代码库中被广泛采用。为了实现从 JUnit 4 到 JUnit 5 的无缝迁移，JUnit 5 团队实现了 `junit-jupiter-migrationsupport` 模块。如果要在项目中使用这个模块，应该导入模块依赖。Maven 的示例在这里：

```java
<dependency>
   <groupId>org.junit.jupiter</groupId>
   <artifactId>junit-jupiter-migrationsupport</artifactId>
   <version>${junit.jupiter.version}</version>
   <scope>test</scope>
</dependency>
```

这个依赖的 Gradle 声明是这样的：

```java
dependencies {
      testCompile("org.junit.jupiter:junit-jupiter-
      migrationsupport:${junitJupiterVersion}")
}
```

JUnit 5 中的规则支持仅限于与 Jupiter 扩展模型在语义上兼容的规则，包括以下规则：

+   `junit.rules.ExternalResource` (包括 `org.junit.rules.TemporaryFolder`)。

+   `junit.rules.Verifier` (包括 `org.junit.rules.ErrorCollector`)。

+   `junit.rules.ExpectedException`。

为了在 Jupiter 测试中启用这些规则，测试类应该用类级别的注解 `@EnableRuleMigrationSupport` 进行注解（位于包 `org.junit.jupiter.migrationsupport.rules` 中）。让我们看几个例子。首先，以下测试用例在 Jupiter 测试中定义并使用了 `TemporaryFolder` JUnit 4 规则：

```java
package io.github.bonigarcia;

import java.io.IOException;
import org.junit.Rule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.migrationsupport.rules.EnableRuleMigrationSupport;
import org.junit.rules.TemporaryFolder;

@EnableRuleMigrationSupport
class TemporaryFolderRuleTest {

    @Rule
    TemporaryFolder temporaryFolder = new TemporaryFolder();

    @BeforeEach
    void setup() throws IOException {
        temporaryFolder.create();
    }

    @Test
    void test() {
        System.*out*.println("Temporary folder: " +         
            temporaryFolder.getRoot());
    }

    @AfterEach
    void teardown() {
        temporaryFolder.delete();
    }

}
```

在执行这个测试时，临时文件夹的路径将被记录在标准输出中：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00064.gif)

使用 JUnit 4 的 *TemporaryFolder* 规则执行 Jupiter 测试

以下测试演示了在 Jupiter 测试中使用 `ErrorCollector` 规则。请注意，收集器规则允许在发现一个或多个问题后继续执行测试：

```java
package io.github.bonigarcia;

import static org.hamcrest.CoreMatchers.equalTo;

import org.junit.Rule;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.migrationsupport.rules.EnableRuleMigrationSupport;
import org.junit.rules.ErrorCollector;

@EnableRuleMigrationSupport
class ErrorCollectorRuleTest {

    @Rule
    public ErrorCollector collector = new ErrorCollector();

    @Test
    void test() {
        collector.checkThat("a", *equalTo*("b"));
        collector.checkThat(1, *equalTo*(2));
        collector.checkThat("c", *equalTo*("c"));
    }

}
```

这些问题将在测试结束时一起报告：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00065.gif)

使用 JUnit 4 的 *ErrorCollector* 规则执行 Jupiter 测试

最后，`ExpectedException` 规则允许我们配置测试以预期在测试逻辑中抛出给定的异常：

```java
package io.github.bonigarcia;

import org.junit.Rule;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.migrationsupport.rules.EnableRuleMigrationSupport;
import org.junit.rules.ExpectedException;

@EnableRuleMigrationSupport
class ExpectedExceptionRuleTest {

    @Rule
    ExpectedException thrown = ExpectedException.*none*();

    @Test
    void throwsNothing() {
    }

    @Test
    void throwsNullPointerException() {
        thrown.expect(NullPointerException.class);
        throw new NullPointerException();
    }

}
```

在这个例子中，即使第二个测试引发了 `NullPointerException`，由于预期到了这个异常，测试将被标记为成功。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-sw-test-junit5/img/00066.gif)

使用 JUnit 4 的 *ExpectedException* 规则执行 Jupiter 测试

# 总结

在本章中，我们介绍了 JUnit 5 框架全新编程模型 Jupiter 的基础知识。这个编程模型提供了丰富的 API，可以被从业者用来创建测试用例。Jupiter 最基本的元素是注解 `@Test`，它标识 Java 类中作为测试的方法（即对 SUT 进行测试和验证的逻辑）。此外，还有不同的注解可以用来控制测试生命周期，即 `@BeforeAll`、`@BeforeEach`、`@AfterEach` 和 `@AfterAll`。其他有用的 Jupiter 注解包括 `@Disabled`（跳过测试）、`@DisplayName`（提供测试名称）、`@Tag`（标记和过滤测试）。

Jupiter 提供了丰富的断言集，这些断言是 `Assertions` 类中的静态方法，用于验证从 SUT 获取的结果是否与某个预期值相对应。我们可以通过多种方式对测试执行施加条件。一方面，我们可以使用 `Assumptions` 仅在某些条件符合预期时运行测试（或其中的一部分）。

我们已经学习了如何使用`@Nested`注解简单地创建嵌套测试，这可以用来按照嵌套类的关系顺序执行测试。我们还学习了使用 JUnit 5 编程模型创建重复测试的简便方法。`@RepeatedTest`注解用于此目的，可以重复执行指定次数的测试。最后，我们看到 Jupiter 为几个传统的 JUnit 4 测试规则提供了支持，包括`ExternalResource`、`Verifier`和`ExpectedException`。

在第四章中，*使用高级 JUnit 功能简化测试*，我们继续探索 JUnit 编程模型。具体来说，我们回顾了 JUnit 5 的高级功能，包括依赖注入、动态测试、测试接口、测试模板、参数化测试、JUnit 5 与 Java 9 的兼容性。最后，我们回顾了 JUnit 5.1 中计划的一些功能，这些功能在撰写本文时尚未实现。
