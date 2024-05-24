# ExtJS 和 Spring 企业应用开发（一）

> 原文：[`zh.annas-archive.org/md5/84CE5C4C4F19D0840640A27766EB042A`](https://zh.annas-archive.org/md5/84CE5C4C4F19D0840640A27766EB042A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

企业应用程序开发是一种在这个快节奏的技术世界中很少被承认的艺术形式。本书描述了使用两种最流行的技术——Spring 框架和 Sencha Ext JS——简化大规模开发项目的模式和策略。每一章都定义并构建了企业应用程序堆栈中的一个简洁层，压缩了多年开发实际项目所获得的 Web 开发方法。我们涵盖了相当广泛的概念领域，所以准备好迎接一个有趣的旅程！

本书不是 Java、JavaScript 或任何 Web 开发概念的介绍。书中包含大量实际的 Java 和 JavaScript 代码，因此需要对这些技术有一定的了解。如果你对 Java 和相关概念如面向对象编程不熟悉，那么在跟随示例和解释时可能会感到困难。同样适用于 Ext JS 开发；你需要对基本概念有一定的经验，包括框架 API，才能跟随大多数示例。

你不需要成为专家，但初学者可能希望从其他地方开始他们的旅程。

无论您的经验和背景如何，本书提供的实际示例都是以彻底覆盖每个概念为目标，然后再进入下一章。

# 本书涵盖的内容

第一章，“准备开发环境”，讨论了开发环境的安装和配置，包括 Java 开发工具包、NetBeans 和 MySQL。我们还将介绍 Maven，创建一个新的 NetBeans 项目，并将项目部署到 GlassFish 4 应用服务器。

第二章，“任务时间跟踪数据库”，定义了任务时间跟踪（3T）数据库设计，并帮助配置 NetBeans 作为 MySQL 服务器的客户端。我们创建和填充所有表，并确定可能适用于企业使用的可能增强功能。

第三章，“使用 JPA 反向工程领域层”，帮助我们使用 NetBeans IDE 对 3T 数据库进行反向工程，创建 JPA 实体的领域层。在我们检查和定义核心 JPA 概念时，这些实体将被探讨和重构。

第四章，“数据访问变得容易”，介绍了数据访问对象（DAO）设计模式，并帮助使用我们在上一章中定义的领域类实现健壮的数据访问层。还介绍了 Java 泛型和接口、简单日志门面（SLF4J）、JPA EntityManager 和事务语义。

第五章，“使用 Spring 和 JUnit 测试 DAO 层”，介绍了 JUnit 测试环境的配置以及为我们的 DAO 实现开发测试用例。我们介绍了 Spring 控制反转（IoC）容器，并探讨了 Spring 配置以将 Spring 管理的 JUnit 测试与 Maven 集成。

第六章，“回到业务-服务层”，探讨了企业应用程序开发中服务层的作用。然后，我们通过数据传输对象（DTO）设计模式使用值对象（VO）来实现我们的 3T 业务逻辑。我们还探讨了在编写实现之前编写测试用例——这是测试驱动开发和极限编程的核心原则。

第七章，“网络请求处理层”，为生成 JSON 数据的 Web 客户端定义了一个请求处理层，该层使用 Java EE 7 中引入的新 API——Java API for JSON processing。我们实现了轻量级的 Spring 控制器，介绍了 Spring 处理程序拦截器，并使用 Java 类配置了 Spring MVC。

第八章，“在 GlassFish 上运行 3T”，完成了我们的 Spring 配置，并允许我们将 3T 应用程序部署到 GlassFish 4 服务器。我们还配置 GlassFish 4 服务器，使其能够独立于 NetBeans IDE 运行，就像在企业环境中一样。

第九章，“开始使用 Ext JS 4”，介绍了强大的 Ext JS 4 框架，并讨论了核心的 Ext JS 4 MVC 概念和实际的设计约定。我们使用 Sencha Cmd 和 Ext JS 4 SDK 安装和配置我们的 Ext JS 开发环境，生成我们的 3T 应用程序框架。

第十章，“登录和用户维护”，帮助我们开发 3T 应用程序所需的 Ext JS 4 组件，并维护用户登录。我们将讨论 Ext JS 4 模型持久化，构建各种视图，审查应用程序概念，并开发两个 Ext JS 控制器。

第十一章，“构建任务日志用户界面”，继续加强我们对 Ext JS 4 组件的理解，同时实现任务日志用户界面。

第十二章，“3T 管理变得更容易”，使我们能够开发 3T 管理界面，并介绍了 Ext JS 4 树组件。我们将研究动态树加载，并实现拖放树操作。

第十三章，“将您的应用程序部署到生产环境”，将帮助我们准备、构建和部署我们的 3T 项目到 GlassFish 服务器。我们介绍了 Ext JS 主题化，将 Sencha Cmd 编译与 Maven 集成，自动化生成 Ext JS 4 app-all.js 文件的过程，并学习如何将我们的生产版本部署到 GlassFish 服务器上。

附录，“介绍 Spring Data JPA”，对 Spring Data JPA 进行了非常简要的介绍，作为第四章，“数据访问变得更容易”中讨论的实现的替代方案。

# 本书所需内容

本书中的示例可以在支持以下软件的任何 Windows、Mac 或 Linux 平台上运行：

+   Java 开发工具包（JDK）1.7

+   NetBeans 7.4+

+   MySQL 5+

+   Sencha Cmd

所有软件都可以在相应章节中列出的网站免费下载。

# 本书适合对象

本书特别适用于从事大型 Web 应用程序开发项目的人员，包括应用架构师、Java 开发人员和 Ext JS 开发人员。

## 应用架构师

架构师从技术角度理解全局图景，并负责制定开发标准的蓝图。本书将向您介绍 Spring Framework 和 Sencha Ext JS 的强大功能，以及在设计下一个项目时如何最好地利用这些技术。

## Java 开发人员

无论您的理解水平如何，您都将学习 Spring 框架如何鼓励良好的编程实践。这包括一个清晰的、分层的结构，易于增强和维护。对于 Spring 的新手来说，他们会惊讶于实现重大结果所需的努力是多么少。对于新手和有经验的 Spring 开发人员，重点将是企业 Web 开发的最佳实践，以实现与 Sencha Ext JS 客户端的无缝集成。如果您从未使用过 Sencha Ext JS，您会惊讶于强大的 UI 可以多快地将后端数据栩栩如生。

## Ext JS 开发人员

Sencha Ext JS 是一个强大的框架，用于构建跨浏览器兼容的企业应用程序。本书将从分析到提供完全功能的解决方案解决现实世界的问题。您将看到通常隐藏在 Ext JS 开发人员背后的许多开发阶段；您还将了解为客户端消费而生成 JSON 数据所需的步骤。关注 Ext JS 组件的章节将介绍基于最新 MVC 设计模式的可维护开发的简单策略。

# 约定

在本书中，您将找到一些区分不同类型信息的文本样式。以下是这些样式的一些示例，以及它们的含义解释。

文本中的代码单词、文件夹名称、文件名、文件扩展名、路径名、虚拟 URL 和用户输入显示如下：“`ManageTaskLogs`的定义如下：”

代码块设置如下：

```java
Ext.define('TTT.store.Task', {
    extend: 'Ext.data.Store',
    requires: ['TTT.model.Task'],
    model: 'TTT.model.Task',
    proxy: {
        type: 'ajax',
        url:'task/findAll.json',
        reader: {
            type: 'json',
            root: 'data'
        }
    }    
});
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```java
controllers: [
  'MainController',
  'UserController',
  'TaskLogController'
],
models: [
  'User',
  'Project',
 'Task',
 'TaskLog'
],
stores: [
  'User',
  'Project',
 'Task',
 'TaskLog'
]
```

任何命令行输入或输出都以以下方式编写：

```java
sencha –sdk ext compile -classpath=app page -yui -in index.html -out build/index.html

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“如果存在，添加新的任务日志将保留当前选择的**日期**和**项目**：”。

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：准备您的开发环境

本章将安装和配置您的开发环境。**快速应用开发**（**RAD**）工具是**NetBeans**，这是一个开源的、跨平台的**集成开发环境**（**IDE**），可用于创建视觉桌面、移动、Web 和**面向服务的体系结构**（**SOA**）应用程序。NetBeans 官方支持 Java、PHP、JavaScript 和 C/C++编程语言，但它以为所有最新的**Java 企业版**（**Java EE**）标准提供了完整的工具集而闻名（目前是 Java EE 7）。

本书选择的数据库是 MySQL，这是世界上最广泛使用的开源**关系数据库管理系统**（**RDBMS**）。MySQL 是 Linux 平台上托管的 Web 应用程序的最受欢迎的数据库选择，并且在多种应用程序中继续提供出色的性能。其小巧的占用空间和易用性使其非常适合在单台计算机上进行开发使用。

本书中使用的应用服务器是**GlassFish 4**，它与 NetBeans 捆绑在一起。GlassFish 作为 NetBeans 安装的一部分进行安装，两者之间的紧密集成使得配置 GlassFish 变得简单。GlassFish 是一个开源的、生产级的应用服务器，实现了所有的 Java EE 7 特性。它具有企业级的可靠性，并被许多人认为是最好的开源应用服务器。GlassFish 4 是 Java EE 7 规范的**参考实现**（**RI**），完整的描述可以在[`glassfish.java.net/downloads/ri/`](https://glassfish.java.net/downloads/ri/)找到。

所有这些开发工具都可以免费在 PC、Mac 和 Linux 上使用。每个工具都有大量的示例、全面的教程和在线支持论坛可供使用。

需要注意的是，尽管本章重点介绍了 NetBeans、MySQL 和 GlassFish，但读者可以根据自己熟悉的工具配置任何合适的组合。本书中概述的开发任务同样可以使用 Eclipse、Oracle 和 JBoss 来完成，尽管一些描述的配置细节可能需要进行微小的修改。

在本章中，我们将执行以下任务：

+   安装 MySQL 数据库服务器

+   安装 Java SDK

+   安装和配置 NetBeans IDE

+   创建应用项目并探索 Maven

+   在 GlassFish 中运行项目

# 安装 MySQL

MySQL 可以从[`www.mysql.com/downloads/mysql`](http://www.mysql.com/downloads/mysql)下载。选择适合您操作系统和架构的 MySQL 社区服务器。重要的是要遵循说明，注意安装目录和路径以备将来参考。下载并运行安装文件后，您应该选择本书的**开发者默认**安装。

![安装 MySQL](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_01_01.jpg)

除非您熟悉 MySQL，否则最好选择默认设置。这将包括将默认端口设置为`3306`，启用 TCP/IP 网络，并打开所需的防火墙端口以进行网络访问（在所有应用程序都在同一环境上运行的开发机器上并不是严格要求的，但如果您正在配置专用的 MySQL 服务器，则是必需的）。

无论环境如何，在安装过程中设置 root 用户密码是很重要的。我们将使用 root 用户连接到运行的 MySQL 服务器来执行命令。

![安装 MySQL](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_01_02.jpg)

### 注意

本书的其余部分将假定 root 用户的密码为`adminadmin`。这不是一个非常安全的密码，但应该很容易记住！

我们建议将 MySQL 服务器配置为在操作系统启动时启动。如何完成此操作将取决于您的环境，但通常是在“初始配置”操作的最后执行的。Windows 用户将有选项在系统启动时启动 MySQL 服务器。Mac 用户需要在安装服务器后安装**MySQL 启动项**。

如果您决定不在操作系统启动时启动 MySQL，则需要在需要时手动启动 MySQL 服务器。如何完成此操作将再次取决于您的环境，但您现在应该启动服务器以确认安装成功。

### 注意

Unix 和 Linux 用户需要根据其操作系统安装 MySQL。这可能包括使用高级包装工具（APT）或另一个安装工具（YaST），甚至从源代码安装 MySQL。有关各种操作系统的详细说明，请参见[`dev.mysql.com/doc/refman/5.7/en/installing.html`](http://dev.mysql.com/doc/refman/5.7/en/installing.html)。

在配置过程结束时，您将拥有一个运行的 MySQL 服务器，可以在第二章中使用，*任务时间跟踪器数据库*。

# 安装 Java SE 开发工具包（JDK）

可以从[`www.oracle.com/technetwork/java/javase/downloads/index.html`](http://www.oracle.com/technetwork/java/javase/downloads/index.html)下载 Java SE 开发工具包（JDK）。如果您的系统已安装了 JDK 7 Update 45（或更高版本），则可以选择跳过此步骤。

### 注意

不要选择 NetBeans 捆绑包，因为它不包含 GlassFish 服务器。

![安装 Java SE 开发工具包（JDK）](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_01_03.jpg)

在选择适当的发行版之前，您需要接受 JDK 7 许可协议。下载 JDK 后，运行安装程序并按照说明和提示操作。

# 安装 NetBeans IDE

NetBeans 可以从[`netbeans.org/downloads/`](https://netbeans.org/downloads/)下载。该发行版要求在您的平台上已安装有效的 JDK。在撰写本文时，我使用了 JDK 7 Update 45，但任何 JDK 7（或更高版本）都可以。有几个发行版捆绑包；您需要选择**Java EE**捆绑包。

![安装 NetBeans IDE](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_01_04.jpg)

撰写本文时的最新版本是 NetBeans 7.4，引入了重要的新功能，包括扩展的 HTML5 和 JavaScript 支持。首次，NetBeans 还包括对 Ext JS 框架的编辑和代码完成支持。

要安装软件，只需从 NetBeans 网站下载并按照详细说明进行操作。这将带您通过以下一系列设置屏幕：

1.  GlassFish 4 服务器会自动选择。您无需安装 Tomcat。

1.  接受许可协议中的条款。

1.  接受 JUnit 许可协议的条款。JUnit 用于第五章中的测试，*使用 Spring 和 JUnit 测试 DAO 层*。

1.  注意 NetBeans IDE 的安装路径以备将来参考。选择先前安装的适当 JDK（如果系统上有多个 JDK）。

1.  注意 GlassFish 4 服务器的安装路径以备将来参考。

1.  最终屏幕总结了安装过程。在单击**安装**开始过程之前，请务必**检查更新**。

该过程可能需要几分钟，具体取决于您的平台和硬件。

安装完成后，您可以首次运行 NetBeans。如果您之前安装过 NetBeans 的版本，则可能会提示您**导入设置**。然后默认的开放屏幕将显示如下：

![安装 NetBeans IDE](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_01_06.jpg)

现在可以从菜单中打开最有用的面板：

+   **项目**：此面板是项目源的主要入口点。它显示了重要项目内容的逻辑视图，分组到适当的上下文中。

+   **文件**：此面板显示项目节点在文件系统上的实际文件结构。

+   **服务**：此面板显示您的运行时资源。它显示了重要的运行时资源的逻辑视图，如与 IDE 注册的服务器和数据库。

在这个阶段，前两个面板将是空的，但**服务**面板将有几个条目。打开**服务器**面板将显示安装的 GlassFish 4 服务器，如下截图所示：

![安装 NetBeans IDE](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_01_07.jpg)

# 介绍 Maven

Apache Maven 是一个用于构建和管理基于 Java 的项目的工具。它是一个开源项目，托管在[`maven.apache.org`](http://maven.apache.org)，并与 NetBeans IDE 捆绑在一起。Maven 简化了所有 Java 开发项目中常见的许多步骤，并提供了许多功能，包括以下内容：

+   提供约定优于配置。Maven 带有一系列预定义的目标，用于执行某些明确定义的任务，包括项目的编译、测试和打包。所有任务都通过单个配置文件`pom.xml`管理。

+   一致的编码结构和项目框架。每个 Maven 项目都具有相同的目录结构和源文件、测试文件、构建文件和项目资源的位置。这种共同的结构使我们能够轻松地了解项目。

+   一个一致的构建系统，具有许多插件，使常见任务变得容易。

+   作为构建过程的一部分执行测试的能力。

+   一个高度灵活和强大的依赖管理系统。这允许软件开发人员通过（外部或远程）Maven 仓库在互联网上发布信息和共享 Java 库。然后 Maven 会将这些库下载并在本地缓存，以供项目使用。

我们鼓励您访问 Maven 网站，探索其中提供的许多功能。NetBeans 将使用 Maven 来创建和管理 Web 应用程序项目。

# 创建 Maven Web 应用程序项目

NetBeans 项目封装了维护和开发应用程序所需的所有源代码和相关组件。从菜单中导航到**文件** | **新建项目**开始这个过程：

![创建 Maven Web 应用程序项目](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_01_08.jpg)

在**类别**列表中选择**Maven**，在**项目**列表中选择**Web 应用程序**，如前面的截图所示，然后选择**下一步**按钮。这将呈现给您项目配置屏幕，其中包括以下字段：

+   **项目名称**：这指定了项目在项目窗口中的显示名称。这个名称也用于创建项目文件夹，不能包含空格。

### 注意

我们的项目名为 Task Time Tracker。这个工具将允许用户管理不同项目的不同任务所花费的时间。项目名称字段是项目名称的小写、无空格的翻译：`task-time-tracker`。

+   **项目位置**：这指定了您想要存储项目元数据和源代码的文件系统根文件夹。我们通常会在驱动器的根级别创建一个特定于项目的文件夹，而不是将其深埋在 NetBeans 下的文件夹结构中。这样可以更容易地找到并将文件复制到项目中。

### 注意

Windows 用户应在`c:\projects`下创建一个项目文件夹。Mac 用户可以用`/Users/{username}/projects`替换这个位置，Unix 用户可以用`/home/{username}/projects`替换。本书的其余部分将在所有示例中引用这个位置为*项目文件夹*。

+   **项目文件夹**：项目文件夹是只读的，根据项目名称和项目位置生成。

+   **Artifact Id**：这是一个只读的 Maven 特定属性，用于标识项目，基于项目名称。

+   **Group Id**：这是另一个 Maven 属性，表示多个构件的顶级容器。它通常代表拥有项目的组织的**顶级域**（**TLD**）。

### 注意

项目的**Group Id**是`com.gieman`，作者的公司。

+   **版本**：这是另一个 Maven 属性，表示构件的版本。默认版本是**1.0-SNAPSHOT**，我们将其更改为`1.0`。随着项目的发展和发布新版本，Maven 将根据它们的版本跟踪不同的构建。

+   **包**：IDE 将根据此字段自动创建基于 Java 源包的结构。我们将使用包`com.gieman.tttracker`。

您现在应该已经输入了以下项目详细信息：

![创建 Maven Web 应用程序项目](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_01_09.jpg)

点击**下一步**按钮查看最终屏幕。在单击**完成**按钮之前，不要更改默认的 GlassFish Server 4.0 和 Java EE 7 设置。现在您将在**项目创建**输出选项卡中看到活动，因为项目正在创建和配置。打开**项目**和**文件**面板将允许您查看项目结构：

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

![创建 Maven Web 应用程序项目](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_01_10.jpg)

在任一选项卡中右键单击项目名称将允许您选择项目的**属性**。这将显示与项目相关的所有属性和路径，分别属于不同的类别：

![创建 Maven Web 应用程序项目](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_01_12.jpg)

您不需要在本书的其余部分更改这些属性。

## 理解 POM 和依赖管理

每个 Maven 项目在 NetBeans 项目的根级别都有一个`pom.xml`配置文件。点击**文件**视图，双击`pom.xml`文件以在编辑器中打开它：

![理解 POM 和依赖管理](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_01_13.jpg)

### 注意

您应该看到**导航器**窗口在左下角面板中打开。这显示了正在编辑的文件的大纲，在浏览大文件时非常有帮助。在**导航器**中双击节点将会将光标定位到编辑器中的适当行。

如果**导航器**窗口没有打开（或已关闭），您可以通过从菜单导航到**窗口** | **导航** | **导航器**来手动打开它。

**项目对象模型（POM）**完全定义了项目和所有必需的 Maven 属性和构建行为。`pom.xml`中只显示了一个依赖项：

```java
<dependencies>
  <dependency>
    <groupId>javax</groupId>
    <artifactId>javaee-web-api</artifactId>
    <version>7.0</version>
    <scope>provided</scope>
  </dependency>
</dependencies>
```

这个依赖项标识了项目构建所需的 Java EE 7。这个条目确保了完整的 Java EE 7 API 在任务时间跟踪项目中可用于 Java 编码。我们的项目还需要 Spring 框架，现在必须将其添加为额外的依赖项。在编辑器中输入时，将会出现自动补全帮助来确定正确的依赖项。在添加 Spring 框架的`groupId`和`artifactId`条目后，如下截图所示，按下*Ctrl* +空格键盘快捷键将打开以文本`spring`开头的`artifactId`的可用匹配条目：

![理解 POM 和依赖管理](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_01_14.jpg)

如果此自动完成列表不可用，可能是因为 Maven 仓库首次进行索引。在这种情况下，您将在编辑器底部看到以下截图：

![理解 POM 和依赖管理](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_01_24.jpg)

耐心等待几分钟，索引将完成，自动完成将变为可用。索引是从 Maven 仓库下载可用条目所必需的。

所需的 Spring 框架组件如下：

+   `spring-context`：这是 Spring 的依赖注入容器所需的中心构件

+   `spring-tx`：这是实现事务行为所需的事务管理抽象

+   `spring-context-support`：这些是各种应用程序上下文实用程序，包括 Ehcache、JavaMail、Quartz 和 FreeMarker 集成

+   `spring-jdbc`：这是 JDBC 数据访问库

+   `spring-orm`：这是用于 JPA 开发的**对象-关系映射**（**ORM**）集成

+   `spring-instrument`：用于类的编织

+   `spring-webmvc`：这是用于 Servlet 环境的**Spring 模型-视图-控制器**（**MVC**）

+   `spring-test`：这是用于使用 JUnit 测试 Spring 应用程序的支持

要使用最新的 Spring 发布版本（3.2.4）添加这些依赖项，需要对`pom.xml`文件进行以下添加：

```java
<dependency>
  <groupId>org.springframework</groupId>
  <artifactId>spring-context</artifactId>
  <version>3.2.4.RELEASE</version>
</dependency>
<dependency>
  <groupId>org.springframework</groupId>
  <artifactId>spring-context-support</artifactId>
  <version>3.2.4.RELEASE</version>
</dependency>
<dependency>
  <groupId>org.springframework</groupId>
  <artifactId>spring-tx</artifactId>
  <version>3.2.4.RELEASE</version>
</dependency>
<dependency>
  <groupId>org.springframework</groupId>
  <artifactId>spring-jdbc</artifactId>
  <version>3.2.4.RELEASE</version>
</dependency>
<dependency>
  <groupId>org.springframework</groupId>
  <artifactId>spring-orm</artifactId>
  <version>3.2.4.RELEASE</version>
</dependency>
<dependency>
  <groupId>org.springframework</groupId>
  <artifactId>spring-instrument</artifactId>
  <version>3.2.4.RELEASE</version>
</dependency>
<dependency>
  <groupId>org.springframework</groupId>
  <artifactId>spring-webmvc</artifactId>
  <version>3.2.4.RELEASE</version>
</dependency>
<dependency>
  <groupId>org.springframework</groupId>
  <artifactId>spring-test</artifactId>
  <version>3.2.4.RELEASE</version>
</dependency>
```

## 理解依赖范围

最后一个 Spring 框架依赖项仅在测试时才需要。我们可以通过添加`scope`属性并将其值设置为`test`来定义这一点。这告诉 Maven 该依赖项仅在运行构建的测试阶段时才需要，并且不需要部署。

```java
<dependency>
  <groupId>org.springframework</groupId>
  <artifactId>spring-test</artifactId>
  <version>3.2.4.RELEASE</version>
  <scope>test</scope>
</dependency>
```

NetBeans 自动生成的`javaee-web-api`依赖项的范围为`provided`。这意味着该依赖项不需要部署，并且由目标服务器提供。GlassFish 4 服务器本身是该依赖项的提供者。

如果没有包含`scope`属性，依赖的 JAR 将包含在最终构建中。这相当于提供`compile`范围的条目。因此，所有 Spring 框架依赖的 JAR 将包含在最终构建文件中。

有关 Maven 依赖机制和范围的详细解释，请参阅[`maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html`](http://maven.apache.org/guides/introduction/introduction-to-dependency-mechanism.html)。

## 定义 Maven 属性

在`pom.xml`中定义的 Spring 框架依赖项都具有相同的版本（3.2.4.RELEASE）。这种重复不理想，特别是当我们希望在以后升级到新版本时。需要在多个地方进行更改，每个 Spring 依赖项都需要更改一次。一个简单的解决方案是添加一个属性来保存发布版本值，如下所示：

```java
<properties>
<endorsed.dir>${project.build.directory}/endorsed</endorsed.dir>
<project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
<spring.version>3.2.4.RELEASE</spring.version>
</properties>
```

我们现在可以使用这个自定义属性`spring.version`来替换多个重复项，如下所示：

```java
<dependency>
<groupId>org.springframework</groupId>
  <artifactId>spring-context-support</artifactId>
  <version>${spring.version}</version>
</dependency>
```

然后在构建过程中，`${spring.version}`占位符将被替换为`properties`的值。

## 理解 Maven 构建插件

Maven 构建过程在适当的构建阶段执行每个定义的构建插件。可以在[`maven.apache.org/plugins/index.html`](http://maven.apache.org/plugins/index.html)找到构建插件的完整列表。我们将在后续章节中根据需要介绍插件，但现在我们对 NetBeans IDE 创建的默认插件感兴趣。

`maven-compiler-plugin`控制并执行 Java 源文件的编译。该插件允许您指定编译的`source`和`target` Java 版本，如下所示：

```java
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-compiler-plugin</artifactId>
  <version>3.1</version>
  <configuration>
    <source>1.7</source>
    <target>1.7</target>
    <compilerArguments>
      <endorseddirs>${endorsed.dir}</endorseddirs>
    </compilerArguments>
  </configuration>
</plugin>
```

在为旧的 Java 服务器编译项目时，可能需要将这些值更改为`1.6`。

`maven-war-plugin`为项目构建 WAR 文件，如下所示：

```java
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-war-plugin</artifactId>
  <version>2.3</version>
  <configuration>
    <failOnMissingWebXml>false</failOnMissingWebXml>
  </configuration>
</plugin>
```

默认生成的 WAR 文件名是`{artifactId}-{version}.war`，可以通过包含`warName`配置属性来更改。在最后一章中，我们将在为生产发布构建项目时向此插件添加属性。`maven-war-plugin`选项的完整列表可以在[`maven.apache.org/plugins/maven-war-plugin/war-mojo.html`](http://maven.apache.org/plugins/maven-war-plugin/war-mojo.html)找到。

`maven-dependency-plugin`将依赖的 JAR 文件复制到定义的输出目录，如下所示：

```java
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-dependency-plugin</artifactId>
  <version>2.6</version>
  <executions>
    <execution>
      <phase>validate</phase>
      <goals>
        <goal>copy</goal>
      </goals>
      <configuration>
        <outputDirectory>${endorsed.dir}</outputDirectory>
        <silent>true</silent>
        <artifactItems>
          <artifactItem>
            <groupId>javax</groupId>
            <artifactId>javaee-endorsed-api</artifactId>
            <version>7.0</version>
            <type>jar</type>
          </artifactItem>
        </artifactItems>
      </configuration>
    </execution>
  </executions>
</plugin>
```

这对于查看项目使用了哪些 JAR，并识别所需的传递依赖（依赖的依赖）非常有用。

我们将修改此插件，将项目的所有编译时依赖项复制到`${project.build.directory}`中的目录。这个特殊的构建目录位于项目的根文件夹下，名为`target`，是构建过程的目标目的地。更新后的条目现在如下所示：

```java
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-dependency-plugin</artifactId>
  <version>2.1</version>
  <executions>
    <execution>
      <id>copy-endorsed</id>
      <phase>validate</phase>
      <goals>
        <goal>copy</goal>
      </goals>
      <configuration>
        <outputDirectory>${endorsed.dir}</outputDirectory>
        <silent>true</silent>
        <artifactItems>
          <artifactItem>
            <groupId>javax</groupId>
            <artifactId>javaee-endorsed-api</artifactId>
            <version>7.0</version>
            <type>jar</type>
          </artifactItem>
        </artifactItems>
      </configuration>
    </execution> 
    <execution>
      <id>copy-all-dependencies</id>
      <phase>compile</phase>
      <goals>
        <goal>copy-dependencies</goal>
      </goals>
      <configuration>
        <outputDirectory>${project.build.directory}/lib
        </outputDirectory>
        <includeScope>compile</includeScope>
      </configuration> 
    </execution>
  </executions>
</plugin>
```

由于我们现在在单个插件中执行两个执行，每个执行都需要自己的`<id>`。第二个执行，ID 为`copy-all-dependencies`，将把所有依赖的 JAR（范围为`compile`）复制到`target/lib`目录中。

## 执行 Maven 构建

执行构建的最简单方法是单击工具栏中的**清理和构建项目**按钮。您还可以在**项目**选项卡中右键单击项目节点，然后从菜单中选择**清理和构建**。然后，构建过程将执行 POM 中定义的每个阶段，导致 Java 代码编译，依赖项解析（和复制），最后生成 WAR 文件。打开目标目录结构将显示构建结果，如下所示：

![执行 Maven 构建](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_01_15.jpg)

尽管我们还没有写一行代码，但生成的 WAR 文件`task-time-tracker-1.0.war`现在可以部署到 GlassFish 服务器上。

# 启动 GlassFish 4 服务器

打开**服务**选项卡并展开**服务器**节点将列出在 NetBeans 安装过程中安装的 GlassFish 服务器。您现在可以右键单击**GlassFish Server 4.0**节点，并选择**启动**，如下截图所示：

![启动 GlassFish 4 服务器](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_01_16.jpg)

**输出**面板现在应该在您的 NetBeans IDE 底部打开，并显示启动结果。选择**GlassFish Server 4.0**选项卡以查看详细信息。

![启动 GlassFish 4 服务器](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_01_17.jpg)

倒数第五行标识服务器已启动，并正在监听端口 8080，日志中写为 8,080：

**INFO: Grizzly Framework 2.3.1 started in: 16ms - bound to [/0.0.0.0:8,080]**

您现在可以打开您喜欢的浏览器，并查看页面`http://localhost:8080`。

### 注意

请注意，根据您的环境，可能有其他应用程序监听端口 8080。在这种情况下，您需要用 GlassFish 服务器输出中定义的正确端口替换 8080。

![启动 GlassFish 4 服务器](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_01_18.jpg)

您现在可以右键单击**GlassFish Server 4.0**节点，然后单击**停止**来停止服务器。

![启动 GlassFish 4 服务器](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_01_19.jpg)

# 运行 Task Time Tracker 项目

我们已经成功构建了项目；现在是时候在 GlassFish 中运行项目了。单击**运行**工具栏项以启动进程，如下所示：

![运行 Task Time Tracker 项目](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_01_20.jpg)

输出应该显示进程，首先构建项目，然后启动并部署到 GlassFish 服务器。最后一步将打开您的默认浏览器，并显示所有开发人员都喜爱的世界著名消息，如下截图所示：

![运行 Task Time Tracker 项目](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_01_21.jpg)

恭喜！您现在已配置了开发、构建和部署 Spring Java 项目的核心组件。最后一步是更改默认页面上的文本。打开`index.html`文件，如下面的截图所示：

![运行任务时间跟踪器项目](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_01_22.jpg)

将`<title>`更改为`任务时间跟踪器首页`，将`<h1>`文本更改为`欢迎来到任务时间跟踪器！`。保存页面并刷新浏览器以查看更改。

![运行任务时间跟踪器项目](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_01_23.jpg)

### 注意

在刷新浏览器后没有看到更新的文本更改？在某些情况下，首次部署到 GlassFish 后，刷新页面时可能看不到在`index.html`文件中所做的更改。重新启动您的 NetBeans IDE 应该可以解决问题，并确保随后的更改在保存任何项目资源时立即部署到 GlassFish。

# 总结

在本章中，我们介绍了本书中将使用的一些关键技术。您已经下载并安装了 MySQL 数据库服务器、JDK 和 NetBeans IDE。然后我们介绍了 Maven 以及它如何简化 Java 项目的构建和管理。最后，我们在不写一行代码的情况下将我们的骨架任务时间跟踪器项目部署到了 GlassFish。

尽管我们已将 Spring 框架添加到我们的项目中，但我们尚未深入了解它的用法。同样，我们还没有提到 Sencha Ext JS。请耐心等待，还有很多内容要介绍！下一章将介绍我们的任务时间跟踪器数据库表，并开始我们的开发之旅。


# 第二章：任务时间跟踪器数据库

本章定义了**任务时间跟踪器**（3T）数据库设计，并将 NetBeans 配置为 MySQL 服务器的客户端。

3T 应用程序将用于跟踪不同公司项目上花费的时间。主要实体包括：

+   公司：这是拥有零个或多个项目的实体。公司是独立的，可以独立存在（它没有外键）。

+   项目：这代表任务的分组。每个项目都属于一个公司，可以包含零个或多个任务。

+   任务：这些代表可能为项目承担的活动。一个任务属于一个项目。

+   用户：他们是承担任务的参与者。用户可以将花费的时间分配给不同的任务。

+   任务日志：这是用户在任务上花费的时间记录。花费的时间以分钟为单位存储。

这些实体定义导致了一个非常简单的数据库设计：

![任务时间跟踪器数据库](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_02_21.jpg)

我们将所有的 3T 表都以`ttt_`作为前缀。大型企业数据库可能包含数百个表，您很快就会欣赏到表名的前缀以将相关表分组。

# 用 NetBeans 连接 MySQL

在 NetBeans IDE 的**服务**选项卡中，导航到**数据库** | **驱动程序**。您会看到 NetBeans 带有几种不同的数据库驱动程序：

![用 NetBeans 连接 MySQL](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_02_01.jpg)

右键单击**数据库**节点，然后单击**注册 MySQL 服务器…**，如下面的屏幕截图所示：

![用 NetBeans 连接 MySQL](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_02_02.jpg)

对于 Windows 用户，这将打开一个具有默认设置的对话框。在上一章安装 MySQL 服务器时输入管理员密码，并勾选**记住密码**选项：

![用 NetBeans 连接 MySQL](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_02_03.jpg)

Mac 用户在设置连接属性之前会看到一个不同的窗口。在单击**下一步**按钮之前选择 MySQL 驱动程序：

![用 NetBeans 连接 MySQL](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_02_04.jpg)

然后，您可以指定所需的数据库连接详细信息：

![用 NetBeans 连接 MySQL](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_02_05.jpg)

完成这些任务后，您将在**数据库**节点中看到**MySQL 服务器**。右键单击服务器，然后选择**连接**以连接到服务器（如果尚未连接）：

![用 NetBeans 连接 MySQL](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_02_06.jpg)

这将连接 NetBeans 到 MySQL 服务器并列出可用的数据库。右键单击服务器，然后选择**创建数据库**，如下面的屏幕截图所示：

![用 NetBeans 连接 MySQL](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_02_07.jpg)

输入数据库名称，如下面的屏幕截图所示，然后单击**确定**创建数据库：

![用 NetBeans 连接 MySQL](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_02_08.jpg)

最后一步是连接到新创建的**task_time_tracker**数据库。右键单击**task_time_tracker**，然后选择**连接…**，如下面的屏幕截图所示：

![用 NetBeans 连接 MySQL](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_02_09.jpg)

这将为**task_time_tracker**数据库添加一个 MySQL 数据库连接条目，可以在需要时通过右键单击打开：

![用 NetBeans 连接 MySQL](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_02_10.jpg)

现在，您可以右键单击数据库连接并选择**执行命令…**选项，在工作区中打开**SQL 命令**编辑器：

![用 NetBeans 连接 MySQL](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_02_11.jpg)

**SQL 命令**编辑器是您将在其中输入并执行针对数据库的命令的地方：

![用 NetBeans 连接 MySQL](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_02_12.jpg)

# 3T 数据库

以下的 SQL 语句定义了 3T 中使用的 MySQL 表。可以使用任何数据库，并且用 MySQL 特定的代码进行了突出以识别与 ANSI SQL 的不同之处。

## 公司表

公司有项目，我们需要跟踪不同任务所花费的时间。因此，公司是需要定义的第一个表。它是一个非常简单的结构：

```java
create table ttt_company(
  id_company  int unsigned not null auto_increment,
  company_name varchar(200) not null,
  primary key(id_company)
);
```

MySQL 使用`auto_increment`关键字来标识应自动递增的数字列（默认递增速率为一个数字），基于列中当前最高值。这用于生成`id_company`主键值。让我们添加一些公司数据：

```java
insert into ttt_company(company_name) values ('PACKT Publishing');
insert into ttt_company(company_name) values ('Gieman It Solutions');
insert into ttt_company(company_name) values ('Serious WebDev');
```

在**SQL 命令**编辑器中输入这些语句后，您可以通过单击以下截图右上角的按钮来执行这些语句（运行 SQL 按钮已用圈圈标出）：

![公司表](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_02_13.jpg)

这些语句的输出将显示在 IDE 的底部：

![公司表](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_02_14.jpg)

您现在可以通过在**SQL 命令**编辑器中执行以下语句来查看插入的数据：

```java
select * from ttt_company;
```

或者，您还可以右键单击数据库中的表节点，然后选择**查看数据...**：

![公司表](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_02_15.jpg)

这将导致以下截图：

![公司表](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_02_16.jpg)

## 项目表

一个公司可以有任意数量的项目，每个项目都属于一个公司。表定义如下：

```java
create table ttt_project(
  id_project  int unsigned not null auto_increment,
  project_name varchar(200) not null,
  id_company  int unsigned not null,
  primary key(id_project),
  foreign key(id_company) references ttt_company(id_company)
);
```

再次，我们可以添加一些数据：

```java
insert into ttt_project(project_name, id_company) values('Enterprise Application Development with Spring and ExtJS', 1);
insert into ttt_project(project_name, id_company) values ('TheSpring Framework for Beginners', 1);
insert into ttt_project(project_name, id_company) values('Advanced Sencha ExtJS4 ', 1);
insert into ttt_project(project_name, id_company) values ('The 3TProject', 2);
insert into ttt_project(project_name, id_company) values('Breezing', 2);
insert into ttt_project(project_name, id_company) values ('GiemanWebsite', 2);
insert into ttt_project(project_name, id_company) values('Internal Office Projects', 3);
insert into ttt_project(project_name, id_company) values('External Consulting Tasks', 3);
```

在这些`insert`语句中，我们已经提供了对公司表的外键，并再次允许 MySQL 生成主键。执行这些命令并浏览`ttt_project`表数据应该显示如下截图所示：

![项目表](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_02_17.jpg)

## 任务表

一个项目可以有任意数量的任务，每个任务都属于一个项目。现在可以添加表和测试数据如下：

```java
create table ttt_task(
  id_task   int unsigned not null auto_increment,
  id_project  int unsigned not null,  
  task_name  varchar(200) not null,
  primary key(id_task),
  foreign key(id_project) references ttt_project(id_project)
);
```

我们现在将为一些项目添加一系列任务：

```java
insert into ttt_task(id_project, task_name)values (1, 'Chapter 1');
insert into ttt_task(id_project, task_name)values (1, 'Chapter 2');
insert into ttt_task(id_project, task_name)values (1, 'Chapter 3');

insert into ttt_task(id_project, task_name)values (2, 'Chapter 1');
insert into ttt_task(id_project, task_name)values (2, 'Chapter 2');
insert into ttt_task(id_project, task_name)values (2, 'Chapter 3');

insert into ttt_task(id_project, task_name)values (3, 'Preface');
insert into ttt_task(id_project, task_name)values (3, 'Appendix');
insert into ttt_task(id_project, task_name)values (3, 'Illustrations');

insert into ttt_task(id_project, task_name)values (4, 'DatabaseDevelopment');
insert into ttt_task(id_project, task_name)values (4, 'Javadevelopment');
insert into ttt_task(id_project, task_name)values (4, 'SenchaDevcelopment');
insert into ttt_task(id_project, task_name)values (4, 'Testing');
```

执行这些命令并浏览`ttt_task`表数据将显示以下截图：

![任务表](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_02_18.jpg)

## 用户表

我们设计的下一个表包含用户信息：

```java
create table ttt_user(
  username        varchar(10) not null,
  first_name      varchar(100) not null,
  last_name       varchar(100) not null,
  email           varchar(100) not null unique,
  password        varchar(100) not null,
  admin_role      char(1) not null,
  primary key(username)
);
```

请注意，`admin_role`列将用于标识用户是否在 3T 应用程序中具有管理权限。我们现在将添加两个用户：

```java
insert into ttt_user(username, first_name, last_name, email,password, admin_role) values ('jsmith', 'John', 'Smith', 'js@tttracker.com', 'admin','N');
insert into ttt_user(username, first_name, last_name, email,password, admin_role) values ('bjones', 'Betty', 'Jones', 'bj@tttracker.com','admin','Y');
```

运行这组命令将创建用户表，然后插入我们的两个测试用户，如下截图所示：

![用户表](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_02_19.jpg)

## 任务日志表

最终的表将用于输入不同任务所花费的时间。

```java
create table ttt_task_log(
  id_task_log   int unsigned not null auto_increment,
  id_task    int unsigned not null,
  username   varchar(10) not null,
  task_description varchar(2000) not null,
  task_log_date  date not null,
  task_minutes  int unsigned not null,
  primary key(id_task_log),
  foreign key(id_task) references ttt_task(id_task),
  foreign key(username) references ttt_user(username)
);
```

现在我们将为我们的用户约翰史密斯（`jsmith`）的表添加一些数据。请注意，每个任务所花费的时间以分钟为单位，并且 MySQL 函数`now()`用于返回当前时间戳：

```java
insert into ttt_task_log (id_task, username, task_description,task_log_date,task_minutes)values(1,'jsmith','Completed Chapter 1 proof reading',now(),120);
insert into ttt_task_log (id_task, username, task_description,task_log_date,task_minutes)values(2,'jsmith','Completed Chapter 2 draft',now(), 240);
insert into ttt_task_log (id_task, username, task_description,task_log_date,task_minutes)values(3,'jsmith','Completed preparation work for initialdraft',now(), 90);
insert into ttt_task_log (id_task, username, task_description,task_log_date,task_minutes)values(3,'jsmith','Prepared database for Ch3 task',now(), 180);
```

类似地，我们将为贝蒂琼斯（`bjones`）插入一些测试数据：

```java
insert into ttt_task_log (id_task, username, task_description,task_log_date,task_minutes)values(1,'bjones','Started Chapter 1 ',now(), 340);
insert into ttt_task_log (id_task, username, task_description,task_log_date,task_minutes)values(2,'bjones','Finished Chapter 2 draft',now(), 140);
insert into ttt_task_log (id_task, username, task_description,task_log_date,task_minutes)values(3,'bjones','Initial draft work completed',now(), 450);
insert into ttt_task_log (id_task, username, task_description,task_log_date,task_minutes)values(3,'bjones','Database design started',now(), 600);
```

现在可以查看这些`insert`语句的结果，如下截图所示：

![任务日志表](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_02_20.jpg)

# 3T 数据库的企业选项

先前提供的表和列定义是我们 3T 项目所需的最简单的。然而，还有一些潜在的选项可以添加以增强企业使用的结构。

## 密码加密

企业应用程序要求密码字段使用单向算法进行加密以确保安全。密码永远不应以明文形式存储，也永远不应该在数据库中可见（就像我们目前可以做的那样）。本书的范围超出了涵盖密码安全策略的范围，但可以在[`www.jasypt.org/howtoencryptuserpasswords.html`](http://www.jasypt.org/howtoencryptuserpasswords.html)找到核心原则的非常好的解释。

MySQL 提供了许多密码加密函数，可以用于此目的。我们建议您浏览文档[`dev.mysql.com/doc/refman/5.7/en/encryption-functions.html`](https://dev.mysql.com/doc/refman/5.7/en/encryption-functions.html)以了解可用的不同选项。

## LDAP 集成

许多企业使用**LDAP**（轻量级目录访问协议）来维护其组织内的用户。LDAP 最常用于提供单一登录，其中一个用户的密码在许多服务之间共享。因此，在这种情况下，用户表中的密码列将不需要。如果一个组织跨越多个地理位置，可能会有几个分布在不同大陆的 LDAP 领域。这种情况可能需要一个新的表来存储 LDAP 授权服务器。然后，每个用户可能会被分配一个授权 LDAP 服务器来处理他们的登录。

## 审计追踪

企业系统通常需要广泛的审计追踪（何时以及为什么发生了某个动作，以及是谁执行了它）。这对于公开上市的大型组织尤为重要。例如，**萨班斯-奥克斯法案**（**SOX**）要求所有在美国境内上市的公司必须建立内部控制和程序，以减少公司欺诈的可能性。这些流程包括识别任何时间段内的授权和未授权更改或潜在可疑活动。

“谁，何时，为什么”这些问题是设计企业数据库时需要考虑的审计追踪的基础。简单地向所有表添加一些额外的列是一个很好的开始：

```java
who_created varchar(10) not null
who_updated varchar(10) not null
when_created datetime default current_timestamp
when_updated datetime on update current_timestamp
```

请注意，这个语法是针对 MySQL 的，但类似的功能对大多数数据库都是可用的。`who_created`和`who_updated`列将需要通过程序更新。开发人员需要确保在处理相关操作时这些字段被正确设置。`when_created`和`when_updated`列不需要开发人员考虑。它们会被 MySQL 自动维护。`when_created`字段将自动设置为`current_timestamp` MySQL 函数，表示查询开始时间，以确定记录被插入到数据库中的确切时刻。`when_updated`字段将在每次记录本身被更新时自动更新。添加这四个额外的列将确保基本级别的审计追踪是可用的。现在我们可以查看谁创建了记录以及何时，还可以查看谁执行了最后的更新以及何时。例如，`ttt_company`表可以重新设计如下：

```java
create table ttt_company(
  id_company      int unsigned not null auto_increment,
  company_name    varchar(200) not null,
  who_created varchar(10) not null,
  who_updated varchar(10) not null,
  when_created datetime default current_timestamp,
  when_updated datetime on update current_timestamp,
  primary key(id_company)
);
```

### 登录活动审计

这提供了跟踪基本用户活动的能力，包括谁登录了，何时登录了，以及从哪里登录了。这是企业审计追踪的另一个关键部分，还应包括跟踪无效的登录尝试。这些信息需要通过程序维护，并需要一个类似以下代码结构的表：

```java
create table ttt_user_log(
  id_user_log int unsigned not null auto_increment,
  username varchar(10) not null,
  ip_address varchar(20) not null,
  status char not null,
  log_date datetime default current_timestamp,
  primary key(id_user_log)
);
```

`status`字段可以用于标识登录尝试（例如，**S**可以表示成功，**F**可以表示失败，而**M**可以表示成功的移动设备登录）。所需的信息需要根据企业的合规要求来定义。

### 自定义审计表

通常需要审计特定表的每个操作和数据更改。在这种情况下，“何时”和“谁”更新字段是不够的。这种情况需要一个包含原始表中所有字段的审计（或快照）表。每次记录更新时，当前快照都会被写入审计表，以便每个更改都可以用于审计目的。这样的表也可能被称为存档表，因为数据的演变在每次更改时都被存档。这些自定义审计表通常不是通过编程方式维护的，而是由关系数据库管理系统（RDBMS）管理，可以通过触发器或内置的日志记录/存档功能来管理。

# 摘要

本章定义了一个将用于构建 3T 应用程序的数据库结构。我们已连接到 MySQL 服务器并执行了一系列 SQL 语句来创建和填充一组表。每个表都使用“自动增量”列，以便 MySQL 可以自动管理和生成主键。虽然表结构并不复杂，但我们也已经确定了可能适用于企业使用的可能增强功能。

在第三章中，*使用 JPA 逆向工程领域层*，我们将通过逆向工程我们的数据库来创建一组**Java 持久化 API**（**JPA**）实体，开始我们的 Java 之旅。我们的 JPA 领域层将成为我们 3T 应用程序的数据核心。


# 第三章：使用 JPA 进行领域层的逆向工程

领域层代表了模拟应用程序核心的真实世界实体。在最高层次上，领域层代表了应用程序的业务领域，并完全描述了实体、它们的属性以及它们之间的关系。在最基本的层次上，领域层是一组**普通的旧 Java 对象**（**POJOs**），它们定义了数据库表的 Java 表示，这些表被映射到应用程序上。这种映射是通过 JPA 实现的。

**Java 持久化 API**（**JPA**）是 Java EE 5 平台中最重要的进步之一，它用更简单的基于 POJO 的编程模型取代了复杂和繁琐的实体 bean。JPA 提供了一套标准的**对象关系映射**（**ORM**）规则，这些规则简单直观，易于学习。数据库关系、属性和约束通过 JPA 注解映射到 POJOs 上。

在本章中，我们将执行以下操作：

+   使用 NetBeans IDE 对 3T 数据库进行逆向工程

+   探索并定义我们领域层的 JPA 注解

+   介绍**Java 持久化查询语言**（**JPQL**）

# 理解使用 JPA 的原因

JPA 是一种提高开发人员专注于业务而不是编写低级 SQL 和 JDBC 代码的生产力工具。它完全消除了将 Java 的`ResultSet`映射到 Java 领域对象的需要，并大大减少了产生可用和功能性应用程序所需的工作量。基于 JPA 的应用程序将更容易维护、测试和增强。更重要的是，您的应用程序代码质量将显著提高，领域实体将变得自我描述。

根据个人经验，我估计编写传统的 SQL 应用程序（不使用 JPA，直接编写 CRUD SQL 语句）所需的时间大约是使用 JPA 方法的 10-15 倍。这意味着在企业应用程序中节省了大量的时间和精力。在应用程序的生命周期中，考虑到维护、错误修复和增强，仅仅通过节约成本就可能是成功与失败之间的差异。

# 理解 JPA 实现

JPA 规范最初是从包括 TopLink（来自 Oracle）、Hibernate 和 Kodo 在内的关键 ORM 实现的经验中演变而来。这些产品通过将领域层中的底层 SQL 抽象出来，并简化实现核心 CRUD 操作（创建、读取、更新和删除）所需的开发工作，从而彻底改变了 Java 数据库交互。每个实现都支持 JPA 标准以及它们自己的专有 API。例如，TopLink 提供了超出 JPA 规范的缓存增强功能，以及针对 Oracle 数据库的复杂查询优化。您选择的实现可能取决于应用程序的要求（例如，分布式缓存）以及底层数据库本身。

GlassFish 4 服务器捆绑了开源的**EclipseLink** JPA 实现，这是我们将在本书中使用的。有关 EclipseLink 项目的更多信息，请访问[`www.eclipse.org/eclipselink/`](http://www.eclipse.org/eclipselink/)。您无需下载任何文件，因为在逆向工程过程中，EclipseLink 依赖项将自动添加到您的`pom.xml`文件中。

# 使用 NetBeans 进行逆向工程

“从数据库创建新实体类”向导是 NetBeans 中最有帮助和节省时间的向导之一。它从现有的数据库连接生成一组实体类，提取和注释所有字段，并定义类之间的关系。要访问该向导，请导航到“文件”|“新建文件”。这将打开“新建文件”窗口，然后您可以选择“持久性”类别，然后选择“来自数据库的实体类”文件类型：

![使用 NetBeans 进行反向工程](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_03_01.jpg)

单击“下一步”以显示“数据库表”屏幕，您可以在其中创建“新数据源”：

![使用 NetBeans 进行反向工程](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_03_02.jpg)

这将允许您输入“JNDI 名称”并选择在上一章中创建的“数据库连接”：

![使用 NetBeans 进行反向工程](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_03_03.jpg)

向导现在将读取所有表并将它们显示在“可用表”列表中。选择所有表并将它们添加到“已选表”列表中，如图所示：

![使用 NetBeans 进行反向工程](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_03_04.jpg)

单击“下一步”按钮。这将显示以下屏幕，显示实体类生成属性。通过双击每个“类名”行来更改每个实体的“类名”，以删除“Ttt”前缀来编辑此属性（屏幕截图显示了编辑前的`User`实体）。为什么要删除这个“Ttt”？简单地因为反向工程过程会自动创建基于表名的类名，而“Ttt”前缀对我们的设计没有任何帮助。下一个更改必须在包名中完成。如图所示，在包名中添加“domain”。这将在“com.gieman.tttracker.domain”包中生成新的实体类，代表我们的业务领域对象和相关的辅助类。根据用途或目的将我们的类放在定义明确的独立包中，增强了我们轻松维护应用程序的能力。对于大型企业应用程序，定义良好的 Java 包结构至关重要。

最后一步是取消选中“生成 JAXB 注释”复选框。我们不需要通过 JAXB 生成 XML，因此我们不需要额外的注释。

![使用 NetBeans 进行反向工程](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_03_05.jpg)

现在单击“下一步”按钮，将显示以下屏幕。最后一步涉及选择适当的“集合类型”。有三种不同类型的集合可以使用，并且都可以同样成功地使用。我们将默认的“集合类型”更改为`java.util.List`，因为在应用程序的业务逻辑中，排序顺序通常很重要，而其他类型不允许排序。在更个人的层面上，我们更喜欢使用`java.util.List` API 而不是`java.util.Set`和`java.util.Collection` API。

![使用 NetBeans 进行反向工程](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_03_06.jpg)

单击“完成”按钮开始反向工程过程。过程完成后，您可以打开`src/java`节点查看生成的文件，如下图所示：

![使用 NetBeans 进行反向工程](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_03_07.jpg)

# 介绍 persistence.xml 文件

`persistence.xml`文件是在反向工程过程中生成的，为一组实体类定义了 JPA 配置。该文件始终位于类路径根目录下的`META-INF`目录中。Maven 项目有一个名为`resources`的特殊目录，位于`src/main`目录中，其中包含适用于构建 Java 项目的其他资源。构建项目时，Maven 会自动将`resources`目录复制到类路径的根目录。双击打开文件以在编辑器中显示文件的“设计”视图：

![介绍 persistence.xml 文件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_03_08.jpg)

**设计**视图包含用于配置持久性单元行为的几个属性。我们将坚持使用最简单的设置，但我们鼓励您探索可能对您自己应用程序需求有用的不同策略。例如，需要自动创建表的项目将欣赏**表生成策略**的**创建**或**删除和创建**。选择不同的选项并切换到**源**视图将帮助我们快速识别`persistence.xml`文件中的适当属性。

点击顶部的**源**按钮以以文本格式查看默认文件内容：

![介绍 persistence.xml 文件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_03_09.jpg)

将默认的`persistence-unit`节点`name`属性值更改为`tttPU`，而不是长自动生成的名称。此值将用于您的 Java 代码来引用此持久性单元，并且易于记忆。`provider`节点值会自动设置为适当的 EclipseLink 类，`jta-data-source`节点值会自动设置为在反向工程向导期间使用的数据源。`exclude-unlisted-classes`设置将定义是否对注释的实体类进行类路径扫描。将其更改为`false`。对于大型项目，这是确保类不会被意外省略的最安全方法。还可以以以下方式明确指定每个类：

![介绍 persistence.xml 文件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_03_10.jpg)

这对于小型项目来说很好，但如果您有数百个实体类，这就不太实际了。在前面的示例中，`exclude-unlisted-classes`属性设置为`true`，这意味着只有指定的类将被加载，无需进行类路径扫描。我们更喜欢通过将`exclude-unlisted-classes`设置为`false`来定义我们的 JPA 类的第一种方法，从而通过类路径扫描加载所有注释的实体类。

感兴趣的最终配置项是`transaction-type`属性。此项支持两种不同类型的事务，我们默认设置为`JTA`。**JTA**（**Java 事务 API**）表示事务将由 GlassFish 服务器提供的 Java EE 事务管理器管理。我们将在第五章中构建测试用例时探索`RESOURCE_LOCAL`替代 JTA。在这种情况下，事务将在没有 Java EE 容器的情况下在本地管理。

# 重构 Java 类

通过一些重构，可以改进反向工程过程生成的类，使代码更易读和理解。当我们实际上是在引用类时，一些自动生成的属性和字段的名称中都有`id`，而`java.util.List`对象的集合中都有`list`。让我们从`Company.java`文件开始。

## Company.java 文件

该文件代表`Company`实体。双击文件以在编辑器中打开并浏览内容。这个类是一个简单的 POJO，除了标准的`hashCode`，`equals`和`toString`方法外，还有每个属性的 set 和 get 方法。该类有一个无参构造函数（JPA 规范要求域对象必须动态创建，没有任何属性），一个仅接受主键的第二个构造函数和一个完整（所有参数）的构造函数。我们将通过对`Company.java`文件进行一些小的更改来使代码更易读。

第一个更改是将文件中的`projectList`字段到处重命名为`projects`。这可以通过选择`projectList`字段，然后从菜单中选择**重构** | **重命名**来轻松实现：

![Company.java 文件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_03_11.jpg)

现在您可以将字段名称更改为**projects**。在单击**Refactor**按钮之前，确保还选择**Rename Getters and Setters**选项。

![Company.java 文件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_03_12.jpg)

进行这些更改将更改字段名称并为`projects`字段生成新的获取和设置方法。

`Company.java`文件的最终更改是将`mappedBy`属性从`idCompany`重命名为`company`。适当的行现在应该如下所示的代码：

```java
@OneToMany(cascade = CascadeType.ALL, mappedBy = "company")
private List<Project> projects;
```

最终重构的`Company.java`文件现在应该如下所示的代码片段：

```java
package com.gieman.tttracker.domain;

import java.io.Serializable;
import java.util.List;
import javax.persistence.Basic;
import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Entity
@Table(name = "ttt_company")
@NamedQueries({
    @NamedQuery(name = "Company.findAll", query = "SELECT c FROM Company c"),
    @NamedQuery(name = "Company.findByIdCompany", query = "SELECT c FROM Company c WHERE c.idCompany = :idCompany"),
    @NamedQuery(name = "Company.findByCompanyName", query = "SELECT c FROM Company c WHERE c.companyName = :companyName")})
public class Company implements Serializable {
    private static final long serialVersionUID = 1L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Basic(optional = false)
    @Column(name = "id_company")
    private Integer idCompany;
    @Basic(optional = false)
    @NotNull
    @Size(min = 1, max = 200)
    @Column(name = "company_name")
    private String companyName;
    @OneToMany(cascade = CascadeType.ALL, mappedBy = "company")
    private List<Project> projects;

    public Company() {
    }

    public Company(Integer idCompany) {
        this.idCompany = idCompany;
    }

    public Company(Integer idCompany, String companyName) {
        this.idCompany = idCompany;
        this.companyName = companyName;
    }

    public Integer getIdCompany() {
        return idCompany;
    }

    public void setIdCompany(Integer idCompany) {
        this.idCompany = idCompany;
    }

    public String getCompanyName() {
        return companyName;
    }

    public void setCompanyName(String companyName) {
        this.companyName = companyName;
    }

    public List<Project> getProjects() {
        return projects;
    }

    public void setProjects(List<Project> projects) {
        this.projects = projects;
    }

    @Override
    public int hashCode() {
        int hash = 0;
        hash += (idCompany != null ? idCompany.hashCode() : 0);
        return hash;
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof Company)) {
            return false;
        }
        Company other = (Company) object;
        if ((this.idCompany == null && other.idCompany != null) || (this.idCompany != null && !this.idCompany.equals(other.idCompany))) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "com.gieman.tttracker.domain.Company[ idCompany=" + idCompany + " ]";
    }

}
```

JPA 使用约定优于配置的概念来简化实体的配置。这是通过使用具有合理默认值的注释来实现的，以保持实体定义的简洁。现在，让我们看看此文件中的关键 JPA 注释。

### @Entity 注释

这是一个标记注释，指示 JPA 持久性提供者`Company`类是一个实体。当`persistence.xml`文件中的`exclude-unlisted-classes`设置为`false`时，JPA 会扫描`@Entity`注释。没有`@Entity`注释，持久性引擎将忽略该类。

### @Table 注释

@Table 注释定义了由此实体类表示的底层数据库表。`@Table(name = "ttt_company")`行告诉持久性提供者`Company`类表示`ttt_company`表。任何实体类中只能定义一个表注释。

### @Id 注释

@Id 注释定义了类中的主键字段，并且对于每个实体都是必需的。如果不存在@Id 注释，持久性提供者将抛出异常。表示`ttt_company`表中主键的`Company`类属性是`Integer idCompany`字段。此字段附加了三个附加注释，其中以下注释特定于主键。

### @GeneratedValue 注释

此注释标识持久性引擎应如何为将记录插入表中生成新的主键值。`strategy=GenerationType.IDENTITY`行将在后台使用 MySQL 自动增量策略将记录插入`ttt_company`表。不同的数据库可能需要不同的策略。例如，Oracle 数据库表可以通过定义以下生成器注释以使用序列作为主键生成的基础：

```java
@GeneratedValue(generator="gen_seq_company")
@SequenceGenerator(name="gen_seq_company", sequenceName="seq_id_company")
```

### 注意

主键生成与类本身无关。持久性引擎将根据生成策略处理主键的生成。

### @Basic 注释

这是一个可选的注释，用于标识字段的可空性。`@Basic(optional = false)`行用于指定字段不是可选的（不可为 null）。同样，`@Basic(optional = true)`行可用于其他可能可为空的字段。

### @Column 注释

此注释指定字段映射到的列。因此，`@Column(name = "id_company")`行将`ttt_company`表中的`id_company`列映射到类中的`idCompany`字段。

### @NotNull 和@Size 注释

这些注释是`javax.validation.constraints`包的一部分（Bean Validation 包是在 Java EE 6 中引入的），定义了字段不能为空以及字段的最小和最大大小。`ttt_company`表中的`company_name`列被定义为`varchar(200) not null`，这就是在反向工程过程中创建这些注释的原因。

### @OneToMany 注释

`Company`类可能有零个或多个`Projects`实体。这种关系由`@OneToMany`注解定义。简而言之，我们可以描述这种关系为*一个公司可以有多个项目*。在 JPA 中，通过在此注解中定义`mappedBy`属性，实体与其他实体的集合相关联。我们已经将原始的`mappedBy`值重构为`company`。这将是在我们在下一节中重构`Project`文件后，在`Project.java`文件中的字段的名称。

### @NamedQueries 注解

`@NamedQueries`注解值得单独解释。我们稍后会详细讨论这些。

## Projects.java 文件

你现在可能已经猜到，这个文件代表`Project`实体，并映射到`ttt_project`表。双击文件以在编辑器中打开并浏览内容。我们将再次进行一些重构，以澄清自动生成的字段：

+   使用重构过程将自动生成的`idCompany`字段重命名为`company`。不要忘记重命名 get 和 set 方法。

+   将自动生成的`taskList`字段重命名为`tasks`。不要忘记再次编写 get 和 set 方法！

+   将`mappedBy`值从`idProject`重命名为`project`。

最终重构后的文件现在应该如下代码所示：

```java
package com.gieman.tttracker.domain;

import java.io.Serializable;
import java.util.List;
import javax.persistence.Basic;
import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Entity
@Table(name = "ttt_project")
@NamedQueries({
    @NamedQuery(name = "Project.findAll", query = "SELECT p FROM Project p"),
    @NamedQuery(name = "Project.findByIdProject", query = "SELECT p FROM Project p WHERE p.idProject = :idProject"),
    @NamedQuery(name = "Project.findByProjectName", query = "SELECT p FROM Project p WHERE p.projectName = :projectName")})
public class Project implements Serializable {
    private static final long serialVersionUID = 1L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Basic(optional = false)
    @Column(name = "id_project")
    private Integer idProject;
    @Basic(optional = false)
    @NotNull
    @Size(min = 1, max = 200)
    @Column(name = "project_name")
    private String projectName;
    @JoinColumn(name = "id_company", referencedColumnName = "id_company")
    @ManyToOne(optional = false)
    private Company company;
    @OneToMany(cascade = CascadeType.ALL, mappedBy = "project")
    private List<Task> tasks;

    public Project() {
    }
    public Project(Integer idProject) {
        this.idProject = idProject;
    }

    public Project(Integer idProject, String projectName) {
        this.idProject = idProject;
        this.projectName = projectName;
    }

    public Integer getIdProject() {
        return idProject;
    }

    public void setIdProject(Integer idProject) {
        this.idProject = idProject;
    }

    public String getProjectName() {
        return projectName;
    }

    public void setProjectName(String projectName) {
        this.projectName = projectName;
    }

    public Company getCompany() {
        return company;
    }

    public void setCompany(Company company) {
        this.company = company;
    }

    public List<Task> getTasks() {
        return tasks;
    }

    public void setTasks(List<Task> tasks) {
        this.tasks = tasks;
    }

    @Override
    public int hashCode() {
        int hash = 0;
        hash += (idProject != null ? idProject.hashCode() : 0);
        return hash;
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof Project)) {
            return false;
        }
        Project other = (Project) object;
        if ((this.idProject == null && other.idProject != null) || (this.idProject != null && !this.idProject.equals(other.idProject))) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "com.gieman.tttracker.domain.Project[ idProject=" + idProject + " ]";
    }

}
```

### @ManyToOne 注解

这个注解表示实体之间的关系；它是`@OneToMany`注解的反向。对于`Project`实体，我们可以说*多个项目对应一个公司*。换句话说，一个`Project`实体属于一个单一的`Company`类，而（反过来）一个`Company`类可以有任意数量的`Projects`实体。这种关系在数据库级别（即底层表中的外键关系）中定义，并在`@JoinColumn`注解中实现：

```java
@JoinColumn(name = "id_company", referencedColumnName = "id_company")
```

`name`属性定义了`ttt_project`表中的列名，该列是指向`ttt_company`表中的`referencedColumnName`列的外键。

## 双向映射和拥有实体

通过`@ManyToOne`和`@OneToMany`注解，理解一个实体如何通过这两个注解与另一个实体相关联是非常重要的。`Company`类有一个映射的`Projects`实体列表，定义如下：

```java
  @OneToMany(cascade = CascadeType.ALL, mappedBy = "company")
  private List<Project> projects;
```

而`Project`类恰好有一个映射的`Company`实体：

```java
  @JoinColumn(name="id_company", referencedColumnName="id_company")
  @ManyToOne(optional=false)
  private Company company;
```

这被称为双向映射，每个方向上每个类都有一个映射。一个多对一的映射回到源，就像`Project`实体回到`Company`实体一样，意味着源（`Company`）到目标（`Project`）有一个对应的一对多映射。术语**源**和**目标**可以定义如下：

+   **源**：这是一个可以独立存在于关系中的实体。源实体不需要目标实体存在，`@OneToMany`集合可以为空。在我们的例子中，`Company`实体可以存在而不需要`Project`实体。

+   **目标**：这是一个没有参考有效源就无法独立存在的实体。目标上定义的`@ManyToOne`实体不能为空。在我们的设计中，`Project`实体不能存在而没有有效的`Company`实体。

**拥有实体**是一个从数据库角度理解另一个实体的实体。简单来说，拥有实体具有`@JoinColumn`定义，描述形成关系的基础列。在`Company`-`Project`关系中，`Project`是拥有实体。请注意，一个实体可以同时是目标和源，如下面的`Project.java`文件片段所示：

```java
  @OneToMany(cascade = CascadeType.ALL, mappedBy = "project")
  private List<Task> tasks;
```

在这里，`Project`是`Task`实体关系的源，我们期望在`Task`类上找到一个反向的`@ManyToOne`注解。这正是我们将找到的。

## Task.java 文件

这个文件定义了代表`ttt_task`表的`Task`实体。打开文件并执行以下重构：

+   删除自动生成的`taskLogList`字段，同时也删除相关的 get 和 set 方法。为什么要这样做？系统中可能有数百万条任务日志与每个`Task`实例相关联，不建议在`Task`对象内保存对这么大一组`TaskLog`实例的引用。

+   将自动生成的`idProject`字段重命名为`project`。不要忘记再次删除 get 和 set 方法。

在进行了上述更改之后，您会发现一些导入不再需要，并且在 NetBeans IDE 中被标记出来：

![Task.java 文件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_03_13.jpg)

*Ctrl* + *Shift* + *I*的组合键将删除所有未使用的导入。另一种选择是单击下图中显示的图标，打开菜单并选择**删除**选项：

![Task.java 文件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_03_14.jpg)

清理代码并删除未使用的导入是一个简单的过程，这是一个良好的实践。

最终重构后的文件现在应该看起来像以下代码片段：

```java
package com.gieman.tttracker.domain;

import java.io.Serializable;
import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Entity
@Table(name = "ttt_task")
@NamedQueries({
    @NamedQuery(name = "Task.findAll", query = "SELECT t FROM Task t"),
    @NamedQuery(name = "Task.findByIdTask", query = "SELECT t FROM Task t WHERE t.idTask = :idTask"),
    @NamedQuery(name = "Task.findByTaskName", query = "SELECT t FROM Task t WHERE t.taskName = :taskName")})
public class Task implements Serializable {
    private static final long serialVersionUID = 1L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Basic(optional = false)
    @Column(name = "id_task")
    private Integer idTask;
    @Basic(optional = false)
    @NotNull
    @Size(min = 1, max = 200)
    @Column(name = "task_name")
    private String taskName;
    @JoinColumn(name = "id_project", referencedColumnName = "id_project")
    @ManyToOne(optional = false)
    private Project project;

    public Task() {
    }

    public Task(Integer idTask) {
        this.idTask = idTask;
    }

    public Task(Integer idTask, String taskName) {
        this.idTask = idTask;
        this.taskName = taskName;
    }

    public Integer getIdTask() {
        return idTask;
    }

    public void setIdTask(Integer idTask) {
        this.idTask = idTask;
    }

    public String getTaskName() {
        return taskName;
    }

    public void setTaskName(String taskName) {
        this.taskName = taskName;
    }

    public Project getProject() {
        return project;
    }

    public void setProject(Project project) {
        this.project = project;
    }

    @Override
    public int hashCode() {
        int hash = 0;
        hash += (idTask != null ? idTask.hashCode() : 0);
        return hash;
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof Task)) {
            return false;
        }
        Task other = (Task) object;
        if ((this.idTask == null && other.idTask != null) || (this.idTask != null && !this.idTask.equals(other.idTask))) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "com.gieman.tttracker.domain.Task[ idTask=" + idTask + " ]";
    }    
}
```

注意`@ManyToOne`注释引用`Project`类，使用`@JoinColumn`定义。`Task`对象拥有这个关系。

## User.java 文件

`User`实体代表了底层的`ttt_user`表。生成的类对与`TaskLog`类的关系有一个`@OneToMany`定义：

```java
  @OneToMany(cascade = CascadeType.ALL, mappedBy = "username")
  private List<TaskLog> taskLogList;
```

在这个文件中进行重构将再次**完全删除**这个关系。如`Tasks.java`部分所述，一个`User`实体也可能有成千上万的任务日志。通过了解应用程序的要求和数据结构，完全删除不必要的关系通常更加清晰。

您还会注意到在反向工程过程中，默认情况下`@Pattern`注释被注释掉了。`email`字段名称告诉 NetBeans 这可能是一个电子邮件字段，如果需要，NetBeans 会添加注释以供使用。我们将取消注释此注释以启用对该字段的电子邮件模式检查，并添加所需的导入：

```java
import javax.validation.constraints.Pattern;
```

重构后的`User.java`文件现在应该看起来像以下代码片段：

```java
package com.gieman.tttracker.domain;

import java.io.Serializable;
import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

@Entity
@Table(name = "ttt_user")
@NamedQueries({
    @NamedQuery(name = "User.findAll", query = "SELECT u FROM User u"),
    @NamedQuery(name = "User.findByUsername", query = "SELECT u FROM User u WHERE u.username = :username"),
    @NamedQuery(name = "User.findByFirstName", query = "SELECT u FROM User u WHERE u.firstName = :firstName"),
    @NamedQuery(name = "User.findByLastName", query = "SELECT u FROM User u WHERE u.lastName = :lastName"),
    @NamedQuery(name = "User.findByEmail", query = "SELECT u FROM User u WHERE u.email = :email"),
    @NamedQuery(name = "User.findByPassword", query = "SELECT u FROM User u WHERE u.password = :password"),
    @NamedQuery(name = "User.findByAdminRole", query = "SELECT u FROM User u WHERE u.adminRole = :adminRole")})
public class User implements Serializable {
    private static final long serialVersionUID = 1L;
    @Id
    @Basic(optional = false)
    @NotNull
    @Size(min = 1, max = 10)
    @Column(name = "username")
    private String username;
    @Basic(optional = false)
    @NotNull
    @Size(min = 1, max = 100)
    @Column(name = "first_name")
    private String firstName;
    @Basic(optional = false)
    @NotNull
    @Size(min = 1, max = 100)
    @Column(name = "last_name")
    private String lastName;
    @Pattern(regexp="[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:a-z0-9?\\.)+a-z0-9?", message="Invalid email")
    @Basic(optional = false)
    @NotNull
    @Size(min = 1, max = 100)
    @Column(name = "email")
    private String email;
    @Basic(optional = false)
    @NotNull
    @Size(min = 1, max = 100)
    @Column(name = "password")
    private String password;
    @Column(name = "admin_role")
    private Character adminRole;

    public User() {
    }

    public User(String username) {
        this.username = username;
    }

    public User(String username, String firstName, String lastName, String email, String password) {
        this.username = username;
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Character getAdminRole() {
        return adminRole;
    }

    public void setAdminRole(Character adminRole) {
        this.adminRole = adminRole;
    }

    @Override
    public int hashCode() {
        int hash = 0;
        hash += (username != null ? username.hashCode() : 0);
        return hash;
    }

    @Override
    public boolean equals(Object object) {
         if (!(object instanceof User)) {
            return false;
        }
        User other = (User) object;
        if ((this.username == null && other.username != null) || (this.username != null && !this.username.equals(other.username))) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "com.gieman.tttracker.domain.User[ username=" + username + " ]";
    }   
}
```

## TaskLog.java 文件

我们应用程序中的最终实体代表了`ttt_task_log`表。这里需要进行的重构是将`idTask`字段重命名为`task`（记得同时重命名 get 和 set 方法），然后将`username`字段重命名为`user`。文件现在应该看起来像以下代码片段：

```java
package com.tttracker.domain;

import java.io.Serializable;
import java.util.Date;
import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Entity
@Table(name = "ttt_task_log")
@NamedQueries({
  @NamedQuery(name = "TaskLog.findAll", query = "SELECT t FROM TaskLog t"),
  @NamedQuery(name = "TaskLog.findByIdTaskLog", query = "SELECT t FROM TaskLog t WHERE t.idTaskLog = :idTaskLog"),
  @NamedQuery(name = "TaskLog.findByTaskDescription", query = "SELECT t FROM TaskLog t WHERE t.taskDescription = :taskDescription"),
  @NamedQuery(name = "TaskLog.findByTaskLogDate", query = "SELECT t FROM TaskLog t WHERE t.taskLogDate = :taskLogDate"),
  @NamedQuery(name = "TaskLog.findByTaskMinutes", query = "SELECT t FROM TaskLog t WHERE t.taskMinutes = :taskMinutes")})
public class TaskLog implements Serializable {
  private static final long serialVersionUID = 1L;
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Basic(optional = false)
  @Column(name = "id_task_log")
  private Integer idTaskLog;
  @Basic(optional = false)
  @NotNull
  @Size(min = 1, max = 2000)
  @Column(name = "task_description")
  private String taskDescription;
  @Basic(optional = false)
  @NotNull
  @Column(name = "task_log_date")
  @Temporal(TemporalType.DATE)
  private Date taskLogDate;
  @Basic(optional = false)
  @NotNull
  @Column(name = "task_minutes")
  private int taskMinutes;
  @JoinColumn(name = "username", referencedColumnName = "username")
  @ManyToOne(optional = false)
  private User user;
  @JoinColumn(name = "id_task", referencedColumnName = "id_task")
  @ManyToOne(optional = false)
  private Task task;

  public TaskLog() {
  }

  public TaskLog(Integer idTaskLog) {
    this.idTaskLog = idTaskLog;
  }

  public TaskLog(Integer idTaskLog, String taskDescription, Date taskLogDate, int taskMinutes) {
    this.idTaskLog = idTaskLog;
    this.taskDescription = taskDescription;
    this.taskLogDate = taskLogDate;
    this.taskMinutes = taskMinutes;
  }

  public Integer getIdTaskLog() {
    return idTaskLog;
  }

  public void setIdTaskLog(Integer idTaskLog) {
    this.idTaskLog = idTaskLog;
  }

  public String getTaskDescription() {
    return taskDescription;
  }

  public void setTaskDescription(String taskDescription) {
    this.taskDescription = taskDescription;
  }

  public Date getTaskLogDate() {
    return taskLogDate;
  }

  public void setTaskLogDate(Date taskLogDate) {
    this.taskLogDate = taskLogDate;
  }

  public int getTaskMinutes() {
    return taskMinutes;
  }

  public void setTaskMinutes(int taskMinutes) {
    this.taskMinutes = taskMinutes;
  }

  public User getUser() {
    return user;
  }

  public void setUser(User user) {
    this.user = user;
  }

  public Task getTask() {
    return task;
  }

  public void setTask(Task task) {
    this.task = task;
  }

  @Override
  public int hashCode() {
    int hash = 0;
    hash += (idTaskLog != null ? idTaskLog.hashCode() : 0);
    return hash;
  }

  @Override
  public boolean equals(Object object) {
    if (!(object instanceof TaskLog)) {
      return false;
    }
    TaskLog other = (TaskLog) object;
    if ((this.idTaskLog == null && other.idTaskLog != null) || (this.idTaskLog != null && !this.idTaskLog.equals(other.idTaskLog))) {
      return false;
    }
    return true;
  }

  @Override
  public String toString() {
    return "com.tttracker.domain.TaskLog[ idTaskLog=" + idTaskLog + " ]";
  }
}
```

# 介绍 Java 持久性查询语言

阅读本书的每个人都应该熟悉 SQL 查询及其工作原理。针对`ttt_company`表构建一个简单的查询以检索所有记录将如下所示：

```java
select * from ttt_company
```

将结果集限制为以`G`开头的公司将如下代码行所示：

```java
select * from ttt_company where company_name like "G%"
```

在 JPA 中，我们处理实体和实体之间的关系。**Java 持久性查询语言**（**JPQL**）用于以类似于 SQL 的方式制定查询。前面提到的语句将以 JPQL 形式写成如下：

```java
SELECT c FROM Company c
```

接下来的语句将被写成如下形式：

```java
SELECT c FROM Company c WHERE c.companyName LIKE 'G%'
```

以下是 SQL 和 JPQL 之间的主要区别：

+   JPQL 类和字段名称区分大小写。当我们处理类时，类名必须以大写字母开头。所有字段必须与类中定义的大小写完全一致。以下语句将无法编译，因为公司实体以小写`c`开头：

```java
SELECT c FROM company c WHERE c.companyName LIKE 'G%'
```

+   JPQL 关键字不区分大小写。上述语句也可以写成如下形式：

```java
select c from Company c where c.companyName like 'G%'
```

+   JPQL 使用别名来定义实例和实例之间的关系。在前面的例子中，小写的`c`被用作`SELECT`和`WHERE`子句中的别名。

+   JPQL 查询可以是静态的（在注释中定义）或动态的（在运行时构建和执行）。静态查询只编译一次，并在需要时查找。这使得静态查询更快速和更高效。

+   JPQL 查询被翻译成 SQL；然后针对底层数据库执行。这种翻译允许在持久性引擎中进行特定于数据库的查询优化。

+   JPQL 有一套丰富的函数来定义条件表达式。这些表达式被翻译成底层数据库的正确 SQL。这意味着开发人员不再需要编写特定于数据库的 SQL 语句。在不同数据库之间切换不需要任何编码，因为 JPQL 语句抽象了执行语句所需的底层 SQL。

### 注意

我们强烈建议您花时间学习 JPQL。有许多专门介绍 JPA 和 JPQL 的优秀书籍可供阅读，它们解释了高级用法。互联网上也有许多在线教程和 JPQL 示例。本书的范围超出了基础知识，我们将其留给您进一步深入学习这种丰富语言。

## 定义命名查询

反向工程过程在每个类中生成了一组`@NamedQuery`注解，每个持久字段都有一个。例如，`Company`类定义了以下命名查询：

```java
@NamedQueries({
  @NamedQuery(name = "Company.findAll", query = "SELECT c FROM Company c"),
  @NamedQuery(name = "Company.findByIdCompany", query = "SELECT c FROM Company c WHERE c.idCompany = :idCompany"),
  @NamedQuery(name = "Company.findByCompanyName", query = "SELECT c FROM Company c WHERE c.companyName = :companyName")}) 
```

每个`@NamedQuery`名称在持久性引擎内必须是唯一的；因此，它以类的名称为前缀。第一个查询名称`Company.findAll`表示`Company`对象的完整列表。第二个查询使用命名参数`idCompany`作为运行时提供的值的占位符。命名参数总是以冒号符号为前缀。您应该花一些时间浏览 Java 类中生成的查询，以熟悉基本的 JPQL 语法。我们将在接下来的章节中学习更多关于命名查询以及它们的用法。

# 重构 Java equals()和 hashCode()

我们的领域层实体类已定义了自动生成的`equals`和`hashCode`方法。例如，`Company`类定义了如下方法：

![重构 Java equals()和 hashCode()](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_03_15.jpg)

最佳实践是始终提供正确实现的`equals`和`hashCode`方法，这些方法使用实体 ID 来计算返回的值。这些方法由 JPA 用于确定实体之间的相等性。我们的自动生成的`equals`方法将与 JPA 一起正常工作，因为 ID 实体在每个方法的比较中都被使用。然而，83 行上的`//TODO: Warning`消息（参见上一个屏幕截图）指示了一个问题，如果我们使用 NetBeans IDE 重新生成`equals`方法，就可以避免这个问题。

删除`equals`方法，并使用鼠标右键单击编辑器中的`Company.java`文件，显示上下文菜单。选择**Insert Code…**选项：

![重构 Java equals()和 hashCode()](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_03_16.jpg)

从弹出菜单中，选择**equals()…**选项，并确保在**Generate equals()**弹出窗口中选择了**idCompany : Integer**字段：

![重构 Java equals()和 hashCode()](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_03_17.jpg)

单击**Generate**以创建新的`equals`方法：

![重构 Java equals()和 hashCode()](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_03_19.jpg)

单击信息图标（圈出的）在第 92 行上显示上下文信息：

![重构 Java equals()和 hashCode()](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_03_20.jpg)

单击**if 语句是多余的**以进一步清理您的代码，并用以下行替换`if`语句：

```java
return Objects.equals(this.idCompany, other.idCompany);
```

`Objects`类是在 Java 1.7 中引入的，它包含用于操作对象的静态实用方法。`Objects.equals`方法考虑了`null`值，并解决了自动生成的`equals`方法可能出现的`//TODO: Warning`问题。来自 Java 1.7 JavaDoc 的`Objects.equals`方法：

### 注意

如果参数彼此相等，则返回`true`，否则返回`false`。因此，如果两个参数都为 null，则返回`true`，如果恰好一个参数为 null，则返回`false`。否则，使用第一个参数的`equals`方法来确定相等性。

现在，您可以以类似的方式替换`Project`，`Task`，`User`和`TaskLog`实体类的自动生成的`equals`方法。

# 总结

在本章中，我们将 3T 数据库反向工程为一组 Java 类。每个 Java 类代表一个带有注释的 JPA 实体，定义了实体之间的关系以及数据库列与 Java 字段的映射。我们通过命名查询定义简要介绍了 JPQL，并介绍了关键的 JPA 注释。

尽管本章介绍了许多关键概念，但 JPA 和 JPQL 的范围还有很多需要学习的地方。JPA 是企业应用程序开发中的关键工具，可以轻松进行增强和与数据库无关的编程。

下一章将介绍**数据访问对象**（**DAO**）设计模式，并使用我们刚刚定义的领域类实现一个强大的数据访问层。我们的 JPA 之旅刚刚开始！


# 第四章：数据访问变得简单

数据访问对象（DAO）设计模式是一种简单而优雅的方式，将数据库持久性与应用程序业务逻辑抽象出来。这种设计确保了企业应用程序的两个核心部分的清晰分离：数据访问层和服务（或业务逻辑）层。DAO 模式是一种广为人知的 Java EE 编程结构，最初由 Sun Microsystems 在其 Java EE 设计蓝图中引起关注，后来被其他编程环境如.NET 框架所采用。

以下图片说明了 DAO 层在整个应用程序结构中的位置：

![数据访问变得简单](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_04_05.jpg)

在 DAO 层更改实现不应以任何方式影响服务层。这是通过定义 DAO 接口来实现的，以封装服务层可以访问的持久性操作。DAO 实现本身对服务层是隐藏的。

# 定义 DAO 接口

Java 编程语言中的接口定义了一组方法签名和常量声明。接口公开行为（或*可以做什么）并定义了实现类承诺提供的合同（*如何做）。我们的 DAO 层将包含每个域对象一个接口和一个实现类。

### 注意

接口的使用在企业编程中经常被误解。有人认为，“为什么在代码库中添加另一组 Java 对象，当它们并不是必需的时候”。接口确实增加了你编写的代码行数，但它们的美妙之处将在你被要求重构一个使用接口编写的老项目时得到赞赏。我曾将基于 SQL 的持久性层迁移到 JPA 持久性层。新的 DAO 实现替换了旧的实现，而服务层几乎没有发生任何重大变化，这要归功于接口的使用。开发是并行进行的，同时支持现有（旧的）实现，直到我们准备好切换到新的实现。这是一个相对轻松的过程，如果没有接口的使用，就不会那么容易实现。

让我们从公司接口开始。

## 添加 CompanyDao 接口

1.  从菜单中导航到“文件”|“新建文件”，并选择“Java 接口”，如下截图所示：![添加 CompanyDao 接口](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_04_01.jpg)

1.  点击“下一步”按钮，并按照以下截图中显示的方式填写详细信息：![添加 CompanyDao 接口](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_04_02.jpg)

接口的名称是`CompanyDao`。我们本可以使用大写首字母缩写`CompanyDAO`来命名此接口。为了符合较新的 Java EE 命名风格，我们决定使用驼峰式缩写形式。最近的例子包括`Html`*、`Json`*和`Xml`*类和接口，例如`javax.json.JsonObject`。我们也相信这种形式更容易阅读。但是，这并不妨碍您使用大写首字母缩写；在 Java EE 中也有许多这样的例子（`EJB`*、`JAXB`*和`JMS`*接口和类等）。无论您选择哪种形式，都要保持一致。不要混合形式，创建`CompanyDAO`和`ProjectDao`接口！

请注意，包`com.gieman.tttracker.dao`目前还不存在，将由系统为您创建。点击“完成”以创建您的第一个接口，之后 NetBeans 将在编辑器中打开该文件。

![添加 CompanyDao 接口](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_04_03.jpg)

公司接口将定义我们在应用程序中将使用的持久性方法。核心方法必须包括执行每个 CRUD 操作的能力，以及适合我们业务需求的任何其他操作。我们将在此接口中添加以下方法：

+   `persist`：此方法插入新的公司记录

+   `merge`：此方法更新现有的公司记录

+   `remove`：这个方法删除公司记录

+   `find`：这个方法使用主键选择公司记录

+   `findAll`：这个方法返回所有公司记录

请注意，JPA 术语`persist`、`merge`、`remove`和`find`等同于 SQL 操作`insert`、`update`、`delete`和`select`。按照以下代码将这些方法添加到`CompanyDao`中：

```java
package com.gieman.tttracker.dao;

import com.gieman.tttracker.domain.Company;
import java.util.List;
public interface CompanyDao {

    public Company find(Integer idCompany);

    public List<Company> findAll();

    public void persist(Company company);

    public Company merge(Company company);

    public void remove(Company company);
}
```

我们已经定义了实现类必须承诺提供的契约。现在我们将添加`ProjectDao`接口。

## 添加 ProjectDao 接口

`ProjectDao`接口将定义一组类似于`CompanyDao`接口的方法：

```java
package com.gieman.tttracker.dao;

import com.gieman.tttracker.domain.Company;
import com.gieman.tttracker.domain.Project;
import java.util.List;

public interface ProjectDao {

    public Project find(Integer idProject);

    public List<Project> findAll();

    public void persist(Project project);

    public Project merge(Project project);

    public void remove(Project project);
}
```

你会注意到`ProjectDao`接口中的所有方法签名与`CompanyDao`接口中的完全相同。唯一的区别在于类类型，其中`Company`被`project`替换。在我们将要添加的所有其他接口（`TaskDao`、`UserDao`和`TaskLogDao`）中，情况也是如此。每个接口都需要一个`find`方法的定义，看起来像下面的代码：

```java
public Company find(Integer idCompany); // in CompanyDao
public Project find(Integer idProject); // in ProjectDao
public Task find(Integer idTask); // in TaskDao
public User find(Integer idUser); // in UserDao
public TaskLog find(Integer idTaskLog); // in TaskLogDao
```

正如你所看到的，每个方法的唯一功能区别是返回类型。对于`persist`、`merge`和`remove`方法也是如此。这种情况非常适合使用 Java 泛型。

## 定义一个通用的 DAO 接口

这个接口将被我们的每个 DAO 接口扩展。`GenericDao`接口使用泛型来定义每个方法，以便可以被每个后代接口使用。然后这些方法将免费提供给扩展接口。与在`CompanyDao`、`ProjectDao`、`TaskDao`、`UserDao`和`TaskLogDao`接口中定义`find(Integer id)`方法不同，`GenericDao`接口定义了通用方法，然后这些方法对所有后代接口都可用。

### 注意

这是一种强大的企业应用程序编程技术，应该在设计或构建应用程序框架时始终考虑。使用 Java 泛型的良好结构设计将简化多年来的变更请求和维护。

通用接口定义如下：

```java
package com.gieman.tttracker.dao;

public interface GenericDao<T, ID> {

    public T find(ID id);

    public void persist(T obj);

    public T merge(T obj);

    public void remove(T obj);
}
```

我们现在可以按照以下方式重构`CompanyDao`接口：

```java
package com.gieman.tttracker.dao;

import com.gieman.tttracker.domain.Company;
import java.util.List;

public interface CompanyDao extends GenericDao<Company, Integer>{

    public List<Company> findAll();

}
```

注意我们如何使用`<Company, Integer>`类型扩展了`GenericDao`接口。`GenericDao`接口中的类型参数`<T, ID>`成为了`CompanyDao`定义中指定的类型的占位符。在`CompanyDao`接口中，`GenericDao`接口中找到的`T`或`ID`将被替换为`Company`和`Integer`。这会自动将`find`、`persist`、`merge`和`remove`方法添加到`CompanyDao`中。

泛型允许编译器在编译时检查类型正确性。这提高了代码的健壮性。关于 Java 泛型的良好解释可以在[`docs.oracle.com/javase/tutorial/extra/generics/index.html`](http://docs.oracle.com/javase/tutorial/extra/generics/index.html)找到。

以类似的方式，我们现在可以重构`ProjectDao`接口：

```java
package com.gieman.tttracker.dao;

import com.gieman.tttracker.domain.Company;
import com.gieman.tttracker.domain.Project;
import java.util.List;

public interface ProjectDao extends GenericDao<Project, Integer>{

    public List<Project> findAll();

}
```

让我们以相同的方式继续添加缺失的接口。

## TaskDao 接口

除了通用的泛型方法，我们还需要一个`findAll`方法。这个接口看起来像下面的代码：

```java
package com.gieman.tttracker.dao;

import com.gieman.tttracker.domain.Project;
import com.gieman.tttracker.domain.Task;
import java.util.List;

public interface TaskDao extends GenericDao<Task, Integer>{

    public List<Task> findAll();    
}
```

## UserDao 接口

我们需要系统中所有用户的列表，以及一些查找方法来根据不同的参数识别用户。当我们开发前端用户界面和服务层功能时，将需要这些方法。`UserDao`接口看起来像下面的代码：

```java
package com.gieman.tttracker.dao;

import com.gieman.tttracker.domain.User;
import java.util.List;

public interface UserDao extends GenericDao<User, String> {

    public List<User> findAll();

    public User findByUsernamePassword(String username, String password);

    public User findByUsername(String username);

    public User findByEmail(String email);
}
```

请注意，`UserDao`接口使用`String` ID 类型扩展了`GenericDao`。这是因为`User`领域实体具有`String`主键类型。

## TaskLogDao 接口

`TaskLogDao`接口还需要定义一些额外的方法，以便允许对任务日志数据进行不同的查看。当我们开发前端用户界面和服务层功能时，这些方法将再次被需要。

```java
package com.gieman.tttracker.dao;

import com.gieman.tttracker.domain.Task;
import com.gieman.tttracker.domain.TaskLog;
import com.gieman.tttracker.domain.User;
import java.util.Date;
import java.util.List;

public interface TaskLogDao extends GenericDao<TaskLog, Integer>{

    public List<TaskLog> findByUser(User user, Date startDate, Date endDate);

    public long findTaskLogCountByTask(Task task);

    public long findTaskLogCountByUser(User user);
}
```

请注意，我们为`TaskLogDao`接口的查找方法命名具有描述性的名称，以标识方法的目的。每个查找方法将用于检索适合应用程序业务需求的任务日志条目的子集。

这涵盖了我们应用程序所需的所有接口。现在是时候为我们的每个接口定义实现了。

# 定义通用的 DAO 实现

我们将再次使用 Java 泛型来定义一个通用的祖先类，该类将由我们的每个实现类（`CompanyDaoImpl`、`ProjectDaoImpl`、`TaskDaoImpl`、`TaskLogDaoImpl`和`UserDaoImpl`）扩展。`GenericDaoImpl`和所有其他实现类将被添加到与我们的 DAO 接口相同的`com.gieman.tttracker.dao`包中。`GenericDaoImpl`中的关键代码行已经突出显示，并将在接下来的章节中进行解释：

```java
package com.gieman.tttracker.dao;

import java.io.Serializable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

public class GenericDaoImpl<T, ID extends Serializable> implements GenericDao<T, ID> {

    final protected Logger logger = LoggerFactory.getLogger(this.getClass());    

    @PersistenceContext(unitName = "tttPU")
    protected EntityManager em;

    private Class<T> type;

    public GenericDaoImpl(Class<T> type1) {
        this.type = type1;
    }

    @Override
    @Transactional(readOnly = true, propagation = Propagation.SUPPORTS)
  public T find(ID id) {
        return (T) em.find(type, id);
    }

    @Override
    @Transactional(readOnly = false, propagation = Propagation.REQUIRED)
    public void persist(T o) {
      em.persist(o);
    }

    @Override
    @Transactional(readOnly = false, propagation = Propagation.REQUIRED)
    public T merge(T o) {

          o = em.merge(o);
      return o;
    }
    @Override
    @Transactional(readOnly = false, propagation = Propagation.REQUIRED)
    public void remove(T o) {

        // associate object with persistence context
        o = merge(o);
        em.remove(o);

    }    
}
```

这个类中有很多新概念！让我们一次解决一个。

## Java 的简单日志门面

Java 的简单日志门面或 SLF4J 是对关键日志框架（包括`java.util.logging`、`log4j`和`logback`）的简单抽象。SLF4J 允许最终用户在部署时通过简单地包含适当的实现库来插入所需的日志记录框架。有关 SLF4J 的更多信息可以在[`slf4j.org/manual.html`](http://slf4j.org/manual.html)找到。日志记录不仅允许开发人员调试代码，还可以提供应用程序内部操作和状态的永久记录。应用程序状态的示例可能是当前内存使用情况、当前已经登录的授权用户数量或等待处理的挂起消息数量。在分析生产错误时，日志文件通常是首要查看的地方，它们是任何企业应用程序的重要组成部分。

尽管默认的 Java 日志记录对于简单的用途已经足够，但对于更复杂的应用程序来说就不合适了。`log4J`框架（[`logging.apache.org/log4j/1.2`](http://logging.apache.org/log4j/1.2)）和`logback`框架（[`logback.qos.ch`](http://logback.qos.ch)）是高度可配置的日志记录框架的例子。`logback`框架通常被认为是`log4j`的继任者，因为它在性能、内存消耗和配置文件的自动重新加载等方面都比`log4j`具有一些关键优势。我们将在我们的应用程序中使用`logback`。

通过将以下依赖项添加到`pom.xml`中，所需的 SLF4J 和`logback`库将被添加到应用程序中：

```java
  <dependency>
   <groupId>ch.qos.logback</groupId>
   <artifactId>logback-classic</artifactId>
   <version>${logback.version}</version>
  </dependency>
```

您还需要将额外的`logback.version`属性添加到`pom.xml`中：

```java
 <properties>
  <endorsed.dir>${project.build.directory}/endorsed</endorsed.dir>
  <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  <spring.version>3.2.4.RELEASE</spring.version>
 <logback.version>1.0.13</logback.version>
 </properties>
```

您现在可以执行**清理和构建项目**以下载`logback-classic`、`logback-core`和`slf4j-api` JAR 文件。这将使我们能够添加`GenericDaoImpl`中定义的导入以及日志记录器定义：

```java
final protected Logger logger = LoggerFactory.getLogger(this.getClass());
```

所有后代类现在都可以使用日志记录器（它被声明为`protected`），但不能更改它（它被声明为`final`）。我们将在第五章中开始使用日志记录器，*使用 Spring 和 JUnit 测试 DAO 层*，在那里我们将详细检查`logback.xml`配置文件。

## @PersistenceContext(unitName = "tttPU")行

这一行注释`EntityManager`接口方法是 Spring 框架在运行时插入或注入`EclipseLink`实现所需的全部。`EntityManager`接口定义了与持久化上下文交互的方法，如`persist`、`merge`、`remove`和`find`。`EntityManager`接口方法的完整列表可以在[`docs.oracle.com/javaee/7/api/javax/persistence/EntityManager.html`](http://docs.oracle.com/javaee/7/api/javax/persistence/EntityManager.html)找到。

我们的持久化上下文在`persistence.xml`中定义，我们将其命名为`tttPU`。这是将`GenericDaoImpl`中的`EntityManager`与持久化上下文绑定的方式，通过`@PersistenceContext`注解的`unitName`属性。持久化上下文是一组实体实例（在我们的应用程序中，这些是`Company`、`Project`、`Task`、`User`和`TaskLog`对象），对于任何持久实体，都有一个唯一的实体实例。在持久化上下文中，实体实例及其生命周期是受管理的。

`EntityManager` API 用于创建和删除持久化实体实例，按主键查找实体，以及对实体进行查询。在我们的`GenericDaoImpl`类中，`EntityManager`实例`em`用于执行通用的 CRUD 操作。因此，每个子类都将可以访问这些方法以及`em`实例本身（它被声明为 protected）。

## `@Transactional`注解

`@Transactional`注解是 Spring 声明式事务管理的基石。它允许您在单个方法级别指定事务行为，并且非常简单易用。这个选项对应用程序代码的影响最小，不需要任何复杂的配置。事实上，它完全是非侵入性的，因为不需要 Java 编码来进行提交和回滚。

Spring 建议只对类（和类的方法）使用`@Transactional`注解，而不是对接口进行注解（完整的解释可以在[`static.springsource.org/spring/docs/3.2.x/spring-framework-reference/html/transaction.html`](http://static.springsource.org/spring/docs/3.2.x/spring-framework-reference/html/transaction.html)找到）。因此，我们将对通用和实现类中的所有适当方法使用以下之一的注解：

```java
@Transactional(readOnly = false, propagation = Propagation.REQUIRED)
@Transactional(readOnly = true, propagation = Propagation.SUPPORTS)
```

`@Transactional`注解是指定方法必须具有事务语义的元数据。例如，我们可以定义元数据，定义在调用此方法时启动全新的只读事务，挂起任何现有事务。默认的`@Transactional`设置如下：

+   - `propagation`设置为`Propagation.REQUIRED`

+   - `readOnly`为 false

定义所有属性，包括默认设置，是一个好习惯，就像我们之前做的那样。让我们详细地检查这些属性。

### Propagation.REQUIRED 属性

- 默认值为不指定`propagation`设置的事务。如果存在当前事务，则支持此属性，如果不存在事务，则创建一个新的事务。这确保了`Propagation.REQUIRED`注解的方法始终有一个有效的事务可用，并且应该在持久化存储中修改数据时使用。这个属性通常与`readOnly=false`结合使用。

### - Propagation.SUPPORTS 属性

如果存在当前事务，则支持此属性，如果不存在事务，则以非事务方式执行。如果注解的方法不修改数据（不会对数据库执行 insert、update 或 delete 语句），则应该使用`Propagation.SUPPORTS`属性。这个属性通常与`readOnly=true`结合使用。

### readOnly 属性

这只是一个提示，用于实际事务子系统，以便在可能的情况下优化执行的语句。可能事务管理器无法解释此属性。然而，对于自我记录的代码来说，包含此属性是一个很好的做法。

### 其他事务属性

Spring 允许我们使用额外的选项来微调事务属性，这超出了本书的范围。浏览之前提到的链接，了解更多关于如何在更复杂的情况下管理事务的信息，包括多个事务资源。

# 定义 DAO 实现

以下 DAO 实现将从`GenericDaoImpl`继承核心 CRUD 操作，并根据实现的接口添加自己的特定于类的方法。每个方法将使用`@Transactional`注解来定义适当的事务行为。

## `CompanyDaoImpl`类

我们的`CompanyDaoImpl`类的完整列表如下：

```java
package com.gieman.tttracker.dao;

import com.gieman.tttracker.domain.Company;
import java.util.List;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Repository("companyDao")
@Transactional
public class CompanyDaoImpl extends GenericDaoImpl<Company, Integer> 
    implements CompanyDao {

    public CompanyDaoImpl() {
        super(Company.class);
    }

    @Override
    @Transactional(readOnly = true, propagation = Propagation.SUPPORTS)
    public List<Company> findAll() {
        return em.createNamedQuery("Company.findAll")
                .getResultList();
    }    
}
```

首先要注意的是`@Repository("companyDao")`注解。这个注解被 Spring 用来在应用程序加载时自动检测和处理 DAO 对象。Spring API 将这个注解定义如下：

### 注意

它表示一个带注解的类是一个`Repository`，最初由领域驱动设计（Evans, 2003）定义为一种模拟对象集合的存储、检索和搜索行为的机制。

注解的目的是允许 Spring 通过`classpath`扫描自动检测实现类，并处理该类以进行数据访问异常转换（Spring 用于将数据库异常消息从底层实现中抽象出来）。Spring 应用程序将持有实现类的引用，键为`companyDao`。最佳实践是将键值与实现的接口名称匹配。

`CompanyDaoImpl`类还引入了在上一章的反向工程过程中定义的 JPA 命名查询的使用。方法调用`em.createNamedQuery("Company.findAll")`创建了持久化引擎中由唯一标识符`"Company.findAll"`定义的命名查询。这个命名查询是在`Company`类中定义的。调用`getResultList()`执行了针对数据库的查询，返回了一个`java.util.List`的 Company 对象。现在让我们来审查一下`Company`类中的命名查询定义：

```java
@NamedQuery(name = "Company.findAll", query = "SELECT c FROM Company c")
```

我们将对这个命名查询进行微小的更改，以按照`companyName`的升序排列结果。这将需要在查询语句中添加`ORDER BY`子句。`Company`类中的最终命名查询定义现在看起来像以下代码：

```java
@NamedQueries({
    @NamedQuery(name = "Company.findAll", query = "SELECT c FROM Company c ORDER BY c.companyName ASC "),
    @NamedQuery(name = "Company.findByIdCompany", query = "SELECT c FROM Company c WHERE c.idCompany = :idCompany"),
    @NamedQuery(name = "Company.findByCompanyName", query = "SELECT c FROM Company c WHERE c.companyName = :companyName")})
```

## `ProjectDaoImpl`类

这个实现被定义为：

```java
package com.gieman.tttracker.dao;

import com.gieman.tttracker.domain.Company;
import com.gieman.tttracker.domain.Project;
import java.util.List;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Repository("projectDao")
@Transactional
public class ProjectDaoImpl extends GenericDaoImpl<Project, Integer> 
    implements ProjectDao {

    public ProjectDaoImpl() {
        super(Project.class);
    }

    @Override
    @Transactional(readOnly = true, propagation = Propagation.SUPPORTS)
    public List<Project> findAll() {
        return em.createNamedQuery("Project.findAll")
                .getResultList();
    }    
}
```

再次，我们将在`Project`类的`Project.findAll`命名查询中添加`ORDER BY`子句：

```java
@NamedQuery(name = "Project.findAll", query = "SELECT p FROM Project p ORDER BY p.projectName")
```

## `TaskDaoImpl`类

这个类被定义为：

```java
package com.gieman.tttracker.dao;

import com.gieman.tttracker.domain.Project;
import com.gieman.tttracker.domain.Task;
import java.util.List;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Repository("taskDao")
@Transactional
public class TaskDaoImpl extends GenericDaoImpl<Task, Integer> implements TaskDao {

    public TaskDaoImpl() {
        super(Task.class);
    }

    @Override
    @Transactional(readOnly = true, propagation = Propagation.SUPPORTS)
    public List<Task> findAll() {
        return em.createNamedQuery("Task.findAll")
                .getResultList();
    }
}
```

再次，我们将在`Task`类的`Task.findAll`命名查询中添加`ORDER BY`子句：

```java
@NamedQuery(name = "Task.findAll", query = "SELECT t FROM Task t ORDER BY t.taskName")
```

## `UserDaoImpl`类

这个`UserDaoImpl`类将需要在`User`领域类中添加一个额外的命名查询，以测试用户的登录凭据（用户名/密码组合）。`UserDaoImpl`类的定义如下：

```java
package com.gieman.tttracker.dao;

import com.gieman.tttracker.domain.User;
import java.util.List;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Repository("userDao")
@Transactional
public class UserDaoImpl extends GenericDaoImpl<User, String> implements UserDao {

    public UserDaoImpl() {
        super(User.class);
    }

    @Override
    @Transactional(readOnly = true, propagation = Propagation.SUPPORTS)
    public List<User> findAll() {
        return em.createNamedQuery("User.findAll")
                .getResultList();
    }

    @Override
    @Transactional(readOnly = true, propagation = Propagation.SUPPORTS)
    public User findByUsernamePassword(String username, String password) {

        List<User> users = em.createNamedQuery("User.findByUsernamePassword")
                .setParameter("username", username)
                .setParameter("password", password)
                .getResultList();

        return (users.size() == 1 ? users.get(0) : null);
    }    

    @Override
    @Transactional(readOnly = true, propagation = Propagation.SUPPORTS)
    public User findByUsername(String username) {
        List<User> users = em.createNamedQuery("User.findByUsername")
                .setParameter("username", username)
                .getResultList();

        return (users.size() == 1 ? users.get(0) : null);
    }    

    @Override
    @Transactional(readOnly = true, propagation = Propagation.SUPPORTS)
    public User findByEmail(String email) {

        List<User> users = em.createNamedQuery("User.findByEmail")
                .setParameter("email", email)
                .getResultList();

        return (users.size() == 1 ? users.get(0) : null);
    }    
}
```

缺少的命名查询是`User.findByUsernamePassword`，用于验证具有给定用户名和密码的用户。查询定义必须添加到`User`类中，如下所示：

```java
@NamedQuery(name = "User.findByUsernamePassword", query = "SELECT u FROM User u WHERE u.password = :password AND (u.email = :username OR u.username = :username)")
```

请注意，这个定义允许用户通过用户名或电子邮件字段进行匹配。正如在 Web 应用程序中的常见做法一样，用户可以使用他们的唯一登录名（用户名）或他们的电子邮件地址进行登录。

`findByEmail`、`findByUsername`和`findByUsernamePassword`方法只能返回`null`（未找到匹配）或单个结果，因为数据库中这些唯一字段不可能有多条记录。我们可以使用类似以下的代码来代替使用`getResultList()`方法来检索结果列表并测试列表大小是否为一：

```java
public User findByEmail(String email) {

  User user = (User) em.createNamedQuery("User.findByEmail")
      .setParameter("email", email)
      .getSingleResult();

  return user;
}
```

`getSingleResult()`方法返回确切的一个结果，如果找不到单个结果，则会抛出异常。您还会注意到需要将返回的结果转换为所需的`User`类型。调用方法还需要捕获从`getSingleResult()`方法抛出的任何异常，除非之前给出的示例代码更改为捕获异常。

```java
public User findByEmail(String email) {

  User user = null;

  try {
    user = (User) em.createNamedQuery("User.findByEmail")
      .setParameter("email", email)
      .getSingleResult();

  } catch(NoResultException nre){

 }
  return user;
}
```

我们相信我们的`UserDaoImpl`接口中的代码比使用`try`/`catch`函数包装`getSingleResult()`方法的先前示例更清晰。然而，在两种情况下，如果找不到记录，该方法都会返回`null`。

### 注意

在企业编程中应谨慎使用异常，只能在真正的异常情况下使用。除非异常表示调用代码无法恢复的情况，否则应避免抛出异常。如果情况不如预期，返回`null`（或者在适当的情况下返回 true/false）会更清晰。

我们不认为无法按 ID 或电子邮件或电子邮件地址找到记录是一个异常情况；可能是不同的用户已删除了记录，或者根本没有使用指定电子邮件的记录。返回`null`清楚地表明未找到记录，而无需抛出异常。

无论您是抛出异常来指示找不到记录，还是使用`null`作为我们的首选，您的 API 都应该记录下行为。例如，`UserDaoImpl.findByUsernamePassword`方法可以记录如下：

```java
/**
 * Find a User with the username/password combination or return null
 * if a valid user could not be found.
 * @param username
 * @param password
 * @return valid User object or null if not found.
 */
```

您的 API 的用户将了解预期的行为并相应地编写其交互。

## `TaskLogDaoImpl`类

我们应用程序中的最终 DAO 类如下：

```java
package com.gieman.tttracker.dao;

import com.gieman.tttracker.domain.Task;
import com.gieman.tttracker.domain.TaskLog;
import com.gieman.tttracker.domain.User;
import java.util.Date;
import java.util.List;
import javax.persistence.TemporalType;

public class TaskLogDaoImpl extends GenericDaoImpl<TaskLog, Integer> implements TaskLogDao {

    public TaskLogDaoImpl() {
        super(TaskLog.class);
    }

    @Override
    public List<TaskLog> findByUser(User user, Date startDate, Date endDate) {
        return em.createNamedQuery("TaskLog.findByUser")
                .setParameter("user", user)
                .setParameter("startDate", startDate, TemporalType.DATE)
                .setParameter("endDate", endDate, TemporalType.DATE)
                .getResultList();
    }

    @Override
    public long findTaskLogCountByTask(Task task) {
        Long count = (Long) em.createNamedQuery("TaskLog.findTaskLogCountByTask")
                .setParameter("task", task)
                .getSingleResult();
        return count;
    }

    @Override
    public long findTaskLogCountByUser(User user) {
        Long count = (Long) em.createNamedQuery("TaskLog.findTaskLogCountByUser")
                .setParameter("user", user)
                .getSingleResult();

        return count;
    }
}
```

这一次，我们将重构`TaskLog`命名查询如下：

```java
@NamedQueries({
    @NamedQuery(name = "TaskLog.findByUser", query = "SELECT tl FROM TaskLog tl WHERE tl.user = :user AND tl.taskLogDate BETWEEN :startDate AND :endDate order by tl.taskLogDate ASC"),
    @NamedQuery(name = "TaskLog.findTaskLogCountByTask", query = "SELECT count(tl) FROM TaskLog tl WHERE tl.task = :task "),
    @NamedQuery(name = "TaskLog.findTaskLogCountByUser", query = "SELECT count(tl) FROM TaskLog tl WHERE tl.user = :user ")
})
```

我们已删除几个不需要的查询，并添加了三个新的查询，如所示。`TaskLog.findByUser`查询将用于列出分配给用户的任务日志的给定日期范围。请注意在`TaskLogDaoImpl.findByUser`方法中设置参数时，使用`TemporalType.DATE`来确保严格的日期比较，忽略任何时间组件（如果存在）。

`TaskLog.findTaskLogCountByTask`和`TaskLog.findTaskLogCountByUser`命名查询将在我们的服务层中用于测试是否允许删除。我们将实施检查以确保如果分配了有效的任务日志，则用户或任务可能不会被删除。

# 更好的领域层

让我们现在重新审视在第三章中创建的领域层，*使用 JPA 逆向工程领域层*。为这一层中的所有实体定义一个祖先类不仅是最佳实践，而且还将使我们的领域层在未来更容易增强。我们的祖先类定义如下：

```java
package com.gieman.tttracker.domain; 
import java.io.Serializable;

public abstract class AbstractEntity implements Serializable{

}
```

尽管这个类有一个空的实现，但我们将在随后的章节中添加功能。

我们还将定义一个适当的接口，该接口具有一个通用方法来返回实体的 ID：

```java
package com.gieman.tttracker.domain;

public interface EntityItem<T> {

    public T getId();

}
```

我们的领域层现在可以扩展我们的基本`AbstractEntity`类并实现`EntityItem`接口。对我们的`Company`类所需的更改如下：

```java
public class Company extends AbstractEntity implements EntityItem<Integer> {

// many more lines of code here

 @Override
 public Integer getId() {
 return idCompany;
 } 
}
```

以类似的方式，我们可以更改剩余的领域类：

```java
public class Project extends AbstractEntity implements EntityItem<Integer> {

// many more lines of code here

 @Override
 public Integer getId() {
 return idProject;
 } 
}
public class Task extends AbstractEntity implements EntityItem<Integer> {

// many more lines of code here

 @Override
 public Integer getId() {
 return idTask;
 } 
}
public class User extends AbstractEntity implements EntityItem<String> {

// many more lines of code here

 @Override
 public String getId() {
 return username;
 } 
}
public class TaskLog extends AbstractEntity implements EntityItem<Integer> {

// many more lines of code here

 @Override
 public Integer getId() {
 return idTaskLog;
 } 
}
```

我们现在将为领域层中的未来变更做好充分准备。

# 练习-一个简单的变更请求

这个简单的练习将再次展示泛型的强大。现在，插入到数据库中的每条记录都应该使用`logger.info()`记录日志，消息为：

```java
The "className" record with ID=? has been inserted
```

此外，删除的记录应该使用`logger.warn()`记录日志，消息为：

```java
The "className" record with ID=? has been deleted
```

在这两种情况下，`?`标记应该被插入或删除的实体的 ID 替换，而`className`标记应该被插入或删除的实体的类名替换。使用泛型时，这是一个微不足道的改变，因为这段代码可以添加到`GenericDaoImpl`类的`persist`和`remove`方法中。如果不使用泛型，每个`CompanyDaoImpl`、`ProjectDaoImpl`、`TaskDaoImpl`、`UserDaoImpl`和`TaskLogDaoImpl`类都需要进行这个改变。考虑到企业应用程序可能在 DAO 层中表示 20、30、40 个或更多的表，这样一个微不足道的改变在没有使用泛型的情况下可能并不那么微不足道。

您的任务是按照之前概述的实现更改请求。请注意，这个练习将向您介绍`instanceof`运算符。

# 总结

本章介绍了数据访问对象设计模式，并定义了一组接口，这些接口将在我们的 3T 应用程序中使用。DAO 设计模式清楚地将持久层操作与应用程序的业务逻辑分离开来。正如将在下一章中介绍的那样，这种清晰的分离确保了数据访问层易于测试和维护。

我们还介绍了 Java 泛型作为一种简化应用程序设计的技术，通过将通用功能移动到祖先。`GenericDao`接口和`GenericDaoImpl`类定义并实现了将免费提供给扩展组件的方法。我们的实现还介绍了 SLF4J、事务语义和使用 JPA 命名查询。

我们的旅程现在将继续进行，第五章，*使用 Spring 和 JUnit 测试 DAO 层*，在那里我们将配置一个测试环境，并为我们的 DAO 实现开发测试用例。
