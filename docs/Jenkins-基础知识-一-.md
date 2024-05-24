# Jenkins 基础知识（一）

> 原文：[`zh.annas-archive.org/md5/b6fa1c87ed9f6def1cfd7f79d997c56b`](https://zh.annas-archive.org/md5/b6fa1c87ed9f6def1cfd7f79d997c56b)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

DevOps 是 2015 年的热门词汇，并且根据多家研究机构的市场趋势预测，未来几年仍将如此。在 DevOps 文化中，业务所有者、开发团队、运维团队和 QA 团队协同工作，以持续且高效的方式交付成果。它使组织能够更快地抓住机遇，并缩短将客户反馈纳入新功能开发或创新的时间。DevOps 的最终目标是缩短从初始概念到以生产就绪应用程序形式呈现的概念结果之间的时间。DevOps 关注应用程序交付、新功能开发、错误修复、测试和维护版本。它提高了效率、安全性、可靠性、可预测性以及更快的开发和部署周期。它涵盖了从开发、测试、运维到发布的所有 SDLC 阶段。

持续集成（CI）和持续交付（CD）是 DevOps 文化的重要组成部分。Jenkins 是一个功能全面的技术平台，使用户能够实施 CI 和 CD。这有助于用户通过自动化应用程序交付生命周期来提供更好的应用程序。CI 包括构建、测试和打包过程的自动化。CD 包括跨不同环境的应用程序交付管道。Jenkins 使用户能够在敏捷环境中为软件开发利用持续集成服务。持续集成系统是敏捷团队的重要组成部分，因为它们有助于强化敏捷开发的原理。持续集成是 DevOps 文化的重要组成部分，因此，许多开源和商业的持续交付工具都利用 Jenkins 或提供集成点。Jenkins 使敏捷团队能够专注于工作和创新，通过自动化构建、制品管理和部署过程，而不是担心手动过程。它可以用于基于 Apache Ant 和 Maven 2 / Maven 3 项目的自由风格软件项目构建。它还可以执行 Windows 批处理命令和 shell 脚本。

安装 Jenkins 有多种方式，并且可以在不同的平台上使用，如 Windows 和 Linux。Jenkins 以 Windows、FreeBSD、OpenBSD、Red Hat、Fedora、CentOS、Ubuntu、Debian、Mac OS X、openSUSE、Solaris、OpenIndiana、Gentoo 的原生包形式提供，或者以 WAR 文件的形式提供。使用 Jenkins 最快捷简便的方式是使用 WAR 文件。它可以通过使用插件轻松定制。有各种类型的插件可根据特定需求定制 Jenkins。插件类别包括源代码管理（例如，Git 插件、CVS 插件、Bazaar 插件）、构建触发器（例如，加速构建现在插件和构建流插件）、构建报告（例如，代码扫描器插件和磁盘使用插件）、身份验证和用户管理（例如，活动目录插件和 Github OAuth 插件）、集群管理和分布式构建（例如，亚马逊 EC2 插件和 Azure 从属插件）等。

Jenkins 因其允许用户管理和控制构建、测试、打包和静态代码分析等阶段而深受用户欢迎。它赢得了 2011 年 InfoWorld Bossies 奖、2011 年 O'Reilly 开源奖、ALM&SCM 等奖项。Jenkins 的主要用户包括 NASA、Linkedin、eBay 和 Mozilla 基金会。

以下是使 Jenkins 非常受欢迎的一些特点：

+   一个具有 Web GUI 的开源工具。

+   基于 Java 的持续构建系统——易于编写插件。

+   高度可配置的工具——基于插件的架构，支持多种技术、仓库、构建工具和测试工具。

+   Jenkins 用户社区庞大且活跃，拥有超过 1,000 个开源插件。

+   支持.Net、iOS、Android 和 Ruby 开发的持续集成。

+   支持常见的 SCM 系统，如 SVN、CVS、Git 等。

+   支持常见的测试框架，如 Junit、Selenium 等。

Jenkins 通过自动化跨不同阶段（如构建、测试、代码分析等）加速应用程序开发过程。它还使用户能够实现应用程序交付生命周期的端到端自动化。

# 本书涵盖的内容

第一章，*探索 Jenkins*，详细介绍了持续集成的基本概念，并提供了 Jenkins 的概览。本章还描述了 Jenkins 的安装和配置过程，并快速浏览了 Jenkins 的一些关键特性和插件安装。此外，本章还将涵盖部署管道的内容，而其余章节将详细介绍其实施。

第二章，*代码仓库和构建工具的安装与配置*，详细描述了如何为应用程序生命周期管理准备运行时环境，并将其与 Jenkins——一个开源的持续集成工具——进行配置。它将介绍如何将 Eclipse 与 SVN 和 Git 等代码仓库集成，为部署管道中的持续集成创建基础，这在第一章，*探索 Jenkins*中有所解释。

第三章，*Jenkins、SVN 与构建工具的集成*，详细描述了如何为 Java 应用程序创建和配置构建作业，以及如何运行构建作业和单元测试案例。它涵盖了从运行构建到创建部署所需的发行文件或 WAR 文件的所有方面。

第四章，*实施自动化部署*，在部署管道中向前迈进一步，通过在本地或远程应用程序服务器上部署工件。它将深入探讨自动化部署和持续交付过程，并介绍如何使用 Jenkins 在公共云平台上部署应用程序。

第五章，*托管 Jenkins*，描述了如何在平台即服务（PaaS）模型上使用 Jenkins，该模型由 Red Hat OpenShift 和 CloudBees 等流行的 PaaS 提供商提供。以 CloudBees 为例，本章还详细介绍了不同客户如何根据其需求使用 Jenkins。本章将探讨如何在 Jenkins 中使用与云相关的插件以有效利用 Jenkins。

第六章，*管理代码质量和通知*，介绍了如何将静态代码分析行为集成到 Jenkins 中。代码质量是影响应用程序效能的极其重要的特性，通过与 Sonar、CheckStyle、FindBug 等工具集成，你可以深入了解代码中的问题部分。

第七章，*管理和监控 Jenkins*，深入探讨了 Jenkins 节点的管理以及使用 Java Melody 监控它们以提供资源利用情况的详细信息。本章还涵盖了如何监控为 Java 应用程序配置的构建作业，以及如何通过备份来管理这些配置。此外，本章讨论了 Jenkins 中可用的基本安全配置，以实现更好的访问控制和授权。

第八章，*超越 Jenkins 基础——利用“必备”插件*，涵盖了 Jenkins 在特定场景下极其有用的高级用法。本章介绍了基于场景的使用案例以及有助于开发和运维团队的具体插件，以更好地利用 Jenkins。

# 本书所需条件

本书假设您至少熟悉 Java 编程语言。掌握核心 Java 和 JEE 知识是必要的。对程序逻辑有深刻理解将为您在使用 Jenkins 插件和编写 shell 命令时提供背景，从而提高效率。

由于应用程序开发生命周期通常会涉及许多工具，因此了解诸如 SVN、Git 等版本控制系统；如 Eclipse 等 IDE 工具；以及如 Ant 和 Maven 等构建工具的知识是必要的。

了解代码分析工具将使配置和集成工作更轻松；然而，对于本书中的练习来说，这并不是极其关键的。大多数配置步骤都已清晰说明。

本书将引导您完成在基于 Windows 和 Linux 的主机上安装 Jenkins 的步骤。为了立即取得成功，您需要拥有运行现代 Linux 版本的宿主机的管理员权限；CentOS 6.x 将用于演示目的。如果您是更有经验的读者，那么几乎任何最新发布的发行版都能同样适用（但您可能需要做一些本书未详细说明的额外工作）。如果您没有访问专用 Linux 主机的权限，虚拟主机（或多个虚拟主机）在 VirtualBox 或 VMware 工作站等虚拟化软件中运行也可以。

此外，您需要访问互联网以下载您尚未拥有的插件并安装 Jenkins。

# 本书适合的读者

本书面向参与应用程序开发生命周期并寻求自动化流程的开发者和系统管理员。开发者、技术负责人、测试人员和运维专业人士是本书的目标读者，旨在帮助他们快速上手 Jenkins。读者了解开发和运维团队面临的问题，因为他们是应用程序生命周期管理过程中的利益相关者。启动 Jenkins 的原因在于理解在持续集成、自动化测试案例执行和持续交付中贡献的重要性，以实现有效的应用程序生命周期管理。

# 约定

在本书中，您会发现多种文本样式，用以区分不同类型的信息。以下是这些样式的示例及其含义的解释。

文本中的代码词汇、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 手柄等，如下所示："通过执行`git commit -m "初始提交" –a`来提交。"

任何命令行输入或输出如下所示：

```
[root@localhost testmit]# service httpd restart
Stopping httpd:
[  OK  ]

```

新术语和重要词汇以粗体显示。屏幕上出现的词汇，如菜单或对话框中的词汇，在文本中这样显示："一旦构建成功，请在构建作业中验证**工作区**。"

### 注意

警告或重要提示以这样的方框形式出现。

### 提示

提示和技巧这样显示。


# 第一章：探索 Jenkins

|   | *"持续的努力——而非力量或智慧——是解锁我们潜能的关键。"* |   |
| --- | --- | --- |
|   | --*温斯顿·丘吉尔* |

Jenkins 是一个用 Java 编写的开源应用程序，它是最受欢迎的**持续集成**（**CI**）工具之一，用于构建和测试各种项目。在本章中，我们将快速概览 Jenkins、其核心特性及其对 DevOps 文化的影响。在我们开始使用 Jenkins 之前，我们需要安装它。本章提供了一个详细的安装指南。安装 Jenkins 非常简单，且与操作系统版本无关。

我们还将学习 Jenkins 的基本配置。我们将快速浏览 Jenkins UI 的一些关键部分和插件安装。本章还将涵盖 DevOps 流水线以及后续章节将如何实现它。

具体来说，本章将讨论以下主题：

+   介绍 Jenkins 及其特性

+   在 Windows 和 CentOS 操作系统上安装 Jenkins

+   快速浏览 Jenkins 仪表板

+   如何在 Jenkins 中更改配置设置

+   什么是部署流水线

各就各位，预备，开始！

# 介绍 Jenkins 及其特性

首先，让我们理解什么是持续集成。CI 是近年来最流行的应用开发实践之一。开发者将错误修复、新功能开发或创新功能集成到代码仓库中。CI 工具通过自动化构建和自动化测试执行来验证集成过程，以检测应用程序当前源代码中的问题，并提供快速反馈。

![Jenkins 及其特性介绍](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_01_01.jpg)

Jenkins 是一个简单、可扩展且用户友好的开源工具，为应用程序开发提供 CI 服务。Jenkins 支持 StarTeam、Subversion、CVS、Git、AccuRev 等 SCM 工具。Jenkins 可以构建 Freestyle、Apache Ant 和 Apache Maven 项目。

插件的概念使 Jenkins 更具吸引力，易于学习且易于使用。有多种类别的插件可用，例如源代码管理、从属启动器和控制器、构建触发器、构建工具、构建通知、构建报告、其他构建后操作、外部站点/工具集成、UI 插件、身份验证和用户管理、Android 开发、iOS 开发、.NET 开发、Ruby 开发、库插件等。

Jenkins 定义了接口或抽象类，这些接口或抽象类模拟了构建系统的一个方面。接口或抽象类定义了需要实现的内容；Jenkins 使用插件来扩展这些实现。

### 注意

要了解更多关于所有插件的信息，请访问 [`wiki.jenkins-ci.org/x/GIAL`](https://wiki.jenkins-ci.org/x/GIAL)。

要了解如何创建新插件，请访问 [`wiki.jenkins-ci.org/x/TYAL`](https://wiki.jenkins-ci.org/x/TYAL)。

要下载不同版本的插件，请访问[`updates.jenkins-ci.org/download/plugins/`](https://updates.jenkins-ci.org/download/plugins/)。

## 功能

Jenkins 是市场上最受欢迎的 CI 服务器之一。其受欢迎的原因如下：

+   在不同操作系统上易于安装。

+   易于升级——Jenkins 的发布周期非常快。

+   简单易用的用户界面。

+   通过使用第三方插件轻松扩展——超过 400 个插件。

+   在用户界面中轻松配置设置环境。还可以根据喜好自定义用户界面。

+   主从架构支持分布式构建，以减轻 CI 服务器的负载。

+   Jenkins 附带围绕 JUnit 构建的测试框架；测试结果以图形和表格形式提供。

+   基于 cron 表达式的构建调度（欲了解更多关于 cron 的信息，请访问[`en.wikipedia.org/wiki/Cron`](http://en.wikipedia.org/wiki/Cron)）。

+   预构建步骤中执行 Shell 和 Windows 命令。

+   与构建状态相关的通知支持。

# 在 Windows 和 CentOS 上安装 Jenkins

1.  前往[`jenkins-ci.org/`](https://jenkins-ci.org/)。在 Jenkins 网站首页找到**下载 Jenkins**部分。![在 Windows 和 CentOS 上安装 Jenkins](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_01_02.jpg)

1.  根据您的操作系统下载`war`文件或原生包。运行 Jenkins 需要 Java 安装。

1.  根据您的操作系统安装 Java，并相应地设置 JAVA_HOME 环境变量。

## 在 Windows 上安装 Jenkins

1.  选择适用于 Windows 的原生包。它将下载`jenkins-1.xxx.zip`。在我们的例子中，它将下载`jenkins-1.606.zip`。解压后，您将得到`setup.exe`和`jenkins-1.606.msi`文件。

1.  点击`setup.exe`，并按顺序执行以下步骤。在欢迎屏幕上，点击**下一步**：![在 Windows 上安装 Jenkins](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_01_03.jpg)

1.  选择目标文件夹并点击**下一步**。

1.  点击**安装**开始安装。请等待安装向导安装 Jenkins。![在 Windows 上安装 Jenkins](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_01_04.jpg)

1.  完成 Jenkins 安装后，点击**完成**按钮。![在 Windows 上安装 Jenkins](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_01_05.jpg)

1.  通过在已安装 Jenkins 的系统上打开 URL `http://<ip_address>:8080`来验证 Windows 机器上的 Jenkins 安装。![在 Windows 上安装 Jenkins](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_01_06.jpg)

## 在 CentOS 上安装 Jenkins

1.  要在 CentOS 上安装 Jenkins，请将 Jenkins 仓库定义下载到本地系统的`/etc/yum.repos.d/`目录，并导入密钥。

1.  使用`wget -O /etc/yum.repos.d/jenkins.repo http://pkg.jenkins-ci.org/redhat/jenkins.repo`命令下载`repo`。![在 CentOS 上安装 Jenkins](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_01_07.jpg)

1.  现在，运行`yum install Jenkins`；它将解决依赖关系并提示安装。![在 CentOS 上安装 Jenkins](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_01_08.jpg)

1.  回复`y`，它将下载所需的软件包以在 CentOS 上安装 Jenkins。通过执行`service jenkins status`命令来验证 Jenkins 状态。最初，它将处于停止状态。通过在终端中执行`service jenkins start`来启动 Jenkins。![在 CentOS 上安装 Jenkins](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_01_09.jpg)

1.  通过在已安装 Jenkins 的系统上打开 URL `http://<ip_address>:8080`来验证 CentOS 机器上的 Jenkins 安装。![在 CentOS 上安装 Jenkins](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_01_10.jpg)

## 将 Jenkins 作为 Web 应用程序安装

1.  从[`jenkins-ci.org/`](http://jenkins-ci.org/)下载**Java Web 档案(.war)**（最新版本(1.606)）。

1.  将`jenkins.war`复制到您的虚拟或物理机中。根据操作系统打开命令提示符或终端。在我们的例子中，我们将它复制到一个 CentOS 虚拟机的目录中。![将 Jenkins 作为 Web 应用程序安装](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_01_11.jpg)

1.  打开命令提示符并执行`java –jar Jenkins.war`命令。通过在已安装 Jenkins 的系统上打开`http://<ip_address>:8080` URL 来验证系统上的 Jenkins 安装。![将 Jenkins 作为 Web 应用程序安装](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_01_12.jpg)

# Jenkins 仪表板的快速入门之旅

1.  在 Jenkins 仪表板上，点击**创建新作业**或**新建项**以创建自由风格或基于 Maven 的 CI 项目。![Jenkins 仪表板的快速入门之旅](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_01_13.jpg)

1.  要验证系统属性，请访问`http://<ip_address>:8080/systeminfo`，或点击**管理 Jenkins**，然后点击**系统信息**以获取环境信息以协助故障排除。![Jenkins 仪表板的快速入门之旅](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_01_14.jpg)

# 如何在 Jenkins 中更改配置设置

1.  点击仪表板上的**管理 Jenkins**链接以配置系统、安全、管理插件、从节点、凭证等。![如何在 Jenkins 中更改配置设置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_01_15.jpg)

1.  点击**配置系统**链接以配置 Java、Ant、Maven 和其他第三方产品的相关信息。![如何在 Jenkins 中更改配置设置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_01_16.jpg)

1.  Jenkins 使用 Groovy 作为其脚本语言。要在 Jenkins 仪表板上执行任意脚本进行管理/故障排除/诊断，请前往仪表板上的**管理 Jenkins**链接，点击**脚本控制台**，并运行`println(Jenkins.instance.pluginManager.plugins)`。![如何在 Jenkins 中更改配置设置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_01_17.jpg)

1.  要验证系统日志，请前往仪表板上的**管理 Jenkins**链接，点击**系统日志**链接，或访问`http://localhost:8080/log/all`。![如何在 Jenkins 中更改配置设置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_01_18.jpg)

1.  要获取有关 Jenkins 中第三方库的更多信息——版本和许可证信息，请点击仪表板上的**管理 Jenkins**链接，然后点击**关于 Jenkins**链接。![如何在 Jenkins 中更改配置设置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_01_19.jpg)

# 什么是部署管道？

应用程序开发生命周期传统上是一个漫长且手动的过程。此外，它需要开发和运维团队之间的有效协作。部署管道展示了应用程序开发生命周期中涉及的自动化，包括自动化构建执行和测试执行、向利益相关者通知以及在不同运行时环境中的部署。实际上，部署管道是 CI 和持续交付的结合，因此是 DevOps 实践的一部分。下图描绘了部署管道过程：

![什么是部署管道？](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_01_20.jpg)

开发团队成员将代码检入源代码仓库。诸如 Jenkins 之类的 CI 产品被配置为从代码仓库轮询变更。仓库中的变更被下载到本地工作区，Jenkins 触发自动化构建过程，该过程由 Ant 或 Maven 辅助。自动化测试执行或单元测试、静态代码分析、报告以及成功或失败的构建过程通知也是 CI 过程的一部分。

一旦构建成功，它可以被部署到不同的运行时环境，如测试、预生产、生产等。在 JEE 应用程序中部署`war`文件通常是部署管道的最后阶段。

部署管道最大的好处之一是更快的反馈循环。在应用程序早期阶段识别问题，并且不依赖于手动努力，使得整个端到端过程更加有效。

在接下来的章节中，我们将看到如何使用 Jenkins 来实施现代化 IT 中的 CI 实践。

### 注意

欲了解更多信息，请访问[`martinfowler.com/bliki/DeploymentPipeline.html`](http://martinfowler.com/bliki/DeploymentPipeline.html)和[`www.informit.com/articles/article.aspx?p=1621865&seqNum=2`](http://www.informit.com/articles/article.aspx?p=1621865&seqNum=2)。

# 自测题

Q1. 什么是 Jenkins？

1.  一个持续集成产品

1.  一个持续交付产品

Q2. 是什么使得 Jenkins 可扩展？

1.  插件

1.  开源发布

Q3. 使用哪个命令来运行 Jenkins 安装文件的`war`格式？

1.  java –jar `Jenkins.war`

1.  java –j `Jenkins.war`

Q4. 如何在 Jenkins 仪表板上获取系统信息？

1.  访问`http://<ip_address>:8080/manage`

1.  访问`http://<ip_address>:8080/systeminfo`

Q5. 如何在 Jenkins 仪表板上更改全局配置设置？

1.  点击仪表板上的**管理 Jenkins**链接

1.  点击仪表板上的**凭据**链接

Q6. 什么是部署管道？

1.  持续集成实践

1.  持续交付实践

1.  展示应用程序开发生命周期中涉及的自动化

1.  以上都不是

Q7. 解释部署管道的好处是什么？

1.  更快的反馈循环

1.  在应用程序早期阶段识别问题

1.  不依赖于人工努力

1.  以上所有

# 总结

恭喜！我们已到达本章末尾，因此我们已在物理或虚拟机上安装了 Jenkins，您可以准备进入下一章。至此，我们涵盖了 CI 的基础知识以及 Jenkins 及其特性的介绍。我们完成了 Jenkins 在 Windows 和 CentOS 平台上的安装。我们还快速浏览了 Jenkins 仪表板中可用的功能。除此之外，我们还讨论了部署管道及其在 CI 中的重要性。

既然我们能够使用我们的 CI 服务器 Jenkins，我们可以开始创建一个作业并验证 Jenkins 的工作方式。


# 第二章：代码仓库和构建工具的安装与配置

|   | *"生活本就简单，是我们执意将其复杂化"* |   |
| --- | --- | --- |
|   | --*孔子* |

我们在上一章中探讨了部署管道，其中源代码仓库和自动化构建构成了重要部分。SVN、Git、CVS 和 StarTeam 是一些流行的代码仓库，它们管理代码、制品或文档的变更，而 Ant 和 Maven 则是 Java 应用程序中流行的构建自动化工具。

本章详细描述了如何为 Java 应用程序的生命周期管理准备运行时环境，并使用 Jenkins 进行配置。它将涵盖如何将 Eclipse 与 SVN 等代码仓库集成，为持续集成创建基础。以下是本章涵盖的主题列表：

+   概述 Jenkins 中的构建及其要求

+   安装 Java 并配置环境变量

+   CentOS 和 Windows 上的 SVN 安装、配置和操作

+   安装 Ant

+   在 Jenkins 中配置 Ant、Maven 和 JDK

+   将 Eclipse 与代码仓库集成

+   安装和配置 Git

+   在 Jenkins 中创建一个新的使用 Git 的构建作业

# 概述 Jenkins 中的构建及其要求

为了解释持续集成，我们将使用安装在物理机或笔记本电脑上的代码仓库，而 Jenkins 则安装在虚拟机上，正如第一章 *探索 Jenkins* 中所建议的不同方式。下图描绘了运行时环境的设置：

![Jenkins 中构建的概述及其要求](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_01.jpg)

我们在第一章 *探索 Jenkins* 中看到，仪表板上的**管理 Jenkins**链接用于配置系统。点击**配置系统**链接以配置 Java、Ant、Maven 和其他第三方产品相关信息。我们可以使用 Virtual Box 或 VMware 工作站创建虚拟机。我们需要安装所有必需的软件以提供持续集成的运行时环境。我们假设系统中已安装 Java。

# 安装 Java 并配置环境变量

如果系统中尚未安装 Java，则可以按以下步骤进行安装：

在 CentOS 仓库中查找 Java 相关的包，并定位到合适的安装包。

```
[root@localhost ~]# yum search java
Loaded plugins: fastestmirror, refresh-packagekit, security
.
.
ant-javamail.x86_64 : Optional javamail tasks for ant
eclipse-mylyn-java.x86_64 : Mylyn Bridge:  Java Development
.
.
java-1.5.0-gcj.x86_64 : JPackage runtime compatibility layer for GCJ
java-1.5.0-gcj-devel.x86_64 : JPackage development compatibility layer for GCJ
java-1.5.0-gcj-javadoc.x86_64 : API documentation for libgcj
java-1.6.0-openjdk.x86_64 : OpenJDK Runtime Environment
java-1.6.0-openjdk-devel.x86_64 : OpenJDK Development Environment
java-1.6.0-openjdk-javadoc.x86_64 : OpenJDK API Documentation
java-1.7.0-openjdk.x86_64 : OpenJDK Runtime Environment
jcommon-serializer.x86_64 : JFree Java General Serialization Framework
.
.
Install the identified package java-1.7.0-openjdk.x86_64
[root@localhost ~]# yum install java-1.7.0-openjdk.x86_64
Loaded plugins: fastestmirror, refresh-packagekit, security
No such command: in. Please use /usr/bin/yum –help

```

现在通过执行`yum install`命令安装本地仓库中可用的 Java 包，如下所示：

```
[root@localhost ~]# yum install java-1.7.0-openjdk.x86_64
Loaded plugins: fastestmirror, refresh-packagekit, security
Loading mirror speeds from cached hostfile
Setting up Install Process
Resolving Dependencies
--> Running transaction check
---> Package java-1.7.0-openjdk.x86_64 1:1.7.0.3-2.1.el6.7 will be installed
--> Finished Dependency Resolution

Dependencies Resolved
.
.
Install       1 Package(s)

Total download size: 25 M
Installed size: 89 M
Is this ok [y/N]: y
Downloading Packages:
java-1.7.0-openjdk-1.7.0.3-2.1.el6.7.x86_64.rpm                                                                                                  |  25 MB     00:00
Running rpm_check_debug
Running Transaction Test
Transaction Test Succeeded
Running Transaction
 Installing : 1:java-1.7.0-openjdk-1.7.0.3-2.1.el6.7.x86_64                                       1/1
 Verifying  : 1:java-1.7.0-openjdk-1.7.0.3-2.1.el6.7.x86_64                                      1/1

Installed:
 java-1.7.0-openjdk.x86_64 1:1.7.0.3-2.1.el6.7
Complete!

```

Java 已成功从本地仓库安装。

## 配置环境变量

以下是配置环境变量的步骤：

1.  设置`JAVA_HOME`和`JRE_HOME`变量

1.  转到`/root`

1.  按下*Ctrl* + *H*以列出隐藏文件

1.  找到`.bash_profile`并编辑它，通过追加 Java 路径，如下面的截图所示：![配置环境变量](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_02.jpg)

# 在 CentOS 和 Windows 上安装、配置和操作 SVN

从本地仓库在 CentOS 上安装 SVN。

## 在 CentOS 上安装 SVN

要在 CentOS 机器上安装 SVN，请执行以下`yum install mod_dav_svn subversion`命令：

```
[root@localhost ~]# yum install mod_dav_svn subversion
Loaded plugins: fastestmirror, refresh-packagekit, security
Loading mirror speeds from cached hostfile
Setting up Install Process
Resolving Dependencies
--> Running transaction check
---> Package mod_dav_svn.x86_64 0:1.6.11-7.el6 will be installed
---> Package subversion.x86_64 0:1.6.11-7.el6 will be installed
--> Processing Dependency: perl(URI) >= 1.17 for package: subversion-1.6.11-7.el6.x86_64
--> Running transaction check
---> Package perl-URI.noarch 0:1.40-2.el6 will be installed
--> Finished Dependency Resolution

Dependencies Resolved
.
.
Installed:
 mod_dav_svn.x86_64 0:1.6.11-7.el6                                                   subversion.x86_64 0:1.6.11-7.el6

Dependency Installed:
 perl-URI.noarch 0:1.40-2.el6
Complete!
[root@localhost ~]#

```

### 配置 SVN

使用`htpasswd`命令创建密码文件。最初使用`-cm`参数。这会创建文件并用 MD5 加密密码。如果需要添加用户，确保您只使用`-m`标志，而不是初始创建后的`–c`。

```
[root@localhost conf.d]# htpasswd -cm /etc/svn-auth-conf yourusername
New password:
Re-type new password:
Adding password for user yourusername
[root@localhost conf.d]#

[root@localhost conf.d]# htpasswd -cm /etc/svn-auth-conf mitesh
New password:
Re-type new password:
Adding password for user mitesh
[root@localhost conf.d]#

```

现在在 Apache 中配置 SVN 以整合两者。编辑`/etc/httpd/conf.d/subversion.conf`。位置是 Apache 将在 URL 栏中传递的内容。

```
LoadModule dav_svn_module     modules/mod_dav_svn.so
LoadModule authz_svn_module   modules/mod_authz_svn.so

#
# Example configuration to enable HTTP access for a directory
# containing Subversion repositories, "/var/www/svn".  Each repository
# must be both:
#
#   a) readable and writable by the 'apache' user, and
#
#   b) labelled with the 'httpd_sys_content_t' context if using
#   SELinux
#

#
# To create a new repository "http://localhost/repos/stuff" using
# this configuration, run as root:
#
#   # cd /var/www/svn
#   # svnadmin create stuff
#   # chown -R apache.apache stuff
#   # chcon -R -t httpd_sys_content_t stuff
#

<Location />
 DAV svn
 SVNParentPath /var/www/svn/
#
#   # Limit write permission to list of valid users.
#   <LimitExcept GET PROPFIND OPTIONS REPORT>
#      # Require SSL connection for password protection.
#      # SSLRequireSSL
#
 AuthType Basic
 SVNListParentPath on
 AuthName "Subversion repos"
 AuthUserFile /etc/svn-auth-conf
 Require valid-user
#   </LimitExcept>
</Location>

```

现在所有配置都已完成。让我们在 SVN 上执行操作。

### SVN 操作

在 CentOS 虚拟机上创建实际仓库以执行 SVN 操作。

```
[root@localhost ~] cd /var/www/ -- Or wherever you placed your path above
[root@localhost ~] mkdir svn
[root@localhost ~] cd svn
[root@localhost ~] svnadmin create repos
[root@localhost ~] chown -R apache:apache repos
[root@localhost ~] service httpd restart

```

### 将目录导入 SVN

创建一个示例文件夹结构以测试 SVN 操作。创建`mytestproj`目录，其下包含名为`main`、`configurations`和`resources`的子目录。在每个子目录中创建示例文件。

```
[root@localhost mytestproj]# svn import /tmp/mytestproj/ file:///var/www/svn/repos/mytestproj -m "Initial repository layout for mytestproj"
Adding         /tmp/mytestproj/main
Adding         /tmp/mytestproj/main/mainfile1.cfg
Adding         /tmp/mytestproj/configurations
Adding         /tmp/mytestproj/configurations/testconf1.cfg
Adding         /tmp/mytestproj/resources
Adding         /tmp/mytestproj/resources/testresources1.cfg
Committed revision 1.

```

在 Web 浏览器中验证仓库：`http://localhost/repos`。

### 从 SVN 检出

要从仓库检出源代码，请执行以下操作：

1.  启动`httpd`服务。

    ```
    [root@localhost testmit]# service httpd restart
    Stopping httpd:
    [  OK  ]
    Starting httpd: httpd: Could not reliably determine the server's fully qualified domain name, using localhost.localdomain for ServerName
    [  OK  ]

    ```

1.  检出源代码。

    ```
    [root@localhost testmit]# svn co http://localhost/repos/mytestproj
    Authentication realm: <http://localhost:80> Subversion repos
    Password for 'root':
    Authentication realm: <http://localhost:80> Subversion repos
    Username: mitesh
    Password for 'mitesh':xxxxxxxxx

    -----------------------------------------------------------------------
    ATTENTION!  Your password for authentication realm:

     <http://localhost:80> Subversion repos

    can only be stored to disk unencrypted! You are advised to configure your system so that Subversion can store passwords encrypted, if possible. See the documentation for details.

    ```

1.  您可以通过在`/root/.subversion/servers`中将`store-plaintext-passwords`选项的值设置为`yes`或`no`来避免未来出现此警告。

    ```
    -----------------------------------------------------------------------
    Store password unencrypted (yes/no)? no
    A    mytestproj/main
    A    mytestproj/main/mainfile1.cfg
    A    mytestproj/configurations
    A    mytestproj/configurations/testconf1.cfg
    A    mytestproj/options
    A    mytestproj/options/testopts1.cfg
    Checked out revision 1.

    ```

## 在 Windows 上安装 VisualSVN Server

1.  从[`www.visualsvn.com/server/download/`](https://www.visualsvn.com/server/download/)下载 VisualSVN 服务器。它允许您在 Windows 上安装和管理一个完全功能的 Subversion 服务器。

1.  执行`VisualSVN-Server-x.x.x-x64.msi`并按照向导安装 VisualSVN Server。

1.  打开 VisualSVN Server 管理器。

1.  创建一个新仓库，名为`JenkinsTest`。![Windows 上的 VisualSVN Server](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_03.jpg)

1.  选择常规 Subversion 仓库并点击**下一步 >**。![Windows 上的 VisualSVN Server](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_04.jpg)

1.  提供**仓库名称**并点击**下一步 >**。![Windows 上的 VisualSVN Server](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_05.jpg)

1.  选择**单项目仓库**并点击**>**。![Windows 上的 VisualSVN Server](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_06.jpg)

1.  根据您的需求选择仓库访问权限，然后点击**创建**。![Windows 上的 VisualSVN Server](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_07.jpg)

1.  查看创建的仓库详情并点击**完成**。![Windows 上的 VisualSVN Server](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_08.jpg)

1.  在 VisualSVN Server 管理器中验证新创建的仓库。![Windows 上的 VisualSVN Server](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_09.jpg)

1.  在浏览器中验证仓库位置，如下所示：![Windows 上的 VisualSVN Server](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_10.jpg)

1.  现在从[`sourceforge.net/projects/tortoisesvn/`](http://sourceforge.net/projects/tortoisesvn/)安装 SVN 客户端，以执行 SVN 操作。

让我们在 Eclipse 中创建一个示例 JEE 项目，以说明 SVN 和 Eclipse 的集成。

1.  打开 Eclipse，转到**文件**菜单并点击**动态 Web 项目**。![Windows 上的 VisualSVN Server](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_11.jpg)

1.  将弹出一个对话框以创建一个**新动态 Web 项目**。![Windows 上的 VisualSVN Server](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_12.jpg)

1.  为简单项目创建源文件和`build`文件。![Windows 上的 VisualSVN Server](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_13.jpg)

1.  转到**应用程序目录**，右键点击，选择**TortoiseSVN**，然后从子菜单中选择**导入**。![Windows 上的 VisualSVN Server](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_14.jpg)

1.  输入仓库 URL 并点击**确定**。![Windows 上的 VisualSVN Server](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_15.jpg)

1.  它将把应用程序中的所有文件添加到 SVN，如下面的截图所示。![Windows 上的 VisualSVN Server](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_16.jpg)

1.  通过在浏览器中访问 SVN 仓库来验证导入，如下所示：![Windows 上的 VisualSVN Server](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_17.jpg)

# 将 Eclipse 与代码仓库集成

1.  打开 Eclipse IDE，转到**帮助**菜单并点击**安装新软件**。

1.  通过添加此 URL 添加仓库：[`subclipse.tigris.org/update_1.10.x`](http://subclipse.tigris.org/update_1.10.x)，然后选择所有包并点击**下一步 >**。![将 Eclipse 与代码仓库集成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_18.jpg)

1.  在向导中查看要安装的项和许可证协议。接受条款并点击**完成**。

1.  重启 Eclipse。转到**窗口**菜单，选择**显示视图**，点击**其他**，并找到 SVN 和 SVN 仓库。

1.  在 SVN 仓库区域，右键点击并选择**新建**；从子菜单中选择**仓库位置…**。![将 Eclipse 与代码仓库集成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_19.jpg)

1.  在 Eclipse 中添加一个新的 SVN 仓库，使用此 URL：`https://<Ip 地址/本地主机/主机名>/svn/JenkinsTest/`。

1.  点击**完成**。![将 Eclipse 与代码仓库集成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_20.jpg)

1.  验证 SVN 仓库。![将 Eclipse 与代码仓库集成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_21.jpg)

尝试将安装在 CentOS 上的 SVN 与 Eclipse IDE 集成，作为练习。

# 安装和配置 Ant

1.  从[`ant.apache.org/bindownload.cgi`](https://ant.apache.org/bindownload.cgi)下载 Ant 发行版并解压。

1.  设置`ANT_HOME`和`JAVA_HOME`环境变量。![安装和配置 Ant](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_22.jpg)

Jenkins 中有一个选项可以自动安装 Ant 或 Maven。我们将在*Jenkins 中配置 Ant、Maven 和 JDK*部分学习这一点。

# 安装 Maven

从[`maven.apache.org/download.cgi`](https://maven.apache.org/download.cgi)下载 Maven 二进制 ZIP 文件，并将其提取到 Jenkins 安装的本地系统中。

![安装 Maven](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_23.jpg)

# 在 Jenkins 中配置 Ant、Maven 和 JDK

1.  使用此 URL 在浏览器中打开 Jenkins 仪表板：`http://<ip_address>:8080/configure`。转到**管理 Jenkins**部分并点击**系统配置**。

1.  根据以下截图所示安装配置 Java：![在 Jenkins 中配置 Ant、Maven 和 JDK](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_24.jpg)

1.  在同一页面上自动配置或安装 Ant，并配置 Maven。![在 Jenkins 中配置 Ant、Maven 和 JDK](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_25.jpg)

# 安装和配置 Git

Git 是一个免费且开源的分布式版本控制系统。本节我们将尝试安装和配置 Git。

1.  在基于 CentOS 的系统中打开终端，并在终端中执行`yum install git`命令。

1.  成功安装后，使用`git --version`命令验证版本。

1.  使用`git config`命令提供用户信息，以便`commit`消息将附带正确的信息。

1.  提供姓名和电子邮件地址以嵌入提交中。

1.  要创建工作区环境，请在主目录中创建一个名为`git`的目录，然后在该目录内创建一个名为`development`的子目录。

    在终端中使用`mkdir -p ~/git/development ; cd ~/git/development`。

1.  将`AntExample1`目录复制到`development`文件夹中。

1.  使用`git init`命令将现有项目转换为工作区环境。

1.  初始化仓库后，添加文件和文件夹。![安装和配置 Git](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_26.jpg)

1.  执行`git commit -m "初始提交" –a`进行提交。![安装和配置 Git](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_27.jpg)

1.  验证 Git 仓库![安装和配置 Git](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_28.jpg)

1.  在 Git 仓库中验证项目。![安装和配置 Git](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_29.jpg)

# 在 Jenkins 中使用 Git 创建新构建作业

1.  在 Jenkins 仪表板上，点击**管理 Jenkins**并选择**管理插件**。点击**可用**标签并在搜索框中输入`github`插件。

1.  勾选复选框并点击按钮，**立即下载并在重启后安装**。

1.  重启 Jenkins。![在 Jenkins 中使用 Git 创建新构建作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_30.jpg)

1.  创建新的**自由风格项目**。提供**项目名称**并点击**确定**。![在 Jenkins 中使用 Git 创建新构建作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_31.jpg)

1.  在**源代码管理**部分配置**Git**。![在 Jenkins 中使用 Git 创建新构建作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_32.jpg)

1.  通过点击**添加构建步骤**添加**调用 Ant**构建步骤。![在 Jenkins 中使用 Git 创建新构建作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_33.jpg)

1.  执行构建。![在 Jenkins 中使用 Git 创建新构建作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_34.jpg)

1.  点击**控制台输出**查看构建进度。![在 Jenkins 中使用 Git 创建新构建作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_35.jpg)

1.  构建成功后，验证构建作业中的**工作区**。![在 Jenkins 中使用 Git 创建新构建作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_02_36.jpg)

1.  完成！

# 自测题

Q1. 在哪里设置`JAVA_HOME`和`JRE_HOME`环境变量？

1.  `/root/ .bash_profile`

1.  `/root/ .env_profile`

1.  `/root/ .bash_variables`

1.  `/root/ .env_variables`

Q2. 哪些是有效的 SVN 操作？

1.  `svn import /tmp/mytestproj/`

1.  `svn co http://localhost/repos/mytestproj`

1.  上述两者皆是。

Q3\. 在 Jenkins 中，您在哪里配置 Java 和 Ant？

1.  前往**管理 Jenkins**部分，然后点击**系统配置**。

1.  前往**管理 Jenkins**部分，然后点击**全局配置**。

# 总结

好极了！我们已到达本章的结尾。我们介绍了如何通过设置本地 CentOS 仓库、在 CentOS 和 Windows 上安装如 SVN 的代码仓库以及构建工具 Ant 来准备持续集成的环境。我们还详细说明了如何在 Jenkins 中配置仓库和构建工具。最后，我们探讨了如何将集成开发环境与代码仓库集成，以便进行高效的开发和简便的`commit`操作，从而促进部署流水线流程。


# 第三章：Jenkins、SVN 与构建工具的集成

|   | *"改变的障碍不是太少关心；而是太多复杂性"* |   |
| --- | --- | --- |
|   | --*比尔·盖茨* |

我们已经了解了如何设置环境以使用 Jenkins 进行持续集成，并且已经在 Jenkins 中配置了构建工具。Eclipse 与 SVN 的集成将帮助开发人员轻松执行仓库操作。

现在我们准备好为持续集成创建我们的第一个构建作业。本章详细描述了如何使用 Ant 和 Maven 等构建工具为 Java 应用程序创建和配置构建作业；如何运行构建作业、单元测试案例。它涵盖了运行构建以创建用于部署的发行文件或`war`文件的所有方面，以及提供基于偏好的构建作业和测试结果定制显示的仪表板视图插件。以下是本章涵盖的主要点：

+   使用 Ant 为 Java 应用程序创建和配置构建作业

+   使用 Maven 为 Java 应用程序创建和配置构建作业

+   构建执行与测试案例

# 使用 Ant 为 Java 应用程序创建和配置构建作业

在为 Java 应用程序创建和配置构建作业之前，我们将安装一个仪表板视图插件，以更好地管理构建，并显示构建和测试的结果。我们已经在第二章，*代码仓库和构建工具的安装与配置*中看到了如何创建基本作业。

## 仪表板视图插件

此插件提供了一个新视图，为 Jenkins 构建作业提供类似门户的视图。从[`wiki.jenkins-ci.org/display/JENKINS/Dashboard+View`](https://wiki.jenkins-ci.org/display/JENKINS/Dashboard+View)下载。它适合展示结果和趋势。此外，它还允许用户以有效的方式排列显示项。在 Jenkins 仪表板上，转到**管理 Jenkins**链接，点击**管理插件**并安装 Dashboard View 插件。通过点击**已安装**标签验证安装。

![仪表板视图插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_01.jpg)

在 Jenkins 仪表板上，点击加号按钮创建新视图。提供一个**视图名称**并选择视图类型；在我们的例子中是**仪表板**，然后点击**确定**。

![仪表板视图插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_02.jpg)

提供一个**名称**并选择需要在视图中包含的**作业**，如下面的截图所示：

![仪表板视图插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_03.jpg)

在视图配置中，点击**右侧栏添加仪表板小部件**，并选择**测试统计网格**。添加**测试统计图**。这将显示以统计和图表形式呈现的测试结果。

![仪表板视图插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_04.jpg)

## 为 Java 应用程序创建和配置构建作业

在仪表板上点击**新建项**以创建一个使用 Ant 作为构建工具的 Java 应用程序的新构建。输入**项名称**，并选择**自由风格项目**。点击**确定**。

![为 Java 应用程序创建和配置构建作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_05.jpg)

它将打开新构建作业的配置。在**源代码管理**中，选择**Subversion**。提供**仓库 URL**和**凭证**。在第二章中，我们安装了 Subversion 并将源代码添加到了 SVN。

提供您在浏览器中用于访问源代码仓库的 URL。

![为 Java 应用程序创建和配置构建作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_06.jpg)

如果框中没有**凭证**，请点击**添加**按钮。提供**范围**、**用户名**、**密码**和**描述**，然后点击**添加**以使其在构建作业配置中的列表框中可用。**范围**决定凭证可以在哪里使用。例如，系统范围将凭证的使用限制在与凭证关联的对象上。它比全局范围提供更好的保密性。全局范围的凭证对与凭证关联的对象及其所有子对象可用。

![为 Java 应用程序创建和配置构建作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_07.jpg)

在构建作业配置中，转到**构建触发器**部分并选择**轮询 SCM**单选按钮。在*** * * * ***格式中提供计划详细信息，如图所示。它将每分钟轮询仓库以验证开发人员提交到仓库的更改。

![为 Java 应用程序创建和配置构建作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_08.jpg)

**计划**字段遵循 cron 语法，即分钟 小时 日 月 星期。

例如，H * * * * 表示每小时轮询一次，H/15 * * * * 表示每十五分钟轮询一次。

完成**构建触发器**和**源代码管理**配置后，我们需要提供与构建工具相关的详细信息，以便 Jenkins 在构建触发时可以使用它们来执行。点击**添加构建步骤**并选择**调用 Ant**。从下拉菜单中，选择在第二章中配置的 Ant，即*代码仓库和构建工具的安装与配置*，并提供您希望从构建中执行的**目标**名称。

![为 Java 应用程序创建和配置构建作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_09.jpg)

点击**应用**和**保存**按钮以完成配置。在 Jenkins 仪表板上点击**立即构建**按钮。它将检查源代码仓库中所有最新的可用代码，并与安装 Jenkins 的机器上的本地工作区进行对比，如图所示。在特定作业的**构建历史**部分，点击**构建编号**，然后点击**控制台输出**。

![为 Java 应用程序创建和配置构建作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_10.jpg)

一旦检出过程完成，根据目标执行构建文件，如果本地工作区中所有构建执行所需的依赖项和文件都可用，则构建执行将成功，如图所示：

![为 Java 应用程序创建和配置构建作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_11.jpg)

要验证本地工作区，请转到您创建的视图，选择**构建作业**，然后点击**工作区**。验证所有文件和文件夹是否都可用，如源代码仓库所提供。

![为 Java 应用程序创建和配置构建作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_12.jpg)

# 使用 Maven 为 Java 应用程序创建和配置构建作业

在仪表板上点击**新建项目**，为使用 Maven 作为构建工具的 Java 应用程序创建新的构建。输入**项目名称**并从列表中选择**Maven 项目**。

![使用 Maven 为 Java 应用程序创建和配置构建作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_13.jpg)

它将打开新构建作业的配置。在**源代码管理**中，选择**Subversion**。提供**仓库 URL**和**凭证**。在第二章，*代码仓库和构建工具的安装与配置*中，我们安装了**Subversion**，并将源代码添加到 SVN。

![使用 Maven 为 Java 应用程序创建和配置构建作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_14.jpg)

在构建作业配置中，转到**构建触发器**部分并选择**轮询 SCM**单选按钮。按照*** * * * ***格式提供计划详细信息，如图所示。它将每分钟轮询仓库以验证开发人员提交到仓库的更改。添加 Maven 构建步骤。提供构建文件的名称；默认情况下是`pom.xml`。提供**目标和选项**，如果留空，则将执行默认目标。

![使用 Maven 为 Java 应用程序创建和配置构建作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_15.jpg)

点击**立即构建**以执行构建作业或提交更新的代码到仓库，构建将根据我们在**构建触发器**中的配置自动执行。

![使用 Maven 为 Java 应用程序创建和配置构建作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_16.jpg)

它将针对安装 Jenkins 的机器上的本地工作区，检出源代码仓库中所有最新的可用代码，如下所示。

![使用 Maven 为 Java 应用程序创建和配置构建作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_17.jpg)

结账过程完成后，将根据目标启动构建文件执行，如果构建执行所需的所有依赖项和文件都可在本地工作区中获得，则构建执行将成功，如下所示。

![使用 Maven 为 Java 应用程序创建和配置构建作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_18.jpg)

# 构建执行与测试案例

Jenkins 允许在仪表板上发布 JUnit 格式的测试结果。我们无需为此安装任何特定插件。如果我们已有用 JUnit 编写的测试案例，则执行它们很容易。确保在构建文件中为测试案例执行创建目标或任务。在构建作业配置中，点击**构建后操作**并选择**发布 JUnit 测试结果报告**。提供**测试报告 XMLs**文件的位置并保存构建作业配置。

![构建执行与测试案例](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_19.jpg)

通过点击**立即构建**来执行构建。构建完成后，点击仪表板上的**测试结果**链接。

![构建执行与测试案例](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_20.jpg)

点击包链接以在摘要页面上获取详细的测试结果。

![构建执行与测试案例](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_21.jpg)

点击类链接以在页面上获取详细的测试结果。

![构建执行与测试案例](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_22.jpg)

验证所有测试名称、持续时间和状态，如下所示：

![构建执行与测试案例](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_23.jpg)

通过点击 Jenkins 仪表板上每个测试案例的单独链接进行验证。

![构建执行与测试案例](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_24.jpg)

我们已配置仪表板视图插件以显示测试统计图和测试趋势图。

验证自定义视图中的成功、失败或跳过测试的数量及百分比，如下所示。

![构建执行与测试案例](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_25.jpg)

在仪表板视图中验证测试趋势图。

![构建执行与测试案例](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_03_26.jpg)

# 自测问题

Q1. 安装仪表板视图插件的目的是什么？

1.  为 Jenkins 构建作业提供类似门户的视图

1.  运行与 Jenkins 构建作业相关的测试案例

1.  显示构建结果

Q2. 为 SVN 创建凭据时可用的字段有哪些？

1.  **范围**、**用户名**、**密码**、**描述**

1.  **范围**、**用户名**、**密码**

1.  **用户名**、**密码**、**描述**

Q3. **构建触发器计划**部分中的*****是什么意思？

1.  每日轮询 SCM

1.  每小时轮询 SCM

1.  每分钟轮询 SCM

1.  每秒轮询 SCM

问题 4：Ant 和 Maven 的构建文件名称分别是什么？

1.  `pom.xml`, `build.xml`

1.  `build.xml`, `pom.xml`

1.  `pom.xml`, `root.xml`

1.  `ant.xml`, `maven.xml`

# 总结

我们再次来到本章中令人感到成就感的部分。在本章中，我们学习了如何定制 Jenkins 仪表板，并根据构建作业在仪表板上展示测试结果。我们还为示例 Java 应用程序创建了第一个构建作业。我们使用了 Ant 和 Maven 等构建工具来执行构建并创建构件。最后，我们了解了如何执行测试用例，并在 Jenkins 门户上显示结果。

在下一章中，我们将直接从 Jenkins 部署应用程序到应用服务器，并介绍在亚马逊网络服务上部署应用程序的入门知识。


# 第四章：实施自动化部署

|   | *简洁是可靠性的前提* |   |
| --- | --- | --- |
|   | --*艾兹格·迪科斯彻* |

我们已经介绍了持续集成的概念，并了解了如何使用 Jenkins 实现它。现在是时候迈向应用程序部署管道的下一步，即自动化部署。在将应用程序自动化部署到 Tomcat 应用服务器之前，我们将首先理解持续交付和持续部署的概念。

本章将通过在本地或远程应用服务器上部署制品，进一步推进部署管道。它将深入了解自动化部署和持续交付流程。

+   持续交付与持续部署概述

+   从 Jenkins 向 Tomcat 服务器部署文件

# 持续交付与持续部署概述

持续交付是持续集成实践的延伸。应用程序制品以自动化方式达到生产就绪状态，但并未部署到生产环境中。持续部署是持续交付的延伸，其中应用程序的变更最终部署到生产环境中。持续交付是 DevOps 实践的必备条件。接下来我们将了解如何使用 Jenkins 部署应用程序制品。

### 注意

欲了解更多关于持续交付和持续部署的详情，请访问：

[持续交付与持续部署对比](http://continuousdelivery.com/2010/08/continuous-delivery-vs-continuous-deployment/)

[持续交付书籍](http://martinfowler.com/books/continuousDelivery.html)

# 安装 Tomcat

Tomcat 是由**Apache 软件基金会**（**ASF**）开发的开源 Web 服务器和 Servlet 容器。我们将使用 Tomcat 来部署 Web 应用程序。

1.  访问[Tomcat 官网](https://tomcat.apache.org)并下载 Tomcat。将所有文件解压到系统中的相关文件夹。

1.  在`conf/server.xml`中将端口号从`8080`更改为`9999`。

    ```
     <Connector port="9999" protocol="HTTP/1.1" 
     connectionTimeout="20000" 
     redirectPort="8443" />

    ```

1.  根据您的操作系统，打开终端或命令提示符。转到`tomcat`目录。转到`bin`文件夹，并运行`startup.bat`或`startup.sh`。以下是在 Windows 上运行`startup.bat`的示例。![安装 Tomcat](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_04_01.jpg)

1.  打开浏览器并访问`http://localhost:9999`。我们也可以通过 IP 地址`http://<IP 地址>:9999`访问 Tomcat 主页。![安装 Tomcat](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_04_02.jpg)

# 从 Jenkins 向 Tomcat 部署 war 文件

我们将使用[Jenkins 部署插件](https://wiki.jenkins-ci.org/x/CAAjAQ)将`war`文件部署到特定容器中。

部署插件会获取`war`/`ear`文件，并在构建结束时将其部署到本地或远程运行的应用程序服务器上。

它支持以下容器：

+   Tomcat: 4.x/5.x/6.x/7.x

+   JBoss: 3.x/4.x

+   Glassfish: 2.x/3.x

要在`Websphere`容器中部署`war`文件，请使用[`wiki.jenkins-ci.org/x/UgCkAg`](https://wiki.jenkins-ci.org/x/UgCkAg)上提供的 Deploy WebSphere 插件。

要在`Weblogic`容器中部署`war`文件，请使用[`wiki.jenkins-ci.org/x/q4ahAw`](https://wiki.jenkins-ci.org/x/q4ahAw)上提供的 WebLogic Deployer 插件。

1.  在 Jenkins 仪表板上，前往**管理 Jenkins**链接，然后点击**管理插件**并安装**Deploy plugin**。![从 Jenkins 部署 war 文件到 Tomcat](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_04_03.jpg)

1.  等待**Deploy Plugin**安装完成。![从 Jenkins 部署 war 文件到 Tomcat](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_04_04.jpg)

1.  前往 Jenkins 仪表板并选择任何构建作业。点击所选构建作业的**配置**链接。

1.  在相关作业的配置页面上点击**添加构建后操作**按钮，并选择**Deploy war/ear to container**，如图所示。![从 Jenkins 部署 war 文件到 Tomcat](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_04_05.jpg)

1.  在**构建后操作**部分添加**Deploy war/ear to a container**。提供一个相对于工作空间的**war**文件路径，并从可用列表框中选择**Tomcat 7.x**作为容器，如图所示。![从 Jenkins 部署 war 文件到 Tomcat](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_04_06.jpg)

1.  提供**管理器用户名**和**管理器密码**；在`tomcat-users.xml`中，并取消以下内容的注释：

    ```
    <!--
      <role rolename="tomcat"/>
      <role rolename="role1"/>
      <user username="tomcat" password="tomcat" roles="tomcat"/>
      <user username="both" password="tomcat" roles="tomcat,role1"/>
      <user username="role1" password="tomcat" roles="role1"/>
    -->
    ```

1.  在未注释的部分添加以下内容：

    ```
    <role rolename="manager-script"/>
    <user username="mitesh51" password="*********" roles="manager-script"/>  
    ```

1.  重启 Tomcat，访问`http://localhost:9999/manager/html`，并输入用户名和密码。在 Jenkins 中使用相同的用户名和密码作为管理器凭证。![从 Jenkins 部署 war 文件到 Tomcat](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_04_07.jpg)

1.  点击**立即构建**。![从 Jenkins 部署 war 文件到 Tomcat](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_04_08.jpg)

1.  构建完成后，验证 Tomcat 应用服务器中应用程序部署的控制台输出。![从 Jenkins 部署 war 文件到 Tomcat](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_04_09.jpg)

1.  验证 Tomcat 安装目录中的`webapps`目录。![从 Jenkins 部署 war 文件到 Tomcat](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_04_10.jpg)

1.  验证 Tomcat 管理器，并检查 Tomcat 应用服务器中应用的状态。![从 Jenkins 部署 war 文件到 Tomcat](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_04_11.jpg)

1.  如果 Tomcat 服务器安装在远程服务器上，则在 Tomcat URL 中使用 IP 地址，如图所示：![从 Jenkins 部署 war 文件到 Tomcat](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_04_12.jpg)

我们只需在远程部署时更改 Tomcat URL。

# 自测题

Q1. 持续交付和持续部署是相同的。

1.  正确

1.  错误

Q2. 如何启用 Tomcat 管理器访问？

1.  启动 Tomcat

1.  修改`server.xml`

1.  修改`tomcat-users.xml`

1.  修改`web.xml`

# 总结

做得好！我们已到达本章末尾；让我们总结一下所涵盖的内容。我们已经理解了持续交付和持续部署的概念。我们在这里主要探讨的是，在构建成功后，将应用程序工件部署到特定的应用程序服务器上。

在下一章中，我们将学习如何在云上管理 Jenkins，并探讨一些案例研究。


# 第五章：托管 Jenkins

|   | *"生产力就是能够做你以前从未能做的事情"* |   |
| --- | --- | --- |
|   | --*弗朗茨·卡夫卡* |

我们已经理解了持续交付和持续部署的概念。我们还看到了如何将`war`文件从 Jenkins 部署到 Tomcat 服务器。现在，我们将探讨如何利用托管的 Jenkins。不同的服务提供商将 Jenkins 作为服务提供。我们将了解 OpenShift 和 CloudBees 如何向用户提供 Jenkins。

本章详细描述了如何使用由流行的 PaaS 提供商（如 Red Hat OpenShift 和 CloudBees）提供的托管 Jenkins。本章还涵盖了根据客户需求使用 Jenkins 的各种细节。本章将探讨如何在 Jenkins 中使用与云相关的插件以有效使用 Jenkins。本章将涵盖以下主题：

+   在 OpenShift PaaS 中探索 Jenkins

+   在云中探索 Jenkins – CloudBees

+   CloudBees 企业插件概览

+   CloudBees 的 Jenkins 案例研究

# 在 OpenShift PaaS 中探索 Jenkins

OpenShift Online 是 Red Hat 提供的公共 PaaS——应用程序开发和托管平台。它自动化了应用程序的配置、取消配置、管理和扩展过程。这支持命令行客户端工具和 Web 管理控制台，以便轻松启动和管理应用程序。Jenkins 应用由 OpenShift Online 提供。OpenShift Online 有一个免费计划。

1.  要注册 OpenShift Online，请访问[`www.openshift.com/app/account/new`](https://www.openshift.com/app/account/new)。![在 OpenShift PaaS 中探索 Jenkins](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_01.jpg)

1.  一旦注册，你将在[`openshift.redhat.com/app/console/applications`](https://openshift.redhat.com/app/console/applications)获得欢迎屏幕。

1.  点击**立即创建你的第一个应用程序**。![在 OpenShift PaaS 中探索 Jenkins](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_02.jpg)

1.  选择应用程序类型，在我们的例子中，选择**Jenkins 服务器**。![在 OpenShift PaaS 中探索 Jenkins](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_03.jpg)

1.  为你的 Jenkins 服务器提供**公共 URL**，如下面的截图所示：![在 OpenShift PaaS 中探索 Jenkins](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_04.jpg)

1.  点击**创建应用程序**。![在 OpenShift PaaS 中探索 Jenkins](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_05a.jpg)

1.  点击**在浏览器中访问应用**。![在 OpenShift PaaS 中探索 Jenkins](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_05.jpg)

1.  在 Web 浏览器中访问 Jenkins。然后，使用 OpenShift 仪表板提供的凭据登录。![在 OpenShift PaaS 中探索 Jenkins](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_06.jpg)

1.  以下是 Jenkins 仪表板的截图：![在 OpenShift PaaS 中探索 Jenkins](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_07.jpg)

# 在云中探索 Jenkins – CloudBees

DEV@cloud 是在 CloudBees 管理的安全、多租户环境中托管的 Jenkins 服务。它运行特定版本的 Jenkins，以及与该版本良好支持的插件的选定版本。所有更新和补丁都由 CloudBees 管理，并且可用的自定义有限。

1.  访问[`www.cloudbees.com/products/dev`](https://www.cloudbees.com/products/dev)并订阅。![探索云中的 Jenkins – CloudBees](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_08.jpg)

1.  完成订阅流程后，我们将获得 CloudBees 的仪表板，如下面的截图所示。点击**构建**。![探索云中的 Jenkins – CloudBees](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_09.jpg)

1.  我们将看到 Jenkins 仪表板，如下面的截图所示：![探索云中的 Jenkins – CloudBees](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_10.jpg)

1.  点击**管理 Jenkins**以配置和安装插件。![探索云中的 Jenkins – CloudBees](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_11.jpg)

    ### 注意

    在配置构建任务之前，我们需要将应用程序的源代码存储在 CloudBees 提供的库服务中。点击**生态系统**，然后点击**库**。

    ![探索云中的 Jenkins – CloudBees](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_12.jpg)

1.  点击子版本库或**添加库**，获取库的 URL。![探索云中的 Jenkins – CloudBees](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_13.jpg)

1.  点击应用程序文件夹，将其导入 CloudBees 提供的子版本库。使用 TortoiseSVN 或其他 SVN 客户端导入代码。![探索云中的 Jenkins – CloudBees](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_14.jpg)

1.  提供从 CloudBees 复制的库 URL，然后点击**确定**。![探索云中的 Jenkins – CloudBees](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_15.jpg)

1.  提供认证信息（用户名和密码与我们的 CloudBees 账户相同）。

    点击**确定**。

    ![探索云中的 Jenkins – CloudBees](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_16.jpg)

    导入过程将根据源文件的大小耗费一些时间。

    ![探索云中的 Jenkins – CloudBees](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_17.jpg)

1.  在浏览器中验证库 URL，我们将找到最近导入的项目。![探索云中的 Jenkins – CloudBees](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_18.jpg)

1.  成功导入操作后，验证 Jenkins 仪表板。![探索云中的 Jenkins – CloudBees](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_19.jpg)

1.  在 Jenkins 仪表板上点击**新建项目**。选择**自由风格项目**，并为新构建任务命名。点击**确定**。![探索云中的 Jenkins – CloudBees](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_20.jpg)

1.  配置页面将允许我们为构建任务配置各种特定设置。![探索云中的 Jenkins – CloudBees](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_21.jpg)

1.  在构建任务中配置**Subversion**库。![探索云中的 Jenkins – CloudBees](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_22.jpg)

1.  点击**应用**，然后点击**保存**。![探索云中的 Jenkins – CloudBees](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_23.jpg)

1.  点击**立即构建**。![在云中探索 Jenkins – CloudBees](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_24.jpg)

    验证控制台输出。

    ![在云中探索 Jenkins – CloudBees](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_25.jpg)

    接着，它将编译源文件，并根据`build.xml`文件创建一个`war`文件，因为这是一个基于 Ant 的项目。

    ![在云中探索 Jenkins – CloudBees](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_26.jpg)

1.  在 Jenkins 仪表板上验证成功构建。![在云中探索 Jenkins – CloudBees](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_05_27.jpg)

# CloudBees 企业插件概览

以下是一些重要的 CloudBees 企业插件：

## **工作流插件**

管理软件交付管道是一项复杂的任务，开发和运维团队需要管理可能需要数天才能完成的复杂作业。工作流插件支持复杂的管道。该插件使用 Groovy DSL 进行工作流，并提供从主从故障中暂停和重新启动作业的设施。

欲了解更多信息，请访问[`www.cloudbees.com/products/cloudbees-jenkins-platform/team-edition/features/workflow-plugin`](https://www.cloudbees.com/products/cloudbees-jenkins-platform/team-edition/features/workflow-plugin)。

## **检查点插件**

让我们考虑一个场景，一个长时间运行的构建作业几乎在其结束阶段失败。这可能会影响交付计划。检查点插件提供了在检查点重新启动工作流的设施。因此，它消除了由于主从故障导致的延迟。此外，它可以帮助 Jenkins 和基础设施故障的恢复。

欲了解更多信息，请访问[`www.cloudbees.com/products/jenkins-enterprise/plugins/checkpoints-plugin`](https://www.cloudbees.com/products/jenkins-enterprise/plugins/checkpoints-plugin)。

## **基于角色的访问控制插件**

认证和授权在安全方面扮演着重要角色。授权策略可以帮助有效控制对 Jenkins 作业的访问。在项目级别和可见性方面设置权限也很重要。CloudBees 提供的**基于角色的访问控制**（**RBAC**）插件具有以下功能：

+   定义各种安全角色

+   为组分配规则

+   在全球或对象级别分配角色

+   将特定对象的组管理委托给用户

欲了解更多关于基于角色的访问控制插件的信息，请访问[`www.cloudbees.com/products/jenkins-enterprise/plugins/role-based-access-control-plugin`](https://www.cloudbees.com/products/jenkins-enterprise/plugins/role-based-access-control-plugin)。

## **高可用性插件**

Jenkins 主节点的停机时间，无论是由软件还是硬件引起的，都会影响整个产品团队。快速恢复 Jenkins 主节点至关重要，而这通常需要数小时。高可用性插件通过保留多个主节点作为备份来消除因主节点故障导致的停机时间。当检测到主节点故障时，备份主节点会自动启动。此插件使得故障检测和恢复成为一个自动过程，而非手动操作。

欲了解更多信息，请访问[`www.cloudbees.com/products/jenkins-enterprise/plugins/high-availability-plugin`](https://www.cloudbees.com/products/jenkins-enterprise/plugins/high-availability-plugin)。

## VMware ESXi/vSphere Auto-Scaling 插件

考虑这样一个场景：您需要在现有的基于 VMware 的虚拟化基础设施中运行多个 Jenkins 从节点，以利用未充分利用的容量。VMware vCenter Auto-Scaling 插件允许您在基于 VMware 的虚拟化基础设施中创建可用的从节点机器。可以配置具有相同配置的多个虚拟机池。

以下操作可在虚拟机上执行：

+   开机

+   关机/挂起

+   恢复到最后一个快照

欲了解更多信息，请访问[`www.cloudbees.com/products/jenkins-enterprise/plugins/vmware-esxivsphere-auto-scaling-plugin`](https://www.cloudbees.com/products/jenkins-enterprise/plugins/vmware-esxivsphere-auto-scaling-plugin)。

要查找 CloudBees 提供的所有插件的详细信息，请访问[`www.cloudbees.com/products/jenkins-enterprise/plugins`](https://www.cloudbees.com/products/jenkins-enterprise/plugins)。

# CloudBees 提供的 Jenkins 案例研究

我们将介绍一些 CloudBees 的案例研究，展示 Jenkins 的有效使用。

## Apache jclouds

Apache jclouds 是一个开源的多云工具包，提供在多个云上管理工作负载的功能。它基于 Java 平台创建，为用户提供了使用特定云平台功能创建和管理应用程序的完整控制权。它支持跨各种云平台的无缝迁移。Apache jclouds 支持 30 个云提供商和云软件栈，如 Joyent、Docker、SoftLayer、Amazon EC2、OpenStack、Rackspace、GoGrid、Azure 和 Google。Apache jclouds 拥有众多知名用户，如 CloudBees、Jenkins、Cloudify、cloudsoft、Twitter、Cloudswitch、enStratus 等。

### 挑战

jclouds 社区使用 Jenkins CI 进行持续集成。随着时间的推移，管理和维护 Jenkins 变得越来越困难，成本也越来越高。管理 Jenkins 是一项耗时且繁琐的任务。大多数时候，开发者忙于管理 Jenkins，而非编写代码以提升 jclouds 的效率。

### 解决方案

jclouds 团队探索了市场上可用的 PaaS 产品，并考虑了 CloudBees，这将帮助他们消除基础设施管理和维护。jclouds 团队认识到，将 Jenkins CI 工作转移到 DEV@cloud 很容易，并立即从开发者那里获得生产力提升。每周从 Jenkins 维护活动中节省了近 4 小时。

### 优势

+   通过消除服务器重启、服务器规模调整、软件更新和补丁等自动从 CloudBees 服务内部执行的活动，实现 100%专注于软件开发

+   开发者生产力提高了 33%

+   CloudBees 对 Jenkins CI 问题的技术支持

欲了解更多关于此案例研究的信息，请访问[`www.cloudbees.com/casestudy/jclouds`](https://www.cloudbees.com/casestudy/jclouds)。

## 全球银行

全球银行是全球顶级金融机构之一，提供企业与投资银行服务、私人银行服务、信用卡服务和投资管理。它拥有庞大的国际业务网络。

### 挑战

全球银行现有的流程正遭受着分散的构建流程、未经批准的软件版本和缺乏技术支持的困扰。缺乏中央控制或管理，以及流程的标准化。构建资产并非始终可访问。需要一个具有审计能力的应用程序构建服务的自动化安全流程。Jenkins 提供了标准化，以及其他集中管理的优势，如稳健性和有用的插件的可用性。在使用开源 Jenkins 后，该金融机构面临了开源 Jenkins 中不存在的其他挑战。需要更多功能来实现审批、安全、备份和审计。

### 解决方案

为了克服现有挑战，全球银行评估并选择了 CloudBees Jenkins Enterprise，考虑到其额外的高可用性、备份、安全性和作业组织插件，以及为开源 Jenkins 和开源 Jenkins 插件获取技术支持的能力。全球银行利用 CloudBees 的技术支持来设置 CloudBees Jenkins Enterprise。

### 优势

+   RBAC 插件提供安全性和额外的企业级功能。Folders 插件提供版本控制，并确保只有经过批准的软件版本被共享。

+   通过消除对每个应用程序的本地构建实例进行监控的需求，每个应用程序节省了半天开发时间。

+   技术支持能力的可用性。

欲了解更多信息，请访问[`www.cloudbees.com/casestudy/global-bank`](https://www.cloudbees.com/casestudy/global-bank)。

## 服务流程

Service-Flow 提供在线集成服务，以连接组织和各种利益相关者使用的不同 IT 服务管理工具。它提供自动创建票据、票据信息交换和票据路由的功能。它有适用于许多 ITSM 工具的适配器，如 ServiceNow 和 BMC，以及 Microsoft Service Manager Fujitsu、Atos、Efecte 和 Tieto。

### 挑战

Service-Flow 希望构建自己的服务，而不使用任何通用集成工具来实现敏捷性。Service-Flow 有多个要求，例如注重敏捷性，这需要一个支持快速开发和频繁增量更新的平台，支持 Jenkins，对数据进行控制，可靠性和可用性。

### 解决方案

Service-Flow 使用 CloudBees 平台构建和部署其 ITSM 集成服务。DEV@cloud 已被用于建立版本控制仓库，编写第一个 Java 类，设置一些基本的 Jenkins 作业，运行单元测试，执行集成测试以及其他质量检查。Service-Flow 服务在云中，通过使用 CloudBees 平台添加新功能，客户群迅速增长。

### 好处

+   开发时间减少了 50%，三个月内生产发布

+   每周多次部署更新，无需服务停机

+   生产中实现了 99.999% 的可用性

欲了解更多信息，请访问 [`www.cloudbees.com/casestudy/service-flow`](https://www.cloudbees.com/casestudy/service-flow)。

更多案例研究，请访问 [`www.cloudbees.com/customers`](https://www.cloudbees.com/customers)。

# 自测问题

Q1. 关于 CloudBees 提供的 Workflow 插件，哪项陈述是正确的？

1.  从主从故障中暂停和重启作业

1.  管理软件交付管道

1.  它使用 Groovy DSL 进行工作流程

1.  上述所有内容

Q2. CloudBees 提供的 RBAC 插件有哪些功能？

1.  定义各种安全角色

1.  将规则分配给组

1.  将角色全局分配或对象级别分配

1.  上述所有内容

Q3. CloudBees 提供的 VMware ESXi/vSphere Auto-Scaling 插件可以执行哪些操作？

1.  开机

1.  关机/挂起

1.  恢复到最后一个快照

1.  上述所有内容

# 总结

关于章节结束的有趣之处在于：每个结束的章节都引领你走向新的开始。我们了解了如何在 PaaS、RedHat OpenShift 和 CloudBees 等云服务模型上配置、管理和使用 Jenkins。我们还介绍了一些来自 CloudBees 的有趣的企业插件，这些插件增加了很大的灵活性和价值。在最后一节中，我们提供了关于 Jenkins 如何为许多组织带来益处的各种案例研究的详细信息，以及他们如何利用 Jenkins 的功能来获得竞争优势。


# 第六章：管理代码质量和通知

|   | *"通过进行非常小的增量更改来限制您的负担"* |   |
| --- | --- | --- |
|   | --*匿名* |

我们看到了各种客户如何根据他们的需求在云上使用 Jenkins。我们还看到了 Red Hat OpenShift 和 CloudBees 的云端产品，以及案例研究，以了解 Jenkins 如何有效地使用。现在，是时候了解关于代码质量检查和构建失败通知的额外方面了。

本章将教你如何将静态代码分析行为集成到 Jenkins 中。代码质量是影响应用程序效能的极其重要的特性，通过与 Sonar、Checkstyle、FindBugs 等工具集成，用户可以洞察到代码中的问题部分。

+   与 Sonar 集成

+   探索静态代码分析插件

+   构建状态的电子邮件通知

# 与 Sonar 集成

代码质量是 DevOps 文化的一个重要方面。它提供了质量检查，突出了可靠性、安全性、效率、可移植性、可管理性等方面的水平。它有助于发现源代码中的错误或可能的错误，并建立与组织中编码标准一致的文化。

SonarQube 是一个开源的代码质量持续检查平台。它支持 Java、C#、PHP、Python、C/C++、Flex、Groovy、JavaScript、PL/SQL、COBOL、Objective-C、Android 开发等。它提供关于编码标准、代码覆盖、复杂代码、单元测试、重复代码、潜在错误、注释、设计和架构的报告。

1.  前往[`www.sonarqube.org/downloads/`](http://www.sonarqube.org/downloads/)，下载 SonarQube 5.1。![与 Sonar 集成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_06_01.jpg)

1.  提取文件，它将类似于以下截图：![与 Sonar 集成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_06_02.jpg)

1.  根据您想要运行 SonarQube 的操作系统，转到`bin`文件夹以运行 SonarQube。![与 Sonar 集成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_06_03.jpg)

1.  根据您的平台选择一个文件夹，在我们的例子中，我们将在 CentOS 上安装，因此我们将选择`linux-x86-64`。![与 Sonar 集成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_06_04.jpg)

1.  打开终端并进入 SonarQube 的安装目录；转到`bin/linux-x86-64/`并运行`sonar.sh`。我们需要使用`sonar.sh`的参数，如下所示：

    ```
    [root@localhost linux-x86-64]# ./sonar.sh
    Usage: ./sonar.sh { console | start | stop | restart | status | dump }

    ```

    ![与 Sonar 集成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_06_05.jpg)

1.  访问`http://localhost:9000/`或`http://<IP 地址>:9000/`。![与 Sonar 集成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_06_06.jpg)

1.  探索 SonarQube 仪表板中的**规则**。![与 Sonar 集成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_06_07.jpg)

1.  验证 SonarQube 仪表板中的**设置**。![与 Sonar 集成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_06_08.jpg)

1.  创建`sonar-project.properties`，并将其保存在项目存储的仓库中：

    ```
    # must be unique in a given SonarQube instance
    sonar.projectKey=Ant:project
    # this is the name displayed in the SonarQube UI
    sonar.projectName=Ant project
    sonar.projectVersion=1.0
    sonar.sources=src

    ```

1.  在 Jenkins 中安装 SonarQube 插件。欲了解更多信息，请访问[`wiki.jenkins-ci.org/display/JENKINS/SonarQube+plugin`](https://wiki.jenkins-ci.org/display/JENKINS/SonarQube+plugin)。![与 Sonar 集成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_06_09.jpg)

1.  点击**管理 Jenkins**并前往**系统配置**。转到**SonarQube**部分，并在 Jenkins 中配置 SonarQube。![与 Sonar 集成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_06_10.jpg)

1.  在构建作业中添加构建步骤**调用独立 SonarQube 分析**。![与 Sonar 集成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_06_11.jpg)

1.  运行构建作业，若遇到证书错误，执行`svn export`命令以解决证书问题。![与 Sonar 集成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_06_12.jpg)

1.  执行`svn export`命令以解决虚拟机上安装的 SonarQube 和 Jenkins 的证书问题，如以下截图所示：![与 Sonar 集成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_06_13.jpg)

1.  运行构建作业。![与 Sonar 集成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_06_14.jpg)

1.  在控制台中验证 Sonar 执行步骤。![与 Sonar 集成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_06_15.jpg)

1.  刷新 SonarQube 仪表板，我们便能在 SonarQube 中查看最近执行的构建的详细信息，如以下截图所示：![与 Sonar 集成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_06_16.jpg)

1.  如需获取更多代码验证详情，点击项目，我们将能看到**代码行数**、**重复度**、**复杂度**等详细信息。![与 Sonar 集成](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_06_17.jpg)

进一步探索 SonarQube 与 Jenkins 的集成，如下步骤所示。

# 探索静态代码分析插件

静态代码分析插件为静态代码分析插件提供实用工具。Jenkins 使用不同的插件进行配置和解析，解释了多个静态代码分析工具的结果文件。通过这些插件，我们可以更灵活地构建您所需的内容。

要安装这些插件中的任何一个，请前往 Jenkins 仪表板，点击**管理 Jenkins**，然后选择**管理插件**链接。转到**可用**标签页，找到相应的插件并选中它。点击**立即下载**，并在重启后安装。

所有这些结果均由同一后端可视化。以下插件使用相同的可视化方式：

## 检查样式插件

检查样式插件为开源静态代码分析程序 Checkstyle 生成报告。

欲了解更多关于检查样式插件的信息，请访问[`wiki.jenkins-ci.org/display/JENKINS/Checkstyle+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Checkstyle+Plugin)。

## FindBugs 插件

FindBugs 插件由静态分析收集器插件支持，该插件在聚合趋势图、健康报告和构建稳定性中显示结果。

欲了解更多信息，请访问[`wiki.jenkins-ci.org/display/JENKINS/FindBugs+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/FindBugs+Plugin)。

## 编译器警告插件

编译器警告插件在控制台日志或日志文件中生成编译器警告的趋势报告。

欲了解更多信息，请访问[警告插件](https://wiki.jenkins-ci.org/display/JENKINS/Warnings+Plugin)。

要发布 Checkstyle、FindBugs 和编译器警告插件的组合结果，请前往任何作业的**构建**部分，点击**添加构建后操作**，并选择**发布组合分析结果**。

![编译器警告插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_06_18.jpg)

我们还可以通过使用仪表板视图插件查看这些结果。

在仪表板视图的配置中，点击**编辑视图**并在**警告数量**部分选择复选框。在不同部分添加**仪表板小部件**，用于 Checkstyle、编译器和 Findbug。

![编译器警告插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_06_19.jpg)

在所有更改和运行构建作业后验证视图。

![编译器警告插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_06_20.jpg)

以下插件也很有用。

## DRY 插件

DRY 插件显示项目中的重复代码块。它仅显示重复代码检查工具的结果。

欲了解更多信息，请访问[DRY 插件](https://wiki.jenkins-ci.org/display/JENKINS/DRY+Plugin)。

## PMD 插件

PMD 插件扫描构建工作区中的`pmd.xml`文件，并报告警告。

欲了解更多信息，请访问[PMD 插件](https://wiki.jenkins-ci.org/display/JENKINS/PMD+Plugin)。

## 任务扫描器插件

任务扫描器插件扫描工作区文件中的开放任务并提供趋势报告。

欲了解更多信息，请访问[Jenkins 任务扫描器插件](https://wiki.jenkins-ci.org/display/JENKINS/Task+Scanner+Plugin)。

## CCM 插件

CCM 插件提供.NET 代码的圈复杂度详细信息。

欲了解更多信息，请访问[CCM 插件](https://wiki.jenkins-ci.org/display/JENKINS/CCM+Plugin)。

## Android Lint 插件

Android Lint 插件解析来自 Android lint 工具的输出。

欲了解更多信息，请访问[Android Lint 插件](https://wiki.jenkins-ci.org/display/JENKINS/Android+Lint+Plugin)。

## OWASP 依赖检查插件

依赖检查 Jenkins 插件具有执行依赖分析构建的能力。

欲了解更多信息，请访问[OWASP 依赖检查插件](https://wiki.jenkins-ci.org/display/JENKINS/OWASP+Dependency-Check+Plugin)。

# 构建状态的电子邮件通知

要基于构建状态发送电子邮件通知，我们需要配置 SMTP 详细信息。点击**管理 Jenkins**，然后进入**系统配置**。前往**电子邮件通知**部分。

![构建状态的电子邮件通知](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_06_21.jpg)

前往构建作业配置，点击**添加构建后操作**。选择**电子邮件通知**。提供收件人列表并保存。

![构建状态的电子邮件通知](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_06_22.jpg)

运行构建作业，若构建失败，则会在邮箱中收到电子邮件通知。

# 自测题

Q1. SonarQube 支持哪些编程语言？

1.  Java

1.  C#

1.  PHP

1.  Python

1.  C/C++

1.  JavaScript

1.  以上皆是

Q2. 以下哪项不是静态代码分析插件？

1.  DRY 插件

1.  PMD 插件

1.  任务扫描器插件

1.  FindBugs 插件

1.  上述皆非

# 总结

至此，我们又来到了另一章的结尾。我们需要记住，每一个新的开始都源自另一个开始的结束。总结一下，我们学习了如何管理已配置应用程序的代码质量，以及如何使用通知功能，在构建失败时向开发者发送信息。我们还简要介绍了一些静态代码分析插件，以对其有所了解。在下一章中，我们将学习如何管理和监控 Jenkins。


# 第七章：管理与监控 Jenkins

|   | *"开始时跌倒 + 经常跌倒 + 学会快速恢复 = 更快上市时间"* |   |
| --- | --- | --- |
|   | --*匿名* |

上一章我们学习了 Sonar 与 Jenkins 的集成、静态代码分析插件概览以及构建状态的通知。现在，是时候专注于 Jenkins 的管理和监控了。

本章深入探讨了 Jenkins 节点的管理以及使用 Java Melody 监控它们，以提供资源利用情况的详细信息。还涵盖了如何管理和监控构建作业。本章详细描述了 Jenkins 中可用的基本安全配置，以实现更好的访问控制和授权。以下是本章将涵盖的主题列表：

+   管理 Jenkins 主节点和从节点

+   Jenkins 监控与 JavaMelody

+   管理磁盘使用

+   使用构建监控插件进行构建作业特定监控

+   管理访问控制和授权

+   维护基于角色和项目的权限

+   管理管理员账户

+   审计跟踪插件—概览与使用

# 管理 Jenkins 主节点和从节点

主节点代表 Jenkins 的基本安装，负责构建系统的所有任务。它能满足所有用户请求，并具备独立构建项目的容量。从节点是设置来减轻主节点构建项目负担的系统，但委托行为取决于每个项目的配置。委托可以具体配置为构建作业。

1.  在 Jenkins 仪表板上，前往**管理 Jenkins**。点击**管理节点**链接。它将提供所有节点的信息，如下面的截图所示：![管理 Jenkins 主节点和从节点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_01.jpg)

1.  要创建从节点，点击**新建节点**。![管理 Jenkins 主节点和从节点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_02.jpg)

1.  提供**名称**、**描述**、**标签**等。选择**通过 Java Web Start 启动从节点代理**作为**启动方法**。提供**标签**；在我们的例子中，它是`java8`：![管理 Jenkins 主节点和从节点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_03.jpg)

1.  点击**保存**。它将打开一个页面，详细说明如何启动从节点。![管理 Jenkins 主节点和从节点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_04.jpg)

1.  在 Windows 机器上打开终端并运行`javaws http://192.168.13.128:8080/computer/WindowsNode/slave-agent.jnlp`。![管理 Jenkins 主节点和从节点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_05.jpg)

    它将打开一个下载应用程序的对话框。

    ![管理 Jenkins 主节点和从节点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_06.jpg)

1.  运行**Jenkins 远程代理**。![管理 Jenkins 主节点和从节点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_07.jpg)

    将打开一个小窗口用于 Jenkins 从节点代理。

    ![管理 Jenkins 主节点和从节点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_08.jpg)

    **从节点 WindowsNode**将通过 JNLP 代理连接。

    ![管理 Jenkins 主节点和从节点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_09.jpg)

1.  在 Jenkins 仪表板上，前往**管理 Jenkins**。点击**管理节点**链接。它将提供所有节点的信息，如下截图所示。在左侧边栏的**构建执行器状态**部分验证两个节点。![管理 Jenkins 主从节点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_10.jpg)

1.  如果我们想在特定节点上运行选择性构建作业，则可以按作业配置它，如下截图所示。勾选**限制此项目可运行的位置**并提供在作业配置页面上给定特定节点的**标签表达式**。![管理 Jenkins 主从节点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_11.jpg)

1.  点击**立即构建**以执行构建。验证控制台并查找我们在前一部分中配置的 WindowsNode 上的远程构建。

    它将在从节点上检出代码并在特定节点上执行操作。

    ![管理 Jenkins 主从节点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_12.jpg)

这种配置在希望在特定节点上可用的特定运行时环境中运行构建作业时很有用。

# Jenkins 监控与 JavaMelody

监控插件通过 JavaMelody 提供 Jenkins 的监控。它提供 CPU、内存、系统平均负载、HTTP 响应时间等图表。还提供 HTTP 会话、错误和日志、GC 操作、堆转储、无效会话等的详细信息。从 Jenkins 仪表板安装监控插件。

![Jenkins 监控与 JavaMelody](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_13.jpg)

1.  在 Jenkins 仪表板上，点击**管理 Jenkins**。点击**Jenkins 主节点监控**，如下截图所示：![Jenkins 监控与 JavaMelody](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_14.jpg)

1.  它将打开 JavaMelody 监控的统计信息，如下截图所示。观察所有统计信息：![Jenkins 监控与 JavaMelody](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_15.jpg)

1.  向下滚动页面，我们将找到**系统错误日志统计信息**。![Jenkins 监控与 JavaMelody](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_16.jpg)

1.  要获取更多信息，请点击任何部分的**详细信息**链接。HTTP 统计信息如下所示：![Jenkins 监控与 JavaMelody](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_17.jpg)

1.  更多详情请访问 [`wiki.jenkins-ci.org/display/JENKINS/Monitoring`](https://wiki.jenkins-ci.org/display/JENKINS/Monitoring) 了解监控插件。

# 管理磁盘使用

1.  磁盘使用插件记录磁盘使用情况。从 Jenkins 仪表板安装**磁盘使用插件**。![管理磁盘使用](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_18.jpg)

1.  插件成功安装后，我们将在管理 Jenkins 页面获得**磁盘使用**链接，如下截图所示：![管理磁盘使用](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_19.jpg)

1.  磁盘使用插件将展示所有作业和所有工作区的项目级详细信息，并显示**磁盘使用趋势**。![管理磁盘使用](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_20.jpg)

如需了解更多关于磁盘使用插件的详细信息，请访问[`wiki.jenkins-ci.org/display/JENKINS/Disk+Usage+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Disk+Usage+Plugin)。

# 使用构建监控插件进行构建监控

**构建监控插件**提供所选 Jenkins 任务状态的详细视图。它显示所选任务的状态和进度，以及可能负责“破坏构建”的人员姓名。此插件支持 Claim 插件、视图任务过滤器、构建失败分析器和 CloudBees 文件夹插件。

![使用构建监控插件进行构建监控](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_21.jpg)

1.  将使用 Dashboard View 插件创建一个视图，该视图提供构建任务特定监控的详细信息。创建新视图并选择**构建监控视图**。![使用构建监控插件进行构建监控](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_22.jpg)

1.  选择**任务**并保存详细信息。![使用构建监控插件进行构建监控](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_23.jpg)

1.  点击新创建的视图，我们将看到类似于以下截图的界面：![使用构建监控插件进行构建监控](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_24.jpg)

如需了解更多关于插件的详细信息，请访问[`wiki.jenkins-ci.org/display/JENKINS/Build+Monitor+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Build+Monitor+Plugin)。

# 访问控制与授权管理

Jenkins 支持多种安全模型，并能与不同的用户存储库集成。

1.  转到 Jenkins 仪表板，点击**管理 Jenkins**，然后点击**配置全局安全**。

1.  点击**启用安全**。![访问控制与授权管理](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_25.jpg)

    一旦我们启用安全，所有选项都将可见，如下面的截图所示：

    ![访问控制与授权管理](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_26.jpg)

1.  点击**Jenkins 自有用户数据库**。点击**保存**。![访问控制与授权管理](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_27.jpg)

1.  现在，点击右上角的**注册**链接。提供**用户名**、**密码**、**全名**和**电子邮件地址**。![访问控制与授权管理](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_28.jpg)

1.  点击仪表板上的**登录**链接。![访问控制与授权管理](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_29.jpg)

    我们将看到右上角显示用户名的 Jenkins 仪表板。

    ![访问控制与授权管理](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_30.jpg)

1.  点击**人员**以验证所有用户。![访问控制与授权管理](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_31.jpg)

1.  在 Jenkins 仪表板上，点击**管理 Jenkins**。点击**管理用户**。![访问控制与授权管理](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_32.jpg)

    我们可以在同一页面上编辑用户详细信息。这是用户的一个子集，其中也包含自动创建的用户。

# 维护角色和基于项目的安全性

对于授权，我们可以在**配置全局安全**页面上定义**基于矩阵的安全性**。

1.  添加组或用户，并根据不同部分如**凭证**、**从属**、**任务**等配置安全设置。

1.  点击 **保存**。![维护角色和基于项目的安 全](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_33.jpg)

    我们可以使用多个用户进行基于矩阵的安全设置，如下面的截图所示：

    ![维护角色和基于项目的安 全](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_34.jpg)

1.  尝试使用新添加的无权限用户访问 Jenkins 仪表板，我们将发现授权错误。![维护角色和基于项目的安 全](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_35.jpg)

1.  现在为新添加的用户提供总体读取权限；构建、读取和工作区权限。![维护角色和基于项目的安 全](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_36.jpg)

1.  使用新添加的用户登录并验证我们是否可以看到仪表板。我们看不到 **管理 Jenkins** 链接，因为我们未提供这些权限。![维护角色和基于项目的安 全](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_37.jpg)

1.  点击任何构建作业。构建链接可用，因为我们已授予权限，但配置链接不可用，因为我们未为其授予权限。![维护角色和基于项目的安 全](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_38.jpg)

1.  我们还可以设置 **基于项目的矩阵授权策略**。![维护角色和基于项目的安 全](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_39.jpg)

1.  转到特定构建作业的配置并 **启用基于项目的安 全**。![维护角色和基于项目的安 全](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_40.jpg)

1.  为不同用户分配权限，并使用特定用户名登录以验证授权策略是否正常工作。![维护角色和基于项目的安 全](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_41.jpg)

1.  验证构建详细信息，如下面的截图所示：![维护角色和基于项目的安 全](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_42.jpg)

我们已经介绍了 Jenkins 安全配置的基础知识。作为练习，请探索其他选项。如果授权设置不正确，可以通过编辑 `config.xml` 进行更正。将其视为自学内容。

# 审计轨迹插件 – 概览与使用

审计轨迹插件记录执行特定 Jenkins 操作（如配置作业）的用户。此插件在 Jenkins 主配置页面中添加了一个 **审计轨迹** 部分。

安装 **审计轨迹插件**。

![审计轨迹插件 – 概览与使用](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_43.jpg)

在 Jenkins 配置中，配置 **日志记录器**，如下面的截图所示：

![审计轨迹插件 – 概览与使用](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_44.jpg)

停止 Jenkins 服务器并重新启动。运行任何构建作业并打开日志文件以验证日志记录。

![审计轨迹插件 – 概览与使用](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_07_45.jpg)

要获取更多详细信息，请访问 [`wiki.jenkins-ci.org/display/JENKINS/Audit+Trail+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Audit+Trail+Plugin)。

# 自测问题

Q1. 使从节点上线有哪些不同方式？

1.  从浏览器在从节点上启动代理

1.  从命令行运行 `slave-agent.jnlp` 命令

1.  运行 `java -jar slave.jar`

1.  以上所有

Q2. Jenkins 监控为哪些选项提供图表？

1.  中央处理器

1.  内存

1.  系统负载平均值

1.  HTTP 响应时间

1.  以上所有

Q3. Jenkins 中的安全领域有哪些选项？

1.  委托给 Servlet 容器

1.  Jenkins 自身的用户数据库

1.  LDAP

1.  Unix 用户/组数据库

1.  以上所有

# 总结

无论我们构建了什么好东西，最终都会塑造我们自己。在本章中，我们介绍了主从节点的概念，如何监控构建作业，以及使用管理功能进行统计报告。我们还了解了如何通过使用基于角色的安全配置来确保 Jenkins 环境的安全，包括身份验证和授权。我们看到了审计跟踪插件如何在 Jenkins 中存储审计细节。

在下一章中，我们将介绍一些重要的插件，这些插件为 Jenkins 增加了显著的价值。在我们告别之前，让我们享受最后的旅程。


# 第八章：超越 Jenkins 基础 —— 利用“必备”插件

|   | *"力量和成长只来自持续不断的努力和奋斗。"* |   |
| --- | --- | --- |
|   | --*拿破仑·希尔* |

在上一章中，我们涵盖了 Jenkins 的管理、监控以及安全方面。在安全方面，我们理解了认证和授权的工作原理。现在，是时候认识一些重要插件带来的附加价值了。

本章涵盖了 Jenkins 的高级用法，这在特定场景下极为有用。本章还涵盖了基于场景的特定插件的使用，这些插件有助于开发和运维团队更好地利用 Jenkins。其中一些插件在通知场景中极为有用。以下是本章将涵盖的主要主题：

+   Extended E-mail Plugin

+   Workspace cleanup Plugin

+   Pre-scm-buildstep Plugin

+   Conditional BuildStep Plugin

+   EnvInject Plugin

+   Build Pipeline Plugin

# Extended Email Plugin

Email-ext 插件扩展了 Jenkins 提供的电子邮件通知功能。它在触发邮件通知的条件和内容生成方面提供了更多定制化选项。

您可以从 Jenkins 仪表板安装此插件。

![Extended Email Plugin](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_08_01.jpg)

定制化可在三个领域进行：

+   触发器：我们可以选择导致发送电子邮件通知的条件

+   内容：我们可以指定每个触发电子邮件的主题和正文内容；我们可以在内容中使用默认环境变量

+   收件人：我们可以指定谁应该在触发时收到电子邮件

在 Jenkins 仪表板中，点击**管理 Jenkins**，然后点击**系统配置**。前往**扩展电子邮件通知**部分，配置应与您的 SMTP 邮件服务器设置相匹配的全球电子邮件扩展属性。

![Extended Email Plugin](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_08_02.jpg)

我们还可以自定义主题、最大附件大小、默认内容等。

![Extended Email Plugin](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_08_03.jpg)

要在构建作业中配置特定的 Email-ext，请在项目配置页面上启用它。在**构建后操作**中选择标有**可编辑邮件通知**的复选框。配置由逗号（或空格）分隔的全球收件人、主题和内容列表。在高级配置中，我们可以配置预发送脚本、触发器、电子邮件令牌等。

![Extended Email Plugin](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_08_04.jpg)

预发送脚本功能允许我们编写一个脚本，该脚本可以在发送消息之前修改`MimeMessage`对象。触发器允许我们配置必须满足的条件以发送电子邮件。Email-ext 插件使用令牌允许动态数据插入到收件人列表、电子邮件主题行或正文中。更多详情，请访问[`wiki.jenkins-ci.org/display/JENKINS/Email-ext+plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Email-ext+plugin)。

# Workspace cleanup Plugin

工作区清理插件用于在构建之前或构建完成并保存工件时从 Jenkins 删除工作区。如果我们想在干净的工件区开始 Jenkins 构建，或者我们想在每次构建之前清理特定目录，那么我们可以有效地使用此插件。删除工作区有不同的选项。

你可以在 Jenkins 仪表板上安装此插件。

![工作区清理插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_08_05.jpg)

我们可以根据构建作业的状态应用要删除的文件的模式。我们可以添加工作区删除的后构建操作。

![工作区清理插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_08_06.jpg)

更多详情，请访问[`wiki.jenkins-ci.org/display/JENKINS/Workspace+Cleanup+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Workspace+Cleanup+Plugin)。

# Pre-scm-buildstep 插件

Pre-scm-buildstep 插件允许在 SCM 检出之前运行特定构建步骤，以防我们需要根据任何特殊要求（如添加包含 SCM 设置的文件、执行创建某些文件的命令、清理或调用需要在检出前运行的其他脚本）对工作区执行任何构建步骤操作。

你可以在 Jenkins 仪表板上安装此插件。

![Pre-scm-buildstep 插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_08_07.jpg)

从列表中选择条件步骤，如下面的截图所示：

![Pre-scm-buildstep 插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_08_08.jpg)

根据需求选择条件步骤，并提供基于操作系统的命令列表，如下面的截图所示：

![Pre-scm-buildstep 插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_08_09.jpg)

更多详情，请访问[`wiki.jenkins-ci.org/display/JENKINS/pre-scm-buildstep`](https://wiki.jenkins-ci.org/display/JENKINS/pre-scm-buildstep)。

# 条件构建步骤插件

构建步骤插件允许我们包装任意数量的其他构建步骤，根据定义的条件控制它们的执行。

你可以在 Jenkins 仪表板上安装此插件。

![条件构建步骤插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_08_10.jpg)

此插件定义了几种核心运行条件，例如：

+   始终/从不：从作业配置中禁用构建步骤

+   布尔条件：如果令牌扩展为 true 的表示，则执行步骤

+   当前状态：如果当前构建状态在配置/特定范围内，则执行构建步骤

+   文件存在/文件匹配：如果文件存在或匹配模式，则执行步骤

+   字符串匹配：如果两个字符串相同，则执行步骤

+   数值比较：根据比较两个数字的结果执行构建步骤

+   正则表达式匹配：提供正则表达式和标签，如果表达式与标签匹配，则执行构建步骤

+   时间/星期：在一天中的指定时间段或一周的某一天执行构建作业

+   与/或/非：逻辑操作，用于组合和反转运行条件的意义

+   构建原因：根据构建原因执行构建步骤，例如，由计时器、用户、SCM 变更等触发

+   脚本条件：利用 shell 脚本决定是否跳过某一步骤

+   批处理条件：利用批处理决定是否跳过某一步骤

从**添加构建步骤**中选择**条件步骤（单个）**。

![条件构建步骤插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_08_11.jpg)

从**添加构建步骤**中选择**条件步骤（多个）**。我们可以在此条件步骤中添加多个条件步骤。

![条件构建步骤插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_08_12.jpg)

欲了解更多详情，请访问[`wiki.jenkins-ci.org/display/JENKINS/Conditional+BuildStep+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Conditional+BuildStep+Plugin)。

# EnvInject 插件

我们知道，开发、测试和生产等不同环境需要不同的配置。

从 Jenkins 仪表板安装此插件。

![EnvInject 插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_08_13.jpg)

EnvInject 插件提供了为不同构建作业创建隔离环境的设施。EnvInject 插件在节点启动时、SCM 签出前后、运行时的构建步骤等情况下注入环境变量。选择**向构建过程注入环境变量**，具体针对构建作业。

![EnvInject 插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_08_14.jpg)

欲了解更多详情，请访问[`wiki.jenkins-ci.org/display/JENKINS/EnvInject+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/EnvInject+Plugin)。

# 构建管道插件

持续集成已成为应用程序开发的流行实践。构建管道插件提供了一个管道视图，显示上游和下游连接的工作，这些工作通常形成一个构建管道，并具有定义手动触发器或审批流程的能力。我们可以在部署到生产环境之前，通过不同的质量门协调版本升级，创建一系列工作。

从 Jenkins 仪表板安装此插件。

![构建管道插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_08_15.jpg)

我们已安装仪表板视图插件。我们将为四个构建作业创建一个管道。假设我们有四个构建作业，如下图所示，每个构建作业的目标如下：

![构建管道插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_08_16.jpg)

1.  创建一个新视图并选择**构建管道视图**。![构建管道插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_08_17.jpg)

1.  在构建管道的配置中提供描述并选择布局。

1.  选择初始工作并设置显示的构建数量，然后保存配置。![构建管道插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_08_18.jpg)

1.  在构建管道的配置中，选择触发参数化构建的工作，如**后构建操作**中的`settle-build`工作。它将是管道中的第一个构建工作。![构建管道插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_08_19.jpg)

1.  在`settle-build`作业中，在**构建后操作**中触发`settle-aws-provisioning`作业的参数化构建。![构建管道插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_08_20.jpg)

1.  在`settle-aws-provisioning`作业中，在**构建后操作**中为`settle-deploy`作业执行手动构建步骤。![构建管道插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_08_21.jpg)

1.  在`settle-aws-provisioning`作业中，在**构建后操作**中触发`settle-deploy`作业的参数化构建。在`settle-deploy`构建作业中，我们可以编写脚本或执行命令，以便将`war`文件部署到云环境中新配置的虚拟机上。![构建管道插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_08_22.jpg)

1.  前往我们之前创建的仪表板视图，并验证在上一节配置的构建作业后创建的管道。新的构建管道将如以下图示创建：![构建管道插件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ess/img/3471_08_23.jpg)

更多详情，请访问[`wiki.jenkins-ci.org/display/JENKINS/Build+Pipeline+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Build+Pipeline+Plugin)。

# 自我测试问题

Q1. 扩展邮件插件在哪些领域提供定制化？

1.  触发器

1.  内容

1.  收件人

1.  以上所有

Q2. 工作区清理插件提供了一个选项，当构建状态为：

1.  成功

1.  不稳定

1.  失败

1.  未构建

1.  中止

1.  以上所有

# 总结

我们学习了如何使用一些重要插件来辅助 Jenkins 现有的功能，以满足特定需求。我们涵盖了 Jenkins 的基本使用，包括安装运行时环境、创建构建作业、使用 Jenkins 云、监控、管理、安全以及附加插件。对于本书的范围，这似乎已经足够。下一步是在云环境中动态配置资源，以实现 DevOps 旅程中的端到端自动化。

如果你想要一个幸福的结局，当然这取决于你在哪里停止你的故事。我们当然知道在哪里停止我们的故事！
