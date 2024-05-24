# Jenkins 扩展指南（一）

> 原文：[`zh.annas-archive.org/md5/1B4E904A1EC387CFCD69447FB1ABCAA9`](https://zh.annas-archive.org/md5/1B4E904A1EC387CFCD69447FB1ABCAA9)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Jenkins 提供了许多接口和扩展点，以使用户能够定制和扩展其功能。在本书中，我们将深入探讨这些接口，并提供实际的现实世界示例，将带领您的 Jenkins 使用提升到一个新的水平。

在本书中，您将学习如何开发和测试自己的 Jenkins 插件，了解如何设置完全自动化的构建流水线和开发流程，发现如何与 API 和 CLI 进行交互，以及如何增强用户界面。

# 本书涵盖的内容

第一章，“准备步骤”，将涵盖初始设置步骤 - 设置开发环境，Jenkins 概述以及安装和运行它的一些选项，以及扩展基本设置。我们还将回顾持续集成的原则，这些原则稍后将更详细地探讨。

第二章，“自动化 Jenkins UI”，将讨论通过自动化和调整 Jenkins 前端来缓解一些常见问题和瓶颈。在这里，我们将看到四个相当典型的用例，确定问题的根本原因，并提出一些可能的改进，通过改变和自动化 GUI 来实现。

第三章，“Jenkins 和 IDE”，建立在我们之前讨论的持续集成原则的基础上，并介绍了 Mylyn 项目。

然后详细介绍了如何设置一个流程，使开发人员能够直接从他们的 IDE 中与 Jenkins 进行交互。一系列示例涵盖了 Eclipse，NetBeans 和 IntelliJ。

第四章，“API 和 CLI”，说明了我们如何通过其 API 和 CLI 自动化和扩展 Jenkins。在本章中，我们将通过一个示例“信息辐射器”项目的高级“构建块”来说明如何使用这些接口。

本章将解释如何创建一个动态应用程序，通过其公开的接口从 Jenkins 中获取信息。

我们还将回顾其他通过 CLI 扩展 Jenkins 的方法 - 通过自动和远程地启动作业和对 Jenkins 进行其他更改。

第五章，“扩展点”，介绍了许多重要概念，为随后章节中的 Jenkins 扩展点主题奠定了基础。我们将运行 Java 接口，按合同设计，抽象类和单例。然后，我们将看看在我们定义 Jenkins 中自己的扩展点时，这些模式是如何在现实世界中使用的。

第六章，“开发您自己的 Jenkins 插件”，将结合前面章节的技能、概念和工具来构建我们的第一个 Jenkins 插件。

我们将学习如何设置 Maven 并将其用于 Jenkins 插件开发。然后，我们将创建我们的第一个 Jenkins 插件，学习如何在本地安装它，然后学习如何使用 Maven 快速进行后续更改的制作，构建和部署。

第七章，“扩展 Jenkins 插件”，使用了在上一章中创建的具有“Hello world”功能的简单插件，以便专注于掌握这些过程和工具。本章将介绍开始添加自己的实现的最佳方法。您将学习如何重用现有的代码和功能，并了解如何在何处找到它们。

在查看一些现有插件并将其用作示例之后，我们将详细了解一些您可以在自己的项目中利用的其他资源和技术。

第八章，“测试和调试 Jenkins 插件”，解释了如何测试和调试您自己的代码，以及如何将相同的方法应用于现有插件进行故障排除。

它涵盖了使用 Maven 运行测试，检查了一个流行插件中的一些现有测试，并使用这些来演示您如何调整这些方法以适应您自己的项目。

我们还将介绍如何通过 IDE 调试实时代码，并展示如何将这些有用的功能集成到流行的开发 IDE 中。本章的最后一部分将介绍内置的 Jenkins Logger 控制台。

第九章，“将事物组合在一起”，介绍了 Jenkins 如何扩展以与其他技术和语言一起工作。我们将首先看一下 Jenkins 脚本控制台，并看看它与一些 Groovy 脚本结合时有多么有用，通过提供一些示例来说明。然后，我们将讨论使用 Groovy、Grails 和 Gradle 开发应用程序，作为 Maven 和 Java 的可能替代方案。本章的最后部分涵盖了 Jenkins 和 Docker，然后讨论了如何为 iOS 和 Android 开发设置构建和部署流水线。

# 您需要为这本书做好准备

假定读者对 Jenkins 和编程有一定的了解，有兴趣学习不同的选项以将事物提升到下一个水平，并且有倾向于了解如何定制和扩展 Jenkins 以满足他们的需求和需求。

# 这本书适合谁

这本书主要面向对将他们与 Jenkins 的交互和使用提升到下一个水平感兴趣的开发人员和管理员——将其扩展以适应他们的需求，通过其接口与 Jenkins 进行交互，并开发自己的自定义单元测试插件。

# 约定

在这本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是这些样式的一些示例以及它们的含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“我们可以通过使用`include`指令包含其他上下文。”

代码块设置如下：

```
<html>
  <head>
    <meta http-equiv="refresh" content="5">
    <style type="text/css">
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```
<html>
  <head>
    <**meta http-equiv="refresh" content="5"**>
    <style type="text/css">
```

任何命令行输入或输出都将按以下方式编写：

```
**java -jar jenkins-cli.jar -s http://minty:8080/ get-job VeryBasicJob**

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“请注意，[`jenkins-ci.org/`](http://jenkins-ci.org/)主页还为许多流行操作系统提供了**本机安装程序**，位于**本机软件包**列下。”

### 注意

警告或重要说明会以这样的方式出现在框中。

### 提示

提示和技巧显示为这样。


# 第一章：准备步骤

在这第一章中，我们将从几个不同的角度来看 Jenkins；如何获取和运行它，人们使用它的方式和原因，以及它为他们提供了什么。在这样做的过程中，我们将看一些标准用例，并检查 Jenkins 安装通常会随着时间的推移而演变的方式——通常从基本安装和核心功能开始，然后逐渐变得更加定制和先进，使用不同类型的扩展。我们将从“现成的”插件开始，然后逐步扩展这些插件，然后看如何开发自己的插件。

然后我们将总结本书的高层目标，并详细说明您希望从中获得的内容。

我们将概述你需要运行后续章节中涵盖的实际示例所需的各种工具和环境设置，并通过识别 Jenkins 可以用来实现这些最佳实践的一些方式来审查**持续集成**（**CI**）的最佳实践。

在本书中，假设您已经对 Jenkins 有一些工作知识，因此我们不会花太多时间来介绍基础知识，比如安装和启动 Jenkins，或者详细说明标准功能和核心功能的使用。

如果您想了解更多关于这些主题的细节，在线有许多有用的教程和示例；Jenkins 主页的**使用 Jenkins**部分，[`jenkins-ci.org`](https://jenkins-ci.org)，通常是寻求一般设置和使用问题帮助的好起点。

# 开始使用 Jenkins

作为一个 Java 应用程序，Jenkins 可以根据您的要求、个人偏好和运行环境的不同方式进行安装和运行。

快速启动 Jenkins 的最简单和最简单的方法是设置 Java，从 Jenkins 主页([www.jenkins-ci.org](http://www.jenkins-ci.org))下载最新的 Jenkins WAR 文件，然后像这样从命令行启动它：

```
**java –jar jenkins.war**

```

以下图示了通过运行两个简单命令来使用这种方法：

1.  `wget http://mirrors.jenkins-ci.org/war/latest/jenkins.war`：

这个命令从主站点下载最新版本的 Jenkins。

`wget`是一个从网络获取文件的 Linux 实用程序——如果您使用的平台没有`wget`，您可以通过浏览器将链接（`jenkins.war`文件）保存到工作目录。

URL 是通过从主页[`jenkins-ci.org/`](https://jenkins-ci.org/)复制**最新和最伟大**链接获得的。请注意，还有一个选项可以下载并使用长期支持版本，而不是当前的、最新的和最伟大的版本，如下所述：[`wiki.jenkins-ci.org/display/JENKINS/LTS+Release+Line`](https://wiki.jenkins-ci.org/display/JENKINS/LTS+Release+Line)。

这对于更保守的安装来说更可取，稳定性比拥有最新功能更重要。

1.  `java –jar jenkins.war`：

这第二个命令告诉 Java 运行我们刚刚下载的 WAR 文件作为一个应用程序，产生了你可以在下面的截图中看到的结果输出——Jenkins 从 WAR 文件中解压，检查和初始化各个子系统，并在端口`8080`上启动一个进程：

![开始使用 Jenkins](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00002.jpeg)

下载和启动 Jenkins

这个简单的过程通常是下载最新版本的 Jenkins 并让它运行所需的全部。现在你应该能够通过浏览器访问`http://localhost:8080`的 web 界面，并开始设置工作来让 Jenkins 为你工作：

![开始使用 Jenkins](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00003.jpeg)

Jenkins 启动页面

# 扩展基本设置

当您从启动我们之前查看的进程的命令提示符或 shell 退出时，Jenkins 实例将随着退出而停止，因此除了非常快速的临时测试外，强烈建议使用某种初始化或进程管理脚本。这样的脚本也可以很容易地定制，以执行一些对您有益的功能，例如以下内容：

+   在系统启动时启动

+   满足`stop|start|restart|status`请求

+   将控制台输出重定向到日志文件，以便您可以监视其中的问题

+   作为后台/守护进程运行

+   通过设置`--httpPort=`参数在非标准端口上运行，在端口`8080`已被另一个应用程序使用的情况下

+   绑定到特定的网络接口，而不是使用`--httpListenAddress=`选项的默认值`0.0.0.0`

这个基于 Ubuntu 的示例脚本从主页演示了 Jenkins 在 Tomcat 下运行的许多先前提到的功能。该脚本可以在[`wiki.jenkins-ci.org/display/JENKINS/JenkinsLinuxStartupScript`](https://wiki.jenkins-ci.org/display/JENKINS/JenkinsLinuxStartupScript)找到，如下所示：

```
#!/bin/sh
#
# Startup script for the Jenkins Continuous Integration server
# (via Jakarta Tomcat Java Servlets and JSP server)
#
# chkconfig: - 85 15
# description: Jakarta Tomcat Java Servlets and JSP server
# processname: jenkins
# pidfile: /home/jenkins/jenkins-tomcat.pid

# Set Tomcat environment.
JENKINS_USER=jenkins
LOCKFILE=/var/lock/jenkins
export PATH=/usr/local/bin:$PATH
export HOME=/home/jenkins
export JAVA_HOME=/usr/lib/jvm/java-6-sun
export JENKINS_BASEDIR=/home/jenkins
export TOMCAT_HOME=$JENKINS_BASEDIR/apache-tomcat-6.0.18
export CATALINA_PID=$JENKINS_BASEDIR/jenkins-tomcat.pid
export CATALINA_OPTS="-DJENKINS_HOME=$JENKINS_BASEDIR/jenkins-home -Xmx512m -Djava.awt.headless=true"

# Source function library.
. /etc/rc.d/init.d/functions

[ -f $TOMCAT_HOME/bin/catalina.sh ] || exit 0

export PATH=$PATH:/usr/bin:/usr/local/bin

# See how we were called.
case "$1" in
  start)
        # Start daemon.
        echo -n "Starting Tomcat: "
        su -p -s /bin/sh $JENKINS_USER -c "$TOMCAT_HOME/bin/catalina.sh start"
        RETVAL=$?
        echo
        [ $RETVAL = 0 ] && touch $LOCKFILE
        ;;
  stop)
        # Stop daemons.
        echo -n "Shutting down Tomcat: "
        su -p -s /bin/sh $JENKINS_USER -c "$TOMCAT_HOME/bin/catalina.sh stop"
        RETVAL=$?
        echo
        [ $RETVAL = 0 ] && rm -f $LOCKFILE
        ;;
  restart)
        $0 stop
        $0 start
        ;;
  condrestart)
       [ -e $LOCKFILE ] && $0 restart
       ;;
  status)
        status -p $CATALINA_PID -l $(basename $LOCKFILE) jenkins
        ;;
  *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
esac
exit 0
```

请注意，[`jenkins-ci.org/`](http://jenkins-ci.org/)主页还托管了许多流行操作系统的**本机安装程序**，在**本机软件包**栏下。这些页面提供了每个操作系统的下载链接和安装说明。

您可能还想考虑在 J2EE 容器中运行 Jenkins，这通常会更好地与您现有的软件堆栈和架构相匹配。这可能意味着您将继承额外的好处，如容器的日志记录、身份验证、授权或弹性。Jenkins 可以在许多流行的 J2EE 兼容容器中运行，包括以下内容：

+   WebSphere

+   WebLogic

+   Tomcat

+   JBoss

+   Jetty

+   Jonas

Web 上有更多的`init`脚本示例和详细的安装说明，应该涵盖任何操作系统和容器设置的组合。这意味着您应该能够设置 Jenkins 以适应您的环境和偏好。

为了本书的目的，我们将假设 Jenkins 直接从本地主机的命令行运行。如果您使用 J2EE 容器来托管应用程序或在远程主机上运行应用程序，您唯一会注意到的区别是您可能需要执行额外的管理和部署步骤。

# Jenkins 演进

通常，大多数用户或组织会通过设置基本的标准 Jenkins 安装来开始他们的 Jenkins 之旅，以管理一些简单的开发任务。最常见的用途是构建您的源代码，无论是定期还是在中央仓库（Git、Subversion 等）中更改时。

使用 Jenkins 自动化这种简单和重复的任务通常会很快而轻松地提供许多有用的好处。直接使用，您将获得一系列有用的功能，如任务调度和作业触发、构建和测试报告页面、在出现新问题时发送电子邮件通知和警报，以及提供当前代码库的健康（或不健康）的快速实时反馈。如果您还没有工具来提供这些功能，那么设置标准的 Jenkins 实例将提供这些初始基本功能，这些功能本身可能会改变您的开发流程。

在这之后的下一个逻辑步骤是逐渐向设置中添加更多的智能和复杂性——代码是否编译正常？现在通过了多少单元测试？应用程序编译需要多长时间？哦，我们能否在网页上显示谁改变了代码库的哪些部分？我们的应用程序是否比以前运行得更快或更好，是否稳定？甚至在我们开始添加任何类型的扩展或定制之前，核心的 Jenkins 安装就提供了大量的选项——你可以选择在任何运行 Java 的平台上构建你的应用程序（这意味着现在几乎任何地方都可以），你也可以以最适合你和当前设置的方式来做，包括使用标准和流行的构建工具，如 Ant 或 Maven，并/或重用现有的 Ant 或 Maven 构建脚本，或者你的 Linux Shell 或 Windows DOS 脚本。

您还可以通过部署 Jenkins 从节点轻松设置跨平台环境，这将允许您在不同的主机上运行不同的作业。这在使用组合操作系统的环境中可能很有用；例如，您的应用程序在 Linux 上运行，您希望在 Windows 主机上使用 Internet Explorer 运行基于浏览器的测试。

作为现有流程易于配置的“包装器”的能力，再加上 Jenkins 的灵活性，使得很容易以最小的变化或中断来适应您的特定设置。这使得 Jenkins 比不得不改变现有的构建和部署流程和实践来适应新工具的要求要容易得多。

在这个阶段之后，建立持续集成环境的好处往往变得非常明显：如果我们可以自动构建我们的代码并打包我们的应用程序，那么如果我们能够自动部署它，那不是很好吗？然后，如果我们这样做了，我们可以自动测试我们的新应用程序在目标平台的副本上的性能如何！

在达到这一点时，Jenkins 将成为您持续集成过程中的关键工具，您可以将其扩展以满足不断增长和特定的需求，您将从中获得更多的好处。

这将引导我们扩展 Jenkins，这是我们将在本书的其余部分中研究的内容。

扩展 Jenkins 的最简单方法是通过其不断扩展的插件。建议并且有益的是浏览它们；现有的插件经常得到改进，并更新了新功能，新的插件也在不断增加到列表中。然而，我们将不仅仅在这里审查一些流行的插件——在本书结束时，您应该能够将您对 Jenkins 的使用提升到一个新的水平，创建您自己的定制插件和扩展，并使用 Jenkins 提供给我们的许多功能和接口进行扩展和交互。

我们将详细研究以下内容：

+   我们可以使用现有功能的不同方式

+   通过其各种接口和 API 与 Jenkins 进行交互

+   如何在 IDE 内部与 Jenkins 进行交互

+   构建现有功能以满足您的需求的方法

+   开发、测试和构建您自己的定制 Jenkins 扩展。

以下是我们将使用的主要工具，以及有关设置它们的信息，以及如果需要的话进一步帮助和信息的来源：

+   **Java 开发工具包**（**JDK**）：您需要与您的 Java IDE 相同位级的版本，也就是说，根据您的架构和偏好，两者都需要是 32 位或 64 位。您可以选择 IBM、Oracle 或 OpenJDK 6.0 或更高版本。每个供应商都为所有主要平台提供安装说明。

+   Java IDE：我们主要将使用 Eclipse，但也会尽可能满足 NetBeans 和 IntelliJ。

每个 IDE 的最新版本都可以在各自的网站上找到：

+   [`www.eclipse.org/downloads/`](https://www.eclipse.org/downloads/)

+   [`netbeans.org/downloads/`](https://netbeans.org/downloads/)

+   [`www.jetbrains.com/idea/download/`](https://www.jetbrains.com/idea/download/)

+   Mylyn：这用于从我们的 IDE 与 Jenkins 进行通信。如果您的 IDE 中尚未包含 Mylyn，您可以从 Eclipse 网站下载它：[`www.eclipse.org/mylyn/downloads/`](http://www.eclipse.org/mylyn/downloads/)。我们将在第三章中详细介绍这一点，*Jenkins 和 IDE*。

+   Maven：我们将使用 Maven 3 来构建 Jenkins 源代码和我们自己的自定义插件。Maven 是一个 Java 工具，因此它需要了解您系统的 JDK。

+   Jenkins 源：这将由 Maven 下载。

+   Git：在大多数 Linux 平台上，`sudo apt-get install git`的等效命令应该足够了。在 Mac 上，有几个选项，包括 Sourceforge 上的`git-osx`安装程序。对于 Microsoft Windows，可以在[`msysgit.github.io/`](http://msysgit.github.io/)上找到可执行安装程序。

随着我们在后面的章节中使用它们，我们将更详细地介绍每个组件的安装和使用。

# 使用 Jenkins 进行持续集成

在我们结束本章之前，这里是持续集成的关键实践列表（由 Martin Fowler 在 2006 年定义），以及 Jenkins 可以帮助您实现这些实践的方式的示例：

+   维护单一源代码存储库：Jenkins 可以与所有现代源代码和版本控制存储库进行交互——一些功能是内置的，其他功能可以作为扩展添加。

+   自动化构建：正如前面的用例中所描述的，这是 Jenkins 的核心目标之一，也经常是开始使用 Jenkins 的主要动力。

+   使您的构建自我测试：这通常是在使用 Jenkins 设置 CI 环境的第二步——一旦自动化了代码构建，自动化测试也是自然的进展。

+   每个人每天都致力于主线：不幸的是，我们无法强迫开发人员这样做。然而，我们可以很容易地突出和报告谁在做什么，或者没有做什么，这最终应该帮助他们学会遵循这一最佳实践。

+   每次提交都应在集成机器上构建主线：构建可以由开发人员的提交触发，并且 Jenkins 从节点可以用于构建并提供准确的副本环境以进行构建。

+   立即修复破损的构建：这是另一个需要采用的开发人员最佳实践——当 Jenkins 显示红色时，重点应该放在修复问题上，直到显示绿色。在构建破损时，没有人应该提交新的更改，Jenkins 可以配置为以最有效的方式传达当前状态。

+   保持构建速度快：通过将工作分派和分布到分布式从节点，并通过分解构建来识别和专注于已更改的区域，Jenkins 可以被调整为对变化提供快速响应——一个良好的目标是提交更改并在 10 分钟内获得清晰的结果或影响。

+   在生产环境的克隆中进行测试：在编译新更改后，可以创建下游 Jenkins 作业，这些作业将准备环境并将其带到所需的级别——应用数据库更改，启动依赖进程，并部署其他先决条件。在 Jenkins 与虚拟机或容器结合使用，自动在已知良好状态下启动环境可能非常有用。

+   **让任何人都能轻松获取最新的可执行文件**：Jenkins 可以设置为充当托管最新版本的 Web 服务器，以便每个人（以及其他进程/消费者）可以轻松获取，或者还可以用于在新版本已上传到 Nexus、Artifactory 等时向感兴趣的方发送详细信息和链接。

+   **每个人都可以看到发生了什么**：Jenkins 的通信方式可以通过多种方式扩展——包括电子邮件提醒、桌面通知、信息辐射器、RSS 订阅、即时通讯等等——从熔岩灯和交通灯到无处不在的玩具火箭发射器！

+   **自动化部署**：这通常是“构建->测试->部署”自动化顺序的逻辑延伸，Jenkins 可以在许多方面提供帮助；通过在部署主机上运行从属节点，或者设置作业以连接到目标并使用最近构建的构件进行更新。

一旦您实现了前述的最佳实践，通常会有许多重要的好处——您的团队将会发布质量更高的软件，并且比以往更快地完成，成本也更低。然而，仅仅建立自动化构建、测试和部署流程是不够的；测试、环境和文化也必须具有足够的质量，而且开发人员、经理和业主对流程和实践的认可通常会产生重大影响。

# 总结

在这个准备章节中，我们已经从功能和实际角度了解了 Jenkins 的基础知识。我们已经对我们将在接下来的章节中使用的工具集进行了高层次的概述，并回顾了持续集成的最佳实践以及 Jenkins 如何帮助您的团队实现这些实践的方式。

在下一章中，我们将探讨如何扩展 Jenkins 用户界面，使其更加高效和智能，以及如何扩展用户体验，使最终用户、Jenkins 管理员、构建脚本和流程的生活更加轻松和高效。


# 第二章：自动化 Jenkins UI

在本章中，我们将研究一系列不同的方法，可以用来改变和增强 Jenkins 的**用户界面**（**UI**）。

与整个 Jenkins 一样，Jenkins 的 UI 是高度可定制的，并且从一开始就明确设计为可适应和可扩展，以便您可以根据自己的特定要求和环境进行定制和调整。

有不同的方式可以定制 UI，从纯粹的*外观*化妆品改变到用户输入的改进，然后到 Jenkins 作业的自动创建和设置动态从节点供应系统。

焦点和最合适的方法通常是由 Jenkins 的使用方式驱动的；通常情况下，关注特定情况中最重要的领域通常是可以获得最大利益的地方。

在本章中，我们将研究四种最常见的用例场景，以及自动化和开发 Jenkins UI 对每种情况可能有所帮助的不同方式。

# 用例场景 1 - 大量作业

单个 Jenkins 实例可以包含许多作业。实际限制因多种因素而异，如下所示：

+   硬件资源，如 RAM、CPU、磁盘和网络性能

+   从节点——有多少个，它们是如何设置的，以及它们的性能

+   工作在主节点和从节点之间分布得如何

+   个别作业的设置；它们的大小、功能、历史和保留

Jenkins 实例拥有超过 1,000 个作业或大约 100 个从节点连接到主节点并不罕见。

管理这造成的性能负载本身就是一项艰巨的任务，Jenkins 还需要管理这些作业的呈现和清理工作——您的用户不希望浏览超过 1,000 个作业来搜索他们需要的作业，我们还需要确保旧作业被清理或归档，新作业可以轻松而准确地创建。

如果您可以减少所需的作业数量，那么管理和资源开销将相应减少，性能、可用性和可靠性也将提高，用户体验也将得到改善。

一些规划和对 UI 的一点自动化通常可以帮助我们实现这一点——让我们看看一些场景和可能的解决方案。

如果最紧迫的问题或瓶颈是有太多的作业，首先了解所有这些作业的需求来源，然后看看我们能做些什么来减轻这个问题，将会很有帮助。

开发团队经常在 Sprints 和/或 Releases 中工作。这通常意味着有一个主要的开发流和一个或多个分支流。通常这个惯例也会在 Jenkins 中遵循——我们可能希望设置 Jenkins 作业来构建然后部署 Sprint 3 或 Release 49 代码到集成环境，同时将我们的主线更改部署到 CI 和开发环境。同时，可能有一个逻辑或业务要求来支持*一切*的生产版本，以防出现问题。

这可能意味着设置相应命名的作业，比如`Sprint 3`，并在配置中硬编码这个值，伪代码大致是*获取 Sprint 3 战争文件并部署到 Sprint 3 服务器…*。

这些工作将有一个有限的（可能相当短的）寿命，然后需要清理或更新为下一个 Sprint 或 Release 的新值。这种定期和手动的维护很快就会成为一个头痛的问题，这进一步增加了人为错误导致错误的部署到错误的地方的可能性。

这种常见情况的一个简单解决方案是利用 Jenkins 环境变量。如果您导航到**管理 Jenkins** | **配置系统** | **全局属性**，您可以创建和定义自己的键值对，这些键值对立即可用于任何节点上的每个作业：

![用例场景 1 - 大量作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00004.jpeg)

前面的截图显示了您可能想设置的几种简单的键值对的示例 - 它们可以是您喜欢或需要的任何内容。

使用这种方法意味着，与其为每个发布或冲刺创建大量新作业，并为将很快过时的多个并发发布提供支持，您可以只定义两三个永久作业集，这些作业将从该位置获取键值对并使用它们来驱动它们的操作 - 我们的作业配置伪代码随后发生变化。最初，它采用以下形式：

*获取 Sprint 3 war 文件并部署到 Sprint 3 服务器...*

这些变化更通用，类似于以下内容：

*获取${SPRINT} war 文件并部署到${SPRINT}服务器...*

这种简单的方法变通，有时可以让您通过（并集中）更新这些环境变量到开发生命周期所需的新属性的位置，从而大大减少 Jenkins 作业的数量 - 例如，在发布、冲刺或迭代周期结束时。

这一次中心配置更改将立即更新所有作业，以便它们可以使用这些新值，这种方法可以扩展到包括构建、测试和部署过程的许多其他方面的信息，要检出和构建的分支位置，或者构建的构件应该部署到的环境或主机等。下面的截图显示了反映这一变化的控制台输出页面：

![用例场景 1 - 大量作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00005.jpeg)

如果您需要为每个迭代创建新作业，还有一些方法可以自动化 UI 以简化此过程 - 我们可以使用 Jenkins 来管理 Jenkins。

如果您查看文件系统上的 Jenkins 主目录（由 JENKINS_HOME 变量定义），您将看到用于存储每个 Jenkins 作业设置的结构：每个作业由一个以其代表的作业名称命名的文件夹表示，每个文件夹包含一个名为`config.xml`的 XML 文件。每个`config.xml`文件包含该作业的设置和信息。

通常还有其他几个文件和文件夹，例如用于跟踪下一个构建的编号的文件（`nextBuildNumber`）和用于跟踪和存储先前构建创建的历史和构件的文件夹。

Jenkins 作业的基本框架，在其最基本的形式下，就是这样简单：

+   一个以作业名称命名的文件夹，例如`VeryBasicJob`

+   在这个文件夹里，一个名为`config.xml`的文件

+   在这个文件里，有一些类似以下的 XML：

```
<?xml version='1.0' encoding='UTF-8'?>
<project>
  <actions/>
  <description>A bare-bones Jenkins job</description>
  <keepDependencies>false</keepDependencies>
  <properties/>
  <scm class="hudson.scm.NullSCM"/>
  <canRoam>true</canRoam>
  <disabled>false</disabled>
  <blockBuildWhenDownstreamBuilding>false</blockBuildWhenDownstreamBuilding>
  <blockBuildWhenUpstreamBuilding>false</blockBuildWhenUpstreamBuilding>
  <triggers/>
  <concurrentBuild>false</concurrentBuild>
  <builders>
    <hudson.tasks.Shell>
      <command>echo &quot;A very simple shell-based job&quot;</command>
    </hudson.tasks.Shell>
  </builders>
  <publishers/>
  <buildWrappers/>
</project>
```

正如您所看到的，这个简单的作业包含一些非常简单的 XML 标签和数据，详细说明了`<description>`和`<command>`标签，以及 Jenkins 使用的各种其他设置。

Jenkins UI 将解释此文件夹和 XML 文件，并显示**配置**页面如下：

![用例场景 1 - 大量作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00006.jpeg)

当源配置和前端 UI 并排显示时，就像您在前面的截图中看到的那样，很明显，改变 XML 文件应该改变 UI 显示的作业，反之亦然。

因此，如果我们可以自动创建这些 XML 文件并以某种方式加载到 Jenkins 中，那么我们也应该能够自动化并对所有 Jenkins 作业进行版本控制，并允许最终用户在运行时应用他们需要的任何自定义，从而消除手动干预的需要。

从版本控制中获取文件夹结构和 XML 文件，使用用户选择的值更新这些 XML 文件，并将生成的配置加载到我们的 Jenkins 实例中，这些都是 Jenkins 的理想工具-我们可以设置 Jenkins 来设置 Jenkins！

简而言之，首先可以通过*模板化*您的 XML 文件来实现此过程-将所有对变量因素的引用（例如对**Release**、**Sprint**、**Hostnames**等的引用）替换为易于识别的内容。然后，创建 Jenkins 作业，使用户能够指定他们想要在这些占位符值的位置使用什么。

下一步是执行一些字符串替换（使用您喜欢的工具-**Perl**、**Sed**、**Awk**等）来用用户选择的值替换占位符值，然后您只需要在运行时将新配置加载到 Jenkins 中。

为了演示这种可能的方法，这里有一个基本的功能性 shell 脚本，它使用注释解释了每个步骤的进行。这使用了`Jenkins-cli.jar`文件，您可以通过转到您的 Jenkins 实例并在 URL 中添加`/cli`来下载并了解更多信息，例如：`http://myjenkins.instance:8080/cli`。

在这里，您还将找到有关 Jenkins 提供的许多功能和能力的详细帮助和信息。

```
# set up the variables required for this to work:
export JAVA="/usr/bin/java"
# Location & port of your Jenkins server
export HOST=http://myjenkinshost:8080

# location of the Jenkins CLI jar file
export CLI_JAR="/tool/ jenkins-cli.jar"

# a simple counter to track the number of jobs created
export COUNTER=0
# the location of the customized config.xml files to load
export WORKDIR="/home/jenkins_user/jobstoload"
# a simple for loop to iterate through each job:
for JobName in `ls $WORKDIR`
do echo "About to create job number ${COUNTER} with name ${JobName}"
${JAVA} -jar ${CLI_JAR} -s ${HOST} create-job ${JobName} < $WORKDIR/${JobName}/config.xml
  echo "${JobName} created."
  let COUNTER++
  echo " "
done
```

这个简单的例子，在 Jenkins 作业中设置后，可以通过从版本控制中拉取模板并允许用户从预定义的有效选项集中进行选择，从而快速、轻松、可靠地允许用户创建（或清理）新的 Jenkins 作业。

# 用例场景 2-多个主机

Jenkins UI 也可以定制，以帮助管理需要大量 Slave 主机的安装。这可能需要通过将负载分配到其他系统来改善构建或测试运行的性能，或者在 Jenkins 用于执行跨多主机操作系统的功能时-这是 Jenkins 可以通过内置的 JNLP 功能非常容易地实现的。

通常，测试要求决定运行不同操作系统和软件组合的各种不同节点是必不可少的-当您有一个需要在不同版本的 Internet Explorer 上进行测试的应用程序时，这是很常见的；每个版本都需要一个不同的 Windows 主机，因为每个主机一次只能支持一个浏览器版本。

管理多个和不同的 Slave 节点可能会有问题；然而，Jenkins UI 提供了几个功能，可以帮助简化和自动化这一方面。

管理具有许多 Slave 节点的实例的最简单方法之一是使用 Slave 标记方案和描述单个节点执行的能力或功能的命名约定。

要做到这一点，首先需要对 Slave 节点进行标记-这可以在创建时进行，也可以返回到现有的 Slave 节点并根据需要对其进行标记-请注意以下 Slave 定义页面中指定的多个标签：

![用例场景 2-多个主机](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00007.jpeg)

正如您所看到的，这个简单的 Slave 已被赋予`tomcat`、`java6`和`integration`的多个标签。

现在，我们可以创建或修改一个作业，并选择**限制此项目可以运行的位置**选项，如下面的屏幕截图所示：

![用例场景 2-多个主机](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00008.jpeg)

如果我们输入与一个或多个现有标签（在这种情况下为`integration`）匹配的标签，那么此作业将在与此标签匹配的节点上运行。在存在多个匹配项的情况下，作业将仅在其中一个节点上运行。

这个简单但非常强大的 UI 功能使您能够在多个节点之间分配负载。这些节点可以执行不同的功能，或者它们可以具有不同的能力-标签可以是任何有助于您决定对您的情况最好的东西。

您可以决定区分节点的物理特性，例如具有大量可用磁盘空间、更多内存或快速处理器的节点，或者具有所需级别的本地数据库或代码部署的节点，或者具有应用服务器或其他支持工具的节点。这样，您不仅可以分配负载，还可以通过将适合的作业放在最适合它们的主机上，以及通过汇集资源来优化各种构建任务的响应时间，从而最大化性能并减少周转时间，尽快完成紧急任务，并将不太紧急的作业排队在一组专用服务器上。

使用 Swarm 插件可以进一步采用这种方法：[`wiki.jenkins-ci.org/display/JENKINS/Swarm+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Swarm+Plugin)。

该插件提供了一个额外的功能，可以通过 UDP 广播自动配置和连接新的从节点，发现并连接新的节点到现有的主节点，从而创建一个临时集群，您可以根据需求进行定制。

您可以使用此功能设置当构建队列达到预定义阈值时，新节点将动态配置并添加到可用节点池中。您需要在主节点上安装该功能，并在新的从节点上使用命令行客户端。

Swarm 节点在创建时也可以通过 CLI 中的`-labels`参数分配多个标签。这些值还可以由创建它们的脚本设置；例如，脚本可以检查本地 Oracle 安装的存在或大量的可用磁盘空间，然后使用这些结果来决定要应用哪些标签——例如`database`、`performance`、`java6`、`tomcat`等等。

另一个非常强大的动态主机配置和管理工具是 Docker，而且，不出所料，Jenkins 也有可用的插件：

[`wiki.jenkins-ci.org/display/JENKINS/Docker+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Docker+Plugin)

Docker 允许您快速轻松地创建和管理在 Docker 容器中运行的 Docker 镜像。这些在实践中与虚拟机非常相似，但体积更小、更轻，因此比传统虚拟机更快更容易进行配置。

Docker 镜像也可以通过**Docker Registry**进行版本控制，它类似于虚拟机的 Git 或 Subversion 仓库；您可以从 Docker Index 中拉取现有的镜像，并更新以满足您的需求（就像为虚拟机执行任务一样——执行任务，如部署 Tomcat，安装和配置 Apache，上传一些脚本，添加 Java 的版本，或安装 Jenkins）。一旦您定制了您的镜像，您可以选择将其推送/发布回到索引中，状态与您创建时完全相同，但名称不同，从而创建一个模板从节点，您可以快速可靠地配置到运行 Docker 的任何平台。甚至可以在虚拟机上运行 Docker——这种方法提供的可能性非常有趣，我们将在第九章 *将事物放在一起*中更详细地讨论这一点。

# 用例场景 3 - 通过 UI 自动化帮助用户

定制和自动化 Jenkins 用户界面可以帮助并赋予您的 Jenkins 实例的用户自助帮助。

通过确保只有用户能够输入有效数据，我们可以大大减少无效输入和由此产生的问题的风险，这也应该改善用户体验。

这样做的最常见方式是在运行时验证用户输入。例如，如果您的作业提示用户输入一周中的某一天或一个构建编号，您可以分别将其分配给一个名为`$WEEKDAY`或`$MY_BUILD_NUM`的变量。 

然后，我们可以设置我们的作业以确保提供的用户数据是有效的——如果`$WEEKDAY`的值不是一周中的有效日期，或者用户提供的构建编号是`Build Two`而不是我们希望的整数值，我们可以导致构建失败，并显示错误消息解释用户做错了什么以及如何纠正，而不是让我们的作业继续进行并让它尝试执行我们知道是无效的功能或创建某些东西。

如果您可以让用户知道您的期望，这也是一个良好的做法，对所有相关方都有帮助——通过在输入框旁边设置描述，可以轻松实现这一点：

![用例场景 3-通过 UI 自动化帮助用户](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00009.jpeg)

在运行时，此配置将向用户提供我们希望他们输入的描述，并通过设置默认值为 0，我们可以给他们另一个提示。

然后，这个 Jenkins 作业可以检查`$MY_BUILD_NUM`的值（正如我们所希望和请求的那样）是否大于零且小于 101，然后我们可以相当确信事情可以继续进行。

通常更安全的做法是采取下一个逻辑步骤，并限制用户可以选择的选项。这进一步减少了风险，也让用户体验更好——他们可能只偶尔运行某些作业，期望他们记住你想要的内容有时可能有点过分要求。这可以通过向他们呈现一系列有效选项并确保他们选择其中之一来实现：

![用例场景 3-通过 UI 自动化帮助用户](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00010.jpeg)

上述信息将在运行时向用户呈现如下：

![用例场景 3-通过 UI 自动化帮助用户](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00011.jpeg)

这种方法应该会更加健壮，只要我们记得在尝试使用它之前检查${WEEKDAY}的值是否等于**请选择...**！

这种方法可以通过从其他来源获取数据并在运行时动态构建用户可用的选项来进一步扩展。

另一个有用且更强大的例子是能够使用当前 Subversion 标签的值填充选择列表。

这可以通过参数化构建的**列出 Subversion 标签（等等）**选项来实现。这允许您向用户呈现当前可用标签的列表供选择——例如，这些标签可以由其他 Jenkins 作业创建，并且可能包含用户可以选择的候选构建列表，以便将构建部署到环境中。

假设您有一个具有以下结构的 Subversion 存储库：

`https://subversionrepo/mainproject/tags/Build_12.56`

`https://subversionrepo/mainproject/tags/Build_14.78`

`https://subversionrepo/mainproject/tags/Build_18.20`

在这种情况下，用户将看到一个下拉菜单，提供这三个构建中的一个选择。

用户选择的选项在运行时分配给您创建的变量，比如`$BUILD_TO_DEPLOY`，然后您的作业可以使用此选择来检出请求的构建并使用 SVN URL 与用户的首选选项部署它：

`https://subversionrepo/mainproject/tags/${BUILD_TO_DEPLOY}`

此功能作为 Subversion 插件的一部分提供，现在是核心 Jenkins 构建的一部分。

还有许多其他插件和功能可以用来构建和改进您的用户界面体验 - 内置的 Jenkins **Views**功能允许您创建一个动态列表，其中列出符合您条件的作业。这可以表示为一个简单的正则表达式，以便所有匹配的作业都将显示在一个视图中。当与合理的作业命名约定结合使用时，这种方法特别有效。

其他可能改善用户体验的方法包括设置管理作业执行和流程的流水线。通过设置用户可以轻松启动的流程，然后继续执行一系列其他作业，用户只需要触发几个动作中的第一个，就像推倒多米诺骨牌一样，而不是在检查前一个构建是否已完成并检查其输出后触发每个构建。

这可以通过简单地使用每个作业下的内置**构建其他项目**选项来实现一个简单的序列。使用各种触发选项，我们可以微调一些东西，以便某些作业在出现问题时停止流程，或者在适当时继续进行。

如果您想添加更多选项，有许多插件可以帮助您。Build Pipeline 插件提供了一些有用的功能，Join 插件也非常有用。如果您想同时运行多个作业，然后等待它们完成后继续并触发下一个作业 - 像往常一样，Jenkins 插件几乎适用于所有场合！

# 用例场景 4 - UI 调整

有时 Jenkins 被设置好后就在后台运行，很少被检查或查看，除非出了问题，用户们都很满意事情得以完成。

在其他情况下，Jenkins 用户界面被许多人同时大量使用，所有这些人都不可避免地会有自己的需求和优先事项，然后 Jenkins 的外观和感觉就成了一个高优先级。

有许多方法可以满足用户的需求，包括设置多个视图，每个视图为不同的用户或组提供适合他们的（Jenkins）世界的视图。

![用例场景 4 - UI 调整](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00012.jpeg)

使用简单的`.*job.*`正则表达式确保所有包含字符串`"job"`在其标题中的作业（现有和未来的）都将显示在此视图中。同样，这确实依赖于一个合理的命名约定，但如果这样做了，它可以将此方面的维护要求减少到零 - 当创建一个新的匹配作业时，它会自动添加到视图中。

在这个领域提供进一步增强的插件包括 Personal View 插件；正如其名称所示，它使用户能够创建和管理自己的世界视图，查看**作业过滤器**，并允许进一步调整。**Chosen Views Tab**栏非常有用，如果您最终拥有太多视图并希望轻松管理所有视图在一个屏幕上！

# 总结

在本章中，我们探讨了用户界面可以如何改变以满足您的需求。我们研究了一些常见问题，并审查了一些可能用于缓解这些问题的方法。

正如您所见，Jenkins 用户界面非常强大，其中很大一部分力量来自于其灵活性和可扩展性。

调整 Jenkins 用户界面以适应您环境中适用的任何用例，可以极大地改善 Jenkins 安装的成功。同时，它也可以使用户体验更加积极，并引导用户以互惠互利的方式与 Jenkins 进行交互。当人们很容易找到他们想要的东西，很难犯错（例如，由于运行时验证、动态填充的表单和自动创建的作业套件），您应该会拥有更快乐的用户和更健壮、高效的 Jenkins。

Jenkins 的内置功能通常可以提供足够的灵活性来解决您最紧迫的 Jenkins 用户界面问题；然而，丰富的可用插件使您可以很容易地进一步扩展功能，如果您愿意的话。

在第 6 和第七章，当我们自己查看扩展 Jenkins 用户界面时，我们将更详细地重新讨论这个话题。我们将看到如何开发并直接将自定义的 GUI 项目添加到 Jenkins 用户界面，使您能够使用 Jelly、自己的插件和提供的 Jenkins 扩展点进一步扩展功能。


# 第三章：Jenkins 和 IDE

在第一章*准备步骤*中，我们高层次地了解了持续集成的基本原则和目标。然后，我们通过一些相当典型的 Jenkins 使用案例场景，来说明扩展 Jenkins 可以帮助我们实现这些目标。

在本章中，我们将更详细地了解如何扩展 Jenkins 并实现持续集成的原则和目标。本章的重点是发现我们如何帮助软件开发人员使事情变得更容易。管理和开发团队的支持和*认同*对于任何良好的构建流程的成功至关重要，而开发人员显然是任何软件开发团队的基本组成部分。

我们将看一下一些方法，您可以使用这些方法来扩展和调整 Jenkins 以满足开发人员的特定需求和要求，并且我们将演示如何调整 Jenkins 信息呈现的方式，以便与他们的工作方式自然地融合。这里的意图是赋予人们他们发现既有益又易于使用的工具，并因此鼓励人们*做正确的事情*，而不是试图通过使用指标、威胁、唠叨的电子邮件和每次构建失败时指责别人来强迫他们做我们所指示的事情——这是一种确保最终会有很多不满的开发人员的方法，他们只想低调地工作！

理解动机是理解行为的关键，而且，相当合理的是，开发人员通常会高度专注于开发代码更改。他们通常不太感兴趣执行额外的任务，比如监视构建仪表板的更新或滚动一整天的电子邮件，以检查是否有其他人最近破坏了构建，然后再提交他们的更改。他们自然而然地专注于自己的角色、优先事项、编写代码和测试，并将它们交付，以便他们可以继续下一个任务。任何偏离或分散注意力的事情可能被视为适得其反。因此，如果我们可以扩展 Jenkins，同时使开发人员更容易专注于他们代码的质量，并鼓励他们从持续集成的角度*做正确的事情*，那么每个人都应该更加快乐...好吧，这是目标。

我通常用来实现这一点的方法最好由这句话来描述：

| | *"让错误的事情变得困难，让正确的事情变得容易。"* | |
| --- | --- | --- |
| | --雷·亨特 |

这是一个简单但有效的口头禅，我发现在这种情况下真的很有效。雷·亨特是自然马术运动的创始人，他在训练马匹时非常成功地运用了这一哲学。而且，说实话，我在将其应用于开发人员时也取得了一些成功！

因此，本章的重点是探索我们如何扩展 Jenkins，以便为辛勤工作的开发人员提供所需的信息，让他们能够自然方便地吸收，并且让他们更容易*做正确的事情*。如果我们能够直接在他们已经花费大部分时间的 IDE 中呈现信息，希望我们可以实现这一点。

回到我们的持续集成目标，从开发人员的角度来看，我们在这里试图鼓励三种主要行为：

1.  **频繁提交**：我们可以通过使用适当的版本控制系统来使这一点变得容易，该系统允许开发人员在他们正在使用的 IDE 中快速进行检入，并且不会分散他们的注意力来检查构建任务和状态。

1.  **如果构建失败，将其作为最重要的事情来修复**：使当前状态非常明显将有助于实现这一点。

1.  **检查您的操作结果**：这将大大改善其功能。

快速反馈并使其易于查看（并且不容易错过！）也会在这里有所帮助。如果我们可以从开发人员已经使用的 IDE 中清晰地呈现所有这些信息，我们应该会看到一些小的改进。

虽然我们即将要运行的技术解决方案应该对我们有所帮助，但我们不能指望它们单独成为奇迹。正如之前提到的，需要一个团队共同努力才能使这些事情起作用，因此建立和监控一套开发人员最佳实践、发布标准和指南，并提供用户教育和信息，都在建立高效和专业的开发团队和生产构建过程 IDE 以及 Jenkins 构建连接器中起着重要作用。

有不同的开发 IDE，选择取决于许多因素，如编程语言（Java，C ++，.Net 等），环境（Linux，Windows，Mac 等）以及公司和个人偏好（开源或闭源）。我们将看一下一些最受欢迎的 IDE 和它们的解决方案；但是，还有许多其他可用的解决方案，以满足不同的需求。

# Eclipse 和 Mylyn

我们将要查看的第一个，也可能是迄今为止最受欢迎的所有开发 IDE 中的 Eclipse 平台-这对于许多不同的项目（包括 Java，C/C++和 PHP）都非常受欢迎，并且具有庞大的用户群和丰富成熟且易获得的插件。

为了实现我们向开发人员展示 Jenkins 信息的目标，Mylyn 目前是我们可以与 Eclipse 一起使用的最受欢迎的扩展。

有关 Mylyn 及其提供的许多功能的更多信息，请访问此链接：

[`www.eclipse.org/mylyn/`](http://www.eclipse.org/mylyn/)

此链接中的文档还指出，Mylyn*减少信息过载并使多任务处理变得容易*，这正是我们正在寻找的！

# 安装 Mylyn

Mylyn 已预装在最新版本的 Eclipse 中，因此您可能只需要通过导航到**窗口** | **显示视图** | **其他**，然后从**Mylyn**类别中选择**构建**组件来选择它：

![安装 Mylyn](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00013.jpeg)

现在，您只需要使用以下详细信息配置 Mylyn：

如果您使用的 Eclipse 版本未预装 Mylyn，您可以通过选择**帮助** | **软件更新...**，然后添加一个具有此 URL 的新更新站点来下载并安装它：[`download.eclipse.org/tools/mylyn/update/e3.4`](http://download.eclipse.org/tools/mylyn/update/e3.4%20)（如果有更高版本可用且更受欢迎）。

完成后，选择刚刚创建的新更新站点，并添加您想要安装的 Mylyn 组件。

## Mylyn 和 Jenkins 配置

安装完成后，您将能够从主工具栏菜单中选择**窗口**，然后**显示视图**，**Mylyn**和**构建**。

这应该产生一个类似于以下窗口，然后您可以选择突出显示的选项来创建新的构建服务器定义：

![Mylyn 和 Jenkins 配置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00014.jpeg)

这将产生一个新的向导：

![Mylyn 和 Jenkins 配置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00015.jpeg)

选择**Hudson**选项并单击**下一步**后，您将看到一个**服务器属性**对话框，您可以在其中定义和配置**新构建服务器**的属性：

![Mylyn 和 Jenkins 配置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00016.jpeg)

在这里，您可以指定 Jenkins 服务器的 URL 和所需的凭据。快速刷新应该显示成功连接到 Jenkins 实例，并且还会拉回一个作业定义列表供您选择。请注意，Mylyn 还提供了一系列其他连接和授权功能，如果需要，您可以进行配置。

快速检查使用**验证**按钮后，点击**完成**保存并关闭服务器配置。

这将导致一个新的**构建**窗口显示您从 Jenkins 服务器中选择的作业的实时信息，类似于这样：

![Mylyn 和 Jenkins 配置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00017.jpeg)

在此窗口中探索选项表明，您可以右键单击并选择执行所选作业的多个有用功能：

![Mylyn 和 Jenkins 配置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00018.jpeg)

您可以执行以下功能：

+   查看所选作业的历史记录

+   在 Eclipse 中在浏览器中打开作业

+   运行所选的作业

+   查看最后一次运行的控制台输出

+   在 JUnit 视图中显示 JUnit 结果

所有这些都可以直接从 Eclipse IDE 中完成，使开发人员非常容易地关注他们需要了解的事情，几乎没有什么努力和最小的干扰。

# IntelliJ IDEA 和 Jenkins 构建连接器

由 JetBrains 开发的 IntelliJ IDEA 是另一个非常受欢迎的集成开发环境，与 Eclipse 类似，它也有大量的附加组件和插件可用于扩展其使用和功能。

在本节中，我们将快速查看在 IntelliJ IDEA 中安装和配置**Jenkins 控制插件**，并将其配置为提供类似于 Eclipse 下 Mylyn 提供的功能。

在 IntelliJ 中安装插件非常容易-打开**首选项**菜单项，然后在左侧菜单中选择**插件**。Jenkins 控制插件目前未与 IDE 捆绑在一起，因此请按照以下截图中显示的点击**浏览存储库...**按钮：

![IntelliJ IDEA 和 Jenkins 构建连接器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00019.jpeg)

这将打开一个新的子窗口，您可以在搜索对话框中输入`Jenkins`以找到两个（当前）可用的插件，如下所示：

![IntelliJ IDEA 和 Jenkins 构建连接器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00020.jpeg)

点击绿色的**安装插件**按钮-插件将被下载，并提示您重新启动 IntelliJ IDEA-这样安装就完成了。

重新启动 IDE 后，点击**查看**菜单，选择**工具窗口**，您应该会看到一个新的**Jenkins**选项。选择此选项会产生一个名为**Jenkins**的新窗格，在那里您可以通过点击扳手图标并填写必要的详细信息来配置连接到 Jenkins 服务器：

![IntelliJ IDEA 和 Jenkins 构建连接器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00021.jpeg)

我的示例 Jenkins 实例非常简单-您可能希望在真实的 Jenkins 实例上使用身份验证，因此需要填写相应的详细信息。您可能希望调整时间和日志记录设置以适应自己；但是，基本设置非常简单，也非常类似于之前的 Mylyn 示例。

完成后，点击**确定**按钮，您应该在 IntelliJ 内看到您的 Jenkins 实例的视图：

![IntelliJ IDEA 和 Jenkins 构建连接器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00022.jpeg)

与 Mylyn 一样，您可以使用此插件执行几个有用的功能-监视构建的状态，触发新的构建，并查看所选作业的结果和历史记录。

# NetBeans

NetBeans IDE 具有内置功能，可以通过`HudsonInNetBeans`服务监视 Jenkins。

在 NetBeans 中选择**服务**选项卡将显示一个 Hudson Builders 项目，您可以在其中定义您的 Jenkins 实例，并根据 Jenkins 服务器上可用的视图定义配置要监视的项目：

![NetBeans](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00023.jpeg)

注册服务器后，您将收到 IDE 内弹出窗口通知任何失败情况。您可以在这里阅读有关此扩展的功能和配置的更多信息：[`wiki.netbeans.org/HudsonInNetBeans#General_setup_and_view`](http://wiki.netbeans.org/HudsonInNetBeans#General_setup_and_view)。

此外，构建监视器插件也可以添加以包括状态栏通知——可以从插件主页下载：[`plugins.netbeans.org/plugin/814/build-monitor`](http://plugins.netbeans.org/plugin/814/build-monitor)。

然后，通过选择**下载**选项并导航到最近下载的带有`.nbm`扩展名的文件，从**工具**|**插件**菜单项安装插件：

![NetBeans](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00024.jpeg)

现在，只需选择**安装**，同意条款，然后再次点击**安装**—完成后，点击**完成**。现在，您应该有一个状态栏项目，可以配置为监视一个或多个 Jenkins 作业的状态，从而提供另一种有用且不会打扰的机制来关注更重要的构建。

# 总结

在本章中，我们看了持续集成的关键目标，以及它们如何与开发人员特别相关。我们已经审查了在这个领域我们想要实现什么，以及我们如何做到这一点，即通过使开发人员能够轻松地做正确的事情，并使他们的生活和角色更加轻松。

有许多不同的选项可供我们将 Jenkins 与开发环境集成，我们已经详细介绍了三种最流行的 IDE 的一些常见示例——这些 IDE 还有许多其他选项，其他 IDE 也有许多其他选项。如果前面的选项不适合您的环境，希望一般的想法和方法能够转化为适合您的东西。这些插件正在定期开发和增强，因此选择最适合您和您的环境的方法和组合。关键目标是让他人的生活变得更轻松，并鼓励他们也让您的生活变得更轻松！

此外，除了 IDE 之外，我们还有许多其他方式可以将 Jenkins 信息传达给其他人；有系统托盘通知器、信息辐射器、仪表板、自定义 Web 应用程序、电子邮件提醒、即时消息通知，甚至是自动化的熔岩灯和泡沫火箭发射器！

在下一章中，我们将看看与 Jenkins 互动的其他几种方式——这些方式更加技术化，不太关注最终用户，但它们在某种程度上相关，可能会给您一些开发自己定制解决方案的替代想法。


# 第四章：API 和 CLI

在上一章中，我们看了几种与 Jenkins 交互和扩展其使用的方式，以便开发人员可以直接从他们的开发环境中受益。

我们看到的插件和附加组件显然可以从 Jenkins 中获取“实时”数据，以便直接将这些数据传达到客户环境（开发人员的 IDE）。

在本章中，我们将看看这些插件是如何能够访问这些信息的，并且我们将探索 Jenkins 为编程交互提供的各种机制和接口，例如 Jenkins **应用程序编程接口**（**API**）。我们还将探索 Jenkins **命令行界面**（**CLI**），它提供了一种远程以编程方式和/或交互方式与 Jenkins 进行交互的机制。

这两个功能都非常强大，并且是扩展 Jenkins 的基本实用程序。

通常您会使用 Jenkins API 的三个主要功能如下：

+   从 Jenkins 检索和使用信息

+   基于外部事件触发构建

+   创建、复制和更改 Jenkins 配置

# 使用 Jenkins XML API 创建信息辐射器

为了说明您如何可以使用 Jenkins API 以编程方式从 Jenkins 中提取实时信息，我们将高层次地看一个实际示例 - 创建一个信息辐射器，从 Jenkins 获取信息并在外部网页中显示它。我们将不会详细编写所有的代码；但是，我们将详细分析基本构建块，以便您能够采用一般方法并使用您选择的语言开发自己的定制解决方案。

信息辐射器是简单但有用的*实时*网页，允许人们实时轻松监视您最关键的 Jenkins 作业的状态。这与我们之前看到的 IDE 插件非常相似，但是这些指示器显示在办公室的电视屏幕上，以辐射信息。

信息辐射器的约定是*保持简单* - 尽可能少地拥有作业，并且如果一切正常则显示绿色指示器，如果有问题则显示红色指示器。有时，如果构建正在进行中，则显示琥珀色指示器也是有用的。这个简单的系统有助于突出需要作为最优先解决的紧急问题，并且它还有助于阻止人们在他们清楚地看到构建当前不稳定时检入新更改；向已经破损的系统添加进一步的更改只会加剧问题。

在我们的高级概述中，我们将监视一个 Jenkins 构建的当前状态。您可以重复使用和扩展相同的方法来监视您想要的任意数量的构建，并且您将看到如何可以额外拉取和报告来自 Jenkins 作业的其他细节。

请注意，有许多预先构建的解决方案可供您使用，包括各种不同需求的插件 - 我们在这里故意采用自定义方法，以展示可能性并向您展示如何使用 Jenkins API。

# 从 Jenkins 获取信息

第一步是获取我们（程序化）的信息。最简单的方法是通过 XML API 进行。这只是简单地将`/api/xml`字符串附加到您想要监视的作业的 URL 上，如下所示：`http://yourjenkinsserver:8080/job/YourJob/api/xml`。

### 注意

请注意，还有一个可用的 JSON API；如果这更适合您的需求 - 只需将`api/xml`替换为`api/json`，以便以 JSON 格式接收相同的信息。

如果您在浏览器中执行此操作，您应该看到与我的**VeryBasicJob**作业类似的 XML：

从 Jenkins 获取信息

API 返回的文本很简单，XML 本身也很简单易懂；快速浏览一下就会发现它包含了您对刚刚查询的工作所需的所有信息——只是需要进行处理和解释。对于这些 XML 元素，似乎没有太多的文档可用；但是，如果您从尽可能简单的工作开始，然后对其进行更改和添加，您应该能够弄清楚每个元素的作用以及可能的值。

XML 处理器是处理这个问题的最佳方法，您选择的脚本或编程语言应该提供多种选择。例如，Perl 有**XML::Simple**，Python 有**ElementTree**，Groovy 有**XmlParser**，Java 有**JAXP**，还有许多其他选项。如果您没有这些，您可以在 shell 脚本中使用`grep`和`awk`来查找您想要的行和值。

因此，我们现在有一个我们想要监视的工作，一种获取所有当前工作信息的方法，一个适当的处理 XML 的方法，以及提取我们想要的信息的机制。

对于这个例子，我们真正想知道的只是构建的当前状态——对应于我们的红色、琥珀色和绿色健康指示器的值——这些值作为作业的当前`color`属性存在于 XML 示例中。

例如，考虑以下 XML 标记：`<color>blue</color>`。这表明我们目前有一个非运行和稳定的工作，而`<color>blue_anime</color>`则指的是上次构建健康且当前正在构建的工作的蓝色和动画健康指示图标。

我们可以简单地将任何提到`anime`的内容显示为琥珀色在我们的信息显示器中。`<color>red</color>`和`<color>red_anime</color>`分别是失败和运行（但以前失败）的作业的明显等价物。如果您查看各种不同类型和状态的作业的 XML，您将能够发现并解释所使用的命名约定——只需将`/api/xml`添加到各种作业的选择中并进行比较。

# 自动化工作

我们简单的信息显示器的下一个障碍是自动化和调度工作，正如您所期望的那样，我们可以在 Jenkins 中非常快速和轻松地完成这项工作。

只需创建一个新的 Jenkins 作业，获取相应的 URL（在末尾加上`/api/xml`），并将其传递给您的 XML 解析脚本以提取当前值。

许多编程和脚本语言都具有内置的 XML 或网络获取功能，但如果您愿意，您也可以使用 curl 或 wget 来获取数据，然后将其传递给您的脚本。

Jenkins 作业可以按照您的需要安排运行频率——您可以使用标准的 cron 表示法通过内置的 cron 函数来设置作业，例如，您可以将作业设置为每两分钟运行一次，如下所示：

![自动化工作](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00026.jpeg)

在这个示例中，我指定了`H/2 * * * *`，以便每两分钟运行一次此作业。符号`H`是 Jenkins 内置的一个方便机制，允许 Jenkins 平衡和管理作业调度。Jenkins 能够分发负载，而不是在完全相同的时间触发所有作业。要了解更多详情，请点击**Schedule**输入框旁边的**?**图标，其中写着以下内容：

**为了让定期计划的任务对系统产生均匀的负载，应尽可能使用符号 H（哈希）。例如，对于十几个每天的作业使用 0 0 * * *将在午夜引起大量的负载。相比之下，使用 H H * * *仍然每天执行每个作业一次，但不会同时执行，更好地利用有限的资源。**

如果您对 cron 语法不熟悉，请在任何 Linux 系统上查看 cron 手册页（在终端中键入`man cron`）。还有一些有用的 cron 生成器在线，比如[`crontab-generator.org/`](http://crontab-generator.org/)，这些都非常有用。

### 注意

请注意，在决定和设置重复构建的频率之前，强烈建议您测试和微调您的作业*。例如，如果您的作业运行需要 3 分钟，而您设置它每分钟运行一次，事情将不会进行顺利！

这一步的最后一个任务是将数据存储在某个地方-我通常更喜欢一个简单的 MySQL 数据库，我可以通过将当前运行时参数传递给 MySQL 二进制文件来在作业结束时更新。

# 辐射信息

最后一步是将数据库中的信息显示为颜色"辐射器"——这只是简单地生成一个查询数据并将这些信息转换为适当颜色-红色、琥珀色或绿色的网页。这可以用许多语言来实现，包括 PHP、JSP 和 ASP，但最简单的方法可能是让您的 Jenkins 作业为您写出原始 HTML 到一个文件，也许像这样：

```
<html>
  <head>
    <**meta http-equiv="refresh" content="5"**>
    <style type="text/css">
      .myclass{
        width:270px;
        height:150px;
        position:absolute;
        left:50%;
        top:50%;
        margin:-75px 0 0 -135px;
      }
    </style>
  </head>
  <body style="background**:#088A08**">
    <div class="myclass">Status of my VerySimpleJob</div>
  </body>
</html>
```

使用作业更新背景颜色的值。请注意，前面的代码中有一个 Meta 刷新标签，每 5 秒重新加载页面一次-否则您将长时间看着相同的信息！

# Jenkins 作为 Web 服务器- userContent 目录

您甚至可以让 Jenkins 充当一个简单的 Web 服务器，并托管我们为您创建的网页-如果您将作业生成的文件复制到`JENKINS_HOME`位置中的`userContent`目录中，您将在此 URL 看到该文件出现：`http://myjenkins:8080/userContent`

这应该如下所示：

![Jenkins 作为 Web 服务器- userContent 目录](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00027.jpeg)

点击**inforad.html**链接将给您以下页面-我们非常简单的 DIY 信息辐射器：

![Jenkins 作为 Web 服务器- userContent 目录](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00028.jpeg)

这个简单的练习说明了您如何通过 API 查询 Jenkins 以实时检索和消耗信息。

# Jenkins CLI

在本节中，我们将回顾 Jenkins CLI-这是另一个 Jenkins 扩展点，在某些情况下可能非常有用-通常用于针对远程 Jenkins 服务器运行命令，执行触发构建或更新配置等功能。

## 如何设置

为了使用 Jenkins CLI，您需要"jenkins-cli.jar"文件。

这可以很快、很容易地从您自己的 Jenkins 服务器获取。如果您在 Jenkins 实例的 Web 地址后附加"/cli"，您应该会看到一个类似于这样的页面：

![如何设置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00029.jpeg)

这个 URL 提供了您启动 Jenkins CLI 所需的一切。

有一个指向 Jenkins Wiki 主题的链接，以获取更多信息，还有一个直接从您的服务器下载 Jenkins-cli.jar 文件的链接（`http://{yourserverand:port}/jnlpJars/jenkins-cli.jar`），以及可用 CLI 命令的列表和简要描述。

## 如何使用它

一旦您在本地保存了 CLI jar（您可以通过浏览器下载它，也可以使用命令行工具，如`wget`或`curl`），您只需要设置好您的 Java 环境，然后执行帮助页面开头详细说明的命令，如下所示：

`java -jar jenkins-cli.jar -s http://{yourserverand:port}/ help`

假设您在当前目录中有`Jenkins-cli.jar`，并且您更新了地址以反映您的服务器，您应该会收到基本的帮助信息，然后您就可以开始了。

## 通过 CLI 触发远程作业

CLI 最常见、也许是最简单的任务是在流程的某个特定点触发远程作业运行。当您将 Jenkins 与其他传统系统集成并逐渐引入自动化到手动流程中时，这可能非常有用。您可能无法立即自动化所有内容，或者一次性让 Jenkins 控制所有内容，但是如果您可以设置一个 Jenkins 作业来自动化现有手动工作流程的各个部分，那么您可以逐步引入 Jenkins，并逐步消除链条中的手动步骤。

例如，假设我们有一个传统的批处理作业，运行某种形式的数据处理。这个处理可能需要一些时间来运行，可能会有另一个步骤来检查处理是否完成，如果是的话，然后将新数据传输到另一个位置或传递给另一个进程。我们可以首先创建一个 Jenkins 作业，当调用时，它会接收数据，检查它是否有效，然后将其传递给流程的下一部分。这可能会消除一个手动步骤并减少整体处理时间。但是 Jenkins 作业如何知道何时运行？可能无法有效或可能无法告知处理是否已完成，但我们可以对流程进行小的更新，以在初始处理后自动调用 Jenkins 作业。

远程触发在简化的 Jenkins 服务器上运行作业就像这样简单：

![通过 CLI 触发远程作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00030.jpeg)

在这里，我们首先使用`curl`将 Jenkins CLI jar 文件下载到当前目录：

```
**curl -O http://minty:8080/jnlpJars/jenkins-cli.jar**

```

这一步只需要做一次。然后我们将使用这个命令调用远程作业：

```
**java -jar jenkins-cli.jar -s http://minty:8080/ build VeryBasicJob**

```

使用这种简单的配置，您将得不到任何反馈；但是，在 Jenkins 服务器上检查`VeryBasicJob`应该会显示作业已触发，并且在控制台输出中，它还应该提到以下内容：

**由匿名用户从命令行启动**

所以，我们可以看到这已经可以了，但是缺乏反馈并不是很有帮助。如果我们在命令中添加`-s`和`-v`参数，我们将得到完整的详细信息，如下所示：

![通过 CLI 触发远程作业](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00031.jpeg)

这看起来好多了——我们现在可以看到我们已经启动了`VeryBasicJob`的第 9 次运行，它只是在成功退出之前睡了 20 秒。

这些输出信息可以用于客户端脚本中检查成功或失败，或者您可以记录作业编号，或记录任何其他有用的输出。

显然，我们通常不会在没有任何形式的身份验证的情况下运行 Jenkins，因此在现实世界中，事情会变得有点复杂。您首先需要在 Jenkins 的用户配置页面中为您运行 CLI 命令的用户授予“Overall/Read”帐户权限。然后您可以简单地在命令行的末尾添加用户名和密码，如下所示：

```
**--username don --password MyPassword123**

```

这足以让事情运转起来，但从安全角度来看仍然不够好；凭据将以明文形式显示在您添加它们的脚本中，或者在您使用的 shell 的历史记录中，或者在您没有使用 HTTPS 时的 HTTP 流中。凭据也可能作为参数显示在用户运行`ps`或`top`等命令时传递给运行的进程，等等，在同一主机上。

更安全的方法是设置 SSH 密钥并传递私钥以获取公钥。如果您在 Jenkins 的“配置”中为您的用户名设置 SSH 密钥，您可以在提供的文本框中设置您的帐户的 SSH 密钥。这里有关设置 SSH 的详细说明：

[`help.github.com/articles/generating-ssh-keys/`](https://help.github.com/articles/generating-ssh-keys/)

完成此操作后，根据您使用的 Jenkins 版本，Jenkins 可能会自动检查并使用您的 SSH 凭据来自以下任何位置：

```
**~/.ssh/identity, ~/.ssh/id_dsa, ~/.ssh/id_rsa**

```

然后，您可以明确提供密钥的路径（将其附加到命令行而不是之前的用户名和密码详细信息）：

```
**-i ~/.ssh/id_rsa**

```

对于需要参数的工作（即您已设置为在运行时从用户请求信息的工作），您可以提供额外的“-p”参数，如下所示：

```
**-p sprint=1.7**

```

这将被传递给作业，就好像用户通过用户界面输入数据一样，并假设为该作业配置了名为“sprint”的输入元素。

## 更新 Jenkins 配置

Jenkins CLI 的另一个非常有用的能力是以编程方式和远程方式更新 Jenkins 配置。

从帮助页面上，我们看到当我们在服务器 URL 后附加`/cli`时，两个命令`get-job`和`create-job`非常有用。

运行 get-job 将请求 Jenkins 提供该作业的 XML 定义。

例如，考虑以下命令：

```
**java -jar jenkins-cli.jar -s http://minty:8080/ get-job VeryBasicJob**

```

当在我的服务器上运行时，它将返回以下输出：

![更新 Jenkins 配置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00032.jpeg)

这个 XML 也可以通过在命令的末尾添加`> VeryBasicJob.xml`来重定向到文件，然后可以将文件作为定期备份添加或更新到您的版本控制软件中。

同样，您可以选择使用 create-job 命令创建新作业，如下所示：

```
**java -jar jenkins-cli.jar -s http://{yourserverand:port} create-job MyNewJobName < MyNewJob.xml**

```

例如，可以通过 Jenkins 作业、XML 模板和一些用户指定的输入的组合来编程创建`MyNewJob.xml`文件。

我们还可以使用 update-job 来更新现有作业，与现有作业名称结合使用：

```
**java -jar jenkins-cli.jar -s http://{yourserverand:port} update-job VeryBasicJob < VeryBasicJob_v2.xml**

```

这种方法可以用来构建一个机制，将您的 Jenkins 配置的全部或部分备份到版本控制，然后通过 Jenkins 以编程方式重新加载它们。

如果需要，您还可以扩展此方法以对 XML 文件（因此也是它们创建的作业配置）进行一些修改；例如，定期更新发布或冲刺详细信息。

# 摘要

在本章中，我们探讨了 Jenkins API 和 Jenkins CLI 打开的可能性。

我们已经通过一些高级示例并说明了如何使用 XML API 开发自己的定制信息辐射器。

我们还概述了 CLI 提供的一些功能，并演示了如何使用它们。

从这两个功能的开放性可以看出，Jenkins 的灵活性非常惊人——它是一个开放平台，为您提供了许多适应和扩展它以满足您的需求和要求的方式。

我们之前检查的插件能够在远程 Jenkins 服务器上显示实时信息的方式现在应该是非常明显的，当我们稍后看看如何为 Jenkins 开发我们自己的插件时，我们将进一步使用 API 和 CLI。

在下一章中，我们将探索 Jenkins 扩展点，研究其背后的理论，并审查开发的最佳实践。


# 第五章：扩展点

在本章中，我们将介绍并探讨开发 Jenkins 插件时使用的理论和设计概念。我们将在这里涵盖高层概念，并提供一些通用示例，作为下两章的准备，我们将看到如何为实际情况实现这些想法。

在本章中，我们将介绍以下设计模式：

+   接口

+   抽象类

+   单例

此外，我们将回顾几个重要的设计概念：

+   契约设计

+   扩展点

+   创建扩展

+   注解

# Jenkins 插件的简要历史

Jenkins 有数千个可用的插件，涵盖了广泛的任务范围，并为使用和使用 Jenkins 的社区提供了丰富的宝贵资源。许多现有的插件最初提供了简单的功能并提供了有限的功能，但其中大多数已经发展成为非常成熟的软件，提供了大量的功能。许多插件也已经并入了 Jenkins 核心功能，将它们从额外的可选附加组件转变为默认情况下随 Jenkins 一起提供的代码。

Jenkins 插件的成功及其插件范围的主要原因之一是一开始用于开发和扩展 Jenkins 的设计理念。这种软件开发方法鼓励人们共同合作，使项目能够从彼此中受益，并创建了一个高度富有成效和协作的开发者和贡献者社区。

当您首次考虑为 Jenkins 开发自己的插件时，您应该首先解决几个问题——以下链接提供了在着手开发自己的新插件之前应采取的步骤的详细描述：

[`wiki.jenkins-ci.org/display/JENKINS/Before+starting+a+new+plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Before+starting+a+new+plugin)

这背后的意图是提高插件的质量并避免重复。这种方法旨在鼓励现有和未来或拟议的插件的开发者共同合作，并在现有功能的基础上构建，而不是拥有大量非常相似的插件，每个插件都做一些略有不同的事情。

如果您正在寻找当前插件列表中不可用的一些附加功能，有可能有人正在努力提供此功能。如果您在开发社区中公布您的需求和意图，这可能会为您节省大量时间和麻烦。您可以选择与其他开发人员合作开发这个新插件，而不是自己动手。这种合作的最终结果更有可能产生受欢迎和高质量的产品，而不是两个开发人员创建类似功能。您还可能会发现您正在寻找的大部分功能已经在相关插件中可用，并且通过一些信息和合作，您可能能够利用这些功能来重用大部分现有代码来添加新功能。

所有这些协作、代码重用和增强主要是通过使用**扩展点**来实现的，这些扩展点代表插件或 Jenkins 功能的某些方面。这些是接口和抽象类，它们通过声明和公开的入口点实现交互和重用，提供并执行服务以符合文档化的合同。

现在我们将快速了解这些想法背后的理论，这样当我们编写自己的插件时，我们将了解幕后发生了什么，以及为什么我们从一开始就要考虑重用和扩展。

# 接口

Java 中的接口是用来提供和声明**合同**的机制，该合同定义了如何与和重用现有软件进行交互。这种方法背后的主要思想是，它消除了对内部工作方式的了解要求；您只需要知道所需的输入参数应该是什么，以及通过调用接口可以期望得到什么。代码的内部工作原理和处理方式并不是真正重要的，只要您遵守声明的合同，一切都应该没问题。

这种“按合同设计”的方法的另一个主要好处是，它减少了代码和流程更新对外部用户的影响。例如，如果您在名为`calculator`的类上调用一个`add`接口，该接口接受两个数字并返回结果，您（作为此服务的消费者）不需要知道或关心加法是如何完成的——在内部，该类可能只是简单地将两个 Java 整数相加，或者输入变量可能被传递到云中的 Web 服务，该服务将答案返回给`calculator`。代码和使用的方法可以完全重新设计和重写，但只要每个人都遵守约定的合同和接口，外部消费者就不应受到影响。

这种明确定义的接口还使得编写自动回归测试变得更加容易。当您知道有一个明确定义和稳定的接口时，通常可以简单地针对它编写测试，这些测试不需要太多的维护，因为接口通常不太可能被更改。这些测试可以在相关代码更改时作为 CI 构建的一部分自动重新运行，任何差异都应该很容易被识别。

要在 Java 中创建一个接口，我们在类定义中使用**interface**关键字：

```
**interface** Vehicle {
  // Vehicle methods
  // …
}
```

要使外部类使用这个接口，我们在类声明中使用**implements**关键字，如下所示：

```
class Motorbike **implements** Vehicle {
  // Vehicle Methods
  // …
  // Motorbike Methods
  // …
}
```

由于`Motorbike`类声明实现了`Vehicle`，它将需要实现在`Vehicle`中声明的每个方法。Java 编译器将确保在编译时完成这些操作。对于我们的`Vehicle`示例，这些方法可能包括逻辑函数，例如启动、停止、左转、右转、刹车和加速。`Motorbike`类特定的方法可能包括特定的内容，例如“飙车”，伸展支架，倒下等。

# 抽象类

Java 中的抽象类提供了可以被其他类使用的高级功能。您不能直接创建抽象类，但可以实现从抽象类派生的另一个类。

最简单的解释是，抽象类是一种类型的东西，但不是一个具体的东西——我的意思是，您可以有一个像我们的`Vehicle`示例那样声明了我们提到的所有方法的抽象类，但您永远不能只创建一个车辆——您必须有一些具体的东西，例如汽车、摩托车、气垫船、直升机等；您不能只有一个通用的车辆。

我们所有的车辆都略有不同，但共享相同的基本功能——它们可以行驶，可以停止，可以转弯。因此，这一共同的功能集可以被建模为抽象（`Vehicle`）类的基本方法，每当您创建一种新类型的车辆时，您将可以使用所有这些方法。

要在 Java 中创建一个抽象类，您必须使用`abstract`关键字：

```
abstract class Vehicle{}
```

通常，抽象类只会定义方法（行驶、停止、转弯），而子类将提供它们的实际实现。

我们的`Motorbike`类将扩展这个抽象类。

```
class Motorbike extends Vehicle {}
```

扩展抽象类的子类被称为**具体类**：

![抽象类](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00033.jpeg)

与抽象类的概念和逻辑分组不同，这些代表真实的、有形的对象。

# 抽象和接口

扩展点利用抽象和接口来允许和鼓励功能的重用。

在下图中，**存款**声明了一个名为**转账到储蓄**的扩展点。如果我们将其视为现有的代码，并且为了举例，如果我们想要创建一个新的**储蓄账户**对象，我们可以扩展已提供的存款功能，并使用它来实现一个名为储蓄账户的新功能，它扩展了存款。这意味着它将使用大部分存款功能，并且还将提供自己的附加功能。

![抽象和接口](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00034.jpeg)

在另一个例子中，我们将现有的`开户`代码扩展到`添加联名账户持有人`。这使用了许多`开户`方法，但也声明了一些特定于第二申请人的方法。以下图表显示了关系：

![抽象和接口](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00035.jpeg)

在我们有多个应用程序的情况下，我们可以扩展开户来创建一个新的**添加联名账户持有人**对象。这个新对象将包含并重用大部分开户代码，但它将以稍微不同的方式来满足第二个账户持有人的需求。

抽象类型是 Java 编程和面向对象设计中的一个关键概念。它们有时被称为**存在**类型，这有助于强调它们是*一种东西*，但没有必要的实现或属性来实际成为*一种东西*。

# 单例

在我们从高级和设计理论主题转移到在 Jenkins 中实现扩展之前，还有一个 Java 设计模式我们需要涵盖——单例模式。

当您希望确保给定类只有零个或一个实例时，可以使用单例。

通常，当您需要控制并发操作时会出现这种模式——通过确保只有一个实例可能，我们可以确保不会面临任何并发或竞争条件，因为这个类（和它的代码）将*绝对*是任何给定时间的唯一可能实例。通常，一个单例将被许多不同的函数使用，其目的是安全地处理和管理这种需求。

一个常见的单例示例是日志记录实用程序。例如，一个从系统的几个不同区域随时接收消息的类。然后它打开一个日志文件并将消息附加到文件中。我们不希望两个类同时写入同一个日志文件——那将引起混乱并且最终会以悲剧结束——因此控制和访问由该类的最多一个实例进行管理和限制。这个实例将被保证拥有并自由地写入日志文件，并且它将安全地知道没有其他相同类的实例在同时做同样的事情——它安全地管理“将这些信息写入日志文件”的功能。

希望使用“写入日志文件”方法的代码部分将尝试初始化单例对象。如果该对象的实例已经存在，我们将重用它，如果当前没有实例，将创建一个实例。然后它将保持可用，直到程序退出，或者被清理。

单例实例化是通过私有构造函数进行管理的，以便只有单例内部的代码才能创建它，如下所示：

```
public class Singleton {
  private static Singleton uniqueInstance = new Singleton();

  private Singleton() {}

  public static Singleton getInstance() {
    return uniqueInstance;
  }

  public String getDescription() {
    return "Singleton class";
  }
}
```

这被称为急切实例化，因为我们将在调用`getInstance()`方法之前每次创建一个新的单例对象。

对此的另一种方法——你使用哪种取决于你的偏好和要求——是使用延迟实例化，如下所示：

```
public class Singleton {
  private static Singleton uniqueInstance;
  private Singleton() {}

  public static synchronized Singleton getInstance() {
    if (uniqueInstance == null) {
      uniqueInstance = new Singleton();
    }
    return uniqueInstance;
  }

  public String getDescription() {
    return "Singleton class";
  }
}
```

在这里，我们使用了一个静态的单例实例，并同步了`getInstance()`方法。比较这两种方法应该有助于您决定最适合您需求的方法。在 UML 中，可以这样记录一个单例：

![Singletons](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00036.jpeg)

# 在 Jenkins 中声明一个扩展

正如我们迄今所见，一旦我们理解了它们背后的逻辑，创建一个接口或抽象类就很简单。声明一个接口或抽象类，然后实现所需的功能会更容易。

一旦您了解何时使用每种设计模式以及哪种方法适合您的要求，创建一个单例也很简单。

如果我们在创建或添加组件到 Jenkins 插件时牢记这一模式，我们应该能够确定适当的机会，可以在那里公开一个接口并为其他人创建一个扩展点以供使用。例如，如果您正在开发一个插件，出于某种原因将 Jenkins 作业的历史转换为 CSV 文件，以便可以导出并在电子表格中进行分析，您将编写函数将一些数据转换为 CSV 值——这可以声明为一个扩展点，只要传递的数据是指定类型的，其他人就可以重用您的代码将其数据转换为 CSV，而不是每个人都实现相同的函数，这将导致不必要的重复。

要在 Jenkins 中定义或创建一个扩展，我们使用`@Extension`注释类型。

Jenkins 会捕获这个注释，并将新的扩展添加到一个`ExtensionList`对象中，然后可以通过`ExtensionFinder`找到该扩展。

有关扩展注释的更多细节可以在这里找到：[`javadoc.jenkins-ci.org/?hudson/Extension.html`](http://javadoc.jenkins-ci.org/?hudson/Extension.html)。

以下示例显示了`Animal`扩展点的声明：

```
/**
 * Extension point that defines different kinds of animals
 */
public abstract class Animal implements ExtensionPoint {
  ...

  /**
   * All registered {@link Animal}s.
   */
  public static ExtensionList<Animal> all() {
    return Hudson.getInstance().getExtensionList(Animal.class);
  }
}
```

这说明了一个实现`ExtensionPoint`的抽象类：[`wiki.jenkins-ci.org/display/JENKINS/Defining+a+new+extension+point`](https://wiki.jenkins-ci.org/display/JENKINS/Defining+a+new+extension+point)。

# 总结

在本章中，我们探讨了几种主要设计模式背后的概念，并看到了何时使用每种方法以及为什么这样做。

如果您是一位经验丰富的 Java 程序员，这些概念应该非常熟悉，如果不是，那么希望这将成为一个基础，不仅帮助您理解我们在随后章节中所做的事情，也帮助您理解我们为什么这样做。

在本章的开头，我们提到了插件开发背后的哲学——人们应该寻求合作，重用和扩展现有的代码，以尽可能提供新的功能。如果每个人都单独创建自己特定需求的插件，而不是合作和贡献到现有的努力中，就会出现大量重复和复制，结果质量会大大降低。

这种理念和前述的设计方法已经创造了一个插件开发者社区，他们通过提供大量功能来生产高质量的软件，使 Jenkins 用户能够适应和扩展 Jenkins 以执行非常多样化的任务。

在下一章中，我们将在这些知识的基础上构建，并看到我们在开发第一个 Jenkins 插件时使用的概念。


# 第六章：开发您自己的 Jenkins 插件

在上一章中，我们专注于 Jenkins 插件背后的高级概念。

在本章中，我们将亲自动手，通过设置我们的开发环境，熟悉我们需要了解的工具和约定，然后创建我们的第一个 Jenkins 插件。

在本章结束时，您应该熟悉以下内容：

+   使用 Maven 进行构建和依赖管理

+   用于插件项目的结构和布局

+   创建您自己的 Jenkins 插件项目

+   对插件源代码进行基本更改

+   编译，打包和部署插件到远程 Jenkins 实例

+   使用 IDE 进行更改和运行 Jenkins

+   在 IDE 中运行和调试 Jenkins 和您的插件代码的基础知识

我们将首先设置我们的开发环境；然后，按照传统方式，我们将创建一个非常简单的`Hello World`Jenkins 插件项目，以说明机制并让我们开始。

本章的大部分内容都是基于 Jenkins 插件教程指南中涵盖的主题：

[`wiki.jenkins-ci.org/display/JENKINS/Plugin+tutorial`](https://wiki.jenkins-ci.org/display/JENKINS/Plugin+tutorial)

### 注意

这个页面有很多有用的参考资料，如果您在本章的任何方面遇到困难，这应该是您的首要选择。

我们将首先专注于工具、约定和框架，并坚持使用最简单的插件，以便对开发插件所使用的过程和工具有扎实的理解。我们将在下一章中研究扩展点和更复杂的代码更改。

我们还将介绍在 Eclipse 中直接进行的插件开发和基本 Jenkins 调试的 IDE 设置。

### 提示

首先，我们集中于使用 Java 和 Maven，因为它们目前是构建插件最常用的工具集，但我们也将在下一章中看看替代方法，比如 Groovy 和 Gradle。

让我们开始设置您的环境。

# Maven 简介

我们将使用 Maven 来构建我们的插件。如果您对 Maven 不熟悉，不用担心——Maven 的主要观点是，您不一定需要对 Maven 了解很多，就可以使用它并从中获得很多好处！

对于一个相当不寻常的构建工具来说，您可能期望自己深陷于配置文件和代码中。然而，由于 Maven 的核心理念是使用“约定优于配置”，因此即使没有这些文件，Maven 也可以很好地工作。

Maven 的工作假设您和您的项目遵循一套标准、合理的约定。这些并不是太奇怪或繁重的东西，所以如果您遵循这条路线，那么 Maven 应该知道一切在哪里，以及您想要实现什么，并将帮助您快速轻松地启动和运行。

其中一个核心假设与您的项目结构有关；具体来说，如果您使用的是这样的目录布局：

| 项目 | 默认目录（相对于项目目录） |
| --- | --- |
| 源代码 | `src/main/java` |
| 资源 | `src/main/resources` |
| 测试 | `src/test` |
| 编译代码 | `target` |
| 可分发的 JAR | `target/classes` |

给定一个遵循这个约定的项目，Maven 将自动知道如何构建您的代码，如何测试它，以及如何将所有内容打包得很好，而无需其他配置或干预，为您提供了很大的好处，成本很小。

### 提示

只要您的项目坚持 Maven 所期望的路径，这就很好……如果您偏离了，事情就会变得非常混乱！这使得 Maven 非常适合新的和良好结构的项目，但在引入具有其自己关于位置和命名约定的传统项目时，需要更多的工作。

# 安装 Maven

Maven 是一个 Java 工具，因此，我们需要安装 Java 才能使用它。如果你在本地运行 Jenkins，你的系统上应该已经有 Java 了，但如果没有，你可以从以下链接下载适合你平台的 JDK——需要 6.0 或更高版本：

[`www.oracle.com/technetwork/java/javase/downloads/index.html`](http://www.oracle.com/technetwork/java/javase/downloads/index.html)

一旦你解决了 Java 的先决条件，就从 Apache 网站下载适合你平台的 Maven：

[`maven.apache.org/download.cgi`](https://maven.apache.org/download.cgi)

然后按照此页面上的操作系统的安装步骤进行安装：

[`maven.apache.org/install.html`](https://maven.apache.org/install.html)

在所有平台上，主要要求是确保你的`PATH`中有`JAVA_HOME`变量，并且`PATH`还包含你从下载中提取的 Maven `bin`目录。

一旦你设置好了，当你运行`java -version`然后`mvn -version`时，你应该得到与以下大致相似的东西——我也在这里显示 Java 和 Maven 环境变量供你参考：

![Installing Maven](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00037.jpeg)

现在我们需要告诉 Maven 关于 Jenkins 的情况；它在哪里以及如何构建它。我们通过更新 m2 主目录中的`settings.xml`文件来实现这一点，其中包含在前面提到的 Jenkins 插件教程页面的**设置环境**部分提供的 XML：

[`wiki.jenkins-ci.org/display/JENKINS/Plugin+tutorial`](https://wiki.jenkins-ci.org/display/JENKINS/Plugin+tutorial)

在 Linux 或 Mac 中找到你的`settings.xml`文件：`~/.m2/settings.xml`。

对于 Windows，文件位于：`%USERPROFILE%\.m2\`。

在`settings.xml`文件中添加以下文本：

```
<settings>
  <pluginGroups>
    <pluginGroup>org.jenkins-ci.tools</pluginGroup>
  </pluginGroups>

  <profiles>
    <!-- Give access to Jenkins plugins -->
    <profile>
      <id>jenkins</id>
      <activation>
        <activeByDefault>true</activeByDefault> 
          <!-- change this to false, if you don't like to have it on per default -->
      </activation>
      <repositories>
        <repository>
          <id>repo.jenkins-ci.org</id>
          <url>http://repo.jenkins-ci.org/public/</url>
        </repository>
      </repositories>
      <pluginRepositories>
        <pluginRepository>
          <id>repo.jenkins-ci.org</id>
          <url>http://repo.jenkins-ci.org/public/</url>
        </pluginRepository>
      </pluginRepositories>
    </profile>
  </profiles>
  <mirrors>
    <mirror>
      <id>repo.jenkins-ci.org</id>
      <url>http://repo.jenkins-ci.org/public/</url>
      <mirrorOf>m.g.o-public</mirrorOf>
    </mirror>
  </mirrors>
</settings>
```

为每个项目创建一个新目录是个好主意。这样做可以保持清洁和简单，而不是让多个项目共存于一个文件夹中。要为这个项目创建一个目录，运行`mkdir`，然后`cd`进入目录，如下所示：

```
**mkdir jenkinspluginexample**
**cd jenkinspluginexample**

```

之后，我们可以开始构建，这将为我们创建一个骨架插件项目：

```
**mvn -U org.jenkins-ci.tools:maven-hpi-plugin:create**

```

### 注意

如果在这一点上有任何问题，请首先检查以下三个常见原因：

+   `mvn`在这个目录下工作吗？使用`mvn -version`进行检查

+   Java 在这个目录下工作吗？使用`java -version`进行检查

+   你有互联网连接吗？使用 `ping www.google.com` 进行检查

如果一切顺利，你将被提示回答几个简单的问题；Maven 将要求你指定插件的`groupId`和`artifactId`参数。

对于`groupId`，惯例是使用你的域名倒序，然后是项目名称，全部小写并用点分隔。给定`donaldsimpson.co.uk`域名和`jenkinspluginexample`项目名称，我会使用这个：`uk.co.donaldsimpson.jenkinspluginexample`。

`artifactId`的值应该是你的项目名称，即`jenkinspluginexample`。

如果`jenkinspluginexample`项目包含多个组件或服务，你应该在这里附加额外的服务名称，例如以下内容：

```
**jenkinspluginexample-service**
**jenkinspluginexample-web**
**jenkinspluginexample-gui**

```

这种方法的目的是确保与组 ID 一起使用时，项目的每个部分都能保持独特和容易识别。

![Installing Maven](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00038.jpeg)

上述截图是先前输入的结果，并声明使用骨架插件创建了版本 1.0 快照构建，这为我们创建了一个非常基本的第一个插件供我们检查。

现在看看新创建的子目录里面，它的名称应该与你的`artifactId`匹配。

在探索这个目录之后，我们现在应该生成了创建最基本插件所需的所有示例。这些包括以下内容：

+   `pom.xml`：我们项目的新 Maven POM 文件，其中包含 Maven 构建、打包和分发我们示例插件所需的信息

+   `src/main`：这个目录包含 Java 目录和资源目录

+   `src/main/java`：这个目录包含我们稍后将更新的`Hello World`构建器类

+   `src/main/resources`：这个文件夹包含配置和帮助文件

仔细查看我们刚刚生成并提到的这些新文件夹的内容，将帮助你熟悉 Maven 和 Jenkins 用于开发、构建和分发插件的不同文件和结构。布局遵循 Maven 的约定，并且也用于许多其他项目。

正如你之前看到的，我们的新项目目录有自己的`pom.xml`文件，所以我们应该能够将其构建为一个 Maven 项目——让我们来看看并尝试一下！

切换到新的`pom.xml`文件所在的位置，并查看它——你会看到这里提供了各种可用的目标，以及与我们的项目一起使用所需的所有细节。

还有一个打包声明，如下所示：

```
<packaging>hpi</packaging>
```

这告诉 Maven 你希望将这个项目打包成一个 HPI 文件——这是 Jenkins 插件的标准文件格式。其他打包指令通常包括 ZIP、JAR、WAR 和 EAR。

Maven 还假设你希望对项目执行一组标准任务——这些通常包括以下功能或**阶段**：

+   `validate`：这将验证项目是否正确，并且所有必要的信息都是可用的。

+   `compile`：这将编译项目的源代码。

+   `test`：这将使用适当的单元测试框架测试编译后的源代码。这些测试不应该需要代码被打包或部署。

+   `package`：这将编译后的代码打包成可分发的格式，比如 JAR。

+   `integration-test`：如果需要，这个过程会将包部署到集成测试环境中。

+   `verify`：这将运行检查以验证包是否有效并符合质量标准。

+   `install`：这将把包安装到本地仓库，以便在其他项目中作为依赖使用。

+   `deploy`：这是在集成或发布环境中完成的。此功能将最终的包复制到远程存储库，以便与其他开发人员和项目共享包。

+   `clean`：这将清理先前构建创建的构件。

+   `site`：这为该项目生成站点文档。

这个指南有关于 Maven 阶段和目标以及它们如何关联的更多信息：

[`maven.apache.org/guides/getting-started/maven-in-five-minutes.html`](https://maven.apache.org/guides/getting-started/maven-in-five-minutes.html)

如果我们现在运行`package`目标，Maven 应该会运行所有先决步骤，然后生成一个 HPI 文件，我们可以通过运行以下命令将其部署到 Jenkins：

```
**mvn package**

```

这个阶段将使用 POM 文件中的信息下载所有必需的依赖项。然后它将编译 Java 代码，并且如果存在测试（在预期位置`src/test`中），也会运行测试。

根据你的互联网连接，这可能需要一些时间，因为 Maven 将对所有声明的依赖项（以及它们的依赖项！）进行初始下载，这些依赖项在本地还没有。在后续运行中，事情应该会快得多，因为 Maven 将在`.m2/repository`缓存文件夹中保留已下载的资源，该文件夹位于你的家目录旁边，就在我们之前更新的 settings.xml 文件旁边。

完成后，你现在应该有一个可分发的`.hpi`文件！

![安装 Maven](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00039.jpeg)

从前面的图像中可以看出，控制台输出在最后附近解释了代码已经被编译成一个 Java 存档（`.jar`）文件，资源（Jelly、配置和 HTML 文件）已经被包含，并且一切都已经在我的情况下被打包成了一个名为`jenkinspluginexample.hpi`的结果存档，现在位于`target/`目录中。

我们还没有写一行代码，但我们刚刚制作了我们的第一个 Jenkins 插件！

现在让我们将其部署到标准的 Jenkins 实例：

1.  打开您的 Jenkins 实例的主页。

1.  导航到 Jenkins 的**主页** | **管理 Jenkins**。

1.  选择**管理插件**，然后选择**高级**。

1.  滚动到**上传插件**部分，然后点击**浏览**。

1.  导航到您的项目目录的目标目录中的新`.hpi`文件所在的本地文件夹：![安装 Maven](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00040.jpeg)

单击**提交**按钮后，您应该看到您的插件已上传并安装到您的 Jenkins 实例上：

![安装 Maven](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00041.jpeg)

现在，您的已安装插件列表中将会有一个`TODO`插件，以及快照构建编号和您的名字作为作者。

如果您现在点击任何自由风格作业的**配置**，将会有一个新选项添加一个名为**Say hello world**的构建步骤：

![安装 Maven](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00042.jpeg)

选择这个选项将产生以下对话框，您需要在其中提供您的名字：

![安装 Maven](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00043.jpeg)

毫不奇怪，对于一个`Hello World`项目，下次运行此作业时，这将显示为控制台输出中的一个额外构建步骤：

![安装 Maven](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00044.jpeg)

在 Jenkins 实例上安装和运行我们自己的插件看起来很酷，第一次这样做很有趣。然而，当您开发插件时，每次进行小改动时都要经历这样的过程比您想象的更麻烦！

现在让我们看看如何进行第一次代码更改以及更智能、更高效地打包、部署和测试我们的代码。

首先，对`HelloWorldBuilder.java`文件进行微小的更改，该文件位于您的`src/main/java`目录中：

```
src/main/java/uk/co/donaldsimpson/jenkinspluginexample/jenkinspluginexample/HelloWorldBuilder.java
```

![安装 Maven](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00045.jpeg)

最初，这行是这样的：

```
listener.getLogger().println("Hello, "+name+"!");
```

我只是将前一行改成了以下内容：

```
listener.getLogger().println("Hello there, "+name+"!");
```

与其再次经历之前的整个过程——编译、打包、通过 Jenkins 网页部署等等——来检查这个小更新，我们可以通过一个简单的 Maven 命令执行所有这些步骤：

```
**mvn hpi:run**

```

这将编译代码（在接受我们的修改后），然后启动并在您的计算机上运行一个带有我们新更新的插件的本地 Jenkins 实例——这使得测试您的更改变得更容易、更快速、也更安全。

要在 Windows 上执行此操作，首先导出以下设置：

```
**set MAVEN_OPTS=-Xdebug –Xrunjdwp:transport=dt_socket,server=y,address=8000,suspend=n**

```

在 Unix 和 Mac 上，执行相应的操作，如下所示：

```
**export MAVEN_OPTS="-Xdebug –Xrunjdwp:transport=dt_socket,server=y,address=8000,suspend=n"**

```

然后，无论平台如何，调用`hpi:run`目标，如下所示：

```
**mvn hpi:run**

```

之后，您将能够看到 Maven 下载依赖项，然后启动一个本地的 Jetty 实例，该实例在其中运行具有您的插件的 Jenkins！

密切关注控制台输出，当显示以下文本时，您将看到一切都完成了：**INFO: Jenkins is fully up and running**。

在这一点上，您可以通过将浏览器指向以下位置来安全地连接到 Jenkins 实例：

`http://127.0.0.1:8080/jenkins/`

### 注意

不要尝试连接到您在`MAVEN_OPTS`中设置的`8000`端口——这用于调试，我们稍后会看一下。使用端口`8080`，并注意附加的`/jenkins/`路径也是必需的，以便连接。

现在，我们可以创建和配置一个新的自由风格作业，并通过选择使用我们的**Say hello world**作业并将我们的名字添加到其中来添加与之前相同的构建步骤。

运行这个新作业应该会产生预期的输出，如下所示：

![安装 Maven](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00046.jpeg)

这证明了我们的代码更改已被接受，并展示了您可以多快多轻松地进行代码更改、测试、打包、部署和验证——一个小小的 Maven 命令为您完成了大部分工作！在初始设置和下载之后，这也是一个相当快速的过程。

为了使生活更加轻松，我们可以设置一个 IDE 来帮助我们开发 Jenkins 插件。

### 注意

官方的 Jenkins 插件教程页面位于[`wiki.jenkins-ci.org/display/JENKINS/Plugin+tutorial`](https://wiki.jenkins-ci.org/display/JENKINS/Plugin+tutorial)。该教程包含了 NetBeans、IntelliJ IDEA 和 Eclipse 的步骤。前两者非常简单，所以我们将在这里更详细地介绍 Eclipse 的设置。

插件指南目前建议使用此命令为插件开发生成新的 Eclipse 工作空间：

```
mvn –DdownloadSources=true –DdownloadJavadocs=true -DoutputDirectory=target/eclipse-classes –Declipse.workspace=**/path/to/workspace** eclipse:eclipse eclipse:add-maven-repo
```

您需要将`/path/to/workspace`更新为系统上合适的工作空间位置，这可以是您喜欢的任何地方，但理想情况下应该与其他 Eclipse 工作空间相邻。

### 注意

我在运行建议的命令时遇到了问题，并发现`eclipse:add-maven-repo`已经过时，所以我将其更新为`eclipse:configure-workspace`。

对于我的项目，以下操作有效：

```
mvn –DdownloadSources=true –DdownloadJavadocs=true -DoutputDirectory=target/eclipse-classes -Declipse.workspace=/Users/donaldsimpson/Documents/JenkinsPluginEclipseWorkspace eclipse:eclipse eclipse:configure-workspace
```

确保您从创建`Hello World`插件的相同目录中运行此命令，因为它需要`pom.xml`文件和其他资源。

完成后，此步骤应成功在新的工作空间中填充一个新的 Eclipse`.metadata`目录，并在您的项目目录中具有所有必需的设置和资源。

接下来，打开 Eclipse 并切换到您选择的工作空间，选择**导入**（在**文件**菜单下），选择**常规**，然后选择**现有项目到工作空间**，如下所示：

![安装 Maven](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00047.jpeg)

将此对话框指向您创建`Hello World`插件的目录（`pom.xml`文件所在的位置），Eclipse 应该会自动为您加载项目：

![安装 Maven](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00048.jpeg)

完成后，您的 IDE 应该看起来像这样：

![安装 Maven](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00049.jpeg)

现在您可以在 Eclipse 中编辑 Java 类和插件资源。

### 提示

请记住，您还可以启用我们之前设置的 Mylyn 插件，以便随时关注您最重要的 Jenkins 构建的情况！

您还可以从这里管理项目的 POM 文件并运行 Maven 构建——右键单击`pom.xml`文件，然后选择**运行为**和**Maven 构建**，Jenkins 现在应该会直接在您的 Eclipse 控制台中启动，并且您的插件已经部署了最新版本的代码。

要测试此设置，请尝试进行另一个非常简单的更改——在前面的图像中，我将输出消息更新为**Hello again**，只是为了不同。保存`Hello World`构建器类，然后通过 Eclipse 运行 Maven 目标`hpi:run`将启动 Jenkins，您可以在 Eclipse 中看到所做的更改。

您还可以在**调试**模式下运行 Jenkins，并通过单击 Eclipse 中所需代码的行来设置断点，如下所示：

![安装 Maven](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00050.jpeg)

在这里，我们可以看到当通过 Jenkins 运行构建时，断点被激活。此时，焦点将自动从浏览器中的 Jenkins 切换到 Eclipse IDE，在那里我们可以实时检查现有变量的当前值。然后，我们可以通过实时调试值并在每一步监视控制台输出来逐步走过代码。

这是一个非常方便的开发功能，以这种方式设置 Jenkins 插件开发环境可以使事情更加高效，也可以让您的生活变得更轻松！

# 摘要

在本章中，我们已经构建、打包和部署了我们自己的“基本”Jenkins 插件。

我们已经了解了开发 Jenkins 插件所使用的工具和约定。我们在开发主机上设置了 Java、Maven 和 Eclipse，并学会了如何构建、打包、测试、部署，甚至调试我们自己的插件。

我们仍然缺少的主要内容是您决定放在中间的内容！这将是我们下一章的重点。


# 第七章：扩展 Jenkins 插件

到目前为止，我们已经看过 Jenkins 插件开发的以下内容：

+   采取的方法-在可能的情况下重用，避免不必要的重复

+   协作-过程和社区如何工作

+   使用的设计方法和 Java 模式

+   设置开发环境和构建工具

+   开发第一个简单的插件

+   本地和远程部署和测试我们的插件

我们现在将看一下帮助您解决上一章缺失的中间部分并实现使您的插件能够做任何事情的方法！

这里的意图是引导您开发自己的插件，并演示您可以（并且应该）如何处理已经存在的资源的（再）使用的方式。

这意味着当您想要开发自己的插件并且想要尽可能快速和轻松地进行开发时，您可以通过遵循最佳实践并避免向 Jenkins 和插件代码库添加不必要的重复来实现这一点。

在此过程中，我们还将探索 Jenkins 插件使用的一些额外框架和技术。这些包括 Jelly、Stapler、本地化和国际化；当这些工具和实践一起使用时，能够使插件开发人员重用 Jenkins 内置功能，使他们的插件看起来像是“属于”Jenkins，而不是简单地添加上去的东西，通过保持与用户界面的其他部分相同的外观和感觉。

遵循这种方法，开始并了解如何使用这些框架将为您节省大量时间和挫折。一旦您知道如何研究和重用现有插件和 Jenkins 提供的代码和功能，您也将节省大量的开发工作。

在开发`Hello World`插件时，我们涵盖了大量新信息并引入了一些新概念。这些都是在相当高的层次上完成的，并且最小化了编码和配置，以便我们可以专注于整个过程并了解事物的运作方式。实际的代码非常简单，对于一个插件来说，它只是在每次运行构建时向控制台日志中写入一条消息。

毫无疑问，Jenkins 插件已被创建用于执行各种任务，并且它们以各种方式执行这些任务-有些与 Jenkins 用户界面无缝集成，而其他一些在背景中默默工作。有些扩展了现有功能，而其他一些添加了全新的功能。插件似乎是一致的-它们大致具有相同的外观和感觉，而不是看起来像是由不同的人开发的，他们对颜色方案、导航、对话框等有自己的想法。它们甚至能够响应区域设置的更改，根据用户指定的首选项以不同语言提供对话框。尽管 Jenkins 的许多功能来自大量插件，其中许多已经被吸收到 Jenkins 的核心中，但印象和用户体验是一个相当流畅和一致的整体，而不是一个碎片化和不一致的添加集合。

在本章中，我们将看一下进入 Jenkins 插件的其他元素，并扩展您可以完善自己的插件的方式。我们还将看一下如何查找和重用现有的代码/插件以便快速开始，并且我们将浏览一个提供类似于我们想要开始开发的假设新插件的功能的插件的内容。

# 从哪里开始？

因此，在查看了 Jenkins 网站和社区之后，我们决定编写一个新的插件，因为目前没有任何现成的（或者正在开发中的）插件能够满足我们的需求；我们应该从哪里开始呢？

我们可以从一个新的空白 Eclipse 项目开始，如果我们真的想的话，可以自己写所有的东西，但那将需要很长时间。

我们可以使用骨架`Hello World`项目，删除其中的内容，然后开始向其中添加我们的代码，但考虑到我们已经讨论了一段时间的代码重用和避免重复，这似乎不是我们期望遵循的方法。

即使您对插件有一个完全新颖的想法，也肯定已经有与之大致相关的东西存在；即使这并不能提供我们想要的功能，它可能以类似的方式工作或使用我们已经确定的许多感兴趣的扩展点，因此值得检查一下。

# 查看现有插件列表

通常，查看的第一个地方是可用插件的列表。如果您的 Jenkins 实例是最新的，您可以在 Jenkins 的**可用插件**页面中浏览当前可用的选项。

转到**管理 Jenkins**，然后选择**管理插件**，并选择**可用**选项卡，以选择越来越多的插件列表。

请注意，此屏幕允许您按特定单词进行过滤，并提供每个插件的简要描述。

另外，Jenkins 的**插件**页面提供了一个更容易浏览和稍微更详细的列表：

[`wiki.jenkins-ci.org/display/JENKINS/Plugins`](https://wiki.jenkins-ci.org/display/JENKINS/Plugins)

这将按其一般类别或功能对插件进行分组，并提供到每个插件相应 Jenkins 主页的链接。反过来，主页提供了更多信息，包括指向 GitHub 上该插件的源代码的链接，您可以在线浏览或本地下载。

如果您能在这里找到与您的插件类似的东西，那么在 GitHub 上查看源代码将使您能够详细了解每个插件的工作原理。您还将能够找出此插件使用了哪些扩展点。

另一个要考虑的选项是直接转到这里的**扩展点**索引页面：

[`wiki.jenkins-ci.org/display/JENKINS/Extension+points`](https://wiki.jenkins-ci.org/display/JENKINS/Extension+points)

此列表是由**Extension Indexer**程序自动生成和维护的，该程序可在以下位置找到：

[`github.com/jenkinsci/backend-extension-indexer`](https://github.com/jenkinsci/backend-extension-indexer)

该程序解析当前代码库中声明的所有扩展点，然后在生成的**扩展点**页面上列出它们，以及诸如项目主页和使用它们的插件列表等进一步的细节。

无论哪个起点适合您，插件列表还是扩展点列表，您都应该希望最终到达同一个地方——大致类似于您想要最终得到的东西的想法，这应该是一个很好的开始。

例如，如果我的插件与 Docker 连接，我可以从本地 Jenkins 的现有插件列表开始搜索：

![查看现有插件列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00051.jpeg)

或者，我可以转到[`wiki.jenkins-ci.org/display/JENKINS/Extension+points`](https://wiki.jenkins-ci.org/display/JENKINS/Extension+points)，并在这里搜索 Docker 的引用：

![查看现有插件列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00052.jpeg)

这两条路最终都会导致所讨论的插件的主页，例如：

![查看现有插件列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00053.jpeg)

这告诉您关于插件的一切，包括指向托管在 GitHub 上的此插件的源代码和配置文件的链接。

为了说明其余的过程并介绍其他你可能想要使用的框架和文件，我们将考虑一个我们想要开始开发的新插件。我们将尝试找到一个已经存在的东西，用它来开始，然后查看代码、配置文件和扩展点，以便让我们达到可以开始添加我们自己的代码的地步。

# 需要一个新的构建类型

对于这个假设的例子，我将首先创建一个用于 Docker 构建的新构建步骤。这将允许用户创建这种类型的构建，添加一些信息，然后最终执行与 Docker 构建类似的操作。

在通常添加构建步骤的选项中（加上我们的**打印 Hello World**示例）：

![需要一个新的构建类型](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00054.jpeg)

这个令人惊奇的新插件将添加一个额外的条目来启动 Docker 构建。

通过查看添加额外构建步骤的类似项目和**Hello World**示例，我猜想我的新插件也需要扩展`Builder`、`BuildStep`和`AbstractProject`类。

在查看之前列出的链接和资源之后，我发现有一个现有的 Graven 插件项目，执行的步骤与我们想要的非常相似，而且恰好包括了我们想要在本章中检查的所有新资源。另外，这里还有一些方便的文档：

[`wiki.jenkins-ci.org/display/JENKINS/Create+a+new+Plugin+with+a+custom+build+Step`](https://wiki.jenkins-ci.org/display/JENKINS/Create+a+new+Plugin+with+a+custom+build+Step)

让我们来看一下。源代码可以从 GitHub 下载，然后提取到本地目录：

[`github.com/jenkinsci/graven-plugin`](https://github.com/jenkinsci/graven-plugin)

这给了我们开始自己的插件所需的一切，这比从头开始要容易得多——我们可以检查和重用这里使用的扩展点，看看插件是如何创建新的构建类型，并调整属性文件和其他资源的，因为它执行了我们想要做的相同步骤。

# 加载和构建我们的起点

让我们将这个项目导入到 Eclipse 中。同样，这个过程非常简单；就像我们在上一章中所做的那样，我们将为我们的 Eclipse 项目创建一个目录，使用`cd`进入包含我们项目的 POM 文件的目录，然后再次运行`eclipse:configure-workspace`目标，如下所示：

```
mvn -DdownloadSources=true -DdownloadJavadocs=true -DoutputDirectory=target/eclipse-classes -Declipse.workspace=/Users/donaldsimpson/Documents/GravenPluginMasterWorkspace eclipse:eclipse eclipse:configure-workspace
```

这应该下载所有的依赖项，并允许你将项目导入到你的 IDE 中（导航到**文件** | **导入** | **常规** | **导入现有项目到工作区**），就像我们在上一章中所做的那样。

现在你应该已经将这个插件的所有资源和源代码加载到你的 IDE 中，它应该大致看起来像这样：

![加载和构建我们的起点](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00055.jpeg)

我们现在将快速浏览这些文件和文件类型，解释它们的功能，并探索它们为这个插件提供的附加插件组件和选项，以及它们可能为我们的新插件带来的潜在功能。

# 构建器类和 Stapler

第一个类是`GravenBuilder.java`。该类声明扩展了`Builder`类：

```
public class GravenBuilder extends Builder {
```

正如我们在[`javadoc.jenkins-ci.org/hudson/tasks/Builder.html`](http://javadoc.jenkins-ci.org/hudson/tasks/Builder.html)的 JavaDoc 中所看到的，扩展`Builder`类将把这个类注册为 Jenkins 的**自定义构建器**，这正是我们想要的。

### 提示

这个扩展声明是**扩展点**页面如何更新的——构建索引的程序将在代码中找到这个引用，并自动为我们创建关联。

`GravenBuilder`类还包含这个简单的方法：

```
@DataBoundConstructor
public GravenBuilder(String task) {
  this.task = task;
}
```

通过使用`@DataBoundConstructor`注解，当用户决定创建此新的构建类型时，此方法将注册此任务/构建类型的选择。这是通过 Jenkins 使用的 Stapler 框架自动完成的，该框架用于序列化和转换 Java 对象。您可以在此处了解有关 Stapler 的更多信息，它的工作原理以及如何在插件中使用它。

[`stapler.kohsuke.org/what-is.html`](http://stapler.kohsuke.org/what-is.html)

此外，在`GravenBuilder`类中，有一个名为`Descriptor`的内部类。这个类扩展了`BuildStepDescriptor`，其功能是为 Jenkins 提供一种管理`GravenBuilder`实例及其生命周期的方式。

`GravenInstallation`类包含所有必需的安装和注册设置；这些设置工具提示并定义了用于此插件的显示名称等。

# Jelly 和 Jenkins

`config.jelly`配置文件是一个简单的 Jelly 模板。您可以在以下链接中了解有关 Jenkins 中 Jelly 的更多信息：

[`wiki.jenkins-ci.org/display/JENKINS/Basic+guide+to+Jelly+usage+in+Jenkins`](https://wiki.jenkins-ci.org/display/JENKINS/Basic+guide+to+Jelly+usage+in+Jenkins)

您可以在[`commons.apache.org/proper/commons-jelly/`](http://commons.apache.org/proper/commons-jelly/)中了解更多关于 Jelly 的一般信息。这篇文章陈述了以下内容：

> *Jelly 是基于 Java 和 XML 的脚本和处理引擎。*

在这种情况下，Jelly 的主要目的是为开发人员提供一个高度灵活的标签库，通过它们可以快速轻松地创建和处理 UI 视图更改。

从开发者的角度来看，Jelly 文件与 Java 代码交互，以在运行时获取和设置声明的值，并通过 UI 呈现给用户。

# 帮助

`help*.html`文件为用户提供上下文相关的帮助消息。这些消息只是在`<div>`标签内定义，并将显示为 Jenkins 用户界面中的标准工具提示。这种方法允许您引导用户，建议他们可以做什么，不能做什么，并解释您的插件的功能和要求。

`index.jelly`文件为用户提供了关于此插件功能的一般高级描述——当我们在 Jenkins 中查看插件运行时，我们将看到这段文本显示为插件描述。

# 属性文件和消息

`Messages.properties`和`config_fr.properties`文件用于提供 i18n 国际化，如下所述：

[`wiki.jenkins-ci.org/display/JENKINS/Internationalization`](https://wiki.jenkins-ci.org/display/JENKINS/Internationalization)

在此链接中有关本地化和国际化的更多详细信息：

[`www.w3.org/International/questions/qa-i18n`](http://www.w3.org/International/questions/qa-i18n)

在 Jenkins 插件开发中，我们实际上只需要提供`config_LOCALE.properties`文件来满足每种语言。例如，如果用户的`LOCALE`变量设置为`fr`，则将使用`config_fr.properties`文件中的消息——其他`LOCALE`文件可以根据需要添加以支持其他语言。

您的插件代码能够在运行时使用和引用这些属性，如下所示：

```
Messages.GravenBuilder_Task()
```

`Messages.java`类在目标目录中是根据这些属性文件在构建时生成的。

# POM 文件

最后剩下的文件`pom.xml`是我们之前看过的 Maven 设置文件。这个文件特定于我们在此处使用的插件，并包含将用于构建、运行和打包项目的组、artifact 和版本信息，我们现在将执行这些操作。

右键单击`pom.xml`文件，然后选择**Run as**，然后**Maven Build...**允许您再次指定`hpi:run`目标，这应该会启动一个新的本地 Jenkins 实例，其中包含了这个插件编译和部署到这个新实例的所有资源和本地化设置。

当实例启动时，我们可以通过浏览器连接并查看我们在理论上审查过的各种设置和代码在实践中被使用。

我们可以检查并查看插件是否被列为已安装，以及消息文本，这些消息文本是从`index.jelly`中提取的：

![POM 文件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00056.jpeg)

当我们创建一个新的自由风格作业并查看可用的**构建**步骤时，这个插件将显示为一个新选项——**执行 GRaveN 任务**，这是从**Messages.properties**中提取的：

![POM 文件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00057.jpeg)

当我们选择这个选项时，我们将看到在配置和代码中定义的对话框、本地化工具提示和输入框：

![POM 文件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00058.jpeg)

这个示例插件看起来像是我们假想插件的一个很好的起点。它可能不能做我们想做的一切，但我们可以调整和重用设置文件和一些代码以及扩展点，让我们开始，并且可以很快地运行我们自己的插件的基本功能。

这个假想插件的实现，或者你自己的插件，在细节上可能有不同的需求，但希望这能说明你可以遵循的方法和途径，让你快速启动你的插件。

如果你想了解一个插件是如何工作的，或者如何改变一个插件，或者修复一个插件中的错误，了解各种资源文件的使用方法，并通过从源代码开始加载和运行任何本地插件是一项非常有用的技能。

# 插件进展

我们搜索并找到了大致符合我们想要做的事情的东西，至少起步阶段是这样。我们已经确定了提供我们需要的一些功能的扩展点，并且我们已经有了一个功能非常齐全的插件的雏形，它看起来和感觉像 Jenkins 的一个正常部分。它将为用户提供内置的帮助，甚至会说用户偏好的语言...只要我们添加相应的配置文件。

# 总结

这个插件的下一步将是实现更多我们自己的代码，执行 Docker 构建，或者我们想要执行的任何功能。再次，这个功能可以进一步利用可用的扩展点，或者如果没有可用的扩展点可以做我们想要的事情，我们应该考虑声明它们的接口，并在编写自己的实现后与社区分享。

在下一章中，我们将探讨测试插件的工具、选项和资源。当我们探讨如何处理、解决和避免插件问题时，我们还将进一步深入调试。


# 第八章：测试和调试 Jenkins 插件

在本章中，我们将看一下 Jenkins 插件的测试和调试。我们将探讨目前可用的几种流行选项和方法，并审查每种方法的好处和适用性。

如果您愿意简单地运行标准的 Java 单元测试，那么测试 Jenkins 插件就相当简单，但是如果您希望通过用户界面测试和模拟交互，测试可能会变得有点复杂。我们将从一个简单的例子开始，然后再看一些您可能希望进一步调查的方法和工具，以应对更复杂的情况。

能够调试 Jenkins 插件是您开发技能的宝贵补充—它可以帮助您了解在开发自己的插件时发生了什么，并且还可以帮助您解决其他插件或 Jenkins 本身的问题。

在本章中，我们将看一下以下主题：

+   测试：在测试下，我们将涵盖以下主题：

+   为现有项目运行测试

+   编写您自己的测试

+   可用工具

+   技术—HTML 抓取，模拟等

+   调试：在调试下，我们将涵盖以下主题：

+   标准日志文件

+   使用本地 Jenkins 调试会话

+   从 IDE 连接

+   `mvnDebug`命令

# 使用 Maven 运行测试

当我们早些时候探索插件开发时，我们学会了在哪里找到并如何获取任何给定 Jenkins 插件的源代码。

大多数插件的完整源代码可以从 GitHub 快速轻松地下载，然后在本地机器上构建。在许多情况下，这也包括单元测试，这些测试与源代码捆绑在一起，可以在预期的（按照 Maven 约定）`src/test`位置找到。检查一些流行的插件将为您提供有用的信息，并为编写自己的测试用例提供一个很好的起点。

Maven 的`test`目标将执行所有测试，并通过详细说明所有通常的统计数据，如运行的测试数量以及有多少失败和错误，以及跳过的测试数量，生成结果的摘要。

为了演示这个过程，我们将看一下非常流行的`Green Balls`插件，它简单地用绿色的球替换了 Jenkins 中的标准蓝色球。

### 提示

这个链接解释了为什么 Jenkins 默认是蓝色的球：

[`jenkins-ci.org/content/why-does-jenkins-have-blue-balls`](http://jenkins-ci.org/content/why-does-jenkins-have-blue-balls)

绿色球插件主页链接到这个 GitHub 位置，您可以在其中下载源代码和配置文件的 zip 文件，或使用提供的 URL 进行克隆：

[`github.com/jenkinsci/greenballs-plugin`](https://github.com/jenkinsci/greenballs-plugin)

我们正在研究这个示例插件，因为它包含了涵盖主要主题和测试风格的各种测试—我们将很快更详细地看一下内容。一旦您将源代码下载到本地机器上，您应该能够通过简单运行 Maven 的`test`目标来启动测试：

```
**mvn test**

```

然后，该目标将在执行所有测试之前运行所有先决设置步骤，然后报告结果，如下所示：

![使用 Maven 运行测试](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00059.jpeg)

请注意，可以通过指定测试的名称来运行单个测试，如下所示：

```
**mvn test -Dtest=GreenBallIntegrationTest**

```

这将导致运行一个测试，或者您可以使用通配符，如下所示：

```
**mvn test -Dtest=*ilter***

```

前面的代码导致在这种情况下运行四个测试。

这种方法可以用来将您的测试分类为逻辑套件—集成测试、夜间测试、回归测试或单元测试—无论您喜欢什么，只需将一致的命名约定应用于您的测试类，然后设置 Jenkins 作业，或运行 Maven 目标，执行相应的操作，例如：

```
**mvn test –Dtest=*Integration***

```

`Green Balls`插件包含两个测试类：`GreenBallFilterTest`和`GreenBallIntegrationTest`，它们展示了插件测试的两种不同方法—浏览它们的源代码应该有助于了解如何开发自己的测试。

`GreenBallFilterTest` 执行一些简单的模式匹配测试，以确保正确的图像已经就位：

![使用 Maven 运行测试](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00060.jpeg)

`GreenBallIntegrationTest`，如下截图所示，扩展了`HudsonTestCase`并使用`com.gargoylesoftware.htmlunit.WebResponse`来直接测试和与部署的 Web 组件进行交互，断言它们返回预期的结果：

![使用 Maven 运行测试](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00061.jpeg)

这个 Jenkins 页面提供了有用的资源，供进一步阅读，以满足更详细和复杂的测试场景：

[`wiki.jenkins-ci.org/display/JENKINS/Unit+Test`](https://wiki.jenkins-ci.org/display/JENKINS/Unit+Test)

此链接涵盖了模拟、HTML 抓取、提交表单、JavaScript 和网页断言等主题。

# 调试 Jenkins

本章的其余部分侧重于以多种不同的方式进行调试，以帮助进一步了解应用程序及其运行时行为。

主要关注于使用本地的 Jenkins 实例和 IDE 来调试开发会话；然而，了解 Jenkins 内置日志选项的可用选项仍然很有用，这些选项是复杂且高度可定制的。这些通常是解决任何问题的良好起点，因此我们将在继续开发自己的代码时，首先快速概述这些选项，然后再转向您可能想要设置和使用的调试类型。

## 服务器调试 – 快速回顾

Jenkins 使用`java.util.logging`包进行日志记录；有关详细信息，请参阅此处：

[`docs.oracle.com/javase/7/docs/api/java/util/logging/package-summary.html`](https://docs.oracle.com/javase/7/docs/api/java/util/logging/package-summary.html)

有关 Jenkins 日志记录的文档在此处可用：

[`wiki.jenkins-ci.org/display/JENKINS/Logging`](https://wiki.jenkins-ci.org/display/JENKINS/Logging)

本页面解释了如何设置自定义日志记录器—这对于分离和过滤所有日志输出以帮助查找感兴趣的内容非常有用，因为*所有*通常都被传送到默认日志中，这可能使分析变得困难。

可以使用用户界面在**管理 Jenkins** | **系统日志** | **所有 Jenkins 日志**中检查 Jenkins 系统日志，并且页面底部还有 RSS 订阅的链接可用：

![服务器调试 – 快速回顾](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00062.jpeg)

这些可以帮助识别和过滤系统中的不同类型的事件。

对于从节点的问题，可以在以下位置找到日志文件：`~/.jenkins/logs/slaves/{slavename}`。

对于作业问题，历史日志文件保存在`~/.jenkins/jobs/{jobname}/builds/{jobnumber}`。

您还可以通过在启动过程中添加额外的`-D`参数来以特定的日志记录级别启动 Jenkins：

```
-Djava.util.logging.loglevel={level}
```

在这里，`level`是以下之一：

+   `SEVERE（最高值）`

+   `WARNING`

+   `INFO`

+   `CONFIG`

+   `FINE`

+   `FINER`

+   `FINEST（最低值）`

`Off`和`All`级别也可用—请参阅此页面以获取更多详细信息和选项：

[`docs.oracle.com/javase/7/docs/api/java/util/logging/Level.html`](http://docs.oracle.com/javase/7/docs/api/java/util/logging/Level.html)

## 使用 IntelliJ 进行调试

要从 IntelliJ 中进行调试，请将 IntelliJ 指向项目的`pom.xml`文件，然后从运行菜单中选择选项来创建新的运行/调试配置。这应该会带您到一个类似于这样的屏幕：

![使用 IntelliJ 进行调试](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00063.jpeg)

IntelliJ 已经解析了 POM 文件，并且知道它包含的可用目标。一旦您开始输入，例如`hpi`，您将看到一个下拉列表，其中包含所有匹配的选项供您选择。

从下拉菜单中选择并运行所需的目标（在这种情况下再次是**hpi:run**），然后单击**Debug**。

您应该在控制台中看到熟悉的 Jenkins 启动过程，然后能够连接到本地调试会话：

`http://localhost:8080/jenkins`

在与之前更改“Hello World”文本的相同位置的代码中添加一个调试点（双击左边缘上写着**hello world…**的行，然后运行 Jenkins 作业）。这应该运行到您设置的断点并产生这个：

![使用 IntelliJ 进行调试](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00064.jpeg)

然后，您可以使用调试箭头和按钮来驱动调试过程：

![使用 IntelliJ 进行调试](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00065.jpeg)

这些允许您进入、跳过或退出当前的调试点，并且您应该能够检查列出的变量，以反映正在调试的应用程序的实时状态。

有关使用 IntelliJ 进行调试的更多信息，请参阅此链接：

[`www.jetbrains.com/idea/help/stepping-through-the-program.html`](https://www.jetbrains.com/idea/help/stepping-through-the-program.html)

## 使用 Eclipse 进行调试

使用 Eclipse 进行调试与之前描述的 IntelliJ 非常相似。

要设置断点，请在代码窗口的左侧边缘双击，就像这样：

![使用 Eclipse 进行调试](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00066.jpeg)

接下来，在 Eclipse 项目中右键单击 POM 文件，然后选择**Debug as…**，将出现以下窗口：

![使用 Eclipse 进行调试](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00067.jpeg)

指定`hpi:run`目标，然后单击**Debug**；Jenkins 应该像往常一样在 Eclipse 控制台窗口中启动。

与以前一样，将浏览器指向`http://localhost:8080/jenkins`，然后创建或运行一个触发您之前设置的断点的作业 - 当达到这个代码/点时，Jenkins 将冻结，焦点将切换到 Eclipse，在那里您可以检查当前变量和属性的状态，并浏览各种调试步骤，进一步深入问题或跳过区域以查看发生了什么变化。

## mvnDebug

`mvnDebug`工具提供了一个可能会对您感兴趣的替代方法。要使用此功能，请在命令行中运行`mvnDebug hpi:run`。

这应该启动 Maven 调试模式，并在本地主机的端口`8000`上启动监听器，就像这样：

![mvnDebug](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00068.jpeg)

现在切换到您的 IDE，并连接到这个端口的调试会话。例如，在 Eclipse 中，选择**Run** | **Debug Configurations…**

这应该产生以下窗口，您可以从中选择**Remote Java Application**。检查主机和端口是否匹配：

![mvnDebug](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00069.jpeg)

接下来，选择**Debug**连接到您在控制台中启动的`mvnDebug`会话。此时，`hpi:run`目标将在（控制台中）启动，并在 Maven 中以调试模式运行 Jenkins，同时连接到您选择的调试器，例如 Eclipse。

如果您检查`mvnDebug`可执行文件，您会发现它只是在运行普通的`mvn`二进制文件之前设置`MAVEN_DEBUG_OPTS`，如下所示：

```
MAVEN_DEBUG_OPTS="-Xdebug -Xrunjdwp:transport=dt_socket,server=y,suspend=y,address=8000"
echo Preparing to Execute Maven in Debug Mode
env MAVEN_OPTS="$MAVEN_OPTS $MAVEN_DEBUG_OPTS" $(dirname $0)/mvn "$@"
```

这表明，如果您愿意，可以很容易地指定不同的端口，或者您可以调整此脚本以添加您可能想要包含的任何其他参数或设置。

# Jenkins Logger 控制台

本章的最后一个主题是内置在 Jenkins 调试版本中的**Logger Console**。

当您通过 Maven 启动 Jenkins 的本地开发实例（无论是通过命令行还是 IDE），您会注意到屏幕左侧包含的额外**Logger Console**框：

![Jenkins Logger 控制台](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00070.jpeg)

展开此框将显示一个**实时**日志输出窗口，您可以实时自定义以调整和过滤您想要看到或隐藏的日志项目的类型和严重程度。

保持选择**info**会提供非常冗长的输出级别，其中包括有关鼠标悬停事件和其他 UI 交互的信息。在调试 UI 问题时，这些信息可能非常有用。

取消**info**框的勾选只留下**warn**和**error**消息。日志输出可以通过暂停和可选清除输出以及调整过滤器来满足您的需求。以下截图显示了**Logger Console**：

![Jenkins Logger Console](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/ext-jks/img/00071.jpeg)

# 总结

正如您所看到的，Jenkins 内部有大量的选项和方法可供测试和调试。本章介绍了一些您可能会发现对自己的开发流程有用的主要工具和方法。

了解如何测试和调试您的代码，并设置一个适合您需求和偏好的高效开发环境，应该会提高您自己开发的质量。当您考虑分发自己的插件并考虑替代开发选项时，这也应该会让事情变得更容易。我们将在下一章中看一些替代技术和语言。
