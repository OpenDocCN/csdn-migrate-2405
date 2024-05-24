# Jenkins 持续集成秘籍（一）

> 原文：[`zh.annas-archive.org/md5/B61AA47DB2DCCD9DEF9EF3E145A763A7`](https://zh.annas-archive.org/md5/B61AA47DB2DCCD9DEF9EF3E145A763A7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

Jenkins 是一个基于 Java 的持续集成（CI）服务器，支持在软件周期的早期发现缺陷。 由于插件数量迅速增长（目前超过 1,000 个），Jenkins 与许多类型的系统通信，构建和触发各种测试。

CI 涉及对软件进行小改动，然后构建和应用质量保证流程。 缺陷不仅出现在代码中，还出现在命名约定、文档、软件设计方式、构建脚本、将软件部署到服务器的过程等方面。 CI 迫使缺陷早日显现，而不是等待软件完全生产出来。 如果在软件开发生命周期的后期阶段发现了缺陷，那么处理过程将会更加昂贵。 一旦错误逃逸到生产环境中，修复成本将急剧增加。 估计捕捉缺陷的成本早期是后期的 100 到 1,000 倍。 有效地使用 CI 服务器，如 Jenkins，可能是享受假期和不得不加班英雄般拯救一天之间的区别。 而且你可以想象，在我作为一个有着对质量保证的渴望的高级开发人员的日常工作中，我喜欢漫长而乏味的日子，至少是对于关键的生产环境。

Jenkins 可以定期自动构建软件，并根据定义的标准触发测试，拉取结果并基于定义的标准失败。 通过构建失败早期降低成本，增加对所生产软件的信心，并有可能将主观流程转变为开发团队认为是公正的基于指标的进攻性流程。

Jenkins 不仅是一个 CI 服务器，它还是一个充满活力和高度活跃的社区。 开明的自我利益决定了参与。 有许多方法可以做到这一点：

+   参与邮件列表和 Twitter（[`wiki.jenkins-ci.org/display/JENKINS/Mailing+Lists`](https://wiki.jenkins-ci.org/display/JENKINS/Mailing+Lists)）。 首先，阅读帖子，随着你了解到需要什么，然后参与讨论。 持续阅读列表将带来许多合作机会。

+   改善代码并编写插件（[`wiki.jenkins-ci.org/display/JENKINS/Help+Wanted`](https://wiki.jenkins-ci.org/display/JENKINS/Help+Wanted)）。

+   测试 Jenkins，尤其是插件，并撰写 Bug 报告，捐赠你的测试计划。

+   通过编写教程和案例研究来改善文档。

# 这本书涵盖了什么内容

第一章，*维护 Jenkins*，描述了常见的维护任务，如备份和监视。 本章中的配方概述了适当维护的方法，进而降低了故障的风险。

第二章，*增强安全性*，详细介绍如何保护 Jenkins 的安全性以及启用单点登录（SSO）的价值。本章涵盖了许多细节，从为 Jenkins 设置基本安全性，部署企业基础设施（如目录服务）到部署自动测试 OWASP 十大安全性。

第三章，*构建软件*，审查了 Jenkins 与 Maven 构建的关系以及使用 Groovy 和 Ant 进行少量脚本编写。配方包括检查许可证违规、控制报告创建、运行 Groovy 脚本以及绘制替代度量。

第四章，*通过 Jenkins 进行沟通*，审查了针对不同目标受众（开发人员、项目经理以及更广泛的公众）的有效沟通策略。Jenkins 是一个有才华的沟通者，通过电子邮件、仪表板和谷歌服务的一大群插件通知您。它通过移动设备对您叫嚷，在您经过大屏幕时辐射信息，并通过 USB 海绵导弹发射器向您射击。

第五章，*利用度量改善质量*，探讨了源代码度量的使用。为了节省成本和提高质量，您需要尽早在软件生命周期中消除缺陷。Jenkins 测试自动化创建了一张度量的安全网。本章的配方将帮助您构建这个安全网。

第六章，*远程测试*，详细介绍了建立和运行远程压力测试和功能测试的方法。本章结束时，您将对 Web 应用程序和 Web 服务运行性能和功能测试。包括两种典型的设置方案。第一种是通过 Jenkins 将 WAR 文件部署到应用服务器。第二种是创建多个从节点，准备好将测试工作从主节点转移。

第七章，*探索插件*，有两个目的。第一个是展示一些有趣的插件。第二是审查插件的工作原理。

附录，*增进质量的流程*，讨论了本书中的配方如何支持质量流程，并指向其他相关资源。这将帮助您形成一个完整的图景，了解配方如何支持您的质量流程。

# 本书所需准备的内容

本书假设您已经在运行 Jenkins 实例。

要运行本书提供的配方，您需要以下软件：

**推荐：**

+   Maven 3 ([`maven.apache.org`](http://maven.apache.org))

+   Jenkins ([`jenkins-ci.org/`](http://jenkins-ci.org/))

+   Java 版本 1.8 ([`java.com/en/download/index.jsp`](http://java.com/en/download/index.jsp))

**可选的:**

+   VirtualBox ([`www.virtualbox.org/`](https://www.virtualbox.org/))

+   SoapUI ([`www.soapui.org`](http://www.soapui.org))

+   JMeter ([`jmeter.apache.org/`](http://jmeter.apache.org/))

**有帮助的:**

+   一个本地的 subversion 或 Git 仓库

+   首选的操作系统：Linux（Ubuntu）

    ### 注意

    请注意，您可以从 Jenkins GUI (`http://localhost:8080/configure`) 中安装不同版本的 Maven、Ant 和 Java。您不需要将这些作为操作系统的一部分安装。

安装 Jenkins 有许多方法：作为 Windows 服务安装，使用 Linux 的仓库管理功能（如`apt`和`yum`），使用 Java Web Start，或直接从 WAR 文件运行。您可以选择您感觉最舒适的方法。但是，您可以从 WAR 文件运行 Jenkins，使用命令行中的 HTTPS，指向自定义目录。如果任何实验出现问题，则可以简单地指向另一个目录并重新开始。

要使用此方法，首先将`JENKINS_HOME`环境变量设置为您希望 Jenkins 在其中运行的目录。接下来，运行类似以下命令的命令：

```
Java –jar jenkins.war –httpsPort=8443 –httpPort=-1

```

Jenkins 将开始在端口`8443`上通过 https 运行。通过设置`httpPort=-1`关闭 HTTP 端口，并且终端将显示日志信息。

您可以通过执行以下命令来请求帮助：

```
Java –jar jenkins.war –help

```

可以在[`wiki.jenkins-ci.org/display/JENKINS/Installing+Jenkins`](https://wiki.jenkins-ci.org/display/JENKINS/Installing+Jenkins)找到更广泛的安装说明。

对于在 VirtualBox 中使用 Jenkins 设置虚拟镜像的更高级菜谱描述，您可以使用第一章 *维护 Jenkins* 中的 *使用测试 Jenkins 实例* 菜谱。

# 这本书是为谁准备的

本书适用于 Java 开发人员、软件架构师、技术项目经理、构建管理器以及开发或 QA 工程师。预期具有对软件开发生命周期的基本理解，一些基本的 Web 开发知识以及对基本应用服务器概念的熟悉。还假定具有对 Jenkins 的基本理解。

# 节

在本书中，您会发现几个经常出现的标题（准备就绪，如何做，它是如何工作的，还有更多以及另请参见）。

为了清晰地说明如何完成一个菜谱，我们使用以下各节。

## 准备就绪

本节告诉您可以在菜谱中期待什么，并描述了为菜谱设置任何软件或任何预备设置所需的步骤。

## 如何做…

本节包含了遵循菜谱所需的步骤。

## 它是如何工作的…

本节通常包含了对前一节中发生的事情的详细解释。

## 还有…

本节包含有关菜谱的其他信息，以使读者更加了解菜谱。

## 另请参见

本节提供了其他有用信息的相关链接。

# 约定

在本书中，您将找到一些区分不同类型信息的文本样式。 以下是这些样式的一些示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟网址、用户输入和 Twitter 用户名显示如下："然后，特定于工作的配置将存储在子目录中的`config.xml`中。"

代码块设置如下：

```
<?xml version='1.0' encoding='UTF-8'?>
<org.jvnet.hudson.plugins.thinbackup.ThinBackupPluginImpl plugin="thinBackup@1.7.4">
<fullBackupSchedule>1 0 * *  7</fullBackupSchedule>
<diffBackupSchedule>1 1 * * *</diffBackupSchedule>
<backupPath>/data/jenkins/backups</backupPath>
<nrMaxStoredFull>61</nrMaxStoredFull>
<excludedFilesRegex></excludedFilesRegex>
<waitForIdle>false</waitForIdle>
<forceQuietModeTimeout>120</forceQuietModeTimeout>
<cleanupDiff>true</cleanupDiff>
<moveOldBackupsToZipFile>true</moveOldBackupsToZipFile>
<backupBuildResults>true</backupBuildResults>
<backupBuildArchive>true</backupBuildArchive>
<backupUserContents>true</backupUserContents>
<backupNextBuildNumber>true</backupNextBuildNumber>
<backupBuildsToKeepOnly>true</backupBuildsToKeepOnly>
</org.jvnet.hudson.plugins.thinbackup.ThinBackupPluginImpl>
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```
server {
  listen   80;
  server_name  localhost;
  access_log  /var/log/nginx/jenkins _8080_proxypass_access.log;
  error_log  /var/log/nginx/jenkins_8080_proxypass_access.log;
  location / {
    proxy_pass      http://127.0.0.1:7070/;
    include         /etc/nginx/proxy.conf;
  }
}
```

任何命令行输入或输出都将显示如下：

```
sudo apt-get install jenkins

```

**新术语**和**重要词汇**以粗体显示。 您在屏幕上看到的单词，例如菜单或对话框中的单词，将以此类似的形式显示在文本中：“单击**保存**。”

### 注意

警告或重要提示将显示在此框中。

### 提示

技巧和窍门会显示如此。

# 读者反馈

我们的读者反馈始终受欢迎。 请告诉我们您对本书的看法——您喜欢或不喜欢的方面。 读者反馈对我们非常重要，因为它帮助我们开发您真正会受益的标题。

要发送给我们一般反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在您的消息主题中提及书名。

如果您在某个主题上拥有专业知识，并且对编写或为书籍做贡献感兴趣，请参阅我们的作者指南，网址为 [www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您是 Packt 书籍的自豪拥有者，我们有一些东西可以帮助您充分利用您的购买。

## 下载示例代码

您可以从 [`www.packtpub.com`](http://www.packtpub.com) 的帐户中下载您购买的所有 Packt Publishing 书籍的示例代码文件。 如果您在其他地方购买了此书，您可以访问 [`www.packtpub.com/support`](http://www.packtpub.com/support) 并注册以直接通过电子邮件接收文件。

## 勘误

虽然我们已经尽了一切努力确保内容的准确性，但错误确实会发生。 如果您在我们的书中发现错误——可能是文本中的错误或代码中的错误——我们将不胜感激您向我们报告。 这样做可以帮助其他读者免受挫折，并帮助我们改进本书的后续版本。 如果您发现任何勘误，请访问 [`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书籍，单击**勘误提交表**链接，并输入您的勘误详情。 一旦验证您的勘误，您的提交将被接受，并且勘误将被上传到我们的网站或添加到该标题的错误部分下的任何现有勘误列表中。

要查看先前提交的勘误表，请访问 [`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support) 并在搜索框中输入书名。所需信息将出现在**勘误表**部分下。

## 盗版

盗版互联网上的受版权保护的材料是各种媒体持续面临的问题。在 Packt，我们非常重视对我们的版权和许可的保护。如果你在互联网上发现我们作品的任何形式的非法副本，请立即提供给我们位置地址或网站名称，以便我们采取措施解决。

请通过 `<copyright@packtpub.com>` 联系我们，并附上怀疑盗版材料的链接。

我们感谢您帮助保护我们的作者和我们为您提供有价值内容的能力。

## 问题

如果你对本书的任何方面有问题，可以通过 `<questions@packtpub.com>` 联系我们，我们将尽力解决问题。


# 第一章：维护 Jenkins

在本章中，我们将涵盖以下步骤:

+   使用测试 Jenkins 实例

+   备份和恢复

+   从命令行修改 Jenkins 配置

+   安装 Nginx

+   配置 Nginx 作为反向代理

+   报告总体存储使用情况

+   通过日志解析故意失败的构建

+   通过日志解析添加警告存储使用违规的作业

+   通过 Firefox 与 Jenkins 保持联系

+   通过 JavaMelody 进行监视

+   跟踪脚本粘合剂

+   编写 Jenkins 命令行界面脚本

+   使用 Groovy 全局修改作业

+   发出归档需求信号

# 介绍

Jenkins 功能丰富，通过插件可以大大扩展。Jenkins 与许多外部系统进行通信，其作业与许多不同的技术合作。在一个运行 24 x 7 的丰富环境中维护 Jenkins 是一个挑战。你必须注意细节。添加新作业很容易，而且你不太可能很快删除旧项目。负载增加，密码过期，存储填满。此外，Jenkins 及其插件的改进速度很快。每周都会发布一个新的 Jenkins 小版本，主要是改进，偶尔会有 bug。在复杂环境中保持系统稳定，你需要监视、清理存储、备份、控制你的 Jenkins 脚本，并始终保持清洁和抛光。本章包含最常见任务的步骤。正确的维护可以降低失败的风险，例如:

+   **新插件引发异常**: 有很多优秀的插件正在快速版本更改中编写。在这种情况下，你很容易意外添加带有新缺陷的插件新版本。在升级期间曾出现过插件突然不起作用的情况。为了防止插件异常的风险，在发布到关键系统之前考虑使用一个测试 Jenkins 实例。

+   **存储溢出的问题**: 如果你保留了包括 war 文件、大量的 JAR 文件或其他类型的二进制文件和源代码在内的构建历史记录，那么你的存储空间会以惊人的速度被消耗掉。存储成本已经大幅降低，但存储使用量意味着更长的备份时间和更多从从节点到主节点的通信。为了最小化磁盘溢出的风险，你需要考虑你的备份和恢复策略，以及作业高级选项中表达的相关构建保留策略。

+   **脚本混乱**: 由于作业由各个开发团队编写，所包含脚本的位置和风格各异。这使得你很难跟踪。考虑使用明确定义的脚本位置和通过插件管理的脚本仓库。

+   **资源耗尽**: 随着内存消耗或强烈作业数量增加，Jenkins 会变慢。正确的监控和快速反应会减少影响。

+   **由于有机增长而导致工作之间普遍缺乏一致性**：Jenkins 安装和使用都很简单。无缝开启插件的能力令人上瘾。Jenkins 在组织内的采用速度可能令人叹为观止。没有一致的政策，你的团队将引入大量插件，并且也会有很多执行相同工作方式的方式。规范提高了工作的一致性和可读性，从而减少了维护工作。

    ### 注意

    本章中的示例旨在解决提到的风险。它们只代表一套方法。如果您有意见或改进意见，请随时通过 `<bergsmooth@gmail.com>` 联系我，或者最好是向 Jenkins 社区维基添加教程。

Jenkins 社区正在为您努力工作。Jenkins 每周都有小版本发布，并且许多插件偶尔都会有增量改进，因为变化的速度，会引入错误。如果您发现问题，请报告。

### 提示

**加入社区**

要添加社区错误报告或修改维基页面，您需要在 [`wiki.jenkins-ci.org/display/JENKINS/Issue+Tracking`](https://wiki.jenkins-ci.org/display/JENKINS/Issue+Tracking) 创建一个帐户。

# 使用测试 Jenkins 实例

**持续集成**（**CI**）服务器在创建确定性发布周期方面至关重要。如果 CI 存在长期不稳定性，那么在项目计划中达到里程碑的速度将会减慢。增量升级令人上瘾并且大多数情况下很简单，但应该以 Jenkins 的关键角色——软件项目的生命周期为依据来看待。

在将插件发布到您的 Jenkins 生产服务器之前，值得积极部署到一个测试 Jenkins 实例，然后坐下来让系统运行作业。这样可以给你足够的时间来对发现的任何轻微缺陷做出反应。

设置测试实例的方法有很多种。其中一种是使用 Ubuntu 的虚拟图像，并与 *主机* 服务器（虚拟机运行的服务器）共享工作区。这种方法有很多优点：

+   **保存状态**：您可以随时保存运行中虚拟图像的状态，并在以后返回到该运行状态。这对于有高风险失败的短期实验非常有用。

+   **共享图像的能力**：您可以在任何可以运行播放器的地方运行虚拟图像。这可能包括您的家庭桌面或一个高级服务器。

+   **使用多种不同操作系统**：这对运行具有多种浏览器类型的集成测试或功能测试的节点机器非常有用。

+   **交换工作区**：通过将工作区放在虚拟服务器主机外部，您可以测试不同版本级别的操作系统与一个工作区。您还可以测试 Jenkins 的一个版本与具有不同插件组合的不同主机工作区。

    ### 提示

    **长期支持版本**

    社区通过使用长期支持版本的 Jenkins 来管理核心稳定性，这个版本相对于最新版本来说更加成熟，功能较少。然而，它被认为是升级最稳定的平台（[`mirrors.jenkins-ci.org/war-stable/latest/jenkins.war`](http://mirrors.jenkins-ci.org/war-stable/latest/jenkins.war)）。

测试实例通常比接受和生产系统的规格低。通过让测试实例处于饥饿状态，你可以及早暴露出某些类型的问题，比如内存泄漏。随着你将配置移到生产环境，你希望扩大容量，这可能涉及从虚拟机移动到硬件。

这个教程详细介绍了如何使用 VirtualBox（[`www.virtualbox.org/`](http://www.virtualbox.org/)），这是一个开源的虚拟图像播放器，带有一个 Ubuntu 镜像（[`www.ubuntu.com/`](http://www.ubuntu.com/)）。虚拟图像将挂载主机服务器上的一个目录。然后你将 Jenkins 指向挂载的目录。当客户端操作系统重新启动时，Jenkins 将自动运行并对共享目录进行操作。

### 注意

在整本书中，将使用 Ubuntu 作为示例操作系统引用各个案例。

## 准备就绪

你需要下载并安装 VirtualBox。你可以在[`www.virtualbox.org/manual/UserManual.html`](https://www.virtualbox.org/manual/UserManual.html)找到下载最新版本 VirtualBox 的详细说明。在撰写本书时，从 VirtualBox 镜像 SourceForge 网站下载的最新版本是 Ubuntu 11.04。解压缩 Ubuntu 11.04 虚拟图像文件从[`sourceforge.net/projects/virtualboximage/files/Ubuntu%20Linux/11.04/ubuntu_11.04-x86.7z/download`](http://sourceforge.net/projects/virtualboximage/files/Ubuntu%20Linux/11.04/ubuntu_11.04-x86.7z/download)。

如果遇到问题，手册是一个很好的起点；特别是，请参考*第十二章*，*故障排除*，网址为[`www.virtualbox.org/manual/ch12.html`](http://www.virtualbox.org/manual/ch12.html)。

请注意，在阅读时可能会有更新的图像可用。随时尝试最新版本；很可能这个教程仍然适用。

你会在[`virtualboxes.org/images/ubuntu-server/`](http://virtualboxes.org/images/ubuntu-server/)找到一系列最新的 Ubuntu 虚拟图像。

### 提示

**安全注意事项**

如果你考虑使用他人的操作系统镜像，这是一个不良的安全实践，那么你应该按照[`wiki.ubuntu.com/Testing/VirtualBox`](https://wiki.ubuntu.com/Testing/VirtualBox)中提到的方法从引导光盘创建一个 Ubuntu 镜像。

## 如何操作...

1.  运行 VirtualBox 并点击左上角的**新建**图标。现在你会看到一个用于安装虚拟图像的向导。

1.  将**名称**设置为`Jenkins_Ubuntu_11.04`。操作系统类型将自动更新。点击**下一步**按钮。

1.  将**内存**设置为**2048 MB**，然后点击**下一步**。

    请注意，主机机器需要比其分配给客户镜像的总内存多 1GB RAM。在本例中，你的主机机器需要 3GB RAM。欲了解更多详情，请访问[`www.oracle.com/us/technologies/virtualization/oraclevm/oracle-vm-virtualbox-ds-1655169.pdf`](http://www.oracle.com/us/technologies/virtualization/oraclevm/oracle-vm-virtualbox-ds-1655169.pdf)。

1.  选择**使用现有硬盘**。单击文件夹图标浏览并选择未打包的 VDI 镜像：![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_01.jpg)

1.  按下**创建**按钮。

1.  点击**启动**图标启动虚拟镜像：![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_02.jpg)

1.  使用用户名和密码`Ubuntu reverse`登录客户操作系统。

1.  从终端更改 Ubuntu 用户的密码如下：

    ```
    sudo passwd

    ```

1.  按照[`pkg.jenkins-ci.org/debian/`](http://pkg.jenkins-ci.org/debian/)中的说明安装 Jenkins 存储库。

1.  根据安全补丁更新操作系统（这可能需要一些时间取决于带宽）：

    ```
    sudo apt-get update
    sudo apt-get upgrade

    ```

1.  安装内核的`dkms`模块：

    ```
    sudo apt-get install dkms

    ```

    注意，`dkms`模块支持安装其他内核模块，例如 VirtualBox 所需的模块。欲了解更多详情，请访问[`help.ubuntu.com/community/DKMS`](https://help.ubuntu.com/community/DKMS)。

1.  安装 Jenkins：

    ```
    sudo apt-get install jenkins

    ```

1.  安装 VirtualBox 的内核模块：

    ```
    sudo /etc/init.d/vboxadd setup

    ```

1.  使用 VirtualBox 窗口中的**设备**菜单选项安装客户附件：![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_03.jpg)

1.  将`jenkins`用户添加到`vboxsf`组，如下所示：

    ```
    sudo gedit /etc/group
    vboxsf:x:1001:Jenkins

    ```

1.  修改`/etc/default/jenkins`中的`JENKINS_HOME`变量，以指向挂载的共享目录：

    ```
    sudo gedit /etc/default/jenkins
    JENKINS_HOME=/media/sf_workspacej

    ```

1.  在主机操作系统上创建名为`workspacej`的目录。

1.  在 VirtualBox 中，右键单击 Ubuntu 镜像并选择**设置**。

1.  将**文件夹路径**字段更新为指向您之前创建的目录。在下面的截屏中，你可以看到该文件夹是在我的`home`目录下创建的：![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_04.jpg)

1.  重新启动 VirtualBox，然后启动 Ubuntu 客户操作系统。

1.  在客户操作系统上运行 Firefox 并浏览`http://localhost:8080`。你将看到一个本地运行的 Jenkins 实例，准备用于实验。

## 它是如何工作的...

首先，你安装了一个 Ubuntu 的虚拟镜像，更改了密码，使其他人更难登录，并更新了客户操作系统的安全补丁。

Jenkins 存储库已添加到客户操作系统中已知存储库的列表。这涉及在本地安装存储库密钥。该密钥用于验证自动下载的软件包属于您同意信任的存储库。一旦信任启用，您可以通过标准软件包管理安装最新版本的 Jenkins，并随后积极更新。

您需要安装一些额外的代码，称为客户端附加组件，以便 VirtualBox 可以从主机共享文件夹。客户端附加组件依赖于**动态内核模块支持**（**DKMS**）。DKMS 允许将代码的部分动态添加到内核中。当您运行`/etc/init.d/vboxadd setup`命令时，VirtualBox 通过 DKMS 添加了客户端附加组件模块。

### 注意

**警告**：如果您忘记添加 DKMS 模块，则共享文件夹将在没有显示任何错误的情况下失败。

默认的 Jenkins 实例现在需要进行一些重新配置：

+   `jenkins`用户需要属于`vboxsf`组，以便具有使用共享文件夹的权限

+   `/etc/init.d/jenkins 启动`脚本指向`/etc/default/jenkins`，从而获取特定属性的值，如`JENKINS_HOME`

接下来，您可以通过 VirtualBox GUI 向宿主操作系统添加共享文件夹，最后重新启动 VirtualBox 和宿主操作系统，以确保系统处于完全配置和正确初始化的状态。

配置 VirtualBox 网络有许多选项。您可以在[`www.virtualbox.org/manual/ch06.html`](http://www.virtualbox.org/manual/ch06.html)找到一个很好的介绍。

## 参见

+   *通过 JavaMelody 进行监控*的方法

+   在[`virtualboximages.com/`](http://virtualboximages.com/)和[`virtualboxes.org/images/`](http://virtualboxes.org/images/)有两个优秀的虚拟镜像来源

# 备份和恢复

对于 Jenkins 的顺利运行来说，一个核心任务是定期备份其主目录（在 Ubuntu 中为`/var/lib/jenkins`），不一定是所有的工件，但至少是其配置以及插件需要生成报告的测试历史记录。

备份没有意义，除非您可以还原。关于此主题有很多故事。我最喜欢的（我不会提及涉及的著名公司）是在 70 年代初期的某个地方，一家公司购买了一台非常昂贵的软件和磁带备份设备，以备份通过他们的主机收集的所有营销结果。然而，并非所有事情都是自动化的。每晚都需要将一盘磁带移入特定插槽。一个工人被分配了这项任务。一年来，工人专业地完成了这项任务。有一天发生了故障，需要备份。备份无法还原。原因是工人每晚还需要按下录制按钮，但这不是分配给他的任务的一部分。没有定期测试还原过程。失败的是过程，而不是薪水微薄的人。因此，吸取历史教训，本配方描述了备份和还原。

目前，备份有多个插件可用。我选择了 thinBackup 插件（[`wiki.jenkins-ci.org/display/JENKINS/thinBackup`](https://wiki.jenkins-ci.org/display/JENKINS/thinBackup)），因为它允许调度。

### 提示

**插件的快速演进和配方的有效性**

插件更新频繁，可能每周都需要更新。然而，核心配置改变的可能性不大，但增加额外选项的可能性很大，这会增加你在 GUI 中输入的变量。因此，本书中显示的截图可能与最新版本略有不同，但配方应该保持不变。

## 准备工作

为 Jenkins 创建一个具有读写权限的目录并安装 thinBackup 插件。

### 小贴士

**把墨菲当朋友**

你应该假设本书中的所有配方情况最糟糕：外星人攻击、咖啡泼在主板上、猫吃电缆、电缆吃猫等等。确保你正在使用一个测试 Jenkins 实例。

## 操作步骤...

1.  在**管理 Jenkins**页面点击**ThinBackup**链接：![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_32.jpg)

1.  点击**工具集**图标旁边的**设置**链接。

1.  按照以下截图中显示的细节添加，其中`/data/jenkins/backups`是你之前创建的目录的占位符。注意关于使用`H`语法的警告；这将在稍后解释。![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_05.jpg)

1.  点击**保存**。

1.  然后，点击**立即备份**图标。

1.  从命令行访问你的备份目录。现在你应该看到一个名为`FULL-{timestamp}`的额外子目录，其中`{timestamp}`是创建完整备份所需的秒数。

1.  点击**还原**图标。

1.  将显示一个名为**从备份还原**的下拉菜单，其中显示了备份的日期。选择刚刚创建的备份，然后点击**还原**按钮：![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_06.jpg)

1.  为了保证一致性，重新启动 Jenkins 服务器。

## 工作原理...

备份调度程序使用 cron 表示法（[`en.wikipedia.org/wiki/Cron`](http://en.wikipedia.org/wiki/Cron)）。`1 0 * * 7`表示每周的第七天在凌晨 00:01。`1 1 * * *`意味着差异备份每天只发生一次，在凌晨 1:01。每隔七天，前一次的差异备份将被删除。

还记得配置时的警告吗？将时间符号替换为`H`允许 Jenkins 选择何时运行 thinBackup 插件。`H H * * *`将在一天中的随机时间触发作业，从而分散负载。

等待 Jenkins/Hudson 空闲以执行备份是一种安全方法，并帮助 Jenkins 分散负载。建议启用此选项；否则，由于构建锁定文件，备份可能会损坏。

在指定的分钟数后强制 Jenkins 进入安静模式，确保在备份时没有作业在运行。此选项在等待 Jenkins 在特定时间内保持安静后强制进入安静模式。这可以避免备份等待 Jenkins 自然达到安静时刻时出现问题。

差异备份仅包含自上次完整备份以来已修改的文件。插件查看最后修改日期以确定需要备份的文件。如果另一个进程更改了最后修改日期但实际上没有更改文件内容，该过程有时可能会出错。

**61** 是使用备份创建的目录数。由于我们通过 **清理差异备份** 选项清理差异，因此在清理最旧的备份之前，我们将达到大约 54 个完整备份，大约一年的存档。

我们选择了备份构建结果，因为我们假设我们是在作业内进行清理。完整存档中不会有太多额外的内容添加。但是，如果配置错误，你应该监视存档的存储使用情况。

清理差异备份可以避免手动进行清理工作。将旧备份移到 ZIP 文件中可以节省空间，但可能会暂时减慢 Jenkins 服务器的速度。

### 注意

为了安全起见，定期将存档复制到系统之外。

名为**备份构建存档**、**备份 'userContent' 文件夹**和**备份下一个构建编号文件**的备份选项会增加备份的内容和系统状态。

恢复是返回到恢复菜单并选择日期的问题。额外选项包括恢复构建编号文件和插件（从外部服务器下载以减小备份大小）。

### 注意

我再次强调，你应该定期进行恢复操作，以避免尴尬。

全面备份是最安全的，因为它们会恢复到一个已知的状态。因此，在完整备份之间不要生成太多差异备份。

## 这还没完呢…

还有几点给你思考。

### 检查权限错误

如果有权限问题，插件将悄无声息地失败。要发现这些问题，你需要检查 Jenkins 的日志文件，`/var/log/jenkins/jenkins.log（适用于 *NIX 发行版）`，查看日志级别为 `SEVERE` 的日志：

```
SEVERE: Cannot perform a backup. Please be sure jenkins/hudson has write privileges in the configured backup path {0}.

```

### 测试排除模式

下面的 Perl 脚本将允许你测试排除模式。只需将 `$content` 值替换为你的 Jenkins 工作区位置，将 `$exclude_pattern` 替换为你要测试的模式。以下脚本将打印排除的文件列表：

```
#!/usr/bin/perl
use File::Find;
my $content = "/var/lib/jenkins";
my $exclude_pattern = '^.*\.(war)|(class)|(jar)$';
find( \&excluded_file_summary, $content );
subexcluded_file_summary {
  if ((-f $File::Find::name)&&( $File::Find::name =~/$exclude_pattern/)){
print "$File::Find::name\n";
  }
}
```

### 小贴士

**下载示例代码**

你可以从你在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载所有你购买的 Packt Publishing 书籍的示例代码文件。如果你在其他地方购买了这本书，你可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)注册，以便直接通过电子邮件接收文件。

你可以在[`perldoc.perl.org/File/Find.html`](http://perldoc.perl.org/File/Find.html)找到标准 Perl 模块 `File::Find` 的文档。

对于 `$content` 提及的每个文件和目录，`find(\&excluded_file_summary,$content);` 行调用 `excluded_file_summary` 函数。

排除模式`'^.*\.(war)|(class)|(jar)$`忽略所有的 WAR、class 和 JAR 文件。

### 提示

**EPIC Perl**

如果你是一名偶尔编写 Perl 脚本的 Java 开发人员，请考虑在 Eclipse 中使用 EPIC 插件（[`www.epic-ide.org/`](http://www.epic-ide.org/)）。

## 另请参阅

+   *报告整体存储使用*示例

+   *添加一个通过日志解析警告存储使用违规的作业*示例

# 从命令行修改 Jenkins 配置

你可能会想知道 Jenkins 工作空间顶层的 XML 文件。这些是配置文件。`config.xml` 文件是处理默认服务器值的主要文件，但也有特定的文件用于通过 GUI 设置任何插件的值。

工作空间下还有一个`jobs`子目录。每个单独的作业配置都包含在与作业同名的子目录中。然后，作业特定的配置存储在子目录中的`config.xml`中。对于`users`目录也是类似的情况：每个用户一个子目录，其中个人信息存储在`config.xml`中。

在所有基础设施中的 Jenkins 服务器具有相同的插件和版本级别的受控情况下，您可以在一个测试机器上进行测试，然后将配置文件推送到所有其他机器上。然后，你可以使用**命令行界面**（**CLI**）或`/etc/init.d`下的脚本重启 Jenkins 服务器，如下所示：

```
sudo /etc/init.d/jenkins restart

```

此示例使你熟悉主要的 XML 配置结构，然后根据 XML 的详细信息提供有关插件 API 的提示。

## 准备工作

你需要一个启用了安全性并且能够通过登录并通过命令行或通过文本编辑器进行编辑的能力来编辑文件的 Jenkins 服务器。

## 如何操作...

1.  在 Jenkins 的顶层目录中，寻找`config.xml`文件。编辑带有`numExecutors`的行，将数字`2`改为`3`：

    ```
    <numExecutors>3</numExecutors>
    ```

1.  重新启动服务器。你会看到执行器的数量已从默认的两个增加到三个：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_07.jpg)

1.  插件通过 XML 文件持久保存其配置。为了证明这一点，请查找`thinBackup.xml`文件。除非你已安装 thinBackup 插件，否则你找不到它。

1.  再次查看*备份和恢复*的示例。现在你会找到以下 XML 文件：

    ```
    <?xml version='1.0' encoding='UTF-8'?>
    <org.jvnet.hudson.plugins.thinbackup.ThinBackupPluginImpl plugin="thinBackup@1.7.4">
    <fullBackupSchedule>1 0 * *  7</fullBackupSchedule>
    <diffBackupSchedule>1 1 * * *</diffBackupSchedule>
    <backupPath>/data/jenkins/backups</backupPath>
    <nrMaxStoredFull>61</nrMaxStoredFull>
    <excludedFilesRegex></excludedFilesRegex>
    <waitForIdle>false</waitForIdle>
    <forceQuietModeTimeout>120</forceQuietModeTimeout>
    <cleanupDiff>true</cleanupDiff>
    <moveOldBackupsToZipFile>true</moveOldBackupsToZipFile>
    <backupBuildResults>true</backupBuildResults>
    <backupBuildArchive>true</backupBuildArchive>
    <backupUserContents>true</backupUserContents>
    <backupNextBuildNumber>true</backupNextBuildNumber>
    <backupBuildsToKeepOnly>true</backupBuildsToKeepOnly>
    </org.jvnet.hudson.plugins.thinbackup.ThinBackupPluginImpl>
    ```

## 工作原理...

Jenkins 使用 XStream ([`xstream.codehaus.org/`](http://xstream.codehaus.org/)) 将其配置持久化为可读的 XML 格式。工作空间中的 XML 文件是插件、任务和各种其他持久化信息的配置文件。`config.xml` 文件是主配置文件。安全设置和全局配置在这里设置，并反映通过 GUI 进行的更改。插件使用相同的结构，XML 值对应于底层插件类中的成员值。GUI 本身是通过 Jelly 框架 ([`commons.apache.org/jelly/`](http://commons.apache.org/jelly/)) 从 XML 创建的。

通过重新启动服务器，您可以确保在初始化阶段捕获到任何配置更改。

### 注意

还可以从**管理 Jenkins**页面的存储功能中使用**重新加载配置**，在不重新启动的情况下加载更新的配置。

## 还有更多...

这里有几件事情供你考虑。

### 关闭安全性

当您测试新的安全功能时，很容易将自己锁在 Jenkins 外面。您将无法再次登录。要解决此问题，通过编辑 `config.xml` 将 `useSecurity` 修改为 `false`，然后重新启动 Jenkins；现在安全功能已关闭。

### 查找自定义插件扩展的 JavaDoc

下面的代码行是名为 `thinBackup.xml` 的薄插件配置文件的第一行，提到了信息持久化的类。类名是一个很好的 Google 搜索词。插件可以扩展 Jenkins 的功能，可能会为管理 Groovy 脚本公开有用的方法：

```
<org.jvnet.hudson.plugins.thinbackup.ThinBackupPluginImpl>
```

### 添加垃圾的效果

只要它们被识别为有效的 XML 片段，Jenkins 就能很好地识别无效配置。例如，将以下代码添加到 `config.xml` 中：

```
<garbage>yeuchblllllllaaaaaa</garbage>
```

当您重新加载配置时，您将在**管理 Jenkins**屏幕的顶部看到这个：

![添加垃圾的效果](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_08.jpg)

按下**管理**按钮将返回到详细的调试信息页面，其中包括调和数据的机会：

![添加垃圾的效果](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_09.jpg)

从中可以看出，Jenkins 在阅读不理解的损坏配置时是开发人员友好的。

## 另见

+   *使用测试 Jenkins 实例* 配方

# 安装 Nginx

此配方描述了安装基本 Nginx 安装所需的步骤。

Nginx（发音为 *engine-x*）是一个免费的、开源的、高性能的 HTTP 服务器和反向代理，以及 IMAP/POP3 代理服务器。Igor Sysoev 在 2002 年开始开发 Nginx，在 2004 年发布了第一个公开版本。Nginx 以其高性能、稳定性、丰富的功能集、简单的配置和低资源消耗而闻名。

### 注意

您可以在 [`wiki.nginx.org/Main`](http://wiki.nginx.org/Main) 找到 Nginx 社区的 wiki 站点。

在你的 Jenkins 服务器前面放置一个 Nginx 服务器有很多优点：

+   **简单配置**: 语法简单直观。配置新服务器的基本细节只需要几行易于阅读的文本。

+   **速度和资源消耗**: Nginx 以比竞争对手更快的速度运行，并且资源消耗更少。

+   **URL 重写**: 强大的配置选项允许你直接管理 Nginx 后面的多个服务器的 URL 命名空间。

+   **抵消 SSL**: Nginx 可以负责安全连接，减少组织中所需的证书数量，并降低 Jenkins 服务器的 CPU 负载。

+   **缓存**: Nginx 可以缓存 Jenkins 的大部分内容，减少 Jenkins 服务器必须返回的请求数量。

+   **监控**: 当 Nginx 部署在多个 Jenkins 服务器前时，其集中日志文件可以作为一个明确的监控点。

## 准备工作

阅读官方安装说明：[`wiki.nginx.org/Install`](http://wiki.nginx.org/Install)。

## 如何操作...

1.  从终端输入：

    ```
    sudo apt-get install nginx

    ```

1.  浏览至本地主机位置。现在你将看到 Nginx 的欢迎页面：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_10.jpg)

1.  从终端输入 `sudo /etc/init.d/nginx`，你将获得以下输出：

    ```
    Usage: nginx {start|stop|restart|reload|force-reload|status|configtest|rotate|upgrade}

    ```

    请注意，你不仅可以停止和启动服务器，还可以检查状态并运行配置测试。

1.  通过输入 `sudo /etc/init.d/nginx status` 命令检查服务器状态：

    ```
    * nginx is running

    ```

1.  在 gedit 中编辑欢迎页面：

    ```
    sudo gedit /usr/share/nginx/html/index.html.

    ```

1.  在 `<body>` 标签后，添加 `<h1>Welcome to nginx working with Jenkins</h1>`。

1.  保存文件。

1.  浏览至本地主机位置。你将看到一个修改过的欢迎页面：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_11.jpg)

1.  查看 `/etc/nginx/nginx.conf` 配置文件，特别是以下几行：

    ```
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    ```

1.  编辑并保存 `/etc/nginx/sites-available/default`。对于两个 `listen` 部分，将数字 `80` 改为 `8000`：

    ```
    listen 8000 default_server;
    listen [::]:8000 default_server ipv6only=on;
    ```

    如果端口 `8000` 已被另一个服务器使用，则可以随意更改为其他端口号。

1.  通过终端运行以下命令测试配置：

    ```
    sudo /etc/init.d/nginx configtest
    * Testing nginx configuration   [ OK ]

    ```

1.  从终端重新启动服务器：

    ```
    sudo /etc/init.d/nginx restart
    * Restarting nginx nginx

    ```

1.  浏览至本地主机位置。你将看到无法连接的警告：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_12.jpg)

1.  浏览至 `localhost:8000`，你将看到欢迎页面。

## 工作原理...

你使用 `apt` 命令以默认设置安装了 Nginx。 `/etc/init.d/nginx` 命令用于控制服务器。你编辑了欢迎页面，位于 `/usr/share/nginx/html/index.html`，并重新启动了 Nginx。

主配置文件是 `/etc/nginx/nginx.conf`。 `include /etc/nginx/conf.d/*.conf;` 行从 `/etc/nginx/conf.d` 目录中具有 `conf` 扩展名的任何文件收集配置设置。它还通过 `include /etc/nginx/sites-enabled/*;` 命令收集 `/etc/nginx/sites-enabled` 目录中的任何配置文件。

您通过在名为`/etc/nginx/sites-available/default`的默认配置文件中使用`listen`指令更改了 Nginx 服务器监听的端口号。为了避免尴尬，我们在部署更改之前测试了配置。您可以通过终端使用`/etc/init.d/nginx configtest`命令来执行此操作。

### 提示

**支持信息**

*Nginx HTTP 服务器*由*Packt Publishing*出版的书籍详细介绍了 Nginx 的许多方面。您可以在[`www.packtpub.com/nginx-http-server-for-web-applications/book`](https://www.packtpub.com/nginx-http-server-for-web-applications/book)找到此书。

关于配置的示例章节可在线获取，网址为[`www.packtpub.com/sites/default/files/0868-chapter-3-basic-nginx-configuration_1.pdf`](http://www.packtpub.com/sites/default/files/0868-chapter-3-basic-nginx-configuration_1.pdf)。

## 更多内容……

这里还有一些您需要考虑的要点。

### 命名日志文件

Nginx 允许您在多个端口上运行多个虚拟主机。为了帮助您维护服务器，建议您将日志文件分开。为此，您需要更改`/etc/nginx/nginx.conf`中的以下行：

```
access_log /var/log/nginx/access.log;
error_log /var/log/nginx/error.log;
```

为他人提供方便。考虑使用一致的命名约定，例如包括主机名和端口号：

```
access_log /var/log/nginx/HOST_PORT_access.log;
error_log /var/log/nginx/HOST_PORT_error.log;
```

### 备份配置

我再次强调一下这一点。备份配置更改对于您的基础设施的平稳运行至关重要。就个人而言，我将所有配置更改备份到版本控制系统中。我可以查看提交日志，准确地了解何时犯了错误或使用了巧妙的调整。但是，版本控制并不总是可行的，因为可能包含诸如密码之类的敏感信息。至少要在本地自动备份配置。

## 另请参阅

+   *将 Nginx 配置为反向代理*配方

# 配置 Nginx 为反向代理

本文介绍如何将 Nginx 配置为 Jenkins 的反向代理。您将修改日志文件和端口位置，调整缓冲区大小和传递的请求标头。我还会介绍在重新启动 Nginx 之前测试配置的最佳实践。这种最佳实践帮助我避免了许多尴尬的时刻。

## 准备工作

您需要遵循*安装 Nginx*配方，并在`localhost:8080`上运行 Jenkins 实例。

## 如何做……

1.  创建`/etc/nginx/proxy.conf`文件，并添加以下代码：

    ```
    proxy_redirect          off;
    proxy_set_header        Host            $host;
    proxy_set_header        X-Real-IP       $remote_addr;
    proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
    client_max_body_size    10m;
    client_body_buffer_size 128k;
    proxy_connect_timeout   90;
    proxy_send_timeout      90;
    proxy_read_timeout      90;
    proxy_buffers           32 4k;
    ```

1.  创建`/etc/nginx/sites-enabled/jenkins_8080_proxypass`文件，并添加以下代码：

    ```
    server {
    listen   80;
    server_name  localhost;
    access_log  /var/log/nginx/jenkins _8080_proxypass_access.log;
    error_log  /var/log/nginx/jenkins_8080_proxypass_access.log;

    location / {
    proxy_pass      http://127.0.0.1:7070/;
    include         /etc/nginx/proxy.conf;
            }
    }
    ```

1.  从终端运行`sudo /etc/init.d/nginx configtest`。您将看到以下输出：

    ```
    * Testing nginx configuration   [ OK ]

    ```

1.  在终端中，通过运行以下命令重新启动服务器：

    ```
    sudo /etc/init.d/nginx restart

    ```

1.  浏览至本地主机位置。连接将超时，如下面的截图所示：![如何做……](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_13.jpg)

1.  查看访问日志 `/var/log/nginx/jenkins _8080_proxypass_access.log`。您将看到类似于以下行的行（请注意，`499` 是状态码）：

    ```
    127.0.0.1 - - [25/Jun/2014:17:50:50 +0200] "GET / HTTP/1.1" 499 0 "-" "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:30.0) Gecko/20100101 Firefox/30.0"

    ```

1.  编辑 `/etc/nginx/sites-enabled/jenkins_8080_proxypass`，将 `7070` 更改为 `8080`：

    ```
    location / {
    proxy_pass      http://127.0.0.1:8080/;
    include         /etc/nginx/proxy.conf;
            }
    ```

1.  测试配置更改：

    ```
    sudo /etc/init.d/nginx configtest
    * Testing nginx configuration   [ OK ]

    ```

1.  从终端运行以下命令重新启动 Nginx 服务器：

    ```
    sudo /etc/init.d/nginx restart

    ```

1.  浏览到本地主机位置。您将看到 Jenkins 的主页面。

## 工作原理...

Nginx 配置语法的致敬之处在于您只需配置几行即可配置 Nginx。

默认情况下，Nginx 对 `/etc/nginx/sites-enabled/` 目录中的文件中的任何配置都会起作用。在本次操作中，您向该目录添加了一个文件；然后，它被添加到 Nginx 的配置设置中，并在下次重启时生效。

配置文件包含一个带有端口和服务器名称 `localhost` 的 `server` 块。您可以在配置中定义多个服务器，它们监听不同的端口并具有不同的服务器名称。但是，在我们的情况下，我们只需要一个服务器：

```
server {
listen   80;
server_name  localhost;
```

您还定义了日志文件的位置，如下所示：

```
access_log  /var/log/nginx/Jenkins_8080_proxypass_access.log;
error_log  /var/log/nginx/jenkins_8080_proxypass_access.log;
```

Nginx 将请求头中指定的 URI 与服务器块内定义的位置指令的参数进行比较。在本例中，您只有一个指向顶级 `/` 的位置命令：

```
location / {
```

可以配置多个位置。但是，在我们的示例中，只有一个位置将所有请求传递给位于 `127.0.0.1:8080` 的 Jenkins 服务器：

```
  proxy_pass      http://127.0.0.1:8080/;
```

如上所述，当 `proxy_pass` 指向不存在的位置时，将返回 `499` HTTP 状态码。这是 Nginx 特定的标记问题的方式。

### 注意

注意，`proxy_pass` 可以同时使用 HTTP 和 HTTPS 协议。

我们加载了第二个配置文件，该文件处理了代理的详细设置。这是有用的，因为您可以在许多服务器配置中重复相同的设置，使详细信息保持集中。这种方法有助于可读性和维护。

```
include         /etc/nginx/proxy.conf;
```

### 注意

Nginx 配置允许您使用嵌入变量，如 `$remote_addr` 客户端的远程地址。Nginx 参考手册详细介绍了嵌入变量。您可以在 [`nginx.com/wp-content/uploads/2014/03/nginx-modules-reference-r3.pdf`](http://nginx.com/wp-content/uploads/2014/03/nginx-modules-reference-r3.pdf) 找到该手册。

在 `proxy.conf` 中，您设置了头信息。您将 `X-REAL-IP` 和 `X-Forwarded-For` 设置为请求者的远程地址。对于后端服务器和负载均衡器的顺利运行，您需要这两个头信息：

```
proxy_set_header        X-Real-IP       $remote_addr;
proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
```

### 注意

欲了解更多关于 `X-Forwarded-For` 的信息，请访问 [`en.wikipedia.org/wiki/X-Forwarded-For`](http://en.wikipedia.org/wiki/X-Forwarded-For)。

您还定义了性能相关的其他细节，包括客户端主体的最大大小（10 兆字节）、超时值（90 秒）和内部缓冲区大小（324 千字节）：

```
client_max_body_size    10m;
client_body_buffer_size 128k;
proxy_connect_timeout   90;
proxy_send_timeout      90;
proxy_read_timeout      90;
proxy_buffers           32 4k;
```

### 注意

有关 Nginx 作为反向代理服务器的更多信息，请访问 [`nginx.com/resources/admin-guide/reverse-proxy/`](http://nginx.com/resources/admin-guide/reverse-proxy/)。

## 还有更多……

这里还有一些你需要考虑的要点。

### 测试复杂配置

现代计算机价格便宜而且功能强大。它们能够支持多个测试 Jenkins 和 Nginx 服务器。测试复杂配置的方法有很多。其中一种是在虚拟网络上运行多个虚拟机。另一种是使用不同的环回地址和/或不同的端口（`127.0.0.1:8080`、`127.0.0.2:8080`等）。这两种方法的优点是可以将网络流量保持在以太网卡上，并保留在计算机本地。

正如前言中所述，您可以通过类似以下命令从命令行运行 Jenkins：

```
java –jar jenkins.war –httpsport=8443 –httpPort=-1

```

Jenkins 将开始在端口`8443`上通过 HTTPS 运行。 `-httpPort=-1` 关闭了 HTTP 端口。

要选择一个单独的主目录，您首先需要设置 `JENKINS_HOME` 环境变量。

您将使用以下命令在`127.0.0.2`的端口`80`上运行 Jenkins：

```
sudo –jar jenkins.war  --httpPort=80 --httpListenAddress=127.0.0.2

```

### 卸载 SSL

Nginx 的优点之一是你可以让它处理 SSL 请求，然后将它们作为 HTTP 请求传递给多个 Jenkins 服务器。你可以在 [`wiki.jenkins-ci.org/display/JENKINS/Jenkins+behind+an+nginx+reverse+proxy`](https://wiki.jenkins-ci.org/display/JENKINS/Jenkins+behind+an+nginx+reverse+proxy) 找到这个基本配置。

首先，您需要将端口`80`上的请求重定向到 HTTPS URL。在以下示例中，使用了`301`状态码：

```
server {
listen 80;
return 301 https://$host$request_uri;
}
```

这表示链接已永久移动。这允许重定向被缓存。然后，您将需要在端口`443`上设置服务器，这是 HTTPS 的标准端口，并加载服务器和其关联密钥的证书：

```
server {
listen 443;
server_name localhost;

ssl on;
ssl_certificate /etc/nginx/ssl/server.crt;
ssl_certificate_key /etc/nginx/ssl/server.key;
```

最后，您需要在配置为端口`443`的服务器中使用 `location` 和 `proxy_pass` 将 HTTP 传递给运行 HTTP 的 Jenkins 服务器：

```
location / {
proxy_pass              http://127.0.0.1:8080;
```

### 提示

尽管它很简单，但已知的配置陷阱是众所周知的，其中一些在 [`wiki.nginx.org/Pitfalls`](http://wiki.nginx.org/Pitfalls) 中提到。

## 另请参阅

+   *安装 Nginx* 配方

# 报告整体存储使用情况

组织有各自的方式来处理不断增长的磁盘使用情况。政策从没有政策，依赖于临时人类互动，到拥有最先进的软件和中央报告设施。大多数组织处于这两个极端之间，大部分是临时干预，对于更关键的系统则自动报告一些情况。凭借极小的努力，你可以让 Jenkins 通过 GUI 报告磁盘使用情况，并定期运行触发有用事件的 Groovy 脚本。

该配方突出了磁盘使用插件，并使用该配方来讨论在 Jenkins 工作区中存储归档的成本。

磁盘使用插件与一个早期警告系统结合使用时效果最好，该系统在达到软限制或硬限制时会通知您。通过日志解析来警告存储使用违规的作业添加配方详细说明了解决方案。这个配方表明配置 Jenkins 需要很少的努力。每一步甚至可能看起来都很琐碎。Jenkins 的强大之处在于你可以从一系列简单的步骤和脚本中构建复杂的响应。

## 准备工作

您需要安装磁盘使用插件。

## 如何做...

1.  点击**管理 Jenkins**页面下的**磁盘使用情况**链接：![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_14.jpg)

1.  Jenkins 显示每个项目名称、构建和工作空间磁盘使用情况摘要的页面。点击表格顶部以按文件使用情况对工作空间进行排序：![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_15.jpg)

## 工作原理...

在 Jenkins 中添加插件非常简单。问题是您将如何处理这些信息。

在构建中你很容易忘记一个复选框；也许一个高级选项被错误地启用了。高级选项有时可能会有问题，因为它们不直接显示在 GUI 中，所以您需要先点击**高级**按钮，然后再查看它们。在星期五下午，这可能是一步太远了。

高级选项包括工件保留选项，您需要正确配置以避免磁盘使用过多。在上一个示例中，**Sakai Trunk**的工作空间为**2 GB**。这个大小与作业有自己的本地 Maven 存储库有关，如**使用私有 Maven 存储库**高级选项所定义。你很容易忽略这个选项。在这种情况下，没有什么可以做的，因为 trunk 拉取可能会导致其他项目不稳定的快照 jar。以下截图显示的高级选项包括工件：

![工作原理...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_16.jpg)

查看项目的高级选项后，查看项目的磁盘使用情况，可以帮助您找到不必要的私有存储库。

## 还有更多...

如果您保留了大量的工件，这表明您使用 Jenkins 的目的失败了。Jenkins 是推动产品通过其生命周期的引擎。例如，当一个作业每天构建快照时，你应该将快照推送到开发人员认为最有用的地方。那不是 Jenkins，而是一个 Maven 存储库或者像 Artifactory ([`www.jfrog.com/products.php`](http://www.jfrog.com/products.php))、Apache Archiva ([`archiva.apache.org/`](http://archiva.apache.org/)) 或 Nexus ([`nexus.sonatype.org/`](http://nexus.sonatype.org/)) 这样的存储库管理器。这些存储库管理器与将内容转储到磁盘相比具有显著优势，例如：

+   **通过充当缓存加快构建速度**：开发团队往往会处理相似或相同的代码。如果您构建并使用仓库管理器作为镜像，那么仓库管理器将缓存依赖项；当作业 Y 请求相同的构件时，下载将在本地进行。

+   **充当本地共享快照的机制**：也许您的一些快照仅用于本地使用。仓库管理器具有限制访问的功能。

+   **用于便捷的构件管理的图形用户界面**：所有三个仓库管理器都有直观的 GUI，使您的管理任务尽可能简单。

在考虑到这些因素的情况下，如果您在 Jenkins 中看到构件的积累，而它们比部署到仓库更不可访问和有益，请将其视为需要升级基础设施的信号。

欲了解更多信息，请访问[`maven.apache.org/repository-management.html`](http://maven.apache.org/repository-management.html)。

### 注意

**保留策略**

Jenkins 可能会消耗大量磁盘空间。在作业配置中，您可以决定是保留构件还是在一段时间后自动删除它们。删除构件的问题是您也将删除任何自动测试的结果。幸运的是，有一个简单的技巧可以避免这种情况。在配置作业时，点击**丢弃旧构建**，选中**高级**复选框，并定义**保留构件的最大构建数**。然后在指定的构建数后删除构件，但日志和结果会被保留。这有一个重要的后果：即使您已经删除了其他占用磁盘更多的构件，您现在也允许报告插件继续显示测试历史。

## 另请参阅

+   **备份和恢复**配方

# 通过日志解析有意失败的构建

让我们想象一下，您被要求清理没有在其构建过程中运行任何单元测试的代码。代码很多。为了迫使质量的提高，如果您错过了一些残留的缺陷，那么您希望 Jenkins 构建失败。

你需要的是一个灵活的日志解析器，它可以在构建输出中发现的问题失败或警告。救命稻草是，本配方描述了如何配置一个日志解析插件，该插件可以在控制台输出中发现不需要的模式，并在发现模式时失败作业。例如，当没有单元测试时，Maven 会发出警告。

## 准备工作

您需要按照[`wiki.jenkins-ci.org/display/JENKINS/Log+Parser+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Log+Parser+Plugin)中提到的安装日志解析器插件。

## 如何做...

1.  在 Jenkins 工作空间下创建由 Jenkins 拥有的`log_rules`目录。

1.  将`no_tests.rule`文件添加到`log_rules`目录中，内容为一行：

    ```
    error /no tests/
    ```

1.  创建一个带有在编译过程中产生弃用警告的源代码的作业。在以下示例中，您正在使用来自 Sakai 项目的 CLOG 工具：

    +   **作业名称**：`Sakai_CLOG_Test`

    +   **Maven 2/3 项目**

    +   **源代码管理**：`Git`

    +   **仓库 URL**：`https://source.sakaiproject.org/contrib/clog/trunk`

    +   **构建**

    +   **Maven 版本**：`3.2.1`（或者您当前版本的标签）

    +   **目标和选项**：`clean install`

1.  运行构建。它不应该失败。

1.  如下截图所示，访问 Jenkins 的**管理配置**页面，并在**控制台输出解析**部分添加描述和解析规则文件的位置：![操作方法...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_17.jpg)

1.  在 `Sakai_CLOG_Test` 作业的**后构建操作**部分中选中**控制台输出（构建日志）解析**框。

1.  选中**在错误时标记构建失败**复选框：![操作方法...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_18.jpg)

    为**选择解析规则**选择**停止无测试**。

    构建作业，现在它应该失败了。

1.  单击左侧菜单中的**解析的控制台输出**链接。现在您将能够看到解析的错误，如下截图所示：![操作方法...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_19.jpg)

## 工作原理...

全局配置页面允许您添加每个带有一组解析规则的文件。规则使用插件主页（[`wiki.jenkins-ci.org/display/JENKINS/Log+Parser+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Log+Parser+Plugin)）中提到的正则表达式。

您使用的规则文件由一行组成：`error /no tests/`。

如果在控制台输出中找到**无测试**模式（区分大小写的测试），则插件会将其视为错误，构建将失败。可以添加更多的测试行。找到的第一个规则胜出。其他级别包括`warn`和`ok`。

源代码是从不存在单元测试的 Sakai ([`www.sakaiproject.org`](http://www.sakaiproject.org)) 区域中拉取的。

规则文件具有独特的`.rules`扩展名，以防您想在备份期间编写排除规则。

安装插件后，您可以在先前创建的规则文件之间为每个作业选择。

### 注意

这个插件赋予您周期性扫描明显的语法错误并适应新环境的能力。您应该考虑系统地遍历一系列失败的可疑构建的规则文件，直到完全清理为止。

## 还有更多...

另外两个常见的日志模式示例可能会出现问题，但通常不会导致构建失败：

+   **MD5 校验和**：如果 Maven 仓库有一个工件，但没有其关联的 MD5 校验和文件，那么构建将下载该工件，即使它已经有一个副本。幸运的是，该过程将在控制台输出中留下一条`warn`消息。

+   **启动自定义集成服务失败**：当您真正希望构建失败时，这些失败可能会以`warn`或`info`级别记录。

## 另请参阅

+   *添加一个作业以通过日志解析警告存储使用违规情况*的步骤

# 添加一个作业以通过日志解析警告存储使用违规情况

磁盘使用插件不太可能满足您的所有磁盘维护需求。此方案将向您展示如何通过添加自定义 Perl 脚本来加强磁盘监视，以警告磁盘使用违规行为。

脚本将生成两个警报：当磁盘使用量超出可接受水平时生成硬错误，当磁盘接近该限制时生成软警告。然后，日志解析器插件将相应地做出反应。

### 注意

对于 Jenkins 任务而言，使用 Perl 是典型的，因为 Jenkins 可以很好地适应大多数环境。您可以预期在获取工作时使用 Perl、Bash、Ant、Maven 和全系列的脚本和绑定代码。

## 准备工作

如果尚未这样做，请在 Jenkins 工作区下创建一个由 Jenkins 拥有的名为`log_rules`的目录。还要确保 Perl 脚本语言已安装在您的计算机上，并且 Jenkins 可以访问。Perl 默认安装在 Linux 发行版上。ActiveState 为 Mac 和 Windows 提供了一个体面的 Perl 发行版（[`www.activestate.com/downloads`](http://www.activestate.com/downloads)）。

## 如何操作...

1.  在`log_rules`目录下添加名为`disk.rule`的文件，并包含以下两行：

    ```
    error /HARD_LIMIT/
    warn /SOFT_LIMIT/
    ```

1.  访问 Jenkins 的**管理配置**页面，并将描述`DISC_USAGE`添加到**控制台输出**部分。指向解析规则文件的位置。

1.  将以下名为`disk_limits.pl`的 Perl 脚本添加到选择的位置，确保 Jenkins 用户可以读取该文件：

    ```
    use File::Find;
    my $content = "/var/lib/jenkins";
    if ($#ARGV != 1 ) {
      print "[MISCONFIG ERROR] usage: hard soft (in Bytes)\n";
      exit(-1);
    }
    my $total_bytes=0;
    my $hard_limit=$ARGV[0];
    my $soft_limit=$ARGV[1];

    find( \&size_summary, $content );

    if ($total_bytes>= $hard_limit){
    print "[HARD_LIMIT ERROR] $total_bytes>= $hard_limit (Bytes)\n";
    }elseif ($total_bytes>= $soft_limit){
    print "[SOFT_LIMIT WARN] $total_bytes>= $soft_limit (Bytes)\n";
    }else{
    print "[SUCCESS] total bytes = $total_bytes\n";
    }

    subsize_summary {
      if (-f $File::Find::name){
        $total_bytes+= -s $File::Find::name;
      }
    }
    ```

1.  修改`$content`变量以指向 Jenkins 工作区。

1.  创建一个自由风格软件项目任务。

1.  在**构建**部分下，添加**构建步骤 / 执行 Shell**。对于命令，请添加`perl disk_limits.pl 9000000 2000000`。

1.  随意更改硬限制和软限制（`9000000` `2000000`）。

1.  在**后构建操作**中检查**控制台输出（构建日志）解析**。

1.  勾选**在警告时标记构建不稳定**复选框。

1.  勾选**在错误时标记构建失败**复选框。

1.  将解析规则文件选择为**DISC_USAGE**：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_20.jpg)

1.  多次运行构建。

1.  在左侧的**构建历史**下，选择趋势链接。您现在可以查看趋势报告，并查看成功和失败的时间线，如以下屏幕截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_21.jpg)

## 工作原理...

Perl 脚本期望接收两个命令行输入：硬限制和软限制。硬限制是`$content`目录下磁盘利用率不应超过的字节值。软限制是一个较小的字节值，触发警告而不是错误。警告给管理员提供了在达到硬限制之前清理的时间。

Perl 脚本遍历 Jenkins 工作区并计算所有文件的大小。对于工作区下的每个文件或目录，脚本调用`size_summary`方法。

如果硬限制小于内容大小，则脚本会生成日志输出`[HARD_LIMIT ERROR]`。解析规则将捕获此错误并导致构建失败。如果达到软限制，则脚本将生成输出`[SOFT_LIMIT WARN]`。插件将根据`warn /SOFT_LIMIT/`规则检测到这一点，然后发出作业`warn`信号。

## 还有更多...

欢迎来到 Jenkins 的奇妙世界。您现在可以利用所有安装的功能。作业可以按计划执行，并在失败时发送电子邮件。您还可以发布推文、添加 Google 日历条目，并触发额外的事件，例如磁盘清理构建等等。您的想象力和 21 世纪的技术基本上是有限的。

## 另请参阅

+   *备份和恢复*配方

# 通过 Firefox 与 Jenkins 保持联系

如果您是 Jenkins 管理员，则您的角色是密切关注您的基础架构内构建活动的起伏变化。由于非编码原因，构建有时会偶尔冻结或中断。如果构建失败并且这与基础架构问题有关，则您需要迅速收到警告。Jenkins 可以通过多种方式做到这一点。第四章 *通过 Jenkins 进行通信*，专门介绍了针对不同受众的不同方法。从电子邮件、Twitter 和对话服务器，您可以选择广泛的提示、踢、喊和 ping。我甚至可以想象一个 Google 夏季代码项目，其中一个远程控制的小车移动到睡着的管理员身边，然后吹口哨。

这个配方是你被联系的更愉快的方式之一。你将使用 Firefox 附加组件拉取 Jenkins 的 RSS 源。这样你就可以在日常工作中查看构建过程了。

## 准备就绪

您需要在计算机上安装 Jenkins，并在至少一个 Jenkins 实例上拥有一个运行作业历史的帐户。您还需要添加 Status-4-Evar 插件，您可以从[`addons.mozilla.org/zh-CN/firefox/addon/status-4-evar/`](https://addons.mozilla.org/zh-CN/firefox/addon/status-4-evar/)获取。

### 注

以下网址将解释自上一版书籍以来 Firefox 状态栏发生了什么变化[`support.mozilla.org/zh-CN/kb/what-happened-status-bar`](https://support.mozilla.org/zh-CN/kb/what-happened-status-bar)。

### 提示

**为开发者做广告**

如果你喜欢这个附加组件，并希望将来获得更多功能，那么在附加组件作者的网站上捐款几美元是理性的自利行为。

## 如何做...

1.  选择浏览器右上角的打开菜单图标：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_22.jpg)

1.  点击附加组件按钮：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_23.jpg)

1.  在**搜索批量**（右上角），**搜索所有附加组件**标题搜索 Jenkins。

1.  点击**安装**按钮安装**Jenkins 构建监视器**。

1.  重新启动 Firefox。

1.  现在，在 Firefox 的右下角，您会看到一个小的 Jenkins 图标：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_24.jpg)

1.  右键单击图标。

1.  选择**首选项**，然后会出现**订阅**屏幕。

1.  为您的 Jenkins 实例添加一个可识别但简短的名称。例如，`插件测试服务器`。

1.  为 **Feed URL** 添加 URL，结构如下 `http://host:port/rssAll` 例如，`http://localhost:8080/rssAll`：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_25.jpg)

1.  检查**启用执行器监控**。

1.  单击**确定**按钮。插件工具栏中会出现一个区域，显示着**插件测试服务器**的订阅 URL 名称和一个健康图标。如果您将鼠标悬停在名称上，将显示更详细的状态信息：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_26.jpg)

## 工作原理...

Jenkins 提供了 RSS 订阅以使其状态信息可供各种工具访问。Firefox 插件会轮询配置的订阅，并以易于理解的格式显示信息。

要为特定的关键作业进行配置，您需要使用以下结构：`http://host:port/job/job name/rssAll`

要仅查看构建失败，请将 `rssAll` 替换为 `rssFailed`。要仅查看最后一次构建，请将 `rssAll` 替换为 `rssLatest`。

## 还有更多...

这里还有一些需要考虑的事项。

### RSS 凭据

如果在您的 Jenkins 实例上启用了安全性，则大多数 RSS 订阅将受到密码保护。要添加密码，您需要修改订阅 URL 为以下结构：

`http://username:password@host:port/path`

### 提示

**警告**

使用此插件的负面方面是在编辑期间显示任何订阅 URL 密码的纯文本。

### Firefox 的替代方案

Firefox 可在多个操作系统上运行。这使您可以在这些操作系统上使用一个插件进行通知。然而，缺点是您必须保持 Firefox 浏览器在后台运行。另一种选择是特定于操作系统的通知软件，它会在系统托盘中弹出。这种软件的示例包括用于 Mac OSX 的 CCMenu ([`ccmenu.org`](http://ccmenu.org)) 或用于 Windows 的 CCTray ([`en.sourceforge.jp/projects/sfnet_ccnet/releases/`](http://en.sourceforge.jp/projects/sfnet_ccnet/releases/))。

## 另请参阅

+   第四章中的 *使用 Google 日历进行移动演示* 配方，*通过 Jenkins 进行通信*

# 通过 JavaMelody 进行监控

JavaMelody（[`code.google.com/p/javamelody/`](http://code.google.com/p/javamelody/)）是一个提供全面监控的开源项目。Jenkins 插件监控 Jenkins 的主实例和节点。该插件提供了大量重要信息。你可以查看主要数量（如 CPU 或内存）1 天、1 周甚至数月的演变图表。演变图表非常适合确定资源消耗大的定期作业。JavaMelody 允许您实时监控资源的渐进性退化。它通过将统计数据导出为 PDF 格式来简化报告的编写。JavaMelody 已经拥有超过 25 个人年的努力，功能丰富。

本文介绍了如何轻松安装监控插件（[`wiki.jenkins-ci.org/display/Jenkins/Monitoring`](https://wiki.jenkins-ci.org/display/Jenkins/Monitoring)），然后讨论了故障排除策略及其与生成的指标的关系。

### 提示

**社区合作**

如果你觉得这个插件有用，请考虑回馈给插件或核心 JavaMelody 项目。

## 准备工作

你需要安装监控插件。

## 如何操作...

1.  在**管理 Jenkins**页面点击**监控 Jenkins 主节点**链接。现在你会看到详细的监控信息，如下截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_27.jpg)

1.  在`http://host:port/monitoring?resource=help/help.html`上阅读在线帮助，其中 host 和 port 指向你的服务器。

1.  通过访问`http://host:port/monitoring/nodes`直接查看节点进程的监控。

## 工作原理...

JavaMelody 的优点是以 Jenkins 用户身份运行，并且可以访问所有相关的指标。它的主要缺点是作为服务器的一部分运行，一旦发生故障就会停止监视。因此，由于这个缺点，你应该将 JavaMelody 视为监控解决方案的一部分，而不是整个解决方案。

## 还有更多...

监控是全面测试和故障排除的基础。本节探讨了这些问题与插件中提供的测量之间的关系。

### 使用 JavaMelody 进行故障排除 - 内存

你的 Jenkins 服务器有时可能会出现内存问题，原因是构建过于贪婪、插件泄露或基础架构中的某些隐藏复杂性。JavaMelody 具有广泛的内存测量范围，包括堆转储和内存直方图。

Java 虚拟机将内存分成各种区域，为了清理，它会删除没有对其他对象的引用的对象。当垃圾回收忙碌时，它可能会占用大量 CPU 资源，而且内存越满，垃圾回收就越繁忙。对于外部监控代理来说，这看起来像是一个 CPU 峰值，通常很难追踪到。仅仅因为垃圾收集器管理内存，就认为 Java 中不存在内存泄漏的潜力也是一种错误。许多常见做法，如自定义缓存或调用本地库，都可能导致内存被持有太长时间。

慢慢渗漏的内存泄漏将显示为与内存相关的演化图上的缓缓上升。如果你怀疑有内存泄漏，那么你可以通过**执行垃圾收集器**链接来强制插件进行完整的垃圾收集。如果不是内存泄漏，那么这个缓缓上升将会突然下降。

内存问题也可能表现为大的 CPU 峰值，因为垃圾收集器拼命尝试清理，但几乎无法清理足够的空间。垃圾收集器还可以在全面寻找不再被引用的对象时暂停应用程序（"停止世界"垃圾收集），从而导致网页浏览器请求的响应时间增加。这可以通过**统计 http - 1 天**中的**平均**和**最大**时间来观察到。

### 使用 JavaMelody 进行故障排除 - 痛苦的工作

你应该考虑以下几点：

+   **卸载工作**：为了稳定的基础设施，尽可能地从主实例中卸载尽可能多的工作。如果你有定期任务，请将最重的任务在时间上保持分离。时间分离不仅能均匀负载，而且可以通过观察 JavaMelody 的演化图来更容易地找到有问题的构建。还要考虑空间分离；如果某个节点或一组标记的节点显示出问题，那么开始切换作业的机器位置，并通过 `http://host:port/monitoring/nodes` 查看它们的单独性能特征。

+   **硬件成本低廉**：与支付人工小时相比，购买额外的 8 GB 大约相当于一个人小时的努力。

    ### 注意

    一个常见的错误是向服务器添加内存，同时忘记更新初始化脚本以允许 Jenkins 使用更多内存。

+   **审查构建脚本**：Javadoc 生成和自定义 Ant 脚本可以分叉 JVM 并在其自己的配置中保留定义的内存。编程错误也可能是问题的原因。不要忘记审查 JavaMelody 关于**统计系统错误日志**和**统计 http 系统错误**的报告。

+   **不要忘记外部因素**：因素包括备份、定期任务、更新 locate 数据库和网络维护。这些将显示为演化图中的周期性模式。

+   **人多势众**：结合磁盘使用插件等使用 JavaMelody，以全面了解重要统计信息。每个插件都很容易配置，但它们对您的有用性将比增加额外插件的维护成本增长更快。

## 另请参阅

+   第七章, *插件探索*中的*使用 Groovy 钩子脚本和在启动时触发事件*食谱

# 跟踪脚本粘合剂

如果维护脚本在基础架构中分散，备份和特别是还原将产生负面影响。最好将您的脚本放在一个地方，然后通过节点远程运行它们。考虑将您的脚本放在主 Jenkins 主目录下并备份到 Git 存储库。如果您能在线共享较不敏感的脚本，对社区来说将更好。您的组织将获得好处；然后脚本将得到一些重要的同行审查和改进。有关社区存储库详细信息，请查看`http://localhost:8080/scriptler.git/`中的支持信息。

在本食谱中，我们将探讨 Scriptler 插件的使用，以在本地管理您的脚本并从在线目录下载有用的脚本。

## 准备工作

您需要安装 Scriptler 插件（[`wiki.jenkins-ci.org/display/JENKINS/Scriptler+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Scriptler+Plugin)）。

## 如何操作...

1.  在**Manage Jenkins**页面下点击**Scriptler**链接。您会注意到粗体文本。当前您没有任何可用的脚本；您可以从远程目录导入脚本或创建自己的脚本。

1.  在左侧点击**远程脚本目录**链接。

1.  点击**ScriptierWeb**选项卡。

1.  点击**getThreadDump**的软盘图标。如果脚本不可用，则选择另一个您喜欢的脚本。

1.  点击**Submit**按钮。

1.  您现在已经返回到**Scriptler**主页面。您会看到三个图标。选择最右边的图标来执行脚本：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_28.jpg)

1.  您现在位于**运行脚本**页面。选择一个节点，然后点击**运行**按钮。

    ### 注意

    如果脚本出现`startup failed`消息，则请在`entry.key`和`for`之间添加一行，然后脚本将正常运行。

1.  要编写新的 Groovy 脚本或上传您本地系统上的脚本，请在左侧点击**添加新脚本**链接。

## 工作原理...

此插件允许您轻松管理您的 Groovy 脚本，并强制将所有 Jenkins 管理员的代码放在一个标准位置，这样您就可以更轻松地计划备份，并间接共享知识。

该插件创建了一个名为 `scriptler` 的目录，位于 Jenkins 工作空间下，并将你创建的文件的元信息持久化到 `scriptler.xml` 文件中。第二个文件名为 `scriptlerweb-catalog.xml`，提到了可以下载的在线文件列表。

所有本地脚本都包含在子目录 scripts 中。

## 还有更多...

如果足够多的人使用这个插件，那么在线脚本列表将大大增加生成一个重要的可重用代码库的过程。因此，如果你有有趣的 Groovy 脚本，那就上传吧。你需要在第一次登录时创建一个新账户，以便登录到 [`scriptlerweb.appspot.com/login.gtpl`](http://scriptlerweb.appspot.com/login.gtpl)。

上传你的脚本允许人们对其投票，并向你发送反馈。免费的同行评审只会提高你的脚本技能，并在更广泛的社区中增加你的认可度。

## 另请参阅

+   *Scripting the Jenkins CLI* 配方

+   *使用 Groovy 对作业进行全局修改* 配方

# Scripting the Jenkins CLI

Jenkins CLI ([`wiki.jenkins-ci.org/display/JENKINS/Jenkins+CLI`](https://wiki.jenkins-ci.org/display/JENKINS/Jenkins+CLI)) 允许你在远程服务器上执行多项维护任务。任务包括将 Jenkins 实例上线和下线、触发构建以及运行 Groovy 脚本。这使得对最常见的琐事进行脚本化变得容易。

在这个配方中，你将登录到 Jenkins 实例，运行一个查找大于某个大小的文件的 Groovy 脚本，然后退出登录。该脚本代表了一个典型的维护任务。在审查输出后，你可以运行第二个脚本来删除你想要删除的文件列表。

### 注意

在撰写本章时，交互式 Groovy shell 无法从 CLI 中工作。这在错误报告中有所提及：[`issues.jenkins-ci.org/browse/JENKINS-5930`](https://issues.jenkins-ci.org/browse/JENKINS-5930)。

## 准备工作

从`http://host/jnlpJars/jenkins-cli.jar`下载 CLI JAR 文件。

将以下脚本添加到 Jenkins 控制下的一个目录，并将其命名为 `large_files.groovy`：

```
root = jenkins.model.Jenkins.instance.getRootDir()
count = 0
size =0
maxsize=1024*1024*32
root.eachFileRecurse() { file ->
count++
size+=file.size();
if (file.size() >maxsize) {
println "Thinking about deleting: ${file.getPath()}"
            // do things to large files here
        }
}
println "Space used ${size/(1024*1024)} MB Number of files ${count}"
```

## 如何做...

1.  从终端运行以下命令，将`http://host`替换为你服务器的真实地址，例如，`http://localhost:8080`。

    ```
    java -jar jenkins-cli.jar -s 
    http://host  login --username username

    ```

1.  输入你的密码。

1.  查看在线帮助：

    ```
    java -jar jenkins-cli.jar -s 
    http://host   help

    ```

1.  运行 Groovy 脚本。输出现在将提到所有超大文件：

    ```
    java -jar jenkins-cli.jar -s http://host groovy large_files.groovy

    ```

1.  通过运行以下命令注销：

    ```
    java -jar jenkins-cli.jar -s http://host logout.

    ```

## 工作原理...

CLI 允许你从命令行工作并执行标准任务。将 CLI 包装在诸如 Bash 等的 shell 脚本中，可以让你同时脚本化维护任务和大量 Jenkins 实例。本配方执行了大量维护工作。在这种情况下，它检查 x 个文件以查找超大的构件，节省你可以用在更有趣任务上的时间。

在执行任何命令之前，你需要通过 `login` 命令进行身份验证。

评审`root = jenkins.model.Jenkins.instance.getRootDir()`脚本使用 Jenkins 框架获取指向 Jenkins 工作空间的`java.io.File`。

通过`maxsize=1024*1024*32`设置最大文件大小为 32 MB。

该脚本使用标准的`root.eachFileRecurse(){ file ->` Groovy 方法访问 Jenkins 工作空间下的每个文件。

### 注意

你可以在[Jenkins 的当前 JavaDoc](http://javadoc.jenkins-ci.org/)中找到最新的文档。

## 还有更多...

此示例中使用的身份验证可以改进。你可以在`http://localhost:8080/user/{username}/configure`（其中`username`是你的用户名）下添加你的 SSH 公钥，方法是将其剪切并粘贴到**SSH 公钥**部分。你可以在[`wiki.jenkins-ci.org/display/JENKINS/Jenkins+CLI`](https://wiki.jenkins-ci.org/display/JENKINS/Jenkins+CLI)找到详细说明。

在撰写本书时，关键方法存在一些问题。有关更多信息，请访问[`issues.jenkins-ci.org/browse/JENKINS-10647`](https://issues.jenkins-ci.org/browse/JENKINS-10647)。尽管安全性较低，但请随时使用在本示例中已被证明稳定运行的方法。

### 注意

CLI 易于扩展，因此随着时间的推移，CLI 的命令列表会增加。因此，偶尔检查帮助选项非常重要。

## 另请参阅

+   *使用 Groovy 全局修改作业* 示例

+   *编写全局构建报告的脚本* 示例

# 使用 Groovy 全局修改作业

Jenkins 不仅是一个持续集成服务器，而且还是一个具有从脚本控制台中可用的暴露内部结构的丰富框架。你可以通过编程方式迭代作业、插件、节点配置和各种丰富的对象。随着作业数量的增加，你会注意到脚本变得更有价值。例如，想象一下，如果你需要在 100 个作业中增加自定义内存设置。一个 Groovy 脚本可以在几秒钟内完成。

这个示例是一个典型的例子：你将运行一个脚本，该脚本通过所有作业进行迭代。然后，脚本通过作业名称找到一个特定的作业，然后使用一个随机数更新该作业的描述。

## 准备就绪

使用管理员帐户登录 Jenkins。

## 操作步骤...

1.  创建一个名为`MyTest`的空作业。

1.  在**管理 Jenkins**页面中，点击**脚本控制台**链接。

1.  点击**添加新脚本**。

1.  将以下脚本剪切并粘贴到**脚本**文本区域输入：

    ```
    import java.util.Random
    Random random = new Random()

    hudson.model.Hudson.instance.items.each{ job ->
    println ("Class: ${job.class}")
    println ("Name: ${job.name}")
    println ("Root Dir: ${job.rootDir}")
    println ("URL: ${job.url}")
    println ("Absolute URL: ${job.absoluteUrl}")

    if ("MyTest".equals(job.name)){
      println ("Description: ${job.description}")
    job.setDescription("This is a test id: ${random.nextInt(99999999)}")
    }
    }
    ```

1.  点击**运行**按钮。结果应与以下屏幕截图类似：![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_29.jpg)

1.  再次运行脚本；您会注意到描述中的随机数现在已经改变了。

1.  复制并运行以下脚本：

    ```
    for (slave in hudson.model.Hudson.instance.slaves) {
    println "Slave class: ${slave.class}"
    println "Slave name: ${slave.name}"
    println "Slave URL: ${slave.rootPath}"
    println "Slave URL: ${slave.labelString}\n"
    }
    ```

    如果您的 Jenkins 主服务器上没有`slave`实例，则不会返回任何结果。否则，输出将类似于以下屏幕截图：

    ![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_30.jpg)

## 它是如何工作的...

Jenkins 有一个丰富的框架，可以在脚本控制台中使用。第一个脚本遍历其父级为 `AbstractItem` 的作业 ([`javadoc.jenkins-ci.org/hudson/model/AbstractItem.html`](http://javadoc.jenkins-ci.org/hudson/model/AbstractItem.html))。第二个脚本遍历 `slave` 对象的实例 ([`javadoc.jenkins-ci.org/hudson/slaves/SlaveComputer.html`](http://javadoc.jenkins-ci.org/hudson/slaves/SlaveComputer.html))。

## 还有更多...

针对硬核的 Java 开发者：如果您不知道如何执行编程任务，那么示例代码的极佳来源是 Jenkins 插件的 Subversion 目录 ([`svn.jenkins-ci.org/trunk/hudson/plugins/`](https://svn.jenkins-ci.org/trunk/hudson/plugins/)) 和更新更及时的 Github 位置 ([`github.com/jenkinsci`](https://github.com/jenkinsci))。

### 注意

如果您有兴趣捐赠您自己的插件，请查阅[`wiki.jenkins-ci.org/display/JENKINS/Hosting+Plugins`](https://wiki.jenkins-ci.org/display/JENKINS/Hosting+Plugins)上的信息。

## 另请参阅

+   *Scripting the Jenkins CLI* 配方

+   *Scripting global build reports* 配方

# 表示需要归档

每个开发团队都是独特的。团队有自己的业务方式。在许多组织中，周期性需要完成一次性任务。例如，每年结束时，对整个文件系统进行全面备份。

本配方详细介绍了一个脚本，该脚本检查任何作业的最后一次成功运行；如果年份与当前年份不同，则在作业描述的开头设置警告。因此，它向您提示现在是执行某些操作的时候，例如归档然后删除。当然，您也可以通过编程方式执行归档。但是，对于高价值的操作，值得强制干预，让 Groovy 脚本引起您的注意。

## 准备工作

使用管理账户登录 Jenkins。

## 如何执行...

1.  在 **管理 Jenkins** 页面中，点击 **Script Console** 链接，然后运行以下脚本：

    ```
    Import hudson.model.Run;
    Import java.text.DateFormat;

    def warning='<font color=\'red\'>[ARCHIVE]</font> '
    def now=new Date()

    for (job in hudson.model.Hudson.instance.items) {
    println "\nName: ${job.name}"
        Run lastSuccessfulBuild = job.getLastSuccessfulBuild()
    if (lastSuccessfulBuild != null) {
    def time = lastSuccessfulBuild.getTimestamp().getTime()
    if (now.year.equals(time.year)){
    println("Project has same year as build");
    }else {
    if (job.description.startsWith(warning)){
    println("Description has already been changed");
    }else{
    job.setDescription("${warning}${job.description}")
            }
         }
       }
    }
    ```

    任何项目，如果其上次成功构建的年份不同于当前年份，则在其描述的开头添加了以红色显示的 **[ARCHIVE]** 一词，如下图所示：

    ![如何执行...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_01_31.jpg)

## 它是如何工作的...

检查代码清单：

+   定义了一个警告字符串，并将当前日期存储在 now 中。通过 `for` 语句在 Jenkins 中以编程方式迭代每个作业。

+   Jenkins 有一个用于存储构建运行信息的类。运行时信息通过 `job.getLastSuccessfulBuild()` 检索，并存储在 `lastSuccessfulBuild` 实例中。如果没有成功的构建，则 `lastSuccessfulBuild` 被设置为 `null`；否则，它具有运行时信息。

+   检索上次成功构建的时间，然后通过 `lastSuccessfulBuild.getTimestamp().getTime()` 将其存储在 `time` 实例中。

当前年份与上次成功构建的年份进行比较，如果它们不同并且警告字符串尚未添加到作业描述的开头，则更新描述。

### 提示

**Javadoc**

你会在 [`javadoc.jenkins-ci.org/hudson/model/Job.html`](http://javadoc.jenkins-ci.org/hudson/model/Job.html) 找到作业 API，并且在 [`javadoc.jenkins-ci.org/hudson/model/Run.html`](http://javadoc.jenkins-ci.org/hudson/model/Run.html) 找到 `Run` 信息。

## 还有更多...

在编写自己的代码之前，你应该审查已经存在的代码。Jenkins 拥有一个庞大、免费可用且开放授权的示例代码库，插件数量达到了 1,000 个并且在不断扩展。尽管在这种情况下使用了标准 API，但值得仔细审查插件代码库。在这个例子中，你会发现部分代码是从 `lastsuccessversioncolumn` 插件中重用的。([`tinyurl.com/pack-jenkins-1`](http://tinyurl.com/pack-jenkins-1))。

### 提示

如果你在审查插件代码库时发现任何缺陷，请通过补丁和错误报告为社区做出贡献。

## 另请参阅

+   *Scripting the Jenkins CLI* 配方

+   *使用 Groovy 全局修改作业* 配方


# 第二章： 增强安全性

在本章中，我们将涵盖以下内容：

+   测试 OWASP 十大安全问题

+   通过模糊测试在 Jenkins 中查找 500 错误和 XSS 攻击

+   通过小型配置更改提高安全性

+   使用 JCaptcha 防止注册机器人

+   通过 Groovy 查看 Jenkins 用户

+   使用审计追踪插件

+   安装 OpenLDAP

+   使用脚本领域身份验证进行配置

+   通过自定义组脚本查看基于项目的矩阵策略

+   管理 OpenLDAP

+   配置 LDAP 插件

+   安装 CAS 服务器

+   在 Jenkins 中启用 SSO

+   探索 OWASP Dependency-Check 插件

# 介绍

在本章中，我们将讨论 Jenkins 的安全性，考虑到 Jenkins 可以存在于多样的基础架构中。我们还将探讨如何扫描 Jenkins 编译时使用的 Java 代码库中已知安全问题。

唯一完全安全的系统是不存在的系统。对于真实服务，你需要注意不同面向攻击的表面。Jenkins 的主要表面是其基于 Web 的图形用户界面及其与从节点和本机操作系统的信任关系。在线服务需要严密关注其安全表面。对于 Jenkins，主要有三个原因：

+   Jenkins 有能力通过其插件或主从拓扑结构与各种基础架构通信

+   插件周围的代码更改速度很快，可能意外包含与安全相关的缺陷

+   你需要加固默认安装，使其对外开放

一个平衡因素是，使用 Jenkins 框架的开发人员应用经过验证的技术，例如 XStream（[`xstream.codehaus.org/`](http://xstream.codehaus.org/)）用于配置持久性，Jelly（[`commons.apache.org/jelly/`](http://commons.apache.org/jelly/)）用于呈现 GUI。这种使用知名框架最小化了支持代码数量，而使用的代码经过了充分测试，限制了漏洞范围。

另一个积极的方面是 Jenkins 代码是免费供审查的，核心社区保持警惕。贡献代码的任何人不太可能故意添加缺陷或意外的许可证标头。然而，你应该信任但要核实。

本章前半部分致力于 Jenkins 环境。在后半部分，你将看到 Jenkins 如何融入更广泛的基础架构。

**轻量级目录访问**（**LDAP**）广泛可用，并且是企业目录服务的事实标准。我们将使用 LDAP 进行 Jenkins 的身份验证和授权，然后使用 JASIG 的**中央认证服务**（**CAS**）进行**单点登录**（**SSO**）。了解更多，请访问[`www.jasig.org/cas`](http://www.jasig.org/cas)。CAS 允许您登录一次，然后转到其他服务而无需重新登录。当您希望从 Jenkins 链接到其他受密码保护的服务（例如组织的内部 wiki 或代码浏览器）时，这非常有用。同样重要的是，CAS 可以在幕后连接到多种类型的身份验证提供者，例如 LDAP、数据库、文本文件以及越来越多的其他方法。这使得 Jenkins 间接地可以使用许多登录协议，这些协议已经由其插件提供。

### 提示

**安全公告**

Jenkins 相关安全公告有电子邮件列表和 RSS 源。您可以在[`wiki.jenkins-ci.org/display/JENKINS/Security+Advisories`](https://wiki.jenkins-ci.org/display/JENKINS/Security+Advisories)找到公告源的链接。

# 测试 OWASP 的十大安全问题

本文介绍了使用 OWASP 的渗透测试工具 w3af 对 Jenkins 进行已知安全问题的自动测试。有关更多信息，请访问[`w3af.sourceforge.net`](http://w3af.sourceforge.net)。OWASP 的目的是使应用程序安全可见。2010 年 OWASP 的十大不安全性列表包括以下内容：

+   **A2-跨站脚本（XSS）**：当应用程序将未经转义的输入返回给客户端的浏览器时，可能会发生 XSS 攻击。Jenkins 管理员可以通过作业描述默认执行此操作。

+   **A6-安全配置错误**：Jenkins 插件赋予您编写自定义身份验证脚本的能力。通过错误的配置很容易出错。

+   **A7-不安全的加密存储**：Jenkins 有 600 多个插件，每个插件都将其配置存储在单独的 XML 文件中。密码以明文形式存储可能会有罕见的错误。您需要仔细检查。

+   **A9-传输层保护不足**：Jenkins 默认运行在 HTTP 上。获取受信任的证书可能会很麻烦并涉及额外的成本。您可能会心生诱惑，不实施 TLS，从而使您的数据包处于开放状态。

您会发现 2013 年的 OWASP 十大不安全性与 2010 年版本相比有些变化。最显著的变化是包含了 A9-使用已知弱点组件。如果您的软件依赖于旧库，那么就有机会利用已知弱点进行操纵。

Jenkins 拥有一个由积极、分散和勤奋的社区编写的大量插件。由于代码的大量更改，可能会无意中添加安全缺陷。例如，在配置文件中明文留下密码，或者使用不移除可疑 JavaScript 的不安全渲染。你可以通过手动审查配置文件来找到第一类缺陷。第二类缺陷对更广泛的受众可见，因此更容易被破解。你可以手动攻击新的插件。互联网上有很多有用的备忘单（[`ha.ckers.org/xss.html`](http://ha.ckers.org/xss.html)）。这种工作很乏味；自动化测试可以覆盖更多内容，并作为 Jenkins 作业的一部分定期安排。

在名为*探索 OWASP Dependency-Check 插件*的配方中，你将配置 Jenkins，让它基于自动审查你的代码依赖关系来警告你已知的攻击向量。

### 提示

**OWASP 商店**

OWASP 每年发布一份关于 Web 应用程序十大最常见安全攻击向量的列表。他们通过 [`lulu.com`](http://lulu.com) 发布此文档和各种书籍。在 Lulu，你可以免费获取 OWASP 文档的 PDF 版本，或者购买廉价的按需打印版本。你可以在官方商店找到它：[`stores.lulu.com/owasp`](http://stores.lulu.com/owasp)。

## 准备工作

渗透测试有可能损坏正在运行的应用程序。确保你备份了 Jenkins 工作空间的副本。你可能需要重新安装。同时关闭 Jenkins 中的任何已启用安全性：这样可以让 w3af 自由地漫游安全表面。

从 SourceForge 下载 w3af 的最新版本（[`w3af.org/download/`](http://w3af.org/download/)），并且也下载并阅读 OWASP 的十大已知攻击列表（[`www.owasp.org/index.php/Category:OWASP_Top_Ten_Project`](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project)）。

w3af 同时具有 Windows 和 *NIX 安装包；使用您选择的操作系统安装。但是，Windows 安装程序不再受支持，没有安装程序的安装过程很复杂。因此，最好使用工具的 *NIX 版本。

### 注意

w3af 的 Debian 包比 Linux 的 SourceForge 包老旧且不稳定。因此，不要使用 `apt-get` 和 `yum` 安装方法，而是使用从 SourceForge 下载的包。

## 如何操作...

1.  要安装 w3af，请按照开发者网站上给出的说明进行操作（[`w3af.org/download/`](http://w3af.org/download/)）。如果 Ubuntu 存在任何无法解决的依赖问题，请退回到 `apt-get` 安装方法，并安装工具的旧版本，方法如下：

    ```
    sudo apt-get install w3af

    ```

1.  运行 w3af。

1.  在**配置文件**选项卡下，选择**OWASP_TOP10**。

1.  在**目标**地址窗口下，填写 `http://localhost:8080/`，将主机名更改为适合您的环境。

1.  点击 **Start** 按钮。现在将进行渗透测试，而 **Start** 按钮将更改为 **Stop**。在扫描结束时，**Stop** 按钮将更改为 **Clear**：![操作方法...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_01.jpg)

1.  通过选择 **Log** 标签查看攻击历史记录。

1.  通过单击 **Results** 标签查看结果。

1.  在第一次扫描后，在 **Profiles** 下选择 **full_audit**。

1.  点击 **Clear** 按钮。

1.  在 **Target** 地址窗口中键入 `http://localhost:8080/`。

1.  点击 **Start** 按

1.  等待扫描完成并查看 **Results** 标签。

## 它是如何工作的...

w3af 由安全专业人员编写。它是一个可插拔的框架，具有为不同类型的攻击编写的扩展。配置文件定义了您将在渗透测试中使用的插件及其关联的配置。

您首先使用 **OWASP_TOP10** 配置文件进行攻击，然后再次使用更全面的插件进行攻击。

结果会根据您的设置而变化。根据插件，偶尔会标记出不存在的安全问题。您需要手动验证所提到的任何问题。

在写作时，使用这种方法未发现重大缺陷。然而，该工具指出了缓慢的链接并生成了服务器端异常。这是你想在错误报告中记录的信息类型。

## 还有更多...

一致地保护您的应用程序需要经验丰富的细节关注。以下是您需要审查的更多内容。

### 使用 Webgoat 进行目标练习

安全缺陷的前十名列表有时会难以理解。如果你有一些空闲时间，喜欢针对一个故意不安全的应用程序进行实践，那么你应该尝试一下 Webgoat ([`www.owasp.org/index.php/Category:OWASP_WebGoat_Project`](https://www.owasp.org/index.php/Category:OWASP_WebGoat_Project))。

Webgoat 配有提示系统和链接到视频教程的文档良好；它几乎没有误解攻击的余地。

### 更多工具

w3af 是一个强大的工具，但与以下工具一起使用效果更好：

+   **Nmap** ([`nmap.org/`](http://nmap.org/))：一个易于使用、非常流行、屡获殊荣的网络扫描器。

+   **Nikto** ([`cirt.net/nikto2`](http://cirt.net/nikto2))：一个 Perl 脚本，快速总结系统详细信息并查找最明显的缺陷。

+   **Skipfish** ([`code.google.com/p/skipfish/downloads/list`](https://code.google.com/p/skipfish/downloads/list))：一个利用大量请求长时间运行的 C 程序。您可以从不同的攻击字典中进行选择。这是一个极好的穷人压力测试；如果您的系统保持稳定，那么您就知道它已经达到了最低的稳定水平。

+   **Wapiti** ([`wapiti.sourceforge.net/`](http://wapiti.sourceforge.net/))：一个基于 Python 的脚本，发现可攻击的 URL，然后循环遍历一个邪恶参数列表。

Jenkins 是灵活的，因此可以通过运行作业中的脚本调用各种工具，包括提到的安全工具。

### 注

有许多优秀的资源可用于保护本地操作系统，包括 Debian 安全指南（[`www.debian.org/doc/manuals/securing-debian-howto/`](https://www.debian.org/doc/manuals/securing-debian-howto/)）；对于 Windows，可以在 MSDN 安全中心下找到相关文章（[`msdn.microsoft.com/en-us/security/`](http://msdn.microsoft.com/en-us/security/)）；对于 Mac，可以参考苹果官方的安全指南（[`www.apple.com/support/security/guides/`](https://www.apple.com/support/security/guides/)）。在线服务需要高度关注其安全性。

## 另请参阅

+   *通过模糊查找 Jenkins 中的 500 错误和 XSS 攻击* 配方

+   *通过小配置更改提高安全性* 配方

+   *探索 OWASP 依赖检查插件* 配方

# 通过模糊查找 Jenkins 中的 500 错误和 XSS 攻击

该配方描述了如何使用模糊器在您的 Jenkins 服务器中查找服务器端错误和 XSS 攻击。

模糊器会遍历一系列网址，盲目地附加不同的参数，并检查服务器的响应。输入的参数是关于脚本命令的变化，例如 `<script>alert("random string");</script>`。如果服务器的响应包含脚本的未转义版本，那么就发现了一种攻击向量。

跨站脚本攻击目前是较流行的一种攻击形式（[`en.wikipedia.org/wiki/Cross-site_scripting`](http://en.wikipedia.org/wiki/Cross-site_scripting)）。该攻击涉及将脚本片段注入客户端浏览器，以便脚本以来自受信任网站的方式运行。例如，一旦您已登录应用程序，您的会话 ID 可能存储在 cookie 中。注入的脚本可能会读取 cookie 中的值，然后将信息发送到另一台服务器，以备重用尝试。

一个模糊器会发现攻击目标站点上的链接以及站点网页中存在的表单变量。对于发现的网页，它会基于历史攻击和大量微小变化重复发送输入。如果返回的响应与发送的相同的随机字符串，模糊器就知道它发现了一个**恶意网址**。

要完全与基于 Web 的应用程序的构建流程集成，您需要构建应用程序、部署和运行应用程序、从脚本运行模糊器，并最终使用日志解析来在输出中提到恶意网址时失败构建。对于您希望集成的其他命令行工具，该流程将类似。有关日志解析的更多信息，请参阅第一章 中的 *通过日志解析故意失败构建* 配方，*Maintaining Jenkins*。

## 准备工作

备份你的牺牲 Jenkins 服务器并关闭其安全性。预计攻击结束时应用程序将不稳定。

你需要在你的计算机上安装 Python 编程语言。要下载和安装 Wapiti，你需要按照 [`wapiti.sourceforge.net`](http://wapiti.sourceforge.net) 上的说明进行操作。

### 注意

如果你从本地机器攻击本地机器，那么你可以关闭其网络。攻击将留在环回网络驱动程序中，不会有数据包逃逸到互联网。

在这个教程中，方法和命令行选项都是正确的。但是，在阅读时，提到的结果可能不存在。Jenkins 经历了快速的生命周期，开发人员迅速清除错误。

## 如何操作...

1.  在 `wapiti` bin 目录中运行以下命令：

    ```
    python wapiti  http://localhost:8080 -m "-all,xss,exec" -x http://localhost:8080/pluginManager/* -v2

    ```

1.  当命令运行完成时，你将在控制台输出中看到最终报告的位置：

    ```
    Report
    ------
    A report has been generated in the file
    ~/.wapiti/generated_report
    ~/.wapiti/generated_report/index.html with a browser to see this report.

    ```

1.  在网页浏览器中打开报告并进行审阅：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_12.jpg)

1.  点击**内部服务器错误**链接。

1.  对于其中一个名为**在 /iconSize 中发现的异常**的项目，从**cURL 命令行**选项卡中复制 URL：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_13.jpg)

1.  在网页浏览器中打开 URL。现在你会看到一个新生成的 Jenkins 错误报告页面，如下图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_14.jpg)

1.  运行以下命令：

    ```
    python wapiti http://localhost:8080 -m "-all,xss,permanentxss" -x http://localhost:8080/pluginManager/*

    ```

1.  查看输出以验证 `permanentxss` 模块是否已运行：

    ```
    [*] Loading modules :
    mod_crlf, mod_exec, mod_file, mod_sql, mod_xss, mod_backup, mod_htaccess, mod_blindsql, mod_permanentxss, mod_nikto
    [+] Launching module xss
    [+] Launching module permanentxss

    ```

## 工作原理...

Wapiti 载入不同的模块。默认情况下，会使用所有模块。你需要进行选择；对于 Ubuntu Linux 的 Version 2.2.1，这会导致 Wapiti 崩溃或超时。

要加载特定模块，请使用 `-m` 选项。

`-m "-all,xss,exec"` 语句告诉 Wapiti 忽略所有模块，除了 `xss` 和 `exec` 模块。

`exec` 模块非常擅长在 Jenkins 中找到 500 错误。这主要是由于 Jenkins 无法很好地处理意外输入。这纯粹是一组外观问题。但是，如果开始出现与文件或数据库服务等资源相关的错误，则应提高问题的优先级并发送错误报告。

`-x` 选项指定要忽略的 URL。在这种情况下，我们不想给插件管理器带来麻烦。如果这样做，它将向一个无辜的外部服务生成大量请求。

Wapiti 爬取网站。如果你不小心，工具可能会跟踪到你不想测试的位置。为了避免尴尬，请小心使用排除 URL 的选项 `-x`。

`-v2` 选项设置日志的详细程度最高，这样你就可以看到所有攻击。

在 Wapiti 的第二次运行中，你还使用了 `permanentxss` 模块，有时会发现真正的 XSS 攻击，这取决于开发人员构建功能和清理错误之间的竞争。

### 注意

**穷人版的质量保证**

模糊测试器擅长覆盖应用程序的大部分 URL 空间，触发可能会耗费大量时间来查找的错误。考虑在项目的 QA 过程中通过 Jenkins 作业进行自动化。

## 还有更多...

您在此方法中生成的报告提到的服务器错误比 XSS 攻击要多得多。这是因为许多生成的错误是由于意外的输入导致失败，这些失败只被最后一层错误处理捕获，本例中为错误报告页面。如果您认为错误值得报告，请按照 bug 报告页面上的说明操作。

这里有一些关于堆栈跟踪输出背后含义的指南：

+   `java.lang.SecurityException`：如果 Jenkins 用户正在进行程序员认为不安全的操作，比如访问 URL，则只有在您登录后才能到达此处。

+   `java.lang.IllegalArgumentException`：Jenkins 检查了参数的有效范围，参数值超出了该范围。这是故意抛出的异常。

+   `java.lang.NumberFormatException`：Jenkins 没有检查有效的字符串，然后尝试将一个不符合规范的字符串解析为数字。

+   `java.lang.NullPointerException`：通常发生在您访问一个没有设置所有参数的 URL 时，Jenkins 期望的参数值不存在。在程序员的语言中：代码期望存在一个不存在的对象，然后尝试调用不存在对象的方法，而不检查对象是否存在。程序员需要添加更多的错误检查。编写一个错误报告。

## 另请参阅

+   测试 OWASP 前 10 大安全问题的方法

+   通过小的配置更改提高安全性的方法

# 通过小的配置更改提高安全性

此方法描述了修改后的配置，以加强 Jenkins 的默认安全设置。重新配置包括在控制台输出中掩码密码和添加一次性随机数，这使得很难伪造表单输入。这些调整的组合极大地加强了 Jenkins 的安全性。

## 准备就绪

您将需要安装 Mask Passwords 插件 ([`wiki.jenkins-ci.org/display/JENKINS/Mask+Passwords+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Mask+Passwords+Plugin))。

## 如何操作...

1.  创建一个作业。

1.  单击**掩码密码**复选框并添加一个变量。

1.  在**名称**字段中键入`MyPassword`，在**密码**字段中键入`changeme`，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_05.jpg)

1.  在**执行 shell**中键入`echo This is MyPassword $MyPassword`。

1.  运行作业。

1.  查看**控制台输出**：![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_06.jpg)

1.  返回**配置全局安全性**页面，单击**防止跨站点请求伪造攻击**，确保选择了**默认 Crumb 发行者**选项：![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_07.jpg)

## 工作原理...

屏蔽密码插件将密码从屏幕或控制台中删除，并用 **x** 替换，从而避免意外阅读。 除非你发现未记录的副作用或需要调试一个任务，否则你应该始终保持该插件打开状态。

### 注意

你可以在 **配置系统** 的 **自动屏蔽密码参数** 部分全局设置参数。

跨站请求伪造（[`en.wikipedia.org/wiki/Cross-site_request_forgery`](http://en.wikipedia.org/wiki/Cross-site_request_forgery)）的例子，例如，如果你意外地访问了第三方位置；该位置上的脚本尝试使你的浏览器执行一个动作（如删除一个任务），方法是让你的网页浏览器访问 Jenkins 中已知的 URL。 Jenkins 会认为浏览器是在执行你的命令，然后遵循该请求。 一旦开启了 nonce 特性，Jenkins 通过生成一个称为**nonce**的随机一次性数字来避免 CSRF，在请求的一部分返回。 这个数字不容易被知晓，并且在短时间内失效，限制了重放攻击的风险。

## 还有更多...

Jenkins 使用起来非常愉快。 这是因为 Jenkins 使得完成工作变得容易，并且可以通过插件与多种基础架构进行通信。 这意味着，在许多组织中，随着服务的有机增长，管理员的数量迅速增加。 在管理员团队习惯于能够添加任意标记的灵活性之前，考虑及早开启 HTML 转义。

考虑偶尔重播 *通过模糊测试查找 Jenkins 中的 500 错误和 XSS 攻击* 的方法，以验证消除此潜在 XSS 攻击源。

## 请参阅

+   *测试 OWASP 前十大安全问题* 的方法

+   *通过模糊测试查找 Jenkins 中的 500 错误和 XSS 攻击* 的方法

# 使用 JCaptcha 避免注册机器人

**CAPTCHA** 代表 **Completely Automated Public Turing Test to tell Computers and Humans Apart**。 最常见的 CAPTCHA 是显示为图形的连续字母和数字，你必须正确输入到文本输入框中。

如果你允许任何人在你的 Jenkins 服务器上注册账号，那么你最不想要的就是机器人（自动化脚本）创建账号，然后将其用于不礼貌的用途。 机器人具有规模经济效应，能够快速扫描互联网而且永远不会感到无聊。 CAPTCHA 是对这些愚蠢攻击的必要防御手段。

机器人的负面目的如下：

+   对你的服务器执行 **拒绝服务** (**DOS**) 攻击，例如，通过自动创建大量的重型任务

+   **分布式拒绝服务攻击** (**DDOS**)，通过利用多个 Jenkins 服务器发送大量请求来攻击其他服务器

+   通过注入不需要的广告或指向恶意网站的内容

+   通过添加永久存储并在用户意外浏览 Jenkins 站点时运行的脚本

    ### 注意

    商业动机导致犯罪分子绕过 CAPTCHA 的行为在法律案例中有着充分的记录。你可以在[`www.wired.com/2010/10/hacking-captcha/`](http://www.wired.com/2010/10/hacking-captcha/)找到其中一个案例。

## 准备就绪

确保已备份你的 Jenkins 服务器。你将修改其安全设置。很容易出现服务变更错误。

### 提示

JCaptcha 插件是基于 Java 实现的，你可以在[`jcaptcha.atlassian.net/wiki/display/general/Home`](https://jcaptcha.atlassian.net/wiki/display/general/Home)找到。

## 如何操作...

1.  以管理员身份登录。

1.  点击**配置全局安全性**链接。

1.  在**安全领域**下选择 Jenkins 自己的用户数据库。

1.  如下截图所示，选择**允许用户注册**：![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_01a.jpg)

1.  点击**保存**。

1.  浏览注册位置`http://localhost:8080/signup`。你会看到类似以下截图的内容：![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_02.jpg)

1.  在**管理 Jenkins**页面点击**管理插件**链接。

1.  选择**可用**选项卡。

1.  安装 JCaptcha 插件。

1.  在**管理 Jenkins**页面下点击**配置全局安全性**链接。

1.  在**安全领域**下选择 Jenkins 自己的用户数据库。

1.  如下截图所示，选择**在注册时启用验证码**：![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_03.jpg)

1.  点击**保存**，然后点击**注销**链接。

1.  浏览注册位置`http://localhost:8080/signup`。该页面现在通过 CAPTCHA 进行了防御，如下截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_04.jpg)

## 工作原理...

安装该插件将在注册流程中添加 CAPTCHA 图像。图像需要模式识别才能解读。人类在这方面非常擅长；自动化流程则要差得多，但在不断改善。

## 还有更多...

这里有几个你可以考虑的要点。

### 深度防御

防御方法（如 CAPTCHA）与进攻方法（如越来越智能的机器人）之间存在一场竞赛。没有一种解决方案能将风险降至零。最佳实践是考虑采用分层方法。根据你的要求，考虑添加身份验证、限制访问到已知 IP 地址、备份配置、审查日志文件、漏洞测试以及改善站点的一般安全卫生情况。

### 提示

SANS 研究所撰写了一篇关于深度防御策略的论文[`www.sans.org/reading-room/whitepapers/basics/defense-in-depth-525`](http://www.sans.org/reading-room/whitepapers/basics/defense-in-depth-525)。

### 有关机器人的更多信息

安全竞赛仍在继续。机器人变得越来越聪明，脚本小子也更多。以下是关于这场竞赛的一些背景文章：

+   要了解更多关于脚本小子的信息，请访问[`en.wikipedia.org/wiki/Script_kiddie`](http://en.wikipedia.org/wiki/Script_kiddie)。

+   Imperva 的一份报告解释了为什么 CAPTCHA 越来越容易破解，见[`www.imperva.com/docs/HII_a_CAPTCHA_in_the_Rye.pdf`](http://www.imperva.com/docs/HII_a_CAPTCHA_in_the_Rye.pdf)。

+   谷歌正在改进模仿 CAPTCHA 的难度([`www.cnet.com/news/whats-up-bot-google-tries-new-captcha-method/`](http://www.cnet.com/news/whats-up-bot-google-tries-new-captcha-method/))。

## 另请参阅

+   *测试 OWASP 十大安全问题*配方

# 通过 Groovy 查看 Jenkins 用户

Groovy 脚本在主机服务器上作为 Jenkins 用户运行。此处介绍的配方突显了 Jenkins 应用程序和主机服务器的威力和危险性。

## 准备就绪

以管理员身份登录您的测试 Jenkins 实例。

## 如何做...

1.  从**脚本控制台**(`http://localhost:8080/script`)运行以下脚本：

    ```
    def printFile(location) {
    pub = new File(location)
    if (pub.exists()){ 
    println "Location ${location}"
    pub.eachLine{line->println line}
        } else{
    println "${location} does not exist"
        }
    }

    printFile("/etc/passwd")
    printFile("/var/lib/jenkins/.ssh/id_rsa")
    printFile("C:/Windows/System32/drivers/etc/hosts")
    ```

1.  查看输出。

    对于典型的*NIX 系统，它将类似于以下截图：

    ![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_17.jpg)

    对于 Windows 系统，它将类似于以下截图：

    ![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_16.jpg)

## 它是如何工作的...

您运行的脚本并不像看起来那么良性。Groovy 脚本可以做任何 Jenkins 用户在主机服务器上以及测试 Jenkins 服务器内具有权限执行的操作。定义了一个方法，该方法读取作为字符串传递的文件的位置。然后脚本打印内容。如果文件不存在，则也会提到。测试了三个位置。您可以轻松添加更详细的位置集。

文件的存在清晰地定义了所使用的操作系统类型和磁盘分区的结构。

`/etc/passwd`文件通常不包含密码。密码隐藏在一个影子密码文件中，安全地不可见。但是，用户名具有真实的登录帐户（不是`/bin/false`），以及它们是否具有 shell 脚本，这提示了要尝试通过专注于字典攻击来尝试破解的帐户。

如果为 Jenkins 生成私钥和公钥，则可以节省配置工作量。这允许脚本在用户的许可下运行，而无需密码登录。Jenkins 通常用于控制其从属节点。通过 Groovy 脚本检索密钥代表了更广泛基础架构的进一步危险。

如果任何插件以明文或可解密文本存储密码，则可以捕获插件的 XML 配置文件并进行解析。

您不仅可以读取文件，还可以更改权限并覆盖二进制文件，使攻击更难发现并更具侵略性。

## 更多信息...

限制风险的最佳方法是限制具有在**脚本控制台**中运行 Groovy 脚本权限的登录帐户数，并定期审查审计日志。

通过使用基于矩阵的策略，限制管理员帐户变得更加容易，你可以决定每个用户或组的权限。这一策略的一个改进是基于项目的矩阵策略，其中可以选择每个作业的权限。然而，基于项目的矩阵策略在管理方面的成本要高得多。

### 注意

自 Jenkins 的版本 1.430 以来，矩阵式安全策略暴露了额外的权限，以决定哪个组或用户可以运行 Groovy 脚本。随着时间的推移，预计会增加更多的权限。

## 另请参阅

+   *使用审计跟踪插件*配方

+   *通过自定义组脚本审查项目矩阵策略*配方

# 使用审计跟踪插件

任务可能会失败。如果你能看到最后运行任务的人以及他们做了什么改变，可以加快调试速度。这个配方确保你已经启用了审计，并创建了一组本地审计日志，其中包含大量事件的历史记录，而不是默认定义的小日志大小。

## 准备工作

安装审计跟踪插件（[`wiki.jenkins-ci.org/display/JENKINS/Audit+Trail+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Audit+Trail+Plugin)）。

## 如何操作...

1.  访问**配置 Jenkins**屏幕（`http://localhost:8080/configure`）。

1.  在**审计跟踪**部分，点击**添加记录器**按钮。

1.  修改**审计跟踪**的默认设置以允许长时间的观察。将**日志文件大小 MB**更改为`128`，**日志文件计数**更改为`40`。

1.  点击**高级...**按钮以审查所有设置。![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_08a.jpg)

## 工作原理...

审计插件创建了一个名为**审计跟踪**的日志记录器（[`wiki.jenkins-ci.org/display/JENKINS/Logger+Configuration`](https://wiki.jenkins-ci.org/display/JENKINS/Logger+Configuration)）。你可以访问日志的**记录器**页面，网址为`http://localhost:8080/log/?`来查看哪些记录器正在记录。

日志记录器的输出通过 Jenkins 配置屏幕中看到的**URL 模式来记录**进行过滤。你会发现日志文件格式比大多数日志更易读，以日期时间戳开始，日志中间描述正在发生的事情，并在最后指明操作的用户。看看以下示例：

*2011 年 7 月 18 日下午 3:18:51 由用户 Alan 启动的 job/Fulltests_1/ #3*

*2011 年 7 月 18 日下午 3:19:22 /job/Fulltests_1/configSubmit by Alan*

现在清楚地知道谁什么时候做了什么。

### 注意

考虑将`audit.log`文件本身放在版本控制系统下。这样做有三个主要原因。首先是在存储故障的情况下。第二个是为了使更难以修改审计日志而不留下证据。最后，这是一个集中收集整个企业的小日志文件的地方。

## 还有更多...

这里还有一些你应该考虑的东西。

### 一个补充插件 - JobConfigHistory

一个补充插件，用于跟踪配置更改并在作业内部显示信息，称为 JobConfigHistory 插件 ([`wiki.jenkins-ci.org/display/JENKINS/JobConfigHistory+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/JobConfigHistory+Plugin))。该插件的优点是您可以看到谁做了这些关键更改。缺点是它向潜在的完整 GUI 添加了一个图标，为其他功能留下了较少的空间。

### 缺少审计日志

对于安全官员来说，略微偏执有所帮助。如果您的审计日志突然丢失，那么这很可能是黑客希望掩盖其踪迹的迹象。如果一个文件丢失或审计时间出现间隙，这也是真实的。即使这是由于配置问题或损坏的文件系统引起的，您也应该调查。缺少日志应触发对相关服务器的更广泛审查。至少，审计插件的行为与预期不符。

考虑为这些极具价值的日志添加一个小的报告脚本。例如，考虑修改 第三章中的*在 Jenkins 中报告替代代码度量*配方，*构建软件*，以解析日志文件并制作随后以图形显示的度量。这使您可以随着时间查看团队工作的起伏。当然，数据可以伪造，但这需要额外的努力。

### 注意

减少日志文件篡改风险的一种方法是将日志事件发送到中央远程 syslog 服务器。您可以配置审计追踪插件以与**配置系统**页面中的 syslog 配合使用。

### Swatch

您可以想象一种情况，您不希望某些用户运行 Groovy 脚本，并且希望在发生意外操作时收到电子邮件。如果您想要立即对特定日志模式做出反应且尚未有基础设施，请考虑使用 Swatch，这是一个开源产品，可以在大多数 *NIX 发行版中免费使用。([`sourceforge.net/projects/swatch/`](http://sourceforge.net/projects/swatch/) 和 [`www.jaxmag.com/itr/online_artikel/psecom,id,766,nodeid,147.html`](http://www.jaxmag.com/itr/online_artikel/psecom,id,766,nodeid,147.html))。

Swatch 是一个 Perl 脚本，定期审查日志。如果发现模式，则通过电子邮件或执行命令做出反应。

## 另请参阅

+   *通过小的配置更改改善安全性*配方

+   *通过 Groovy 查看 Jenkins 用户*配方

+   第三章中的*在 Jenkins 中报告替代代码度量*配方，*构建软件*

# 安装 OpenLDAP

**轻量级目录访问协议**（**LDAP**）提供了一个非常流行的开放标准目录服务。它在许多组织中用于向世界展示用户信息。LDAP 还用作保存用户密码进行身份验证的中央服务，并且可以包含外部系统可能需要的路由邮件、POSIX 帐户管理以及各种其他信息。Jenkins 可以直接连接到 LDAP 进行身份验证，或间接通过 CAS SSO 服务器（[`www.jasig.org/cas`](http://www.jasig.org/cas)），后者再使用 LDAP 作为其密码容器。Jenkins 还有一个电子邮件插件（[`wiki.jenkins-ci.org/display/JENKINS/LDAP+Email+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/LDAP+Email+Plugin)），它从 LDAP 中提取其路由信息。

因为 LDAP 是一个常见的企业服务，Jenkins 在构建应用程序的测试基础设施时也可能会遇到 LDAP，作为集成测试的一部分。

本教程向您展示如何快速安装一个名为 `slapd` 的 OpenLDAP 服务器（[`www.openldap.org/`](http://www.openldap.org/)），然后通过 **LDAP 数据交换格式**（**LDIF**）添加组织、用户和组，LDIF 是一种简单的文本格式，用于存储 LDAP 记录（[`en.wikipedia.org/wiki/LDAP_Data_Interchange_Format`](http://en.wikipedia.org/wiki/LDAP_Data_Interchange_Format)）。

### 注意

Active Directory 在企业环境中也很流行。Jenkins 有一个用于 Active Directory 的插件（[`wiki.jenkins-ci.org/display/JENKINS/Active+Directory+plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Active+Directory+plugin)）。

## 准备工作

本教程假定你正在运行一个现代的基于 Debian 的 Linux，比如 Ubuntu。

### 注意

有关在 Windows 上安装 OpenLDAP 的详细说明，请参阅 [`www.userbooster.de/en/support/feature-articles/openldap-for-windows-installation.aspx`](http://www.userbooster.de/en/support/feature-articles/openldap-for-windows-installation.aspx)。

将以下 LDIF 条目保存到 `basic_example.ldif` 文件中，并将其放在您的主目录中：

```
dn: ou=mycompany,dc=nodomain
objectClass: organizationalUnit
ou: mycompany

dn: ou=people,ou=mycompany,dc=nodomain
objectClass: organizationalUnit
ou: people

dn: ou=groups,ou=mycompany,dc=nodomain
objectClass: organizationalUnit
ou: groups

dn: uid=tester1,ou=people,ou=mycompany,dc=nodomain
objectClass: inetOrgPerson
uid: tester1
sn: Tester
cn: I AM A Tester
displayName: tester1 Tester
userPassword: changeme
mail: tester1.tester@dev.null

dn: cn=dev,ou=groups,ou=mycompany,dc=nodomain
objectclass: groupofnames
cn: Development
description: Group for Development projects
member: uid=tester1,ou=people,dc=mycompany,dc=nodomain

```

## 如何做...

1.  通过执行以下命令安装 LDAP 服务器 `slapd`：

    ```
    sudo apt-get install slapdldap-utils

    ```

1.  当询问时，请填写管理员密码。

1.  从命令行添加 LDIF 记录；然后会要求输入你在第 2 步中使用的管理员密码。执行以下命令：

    ```
    ldapadd -x -D cn=admin,dc=nodomain -W -f ./basic_example.ldif

    ```

## 工作原理...

LDIF 是 LDAP 中记录的文本表达形式。

+   **区别名称**（**dn**）：这是每个记录的唯一标识符，结构化使对象驻留在组织树结构中。

+   `objectClass`：`objectClass`，比如 `organizationalUnit`，定义了一组必需和可选属性。在 `organizationalUnit` 的情况下，`ou` 属性是必需的。这对于捆绑定义目的的属性很有用，比如创建属于一个组织结构的属性或拥有电子邮件帐户。

在示例中，在安装 LDAP 服务器后，我们通过包安装期间创建的管理员帐户（默认`dn:cn=admin,dc=nodomain`）导入了数据；如果是这种情况，您将需要更改示例第 2 步中`-D`选项的值。

管理员帐户的默认`dn`可能会有所不同，这取决于您安装了哪个版本的 slapd。

LDIF 创建了一个具有三个组织单位的组织结构：

+   `dn`：ou=mycompany,dc=nodomain

+   `dn`：ou=people,ou=mycompany,dc=nodomain：搜索人员的位置

+   `dn`：ou=groups,ou=mycompany,dc=nodomain：搜索组的位置

为了测试，创建了一个用户（`dn: uid=tester1,ou=people,ou=mycompany,dc=nodomain`）。记录必须具有的属性列表由`inetOrgPerson`对象类定义。

通过`groupOfNames`对象类创建了一个组（`dn: cn=dev,ou=groups,ou=mycompany,dc=nodomain`）。通过添加指向用户的`dn`的成员属性，将用户添加到组中。

Jenkins 查找用户名以及用户所属的组。在 Jenkins 中，您可以根据他们的组信息定义用户可以配置哪些项目。因此，您应考虑添加与您的 Jenkins 作业结构匹配的组，例如开发、验收，以及为那些需要全局权限的人员添加一个组。

## 更多信息...

这个 LDIF 示例没有涵盖添加`objectClass`和**访问控制列表**（**ACLs**）：

+   `objectClass`：LDAP 使用`objectClass`对传入的记录创建请求进行检查。如果记录中不存在所需的属性，或者类型错误，则 LDAP 将拒绝数据。有时需要添加一个新的`objectClass`；您可以使用图形工具完成此操作。*管理 OpenLDAP*示例展示了这样一个工具。

+   **访问控制列表**：这些定义了哪个用户或哪个组可以做什么。有关这个复杂主题的信息，请访问[`www.openldap.org/doc/admin24/access-control.html`](http://www.openldap.org/doc/admin24/access-control.html)。您还可以从`man slapd.access`命令行中查看您的 OpenLDAP 服务器的主要入口。

## 另请参阅

+   *管理 OpenLDAP*示例

+   *配置 LDAP 插件*示例

# 使用脚本领域认证进行配置

对于许多企业应用程序，配置发生在用户首次登录时。例如，可以创建带有内容的目录，将用户添加到电子邮件分发列表，修改访问控制列表，或者向市场部门发送电子邮件。

这个示例将向您展示如何使用两个脚本：一个用于通过 LDAP 登录并执行示例配置，另一个用于返回用户所属的组列表。这两个脚本都使用 Perl，这使得代码紧凑。

## 准备工作

您需要安装 Perl 和`Net::LDAP`模块。对于 Debian 发行版，您应通过以下命令安装`libnet-ldap-perl`软件包：

```
sudo apt-get install libnet-ldap-perl

```

你还需要安装 Script Realm 插件（[`wiki.jenkins-ci.org/display/JENKINS/Script+Security+Realm`](https://wiki.jenkins-ci.org/display/JENKINS/Script+Security+Realm)）。

## 如何做到...

1.  作为 Jenkins 用户，将以下文件放置在 Jenkins 控制的目录下，并赋予可执行权限。将文件命名为 `login.pl`。确保 `$home` 变量指向正确的工作空间：

    ```
    #!/usr/bin/perl
    use Net::LDAP;
    use Net::LDAP::Utilqw(ldap_error_text);

    my $dn_part="ou=people,ou=mycompany,dc=nodomain";
    my $home="/var/lib/jenkins/userContent";
    my $user=$ENV{'U'};
    my $pass=$ENV{'P'};

    my $ldap = Net::LDAP->new("localhost");
    my $result =$ldap->bind("uid=$user,$dn_part", password=>$pass);
    if ($result->code){
    my $message=ldap_error_text($result->code);
    print "dn=$dn\nError Message: $message\n";
    exit(1);
        }
    # Do some provisioning
    unless (-e  "$home/$user.html"){
    open(HTML, ">$home/$user.html");
    print HTML "Hello <b>$user</b> here is some information";
    close(HTML);
    }
    exit(0);
    ```

1.  作为 Jenkins 用户，将以下文件放置在 Jenkins 控制的目录下，并赋予可执行权限。将文件命名为 `group.pl`：

    ```
    #!/usr/bin/perl
    print "guest,all";
    exit(0);
    ```

1.  通过 **全局安全配置** 屏幕下的 **安全领域** 子部分配置插件，然后添加以下详细信息：

    +   检查 **通过自定义脚本进行身份验证**

    +   **登录命令**：`/var/lib/Jenkins/login.pl`

    +   **分组命令**：`/var/lib/Jenkins/group.pl`

    +   **分组分隔符**

1.  点击 **保存** 按钮。

1.  使用用户名 `tester1` 和密码 `changeme` 登录。

1.  访问 `http://localhost:8080/userContent/tester1.html` 中的配置内容。你会看到以下截图：![如何做到...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_09.jpg)

## 工作原理...

`login.pl` 脚本从环境变量 `U` 和 `P` 中提取用户名和密码。然后脚本尝试将用户自绑定到计算出的唯一 LDAP 记录。例如，用户 `tester1` 的专有名称是 `uid=tester1, ou=people,ou=mycompany,dc=nodomain`。

### 注

自绑定发生在你搜索自己的 LDAP 记录并同时进行身份验证时。这种方法的优点是允许你的应用程序在不使用全局管理帐户的情况下测试密码的真实性。

如果身份验证失败，则返回退出码 `1`。如果身份验证成功，则进行配置过程，然后返回退出码 `0`。

如果文件尚不存在，则会创建它。在配置过程中会创建一个简单的 HTML 文件。这只是一个示例；你可以做更多的事情，从发送电子邮件提醒到在整个组织范围内进行完整的帐户配置。

`group.pl` 脚本简单地返回包括每个用户的两个组，即 guests 和 all。Guest 是仅供访客使用的组。All 是所有用户（包括访客）都属于的组。稍后，如果你想发送关于服务维护的电子邮件，那么你可以使用 LDAP 查询通过 all 组收集电子邮件地址。

## 还有更多...

根据所使用的模式，LDAP 服务器用于多种目的。你可以路由邮件、创建登录帐户等。这些帐户由常见的认证平台强制执行，如**可插拔认证模块**（**PAM**），特别是 `PAM_LDAP`（[`www.padl.com/OSS/pam_ldap.html`](http://www.padl.com/OSS/pam_ldap.html) 和 [`www.yolinux.com/TUTORIALS/LDAP_Authentication.html`](http://www.yolinux.com/TUTORIALS/LDAP_Authentication.html)）。

在阿姆斯特丹大学，我们使用自定义架构，以便用户记录具有一个用于倒计时记录的属性。计划任务执行对计数器的 LDAP 搜索，然后将计数器递减一。任务注意到当计数器达到某些数字时，并执行诸如发送电子邮件警告之类的操作。

您可以想象将此方法与自定义登录脚本结合使用。一旦顾问首次登录 Jenkins，他们将在将其 LDAP 记录移至“待忽略”分支之前获得一定的宽限期。

## 另请参阅

+   *通过自定义组脚本审查基于项目的矩阵策略*示例

# 通过自定义组脚本审查基于项目的矩阵策略

安全最佳实践要求您应该将个别用户的权限限制到他们所需的级别。

本示例探讨了基于项目的矩阵策略。在此策略中，您可以逐个作业地为个别用户或组分配不同的权限。

本示例使用启用了 Script Security 插件的自定义领域脚本，允许您使用任何长度大于五个字符的名称和密码登录，并将测试用户放置在其自己的独特组中。这将允许您测试基于项目的矩阵策略。

使用自定义脚本进行用户认证和定义组，使您的测试 Jenkins 服务器能够连接到各种非标准的身份验证服务。

## 准备就绪

您需要安装 Script Security Realm 插件 ([`wiki.jenkins-ci.org/display/JENKINS/Script+Security+Realm`](https://wiki.jenkins-ci.org/display/JENKINS/Script+Security+Realm)) 并且还要安装具有 URI 模块的 Perl ([`search.cpan.org/dist/URI/URI/Escape.pm`](http://search.cpan.org/dist/URI/URI/Escape.pm))。URI 模块包含在现代 Perl 发行版中，因此在大多数情况下，脚本将直接运行。

## 操作步骤...

1.  将以下脚本复制到 Jenkins 工作区的`login2.pl`文件中：

    ```
    #!/usr/bin/perl
    my $user=$ENV{'U'};
    my $pass=$ENV{'P'};
    my $min=5;

    if ((length($user) < $min) || (length($pass) < $min)) {
        //Do something here for failed logins
    exit (-1);
    }
    exit(0);
    ```

1.  将脚本的所有者和组更改为`jenkins`，如下所示：

    ```
    sudo chown jenkins:jenkins /var/lib/jenkins/login2.pl

    ```

1.  将以下脚本复制到 Jenkins 工作区的`group2.pl`文件中：

    ```
    #!/usr/bin/perl
    use URI;
    use URI::Escape;
    my $raw_user=$ENV{'U'};
    my $group=uri_escape($raw_user);
    print "grp_$group";
    exit(0);
    ```

1.  将脚本的所有者和组更改为`jenkins`，如下所示：

    ```
    sudo chown jenkins:jenkins /var/lib/jenkins/group2.pl

    ```

1.  在**全局安全性配置**屏幕下的**安全域**子部分配置插件。

1.  选择**通过自定义脚本进行身份验证**单选按钮，并添加以下详细信息：![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_19.jpg)

1.  选中**基于项目的矩阵授权策略**复选框。

1.  添加名为`adm_alan`的用户并授予完整权限，如下截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_10.jpg)

1.  点击**保存**按钮。

1.  尝试以密码少于五个字符登录`adm_alan`。

1.  以`adm_alan`登录，密码大于五个字符即可。

1.  创建一个名为`project_matrix_test`且无配置的新作业。

1.  在作业中选中**启用基于项目的安全性**复选框。

1.  添加`grp_proj_tester`组的完全权限（例如，选中所有复选框）：![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_11.jpg)

1.  以用户`I_cant_see_you`身份登录。注意，您无法查看最近创建的作业`project_matrix_test`。

1.  以`proj_tester`身份登录。注意，您现在可以查看和配置`project_matrix_test`。

## 它是如何工作的...

`login2.pl`脚本允许任何用户名-密码组合成功登录，只要它至少是`$min`变量定义的长度。

`group2.pl`脚本从环境中读取用户名，然后转义名称，以确保以后不会意外运行任何恶意脚本。`group2.pl`脚本将用户放入`grp_username`组中。例如，如果`proj_tester`登录，则属于`grp_proj_tester`组。

组脚本允许我们以任意用户身份登录并查看用户的权限。在基于项目的矩阵策略中，用户或组的权限在两个级别上定义：

+   通过 Jenkins 配置页面进行全局设置。这是您应该为系统范围管理定义全局账户的地方。

+   通过作业配置屏幕的每个项目。全局账户可以获得额外的项目权限，但不能失去权限。

在这个示例中，您以一个行为类似根管理员的全局账户`adm_alan`登录。然后，您以`I_cant_see_you`登录；这根本没有额外权限，甚至看不到作业首页。最后，您以`proj_tester`登录，他属于`grp_proj_tester`组，具有特定作业的完全权限。

使用每个项目的权限，不仅限制个人用户的权力，还可以确定他们可以查看哪些项目。这个功能对于拥有大量作业的 Jenkins 主服务器特别有用。

## 还有更多...

还有一些事情您应该考虑。

### 我自己的自定义安全漏洞

我希望您已经发现了这一点。登录脚本存在一个重大的安全缺陷。由`U`变量定义的用户名输入未经检查是否有恶意内容。例如，用户名可以如下：

```
<script>alert('Do something');</script>
```

稍后，如果任意插件将用户名显示为自定义视图的一部分，那么如果插件没有安全转义，用户名将在最终用户的浏览器中运行。这个例子展示了安全性出错有多容易。最好在可以的时候使用知名且受信任的库。例如，OWASP 的 Java 特定`AntiSamy`库（[`www.owasp.org/index.php/Category:OWASP_AntiSamy_Project`](https://www.owasp.org/index.php/Category:OWASP_AntiSamy_Project)）在过滤 CSS 或 HTML 片段形式的输入方面表现出色。

对于 Perl，在这个主题上有很多优秀的文章，比如[`www.perl.com/pub/2002/02/20/css.html`](http://www.perl.com/pub/2002/02/20/css.html)。

### 静态代码审查、污点标记和去污点标记

静态代码审查是指读取未运行的代码并查找已知代码缺陷的工具。PMD 和 FindBugs 是很好的示例（[`fsmsh.com/2804.com`](http://fsmsh.com/2804.com)）。这些通用工具之一可以检查您的代码以查找安全缺陷。采取的一种方法是如果输入来自外部来源（例如 Internet）或直接来自文件，则将其视为输入污染。要解除污染，必须首先将输入传递给正则表达式，并安全地转义、移除或报告不需要的输入。

## 另请参阅

+   *使用脚本领域身份验证进行配置*教程

# OpenLDAP 管理

本教程是 LDAP 管理的快速入门。它详细介绍了如何通过命令行添加或删除用户记录，并强调了使用示例 LDAP 浏览器的方法。这些技能对于维护用于集成测试或 Jenkins 帐户管理的 LDAP 服务器非常有用。

## 准备工作

要尝试此操作，您需要安装带有`Net::LDAP`模块的 Perl。例如，对于 Debian 发行版，您应该安装`libnet-ldap-perl`包（[`ldap.perl.org`](http://ldap.perl.org)）。

您还需要安装 LDAP 浏览器 JExplorer（[`jxplorer.org/`](http://jxplorer.org/)）。

## 如何做...

1.  要将用户添加到 LDAP，您需要将以下 LDIF 记录写入名为`basic_example.ldif`的文件中：

    ```
    dn: uid=tester121,ou=people,ou=mycompany,dc=nodomain
    objectClass: inetOrgPerson
    uid: tester121
    sn: Tester
    givenName: Tester121 Tester
    cn: Tester121 Tester
    displayName: Tester121 Tester
    userPassword: changeme
    mail: 121.tester@dev.null
    ```

1.  在记录末尾添加一行，并将前一条记录复制到文本文件中，在第二条记录中将数字`121`替换为`122`。

1.  运行以下`ldapadd`命令，并在询问时输入 LDAP 管理员密码。

    ```
    ldapadd -x -D cn=admin,dc=nodomain -W -f ./basic_example.ldif

    ```

1.  运行 Jxplorer，连接以下值：

    +   **主机**：`localhost`

    +   **级别**：`Anonymous`

    +   选择**Schema**选项卡，然后在**objectClasses**下选择**account**。

    +   在**Table Editor**中，您会看到以**MAY**或**MUST**提及的属性：

    ![如何做...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_12a.jpg)

1.  通过选择**文件**，然后选择**断开连接**来断开与`Anonymous`帐户的连接。

1.  选择**文件**，然后选择**连接**，以`admin`帐户重新连接。添加以下细节：

    +   **主机**：**Localhost**

    +   **级别**：用户+密码

    +   **用户 DN**：`cn=admin,dc=nodomain`

    +   **密码**：您的密码

1.  在**Explore**选项卡下，选择**tester1**。

1.  在**Table Editor**中，将**1021 XT**值添加到**postalCode**中，然后单击**提交**。

1.  在屏幕顶部选择**LDIF**菜单选项，然后单击**Export Subtree**。

1.  单击**确定**按钮，然后编写要将 LDIF 导出到的文件的名称，然后单击**保存**。

1.  创建具有以下代码行的可执行脚本并运行它：

    ```
    #!/usr/bin/perl
    use Net::LDAP;
    use Net::LDAP::Utilqw(ldap_error_text);

    my $number_users=2;
    my $counter=0;
    my $start=100;

    my $ldap = Net::LDAP->new("localhost");
    $ldap->bind("cn=admin,dc=nodomain",password=>"your_password");

    while ($counter < $number_users){
      $counter++;
        $total=$counter+$start;
    my $dn="uid=tester$total,ou=people,ou=mycompany,dc=nodomain";
    my $result = $ldap->delete($dn); 
    if ($result->code){
    my $message=ldap_error_text($result->code);
    print "dn=$dn\nError Message: $message\n";
        }
    }
    ```

## 工作原理...

在这个示例中，你已经执行了一系列任务。 首先，你使用一个 LDIF 文件添加了两个用户。 这对于小组织中的 LDAP 管理员来说是一个典型的事件。 你可以保存 LDIF 文件，然后进行小的修改以添加或删除用户、组等。

接下来，通过 LDAP 浏览器（在本例中是 Jxplorer）匿名查看了目录结构。 Jxplorer 可以在各种操作系统上运行，并且是开源的。 你的操作突显出 LDAP 是一个企业目录服务，即使是匿名用户也能找到其中的内容。 在 Jxplorer 中页面快速渲染的事实突显出 LDAP 是一个读取优化的数据库，能够高效返回搜索结果。

当要呈现的对象数量增加时，使用 LDAP 浏览器通常会更加令人沮丧。 例如，在阿姆斯特丹大学，有超过 60,000 个学生记录在一个分支下。 在这些情况下，你被迫使用命令行工具或者对搜索过滤器非常小心。

能够查看`ObjectClass`，了解你*可能*使用的属性以及哪些属性是必须使用的，可以帮助你优化你的记录。

接下来，你以管理员用户绑定（执行某些操作）并操作 tester1 的记录。 对于小组织来说，这是一种高效的管理方式。 将记录导出为 LDIF 文件允许你将该记录用作进一步导入记录的模板。

删除脚本是程序控制的一个示例。 这给了你在通过改变几个变量而实现大规模生成、修改和删除记录时很大的灵活性。 Perl 之所以被选择，是因为它的减少冗长性。 这种类型脚本的使用对于整合测试的配置是很典型的。

在删除脚本中，你会看到要删除的用户数量被设置为 2，测试账号的起始值为 100。 这意味着之前生成的两个记录将被删除，例如`tester101`和`tester102`。

这个脚本首先以管理员账号绑定一次，然后通过使用`$counter`来计算每个记录的专有名称，循环处理一系列记录。 对每个记录调用删除方法，任何生成的错误都将被打印出来。

## 还有更多内容...

你应该考虑删除用户的 Perl 脚本，作为整合测试中高效进行 LDAP 服务器配置或清理的示例。 要创建一个添加脚本而不是删除脚本，你可以编写类似的脚本，用以下行代码替换我的`$result = $ldap->delete($dn)`：

```
my$result=$ldap->add($dn,attrs=>[ @$whatToCreate]);
```

这里，`@$whatTOCreate`是一个包含属性和`objectClass`的哈希。 获取更多示例，请访问[`search.cpan.org/~gbarr/perl-ldap/lib/Net/LDAP/Examples.pod#OPERATION_-_Adding_a_new_Record`](http://search.cpan.org/~gbarr/perl-ldap/lib/Net/LDAP/Examples.pod#OPERATION_-_Adding_a_new_Record)。

## 参见

+   *安装 OpenLDAP*配方

+   *配置 LDAP 插件*配方

# 配置 LDAP 插件

LDAP 是企业目录服务的标准。 本配方解释了如何将 Jenkins 连接到您的测试 LDAP 服务器。

## 准备工作

若要尝试此方法，您应首先执行*安装 OpenLDAP*配方中提到的步骤。

## 如何实现...

1.  转到**配置全局安全性**屏幕并选择**启用安全性**。

1.  勾选**LDAP**复选框。

1.  将**服务器**值添加为`127.0.0.1`。

1.  单击**高级**按钮，然后添加以下详细信息：

    +   **用户搜索基础**：`ou=people,ou=mycompany,dc=nodomain`

    +   **用户搜索过滤器**：`uid={0}`

    +   **组搜索基础**：`ou=groups,ou=mycompany,dc=nodomain`

## 工作原理...

测试 LDAP 服务器支持匿名绑定：您可以在未验证的情况下搜索服务器。 大多数 LDAP 服务器都允许这种方法。 但是，一些服务器配置为执行特定的信息安全策略。 例如，您的策略可能强制要求能够匿名验证用户记录是否存在，但您可能无法检索特定属性，例如他们的电子邮件或邮政地址。

匿名绑定简化了配置；否则，您需要为 LDAP 中具有执行搜索权限的用户添加帐户详细信息。 这个账号拥有强大的 LDAP 权限，绝不能共享，并且可能会在您的安全防线中出现漏洞。

用户搜索过滤器`uid={0}`用于查找其`uid`等于用户名的用户。 许多组织更喜欢使用`cn`而不是`uid`； 属性的选择是一种品味问题。 您甚至可以想象使用电子邮件属性来唯一标识一个人，只要该属性不能被用户更改。

### 提示

**安全领域**

当您登录时，将调用`hudson.security.LDAPSecurityRealm`类的一个实例。 代码定义在 Groovy 脚本中，您可以在`Jenkins.war`文件内的**WEB-INF/security/LDAPBindSecurityRealm.groovy**中找到。

欲了解更多信息，请访问[`wiki.hudson-ci.org/display/HUDSON/Standard+Security+Setup`](http://wiki.hudson-ci.org/display/HUDSON/Standard+Security+Setup)。

## 有更多内容...

以下是您需要考虑的一些事情。

### 配置错误与坏凭据之间的区别

首次配置 LDAP 插件时，您的身份验证过程可能由于配置错误而失败。幸运的是，Jenkins 会生成错误消息。 对于 Debian Jenkins 软件包，您可以在`/var/log/jenkins/jenkins.log`中找到日志文件。 对于作为服务运行的 Windows 版本，您可以通过在 Jenkins 源上过滤来查找相关日志查看器中的事件。

两个主要经常出现的错误如下：

+   **用户搜索基础或组搜索基础的配置错误**：相关日志条目将如下所示：

    ```
    org.acegisecurity.AuthenticationServiceException: LdapCallback;[LDAP: error code 32 - No Such Object]; nested exception is javax.naming.NameNotFoundException: [LDAP: error code 32 - No Such Object]; remaining name 'ou=people,dc=mycompany ,dc=nodomain'

    ```

+   **凭证错误**：如果用户不存在于 LDAP 中，您可能要么输入了错误的密码，要么意外地搜索了 LDAP 树的错误部分。因此，日志错误将以以下文本开头：

    ```
    org.acegisecurity.BadCredentialsException: Bad credentials

    ```

### 搜索

应用程序以多种方式从 LDAP 中检索信息：

+   **匿名获取一般信息**：这种方法仅适用于向世界公开的信息。但是，LDAP 服务器也可以将搜索查询限制为特定的 IP 地址。应用程序将取决于您的组织准备披露的属性。如果信息安全政策发生变化，则可能导致应用程序意外中断。

+   **自绑定**：应用程序绑定为用户，然后使用该用户的权限进行搜索。这种方法最清晰。但是，在日志记录中并不总是清楚应用程序背后的操作。

+   **使用具有许多权限的特定于应用程序的管理员帐户**：该帐户获取您的应用程序所需的所有信息，但如果泄露给错误的人，可能会迅速引起重大问题。

    ### 注意

    如果 LDAP 服务器有账户锁定策略，那么黑客很容易锁定应用程序。

实际上，所选择的方法由企业目录服务的预定义访问控制策略定义。

### 小贴士

**审查插件配置**

目前，Jenkins 有超过 600 个插件。虽然偶尔可能会在工作区目录或插件目录中的 XML 配置文件中以纯文本存储密码，但这种情况可能性很小。每次安装需要超级用户账户的新插件时，都应仔细检查相关的配置文件。如果看到纯文本，应编写一个附带补丁的错误报告。

## 另请参阅

+   *安装 OpenLDAP* 配方

+   *管理 OpenLDAP* 配方

# 安装 CAS 服务器

Yale CAS ([`www.jasig.org/cas`](http://www.jasig.org/cas)) 是一个单点登录服务器。它被设计为校园范围的解决方案，因此易于安装并且相对简单地配置以满足您特定的基础设施需求。CAS 允许您登录一次，然后在不再登录的情况下自动使用许多不同的应用程序。这使得用户在一天中使用的典型 Jenkins 用户的应用程序范围内的互动更加愉快。

Yale CAS 在 Java 和 PHP 中有辅助库，可简化第三方应用程序的集成。

Yale CAS 还具有一个可插拔的处理程序集合的显着优势，该处理程序集合通过一系列后端服务器进行身份验证，例如 LDAP、openid ([`openid.net/`](http://openid.net/)) 和 radius ([`en.wikipedia.org/wiki/RADIUS`](http://en.wikipedia.org/wiki/RADIUS))。

在此示例中，您将安装完整版本的 CAS 服务器，从 Tomcat 7 服务器内运行。这个示例比本章中的其他示例更详细，而且很容易配置错误。本示例中提到的修改后的配置文件可从书籍网站下载。

## 准备工作

从 3.4 系列中下载 Yale CAS ([`www.apereo.org/cas/download`](https://www.apereo.org/cas/download)) 并解压缩。本文档是使用版本 3.4.12.1 编写的，但应该可以在 3.4 系列的早期或晚期版本中进行少量修改后运行。

安装 Tomcat 7 ([`tomcat.apache.org/download-70.cgi`](http://tomcat.apache.org/download-70.cgi))。本文档假定已安装的 Tomcat 服务器最初处于关闭状态。

### 注意

从 2014 年 6 月起，CAS 4 文档已从 JASIG 网站移至 [`jasig.github.io/cas/4.0.x/index.html`](http://jasig.github.io/cas/4.0.x/index.html)。

## 如何操作...

1.  在解压缩的 Tomcat 目录中，编辑 `conf/server.xml`，注释掉端口 `8080` 的配置信息，如下所示：

    ```
    <!--
    <Connector port="8080" protocol="HTTP/1.1"   …..
    -->
    ```

1.  在需要启用 SSL 的端口 `9443` 下面添加以下内容：

    ```
    <Connector port="9443"  protocol="org.apache.coyote.http11.Http11Protocol" SSLEnabled="true"
    maxThreads="150" scheme="https" secure="true"
    keystoreFile="${user.home}/.keystore" keystorePass="changeit"
    clientAuth="false" sslProtocol="TLS" />
    ```

1.  Tomcat 将以哪个用户身份运行，可以通过以下命令创建自签名证书：

    ```
    keytool -genkey -alias tomcat -keyalg RSA

    ```

    ### 注意

    如果在你的 `PATH` 环境变量中找不到 `keytool`，那么你可能需要填写已安装的 Java 的 `bin` 目录的完整路径。

1.  从解压缩的 CAS 服务器根目录下方，复制 `modules/cas-server-uber-webapp-3.x.x` 文件（其中 `x.x` 是具体版本号）到 Tomcat Web 应用程序的目录，确保文件重命名为 `cas.war`。

1.  启动 Tomcat。

1.  使用用户名等于密码，例如，`smile`/`smile`，通过 `https://localhost:9443/cas/login` 登录。

1.  停止 Tomcat。

1.  要么修改 `webapps/cas/Web-INF/deployerConfigContext.xml` 文件，要么替换为先前从书籍网站下载的示例文件。要进行修改，你需要注释掉 `SimpleTestUsernamePasswordAuthenticationHandler` 行，如下所示：

    ```
    <!--
      <bean class="org.jasig.cas.authentication.handler.support.SimpleTestUsernamePasswordAuthenticationHandler" />
    -->
    ```

1.  在注释掉的代码下面，添加 LDAP 的配置信息：

    ```
    <bean  class="org.jasig.cas.adaptors.ldap.BindLdapAuthenticationHandler">
    <property name="filter" value="uid=%u" />
    <property name="searchBase" value="ou=people,ou=mycompany,dc=nodomain" />
    <property name="contextSource" ref="contextSource" />
    </bean>
    </list>
    </property>
    </bean>
    ```

1.  在 `</bean>` 后添加额外的 bean 配置，将 `password value` 替换为你自己的密码：

    ```
    <bean id="contextSource" class="org.springframework.ldap.core.support.LdapContextSource">
    <property name="pooled" value="false"/>
    <property name="urls">
    <list>
    <value>ldap://localhost/</value>
    </list>
    </property>
    <property name="userDn" value="cn=admin,dc=nodomain"/>
    <property name="password" value="adminpassword"/>
    <property name="baseEnvironmentProperties">
    <map>
    <entry>
    <key><value>java.naming.security.authentication</value>
    </key>
    <value>simple</value>
    </entry>
    </map>
    </property>
    </bean>
    ```

    重新启动 Tomcat。

1.  使用 `tester1` 帐户通过 `https://localhost:9443/cas/login` 登录。如果看到类似以下截图的页面，恭喜你；你现在已经运行了 SSO!![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_15.jpg)

## 工作原理...

默认情况下，Tomcat 运行在端口 `8080` 上，这恰好是 Jenkins 的端口号。要将端口号更改为 `9443` 并启用 SSL，您必须修改 `conf/server.xml`。为了让 SSL 正常工作，Tomcat 需要一个带有私有证书的密钥库。使用 `${user.home}` 变量指向 Tomcat 用户的主目录，例如，`keystoreFile="${user.home}/.keystore" keystorePass="changeit"`。

您选择的协议是 TLS，这是 SSL 的一个较新且安全的版本。有关更多详细信息，请访问[`tomcat.apache.org/tomcat-7.0-doc/ssl-howto.html`](http://tomcat.apache.org/tomcat-7.0-doc/ssl-howto.html)。

接下来，生成一个证书并将其放置在 Tomcat 用户的证书存储中，准备供 Tomcat 使用。您的证书存储可能包含许多证书，因此`tomcat`别名唯一标识证书。

在下载的 CAS 包中，存在两个 CAS WAR 文件。较大的 WAR 文件包含所有认证处理程序的库，包括所需的 LDAP 处理程序。

默认设置允许您使用与用户名相同的密码登录。此设置仅用于演示目的。要替换或串联处理程序，您必须编辑`webapps/cas/Web-INF/deployerConfigContext.xml`。更多详细信息，请参考[`wiki.jasig.org/display/CASUM/LDAP`](https://wiki.jasig.org/display/CASUM/LDAP)。

如果在任何时候您遇到配置问题，最好检查的地方是 Tomcat 的主日志，`logs/catalina.out`。例如，错误的用户名或密码将生成以下错误：

```
WHO: [username: test]
WHAT: error.authentication.credentials.bad
ACTION: TICKET_GRANTING_TICKET_NOT_CREATED
APPLICATION: CAS
WHEN: Mon Aug 08 21:14:22 CEST 2011
CLIENT IP ADDRESS: 127.0.0.1
SERVER IP ADDRESS: 127.0.0.1

```

## 还有更多...

这里有一些您应该考虑的事情。

### 后端认证

Yale CAS 具有广泛的后端认证处理程序，对于 Java 开发人员来说，撰写自己的处理程序是直截了当的。下表列出了当前的处理程序。请注意，通过使用受支持良好的第三方框架如 JAAS 和 JDBC 实现，您可以连接到比下表中提到的更广泛的服务：

| **Active Directory** | 这连接到您的 Windows 基础设施。 |
| --- | --- |
| **JAAS** | 这实现了标准**可插入认证模块**（**PAM**）框架的 Java 版本。这允许您引入其他认证机制，如 Kerberos。 |
| **LDAP** | 这连接到您的企业目录服务。 |
| **RADIUS** | 这连接到 RADIUS。 |
| **受信任** | 这用于将一些认证卸载到 Apache 服务器或另一个 CAS 服务器。 |
| **通用** | 一组小型通用处理程序，例如从列表或文件中接受用户的处理程序。 |
| **JDBC** | 这个连接数据库，甚至还有用于电子表格和 LDAP 的驱动程序。 |
| **传统** | 这支持 CAS2 协议。 |
| **SPNEGO** | 简单和受保护的 GSSAPI 协商机制允许 CAS 服务器在后端服务之间协商协议。它潜在地允许在后端服务之间过渡。 |
| **X.509 证书** | 这需要一个可信客户端证书。 |

### 使用 ESUP CAS 的另一种安装方法

**ESUP** 联盟还提供了一个经过重新打包的 CAS 版本，包括额外的易用功能，包括一个即开即用的演示版本。然而，ESUP 版本的 CAS 服务器落后于最新版本。如果您想比较这两个版本，您可以在[`esup-casgeneric.sourceforge.net/install-esup-cas-quick-start.html`](http://esup-casgeneric.sourceforge.net/install-esup-cas-quick-start.html)找到 ESUP 的安装文档。

### 注意

ESUP 软件包比此配方更容易安装和配置；但是，它包含的是 CAS 的旧版本。

### 信任 LDAP SSL

在测试 LDAP 服务器上启用 SSL 可以避免在网络上传送可嗅探的密码，但您需要让 CAS 服务器信任 LDAP 服务器的证书。来自 JASIG WIKI 的相关引用是：

*请注意，您的 JVM 需要信任启用 SSL 的 LDAP 服务器的证书，否则 CAS 将拒绝连接到您的 LDAP 服务器。您可以将 LDAP 服务器的证书添加到 JVM 信任存储库 ($JAVA_HOME/jre/lib/security/cacerts) 中来解决此问题。*

### 几个有用的资源

在 JASIG WIKI（[`wiki.jasig.org/`](https://wiki.jasig.org/)）上有许多有用的 CAS 3.4 系列资源：

+   保护您的 CAS 服务器 ([`wiki.jasig.org/display/CASUM/Securing+Your+New+CAS+Server`](https://wiki.jasig.org/display/CASUM/Securing+Your+New+CAS+Server))

+   将 CAS 连接到数据库 ([`wiki.jasig.org/display/CAS/Examples+to+Configure+CAS`](https://wiki.jasig.org/display/CAS/Examples+to+Configure+CAS))

+   创建一个高可用基础设施 ([`www.ja-sig.org/wiki/download/attachments/22940141/HA+CAS.pdf?version=1`](http://www.ja-sig.org/wiki/download/attachments/22940141/HA+CAS.pdf?version=1))

## 另请参阅

+   *在 Jenkins 中启用 SSO* 配方

# 在 Jenkins 中启用 SSO

在这个配方中，您将通过使用 CAS1 插件在 Jenkins 中启用 CAS。为了使 CAS 协议正常工作，您还需要在 Jenkins 和 CAS 服务器之间建立信任关系。Jenkins 插件信任 CAS 服务器的证书。

## 准备就绪

要尝试此操作，您需要按照 *安装 CAS 服务器* 配方和 Cas1 插件 ([`wiki.jenkins-ci.org/display/JENKINS/CAS1+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/CAS1+Plugin)) 中描述的步骤安装 CAS 服务器。

### 注意

Cas1 插件在作者尝试过的环境中表现稳定。然而，还有第二个 CAS 插件 ([`wiki.jenkins-ci.org/display/JENKINS/CAS+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/CAS+Plugin))，旨在通过提供新功能与现有功能一起，例如支持 CAS 2.0 协议，来取代 CAS1 插件。

熟悉了这个配方后，考虑尝试使用 CAS 插件。

## 如何做…

1.  您需要导出 CAS 服务器的公共证书。通过在 Firefox 网页浏览器中访问 `http://localhost:9443` 来执行此操作。在地址栏中，您会看到一个锁定的锁图标位于左侧。点击图标；一个安全弹出对话框将出现。

1.  点击**更多信息**按钮。

1.  点击**查看证书**按钮。

1.  选择**详细信息**选项卡。

1.  点击**导出**按钮。

1.  选择公共证书存储的位置。

1.  按下**保存**。

1.  按以下方式导入到 Java 的密钥库中：

    ```
    sudo keytool -import -alias myprivateroot -keystore ./cacerts -file  location_of_exported certificate

    ```

1.  要配置您的 CAS 设置，请访问 Jenkins 中的**全局安全配置**屏幕，位于**安全领域**部分下。在**访问控制**下，勾选**CAS 协议版本 1**复选框，并添加以下详细信息：

    +   **CAS 服务器 URL**：`https://localhost:9443`

    +   **Hudson 主机名**：`localhost:8080`

1.  从 Jenkins 注销。

1.  登录 Jenkins。您现在将被重定向到 CAS 服务器。

1.  登录 CAS 服务器。您现在将被重定向回 Jenkins。

## 工作原理...

CAS 插件无法验证客户端的凭据，除非它信任 CAS 服务器证书。如果证书由知名的受信任机构生成，那么它们的**根**证书很可能已经存在于默认的密钥库（**cacerts**）中。这是随您的 Java 安装一起预先打包的。然而，在您创建的 CAS 安装配方中，您创建了一个自签名的证书。

CAS 插件的配置细节微不足道。请注意您将**角色验证脚本**字段留空。这意味着您的基于矩阵的策略将不得不依赖于用户被赋予特定权限，而不是由定制的 CAS 服务器定义的组。

恭喜，您拥有一个可以与许多其他应用程序和身份验证服务无缝配合的工作中的 SSO！

## 另请参阅

+   *安装 CAS 服务器* 配方

# 探索 OWASP 依赖检查插件

OWASP 依赖检查工具将 Java 程序和 JavaScript 库与 CVE 数据库中已知的威胁进行比较（[`cve.mitre.org/`](https://cve.mitre.org/)）。CVE 是约 69,000 个公开已知信息安全漏洞和曝光的词典。这个过程是对 OWASP 十大 A9 - 使用已知的易受攻击组件的自然防御。

CVE 数据库被用作漏洞扫描器报告问题的标准，允许工具用户使用一个通用语言来比较其软件的易受攻击程度。CVE 报告包括描述、问题首次报告位置和估计的危险级别。

### 注意

依赖检查工具并不总是准确的，因为它需要将库与漏洞联系起来，有时很难准确匹配库签名。因此，您需要根据输出审查和过滤操作。

## 准备工作

安装 OWASP 依赖检查插件。

## 如何做...

1.  点击 **管理 Jenkins** 页面中的 **配置系统** 链接。

1.  查看 **OWASP 依赖检查** 部分，如以下截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_05a.jpg)

1.  按下 **高级...** 按钮，您将得到类似以下截图的内容：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_06a.jpg)

1.  按下 **分析器...** 按钮，您将得到类似以下截图的内容：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_07a.jpg)

1.  访问 `http://localhost:8080/view/All/newJob`。

1.  创建一个名为 `OWASP` 的自由样式作业。

1.  为 **调用 OWASP 依赖检查分析** 添加一个 **构建** 步骤。

1.  在 **要扫描的路径** 字段中，键入 `/var/lib/jenkins/workspace` 或您选择的项目的路径。

1.  确保 **生成可选的 HTML 报告** 是唯一被选中的复选框。请注意，您未选择 **禁用 CPE 自动更新** 复选框：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_08.jpg)

1.  按下 **保存**。

1.  按下 **立即构建** 图标。

1.  作业完成后，请按以下工作区图标：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_09a.jpg)

1.  点击 **dependency-check-vulnerabilty.html** 链接。根据 Jenkins 工作区内运行的作业，您将看到类似以下截图的报告：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_10a.jpg)

## 工作原理...

安装插件会自动安装 OWASP 依赖检查工具。您可以在工具的主页上找到工具的主页：[`www.owasp.org/index.php/OWASP_Dependency_Check`](https://www.owasp.org/index.php/OWASP_Dependency_Check)：

![工作原理...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_11a.jpg)

通过 Jenkins 界面，您配置了工具查看 Jenkins 主目录下的每个 Java 库 `.jar` 文件。如果您的 Jenkins 服务器配置了许多作业，扫描将需要一些时间。

**禁用 CPE 自动更新** 选项未被选中。这是必要的，因为工具首次运行需要从外部 CVE 数据库下载安全信息。如果不允许此操作发生，则报告将不包含任何信息。虽然下载最新的威胁信息需要时间，但这是找到新问题的最安全方法。

## 更多内容...

在撰写本文时，Jenkins 中的依赖插件选项落后于命令行工具可用的选项。为了让您了解插件中可能的更改，从 [`www.owasp.org/index.php/OWASP_Dependency_Check`](https://www.owasp.org/index.php/OWASP_Dependency_Check) 下载命令行工具。

工具下载并解压缩后，按如下方式运行高级帮助：

```
sh dependency-check.sh –advancedHelp

```

你的输出将类似于以下截图：

![更多内容...](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/jks-ci-cb-2e/img/0082OS_02_18.jpg)

该文本后跟有一组简要的描述，涵盖了所有选项，例如：

```
-n,--noupdate             Disables the automatic updating of the CPE data.

```

选项在 Jenkins GUI 配置中反映出来，或将被反映出来。

### 注意

您可以在 GitHub 上找到该工具的最新代码源（[`github.com/jeremylong/DependencyCheck`](https://github.com/jeremylong/DependencyCheck)）。

## 另请参阅

+   Chapter 1 中的*汇报总体存储使用量*配方，*维护 Jenkins*

+   Chapter 1 中的*通过日志解析添加作业以警告存储使用违规*配方，*维护 Jenkins*
