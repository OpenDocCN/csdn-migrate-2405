# Jenkins 持续集成学习手册（一）

> 原文：[`zh.annas-archive.org/md5/AC536FD629984AF68C1E5ED6CC796F17`](https://zh.annas-archive.org/md5/AC536FD629984AF68C1E5ED6CC796F17)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

在过去的几年里，敏捷软件开发模式在全球范围内得到了相当大的增长。特别是在电子商务领域，对于一种快速灵活应对频繁修改的软件交付解决方案的需求非常巨大。因此，持续集成和持续交付方法越来越受欢迎。

无论是小项目还是大项目，都会获得诸如早期问题检测、避免糟糕的代码进入生产以及更快的交付等好处，这导致了生产力的增加。

本书，*使用 Jenkins 学习持续集成第二版*，作为一个逐步指南，通过实际示例来设置持续集成、持续交付和持续部署系统。这本书是 20% 的理论和 80% 的实践。它首先解释了持续集成的概念及其在敏捷世界中的重要性，并专门有一整章介绍这个概念。用户随后学习如何配置和设置 Jenkins，然后实现使用 Jenkins 的持续集成和持续交付。还有一个关于持续部署的小章节，主要讨论持续交付和持续部署之间的区别。

# 本书内容

第一章，*持续集成的概念*，介绍了一些最流行和广泛使用的软件开发方法如何催生了持续集成。接着详细解释了实现持续集成所需的各种要求和最佳实践。

第二章，*安装 Jenkins*，是一份关于在各种平台上安装 Jenkins 的分步指南，包括 Docker。

第三章，*新 Jenkins*，提供了新 Jenkins 2.x 的外观和感觉概述，并深入解释了其重要组成部分。它还向读者介绍了 Jenkins 2.x 中新增的功能。

第四章，*配置 Jenkins*，专注于完成一些基本的 Jenkins 管理任务。

第五章，*分布式构建*，探讨了如何使用 Docker 实现构建农场，并讨论了将独立机器添加为 Jenkins 从属节点的方法。

第六章，*安装 SonarQube 和 Artifactory*，涵盖了为持续集成安装和配置 SonarQube 和 Artifactory 的步骤。

第七章，*使用 Jenkins 进行持续集成*，带领你设计持续集成并使用 Jenkins 以及其他一些 DevOps 工具来实现它的步骤。

第八章，*使用 Jenkins 进行持续交付*，概述了持续交付的设计以及使用 Jenkins 与其他一些 DevOps 工具实现它的方法。

第九章，*使用 Jenkins 进行持续部署*，解释了持续交付与持续部署之间的区别。它还提供了使用 Jenkins 实现持续部署的逐步指南。

附录，*支持工具和安装指南*，介绍了使您的 Jenkins 服务器在互联网上可访问所需的步骤以及 Git 的安装指南。

# 本书所需的内容

要能够理解本书中描述的所有内容，您需要一台具有以下配置的计算机：

+   **操作系统**：

    +   Windows 7/8/10

    +   Ubuntu 14 及更高版本

+   **硬件要求**：

    +   至少拥有 4 GB 内存和多核处理器的计算机

+   **其他要求**：

    +   GitHub 账户（公共或私人）

# 本书面向的读者

本书旨在读者具有较少或没有敏捷或持续集成和持续交付方面的经验。对于任何新手想要利用持续集成和持续交付的好处以提高生产力并缩短交付时间的人来说，它都是一个很好的起点。

构建和发布工程师、DevOps 工程师、（软件配置管理）SCM 工程师、开发人员、测试人员和项目经理都可以从本书中受益。

已经在使用 Jenkins 进行持续集成的读者可以学习如何将他们的项目提升到下一个级别，即持续交付。

本书的当前版本是其前任的完全重启。第一版读者可以利用当前版本讨论的一些新内容，例如 Pipeline as Code、Multibranch Pipelines、Jenkins Blue Ocean、使用 Docker 的分布式构建农场等。

# 约定

在本书中，您将找到许多用于区分不同类型信息的文本样式。以下是其中一些样式的示例及其含义的解释。文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“这将在您的系统上下载一个`.hpi`文件。”

代码块设置如下：

```
stage ('Performance Testing'){
    sh '''cd /opt/jmeter/bin/
    ./jmeter.sh -n -t $WORKSPACE/src/pt/Hello_World_Test_Plan.jmx -l
    $WORKSPACE/test_report.jtl''';
    step([$class: 'ArtifactArchiver', artifacts: '**/*.jtl'])
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项将加粗显示：

```
stage ('Performance Testing'){
    sh '''cd /opt/jmeter/bin/
    ./jmeter.sh -n -t $WORKSPACE/src/pt/Hello_World_Test_Plan.jmx -l
    $WORKSPACE/test_report.jtl''';
    step([$class: 'ArtifactArchiver', artifacts: '**/*.jtl'])
}
```

在一些命令中使用的额外的“**\**”仅用于指示命令在下一行继续。任何命令行输入或输出都按以下方式编写：

```
 cd /tmp
   wget https://archive.apache.org/dist/tomcat/tomcat-8/ \
   v8.5.16/bin/apache-tomcat-8.5.16.tar.gz
```

**新术语** 和 **重要单词** 以粗体显示。屏幕上看到的单词，例如在菜单或对话框中，会以如下方式出现在文本中：“从 Jenkins 仪表板上，点击 “Manage Jenkins”|“Plugin Manager”|“Available” 选项卡。”

警告或重要提示呈现如下。

提示和技巧呈现如下。

# 读者反馈

我们始终欢迎读者的反馈。请告诉我们您对本书的看法-您喜欢或不喜欢的地方。读者反馈对我们很重要，因为它帮助我们开发让您真正受益的标题。要向我们发送一般反馈，只需发送电子邮件至`feedback@packtpub.com`，并在消息主题中提到书的标题。如果您对某个专题有专业知识，并有兴趣参与撰写或投稿书籍，请查看我们的作者指南，网址为[www.packtpub.com/authors](http://www.packtpub.com/authors)。 

# 客户支持

既然您是 Packt 书籍的自豪所有者，我们有许多措施可帮助您充分利用您的购买。

# 下载示例代码

您可以从您在 [`www.packtpub.com`](http://www.packtpub.com) 的账户下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)，注册后文件将直接发送到您的邮箱。按照以下步骤下载代码文件：

1.  使用您的电子邮件地址和密码登录或注册到我们的网站。

1.  将鼠标指针悬停在顶部的“支持”标签上。

1.  点击“代码下载 & 勘误”。

1.  在搜索框中输入书名。

1.  选择您想要下载代码文件的书籍。

1.  从下拉菜单中选择您购买本书的位置。

1.  点击“代码下载”。

下载文件后，请确保使用最新版本的解压软件解压文件夹：

+   Windows 下的 WinRAR / 7-Zip

+   Mac 下的 Zipeg / iZip / UnRarX

+   Linux 下的 7-Zip / PeaZip

本书的代码包也托管在 GitHub 上，链接为[`github.com/PacktPublishing/Learning-Continuous-Integration-with-Jenkins-Second-Edition`](https://github.com/PacktPublishing/Learning-Continuous-Integration-with-Jenkins-Second-Edition)。我们还有其他丰富的图书和视频代码包可供下载，地址为[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)。赶紧去看看吧！

# 下载本书的彩色图片

我们还为您提供了一个 PDF 文件，其中包含本书中使用的截图/图表的彩色图片。彩色图片将帮助您更好地理解输出中的变化。您可以从[`www.packtpub.com/sites/default/files/downloads/LearningContinuousIntegrationwithJenkinsSecondEdition_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/LearningContinuousIntegrationwithJenkinsSecondEdition_ColorImages.pdf)下载此文件。

# 勘误

尽管我们已经尽一切努力确保内容的准确性，但错误还是会发生。如果你在我们的书中发现了错误——也许是文本或代码中的错误——我们将不胜感激地接受您的报告。通过这样做，你可以帮助其他读者避免困扰，也可以帮助我们改进后续版本的这本书。如果你发现任何勘误，请访问 [`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择你的书，点击勘误提交表格链接，并输入勘误的详细信息。一旦你的勘误被核实，你的提交将被接受，并将勘误上传到我们的网站，或者添加到该标题的现有勘误列表的勘误部分。要查看以前提交的勘误，请访问 [`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，并在搜索字段中输入书名。所需信息将出现在勘误部分下。

# 盗版

互联网上对受版权保护的材料的盗版是所有媒体持续存在的问题。在 Packt，我们非常重视对我们的版权和许可的保护。如果你在互联网上发现我们作品的任何形式的非法副本，请立即向我们提供位置地址或网站名称，以便我们采取措施。请通过 `copyright@packtpub.com` 联系我们，并附上可疑盗版材料的链接。感谢你帮助我们保护我们的作者和我们提供有价值内容的能力。

# 问题

如果你在阅读本书的过程中遇到任何问题，可以通过 `questions@packtpub.com` 联系我们，我们将尽力解决问题。


# 第一章：持续集成的概念

我们将从介绍当今两种主要软件开发方法论开始：瀑布模型和敏捷开发。理解它们的概念和影响将帮助我们回答**持续集成**（**CI**）是如何产生的。

接下来，我们将尝试理解 CI 背后的概念及构成要素。通过阅读这些内容，您将了解到 CI 如何帮助项目实现敏捷。完成本章后，您应该能够：

+   描述 CI 是如何产生的。

+   定义什么是 CI。

+   描述 CI 的要素。

# 软件开发生命周期

对于那些对术语“软件开发生命周期”不太熟悉的人，让我们尝试理解一下。

**软件开发生命周期**，有时简称为**SDLC**，是规划、开发、测试和部署软件的过程。

团队按照一系列阶段进行工作，每个阶段都利用了其前一个阶段的结果，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/357ee6b7-7641-4d0a-93d7-88d28c7a61e5.png)

软件开发生命周期

让我们详细了解 SDLC 的各个阶段。

# 需求分析

这是循环的第一个阶段。在这里，业务团队（主要由业务分析师组成）对其项目的业务需求进行需求分析。需求可能是组织内部的，也可能是来自客户的外部需求。这项研究涉及发现需求的性质和范围。根据收集到的信息，提出了改进系统或创建新系统的建议。项目成本得到确定，并列出了利益。然后确定项目目标。

# 设计

第二阶段是设计阶段。在这里，系统架构师和系统设计师制定软件解决方案的期望功能，并创建项目计划。该计划可能包括流程图、整体接口和布局设计，以及大量的文档。

# 实现

第三阶段是实现阶段。在这里，项目经理创建并分配工作给开发人员。开发人员根据设计阶段定义的任务和目标开发代码。这个阶段可能会持续几个月到一年，这取决于项目的规模。

# 测试

第四阶段是测试阶段。当所有确定的功能都开发完成后，测试团队接管。在接下来的几个月里，所有功能都会经过彻底的测试。软件的每个模块都会被收集和测试。如果在测试过程中出现任何错误或 bug，就会提出缺陷。在出现故障时，开发团队会迅速采取措施解决故障。经过彻底测试的代码随后会被部署到生产环境中。

# 演进

最后阶段是演进阶段或维护阶段。用户/客户的反馈被分析，整个开发、测试和发布新功能和修复的循环以补丁或升级的形式重复。

# 软件开发的瀑布模型

最著名且广泛使用的软件开发过程之一是瀑布模型。瀑布模型是一个顺序软件开发过程，源自制造业。人们可以看到高度结构化的流程在一个方向上运行。在其创立时期，没有其他软件开发方法论，开发人员唯一能够想象的就是简单适用于软件开发的生产线流程。

下图展示了软件开发的瀑布模型：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/3e822d7c-11be-4aba-a2b8-394915bed092.png)

瀑布模型

瀑布方法简单易懂，因为所涉及的步骤类似于 SDLC。

首先是需求分析阶段，然后是设计阶段。在分析和设计部分花费了相当多的时间。一旦完成，就不再进行添加或删除。简而言之，在开发开始后，设计中不允许修改。

然后是实施阶段，实际的开发将在此阶段进行。开发周期可以长达三个月至六个月。这段时间，测试团队通常是空闲的。开发周期结束后，计划整合源代码需要一整周时间。在此期间，会出现许多集成问题，并立即进行修复。这个阶段后是测试阶段。

当测试开始时，会持续三个月甚至更长时间，取决于软件解决方案。测试成功后，源代码将部署在生产环境中。为此，会再次计划一天左右来进行生产部署。可能会出现一些部署问题。软件解决方案上线后，团队会收到反馈，也可能预料到问题。

最后阶段是维护阶段。用户/客户的反馈被分析，整个开发、测试和发布新功能和修复的循环以补丁或升级的形式重复。

毫无疑问，瀑布模型在数十年间运行良好。然而，存在缺陷，但长时间以来被忽视。因为在那个时代，软件项目有足够的时间和资源来完成工作。

然而，看着过去几年软件技术的变化，我们可以说瀑布模型无法满足当前世界的需求。

# 瀑布模型的缺点

以下是瀑布模型的一些缺点：

+   可工作的软件仅在大多数情况下持续一年左右的 SDLC 结束时产生。

+   存在大量不确定性。

+   不适用于对新功能需求过于频繁的项目。例如，电子商务项目。

+   仅在整个开发阶段完成后执行集成。因此，集成问题会在更晚的阶段和大量发现。

+   不存在向后追溯。

+   在各个阶段内很难衡量进度。

# 瀑布模型的优点

通过查看瀑布模型的缺点，我们可以说它主要适用于以下项目：

+   需求已经很好地记录并且是固定的。

+   有足够的资金可供维护管理团队、测试团队、开发团队、构建和发布团队、部署团队等。

+   技术是固定的，而不是动态的。

+   没有模棱两可的要求。最重要的是，它们不会在除了需求分析阶段之外的任何其他阶段中出现。

# 敏捷来拯救

名称**敏捷**恰如其分地暗示了*快速且简单*。敏捷是一种通过自组织团队之间的协作开发软件的方法集。敏捷背后的原则是增量、快速、灵活的软件开发，并促进自适应规划。

敏捷软件开发过程是传统软件开发过程的替代方案。

# 敏捷十二原则

以下是敏捷模型的十二原则：

+   通过尽早和持续地交付有用的软件来实现客户满意度。

+   欢迎在开发的后期接受变更的需求。

+   经常交付可工作的软件（以周为单位，而不是月）。

+   业务、人员和开发者之间的密切日常合作。

+   项目围绕着应该受到信任的积极主动的个人构建。

+   面对面的交流是最好的沟通方式（共同位置）。

+   可工作的软件是进度的主要衡量标准。

+   可持续发展——能够保持稳定的速度。

+   持续关注技术卓越和良好的设计。

+   简单——最大化未完成工作量的艺术是必不可少的。

+   自组织团队。

+   定期适应变化的环境。

要了解更多关于敏捷原则的内容，请访问链接：[`www.agilemanifesto.org`](http://www.agilemanifesto.org)。

敏捷软件开发的十二原则表明了当前软件行业的期望以及其在瀑布模型上的优势。

# 敏捷软件开发过程是如何工作的？

在敏捷软件开发过程中，整个软件应用被分割成多个特性或模块。这些特性以迭代方式交付。每个迭代持续三周，涉及到跨职能团队同时在各个领域工作，如规划、需求分析、设计、编码、单元测试和验收测试。

因此，在任何给定时间点，没有人处于空闲状态。这与瀑布模型大不相同，在瀑布模型中，尽管开发团队正在忙于开发软件，但测试团队、生产团队和其他所有人都是空闲或利用率不高的。以下图示了软件开发的敏捷模型：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/1e48e17b-d7e3-436f-9f70-3a42b1ff01fc.png)

敏捷方法论

从上图中我们可以看到，没有时间花费在需求分析或设计上。相反，准备了一个非常高层次的计划，仅足以勾勒项目的范围。

然后团队经历一系列迭代。迭代可以分类为时间框架，每个时间框架持续一个月，甚至在一些成熟项目中持续一周。在此期间，项目团队开发和测试特性。目标是在单个迭代中开发、测试和发布一个特性。在迭代结束时，该特性进行演示。如果客户喜欢它，那么该特性就上线了。但是，如果被拒绝，该特性将作为待办事项，重新排优先级，并在后续迭代中再次进行处理。

也存在并行开发和测试的可能性。在单个迭代中，可以并行开发和测试多个特性。

# 敏捷软件开发过程的优势

让我们看一下敏捷软件开发过程的一些优势：

+   **功能可以迅速开发和演示**：在敏捷过程中，软件项目被划分为特性，并且每个特性被称为一个待办事项。其想法是从概念化到部署，一周或一个月内开发单个或一组特性。这至少让客户有一个或两个特性可以使用。

+   **资源需求较少**：在敏捷中，没有单独的开发和测试团队。也没有构建或发布团队，或者部署团队。在敏捷中，一个项目团队包含约八名成员。团队的每个成员都能做所有事情。

+   **促进团队合作和交叉培训**：由于团队规模小约为八名成员，团队成员轮流担任角色，并从彼此的经验中学习。

+   **适用于需求经常变化的项目**：在软件开发的敏捷模型中，整个软件被分割成特性，每个特性在短时间内开发和交付。因此，更改特性，甚至完全放弃它，都不会影响整个项目。

+   **极简主义文档**：这种方法主要专注于快速交付可工作的软件，而不是创建庞大的文档。文档存在，但仅限于整体功能。

+   **几乎不需要计划**：由于功能在短时间内依次开发，因此无需进行广泛的规划。

+   **并行开发**：迭代由一个或多个功能依次开发，甚至是并行开发。

# Scrum 框架

Scrum 是一个基于敏捷软件开发流程的开发和维护复杂产品的框架。它不仅仅是一个过程；它是一个具有特定角色、任务和团队的框架。Scrum 由**肯·施瓦伯**和**杰夫·萨瑟兰**编写；他们一起创作了*Scrum 指南*。

在 Scrum 框架中，开发团队决定如何开发一个功能。这是因为团队最了解他们所面临的问题。我假设大多数读者在阅读完这篇文章后都会感到满意。

Scrum 依赖于一个自组织和跨职能的团队。Scrum 团队是自组织的；因此，没有总体团队领导者决定哪个人将做哪个任务，或者如何解决问题。

# Scrum 框架中使用的重要术语

以下是 Scrum 框架中使用的重要术语：

+   **冲刺**：冲刺是在其中创建一个可用且可能可发布的产品的时间段。一个新的冲刺在上一个冲刺结束后立即开始。冲刺的持续时间可能介于两周到一个月之间，具体取决于对 Scrum 的命令。

+   **产品待办列表**：产品待办列表是软件解决方案中所有必需功能的列表。该列表是动态的。也就是说，客户或团队成员时不时地向产品待办列表中添加或删除项目。

+   **冲刺待办列表**：冲刺待办列表是为冲刺选择的产品待办列表项目集合。

+   **增量**：增量是在冲刺期间完成的所有产品待办列表项目以及所有先前冲刺的增量价值的总和。

+   **开发团队**：开发团队负责在每个冲刺结束时交付一个可发布的功能集合，称为增量。只有开发团队的成员创建增量。开发团队由组织授权组织和管理他们的工作。由此产生的协同作用优化了开发团队的整体效率和效果。

+   **产品负责人**：产品负责人是 Scrum 团队与所有其他人之间的中介。他是 Scrum 团队的前台，并与客户、基础架构团队、管理团队以及所有参与 Scrum 的人等进行交互。

+   **Scrum 主管**：Scrum 主管负责确保人们了解并执行 Scrum。Scrum 主管通过确保 Scrum 团队遵循 Scrum 理论、实践和规则来做到这一点。

# Scrum 如何工作？

产品负责人，Scrum Master 和 Scrum 团队共同遵循一套严格的程序来交付软件功能。以下图表解释了 Scrum 开发过程：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/5769741f-1b23-4f9f-8510-161d08fcb172.png)

Scrum 方法论

让我们看看团队经历的 Scrum 软件开发过程的一些重要方面。

# 冲刺计划

冲刺计划是 Scrum 团队规划当前冲刺周期功能的机会。计划主要由开发人员创建。一旦计划创建完成，它会向 Scrum Master 和 Product Owner 解释。冲刺计划是一个时间框定的活动，通常在一个月的冲刺周期中总共约八小时。确保每个人都参与冲刺计划活动是 Scrum Master 的责任。

在会议中，开发团队考虑以下项目：

+   要处理的产品待办事项数量（包括上一个冲刺的新事项和旧事项）。

+   上一个冲刺中的团队表现。

+   开发团队的预期容量。

# 冲刺周期

在冲刺周期内，开发人员只需完成冲刺计划中决定的待办事项。冲刺的持续时间可能会从两周到一个月不等，这取决于待办事项的数量。

# 每日 Scrum 会议

这是每天发生的事情。在 Scrum 会议期间，开发团队讨论昨天完成的工作，以及今天将要完成的工作。他们还讨论阻止他们实现目标的事情。开发团队除了 Scrum 会议外，不参加任何其他会议或讨论。

# 监控冲刺进展

每日 Scrum 是团队测量进展的好机会。Scrum 团队可以跟踪剩余的总工作量，通过这样做，他们可以估计实现冲刺目标的可能性。

# 冲刺计划

在冲刺回顾中，开发团队展示已完成的功能。Product Owner 更新到目前为止的产品待办事项状态。产品待办事项列表根据产品在市场上的表现或使用情况进行更新。冲刺回顾对于一个月的冲刺来说是一个总共四小时的活动。

# 冲刺回顾

在这次会议上，团队讨论了做得好的事情和需要改进的事情。然后，团队决定了要在即将到来的冲刺中改进的要点。这次会议通常在冲刺回顾之后，冲刺计划之前进行。

# 持续集成

持续集成（CI）是一种软件开发实践，开发人员经常将他们的工作与项目的集成分支相结合，并创建一个构建。

集成是将您的个人工作（修改后的代码）提交到公共工作区（潜在的软件解决方案）的行为。这在技术上通过将您的个人工作（个人分支）与公共工作区（集成分支）合并来完成。或者我们可以说，将您的个人分支推送到远程分支。

持续集成是为了尽早发现集成过程中遇到的问题。可以从下图中理解这一点，该图描述了单个持续集成周期中遇到的各种问题。

构建失败可能是由于不正确的代码或在构建过程中出现人为错误（假设任务是手动完成的）而导致的。如果开发人员不经常将他们的本地代码副本与集成分支上的代码重新基准，则可能会出现集成问题。如果代码未通过任何单元测试或集成测试用例，则可能会出现测试问题。

在出现问题时，开发人员必须修改代码以修复它：

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/c923f2eb-e6e1-4dd7-b42c-28c428b8c2b0.png)

持续集成过程

# 敏捷运行在持续集成上

敏捷软件开发过程主要关注快速交付，持续集成帮助敏捷实现了这一速度。但是持续集成是如何做到的呢？让我们通过一个简单的案例来理解。

开发一个功能涉及到许多代码更改，在每次代码更改之间，有一系列任务要执行，比如检入代码，轮询版本控制系统以查看更改，构建代码，单元测试，集成，基于集成代码构建，集成测试和打包。在持续集成环境中，使用诸如*Jenkins*之类的持续集成工具可以使所有这些步骤变得快速且无错误。

添加通知可以使事情变得更快。团队成员越早意识到构建、集成或部署失败，他们就能越快采取行动。下图描述了持续集成过程中涉及的所有步骤：

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/1ce449b9-0115-4152-9e16-c5039649c57d.png)

带通知的持续集成过程

团队通过这种方式快速从一个功能转移到另一个功能。简单地说，敏捷软件开发的*敏捷性*很大程度上是由持续集成所致。

# 从持续集成中受益的项目类型

汽车内嵌系统中编写的代码量比战斗机内嵌系统中的代码量更多。在今天的世界中，嵌入式软件存在于每一种产品中，无论是现代产品还是传统产品。无论是汽车、电视、冰箱、手表还是自行车，所有产品都有多少与软件相关的功能。消费品每天都在变得更加智能。如今，我们可以看到一个产品更多地通过其智能和智能功能来进行市场推广，而不是其硬件功能。例如，空调通过其无线控制功能进行市场推广，电视则通过其智能功能（如嵌入式网页浏览器等）进行市场推广，等等。

推广新产品的需求增加了产品的复杂性。软件复杂性的增加使得敏捷软件开发和 CI 方法学备受关注，尽管过去有时敏捷软件开发仅被 30-40 人的小团队用于简单项目。几乎所有类型的项目都受益于 CI：主要是基于 Web 的项目，例如电子商务网站和手机应用程序。

CI 和敏捷方法论在基于 Java、.NET、Ruby on Rails 和今天存在的每一种编程语言的项目中都被使用。唯一不使用它的地方是在传统系统中。然而，它们甚至也在转向敏捷。基于 SAS、主机的项目；都在尝试从 CI 中受益。

# CI 的元素

让我们看看 CI 过程的重要元素。

# 版本控制系统

这是实现 CI 的最基本和最重要的要求。**版本控制系统**，有时也称为**修订控制系统**，是管理代码历史记录的工具。它可以是集中式的或分布式的。一些著名的集中式版本控制系统包括 SVN 和 IBM Rational ClearCase。在分布式部分，我们有像 Git 和 Mercurial 这样的工具。

理想情况下，构建软件所需的一切都必须进行版本控制。版本控制工具提供许多功能，如标记、分支等。

# 分支策略

使用版本控制系统时，应将分支保持在最低限度。一些公司只有一个主分支，所有的开发活动都在这个分支上进行。然而，大多数公司都遵循一些分支策略。这是因为总会有一部分团队可能在一个发布版上工作，而另一部分团队可能在另一个发布版上工作。有时，需要支持旧版本的发布。这些情况总是导致公司使用多个分支。

GitFlow 是另一种使用多个分支管理代码的方式。在以下方法中，Master/Production 分支保持清洁，仅包含可发布、准备好发货的代码。所有的开发都在 Feature 分支上进行，Integration 分支作为一个公共集成所有功能的地方。以下图示是 GitFlow 的一个中等版本：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/2d249a6c-ede9-4a30-82d0-6bf59340a4f0.png)

分支策略

# GitFlow 分支模型

以下图示说明了完整版本的 GitFlow。我们有一个包含仅生产就绪代码的 Master/Production 分支。功能分支是所有开发都发生的地方。集成分支是代码集成和测试质量的地方。除此之外，我们还有从集成分支拉出的发布分支，只要有稳定版本发布，就会有与发布相关的所有错误修复。还有一个热修复分支，只要有必要进行热修复，就会从 Master/Production 分支拉出来：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/a452caa6-2dd5-4b7b-b374-fcd04f8ea34d.png)

GitFlow 分支策略

# CI 工具

什么是 CI 工具？嗯，它不过是一个协调者。CI 工具位于 CI 系统的中心，连接到版本控制系统、构建工具、二进制存储库管理工具、测试和生产环境、质量分析工具、测试自动化工具等等。有许多 CI 工具：Build Forge、Bamboo 和 TeamCity 等等。但我们书中的重点是 Jenkins：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/89003f6b-027e-46f8-baa2-c3fe1109e946.png)

集中式 CI 服务器

CI 工具提供了创建流水线的选项。每个流水线都有其自身的目的。有一些流水线负责 CI。有些负责测试；有些负责部署等等。技术上，流水线是作业的流动。每个作业是一组按顺序运行的任务。脚本编写是 CI 工具的一个组成部分，它执行各种类型的任务。这些任务可能是简单的，比如从一个位置复制文件/文件夹到另一个位置，或者它们可能是复杂的 Perl 脚本，用于监视文件修改的机器。尽管如此，随着 Jenkins 中可用插件数量的增加，脚本正在被替换。现在，你不需要脚本来构建 Java 代码；有相应的插件可用。你所需要做的就是安装和配置一个插件来完成工作。技术上，插件只是用 Java 编写的小模块。它们减轻了开发人员的脚本编写负担。我们将在后续章节中更多地了解流水线。

# 自触发构建

接下来要理解的重要事情是自触发自动化构建。构建自动化只是一系列自动化步骤，用于编译代码和生成可执行文件。构建自动化可以借助构建工具如 Ant 和 Maven。自触发自动化构建是 CI 系统中最重要的部分。有两个主要因素需要自动化构建机制：

+   速度。

+   尽早捕获集成或代码问题。

有些项目每天会有 100 到 200 次构建。在这种情况下，速度是一个重要因素。如果构建是自动化的，那么可以节省很多时间。如果构建的触发是自动驱动的，而不需要任何手动干预，事情就变得更有趣了。在每次代码更改时自动触发构建进一步节省时间。

当构建频繁且快速时，SDLC 框架中发现错误（构建错误、编译错误或集成错误）的概率更高且更快：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/07304f0b-783a-498e-b707-c033986ca49d.png)

错误概率与构建图

# 代码覆盖

代码覆盖是您的测试用例覆盖的代码量（以百分比表示）。您在覆盖报告中看到的度量标准可能更多或更少，如下表所定义：

| **覆盖类型** | **描述** |
| --- | --- |
| Function | 被调用的函数数量占定义的函数总数的比例 |
| Statement | 程序中实际调用的语句数占总数的比例 |
| Branches | 执行的控制结构的分支数 |
| Condition | 正在测试的布尔子表达式的数量，测试真值和假值 |
| Line | 正在测试的源代码行数占代码总行数的比例 |

代码覆盖类型

该覆盖率百分比通过将被测试项的数量除以找到的项的数量来计算。以下截图显示了来自 SonarQube 的代码覆盖报告：

**![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/ccf7322a-5472-4ad9-98f5-bacf5798ade3.png)**

SonarQube 上的代码覆盖报告

# 代码覆盖工具

根据您使用的语言，可能会发现几种创建覆盖报告的选项。以下是一些流行工具：

| **语言** | **工具** |
| --- | --- |
| Java | Atlassian Clover, Cobertura, JaCoCo |
| C#/.NET | OpenCover, dotCover |
| C++ | OpenCppCoverage, gcov |
| Python | Coverage.py |
| Ruby | SimpleCov |

# 静态代码分析

静态代码分析，通常也称为**白盒**测试，是一种查找代码结构质量的软件测试形式。例如，它回答了代码的健壮性或可维护性如何。静态代码分析是在实际执行程序之前执行的。它与功能测试不同，功能测试着眼于软件的功能方面，并且是动态的。

静态代码分析是对软件内部结构的评估。例如，是否有一段重复使用的代码？代码中是否包含大量的注释行？代码有多复杂？使用用户定义的度量标准，生成了一个分析报告，显示了代码在可维护性方面的质量。它不质疑代码的功能。

一些静态代码分析工具，如 SonarQube，配备了仪表板，显示每次运行的各种指标和统计数据。通常作为 CI 的一部分，每次运行构建时都会触发静态代码分析。如前几节讨论的，静态代码分析也可以在开发人员尝试提交代码之前包含。因此，低质量的代码可以在最初阶段就被阻止。

他们支持许多语言，如 Java、C/C++、Objective-C、C#、PHP、Flex、Groovy、JavaScript、Python、PL/SQL、COBOL 等等。以下截图展示了使用 SonarQube 进行静态代码分析报告：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/ab5d269d-6d44-449e-b6da-be6b1d649e1c.png)

静态代码分析报告

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/da3b4670-eb42-4f16-a02d-deffe64d51ae.png)

静态代码分析报告

# 自动化测试

测试是 SDLC 的重要组成部分。为了保持软件质量，必须让软件解决方案通过各种测试场景。对测试的重视不足可能导致客户不满意和产品延迟。

由于测试是一项手动、耗时且重复的任务，自动化测试流程可以显着提高软件交付速度。然而，自动化测试流程要比自动化构建、发布和部署流程困难得多。通常需要大量工作来自动化项目中几乎所有使用的测试用例。这是一个随着时间逐渐成熟的活动。

因此，在开始自动化测试时，我们需要考虑一些因素。首先考虑那些价值高且易于自动化的测试用例。例如，在步骤相同的情况下自动化测试，尽管每次都使用不同的数据。此外，自动化测试涉及在各种平台上测试软件功能的测试。还要自动化测试涉及使用不同配置运行软件应用程序的测试。

以前，世界主要由桌面应用程序主导。自动化 GUI 系统的测试相当困难。这就需要脚本语言，其中手动鼠标和键盘输入被脚本化并执行以测试 GUI 应用程序。然而，如今，软件世界完全被基于 Web 和移动的应用程序主导，可以通过使用测试自动化工具的自动化方法轻松测试。

一旦代码构建、打包和部署完成，就应该自动运行测试来验证软件。传统上，遵循的流程是为 SIT、UAT、PT 和预生产环境准备环境。首先，发布通过 SIT，即系统集成测试。在这里，对集成代码进行测试，以检查其功能是否完全。如果集成测试通过，则代码将部署到下一个环境，即 UAT，在那里经过用户验收测试，最后可以部署到 PT，在那里经过性能测试。通过这种方式，测试得到了优先考虑。

并不总是可能自动化所有的测试。但是，思想是尽可能自动化所有可能的测试。前述的方法需要许多环境，以及在各种环境中进行更高数量的自动化部署。为了避免这种情况，我们可以采用另一种方法，在这种方法中，只有一个环境部署了构建，然后运行基本测试，然后手动触发长时间

# 二进制存储库工具

作为 SDLC 的一部分，源代码被持续地使用 CI 构建成二进制产物。因此，应该有一个地方来存储这些构建包以供以后使用。答案是，使用一个二进制存储库工具。但是什么是二进制存储库工具？

二进制存储库工具是用于二进制文件的版本控制系统。不要将其与前面讨论的版本控制系统混淆。前者负责对源代码进行版本控制，而后者负责二进制文件，例如`.rar`、`.war`、`.exe`、`.msi`等文件。除了管理构建产物外，二进制存储库工具还可以管理构建所需的第三方二进制文件。例如，Maven 插件始终会下载构建代码所需的插件到一个文件夹中。与其一遍又一遍地下载插件，不如使用存储库工具管理：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/704daee7-e279-40f8-ac8c-2fb2e1f88c33.png)

存储库工具

从上面的说明中，您可以看到，一旦创建了一个构建并通过了所有的检查，构建产物就会被上传到二进制存储库工具中。从这里，开发人员和测试人员可以手动选择、部署和测试它们。或者，如果自动部署已经就位，那么构建产物将自动部署到相应的测试环境。那么，使用二进制存储库的优势是什么呢？

二进制存储库工具执行以下操作：

+   每次生成构建产物时，都会存储在一个二进制存储库工具中。存储构建产物有许多优点。其中一个最重要的优点是，构建产物位于一个集中的位置，可以在需要时访问。

+   它可以存储构建工具所需的第三方二进制插件、模块。因此，构建工具不需要每次运行构建时都下载插件。存储库工具连接到在线源并不断更新插件存储库。

+   记录了什么、何时以及谁创建了一个构建包。

+   它提供了类似于**环境**的分段，以更好地管理发布。这也有助于加速 CI 流程。

+   在 CI 环境中，构建的频率太高，每个构建都会生成一个包。由于所有构建的包都在一个地方，开发人员可以自由选择在高级环境中推广什么，而不推广什么。

# 自动打包

有可能一个构建可能有许多组件。例如，让我们考虑一个具有`.rar`文件作为输出的构建。除此之外，它还有一些 Unix 配置文件、发布说明、一些可执行文件，以及一些数据库更改。所有这些不同的组件需要在一起。将许多组件创建为单个存档或单个媒体的任务称为**打包**。同样，这可以使用 CI 工具自动化，并节省大量时间。

# 使用 CI 的好处

以下是使用 CI 的一些好处。该列表简要概述，不全面。

# 摆脱长时间的集成

很少进行代码集成，正如在瀑布模型中所见，可能导致*合并地狱*。这是一个团队花费数周解决合并问题的情况。

与此相反，将特性分支上的每个提交与集成分支进行集成，并对其进行问题测试（CI），允许您尽早发现集成问题。

# 指标

Jenkins、SonarQube、Artifactory 和 GitHub 等工具可以让您在一段时间内生成趋势。所有这些趋势都可以帮助项目经理和团队确保项目朝着正确的方向和正确的步伐发展。

# 更快地发现问题

这是仔细实施 CI 系统的最重要优势。任何集成问题或合并问题都会被及早发现。CI 系统有能力在构建失败时立即发送通知。

# 快速开发

从技术角度来看，CI 有助于团队更高效地工作。使用 CI 的项目在构建、测试和集成其代码时采用自动和持续的方法。这导致开发速度更快。

开发人员花费更多时间开发他们的代码，零时间构建、打包、集成和部署它，因为一切都是自动化的。这也有助于地理上分布的团队共同工作。有了良好的*软件配置管理流程*，人们可以在广泛分布的团队上工作。

# 花更多时间添加功能

在过去，构建和发布活动由开发人员负责，与常规开发工作一起进行。随后出现了一个趋势，即有专门的团队负责构建、发布和部署活动。而且事情并没有止步于此；这种新模式遭遇了开发人员、发布工程师和测试人员之间的沟通问题和协调不足。然而，使用 CI，所有构建、发布和部署工作都得到了自动化。因此，开发团队无需担心其他任何事情，只需开发功能即可。在大多数情况下，甚至连完整测试都是自动化的。因此，通过使用 CI 流程，开发团队可以花更多时间开发代码。

# 摘要

“每个成功的敏捷项目背后都有一个持续集成的过程。”

在本章中，我们粗略地了解了软件工程流程的历史。我们学习了持续集成（CI）及其组成要素。

本章讨论的各种概念和术语构成了后续章节的基础。没有这些，接下来的章节只是技术知识。

在下一章中，我们将学习如何在各种平台上安装 Jenkins。


# 第二章：安装 Jenkins

本章讲述了如何在各种平台上安装 Jenkins 等内容。完成本章后，您应该能够做到以下几点：

+   在 Servlet 容器（Apache Tomcat）上运行 Jenkins

+   在 Windows/Ubuntu/Red Hat Linux/Fedora 上以独立应用程序的形式运行 Jenkins

+   在反向代理服务器（Nginx）后运行 Jenkins

+   使用 Docker 运行 Jenkins

+   利用 Docker 数据卷的优势

+   使用 Docker 运行 Jenkins 的开发、分段和生产实例

# 在 Servlet 容器内运行 Jenkins

Jenkins 可用于以下 Servlet 容器：

+   Apache Geronimo 3.0

+   GlassFish

+   IBM WebSphere

+   JBoss

+   Jetty

+   Jonas

+   Liberty profile

+   Tomcat

+   WebLogic

在本节中，您将学习如何在 Apache Tomcat 服务器上安装 Jenkins。在 Apache Tomcat 上将 Jenkins 安装为服务相当简单。您可以选择将 Jenkins 与 Apache Tomcat 服务器上已有的其他服务一起运行，或者您可以仅使用 Apache Tomcat 服务器来运行 Jenkins。

# 先决条件

在开始之前，请确保您准备好以下事项：

+   您需要一台至少拥有 4GB 内存和多核处理器的系统。

+   根据团队中的基础设施管理方式，机器可以是云平台的实例（例如 AWS、DigitalOcean 或任何其他云平台）、裸金属机器，或者它可以是一个虚拟机（在 VMware vSphere 或任何其他服务器虚拟化软件上）。

+   机器应该安装有 Ubuntu 16.04。选择一个 LTS 版本。

+   检查管理员权限；安装可能会要求管理员用户名和密码。

# 安装 Java

按照以下步骤在 Ubuntu 上安装 Java：

1.  更新软件包索引：

```
 sudo apt-get update
```

1.  接下来，安装 Java。执行以下命令将安装**Java Runtime Environment**（**JRE**）：

```
 sudo apt-get install default-jre 
```

1.  要设置`JAVA_HOME`环境变量，请获取 Java 安装位置。通过执行以下命令来执行此操作：

```
 update-java-alternatives -l
```

1.  上一个命令将打印在您的机器上安装的 Java 应用程序列表以及它们的安装路径。复制在终端上出现的 Java 路径：

```
 java-1.8.0-openjdk-amd64  1081
        /usr/lib/jvm/java-1.8.0-openjdk-amd64
```

1.  使用以下命令编辑`/etc/environment`文件：

```
 sudo nano /etc/environment 
```

1.  在`/etc/environment`文件中以以下格式添加 Java 路径（您之前复制的路径）：

```
        JAVA_HOME="/usr/lib/jvm/java-1.8.0-openjdk-amd64" 
```

1.  输入*Ctrl* + *X*并选择*Y*以保存并关闭文件。

1.  接下来，使用以下命令重新加载文件：

```
 sudo source /etc/environment
```

# 安装 Apache Tomcat

按照以下步骤下载并安装 Apache Tomcat 服务器到您的 Ubuntu 机器上：

1.  移动到`/tmp`目录并使用`wget`命令下载 Tomcat 应用程序，如下所示：

```
 cd /tmp
       wget https://archive.apache.org/dist/tomcat/tomcat-8/ \
        v8.5.16/bin/apache-tomcat-8.5.16.tar.gz
```

要获取完整的 Apache Tomcat 版本列表，请访问：[`archive.apache.org/dist/tomcat/`](https://archive.apache.org/dist/tomcat/)。

1.  使用以下命令创建一个名为`/opt/tomcat`的目录：

```
 sudo mkdir /opt/tomcat 
```

1.  在`/opt/tomcat`内解压存档的内容：

```
 sudo tar xzvf apache-tomcat-8*tar.gz \
        -C /opt/tomcat --strip-components=1 
```

1.  接下来，使用以下命令创建一个 `systemd` 服务文件：

```
 sudo nano /etc/systemd/system/tomcat.service
```

1.  将以下内容粘贴到文件中：

```
        [Unit] 
        Description=Apache Tomcat Web Application Container 
        After=network.target 

        [Service] 
        Type=forking 

        Environment=JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk-amd64                     
        Environment=CATALINA_PID=/opt/tomcat/temp/tomcat.pid 
        Environment=CATALINA_HOME=/opt/tomcat 
        Environment=CATALINA_BASE=/opt/tomcat 
        Environment='CATALINA_OPTS=-Xms512M -Xmx1024M
        -server -XX:+UseParallelGC' 
        Environment='JAVA_OPTS=-Djava.awt.headless=true
        -Djava.security.egd=file:/dev/./urandom' 

        ExecStart=/opt/tomcat/bin/startup.sh 
        ExecStop=/opt/tomcat/bin/shutdown.sh 

        RestartSec=10 
        Restart=always 

        [Install] 
        WantedBy=multi-user.target 
```

1.  输入 *Ctrl* + *X* 并选择 *Y* 保存并关闭文件。

1.  接下来，使用以下命令重新加载 systemd 守护程序：

```
 sudo systemctl daemon-reload 
```

1.  使用以下命令启动 Tomcat 服务：

```
 sudo systemctl start tomcat 
```

1.  要检查 Tomcat 服务的状态，请运行以下命令：

```
 sudo systemctl status tomcat 
```

1.  您应该看到以下输出：

```
 ● tomcat.service - Apache Tomcat Web Application Container 
          Loaded: loaded (/etc/systemd/system/tomcat.service; disabled;
          vendor preset: enabled) 
          Active: active (running) since Mon 2017-07-31 21:27:39 UTC;
          5s ago 
          Process: 6438 ExecStart=/opt/tomcat/bin/startup.sh (code=exited,
          status=0/SUCCESS) 
         Main PID: 6448 (java) 
            Tasks: 44 
           Memory: 132.2M 
              CPU: 2.013s 
           CGroup: /system.slice/tomcat.service 
                   └─6448 /usr/lib/jvm/java-1.8.0-openjdk-amd64/bin/java
       -Djava.util.logging.config.file=/opt/tomcat/conf/logging.properties
       -Djava.util.logging.manager=org.apache.juli.ClassLoaderLogMan 
```

# 启用防火墙和端口 `8080`

Apache Tomcat 运行在端口 `8080` 上。如果防火墙已禁用，请按照以下步骤启用防火墙：

1.  使用以下命令启用防火墙：

```
 sudo ufw enable 
```

1.  允许端口 `8080` 上的流量：

```
 sudo ufw allow 8080 
```

1.  使用以下命令启用 OpenSSH 以允许 SSH 连接：

```
 sudo ufw enable "OpenSSH" 
```

1.  使用以下命令检查防火墙状态：

```
 sudo ufw status 
```

1.  您应该看到以下输出：

```
 Status: active  
        To                         Action      From 
        --                         ------      ---- 
        8080                       ALLOW       Anywhere 
        OpenSSH                    ALLOW       Anywhere 
        8080 (v6)                  ALLOW       Anywhere (v6) 
        OpenSSH (v6)               ALLOW       Anywhere (v6) 
```

1.  现在，您应该能够访问 Apache Tomcat 服务器页面：`http://<Apache Tomcat 的 IP 地址>:8080`。

# 配置 Apache Tomcat 服务器

在本节中，我们将启用对 Tomcat 管理器应用程序和主机管理器的访问：

1.  打开位于 `/opt/tomcat/conf` 目录内的 `tomcat-users.xml` 文件进行编辑：

```
 sudo nano /opt/tomcat/conf/tomcat-users.xml 
```

1.  文件将看起来像下面这样，为简单起见，我忽略了文件内的注释：

```
        <?xml version="1.0" encoding="UTF-8"?> 
        . . . 
        <tomcat-users  

        xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd" 
        version="1.0"> 
        . . . 
          <!-- 
            <role rolename="tomcat"/> 
            <role rolename="role1"/> 
            <user username="tomcat" password="<must-be-changed>"
             roles="tomcat"/> 
            <user username="both" password="<must-be-changed>"
             roles="tomcat,role1"/> 
            <user username="role1" password="<must-be-changed>"
             roles="role1"/> 
          --> 
        </tomcat-users> 
```

1.  从前一个文件中，您可以看到 `role` 和 `user` 字段被注释了。我们需要启用一个角色和一个用户来允许访问 Tomcat 管理器应用程序页面：

```
        <role rolename="manager-gui"/> 
        <role rolename="admin-gui"/> 
        <user username="admin" password="password"
         roles="manager-gui,admin-gui"/>
```

1.  最后，文件应如下所示（已移除注释）：

```
        <?xml version="1.0" encoding="UTF-8"?>  
        <tomcat-users  

        xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd" 
        version="1.0"> 
          <role rolename="manager-gui"/> 
          <role rolename="admin-gui"/> 
          <user username="admin" password="password"
           roles="manager-gui,admin-gui"/> 
        </tomcat-users> 
```

1.  输入 *Ctrl* + *X* 并选择 *Y* 保存并关闭文件。

1.  默认情况下，您只能从 Apache Tomcat 服务器内访问 Manager 和 Host Manager 应用程序。由于我们将从远程机器管理在 Apache 上运行的服务，因此需要删除这些限制。

1.  打开以下两个文件，`/opt/tomcat/webapps/manager/META-INF/context.xml` 和 `/opt/tomcat/webapps/host-manager/META-INF/context.xml`。

1.  在这些文件中，取消注释以下部分：

```
        <Context antiResourceLocking="false" privileged="true" > 
          <!--<Valve className="org.apache.catalina.valves.RemoteAddrValve" 
          allow="127\.\d+\.\d+\.\d+|::1|0:0:0:0:0:0:0:1" />--> 
          <Manager sessionAttributeValueClassNameFilter="java\.lang\
          .(?:Boolean|Integer|Long|Number|String)|org\.apache\.catalina\
          .filters\.CsrfPreventionFilter\$LruCache(?:\$1)?|java\.util\
          .(?:Linked)$ 
        </Context> 
```

1.  输入 *Ctrl* + *X* 并选择 *Y* 保存并关闭文件。

1.  使用以下命令重新启动 Tomcat 服务器：

```
 sudo systemctl restart tomcat 
```

1.  尝试从 Apache Tomcat 服务器主页访问管理器应用程序和主机管理器。

# 在 Apache Tomcat 服务器上安装 Jenkins

如果您不希望为 Jenkins 主服务器拥有独立的服务器，并希望将其与存在于 Apache Tomcat 服务器上的其他服务一起托管，可以执行以下步骤：

1.  切换到 `/tmp` 目录，并使用 `wget` 命令下载 Jenkins 应用程序，如下所示：

```
 cd /tmp
        wget http://mirrors.jenkins.io/war-stable/latest/jenkins.war 
```

1.  前一个命令将下载最新稳定版本的 `jenkins.war` 文件。

1.  将文件从 `/tmp` 移动到 `/opt/tomcat/`：

```
 sudo mv jenkins.war /opt/tomcat/webapps/ 
```

1.  列出 `/opt/tomcat/webapps/` 目录的内容：

```
 sudo ls -l /opt/tomcat/webapps 
```

您应该看到以下输出：

```
 total 68984 
        -rw-rw-r--  1 ubuntu ubuntu 70613578 Jul 19 22:37 jenkins.war 
        drwxr-x---  3 root   root       4096 Jul 31 21:09 ROOT 
        drwxr-x--- 14 root   root       4096 Jul 31 21:09 docs 
        drwxr-x---  6 root   root       4096 Jul 31 21:09 examples 
        drwxr-x---  5 root   root       4096 Jul 31 21:09 manager 
        drwxr-x---  5 root   root       4096 Jul 31 21:09 host-manager 
        drwxr-x--- 10 root   root       4096 Jul 31 22:52 jenkins 
```

注意，将 `jenkins.war` 包移动到 `webapps` 文件夹时，会自动创建一个 `jenkins` 文件夹。这是因为 `.war` 文件是一个 Web 应用程序存档文件，一旦部署到 `webapps` 目录中就会自动解压缩。我们所做的是一个小型的部署活动。

1.  就是这样了。你可以使用`http://<Tomcat 服务器的 IP 地址>:8080/jenkins`访问 Jenkins。

# 仅在 Apache Tomcat 服务器上安装 Jenkins

如果你选择为 Jenkins 使用单独的 Apache Tomcat 服务器，请按照以下步骤操作：

1.  切换到`/tmp`目录并使用`wget`命令下载 Jenkins 应用程序，如下所示：

```
 cd /tmp 
 wget http://mirrors.jenkins.io/war-stable/latest/jenkins.war 
```

1.  将下载的`jenkins.war`包重命名为`ROOT.war`：

```
 sudo mv jenkins.war ROOT.war 
```

1.  接下来，通过切换到`root`用户删除`/opt/tomcat/webapps`目录中的所有内容：

```
 sudo su - 
 cd /opt/tomcat/webapps 
 sudo rm -r * 
```

1.  现在将`ROOT.war`（重命名）从`/tmp`目录移动到`/opt/tomcat/webapps`文件夹：

```
 sudo mv /tmp/ROOT.war /opt/tomcat/webapps/ 
```

1.  列出`/opt/tomcat/webapps`目录的内容，你会注意到自动创建了一个`ROOT`文件夹：

```
 total 68964 
        drwxr-x--- 10 root   root       4096 Jul 31 23:10 ROOT 
        -rw-rw-r--  1 ubuntu ubuntu 70613578 Jul 19 22:37 ROOT.war 
```

始终建议专门为 Jenkins 配置一个专用的 Web 服务器。

1.  你可以通过`http://<Tomcat 服务器的 IP 地址>:8080/`访问 Jenkins，不需要任何额外路径。显然，Apache 服务器现在是一个 Jenkins 服务器。

删除`/opt/tomcat/webapps`目录下的所有内容（保留`ROOT`目录和`ROOT.war`），然后将`jenkins.war`文件移动到`webapps`文件夹，这样就足以将 Apache Tomcat 服务器单独用于 Jenkins。

将`jenkins.war`重命名为`ROOT.war`的步骤仅在你想要使`http://<Tomcat 服务器的 IP 地址>:8080/`成为 Jenkins 的标准 URL 时才有必要。

# 设置 Jenkins 主目录路径

在开始使用 Jenkins 之前，有一件重要的事情要配置，即`jenkins_home`路径。当你在 Tomcat 上安装 Jenkins 作为服务时，`jenkins_home`路径将自动设置为`/root/.jenkins/`。这是所有 Jenkins 配置、日志和构建存储的位置。你在 Jenkins 仪表板上创建和配置的所有内容都存储在这里。

我们需要使其更易访问，比如`/var/jenkins_home`。可以按照以下方式实现：

1.  使用以下命令停止 Apache Tomcat 服务器：

```
 sudo systemctl stop tomcat 
```

1.  打开`/opt/tomcat/conf`中的`context.xml`文件进行编辑：

```
 sudo nano /opt/tomcat/conf/context.xml 
```

1.  文件看起来是这样的（注释已删除）：

```
        <?xml version="1.0" encoding="UTF-8"?> 
        <Context> 
          <WatchedResource>WEB-INF/web.xml</WatchedResource> 
          <WatchedResource>${catalina.base}/conf/web.xml</WatchedResource> 
        </Context>
```

1.  在`<Context> </Context>`之间添加以下行：

```
        <Environment name="JENKINS_HOME" value="/var/jenkins_home" 
        type="java.lang.String"/> 
```

1.  使用以下命令启动 Tomcat 服务：

```
 sudo systemctl start tomcat 
```

# 在 Windows 上安装独立的 Jenkins 服务器

在 Windows 上安装 Jenkins 非常简单。在执行在 Windows 上安装 Jenkins 的步骤之前，让我们先看看先决条件。

# 先决条件

在开始之前，请确保您已准备好以下事项：

+   我们需要一台至少具有 4 GB RAM 和多核处理器的机器。

+   根据团队中对基础设施的管理方式，该机器可以是云平台上的一个实例（如 AWS、DigitalOcean 或任何其他云平台）、裸金属机器，或者是一个 VM（在 VMware vSphere 或其他服务器虚拟化软件上）。

+   机器上需要安装最新的任一 Windows 操作系统（Windows 7/8/10，Windows Server 2012/2012 R2/2016）。

+   检查管理员权限；安装可能会要求管理员用户名和密码。

+   确保端口`8080`处于开放状态。

# 安装 Java

按照以下步骤安装 Java：

1.  从[`java.com/en/download/manual.jsp`](https://java.com/en/download/manual.jsp)下载最新版本的 Java JRE（根据您的操作系统选择 x86 或 x64）。

1.  按照安装步骤操作。

1.  要检查 Java 是否成功安装，请使用命令提示符运行以下命令：

```
 java -version 
```

1.  您应该获得以下输出：

```
 java version "1.8.0_121" 
        Java(TM) SE Runtime Environment (build 1.8.0_121-b13) 
        Java HotSpot(TM) 64-Bit Server VM (build 25.121-b13, mixed mode) 
```

1.  要设置`JAVA_HOME`，首先使用以下命令获取 Windows 上的 Java 安装路径： 

```
 where java 
```

1.  上一个命令应输出 Java 安装路径，如下所示。复制路径但不包括`\bin\java`：

```
 C:\Program Files\Java\jdk1.8.0_121\bin\java 
```

1.  以管理员身份打开命令提示符，并运行以下命令以设置`JAVA_HOME`路径。确保使用屏幕上显示的 Java 安装路径：

```
 setx -m JAVA_HOME "C:\Program Files\Java\jdk1.8.121" 
```

# 安装最新稳定版本的 Jenkins

要安装最新稳定版本的 Jenkins，请按照以下步骤顺序执行：

1.  在 Jenkins 官方网站[`jenkins.io/download/`](https://jenkins.io/download/)上下载最新稳定的 Jenkins 软件包。要安装最新稳定版本的 Jenkins，请下载**长期支持**（**LTS**）版本。如果只想要最新版本的 Jenkins，则选择周更版。

1.  解压下载的软件包，您将找到一个`jenkins.msi`文件。

1.  运行`jenkins.msi`并按照安装步骤操作。

1.  在安装过程中，您将有选择 Jenkins 安装目录的选项。默认情况下，它将是`C:\Program Files\Jenkins`或`C:\Program Files (x86)\Jenkins`。保持默认设置，然后单击**下一步**按钮。

1.  单击**完成**按钮完成安装。

# 在 Windows 上启动、停止和重启 Jenkins

Jenkins 默认在安装时开始运行。在本节中，显示了启动、停止、重启和检查 Jenkins 服务状态的命令：

1.  通过以下命令从命令提示符中打开**服务**窗口：

```
 services.msc 
```

1.  寻找名为 Jenkins 的服务。

1.  再次右键单击 Jenkins 服务，然后单击**属性**。

1.  在**常规**选项卡下，您可以看到 Jenkins 服务名称、可执行文件路径、服务状态和启动参数。

1.  使用**启动类型**选项，您可以选择 Jenkins 在 Windows 机器上启动的方式。您可以选择自动、手动和自动（延迟启动）中的一种。确保它始终设置为自动。

1.  在以下服务状态中，有手动**启动**、**停止**、**暂停**和**恢复**Jenkins 服务的选项：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/2e09bb15-a5f1-4ba8-9b45-715f0854e770.png)

配置 Jenkins 服务的启动选项

1.  转到下一个标签，即**登录**。在这里，我们通过 Jenkins 启动的用户名。

1.  您可以选择使用本地系统帐户（不推荐），或者您可以创建一个具有特殊权限的特殊 Jenkins 用户（推荐）：

对于 Jenkins，始终首选专用帐户。原因是 Local System 帐户 无法受控制；根据组织的政策，它可能会被删除或密码可能会过期，而 Jenkins 用户帐户可以设置为首选策略和特权。

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/cfea67b3-bd34-479b-8a40-e3fa38068f7c.png)

配置 Jenkins 服务的登录选项

1.  下一个选项卡是 Recovery。在这里，我们可以指定 Jenkins 服务启动失败时的操作项目。

1.  这里有一个例子。在第一次失败时，尝试重新启动 Jenkins，在第二次失败时，尝试重新启动计算机。最后，在随后的失败中，运行一个程序来调试问题，或者我们可以运行一个脚本，将 Jenkins 失败日志通过电子邮件发送给相应的 Jenkins 管理员进行调查：

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/be84fa4e-a90c-434f-9438-842c06375f60.png)

配置 Jenkins 服务的恢复选项

# 在 Ubuntu 上安装独立的 Jenkins 服务器

在 Ubuntu 上安装 Jenkins 服务器相当容易。在执行在 Ubuntu 上安装 Jenkins 的步骤之前，让我们先看看先决条件。

# 先决条件

在开始之前，请确保您准备好了以下事项：

+   我们需要一台至少有 4GB RAM 和多核处理器的机器。

+   根据您团队中如何管理基础设施，该机器可以是云平台上的实例（如 AWS、DigitalOcean 或任何其他云平台）、裸金属机器，或者它可以是一个 VM（在 VMware vSphere 或任何其他服务器虚拟化软件上）。

+   机器应该安装了 Ubuntu 16.04。选择一个 LTS 发行版本。

+   检查管理员特权；安装可能会要求输入管理员用户名和密码。

+   确保端口`8080`是开放的。

# 安装 Java

按照以下步骤安装 Java：

1.  使用以下命令更新软件包索引：

```
 sudo apt-get update 
```

1.  接下来，安装 Java。以下命令将安装 JRE：

```
 sudo apt-get install default-jre 
```

1.  要设置`JAVA_HOME`环境变量，请首先获取 Java 安装位置。通过执行以下命令来执行此操作：

```
 update-java-alternatives -l  
```

1.  上一个命令将打印出安装在您机器上的 Java 应用程序列表，以及它们的安装路径。复制出现在您的终端上的 Java 路径：

```
 java-1.8.0-openjdk-amd64 1081
        /usr/lib/jvm/java-1.8.0-openjdk-amd64
```

1.  使用以下命令打开`/etc/environment`文件进行编辑：

```
 sudo nano /etc/environment 
```

1.  将 Java 路径（您之前复制的路径）以以下格式添加到`/etc/environment`文件中：

```
        JAVA_HOME="/usr/lib/jvm/java-1.8.0-openjdk-amd64" 
```

1.  键入 *Ctrl* + *X* 并选择 *Y* 保存并关闭文件。

1.  接下来，使用以下命令重新加载文件：

```
        sudo source /etc/environment
```

# 安装 Jenkins 的最新版本

要安装 Jenkins 的最新版本，请按照以下顺序执行以下步骤：

1.  使用以下命令将存储库密钥添加到系统中：

```
 wget --no-check-certificate -q -O \
        - https://pkg.jenkins.io/debian/jenkins-ci.org.key | \
 sudo apt-key add - 
```

1.  你应该获得一个`OK`的输出。接下来，使用以下命令添加 Debian 软件包存储库地址：

```
 echo deb http://pkg.jenkins.io/debian binary/ | \
        sudo tee /etc/apt/sources.list.d/jenkins.list 
```

1.  更新软件包索引：

```
 sudo apt-get update 
```

1.  现在，使用以下命令安装 Jenkins：

```
 sudo apt-get install jenkins 
```

1.  如果需要启动 Jenkins，请参阅 *在 Ubuntu 上启动、停止和重新启动 Jenkins* 部分。

1.  Jenkins 现在已经准备好使用了。默认情况下，Jenkins 服务在端口 `8080` 上运行。要访问 Jenkins，请在浏览器中使用 `http://localhost:8080/` 或 `http://<Jenkins 服务器 IP 地址>:8080/`。

# 安装最新稳定版本的 Jenkins

如果您希望安装 Jenkins 的稳定版本，请按顺序执行以下步骤：

1.  使用以下命令将存储库密钥添加到系统中：

```
 wget --no-check-certificate -q -O - \
        https://pkg.jenkins.io/debian-stable/jenkins-ci.org.key | \
        sudo apt-key add - 
```

1.  您应该得到一个 `OK` 的输出。接下来，使用以下命令附加 Debian 软件包存储库地址：

```
 echo deb http://pkg.jenkins.io/debian-stable binary/ | \
        sudo tee /etc/apt/sources.list.d/jenkins.list 
```

1.  更新软件包索引：

```
 sudo apt-get update
```

1.  现在，使用以下命令安装 Jenkins：

```
 sudo apt-get install jenkins 
```

1.  如果需要启动 Jenkins，请参阅 *在 Ubuntu 上启动、停止和重新启动 Jenkins* 部分。

1.  Jenkins 现在已经准备好使用了。默认情况下，Jenkins 服务在端口 `8080` 上运行。要访问 Jenkins，请在浏览器中使用 `http://localhost:8080/` 或 `http://<Jenkins 服务器 IP 地址>:8080/`。

为了排除 Jenkins 故障，访问日志文件 `/var/log/jenkins/jenkins.log`。

Jenkins 服务以用户 `Jenkins` 运行，该用户在安装时自动创建。

# 在 Ubuntu 上启动、停止和重新启动 Jenkins

Jenkins 默认在安装时开始运行。以下是启动、停止、重新启动和检查 Jenkins 服务状态的命令：

1.  要启动 Jenkins，请使用以下命令：

```
 sudo systemctl start jenkins 
```

1.  类似地，要停止 Jenkins，请使用以下命令：

```
 sudo systemctl stop jenkins 
```

1.  要重新启动 Jenkins，请使用以下命令：

```
 sudo systemctl restart jenkins 
```

1.  要检查 Jenkins 服务的状态，请使用以下 `systemctl` 命令：

```
 sudo systemctl status jenkins 
```

1.  您应该看到以下输出：

```
 ● jenkins.service - LSB: Start Jenkins at boot time 
        Loaded: loaded (/etc/init.d/jenkins; bad; vendor preset: enabled) 
        Active: active (exited) since Wed 2017-07-19 22:34:39 UTC; 6min ago 
        Docs: man:systemd-sysv-generator(8) 
```

# 在 Red Hat Linux 上安装独立的 Jenkins 服务器

在本节中，我们将学习在 Red Hat Linux 上安装 Jenkins。这里讨论的安装过程也适用于 Fedora。

# 先决条件

在开始之前，请确保您准备好以下事项：

+   我们需要一台至少拥有 4 GB RAM 和多核处理器的机器。

+   根据您团队中如何管理基础架构，该机器可能是云平台的实例（例如 AWS、DigitalOcean 或任何其他云平台）、裸机、也可能是 VM（在 VMware vSphere 或任何其他服务器虚拟化软件上）。

+   机器应该安装了 RHEL 7.3。

+   检查管理员权限；安装可能会要求输入管理员用户名和密码。

+   确保端口 `8080` 是开放的。

# 安装 Java

按照以下步骤安装 Java：

1.  移动到 `/tmp` 目录并下载 Java：

```
 cd /tmp 
 wget -O java_8.131.rpm \
        http://javadl.oracle.com/webapps/download/AutoDL? \
        BundleId=220304_d54c1d3a095b4ff2b6607d096fa80163 
```

1.  接下来，安装 Java。以下命令将安装 JRE：

```
 sudo rpm -ivh java_8.131.rpm 
```

1.  要设置 `JAVA_HOME` 环境变量，请首先获取 Java 安装位置。通过执行以下命令来执行此操作：

```
 sudo alternatives --config java 
```

1.  上一个命令将打印出在您的机器上安装的 Java 应用程序列表，以及它们的安装路径。复制在您的终端上出现的 Java 路径：

```
 There is 1 program that provides 'java'. 
        Selection    Command 
        ----------------------------------------------- 
        *+ 1           /usr/java/jre1.8.0_131/bin/java
```

1.  使用以下命令将 Java 路径（先前复制的路径）添加到 `/etc/environment` 文件内：

```
 sudo sh \
        -c "echo JAVA_HOME=/usr/java/jre1.8.0_131 >>
        /etc/environment" 
```

# 安装最新版本的 Jenkins

要安装最新版本的 Jenkins，请按照以下步骤进行：

1.  使用以下命令将 Jenkins 仓库添加到 `yum` 仓库内：

```
 sudo wget -O /etc/yum.repos.d/jenkins.repo \
         http://pkg.jenkins-ci.org/redhat/jenkins.repo 
        sudo rpm --import https://jenkins-ci.org/redhat/jenkins-ci.org.key
```

1.  使用以下命令安装 Jenkins：

```
 sudo yum install jenkins 
```

1.  如果需要启动 Jenkins，请查看 *在 Red Hat Linux 上启动、停止和重启 Jenkins* 部分。

Jenkins 现在已准备就绪。默认情况下，Jenkins 服务运行在端口 `8080` 上。要访问 Jenkins，请在浏览器中使用  `http://localhost:8080/` 或 `http://<Jenkins 服务器 IP 地址>:8080/` 。

# 安装最新稳定版本的 Jenkins

如果您更喜欢安装 Jenkins 的稳定版本，请按照以下步骤操作：

1.  使用以下命令将 Jenkins 仓库添加到 `yum` 仓库内：

```
 sudo wget -O /etc/yum.repos.d/jenkins.repo \
         http://pkg.jenkins-ci.org/redhat-stable/jenkins.repo 
 sudo rpm --import https://jenkins-ci.org/redhat/jenkins-ci.org.key 
```

1.  使用以下命令安装 Jenkins：

```
 sudo yum install jenkins
```

1.  如果需要启动 Jenkins，请查看 *在 Red Hat Linux 上启动、停止和重启 Jenkins* 部分。

# 在 Red Hat Linux 上启动、停止和重启 Jenkins

这些是启动、停止、重启和检查 Jenkins 服务状态的命令：

1.  要启动 Jenkins，请使用以下命令：

```
 sudo systemctl start jenkins 
```

1.  同样，要停止 Jenkins，请使用以下命令：

```
 sudo systemctl stop jenkins 
```

1.  要重启 Jenkins，请使用以下命令：

```
 sudo systemctl restart jenkins 
```

1.  要检查 Jenkins 服务的状态，请使用以下 `systemctl` 命令：

```
 sudo systemctl status jenkins  
```

1.  您应该看到以下输出：

```
        ● jenkins.service - LSB: Jenkins Automation Server 
          Loaded: loaded (/etc/rc.d/init.d/jenkins; bad;
          vendor preset: disabled) 
          Active: active (running) since Wed 2017-07-19 18:45:47 EDT;
           2min 31s ago 
             Docs: man:systemd-sysv-generator(8) 
          Process: 1081 ExecStart=/etc/rc.d/init.d/jenkins start
          (code=exited, status=0/SUCCESS) 
           CGroup: /system.slice/jenkins.service 
                   └─1706 /etc/alternatives/java
           -Dcom.sun.akuma.Daemon=daemonized -Djava.awt.headless=true
           -DJENKINS_HOME=/var/lib/j...
```

为了排除 Jenkins 问题，请访问 `var/log/jenkins/jenkins.log` 中的日志。

Jenkins 服务以 Jenkins 用户运行，该用户会在安装时自动创建。

# 在反向代理后运行 Jenkins

在这个例子中，我们将学习如何将一个 Nginx 服务器（在一个独立的机器上运行）放置在 Jenkins 服务器（在另一个独立的机器上运行）的前面。

# 先决条件

在开始之前，请确保您已准备好以下事项：

+   我们需要两台至少配备 4GB 内存和多核处理器的机器。一台将运行 Nginx，另一台将运行 Jenkins。

+   根据团队如何管理基础设施，该机器可以是云平台上的实例（例如 AWS、DigitalOcean 或任何其他云平台）、裸机服务器，或者它可以是一个 VM（在 VMware vSphere 或任何其他服务器虚拟化软件上）。

+   机器应该安装了 Ubuntu 16.04 或更高版本。

+   检查管理员权限；安装可能会要求管理员用户名和密码。

+   两台机器应该在同一个网络上。以下设置假设您的组织有一个用于所有服务的内部网络。

# 安装和配置 Nginx

在 Ubuntu 上安装 Nginx 很简单。请按照以下步骤在 Ubuntu 上安装 Nginx 服务器：

1.  更新本地软件包索引：

```
 sudo apt-get update
```

1.  使用以下命令安装 `nginx`：

```
 sudo apt-get install nginx 
```

# 配置 Nginx 服务器的防火墙

我们需要在我们的 Nginx 服务器上配置防火墙以允许访问 Nginx 服务。请按照以下步骤操作：

1.  使用 `ufw` 命令检查防火墙状态：

```
 sudo ufw status 
```

应该看到以下输出：

```
 Status: inactive 
```

1.  如果已启用，请转到 *第三步*。但是，如果发现它被禁用了，则使用以下命令启用防火墙：

```
 sudo ufw enable  
```

应该看到以下输出

```
        Command may disrupt existing ssh connections.
        Proceed with operation (y|n)? y 
        Firewall is active and enabled on system startup 
```

1.  使用以下命令列出可用的配置。你应该看到三个 Nginx 配置文件和一个 OpenSSH 配置文件：

```
 sudo ufw app list  
```

应该看到以下输出

```
        Available applications: 
          Nginx Full 
          Nginx HTTP 
          Nginx HTTPS 
          OpenSSH
```

`Nginx Full` 配置文件打开 `80` 端口（未加密）和 `443` 端口（TLS/SSL）。

`Nginx HTTP` 配置文件仅打开 `80` 端口（未加密）。

`Nginx HTTPS` 配置文件仅打开 `443` 端口（TLS/SSL）。

`OpenSSH` 配置文件仅打开 `22` 端口（SSH）。

始终建议启用最严格的配置文件。

1.  为了保持简单，我们将启用 `Nginx Full` 配置文件，如以下命令所示：

```
 sudo ufw allow 'Nginx Full'  
        Rules updated 
        Rules updated (v6) 
```

1.  如果未激活，则启用 `OpenSSH` 配置文件，如所示。这将允许我们继续通过 SSH 访问我们的 Nginx 机器：

```
 sudo ufw allow 'OpenSSH' 
```

如果 OpenSSH 被禁用，你将无法登录到你的 Nginx 机器。

1.  使用以下命令验证更改。你应该看到 `Nginx Full` 和 `OpenSSH` 被允许：

```
 sudo ufw status  
```

应该看到以下输出：

```
        Status: active  
        To                         Action      From 
        --                         ------      ---- 
        OpenSSH                    ALLOW       Anywhere 
        Nginx Full                 ALLOW       Anywhere 
        OpenSSH (v6)               ALLOW       Anywhere (v6) 
        Nginx Full (v6)            ALLOW       Anywhere (v6)
```

1.  使用 `systemctl` 命令检查 Nginx 服务是否正在运行：

```
 systemctl status nginx  
```

应该看到以下输出：

```
        ● nginx.service - A high performance web server and a reverse proxy
        server 
           Loaded: loaded (/lib/systemd/system/nginx.service; enabled;
           vendor preset: enabled) 
           Active: active (running) since Thu 2017-07-20 18:44:33 UTC;
        45min ago 
         Main PID: 2619 (nginx) 
            Tasks: 2 
           Memory: 5.1M 
              CPU: 13ms 
           CGroup: /system.slice/nginx.service 
                   ├─2619 nginx: master process /usr/sbin/nginx
           -g daemon on;                master_process on 
                   └─2622 nginx: worker process
```

1.  从前面的输出中，你可以看到我们的 Nginx 服务正常运行。现在尝试使用浏览器访问它。首先，使用 `ip route` 命令获取你的机器的 IP 地址：

```
 ip route  
```

应该看到以下输出：

```
        default via 10.0.2.2 dev enp0s3
        10.0.2.0/24 dev enp0s3  proto kernel
        scope link src 10.0.2.15
        192.168.56.0/24 dev enp0s8  proto kernel  scope link
        src 192.168.56.104 
```

1.  现在使用 `http://<IP Address>:80` 访问 Nginx 主页。你应该看到类似以下截图的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/475542b9-94b7-47d6-a833-8837d27d1f70.png)

Nginx 索引页面

# 启动、停止和重新启动 Nginx 服务器

现在我们的 Nginx 服务器已经启动了，让我们看看一些可以用来管理 Nginx 的命令。就像 Jenkins 一样，我们将使用 `systemctl` 命令来管理 Nginx：

1.  要停止 Nginx，请使用以下命令：

```
 sudo systemctl stop nginx
```

1.  要在停止时启动 Nginx，请使用以下命令：

```
 sudo systemctl start nginx 
```

1.  要重新启动 Nginx，请使用以下命令：

```
 sudo systemctl restart nginx 
```

1.  若要在进行配置更改后重新加载 Nginx，请使用以下命令：

```
 sudo systemctl reload nginx 
```

# 使用 OpenSSL 保护 Nginx

在本节中，我们将学习为我们的 Nginx 服务器设置自签名 SSL 证书。

# 创建 SSL 证书

运行以下命令使用 OpenSSL 创建自签名密钥和证书对：

```
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
-keyout /etc/ssl/private/nginx-selfsigned.key -out \
/etc/ssl/certs/nginx-selfsigned.crt 
```

以下表格解释了前面命令中使用的参数：

| **参数** | **描述** |
| --- | --- |
| `req` | 此参数指示我们要使用 X.509 **证书签名请求** (**CSR**) 管理。 |
| `-x509` | 此参数允许我们创建自签名证书而不是生成证书签名请求。 |
| `-nodes` | 此参数允许 OpenSSL 跳过使用密码短语验证我们的证书的选项。 |
| `-days` | 此参数设置证书有效期。 |
| `-newkey rsa: 2048` | 此参数告诉 OpenSSL 同时生成新证书和新密钥。 `rsa:2048` 选项使 RSA 密钥长度为 `2048` 位。 |
| `-keyout` | 此参数允许您将生成的私钥文件存储在您选择的位置。 |
| `-out` | 此参数允许你将生成的证书存储在你选择的位置。 |

当你执行以下命令生成一个新的私钥和证书时，将提示你提供信息。 提示将如下所示：

```
Country Name (2 letter code) [AU]:DK 
State or Province Name (full name) [Some-State]:Midtjylland 
Locality Name (eg, city) []:Brande 
Organization Name (eg, company) [Internet Widgits Pty Ltd]: Deviced.Inc 
Organizational Unit Name (eg, section) []:DevOps 
Common Name (e.g. server FQDN or YOUR name) []:<IP address of Nginx> 
Email Address []:admin@organisation.com 
```

**通用名称**（**CN**）字段，也称为**完全限定域名**（**FQDN**）非常重要。 你需要提供你的 Nginx 服务器的 IP 地址或域名。

`/etc/ssl/private/` 现在将包含你的 `nginx-selfsigned.key` 文件，而 `/etc/ssl/certs/` 将包含你的 `nginx-selfsigned.crt` 文件。

接下来，我们将创建一个强大的 Diffie-Hellman 组，用于与客户端协商**完全前向安全**（**PFS**）。我们将通过使用`openssl`来执行以下命令：

```
sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048 
```

这将需要相当长的时间，但完成后，它将在 `/etc/ssl/certs/` 内生成一个 `dhparam.pem` 文件。

# 创建强加密设置

在下一节中，我们将设置一个强大的 SSL 密码套件来保护我们的 Nginx 服务器：

1.  创建一个名为 `*s*sl-params.conf` 的配置文件在`/etc/nginx/snippets/`中，如下所示：

```
 sudo nano /etc/nginx/snippets/ssl-params.conf
```

1.  将以下代码复制到文件中：

```
        # from https://cipherli.st/ 
        # and https://raymii.org/s/tutorials/
          Strong_SSL_Security_On_nginx.html 

        ssl_protocols TLSv1 TLSv1.1 TLSv1.2; 
        ssl_prefer_server_ciphers on; 
        ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH"; 
        ssl_ecdh_curve secp384r1; 
        ssl_session_cache shared:SSL:10m; 
        ssl_session_tickets off; 
        ssl_stapling on; 
        ssl_stapling_verify on; 
        resolver 8.8.8.8 8.8.4.4 valid=300s; 
        resolver_timeout 5s; 
        # disable HSTS header for now 
        #add_header Strict-Transport-Security "max-age=63072000;
         includeSubDomains; preload"; 
        add_header X-Frame-Options DENY; 
        add_header X-Content-Type-Options nosniff; 

        ssl_dhparam /etc/ssl/certs/dhparam.pem; 
```

1.  输入 *Ctrl* + *X*，选择 *Y* 保存并关闭文件。

我们使用了 Remy van Elst 在 [`cipherli.st/`](https://cipherli.st/) 中提供的建议。

# 修改 Nginx 配置

接下来，我们将修改我们的 Nginx 配置以启用 SSL。 按照以下步骤进行：

1.  首先，备份你现有的位于`/etc/nginx/sites-available/`中名为`default`的 Nginx 配置文件：

```
 sudo cp /etc/nginx/sites-available/default \
        /etc/nginx/sites-available/default.backup
```

1.  现在，使用以下命令打开文件进行编辑：

```
 sudo nano /etc/nginx/sites-available/default 
```

1.  你会在文件中找到很多被注释掉的内容。 如果你暂时忽略它们，你可能会看到以下内容：

```
        server { 
            listen 80 default_server; 
            listen [::]:80 default_server; 

            # SSL configuration 

            # listen 443 ssl default_server; 
            # listen [::]:443 ssl default_server; 

            . . . 

            root /var/www/html; 

            . . . 

            index index.html index.htm index.nginx-debian.html; 
            server_name _; 

            . . . 
```

1.  我们将修改配置以便未加密的 HTTP 请求自动重定向到加密的 HTTPS。 我们将通过添加以下三行来执行此操作，如下方代码中所示：

```
        server { 
            listen 80 default_server; 
            listen [::]:80 default_server; 
            server_name <nginx_server_ip or nginx domain name>; 
            return 301 https://$server_name$request_uri; 
        } 

            # SSL configuration 

            # listen 443 ssl default_server; 
            # listen [::]:443 ssl default_server; 

            . . .
```

1.  从前面的代码中，你可以看到我们已关闭了服务器块。

1.  接下来，我们将启动一个新的服务器块，取消注释使用端口`443`的两个`listen`指令，并在这些行中添加`http2`以启用 HTTP/2，如下代码块所示：

```
        server { 
            listen 80 default_server; 
            listen [::]:80 default_server; 
            server_name <nginx_server_ip or nginx domain name>; 
            return 301 https://$server_name$request_uri; 
        } 

        server { 

            # SSL configuration 

            listen 443 ssl http2 default_server; 
            listen [::]:443 ssl http2 default_server; 

            . . . 
```

1.  接下来，我们将添加我们自签名证书和密钥的位置。 我们只需要包含我们设置的两个片段文件：

```
        server { 
            listen 80 default_server; 
            listen [::]:80 default_server; 
            server_name <nginx_server_ip or nginx domain name>; 
            return 301 https://$server_name$request_uri; 
        } 
        server { 

            # SSL configuration 

            listen 443 ssl http2 default_server; 
            listen [::]:443 ssl http2 default_server; 
            ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt; 
            ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key; 
            include snippets/ssl-params.conf; 

            . . .
```

1.  接下来，我们将在 SSL 服务器块内设置`server_name`值为我们的 Nginx IP 或域名。默认情况下，`server_name` 可能被设置为一个下划线(`_`)*,* 如下代码块所示：

```
        server { 
            # SSL configuration 

            . . . 

            server_name <nginx_server_ip or nginx domain name>; 

            . . . 
        } 
```

1.  输入 *Ctrl* + *X*，选择 *Y* 保存并关闭文件。

# 启用更改并测试我们的 Nginx 设置

现在我们将重新启动 Nginx 来实施我们的新更改：

1.  首先，检查我们的文件中是否有任何语法错误。通过输入以下命令来执行此操作：

```
 sudo nginx -t 
```

1.  如果一切顺利，你应该能够看到类似以下命令输出的内容：

```
 nginx: [warn] "ssl_stapling" ignored, issuer certificate not found 
        nginx: the configuration file /etc/nginx/nginx.conf syntax is ok 
        nginx: configuration file /etc/nginx/nginx.conf test is successful 
```

1.  使用以下命令重新启动 Nginx：

```
 sudo systemctl restart nginx 
```

1.  接下来，使用`http://<Nginx_IP_Address>:80`访问您的 Nginx 服务器。您应该注意到您已被自动重定向到`https://<Nginx_IP_Address>:80`。

1.  您将看到类似以下截图的警告：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/5778110f-0867-4c0c-b119-383604539831.png)

SSL 警告

1.  这是预期的，因为我们创建的证书未由您浏览器信任的证书颁发机构签名。

1.  单击高级按钮，然后单击**继续访问 192.168.56.104（不安全）**：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/f560e82a-351b-4746-afe3-af784edc9e8b.png)

以不安全的方式继续

1.  您现在应该能够看到 Nginx 默认页面，如以下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/5c249a7f-420a-40f2-ad57-94182360e9f5.png)

带有 SSL 加密的 Nginx 索引页面

# 配置 Jenkins 服务器

在本节中，我们将对我们的 Jenkins 服务器执行一些配置。要首先设置 Jenkins 服务器，请参阅*在 Ubuntu 上安装独立的 Jenkins 服务器*部分。

一旦您运行起一个 Jenkins 服务器，就按照以下步骤进行操作：

1.  要使 Jenkins 与 Nginx 配合工作，我们需要更新 Jenkins 配置，以便 Jenkins 服务器仅侦听 Jenkins IP 地址或 Jenkins 域名接口，而不是所有接口（`0.0.0.0`）。如果 Jenkins 监听所有接口，则可能可以在其原始未加密端口（`8080`）上访问。

1.  为此，请修改`/etc/default/jenkins`配置文件，如下所示：

```
 sudo nano /etc/default/jenkins
```

1.  在文件中，滚动到最后一行或者只查找`JENKINS_ARGS`行。

1.  将以下参数追加到现有的`JENKINS_ARGS`值：

```
        -httpListenAddress=<IP Address of your Jenkins>  
```

1.  最终的`JENKINS_ARGS`行应该类似于这样（单行）：

```
        JENKINS_ARGS="--webroot=/var/cache/$NAME/war
        --httpPort=$HTTP_PORT
        --httpListenAddress=192.168.56.105" 
```

1.  输入*Ctrl* + *X*并选择*Y*以保存并关闭文件。

1.  为了使新的配置生效，重新启动 Jenkins 服务器：

```
 sudo systemctl restart jenkins 
```

1.  要检查 Jenkins 是否正常运行，请执行以下命令：

```
 sudo systemctl status jenkins  
```

你应该能够看到以下截图：

```
        ● jenkins.service - LSB: Start Jenkins at boot time 
           Loaded: loaded (/etc/init.d/jenkins; bad;
           vendor preset: enabled) 
           Active: active (exited) since Sat 2017-07-22 23:30:36 UTC;
           18h ago 
             Docs: man:systemd-sysv-generator(8) 
```

# 将反向代理设置添加到 Nginx 配置中

以下步骤将帮助您向 Nginx 配置中添加反向代理设置：

1.  打开 Nginx 配置文件进行编辑：

```
 sudo nano /etc/nginx/sites-available/default
```

1.  因为我们将所有请求发送到我们的 Jenkins 服务器，所以请注释掉默认的`try_files`行，如下面的代码块所示：

```
        location / { 
          # First attempt to serve request as file, then 
          # as directory, then fall back to displaying a 404\. 
          # try_files $uri $uri/ =404; 
        } 
```

1.  接下来，添加如下所示的代理设置：

```
        location / { 
          # First attempt to serve request as file, then 
          # as directory, then fall back to displaying a 404\. 
          #try_files $uri $uri/ =404; 
          include /etc/nginx/proxy_params; 
          proxy_pass http://<ip address of jenkins>:8080; 
          proxy_read_timeout  90s; 
          # Fix potential "It appears that your reverse proxy set up
 is broken" error. 
          proxy_redirect http://<ip address of jenkins>:8080
 https://your.ssl.domain.name; 
        } 
```

1.  输入*Ctrl* + *X*并选择*Y*以保存并关闭文件。

1.  运行以下命令检查 Nginx 配置文件中是否存在任何语法错误：

```
 sudo nginx -t  
```

你应该能够看到以下输出：

```
        nginx: [warn] "ssl_stapling" ignored, issuer certificate not found 
        nginx: the configuration file /etc/nginx/nginx.conf syntax is ok 
        nginx: configuration file /etc/nginx/nginx.conf test is successful 
```

1.  如果输出没有错误，请重新启动 Nginx 以使新配置生效。使用以下命令：

```
 sudo systemctl restart nginx
```

1.  接下来，使用`https://<nginx_ip_address>:80`访问您的 Nginx 服务器：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/e711c177-52a8-4c0a-b7e8-43858a7ab8f6.png)

Jenkins 入门页面

# 在同一台机器上运行 Nginx 和 Jenkins

如果要在反向代理服务器（Nginx）后运行 Jenkins，且 Jenkins 服务器和 Nginx 服务器在同一台机器上运行，则按顺序执行以下各部分：

1.  使用至少 4 GB RAM 和多核处理器设置一台机器。

1.  根据团队如何管理基础设施，该机器可能是云平台上的实例（如 AWS、DigitalOcean 或任何其他云平台）、裸机，或者可能是 VM（在 VMware vSphere 或任何其他服务器虚拟化软件上）。

1.  机器应安装 Ubuntu 16.04 或更高版本。

1.  检查管理员权限；安装可能会要求输入管理员用户名和密码。

1.  安装 Nginx；参考*安装和配置 Nginx*部分。

1.  配置防火墙；参考*在 Nginx 服务器上配置防火墙*部分。

1.  使用 OpenSSL 安全地配置 Nginx 服务器；参考*使用 OpenSSL 安全地配置 Nginx*部分。

1.  使用以下命令配置防火墙以允许端口`8080`上的流量：

```
 sudo ufw allow 8080 
```

1.  接下来，使用以下命令检查防火墙状态：

```
 sudo ufw status  
```

您应该看到以下输出：

```
        Status: active  
        To                         Action      From 
        --                         ------      ---- 
        OpenSSH                    ALLOW       Anywhere 
        Nginx Full                 ALLOW       Anywhere 
        8080                       ALLOW       Anywhere 
        OpenSSH (v6)               ALLOW       Anywhere (v6) 
        Nginx Full (v6)            ALLOW       Anywhere (v6) 
        8080 (v6)                  ALLOW       Anywhere (v6) 
```

1.  安装 Jenkins，参考*在 Ubuntu 上安装独立 Jenkins 服务器*部分。

1.  配置 Jenkins 服务器；参考*配置 Jenkins 服务器*部分。在执行本节中提到的步骤时，请确保将`<IP Address of your Jenkins>`替换为`127.0.0.1`。

1.  在 Nginx 中添加反向代理设置；参考*将反向代理设置添加到 Nginx 配置*部分。在执行本节中提到的步骤时，您将被要求在 Nginx 配置文件的各处输入 Jenkins 服务器 IP。由于我们的 Jenkins 服务器现在在与 Nginx 相同的机器上运行，因此`<IP Address of your Jenkins>`的值应为`localhost`。

# 在 Docker 上运行 Jenkins

在 Docker 上运行 Jenkins 的真正优势在于当您需要快速创建多个开发和分段实例时。它还非常有用，可以在主 Jenkins 服务器上执行维护活动时将流量重定向到次要 Jenkins 服务器。虽然我们稍后将看到这些用例，但让我们首先尝试在 Docker 上运行 Jenkins。

# 先决条件

在开始之前，请确保准备了以下内容：

+   我们需要一台至少拥有 4 GB RAM（越多越好）和多核处理器的机器。

+   根据团队中的基础设施管理方式，机器可能是云平台上的实例（如 AWS、DigitalOcean 或任何其他云平台）、裸机，或者可能是 VM（在 VMware vSphere 或任何其他服务器虚拟化软件上）。

+   机器应该安装 Ubuntu 16.04 或更高版本。

+   检查管理员权限；安装可能会要求管理员用户名和密码。

# 设置 Docker 主机

在本节中，我们将学习如何使用存储库方法和使用 Debian 软件包安装 Docker。按照以下各节中的步骤设置 Docker 主机。

# 设置存储库

按照以下步骤设置存储库：

1.  使用以下命令让 `apt` 使用存储库：

```
 sudo apt-get install apt-transport-https ca-certificates 
```

1.  使用以下命令添加 Docker 的官方 GPG 密钥：

```
 curl -fsSL https://yum.dockerproject.org/gpg | sudo apt-key add -
```

1.  使用以下命令验证密钥 ID 是否确实为 `58118E89F3A912897C070ADBF76221572C52609D`：

```
 apt-key fingerprint 58118E89F3A912897C070ADBF76221572C52609D
```

你应该看到以下输出：

```
        pub  4096R/2C52609D 2015-07-14 
        Key fingerprint = 5811 8E89 F3A9 1289 7C07  0ADB F762 2157 2C52
         609D 
        uid  Docker Release Tool (releasedocker) docker@docker.com 
```

1.  使用以下命令设置稳定存储库以下载 Docker：

```
 sudo add-apt-repository \
       "deb https://apt.dockerproject.org/repo/ubuntu-$(lsb_release \
       -cs) main" 
```

建议始终使用稳定版本的存储库。

# 安装 Docker

设置存储库后，请执行以下步骤安装 Docker：

1.  使用以下命令更新 `apt` 包索引：

```
 sudo apt-get update 
```

1.  要安装最新版本的 Docker，请运行以下命令：

```
 sudo apt-get -y install docker-engine 
```

1.  要安装特定版本的 Docker，请使用以下命令列出可用版本：

```
 apt-cache madison docker-engine  
```

你应该看到以下输出：

```
        docker-engine | 1.16.0-0~trusty |
        https://apt.dockerproject.org/repo ubuntu-trusty/main amd64
        Packages docker-engine | 1.13.3-0~trusty |
        https://apt.dockerproject.org/repo ubuntu-trusty/main amd64
        Packages  
        ...
```

上一个命令的输出取决于前一节中配置的存储库类型（*设置存储库*）。

1.  接下来，执行以下命令来安装特定版本的 Docker：

```
 sudo apt-get -y install docker-engine=<VERSION_STRING>  
        sudo apt-get -y install docker-engine=1.16.0-0~trusty 
```

1.  Docker 服务会自动启动。要验证 Docker 是否已安装并运行，请执行以下命令：

```
 sudo docker run hello-world  
```

1.  前一个命令应该没有错误，并且你应该看到一个 `Hello from Docker!` 的消息：

```
        Unable to find image 'hello-world:latest' locally 
        latest: Pulling from library/hello-world 
        b04784fba78d: Pull complete 
        Digest: sha256:
          f3b3b28a45160805bb16542c9531888519430e9e6d6ffc09d72261b0d26ff74f 
        Status: Downloaded newer image for hello-world:latest 

        Hello from Docker! 
        This message shows that your installation appears to be working
        correctly. 
        ... 
```

# 从软件包安装

按照以下步骤使用 `.deb` 软件包安装 Docker：

1.  从 [`apt.dockerproject.org/repo/pool/main/d/docker-engine/`](https://apt.dockerproject.org/repo/pool/main/d/docker-engine/) 下载你选择的 `.deb` 软件包。

1.  要安装已下载的软件包，请执行以下命令：

```
 sudo dpkg -i /<path to package>/<docker package>.deb
```

1.  运行以下命令验证 Docker 安装：

```
 sudo docker run hello-world  
```

你应该看到以下输出：

```
        Hello from Docker! 
        This message shows that your installation appears to be working
        correctly. 
```

# 运行 Jenkins 容器

现在我们的 Docker 主机已准备好，让我们运行 Jenkins：

1.  运行以下命令以启动 Jenkins 容器。这可能需要一些时间，因为 Docker 将尝试从 Docker Hub 下载 Jenkins Docker 镜像 (`jenkins/jenkins:lts`)：

```
 docker run -d --name jenkins_dev -p 8080:8080 \
        -p 50000:50000 jenkins/jenkins:lts  
```

你应该看到以下输出：

```
        ...
 ...
 ... 
        d52829d9da9e0a1789a3117badc862039a0084677be6a771a959d8467b9cc267 
```

1.  以下表格解释了我们在上一个命令中使用的 Docker 命令：

| **参数** | **描述** |
| --- | --- |
| `docker` | 用于调用 Docker 实用程序。 |
| `run` | 用于运行容器的 Docker 命令。 |
| `-d` | 此选项在后台运行容器。 |
| `--name` | 此选项允许您为容器命名。 |
| `-p` | 该选项用于将容器的端口与主机映射。  |
| `jenkins/jenkins:lts` | 用于创建容器的 Docker 镜像及其版本的名称。 `jenkins/jenkins` 是 Jenkins Docker 镜像，`lts` 是该镜像的特定版本。 |

1.  要查看正在运行的容器列表，请执行以下命令：

```
 sudo docker ps --format "{{.ID}}: {{.Image}} {{.Names}}"
```

您应该看到以下输出：

```
        d52829d9da9e: jenkins/jenkins:lts jenkins_dev 
```

要使用 Jenkins 的最新 LTS 版本，请使用 `jenkins/jenkins:lts` Jenkins Docker 镜像。

要使用 Jenkins 的最新每周发布版本，请使用 `jenkins/jenkins` Jenkins Docker 镜像。

1.  使用以下命令记下您的 Docker 主机 IP：

```
 sudo ip route  
```

您应该看到以下输出：

```
        default via 10.0.2.2 dev enp0s3 
        10.0.2.0/24 dev enp0s3  proto kernel  scope link  src 10.0.2.15 
        172.17.0.0/16 dev docker0  proto kernel  scope link  src 172.17.0.1 
        192.168.56.0/24 dev enp0s8  proto kernel  scope link
        src 192.168.56.107 
```

1.  您的 Jenkins 服务器现在可通过`http：<Docker 主机的 IP 地址>：8080`访问。现在您应该能够看到 Jenkins 入门页面。

1.  要继续进行 Jenkins 设置，您可能需要`initialAdminPassword`密钥。此文件位于`/var/jenkins_home/secrets/`内。您可以通过以下方式之一获取`initialAdminPassword`文件内的数据。您可以使用以下命令`docker exec`，如下所示：

```
 sudo docker exec -it jenkins_dev \
        cat /var/jenkins_home/secrets/initialAdminPassword
```

或者，通过登录到正在运行的 Jenkins 容器内，使用相同的`docker exec`命令，如下所示：

```
 sudo docker exec -it jenkins_dev bash
```

1.  一旦您进入容器，请执行以下 Linux 命令以获取文件的内容：

```
 cat /var/jenkins_home/secrets/initialAdminPassword \ 
```

这两个命令都会打印`initialAdminPassword`文件的内容，类似于以下所示的内容：

```
 1538ededb4e94230aca12d10dd461e52 
```

这里，`-i` 选项允许您与 Docker 容器进行交互，而 `-t` 选项分配一个伪 `-tty`。

1.  当您仍在 Jenkins 容器内时，请注意`jenkins_home`目录位于`/var/`内，并且`jenkins.war`文件位于`/usr/share/jenkins`内。

`jenkins_home` 是一个非常重要的目录，其中包含您的 Jenkins 作业、构建、元数据、配置、用户等所有内容。

# 使用数据卷运行 Jenkins 容器

在前面的部分中，我们创建了一个 Jenkins 容器，但没有任何机制使`jenkins_home`目录内的数据持久化。简单来说，如果由于某种原因删除 Jenkins 容器，则会删除您的`jenkins_home`目录。

幸运的是，还有一种更好的方法来使用 Docker 运行 Jenkins，那就是使用数据卷。数据卷是特殊的目录，使数据持久化并独立于容器的生命周期。如果容器将数据写入数据卷，则删除容器仍会使数据可用，因为容器及其关联的数据卷是两个不同的实体。

让我们使用数据卷创建一个 Jenkins 容器：

1.  使用以下命令运行 Jenkins 容器：

```
 sudo docker run -d --name jenkins_prod -p 8080:8080\
        -p 50000:50000 -v jenkins-home-prod:/var/jenkins_home \
        jenkins/jenkins:lts 
```

1.  `-v jenkins-home-prod:/var/jenkins_home` 选项将创建一个名为`jenkins-home-prod`的数据卷，并将其映射到容器内的`/var/jenkins_home`目录。

1.  执行以下命令以查看 `jenkins_prod` Jenkins 容器内 `/var/jenkins_home` 目录的内容：

```
 sudo docker exec -it jenkins_prod ls -lrt /var/jenkins_home 
```

您应该看到以下输出：

```
        total 72 
        drwxr-xr-x  2 jenkins jenkins 4096 Jul 26 20:41 init.groovy.d 
        -rw-r--r--  1 jenkins jenkins  102 Jul 26 20:41
         copy_reference_file.log 
        drwxr-xr-x 10 jenkins jenkins 4096 Jul 26 20:41 war 
        -rw-r--r--  1 jenkins jenkins    0 Jul 26 20:41
         secret.key.not-so-secret 
        -rw-r--r--  1 jenkins jenkins   64 Jul 26 20:41 secret.key 
        drwxr-xr-x  2 jenkins jenkins 4096 Jul 26 20:41 plugins 
        drwxr-xr-x  2 jenkins jenkins 4096 Jul 26 20:41 jobs 
        drwxr-xr-x  2 jenkins jenkins 4096 Jul 26 20:41 nodes 
        -rw-r--r--  1 jenkins jenkins  159 Jul 26 20:41
          hudson.model.UpdateCenter.xml 
        -rw-------  1 jenkins jenkins 1712 Jul 26 20:41 identity.key.enc 
        drwxr-xr-x  2 jenkins jenkins 4096 Jul 26 20:41 userContent 
        -rw-r--r--  1 jenkins jenkins  907 Jul 26 20:41 nodeMonitors.xml 
        drwxr-xr-x  3 jenkins jenkins 4096 Jul 26 20:41 logs 
        -rw-r--r--  1 jenkins jenkins    6 Jul 26 20:41
          jenkins.install.UpgradeWizard.state 
        drwxr-xr-x  3 jenkins jenkins 4096 Jul 26 20:41 users 
        drwx------  4 jenkins jenkins 4096 Jul 26 20:41 secrets 
        -rw-r--r--  1 jenkins jenkins   94 Jul 26 20:41 jenkins.CLI.xml 
        -rw-r--r--  1 jenkins jenkins 1592 Jul 26 20:41 config.xml 
        drwxr-xr-x  2 jenkins jenkins 4096 Jul 26 20:41 updates 
```

1.  要列出您的 Docker 卷，请执行以下命令：

```
 sudo docker volume ls 
```

您应该看到以下输出：

```
        DRIVER              VOLUME NAME 

        local               jenkins-home-prod 
```

1.  现在您有一个带有持久 `jenkins_home` 目录的 Jenkins 容器。

# 测试数据卷

我们将通过执行以下步骤来测试我们的数据卷。

1.  我们将对 Jenkins 服务器进行一些更改；这将修改 `/var/jenkins_home` 目录中的内容。

1.  我们将删除 Jenkins 容器。

1.  我们将创建一个新的 Jenkins 容器，该容器将使用相同的数据卷。

1.  使用以下命令检查活动的 Jenkins 容器：

```
 sudo docker ps --format "{{.ID}}: {{.Image}} {{.Names}}"
```

您应该看到以下输出：

```
        5d612225f533: jenkins/jenkins:lts jenkins_prod 
```

1.  使用 `http://<Docker 主机的 IP 地址>:8080` 访问 Jenkins 服务器。

1.  使用以下命令获取 `initialAdminPassword` 文件的内容：

```
 sudo docker exec -it jenkins_prod \
        cat /var/jenkins_home/secrets/initialAdminPassword
```

您应该看到以下输出：

```
        7834556856f04925857723cc0d0523d7
```

1.  在 Jenkins 页面的管理员密码字段下粘贴 `initialAdminPassword` 并继续进行 Jenkins 设置。

1.  在创建第一个管理员用户步骤中创建一个新用户，如下所示的截图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/7e5005a6-ceda-46d4-a968-edb72ea1ff52.png)

在 Jenkins 上创建第一个管理员用户

1.  继续进行剩余的步骤。

1.  执行以下命令以列出 `/var/jenkins_home/users` 目录的内容。这是您拥有所有用户帐户的位置：

```
 sudo docker exec -it jenkins_prod ls -lrt /var/jenkins_home/users 
```

输出应该如下所示：

```
        total 4 
        drwxr-xr-x 2 jenkins jenkins 4096 Jul 26 21:38 developer 
```

1.  注意我们新创建的用户 developer 在 `users` 目录下列出。

1.  现在让我们使用以下命令删除 `jenkins_prod` Jenkins 容器：

```
 sudo docker kill jenkins_prod
        sudo docker rm jenkins_prod 
```

1.  使用以下命令列出现有的 Docker 容器（运行/停止）：

```
 sudo docker ps -a --format "{{.ID}}: {{.Image}} {{.Names}}"
```

您应该看到以下输出。但是，您不应该在列表中看到 `jenkins_prod`：

```
        3511cd609b1b: hello-world eloquent_lalande 
```

1.  使用以下命令列出卷的内容：

```
 sudo docker volume ls 
```

您应该看到类似的内容。您可以看到删除容器并没有删除其关联的数据卷：

```
        DRIVER              VOLUME NAME 

        local               jenkins-home-prod 
```

1.  现在让我们创建一个名为 `jenkins_prod` 的新 Jenkins 容器，该容器使用现有的 `jenkins-home-prod` 卷：

```
 sudo docker run -d --name jenkins_prod -p 8080:8080 \
        -p 50000:50000 -v jenkins-home-prod:/var/jenkins_home \
        jenkins/jenkins:lts 
```

1.  尝试访问 Jenkins 仪表板，使用 `http://<Docker 主机的 IP 地址>:8080`。您将看不到 Jenkins 设置页面；相反，您应该看到登录页面。

1.  使用我们之前创建的用户登录 Jenkins。您应该能够登录。这证明我们的整个 Jenkins 配置是完好的。

# 创建 Jenkins 的开发和分段实例

许多时候，您需要一个 Jenkins 生产服务器的开发或分段实例来测试新功能。Docker 可以轻松且安全地创建多个 Jenkins 服务器实例。

下面是如何做的。在此部分中，我们将使用我们的 Jenkins 生产实例创建一个开发和一个分段实例。

# 先决条件

在我们开始之前，请确保您准备好以下内容：

+   我们需要一个运行 Jenkins 实例（生产）并利用数据卷的 Docker 主机

+   参考*使用数据卷运行 Jenkins 容器*部分

# 创建一个空数据卷

我们将为我们的 Jenkins 的暂存和开发实例分别创建名为`jenkins-home-staging`和`jenkins-home-development`的数据卷：

1.  要创建一个空的`jenkins-home-staging`数据卷，请运行以下命令：

```
 sudo docker volume create --name jenkins-home-staging 
```

1.  要创建一个空的`jenkins-home-development`数据卷，请运行以下命令：

```
 sudo docker volume create --name jenkins-home-development
```

1.  使用`docker volume`命令列出新创建的数据卷：

```
 sudo docker volume ls 
```

您应该看到以下输出：

```
        DRIVER              VOLUME NAME 

        local               jenkins-home-prod 
        local               jenkins-home-development 
        local               jenkins-home-staging
```

1.  从前面的列表中，您可以看到新创建的名为`jenkins-home-staging`和`jenkins-home-development`的数据卷。

如果您已经按照前一节的步骤进行了操作，您还应该看到正在由我们的 Jenkins 生产实例`jenkins_prod`使用的数据卷`jenkins-home-prod`。

# 在数据卷之间复制数据

现在我们有了新创建的空数据卷。让我们将`jenkins-home-prod`的内容复制到每一个数据卷：

1.  使用以下命令将`jenkins-home-prod`的内容复制到`jenkins-home-staging`：

```
 sudo docker run --rm -it --user root \
        -v jenkins-home-prod:/var/jenkins_home \
        -v jenkins-home-staging:/var/jenkins_home_staging \
        jenkins/jenkins:lts bash -c "cd /var/jenkins_home_staging \
        && cp -a /var/jenkins_home/* ." 
```

1.  前一个命令将执行以下操作：

    +   它首先将使用 Jenkins 的 Docker 镜像`jenkins/jenkins:lts`创建一个交互式容器（容器是临时的）。

    +   在这个临时容器上执行的所有操作都将使用`root`用户。注意前一个命令中的`--user root`选项。

    +   它将`jenkins-home-prod`数据卷的内容挂载到容器内的`/var/jenkins_home`目录中。注意`-v jenkins-home-prod:/var/jenkins_home`选项。

    +   类似地，它将`jenkins-home-staging`数据卷的不存在内容挂载到容器内不存在的`/var/jenkins_home_staging`目录中。注意`-v jenkins-home-staging:/var/jenkins_home_staging`选项。

    +   然后，它将`/var/jenkins_home`的内容复制到`/var/jenkins_home_staging`。注意`bash -c "cd /var/jenkins_home_staging && cp -a /var/jenkins_home/*"`选项。

1.  现在，使用以下命令将`jenkins-home-prod`的内容复制到`jenkins-home-development`：

```
 sudo docker run --rm -it --user root \
        -v jenkins-home-prod:/var/jenkins_home \
        -v jenkins-home-development:/var/jenkins_home_development \
        jenkins/jenkins:lts bash -c "cd /var/jenkins_home_development \
        && cp -a /var/jenkins_home/* ." 
```

1.  现在我们在所有三个数据卷上都有相同的数据：`jenkins-home-prod`、`jenkins-home-staging`和`jenkins-home-development`。

# 创建开发和暂存实例

现在我们已经为开发和暂存准备好了数据卷，让我们使用它们生成容器：

1.  要创建名为`jenkins_staging`的 Jenkins 暂存实例，并使用`jenkins-home-staging`数据卷，请运行以下命令：

```
 sudo docker run -d --name jenkins_staging \
        -v jenkins-home-staging:/var/jenkins_home -p 8081:8080 \
        -p 50001:50000 jenkins/jenkins:lts
```

前一个命令将创建一个运行在端口`8080`上的 Jenkins 实例，并将其映射到 Docker 主机的端口`8081`。我们选择 Docker 主机上的不同端口，因为我们已经有我们的 Jenkins 生产实例`jenkins_prod`运行在端口`8080`上，该端口映射到 Docker 主机的端口`8080`。

相同的原因也适用于将 Jenkins 实例上的端口`50000`映射到 Docker 主机上的端口`50001`。

1.  尝试使用`http：<Docker 主机的 IP 地址>：8081`访问您的 Jenkins 暂存实例。

1.  同样地，要使用 `jenkins-home-development` 数据卷创建一个名为 `jenkins_development` 的 Jenkins 开发实例，请运行以下命令：

```
 sudo docker run -d --name jenkins_development \
        -v jenkins-home-development:/var/jenkins_home -p 8082:8080 \
        -p 50002:50000 jenkins/jenkins:lts 
```

上一个命令将创建一个运行在端口 `8080` 上并映射到 Docker 主机端口 `8082` 的 Jenkins 实例。我们选择 Docker 主机上的不同端口，因为端口 `8080` 和 `8081` 已经在 Docker 主机上被使用了。

同样的理由也适用于将 Jenkins 实例上的端口 `50000` 映射到 Docker 主机上的端口 `50002`。

1.  尝试使用 `http:<Docker 主机的 IP 地址>:8082` 访问您的 Jenkins 开发实例。

# 摘要

在本章中，我们学习了如何在 Apache Tomcat 服务器上安装 Jenkins，以及如何在各种操作系统上作为独立应用程序安装 Jenkins。我们还学习了如何在 Jenkins 服务器前面设置一个反向代理服务器（Nginx），并使用 SSL 安全连接。

最重要的是，我们学会了如何在 Docker 上运行 Jenkins。我们还看到了在 Docker 上使用数据卷的优势，并学习了如何利用它们来创建我们 Jenkins 服务器的按需实例（开发或者预备环境）。

当前章节的主要目标是向读者展示 Jenkins 在安装过程和支持的操作系统种类方面的多样性。Jenkins 管理将在第四章中讨论，*配置 Jenkins*。

在下一章中，我们将快速概述 Jenkins 2.x 中的新特性。
