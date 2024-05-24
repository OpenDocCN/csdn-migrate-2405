# Docker 和 Jenkins 持续交付（一）

> 原文：[`zh.annas-archive.org/md5/7C44824F34694A0D5BA0600DC67F15A8`](https://zh.annas-archive.org/md5/7C44824F34694A0D5BA0600DC67F15A8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

多年来，我一直观察软件交付流程。我写了这本书，因为我知道有多少人仍然在发布过程中挣扎，并在日夜奋斗后感到沮丧。尽管多年来已经开发了许多自动化工具和流程，但这一切仍在发生。当我第一次看到持续交付流程是多么简单和有效时，我再也不愿意回到繁琐的传统手动交付周期。这本书是我经验的结果，也是我进行的许多持续交付研讨会的结果。我分享了使用 Jenkins、Docker 和 Ansible 的现代方法；然而，这本书不仅仅是工具。它介绍了持续交付背后的理念和推理，最重要的是，我向所有我遇到的人传达的主要信息：持续交付流程很简单，要使用它！

# 本书内容

第一章《介绍持续交付》介绍了公司传统的软件交付方式，并解释了使用持续交付方法改进的理念。本章还讨论了引入该流程的先决条件，并介绍了本书将构建的系统。

第二章《介绍 Docker》解释了容器化的概念和 Docker 工具的基础知识。本章还展示了如何使用 Docker 命令，将应用程序打包为 Docker 镜像，发布 Docker 容器的端口，并使用 Docker 卷。

第三章《配置 Jenkins》介绍了如何安装、配置和扩展 Jenkins。本章还展示了如何使用 Docker 简化 Jenkins 配置，并实现动态从节点供应。

第四章《持续集成管道》解释了流水线的概念，并介绍了 Jenkinsfile 语法。本章还展示了如何配置完整的持续集成管道。

第五章《自动验收测试》介绍了验收测试的概念和实施。本章还解释了工件存储库的含义，使用 Docker Compose 进行编排，以及编写面向 BDD 的验收测试的框架。

第六章，*使用 Ansible 进行配置管理*，介绍了配置管理的概念及其使用 Ansible 的实现。本章还展示了如何将 Ansible 与 Docker 和 Docker Compose 一起使用。

第七章，*持续交付流水线*，结合了前几章的所有知识，以构建完整的持续交付过程。本章还讨论了各种环境和非功能测试的方面。

第八章，*使用 Docker Swarm 进行集群*，解释了服务器集群的概念及其使用 Docker Swarm 的实现。本章还比较了替代的集群工具（Kubernetes 和 Apache Mesos），并解释了如何将集群用于动态 Jenkins 代理。

第九章，*高级持续交付*，介绍了与持续交付过程相关的不同方面的混合：数据库管理、并行流水线步骤、回滚策略、遗留系统和零停机部署。本章还包括持续交付过程的最佳实践。

# 本书所需内容

Docker 需要 64 位 Linux 操作系统。本书中的所有示例都是使用 Ubuntu 16.04 开发的，但任何其他具有 3.10 或更高内核版本的 Linux 系统都足够。

# 本书适合对象

本书适用于希望改进其交付流程的开发人员和 DevOps。无需先前知识即可理解本书。

# 约定

在本书中，您将找到一些区分不同信息种类的文本样式。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：`docker info`

代码块设置如下：

```
      pipeline {
           agent any
           stages {
                stage("Hello") {
                     steps {
                          echo 'Hello World'
                     }
                }
           }
      }
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目以粗体设置：

```
 FROM ubuntu:16.04
 RUN apt-get update && \
 apt-get install -y python
```

任何命令行输入或输出都以以下方式编写：

```
$ docker images
REPOSITORY              TAG     IMAGE ID         CREATED            SIZE
ubuntu_with_python      latest  d6e85f39f5b7  About a minute ago 202.6 MB
ubuntu_with_git_and_jdk latest  8464dc10abbb  3 minutes ago      610.9 MB
```

新术语和重要单词以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中显示为这样："点击 新项目"。

警告或重要说明以这样的框出现。

如果您的 Docker 守护程序在公司网络内运行，您必须配置 HTTP 代理。详细说明可以在[`docs.docker.com/engine/admin/systemd/`](https://docs.docker.com/engine/admin/systemd/)找到。

提示和技巧会显示在这样。

所有支持的操作系统和云平台的安装指南都可以在官方 Docker 页面[`docs.docker.com/engine/installation/`](https://docs.docker.com/engine/installation/)上找到。


# 第一章：介绍持续交付

大多数开发人员面临的常见问题是如何快速而安全地发布已实施的代码。然而，传统上使用的交付流程是一个陷阱的来源，通常会导致开发人员和客户的失望。本章介绍了持续交付方法的概念，并为本书的其余部分提供了背景。

本章涵盖以下要点：

+   介绍传统的交付流程及其缺点

+   描述持续交付的概念及其带来的好处

+   比较不同公司如何交付其软件

+   解释自动化部署流水线及其阶段

+   对不同类型的测试及其在流程中的位置进行分类

+   指出成功的持续交付流程的先决条件

+   介绍本书中将使用的工具

+   展示本书中将构建的完整系统

# 什么是持续交付？

持续交付的最准确定义由 Jez Humble 提出，如下所述：“持续交付是能够以可持续的方式将各种类型的变更，包括新功能、配置变更、错误修复和实验，安全快速地投入生产或交付给用户的能力。”该定义涵盖了关键点。

为了更好地理解，让我们想象一个场景。你负责产品，比如说电子邮件客户端应用程序。用户向你提出一个新的需求——他们希望按大小对邮件进行排序。你决定开发需要大约一周的时间。用户可以在什么时候期待使用这个功能呢？通常，在开发完成后，你首先将已完成的功能交给质量保证团队，然后再交给运维团队，这需要额外的时间，从几天到几个月不等。因此，即使开发只花了一周的时间，用户也要在几个月后才能收到！持续交付方法通过自动化手动任务来解决这个问题，使用户能够在实施新功能后尽快收到。

为了更好地展示要自动化的内容和方式，让我们从描述目前大多数软件系统使用的交付流程开始。

# 传统的交付流程

传统的交付流程，顾名思义，已经存在多年，并在大多数 IT 公司中实施。让我们定义一下它的工作原理，并评论其缺点。

# 介绍传统交付过程

任何交付过程都始于客户定义的需求，并以在生产环境上发布结束。差异在于中间。传统上，它看起来如下发布周期图表所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/08f78945-6823-4b83-990b-109618b5dbbf.png)

发布周期始于**产品负责人**提供的需求，他代表**客户**（利益相关者）。然后有三个阶段，在这些阶段中，工作在不同的团队之间传递：

+   **开发**：在这里，开发人员（有时与业务分析师一起）致力于产品。他们经常使用敏捷技术（Scrum 或 Kanban）来提高开发速度并改善与客户的沟通。演示会议被组织起来以获得客户的快速反馈。所有良好的开发技术（如测试驱动开发或极限编程实践）都受到欢迎。实施完成后，代码传递给质量保证团队。

+   **质量保证**：这个阶段通常被称为**用户验收测试**（**UAT**），它需要对主干代码库进行代码冻结，以防止新的开发破坏测试。质量保证团队执行一系列**集成测试**，**验收测试**和**非功能测试**（性能，恢复，安全等）。检测到的任何错误都会返回给开发团队，因此开发人员通常也有很多工作要做。完成 UAT 阶段后，质量保证团队批准了下一个发布计划的功能。

+   **运营**：最后一个阶段，通常是最短的一个阶段，意味着将代码传递给**运营**团队，以便他们可以执行发布并监控生产。如果出现任何问题，他们会联系开发人员帮助处理生产系统。

发布周期的长度取决于系统和组织，但通常范围从一周到几个月不等。我听说过最长的是一年。我工作过的最长周期是季度为基础，每个部分的时间分配如下：开发-1.5 个月，UAT-1 个月和 3 周，发布（严格的生产监控）-1 周。

传统交付过程在 IT 行业广泛使用，这可能不是你第一次读到这样的方法。尽管如此，它有许多缺点。让我们明确地看一下它们，以了解为什么我们需要努力追求更好的东西。

# 传统交付过程的缺点

传统交付过程的最显著缺点包括以下内容：

+   **交付速度慢**：在这里，客户在需求规定之后很长时间才收到产品。这导致了不满意的上市时间和客户反馈的延迟。

+   **长反馈周期**：反馈周期不仅与客户有关，还与开发人员有关。想象一下，你意外地创建了一个错误，而你在 UAT 阶段才得知。修复你两个月前工作的东西需要多长时间？即使是小错误也可能需要几周的时间。

+   **缺乏自动化**：稀少的发布不鼓励自动化，这导致了不可预测的发布。

+   **风险的紧急修复**：紧急修复通常不能等待完整的 UAT 阶段，因此它们往往会以不同的方式进行测试（UAT 阶段缩短）或者根本不进行测试。

+   **压力**：不可预测的发布对运营团队来说是有压力的。而且，发布周期通常安排得很紧，这给开发人员和测试人员增加了额外的压力。

+   **沟通不畅**：工作从一个团队传递到另一个团队代表了瀑布式方法，人们开始只关心自己的部分，而不是整个产品。如果出了什么问题，通常会导致责备游戏，而不是合作。

+   **共同责任**：没有团队从头到尾对产品负责。对于开发人员来说，“完成”意味着需求已经实现。对于测试人员来说，“完成”意味着代码已经测试过。对于运营人员来说，“完成”意味着代码已经发布。

+   **工作满意度降低**：每个阶段对不同的团队来说都很有趣，但其他团队需要支持这个过程。例如，开发阶段对开发人员来说很有趣，但在另外两个阶段，他们仍然需要修复错误并支持发布，这通常对他们来说一点都不有趣。

这些缺点只是传统交付过程相关挑战的冰山一角。你可能已经感觉到一定有更好的方法来开发软件，而这种更好的方法显然就是持续交付的方法。

# 持续交付的好处

“你的组织需要多长时间来部署只涉及一行代码的更改？你是否能够重复、可靠地做到这一点？”这些是 Mary 和 Tom Poppendieck（《实施精益软件开发》的作者）的著名问题，被 Jez Humble 和其他作者多次引用。实际上，对这些问题的回答是衡量交付流程健康的唯一有效标准。

为了能够持续交付，而不需要花费大量资金雇佣 24/7 工作的运维团队，我们需要自动化。简而言之，持续交付就是将传统交付流程的每个阶段转变为一系列脚本，称为自动化部署管道或持续交付管道。然后，如果不需要手动步骤，我们可以在每次代码更改后运行流程，因此持续向用户交付产品。

持续交付让我们摆脱了繁琐的发布周期，因此带来了以下好处：

+   **快速交付**：市场推出时间大大缩短，因为客户可以在开发完成后立即使用产品。请记住，软件在用户手中之前不会产生收入。

+   **快速反馈循环**：想象一下，你在代码中创建了一个 bug，当天就进入了生产环境。修复当天工作的东西需要多长时间？可能不多。这与快速回滚策略一起，是保持生产稳定的最佳方式。

+   **低风险发布**：如果每天发布，那么流程变得可重复，因此更安全。俗话说，“如果疼，就多做几次。”

+   **灵活的发布选项**：如果需要立即发布，一切都已准备就绪，因此发布决策不会带来额外的时间/成本。

不用说，我们可以通过消除所有交付阶段并直接在生产环境上进行开发来实现所有好处。然而，这会导致质量下降。实际上，引入持续交付的整个困难在于担心质量会随着消除手动步骤而下降。在本书中，我们将展示如何以安全的方式处理这个问题，并解释为什么与常见观念相反，持续交付的产品 bug 更少，更适应客户的需求。

# 成功案例

我最喜欢的持续交付故事是 Rolf Russell 在其中一次演讲中讲述的。故事如下。2005 年，雅虎收购了 Flickr，这是开发者世界中两种文化的冲突。当时的 Flickr 是一家以初创公司方法为主的公司。相反，雅虎是一家拥有严格规定和安全至上态度的大型公司。他们的发布流程有很大不同。雅虎使用传统的交付流程，而 Flickr 每天发布多次。开发人员实施的每个更改都在当天上线。他们甚至在页面底部有一个页脚，显示最后一次发布的时间以及进行更改的开发人员的头像。

雅虎很少部署，每次发布都带来了很多经过充分测试和准备的更改。Flickr 以非常小的块工作，每个功能都被分成小的增量部分，并且每个部分都快速部署到生产环境。差异如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/10797d6c-4806-4dcf-b5f2-4f3cfdc41eae.png)

你可以想象当两家公司的开发人员相遇时会发生什么。雅虎显然把 Flickr 的同事当作不负责任的初级开发人员，“一群不知道自己在做什么的软件牛仔。”因此，他们想要改变的第一件事是将 QA 团队和 UAT 阶段加入 Flickr 的交付流程。然而，在应用更改之前，Flickr 的开发人员只有一个愿望。他们要求评估整个雅虎公司中最可靠的产品。当发生这种情况时，令人惊讶的是，雅虎所有软件中，Flickr 的停机时间最短。雅虎团队起初不理解，但还是让 Flickr 保持他们当前的流程。毕竟，他们是工程师，所以评估结果是确凿的。只是过了一段时间，他们意识到持续交付流程对雅虎的所有产品都有益处，他们开始逐渐在所有地方引入它。

故事中最重要的问题是-Flickr 如何成为最可靠的系统？实际上，这个事实的原因已经在前面的部分提到过。如果一个发布是少量风险的话：

+   代码更改的增量很小

+   这个过程是可重复的。

这就是为什么，即使发布本身是一项困难的活动，但频繁进行发布时要安全得多。

雅虎和 Flickr 的故事只是许多成功公司的一个例子，对于这些公司来说，持续交付流程被证明是正确的。其中一些甚至自豪地分享了他们系统的细节，如下：

+   **亚马逊**：2011 年，他们宣布在部署之间平均达到 11.6 秒

+   **Facebook**：2013 年，他们宣布每天部署代码更改两次

+   **HubSpot**：2013 年，他们宣布每天部署 300 次

+   **Atlassian**：2016 年，他们发布了一项调查，称他们 65%的客户实践持续交付

您可以在[`continuousdelivery.com/evidence-case-studies/`](https://continuousdelivery.com/evidence-case-studies/)阅读有关持续交付流程和个案研究的更多研究。

请记住，统计数据每天都在变得更好。然而，即使没有任何数字，想象一下每行代码您实现都安全地进入生产的世界。客户可以迅速做出反应并调整他们的需求，开发人员很高兴，因为他们不必解决那么多的错误，经理们很满意，因为他们总是知道当前的工作状态。毕竟，记住，唯一真正的进展度量是发布的软件。

# 自动化部署流水线

我们已经知道持续交付流程是什么，以及为什么我们使用它。在这一部分，我们将描述如何实施它。

让我们首先强调传统交付流程中的每个阶段都很重要。否则，它根本不会被创建。没有人想在没有测试的情况下交付软件！UAT 阶段的作用是检测错误，并确保开发人员创建的内容是客户想要的。运维团队也是如此——软件必须配置、部署到生产环境并进行监控。这是毋庸置疑的。那么，我们如何自动化这个过程，以便保留所有阶段？这就是自动化部署流水线的作用，它由以下图表中呈现的三个阶段组成：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/afeccaf6-be79-485d-bba8-beb5f782b675.png)

自动化部署流水线是一系列脚本，每次提交到存储库的代码更改后都会执行。如果流程成功，最终会部署到生产环境。

每个步骤对应传统交付流程中的一个阶段，如下所示：

+   持续集成：这个阶段检查不同开发人员编写的代码是否能够整合在一起

+   自动验收测试：这取代了手动的 QA 阶段，并检查开发人员实现的功能是否符合客户的要求

+   配置管理：这取代了手动操作阶段-配置环境并部署软件。

让我们深入了解每个阶段的责任和包括哪些步骤。

# 持续集成

持续集成阶段为开发人员提供了第一次反馈。它从代码库检出代码，编译代码，运行单元测试，并验证代码质量。如果任何步骤失败，管道执行将停止，开发人员应该做的第一件事是修复持续集成构建。这个阶段的关键是时间；它必须及时执行。例如，如果这个阶段需要一个小时才能完成，那么开发人员会更快地提交代码，这将导致持续失败的管道。

持续集成管道通常是起点。设置它很简单，因为一切都在开发团队内部完成，不需要与 QA 和运维团队达成协议。

# 自动验收测试

自动验收测试阶段是与客户（和 QA）一起编写的一套测试，旨在取代手动的 UAT 阶段。它作为一个质量门，决定产品是否准备发布。如果任何验收测试失败，那么管道执行将停止，不会运行进一步的步骤。它阻止了进入配置管理阶段，因此也阻止了发布。

自动化验收阶段的整个理念是将质量构建到产品中，而不是在后期进行验证。换句话说，当开发人员完成实现时，软件已经与验收测试一起交付，这些测试验证了软件是否符合客户的要求。这是对测试软件思维的一个重大转变。不再有一个人（或团队）批准发布，一切都取决于通过验收测试套件。这就是为什么创建这个阶段通常是持续交付过程中最困难的部分。它需要与客户的密切合作，并在过程的开始（而不是结束）创建测试。

在遗留系统的情况下，引入自动化验收测试尤其具有挑战性。我们在第九章 *高级持续交付*中对这个主题进行了更详细的描述。

关于测试类型及其在持续交付过程中的位置通常存在很多混淆。也经常不清楚如何自动化每种类型，应该有多少覆盖范围，以及 QA 团队在整个开发过程中应该扮演什么角色。让我们使用敏捷测试矩阵和测试金字塔来澄清这一点。

# 敏捷测试矩阵

Brian Marick 在他的一系列博客文章中，以所谓的敏捷测试矩阵的形式对软件测试进行了分类。它将测试放置在两个维度上：业务或技术面向和支持程序员或批评产品。让我们来看看这个分类：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/8f120904-9296-452a-a8dd-75dc8059ff6d.png)

让我们简要评论一下每种类型的测试：

+   **验收测试（自动化）**：这些测试代表了从业务角度看到的功能需求。它们以故事或示例的形式由客户和开发人员编写，以达成关于软件应该如何工作的一致意见。

+   **单元测试（自动化）**：这些测试帮助开发人员提供高质量的软件并最小化错误数量。

+   **探索性测试（手动）**：这是手动的黑盒测试，试图破坏或改进系统。

+   **非功能性测试（自动化）**：这些测试代表了与性能、可扩展性、安全性等相关的系统属性。

这个分类回答了持续交付过程中最重要的问题之一：QA 在过程中的角色是什么？

手动 QA 执行探索性测试，因此他们与系统一起玩耍，试图破坏它，提出问题，思考改进。自动化 QA 帮助进行非功能性和验收测试，例如，他们编写代码来支持负载测试。总的来说，QA 在交付过程中并没有他们特别的位置，而是在开发团队中扮演着一个角色。

在自动化的持续交付过程中，不再有执行重复任务的手动 QA 的位置。

你可能会看到分类，想知道为什么你在那里看不到集成测试。Brian Marick 在哪里，以及将它们放在持续交付管道的哪里？

为了解释清楚，我们首先需要提到，集成测试的含义取决于上下文。对于（微）服务架构，它们通常意味着与验收测试完全相同，因为服务很小，不需要除单元测试和验收测试之外的其他测试。如果构建了模块化应用程序，那么通过集成测试，我们通常指的是绑定多个模块（但不是整个应用程序）并一起测试它们的组件测试。在这种情况下，集成测试位于验收测试和单元测试之间。它们的编写方式与验收测试类似，但通常更加技术化，并且需要模拟不仅是外部服务，还有内部模块。集成测试与单元测试类似，代表了“代码”视角，而验收测试代表了“用户”视角。关于持续交付流水线，集成测试只是作为流程中的一个单独阶段实施。

# 测试金字塔

前一节解释了过程中每种测试类型代表的含义，但没有提到我们应该开发多少测试。那么，在单元测试的情况下，代码覆盖率应该是多少呢？验收测试呢？

为了回答这些问题，迈克·科恩在他的书《敏捷成功：使用 Scrum 进行软件开发》中创建了所谓的测试金字塔。让我们看一下图表，以便更好地理解它。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/f7a6cd1f-e677-49d1-8646-bca9f764282f.png)

当我们向金字塔顶部移动时，测试变得更慢，创建起来更昂贵。它们通常需要触及用户界面，并雇佣一个单独的测试自动化团队。这就是为什么验收测试不应该以 100%的覆盖率为目标。相反，它们应该以特性为导向，仅验证选定的测试场景。否则，我们将在测试开发和维护上花费巨资，我们的持续交付流水线构建将需要很长时间来执行。

在金字塔底部情况就不同了。单元测试便宜且快速，因此我们应该努力实现 100%的代码覆盖率。它们由开发人员编写，并且为他们提供应该是任何成熟团队的标准程序。

我希望敏捷测试矩阵和测试金字塔澄清了验收测试的角色和重要性。

让我们转向持续交付流程的最后阶段，配置管理。

# 配置管理

配置管理阶段负责跟踪和控制软件及其环境中的变化。它涉及准备和安装必要的工具，扩展服务实例的数量和分布，基础设施清单，以及与应用部署相关的所有任务。

配置管理是解决手动在生产环境部署和配置应用程序带来的问题的解决方案。这种常见做法导致一个问题，即我们不再知道每个服务在哪里运行以及具有什么属性。配置管理工具（如 Ansible、Chef 或 Puppet）能够在版本控制系统中存储配置文件，并跟踪在生产服务器上所做的每一次更改。

3. 取代运维团队手动任务的额外努力是负责应用程序监控。通常通过将运行系统的日志和指标流式传输到一个共同的仪表板来完成，该仪表板由开发人员（或者在下一节中解释的 DevOps 团队）监控。

# 7. 持续交付的先决条件

本书的其余部分致力于如何实施成功的持续交付流水线的技术细节。然而，该过程的成功不仅取决于本书中介绍的工具。在本节中，我们全面审视整个过程，并定义了三个领域的持续交付要求：

+   1. 组织结构及其对开发过程的影响

+   4. 产品及其技术细节

+   6. 开发团队及其使用的实践

# 2. 组织先决条件

组织的工作方式对引入持续交付流程的成功有很大影响。这有点类似于引入 Scrum。许多组织希望使用敏捷流程，但他们不改变他们的文化。除非组织结构进行了调整，否则你无法在开发团队中使用 Scrum。例如，你需要一个产品负责人、利益相关者和理解在冲刺期间不可能进行任何需求更改的管理层。否则，即使有良好的意愿，你也无法成功。持续交付流程也是如此；它需要调整组织结构。让我们来看看三个方面：DevOps 文化、流程中的客户和业务决策。

# 5. DevOps 文化

很久以前，当软件是由个人或微型团队编写时，开发、质量保证和运营之间没有明确的分离。一个人开发代码，测试它，然后将其投入生产。如果出了问题，同一个人调查问题，修复它，然后重新部署到生产环境。现在组织开发的方式逐渐改变，当系统变得更大，开发团队增长时。然后，工程师开始专门从事某个领域。这是完全有道理的，因为专业化会导致生产力的提升。然而，副作用是沟通开销。特别是如果开发人员、质量保证和运营在组织中处于不同的部门，坐在不同的建筑物中，或者外包到不同的国家。这种组织结构对持续交付流程不利。我们需要更好的东西，我们需要适应所谓的 DevOps 文化。

在某种意义上，DevOps 文化意味着回归到根本。一个人或一个团队负责所有三个领域，如下图所示：

！[](assets/2121ef45-ffa9-46d9-adb9-94c98b8b4d1b.png)

能够转向 DevOps 模式而不损失生产力的原因是自动化。与质量保证和运营相关的大部分任务都被移至自动化交付流程，因此可以由开发团队管理。

DevOps 团队不一定只需要由开发人员组成。在许多正在转型的组织中，一个常见的情景是创建由四名开发人员、一个质量保证人员和一个运营人员组成的团队。然而，他们需要密切合作（坐在一起，一起开会，共同开发同一个产品）。

小型 DevOps 团队的文化影响软件架构。功能需求必须被很好地分离成（微）服务或模块，以便每个团队可以独立处理一个部分。

组织结构对软件架构的影响已经在 1967 年观察到，并被规定为康威定律：“任何设计系统（广义定义）的组织都将产生一个结构与组织沟通结构相同的设计。”

# 客户端在流程中

在持续交付采用过程中，客户（或产品负责人）的角色略有变化。传统上，客户参与定义需求，回答开发人员的问题，参加演示，并参与用户验收测试阶段，以确定构建的是否符合他们的意图。

在持续交付中，没有用户验收测试，客户在编写验收测试的过程中至关重要。对于一些已经以可测试的方式编写需求的客户来说，这并不是一个很大的转变。对于其他人来说，这意味着改变思维方式，使需求更加技术导向。

在敏捷环境中，一些团队甚至不接受没有验收测试的用户故事（需求）。即使这些技术可能听起来太严格，但通常会导致更好的开发生产力。

# 业务决策

在大多数公司中，业务对发布计划有影响。毕竟，决定交付哪些功能以及何时交付与公司的不同部门（例如营销）相关，并且对企业具有战略意义。这就是为什么发布计划必须在业务和开发团队之间重新审视和讨论。

显然，有一些技术，如功能切换或手动流水线步骤，有助于在指定时间发布功能。我们将在书中稍后描述它们。准确地说，持续交付这个术语并不等同于持续部署。前者意味着每次提交到存储库都会自动发布到生产环境。持续交付要求较少严格，意味着每次提交都会产生一个发布候选版本，因此允许最后一步（发布到生产环境）是手动的。

在本书的其余部分，我们将互换使用持续交付和持续部署这两个术语。

# 技术和开发先决条件

从技术方面来看，有一些要求需要牢记。我们将在整本书中讨论它们，所以在这里只是简单提一下而不详细讨论：

+   **自动构建、测试、打包和部署操作**：所有操作都需要能够自动化。如果我们处理的系统无法自动化，例如由于安全原因或其复杂性，那么就不可能创建完全自动化的交付流程。

+   **快速流水线执行**：流水线必须及时执行，最好在 5-15 分钟内。如果我们的流水线执行需要几个小时或几天，那么就不可能在每次提交到仓库后运行它。

+   **快速故障恢复**：快速回滚或系统恢复的可能性是必须的。否则，由于频繁发布，我们会冒着生产健康的风险。

+   **零停机部署**：部署不能有任何停机时间，因为我们每天发布多次。

+   **基于主干的开发**：开发人员必须定期签入主分支。否则，如果每个人都在自己的分支上开发，集成很少，因此发布也很少，这恰恰与我们想要实现的相反。

我们将在整本书中更多地讨论这些先决条件以及如何解决它们。记住这一点，让我们转到本章的最后一节，介绍我们计划在本书中构建的系统以及我们将用于此目的的工具。

# 构建持续交付过程

我们介绍了持续交付过程的理念、好处和先决条件。在本节中，我们描述了将在整本书中使用的工具及其在完整系统中的位置。

如果你对持续交付过程的想法更感兴趣，那么可以看看杰兹·汉布尔和大卫·法利的一本优秀书籍，《持续交付：通过构建、测试和部署自动化实现可靠的软件发布》。

# 介绍工具

首先，具体的工具总是比理解其在流程中的作用更不重要。换句话说，任何工具都可以用另一个扮演相同角色的工具替换。例如，Jenkins 可以用 Atlassian Bamboo 替换，Chief 可以用 Ansible 替换。这就是为什么每一章都以为什么需要这样的工具以及它在整个流程中的作用的一般描述开始。然后，具体的工具会与其替代品进行比较描述。这种形式给了你选择适合你环境的正确工具的灵活性。

另一种方法可能是在思想层面上描述持续交付过程；然而，我坚信用代码提取的确切示例，读者可以自行运行，会更好地理解这个概念。

有两种阅读本书的方式。第一种是阅读和理解持续交付流程的概念。第二种是创建自己的环境，并在阅读时执行所有脚本，以理解细节。

让我们快速看一下本书中将使用的工具。然而，在本节中，这只是对每种技术的简要介绍，随着本书的进行，会呈现更多细节。

# Docker 生态系统

Docker 作为容器化运动的明确领导者，在近年来主导了软件行业。它允许将应用程序打包成与环境无关的镜像，因此将服务器视为资源的集群，而不是必须为每个应用程序配置的机器。Docker 是本书的明确选择，因为它完全适合（微）服务世界和持续交付流程。

随着 Docker 一起出现的还有其他技术，如下所示：

+   **Docker Hub**：这是 Docker 镜像的注册表

+   **Docker Compose**：这是一个定义多容器 Docker 应用程序的工具

+   **Docker Swarm**：这是一个集群和调度工具

# Jenkins

Jenkins 绝对是市场上最受欢迎的自动化服务器。它有助于创建持续集成和持续交付流水线，以及一般的任何其他自动化脚本序列。高度插件化，它有一个伟大的社区，不断通过新功能扩展它。更重要的是，它允许将流水线编写为代码，并支持分布式构建环境。

# Ansible

Ansible 是一个自动化工具，可帮助进行软件供应、配置管理和应用部署。它的趋势比任何其他配置管理引擎都要快，很快就可以超过它的两个主要竞争对手：Chef 和 Puppet。它使用无代理架构，并与 Docker 无缝集成。

# GitHub

GitHub 绝对是所有托管版本控制系统中的第一名。它提供了一个非常稳定的系统，一个出色的基于 Web 的用户界面，以及免费的公共存储库服务。话虽如此，任何源代码控制管理服务或工具都可以与持续交付一起使用，无论是在云端还是自托管，无论是基于 Git、SVN、Mercurial 还是其他任何工具。

# Java/Spring Boot/Gradle

多年来，Java 一直是最受欢迎的编程语言。这就是为什么在本书中大多数代码示例都使用 Java。与 Java 一起，大多数公司使用 Spring 框架进行开发，因此我们使用它来创建一个简单的 Web 服务，以解释一些概念。Gradle 用作构建工具。它仍然比 Maven 不那么受欢迎，但发展速度更快。与往常一样，任何编程语言、框架或构建工具都可以替换，持续交付流程将保持不变，所以如果您的技术栈不同，也不用担心。

# 其他工具

我们随意选择了 Cucumber 作为验收测试框架。其他类似的解决方案有 Fitnesse 和 JBehave。对于数据库迁移，我们使用 Flyway，但任何其他工具也可以，例如 Liquibase。

# 创建完整的持续交付系统

您可以从两个角度看待本书的组织方式。

第一个角度是基于自动部署流水线的步骤。每一章都让您更接近完整的持续交付流程。如果您看一下章节的名称，其中一些甚至命名为流水线阶段的名称：

+   持续集成流水线

+   自动验收测试

+   使用 Ansible 进行配置管理

其余章节提供了介绍、总结或与流程相关的附加信息。

本书的内容还有第二个视角。每一章描述了环境的一个部分，这个环境又为持续交付流程做好了充分的准备。换句话说，本书逐步展示了如何逐步构建一个完整系统的技术。为了帮助您了解我们计划在整本书中构建的系统，现在让我们来看看每一章中系统将如何发展。

如果您目前不理解概念和术语，不用担心。我们将在相应的章节中从零开始解释一切。

# 介绍 Docker

在第二章中，*介绍 Docker*，我们从系统的中心开始构建一个打包为 Docker 镜像的工作应用程序。本章的输出如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/360f4181-be46-4ca6-b481-53ba5e352a1a.png)

一个 docker 化的应用程序（Web 服务）作为一个容器在**Docker 主机**上运行，并且可以像直接在主机上运行一样访问。这得益于端口转发（在 Docker 术语中称为端口发布）。

# 配置 Jenkins

在第三章中，*配置 Jenkins*，我们准备了 Jenkins 环境。多个代理（从）节点的支持使其能够处理大量并发负载。结果如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/1098463d-b149-49b8-b80d-b08a6df6e053.png)

**Jenkins**主节点接受构建请求，但执行是在一个**Jenkins 从节点**（代理）机器上启动的。这种方法提供了 Jenkins 环境的水平扩展。

# 持续集成流水线

在第四章中，*持续集成流水线*，我们展示了如何创建持续交付流水线的第一阶段，即提交阶段。本章的输出是下图所示的系统：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/47bc7bc5-8cf0-4d4e-bdc9-f3b7e6b48221.png)

该应用程序是使用 Spring Boot 框架编写的简单的 Java Web 服务。Gradle 用作构建工具，GitHub 用作源代码仓库。对 GitHub 的每次提交都会自动触发 Jenkins 构建，该构建使用 Gradle 编译 Java 代码，运行单元测试，并执行其他检查（代码覆盖率，静态代码分析等）。Jenkins 构建完成后，会向开发人员发送通知。

在这一章之后，您将能够创建一个完整的持续集成流水线。

# 自动验收测试

在第五章中，*自动验收测试*，我们最终合并了书名中的两种技术：*Docker*和*Jenkins*。结果如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/2ca2ff1f-0162-4b35-9b90-06f686b53022.png)

图中的附加元素与自动验收测试阶段有关：

+   **Docker Registry**：在持续集成阶段之后，应用程序首先被打包成一个 JAR 文件，然后作为一个 Docker 镜像。然后将该镜像推送到**Docker Registry**，它充当了 docker 化应用程序的存储库。

+   **Docker 主机**：在执行验收测试套件之前，应用程序必须启动。Jenkins 触发一个**Docker 主机**机器从**Docker Registry**拉取 docker 化的应用程序并启动它。

+   **Docker Compose**：如果完整的应用程序由多个 Docker 容器组成（例如，两个 Web 服务：使用应用程序 2 的应用程序 1），那么**Docker Compose**有助于将它们一起运行。

+   **Cucumber**：应用程序在**Docker 主机**上启动后，Jenkins 运行了一套用**Cucumber**框架编写的验收测试。

# Ansible/持续交付流水线的配置管理

在接下来的两章中，即第六章，*使用 Ansible 进行配置管理*和第七章，*持续交付流水线*，我们完成了持续交付流水线。输出是下图所示的环境：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/6b7eeee2-d286-4b43-a91c-d2066e375a83.png)

Ansible 负责环境，并使得同一应用程序可以部署到多台机器上。因此，我们将应用程序部署到暂存环境，运行验收测试套件，最后将应用程序发布到生产环境，通常是在多个实例上（在多个 Docker 主机上）。

# 使用 Docker Swarm 进行集群/高级持续交付

在第八章中，*使用 Docker Swarm 进行集群*，我们用机器集群替换了每个环境中的单个主机。第九章，*高级持续交付*，此外还将数据库添加到了持续交付流程中。本书中创建的最终环境如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/4e76ac56-d89b-4e6f-8ea0-47a7bc1083ef.png)

暂存和生产环境配备有 Docker Swarm 集群，因此应用程序的多个实例在集群上运行。我们不再需要考虑我们的应用程序部署在哪台精确的机器上。我们只关心它们的实例数量。Jenkins 从属也是在集群上运行。最后的改进是使用 Flyway 迁移自动管理数据库模式，这已经整合到交付流程中。

我希望你已经对我们在本书中计划构建的内容感到兴奋。我们将逐步进行，解释每一个细节和所有可能的选项，以帮助你理解程序和工具。阅读本书后，你将能够在你的项目中引入或改进持续交付流程。

# 摘要

在本章中，我们介绍了从想法开始的持续交付过程，讨论了先决条件，并介绍了本书其余部分使用的工具。本章的关键要点如下：

+   目前大多数公司使用的交付流程存在重大缺陷，可以通过现代自动化工具进行改进

+   持续交付方法提供了许多好处，其中最重要的是：快速交付、快速反馈周期和低风险发布

+   持续交付流水线包括三个阶段：持续集成、自动验收测试和配置管理

+   引入持续交付通常需要组织文化和结构的变革。

+   在持续交付的背景下，最重要的工具是 Docker、Jenkins 和 Ansible

在下一章中，我们将介绍 Docker，并介绍如何构建一个 Docker 化的应用程序。


# 第二章：介绍 Docker

我们将讨论现代持续交付过程应该如何看待，引入 Docker，这种改变了 IT 行业和服务器使用方式的技术。

本章涵盖以下内容：

+   介绍虚拟化和容器化的概念

+   在不同的本地和服务器环境中安装 Docker

+   解释 Docker 工具包的架构

+   使用 Dockerfile 构建 Docker 镜像并提交更改

+   将应用程序作为 Docker 容器运行

+   配置 Docker 网络和端口转发

+   介绍 Docker 卷作为共享存储

# 什么是 Docker？

Docker 是一个旨在通过软件容器帮助应用程序部署的开源项目。这句话来自官方 Docker 页面：

“Docker 容器将软件包装在一个完整的文件系统中，其中包含运行所需的一切：代码、运行时、系统工具、系统库 - 任何可以安装在服务器上的东西。这保证软件无论在什么环境下都能始终运行相同。”

因此，Docker 与虚拟化类似，允许将应用程序打包成可以在任何地方运行的镜像。

# 容器化与虚拟化

没有 Docker，可以使用硬件虚拟化来实现隔离和其他好处，通常称为虚拟机。最流行的解决方案是 VirtualBox、VMware 和 Parallels。虚拟机模拟计算机架构，并提供物理计算机的功能。如果每个应用程序都作为单独的虚拟机镜像交付和运行，我们可以实现应用程序的完全隔离。以下图展示了虚拟化的概念：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/020d670e-74d0-41e8-af9d-8598b12046c2.png)

每个应用程序都作为一个单独的镜像启动，具有所有依赖项和一个客户操作系统。镜像由模拟物理计算机架构的 hypervisor 运行。这种部署方法得到许多工具（如 Vagrant）的广泛支持，并专门用于开发和测试环境。然而，虚拟化有三个重大缺点：

+   **性能低下**：虚拟机模拟整个计算机架构来运行客户操作系统，因此每个操作都会带来显着的开销。

+   **高资源消耗**：模拟需要大量资源，并且必须针对每个应用程序单独进行。这就是为什么在标准桌面机器上只能同时运行几个应用程序。

+   **大的镜像大小**：每个应用程序都随着完整的操作系统交付，因此在服务器上部署意味着发送和存储大量数据。

容器化的概念提出了一个不同的解决方案：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/41c0db73-c10e-42f2-8fec-f45e28ef52f4.png)

每个应用程序都与其依赖项一起交付，但没有操作系统。应用程序直接与主机操作系统接口，因此没有额外的客户操作系统层。这导致更好的性能和没有资源浪费。此外，交付的 Docker 镜像大小明显更小。

请注意，在容器化的情况下，隔离发生在主机操作系统进程的级别。然而，这并不意味着容器共享它们的依赖关系。它们每个都有自己的正确版本的库，如果其中任何一个被更新，它对其他容器没有影响。为了实现这一点，Docker 引擎为容器创建了一组 Linux 命名空间和控制组。这就是为什么 Docker 安全性基于 Linux 内核进程隔离。尽管这个解决方案已经足够成熟，但与虚拟机提供的完整操作系统级隔离相比，它可能被认为略微不够安全。

# Docker 的需求

Docker 容器化解决了传统软件交付中出现的许多问题。让我们仔细看看。

# 环境

安装和运行软件是复杂的。您需要决定操作系统、资源、库、服务、权限、其他软件以及您的应用程序所依赖的一切。然后，您需要知道如何安装它。而且，可能会有一些冲突的依赖关系。那么你该怎么办？如果您的软件需要升级一个库，但其他软件不需要呢？在一些公司中，这些问题是通过拥有**应用程序类别**来解决的，每个类别由专用服务器提供服务，例如，一个用于具有 Java 7 的 Web 服务的服务器，另一个用于具有 Java 8 的批处理作业，依此类推。然而，这种解决方案在资源方面不够平衡，并且需要一支 IT 运维团队来照顾所有的生产和测试服务器。

环境复杂性的另一个问题是，通常需要专家来运行应用程序。一个不太懂技术的人可能会很难设置 MySQL、ODBC 或任何其他稍微复杂的工具。对于不作为特定操作系统二进制文件交付但需要源代码编译或任何其他特定环境配置的应用程序来说，这一点尤为真实。

# 隔离

保持工作区整洁。一个应用程序可能会改变另一个应用程序的行为。想象一下会发生什么。应用程序共享一个文件系统，因此如果应用程序 A 将某些内容写入错误的目录，应用程序 B 将读取不正确的数据。它们共享资源，因此如果应用程序 A 存在内存泄漏，它不仅会冻结自身，还会冻结应用程序 B。它们共享网络接口，因此如果应用程序 A 和 B 都使用端口`8080`，其中一个将崩溃。隔离也涉及安全方面。运行有错误的应用程序或恶意软件可能会对其他应用程序造成损害。这就是为什么将每个应用程序保持在单独的沙盒中是一种更安全的方法，它限制了损害范围仅限于应用程序本身。

# 组织应用程序

服务器通常会因为有大量运行的应用程序而变得混乱，而没有人知道这些应用程序是什么。你将如何检查服务器上运行的应用程序以及它们各自使用的依赖关系？它们可能依赖于库、其他应用程序或工具。如果没有详尽的文档，我们所能做的就是查看运行的进程并开始猜测。Docker 通过将每个应用程序作为一个单独的容器来保持组织，这些容器可以列出、搜索和监视。

# 可移植性

“一次编写，到处运行”，这是 Java 最早版本的广告口号。的确，Java 解决了可移植性问题；然而，我仍然可以想到一些它失败的情况，例如不兼容的本地依赖项或较旧版本的 Java 运行时。此外，并非所有软件都是用 Java 编写的。

Docker 将可移植性的概念提升了一个层次；如果 Docker 版本兼容，那么所提供的软件将在编程语言、操作系统或环境配置方面都能正确运行。因此，Docker 可以用“不仅仅是代码，而是整个环境”来表达。

# 小猫和牛

传统软件部署和基于 Docker 的部署之间的区别通常用小猫和牛的类比来表达。每个人都喜欢小猫。小猫是独一无二的。每只小猫都有自己的名字，需要特殊对待。小猫是用情感对待的。它们死了我们会哭。相反，牛只存在来满足我们的需求。即使牛的形式是单数，因为它只是一群一起对待的动物。没有命名，没有独特性。当然，它们是独一无二的（就像每个服务器都是独一无二的），但这是无关紧要的。

这就是为什么对 Docker 背后的理念最直接的解释是<q>把你的服务器当作牛，而不是宠物。</q>

# 替代的容器化技术

Docker 并不是市场上唯一的容器化系统。实际上，Docker 的最初版本是基于开源的**LXC**（**Linux Containers**）系统的，这是一个容器的替代平台。其他已知的解决方案包括 FreeBSD Jails、OpenVZ 和 Solaris Containers。然而，Docker 因其简单性、良好的营销和创业方法而超越了所有其他系统。它适用于大多数操作系统，允许您在不到 15 分钟内做一些有用的事情，具有许多易于使用的功能，良好的教程，一个伟大的社区，可能是 IT 行业中最好的标志。

# Docker 安装

Docker 的安装过程快速简单。目前，它在大多数 Linux 操作系统上得到支持，并提供了专门的二进制文件。Mac 和 Windows 也有很好的本地应用支持。然而，重要的是要理解，Docker 在内部基于 Linux 内核及其特定性，这就是为什么在 Mac 和 Windows 的情况下，它使用虚拟机（Mac 的 xhyve 和 Windows 的 Hyper-V）来运行 Docker 引擎环境。

# Docker 的先决条件

Docker 的要求针对每个操作系统都是特定的。

**Mac**：

+   2010 年或更新型号，具有英特尔对**内存管理单元**（**MMU**）虚拟化的硬件支持

+   macOS 10.10.3 Yosemite 或更新版本

+   至少 4GB 的 RAM

+   未安装早于 4.3.30 版本的 VirtualBox

**Windows**：

+   64 位 Windows 10 专业版

+   启用了 Hyper-V 包

**Linux**：

+   64 位架构

+   Linux 内核 3.10 或更高版本

如果您的机器不符合要求，那么解决方案是使用安装了 Ubuntu 操作系统的 VirtualBox。尽管这种解决方法听起来有些复杂，但并不一定是最糟糕的方法，特别是考虑到在 Mac 和 Windows 的情况下 Docker 引擎环境本身就是虚拟化的。此外，Ubuntu 是使用 Docker 的最受支持的系统之一。

本书中的所有示例都在 Ubuntu 16.04 操作系统上进行了测试。

# 在本地机器上安装

Dockers 的安装过程非常简单，并且在其官方页面上有很好的描述。

# Ubuntu 的 Docker

[`docs.docker.com/engine/installation/linux/ubuntulinux/`](https://docs.docker.com/engine/installation/linux/ubuntulinux/) 包含了在 Ubuntu 机器上安装 Docker 的指南。

在 Ubuntu 16.04 的情况下，我执行了以下命令：

```
$ sudo apt-get update
$ sudo apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 9DC858229FC7DD38854AE2D88D81803C0EBFCD88
$ sudo apt-add-repository 'deb [arch=amd64] https://download.docker.com/linux/ubuntu xenial main stable'
$ sudo apt-get update
$ sudo apt-get install -y docker-ce
```

所有操作完成后，Docker 应该已安装。然而，目前唯一被允许使用 Docker 命令的用户是`root`。这意味着每个 Docker 命令前都必须加上`sudo`关键字。

我们可以通过将他们添加到`docker`组来使其他用户使用 Docker：

```
$ sudo usermod -aG docker <username>
```

成功注销后，一切都设置好了。然而，通过最新的命令，我们需要采取一些预防措施，以免将 Docker 权限赋予不需要的用户，从而在 Docker 引擎中创建漏洞。这在服务器机器上安装时尤为重要。

# Linux 的 Docker

[`docs.docker.com/engine/installation/linux/`](https://docs.docker.com/engine/installation/linux/) 包含了大多数 Linux 发行版的安装指南。

# Mac 的 Docker

[`docs.docker.com/docker-for-mac/`](https://docs.docker.com/docker-for-mac/) 包含了在 Mac 机器上安装 Docker 的逐步指南。它与一系列 Docker 组件一起提供：

+   带有 Docker 引擎的虚拟机

+   Docker Machine（用于在虚拟机上创建 Docker 主机的工具）

+   Docker Compose

+   Docker 客户端和服务器

+   Kitematic：一个 GUI 应用程序

Docker Machine 工具有助于在 Mac、Windows、公司网络、数据中心以及 AWS 或 Digital Ocean 等云提供商上安装和管理 Docker 引擎。

# Windows 的 Docker

[`docs.docker.com/docker-for-windows/`](https://docs.docker.com/docker-for-windows/) 包含了如何在 Windows 机器上安装 Docker 的逐步指南。它与一组类似于 Mac 的 Docker 组件一起提供。

所有支持的操作系统和云平台的安装指南都可以在官方 Docker 页面上找到，[`docs.docker.com/engine/installation/`](https://docs.docker.com/engine/installation/)。

# 测试 Docker 安装

无论您选择了哪种安装方式（Mac、Windows、Ubuntu、Linux 或其他），Docker 都应该已经设置好并准备就绪。测试的最佳方法是运行`docker info`命令。输出消息应该类似于以下内容：

```
$ docker info
Containers: 0
 Running: 0
 Paused: 0
 Stopped: 0
 Images: 0
...
```

# 在服务器上安装

为了在网络上使用 Docker，可以利用云平台提供商或在专用服务器上手动安装 Docker。

在第一种情况下，Docker 配置因平台而异，但在专门的教程中都有很好的描述。大多数云平台都可以通过用户友好的网络界面创建 Docker 主机，或者描述在其服务器上执行的确切命令。

然而，第二种情况（手动安装 Docker）需要一些评论。

# 专用服务器

在服务器上手动安装 Docker 与本地安装并没有太大区别。

还需要两个额外的步骤，包括设置 Docker 守护程序以侦听网络套接字和设置安全证书。

让我们从第一步开始。出于安全原因，默认情况下，Docker 通过非网络化的 Unix 套接字运行，只允许本地通信。必须添加监听所选网络接口套接字，以便外部客户端可以连接。[`docs.docker.com/engine/admin/`](https://docs.docker.com/engine/admin/)详细描述了每个 Linux 发行版所需的所有配置步骤。

在 Ubuntu 的情况下，Docker 守护程序由 systemd 配置，因此为了更改它的启动配置，我们需要修改`/lib/systemd/system/docker.service`文件中的一行：

```
ExecStart=/usr/bin/dockerd -H <server_ip>:2375
```

通过更改这一行，我们启用了通过指定的 IP 地址访问 Docker 守护程序。有关 systemd 配置的所有细节可以在[`docs.docker.com/engine/admin/systemd/`](https://docs.docker.com/engine/admin/systemd/)找到。

服务器配置的第二步涉及 Docker 安全证书。这使得只有通过证书认证的客户端才能访问服务器。Docker 证书配置的详细描述可以在[`docs.docker.com/engine/security/https/`](https://docs.docker.com/engine/security/https/)找到。这一步并不是严格要求的；然而，除非您的 Docker 守护程序服务器位于防火墙网络内，否则是必不可少的。

如果您的 Docker 守护程序在公司网络内运行，您必须配置 HTTP 代理。详细描述可以在[`docs.docker.com/engine/admin/systemd/`](https://docs.docker.com/engine/admin/systemd/)找到。

# 运行 Docker hello world>

Docker 环境已经设置好，所以我们可以开始第一个示例。

在控制台中输入以下命令：

```
$ docker run hello-world
Unable to find image 'hello-world:latest' locally
latest: Pulling from library/hello-world
78445dd45222: Pull complete
Digest: sha256:c5515758d4c5e1e838e9cd307f6c6a0d620b5e07e6f927b07d05f6d12a1ac8d7
Status: Downloaded newer image for hello-world:latest

Hello from Docker!
This message shows that your installation appears to be working correctly.
...
```

恭喜，您刚刚运行了您的第一个 Docker 容器。我希望您已经感受到 Docker 是多么简单。让我们逐步检查发生了什么：

1.  您使用`run`命令运行了 Docker 客户端。

1.  Docker 客户端联系 Docker 守护程序，要求从名为`hello-world`的镜像创建一个容器。

1.  Docker 守护程序检查是否在本地包含`hello-world`镜像，由于没有，它从远程 Docker Hub 注册表请求了`hello-world`镜像。

1.  Docker Hub 注册表包含了`hello-world`镜像，因此它被拉入了 Docker 守护程序。

1.  Docker 守护程序从`hello-world`镜像创建了一个新的容器，启动了产生输出的可执行文件。

1.  Docker 守护程序将此输出流式传输到 Docker 客户端。

1.  Docker 客户端将其发送到您的终端。

预期的流程可以用以下图表表示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/991a6408-e39f-4455-80eb-b42d883c3a49.png)

让我们看一下在本节中所示的每个 Docker 组件。

# Docker 组件

官方 Docker 页面上说：

“Docker Engine 是一个创建和管理 Docker 对象（如镜像和容器）的客户端-服务器应用程序。”

让我们搞清楚这意味着什么。

# Docker 客户端和服务器

让我们看一下展示 Docker Engine 架构的图表：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/22168b81-9283-421d-8295-d0af9d675db3.png)

Docker Engine 由三个组件组成：

+   **Docker 守护程序**（服务器）在后台运行

+   **Docker 客户端**作为命令工具运行

+   **REST API**

安装 Docker Engine 意味着安装所有组件，以便 Docker 守护程序作为服务在我们的计算机上运行。在`hello-world`示例中，我们使用 Docker 客户端与 Docker 守护程序交互；但是，我们也可以使用 REST API 来做完全相同的事情。同样，在 hello-world 示例中，我们连接到本地 Docker 守护程序；但是，我们也可以使用相同的客户端与远程机器上运行的 Docker 守护程序交互。

要在远程机器上运行 Docker 容器，可以使用`-H`选项：`docker -H <server_ip>:2375 run hello-world`

# Docker 镜像和容器

在 Docker 世界中，镜像是一个无状态的构建块。您可以将镜像想象为运行应用程序所需的所有文件的集合，以及运行它的方法。镜像是无状态的，因此可以通过网络发送它，将其存储在注册表中，命名它，对其进行版本控制，并将其保存为文件。镜像是分层的，这意味着可以在另一个镜像的基础上构建镜像。

容器是镜像的运行实例。如果我们想要多个相同应用的实例，我们可以从同一个镜像创建多个容器。由于容器是有状态的，我们可以与它们交互并更改它们的状态。

让我们来看一个容器和镜像层结构的例子：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/0099e866-f813-47d3-a4b7-b34fb88f722b.png)

底部始终是基础镜像。在大多数情况下，它代表一个操作系统，我们在现有的基础镜像上构建我们的镜像。从技术上讲，可以创建自己的基础镜像，但这很少需要。

在我们的例子中，`ubuntu`基础镜像提供了 Ubuntu 操作系统的所有功能。`add git`镜像添加了 Git 工具包。然后，有一个添加了 JDK 环境的镜像。最后，在顶部，有一个从`add JDK`镜像创建的容器。这样的容器能够从 GitHub 仓库下载 Java 项目并将其编译为 JAR 文件。因此，我们可以使用这个容器来编译和运行 Java 项目，而无需在我们的操作系统上安装任何工具。

重要的是要注意，分层是一种非常聪明的机制，可以节省带宽和存储空间。想象一下，我们的应用程序也是基于`ubuntu`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/26c3a1aa-7f15-49e9-9c27-e5a2ed80fbdb.png)

这次我们将使用 Python 解释器。在安装`add python`镜像时，Docker 守护程序将注意到`ubuntu`镜像已经安装，并且它需要做的只是添加一个非常小的`python`层。因此，`ubuntu`镜像是一个被重复使用的依赖项。如果我们想要在网络中部署我们的镜像，情况也是一样的。当我们部署 Git 和 JDK 应用程序时，我们需要发送整个`ubuntu`镜像。然而，随后部署`python`应用程序时，我们只需要发送一个小的`add python`层。

# Docker 应用程序

许多应用程序以 Docker 镜像的形式提供，可以从互联网上下载。如果我们知道镜像名称，那么只需以与 hello world 示例相同的方式运行它就足够了。我们如何在 Docker Hub 上找到所需的应用程序镜像呢？

让我们以 MongoDB 为例。如果我们想在 Docker Hub 上找到它，我们有两个选项：

+   在 Docker Hub 探索页面上搜索（[`hub.docker.com/explore/`](https://hub.docker.com/explore/)）

+   使用`docker search`命令

在第二种情况下，我们可以执行以下操作：

```
$ docker search mongo
NAME DESCRIPTION STARS OFFICIAL AUTOMATED
mongo MongoDB document databases provide high av... 2821 [OK] 
mongo-express Web-based MongoDB admin interface, written... 106 [OK] 
mvertes/alpine-mongo light MongoDB container 39 [OK]
mongoclient/mongoclient Official docker image for Mongoclient, fea... 19 [OK]
...
```

有很多有趣的选项。我们如何选择最佳镜像？通常，最吸引人的是没有任何前缀的镜像，因为这意味着它是一个官方的 Docker Hub 镜像，因此应该是稳定和维护的。带有前缀的镜像是非官方的，通常作为开源项目进行维护。在我们的情况下，最好的选择似乎是`mongo`，因此为了运行 MongoDB 服务器，我们可以运行以下命令：

```
$ docker run mongo
Unable to find image 'mongo:latest' locally
latest: Pulling from library/mongo
5040bd298390: Pull complete
ef697e8d464e: Pull complete
67d7bf010c40: Pull complete
bb0b4f23ca2d: Pull complete
8efff42d23e5: Pull complete
11dec5aa0089: Pull complete
e76feb0ad656: Pull complete
5e1dcc6263a9: Pull complete
2855a823db09: Pull complete
Digest: sha256:aff0c497cff4f116583b99b21775a8844a17bcf5c69f7f3f6028013bf0d6c00c
Status: Downloaded newer image for mongo:latest
2017-01-28T14:33:59.383+0000 I CONTROL [initandlisten] MongoDB starting : pid=1 port=27017 dbpath=/data/db 64-bit host=0f05d9df0dc2
...
```

就这样，MongoDB 已经启动了。作为 Docker 容器运行应用程序是如此简单，因为我们不需要考虑任何依赖项；它们都与镜像一起提供。

在 Docker Hub 服务上，你可以找到很多应用程序；它们存储了超过 100,000 个不同的镜像。

# 构建镜像

Docker 可以被视为一个有用的工具来运行应用程序；然而，真正的力量在于构建自己的 Docker 镜像，将程序与环境一起打包。在本节中，我们将看到如何使用两种不同的方法来做到这一点，即 Docker `commit`命令和 Dockerfile 自动构建。

# Docker commit

让我们从一个例子开始，使用 Git 和 JDK 工具包准备一个镜像。我们将使用 Ubuntu 16.04 作为基础镜像。无需创建它；大多数基础镜像都可以在 Docker Hub 注册表中找到：

1.  从`ubuntu:16.04`运行一个容器，并连接到其命令行：

```
 $ docker run -i -t ubuntu:16.04 /bin/bash
```

我们拉取了`ubuntu:16.04`镜像，并将其作为容器运行，然后以交互方式（-i 标志）调用了`/bin/bash`命令。您应该看到容器的终端。由于容器是有状态的和可写的，我们可以在其终端中做任何我们想做的事情。

1.  安装 Git 工具包：

```
 root@dee2cb192c6c:/# apt-get update
 root@dee2cb192c6c:/# apt-get install -y git
```

1.  检查 Git 工具包是否已安装：

```
 root@dee2cb192c6c:/# which git
 /usr/bin/git
```

1.  退出容器：

```
 root@dee2cb192c6c:/# exit
```

1.  检查容器中的更改，将其与`ubuntu`镜像进行比较：

```
 $ docker diff dee2cb192c6c
```

该命令应打印出容器中所有更改的文件列表。

1.  将容器提交到镜像：

```
 $ docker commit dee2cb192c6c ubuntu_with_git
```

我们刚刚创建了我们的第一个 Docker 镜像。让我们列出 Docker 主机上的所有镜像，看看镜像是否存在：

```
$ docker images
REPOSITORY       TAG      IMAGE ID      CREATED            SIZE
ubuntu_with_git  latest   f3d674114fe2  About a minute ago 259.7 MB
ubuntu           16.04    f49eec89601e  7 days ago         129.5 MB
mongo            latest   0dffc7177b06  10 days ago        402 MB
hello-world      latest   48b5124b2768  2 weeks ago        1.84 kB
```

如预期的那样，我们看到了`hello-world`，`mongo`（之前安装的），`ubuntu`（从 Docker Hub 拉取的基础镜像）和新构建的`ubuntu_with_git`。顺便说一句，我们可以观察到每个镜像的大小，它对应于我们在镜像上安装的内容。

现在，如果我们从镜像创建一个容器，它将安装 Git 工具：

```
$ docker run -i -t ubuntu_with_git /bin/bash
root@3b0d1ff457d4:/# which git
/usr/bin/git
root@3b0d1ff457d4:/# exit
```

使用完全相同的方法，我们可以在`ubuntu_with_git`镜像的基础上构建`ubuntu_with_git_and_jdk`：

```
$ docker run -i -t ubuntu_with_git /bin/bash
root@6ee6401ed8b8:/# apt-get install -y openjdk-8-jdk
root@6ee6401ed8b8:/# exit
$ docker commit 6ee6401ed8b8 ubuntu_with_git_and_jdk
```

# Dockerfile

手动创建每个 Docker 镜像并使用 commit 命令可能会很费力，特别是在构建自动化和持续交付过程中。幸运的是，有一种内置语言可以指定构建 Docker 镜像时应执行的所有指令。

让我们从一个类似于 Git 和 JDK 的例子开始。这次，我们将准备`ubuntu_with_python`镜像。

1.  创建一个新目录和一个名为`Dockerfile`的文件，内容如下：

```
 FROM ubuntu:16.04
 RUN apt-get update && \
 apt-get install -y python
```

1.  运行命令以创建`ubuntu_with_python`镜像：

```
 $ docker build -t ubuntu_with_python .
```

1.  检查镜像是否已创建：

```
$ docker images
REPOSITORY              TAG     IMAGE ID       CREATED            SIZE
ubuntu_with_python      latest  d6e85f39f5b7  About a minute ago 202.6 MB
ubuntu_with_git_and_jdk latest  8464dc10abbb  3 minutes ago      610.9 MB
ubuntu_with_git         latest  f3d674114fe2  9 minutes ago      259.7 MB
ubuntu                  16.04   f49eec89601e  7 days ago         129.5 MB
mongo                   latest  0dffc7177b06   10 days ago        402 MB
hello-world             latest  48b5124b2768   2 weeks ago        1.84 kB
```

现在我们可以从镜像创建一个容器，并检查 Python 解释器是否存在，方式与执行`docker commit`命令后的方式完全相同。请注意，即使`ubuntu`镜像是`ubuntu_with_git`和`ubuntu_with_python`的基础镜像，它也只列出一次。

在这个例子中，我们使用了前两个 Dockerfile 指令：

+   `FROM`定义了新镜像将基于的镜像

+   `RUN`指定在容器内部运行的命令

所有 Dockerfile 指令都可以在官方 Docker 页面[`docs.docker.com/engine/reference/builder/`](https://docs.docker.com/engine/reference/builder/)上找到。最常用的指令如下：

+   `MAINTAINER`定义了关于作者的元信息

+   `COPY`将文件或目录复制到镜像的文件系统中

+   `ENTRYPOINT`定义了可执行容器中应该运行哪个应用程序

您可以在官方 Docker 页面[https://docs.docker.com/engine/reference/builder/]上找到所有 Dockerfile 指令的完整指南。

# 完整的 Docker 应用程序

我们已经拥有构建完全可工作的应用程序作为 Docker 镜像所需的所有信息。例如，我们将逐步准备一个简单的 Python hello world 程序。无论我们使用什么环境或编程语言，这些步骤都是相同的。

# 编写应用程序

创建一个新目录，在这个目录中，创建一个名为`hello.py`的文件，内容如下：

```
print "Hello World from Python!"
```

关闭文件。这是我们应用程序的源代码。

# 准备环境

我们的环境将在 Dockerfile 中表示。我们需要定义以下指令：

+   应该使用哪个基础镜像

+   （可选）维护者是谁

+   如何安装 Python 解释器

+   如何将`hello.py`包含在镜像中

+   如何启动应用程序

在同一目录中，创建 Dockerfile：

```
FROM ubuntu:16.04
MAINTAINER Rafal Leszko
RUN apt-get update && \
    apt-get install -y python
COPY hello.py .
ENTRYPOINT ["python", "hello.py"]
```

# 构建镜像

现在，我们可以以与之前完全相同的方式构建镜像：

```
$ docker build -t hello_world_python .
```

# 运行应用程序

我们通过运行容器来运行应用程序：

```
$ docker run hello_world_python
```

您应该看到友好的 Hello World from Python!消息。这个例子中最有趣的是，我们能够在没有在主机系统中安装 Python 解释器的情况下运行 Python 编写的应用程序。这是因为作为镜像打包的应用程序在内部具有所需的所有环境。

Python 解释器的镜像已经存在于 Docker Hub 服务中，因此在实际情况下，使用它就足够了。

# 环境变量

我们已经运行了我们的第一个自制 Docker 应用程序。但是，如果应用程序的执行应该取决于一些条件呢？

例如，在生产服务器的情况下，我们希望将`Hello`打印到日志中，而不是控制台，或者我们可能希望在测试阶段和生产阶段有不同的依赖服务。一个解决方案是为每种情况准备一个单独的 Dockerfile；然而，还有一个更好的方法，即环境变量。

让我们将我们的 hello world 应用程序更改为打印`Hello World from` `<name_passed_as_environment_variable> !`。为了做到这一点，我们需要按照以下步骤进行：

1.  更改 Python 脚本以使用环境变量：

```
        import os
        print "Hello World from %s !" % os.environ['NAME']
```

1.  构建镜像：

```
 $ docker build -t hello_world_python_name .
```

1.  运行传递环境变量的容器：

```
 $ docker run -e NAME=Rafal hello_world_python_name
 Hello World from Rafal !
```

1.  或者，我们可以在 Dockerfile 中定义环境变量的值，例如：

```
        ENV NAME Rafal
```

1.  然后，我们可以运行容器而不指定`-e`选项。

```
 $ docker build -t hello_world_python_name_default .
 $ docker run hello_world_python_name_default
 Hello World from Rafal !
```

当我们需要根据其用途拥有 Docker 容器的不同版本时，例如，为生产和测试服务器拥有单独的配置文件时，环境变量尤其有用。

如果环境变量在 Dockerfile 和标志中都有定义，那么命令标志优先。

# Docker 容器状态

到目前为止，我们运行的每个应用程序都应该做一些工作然后停止。例如，我们打印了`Hello from Docker!`然后退出。但是，有些应用程序应该持续运行，比如服务。要在后台运行容器，我们可以使用`-d`（`--detach`）选项。让我们尝试一下`ubuntu`镜像：

```
$ docker run -d -t ubuntu:16.04
```

这个命令启动了 Ubuntu 容器，但没有将控制台附加到它上面。我们可以使用以下命令看到它正在运行：

```
$ docker ps
CONTAINER ID IMAGE        COMMAND     STATUS PORTS NAMES
95f29bfbaadc ubuntu:16.04 "/bin/bash" Up 5 seconds kickass_stonebraker
```

这个命令打印出所有处于运行状态的容器。那么我们的旧容器呢，已经退出了？我们可以通过打印所有容器来找到它们：

```
$ docker ps -a
CONTAINER ID IMAGE        COMMAND        STATUS PORTS  NAMES
95f29bfbaadc ubuntu:16.04 "/bin/bash"    Up 33 seconds kickass_stonebraker
34080d914613 hello_world_python_name_default "python hello.py" Exited lonely_newton
7ba49e8ee677 hello_world_python_name "python hello.py" Exited mad_turing
dd5eb1ed81c3 hello_world_python "python hello.py" Exited thirsty_bardeen
6ee6401ed8b8 ubuntu_with_git "/bin/bash" Exited        grave_nobel
3b0d1ff457d4 ubuntu_with_git "/bin/bash" Exited        desperate_williams
dee2cb192c6c ubuntu:16.04 "/bin/bash"    Exited        small_dubinsky
0f05d9df0dc2 mongo        "/entrypoint.sh mongo" Exited trusting_easley
47ba1c0ba90e hello-world  "/hello"       Exited        tender_bell
```

请注意，所有旧容器都处于退出状态。我们还没有观察到的状态有两种：暂停和重新启动。

所有状态及其之间的转换都在以下图表中显示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/9b56cc40-6571-4e7b-98f0-7617455661b3.png)

暂停 Docker 容器非常罕见，从技术上讲，它是通过使用 SIGSTOP 信号冻结进程来实现的。重新启动是一个临时状态，当容器使用`--restart`选项运行以定义重新启动策略时（Docker 守护程序能够在发生故障时自动重新启动容器）。

该图表还显示了用于将 Docker 容器状态从一个状态更改为另一个状态的 Docker 命令。

例如，我们可以停止正在运行的 Ubuntu 容器：

```
$ docker stop 95f29bfbaadc

$ docker ps
CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES
```

我们一直使用`docker run`命令来创建和启动容器；但是，也可以只创建容器而不启动它。

# Docker 网络

如今，大多数应用程序不是独立运行的，而是需要通过网络与其他系统进行通信。如果我们想在 Docker 容器内运行网站、网络服务、数据库或缓存服务器，那么我们需要至少了解 Docker 网络的基础知识。

# 运行服务

让我们从一个简单的例子开始，直接从 Docker Hub 运行 Tomcat 服务器：

```
$ docker run -d tomcat
```

Tomcat 是一个 Web 应用程序服务器，其用户界面可以通过端口`8080`访问。因此，如果我们在本机安装了 Tomcat，我们可以在`http://localhost:8080`上浏览它。

然而，在我们的情况下，Tomcat 是在 Docker 容器内运行的。我们以与第一个`Hello World`示例相同的方式启动了它。我们可以看到它正在运行：

```
$ docker ps
CONTAINER ID IMAGE  COMMAND           STATUS            PORTS    NAMES
d51ad8634fac tomcat "catalina.sh run" Up About a minute 8080/tcp jovial_kare
```

由于它是作为守护进程运行的（使用`-d`选项），我们无法立即在控制台中看到日志。然而，我们可以通过执行以下代码来访问它：

```
$ docker logs d51ad8634fac
```

如果没有错误，我们应该会看到很多日志，说明 Tomcat 已经启动，并且可以通过端口`8080`访问。我们可以尝试访问`http://localhost:8080`，但是我们无法连接。原因是 Tomcat 已经在容器内启动，我们试图从外部访问它。换句话说，我们只能在连接到容器中的控制台并在那里检查时才能访问它。如何使正在运行的 Tomcat 可以从外部访问呢？

我们需要启动容器并指定端口映射，使用`-p`（`--publish`）标志：

```
-p, --publish <host_port>:<container_port>
```

因此，让我们首先停止正在运行的容器并启动一个新的容器：

```
$ docker stop d51ad8634fac
$ docker run -d -p 8080:8080 tomcat
```

等待几秒钟后，Tomcat 必须已经启动，我们应该能够打开它的页面，`http://localhost:8080`。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/5a754575-bd73-41d5-9f7c-01590ca4ecb7.png)

在大多数常见的 Docker 使用情况下，这样简单的端口映射命令就足够了。我们能够将（微）服务部署为 Docker 容器，并公开它们的端口以启用通信。然而，让我们深入了解一下发生在幕后的情况。

Docker 允许使用`-p <ip>:<host_port>:<container_port>`将指定的主机网络接口发布出去。

# 容器网络

我们已经连接到容器内运行的应用程序。事实上，这种连接是双向的，因为如果你还记得我们之前的例子，我们是从内部执行`apt-get install`命令，并且包是从互联网下载的。这是如何可能的呢？

如果您检查您的机器上的网络接口，您会看到其中一个接口被称为`docker0`：

```
$ ifconfig docker0
docker0 Link encap:Ethernet HWaddr 02:42:db:d0:47:db 
 inet addr:172.17.0.1 Bcast:0.0.0.0 Mask:255.255.0.0
...
```

`docker0`接口是由 Docker 守护程序创建的，以便与 Docker 容器连接。现在，我们可以使用`docker inspect`命令查看 Docker 容器内创建的接口：

```
$ docker inspect 03d1e6dc4d9e
```

它以 JSON 格式打印有关容器配置的所有信息。其中，我们可以找到与网络设置相关的部分。

```
"NetworkSettings": {
     "Bridge": "",
     "Ports": {
          "8080/tcp": [
               {
                    "HostIp": "0.0.0.0",
                    "HostPort": "8080"
               }
          ]
          },
     "Gateway": "172.17.0.1",
     "IPAddress": "172.17.0.2",
     "IPPrefixLen": 16,
}
```

为了过滤`docker inspect`的响应，我们可以使用`--format`选项，例如，`docker inspect --format '{{ .NetworkSettings.IPAddress }}' <container_id>`。

我们可以观察到 Docker 容器的 IP 地址为`172.17.0.2`，并且它与具有 IP 地址`172.17.0.1`的 Docker 主机进行通信。这意味着在我们之前的示例中，即使没有端口转发，我们也可以访问 Tomcat 服务器，使用地址`http://172.17.0.2:8080`。然而，在大多数情况下，我们在服务器机器上运行 Docker 容器并希望将其暴露到外部，因此我们需要使用`-p`选项。

请注意，默认情况下，容器受主机防火墙系统保护，并且不会从外部系统打开任何路由。我们可以通过使用`--network`标志并将其设置为以下内容来更改此默认行为：

+   `bridge`（默认）：通过默认 Docker 桥接网络

+   `none`：无网络

+   `container`：与其他（指定的）容器连接的网络

+   `host`：主机网络（无防火墙）

不同的网络可以通过`docker network`命令列出和管理：

```
$ docker network ls
NETWORK ID   NAME   DRIVER SCOPE
b3326cb44121 bridge bridge local 
84136027df04 host   host   local 
80c26af0351c none   null   local
```

如果我们将`none`指定为网络，则将无法连接到容器，反之亦然；容器无法访问外部世界。`host`选项使容器网络接口与主机相同。它们共享相同的 IP 地址，因此容器上启动的所有内容在外部可见。最常用的选项是默认选项（`bridge`），因为它允许我们明确定义应发布哪些端口。它既安全又可访问。

# 暴露容器端口

我们多次提到容器暴露端口。实际上，如果我们深入研究 GitHub 上的 Tomcat 镜像（[`github.com/docker-library/tomcat`](https://github.com/docker-library/tomcat)），我们可以注意到 Dockerfile 中的以下行：

```
EXPOSE 8080
```

这个 Dockerfile 指令表示应该从容器中公开端口 8080。然而，正如我们已经看到的，这并不意味着端口会自动发布。EXPOSE 指令只是通知用户应该发布哪些端口。

# 自动端口分配

让我们尝试在不停止第一个 Tomcat 容器的情况下运行第二个 Tomcat 容器：

```
$ docker run -d -p 8080:8080 tomcat
0835c95538aeca79e0305b5f19a5f96cb00c5d1c50bed87584cfca8ec790f241
docker: Error response from daemon: driver failed programming external connectivity on endpoint distracted_heyrovsky (1b1cee9896ed99b9b804e4c944a3d9544adf72f1ef3f9c9f37bc985e9c30f452): Bind for 0.0.0.0:8080 failed: port is already allocated.
```

这种错误可能很常见。在这种情况下，我们要么自己负责端口的唯一性，要么让 Docker 使用`publish`命令的以下版本自动分配端口：

+   -p <container_port>：将容器端口发布到未使用的主机端口

+   `-P`（`--publish-all`）：将容器公开的所有端口发布到未使用的主机端口：

```
$ docker run -d -P tomcat
 078e9d12a1c8724f8aa27510a6390473c1789aa49e7f8b14ddfaaa328c8f737b

$ docker port 078e9d12a1c8
8080/tcp -> 0.0.0.0:32772
```

我们可以看到第二个 Tomcat 已发布到端口`32772`，因此可以在`http://localhost:32772`上浏览。

# 使用 Docker 卷

假设您想将数据库作为容器运行。您可以启动这样一个容器并输入数据。它存储在哪里？当您停止容器或删除它时会发生什么？您可以启动新的容器，但数据库将再次为空。除非这是您的测试环境，您不会期望这样的情况发生。

Docker 卷是 Docker 主机的目录，挂载在容器内部。它允许容器像写入自己的文件系统一样写入主机的文件系统。该机制如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/b175c0eb-1e9a-4d07-8f40-8ec867942345.png)

Docker 卷使容器的数据持久化和共享。卷还清楚地将处理与数据分开。

让我们从一个示例开始，并使用`-v <host_path>:<container_path>`选项指定卷并连接到容器：

```
$ docker run -i -t -v ~/docker_ubuntu:/host_directory ubuntu:16.04 /bin/bash
```

现在，我们可以在容器中的`host_directory`中创建一个空文件：

```
root@01bf73826624:/# touch host_directory/file.txt
```

让我们检查一下文件是否在 Docker 主机的文件系统中创建：

```
root@01bf73826624:/# exit
exit

$ ls ~/docker_ubuntu/
file.txt
```

我们可以看到文件系统被共享，数据因此得以永久保存。现在我们可以停止容器并运行一个新的容器，看到我们的文件仍然在那里：

```
$ docker stop 01bf73826624

$ docker run -i -t -v ~/docker_ubuntu:/host_directory ubuntu:16.04 /bin/bash
root@a9e0df194f1f:/# ls host_directory/
file.txt

root@a9e0df194f1f:/# exit
```

不需要使用`-v`标志来指定卷，可以在 Dockerfile 中将卷指定为指令，例如：

```
VOLUME /host_directory
```

在这种情况下，如果我们运行 docker 容器而没有`-v`标志，那么容器的`/host_directory`将被映射到主机的默认卷目录`/var/lib/docker/vfs/`。如果您将应用程序作为镜像交付，并且知道它因某种原因需要永久存储（例如存储应用程序日志），这是一个很好的解决方案。

如果卷在 Dockerfile 中和作为标志定义，那么命令标志优先。

Docker 卷可能会更加复杂，特别是在数据库的情况下。然而，Docker 卷的更复杂的用例超出了本书的范围。

使用 Docker 进行数据管理的一个非常常见的方法是引入一个额外的层，即数据卷容器。数据卷容器是一个唯一目的是声明卷的 Docker 容器。然后，其他容器可以使用它（使用`--volumes-from <container>`选项）而不是直接声明卷。在[`docs.docker.com/engine/tutorials/dockervolumes/#creating-and-mounting-a-data-volume-container`](https://docs.docker.com/engine/tutorials/dockervolumes/#creating-and-mounting-a-data-volume-container)中了解更多。

# 在 Docker 中使用名称

到目前为止，当我们操作容器时，我们总是使用自动生成的名称。这种方法有一些优势，比如名称是唯一的（没有命名冲突）和自动的（不需要做任何事情）。然而，在许多情况下，最好为容器或镜像提供一个真正用户友好的名称。

# 命名容器

命名容器有两个很好的理由：方便和自动化：

+   方便，因为通过名称对容器进行任何操作比检查哈希或自动生成的名称更简单

+   自动化，因为有时我们希望依赖于容器的特定命名

例如，我们希望有一些相互依赖的容器，并且有一个链接到另一个。因此，我们需要知道它们的名称。

要命名容器，我们使用`--name`参数：

```
$ docker run -d --name tomcat tomcat
```

我们可以通过`docker ps`检查容器是否有有意义的名称。此外，作为结果，任何操作都可以使用容器的名称执行，例如：

```
$ docker logs tomcat
```

请注意，当容器被命名时，它不会失去其身份。我们仍然可以像以前一样通过自动生成的哈希 ID 来寻址容器。

容器始终具有 ID 和名称。可以通过任何一个来寻址，它们两个都是唯一的。

# 给图像打标签

图像可以被标记。我们在创建自己的图像时已经做过这个，例如，在构建`hello-world_python`图像的情况下：

```
$ docker build -t hello-world_python .
```

`-t`标志描述了图像的标签。如果我们没有使用它，那么图像将被构建而没有任何标签，结果我们将不得不通过其 ID（哈希）来寻址它以运行容器。

图像可以有多个标签，并且它们应该遵循命名约定：

```
<registry_address>/<image_name>:<version>
```

标签由以下部分组成：

+   `registry_address`：注册表的 IP 和端口或别名

+   `image_name`：构建的图像的名称，例如，`ubuntu`

+   `version`：图像的版本，可以是任何形式，例如，16.04，20170310

我们将在第五章中介绍 Docker 注册表，*自动验收测试*。如果图像保存在官方 Docker Hub 注册表上，那么我们可以跳过注册表地址。这就是为什么我们在没有任何前缀的情况下运行了`tomcat`图像。最后一个版本总是被标记为最新的，也可以被跳过，所以我们在没有任何后缀的情况下运行了`tomcat`图像。

图像通常有多个标签，例如，所有四个标签都是相同的图像：`ubuntu:16.04`，`ubuntu:xenial-20170119`，`ubuntu:xenial`和`ubuntu:latest`。

# Docker 清理

在本章中，我们创建了许多容器和图像。然而，这只是现实场景中的一小部分。即使容器此刻没有运行，它们也需要存储在 Docker 主机上。这很快就会导致存储空间超出并停止机器。我们如何解决这个问题呢？

# 清理容器

首先，让我们看看存储在我们的机器上的容器。要打印所有容器（无论它们的状态如何），我们可以使用`docker ps -a`命令：

```
$ docker ps -a
CONTAINER ID IMAGE  COMMAND           STATUS  PORTS  NAMES
95c2d6c4424e tomcat "catalina.sh run" Up 5 minutes 8080/tcp tomcat
a9e0df194f1f ubuntu:16.04 "/bin/bash" Exited         jolly_archimedes
01bf73826624 ubuntu:16.04 "/bin/bash" Exited         suspicious_feynman
078e9d12a1c8 tomcat "catalina.sh run" Up 14 minutes 0.0.0.0:32772->8080/tcp nauseous_fermi
0835c95538ae tomcat "catalina.sh run" Created        distracted_heyrovsky
03d1e6dc4d9e tomcat "catalina.sh run" Up 50 minutes 0.0.0.0:8080->8080/tcp drunk_ritchie
d51ad8634fac tomcat "catalina.sh run" Exited         jovial_kare
95f29bfbaadc ubuntu:16.04 "/bin/bash" Exited         kickass_stonebraker
34080d914613 hello_world_python_name_default "python hello.py" Exited lonely_newton
7ba49e8ee677 hello_world_python_name "python hello.py" Exited mad_turing
dd5eb1ed81c3 hello_world_python "python hello.py" Exited thirsty_bardeen
6ee6401ed8b8 ubuntu_with_git "/bin/bash" Exited      grave_nobel
3b0d1ff457d4 ubuntu_with_git "/bin/bash" Exited      desperate_williams
dee2cb192c6c ubuntu:16.04 "/bin/bash" Exited         small_dubinsky
0f05d9df0dc2 mongo  "/entrypoint.sh mongo" Exited    trusting_easley
47ba1c0ba90e hello-world "/hello"     Exited         tender_bell
```

为了删除已停止的容器，我们可以使用`docker rm`命令（如果容器正在运行，我们需要先停止它）：

```
$ docker rm 47ba1c0ba90e
```

如果我们想要删除所有已停止的容器，我们可以使用以下命令：

```
$ docker rm $(docker ps --no-trunc -aq)
```

`-aq`选项指定仅传递所有容器的 ID（没有额外数据）。另外，`--no-trunc`要求 Docker 不要截断输出。

我们也可以采用不同的方法，并要求容器在停止时使用`--rm`标志自行删除，例如：

```
$ docker run --rm hello-world
```

在大多数实际场景中，我们不使用已停止的容器，它们只用于调试目的。

# 清理图像

图像和容器一样重要。它们可能占用大量空间，特别是在持续交付过程中，每次构建都会产生一个新的 Docker 图像。这很快就会导致设备上没有空间的错误。要检查 Docker 容器中的所有图像，我们可以使用`docker images`命令：

```
$ docker images
REPOSITORY TAG                         IMAGE ID     CREATED     SIZE
hello_world_python_name_default latest 9a056ca92841 2 hours ago 202.6 MB
hello_world_python_name latest         72c8c50ffa89 2 hours ago 202.6 MB
hello_world_python latest              3e1fa5c29b44 2 hours ago 202.6 MB
ubuntu_with_python latest              d6e85f39f5b7 2 hours ago 202.6 MB
ubuntu_with_git_and_jdk latest         8464dc10abbb 2 hours ago 610.9 MB
ubuntu_with_git latest                 f3d674114fe2 3 hours ago 259.7 MB
tomcat latest                          c822d296d232 2 days ago  355.3 MB
ubuntu 16.04                           f49eec89601e 7 days ago  129.5 MB
mongo latest                           0dffc7177b06 11 days ago 402 MB
hello-world latest                     48b5124b2768 2 weeks ago 1.84 kB
```

要删除图像，我们可以调用以下命令：

```
$ docker rmi 48b5124b2768
```

在图像的情况下，自动清理过程稍微复杂一些。图像没有状态，所以我们不能要求它们在不使用时自行删除。常见的策略是设置 Cron 清理作业，删除所有旧的和未使用的图像。我们可以使用以下命令来做到这一点：

```
$ docker rmi $(docker images -q)
```

为了防止删除带有标签的图像（例如，不删除所有最新的图像），非常常见的是使用`dangling`参数：

```
$ docker rmi $(docker images -f "dangling=true" -q)
```

如果我们有使用卷的容器，那么除了图像和容器之外，还值得考虑清理卷。最简单的方法是使用`docker volume ls -qf dangling=true | xargs -r docker volume rm`命令。

# Docker 命令概述

通过执行以下`help`命令可以找到所有 Docker 命令：

```
$ docker help
```

要查看任何特定 Docker 命令的所有选项，我们可以使用`docker help <command>`，例如：

```
$ docker help run
```

在官方 Docker 页面[`docs.docker.com/engine/reference/commandline/docker/`](https://docs.docker.com/engine/reference/commandline/docker/)上也有对所有 Docker 命令的很好的解释。真的值得阅读，或者至少浏览一下。

在本章中，我们已经介绍了最有用的命令及其选项。作为一个快速提醒，让我们回顾一下：

| **命令** | **解释** |
| --- | --- |
| `docker build` | 从 Dockerfile 构建图像 |
| `docker commit` | 从容器创建图像 |
| `docker diff` | 显示容器中的更改 |
| `docker images` | 列出图像 |
| `docker info` | 显示 Docker 信息 |
| `docker inspect` | 显示 Docker 镜像/容器的配置 |
| `docker logs` | 显示容器的日志 |
| `docker network` | 管理网络 |
| `docker port` | 显示容器暴露的所有端口 |
| `docker ps` | 列出容器 |
| `docker rm` | 删除容器 |
| `docker rmi` | 删除图像 |
| `docker run` | 从图像运行容器 |
| `docker search` | 在 Docker Hub 中搜索 Docker 镜像 |
| `docker start/stop/pause/unpause` | 管理容器的状态 |

# 练习

在本章中，我们涵盖了大量的材料。为了记忆深刻，我们建议进行两个练习。

1.  运行`CouchDB`作为一个 Docker 容器并发布它的端口：

您可以使用`docker search`命令来查找`CouchDB`镜像。

+   +   运行容器

+   发布`CouchDB`端口

+   打开浏览器并检查`CouchDB`是否可用

1.  创建一个 Docker 镜像，其中 REST 服务回复`Hello World!`到`localhost:8080/hello`。使用您喜欢的任何语言和框架：

创建 REST 服务的最简单方法是使用 Python 和 Flask 框架，[`flask.pocoo.org/`](http://flask.pocoo.org/)。请注意，许多 Web 框架默认只在 localhost 接口上启动应用程序。为了发布端口，有必要在所有接口上启动它（在 Flask 框架的情况下，使用`app.run(host='0.0.0.0')`）。

+   +   创建一个 Web 服务应用程序

+   创建一个 Dockerfile 来安装依赖和库

+   构建镜像

+   运行容器并发布端口

+   使用浏览器检查它是否正常运行

# 总结

在本章中，我们已经涵盖了足够构建镜像和运行应用程序作为容器的 Docker 基础知识。本章的关键要点如下：

+   容器化技术利用 Linux 内核特性解决了隔离和环境依赖的问题。这是基于进程分离机制的，因此没有观察到真正的性能下降。

+   Docker 可以安装在大多数系统上，但只有在 Linux 上才能得到原生支持。

+   Docker 允许从互联网上可用的镜像中运行应用程序，并构建自己的镜像。

+   镜像是一个打包了所有依赖关系的应用程序。

+   Docker 提供了两种构建镜像的方法：Dockerfile 或提交容器。在大多数情况下，第一种选项被使用。

+   Docker 容器可以通过发布它们暴露的端口进行网络通信。

+   Docker 容器可以使用卷共享持久存储。

+   为了方便起见，Docker 容器应该被命名，Docker 镜像应该被标记。在 Docker 世界中，有一个特定的约定来标记镜像。

+   Docker 镜像和容器应该定期清理，以节省服务器空间并避免*设备上没有空间*的错误。

在下一章中，我们将介绍 Jenkins 的配置以及 Jenkins 与 Docker 一起使用的方式。


# 第三章：配置 Jenkins

我们已经看到如何配置和使用 Docker。在本章中，我们将介绍 Jenkins，它可以单独使用，也可以与 Docker 一起使用。我们将展示这两个工具的结合产生了令人惊讶的好结果：自动配置和灵活的可扩展性。

本章涵盖以下主题：

+   介绍 Jenkins 及其优势

+   安装和启动 Jenkins

+   创建第一个流水线

+   使用代理扩展 Jenkins

+   配置基于 Docker 的代理

+   构建自定义主从 Docker 镜像

+   配置安全和备份策略

# Jenkins 是什么？

Jenkins 是用 Java 编写的开源自动化服务器。凭借非常活跃的基于社区的支持和大量的插件，它是实施持续集成和持续交付流程的最流行工具。以前被称为 Hudson，Oracle 收购 Hudson 并决定将其开发为专有软件后更名为 Jenkins。Jenkins 仍然在 MIT 许可下，并因其简单性、灵活性和多功能性而备受推崇。

Jenkins 优于其他持续集成工具，是最广泛使用的其类软件。这一切都是可能的，因为它的特性和能力。

让我们来看看 Jenkins 特性中最有趣的部分。

+   **语言无关**：Jenkins 有很多插件，支持大多数编程语言和框架。此外，由于它可以使用任何 shell 命令和任何安装的软件，因此适用于可以想象的每个自动化流程。

+   **可扩展的插件**：Jenkins 拥有一个庞大的社区和大量可用的插件（1000 多个）。它还允许您编写自己的插件，以定制 Jenkins 以满足您的需求。

+   **便携**：Jenkins 是用 Java 编写的，因此可以在任何操作系统上运行。为了方便，它还以许多版本提供：Web 应用程序存档（WAR）、Docker 镜像、Windows 二进制、Mac 二进制和 Linux 二进制。

+   **支持大多数 SCM**：Jenkins 与几乎所有现有的源代码管理或构建工具集成。再次，由于其广泛的社区和插件，没有其他持续集成工具支持如此多的外部系统。

+   **分布式**：Jenkins 具有内置的主/从模式机制，可以将其执行分布在位于多台机器上的多个节点上。它还可以使用异构环境，例如，不同的节点可以安装不同的操作系统。

+   **简单性**：安装和配置过程简单。无需配置任何额外的软件，也不需要数据库。可以完全通过 GUI、XML 或 Groovy 脚本进行配置。

+   **面向代码**：Jenkins 管道被定义为代码。此外，Jenkins 本身可以使用 XML 文件或 Groovy 脚本进行配置。这允许将配置保存在源代码存储库中，并有助于自动化 Jenkins 配置。

# Jenkins 安装

Jenkins 安装过程快速简单。有不同的方法可以做到这一点，但由于我们已经熟悉 Docker 工具及其带来的好处，我们将从基于 Docker 的解决方案开始。这也是最简单、最可预测和最明智的方法。然而，让我们先提到安装要求。

# 安装要求

最低系统要求相对较低：

+   Java 8

+   256MB 可用内存

+   1 GB 以上的可用磁盘空间

然而，需要明白的是，要求严格取决于您打算如何使用 Jenkins。如果 Jenkins 用于为整个团队提供持续集成服务器，即使是小团队，建议具有 1 GB 以上的可用内存和 50 GB 以上的可用磁盘空间。不用说，Jenkins 还执行一些计算并在网络上传输大量数据，因此 CPU 和带宽至关重要。

为了了解在大公司的情况下可能需要的要求，*Jenkins 架构*部分介绍了 Netflix 的例子。

# 在 Docker 上安装

让我们看看使用 Docker 安装 Jenkins 的逐步过程。

Jenkins 镜像可在官方 Docker Hub 注册表中找到，因此为了安装它，我们应该执行以下命令：

```
$ docker run -p <host_port>:8080 -v <host_volume>:/var/jenkins_home jenkins:2.60.1
```

我们需要指定第一个`host_port`参数——Jenkins 在容器外可见的端口。第二个参数`host_volume`指定了 Jenkins 主目录映射的目录。它需要被指定为卷，并因此永久持久化，因为它包含了配置、管道构建和日志。

例如，让我们看看在 Linux/Ubuntu 上 Docker 主机的安装步骤会是什么样子。

1.  **准备卷目录**：我们需要一个具有管理员所有权的单独目录来保存 Jenkins 主目录。让我们用以下命令准备一个：

```
 $ mkdir $HOME/jenkins_home
 $ chown 1000 $HOME/jenkins_home
```

1.  **运行 Jenkins 容器**：让我们将容器作为守护进程运行，并给它一个合适的名称：

```
 $ docker run -d -p 49001:8080 
        -v $HOME/jenkins_home:/var/jenkins_home --name 
        jenkins jenkins:2.60.1
```

1.  **检查 Jenkins 是否正在运行**：过一会儿，我们可以通过打印日志来检查 Jenkins 是否已经正确启动：

```
 $ docker logs jenkins
 Running from: /usr/share/jenkins/jenkins.war
 webroot: EnvVars.masterEnvVars.get("JENKINS_HOME")
 Feb 04, 2017 9:01:32 AM Main deleteWinstoneTempContents
 WARNING: Failed to delete the temporary Winstone file 
        /tmp/winstone/jenkins.war
 Feb 04, 2017 9:01:32 AM org.eclipse.jetty.util.log.JavaUtilLog info
 INFO: Logging initialized @888ms
 Feb 04, 2017 9:01:32 AM winstone.Logger logInternal
 ...
```

在生产环境中，您可能还希望设置反向代理，以隐藏 Jenkins 基础设施在代理服务器后面。如何使用 Nginx 服务器进行设置的简要说明可以在[`wiki.jenkins-ci.org/display/JENKINS/Installing+Jenkins+with+Docker`](https://wiki.jenkins-ci.org/display/JENKINS/Installing+Jenkins+with+Docker)找到。

完成这几个步骤后，Jenkins 就可以使用了。基于 Docker 的安装有两个主要优点：

+   **故障恢复**：如果 Jenkins 崩溃，只需运行一个指定了相同卷的新容器。

+   **自定义镜像**：您可以根据自己的需求配置 Jenkins 并将其存储为 Jenkins 镜像。然后可以在您的组织或团队内共享，而无需一遍又一遍地重复相同的配置步骤。

在本书的所有地方，我们使用的是版本 2.60.1 的 Jenkins。

# 在没有 Docker 的情况下安装

出于前面提到的原因，建议安装 Docker。但是，如果这不是一个选择，或者有其他原因需要采取其他方式进行安装，那么安装过程同样简单。例如，在 Ubuntu 的情况下，只需运行：

```
$ wget -q -O - https://pkg.jenkins.io/debian/jenkins.io.key | sudo apt-key add -
$ sudo sh -c 'echo deb http://pkg.jenkins.io/debian-stable binary/ > /etc/apt/sources.list.d/jenkins.list'
$ sudo apt-get update
$ sudo apt-get install jenkins
```

所有安装指南（Ubuntu、Mac、Windows 等）都可以在官方 Jenkins 页面[`jenkins.io/doc/book/getting-started/installing/`](https://jenkins.io/doc/book/getting-started/installing/)上找到。

# 初始配置

无论您选择哪种安装方式，Jenkins 的第一次启动都需要进行一些配置步骤。让我们一步一步地走过它们：

1.  在浏览器中打开 Jenkins：`http://localhost:49001`（对于二进制安装，默认端口为`8080`）。

1.  Jenkins 应该要求输入管理员密码。它可以在 Jenkins 日志中找到：

```
 $ docker logs jenkins
 ...
 Jenkins initial setup is required. An admin user has been created 
        and a password generated.
 Please use the following password to proceed to installation:

 c50508effc6843a1a7b06f6491ed0ca6

 ...
```

1.  接受初始密码后，Jenkins 会询问是否安装建议的插件，这些插件适用于最常见的用例。您的答案当然取决于您的需求。然而，作为第一个 Jenkins 安装，让 Jenkins 安装所有推荐的插件是合理的。

1.  安装插件后，Jenkins 要求设置用户名、密码和其他基本信息。如果你跳过它，步骤 2 中的令牌将被用作管理员密码。

安装完成后，您应该看到 Jenkins 仪表板：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/5823b433-89cb-43d1-a878-8f7995171901.png)

我们已经准备好使用 Jenkins 并创建第一个管道。

# Jenkins 你好世界

整个 IT 世界的一切都始于 Hello World 的例子。

让我们遵循这个规则，看看创建第一个 Jenkins 管道的步骤：

1.  点击*新建项目*。

1.  将`hello world`输入为项目名称，选择管道，然后点击确定。

1.  有很多选项。我们现在会跳过它们，直接进入管道部分。

1.  在脚本文本框中，我们可以输入管道脚本：

```
      pipeline {
           agent any
           stages {
                stage("Hello") {
                     steps {
                          echo 'Hello World'
                     }
                }
           }
      }
```

1.  点击*保存*。

1.  点击*立即构建*。

我们应该在构建历史下看到#1。如果我们点击它，然后点击*控制台输出*，我们将看到管道构建的日志。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/28b3c9dd-cd74-4912-a9af-b7b3a7724347.png)

我们刚刚看到了第一个例子，成功的输出意味着 Jenkins 已经正确安装。现在，让我们转移到稍微更高级的 Jenkins 配置。

我们将在第四章中更详细地描述管道语法，*持续集成管道*。

# Jenkins 架构

hello world 作业几乎没有时间执行。然而，管道通常更复杂，需要时间来执行诸如从互联网下载文件、编译源代码或运行测试等任务。一个构建可能需要几分钟到几小时。

在常见情况下，也会有许多并发的管道。通常，整个团队，甚至整个组织，都使用同一个 Jenkins 实例。如何确保构建能够快速顺利地运行？

# 主节点和从节点

Jenkins 很快就会变得过载。即使是一个小的（微）服务，构建也可能需要几分钟。这意味着一个频繁提交的团队很容易就能够使 Jenkins 实例崩溃。

因此，除非项目非常小，Jenkins 不应该执行构建，而是将它们委托给从节点（代理）实例。准确地说，我们当前运行的 Jenkins 称为 Jenkins 主节点，它可以委托给 Jenkins 代理。

让我们看一下呈现主从交互的图表：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/1d28685d-ac8c-474b-9052-ed0f1e340e33.png)

在分布式构建环境中，Jenkins 主节点负责：

+   接收构建触发器（例如，提交到 GitHub 后）

+   发送通知（例如，在构建失败后发送电子邮件或 HipChat 消息）

+   处理 HTTP 请求（与客户端的交互）

+   管理构建环境（在从节点上编排作业执行）

构建代理是一个负责构建开始后发生的一切的机器。

由于主节点和从节点的责任不同，它们有不同的环境要求：

+   **主节点**：这通常是一个专用的机器，内存从小型项目的 200 MB 到大型单主项目的 70GB 以上不等。

+   **从节点**：没有一般性要求（除了它应该能够执行单个构建之外，例如，如果项目是一个需要 100GB RAM 的巨型单体，那么从节点机器需要满足这些需求）。

代理也应尽可能通用。例如，如果我们有不同的项目：一个是 Java，一个是 Python，一个是 Ruby，那么每个代理都可以构建任何这些项目将是完美的。在这种情况下，代理可以互换，有助于优化资源的使用。

如果代理不能足够通用以匹配所有项目，那么可以对代理和项目进行标记，以便给定的构建将在给定类型的代理上执行。

# 可扩展性

我们可以使用 Jenkins 从节点来平衡负载和扩展 Jenkins 基础架构。这个过程称为水平扩展。另一种可能性是只使用一个主节点并增加其机器的资源。这个过程称为垂直扩展。让我们更仔细地看看这两个概念。

# 垂直扩展

垂直扩展意味着当主机负载增加时，会向主机的机器应用更多资源。因此，当我们的组织中出现新项目时，我们会购买更多的 RAM，增加 CPU 核心，并扩展 HDD 驱动器。这可能听起来像是一个不可行的解决方案；然而，它经常被使用，甚至被知名组织使用。将单个 Jenkins 主设置在超高效的硬件上有一个非常强大的优势：维护。任何升级、脚本、安全设置、角色分配或插件安装都只需在一个地方完成。

# 水平扩展

水平扩展意味着当组织增长时，会启动更多的主实例。这需要将实例智能分配给团队，并且在极端情况下，每个团队都可以拥有自己的 Jenkins 主实例。在这种情况下，甚至可能不需要从属实例。

缺点是可能难以自动化跨项目集成，并且团队的一部分开发时间花在了 Jenkins 维护上。然而，水平扩展具有一些显著的优势：

+   主机器在硬件方面不需要特殊。

+   不同的团队可以有不同的 Jenkins 设置（例如，不同的插件集）

+   团队通常会感到更好，并且如果实例是他们自己的话，他们会更有效地使用 Jenkins。

+   如果一个主实例宕机，不会影响整个组织

+   基础设施可以分为标准和关键任务

+   一些维护方面可以简化，例如，五人团队可以重用相同的 Jenkins 密码，因此我们可以跳过角色和安全设置（当然，只有在企业网络受到良好防火墙保护的情况下才可能）

# 测试和生产实例

除了扩展方法，还有一个问题：如何测试 Jenkins 升级、新插件或流水线定义？Jenkins 对整个公司至关重要。它保证了软件的质量，并且（在持续交付的情况下）部署到生产服务器。这就是为什么它需要高可用性，因此绝对不是为了测试的目的。这意味着应该始终存在两个相同的 Jenkins 基础架构实例：测试和生产。

测试环境应该尽可能与生产环境相似，因此也需要相似数量的附加代理。

# 示例架构

我们已经知道应该有从属者，（可能是多个）主节点，以及一切都应该复制到测试和生产环境中。然而，完整的情况会是什么样子呢？

幸运的是，有很多公司发布了他们如何使用 Jenkins 以及他们创建了什么样的架构。很难衡量更多的公司是偏好垂直扩展还是水平扩展，但从只有一个主节点实例到每个团队都有一个主节点都有。范围很广。

让我们以 Netflix 为例，来完整了解 Jenkins 基础设施的情况（他们在 2012 年旧金山 Jenkins 用户大会上分享了**计划中的基础设施**）：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/df2ac293-dafb-433e-8d17-f0f7ff006e6a.png)

他们有测试和生产主节点实例，每个实例都拥有一组从属者和额外的临时从属者。总共，它每天提供大约 2000 个构建。还要注意，他们的基础设施部分托管在 AWS 上，部分托管在他们自己的服务器上。

我们应该已经对 Jenkins 基础设施的外观有一个大致的想法，这取决于组织的类型。

现在让我们专注于设置代理的实际方面。

# 配置代理

我们已经知道代理是什么，以及何时可以使用。但是，如何设置代理并让其与主节点通信呢？让我们从问题的第二部分开始，描述主节点和代理之间的通信协议。

# 通信协议

为了让主节点和代理进行通信，必须建立双向连接。

有不同的选项可以启动它：

+   **SSH**：主节点使用标准的 SSH 协议连接到从属者。Jenkins 内置了 SSH 客户端，所以唯一的要求是从属者上配置了 SSHD 服务器。这是最方便和稳定的方法，因为它使用标准的 Unix 机制。

+   **Java Web Start**：在每个代理机器上启动 Java 应用程序，并在 Jenkins 从属应用程序和主 Java 应用程序之间建立 TCP 连接。如果代理位于防火墙网络内，主节点无法启动连接，通常会使用这种方法。

+   **Windows 服务**：主节点在远程机器上注册代理作为 Windows 服务。这种方法不鼓励使用，因为设置很棘手，图形界面的使用也有限制。

如果我们知道通信协议，让我们看看如何使用它们来设置代理。

# 设置代理

在低级别上，代理始终使用上面描述的协议与 Jenkins 主服务器通信。然而，在更高级别上，我们可以以各种方式将从节点附加到主服务器。差异涉及两个方面：

+   **静态与动态**：最简单的选项是在 Jenkins 主服务器中永久添加从节点。这种解决方案的缺点是，如果我们需要更多（或更少）的从节点，我们总是需要手动更改一些东西。更好的选择是根据需要动态提供从节点。

+   **特定与通用**：代理可以是特定的（例如，基于 Java 7 的项目有不同的代理，基于 Java 8 的项目有不同的代理），也可以是通用的（代理充当 Docker 主机，流水线在 Docker 容器内构建）。

这些差异导致了四种常见的代理配置策略：

+   永久代理

+   永久 Docker 代理

+   Jenkins Swarm 代理

+   动态提供的 Docker 代理

让我们逐个检查每种解决方案。

# 永久代理

我们从最简单的选项开始，即永久添加特定代理节点。可以完全通过 Jenkins Web 界面完成。

# 配置永久代理

在 Jenkins 主服务器上，当我们打开“管理 Jenkins”，然后点击“管理节点”，我们可以查看所有已附加的代理。然后，通过点击“新建节点”，给它一个名称，并点击“确定”按钮，最终我们应该看到代理的设置页面：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/8cc335f3-a054-4fe9-851d-a08de74aa7cc.png)

让我们来看看我们需要填写的参数：

+   **名称**：这是代理的唯一名称

+   **描述**：这是代理的任何可读描述

+   **执行器数量**：这是从节点上可以并行运行的构建数量

+   **远程根目录**：这是从节点上的专用目录，代理可以用它来运行构建作业（例如，`/var/jenkins`）；最重要的数据被传输回主服务器，因此目录并不重要

+   **标签**：这包括匹配特定构建的标签（相同标记），例如，仅基于 Java 8 的项目

+   **用法**：这是决定代理是否仅用于匹配标签（例如，仅用于验收测试构建）还是用于任何构建的选项

+   **启动方法**：这包括以下内容：

+   **通过 Java Web Start 启动从属**：在这里，代理将建立连接；可以下载 JAR 文件以及在从属机器上运行它的说明

+   **通过在主节点上执行命令启动从属**：这是在主节点上运行的自定义命令，大多数情况下它会发送 Java Web Start JAR 应用程序并在从属上启动它（例如，`ssh <slave_hostname> java -jar ~/bin/slave.jar`）

+   **通过 SSH 启动从属代理**：在这里，主节点将使用 SSH 协议连接到从属

+   **让 Jenkins 将此 Windows 从属作为 Windows 服务进行控制**：在这里，主节点将启动内置于 Windows 中的远程管理设施

+   **可用性**：这是决定代理是否应该一直在线或者在某些条件下主节点应该将其离线的选项

当代理正确设置后，可以将主节点离线，这样就不会在其上执行任何构建，它只会作为 Jenkins UI 和构建协调器。

# 理解永久从属

正如前面提到的，这种解决方案的缺点是我们需要为不同的项目类型维护多个从属类型（标签）。这种情况如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/43523171-6bcf-41c4-bed4-3658b0e1437c.png)

在我们的示例中，如果我们有三种类型的项目（**java7**，**java8**和**ruby**），那么我们需要维护三个分别带有标签的（集合）从属。这与我们在维护多个生产服务器类型时遇到的问题相同，如第二章 *引入 Docker*中所述。我们通过在生产服务器上安装 Docker Engine 来解决了这个问题。让我们尝试在 Jenkins 从属上做同样的事情。

# 永久 Docker 从属

这种解决方案的理念是永久添加通用从属。每个从属都配置相同（安装了 Docker Engine），并且每个构建与 Docker 镜像一起定义，构建在其中运行。

# 配置永久 Docker 从属

配置是静态的，所以它的完成方式与我们为永久从属所做的完全相同。唯一的区别是我们需要在每台将用作从属的机器上安装 Docker。然后，通常我们不需要标签，因为所有从属都可以是相同的。在从属配置完成后，我们在每个流水线脚本中定义 Docker 镜像。

```
pipeline {
     agent {
          docker {
               image 'openjdk:8-jdk-alpine'
          }
     }
     ...
}
```

当构建开始时，Jenkins 从服务器会从 Docker 镜像`openjdk:8-jdk-alpine`启动一个容器，然后在该容器内执行所有流水线步骤。这样，我们始终知道执行环境，并且不必根据特定项目类型单独配置每个从服务器。

# 理解永久 Docker 代理

看着我们为永久代理所采取的相同场景，图表如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/243f8a95-9de6-4851-bc72-5ec31765a752.png)

每个从服务器都是完全相同的，如果我们想构建一个依赖于 Java 8 的项目，那么我们在流水线脚本中定义适当的 Docker 镜像（而不是指定从服务器标签）。

# Jenkins Swarm 代理

到目前为止，我们总是不得不在 Jenkins 主服务器中永久定义每个代理。这样的解决方案，即使在许多情况下都足够好，如果我们需要频繁扩展从服务器的数量，可能会成为负担。Jenkins Swarm 允许您动态添加从服务器，而无需在 Jenkins 主服务器中对其进行配置。

# 配置 Jenkins Swarm 代理

使用 Jenkins Swarm 的第一步是在 Jenkins 中安装**自组织 Swarm 插件模块**插件。我们可以通过 Jenkins Web UI 在“管理 Jenkins”和“管理插件”下进行。完成此步骤后，Jenkins 主服务器准备好动态附加 Jenkins 从服务器。

第二步是在每台将充当 Jenkins 从服务器的机器上运行 Jenkins Swarm 从服务器应用程序。我们可以使用`swarm-client.jar`应用程序来完成。

`swarm-client.jar`应用程序可以从 Jenkins Swarm 插件页面下载：[`wiki.jenkins-ci.org/display/JENKINS/Swarm+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Swarm+Plugin)。在该页面上，您还可以找到其执行的所有可能选项。

要附加 Jenkins Swarm 从节点，只需运行以下命令：

```
$ java -jar swarm-client.jar -master <jenkins_master_url> -username <jenkins_master_user> -password <jenkins_master_password> -name jenkins-swarm-slave-1
```

在撰写本书时，存在一个`client-slave.jar`无法通过安全的 HTTPS 协议工作的未解决错误，因此需要在命令执行中添加`-disableSslVerification`选项。

成功执行后，我们应该注意到 Jenkins 主服务器上出现了一个新的从服务器，如屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/644e56d6-3e6e-4509-878c-b9fed436136b.png)

现在，当我们运行构建时，它将在此代理上启动。

添加 Jenkins Swarm 代理的另一种可能性是使用从`swarm-client.jar`工具构建的 Docker 镜像。Docker Hub 上有一些可用的镜像。我们可以使用`csanchez/jenkins-swarm-slave`镜像。

# 了解 Jenkins Swarm 代理

Jenkins Swarm 允许动态添加代理，但它没有说明是否使用特定的或基于 Docker 的从属，所以我们可以同时使用它。乍一看，Jenkins Swarm 可能看起来并不是很有用。毕竟，我们将代理设置从主服务器移到了从属，但仍然需要手动完成。然而，正如我们将在第八章中看到的那样，*使用 Docker Swarm 进行集群*，Jenkins Swarm 可以在服务器集群上动态扩展从属。

# 动态配置的 Docker 代理

另一个选项是设置 Jenkins 在每次启动构建时动态创建一个新的代理。这种解决方案显然是最灵活的，因为从属的数量会动态调整到构建的数量。让我们看看如何以这种方式配置 Jenkins。

# 配置动态配置的 Docker 代理

我们需要首先安装 Docker 插件。与 Jenkins 插件一样，我们可以在“管理 Jenkins”和“管理插件”中进行。安装插件后，我们可以开始以下配置步骤：

1.  打开“管理 Jenkins”页面。

1.  单击“配置系统”链接。

1.  在页面底部，有云部分。

1.  单击“添加新的云”并选择 Docker。

1.  填写 Docker 代理的详细信息。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/98d44429-9c8f-451e-9744-68fe5b895396.png)

1.  大多数参数不需要更改；但是，我们需要设置其中两个如下：

+   +   **Docker URL**：代理将在其中运行的 Docker 主机机器的地址

+   **凭据**：如果 Docker 主机需要身份验证的凭据

如果您计划在运行主服务器的相同 Docker 主机上使用它，则 Docker 守护程序需要在`docker0`网络接口上进行监听。您可以以与*在服务器上安装*部分中描述的类似方式进行操作。这与我们在维护多个生产服务器类型时遇到的问题相同，如第二章中所述，*介绍 Docker*，通过更改`/lib/systemd/system/docker.service`文件中的一行为`ExecStart=/usr/bin/dockerd -H 0.0.0.0:2375 -H fd://`

1.  单击“添加 Docker 模板”并选择 Docker 模板。

1.  填写有关 Docker 从属镜像的详细信息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/f56c7001-d4c7-466c-b687-ad946d915267.png)

我们可以使用以下参数：

+   **Docker 镜像**：Jenkins 社区中最受欢迎的从属镜像是`evarga/jenkins-slave`

+   **凭据**：对`evarga/jenkins-slave`镜像的凭据是：

+   用户名：`jenkins`

+   密码：`jenkins`

+   **实例容量**：这定义了同时运行的代理的最大数量；初始设置可以为 10

除了`evarga/jenkins-slave`之外，也可以构建和使用自己的从属镜像。当存在特定的环境要求时，例如安装了 Python 解释器时，这是必要的。在本书的所有示例中，我们使用了`leszko/jenkins-docker-slave`。

保存后，一切都设置好了。我们可以运行流水线来观察执行是否真的在 Docker 代理上进行，但首先让我们深入了解一下 Docker 代理的工作原理。

# 理解动态提供的 Docker 代理

动态提供的 Docker 代理可以被视为标准代理机制的一层。它既不改变通信协议，也不改变代理的创建方式。那么，Jenkins 会如何处理我们提供的 Docker 代理配置呢？

以下图表展示了我们配置的 Docker 主从架构：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/cd-dkr-jkn/img/cba2207e-e746-428b-950c-da8e766e7886.png)

让我们逐步描述 Docker 代理机制的使用方式：

1.  当 Jenkins 作业启动时，主机会在从属 Docker 主机上从`jenkins-slave`镜像运行一个新的容器。

1.  jenkins-slave 容器实际上是安装了 SSHD 服务器的 ubuntu 镜像。

1.  Jenkins 主机会自动将创建的代理添加到代理列表中（与我们在*设置代理*部分手动操作的方式相同）。

1.  代理是通过 SSH 通信协议访问以执行构建的。

1.  构建完成后，主机会停止并移除从属容器。

将 Jenkins 主机作为 Docker 容器运行与将 Jenkins 代理作为 Docker 容器运行是独立的。两者都是合理的选择，但它们中的任何一个都可以单独工作。

这个解决方案在某种程度上类似于永久的 Docker 代理解决方案，因为最终我们是在 Docker 容器内运行构建。然而，不同之处在于从属节点的配置。在这里，整个从属都是 docker 化的，不仅仅是构建环境。因此，它具有以下两个巨大的优势：

+   自动代理生命周期：创建、添加和移除代理的过程是自动化的。

+   可扩展性：实际上，从容器主机可能不是单个机器，而是由多台机器组成的集群（我们将在第八章中介绍使用 Docker Swarm 进行集群化，*使用 Docker Swarm 进行集群化*）。在这种情况下，添加更多资源就像添加新机器到集群一样简单，并且不需要对 Jenkins 进行任何更改。

Jenkins 构建通常需要下载大量项目依赖项（例如 Gradle/Maven 依赖项），这可能需要很长时间。如果 Docker 代理自动为每个构建进行配置，那么值得为它们设置一个 Docker 卷，以便在构建之间启用缓存。

# 测试代理

无论选择了哪种代理配置，现在我们应该检查它是否正常工作。

让我们回到 hello world 流水线。通常，构建的持续时间比 hello-world 示例长，所以我们可以通过在流水线脚本中添加睡眠来模拟它：

```
pipeline {
     agent any
     stages {
          stage("Hello") {
               steps {
                    sleep 300 // 5 minutes
                    echo 'Hello World'
               }
          }
     }
}
```

点击“立即构建”并转到 Jenkins 主页后，我们应该看到构建是在代理上执行的。现在，如果我们多次点击构建，不同的代理应该执行不同的构建（如下截图所示）：

为了防止作业在主节点上执行，记得将主节点设置为离线或在节点管理配置中将**执行器数量**设置为`0`。

通过观察代理执行我们的构建，我们确认它们已经正确配置。现在，让我们看看为什么以及如何创建我们自己的 Jenkins 镜像。

# 自定义 Jenkins 镜像

到目前为止，我们使用了从互联网上拉取的 Jenkins 镜像。我们使用`jenkins`作为主容器，`evarga/jenkins-slave`作为从容器。然而，我们可能希望构建自己的镜像以满足特定的构建环境要求。在本节中，我们将介绍如何做到这一点。

# 构建 Jenkins 从容器

让我们从从容器镜像开始，因为它经常被定制。构建执行是在代理上执行的，因此需要调整代理的环境以适应我们想要构建的项目。例如，如果我们的项目是用 Python 编写的，可能需要 Python 解释器。同样的情况也适用于任何库、工具、测试框架或项目所需的任何内容。

您可以通过查看其 Dockerfile 来查看`evarga/jenkins-slave`镜像中已安装的内容[`github.com/evarga/docker-images`](https://github.com/evarga/docker-images)。

构建和使用自定义镜像有三个步骤：

1.  创建一个 Dockerfile。

1.  构建镜像。

1.  更改主节点上的代理配置。

举个例子，让我们创建一个为 Python 项目提供服务的从节点。为了简单起见，我们可以基于`evarga/jenkins-slave`镜像构建它。让我们按照以下三个步骤来做：

1.  **Dockerfile**：让我们在 Dockerfile 中创建一个新目录，内容如下：

```
 FROM evarga/jenkins-slave
 RUN apt-get update && \
 apt-get install -y python
```

基础 Docker 镜像`evarga/jenkins-slave`适用于动态配置的 Docker 代理解决方案。对于永久性 Docker 代理，只需使用`alpine`、`ubuntu`或任何其他镜像即可，因为 docker 化的不是从节点，而只是构建执行环境。

1.  **构建镜像**：我们可以通过执行以下命令来构建镜像：

```
 $ docker build -t jenkins-slave-python .
```

1.  **配置主节点**：当然，最后一步是在 Jenkins 主节点的配置中设置`jenkins-slave-python`，而不是`evarga/jenkins-slave`（如*设置 Docker 代理*部分所述）。

从节点的 Dockerfile 应该保存在源代码仓库中，并且可以由 Jenkins 自动执行构建。使用旧的 Jenkins 从节点构建新的 Jenkins 从节点镜像没有问题。

如果我们需要 Jenkins 构建两种不同类型的项目，例如一个基于 Python，另一个基于 Ruby，该怎么办？在这种情况下，我们可以准备一个足够通用以支持 Python 和 Ruby 的代理。然而，在 Docker 的情况下，建议创建第二个从节点镜像（通过类比创建`jenkins-slave-ruby`）。然后，在 Jenkins 配置中，我们需要创建两个 Docker 模板并相应地标记它们。

# 构建 Jenkins 主节点

我们已经有一个自定义的从节点镜像。为什么我们还想要构建自己的主节点镜像呢？其中一个原因可能是我们根本不想使用从节点，而且由于执行将在主节点上进行，它的环境必须根据项目的需求进行调整。然而，这是非常罕见的情况。更常见的情况是，我们会想要配置主节点本身。

想象一下以下情景，您的组织将 Jenkins 水平扩展，每个团队都有自己的实例。然而，有一些共同的配置，例如：一组基本插件，备份策略或公司标志。然后，为每个团队重复相同的配置是一种浪费时间。因此，我们可以准备共享的主镜像，并让团队使用它。

Jenkins 使用 XML 文件进行配置，并提供基于 Groovy 的 DSL 语言来对其进行操作。这就是为什么我们可以将 Groovy 脚本添加到 Dockerfile 中，以操纵 Jenkins 配置。而且，如果需要比 XML 更多的更改，例如插件安装，还有特殊的脚本来帮助 Jenkins 配置。

Dockerfile 指令的所有可能性都在 GitHub 页面[`github.com/jenkinsci/docker`](https://github.com/jenkinsci/docker)上有详细描述。

例如，让我们创建一个已经安装了 docker-plugin 并将执行者数量设置为 5 的主镜像。为了做到这一点，我们需要：

1.  创建 Groovy 脚本以操纵`config.xml`并将执行者数量设置为`5`。

1.  创建 Dockerfile 以安装 docker-plugin 并执行 Groovy 脚本。

1.  构建图像。

让我们使用提到的三个步骤构建 Jenkins 主镜像。

1.  **Groovy 脚本**：让我们在`executors.groovy`文件内创建一个新目录，内容如下：

```
import jenkins.model.*
Jenkins.instance.setNumExecutors(5)
```

完整的 Jenkins API 可以在官方页面[`javadoc.jenkins.io/`](http://javadoc.jenkins.io/)上找到。

1.  **Dockerfile**：在同一目录下，让我们创建 Dockerfile：

```
FROM jenkins
COPY executors.groovy 
      /usr/share/jenkins/ref/init.groovy.d/executors.groovy
RUN /usr/local/bin/install-plugins.sh docker-plugin
```

1.  **构建图像**：我们最终可以构建图像：

```
$ docker build -t jenkins-master .
```

创建图像后，组织中的每个团队都可以使用它来启动自己的 Jenkins 实例。

拥有自己的主从镜像可以为我们组织中的团队提供配置和构建环境。在接下来的部分，我们将看到 Jenkins 中还有哪些值得配置。

# 配置和管理

我们已经涵盖了 Jenkins 配置的最关键部分：代理配置。由于 Jenkins 具有高度可配置性，您可以期望有更多的可能性来调整它以满足您的需求。好消息是配置是直观的，并且可以通过 Web 界面访问，因此不需要任何详细的描述。所有内容都可以在“管理 Jenkins”子页面下更改。在本节中，我们只会关注最有可能被更改的一些方面：插件、安全和备份。

# 插件

Jenkins 是高度面向插件的，这意味着许多功能都是通过插件提供的。它们可以以几乎无限的方式扩展 Jenkins，考虑到庞大的社区，这是 Jenkins 如此成功的原因之一。Jenkins 的开放性带来了风险，最好只从可靠的来源下载插件或检查它们的源代码。

选择插件的数量实际上有很多。其中一些在初始配置过程中已经自动安装了。另一个（Docker 插件）是在设置 Docker 代理时安装的。有用于云集成、源代码控制工具、代码覆盖等的插件。你也可以编写自己的插件，但最好先检查一下你需要的插件是否已经存在。

有一个官方的 Jenkins 页面可以浏览插件[`plugins.jenkins.io/`](https://plugins.jenkins.io/)。

# 安全

您应该如何处理 Jenkins 安全取决于您在组织中选择的 Jenkins 架构。如果您为每个小团队都有一个 Jenkins 主服务器，那么您可能根本不需要它（假设企业网络已设置防火墙）。然而，如果您为整个组织只有一个 Jenkins 主服务器实例，那么最好确保您已经很好地保护了它。

Jenkins 自带自己的用户数据库-我们在初始配置过程中已经创建了一个用户。您可以通过打开“管理用户”设置页面来创建、删除和修改用户。内置数据库可以在小型组织的情况下使用；然而，对于大量用户，您可能希望使用 LDAP。您可以在“配置全局安全”页面上选择它。在那里，您还可以分配角色、组和用户。默认情况下，“已登录用户可以做任何事情”选项被设置，但在大规模组织中，您可能需要考虑更详细的细粒度。

# 备份

俗话说：“有两种人：那些备份的人，和那些将要备份的人”。信不信由你，备份可能是你想要配置的东西。要备份哪些文件，从哪些机器备份？幸运的是，代理自动将所有相关数据发送回主服务器，所以我们不需要担心它们。如果你在容器中运行 Jenkins，那么容器本身也不重要，因为它不保存任何持久状态。我们唯一感兴趣的地方是 Jenkins 主目录。

我们可以安装一个 Jenkins 插件（帮助我们设置定期备份），或者简单地设置一个 cron 作业将目录存档到一个安全的地方。为了减小大小，我们可以排除那些不感兴趣的子文件夹（这将取决于你的需求；然而，几乎可以肯定的是，你不需要复制："war"，"cache"，"tools"和"workspace"）。

有很多插件可以帮助备份过程；最常见的一个叫做**备份插件**。

# 蓝色海洋 UI

Hudson（Jenkins 的前身）的第一个版本于 2005 年发布。它已经在市场上超过 10 年了。然而，它的外观和感觉并没有改变太多。我们已经使用它一段时间了，很难否认它看起来过时。Blue Ocean 是一个重新定义了 Jenkins 用户体验的插件。如果 Jenkins 在美学上让你不满意，那么值得一试。

您可以在[`jenkins.io/projects/blueocean/`](https://jenkins.io/projects/blueocean/)的蓝色海洋页面上阅读更多信息！[](assets/8bc21c85-2ef8-4974-8bdf-24d022228c4f.png)

# 练习

在本章中，我们学到了很多关于 Jenkins 配置的知识。为了巩固这些知识，我们建议进行两个练习，准备 Jenkins 镜像并测试 Jenkins 环境。

1.  创建 Jenkins 主和从属 Docker 镜像，并使用它们来运行能够构建 Ruby 项目的 Jenkins 基础设施：

+   创建主 Dockerfile，自动安装 Docker 插件。

+   构建主镜像并运行 Jenkins 实例

+   创建从属 Dockerfile（适用于动态从属供应），安装 Ruby 解释器

+   构建从属镜像

+   在 Jenkins 实例中更改配置以使用从属镜像

1.  创建一个流水线，运行一个打印`Hello World from Ruby`的 Ruby 脚本：

+   创建一个新的流水线

+   使用以下 shell 命令即时创建`hello.rb`脚本：

`sh "echo "puts 'Hello World from Ruby'" > hello.rb"`

+   添加命令以使用 Ruby 解释器运行`hello.rb`

+   运行构建并观察控制台输出

# 总结

在本章中，我们已经介绍了 Jenkins 环境及其配置。所获得的知识足以建立完整基于 Docker 的 Jenkins 基础设施。本章的关键要点如下：

+   Jenkins 是一种通用的自动化工具，可与任何语言或框架一起使用。

+   Jenkins 可以通过插件进行高度扩展，这些插件可以自行编写或在互联网上找到。

+   Jenkins 是用 Java 编写的，因此可以安装在任何操作系统上。它也作为 Docker 镜像正式提供。

+   Jenkins 可以使用主从架构进行扩展。主实例可以根据组织的需求进行水平或垂直扩展。

+   Jenkins 的代理可以使用 Docker 实现，这有助于自动配置和动态分配从机。

+   可以为 Jenkins 主和 Jenkins 从创建自定义 Docker 镜像。

+   Jenkins 是高度可配置的，应始终考虑的方面是：安全性和备份。

在下一章中，我们将专注于已经通过“hello world”示例接触过的部分，即管道。我们将描述构建完整持续集成管道的思想和方法。
