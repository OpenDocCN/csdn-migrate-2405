# Python 云原生教程（一）

> 原文：[`zh.annas-archive.org/md5/7CEC2A066F3DD2FF52013764748D267D`](https://zh.annas-archive.org/md5/7CEC2A066F3DD2FF52013764748D267D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

如今的企业发展如此迅速，以至于拥有自己的基础架构来支持扩张已经不可行。因此，它们一直在利用云的弹性来提供一个构建和部署高度可扩展应用的平台。

这本书将是你学习如何在 Python 中构建云原生架构的一站式书籍。它将首先向你介绍云原生架构，并帮助你分解它。然后你将学习如何使用事件驱动方法在 Python 中构建微服务，并构建 Web 层。接下来，你将学习如何与数据服务交互，并使用 React 构建 Web 视图，之后我们将详细了解应用安全性和性能。然后，你还将学习如何将你的服务 Docker 化。最后，你将学习如何在 AWS 和 Azure 平台上部署应用。我们将以讨论一些关于部署后应用可能出现的问题的概念和技术来结束本书。

这本书将教会你如何构建作为小型标准单元的应用，使用所有经过验证的最佳实践，并避免通常的陷阱。这是一本实用的书；我们将使用 Python 3 及其令人惊叹的工具生态系统来构建一切。本书将带你踏上一段旅程，其目的地是基于云平台的微服务构建完整的 Python 应用程序。

# 本书涵盖的内容

第一章《介绍云原生架构和微服务》讨论了基本的云原生架构，并让你准备好构建应用程序。

第二章《使用 Python 构建微服务》为你提供了构建微服务和根据你的用例扩展它们的完整知识。

第三章《使用 Python 构建 Web 应用程序》构建了一个与微服务集成的初始 Web 应用程序。

第四章《与数据服务交互》让你亲自了解如何将你的应用迁移到不同的数据库服务。

第五章《使用 React 构建 Web 视图》讨论了如何使用 React 构建用户界面。

第六章《使用 Flux 创建可扩展的 UI》让你了解了用于扩展应用的 Flux。

第七章《学习事件溯源和 CQRS》讨论了如何以事件形式存储交易以提高应用性能。

第八章《保护 Web 应用程序》帮助你保护应用程序免受外部威胁。

第九章《持续交付》让你了解频繁应用发布的知识。

第十章《将你的服务 Docker 化》讨论了容器服务和在 Docker 中运行应用程序。

第十一章《在 AWS 平台上部署》教会你如何在 AWS 上为你的应用构建基础架构并设置生产环境。

第十二章《在 Azure 平台上实施》讨论了如何在 Azure 上为你的应用构建基础架构并设置生产环境。

第十三章《监控云应用》让你了解不同的基础架构和应用监控工具。

# 你需要为这本书做好什么准备

您需要在系统上安装 Python。最好使用文本编辑器 Vim/Sublime/Notepad++。在其中一章中，您可能需要下载 POSTMAN，这是一个强大的 API 测试套件，可作为 Chrome 扩展程序使用。您可以在[`chrome.google.com/webstore/detail/postman/fhbjgbiflinjbdggehcddcbncdddomop?hl=en`](https://chrome.google.com/webstore/detail/postman/fhbjgbiflinjbdggehcddcbncdddomop?hl=en)下载。

除了这些之外，如果您在以下网络应用程序上有账户，那将是很好的：

+   Jenkins

+   Docker

+   亚马逊网络服务

+   Terraform

如果您没有账户，这本书将指导您，或者至少指导您如何在先前提到的网络应用程序上创建账户。

# 这本书是为谁写的

这本书适用于具有 Python 基础知识、命令行和基于 HTTP 的应用程序原理的开发人员。对于那些想要学习如何构建、测试和扩展他们的基于 Python 的应用程序的人来说，这本书是理想的选择。不需要有 Python 编写微服务的先前经验。 

# 约定

在这本书中，您将找到一些文本样式，用于区分不同类型的信息。以下是一些样式的示例及其含义的解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下：“创建一个`signup`路由，该路由将使用`GET`和`POST`方法读取页面，并将数据提交到后端数据库。”

代码块设置如下：

```py
    sendTweet(event){
      event.preventDefault();
      this.props.sendTweet(this.refs.tweetTextArea.value); 
      this.refs.tweetTextArea.value = '';
    } 

```

任何命令行输入或输出都以以下方式编写：

```py
$ apt-get install nodejs

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“单击“创建用户”按钮，用户将被创建，并且策略将附加到其中。”

警告或重要说明会以这种方式出现。

技巧和窍门会以这种方式出现。


# 第一章：介绍云原生架构和微服务

我们开始吧！在我们开始构建应用程序之前，我们需要找到以下一些问题的答案：

+   什么是云计算？它有哪些不同类型？

+   什么是微服务及其概念？

+   什么是好去做的基本要求？

在本章中，我们将专注于开发人员或应用程序员在开始编写应用程序之前应该了解的不同概念。

让我们先了解一下系统构建及其演变。

长期以来，我们一直在寻找构建系统的新方法。随着新技术的进步和更好方法的采用，IT 基础设施变得更加可靠和有效，为客户提供更好的体验，也让工程师感到满意。

持续交付帮助我们将软件开发周期转移到生产环境，并让我们识别软件中不同易出错的方面，坚持认为每次代码提交都是适合发布到生产环境的候选项。

我们对互联网运作方式的理解已经推动我们发展出更好的让机器与其他机器交流的方法。虚拟化平台使我们能够独立创建解决方案并调整我们的机器大小，基础设施自动化使我们能够以规模管理这些机器。一些大型、成功的云平台，如亚马逊、Azure 和谷歌，已经采纳了小团队拥有其服务的全生命周期的观点。领域驱动设计（DDD）、持续交付（CD）、按需虚拟化、基础设施自动化、小型自治团队和规模化系统等概念是不同特征，它们有效地将我们的软件投入生产。现在，微服务已经从这个世界中崛起。它并不是在现实之前开发或描述的；它是作为一种趋势或者说是从真实使用中崛起的。在本书中，我将从这些先前的工作中提取出一些内容，以帮助说明如何构建、管理和优化微服务。

许多组织发现，通过采用细粒度的微服务结构，他们可以快速交付软件，并掌握更新的技术。微服务基本上给了我们更多的灵活性来做出反应和做出各种决策，允许我们迅速应对不可避免的影响我们所有人的变化。

# 云计算简介

在我们开始微服务和云原生概念之前，让我们先了解一下云计算的基本概念。

云计算是一个描述广泛的服务的广泛术语。与技术中的其他重大发展一样，许多供应商都抓住了“云”这个词，并将其用于超出基本定义范围的产品。由于云是一个广泛的服务集合，组织可以选择何时、何地以及如何使用云计算。

云计算服务可以分为以下几类：

+   SaaS：这些是准备好被最终用户接受的成熟应用程序

+   PaaS：这些是一组对于想要构建他们的应用程序或快速将其直接托管到生产环境而不必关心底层硬件的用户/开发人员有用的工具和服务

+   IaaS：这是为想要构建自己的业务模型并自定义它的客户提供的服务

云计算作为一个堆栈，可以解释如下：

+   云计算通常被称为堆栈，基本上是一系列服务，其中每个服务都建立在另一个服务的基础上，统称为“云”。

+   云计算模型被认为是一组不同的可配置计算资源（如服务器、数据库和存储），它们彼此通信，并且可以在最少监督下进行配置。

以下图表展示了云计算堆栈组件：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00005.jpeg)

让我们详细了解云计算组件及其用例。

# 软件即服务

以下是描述 SaaS 的关键要点：

+   软件即服务（SaaS）为用户提供了访问托管在服务提供商场所的软件的能力，通过提供商通过互联网提供的服务作为服务通过 Web 浏览器。这些服务基于订阅，并且也被称为按需软件。

+   SaaS 提供公司包括谷歌文档生产套件、甲骨文 CRM（客户关系管理）、微软及其 Office 365 提供和 Salesforce CRM 和 QuickBooks。

+   SaaS 还可以进一步分类为专业 SaaS，专注于特定行业的需求，如医疗保健和农业，或横向 SaaS，专注于软件行业，如人力资源和销售。

+   SaaS 提供基本上是为那些迅速想要掌握现有应用程序的组织而设计的，这些应用程序易于使用和理解，即使对于非技术人员也是如此。根据组织的使用和预算，企业可以选择支持计划。此外，您可以从全球任何地方的任何设备上访问这些 SaaS 应用程序，并且具有互联网功能。

# 平台即服务

以下是描述 PaaS 的关键要点：

+   在 PaaS 提供中，组织/企业无需担心其内部应用程序的硬件和软件基础设施管理

+   PaaS 的最大好处是为开发团队（本地或远程），他们可以在一个共同的框架上高效地构建、测试和部署他们的应用程序，其中底层硬件和软件由 PaaS 服务提供商管理。

+   PaaS 服务提供商提供平台，并在平台周围提供不同的服务

+   PaaS 提供商的示例包括亚马逊网络服务（AWS Elastic Beanstalk）、微软 Azure（Azure 网站）、谷歌应用引擎和甲骨文（大数据云服务）

# 基础设施即服务

以下是描述 IaaS 的关键要点：

+   与 SaaS 不同，在 IaaS 中，客户提供 IT 资源，例如裸金属机器来运行应用程序，硬盘用于存储，以及网络电缆用于网络功能，他们可以根据其业务模型进行定制。

+   在 IaaS 提供中，由于客户可以完全访问其基础设施，他们可以根据其应用程序的要求扩展其 IT 资源。此外，在 IaaS 提供中，客户必须管理应用程序/资源的安全性，并需要在突发故障/崩溃时建立灾难恢复模型。

+   在 IaaS 中，服务是按需提供的，客户根据使用情况收费。因此，客户有责任对其资源进行成本分析，这将有助于限制他们超出预算。

+   它允许客户/消费者根据应用程序的要求定制其基础设施，然后快速高效地拆除基础设施并重新创建。

+   基于 IaaS 的定价模型基本上是按需提供的，这意味着您按需付费。您根据资源的使用和使用时间收费。

+   亚马逊网络服务（提供 Amazon Elastic Compute Cloud（Amazon EC2）和 Amazon Simple Storage Service（Amazon S3））是云服务中的第一个，然而，微软 Azure（虚拟机）、Rackspace（虚拟云服务器）和甲骨文（裸金属云服务）等公司也声名显赫。

# 云原生概念

云原生是构建团队、文化和技术，利用自动化和架构来管理复杂性并释放速度。

云原生概念超越了与其相关的技术。我们需要了解公司、团队和个人是如何取得成功的，才能了解我们的行业将走向何方。

目前，像 Facebook 和 Netflix 这样的公司已经投入了大量资源来研究云原生技术。即使是小型和更灵活的公司现在也意识到了这些技术的价值。

通过云原生的成熟实践的反馈，以下是一些显而易见的优势：

+   以结果为导向和团队满意度：云原生方法展示了将一个大问题分解成小问题的方式，这样每个团队可以专注于个别部分。

+   繁重的工作：自动化减少了引起运营痛苦的重复手动任务，并减少了停机时间。这使得您的系统更加高效，并且产生更加高效的结果。

+   可靠高效的应用程序基础设施：自动化使得在不同环境中部署更加可控——无论是开发、阶段还是生产环境——并且还可以处理意外事件或故障。构建自动化不仅有助于正常部署，而且在灾难恢复情况下也使部署变得更加容易。

+   对应用程序的洞察：围绕云原生应用程序构建的工具提供了更多对应用程序的洞察，使它们易于调试、故障排除和审计。

+   高效可靠的安全性：在每个应用程序中，主要关注点是其安全性，并确保它可以通过所需的渠道进行身份验证。云原生方法为开发人员提供了确保应用程序安全性的不同方式。

+   成本效益的系统：云方法管理和部署您的应用程序使资源的使用更加高效，这也包括应用程序发布，因此通过减少资源的浪费使系统更加具有成本效益。

# 云原生——它的含义和重要性是什么？

云原生是一个广义术语，利用不同的技术，如基础设施自动化、开发中间件和支持服务，这些基本上是您的应用程序交付周期的一部分。云原生方法包括频繁的无故障和稳定的软件发布，并且可以根据业务需求扩展应用程序。

使用云原生方法，您将能够以系统化的方式实现应用程序构建的目标。

云原生方法远比传统的虚拟化导向编排更好，后者需要大量工作来构建适合开发的环境，然后为软件交付过程构建一个完全不同的环境。理想的云原生架构应该具有自动化和组合功能，可以代表您工作。这些自动化技术还应该能够管理和部署您的应用程序到不同的平台，并为您提供结果。

您的云原生架构还应该能够识别一些其他运营因素，如稳定的日志记录、监控应用程序和基础设施，以确保应用程序正常运行。

云原生方法确实帮助开发人员使用诸如 Docker 之类的工具在不同平台上构建其应用程序，Docker 是轻量级且易于创建和销毁的。

# 云原生运行时

容器是如何在从一个计算环境移动到另一个计算环境时可靠运行软件的最佳解决方案。这可能是从一个开发者机器到阶段环境，再到生产环境，也可能是从物理机器到私有或公共云中的虚拟机。Kubernetes 已经成为容器服务的代名词，并且正在变得越来越流行。

随着云原生框架的兴起和围绕其构建的应用程序数量的增加，容器编排的属性受到了更多的关注和使用。以下是您从容器运行时需要的内容：

+   **管理容器状态和高可用性**：务必在生产环境中维护容器的状态（如创建和销毁），因为这对于业务至关重要，并且应能够根据业务需求进行扩展

+   **成本分析和实现**：容器可以根据您的业务预算控制资源管理，并且可以大大降低成本

+   **隔离环境**：在容器内运行的每个进程应保持在该容器内部隔离

+   **跨集群负载平衡**：应用程序流量基本上由一组容器集群处理，应在容器内平衡重定向，这将增加应用程序的响应并保持高可用性

+   **调试和灾难恢复**：由于我们在处理生产系统，因此需要确保我们拥有正确的工具来监视应用程序的健康状况，并采取必要的措施以避免停机并提供高可用性

# 云原生架构

云原生架构与我们为传统系统创建的任何应用程序架构类似，但在云原生应用程序架构中，我们应该考虑一些特征，例如十二要素应用程序（应用程序开发的模式集合）、微服务（将单块业务系统分解为独立的可部署服务）、自助式敏捷基础设施（自助式平台）、基于 API 的协作（通过 API 进行服务之间的交互）和反脆弱性（自我实现和加强应用程序）。

首先，让我们讨论一下*什么是微服务？*

微服务是一个更广泛的术语，将大型应用程序分解为较小的模块进行开发，并使其足够成熟以发布。这种方法不仅有助于有效管理每个模块，还可以在较低级别识别问题。以下是微服务的一些关键方面：

+   **用户友好的界面**：微服务使微服务之间能够清晰分离。微服务的版本控制使 API 更易于控制，并且还为这些服务的消费者和生产者提供了更多自由。

+   **在平台上部署和管理 API**：由于每个微服务都是一个独立的实体，因此可以更新单个微服务而无需更改其他微服务。此外，对于微服务来说，回滚更容易。这意味着部署的微服务的构件在 API 和数据模式方面应兼容。这些 API 必须在不同平台上进行测试，并且测试结果应该在不同团队之间共享，即运营、开发人员等，以维护一个集中的控制系统。

+   **应用程序的灵活性**：开发的微服务应能够处理请求并必须做出响应，无论请求的类型如何，可能是错误的输入或无效的请求。此外，您的微服务应能够处理意外的负载请求并做出适当的响应。所有这些微服务都应该独立测试，以及进行集成测试。

+   **微服务的分发**：最好将服务分割成小块服务，以便可以单独跟踪和开发，并组合成一个微服务。这种技术使微服务的开发更加高效和稳定。

以下图表显示了云原生应用程序的高级架构：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00006.gif)

应用程序架构理想上应该从两个或三个服务开始，尝试通过进一步的版本扩展。了解应用程序架构非常重要，因为它可能需要与系统的不同组件集成，并且在大型组织中，可能有一个单独的团队管理这些组件。在微服务中进行版本控制非常重要，因为它标识了在开发的指定阶段支持的方法。

# 微服务是一个新概念吗？

微服务在行业中已经存在很长时间了。这是创建大型系统的不同组件之间的区别的另一种方式。微服务以类似的方式工作，它们作为不同服务之间的链接，并根据请求类型处理特定交易的数据流。

以下图表描述了微服务的架构：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00007.jpeg)

# 为什么 Python 是云原生微服务开发的最佳选择？

为什么我选择 Python，并推荐尽可能多的人使用它？嗯，这归结于下面部分中解释的原因。

# 可读性

Python 是一种高度表达性和易于学习的编程语言。即使是业余爱好者也可以轻松发现 Python 的不同功能和范围。与其他编程语言（如 Java）不同，它更注重括号、括号、逗号和冒号，Python 让你花更多时间在编程上，而不是在调试语法上。

# 库和社区

Python 的广泛库范围在不同平台（如 Unix、Windows 或 OS X）上非常便携。这些库可以根据您的应用程序/程序要求轻松扩展。有一个庞大的社区致力于构建这些库，这使得它成为商业用例的最佳选择。

就 Python 社区而言，**Python 用户组**（**PUG**）是一个致力于通过基于社区的开发模型增加 Python 在全球范围内的知名度的社区。这些团体成员就基于 Python 的框架发表演讲，这有助于我们构建大型系统。

# 交互模式

Python 交互模式可帮助您调试和测试代码片段，稍后可以将其作为主程序的一部分添加。

# 可扩展性

Python 提供了更好的结构和概念，例如模块，以比任何其他脚本语言（如 shell 脚本）更系统地维护大型程序。

# 了解十二要素应用程序

云原生应用程序符合旨在通过可预测的实践增强灵活性的协议。这个应用程序保持了一种名为**十二要素**应用程序的宣言。它概述了开发人员在构建现代基于 Web 的应用程序时应遵循的方法论。开发人员必须改变他们的编码方式，为他们的应用程序运行的基础设施之间创建一个新的合同。

在开发云原生应用程序时，有几点需要考虑：

+   使用信息化设计，通过自动化增加应用程序的使用率，减少客户的时间和成本

+   在不同环境（如阶段和生产）和不同平台（如 Unix 或 Windows）之间使用应用程序可移植性

+   使用云平台上的应用程序适用性，并了解资源分配和管理

+   使用相同的环境来减少 bug，并通过持续交付/部署实现软件发布的最大灵活性

+   通过最小的监督扩展应用程序并设计灾难恢复架构，实现高可用性

许多十二要素相互作用。它们通过强调声明性配置，专注于速度、安全性和规模。十二要素应用程序可以描述如下：

+   **集中式代码库**：每个部署的代码都在修订控制中进行跟踪，并且应该在多个平台上部署多个实例。

+   **依赖管理**：应用程序应能够声明依赖关系，并使用诸如 Bundler、pip 和 Maven 等工具对其进行隔离。

+   **定义配置**：在操作系统级别定义可能在不同部署环境（如开发、阶段和生产）中不同的配置（即环境变量）。

+   **后备服务**：每个资源都被视为应用程序本身的一部分。后备服务，如数据库和消息队列，应被视为附加资源，并在所有环境中平等消耗。

+   **在构建、发布和运行周期中的隔离**：这涉及在构建工件之间进行严格分离，然后与配置结合，然后从工件和配置组合中启动一个或多个实例。

+   **无状态进程**：应用程序应执行一个或多个实例/进程（例如，主/工作者），它们之间没有共享。

+   **服务端口绑定**：应用程序应是自包含的，如果需要暴露任何/所有服务，则应通过端口绑定（最好是 HTTP）来实现。

+   **扩展无状态进程**：架构应强调在底层平台中管理无状态进程，而不是向应用程序实现更多复杂性。

+   **进程状态管理**：进程应该能够快速扩展并在短时间内优雅地关闭。这些方面可以实现快速扩展性、部署更改和灾难恢复。

+   **持续交付/部署到生产环境**：始终尝试保持不同环境的相似性，无论是开发、阶段还是生产。这将确保您在多个环境中获得类似的结果，并实现从开发到生产的持续交付。

+   **日志作为事件流**：日志记录非常重要，无论是平台级还是应用程序级，因为这有助于了解应用程序的活动。启用不同的可部署环境（最好是生产环境）通过集中服务收集、聚合、索引和分析事件。

+   **临时任务作为一次性进程**：在云原生方法中，作为发布的一部分运行的管理任务（例如数据库迁移）应作为一次性进程运行到环境中，而不是作为具有长时间运行进程的常规应用程序。

云应用平台，如 Cloud Foundry、Heroku 和 Amazon Beanstalk，都经过优化，用于部署十二要素应用。

考虑所有这些标准，并将应用程序与稳定的工程接口集成，即处理无状态概要设计，使得分布式应用程序具备云准备能力。Python 通过其固执、传统而非设置的方式，彻底改变了应用程序系统的发展。

# 设置 Python 环境

正如我们将在本书中展示的那样，拥有正确的环境（本地或用于自动化构建）对于任何开发项目的成功至关重要。如果工作站具有正确的工具，并且设置正确，那么在该工作站上进行开发会感觉像是一股清新的空气。相反，一个设置不良的环境会让任何开发人员使用起来感到窒息。

以下是我们在本书后期需要的先决条件账户：

+   需要创建 GitHub 账户进行源代码管理。使用以下链接中的文章来创建：

[`medium.com/appliedcode/setup-github-account-9a5ec918bcc1`](https://medium.com/appliedcode/setup-github-account-9a5ec918bcc1)

+   应用程序部署需要 AWS 和 Azure 账户。使用以下链接中提供的文章来创建这些账户：

+   AWS: [`medium.com/appliedcode/setup-aws-account-1727ce89353e`](https://medium.com/appliedcode/setup-aws-account-1727ce89353e.)

+   Azure: [`medium.com/appliedcode/setup-microsoft-azure-account-cbd635ebf14b`](https://medium.com/appliedcode/setup-microsoft-azure-account-cbd635ebf14b)

现在，让我们设置一些在开发项目中需要的工具。

# 安装 Git

Git ([`git-scm.com`](https://git-scm.com)) 是一个免费的开源分布式版本控制系统，旨在处理从小型到非常大型的项目，速度和效率都很高。

# 在基于 Debian 的发行版 Linux（如 Ubuntu）上安装 Git

您可以通过几种方式在 Debian 系统上安装 Git：

1.  使用**高级软件包工具**（**APT**）软件包管理工具：

您可以使用 APT 软件包管理工具更新本地软件包索引。然后，您可以以 root 用户身份使用以下命令下载并安装最新的 Git：

```py
      $ apt-get update -y
      $ apt-get install git -y  

```

上述命令将在您的系统上下载并安装 Git。

1.  使用源代码，您可以执行以下操作：

1.  从 GitHub 存储库下载源代码，并从源代码编译软件。

在开始之前，让我们首先安装 Git 的依赖项；以 root 用户身份执行以下命令：

```py
      $ apt-get update -y 
      $ apt-get install build-essential libssl-dev
      libcurl4-gnutls-dev libexpat1-dev gettext unzip -y   

```

2. 安装必要的依赖项后，让我们转到 Git 项目存储库（[`github.com/git/git`](https://github.com/git/git)）下载源代码，如下所示：

```py
      $ wget https://github.com/git/git/archive/v1.9.1.zip -Ogit.zip  

```

3. 现在，使用以下命令解压下载的 ZIP 文件：

```py
      $ unzip git.zip
      $ cd git-*  

```

4. 现在，您必须制作软件包并以 sudo 用户身份安装它。为此，请使用接下来给出的命令：

```py
      $ make prefix=/usr/local all
      $ make prefix=/usr/local install

```

上述命令将在您的系统上安装 Git 到`/usr/local`。

# 在基于 Debian 的发行版上设置 Git

现在我们已经在系统上安装了 Git，我们需要设置一些配置，以便为您生成的提交消息包含您的正确信息。

基本上，我们需要在配置中提供名称和电子邮件。让我们使用以下命令添加这些值：

```py
$ git config --global user.name "Manish Sethi"
$ git config --global user.email manish@sethis.in  

```

# 在 Windows 上安装 Git

让我们在 Windows 上安装 Git；您可以从官方网站（[`git-scm.com/download/win`](https://git-scm.com/download/win)）下载最新版本的 Git。按照下面列出的步骤在 Windows 系统上安装 Git：

1.  下载`.exe`文件后，双击运行。首先，您将看到 GNU 许可证，如此截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00008.jpeg)

点击下一步：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00009.jpeg)

在前面截图中显示的部分中，您可以根据需要自定义设置，或者保持默认设置，这对于本书来说是可以的。

1.  另外，您可以安装 Git Bash 和 Git；点击下一步：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00010.jpeg)

1.  在下一个截图中看到的部分中，您可以启用与 Git 软件包一起提供的其他功能。然后，点击下一步：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00011.jpeg)

1.  您可以通过点击下一步跳过其余步骤，然后进行安装部分。

安装完成后，您将能够看到如下屏幕：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00012.jpeg)

太好了！我们已经成功在 Windows 上安装了 Git！

# 使用 Chocolatey

这是我在 Windows 10 上安装 Git 的首选方式。它以一行安装与之前相同的软件包。如果您还没有听说过 Chocolatey，请停下一切，去多了解一些。它可以用单个命令安装软件；您不再需要使用点击安装程序！

Chocolatey 非常强大，我将其与**Boxstarter**结合使用来设置我的开发机器。如果您负责在 Windows 上为开发人员设置机器，这绝对值得一试。

让我们看看您如何使用 Chocolatey 安装 Git。我假设您已经安装了 Chocolatey（[`chocolatey.org/install`](https://chocolatey.org/install)）（在命令提示符中是一行）。然后，简单地打开`管理员命令`窗口，并输入此命令：

```py
$ choco install git -params '"/GitAndUnixToolsOnPath"'  

```

这将安装 Git 和`BASH`工具，并将它们添加到您的路径中。

# 在 Mac 上安装 Git

在开始 Git 安装之前，我们需要为 OS X 安装命令行工具。

# 为 OS X 安装命令行工具

为了安装任何开发者，您需要安装 Xcode（[`developer.apple.com/xcode/`](https://developer.apple.com/xcode/)），这是一个将近 4GB 的开发者套件。苹果公司在 Mac App Store 上免费提供。为了安装 Git 和 GitHub 设置，您需要安装一些命令行工具，这些工具是 Xcode 开发工具的一部分。

如果您有足够的空间，下载并安装 Xcode，这基本上是一个完整的开发工具包。

您需要在[developer.apple.com](http://developer.apple.com)上创建一个苹果开发者帐户，以便下载命令行工具。设置好您的帐户后，您可以根据版本选择命令行工具或 Xcode，如下所示：

+   如果您使用的是 OS X 10.7.x，下载 10.7 命令行工具。如果您使用的是 OS X 10.8.x，下载 10.8 命令行工具。

+   下载完成后，打开`DMG`文件，并按照说明进行安装。

# 在 OS X 上安装 Git

在 Mac 上安装 Git 与在 Windows 上安装 Git 基本相似。不同之处在于，我们有`dmg`文件而不是`.exe`文件，您可以从 Git 网站（`https://git-scm.com/download/mac`）下载进行安装：

1.  双击下载的`dmg`文件。它将打开一个包含以下文件的查找器：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00013.jpeg)

1.  双击`git-2.10.1-intel-universal-mavericks.dmg`文件；它将打开安装向导进行安装，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00014.jpeg)

1.  点击安装开始安装：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00015.jpeg)

1.  安装完成后，您将看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00016.jpeg)

如果您使用的是 OS X 10.8，并且尚未修改安全设置以允许安装第三方应用程序，则需要在 OS X 允许您安装这些工具之前进行调整。

# 安装和配置 Python

现在，让我们安装 Python，我们将使用它来构建我们的微服务。我们将在整本书中使用 Python 3.x 版本。

# 在基于 Debian 的发行版（如 Ubuntu）上安装 Python

在基于 Debian 的发行版上安装 Python 有不同的方法。

# 使用 APT 软件包管理工具

您可以使用 APT 软件包管理工具更新本地软件包索引。然后，您可以以 root 用户身份使用以下命令下载并安装最新的 Python：

```py
$ apt-get update -y
$ apt-get install python3 -y  

```

以下软件包将自动下载并安装，因为这些是 Python 3 安装的先决条件：

`libpython3-dev libpython3.4 libpython3.4-dev python3-chardet`

`python3-colorama python3-dev python3-distlib python3-html5lib`

`python3-requests python3-six python3-urllib3 python3-wheel python3.4-de`

一旦安装了先决条件，它将在您的系统上下载并安装 Python。

# 使用源代码

您可以从 GitHub 存储库下载源代码并从源代码编译软件，如下所示：

1.  在开始之前，让我们首先安装 Git 的依赖项；以 root 用户身份执行以下命令来完成：

```py
      $ apt-get update -y 
      $ apt-get install build-essential checkinstall libreadline-gplv2-
         dev libncursesw5-dev libssl-dev libsqlite3-dev tk-dev libgdbm-
         dev libc6-dev libbz2-dev -y   

```

1.  现在，让我们使用以下命令从 Python 的官方网站下载 Python（[`www.python.org`](https://www.python.org)）。您也可以根据需要下载最新版本：

```py
      $ cd /usr/local
      $ wget https://www.python.org/ftp/python/3.4.6/Python-3.4.6.tgz  

```

1.  现在，让我们使用以下命令提取已下载的软件包：

```py
      $ tar xzf Python-3.4.6.tgz  

```

1.  现在我们必须编译源代码。使用以下一组命令来完成：

```py
      $ cd python-3.4.6
      $ sudo ./configure
      $ sudo make altinstall  

```

1.  上述命令将在`/usr/local`上安装 Python。使用以下命令检查 Python 版本：

```py
      $ python3 -V 
        Python 3.4.6

```

# 在 Windows 上安装 Python

现在，让我们看看如何在 Windows 7 或更高版本系统上安装 Python。在 Windows 上安装 Python 非常简单快捷；我们将使用 Python 3 及以上版本，您可以从 Python 的下载页面([`www.python.org/downloads/windows/`](https://www.python.org/downloads/windows/))下载。现在执行以下步骤：

1.  根据您的系统配置下载 Windows x86-64 可执行安装程序，并打开它开始安装，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00017.jpeg)

1.  接下来，选择要进行的安装类型。我们将点击“立即安装”以进行默认安装，如此截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00018.jpeg)

1.  安装完成后，将看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00019.jpeg)

太棒了！我们已成功在 Windows 上安装了 Python。

# 在 Mac 上安装 Python

在开始 Python 安装之前，我们需要安装 OS X 的命令行工具。如果您在安装 Git 时已经安装了命令行工具，可以忽略此步骤。

# 在 OS X 上安装命令行工具

为了安装任何开发人员，您需要安装 Xcode ([`developer.apple.com/xcode/`](https://developer.apple.com/xcode/))；您需要在`connect.apple.com`上设置一个帐户以下载相应的 Xcode 版本工具。

然而，还有另一种方法可以使用一个实用程序安装命令行工具，该实用程序随 Xcode 一起提供，名为`xcode-select`，如下所示：

```py
% xcode-select --install  

```

上述命令应触发命令行工具的安装向导。按照安装向导的指示，您将能够成功安装它。

# 在 OS X 上安装 Python

在 Mac 上安装 Python 与在 Windows 上安装 Git 非常相似。您可以从官方网站([`www.python.org/downloads/`](https://www.python.org/downloads/))下载 Python 包。按照以下步骤进行：

1.  Python 包下载完成后，双击开始安装；将显示以下弹出窗口：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00020.jpeg)

1.  接下来的步骤将涉及发布说明和相应的 Python 版本信息：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00021.jpeg)

1.  接下来，您需要同意许可协议，这是安装的必要步骤：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00022.jpeg)

1.  接下来，它将显示安装相关信息，如磁盘占用和路径。点击“安装”开始：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00023.jpeg)

1.  安装完成后，您将看到以下屏幕：![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00024.jpeg)

1.  使用以下命令查看 Python 版本是否已安装：

```py
      % python3 -V  
        Python 3.5.3 

```

太棒了！Python 已成功安装。

# 熟悉 GitHub 和 Git 命令

在本节中，我们将介绍一系列我们将在整本书中经常使用的 Git 命令：

+   **git init**：此命令在首次设置本地存储库时初始化您的本地存储库

+   **git remote add origin <server>**：此命令将您的本地目录链接到远程服务器存储库，以便所有推送的更改都保存在远程存储库中

+   **git status**：此命令列出尚未添加或已修改并需要提交的文件/目录

+   **git add *或 git add <filename>**：此命令添加文件/目录，以便可以跟踪它们，并使它们准备好提交

+   **git commit -m "Commit message"**：此命令可帮助您在本地机器上提交跟踪更改，并生成提交 ID，通过该 ID 可以识别更新的代码

+   **git commit -am "Commit message"**：与上一个命令的唯一区别是，此命令在将所有文件添加到暂存区后，会打开默认编辑器，以根据 Ubuntu（Vim）或 Windows（Notepad++）等操作系统添加提交消息。

+   **git push origin master**：此命令将最后提交的代码从本地目录推送到远程存储库

测试一切，确保我们的环境正常工作。

我们已经在上一节中安装了 Git 和 Python，这些是构建微服务所需的。在本节中，我们将专注于测试已安装的软件包，并尝试熟悉它们。

我们可以做的第一件事是运行 Git 命令，该命令从存储库（通常是 GitHub）上的 HTTPs 获取外部 Python 代码，并将其复制到当前工作空间的适当目录中：

```py
$ git clone https://github.com/PacktPublishing/Cloud-Native-
 Python.git

```

上述命令将在本地机器上创建一个名为`Cloud-Native-Python`的目录；从当前位置切换到`Cloud-Native-Python/chapter1`路径**。**

我们需要安装应用程序的要求，以便运行它。在这种情况下，我们只需要 Flask 模块可用：

```py
$ cd hello.py
$ pip install requirements.txt

```

在这里，Flask 充当 Web 服务器；我们将在下一章中详细了解它。

安装成功后，您可以使用以下命令运行应用程序：

```py
$ python hello.py
* Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)  

```

我认为我们可以看到输出，如下所示：

```py
$ curl http://0.0.0.0:5000/
Hello World!  

```

如果您看到此输出，则我们的 Python 开发环境已正确设置。

现在是时候编写一些 Python 代码了！

# 摘要

在本章中，我们开始探索云平台和云计算堆栈。在本章中，您了解了不同的十二要素应用程序方法论，以及它们如何帮助开发微服务。最后，您了解了开发人员应该具备怎样的理想设置环境，以便创建或开始应用程序的创建。

在下一章中，我们将通过创建后端 REST API 并使用 API 调用或 Python 框架进行测试来开始构建我们的微服务。


# 第二章：使用 Python 构建微服务

现在，既然您了解了微服务是什么，并且希望您对它们的关键优势有所了解，我相信您迫不及待地想要开始构建它们。在本章中，我们将立即开始编写 REST API，这些 API 共同作为微服务工作。

本章我们将涵盖以下主题：

+   构建 REST API

+   测试 API

# Python 概念

让我们首先了解一些 Python 的概念，这些概念将在本书中使用。

# 模块

模块基本上允许您逻辑地组织您的编程代码。它类似于任何其他 Python 程序。在需要仅导入少量代码而不是整个程序的情况下，我们需要它们。**模块**可以是一个或多个函数类的组合，以及其他许多内容。我们将使用一些内置函数，它们是 Python 库的一部分。此外，我们将根据需要创建自己的模块。

以下示例代码展示了模块的结构：

```py
    #myprogram.py 
    ### EXAMPLE PYTHON MODULE
    # Define some variables:
    numberone = 1
    age = 78

    # define some functions
    def printhello():
     print "hello"

    def timesfour(input):
     print input * 4

    # define a class
    class house:
     def __init__(self):
         self.type = raw_input("What type of house? ")
         self.height = raw_input("What height (in feet)? ")
         self.price = raw_input("How much did it cost? ")
         self.age = raw_input("How old is it (in years)? ")

     def print_details(self):
         print "This house is a/an " + self.height + " foot",
         print self.type, "house, " + self.age, "years old and costing\
         " + self.price + " dollars." 

```

您可以使用以下命令导入前面的模块：

```py
# import myprogram

```

# 函数

函数是一块组织良好的、自包含的程序块，执行特定任务，您可以将其合并到自己的更大的程序中。它们的定义如下：

```py
    # function 
    def  functionname(): 
      do something 
      return 

```

以下是需要记住的几点：

+   缩进在 Python 程序中非常重要

+   默认情况下，参数具有位置行为，您需要按照它们在定义时的顺序进行通知

请参阅以下代码片段示例，其中展示了函数：

```py
    def display ( name ): 
    #This prints a passed string into this function 
      print ("Hello" + name) 
      return;

```

您可以按以下方式调用前面的函数：

```py
    display("Manish") 
    display("Mohit") 

```

以下截图显示了前面的 `display` 函数的执行情况：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00025.jpeg)

请注意，如果您的系统上安装了多个 Python 版本，您需要使用 Python 3 而不是 Python，后者使用 Python 的默认版本（通常是 2.7.x）。

# 建模微服务

在本书中，我们将开发一个完整的独立工作的 Web 应用程序。

现在，既然我们对 Python 有了基本的了解，让我们开始对我们的微服务进行建模，并了解应用程序的工作流程。

以下图显示了微服务架构和应用程序工作流程：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00026.jpeg)

# 构建微服务

在本书中，我们将使用 Flask 作为构建微服务的 Web 框架。**Flask** 是一个强大的 Web 框架，易于学习和简单易用。此外，在 Flask 中，我们需要一些样板代码来启动一个简单的应用程序。

由于我们将使用十二要素应用程序概念创建我们的应用程序，因此我们将首先确保我们有一个集中的代码库。到目前为止，您应该知道如何创建 GitHub 存储库。如果不知道，请确保按照第一章中提供的博客文章链接创建它，*介绍云原生架构和微服务*。我们将定期将代码推送到存储库。

假设您在本书的过程中已创建了存储库，我们将使用 GitHub 存储库 ([`github.com/PacktPublishing/Cloud-Native-Python.git`](https://github.com/PacktPublishing/Cloud-Native-Python.git))。

因此，让我们将本地目录与远程存储库同步。确保我们在 app 目录中，使用以下命令：

```py
$ mkdir Cloud-Native-Python  # Creating the directory
$ cd Cloud-Native-Python  # Changing the path to working directory
$ git init . # Initialising the local directory
$ echo "Cloud-Native-Python" > README.md  # Adding description of repository
$ git add README.md  # Adding README.md
$ git commit -am "Initial commit"  # Committing the changes
$ git remote add origin https://github.com/PacktPublishing/Cloud-Native-Python.git  # Adding to local repository
$ git push -u origin master  # Pushing changes to remote repository.

```

您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00027.jpeg)

我们已成功将第一个提交推送到远程存储库；我们将以类似的方式继续这样做，直到我们在构建微服务和应用程序方面达到一定的里程碑。

现在，我们需要安装一个基于文件的数据库，例如 SQLite 版本 3，它将作为我们微服务的数据存储。

要安装 SQLite 3，请使用以下命令：

```py
$ apt-get install sqlite3 libsqlite3-dev -y

```

现在，我们可以创建并使用（源）`virtualenv` 环境，它将使本地应用程序的环境与全局 `site-packages` 安装隔离开来。如果未安装 `virtualenv`，可以使用以下命令进行安装：

```py
$ pip install virtualenv

```

现在按如下方式创建`virtualenv`：

```py
$ virtualenv env --no-site-packages --python=python3
$ source env/bin/activate

```

我们应该看到上述命令的输出，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00028.jpeg)

在`virtualenv`设置之后，当前，我们的`virtualenv`环境中需要安装一个依赖项。使用以下命令将一个包依赖项添加到`requirements.txt`中：

```py
$ echo "Flask==0.10.1" >>  requirements.txt

```

将来，如果应用程序需要更多依赖项，它们将放在`requirements.txt`文件中。

让我们使用要求文件将依赖项安装到`virtualenv`环境中，如下所示：

```py
$ pip install -r requirements.txt

```

现在我们已经安装了依赖项，让我们创建一个名为`app.py`的文件，其中包含以下内容：

```py
    from flask import Flask 

    app = Flask(__name__) 

    if __name__ == "__main__": 
     app.run(host='0.0.0.0', port=5000, debug=True) 

```

上述代码是使用 Flask 运行应用程序的基本结构。它基本上初始化了`Flask`变量，并在端口`5000`上运行，可以从任何地方（`0.0.0.0`）访问。

现在，让我们测试上述代码，并查看一切是否正常工作。

执行以下命令来运行应用程序：

```py
$ python app.py

```

我们应该看到上述命令的输出，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00029.jpeg)

此时，在我们开始构建 RESTful API 之前，我们需要决定我们的根 URL 是什么，以访问服务，这将进一步决定不同方法的子 URI。考虑以下示例：

`http://[hostname]/api/v1/`。

由于在我们的情况下，我们将使用本地机器，`hostname`可以是带有端口的`localhost`，默认情况下，对于 Flask 应用程序，端口为`5000`。因此，我们的根 URL 将如下所示：

`http://localhost:5000/api/v1/`。

现在，让我们决定对哪些资源执行不同的操作，并且这些资源将由此服务公开。在这种情况下，我们将创建两个资源：用户和推文。

我们的用户和信息资源将使用以下 HTTP 方法：

| **HTTP 方法** | **URI** | **操作** |
| --- | --- | --- |
| `GET` | `http://localhost:5000/api/v1/info` | 这将返回版本信息 |
| `GET` | `http://localhost:5000/api/v1/users` | 这将返回用户列表 |
| `GET` | `http://localhost:5000/api/v1/users/[user_id]` | 响应将是指定`user_id`的用户详细信息 |
| `POST` | `http://localhost:5000/api/v1/users` | 此资源将在后端服务器中创建新用户，并使用传递的对象的值 |
| `DELETE` | `http://localhost:5000/api/v1/users` | 此资源将删除以 JSON 格式传递的指定用户名的用户 |
| `PUT` | `http://localhost:5000/api/v1/users/[user_id]` | 此资源将根据 API 调用的一部分传递的 JSON 对象更新特定`user_id`的用户信息。 |

使用客户端，我们将对资源执行操作，如`add`，`remove`，`modify`等等。

在本章的范围内，我们将采用基于文件的数据库，如 SQLite 3，我们之前已经安装过。

让我们去创建我们的第一个资源，即`/api/v1/info`，并显示可用版本及其发布详细信息。

在此之前，我们需要创建一个`apirelease`表模式，如 SQLite 3 中定义的，其中将包含有关 API 版本发布的信息。可以按如下方式完成：

```py
CREATE TABLE apirelease(
buildtime date,
version varchar(30) primary key,
links varchar2(30), methods varchar2(30));

```

创建后，您可以使用以下命令将记录添加到 SQLite 3 中的第一个版本（`v1`）：

```py
Insert into apirelease values ('2017-01-01 10:00:00', "v1", "/api/v1/users", "get, post, put, delete");

```

让我们在`app.py`中定义路由`/api/v1/info`和函数，它将基本上处理`/api/v1/info`路由上的 RESTful 调用。这样做如下：

```py
    from flask import jsonify 
    import json 
    import sqlite3 
    @app.route("/api/v1/info") 
    def home_index(): 
      conn = sqlite3.connect('mydb.db') 
      print ("Opened database successfully"); 
      api_list=[] 
      cursor = conn.execute("SELECT buildtime, version,
      methods, links   from apirelease") 
    for row in cursor: 
        a_dict = {} 
        a_dict['version'] = row[0] 
        a_dict['buildtime'] = row[1] 
        a_dict['methods'] = row[2] 
        a_dict['links'] = row[3] 
        api_list.append(a_dict) 
    conn.close() 
    return jsonify({'api_version': api_list}), 200 

```

现在我们已经添加了一个路由和其处理程序，让我们在`http://localhost:5000/api/v1/info`上进行 RESTful 调用，如此截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00030.jpeg)

太棒了！它有效了！

让我们继续讨论`/api/v1/users`资源，它将帮助我们对用户记录执行各种操作。

我们可以将用户定义为具有以下字段：

+   `id`：这是用户的唯一标识符（数字类型）

+   `username`：这是用户的唯一标识符或`handler`，用于身份验证（字符串类型）

+   `emailid`：这是用户的电子邮件（字符串类型）

+   `password`：这是用户的密码（字符串类型）

+   `full_name`：这是用户的全名（字符串类型）

为了在 SQLite 中创建用户表模式，请使用以下命令：

```py
CREATE TABLE users( 
username varchar2(30), 
emailid varchar2(30), 
password varchar2(30), full_name varchar(30), 
id integer primary key autoincrement); 

```

# 构建资源用户方法

让我们为用户资源定义我们的`GET`方法。

# GET /api/v1/users

`GET/api/v1/users`方法显示所有用户的列表。

```py
app.py:
```

```py
    @app.route('/api/v1/users', methods=['GET']) 
    def get_users(): 
      return list_users() 

```

现在我们已经添加了路由，我们需要定义`list_users()`函数，它将连接数据库以获取完整的用户列表。将以下代码添加到`app.py`中：

```py
    def list_users():
    conn = sqlite3.connect('mydb.db')
    print ("Opened database successfully");
    api_list=[]
    cursor = conn.execute("SELECT username, full_name,
    email, password, id from users")
    for row in cursor:
    a_dict = {}
    a_dict['username'] = row[0]
    a_dict['name'] = row[1]
    a_dict['email'] = row[2]
    a_dict['password'] = row[3]
    a_dict['id'] = row[4]
    api_list.append(a_dict)
    conn.close()
      return jsonify({'user_list': api_list}) 

```

现在我们已经添加了路由和处理程序，让我们测试`http://localhost:5000/api/v1/users` URL，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00031.jpeg)

# GET /api/v1/users/[user_id]

`GET/api/v1/users/[user_id]`方法显示由`user_id`定义的用户详细信息。

让我们创建一个将`GET`请求前置到`app.py`文件中的路由，如下所示：

```py
   @app.route('/api/v1/users/<int:user_id>', methods=['GET']) 
   def get_user(user_id): 
     return list_user(user_id) 

```

如您在上面的代码中所看到的，我们将`list_user(user_id)`路由调用到`list_user(user)`函数中，但`app.py`中尚未定义。让我们定义它以获取指定用户的详细信息，如下所示，在`app.py`文件中：

```py
    def list_user(user_id): 
      conn = sqlite3.connect('mydb.db') 
      print ("Opened database successfully"); 
      api_list=[] 
      cursor=conn.cursor() 
      cursor.execute("SELECT * from users where id=?",(user_id,)) 
      data = cursor.fetchall() 
      if len(data) != 0: 
         user = {} 
               user['username'] = data[0][0] 
         user['name'] = data[0][1] 
         user['email'] = data[0][2] 
         user['password'] = data[0][3] 
         user['id'] = data[0][4] 
            conn.close() 
            return jsonify(a_dict) 

```

现在我们已经添加了`list_user(user_id)`函数，让我们测试一下，看看是否一切正常：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00032.jpeg)

糟糕！看来 ID 不存在；通常，如果 ID 不存在，Flask 应用程序会以`404`错误的 HTML 消息作出响应。由于这是一个 Web 服务应用程序，并且我们正在为其他 API 获取 JSON 响应，因此我们需要为`404`错误编写`handler`，以便即使对于错误，它也应该以 JSON 形式而不是 HTML 响应进行响应。例如，查看以下代码以处理`404`错误。现在，服务器将以代码的一部分作出适当的响应消息，如下所示：

```py
    from flask import make_response 

    @app.errorhandler(404) 
    def resource_not_found(error): 
      return make_response(jsonify({'error':
      'Resource not found!'}),  404) 

```

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00033.jpeg)

此外，您可以从 Flask 中添加`abort`库，这基本上是用于调用异常。同样，您可以为不同的 HTTP 错误代码创建多个错误处理程序。

现在我们的`GET`方法运行良好，我们将继续编写`POST`方法，这类似于将新用户添加到用户列表中。

有两种方法可以将数据传递到`POST`方法中，如下所示：

+   **JSON**：在这种方法中，我们将 JSON 记录作为请求的一部分以对象的形式传递。RESTful API 调用将如下所示：

```py
curl -i -H "Content-Type: application/json" -X POST -d {"field1":"value"} resource_url 

```

+   **参数化**：在这种方法中，我们将记录的值作为参数传递，如下所示：

```py
curl -i -H "Content-Type: application/json" -X POST resource_url?field1=val1&field2=val2 

```

在 JSON 方法中，我们以`json`的形式提供输入数据，并以相同的方式读取它。另一方面，在参数化方法中，我们以 URL 参数的形式提供输入数据（即`username`等），并以相同的方式读取数据。

还要注意，后端的 API 创建将根据所进行的 API 调用类型而有所不同。

# POST /api/v1/users

在本书中，我们采用了`POST`方法的第一种方法。因此，让我们在`app.py`中定义`post`方法的路由，并调用函数将用户记录更新到数据库文件，如下所示：

```py
    @app.route('/api/v1/users', methods=['POST']) 
    def create_user(): 
      if not request.json or not 'username' in request.json or not
      'email' in request.json or not 'password' in request.json: 
        abort(400) 
     user = { 
        'username': request.json['username'], 
        'email': request.json['email'], 
        'name': request.json.get('name',""), 
        'password': request.json['password'] 
     } 
      return jsonify({'status': add_user(user)}), 201 

```

在上面的方法中，我们使用错误代码`400`调用了异常；现在让我们编写它的处理程序：

```py
    @app.errorhandler(400) 
    def invalid_request(error): 
       return make_response(jsonify({'error': 'Bad Request'}), 400) 

```

我们仍然需要定义`add_user(user)`函数，它将更新新的用户记录。让我们在`app.py`中定义它，如下所示：

```py
    def add_user(new_user): 
     conn = sqlite3.connect('mydb.db') 
     print ("Opened database successfully"); 
     api_list=[] 
     cursor=conn.cursor() 
     cursor.execute("SELECT * from users where username=? or
      emailid=?",(new_user['username'],new_user['email'])) 
    data = cursor.fetchall() 
    if len(data) != 0: 
        abort(409) 
    else: 
       cursor.execute("insert into users (username, emailid, password,
   full_name) values(?,?,?,?)",(new_user['username'],new_user['email'],
    new_user['password'], new_user['name'])) 
       conn.commit() 
       return "Success" 
    conn.close() 
    return jsonify(a_dict) 

```

现在我们已经添加了`handler`，以及用户的`POST`方法的路由，让我们通过以下 API 调用来测试添加新用户：

```py
curl -i -H "Content-Type: application/json" -X POST -d '{
"username":"mahesh@rocks", "email": "mahesh99@gmail.com",
"password": "mahesh123", "name":"Mahesh" }' 
http://localhost:5000/api/v1/users

```

然后，验证用户列表的 curl，`http://localhost:5000/api/v1/users`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00034.jpeg)

# DELETE /api/v1/users

`delete`方法帮助删除特定记录，该记录由用户名定义。我们将以 JSON 对象形式传递需要从数据库中删除的`username`。

```py
app.py for the DELETE method for users:
```

```py
    @app.route('/api/v1/users', methods=['DELETE']) 
    def delete_user(): 
     if not request.json or not 'username' in request.json: 
        abort(400) 
     user=request.json['username'] 
      return jsonify({'status': del_user(user)}), 200 

del_user, which deletes the user record specified by username after validating whether it exists or not:
```

```py
    def del_user(del_user): 
      conn = sqlite3.connect('mydb.db') 
      print ("Opened database successfully"); 
      cursor=conn.cursor() 
      cursor.execute("SELECT * from users where username=? ",
      (del_user,)) 
      data = cursor.fetchall() 
      print ("Data" ,data) 
      if len(data) == 0: 
        abort(404) 
      else: 
       cursor.execute("delete from users where username==?",
       (del_user,)) 
       conn.commit() 
         return "Success" 

```

太棒了！我们已经为用户资源的`DELETE`方法添加了路由`/handler`；让我们使用以下`test`API 调用来测试它：

```py
    curl -i -H "Content-Type: application/json" -X delete -d '{ 
"username":"manish123" }' http://localhost:5000/api/v1/users

```

然后，访问用户列表 API（`curl http://localhost:5000/api/v1/users`）以查看是否已进行更改：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00035.jpeg)

太棒了！用户删除成功。

# PUT /api/v1/users

PUT API 基本上帮助我们更新由`user_id`指定的用户记录。

继续并创建一个使用`PUT`方法更新`app.py`文件中定义的`user`记录的路由，如下所示：

```py
    @app.route('/api/v1/users/<int:user_id>', methods=['PUT']) 
    def update_user(user_id): 
     user = {} 
     if not request.json: 
         abort(400) 
     user['id']=user_id 
     key_list = request.json.keys() 
     for i in key_list: 
        user[i] = request.json[i] 
     print (user) 
     return jsonify({'status': upd_user(user)}), 200 

```

让我们指定`upd_user(user)`函数的定义，它基本上会更新数据库中的信息，并检查用户`id`是否存在：

```py
    def upd_user(user): 
      conn = sqlite3.connect('mydb.db') 
      print ("Opened database successfully"); 
      cursor=conn.cursor() 
      cursor.execute("SELECT * from users where id=? ",(user['id'],)) 
      data = cursor.fetchall() 
      print (data) 
      if len(data) == 0: 
        abort(404) 
      else: 
        key_list=user.keys() 
        for i in key_list: 
            if i != "id": 
                print (user, i) 
                # cursor.execute("UPDATE users set {0}=? where id=? ",
                 (i, user[i], user['id'])) 
                cursor.execute("""UPDATE users SET {0} = ? WHERE id =
                ?""".format(i), (user[i], user['id'])) 
                conn.commit() 
        return "Success" 

```

现在我们已经为用户资源添加了`PUT`方法的 API 句柄，让我们按照以下方式进行测试：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00036.jpeg)

我们已经定义了我们的资源，这是版本`v1`的一部分。 现在，让我们定义我们的下一个版本发布，`v2`，它将向我们的微服务添加一个推文资源。 在用户资源中定义的用户被允许对其推文执行操作。 现在，`/api/info`将显示如下：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00037.jpeg)

我们的推文资源将使用以下`HTTP`方法：

| **HTTP 方法** | **URI** | **操作** |
| --- | --- | --- |
| `GET` | `http://localhost:5000/api/v2/tweets` | 这将检索推文列表 |
| `GET` | `http://localhost:5000/api/v2/users/[user_id]` | 这将检索给定特定 ID 的推文 |
| `POST` | `http://localhost:5000/api/v2/tweets` | 此资源将使用作为 API 调用的一部分传递的 JSON 数据在后端数据库中注册新推文 |

我们可以将推文定义为具有以下字段：

+   `id`：这是每条推文的唯一标识符（数字类型）

+   `username`：这应该作为用户存在于用户资源中（字符串类型）

+   `body`：这是推文的内容（字符串类型）

+   `Tweet_time`：（指定类型）

您可以在 SQLite 3 中定义前面的推文资源模式如下：

```py
CREATE TABLE tweets( 
id integer primary key autoincrement, 
username varchar2(30), 
body varchar2(30), 
tweet_time date); 

```

太棒了！推文资源模式已准备就绪； 让我们为推文资源创建我们的`GET`方法。

# 构建资源推文方法

在本节中，我们将使用不同的方法为推文资源创建 API，这将帮助我们在后端数据库上执行不同的操作。

# GET /api/v2/tweets

此方法列出所有用户的所有推文。

将以下代码添加到`app.py`中以添加`GET`方法的路由：

```py
    @app.route('/api/v2/tweets', methods=['GET']) 
    def get_tweets(): 
      return list_tweets() 
    Let's define list_tweets() function which connects to database and
    get us all the tweets and respond back with tweets list 

   def list_tweets(): 
     conn = sqlite3.connect('mydb.db') 
     print ("Opened database successfully"); 
     api_list=[] 
     cursor = conn.execute("SELECT username, body, tweet_time, id from 
     tweets") 
    data = cursor.fetchall() 
    if data != 0: 
        for row in cursor: 
            tweets = {} 
            tweets['Tweet By'] = row[0] 
            tweets['Body'] = row[1] 
            tweets['Timestamp'] = row[2] 
    tweets['id'] = row[3] 
            api_list.append(tweets) 
    else: 
        return api_list 
    conn.close() 
    return jsonify({'tweets_list': api_list}) 

```

因此，现在我们已经添加了获取完整推文列表的功能，让我们通过以下 RESTful API 调用测试前面的代码：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00038.jpeg)

目前，我们还没有添加任何推文，这就是为什么它返回了空集。 让我们添加一些推文。

# POST /api/v2/tweets

POST 方法通过指定的用户添加新推文。

将以下代码添加到`app.py`中，以添加`POST`方法的路由到推文资源：

```py
    @app.route('/api/v2/tweets', methods=['POST']) 
    def add_tweets(): 
      user_tweet = {} 
      if not request.json or not 'username' in request.json or not 
     'body' in request.json: 
        abort(400) 
    user_tweet['username'] = request.json['username'] 
    user_tweet['body'] = request.json['body'] 
    user_tweet['created_at']=strftime("%Y-%m-%dT%H:%M:%SZ", gmtime()) 
    print (user_tweet) 
    return  jsonify({'status': add_tweet(user_tweet)}), 200 

```

让我们添加`add_tweet(user_tweet)`的定义，以通过指定的用户添加推文，如下所示：

```py
    def add_tweet(new_tweets): 
      conn = sqlite3.connect('mydb.db') 
      print ("Opened database successfully"); 
      cursor=conn.cursor() 
      cursor.execute("SELECT * from users where username=? ",
   (new_tweets['username'],)) 
    data = cursor.fetchall() 

    if len(data) == 0: 
        abort(404) 
    else: 
       cursor.execute("INSERT into tweets (username, body, tweet_time)
    values(?,?,?)",(new_tweets['username'],new_tweets['body'], 
    new_tweets['created_at'])) 
       conn.commit() 
       return "Success" 

```

因此，现在我们已经添加了将推文列表添加到数据库的功能，让我们通过以下 RESTful API 调用测试前面的代码：

```py
curl -i -H "Content-Type: application/json" -X POST -d '{
"username":"mahesh@rocks","body": "It works" }' 
http://localhost:5000/api/v2/tweets  

```

我们应该看到前面的 API 调用的输出与以下截图类似：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00039.jpeg)

让我们通过检查推文的状态来检查推文是否成功添加：

```py
curl http://localhost:5000/api/v2/tweets -v

```

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00040.jpeg)

现在我们已经添加了我们的第一条推文，如果我们需要只看到特定 ID 的推文怎么办？在这种情况下，我们使用`GET`方法和`user_id`。

# GET /api/v2/tweets/[id]

`GET`方法列出由指定 ID 制作的推文。

将以下代码添加到`app.py`中，以添加具有指定 ID 的`GET`方法的路由：

```py
    @app.route('/api/v2/tweets/<int:id>', methods=['GET']) 
    def get_tweet(id): 
      return list_tweet(id) 

```

让我们定义`list_tweet()`函数，它连接到数据库，获取具有指定 ID 的推文，并以 JSON 数据响应。 这样做如下：

```py
     def list_tweet(user_id): 
       print (user_id) 
       conn = sqlite3.connect('mydb.db') 
       print ("Opened database successfully"); 
       api_list=[] 
      cursor=conn.cursor() 
      cursor.execute("SELECT * from tweets  where id=?",(user_id,)) 
      data = cursor.fetchall() 
      print (data) 
      if len(data) == 0: 
        abort(404) 
     else: 

        user = {} 
        user['id'] = data[0][0] 
        user['username'] = data[0][1] 
        user['body'] = data[0][2] 
        user['tweet_time'] = data[0][3] 

    conn.close() 
    return jsonify(user) 

```

现在我们已经添加了获取具有指定 ID 的推文的功能，让我们通过在以下位置进行 RESTful API 调用来测试前面的代码：

```py
curl http://localhost:5000/api/v2/tweets/2

```

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00041.jpeg)

通过这些推文的添加，我们成功地构建了 RESTful API，它作为访问数据和执行各种操作所需的微服务共同工作。

# 测试 RESTful API

到目前为止，我们一直在构建 RESTful API 并访问根 URL 以查看响应，并了解不同的方法是否在后端正常工作。由于这是新代码，应该对所有内容进行 100%的测试，以确保它在生产环境中正常工作。在本节中，我们将编写测试用例，这些测试用例应该单独工作，也应该作为一个系统工作，以确保完整的后端服务可以投入生产。

有不同类型的测试，定义如下：

+   **功能测试**：基本上用于测试组件或系统的功能。我们根据组件的功能规范进行此测试。

+   **非功能测试**：这种测试针对组件的质量特征进行，包括效率测试、可靠性测试等。

+   **结构测试**：这种类型的测试用于测试系统的结构。为了编写测试用例，测试人员需要了解代码的内部实现。

在本节中，我们将编写测试用例，特别是单元测试用例，针对我们的应用程序。我们将编写 Python 代码，它将自动运行，测试所有 API 调用，并以测试结果做出响应。

# 单元测试

单元测试是测试工作单元或被测试系统中的逻辑单元的代码片段。以下是单元测试用例的特点：

+   **自动化**：它们应该自动执行

+   **独立**：它们不应该有任何依赖关系

+   一致和可重复：它们应该保持幂等性

+   **可维护**：它们应该足够容易理解和更新

我们将使用一个名为**nose**的单元测试框架。作为替代，我们可以使用 docstest（`https://docs.python.org/2/library/doctest.html`）进行测试。

因此，让我们使用以下命令使用`pip`安装 nose：

```py
$ pip install nose 

```

或者，您可以将其放在`requirement.txt`中，并使用以下命令进行安装：

```py
$ pip install -r requirements.txt

```

现在我们已经安装了 nose 测试框架，让我们开始在一个单独的文件上编写初始测试用例，比如`flask_test.py`，如下所示：

```py
    from app import app 
    import unittest 

   class FlaskappTests(unittest.TestCase): 
     def setUp(self): 
        # creates a test client 
        self.app = app.test_client() 
        # propagate the exceptions to the test client 
        self.app.testing = True 

```

上述代码将测试应用程序并使用我们的应用程序初始化`self.app`。

让我们编写我们的测试用例，以获取`GET` `/api/v1/users`的响应代码，并将其添加到我们的 FlaskappTest 类中，如下所示：

```py
    def test_users_status_code(self): 
        # sends HTTP GET request to the application 
        result = self.app.get('/api/v1/users') 
        # assert the status code of the response 
        self.assertEqual(result.status_code, 200) 

```

上述代码将测试我们是否在`/api/v1/users`上获得`200`的响应；如果没有，它将抛出错误，我们的测试将失败。正如你所看到的，由于这段代码没有任何来自其他代码的依赖，我们将其称为单元测试用例。

现在，如何运行这段代码？由于我们已经安装了 nose 测试框架，只需从测试用例文件的当前工作目录（在本例中为`flask_test.py`）中执行以下命令：

```py
$ nosetests

```

太棒了！同样，让我们为本章前面创建的资源的不同方法的 RESTful API 编写更多的测试用例。

+   GET `/api/v2/tweets`测试用例如下：

```py
    def test_tweets_status_code(self): 
        # sends HTTP GET request to the application 
        result = self.app.get('/api/v2/tweets') 
        # assert the status code of the response 
        self.assertEqual(result.status_code, 200) 

```

+   GET `/api/v1/info`测试用例如下：

```py
    def test_tweets_status_code(self): 
        # sends HTTP GET request to the application 
        result = self.app.get('/api/v1/info') 
        # assert the status code of the response 
        self.assertEqual(result.status_code, 200) 

```

+   POST `/api/v1/users`测试用例写成这样：

```py
    def test_addusers_status_code(self): 
        # sends HTTP POST request to the application 
        result = self.app.post('/api/v1/users', data='{"username":
   "manish21", "email":"manishtest@gmail.com", "password": "test123"}',
   content_type='application/json') 
        print (result) 
        # assert the status code of the response 
        self.assertEquals(result.status_code, 201) 

```

+   PUT `/api/v1/users`测试用例如下：

```py
    def test_updusers_status_code(self): 
        # sends HTTP PUT request to the application 
        # on the specified path 
        result = self.app.put('/api/v1/users/4', data='{"password": 
   "testing123"}', content_type='application/json') 
        # assert the status code of the response 
        self.assertEquals(result.status_code, 200) 

```

+   POST `/api/v1/tweets`测试用例如下：

```py
    def test_addtweets_status_code(self): 
        # sends HTTP GET request to the application 
        # on the specified path 
        result = self.app.post('/api/v2/tweets', data='{"username": 
   "mahesh@rocks", "body":"Wow! Is it working #testing"}', 
   content_type='application/json') 

        # assert the status code of the response 
        self.assertEqual(result.status_code, 201) 

```

+   DELETE `/api/v1/users`测试用例如下：

```py
    def test_delusers_status_code(self): 
        # sends HTTP Delete request to the application 
        result = self.app.delete('/api/v1/users', data='{"username": 
   "manish21"}', content_type='application/json') 
        # assert the status code of the response 
        self.assertEquals(result.status_code, 200) 

```

同样，您可以根据自己的想法编写更多的测试用例，使这些 RESTful API 更加可靠和无错。

让我们一起执行所有这些测试，并检查是否所有测试都已通过。以下屏幕截图显示了对`flask_test.py`脚本的测试结果：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00042.jpeg)

太棒了！现在我们所有的测试都已通过，我们可以继续创建围绕这些 RESTful API 的网页的下一个级别。

# 总结

在这一章中，我们专注于编写大量的代码来构建我们的微服务。我们基本上了解了 RESTful API 的工作原理。我们还看到了如何扩展这些 API，并确保我们理解这些 API 给出的`HTTP`响应。此外，您还学会了如何编写测试用例，这对于确保我们的代码能够正常运行并且适用于生产环境非常重要。


# 第三章：在 Python 中构建 Web 应用程序

在上一章中，我们专注于构建我们的微服务，即基本上是后端 RESTful API，并对其进行测试，以确保响应符合预期。到目前为止，我们一直在使用 curl 测试这些 RESTful API，或者使用测试框架，如 nose、unittest2 等。在本章中，我们将创建一些 HTML 页面，并编写一个 JavaScript REST 客户端，该客户端将与微服务进行交互。

本章中我们将涵盖的主题如下：

+   构建 HTML 页面和数据绑定

+   使用 knockout.js 的 JavaScript REST 客户端

在本章中，我们将创建一个客户端应用程序，该应用程序需要创建从 HTML 网页收集的动态内容，并根据用户的操作，将其作为对后端服务的响应进行更新。

作为开发人员，你一定遇到过许多采用 MVC 模式的应用程序框架。它是一个大类别，是**MVC**（**Model View Controller**）、**MVP**（**Model View Presenter**）和**MVVM**（**Model View ViewModel**）的组合。

在我们的案例中，我们将使用**knockout.js**，这是一个基于 MVVM 模式的 JavaScript 库，它帮助开发人员构建丰富和响应式的网站。它可以作为独立使用，也可以与其他 JavaScript 库一起使用，如 jQuery。Knockout.js 将 UI 与底层 JavaScript 模型绑定在一起。模型根据 UI 的更改而更新，反之亦然，这基本上是双向数据绑定。

在 knockout.js 中，我们将处理两个重要的概念：绑定和 Observables。

Knockout.js 是一个通常用于开发类似桌面的 Web 应用程序的 JavaScript 库。它非常有用，因为它提供了一种与数据源同步的响应机制。它在数据模型和用户界面之间提供了双向绑定机制。在[`knockoutjs.com/documentation/introduction.html`](http://knockoutjs.com/documentation/introduction.html)上阅读更多关于 knockout.js 的信息。

在本章中，我们将创建 Web 应用程序，以向数据库添加用户和推文，并对其进行验证。

# 开始使用应用程序

让我们开始创建一个基本的 HTML 模板。在应用程序根目录中创建一个名为`template`的目录；我们将在此目录中创建所有未来的模板。

现在，让我们按照以下方式为`adduser.html`文件创建基本骨架：

```py
    <!DOCTYPE html> 
    <html> 
      <head> 
        <title>Tweet Application</title> 
      </head> 
      <body> 
        <div class="navbar"> 
         <div class="navbar-inner"> 
           <a class="brand" href="#">Tweet App Demo</a> 
         </div> 
        </div> 
       <div id="main" class="container"> 

         Main content here! 

       </div> 
      <meta name="viewport" content="width=device-width, initial-
       scale=1.0"> 
      <link href="http://netdna.bootstrapcdn.com/twitter-
       bootstrap/2.3.2/css/bootstrap-combined.min.css"
       rel="stylesheet"> 
      <script src="img/jquery- 
       1.9.0.js"></script> 
      <script src="img/twitter-
        bootstrap/2.3.2/js/bootstrap.min.js"></script> 
      <script src="img/knockout-
        2.2.1.js"></script> 
      </body> 
    </html> 

```

如你所见，在前面的代码中，我们指定了一些`.js`脚本，这些脚本是需要的，以使我们的 HTML 具有响应性。这类似于 twitter-bootstrap，它有一个`<meta name="viewport">`属性，可以根据浏览器尺寸来缩放页面。

# 创建应用程序用户

在我们开始编写网页之前，我们需要创建一个用于创建用户的路由，如下所示：

```py
    from flask import render_template 

    @app.route('/adduser') 
    def adduser(): 
     return render_template('adduser.html') 

```

现在我们已经创建了路由，让我们在`adduser.html`中创建一个表单，该表单将要求用户提供与用户相关的必要信息，并帮助他们提交信息：

```py
    <html> 
      <head> 
        <title>Twitter Application</title> 
      </head> 
      <body> 
       <form > 
         <div class="navbar"> 
          <div class="navbar-inner"> 
            <a class="brand" href="#">Tweet App Demo</a> 
          </div> 
        </div> 
        <div id="main" class="container"> 

         <table class="table table-striped"> 
           Name: <input placeholder="Full Name of user" type "text"/> 
           </div> 
           <div> 
             Username: <input placeholder="Username" type="username">
             </input> 
           </div> 
           <div> 
             email: <input placeholder="Email id" type="email"></input> 
           </div> 
           <div> 
             password: <input type="password" placeholder="Password">  
             </input> 
           </div> 
            <button type="submit">Add User</button> 
          </table> 
        </form> 
       <script src="img/
        jquery/1.8.3/jquery.min.js"></script> 
      <script src="img/knockout
        /2.2.0/knockout-min.js"></script> 
      <link href="http://netdna.bootstrapcdn.com/twitter-
       bootstrap/2.3.2/css/bootstrap-combined.min.css"
       rel="stylesheet"> 
      <!-- <script src="img/jquery-
       1.9.0.js"></script> --> 
     <script src="img/twitter- 
       bootstrap/2.3.2/js/bootstrap.min.js"></script> 
    </body> 
   </html> 

```

目前，前面的 HTML 页面只显示空字段，如果尝试提交带有数据的表单，它将无法工作，因为尚未与后端服务进行数据绑定。

现在我们准备创建 JavaScript，它将向后端服务发出 REST 调用，并添加来自 HTML 页面提供的用户内容。

# 使用 Observables 和 AJAX

为了从 RESTful API 获取数据，我们将使用 AJAX。Observables 跟踪数据的更改，并自动在所有使用和由`ViewModel`定义的位置上反映这些更改。

通过使用 Observables，使 UI 和`ViewModel`动态通信变得非常容易。

让我们创建一个名为`app.js`的文件，在静态目录中声明了 Observables，代码如下——如果目录不存在，请创建它：

```py
    function User(data) { 
      this.id = ko.observable(data.id); 
      this.name = ko.observable(data.name); 
      this.username = ko.observable(data.username); 
      this.email = ko.observable(data.email); 
      this.password = ko.observable(data.password); 
    } 

    function UserListViewModel() { 
     var self = this; 
     self.user_list = ko.observableArray([]); 
     self.name = ko.observable(); 
     self.username= ko.observable(); 
     self.email= ko.observable(); 
     self.password= ko.observable(); 

     self.addUser = function() { 
      self.save(); 
      self.name(""); 
      self.username(""); 
      self.email(""); 
      self.password(""); 
     }; 
    self.save = function() { 
      return $.ajax({ 
      url: '/api/v1/users', 
      contentType: 'application/json', 
      type: 'POST', 
      data: JSON.stringify({ 
         'name': self.name(), 
         'username': self.username(), 
         'email': self.email(), 
         'password': self.password() 
      }), 
      success: function(data) { 
         alert("success") 
              console.log("Pushing to users array"); 
              self.push(new User({ name: data.name, username: 
              data.username,email: data.email ,password: 
               data.password})); 
              return; 
      }, 
      error: function() { 
         return console.log("Failed"); 
       } 
     }); 
    }; 
    } 

   ko.applyBindings(new UserListViewModel()); 

```

我知道这是很多代码；让我们了解前面代码的每个部分的用法。

当您在 HTML 页面上提交内容时，请求将在`app.js`接收，并且以下代码将处理请求：

```py
    ko.applyBindings(new UserListViewModel()); 

```

它创建模型并将内容发送到以下函数：

```py
    self.addUser = function() { 
      self.save(); 
      self.name(""); 
      self.username(""); 
      self.email(""); 
      self.password(""); 
   }; 

```

前面的`addUser`函数调用`self.save`函数，并传递数据对象。`save`函数通过 AJAX RESTful 调用后端服务，并执行从 HTML 页面收集的数据的`POST`操作。然后清除 HTML 页面的内容。

我们的工作还没有完成。正如我们之前提到的，这是双向数据绑定，因此我们需要从 HTML 端发送数据，以便在数据库中进一步处理。

在脚本部分中，添加以下行，它将识别`.js`文件路径：

```py
    <script src="img/{{ url_for('static', filename='app.js') }}"></script> 

```

# 为 adduser 模板绑定数据

数据绑定对将数据与 UI 绑定很有用。如果我们不使用 Observables，UI 中的属性只会在第一次处理时被处理。在这种情况下，它无法根据底层数据更新自动更新。为了实现这一点，绑定必须引用 Observable 属性。

现在我们需要将我们的数据与表单及其字段绑定，如下面的代码所示：

```py
    <form data-bind="submit: addUser"> 
     <div class="navbar"> 
       <div class="navbar-inner"> 
           <a class="brand" href="#">Tweet App Demo</a> 
       </div> 
     </div> 
     <div id="main" class="container"> 
      <table class="table table-striped"> 
       Name: <input data-bind="value: name" placeholder="Full Name of
       user" type "text"/> 
     </div> 
     <div> 
       Username: <input data-bind="value: username" 
       placeholder="Username" type="username"></input> 
     </div> 
    <div> 
      email: <input data-bind="value: email" placeholder="Email id" 
      type="email"></input> 
    </div> 
    <div> 
       password: <input data-bind="value: password" type="password" 
       placeholder="Password"></input> 
    </div> 
       <button type="submit">Add User</button> 
     </table> 
    </form> 

```

现在我们准备通过模板添加我们的用户。但是，我们如何验证用户是否成功添加到我们的数据库呢？一种方法是手动登录到数据库。但是，由于我们正在开发 Web 应用程序，让我们在网页上显示我们的数据（存在于数据库中）--甚至是新添加的条目。

为了读取数据库并获取用户列表，将以下代码添加到`app.js`中：

```py
    $.getJSON('/api/v1/users', function(userModels) { 
      var t = $.map(userModels.user_list, function(item) { 
        return new User(item); 
      }); 
     self.user_list(t); 
    }); 

```

现在我们需要在`adduser.html`中进行更改，以显示我们的用户列表。为此，让我们添加以下代码：

```py
    <ul data-bind="foreach: user_list, visible: user_list().length > 
    0"> 
      <li> 
        <p data-bind="text: name"></p> 
        <p data-bind="text: username"></p> 
        <p data-bind="text: email"></p> 
       <p data-bind="text: password"></p> 
     </li> 
    </ul> 

```

太棒了！我们已经完成了添加网页，它将为我们的应用程序创建新用户。它看起来会像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00043.jpeg)

# 从用户创建推文

在开始编写网页之前，我们需要创建一个用于创建推文的路由。可以按以下方式完成：

```py
    from flask import render_template 

    @app.route('/addtweets') 
    def addtweetjs(): 
     return render_template('addtweets.html') 

```

现在，我们已经创建了路由，让我们在`addtweets.html`中创建另一个表单，该表单将要求用户提供与推文相关的必需信息，并帮助他们提交信息：

```py
    <html> 
     <head> 
      <title>Twitter Application</title> 
     </head> 
    <body> 
    <form > 
     <div class="navbar"> 
       <div class="navbar-inner"> 
           <a class="brand" href="#">Tweet App Demo</a> 
       </div> 
      </div> 

      <div id="main" class="container"> 
       <table class="table table-striped"> 
         Username: <input placeholder="Username" type="username">
          </input> 
      </div> 
      <div> 
        body: <textarea placeholder="Content of tweet" type="text"> 
        </textarea> 
      </div> 
      <div> 
      </div> 
       <button type="submit">Add Tweet</button> 
      </table> 

     </form> 
      <script src="img/
       jquery/1.8.3/jquery.min.js"></script> 
      <script src="img/
        knockout/2.2.0/knockout-min.js"></script> 
       <link href="http://netdna.bootstrapcdn.com/twitter-
         bootstrap/2.3.2/css/bootstrap-combined.min.css" 
        rel="stylesheet"> 
      <!-- <script src="img/jquery-
        1.9.0.js"></script> --> 
      <script src="img/twitter-
        bootstrap/2.3.2/js/bootstrap.min.js"></script> 
     </body> 
    </html> 

```

请注意，当前此表单没有数据绑定以与 RESTful 服务通信。

# 使用 AJAX 处理 addtweet 模板的 Observables

让我们开发一个 JavaScript，它将对后端服务进行 REST 调用，并添加来自 HTML 页面的推文内容。

让我们在之前创建的静态目录中创建一个名为`tweet.js`的文件，并使用以下代码：

```py
    function Tweet(data) { 
      this.id = ko.observable(data.id); 
      this.username = ko.observable(data.tweetedby); 
      this.body = ko.observable(data.body); 
      this.timestamp = ko.observable(data.timestamp); 
    } 

    function TweetListViewModel() { 
      var self = this; 
      self.tweets_list = ko.observableArray([]); 
      self.username= ko.observable(); 
      self.body= ko.observable(); 

      self.addTweet = function() { 
      self.save(); 
      self.username(""); 
      self.body(""); 
       }; 

      $.getJSON('/api/v2/tweets', function(tweetModels) { 
      var t = $.map(tweetModels.tweets_list, function(item) { 
        return new Tweet(item); 
      }); 
      self.tweets_list(t); 
      }); 

     self.save = function() { 
      return $.ajax({ 
      url: '/api/v2/tweets', 
      contentType: 'application/json', 
      type: 'POST', 
      data: JSON.stringify({ 
         'username': self.username(), 
         'body': self.body(), 
      }), 
      success: function(data) { 
         alert("success") 
              console.log("Pushing to users array"); 
              self.push(new Tweet({ username: data.username,body: 
              data.body})); 
              return; 
      }, 
      error: function() { 
         return console.log("Failed"); 
      } 
     }); 
      }; 
    } 

   ko.applyBindings(new TweetListViewModel()); 

```

让我们了解最后一段代码的每个部分的用法。

当您在 HTML 页面上提交内容时，请求将发送到`tweet.js`，代码的以下部分将处理请求：

```py
    ko.applyBindings(new TweetListViewModel()); 

```

前面的代码片段创建模型并将内容发送到以下函数：

```py
    self.addTweet = function() { 
      self.save(); 
      self.username(""); 
      self.body(""); 
      }; 

```

前面的`addTweet`函数调用`self.save`函数，并传递数据对象。保存函数通过 AJAX RESTful 调用后端服务，并执行从 HTML 页面收集的数据的`POST`操作。然后清除 HTML 页面的内容。

为了在网页上显示数据，并使其与后端服务中的数据保持同步，需要以下代码：

```py
   function Tweet(data) { 
     this.id = ko.observable(data.id); 
     this.username = ko.observable(data.tweetedby); 
     this.body = ko.observable(data.body); 
     this.timestamp = ko.observable(data.timestamp); 
   } 

```

我们的工作还没有完成。正如我们之前提到的，这是双向数据绑定，因此我们还需要从 HTML 端发送数据，以便在数据库中进一步处理。

在脚本部分中，添加以下行，它将使用路径标识`.js`文件：

```py
   <script src="img/{{ url_for('static', filename='tweet.js') }}"></script> 

```

# 为 addtweet 模板绑定数据

完成后，我们现在需要将我们的数据与表单及其字段绑定，如下面的代码所示：

```py
    <form data-bind="submit: addTweet"> 
      <div class="navbar"> 
        <div class="navbar-inner"> 
           <a class="brand" href="#">Tweet App Demo</a> 
        </div> 
       </div> 
       <div id="main" class="container"> 

        <table class="table table-striped"> 
          Username: <input data-bind="value: username"
          placeholder="Username" type="username"></input> 
       </div> 
       <div> 
         body: <textarea data-bind="value: body" placeholder="Content
         of tweet" type="text"></textarea> 
       </div> 
       <div> 
       </div> 
       <button type="submit">Add Tweet</button> 
       </table> 
    </form> 

```

现在我们准备通过模板添加我们的推文。我们对推文进行验证，就像我们对用户进行验证一样。

为了读取数据库并获取推文列表，请将以下代码添加到`tweet.js`中：

```py
    $.getJSON('/api/v2/tweets', function(tweetModels) { 
      var t = $.map(tweetModels.tweets_list, function(item) { 
      return new Tweet(item); 
     }); 
      self.tweets_list(t); 
     }); 

```

现在，我们需要在`addtweets.html`中进行更改，以显示我们的推文列表。为此，让我们添加以下代码：

```py
    <ul data-bind="foreach: tweets_list, visible: tweets_list().length 
    > 0"> 
     <li> 
       <p data-bind="text: username"></p> 
       <p data-bind="text: body"></p> 
       <p data-bind="text: timestamp"></p> 

     </li> 
   </ul> 

```

太棒了！让我们来测试一下。它看起来会像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00044.jpeg)

以类似的方式，您可以通过从网页应用程序中删除用户或在后端服务中更新用户信息来扩展此用例。

此外，要了解更多关于 knockout.js 库的信息，请查看[`knockoutjs.com/examples/helloWorld.html`](http://knockoutjs.com/examples/helloWorld.html)上的实时示例，这将帮助您更好地理解，并帮助您在应用程序中实施它。

我们创建了这些网页，以确保我们的微服务工作，并让您了解通常如何开发 Web 应用程序；作为开发人员，我们也可以根据自己的用例创建这些 Web 应用程序。

# CORS - 跨源资源共享

CORS 有助于在 API 请求的 API 服务器和客户端之间维护数据完整性。

使用 CORS 的想法是，服务器和客户端应该彼此具有足够的信息，以便它们可以相互验证，并使用 HTTP 标头在安全通道上传输数据。

当客户端发出 API 调用时，它要么是 GET 请求，要么是 POST 请求，其中 body 通常是 text/plain，带有名为**Origin**的标头--这包括与请求页面相关的协议、域名和端口。当服务器确认请求并发送响应以及`Access-Control-Allow-Origin`标头到相同的 Origin 时，它确保响应被正确接收到相应的 Origin。

通过这种方式，在不同来源之间进行资源共享。

几乎所有浏览器现在都支持 CORS，包括 IE 8+、Firefox 3.5+和 Chrome。

现在，既然我们已经准备好了 Web 应用程序，但它还没有启用 CORS，让我们启用它。

首先，您需要使用以下命令在 Flask 中安装 CORS 模块：

```py
$pip install flask-cors

```

前面的包公开了一个 Flask 扩展，该扩展默认情况下在所有路由上为所有来源和方法启用 CORS 支持。安装了该包后，让我们在`app.py`中包含它，如下所示：

```py
    from flask_cors import CORS, cross_origin 

```

要启用 CORS，您需要添加以下行：

```py
   CORS(app) 

```

就是这样。现在，您的 Flask 应用程序中的所有资源都已启用 CORS。

如果您想在特定资源上启用 CORS，则添加以下代码与您的特定资源：

```py
   cors = CORS(app, resources={r"/api/*": {"origins": "*"}}) 

```

目前，我们还没有设置域，但我们正在本地主机级别工作。您可以通过在域名服务器中添加自定义域来测试 CORS，如下所示：

```py
   127.0.0.1    <your-domain-name> 

```

现在，如果您尝试访问此`<your-domain-name>`，它应该能够正常使用此域名，并且您将能够访问资源。

# 会话管理

会话是与单个用户关联的一系列请求和响应事务。会话通常是通过对用户进行身份验证并跟踪他/她在网页上的活动来在服务器级别上维护的。

每个客户端的会话都分配了一个会话 ID。会话通常存储在 cookie 之上，并且服务器使用秘钥对它们进行加密--Flask 应用程序使用临时持续时间的秘钥对其进行解密。

目前，我们还没有设置身份验证--我们将在第八章中定义它，*保护 Web 应用程序*。因此，在这个时间点上，我们将通过询问访问网页的用户名并确保用户使用会话标识来创建会话。

现在让我们创建一个名为`main.html`的网页，其中将包含一个 URL 来创建会话（如果需要设置），以及用于在后端服务上执行操作的路由。如果会话已经存在，您可以清除会话。请参阅以下代码：

```py
    <html> 
      <head> 
        <title>Twitter App Demo</title> 
        <link rel=stylesheet type=text/css href="{{ url_for('static', 
        filename='style.css') }}"> 
    </head> 
    <body> 
        <div id="container"> 
          <div class="title"> 
            <h1></h1> 
          </div> 
          <div id="content"> 
            {% if session['name'] %} 
            Your name seems to be <strong>{{session['name']}}</strong>.
           <br/> 
            {% else %} 
            Please set username by clicking it <a href="{{ 
            url_for('addname') }}">here</a>.<br/> 
            {% endif %} 
           Visit <a href="{{ url_for('adduser') }}">this for adding new 
           application user </a> or <a href="{{ url_for('addtweetjs') 
           }}">this to add new tweets</a> page to interact with RESTFUL
           API. 

           <br /><br /> 
           <strong><a href="{{ url_for('clearsession') }}">Clear 
           session</a></strong> 
            </div> 
            </div> 
        </div> 
       </body> 
    </html> 

```

当前在这个网页中，一些 URL，如`clearsession`和`addname`不会工作，因为我们还没有为它们设置网页和路由。

另外，我们还没有为`main.html`网页设置路由；让我们首先在`app.py`中添加它，如下所示：

```py
    @app.route('/') 

    def main(): 
      return render_template('main.html') 

```

由于我们已经为`main.html`设置了路由，让我们在`app.py`中为`addname`添加路由，如下所示：

```py
   @app.route('/addname') 

   def addname(): 
   if request.args.get('yourname'): 
    session['name'] = request.args.get('yourname') 
    # And then redirect the user to the main page 
      return redirect(url_for('main')) 

    else: 
      return render_template('addname.html', session=session) 

```

正如您在前面的路由中所看到的，它调用了`addname.html`，而我们还没有创建它。让我们使用以下代码创建`addname`模板：

```py
    <html> 
     <head> 
       <title>Twitter App Demo</title> 
       <link rel=stylesheet type=text/css href="{{ url_for('static', 
        filename='style.css') }}"> 
     </head> 
   <body> 
       <div id="container"> 
           <div class="title"> 
               <h1>Enter your name</h1> 
           </div> 
        <div id="content"> 
          <form method="get" action="{{ url_for('addname') }}"> 
            <label for="yourname">Please enter your name:</label> 
            <input type="text" name="yourname" /><br /> 
            <input type="submit" /> 
          </form> 
        </div> 
        <div class="title"> 
               <h1></h1> 
        </div> 
        <code><pre> 
        </pre></code> 
        </div> 
       </div> 
      </body> 
     </html> 

```

太棒了！现在我们可以使用前面的代码设置会话；您将看到一个类似于这样的网页：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00045.jpeg)

现在，如果我们需要清除会话怎么办？由于我们已经从主网页调用了`clearsession`函数，我们需要在`app.py`中创建一个路由，进一步调用会话的`Clear`内置函数，如下所示：

```py
    @app.route('/clear') 

     def clearsession(): 
      # Clear the session 
      session.clear() 
      # Redirect the user to the main page 
      return redirect(url_for('main')) 

```

这就是我们如何设置会话，为用户保持会话，并根据需要清除会话。

# Cookies

Cookies 类似于会话，除了它们以文本文件的形式保存在客户端计算机上；而会话则保存在服务器端。

它们的主要目的是跟踪客户端的使用情况，并根据他们的活动通过了解 cookies 来改善体验。

cookies 属性存储在响应对象中，它是一个键值对的集合，其中包含 cookies、变量及其相应的值。

我们可以使用响应对象的`set_cookie()`函数设置 cookies，以存储 cookie，如下所示：

```py
    @app.route('/set_cookie') 
    def cookie_insertion(): 
      redirect_to_main = redirect('/') 
      response = current_app.make_response(redirect_to_main )   
      response.set_cookie('cookie_name',value='values') 
      return response 

```

同样，读取 cookies 非常容易；`get()`函数将帮助您获取 cookies，如下所示：

```py
    import flask 
    cookie = flask.request.cookies.get('my_cookie') 

```

如果 cookie 存在，它将被分配给 cookie，如果不存在，则 cookie 将返回`None`。

# 摘要

在本章中，您学习了如何使用 JavaScript 库（如 knockout.js）将您的微服务与 Web 应用程序集成。您了解了 MVVM 模式，以及如何利用它们来创建完全开发的 Web 应用程序。您还学习了用户管理概念，如 cookies 和会话，以及如何利用它们。

在下一章中，我们将尝试通过将数据库从 SQLite 移动到其他 NoSQL 数据库服务（如 MongoDB）来加强和保护我们的数据库端。
