# Python 无服务器应用构建指南（一）

> 原文：[`zh.annas-archive.org/md5/3c97e70c885487f68835a4d0838eee09`](https://zh.annas-archive.org/md5/3c97e70c885487f68835a4d0838eee09)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

无服务器工程是一种新的工程领域，允许开发人员编写代码并部署基础架构，而无需担心维护服务器。本书通过 Python 示例解释了无服务器工程的概念和云架构。

# 本书适合对象

本书适用于希望了解云平台（如 Azure 和 Amazon Web Services（AWS））中无服务器架构的 Python 开发人员。假定具有 Python 编程知识。

# 本书涵盖的内容

第一章，“无服务器范式”，向读者介绍了微服务和无服务器架构的概念，并清楚地阐述了其优缺点。

第二章，“在 AWS 中构建无服务器应用程序”，涵盖了 AWS Lambda，并详细解释了该工具中涉及的概念、工作原理和组件。它还解释了在 Lambda 中涉及的安全性、用户控制和代码版本控制的微妙之处。

第三章，“设置无服务器架构”，进一步详细介绍了 AWS Lambda 中的各种触发器以及它们如何与函数集成。读者将学习每个触发器的事件结构以及如何根据使用的触发器类型修改 Lambda 函数。

第四章，“部署无服务器 API”，探讨了 AWS API Gateway，并教读者如何使用 API Gateway 和 Lambda 构建高效、可扩展的无服务器 API。它还教读者如何通过添加授权来改进 API，以及如何设置用户级别的控制，如请求限制。

第五章，“日志记录和监控”，介绍了无服务器应用程序中的日志记录和监控概念。这在该领域大多仍然是一个未解决的问题。本章指导读者如何通过自定义指标和日志记录在 AWS 环境中设置日志记录和监控。本章还深入探讨了在 Python 中记录和监控 Lambda 函数时的最佳实践细节。

第六章，“扩展无服务器架构”，讨论了使用几种第三方工具为大型工作负载扩展无服务器架构的实践。本章还教读者如何使用现有的 Python 模块处理安全性、日志记录和监控。

第七章，“AWS Lambda 中的安全性”，教读者通过利用 AWS 提供的安全功能部署安全的无服务器应用程序。这包括严格控制应用程序可以访问的组件，可以处理或访问应用程序的用户等。这还涉及了对 AWS 虚拟私有云和子网的理解，以深入了解 AWS Lambda 中的安全功能和最佳实践。

第八章，“使用 SAM 部署 Lambda 函数”，介绍了如何通过 Serverless Application Model 将 Lambda 函数部署为基础架构即代码，这是一种编写和部署 Lambda 函数的新方法，使其更容易与其他 IaaS 服务（如 CloudFormation）集成。

第九章，“Microsoft Azure Functions 简介”，使读者熟悉 Microsoft Azure Functions，并解释如何配置和理解该工具的组件。

# 要充分利用本书

读者应该熟悉 Python 编程语言。因此，预期具有相关经验。具有基于云的系统的先前经验也将有所帮助。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“需要注意的是，对于所有 SAM，始终应包括元信息，其中包括`AWSTemplateFormatVersion`和`Transform`。这将告诉`CloudFormation`你编写的代码是 AWS SAM 代码和无服务器应用程序。”

一块代码设置如下：

```py
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
```

**Bold**：表示一个新术语、一个重要词或屏幕上看到的词。例如，菜单或对话框中的单词会在文本中显示为这样。这是一个例子：“要创建一个函数，你需要点击右侧的橙色创建函数按钮。”

警告或重要提示会显示为这样。

提示和技巧会显示为这样。


# 第一章：无服务器范式

很可能，如果你正在阅读这本书，你已经听说过无服务器范式和无服务器工程以及无服务器架构这些术语。如今，开发人员部署应用程序的方式发生了巨大变化，特别是在数据工程和 Web 开发领域，这要归功于**基于事件的架构设计**，也称为**无服务器架构**。

在生产中，服务器负载完成后可能会有空闲资源和服务器空闲，或者在等待下一个工作负载到来。这在基础设施中引入了一些冗余。如果没有工作负载时不需要空闲资源会怎样？如果资源可以在需要时创建，并在工作完成后被销毁呢？

在本章结束时，您将了解无服务器架构和函数即服务的工作原理，以及如何将它们构建到您现有的软件基础设施中。您还将了解什么是微服务，并决定微服务或无服务器操作是否适合您的架构。您还将学习如何在主要的云服务提供商（如**亚马逊网络服务**（**AWS**）和**微软的 Azure**）上使用 Python 构建无服务器应用程序。

本章将涵盖以下内容：

+   理解无服务器架构

+   理解微服务

+   无服务器架构不一定只能是实时的。

+   无服务器架构的优缺点

# 理解无服务器架构

无服务器架构或无服务器工程的概念完全围绕理解函数即服务的概念。互联网上对无服务器计算的最技术和准确的定义如下：

"无服务器计算，也称为**函数即服务**（**FAAS**），是一种云计算和代码执行模型，其中云提供商完全管理函数容器的启动和停止**平台即服务**（**PaaS**）。"

现在，让我们深入了解该定义的每个部分，以更好地理解无服务器计算的范式。我们将从函数即服务这个术语开始。这意味着每个无服务器模型都有一个在云上执行的函数。这些函数只是一些代码块，根据与函数关联的触发器执行。这是 AWS Lambda 环境中触发器的完整列表：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/7b29be3e-815c-410f-ae54-59adf322e984.png)

现在让我们了解是谁管理函数的启动和停止。每当函数通过其中一个可用的触发器触发时，云提供商会启动一个容器，函数在其中执行。此外，在函数成功执行后，函数已经返回了一些东西，或者函数已经用完了时间，容器就会被销毁。这种销毁是为了在需求高峰时重复使用容器，以及在两个触发器之间的时间很短的情况下。现在，我们来到句子的下一部分，函数的容器。这意味着函数是在容器中启动和执行的。这是 Docker 的标准容器定义，Docker 是一个使容器概念非常流行的公司：

"容器镜像是一个轻量级的、独立的、可执行的软件包，包括运行它所需的一切：代码、运行时、系统工具、系统库、设置。"

这有助于将代码、运行环境等功能打包成一个单一的部署包，以实现无缝执行。**部署包**包含了函数的主要代码文件，以及执行函数所需的所有非标准库。部署包的创建过程看起来非常类似于 Python 中的虚拟环境。

因此，我们可以清楚地看出，在无服务器基础架构中没有服务器全天候运行。这有明显的好处，包括不需要专门的运维团队成员来监控服务器。因此，如果有任何额外的成员，可以专注于更好的事情，比如软件研究等。整天不运行服务器可以为公司和/或个人节省大量资金和资源。这一好处在机器学习和数据工程团队中非常明显，他们经常使用 GPU 实例进行工作。因此，运行按需的无服务器 GPU 实例可以节省大量资金，而开发人员或运维团队无需全天候维护它们。

# 理解微服务

与无服务器概念类似，面向微服务的设计策略最近也变得非常流行。尽管这种架构设计在无服务器概念出现之前就存在了很长时间。就像我们试图从互联网上的技术定义理解无服务器架构一样，我们也应该尝试对微服务做同样的事情。微服务的技术定义是：

“微服务，也称为**微服务架构**，是一种将应用程序构建为一组松散耦合的服务的架构风格，这些服务实现业务功能。”

以微服务的形式规划和设计架构既有积极的一面，也有消极的一面，就像无服务器架构一样。了解这两者非常重要，以便在现有架构中何时以及何时不应该利用微服务。让我们先看看拥有微服务架构的积极之处，然后再看看消极之处。

微服务有助于软件团队保持敏捷，并逐步改进。简单来说，由于服务之间解耦，很容易升级和改进服务而不会导致其他服务中断。例如，在社交网络软件中，如果聊天和动态都是微服务，那么在软件团队尝试升级或对聊天服务进行小修复时，动态不必中断。然而，在大型单片系统中，很难像微服务那样轻松地分解事物。因此，即使是架构的一个小组件的修复或升级也会带来停机时间，修复所需的时间比预期的更长。

单片架构的代码库规模本身就是在任何小故障情况下阻碍进展的障碍。另一方面，微服务通过保持代码库精简大大提高了开发人员的生产力，因此他们可以在几乎没有额外开销和停机时间的情况下修复和改进服务。通过容器，微服务可以更好地利用，容器提供有效和完整的虚拟操作系统环境，隔离的进程以及对底层硬件资源的专用访问。

然而，微服务也有其自身的一系列缺点和不利因素，其中最主要的是必须处理分布式系统。现在每个服务都是独立存在的，架构师需要弄清楚它们之间的相互作用，以使产品完全功能。因此，服务之间的适当协调以及关于服务之间如何移动数据的决策是架构师需要做出的非常困难的选择。在为微服务架构设计时，架构师需要处理一些主要的分布式问题，如*共识*、*CAP 定理*和*维护共识的稳定性*以及*连接*等问题。确保和维护安全性也是分布式系统和微服务的一个主要问题。您需要为每个微服务决定单独的安全模式和层，以及为服务之间的数据交互所需的安全决策。

# 无服务器架构不一定只能是实时的

无服务器架构通常被用作实时系统，因为它们作为*函数即服务*，由一组可用的触发器触发。然而，这是一个非常常见的误解，因为无服务器系统既可以作为实时系统，也可以作为批处理架构同样有效。了解如何将无服务器系统的概念作为批处理架构来利用，将为工程团队打开许多工程可能性，因为并非所有工程团队都需要或拥有实时系统来运行。

通过利用以下方法，无服务器系统可以作为批处理：

+   触发器中的 cron 功能

+   队列的概念

首先，让我们了解触发器中的**cron 功能**的概念。云上的无服务器系统具有设置监控的能力，这使得触发器可以每隔几分钟或几小时触发一次，并且可以设置为普通的 cron 作业。这有助于将无服务器的概念作为常规的 cron 批处理作业。在 AWS 环境中，可以通过 AWS CloudWatch 设置 Lambda 作为 cron 触发器，通过手动输入时间间隔来设置 cron 的频率，并且还可以按照 cron 格式输入间隔：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/c7243445-2703-477c-b218-d9d702bce746.png)

在构建无服务器批处理架构时，也可以利用队列的概念。让我们通过设置一个示例数据管道来理解这一点。假设我们打算构建的系统执行以下任务：

1.  用户或服务将一些数据发送到数据库或更简单的数据存储中，例如 AWS 的 S3。

1.  一旦我的数据存储中有超过 100 个文件，我们就需要执行一些任务。比如说，对它们进行一些分析，例如计算页面数量。

这可以通过队列实现，这是我们可以考虑的一个更简单的无服务器系统示例。因此，可以按以下方式实现：

1.  用户或服务将数据上传或发送到我们选择的数据存储中。

1.  为此任务配置了一个队列。

1.  可以配置事件到 S3 存储桶或数据存储，以便一旦数据进入存储，就会向我们之前配置的队列发送消息。

1.  可以设置监控系统来监视队列中的消息数量。建议使用您正在使用的云提供商的监控系统，以便系统保持完全无服务器。

1.  可以设置警报到监控系统，为这些警报配置阈值。例如，每当我们的队列中的消息数量达到或超过 100 时，就需要触发警报。

1.  此警报可以作为触发器，触发 Lambda 函数，该函数首先从队列接收消息，然后使用从消息中接收的文件名查询数据存储。

1.  文件的分析完成后，处理后的文件可以推送到另一个数据存储进行存储。

1.  在整个任务完成后，运行 Lambda 函数的容器或服务器将被终止，从而使这个流水线完全无服务器。

# 无服务器的利弊

现在我们了解了无服务器架构和流水线的样子，以及它们如何可以整合到现有架构中，以及微服务如何帮助保持架构的精简并提高开发人员的生产力，我们将详细讨论无服务器系统的利弊，以便软件开发人员和架构师可以决定何时将无服务器范例整合到其现有系统中，何时不这样做。

无服务器系统的优点包括：

+   **更低的基础设施成本**：通过部署无服务器系统，基础设施成本可以得到极大的优化，因为不需要每天全天候运行服务器。由于服务器仅在触发函数时启动，并在函数成功执行时停止，因此计费仅针对函数运行的短暂时间段。

+   **需要更少的维护**：由于前述原因，也不需要对服务器进行持续监控和维护。由于函数和触发器是自动化的，因此无服务器系统几乎不需要维护。

+   **更高的开发人员生产力**：由于开发人员不需要担心停机时间和服务器维护，他们可以专注于解决更好的软件挑战，如扩展和设计功能。

本书的其余部分将向您展示无服务器系统如何改变软件的方式。因此，由于本章旨在帮助架构师决定无服务器系统是否适合其架构，我们现在将看一下无服务器系统的缺点。

无服务器系统的缺点包括：

+   **函数的时间限制**：无论是 AWS 的 Lambda 还是 GCP 的云函数，执行函数都有一个 5 分钟的时间限制。这使得执行繁重的计算变得不可能。然而，这可以通过以 nohup 模式执行配置工具的 playbook 来解决。这将在本章后面详细介绍。然而，准备好 playbook 并设置容器和其他任何事情应该在 5 分钟的时间限制内完成。当超过 5 分钟限制时，容器会自动被终止。

+   **无法控制容器环境**：开发人员无法控制为执行函数而创建的容器的环境。操作系统、文件系统等都由云提供商决定。例如，AWS 的 Lambda 函数在运行 Amazon Linux 操作系统的容器内执行。

+   **监控容器**：除了云提供商通过其内部监控工具提供的基本监控功能外，没有机制可以对执行无服务器函数的容器进行详细监控。当将无服务器系统扩展到容纳分布式系统时，这变得更加困难。

+   **安全性无法控制**：无法控制数据流的安全性如何得到保障，因为对容器环境的控制非常有限。不过，容器可以在开发人员选择的 VPC 和子网中运行，这有助于解决这个缺点。

然而，无服务器系统可以扩展到大规模计算的分布式系统，开发人员无需担心时间限制。如前所述，这将在接下来的章节中详细讨论。然而，为了了解如何在进行架构决策时选择无服务器系统而不是单片系统进行大规模计算，让我们了解一些重要的指针。

将无服务器系统扩展到分布式系统时需要牢记的要点包括：

+   要将无服务器系统扩展到无服务器分布式系统，必须了解 nohup 的概念是如何工作的。这是一个允许程序和进程在后台运行的**POSIX**命令。

+   Nohup 进程应该被正确记录，包括输出和错误日志。这是您的进程的唯一信息来源。

+   需要利用诸如**Ansible**或**Chef**之类的配置工具来创建一个主从架构，该架构是通过在无服务器函数执行的容器中以 nohup 模式运行的 playbook 生成的。

+   确保通过主服务器执行的所有任务都得到适当的监控和记录是一个良好的做法，因为一旦整个设置完成执行，就没有办法检索日志。

+   必须通过使用云提供商提供的临时凭证设施来确保适当的安全性。

+   必须确保系统的适当关闭。工作进程和主进程应该在任务流程执行完成后立即自我终止。这非常重要，也是使系统无服务器的关键。

+   通常，临时凭证会有一个过期时间，对于大多数环境来说是 3,600 秒。因此，如果开发人员使用临时凭证来执行一个预计需要超过过期时间的任务，那么凭证可能会过期。

+   调试分布式无服务器系统是一个极其困难的任务，原因如下：

+   监控和调试一个 nohup 进程是非常困难的。每当你想要调试一个进程时，你要么参考进程创建的日志文件，要么使用进程 ID 杀死 nohup 进程，然后手动运行脚本进行调试。

+   由于在配置工具中完整的任务列表是顺序执行的，存在一个危险，即开发人员在开始调试过程之前忘记杀死 nohup 进程，从而导致实例可能被终止。

+   由于这是一个分布式系统，可以毫无疑问地说，架构应该能够在发生任何故障或灾难时自我修复。一个例子是当一个工作进程在执行一些操作时崩溃了。整个一堆文件现在丢失了，没有任何恢复的手段。

+   另一个高级灾难场景可能是当两个工作服务器在执行一些操作时崩溃了。在这种情况下，开发人员不知道哪些文件已成功执行，哪些没有。

+   确保所有工作实例都能够平均分配负载以执行，以便分布式系统中的负载保持均匀，时间和资源得到充分优化，这是一个良好的做法。

# 摘要

在本章中，我们了解了什么是无服务器架构。最重要的是，本章帮助架构师决定无服务器是否适合他们的团队和工程，并且如何从现有基础架构过渡/迁移到无服务器范式。我们还研究了微服务的范式以及它们如何帮助构建轻量级和高度敏捷的架构。本章还详细介绍了团队何时应该开始考虑微服务，以及何时可以迁移或将其现有的单体架构拆分成微服务。

然后我们学习了在无服务器领域构建批处理架构的艺术。最常见的一个误解是无服务器系统只适用于实时计算目的。然而，我们已经学会了如何利用这些系统进行批量计算，从而为无服务器范式提供了大量的应用。我们研究了无服务器的利弊，以便能够做出更好的工程决策。

在下一章中，我们将详细了解 AWS Lambda 的工作原理，这是 AWS 云环境中无服务器工程的核心组件。我们将了解触发器的工作原理以及 AWS Lambda 函数的工作方式。您将学习利用容器执行无服务器函数和相关的计算工作负载的概念。之后，我们还将学习配置和测试 Lambda 函数，以及在此过程中了解最佳实践。我们还将介绍 Lambda 函数的版本控制，就像代码的版本控制一样，并为 AWS Lambda 创建部署包，以便开发人员可以舒适地适应第三方库，以及标准库。


# 第二章：在 AWS 中构建无服务器应用程序

本章将介绍使用 AWS Lambda 作为首选工具的无服务器应用程序的概念。这将帮助您了解无服务器工具中涉及的概念、直觉和工作组件。它还将解释 Lambda 内部涉及的安全性、用户控制和版本控制代码的微妙之处。您将通过实践教程和课程指导，了解并学习如何使用 AWS Lambda。因此，建议您在本章中使用笔记本电脑和已设置好的 AWS 帐户，以便轻松执行给定的指令。

本章将涵盖以下主题：

+   AWS Lambda 中的触发器

+   Lambda 函数

+   函数作为容器

+   配置函数

+   测试 Lambda 函数

+   版本化 Lambda 函数

+   创建部署包

# AWS Lambda 中的触发器

无服务器函数是按需计算概念。因此，必须有一个事件来触发 Lambda 函数，以便启动整个计算过程。AWS Lambda 有几个事件可以充当触发器。几乎所有 AWS 服务都可以充当 AWS Lambda 的触发器。以下是您可以用于生成 Lambda 事件的服务列表：

+   API Gateway

+   AWS IoT

+   CloudWatch 事件

+   CloudWatch 日志

+   CodeCommit

+   Cognito 同步触发器

+   DynamoDB

+   Kinesis

+   S3

+   SNS

AWS Lambda 的触发器页面如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/0a984ab1-eb98-4ad2-94f8-1f4d6fef5c53.png)

让我们来看一下一些重要和广泛使用的触发器，并了解它们如何作为无服务器范例中的 FaaS 来利用。它们如下：

+   **API Gateway**：此触发器可用于创建高效、可扩展和无服务器的 API。构建 S3 查询接口时，无服务器 API 有意义的一个场景是。假设我们在一个 S3 存储桶中有一堆文本文件。每当用户使用查询参数命中 API 时，该参数可以是我们想要在存储桶中的文本文件中搜索的某个单词，API Gateway 的触发器将启动一个 Lambda 函数，执行计算逻辑和工作量以执行查询。我们希望 API 触发的 Lambda 函数可以在 API 创建时指定。触发器将相应地在相应的 Lambda 函数控制台中创建。如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/7739cf3b-f508-40b2-bcb5-0e7ead874b3e.png)

+   **CloudWatch**：它主要帮助用户设置 Lambda 的 cron 调度。CloudWatch 日志触发器在用户想要根据 Cloudwatch 日志中的某个关键字执行计算工作负载时非常有用。但是，CloudWatch 警报不能直接通过 CloudWatch 触发器直接触发 Lambda。它们必须通过通知系统发送，例如**AWS 简单通知服务**（**AWS SNS**）。以下是如何在 AWS Lambda 中创建 cron 执行的方法。在下面的屏幕截图中，Lambda 函数设置为每分钟执行一次：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/4c9fd799-c9c5-4366-8fbe-f4f124270bf2.png)

+   **S3**：这是 AWS 的文档存储。因此，每当添加、删除或更改文件时，将作为触发器添加到 AWS Lambda 时，事件将被发送到 AWS Lambda。因此，如果您想在文件上传后立即对文件进行一些计算工作，那么这个触发器可以帮助您实现。S3 的事件结构如下：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/e83a0e56-4388-4c0c-bd0d-3db52c93c7c9.png)

+   **AWS SNS**：AWS 的 SNS 服务帮助用户向其他系统发送通知。此服务还可用于捕获 CloudWatch 警报，并将通知发送到 Lambda 函数以进行计算执行。以下是示例 SNS 事件的样子：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/c7c76994-3f94-4d4f-9560-7d0148941068.png)

# Lambda 函数

**Lambda 函数**是无服务器架构的核心操作部分。它们包含了应该执行的代码。这些函数在触发器被触发时执行。我们已经在上一节中了解了一些最受欢迎的 Lambda 触发器。

每当 Lambda 函数被触发时，它会创建一个具有用户设置的容器。我们将在下一节中了解更多关于容器的知识。

容器的启动需要一些时间，这可能导致在进行 Lambda 函数的新调用时出现延迟，因为需要时间来设置环境并引导用户在高级设置选项卡中提到的设置。因此，为了克服这种延迟，AWS 会在一段时间内解冻一个容器以便在解冻时间内进行另一个 Lambda 调用时重用。因此，使用解冻或现成的 Lambda 函数有助于克服延迟问题。然而，解冻容器的相同全局命名空间也将被用于新的调用。

因此，如果 Lambda 函数有任何在函数内部被操作的全局变量，将它们转换为本地命名空间是一个好主意，因为被操作的全局命名空间变量将被重用，导致 Lambda 函数的执行结果出现故障。

用户需要在高级设置选项卡中指定 Lambda 函数的技术细节，其中包括以下内容：

+   内存（MB）：这是 Lambda 函数需要分配的最大内存，用于您的函数。容器的 CPU 将相应地分配。

+   超时：在容器自动停止之前，函数需要执行的最长时间。

+   DLQ 资源：这是对 AWS Lambda 的死信设置。用户可以添加 SQS 队列或 SNS 主题进行配置。Lambda 函数在失败时会异步重试至少五次。

+   VPC：这使得 Lambda 函数能够访问特定 VPC 中的组件或服务。Lambda 函数在自己的默认 VPC 中执行。

+   KMS 密钥：如果有任何环境变量与 Lambda 函数一起输入，这将帮助我们默认使用**AWS 密钥管理服务**（**KMS**）对它们进行加密。

Lambda 函数的高级设置页面如下：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/6883b0ae-4195-4621-9e2a-af3407fd3ee2.png)

# 函数作为容器

为了理解函数作为/在容器内执行的概念，我们需要正确理解容器的概念。引用 Docker 文档中对容器的定义（[`www.docker.com/what-docker`](https://www.docker.com/what-docker)）[:](https://www.docker.com/what-docker)

容器镜像是一个轻量级的、独立的、可执行的软件包，包括运行它所需的一切：代码、运行时、系统工具、系统库、设置。

适用于 Linux 和 Windows 应用程序；容器化软件将始终在相同的环境中运行，而不受环境的影响。

容器将软件与其周围环境隔离（例如开发和分段环境之间的差异），并帮助减少不同软件在同一基础设施上运行时的冲突。

因此，容器的概念是它们是自包含的隔离环境，就像集装箱船上的集装箱一样，可以托管和在任何主机操作系统上工作，主机操作系统在我们的类比中是主机船。这个类比的形象描述会看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/e2c26768-83bf-4ca5-afa0-960f651ce95a.png)

与前述类比类似，AWS Lambda 的函数也是在每个函数的独特容器中启动的。因此，让我们逐点更详细地了解这个主题：

1.  Lambda 函数可以是单个代码文件或**部署包**的形式。部署包是一个包含核心函数文件以及函数使用的库的压缩文件。我们将在本章的*创建部署包*部分详细了解如何创建部署包。

1.  每当函数被触发或启动时，AWS 会为运行函数而启动一个带有 AWS Linux 操作系统的 EC2 实例。实例的配置将取决于用户在 Lambda 函数的高级设置选项卡中提供的配置。

1.  函数执行成功的最长时间限制为 300 秒，或 5 分钟，之后容器将被销毁。因此，在设计 Lambda 函数和/或部署包时需要牢记这一点。

# 配置函数

在本节中，我们将介绍配置 Lambda 函数的方法，并详细了解所有设置。与上一节类似，我们将了解每个配置及其设置，如下所示：

1.  您可以通过从 AWS 控制台左上角的下拉菜单中选择 AWS Lambda 来转到 AWS Lambda 页面。可以按以下步骤操作：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/a971c7c0-ac7c-4032-838a-9306e5ac0a07.png)

1.  选择 Lambda 选项后，它会将用户重定向到 AWS Lambda 控制台，外观类似于这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/5f3040c3-80f1-4d46-ad5f-61968215099a.png)

1.  要创建一个函数，您需要点击右侧的橙色“创建函数”按钮。这将打开一个用于函数创建的控制台。外观类似于这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/91b67fee-892c-4954-91a5-47b0584f523d.png)

1.  让我们从头开始创建一个函数，以更好地了解配置。因此，为了做到这一点，请点击右上角的“从头开始”按钮。点击后，用户将被引导到 Lambda 的首次运行控制台，外观类似于这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/86d6c931-dd7b-4ee2-8ce5-2f546d3e9569.png)

1.  此页面有三个用户可以选择的配置，即名称、角色和现有角色。名称值是用户可以输入 Lambda 函数名称的地方。角色值是您可以在 AWS 环境中定义权限的方式。角色值的下拉列表将包含以下选项：选择现有角色、从模板创建新角色和创建自定义角色。它们可以如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/ee94ac27-0a27-49bb-8c39-dcc09e308f43.png)

选择现有角色选项将使我们能够选择具有预配置权限的现有角色。第二个选项帮助用户从预先制作的模板创建角色。创建自定义角色选项允许用户从头开始创建具有权限的角色。预先制作的角色列表如下：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/605762e3-0a24-47b9-a644-eb349c5ff5c9.png)

1.  为了本教程的目的，从预先制作的模板中选择一个。通过在屏幕右下角的“创建函数”按钮，我们将进入 Lambda 函数创建页面，其外观类似于这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/aaa97414-bac6-40c6-9f48-c034de864930.png)

1.  在上一页中，我们成功创建了一个 AWS Lambda 函数。现在我们将探索该函数的高级设置。它们位于同一控制台的下部。它们看起来会像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/b159cb6f-45db-4ad8-9f75-fc8d1f5c408e.png)

现在我们将详细了解每个部分。

1.  展开的环境变量部分包含文本框，用于输入我们函数将使用的环境变量的键值对。还可以选择提及我们希望为环境变量设置的加密设置。加密需要通过**AWS KMS**（**密钥管理服务**）进行。环境变量的展开设置框看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/1240de6e-18aa-45f9-9ae0-dbe9acc35964.png)

1.  接下来的设置部分是标签。这类似于所有可用 AWS 服务的标记功能，用于方便的服务发现目的。因此，与所有 AWS 服务的标记类似，这也只需要一个键和一个值。展开的标签部分看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/c81faef8-1e1f-4f68-8ffd-4bf992e09763.png)

1.  在标签部分之后将可见的下一部分是执行角色部分，用户可以在其中为 Lambda 函数的执行设置**身份访问管理（IAM）**角色。由于我们之前已经讨论过 IAM 角色是什么，所以在这里不会再次涉及。如果用户在创建函数时没有设置角色，他们可以在这里设置。Lambda 控制台中将显示如下部分：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/7125de51-b42f-4c62-879e-d1d4d75c9efa.png)

1.  接下来是基本设置部分，其中包括 Lambda 容器的内存、容器的超时时间和 Lambda 函数的描述等设置。容器的内存可以在 128 MB 到 1,536 MB 之间。用户可以在该范围内选择任何值，并将按相应的费用计费。超时时间可以设置为 1 秒到 300 秒，即 5 分钟。超时时间是 Lambda 函数及其容器在被停止或终止之前运行的时间。下一个设置是 Lambda 函数的描述值，它充当 Lambda 函数的元数据。控制台中的该部分如下所示：![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/f710d7d7-5215-4817-81a2-b1ec059106a6.png)

1.  接下来是网络部分，也涉及与**AWS 虚拟私有云**（**VPC**）和相关子网有关的 Lambda 函数的网络设置。即使选择了无 VPC 作为选项，AWS Lambda 也会在其自己的安全 VPC 中运行。但是，如果 Lambda 函数访问或处理位于特定 VPC 或子网中的任何其他服务，则需要在此部分中添加相应的信息，以便网络允许 Lambda 函数容器的流量。控制台中的该部分如下所示：![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/f75cfc81-b7f7-412c-a8c9-ace0d6d69a21.jpg)为了安全起见，前面截图中的敏感信息，如 IP 地址和 VPC 的 ID，已被屏蔽。

1.  接下来是调试和错误处理部分。该部分使用户能够设置确保 Lambda 函数容错和异常处理的措施。这包括**死信队列**（**DLQ**）设置。

1.  Lambda 会自动重试异步调用的失败执行。因此，未处理的有效负载将自动转发到 DLQ 资源。Lambda 控制台中的 DLQ 设置如下：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/b74e9b2e-a5e1-4007-bea9-82a6be36cf5f.png)

用户还可以为 Lambda 函数启用主动跟踪，这将有助于详细监视 Lambda 容器。Lambda 控制台中的调试和错误处理部分的设置如下：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/a74a9e4c-467c-476a-81ef-81b5a7805148.png)

# Lambda 函数测试

与其他软件系统和编程范式一样，Lambda 函数和无服务器架构在部署到生产环境之前进行适当的测试非常重要。我们将在以下几点中尝试理解 Lambda 函数的测试：

1.  在 Lambda 控制台的最顶部栏中，可以看到保存并测试选项，用橙色按钮表示。这个按钮保存 Lambda 函数，然后运行配置的测试函数。在控制台中看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/60f3caa0-0530-4b40-9e10-3dd991c15c94.png)

1.  此外，在同一栏中，存在一个下拉菜单，上面写着选择一个测试事件…. 这包含了用于测试 Lambda 函数的测试事件列表。下拉菜单看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/1114f014-a1ad-4033-99b3-8cf90d913e9c.png)

1.  现在，为了进一步配置 Lambda 函数的测试事件，用户需要在下拉菜单中选择配置测试事件选项。这将打开一个带有测试事件菜单的弹出窗口，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/564fb42c-4c4e-4461-884b-7106e608fa50.png)

1.  这将打开基本的 Hello World 模板，其中包含三个预配置的 JSON 格式测试事件，或边缘情况。但是，根据 Lambda 函数的功能，可以选择其他测试事件。可用的测试模板列表可以在事件模板下拉菜单中看到。下拉菜单中的列表看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/905d7bd8-21d2-46c3-a276-25ebdd9a786e.png)

1.  例如，让我们想象我们正在构建一个流水线，其中 Lambda 函数在将图像文件添加到 S3 存储桶时启动，并且该函数执行一些图像处理任务并将其放回到某个数据存储中。S3 Put 通知的测试事件看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/339a2a51-15e7-4502-b96a-1eb712e5514e.png)

1.  选择或创建测试事件后，用户可以在事件创建控制台的右下角选择创建选项，然后将被要求为事件输入名称。输入必要的细节后，用户将被重定向回 Lambda 控制台。现在，当您在 Lambda 控制台中检查 TestEvent 下拉菜单时，可以在列表中看到保存的测试事件。可以按以下方式验证：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/7d7b1f3b-595b-4bad-bf33-99ac957fade3.png)

由于我将事件命名为**TestEvent**，因此在事件下拉菜单中以相同的名称可见测试。

1.  此外，当我们仔细观察 S3 测试事件中的事件结构时，我们可以观察到向 Lambda 函数提供的元数据。事件结构看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/ff15ffd2-7bb5-4303-bc13-bba656deb732.png)

# Lambda 函数的版本控制

**版本控制系统**（**VCS**）的概念是用于控制和管理代码版本。这个功能直接从主 Lambda 控制台中可用。让我们尝试学习如何为我们的 Lambda 函数进行版本控制：

1.  Lambda 控制台中操作下拉菜单中的第一个选项是发布新版本选项。可以在这里看到这个选项：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/7b880937-3308-472d-800e-00ed54ce1452.png)

1.  当选择发布新版本选项时，Lambda 控制台的版本控制弹出窗口将出现在控制台上。这将询问您的 Lambda 函数的新版本名称。弹出窗口看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/b78150b6-6c9e-4eee-905f-17633a6a48cf.png)

1.  单击发布按钮后，您将被重定向到主 Lambda 控制台。控制台中成功创建的 Lambda 版本看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/a117ec47-8651-41bc-b503-6db458194811.png)

1.  在页面的下半部分，可以注意到以下消息：代码和处理程序编辑仅适用于$LATEST 版本。这意味着只能编辑名为$LATEST 的版本中的代码。版本化的 Lambda 函数是只读的，不能被编辑和操作。当出现问题或用户想要恢复或参考以前的版本时，该版本将覆盖$LATEST 版本以使编辑成为可能。消息看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/6c35f1e1-7d34-4c9d-8119-2f43400a4d43.png)

1.  当点击“点击此处转到 $LATEST 链接”时，用户将被重定向到函数的 $LATEST 版本，用户可以对其进行编辑和操作。Lambda 函数的 $LATEST 版本控制台如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/d872e1c7-1d3b-4aa7-afce-6a4e9a8b1117.png)

# 创建部署包

具有外部库依赖项的 Lambda 函数可以打包为部署包，并上传到 AWS Lambda 控制台。这与在 Python 中创建虚拟环境非常相似。因此，在本节中，我们将学习并了解创建 Python 部署包以在 Lambda 函数中使用的过程。我们将尝试并详细了解创建部署包的过程，如下所示：

1.  部署包通常是 ZIP 包的格式。ZIP 包的内容与任何编程语言的普通库完全相同。

1.  包的结构应该是库文件夹和函数文件在部署包的相同目标或相同层次结构内。布局看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/f46e42f6-0700-481b-be63-584d08bb0682.png)

1.  可以使用 `pip install <library_name> -t <path_of_the_target_folder>` 命令安装 Python 库。这将在目标文件夹内安装包。如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/986316e5-9244-4ed2-bc1c-ff4ed09e6777.png)

1.  现在，当我们有整个部署包文件夹以及库文件夹准备就绪时，我们需要在上传到控制台之前将所有文件夹包括 Lambda 函数文件进行压缩。以下截图显示了如何根据文件夹层次结构进行压缩：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/d5dac1d7-bb73-4319-ba28-b07c503af622.png)

1.  现在，由于压缩包已准备就绪，我们将尝试将包上传到 Lambda 控制台进行处理。要上传 Lambda 包，我们需要在控制台中选择“代码输入类型”选项的下拉列表。在 Lambda 控制台中，选择如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/6ccd81c5-5cfb-4e7d-a4c5-f46fe32736ad.png)

1.  一旦选择了“上传 .ZIP 文件”选项，上传者将变为可见状态，用户可以直接上传部署包，甚至可以通过 S3 存储桶上传。在 Lambda 控制台中，向导将如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/6f4fa67b-53b7-4580-a9a9-c2258507f36c.png)

1.  如前所述，用户还可以选择通过 S3 文件位置上传部署包。在 Lambda 控制台中，该向导如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/12130c7f-5d6e-487a-9c9f-76eb692be568.png)

1.  部署包的命名应与设置中处理程序部分输入的值对齐。部署包的名称和 Lambda 函数文件的名称由点（`.`）分隔，并按照这个顺序排列。可以在以下截图中明确看到：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/406c2dc0-125f-4d22-850a-6be24e2035fe.jpg)

`index` 应该是 Lambda 函数的 文件名 部署包的名称。`handler` 函数文件是核心函数处理程序的名称，即 Lambda 函数。正如 AWS 的文档所述：

在函数中导出的模块名称值”。例如，index.handler 将调用 index.py 中的 exports.handler。

# 总结

在本章中，我们学习了 AWS Lambda 触发器的工作原理以及根据问题陈述和时间间隔选择触发器的概念，特别是在 cron 作业触发器的情况下。我们了解了 Lambda 函数是什么，以及它们的功能和与内存、VPC、安全性和容错相关的设置。我们还了解了 AWS Lambda 特定的容器重用方式。然后，我们涵盖了事件驱动函数以及它们在软件工程领域中的概念、用途和应用。最重要的是，通过我们学习的容器概念，我们现在可以欣赏选择容器来运行 Lambda 函数的选项。

之后，我们讨论了 AWS Lambda 仪表板中的所有配置设置，这些设置对于从头到尾构建和运行 Lambda 函数而言是必要的，而且不会出现任何与设置相关的问题。我们还学习了并了解了 Lambda 中的安全设置，以便在配置 Lambda 函数时处理必要的 VPC 详细信息和安全密钥设置。接着是根据所选触发器的选择来测试 Lambda 函数。我们学习了各种 AWS 服务的响应是什么样子，因为它们是 Lambda 函数的输入。然后，我们学习了如何编写自定义手工测试以进行自定义测试。

在此之后，我们看到了 AWS Lambda 函数的版本控制是如何进行的。我们学习了过去版本和现在版本之间的区别。我们还了解到现在版本是不可变的，不像过去的版本，以及如何在不费力的情况下恢复到过去的版本。我们还学习了如何为依赖于外部包的函数创建部署包，这些包不包括在 Python 的标准库中。我们遇到了函数代码命名的微妙之处，包括文件名和方法处理程序名称，以及部署包可以上传到 Lambda 控制台的两种方式；一种是手动上传，另一种是从 S3 文件位置上传。

在下一章中，我们将详细了解 Lambda 控制台中提供的不同触发器以及如何使用它们。我们还将学习如何在 Python 代码中实现它们。我们将了解事件结构以及来自不同 AWS 服务的响应，并利用它们来构建我们的 Lambda 函数。我们将了解如何将每个触发器集成到 Lambda 函数中，并在 Python 中执行特定任务。最后，我们还将学习有关如何使用无服务器范例将现有基础架构迁移到无服务器的想法和最佳实践。


# 第三章：设置无服务器架构

到目前为止，我们已经了解了无服务器范例是什么，以及无服务器系统是如何工作的。我们还了解了 AWS Lambda 的无服务器工具是如何工作的。我们还学习了 AWS Lambda 中触发器的基础知识，以及用户在 Lambda 环境中可用的系统设置和配置的详细理解。我们还学习了 Lambda 控制台的工作原理，以及如何详细识别和使用 Lambda 控制台的各个部分，包括代码部署、触发器操作、在控制台中部署测试、对 Lambda 函数进行版本控制，以及可用的不同设置。

在本章结束时，您将清楚地了解 AWS Lambda 可用的所有重要触发器，以及如何使用它们来设置高效的 Lambda 架构。您还将了解事件结构是什么，以及某些 AWS 资源的事件结构是什么样子，以及如何使用这些知识来编写和部署基于触发器的 Lambda 架构。

本章将涵盖以下内容：

+   S3 触发器

+   SNS 触发器

+   SQS 触发器

+   CloudWatch 事件和日志触发器

# S3 触发器

S3 是 AWS 对象存储服务，用户可以存储和检索任何类型的对象。在本节中，我们将学习 S3 触发器的工作原理，S3 事件的事件结构是什么样的，以及如何在学习中使用它们来构建 Lambda 函数。

我们将构建一个 Lambda 函数，该函数执行以下操作：

1.  从 S3 服务接收 PUT 请求事件

1.  打印文件名和其他重要细节

1.  将文件传输到不同的存储桶

因此，让我们开始学习如何有效使用 S3 触发器。我们将逐步完成此任务，如下所示：

1.  首先，我们需要为任务创建两个 S3 存储桶。一个将是用户上传文件的存储桶。另一个将是 Lambda 函数传输和上传文件的存储桶。

1.  当没有预先存在的存储桶时，S3 控制台如下所示。您可以通过从 AWS 控制台左上角的下拉服务菜单中选择 S3 服务进入：![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/09a5de57-300f-49c0-8b59-12bc529afa02.png)

1.  让我们创建两个存储桶，即`receiver-bucket`和`sender-bucket`。

1.  `sender-bucket`存储桶将用作用户上传文件的存储桶。`receiver-bucket`存储桶是 Lambda 函数上传文件的存储桶。因此，根据我们的问题陈述，每当我们将文件上传到`sender-bucket`存储桶时，Lambda 函数将被触发，并且文件将被上传到`receiver-bucket`。

1.  当我们在 S3 控制台中单击“创建存储桶”按钮时，我们会得到一个如下所示的对话框：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/0a72eb0c-9445-40b1-9f8c-73b4b34d0e14.png)

1.  在前面的对话框中，我们需要输入以下设置：

+   存储桶名称：顾名思义，我们需要输入正在创建的存储桶的名称。对于第一个存储桶的创建，将其命名为`sender-bucket`，并将第二个存储桶命名为`receiver-bucket`。

+   区域：这是我们希望存储桶所在的 AWS 区域。您可以使用默认区域，也可以使用距离您所在位置最近的区域。

+   从现有存储桶复制设置：这指定我们是否要在控制台中使用与其他存储桶相同的设置。由于我们目前在控制台中没有其他存储桶，因此可以通过将其留空来跳过此设置。之后，您可以单击弹出窗口右下角的“下一步”按钮。

1.  单击“下一步”后，我们将被重定向到弹出窗口的第二个选项卡，即“设置属性”菜单，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/10128d3e-10e6-45e9-b027-0f7ff5062db1.png)

1.  在弹出窗口的此部分，我们需要决定以下设置：

+   版本控制：如果我们想要在 S3 存储桶中保留多个文件版本，这是相关的。当您需要为您的 S3 存储桶使用 Git 风格的版本控制时，需要此设置。请注意，存储成本将根据版本化文档的数量包括在内。

+   服务器访问日志：这将记录对 S3 存储桶的所有访问请求。这有助于调试任何安全漏洞，并保护 S3 存储桶和文件的安全。

+   标签：这将使用*名称:值*样式对存储桶进行标记，与我们学习 Lambda 函数的标记样式相同。

+   对象级别日志记录：这将使用 AWS 的 CloudTrail 服务记录对 S3 存储桶的所有访问请求和其他详细信息和活动。这也将包括 CloudTrail 成本。因此，只有在需要详细记录时才使用此功能。我们将跳过在本节中使用此功能。

1.  完成创建存储桶后，S3 控制台将如下所示，列出了创建的两个存储桶：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/f7f31807-cf46-4bef-ba8d-d20124be7acf.png)

1.  我们已成功为我们的任务创建了 S3 存储桶。现在，我们必须创建一个 Lambda 函数，该函数可以识别`sender-bucket`存储桶中的对象上传，并将该文件发送到`receiver-bucket`存储桶。

1.  在创建 Lambda 函数时，这次从列出的选项中选择 s3-get-object-python 蓝图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/cfc6e86a-9252-4248-b7ed-0055f37f1da5.png)

1.  在下一步中配置存储桶详细信息。在“存储桶”部分，选择`sender-bucket`存储桶，并在“事件类型”操作中选择“对象创建（全部）”选项。这是因为我们希望在`sender-bucket`存储桶中创建对象时向 Lambda 发送通知。该部分的完成部分将如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/a382c99c-082c-489c-924f-b0ef76843400.png)

1.  一旦您启用了触发器，Lambda 将通过为任务创建样板代码来帮助您。我们所需要做的就是编写代码将对象放入`receiver-bucket`存储桶中。Lambda 函数代码部分中可以看到样板代码：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/5ea96838-08fa-4617-84f2-aa8a67147152.png)

1.  当完成此步骤并单击“创建函数”按钮后，您可以在 Lambda 控制台的触发器部分看到一个成功消息，该消息在顶部以绿色显示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/9186f527-a131-41b5-8fb6-21f6f1ddae21.png)

1.  我已将一个小图像文件上传到`sender-bucket`存储桶中。因此，现在`sender-bucket`存储桶的内容如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/a3e237fe-2e78-4a2f-a67d-9878ec9a4f87.png)

1.  一旦上传了这个文件，Lambda 函数就会被触发。Lambda 函数的代码如下所示：

```py
from __future__ import print_function

import json
import urllib
import boto3
from botocore.client import Config

print('Loading function')
sts_client = boto3.client('sts', use_ssl=True)

# Assume a Role for temporary credentials
assumedRoleObject = sts_client.assume_role(
RoleArn="arn:aws:iam::080983167913:role/service-role/Pycontw-Role",
RoleSessionName="AssumeRoleSession1"
)
credentials = assumedRoleObject['Credentials']
region = 'us-east-1'

def lambda_handler(event, context):
    #print("Received event: " + json.dumps(event, indent=2))

    # Get the object from the event and show its content type
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.unquote_plus(event['Records'][0]['s3']       ['object']['key'].encode('utf8'))
    try:
        # Creates a session
        session = boto3.Session(credentials['AccessKeyId'],      credentials['SecretAccessKey'] ,      aws_session_token=credentials['SessionToken'],      region_name=region)

        #Instantiates an S3 resource
        s3 = session.resource('s3',  config=Config(signature_version='s3v4'), use_ssl=True)

        #Instantiates an S3 client
        client = session.client('s3',   config=Config(signature_version='s3v4'), use_ssl=True)

        # Gets the list of objects of a bucket
        response = client.list_objects(Bucket=bucket)

        destination_bucket = 'receiver-bucket'
        source_bucket = 'sender-bucket'

        # Adding all the file names in the S3 bucket in an  array
        keys = []
        if 'Contents' in response:
            for item in response['Contents']:
                keys.append(item['Key']);

        # Add all the files in the bucket into the receiver bucket
        for key in keys:
            path = source_bucket + '/' + key
            print(key)
        s3.Object(destination_bucket,  key).copy_from(CopySource=path)

    Exception as e:
        print(e)
print('Error getting object {} from bucket {}. Make sure they exist and your bucket is in the same region as this function.'.format(key, bucket))
raise e
```

1.  现在，当您运行 Lambda 函数时，您可以在接收者存储桶中看到相同的文件：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/957a5fbb-3d6b-4f34-8a69-ea62d47a06ed.png)

# SNS 触发器

SNS 通知服务可以用于多种用例，其中之一涉及触发 Lambda 函数。SNS 触发器通常用作 AWS CloudWatch 服务和 Lambda 之间的接口。

因此，在本节中，我们将执行以下操作：

1.  创建一个 SNS 主题

1.  为我们的`receiver-bucket`存储桶创建一个 CloudWatch 警报，以监视存储桶中的对象数量

1.  一旦对象计数达到 5，警报将被设置为警报，并相应的通知将被发送到我们刚刚创建的 SNS 主题

1.  然后，这个 SNS 主题将触发一个 Lambda 函数，为我们打印出“Hello World”消息

这将帮助您了解如何监视不同的 AWS 服务并为这些指标设置一些阈值的警报。根据服务的指标是否达到了该阈值，Lambda 函数将被触发。

这个过程的流程如下：

1.  SNS 主题可以从 SNS 仪表板创建。通过单击“创建主题”选项，您将被重定向到 SNS 的主题创建仪表板。AWS 的 SNS 仪表板如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/3262ad33-76f7-4d57-8e43-2e12db82b2c0.png)

接下来的 SNS 主题创建向导如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/b51fe4e3-fed3-41be-80df-b59948f23419.png)

在此创建向导中，您可以为正在创建的 SNS 主题命名，并添加任何您想要的元信息。

1.  主题创建后，您可以在 SNS 仪表板左侧的“主题”菜单中查看它。按钮如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/698f8392-0c40-46b6-a558-4fd6309dfa26.png)

点击“主题”选项卡后，将显示主题列表，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/eeae4a00-0357-4153-a0fd-441b71dad76a.jpg)

1.  现在我们已成功创建了一个 SNS 主题，我们将创建一个 CloudWatch 警报来监视我们的 S3 存储桶中的文件。AWS CloudWatch 仪表板看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/10928218-5dfe-47a1-8c48-150d889b7496.png)

1.  现在，我们可以通过单击仪表板左侧列表中的“警报”按钮转到警报页面。AWS 警报页面如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/bc0501d4-b507-4d58-b7c2-2c589238c3bc.png)

1.  接下来，点击“创建警报”以创建警报。这将打开一个带有多个选项的警报创建向导。根据您的 AWS 生态系统中运行的服务，向导如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/a9f15a2f-b628-447e-a920-7f9287bc587b.png)

1.  由于我们打算为我们的 S3 存储桶创建警报，我们可以转到 S3 指标选项卡，并忽略其他可用的指标。如果您点击 S3 指标类别中的存储指标选项，您将被重定向到另一个警报创建向导，具体取决于您在 S3 中拥有的存储桶数量：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/32782120-1b76-4d1b-8b27-9a929f4dc6e3.png)

1.  如果您观察“指标名称”列中的选项，您将看到每个存储桶都有两个选项可用：NumberOfObjects 和 BucketSizeBytes。它们是不言自明的，我们只需要“NumberOfObjects”选项来监视`receiver-bucket`存储桶。因此，选择该选项并单击“下一步”：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/45fd818d-d08c-4100-857c-4377453774ea.png)

这将带您进入警报定义向导，在那里您需要指定 SNS 主题的详细信息和警报的阈值。向导如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/0921bdeb-5fde-4537-8f95-04aed3bcf7e8.png)

1.  添加阈值和警报名称的详细信息。阈值为五个文件，这意味着一旦相应存储桶（在我们的情况下为`receiver-bucket`）中的文件数量达到五个，警报就会被触发。向导如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/4148aba2-9c69-4913-b885-13d2a49687e7.png)

1.  在“操作”选项中，我们可以配置警报将通知发送到我们刚刚创建的 SNS 主题。您可以从下拉列表中选择主题，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/9438ea9f-5fb0-46a7-bc73-ef23df6afa6c.png)

1.  一旦配置了 SNS 主题，我们可以点击底部的“创建警报”按钮。这将创建与 SNS 主题链接的警报作为通知管道。在仪表板上，创建的警报将如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/55201a98-53ba-42cd-bf02-c2827618e7fc.png)

1.  现在，我们可以继续构建任务的 Lambda 函数。对于这个特定的任务，在创建 Lambda 函数时，请使用 sns-message-python 蓝图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/b08bdcd4-f8b2-4b7e-8ac5-14da83059c1f.png)

1.  在上一步中，当您选择了蓝图后，将要求您输入有关 Lambda 函数的一些元信息，就像我们之前创建 Lambda 函数时所做的那样。在同一向导中，您还将被要求提及 SNS 主题的名称。您可以在这里指定它：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/9c4217ff-c8c1-4bce-b320-f7f88e46b38f.png)

1.  现在我们已经正确选择了 Lambda 函数的所有选项，我们现在可以进行代码编写。期望的代码将如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/b6107109-2c7f-4237-bc5e-62cbb37f1129.png)

上述代码将在 Lambda 函数触发时显示`Hello World`消息。这样我们就完成了此任务的设置。

1.  要测试前面的设置，您可以简单地将超过五个文件上传到您的`receiver-bucket`存储桶，并检查 Lambda 函数的执行情况。

# SQS 触发器

**AWS 简单队列服务（SQS）**是 AWS 队列服务。该服务类似于通常在软件工程中使用的排队机制。这使我们能够在队列中添加、存储和删除消息。

我们将学习如何根据 SQS 队列中的消息数量触发 Lambda 函数。此任务将帮助您了解如何构建无服务器批量数据架构，以及如何自己构建一个。

我们将通过监视我们的 SQS 队列使用 CloudWatch 警报，并通过 SNS 主题将信息传递给 Lambda，就像我们在上一个任务中所做的那样。

因此，在本节中，我们将执行以下操作：

1.  创建一个 SQS 队列

1.  创建一个 SNS 主题

1.  为我们的 SQS 队列创建一个 CloudWatch 警报，以监视队列中的消息数量

1.  一旦消息计数达到 5，警报将被设置为“警报”，并相应的通知将被发送到我们刚刚创建的 SNS 主题

1.  然后，这个 SNS 主题将触发一个 Lambda 函数，为我们打印一个`Hello World`消息。

这将帮助您了解如何监视队列，并构建高效的无服务器数据架构，而不是实时的批处理。

此过程的流程如下：

1.  我们将首先创建一个 AWS SQS 队列。我们需要转到我们 AWS 账户的 SQS 仪表板。仪表板如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/39c005af-791e-433c-858a-3ba9d9d1292b.png)

1.  单击“立即开始”按钮创建一个 SQS 队列。它会将您重定向到队列创建向导，在那里您需要输入名称、队列类型等详细信息。队列创建向导如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/50152dc5-a8d0-4eea-964c-ec94f4a3a3f5.png)

1.  您可以在“队列名称”中输入队列的名称。在“您需要什么类型的队列？”选项中，选择“标准队列”选项。在底部的选项中，选择蓝色的“快速创建队列”选项：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/03c94053-37fe-49db-bc53-bc2049fabe0e.png)

“配置队列”选项是用于高级设置的。对于这个任务，不需要调整这些设置。高级设置如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/67e1af76-950f-4b85-bfe9-f574dadb53cc.png)

1.  创建队列后，您将被带到 SQS 页面，那里列出了您创建的所有队列，类似于 SNS 列表。此页面如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/6a3174a2-251c-4b5b-af46-673a86e7514e.jpg)

1.  由于我们在上一个任务中已经创建了一个 SNS 主题，我们将为此目的使用相同的主题。如果您还没有创建 SNS 主题，您可以参考上一个任务中有关如何创建主题的说明。SNS 主题列表如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/489ab47d-2c1e-4d58-a857-5b33a52e7154.jpg)

1.  现在，我们将转到 CloudWatch 仪表板，创建一个警报来监视我们的 SQS 队列，并通过我们已经创建的 SNS 主题向 Lambda 发送通知。我们现在可以在警报创建向导中看到 SQS 队列的指标：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/70942869-f930-4886-be27-da5db529dc1b.png)

1.  通过单击 SQS 指标下的“队列指标”选项，我们将被带到列出所有队列指标的页面，我们需要选择其中一个用于我们的警报：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/8d9f61c2-5448-4a61-9350-36d7147f350f.png)

1.  在这里，我们对“ApproximateNumberOfMessagesVisible”指标感兴趣，该指标提供了队列中的消息数量。它说是“Approximate”，因为 SQS 是一个分布式队列，消息数量只能以随机方式确定。

1.  在下一页中，从列表中选择“ApproximateNumberOfMessagesVisible”指标后，可以像我们在上一个任务中为 S3 指标所做的那样配置必要的设置。页面应该如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/ac9558df-bc94-4b64-835f-c0fea9f2e7fa.png)

1.  在操作部分，配置我们要发送通知的 SNS 主题。这一步与我们在上一个任务中配置 SNS 主题的方式类似：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/6a9ed54d-2897-40b3-9ab1-e327bb359f61.png)

1.  一旦您对元数据和您为警报配置的设置感到满意，您可以单击屏幕右下角的蓝色创建警报按钮。这将成功创建一个监视您的 SQS 队列并向您配置的 SNS 主题发送通知的警报：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/def27a8d-3fb9-4bcc-89d5-c2d7d93f2591.png)

1.  我们可以使用上一个任务中创建的 Lambda 函数。确保触发器是我们用于配置警报通知系统的 SNS 主题：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/5d5aae9c-805b-4fcb-8ea4-602553ca4ed8.jpg)

1.  此任务的 Lambda 函数代码如下：

```py
from __future__ import print_function
import json
print('Loading function')
def lambda_handler(event, context):
    #print("Received event: " + json.dumps(event, indent=2))
    message = event['Records'][0]['Sns']['Message']
    print("From SNS: " + message)
    print('Hello World')
    return message
```

# CloudWatch 触发器

**CloudWatch**是 AWS 的日志记录和监控服务，大多数服务的日志都会被存储和监控。在本节中，我们将学习 CloudWatch 触发器的工作原理，CloudWatch 查询在实践中的工作原理，如何在 Lambda 函数中配置它，以及如何利用这些知识来构建 Lambda 函数。

因此，在本节中，我们将执行以下操作：

1.  创建一个 CloudWatch 日志

1.  简要了解 CloudWatch 日志的工作原理

1.  创建一个由 CloudWatch 触发器触发的 Lambda 函数

这将帮助您理解并构建弹性和稳定的无服务器架构。

这个过程的流程如下：

1.  要创建一个 CloudWatch 日志组，请点击 CloudWatch 控制台左侧的日志选项：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/76623ee2-7ff2-40d9-b4e0-7e07a76ca89f.png)

1.  一旦您进入 AWS CloudWatch 日志页面，您将看到一个已经存在的日志组列表。CloudWatch 日志页面看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/c23bdbdf-ee89-4449-8979-5d503712e8e8.png)

1.  让我们继续创建一个新的 CloudWatch 日志。您可以在顶部的操作下拉菜单中看到创建新日志组的选项：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/53517c8e-c595-4e20-925c-35967b6b0cac.png)

1.  在下一步中，您将被要求命名您正在创建的日志组。继续输入相关信息，然后单击创建日志组：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/6315be94-5485-490f-ae80-d660c7e88531.png)

1.  所以，现在我们在 CloudWatch 控制台的日志组列表中有一个新的日志组：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/c02d6c18-85b0-4fcb-99cd-9e39456e0c45.png)

1.  日志组创建后，我们现在可以开始处理我们的 Lambda 函数。因此，让我们转到 Lambda 控制台并开始创建一个新函数。

1.  从蓝图中选择 cloudwatch-logs-process-data 蓝图。描述如下：Amazon CloudWatch 日志日志组摄取的实时日志事件的实时消费者：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/61ffd152-0d65-4079-9dfb-5007b3dffeee.png)

1.  选择相应的蓝图选项后，您将像往常一样被重定向到 Lambda 创建向导：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/9d4e0e03-c35d-4b60-9d6f-708caf1b85e7.png)

1.  就像我们在上一个任务中所做的那样，在 Lambda 创建面板的 cloudwatch-logs 窗格中，我们还将输入有关日志名称和其他细节的相关信息：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/d882d70c-60fd-4d07-8019-83d11b359ea1.png)

1.  单击创建函数后，我们将被重定向到一个触发器页面，并显示成功消息。

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/76767741-339a-45bd-9323-6b8fbc1ba9e1.jpg)

1.  所以，现在我们编写 Lambda 函数代码来识别日志组并打印`Hello World`消息：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/42a6a6b2-7e14-46ac-bcf6-890cef77d9b3.png)

1.  我们已经成功完成了另一个任务，了解了如何通过 AWS CloudWatch 日志触发 Lambda 函数。此任务的 Lambda 函数代码如下：

```py
 import boto3
 import logging
 import json
 logger = logging.getLogger()
 logger.setLevel(logging.INFO)
 def lambda_handler(event, context):
 #capturing the CloudWatch log data
 LogEvent = str(event['awslogs']['data'])
 #converting the log data from JSON into a dictionary
 cleanEvent = json.loads(LogEvent)
 print 'Hello World'
 print cleanEvent['logEvents']
```

# 摘要

在本章中，我们已经学到了有关各种 Lambda 触发器如何工作以及如何配置它们，设置触发器并编写 Lambda 函数代码来处理它们的数据。

在第一个任务中，我们学习了 S3 事件的工作原理，以及如何理解并接收来自 S3 服务的事件到 AWS Lambda。我们了解了如何通过 CloudWatch 监视 S3 存储桶的文件详细信息，并通过 AWS SNS 将该通知发送到 Lambda 函数。

我们还学习了如何创建 SNS 主题，以及如何将它们用作从 CloudWatch 到 AWS Lambda 的多个 AWS 服务的中间路由。

我们简要了解了 AWS CloudWatch 的工作原理。我们了解了各种 AWS 服务的指标是什么样子，比如 S3、SQS 和 CloudWatch。我们还学会了为 CloudWatch 警报设置阈值，以及如何将这些警报连接到 AWS SNS 等通知服务。

我们学习了 AWS CloudWatch Logs 的工作原理，以及如何连接和使用 Lambda 中的 CloudWatch 触发器，以便在添加/接收新的日志事件时触发它。总的来说，在本章中，我们成功创建了新的 AWS 服务，如 SQS、CloudWatch Logs、SNS 和 S3 存储桶，并成功构建和部署了三个无服务器任务/流水线。

在下一章中，我们将学习如何构建无服务器 API，我们将在其中执行一些任务，就像我们在本章中所做的那样，并且深入了解 API 的工作原理，最重要的是，无服务器 API 的工作原理。


# 第四章：部署无服务器 API

到目前为止，我们在学习无服务器应用程序和构建无服务器工程方面已经走了很长一段路。我们已经了解了无服务器范例的实际含义，AWS Lambda 函数的工作原理，了解了 AWS Lambda 的内部工作原理，以及对多个触发器的详细了解。我们还围绕尝试触发器并将它们部署为端到端无服务器流水线进行了几个迷你项目。

在本章中，您将学习如何使用 AWS Lambda 和 AWS API 网关服务构建高效可扩展的无服务器 API。我们将从了解 API 网关的工作原理开始，而不是直接构建无服务器 API。之后，我们将了解 API 网关和 AWS Lambda 如何相互集成。最后，作为本章学习的一部分，我们将创建和部署一个完全功能的无服务器 API。

本章涵盖以下主题：

+   API 方法和资源

+   设置集成

+   部署用于 API 执行的 Lambda 函数

+   处理身份验证和用户控制

# API 方法和资源

在本节中，我们将学习 AWS 的 API 服务，即 API 网关，并了解控制台中为创建 API 的用户提供的组件和设置。我们将浏览所有组件并更好地了解 API 网关。创建无服务器 API 的步骤如下：

1.  我们将从打开 API 网关控制台开始，它看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/77983079-abbd-4875-851d-6e09321bdc6c.png)

1.  在 API 网关控制台上，单击“开始”按钮开始创建 API。它将带您进入一个 API 创建向导，弹出窗口上显示“创建示例 API”：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/8453d058-8208-40d0-8c88-c518a75b43d0.png)

1.  单击“确定”按钮后，您将被重定向到一个页面，显示示例 API，从中您可以了解 API 响应的样子：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/8a58f0ab-0c83-4c3b-a724-d6b68316d241.png)

我们在此示例中构建的 API 是用于宠物商店和维护商店内宠物的。通过浏览 API，您将看到 API 的各个部分是什么样子。API 如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/1850eb9c-f409-44c6-a7a8-56e6754e29bf.png)

1.  单击末尾的“导入”按钮后，您将被重定向到我们刚刚创建的 PetStore（b7exp0d681）API 页面。具有所有组件的 API 页面如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/314f78ff-589d-4cd6-b632-7989087b0f9c.png)

1.  该 API 中的资源是 GET 和 POST 资源，您可以在其中添加宠物并查看宠物，它们作为列表可用。我们创建的 API 的资源列表如下：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/6cf3936a-cc2f-46cf-b706-090012aee0ea.png)

1.  通过单击第一个 GET 资源，我们可以看到从客户端到端点再返回客户端的详细执行流程。资源的执行流程如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/f473698f-c3d1-4c97-a106-a7d2eebecb55.png)

1.  现在，如果我们单击 POST 资源，我们将找到与 POST 资源相似的模型执行流程。它看起来与 GET 资源非常相似，但是这里 API 端点被指定为 URL，因为我们正在尝试从中检索结果。执行模型如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/0c4d2b07-3fa4-4230-ad87-fda3eb91fb73.png)

在 API 网关中，有一种称为 Stages 的东西，可以用作 API 的版本模型。实际上，Stages 的一些常见名称是**测试**，**开发**和**生产**。Stages 菜单如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/862e05dd-969e-43ee-8d11-87e3174223fd.png)

1.  单击“创建”选项后，将打开一个阶段的创建向导。如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/24dfbf47-6fa7-4e7a-bce3-c019246ad81c.png)

1.  您可以为阶段名称值选择任何名称，并根据您分配的名称和此阶段的目的添加阶段描述值。在此之前，您需要部署已创建的 API。这可以在“操作”下拉菜单中选择“部署 API”按钮来完成：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/1f42a071-fc01-4eff-b37c-5f3c41c299d3.png)

1.  在下一个菜单中，您可以选择阶段名称和其他详细信息，然后最终单击“部署”按钮，这将使用特定阶段部署您的 API。如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/f694b7f3-ae32-4f2e-9f5b-5bf35a054543.png)

部署的阶段如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/13c5a18c-5468-4bce-9a6b-5b38c41659ca.png)

# 设置集成

现在，我们已经了解了 AWS API Gateway 服务的基本工作原理，我们将继续使用这些知识来构建一个涉及部署完全无服务器 API 的端到端项目。

在本节中，我们将从头开始构建和部署一个完全无服务器的 API 函数，并学习 AWS Lambda 与 AWS API Gateway 集成的内部和其他实现细节。我们将逐步构建无服务器 API。因此，请按照以下顺序进行操作。该过程如下：

1.  首先，我们将开始创建一个新的 API。这可以通过 Lambda 控制台完成，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/70ae1912-ad8b-499f-a057-7643a4028bb5.png)

1.  单击“+创建 API”按钮后，您将被重定向到 API 创建向导页面，在那里您将被要求输入您打算构建的 API 的名称和描述。目前，我已将名称输入为`TestLambdaAPI`。但是，您可以自由添加任何名称和描述。API 创建控制台如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/547a9a71-871c-4385-b1e4-af300a8f7980.png)

1.  单击“创建 API”按钮后，您将被重定向到您创建的 API 页面。API 页面看起来类似于这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/9062284a-2428-4469-b50b-b3d75a24e582.png)

1.  现在我们已经成功创建了一个 API，我们现在将继续在 API 中创建资源。您可以通过单击“操作”下拉菜单中的“创建资源”选项来执行此操作：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/91bb7f8c-6aa0-42cd-9657-d7d3d26a801d.png)

1.  这将打开一个资源创建向导，在这里您可以添加我们打算构建的 API 资源的名称和资源路径。创建资源后，单击“创建资源”按钮，以便相应地创建 API 资源的设置。出于本教程的目的，我将其命名为`LambdaAPI`。但是，您可以随意命名。API 创建向导如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/c1399e16-8ea2-4093-9731-40da3feafbd5.png)

您刚刚创建的资源现在在 API 控制台中处于活动状态；您可以在“资源”部分下看到它：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/8d176ac4-5444-4d97-908b-377d008e9bf9.png)

1.  您可以创建资源的版本，甚至只是资源下的资源。让我们继续创建一个。为此，您需要单击已创建的资源，然后单击“操作”菜单中的下拉菜单中的“创建资源”选项：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/7133db2c-ff1c-4d50-9f16-4ec673ec2f21.png)

1.  这将在我们已经创建的资源下打开一个类似的资源创建向导。您可以将该资源命名为`version1`或只是`v1`，这是一种常规的软件实践。我将其命名为`v1`。但是，您可以根据需要命名它：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/ee774cc7-8eaa-4cfe-9b61-51654b86ffd6.png)

现在，我们在已有资源`/lambdaapi`下有一个名为`v1`的资源。我们可以在“资源”部分中看到这一点。因此，现在我们的 API 的资源层次结构如下：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/3f05ee06-fdd4-4f28-9089-254cd78b0b5e.png)

1.  我们将为宠物商店创建一个无服务器 API，用于获取和查询宠物列表。因此，以下步骤将相应地对齐。API 应返回宠物的名称。因此，我们将为此创建一个新的宠物资源。我们将在`/v1`资源下创建一个资源：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/942939eb-4f65-48bf-b506-3b0fb5a7bbb1.png)

1.  在将`/pets`资源添加到`/v1`资源下后，我们的 API 的层次结构如下：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/c04c2044-ddb5-42ca-b54c-2ddd1236f97f.png)

1.  现在，我们将添加一个自定义资源，使我们能够查询 API。通过自定义，我们的意思是在向此 API 发送请求时，可以添加任何字符串到资源中，并且 API 会通过 Lambda 代码检查和查询该字符串后发送回一个请求。自定义资源可以与普通资源区分开，因为它们可以用大括号创建。以下截图将帮助您了解如何创建它们：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/5664f793-4837-4cd6-856f-e83a0541f088.png)

1.  单击“创建资源”按钮后，将创建`/pets`的新自定义子资源。现在资源的层次结构如下：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/48c41ba6-1303-4315-a62f-d2861059cf79.png)

1.  API 的整体结构如下，如下截图右上角所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/783da33a-f27a-4981-965d-5d5fcf215529.png)

1.  现在，我们将为此自定义资源添加方法。因为我们只会查询宠物列表，所以我们只会添加 GET 方法。这可以通过单击{type}资源并在顶部面板的下拉“操作”菜单中单击“创建方法”来完成：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/fc5dcff4-b616-48f4-a946-c1d94f887678.png)

1.  这将在{type}资源下创建一个小的下拉样式菜单，您可以从可用方法中选择一个方法：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/f86516df-6431-4f81-8d74-837a5b629442.png)

1.  我们需要从可用选项中选择“GET”选项。这将如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/7415aff4-6d63-4832-8736-fb8a7877e7e9.png)

1.  选择“GET”选项并单击旁边的小勾按钮后，我们将在我们的{type}资源下创建 GET 方法。现在的层次结构如下：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/ef4c6cd9-0912-4457-8dec-95c6acf52921.png)

# 部署 Lambda 函数以执行 API

在本节中，我们将看一下部署 Lambda 函数的步骤：

1.  当您单击该方法时，还可以在 API 控制台的右侧看到 GET 方法的详细信息。详细信息如下：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/6c67dfce-45f9-4648-8922-7b02b8eb568e.png)

1.  在 GET 方法控制台中，单击“Lambda 函数”选项。根据您的偏好选择任何一个地区。我选择了 us-east-1 作为地区，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/4ab15692-b5bf-4825-9b11-e15eef1bdd6f.png)

1.  正如预期的那样，它说我们在该地区没有 Lambda 函数。因此，我们需要继续创建一个。单击“创建 Lambda 函数”链接。这将带您到 Lambda 创建控制台，我们已经熟悉：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/27281b9e-3209-4530-8784-256f386b2f18.png)

1.  从这里，从蓝图列表中选择关键字：hello-world-python 蓝图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/cc88530b-ba15-4927-8a60-a196fc2219da.png)

1.  在下一个控制台中，选择 Lambda 函数的基本信息，就像我们在之前的章节中所做的那样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/2983dee9-a909-4091-b017-3316de0044ef.png)

1.  添加相关细节后，单击橙色的“创建函数”按钮。这将带您到刚刚创建的 Lambda 函数的页面。代码可以从那里开始编辑：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/96a0e196-367d-4920-8553-2a3e28bf186a.png)

1.  在函数的代码中，使用这段代码，而不是与蓝图一起提供的代码：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/e675ac9d-79e7-4a7a-bb1f-b6decc56f2ce.png)

1.  我们现在已经调整了函数代码。现在，您可以继续保存函数：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/aacde03a-2d88-4c33-8949-74da00fed010.png)

1.  现在，返回 API 网关控制台，转到 GET 方法页面。在此，在“us-east-1”区域的 Lambda 函数下，我开始获得刚刚创建的 Lambda 函数（无服务器 API）作为选项：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/6e6d06af-02dc-4b95-ac11-a7e242aca617.png)

1.  单击“保存”后，您将看到一个弹出窗口，询问您是否确认授予 API 网关调用 Lambda 函数的权限，您可以单击“确定”来确认：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/852f0f08-5d10-41e9-b073-94f4f2e49223.png)

1.  单击“确定”后，您将被重定向到 GET 方法的数据流页面，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/c1f73f62-da07-4029-a727-ee926996d125.png)

# 处理身份验证和用户控件

部署后，接下来我们将讨论如何处理身份验证和用户控件。步骤如下：

1.  现在我们已经成功创建了无服务器 API 的框架，我们现在将致力于使其成为一个完全功能的 API 所需的细节。我们将从应用映射模板开始。这可以在“集成请求”菜单中完成。单击“集成请求”链接将带您到一个看起来像这样的控制台：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/5251a40d-48d2-48c1-a7af-f649a985fce3.png)

1.  如果您在同一控制台中向下滚动一点，您会注意到“Body Mapping Templates”部分在最后：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/8f301f36-d13b-43be-8435-b925bd566be2.png)

1.  单击“Body Mapping Templates”将展开该特定部分中的可用选项：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/f52aa43b-becc-406a-84e5-51ad7dab2f78.png)

1.  选择第二个选项，即“当未定义模板时（推荐）”。然后，单击“添加映射模板”选项，添加`application/json`，然后单击其旁边的小灰色勾号：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/ef5353b2-1f3a-4e5e-acc0-e515394882af.png)

1.  单击其旁边的小灰色勾号后，“Body Mapping Templates”部分的空间将如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/094fc096-36f9-4054-b7bd-b13d313773a6.png)

1.  现在，在模板文本框中，添加以下代码并单击文本框下方的“保存”按钮：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/480207dc-5a03-4384-af3e-3b5c9bc224ba.png)

1.  因此，在所有这些步骤之后，生成的“Body Mapping Templates”部分将如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/e9e666be-3cb8-4849-9ef0-18d743d2949b.png)

1.  现在，返回到方法执行页面，我们可以看到左侧的“测试”选项，下面是一个闪电符号：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/ff995a15-e50f-49e0-b231-2780b4d09551.png)

1.  在“客户端”部分左侧的“测试”按钮上方和“雷电”选项上单击，将带您到一个页面，您可以在该页面上测试您刚刚创建的 API：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/88b995a6-60cf-4c81-9957-29eda8e0c2b2.png)

1.  现在，在{type}下方的文本框中键入“异国情调”，然后单击底部的“测试”按钮。如果一切顺利，我们应该看到我们在 Lambda 函数的函数代码中输入的所有异国情调宠物的列表：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/849e6fda-c63d-42d8-90be-e4a32cb2fd18.png)

1.  确实如此，我们确实得到了目录中所有异国情调的宠物的列表。因此，本章到此结束，您已经学会了如何从头开始构建一个完全成熟的无服务器 API，包括如何部署它。

1.  此外，如果您想添加额外的安全设置，如授权和 API 密钥要求，您可以在“方法请求”菜单中进行设置：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/1387a18f-b76d-4345-a542-94ee7923f244.png)

# 总结

在本章中，我们学习了如何从头开始构建一个完全无服务器的 API。我们还学习了如何为 API 添加更多资源和方法，以及如何成功将其部署到多个开发阶段，并如何添加额外的安全设置，如授权和 API 密钥，以进行身份验证。

然后，我们学会了如何将 Lambda 函数与 API 网关的 API 服务关联起来，以处理 API 的计算任务。

在下一章中，我们将学习有关无服务器应用程序的日志记录和监控。在该章节中，我们将详细了解 AWS 的日志记录和监控服务，如 CloudWatch 指标、CloudWatch 日志和 CloudWatch 仪表板，并尝试为我们的无服务器应用程序设置它们。我们还将学习如何使用一些 AWS 服务从 AWS Lambda 创建日志记录和监控管道到这些监控工具。


# 第五章：日志记录和监视

我们已经了解了无服务器架构的概念，并了解了 AWS 的无服务器服务 AWS Lambda 的基础知识和内部工作原理。我们还创建了一些示例无服务器项目，以更好地理解这些概念。在学习过程中，我们还学习了其他几个 AWS 服务的基础知识，例如警报、SNS、SQS、S3 存储桶和 CloudWatch。

在本章中，我们将学习如何为我们构建的无服务器系统进行日志记录和监视。日志记录和监视软件代码和系统非常重要，因为它们帮助我们进行遥测和灾难恢复。日志记录是一个过程，我们在其中存储代码或整体架构发出的日志。监视是一个过程，我们密切监视代码或架构中组件和进程的活动、状态和健康状况。

因此，您将学习如何设置和了解 AWS Lambda 的监视套件，它与 AWS 的监视服务 CloudWatch 仪表板紧密集成。我们还将学习 AWS 的日志记录服务 CloudWatch Logs 服务。最后，我们还将学习和了解 AWS 的分布式跟踪和监视服务 CloudTrail 服务。

本章涵盖以下主题：

+   了解 CloudWatch

+   了解 CloudTrail

+   CloudWatch 中的 Lambda 指标

+   CloudWatch 中的 Lambda 日志

+   Lambda 中的日志记录

# 了解 CloudWatch

如前所述，CloudWatch 是 AWS 的日志记录和监视服务。我们已经了解并学习了 CloudWatch 警报，这是 CloudWatch 的一个子功能。现在我们将学习该服务的图形套件。AWS 环境中几乎每个服务都有一种方法将其日志和指标发送到 CloudWatch 进行日志记录和监视。每个服务可能有多个可以监视的指标，具体取决于其功能。

同样，AWS Lambda 也有一些指标，例如调用次数、调用运行时间等，它会发送到 CloudWatch。值得注意的是开发人员也可以将自定义指标发送到 CloudWatch。因此，在接下来的步骤中，我们将学习与 AWS Lambda 对应的 AWS CloudWatch 的不同部分和功能：

1.  首先，让我们看看 CloudWatch 控制台的外观，并通过浏览控制台来感受一下。浏览至[console.aws.amazon.com/cloudwatch/](https://signin.aws.amazon.com/signin?redirect_uri=https%3A%2F%2Fconsole.aws.amazon.com%2Fcloudwatch%2F%3Fstate%3DhashArgs%2523%26isauthcode%3Dtrue&client_id=arn%3Aaws%3Aiam%3A%3A015428540659%3Auser%2Fcloudwatch&forceMobileApp=0)：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/1046303e-63ab-4f58-8dd5-3757559e8d88.png)

1.  正如我们所看到的，CloudWatch 控制台中有大量信息。因此，我们现在将尝试逐个了解每个组件。在左侧，我们可以看到一系列选项，包括仪表板、警报、计费等。我们将尝试了解它们以及它们作为了解 CloudWatch 控制台的一部分的功能。

1.  这里的仪表板是用户可以配置的 CloudWatch 指标面板。例如，用户可能希望在一个地方拥有一组特定的服务器（EC2）指标，以便更好地监视它们。这就是 AWS CloudWatch 仪表板发挥作用的地方。当您点击左侧的“仪表板”选项时，您可以看到仪表板控制台，它看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/8a4bc481-d9a3-4ff4-96be-c025773752b8.png)

1.  让我们继续点击控制台左上角的蓝色“创建仪表板”按钮，创建一个新的仪表板。将出现以下框：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/22ac5911-7102-4b57-b57c-67f86a992261.png)

1.  这将带您进入下一步，您将被要求为仪表板选择一个小部件类型。目前有四种类型的小部件可用。小部件选择屏幕如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/98a3e0c5-f7bb-465a-8b7d-d719c5067d18.png)

1.  出于本教程的目的，我选择了线条样式小部件。您可以选择适合您的图表样式和所需监视的任何小部件。一旦您选择了小部件样式并单击蓝色的“配置”按钮，您将被重定向到一个向导，在那里您将被要求添加一个度量，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/03495b0c-d00c-4397-bf4f-0435e606b263.png)

1.  在底部选择一个可用的度量，并将其添加到小部件中。一旦您选择了度量标准，点击页面右下角的蓝色“创建小部件”按钮，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/49439599-8f9f-4604-8795-a45411ba4eeb.png)

1.  现在，您可以在“仪表板”部分看到您刚刚创建的仪表板：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/0d9b4553-1e12-4e4f-bb4f-e0ee8f81352b.png)

1.  我们已经成功学习并创建了 AWS CloudWatch 仪表板。现在我们将继续学习 CloudWatch 事件。在前几章中，我们已经了解了 CloudWatch 警报，查看了它们的功能以及如何创建和使用它们。

1.  在 CloudWatch 菜单的左侧单击“事件”链接。您将被重定向到 CloudWatch 事件页面，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/db25848e-e62f-43ab-ba37-ccb0fa4fb150.png)

1.  一旦您单击蓝色的“创建规则”按钮，您将被重定向到事件创建向导，它看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/cb2ad2e0-c2b9-4499-9e65-55274aa727ce.png)

1.  可以有两种类型的事件，即事件模式和计划，它们各自有不同的目的。在这里，我们只会了解计划类型，因为它对于调度 Lambda 函数非常方便：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/52498f0f-822b-47b8-a1cf-5d9f9072ffcd.png)

1.  速率可以以分钟、小时或天为单位设置，也可以设置为 cron 表达式，无论您喜欢哪种方式。现在，需要选择目标。目标可以是任何有效的 Lambda 函数，如下拉菜单所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/a0c2d995-161b-4f16-b852-448fbcc6b48f.png)

1.  一旦您选择了函数，您可以在底部单击蓝色的“配置详细信息”。这将带您到配置规则详细信息页面，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/c7c5f05a-3898-404f-9493-e6565f19fbe7.png)

1.  一旦您输入要创建的规则的名称和描述，您可以单击底部的蓝色“创建规则”按钮。这将成功创建一个事件，并将在您的 CloudWatch 控制台中反映出来：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/2f488395-182b-46db-ab1b-bd33a090ef0f.png)

我们已成功为 Lambda 函数添加了一个 cron 事件，这意味着 Lambda 将按照用户在事件设置中指定的间隔定期调用。

1.  现在，我们将尝试了解 AWS CloudWatch 的日志功能。这是 Lambda 函数存储其日志的地方。您可以单击左侧菜单中的“日志”链接，以访问 CloudWatch 日志的控制台：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/d2d37382-f5b9-4a68-a770-a3f74538479d.png)

1.  我们可以看到我们在整本书中创建的所有 Lambda 函数的完整日志列表。当您单击日志组时，您可以找到有关它的更多详细信息，以及自定义选项。每个日志流都是与 Lambda 函数相关联的调用：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/eef02958-3237-4aeb-84d1-4724fdf4f25d.png)

1.  您还可以利用 CloudWatch 提供的附加功能来处理日志数据，这可以在“日志组”中的下拉“操作”菜单中看到：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/922f928e-2eb2-4130-a62f-abbddb68aa90.png)

1.  最后，我们将通过探索和学习 CloudWatch 指标来结束。可以通过单击 CloudWatch 控制台左侧的“指标”选项来访问指标控制台：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/8841372c-f770-4656-b97b-c4042c14eb8d.png)

1.  您可以在底部菜单中选择任何选项来绘制指标。在本教程中，我已添加了一个 Lambda 指标，即函数`serverless-api`中的错误数量：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/159fc81d-ca6b-4b58-acba-becd2c391461.png)

# 了解 CloudTrail

CloudTrail 是 AWS 的另一个监控服务，您可以查看在您的 AWS 帐户中发生的所有事件和路径。该服务比 CloudWatch 服务更详细，因为它记录和存储事件和路径的方式更详细。

因此，我们将在以下步骤中探索和学习有关此服务的信息：

1.  可以在[console.aws.amazon.com/cloudtrail/](https://signin.aws.amazon.com/signin?redirect_uri=https%3A%2F%2Fconsole.aws.amazon.com%2Fcloudtrail%2Fhome%3Fstate%3DhashArgs%2523%26isauthcode%3Dtrue&client_id=arn%3Aaws%3Aiam%3A%3A015428540659%3Auser%2Fcloudtrail&forceMobileApp=0)访问 AWS CloudTrail 的仪表板：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/ce2500b6-f225-4255-8023-d255bbee795b.png)

1.  当您单击“事件历史记录”按钮时，您可以在 CloudTrail 菜单的左侧看到 AWS 帐户中的事件列表。事件历史记录页面如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/6b2bab2d-c948-45e8-9594-0b29c27bd9db.png)

1.  CloudTrail 的第三个功能是路径。用户可以为他们的 AWS 服务设置路径，例如 Lambda。已设置的路径可以在路径仪表板上找到。这可以通过单击左侧菜单中的“路径”选项来访问：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/623c5cb7-de80-48fd-b9ac-7d36933a3b27.png)

1.  现在，让我们了解如何在 CloudTrail 仪表板中创建路径。您可以转到 CloudTrail 的主仪表板，然后单击蓝色的“创建路径”按钮。这将带您进入路径创建向导：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/46c4272b-7b8d-47f9-818a-f1beeaa44072.png)

1.  您可以在此处输入您的路径的详细信息。您可以将默认选项保留为“将路径应用于所有区域”和“管理事件”选项：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/1617ea6b-b03a-4308-ad6e-894561bd5025.png)

1.  现在，继续下一个设置，选择 Lambda 选项，然后单击选项列表中的“记录所有当前和未来的函数”。这将确保我们所有的 Lambda 函数都能够正确记录在 CloudTrail 中：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/9c69f7dd-45b8-40d7-997f-157529678aa4.png)

1.  现在，在最终的“存储位置”选项中，选择一个 S3 存储桶来存储 CloudTrail 日志。这可以是已经存在的存储桶，或者您也可以要求 CloudTrail 为此创建一个新的存储桶。我正在使用一个现有的存储桶：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/d39c4224-9ae5-41d8-9ac0-6f220f628439.png)

1.  在所有详细信息和设置都已相应配置后，您可以单击蓝色的“创建路径”按钮来创建路径。现在，您可以在 CloudTrail 仪表板中看到您刚刚创建的路径，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/93727858-8059-47b2-a5be-3975204b45d8.png)

1.  现在，当您单击刚刚创建的路径时，您可以看到所有配置详细信息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/b8ecaae1-742f-4432-89f3-9eb34c7bc33e.png)

1.  您还可以注意到一个非常有趣的选项，它使您能够配置 CloudWatch 日志以及 SNS，以通知您任何特定的活动，例如当 Lambda 函数出现错误时：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/70560b9e-6ef6-4e5f-af54-6692315440a6.png)

1.  最后，您还可以像其他 AWS 服务一样为路径添加标记：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/1b11d26e-56a2-4116-b352-2001c689eaf2.png)

1.  此外，让我们了解如何为我们的路径配置 CloudWatch 日志。因此，您需要单击标记部分上方的蓝色“配置”按钮：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/eaea7387-216c-46d9-b4f3-70f3d8c5531d.png)

1.  单击“继续”将带您到创建向导，您需要根据 IAM 角色设置相应地配置权限。在本教程中，我已选择了“创建新的 IAM 角色”选项，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/f6d4dba6-f006-463b-81a7-1ba5f14f6833.png)

1.  完成 IAM 角色设置配置后，您可以单击底部的蓝色“允许”按钮。经过几秒钟的验证后，CloudWatch 日志将被配置，您可以在此处的同一 CloudWatch 日志部分中看到：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/8129a3da-2968-47ea-b627-f3db726c986e.png)

# Lambda 在 CloudWatch 中的指标

由于我们已经学习和了解了 CloudWatch 和 CloudTrail 服务在日志记录和监视方面的工作原理，我们将继续尝试为我们的 Lambda 函数实现它们。在本节中，您将了解 Lambda 拥有的 CloudWatch 监控的指标类型，并学习如何创建包含所有这些指标的仪表板。

与本章和本书中的先前部分类似，我们将尝试以以下步骤的形式理解概念：

1.  当您导航到 AWS Lambda 控制台时，您将看到您已经创建的 Lambda 函数在可用函数列表中：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/b2c86ede-f9c1-4044-b7bf-bc4e5627be16.png)

1.  当您单击函数时，您将在顶部看到两个可用选项：配置和监视。导航到监视部分。您将看到包含以下内容的指标仪表板：

+   调用

+   持续时间

+   错误

+   节流

+   迭代器年龄

+   DLQ 错误

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/45c11785-1c42-40f6-9a4d-5dab9bdadb50.png)

调用和持续时间

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/6ec83c08-9292-429f-b6c1-dcd95e98e439.png)

错误和节流

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/f494d4c8-8651-4c69-8d14-7d47ca414b94.png)

迭代器年龄和 DLQ 错误

1.  让我们逐一详细了解每一个。第一个指标是调用指标，*x*轴上是时间，*y*轴上是 Lambda 函数的调用次数。该指标帮助我们了解 Lambda 函数何时以及多少次被调用：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/97cc9acf-9a68-4bbe-99dc-17d3ef287af2.png)

单击“跳转到日志”将带您到 Lambda 调用的 CloudWatch 日志控制台，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/7ce781ee-0bf6-48a6-b992-eac28a1924db.png)

当您单击“跳转到指标”选项时，它将带您到该特定指标的 CloudWatch 指标仪表板，该仪表板为您提供了同一指标的更加定制和细粒度的图表，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/87642e50-d03f-4d24-abfe-78bba3540f4f.png)

1.  Lambda 监控仪表板中的第二个指标是持续时间指标，它告诉您每次调用 Lambda 函数的持续时间。它还将时间作为*X*轴，并以毫秒为单位在*Y*轴上显示持续时间。它还告诉您在一段时间内 Lambda 函数的最大、平均和最小持续时间：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/2d2da06d-39b3-420f-b81d-735af4e8f75a.png)

1.  再次单击“跳转到日志”按钮将带您到与先前指标相同的页面。单击“跳转到指标”按钮将带您到持续时间指标的 CloudWatch 指标页面，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/b79022ab-c988-4ba6-80d1-dd7a5c4e69ce.png)

1.  第三个指标是错误指标，它帮助我们查看 Lambda 函数调用中的错误。*Y*轴是错误数量，*X*轴是时间轴：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/8973a822-31e5-4b64-bbd7-93dac36607b5.png)

1.  单击“跳转到指标”链接，可以看到相同指标的 CloudWatch 仪表板：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/25fa346e-6462-4fe2-a095-99dc0b74e996.png)

1.  第四个指标是节流。这个指标计算了您的 Lambda 函数被节流的次数，也就是函数的并发执行次数超过了每个区域的设定限制 1,000 次的次数。我们不会经常遇到这个指标，因为我们在本书中构建的 Lambda 函数示例都远远低于并发限制：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/531b1e5a-cf88-4c3f-b9f8-f9bab88de0ef.png)

1.  通过单击跳转到指标链接，我们还可以在我们的 CloudWatch 指标仪表板中看到这个指标：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/c45abd31-7c67-47cb-943d-41607e64ac3f.png)

1.  第五个指标是迭代器年龄。这仅对由 DynamoDB 流或 Kinesis 流触发的函数有效。它给出了函数处理的最后一条记录的年龄：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/1d65a61c-c6c5-49bd-a23c-dd9a014a0b3e.png)

跳转到指标链接将带您到此指标的 CloudWatch 指标仪表板：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/335da45d-9628-435e-b9db-b7c9a5c6d562.png)

1.  第六个也是最后一个指标是 DLQ 错误指标。这给出了在将消息（失败的事件负载）发送到死信队列时发生的错误数量。大多数情况下，错误是由于故障的权限配置和超时引起的：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/089213e4-6e0e-4b56-aa5e-56af3eb17f52.png)

单击跳转到指标链接将带您到相同指标的 CloudWatch 指标仪表板：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/062ee619-3b95-4949-85b3-054c50481d1e.png)

# CloudWatch 中的 Lambda 日志

到目前为止，我们已经非常详细地了解了 AWS Lambda 的指标。现在，我们将继续了解 Lambda 函数的日志。与往常一样，我们将尝试通过以下步骤来理解它们：

1.  AWS Lambda 函数的日志存储在 CloudWatch 的日志服务中。您可以通过单击主 CloudWatch 仪表板上的日志仪表板来访问 CloudWatch 日志服务。

1.  当您单击服务器端 API 的日志，/aws/lambda/serverless-api，在列表中，我们转到无服务器 API 的日志流，它看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/40d6b9b7-3963-428a-8659-c65aace1b751.png)

1.  这里的每个日志流都是一个 Lambda 调用。因此，每当您的 Lambda 函数被调用时，它都会在这里创建一个新的日志流。如果调用是 Lambda 的重试过程的一部分，那么该特定调用的日志将被写入最近的日志流下。单个日志流可以包含多个细节。但首先，让我们看看特定的日志流是什么样子的：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/9b532fda-5179-4224-bb3b-8b3368ae8fba.png)

1.  此外，如果您仔细观察，您会发现 Lambda 的日志还提供有关 Lambda 函数调用的持续时间、计费持续时间以及函数使用的内存的信息。这些指标有助于更好地了解我们函数的性能，并进行进一步的优化和微调：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/5737c445-d61e-4dfe-9c50-06eb9be58965.png)

1.  CloudWatch 日志中有几列可供选择，这些列在前面的截图中没有显示。这些是可用选项：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/b8580207-9fe8-444e-aa6b-7b34ee5e997e.png)

因此，当您选择更多的选项时，您将在仪表板中看到它们作为列。当您对我们的 Lambda 函数进行更精细的调试时，这些选项非常有用：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/613ad444-0922-42a9-bf3b-43c226ad3014.png)

# Lambda 中的日志记录语句

清楚地记录您的评论和错误始终是一个良好的软件实践。因此，我们现在将了解如何从 Lambda 函数内部记录日志。在 Lambda 函数内部记录日志有两种广泛的方法。我们现在将通过以下步骤的示例来学习和理解它们：

1.  第一种方法是使用 Python 的`logging`库。这在 Python 脚本中作为标准的日志记录实践被广泛使用。我们将编辑之前为无服务器 API 编写的代码，并在其中添加日志记录语句。代码将如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/efddfce9-0f57-47c1-b818-f2e354229456.png)

在前面的截图中的代码如下：

```py
import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
def lambda_handler(event, context):
 mobs = {
 "Sea": ["GoldFish", "Turtle", "Tortoise", "Dolphin", "Seal"],
 "Land": ["Labrador", "Cat", "Dalmatian", "German Shepherd",
 "Beagle", "Golden Retriever"],
 "Exotic": ["Iguana", "Rock Python"]
 }

 logger.info('got event{}'.format(event))
 logger.error('something went wrong')

 return 'Hello from Lambda!'
 #return {"type": mobs[event['type']]}
```

1.  现在，当您保存后运行 Lambda 函数，您可以看到一个绿色的成功执行语句，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/947377e1-12e7-4197-844a-9f7433a0a6b6.png)

1.  当您点击“详细”选项时，您可以清楚地看到执行日志语句：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/dac4ea52-e0f2-4246-8c51-aaedc2db9558.png)

1.  记录语句的下一种方式是简单地在 Python 中使用`print`语句。这是在 Python 脚本中打印日志语句的最常见方式。因此，我们将在我们的函数代码中添加一个`Hello from Lambda`的打印语句，看看我们是否在 Lambda 执行中获得日志：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/bfdb14b4-bbaf-4f5f-b5e1-ddef710ef470.png)

此 Lambda 函数的代码如下：

```py
 def lambda_handler(event, context):
 mobs = {
     "Sea": ["GoldFish", "Turtle", "Tortoise", "Dolphin", "Seal"],
     "Land": ["Labrador", "Cat", "Dalmatian", "German Shepherd",
     "Beagle", "Golden Retriever"],
     "Exotic": ["Iguana", "Rock Python"]
}
print 'Hello from Lambda!'
return 1
#return {"type": mobs[event['type']]}
```

1.  当我们点击“测试”来执行代码时，我们应该看到一个绿色的消息，表示成功执行：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/935ec9df-157e-478f-8eae-ca699d5d7b0c.png)

1.  同样，就像之前所做的那样，点击“详细”切换将给您完整的执行日志：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/912656a0-9fa1-4946-a70d-0989ce6f2563.png)

1.  我们也可以看到`Hello from Lambda`的消息。对于我们的 Lambda 函数有两种可用的日志记录选项，始终最好使用第一种选项，即通过 Python 的日志记录模块。这是因为该模块提供了更大的灵活性，并帮助您区分信息、错误和调试日志。

# 摘要

在本章中，我们已经了解了 AWS 的监控和日志记录功能。我们还了解了 AWS 环境中可用的监控和日志记录工具。我们还学习了如何监控我们的 Lambda 函数以及如何为我们的 Lambda 函数设置日志记录。

我们已经了解了行业遵循的日志记录和监控实践，以及在 Lambda 函数内部记录语句的各种方式。

在下一章中，我们将学习如何扩展我们的无服务器架构，使其变得分布式，并能够处理大规模的工作负载，同时仍然保留无服务器设置的优点。


# 第六章：扩展无服务器架构

到目前为止，我们已经学会了如何构建、监控和记录无服务器函数。在本章中，我们将学习一些概念和工程技术，帮助扩展无服务器应用程序以进行分布式，并使其能够以高标准的安全性和吞吐量处理大量工作负载。在本章中，我们还将使用一些第三方工具，如 Ansible，来扩展我们的 Lambda 函数。我们将扩展我们的 Lambda 函数以生成分布式无服务器架构，这将涉及生成多个服务器（或在 AWS 环境中的实例）。因此，在阅读本章中提到的示例时，您需要牢记这一点。

本章假定您对规划工具（如 Ansible、Chef 等）有一定的了解。您可以在它们各自的网站上快速阅读或复习这些知识，这些网站上有快速教程。如果没有，您可以安全地跳过本章，继续下一章。

本章包括五个部分，涵盖了扩展无服务器架构的所有基础知识，并为您构建更大、更复杂的无服务器架构做好准备：

+   第三方编排工具

+   服务器的创建和终止

+   安全最佳实践

+   扩展的困难

+   处理困难

# 第三方编排工具

在这一部分，我们将学习和熟悉基础设施的规划和编排概念。我们将探讨一些工具，即 Chef 和 Ansible。让我们按照以下步骤开始：

1.  我们将从介绍 Chef 开始。您可以访问 Chef 的官方网站[`www.chef.io/chef/`](https://www.chef.io/chef/)：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/a06338bf-fb28-4b03-810a-82fae062bd39.png)

1.  Chef 有一套非常好的教程，可以让您动手实践。这些教程以每次 10 到 15 分钟的迷你教程形式组织，易于消化。请访问[`learn.chef.io/`](https://learn.chef.io/)来获取这些教程：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/825c1b56-d209-430e-bbeb-ffc5001d2368.png)

1.  要开始进行基础设施规划和编排，您可以参考 Chef 的文档：[`docs.chef.io/`](https://docs.chef.io/)。页面如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/79e49b87-d2a2-4def-be1d-2621304ed087.png)

1.  您可以参考文档中的 AWS Driver Resources 页面，了解如何通过 Chef 与各种 AWS 服务进行交互：[`docs.chef.io/provisioning_aws.html`](https://docs.chef.io/provisioning_aws.html)。页面如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/3db9fa23-9e46-4eb9-9f98-8f1040780be7.png)

1.  您还可以参考 aws Cookbook 来达到同样的目的。这个资源有非常好的文档和 API，可以与多个 AWS 服务进行交互。这个文档的 URL 是[`supermarket.chef.io/cookbooks/aws`](https://supermarket.chef.io/cookbooks/aws)。页面如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/95c29787-d6ca-49e0-95bc-4ad3fa8ffedb.png)

1.  当您向下滚动后，可以看到对 cookbook 的详细描述，直接在 cookbook 的标题之后。

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/2344f475-dc92-44ba-899b-d58d703e6bd6.png)

1.  另一个用于规划和编排软件资源的好工具是 Ansible。这有助于软件工程师通过 yaml 脚本自动化基础设施的多个部分。与 Chef 环境类似，这些脚本被称为**cookbooks**。

1.  我们将在随后的章节中使用这个工具来学习如何规划我们的基础设施。Ansible 的文档可以在[`docs.ansible.com/`](http://docs.ansible.com/)找到：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/c03b9e64-50de-416c-9e94-2764d847eefb.png)

1.  产品 ANSIBLE TOWER 超出了本书的范围。我们将学习并使用 ANSIBLE CORE，这是 Ansible 及其母公司 Red Hat 的旗舰产品。

1.  Ansible 有一个非常有用的视频，可以帮助您更好地理解和使用该工具。您可以在文档页面上单击快速入门视频链接来访问：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/f1e1efa6-0b68-4a68-9649-b7f3c53c5489.png)

1.  观看视频后，您可以继续从文档本身了解产品。可以在以下网址访问 Ansible 的完整文档：[`docs.ansible.com/ansible/latest/index.html`](http://docs.ansible.com/ansible/latest/index.html)：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/f06582a8-f9bf-41a2-8d05-8ec9f3bd1505.png)

1.  EC2 模块是我们将用于配置和编排 AWS EC2 实例的模块。该部分文档非常清晰地解释了如何启动和终止 EC2 实例，以及如何添加和挂载卷；它还使我们能够将我们的 EC2 实例配置到我们自己特定的**虚拟私有云**（**VPC**）和/或我们自己的**安全组**（**SGs**）中。EC2 文档屏幕如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/dc173ebc-4ff1-4bff-ad37-8cce256003ec.png)

1.  您可以在 Ansible Core 文档的以下 URL 找到：[`docs.ansible.com/ansible/latest/ec2_module.html`](http://docs.ansible.com/ansible/latest/ec2_module.html)。向下滚动后，您可以看到如何使用 Ansible 的 EC2 模块来处理 AWS EC2 实例的各种任务的几个示例。其中一些如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/76a160bd-a2dd-4913-8f0e-6fae8b2455dc.png)

# 服务器的创建和终止

在本章中，我们将学习如何使用一些第三方工具来帮助我们构建所需的架构。与本章中的所有部分一样，信息将被分解为步骤：

1.  我们将学习的第一个工具是 Ansible。它是一个配置和编排工具，可以帮助自动化基础架构的多个部分。根据您阅读本书的时间，Ansible 项目的主页（[`www.ansible.com/`](https://www.ansible.com/)）将看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/a5f8df9d-0b00-418c-8257-1a9ec9d33c1b.png)

1.  Ansible 的安装过程因不同操作系统而异。一些流行操作系统的说明如下：

+   +   **对于 Ubuntu**：

```py
sudo apt-get update
sudo apt-get install software-properties-common
sudo apt-add-repository ppa:ansible/ansible
sudo apt-get update
sudo apt-get install ansible
```

+   +   **对于 Linux**：

```py
git clone https://github.com/ansible/ansible.git
cd ./ansible
make rpm
sudo rpm -Uvh ./rpm-build/ansible-*.noarch.rpm
```

+   +   **对于 OS X**：

```py
sudo pip install ansible
```

1.  现在，我们将了解**nohup**的概念。因此，您不需要对服务器进行持久的 SSH 连接来运行`nohup`命令，因此我们将使用这种技术来运行我们的主-服务器架构（要了解更多关于 nohup 的信息，请参考：[`en.wikipedia.org/wiki/Nohup`](https://en.wikipedia.org/wiki/Nohup)）。

让我们来看看维基百科上对其的定义（在撰写本书时），**nohup**是一个忽略**HUP**（挂起）信号的**POSIX**命令。**HUP**信号是终端警告依赖进程注销的方式。

1.  现在，我们将学习如何从 Ansible 中配置服务器，通过 SSH 连接到它们，在其中运行简单的`apt-get update`任务，并终止它们。通过这个，您将学习如何编写 Ansible 脚本，以及了解 Ansible 如何处理云资源的配置。以下 Ansible 脚本将帮助您了解如何配置 EC2 实例：

```py
- hosts: localhost
  connection: local
  remote_user: test
  gather_facts: no

  environment:
    AWS_ACCESS_KEY_ID: "{{ aws_id }}"
    AWS_SECRET_ACCESS_KEY: "{{ aws_key }}"

    AWS_DEFAULT_REGION: "{{ aws_region }}"

  tasks: 
- name: Provisioning EC2 instaces 
  ec2: 
    assign_public_ip: no
    aws_access_key: "{{ access_key }}"
    aws_secret_key: "{{ secret_key }}"
    region: "{{ aws_region }}"
    image: "{{ image_instance }}"
    instance_type: "{{ instance_type }}"
    key_name: "{{ ssh_keyname }}"
    state: present
    group_id: "{{ security_group }}"
    vpc_subnet_id: "{{ subnet }}"
    instance_profile_name: "{{ Profile_Name }}"
    wait: true
    instance_tags: 
      Name: "{{ Instance_Name }}" 
    delete_on_termination: yes
    register: ec2 
    ignore_errors: True
```

`{{ }}`括号中的值需要根据您的方便和规格填写。上述代码将根据`{{ Instance_Name }}`部分的规格在您的控制台中创建一个 EC2 实例并命名它。

1.  `ansible.cfg`文件应包括所有关于控制路径、有关转发代理的详细信息，以及 EC2 实例密钥的路径。`ansible.cfg`文件应如下所示：

```py
[ssh_connection]
ssh_args=-o ControlMaster=auto -o ControlPersist=60s -o ControlPath=/tmp/ansible-ssh-%h-%p-%r -o ForwardAgent=yes

[defaults]
private_key_file=/path/to/key/key.pem
```

1.  当您使用`ansible-playbook -vvv < playbook 名称 >.yml`执行此代码时，您可以在 EC2 控制台中看到 EC2 实例被创建：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/990b02ae-a1cb-4ada-80dd-6fbb6d11cfa4.png)

1.  现在，我们将终止通过 Ansible 刚刚创建的实例。这也将在一个类似于我们提供实例的 Ansible 脚本中完成。以下代码执行此操作：

```py
  tasks:
    - name: Terminate instances that were previously launched
      connection: local
      become: false
      ec2:
        state: 'absent'
        instance_ids: '{{ ec2.instance_ids }}'
        region: '{{ aws_region }}'
      register: TerminateWorker
      ignore_errors: True
```

1.  现在，您可以在控制台中看到实例被终止。请注意，直到任务（例如提供和终止实例）的代码都是相同的，因此您可以从提供任务中复制并粘贴：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/b3afa19c-951b-4671-af4e-c7bbc7a2d624.png)

因此，我们已成功学习了如何通过 Ansible 脚本提供和终止 EC2 实例。我们将使用这些知识进行提供，并将同时终止 EC2 实例。

1.  通过对我们之前使用的 yaml 脚本中的提供代码进行小的更改，我们可以通过简单添加`count`参数来同时提供多个服务器（EC2 实例）。以下代码将根据*jinja 模板*中指定的实例数量提供实例，旁边是`count`参数。在我们的示例中，它是`ninstances`：

```py
- hosts: localhost
  connection: local
  remote_user: test
  gather_facts: no

  environment:
    AWS_ACCESS_KEY_ID: "{{ aws_id }}"
    AWS_SECRET_ACCESS_KEY: "{{ aws_key }}"

    AWS_DEFAULT_REGION: "{{ aws_region }}"

  tasks: 
- name: Provisioning EC2 instaces 
  ec2: 
    assign_public_ip: no
    aws_access_key: "{{ access_key }}"
    aws_secret_key: "{{ secret_key }}"
    region: "{{ aws_region }}"
    image: "{{ image_instance }}"
    instance_type: "{{ instance_type }}"
    key_name: "{{ ssh_keyname }}"
    count: "{{ ninstances }}"
    state: present
    group_id: "{{ security_group }}"
    vpc_subnet_id: "{{ subnet }}"
    instance_profile_name: "{{ Profile_Name }}"
    wait: true
    instance_tags: 
      Name: "{{ Instance_Name }}" 
    delete_on_termination: yes
    register: ec2 
```

1.  现在，我们的 Ansible 脚本已经准备好了，我们将使用它来从 Lambda 函数启动我们的基础架构。为此，我们将利用我们对 nohup 的知识。

1.  在 Lambda 函数中，您只需要编写创建服务器的逻辑，然后使用库`paramiko`进行一些基本安装，然后以 nohup 模式运行 Ansible 脚本，如下所示：

```py
import paramiko
import boto3
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.CRITICAL)
region = 'us-east-1'
image = 'ami-<>'
ubuntu_image = 'ami-<>'
keyname = '<>'

def lambda_handler(event, context):
    credentials = {<>}
    k = paramiko.RSAKey.from_private_key_file("<>")
        c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    logging.critical("Creating Session")
    session = boto3.Session(credentials['AccessKeyId'], 
    credentials['SecretAccessKey'],
    aws_session_token=credentials['SessionToken'], region_name=region)
    logging.critical("Created Session")
    logging.critical("Create Resource")
    ec2 = session.resource('ec2', region_name=region)
    logging.critical("Created Resource")
    logging.critical("Key Verification")

    key = '<>'
    k = paramiko.RSAKey.from_private_key_file(key)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    logging.critical("Key Verification done")
    # Generate Presigned URL for downloading EC2 key from    an S3 bucket into master
    s3client = session.client('s3')

# Presigned url for downloading pem file of the server from an S3 bucket
    url = s3client.generate_presigned_url('get_object',     Params={'Bucket': '<bucket_name>', 'Key': '<file_name_of_key>'},
ExpiresIn=300)
    command = 'wget ' + '-O <>.pem ' + "'" + url + "'"
    logging.critical("Create Instance")

while True:
    try:
        logging.critical("Trying")
        c.connect(hostname=dns_name, username="ubuntu", pkey=k)
    except:
        logging.critical("Failed")
    continue
        break
    logging.critical("connected")

    if size == 0:
        s3client.upload_file('<>.pem', '<bucket_name>', '<>.pem')
    else:
        pass
    set_key = credentials['AccessKeyId']
    set_secret = credentials['SecretAccessKey']
    set_token = credentials['SessionToken']

# Commands to run inside the SSH session of the server
    commands = [command,
"sudo apt-get -y update",
"sudo apt-add-repository -y ppa:ansible/ansible",
"sudo apt-get -y update",
"sudo apt-get install -y ansible python-pip git awscli",
"sudo pip install boto markupsafe boto3 python-dateutil     futures",
"ssh-keyscan -H github.com >> ~/.ssh/known_hosts",
"git clone <repository where your ansible script is> /home/ubuntu/<>/",
"chmod 400 <>.pem",
"cd <>/<>/; pwd ; nohup ansible-playbook -vvv provision.yml > ansible.out 2> ansible.err < /dev/null &"]

# Running the commands
    for command in commands:
        logging.critical("Executing %s", command)
stdin, stdout, stderr = c.exec_command(command)
    logging.critical(stdout.read())
    logging.critical("Errors : %s", stderr.read())
        c.close()
    return dns_name
```

# 安全最佳实践

确保高级别安全始终是微服务的主要问题。在设计安全层时，您需要牢记多个软件层次。工程师需要为每个服务定义安全协议，然后还需要定义每个服务之间的数据交互和传输的协议。

在设计分布式无服务器系统时，必须牢记所有这些方面，其中（几乎）每个 Ansible 任务都是一个微服务。在本节中，我们将了解如何设计安全协议，并使用一些 AWS 内置服务对其进行监视。

我们将逐步了解如何为我们的无服务器架构编写安全协议：

1.  首先，每当您在 AWS Python 脚本中使用**Boto**创建会话时，请尝试使用**AWS 安全令牌服务**（**STS**）创建特定时间段的临时凭证：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/98dcd848-36f3-4826-a507-c80f00238c0c.png)

您可以查看 STS 的文档：[`docs.aws.amazon.com/STS/latest/APIReference/Welcome.html`](https://docs.aws.amazon.com/STS/latest/APIReference/Welcome.html)。

1.  STS 服务的 AssumeRole API 使程序员能够在其代码中扮演 IAM 角色：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/9e6c5386-d7ca-4e42-a57e-ff04caa651ed.png)

您可以在以下页面找到其文档：[`docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html`](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)

1.  可以在`boto3`文档中查看其 Python 版本：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/aee5b2d3-3237-4904-b005-8b7a07fe24bf.png)

此文档可以在此处找到：[`boto3.readthedocs.io/en/latest/reference/services/sts.html`](http://boto3.readthedocs.io/en/latest/reference/services/sts.html)。

1.  向下滚动，您可以在 Python 中找到 AssumeRole API 的用法：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/76e319b3-f47d-46e0-b9e5-645ef255f222.png)

1.  必须小心确保微服务之间和/或微服务与其他 AWS 资源之间的数据交换在进行身份验证的情况下安全进行。例如，开发人员可以配置 S3 存储桶以限制诸如未加密上传、下载和不安全文件传输等操作。存储桶策略可以编写如下以确保所有这些事项得到处理：

```py
{
    "Version": "2012-10-17",
    "Id": "PutObjPolicy",
    "Statement": [
    {
        "Sid": "DenyIncorrectEncryptionHeader",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:PutObject",
        "Resource": "arn:aws:s3:::<bucket_name>/*",
        "Condition": {
            "StringNotEquals": {
                "s3:x-amz-server-side-encryption": "aws:kms"
            }
        }
    },
    {
        "Sid": "DenyUnEncryptedObjectUploads",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:PutObject",
        "Resource": "arn:aws:s3:::<bucket_name2>/*",
        "Condition": {
            "Null": {
                "s3:x-amz-server-side-encryption": "true"
            }
        }
    },
    {
        "Sid": "DenyNonSecureTraffic",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": "arn:aws:s3:::<bucket_name>/*",
        "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    },
    {
        "Sid": "DenyNonSecureTraffic",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": "arn:aws:s3:::<bucket_name2>/*",
        "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    }
]
}
```

1.  完成编写存储桶策略后，您可以在 S3 的 Bucket Policy 部分中更新它：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/332d132a-0366-4b37-b119-3474624a7d2c.png)

1.  AWS Config 提供了一个非常有用的界面，用于监控多种安全威胁，并帮助有效地避免或捕捉它们。AWS Config 的仪表板如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/ea5571d8-5cd9-4bbe-8f44-fab3b7e1c5e5.png)

1.  您可以看到仪表板显示了 2 个不符合规定的资源，这意味着我的两个 AWS 资源不符合我在配置中设置的规则。让我们看看这些规则：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/0703fc51-40ff-47c6-968d-e74dbdbd3861.png)

这意味着我们有两个 AWS S3 存储桶，这些存储桶没有通过存储桶策略打开 SSL 请求。单击“规则”链接后，您可以看到更多详细信息，包括存储桶名称，以及记录这些配置更改的时间戳：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/c43909d7-bff5-440e-85b2-fc0e407cbe12.png)

# 识别和处理扩展中的困难

扩展分布式无服务器系统会遇到一系列工程障碍和问题，事实上，无服务器系统的概念仍处于非常幼稚的阶段，这意味着大多数问题仍未解决。但是，这不应该阻止我们尝试解决和克服这些障碍。

我们将尝试了解一些这些障碍，并学习如何解决或克服它们，如下所述：

+   这更多是架构师的错误，而不是障碍。然而，重要的是要将其视为一个障碍，因为太多的架构师/软件工程师陷入了高估或低估的陷阱。我们将尝试解决的问题是在扩展时必须启动的确切实例数量。在大多数自托管的 MapReduce 风格系统中，这是开箱即用的。

+   通过在不同类型的实例上事先对工作负载进行适当的基准测试，并相应地进行扩展，可以解决这个问题。让我们通过以机器学习管道为例来理解这一点。由于我们的基准测试工作，我们已经知道*m3.medium*实例可以在 10 分钟内处理 100 个文件。因此，如果我的工作负载有 202 个文件，并且我希望在接近 10 分钟内完成，我希望有两个这样的实例来处理这个工作负载。即使我们事先不知道工作负载，我们也可以编写一个 Python 脚本，从数据存储中获取该数字，无论是 SQS 队列指针、S3 还是其他数据库；然后将该数字输入到 Ansible 脚本中，并运行 playbook。

+   由于我们已经了解了如何处理大型无服务器系统中的安全性，我们将简要介绍一下。在大型分布式无服务器工作负载中会发生多个复杂的数据移动。使用适当的安全协议并监控它们，如前面安全部分中详细提到的，将有助于克服这个问题。

+   日志记录是分布式无服务器系统中的一个主要问题，也是一个尚未完全解决的问题。由于系统和容器在工作负载完成后被销毁，日志记录一直是一项非常困难的任务。您可以通过几种方式记录工作流程。最流行的方法是分别记录每个 Ansible 任务，还有一个是最后一个 Ansible 任务是将日志打包并将压缩文件发送到数据存储，如 S3 或 Logstash。最后一种方法是最受欢迎的，因为它更好地捕获了执行流程，整个日志跟踪都在一个文件中。

+   监控类似于日志记录。监控这些系统也大多是一个未解决的问题。由于服务器在工作负载运行后全部终止，我们无法从服务器中轮询历史日志，并且延迟也不会被容忍，或者更准确地说，不可能。通过在每个任务后执行一个任务，根据前一个任务是否成功执行发送自定义指标到 CloudWatch 来监视 Ansible 的每个任务。这将看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/97c4c19a-d7dc-4534-9e9b-366b1df91347.png)

+   调试试运行也可能变得非常令人沮丧，非常快。这是因为，如果你不够快，整个系统可能在你甚至没有机会查看日志之前就被终止。此外，在调试时，Ansible 会发出非常冗长的日志，当生成多个实例时可能会显得很压倒。

+   一些基本的 Unix 技巧可以帮助处理这些问题。最重要的是监视日志文件的末尾，大约 50 行左右。这有助于不被大量日志所压倒，也可以监视 Ansible 笔记本的执行情况。

# 总结

在本章中，我们学习了如何将我们的无服务器架构扩展到大规模分布式的无服务器基础设施。我们学会了如何在现有的 Lambda 基础设施的基础上处理大量工作负载。

我们学会了使用 nohup 的概念，将我们的 Lambda 函数用作构建主-工作者架构的启动板，以考虑并行计算。我们学会了如何利用配置和编排工具，如 Ansible 和 Chef，来生成和编排多个 EC2 实例。

从本章中获得的知识将为构建许多复杂的基础设施打开大门，这些基础设施可以处理数据和请求，无论是在大小还是速度上。这将使您能够操作多个微服务紧密相互交织在一起。这也将帮助您构建类似 MapReduce 的系统，并与其他 AWS 服务无缝交互。


# 第七章：AWS Lambda 中的安全性

我们已经学会了如何在 AWS Lambda 中构建和配置无服务器函数。我们已经学会了如何使用第三方工具扩展它们。我们还仔细研究了微服务的工作原理以及如何在其中确保安全性，同时确保弹性和速度。

在本章中，我们将了解 AWS 环境中的安全性，牢记我们的 Lambda 函数。我们将了解 AWS VPC、安全组和子网等服务与 Lambda 函数相关的工作原理。

本章涵盖以下主题：

+   了解 AWS VPCs

+   了解 VPC 中的子网

+   在私有子网中保护 Lambda

+   控制对 Lambda 函数的访问

+   在 Lambda 中使用 STS 进行安全的基于会话的执行

# 了解 AWS 虚拟私有云（VPC）

在本节中，我们将了解 AWS VPC。VPC 是 AWS 环境安全层中非常常见的组件；它们是云中的隔离部分，用户可以在其中托管其服务并构建基础设施。VPC 是安全的第一层。我们将尝试以项目符号的形式了解 VPC 在 Lambda 函数的上下文中的情况，如下所示：

1.  VPC 可以在 AWS 的 VPC 服务仪表板中创建和修改，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/3c3762c6-8790-4917-83b0-be9140b15f4d.png)

1.  现在，让我们快速学习如何创建自己的 VPC。为此，请单击“创建 VPC”。您将看到一个弹出框，要求您为新 VPC 输入更多元信息：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/05c269c0-509c-4726-884e-3d3d35591a58.png)

1.  名称标签框需要有 VPC 的名称。IPv4 CIDR 块是您为无类域间路由输入 IP 范围的地方。然后，您可以选择是否要 IPv6 CIDR 块。您还可以选择租户设置；这定义了您的 EC2 实例在 VPC 内的运行方式，以及相应的资源共享：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/bfb7cd21-79f7-4ca8-b951-67ace4d70362.png)

1.  我们已成功创建了具有必要设置和`Test-VPC`名称的 VPC。我们可以在仪表板上看到所有相应的元设置：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/8d2eafa5-fc67-4646-9bb3-ea6540b3ef71.png)

1.  您还可以查看 VPC 的摘要，其中包括 IPv4 设置、网络访问控制列表（ACL）设置、动态主机配置协议（DHCP）选项以及 DNS 设置，所有这些都可以根据我们的需求稍后进行配置。您还可以在“下一个 CIDR 块”选项卡下看到 IPv4 CIDR 块：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/95d20d08-7ee2-46a2-9544-0a57761b849a.png)

1.  我们还可以创建 VPC 流日志，记录进出 VPC 的流量和数据移动。这将促进更好的日志管理，确保安全性和更好的监控。目前，流日志尚未设置：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/a5b7913b-6f53-4929-9df0-02f3822ad360.png)

1.  要创建 VPC 流日志，您只需单击底部的“创建流日志”按钮。这将打开一个流日志创建向导，在其中您可以根据需要输入各种设置的详细信息。创建向导看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/6ff42f25-88e5-4c11-8f2f-9951893653e0.png)

1.  一旦输入了所有细节，您可以继续并点击底部的“创建流日志”选项，这将使用所需的设置创建 VPC 流日志：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/f657e092-032b-4488-a685-aa60fbbb6414.png)

1.  创建后，您可以在“流日志”选项卡下看到新创建的 VPC 流日志，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/c8f5cc05-8d7f-47d3-8e6f-1131ae27f94a.png)

1.  现在，让我们从 AWS Lambda 的角度了解 VPCs。就像任何其他 AWS 资源一样，Lambda 函数也可以托管在 VPC 内。您可以在 AWS Lambda 函数的“网络”部分中看到该设置。它看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/f56b1d48-07c6-4632-a861-1dffa46dcfd4.png)

1.  从下拉列表中，您可以选择要托管 Lambda 函数的 VPC：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/830ca55c-9173-4960-a2dd-b8ae008ab76e.png)

1.  选择 VPC 后，它将进一步要求您输入有关子网、安全组等的详细信息，如下面的屏幕截图所示。我们将在接下来的部分中了解它们，因此，我们稍后将为 Lambda 函数配置 VPC：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/39fb6710-baff-401c-910a-e386c2af07e9.png)

# 了解 VPC 中的子网

在本节中，我们将学习和了解 AWS 子网，这些是 AWS VPC 的子部分。VPC 可以进一步划分为多个子网。这些子网可以根据架构的安全需求分为公共或私有。我们将从 AWS Lambda 函数的角度来看子网的概念。

我们将执行以下步骤：

1.  您可以通过 VPC 页面本身转到子网菜单。您需要在左侧的“您的 VPCs”选项下单击“子网”选项：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/816d6fed-9461-4052-abf5-0ae138b16a8a.png)

1.  这将带您进入子网控制台，在那里您将看到一些已经存在的子网。这些是您所在区域每个可用区的默认子网：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/46cc3156-ead4-4571-a4cd-7338e9c1b7ec.png)

1.  现在，要创建新的子网，您需要单击控制台左上角的蓝色“创建子网”按钮。在创建向导中，您将被要求输入以下详细信息-子网的名称、要放置的 VPC、可用区以及首选的 IPv4 CIDR 块。我已将此子网放在了我们在上一节中创建的 VPC 中：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/e671fcdc-7f96-4d47-a99e-9d36d675418c.png)

1.  当您在创建向导的右下方单击“是，创建”按钮时，新的子网将被创建。您可以在控制台上的子网列表中看到它：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/39f11fcc-ef44-4aed-8850-169adf828115.png)

1.  现在，我们将使用刚刚创建的 VPC 和子网填写 Lambda 函数的安全设置。目前，AWS Lambda 的网络设置如下：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/ba7a0cd2-dc7a-4f33-bf3b-fac817f51bb1.png)

1.  在添加所需的设置后，即 VPC、子网和安全组的详细信息后，我们的 Lambda 函数的网络设置将如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/f566c9d4-69a5-4d3d-b0a1-8b77bc44dc2c.png)

...![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/452cf8d2-5e41-489c-85d5-84ab3fae0f98.png)

1.  设置 Lambda 函数的网络设置后，单击 Lambda 控制台右上角的橙色“保存”按钮，将这些设置保存到 Lambda 函数中。

# 在私有子网中保护 Lambda

**私有子网**是不对互联网开放的子网。它们的所有流量都通过同一 VPC 中的公共子网使用路由表的概念进行路由。让我们了解如何将我们的 Lambda 函数放在私有子网中以增加额外的安全层：

1.  在 AWS 控制台中创建的子网默认情况下不是私有的。让我们通过查看刚刚创建的子网的详细信息来评估和确认这一点：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/9aa312f6-84ce-4f26-a6ae-0bd9838d5fef.png)

1.  单击“路由表”选项卡将显示子网的路由设置，基本上告诉我们允许进入子网的是什么类型的流量：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/bcb498f4-e225-472c-998c-b38b7f44f5a8.png)

1.  在“网络 ACL”选项卡中，您可以看到为我们的子网分配的网络规则。在这里，我们可以看到子网对所有流量（0.0.0.0/0）都是开放的。因此，为了使我们的子网变为私有，我们需要修复这个问题：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/1f89e289-50ab-457d-80c5-6e55a940d56e.png)

1.  通过单击控制台左侧的链接，转到网络 ACLs 控制台。您将进入以下页面：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/3f01d910-b977-4ef2-af40-71052ce5a097.png)

1.  现在，单击“创建网络 ACL”蓝色按钮以创建新的 ACL。在创建向导中选择我们的 VPC，然后为 ACL 输入名称：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/117d9fa7-b119-4019-bfe0-d5398ccfebb7.png)

1.  现在，在新 ACL 的入站规则中，添加以下规则。在“来源”部分，添加任何公共子网的 IPv4 设置，然后单击保存：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/eec95e92-7393-49bf-b225-ce3c956cca57.png)

1.  现在，用新的 ACL 替换当前子网的 ACL，使我们的子网成为私有子网：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-app-py/img/4634f40c-262b-46f6-bf21-4da5234d2118.png)

现在，我们的 Lambda 函数位于私有子网中，使其更加安全。

# 控制对 Lambda 函数的访问

我们已经了解了确保 Lambda 函数和无服务器架构安全所需的所有安全设置。因此，从安全角度设计基于无服务器系统的工程师应该牢记以下几点：

+   VPC 和子网设置可以添加到 Lambda 函数的“网络”部分。

+   建议将 Lambda 函数放置在至少两个子网中以实现容错目的。但这并非强制性要求。

+   如果您将 Lambda 函数放置在私有子网中，您需要确保私有子网从 VPC 中的公共子网中接收到适当的流量。如果没有，那么 Lambda 函数基本上被锁定了。

# 在 Lambda 中使用 STS 进行安全的基于会话的执行

在 Lambda 函数内访问其他 AWS 服务和组件时，您可以利用**AWS 的简单令牌服务**（**STS**）来确保基于会话的访问，这将在实质上增加一层额外的安全性。正如我们已经讨论过并学会如何在代码中使用 STS 凭据，我们将跳转到文档链接。

AWS STS 的官方文档将帮助您了解会话访问的工作原理：[`docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html`](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html)。

这是在 Python 代码中使用 STS 凭据的*Boto3 Python 文档*：[`boto3.readthedocs.io/en/latest/reference/services/sts.html`](http://boto3.readthedocs.io/en/latest/reference/services/sts.html)。

# 总结

在本章中，我们深入学习了 Lambda 函数中的安全性工作原理。我们了解了 VPC 和子网在 AWS 环境中的工作原理。我们学会了创建 VPC，并创建了公共和私有子网。这将让您更好地了解安全性是如何从整个 AWS 视角工作的。

我们还学会了如何将 Lambda 函数放置在我们在本章中创建的 VPC 和子网中。我们了解了如何在 VPC 和子网内处理和路由流量。

最后，我们还学会了如何通过基于会话的访问实现 Python 代码的更好安全性，从而将安全性置于开发人员的控制之下。

在下一章中，您将学习**无服务器应用程序模型**（**SAM**）以及如何编写 SAM 模型并通过它们部署 Lambda 应用程序。
