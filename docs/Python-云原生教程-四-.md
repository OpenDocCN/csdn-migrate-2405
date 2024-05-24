# Python 云原生教程（四）

> 原文：[`zh.annas-archive.org/md5/7CEC2A066F3DD2FF52013764748D267D`](https://zh.annas-archive.org/md5/7CEC2A066F3DD2FF52013764748D267D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：在 Azure 平台上实施

在上一章中，我们看到了一个用于托管我们的应用程序的云计算平台--AWS--其中包含了所有功能，以使应用程序具有高可用性，并且没有停机时间。在本章中，我们将讨论另一个名为**Microsoft Azure**的云平台。

本章包括以下主题：

+   介绍 Microsoft Azure

+   构建应用程序基础设施 Azure 服务

+   使用 Jenkins 与 Azure 进行 CI/CD

# 开始使用 Microsoft Azure

正如其名称所示，Microsoft Azure 是由微软拥有的公共云平台，为其客户提供不同的 PaaS 和 IaaS 服务。一些流行的服务包括虚拟机、应用服务、SQL 数据库、资源管理器等。

Azure 服务主要分为这两个类别：

+   **平台服务**：这些是为客户提供环境来构建、管理和执行他们的应用程序，同时自行处理基础架构的服务。以下是一些 Azure 服务按其各种类别：

+   **管理服务**：这些提供了管理门户和市场服务，提供了 Azure 中的图库和自动化工具。

+   **计算**：这些是诸如 fabric、函数等服务，帮助开发人员开发和部署高度可扩展的应用程序。

+   **CDN 和媒体**：这些分别提供全球范围内安全可靠的内容传递和实时流媒体。

+   **Web +移动**：这些是与应用程序相关的服务，如 Web 应用程序和 API 应用程序，主要用于 Web 和移动应用程序。

+   **分析**：这些是与大数据相关的服务，可以帮助机器学习开发人员进行实时数据处理，并为您提供有关数据的见解，如 HDInsight、机器学习、流分析、Bot 服务等。

+   **开发工具**：这些服务用于版本控制、协作等。它包括 SDK 等。

+   **AI 和认知服务**：这些是基于人工智能的服务，例如语音、视觉等。一些提供此类服务的服务包括文本分析 API、认知等。

+   **基础设施服务**：这些是服务提供商负责硬件故障的服务。服务器的定制是客户的责任。客户还管理其规格：

+   **服务器计算和容器**：这些是虚拟机和容器等服务，为客户应用程序提供计算能力。

+   **存储**：这些分为两种类型--BLOB 和文件存储。根据延迟和速度提供不同的存储能力。

+   **网络**：这些提供了一些与网络相关的服务，如负载均衡器和虚拟网络，可以帮助您保护网络，并使其对客户响应更加高效。

以下图表将更好地理解 Azure 平台：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00187.jpeg)

您可以在以下链接详细查看所有 Microsoft Azure 产品提供：

[`azure.microsoft.com/en-in/services/`](https://azure.microsoft.com/en-in/services/)

要开始使用 Microsoft Azure，您需要拥有一个账户。由于本章涉及在 Azure 上实施我们的应用程序，我们不会介绍如何创建账户。如果您需要帮助，可以阅读以下链接中的文章，这将确实帮助您：

[`medium.com/appliedcode/setup-microsoft-azure-account-cbd635ebf14b`](https://medium.com/appliedcode/setup-microsoft-azure-account-cbd635ebf14b)

Azure 提供了一些基于 SaaS 的服务，您可以在[`azuremarketplace.microsoft.com/en-us`](https://azuremarketplace.microsoft.com/en-us)上查看。

# 关于 Microsoft Azure 基础知识的几点

一旦您准备好并登录到您的 Azure 账户，您将被重定向到 Azure 门户([`portal.azure.com`](https://portal.azure.com))，它将展示 Azure 服务。最初，Azure 提供了一个免费账户，并为您的使用提供了价值为 200 美元的信用额，有效期为 30 天。微软 Azure 也支持按需付费模式，当您用完所有免费信用后，可以切换到付费账户。

以下是您在继续之前应该了解的一些 Azure 基本概念：

+   **Azure 资源管理器**: 最初，Azure 基于一种称为**ASM**(**Azure 服务管理器**)的部署模型。在最新版本的 Azure 中，采用了**ARM**(**Azure 资源管理器**)，它提供了高可用性和更灵活性。

+   **Azure 区域**: 全球分布约 34 个区域。

+   Azure 区域列表可在[`azure.microsoft.com/en-us/regions/`](https://azure.microsoft.com/en-us/regions/)上找到。

+   特定区域所有服务的列表可在[`azure.microsoft.com/en-us/regions/services/`](https://azure.microsoft.com/en-us/regions/services/)上找到。

+   **Azure 自动化**: Azure 提供了许多模板在不同的基于 Windows 的工具中，如 Azure-PowerShell，Azure-CLI 等。您可以在[`github.com/Azure`](https://github.com/Azure)找到这些模板。

由于 Azure 是由微软拥有的，我们将主要在 Azure 控制台(UI)上工作，并通过它创建资源。Azure 环境非常适合喜欢在 Windows 系统上部署他们的应用程序的开发人员或 DevOps 专业人员，他们的应用程序是用.NET 或 VB 编写的。它还支持最新的编程语言，如 Python，ROR 等。

对于喜欢在 Microsoft 产品上工作的人来说，Microsoft Azure 是理想的选择，比如 Visual Studio。

# 使用 Azure 架构我们的应用基础设施

一旦您进入 Azure 门户，您应该在屏幕上看到以下默认仪表板：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00188.jpeg)

现在是时候在 MS Azure 上架构我们的应用基础设施了。我们将按照下面给出的架构图创建我们在 Azure 上的生产环境：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00189.jpeg)

在这个架构中，我们将使用一些 Azure 服务，它们如下：

+   **虚拟机**: 这类似于我们在 AWS 中的 EC2 机器。我们将在虚拟机中部署我们的应用程序和 MongoDB 服务器。

+   **虚拟网络**: 虚拟网络在 AWS 中等同于 VPC，需要创建以保持我们的通信网络安全。

+   **存储**: 每个虚拟机都由一个存储账户支持，我们不需要显式创建，因为它会随着虚拟机一起创建来存储您的数据。

+   **负载均衡器**: 这个负载均衡器的使用与 AWS 中的负载均衡器相同，但它们在算法上有轻微的变化，因为 Azure 主要遵循基于哈希的平衡或源 IP 算法，而 AWS 遵循轮询算法或粘性会话算法。

+   **DNS**: 当我们有域名注册时，DNS 很有用，我们需要从 Azure 管理我们的 DNS。在云平台中，我们称之为**区域**。

+   **子网**: 我们将在虚拟网络中创建一个子网，以区分我们的资源，这些资源需要面向互联网或不需要。

+   **自动扩展**: 我们在图中没有提到这一点，因为它取决于您的应用需求和客户响应。

因此，让我们开始创建我们的应用服务器(即虚拟机)，我们的应用程序将驻留在其中。

正如我之前提到的，Azure 有一个非常用户友好的 UI，它会根据您定义的资源在后台创建程序代码，并使用资源管理器将其提供给您，这使得 DevOps 工程师的工作更加轻松。

# 在 Azure 中创建虚拟机

按照下面列出的步骤在 Microsoft Azure 中创建一个虚拟机：

1.  转到 Azure 仪表板，并在左侧面板中选择 新建 以启动 VM 向导，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00190.jpeg)

1.  现在我们需要选择要启动的操作系统。我们将在列表中选择 **Ubuntu Server 16.04 LTS** 服务器选项（我们选择此选项，因为我们的应用程序是在 Ubuntu 操作系统上开发的）。

在接下来的屏幕中，我们需要选择部署模型。有两种部署模型可用。它们是经典型（标准 VM）和资源管理器（高可用性 VM）。选择资源管理器模型，如下截图所示，然后点击 创建 按钮继续：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00191.jpeg)![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00192.jpeg)

1.  在下一个屏幕上，我们需要提供 VM 的用户名和身份验证方法，如下截图所示；点击 确定 继续：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00193.jpeg)

1.  接下来，我们需要根据需求选择虚拟机的大小。我们将选择标准型的 DS1_V2。选择它，然后点击页面底部的 选择 按钮，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00194.jpeg)

1.  在下一个屏幕中，我们将定义一些可选细节，如网络、子网、公共 IP 地址、安全组、监视等：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00195.jpeg)

每次创建虚拟网络时，都建议创建一个虚拟网络，并通过单击虚拟网络进行选择。在管理和非管理磁盘方面，我更喜欢管理磁盘。这是因为在非管理磁盘中，我们选择创建存储帐户，而且由于我们为多个应用服务器创建它，每个应用服务器将有其单独的存储帐户。所有存储帐户可能都会落入单个存储单元，这可能导致单点故障。另一方面，在管理磁盘的情况下，Azure 通过将我们的磁盘存储在单独的存储单元中来管理我们的磁盘，这使其高度可用。

如果您不提供这些细节，系统将自动设置。

1.  在下一个屏幕中，我们需要审查向导中定义的所有细节，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00196.jpeg)

1.  在页面底部，您将找到一个链接，该链接将使您能够以模板形式或以不同语言的代码形式下载完整的配置。请参阅以下截图，显示了我们提供的配置生成的代码：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00197.jpeg)

1.  点击 确定 开始部署虚拟机。

现在，我们的仪表板应该在一段时间后运行一个 VM，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00198.jpeg)

现在您可以访问虚拟机，下载您的应用程序，并像在本地机器上一样部署它。

同样，我们可以为您的应用程序创建多个 VM 实例，作为应用服务器。

此外，我们可以创建一个带有 MongoDB 服务器安装的 VM。您需要遵循的安装步骤与我们在第四章中定义的步骤类似，*交互式数据服务*。

我们可以通过单击仪表板上的 VM（即 appprod）图标来查看 VM 的性能，应该如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00199.jpeg)

接下来，我们需要将之前创建的应用服务器添加到负载均衡器中。因此，我们需要按以下步骤创建负载均衡器：

+   转到 [`portal.azure.com/?whr=live.com#blade/HubsExtension/Resources/resourceType/Microsoft.Network%2FLoadBalancers`](https://portal.azure.com/?whr=live.com#blade/HubsExtension/Resources/resourceType/Microsoft.Network%2FLoadBalancers)，并点击屏幕中央的创建负载均衡器按钮，如下截图所示：

+   在下一个屏幕中，我们需要指定 LB 名称，并提供 LB 用途的类型。我们可以在此处启动 ELB，与您的应用服务器在同一组中，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00200.jpeg)

单击“创建”按钮以启动 LB 创建。

1.  一旦负载均衡器准备好供我们使用，我们应该能够看到以下屏幕，显示其详细信息：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00201.jpeg)

1.  接下来，我们需要添加后端池，即我们的应用服务器，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00202.jpeg)

1.  现在我们需要添加健康探测，即您的应用程序的健康状态，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00203.jpeg)

接下来，我们将按照这里所示的方式为我们的应用程序添加前端池。

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00204.jpeg)

现在我们已经为我们的应用程序设置好了负载均衡器。

您可以在 Azure 文档的此链接中阅读有关负载均衡器的更多信息：[`docs.microsoft.com/en-us/azure/load-balancer/load-balancer-overview`](https://docs.microsoft.com/en-us/azure/load-balancer/load-balancer-overview)

现在，我们已经根据我们的架构图创建了基础设施。是时候为我们在 Azure 基础设施上部署应用程序配置 Jenkins 了。

# 使用 Jenkins 和 Azure 进行 CI/CD 流水线

首先，我们需要转到活动目录服务，您可以在下一个截图中看到：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00205.jpeg)

现在我们需要注册我们的应用程序，因此，请在左窗格中选择“应用程序注册”。您将看到一个类似于下一个屏幕的屏幕，在那里您需要提供您的应用程序详细信息：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00206.jpeg)

1.  之后，您将能够生成访问 Jenkins 作业所需的密钥。

1.  您将看到下一个屏幕，其中包含秘密密钥的详细信息，您还将在同一页上找到其他详细信息，例如“对象 ID”和“应用程序 ID”：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00207.jpeg)

现在我们有了配置 Jenkins 作业所需的信息。因此，请转到 Jenkins 控制台，在“管理 Jenkins”部分中的“管理插件”中安装插件“Azure VM 代理”。

安装插件后，转到“管理 Jenkins”，单击“配置系统”，如下一个截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00208.jpeg)

在下一个屏幕中，滚动到名为 Cloud 的底部部分，单击“添加云”按钮，并选择新的 Microsoft Azure VM 代理选项。这将在同一页上生成一个部分。

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00209.jpeg)

您可以在其文档中阅读有关 MS Azure VM 代理插件的更多信息（[`wiki.jenkins.io/display/JENKINS/Azure+VM+Agents+plugin`](https://wiki.jenkins.io/display/JENKINS/Azure+VM+Agents+plugin)）。

在最后一个屏幕中，您需要添加之前生成的 Azure 凭据。如果您单击下一个屏幕中可以看到的“添加”按钮，您可以添加诸如“订阅 ID”等值：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00210.jpeg)

在同一部分的下一部分，您需要提供 VM 的详细配置，例如模板、VM 类型等：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00211.jpeg)

在上面的截图中，标签是最重要的属性，我们将在 Jenkins 作业中使用它来识别该组。

现在，您需要提供您想要执行的操作，也就是说，如果您想要部署您的应用程序，您可以提供下载代码并运行应用程序的命令。

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00212.jpeg)

单击“保存”以应用设置。

现在，在 Jenkins 中创建一个新的作业。此外，在 GitBucket 部分，您通常提供存储库详细信息的地方，您将找到一个新的复选框，称为“限制此项目可以运行的位置”，并要求您提供标签表达式名称。在我们的情况下，它是`msubuntu`。就是这样！

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00213.jpeg)

现在我们已经准备好运行我们的 Jenkins 作业，将我们的应用程序部署到 VM（即应用服务器）上。

最后，我们能够在 Azure 平台上部署我们的应用程序。

# 总结

在本章中，您已经了解了由微软提供的 Azure 平台，并在其上部署了您的云原生应用程序。我们看了一种在 Azure 平台上构建相同基础设施的不同方法。您还看到了 Jenkins 与 Azure 平台的集成，用于 CI/CD。在下一章中，我们将看看一些非常有用的工具，用于管理和解决与应用程序相关的问题，并以更快的方式解决这些问题，以便我们的应用程序可以保持零停机时间。敬请关注下一章关于监控的内容！


# 第十三章：监控云应用程序

在前几章中，我们讨论了云原生应用程序开发，并将其部署到云平台供客户使用，以提高可用性。我们的工作还没有结束。基础设施和应用程序管理是一个完全独立的领域或流，它监控基础设施以及应用程序的性能，使用工具实现最小或零停机。在本章中，我们将讨论一些可以帮助您做到这一点的工具。

本章将涵盖以下主题：

+   AWS 服务，如 CloudWatch，Config 等

+   Azure 服务，如应用程序洞察、日志分析等

+   ELK 堆栈的日志分析简介

+   开源监控工具，如 Prometheus 等

# 在云平台上进行监控

到目前为止，我们已经讨论了如何开发应用程序并在不同平台上部署它，以使其对客户业务模型有用。然而，即使在开发应用程序之后，您仍需要具有专业知识的人员，他们将利用工具在平台上管理您的应用程序，这可能是公共云或本地部署。

在本节中，我们将主要讨论公共云提供商提供的工具或服务，使用这些工具我们可以管理基础设施，并关注应用程序洞察，即性能。

在继续讨论工具之前，让我们在为任何应用程序分配基础设施时考虑一些要点：

+   定期对一定的请求集合进行负载测试是一个好的做法。这将帮助您判断应用程序的初始资源需求。我们可以提到的一些工具是 Locust ([`locust.io/`](http://locust.io/))和 JMeter ([`jmeter.apache.org/`](https://jmeter.apache.org/))。

+   建议以最少的配置分配资源，并使用与应用程序使用情况相关的自动扩展工具。

+   在资源分配方面应该尽量减少手动干预。

考虑所有前述要点。确保建立监控机制以跟踪资源分配和应用程序性能是必要的。让我们讨论云平台提供的服务。

# 基于 AWS 的服务

以下是**AWS**（**亚马逊云服务**）提供的服务及其在应用程序和基础设施监控方面的使用。

# 云监控

这项 AWS 服务跟踪您的 AWS 资源使用情况，并根据定义的警报配置向您发送通知。可以跟踪 AWS 计费、Route 53、ELB 等资源。以下屏幕截图显示了一个触发的警报：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00214.jpeg)

最初，我们必须在[`console.aws.amazon.com/cloudwatch/home?region=us-east-1#alarm:alarmFilter=ANY`](https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#alarm:alarmFilter=ANY)设置 CloudWatch 警报。

您应该看到以下屏幕，在那里您需要单击“创建警报”按钮，根据一些指标创建自己的警报：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00215.jpeg)

现在，单击“创建警报”按钮。将弹出一个向导，询问需要监控的指标：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00216.jpeg)

上述屏幕截图列出了所有可监控的指标，以及可以设置警报的指标。

在下一个屏幕中，我们需要检查 EC2 指标。根据您的要求，您可以选择任何指标，例如，我们将选择 NetworkIn 指标并单击“下一步”：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00217.jpeg)

在下一个屏幕上，我们需要提供警报名称和描述，以及警报预览。此外，我们需要根据触发警报的条件提供条件。

此外，我们需要设置服务通知服务，通知需要以电子邮件形式发送：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00218.jpeg)

添加完详细信息后，单击“创建警报”按钮设置警报。

现在，每当“NetworkIn”指标达到其阈值时，它将通过电子邮件发送通知。

同样，我们可以设置不同的指标来监视资源利用率。

另一种创建警报的方法是在资源的监视部分选择“创建警报”按钮，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00219.jpeg)

您可以查看 AWS 文档（[`aws.amazon.com/documentation/cloudwatch/`](https://aws.amazon.com/documentation/cloudwatch/)）获取更多信息。

# CloudTrail

这是 AWS 云服务中最重要的之一，默认情况下会跟踪 AWS 账户上的任何活动，无论是通过控制台还是编程方式。在这项服务中，我们不需要配置任何内容。如果您的账户受到威胁，或者我们需要检查资源操作等情况，这项服务就是必需的。

以下截图将显示与账户相关的一些活动：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00220.jpeg)

有关更多信息，您可以查看 AWS 文档（[`aws.amazon.com/documentation/cloudtrail/`](https://aws.amazon.com/documentation/cloudtrail/)）。

# AWS Config 服务

这是另一个 AWS 服务，我们可以根据定义的模板规则检查 AWS 资源的配置。

请注意，此服务将需要创建服务角色以访问 AWS 资源。

在这项服务中，我们只需要根据提供的模板设置规则。AWS 或客户模板用于对我们作为应用程序部署的一部分创建的资源进行检查。要向服务配置添加新规则，请转到[`console.aws.amazon.com/config/home?region=us-east-1#/rules/view`](https://console.aws.amazon.com/config/home?region=us-east-1#/rules/view)：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00221.jpeg)

在上述屏幕中，我们需要添加一个新规则，该规则将评估所有资源或您指定的资源。单击“添加规则”以添加新规则，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00222.jpeg)

在上述截图中，选择规则以打开基于需要跟踪的资源的资源监视配置。

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00223.jpeg)

上述截图是 AWS ec2-instance-in-vpc 模板配置，它将帮助您验证 EC2 是否在具有正确配置的 VPC 中。在这里，您可以指定需要评估的 VPC。

单击“保存”以添加新规则。一旦评估完成，我们将看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00224.jpeg)

以下资源报告显示如下：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00225.jpeg)

您可以查看 AWS 文档（[`aws.amazon.com/documentation/config/`](https://aws.amazon.com/documentation/config/)）获取更多信息。

# Microsoft Azure 服务

以下是 Microsoft Azure 提供的服务，可以帮助您管理应用程序性能。

# 应用程序洞察

这项由 Azure 提供的服务可帮助您管理应用程序性能，对于 Web 开发人员非常有用，可以帮助他们检测、诊断和诊断应用程序问题。

要设置应用程序洞察，您只需要知道应用程序和组名称，这些名称是您基础架构所在的。现在，如果您在左侧窗格上单击“+”号，您应该会看到类似以下截图的屏幕：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00226.jpeg)

在这里，我们可以选择应用程序洞察服务，需要提供应用程序洞察名称、需要监视的组名称以及需要启动的区域。

一旦启动，您将看到以下屏幕，其中将向您展示如何使用应用程序洞察配置资源。以下是一些描述的指标：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00227.jpeg)

查看完整的参考文档，访问[`docs.microsoft.com/en-us/azure/application-insights/app-insights-profiler`](https://docs.microsoft.com/en-us/azure/application-insights/app-insights-profiler)，其中将提供有关如何配置应用程序洞察与资源的完整信息。

现在出现的问题是应用程序洞察监视哪些指标。以下是一些描述的指标：

+   **请求速率**、**响应时间**和**失败率**：这可以让您了解请求的类型及其响应时间，有助于资源管理

+   **Ajax 调用**：这将跟踪网页的速率、响应时间和失败率。

+   **用户和会话详情**：这跟踪用户和会话信息，如用户名、登录、注销详情等

+   **性能管理**：这跟踪 CPU、网络和 RAM 的详细信息

+   **主机诊断**：这是为了计算 Azure 的资源

+   **异常**：这可以让您了解服务器和浏览器报告的异常

您可以为系统配置许多指标。有关更多信息，请查看[`docs.microsoft.com/en-us/azure/application-insights/app-insights-metrics-explorer`](https://docs.microsoft.com/en-us/azure/application-insights/app-insights-metrics-explorer)。

您可以查看 Azure 文档([`docs.microsoft.com/en-us/azure/application-insights/`](https://docs.microsoft.com/en-us/azure/application-insights/))，了解更多与应用程序洞察相关的信息。

到目前为止，我们一直在云平台上验证和监视应用程序及其基础设施。然而，一个非常重要的问题是：如果出现应用程序问题，我们该如何进行故障排除？下一部分关于 ELK 堆栈将帮助您确定问题，这可能是系统级或应用程序级的问题。

# ELK 堆栈介绍

ELK 堆栈由 Elasticsearch、Logstash 和 Kibana 组成。所有这些组件一起工作，收集各种类型的日志，可以是系统级日志（即 Syslog、RSYSLOG 等）或应用程序级日志（即访问日志、错误日志等）。

有关 ELK 堆栈的设置，您可以参考这篇文章，其中除了 ELK 堆栈外，还使用 Filebeat 配置将日志发送到 Elasticsearch：

[`www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-elk-stack-on-ubuntu-14-04`](https://www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-elk-stack-on-ubuntu-14-04)。

# Logstash

Logstash 需要安装在需要收集日志并将其传送到 Elasticsearch 以创建索引的服务器上。

安装 Logstash 后，建议配置位于`/etc/logstash`的`logstash.conf`文件，包括 Logstash 日志文件的旋转（即`/var/log/logstash/*.stdout`、`*.err`或`*.log`）或后缀格式，如数据格式。以下代码块是供您参考的模板：

```py
    # see "man logrotate" for details 

    # number of backlogs to keep 
    rotate 7 

    # create new (empty) log files after rotating old ones 
    create 

    # Define suffix format 
    dateformat -%Y%m%d-%s 

    # use date as a suffix of the rotated file 
    dateext 

   # uncomment this if you want your log files compressed 
   compress 

   # rotate if bigger that size 
   size 100M 

   # rotate logstash logs 
   /var/log/logstash/*.stdout 
   /var/log/logstash/*.err 
   /var/log/logstash/*.log { 
       rotate 7 
       size 100M 
       copytruncate 
       compress 
       delaycompress 
       missingok 
       notifempty 
    } 

```

为了将日志传送到 Elasticsearch，您需要在配置中有三个部分，名为输入、输出和过滤，这有助于创建索引。这些部分可以在单个文件中，也可以在单独的文件中。

Logstash 事件处理管道按照输入-过滤-输出的方式工作，每个部分都有自己的优势和用途，其中一些如下：

+   **输入**：这个事件需要从日志文件中获取数据。一些常见的输入包括文件，它使用`tailf`读取文件；Syslog，它从监听端口`514`的 Syslogs 服务中读取；beats，它从 Filebeat 收集事件，等等。

+   **过滤器**：Logstash 中的这些中间层设备根据定义的过滤器对数据执行某些操作，并分离符合条件的数据。其中一些是 GROK（根据定义的模式结构化和解析文本）、clone（通过添加或删除字段复制事件）等。

+   **输出**：这是最终阶段，我们将经过过滤的数据传递到定义的输出。可以有多个输出位置，我们可以将数据传递到进一步索引。一些常用的输出包括 Elasticsearch（非常可靠；一个更容易、更方便的平台来保存您的数据，并且更容易在其上查询）和 graphite（用于以图表形式存储和显示数据的开源工具）。

以下是 Syslog 日志配置的示例：

+   Syslog 的输入部分写成如下形式：

```py
   input { 
     file { 
     type => "syslog" 
    path => [ "/var/log/messages" ] 
    } 
   }

```

+   Syslog 的过滤器部分写成如下形式：

```py
   filter { 
     grok { 
      match => { "message" => "%{COMBINEDAPACHELOG}" } 
     } 
    date { 
     match => [ "timestamp" , "dd/MMM/yyyy:HH:mm:ss Z" ] 
    } 
  } 

```

+   Syslog 的输出部分写成如下形式：

```py
   output { 
     elasticsearch { 
       protocol => "http" 
       host => "es.appliedcode.in" 
       port => "443" 
       ssl => "true" 
       ssl_certificate_verification => "false" 
       index => "syslog-%{+YYYY.MM.dd}" 
       flush_size => 100 
      } 
   } 

```

用于传输日志的配置文件通常存储在`/etc/logstash/confd/`中。

如果为每个部分创建单独的文件，则需要遵循命名文件的约定；例如，输入文件应命名为`10-syslog-input.conf`，过滤器文件应命名为`20-syslog-filter.conf`。同样，对于输出，它将是`30-syslog-output.conf`。

如果要验证配置是否正确，可以执行以下命令：

```py
 $ sudo service logstash configtest

```

有关 Logstash 配置的更多信息，请参阅文档示例[`www.elastic.co/guide/en/logstash/current/config-examples.html`](https://www.elastic.co/guide/en/logstash/current/config-examples.html)。

# Elasticsearch

Elasticsearch ([`www.elastic.co/products/elasticsearch`](https://www.elastic.co/products/elasticsearch))是一个日志分析工具，它帮助存储并根据配置和时间戳创建索引，解决了开发人员试图识别与其问题相关的日志的问题。Elasticsearch 是基于 Lucene 搜索引擎的 NoSQL 数据库。

安装完 Elasticsearch 后，您可以通过点击以下 URL 验证版本和集群详细信息：[](http://ip-address) `http://ip-address:9200/`。

输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00228.jpeg)

这证明了 Elasticsearch 正在运行。现在，如果要查看日志是否已创建，可以使用以下 URL 查询 Elasticsearch：

`http://ip-address:9200/_search?pretty`。

输出将如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00229.jpeg)

要查看已创建的索引，可以点击以下 URL：

`http://ip-address:9200/_cat/indices?v`。

输出将类似于以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00230.gif)

如果您想了解更多关于 Elasticsearch 查询、索引操作等内容，请阅读本文：

[`www.elastic.co/guide/en/elasticsearch/reference/current/indices.html`](https://www.elastic.co/guide/en/elasticsearch/reference/current/indices.html)。

# Kibana

Kibana 工作在 Elasticsearch 的顶层，可视化提供环境接收的数据的洞察，并帮助做出必要的决策。简而言之，Kibana 是一个用于从 Elasticsearch 搜索日志的 GUI。

安装 Kibana 后，应出现在`http://ip-address:5601/`，它将要求您创建索引并配置 Kibana 仪表板：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00231.jpeg)

配置完成后，应出现以下屏幕，其中显示了带有时间戳的日志格式：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00232.jpeg)

现在，我们需要创建仪表板，以便以图表、饼图等形式查看日志。

有关创建 Kibana 仪表板的更多信息，请参阅 Kibana 文档([`www.elastic.co/guide/en/kibana/current/dashboard-getting-started.html`](https://www.elastic.co/guide/en/kibana/current/dashboard-getting-started.html))。

作为 Kibana 的替代方案，您可能对 Grafana([`grafana.com/`](https://grafana.com/))感兴趣，这也是一种分析和监控工具。

现在，问题是：Grafana 与 Kibana 有何不同？以下是答案：

| **Grafana** | **Kibana** |
| --- | --- |
| Grafana 仪表板专注于基于系统指标 CPU 或 RAM 的时间序列图表。Kibana 专用于日志分析。 |
| Grafana 的内置 RBA（基于角色的访问）决定用户对仪表板的访问权限。 | Kibana 无法控制仪表板访问权限。 |
| Grafana 支持除 Elasticsearch 之外的不同数据源，如 Graphite、InfluxDB 等。 | Kibana 与 ELK 堆栈集成，使其用户友好。 |

这是关于 ELK 堆栈的，它为我们提供了有关应用程序的见解，并帮助我们解决应用程序和服务器问题。在下一节中，我们将讨论一个名为**Prometheus**的本地开源工具，它对监视不同服务器的活动非常有用。

# 开源监控工具

在本节中，我们将主要讨论由第三方拥有并收集服务器指标以排除应用程序问题的工具。

# Prometheus

Prometheus([`prometheus.io`](https://prometheus.io))是一个开源监控解决方案，可跟踪系统活动指标，并在需要您采取任何操作时立即向您发出警报。这个工具是用**Golang**编写的。

这个工具类似于 Nagios 等工具正在变得越来越受欢迎。它收集服务器的指标，但也根据您的需求为您提供模板指标，例如`http_request_duration_microseconds`，以便您可以使用 UI 生成图表以更好地理解它并以高效的方式监视它。

请注意，默认情况下，Prometheus 在`9090`端口上运行。

要安装 Prometheus，请按照官方网站上提供的说明进行操作([`prometheus.io/docs/introduction/getting_started/`](https://prometheus.io/docs/introduction/getting_started/))。安装完成并且服务启动后，尝试打开`http://ip-address:9090/status`以了解状态。以下屏幕显示了 Prometheus 的构建信息，即版本、修订版本等。

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00233.jpeg)

要了解配置了哪些目标，请使用`http://ip-address:9090/targets`。输出将类似于这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00234.jpeg)

为了生成图表，请使用`http://ip-address:9090/graph`并选择需要实现图表的指标。输出应类似于以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00235.jpeg)

同样，我们可以请求由 Prometheus 识别的其他一些指标，例如主机上线状态。以下屏幕截图显示了一段时间内的主机状态：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00236.jpeg)

Prometheus 有一些不同用途的组件，如下所示：

+   **AlertManager**：此组件将帮助您基于指标设置服务器的警报，并定义其阈值。我们需要在服务器中添加配置来设置警报。查看[`prometheus.io/docs/alerting/alertmanager/`](https://prometheus.io/docs/alerting/alertmanager/)上的 AlertManager 文档。

+   **Node exporter**：此导出器对硬件和操作系统指标非常有用。在[`prometheus.io/docs/instrumenting/exporters/`](https://prometheus.io/docs/instrumenting/exporters/)上阅读有关不同类型导出器的更多信息。

+   **Pushgateway**：此 Pushgateway 允许您运行批处理作业以公开您的指标。

+   Grafana：Prometheus 与 Grafana 集成，帮助仪表板查询 Prometheus 上的指标。

# 总结

这一章以不同的方式非常有趣。从基于云平台的工具，如 Cloudwatch 和 Application Insights 开始，这些工具帮助您在云平台上管理应用程序。然后，它转向开源工具，开发人员一直以来都将其作为首选，因为他们可以根据自己的需求进行定制。我们看了 ELK 堆栈，它一直很受欢迎，并且在许多组织中以某种方式经常被使用。

现在，我们已经到达了本书的结尾，但希望会有另一版，届时我们将讨论高级应用开发，并提供更多对 QA 受众有用的测试案例。尽情编码吧！
