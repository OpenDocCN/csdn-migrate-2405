# Go 无服务应用实用指南（一）

> 原文：[`zh.annas-archive.org/md5/862FBE1FF9A9C074341990A4C2200D42`](https://zh.annas-archive.org/md5/862FBE1FF9A9C074341990A4C2200D42)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

无服务器架构在技术社区中很受欢迎，其中 AWS Lambda 是很受欢迎的。Go 语言易于学习，易于使用，并且易于其他开发人员阅读，现在它已被誉为 AWS Lambda 支持的语言。本书是您设计无服务器 Go 应用程序并将其部署到 Lambda 的最佳指南。

本书从快速介绍无服务器架构及其优势开始，然后通过实际示例深入探讨 AWS Lambda。然后，您将学习如何在 Go 中使用 AWS 无服务器服务设计和构建一个可投入生产的应用程序，而无需预先投资基础设施。本书将帮助您学习如何扩展无服务器应用程序并在生产中处理分布式无服务器系统。然后，您还将学习如何记录和测试您的应用程序。

在学习的过程中，您还将发现如何设置 CI/CD 管道以自动化 Lambda 函数的部署过程。此外，您将学习如何使用 AWS CloudWatch 和 X-Ray 等服务实时监视和排除故障您的应用程序。本书还将教您如何扩展无服务器应用程序并使用 AWS Cognito 安全访问。

通过本书，您将掌握设计、构建和部署基于 Go 的 Lambda 应用程序到生产的技能。

# 这本书适合谁

这本书适合希望了解无服务器架构的 Gophers。假定具有 Go 编程知识。对于有兴趣在 Go 中构建无服务器应用程序的 DevOps 和解决方案架构师也会从本书中受益。

# 本书涵盖了什么

第一章《Go 无服务器》给出了关于无服务器是什么，它是如何工作的，它的特点是什么，为什么 AWS Lambda 是无服务器计算服务的先驱，以及为什么您应该使用 Go 构建无服务器应用程序的基础解释。

第二章《开始使用 AWS Lambda》提供了在 Go 运行时和开发环境旁边设置 AWS 环境的指南。

第三章《使用 Lambda 开发无服务器函数》描述了如何从头开始编写您的第一个基于 Go 的 Lambda 函数，以及如何从控制台手动调用它。

第四章《使用 API Gateway 设置 API 端点》说明了如何使用 API Gateway 在收到 HTTP 请求时触发 Lambda 函数，并构建一个由无服务器函数支持的统一事件驱动的 RESTful API。

第五章《使用 DynamoDB 管理数据持久性》展示了如何通过使用 DynamoDB 数据存储解决 Lambda 函数无状态问题来管理数据。

第六章《部署您的无服务器应用程序》介绍了在构建 AWS Lambda 中的无服务器函数时可以使用的高级 AWS CLI 命令和选项，以节省时间。它还展示了如何创建和维护 Lambda 函数的多个版本和发布。

第七章《实施 CI/CD 管道》展示了如何设置持续集成和持续部署管道，以自动化 Lambda 函数的部署过程。

第八章《扩展您的应用程序》介绍了自动缩放的工作原理，Lambda 如何在高峰服务使用期间处理流量需求而无需容量规划或定期缩放，以及如何使用并发预留来限制执行次数。

第九章《使用 S3 构建前端》说明了如何使用由无服务器函数支持的 REST 后端构建单页面应用程序。

第十章，*测试您的无服务器应用程序*，展示了如何使用 AWS 无服务器应用程序模型在本地测试无服务器应用程序。它还涵盖了 Go 单元测试和使用第三方工具进行性能测试，并展示了如何使用 Lambda 执行测试工具。

第十一章，*监控和故障排除*，进一步介绍了如何使用 CloudWatch 设置函数级别的监控，以及如何使用 AWS X-Ray 调试和故障排除 Lambda 函数，以便对应用程序进行异常行为检测。

第十二章，*保护您的无服务器应用程序*，致力于在 AWS Lambda 中遵循最佳实践和建议，使您的应用程序符合 AWS Well-Architected Framework 的要求，从而使其具有弹性和安全性。

第十三章，*设计成本效应应用程序*，还介绍了一些优化和减少无服务器应用程序计费的技巧，以及如何使用实时警报跟踪 Lambda 的成本和使用情况，以避免问题的出现。

第十四章，*基础设施即代码*，介绍了诸如 Terraform 和 SAM 之类的工具，帮助您以自动化方式设计和部署 N-Tier 无服务器应用程序，以避免人为错误和可重复的任务。

# 要充分利用本书

本书适用于在 Linux、Mac OS X 或 Windows 下工作的任何人。您需要安装 Go 并拥有 AWS 账户。您还需要 Git 来克隆本书提供的源代码库。同样，您需要具备 Go、Bash 命令行和一些 Web 编程技能的基础知识。所有先决条件都在第二章中进行了描述，*开始使用 AWS Lambda*，并提供了确保您能轻松跟随本书的说明。

最后，请记住，本书并不意味着取代在线资源，而是旨在补充它们。因此，您显然需要互联网访问来完成阅读体验的某些部分，通过提供的链接。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)注册，直接将文件发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩软件解压缩文件夹：

+   Windows 的 WinRAR/7-Zip

+   Mac 的 Zipeg/iZip/UnRarX

+   Linux 的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go`](https://github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自丰富书籍和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含了本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/HandsOnServerlessApplicationswithGo_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/HandsOnServerlessApplicationswithGo_ColorImages.pdf)。

# 使用的约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些样式的示例及其含义的解释。

文本中的代码单词显示如下：“在工作空间中，使用`vim`创建一个`main.go`文件，内容如下。”

代码块设置如下：

```go
package main
import "fmt"

func main(){
  fmt.Println("Welcome to 'Hands-On serverless Applications with Go'")
}
```

任何命令行输入或输出都是这样写的：

```go
pip install awscli
```

**粗体**：表示一个新术语，一个重要词，或者您在屏幕上看到的词。例如，菜单或对话框中的单词会在文本中显示为这样。这里有一个例子：“在`Source`页面上，选择`GitHub`作为源提供者。”

警告或重要说明看起来像这样。

提示和技巧看起来像这样。


# 第一章：Go 无服务器

本章将为您提供对**无服务器架构**是什么，它是如何工作的，以及它的特点是什么的基础理解。您将了解到**AWS Lambda**如何与谷歌云函数和微软 Azure 函数等大型参与者不相上下。然后，您将了解 AWS Lambda 的不同执行环境及其对 Go 语言的支持。此外，我们将讨论使用 Go 作为构建无服务器应用程序的编程语言的优势。

本章将涵盖以下主题：

+   云计算模型——了解它们是什么以及可以用于什么。

+   无服务器架构的优缺点。

+   为什么 Go 非常适合 AWS Lambda。

# 无服务器范式

基于云的应用程序可以构建在低级基础设施部件上，也可以使用提供抽象层的更高级服务，从而摆脱核心基础设施的管理、架构和扩展要求。在接下来的部分，您将了解不同的云计算模型。

# 云计算的演进

云提供商根据四种主要模型提供其服务：IaaS、PaaS、CaaS 和 FaaS。所有上述模型只是在底层添加了数千台服务器、磁盘、路由器和电缆。它们只是在顶部添加了抽象层，以使管理更容易，并增加开发速度。

# 基础设施即服务

**基础设施即服务**（**IaaS**），有时缩写为 IaaS，是基本的云消费模型。它在虚拟化平台之上构建了一个 API，以访问计算、存储和网络资源。它允许客户无限扩展其应用程序（无需容量规划）。

在这种模型中，云提供商抽象了硬件和物理服务器，云用户负责管理和维护其上的客户操作系统和应用程序。

根据 Gartner 的基础设施即服务魔力象限图，AWS 是领先者。无论您是在寻找内容传递、计算能力、存储还是其他服务功能，AWS 在 IaaS 云计算模型方面是各种可用选项中最有利的。它主导着公共云市场，而微软 Azure 正在逐渐赶上亚马逊，其次是谷歌云平台和 IBM 云。

# 平台即服务

**平台即服务**（**PaaS**）为开发人员提供了一个框架，他们可以在其中开发应用程序。它简化、加快了开发、测试和部署应用程序的过程，同时隐藏了所有实现细节，如服务器管理、负载均衡器和数据库配置。

PaaS 建立在 IaaS 之上，因此隐藏了底层基础设施和操作系统，使开发人员能够专注于提供业务价值并减少运营开销。

Heroku 是最早推出 PaaS 的之一，于 2007 年；后来，谷歌应用引擎和 AWS 弹性 Beanstalk 也加入了竞争。

# 容器即服务

**容器即服务**（**CaaS**）随着 2013 年 Docker 的发布而变得流行。它使得在本地数据中心或云上构建和部署容器化应用变得容易。

容器改变了 DevOps 和站点可靠性工程师的规模单位。多个容器可以在单个虚拟机上运行，这样可以更好地利用服务器并降低成本。它还通过消除“在我的机器上运行”的笑话，使开发人员和运维团队更加紧密地联系在一起。这种转变到容器使多家公司能够现代化其传统应用程序并将其迁移到云上。

为了实现容错、高可用性和可伸缩性，需要一个编排工具，比如 Docker Swarm、Kubernetes 或 Apache Mesos，来管理节点集群中的容器。因此，引入了 CaaS 来快速高效地构建、部署和运行容器。它还处理了诸如集群管理、扩展、蓝/绿部署、金丝雀更新和回滚等重型任务。

市场上最流行的 CaaS 平台是 AWS，因为 57%的 Kubernetes 工作负载运行在亚马逊**弹性容器服务**（**ECS**）、**弹性 Kubernetes 服务**（**EKS**）和 AWS Fargate 上，其次是 Docker Cloud、CloudFoundry 和 Google 容器引擎。

这种模型，CaaS，使您能够进一步分割虚拟机以实现更高的利用率，并在机器集群中编排容器，但云用户仍然需要管理容器的生命周期；作为解决方案，引入了**函数即服务**（**FaaS**）。

# 函数即服务

FaaS 模型允许开发人员在不需要预配或维护复杂基础设施的情况下运行代码（称为函数）。云提供商将客户代码部署到完全托管的、临时的、有时间限制的容器中，这些容器仅在函数调用期间处于活动状态。因此，企业可以在不必担心扩展或维护复杂基础设施的情况下实现增长；这被称为无服务器化。

亚马逊在 2014 年推出了 AWS Lambda，开启了无服务器革命，随后是微软 Azure Functions 和 Google Cloud Functions。

# 无服务器架构

无服务器计算，或者说 FaaS，是云计算的第四种消费方式。在这种模式下，预配、维护和打补丁的责任从客户转移到了云提供商。开发人员现在可以专注于构建新功能和创新，并且只支付他们消耗的计算时间。

# 无服务器化的好处

无服务器化有很多合理之处：

+   **无运维**：服务器基础设施由云提供商管理，这减少了开销并提高了开发速度。操作系统更新和补丁由 FaaS 提供商处理。这导致了缩短的上市时间和更快的软件发布，消除了系统管理员的需求。

+   **自动扩展和高可用性**：作为规模的单位，函数导致了小型、松耦合和无状态的组件，从长远来看，这会导致可伸缩的应用程序。如何有效地利用基础设施来为客户提供服务请求并根据负载水平扩展函数，这取决于服务提供商。

+   **成本优化**：您只支付您消耗的计算时间和资源（RAM、CPU、网络或调用时间）。您不支付闲置资源。没有工作意味着没有成本。例如，如果 Lambda 函数的计费周期为 100 毫秒，那么它可以显著降低成本。

+   **多语言**：无服务器方法带来的一个好处是，作为程序员，您可以根据您的用例选择不同的语言运行时。应用程序的一部分可以用 Java 编写，另一部分可以用 Go 编写，另一部分可以用 Python 编写；只要能完成工作，就没有关系。

# 无服务器化的缺点

另一方面，无服务器计算仍处于起步阶段；因此，并不适用于所有用例，并且它确实有其局限性：

+   **透明性**：基础设施由 FaaS 提供商管理。这是为了灵活性；您无法完全控制您的应用程序，无法访问底层基础设施，也无法在不同平台提供商之间切换（供应商锁定）。未来，我们预计将会有更多工作朝着 FaaS 的统一化方向发展；这将有助于避免供应商锁定，并允许我们在不同的云提供商甚至本地运行无服务器应用程序。

+   **调试**：监控和调试工具并非是针对无服务器架构而构建的。因此，无服务器函数很难进行调试和监控。此外，在部署之前很难设置本地环境来测试您的函数（预集成测试）。好消息是，随着无服务器的普及和社区和云提供商创建了多个开源项目和框架（如 AWS X-Ray、Datadog、Dashbird 和 Komiser），最终会出现工具来改善无服务器环境的可观察性。

+   **冷启动**：处理函数的第一个请求需要一些时间，因为云提供商需要为您的任务分配适当的资源（AWS Lambda 需要启动一个容器）。为了避免这种情况，您的函数必须保持活动状态。

+   **无状态**：函数需要是无状态的，以提供使无服务器应用程序能够透明扩展的提供。因此，要持久保存数据或管理会话，您需要使用外部数据库，如 DynamoDB 或 RDS，或内存缓存引擎，如 Redis 或 Memcached。

尽管已经说明了所有这些限制，但这些方面将随着越来越多的供应商推出升级版本的平台而发生变化。

# 无服务器云提供商

有多个 FaaS 提供商，但为了简单起见，我们只比较最大的三个：

+   AWS Lambda

+   Google Cloud Functions

+   Microsoft Azure Functions

以下是一张图示比较：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/d9753fec-4fb3-46ed-a985-de9fb4b21fad.png)

如前图所示，AWS Lambda 是当今无服务器空间中使用最广泛、最知名和最成熟的解决方案，这就是为什么即将到来的章节将完全专注于 AWS Lambda。

# AWS Lambda

AWS Lambda 是 AWS 无服务器平台的核心：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/c79de2b6-2b19-4d23-95a9-95be3e42fc0a.png)

AWS Lambda 在 2014 年的 re:Invent 上推出。这是无服务器计算的第一个实现，用户可以将他们的代码上传到 Lambda。它会代表用户执行操作和管理活动，包括提供容量、监控舰队健康状况、应用安全补丁、部署他们的代码，并将实时日志和指标发布到 Amazon CloudWatch。

Lambda 遵循事件驱动架构。您的代码会在响应事件时触发并并行运行。每个触发器都会被单独处理。此外，您只需按执行次数收费，而使用 EC2 时则按小时计费。因此，您可以以低成本和零前期基础设施投资获得应用程序的自动扩展和容错能力。

# 事件源

AWS Lambda 根据事件运行您的代码。当这些事件源检测到事件时，将调用您的函数：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/0cd47bd2-b1b1-45d6-b1aa-16b2f9f54182.png)

Amazon 现在支持 SQS 作为 Lambda 的事件源

# 使用情况

AWS Lambda 可用于无尽的应用场景：

+   **Web 应用程序**：您可以使用 S3 和 Lambda 来代替维护带有 Web 服务器的专用实例来托管您的静态网站，以便以更低的成本获得可伸缩性。下图描述了一个无服务器网站的示例：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/495d1451-4d2a-41db-8913-711919a45c94.png)

**Route 53**中的别名记录指向**CloudFront**分发。**CloudFront**分发建立在**S3 Bucket**之上，其中托管着静态网站。**CloudFront**减少了对静态资产（JavaScript、CSS、字体和图像）的响应时间，提高了网页加载时间，并减轻了分布式拒绝服务（DDoS）攻击。然后，来自网站的 HTTP 请求通过**API Gateway** HTTP 端点，触发正确的**Lambda Function**来处理应用程序逻辑并将数据持久保存到完全托管的数据库服务，如**DynamoDB**。

+   **移动和物联网**：构建传感器应用程序的示意图，该应用程序从实时传感器连接的设备中测量温度，并在温度超出范围时发送短信警报，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/747c45cd-e10b-4c40-98af-0092c7dea0df.png)

**连接设备**将数据摄入到**AWS IoT**。**AWS IoT**规则将调用**Lambda 函数**以分析数据，并在紧急情况下向**SNS 主题**发布消息。发布消息后，Amazon SNS 将尝试将该消息传递给订阅主题的每个端点。在这种情况下，它将是**短信**。

+   **数据摄入：**监控日志并保持审计跟踪是强制性的，您应该意识到云基础设施中的任何安全漏洞。以下图表说明了一个实时日志处理管道与 Lambda：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/9027c43f-240d-45cf-a725-6e9c965aa317.png)

VPC 流日志功能捕获有关 VPC 中网络接口的 IP 流量信息，并将日志发送到 Amazon CloudWatch 日志。AWS CloudTrail 记录您帐户上的所有 AWS API 调用。所有日志都被聚合并流式传输到 AWS Kinesis 数据流。

Kinesis 触发 Lambda 函数，分析日志以查找事件或模式，并在异常活动发生时向 Slack 或 PagerDuty 发送通知。最后，Lambda 将数据集发布到预安装了 Kibana 的 Amazon Elasticsearch，以可视化和分析网络流量和日志，使用动态和交互式仪表板。这是为了长期保留和存档日志，特别是对于具有合规性计划的组织。Kinesis 将日志存储在 S3 存储桶中进行备份。可以配置存储桶的生命周期策略，将未使用的日志存档到 Glacier。

+   **定时任务：**定时任务和事件非常适合 Lambda。您可以使用 Lambda 创建备份，生成报告和执行 cron 作业，而不是保持实例 24/7 运行。以下示意图描述了如何使用 AWS Lambda 执行后处理作业：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/9ce30d4e-f069-458d-ba7a-508814f4453e.png)

当视频到达 S3 存储桶时，事件将触发一个 Lambda 函数，该函数将视频文件名和路径传递给弹性转码器管道，以执行视频转码，生成多种视频格式（.avi，.h264，.webm，.mp3 等），并将结果存储在 S3 存储桶中。

+   **聊天机器人和语音助手：**您可以使用**自然语言理解**（**NLU**）或**自动语音识别**（**ASR**）服务，如 Amazon Lex，构建可以触发 Lambda 函数以响应语音命令或文本的应用程序机器人。以下图表描述了使用 Lambda 构建个人助手的用例：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/c4062825-155f-4520-9594-ad9055d56db3.png)

用户可以询问**Amazon Echo**关于其待办事项清单。Echo 将拦截用户的语音命令并将其传递给自定义**Alexa 技能**，该技能将进行语音识别并将用户的语音命令转换为意图，触发**Lambda 函数**，然后查询**Trello** API 以获取今天的任务列表。

由于 Lambda 在内存、CPU 和超时执行方面的限制，它不适用于长时间运行的工作流和其他大规模工作负载。

# Go 无服务器

AWS 在 2018 年 1 月宣布支持 Go 作为 AWS Lambda 的语言。已经有一些开源框架和库可以用来支持使用 Node.js 的 Go 应用程序（Apex 无服务器框架），但现在 Go 已经得到官方支持，并添加到可以用来编写 Lambda 函数的编程语言列表中：

+   Go

+   Node.js

+   Java

+   Python

+   .NET

但是我们应该使用哪种语言来编写高效的 Lambda 函数呢？无服务器的一个原因是多语言。无论您选择哪种语言，编写 Lambda 函数的代码都有一个共同的模式。同时，您需要特别注意性能和冷启动。这就是 Go 发挥作用的地方。以下图表突出了在 AWS Lambda 中使用 Go 进行无服务器应用程序的主要优势：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/eb71b2e0-fac2-48d8-a69b-3ed77650afb6.png)

+   **面向云**：它是由谷歌专门为云设计的，考虑到可扩展性，并减少构建时间。Go 是分布式系统和基础设施工具的坚实语言。Docker、Kubernetes、Terraform、etcd、Prometheus 等许多编排、提供和监控工具都是使用 Go 构建的。

+   **快速**：Go 编译成单个二进制文件。因此，您可以向 AWS Lambda 提供预编译的 Go 二进制文件。AWS 不会为您编译 Go 源文件，这会产生一些后果，比如快速的冷启动时间。Lambda 不需要设置运行时环境；另一方面，Java 需要启动 JVM 实例来使您的函数热起来。Go 具有清晰的语法和明确的语言规范。这为开发人员提供了一种易于学习的语言，并在产生可维护的代码的同时快速显示出良好的结果。

+   **可扩展**：Go 具有内置的 goroutines 并发，而不是线程。它们从堆中消耗了几乎 2 Kb 的内存，并且比线程工作得更快；因此，您可以随时启动数百万个 goroutine。对于软件开发，不需要框架；Golang 社区已经构建了许多工具，这些工具受到 Go 语言核心的本地支持：

+   Go 的错误处理很优雅。

+   轻量级的单元测试框架。

+   标准库稳固—HTTP 协议支持开箱即用。

+   支持的常见数据类型和结构—映射、数组、结构等。

+   **高效**：它涉及高效的执行和编译。Go 是一种编译语言；它编译成单个二进制文件。它使用静态链接将所有依赖项和模块组合成一个单个的二进制文件。此外，它更快的编译速度允许快速反馈。快速的开发节省时间和金钱；因此，这对于预算紧张的人来说无疑是最重要的优势。

+   **不断增长的社区**：以下截图显示了（根据 StackOverflow Survey 2017 观察到的）最受喜爱、最受恐惧和最想要的编程语言的流行度和使用率：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/3f31de28-9070-4f2a-be2c-39fd6764156d.png)

此外，Go 得到了谷歌的支持，并拥有一个庞大、不断增长的生态系统和众多 GitHub 上的贡献者，以及出色的 IDE 支持（IntelliJ、VSCode、Atom、GoGland）和调试功能。

# 总结

AWS Lambda 是无服务器计算或 FaaS 的第一个成功实现。它使用户摆脱了管理服务器的束缚，提高了开发速度，降低了系统复杂性，并使小型企业能够在零前期基础设施投资的情况下扩大规模。

对于在 Lambda 上运行业务的人来说，Go 对 AWS Lambda 的支持可以显著节省成本并提高性能。所以如果你正在寻找一种现代、快速、安全、易用的语言，Go 就是你的选择。

在下一章中，您将开始使用 AWS Lambda 控制台并设置您的 Golang 开发环境。

# 问题

1.  使用无服务器方法的优势是什么？

1.  Lambda 是一种节省时间的方法吗？

1.  无服务器架构如何实现微服务？

1.  AWS Lambda 函数的最长时间限制是多少？

1.  以下哪些是 AWS Lambda 支持的事件源？

+   Amazon Kinesis 数据流

+   Amazon RDS

+   AWS CodeCommit

+   AWS CloudFormation

1.  解释一下在 Go 中 goroutine 是什么。你如何停止 goroutines？

1.  AWS 中的 Lambda@Edge 是什么？

1.  函数即服务和平台即服务之间有什么区别？

1.  AWS Lambda 冷启动是什么？

1.  AWS Lambda 函数可以是无状态的还是有状态的？


# 第二章：开始使用 AWS Lambda

本章提供了在 Go 运行时和开发环境中设置 AWS 环境的指南。您将了解强大的 AWS CLI，它将使部署无服务器应用程序更加高效，并极大地提高您的生产力。

此外，您将获得一组关于如何选择您的 Go **集成开发环境**（**IDE**）的提示和建议。

# 技术要求

在继续安装和配置 AWS 和 Go 环境之前，建议您在笔记本电脑（Windows、Linux 或 macOS X）上跟着本章进行操作，预先安装 Python 2 版本 2.6.5+或 Python 3 版本 3.3+，并设置好 AWS 账户，以便您可以轻松执行给定的命令。本章的代码包托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-serverless-Applications-with-Go`](https://github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go)。

# 设置 AWS 环境

本节将指导您如何安装和配置 AWS 命令行。CLI 是一个可靠且必不可少的工具，将在接下来的章节中介绍；它将通过自动化 Lambda 函数的部署和配置为我们节省大量时间。

# AWS 命令行

AWS CLI 是一个强大的工具，可从终端会话中管理您的 AWS 服务和资源。它是建立在 AWS API 之上的，因此通过 AWS 管理控制台可以完成的所有操作都可以通过 CLI 完成；这使它成为一个方便的工具，可以用来通过脚本自动化和控制您的 AWS 基础架构。后面的章节将提供有关使用 CLI 管理 Lambda 函数和创建其他围绕 Lambda 的 AWS 服务的信息。

让我们来看一下 AWS CLI 的安装过程；您可以在*AWS 管理控制台*部分找到有关其配置和测试的信息。

# 安装 AWS CLI

要开始，请打开一个新的终端会话，然后使用`pip` Python 软件包管理器来安装`awscli`的最新稳定版本：

```go
pip install awscli
```

如果您已安装 CLI，则建议出于安全目的升级到最新版本：

```go
pip install --upgrade awscli
```

Windows 用户也可以使用 MSI 安装程序([`s3.amazonaws.com/aws-cli/AWSCLI64.msi`](https://s3.amazonaws.com/aws-cli/AWSCLI64.msi)或[`s3.amazonaws.com/aws-cli/AWSCLI32.msi`](https://s3.amazonaws.com/aws-cli/AWSCLI32.msi)*)*，无需安装 Python。

安装完成后，您需要将 AWS 二进制路径添加到`PATH`环境变量中，方法如下：

+   对于 Windows，按 Windows 键，然后键入环境变量。在环境变量窗口中，突出显示**系统变量**部分中的`PATH`变量。编辑它并通过在最后一个路径后面放置一个分号来添加路径，输入安装 CLI 二进制文件的文件夹的完整路径。

+   对于 Linux、Mac 或任何 Unix 系统，请打开您的 shell 配置文件（`.bash_profile`、`.profile`或`.bash_login`），并将以下行添加到文件的末尾：

```go
export PATH=~/.local/bin:$PATH
```

最后，将配置文件加载到当前会话中：

```go
source ~/.bash_profile
```

通过打开一个新的终端会话并输入以下命令来验证 CLI 是否正确安装：

```go
aws --version
```

您应该能够看到 AWS CLI 的版本；在我的情况下，安装了 1.14.60 版本：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/ec6f5ad5-48fa-455f-8bd9-d3f3ecb385b0.png)

让我们来测试一下，并以法兰克福地区的 Lambda 函数为例进行列出：

```go
aws lambda list-functions --region eu-central-1
```

上一个命令将显示以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/a9f5051f-6af0-4e26-8073-ac6fc7e97ad1.png)

在使用 CLI 时，通常需要您的 AWS 凭证来对 AWS 服务进行身份验证。有多种方法可以配置 AWS 凭证：

+   **环境凭证**：`AWS_ACCESS_KEY_ID`和`AWS_SECRET_KEY`变量。

+   **共享凭证文件**：`~/.aws/credentials`文件。

+   **IAM 角色**：如果您在 EC2 实例中使用 CLI，则这些角色可以避免在生产中管理凭据文件的需要。

在下一节中，我将向您展示如何使用**AWS 身份和访问管理**（**IAM**）服务为 CLI 创建新用户。

# AWS 管理控制台

IAM 是一个允许您管理用户、组以及他们对 AWS 服务的访问级别的服务。

强烈建议您除了进行结算任务外，不要使用 AWS 根帐户执行任何任务，因为它具有创建和删除 IAM 用户、更改结算、关闭帐户以及在 AWS 帐户上执行所有其他操作的最终权限。因此，我们将创建一个新的 IAM 用户，并根据*最小权限原则*授予其访问正确 AWS 资源所需的权限。在这种情况下，用户将完全访问 AWS Lambda 服务：

1.  使用您的 AWS 电子邮件地址和密码登录 AWS 管理控制台（[`console.aws.amazon.com/console/home`](https://console.aws.amazon.com/console/home)）。

1.  从**安全、身份和合规性**部分打开**IAM**控制台：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/0c79c822-802f-4e49-95c5-338317005bb3.png)

1.  从导航窗格中，选择用户，然后单击“添加用户”按钮，为用户设置名称，并选择编程访问（如果您希望同一用户访问控制台，则还要选择 AWS 管理控制台访问）：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/8cb3470b-5390-4319-bb8e-6f9ed5b00332.png)

1.  在“设置权限”部分，将 AWSLambdaFullAccess 策略分配给用户：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/a04d00d8-8f99-4eb3-ac17-5de986f12b32.png)

1.  在最后一页，您应该看到用户的 AWS 凭据：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/767571a7-8d64-4bec-be8b-048f47b7922a.png)

确保将访问密钥保存在安全位置，因为您将无法再次看到它们：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/d6919348-6e5b-4968-a63d-09a3426d3e09.png)

# 配置

我们的 IAM 用户已创建。让我们使用`aws configure`命令提供访问密钥和秘密密钥以及默认区域：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/8cd29640-c603-455c-803a-90d51132785c.png)

CLI 将在本地文件`~/.aws/credentials`（或在 Windows 上的`%UserProfile%\.aws/credentials`）中存储在前述命令中指定的凭据，内容如下：

```go
[default]
aws_access_key_id = AKIAJYZMNSSSMS4EKH6Q
aws_secret_access_key = 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
region=eu-central-1
```

# 测试

就是这样；尝试以下命令，如果您有任何 Lambda 函数，您应该能够看到它们被列出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/fc8c86f5-0db3-4547-8da4-cbb7db791d1f.png)

默认输出为 JSON。您可以通过添加`--output`选项（支持的值：*json*、*table*、*text*）来更改命令的输出格式。以下是以表格格式显示的结果：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/07bcdb7f-2e39-4fce-b308-c7bdd5de8aca.png)

此外，您可以使用`--query`选项从此 JSON 文档中提取输出元素。例如，要输出函数名称属性，可以使用以下命令：

```go
aws lambda list-functions --query Functions[].FunctionName
```

输出应该类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/bacc9024-c0f8-4e4b-a722-0b2c670ee374.png)

可以使用`jq`这样的工具来操作 JSON。它使我们能够针对 CLI 返回的 JSON 进行过滤、映射、计数和执行其他高级 JSON 处理：

```go
aws lambda list-functions | jq '.Functions[].FunctionName'
```

控制台将显示以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/65fd55d9-0655-478f-a6be-6e856aad12b7.png)

# 设置 Go 环境

本节将指导您如何在多个平台上下载和安装 Go，如何构建一个简单的 Hello World 应用程序，以及如何使用 IDE 加快 Go 开发速度。在此过程中，您将熟悉编写 Go 函数所需的 Go 命令。

# 运行时环境

从 Go 下载页面（[`golang.org/dl/`](https://golang.org/dl/)）下载适合您操作系统和架构的适当软件包：

+   **对于 macOS X：**下载`goVersion.darwin.amd64.pkg`文件，并按照安装提示进行操作。您可能需要重新启动任何打开的终端会话以使更改生效。

+   **对于 Windows**：下载 MSI 安装程序并按照向导进行操作。安装程序将为您设置环境变量。

+   **对于 Linux**：打开一个新的终端会话，并键入以下命令（在撰写本文时，当前版本为 1.10）：

```go
curl https://golang.org/doc/install?download=go1.10.1.linux-amd64.tar.gz -O /tmp/go1.10.tar.gz
tar -C /usr/local -xzf /tmp/go1.10.tar.gz
```

前面的命令将使用`curl`下载最新的 Go 包。然后，它将使用`tar`来解压该包。接下来，通过将以下行添加到您的 shell 的配置脚本中，将`/usr/local/go/bin`添加到`PATH`环境变量中：

```go
export PATH=$PATH:/usr/local/go/bin
```

如果您将 Go 安装在自定义目录中，而不是`/usr/local`，您必须设置`GOROOT`环境变量，指向安装目录：

```go
export GOROOT=PATH/go
export PATH=$PATH:$GOROOT/bin
```

然后您需要重新加载用户配置文件以应用更改：

```go
$ source ~/.bash_profile
```

现在 Go 已经正确安装，并且已经为您的计算机设置了路径，让我们来测试一下。创建一个工作区，我们将在整本书中构建我们的无服务器应用程序：

```go
mkdir -p $HOME/go/src
```

Go 源代码位于工作区中；默认情况下应该是`$HOME/go`。如果您想使用不同的目录，您需要设置`GOPATH`环境变量。

要验证 Go 工作区是否正确配置，您可以运行`go env`命令：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/e73dbc4f-41ce-49e3-acc5-37b55ef37028.png)

如果设置了`GOPATH`变量，您就可以开始了。在工作区内，使用`vim`创建一个`main.go`文件，内容如下：

```go
package main
import "fmt"

func main(){
  fmt.Println("Welcome to 'Hands-On serverless Applications with Go'")
}
```

使用以下命令编译文件：

```go
go run main.go
```

如果成功运行，文件将显示“欢迎来到'使用 Go 进行无服务器应用'”，这表明 Go 正在正确编译文件。

Go 是一种编译语言，因此您可以使用以下命令为应用程序生成单个二进制文件：

```go
go build -o app main.go
```

如果您想为特定的操作系统和架构构建可执行文件，可以覆盖`GOOS`和`GOARCH`参数：

```go
GOOS=linux GOARCH=amd64 go build -o app main.go
```

使用 vim 文本编辑器编辑 Go 并不是最佳选择；因此，在下一节中，我将向您展示如何使用 VSCode 作为 Go 编辑器，以增强您的开发生产力/体验。

# 开发环境

拥有一个 IDE 可以提高您的开发速度，并节省大量时间，这些时间可以用于调试和搜索正确的语法。此外，您可以轻松导航和搜索 Lambda 函数代码。

但我们应该使用哪一个呢？有许多解决方案；这些解决方案可以分为三个主要类别：

+   **IDE**：GoLand，Eclipse，Komodo

+   **编辑器**：Atom，VSCode，Sublime Text

+   **基于云的 IDE**：Cloud9，Codeanywhere，CodeEnvy

Go 生态系统提供了各种编辑器和 IDE；确保您尝试它们，找到最适合您的那个。

我选择了 Visual Studio Code（VS Code），因为它符合我的所有标准：

+   开源

+   支持多种语言

+   插件驱动工具

+   强大的社区和支持

VSCode 对 Go 开发有很好的支持，包括开箱即用的语法高亮显示，内置的 GIT 集成，所有 Go 工具的集成以及 Delve 调试器。

除了对 Go 的本机支持外，开源社区还构建了一些有用和强大的插件，您可以从 VSCode Marketplace 安装：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/fb1dfa15-617b-41cc-abb5-404d208f4fce.png)

VSCode 也是跨平台的，因此您可以在 Mac、Linux 或 Windows 上使用它。使用 Visual Studio Code，您可以通过一系列可用的插件扩展功能，这些插件带来了许多强大和稳健的功能，例如以下内容：

+   **自动完成**：在编写 Go 文件时，您可以看到 IntelliSense 提供了建议的完成：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/0bbd3ee9-32bc-44e2-bda7-87c539cb1e96.png)

+   **签名帮助**：悬停在任何变量、函数或结构上都会给出有关该项的信息，例如文档、签名、预期输入和输出参数。例如，以下屏幕截图显示了有关`Println`的信息，该信息是从悬停在`main.go`文件上获得的：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/ab28ea9a-b336-4d88-b0a9-76e02fa4ffc7.png)

+   **代码格式化**：它会在保存时自动格式化您的 Go 源代码，使用**gofmt**工具，使您的代码更易于编写、阅读和维护。

+   **集成调试器**：您可以设置断点和条件断点，并查看每个帧中的堆栈跟踪和本地和全局变量。

+   **自动导入 Go 包**：它会在保存时自动导入所需的 Go 包。

+   **测试运行器**：它允许您运行、停止和重新启动单元测试以及集成测试。

我期待着 JetBrains 发布的 GoLand 的稳定版本：它看起来是一个非常有前途的 Go IDE，我很期待它的发展。

就是这样！您已经准备好开始在 Go 中构建和部署无服务器应用程序。

# 摘要

在本章中，我们学习了如何安装、配置和使用 AWS CLI。当涉及管理 AWS 服务和自动部署 Lambda 函数时，这个工具将非常有帮助。然后，我们介绍了如何创建用户并从 IAM 生成 AWS 凭据，以获取最少必要的权限。这样，如果您的访问密钥落入错误的手中，造成的危害将是有限的。此外，我们学习了如何设置 Go 环境，逐步在多个平台（Windows、macOS X 和 Linux）上安装 Go，并编译了我们的第一个 Go 中的 Hello World 应用程序。在此过程中，我们介绍了 Go 中最重要的命令，这将帮助您轻松地跟随后面的章节。

在下一章中，我们将终于动手编写我们的第一个 Go 中的 Lambda 函数。

# 问题

1.  AWS CLI 不支持哪种格式？

+   JSON

+   表

+   XML

+   文本

1.  是否建议使用 AWS 根帐户进行日常与 AWS 的交互？如果是，为什么？

1.  您需要设置哪些环境变量才能使用 AWS CLI？

1.  如何使用带有命名配置文件的 AWS CLI？

1.  解释 GOPATH 环境变量。

1.  哪个命令行命令编译 Go 程序？

+   `go build`

+   `go run`

+   `go fmt`

+   `go doc`

1.  什么是 Go 工作区？


# 第三章：使用 Lambda 开发无服务器函数

在本章中，我们最终将学习如何从头开始编写我们的第一个基于 Go 的 Lambda 函数，然后学习如何手动配置、部署和测试 Lambda 函数。在此过程中，您将获得一组关于如何授予函数访问权限以便安全地与其他 AWS 服务进行交互的提示。

我们将涵盖以下主题：

+   用 Go 编写 Lambda 函数

+   执行角色

+   部署包

+   事件测试

# 技术要求

为了跟随本章，您需要按照上一章中描述的设置和配置您的 Go 和 AWS 开发环境。熟悉 Go 是首选但不是必需的。本章的代码包托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go`](https://github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go)。

# 用 Go 编写 Lambda 函数

按照本节中的步骤从头开始创建您的第一个 Go Lambda 函数：

1.  编写 Lambda 函数需要安装一些依赖项。因此，打开一个新的终端会话，并使用以下命令安装 Go Lambda 包：

```go
go get github.com/aws/aws-lambda-go/lambda
```

1.  接下来，打开您喜欢的 Go IDE 或编辑器；在我的情况下，我将使用 VS Code。在**GOPATH**中创建一个新的项目目录，然后将以下内容粘贴到`main.go`文件中：

```go
package main

import "github.com/aws/aws-lambda-go/lambda"

func handler() (string, error){
  return "Welcome to Serverless world", nil
}

func main() {
  lambda.Start(handler)
}
```

前面的代码使用`lambda.Start()`方法注册一个入口点处理程序，其中包含当调用 Lambda 函数时将执行的代码。Lambda 支持的每种语言都有其自己的要求，用于定义如何定义函数处理程序。对于 Golang，处理程序签名必须满足以下标准：

+   +   它必须是一个函数

+   它可以有 0 到 2 个参数

+   它必须返回一个错误

1.  接下来，登录到 AWS 管理控制台（[`console.aws.amazon.com/console/home`](https://console.aws.amazon.com/console/home)）并从“计算”部分选择 Lambda：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/412343fb-3776-4b96-b9f2-50f5b67e7a32.png)

1.  在 AWS Lambda 控制台中，点击“创建函数”按钮，然后按照向导创建您的第一个 Lambda 函数：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/a5cdb37f-7e6a-4c25-b95e-2b9ae9d89638.png)

1.  选择从头开始的作者选项，为您的函数命名，然后从支持的语言列表中选择 Go 1.x 作为运行时环境：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/ab9ba4d1-724a-44e2-90dc-a3f8b7e59aa4.png)

您必须为您的 Lambda 函数分配一个 IAM 角色（称为执行角色）。附加到该角色的 IAM 策略定义了您的函数代码被授权与哪些 AWS 服务进行交互。

# 执行角色

1.  现在我们已经学会了如何编写我们的第一个 Go Lambda 函数，让我们从身份和访问管理（[`console.aws.amazon.com/iam/home`](https://console.aws.amazon.com/iam/home)）中创建一个新的 IAM 角色，以授予函数访问 AWS CloudWatch 日志的权限：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/fed0ecb8-e57c-4f10-bd5e-2c97d6399375.png)

1.  在权限页面上，您可以选择一个现有的 AWS 托管策略，称为 CloudWatchFullAccess，或者（如第 3 步所示）创建一个最小特权的 IAM 角色（AWS 推荐的第二个选项；专门讨论安全最佳实践的章节将深入讨论 Lambda 函数）：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/54765997-c910-430a-9ad0-1951e03e8c4e.png)

1.  继续点击“创建策略”按钮，并通过从可视编辑器中选择适当的服务（`CloudWatch`）来创建一个策略：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/6eb0c424-cde0-40b7-8aa8-7e519a3478d4.png)

1.  对于熟悉 JSON 格式的读者，可以在 JSON 选项卡中使用 JSON 策略文档。该文档必须有一个声明，授予创建日志组和日志流以及将日志事件上传到 AWS CloudWatch 的权限：

```go
{
 "Version": "2012-10-17",
 "Statement": [
    {
      "Sid": "VisualEditor0",
      "Effect": "Allow",
      "Action": [
         "logs:CreateLogStream",
         "logs:CreateLogGroup",
         "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
 }
```

1.  在“审阅策略”页面上，为策略输入名称和描述：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/f2322533-cdd1-4dc5-b282-bc2dc39c21a1.png)

1.  返回“创建角色”页面，点击“刷新”，您应该看到我们之前创建的策略：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/e08e45ad-56f4-466e-a29b-ee206af94ef5.png)

1.  在“审阅”页面上，为角色输入名称并选择“创建角色”：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/8eeaac41-4450-4192-ba70-bed47810e001.png)

1.  现在我们的角色已经定义，返回 Lambda 表单创建并从现有角色下拉列表中选择 IAM 角色（可能需要刷新页面以使更改生效），然后点击“创建函数”按钮：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/2b51eed3-fd9b-4482-901c-9ff3c6f15b75.png)

可以选择使用 AWS CLI 部署 Lambda 函数。有关此内容及其逐步过程的更全面讨论将保留在第六章中，“部署您的无服务器应用程序”中进行。

Lambda 控制台将显示绿色的成功消息，表示您的函数已成功创建：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/98a02fa0-b70d-4d9b-96ed-8aec263a7c0e.png)

在编写、打包和创建 Lambda 函数之后，我们有各种配置选项可设置，定义代码在 Lambda 中的执行方式。如前面的截图所示，您可以通过不同的 AWS 服务（称为触发器）触发 Lambda 函数。

将其余高级设置保持不变（VPC、资源使用、版本、别名和并发），因为它们将在后续章节中进行深入讨论。

由于 Go 是最近添加的语言，其开发人员尚未添加内联编辑器的功能，因此您必须以 ZIP 文件格式提供可执行二进制文件，或者引用您已上传包的 S3 存储桶和对象键：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/cf6af336-36cb-4fe1-a38b-e4226554ddb5.png)

# 部署包

在本节中，我们将看到如何为函数构建部署包以及如何将其部署到 AWS Lambda 控制台。

# 上传 ZIP 文件

如第一章“Go 无服务器”中所述，Go 是一种编译语言。因此，您必须使用以下 Shell 脚本生成可执行二进制文件：

```go
#!/bin/bash

echo "Build the binary"
GOOS=linux GOARCH=amd64 go build -o main main.go

echo "Create a ZIP file"
zip deployment.zip main

echo "Cleaning up"
rm main
```

Lambda 运行时环境基于**Amazon Linux AMI**；因此，处理程序应为 Linux 编译（注意使用`GOOS`标志）。

对于 Windows 用户，建议您使用`build-lambda-zip`工具为 Lambda 创建一个可用的 ZIP 文件。

执行以下 Shell 脚本：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/9a2cdf06-74fa-4cc7-9a83-8a4f00696fee.png)

现在我们的 ZIP 文件已经生成；您现在可以返回 Lambda 控制台并上传 ZIP 文件，确保更新处理程序为 main 并保存结果：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/f62c09cb-8c95-48a7-a6d7-246b4dc837e7.png)

处理程序配置属性必须与可执行文件的名称匹配。如果您使用不同名称构建（`go build -o NAME`）二进制文件，则必须相应地更新处理程序属性。

# 从 Amazon S3 上传

将部署包上传到 Lambda 的另一种方法是使用 AWS S3 存储桶存储 ZIP 文件。在存储中，选择 S3 打开 Amazon S3 控制台：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/2f930baf-b8a9-4528-b9a1-4a6501f1a198.png)

在您可以将 ZIP 上传到 Amazon S3 之前，您必须在创建 Lambda 函数的同一 AWS 区域中创建一个新的存储桶，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/0de5d7c0-9d7f-4043-8294-ebe080a69df8.png)

S3 存储桶具有全局命名空间。因此，它必须在 Amazon S3 中所有现有存储桶名称中全局唯一。

现在您已经创建了一个存储桶，将在上一节中生成的 ZIP 文件拖放到目标存储桶中，或者使用上传按钮：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/2227f1b1-ef0d-4640-bb0c-c4723367f6d1.png)

可以使用 AWS CLI 将部署包上传到 S3 存储桶，如下所示：

```go
aws s3 cp deployment.zip s3://hello-serverless-packt
```

确保 IAM 用户被授予`S3:PutObject`权限，以便使用 AWS 命令行上传对象。

上传后，选择 ZIP 文件并将链接值复制到剪贴板：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/ab64bc3c-3b3e-4ef2-b8bd-a2aa51543acf.png)

返回 Lambda 仪表板，从“代码输入类型”下拉列表中选择“从 Amazon S3 上传文件”，然后粘贴 S3 中部署包的路径：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/489b333e-e286-4a15-af88-713128355c7c.png)

保存后，您可以在 AWS Lambda 控制台中测试 Lambda 函数。

# 事件测试

以下步骤将演示如何从控制台调用 Lambda 函数：

1.  现在函数已部署，让我们通过单击控制台右上角的“测试”按钮，手动使用示例事件数据来调用它。

1.  选择“配置测试事件”会打开一个新窗口，其中有一个下拉菜单。下拉菜单中的项目是样本 JSON 事件模板，这些模板是 Lambda 可以消耗的源事件或触发器的模拟，以便测试其功能（回顾第一章，*Go Serverless*）：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/d4d4c786-f965-4dba-8a24-6ffa7e04a358.png)

1.  保留默认的 Hello World 选项。输入事件名称并提供一个空的 JSON 对象：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/b0cc4403-eea5-4c3d-9343-9ffac4c768db.png)

1.  选择创建。保存后，您应该在测试列表中看到 EmptyInput：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/117b2716-dc07-4452-a260-186a9edd852d.png)

1.  再次单击“测试”按钮。AWS Lambda 将执行您的函数并显示以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/4eccea08-95bf-4f06-ac86-adf5aa64dd27.png)

除了函数返回的结果外，我们还将能够看到“欢迎来到无服务器世界”，这是关于 Lambda 函数的资源使用和执行持续时间的全局概述，以及 Lambda 函数写入 CloudWatch 的日志。

将在第十一章中讨论使用 CloudWatch 指标进行高级监控以及使用 CloudWatch 日志和 CloudTrail 进行日志记录和故障排除。

恭喜！您刚刚设置并部署了您的第一个 Lambda 函数。当您使用触发器或源事件与 Lambda 函数一起使用时，Lambda 的真正力量就会显现出来，因此它会根据发生的事件执行。我们将在下一章中看看这一点。

# 摘要

在本章中，我们学习了如何从头开始使用 Go 编写 Lambda 函数。然后，我们介绍了如何为 Lambda 创建执行角色，以便将事件日志生成到 AWS CloudWatch。我们还学习了如何从 AWS Lambda 控制台手动测试和调用此函数。

在下一章中，我将向您介绍如何使用触发器自动调用 Lambda 函数，以及如何使用 AWS API Gateway 构建一个统一的 RESTful API 来执行 Lambda 函数以响应 HTTP 请求。

# 问题

1.  为 AWS Lambda 函数创建 IAM 角色的命令行命令是什么？

1.  在弗吉尼亚地区（*us-east-1*）创建一个新的 S3 存储桶并将 Lambda 部署包上传到其中的命令行命令是什么？

1.  Lambda 包大小限制是多少？

+   10 MB

+   50 MB

+   250 MB

1.  AWS Lambda 控制台支持编辑 Go 源代码。

+   True

+   False

1.  AWS Lambda 执行环境的基础是什么？

+   Amazon Linux 镜像

+   Microsoft Windows Server

1.  AWS Lambda 中如何表示事件？


# 第四章：使用 API 网关设置 API 端点

在上一章中，我们学习了如何使用 Go 构建我们的第一个 Lambda 函数。我们还学习了如何从控制台手动调用它。为了利用 Lambda 的强大功能，在本章中，我们将学习如何在收到 HTTP 请求时触发这个 Lambda 函数（事件驱动架构）使用 AWS API 网关服务。在本章结束时，您将熟悉 API 网关高级主题，如资源、部署阶段、调试等。

我们将涵盖以下主题：

+   开始使用 API 网关

+   构建 RESTful API

# 技术要求

本章是上一章的后续内容，因此建议先阅读上一章，以便轻松地理解本部分。此外，需要对 RESTful API 设计和实践有基本的了解。本章的代码包托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go`](https://github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go)。

# 开始使用 API 网关

API 网关是 AWS 无服务器 API 代理服务，允许您为所有 Lambda 函数创建一个单一且统一的入口点。它代理和路由传入的 HTTP 请求到适当的 Lambda 函数（映射）。从服务器端的角度来看，它是一个外观或包装器，位于 Lambda 函数的顶部。但是，从客户端的角度来看，它只是一个单一的单片应用程序。

除了为客户端提供单一接口和可伸缩性外，API 网关还提供了以下强大功能：

+   **缓存**：您可以缓存端点响应，从而减少对 Lambda 函数的请求次数（成本优化）并增强响应时间。

+   **CORS 配置**：默认情况下，浏览器拒绝从不同域的资源访问。可以通过在 API 网关中启用**跨域资源共享**（**CORS**）来覆盖此策略。

CORS 将在第九章中深入讨论，*使用 S3 构建前端*，并提供一个实际示例。

+   **部署阶段/生命周期**：您可以管理和维护多个 API 版本和环境（沙盒、QA、暂存和生产）。

+   **监控**：通过启用与 API 网关的 CloudWatch 集成，简化故障排除和调试传入请求和传出响应。它将推送一系列日志事件到 AWS CloudWatch 日志，并且您可以向 CloudWatch 公开一组指标，包括：

+   客户端错误，包括 4XX 和 5XX 状态代码

+   在给定周期内的 API 请求总数

+   端点响应时间（延迟）

+   **可视化编辑**：您可以直接从控制台描述 API 资源和方法，而无需任何编码或 RESTful API 知识。

+   **文档**：您可以为 API 的每个版本生成 API 文档，并具有导入/导出和发布文档到 Swagger 规范的能力。

+   **安全和身份验证**：您可以使用 IAM 角色和策略保护您的 RESTful API 端点。API 网关还可以充当防火墙，防止 DDoS 攻击和 SQL/脚本注入。此外，可以在此级别强制执行速率限制或节流。

以上是足够的理论。在下一节中，我们将介绍如何设置 API 网关以在收到 HTTP 请求时触发我们的 Lambda 函数。

除了支持 AWS Lambda 外，API 网关还可用于响应 HTTP 请求调用其他 AWS 服务（EC2、S3、Kinesis、CloudFront 等）或外部 HTTP 端点。

# 设置 API 端点

以下部分描述了如何使用 API 网关触发 Lambda 函数：

1.  要设置 API 端点，请登录到**AWS 管理控制台**（[`console.aws.amazon.com/console/home`](https://console.aws.amazon.com/console/home)），转到 AWS Lambda 控制台，并选择我们在上一章节中构建的 Lambda 函数 HelloServerless：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/ec552854-7f6a-4af7-a783-a47090e60fcf.png)

1.  从可用触发器列表中搜索 API 网关并单击它：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/7c108355-b25b-4606-999f-9f0eae4e15fc.png)

可用触发器的列表可能会根据您使用的 AWS 区域而变化，因为 AWS Lambda 支持的源事件并不在所有 AWS 区域都可用。

1.  页面底部将显示一个“配置触发器”部分，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/b890ed7d-ec62-413d-8aba-988cfce91843.png)

1.  创建一个新的 API，为其命名，将部署阶段设置为`staging`，并将 API 公开给公众：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/c50f7775-2b70-4e2c-9889-a2a85a45bdfd.png)

表格将需要填写以下参数：

+   **API 名称**：API 的唯一标识符。

+   **部署阶段**：API 阶段环境，有助于分隔和维护不同的 API 环境（开发、staging、生产等）和版本/发布（主要、次要、测试等）。此外，如果实施了持续集成/持续部署流水线，它非常方便。

+   **安全性**：它定义了 API 端点是公开还是私有：

+   **开放**：可公开访问，任何人都可以调用

+   **AWS IAM**：将由被授予 IAM 权限的用户调用

+   **使用访问密钥打开**：需要 AWS 访问密钥才能调用

1.  定义 API 后，将显示以下部分：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/82193949-da9d-43db-a379-08813ace3a85.png)

1.  单击页面顶部的“保存”按钮以创建 API 网关触发器。保存后，API 网关调用 URL 将以以下格式生成：`https://API_ID.execute-api.AWS_REGION.amazonaws.com/DEPLOYMENT_STAGE/FUNCTION_NAME`，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/c7e5a33e-5bab-4a0d-ac91-0443b7a6cb54.png)

1.  使用 API 调用 URL 在您喜欢的浏览器中打开，您应该会看到如下屏幕截图中所示的消息：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/8c7c1435-c10c-49a2-8412-df2be96ce26c.png)

1.  内部服务器错误消息意味着 Lambda 方面出现了问题。为了帮助我们解决问题并调试问题，我们将在 API 网关中启用日志记录功能。

# 调试和故障排除

为了解决 API 网关服务器错误，我们需要按照以下步骤启用日志记录：

1.  首先，我们需要授予 API 网关访问 CloudWatch 的权限，以便能够将 API 网关日志事件推送到 CloudWatch 日志中。因此，我们需要从身份和访问管理中创建一个新的 IAM 角色。

为了避免重复，有些部分已被跳过。如果您需要逐步操作，请确保您已经从上一章节开始。

下面的屏幕截图将让您了解如何创建 IAM 角色：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/bd8f0a0c-1dc3-47e3-9afa-06b63bef37f1.png)

1.  从 AWS 服务列表中选择 API 网关，然后在权限页面上，您可以执行以下操作之一：

+   选择一个名为 AmazonAPIGatewayPushToCloudWatchLogs 的现有策略，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/a062fcf9-e705-4f16-ab36-220ba6f9a605.png)

+   +   创建一个新的策略文档，其中包含以下 JSON：

```go
{
 "Version": "2012-10-17",
 "Statement": [
 {
 "Effect": "Allow",
     "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:PutLogEvents",
        "logs:GetLogEvents",
        "logs:FilterLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

1.  接下来，为角色指定一个名称，并将角色 ARN（Amazon 资源名称）复制到剪贴板上：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/682c4898-26b9-431a-b1fb-b5ee95adba11.png)

1.  然后，从“网络和内容传递”部分选择 API 网关。单击“设置”，粘贴我们之前创建的 IAM 角色 ARN：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/53c94f8d-7384-4dc9-b0f9-3ced14c6d161.png)

1.  保存并选择由 Lambda 函数创建的 API。在导航窗格中单击“阶段”：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/e2d174ac-a164-491b-8809-4669599eb33b.png)

1.  然后，点击日志选项卡，在 CloudWatch 设置下，点击启用 CloudWatch 日志，并选择要捕获的日志级别。在这种情况下，我们对错误日志感兴趣：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/9ab2557f-c566-4b95-9081-3c6989bd55b7.png)

1.  尝试使用 API URL 再次调用 Lambda，并跳转到 AWS CloudWatch 日志控制台；您会看到已创建了一个新的日志组，格式为*API-Gateway-Execution-Logs_AP_ID/DEPLOYMENT_STAGE*：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/041d48b4-8982-4bf3-8151-aedc5c1ceea9.png)

1.  点击日志组，您将看到 API 网关生成的日志流：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/09c34f90-5688-45da-9238-9c480fbcf6fb.png)

1.  前面的日志表明，从 Lambda 函数返回的响应格式不正确。正确的响应格式应包含以下属性：

+   **Body**：这是一个必需的属性，包含函数的实际输出。

+   **状态码**：这是函数响应状态码，如 HTTP/1.1 标准中所述([`tools.ietf.org/html/rfc7231#section-6`](https://tools.ietf.org/html/rfc7231#section-6))。这是强制性的，否则 API 网关将显示 5XX 错误，如前一节所示。

+   **可选参数**：它包括`Headers`和`IsBase64Encoded`等内容。

在接下来的部分中，我们将通过格式化 Lambda 函数返回的响应来修复此错误响应，以满足 API 网关期望的格式。

# 使用 HTTP 请求调用函数

如前一节所示，我们需要修复 Lambda 函数返回的响应。我们将返回一个包含实际字符串值的`struct`变量，以及一个`StatusCode`，其值为`200`，告诉 API 网关请求成功。为此，更新`main.go`文件以匹配以下签名：

```go
package main

import "github.com/aws/aws-lambda-go/lambda"

type Response struct {    
  StatusCode int `json:"statusCode"`
  Body string `json:"body"`
}

func handler() (Response, error) {
  return Response{
    StatusCode: 200,
    Body: "Welcome to Serverless world",
  }
, nil
}

func main() {
  lambda.Start(handler)
} 
```

更新后，使用上一章节提供的 Shell 脚本构建部署包，并使用 AWS Lambda 控制台上传包到 Lambda，或使用以下 AWS CLI 命令：

```go
aws lambda update-function-code --function-name HelloServerless \
 --zip-file fileb://./deployment.zip \
 --region us-east-1
```

确保您授予 IAM 用户`lambda:CreateFunction`和`lambda:UpdateFunctionCode`权限，以便在本章节中使用 AWS 命令行。

返回到您的网络浏览器，并再次调用 API 网关 URL：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/d26a326f-64ed-4c68-ab2d-4922e7001f60.png)

恭喜！您刚刚使用 Lambda 和 API 网关构建了您的第一个事件驱动函数。

供快速参考，Lambda Go 包提供了一种更容易地将 Lambda 与 API 网关集成的方法，即使用`APIGatewayProxyResponse`结构。

```go
package main

import (
  "github.com/aws/aws-lambda-go/events"
  "github.com/aws/aws-lambda-go/lambda"
)

func handler() (events.APIGatewayProxyResponse, error) {
  return events.APIGatewayProxyResponse{
    StatusCode: 200,
    Body: "Welcome to Serverless world",
  }, nil
}

func main() {
  lambda.Start(handler)
}
```

现在我们知道如何在响应 HTTP 请求时调用 Lambda 函数，让我们进一步构建一个带有 API 网关的 RESTful API。

# 构建 RESTful API

在本节中，我们将从头开始设计、构建和部署一个 RESTful API，以探索涉及 Lambda 和 API 网关的一些高级主题。

# API 架构

在进一步详细介绍架构之前，我们将看一下一个 API，它将帮助本地电影租赁店管理其可用电影。以下图表显示了 API 网关和 Lambda 如何适应 API 架构：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/6db48f44-d52f-4e97-bfd3-7ff4dfe20831.png)

AWS Lambda 赋予了微服务开发的能力。也就是说，每个端点触发不同的 Lambda 函数。这些函数彼此独立，可以用不同的语言编写。因此，这导致了在函数级别的扩展、更容易的单元测试和松散的耦合。

所有来自客户端的请求首先经过 API 网关。然后将传入的请求相应地路由到正确的 Lambda 函数。

请注意，单个 Lambda 函数可以处理多个 HTTP 方法（`GET`，`POST`，`PUT`，`DELETE`等）。为了利用微服务的优势，我们将为每个功能创建多个 Lambda 函数。但是，构建一个单一的 Lambda 函数来处理多个端点可能是一个很好的练习。

# 端点设计

现在架构已经定义好了，我们将实现前面图表中描述的功能。

# GET 方法

要实现的第一个功能是列出电影。这就是`GET`方法发挥作用的地方。要执行此操作，需要参考以下步骤：

1.  创建一个 Lambda 函数来注册`findAll`处理程序。此处理程序将`movies`结构的列表转换为`string`，然后将此字符串包装在`APIGatewayProxyResponse`变量中，并返回带有 200 HTTP 状态代码的字符串。它还处理转换失败的错误。处理程序的实现如下：

```go
package main

import (
  "encoding/json"

  "github.com/aws/aws-lambda-go/events"
  "github.com/aws/aws-lambda-go/lambda"
)

var movies = []struct {
  ID int `json:"id"`
  Name string `json:"name"`
}{
    {
      ID: 1,
      Name: "Avengers",
    },
    {
      ID: 2,
      Name: "Ant-Man",
    },
    {
      ID: 3,
      Name: "Thor",
    },
    {
      ID: 4,
      Name: "Hulk",
    }, {
      ID: 5,
      Name: "Doctor Strange",
    },
}

func findAll() (events.APIGatewayProxyResponse, error) {
  response, err := json.Marshal(movies)
  if err != nil {
    return events.APIGatewayProxyResponse{}, err
  }

  return events.APIGatewayProxyResponse{
    StatusCode: 200,
    Headers: map[string]string{
      "Content-Type": "application/json",
    },
    Body: string(response),
  }, nil
}

func main() {
  lambda.Start(findAll)
}
```

您可以使用`net/http` Go 包而不是硬编码 HTTP 状态代码，并使用内置的状态代码变量，如`http.StatusOK`，`http.StatusCreated`，`http.StatusBadRequest`，`http.StatusInternalServerError`等。

1.  然后，在构建 ZIP 文件后，使用 AWS CLI 创建一个新的 Lambda 函数：

```go
aws lambda create-function --function-name FindAllMovies \
 --zip-file fileb://./deployment.zip \
 --runtime go1.x --handler main \
 --role arn:aws:iam::ACCOUNT_ID:role/FindAllMoviesRole \
 --region us-east-1
```

`FindAllMoviesRole`应该事先创建，如前一章所述，具有允许流式传输 Lambda 日志到 AWS CloudWatch 的权限。

1.  返回 AWS Lambda 控制台；您应该看到函数已成功创建：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/68a10a54-c57b-4215-bc13-5e5963bef6cf.png)

1.  创建一个带有空 JSON 的示例事件，因为该函数不需要任何参数，并单击“测试”按钮：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/3ded86f5-21f6-43db-bf03-7788caf6e811.png)

您会注意到在前一个屏幕截图中，该函数以 JSON 格式返回了预期的输出。

1.  现在函数已经定义好了，我们需要创建一个新的 API 网关来触发它：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/4a6419f0-5de2-4331-a49d-fdc40860d891.png)

1.  接下来，从“操作”下拉列表中选择“创建资源”，并将其命名为 movies：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/4035b98f-73ab-455a-8b9b-452485e533a8.png)

1.  通过单击“创建方法”在`/movies`资源上公开一个 GET 方法。在“集成类型”部分下选择 Lambda 函数，并选择*FindAllMovies*函数：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/fd7952a6-1fe9-4a99-b4dd-fc1fb6204c57.png)

1.  要部署 API，请从“操作”下拉列表中选择“部署 API”。您将被提示创建一个新的部署阶段：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/048ca6a2-b121-4e8e-a884-263a07f18a3a.png)

1.  创建部署阶段后，将显示一个调用 URL：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/0b3c50d4-bbb7-44fd-b5c8-b24f44667c92.png)

1.  将浏览器指向给定的 URL，或者使用像 Postman 或 Insomnia 这样的现代 REST 客户端。我选择使用 cURL 工具，因为它默认安装在几乎所有操作系统上：

```go
curl -sX GET https://51cxzthvma.execute-api.us-east-1.amazonaws.com/staging/movies | jq '.'
```

上述命令将以 JSON 格式返回电影列表：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/21ebbf74-2264-4953-8197-bae5bcd7ebbb.png)

当调用`GET`端点时，请求将通过 API 网关，触发`findAll`处理程序。这将返回一个以 JSON 格式代理给客户端的响应。

现在`findAll`函数已经部署，我们可以实现一个`findOne`函数来按其 ID 搜索电影。

# 带参数的 GET 方法

`findOne`处理程序期望包含事件输入的`APIGatewayProxyRequest`参数。然后，它使用`PathParameters`方法获取电影 ID 并验证它。如果提供的 ID 不是有效数字，则`Atoi`方法将返回错误，并将 500 错误代码返回给客户端。否则，将根据索引获取电影，并以包含`APIGatewayProxyResponse`的 200 OK 状态返回给客户端：

```go
...

func findOne(req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
  id, err := strconv.Atoi(req.PathParameters["id"])
  if err != nil {
    return events.APIGatewayProxyResponse{
      StatusCode: 500,
      Body:       "ID must be a number",
    }, nil
  }

  response, err := json.Marshal(movies[id-1])
  if err != nil {
    return events.APIGatewayProxyResponse{
      StatusCode: 500,
      Body:       err.Error(),
    }, nil
  }

  return events.APIGatewayProxyResponse{
    StatusCode: 200,
    Headers: map[string]string{
      "Content-Type": "application/json",
    },
    Body: string(response),
  }, nil
}

func main() {
  lambda.Start(findOne)
}
```

请注意，在上述代码中，我们使用了处理错误的两种方法。第一种是`err.Error()`方法，当编码失败时返回内置的 Go 错误消息。第二种是用户定义的错误，它是特定于错误的，易于从客户端的角度理解和调试。

类似于`FindAllMovies`函数，为搜索电影创建一个新的 Lambda 函数：

```go
aws lambda create-function --function-name FindOneMovie \
 --zip-file fileb://./deployment.zip \
 --runtime go1.x --handler main \
 --role arn:aws:iam::ACCOUNT_ID:role/FindOneMovieRole \
 --region us-east-1
```

返回 API Gateway 控制台，创建一个新资源，并公开`GET`方法，然后将资源链接到`FindOneMovie`函数。请注意路径中的`{id}`占位符的使用。`id`的值将通过`APIGatewayProxyResponse`对象提供。以下屏幕截图描述了这一点：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/72a7969a-7868-45fb-9f68-59b39d73e2c5.png)

重新部署 API，并使用以下 cURL 命令测试端点：

```go
curl -sX https://51cxzthvma.execute-api.us-east-1.amazonaws.com/staging/movies/1 | jq '.' 
```

将返回以下 JSON：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/71fb6d67-279e-4739-a3be-0dabdc8aa39c.png)

当使用 ID 调用 API URL 时，如果存在，将返回与 ID 对应的电影。

# POST 方法

现在我们知道了如何使用路径参数和不使用路径参数来使用 GET 方法。下一步将是通过 API Gateway 向 Lambda 函数传递 JSON 有效负载。代码是不言自明的。它将请求输入转换为电影结构，将其添加到电影列表中，并以 JSON 格式返回新的电影列表：

```go
package main

import (
  "encoding/json"

  "github.com/aws/aws-lambda-go/events"
  "github.com/aws/aws-lambda-go/lambda"
)

type Movie struct {
  ID int `json:"id"`
  Name string `json:"name"`
}

var movies = []Movie{
  Movie{
    ID: 1,
    Name: "Avengers",
  },
  ...
}

func insert(req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
  var movie Movie
  err := json.Unmarshal([]byte(req.Body), &movie)
  if err != nil {
    return events.APIGatewayProxyResponse{
      StatusCode: 400,
      Body: "Invalid payload",
    }, nil
  }

  movies = append(movies, movie)

  response, err := json.Marshal(movies)
  if err != nil {
    return events.APIGatewayProxyResponse{
      StatusCode: 500,
      Body: err.Error(),
    }, nil
  }

  return events.APIGatewayProxyResponse{
    StatusCode: 200,
    Headers: map[string]string{
      "Content-Type": "application/json",
    },
    Body: string(response),
  }, nil
}

func main() {
  lambda.Start(insert)
}
```

接下来，使用以下命令为`InsertMovie`创建一个新的 Lambda 函数*：*

```go
aws lambda create-function --function-name InsertMovie \
 --zip-file fileb://./deployment.zip \
 --runtime go1.x --handler main \
 --role arn:aws:iam::ACCOUNT_ID:role/InsertMovieRole \
 --region us-east-1
```

接下来，在`/movies`资源上创建一个`POST`方法，并将其链接到`InsertMovie`函数：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/60b78a39-0b53-4814-b6e9-2f69bce47766.png)

要测试它，使用以下 cURL 命令，使用`POST`动词和`-d`标志，后跟 JSON 字符串（带有`id`和`name`属性）：

```go
curl -sX POST -d '{"id":6, "name": "Spiderman:Homecoming"}' https://51cxzthvma.execute-api.us-east-1.amazonaws.com/staging/movies | jq '.'
```

上述命令将返回以下 JSON 响应：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/fe9cd668-035f-41ee-ba7d-6f2bead59d27.png)

如您所见，新电影已成功插入。如果再次测试，它应该按预期工作：

```go
curl -sX POST -d '{"id":7, "name": "Iron man"}' https://51cxzthvma.execute-api.us-east-1.amazonaws.com/staging/movies | jq '.'
```

上述命令将返回以下 JSON 响应：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/c6d4771b-cdbe-43a8-968f-01e87e45bfd0.png)

如您所见，它成功了，并且电影再次按预期插入，但是如果我们等待几分钟并尝试插入第三部电影会怎样？以下命令将用于再次执行它：

```go
curl -sX POST -d '{"id":8, "name": "Captain America"}' https://51cxzthvma.execute-api.us-east-1.amazonaws.com/staging/movies | jq '.'

```

再次，将返回一个新的 JSON 响应：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/460bf1f2-44ca-4dc9-b2a3-1b2cbe92fe02.png)

您会发现 ID 为 6 和 7 的电影已被移除；为什么会这样？很简单。如果您还记得第一章中的*Go Serverless*，Lambda 函数是无状态的。当第一次调用`InsertMovie`函数（第一次插入）时，AWS Lambda 会创建一个容器并将函数有效负载部署到容器中。然后，在被终止之前保持活动状态几分钟（**热启动**），这就解释了为什么第二次插入会成功。在第三次插入中，容器已经被终止，因此 Lambda 会创建一个新的容器（**冷启动**）来处理插入。

因此，之前的状态已丢失。以下图表说明了冷/热启动问题：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/be7e04f8-2874-4469-8b8d-0e397ac9a9ad.png)

这解释了为什么 Lambda 函数应该是无状态的，以及为什么我们不应该假设状态会从一次调用到下一次调用中保留。那么，在处理无服务器应用程序时，我们如何管理数据持久性呢？答案是使用 DynamoDB 等外部数据库，这将是即将到来的章节的主题。

# 总结

在本章中，您学习了如何使用 Lambda 和 API Gateway 从头开始构建 RESTful API。我们还介绍了如何通过启用 CloudWatch 日志功能来调试和解决传入的 API Gateway 请求，以及如何创建 API 部署阶段以及如何创建具有不同 HTTP 方法的多个端点。最后，我们了解了冷/热容器问题以及为什么 Lambda 函数应该是无状态的。

在接下来的章节中，我们将使用 DynamoDB 作为数据库，为我们的 API 管理数据持久性。


# 第五章：使用 DynamoDB 管理数据持久性

在上一章中，我们学习了如何使用 Lambda 和 API Gateway 构建 RESTful API，并发现了为什么 Lambda 函数应该是无状态的。在本章中，我们将使用 AWS DynamoDB 解决无状态问题。此外，我们还将看到如何将其与 Lambda 函数集成。

我们将涵盖以下主题：

+   设置 DynamoDB

+   使用 DynamoDB

# 技术要求

本章是上一章的后续，因为它将使用相同的源代码。因此，为避免重复，某些代码片段将不予解释。此外，最好具备 NoSQL 概念的基本知识，以便您可以轻松地跟随本章。本章的代码包托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go`](https://github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go)。

# 设置 DynamoDB

DynamoDB 是 AWS 的 NoSQL 数据库。它是一个托管的 AWS 服务，允许您在不管理或维护数据库服务器的情况下按比例存储和检索数据。

在深入了解与 AWS Lambda 的集成之前，您需要了解一些关于 DynamoDB 的关键概念：

+   **结构和设计**：

+   **表**：这是一组项目（行），其中每个项目都是一组属性（列）和值。

+   **分区键**：也称为哈希键。这是 DynamoDB 用来确定可以找到项目的分区（物理位置）（读操作）或将存储项目的分区（写操作）的唯一 ID。可以使用排序键来对同一分区中的项目进行排序。

+   **索引**：与关系数据库类似，索引用于加速查询。在 DynamoDB 中，可以创建两种类型的索引：

+   **全局二级索引**（**GSI**）

+   **本地二级索引**（**LSI**）

+   **操作**：

+   **扫描**：顾名思义，此操作在返回所请求的项目之前扫描整个表。

+   **查询**：此操作根据主键值查找项目。

+   **PutItem**：这将创建一个新项目或用新项目替换旧项目。

+   **GetItem**：通过其主键查找项目。

+   **DeleteItem**：通过其主键在表中删除单个项目。

在性能方面，扫描操作效率较低，成本较高（消耗更多吞吐量），因为该操作必须遍历表中的每个项目以获取所请求的项目。因此，始终建议使用查询而不是扫描操作。

现在您熟悉了 DynamoDB 的术语，我们可以开始创建我们的第一个 DynamoDB 表来存储 API 项目。

# 创建表

要开始创建表，请登录 AWS 管理控制台（[`console.aws.amazon.com/console/home`](https://console.aws.amazon.com/console/home)）并从**数据库**部分选择 DynamoDB。点击**创建表**按钮以创建新的 DynamoDB 表，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/d9602a30-7f26-4d7d-a22e-e2e5a3a1dada.png)

接下来，在下一个示例中为表命名为`movies`。由于每部电影将由唯一 ID 标识，因此它将是表的分区键。将所有其他设置保留为默认状态，然后点击创建，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/778d260b-e9d9-469a-a2d0-79fae4b4f2a2.png)

等待几秒钟，直到表被创建，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/ffd40dce-59bf-4d91-bfba-26dcce344897.png)

创建`movies`表后，将提示成功消息以确认其创建。现在，我们需要将示例数据加载到表中。

# 加载示例数据

要在`movies`表中填充项目，请点击**项目**选项卡：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/2b88f35a-8d5b-4991-84e8-3144f45c3fd1.png)

然后，点击**创建项目**并插入一个新电影，如下面的屏幕截图所示（您需要使用加号（+）按钮添加额外的列来存储电影名称）：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/40c329da-cd7a-41f7-b4be-670ee9a36e31.png)

点击保存。表应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/ebb6530d-ff25-41fa-98f7-4fc7e45d3f40.png)

对于真实的应用程序，我们不会使用控制台来填充数百万条目。为了节省时间，我们将使用 AWS SDK 编写一个小型的 Go 应用程序来将项目加载到表中。

在 Go 工作区中创建一个新项目，并将以下内容复制到`init-db.go`文件中：

```go
func main() {
  cfg, err := external.LoadDefaultAWSConfig()
  if err != nil {
    log.Fatal(err)
  }

  movies, err := readMovies("movies.json")
  if err != nil {
    log.Fatal(err)
  }

  for _, movie := range movies {
    fmt.Println("Inserting:", movie.Name)
    err = insertMovie(cfg, movie)
    if err != nil {
      log.Fatal(err)
    }
  }

}
```

上述代码读取一个 JSON 文件（[`github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go/blob/master/ch5/movies.json`](https://github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go/blob/master/ch5/movies.json)），其中包含一系列电影；将其编码为`Movie`结构的数组，如下所示：

```go
func readMovies(fileName string) ([]Movie, error) {
  movies := make([]Movie, 0)

  data, err := ioutil.ReadFile(fileName)
  if err != nil {
    return movies, err
  }

  err = json.Unmarshal(data, &movies)
  if err != nil {
    return movies, err
  }

  return movies, nil
}
```

然后，它遍历电影数组中的每部电影。然后，使用`PutItem`方法将其插入 DynamoDB 表中，如下所示：

```go
func insertMovie(cfg aws.Config, movie Movie) error {
  item, err := dynamodbattribute.MarshalMap(movie)
  if err != nil {
    return err
  }

  svc := dynamodb.New(cfg)
  req := svc.PutItemRequest(&dynamodb.PutItemInput{
    TableName: aws.String("movies"),
    Item: item,
  })
  _, err = req.Send()
  if err != nil {
    return err
  }
  return nil
}
```

确保使用终端会话中的`go get github.com/aws/aws-sdk-go-v2/aws`命令安装 AWS Go SDK*.*

要加载`movies`表中的数据，请输入以下命令：

```go
AWS_REGION=us-east-1 go run init-db.go
```

您可以使用 DynamoDB 控制台验证加载到`movies`表中的数据，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/729f5fbc-9820-4ce3-9161-521ce3eb2bac.png)

现在 DynamoDB 表已准备就绪，我们需要更新每个 API 端点函数的代码，以使用表而不是硬编码的电影列表。

# 使用 DynamoDB

在这一部分，我们将更新现有的函数，从 DynamoDB 表中读取和写入。以下图表描述了目标架构：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/ca81f50b-4e81-4c21-9871-6cd97eeabfc6.png)

API Gateway 将转发传入的请求到目标 Lambda 函数，该函数将在`movies`表上调用相应的 DynamoDB 操作。

# 扫描请求

要开始，我们需要实现负责返回电影列表的函数；以下步骤描述了如何实现这一点：

1.  更新`findAll`处理程序端点以使用`Scan`方法从表中获取所有项目：

```go
func findAll() (events.APIGatewayProxyResponse, error) {
  cfg, err := external.LoadDefaultAWSConfig()
  if err != nil {
    return events.APIGatewayProxyResponse{
      StatusCode: http.StatusInternalServerError,
      Body: "Error while retrieving AWS credentials",
    }, nil
  }

  svc := dynamodb.New(cfg)
  req := svc.ScanRequest(&dynamodb.ScanInput{
    TableName: aws.String(os.Getenv("TABLE_NAME")),
  })
  res, err := req.Send()
  if err != nil {
    return events.APIGatewayProxyResponse{
      StatusCode: http.StatusInternalServerError,
      Body: "Error while scanning DynamoDB",
    }, nil
  }

  response, err := json.Marshal(res.Items)
  if err != nil {
    return events.APIGatewayProxyResponse{
      StatusCode: http.StatusInternalServerError,
      Body: "Error while decoding to string value",
    }, nil
  }

  return events.APIGatewayProxyResponse{
    StatusCode: 200,
    Headers: map[string]string{
      "Content-Type": "application/json",
    },
    Body: string(response),
  }, nil
}
```

此功能的完整实现可以在 GitHub 存储库中找到（[`github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go/blob/master/ch5/findAll/main.go`](https://github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go/blob/master/ch5/findAll/main.go)）。

1.  构建部署包，并使用以下 AWS CLI 命令更新`FindAllMovies` Lambda 函数代码：

```go
aws lambda update-function-code --function-name FindAllMovies \
 --zip-file fileb://./deployment.zip \
 --region us-east-1
```

1.  确保更新 FindAllMoviesRole，以授予 Lambda 函数调用 DynamoDB 表上的`Scan`操作的权限，方法是添加以下 IAM 策略：

```go
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "1",
      "Effect": "Allow",
      "Action": "dynamodb:Scan",
      "Resource": [
        "arn:aws:dynamodb:us-east-1:ACCOUNT_ID:table/movies/index/ID",
        "arn:aws:dynamodb:us-east-1:ACCOUNT_ID:table/movies"
      ]
    }
  ]
}
```

一旦策略分配给 IAM 角色，它应该成为附加策略的一部分，如下一张截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/ec5e0848-c799-4198-9587-0907f2458486.png)

1.  最后，使用 Lambda 控制台或 AWS CLI，添加一个新的环境变量，指向我们之前创建的 DynamoDB 表名：

```go
aws lambda update-function-configuration --function-name FindAllMovies \
 --environment Variables={TABLE_NAME=movies} \
 --region us-east-1
```

下图显示了一个正确配置的 FindAllMovies 函数，具有对 DynamoDB 和 CloudWatch 的 IAM 访问权限，并具有定义的`TABLE_NAME`环境变量：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/90ddc595-42c2-4356-89a7-4a0441a012e8.png)

正确配置的 FindAllMovies 函数

1.  保存并使用以下 cURL 命令调用 API Gateway URL：

```go
curl -sX GET https://51cxzthvma.execute-api.us-east-1.amazonaws.com/staging/movies | jq '.'
```

1.  将以 JSON 格式返回一个数组，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/9970ba6a-ebfe-4d8c-96f5-fcb677345e48.png)

1.  端点正在工作，并从表中获取电影项目，但返回的 JSON 是原始的 DynamoDB 响应。我们将通过仅返回`ID`和`Name`属性来修复这个问题，如下所示：

```go
movies := make([]Movie, 0)
for _, item := range res.Items {
  movies = append(movies, Movie{
    ID: *item["ID"].S,
    Name: *item["Name"].S,
  })
}

response, err := json.Marshal(movies)
```

1.  此外，生成 ZIP 文件并更新 Lambda 函数代码，然后使用前面给出的 cURL 命令调用 API Gateway URL，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/af479fe5-73a7-486c-8dc9-b5f69ad75fa6.png)

好多了，对吧？

# GetItem 请求

要实现的第二个功能将负责从 DynamoDB 返回单个项目，以下步骤说明了应该如何构建它：

1.  更新`findOne`处理程序以调用 DynamoDB 中的`GetItem`方法。这应该返回一个带有传递给 API 端点参数的标识符的单个项目：

```go
func findOne(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
  id := request.PathParameters["id"]

  cfg, err := external.LoadDefaultAWSConfig()
  if err != nil {
    return events.APIGatewayProxyResponse{
      StatusCode: http.StatusInternalServerError,
      Body: "Error while retrieving AWS credentials",
    }, nil
  }

  svc := dynamodb.New(cfg)
  req := svc.GetItemRequest(&dynamodb.GetItemInput{
    TableName: aws.String(os.Getenv("TABLE_NAME")),
    Key: map[string]dynamodb.AttributeValue{
      "ID": dynamodb.AttributeValue{
        S: aws.String(id),
      },
    },
  })
  res, err := req.Send()
  if err != nil {
    return events.APIGatewayProxyResponse{
      StatusCode: http.StatusInternalServerError,
      Body: "Error while fetching movie from DynamoDB",
    }, nil
  }

  ...
}
```

此函数的完整实现可以在 GitHub 存储库中找到（[`github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go/blob/master/ch5/findOne/main.go`](https://github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go/blob/master/ch5/findAll/main.go)）。

1.  与`FindAllMovies`函数类似，创建一个 ZIP 文件，并使用以下 AWS CLI 命令更新现有的 Lambda 函数代码：

```go
aws lambda update-function-code --function-name FindOneMovie \
 --zip-file fileb://./deployment.zip \
 --region us-east-1
```

1.  授予`FindOneMovie` Lambda 函数对`movies`表的`GetItem`权限的 IAM 策略：

```go
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "1",
      "Effect": "Allow",
      "Action": "dynamodb:GetItem",
      "Resource": "arn:aws:dynamodb:us-east-1:ACCOUNT_ID:table/movies"
    }
  ]
}
```

1.  IAM 角色应配置如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/97c1e2d9-b691-4661-a10f-b6603de50f75.png)

1.  使用 DynamoDB 表名定义一个新的环境变量：

```go
aws lambda update-function-configuration --function-name FindOneMovie \
 --environment Variables={TABLE_NAME=movies} \
 --region us-east-1
```

1.  返回`FindOneMovie`仪表板，并验证所有设置是否已配置，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/b12ebdf3-11f4-4db8-85be-586c46979aea.png)

1.  通过发出以下 cURL 命令调用 API Gateway：

```go
curl -sX GET https://51cxzthvma.execute-api.us-east-1.amazonaws.com/staging/movies/3 | jq '.'
```

1.  如预期的那样，响应是一个具有 ID 为 3 的单个电影项目，如 cURL 命令中请求的那样：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/9d7a8cf7-359c-48f7-afbe-119c70506adc.png)

# PutItem 请求

到目前为止，我们已经学会了如何列出所有项目并从 DynamoDB 返回单个项目。以下部分描述了如何实现 Lambda 函数以将新项目添加到数据库中：

1.  更新`insert`处理程序以调用`PutItem`方法将新电影插入表中：

```go
func insert(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
  ...

  cfg, err := external.LoadDefaultAWSConfig()
  if err != nil {
    return events.APIGatewayProxyResponse{
      StatusCode: http.StatusInternalServerError,
      Body: "Error while retrieving AWS credentials",
    }, nil
  }

  svc := dynamodb.New(cfg)
  req := svc.PutItemRequest(&dynamodb.PutItemInput{
    TableName: aws.String(os.Getenv("TABLE_NAME")),
    Item: map[string]dynamodb.AttributeValue{
      "ID": dynamodb.AttributeValue{
        S: aws.String(movie.ID),
      },
      "Name": dynamodb.AttributeValue{
        S: aws.String(movie.Name),
      },
    },
  })
  _, err = req.Send()
  if err != nil {
    return events.APIGatewayProxyResponse{
      StatusCode: http.StatusInternalServerError,
      Body: "Error while inserting movie to DynamoDB",
    }, nil
  }

  ...
}
```

此函数的完整实现可以在 GitHub 存储库中找到（[`github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go/blob/master/ch5/insert/main.go`](https://github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go/blob/master/ch5/findAll/main.go)）。

1.  创建部署包，并使用以下命令更新`InsertMovie` Lambda 函数代码：

```go
aws lambda update-function-code --function-name InsertMovie \
 --zip-file fileb://./deployment.zip \
 --region us-east-1
```

1.  允许该函数在电影表上调用`PutItem`操作，并使用以下 IAM 策略：

```go
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "1",
      "Effect": "Allow",
      "Action": "dynamodb:PutItem",
      "Resource": "arn:aws:dynamodb:us-east-1:ACCOUNT_ID:table/movies"
    }
  ]
}
```

以下截图显示 IAM 角色已更新以处理`PutItem`操作的权限：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/342056fe-729b-4b4f-9115-b6ac94d5c117.png)

1.  创建一个新的环境变量，DynamoDB 表名如下：

```go
aws lambda update-function-configuration --function-name InsertMovie \
 --environment Variables={TABLE_NAME=movies} \
 --region us-east-1
```

1.  确保 Lambda 函数配置如下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/6605624f-7263-42fd-a746-d0280410f375.png)

正确配置的 InsertMovie 函数

1.  通过在 API Gateway URL 上调用以下 cURL 命令插入新电影：

```go
curl -sX POST -d '{"id":"17", "name":"The Punisher"}' https://51cxzthvma.execute-api.us-east-1.amazonaws.com/staging/movies | jq '.'
```

1.  验证电影是否已插入 DynamoDB 控制台，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/b7eea63f-4d13-4f9b-bdad-0b0f642b0db7.png)

验证插入是否成功执行的另一种方法是使用 cURL 命令使用`findAll`端点：

```go
curl -sX GET https://51cxzthvma.execute-api.us-east-1.amazonaws.com/staging/movies | jq '.'
```

1.  具有 ID 为`17`的电影已创建。如果表中包含具有相同 ID 的电影项目，则会被替换。以下是输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/d1e275f0-c10e-44ae-a39f-b14a9ea600ae.png)

# DeleteItem 请求

最后，为了从 DynamoDB 中删除项目，应实现以下 Lambda 函数：

1.  注册一个新的处理程序来删除电影。处理程序将请求体中的有效负载编码为`Movie`结构：

```go
var movie Movie
err := json.Unmarshal([]byte(request.Body), &movie)
if err != nil {
   return events.APIGatewayProxyResponse{
      StatusCode: 400,
      Body: "Invalid payload",
   }, nil
}
```

1.  然后，调用`DeleteItem`方法，并将电影 ID 作为参数从表中删除：

```go
cfg, err := external.LoadDefaultAWSConfig()
if err != nil {
  return events.APIGatewayProxyResponse{
    StatusCode: http.StatusInternalServerError,
    Body: "Error while retrieving AWS credentials",
  }, nil
}

svc := dynamodb.New(cfg)
req := svc.DeleteItemRequest(&dynamodb.DeleteItemInput{
  TableName: aws.String(os.Getenv("TABLE_NAME")),
  Key: map[string]dynamodb.AttributeValue{
    "ID": dynamodb.AttributeValue{
      S: aws.String(movie.ID),
    },
  },
})
_, err = req.Send()
if err != nil {
  return events.APIGatewayProxyResponse{
    StatusCode: http.StatusInternalServerError,
    Body: "Error while deleting movie from DynamoDB",
  }, nil
}
```

此函数的完整实现可以在 GitHub 存储库中找到（[`github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go/blob/master/ch5/delete/main.go`](https://github.com/PacktPublishing/Hands-On-Serverless-Applications-with-Go/blob/master/ch5/findAll/main.go)）。

1.  与其他函数一样，创建一个名为`DeleteMovieRole`的新 IAM 角色，该角色具有将日志推送到 CloudWatch 并在电影表上调用`DeleteItem`操作的权限，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/b12c59b9-b5c5-425a-a3d3-7216bbcfb7a4.png)

1.  接下来，在构建部署包后创建一个新的 Lambda 函数：

```go
aws lambda create-function --function-name DeleteMovie \
 --zip-file fileb://./deployment.zip \
 --runtime go1.x --handler main \
 --role arn:aws:iam::ACCOUNT_ID:role/DeleteMovieRole \
 --environment Variables={TABLE_NAME=movies} \
 --region us-east-1
```

1.  返回 Lambda 控制台。应该已创建一个`DeleteMovie`函数，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/7b7ca496-3ee9-4be8-8099-47156c0478fe.png)

1.  最后，我们需要在 API Gateway 的`/movies`端点上公开一个`DELETE`方法。为此，我们不会使用 API Gateway 控制台，而是使用 AWS CLI，以便您熟悉它。

1.  要在`movies`资源上创建一个`DELETE`方法，我们将使用以下命令：

```go
aws apigateway put-method --rest-api-id API_ID \
 --resource-id RESOURCE_ID \
 --http-method DELETE \
 --authorization-type "NONE" \
 --region us-east-1 
```

1.  但是，我们需要提供 API ID 以及资源 ID。这些 ID 可以在 API Gateway 控制台中轻松找到，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/939137cb-caec-46a0-8461-1dd68979dd39.png)

对于像我这样的 CLI 爱好者，您也可以通过运行以下命令来获取这些信息：

+   +   REST API ID：

```go
aws apigateway get-rest-apis --query "items[?name==\`MoviesAPI\`].id" --output text
```

+   +   资源 ID：

```go
aws apigateway get-resources --rest-api-id API_ID --query "items[?path==\`/movies\`].id" --output text
```

1.  现在已经定义了 ID，更新`aws apigateway put-method`命令，使用你的 ID 并执行该命令。

1.  接下来，将`DeleteMovie`函数设置为`DELETE`方法的目标：

```go
aws apigateway put-integration \
 --rest-api-id API_ID \
 --resource-id RESOURCE_ID \
 --http-method DELETE \
 --type AWS_PROXY \
 --integration-http-method DELETE \
 --uri arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:ACCOUNT_ID:function:DeleteMovie/invocations \
 --region us-east-1
```

1.  最后，告诉 API Gateway 跳过任何翻译，并在 Lambda 函数返回的响应中不做任何修改：

```go
aws apigateway put-method-response \
 --rest-api-id API_ID \
 --resource-id RESOURCE_ID \
 --http-method DELETE \
 --status-code 200 \
 --response-models '{"application/json": "Empty"}' \
 --region us-east-1
```

1.  在资源面板中，应该定义一个`DELETE`方法，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/28a1ef22-904e-4f87-aabf-053d9ef08d44.png)

1.  使用以下 AWS CLI 命令重新部署 API：

```go
aws apigateway create-deployment \
 --rest-api-id API_ID \
 --stage-name staging \
 --region us-east-1
```

1.  使用以下 cURL 命令删除电影：

```go
curl -sX DELETE -d '{"id":"1", "name":"Captain America"}' https://51cxzthvma.execute-api.us-east-1.amazonaws.com/staging/movies | jq '.'
```

1.  通过调用`findAll`端点的以下 cURL 命令来验证电影是否已被删除：

```go
curl -sX GET https://51cxzthvma.execute-api.us-east-1.amazonaws.com/staging/movies | jq '.'
```

1.  ID 为 1 的电影不会出现在返回的列表中。您可以在 DynamoDB 控制台中验证电影已成功删除，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-svls-app-go/img/3bea6331-a823-476e-a529-21f264eefb6e.png)

确实，ID 为 1 的电影不再存在于`movies`表中。

到目前为止，我们已经使用 AWS Lambda，API Gateway 和 DynamoDB 创建了一个无服务器 RESTful API。

# 摘要

在本章中，您学会了如何使用 Lambda 和 API Gateway 构建事件驱动的 API，以及如何在 DynamoDB 中存储数据。在后面的章节中，我们将进一步添加 API Gateway 顶部的安全层，构建 CI/CD 管道以自动化部署，等等。

在下一章中，我们将介绍一些高级的 AWS CLI 命令和选项，您可以在构建 AWS Lambda 中的无服务器函数时使用这些选项来节省时间。我们还将看到如何创建和维护多个版本和发布 Lambda 函数。

# 问题

1.  实现一个`update`处理程序来更新现有的电影项目。

1.  在 API Gateway 中创建一个新的 PUT 方法来触发`update` Lambda 函数。

1.  实现一个单一的 Lambda 函数来处理所有类型的事件（GET，POST，DELETE，PUT）。

1.  更新`findOne`处理程序以返回有效请求的正确响应代码，但是空数据（例如，请求的 ID 没有电影）。

1.  在`findAll`端点上使用`Range`头和`Query`字符串实现分页系统。
