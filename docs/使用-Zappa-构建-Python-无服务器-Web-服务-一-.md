# 使用 Zappa 构建 Python 无服务器 Web 服务（一）

> 原文：[`zh.annas-archive.org/md5/3c97e70c885487f68835a4d0838eee09`](https://zh.annas-archive.org/md5/3c97e70c885487f68835a4d0838eee09)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书基于以现代方式开发基于 Python 的无服务器 Web 或微服务的方式。无服务器涉及云服务提供商提供的无服务器基础设施。本书展示了如何使用亚马逊网络服务来实现无服务器基础设施。此外，它还涵盖了使用 Zappa 的部署过程。Zappa 消除了手动干预，为您提供了自动化的部署方式，并帮助您维护多个部署阶段。

# 本书适合谁

本书适用于初学者到有经验的 Python 开发人员，他们想要了解在无服务器基础设施上开发 Python Web 服务或微服务的方式。有经验的 Python 开发人员可以通过学习无服务器技术和了解无服务器部署来提升他们的技能。

# 本书涵盖的内容

第一章，*用于无服务器的亚马逊网络服务*，涵盖了理解 AWS Lambda 和 API Gateway 服务的基础知识。还介绍了通过与 AWS 控制台和 CLI 工具交互创建无服务器服务的手动过程。

第二章，*开始使用 Zappa*，解释了 Zappa 工具的概念，并详细说明了使用 Zappa 相对于 AWS 服务的手动过程的好处。

第三章，*使用 Zappa 构建 Flask 应用程序*，探讨了基本的 Flask 应用程序开发，并使用 Zappa 作为无服务器应用程序进行部署。

第四章，*使用 Zappa 构建基于 Flask 的 REST API*，介绍了基于 Flask 的 RESTful API 开发和使用 Zappa 的部署过程。

第五章，*使用 Zappa 构建 Django 应用程序*，讨论了 Django 核心应用程序开发，并使用 Zappa 将应用程序部署为 AWS Lambda 上的无服务器应用程序。

第六章，*使用 Zappa 构建 Django REST API*，专注于使用 Django REST 框架实现 RESTful API 以及使用 Zappa 的部署过程。

第七章，*使用 Zappa 构建 Falcon 应用程序*，带您了解使用 Falcon 框架开发 RESTful API 作为微服务的过程，以及使用 Zappa 的部署过程。

第八章，*使用 SSL 的自定义域*，解释了如何使用 Zappa 配置自定义域，并涵盖了使用 AWS 生成 SSL。

第九章，*在 AWS Lambda 上执行异步任务*，展示了使用 Zappa 执行耗时任务的异步操作的实现。

第十章，*高级 Zappa 设置*，让您熟悉 Zappa 工具的附加设置，以增强应用部署过程。

第十一章，*使用 Zappa 保护无服务器应用程序*，概述了使用 Zappa 在 AWS Lambda 上保护无服务器应用程序的安全方面。

第十二章，*使用 Docker 的 Zappa*，介绍了在 AWS Lambda 上下文环境中使用 Docker 容器化进行应用程序开发。

# 充分利用本书

在开始之前，读者需要一些先决条件。读者应具备以下条件：

+   对虚拟环境有很好的理解

+   理解 Python 包安装

+   了解使用 Apache 或 NGINX 进行传统部署的知识

+   对 Web 服务或微服务的基本了解

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的账户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，文件将直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的以下工具解压或提取文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Zipeg/iZip/UnRarX 适用于 Mac

+   7-Zip/PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Building-Serverless-Python-Web-Services-with-Zappa`](https://github.com/PacktPublishing/Building-Serverless-Python-Web-Services-with-Zappa)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自丰富书籍和视频目录的其他代码包可供下载，网址为**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**。快去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/BuildingServerlessPythonWebServiceswithZappa_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/BuildingServerlessPythonWebServiceswithZappa_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“Zappa 部署需要生成`zappa_settings.json`文件，该文件生成`zappa init`命令。”

代码块设置如下：

```py
client = boto3.client('lambda')
response = client.invoke(
    FunctionName='MyFunction',
    InvocationType='Event'
)
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```py
$ curl https://quote-api.abdulwahid.info/daily
{"quote": "May the Force be with you.", "author": "Star Wars", "category": "Movies"}
```

任何命令行输入或输出都以以下方式编写：

```py
$ pip install awscli
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单中的单词或对话框中的单词会在文本中以这种方式出现。这是一个例子：“单击“创建函数”按钮。”

警告或重要说明会出现在这样的地方。

提示和技巧会出现在这样的地方。


# 第一章：用于无服务器的亚马逊网络服务

在本章中，我们将学习关于亚马逊网络服务管理无服务器基础架构。我们将探索 AWS 工作流程以创建无服务器应用程序。我们将学习手动创建基本无服务器应用程序的过程，以及使用 AWS CLI 进行自动化处理的过程。

本章我们将涵盖的主题包括：

+   从传统服务器过渡到无服务器

+   开始使用 AWS Lambda

+   AWS Lambda 的工作原理

+   执行 Lambda 函数

+   创建 Lambda 触发器

+   创建无服务器 RESTful API

+   通过 AWS CLI 与 AWS Lambda 进行交互

# 技术要求

在继续之前，有一些技术先决条件。我们将通过 Web 控制台和 AWS CLI 演示 AWS。应考虑以下先决条件：

+   所有演示都在 Ubuntu 16.04 的 Linux 机器上进行了测试。我们已经分享了本书中使用的每个库的链接。您可以获取有关特定平台的安装和配置的详细信息。

+   我们使用开源库和软件。因此，对于每个库，我们将分享其官方文档链接。您可以参考这些链接以获取有关特定库的详细信息。

# 从传统服务器过渡到无服务器

自从 Web 托管开始以来，Web 托管发生了巨大变化。物理服务器机器被多个 Web 应用程序共享，当需要扩展时，这是一个真正的挑战。对于任何个人或公司来说，购买整个服务器机器来托管其 Web 应用程序都非常昂贵。

但是，由于虚拟化，任何 Web 应用程序都不需要物理服务器。虚拟化提供了创建许多虚拟服务器的能力，而不是单个物理服务器。

现在，无服务器的新时代使开发人员的生活变得更加轻松，因为我们可以将辛勤工作集中在开发上，而不是花时间和金钱在部署上。

亚马逊推出了亚马逊弹性计算云（Amazon EC2）作为云计算解决方案。亚马逊 EC2 使得在亚马逊云中创建一系列虚拟服务器或实例成为可能，而无需投资于硬件。您可以根据网络、计算和存储的需求进行扩展。

无服务器方法只是消除设置托管环境的手动工作量的过程。云服务提供商提供无服务器服务，因此您实际上从未拥有任何服务器。相反，云服务提供商在高可用性基础设施中执行您的代码。

# 开始使用 AWS Lambda

许多云服务提供商为无服务器基础架构引入了不同的服务。亚马逊推出了 AWS Lambda 作为计算服务，您只需提供代码，AWS Lambda 就会在高度可扩展的基础设施中执行代码。您无需担心手动管理服务。您需要支付代码执行的计算时间，当您的代码未运行时则不收费。

AWS Lambda 根据需要执行代码，以响应诸如 S3 存储桶上的数据存储事件、Amazon DynamoDB 事件和通过 API Gateway 的 HTTP 请求事件等事件。AWS Lambda 能够根据 AWS CloudWatch Events 的计划时间事件执行代码。AWS Lambda 支持 Python、Node.js、C#和 Java。

亚马逊简单存储服务（S3）是亚马逊提供的存储服务。它具有一个简单的 Web 界面来存储数据。亚马逊 S3 具有可供其他服务使用的相关服务事件。

# AWS Lambda 的工作原理

您需要编写一个函数，该函数将由 AWS Lambda 代表您执行。

AWS Lambda 是基于容器的模型实现的，支持运行时环境，并根据 Lambda 函数的配置执行代码。当调用 Lambda 函数时，它会根据 AWS Lambda 配置启动容器（执行环境），并启用基本的运行时环境，这是执行代码所需的。

让我们从一些实际工作开始：

1.  要创建一个 Lambda 函数，您必须拥有 AWS 账户。如果您没有 AWS 账户，那么您需要在 AWS 上注册（[`aws.amazon.com/`](https://aws.amazon.com/)），提供一些基本的联系和付款信息，因为这是亚马逊所需的基本信息。

1.  转到 Lambda 主页（[`console.aws.amazon.com/lambda/home`](https://console.aws.amazon.com/lambda/home)）。单击“创建函数”按钮。这将重定向您到**创建函数**页面，下一步将描述该页面。请查看以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00005.jpeg)

1.  AWS 提供了三种不同的选项来创建 Lambda 函数，比如从头开始创建、蓝图和无服务器应用程序存储库。我们将使用蓝图选项，其中包含一些内置的 Lambda 函数。我们可以根据搜索栏中的要求选择这些蓝图，您可以通过标签和属性进行过滤，或者通过关键字搜索：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00006.jpeg)

1.  让我们选择一个 hello-world-python 蓝图。一旦我们选择了蓝图，我们需要设置关于 Lambda 函数的基本信息。这些信息包括 Lambda 函数的名称和角色，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00007.jpeg)

1.  在这里，名称将是您的 Lambda 函数的唯一标识，而角色定义了您的 Lambda 函数的权限。

有三种选项可用于创建角色：

+   选择现有角色

+   从模板创建新角色

+   创建自定义角色

让我们更详细地看一下它们：

+   **选择现有角色**：这允许您选择先前创建的角色。

+   **从模板创建新角色**：在这里，您需要定义一个角色名称。AWS Lambda 提供了预先配置的内置角色策略模板，具有预配置的权限。这些权限基于 AWS Lambda 函数所需的其他 AWS 服务相关权限。在任何角色选择上，Lambda 将自动将日志记录权限添加到 CloudWatch（AWS 日志记录服务），因为这是 Lambda 所需的基本权限。

+   **创建自定义角色**：AWS 提供了额外的权限来创建一个定制的角色来访问 AWS Lambda。在这里，您可以根据自己的需求定义角色。

1.  让我们创建一个带有某些角色的`HelloWorld` Lambda 函数。在这里，我选择了 S3 对象只读权限策略模板。

1.  以下屏幕截图描述了新创建的`HelloWorld` Lambda 函数：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00008.jpeg)

HelloWorld Lambda 函数

Lambda 函数包括三个部分：

+   配置

+   触发器

+   监控

让我们来看一下关于配置和监控的详细信息。我们将为触发器设置一个单独的部分。

# 配置

Lambda 执行取决于配置设置。配置 Lambda 函数需要以下详细信息：

+   函数代码

+   环境变量

+   标签

+   执行角色

+   基本设置

+   网络

+   调试和错误处理

# 函数代码

在这里，您需要编写代码。Lambda 函数有一个预定义的编写代码的模式。在编写代码时，您需要理解上下文。Lambda 提供了三种可行性，这决定了代码的运行时执行：

+   **代码输入类型**：此部分提供了三种选项来决定代码的输入类型，比如内联编辑代码、上传 ZIP 文件和从 Amazon S3 上传文件。

+   **运行时**：此部分提供了选项来决定代码的运行时编程语言上下文，比如 Python、C#、NodeJS 和 Java。

+   处理程序：处理程序定义了您的方法/函数的路径，例如`<filename>.<method_name>`。例如，如果您想要执行一个名为`handler`的函数，该函数在`main.py`中定义，那么它将是`main.handler`。

让我们回到我们新创建的名为`lambda_handler`的 hello world 函数。

在这里，处理程序的值被定义为`lambda_function.lambda_handler`，其中`lambda_function.py`是文件名，`lambda_handler`是方法名：

```py
def lambda_handler(event, context): 
    print("value1 = " + event['key1']) 
    print("value2 = " + event['key2']) 
```

`Lambda_handler`接受两个位置参数，`event`和`context`：

+   `event`：此参数包含与事件相关的信息。例如，如果我们配置 Lambda 函数与 Amazon S3 存储桶事件，那么我们将在事件参数中获得 S3 存储桶信息，例如存储桶名称，区域等。

+   `context`：此参数包含可能在运行时需要的与上下文相关的信息，以供代码执行。

# 环境变量

您可以以键值对的形式设置环境变量，这些变量可以在您的代码中使用。

# 标签

您可以使用标签对 Lambda 函数进行分组和过滤。您可能有多个具有不同区域的 Lambda 函数，因此标签有助于使 Lambda 函数更易管理。

# 执行角色

正如我们之前讨论的，在创建 Lambda 函数时角色和权限，Lambda 提供了编辑您在创建 Lambda 函数时选择的现有角色的能力。

# 基本设置

在基本设置下，您可以配置内存和执行超时。Lambda 支持的内存范围从 128 MB 到 1,536 MB。超时执行以秒为单位；Lambda 支持的默认超时执行时间为 300 秒。此设置可帮助您控制 Lambda 函数的代码执行性能和成本。

# 网络

在网络部分，您可以配置对 Lambda 函数的网络访问。

AWS 提供了**VPC**（虚拟私有云）服务，用于创建允许访问 AWS 服务的虚拟网络。您还可以根据自己的需求配置网络。

我们将在接下来的章节中讨论带有 VPC 的 Lambda 函数。目前，我们将在网络部分选择无 VPC。

# 调试和错误处理

AWS Lambda 会自动重试失败的异步调用。但是您也可以配置**DLQ**（死信队列），例如 SQS 队列或 SNS 主题。要配置 DLQ，Lambda 函数必须具有访问 DLQ 资源的权限。

既然我们了解了配置，让我们继续执行 Lambda 函数。

让我们看一下*监控*部分，它描述了与我们的 Lambda 函数相关的活动。它可以用于分析我们的 Lambda 函数执行的性能。

# 监控

AWS CloudWatch 是 AWS 资源的监控服务，并管理所有活动日志。它创建指标数据以生成统计数据。CloudWatch 实现了对 AWS 资源的实时监控。它还监视与 AWS EC2 或 RDS 数据库实例以及其他资源相关的硬件信息。

Lambda 监控部分显示与 Lambda 函数活动和性能相关的最近 24 小时的分析数据。以下屏幕截图显示了我们的 hello world Lambda 函数的监控分析信息：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00009.jpeg)

让我们继续下一节，我们将看一下 Lambda 函数的执行。

# 执行 Lambda 函数

AWS Lambda 支持多种执行方法。让我们从其自己的 Web 控制台界面开始基本执行。AWS Lambda 提供了手动测试函数的能力，您可以在其中定义测试事件上下文。如果您想针对其他 Amazon 服务进行测试，则有内置的事件模板可用。

以下屏幕截图演示了测试事件的创建：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00010.jpeg)

如前面的屏幕截图所示，单个 Lambda 函数最多可以有 10 个测试事件，并且测试事件是持久的，因此您可以在需要测试 Lambda 函数时重复使用它们。

我使用事件名称`HelloWorld`创建了测试事件，现在我将执行`HelloWorld`函数，将 Lambda 函数转换为 Python 微服务，如下所示：

```py
from __future__ import print_function 
import json 

print('Loading function') 

def lambda_handler(event, context): 
    print("Received event: " + json.dumps(event, indent=2)) 
    print("value1 = " + event['key1']) 
    print("value2 = " + event['key2']) 
    print("value3 = " + event['key3']) 
    return "Hello World" 
```

在这里，我们打印事件数据，然后返回到`Hello World`字符串：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00011.jpeg)

Lambda 在每个请求执行上管理一些信息，例如请求 ID 和计费信息。Lambda 价格模型是基于请求处理的时间消耗，而请求 ID 是每个请求的唯一标识。

在日志输出中，您可以看到所有的打印语句输出。现在，让我们引发一个错误，看看 Lambda 如何响应并返回日志。

我们将用以下片段替换当前代码：

```py
from __future__ import print_function 
import json 

print('Loading function') 

def lambda_handler(event, context): 
    print("Received event: " + json.dumps(event, indent=2)) 
    raise Exception('Exception raised manually.') 
```

以下屏幕截图是执行结果的日志片段：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00012.jpeg)

在这里，Lambda 以完整的堆栈跟踪信息做出了响应，并将其记录下来。您可以检查 CloudWatch 日志，因为 CloudWatch 已预先配置了 AWS Lambda 执行。

我们从 Lambda 控制台了解了 Lambda 函数的执行，现在是时候从计划触发器执行 Lambda 函数了。在我们的项目中，我们经常需要有一个 cron 作业计划，在特定时间段执行一些功能。

Lambda 触发器将帮助我们根据事件设置触发器。让我们继续介绍如何向我们的 hello world 函数引入触发器。

# 创建 Lambda 触发器

Lambda 函数可以根据事件进行配置。AWS 提供了支持许多事件的触发器列表。这些触发器属于它们关联的 AWS 服务。

您可以从触发器部分向 Lambda 函数添加触发器。

我将稍微修改 hello world Lambda 函数。在这里，我们打印请求 ID，该 ID 作为`aws_request_id`属性在上下文对象中接收。它还打印时间戳：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00013.jpeg)

现在，我们将向我们的 Lambda 函数添加一个触发器，该触发器将每分钟执行我们的 Lambda 函数。

以下屏幕截图显示了“添加触发器”流程，在这里您可以轻松地从左侧面板配置任何触发器与您的 Lambda 函数：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00014.jpeg)

我们将配置 CloudWatch Events 触发器。CloudWatch Events 提供描述 AWS 资源更改的几乎实时系统事件。

您可以设置简单的事件规则，以在发生 AWS 资源的操作事件时进行操作，并且还可以安排自动事件，根据 cron 或速率表达式自触发。

cron 和速率表达式是定义计划表达式的两种不同方法。cron 表达式有六个必填字段，如 cron（字段），而速率表达式有两个必填字段，如速率（值单位）。这些方法帮助我们定义计划表达式。您可以在[`docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html`](http://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html)找到详细信息。

在这里，我们将安排一个速率表达式，以便每分钟执行我们的 hello world Lambda 函数。我们需要从触发器下拉菜单中选择 CloudWatch Events。

为了创建 CloudWatch 事件规则，我们将创建一个新规则。我们需要使用一些必需的信息设置规则，例如规则名称，这是一个唯一标识符。因此，我们将规则命名为`hello-world-every-minute`，规则类型为事件模式或计划表达式。在我们的情况下，它将是一个计划表达式，速率（1 分钟），如前面的屏幕截图所示。

一旦我们设置了触发器并启用它，按照计划表达式，计划事件将被触发。让我们在五分钟后查看我们的 hello world Lambda 日志。

要查看与任何服务相关的日志，您需要执行以下操作：

1.  在[`console.aws.amazon.com/cloudwatch/`](https://console.aws.amazon.com/cloudwatch/)上打开 CloudWatch 控制台

1.  在导航窗格中，选择日志

1.  选择与`HelloWorld` Lambda 函数相关的日志组

以下屏幕截图描述了 CloudWatch 日志访问：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00015.jpeg)

通过选择`HelloWorld` Lambda 函数日志组，您可以看到与我们的`HelloWorld` Lambda 函数相关的日志活动。以下屏幕截图显示了`HelloWorld`函数的日志：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00016.jpeg)

在这里，您可以看到我们的 hello world Lambda 函数自从我们启用了触发器以来每分钟执行一次。

现在，让我们继续创建一个无服务器的 RESTful API。

# 无服务器 RESTful API

让我们了解微服务场景，我们将部署一个无服务器的 hello world 函数，通过 API Gateway 响应 HTTP 事件。

Amazon API Gateway 服务使您能够创建、管理和发布与任何规模的 AWS 资源交互的 RESTful API。API Gateway 提供了一个接口，通过该接口您可以通过 REST 应用程序编程接口公开后端。

为了启用 AWS 无服务器基础设施，API Gateway 发挥着重要作用，因为它可以配置为执行 Lambda 函数。

现在，我们将配置一个 API Gateway 服务来执行 Lambda 函数

这是 hello world 函数：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00017.jpeg)

当我们将 AWS Lambda 函数与 API Gateway 集成时，Lambda 函数必须返回一个带有所需键的字典对象，如`statusCode`、`headers`和`body`。`body`属性的值必须是 JSON 字符串。因此，我们将 Python 字典转换为 JSON 字符串。

现在是时候将 API Gateway 与 Lambda 函数集成了。正如我们在之前关于触发器的讨论中所看到的，我们将使用 API Gateway 添加一个触发器：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00018.jpeg)

我们将创建一个名为`LambdaMicroservice`的 API Gateway 服务。API Gateway 使您能够根据需要创建和维护部署阶段。

如果您想保护您的 API，那么您有两个选项——使用 AWS IAM 并使用访问密钥打开它，或者保持它开放，使其公开可用。

AWS **IAM**（身份访问管理）是 AWS 云服务，有助于创建安全访问凭据以访问 AWS 云服务。

使用访问密钥功能允许您从 API Gateway 控制台生成密钥。在我们的情况下，我们只会保持安全性开放，因为我们需要公开访问我们的 API：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00019.jpeg)

一旦添加并保存更改，REST API 将在几秒钟内准备就绪。调用 URL 就是我们的 REST API 端点。

让我们使用`curl`命令行工具访问调用 URL 并查看发生了什么：

```py
$ curl https://cfi6872cxa.execute-api.us-east-2.amazonaws.com/prod/HelloWorld
{"message": "Hello World returned in JSON"}
```

就是这样。我们已经使用 AWS Lambda 和 API Gateway 创建了一个无服务器的 RESTful API。现在，我们将看看如何使用 AWS CLI 与 AWS 服务进行交互。

# AWS Lambda 与 AWS CLI 的交互

AWS CLI 是在 AWS SDK for Python 的基础上开发的开源工具，使用 Boto 库提供与 AWS 服务交互的命令。通过非常少的配置，您可以从 CLI 管理任何 AWS 服务。它提供对 AWS 服务的直接访问，您可以开发 shell 脚本来管理您的资源。

例如，如果您想将文件上传到 S3 存储桶，那么您只需通过 CLI 执行一个命令即可完成：

```py
$ aws s3 cp index.html s3://bucket-name/ 
```

`aws s3 cp`是一个类似 shell 的命令，执行多部分文件上传操作以完成操作。

它还支持对一些 AWS 服务进行定制。您可以使用`--help`命令查看`aws-cli`支持的 AWS 服务列表。

# 安装 AWS CLI

`awscli`可用作 Python 分发包。您可以使用`pip`命令轻松安装它，如下面的代码所述：

```py
$ pip install awscli --upgrade  
```

以下是先决条件：

+   Python 2 的版本为 2.6.5+或 Python 3 的版本为 3.3+

+   Unix、Linux、macOS 或 Windows

# 配置 AWS CLI

`awscli`直接访问 AWS 服务，但我们需要配置和验证它以访问 AWS 服务。

运行`aws configure`命令以配置 AWS CLI 与您的 Amazon 帐户：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00020.jpeg)

您可以从“My Security Credentials”选项中获取 AWS 访问密钥 ID 和 AWS 秘密访问密钥，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00021.jpeg)

让我们使用 AWS CLI 配置 AWS Lambda 函数。

# 使用 AWS CLI 配置 Lambda 函数

让我们使用`awscli 实用程序`命令配置我们的 hello world Lambda 函数和触发器。

AWS CLI 支持所有可用的 AWS 服务。您可以使用`aws help`查看`aws`命令的详细描述，并列出所有可用的服务。

我们对 Lambda 感兴趣，因为我们将创建一个具有简单 hello world 上下文的 Lambda 函数：

```py
$ aws lambda help  
```

这将列出 Lambda 服务的完整描述以及管理 AWS Lambda 服务所需的所有可用命令。

# 创建 Lambda 函数

在这里，我们将使用`aws lambda create-function`命令创建一个新的 Lambda 函数。要运行此命令，我们需要传递必需和可选参数。

确保您具有具有`lambda:CreateFunction`操作权限的角色。

以前，在 AWS Lambda 控制台中，我们选择了内联编辑作为代码入口点。现在，我们将使用 ZIP 文件作为部署包。

在创建 Lambda 函数之前，我们应该创建一个 Lambda 函数部署包。

此部署包将是一个 ZIP 文件，其中包含您的代码和任何依赖项。

如果您的项目有一些依赖关系，则必须在项目的根目录中安装依赖关系。例如：

```py
 $ pip install requests -t <project-dir> OR  
 $ pip install -r requirements.txt  -t <project-dir> 
```

这里，`-t`选项表示目标目录。

在名为`handler.py`的文件中创建一个简单的`lambda_handler`函数，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00022.jpeg)

现在，让我们制作一个 ZIP 文件作为部署包，其中包含前面的代码：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00023.jpeg)

现在，我们准备创建 Lambda 函数。以下截图描述了命令执行：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00024.jpeg)

您可以看到，在 AWS Lambda 控制台中，Lambda 函数立即被创建：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00025.jpeg)

让我们讨论我们在`aws lambda create-function`命令中使用的必需和可选参数：

+   `--function-name`（必需）：名称不言自明。我们需要传递要创建的 Lambda 函数的名称。

+   `--role`（必需）：这是一个必需的参数，我们需要将 AWS 角色 ARN 用作值。确保此角色具有创建 Lambda 函数的权限。

+   `--runtime`（必需）：我们需要提到 Lambda 函数执行的运行时环境。正如我们之前提到的，AWS Lambda 支持 Python、Node.js、C#和 Java。因此，这些是可能的值：

+   `python2.7`

+   `python3.6`

+   `nodejs`

+   `nodejs4.3`

+   `nodejs6.10`

+   `nodejs4.3-edge`

+   `dotnetcore1.0`

+   `java8`

+   `--handler`（必需）：在这里，我们提到将作为 AWS Lambda 执行入口点的函数路径。在我们的情况下，我们使用了`handler.lambda_function`，其中处理程序是包含`lambda_function`的文件。

+   `--description`：此选项允许您添加有关 Lambda 函数的一些文本描述。

+   `--zip-file`：此选项用于从本地环境/计算机上传代码的部署包文件。在这里，您需要在 ZIP 文件路径前添加`fileb://`作为前缀。

+   `--code`：此选项可帮助您从 AWS S3 存储桶上传部署包文件。

您应该传递一个带有模式的字符串值，例如这里所示的一个：

```py
 "S3Bucket=<bucket-name>,S3Key=<file-name>,S3ObjectVersion=<file-version-id>". 
```

还有许多其他可选参数，您可以通过`help`命令查看，例如`aws lambda create-function help`*.* 您可以根据自己的需求使用它们。

现在我们将看到使用命令`$ aws lambda invoke`调用 Lambda 函数。

# 调用函数

Lambda CLI 提供了一个命令来直接调用 Lambda 函数：

```py
$ aws lambda invoke --function-name <value> <outfile> 
```

让我们来看看这些参数：

+   `--function-name`（必需）：此参数要求输入 Lambda 函数名称

+   `outfile`（必需）：在这里，您需要提到一个文件名，返回的输出或 Lambda 函数的响应将被存储在那里

这里还有其他可选参数，您可以通过`help`命令列出。

让我们调用我们最近创建的`HelloWorldCLI`函数：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00026.jpeg)

当我们调用 Lambda 函数时，它立即以状态代码做出响应，并且 Lambda 函数返回的输出数据存储在新创建的`lambda_output.txt`文件中，通过`lambda invoke`命令。

# 创建事件源映射

这是`aws lambda`命令的一个子命令，用于为您的 Lambda 函数创建事件映射。`$ aws lambda create-event-source-mapping`仅支持 Amazon Kinesis 流和 Amazon DynamoDB 流事件映射。我们将在即将到来的章节中讨论使用 Zappa 进行 Amazon API Gateway 和 CloudWatch 事件的事件映射。

# 总结

在本章中，我们学习了创建简单的 AWS Lambda 的手动过程，并配置了一些触发器。此外，我们还使用 AWS CLI 查看了 AWS Lambda 的配置。实现无服务器应用程序真是令人惊讶。这些 AWS 服务在创建无服务器基础架构中扮演着重要的角色，您可以在其中开发应用程序并将其部署为无服务器。

# 问题

1.  无服务器的好处是什么？

1.  Amazon S3 在无服务器基础架构中的作用是什么？


# 第二章：使用 Zappa 入门

之前，我们学习了如何使用 AWS Web 控制台和 AWS CLI 创建无服务器应用程序。现在，我们将学习 Zappa 和自动化操作，以创建无服务器应用程序。

在本章中，我们将涵盖以下主题：

+   什么是 Zappa？

+   安装和配置 Zappa

+   使用 Zappa 构建、测试和部署 Python Web 服务

+   Zappa 的用途

# 技术要求

在继续之前，让我们确保满足技术要求。接下来的小节将介绍本章的硬件和软件要求。

# 硬件

为了演示目的，我们使用了一个基本配置的机器，具体规格如下：

+   内存—16GB

+   处理器—Intel Core i5

+   CPU—2.30GHz x 4

+   图形—Intel HD Graphics 520

# 软件

以下是软件规格：

+   OS—Ubuntu 16.04 LTS

+   OS 类型—64 位

+   Python 3.6

+   Python 开发包：`build-essential`、`python-dev`和`python-virtualenv`

+   AWS 凭据和 AWS CLI

+   Zappa

我们将在接下来的章节中详细描述设置环境的过程。与此同时，你可以配置诸如`python3.6`和`awscli`等必要的软件包。

# 什么是 Zappa？

Zappa 是一个开源工具，由 Gun.io 的创始人/CTO Rich Jones 开发和设计（[`www.gun.io/`](https://www.gun.io/)）。Zappa 主要设计用于在 AWS Lambda 和 API Gateway 上构建和部署无服务器 Python 应用程序。

Zappa 非常适合使用 Flask 和 Bottle 等框架部署无服务器 Python 微服务，用于托管大型 Web 应用程序和 CMSes 的 Django。你也可以部署任何 Python WSGI 应用程序。

在上一章中，我们使用 AWS Lambda 和 API Gateway 实现了基本的 hello world 微服务。Zappa 自动化了所有这些手动流程，并为我们提供了一个方便的工具来构建和部署 Python 应用程序。

就像这样简单：

```py
$ pip install zappa
$ zappa init
$ zappa deploy
```

正如我们之前所描述的，传统的 Web 托管是指服务器需要始终在线，监听 HTTP 请求并逐个处理请求。如果传入的 HTTP 请求队列增长，那么服务器将无法每秒处理那么多请求，就会出现超时错误。

API Gateway 使用虚拟 HTTP 服务器为每个请求提供自动扩展。这就是它可以在不失败的情况下为数百万个请求提供服务的原因。因此，我们可以在当前部署成本的零停机侵害下获得无限扩展。

现在，我们将进行一个应用程序演示，但在此之前，让我们在你的机器上配置 Zappa，我们将在接下来的章节中介绍。

# 安装和配置 Zappa

安装 Zappa 是一项简单的任务，但在继续之前，我们需要配置先决条件。确保你有 Python 2.7 或 Python 3.6，并且有一个有效的 AWS 账户。现在，你需要在你的机器上使用`help awscli`配置 AWS 凭据：

```py
$ pip install awscli
```

使用`aws configure`命令配置 AWS 凭据，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00027.jpeg)

配置 AWS 凭据要求你有 AWS 访问密钥 ID、AWS 秘密访问密钥、默认区域名称和默认输出格式。

你可以从“我的安全凭据”页面获取 AWS 凭据信息，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00028.jpeg)

一旦你配置了 AWS 凭据，我们就可以继续安装 Zappa 了。

Zappa 必须安装在虚拟环境中。强烈建议在安装 Zappa 之前创建一个虚拟环境并激活它。我倾向于使用`virtualenv`工具。还有其他可用于管理虚拟环境的工具：

```py
$ virtualenv env -p python3.6
```

在这里，我们创建了一个名为`env`的虚拟环境，并使用`python3.6`，其中`-p`表示 Python 版本。现在，按照以下步骤激活虚拟环境：

```py
$ source env/source/bin
```

现在我们已经准备好了，让我们使用`pip`安装 Zappa：

```py
$ pip install zappa
```

现在，我们准备启动 Zappa。在接下来的章节中，我们将创建一个小程序，演示如何使 Zappa 的部署变成无服务器。

# 使用 Zappa 构建、测试和部署 Python Web 服务

我们将使用 Python 的 Bottle 框架创建一个简单的 hello world 程序作为微服务。让我们按照一些基本步骤来配置一个使用 Bottle 框架的小项目：

1.  首先，我们将创建一个名为`lambda_bottle_poc`的新项目目录：

```py
$ mkdir lambda_bottle_poc
```

1.  让我们在`lambda_bottle_poc`目录中创建一个虚拟环境：

```py
$ virtualenv env -p python3.6
```

1.  以下是使用 Bottle 框架的基本 hello world 程序：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00029.jpeg)

现在是时候将程序部署为 AWS Lambda 上的无服务器，并通过 API Gateway 公开`/hello` API。在上一章中，我们描述了使用 AWS 控制台和 AWS CLI 手动部署 Python 应用程序的过程，这是一个非常大的挑战。

但借助 Zappa，所有 AWS 控制台和 AWS CLI 的手动流程都被自动化，并提供了一种快速的方式来在无服务器环境中部署和维护您的应用程序。

# 构建部署包

让我们使用`zappa init`命令初始化 Zappa。这个命令可以帮助您创建和部署 Python 应用程序。这个命令以用户交互模式运行，并提出一些基本问题，以便我们可以设置部署过程。

问卷结束时，Zappa 创建了一个名为`zappa_settings.json`的 JSON 文件。这个文件实际上就是 Zappa 的支撑，因为它维护了 Zappa 内部使用的映射信息。

我们将在接下来的几分钟内详细讨论 Zappa 的`init`命令过程。在那之前，先看一下以下截图，描述了`zappa init`命令的流程：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00030.jpeg)

正如您所看到的，`zappa init`启动了用户交互模式，并提出了一些问题。让我们看看每个问题的一些信息。

# 您想如何称呼这个环境？（默认开发）

Amazon API Gateway 提供了一种机制来维护托管 API 的不同环境阶段。例如，您可以为开发、暂存和生产创建环境阶段。

借助 Zappa，您可以非常轻松地管理环境阶段。对于前面的问题，您可以定义自己的环境阶段名称，或者将其留空以考虑默认的阶段名称为`dev`。

# 你想给你的存储桶起什么名字？（默认 zappa-2o2zd8dg4）

Zappa 部署将需要上传到私有的 Amazon S3 存储桶。AWS Lambda 需要两种类型的代码输入，即内联代码和上传 ZIP 文件。如果 ZIP 文件大小超过 10MB，则考虑将 ZIP 文件上传到 Amazon S3。这就是为什么 Zappa 默认创建一个存储桶，用于上传部署 ZIP 文件并引用 AWS Lambda。

您可以提供自己现有的存储桶名称，或者选择由 Zappa 建议的默认名称。如果存储桶不存在，Zappa 将自动为您创建一个。

# 你的应用功能的模块化路径是什么？（默认开发）

AWS Lambda 函数需要一个属性，比如`lambda_handler`，它指向一个函数作为 Lambda 执行的入口点。因此，我们需要提供有关函数名称的信息，以模块化路径的形式，例如`<filename>.<function_name/app_name>`给 Zappa。

在我们的案例中，我们有一个名为`hello.py`的文件，以及使用 Python Bottle 框架的`Bottle`类创建的应用对象。因此，对于这个问题的答案是`hello.app`。

# 您想全球部署应用程序吗？（默认否）

AWS 提供了一个功能，可以将 Lambda 服务扩展到所有可用的区域。如果您希望使您的服务全球可用，并且延迟更少，那就是您应该做的。Zappa 支持这个功能，它将使您能够在所有区域扩展 Lambda 服务，而无需任何手动操作。

最后，您将得到一个`zappa_settings.json`文件，其中包含了与您的部署相关的所有配置。让我们在下一节中查看`zappa_settings.json`文件。

# zappa_settings.json 文件

完成问卷调查后，Zappa 会根据您的输入创建一个基本的`zappa_settings.json`文件。`zappa_settings.json`在配置 Zappa 与您的项目时起着重要作用。如果您在现有项目（`Django/Flask/Pyramid/Bottle`）中初始化 Zappa，那么 Zappa 会自动检测项目类型，并相应地创建`zappa_settings.json`文件。

以下是我们新创建的`zappa_settings.json`文件的内容，用于 hello world 程序：

```py
{
   "dev": {
       "app_function": "hello.app",
       "aws_region": "ap-south-1",
       "profile_name": "default",
       "project_name": "lambda-bottle-p",
       "runtime": "python3.6",
       "s3_bucket": "zappa-2o2zd8dg4"
   }
}
```

对于 Django 项目，它使用`django_settings`而不是`app_function`。`django_settings`需要用您的 Django 设置的路径进行初始化：

```py
{
   "dev": {
       "django_settings": "your_project.settings",
       "aws_region": "ap-south-1",
       "profile_name": "default",
       "project_name": "lambda-bottle-p",
       "runtime": "python3.6",
       "s3_bucket": "zappa-2o2zd8dg4"
   }
}
```

上述配置足以部署一个基本的 Python Web 应用程序。让我们继续部署 hello world 作为无服务器应用程序。

# 部署和测试 hello world

Zappa 部署非常简单，因为您只需要运行一个命令来开始部署：

```py
$ zappa deploy <stage_name>
```

就是这样！我们已经完成了部署。现在，让我们部署 hello world 程序。以下截图描述了部署过程：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00031.jpeg)

部署完成后，我们会得到 API URL 端点。让我们通过访问`/hello`端点的 API URL 来测试 hello world 应用程序：

```py
$ curl -l  https://071h4br4e0.execute-api.ap-south-1.amazonaws.com/dev/hello
```

运行上述命令后，您将看到以下输出：

```py
Hello World!
```

能够在几秒钟内配置服务并部署真是太神奇了。现在，我们将详细了解与`zappa_settings.json`文件相关的基本用法。

# 基本用法

Zappa 涵盖了每一个部署过程。让我们详细讨论一下 Zappa 的部署流程。

# 初始部署

一旦您初始化了 Zappa，您就可以通过单个命令将应用程序部署到`production`阶段，如下面的代码片段所示：

```py
$ zappa deploy production
.
.
.
Deployment complete ! https://071h4br4e0.execute-api.ap-south-1.amazonaws.com/production
```

当您调用`$ zappa deploy`命令时，Zappa 会执行一些任务来完成部署。以下是 Zappa 关于部署的内部流程和过程：

1.  通过将本地环境中的应用程序代码压缩成 ZIP 存档文件，并用预编译的 Lambda 包中的版本替换任何依赖项。

1.  使用所需的 WSGI 中间件设置 Lambda `handler`函数。

1.  将前两个步骤生成的存档上传到 Amazon S3 存储桶。

1.  创建和管理必要的 AWS IAM 策略和角色。

1.  使用上传到 AWS S3 存储桶的 ZIP 存档文件创建 AWS Lambda 函数。

1.  根据 Zappa 配置创建 AWS API Gateway 资源以及不同的阶段。

1.  为 API Gateway 资源创建 WSGI 兼容路由。

1.  将 API Gateway 路由链接到 AWS Lambda 函数。

1.  最后，从 AWS S3 中删除 ZIP 文件。

注意：`lambda-packages`（[`github.com/Miserlou/lambda-packages`](https://github.com/Miserlou/lambda-packages)）是由 Zappa 社区维护的开源存储库。该存储库包含了最基本的 Python 库作为预编译的二进制文件，这些文件将与 AWS Lambda 兼容。

这就是 Zappa 处理部署过程的方式——它会自行完成所有这些任务，并让您通过一个命令来部署您的应用程序。

# 更新

如果您已经部署了应用程序，那么您只需使用以下命令简单地在 AWS Lambda 上更新最新的应用程序代码：

```py
$ zappa update production
.
.
.
Your updated Zappa deployment is live!: https://071h4br4e0.execute-api.ap-south-1.amazonaws.com/production
```

我们可以将其与仅更新一些任务的`zappa deploy`进行比较。它们在这里提到：

+   它使用最新的应用程序代码创建一个存档 ZIP；本地环境是一个预编译的 Lambda 包

+   将存档的 ZIP 上传到 AWS S3

+   更新 AWS Lambda

就是这样！我们已经完成了更新现有的部署，而且只花了几秒钟。

# 状态

你可以通过运行以下命令简单地检查应用程序部署的状态：

```py
$ zappa status production
```

这将打印有关 AWS Lambda 函数、计划事件和 API Gateway 的详细信息。

# 尾随日志

Zappa 提供了一个查看与部署相关日志的功能。你可以简单地使用以下命令：

```py
$ zappa tail production
```

这将打印与 HTTP 请求和 AWS 事件相关的所有日志。如果你想打印与 HTTP 请求相关的日志，你可以简单地传递`--http`参数：

```py
$ zappa tail production --http
```

你可以通过简单地使用以下代码来撤销前面的命令，从而反转非 HTTP 事件和日志消息：

```py
$ zappa tail production --non-http
```

你还可以使用`--since`参数限制日志的时间：

```py
$ zappa tail production --since 1h # 1 hour
$ zappa tail production --since 1m # 1 minute
$ zappa tail production --since 1mm # 1 month  
```

你还可以使用`--filter`参数过滤日志，例如：

```py
$ zappa tail production --since 1h --http --filter “POST”
```

这将仅显示最近一小时的 HTTP`POST`请求。这使用 AWS CloudWatch 日志过滤器模式（[`docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html`](http://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html)）。

# 回滚

AWS Lambda 维护你的部署的修订版。你可以通过提供一个修订号来回滚到先前部署的版本，如下所示：

```py
$ zappa rollback production -n 3
```

这将简单地将 Lambda 代码恢复到先前上传的归档 ZIP。

# 取消部署

如果你想完全删除你部署的应用程序，那么你只需使用以下命令：

```py
$ zappa undeploy production
```

这将删除发布的 AWS Lambda 和 API Gateway。如果你想要与你的应用程序相关的 AWS CloudWatch 日志，那么你只需在前面的命令中传递参数，如下所示：

```py
$ zappa undeploy production --remove-logs
```

这将清除 AWS CloudWatch 中的日志。

# 包

Zappa 提供了一个命令，在不部署应用程序的情况下在本地生成一个构建包归档：

```py
$ zappa package production
```

当你运行这个命令时，Zappa 会自动将你的活动虚拟环境打包成 AWS Lambda 兼容的包。

在内部，它用 AWS Lambda 兼容的、预编译版本替换任何本地依赖。这些依赖按以下顺序包括：

+   Lambda 兼容许多来自本地缓存的 Linux wheels

+   Lambda 兼容许多来自 PyPi 的 Linux wheels

+   Lambda 包中的 Lambda 特定版本（[`github.com/Miserlou/lambda-packages`](https://github.com/Miserlou/lambda-packages)）

+   归档活动虚拟环境

+   归档项目目录

在处理、打包和打包时，Zappa 会忽略一些不必要的文件，比如`.pyc`文件。如果它们可用，那么`.py`将被忽略。Zappa 还设置正确的执行权限，配置包设置，并创建一个唯一的、可审计的包清单文件。

生成的包归档将与 Lambda 兼容。你可以设置一个回调函数，一旦创建了归档，它将被调用：

```py
{
    "production": {
       "callbacks": {
            "zip": "my_app.zip_callback"
        }
    }
 }
```

在这里，production 是你的舞台名称，在回调中，你可以通过映射到`"zip"`来设置回调方法。这可以帮助你编写自己的自定义部署自动化。

我们已经看到了 Zappa 的基本用法。现在是时候做一些实际的工作了。我们将使用 Zappa 构建一些 Python 应用程序开发，敬请关注！

# 摘要

Zappa 提供了灵活的功能，让你可以执行部署过程。我们介绍了 Zappa 的基本用法，并了解了打包和部署过程。Zappa 让开发人员可以非常简单和容易地配置和执行应用程序到无服务器环境的部署。

# 问题

1.  Zappa 是什么？

1.  我们如何在 AWS 中保护应用程序？


# 第三章：使用 Zappa 构建 Flask 应用程序

在上一章中，我们了解了使用 Zappa 自动化部署过程的重要性，因为 Zappa 帮助我们在 AWS 无服务器基础架构上部署 Python 应用程序。我们使用它来开发使用一些 Python Web 框架的 Python 应用程序。在本章中，我们将开发一个基于 Flask 的应用程序，作为 AWS Lambda 上的无服务器应用程序。

在上一章中，我们了解了 Zappa 如何有助于执行无服务器部署，以及如何通过单个命令轻松部署。现在，是时候看到 Zappa 部署的更大型应用程序了，因为看到应用程序如何配置并移动到 AWS Lambda 是非常重要的。

在本章中，我们将涵盖以下主题：

+   什么是 Flask？

+   最小的 Flask 应用程序

+   与 Zappa 配置

+   在 AWS Lambda 上构建，测试和部署

+   一个完整的 Flask Todo 应用程序

# 技术要求

在继续之前，让我们了解技术要求并配置开发环境。本章中有一个应用程序开发的概念演示。因此，有一些先决条件：

+   Ubuntu 16.04/macOS/Windows

+   Python 3.6

+   Pipenv 工具

+   Zappa

+   Flask

+   Flask 扩展

一旦您配置了 Python 3.6 并安装了 Pipenv 工具，您可以创建一个虚拟环境并安装这些软件包。我们将在后面的章节中探索其安装和配置。让我们继续了解一些基于 Python 框架及其相关实现的基本概念。

# 什么是 Flask？

Flask 是 Python 社区中知名的微型 Web 框架。它因其可扩展的特性而被广泛采用和青睐。Flask 旨在保持代码简单但可扩展。

默认情况下，Flask 不包括任何数据库抽象层，表单验证或任何其他特定功能。相反，Flask 支持扩展以向您的应用程序添加任何明确定义的功能。有许多扩展可用于提供数据库集成，表单验证，文件上传处理，身份验证等。Flask 核心团队审查扩展，并确保它们不会破坏未来的发布。

Flask 允许您根据应用程序的需要定义设计。您不必遵循 Flask 的一些严格规则。您可以将应用程序代码编写在单个文件中，也可以以模块化的方式编写。Flask 支持内置开发服务器和快速调试器，单元测试，RESTful 请求分发，Jinja2 模板化和安全的 cookies（用于客户端会话），所有这些都符合 WSGI 1.0 标准和基于 Unicode。

这就是为什么许多 Python 社区的人更喜欢将 Flask 框架作为他们的首选。让我们继续前进，探索基于 Flask 的应用程序开发过程，实际实现以及无服务器方法。

# 安装 Flask

Flask 主要依赖于两个外部库，即 Werkzeug 和 Jinja2。Werkzeug 提供了 Python 标准的 WSGI（Web 服务器网关接口），使 Python 应用程序能够与 HTTP 交互。Jinja2 是一个模板引擎，使您能够使用自定义上下文呈现 HTML 模板。

现在，让我们继续安装 Flask。所有其依赖项将自动安装；您无需手动安装依赖项。

建议您使用`virtualenv`来安装 Flask，因为`virtualenv`使您能够为不同的 Python 项目并行安装 Python 软件包。

如果您没有`virtualenv`，那么您可以使用以下代码简单安装它：

```py
$ sudo apt-get install python-virtualenv
```

一旦您安装了`virtualenv`，您需要为您的 Flask 项目创建一个新的环境，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00032.jpeg)

我们将在接下来的章节中使用`virtualenv`。现在，让我们安装 Flask：

```py
$ pip install flask
```

我们准备好开始使用 Flask 了。我们将创建一个最小的 Flask 应用程序来演示 Flask 应用程序的工作流程。

# 一个最小的 Flask 应用程序

让我们看看最小的 Flask 应用程序是什么样子的：

```py
from flask import Flask
app = Flask(__name__)
@app.route('/')
def index():
  return 'Hello World!'
```

就是这样，我们完成了最小的 Flask 应用程序。使用 Flask 配置和创建微服务非常简单。

让我们讨论一下前面的代码到底在做什么，以及我们如何运行这个程序：

1.  首先，我们导入了一个 Flask 类。

1.  接下来，我们创建了一个 Flask 类的实例。这个实例将是我们的 WSGI 应用程序。第一个参数将是模块或包的名称。在这里，我们创建了一个单一的模块，因此我们使用了`__name__`。这是必需的，这样 Flask 就知道在哪里查找模板、静态和其他目录。

1.  然后，我们使用`app.route`作为装饰器，带有 URL 名称作为参数。这将定义并映射路由到指定的函数。

1.  该函数将被调用以处理路由装饰器中指定的 URL 的 HTTP 请求。

要运行这个程序，您可以使用`flask`命令或`python -m flask`，但在此之前，您需要设置一个环境变量`FLASK_APP`，并指定 Flask 实例所在的模块文件名：

```py
$ export FLASK_APP=hello_world.py
$ flask run
* Serving Flask app "flask_todo.hello_world"
* Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)
```

这启动了一个内置服务器，足够用于本地测试和调试。以下是浏览器中运行的本地主机的截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00033.jpeg)

当然，这在生产环境下是行不通的，但 Flask 提供了许多部署选项。您可以查看[`flask.pocoo.org/docs/0.12/deploying/#deployment`](http://flask.pocoo.org/docs/0.12/deploying/#deployment)获取更多信息，但在我们的情况下，我们将使用 Zappa 在 AWS Lambda 和 API Gateway 上部署到无服务器环境。

# 使用 Zappa 进行配置

为了配置 Zappa，需要安装 Zappa，如前一章所述。Zappa 提供了`zappa init`命令，它可以启用用户交互模式初始化，以便我们可以配置 Python 应用程序。

我遵循了`zappa init`命令建议的默认配置设置。这会生成`zappa_settings.json`文件，这是配置任何 Python 应用程序与 Zappa 的基础。

以下是`zappa_settings.json`文件的内容：

```py
{
  "dev": {
      "app_function": "hello_world.app",
      "aws_region": "ap-south-1",
      "profile_name": "default",
      "project_name": "flask-todo",
      "runtime": "python3.6",
      "s3_bucket": "zappa-yrze3w53y"
  }
}
```

现在，在初始化期间，Zappa 有能力识别您的 Python 应用程序的类型，并相应地生成设置属性。在我们的情况下，Zappa 检测到 Python 程序是一个 Flask 应用程序。因此，它要求 Flask 实例路径，我们在`hello_world.py`文件中初始化为`app = Flask(__name__)`。

现在 Zappa 配置已经按照我们的基本需求完成，是时候在 AWS Lambda 上部署它了。

# 在 AWS Lambda 上构建、测试和部署

我们在前一章描述了 Zappa 的基本用法和一些基本命令。使用这些命令，我们可以构建部署包、部署应用程序和执行其他基本操作。

一旦您在`zappa_settings.json`文件中设置了所有有效的属性，您就可以使用`zappa deploy <stage_name>`命令开始部署过程。根据我们的`zappa_settings.json`文件，我们定义了一个名为`dev`的阶段，因此，要开始部署，我们可以运行`deploy`命令，如下面的代码所示：

```py
$ zappa deploy dev
```

以下截图描述了部署流程：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00034.jpeg)

一旦 Zappa 部署完成，它会生成一个随机的 API 网关端点。Zappa 根据`zappa_settings.json`文件配置 AWS Lambda 与 API Gateway。

现在，Flask 应用程序可以通过先前生成的 API 访问。让我们测试一下，看看 Flask 应用程序的 Hello World!响应。您可以在浏览器中输入 URL，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00035.jpeg)

现在，让我们继续下一节，看看如何使用 Flask 框架开发应用程序。

# 一个完整的 Flask Todo 应用程序

由于我们已经看到 Zappa 如何轻松部署 Flask 应用程序，现在是时候看看在开发基于 Flask 的应用程序时可能需要的完整工作流程。我们将开发一个基于 Flask 的模块化应用程序，其中每个功能都将是一个独立的模块，例如认证、待办应用程序等。

认证模块将负责维护认证和授权机制。它还将包括登录和注册过程的实现。

而`todo`模块将有一个基本的 todo 操作实现，这个操作流程将由认证模块授权。借助 Flask 扩展，我们将管理和配置这些模块。除了这些核心模块，我们还将看到与用户界面、数据库配置和静态文件集成相关的实现。

# 先决条件

为了设置开发环境，我们需要执行一些与`virtualenv`和所需包相关的配置。

# Virtualenv

在我们开始项目工作之前，让我们创建一个虚拟环境并启用它，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00036.jpeg)

# Flask 扩展

Flask 是一个微框架，但它具有可扩展的特性，您可以根据需要添加更多功能。为了开发一个待办应用程序，我们可能需要一些基本功能，如数据持久性和用户认证机制。因此，在开发 Flask 应用程序时，我们将使用一些 Flask 扩展。

Flask 注册表提供了许多扩展，这些扩展是独立的包，您可以轻松地将它们配置到您的 Flask 应用程序实例中。您可以在[`flask.pocoo.org/extensions/`](http://flask.pocoo.org/extensions/)上看到完整的 Flask 扩展列表。

我们将使用以下 Flask 和 Flask 扩展包：

+   `Flask==0.12.2`

+   `Flask-Login==0.4.0`

+   `Flask-SQLAlchemy==2.3.2`

+   `Flask-WTF==0.14.2`

+   `Flask-Migrate==2.1.1`

我建议将这些包列在一个名为`requirements.txt`的单独文件中，然后一次性安装它们，如下所示：

```py
pip install -r requirements.txt
```

这将安装所有列出的包及其依赖项。

# 脚手架

在从头开始实现任何项目时，您可以自由设计项目的脚手架。我们将遵循以下截图中显示的脚手架：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00037.jpeg)

让我们详细看看每个目录及其用途：

+   `.env`：这是我们的`virtualenv`目录，是通过`virtualenv`命令创建的。

+   `auth`：我们将使用`Flask-Login`和`Flask-SqlAlchemy`扩展创建一个独立的通用认证模块。

+   `config`：在这里，我们将创建一些配置和通用数据库模型，其他模块可能需要这些模型。

+   `static`：将静态内容放在`static`目录下是 Flask 的标准做法。因此，我们将使用这个目录来存放所有需要的静态内容。

+   `templates`：Flask 内置支持 Jinja2 模板引擎，并遵循基于模块名称的模板文件的标准布局。我们将在实际使用模板时详细描述这一点。

+   `todo`：这是一个独立的 Flask 模块或包，具有基本的待办功能。

+   `__init__.py`：这是 Python 的标准文件，必须在目录下构建 Python 包。我们将在这里编写代码来配置我们的应用程序。

+   `migrations`：这个目录是由`Flask-Migrate`自动生成的。在后面的部分中，我们将看到`Flask-Migrate`的工作原理。

+   `.gitignore`：这个文件包含了应该被 Git 版本控制忽略的文件和目录列表。

+   `LICENSE`：我使用 GitHub 创建了一个 Git 存储库，并为我们的`flask_todo`存储库包含了 MIT 许可证。

+   `README.md`：这个文件用于在 GitHub 上描述有关存储库的信息。

+   `requirements.txt`：这是我们列出了在前面部分提到的所有所需包的文件。

+   `run.py`：在这里，我们将创建我们的 Flask 应用的最终实例。

+   `zappa_settings.json`：这个文件是由 Zappa 生成的，包含了与 Zappa 相关的配置。

我们将在接下来的部分详细解释代码。

# 配置

在实施任何项目时，我们可能需要一些特定于不同环境的配置，例如在开发环境中切换调试模式和在生产环境中监控。

Flask 有一种灵活的方式来克服配置处理机制。Flask 在其实例上提供了一个`config`对象。这个`config`对象是通过扩展 Python 的`dictionary`对象构建的，但具有一些额外的功能，如从文件、对象和默认内置配置加载配置。您可以在[`flask.pocoo.org/docs/0.12/config/`](http://flask.pocoo.org/docs/0.12/config/)上查看`config`机制的详细描述。

为了根据环境维护配置，我们将创建一个名为`config/config.py`的文件，其中包含以下代码：

```py
import os
from shutil import copyfile

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

def get_sqlite_uri(db_name):
    src = os.path.join(BASE_DIR, db_name)
    dst = "/tmp/%s" % db_name
    copyfile(src, dst)
    return 'sqlite:///%s' % dst

class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(24)
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_RECORD_QUERIES = True
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    @staticmethod
    def init_app(app):
        pass

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = get_sqlite_uri('todo-dev.db')

class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = get_sqlite_uri('todo-prod.db')

config = {
    'dev': DevelopmentConfig,
    'production': ProductionConfig,
}
```

在这里，我们创建了一个`Config`对象作为一个具有一些通用配置和`Flask-SqlAlchemy`配置的基类。然后，我们用特定于环境的类扩展了基本的`Config`类。最后，我们创建了一个映射对象，我们将从上述键中使用。

# 基本模型

SQLAlchemy 最著名的是其**对象关系映射器**（**ORM**），这是一个可选组件，提供了数据映射器模式，其中类可以以多种方式映射到数据库中，允许对象模型和数据库模式从一开始就以一种清晰的解耦方式发展。我们在这里使用`Flask-SQLAlchemy`扩展，它扩展了对 SQLAlchemy 的支持。`Flask-SQLAlchemy`增强了可能需要与 Flask 应用集成的功能。

我们将组合使用`Flask-SQLAlchemy`所需的通用 SQL 操作。因此，我们将创建一个基本模型类，并将使用这个类来创建其他模块的模型类。这就是我们将其放在`config`目录下的原因。这是`models.py`文件。

文件—`config/models.py`：

```py
from app import db

class BaseModel:
    """
    Base Model with common operations.
    """

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def save(self):
        db.session.add(self)
        db.session.commit()
        return self
```

您可以在这里看到，我们将所有模型都需要的数据库操作分组在一起。`db`实例是在`app/__init__.py`文件中使用`Flask-SQLAlchemy`扩展创建的。

在这里，我们实现了`save`和`delete`方法。`db.Model`定义了一个通用模式，用于创建代表数据库表的模型类。为了保存和删除，我们需要遇到一些预定义的操作，如`db.session.add()`、`db.session.delete()`和`db.session.commit()`。

因此，我们将通用操作分组在`save`和`delete`方法下。这些方法将从一个模型类中调用，该模型类将继承它们。我们将在稍后创建一个模型类时再详细介绍。

# 认证

为了开发一个认证模块，我们将使用`Flask-Login`扩展。`Flask-Login`扩展提供了用户会话管理机制。它处理管理用户会话的常见任务，如登录、注销和记住用户。

要集成`Flask-Login`，您需要创建实例并定义一些默认参数，如下面的代码片段中所述：

```py
from flask_login import LoginManager
app = Flask(__name__)
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'auth.login'
login_manager.login_message_category = "info"
login_manager.init_app(app)
```

我们将创建一个认证模块作为一个`auth`包。`auth`包将具有基本的脚手架，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00038.jpeg)

# 蓝图

在深入描述每个文件之前，让我们看一下 Flask 实例化机制。正如你已经知道的，我们正在创建一个独立模块作为`root`模块下的一个子模块。Flask 引入了蓝图的概念，用于将子模块组件放在一个共同的模式下。

Flask 蓝图实例非常类似于 Flask 实例，但它不是一个应用程序对象。相反，它具有构建和扩展父应用程序的能力。借助蓝图，您可以设计一个模块化的应用程序。

```py
Blueprint instantiation in the auth/__init__.py file:
```

```py
from flask import Blueprint
auth = Blueprint('auth', __name__)
from . import views
```

如您所见，它具有与`Flask`类非常相似的特征，并遵循类似的模式。现在，我们将在视图中使用`blueprint`的`auth`实例来注册路由。要执行应用程序，我们需要将`blueprint`对象与 Flask 应用程序实例绑定。

```py
app/__init__.py file where we are going to create the Flask application instance:
```

```py
from .auth import auth as auth_blueprint
from app.config import config

app = Flask(__name__)
app.config.from_object(config[environment])

app.register_blueprint(auth_blueprint, url_prefix='/auth')
```

借助`register_blueprint`方法，我们正在注册`auth`模块蓝图，我们还可以添加 URL 前缀。在查看`todo`模块解释之后，我们将对此文件进行完整描述。

# 模型

让我们从创建具有基本功能的`User`模型开始。以下是用户模型的代码片段。

文件—`auth/models.py`：

```py
import re
from datetime import datetime

from app.config.models import BaseModel
from flask_login.mixins import UserMixin
from sqlalchemy.orm import synonym
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from app import login_manager

class User(UserMixin, BaseModel, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    _email = db.Column('email', db.String(64), unique=True)
    password_hash = db.Column(db.String(128))

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)

    def __repr__(self):
        return '<User {0}>'.format(self.email)

    @property
    def email(self):
        return self._email

    @email.setter
    def email(self, email):
        if not len(email) <= 64 or not bool(re.match(r'^\S+@\S+\.\S+$', email)):
            raise ValueError('{} is not a valid email address'.format(email))
        self._email = email

    email = synonym('_email', descriptor=email)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        if not bool(password):
            raise ValueError('no password given')

        hashed_password = generate_password_hash(password)
        if not len(hashed_password) <= 128:
            raise ValueError('not a valid password, hash is too long')
        self.password_hash = hashed_password

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'email': self.email
        }

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
```

现在，我们已经创建了`User`模型，但它如何与`Flask-Login`扩展相关联或映射呢？答案是`load_user`方法，该方法由`login_manager.user_loader`装饰器包装。Flask 提供了这个方法来将用户加载到会话中。该方法使用会话中存在的`user_id`进行调用。

我们可以通过`User`模型将用户数据持久化到数据库中。作为一个 Web 应用程序，用户数据需要通过用户界面（如 HTML）输入。根据我们的需求，我们需要两种类型的 HTML 表单，用于登录和注册功能。

让我们继续下一节，学习通过 Flask 渲染 HTML 表单。

# 表单

`Flask-WTF`扩展提供了在 Flask 中开发表单并通过 Jinja2 模板渲染它们的能力。`Flask-WTF`扩展了`WTForms`库，该库具有设计表单的标准模式。

我们需要两个表单，如`SignupForm`和`LoginForm`。以下是创建表单类的代码。

文件—`auth/forms.py`：

```py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Required, Length, Email, EqualTo

class LoginForm(FlaskForm):
    email = StringField(
        'Email', validators=[Required(), Length(1,64), Email()]
    )
    password = PasswordField(
        'Password', validators=[Required()]
    )
    submit = SubmitField('Log In')

class SignupForm(FlaskForm):
    email = StringField(
        'Email', validators=[Required(), Length(1,64), Email()]
    )
    password = PasswordField(
        'Password', validators=[
            Required(),
            EqualTo('confirm_password', message='Password must match.')]
    )
    confirm_password = PasswordField(
        'Confirm Password', validators=[Required()]
    )
    submit = SubmitField('Sign up')
```

在这里，我们创建了一些带有验证的表单。现在，我们将在视图部分中使用这些表单，在那里我们将呈现模板以及表单上下文。

# 视图

Flask 以一种非常灵活的方式实现了视图，您可以在其中定义路由。Flask 的通用视图实现受到 Django 的通用视图的启发。我们将在后面的部分详细描述方法视图，但在这里，我们将使用简单的视图。

以下是视图片段。

文件—`auth/views.py`：

```py
from flask import render_template, redirect, url_for
from flask_login import login_user, login_required, logout_user

from app.auth import auth
from app.auth.forms import LoginForm, SignupForm
from app.auth.models import User

@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_by_email = User.query.filter_by(email=form.email.data).first()
        if user_by_email is not None and user_by_email.verify_password(form.password.data):
            login_user(user_by_email)
            return redirect(url_for('todo.list'))
    return render_template('auth/login.html', form=form)

@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        if not User.query.filter_by(email=form.email.data).scalar():
            User(
                email = form.email.data,
                password = form.password.data
            ).save()
            return redirect(url_for('auth.login'))
        else:
            form.errors['email'] = 'User already exists.'
            return render_template('auth/signup.html', form=form)
    return render_template('auth/signup.html', form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
```

在这里，我们创建了`/login`、`/signup`和`/logout`路由，我们根据 HTTP 请求调用它们。我们在 HTTP `GET`请求上呈现一个空的表单实例，并在`POST`请求上通过使用`Flask-WTF`方法和`validate_on_submit()`方法处理数据。在呈现模板时，我们传递表单实例并根据需要的操作进行重定向。

让我们在下一节中看一下模板机制。

# 模板

Flask 内置了对 Jinja2 模板的支持。Jinja2 模板具有用于呈现 HTML 的标准定义模式。我们可以通过传递上下文参数来放置动态内容。Jinja2 提供了使用一些表达式和条件、扩展和包含模板功能来呈现 HTML 的能力。

Flask 遵循标准的模板搭建结构来布置所有模板文件。以下是我们遵循的搭建结构，通过在项目根目录下创建一个`templates`目录，然后根据其他模块名称创建子目录：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00039.jpeg)

在这里，我们根据模块创建了模板，并将通用模板放在根目录下。

同样，我们保持了静态文件的脚手架：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00040.jpeg)

我们保留了静态库和模块相关文件。借助`url_for`方法，我们可以获取任何静态文件和路由的相对路径。因此，在以下模板中，我们使用`url_for`方法包含了所有静态文件，例如`<link rel="stylesheet" href="{{ url_for('static', filename='bootstrap/css/bootstrap.min.css')}}">`。

同样，我们将在基本模板中包含所有静态文件。

文件—`templates/base.html`：

```py
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <meta name="author" content="AbdulWahid AbdulHaque">
    <title>Flask Todo App</title>

    <link rel="stylesheet" href="{{ url_for('static', filename='bootstrap/css/bootstrap.min.css') }}">
    <link rel="stylesheet" href="{{ url_for('static', filename='bootstrap/css/bootstrap.min.css.map') }}">
    {% block css %}{% endblock %}

    <script type="text/javascript" src="img/jquery-3.3.1.min.js')}}"></script>
    <script type="text/javascript" src="img/bootstrap.min.js')}}"></script>
    <script type="text/javascript" src="img/popper.min.js')}}"></script>
    {% block js %}{% endblock %}
</head>
<body>
    {% include 'navbar.html' %}
    {% block body %}{% endblock %}
    <script type="text/javascript">
        $('.dropdown-toggle').dropdown();
    </script>
</body>
</html>
```

我们定义了所有其他模板所需的通用 HTML。我们还创建了一个基本的 bootstrap 导航栏，并将其保存在`navbar.html`中，通过`{% include 'navbar.html' %}`包含在`base.html`模板中。正如你所看到的，Jinja2 模板使得维护模板和提供标准模式变得非常容易。

```py
navbar.html template where we created a navbar using Bootstrap CSS classes.
```

文件—`templates/navbar.html`：

```py
<nav class="navbar navbar-expand-lg navbar-light bg-light">
    <a class="navbar-brand" href="#">Todo's</a>
    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNavDropdown" aria-controls="navbarNavDropdown" aria-expanded="false" aria-label="Toggle navigation">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarNavDropdown">
        {% if current_user.is_authenticated %}
        <ul class="navbar-nav ml-auto">
            <li class="nav-item dropdown ml-auto">
                <a class="nav-link dropdown-toggle" href="#" id="navbarDropdownMenuLink" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                    Welcome <i>{{ current_user.email }}</i>
                </a>
                <div class="dropdown-menu" aria-labelledby="navbarDropdownMenuLink">
                    <a class="dropdown-item" href="../auth/logout">Logout</a>
                </div>
            </li>
        </ul>
        {% endif %}
    </div>
  </nav>
```

在设计`navbar.html`时，我们添加了一些条件语句，以在用户登录时显示已登录用户的信息和注销选项。

让我们继续进行注册和登录页面。以下是注册页面的代码片段。

文件—`templates/auth/signup.html`：

```py
{% extends "base.html" %}

{% block body %}
<div class="container align-middle mx-auto" style="width:30%; margin-top:5%">
    <div class="card bg-light mb-3">
        <div class="card-header"><h3>Sign Up</h3></div>
        <div class="card-body">
            <form method="post">
                {{ form.hidden_tag() }}
                {% if form.errors %}
                    {% for error in form.errors.values() %}
                        <div class="alert alert-danger" role="alert">
                            {{error}}
                        </div>
                    {% endfor %}
                  {% endif %}
                <div class="form-group">
                    <label for="exampleInputEmail1">Email address</label>
                    {{ form.email(class_="form-control", id="exampleInputEmail1", placeholder="Email", maxlength=128)}}
                    <small id="emailHelp" class="form-text text-muted">We'll never share your email with anyone else.</small>
                </div>
                <div class="form-group">
                    <label for="exampleInputPassword1">Password</label>
                    {{ form.password(class_="form-control", placeholder="Password") }}
                </div>
                <div class="form-group">
                    <label for="exampleInputPassword">Confirm Password</label>
                    {{ form.confirm_password(class_="form-control", placeholder="Confirm Password") }}
                </div>
                <div class="form-group">
                    {{ form.submit(class_="btn btn-primary btn-lg") }}
                    <a class="float-right" href="login">Already have account.</a>
                </div>
            </form>
        </div>
      </div>
</div>
{% endblock %}
```

这是注册页面的输出：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00041.jpeg)

在`auth.signup`视图的 HTTP `GET`请求中，这将返回一个空表单，并通过`signup.html`模板进行渲染。我们还添加了代码来在注册视图中接收 HTTP `POST`请求上的注册数据。我们使用`User`模型在注册过程中持久化用户数据。

这是登录模板。

文件—`templates/auth/login.html`：

```py
{% extends "base.html" %}

{% block body %}
<div class="container align-middle mx-auto" style="width:30%; margin-top:5%">
    <div class="card bg-light mb-3">
        <div class="card-header"><h3>Login</h3></div>
        <div class="card-body">
            <form method="post">
                {{ form.hidden_tag() }}
                {% if form.errors %}
                    <div class="has-error"><strong>Unable to login. Typo?</strong></div>
                  {% endif %}
                <div class="form-group">
                    <label for="exampleInputEmail1">Email address</label>
                    {{ form.email(class_="form-control", id="exampleInputEmail1", placeholder="Email", maxlength=128)}}
                    <small id="emailHelp" class="form-text text-muted">We'll never share your email with anyone else.</small>
                </div>
                <div class="form-group">
                    <label for="exampleInputPassword1">Password</label>
                    {{ form.password(class_="form-control", id="exampleInputPassword1", placeholder="Password") }}
                </div>
                <div class="form-group">
                    {{ form.submit(class_="btn btn-primary btn-lg") }}
                    <a class="float-right" href="signup">New around here? Sign up</a>
                </div>
            </form>
        </div>
      </div>
</div>
{% endblock %}
```

现在，用户可以继续登录系统。对于登录，我们创建了登录表单，并通过`auth.login`视图进行渲染。以下是登录页面的截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00042.jpeg)

在 HTTP `POST`请求中，我们使用`Flask-Login`扩展来处理用户登录机制，它提供了一个名为`login_user`的函数并执行登录过程。它创建一个会话并将`user_id`添加到会话中，以便在进一步的请求中记住用户，直到我们从会话中移除用户或使用`auth.logout`视图中提到的`logout_user`方法执行注销。

认证过程在这里完成，当用户登录成功并重定向到另一个页面或模板时。现在，是时候继续进行`todo`模块了。

# Todo

Todo 程序被认为是一个简单直接的应用程序，并且在 hello world!之后广泛用于解释任何语言或框架。我们也为`todo`模块遵循相同的脚手架结构。

以下是`todo`模块的脚手架的截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00043.jpeg)

让我们看看`todo`模块中每个文件的详细描述。

# 蓝图

Flask 引入了蓝图的概念，用于开发应用程序组件和命令模式，可以在应用程序或多个应用程序中使用。它有助于通过将根 Flask 应用程序对象集中化来理解大型应用程序。蓝图充当一个独立的 Flask 应用程序，而不创建实际的 Flask 应用程序对象，并且能够实例化应用程序对象，初始化多个扩展，并注册集合。它还提供模板过滤器、静态文件、模板和其他实用程序。

如`auth`模块中所述，我们还将为 Todo 应用程序创建`Blueprint`实例。这将在`app.__init__.py`文件中配置，这是我们创建 Flask 应用程序实例的地方。

```py
todo module's blueprint.
```

文件—`todo/__init__.py`：

```py
from flask import Blueprint

todo = Blueprint('todo', __name__)

from . import views 
```

一旦我们创建了`todo`模块的`blueprint`对象，我们就可以使用它在视图中添加路由，并将 blueprint 注册到 Flask 应用程序实例中。

```py
app/__init__.py, which is where we are going to register blueprint:
```

```py
from .auth import auth as auth_blueprint
from app.config import config

app = Flask(__name__)
app.config.from_object(config[environment])

app.register_blueprint(todo_blueprint, url_prefix='/todos')
```

# 模型

我们将使用`Flask-SQLAlchemy`来创建一个待办事项模型。它将与`User`模型建立关系，并带有一个反向引用，这样我们就可以查询与`User`模型相关的`todo`数据。

以下是待办事项模型的代码片段。

文件-`todo/models.py`：

```py
from datetime import datetime
from app import db
from app.config.models import BaseModel

class Todo(db.Model, BaseModel):
    __tablename__ = 'todo'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128))
    is_completed = db.Column(db.Boolean, default=False)
    created_by = db.Column(db.String(64), db.ForeignKey('user.email'))
    user = db.relationship('User', backref=db.backref('todos', lazy=True))

    def __init__(self, title, created_by=None, created_at=None):
        self.title = title
        self.created_by = created_by
        self.created_at = created_at or datetime.utcnow()

    def __repr__(self):
        return '<{0} Todo: {1} by {2}>'.format(
            self.status, self.title, self.created_by or 'None')

    @property
    def status(self):
        return 'finished' if self.is_completed else 'open'

    def finished(self):
        self.is_completed = True
        self.finished_at = datetime.utcnow()
        self.save()

    def reopen(self):
        self.is_completed = False
        self.finished_at = None
        self.save()

    def to_dict(self):
        return {
            'title': self.title,
            'created_by': self.created_by,
            'status': self.status,
        }
```

在这里，我们使用基本功能和验证创建了待办事项模型。现在，我们将使用这个模型来持久化`todo`数据。然而，我们还需要为用户提供一个 UI 来输入`todo`数据并执行一些操作。

# 表单

我们将拥有一个简单的待办事项表单，其中包含一个带有提交按钮的文本框。它还应该包含列表视图来显示待办事项数据。

以下是待办事项表单的代码片段。

文件-`todo/forms.py`：

```py
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import Required, Length

class TodoForm(FlaskForm):
    title = StringField(
        'What needs to be done?', validators=[Required(), Length(1, 128)]
    )
    submit = SubmitField('Submit')
```

正如你所看到的，我们的待办事项表单非常简单，带有一些基本的验证。现在是时候在视图中使用这个表单来将它们渲染成 HTML 模板了。

# 视图

我们创建了一个待办事项蓝图的实例，并将使用这个实例在视图中创建路由。以下是视图的代码片段。

文件-`todo/views.py`：

```py
import json

from flask import render_template, redirect, url_for, jsonify, request
from flask_login import login_required, current_user
from app.todo import todo
from app.todo.forms import TodoForm
from app.todo.models import Todo

@todo.route('/', methods=['GET', 'POST'])
@login_required
def list():
    context = dict()
    form = TodoForm()
    if form.validate_on_submit():
        Todo(form.title.data, created_by=current_user.email).save()
        return redirect(url_for('todo.list'))
    context['form'] = form
    context['todos'] = current_user.todos
    context['items_left'] = len([todo for todo in current_user.todos if not todo.is_completed])
    return render_template('todo/list.html', **context)

@todo.route('/<todo_id>', methods=['DELETE'])
@login_required
def remove(todo_id):
    Todo.query.filter_by(id=int(todo_id)).delete()
    return jsonify({'message': 'Todo removed successfully'})

@todo.route('/<todo_id>', methods=['PATCH'])
@login_required
def update(todo_id):
    data = json.loads([k for k in request.form.keys()][0])
    todo = Todo.query.filter_by(id=int(todo_id)).scalar()
    if data.get('status'):
        todo.finished()
    else:
        todo.reopen()
    return jsonify({'message': 'Todo updated successfully'})
```

我们在这里定义了三个路由。在注册待办事项蓝图到 Flask 应用对象时，我们已经使用了`todos`作为前缀。记住这一点，我们决定使用这些路由 URL。

为了持久化待办事项数据，我们需要执行四种类型的操作，即—创建一个待办事项，列出待办事项，更新任何特定项目，和删除任何特定的待办事项。这些操作无非是标准的**CRUD**（**创建**，**检索**，**更新**，**删除**）操作。

# 创建

为了创建一个操作，我们决定将 URL 设置为`/`，但是加上前缀后，它将变成`todos/`。在 HTTP `POST`请求中，我们期望从用户那里得到待办事项数据，根据提交的数据，我们将使用待办事项模型创建待办事项数据，例如`Todo(form.description.data, creator=current_user.email).save()`。

# 检索

```py
current_user.todos and filter the data using list compensation. Then, we prepare the context and pass it to the render_template method to display the data in HTML.
```

# 更新

要更新待办事项数据，我们将使用 HTTP `PATCH`请求来访问路由`todos/<todo_id>`。但是，这次我们没有任何表单，需要传递数据，因此我们使用 jQuery 来进行`PATCH`请求的 Ajax 查询。

我们定义了一些属性和方法来标记待办事项数据是否完成，因此根据更新的数据，我们将使用这些方法来更新待办事项记录。

# 删除

类似于从数据库中删除待办事项记录，我们需要使用待办事项模型的查询方法，比如`Todo.query.filter_by(id=int(todo_id)).delete()`。正如你所看到的，路由视图非常简单。现在，让我们来看一下模板。

# 模板

需要做很多工作来完成待办事项的工作流。我们定义了`templates/todo/list.html`模板来显示待办事项表单和待办事项记录列表。在前面的部分中，我们描述了如何渲染和传递上下文数据。

以下是待办事项列表模板的代码片段。

文件-`templates/todo/list.html`：

```py
{% extends "base.html" %}
{% block js %}
    <script src="img/list.js')}}"></script>
{% endblock %}
{% block body %}
<div class="container align-middle mx-auto" style="width:30%; margin-top:5%">
    <div class="card mb-3">
        <div class="card-header" align="center"><h3>todo's</h3></div>
        <div class="card-body">
            <form method="post" class="form-inline">
                {{ form.hidden_tag() }}
                {% if form.errors %}
                    <div class="has-error"><strong>Invalid task. Typo?</strong></div>
                  {% endif %}
                <div class="form-group ml-3">
                    {{ form.title(class_="form-control", placeholder="What needs to be done?", maxlength=128)}}
                </div>
                <div class="form-group">
                    {{ form.submit(class_="btn btn-primary ml-2") }}
                </div>
            </form>
            <div class="badge badge-pill badge-info ml-3 mt-2">
                {{items_left}} items left
            </div>
            <ul class="list-group list-group-flush mt-3" id="todolist">
                {% for todo in todos %}
                <li class="list-group-item" id="{{todo.id}}">
                    <input type="checkbox" aria-label="Checkbox for following text input" {% if todo.is_completed %} checked {% endif %}>
                    {{todo.title}}
                    <span class="badge badge-danger badge-pill float-right">X</span>
                </li>
                {% endfor %}
            </ul>
        </div>
      </div>
</div>

<script>

</script>
{% endblock %}
```

我们使用上下文数据来显示待办事项表单和记录列表。有一些操作我们需要编写 jQuery 代码，比如根据复选框操作更新待办事项，以及根据删除按钮操作删除待办事项。

以下是 jQuery 代码片段。

文件-`static/todo/list.js`：

```py
var csrftoken = $('meta[name=csrf-token]').attr('content');
function csrfSafeMethod(method) {
// these HTTP methods do not require CSRF protection
return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
}

$.ajaxSetup({
    beforeSend: function(xhr, settings) {
      if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
        xhr.setRequestHeader("X-CSRFToken", csrftoken);
      }
    }
  });

$(document).ready(function(){

    // Update todo
    $('#todolist li>input[type="checkbox"]').on('click', function(e){
        var todo_id = $(this).parent().closest('li').attr('id');
        $.ajax({
            url : todo_id,
            method : 'PATCH',
            data : JSON.stringify({status: $(this).prop('checked')}),
            success : function(response){
                location.reload();
            },
            error : function(error){
                console.log(error)
            }
        })
    })

    // Remove todo
    $('#todolist li>span').on('click', function(e){
        var todo_id = $(this).parent().closest('li').attr('id');
        $.ajax({
            url : todo_id,
            method : 'DELETE',
            success : function(response){
                location.reload();
            },
            error : function(error){
                console.log(error)
            }
        })
    })
})
```

在进行 Ajax 请求时，我们还添加了对 CSRF 的支持。Ajax 请求非常简单直接，因为这些请求是通过前面提到的 todo 路由来服务的。以下是待办事项列表页面的截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00044.jpeg)

现在，我们已经完成了`todo`模块，是时候用 Flask 应用对象配置 todo 蓝图了。

# FLASK_APP

在任何 Flask 项目中，我们创建 Flask 应用程序对象，并使用`FLASK_APP`参数或环境变量的值引用文件路径。在我们的情况下，我们创建了一个模块化应用程序，为特定操作定义了单独的模块，但现在我们需要将所有这些模块合并到一个地方。我们已经看到了`blueprint`对象及其集成。在这里，我们将看到将`blueprint`和其他所需扩展组合的实际过程。

以下是 Flask 应用程序对象的代码片段。

文件-`app/__init__.py`：

```py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect

from app.config import config

db = SQLAlchemy()
migrate = Migrate()
csrf = CSRFProtect()

login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'auth.login'
login_manager.login_message_category = "info"

def create_app(environment):
    app = Flask(__name__)
    app.config.from_object(config[environment])

    csrf.init_app(app)
    db.init_app(app)
    migrate.init_app(app, db=db)
    login_manager.init_app(app)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    from .todo import todo as todo_blueprint
    app.register_blueprint(todo_blueprint, url_prefix='/todos')

    return app
```

在这里，我们正在配置扩展和蓝图，但是在一个名为`create_app`的方法下。这个方法需要一个参数来设置特定环境的配置，因此最好有这个函数，并为特定配置获取 Flask 应用程序实例。

```py
run.py, where we will be using the create_app method.
```

文件-`flask_todo/run.py`：

```py
from app import create_app

app = create_app('dev')
```

在这里，我们使用了`dev`环境配置。您可以将此文件用作您的`FLASK_APP`参数，例如`FLASK_APP=run.py flask run`。

我们已经完成了 todo 应用程序的开发，现在是时候使用 Zappa 进行部署了。

# 部署

我们将使用 Zappa 进行部署。要配置 Zappa，您需要安装 Zappa 并使用 AWS CLI 配置您的 AWS 凭据。一旦我们安装了 Zappa 并处理了 AWS CLI 配置，我们就可以继续部署 Todo 应用程序。

以下是`zappa init`命令过程的截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00045.jpeg)

当我们运行`zappa init`命令时，Zappa 会自动识别框架类型并建议所需的参数。在我们的情况下，我们将`app_function`名称保持为`run.app`，因为我们是通过`run.py`中的`create_app`方法初始化`flask app`对象。

`zappa init`命令创建了`zappa_settings.json`文件，其中包含了所有配置的参数。您可以根据需要自由修改它。

现在，是时候使用`zappa deploy <stage_name>`命令执行部署过程了。最初，我们将使用`zappa deploy`命令。一旦我们的应用程序部署完成，我们就不能再使用**`zappa deploy`**命令了。相反，我们需要使用`zappa update <stage_name>`命令。

以下是`zappa deploy dev`命令的代码：

```py
$ zappa deploy dev
Calling deploy for stage dev..
Creating chapter-3-dev-ZappaLambdaExecutionRole IAM Role..
Creating zappa-permissions policy on chapter-3-dev-ZappaLambdaExecutionRole IAM Role.
Downloading and installing dependencies..
 - sqlite==python36: Using precompiled lambda package
Packaging project as zip.
Uploading chapter-3-dev-1529318192.zip (9.4MiB)..
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 9.87M/9.87M [00:05<00:00, 1.89MB/s]
Scheduling..
Scheduled chapter-3-dev-zappa-keep-warm-handler.keep_warm_callback with expression rate(4 minutes)!
Uploading chapter-3-dev-template-1529318886.json (1.6KiB)..
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1.62K/1.62K [00:00<00:00, 4.87KB/s]
Waiting for stack chapter-3-dev to create (this can take a bit)..
 50%|██████████████████████████████████████████████████████████████████████████████████████████████▌ | 2/4 [00:09<00:10, 5.29s/res]
Deploying API Gateway..
Deployment complete!: https://m974nz8zld.execute-api.ap-south-1.amazonaws.com/dev
```

我们已经完成了部署，并且能够访问生成的 URL 上的 Todo 应用程序，如下截图所示。

访问 URL 后的输出如下（[`m974nz8zld.execute-api.ap-south-1.amazonaws.com/dev/auth/signup`](https://m974nz8zld.execute-api.ap-south-1.amazonaws.com/dev/auth/signup)[)](https://p2wdbhjwd6.execute-api.ap-south-1.amazonaws.com/dev/auth/signup)：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00046.jpeg)

我将保持`flask_todo` Lambda 函数处于活动状态，以便您随时尝试。我已经创建了一个 GitHub 存储库（[`github.com/PacktPublishing/Building-Serverless-Python-Web-Services-with-Zappa/tree/master/chapter_3`](https://github.com/PacktPublishing/Building-Serverless-Python-Web-Services-with-Zappa/tree/master/chapter_3)），并将所有代码库推送到其中以供将来参考。

# 总结

在本章中，我们介绍了使用 Zappa 在服务器环境上创建基于 Flask 的应用程序并部署的工作流程。借助 Zappa，我们将应用程序移动到 AWS Lambda 并执行操作以维护部署。在部署应用程序时，我们不需要配置传统的服务器软件；相反，我们只需使用 JSON 文件来配置具有多个环境的部署。

在下一章中，我们将看到 REST API 的实现。

# 问题

1.  Amazon API Gateway 是什么？

1.  `zappa_settings.json`中的`function_name`的用途是什么？
