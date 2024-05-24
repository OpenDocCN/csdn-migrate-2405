# Kubernetes 无服务器应用手册（一）

> 原文：[`zh.annas-archive.org/md5/8919C4FA258132C529A8BB4FA8603A2F`](https://zh.annas-archive.org/md5/8919C4FA258132C529A8BB4FA8603A2F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Kubernetes 是近年来突出的技术之一；它已被所有主要公共云提供商采用为容器集群和编排平台，并迅速成为行业标准。

再加上 Kubernetes 是开源的，您就拥有了在多个公共和私有提供商上托管自己的平台即服务或 PaaS 的完美基础；您甚至可以在笔记本电脑上运行它，并且由于其设计，您将在所有平台上获得一致的体验。

它的设计也使其成为运行无服务器函数的理想平台。在本书中，我们将研究几个可以部署在 Kubernetes 上并与之集成的平台，这意味着我们不仅拥有 PaaS，还有一个强大的 FaaS 平台在您的 Kubernetes 环境中运行。

# 本书适合对象

本书主要面向运维工程师、云架构师和开发人员，他们希望在 Kubernetes 集群上托管他们的无服务器函数。

# 本书内容

第一章，*无服务器景观*，解释了什么是无服务器。此外，我们将在公共云上使用 AWS Lambda 和 Azure Functions 来运行无服务器函数，获得一些实际经验。

第二章，*Kubernetes 简介*，讨论了 Kubernetes 是什么，它解决了什么问题，并且还回顾了它的背景，从谷歌的内部工程工具到开源强大工具。

第三章，*在本地安装 Kubernetes*，解释了如何通过实践经验来使用 Kubernetes。我们将使用 Minikube 安装本地单节点 Kubernetes 集群，并使用命令行客户端与其交互。

第四章，*介绍 Kubeless 函数*，解释了在本地运行 Kubernetes 后如何使用 Kubeless 启动第一个无服务器函数。

第五章，*使用 Funktion 进行无服务器应用*，解释了使用 Funktion 来调用无服务器函数的一种略有不同的方法。

第六章，*在云中安装 Kubernetes*，介绍了在 DigitalOcean、AWS、Google Cloud 和 Microsoft Azure 上启动集群的过程，以及在本地使用 Kubernetes 进行一些实践经验后的操作。

第七章，*Apache OpenWhisk 和 Kubernetes*，解释了如何在我们新推出的云 Kubernetes 集群上启动、配置和使用最初由 IBM 开发的无服务器平台 Apache OpenWhisk。

第八章，*使用 Fission 启动应用程序*，介绍了部署 Fission 的过程，这是 Kubernetes 的流行无服务器框架，并附带了一些示例函数。

第九章，*了解 OpenFaaS*，介绍了 OpenFaaS。虽然它首先是一个用于 Docker 的函数即服务框架，但也可以部署在 Kubernetes 之上。

第十章，*无服务器考虑因素*，讨论了安全最佳实践以及如何监视您的 Kubernetes 集群。

第十一章，*运行无服务器工作负载*，解释了 Kubernetes 生态系统的快速发展以及您如何跟上。我们还讨论了您应该使用哪些工具，以及为什么您希望将无服务器函数部署在 Kubernetes 上。

# 为了充分利用本书

**操作系统**：

+   macOS High Sierra

+   Ubuntu 17.04

+   Windows 10 专业版

**软件**：

在本书中，我们将安装几个命令行工具；每个工具都将在各章节中提供安装说明和其要求的详细信息。请注意，虽然提供了 Windows 系统的说明，但我们将主要使用最初设计为在 Linux/Unix 系统上运行的工具，如 Ubuntu 17.04 和 macOS High Sierra，并且本书将偏向这些系统。虽然在撰写时已尽最大努力验证这些工具在基于 Windows 的系统上的运行情况，但由于一些工具是实验性构建的，我们无法保证它们在更新的系统上仍然能够正常工作，因此，我建议使用 Linux 或 Unix 系统。

硬件：

+   **Windows 10 专业版和 Ubuntu 17.04 系统要求**：

+   使用 2011 年或之后推出的处理器（CPU），核心速度为 1.3 GHz 或更快，除了基于*Llano*和*Bobcat*微架构的英特尔 Atom 处理器或 AMD 处理器

+   最低 4 GB RAM，建议使用 8 GB RAM 或更多

+   **Apple Mac 系统要求**：

+   iMac：2009 年底或更新

+   MacBook/MacBook（Retina）：2009 年底或更新

+   **MacBook Pro**：2010 年中期或更新

+   **MacBook Air**：2010 年末或更新版本

+   **Mac mini**：2010 年中期或更新版本

+   **Mac Pro**：2010 年中期或更新版本

**至少可以访问以下公共云服务之一**：

+   **AWS**：[`aws.amazon.com/`](https://aws.amazon.com/)

+   **Google Cloud**：[`cloud.google.com/`](https://cloud.google.com/)

+   **Microsoft Azure**：[`azure.microsoft.com/`](https://azure.microsoft.com/)

+   **DigitalOcean**：[`www.digitalocean.com/`](https://www.digitalocean.com/)

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，文件将直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的以下软件解压缩文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Kubernetes-for-Serverless-Applications`](https://github.com/PacktPublishing/Kubernetes-for-Serverless-Applications)。我们还有其他丰富的图书和视频的代码包可供下载，网址为**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**。请查看！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/KubernetesforServerlessApplications_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/KubernetesforServerlessApplications_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：指示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。这是一个例子：“这包含一个名为`index.html`的单个文件。”

一段代码设置如下：

```
apiVersion: apps/v1beta1
kind: Deployment
metadata:
  name: cli-hello-world
  labels:
    app: nginx
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目以粗体设置：

```
apiVersion: apps/v1beta1
kind: Deployment
metadata:
  name: cli-hello-world
  labels:
    app: nginx
```

任何命令行输入或输出都将按照以下方式编写：

```
$ brew cask install minikube
```

**粗体**：表示一个新术语，一个重要的词，或者你在屏幕上看到的词。例如，菜单或对话框中的单词会在文本中以这种方式出现。这是一个例子：“在页面底部，您将有一个按钮，可以让您为您的帐户创建访问令牌和访问令牌密钥。”

警告或重要提示会以这种方式出现。提示和技巧会以这种方式出现。


# 第一章：无服务器景观

欢迎来到《用于无服务器应用的 Kubernetes》的第一章。在本章中，我们将讨论以下内容：

+   我们所说的无服务器和函数作为服务是什么意思？

+   有哪些服务？

+   亚马逊网络服务的 Lambda 的一个例子。

+   Azure Functions 的一个例子

+   使用无服务器工具包

+   我们可以使用无服务器和函数作为服务解决什么问题？

我认为重要的是我们首先要解决房间里的大象，那就是无服务器这个术语。

# 无服务器和函数作为服务

当你对某人说无服务器时，他们首先得出的结论是你在没有任何服务器的情况下运行你的代码。

如果你使用我们将在本章后面讨论的公共云服务之一，这可能是一个相当合理的结论。然而，当在你自己的环境中运行时，你无法避免必须在某种服务器上运行。

在我们讨论无服务器和函数作为服务的含义之前，我们应该讨论我们是如何到达这里的。和我一起工作的人无疑会告诉你，我经常使用“宠物与牛群”这个类比，因为这是一个很容易解释现代云基础设施与更传统方法之间差异的方式。

# 宠物、牛群、鸡、昆虫和雪花

我第一次接触“宠物与牛群”这个类比是在 2012 年，当时 Randy Bias 发布了一份幻灯片。这张幻灯片是在 Randy Bias 在云扩展会议上关于开放和可扩展云的架构的演讲中使用的。在演讲的最后，他介绍了宠物与牛群的概念，Randy 将其归因于当时在微软担任工程师的 Bill Baker。

幻灯片主要讨论的是扩展而不是升级；让我们更详细地讨论一下，并讨论自五年前首次进行演示以来所做的一些补充。

Randy 的幻灯片可以在[`www.slideshare.net/randybias/architectures-for-open-and-scalable-clouds`](https://www.slideshare.net/randybias/architectures-for-open-and-scalable-clouds)找到。

# 宠物

宠物通常是我们作为系统管理员花时间照顾的东西。它们是传统的裸金属服务器或虚拟机：

+   我们像给宠物起名字一样给每台服务器起名字。例如，`app-server01.domain.com`和`database-server01.domain.com`。

+   当我们的宠物生病时，你会把它们带到兽医那里。这很像你作为系统管理员重新启动服务器，检查日志，并更换服务器的故障组件，以确保它正常运行。

+   你多年来一直密切关注你的宠物，就像对待服务器一样。你监视问题，修补它们，备份它们，并确保它们有充分的文档记录。

运行宠物并没有太大问题。然而，你会发现你大部分的时间都花在照顾它们上——如果你有几十台服务器，这可能还可以接受，但如果你有几百台服务器，情况就开始变得难以管理了。

# 牛

牛更能代表你应该在公共云中运行的实例类型，比如**亚马逊网络服务**（**AWS**）或微软 Azure，在那里你启用了自动扩展。

+   你的牛群里有很多牛，你不给它们起名字；相反，它们被编号和标记，这样你就可以追踪它们。在你的实例集群中，你也可能有太多实例需要命名，所以像牛一样，你给它们编号和标记。例如，一个实例可以被称为`ip123067099123.domain.com`，并标记为`app-server`。

+   当你的牛群中的一头生病时，你会射杀它，如果你的牛群需要，你会替换它。同样地，如果你集群中的一个实例开始出现问题，它会被自动终止并替换为一个副本。

+   你不指望牛群中的牛能活得像宠物一样长久，同样地，你也不指望你的实例的正常运行时间能以年为单位。

+   你的牛群生活在一个牧场里，你从远处观察它，就像你不监视集群中的单个实例一样；相反，你监视集群的整体健康状况。如果你的集群需要额外的资源，你会启动更多的实例，当你不再需要资源时，实例会被自动终止，使你回到期望的状态。

# 鸡

2015 年，Bernard Golden 在一篇名为《云计算：宠物、牛和鸡？》的博客文章中，将鸡引入到宠物与牛的比喻中。Bernard 建议将鸡作为描述容器的一个好术语，与宠物和牛并列：

+   鸡比牛更有效率；你可以把更多的鸡放在你的牛群所占用的同样空间里。同样地，你可以在你的集群中放更多的容器，因为你可以在每个实例上启动多个容器。

+   每只鸡在饲养时需要的资源比你的牧群成员少。同样，容器比实例需要的资源更少，它们只需要几秒钟就可以启动，并且可以配置为消耗更少的 CPU 和 RAM。

+   鸡的寿命远低于你的牧群成员。虽然集群实例的正常运行时间可能是几小时到几天，但容器的寿命可能只有几分钟。

不幸的是，伯纳德的原始博客文章已经不再可用。然而，The New Stack 已经重新发布了一篇版本。你可以在[`thenewstack.io/pets-and-cattle-symbolize-servers-so-what-does-that-make-containers-chickens/`](https://thenewstack.io/pets-and-cattle-symbolize-servers-so-what-does-that-make-containers-chickens/)找到重新发布的版本。

# 昆虫

与动物主题保持一致，埃里克·约翰逊为 RackSpace 撰写了一篇介绍昆虫的博客文章。这个术语被用来描述无服务器和函数即服务。

昆虫的寿命远低于鸡；事实上，一些昆虫只有几小时的寿命。这符合无服务器和函数即服务的特点，因为它们的寿命只有几秒钟。

在本章的后面，我们将看一下来自 AWS 和微软 Azure 的公共云服务，这些服务的计费是以毫秒为单位，而不是小时或分钟。

埃里克的博客文章可以在[`blog.rackspace.com/pets-cattle-and-nowinsects/`](https://blog.rackspace.com/pets-cattle-and-nowinsects/)找到。

# 雪花

大约在兰迪·拜斯提到宠物与牛群的讲话时，马丁·福勒写了一篇名为*SnowflakeServer*的博客文章。这篇文章描述了每个系统管理员的噩梦：

+   每片雪花都是独一无二的，无法复制。就像办公室里那台由几年前离开的那个人建造而没有记录的服务器一样。

+   雪花是脆弱的。就像那台服务器一样——当你不得不登录诊断问题时，你会很害怕，你绝对不会想重新启动它，因为它可能永远不会再次启动。

马丁的帖子可以在[`martinfowler.com/bliki/SnowflakeServer.html`](https://martinfowler.com/bliki/SnowflakeServer.html)找到。

# 总结

一旦我解释了宠物、牛群、鸡、昆虫和雪花，我总结道：

“那些拥有**宠物**的组织正在慢慢将他们的基础设施变得更像**牛**。那些已经将他们的基础设施运行为**牛**的人正在向**鸡**转变，以充分利用他们的资源。那些运行**鸡**的人将会考虑将他们的应用程序转变为**昆虫**，通过将他们的应用程序完全解耦成可单独执行的组件来完成。”

最后我这样说：

“没有人想要或者应该运行**雪花**。”

在这本书中，我们将讨论昆虫，我会假设你对覆盖牛和鸡的服务和概念有一些了解。

# 无服务器和昆虫

如前所述，使用“无服务器”这个词会给人一种不需要服务器的印象。无服务器是用来描述一种执行模型的术语。

在执行这个模型时，作为最终用户的你不需要担心你的代码在哪台服务器上执行，因为所有的决策都是由抽象出来的，与你无关——这并不意味着你真的不需要任何服务器。

现在有一些公共云服务提供了如此多的服务器管理抽象，以至于可以编写一个不依赖于任何用户部署服务的应用程序，并且云提供商将管理执行代码所需的计算资源。

通常，这些服务，我们将在下一节中看到，是按每秒执行代码所使用的资源计费的。

那么这个解释如何与昆虫类比呢？

假设我有一个网站，允许用户上传照片。一旦照片上传，它们就会被裁剪，创建几种不同的尺寸，用于在网站上显示缩略图和移动优化版本。

在宠物和牛的世界中，这将由一个 24/7 开机等待用户上传图像的服务器来处理。现在这台服务器可能不只是执行这一个功能；然而，如果几个用户都决定上传十几张照片，那么这将在执行该功能的服务器上引起负载问题。

我们可以采用鸡的方法，跨多台主机运行多个容器来分发负载。然而，这些容器很可能也会全天候运行；它们将会监视上传以进行处理。这种方法可以让我们水平扩展容器的数量来处理请求的激增。

使用昆虫的方法，我们根本不需要运行任何服务。相反，函数应该由上传过程触发。一旦触发，函数将运行，保存处理过的图像，然后终止。作为开发人员，你不需要关心服务是如何被调用或在哪里执行的，只要最终得到处理过的图像即可。

# 公共云服务

在我们深入探讨本书的核心主题并开始使用 Kubernetes 之前，我们应该看看其他选择；毕竟，我们将在接下来的章节中涵盖的服务几乎都是基于这些服务的。

三大主要的公共云提供商都提供无服务器服务：

+   AWS 的 AWS Lambda（[`aws.amazon.com/lambda/`](https://aws.amazon.com/lambda/)）

+   微软的 Azure Functions（[`azure.microsoft.com/en-gb/services/functions/`](https://azure.microsoft.com/en-gb/services/functions/)）

+   谷歌的 Cloud Functions（[`cloud.google.com/functions/`](https://cloud.google.com/functions/)）

这些服务都支持几种不同的代码框架。对于本书的目的，我们不会过多地研究代码框架，因为使用这些框架是一个基于你的代码的设计决策。

我们将研究这两种服务，AWS 的 Lambda 和微软 Azure 的 Functions。

# AWS Lambda

我们要看的第一个服务是 AWS 的 AWS Lambda。该服务的标语非常简单：

“无需考虑服务器即可运行代码。”

现在，那些之前使用过 AWS 的人可能会认为这个标语听起来很像 AWS 的弹性 Beanstalk 服务。该服务会检查你的代码库，然后以高度可扩展和冗余的配置部署它。通常，这是大多数人从宠物到牲畜的第一步，因为它抽象了 AWS 服务的配置，提供了可扩展性和高可用性。

在我们开始启动一个 hello world 示例之前，我们将需要一个 AWS 账户和其命令行工具安装。

# 先决条件

首先，您需要一个 AWS 账户。如果您没有账户，可以在[`aws.amazon.com/`](https://aws.amazon.com/)注册一个账户：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/490eef47-c9e6-4409-b7b3-7152208e8d41.png)

虽然单击“创建免费账户”，然后按照屏幕上的说明将为您提供 12 个月的免费访问多项服务，但您仍然需要提供信用卡或借记卡详细信息，并且可能会产生费用。

有关 AWS 免费套餐的更多信息，请参阅[`aws.amazon.com/free/`](https://aws.amazon.com/free/)。此页面让您了解 12 个月免费服务涵盖的实例大小和服务，以及其他服务的永久优惠，其中包括 AWS Lambda。

一旦您拥有 AWS 账户，您应该使用 AWS **身份和访问管理**（**IAM**）服务创建一个用户。该用户可以拥有管理员权限，您应该使用该用户访问 AWS 控制台和 API。

有关创建 IAM 用户的更多详细信息，请参阅以下页面：

+   **开始使用 IAM**：[`docs.aws.amazon.com/IAM/latest/UserGuide/getting-started.html`](http://docs.aws.amazon.com/IAM/latest/UserGuide/getting-started.html)

+   **IAM 最佳实践**：[`docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html`](http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

不建议使用 AWS 根账户启动服务和访问 API；如果凭据落入错误的手中，您可能会失去对账户的所有访问权限。使用 IAM 而不是您的根账户，并且您还应该使用多因素身份验证锁定根账户，这意味着您将始终可以访问您的 AWS 账户。

最后一个先决条件是您需要访问 AWS 命令行客户端，我将使用 macOS，但该客户端也适用于 Linux 和 Windows。有关如何安装和配置 AWS 命令行客户端的信息，请参阅：

+   **安装 AWS CLI**：[`docs.aws.amazon.com/cli/latest/userguide/installing.html`](http://docs.aws.amazon.com/cli/latest/userguide/installing.html)

+   **配置 AWS CLI**：[`docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html`](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html)

在配置 AWS CLI 时，请确保将默认区域配置为您将在 AWS Web 控制台中访问的区域，因为没有比在 CLI 中运行命令然后在 Web 控制台中看不到结果更令人困惑的事情了。

安装后，您可以通过运行以下命令来测试您是否可以从命令行客户端访问 AWS Lambda：

```
$ aws lambda list-functions
```

这应该返回一个空的函数列表，就像下面的截图中所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/d1ca6867-43ce-4be1-b4c7-fb09317425c5.png)

现在我们已经设置、创建并使用非根用户登录了帐户，并且已经安装和配置了 AWS CLI，我们可以开始启动我们的第一个无服务器函数了。

# 创建 Lambda 函数

在 AWS 控制台中，单击屏幕左上角的“服务”菜单，然后通过使用过滤框或单击列表中的服务来选择 Lambda。当您首次转到 AWS 控制台中的 Lambda 服务页面时，您将看到一个欢迎页面：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/9af2ae92-b7f8-4e06-adb2-7b74b844b5cf.png)

单击“创建函数”按钮将直接进入启动我们的第一个无服务器函数的过程。

创建函数有四个步骤；我们需要做的第一件事是选择一个蓝图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/6383ef38-2b49-4ed2-b030-e618b1dab251.png)

对于基本的 hello world 函数，我们将使用一个名为`hello-world-python`的预构建模板；将其输入到过滤器中，您将看到两个结果，一个是 Python 2.7，另一个使用 Python 3.6：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/d849d4c8-bb1f-4ba1-961f-eca27f408e18.png)

选择`hello-world-python`，然后单击“导出”将为您提供下载用于函数的代码的选项，该代码位于`lambda_function.py`文件中，以及 Lambda 在第 3 步中使用的模板。这可以在`template.yaml`文件中找到。

代码本身非常基本，就像你想象的那样。它除了返回传递给它的值之外什么也不做。如果您没有跟随，`lambda_function.py`文件的内容如下：

```
from __future__ import print_function

import json

print('Loading function')

def lambda_handler(event, context):
  #print("Received event: " + json.dumps(event, indent=2))
  print("value1 = " + event['key1'])
  print("value2 = " + event['key2'])
  print("value3 = " + event['key3'])
  return event['key1'] # Echo back the first key value
  #raise Exception('Something went wrong')
```

`template.yaml`文件包含以下内容：

```
AWSTemplateFormatVersion: '2010-09-09'
Transform: 'AWS::Serverless-2016-10-31'
Description: A starter AWS Lambda function.
Resources:
  helloworldpython:
    Type: 'AWS::Serverless::Function'
    Properties:
      Handler: lambda_function.lambda_handler
      Runtime: python2.7
      CodeUri: .
      Description: A starter AWS Lambda function.
      MemorySize: 128
      Timeout: 3
      Role: !<tag:yaml.org,2002:js/undefined> ''
```

正如您所看到的，模板文件配置了`Runtime`和一些合理的`MemorySize`和`Timeout`值。

要继续到第 2 步，请单击函数名称，对我们来说是`hello-world-python`，您将进入页面，可以选择如何触发函数：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/f5f90a24-fbc4-4ee3-b6b0-99be4319790c.png)

我们暂时不打算使用触发器，我们将在下一个启动的函数中更详细地了解这些内容；所以现在，请单击“下一步”。

第 3 步是我们配置函数的地方。这里有很多信息要输入，但幸运的是，我们需要输入的许多细节已经从我们之前查看的模板中预填充，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/5d6396f6-b222-44b7-95e6-018b1ee71c9f.png)我们需要输入的详细信息如下：带有*的是必填项，斜体中的*信息*是预填充的，可以保持不变。

以下列表显示了所有表单字段及其应输入的内容：

+   基本信息：

+   名称：myFirstFunction

+   描述：一个起始的 AWS Lambda 函数

+   运行时：Python 2.7

+   Lambda 函数代码：

+   代码输入类型：这包含了函数的代码，无需编辑

+   启用加密助手：不选中

+   环境变量：留空

+   Lambda 函数处理程序和角色：

+   处理程序：lambda_function.lambda_handler

+   角色：保持选择“从模板创建新角色”

+   角色名称：myFirstFunctionRole

+   策略模板：我们不需要为此函数使用策略模板，保持空白

将标签和高级设置保持默认值。输入前述信息后，单击“下一步”按钮，进入第 4 步，这是函数创建之前的最后一步。

查看页面上的详细信息。如果您确认所有信息都已正确输入，请单击页面底部的“创建函数”按钮；如果需要更改任何信息，请单击“上一步”按钮。

几秒钟后，您将收到一条消息，确认您的函数已创建：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/0f0cdf16-4af5-47f4-af8e-8ec797b71a31.png)

在上述截图中，有一个“测试”按钮。单击此按钮将允许您调用函数。在这里，您可以自定义发送到函数的值。如下截图所示，我已更改了`key1`和`key2`的值：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/2b2ec257-f2e5-413d-b4e0-0ea12d245b26.png)

编辑完输入后，点击“保存并测试”将存储您更新的输入，然后调用该函数：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/bf6ec9e2-39d9-4b2c-82b3-6d9d4180daa1.png)

点击执行结果消息中的“详细信息”将显示函数被调用的结果以及使用的资源：

```
START RequestId: 36b2103a-90bc-11e7-a32a-171ef5562e33 Version: $LATEST
value1 = hello world
value2 = this is my first serverless function
value3 = value3
END RequestId: 36b2103a-90bc-11e7-a32a-171ef5562e33
```

具有`36b2103a-90bc-11e7-a32a-171ef5562e33` ID 的请求的报告如下：

+   `持续时间：0.26 毫秒`

+   `计费持续时间：100 毫秒`

+   `内存大小：128 MB`

+   `最大内存使用：19 MB`

如您所见，函数运行需要`0.26 毫秒`，我们被收取了最低持续时间`100 毫秒`。函数最多可以消耗`128 MB`的 RAM，但在执行过程中我们只使用了`19 MB`。

返回到命令行，再次运行以下命令会显示我们的函数现在已列出：

```
$ aws lambda list-functions
```

上述命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/05a66f97-617a-4692-88b7-e7ebc8f62aac.png)

我们也可以通过运行以下命令从命令行调用我们的函数：

```
$ aws lambda invoke \
 --invocation-type RequestResponse \
 --function-name myFirstFunction \
 --log-type Tail \
 --payload '{"key1":"hello", "key2":"world", "key3":"again"}' \
 outputfile.txt 
```

如您从上述命令中所见，`aws lambda invoke`命令需要几个标志：

+   `--invocation-type`：有三种调用类型：

+   `RequestResponse`：这是默认选项；它发送请求，在我们的情况下在命令的`--payload`部分中定义。一旦请求被发出，客户端就会等待响应。

+   `事件`：这会发送请求并触发事件。客户端不等待响应，而是会收到一个事件 ID。

+   `DryRun`：这会调用函数，但实际上不执行它——这在测试用于调用函数的详细信息是否具有正确的权限时非常有用。

+   `--function-name`：这是我们要调用的函数的名称。

+   `--log-type`：目前只有一个选项，`Tail`。这返回`--payload`的结果，这是我们要发送给函数的数据；通常这将是 JSON。

+   `outputfile.txt`：命令的最后部分定义了我们要存储命令输出的位置；在我们的情况下，这是一个名为`outputfile.txt`的文件，它被存储在当前工作目录中。

在从命令行调用命令时，您应该会得到以下结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/96133eac-6f74-456c-9e4c-a2b589b39a00.png)

返回到 AWS 控制台并保持在`myFirstFunction`页面上，点击“监控”将呈现有关函数的一些基本统计信息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/7f872ac0-1026-4e5e-ac11-86d1c549ad0a.png)

从前面的图表中可以看出，有关您的函数被调用的次数、所需时间以及是否存在任何错误的详细信息。

单击 CloudWatch 中的查看日志将打开一个列出`myFirstFunction`日志流的新标签页。单击日志流的名称将带您到一个页面，该页面会显示每次函数被调用的结果，包括在 AWS 控制台中进行测试以及从命令行客户端进行调用。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/afe2bb09-fee8-448b-a967-23c0bb79cae9.png)

监控页面和日志在调试 Lambda 函数时非常有用。

# 微软 Azure Functions

接下来，我们将看一下微软的无服务器服务 Azure Functions。微软将这项服务描述为：

"Azure Functions 是一个解决方案，可以轻松在云中运行小段代码或“函数”。您可以仅编写您需要解决的问题的代码，而不必担心整个应用程序或运行它的基础架构。"

与 Lambda 一样，您的 Function 可以通过多种方式被调用。在这个快速演示中，我们将部署一个通过 HTTP 请求调用的 Function。

# 先决条件

您需要一个 Azure 账户来跟随这个示例。如果您没有账户，可以在[`azure.microsoft.com/`](https://azure.microsoft.com/)上注册一个免费账户：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/aaae171e-6f5e-436d-a525-4295a6f8ca25.png)

在撰写本文时，微软向所有新账户提供了 200 美元的 Azure 服务信用额度，就像 AWS 一样，有几项服务有免费套餐。

虽然您可以获得 200 美元的信用额度，但您仍需要提供信用卡详细信息以进行验证。有关免费套餐中的服务和限制的更多信息，请参阅[`azure.microsoft.com/en-gb/free/pricing-offers/`](https://azure.microsoft.com/en-gb/free/pricing-offers/)。

# 创建一个 Function 应用程序

我们将使用基于 Web 的控制面板来创建我们的第一个 Function 应用程序。一旦您拥有了账户，您应该会看到类似以下页面：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/385debf1-c35f-4010-a79c-7b80a48a9a70.png)关于微软 Azure 控制面板的一件事是，它可以水平滚动，因此如果您在页面上迷失了方向，通常可以通过向右滚动找回需要的位置。

如前面的屏幕截图所示，有相当多的选项。要开始创建您的第一个函数，您应该在左侧菜单顶部单击“+新建”。

从这里，您将进入 Azure 市场。单击计算，然后在特色市场项目列表中，您应该看到函数应用程序。单击此处，您将进入一个表单，询问您想要创建的函数的一些基本信息：

+   应用程序名称：随意命名；在我的案例中，我将其命名为`russ-test-version`。这必须是一个唯一的名称，如果您想要的应用程序名称已经被另一个用户使用，您将收到一条消息，告知您所选的应用程序名称不可用。

+   订阅：选择要在其中启动您的函数的 Azure 订阅。

+   资源组：在输入应用程序名称时，这将自动填充。

+   托管计划：将其保留为默认选项。

+   位置：选择离您最近的地区。

+   存储：这将根据您提供的应用程序名称自动填充，为了我们的目的，请保留选择“创建新”。

+   固定到仪表板：选中此项，因为这将使我们能够快速找到我们创建的函数。

如果您没有在您的帐户中跟随，我的完成表格看起来像下面的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/1e5b5baf-6ff7-407a-b73a-274b3d3f9b6e.png)

填写完表格后，单击表单底部的“创建”按钮，您将被带回到您的仪表板。您将收到一个通知，告知您的函数正在部署，如下图右侧的框中所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/7b63fff0-90ee-4180-90ce-27e105345252.png)

单击仪表板中的方框或顶部菜单中的通知（带有数字 1 的铃铛图标）将带您到概述页面；在这里，您可以查看部署的状态：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/f0457e45-0048-4299-b1c0-41d1d882b679.png)

部署后，您应该有一个空的函数应用程序，可以准备将代码部署到其中：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/74c2fe59-1540-45cd-a50a-5495c6cc2b05.png)

要部署一些测试代码，您需要在左侧菜单中的函数旁边单击“+”图标；这将带您到以下页面：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/b3aeb6d1-3b24-4424-936b-54eaa633c4bd.png)

选择 Webhook + API 和 CSharp 后，单击“创建此函数”；这将向您的函数应用程序添加以下代码：

```
using System.Net;

public static async Task<HttpResponseMessage> Run(HttpRequestMessage req, TraceWriter log)
{
    log.Info("C# HTTP trigger function processed a request.");

    // parse query parameter
    string name = req.GetQueryNameValuePairs()
        .FirstOrDefault(q => string.Compare(q.Key, "name", true) == 0)
        .Value;

    // Get request body
    dynamic data = await req.Content.ReadAsAsync<object>();

    // Set name to query string or body data
    name = name ?? data?.name;

    return name == null
        ? req.CreateResponse(HttpStatusCode.BadRequest, "Please pass
        a name on the query string or in the request body")
        : req.CreateResponse(HttpStatusCode.OK, "Hello " + name);
}
```

这段代码简单地读取变量`name`，它通过 URL 传递，然后作为`Hello <name>`打印回给用户。

我们可以通过单击页面顶部的“运行”按钮来测试这一点。这将执行我们的函数，并为您提供输出和日志：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/53a57b86-99be-44f4-8d83-650bbfdfff5f.png)

测试运行的日志如下：

```
2017-09-09T15:28:08 Welcome, you are now connected to log-streaming service.2017-09-09T15:29:07.145 Function started (Id=4db505c2-5a94-4ab4-8e12-c45d29e9cf9c)2017-09-09T15:29:07.145 C# HTTP trigger function processed a request.2017-09-09T15:29:07.176 Function completed (Success, Id=4db505c2-5a94-4ab4-8e12-c45d29e9cf9c, Duration=28ms)
```

您还可以通过单击左侧菜单中的“监视”来查看有关函数应用的更多信息。从以下屏幕截图中可以看出，我们有关于函数调用次数的详细信息，以及每次执行的状态和持续时间：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/17005c7d-9339-4778-9427-4b1d9abc22f5.png)有关函数应用调用的更详细信息，您可以启用 Azure 应用程序洞察，并且有关此服务的更多信息，请参阅[`azure.microsoft.com/en-gb/services/application-insights/`](https://azure.microsoft.com/en-gb/services/application-insights/)。

能够在 Azure 仪表板的安全环境中进行测试是很好的，但是如何直接访问您的函数应用呢？

如果单击 HttpTriggerCSharp1，它将带您回到您的代码，在代码块上方，您将有一个按钮，上面写着“获取函数 URL”，单击此按钮将弹出一个包含 URL 的覆盖框。复制这个：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/a96cb806-1592-4675-9a54-4bc2b686e4b9.png)

对我来说，URL 是：

`https://russ-test-function.azurewebsites.net/api/HttpTriggerCSharp1?code=2kIZUVH8biwHjM3qzNYqwwaP6O6gPxSTHuybdNZaD36cq3HptD5OUw==`

前面的 URL 将不再起作用，因为函数已被移除；它仅用于说明目的，您应该用您的 URL 替换它。

为了在命令行上与 URL 交互，我将使用 HTTPie，这是一个命令行 HTTP 客户端。有关 HTTPie 的更多详细信息，请参阅项目主页[`httpie.org/`](https://httpie.org/)。

使用以下命令在命令行上调用该 URL：

```
$ http "https://russ-test-function.azurewebsites.net/api/HttpTriggerCSharp1?code=2kIZUVH8biwHjM3qzNYqwwaP6O6gPxSTHuybdNZaD36cq3HptD5OUw=="
```

这给我们带来了以下结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/aef3a83d-dab4-475f-90db-e4af340aa111.png)

从返回的内容中可以看出，我们的函数应用返回了 HttpStatusCode BadRequest 消息。这是因为我们没有传递`name`变量。为了做到这一点，我们需要更新我们的命令为：

```
$ http "https://russ-test-function.azurewebsites.net/api/HttpTriggerCSharp1?code=2kIZUVH8biwHjM3qzNYqwwaP6O6gPxSTHuybdNZaD36cq3HptD5OUw==&name=kubernetes_for_serverless_applications"
```

正如您所期望的那样，这将返回正确的消息：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/0c2d6785-a9f2-416e-97e5-0fd4ad62f7f9.png)

您还可以在浏览器中输入 URL 并查看消息：

！[](assets/22f9d26d-137f-4e5c-a743-6677c6e52752.png)

# 无服务器工具包

在完成本章之前，我们将看一下无服务器工具包。这是一个旨在在不同的云提供商之间部署无服务器函数时提供一致体验的应用程序。您可以在[`serverless.com/.`](https://serverless.com/)找到服务的主页。

从主页上可以看到，它支持 AWS 和 Microsoft Azure，以及 Google Cloud 平台和 IBM OpenWhisk。您还会注意到有一个注册按钮；单击此按钮并按照屏幕提示创建您的帐户。

注册后，您将收到一些非常简单的关于如何安装工具和部署第一个应用程序的说明；让我们现在遵循这些。首先，我们需要通过运行来安装命令行工具：

```
$ npm install serverless -g
```

安装将需要几分钟，一旦安装完成，您应该能够运行：

```
$ serverless version
```

这将确认上一个命令安装的版本：

！[](assets/f8a53f70-7d32-454b-9f85-a1af8a3a2a77.png)

现在命令行工具已安装并且我们已确认可以在没有任何错误的情况下获取版本号，我们需要登录。要做到这一点，请运行：

```
$ serverless login
```

此命令将打开一个浏览器窗口，并带您到登录页面，您需要选择要使用的帐户：

！[](assets/0a3f479e-2f81-4efa-b354-2b639b5048c0.png)

如前面的屏幕截图所示，它知道我上次使用 GitHub 帐户登录到无服务器，因此单击这将生成一个验证码：

！[](assets/9617b99a-c9b2-42ed-b3fd-e19630b3cd2d.png)

将代码粘贴到终端提示符中，然后按键盘上的*Enter*键将您登录：

！[](assets/98f434e4-34a5-4944-86b8-bb0e3fc183d3.png)

现在我们已经登录，我们可以创建我们的第一个项目，这将是另一个`hello-world`应用程序。

要在 AWS 中启动我们的`hello-world`函数，我们必须首先创建一个文件夹来保存无服务器工具包创建的工件，并切换到该文件夹；我在我的“桌面”上创建了一个文件夹，使用：

```
$ mkdir ~/Desktop/Serverless
$ cd ~/Desktop/Serverless
```

要生成启动我们的`hello-world`应用程序所需的文件，我们需要运行：

```
$ serverless create --template hello-world
```

这将返回以下消息：

！[](assets/95eebe4f-7ae4-44cb-a4fa-9fbbee44bb72.png)

在我的编辑器中打开`serverless.yml`，我可以看到以下内容（我已删除了注释）：

```
service: serverless-hello-world
provider:
  name: aws
  runtime: nodejs6.10
functions:
  helloWorld:
    handler: handler.helloWorld
    # The `events` block defines how to trigger the handler.helloWorld code
    events:
      - http:
          path: hello-world
          method: get
          cors: true
```

我将服务更新为`russ-test-serverless-hello-world`；您也应该选择一个独特的名称。一旦我保存了更新的`serverless.yml`文件，我就运行了：

```
$ serverless deploy
```

您可能已经猜到，这将`hello-world`应用程序部署到了 AWS：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/28247467-6cf2-4ed2-8c4d-44ae1e7e48f2.png)

使用 HTTPie 访问终端 URL：

```
$ http --body "https://5rwwylyo4k.execute-api.us-east-1.amazonaws.com/dev/hello-world"
```

这将返回以下 JSON：

```
{
    "input": {
        "body": null,
        "headers": {
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "CloudFront-Forwarded-Proto": "https",
            "CloudFront-Is-Desktop-Viewer": "true",
            "CloudFront-Is-Mobile-Viewer": "false",
            "CloudFront-Is-SmartTV-Viewer": "false",
            "CloudFront-Is-Tablet-Viewer": "false",
            "CloudFront-Viewer-Country": "GB",
            "Host": "5rwwylyo4k.execute-api.us-east-1.amazonaws.com",
            "User-Agent": "HTTPie/0.9.9",
            "Via": "1.1 dd12e7e803f596deb3908675a4e017be.cloudfront.net
             (CloudFront)",
            "X-Amz-Cf-Id": "bBd_ChGfOA2lEBz2YQDPPawOYlHQKYpA-
             XSsYvVonXzYAypQFuuBJw==",
            "X-Amzn-Trace-Id": "Root=1-59b417ff-5139be7f77b5b7a152750cc3",
            "X-Forwarded-For": "109.154.205.250, 54.240.147.50",
            "X-Forwarded-Port": "443",
            "X-Forwarded-Proto": "https"
        },
        "httpMethod": "GET",
        "isBase64Encoded": false,
        "path": "/hello-world",
        "pathParameters": null,
        "queryStringParameters": null,
        "requestContext": {
            "accountId": "687011238589",
            "apiId": "5rwwylyo4k",
            "httpMethod": "GET",
            "identity": {
                "accessKey": null,
                "accountId": null,
                "apiKey": "",
                "caller": null,
                "cognitoAuthenticationProvider": null,
                "cognitoAuthenticationType": null,
                "cognitoIdentityId": null,
                "cognitoIdentityPoolId": null,
                "sourceIp": "109.154.205.250",
                "user": null,
                "userAgent": "HTTPie/0.9.9",
                "userArn": null
            },
            "path": "/dev/hello-world",
            "requestId": "b3248e19-957c-11e7-b373-8baee2f1651c",
            "resourceId": "zusllt",
            "resourcePath": "/hello-world",
            "stage": "dev"
        },
        "resource": "/hello-world",
        "stageVariables": null
    },
    "message": "Go Serverless v1.0! Your function executed successfully!"
}
```

在浏览器中输入终端 URL（在我的情况下，我正在使用 Safari）会显示原始输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/9d4a4322-f408-4266-8db3-7f331506ad90.png)

转到`serverless deploy`命令末尾提到的 URL，可以概览您使用 serverless 部署到 Lambda 的函数：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/c4b72966-2f3f-4a82-8996-cedbb2196a46.png)

通过转到[`console.aws.amazon.com/`](https://console.aws.amazon.com/)打开 AWS 控制台，从服务菜单中选择 Lambda，然后切换到您的函数启动的区域；这应该会显示您的函数：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/def45ba0-8167-4302-aea8-fbcdfcd45caf.png)

此时，您可能会想，“我的帐户是如何启动的？我没有提供任何凭据！” 无服务器工具旨在使用与我们在启动第一个 Lambda 函数之前安装的 AWS CLI 相同的凭据-这些凭据可以在您的计算机上的`~/.aws/credentials`找到。

要删除函数，只需运行：

```
$ serverless remove
```

这将删除无服务器工具包在您的 AWS 帐户中创建的所有内容。

有关如何使用无服务器工具包启动 Azure 函数的更多信息，请参阅快速入门指南，该指南可以在[`serverless.com/framework/docs/providers/azure/guide/quick-start/`](https://serverless.com/framework/docs/providers/azure/guide/quick-start/)找到。

# 无服务器和函数作为服务解决的问题

尽管到目前为止我们只启动了最基本的应用程序，但我希望您开始看到使用无服务器如何有助于开发您的应用程序。

想象一下，你有一个 JavaScript 应用程序，它托管在像亚马逊的 S3 服务这样的对象存储中。你的应用程序可以用 React（[`facebook.github.io/react/`](https://facebook.github.io/react/)）或 Angular（[`angular.io/`](https://angular.io/)）编写，这两种技术都允许你使用 JSON 加载外部数据。这些数据可以通过无服务器函数请求和传递 - 结合这些技术可以创建一个应用程序，不仅没有单点故障，而且在使用公共云服务时，是一个真正的*按需付费*应用程序。

由于无服务器函数被执行然后立即终止，你不应该担心它在哪里或者如何执行，只要它执行了。这意味着你的应用程序理论上应该是可伸缩的，也比传统的基于服务器的应用程序更容错。

例如，如果在调用你的一个函数时出现问题，例如，如果它崩溃了或者有资源问题，并且你知道下次调用函数时它将被重新启动，你不需要担心你的代码在有问题的服务器上执行。

# 总结

在本章中，我们快速了解了什么是无服务器，并在 AWS 和 Microsoft Azure 中启动和交互了无服务器函数，还使用了一个名为无服务器的第三方工具，在 AWS 中创建了一个无服务器函数。

到目前为止，你可能已经注意到我们还没有提到 Kubernetes，对于一本名为*用于无服务器应用程序的 Kubernetes*的书来说，这可能有点奇怪。不过不用担心，在下一章中我们将更详细地了解 Kubernetes，一切将变得清晰起来。


# 第二章：Kubernetes 简介

正如前一章末尾提到的，本章将讨论 Kubernetes。我们将讨论：

+   Kubernetes 的简要历史-它从哪里来？

+   它是如何运作的？

+   Kubernetes 的用例是什么，谁在使用它？

+   为什么要在服务器上运行无服务器？

# Kubernetes 的简要历史

在讨论 Kubernetes 的起源之前，我们应该快速讨论一下 Kubernetes 是什么。它的发音是**koo-ber-net****-eez**，有时被称为**K8s**。**Kubernetes**是希腊语，意思是船长或船舵手，考虑到 Kubernetes 的设计目的，这个名字非常贴切。该项目的网站位于[`kubernetes.io/`](https://kubernetes.io/)，描述了它是：

“用于自动化部署、扩展和管理容器化应用的开源系统。”

该项目起源于谷歌内部的一个名为**Borg**的项目。在 Docker 引起轰动之前，谷歌长期使用容器技术。

# 控制组

谷歌自己的容器之旅始于 2006 年，当时他们的两名工程师开始了**控制组**（**cgroups**）项目。这是 Linux 内核的一个功能，可以隔离诸如 RAM、CPU、网络和磁盘 I/O 等资源，以供一组进程使用。cgroups 最初是在 2007 年发布的，在 2008 年初，该功能被合并到 Linux 内核主线版本 2.6.24 中。

您可以在[`kernelnewbies.org/Linux_2_6_24`](https://kernelnewbies.org/Linux_2_6_24)找到 Linux 内核 2.6.24 版本的发布说明。您可以在*重要事项*列表中的*第 10 点*找到有关 cgroups 引入的信息，其中讨论了允许 cgroups 连接到内核的框架。

# lmctfy

几年后的 2013 年 10 月，谷歌发布了他们自己的容器系统的开源版本，名为**lmctfy**，实际上是**Let Me Contain That For You**的缩写。这个工具实际上是他们在自己的服务器上使用的，用于运行 Linux 应用容器，它被设计为 LXC 的替代品。

lmctfy、LXC 和 Docker 都占据着同样的领域。为此，谷歌实际上在 2015 年停止了 lmctfy 的所有开发。该项目的 GitHub 页面上有一则声明，谷歌一直在与 Docker 合作，他们正在将 lmctfy 的核心概念移植到 libcontainer 中。

# Borg

这就是 Borg 项目的由来。谷歌大量使用容器，我说的是*大量*。2014 年 5 月，谷歌的 Joe Beda 在 Gluecon 上做了一个名为*大规模容器*的演讲。演讲中有一些引人注目的引用，比如：

“谷歌所有的东西都在容器中运行。”

而最常谈论的一个是：

“我们每周启动超过 20 亿个容器。”

这相当于每秒大约 3000 个，在演讲中提到，这个数字不包括任何长时间运行的容器。

虽然 Joe 详细介绍了谷歌当时如何使用容器，但他并没有直接提到 Borg 项目；相反，它只是被称为一个集群调度器。

演讲的最后一个要点是题为*声明式优于命令式*的幻灯片，介绍了以下概念：

+   命令式：在那台服务器上启动这个容器

+   声明式：运行 100 个此容器的副本，目标是同时最多有 2 个任务处于停机状态

这个概念解释了谷歌是如何能够每周启动超过 20 亿个容器，而不必真正管理超过 20 亿个容器。

直到 2015 年谷歌发表了一篇名为《谷歌 Borg 的大规模集群管理》的论文，我们才真正了解到了 Joe Beda 在前一年提到的集群调度器的实践和设计决策。

论文讨论了谷歌内部的工具 Borg 是如何运行成千上万的作业的，这些作业几乎构成了谷歌所有应用程序的集群，这些集群由成千上万台机器组成。

然后它揭示了像 Google Mail、Google Docs 和 Google Search 这样的面向客户的服务也都是从 Borg 管理的集群中提供的，以及他们自己的内部工具。它详细介绍了用户可以使用的作业规范语言，以声明他们期望的状态，使用户能够轻松部署他们的应用程序，而不必担心在谷歌基础设施中部署应用程序所需的所有步骤。

我建议阅读这篇论文，因为它很好地概述了谷歌是如何处理自己的容器服务的。

另外，如果你在想，Borg 是以《星际迷航：下一代》电视剧中的外星种族命名的。

# 项目七

2014 年，Joe Beda、Brendan Burns 和 Craig McLuckie 加入了 Brian Grant 和 Tim Hockin 参与了第七号项目。

这个项目以《星际迷航》中的角色“第七号九”命名，旨在制作一个更友好的 Borg 版本。在第一次提交时，该项目已经有了一个外部名称，即 Kubernetes。

你可以在[`github.com/kubernetes/kubernetes/commit/2c4b3a562ce34cddc3f8218a2c4d11c7310e6d56`](https://github.com/kubernetes/kubernetes/commit/2c4b3a562ce34cddc3f8218a2c4d11c7310e6d56)看到第一次提交，第一个真正稳定的版本是在四个月后发布的，可以在[`github.com/kubernetes/kubernetes/releases/tag/v0.4`](https://github.com/kubernetes/kubernetes/releases/tag/v0.4)找到。

最初，Kubernetes 的目标是将谷歌从 Borg 和运行其大型容器集群中学到的一切开源化，作为吸引客户使用谷歌自己的公共云平台的一种方式——这就是为什么你可能仍然会在项目的原始 GitHub 页面上找到对该项目的引用[`github.com/GoogleCloudPlatform/kubernetes/`](https://github.com/GoogleCloudPlatform/kubernetes/)。

然而，到了 2015 年 7 月的 1.0 版本发布时，谷歌已经意识到它已经远远超出了这个范畴，他们加入了 Linux 基金会、Twitter、英特尔、Docker 和 VMware（举几个例子），共同组建了云原生计算基金会。作为这一新合作的一部分，谷歌将 Kubernetes 项目捐赠为新组织的基础。

此后，其他项目也加入了 Kubernetes，比如：

+   Prometheus（[`prometheus.io/`](https://prometheus.io/)），最初由 SoundCloud 开发，是一个可用于存储指标的时间序列数据库。

+   Fluentd（[`www.fluentd.org/`](https://www.fluentd.org/)）是一个数据收集器，允许你从许多不同的来源获取数据，对其进行过滤或规范化，然后将其路由到诸如 Elasticsearch、MongoDB 或 Hadoop（举几个例子）这样的存储引擎。

+   containerd（[`containerd.io/`](http://containerd.io/)）是一个由 Docker 最初开发的开源容器运行时，用于实现 Open Container Initiative 标准。

+   CoreDNS（[`coredns.io/`](https://coredns.io/)）是一个完全基于插件构建的 DNS 服务，这意味着你可以创建传统上配置极其复杂的 DNS 服务。

除此之外，像 AWS、微软、红帽和甲骨文这样的新成员都在支持和为基金会的项目提供资源。

# Kubernetes 概述

现在我们对 Kubernetes 的起源有了一个概念，我们应该逐步了解构成典型 Kubernetes 集群的所有不同组件。

Kubernetes 本身是用 Go 编写的。虽然项目的 GitHub 页面显示该项目目前 84.9%是 Go，其余的 5.8%是 HTML，4.7%是 Python，3.3%是 Shell（其余是配置/规范文件等），都是文档和辅助脚本。

Go 是一种由 Google 开发并开源的编程语言，谷歌将其描述为*一种快速、静态类型、编译语言，感觉像一种动态类型、解释语言*。更多信息，请参见[`golang.org/`](https://golang.org/)。

# 组件

Kubernetes 有两个主要的服务器角色：主服务器和节点；每个角色都由多个组件组成。

主服务器是集群的大脑，它们决定 pod（在下一节中更多介绍）在集群内部部署的位置，并且对集群的健康状况以及 pod 本身的健康状况进行操作和查看。

主服务器的核心组件包括：

+   `kube-apiserver`：这是您的 Kubernetes 控制面板的前端；无论您使用什么来管理您的集群，它都将直接与此 API 服务通信。

+   `etcd`：`etcd`是 Kubernetes 用来存储集群状态的分布式键值存储。

+   `kube-controller-manager`：此服务在后台工作，以维护您的集群。它查找加入和离开集群的节点，确保正在运行正确数量的 pod，并且它们健康等等。

+   `cloud-controller-manager`：这项服务是 Kubernetes 的新功能。它与`kube-controller-manager`一起工作，其目的是与 AWS、Google Cloud 和 Microsoft Azure 等云提供商的 API 进行交互。它执行的任务示例可能是，如果要从集群中删除一个节点，它将检查您的云服务 API，看看节点是否仍然存在。如果存在，则可能会出现问题；如果不存在，则很可能是因为缩放事件而删除了节点。

+   `kube-scheduler`：根据一系列规则、利用率和可用性选择 pod 应该在哪里启动。

接下来我们有节点。一旦部署，主节点与安装在节点上的组件进行交互，以在集群内实现变化；这些是您的 pod 运行的地方。

组成节点的组件有：

+   `kubelet`：这是在节点上运行的主要组件。它负责接受来自主服务器的指令并报告回去。

+   `kube-proxy`：这项服务有助于集群通信。它充当节点上所有网络流量的基本代理，并能够配置 TCP/UDP 转发或充当 TCP/UDP 轮询负载均衡器到多个后端。

+   `docker`或`rkt`：这些是节点上实际的容器引擎。`kubelet`服务与它们交互，以启动和管理运行在集群节点上的容器。在接下来的章节中，我们将看到运行这两种节点的示例。

+   `supervisord`：这个进程管理器和监视器维护着节点上其他服务的可用性，比如`kubelet`、`docker`和`rkt`。

+   `fluentd`：这项服务有助于集群级别的日志记录。

你可能已经注意到，这些服务中唯一提到容器的是`docker`和`rkt`。Kubernetes 实际上并不直接与您的容器交互；相反，它与一个 pod 通信。

# Pods 和服务

正如前面提到的，Kubernetes 不部署容器；相反，它启动 pod。在其最简单的形式中，一个 pod 实际上可以是一个单一的容器；然而，通常一个 pod 由多个容器、存储和网络组成。

以下内容仅供说明，不是一个实际的例子；我们将在下一章中通过一个实际的例子来进行讲解。

把一个 pod 想象成一个完整的应用程序；例如，如果你运行一个简单的 web 应用程序，它可能只运行一个 NGINX 容器——这个 pod 的定义文件将看起来像下面这样：

```
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
  - name: nginx
    image: nginx:latest
    ports:
    - containerPort: 8080
```

正如你所看到的，我们提供了关于我们的 pod 的一些简单元数据，这种情况下只是名称，这样我们就可以识别它。然后我们定义了一个单一的容器，它正在运行来自 Docker hub 的最新 NGINX 镜像，并且端口`8080`是开放的。

就目前而言，这个 pod 是相当无用的，因为我们只打算显示一个欢迎页面。接下来，我们需要添加一个卷来存储我们网站的数据。为了做到这一点，我们的 pod 定义文件将如下所示：

```
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
  - name: nginx
    image: nginx:latest
    volumeMounts:
    - mountPath: /srv/www
      name: web-data
      readOnly: true
    ports:
    - containerPort: 8080
 volumes:
 - name: web-data
 emptyDir: {} 
```

正如你所看到的，我们现在正在创建一个名为`web-data`的卷，并将其以只读方式挂载到`/srv/www`，这是我们 NGINX 容器上的默认网站根目录。但这还是有点毫无意义，因为我们的卷是空的，这意味着我们的所有访问者将只看到一个 404 页面。

让我们添加第二个容器，它将从 Amazon S3 存储桶同步我们网站的 HTML：

```
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
  - name: nginx
    image: nginx:latest
    volumeMounts:
    - mountPath: /srv/www
      name: web-data
      readOnly: true
    ports:
    - containerPort: 8080
  - name: sync
    image: ocasta/sync-s3:latest
    volumeMounts:
    - mountPath: /data
      name: web-data
      readOnly: false
    env:
    - ACCESS_KEY: "awskey"
      SECRET_KEY: "aws_secret"
      S3_PATH: "s3://my-awesome-website/"
      SYNC_FROM_S3: "true"
  volumes:
  - name: web-data
    emptyDir: {}
```

现在我们有两个容器：一个是 NGINX，现在还有一个运行`s3 sync`命令的容器（[`github.com/ocastastudios/docker-sync-s3/`](https://github.com/ocastastudios/docker-sync-s3/)）。这将把我们网站的所有数据从名为`my-awesome-website`的 Amazon S3 存储桶复制到与 NGINX 容器共享的卷中。这意味着我们现在有一个网站；请注意，这一次，因为我们想要写入卷，我们不会将其挂载为只读。

到目前为止，你可能会想到自己；我们有一个从 Amazon S3 存储桶部署的网站服务的 pod，这一切都是真实的。然而，我们还没有完全完成。我们有一个正在运行的 pod，但我们需要将该 pod 暴露给网络，以便在浏览器中访问它。

为了做到这一点，我们需要启动一个服务。对于我们的示例，服务文件看起来可能是这样的：

```
apiVersion: v1
kind: Service
metadata:
  name: nginx-service
spec:
  selector:
    app: nginx
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
```

正如你所看到的，服务定义看起来与 pod 的定义类似。我们使用元数据部分设置名称。然后我们选择我们的 NGINX pod，并将端口`80`映射到端口`8080`，这是我们的 pod 正在侦听的端口。

如前所述，当我们启动第一个 Kubernetes 集群时，我们将在下一章更详细地讨论这个问题，但现在，这应该让你对 Kubernetes 的运作方式有一个很好的了解。

# 工作负载

在上一节中，我们看了 pod 和服务。虽然这些可以手动启动，但你也可以使用控制器来管理你的 pod。这些控制器允许执行不同类型的工作负载。我们将快速看一下不同类型的控制器，还讨论何时使用它们。

# 副本集

ReplicaSet 可用于启动和维护相同 pod 的多个副本。例如，使用我们在上一节中讨论的 NGINX pod，我们可以创建一个 ReplicaSet，启动三个相同 pod 的副本。然后可以在这三个 pod 之间进行负载均衡。

我们的三个 pod 可以分布在多个主机上，这意味着，如果一个主机因任何原因消失，将导致我们的一个 pod 停止服务，它将自动在健康节点上被替换。你还可以使用 ReplicaSet 来自动和手动地添加和删除 pod。

# 部署

您可能会认为使用 ReplicaSet 可以进行滚动升级和回滚。不幸的是，ReplicaSets 只能复制相同版本的 pod；幸运的是，这就是部署的用武之地。

部署控制器旨在更新 ReplicaSet 或 pod。让我们以 NGINX 为例。正如您从以下定义中所看到的，我们有 `3` 个副本都在运行 NGINX 版本 `1.9.14`：

```
apiVersion: apps/v1beta1
kind: Deployment
metadata:
  name: nginx-deployment
spec:
  replicas: 3
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.9.14
        ports:
        - containerPort: 80
```

`kubectl` 是 Kubernetes 的命令行客户端；我们将在下一章中更详细地讨论这个问题。

我们可以使用以下命令进行部署：

```
$ kubectl create -f nginx-deployment.yaml
```

现在假设我们想要更新使用的 NGINX 图像的版本。我们只需要运行以下命令：

```
$ kubectl set image deployment/nginx-deployment nginx=nginx:1.13.5 deployment "nginx-deployment" image updated
```

这将逐个更新每个 pod，直到所有的 pod 都运行新版本的 NGINX。

# StatefulSets

这个控制器是 Kubernetes 中的新功能，旨在取代 PetSets。正如您可能从名称中猜到的那样，pod 作为部署的一部分维护其状态。它们被设计为具有：

+   在整个 pod 生命周期中保持一致的唯一网络标识符

+   持久存储

+   按照您定义的顺序执行的优雅部署和扩展

+   用户定义和控制的自动滚动更新

因此，虽然名称有所变化，但您应该将 StatefulSets 视为宠物，将 ReplicaSets 视为牲畜。

# Kubernetes 使用案例

正如我们在本章中已经提到的，Kubernetes 几乎可以在任何地方运行，从您的本地机器（我们将在下一章中介绍），到您的本地硬件或虚拟机基础设施，甚至可能跨越 AWS、Microsoft Azure 或 Google Cloud 的数百个公共云实例。事实上，您甚至可以在 Kubernetes 集群中跨多个环境。

这意味着无论您在何处运行应用程序，都会获得一致的体验，但也可以利用底层平台的功能，比如负载平衡、持久存储和自动扩展，而无需真正设计应用程序以意识到它是在运行，比如在 AWS 或 Microsoft Azure 上。

阅读成功案例时你会注意到的一个共同点是，人们谈论的是不被锁定在一个特定的供应商上。由于 Kubernetes 是开源的，他们不会被任何许可成本所限制。如果他们遇到问题或想要添加功能，他们可以直接深入源代码进行更改；他们也可以通过拉取请求将他们所做的任何更改贡献回项目中。

另外，正如前面讨论的，使用 Kubernetes 使他们不会被锁定在任何一个特定的平台供应商或架构上。这是因为可以合理地假设 Kubernetes 在安装在其他平台时会以完全相同的方式运行。因此，突然之间，您可以相对轻松地将您的应用程序在不同提供商之间移动。

另一个常见的用例是运维团队将 Kubernetes 用作基础设施即服务（IaaS）平台。这使他们能够通过 API、Web 和 CLI 向开发人员提供资源，这意味着他们可以轻松地融入自己的工作流程。它还为本地开发提供了一个一致的环境，从暂存或用户验收测试（UAT）到最终在生产环境中运行他们的应用程序。

这也是为什么使用 Kubernetes 执行无服务器工作负载是一个好主意的部分原因。您不会被任何一个提供商锁定，比如 AWS 或 Microsoft Azure。事实上，您应该把 Kubernetes 看作是一个云平台，就像我们在第一章中看到的那些；它有一个基于 Web 的控制台，一个 API 和一个命令行客户端。

# 参考资料

关于 Kubernetes 的几个案例研究，用户详细介绍了他们在使用 Kubernetes 过程中的经历：

+   **Wink**：[`kubernetes.io/case-studies/wink/`](https://kubernetes.io/case-studies/wink/)

+   **Buffer**：[`kubernetes.io/case-studies/buffer/`](https://kubernetes.io/case-studies/buffer/)

+   **Ancestry**：[`kubernetes.io/case-studies/ancestry/`](https://kubernetes.io/case-studies/ancestry/)

+   **Wikimedia 基金会**：[`kubernetes.io/case-studies/wikimedia/`](https://kubernetes.io/case-studies/wikimedia/)

还有来自以下内容的讨论、采访和演示：

+   **The New Times**：[`www.youtube.com/watch?v=P5qfyv_zGcU`](https://www.youtube.com/watch?v=P5qfyv_zGcU)

+   蒙佐：[`www.youtube.com/watch?v=YkOY7DgXKyw`](https://www.youtube.com/watch?v=YkOY7DgXKyw)

+   高盛：[`blogs.wsj.com/cio/2016/02/24/big-changes-in-goldmans-software-emerge-from-small-containers/`](https://blogs.wsj.com/cio/2016/02/24/big-changes-in-goldmans-software-emerge-from-small-containers/)

最后，您可以在[`www.cncf.io/`](https://www.cncf.io/)了解更多关于 Cloud Native Computing Foundation 的信息。

# 总结

在这一章中，我们谈到了 Kubernetes 的起源，并介绍了一些其使用案例。我们还了解了一些基本功能。

在下一章中，我们将通过在本地安装 Minikube 来亲自体验 Kubernetes。一旦我们安装好了本地的 Kubernetes，我们就可以继续进行第四章，“介绍 Kubeless 功能”，在那里我们将开始在 Kubernetes 上部署我们的第一个无服务器函数。


# 第三章：本地安装 Kubernetes

在本章中，我们将看看如何使用 Minikube 快速搭建本地的 Kubernetes 安装。一旦我们的本地 Kubernetes 安装运行起来，我们将学习一些基本功能，并讨论在本地运行 Kubernetes 的局限性。我们将学习在以下平台上安装 Kubernetes：

+   macOS 10.13 High Sierra

+   Windows 10 专业版

+   Ubuntu 17.04

在我们开始安装之前，让我们快速看一下我们将使用的工具来部署我们的本地 Kubernetes 集群。

# 关于 Minikube

当你阅读上一章时，你可能会想到 Kubernetes 看起来很复杂。有很多组件需要配置，而且不仅需要配置，还需要监控和管理。

我记得当我最初看 Kubernetes 时，它刚发布不久，安装说明非常长，而且事情有点儿棘手。

在安装过程的开始阶段误读了一步，你可能会在安装过程的后期陷入麻烦——这让我想起了以前杂志上会包含游戏代码清单的情形。如果你在任何地方打错字，那么事情要么根本不起作用，要么会出现意外崩溃。

随着 Kubernetes 的成熟，安装过程也在不断改进。相当快地，一些辅助脚本被开发出来，以帮助在各种平台上启动 Kubernetes；Minikube 就是其中之一。

它的工作就是创建一个本地的 Kubernetes 节点。考虑到 Kubernetes 支持的功能范围，它有令人惊讶的多种功能，比如：

+   DNS，NodePorts 和 Ingress

+   ConfigMaps 和 Secrets

+   容器运行时的选择；你可以使用 Docker 或 rkt

+   通过`hostPath`持久卷

+   仪表板

通常需要公共云提供商（如 AWS，Microsoft Azure 或 Google Cloud）或多个主机的 Kubernetes 功能是不受支持的。其中一些功能包括：

+   负载均衡器

+   高级调度策略

这是因为 Minikube 只在本地 PC 上的虚拟机上启动单个节点。但这不应该限制你；请记住，你只会想要在 Minikube 上进行开发，并且不应该使用它构建生产服务。还有很多其他工具，将在第六章中介绍，*在云中安装 Kubernetes*，更适合在公共云或其他供应商中启动生产就绪的 Kubernetes 集群。

Minikube 由两个核心组件组成：

+   **libmachine**：这个来自 Docker 的库用于在主机上提供虚拟机。它是 Docker Machine 以及 Docker for macOS 和 Docker for Windows 的核心组件。

+   **localkube**：这个库是由 Redspread（现在是 CoreOS 的一部分）开发并捐赠给 Minikube 项目的，它负责在启动虚拟机后部署和维护 Kubernetes 节点。

不再讨论 Minikube 能做什么，我们应该看看如何安装它，然后讨论如何与它交互。

# 安装 Minikube

我们将看看如何在介绍中提到的三种不同操作系统上安装 Minikube。一旦安装完成，与 Minikube 交互的过程大部分是一致的，这意味着，虽然我在示例中使用的是 macOS，但相同的命令也适用于 Windows 和 Linux。考虑到早期 Kubernetes 安装和配置过程的复杂性，你会惊讶地发现现在的过程是多么简单。

# macOS 10.13 High Sierra

要在 macOS 上安装 Minikube，你首先必须安装 Homebrew 和 Cask。

Homebrew 是 macOS 的基于命令行的软件包管理器。Homebrew 用于安装命令行工具和 Cask，Cask 是一个用于管理桌面应用程序的附加组件。它非常有用，可以管理 macOS 应用商店中不可用的软件，同时也可以避免你在自己的机器上手动编译软件。

如果你还没有安装 Homebrew，你可以通过运行以下命令来安装它：

```
$ /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

安装完成后，你需要通过运行以下命令来安装 Cask：

```
$ brew install cask
```

如果你已经安装了 Homebrew 和 Cask，那么你应该确保一切都是最新的，并且准备好使用以下命令运行：

```
$ brew update
$ brew doctor
```

一旦 Homebrew 和 Cask 准备好，你可以通过运行以下命令来安装 Minikube：

```
$ brew cask install minikube
```

首先会下载依赖项，然后安装 Minikube：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/464c27fa-0f16-4e69-ad1e-b1199b8d33ab.png)

该过程不到一分钟，安装完成后，您应该能够执行以下操作：

```
$ minikube version
```

这将显示当前版本；在我的情况下，这是`v0.22.2`。我们现在已经安装并准备好使用 Minikube 了。

# Windows 10 专业版

与我们在 macOS 上安装 Minikube 的方式类似，我们将使用一个包管理器；这次叫做 Chocolatey。

Chocolatey 是 Windows 的一个包管理器，类似于 macOS 上的 Homebrew。它使您能够从命令行安装软件，并支持 PowerShell 和`cmd.exe`。我们将使用 PowerShell。

如果您没有安装 Chocolatey，可以在以管理员权限启动的 PowerShell 控制台中运行以下命令：

以下命令是一行，而不是多行。另外，由于我们使用`Set-ExecutionPolicy Bypass`来运行安装命令，您将被询问是否确定。由于我们直接从 Chocolatey 网站通过 HTTPS 运行脚本，您应该能够信任该脚本并回答是。

```
$ Set-ExecutionPolicy Bypass; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
```

安装了 Chocolatey 后，您可以通过运行以下命令来安装 Minikube：

```
$ choco install minikube
```

这将下载并安装依赖项，然后安装 Minikube。当您被要求确认是否要运行脚本时，请回答是：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/7bee2b97-fc9e-4958-8396-3d9f9622162c.png)

安装后，您将能够运行以下命令：

```
$ minikube version
```

这将返回安装的 Minikube 版本；对我来说，这是`v0.22.2`。

# Ubuntu 17.04

与 macOS 和 Windows 版本不同，我们将不会使用包管理器在 Ubuntu 17.04 上安装 Minikube。相反，我们将直接从项目页面下载二进制文件。要做到这一点，只需运行以下命令：

```
$ curl -Lo minikube https://storage.googleapis.com/minikube/releases/v0.22.2/minikube-linux-amd64 && chmod +x minikube && sudo mv minikube /usr/local/bin/
```

Minikube 将被下载，将设置执行权限，并将移动到`/usr/local/bin/`，以便在系统路径中。

现在 Minikube 已安装，我们需要下载`kubectl`。在 macOS 和 Windows 安装过程中，这是由包管理器处理的；幸运的是，这个过程与我们刚刚运行以安装 Minikube 的命令几乎相同：

```
$ curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl && chmod +x ./kubectl && sudo mv ./kubectl /usr/local/bin/kubectl
```

安装后，您应该能够再次运行以下命令来确认安装的 Minikube 版本：

```
$ minikube version
```

当我运行该命令时，它返回`v0.22.2`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/a69b796f-ae90-4574-929c-81543ba288e1.png)

# Hypervisors

Minikube 支持多种不同的 hypervisors。 Hypervisor 是一个用于启动虚拟机的进程；它将虚拟机的操作系统与您自己的操作系统隔离开来，同时允许它共享 CPU、RAM 和磁盘空间等资源。

Minikube 默认支持以下 hypervisors：

+   **Hyper-V（Windows 10）**：这是本机 hypervisor；它适用于 Windows 10 专业版和 Windows 服务器

+   **KVM（Ubuntu 17.04）**：这是本机 Linux hypervisor，在大多数现代发行版的 Linux 内核中运行

+   **VirtualBox（macOS，Windows 10 和 Ubuntu 17.04）**：由 Oracle 发布，VirtualBox 是一个开源的 x86 hypervisor，可以在大量操作系统上运行

+   **VMware Fusion（macOS）**：Fusion 提供了一个经过优化的 macOS hypervisor，其最大优势是能够在 macOS 上运行和公开 Windows 应用程序

+   **xhyve（macOS）**：这是 macOS 上的本机 hypervisor；就像 Linux 上的 KVM 一样，它内置在内核中

从列表中可以看出，在本章中我们涵盖的三种操作系统中，只有 VirtualBox 得到支持。因此，它是 Minikube 支持的默认 hypervisor。如果您已经安装了 VirtualBox，可以运行以下与您选择的操作系统相关的命令。

对于 macOS，我们可以使用 Homebrew 和 Cask 来安装 VirtualBox：

```
$ brew cask install virtualbox
```

同样，对于 Windows 10，您可以使用 Chocolatey 来安装 VirtualBox：

如果启用了 Hyper-V，则无法在 Windows 10 上使用 VirtualBox。如果您希望跟随操作，请在继续之前禁用 Hyper-V。

```
$ choco install virtualbox
```

最后，对于 Ubuntu 17.04，您需要运行以下命令来添加存储库和密钥：

```
$ wget -q http://download.virtualbox.org/virtualbox/debian/oracle_vbox.asc -O- | sudo apt-key add -
$ sudo sh -c 'echo "deb http://download.virtualbox.org/virtualbox/debian $(lsb_release -sc) contrib" >> /etc/apt/sources.list'
```

然后运行以下命令来加载我们之前添加的存储库并安装软件包：

```
$ sudo apt-get update
$ sudo apt-get install virtualbox-5.1
```

现在您应该能够在列出的软件程序中看到 Virtualbox。

# 启动 Minikube

要完成我们的安装，我们需要启动 Minikube。要做到这一点，请运行以下命令：

```
$ minikube start
```

在 macOS 上，您应该看到类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/d38cb49c-8985-428f-b2aa-1050efa97202.png)

如您所见，用于创建虚拟机的 ISO 已经下载。虚拟机启动，我们将用于对我们的单节点集群进行身份验证的证书被生成，最后`kubectl`被配置为使用我们本地 Kubernetes 集群的详细信息。

在 Windows 10 上运行相同的命令将得到完全相同的步骤：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/f674dbe4-9477-4a5f-b435-8cc7595b4028.png)

另外，正如您可能已经猜到的那样，在 Ubuntu 17.04 上运行会得到相同的结果。运行以下命令：

```
$ minikube status
```

您将收到一条消息，确认一切正常运行，并且 `kubectl` 已正确配置以与您的 Kubernetes 集群通信：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/9d82313e-556f-4a63-acd5-9a313debb3fa.png)

如果您打开 VirtualBox，您应该会看到您的 Minikube 虚拟机正在运行；例如，当我在 Windows 10 上打开 VirtualBox 时就是这种情况：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/9f35164d-8dc0-4b4d-b7ce-c0e8f17eb985.png)

尽管我们在三种不同的操作系统上启动了 Minikube，除了初始安装之外，您已经可以体验我们在第二章中讨论的内容了：没有供应商锁定和一致的体验，而且这是在我们开始使用新安装的 Kubernetes 集群之前。

# Minikube 命令

到目前为止，我们已经使用了 `minikube start` 和 `minikube status` 命令来启动我们的单节点 Kubernetes 集群，并检查一切是否按预期运行。在我们开始与 Kubernetes 交互之前，我想介绍一些更基本的 Minikube 命令。

# 停止和删除

由于我们将我们的单节点 Kubernetes 集群作为虚拟机在您的主机上运行，您可能不希望它一直运行，占用资源。

有两种选项可以实现这一点，第一种是 `minikube stop`。这个命令将停止您的节点，并保持虚拟机完整。如果您计划在下次通过运行 `minikube start` 启动节点时继续之前的工作，您应该使用这个命令。

虽然 `minikube stop` 命令会停止您的虚拟机在主机上使用 CPU 和 RAM 资源，但用于托管虚拟机的硬盘映像仍将存在于您的机器上。虽然新启动的集群不会占用主机硬盘上太多空间，在我的 macOS 安装中大约为 650 MB；一旦您开始使用集群，您可能会发现这个空间至少会翻倍。

这就是我们下一个命令发挥作用的地方。`minikube delete` 命令将完全删除集群，包括所有虚拟机文件，释放主机机器上使用的空间。

在写作时，运行`minikube delete`将立即删除您的虚拟机，无论其是否正在运行。不会有提示询问您是否确定，也没有从该命令返回的方法（除非您有备份），因此请确保谨慎使用此命令。

当您再次运行`minikube start`时，您的集群将从头开始启动，就像我们在上一节中首次体验到的那样。

# 环境

接下来，我们有一些命令，显示有关虚拟机的信息，以及 Minikube 在您的设备上配置的环境。

首先，我们有一个非常简单的命令`minikube ip`。这个命令只是返回虚拟机的 IP 地址。如果您想通过脚本与集群交互，这将非常有用。您可以包含命令的输出，以引用集群的当前 IP 地址，而无需在脚本中硬编码实际的 IP 地址。

我们要看的下一个命令是`minikube docker-env`。运行此命令应该会在屏幕上打印出类似以下输出：

```
$ minikube docker-env
export DOCKER_TLS_VERIFY="1"
export DOCKER_HOST="tcp://192.168.99.101:2376"
export DOCKER_CERT_PATH="/Users/russ/.minikube/certs"
export DOCKER_API_VERSION="1.23"
# Run this command to configure your shell:
# eval $(minikube docker-env)
```

输出的作用是允许您（如果已安装）配置本地 Docker 客户端与 Minikube 虚拟机上的 Docker 安装进行通信。然而，这样做也有一个缺点。目前作为 Minikube 虚拟机镜像的一部分分发的 Docker 版本略落后于当前版本。您可以通过运行`eval $(minikube docker-env)`，然后`docker version`来查看这一点。当我运行这两个命令时，得到了以下结果：

```
$ eval $(minikube docker-env)
$ docker version
Client:
 Version: 17.06.2-ce
 API version: 1.23
 Go version: go1.8.3
 Git commit: cec0b72
 Built: Tue Sep 5 20:12:06 2017
 OS/Arch: darwin/amd64

Server:
 Version: 1.12.6
 API version: 1.24 (minimum version )
 Go version: go1.6.4
 Git commit: 78d1802
 Built: Wed Jan 11 00:23:16 2017
 OS/Arch: linux/amd64
 Experimental: false
```

从输出中可以看出，写作时 Minikube 使用的 Docker 版本比我在 macOS 上安装的最新稳定版本要落后两个版本。在本书涵盖的内容范围内，运行旧版本的 Docker 并不是问题，也不需要担心，因为我们不会直接与其交互。

# 虚拟机访问和日志

您可以通过 SSH 登录到 Minikube 虚拟机。在安装过程中，生成了一个 SSH 密钥，并在启动时与虚拟机共享。您可以通过运行`minikube ssh-key`来检查此密钥的位置。这将返回密钥的私钥部分的路径。您可以将其与其他命令结合使用，在 macOS 或 Ubuntu 上运行以下命令来 SSH 登录到虚拟机：

```
$ ssh docker@$(minikube ip) -i $(minikube ssh-key)
```

这将动态生成虚拟机的 IP 地址和私钥路径:

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/a0e42ee1-c47f-44a0-ba3f-1d2b969475e3.png)

然而，Minikube 还有一个命令可以为您运行这个命令，并且在所有平台上都受支持。运行`minikube ssh`将直接将您登录到虚拟机作为 Docker 用户，如下面的终端输出所示:

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/69225215-9ba9-4975-b5bc-1f538d51071e.png)

我们要快速查看的最后一个命令是`minikube logs`。这会显示`localkube`实例生成的所有日志:

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/1956e512-f65d-4800-842d-f1273ce6aaee.png)

这些日志用于帮助调试您的 Minikube 安装中的问题。它们不包含任何用户数据，这意味着您不能使用它们来帮助跟踪您启动的服务或 pod 的任何问题。

# 你好世界

现在我们的单节点 Kubernetes 集群已经运行起来了，使用 Minikube，我们可以尝试启动一个服务。我们将首先使用仪表板，然后再转向命令行客户端。

# 仪表板

每个 Minikube 安装都带有一个基于 Web 的仪表板。这可以通过运行`minikube dashboard`来访问，它会立即在您的默认浏览器中打开仪表板:

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/37f69f3b-f34e-44b7-9570-875ab2ca69ae.png)

点击页面左上角的+创建按钮，将带您到一个表单，让您部署一个容器化应用程序。

在部署容器化应用页面上，您会找到几个选项。保持启用下面的指定应用程序详细信息选项，填写如下:

+   应用名称: `dashboard-hello-world`

+   容器镜像: `nginx:latest`

+   **Pod 数量**: `1`

+   **服务**: 外部

+   **端口**: `8080`

+   **目标端口**: `80`

+   **协议**: TCP

对于我们的目的，我们不需要填写在“显示高级选项”下找到的任何选项。只需点击表单底部的“部署”按钮。过一会儿，您的仪表板应该显示您有一个部署、pod、ReplicaSet 和服务，所有这些都带有`dashboard-hello-world`的名称:

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/0d41bef9-a797-4ac8-8f1c-da8812423e57.png)

您可以通过运行以下命令查看服务:

```
$ minikube service dashboard-hello-world
```

这将返回以下消息:

```
Opening kubernetes service default/dashboard-hello-world in default browser...
```

打开您的浏览器，在那里您应该看到默认的 NGINX 页面:

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/43019ac6-951f-4e28-8783-8e0e48aba3da.png)

虽然这只是一个非常基本的例子，但它确实展示了使用仪表板启动简单应用程序有多简单。现在让我们看看如何转移到命令行。

# 命令行

在上一章中，我们简要介绍了如何使用 YAML 或 JSON 文件来定义您的 pod、ReplicaSets 和服务。让我们使用`kubectl`来启动一个与前一个应用程序相同的应用程序。

首先，我们需要一个要启动的文件；您可以在本书的代码包和 GitHub 存储库的`Chapter03`文件夹中找到名为`cli-hello-world.yml`的副本：

```
apiVersion: v1
kind: Service
metadata:
  name: cli-hello-world
spec:
  selector:
    app: cli-hello-world
  type: NodePort
  ports:
  - protocol: TCP
    port: 8000
    targetPort: 80
---
apiVersion: apps/v1beta1
kind: Deployment
metadata:
  name: cli-hello-world
  labels:
    app: nginx
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cli-hello-world
  template:
    metadata:
      labels:
        app: cli-hello-world
    spec:
      containers:
      - name: nginx
        image: nginx:latest
        ports:
        - containerPort: 80
```

您可能已经注意到，虽然这是一个单独的文件，但实际上我们有两个不同的部分。第一个启动外部服务，在端口`8000`上公开它，以便与我们在上一节使用仪表板启动的外部服务不发生冲突。第二部分定义了 pod 和复制集；这与我们使用仪表板启动的内容非常相似。

要启动应用程序，我们只需要运行以下命令：

```
$ kubectl apply -f cli-hello-world.yml
```

您几乎立即会收到已创建服务和部署的确认：

```
service "cli-hello-world" created
deployment "cli-hello-world" created
```

创建后，您应该能够运行以下命令在浏览器中打开应用程序：

```
$ minikube service cli-hello-world
```

再次，您应该会看到默认的 NGINX 页面。

我相信当我们打开仪表板时，您点击了页面左侧可以找到的菜单项。所有这些信息也可以在命令行中找到，所以让我们简要地看一下我们可以使用的一些命令来了解有关我们集群的更多信息。

您将要运行的更常见的命令之一是`kubectl get`。这将获取 pod、ReplicaSets 和服务的列表，以及更多内容。运行以下命令应该给我们一个类似于仪表板概述的视图：

```
$ kubectl get pods
$ kubectl get replicasets
$ kubectl get services
$ kubectl get secrets
```

正如您从以下终端输出中所看到的，所有内容都列出了其当前状态：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/64c2e209-fa24-4d47-8db3-6b99d1cfa9e7.png)

您可以获得很多选项；例如，尝试运行这个：

```
$ kubectl get endpoints
$ kubectl get events
$ kubectl get storageclasses
```

只运行`kubectl get`将列出您可以使用的所有不同参数。现在我们有了完整的 pod 名称，在我的情况下是`cli-hello-world-3678853705-f41d2`，我们可以通过运行`kubectl describe`命令来了解更多关于它的细节。例如，我运行了这个：

```
$ kubectl describe pods/cli-hello-world-3678853705-f41d2
```

当您在本地运行命令时，请更新 pod 名称以反映您自己的名称。Kubernetes 在启动时为每个 pod 添加一个唯一 ID，以确保您可以在任何给定的主机上运行多个相同的 pod。

我得到了以下信息：

```
Name: cli-hello-world-3678853705-f41d2
Namespace: default
Node: minikube/192.168.99.100
Start Time: Sun, 08 Oct 2017 10:41:06 +0100
Labels: app=cli-hello-world
 pod-template-hash=3678853705
Annotations: kubernetes.io/created-by={"kind":"SerializedReference","apiVersion":"v1","reference":{"kind":"ReplicaSet","namespace":"default","name":"cli-hello-world-3678853705","uid":"ce7b2030-ac0c-11e7-9136-08002...
Status: Running
IP: 172.17.0.5
Created By: ReplicaSet/cli-hello-world-3678853705
Controlled By: ReplicaSet/cli-hello-world-3678853705
Containers:
 nginx:
 Container ID: docker://0eec13c8340b7c206bc900a6e783122cf6210561072b286bda10d225ffb3c658
 Image: nginx:latest
 Image ID: docker-pullable://nginx@sha256:af32e714a9cc3157157374e68c818b05ebe9e0737aac06b55a09da374209a8f9
 Port: 80/TCP
 State: Running
 Started: Sun, 08 Oct 2017 10:41:09 +0100
 Ready: True
 Restart Count: 0
 Environment: <none>
 Mounts:
 /var/run/secrets/kubernetes.io/serviceaccount from default-token-v563p (ro)
Conditions:
 Type Status
 Initialized True
 Ready True
 PodScheduled True
Volumes:
 default-token-v563p:
 Type: Secret (a volume populated by a Secret)
 SecretName: default-token-v563p
 Optional: false
QoS Class: BestEffort
Node-Selectors: <none>
Tolerations: <none>
Events:
 Type Reason Age From Message
 ---- ------ ---- ---- -------
 Normal Scheduled 31m default-scheduler Successfully assigned cli-hello-world-3678853705-f41d2 to minikube
 Normal SuccessfulMountVolume 31m kubelet, minikube MountVolume.SetUp succeeded for volume "default-token-v563p"
 Normal Pulling 31m kubelet, minikube pulling image "nginx:latest"
 Normal Pulled 31m kubelet, minikube Successfully pulled image "nginx:latest"
 Normal Created 31m kubelet, minikube Created container
 Normal Started 31m kubelet, minikube Started container
```

您可以使用 `kubectl describe` 查找几乎可以使用 `kubectl get` 列出的所有信息，例如：

```
$ kubectl describe services/cli-hello-world
$ kubectl describe replicasets/cli-hello-world-3678853705
$ kubectl describe storageclasses/standard
```

同样，您可以通过仅运行`kubectl describe`来了解更多信息。在接下来的章节中，我们将介绍更多命令，以便在本书结束时，您将能够充分利用`kubectl`。

在完成本章之前，我希望我们能够快速看一下如何将存储从本地机器挂载到 Minikube 虚拟机内部，然后再挂载到我们的 pod 内部。

您将在`Chapter03`文件夹中找到一个名为`html`的文件夹。其中包含一个名为`index.html`的单个文件。在`Chapter03`文件夹中运行以下命令将挂载 HTML 到虚拟机内部：

```
$ minikube mount ./html:/data/html
```

您可以从运行命令后显示的消息中看到这一点：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/393608e8-b7ce-4f2f-9d89-eb992e934f2e.png)在撰写本文时，已知在 Windows 10 主机上使用`minikube mount`命令存在一个已知的 bug，请参阅以下 GitHub 问题以获取更多信息[`github.com/kubernetes/minikube/issues/1473`](https://github.com/kubernetes/minikube/issues/1473)和[`github.com/kubernetes/minikube/issues/2072`](https://github.com/kubernetes/minikube/issues/2072)。

您需要保持此进程运行，因此在本节的其余部分中打开一个新的终端或 PowerShell 窗口以供使用。

运行以下命令：

```
$ minikube ssh
$ ls -lhat /data/html/
$ exit
```

这些命令将使您登录到 Minikube 虚拟机，获取`/data/html/`的目录列表，然后退出虚拟机：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/bb20fd7e-b2c3-481b-ace5-9d98ee7191b6.png)

如您所见，我们的`index.html`文件在`/data/html/`中的集群节点上可用。返回到`Chapter03`文件夹，您应该会看到一个名为`cli-hello-world-storage.yml`的文件。其中包含使用此挂载文件夹的服务和部署信息。

服务部分看起来与本节中先前使用的很相似；但是，在部署部分有一个额外的内容：

```
apiVersion: apps/v1beta1
kind: Deployment
metadata:
  name: cli-hello-world-storage
  labels:
    app: nginx
spec:
  replicas: 1
  selector:
    matchLabels:
      app: cli-hello-world-storage
  template:
    metadata:
      labels:
        app: cli-hello-world-storage
    spec:
      volumes:
      - name: html
        hostPath:
          path: /data/html
      containers:
      - name: nginx
        image: nginx:latest
        ports:
        - containerPort: 80
        volumeMounts:
        - mountPath: /usr/share/nginx/html
          name: html
```

正如您所看到的，在部署的`spec`部分中，我们现在正在定义一个名为`html`的`volume`，然后在容器部分中，我们正在使用`mountPath`选项将名为`html`的卷挂载到`/usr/share/nginx/html`，这是我们在容器中使用的 NGINX 容器映像的默认网页根目录。

使用`kubectl apply`命令启动您的应用程序，然后使用`minikube service`命令在浏览器中打开服务：

```
$ kubectl apply -f cli-hello-world-storage.yml
$ minikube service cli-hello-world-storage
```

您应该看到以下页面：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/eddcda5f-6a0b-4d40-aaeb-e07d3e1d3fe1.png)

如果您在本地机器上的`html`文件夹中编辑`index.html`，当您刷新浏览器窗口时，更改将立即反映出来。

在我们进入下一章之前，我们应该删除本章中使用的 Minikube 虚拟机，以便我们从头开始。首先，我们有一个进程，它正在保持我们主机机器上的`html`文件夹挂载。要终止此进程，请返回到终端或 PowerShell 并按下*Ctrl* + *C*；这将向进程发送终止信号并将您返回到命令行。然后我们可以运行：

```
$ minikube delete
```

这将删除当前的虚拟机，这意味着当我们下次启动 Minikube 时，它将从头开始。

# 参考资料

有关本章中使用的工具的更多信息，请访问它们的项目页面：

+   **Minikube**: [`github.com/kubernetes/minikube`](https://github.com/kubernetes/minikube)

+   **kubectl**: [`kubernetes.io/docs/user-guide/kubectl-overview/`](https://kubernetes.io/docs/user-guide/kubectl-overview/)

+   **Homebrew**: [`brew.sh/`](https://brew.sh)

+   **Cask**: [`caskroom.github.io/`](https://caskroom.github.io/)

+   **Chocolatey**: [`chocolatey.org/`](https://chocolatey.org/)

+   **VirtualBox**: [`www.virtualbox.org/`](https://www.virtualbox.org/)

# 总结

在本章中，我们使用 Minikube 在本地机器上安装了单节点 Kubernetes 集群；我们看了如何在 macOS、Windows 10 和 Ubuntu Linux 上实现这一点。一旦安装完成，我们发现无论我们的本地机器运行哪个操作系统，我们都可以以完全相同的方式与我们的单节点 Kubernetes 集群进行交互。

然后，我们首次启动了 Pods、ReplicaSets 和服务，使用了 Kubernetes 仪表板和名为`kubectl`的 Kubernetes 命令行客户端。

在下一章中，我们将在我们目前在本地运行的单节点 Kubernetes 集群上启动我们的第一个无服务器工具，名为 Kubeless。


# 第四章：介绍 Kubeless 功能

现在我们的 Kubernetes 安装已经运行起来了，我们可以开始运行我们的第一个无服务器应用程序；我们将通过一些示例来安装和运行 Kubeless。我们将涵盖以下主题：

+   安装 Kubeless

+   Kubeless 概述

+   使用 Kubeless 运行我们的第一个函数-“hello world”示例

+   更高级的示例-发布推文

+   无服务器插件

让我们开始在我们的三个目标操作系统上安装 Kubeless。

# 安装 Kubeless

Kubeless 有两个组件；第一个是在 Kubernetes 上运行的堆栈，第二部分是您用来与 Kubeless 集群交互的命令行客户端。

我们首先将看看如何让 Kubeless 在 Kubernetes 上运行起来。一旦运行起来，我们将看看如何在我们的三个目标操作系统上安装命令客户端。

# Kubeless Kubernetes 集群

我们将在上一章中安装和配置的单节点 Minikube 集群上安装 Kubeless。我们需要做的第一件事是确保我们从一个干净的 Kubernetes 安装开始。为此，我们只需要运行以下两个命令：

请记住，运行`minikube delete`命令将立即删除当前正在运行的虚拟机，而不会发出警告，这意味着您的 Minikube 单节点集群上当前活动的所有内容都将丢失。

```
$ minikube delete
$ minikube start
```

现在我们的新的单节点 Kubernetes 集群已经运行起来了，我们需要通过运行以下命令为 Kubeless 创建一个命名空间：

```
$ kubectl create ns kubeless
```

然后通过运行以下命令安装 Kubeless 本身：

在撰写本文时，Kubeless 的当前版本是 v0.2.3。您可以在项目的 GitHub 发布页面[`github.com/kubeless/kubeless/releases`](https://github.com/kubeless/kubeless/releases)上检查最新版本。要安装更新版本，只需在以下 URL 中使用更新的版本号，但请注意，不同版本之间的输出可能会有所不同。

```
$ kubectl create -f https://github.com/kubeless/kubeless/releases/download/v0.2.3/kubeless-v0.2.3.yaml
```

如您所见，这将创建并启动在您的单节点 Kubernetes 集群上运行 Kubeless 所需的所有组件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/512c4f3f-0ccb-4f15-bfa7-b0ab993f6409.png)

一切启动需要一些时间。您可以通过运行以下命令来检查每个组件的状态：

```
$ kubectl get pods -n kubeless
$ kubectl get deployment -n kubeless
$ kubectl get statefulset -n kubeless
```

这应该会显示类似以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/8e0de3e0-f560-4245-9dd8-d45588db224a.png)

或者，您也可以使用 Kubernetes 仪表板来检查状态。要做到这一点，运行以下命令打开仪表板：

```
$ minikube dashboard
```

当仪表板首次打开时，它被配置为显示默认命名空间，因为我们执行的第一个命令创建了一个名为`kubeless`的新命名空间。我们需要切换到`kubeless`命名空间以查看其中部署的 Pods、Deployments 和 Stateful Sets。

一旦您更改了命名空间，您应该在以下页面上看到一些内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/5ffd6926-4594-4952-b813-e93a474da322.png)

正如您所看到的，我们只用两个命令就部署了一组相当复杂的服务。所有繁重的工作和复杂性都已完全抽象化。

# 命令行客户端

现在 Kubeless 已经安装在我们的单节点 Kubernetes 集群上，我们可以考虑安装命令行客户端；这是我们将与我们的 Kubeless 集群进行交互的方式。

# macOS 10.13 High Sierra

由于我们已经在上一章安装了 Homebrew，我们将使用`brew`命令来安装 Kubeless。为此，我们需要添加 Kubeless tap；tap 是一个包含软件安装说明的第三方存储库。一旦 tap 被添加，我们就可以以与我们在第二章中安装 Minikube 相同的方式安装 Kubeless。

要安装 tap，然后安装 Kubeless 命令行客户端，请运行以下两个命令：

```
$ brew tap kubeless/tap
$ brew install kubeless
```

安装完成后，您可以通过运行以下命令来检查已安装的客户端的版本：

```
$ kubeless version
```

如果这返回的客户端版本与您安装的软件不同，不要太担心；这不应该是一个问题。

# Windows 10 专业版

不幸的是，Kubeless 没有可用的 Chocolatey 安装程序，因此我们必须手动下载和解压可执行文件。要在 PowerShell 中执行此操作，请运行以下命令：

```
$ Invoke-WebRequest -Uri https://github.com/kubeless/kubeless/releases/download/v0.2.3/kubeless_windows-amd64.zip -Outfile C:\Temp\kubeless_windows-amd64.zip
$ expand-archive -path 'C:\Temp\kubeless_windows-amd64.zip' -destinationpath 'C:\Temp\kubeless_windows-amd64'
$ Move-Item C:\Temp\kubeless_windows-amd64\bundles\kubeless_windows-amd64\kubeless.exe .\
```

或者，您可以从 Kubeless 发布页面下载`kubeless_windows-amd64.zip`文件。下载后，解压`.zip`文件，并将`kubeless.exe`文件放在我们可以执行它的位置。从包含您的`kubeless.exe`文件的文件夹运行以下命令：

```
$ ./kubeless version
```

这将返回命令行客户端的版本。

# Ubuntu 17.04

就像 Windows 10 版本的 Kubeless 命令行客户端一样，我们需要下载发布版本，解压缩并将可执行文件移动到指定位置。要做到这一点，请运行以下命令：

```
$ curl -Lo /tmp/kubeless.zip https://github.com/kubeless/kubeless/releases/download/v0.2.3/kubeless_linux-amd64.zip
$ unzip /tmp/kubeless.zip -d /tmp
$ chmod +x /tmp/bundles/kubeless_linux-amd64/kubeless
$ sudo mv /tmp/bundles/kubeless_linux-amd64/kubeless /usr/local/bin/
```

最后，为了检查可执行文件是否按预期工作，请运行：

```
$ kubeless version
```

我们已经准备好在我们的 Ubuntu Linux 主机上使用 Kubeless。

# Kubeless Web 界面

在我们继续之前，我们还可以安装 Kubeless 的 Web 界面。就像 Kubeless 本身一样，只需运行以下命令即可轻松安装：

```
$ kubectl create -f https://raw.githubusercontent.com/kubeless/kubeless-ui/master/k8s.yaml
```

然后，您可以使用 Minikube 运行以下命令在浏览器中打开服务：

```
$ minikube service ui --namespace kubeless
```

从上述命令中可以看出，由于`ui`服务已部署在`kubeless`命名空间中，我们需要通过传递`--namespace`标志来让 Minikube 知道这是服务的访问位置。Kubeless Web 界面可能需要几分钟才能启动，但当它启动时，您应该会看到一个类似以下内容的页面：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/c568edd3-5b21-4002-8ad7-8b60e540fdc8.png)

# Kubeless 概述

在开始使用 Kubeless 部署无服务器函数之前，我们应该花点时间来了解一下我们刚刚安装的内容，并查看在使用 Kubeless 命令行客户端时可用的命令。

正如我们已经提到的，安装过程非常简单——在我们的单节点 Kubernetes 集群上安装 Kubeless 时，安装过程基本上是一样的，即使我们在由多个节点组成的 Kubernetes 上安装它也是如此。

# 那么，什么是 Kubeless 呢？

Kubeless 是一个支持在 Kubernetes 集群上部署无服务器函数的框架，它允许您使用 HTTP 和事件触发器来执行 Python、Node.js 或 Ruby 代码。该框架是使用核心 Kubernetes 功能构建的，如部署、服务、ConfigMaps 等。这使得 Kubeless 的代码库很小，并且意味着开发人员不必重复大量的调度逻辑，因为它已经存在于 Kubernetes 核心中。

它通过利用 Kubernetes 控制器来工作。使用控制器，Kubeless 开发人员已扩展了 Kubernetes API，以在 Kubernetes 中添加一个函数对象。 Kubeless 控制器作为部署在 Kubernetes 集群中运行，其主要工作是监视函数端点的调用。当调用端点时，将执行包含函数代码的运行时；这些是预构建的 Docker 镜像，用于包装您的函数，使用 ConfigMaps 注入到 Kubernetes 集群中的 Apache Kafka 消费者或 HTTP 服务器中，您可以像调用任何其他网页一样调用它们。

Apache Kafka 是一个分布式流平台，让您可以发布和订阅信息流。在我们的情况下，这个信息流是触发的事件，Kubeless 控制器订阅了这个事件。

所有这些意味着我们可以在我们运行的单节点集群中获得与我们在第一章 *无服务器景观*中涵盖的 AWS 和 Microsoft Azure 的无服务器服务类似的体验，包括我们本地运行的 Kubernetes 集群。

# 谁创造了 Kubeless？

Kubeless 是由 Bitnami（[`bitnami.com/`](https://bitnami.com/)）创建的，它是他们编写并开源支持将应用程序轻松部署到 Kubernetes 集群的几个项目之一。

Bitnami 多年来一直是分发预打包的开源和商业支持许可应用的领导者，在撰写本文时有超过 140 个应用程序，以可预测和一致的方式跨多个不同平台和公共云进行分发和支持，因此支持和开发 Kubernetes 对他们来说是一个自然的选择。

他们是 Helm 的核心贡献者，与微软和谷歌一起，Helm 是由 Cloud Native Computing Foundation 论坛维护的 Kubernetes 的包管理器，我们知道来自第二章 *Kubernetes 简介*。

您可以在[`kubeless.io/`](http://kubeless.io/)找到 Kubeless 网站。

# Kubeless 命令

Kubeless 命令行客户端有几个命令。在我们使用 Kubeless 在 Kubernetes 上启动我们的第一个无服务器函数之前，我们应该快速讨论一些我们将要使用的命令。

我们将要使用的最常见的命令是`kubeless function`。这允许我们`部署`、`删除`、`编辑`和`列出`函数。此外，我们可以通过使用`call`执行我们的函数，并检查`日志`。

接下来，我们有`kubeless ingress`；使用此命令，我们可以`创建`、`删除`和`列出`到我们函数的路由。

最后，我们还将看一下`kubeless topic`；与`ingress`一样，它允许我们`创建`、`删除`和`列出`主题，以及向主题`发布`消息。

# Hello world

首先，我们将看一下部署两个非常简单的 hello world 函数。第一个简单地打印`Hello World!`，第二个接受输入，然后将其显示回给你。

# 基本示例

首先，我们需要我们的函数。静态的 hello-world 函数需要以下三行 Python 代码：

```
import json
def handler():
    return "Hello World!"
```

将前面的代码放在名为`hello.py`的文件中，该文件也可以在伴随本书的 GitHub 存储库的`Chapter04/hello-world`文件夹中找到。

现在我们有了我们的函数，我们可以通过运行以下命令将其部署到默认命名空间中：

```
$ kubeless function deploy hello \
 --from-file hello.py
 --handler hello.handler \
 --runtime python2.7 \
  --trigger-http
```

此命令创建一个名为`hello`的函数，使用文件`hello.py`。每当执行名为`hello.handler`的函数时，我们使用`python2.7`运行时，并且我们的函数被设置为由`http`请求触发。

您可能已经注意到，当您运行命令时，没有任何反馈，所以要检查函数是否已创建，您可以运行以下命令：

```
$ kubeless function ls
```

在前面的命令中有几列：

+   `名称`：这是函数的名称

+   `命名空间`：函数部署到的命名空间的名称

+   `处理程序`：要运行的处理程序的名称—在我们的情况下，处理程序只是处理程序，因此它正在调用`hello-world.handler`

+   `运行时`：Kubeless 支持的每种语言都有单独的运行时

+   `类型`：这是函数被调用的方式，在我们的情况下这是 HTTP

+   `主题`：如果我们订阅消息队列，这将是我们要观察消息的主题

另外，正如前一节中提到的，Kubeless 将函数对象添加到 Kubernetes 中。您可以运行以下命令来检查我们的函数是否被列在函数对象中：

```
$ kubectl get functions
```

通过这些命令运行应该会给您一些类似以下结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/a065e896-8db8-4d0e-ac06-292efb0e4dc5.png)

现在我们的函数已部署，我们可以执行它。要运行此操作，请运行：

```
$ kubeless function call hello
```

这将产生以下结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/fae35d98-a824-4619-a8bf-4312b2459612.png)

我们调用函数的另一种方式是使用 Kubeless Web 界面。通过运行以下命令打开它：

```
$ minikube service ui --namespace kubeless
```

打开后，您应该在左侧列出函数`hello`。单击`hello`将显示函数中的代码，并且右侧有一个标有 RUN FUNCTION 的按钮；单击此按钮将执行`hello`函数并返回`Hello World!`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/a103d7d4-d225-44d4-8d1e-bd34376d9930.png)

我们与函数交互的最终方式是创建 Ingress 规则；但是，在执行此操作之前，我们必须在 Minikube 中启用 Ingress 插件。要执行此操作，请运行以下命令：

```
$ minikube addons enable ingress
```

现在 Ingress 插件已启用，我们需要使用 Kubeless 创建 Ingress 路由。要执行此操作，我们只需要运行以下命令：

```
$ kubeless ingress create --function hello hello-ingress
```

我们需要知道 Kubeless 创建的主机，以便访问我们的服务。要执行此操作，请运行以下命令：

```
$ kubeless ingress ls
```

这将提供有关我们创建的 Ingress 路由的信息，包括我们将能够使用的主机来访问该服务。对我来说，这是`http://hello.192.168.99.100.nip.io/`。

`nip.io`是一个简单且免费的 DNS 服务，允许您创建 DNS 记录将您的主机映射到 IP 地址。Kubeless 使用此服务创建有效的主机以路由到您的服务。

在我的浏览器中打开此 URL 返回`Hello World!`，通过 HTTPie 运行它也是如此，我们在第一章中介绍了 HTTPie，您可以从以下终端输出中看到：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/0a40f91c-d6bb-4622-96ab-8228c1f9c878.png)

现在我们的第一个函数已经运行起来了，让我们看看如何创建一个可以传递并打印数据的函数。

# 读取数据的示例

我们的新函数代码仍然非常简单：

```
import json

def handler(context):
    print context.json
    return context.json
```

此代码的全部作用只是接收我们发布的 JSON 并将其显示给我们。将其放入名为`hello-name.py`的文件中，或者使用 GitHub 存储库中`Chapter04/hello-world/`文件夹中的文件。一旦有了文件，您可以通过运行以下命令创建函数：

```
$ kubeless function deploy hello-name \
 --from-file hello-name.py \
 --handler hello-name.handler \
 --runtime python2.7 \
 --trigger-http
```

部署函数后，通过运行以下命令检查是否已创建：

```
$ kubeless function ls
```

您应该看到列出了两个函数，`hello`和`hello-name`。现在我们已经创建了新函数，可以通过运行以下命令来调用它：

```
$ kubeless function call hello-name --data '{ "name": "Russ" }'
```

请注意，这次我们使用`--data`标志将数据传递给函数。运行所有命令后，您应该看到类似以下终端输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/a6639d16-6ca1-4734-8002-583e1e08b50d.png)

在使用 Web 界面调用函数时，我们还需要传递数据。要做到这一点，再次打开界面，运行：

```
$ minikube service ui --namespace kubeless
```

打开后，点击`hello-name`函数。在点击 RUN FUNCTION 按钮之前，使用下拉菜单将 GET 更改为 POST，并在请求表单中输入以下内容：

```
{ "name": "Russ" }
```

现在，点击 RUN FUNCTION 按钮。这将返回与`kubeless function call`命令相同的结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/74229f95-2b2a-4338-ac02-95f7175eb8a6.png)

我们还可以通过配置 Ingress 路由直接与服务交互：

```
$ kubeless ingress create --function hello-name hello-name-ingress
$ kubeless ingress list
```

这将为我们的两个函数提供 URL：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/04cb951e-861b-40c9-a279-b68696db2150.png)

与我们的第一个示例不同，转到`hello-name`的 URL，对我来说是`http://hello-name.192.168.99.100.nip.io/`，将会显示错误：500 内部服务器错误（或在 Kubeless 的后续版本中，显示 504 网关超时）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/041b574c-34fc-4f43-91af-fba1f8cc17e5.png)

为什么会这样，尽管我们使用`kubeless function call`命令和 Kubeless Web 界面调用时都没有错误？

通过简单地将 URL 输入到浏览器中，我们没有发布任何数据供函数返回；这就是为什么会生成错误的原因。我们可以通过检查日志来确认这一点。要做到这一点，刷新浏览器中的页面几次，然后运行以下命令：

```
$ kubeless function logs hello-name
```

您应该看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/28667ea3-e6f4-40fa-9d03-ace20d7eb60d.png)

前面日志输出的第一行是内部健康检查，它是成功的，因为生成了`200`状态，您可以在`GET`之后看到。接下来的几行包含我们要查找的错误；正如您所看到的，我们得到了`Traceback`，然后是以下内容：`TypeError: handler() takes exactly 1 argument (0 given)`。这意味着函数期望传递数据，但没有传递。下一行是来自我们浏览器的请求；正如您在`GET`之后看到的，有一个`500`的状态。

那么，我们如何与需要 POST 数据而不是 GET 的函数进行交互呢？在 macOS 和 Linux 命令行上，您可以通过几种方式实现这一点，但在 Windows 上，您将不得不运行其他东西。与其通过不同的示例来工作，我要安装一个名为 Postman 的软件。这个桌面软件适用于我们在书中涵盖的所有三种操作系统，并且它将为我们与`hello-name`函数以及我们启动的任何其他函数进行交互提供一个很好的图形界面。

要在 macOS 10.13 High Sierra 上使用 Homebrew 安装 Postman，只需运行：

```
$ brew cask install postman
```

Postman 有一个 Chocolatey 软件包，因此如果您使用的是 Windows 10 专业版，可以运行：

```
$ choco install postman
```

要在 Ubuntu 17.04 上安装 Postman，我们需要运行一些额外的步骤。首先，我们需要下载、解压缩并移动文件到指定位置，确保清理和移动我们需要的文件。为此，请运行以下命令：

```
$ wget https://dl.pstmn.io/download/latest/linux64 -O postman.tar.gz
$ sudo tar -xzf postman.tar.gz -C /opt
$ rm postman.tar.gz
$ sudo ln -s /opt/Postman/Postman /usr/bin/postman
```

现在我们已经将文件放在了正确的位置，我们可以通过运行以下命令为它们创建一个桌面启动器：

```
$ cat > ~/.local/share/applications/postman.desktop <<EOL
[Desktop Entry]
Encoding=UTF-8
Name=Postman
Exec=postman
Icon=/opt/Postman/resources/app/assets/icon.png
Terminal=false
Type=Application 
Categories=Development;
EOL
```

创建了启动器后，您应该在已安装软件列表中看到一个 Postman 图标出现。

现在我们已经安装了 Postman，打开它，您将看到一个屏幕，询问您是否要注册。如果您愿意注册或不注册，完全取决于您；该服务是免费的，如果您需要测试向 API 发送数据，您会发现它非常有用。一旦您通过了注册或登录选项，您将看到一个类似以下的屏幕：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/a7b780ee-1998-41a4-b4b1-a82103f989b9.png)

点击 BUILDING BLOCKS 下的 Request 选项；这将带您进入保存对话框。在这里，输入`hello-name`的请求名称，然后点击+Create Collection。在这里，创建一个名为`Kubeless`的集合，然后点击 Save to Kubeless 按钮。

首先，使用下拉菜单将 GET 更改为 POST，然后在标有输入请求 URL 的空格中输入`http://hello-name.192.168.99.100.nip.io`（或者如果不同的话，输入您的 URL）。现在我们已经定义了我们将要发布我们的数据，我们需要实际给 Postman 传递需要传递给我们的函数的数据。

要输入数据，请单击 Body，然后选择原始选项。当您选择原始选项时，输入字段将发生变化，您应该看到单词 Text 和旁边的下拉图标。单击这个图标，然后选中 JSON（application/json）选项。一旦更改，输入以下内容到主字段中：

```
{
  "name": "Russ" 
}
```

现在 Postman 已经配置为将 JSON 数据发送到我们的函数，您可以单击发送。这将发布我们定义的数据，然后在屏幕底部显示结果，以及 HTTP 状态和请求执行所需的时间，就像下面的截图一样：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/68e8d681-0794-4ad0-851a-e9aadfcd7179.png)

单击保存按钮将保存设置，如果您想重新运行它们的话。

在我们继续下一节之前，我们应该整理一下我们的函数。要做到这一点，我们只需要运行：

```
$ kubeless ingress delete hello
$ kubeless function delete hello
$ kubeless ingress delete hello-name
$ kubeless function delete hello-name
```

这将删除我们的两个 hello world 函数和 Ingress 路由。您还可以在 Kubeless web 界面和 Kubernetes 仪表板中再次检查是否已删除了所有内容；您可以通过运行以下命令打开它们：

```
$ minikube service ui --namespace kubeless
$ minikube dashboard
```

如果您发现任何剩余的内容，无论是`hello`还是`hello-name`，您都可以从仪表板中删除服务、pod，甚至 Ingress 路由。

# Twitter 示例

Kubeless GitHub 账户有一些更多的示例应用程序，这些应用程序不仅可以打印静态内容或转发您发送的数据。在这个例子中，我们将看看如何创建一个可以发布到 Twitter 账户的函数。

# Twitter API

在我们看如何启动函数之前，我们需要为我们的函数生成密钥，以便对 Twitter 进行身份验证，然后发布到您的账户。为此，您需要以下内容：

+   Twitter 账户

+   与账户注册的手机号码

如果您有它们，那么前往 Twitter 应用程序页面[`apps.twitter.com/`](https://apps.twitter.com/)将为您呈现一个表格（应用程序详情）-我使用了以下信息。然而，一些字段需要对您来说是唯一的；这些字段用*标记：

+   名称*：`MedialGlassesKubeless`

+   描述：`使用 Kubeless 测试发布到 Twitter`

+   网站*：`https://media-glass.es/`

+   回调 URL：留空

+   开发者协议：同意协议

填写完上述信息后，点击“创建 Twitter 应用”按钮。创建应用程序后，您将被带到一个页面，允许您管理您的应用程序。页面上的一个选项卡是“密钥和访问令牌”；点击这个选项卡将显示您的消费者密钥（API 密钥）和消费者秘钥（API 秘钥）—请记下这些信息。

在页面底部，您将有一个按钮，允许您为您的帐户创建访问令牌和访问令牌秘钥；点击按钮将生成这些令牌—再次，请记下这些信息。

虽然以下示例将包含我生成的密钥，但它们已被撤销，您应该使用您自己的密钥。此外，由于它们允许对您的 Twitter 帐户进行读写访问，将它们存储在 GitHub、Gists 或其他版本控制软件等公开可访问的地方可能导致第三方未经您的许可就完全访问您的 Twitter 帐户。

# 将秘密添加到 Kubernetes

现在我们已经配置了 Twitter 应用程序，并且拥有了发布推文所需的所有令牌，我们需要将它们添加到 Kubernetes 中。Kubernetes 允许您定义秘密；这些是您的应用程序需要使用的 API 密钥和令牌等变量。但是，您可能不希望将它们放在源代码控制下或嵌入到您的应用程序中，因为相同代码的各种部署使用不同的密钥与 API 进行交互—例如，代码的开发版本使用与生产版本不同的 API 凭据。

要添加前一节中记下的令牌，您只需要运行以下命令，用您的令牌和密钥替换大写的占位符：

```
$ kubectl create secret generic twitter \
 --from-literal=consumer_key=YOUR_CONSUMER_KEY \ 
 --from-literal=consumer_secret=YOUR_CONSUMER_SECRET \
 --from-literal=token_key=YOUR_TOKEN_KEY \
 --from-literal=token_secret=YOUR_TOKEN_SECRET
```

对我来说，命令看起来像下面这样：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/2ac31d01-3e2b-44d6-a10e-408be3e438ef.png)

这样就创建了一个名为`twitter`的秘密，其中包含我们传递给命令的四个不同的键和令牌。您可以通过运行以下命令来列出这些秘密：

```
$ kubectl get secret
```

这将列出您的 Kubernetes 集群中的所有秘密，如下面终端输出所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/03d530ba-27c4-4586-9c23-169891138d84.png)

这里有默认的 Kubernetes 服务账户令牌，包含三个项目，以及我们的`twitter`秘密，其中包含四个键和令牌。您也可以在 Kubernetes 仪表板中查看秘密：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/46a1520c-fa01-4080-a3ec-a937485a8ce8.png)

从前面的屏幕截图中可以看出，您还可以通过单击眼睛图标来显示秘密。

# Twitter 函数

现在我们的环境准备好了，我们可以部署函数了。为此，我们需要两个文件；第一个是`requirements.txt`文件，其中只包含两行：

```
python-twitter
kubernetes==2.0.0
```

`requirements.txt`文件让 Python 知道要与我们的代码一起部署的外部库。在我们的文件中，我们使用`twitter`库，以便可以轻松地发布推文，还使用`kubernetes`库来解码我们在上一节中创建的秘密。使用这些库意味着我们的代码非常简化，因为所有的繁重工作都发生在我们的核心函数之外。函数的代码如下：

```
import base64
import twitter

from kubernetes import client, config

config.load_incluster_config()

v1=client.CoreV1Api()

for secrets in v1.list_secret_for_all_namespaces().items:
    if secrets.metadata.name == 'twitter':
        consumer_key = base64.b64decode(secrets.data['consumer_key'])
        consumer_secret = base64.b64decode(secrets.data['consumer_secret'])
        token_key = base64.b64decode(secrets.data['token_key'])
        token_secret = base64.b64decode(secrets.data['token_secret'])

api = twitter.Api(consumer_key=consumer_key,
                  consumer_secret=consumer_secret,
                  access_token_key=token_key,
                  access_token_secret=token_secret)

def handler(context):
    msg = context.json
    status = api.PostUpdate(msg['tweet'])
```

将此内容放入名为`tweet.py`的文件中。与以前一样，`requirements.txt`和`tweet.py`文件都可以在 GitHub 存储库`Chapter04/twitter/`中找到。

部署函数的命令在部署命令中有一个附加项。由于我们现在正在加载外部库，我们需要让 Kubeless 知道我们想要使用`requirements.txt`文件，方法是添加`--dependencies`标志：

```
$ kubeless function deploy twitter \
 --from-file tweet.py \
 --handler tweet.handler \
 --runtime python2.7 \
 --trigger-http \
 --dependencies requirements.txt
```

从以下终端输出中可以看出，在运行`kubeless function list`命令时现在列出了依赖项：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/4c4fc377-f38c-451e-acc6-46969dfaecdd.png)

现在我们的函数已经部署，我们可以开始发推文了。要发送我们的第一条推文，您只需运行以下命令：

```
$ kubeless function call twitter --data '{"tweet": "Testing twitter function from Kubeless!"}'
```

您将不会收到任何反馈，但如果您转到您的 Twitter 帐户，您应该会看到这条推文：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/66f521f6-717a-432b-8c15-7906e6aeafba.png)

您还可以使用 Postman 发送推文。首先，通过运行以下命令创建一个 Ingress 路由：

```
$ kubeless ingress create --function twitter twitter-ingress
$ kubeless ingress list
```

这将创建路由并给我们提供访问函数所需的主机：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/f9daa0b6-64d2-49e3-9500-58b2440ec5ac.png)

现在我们可以打开 Postman，并且像以前一样配置它，但是这个文件将以下内容作为发布内容：

```
{
  "tweet": "Testing twitter function from Kubeless using @postmanclient!"
}
```

单击发送将发布推文，并且与使用`kubeless function call`命令调用函数时一样，不会给我们任何反馈：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/2be50eb1-e057-423c-a3e1-d817773ba022.png)

检查 Twitter 应该会显示第二条推文，这次提到了`@postmanclient`。您可以在以下 URL 查看我的两条测试推文：

+   命令行推文：[`twitter.com/mediaglasses/status/922036070954536960`](https://twitter.com/mediaglasses/status/922036070954536960)

+   Postman 推文：[`twitter.com/mediaglasses/status/922038490883346432`](https://twitter.com/mediaglasses/status/922038490883346432)

再次，在继续下一部分之前，我们应该删除我们的函数并整理一下：

```
$ kubeless function delete twitter
$ kubeless ingress delete twitter-ingress
$ kubectl delete secret twitter
```

另外，如果需要的话，你应该返回[`apps.twitter.com/`](https://apps.twitter.com/)并删除或撤销你的应用程序或令牌。

# Kubeless 无服务器插件

回到第一章，*无服务器景观*，我们安装了 Serverless 框架来部署 AWS Lambda 函数；无服务器也适用于 Kubeless。

如果你还没有安装无服务器，这里是如何在我们正在涵盖的三个操作系统上安装它的快速回顾。

尽管已经尽一切努力确保以下说明适用于所有支持的平台，但由于插件所需的一些依赖项的兼容性问题，Kubeless 无服务器插件在*基于 Windows 的*操作系统上的运行成功程度有所不同。

对于 macOS 10.13 High Sierra，运行以下命令使用 Homebrew 安装 Node.js：

```
$ brew install node
```

如果你正在使用 Windows 10 专业版，你可以通过运行 Chocolatey 来安装 Node.js：

```
$ choco install nodejs
```

最后，如果你使用的是 Ubuntu 17.04，你可以使用以下命令安装 Node.js：

```
$ curl -sL https://deb.nodesource.com/setup_8.x | sudo -E bash -
$ sudo apt-get install -y nodejs
```

现在最新版本的 Node.js 已安装，我们可以使用**Node Package Manager** (**NPM**)通过运行以下命令来安装无服务器：

```
$ npm install -g serverless
```

一旦无服务器安装完成，你可以使用以下命令登录：

```
$ serverless login
```

现在无服务器已安装，我们可以通过运行以下命令启动演示 Kubeless 函数：

```
$ serverless create --template kubeless-python --path new-project
$ cd new-project
$ npm install
```

如果你没有跟着做，运行这些命令会得到以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/ae272daf-8510-4fb1-acbc-c650f0d9ed05.png)

这安装了 Kubeless 无服务器插件并创建了定义我们函数的`serverless.yml`文件。其中包含以下内容：

```
service: new-project

provider:
  name: kubeless
  runtime: python2.7

plugins:
  - serverless-kubeless

functions:
  hello:
    handler: handler.hello
```

正如你所看到的，这段代码告诉无服务器我们正在使用 Kubeless，并且它应该使用 Kubeless 插件。它还定义了一个名为`hello`的函数和处理程序。该函数可以在`handler.py`文件中找到。这包含以下代码，与我们在本章前面看过的 hello-world 示例非常相似：

```
import json

def hello(request):
    body = {
        "message": "Go Serverless v1.0! Your function executed successfully!",
        "input": request.json
    }

    response = {
        "statusCode": 200,
        "body": json.dumps(body)
    }

    return response
```

现在我们有了示例函数，我们可以通过运行以下命令部署服务：

```
$ serverless deploy -v
```

服务部署完成后，最后一步是部署函数本身。要做到这一点，请运行：

```
$ serverless deploy function -f hello
```

使用无服务器本身来调用函数可能会导致以下错误，如果出现这种情况，不要担心：

```
$ serverless invoke --function hello --data '{"Kubeless": "Welcome!"}' -l
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/46e38a11-2f63-4841-9dcb-0ec381c9ca39.png)

您仍然可以使用 Kubeless 访问该函数：

```
$ kubeless function list
$ kubeless function call hello --data '{"Kubeless": "Welcome!"}'
```

这将返回预期的结果：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/a30409ea-a28b-4d16-9225-c73774c79b6f.png)

要删除示例函数，请运行以下命令：

```
$ serverless remove
```

在完成本章之前，让我们看一个使用事件而不是 HTTP 的示例。在 GitHub 存储库的`Chapter04/serverless-event/`文件夹中，有一个监听事件的示例应用程序。

`serverless.yml`文件与之前的 HTTP 示例不同，除了处理程序外，还添加了一个包含触发器/主题的事件部分：

```
service: events

provider:
  name: kubeless
  runtime: python2.7

plugins:
  - serverless-kubeless

functions:
  events:
    handler: handler.events
    events:
      - trigger: 'hello_topic'
```

`handler.py`文件可能包含迄今为止我们所看到的最简单的代码：

```
def events(context):
    return context
```

要启动示例，只需从`Chapter04/serverless-event/`文件夹中运行以下命令：

```
$ npm install
$ serverless deploy -v
$ kubeless function list
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/0aca75c4-1e13-4c4c-8507-4b3900c3aacc.png)

从前面的终端输出中可以看出，我们有一个`PubSub`类型和一个`hello_topic`主题。现在我们可以通过运行以下命令在`hello_topic`主题中发布事件：

```
$ kubeless topic publish --topic hello_topic --data 'testing an event!'
$ kubeless topic publish --topic hello_topic --data 'and another event!'
```

最后，我们可以通过运行日志来检查这两个事件是否已经被处理：

```
$ serverless logs -f events
```

从以下输出中可以看出，事件已成功发布并由我们的测试函数处理：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-svls-app/img/c0fe43a8-e234-4028-8272-5cedd178a7d8.png)

在进入下一章之前，我们可以通过运行以下命令删除我们的 Kubeless Kubernetes 单节点集群：

```
$ minikube delete
```

# 摘要

在本章中，我们已经将 Kubeless 部署到了我们使用 Minikube 启动的单节点 Kubernetes 上。我们安装了 Kubernetes 命令行客户端和基于 Web 的界面。一旦集群部署并安装了工具，我们就在 Kubeless 安装上部署和执行函数。

在安装一个更有用的发布推文的函数之前，我们先安装了两个基本的测试函数。然后，我们看了一下如何使用 Serverless 框架与 Kubeless 进行交互。

在下一章中，我们将看一下一个名为**Funktion**的基于事件的框架。
