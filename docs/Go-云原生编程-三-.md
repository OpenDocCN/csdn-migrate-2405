# Go 云原生编程（三）

> 原文：[`zh.annas-archive.org/md5/E4B340F53EAAF54B7D4EF0AD6F8B1333`](https://zh.annas-archive.org/md5/E4B340F53EAAF54B7D4EF0AD6F8B1333)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：AWS I - 基础知识，Go 的 AWS SDK 和 EC2

欢迎来到我们学习 Go 语言云编程的新阶段。在本章中，我们将开始讨论云技术，涵盖热门的亚马逊网络服务（AWS）平台。AWS 是最早提供给客户在其创业公司、企业甚至个人项目中使用的云平台之一。AWS 于 2006 年由亚马逊推出，并自那时起不断增长。由于该主题的规模较大，我们将把材料分成两章。

在本章中，我们将涵盖以下主题：

+   AWS 基础知识

+   Go 的 AWS SDK

+   如何设置和保护 EC2 实例

# AWS 基础知识

AWS 的最简单定义是，它是亚马逊提供的一项服务，您可以在其云平台上购买虚拟机、数据库、消息队列、RESTful API 端点以及各种托管的软件产品。要充分了解 AWS，我们需要涵盖平台上提供的一些主要服务。然后，我们将深入学习如何利用 Go 来构建能够利用 AWS 通过其云 API 提供的服务的应用程序的能力。

+   弹性计算云（EC2）：弹性计算云（EC2）是 AWS 提供的最受欢迎的服务之一。它可以简单地描述为在 AWS 上需要旋转新服务器实例时使用的服务。EC2 之所以特殊，是因为它使启动服务器和分配资源的过程对用户和开发人员来说几乎是轻而易举的。EC2 支持自动扩展，这意味着应用程序可以根据用户的需求自动扩展和缩减。该服务支持多种设置和操作系统。

+   简单存储服务（S3）：S3 允许开发人员存储不同类型的数据以供以后检索和数据分析。S3 是另一个全球众多开发人员使用的热门 AWS 服务。通常，开发人员在 S3 上存储图像、照片、视频和类似类型的数据。该服务可靠、扩展性好，易于使用。S3 的用例很多；它可用于网站、移动应用程序、IOT 传感器等。

+   简单队列服务（SQS）：SQS 是 AWS 提供的托管消息队列服务。简而言之，我们可以将消息队列描述为一种软件，可以可靠地接收消息、排队并在其他应用程序之间传递它们。SQS 是一种可扩展、可靠且分布式的托管消息队列。

+   亚马逊 API 网关：亚马逊 API 网关是一个托管服务，使开发人员能够大规模创建安全的 Web API。它不仅允许您创建和发布 API，还公开了诸如访问控制、授权、API 版本控制和状态监控等复杂功能。

+   DynamoDB：DynamoDB 是一种托管在 AWS 中并作为服务提供的 NoSQL 数据库。该数据库灵活、可靠，延迟仅为几毫秒。NoSQL 是用来描述非关系型且性能高的数据库的术语。非关系型数据库是一种不使用关系表来存储数据的数据库类型。DynamoDB 利用了两种数据模型：文档存储和键值存储。文档存储数据库将数据存储在一组文档文件中，而键值存储将数据放入简单的键值对中。在下一章中，您将学习如何构建能够利用 DynamoDB 强大功能的 AWS 中的 Go 应用程序。

+   Go 语言的 AWS SDK：AWS SDK for Go 是一组 Go 库，赋予开发人员编写可以与 AWS 生态系统进行交互的应用程序的能力。这些库是我们将利用的工具，用于利用我们迄今提到的不同 AWS 服务，如 EC2、S3、DynamoDB 和 SQS。

在本章和下一章中，我们将更深入地介绍这些技术。我们将在本章讨论的每个主题都是庞大的，可以用整本书来覆盖。因此，我们不会覆盖每个 AWS 服务的每个方面，而是提供对每个服务的实际见解，以及如何将它们作为一个整体来构建强大的生产级应用程序。在深入研究每个 AWS 服务之前，让我们先了解一些 AWS 世界中的一般概念。

# AWS 控制台

AWS 控制台是一个网页门户，为我们提供访问 AWS 提供的多种服务和功能。要访问该门户，您首先需要导航到[aws.amazon.com](http://aws.amazon.com)，然后选择“登录到控制台”选项，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/439b8a86-a7fb-4a58-a6f1-d6aa839a59bb.jpg)

一旦您登录控制台，您将看到一个展示 AWS 提供的服务的网页：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/d546f848-b579-4e2c-942b-b3f31811b158.png)

# AWS 命令行界面（CLI）

AWS CLI 是一个开源工具，提供与 AWS 服务交互的命令。AWS CLI 是跨平台的；它可以在 Linux、macOS 和 Windows 上运行。在本章中，我们将使用该工具执行某些任务，例如从`S3`文件夹复制文件到 EC2 实例。AWS CLI 可以执行类似于 AWS 控制台执行的任务；这包括 AWS 服务的配置、部署和监控。该工具可以在以下网址找到：[`aws.amazon.com/cli/`](https://aws.amazon.com/cli/)。

# AWS 区域和可用区

AWS 服务托管在世界各地的多个地理位置。在 AWS 世界中，位置包括区域和可用区。每个区域是一个独立的地理位置。每个区域包含多个隔离的内部位置，称为可用区。一些服务 —— 例如 Amazon EC2，例如 —— 让您完全控制要为您的服务部署使用哪些区域。您还可以在区域之间复制资源。您可以在以下网址找到可用的 AWS 区域列表：[`docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-available-regions`](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-available-regions)。

对于在 AWS 中进行复杂应用程序部署的开发人员，他们通常将其微服务部署到多个区域。这样可以确保即使某个区域的亚马逊数据中心遭受故障，应用程序也能享受高可用性。

# AWS 标签

AWS 标签是 AWS 宇宙中的另一个重要概念。它允许您正确分类您的不同 AWS 资源。这非常有用，特别是当您为不同的事物使用多个 AWS 服务时。例如，您可以设置一个或多个标签来识别您用于移动应用程序的`S3`存储桶。然后可以使用相同的标签来识别您用于该移动应用程序后端的 EC2 实例。标签是键值对；值是可选的。

更好地理解 AWS 标签的资源可以在以下网址找到：[`aws.amazon.com/answers/account-management/aws-tagging-strategies/`](https://aws.amazon.com/answers/account-management/aws-tagging-strategies/)。

# AWS 弹性 Beanstalk

在我们开始实际深入研究 AWS 服务之前，有必要提到 AWS 生态系统中一个有用的服务，称为*弹性 Beanstalk*。该服务的目的是通过 AWS 控制台提供一个易于使用的配置向导，让您可以快速在 AWS 上部署和扩展您的应用程序。

这项服务在多种场景中都很有用，我们鼓励读者在阅读本章和本书的下一章之后探索它。然而，在本书中我们不会专注于 Elastic Beanstalk。这是因为本书在涉及 AWS 时的目的是为您提供关于主要 AWS 服务内部工作的实用基础知识。这些知识将使您不仅能够在 AWS 上部署和运行应用程序，还能够对事物的运作有很好的把握，并在必要时进行调整。这些基础知识也是您需要将技能提升到本书之外的下一个水平所需的。

涵盖 AWS Beanstalk 而不深入探讨使 AWS 成为开发人员的绝佳选择的关键 AWS 服务将不足以让您获得足够的知识以长期有效。然而，如果您在阅读本章和本书的下一章之后再看 AWS Beanstalk，您将能够理解幕后发生了什么。

该服务可以在[`aws.amazon.com/elasticbeanstalk/`](https://aws.amazon.com/elasticbeanstalk/)找到。

# AWS 服务

现在，是时候学习如何利用 Go 的力量与 AWS 交互并构建云原生应用程序了。在本节中，我们将开始实际深入一些构建现代生产级云应用程序所需的 AWS 服务。

# AWS SDK for Go

如前所述，AWS SDK for Go 是一组库，使 Go 能够展现 AWS 的强大功能。为了利用 SDK，我们首先需要了解一些关键概念。

我们需要做的第一步是安装 AWS SDK for Go；通过运行以下命令来完成：

```go
go get -u github.com/aws/aws-sdk-go/...
```

像任何其他 Go 包一样，这个命令将在我们的开发机器上部署 AWS SDK 库。

# 配置 AWS 区域

第二步是指定 AWS 区域；这有助于确定在进行调用时发送 SDK 请求的位置。SDK 没有默认区域，这就是为什么我们必须指定一个区域。有两种方法可以做到这一点：

+   将区域值分配给名为`AWS_REGION`的环境变量。区域值的示例是`us-west-2`或`us-east-2`。

+   在代码中指定它——稍后会更多。

# 配置 AWS SDK 身份验证

第三步是实现适当的 AWS 身份验证；这一步更加复杂，但非常重要，以确保我们的代码与不同的 AWS 服务进行交互时的安全性。为了做到这一点，我们需要向我们的应用程序提供安全凭据，以便对 AWS 进行安全调用。

生成您需要使代码在通过 SDK 与 AWS 通信时正常工作的凭据有两种主要方法：

+   创建用户，它只是代表一个人或一个服务的身份。您可以直接为用户分配单独的权限，或将多个用户组合成一个允许用户共享权限的组。AWS SDK for Go 要求用户使用 AWS 访问密钥来对发送到 AWS 的请求进行身份验证。AWS 访问密钥由两部分组成：访问密钥 ID 和秘密访问密钥。这是我们在本地服务器上运行应用程序时使用的内容。

+   下一种方法是创建一个角色。角色与用户非常相似，因为它是具有特定权限的身份。然而，角色不是分配给人员的；它是根据特定条件分配给需要它的人员。例如，可以将角色附加到 EC2 实例，这将允许在该 EC2 实例上运行的应用程序进行安全调用 AWS，而无需指定不同的用户。这是在 EC2 实例上运行应用程序时的推荐方法，其中预期应用程序将进行 AWS API 调用。

# 创建 IAM 用户

如果您是从自己的本地计算机运行应用程序，创建访问密钥的推荐方式是创建一个具有特定权限访问 AWS 服务的用户。这是通过在**AWS 身份和访问管理**（**IAM**）中创建用户来完成的。

要在 IAM 中创建用户，我们首先需要登录到 AWS 主要网络控制台，然后点击 IAM，它应该在“安全性、身份和合规性”类别下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/bcd9b3b4-a29c-4430-95c3-736eccb72700.jpg)

接下来，我们需要点击右侧的“用户”选项，然后点击“添加用户”来创建一个新的 IAM 用户：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/eebc7730-bb98-494a-9a3c-8e94d4ea0874.png)

然后，您将被引导使用用户创建向导来帮助您创建用户并生成访问密钥。在此向导的第一步中，您将可以选择用户名并选择用户的 AWS 访问类型。AWS 访问类型包括两种主要类型：程序访问或 AWS 管理控制台访问。显然，为了创建可以被 AWS SDK 使用的用户，我们需要选择程序访问，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/5b021144-db9b-4003-8e25-fb18962a8969.png)

下一步将涉及将权限附加到正在创建的用户。然而，在我们讨论三种方法之前，我们首先需要了解策略的概念。策略只是定义权限的一种灵活方法。例如，可以创建一个新策略来定义对特定 S3 文件夹的只读访问权限。然后，任何获得此策略附加的用户或组将只被允许对此特定 S3 文件夹进行只读访问。AWS 提供了许多预创建的策略，我们可以在我们的配置中使用。例如，有一个名为**AmazonS3FullAccess**的策略，允许其持有者对 S3 进行完全访问。现在，让我们回到为用户分配权限的三种方法：

+   **将用户添加到组中**：组是一个可以拥有自己策略的实体。多个用户可以添加到一个或多个组中。您可以将组简单地看作是用户的文件夹。特定组下的用户将享有所述组策略允许的所有权限。在这一步中的配置向导将允许您创建一个新组并为其分配策略，如果需要的话。这通常是分配权限给用户的推荐方式。

+   **从现有用户复制权限**：这允许新用户享有已为不同用户配置的所有组和策略。例如，将用户添加到新团队中时使用。

+   **直接附加现有策略**：这允许直接将策略分配给新用户，而无需经过组或从其他用户复制。这种方法的缺点是，如果每个用户都被分配了个别的策略，而没有组提供的秩序感，随着用户数量的增加，管理用户将变得繁琐。

以下是三个选项的截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/ce462fe2-dd3a-4a7f-bc32-05af793fdade.png)

完成权限设置后，我们可以审查我们的选择并继续创建新用户。一旦创建了新用户，我们将有一个选项来下载用户的访问密钥作为 CSV 文件。我们必须这样做才能在以后的应用程序中利用这些访问密钥。访问密钥由访问密钥 ID 和秘密访问密钥值组成。

一旦您获得了访问密钥，有多种方法可以让您的代码使用它们；我们将讨论其中的三种：

**直接使用环境变量**：AWS SDK 代码将查找两个主要的环境变量，以及一个可选的第三个环境变量。我们只讨论两个主要的环境变量：

+   `AWS_ACCESS_KEY_ID`：在这里我们设置访问密钥的密钥 ID

+   `AWS_SECRET_ACCESS_KEY`：在这里我们设置访问密钥的秘密密钥值

环境变量通常在 SDK 默认情况下在移动到下一个方法之前进行检查。

**利用凭证文件**：凭证文件是一个存放访问密钥的纯文本文件。该文件必须命名为`credentials`，并且必须位于计算机主目录的`.aws/`文件夹中。主目录显然会根据您的操作系统而变化。在 Windows 中，您可以使用环境变量`%UserProfile%`指定主目录。在 Unix 平台上，您可以使用名为`$HOME`或`~`的环境变量。凭证文件是`.ini`格式的，可能如下所示：

```go
[default]
aws_access_key_id = <YOUR_DEFAULT_ACCESS_KEY_ID>
aws_secret_access_key = <YOUR_DEFAULT_SECRET_ACCESS_KEY>

[test-account]
aws_access_key_id = <YOUR_TEST_ACCESS_KEY_ID>
aws_secret_access_key = <YOUR_TEST_SECRET_ACCESS_KEY>

[prod-account]
; work profile
aws_access_key_id = <YOUR_PROD_ACCESS_KEY_ID>
aws_secret_access_key = <YOUR_PROD_SECRET_ACCESS_KEY>
```

方括号之间的名称称为**配置文件**。如前面的片段所示，您的凭证文件可以指定映射到不同配置文件的不同访问密钥。然而，接下来出现一个重要问题，那就是我们的应用程序应该使用哪个配置文件？为此，我们需要创建一个名为`AWS_PROFILE`的环境变量，该变量将指定配置文件名称和分配给其的应用程序名称。例如，假设我们的应用程序名为`testAWSapp`，我们希望它使用`test-account`配置文件，那么我们将设置`AWS_PROFILE`环境变量如下：

```go
$ AWS_PROFILE=test-account testAWSapp
```

如果未设置`AWS_PROFILE`环境变量，则默认情况下将选择*default*配置文件。

**在应用程序中硬编码访问密钥**：出于安全原因，通常不建议这样做。因此，尽管从技术上讲是可能的，但不要在任何生产系统中尝试这样做，因为任何可以访问您的应用程序代码（可能在 GitHub 中）的人都可以检索并使用您的访问密钥。

# 创建 IAM 角色

如前所述，如果您的应用程序在 Amazon EC2 实例上运行，则建议使用 IAM 角色。通过 AWS 控制台创建 IAM 角色的过程与创建 IAM 用户类似：

1.  首先登录到 AWS 控制台（[aws.amazon.com](http://aws.amazon.com)）

1.  然后我们从“安全，身份和合规性”类别下选择 IAM

从那里，我们将走另一条路。这一次，我们点击右侧的“角色”，然后选择“创建新角色”：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/5c9cad36-2933-4b29-b19e-59c49d9f6dca.jpg)

选择创建新角色后，我们将得到角色创建向导。

我们首先被要求选择角色类型。对于我们的情况，我们需要选择 EC2 服务角色，然后选择 Amazon EC2：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/4c35989d-e81b-4523-8448-190604016ca7.jpg)

然后，我们将点击下一步。然后，我们需要选择我们的新角色将使用的策略：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/85f26f5d-5d7e-4f21-9493-e92d1cfd1556.jpg)

为了我们的应用程序，让我们选择以下四个策略：

+   AmazonS3FullAccess

+   AmazonSQSFullAccess

+   AmazonDynamoDBFullAccess

+   AmazonAPIGatewayAdministrator

然后，我们再次点击下一步，然后我们进入最后一步，在这一步中我们可以设置角色名称，审查我们的配置，然后点击“创建角色”来创建一个新角色。为了我们的目的，我创建了一个名为`EC2_S3_API_SQS_Dynamo`的新角色：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/8a4276c7-38b6-4ee6-984b-d9b77ebcf165.jpg)

一旦我们点击“创建角色”，一个具有我们选择的策略的新角色就会被创建。

然后可以将此角色附加到 EC2 实例上，我们的应用程序代码将在其中运行。我们将在 EC2 部分探讨如何做到这一点。

# AWS SDK for Go 的基础知识

为了利用 AWS SDK for Go 的功能，我们需要掌握两个关键概念。

# 会话

第一个概念是会话的概念。会话是 SDK 中包含配置信息的对象，我们可以将其与其他对象一起使用，以与 AWS 服务进行通信。

`session`对象可以被共享并被不同的代码片段使用。应该缓存并重复使用该对象。创建新的`session`对象涉及加载配置数据，因此重用它可以节省资源。只要不被修改，`session`对象就可以安全地并发使用。

要创建一个新的`session`对象，我们可以简单地编写以下代码：

```go
session, err := session.NewSession()
```

这将创建一个新的`session`并将其存储在名为 session 的变量中。如果我们通过上述代码创建一个新的`session`，将使用默认配置。如果需要覆盖配置，可以将`aws.Config`类型结构体的对象指针作为参数传递给`NewSession()`结构体。假设我们想设置`Region`：

```go
session, err := session.NewSession(&aws.Config{
    Region: aws.String("us-east-2"),
})
```

我们可以使用另一个构造函数来创建一个新的会话，称为`NewSessionWithOptions()`；这有助于覆盖我们用于提供创建会话所需信息的一些环境变量。例如，我们之前讨论过如何定义一个配置文件来存储应用程序使用的凭据。这是它的样子：

```go
session,err := session.NewSessionWithOptions(session.Options{
   Profile: "test-account",
})
```

# 服务客户端

第二个概念是服务客户端的概念。服务客户端是一个对象，它提供对特定 AWS 服务（如 S3 或 SQS）的 API 访问。

服务客户端对象是从会话对象创建的。以下是一个利用 S3 服务客户端获取存储桶列表（S3 存储桶只是文件和文件夹的容器）并逐个打印每个存储桶名称的代码片段示例：

```go
//Don't forget to import github.com/aws/aws-sdk-go/service/s3

 sess, err := session.NewSession(&aws.Config{
    Region: aws.String("us-west-1"),
  })
  if err != nil {
    log.Fatal(err)
  }
  s3Svc := s3.New(sess)
  results, err := s3Svc.ListBuckets(nil)
  if err != nil {
    log.Fatal("Unable to get bucket list")
  }

  fmt.Println("Buckets:")
  for _, b := range results.Buckets {
    log.Printf("Bucket: %s \n", aws.StringValue(b.Name))
  }
```

只要确保不在并发代码中更改配置，服务客户端对象通常是安全的并发使用。

在底层，服务客户端使用 Restful API 调用与 AWS 进行交互。但是，它们会为您处理构建和保护 HTTP 请求所涉及的所有繁琐代码。

当我们阅读本章和下一章时，我们将创建会话和服务客户端对象，以访问不同的 AWS 服务。会话和服务客户端是我们构建适当的 AWS 云原生应用程序所需的构建代码块。SDK 允许您深入了解底层请求；如果我们想在发送请求之前执行一些操作，这通常是有帮助的。

AWS SDK 的大多数 API 方法调用都遵循以下模式：

1.  API 方法的名称通常描述某个操作。例如，假设我们有一个**简单队列服务**（**SQS**）服务客户端对象，并且我们需要获取特定队列的 URL 地址。方法名称将是`GetQueueUrl`。

1.  API 方法的输入参数通常类似于`<method name>Input`；因此，在`GetQueueUrl`方法的情况下，其输入类型是`GetQueueUrlInput`。

1.  API 方法的输出类型通常类似于<method name>Output；因此，在`GetQueueURL`方法的情况下，其输出类型是`GetQueueUrlOutput`。

# 本机数据类型

关于 SDK 方法的另一个重要说明是，几乎所有用作参数或结构字段的数据类型都是指针，即使数据类型是本机的。例如，SDK 倾向于使用`*`string 而不是使用字符串数据类型来表示字符串值，整数和其他类型也是如此。为了让开发人员的生活更轻松，AWS SDK 为 Go 提供了帮助方法，用于在确保执行 nil 检查以避免运行时恐慌的同时，在本机数据类型和它们的指针之间进行转换。

将本机数据类型转换为相同数据类型的指针的帮助方法遵循以下模式：`aws.<datatype>`。例如，如果我们调用`aws.String("hello")`，该方法将返回一个指向存储`Hello`值的字符串的指针。如果我们调用`aws.Int(1)`，该方法将返回一个值为 1 的 int 的指针。

另一方面，将指针转换回其数据类型的方法在进行 nil 检查时遵循以下模式：`aws.<datatype>Value`。例如，如果我们调用`aws.IntValue(p)`，其中`p`是值为 1 的 int 指针，返回的结果就是一个值为 1 的 int。为了进一步澄清，以下是 SDK 代码中`aws.IntValue`的实现：

```go
func IntValue(v *int) int {
  if v != nil {
    return *v
  }
  return 0
}
```

# 共享配置

由于不同的微服务可能需要在与 AWS 交互时使用相同的配置设置，AWS 提供了一种使用所谓的共享配置的选项。共享配置基本上是一个存储在本地的配置文件。文件名和路径是`.aws/config`。请记住，`.aws`文件夹将存在于操作系统的主文件夹中；在讨论凭据文件时已经涵盖了该文件夹。

配置文件应遵循类似于凭据文件的 ini 格式。它还支持与我们之前在凭据文件中介绍的方式类似的配置文件中的配置文件。以下是`.aws/config`应该是什么样子的示例：

```go
[default]
region=us-west-2
```

为了让特定服务器中的微服务能够使用该服务器的 AWS 配置文件，有两种方法：

1.  将`AWS_SDK_LOAD_CONFIG`环境变量设置为 true；这将导致 SDK 代码使用配置文件。

1.  创建会话对象时，利用`NewSessionWithOptions`构造函数来启用共享配置。代码如下：

```go
sess, err := session.NewSessionWithOptions(session.Options{
    SharedConfigState: SharedConfigEnable,
})
```

有关完整的 AWS Go SDK 文档，您可以访问[`docs.aws.amazon.com/sdk-for-go/api/`](https://docs.aws.amazon.com/sdk-for-go/api/)。

# 分页方法

一些 API 操作可能会返回大量结果。例如，假设我们需要发出 API 调用来从 S3 存储桶中检索项目列表。现在，假设 S3 存储桶包含大量项目，并且在一个 API 调用中返回所有项目是不高效的。AWS Go SDK 提供了一个名为**Pagination**的功能来帮助处理这种情况。通过分页，您可以在多个页面中获取结果。

您可以一次读取每页，然后在准备处理新项目时转到下一页。支持分页的 API 调用类似于<方法名称>Pages。例如，与`ListObjects` S3 方法对应的分页 API 方法调用是`ListObjectsPages`。`ListObjectPages`方法将迭代从`ListObject`操作结果的页面。它接受两个参数——第一个参数是`ListObjectInput`类型，它将告诉`ListObjectPages`我们要读取的 S3 存储桶的名称，以及我们希望每页的最大键数。第二个参数是一个函数，每页的响应数据都会调用该函数。函数签名如下：

```go
func(*ListObjectsOutput, bool) bool
```

此参数函数有两个参数。第一个参数携带我们操作的结果；在我们的情况下，结果将托管在`ListObjectsOutput`类型的对象中。第二个参数是`bool`类型，基本上是一个标志，如果我们在最后一页，则为 true。函数返回类型是`bool`；我们可以使用返回值来停止迭代页面。这意味着每当我们返回 false 时，分页将停止。

以下是 SDK 文档中的一个示例，完美展示了分页功能，利用了我们讨论过的方法。以下代码将使用分页功能来浏览存储在 S3 存储桶中的项目列表。我们将每页请求最多 10 个键。我们将打印每页的对象键，然后在最多浏览三页后退出。代码如下：

```go
svc, err := s3.NewSession(sess)
if err != nil {
    fmt.Println("Error creating session ", err)
}
inputparams := &s3.ListObjectsInput{
    Bucket: aws.String("mybucket"),
    MaxKeys: aws.Int64(10),
}
pageNum := 0
svc.ListObjectsPages(inputparams, func(page *s3.ListObjectsOutput, lastPage bool) bool {
    pageNum++
    for _, value := range page.Contents {
        fmt.Println(*value.Key)
    }
    return pageNum < 3
})
```

# 等待者

等待器是允许我们等待直到某个操作完成的 API 调用。大多数等待方法通常遵循 WaitUntil<action> 格式。例如，在使用 DynamoDB 数据库时，有一个名为`WaitUntilTableExists`的 API 方法调用，它将简单地等待直到满足条件。

# 处理错误

AWS Go SDK 返回`awserr.Error`类型的错误，这是 AWS SDK 中的特殊接口类型，满足通用的 Go 错误接口类型。`awserr.Error`支持三种主要方法：

+   `Code()`: 返回与问题相关的错误代码

+   `Message()`: 返回错误的字符串描述

+   `OrigErr()`: 返回包装在`awserr.Error`类型中的原始错误；例如，如果问题与网络有关，`OrigErr()`将返回原始错误，该错误可能属于 Go net 包

为了暴露和利用`awserr.Error`类型，我们需要使用 Go 语言中的类型断言功能。

让我们展示如何使用实际示例中的`awserr.Error`类型。假设在我们的应用程序中，我们使用 Dynamodb 服务客户端对象通过项目 ID 从 Dynamodb 表中检索项目。但是，我们在表名中犯了一个错误，现在它不存在，这将导致调用失败。代码如下：

```go
    result, err := dynamodbsvc.GetItem(&dynamodb.GetItemInput{
      Key: map[string]*dynamodb.AttributeValue{
        "ID": {
          N: aws.String("9485"),
        },
      },
      TableName: aws.String("bla"),
    })
    if err != nil {
      if v, ok := err.(awserr.Error); ok {
        log.Println("AWS ERROR...")
        if v.Code() == dynamodb.ErrCodeResourceNotFoundException {
          log.Println("Requested resource was not found...")
          return
        }
      }
    }
```

从上述代码中，如果`dynamodbsvc.GetItem()`方法失败并且我们无法获取该项，我们捕获错误是否发生，然后使用 Go 的类型断言从我们的错误对象中获取底层的`awserr.Error`类型。然后我们继续检查错误代码并将其与我们的 SDK 中指示资源未找到问题的错误代码进行比较。如果确实是资源未找到的问题，我们打印一条指示这样的消息然后返回。以下是前面的代码中我们进行错误检测和处理的具体代码段，如当前段落所述：

```go
    if err != nil {
      if v, ok := err.(awserr.Error); ok {
        log.Println("AWS ERROR...")
        if v.Code() == dynamodb.ErrCodeResourceNotFoundException {
          log.Println("Requested resource was not found...")
          return
        }
      }
    }
```

# 弹性计算云（EC2）

与任何其他 AWS 服务一样，我们将从 AWS 控制台开始，以便能够启动和部署 EC2 实例。如前所述，EC2 简单地可以描述为在 AWS 上需要旋转新服务器实例时使用的服务。让我们探索创建和访问 EC2 实例所需的步骤。

# 创建 EC2 实例

在 AWS 控制台的主屏幕上，我们需要选择 EC2 以启动新的 EC2 实例：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/8b254480-4e67-4e85-9c40-a7ad48b3e8ba.jpg)

下一个屏幕将显示许多不同的选项来管理 EC2 实例。现在，我们需要做的是单击“启动实例”按钮。您会注意到 AWS 区域在这里显示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/a8be8561-3162-45b5-8c30-0915899f8628.png)

之后，我们将选择要在云上用作虚拟服务器的镜像。**Amazon Machine Image**（AMI）是一个缩写，用于描述 Amazon 虚拟服务器镜像以及启动所需的所有信息。AMI 包括一个模板，描述了操作系统、虚拟服务器中的应用程序、指定哪个 AWS 帐户可以使用 AMI 启动虚拟服务器实例的启动权限，以及指定一次启动后要附加到实例的卷的设备映射。亚马逊提供了许多现成的 AMI，我们可以立即使用。但是，您也可以创建自己的 AMI。

以下是 AWS 控制台中 AMI 选择屏幕的外观：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/d69e094e-1c94-437d-add1-0060b6bf08d1.png)

从 AMI 描述中可以看出，AMI 定义了操作系统、命令行工具、编程语言环境（如 Python、Ruby 和 Pert）。

现在，让我们选择亚马逊 Linux AMI 选项，以继续下一步。在这一步中，我们可以选择我们想要的服务器镜像。在这里，您可以选择 CPU 核心数、内存和网络性能等。您会注意到“EBS”一词位于“实例存储”下。**弹性块存储**（**EBS**）提供云托管存储卷，并提供高可用性、可扩展性和耐用性。每个 EBS 都在其可用性区域内复制。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/51a9e520-77b9-4ad0-9ee7-51de8abda736.png)

接下来，我们可以点击“审阅并启动”按钮来启动 AMI，或者点击“下一步：配置实例详细信息”按钮来深入了解实例的配置选项。更深入的配置选项包括实例数量、子网、网络地址等。

配置实例详细信息也是我们为 EC2 分配 IAM 角色（我们之前讨论过的）的地方。我们在本章前面创建的 IAM 角色名为 EC2_S3_API_SQS_Dynamo，它将允许在此 EC2 实例上运行的应用程序访问 S3 服务、API 网关服务、SQS 服务和 Dynamo 数据库。配置页面将如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/eb2ab8db-ed50-4cb2-bec9-0f5d60b37301.jpg)

为了这一章的目的，我们将点击“审阅并启动”来审阅然后启动实例。让我们来看一下审阅页面：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/ca591d91-4d43-445a-89a6-8339e3474ff6.png)

一旦我们对所有设置感到满意，我们可以继续点击“启动”。这将显示一个对话框，要求一个公钥-私钥对。公钥加密的概念在第三章中有更详细的讨论。简而言之，我们可以将公钥与其他人分享，以便他们在发送消息之前对其进行加密。加密的消息只能通过您拥有的私钥解密。

对于 AWS，为了允许开发人员安全地连接到他们的服务，AWS 要求开发人员选择公钥-私钥对以确保访问安全。公钥存储在 AWS 中，而私钥由开发人员存储。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/40ca0b47-18a0-45da-ad3b-5a37710db0e6.png)

如果您还没有在 AWS 上拥有公钥-私钥对，这是我们可以创建的步骤。AWS 还允许您在不创建密钥的情况下继续，这显然会更不安全，不建议在生产应用中使用。让我们看看当我们点击第一个列表框时会得到的三个选项：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/4aeacf13-62ec-47ca-88ac-6bcc7f158ccc.jpg)

如果您选择创建新的密钥对选项，您将有机会命名您的密钥对并下载私钥。您必须下载私钥并将其存储在安全位置，以便以后使用：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/2ff9d334-940c-4e1c-86fa-c4fc60679122.png)

最后，在我们下载私钥并准备启动实例后，我们可以点击“启动实例”按钮。这将启动启动实例的过程，并显示状态指示。下一个屏幕通常是这样的：

>![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/a6e34d0c-cdb9-4f2f-bc98-a0ade1e12ccf.png)

完美；通过这一步，我们在亚马逊云中拥有了我们自己的 Linux 虚拟机。让我们找出如何连接并探索它。

# 访问 EC2 实例

为了访问我们已经创建的 EC2 实例，我们需要首先登录 AWS 控制台，然后像之前一样选择 EC2。这将为您提供访问 EC2 仪表板的权限。从那里，我们需要点击实例，以访问我们帐户下当前创建的 EC2 实例。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/3fd786ae-a434-4833-9052-c0e58581b0d2.jpg)

这将打开一个已经创建的 EC2 实例列表。我们刚刚创建的实例是第一个；您会注意到它的实例 ID 与我们之前创建实例时显示的实例 ID 相匹配。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/72ea8a59-0a45-4664-838d-498421c065ce.jpg)

上述截图显示我们的实例目前正在 AWS 上运行。如果需要，我们可以像连接到任何远程服务器一样连接到它。让我们探讨如何做到这一点。

第一步是选择相关的实例，然后点击连接按钮。这不会直接连接到您的实例；但是，它会提供一系列有用的指令，说明如何建立与您的 EC2 实例的连接。为了建立连接，您需要使用 SSH 协议和之前下载的私人加密密钥远程登录到 EC2 虚拟服务器。**Secure Shell** (**SSH**) 是一种用户安全登录远程计算机的协议。

调用 SSH 的方法可能因操作系统而异。例如，如果您使用的是 Windows 操作系统，那么您应该使用流行的 PuTTY 工具（在 [`www.chiark.greenend.org.uk/~sgtatham/putty/latest.html`](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) 找到）来建立与 EC2 实例的 SSH 连接。如果您使用的是 macOS 或 Linux，您可以直接使用 SSH 命令。

# 从 Linux 或 macOS 机器访问 EC2 实例

为了从 Linux 或 macOS 机器访问在 AWS 上创建的 EC2 实例，我们需要使用 SSH 命令。

第一步是确保连接的私钥——我们在创建 EC2 实例时下载的——是安全的，不能被外部方访问。这通常是通过在终端上执行以下命令来完成的：

```go
chmod 400 my-super-secret-key-pair.pem
```

`my-super-secret-key-pair.pem` 是包含私钥的文件名。显然，如果文件名不同，那么您需要确保命令将针对正确的文件名。为了使上述命令生效，我们需要从与密钥所在的相同文件夹运行它。否则，我们需要指定密钥的路径。

在确保密钥受到公共访问的保护之后，我们需要使用 SSH 命令连接到我们的 EC2 实例。为此，我们需要三个信息：私钥文件名、EC2 镜像用户名和连接的 DNS 名称。我们已经知道了密钥文件名，这意味着我们现在需要找出连接的用户名和 DNS 名称。用户名将取决于 EC2 实例的操作系统。以下表显示了操作系统到用户名的映射：

| **操作系统** | **用户名** |
| --- | --- |
| 亚马逊 Linux | `ec2-user` |
| RHEL（Red Hat Enterprise Linux） | `ec2-user` 或 root |
| Ubuntu | ubuntu 或 root |
| Centos | centos |
| Fedora | `ec2-user` |
| SUSE | `ec2-user` 或 root |

对于其他操作系统，如果 `ec2-user` 或 root 无法使用，请与 **Amazon Machine Image** (**AMI**) 提供商确认。

现在，我们需要的剩下的信息是连接到 EC2 实例的 DNS 名称。我们可以通过简单地查看状态页面上的 EC2 实例详细信息来找到它：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/ad397b79-0039-4abe-bede-8632405a7396.jpg)

有了这个，我们就有了执行 SSH 命令访问我们的 EC2 实例所需的一切；命令如下所示：

```go
ssh -i "my-super-secret-key-pair.pem" ec2-user@ec2-54-193-5-28.us-west-1.compute.amazonaws.com
```

上述命令中的私钥名称是 `my-super-secret-key-pair.pem`，用户名是 `ec2-user`，DNS 是 `ec2-54-193-5-28.us-west-1.compute.amazonaws.com`。

这个命令将允许我们访问我们刚刚创建的 EC2 实例；屏幕上会显示如下内容：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/7ff19708-efe2-4851-ac97-938e07d0f6bf.jpg)

# 从 Windows 访问 EC2

要从 Windows 访问 EC2，我们可以使用我们在前一节中介绍的 SSH 工具的 Windows 版本，或者我们可以使用 PuTTY。PuTTY 是一个非常受欢迎的 SSH 和 telnet 客户端，可以在 Windows 或 Unix 上运行。要下载 PuTTY，我们需要访问[`www.chiark.greenend.org.uk/~sgtatham/PuTTY/latest.html`](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html)。下载 PuTTY 后，安装并运行它，主屏幕将类似于这样：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/207250d6-fde7-4379-9169-0abf6ea8e15c.jpg)

在我们可以使用 PuTTY 连接到我们的 EC2 实例之前，我们需要将之前获得的私钥文件转换为可以被 PuTTY 软件轻松消耗的不同文件类型。

要执行私钥转换，我们将需要一个名为**PuTTYgen**的工具的帮助，它随 PuTTY 一起安装。PuTTYgen 可以在所有程序>PuTTY>PuTTYgen 下找到。启动后，PuTTYgen 看起来像这样：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/cdff06dc-02fb-4712-8e2f-03c302af006f.jpg)

在参数下，确保选择 RSA 作为加密算法，生成的密钥中有 2048 位。

要继续，让我们点击“加载”按钮，以便能够将我们的 AWS 私钥加载到工具中。加载按钮将打开一个对话框，允许我们选择私钥文件。我们需要选择显示所有文件的选项，以便查看私钥文件：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/2d2982a9-f062-4409-a9a5-1db4a6b3dafa.jpg)![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/f8583255-4a60-463b-a99f-438c4c5a4202.jpg)

然后，我们可以选择密钥，然后点击“打开”，以便将密钥加载到 PuTTYgen 工具中。下一步是点击“保存私钥”以完成密钥转换。会出现一个警告，询问您是否确定要保存此密钥而不使用密码来保护它；点击“是”。密码是额外的保护层；但是，它需要用户输入才能工作。因此，如果我们想要自动化 SSH 连接到 EC2 实例，我们不应该启用密码。点击“是”后，我们可以选择转换文件的文件名；然后，我们点击“保存”以创建和保存文件。PuTTY 私钥是`*.ppk`类型的。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/8c85fbf2-43ae-4a09-aa1b-5d27f808eed9.jpg)

完美；我们现在有一个 PuTTY 私钥可以用于我们的用例。下一步是打开 PuTTY 工具，以使用此密钥通过 SSH 连接到 EC2 实例。

打开 PuTTY 后，我们需要转到连接类别下的 SSH 选项，然后从那里导航到 Auth 选项。在 Auth 窗口中，我们将搜索我们之前创建的 PuTTY 私钥文件的加载选项。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/7e53ca77-6eab-49df-8f7d-768d851c25e3.jpg)

接下来，我们需要点击右侧的“会话”类别。然后，在右侧的“主机名（或 IP 地址）”字段下，我们需要输入用户名和公共 DNS 地址，格式如下：`用户名@DNS 公共`名称。在我们的情况下，看起来是这样的：`ec2-user@ec2-54-193-5-28.us-west-1.compute.amazonaws.com`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/4cf2b45f-2151-4049-8945-fde0f0f4e015.jpg)

从那里，我们可以点击“打开”以打开到 EC2 实例的会话。第一次尝试打开会话时，我们会收到一条消息，询问我们是否信任我们要连接的服务器。如果我们信任它，我们需要点击“是”，这将把服务器的主机密钥缓存到注册表中。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/77b9cfd9-072d-4096-921b-496eb7385b4c.jpg)

这将打开到我们的 EC2 实例的安全会话；然后我们可以随心所欲地使用它：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/00be9dc3-a3da-4f8d-a8a9-2d4181bfe384.jpg)

PuTTY 有保存现有会话信息的功能。完成配置后，我们可以选择一个名称，然后点击“另存为”，如下图所示，以保存会话信息：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/500c1a98-a1ce-4b03-8708-36d030ee784b.jpg)

# 安全组

太好了！这足以涵盖如何在不同操作系统中配置和设置 EC2 实例的实用知识。现在，我们需要涵盖的另一个主题是安全组。您可以将安全组视为围绕您的 EC2 实例的防火墙规则集合。例如，通过添加安全规则，您可以允许在您的 EC2 上运行的应用程序接受 HTTP 流量。您可以创建规则以允许访问特定的 TCP 或 UDP 端口，以及其他更多内容。

由于我们预计将 Web 服务部署到我们的 EC2 实例上，比如*事件微服务*。我们需要创建一个允许 HTTP 流量的安全组，然后将该组分配给我们的 EC2 实例。

我们需要做的第一步是打开 EC2 仪表板，方法是转到 AWS 控制台主屏幕，然后选择 EC2，就像我们之前做的那样。一旦我们进入 EC2 仪表板，我们可以点击左侧的安全组，它将位于网络和安全类别下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/36d1816b-74f9-4ab2-990c-27c3e84882cd.jpg)

安全组仪表板将显示已经创建的所有安全组的列表。该仪表板允许我们创建新组或编辑现有组。由于在我们的情况下，我们正在创建一个新组，我们需要点击仪表板左上角的“创建安全组”。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/1670b49c-b298-42f0-8ee2-c1170abfab72.jpg)

一个表单窗口将弹出，我们需要填写字段以创建我们的安全组。首先，我们需要为安全组提供一个名称，一个可选的描述，我们的安全组将应用的虚拟私有云的名称。虚拟私有云简单地定义为 AWS 云中的逻辑隔离部分；我们可以定义自己的。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/5bd0cd79-5c5f-499d-834b-4748c570f914.jpg)

在前面的截图中，我们将我们的安全组命名为 HTTP 访问；我们将其描述为启用 HTTP 访问的安全组，然后我们选择默认 VPC。

下一步是点击“添加规则”按钮，开始定义组成我们安全组的规则。点击后，安全组规则部分将出现新行。我们需要点击“类型”列下的列表框，然后选择 HTTP。结果如下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/b9f229e1-0ed8-4178-b573-d739f09ebedd.jpg)

您会注意到协议、端口范围和源字段将为您填写。TCP 是 HTTP 的基础协议，端口 80 是 HTTP 端口。

如果需要，我们也可以添加一个 HTTPS 规则；我们将按照相同的步骤进行，只是在选择类型时，选择 HTTPS 而不是 HTTP。您还可以探索其他选项，以了解安全规则下可以创建哪些其他异常。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/13c00405-b940-45fc-ba07-6ff2f18c67a4.jpg)

创建安全组后，我们将在我们的安全组列表中找到它：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/f075d6d8-2d43-49d2-b962-408777d5df54.jpg)

创建了安全组后，我们可以将其附加到现有的 EC2 实例。这是通过返回 EC2 仪表板，然后选择“运行中的实例”，然后从 EC2 实例列表中选择感兴趣的实例来完成的。然后，我们点击“操作”，然后“网络”，然后“更改安全组”：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/61cd6d91-ca7e-4826-bd10-8f75bfbc3c8c.jpg)

从那里，我们可以选择要附加到我们实例的安全组：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/98eb077e-f893-4185-8fdb-351b31958231.jpg)

完美；有了这个，我们的 EC2 实例现在允许在其内部运行的应用程序访问 HTTP。

另一个重要的说明是，我们可以在创建 EC2 实例时将安全组分配给 EC2 实例。我们可以通过在创建新实例时点击“配置实例详细信息”，然后按照配置向导到“配置安全组”选项来访问此选项。

# 总结

在本章中，我们开始学习如何配置 EC2 以及如何使用 AWS SDK for Go。在下一章中，我们将继续深入了解 AWS，学习一些关键的 AWS 服务以及如何编写能够正确利用它们的 Go 代码。


# 第八章：AWS II–S3、SQS、API Gateway 和 DynamoDB

在本章中，我们将继续介绍亚马逊网络服务的大主题。在本章中，我们将介绍 S3 服务、SQS 服务、AWS API 网关服务和 DynamoDB 服务。这些服务中的每一个都是您在云上构建生产应用程序的强大工具。

我们将在本章中涵盖以下主题：

+   AWS S3 存储服务

+   SQS 消息队列服务

+   AWS API 网关服务

+   DynamoDB 数据库服务

# 简单存储服务（S3）

Amazon S3 是 AWS 负责存储和分析数据的服务。数据通常包括各种类型和形状的文件（包括音乐文件、照片、文本文件和视频文件）。例如，S3 可以用于存储静态数据的代码文件。让我们来看看如何在 AWS 中使用 S3 服务。

# 配置 S3

S3 服务将文件存储在存储桶中。每个存储桶可以直接保存文件，也可以包含多个文件夹，而每个文件夹又可以保存多个文件。

我们将使用 AWS Web 控制台来配置 S3，类似于我们在 EC2 中所做的。第一步是导航到 AWS Web 控制台，然后选择 S3：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/fa3ea49a-4f8e-4191-bfb1-ddc51cd6d8d7.png)

这将打开 Amazon S3 控制台；从那里，我们可以点击“创建存储桶”来创建一个新的存储桶来存储数据文件夹：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/c2cb783f-9073-4468-8c89-c36969afa322.png)

这将启动一个向导，将引导您完成创建存储桶所需的不同步骤。这将使您有权设置存储桶名称、启用版本控制或日志记录、设置标签和设置权限。完成后，将为您创建一个新的存储桶。存储桶名称必须是唯一的，以免与其他 AWS 用户使用的存储桶发生冲突。

我创建了一个名为`mnandbucket`的存储桶；它将显示在我的 S3 主网页的存储桶列表中。如果您的存储桶比页面能显示的更多，您可以在搜索栏中搜索存储桶：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/9209eb72-1f0b-412b-8674-e8f855a5c7d3.png)

一旦进入存储桶，我们就可以创建文件夹并上传文件：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/84fb98d0-037a-4d65-b425-8a8de899ec32.png)

完美！通过这样，我们对 S3 是什么有了一个实际的了解。

您可以从以下网址下载此文件：[`www.packtpub.com/sites/default/files/downloads/CloudNativeprogrammingwithGolang_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/CloudNativeprogrammingwithGolang_ColorImages.pdf)。

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Cloud-Native-Programming-with-Golang`](https://github.com/PacktPublishing/Cloud-Native-programming-with-Golang)。

S3 存储可以用于存储我们的应用程序文件以供以后使用。例如，假设我们构建了我们的`events`微服务以在 Linux 环境中运行，并且应用程序的文件名简单地是`events`。然后我们可以简单地将文件存储在 S3 文件夹中；然后，每当我们需要 EC2 实例获取文件时，我们可以使用 Ec2 实例中的 AWS 命令行工具来实现。

首先，我们需要确保 AWS 角色已经正确定义，以允许我们的 EC2 实例访问 S3 存储，就像之前介绍的那样。然后，从那里，要将文件从 S3 复制到我们的 EC2 实例，我们需要从我们的 EC2 实例中发出以下命令：

```go
aws s3 cp s3://<my_bucket>/<my_folder>/events my_local_events_copy
```

上述命令将从 S3 存储中检索`events`文件，然后将其复制到一个名为`my_local_events_copy`的新文件中，该文件将位于当前文件夹中。`<my_bucket>`和`<my_folder>`分别表示 S3 存储中事件文件所在的存储桶和文件夹。

在将可执行文件复制到 EC2 后，我们需要通过 Linux 的`chmod`命令给予它执行权限。这是通过以下命令实现的：

```go
chmod u+x <my_executable_file>
```

在上述命令中，`<my_executable_file>`是我们想要在 EC2 实例中获得足够访问权限以执行的文件。

# 简单队列服务（SQS）

如前所述，SQS 是 AWS 提供的消息队列。可以与 SQS 交互的应用程序可以在 AWS 生态系统内发送和接收消息。

让我们从讨论如何从 Amazon 控制台配置 SQS 开始。通常情况下，第一步是登录到 Amazon 控制台，然后从主仪表板中选择我们的服务。在这种情况下，服务名称将被称为简单队列服务：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/ffd92463-21cb-4417-a776-8e51ca287e69.png)

接下来，我们需要单击“入门”或“创建新队列”。队列创建页面将为我们提供配置新队列行为的能力。例如，我们可以设置允许的最大消息大小、保留消息的天数或接收消息的等待时间：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/d01b6f1b-b33e-4864-8925-295cc565b8f5.png)

当您满意您的设置时，单击“创建队列”——我选择了名称`eventqueue`。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/5027860c-394a-4bde-9e32-7a8c8b3ee3f5.png)

这将创建一个新的 AWS SQS 队列，我们可以在我们的代码中使用。现在，是时候讨论如何编写代码与我们的新队列进行交互了。

太好了！有了我们创建的队列，我们准备编写一些代码，通过新创建的 AWS SQS 队列发送和接收消息。让我们开始探索我们需要编写的代码，以便发送一些数据。

AWS SDK Go SQS 包的文档可以在[`godoc.org/github.com/aws/aws-sdk-go/service/sqs`](https://godoc.org/github.com/aws/aws-sdk-go/service/sqs)找到。

与任何其他 AWS 服务一样，我们需要先完成两个关键步骤：

+   获取或创建会话对象

+   为我们想要的 AWS 服务创建服务客户端

前面的步骤通过以下代码进行了覆盖：

```go
 sess, err := session.NewSession(&aws.Config{
   Region: aws.String("us-west-1"),
 })
 if err != nil {
   log.Fatal(err)
 }
 sqsSvc := sqs.New(sess)
```

在调用`NewSession()`构造函数时，前面的代码通过代码设置了区域；但是，我们也可以选择使用共享配置，如前一章所述。我在这段代码中使用了`log.Fatal()`，因为这只是测试代码，所以如果出现任何错误，我希望退出并报告错误消息。

接下来，我们需要获取消息队列的 URL。URL 很重要，因为它在 SDK 方法调用中充当消息队列的唯一标识符。我们可以通过 AWS 控制台 SQS 页面获取 URL，当选择队列时，队列的 URL 将显示在详细信息选项卡中，也可以通过使用我们创建队列时选择的队列名称来通过代码获取 URL。在我的情况下，我称我的队列为`eventqueue`；所以，让我们看看如何通过我们的代码从该名称获取 URL：

```go
  QUResult, err := sqsSvc.GetQueueUrl(&sqs.GetQueueUrlInput{
    QueueName: aws.String("eventqueue"),
  })
  if err != nil {
    log.Fatal(err)
  }
```

`QUResult`对象是`*GetQueueUrlOutput`类型的，它是指向包含`*string`类型的`QueueUrl`字段的结构体的指针。如果`GetQueueUrl()`方法成功执行，该字段应该包含我们的队列 URL。

太好了！现在我们有了队列的 URL，我们准备通过消息队列发送一些数据。但在这样做之前，我们需要了解一些重要的定义，以理解即将到来的代码。

+   **消息主体***:* 消息主体只是我们试图发送的核心消息。例如，如果我想通过 SQS 发送一个 hello 消息，那么消息主体将是 hello。

+   **消息属性***:* 消息属性是一组结构化的元数据项。您可以简单地将它们视为您可以定义并与消息一起发送的键值对列表。消息属性是可选的；但是，它们可能非常有用，因为它们允许发送比纯文本更结构化和复杂的消息。消息属性允许我们在开始处理消息主体之前了解消息可能包含的内容。我们可以在每条消息中包含多达 10 个消息属性。消息属性支持三种主要数据类型：字符串、数字和二进制。二进制类型表示二进制数据，如压缩文件和图像。

现在，让我们回到我们的示例代码；假设我们想通过 SQS 发送一条消息给我们的事件应用，表示某些音乐会的客户预订；我们的消息将具有以下属性：

+   **消息属性**：我们希望有两个消息属性：

+   `message_type`：我们尝试发送的消息类型——在我们的情况下，此属性的值将是"RESERVATION"

+   `Count`：包含在此消息中的预订数量

+   **消息正文**：这包括以 JSON 格式表示的预订数据。数据包括预订音乐会的客户姓名和事件名称（在这种情况下是音乐会）

以下是代码的样子：

```go
sendResult, err := sqsSvc.SendMessage(&sqs.SendMessageInput{
  MessageAttributes: map[string]*sqs.MessageAttributeValue{
    "message_type": &sqs.MessageAttributeValue{
      DataType: aws.String("String"),
      StringValue: aws.String("RESERVATION"),
    },
    "Count": &sqs.MessageAttributeValue{
      DataType: aws.String("Number"),
      StringValue: aws.String("2"),
    },
  },
  MessageBody: aws.String("[{customer:'Kevin S',event:'Pink Floyd Concert'},{customer:'Angela      T',event:'Cold Play Concert'}]"),
  QueueUrl: QUResult.QueueUrl,
})
```

上述代码使用`SendMessage()`方法发送消息。`SendMessage()`接受`*SendMessageInput{}`类型的参数，我们在其中定义消息属性、消息正文，并标识队列 URL。

之后，我们可以检查是否发生了任何错误。我们可以通过以下代码获取我们创建的消息的 ID：

```go
  if err != nil {
    log.Fatal(err)
  }
  log.Println("Message sent successfully", *sendResult.MessageId)
```

完美！有了这段示例代码，我们现在知道如何通过 SQS 发送消息。现在，让我们学习如何接收它们。

在我们开始查看消息接收代码之前，有一些概念需要涵盖和问题需要回答。让我们假设我们有一个微服务架构，超过一个微服务从 SQS 消息队列中读取消息。一个重要的问题是，我们的服务接收到消息后该怎么办？该消息之后是否允许其他服务接收？这两个问题的答案取决于消息的目的。如果消息应该被消费和处理一次，那么我们需要确保第一个正确接收到消息的服务应该从队列中删除它。

在 AWS SQS 的世界中，当标准队列中的消息被接收时，消息不会从队列中删除。相反，我们需要在接收消息后明确从队列中删除消息，以确保它消失，如果这是我们的意图。然而，还有另一个复杂之处。假设微服务 A 接收了一条消息并开始处理它。然而，在微服务 A 删除消息之前，微服务 B 接收了消息并开始处理它，这是我们不希望发生的。

为了避免这种情况，SQS 引入了一个叫做**可见性超时**的概念。可见性超时简单地使消息在被一个消费者接收后一段时间内不可见。这个超时给了我们一些时间来决定在其他消费者看到并处理消息之前该怎么处理它。

一个重要的说明是，并不总是能保证不会收到重复的消息。原因是因为 SQS 队列通常分布在多个服务器之间。有时删除请求无法到达服务器，因为服务器离线，这意味着尽管有删除请求，消息可能仍然存在。

在 SQS 的世界中，另一个重要概念是长轮询或等待时间。由于 SQS 是分布式的，可能偶尔会有一些延迟，有些消息可能接收得比较慢。如果我们关心即使消息接收慢也要接收到消息，那么在监听传入消息时我们需要等待更长的时间。

以下是一个示例代码片段，显示从队列接收消息：

```go
  QUResult, err := sqsSvc.GetQueueUrl(&sqs.GetQueueUrlInput{
    QueueName: aws.String("eventqueue"),
  })
  if err != nil {
    log.Fatal(err)
  }
  recvMsgResult, err := sqsSvc.ReceiveMessage(&sqs.ReceiveMessageInput{
    AttributeNames: []*string{
      aws.String(sqs.MessageSystemAttributeNameSentTimestamp),
    },
    MessageAttributeNames: []*string{
      aws.String(sqs.QueueAttributeNameAll),
    },
    QueueUrl: QUResult.QueueUrl,
    MaxNumberOfMessages: aws.Int64(10),
    WaitTimeSeconds: aws.Int64(20),
  })
```

在上述代码中，我们尝试监听来自我们创建的 SQS 队列的传入消息。我们像之前一样使用`GetQueueURL()`方法来检索队列 URL，以便在`ReceiveMessage()`方法中使用。

`ReceiveMessage()`方法允许我们指定我们想要捕获的消息属性（我们之前讨论过的），以及一般的系统属性。系统属性是消息的一般属性，例如随消息一起传递的时间戳。在前面的代码中，我们要求所有消息属性，但只要消息时间戳系统属性。

我们设置单次调用中要接收的最大消息数为 10。重要的是要指出，这只是请求的最大消息数，因此通常会收到更少的消息。最后，我们将轮询时间设置为最多 20 秒。如果我们在 20 秒内收到消息，调用将返回捕获的消息，而无需等待。

现在，我们应该怎么处理捕获的消息呢？为了展示代码，假设我们想要将消息正文和消息属性打印到标准输出。之后，我们删除这些消息。这是它的样子：

```go
for i, msg := range recvMsgResult.Messages {
    log.Println("Message:", i, *msg.Body)
    for key, value := range msg.MessageAttributes {
      log.Println("Message attribute:", key, aws.StringValue(value.StringValue))
    }

    for key, value := range msg.Attributes {
      log.Println("Attribute: ", key, *value)
    }

    log.Println("Deleting message...")
    resultDelete, err := sqsSvc.DeleteMessage(&sqs.DeleteMessageInput{
      QueueUrl: QUResult.QueueUrl,
      ReceiptHandle: msg.ReceiptHandle,
    })
    if err != nil {
      log.Fatal("Delete Error", err)
    }
    log.Println("Message deleted... ")
  }
```

请注意，在前面的代码中，我们在`DeleteMessage()`方法中使用了一个名为`msg.ReceiptHandle`的对象，以便识别我们想要删除的消息。ReceiptHandle 是我们从队列接收消息时获得的对象；这个对象的目的是允许我们在接收消息后删除消息。每当接收到一条消息时，都会创建一个 ReceiptHandle。

此外，在前面的代码中，我们接收了消息然后对其进行了解析：

+   我们调用`msg.Body`来检索我们消息的正文

+   我们调用`msg.MessageAttributes`来获取我们消息的消息属性

+   我们调用`msg.Attributes`来获取随消息一起传递的系统属性

有了这些知识，我们就有足够的知识来为我们的`events`应用程序实现一个 SQS 消息队列发射器和监听器。在之前的章节中，我们为应用程序中的消息队列创建了两个关键接口需要实现。其中一个是发射器接口，负责通过消息队列发送消息。另一个是监听器接口，负责从消息队列接收消息。

作为一个快速的复习，发射器接口的样子是什么：

```go
package msgqueue

// EventEmitter describes an interface for a class that emits events
type EventEmitter interface {
  Emit(e Event) error
}
```

此外，以下是监听器接口的样子：

```go
package msgqueue

// EventListener describes an interface for a class that can listen to events.
type EventListener interface {
 Listen(events ...string) (<-chan Event, <-chan error, error)
 Mapper() EventMapper
}
```

`Listen`方法接受一个事件名称列表，然后将这些事件以及尝试通过消息队列接收事件时发生的任何错误返回到一个通道中。这被称为通道生成器模式。

因此，为了支持 SQS 消息队列，我们需要实现这两个接口。让我们从`Emitter`接口开始。我们将在`./src/lib/msgqueue`内创建一个新文件夹；新文件夹的名称将是`sqs`。在`sqs`文件夹内，我们创建两个文件——`emitter.go`和`listener.go`。`emitter.go`是我们将实现发射器接口的地方。

我们首先创建一个新对象来实现发射器接口——这个对象被称为`SQSEmitter`。它将包含 SQS 服务客户端对象，以及我们队列的 URL：

```go
type SQSEmitter struct {
  sqsSvc *sqs.SQS
  QueueURL *string
}
```

然后，我们需要为我们的发射器创建一个构造函数。在构造函数中，我们将从现有会话或新创建的会话中创建 SQS 服务客户端。我们还将利用`GetQueueUrl`方法来获取我们队列的 URL。这是它的样子：

```go
func NewSQSEventEmitter(s *session.Session, queueName string) (emitter msgqueue.EventEmitter, err error) {
  if s == nil {
    s, err = session.NewSession()
    if err != nil {
      return
    }
  }
  svc := sqs.New(s)
  QUResult, err := svc.GetQueueUrl(&sqs.GetQueueUrlInput{
    QueueName: aws.String(queueName),
  })
  if err != nil {
    return
  }
  emitter = &SQSEmitter{
    sqsSvc: svc,
    QueueURL: QUResult.QueueUrl,
  }
  return
}
```

下一步是实现发射器接口的`Emit()`方法。我们将发射的消息应具有以下属性：

+   它将包含一个名为`event_name`的单个消息属性，其中将保存我们试图发送的事件的名称。如前所述，在本书中，事件名称描述了我们的应用程序试图处理的事件类型。我们有三个事件名称 - `eventCreated`、`locationCreated`和`eventBooked`。请记住，这里的`eventCreated`和`eventBooked`是指应用程序事件（而不是消息队列事件）的创建或预订，例如音乐会或马戏团表演。

+   它将包含一个消息正文，其中将保存事件数据。消息正文将以 JSON 格式呈现。

代码将如下所示：

```go
func (sqsEmit *SQSEmitter) Emit(event msgqueue.Event) error {
  data, err := json.Marshal(event)
  if err != nil {
    return err
  }
  _, err = sqsEmit.sqsSvc.SendMessage(&sqs.SendMessageInput{
    MessageAttributes: map[string]*sqs.MessageAttributeValue{
      "event_name": &sqs.MessageAttributeValue{
        DataType: aws.String("string"),
        StringValue: aws.String(event.EventName()),
      },
    },
    MessageBody: aws.String(string(data)),
    QueueUrl: sqsEmit.QueueURL,
  })
  return err
}
```

有了这个，我们就有了一个用于发射器接口的 SQS 消息队列实现。现在，让我们讨论监听器接口。

监听器接口将在`./src/lib/msgqueue/listener.go`文件中实现。我们从将实现接口的对象开始。对象名称是`SQSListener`。它将包含消息队列事件类型映射器、SQS 客户端服务对象、队列的 URL、从一个 API 调用中接收的消息的最大数量、消息接收的等待时间和可见性超时。这将如下所示：

```go
type SQSListener struct {
  mapper msgqueue.EventMapper
  sqsSvc *sqs.SQS
  queueURL *string
  maxNumberOfMessages int64
  waitTime int64
  visibilityTimeOut int64
}
```

我们将首先从构造函数开始；代码将类似于我们为发射器构建的构造函数。我们将确保我们有一个 AWS 会话对象、一个服务客户端对象，并根据队列名称获取我们队列的 URL：

```go
func NewSQSListener(s *session.Session, queueName string, maxMsgs, wtTime, visTO int64) (listener msgqueue.EventListener, err error) {
  if s == nil {
    s, err = session.NewSession()
    if err != nil {
      return
    }
  }
  svc := sqs.New(s)
  QUResult, err := svc.GetQueueUrl(&sqs.GetQueueUrlInput{
    QueueName: aws.String(queueName),
  })
  if err != nil {
    return
  }
  listener = &SQSListener{
    sqsSvc: svc,
    queueURL: QUResult.QueueUrl,
    mapper: msgqueue.NewEventMapper(),
    maxNumberOfMessages: maxMsgs,
    waitTime: wtTime,
    visibilityTimeOut: visTO,
  }
  return
}
```

之后，我们需要实现`listener`接口的`Listen()`方法。该方法执行以下操作：

+   它将接收到的事件名称列表作为参数

+   它监听传入的消息

+   当它接收到消息时，它会检查消息事件名称并将其与作为参数传递的事件名称列表进行比较

+   如果接收到不属于请求事件的消息，它将被忽略

+   如果接收到属于已知事件的消息，它将通过“Event”类型的 Go 通道传递到外部世界

+   通过 Go 通道传递后，接受的消息将被删除

+   发生的任何错误都会通过另一个 Go 通道传递给错误对象

让我们暂时专注于将监听和接收消息的代码。我们将创建一个名为`receiveMessage()`的新方法。以下是它的分解：

1.  首先，我们接收消息并将任何错误传递到 Go 错误通道：

```go
func (sqsListener *SQSListener) receiveMessage(eventCh chan msgqueue.Event, errorCh chan error, events ...string) {
  recvMsgResult, err := sqsListener.sqsSvc.ReceiveMessage(&sqs.ReceiveMessageInput{
    MessageAttributeNames: []*string{
      aws.String(sqs.QueueAttributeNameAll),
    },
    QueueUrl: sqsListener.queueURL,
    MaxNumberOfMessages: aws.Int64(sqsListener.maxNumberOfMessages),
    WaitTimeSeconds: aws.Int64(sqsListener.waitTime),
    VisibilityTimeout: aws.Int64(sqsListener.visibilityTimeOut),
  })
  if err != nil {
    errorCh <- err
  }
```

1.  然后，我们逐条查看接收到的消息并检查它们的消息属性 - 如果事件名称不属于请求的事件名称列表，我们将通过移动到下一条消息来忽略它：

```go
bContinue := false
for _, msg := range recvMsgResult.Messages {
  value, ok := msg.MessageAttributes["event_name"]
  if !ok {
    continue
  }
  eventName := aws.StringValue(value.StringValue)
  for _, event := range events {
    if strings.EqualFold(eventName, event) {
      bContinue = true
      break
    }
  }

  if !bContinue {
    continue
  }
```

1.  如果我们继续，我们将检索消息正文，然后使用我们的事件映射器对象将其翻译为我们在外部代码中可以使用的事件类型。事件映射器对象是在第四章中创建的，*使用消息队列的异步微服务架构*；它只是获取事件名称和事件的二进制形式，然后将一个事件对象返回给我们。之后，我们获取事件对象并将其传递到事件通道。如果我们检测到错误，我们将错误传递到错误通道，然后移动到下一条消息：

```go
message := aws.StringValue(msg.Body)
event, err := sqsListener.mapper.MapEvent(eventName, []byte(message))
if err != nil {
  errorCh <- err
  continue
}
eventCh <- event
```

1.  最后，如果我们在没有错误的情况下到达这一点，那么我们知道我们成功处理了消息。因此，下一步将是删除消息，以便其他人不会处理它：

```go
    _, err = sqsListener.sqsSvc.DeleteMessage(&sqs.DeleteMessageInput{
      QueueUrl: sqsListener.queueURL,
      ReceiptHandle: msg.ReceiptHandle,
    })

    if err != nil {
      errorCh <- err
    }
  }
}
```

这很棒。然而，你可能会想，为什么我们没有直接将这段代码放在`Listen()`方法中呢？答案很简单：我们这样做是为了清理我们的代码，避免一个庞大的方法。这是因为我们刚刚覆盖的代码片段需要在循环中调用，以便我们不断地从消息队列中接收消息。

现在，让我们看一下`Listen()`方法。该方法将需要在 goroutine 内的循环中调用`receiveMessage()`。需要 goroutine 的原因是，否则`Listen()`方法会阻塞其调用线程。这是它的样子：

```go
func (sqsListener *SQSListener) Listen(events ...string) (<-chan msgqueue.Event, <-chan error, error) {
  if sqsListener == nil {
    return nil, nil, errors.New("SQSListener: the Listen() method was called on a nil pointer")
  }
  eventCh := make(chan msgqueue.Event)
  errorCh := make(chan error)
  go func() {
    for {
      sqsListener.receiveMessage(eventCh, errorCh)
    }
  }()

  return eventCh, errorCh, nil
}
```

前面的代码首先确保`*SQSListener`对象不为空，然后创建用于将`receiveMessage()`方法的结果传递给外部世界的 events 和 errors Go 通道。

# AWS API 网关

我们深入云原生应用程序的下一步是进入 AWS API 网关。如前所述，AWS API 网关是一个托管服务，允许开发人员为其应用程序构建灵活的 API。在本节中，我们将介绍有关该服务的实际介绍以及如何使用它的内容。

与我们迄今为止涵盖的其他服务类似，我们将通过 AWS 控制台创建一个 API 网关。首先，像往常一样，访问并登录到[aws.amazon.com](http://aws.amazon.com)的 AWS 控制台。

第二步是转到主页，然后从应用服务下选择 API Gateway：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/c4769d0c-1552-453c-97eb-858fb84c6788.png)

接下来，我们需要从左侧选择 API，然后点击创建 API。这将开始创建一个新的 API 供我们的应用使用的过程：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/ca26727e-794e-46a8-a48b-b373300c0a3a.png)

然后，我们可以选择我们的新 API 的名称，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/6fecc87a-19a7-464a-bc6a-deea81ef9aba.png)

现在，在创建 API 之后，我们需要在 AWS API 网关和嵌入在我们的 MyEvents 应用程序中的 RESTful API 的地址之间创建映射。MyEvents 应用程序包含多个微服务。其中一个微服务是事件服务；它支持可以通过其 RESTful API 激活的多个任务。作为复习，这里是 API 任务的快速摘要和它们相对 URL 地址的示例：

1.  **搜索事件**：

+   **ID**：相对 URL 是`/events/id/3434`，方法是`GET`，HTTP 主体中不需要数据。

+   **名称**：相对 URL 是`/events/name/jazz_concert`，方法是`GET`，HTTP 主体中不需要数据。

1.  **一次检索所有事件**：相对 URL 是`/events`，方法是`GET`，HTTP 主体中不需要数据。

1.  **创建新事件**：相对 URL 是`/events`，方法是`POST`，HTTP 主体中期望的数据需要是我们想要添加的新事件的 JSON 表示。假设我们想要添加在美国演出的`aida 歌剧`。那么 HTTP 主体会是这样的：

```go
{
    name: "opera aida",
    startdate: 768346784368,
    enddate: 43988943,
    duration: 120, //in minutes
    location:{
        id : 3 , //=>assign as an index
        name: "West Street Opera House",
        address: "11 west street, AZ 73646",
        country: "U.S.A",
        opentime: 7,
        clostime: 20
        Hall: {
            name : "Cesar hall",
            location : "second floor, room 2210",
            capacity: 10
        }
    }
}
```

让我们逐个探索事件微服务 API 的任务，并学习如何让 AWS API 网关充当应用程序的前门。

从前面的描述中，我们有三个相对 URL：

+   `/events/id/{id}`，其中`{id}`是一个数字。我们支持使用该 URL 进行`GET` HTTP 请求。

+   `/events/name/{name}`，其中`{name}`是一个字符串。我们支持使用该 URL 进行`GET` HTTP 请求。

+   `/events`，我们支持使用此 URL 进行`GET`和`POST`请求。

为了在我们的 AWS API 网关中表示这些相对 URL 和它们的方法，我们需要执行以下操作：

1.  创建一个名为`events`的新资源。首先访问我们新创建的 API 页面。然后，通过点击操作并选择创建资源来创建一个新资源：![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/0f3fdfa1-1a5b-484e-899b-6d84c1f92329.png)

1.  确保在新资源上设置名称和路径为`events`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/8f64e9d5-4c76-44f1-8619-dcb9dd28cf83.png)

1.  然后，选择新创建的`events`资源并创建一个名为`id`的新资源。再次选择`events`资源，但这次创建一个名为`name`的新资源。这是它的样子：![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/c3ee5533-1b7b-4d69-bf25-4fc82b937394.png)

1.  选择`id`资源，然后创建一个新的资源。这一次，再次将资源名称命名为`id`；但是，资源路径需要是`{id}`。这很重要，因为它表明`id`是一个可以接受其他值的参数。这意味着这个资源可以表示一个相对 URL，看起来像这样`/events/id/3232`：![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/aac14ca8-f2ab-409e-8c10-9b70f2b7b08c.png)

1.  与步骤 4 类似，我们将选择`name`资源，然后在其下创建另一个资源，资源名称为`name`，资源路径为`{name}`。这是最终的样子：![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/26f4531e-fb61-48cf-b537-ede864da0d7e.png)

1.  现在，这应该涵盖了我们所有的相对 URL。我们需要将支持的 HTTP 方法附加到相应的资源上。首先，我们将转到`events`资源，然后将`GET`方法以及`POST`方法附加到它上面。为了做到这一点，我们需要点击 s，然后选择创建方法：![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/136c1c91-6bc1-4cb8-b5a0-1ee19ebc5beb.png)

1.  然后我们可以选择 GET 作为方法类型：![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/fb182a15-d591-4060-aafd-36923b802351.png)

1.  然后我们选择 HTTP 作为集成类型。从那里，我们需要设置端点 URL。端点 URL 需要是与此资源对应的 API 端点的绝对路径。在我们的情况下，因为我们在'events'资源下，该资源在'events'微服务上的绝对地址将是`<EC2 DNS Address>/events`。假设 DNS 是`http://ec2.myevents.com`；这将使绝对路径为`http://ec2.myevents.com/events`。这是这个配置的样子：![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/7f554357-b403-4375-b3a6-8b06db91e1d6.png)

1.  我们将重复上述步骤；但是，这一次我们将创建一个`POST`方法。

1.  我们选择`{id}`资源，然后创建一个新的`GET`方法。`EndPoint` URL 需要包括`{id}`；这是它的样子：![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/9eb620b8-1220-4b85-8857-cfb8a0c7dc39.png)

1.  我们将重复使用`{name}`资源进行相同的步骤；这是 Endpoint URL 的样子：`http://ec2.myevents.com/events/name/{name}`。

完美！通过这样，我们为我们的事件微服务 API 创建了 AWS API 网关映射。我们可以使用相同的技术在我们的 MyEvents API 中添加更多资源，这些资源将指向属于 MyEvents 应用程序的其他微服务。下一步是部署 API。我们需要做的第一件事是创建一个新的阶段。阶段是一种标识已部署的可由用户调用的 RESTful API 的方式。在部署 RESTful API 之前，我们需要创建一个阶段。要部署 API，我们需要点击操作，然后点击部署 API：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/c7f19c7c-5bd3-48b3-b059-fc6327340fdc.png)

如果我们还没有阶段，我们需要选择[New Stage]作为我们的部署阶段，然后选择一个阶段名称，最后点击部署。我将我的阶段命名为`beta`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/d4035639-deb8-48ed-85a4-bfd9e61d9a85.png)

一旦我们将 RESTful API 资源部署到一个阶段，我们就可以开始使用它。我们可以通过导航到阶段，然后点击所需资源来查找我们的 AWS API 网关门到我们的事件微服务的 API URL。在下图中，我们选择了 events 资源，API URL 可以在右侧找到：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/747e1c87-2da3-44a7-bbbb-90e4df64b407.png)

# DynamoDB

DynamoDB 是 AWS 生态系统中非常重要的一部分；它通常作为众多云原生应用程序的后端数据库。DynamoDB 是一个分布式高性能数据库，托管在云中，由 AWS 作为服务提供。

# DynamoDB 组件

在讨论如何编写可以与 DynamoDB 交互的代码之前，我们需要首先了解一些关于数据库的重要概念。DynamoDB 由以下组件组成：

+   表：与典型的数据库引擎一样，DynamoDB 将数据存储在一组表中。例如，在我们的 MyEvents 应用程序中，我们可以有一个“事件”表，用于存储诸如音乐会名称和开始日期之类的事件信息。同样，我们还可以有一个“预订”表，用于存储我们用户的预订信息。我们还可以有一个“用户”表，用于存储我们用户的信息。

+   项目：项目只是 DynamoDB 表的行。项目内的信息称为属性。如果我们以“事件”表为例，项目将是该表中的单个事件。同样，如果我们以“用户”表为例，每个项目都是一个用户。表中的每个项目都需要一个唯一标识符，也称为主键，以区分该项目与表中所有其他项目。

+   属性：如前所述，属性代表项目内的信息。每个项目由一个或多个属性组成。您可以将属性视为数据的持有者。每个属性由属性名称和属性值组成。如果我们以“事件”表为例，每个“事件”项目将具有一个`ID`属性来表示事件 ID，一个“名称”属性来表示事件名称，一个“开始日期”属性，一个“结束日期”属性等等。

项目主键是项目中必须预先定义的唯一属性。但是，项目中的任何其他属性都不需要预定义。这使得 DynamoDB 成为一个无模式数据库，这意味着在填充表格数据之前不需要定义数据库表的结构。

DynamoDB 中的大多数属性都是标量的。这意味着它们只能有一个值。标量属性的一个示例是字符串属性或数字属性。有些属性可以是嵌套的，其中一个属性可以承载另一个属性，依此类推。属性允许嵌套到 32 级深度。

# 属性值数据类型

如前所述，每个 DynamoDB 属性由属性名称和属性值组成。属性值又由两部分组成：值的数据类型名称和值数据。在本节中，我们将重点关注数据类型。

有三个主要的数据类型类别：

+   标量类型：这是最简单的数据类型；它表示单个值。标量类型类别包括以下数据类型名称：

+   `S`：这只是一个字符串类型；它利用 UTF-8 编码；字符串的长度必须在零到 400 KB 之间。

+   `N`：这是一个数字类型。它们可以是正数、负数或零。它们可以达到 38 位精度。

+   `B`：二进制类型的属性。二进制数据包括压缩文本、加密数据或图像。长度需要在 0 到 400 KB 之间。我们的应用程序必须在将二进制数据值发送到 DynamoDB 之前以 base64 编码格式对二进制数据进行编码。

+   `BOOL`：布尔属性。它可以是 true 或 false。

+   文档类型：文档类型是一个具有嵌套属性的复杂结构。此类别下有两个数据类型名称：

+   `L`：列表类型的属性。此类型可以存储有序集合的值。对可以存储在列表中的数据类型没有限制。

+   `Map`：地图类型将数据存储在无序的名称-值对集合中。

+   集合类型：集合类型可以表示多个标量值。集合类型中的所有项目必须是相同类型。此类别下有三个数据类型名称：

+   `NS`：一组数字

+   `SS`：一组字符串

+   `BS`：一组二进制值

# 主键

如前所述，DynamoDB 表项中唯一需要预先定义的部分是主键。在本节中，我们将更深入地了解 DynamoDB 数据库引擎的主键。主键的主要任务是唯一标识表中的每个项目，以便没有两个项目可以具有相同的键。

DynamoDB 支持两种不同类型的主键：

+   **分区键**：这是一种简单类型的主键。它由一个称为分区键的属性组成。DynamoDB 将数据存储在多个分区中。分区是 DynamoDB 表的存储层，由固态硬盘支持。分区键的值被用作内部哈希函数的输入，生成一个确定项目将被存储在哪个分区的输出。

+   **复合键**：这种类型的键由两个属性组成。第一个属性是我们之前讨论过的分区键，而第二个属性是所谓的'排序键'。如果您将复合键用作主键，那么多个项目可以共享相同的分区键。具有相同分区键的项目将被存储在一起。然后使用排序键对具有相同分区键的项目进行排序。排序键对于每个项目必须是唯一的。

每个主键属性必须是标量，这意味着它只能保存单个值。主键属性允许的三种数据类型是字符串、数字或二进制。

# 二级索引

DynamoDB 中的主键为我们通过它们的主键快速高效地访问表中的项目提供了便利。然而，有很多情况下，我们可能希望通过除主键以外的属性查询表中的项目。DynamoDB 允许我们创建针对非主键属性的二级索引。这些索引使我们能够在非主键项目上运行高效的查询。

二级索引只是包含来自表的属性子集的数据结构。表允许具有多个二级索引，这在查询表中的数据时提供了灵活性。

为了进一步了解二级查询，我们需要涵盖一些基本定义：

+   **基本表**：每个二级索引都属于一个表。索引所基于的表，以及索引获取数据的表，称为基本表。

+   **投影属性**：投影属性是从基本表复制到索引中的属性。DynamoDB 将这些属性与基本表的主键一起复制到索引的数据结构中。

+   **全局二级索引**：具有与基本表不同的分区键和排序键的索引。这种类型的索引被认为是`全局`的，因为对该索引执行的查询可以跨越基本表中的所有数据。您可以在创建表时或以后创建全局二级索引。

+   **本地二级索引**：一个具有与基本表相同的分区键，但不同排序键的索引。这种类型的索引是`本地`的，因为本地二级索引的每个分区都与具有相同分区键值的基本表分区相关联。您只能在创建表时同时创建本地二级索引。

# 创建表

让我们利用 AWS Web 控制台创建 DynamoDB 表，然后我们可以在代码中访问这些表。第一步是访问 AWS 管理控制台主仪表板，然后点击 DynamoDB：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/bbf657e8-3fd0-422b-bce5-0a885e5138d7.png)

点击 DynamoDB 后，我们将转到 DynamoDB 主仪表板，在那里我们可以创建一个新表：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/198c41bb-7bec-468e-bd0b-503c805615c7.png)

下一步是选择表名和主键。正如我们之前提到的，DynamoDB 中的主键可以由最多两个属性组成——分区键和排序键。假设我们正在创建一个名为`events`的表。让我们使用一个简单的主键，它只包含一个名为`ID`的`Binary`类型的分区键：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/ca49341a-0bd3-45b7-8476-66525e3d9459.png)

我们也将保留默认设置。稍后我们将重新访问一些设置，比如次要索引。配置完成后，我们需要点击创建来创建表格。然后我们将重复这个过程，创建所有其他我们想要创建的表格：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/480544e0-799f-4345-becd-7df929b5a06f.png)

一旦表格创建完成，我们现在可以通过我们的代码连接到它，编辑它，并从中读取。但是，在我们开始讨论代码之前，我们需要创建一个次要索引。为此，我们需要首先访问我们新创建的表格，选择左侧的 Tables 选项。然后，我们将从表格列表中选择`events`表。之后，我们需要选择 Indexes 选项卡，然后点击 Create Index 来创建一个新的次要索引：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/46bf125c-75b5-4d92-9907-664ff938dc5c.png)

次要索引名称需要是我们表格中希望用作次要索引的属性名称。在我们的情况下，我们希望用于查询的属性是事件名称。这个属性代表了我们需要的索引，以便在查询事件时通过它们的名称而不是它们的 ID 来运行高效的查询。创建索引对话框如下所示；让我们填写不同的字段，然后点击创建索引：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/c1356996-0d2d-423e-9014-bbd34892db27.png)

完美！通过这一步，我们现在已经准备好我们的表格了。请注意上面的屏幕截图中索引名称为`EventName-index`。我们将在后面的 Go 代码中使用该名称。

# Go 语言和 DynamoDB

亚马逊已经为 Go 语言提供了强大的包，我们可以利用它们来构建可以有效地与 DynamoDB 交互的应用程序。主要包可以在[`docs.aws.amazon.com/sdk-for-go/api/service/dynamodb/`](https://docs.aws.amazon.com/sdk-for-go/api/service/dynamodb/)找到。

在我们开始深入代码之前，让我们回顾一下我们在第二章中讨论的`DatabaseHandler`接口，*使用 Rest API 构建微服务*。这个接口代表了我们的微服务的数据库处理程序层，也就是数据库访问代码所在的地方。在`events`服务的情况下，这个接口支持了四种方法。它看起来是这样的：

```go
type DatabaseHandler interface {
  AddEvent(Event) ([]byte, error)
  FindEvent([]byte) (Event, error)
  FindEventByName(string) (Event, error)
  FindAllAvailableEvents() ([]Event, error)
}
```

在我们努力实现如何编写可以与 DynamoDB 一起工作的应用程序的实际理解的过程中，我们将实现前面的四种方法来利用 DynamoDB 作为后端数据库。

与其他 AWS 服务类似，AWS Go SDK 提供了一个服务客户端对象，我们可以用它来与 DynamoDB 交互。同样，我们需要首先获取一个会话对象，然后使用它来创建一个 DynamoDB 服务客户端对象。代码应该是这样的：

```go
  sess, err := session.NewSession(&aws.Config{
    Region: aws.String("us-west-1"),
  })
  if err != nil {
    //handler error, let's assume we log it then exit.
    log.Fatal(err)
  }
  dynamodbsvc := dynamodb.New(sess)
```

`dynamodbsvc`最终成为我们的服务客户端对象，我们可以用它来与 DynamoDB 交互。

现在，我们需要创建一个名为 dynamolayer.go 的新文件，它将存在于相对文件夹`./lib/persistence/dynamolayer`下，这是我们应用程序的一部分：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/f489a243-776b-4e69-bfef-7f9e3020517a.png)

`dynamolayer.go`文件是我们的代码所在的地方。为了实现`databasehandler`接口，我们需要遵循的第一步是创建一个`struct`类型，它将实现接口方法。让我们称这个新类型为`DynamoDBLayer`；代码如下：

```go
type DynamoDBLayer struct {
  service *dynamodb.DynamoDB
}
```

`DynamoDBLayer`结构包含一个类型为`*dynamodb.DynamoDB`的字段；这个结构字段表示 DynamoDB 的 AWS 服务客户端，这是我们在代码中与 DynamoDB 交互的关键对象类型。

下一步是编写一些构造函数来初始化`DynamoDBLayer`结构。我们将创建两个构造函数——第一个构造函数假设我们没有现有的 AWS 会话对象可用于我们的代码。它将接受一个字符串参数，表示我们的 AWS 区域（例如，`us-west-1`）。然后，它将利用该区域字符串创建一个针对该区域的会话对象。之后，会话对象将用于创建一个 DynamoDB 服务客户端对象，该对象可以分配给一个新的`DynamoDBLayer`对象。第一个构造函数将如下所示：

```go
func NewDynamoDBLayerByRegion(region string) (persistence.DatabaseHandler, error) {
  sess, err := session.NewSession(&aws.Config{
    Region: aws.String(region),
  })
  if err != nil {
    return nil, err
  }
  return &DynamoDBLayer{
    service: dynamodb.New(sess),
  }, nil
}
```

第二个构造函数是我们在已经有现有的 AWS 会话对象时会使用的构造函数。它接受会话对象作为参数，然后使用它创建一个新的 DynamoDB 服务客户端，我们可以将其分配给一个新的`DynamoDBLayer`对象。代码将如下所示：

```go
func NewDynamoDBLayerBySession(sess *session.Session) persistence.DatabaseHandler {
  return &DynamoDBLayer{
    service: dynamodb.New(sess),
  }
}
```

太好了！现在，构造函数已经完成，让我们实现`DatabaseHandler`接口方法。

在我们继续编写代码之前，我们需要先介绍两个重要的概念：

+   `*dynamoDB.AttributeValue`：这是一个结构类型，位于 dynamodb Go 包内。它表示 DynamoDB 项目属性值。

+   `dynamodbattribute`：这是一个位于 dynamodb 包下的子包。该包的文档可以在以下位置找到：

`https://docs.aws.amazon.com/sdk-for-go/api/service/dynamodb/dynamodbattribute/`。该包负责在 Go 应用程序内部将 Go 类型与`dynamoDB.AttributeValues`之间进行转换。这提供了一种非常方便的方式，将我们应用程序内部的 Go 类型转换为可以被 dynamoDB 包方法理解的类型，反之亦然。`dynamodbattribute`可以利用 marshal 和 unmarshal 方法将切片、映射、结构甚至标量值转换为`dynamoDB.AttributeValues`。

我们将从现在开始利用`dynamoDB.AttributeValue`类型的强大功能，以及`dynamodbattribute`包来编写能够与 DynamoDB 一起工作的代码。

我们将要介绍的第一个`DatabaseHandler`接口方法是`AddEvent()`方法。该方法接受一个`Event`类型的参数，然后将其作为一个项目添加到数据库中的事件表中。在我们开始介绍方法的代码之前，我们需要先了解一下我们需要利用的 AWS SDK 组件：

+   `AddEvent()`将需要使用 AWS SDK 方法`PutItem()`

+   `PutItem()`方法接受一个`PutItemInput`类型的参数

+   `PutItemInput`需要两个信息来满足我们的目的——表名和我们想要添加的项目

+   `PutItemInput`类型的表名字段是*string 类型，而项目是`map[string]*AttributeValue`类型

+   为了将我们的 Go 类型 Event 转换为`map[string]*AttributeValue`，根据前面的观点，这是我们需要为`PutItemInput`使用的项目字段类型，我们可以利用一个名为`dynamodbattribute.MarshalMap()`的方法

还有一个重要的备注我们需要介绍；以下是我们的`Event`类型的样子：

```go
type Event struct {
  ID bson.ObjectId `bson:"_id"`
  Name string 
  Duration int
  StartDate int64
  EndDate int64
  Location Location
}
```

它包含了通常需要描述诸如音乐会之类的事件的所有关键信息。然而，在使用 DynamoDB 时，`Event`类型有一个问题——在 DynamoDB 世界中，关键字`Name`是一个保留关键字。这意味着如果我们保留结构体不变，我们将无法在查询中使用 Event 结构体的 Name 字段。幸运的是，`dynamodbattribute`包支持一个名为`dynamodbav`的结构标签，它允许我们用另一个名称掩盖结构字段名。这将允许我们在 Go 代码中使用结构字段 Name，但在 DynamoDB 中以不同的名称公开它。添加结构字段后，代码将如下所示：

```go
type Event struct {
  ID bson.ObjectId `bson:"_id"`
  Name string `dynamodbav:"EventName"`
  Duration int
  StartDate int64
  EndDate int64
  Location Location
}
```

在前面的代码中，我们利用了`dynamodbav`结构标签，将`Name`结构字段定义为与 DynamoDB 交互时的`EventName`。

太好了！现在，让我们看一下`AddEvent()`方法的代码：

```go
func (dynamoLayer *DynamoDBLayer) AddEvent(event persistence.Event) ([]byte, error) {
  av, err := dynamodbattribute.MarshalMap(event)
  if err != nil {
    return nil, err
  }
  _, err = dynamoLayer.service.PutItem(&dynamodb.PutItemInput{
    TableName: aws.String("events"),
    Item: av,
  })
  if err != nil {
    return nil, err
  }
  return []byte(event.ID), nil
}
```

前面代码的第一步是将事件对象编组为`map[string]*AttributeValue`。接下来是调用属于 DynamoDB 服务客户端的`PutItem()`方法。`PutItem`接受了前面讨论过的`PutItemInput`类型的参数，其中包含了我们想要添加的表名和编组的项目数据。最后，如果没有错误发生，我们将返回事件 ID 的字节表示。

我们需要讨论的下一个`DatabaseHandler`接口方法是`FindEvent()`。该方法通过其 ID 检索事件。请记住，当我们创建`events`表时，我们将 ID 属性设置为其键。以下是我们需要了解的一些要点，以了解即将到来的代码：

+   `FindEvent()`利用了一个名为`GetItem()`的 AWS SDK 方法。

+   `FindEvent()`接受`GetItemInput`类型的参数。

+   `GetItemInput`类型需要两个信息：表名和项目键的值。

+   `GetItem()`方法返回一个名为`GetItemOutput`的结构类型，其中有一个名为`Item`的字段。`Item`字段是我们检索的数据库表项目所在的位置。

+   从数据库中获取的项目将以`map[string]*AttributeValue`类型表示。然后，我们可以利用`dynamodbattribute.UnmarshalMap()`函数将其转换为`Event`类型。

代码最终将如下所示：

```go
func (dynamoLayer *DynamoDBLayer) FindEvent(id []byte) (persistence.Event, error) {
  //create a GetItemInput object with the information we need to search for our event via it's ID attribute
  input := &dynamodb.GetItemInput{
    Key: map[string]*dynamodb.AttributeValue{
      "ID": {
        B: id,
      },
    },
    TableName: aws.String("events"),
  }
  //Get the item via the GetItem method
  result, err := dynamoLayer.service.GetItem(input)
  if err != nil {
    return persistence.Event{}, err
  }
  //Utilize dynamodbattribute.UnmarshalMap to unmarshal the data retrieved into an Event object
  event := persistence.Event{}
  err = dynamodbattribute.UnmarshalMap(result.Item, &event)
  return event, err
}
```

请注意，在前面的代码中，`GetItemInput`结构体的`Key`字段是`map[string]*AttributeValue`类型。该映射的键是属性名称，在我们的情况下是`ID`，而该映射的值是`*AttributeValue`类型，如下所示：

```go
{
  B: id,
}
```

前面代码中的`B`是`AttributeValue`中的一个结构字段，表示二进制类型，而`id`只是传递给我们的`FindEvent()`方法的字节片参数。我们使用二进制类型字段的原因是因为我们的事件表的 ID 键属性是二进制类型。

现在让我们转到事件微服务的第三个`DatabaseHandler`接口方法，即`FindEventByName()`方法。该方法通过名称检索事件。请记住，当我们之前创建`events`表时，我们将`EventName`属性设置为二级索引。我们这样做的原因是因为我们希望能够通过事件名称从`events`表中查询项目。在我们开始讨论代码之前，这是我们需要了解的关于该方法的信息：

+   `FindEventByName()`利用了一个名为`Query()`的 AWS SDK 方法来查询数据库。

+   `Query()`方法接受`QueryInput`类型的参数，其中需要四个信息：

+   我们希望执行的查询，在我们的情况下，查询只是`EventName = :n`。

+   上述表达式中`:n`的值。这是一个参数，我们需要用要查找的事件的名称来填充它。

+   我们想要为我们的查询使用的索引名称。在我们的情况下，我们为 EventName 属性创建的二级索引被称为`EventName-index`。

+   我们想要运行查询的表名。

+   如果`Query()`方法成功，我们将得到我们的结果项作为 map 切片；结果项将是`[]map[string]*AttributeValue`类型。由于我们只寻找单个项目，我们可以直接检索该地图切片的第一个项目。

+   `Query()`方法返回一个`QueryOutput`结构类型的对象，其中包含一个名为`Items`的字段。`Items`字段是我们的查询结果集所在的地方。

+   然后，我们需要利用`dynamodbattribute.UnmarshalMap()`函数将`map[string]*AttributeValue`类型的项目转换为`Event`类型。

代码如下所示：

```go
func (dynamoLayer *DynamoDBLayer) FindEventByName(name string) (persistence.Event, error) {
  //Create the QueryInput type with the information we need to execute the query
  input := &dynamodb.QueryInput{
    KeyConditionExpression: aws.String("EventName = :n"),
    ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
      ":n": {
        S: aws.String(name),
      },
    },
    IndexName: aws.String("EventName-index"),
    TableName: aws.String("events"),
  }
  // Execute the query
  result, err := dynamoLayer.service.Query(input)
  if err != nil {
    return persistence.Event{}, err
  }
  //Obtain the first item from the result
  event := persistence.Event{}
  if len(result.Items) > 0 {
    err = dynamodbattribute.UnmarshalMap(result.Items[0], &event)
  } else {
    err = errors.New("No results found")
  }
  return event, err
}
```

DynamoDB 中的查询是一个重要的主题。我建议您阅读 AWS 文档，解释查询的工作原理，可以在[`docs.aws.amazon.com/amazondynamodb/latest/developerguide/Query.html`](http://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Query.html)找到。

我们将在本章讨论的最后一个`DatabaseHandler`接口方法是`FindAllAvailableEvents()`方法。这个方法检索 DynamoDB 中'events'表的所有项目。在深入代码之前，我们需要了解以下内容：

+   `FindAllAvailableEvents()`需要利用一个名为`Scan()`的 AWS SDK 方法。这个方法执行扫描操作。扫描操作可以简单地定义为遍历表中的每个项目或者二级索引中的每个项目的读取操作。

+   `Scan()`方法需要一个`ScanInput`结构类型的参数。

+   `ScanInput`类型需要知道表名才能执行扫描操作。

+   `Scan()`方法返回一个`ScanOutput`结构类型的对象。`ScanOutput`结构包含一个名为`Items`的字段，类型为`[]map[string]*AttributeValue`。这就是扫描操作的结果所在的地方。

+   `Items`结构字段可以通过`dynamodbattribute.UnmarshalListofMaps()`函数转换为`Event`类型的切片。

代码如下所示：

```go
func (dynamoLayer *DynamoDBLayer) FindAllAvailableEvents() ([]persistence.Event, error) {
  // Create the ScanInput object with the table name
  input := &dynamodb.ScanInput{
    TableName: aws.String("events"),
  }

  // Perform the scan operation
  result, err := dynamoLayer.service.Scan(input)
  if err != nil {
    return nil, err
  }

  // Obtain the results via the unmarshalListofMaps function
  events := []persistence.Event{}
  err = dynamodbattribute.UnmarshalListOfMaps(result.Items, &events)
  return events, err
}
```

关于扫描操作的一个重要说明是，由于在生产环境中，扫描操作可能返回大量结果，有时建议利用我们在前一章中提到的 AWS SDK 的分页功能来进行扫描。分页功能允许您的操作结果分页显示，然后您可以进行迭代。扫描分页可以通过`ScanPages()`方法执行。

# 摘要

在本章中，我们深入了解了 AWS 世界中一些最受欢迎的服务。到目前为止，我们已经掌握了足够的知识，可以构建能够利用 AWS 为云原生应用程序提供的一些关键功能的生产级 Go 应用程序。

在下一章中，我们将进一步学习构建 Go 云原生应用程序的知识，涵盖持续交付的主题。


# 第九章：持续交付

在之前的三章中，您了解了现代容器技术和云环境，如何从您的应用程序（或更准确地说，MyEvents 应用程序）创建容器映像，以及如何将它们部署到这些环境中。

在本章中，您将学习如何为您的应用程序采用**持续集成**（**CI**）和**持续交付**（**CD**）。CI 描述了一种实践，即您持续构建和验证您的软件项目（理想情况下，对软件的每一次更改都进行构建和验证）。CD 通过在非常短的发布周期内（在这种情况下，当然是进入云环境）不断部署您的应用程序来扩展这种方法。

这两种方法都需要高度自动化才能可靠地工作，涉及到应用程序的构建和部署过程。在之前的章节中，我们已经看过您如何使用容器技术部署您的应用程序。由于 Docker 和 Kubernetes 等技术很容易自动化，它们通常与 CD 非常好地集成。

在本章的过程中，您将学习如何为采用 CI 和 CD 设置您的项目（例如，通过设置适当的版本控制和依赖管理）。我们还将介绍一些流行的工具，您可以使用这些工具在应用程序代码更改时自动触发新的构建和发布。

我们将在本章中涵盖以下主题：

+   在版本控制中管理 Go 项目

+   使用依赖捆绑进行可重复构建

+   使用 Travis CI 和/或 GitLab 自动构建您的应用程序

+   自动将您的应用程序部署到 Kubernetes 集群

# 设置您的项目

在实际为我们的项目实施持续交付之前，让我们先做一些准备工作。稍后，这些准备工作将使我们将要使用的工具更容易地以自动化的方式构建和部署您的应用程序。

# 设置版本控制

在自动构建您的应用程序之前，您需要一个存储应用程序源代码的地方。这通常是**版本控制系统**（**VCS**）的工作。通常情况下，使您能够进行持续交付的工具与版本控制系统紧密集成，例如，通过在源代码更改时触发应用程序的新构建和部署。

如果您还没有自己做过这个，那么您现在的第一步应该是将您现有的代码库放入 VCS 中。在本例中，我们将使用当前事实上的标准 VCS，即 Git。尽管还有许多其他版本控制系统，但 Git 是最广泛采用的；您会发现许多提供商和工具为您提供 Git 存储库作为托管服务或自托管。此外，许多（如果不是大多数）CD 工具都与 Git 集成。

在本章的其余部分，我们将假设您熟悉 Git 的基本工作原理。如果您希望了解如何使用 Git，我们推荐 Packt 出版的*Git: Mastering Version Control*一书，作者是*Ferdinando Santacroce 等人*。

我们还假设您有两个远程 Git 存储库可用，您可以将 Go 应用程序源代码和前端应用程序源代码推送到这些存储库。对于我们将要使用的第一个持续交付工具，我们将假设您的存储库托管在 GitHub 的以下 URL：

+   `git+ssh://git@github.com/<user>/myevents.git`

+   `git+ssh://git@github.com/<user>/myevents-frontend.git`

当然，实际的存储库 URL 将根据您的用户名而变化。在以下示例中，我们将始终使用`<user>`作为您的 GitHub 用户名的占位符，因此请记住在必要时用您的实际用户名替换它。

您可以通过在本地机器上设置一个本地的 Git 仓库来跟踪源代码的更改。要初始化一个新的 Git 仓库，请在 Go 项目的根目录中运行以下命令（通常在 GOPATH 目录中的`todo.com/myevents`）：

```go
$ git init . 
```

这将设置一个新的 Git 存储库，但尚未将任何文件添加到版本控制中。在实际将任何文件添加到存储库之前，请配置一个`.gitignore`文件，以防止 Git 将您的编译文件添加到版本控制中：

```go
/eventservice/eventservice 
/bookingservice/bookingservice 
```

创建`.gitignore`文件后，运行以下命令将当前代码库添加到版本控制系统中：

```go
$ git add . 
$ git commit -m "Initial commit" 
```

接下来，使用`git remote`命令配置远程存储库，并使用`git push`推送您的源代码：

```go
$ git remote add origin ssh://git@github.com/<user>/myevents.git 
$ git push origin master 
```

拥有一个可工作的源代码存储库是构建持续集成/交付流水线的第一步。在接下来的步骤中，我们将配置 CI/CD 工具，以便在您将新代码推送到远程 Git 存储库的主分支时构建和部署您的应用程序。

使用相同的 Git 命令为您的前端应用程序创建一个新的 Git 存储库，并将其推送到 GitHub 上的远程存储库。

# 将您的依赖项放入 vendor 中

到目前为止，我们只是使用`go get`命令安装了 MyEvents 应用程序所需的 Go 库（例如`gopkg.in/mgo.v2`或`github.com/gorilla/mux`包）。尽管这对开发来说效果还不错，但使用`go get`安装依赖有一个显著的缺点，即每次在尚未下载的包上运行`go get`时，它将获取该库的最新版本（从技术上讲，是相应源代码库的最新*master*分支）。这可能会产生不好的后果；想象一下，您在某个时间点克隆了您的存储库，并使用`go get ./...`安装了所有依赖项。一周后，您重复这些步骤，但现在可能会得到完全不同版本的依赖项（积极维护和开发的库可能每天都会有数十个新的提交到其主分支）。如果其中一个更改改变了库的 API，这可能导致您的代码从一天到另一天无法再编译。

为了解决这个问题，Go 1.6 引入了**vendoring**的概念。使用 vendoring 允许您将项目所需的库复制到包内的`vendor/`目录中（因此，在我们的情况下，`todo.com/myevents/vendor/`将包含诸如`todo.com/myevents/vendor/github.com/gorilla/mux/`的目录）。在运行`go build`编译包时，`vendor/`目录中的库将优先于 GOPATH 中的库。然后，您可以简单地将`vendor/`目录与应用程序代码一起放入版本控制，并在克隆源代码存储库时进行可重复的构建。

当然，手动将库复制到包的`vendor/`目录中很快就变得乏味。通常，这项工作是由**依赖管理器**完成的。目前，Go 有多个依赖管理器，最流行的是**Godep**和**Glide**。这两者都是社区项目；一个官方的依赖管理器，简称为**dep**，目前正在开发中，并且已经被认为是安全的用于生产，但在撰写本书时，仍被指定为实验。

您可以在[`github.com/golang/dep`](https://github.com/golang/dep)找到有关 dep 的更多信息。

在这种情况下，我们将使用 Glide 填充我们应用程序的`vendor/`目录。首先，通过运行以下命令安装 Glide：

```go
$ curl https://glide.sh/get | sh 
```

这将在您的`$GOPATH/bin`目录中放置一个 glide 可执行文件。如果您想要全局使用 glide，可以将它从那里复制到您的路径中，如下所示：

```go
$ cp $GOPATH/bin/glide /usr/local/bin/glide 
```

Glide 的工作方式类似于您可能从其他编程语言中了解的包管理器（例如，Node.js 的 npm 或 PHP 的 Compose）。它通过从包目录中读取 `glide.yaml` 文件来操作。在此文件中，您声明应用程序的所有依赖项，并可以选择为 Glide 安装这些库提供特定版本。要从现有应用程序创建 `glide.yaml` 文件，请在包目录中运行 `glide init .` 命令：

```go
$ glide init . 
```

在初始化项目时，Glide 将检查应用程序使用的库，并尝试自动优化您的依赖声明。例如，如果 Glide 发现一个提供稳定版本（通常是 Git 标签）的库，它将提示您是否希望使用这些稳定版本的最新版本，而不是依赖项的（可能更不稳定）主分支。

运行 `glide init` 时，它将产生类似于此的输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/d741911d-8bef-4db2-bcc7-34bad737e478.png)

`glide init` 命令将在应用程序的根目录中创建一个 `glide.yaml` 文件，其中声明了所有必需的依赖项。对于 MyEvents 应用程序，此文件应该类似于这样：

```go
package: todo.com/myevents 
import: 
- package: github.com/Shopify/sarama 
  version: ¹.11.0 
- package: github.com/aws/aws-sdk-go 
  version: ¹.8.17 
  subpackages: 
  - service/dynamodb 
- package: github.com/gorilla/handlers 
  version: ¹.2.0 
# ... 
```

`glide.yaml` 文件声明了您的项目需要哪些依赖项。创建此文件后，您可以运行 `glide update` 命令来实际解析声明的依赖项并将它们下载到您的 `vendor/` 目录中。

如前面的屏幕截图所示，`glide update` 不仅会将 `glide.yaml` 文件中声明的依赖项下载到 `vendor/` 目录中，还会下载它们的依赖项。最终，Glide 将递归下载应用程序的整个依赖树，并将其放在 `vendor/` 目录中。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/bff51f22-c24e-4569-8fd8-5f46b49ee7eb.png)

对于它下载的每个包，Glide 将精确的版本写入一个新文件 `glide.lock`（您可以通过打开它来查看此文件，但实际上不应手动编辑）。`glide.lock` 文件允许您通过运行 `glide install` 在任何以后的时间点重建这组精确的依赖项及其精确的版本。您可以通过删除您的 `vendor/` 目录然后运行 `glide install` 来验证此行为。

拥有 `vendor/` 目录和 Glide 配置文件会给您以下两个选项：

+   您可以将整个 `vendor/` 目录与实际应用程序文件一起放入版本控制。好处是，现在任何人都可以克隆您的存储库（在这种情况下，任何人都包括想要构建和部署您的代码的 CI/CD 工具），并且所有依赖项的确切所需版本都可以立即使用。这样，从头构建应用程序实际上只是一个 `git clone` 或 `go build` 命令。缺点是，您的源代码存储库会变得更大，可能需要更多的磁盘空间来存储，克隆需要更多的时间。

+   或者，您可以将 `glide.yaml` 和 `glide.lock` 文件放入版本控制，并通过将其添加到 `.gitignore` 文件中来排除 `vendor/` 目录。好处是，这样可以使您的存储库更小，克隆速度更快。但是，在克隆存储库后，用户现在需要显式运行 `glide install` 从互联网下载 `glide.lock` 文件中指定的依赖项。

这两个选项都可以很好地工作，因此最终这是个人口味的问题。由于存储库大小和磁盘空间在这些天很少被考虑，而且因为它使构建过程显着更容易，所以我个人偏好于将整个 `vendor/` 目录放入版本控制：

```go
$ git add vendor 
$ git commit -m"Add dependencies" 
$ git push 
```

这关注了我们的后端服务，但我们还需要考虑前端应用程序。由于我们在第五章中使用 npm 来安装我们的依赖项，大部分工作已经为我们完成。有趣的是，关于是否将依赖项放入版本控制的确切论点（在这种情况下，是`node_modules/`目录而不是`vendor/`）也适用于 npm。是的，就像 Go 的`vendor/`目录一样，我更喜欢将整个`node_modules/`目录放入版本控制中：

```go
$ git add node_modules 
$ git commit -m "Add dependencies" 
$ git push 
```

明确声明项目的依赖关系（包括使用的版本）是确保可重现构建的重要一步。根据您选择是否将依赖项包含在版本控制中，用户在克隆源代码存储库后要么直接获得整个应用程序源代码（包括依赖项），要么可以通过运行`glide install`或`npm install`来轻松重建它。

现在我们已经将项目放入版本控制，并明确声明了依赖关系，我们可以看一下一些最流行的 CI/CD 工具，您可以使用它们来持续构建和部署您的应用程序。

# 使用 Travis CI

**Travis CI**是一个持续集成的托管服务。它与 GitHub 紧密耦合（这就是为什么您实际上需要在 GitHub 上拥有一个 Git 存储库才能使用 Travis CI）。它对于开源项目是免费的，这与其良好的 GitHub 集成一起，使其成为许多热门项目的首选。对于构建私有 GitHub 项目，有一个付费使用模式。

Travis 构建的配置是通过一个名为`.travis.yml`的文件完成的，该文件需要存在于存储库的根级别。基本上，这个文件可以看起来像这样：

```go
language: go 
go: 
  - 1.6 
  - 1.7 
  - 1.8 
 - 1.9
env: 
  - CGO_ENABLED=0 

install: true 
script: 
  - go build 
```

`language`属性描述了您的项目所使用的编程语言。根据您在这里提供的语言，您将在构建环境中有不同的工具可用。`go`属性描述了应该为哪些 Go 版本构建您的应用程序。对于可能被多种用户在潜在非常不同的环境中使用的库来说，测试您的代码是否适用于多个 Go 版本尤为重要。`env`属性包含应该传递到构建环境中的环境变量。请注意，我们之前在第六章中使用过`CGO_ENABLED`环境变量，*在容器中部署您的应用程序*，来指示 Go 编译器生成静态链接的二进制文件。

`install`属性描述了设置应用程序依赖项所需的步骤。如果完全省略，Travis 将自动运行`go get ./...`来下载所有依赖项的最新版本（这正是我们不想要的）。`install: true`属性实际上指示 Travis 不执行任何设置依赖项的操作，这正是我们应该采取的方式，如果您的依赖项已经包含在您的源代码存储库中。

如果您决定不在版本控制中包含您的`vendor/`目录，则安装步骤需要包含 Travis 下载 Glide 并使用它来安装项目的依赖项的说明：

```go
install: 
  - go get -v github.com/Masterminds/glide 
  - glide install 
```

`script`属性包含 Travis 应该运行的命令，以实际构建您的项目。当然，构建您的应用程序的最明显的步骤是`go build`命令。当然，您可以在这里添加额外的步骤。例如，您可以使用`go vet`命令来检查您的源代码是否存在常见错误：

```go
scripts: 
  - go vet $(go list ./... | grep -v vendor)
 - cd eventservice && go build 
  - cd bookingservice && go build 
```

`$(go list ./... | grep -v vendor)`命令是一个特殊的技巧，用于指示`go vet`不要分析包目录中的`vendor/`源代码。否则，`go vet`可能会抱怨您的项目依赖项中的许多问题，您可能不想（甚至无法）修复。

创建`.travis.yml`文件后，将其添加到版本控制并将其推送到远程存储库：

```go
$ git add .travis.yml 
$ git commit -m "Configure Travis CI" 
$ git push 
```

现在您的存储库中有一个*.travis.yml*文件，您可以为该存储库启用 Travis 构建。为此，请使用 GitHub 凭据登录[`travis-ci.org`](https://travis-ci.org)（如果您打算使用付费版，则使用[`travis-ci.com`](https://travis-ci.com)），登录后，您将找到您的公开可用 GitHub 存储库列表，以及一个开关，允许您为每个存储库启用 Travis 构建（就像以下截图中一样）：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/16b2df49-adb2-4bc2-9640-7f1178f4f7d8.png)

继续启用`myevents`和`myevents-frontend`存储库（如果其中一个存储库中没有`.travis.yml`文件也没关系）。

在 Travis 用户界面中启用项目后，下一次对存储库的 Git 推送将自动触发 Travis 上的构建。您可以通过对代码进行小的更改或只是在某个地方添加一个新的空文本文件并将其推送到 GitHub 来测试这一点。在 Travis 用户界面中，您会很快注意到项目的新构建弹出。

构建将运行一段时间（从计划构建到实际执行可能需要一段时间）。之后，您将看到构建是否成功完成或是否发生错误（在后一种情况下，您还将通过电子邮件收到通知），如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/88e50e75-5a21-4d8c-905d-1f5e5d6d0187.png)

如果您已经指定了多个要测试的 Go 版本，您将注意到每个提交都有多个构建作业（就像前面的截图中一样）。单击其中任何一个以接收详细的构建输出。如果您的构建因任何原因失败（当您推送无法通过`go vet`或甚至无法编译的代码时，这是非常有用的）。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/4724ad2c-300e-4671-af09-0060ff769771.png)

总的来说，Travis 与 GitHub 集成得非常好。在 GitHub 用户界面中，您还将看到每个提交的当前构建状态，并且还可以使用 Travis 在将其合并到主分支之前验证拉取请求。

到目前为止，我们已经使用 Travis 来验证存储库中的代码是否不包含任何错误并且可以编译（这通常是持续集成的目标）。但是，我们还没有配置应用程序的实际部署。这就是我们接下来要做的事情。

在 Travis 构建中，您可以使用 Docker 构建和运行容器映像。要启用 Docker 支持，请将以下属性添加到您的`.travis.yml`文件的顶部：

```go
sudo: required 
services: 
  - docker 
language: go 
go: 
  - 1.9 
```

由于我们实际上不想为多个不同版本的 Go 构建 Docker 映像，因此完全可以从 Travis 文件中删除 Go 版本 1.6 到 1.8。

由于我们的项目实际上由两个部署构件（事件服务和预订服务）组成，我们可以进行另一个优化：我们可以使用构建矩阵并行构建这两个服务。为此，请将`env`属性添加到您的`.travis.yml`文件，并调整`script`属性，如下所示：

```go
sudo: required 
services: 
  - docker 
language: go 
go: 1.9 
env: 
  global: 
    - CGO_ENABLED=0 
  matrix: 
    - SERVICE=eventservice 
    - SERVICE=bookingservice
 install: true 
script: 
  - go vet $(go list ./... | grep -v vendor) 
  - cd $SERVICE && go build 
```

有了这个配置，Travis 将为代码存储库中的每次更改启动两个构建作业，其中每个构建一个包含在该存储库中的两个服务之一。

之后，您可以将`docker image build`命令添加到`script`属性中，以从编译的服务构建容器映像：

```go
script: 
  - go vet $(go list ./... | grep -v vendor) 
  - cd $SERVICE && go build 
  - docker image build -t myevents/$SERVICE:$TRAVIS_BRANCH $SERVICE 
```

上述命令构建了一个名为`myevents/eventservice`或`myevents/bookingservice`的 Docker 镜像（取决于当前`$SERVICE`的值）。Docker 镜像是使用当前分支（或 Git 标签）名称作为标记构建的。这意味着对*master*分支的新推送将导致构建一个`myevents/eventservice:master`镜像。当推送名为*v1.2.3*的 Git 标签时，将创建一个`myevents/eventservice:v1.2.3`镜像。

最后，您需要将新的 Docker 镜像推送到注册表。为此，请将一个新属性`after_success`添加到您的`.travis.yml`文件中：

```go
after_success: 
  - if [ -n "${TRAVIS_TAG}" ] ; then 
      docker login -u="${DOCKER_USERNAME}" -p="${DOCKER_PASSWORD}"; 
      docker push myevents/$SERVICE:$TRAVIS_BRANCH; 
    fi 
```

在`after_success`中指定的命令将在`scripts`中的所有命令成功完成后运行。在这种情况下，我们正在检查`$TRAVIS_TAG`环境变量的内容；因此，只有为 Git 标签构建的 Docker 镜像才会实际推送到远程注册表。

如果您使用的是与 Docker Hub 不同的 Docker 镜像注册表，请记住在`docker login`命令中指定注册表的 URL。例如，当使用`quay.io`作为注册表时，命令应如下所示：`docker login -u="${DOCKER_USERNAME}" -p="${DOCKER_PASSWORD}" quay.io`。

为了使此命令工作，您需要定义环境变量`$DOCKER_USERNAME`和`$DOCKER_PASSWORD`。理论上，您可以在`.travis.yml`文件的`env`部分中定义这些变量。但是，对于诸如密码之类的敏感数据，将它们定义在公开可用的文件中供所有人查看是一个非常愚蠢的想法。相反，您应该使用 Travis 用户界面为构建配置这些变量。为此，请转到项目的设置页面，您可以在项目概述页面上单击“更多选项”按钮时找到：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/66335f96-033a-4f38-bb3c-71714e5d2844.png)

在项目设置中，您将找到一个名为环境变量的部分。通过指定`DOCKER_USERNAME`和`DOCKER_PASSWORD`变量在这里配置您的 Docker 注册表凭据：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/d2472861-3242-4f9d-9a2d-a8fa53dafc32.png)

或者，您可以通过加密后将秘密变量添加到您的`.travis.yml`文件中，然后将其放置在版本控制中。为此，您将需要 Travis 命令行客户端 CLI。Travis CLI 是一个 Ruby 工具，您可以通过 Ruby 软件包管理器`gem`安装。

```go
$ gem install travis
```

之后，您可以使用 Travis CLI 对变量进行加密，并自动将其添加到您的`.travis.yml`文件中：

```go
$ travis encrypt DOCKER_PASSWORD="my-super-secret-password" --add
```

这将向您的`.travis.yml`文件添加一个新变量，看起来像这样：

```go
...
env:
 global:
 - secure: <encrypted value>
```

通过 Travis UI 添加您的秘密变量以及对其进行加密并将其添加到您的`.travis.yml`文件中，这两种方法都是处理 Travis 构建中的敏感数据的有效方法。

将新的构建配置保存在`.travis.yml`中，并将其推送到 GitHub。要构建和发布新的 Docker 镜像，现在可以推送一个新的`git`标签：

```go
$ git tag v1.0.0 
$ git push --tags 
```

此时，Travis CI 将拉取您的代码，编译所有 Go 二进制文件，并为构建配置中配置的 Docker 注册表发布两个后端服务的 Docker 镜像。

我们仍然需要为前端应用程序添加类似的构建配置。实际上，构建 Docker 镜像的步骤完全相同；但是，我们需要运行 Webpack 模块打包程序而不是`go build`。以下是一个应该涵盖整个前端构建的`.travis.yml`文件：

```go
language: node_js 
node_js: 
  - 6 
env: 
  - SERVICE=frontend 
install: 
  - npm install -g webpack typescript 
  - npm install 
script: 
  - webpack 
after_success: 
  - if [ -n "${TRAVIS_TAG}" ] ; then 
    docker login -u="${DOCKER_USERNAME}" -p="${DOCKER_PASSWORD}"; 
    docker push myevents/${SERVICE}:${TRAVIS_BRANCH}; 
    fi 
```

# 部署到 Kubernetes

使用 GitHub 和 Travis，我们现在已经自动化了从更改应用程序源代码到构建新二进制文件再到创建新的 Docker 镜像并将其推送到容器注册表的整个工作流程。这很棒，但我们仍然缺少一个关键步骤，那就是在生产环境中运行新的容器映像。

在之前的章节中，您已经使用 Kubernetes 并将容器化应用部署到 Minikube 环境中。对于本节，我们将假设您已经拥有一个正在运行的公共可访问的 Kubernetes 环境（例如，使用 AWS 中的 `kops` 提供的集群或 Azure 容器服务）。

首先，Travis CI 需要访问您的 Kubernetes 集群。为此，您可以在 Kubernetes 集群中创建一个 **服务账户**。然后，该服务账户将收到一个 API 令牌，您可以在 Travis 构建中配置为秘密环境变量。要创建服务账户，请在本地机器上运行以下命令（假设您已经设置了 `kubectl` 以与 Kubernetes 集群通信）：

```go
$ kubectl create serviceaccount travis-ci 
```

上述命令将创建一个名为 `travis-ci` 的新服务账户和一个包含该账户 API 令牌的新密钥对象。要确定密钥，现在运行 `kubectl describe serviceaccount travis-ci` 命令：

```go
$ kubectl describe serviceaccount travis-ci 
Name:        travis-ci 
Namespace:   default 
Labels:      <none> 
Annotations: <none> 

Image pull secrets: <none> 
Mountable secrets:  travis-ci-token-mtxrh 
Tokens:             travis-ci-token-mtxrh 
```

使用令牌密钥名称（在本例中为 `travis-ci-token-mtxrh`）来访问实际的 API 令牌：

```go
$ kubectl get secret travis-ci-token-mtxrh -o=yaml 
apiVersion: v1 
kind: Secret 
data: 
  ca.crt: ... 
  namespace: ZGVmYXVsdA== 
  token: ... 
# ... 
```

您将需要 `ca.crt` 和 `token` 属性。这两个值都是 BASE64 编码的，因此您需要通过 `base64 --decode` 管道传递这两个值来访问实际值：

```go
$ echo "<token from above>" | base64 --decode 
$ echo "<ca.crt from above>" | base64 --decode 
```

与 API 服务器的 URL 一起，这两个值可以用于从 Travis CI（或其他 CI/CD 工具）对 Kubernetes 集群进行身份验证。

要在 Travis CI 构建中实际配置 Kubernetes 部署，请从在 `install` 部分添加以下命令开始设置 `kubectl`：

```go
install: 
  - curl -LO https://storage.googleapis.com/kubernetes- 
release/release/v1.6.1/bin/linux/amd64/kubectl && chmod +x kubectl 
  - echo "${KUBE_CA_CERT}" > ./ca.crt 
  - ./kubectl config set-credentials travis-ci --token="${KUBE_TOKEN}" 
  - ./kubectl config set-cluster your-cluster --server=https://your-kubernetes-cluster --certificate-authority=ca.crt 
  - ./kubectl config set-context your-cluster --cluster=your-cluster --user=travis-ci --namespace=default 
  - ./kubectl config use-context your-cluster 
```

要使这些步骤生效，您需要在 Travis CI 设置中将环境变量 `$KUBE_CA_CERT` 和 `$KUBE_TOKEN` 配置为秘密环境变量，并使用从上述 `kubectl get secret` 命令中获取的值。

在配置了 `kubectl` 后，您现在可以将额外的步骤添加到您的项目的 `after_success` 命令中：

```go
after_success: 
  - if [ -n "${TRAVIS_TAG}" ] ; then 
    docker login -u="${DOCKER_USERNAME}" -p="${DOCKER_PASSWORD}"; 
    docker push myevents/${SERVICE}:$TRAVIS_BRANCH; 
    ./kubectl set image deployment/${SERVICE} api=myevents/${SERVICE}:${TRAVIS_BRANCH}; 
    fi 
```

`kubectl set image` 命令将更改应该用于给定 Deployment 对象的容器镜像（在本例中，假设您有名为 `eventservice` 和 `bookingservice` 的部署）。Kubernetes 部署控制器将继续使用新的容器镜像创建新的 Pod，并关闭运行旧镜像的 Pod。

# 使用 GitLab

GitHub 和 Travis 都是构建和部署开源项目（以及私有项目，如果您不介意为其服务付费）的优秀工具。然而，在某些情况下，您可能希望在自己的环境中托管源代码管理和 CI/CD 系统，而不是依赖外部服务提供商。

这就是 GitLab 发挥作用的地方。GitLab 是一种类似于 GitHub 和 Travis 组合的服务的软件（意味着源代码管理和 CI），您可以在自己的基础设施上托管。在接下来的部分中，我们将向您展示如何设置自己的 GitLab 实例，并构建一个类似于前一节中使用 GitLab 和其 CI 功能构建的构建和部署流水线。

GitLab 提供开源的 **社区版**（**CE**）和付费的 **企业版**（**EE**），提供一些额外的功能。对于我们的目的，CE 就足够了。

# 设置 GitLab

您可以使用供应商提供的 Docker 镜像轻松地设置自己的 GitLab 实例。要启动 GitLab CE 服务器，请运行以下命令：

```go
$ docker container run --detach \
  -e GITLAB_OMNIBUS_CONFIG="external_url 'http://192.168.2.125/';" \
  --name gitlab \
  -p 80:80 \
  -p 22:22 \
  gitlab/gitlab-ce:9.1.1-ce.0
```

注意传递到容器中的 `GITLAB_OMNIBUS_CONFIG` 环境变量。此变量可用于将配置代码（用 Ruby 编写）注入到容器中；在本例中，它用于配置 GitLab 实例的公共 HTTP 地址。在本地启动 GitLab 时，通常最容易使用您的机器的公共 IP 地址（在 Linux 或 macOS 上，使用 `ifconfig` 命令找到它）。

如果您要在服务器上为生产使用设置 GitLab（而不是在本地机器上进行实验），您可能希望为配置和存储库数据创建两个数据卷，然后可以在容器中使用。这将使您能够轻松地将 GitLab 安装升级到较新的版本：

```go
$ docker volume create gitlab-config
$ docker volume create gitlab-data
```

创建卷后，在`docker container run`命令中使用`-v gitlab-config:/etc/gitlab`和`-v gitlab-data:/var/opt/gitlab`标志，以实际为 Gitlab 实例使用这些卷。

在新创建的容器中运行的 GitLab 服务器可能需要几分钟才能完全启动。之后，您可以在`http://localhost`上访问您的 GitLab 实例：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/c04abec5-6eee-4d39-b32c-cb97723094e1.png)

首次在浏览器中打开 GitLab 时，您将被提示为初始用户设置新密码。设置密码后，您可以使用用户名`root`和之前设置的密码登录。如果您正在设置 GitLab 的生产实例，下一步将是设置一个新用户，您可以使用该用户登录，而不是 root。出于演示目的，继续作为 root 进行工作也是可以的。

首次登录后，您将看到一个“开始”页面，您可以在该页面上创建新的组和新项目。GitLab 项目通常与 Git 源代码存储库相关联。为了为 MyEvents 应用程序设置 CI/CD 流水线，请继续创建两个名为`myevents`和`myevents-frontend`的新项目，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/07777c0a-aa0a-4247-9772-06718a2f6731.png)

为了将代码推送到新的 GitLab 实例中，您需要提供用于身份验证的 SSH 公钥。为此，请点击右上角的用户图标，选择“设置”，然后选择 SSH 密钥选项卡。将您的 SSH 公钥粘贴到输入字段中并保存。

接下来，将您的新 GitLab 存储库添加为现有 MyEvents 存储库的远程，并推送您的代码：

```go
$ git remote add gitlab ssh://git@localhost/root/myevents.git 
$ git push gitlab master:master 
```

类似地进行前端应用程序的设置。之后，您将能够在 GitLab Web UI 中找到您的文件：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/92b3c8ba-ce38-4039-9d42-6c2ae24deb6c.png)

# 设置 GitLab CI

为了使用 GitLab 的 CI 功能，您需要设置一个额外的组件：GitLab CI Runner。虽然 GitLab 本身负责管理应用程序的源代码并决定何时触发新的 CI 构建，但 CI Runner 负责实际执行这些作业。将实际的 GitLab 容器与 CI Runner 分开允许您分发 CI 基础设施，并且例如在不同的机器上拥有多个 Runner。 

GitLab CI Runner 也可以使用 Docker 镜像进行设置。要设置 CI Runner，请运行以下命令：

```go
$ docker container run --detach \ 
    --name gitlab-runner \ 
    --link gitlab:gitlab \ 
    -v /var/run/docker.sock:/var/run/docker.sock \ 
    gitlab/gitlab-runner:v1.11.4 
```

启动 GitLab CI Runner 后，您需要在主 GitLab 实例上注册它。为此，您将需要 Runner 的注册令牌。您可以在 GitLab UI 的管理区域中找到此令牌。通过右上角的扳手图标访问管理区域，然后选择 Runners。您将在第一个文本段落中找到 Runner 的注册令牌：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/f25a2ddd-5d9c-476b-ae80-db15d56b0664.png)

要注册您的 Runner，请运行以下命令：

```go
$ docker container exec \ 
    -it gitlab-runner \ 
    gitlab-runner register -n \ 
      --url http://gitlab \ 
      --registration-token <TOKEN> \ 
      --executor docker \ 
      --docker-image ubuntu:16.04 \ 
      --docker-volumes /var/run/docker.sock:/var/run/docker.sock \
      --description "Gitlab CI Runner" 
```

此命令在主 GitLab 实例上注册先前启动的 GitLab CI Runner。`--url`标志配置了主 GitLab 实例的可访问 URL（通常情况下，当您的 runner 在与主 Gitlab 实例相同的容器网络上时，这可以是`http://gitlab`；或者，您可以在这里使用您主机的公共 IP 地址，我的情况下是`http://192.168.2.125/`）。接下来，复制并粘贴`--registration-token`标志的注册令牌。`--executor`标志配置 GitLab CI Runner 在自己的隔离 Docker 容器中运行每个构建作业。`--docker-image`标志配置默认情况下应该用作构建环境的 Docker 镜像。`--docker-volumes`标志确保您可以在构建中使用 Docker Engine（这一点尤为重要，因为我们将在这些构建中构建我们自己的 Docker 镜像）。

将`/var/run/docker.sock`套接字挂载到您的 Gitlab Runner 中，将您主机上运行的 Docker 引擎暴露给您的 CI 系统的用户。如果您不信任这些用户，这可能构成安全风险。或者，您可以设置一个新的 Docker 引擎，它本身运行在一个容器中（称为 Docker-in-Docker）。有关详细的设置说明，请参阅 GitLab 文档[`docs.gitlab.com/ce/ci/docker/using_docker_build.html#use-docker-in-docker-executor`](https://docs.gitlab.com/ce/ci/docker/using_docker_build.html#use-docker-in-docker-executor)。

`docker exec`命令应该产生类似于以下截图的输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/8e7c0c49-fc88-4de9-ae55-15cdf43c3c10.png)

成功注册 Runner 后，您应该能够在 GitLab 管理 UI 中找到它：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/59e6a201-ec4f-4f53-ba09-fef9f12f571c.png)

现在您已经有一个工作的 CI Runner，您可以开始配置实际的 CI 作业。与 Travis CI 类似，GitLab CI 作业是通过一个配置文件进行配置的，该文件放置在源代码存储库中。与已知的`.travis.yml`类似，该文件名为`.gitlab-ci.yml`。尽管它们的名称相似，但其格式略有不同。

每个 GitLab CI 配置由多个阶段组成（默认情况下为构建、测试和部署，尽管这是完全可定制的）。每个阶段可以包含任意数量的作业。所有阶段一起形成一个流水线。流水线中的每个作业都在自己隔离的 Docker 容器中运行。

让我们从 MyEvents 后端服务开始。在项目的根目录中放置一个新文件`.gitlab-ci.yml`：

```go
build:eventservice: 
  image: golang:1.9.2 
  stage: build 
  before_script: 
    - mkdir -p $GOPATH/src/todo.com 
    - ln -nfs $PWD $GOPATH/src/todo.com/myevents 
    - cd $GOPATH/src/todo.com/myevents/eventservice 
  script: 
    - CGO_ENABLED=0 go build 
  artifacts: 
    paths: 
      - ./eventservice/eventservice 
```

那么，这段代码实际上是做什么呢？首先，它指示 GitLab CI Runner 在基于`golang:1.9.2`镜像的 Docker 容器中启动此构建。这确保您在构建环境中可以访问最新的 Go SDK。`before_script`部分中的三个命令负责设置`$GOPATH`，`script`部分中的一个命令是实际的编译步骤。

请注意，此构建配置假定您的项目的所有依赖项都已在版本控制中进行了分发。如果您的项目中只有一个`glide.yaml`文件，那么在实际运行`go build`之前，您还需要设置 Glide 并运行`glide install`。

最后，artifacts 属性定义了由 Go `build`创建的`eventservice`可执行文件应作为构建 artifact 进行存档。这将允许用户稍后下载此构建 artifact。此外，该 artifact 将在同一流水线的后续作业中可用。

现在，将`.gitlab-ci.yml`文件添加到您的源代码存储库中，并将其推送到 GitLab 服务器：

```go
$ git add .gitlab-ci.yml 
$ git commit -m "Configure GitLab CI" 
$ git push gitlab 
```

当您推送配置文件后，转到 GitLab Web UI 中的项目页面，然后转到 Pipelines 选项卡。您将找到为您的项目启动的所有构建流水线的概述，以及它们的成功情况：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/33e32a1a-00f5-495b-9f43-8f986ea74847.png)

现在，我们的流水线只包括一个阶段（`build`）和一个作业（`build:eventservice`）。您可以在`Pipelines`概述的`Stages`列中看到这一点。要查看`build:eventservice`作业的确切输出，请单击流水线状态图标，然后单击`build:eventservice`作业：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/9c40d302-b4a0-4296-9cec-2e86e028362f.png)

接下来，我们可以扩展我们的`.gitlab-ci.yml`配置文件，以包括预订服务的构建：

```go
build:eventservice: # ... 

build:bookingservice: 
  image: golang:1.9.2 
  stage: build 
  before_script: 
    - mkdir -p $GOPATH/src/todo.com 
    - ln -nfs $PWD $GOPATH/src/todo.com/myevents 
    - cd $GOPATH/src/todo.com/myevents/bookingservice 
  script: 
    - CGO_ENABLED=0 go build 
  artifacts: 
    paths: 
      - ./bookingservice/bookingservice 
```

当您再次推送代码时，您会注意到为您的项目启动的下一个流水线由两个作业并行运行（更多或更少，取决于 GitLab CI Runner 的配置及其当前工作负载）：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/5a64c80c-9044-4845-86c9-aaee701680d0.png)

接下来，我们可以添加两个构建实际 Docker 镜像的作业。这些作业需要在已经配置的构建步骤之后执行，因为我们需要编译后的 Go 二进制文件来创建 Docker 镜像。因此，我们无法将 docker 构建步骤配置为在构建阶段运行（一个阶段内的所有作业是并行执行的，至少在潜在情况下，并且不能相互依赖）。因此，我们将首先重新配置项目的构建阶段。这也是在`.gitlab-ci.yml`文件中基于每个项目的基础上完成的：

```go
stages: 
  - build 
  - dockerbuild 
  - publish 
  - deploy 

build:eventservice: # ... 
```

接下来，我们可以在实际的构建作业中使用这些新的阶段：

```go
dockerbuild:eventservice: 
  image: docker:17.04.0-ce 
  stage: dockerbuild 
  dependencies: 
    - build:eventservice 
  script: 
    - docker container build -t myevents/eventservice:$CI_COMMIT_REF_NAME eventservice 
  only: 
    - tags 
```

`dependencies`属性声明了这一步需要先完成`build:eventservice`作业。它还使得该作业的构建产物在这个作业中可用。`script`只包含`docker container build`命令(`$CI_COMMIT_REF_NAME`)，其中包含当前 Git 分支或标签的名称。`only`属性确保只有在推送新的 Git 标签时才构建 Docker 镜像。

为构建预订服务容器镜像添加相应的构建作业：

```go
dockerbuild:bookingservice: 
  image: docker:17.04.0-ce 
  stage: dockerbuild 
  dependencies: 
    - build:bookingservice 
  script: 
    - docker container build -t myevents/bookingservice:$CI_COMMIT_REF_NAME bookingservice 
  only: 
    - tags 
```

将修改后的`.gitlab-ci.yml`文件添加到版本控制中，并创建一个新的 Git 标签来测试新的构建流水线：

```go
$ git add .gitlab-ci.yml 
$ git commit -m"Configure Docker builds" 
$ git push gitlab 

$ git tag v1.0.1 
$ git push gitlab --tags 
```

在流水线概述中，您现在会找到四个构建作业：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/40656dbf-18bd-45c8-8bd6-88f06b83c95c.png)

构建 Docker 镜像后，我们现在可以添加第五个构建步骤，将创建的注册表发布到 Docker 注册表中：

```go
publish: 
  image: docker:17.04.0-ce 
  stage: publish 
  dependencies: 
    - dockerbuild:eventservice 
    - dockerbuild:bookingservice 
  before_script: 
    - docker login -u ${DOCKER_USERNAME} -p ${DOCKER_PASSWORD} 
  script: 
    - docker push myevents/eventservice:${CI_COMMIT_REF_NAME} 
    - docker push myevents/bookingservice:${CI_COMMIT_REF_NAME} 
  only: 
    - tags 
```

与之前的 Travis CI 构建类似，这个构建作业依赖于环境变量`$DOCKER_USERNAME`和`$DOCKER_PASSWORD`。幸运的是，GitLab CI 提供了类似于 Travis CI 的秘密环境变量的功能。为此，在 GitLab web UI 中打开项目的设置选项卡，然后选择 CI/CD Pipelines 选项卡，搜索秘密变量部分：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/392d38cf-4057-4fdd-a622-4eb0882d6e35.png)

使用此功能配置您选择的容器注册表的凭据（如果您使用的是 Docker Hub 之外的注册表，请记得相应地调整前面构建作业中的`docker login`命令）。

最后，让我们为将应用程序实际部署到 Kubernetes 集群中添加最终的构建步骤：

```go
deploy: 
  image: alpine:3.5 
  stage: deploy 
  environment: production 
  before_script: 
    - apk add --update openssl 
    - wget -O /usr/local/bin/kubectl https://storage.googleapis.com/kubernetes- 
release/release/v1.6.1/bin/linux/amd64/kubectl && chmod +x /usr/local/bin/kubectl 
    - echo "${KUBE_CA_CERT}" > ./ca.crt 
    - kubectl config set-credentials gitlab-ci --token="${KUBE_TOKEN}" 
    - kubectl config set-cluster your-cluster --server=https://your-kubernetes-cluster.example --certificate-authority=ca.crt 
    - kubectl config set-context your-cluster --cluster=your-cluster --user=gitlab-ci --namespace=default 
    - kubectl config use-context your-cluster 
  script: 
    - kubectl set image deployment/eventservice api=myevents/eventservice:${CI_COMMIT_REF_NAME} 
    - kubectl set image deployment/bookingservice api=myevents/eventservice:${CI_COMMIT_REF_NAME} 
  only: 
    - tags 
```

这个构建步骤使用了`alpine:3.5`基础镜像（一个非常小的镜像大小的极简 Linux 发行版），其中我们首先下载，然后配置`kubectl`二进制文件。这些步骤与我们在前面部分配置的 Travis CI 部署类似，并且需要在 GitLab UI 中将环境变量`$KUBE_CA_CERT`和`$KUBE_TOKEN`配置为秘密变量。

请注意，在这个例子中，我们使用了一个名为`gitlab-ci`的 Kubernetes 服务账户（之前，我们创建了一个名为`travis-ci`的账户）。因此，为了使这个例子工作，您需要使用在前面部分已经使用过的命令创建一个额外的服务账户。

到目前为止，我们基于 GitLab 的构建和部署流水线已经完成。再次查看 GitLab UI 中的流水线视图，以充分了解我们的流水线：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/cld-ntv-prog-go/img/910c4c84-ff01-46bf-90e0-c10a53ca8d9d.png)

GitLab 的流水线功能几乎是实现复杂构建和部署流程的完美解决方案。而其他 CI/CD 工具会限制你只能使用一个环境进行单一构建作业，GitLab 的流水线允许你为构建的每个步骤使用一个隔离的环境，甚至在可能的情况下并行运行这些步骤。

# 总结

在本章中，你学会了如何轻松自动化应用程序的构建和部署工作流程。在微服务架构中，拥有自动化的部署工作流程尤为重要，因为你会经常部署许多不同的组件。如果没有自动化，部署复杂的分布式应用程序将变得越来越繁琐，并且会影响你的生产效率。

现在我们的应用部署问题已经解决（简而言之，容器+持续交付），我们可以将注意力转向其他事项。我们部署的应用程序在运行并不意味着它实际上在做它应该做的事情。这就是为什么我们需要监控在生产环境中运行的应用程序。监控能够让你在运行时跟踪应用程序的行为并快速发现错误，这就是为什么下一章的重点将放在监控你的应用程序上。
