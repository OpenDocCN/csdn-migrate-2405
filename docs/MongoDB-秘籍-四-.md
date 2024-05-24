# MongoDB 秘籍（四）

> 原文：[`zh.annas-archive.org/md5/9F335F41611FE256D46F623124D9DAEC`](https://zh.annas-archive.org/md5/9F335F41611FE256D46F623124D9DAEC)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：在云上部署 MongoDB

在本章中，我们将涵盖以下配方：

+   设置和管理 MongoLab 账户

+   在 MongoLab 上设置沙箱 MongoDB 实例

+   从 MongoLab GUI 上操作 MongoDB

+   在 Amazon EC2 上设置 MongoDB 而不使用 AMI

+   使用 Docker 容器设置 MongoDB

# 介绍

虽然解释云计算不在本书的范围内，但我将在一段话中解释一下。任何规模的企业都需要硬件基础设施，并在其上安装不同的软件。操作系统是基本软件，还需要不同的服务器（从软件角度）用于存储、邮件、网络、数据库、DNS 等。所需的软件框架/平台列表将变得很长。这里的重点是，这些硬件和软件平台的初始预算很高，所以我们甚至没有考虑托管它所需的房地产。这就是亚马逊、Rackspace、Google 和微软等云计算提供商的作用所在。他们在全球不同的数据中心托管了高端硬件和软件，并让我们从不同的配置中选择开始一个实例。然后通过公共网络远程访问以进行管理。我们所有的设置都是在云提供商的数据中心中完成的，我们只是按需付费。关闭实例，停止付费。不仅是小型初创企业，大型企业也经常暂时转向云服务器以满足临时的计算资源需求。提供商提供的价格也非常有竞争力，特别是 AWS，其受欢迎程度说明了一切。

维基页面[`en.wikipedia.org/wiki/Cloud_computing`](http://en.wikipedia.org/wiki/Cloud_computing)有很多细节，对于新概念的人来说可能有点太多，但仍然是一篇不错的阅读。[`computer.howstuffworks.com/cloud-computing/cloud-computing.htm`](http://computer.howstuffworks.com/cloud-computing/cloud-computing.htm)上的文章也很不错，如果你对云计算的概念不熟悉，也建议你阅读一下。

在本章中，我们将使用 MongoDB 服务提供商在云上设置 MongoDB 实例，然后在**亚马逊网络服务**（**AWS**）上自己设置。

# 设置和管理 MongoLab 账户

在这个配方中，我们将评估 MongoLab 这样的供应商，他们提供 MongoDB 作为一项服务。这个介绍性的配方将向你介绍 MongoDB 作为一项服务是什么，然后演示如何在 MongoLab([`mongolab.com/`](https://mongolab.com/))中设置和管理一个账户。

到目前为止，本书中的所有配方都涵盖了在组织/个人场所设置、管理、监控和开发 MongoDB 实例。这不仅需要具有适当技能的人手来管理部署，还需要适当的硬件来安装和运行 Mongo 服务器。这需要大量的前期投资，这对于初创企业甚至对于尚不确定是否要采用或迁移到这项技术的组织来说可能不是一个可行的解决方案。他们可能希望评估一下，看看情况如何，然后再全面转向这个解决方案。理想的情况是有一个服务提供商来负责托管 MongoDB 部署、管理和监控部署，并提供支持。选择这些服务的组织无需事先投资来设置服务器或招聘或外包顾问来管理和监控实例。你需要做的就是选择硬件和软件平台和配置以及适当的 MongoDB 版本，然后从用户友好的 GUI 中设置环境。它甚至给了你一个选项来使用你现有的云提供商的服务器。

我们简要地看到了这些供应商托管服务的作用以及它们为什么是必要的；我们将通过在 MongoLab 上设置帐户并查看一些基本用户和帐户管理来开始这个配方。MongoLab 绝不是 MongoDB 的唯一托管提供商。您还可以查看[`www.mongohq.com/`](http://www.mongohq.com/)和[`www.objectrocket.com/`](http://www.objectrocket.com/)。在撰写本书时，MongoDB 自己开始在 Azure 云上提供 MongoDB 作为服务，目前处于测试阶段。

## 如何操作…

1.  如果您尚未创建帐户，请访问[`mongolab.com/signup/`](https://mongolab.com/signup/)进行注册；只需填写相关详细信息并创建一个帐户。

1.  创建帐户后，单击右上角的“帐户”链接：![如何操作…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_07_02.jpg)

1.  在顶部单击“帐户用户”选项卡；它应该是默认选中的：![如何操作…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_07_03.jpg)

1.  要添加新帐户，请单击“+添加帐户用户”按钮。一个弹出窗口将要求输入用户名、电子邮件 ID 和密码。输入相关详细信息，然后单击“添加”按钮。

1.  单击用户，您应该被导航到一个页面，您可以在该页面更改用户名、电子邮件 ID 和密码。您可以通过在此屏幕上单击“更改为管理员”按钮将管理权限转移给用户。

1.  同样，通过单击自己的用户详细信息，您可以选择更改用户名、电子邮件 ID 和密码。

1.  单击“设置双因素身份验证”按钮以激活使用 Google Authenticator 的多因素身份验证。您需要在 Android、iOS 或 BlackBerry 手机上安装 Google Authenticator 才能继续设置多因素身份验证。

1.  单击按钮后，我们应该看到可以使用 Google Authenticator 扫描的 QR 码，或者如果无法扫描，可以单击 QR 码下面的 URL，这将显示代码。在 Google Authenticator 中手动设置基于时间的帐户。Google Authenticator 有两种类型的帐户，基于时间和基于计数器。

### 提示

请参阅[`en.wikipedia.org/wiki/Google_Authenticator`](http://en.wikipedia.org/wiki/Google_Authenticator)获取更多详细信息。

1.  同样，您可以通过单击“帐户用户”中用户行旁边的叉号来从帐户页面中删除用户。

## 工作原理…

在这一部分没有太多需要解释的。设置过程和用户管理非常简单。请注意，我们在这里添加的用户不是数据库用户。这些是可以访问 MongoLab 帐户的用户。**帐户**可以是组织的名称，并且可以在屏幕顶部看到。在手持设备上 Google Authenticator 软件中设置的多因素身份验证帐户不应被删除，因为每当用户从浏览器登录到 MongoLab 帐户时，他将被要求输入 Google Authenticator 帐户以继续。

# 在 MongoLab 上设置沙箱 MongoDB 实例

在上一篇文章中，我们看到了如何在 MongoLab 上设置帐户并向帐户添加用户。我们还没有看到如何在云上启动实例并使用它执行一些简单的操作。在这个配方中，这正是我们要做的事情。

## 准备工作

请参考前一篇文章，“设置和管理 MongoLab 帐户”，以在 MongoLab 上设置帐户。我们将设置一个免费的沙箱实例。我们将需要一种连接到这个已启动的`mongo`实例的方法，因此将需要一个仅随完整的 mongo 安装一起提供的 mongo shell，或者您可以选择使用您选择的编程语言来连接到已启动的`mongo`实例以执行操作。请参阅第三章，“编程语言驱动程序”中有关使用 Java 或 Python 客户端连接和执行操作的配方。

## 如何操作…

1.  转到主页，[`mongolab.com/home`](https://mongolab.com/home)，然后点击**创建新**按钮。

1.  选择云提供商，例如，我们选择亚马逊网络服务（AWS）：![操作步骤…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_07_04.jpg)

1.  点击**单节点（开发）**，然后选择**沙盒**选项。不要更改云服务器的位置，因为免费沙盒实例并非在所有数据中心都可用。由于这是一个沙盒，我们可以接受任何位置。

1.  为您的数据库添加任何名称；我选择的名称是`mongolab-test`。在输入名称后，点击**创建新的 MongoDB 部署**。

1.  这将带您到主页，现在应该可以看到数据库。点击实例名称。此页面显示所选的 MongoDB 实例的详细信息。在页面顶部提供了在 shell 或编程语言中连接的指示，以及已启动实例的公共主机名。

1.  点击**用户**选项卡，然后点击**添加数据库用户**按钮。在弹出窗口中，分别添加用户名和密码为`testUser`和`testUser`（或者您自己选择的任何用户名和密码）。![操作步骤…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_07_05.jpg)

1.  添加用户后，按照以下步骤启动 mongo shell，假设数据库名称为`mongolab-test`，用户名和密码为`testUser`：

```sql
$ mongo <host-name>/mongolab-test –u testUser –p testUser

```

连接后，在 shell 中执行以下操作，并检查数据库名称是否为`mongolab-test`：

```sql
> db

```

1.  按以下方式向集合中插入一个文档：

```sql
> db.messages.insert({_id:1, message:'Hello mongolab'})

```

1.  按以下方式查询集合：

```sql
> db.messages.findOne()

```

## 工作原理…

执行的步骤非常简单，我们在云中创建了一个共享的沙盒实例。MongoLab 本身不托管实例，而是使用云提供商之一来托管。MongoLab 并不支持所有提供商的沙盒实例。沙盒实例的存储空间为 0.5 GB，并与同一台机器上的其他实例共享。共享实例比在专用实例上运行要便宜，但性能方面要付出代价。CPU 和 IO 与其他实例共享，因此我们共享实例的性能并不一定在我们的控制之下。对于生产用例，共享实例不是一个推荐的选项。同样，当在生产环境中运行时，我们需要设置一个副本集。如果我们看一下步骤 2 中的图像，我们会看到**单节点（开发）**选项旁边还有另一个选项卡。在这里，您可以选择机器的配置，包括 RAM 和磁盘容量（以及价格），并设置一个副本集。

![工作原理…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_07_06.jpg)

如您所见，您可以选择要使用的 MongoDB 版本。即使 MongoDB 发布了新版本，MongoLab 也不会立即开始支持，因为他们通常会等待几个次要版本的发布，然后才支持生产用户。此外，当我们选择配置时，默认可用的选项是两个数据节点和一个仲裁者，这对于大多数用例来说已经足够了。

所选择的 RAM 和磁盘完全取决于数据的性质以及查询密集程度或写入密集程度。这种大小选择是我们无论是在自己的基础设施上部署还是在云上部署都需要做的。工作集是在选择硬件的 RAM 之前必须了解的重要内容。概念验证和实验是为了处理数据的一个子集，然后可以对整个数据集进行估算。如果 IO 活动很高并且需要低 IO 延迟，您甚至可以选择 SSD，就像前面的图像中所示的那样。独立实例在可伸缩性方面与副本集一样好，除了可用性。因此，我们可以选择独立实例进行此类估算和开发目的。共享实例，无论是免费还是付费，都是开发目的的良好选择。请注意，与专用实例一样，共享实例不能按需重新启动。

我们选择哪个云服务提供商？如果您已经在云中部署了应用服务器，那么显然必须与您现有的供应商相同。建议您为应用服务器和数据库使用相同的云供应商，并确保它们都部署在同一位置，以最小化延迟并提高性能。如果您是从头开始的，那么请花些时间选择云服务提供商。查看应用程序所需的所有其他服务，例如存储、计算、其他服务（如邮件、通知服务等）。所有这些分析都超出了本书的范围，但一旦完成并确定了供应商，您可以相应地在 MongoLab 中选择要使用的供应商。就定价而言，所有主要供应商都提供有竞争力的定价。

# 从 MongoLab GUI 对 MongoDB 执行操作

在上一个步骤中，我们看到了如何在云中使用 MongoLab 为 MongoDB 设置一个简单的沙箱实例。在本步骤中，我们将在此基础上构建，并查看 MongoLab 从管理、管理、监控和备份的角度为您提供了哪些服务。

## 准备工作

请参阅上一个步骤，*在 MongoLab 上设置沙箱 MongoDB 实例*，了解如何在云中使用 MongoLab 设置沙箱实例。

## 如何做…

1.  转到[`mongolab.com/home`](https://mongolab.com/home)；您应该看到数据库、服务器和集群的列表。如果您遵循了上一个步骤，您应该会看到一个独立的数据库，`mongolab-test`（或者您为数据库选择的任何名称）。单击数据库名称，这应该会带您到数据库详细信息页面。

1.  单击**集合**选项卡后，应该默认选择，我们应该看到数据库中存在的集合列表。如果在执行本步骤之前执行了上一个步骤，您应该会在数据库中看到一个名为 messages 的集合。

1.  单击集合的名称，我们应该会被导航到集合详细信息页面，如下所示：![如何做…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_07_07.jpg)

1.  单击**统计**选项以查看集合的统计信息。

1.  在**文档**选项卡中，我们可以查询集合。默认情况下，我们看到每页显示 10 个文档的所有文档，可以从每页记录下拉菜单中进行更改。可以选择的最大值为 100。

1.  还有另一种查看文档的方法，即作为表格。单击**显示**模式中的**表格**单选按钮，并单击链接以创建/编辑表视图。在显示的弹出窗口中，输入以下消息集合的文档，然后单击**提交**：

```sql
{
    "id": "_id",
    "Message Text": "message"
}
```

在这样做的情况下，显示将会按以下方式更改：

![如何做…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_07_08.jpg)

1.  从**--开始新搜索--**下拉菜单中，选择**[新搜索]**选项，如下图所示：![如何做…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_07_09.jpg)

1.  使用新查询，我们看到以下字段，让我们输入查询字符串、排序顺序和投影。将查询输入为`{"_id":1}`，字段输入为`{"message":1, "_id":0}`：![如何做…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_07_10.jpg)

1.  您可以选择通过单击**保存此搜索**按钮并为要保存的查询命名来保存查询。

1.  可以通过单击每条记录旁边的叉号来删除单个文档。同样，顶部的**删除全部**按钮将删除集合的所有内容。

1.  类似地，单击**+添加文档**将弹出一个编辑器，用于输入要插入集合的文档。由于 MongoDB 是无模式的，文档不需要具有固定的字段集；应用程序应该能够理解它。

1.  转到`https://mongolab.com/databases/<your database name>（在本例中为 mongolab-test）`，也可以通过从主页单击数据库名称来到达。

1.  单击**统计**选项卡旁边的**用户**选项卡。在表中显示的内容是`db.stats()`命令的结果。

1.  类似地，单击**备份**选项卡，位于**统计**选项卡旁边的顶部。在这里，我们可以选择定期备份或一次性备份。

1.  当您单击**计划定期备份**时，会弹出一个窗口，让您输入调度的详细信息，例如备份的频率，需要进行备份的时间以及要保留的备份数量。

1.  备份位置可以选择为 MongoLab 自己的 S3 存储桶或 Rackspace 云文件。您可以选择使用自己帐户的存储空间，在这种情况下，您将不得不共享 AWS 访问密钥/秘密密钥或 Rackspace 的 UserID/API 密钥。

## 工作原理...

步骤 1 到 5 非常简单。在第 6 步，我们提供了一个 JSON 文档，以表格格式显示结果。文档的格式如下：

```sql
{
  <display column 1> : <name of the field in the JSON document> ,
  <display column 2> : <name of the field in the JSON document> ,

  <display column n> : <name of the field in the JSON document> 
}
```

键是要显示的列的名称，值是实际文档中字段的名称，其值将显示为此列的值。为了更清楚地理解，请查看为消息集合定义的文档，然后查看显示的表格数据。以下是我们提供的 JSON 文档，其中将列的名称作为键的值，并将文档中的实际字段作为列的值：

```sql
{
    "id": "_id",
    "Message Text": "message"
}
```

请注意，这里的 JSON 文档的字段名称和值都用引号括起来。Mongo shell 在这方面很宽松，允许我们在不使用引号的情况下给出字段名称。

如果我们访问关于备份的第 16 步，我们会发现备份要么存储在 MongoLab 的 AWS S3/Rackspace 云文件中，要么存储在您自定义的 AWS S3 存储桶/Rackspace 云文件中。在后一种情况下，您需要与 MongoLab 共享您的 AWS/Rackspace 凭据。如果这是一个问题，并且凭据可能被用来访问其他资源，建议您创建一个单独的帐户，并将其用于从 MongoLab 进行备份。您还可以使用创建的备份来从 MongoLab 创建一个新的 MongoDB 服务器实例。不用说，如果您使用自己的 AWS S3 存储桶/Rackspace 云文件，存储费用是额外的，因为它们不是 MongoLab 费用的一部分。

有一些值得一提的重要点。MongoLab 为各种操作提供了 REST API。 REST API 可以用来代替标准驱动程序执行 CRUD 操作；但是，使用 MongoDB 客户端库是推荐的方法。现在使用 REST API 而不是语言驱动程序的一个很好的理由是，如果客户端通过公共网络连接到 MongoDB 服务器。我们在本地机器上启动的 shell 连接到云上的 MongoDB 服务器会将未加密的数据发送到服务器，这使其容易受到攻击。另一方面，如果使用 REST API，流量将通过安全通道发送，因为使用了 HTTPS。MongoLab 计划在未来支持客户端和服务器之间通信的安全通道，但在撰写本书时，这是不可用的。如果应用程序和数据库位于云提供商的同一数据中心，则您是安全的，并且可以依赖云提供商为其本地网络提供的安全性，这通常不是一个问题。但是，除了确保您的数据不通过公共网络传输之外，您无法做任何安全通信的事情。

还有一种情况是 MongoLab 无法使用的，那就是当您希望实例在您自己的虚拟机实例上运行，而不是由 MongoLab 选择的实例，或者当我们希望应用程序在虚拟专用云中。云提供商确实提供诸如 Amazon VPC 之类的服务，其中 AWS 云的一部分可以被视为您网络的一部分。如果您打算在这样的环境中部署 MongoDB 实例，那么 MongoLab 将无法使用。

# 在 Amazon EC2 上手动设置 MongoDB

在之前的几个配方中，我们看到了如何使用 MongoLab 提供的托管服务在云中启动 MongoDB，该服务为我们提供了在所有主要云供应商上设置 MongoDB 的替代方案。但是，如果我们计划自己托管和监控实例以获得更大的控制权，或者在我们自己的虚拟私有云中设置，我们可以自己做。虽然各个云供应商的流程有所不同，但我们将使用 AWS 进行演示。有几种方法可以做到这一点，但在这个配方中，我们将使用**Amazon Machine Image**（**AMI**）。AMI 是一个模板，包含了启动云上新虚拟机实例时将使用的操作系统、软件等详细信息。要了解更多关于 AMI 的信息，请参考[`en.wikipedia.org/wiki/Amazon_Machine_Image`](http://en.wikipedia.org/wiki/Amazon_Machine_Image)。

谈到 AWS EC2，它代表弹性云计算，是一个让您在云中创建、启动和停止不同配置的服务器的服务，运行您选择的操作系统。（价格也相应不同。）同样，亚马逊**弹性块存储**（**EBS**）是一个提供高可用性和低延迟的持久块存储的服务。初始时，每个实例都附有一个称为临时存储的存储。这是一个临时存储，当实例重新启动时，数据可能会丢失。因此，EBS 块存储被附加到 EC2 实例上，以保持持久性，即使实例停止然后重新启动。标准 EBS 不提供每秒保证的最小**IO 操作**（**IOPS**）。对于中等工作负载，大约 100 IOPS 的默认值是可以的。但是，对于高性能 IO，也可以使用具有保证 IOPS 的 EBS 块。与标准 EBS 块相比，价格更高，但如果低 IO 速率可能成为系统性能瓶颈的话，这是一个不错的选择。

在这个配方中，我们将设置一个小型微实例，作为一个足够好的沙盒实例，并附加一个 EBS 块卷。

## 准备工作

首先，您需要做的是注册一个 AWS 账户。访问[`aws.amazon.com/`](http://aws.amazon.com/)，然后点击**注册**。如果您有亚马逊账户，请登录，否则，请创建一个新账户。尽管我们这里使用的配方将使用免费的微实例，但您仍需要提供信用卡信息，除非我们另有明确说明。我们将使用 Putty 连接到云上的实例。如果您的机器上尚未安装 Putty，可以下载并安装。下载地址为[`www.putty.org/`](http://www.putty.org/)。

对于使用 AMI 进行安装的特定配方，我们不能使用微实例，而必须使用标准大型实例。您可以在[`aws.amazon.com/ec2/pricing/`](https://aws.amazon.com/ec2/pricing/)上获取不同地区 EC2 实例定价的更多详细信息。根据地理和财务因素选择适当的地区。

1.  首先，您需要做的是创建一个密钥对，以防您尚未创建。从 1 到 5 的以下步骤仅用于创建密钥对。此密钥对将用于从 Putty 客户端登录到云中启动的 Unix 实例。如果密钥对已经创建并且`.pem`文件对您可用，请跳到第 6 步。

1.  转到[`console.aws.amazon.com/ec2/`](https://console.aws.amazon.com/ec2/)，确保右上角显示的地区（如下图所示）与您计划设置实例的地区相同。![准备工作](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_07_15.jpg)

1.  选择区域后，**资源**标题的页面将显示该区域的所有实例、密钥对、IP 地址等。单击**密钥对**链接，这将引导您到显示所有现有密钥对并且您可以创建新密钥对的页面。

1.  单击**创建密钥对**按钮，在弹出窗口中输入您选择的任何名称。假设我们称之为`EC2 测试密钥对`，然后单击**创建**。

1.  创建后，将生成一个`.pem`文件。确保保存该文件，因为随后需要访问该机器。

1.  接下来，我们将把这个`.pem`文件转换为一个`.ppk`文件，以便与 Putty 一起使用。

1.  打开 puttygen；如果尚未提供，可以从[`www.chiark.greenend.org.uk/~sgtatham/putty/download.html`](http://www.chiark.greenend.org.uk/~sgtatham/putty/download.html)下载。

您应该在屏幕上看到以下内容：

![准备就绪](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_07_16.jpg)

1.  选择**SSH-2 RSA**选项，然后单击**加载**按钮。在文件对话框中，选择**所有文件**，然后选择与在 EC2 控制台中生成的密钥对一起下载的`.pem`文件。

1.  一旦导入了`.pem`文件，单击**保存私钥**选项，并使用任何名称保存文件；这次文件是`.ppk`文件。将此文件保存以便将来从 putty 登录到 EC2 实例。

### 注意

如果您使用的是 Mac OS X 或 Linux，可以使用`ssh-keygen`实用程序生成 SSH 密钥。

## 如何操作…

1.  转到[`console.aws.amazon.com/ec2/`](https://console.aws.amazon.com/ec2/)，然后单击左侧的**实例**选项，然后单击**启动实例**按钮：![如何操作…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_07_21.jpg)

1.  由于我们想要启动一个免费的微实例，在左侧勾选**仅限免费套餐**复选框。在右侧，选择我们想要设置的实例。我们选择使用**Ubuntu 服务器**。单击**选择**以导航到下一个窗口。

1.  选择微实例，然后单击**审阅和启动**。忽略安全警告；您将拥有的默认安全组将接受来自公共网络上所有主机的端口 22 的连接。

1.  不更改任何默认设置，单击**启动**。启动后，将弹出一个窗口，让您选择现有的密钥对。如果您继续没有密钥对，您将需要密码或需要创建一个新的密钥对。在上一篇文章中，我们已经创建了一个密钥对，这就是我们将在这里使用的内容。

1.  单击**启动实例**以启动新的微实例。

1.  参考上一篇文章中第 9 至 12 步，了解如何使用 Putty 连接到已启动的实例。请注意，这次我们将使用 Ubuntu 用户，而不是上一篇文章中使用的`ec2-user`，因为这次我们使用的是 Ubuntu 而不是 Amazon Linux。

1.  在添加 MongoDB 存储库之前，我们需要按照以下步骤导入 MongoDB 公钥：

```sql
$ sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 7F0CEB10

```

1.  在操作系统 shell 中执行以下命令：

```sql
$ echo "deb http://repo.mongodb.org/apt/ubuntu trusty/mongodb-org/3.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.0.list

```

1.  通过执行以下命令加载本地数据库：

```sql
$ sudo apt-get install mongodb-org

```

1.  执行以下命令以创建所需的目录：

```sql
$ sudo mkdir /data /log

```

1.  按照以下步骤启动`mongod`进程：

```sql
$ sudo mongod --dbpath /data --logpath /log/mongodb.log --smallfiles --oplogsize 50 –fork

```

为了确保服务器进程正在运行，执行以下命令，并且我们应该在日志中看到以下内容：

```sql
$ tail /log/mongodb.log
2015-05-04T13:41:16.533+0000 [initandlisten] journal dir=/data/journal
2015-05-04T13:41:16.534+0000 [initandlisten] recover : no journal files present, no recovery needed
2015-05-04T13:41:16.628+0000 [initandlisten] waiting for connections on port 27017

```

1.  按照以下步骤启动 mongo shell 并执行以下命令：

```sql
$ mongo
> db.ec2Test.insert({_id: 1, message: 'Hello World !'})
> db.ec2Test.findOne()

```

## 工作原理…

许多步骤都是不言自明的。建议您至少阅读前一篇文章，因为那里解释了许多概念。在前一篇文章中解释的大多数概念也适用于这里。这一节中解释了一些不同的地方。对于安装，我们选择了 Ubuntu，而不是使用 AMI 设置服务器时的标准 Amazon Linux。不同的操作系统在安装方面有不同的步骤。请参阅[`docs.mongodb.org/manual/installation/`](http://docs.mongodb.org/manual/installation/)，了解如何在不同平台上安装 MongoDB 的步骤。本文中步骤 7 至 9 是特定于在 Ubuntu 上安装 MongoDB 的。请参阅[`help.ubuntu.com/12.04/serverguide/apt-get.html`](https://help.ubuntu.com/12.04/serverguide/apt-get.html)，了解我们在这里执行的`apt-get`命令的更多细节，以安装 MongoDB。

在我们的情况下，我们选择将数据、日志和日志文件夹放在同一个 EBS 卷上。这是因为我们设置的是一个`dev`实例。在`prod`实例的情况下，有不同的 EBS 卷，为了最佳性能，有预留的 IOPS。这种设置使我们能够利用这样一个事实，即这些不同的卷有不同的控制器，因此可以进行并发写操作。预留 IOPS 的 EBS 卷由 SSD 驱动器支持。[`docs.mongodb.org/manual/administration/production-notes/`](http://docs.mongodb.org/manual/administration/production-notes/)上的生产部署说明指出，MongoDB 部署应该由 RAID-10 磁盘支持。在 AWS 上部署时，优先选择 PIOPS 而不是 RAID-10。例如，如果需要 4000 IOPS，则选择具有 4000 IOPS 的 EBS 卷，而不是具有 2 X 2000 IOPS 或 4 X 1000 IOPS 设置的 RAID-10 设置。这不仅消除了不必要的复杂性，而且使得可以对单个磁盘进行快照，而不是处理 RAID-10 设置中的多个磁盘。谈到快照，大多数生产部署中的日志和数据是写入到不同的卷中的。这是快照无法工作的情况。我们需要刷新 DB 写入，锁定数据以进行进一步的写入，直到备份完成，然后释放锁定。有关快照和备份的更多详细信息，请参阅[`docs.mongodb.org/manual/tutorial/backup-with-filesystem-snapshots/`](http://docs.mongodb.org/manual/tutorial/backup-with-filesystem-snapshots/)。

请参阅[`docs.mongodb.org/ecosystem/platforms/`](http://docs.mongodb.org/ecosystem/platforms/)，了解在不同云提供商上部署的更多详细信息。有一个专门针对 Amazon EC2 实例备份的部分。在生产部署中，最好使用 AMI 来设置 MongoDB 实例，就像在前一篇文章中演示的那样，而不是手动设置实例。手动设置适用于小型开发目的，而具有预留 IOPS 的 EBS 卷的大型实例则过于复杂。

## 另请参阅

+   云形成是一种可以定义模板并自动化 EC2 实例创建的方式。您可以在[`aws.amazon.com/cloudformation/`](https://aws.amazon.com/cloudformation/)了解更多云形成是什么，并参考[`mongodb-documentation.readthedocs.org/en/latest/ecosystem/tutorial/automate-deployment-with-cloudformation.html`](https://mongodb-documentation.readthedocs.org/en/latest/ecosystem/tutorial/automate-deployment-with-cloudformation.html)。

+   另一种选择是使用 Mongo 的云服务：[`docs.cloud.mongodb.com/tutorial/nav/add-servers-through-aws-integration/`](https://docs.cloud.mongodb.com/tutorial/nav/add-servers-through-aws-integration/)。

+   您可以通过参考维基百科上的这两个 URL 了解有关 RAID 的更多信息：[`en.wikipedia.org/wiki/Standard_RAID_levels`](http://en.wikipedia.org/wiki/Standard_RAID_levels)和[`en.wikipedia.org/wiki/Nested_RAID_levels`](http://en.wikipedia.org/wiki/Nested_RAID_levels)。这里给出的描述非常全面。

# 使用 Docker 容器设置 MongoDB

容器移动，我喜欢称之为，已经触及了信息技术的几乎所有方面。作为首选工具的 Docker 对于创建和管理容器至关重要。

在本教程中，我们将在 Ubuntu（14.04）服务器上安装 Docker 并在容器中运行 MongoDB。

## 准备工作

1.  首先，我们需要在我们的 Ubuntu 服务器上安装 Docker，可以通过运行此命令来完成：

```sql
$ wget -qO- https://get.docker.com/ | sh

```

1.  启动 Docker 服务：

```sql
$ service docker start 
> docker start/running, process 24369

```

1.  确认 Docker 是否正在运行如下：

```sql
$ docker info
> Containers: 40
> Images: 311
> Storage Driver: aufs
>  Root Dir: /var/lib/docker/aufs
>  Dirs: 395
> Execution Driver: native-0.2
> Kernel Version: 3.13.0-37-generic
> Operating System: Ubuntu 14.04.2 LTS
> WARNING: No swap limit support

```

## 如何做…

1.  从 Docker Hub 获取默认的 MongoDB 图像如下：

```sql
$ docker pull mongo

```

1.  让我们确认图像是否已安装以下命令：

```sql
$ docker images | grep mongo

```

1.  启动 MongoDB 服务器：

```sql
$ docker run -d  --name mongo-server-1 mongo
> dfe7684dbc057f2d075450e3c6c96871dea98ff6b78abe72944360f4c239a72e

```

或者，您也可以运行`docker ps`命令来检查正在运行的容器列表。

1.  获取此容器的 IP：

```sql
$ docker inspect mongo-server-1 | grep IPAddress
> "IPAddress": "172.17.0.3",

```

1.  使用 mongo 客户端连接到我们的新容器：

```sql
$ mongo  172.17.0.3
>MongoDB shell version: 3.0.4
> connecting to: 172.17.0.3/test
> 

```

1.  在服务器上创建一个目录：

```sql
$ mkdir –p /data/db2

```

1.  启动一个新的 MongoDB 容器：

```sql
$ docker run -d --name mongo-server-2 -v /data/db1:/data/db mongo

```

1.  获取此新容器的 IP，如第 4 步所述，并使用 Mongo 客户端进行连接：

```sql
$ docker inspect mongo-server-2 | grep IPAddress
> "IPAddress": "172.17.0.4",
$ mongo  172.17.0.4
>MongoDB shell version: 3.0.4
> connecting to: 172.17.0.4/test
> 

```

1.  让我们为我们的最终容器创建另一个目录：

```sql
$ mkdir –p /data/db3 

```

启动一个新的 MongoDB 容器：

```sql
$ docker run -d --name mongo-server-3  -v /data/db3:/data/db -p 9999:27017 mongo

```

1.  让我们通过 localhost 连接到这个容器：

```sql
$ mongo localhost:9999
> MongoDB shell version: 3.0.4
> connecting to: localhost:9999/test

```

## 它是如何工作的…

我们首先从 DockerHub（[`hub.docker.com/_/mongo/`](https://hub.docker.com/_/mongo/)）下载默认的 MongoDB 图像。Docker 图像是为其应用程序定制的自持续 OS 图像。所有 Docker 容器都是这些图像的隔离执行。这与使用 OS 模板创建虚拟机非常相似。

图像下载操作默认为获取最新的稳定的 MongoDB 图像，但您可以通过提及标签来指定您选择的版本，例如`docker pull mongo:2.8`。

我们通过运行`docker images`命令来验证图像是否已下载，该命令将列出服务器上安装的所有图像。在第 3 步，我们使用名称`mongo-server-1`在分离（-d）模式下启动容器，使用我们的 mongo 图像。描述容器内部可能超出了本教程的范围，但简而言之，我们现在在我们的 Ubuntu 机器内部运行一个隔离的`docker 伪服务器`。

默认情况下，每个 Docker 容器都会被 docker 服务器分配一个 RFC 1918（不可路由）的 IP 地址空间。为了连接到这个容器，我们在第 4 步获取 IP 地址，并在第 5 步连接到`mongodb`实例。

但是，每个 Docker 容器都是短暂的，因此销毁容器意味着丢失数据。在第 6 步，我们创建一个本地目录，用于存储我们的 mongo 数据库。在第 7 步中启动一个新的容器；它类似于我们之前的命令，但增加了 Volumes（-v）开关。在我们的示例中，我们将`/data/db2`目录暴露给 mongo 容器命名空间作为`/data/db`。这类似于 NFS 样的文件挂载，但在内核命名空间的限制内。

最后，如果我们希望外部系统连接到此容器，我们将容器的端口绑定到主机的端口。在第 9 步，我们使用端口（-p）开关将 Ubuntu 服务器上的 TCP `9999`端口绑定到此容器的 TCP `27017`端口。这确保任何连接到服务器端口`9999`的外部系统将被路由到这个特定的容器。

## 另请参阅

您还可以尝试使用 docker 命令的 Link（-l）命令行参数链接两个容器。

有关更多信息，请访问[`docs.docker.com/userguide/dockerlinks/`](http://docs.docker.com/userguide/dockerlinks/)。


# 第八章：与 Hadoop 集成

在本章中，我们将涵盖以下示例：

+   使用 mongo-hadoop 连接器执行我们的第一个样本 MapReduce 作业

+   编写我们的第一个 Hadoop MapReduce 作业

+   在 Hadoop 上使用流式处理运行 MapReduce 作业

+   在 Amazon EMR 上运行 MapReduce 作业

# 介绍

Hadoop 是一个众所周知的用于处理大型数据集的开源软件。它还有一个用于 MapReduce 编程模型的 API，被广泛使用。几乎所有的大数据解决方案都有某种支持，以便将它们与 Hadoop 集成，以使用其 MapReduce 框架。MongoDB 也有一个连接器，可以与 Hadoop 集成，让我们使用 Hadoop MapReduce API 编写 MapReduce 作业，处理驻留在 MongoDB/MongoDB 转储中的数据，并将结果写入 MongoDB/MongoDB 转储文件。在本章中，我们将看一些关于基本 MongoDB 和 Hadoop 集成的示例。

# 使用 mongo-hadoop 连接器执行我们的第一个样本 MapReduce 作业

在这个示例中，我们将看到如何从源代码构建 mongo-hadoop 连接器，并设置 Hadoop，以便仅用于在独立模式下运行示例。连接器是在 Mongo 中使用数据运行 Hadoop MapReduce 作业的支柱。

## 准备工作

Hadoop 有各种发行版；但是，我们将使用 Apache Hadoop ([`hadoop.apache.org/`](http://hadoop.apache.org/))。安装将在 Ubuntu Linux 上进行。Apache Hadoop 始终在 Linux 环境下运行用于生产，Windows 未经过生产系统测试。开发目的可以使用 Windows。如果您是 Windows 用户，我建议您安装虚拟化环境，如 VirtualBox ([`www.virtualbox.org/`](https://www.virtualbox.org/))，设置 Linux 环境，然后在其上安装 Hadoop。在这个示例中没有展示设置 VirtualBox 和 Linux，但这不是一项繁琐的任务。这个示例的先决条件是一台安装了 Linux 操作系统的机器和一个互联网连接。我们将在这里设置 Apache Hadoop 的 2.4.0 版本。在撰写本书时，mongo-hadoop 连接器支持的最新版本是 2.4.0。

需要 Git 客户端来克隆 mongo-hadoop 连接器的存储库到本地文件系统。参考[`git-scm.com/book/en/Getting-Started-Installing-Git`](http://git-scm.com/book/en/Getting-Started-Installing-Git)来安装 Git。

您还需要在操作系统上安装 MongoDB。参考[`docs.mongodb.org/manual/installation/`](http://docs.mongodb.org/manual/installation/)并相应地安装它。启动监听端口`27017`的`mongod`实例。不需要您成为 Hadoop 的专家，但对它有一些了解会有所帮助。了解 MapReduce 的概念很重要，了解 Hadoop MapReduce API 将是一个优势。在这个示例中，我们将解释完成工作所需的内容。您可以从其他来源获取有关 Hadoop 及其 MapReduce API 的更多详细信息。维基页面[`en.wikipedia.org/wiki/MapReduce`](http://en.wikipedia.org/wiki/MapReduce)提供了有关 MapReduce 编程的一些很好的信息。

## 如何做…

1.  我们将首先安装 Java、Hadoop 和所需的软件包。我们将从在操作系统上安装 JDK 开始。在操作系统的命令提示符上键入以下内容：

```sql
$ javac –version

```

1.  如果程序无法执行，并告知您包含 javac 和程序的各种软件包，则需要按照以下方式安装 Java：

```sql
$ sudo apt-get install default-jdk

```

这就是我们安装 Java 所需要做的一切。

1.  从[`www.apache.org/dyn/closer.cgi/hadoop/common/`](http://www.apache.org/dyn/closer.cgi/hadoop/common/)下载当前版本的 Hadoop，并下载 2.4.0 版本（或最新的 mongo-hadoop 连接器支持）。

1.  在下载`.tar.gz`文件后，在命令提示符上执行以下操作：

```sql
$ tar –xvzf <name of the downloaded .tar.gz file>
$ cd <extracted directory>

```

打开`etc/hadoop/hadoop-env.sh`文件，并将`export JAVA_HOME = ${JAVA_HOME}`替换为`export JAVA_HOME = /usr/lib/jvm/default-java`。

现在，我们将在本地文件系统上从 GitHub 获取 mongo-hadoop 连接器代码。请注意，您无需 GitHub 帐户即可克隆存储库。请按照以下操作系统命令提示符中的 Git 项目进行克隆：

```sql
$git clone https://github.com/mongodb/mongo-hadoop.git
$cd mongo-hadoop 

```

1.  创建软链接- Hadoop 安装目录与我们在第 3 步中提取的目录相同：

```sql
$ln –s <hadoop installation directory> ~/hadoop-binaries

```

例如，如果 Hadoop 在主目录中提取/安装，则应执行以下命令：

```sql
$ln –s ~/hadoop-2.4.0 ~/hadoop-binaries

```

默认情况下，mongo-hadoop 连接器将在`〜/hadoop-binaries`文件夹下查找 Hadoop 分发。因此，即使 Hadoop 存档在其他位置提取，我们也可以创建软链接。创建软链接后，我们应该在`〜/hadoop-binaries/hadoop-2.4.0/bin`路径中拥有 Hadoop 二进制文件。

1.  现在，我们将从源代码为 Apache Hadoop 版本 2.4.0 构建 mongo-hadoop 连接器。默认情况下，构建最新版本，因此现在可以省略`-Phadoop_version`参数，因为 2.4 是最新版本。

```sql
$./gradlew jar –Phadoop_version='2.4'

```

此构建过程将需要一些时间才能完成。

1.  构建成功后，我们将准备执行我们的第一个 MapReduce 作业。我们将使用 mongo-hadoop 连接器项目提供的`treasuryYield`示例来执行此操作。第一步是将数据导入 Mongo 的集合中。

1.  假设`mongod`实例正在运行并监听端口`27017`进行连接，并且当前目录是 mongo-hadoop 连接器代码库的根目录，请执行以下命令：

```sql
$ mongoimport -c yield_historical.in -d mongo_hadoop --drop examples/treasury_yield/src/main/resources/yield_historical_in.json

```

1.  导入操作成功后，我们需要将两个 jar 文件复制到`lib`目录中。在操作系统 shell 中执行以下操作：

```sql
$ wget http://repo1.maven.org/maven2/org/mongodb/mongo-java-driver/2.12.0/mongo-java-driver-2.12.0.jar
$ cp core/build/libs/mongo-hadoop-core-1.2.1-SNAPSHOT-hadoop_2.4.jar ~/hadoop-binaries/hadoop-2.4.0/lib/
$ mv mongo-java-driver-2.12.0.jar ~/hadoop-binaries/hadoop-2.4.0/lib

```

### 注意

为了 mongo-hadoop 核心构建的 JAR 文件要复制，根据代码的前面部分和为 Hadoop-2.4.0 构建的版本，更改 JAR 的名称。当您为连接器和 Hadoop 的不同版本自行构建时，Mongo 驱动程序可以是最新版本。在撰写本书时，版本 2.12.0 是最新版本。

1.  现在，在操作系统 shell 的命令提示符上执行以下命令：

```sql
 ~/hadoop-binaries/hadoop-2.4.0/bin/hadoop     jar     examples/treasury_yield/build/libs/treasury_yield-1.2.1-SNAPSHOT-hadoop_2.4.jar  \com.mongodb.hadoop.examples.treasury.TreasuryYieldXMLConfig  \-Dmongo.input.split_size=8     -Dmongo.job.verbose=true  \-Dmongo.input.uri=mongodb://localhost:27017/mongo_hadoop.yield_historical.in  \-Dmongo.output.uri=mongodb://localhost:27017/mongo_hadoop.yield_historical.out

```

1.  输出应该打印出很多内容；但是，输出中的以下行告诉我们 MapReduce 作业成功：

```sql
 14/05/11 21:38:54 INFO mapreduce.Job: Job job_local1226390512_0001 completed successfully

```

1.  从 mongo 客户端连接运行在本地主机上的`mongod`实例，并对以下集合执行查找：

```sql
$ mongo
> use mongo_hadoop
switched to db mongo_hadoop
> db.yield_historical.out.find()

```

## 工作原理…

安装 Hadoop 并不是一项简单的任务，我们不需要进行这项工作来尝试 hadoop-mongo 连接器的示例。有专门的书籍和文章可供学习 Hadoop、其安装和其他内容。在本章中，我们将简单地下载存档文件，提取并以独立模式运行 MapReduce 作业。这是快速入门 Hadoop 的最快方式。在步骤 6 之前的所有步骤都是安装 Hadoop 所需的。在接下来的几个步骤中，我们将克隆 mongo-hadoop 连接器配方。如果您不想从源代码构建，也可以在[`github.com/mongodb/mongo-hadoop/releases`](https://github.com/mongodb/mongo-hadoop/releases)下载适用于您 Hadoop 版本的稳定版本。然后，我们为我们的 Hadoop 版本（2.4.0）构建连接器，直到第 13 步。从第 14 步开始，我们将运行实际的 MapReduce 作业来处理 MongoDB 中的数据。我们将数据导入到`yield_historical.in`集合中，这将作为 MapReduce 作业的输入。继续使用`mongo_hadoop`数据库在 mongo shell 中查询集合，以查看文档。如果您不理解内容，不用担心；我们想要看到这个示例中的数据意图。

下一步是在数据上调用 MapReduce 操作。执行 Hadoop 命令，给出一个 jar 的路径（`examples/treasury_yield/build/libs/treasury_yield-1.2.1-SNAPSHOT-hadoop_2.4.jar`）。这个 jar 包含了实现国库收益率样本 MapReduce 操作的类。在这个 JAR 文件中的`com.mongodb.hadoop.examples.treasury.TreasuryYieldXMLConfig`类是包含主方法的引导类。我们很快就会访问这个类。连接器支持许多配置。完整的配置列表可以在[`github.com/mongodb/mongo-hadoop/`](https://github.com/mongodb/mongo-hadoop/)找到。现在，我们只需要记住`mongo.input.uri`和`mongo.output.uri`是 map reduce 操作的输入和输出集合。

项目克隆后，您现在可以将其导入到您选择的任何 Java IDE 中。我们特别感兴趣的是位于`/examples/treasury_yield`的项目和位于克隆存储库根目录中的核心。

让我们看一下`com.mongodb.hadoop.examples.treasury.TreasuryYieldXMLConfig`类。这是 MapReduce 方法的入口点，并在其中有一个主方法。要使用 mongo-hadoop 连接器为 mongo 编写 MapReduce 作业，主类始终必须扩展自`com.mongodb.hadoop.util.MongoTool`。这个类实现了`org.apache.hadoop.Tool`接口，该接口具有 run 方法，并由`MongoTool`类为我们实现。主方法需要做的就是使用`org.apache.hadoop.util.ToolRunner`类执行这个类，通过调用其静态`run`方法传递我们的主类的实例（这是`Tool`的实例）。

有一个静态块，从两个 XML 文件`hadoop-local.xml`和`mongo-defaults.xml`中加载一些配置。这些文件（或任何 XML 文件）的格式如下。文件的根节点是具有多个属性节点的配置节点：

```sql
<configuration>
  <property>
    <name>{property name}</name> 
    <value>{property value}</value>
  </property>
  ...
</configuration>
```

在这种情况下有意义的属性值是我们之前提到的 URL 中提供的所有值。我们在引导类`TreasuryYieldXmlConfig`的构造函数中实例化`com.mongodb.hadoop.MongoConfig`，将`org.apache.hadoop.conf.Configuration`的实例包装起来。`MongoConfig`类提供了合理的默认值，这足以满足大多数用例。我们需要在`MongoConfig`实例中设置的一些最重要的事情是输出和输入格式、`mapper`和`reducer`类、mapper 的输出键和值，以及 reducer 的输出键和值。输入格式和输出格式将始终是`com.mongodb.hadoop.MongoInputFormat`和`com.mongodb.hadoop.MongoOutputFormat`类，这些类由 mongo-hadoop 连接器库提供。对于 mapper 和 reducer 的输出键和值，我们有任何`org.apache.hadoop.io.Writable`实现。有关`org.apache.hadoop.io`包中不同类型的 Writable 实现，请参考 Hadoop 文档。除此之外，mongo-hadoop 连接器还在`com.mongodb.hadoop.io`包中为我们提供了一些实现。对于国库收益率示例，我们使用了`BSONWritable`实例。这些可配置的值可以在之前看到的 XML 文件中提供，也可以以编程方式设置。最后，我们可以选择将它们作为`vm`参数提供，就像我们为`mongo.input.uri`和`mongo.output.uri`所做的那样。这些参数可以在 XML 中提供，也可以直接从代码中在`MongoConfig`实例上调用；这两种方法分别是`setInputURI`和`setOutputURI`。

现在我们将看一下`mapper`和`reducer`类的实现。我们将在这里复制类的重要部分以进行分析。有关整个实现，请参考克隆的项目：

```sql
public class TreasuryYieldMapper
    extends Mapper<Object, BSONObject, IntWritable, DoubleWritable> {

    @Override
    public void map(final Object pKey,
                    final BSONObject pValue,
                    final Context pContext)
        throws IOException, InterruptedException {
        final int year = ((Date) pValue.get("_id")).getYear() + 1900;
        double bid10Year = ((Number) pValue.get("bc10Year")).doubleValue();
        pContext.write(new IntWritable(year), new DoubleWritable(bid10Year));
    }
}
```

我们的 mapper 扩展了`org.apache.hadoop.mapreduce.Mapper`类。四个通用参数是键类、输入值类型、输出键类型和输出值类型。map 方法的主体从输入文档中读取`_id`值，即日期，并从中提取年份。然后，它从文档中获取`bc10Year`字段的双值，并简单地写入上下文键值对，其中键是年份，双值是上下文键值对的值。这里的实现不依赖于传递的`pKey`参数的值，可以使用该值作为键，而不是在实现中硬编码`_id`值。该值基本上是使用 XML 中的`mongo.input.key`属性或`MongoConfig.setInputKey`方法设置的相同字段。如果没有设置，`_id`是默认值。

让我们来看一下 reducer 的实现（删除了日志记录语句）：

```sql
public class TreasuryYieldReducer extends Reducer<IntWritable, DoubleWritable, IntWritable, BSONWritable> {

    @Override
    public void reduce(final IntWritable pKey, final Iterable<DoubleWritable> pValues, final Context pContext)throws IOException, InterruptedException {
      int count = 0;
      double sum = 0;
      for (final DoubleWritable value : pValues) {
        sum += value.get();
        count++;
      }
      final double avg = sum / count;
      BasicBSONObject output = new BasicBSONObject();
      output.put("count", count);
      output.put("avg", avg);
      output.put("sum", sum);
      pContext.write(pKey, new BSONWritable(output));
    }
}
```

这个类扩展自`org.apache.hadoop.mapreduce.Reducer`，有四个通用参数：输入键、输入值、输出键和输出值。reducer 的输入是 mapper 的输出，因此，如果你仔细观察，你会发现前两个通用参数的类型与我们之前看到的 mapper 的最后两个通用参数相同。第三和第四个参数是从 reduce 中发出的键和值的类型。值的类型是`BSONDocument`，因此我们有`BSONWritable`作为类型。

现在我们有了 reduce 方法，它有两个参数：第一个是键，与 map 函数发出的键相同，第二个参数是发出的相同键的值的`java.lang.Iterable`。这就是标准的 map reduce 函数的工作原理。例如，如果 map 函数给出以下键值对，(1950, 10), (1960, 20), (1950, 20), (1950, 30)，那么 reduce 将使用两个唯一的键 1950 和 1960 进行调用，并且键 1950 的值将是`Iterable`，包括(10, 20, 30)，而 1960 的值将是单个元素(20)的`Iterable`。reducer 的 reduce 函数简单地迭代双值的`Iterable`，找到这些数字的和与计数，并写入一个键值对，其中键与传入的键相同，输出值是`BasicBSONObject`，其中包括计算值的和、计数和平均值。

在克隆的 mongo-hadoop 连接器示例中，包括 Enron 数据集在内有一些很好的示例。如果你想玩一下，我建议你看看这些示例项目并运行它们。

## 更多内容…

我们在这里看到的是一个现成的示例，我们执行了它。没有什么比自己编写一个 MapReduce 作业来澄清我们的理解更好。在下一个示例中，我们将使用 Java 中的 Hadoop API 编写一个 MapReduce 作业，并看到它的运行情况。

## 另请参阅…

如果你想知道`Writable`接口是什么，为什么不应该使用普通的旧序列化，那么请参考这个 URL，由 Hadoop 的创建者解释：[`www.mail-archive.com/hadoop-user@lucene.apache.org/msg00378.html`](http://www.mail-archive.com/hadoop-user@lucene.apache.org/msg00378.html)。

# 编写我们的第一个 Hadoop MapReduce 作业

在这个示例中，我们将使用 Hadoop MapReduce API 编写我们的第一个 MapReduce 作业，并使用 mongo-hadoop 连接器从 MongoDB 获取数据运行它。请参考第三章中的*使用 Java 客户端在 Mongo 中执行 MapReduce*示例，了解如何使用 Java 客户端实现 MapReduce、测试数据创建和问题陈述。

## 准备工作

请参考之前的*使用 mongo-hadoop 连接器执行我们的第一个样本 MapReduce 作业*食谱来设置 mongo-hadoop 连接器。此食谱的先决条件和第三章中的*使用 Java 客户端在 Mongo 中执行 MapReduce*食谱是我们此食谱所需的全部内容。这是一个 maven 项目，因此需要设置和安装 maven。请参考第一章中的*从 Java 客户端连接到单节点*食谱，在那里我们提供了在 Windows 上设置 maven 的步骤；该项目是在 Ubuntu Linux 上构建的，以下是您需要在操作系统 shell 中执行的命令：

```sql
$ sudo apt-get install maven

```

## 操作步骤如下...

1.  我们有一个 Java `mongo-hadoop-mapreduce-test`项目，可以从 Packt 网站下载。该项目旨在实现我们在第三章中实现的用例，即在 MongoDB 的 MapReduce 框架中使用 Python 和 Java 客户端调用 MapReduce 作业。

1.  在项目根目录中的当前目录中的命令提示符下，执行以下命令：

```sql
$ mvn clean package

```

1.  JAR 文件`mongo-hadoop-mapreduce-test-1.0.jar`将被构建并保存在目标目录中。

1.  假设 CSV 文件已经导入到`postalCodes`集合中，请在仍然位于我们刚构建的`mongo-hadoop-mapreduce-test`项目根目录中的当前目录中执行以下命令：

```sql
~/hadoop-binaries/hadoop-2.4.0/bin/hadoop \
 jar target/mongo-hadoop-mapreduce-test-1.0.jar \
 com.packtpub.mongo.cookbook.TopStateMapReduceEntrypoint \
 -Dmongo.input.split_size=8 \
-Dmongo.job.verbose=true \
-Dmongo.input.uri=mongodb://localhost:27017/test.postalCodes \
-Dmongo.output.uri=mongodb://localhost:27017/test.postalCodesHadoopmrOut

```

1.  MapReduce 作业完成后，通过在操作系统命令提示符上键入以下内容打开 mongo shell，并在 shell 中执行以下查询：

```sql
$ mongo
> db.postalCodesHadoopmrOut.find().sort({count:-1}).limit(5)

```

1.  将输出与我们之前使用 mongo 的 map reduce 框架执行 MapReduce 作业时获得的输出进行比较（在第三章中，*编程语言驱动程序*）。

## 工作原理...

我们将类保持得非常简单，只包含我们需要的最少内容。我们的项目中只有三个类：`TopStateMapReduceEntrypoint`、`TopStateReducer`和`TopStatesMapper`，都在同一个`com.packtpub.mongo.cookbook`包中。mapper 的`map`函数只是将键值对写入上下文，其中键是州的名称，值是整数值 1。以下是来自`mapper`函数的代码片段：

```sql
context.write(new Text((String)value.get("state")), new IntWritable(1));
```

Reducer 获得的是相同的键，即州的列表和整数值，为 1。我们所做的就是将相同州的名称和可迭代的总和写入上下文。现在，由于在 Iterable 中没有 size 方法可以在常数时间内给出计数，我们只能在线性时间内将所有得到的 1 相加。以下是 reducer 方法中的代码：

```sql
int sum = 0;
for(IntWritable value : values) {
  sum += value.get();
}
BSONObject object = new BasicBSONObject();
object.put("count", sum);
context.write(text, new BSONWritable(object));
```

我们将文本字符串写入键，将包含计数的 JSON 文档写入上下文。然后，mongo-hadoop 连接器负责将`postalCodesHadoopmrOut`文档写入我们拥有的输出集合，其中`_id`字段与发射的键相同。因此，当我们执行以下操作时，我们将获得数据库中拥有最多城市的前五个州：

```sql
> db. postalCodesHadoopmrOut.find().sort({count:-1}).limit(5)
{ "_id" : "Maharashtra", "count" : 6446 }
{ "_id" : "Kerala", "count" : 4684 }
{ "_id" : "Tamil Nadu", "count" : 3784 }
{ "_id" : "Andhra Pradesh", "count" : 3550 }
{ "_id" : "Karnataka", "count" : 3204 }

```

最后，主入口类的主方法如下：

```sql
Configuration conf = new Configuration();
MongoConfig config = new MongoConfig(conf);
config.setInputFormat(MongoInputFormat.class);
config.setMapperOutputKey(Text.class);
config.setMapperOutputValue(IntWritable.class);
config.setMapper(TopStatesMapper.class);
config.setOutputFormat(MongoOutputFormat.class);
config.setOutputKey(Text.class);
config.setOutputValue(BSONWritable.class);
config.setReducer(TopStateReducer.class);
ToolRunner.run(conf, new TopStateMapReduceEntrypoint(), args);
```

我们所做的就是使用`com.mongodb.hadoop.MongoConfig`实例将`org.apache.hadoop.conf.Configuration`对象包装起来，以设置各种属性，然后使用 ToolRunner 提交 MapReduce 作业以执行。

## 另请参阅

我们使用 Hadoop API 在 Hadoop 上执行了一个简单的 MapReduce 作业，从 MongoDB 获取数据，并将数据写入 MongoDB 集合。如果我们想要用不同的语言编写`map`和`reduce`函数怎么办？幸运的是，使用一个称为 Hadoop streaming 的概念是可能的，其中`stdout`用作程序和 Hadoop MapReduce 框架之间的通信手段。在下一个示例中，我们将演示如何使用 Python 来实现与本示例中相同的用例，使用 Hadoop streaming。

# 使用流式传输在 Hadoop 上运行 MapReduce 作业

在我们之前的示例中，我们使用 Hadoop 的 Java API 实现了一个简单的 MapReduce 作业。用例与我们在第三章的示例中使用 Python 和 Java 中的 Mongo 客户端 API 实现 MapReduce 相同。在这个示例中，我们将使用 Hadoop streaming 来实现 MapReduce 作业。

流式传输的概念是基于使用`stdin`和`stdout`进行通信。您可以在[`hadoop.apache.org/docs/r1.2.1/streaming.html`](http://hadoop.apache.org/docs/r1.2.1/streaming.html)上获取有关 Hadoop streaming 及其工作原理的更多信息。

## 准备工作…

请参考本章中的*使用 mongo-hadoop 连接器执行我们的第一个示例 MapReduce 作业*示例，了解如何为开发目的设置 Hadoop 并使用 Gradle 构建 mongo-hadoop 项目。就 Python 库而言，我们将从源代码安装所需的库；但是，如果您不希望从源代码构建，可以使用`pip`（Python 的软件包管理器）进行设置。我们还将看到如何使用`pip`设置 pymongo-hadoop。

参考第一章中的*使用 Python 客户端连接到单个节点*示例，了解如何为您的主机操作系统安装 PyMongo。

## 工作原理…

1.  我们将首先从源代码构建 pymongo-hadoop。将项目克隆到本地文件系统后，在克隆项目的根目录中执行以下操作：

```sql
$ cd streaming/language_support/python
$ sudo python setup.py install

```

1.  输入密码后，设置将继续在您的计算机上安装 pymongo-hadoop。

1.  这就是我们需要从源代码构建 pymongo-hadoop 的全部内容。但是，如果您选择不从源代码构建，可以在操作系统 shell 中执行以下命令：

```sql
$ sudo pip install pymongo_hadoop

```

1.  以任何方式安装 pymongo-hadoop 后，我们将在 Python 中实现我们的`mapper`和`reducer`函数。`mapper`函数如下：

```sql
#!/usr/bin/env python

import sys
from pymongo_hadoop import BSONMapper
def mapper(documents):
  print >> sys.stderr, 'Starting mapper'
  for doc in documents:
    yield {'_id' : doc['state'], 'count' : 1}
  print >> sys.stderr, 'Mapper completed'

BSONMapper(mapper)
```

1.  现在是`reducer`函数，将如下所示：

```sql
#!/usr/bin/env python

import sys
from pymongo_hadoop import BSONReducer
def reducer(key, documents):
  print >> sys.stderr, 'Invoked reducer for key "', key, '"'
  count = 0
  for doc in documents:
    count += 1
  return {'_id' : key, 'count' : count}

BSONReducer(reducer)
```

1.  环境变量`$HADOOP_HOME`和`$HADOOP_CONNECTOR_HOME`应该分别指向 Hadoop 和 mongo-hadoop 连接器项目的基本目录。现在，我们将在操作系统 shell 中使用以下命令调用`MapReduce`函数。书中提供的代码在 Packt 网站上有`mapper`，`reduce` Python 脚本和 shell 脚本，将用于调用`mapper`和`reducer`函数：

```sql
$HADOOP_HOME/bin/hadoop jar \
$HADOOP_HOME/share/hadoop/tools/lib/hadoop-streaming* \
-libjars $HADOOP_CONNECTOR_HOME/streaming/build/libs/mongo-hadoop-streaming-1.2.1-SNAPSHOT-hadoop_2.4.jar \
-input /tmp/in \
-output /tmp/out \
-inputformat com.mongodb.hadoop.mapred.MongoInputFormat \
-outputformat com.mongodb.hadoop.mapred.MongoOutputFormat \
-io mongodb \
-jobconf mongo.input.uri=mongodb://127.0.0.1:27017/test.postalCodes \
-jobconf mongo.output.uri=mongodb://127.0.0.1:27017/test.pyMRStreamTest \
-jobconf stream.io.identifier.resolver.class=com.mongodb.hadoop.streaming.io.MongoIdentifierResolver \
-mapper mapper.py \
-reducer reducer.py

```

在执行此命令时，`mapper.py`和`reducer.py`文件位于当前目录中。

1.  执行该命令时，应该需要一些时间来成功执行 MapReduce 作业，在操作系统命令提示符上键入以下命令打开 mongo shell，并从 shell 执行以下查询：

```sql
$ mongo
> db.pyMRStreamTest.find().sort({count:-1}).limit(5)

```

1.  将输出与我们之前在第三章中使用 mongo 的 MapReduce 框架执行 MapReduce 作业时获得的输出进行比较，*编程语言驱动程序*。

## 如何做…

让我们看一下步骤 5 和 6，我们编写`mapper`和`reducer`函数。我们定义了一个接受所有文档列表的`map`函数。我们遍历这些文档，并产生文档，其中`_id`字段是键的名称，计数值字段的值为 1。产生的文档数量将与输入文档的总数相同。

最后，我们实例化了`BSONMapper`，它接受`mapper`函数作为参数。该函数返回一个生成器对象，然后该`BSONMapper`类使用它来向 MapReduce 框架提供值。我们需要记住的是，`mapper`函数需要返回一个生成器（在循环中调用`yield`时返回），然后实例化`BSONMapper`类，这是由`pymongo_hadoop`模块提供给我们的。如果你感兴趣，你可以选择查看我们本地文件系统中克隆的项目中的`streaming/language_support/python/pymongo_hadoop/mapper.py`文件的源代码，看看它是做什么的。这是一段小而简单易懂的代码。

对于`reducer`函数，我们得到了键和该键对应的文档列表作为值。键与`map`函数中发出的文档的`_id`字段的值相同。我们在这里简单地返回一个新文档，其中`_id`是州的名称，计数是该州的文档数。记住，我们返回一个文档，而不是像在 map 中那样发出一个文档。最后，我们实例化`BSONReducer`并传递`reducer`函数。在我们本地文件系统中克隆的项目中的`streaming/language_support/python/pymongo_hadoop/reducer.py`文件中有`BSONReducer`类的实现。

最后，我们在 shell 中调用命令来启动使用流处理的 MapReduce 作业。这里需要注意的几点是，我们需要两个 JAR 文件：一个在 Hadoop 分发的`share/hadoop/tools/lib`目录中，另一个在 mongo-hadoop 连接器中，位于`streaming/build/libs/`目录中。输入和输出格式分别是`com.mongodb.hadoop.mapred.MongoInputFormat`和`com.mongodb.hadoop.mapred.MongoOutputFormat`。

正如我们之前看到的，`sysout`和`sysin`构成了流处理的基础。所以，基本上，我们需要对我们的 BSON 对象进行编码以写入`sysout`，然后，我们应该能够读取`sysin`以将内容再次转换为 BSON 对象。为此，mongo-hadoop 连接器为我们提供了两个框架类，`com.mongodb.hadoop.streaming.io.MongoInputWriter`和`com.mongodb.hadoop.streaming.io.MongoOutputReader`，用于对 BSON 对象进行编码和解码。这些类分别扩展自`org.apache.hadoop.streaming.io.InputWriter`和`org.apache.hadoop.streaming.io.OutputReader`。

`stream.io.identifier.resolver.class`属性的值是`com.mongodb.hadoop.streaming.io.MongoIdentifierResolver`。这个类继承自`org.apache.hadoop.streaming.io.IdentifierResolver`，并且让我们有机会注册我们的`org.apache.hadoop.streaming.io.InputWriter`和`org.apache.hadoop.streaming.io.OutputReader`的实现到框架中。我们还使用我们自定义的`IdentifierResolver`注册输出键和输出值类。只要记住，如果你正在使用 mongo-hadoop 连接器进行流处理，一定要始终使用这个解析器。

我们最终执行了之前讨论过的`mapper`和`reducer`的 Python 函数。要记住的一件重要的事情是，不要从`mapper`和`reducer`函数中向`sysout`打印日志。`sysout`和`sysin`的 mapper 和 reducer 是通信的手段，向其中写入日志可能会产生不良行为。正如我们在示例中看到的，要么写入标准错误（`stderr`），要么写入日志文件。

### 注意

在 Unix 中使用多行命令时，可以使用`\`在下一行继续命令。但是，记住在`\`后面不要有空格。

# 在 Amazon EMR 上运行 MapReduce 作业

这个教程涉及在 AWS 上使用云来运行 MapReduce 作业。您需要一个 AWS 账户才能继续。在[`aws.amazon.com/`](http://aws.amazon.com/)注册 AWS。我们将看到如何在云上使用 Amazon Elastic Map Reduce (Amazon EMR)运行 MapReduce 作业。Amazon EMR 是亚马逊在云上提供的托管 MapReduce 服务。更多详情请参考[`aws.amazon.com/elasticmapreduce/`](https://aws.amazon.com/elasticmapreduce/)。Amazon EMR 从 AWS S3 存储桶中获取数据、二进制文件/JAR 等，处理它们并将结果写回 S3 存储桶。Amazon Simple Storage Service (Amazon S3)是 AWS 提供的另一个用于云上数据存储的服务。更多关于 Amazon S3 的详情请参考[`aws.amazon.com/s3/`](http://aws.amazon.com/s3/)。虽然我们将使用 mongo-hadoop 连接器，有趣的是我们不需要一个 MongoDB 实例在运行。我们将使用存储在 S3 存储桶中的 MongoDB 数据转储进行数据分析。MapReduce 程序将在输入的 BSON 转储上运行，并在输出存储桶中生成结果 BSON 转储。MapReduce 程序的日志将被写入另一个专门用于日志的存储桶。下图给出了我们的设置在高层次上的样子：

在 Amazon EMR 上运行 MapReduce 作业

## 准备工作

我们将使用与*编写我们的第一个 Hadoop MapReduce 作业*教程相同的 Java 示例。要了解更多关于`mapper`和`reducer`类实现的信息，您可以参考同一教程的*它是如何工作的*部分。我们有一个`mongo-hadoop-emr-test`项目，其中包含可以从 Packt 网站下载的代码，用于使用 AWS EMR API 在云上创建 MapReduce 作业。为了简化事情，我们将只上传一个 JAR 到 S3 存储桶来执行 MapReduce 作业。这个 JAR 将使用 BAT 文件在 Windows 上组装，使用 Unix 操作系统上的 shell 脚本。`mongo-hadoop-emr-test`Java 项目有一个`mongo-hadoop-emr-binaries`子目录，其中包含必要的二进制文件以及将它们组装成一个 JAR 的脚本。

已组装的`mongo-hadoop-emr-assembly.jar`文件也提供在子目录中。运行`.bat`或`.sh`文件将删除这个 JAR 并重新生成已组装的 JAR，这并不是必需的。已提供的已组装的 JAR 足够好，可以正常工作。Java 项目包含一个`data`子目录，其中包含一个`postalCodes.bson`文件。这是从包含`postalCodes`集合的数据库中生成的 BSON 转储。mongo 分发提供的`mongodump`实用程序用于提取这个转储。

## 如何操作...

1.  这个练习的第一步是在 S3 上创建一个存储桶。您可以选择使用现有的存储桶；但是，对于这个教程，我创建了一个`com.packtpub.mongo.cookbook.emr-in`存储桶。请记住，存储桶的名称必须在所有 S3 存储桶中是唯一的，您将无法创建一个具有相同名称的存储桶。您将不得不创建一个不同名称的存储桶，并在这个教程中使用它来代替`com.packtpub.mongo.cookbook.emr-in`。

### 提示

不要使用下划线(`_`)创建存储桶名称；而是使用连字符(`-`)。使用下划线创建存储桶名称不会失败；但是后来的 MapReduce 作业会失败，因为它不接受存储桶名称中的下划线。

1.  我们将上传已组装的 JAR 文件和一个`.bson`文件到新创建（或现有）的 S3 存储桶。要上传文件，我们将使用 AWS 网络控制台。点击**上传**按钮，选择已组装的 JAR 文件和`postalCodes.bson`文件上传到 S3 存储桶。上传后，存储桶的内容应该如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_08_01.jpg)

1.  接下来的步骤是从 AWS 控制台启动 EMR 作业，而不需要编写一行代码。我们还将看到如何使用 AWS Java SDK 启动此作业。如果您希望从 AWS 控制台启动 EMR 作业，请按照步骤 4 到 9 进行。如果要使用 Java SDK 启动 EMR 作业，请按照步骤 10 和 11 进行。

1.  我们将首先从 AWS 控制台启动一个 MapReduce 作业。访问[`console.aws.amazon.com/elasticmapreduce/`](https://console.aws.amazon.com/elasticmapreduce/)并点击**创建集群**按钮。在**集群配置**屏幕中，输入图中显示的细节，除了日志桶，您需要选择作为日志需要写入的桶。您还可以点击文本框旁边的文件夹图标，选择您的帐户中存在的桶作为日志桶。![操作步骤…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_08_07.jpg)

### 注意

终止保护选项设置为**否**，因为这是一个测试实例。如果出现任何错误，我们宁愿希望实例终止，以避免保持运行并产生费用。

1.  在**软件配置**部分，选择**Hadoop 版本**为**2.4.0**，**AMI 版本**为**3.1.0 (hadoop 2.4.0)**。通过点击其名称旁边的叉号来移除额外的应用程序，如下图所示：![操作步骤…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_08_08.jpg)

1.  在**硬件配置**部分，选择**EC2 实例类型**为**m1.medium**。这是我们需要为 Hadoop 版本 2.4.0 选择的最低配置。从下图中可以看到所选择的从属和任务实例的数量为零：![操作步骤…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_08_09.jpg)

1.  在**安全和访问**部分，保留所有默认值。我们也不需要**引导操作**，所以也保持不变。

1.  最后一步是为 MapReduce 作业设置**步骤**。在**添加步骤**下拉菜单中，选择**自定义 JAR**选项，然后选择**自动终止**选项为**是**，如下图所示：![操作步骤…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_08_10.jpg)

现在点击**配置**和**添加**按钮并输入细节。

**JAR S3 位置**的值为`s3://com.packtpub.mongo.cookbook.emr-in/mongo-hadoop-emr-assembly.jar`。这是我输入桶中的位置；您需要根据自己的输入桶更改输入桶。JAR 文件的名称将保持不变。

在**参数**文本区域中输入以下参数；主类的名称在列表中排在第一位：

`com.packtpub.mongo.cookbook.TopStateMapReduceEntrypoint`

`-Dmongo.job.input.format=com.mongodb.hadoop.BSONFileInputFormat`

`-Dmongo.job.mapper=com.packtpub.mongo.cookbook.TopStatesMapper`

-Dmongo.job.reducer=com.packtpub.mongo.cookbook.TopStateReducer

`-Dmongo.job.output=org.apache.hadoop.io.Text`

`-Dmongo.job.output.value=org.apache.hadoop.io.IntWritable`

`-Dmongo.job.output.value=org.apache.hadoop.io.IntWritable`

`-Dmongo.job.output.format=com.mongodb.hadoop.BSONFileOutputFormat`

`-Dmapred.input.dir=s3://com.packtpub.mongo.cookbook.emr-in/postalCodes.bson`

`-Dmapred.output.dir=s3://com.packtpub.mongo.cookbook.emr-out/`

1.  最后两个参数的值包含了我 MapReduce 样本使用的输入和输出桶；这个值将根据您自己的输入和输出桶而改变。失败时的操作值将为终止。在填写完所有这些细节后，点击**保存**：![操作步骤…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_08_11.jpg)

1.  现在点击**创建集群**按钮。这将需要一些时间来配置和启动集群。

1.  在接下来的几步中，我们将使用 AWS Java API 在 EMR 上创建一个 MapReduce 作业。将提供的代码示例中的`EMRTest`项目导入到您喜欢的 IDE 中。导入后，打开`com.packtpub.mongo.cookbook.AWSElasticMapReduceEntrypoint`类。

1.  类中有五个常量需要更改。它们是您将用于示例的输入、输出和日志存储桶，以及 AWS 访问密钥和秘密密钥。访问密钥和秘密密钥在您使用 AWS SDK 时充当用户名和密码。相应地更改这些值并运行程序。成功执行后，它应该为您新启动的作业提供一个作业 ID。

1.  无论您如何启动 EMR 作业，请访问 EMR 控制台[`console.aws.amazon.com/elasticmapreduce/`](https://console.aws.amazon.com/elasticmapreduce/)以查看您提交的 ID 的状态。您在启动的作业的第二列中可以看到作业 ID，它将与您执行 Java 程序时在控制台上打印的作业 ID 相同（如果您使用 Java 程序启动）。单击启动的作业的名称，这应该将您引导到作业详细信息页面。硬件配置将需要一些时间，然后最终，您的 MapReduce 步骤将运行。作业完成后，作业的状态应在作业详细信息屏幕上如下所示:![操作方法…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_08_04.jpg)

展开后，**步骤**部分应如下所示：

![操作方法…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_08_05.jpg)

1.  单击日志文件部分下方的 stderr 链接，以查看 MapReduce 作业的所有日志输出。

1.  现在 MapReduce 作业已完成，我们的下一步是查看其结果。访问 S3 控制台[`console.aws.amazon.com/s3`](https://console.aws.amazon.com/s3)并访问输出存储桶。在我的情况下，以下是输出存储桶的内容:![操作方法…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_08_06.jpg)

`part-r-0000.bson`文件是我们感兴趣的。这个文件包含了我们的 MapReduce 作业的结果。

1.  将文件下载到本地文件系统，并使用 mongorestore 实用程序导入到本地运行的 mongo 实例中。请注意，以下命令的还原实用程序期望 mongod 实例正在运行并侦听端口`27017`，并且当前目录中有`part-r-0000.bson`文件：

```sql
$ mongorestore part-r-00000.bson -d test -c mongoEMRResults

```

1.  现在，使用 mongo shell 连接到`mongod`实例并执行以下查询：

```sql
> db.mongoEMRResults.find().sort({count:-1}).limit(5)

```

对于查询，我们将看到以下结果：

```sql
{ "_id" : "Maharashtra", "count" : 6446 }
{ "_id" : "Kerala", "count" : 4684 }
{ "_id" : "Tamil Nadu", "count" : 3784 }
{ "_id" : "Andhra Pradesh", "count" : 3550 }
{ "_id" : "Karnataka", "count" : 3204 }

```

1.  这是前五个结果的预期结果。如果我们比较在*在 Java 客户端中执行 Mongo 的 MapReduce*中得到的结果，来自第三章的*编程语言驱动程序*，使用 Mongo 的 MapReduce 框架和本章中的*编写我们的第一个 Hadoop MapReduce 作业*配方，我们可以看到结果是相同的。

## 工作原理…

Amazon EMR 是一项托管的 Hadoop 服务，负责硬件配置，并让您远离设置自己的集群的麻烦。与我们的 MapReduce 程序相关的概念已经在“编写我们的第一个 Hadoop MapReduce 作业”一文中进行了介绍，没有更多要提到的了。我们所做的一件事是将我们需要的 JAR 文件组装成一个大的 JAR 文件来执行我们的 MapReduce 作业。这种方法对于我们的小型 MapReduce 作业来说是可以的；对于需要大量第三方 JAR 文件的大型作业，我们将不得不采用一种方法，将 JAR 文件添加到 Hadoop 安装的`lib`目录中，并以与我们在本地执行的 MapReduce 作业相同的方式执行。我们与本地设置不同的另一件事是不使用`mongid`实例来获取数据和写入数据，而是使用 mongo 数据库中的 BSON 转储文件作为输入，并将输出写入 BSON 文件。然后将输出转储导入到本地 mongo 数据库，并对结果进行分析。将数据转储上传到 S3 存储桶并在云上使用云基础设施对已上传到 S3 的数据运行分析作业是一个不错的选择。EMR 集群从存储桶访问的数据不需要公共访问权限，因为 EMR 作业使用我们账户的凭据运行；我们可以访问我们自己的存储桶来读取和写入数据/日志。

## 另请参阅

尝试了这个简单的 MapReduce 作业之后，强烈建议您了解亚马逊 EMR 服务及其所有功能。EMR 的开发人员指南可以在[`docs.aws.amazon.com/ElasticMapReduce/latest/DeveloperGuide/`](http://docs.aws.amazon.com/ElasticMapReduce/latest/DeveloperGuide/)找到。

Enron 数据集中提供了 mongo-hadoop 连接器示例中的一个 MapReduce 作业。它可以在[`github.com/mongodb/mongo-hadoop/tree/master/examples/elastic-mapreduce`](https://github.com/mongodb/mongo-hadoop/tree/master/examples/elastic-mapreduce)找到。您也可以选择根据给定的说明在亚马逊 EMR 上实现此示例。


# 第九章：开源和专有工具

在本章中，我们将涵盖一些开源和专有工具。以下是本章中将要介绍的配方：

+   使用 spring-data-mongodb 进行开发

+   使用 JPA 访问 MongoDB

+   通过 REST 访问 MongoDB

+   为 MongoDB 安装基于 GUI 的客户端 MongoVUE

# 介绍

有大量的工具/框架可用于简化使用 MongoDB 的软件的开发/管理过程。我们将看一些这些可用的框架和工具。对于开发人员的生产力（在这种情况下是 Java 开发人员），我们将看一下 spring-data-mongodb，它是流行的 spring data 套件的一部分。

JPA 是一个广泛使用的 ORM 规范，特别是与关系数据库一起使用。（这是 ORM 框架的目标。）然而，有一些实现让我们可以将其与 NoSQL 存储（在这种情况下是 MongoDB）一起使用。我们将看一个提供这种实现的提供者，并用一个简单的用例来测试它。

我们将使用 spring-data-rest 来为客户端公开 MongoDB 的 CRUD 存储库，以便客户端调用底层 spring-data-mongo 存储库支持的各种操作。

在 shell 中查询数据库是可以的，但最好有一个良好的 GUI，使我们能够从 GUI 中执行所有与管理/开发相关的任务，而不是在 shell 中执行命令来执行这些活动。我们将在本章中看一个这样的工具。

# 使用 spring-data-mongodb 进行开发

从开发人员的角度来看，当程序需要与 MongoDB 实例交互时，他们需要使用特定平台的相应客户端 API。这样做的麻烦在于我们需要编写大量的样板代码，而且不一定是面向对象的。例如，我们有一个名为`Person`的类，具有各种属性，如`name`、`age`、`address`等。相应的 JSON 文档与这个`person`类的结构类似。

```sql
{
  name:"…",
  age:..,
  address:{lineOne:"…", …}
}
```

然而，为了存储这个文档，我们需要将`Person`类转换为 DBObject，这是一个具有键值对的映射。真正需要的是让我们将这个`Person`类本身作为一个对象持久化到数据库中，而不必将其转换为 DBObject。

此外，一些操作，如按文档的特定字段搜索、保存实体、删除实体、按 ID 搜索等，都是非常常见的操作，我们往往会反复编写类似的样板代码。在这个配方中，我们将看到 spring-data-mongodb 如何解除我们这些繁琐和繁重的任务，以减少不仅开发工作量，还减少引入这些常见写函数中的错误的可能性。

## 准备工作

`SpringDataMongoTest`项目，存在于本章的捆绑包中，是一个 Maven 项目，必须导入到您选择的任何 IDE 中。所需的 maven 构件将自动下载。需要一个单独的 MongoDB 实例正在运行并监听端口`27017`。有关如何启动独立实例的说明，请参阅第一章中的*安装单节点 MongoDB*配方，*安装和启动服务器*。

对于聚合示例，我们将使用邮政编码数据。有关如何创建测试数据，请参阅第二章中的*创建测试数据*配方，*命令行操作和索引*。

## 如何做…

1.  我们将首先探索 spring-data-mongodb 的存储库功能。从您的 IDE 中打开测试用例的`com.packtpub.mongo.cookbook.MongoCrudRepositoryTest`类并执行它。如果一切顺利，MongoDB 服务器实例是可达的，测试用例将成功执行。

1.  另一个测试用例`com.packtpub.mongo.cookbook.MongoCrudRepositoryTest2`，用于探索 spring-data-mongodb 提供的存储库支持的更多功能。这个测试用例也应该成功执行。

1.  我们将看到如何使用 spring-data-mongodb 的`MongoTemplate`执行 CRUD 操作和其他常见操作。打开`com.packtpub.mongo.cookbook.MongoTemplateTest`类并执行它。

1.  或者，如果不使用 IDE，可以在命令提示符中使用 maven 执行所有测试，当前目录在`SpringDataMongoTest`项目的根目录中：

```sql
$ mvn clean test

```

## 它是如何工作的...

我们首先看一下在`com.packtpub.mongo.cookbook.MongoCrudRepositoryTest`中做了什么，我们在那里看到了 spring-data-mongodb 提供的存储库支持。以防你没有注意到，我们没有为存储库编写一行代码。实现所需代码的魔力是由 spring data 项目完成的。

让我们首先看一下 XML 配置文件的相关部分：

```sql
  <mongo:repositories base-package="com.packtpub.mongo.cookbook" />
  <mongo:mongo id="mongo" host="localhost" port="27017"/>
  <mongo:db-factory id="factory" dbname="test" mongo-ref="mongo"/>
  <mongo:template id="mongoTemplate" db-factory-ref="factory"/>  
```

我们首先看一下最后三行，这些是 spring-data-mongodb 命名空间声明，用于实例化`com.mongodb.Mongo`，客户端的`com.mongodb.DB`实例的工厂，以及`template`实例，用于在 MongoDB 上执行各种操作。稍后我们将更详细地看一下`org.springframework.data.mongodb.core.MongoTemplate`。

第一行是所有 CRUD 存储库的基本包的命名空间声明。在这个包中，我们有一个接口，具有以下内容：

```sql
public interface PersonRepository extends PagingAndSortingRepository<Person, Integer>{

  /**
   *
   * @param lastName
   * @return
   */
  Person findByLastName(String lastName);
}
```

`PagingAndSortingRepository`接口来自 spring data 核心项目的`org.springframework.data.repository`包，并在同一项目中扩展自`CrudRepository`。这些接口为我们提供了一些最常见的方法，例如按 ID/主键搜索、删除实体以及插入和更新实体。存储库需要一个对象，它将其映射到底层数据存储。spring data 项目支持大量的数据存储，不仅限于 SQL（使用 JDBC 和 JPA）或 MongoDB，还包括其他 NoSQL 存储，如 Redis 和 Hadoop，以及 Solr 和 Elasticsearch 等搜索引擎。在 spring-data-mongodb 的情况下，对象被映射到集合中的文档。

`PagingAndSortingRepository<Person, Integer>`的签名表示第一个是 CRUD 存储库构建的实体，第二个是主键/ID 字段的类型。

我们只添加了一个`findByLastName`方法，它接受一个字符串值作为姓氏的参数。这是一个特定于我们的存储库的有趣操作，甚至不是我们实现的，但它仍然会按预期工作。Person 是一个 POJO，我们用`org.springframework.data.annotation.Id`注解标记了`id`字段。这个类没有什么特别之处；它只有一些普通的 getter 和 setter。

有了所有这些细节，让我们通过回答一些你心中的问题来把这些点连接起来。首先，我们将看到我们的数据去了哪个服务器、数据库和集合。如果我们查看配置文件的 XML 定义，`mongo:mongo`，我们可以看到我们通过连接到 localhost 和端口`27017`来实例化`com.mongodb.Mongo`类。`mongo:db-factory`声明用于表示要使用的数据库是`test`。最后一个问题是：哪个集合？我们类的简单名称是`Person`。集合的名称是简单名称的第一个字符小写，因此`Person`对应到`person`，而`BillingAddress`之类的东西将对应到`billingAddress`集合。这些是默认值。但是，如果您需要覆盖此值，可以使用`org.springframework.data.mongodb.core.mapping.Document`注解注释您的类，并使用其 collection 属性来给出您选择的任何名称，正如我们将在后面的示例中看到的。

查看集合中的文档，只需执行`com.packtpub.mongo.cookbook.MongoCrudRepositoryTest`类中的一个测试用例`saveAndQueryPerson`方法。现在，连接到 mongo shell 中的 MongoDB 实例并执行以下查询：

```sql
> use test
> db.person.findOne({_id:1})
{
 "_id" : 1,
 "_class" : "com.packtpub.mongo.cookbook.domain.Person",
 "firstName" : "Steve",
 "lastName" : "Johnson",
 "age" : 20,
 "gender" : "Male"
 …
}

```

正如我们在前面的结果中所看到的，文档的内容与我们使用 CRUD 存储库持久化的对象相似。文档中字段的名称与 Java 对象中相应属性的名称相同，有两个例外。使用`@Id`注释的字段现在是`_id`，与 Java 类中字段的名称无关，并且在文档中添加了一个额外的`_class`属性，其值是 Java 类本身的完全限定名称。这对应用程序没有任何用处，但是 spring-data-mongodb 用作元数据。

现在更有意义了，并且让我们了解 spring-data-mongodb 必须为所有基本的 CRUD 方法做些什么。我们执行的所有操作都将使用 spring-data-mongodb 项目中的`MongoTemplate`（`MongoOperations`，这是`MongoTemplate`实现的接口）类。它将使用主键，在使用`Person`实体类派生的集合上的`_id`字段上调用 find。`save`方法简单地调用`MongoOperations`上的`save`方法，而`MongoOperations`又调用`com.mongodb.DBCollection`类上的`save`方法。

我们仍然没有回答`findByLastName`方法是如何工作的。spring 如何知道要调用什么查询以返回数据？这些是以`find`、`findBy`、`get`或`getBy`开头的特殊类型的方法。在命名方法时需要遵循一些规则，存储库接口上的代理对象能够正确地将此方法转换为集合上的适当查询。例如，`Person`类的存储库中的`findByLastName`方法将在 person 文档的`lastName`字段上执行查询。因此，`findByLastName(String lastName)`方法将在数据库上触发`db.person.find({'lastName': lastName })`查询。根据方法定义的返回类型，它将返回来自数据库的结果中的`List`或第一个结果。我们在我们的查询中使用了`findBy`，但是任何以`find`开头，中间有任何文本，并以`By`结尾的都可以工作。例如，`findPersonBy`也与`findBy`相同。

要了解更多关于这些`findBy`方法，我们有另一个测试`MongoCrudRepositoryTest2`类。在您的 IDE 中打开这个类，可以与本文一起阅读。我们已经执行了这个测试用例；现在，让我们看看这些`findBy`方法的使用和它们的行为。这个接口中有七个`findBy`方法，其中一个方法是同一接口中另一个方法的变体。为了清楚地了解查询，我们将首先查看测试数据库中`personTwo`集合中的一个文档。在连接到运行在 localhost 上的 MongoDB 服务器的 mongo shell 中执行以下操作：

```sql
> use test
> db.personTwo.findOne({firstName:'Amit'})
{
 "_id" : 2,
 "_class" : "com.packtpub.mongo.cookbook.domain.Person2",
 "firstName" : "Amit",
 "lastName" : "Sharma",
 "age" : 25,
 "gender" : "Male",
 "residentialAddress" : {
 "addressLineOne" : "20, Central street",
 "city" : "Mumbai",
 "state" : "Maharashtra",
 "country" : "India",
 "zip" : "400101"
 }
}

```

请注意，存储库使用`Person2`类；但是使用的集合的名称是`personTwo`。这是可能的，因为我们在`Person2`类的顶部使用了`@Document(collection="personTwo")`注解。

回到`com.packtpub.mongo.cookbook.PersonRepositoryTwo`存储库类中的七种方法，让我们逐一看看它们：

| 方法 | 描述 |
| --- | --- |
| `findByAgeGreaterThanEqual` | 这个方法将在`personTwo`集合上触发一个查询，`{'age':{'$gte':<age>}}`。秘密在于方法的名称。如果我们把它分开，`findBy`后面告诉我们我们想要什么。`age`属性（首字母小写）是将在具有`$gte`运算符的文档上查询的字段，因为方法的名称中有`GreaterThanEqual`。用于比较的值将是传递的参数的值。结果是`Person2`实体的集合，因为我们会有多个匹配项。 |
| `findByAgeBetween` | 这个方法将再次在年龄上进行查询，但将使用`$gt`和`$lt`的组合来找到匹配的结果。在这种情况下，查询将是`{'age' : {'$gt' : from, '$lt' : to}}`。重要的是要注意 from 和 to 两个值在范围内都是排他的。测试用例中有两种方法，`findByAgeBetween`和`findByAgeBetween2`。这些方法展示了对不同输入值的 between 查询的行为。 |
| `findByAgeGreaterThan` | 这个方法是一个特殊的方法，它还会对结果进行排序，因为该方法有两个参数：第一个参数是年龄将要进行比较的值，第二个参数是`org.springframework.data.domain.Sort`类型的字段。有关更多详细信息，请参考 spring-data-mongodb 的 Javadocs。 |
| `findPeopleByLastNameLike` | 这个方法用于通过匹配模式查找姓氏匹配的结果。用于匹配目的的是正则表达式。例如，在这种情况下，触发的查询将是`{'lastName' : <lastName as regex>}`。这个方法的名称以`findPeopleBy`开头，而不是`findBy`，它的工作方式与`findBy`相同。因此，当我们在所有描述中说`findBy`时，实际上是指`find…By`。提供的值作为参数将用于匹配姓氏。 |
| `findByResidentialAddressCountry` | 这是一个有趣的方法。在这里，我们通过居住地址的国家进行搜索。实际上，这是`Person`类中`residentialAddress`字段中的`Address`类中的一个字段。查看`personTwo`集合中的文档，以了解查询应该是什么样子。当 spring data 找到名称为`ResidentialAddressCountry`时，它将尝试使用此字符串找到各种组合。例如，它可以查看`Person`类中的`residentialAddressCountry`字段，或者`residential.addressCountry`，`residentialAddress.country`或`residential.address.country`。如果没有冲突的值，如我们的情况下的`residentialAddress`。字段'country'是'Person2'文档的一部分，因此将在查询中使用。但是，如果存在冲突，则可以使用下划线来清楚地指定我们要查看的内容。在这种情况下，方法可以重命名为`findByResidentialAddress_country`，以清楚地指定我们期望的结果。测试用例`findByCountry2`方法演示了这一点。 |
| `findByFirstNameAndCountry` | 这是一个有趣的方法。我们并不总是能够使用方法名来实现我们实际想要的功能。为了让 spring 自动实现查询，方法的名称可能会有点难以使用。例如，`findByCountryOfResidence`听起来比`findByResidentialAddressCountry`更好。然而，我们只能使用后者，因为这是 spring-data-mongodb 构造查询的方式。使用`findByCountryOfResidence`并没有提供如何构造查询给 spring data 的细节。但是，有一个解决方法。您可以选择使用`@Query`注解，并在方法调用时指定要执行的查询。以下是我们使用的注解：`@Query("{'firstName':?0, 'residentialAddress.country': ?1}")`我们将值写成一个将被执行并将函数的参数绑定到查询的查询，作为从零开始的编号参数。因此，方法的第一个参数将绑定到`?0`，第二个参数将绑定到`?1`，依此类推。 |

我们看到了`findBy`或`getBy`方法如何自动转换为 MongoDB 的查询。同样，我们有以下方法的前缀。`countBy`方法返回给定条件的长数字，该条件是从方法名称的其余部分派生的，类似于`findBy`。我们可以使用`deleteBy`或`removeBy`来根据派生条件删除文档。关于`com.packtpub.mongo.cookbook.domain.Person2`类的一点需要注意的是，它没有无参数构造函数或设置器来设置值。相反，spring 将使用反射来实例化此对象。

spring-data-mongodb 支持许多`findBy`方法，这里并未涵盖所有。有关更多详细信息，请参阅 spring-data-mongodb 参考手册。参考手册中提供了许多基于 XML 或 Java 的配置选项。这些 URL 将在本食谱的*参见*部分中提供。

我们还没有完成；我们还有另一个测试用例`com.packtpub.mongo.cookbook.MongoTemplateTest`，它使用`org.springframework.data.mongodb.core.MongoTemplate`执行各种操作。您可以打开测试用例类，看看执行了哪些操作以及调用了 MongoTemplate 的哪些方法。

让我们来看看 MongoTemplate 类的一些重要和经常使用的方法：

| 方法 | 描述 |
| --- | --- |
| `save` | 该方法用于在 MongoDB 中保存（如果是新的则插入；否则更新）实体。该方法接受一个参数，即实体，并根据其名称或`@Document`注解找到目标集合。save 方法有一个重载版本，还接受第二个参数，即需要将数据实体持久化到的集合的名称。 |
| `remove` | 这个方法用于从集合中删除文档。在这个类中有一些重载的方法。所有这些方法都接受要删除的实体或`org.springframework.data.mongodb.core.query.Query`实例，用于确定要删除的文档。第二个参数是要从中删除文档的集合的名称。当提供实体时，可以推导出集合的名称。如果提供了`Query`实例，我们必须给出集合的名称或实体类的名称，然后将用于推导集合的名称。 |
| `updateMulti` | 这是用于一次更新多个文档的函数。第一个参数是用于匹配文档的查询。第二个参数是`org.springframework.data.mongodb.core.query.Updat` `e`实例。这是将在使用第一个`Query`对象选择的文档上执行的更新。下一个参数是实体类或集合名称，用于执行更新。有关该方法及其各种重载版本的更多详细信息，请参阅 Javadocs。 |
| `updateFirst` | 这是`updateMulti`方法的相反操作。此操作将仅更新第一个匹配的文档。我们在单元测试用例中没有涵盖这个方法。 |
| `insert` | 我们提到 save 方法可以执行插入和更新。模板中的 insert 方法调用底层 mongo 客户端的 insert 方法。如果要插入一个实体或文档，调用 insert 或 save 方法没有区别。然而，如我们在测试用例中看到的 insertMultiple 方法，我们创建了一个包含三个`Person`实例的列表，并将它们传递给 insert 方法。三个`Person`实例的所有三个文档将作为一个调用的一部分发送到服务器。无论何时插入失败的行为是由 Write Concern 的 continue on error 参数确定的。它将确定批量插入在第一次失败时是否失败，或者即使在报告最后一个错误时也会继续。URL [`docs.mongodb.org/manual/core/bulk-inserts/`](http://docs.mongodb.org/manual/core/bulk-inserts/) 提供了有关批量插入和各种写关注参数的更多详细信息，可以改变行为。 |
| `findAndRemove`/`findAllAndRemove` | 这两个操作都用于查找然后删除文档。第一个找到一个文档，然后返回被删除的文档。这个操作是原子的。然而，后者在返回所有被删除文档的实体列表之前找到并删除所有文档。 |
| `findAndModify` | 这个方法在功能上类似于我们在 mongo 客户端库中拥有的`findAndModify`。它将原子地查找并修改文档。如果查询匹配多个文档，只有第一个匹配项将被更新。该方法的前两个参数是要执行的查询和更新。接下来的几个参数是要在其上执行操作的实体类或集合名称。此外，还有一个特殊的`org.springframework.data.mongodb.core.FindAndModifyOptions`类，它只对`findAndModify`操作有意义。这个实例告诉我们在操作执行后是否要查找新实例或旧实例，以及是否要执行 upsert。只有在不存在与匹配查询的文档时才相关。还有一个额外的布尔标志，告诉客户端这是否是一个`findAndRemove`操作。实际上，我们之前看到的`findAndRemove`操作只是一个方便的函数，它使用了这个删除标志来委托`findAndModify`。 |

在前面的表中，当谈到更新时，我们提到了`Query`和`Update`类。这些是 spring-data-mongodb 中的特殊便捷类，它们让我们使用易于理解且具有改进可读性的语法构建 MongoDB 查询。例如，在 mongo 中检查`lastName`是否为`Johnson`的查询是`{'lastName':'Johnson'}`。在 spring-data-mongodb 中，可以按照以下方式构建相同的查询：

```sql
new Query(Criteria.where("lastName").is("Johnson"))

```

与以 JSON 形式给出查询相比，这种语法看起来更整洁。让我们举另一个例子，我们想要在我们的数据库中找到所有 30 岁以下的女性。现在查询将构建如下：

```sql
new Query(Criteria.where("age").lt(30).and("gender").is("Female"))

```

同样，对于更新，我们希望根据一些条件为一些客户设置一个布尔标志`youngCustomer`为`true`。要在文档中设置此标志，MongoDB 格式如下：

```sql
{'$set' : {'youngCustomer' : true}}

```

在 spring-data-mongodb 中，可以通过以下方式实现：

```sql
new Update().set("youngCustomer", true)

```

请参考 Javadocs，了解在 spring-data-mongodb 中可用于构建查询和更新的所有可能方法。

这些方法绝不是`MongoTemplate`类中唯一可用的方法。还有许多其他方法用于地理空间索引、获取集合中文档数量的便捷方法、聚合和 MapReduce 支持等。有关更多详细信息和方法，请参考`MongoTemplate`的 Javadocs。

说到聚合，我们还有一个名为`aggregationTest`的测试用例方法，用于对集合执行聚合操作。我们在 MongoDB 中有一个`postalCodes`集合，其中包含各个城市的邮政编码详细信息。集合中的一个示例文档如下：

```sql
{
        "_id" : ObjectId("539743b26412fd18f3510f1b"),
        "postOfficeName" : "A S D Mello Road Fuller Marg",
        "pincode" : 400001,
        "districtsName" : "Mumbai",
        "city" : "Mumbai",
        "state" : "Maharashtra"
}
```

我们的聚合操作意图是找到集合中文档数量前五名的州。在 mongo 中，聚合管道如下所示：

```sql
[
{'$project':{'state':1, '_id':0}},
{'$group':{'_id':'$state', 'count':{'$sum':1}}}
{'$sort':{'count':-1}},
{'$limit':5}
]
```

在 spring-data-mongodb 中，我们使用`MongoTemplate`调用了聚合操作：

```sql
Aggregation aggregation = newAggregation(

    project("state", "_id"),
    group("state").count().as("count"),
    sort(Direction.DESC, "count"),
    limit(5)  
);

AggregationResults<DBObject> results = mongoTemplate.aggregate(
    aggregation,
    "postalCodes",
    DBObject.class);
```

关键在于创建`org.springframework.data.mongodb.core.aggregation.Aggregation`类的实例。`newAggregation`方法是从同一类中静态导入的，并接受`varargs`，用于不同的`org.springframework.data.mongodb.core.aggregation.AggregationOperation`实例，对应于链中的一个操作。`Aggregation`类有各种静态方法来创建`AggregationOperation`的实例。我们使用了其中一些，比如`project`、`group`、`sort`和`limit`。有关更多详细信息和可用方法，请参考 Javadocs。`MongoTemplate`中的`aggregate`方法接受三个参数。第一个是`Aggregation`类的实例，第二个是集合的名称，第三个是聚合结果的返回类型。有关更多详细信息，请参考聚合操作测试用例。

## 另请参阅

+   有关更多详细信息和 API 文档，请参考[`docs.spring.io/spring-data/mongodb/docs/current/api/`](http://docs.spring.io/spring-data/mongodb/docs/current/api/)的 Javadocs。

+   spring-data-mongodb 项目的参考手册可以在[`docs.spring.io/spring-data/data-mongodb/docs/current/reference/`](http://docs.spring.io/spring-data/data-mongodb/docs/current/reference/)找到

# 使用 JPA 访问 MongoDB

在这个示例中，我们将使用一个 JPA 提供程序，它允许我们使用 JPA 实体来实现与 MongoDB 的对象到文档映射。

## 准备工作

启动独立的服务器实例，监听端口`27017`。这是一个使用 JPA 的 Java 项目。我们期望熟悉 JPA 及其注解，尽管我们将要查看的内容相当基础。如果您不熟悉 maven，可以参考第一章中的*使用 Java 客户端连接单节点*部分来设置 maven。从提供的捆绑包中下载`DataNucleusMongoJPA`项目。虽然我们将从命令提示符中执行测试用例，但您也可以将项目导入到您喜欢的 IDE 中查看源代码。

## 如何做…

1.  转到`DataNucleusMongoJPA`项目的根目录，并在 shell 中执行以下操作：

```sql
$ mvn clean test

```

1.  这应该会下载构建和运行项目所需的必要工件，并成功执行测试用例。

1.  一旦测试用例执行完毕，打开 mongo shell 并连接到本地实例。

1.  在 shell 中执行以下查询：

```sql
> use test
> db.personJPA.find().pretty()

```

## 工作原理…

首先，让我们看一下在`personJPA`集合中创建的示例文档：

```sql
{
        "_id" : NumberLong(2),
        "residentialAddress" : {
                "residentialAddress_zipCode" : "400101",
                "residentialAddress_state" : "Maharashtra",
                "residentialAddress_country" : "India",
                "residentialAddress_city" : "Mumbai",
                "residentialAddress_addressLineOne" : "20, Central street"
        },
        "lastName" : "Sharma",
        "gender" : "Male",
        "firstName" : "Amit",
        "age" : 25
}
```

我们执行的步骤非常简单；让我们逐个查看使用的类。我们从`com.packtpub.mongo.cookbook.domain.Person`类开始。在类的顶部（包和导入之后），我们有以下内容：

```sql
@Entity
@Table(name="personJPA")
public class Person {
```

这表示`Person`类是一个实体，它将持久化到`personJPA`集合中。请注意，JPA 主要设计为**对象关系映射**（**ORM**）工具，因此使用的术语更多地是针对关系数据库。在 RDBMS 中，表与 MongoDB 中的集合是同义词。类的其余部分包含了人的属性，以及用`@Column`和`@Id`注释的列作为主键。这些都是简单的 JPA 注释。有趣的是看一下`com.packtpub.mongo.cookbook.domain.ResidentialAddress`类，它存储为`Person`类中的`residentialAddress`变量。如果我们看一下之前给出的人员文档，`@Column`注释中给出的所有值都是人员键的名称；还要注意`Enum`如何转换为字符串值。`residentialAddress`字段是`Person`类中的变量名，存储地址实例。如果我们看`ResidentialAddress`类，我们可以看到类名上方的`@Embeddable`注解。这再次是一个 JPA 注解，表示这个实例本身不是一个实体，而是嵌入在另一个`Entity`或`Embeddable`类中。请注意文档中字段的名称；在这种情况下，它们的格式如下：`<person 类中的变量名>_<ResidentialAddress 类中的变量名的值>`。

这里有一个问题。字段的名称太长，占用了不必要的空间。解决方案是在`@Column`注解中使用较短的值。例如，`@Column(name="ln")`注解代替`@Column(name="lastName")`，将在文档中创建一个名为`ln`的键。不幸的是，这在嵌入的`ResidentialAddress`类中不起作用；在这种情况下，您将不得不处理较短的变量名。现在我们已经看到了实体类，让我们看看`persistence.xml`：

```sql
<persistence-unit name="DataNucleusMongo">
  <class>com.packtpub.mongo.cookbook.domain.Person</class>
  <properties>
    <property name="javax.persistence.jdbc.url" value="mongodb:localhost:27017/test"/>
  </properties>
</persistence-unit>
```

这里只有一个名为`DataNucleusMongo`的持久性单元定义。有一个类节点，即我们将使用的实体。请注意，嵌入式地址类在这里没有提到，因为它不是一个独立的实体。在属性中，我们提到了要连接的数据存储的 URL。在这种情况下，我们连接到本地主机上的实例，端口`27017`，数据库为 test。

现在，让我们看一下查询和插入数据的类。这是我们的`com.packtpub.mongo.cookbook.DataNucleusJPATest`测试类。我们创建`javax.persistence.EntityManagerFactory`作为`Persistence.createEntityManagerFactory("DataNucleusMongo")`。这是一个线程安全的类，其实例在线程之间共享；字符串参数也与我们在`persistence.xml`中使用的持久化单元的名称相同。对`javax.persistence.EntityManager`的所有其他调用，以持久化或查询集合，都要求我们使用`EntityManagerFactory`创建一个实例——使用它，然后在操作完成后关闭它。所有执行的操作都符合 JPA 规范。测试用例类持久化实体并查询它们。

最后，让我们看一下`pom.xml`，特别是我们使用的增强器插件，如下所示：

```sql
<plugin>
  <groupId>org.datanucleus</groupId>
  <artifactId>datanucleus-maven-plugin</artifactId>
  <version>4.0.0-release</version>
  <configuration>
    <log4jConfiguration>${basedir}/src/main/resources/log4j.properties</log4jConfiguration>
    <verbose>true</verbose>
  </configuration>
  <executions>
    <execution>
      <phase>process-classes</phase>
      <goals>
        <goal>enhance</goal>
      </goals>
    </execution>
  </executions>
</plugin>
```

我们编写的实体需要增强才能作为 JPA 实体使用数据核。前面的插件将附加到 process-class 阶段，然后调用插件的增强。

## 另请参阅

+   有多种方法可以使用数据核增强器增强 JPA 实体。请参考[`www.datanucleus.org/products/datanucleus/jdo/enhancer.html`](http://www.datanucleus.org/products/datanucleus/jdo/enhancer.html)以获取可能的选项。甚至有一个 Eclipse 插件，允许实体类被增强/仪器化以供数据核使用。

+   JPA 2.1 规范可以在[`www.jcp.org/aboutJava/communityprocess/final/jsr338/index.html`](https://www.jcp.org/aboutJava/communityprocess/final/jsr338/index.html)找到。

# 通过 REST 访问 MongoDB

在这个示例中，我们将看到如何使用 REST API 访问 MongoDB 并执行 CRUD 操作。我们将使用 spring-data-rest 进行 REST 访问，使用 spring-data-mongodb 执行 CRUD 操作。在继续进行这个示例之前，重要的是要知道如何使用 spring-data-mongodb 实现 CRUD 存储库。请参考本章中的*使用 spring-data-mongodb 进行开发*示例，了解如何使用这个框架。

一个人必须要问的问题是，为什么需要 REST API？有些情况下，有一个数据库被许多应用程序共享，并且可能是用不同的语言编写的。编写 JPA DAO 或使用 spring-data-mongodb 对于 Java 客户端来说已经足够好了，但对于其他语言的客户端来说就不够了。在应用程序本地拥有 API 甚至不能给我们一个集中访问数据库的方式。这就是 REST API 发挥作用的地方。我们可以在 Java 中开发服务器端数据访问层和 CRUD 存储库——具体来说是 spring-data-mongodb，然后通过 REST 接口将其暴露给任何语言编写的客户端来调用它们。我们不仅以平台无关的方式调用我们的 API，还提供了一个进入我们数据库的单一入口。

## 准备就绪

除了 spring-data-mongodb 示例的先决条件之外，这个示例还有一些其他要求。首先是从 Packt 网站下载`SpringDataRestTest`项目，并将其作为 maven 项目导入到您的 IDE 中。或者，如果您不希望导入到 IDE 中，您可以从命令提示符中运行服务请求，我们将在下一节中看到。没有特定的客户端应用程序用于通过 REST 执行 CRUD 操作。我将使用 Chrome 浏览器和 Advanced REST Client 浏览器的特殊插件来演示这些概念，以向服务器发送 HTTP POST 请求。这些工具可以在 Chrome 网络商店的**开发者工具**部分找到。

## 操作步骤...

1.  如果您已将项目作为 maven 项目导入 IDE，请执行`com.packtpub.mongo.cookbook.rest.RestServer`类，这是引导类，启动本地服务器，接受客户端连接。

1.  如果要从命令提示符中作为 maven 项目执行该项目，转到项目的根目录并运行以下命令：

```sql
mvn spring-boot:run

```

1.  如果一切顺利，服务器已经启动，命令提示符上将看到以下行：

```sql
[INFO] Attaching agents: []

```

1.  无论以何种方式启动服务器，都在浏览器的地址栏中输入`http://localhost:8080/people`，我们应该看到以下 JSON 响应。因为底层的人员集合是空的，所以会看到这个响应。

```sql
{
  "_links" : {
    "self" : {
      "href" : "http://localhost:8080/people{?page,size,sort}",
      "templated" : true
    },
    "search" : {
      "href" : "http://localhost:8080/people/search"
    }
  },
  "page" : {
    "size" : 20,
    "totalElements" : 0,
    "totalPages" : 0,
    "number" : 0
  }
}
```

1.  我们现在将使用 HTTP POST 请求将一个新文档插入到人员集合中，请求将被发送到`http://localhost:8080/people`。我们将使用 Chrome 浏览器的 Advanced REST Client 扩展来向服务器发送 POST 请求。发送的文档是：

```sql
{"lastName":"Cruise", "firstName":"Tom", "age":52, "id":1}.

```

请求的内容类型是`application/json`。

以下图片显示了发送到服务器的 POST 请求和服务器的响应：

![操作步骤…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_09_01.jpg)

1.  现在，我们将使用浏览器中的`_id`字段来查询这个文档，这个字段在这种情况下是`1`。在浏览器的地址栏中输入`http://localhost:8080/people/1`。您应该看到我们在步骤 3 中插入的文档。

1.  现在我们在集合中有一个文档了（您可以尝试为具有不同名称和更重要的是唯一 ID 的人插入更多文档），我们将使用姓氏查询文档。首先，在浏览器的地址栏中输入以下 URL 以查看所有可用的搜索选项：`http://localhost:8080/people/search`。我们应该看到一个`search`方法，`findByLastName`，它接受一个命令行参数`lastName`。

1.  要按姓氏搜索，我们的情况下是 Cruise，可以在浏览器的地址栏中输入以下 URL：`http://localhost:8080/people/search/findByLastName?lastName=Cruise`。

1.  现在我们将更新 ID 为`1`的人的姓氏和年龄，目前是汤姆·克鲁斯。让我们把姓氏更新为汉克斯，年龄更新为`58`。为此，我们将使用 HTTP PATCH 请求，并且请求将被发送到`http://localhost:8080/people/1`，这个地址唯一标识了要更新的文档。HTTP PATCH 请求的主体是`{"lastName":"Hanks", "age":58}`。参考以下图片，查看我们发送的更新请求：![操作步骤…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_09_02.jpg)

1.  为了验证我们的更新是否成功（我们知道它成功了，因为在 PATCH 请求之后我们得到了一个响应状态 204），再次在浏览器的地址栏中输入`http://localhost:8080/people/1`。

1.  最后，我们删除文档。这很简单，我们只需向`http://localhost:8080/people/1`发送一个 DELETE 请求。一旦 DELETE 请求成功，从浏览器向`http://localhost:8080/people/1`发送一个 HTTP GET 请求，我们不应该得到任何文档作为返回。

## 工作原理…

我们不会在这个教程中再次重复 spring-data-mongodb 的概念，而是将看一些我们专门为 REST 接口添加的注释。第一个是在类名的顶部，如下所示：

```sql
@RepositoryRestResource(path="people")
public interface PersonRepository extends PagingAndSortingRepository<Person, Integer> {
```

这用于指示服务器可以使用 people 资源访问此 CRUD 存储库。这就是为什么我们总是在`http://localhost:8080/people/`上进行 HTTP GET 和 POST 请求的原因。

第二个注释在`findByLastName`方法中。我们有以下方法签名：

```sql
Person findByLastName(@Param("lastName") String lastName);
```

这里，方法的`lastName`参数使用了`@Param`注释，用于注释将在调用存储库上的此方法时传递的`lastName`参数的参数名称。如果我们看一下上一节的第 6 步，我们可以看到使用 HTTP GET 请求调用了`findByLastName`，并且 URL 的`lastName`参数的值被用作在调用存储库方法时传递的字符串值。

我们的示例非常简单，只使用一个参数进行搜索操作。我们可以为存储库方法使用多个参数，并在 HTTP 请求中使用相同数量的参数，这些参数将映射到存储库上的方法，以便调用 CRUD 存储库。对于某些类型，例如要发送的日期，请使用`@DateTimeFormat`注释，该注释将用于指定日期和时间格式。有关此注释及其用法的更多信息，请参阅 spring Javadocs [`docs.spring.io/spring/docs/current/javadoc-api/`](http://docs.spring.io/spring/docs/current/javadoc-api/)

这就是我们向 REST 接口发出的 GET 请求，以查询和搜索数据。我们最初通过向服务器发送 HTTP POST 请求来创建文档数据。要创建新文档，我们将始终发送 POST 请求，将要创建的文档作为请求的主体发送到标识 REST 端点的 URL，即`http://localhost:8080/people/`。发送到此集合的所有文档都将使用`PersonRepository`来持久化`Person`在相应的集合中。

我们的最后两个步骤是更新人员和删除人员。执行这些操作的 HTTP 请求类型分别为 PATCH 和 DELETE。在第 7 步中，我们更新了人员 Tom Cruise 的文档，并更新了他的姓和年龄。为了实现这一点，我们的 PATCH 请求被发送到标识特定人员实例的 URL，即`http://localhost:8080/people/1`。请注意，在创建新人员的情况下，我们的 POST 请求总是发送到`http://localhost:8080/people`，而不是发送到 PATCH 和 DELETE 请求，其中我们将 HTTP 请求发送到表示要更新或删除的特定人员的 URL。在更新的情况下，PATCH 请求的主体是 JSON，其提供的字段将替换目标文档中的相应字段以进行更新。所有其他字段将保持不变。在我们的情况下，目标文档的`lastName`和年龄被更新，而`firstName`保持不变。在删除的情况下，消息主体不为空，并且 DELETE 请求本身指示应删除发送请求的目标。

您还可以发送 PUT 请求，而不是 PATCH 请求到标识特定人员的 URL；在这种情况下，集合中的整个文档将被更新或替换为作为 PUT 请求的一部分提供的文档。

## 另请参阅

spring-data-rest 的主页位于[`projects.spring.io/spring-data-rest/`](http://projects.spring.io/spring-data-rest/)，您可以在那里找到其 Git 存储库、参考手册和 Javadocs URL 的链接。

# 安装基于 GUI 的 MongoDB 客户端 MongoVUE

在这个示例中，我们将看到一个基于 GUI 的 MongoDB 客户端。在整本书中，我们一直使用 mongo shell 来执行我们需要的各种操作。它的优点如下：

+   它与 MongoDB 安装一起打包

+   由于轻量级，您不必担心它占用系统资源

+   在没有基于 GUI 的界面的服务器上，shell 是连接、查询和管理服务器实例的唯一选项

话虽如此，如果您不在服务器上并且想要连接到数据库实例进行查询、查看查询计划、管理等操作，最好有一个具有这些功能的 GUI，让您可以轻松完成任务。作为开发人员，我们总是使用基于 GUI 的厚客户端查询我们的关系数据库，那么为什么不为 MongoDB 呢？

在这个示例中，我们将看到如何安装 MongoDB 客户端 MongoVUE 的一些功能。该客户端仅适用于 Windows 机器。该产品既有付费版本（根据用户数量的不同级别进行许可），也有一些限制的免费版本。在这个示例中，我们将看看免费版本。

## 准备工作

对于这个示例，以下步骤是必要的：

1.  启动 MongoDB 服务器的单个实例。接受连接的端口将是默认端口`27017`。

1.  在 mongod 服务器启动后，从命令提示符导入以下两个集合：

```sql
$ mongoimport --type json personTwo.json -c personTwo -d test –drop
$ mongoimport --type csv -c postalCodes -d test pincodes.csv --headerline –drop

```

## 如何操作...

1.  从[`www.mongovue.com/downloads/`](http://www.mongovue.com/downloads/)下载 MongoVUE 的安装程序 ZIP。下载后，只需点击几下，软件就会安装好。

1.  打开安装的应用程序；由于这是免费版本，在前 14 天内我们将拥有所有功能，之后，一些功能将不可用。详情请参见[`www.mongovue.com/purchase/`](http://www.mongovue.com/purchase/)。

1.  我们要做的第一件事是添加数据库连接：

+   一旦打开以下窗口，点击（**+**）按钮添加新连接：![如何操作...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_09_03.jpg)

+   打开后，我们将得到另一个窗口，在其中填写服务器连接详细信息。在新窗口中填写以下详细信息，然后单击**测试**。如果连接正常，这应该成功；最后，单击**保存**。![如何操作...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_09_04.jpg)

+   添加后，连接到实例。

1.  在左侧导航面板中，我们将看到添加的实例和其中的数据库，如下图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_09_05.jpg)

正如我们在上图中所看到的，将鼠标悬停在集合名称上会显示集合中的文档大小和计数。

1.  让我们看看如何查询一个集合并获取所有文档。我们将使用`test`中的`postalCodes`集合。右键单击集合名称，然后单击**查看**。我们将看到集合的内容显示为树形视图，我们可以展开并查看内容，表格视图，以表格网格显示内容，以及文本视图，以普通 JSON 文本显示内容。

1.  让我们看看当我们查询具有嵌套文档的集合时会发生什么；`personTwo`是一个具有以下示例文档的集合：

```sql
{
  "_id" : 1,
  "_class" : "com.packtpub.mongo.cookbook.domain.Person2",
  "firstName" : "Steve",
  "lastName" : "Johnson",
  "age" : 30,
  "gender" : "Male",
  "residentialAddress" : {
    "addressLineOne" : "20, Central street",
    "city" : "Sydney",
    "state" : "NSW",
    "country" : "Australia"
  }
}
```

当我们查询以查看集合中的所有文档时，我们会看到以下图像：

![如何操作...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_09_06.jpg)

`residentialAddress`列显示值为嵌套文档，并显示其中的字段数。将鼠标悬停在上面会显示嵌套文档；或者，您可以单击该列以再次以网格形式显示此文档中的内容。显示嵌套文档后，您可以单击网格顶部返回一级。

1.  让我们看看如何编写查询以检索所选文档：

+   右键单击**postalCodes**集合，然后单击**查找**。我们将在**{查找}**文本框和**{排序}**字段中输入以下查询，然后单击右侧的**查找**按钮：![如何操作...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_09_07.jpg)

+   我们可以从选项卡中选择所需的视图类型，包括**树形视图**、**表格视图**或**文本视图**。查询计划也会显示。每次运行任何操作时，底部的 Learn shell 会显示实际执行的 Mongo 查询。在这种情况下，我们看到以下内容：

```sql
[ 11:17:07 PM ]
db.postalCodes.find({ "city" : /Mumbai/i }).limit(50);
db.postalCodes.find({ "city" : /Mumbai/i }).limit(50).explain();

```

+   查询计划也会显示每次查询，截至当前版本 1.6.9.0，没有办法禁用查询计划的显示。

1.  在**树形视图**中，右键单击文档会给出更多选项，例如展开它，复制 JSON 内容，向该文档添加键，删除文档等。尝试使用右键从集合中删除文档，并尝试向文档添加任何其他键。您可以选择通过重新导入`postalCodes`集合中的数据来恢复文档。

1.  要在集合中插入文档，请执行以下操作。我们将在`personTwo`集合中插入一个文档：

+   右键单击**personTwo**集合名称，然后单击**插入/导入文档…**，如下图所示：![如何做…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_09_08.jpg)

+   将出现另一个弹出窗口，在那里您可以选择输入单个 JSON 文档或包含要导入的 JSON 文档的有效文本文件。我们通过导入单个文档导入了以下文档：

```sql
{
  "_id" : 4, 
  "firstName" : "Jack",
  "lastName" : "Jones",
 "age" : 35,
 "gender" : "Male" 
}
```

+   成功导入文档后，查询集合；我们将查看新导入的文档以及旧文档。

1.  让我们看看如何更新文档：

+   您可以右键单击左侧的集合名称，然后单击**更新**，或者在顶部选择**更新**选项。在任何一种情况下，我们将看到以下窗口。在这里，我们将更新在上一步中插入的人的年龄：![如何做…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_09_09.jpg)

+   在此 GUI 中需要注意的一些事项是左侧的查询文本框，用于查找要更新的文档，以及右侧的更新 JSON，它将应用于所选的文档。

+   在更新之前，您可以选择点击**计数**按钮，以查看可以更新的文档数量（在本例中为一个）。点击**查找**将以树形式显示文档。在右侧，在更新 JSON 文本下方，我们可以通过点击**更新 1**或**全部更新**来选择更新一个文档和多个文档。

+   如果找不到给定**查找**条件的文档，可以选择**Upsert**操作。

+   前一屏幕右下角的单选按钮显示`getLastError`操作的输出或更新后的结果，如果是后者，则将执行查询以查找已更新的文档。

+   但是，查找查询并不是绝对可靠的，可能会返回与真正更新的结果不同的结果，就像在**查找**文本框中一样。更新和查找操作不是原子的。

1.  到目前为止，我们已经在小集合上进行了查询。随着集合大小的增加，执行完整集合扫描的查询是不可接受的，我们需要创建索引如下：

+   要按`lastName`升序和年龄降序创建索引，我们将调用`db.personTwo.ensureIndex({'lastName':1, 'age':-1})`。

+   使用 MongoVUE，有一种方法可以通过右键单击屏幕左侧的集合名称并选择**添加索引…**来可视化创建相同的索引。

+   在新的弹出窗口中，输入索引的名称，并选择**可视**选项卡，如图所示。分别选择**lastName**和**age**字段，以升序和降序的方式：![如何做…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_09_10.jpg)

+   填写这些细节后，点击**创建**。这应该通过触发`ensureIndex`命令为我们创建索引。

+   您可以选择将索引设置为**唯一**和**删除重复项**（当选择唯一时将启用），甚至可以在后台创建大型、长时间运行的索引创建。

+   请注意**可视**选项卡旁边的**Json**选项卡。这是您可以输入`ensureIndex`命令的地方，就像在 shell 中一样，以创建索引。

1.  我们将看到如何删除索引：

+   简单地展开左侧的树（如第 9 步的屏幕截图所示）

+   展开集合后，我们将看到在其上创建的所有索引

+   除了`_id`字段上的默认索引外，所有其他索引都可以被删除。

+   简单右键单击名称，选择**删除索引**以删除，或点击**属性**查看其属性

1.  在了解了基本的 CRUD 操作和创建索引之后，让我们看看如何执行聚合操作：

+   在聚合索引的创建中没有可视化工具，只是一个文本区域，我们在其中输入我们的聚合管道

+   在以下示例中，我们对`postalCodes`集合执行聚合，以找到在集合中出现次数最多的五个州

+   我们将输入以下聚合管道：

```sql
{'$project' : {'state':1, '_id':0}},
{'$group': {'_id':'$state', 'count':{'$sum':1}}},
{'$sort':{'count':-1}},
{'$limit':5}
```

![如何做...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_09_11.jpg)

+   一旦进入管道，点击**聚合**按钮以获取聚合结果

1.  执行 MapReduce 甚至更酷。我们将执行的用例与前面的用例类似，但我们将看到如何使用 MongoVUE 实现 MapReduce 操作：

+   要执行 map reduce 作业，请在左侧菜单中右键单击集合名称，然后单击**Map Reduce**。

+   此选项位于我们在上一张图片中看到的**Aggregation**选项正上方。这为我们提供了一个相当整洁的 GUI，可以输入**Map**、**Reduce**、**Finalize**和**In & Out**，如下图所示：![如何做...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_09_12.jpg)

+   `Map`函数就是以下内容：

```sql
function Map() {
  emit(this.state, 1)
}
```

+   `Reduce`函数如下：

```sql
function Reduce(key, values) {
  return Array.sum(values)
}
```

+   保持`Finalize`方法未实现，并在**In & Out**部分填写以下细节：![如何做...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_09_13.jpg)

+   单击**开始**开始执行 MapReduce 作业。

+   我们将输出打印到`mongoVue_mr`集合。使用以下查询查询`mongoVue_mr`集合：

```sql
db.mongoVue_mr.find().sort({value:-1}).limit(5)
```

+   检查结果是否与使用聚合获得的结果相匹配。

+   选择了 map reduce 的格式作为**Reduce**。有关更多选项及其行为，请访问[`docs.mongodb.org/manual/reference/command/mapReduce/#mapreduce-out-cmd`](http://docs.mongodb.org/manual/reference/command/mapReduce/#mapreduce-out-cmd)。

1.  现在可以使用`MongoVUE`监视服务器实例：

+   要监视一个实例，请点击顶部菜单中的**工具** | **监视**。

+   默认情况下，不会添加任何服务器，我们必须点击**+添加服务器**来添加服务器实例。

+   选择添加的本地实例或任何要监视的服务器，然后单击**连接**。

+   我们将看到相当多的监控细节。MongoVUE 使用`db.serverStatus`命令来提供这些统计信息，并限制我们在繁忙的服务器实例上执行此命令的频率，我们可以在屏幕顶部选择**刷新间隔**，如下图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/B04831_09_14.jpg)

## 工作原理...

我们在前面的部分中所涵盖的内容对于我们作为开发人员和管理员来执行大部分活动都是非常简单的。

## 还有更多...

有关管理和监控 MongoDB 实例的管理和监控的详细信息，请参阅第四章、*管理*和第六章、*监控和备份*。

## 另请参阅

+   请参阅[`www.mongovue.com/tutorials/`](http://www.mongovue.com/tutorials/)，了解有关 MongoVUE 的各种教程

### 注意

在编写本书时，MongoDB 计划发布一个名为**Compass**的类似数据可视化和操作产品。您应该查看[`www.mongodb.com/products/compass`](https://www.mongodb.com/products/compass)。


# 附录 A. 参考概念

本附录包含一些额外信息，将帮助您更好地理解配方。我们将尽可能详细地讨论写入关注和读取偏好。

# 写入关注及其重要性

写入关注是 MongoDB 服务器提供的关于客户端执行的写入操作的最低保证。客户端应用程序设置了各种级别的写入关注，以便从服务器获取在服务器端写入过程中达到某个阶段的保证。

对于保证的要求越强，从服务器获取响应的时间就越长（可能）。在写入关注中，我们并不总是需要从服务器获取关于写入操作完全成功的确认。对于一些不太关键的数据，比如日志，我们可能更感兴趣地通过连接发送更多的写入。另一方面，当我们试图更新敏感信息，比如客户详细信息时，我们希望确保写入成功（一致和持久）；数据完整性至关重要，优先于写入速度。

写入关注的一个极其有用的特性是在特定情况下在写入操作的速度和数据一致性之间进行权衡。然而，这需要对设置特定写入关注的影响有深入的理解。下图从左到右运行，并显示了写入保证水平的增加：

![写入关注及其重要性](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/1943OS_Appendix_01.jpg)

随着我们从**I**到**IV**，执行的写入保证越来越强，但从客户端的角度来看，执行写入操作所需的时间也越来越长。所有写入关注都以 JSON 对象的形式表示，使用三个不同的键，即`w`、`j`和`fsync`。另外，还使用了一个名为`wtimeout`的键，用于提供写入操作的超时值。让我们详细看一下这三个键：

+   `w`：用于指示是否等待服务器的确认，是否报告由于数据问题而导致的写入错误，以及数据是否被复制到次要位置。其值通常是一个数字，还有一个特殊情况，值可以是`majority`，我们稍后会看到。

+   `j`：这与日志记录有关，其值可以是布尔值（true/false 或 1/0）。

+   `fsync`：这是一个布尔值，与写入是否等待数据刷新到磁盘有关。

+   `wtimeout`：指定写入操作的超时时间，如果服务器在提供的时间内没有在几秒内回复客户端，驱动程序将向客户端抛出异常。我们很快会详细了解该选项。

在我们划分到驱动程序的**I**部分中，我们有两种写入关注点，分别是`{w:-1}`和`{w:0}`。这两种写入关注点都很常见，它们既不等待服务器对写入操作的确认，也不会报告由于唯一索引违规而在服务器端引起的任何异常。客户端将收到一个`ok`响应，并且只有在以后查询数据库时发现数据丢失时才会发现写入失败。两者的区别在于它们在网络错误时的响应方式。当我们设置`{w:-1}`时，操作不会失败，并且用户将收到写入响应。但是，它将包含一个响应，指出网络错误阻止了写入操作的成功，并且不应尝试重新写入。另一方面，对于`{w:0}`，如果发生网络错误，驱动程序可能选择重试操作，并且如果由于网络错误导致写入失败，则向客户端抛出异常。这两种写入关注点以牺牲数据一致性为代价，快速向调用客户端返回响应。这些写入关注点适用于日志记录等用例，其中偶尔的日志写入丢失是可以接受的。在较早版本的 MongoDB 中，如果调用客户端没有提及任何写入关注点，则`{w:0}`是默认的写入关注点。在撰写本书时，这已更改为默认的`{w:1}`选项，而`{w:0}`选项已被弃用。

在图表的**II**部分，位于驱动程序和服务器之间，我们讨论的写入关注点是`{w:1}`。驱动程序等待服务器对写入操作的确认完成。请注意，服务器的响应并不意味着写入操作已经持久化。这意味着更改刚刚更新到内存中，所有约束都已经检查，并且任何异常都将报告给客户端，与我们之前看到的两种写入关注点不同。这是一个相对安全的写入关注点模式，将会很快，但如果在数据从内存写入日志时发生崩溃，仍然有一些数据丢失的可能性。对于大多数用例来说，这是一个不错的选择。因此，这是默认的写入关注点模式。

接下来，我们来到图表的**III**部分，从服务器的入口点到日志。我们在这里寻找的写入关注点是`{j:1}`或`{j:true}`。这种写入关注点确保只有当写入操作写入日志时，才会向调用客户端返回响应。但是什么是日志呢？这是我们在第四章中深入了解的内容，但现在，我们只看一种机制，确保写入是持久的，数据在服务器崩溃时不会损坏。

最后，让我们来到图表的**IV**部分；我们讨论的写入关注点是`{fsync:true}`。这要求在向客户端发送响应之前将数据刷新到磁盘。在我看来，当启用日志记录时，这个操作实际上并没有增加任何价值，因为日志记录确保即使在服务器崩溃时也能保持数据持久性。只有在禁用日志记录时，此选项才能确保客户端接收到成功响应时写入操作成功。如果数据真的很重要，首先不应该禁用日志记录，因为它还确保磁盘上的数据不会损坏。

我们已经看到了单节点服务器的一些基本写入关注点，或者仅适用于复制集中的主节点的写入关注点。

### 注意

讨论一个有趣的事情是，如果我们有一个写关注，比如`{w:0, j:true}`？我们不等待服务器的确认，同时确保写入已经被记录到日志中。在这种情况下，日志标志优先，并且客户端等待写操作的确认。应该避免设置这种模棱两可的写关注，以避免不愉快的惊喜。

现在，我们将讨论涉及副本集辅助节点的写关注。让我们看一下下面的图表：

![写关注及其重要性](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/1943OS_Appendix_02.jpg)

任何`w`值大于一的写关注都表示在发送响应之前，辅助节点也需要确认。如前图所示，当主节点接收写操作时，它将该操作传播到所有辅助节点。一旦它从预定数量的辅助节点收到响应，它就向客户端确认写操作已成功。例如，当我们有一个写关注`{w:3}`时，这意味着只有当集群中的三个节点确认写操作时，客户端才会收到响应。这三个节点包括主节点。因此，现在只有两个辅助节点需要对成功的写操作做出响应。

然而，为写关注提供一个数字存在问题。我们需要知道集群中节点的数量，并相应地设置`w`的值。较低的值将向复制数据的少数节点发送确认。值太高可能会不必要地减慢向客户端的响应，或者在某些情况下可能根本不发送响应。假设您有一个三节点副本集，我们的写关注是`{w:4}`，服务器将在数据复制到三个不存在的辅助节点时才发送确认，因为我们只有两个辅助节点。因此，客户端需要很长时间才能从服务器那里得知写操作的情况。解决这个问题有几种方法：

+   使用`wtimeout`键并指定写关注的超时时间。这将确保写操作不会阻塞超过`wtimeout`字段指定的时间（以毫秒为单位）。例如，`{w:3, wtimeout:10000}`确保写操作不会阻塞超过 10 秒（10,000 毫秒），之后将向客户端抛出异常。在 Java 的情况下，将抛出`WriteConcernException`，根本原因消息将说明超时的原因。请注意，此异常不会回滚写操作。它只是通知客户端操作在指定的时间内未完成。它可能在客户端收到超时异常后的一段时间内在服务器端完成。由应用程序来处理异常并以编程方式采取纠正措施。超时异常的消息传达了一些有趣的细节，我们将在执行写关注的测试程序时看到。

+   在副本集的情况下，指定`w`的更好方法是将值指定为`majority`。这种写关注会自动识别副本集中的节点数，并在数据复制到大多数节点时向客户端发送确认。例如，如果写关注是`{w:"majority"}`，并且副本集中的节点数为三，则`majority`将是`2`。而在以后，当我们将节点数更改为五时，`majority`将是`3`个节点。当写关注的值给定为`majority`时，自动计算形成大多数所需的节点数。

现在，让我们将我们讨论的概念付诸实践，并执行一个测试程序，演示我们刚刚看到的一些概念。

## 建立副本集

要设置副本集，您应该知道如何启动具有三个节点的基本副本集。参考第一章 *安装和启动服务器*中的*作为副本集的一部分启动多个实例*配方。这个配方是基于那个配方构建的，因为在启动副本集时需要额外的配置，我们将在下一节中讨论。请注意，此处使用的副本与您之前使用的副本在配置上有轻微变化。

在这里，我们将使用一个 Java 程序来演示各种写入关注点及其行为。在第一章 *安装和启动服务器*中的*使用 Java 客户端连接单个节点*配方中，直到设置 Maven 之前，应该被访问。如果您来自非 Java 背景，这可能有点不方便。

### 注意

Java 项目名为`Mongo Java`可在该书的网站上下载。如果设置完成，只需执行以下命令即可测试该项目：

```sql
mvn compile exec:java -Dexec.mainClass=com.packtpub.mongo.cookbook.FirstMongoClient

```

该项目的代码可在该书的网站上下载。下载名为`WriteConcernTest`的项目，并将其保存在本地驱动器上以备执行。

所以，让我们开始吧：

1.  为副本集准备以下配置文件。这与我们在第一章 *安装和启动服务器*中的*作为副本集的一部分启动多个实例*配方中看到的配置文件相同，我们在那里设置了副本集，只有一个区别，`slaveDelay:5`，`priority:0`：

```sql
cfg = {
 _id:'repSetTest',
 members:[
 {_id:0, host:'localhost:27000'},
 {_id:1, host:'localhost:27001'},
 {_id:2, host:'localhost:27002', slaveDelay:5, priority:0}
 ]
}

```

1.  使用此配置启动一个三节点副本集，其中一个节点监听端口`27000`。其他节点可以是您选择的任何端口，但如果可能的话，请坚持使用`27001`和`27002`（如果决定使用不同的端口号，我们需要相应更新配置）。还要记得在启动副本集时，将副本集的名称设置为`replSetTest`，并将其作为`replSet`命令行选项。在继续下一步之前，请给副本集一些时间来启动。

1.  此时，具有前述规格的副本集应该已经启动并运行。我们现在将执行 Java 中提供的测试代码，以观察不同写入关注点的一些有趣事实和行为。请注意，此程序还尝试连接到没有 Mongo 进程监听连接的端口。选择的端口是`20000`；在运行代码之前，请确保没有服务器正在运行并监听端口`20000`。

1.  转到`WriteConcernTest`项目的根目录并执行以下命令：

```sql
mvn compile exec:java -Dexec.mainClass=com.packtpub.mongo.cookbook.WriteConcernTests

```

这需要一些时间才能完全执行，具体取决于您的硬件配置。在我的机器上大约花了 35 到 40 秒的时间，我的机器上有一个 7200 转的传统硬盘。

在我们继续分析日志之前，让我们看看添加到配置文件中设置副本的这两个附加字段是什么。`slaveDelay`字段表示特定的副本（在本例中监听端口`27002`的副本）将比主节点滞后 5 秒。也就是说，当前在该副本节点上复制的数据是 5 秒前添加到主节点上的数据。其次，该节点永远不能成为主节点，因此必须添加`priority`字段并赋值为`0`。我们已经在第四章 *管理*中详细介绍了这一点。

现在让我们分析前述命令执行的输出。这里不需要查看提供的 Java 类；控制台上的输出就足够了。输出控制台的一些相关部分如下：

```sql
[INFO] --- exec-maven-plugin:1.2.1:java (default-cli) @ mongo-cookbook-wctest ---
Trying to connect to server running on port 20000
Trying to write data in the collection with write concern {w:-1}
Error returned in the WriteResult is NETWORK ERROR
Trying to write data in the collection with write concern {w:0}
Caught MongoException.Network trying to write to collection, message is Write operation to server localhost/127.0.0.1:20000 failed on database test
Connected to replica set with one node listening on port 27000 locally

Inserting duplicate keys with {w:0}
No exception caught while inserting data with duplicate _id
Now inserting the same data with {w:1}
Caught Duplicate Exception, exception message is { "serverUsed" : "localhost/127.0.0.1:27000" , "err" : "E11000 duplicate key error index: test.writeConcernTest.$_id_  dup key: { : \"a\" }" , "code" : 11000 , "n" : 0 , "lastOp" : { "$ts" :1386009990 , "$inc" : 2} , "connectionId" : 157 , "ok" : 1.0}
Average running time with WriteConcern {w:1, fsync:false, j:false} is 0 ms
Average running time with WriteConcern {w:2, fsync:false, j:false} is 12 ms
Average running time with WriteConcern {w:1, fsync:false, j:true} is 40 ms
Average running time with WriteConcern {w:1, fsync:true, j:false} is 44 ms
Average running time with WriteConcern {w:3, fsync:false, j:false} is 5128 ms
Caught WriteConcern exception for {w:5}, with following message { "serverUsed" : "localhost/127.0.0.1:27000" , "n" : 0 , "lastOp" : { "$ts" : 1386009991 , "$inc" : 18} , "connectionId" : 157 , "wtimeout" : true , "waited" : 1004 , "writtenTo" : [ { "_id" : 0 , "host" : "localhost:27000"} , { "_id" : 1 , "host" : "localhost:27001"}] , "err" : "timeout" , "ok" : 1.0}
 [INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time: 36.671s
[INFO] Finished at: Tue Dec 03 00:16:57 IST 2013
[INFO] Final Memory: 13M/33M
[INFO] ------------------------------------------------------------------------

```

日志中的第一条语句说明我们尝试连接到一个监听端口`20000`的 Mongo 进程。由于不应该有 Mongo 服务器在此端口上运行并监听客户端连接，因此我们所有对该服务器的写操作都不应成功，现在我们有机会看看当我们使用写关注`{w:-1}`和`{w:0}`并向这个不存在的服务器写入时会发生什么。

输出中的下两行显示，当我们有写关注`{w:-1}`时，我们确实得到了写入结果，但其中包含了设置为指示网络错误的错误标志。但是，没有抛出异常。在写关注`{w:0}`的情况下，我们在客户端应用程序中对任何网络错误都会得到异常。当然，在这种情况下，所有其他确保严格保证的写关注也会抛出异常。

现在我们来到连接到副本集的代码部分，其中一个节点正在监听端口`27000`（如果没有，代码将在控制台上显示错误并终止）。现在，我们尝试向集合中插入一个具有重复`_id`字段（`{'_id':'a'}`）的文档，一次使用写关注`{w:0}`，一次使用`{w:1}`。正如我们在控制台中看到的，前者（`{w:0}`）没有抛出异常，从客户端的角度来看插入成功进行了，而后者（`{w:1}`）向客户端抛出了异常，指示重复键。异常包含了关于服务器主机名和端口的大量信息，在异常发生时：唯一约束失败的字段；客户端连接 ID；错误代码；以及导致异常的不唯一值。事实是，即使使用`{w:0}`作为写关注进行插入，它也失败了。但是，由于驱动程序没有等待服务器的确认，它从未被通知插入失败。

继续前进，我们现在尝试计算写操作完成所需的时间。这里显示的时间是执行相同操作的给定写关注五次所需时间的平均值。请注意，这些时间将在程序的不同执行实例上变化，这种方法只是为了给我们的研究提供一些粗略的估计。我们可以从输出中得出结论，写关注`{w:1}`所需的时间少于`{w:2}`（要求从一个辅助节点获得确认），而`{w:2}`所需的时间少于`{j:true}`，而`{j:true}`又少于`{fsync:true}`。输出的下一行告诉我们，当写关注为`{w:3}`时，写操作完成所需的平均时间大约为 5 秒。你猜为什么会这样吗？为什么会花这么长时间？原因是，当`w`为`3`时，我们只有在两个辅助节点确认写操作时才向客户端发送确认。在我们的情况下，一个节点比主节点延迟约 5 秒，因此只有在 5 秒后才能确认写操作，因此客户端大约在 5 秒后从服务器收到响应。

让我们在这里做一个快速练习。当我们的写关注为`{w:'majority'}`时，你认为大约的响应时间会是多少？这里的提示是，对于一个三个节点的副本集，两个是大多数。

最后我们看到了超时异常。超时是使用文档的`wtimeout`字段设置的，以毫秒为单位。在我们的情况下，我们设置了 1000 毫秒的超时，即 1 秒，并且在将响应发送回客户端之前从副本集中获得确认的节点数为 5（四个从实例）。因此，我们的写关注是`{w:5, wtimeout:1000}`。由于我们的最大节点数为三个，所以将`w`设置为`5`的操作将等待很长时间，直到集群中添加了另外两个从实例。设置超时后，客户端返回并向客户端抛出错误，传达一些有趣的细节。以下是作为异常消息发送的 JSON：

```sql
{ "serverUsed" : "localhost/127.0.0.1:27000" , "n" : 0 , "lastOp" : { "$ts" : 1386015030 , "$inc" : 1} , "connectionId" : 507 , "wtimeout" : true , "waited" : 1000 , "writtenTo" : [ { "_id" : 0 , "host" : "localhost:27000"} , { "_id" : 1 , "host" : "localhost:27001"}] , "err" : "timeout" , "ok" : 1.0}

```

让我们看看有趣的字段。我们从`n`字段开始。这表示更新的文档数量。在这种情况下，它是一个插入而不是更新，所以保持为`0`。`wtimeout`和`waited`字段告诉我们事务是否超时以及客户端等待响应的时间；在这种情况下是 1000 毫秒。最有趣的字段是`writtenTo`。在这种情况下，插入在超时时成功在副本集的这两个节点上，并且因此在数组中看到。第三个节点的`slaveDelay`值为 5 秒，因此数据仍未写入。这证明超时不会回滚插入，它确实成功进行。实际上，即使操作超时，具有`slaveDelay`的节点也将在 5 秒后拥有数据，这是有道理的，因为它保持主节点和从节点同步。应用程序有责任检测此类超时并处理它们。

# 查询的读取偏好

在前一节中，我们看到了写关注是什么以及它如何影响写操作（插入、更新和删除）。在本节中，我们将看到读取偏好是什么以及它如何影响查询操作。我们将讨论如何在单独的配方中使用读取偏好，以使用特定的编程语言驱动程序。

当连接到单个节点时，默认情况下允许查询操作连接到主节点，如果连接到从节点，则需要明确声明可以通过在 shell 中执行`rs.slaveOk()`来从从实例查询。

然而，考虑从应用程序连接到 Mongo 副本集。它将连接到副本集，而不是从应用程序连接到单个实例。根据应用程序的性质，它可能总是想要连接到主节点；总是连接到从节点；更喜欢连接到主节点，但在某些情况下连接到从节点也可以，反之亦然，最后，它可能连接到地理位置靠近它的实例（嗯，大部分时间）。

因此，读取偏好在连接到副本集而不是单个实例时起着重要作用。在下表中，我们将看到各种可用的读取偏好以及它们在查询副本集方面的行为。共有五种，名称不言自明：

| 读取偏好 | 描述 |
| --- | --- |
| `primary` | 这是默认模式，它允许查询仅在主实例上执行。这是唯一保证最新数据的模式，因为所有写操作都必须通过主实例进行。然而，如果没有主实例可用，读操作将失败，这在主机宕机并持续到选择新的主机时会发生一段时间。 |
| `primaryPreferred` | 这与前面的主读取偏好相同，只是在故障切换期间，当没有主机可用时，它将从从节点读取数据，这些时候可能不会读取到最新数据。 |
| `secondary` | 这与默认的 primary 读取偏好完全相反。此模式确保读取操作永远不会转到 primary，而总是选择 secondary。在这种模式下，读取不一致的数据的机会最大，因为它没有更新到最新的写操作。但是，对于不面向最终用户并且用于某些实例获取每小时统计和分析作业的应用程序来说，这是可以接受的（事实上是首选），其中数据的准确性最不重要，但不会增加对 primary 实例的负载是关键的。如果没有 secondary 实例可用或可达，只有 primary 实例，读取操作将失败。 |
| `secondaryPreferred` | 这与前面的 secondary 读取偏好类似，除了如果没有 secondary 可用，读取操作将转到 primary 实例。 |
| `nearest` | 与所有先前的读取偏好不同，这可以连接到 primary 或 secondary。这种读取偏好的主要目标是客户端和副本集实例之间的最小延迟。在大多数情况下，由于网络延迟和客户端与所有实例之间的相似网络，所选择的实例将是地理上接近的实例。 |

与写关注可以与分片标签结合使用类似，读取偏好也可以与分片标签一起使用。由于标签的概念已经在第四章中介绍过，您可以参考它以获取更多详细信息。

我们刚刚看到了不同类型的读取偏好（除了使用标签的那些），但问题是，我们如何使用它们？本书中涵盖了 Python 和 Java 客户端，并将看到如何在它们各自的示例中使用它们。我们可以在各个级别设置读取偏好：在客户端级别、集合级别和查询级别，查询级别指定的读取偏好将覆盖先前设置的任何其他读取偏好。

让我们看看最近的读取偏好意味着什么。从概念上讲，它可以被可视化为以下图表：

![查询的读取偏好](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/1943OS_Appendix_03.jpg)

Mongo 副本集设置了一个 secondary，它永远不会成为 primary，在一个单独的数据中心，另一个数据中心有两个（一个 primary 和一个 secondary）。在两个数据中心都部署了相同的应用程序，使用 primary 读取偏好，将始终连接到**数据中心 I**中的 primary 实例。这意味着，对于**数据中心 II**中的应用程序，流量将通过公共网络，这将具有较高的延迟。但是，如果应用程序可以接受略有陈旧的数据，它可以将读取偏好设置为最近，这将自动让**数据中心 I**中的应用程序连接到**数据中心 I**中的实例，并允许**数据中心 II**中的应用程序连接到**数据中心 II**中的 secondary 实例。

但接下来的问题是，驱动程序如何知道哪一个是最近的？术语“地理上接近”是误导的；实际上是具有最小网络延迟的那个。我们查询的实例可能在地理上比副本集中的另一个实例更远，但它可能被选择，只是因为它具有可接受的响应时间。通常，更好的响应时间意味着地理上更接近。

以下部分是为那些对驱动程序内部细节感兴趣的人准备的，关于最近节点是如何选择的。如果您只对概念感兴趣而不关心内部细节，可以放心地跳过其余内容。

## 了解内部情况

让我们看一下来自 Java 客户端（用于此目的的驱动程序为 2.11.3）的一些代码片段，并对其进行一些解释。如果我们查看`com.mongodb.TaggableReadPreference.NearestReadPreference.getNode`方法，我们会看到以下实现：

```sql
@Override
ReplicaSetStatus.ReplicaSetNode getNode(ReplicaSetStatus.ReplicaSet set) {
  if (_tags.isEmpty())
    return set.getAMember();

  for (DBObject curTagSet : _tags) {
    List<ReplicaSetStatus.Tag> tagList = getTagListFromDBObject(curTagSet);
    ReplicaSetStatus.ReplicaSetNode node = set.getAMember(tagList);
    if (node != null) {
      return node;
    }
  }
  return null;
}
```

目前，如果我们忽略指定标签的内容，它所做的就是执行`set.getAMember()`。

这个方法的名称告诉我们，有一组副本集成员，我们随机返回其中一个。那么是什么决定了集合是否包含成员？如果我们再深入一点研究这个方法，我们会在`com.mongodb.ReplicaSetStatus.ReplicaSet`类中看到以下代码行：

```sql
public ReplicaSetNode getAMember() {
  checkStatus();
  if (acceptableMembers.isEmpty()) {
    return null;
  }
  return acceptableMembers.get(random.nextInt(acceptableMembers.size()));
}
```

好的，它所做的就是从内部维护的副本集节点列表中选择一个。现在，随机选择可以是一个 secondary，即使可以选择一个 primary（因为它存在于列表中）。因此，我们现在可以说当最近的节点被选择为读取偏好时，即使主节点在候选者列表中，也可能不会被随机选择。

现在的问题是，`acceptableMembers`列表是如何初始化的？我们看到它是在`com.mongodb.ReplicaSetStatus.ReplicaSet`类的构造函数中完成的，如下所示：

```sql
this.acceptableMembers =Collections.unmodifiableList(calculateGoodMembers(all, calculateBestPingTime(all, true),acceptableLatencyMS, true));
```

`calculateBestPingTime`行只是找到所有 ping 时间中的最佳时间（稍后我们将看到这个 ping 时间是什么）。

值得一提的另一个参数是`acceptableLatencyMS`。这在`com.mongodb.ReplicaSetStatus.Updater`中初始化（实际上是一个不断更新副本集状态的后台线程），`acceptableLatencyMS`的值初始化如下：

```sql
slaveAcceptableLatencyMS = Integer.parseInt(System.getProperty("com.mongodb.slaveAcceptableLatencyMS", "15"));
```

正如我们所见，这段代码搜索名为`com.mongodb.slaveAcceptableLatencyMS`的系统变量，如果找不到，则初始化为值`15`，即 15 毫秒。

这个`com.mongodb.ReplicaSetStatus.Updater`类还有一个`run`方法，定期更新副本集的统计信息。不深入研究，我们可以看到它调用`updateAll`，最终到达`com.mongodb.ConnectionStatus.UpdatableNode`中的`update`方法。

```sql
long start = System.nanoTime();
CommandResult res = _port.runCommand(_mongo.getDB("admin"), isMasterCmd);
long end = System.nanoTime()
```

它所做的就是执行`{isMaster:1}`命令并记录响应时间（以纳秒为单位）。这个响应时间转换为毫秒并存储为 ping 时间。所以，回到`com.mongodb.ReplicaSetStatus.ReplicaSet`类中，`calculateGoodMembers`所做的就是找到并添加副本集中不超过`acceptableLatencyMS`毫秒的成员，这些成员的 ping 时间不超过副本集中找到的最佳 ping 时间。

例如，在一个有三个节点的副本集中，客户端到三个节点（节点 1、节点 2 和节点 3）的 ping 时间分别为 2 毫秒、5 毫秒和 150 毫秒。正如我们所见，最佳时间是 2 毫秒，因此节点 1 进入了良好成员的集合中。现在，从剩下的节点中，所有延迟不超过最佳时间的`acceptableLatencyMS`的节点也是候选者，即*2 + 15 毫秒 = 17 毫秒*，因为 15 毫秒是默认值。因此，节点 2 也是一个候选者，剩下的是节点 3。现在我们有两个节点在良好成员的列表中（从延迟的角度来看是好的）。

现在，将我们在前面的图表中看到的所有内容整合起来，最小的响应时间将来自同一数据中心中的一个实例（从这两个数据中心的编程语言驱动程序的角度来看），因为其他数据中心中的实例可能由于公共网络延迟而无法在 15 毫秒（默认可接受值）内响应。因此，**数据中心 I**中的可接受节点将是该数据中心中的两个副本集节点，其中一个将被随机选择，而对于**数据中心 II**，只有一个实例存在，也是唯一的选择。因此，它将由在该数据中心运行的应用程序选择。
