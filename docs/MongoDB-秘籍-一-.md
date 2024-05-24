# MongoDB 秘籍（一）

> 原文：[`zh.annas-archive.org/md5/9F335F41611FE256D46F623124D9DAEC`](https://zh.annas-archive.org/md5/9F335F41611FE256D46F623124D9DAEC)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

MongoDB 是一种面向文档的领先 NoSQL 数据库，提供线性可扩展性，因此成为高容量、高性能系统在所有业务领域的良好竞争者。它在易用性、高性能和丰富功能方面胜过大多数 NoSQL 解决方案。

本书提供了详细的配方，描述了如何使用 MongoDB 的不同功能。这些配方涵盖了从设置 MongoDB、了解其编程语言 API 和监控和管理，到一些高级主题，如云部署、与 Hadoop 集成，以及一些用于 MongoDB 的开源和专有工具。配方格式以简洁、可操作的形式呈现信息；这使您可以参考配方，以解决并了解手头的用例的详细信息，而无需阅读整本书。

# 本书涵盖的内容

第一章，“安装和启动服务器”，全都是关于启动 MongoDB。它将演示如何以独立模式、副本集模式和分片模式启动服务器，使用命令行或配置文件提供的启动选项。

第二章，“命令行操作和索引”，有简单的配方，用于在 Mongo shell 中执行 CRUD 操作，并在 shell 中创建各种类型的索引。

第三章，“编程语言驱动程序”，讨论了编程语言 API。虽然 Mongo 支持多种语言，但我们只会讨论如何使用驱动程序仅从 Java 和 Python 程序连接到 MongoDB 服务器。本章还探讨了 MongoDB 的线协议，用于服务器和编程语言客户端之间的通信。

第四章，“管理”，包含了许多用于管理或 MongoDB 部署的配方。本章涵盖了许多经常使用的管理任务，如查看集合和数据库的统计信息，查看和终止长时间运行的操作以及其他副本集和分片相关的管理。

第五章，“高级操作”，是第二章的延伸，我们将看一些稍微高级的功能，如实现服务器端脚本、地理空间搜索、GridFS、全文搜索，以及如何将 MongoDB 与外部全文搜索引擎集成。

第六章，“监控和备份”，告诉您有关管理和一些基本监控的所有内容。然而，MongoDB 提供了一流的监控和实时备份服务，MongoDB 监控服务（MMS）。在本章中，我们将看一些使用 MMS 进行监控和备份的配方。

第七章，“在云上部署 MongoDB”，涵盖了使用 MongoDB 服务提供商进行云部署的配方。我们将在 AWS 云上设置自己的 MongoDB 服务器，以及在 Docker 容器中运行 MongoDB。

第八章，“与 Hadoop 集成”，涵盖了将 MongoDB 与 Hadoop 集成的配方，以使用 Hadoop MapReduce API 在 MongoDB 数据文件中运行 MapReduce 作业并将结果写入其中。我们还将看到如何使用 AWS EMR 在云上运行我们的 MapReduce 作业，使用亚马逊的 Hadoop 集群 EMR 和 mongo-hadoop 连接器。

第九章，*开源和专有工具*，介绍了使用围绕 MongoDB 构建的框架和产品来提高开发人员的生产力，或者简化使用 Mongo 的一些日常工作。除非明确说明，本章中将要查看的产品/框架都是开源的。

附录，*参考概念*，为您提供了有关写入关注和读取偏好的一些额外信息。

# 您需要什么来阅读本书

用于尝试配方的 MongoDB 版本是 3.0.2。这些配方也适用于版本 2.6.*x*。如果有特定于版本 2.6.*x*的特殊功能，将在配方中明确说明。除非明确说明，所有命令都应在 Ubuntu Linux 上执行。

涉及 Java 编程的示例已在 Java 版本 1.7 上进行了测试和运行，Python 代码则使用 Python v2.7 运行（与 Python 3 兼容）。对于 MongoDB 驱动程序，您可以选择使用最新可用版本。

这些是相当常见的软件类型，它们的最低版本在不同的配方中使用。本书中的所有配方都将提到完成它所需的软件及其各自的版本。一些配方需要在 Windows 系统上进行测试，而另一些需要在 Linux 上进行测试。

# 这本书是为谁准备的

这本书是为对了解 MongoDB 并将其用作高性能和可扩展数据存储的管理员和开发人员设计的。它也适用于那些了解 MongoDB 基础知识并希望扩展知识的人。本书的受众预期至少具有一些 MongoDB 基础知识。

# 约定

在本书中，您将找到一些区分不同信息类型的文本样式。以下是一些这些样式的示例，以及它们的含义解释。

在本书中，您将找到一些区分不同信息类型的文本样式。以下是一些这些样式的示例和它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下："创建`/data/mongo/db 目录`（或您选择的任何目录）"。

代码块设置如下：

```sql
   import com.mongodb.DB;
   import com.mongodb.DBCollection;
   import com.mongodb.DBObject;
   import com.mongodb.MongoClient;
```

任何命令行输入或输出都按如下方式编写：

```sql
$ sudo apt-get install default-jdk

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中："由于我们想要启动一个免费的微实例，请在左侧勾选**仅免费层**复选框"。

### 注意

警告或重要提示会以以下方式显示在框中。

### 提示

提示和技巧会以这种方式出现。

# 读者反馈

我们的读者反馈总是受欢迎的。让我们知道你对这本书的想法——你喜欢什么，或者可能不喜欢什么。读者的反馈对我们开发能让你真正受益的标题非常重要。

要向我们发送一般反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在消息主题中提及书名。

如果您在某个专题上有专业知识，并且有兴趣撰写或为一本书做出贡献，请参阅我们的作者指南[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

既然您已经是 Packt 书籍的自豪所有者，我们有很多事情可以帮助您充分利用您的购买。

## 下载示例代码

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 书籍的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

## 勘误

尽管我们已经尽一切努力确保内容的准确性，但错误确实会发生。如果您在我们的书籍中发现错误——可能是文本或代码中的错误，我们将不胜感激地希望您向我们报告。通过这样做，您可以帮助其他读者避免挫折，并帮助我们改进本书的后续版本。如果您发现任何勘误，请访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书籍，点击**勘误提交表格**链接，并输入您的勘误详情。一旦您的勘误经过验证，您的提交将被接受，并且勘误将被上传到我们的网站上，或者添加到该标题的勘误列表中的任何现有勘误下的勘误部分。您可以通过从[`www.packtpub.com/support`](http://www.packtpub.com/support)选择您的标题来查看任何现有的勘误。

## 盗版

互联网上盗版版权材料是所有媒体的持续问题。在 Packt，我们非常重视保护我们的版权和许可。如果您在互联网上发现我们作品的任何非法副本，请立即向我们提供位置地址或网站名称，以便我们采取补救措施。

请通过`<copyright@packtpub.com>`与我们联系，并附上涉嫌盗版材料的链接。

我们感谢您在保护我们的作者和我们为您提供有价值的内容的能力方面的帮助。

## 问题

如果您在书籍的任何方面遇到问题，可以通过`<questions@packtpub.com>`与我们联系，我们将尽力解决。


# 第一章：安装和启动服务器

在本章中，我们将涵盖以下配方：

+   安装单节点 MongoDB

+   使用命令行选项启动单个节点实例

+   使用配置文件从安装单节点 MongoDB

+   在 Mongo shell 中使用 JavaScript 连接到单个节点

+   从 Java 客户端连接到单个节点

+   从 Python 客户端连接到单个节点

+   作为副本集的一部分启动多个实例

+   连接到副本集以查询和插入数据

+   从 Java 客户端连接到副本集以查询和插入数据

+   从 Python 客户端连接到副本集以查询和插入数据

+   启动包含两个分片的简单分片环境

+   在 shell 中连接到分片并执行操作

# 介绍

在本章中，我们将看看如何启动 MongoDB 服务器。虽然对于开发目的以默认设置启动服务器很容易，但有许多可用于微调启动行为的选项。我们将作为单个节点启动服务器，然后介绍各种配置选项。我们将通过设置一个简单的副本集并运行一个分片集群来结束本章。因此，让我们开始以最简单的方式安装和设置 MongoDB 服务器，以用于简单的开发目的。

# 安装单节点 MongoDB

在这个配方中，我们将看看如何以独立模式安装 MongoDB。这是启动 MongoDB 服务器的最简单和最快的方法，但很少用于生产用例。然而，这是开发目的中启动服务器的最常见方式。在这个配方中，我们将在不看很多其他启动选项的情况下启动服务器。

## 准备工作

嗯，假设我们已经从下载站点下载了 MongoDB 二进制文件，解压缩并将生成的 bin 目录放在操作系统的路径变量中。（这不是强制性的，但这样做后确实变得更加方便。）可以从[`www.mongodb.org/downloads`](http://www.mongodb.org/downloads)下载二进制文件，然后选择您的主机操作系统。

## 如何做…

1.  创建目录`/data/mongo/db`（或您选择的任何目录）。这将是我们的数据库目录，并且需要由`mongod`（mongo 服务器进程）进程具有写入权限。

1.  我们将从控制台启动服务器，数据目录为`/data/mongo/db`，如下所示：

```sql
> mongod --dbpath  /data/mongo/db

```

## 它是如何工作的…

如果您在控制台上看到以下行，则已成功启动服务器：

```sql
[initandlisten] waiting for connections on port 27017

```

启动服务器再也没有比这更容易的了。尽管启动服务器的简单性，但有许多配置选项可用于调整服务器在启动时的行为。大多数默认选项是合理的，不需要更改。使用默认值，服务器应该监听端口`27017`以进行新连接，并且日志将打印到标准输出。

## 另请参阅

有时我们希望在服务器启动时配置一些选项。在*安装单节点 MongoDB*配方中，我们将使用一些更多的启动选项。

# 使用命令行选项启动单个节点实例

在这个配方中，我们将看到如何使用一些命令行选项启动独立的单节点服务器。我们将看一个例子，我们想要做以下事情：

+   启动服务器监听端口`27000`

+   日志应写入`/logs/mongo.log`

+   数据库目录是`/data/mongo/db`

由于服务器已经为开发目的启动，我们不希望预先分配完整大小的数据库文件。（我们很快会看到这意味着什么。）

## 准备工作

如果您已经看过并执行了*安装单节点 MongoDB*配方，则无需做任何不同的事情。如果所有这些先决条件都得到满足，那么我们就可以开始本配方了。

## 如何做…

1.  数据库的 `/data/mongo/db` 目录和日志的 `/logs/` 应该在您的文件系统上创建并存在，并具有适当的权限进行写入。

1.  执行以下命令：

```sql
> mongod --port 27000 --dbpath /data/mongo/db –logpath /logs/mongo.log --smallfiles

```

## 工作原理…

好的，这并不太困难，与之前的配方类似，但这次我们有一些额外的命令行选项。MongoDB 实际上在启动时支持相当多的选项，我认为我们将看到一些最常见和最重要的选项列表：

| 选项 | 描述 |
| --- | --- |
| `--help` 或 `-h` | 用于打印可用的各种启动选项的信息。 |
| `--config` 或 `-f` | 这指定包含所有配置选项的配置文件的位置。我们将在以后的配方中更多地了解这个选项。这只是一种方便的方式，可以在文件中指定配置，而不是在命令提示符中指定；特别是当指定的选项数量更多时。使用一个共享的配置文件跨不同的 MongoDB 实例也将确保所有实例都使用相同的配置运行。 |
| `--verbose` 或 `-v` | 这会使日志更冗长；我们可以添加更多的 v 来使输出更冗长，例如，`-vvvvv`。 |
| `--quiet` | 这会产生更安静的输出；这与冗长或 `-v` 选项相反。它将使日志更少，更整洁。 |
| `--port` | 如果您希望启动服务器侦听除默认端口 `27017` 以外的某个端口，则使用此选项。每当我们希望在同一台机器上启动多个 mongo 服务器时，我们会经常使用此选项，例如，`--port 27018` 将使服务器侦听端口 `27018` 以获取新连接。 |
| `--logpath` | 这提供了一个日志文件的路径，日志将被写入其中。该值默认为 `STDOUT`。例如，`--logpath /logs/server.out` 将使用 `/logs/server.out` 作为服务器的日志文件。请记住，提供的值应该是一个文件，而不是日志将被写入的目录。 |
| `--logappend` | 如果有的话，此选项将追加到现有的日志文件。默认行为是重命名现有的日志文件，然后为当前启动的 mongo 实例的日志创建一个新文件。假设我们已经将日志文件命名为 `server.out`，并且在启动时该文件存在，则默认情况下此文件将被重命名为 `server.out.<timestamp>`，其中 `<timestamp>` 是当前时间。时间是 GMT 时间，而不是本地时间。假设当前日期是 2013 年 10 月 28 日，时间是 12:02:15，则生成的文件将具有以下值作为时间戳：`2013-10-28T12-02-15`。 |
| `--dbpath` | 这为您提供了一个新数据库将被创建或现有数据库存在的目录。该值默认为 `/data/db`。我们将使用 `/data/mongo/db` 作为数据库目录启动服务器。请注意，该值应该是一个目录，而不是文件的名称。 |
| `--smallfiles` | 这在开发过程中经常使用，当我们计划在本地机器上启动多个 mongo 实例时。Mongo 在启动时会在 64 位机器上创建一个大小为 64MB 的数据库文件。出于性能原因，这种预分配会发生，并且文件将被创建并写入零以填充磁盘上的空间。在启动时添加此选项将仅创建一个预分配文件，大小为 16MB（同样，在 64 位机器上）。此选项还会减小数据库和日志文件的最大大小。不要在生产部署中使用此选项。另外，默认情况下，文件大小会增加到最大 2GB。如果选择了 `--smallfile` 选项，则最大增加到 512MB。 |
| `--replSet` | 此选项用于将服务器启动为复制集的成员。此`arg`的值是复制集的名称，例如，`--replSet repl1`。在以后的食谱中，您将更多地了解这个选项，我们将启动一个简单的 mongo 复制集。 |
| `--configsvr` | 此选项用于将服务器启动为配置服务器。当我们在本章的后续食谱中设置一个简单的分片环境时，配置服务器的角色将更加清晰。 |
| `--shardsvr` | 这通知启动的 mongod 进程，该服务器正在作为分片服务器启动。通过给出此选项，服务器还会监听端口`27018`，而不是默认的`27017`。当我们启动一个简单的分片服务器时，我们将更多地了解这个选项。 |
| `--oplogSize` | Oplog 是复制的支柱。它是一个有上限的集合，主实例写入的数据存储在其中，以便复制到次要实例。此集合位于名为`local`的数据库中。在初始化复制集时，oplog 的磁盘空间被预先分配，并且数据库文件（用于本地数据库）被填充为占位符的零。默认值为磁盘空间的 5%，对于大多数情况来说应该足够好。oplog 的大小至关重要，因为有上限的集合是固定大小的，当超过其大小时，它们会丢弃其中的最旧文档，从而为新文档腾出空间。oplog 大小非常小可能导致数据在复制到次要节点之前被丢弃。oplog 大小很大可能导致不必要的磁盘空间利用和复制集初始化的持续时间很长。对于开发目的，当我们在同一主机上启动多个服务器进程时，我们可能希望将 oplog 大小保持在最小值，快速启动复制集，并使用最小的磁盘空间。 |
| `--storageEngine` | 从 MongoDB 3.0 开始，引入了一个名为 Wired Tiger 的新存储引擎。以前（默认）的存储引擎现在称为**mmapv1**。要使用 Wired Tiger 而不是`mmapv1`启动 MongoDB，请使用此选项的`wiredTiger`值。 |
| `--dirctoryperdb` | 默认情况下，MongoDB 的数据库文件存储在一个公共目录中（如`--dbpath`中提供的）。此选项允许您将每个数据库存储在上述数据目录中的自己的子目录中。具有这样细粒度的控制允许您为每个数据库拥有单独的磁盘。 |

## 还有更多…

要获取可用选项的详尽列表，请使用`--help`或`-h`选项。这些选项列表并不详尽，我们将在以后的食谱中看到更多的选项，只要我们需要它们。在下一个食谱中，我们将看到如何使用配置文件而不是命令行参数。

## 另请参阅

+   *使用配置文件提供启动选项的 MongoDB 单节点安装*

+   *启动多个实例作为复制集的一部分* 来启动一个复制集

+   *启动一个包含两个分片的简单分片环境* 来设置一个分片环境

# 使用配置文件进行 MongoDB 的单节点安装

正如我们所看到的，从命令行提供选项可以完成工作，但是一旦我们提供的选项数量增加，情况就开始变得尴尬了。我们有一个干净而好的选择，可以从配置文件而不是作为命令行参数来提供启动选项。

## 准备工作

如果您已经执行了*安装单节点 MongoDB*食谱，那么您无需做任何不同的事情，因为此食谱的所有先决条件都是相同的。

## 如何做…

数据库的`/data/mongo/db`目录和日志的`/logs/`应该在您的文件系统上创建并存在，并具有适当的权限以写入它并执行以下步骤：

1.  创建一个可以有任意名称的配置文件。在我们的情况下，假设我们在`/conf/mongo.conf`中创建了这个文件。然后编辑文件并添加以下行：

```sql
port = 27000
dbpath = /data/mongo/db
logpath = /logs/mongo.log
smallfiles = true
```

1.  使用以下命令启动 mongo 服务器：

```sql
> mongod --config  /config/mongo.conf

```

## 工作原理…

我们在配置文件中提供了前面一篇文章中讨论的所有命令行选项，*使用命令行选项启动单个节点实例*。我们只是将它们提供在一个配置文件中。如果您还没有阅读前一篇文章，我建议您这样做，因为那里我们讨论了一些常见的命令行选项。属性被指定为`<property name> = <value>`。对于所有没有值的属性，例如`smallfiles`选项，给定的值是一个布尔值，true。如果我们需要有详细的输出，我们会在我们的配置文件中`添加 v=true`（或多个 v 以使其更详细）。如果您已经知道命令行选项是什么，那么猜测属性在文件中的值就很容易了。它几乎与去掉连字符的命令行选项相同。

# 使用 JavaScript 在 Mongo shell 中连接到单个节点

这个示例是关于启动 mongo shell 并连接到 MongoDB 服务器。在这里，我们还演示了如何在 shell 中加载 JavaScript 代码。虽然这并不总是必需的，但当我们有一大块带有变量和函数的 JavaScript 代码，并且这些函数需要经常从 shell 中执行并且我们希望这些函数始终在 shell 中可用时，这是很方便的。

## 准备就绪

虽然可能会在不连接到 MongoDB 服务器的情况下运行 mongo shell，但我们很少需要这样做。要在本地主机上启动服务器而不费吹灰之力，请查看第一篇文章*安装单节点 MongoDB*，并启动服务器。

## 如何做…

1.  首先，我们创建一个简单的 JavaScript 文件并将其命名为`hello.js`。在`hello.js`文件中输入以下内容：

```sql
function sayHello(name) {
  print('Hello ' + name + ', how are you?')
}
```

1.  将此文件保存在位置`/mongo/scripts/hello.js`。（这也可以保存在任何其他位置。）

1.  在命令提示符上执行以下操作：

```sql
> mongo --shell /mongo/scripts/hello.js

```

1.  执行此命令时，我们应该在控制台上看到以下内容打印出来：

```sql
MongoDB shell version: 3.0.2
connecting to: test
>

```

1.  通过输入以下命令来测试 shell 连接的数据库：

```sql
> db

```

这应该在控制台上打印出`test`。

1.  现在，在 shell 中输入以下命令：

```sql
> sayHello('Fred')

```

1.  您应该收到以下响应：

```sql
Hello Fred, how are you?

```

### 注意

注意：本书是使用 MongoDB 版本 3.0.2 编写的。您可能正在使用更新的版本，因此在 mongo shell 中可能看到不同的版本号。

## 工作原理…

我们在这里执行的 JavaScript 函数没有实际用途，只是用来演示如何在 shell 启动时预加载函数。`.js`文件中可能包含有效的 JavaScript 代码，可能是一些复杂的业务逻辑。

在没有任何参数的情况下执行`mongo`命令时，我们连接到在本地主机上运行的 MongoDB 服务器，并在默认端口`27017`上监听新连接。一般来说，命令的格式如下：

```sql
mongo <options> <db address> <.js files>

```

在没有传递参数给 mongo 可执行文件的情况下，它相当于将`db 地址`传递为`localhost:27017/test`。

让我们看一些`db 地址`命令行选项的示例值及其解释：

+   `mydb`：这将连接到在本地主机上运行并监听端口`27017`上的连接的服务器。连接的数据库将是`mydb`。

+   `mongo.server.host/mydb`：这将连接到在`mongo.server.host`上运行并使用默认端口`27017`的服务器。连接的数据库将是`mydb`。

+   `mongo.server.host:27000/mydb`：这将连接到在`mongo.server.host`上运行并使用端口`27000`的服务器。连接的数据库将是`mydb`。

+   `mongo.server.host:27000`：这将连接到运行在`mongo.server.host`上的服务器，端口为`27000`。连接的数据库将是默认数据库 test。

现在，Mongo 客户端也有很多选项可用。我们将在下表中看到其中一些：

| 选项 | 描述 |
| --- | --- |
| `--help`或`-h` | 这显示有关各种命令行选项使用的帮助。 |
| `--shell` | 当给定`.js`文件作为参数时，这些脚本将被执行，mongo 客户端将退出。提供此选项可以确保在 JavaScript 文件执行后，shell 保持运行。在启动时，这些`.js`文件中定义的所有函数和变量都可在 shell 中使用。与前面的情况一样，JavaScript 文件中定义的`sayHello`函数可在 shell 中调用。 |
| `--port` | 指定客户端需要连接的 mongo 服务器的端口。 |
| `--host` | 这指定了客户端需要连接的 mongo 服务器的主机名。如果`db 地址`提供了主机名、端口和数据库，那么`--host`和`--port`选项都不需要指定。 |
| `--username`或`-u` | 当 Mongo 启用安全性时，这是相关的。它用于提供要登录的用户的用户名。 |
| `--password`或`-p` | 当 Mongo 启用安全性时，这个选项是相关的。它用于提供要登录的用户的密码。 |

# 使用 Java 客户端连接到单个节点

这个教程是关于为 MongoDB 设置 Java 客户端的。在处理其他教程时，您将反复参考这个教程，所以请仔细阅读。

## 准备工作

以下是这个教程的先决条件：

+   建议使用 Java SDK 1.6 或更高版本。

+   使用最新版本的 Maven。在撰写本书时，版本 3.3.3 是最新版本。

+   在撰写本书时，MongoDB Java 驱动程序版本 3.0.1 是最新版本。

+   连接到互联网以访问在线 maven 存储库或本地存储库。或者，您可以选择一个适合您的计算机访问的本地存储库。

+   Mongo 服务器正在本地主机和端口`27017`上运行。查看第一个教程，*安装单节点 MongoDB*，并启动服务器。

## 操作步骤如下：

1.  如果您的机器上还没有安装最新版本的 JDK，请从[`www.java.com/en/download/`](https://www.java.com/en/download/)下载。我们不会在这个教程中介绍安装 JDK 的步骤，但在进行下一步之前，JDK 应该已经安装好了。

1.  需要从[`maven.apache.org/download.cgi`](http://maven.apache.org/download.cgi)下载 Maven。在下载页面上应该看到类似以下图片的内容。选择`.tar.gz`或`.zip`格式的二进制文件并下载。这个教程是在运行 Windows 平台的机器上执行的，因此这些安装步骤是针对 Windows 的。![操作步骤如下：](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/4831_01_01.jpg)

1.  下载完档案后，我们需要解压它，并将提取的档案中的`bin`文件夹的绝对路径放入操作系统的路径变量中。Maven 还需要将 JDK 的路径设置为`JAVA_HOME`环境变量。记得将你的 JDK 根目录设置为这个变量的值。

1.  现在我们只需要在命令提示符上输入`mvn -version`，如果看到以下开头的输出，我们就成功设置了 maven：

```sql
> mvn -version

```

1.  在这个阶段，我们已经安装了 maven，现在准备创建我们的简单项目，在 Java 中编写我们的第一个 Mongo 客户端。我们首先创建一个`project`文件夹。假设我们创建一个名为`Mongo Java`的文件夹。然后在这个`project`文件夹中创建一个文件夹结构`src/main/java`。`project`文件夹的根目录包含一个名为`pom.xml`的文件。一旦这个文件夹创建完成，文件夹结构应该如下所示：

```sql
      Mongo Java      
      +--src  
      |     +main
      |         +java
      |--pom.xml
```

1.  我们现在只有项目的框架。我们将在`pom.xml`文件中添加一些内容。这并不需要太多。以下内容是我们在`pom.xml`文件中所需要的全部内容：

```sql
<project>
  <modelVersion>4.0.0</modelVersion>
  <name>Mongo Java</name>
  <groupId>com.packtpub</groupId>
  <artifactId>mongo-cookbook-java</artifactId>
  <version>1.0</version>    <packaging>jar</packaging>
  <dependencies>
    <dependency>
      <groupId>org.mongodb</groupId>
      <artifactId>mongo-java-driver</artifactId>
      <version>3.0.1</version>
    </dependency>
  </dependencies>
</project>
```

1.  最后，我们编写一个 Java 客户端，用于连接到 Mongo 服务器并执行一些非常基本的操作。以下是`com.packtpub.mongo.cookbook`包中`src/main/java`位置中的 Java 类，类名为`FirstMongoClient`：

```sql
package com.packtpub.mongo.cookbook;

import com.mongodb.BasicDBObject;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBObject;
import com.mongodb.MongoClient;

import java.net.UnknownHostException;
import java.util.List;

/**
 * Simple Mongo Java client
 *
 */
public class FirstMongoClient {

    /**
     * Main method for the First Mongo Client. Here we shall be connecting to a mongo
     * instance running on localhost and port 27017.
     *
     * @param args
     */
    public static final void main(String[] args) 
throws UnknownHostException {
        MongoClient client = new MongoClient("localhost", 27017);
        DB testDB = client.getDB("test");
        System.out.println("Dropping person collection in test database");
        DBCollection collection = testDB.getCollection("person");
        collection.drop();
        System.out.println("Adding a person document in the person collection of test database");
        DBObject person = 
new BasicDBObject("name", "Fred").append("age", 30);
        collection.insert(person);
        System.out.println("Now finding a person using findOne");
        person = collection.findOne();
        if(person != null) {
            System.out.printf("Person found, name is %s and age is %d\n", person.get("name"), person.get("age"));
        }
        List<String> databases = client.getDatabaseNames();
        System.out.println("Database names are");
        int i = 1;
        for(String database : databases) {
            System.out.println(i++ + ": " + database);
        }
  System.out.println("Closing client");
        client.close();
    }
}
```

1.  现在是执行前面的 Java 代码的时候了。我们将使用 maven 从 shell 中执行它。您应该在项目的`pom.xml`所在的同一目录中：

```sql
mvn compile exec:java -Dexec.mainClass=com.packtpub.mongo.cookbook.FirstMongoClient

```

## 它是如何工作的...

这些是相当多的步骤要遵循。让我们更详细地看一些步骤。直到第 6 步为止，都是直接的，不需要任何解释。让我们从第 7 步开始看起。

我们这里有的`pom.xml`文件非常简单。我们在 mongo 的 Java 驱动程序上定义了一个依赖关系。它依赖于在线存储库`repo.maven.apache.org`来解析这些构件。对于本地存储库，我们所需要做的就是在`pom.xml`中定义`repositories`和`pluginRepositories`标签。有关 maven 的更多信息，请参阅 maven 文档[`maven.apache.org/guides/index.html`](http://maven.apache.org/guides/index.html)。

对于 Java 类，`org.mongodb.MongoClient`类是主干。我们首先使用其重载的构造函数实例化它，给出服务器的主机和端口。在这种情况下，主机名和端口实际上并不是必需的，因为提供的值已经是默认值，而且无参数的构造函数也可以很好地工作。以下代码片段实例化了这个客户端：

```sql
MongoClient client = new MongoClient("localhost", 27017);
```

下一步是获取数据库，在这种情况下，使用`getDB`方法来测试。这将作为`com.mongodb.DB`类型的对象返回。请注意，这个数据库可能不存在，但`getDB`不会抛出任何异常。相反，只有在我们向该数据库的集合中添加新文档时，数据库才会被创建。同样，DB 对象上的`getCollection`将返回一个代表数据库中集合的`com.mongodb.DBCollection`类型的对象。这个集合在数据库中也可能不存在，并且在插入第一个文档时会自动创建。

我们的类中以下两个代码片段向您展示了如何获取`DB`和`DBCollection`的实例：

```sql
DB testDB = client.getDB("test");
DBCollection collection = testDB.getCollection("person");
```

在插入文档之前，我们将删除集合，以便即使在程序的多次执行中，person 集合中也只有一个文档。使用`DBCollection`对象的`drop()`方法来删除集合。接下来，我们创建一个`com.mongodb.DBObject`的实例。这是一个表示要插入到集合中的文档的对象。这里使用的具体类是`BasicDBObject`，它是`java.util.LinkedHashMap`类型，其中键是 String，值是 Object。值也可以是另一个`DBObject`，在这种情况下，它是嵌套在另一个文档中的文档。在我们的例子中，我们有两个键，name 和 age，它们是要插入的文档中的字段名，值分别是 String 和 Integer 类型。`BasicDBObject`的`append`方法将一个新的键值对添加到`BasicDBObject`实例中，并返回相同的实例，这使我们可以链接`append`方法调用以添加多个键值对。然后使用 insert 方法将创建的`DBObject`插入到集合中。这就是我们为 person 集合实例化`DBObject`并将其插入到集合中的方式：

```sql
DBObject person = new BasicDBObject("name", "Fred").append("age", 30);
collection.insert(person);
```

`DBCollection`上的`findOne`方法很简单，它从集合中返回一个文档。这个版本的`findOne`不接受`DBObject`（否则会在选择和返回文档之前执行的查询）作为参数。这相当于在 shell 中执行`db.person.findOne()`。

最后，我们只需调用`getDatabaseNames`来获取服务器中数据库名称的列表。此时，我们应该至少在返回的结果中有`test`和`local`数据库。完成所有操作后，我们关闭客户端。`MongoClient`类是线程安全的，通常一个应用程序使用一个实例。要执行该程序，我们使用 maven 的 exec 插件。在执行第 9 步时，我们应该在控制台的最后看到以下行：

```sql
[INFO] [exec:java {execution: default-cli}]
--snip--
Dropping person collection in test database
Adding a person document in the person collection of test database
Now finding a person using findOne
Person found, name is Fred and age is 30
Database names are
1: local
2: test
INFO: Closed connection [connectionId{localValue:2, serverValue:2}] to localhost:27017 because the pool has been closed.
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESSFUL
[INFO] ------------------------------------------------------------------------
[INFO] Total time: 3 seconds
[INFO] Finished at: Tue May 12 07:33:00 UTC 2015
[INFO] Final Memory: 22M/53M
[INFO] ------------------------------------------------------------------------ 

```

# 使用 Python 客户端连接到单个节点

在这个配方中，我们将使用 Python MongoDB 驱动程序 PyMongo 连接到单个 MongoDB 实例。使用 Python 的简单语法和多功能性与 MongoDB 结合在一起，许多程序员发现这个堆栈可以实现更快的原型设计和减少的开发周期。

## 准备工作

以下是此配方的先决条件：

+   Python 2.7.*x*（尽管该代码与 Python 3.*x*兼容）。

+   PyMongo 3.0.1：Python MongoDB 驱动程序。

+   Python 软件包安装程序（pip）。

+   Mongo 服务器正在 localhost 和端口`27017`上运行。查看第一个配方，*安装单节点 MongoDB*，并启动服务器。

## 如何做…

1.  根据您的操作系统，在 Ubuntu/Debian 系统上安装 pip 实用程序。您可以使用以下命令安装 pip：

```sql
> apt-get install python-pip

```

1.  使用 pip 安装最新的 PyMongo 驱动程序：

```sql
> pip install pymongo

```

1.  最后，创建一个名为`my_client.py`的新文件，并输入以下代码：

```sql
from __future__ import print_function
import pymongo

# Connect to server
client = pymongo.MongoClient('localhost', 27017)

# Select the database
testdb = client.test

# Drop collection
print('Dropping collection person')
testdb.person.drop()

# Add a person
print('Adding a person to collection person')
employee = dict(name='Fred', age=30)
testdb.person.insert(employee)

# Fetch the first entry from collection
person = testdb.person.find_one()
if person:
    print('Name: %s, Age: %s' % (person['name'], person['age']))

# Fetch list of all databases
print('DB\'s present on the system:')
for db in client.database_names():
    print('    %s' % db)

# Close connection
print('Closing client connection')
client.close()
```

1.  使用以下命令运行脚本：

```sql
> python my_client.py

```

## 它是如何工作的…

我们首先通过使用 pip 软件包管理器在系统上安装 Python MongoDB 驱动程序 pymongo。在给定的 Python 代码中，我们首先从`__future__`模块中导入`print_function`，以兼容 Python 3.*x*。接下来，我们导入 pymongo，以便在脚本中使用它。

我们使用 localhost 和`27017`作为 mongo 服务器主机和端口来实例化`pymongo.MongoClient()`。在 pymongo 中，我们可以直接使用`<client>.<database_name>.<collection_name>`的约定来引用数据库及其集合。

在我们的配方中，我们使用客户端处理程序通过引用`client.test`来选择数据库 test。即使数据库不存在，这也会返回一个数据库对象。作为这个配方的一部分，我们通过调用`testdb.person.drop()`来删除集合，其中`testdb`是对`client.test`的引用，`person`是我们希望删除的集合。对于这个配方，我们有意地删除集合，以便重复运行将始终在集合中产生一条记录。

接下来，我们实例化一个名为`employee`的字典，其中包含一些值，如姓名和年龄。现在，我们将使用`insert_one()`方法将此条目添加到我们的`person`集合中。

现在我们知道 person 集合中有一个条目，我们将使用`find_one()`方法获取一个文档。该方法根据磁盘上存储的文档的顺序返回集合中的第一个文档。

随后，我们还尝试通过调用`get_databases()`方法来获取所有数据库的列表到客户端。该方法返回服务器上存在的数据库名称列表。当您尝试断言服务器上是否存在数据库时，此方法可能会派上用场。

最后，我们使用`close()`方法关闭客户端连接。

# 作为副本集的一部分启动多个实例

在这个配方中，我们将看看在同一主机上启动多个服务器作为集群。启动单个 mongo 服务器足以用于开发目的或非关键应用。对于关键的生产部署，我们需要高可用性，如果一个服务器实例失败，另一个实例接管并且数据仍然可用于查询、插入或更新。集群是一个高级概念，我们无法在一个配方中涵盖整个概念。在这里，我们将浅尝辄止，并在本书后面的管理部分的其他配方中进行更详细的讨论。在这个配方中，我们将在同一台机器上启动多个 mongo 服务器进程，用于测试目的。在生产环境中，它们将在同一数据中心甚至不同数据中心的不同机器（或虚拟机）上运行。

让我们简要看一下什么是副本集。顾名思义，它是一组服务器，它们在数据方面彼此是副本。查看它们如何保持彼此同步以及其他内部情况是我们将推迟到管理部分的一些后续配方中，但要记住的一件事是，写操作只会发生在一个节点上，即主节点。默认情况下，所有查询也都是从主节点进行的，尽管我们可能会明确允许在次要实例上进行读操作。要记住的一个重要事实是，副本集并不是为了通过在副本集的各个节点之间分发读操作来实现可伸缩性。它的唯一目标是确保高可用性。

## 准备就绪

虽然不是必需条件，但查看*使用命令行选项启动单节点实例*的配方将会让事情变得更容易，以防您不了解在启动 mongo 服务器时各种命令行选项及其重要性。此外，在继续进行此配方之前，必须完成单服务器设置中提到的必要二进制文件和设置。让我们总结一下我们需要做什么。

我们将在本地主机上启动三个 mongod 进程（mongo 服务器实例）。

我们将为`Node1`、`Node2`和`Node3`分别创建三个数据目录`/data/n1`、`/data/n2`和`/data/n3`。同样，我们将把日志重定向到`/logs/n1.log`、`/logs/n2.log`和`/logs/n3.log`。以下图片将让您对集群的外观有一个概念：

![准备就绪](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/4831_01_02.jpg)

## 如何做…

让我们详细看一下步骤：

1.  为三个节点的数据和日志创建`/data/n1`、`/data/n2`、`/data/n3`和`/logs`目录。在 Windows 平台上，您可以选择`c:\data\n1`、`c:\data\n2`、`c:\data\n3`和`c:\logs\`目录，或者选择其他目录来分别存放数据和日志。确保这些目录对于 mongo 服务器来说具有适当的写权限。

1.  按照以下方式启动三个服务器。在 Windows 平台上，用户需要跳过`--fork`选项，因为它不受支持：

```sql
$ mongod --replSet repSetTest --dbpath /data/n1 --logpath /logs/n1.log --port 27000 --smallfiles --oplogSize 128 --fork
$ mongod --replSet repSetTest --dbpath /data/n2 --logpath /logs/n2.log --port 27001 --smallfiles --oplogSize 128 --fork
$ mongod --replSet repSetTest --dbpath /data/n3 --logpath /logs/n3.log --port 27002 --smallfiles --oplogSize 128 –fork

```

1.  启动 mongo shell 并连接到正在运行的任何 mongo 服务器。在这种情况下，我们连接到第一个（监听端口`27000`）。执行以下命令：

```sql
$ mongo localhost:27000

```

1.  连接到 mongo shell 后，尝试执行一个插入操作：

```sql
> db.person.insert({name:'Fred', age:35})

```

这个操作应该失败，因为副本集尚未初始化。更多信息可以在*它是如何工作的……*部分找到。

1.  下一步是开始配置副本集。我们首先在 shell 中准备一个 JSON 配置，如下所示：

```sql
cfg = {
  '_id':'repSetTest', 'members':[ {'_id':0, 'host': 'localhost:27000'}, {'_id':1, 'host': 'localhost:27001'}, {'_id':2, 'host': 'localhost:27002'} ]
}
```

1.  最后一步是使用上述配置初始化副本集。

```sql
> rs.initiate(cfg)

```

1.  在 shell 上几秒钟后执行`rs.status()`，查看状态。几秒钟后，其中一个应该成为主节点，其余两个应该成为次要节点。

## 它是如何工作的……

我们在*安装单节点 MongoDB*示例中描述了常见的选项，之前的命令行选项示例中也描述了所有这些命令行选项的详细信息。

由于我们启动了三个独立的 mongod 服务，因此在文件系统上有三个专用的数据库路径。同样，我们为每个进程有三个单独的日志文件位置。然后，我们使用指定的数据库和日志文件路径启动了三个 mongod 进程。由于这个设置是为了测试目的，并且在同一台机器上启动，我们使用了`--smallfiles`和`--oplogSize`选项。由于这些进程在同一主机上运行，我们还选择了显式端口，以避免端口冲突。我们选择的端口是`27000`、`27001`和`27002`。当我们在不同的主机上启动服务器时，我们可能会选择一个单独的端口，也可能不选择。在可能的情况下，我们可以选择使用默认端口。

`--fork`选项需要一些解释。通过选择此选项，我们可以从操作系统的 shell 中将服务器作为后台进程启动，并在 shell 中恢复控制，然后可以启动更多这样的 mongod 进程或执行其他操作。如果没有`--fork`选项，我们不能在一个 shell 中启动多个进程，需要在三个单独的 shell 中启动三个 mongod 进程。

如果我们查看日志目录中生成的日志，我们应该看到其中的以下行：

```sql
[rsStart] replSet can't get local.system.replset config from self or any seed (EMPTYCONFIG)
[rsStart] replSet info you may need to run replSetInitiate -- rs.initiate() in the shell -- if that is not already done

```

尽管我们使用`--replSet`选项启动了三个 mongod 进程，但我们仍然没有将它们配置为副本集。这个命令行选项只是用来告诉服务器在启动时，这个进程将作为副本集的一部分运行。副本集的名称与传递给命令提示符的选项的值相同。这也解释了为什么在初始化副本集之前，在一个节点上执行的插入操作失败了。在 mongo 副本集中，只能有一个主节点，所有的插入和查询都在这里进行。在显示的图像中，**N1**节点显示为主节点，并监听端口**27000**以进行客户端连接。所有其他节点都是从节点，它们与主节点同步，因此默认情况下也禁用了查询。只有在主节点宕机时，其中一个从节点才会接管并成为主节点。但是，可以查询从节点的数据，就像我们在图像中所示的那样；我们将在下一个示例中看到如何从从节点实例查询。

现在剩下的就是通过将我们启动的三个进程分组来配置副本集。首先定义一个 JSON 对象如下：

```sql
cfg = {
  '_id':'repSetTest', 'members':[ {'_id':0, 'host': 'localhost:27000'}, {'_id':1, 'host': 'localhost:27001'}, {'_id':2, 'host': 'localhost:27002'} ]
}
```

有两个字段，`_id`和`members`，分别用于副本集的唯一 ID 和该副本集中 mongod 服务器进程的主机名和端口号数组。在这种情况下，使用 localhost 来引用主机并不是一个很好的主意，通常是不鼓励的；然而，在这种情况下，因为我们在同一台机器上启动了所有进程，所以可以接受。最好是通过主机名来引用主机，即使它们在 localhost 上运行。请注意，您不能在同一配置中混合使用 localhost 和主机名来引用实例。要么是主机名，要么是 localhost。然后，我们连接到三个运行中的 mongod 进程中的任何一个来配置副本集；在这种情况下，我们连接到第一个，然后从 shell 中执行以下操作：

```sql
> rs.initiate(cfg)

```

传递的`cfg`对象中的`_id`字段的值与我们在启动服务器进程时给`--replSet`选项的值相同。如果不给出相同的值，将会抛出以下错误：

```sql
{
 "ok" : 0,
 "errmsg" : "couldn't initiate : set name does not match the set name host Amol-PC:27000 expects"
}

```

如果一切顺利，初始化调用成功，我们应该在 shell 上看到类似以下 JSON 响应：

```sql
{"ok" : 1}

```

几秒钟后，我们应该看到从我们执行此命令的 shell 的不同提示。它现在应该成为主服务器或辅助服务器。以下是连接到副本集的主成员的 shell 的示例：

```sql
repSetTest:PRIMARY>

```

执行`rs.status()`应该给我们一些关于副本集状态的统计信息，我们将在本书的管理部分的后面的教程中深入探讨。目前，`stateStr`字段很重要，包含`PRIMARY`、`SECONDARY`和其他文本。

## 还有更多…

查看*在 shell 中连接到副本集以查询和插入数据*教程，以在连接到副本集后从 shell 执行更多操作。复制并不像我们在这里看到的那么简单。请参阅管理部分，了解更多关于复制的高级教程。

## 另请参阅

如果您想要将独立实例转换为副本集，那么具有数据的实例首先需要成为主服务器，然后将空的辅助实例添加到其中，数据将被同步。请参考以下网址以了解如何执行此操作：

[`docs.mongodb.org/manual/tutorial/convert-standalone-to-replica-set/`](http://docs.mongodb.org/manual/tutorial/convert-standalone-to-replica-set/)

# 在 shell 中连接到副本集以查询和插入数据

在上一个教程中，我们启动了三个 mongod 进程的副本集。在本教程中，我们将通过使用 mongo 客户端应用程序连接到它，执行查询，插入数据，并从客户端的角度查看副本集的一些有趣方面。

## 准备工作

此教程的先决条件是副本集应该已经设置并运行。有关如何启动副本集的详细信息，请参考上一个教程，*作为副本集的一部分启动多个实例*。

## 如何做…

1.  我们将在这里启动两个 shell，一个用于`PRIMARY`，一个用于`SECONDARY`。在命令提示符上执行以下命令：

```sql
> mongo localhost:27000

```

1.  shell 的提示告诉我们我们连接的服务器是`PRIMARY`还是`SECONDARY`。它应该显示副本集的名称，后跟`:`，后跟服务器状态。在这种情况下，如果副本集已初始化，正在运行，我们应该看到`repSetTest:PRIMARY>`或`repSetTest:SECONDARY>`。

1.  假设我们连接到的第一个服务器是一个辅助服务器，我们需要找到主服务器。在 shell 中执行`rs.status()`命令，并查找`stateStr`字段。这应该给我们主服务器。使用 mongo shell 连接到此服务器。

1.  此时，我们应该有两个运行的 shell，一个连接到主服务器，另一个连接到辅助服务器。

1.  在连接到主节点的 shell 中，执行以下插入：

```sql
repSetTest:PRIMARY> db.replTest.insert({_id:1, value:'abc'})

```

1.  这没什么特别的。我们只是在一个我们将用于复制测试的集合中插入了一个小文档。

1.  通过在主服务器上执行以下查询，我们应该得到以下结果：

```sql
repSetTest:PRIMARY> db.replTest.findOne()
{ "_id" : 1, "value" : "abc" }

```

1.  到目前为止，一切顺利。现在，我们将转到连接到`SECONDARY`节点的 shell，并执行以下操作：

```sql
repSetTest:SECONDARY> db.replTest.findOne()

```

这样做后，我们应该在控制台上看到以下错误：

```sql
 { "$err" : "not master and slaveOk=false", "code" : 13435 }

```

1.  现在在控制台上执行以下操作：

```sql
repSetTest:SECONDARY>  rs.slaveOk(true)

```

1.  在 shell 上再次执行我们在步骤 7 中执行的查询。现在应该得到以下结果：

```sql
repSetTest:SECONDARY>db.replTest.findOne()
{ "_id" : 1, "value" : "abc" }

```

1.  在辅助节点上执行以下插入；它不应该成功，并显示以下消息：

```sql
repSetTest:SECONDARY> db.replTest.insert({_id:1, value:'abc'})
not master

```

## 它是如何工作的…

在这个教程中，我们做了很多事情，并且将尝试对一些重要的概念进行一些解释。

我们基本上从 shell 连接到主节点和从节点，并执行（我会说，尝试执行）选择和插入操作。Mongo 副本集的架构由一个主节点（只有一个，不多不少）和多个从节点组成。所有写操作只发生在`PRIMARY`上。请注意，复制不是一种分发读请求负载以实现系统扩展的机制。它的主要目的是确保数据的高可用性。默认情况下，我们不被允许从从节点读取数据。在第 6 步中，我们只是从主节点插入数据，然后执行查询以获取我们插入的文档。这很简单，与集群无关。只需注意我们是从主节点插入文档，然后再查询它。

在下一步中，我们执行相同的查询，但这次是从辅助的 shell 中执行。默认情况下，`SECONDARY`上未启用查询。由于要复制的数据量大、网络延迟或硬件容量等原因，可能会出现数据复制的小延迟，因此，在辅助上进行查询可能无法反映在主服务器上进行的最新插入或更新。但是，如果我们可以接受并且可以容忍数据复制中的轻微延迟，我们只需要通过执行一个命令`rs.slaveOk()`或`rs.slaveOk(true)`来显式地在`SECONDARY`节点上启用查询。完成此操作后，我们可以自由地在辅助节点上执行查询。

最后，我们尝试将数据插入到从节点的集合中。无论我们是否执行了`rs.slaveOk()`，在任何情况下都不允许这样做。当调用`rs.slaveOk()`时，它只允许从`SECONDARY`节点查询数据。所有写操作仍然必须发送到主节点，然后流向从节点。复制的内部将在管理部分的不同示例中进行介绍。

## 另请参阅

下一个示例，*连接到副本集以从 Java 客户端查询和插入数据*，是关于从 Java 客户端连接到副本集。

# 连接到副本集以从 Java 客户端查询和插入数据

在这个示例中，我们将演示如何从 Java 客户端连接到副本集，以及客户端如何在主节点失败时自动切换到副本集中的另一个节点。

## 准备工作

我们需要查看*使用 Java 客户端连接到单个节点*示例，因为它包含了设置 maven 和其他依赖项的所有先决条件和步骤。由于我们正在处理副本集的 Java 客户端，因此副本集必须处于运行状态。有关如何启动副本集的详细信息，请参阅*作为副本集的一部分启动多个实例*示例。

## 如何操作...

1.  编写/复制以下代码片段：（此 Java 类也可从 Packt 网站下载。）

```sql
package com.packtpub.mongo.cookbook;

import com.mongodb.BasicDBObject;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBObject;
import com.mongodb.MongoClient;
import com.mongodb.ServerAddress;

import java.util.Arrays;

/**
 *
 */
public class ReplicaSetMongoClient {

  /**
  * Main method for the test client connecting to the replica set.
   * @param args
  */
  public static final void main(String[] args) throws Exception {
    MongoClient client = new MongoClient(
      Arrays.asList(
        new ServerAddress("localhost", 27000), new ServerAddress("localhost", 27001), new ServerAddress("localhost", 27002)
      )
    );
    DB testDB = client.getDB("test");
    System.out.println("Dropping replTest collection");
    DBCollection collection = testDB.getCollection("replTest");
    collection.drop();
    DBObject object = new BasicDBObject("_id", 1).append("value", "abc");
    System.out.println("Adding a test document to replica set");
    collection.insert(object);
    System.out.println("Retrieving document from the collection, this one comes from primary node");
    DBObject doc = collection.findOne();
    showDocumentDetails(doc);
    System.out.println("Now Retrieving documents in a loop from the collection.");
    System.out.println("Stop the primary instance after few iterations ");
    for(int i = 0 ; i < 10; i++) {
      try {
        doc = collection.findOne();
        showDocumentDetails(doc);
      }
      catch (Exception e) {
        //Ignoring or log a message
      }
      Thread.sleep(5000);
    }
  }

  /**
  *
  * @param obj
  */
  private static void showDocumentDetails(DBObject obj) {
    System.out.printf("_id: %d, value is %s\n", obj.get("_id"), obj.get("value"));
  }
}
```

1.  连接到副本集中的任何节点，比如`localhost:27000`，并从 shell 中执行`rs.status()`。记录副本集中的主实例，并从 shell 连接到它，如果`localhost:27000`不是主实例。在这里，切换到管理员数据库如下：

```sql
repSetTest:PRIMARY>use admin

```

1.  现在我们从操作系统 shell 中执行前面的程序：

```sql
$ mvn compile exec:java -Dexec.mainClass=com.packtpub.mongo.cookbook.ReplicaSetMongoClient

```

1.  通过在连接到主实例的 mongo shell 上执行以下操作来关闭主实例：

```sql
repSetTest:PRIMARY> db.shutdownServer()

```

1.  观察在使用 maven 执行`com.packtpub.mongo.cookbook.ReplicaSetMongoClient`类时控制台上的输出。

## 它是如何工作的...

一个有趣的事情是观察我们如何实例化`MongoClient`实例。它是这样做的：

```sql
  MongoClient client = new MongoClient(Arrays.asList(new ServerAddress("localhost", 27000), new ServerAddress("localhost", 27001), new ServerAddress("localhost", 27002)));
```

构造函数接受一个`com.mongodb.ServerAddress`列表。这个类有很多重载的构造函数，但我们选择使用一个接受主机名和端口的构造函数。我们所做的是将副本集中的所有服务器详细信息提供为一个列表。我们没有提到什么是`PRIMARY`节点，什么是`SECONDARY`节点。`MongoClient`足够智能，可以弄清楚这一点，并连接到适当的实例。提供的服务器列表称为种子列表。它不一定要包含副本集中的所有服务器，尽管目标是尽可能提供尽可能多的服务器。`MongoClient`将从提供的子集中找出所有服务器的详细信息。例如，如果副本集有五个节点，但我们只提供了三个服务器，它也可以正常工作。连接到提供的副本集服务器后，客户端将查询它们以获取副本集元数据，并找出副本集中提供的其他服务器的其余部分。在前面的情况下，我们用三个实例实例化了客户端。如果副本集有五个成员，那么用其中的三个实例化客户端仍然是足够的，剩下的两个实例将被自动发现。

接下来，我们使用 maven 从命令提示符启动客户端。一旦客户端在循环中运行，我们关闭主实例以找到一个文档。我们应该在控制台上看到以下输出：

```sql
_id: 1, value is abc
Now Retrieving documents in a loop from the collection.
Stop the primary instance manually after few iterations
_id: 1, value is abc
_id: 1, value is abc
Nov 03, 2013 5:21:57 PM com.mongodb.ConnectionStatus$UpdatableNode update
WARNING: Server seen down: Amol-PC/192.168.1.171:27002
java.net.SocketException: Software caused connection abort: recv failed
 at java.net.SocketInputStream.socketRead0(Native Method)
 at java.net.SocketInputStream.read(SocketInputStream.java:150)
 …
WARNING: Primary switching from Amol-PC/192.168.1.171:27002 to Amol-PC/192.168.1.171:27001
_id: 1, value is abc

```

正如我们所看到的，在主节点宕机时，循环中的查询被中断。然而，客户端无缝地切换到了新的主节点。嗯，几乎是无缝的，因为客户端可能需要捕获异常，并在经过预定的时间间隔后重试操作。

# 使用 Python 客户端连接到副本集以查询和插入数据

在这个示例中，我们将演示如何使用 Python 客户端连接到副本集，以及客户端在主节点故障时如何自动切换到副本集中的另一个节点。

## 准备工作

请参考*使用 Python 客户端连接到单个节点*示例，因为它描述了如何设置和安装 PyMongo，MongoDB 的 Python 驱动程序。此外，副本集必须处于运行状态。请参考*作为副本集的一部分启动多个实例*示例，了解如何启动副本集的详细信息。

## 操作步骤…

1.  将以下代码写入/复制到`replicaset_client.py`中：（此脚本也可从 Packt 网站下载。）

```sql
from __future__ import print_function
import pymongo
import time

# Instantiate MongoClient with a list of server addresses
client = pymongo.MongoClient(['localhost:27002', 'localhost:27001', 'localhost:27000'], replicaSet='repSetTest')

# Select the collection and drop it before using
collection = client.test.repTest
collection.drop()

#insert a record in
collection.insert_one(dict(name='Foo', age='30'))

for x in range(5):
    try:
        print('Fetching record: %s' % collection.find_one())
    except Exception as e:
        print('Could not connect to primary')
    time.sleep(3)
```

1.  连接到副本集中的任何节点，比如`localhost:27000`，并从 shell 中执行`rs.status()`。记下副本集中的主实例，并从 shell 中连接到它，如果`localhost:27000`不是主节点。在这里，切换到管理员数据库如下：

```sql
> repSetTest:PRIMARY>use admin

```

1.  现在，我们从操作系统 shell 中执行上述脚本如下：

```sql
$ python replicaset_client.py

```

1.  通过在连接到主节点的 mongo shell 上执行以下操作关闭主实例：

```sql
> repSetTest:PRIMARY> db.shutdownServer()

```

1.  观察在执行 Python 脚本的控制台上的输出。

## 工作原理…

您会注意到，在这个脚本中，我们通过给出主机列表而不是单个主机来实例化 mongo 客户端。从版本 3.0 开始，pymongo 驱动程序的`MongoClient()`类在初始化时可以接受主机列表或单个主机，并弃用了`MongoReplicaSetClient()`。客户端将尝试连接列表中的第一个主机，如果成功，将能够确定副本集中的其他节点。我们还专门传递了`replicaSet='repSetTest'`参数，确保客户端检查连接的节点是否是这个副本集的一部分。

一旦连接，我们执行正常的数据库操作，比如选择测试数据库、删除`repTest`集合，并向集合中插入一个文档。

接下来，我们进入一个条件循环，循环五次。每次，我们获取记录，显示它，并休眠三秒。在脚本处于此循环时，我们关闭副本集中的主节点，如步骤 4 中所述。我们应该看到类似于以下的输出：

```sql
Fetching record: {u'age': u'30', u'_id': ObjectId('5558bfaa0640fd1923fce1a1'), u'name': u'Foo'}
Fetching record: {u'age': u'30', u'_id': ObjectId('5558bfaa0640fd1923fce1a1'), u'name': u'Foo'}
Fetching record: {u'age': u'30', u'_id': ObjectId('5558bfaa0640fd1923fce1a1'), u'name': u'Foo'}
Could not connect to primary
Fetching record: {u'age': u'30', u'_id': ObjectId('5558bfaa0640fd1923fce1a1'), u'name': u'Foo'}

```

在上述输出中，客户端在主节点中途断开连接。然而，很快，剩余节点选择了一个新的主节点，mongo 客户端能够恢复连接。

# 启动由两个分片组成的简单分片环境

在这个配方中，我们将建立一个由两个数据分片组成的简单分片设置。由于这是最基本的分片设置来演示概念，因此不会配置任何复制。我们不会深入研究分片的内部结构，这将在管理部分中更多地探讨。

在我们继续之前，这里有一点理论。可伸缩性和可用性是构建任何关键任务应用程序的两个重要基石。可用性是由我们在本章前面的配方中讨论的副本集来处理的。现在让我们来看看可伸缩性。简单地说，可伸缩性是系统应对不断增长的数据和请求负载的能力。考虑一个电子商务平台。在正常的日子里，对网站的点击次数和负载都相当适度，系统的响应时间和错误率都很低。（这是主观的。）现在，考虑系统负载变成平常日负载的两倍、三倍，甚至更多，比如感恩节、圣诞节等。如果平台能够在这些高负载日提供与任何其他日子相似的服务水平，系统就被认为已经很好地应对了请求数量的突然增加。

现在，考虑一个需要存储过去十年中击中特定网站的所有请求的详细信息的归档应用程序。对于击中网站的每个请求，我们在底层数据存储中创建一个新记录。假设每个记录的大小为 250 字节，平均每天有 300 万个请求，我们将在大约五年内超过 1 TB 的数据标记。这些数据将用于各种分析目的，并可能经常被查询。当数据量增加时，查询性能不应受到严重影响。如果系统能够应对不断增长的数据量，并且在数据量较低时仍能提供与低数据量时相当的性能，系统就被认为已经很好地扩展了。

现在我们简要地了解了可伸缩性是什么，让我告诉你，分片是一种机制，让系统能够满足不断增长的需求。关键在于整个数据被分成更小的段，并分布在称为分片的各个节点上。假设我们在 mongo 集合中有 1000 万个文档。如果我们将这个集合分片到 10 个分片上，那么理想情况下每个分片上将有*10,000,000/10 = 1,000,000*个文档。在任何给定的时间点，只有一个文档会驻留在一个分片上（这本身将是生产系统中的一个副本集）。然而，有一些魔法使这个概念隐藏在查询集合的开发人员之外，无论分片的数量如何，他们都会得到一个统一的集合视图。根据查询，mongo 决定查询哪个分片的数据并返回整个结果集。有了这个背景，让我们建立一个简单的分片并仔细研究它。

## 准备就绪

除了已经安装的 MongoDB 服务器，从软件角度来看，没有其他先决条件。我们将创建两个数据目录，一个用于每个分片。将有一个用于数据和一个用于日志的目录。

## 如何做到这一点...

1.  我们首先创建日志和数据的目录。创建以下目录，`/data/s1/db`，`/data/s2/db`和`/logs`。在 Windows 上，我们可以有`c:\data\s1\db`等等用于数据和日志目录。在分片环境中还有一个用于存储一些元数据的配置服务器。我们将使用`/data/con1/db`作为配置服务器的数据目录。

1.  启动以下 mongod 进程，一个用于两个分片中的每一个，一个用于配置数据库，一个用于 mongos 进程。对于 Windows 平台，跳过`--fork`参数，因为它不受支持。

```sql
$ mongod --shardsvr --dbpath  /data/s1/db --port 27000 --logpath /logs/s1.log --smallfiles --oplogSize 128 --fork
$ mongod --shardsvr --dbpath  /data/s2/db --port 27001 --logpath /logs/s2.log --smallfiles --oplogSize 128 --fork
$ mongod --configsvr --dbpath  /data/con1/db --port 25000 --logpath  /logs/config.log --fork
$ mongos --configdb localhost:25000 --logpath  /logs/mongos.log --fork

```

1.  从命令提示符中执行以下命令。这应该显示一个 mongos 提示，如下所示：

```sql
$ mongo
MongoDB shell version: 3.0.2
connecting to: test
mongos>

```

1.  最后，我们设置分片。从 mongos shell 中，执行以下两个命令：

```sql
mongos> sh.addShard("localhost:27000")
mongos> sh.addShard("localhost:27001")

```

1.  在每次添加分片时，我们应该收到一个 ok 回复。应该看到以下 JSON 消息，为每个添加的分片提供唯一 ID：

```sql
{ "shardAdded" : "shard0000", "ok" : 1 }

```

### 注意

我们在所有地方都使用 localhost 来引用本地运行的服务器。这不是一种推荐的方法，也是不鼓励的。更好的方法是使用主机名，即使它们是本地进程。

## 它是如何工作的…

让我们看看我们在这个过程中做了什么。我们为数据创建了三个目录（两个用于分片，一个用于配置数据库）和一个日志目录。我们也可以有一个 shell 脚本或批处理文件来创建这些目录。事实上，在大型生产部署中，手动设置分片不仅耗时，而且容易出错。

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中购买的所有 Packt 图书下载示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便将文件直接发送到您的邮箱。

让我们试着了解我们到底做了什么，以及我们试图实现什么。以下是我们刚刚设置的分片设置的图像：

![它是如何工作的…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/4831_01_03.jpg)

如果我们看一下前面的图像和第 2 步中启动的服务器，我们有分片服务器，它们将在集合中存储实际数据。这是我们启动的四个进程中的前两个，它们监听端口`27000`和`27001`。接下来，我们启动了一个配置服务器，在这个图像的左侧可以看到。这是第 2 步中启动的四个服务器中的第三个服务器，它监听端口`25000`以进行传入连接。这个数据库的唯一目的是维护有关分片服务器的元数据。理想情况下，只有 mongos 进程或驱动程序连接到此服务器以获取有关分片的详细信息/元数据和分片键信息。我们将在下一个示例中看到分片键是什么，我们将在其中操作一个分片集合并查看我们创建的分片的操作。

最后，我们有一个 mongos 进程。这是一个轻量级的进程，不做任何数据持久化，只接受来自客户端的连接。这是一个作为网关的层，将客户端与分片的概念抽象出来。现在，我们可以将其视为基本上是一个路由器，它会查询配置服务器并决定将客户端的查询路由到适当的分片服务器以执行。然后，如果适用，它会聚合来自各个分片的结果并将结果返回给客户端。可以肯定地说，没有客户端直接连接到配置或分片服务器；事实上，除了一些管理操作外，理想情况下没有人应该直接连接到这些进程。客户端只需连接到 mongos 进程并执行他们的查询和插入或更新操作。

仅仅启动碎片服务器、配置服务器和 mongos 进程并不能创建一个分片化的环境。在启动 mongos 进程时，我们提供了配置服务器的详细信息。那么存储实际数据的两个碎片怎么办？然而，作为碎片服务器启动的两个 mongod 进程尚未在配置中声明为碎片服务器。这正是我们在最后一步中通过为两个碎片服务器调用 `sh.addShard()` 来完成的。在启动时，mongos 进程提供了配置服务器的详细信息。从 shell 中添加碎片将存储关于碎片的元数据在配置数据库中，并且 mongos 进程随后将查询此配置数据库以获取碎片的信息。执行示例的所有步骤后，我们将得到一个操作中的碎片，如下所示：

![工作原理…](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-cb/img/4831_01_04.jpg)

在我们结束之前，我们在这里设置的碎片远非理想，也不是在生产环境中的操作方式。前面的图片给了我们一个关于生产环境中典型碎片的想法。碎片的数量不会是两个，而是更多。此外，每个碎片将是一个副本集，以确保高可用性。将有三个配置服务器来确保配置服务器的可用性。同样，将创建任意数量的用于监听客户端连接的碎片的 mongos 进程。在某些情况下，甚至可以在客户端应用程序的服务器上启动。

## 还有更多…

除非我们将碎片投入使用并从 shell 中插入和查询数据，否则碎片有何用处？在下一个示例中，我们将利用这里的碎片设置，添加一些数据，并查看其运行情况。

# 在 shell 中连接到一个碎片并执行操作

在这个示例中，我们将从命令提示符连接到一个碎片，看看如何为一个集合分片，并观察一些测试数据的分割情况。

## 准备就绪

显然，我们需要一个运行中的分片化 mongo 服务器设置。有关如何设置简单碎片的更多详细信息，请参阅上一个示例，*启动由两个碎片组成的简单分片环境*。mongos 进程，如上一个示例中所述，应该监听端口号 `27017`。我们在一个名为 `names.js` 的 JavaScript 文件中得到了一些名称。这个文件需要从 Packt 网站下载并保存在本地文件系统上。该文件包含一个名为 `names` 的变量，其值是一个包含一些 JSON 文档的数组，每个文档代表一个人。内容如下：

```sql
names = [
  {name:'James Smith', age:30},
  {name:'Robert Johnson', age:22},
…
]
```

## 操作步骤…

1.  启动 mongo shell 并连接到本地主机上的默认端口，如下所示。这将确保名称在当前 shell 中可用：

```sql
mongo --shell names.js
MongoDB shell version: 3.0.2
connecting to: test
mongos>

```

1.  切换到将用于测试分片的数据库；我们称之为 `shardDB`：

```sql
mongos> use shardDB

```

1.  在数据库级别启用分片如下：

```sql
mongos> sh.enableSharding("shardDB")

```

1.  如下所示为一个名为 `person` 的集合分片：

```sql
mongos>sh.shardCollection("shardDB.person", {name: "hashed"}, false)

```

1.  将测试数据添加到分片集合中：

```sql
mongos> for(i = 1; i <= 300000 ; i++) {
... person = names[Math.round(Math.random() * 100) % 20]
... doc = {_id:i, name:person.name, age:person.age}
... db.person.insert(doc)
}

```

1.  执行以下操作以获取查询计划和每个碎片上的文档数量：

```sql
mongos> db.person.getShardDistribution()

```

## 工作原理…

这个示例需要一些解释。我们下载了一个 JavaScript 文件，其中定义了一个包含 20 个人的数组。数组的每个元素都是一个具有 `name` 和 `age` 属性的 JSON 对象。我们启动 shell 连接到加载了这个 JavaScript 文件的 mongos 进程。然后切换到我们用于分片目的的 `shardDB`。

要使集合分片化，首先需要为将创建集合的数据库启用分片。我们使用 `sh.enableSharding()` 来实现这一点。

下一步是启用集合进行分片。默认情况下，所有数据将保存在一个分片上，而不会分散在不同的分片上。想想看；Mongo 如何能够有意义地分割数据？整个意图是有意义地分割数据，并尽可能均匀地分割，以便每当我们基于分片键进行查询时，Mongo 都能轻松地确定要查询哪个分片。如果查询不包含分片键，查询将在所有分片上执行，然后数据将由 mongos 进程汇总后返回给客户端。因此，选择正确的分片键非常关键。

现在让我们看看如何对集合进行分片。我们通过调用`sh.shardCollection("shardDB.person", {name: "hashed"}, false)`来实现这一点。这里有三个参数：

+   `shardCollection`方法的第一个参数是`<db name>.<collection name>`格式的集合的完全限定名称。

+   第二个参数是集合中用于分片的字段名称。这是用于在分片上拆分文档的字段。一个好的分片键的要求之一是它应该具有很高的基数（可能值的数量应该很高）。在我们的测试数据中，名称值的基数非常低，因此不是一个好的分片键选择。当使用此作为分片键时，我们对此键进行哈希。我们通过将键标记为`{name: "hashed"}`来实现这一点。

+   最后一个参数指定用作分片键的值是否是唯一的。名称字段肯定不是唯一的，因此它将是 false。如果该字段是，比如说，人的社会安全号码，它可以被设置为 true。此外，社会安全号码是一个很好的分片键选择，因为它的基数很高。请记住，分片键必须存在才能使查询有效。

最后一步是查看查找所有数据的执行计划。此操作的目的是查看数据如何分布在两个分片上。对于 30 万个文档，我们期望每个分片大约有 15 万个文档。然而，从分布统计数据中，我们可以观察到`shard0000`有`1,49,715`个文档，而`shard0001`有`150285`个文档：

```sql
Shard shard0000 at localhost:27000
 data : 15.99MiB docs : 149715 chunks : 2
 estimated data per chunk : 7.99MiB
 estimated docs per chunk : 74857

Shard shard0001 at localhost:27001
 data : 16.05MiB docs : 150285 chunks : 2
 estimated data per chunk : 8.02MiB
 estimated docs per chunk : 75142

Totals
 data : 32.04MiB docs : 300000 chunks : 4
 Shard shard0000 contains 49.9% data, 49.9% docs in cluster, avg obj size on shard : 112B
 Shard shard0001 contains 50.09% data, 50.09% docs in cluster, avg obj size on shard : 112B

```

我建议您做一些额外的建议。

从 mongo shell 连接到各个分片，并在 person 集合上执行查询。查看这些集合中的计数是否与前面的计划中看到的相似。此外，可以发现没有文档同时存在于两个分片上。

我们简要讨论了基数如何影响数据在分片上的分布方式。让我们做一个简单的练习。我们首先删除 person 集合，然后再次执行 shardCollection 操作，但这次使用`{name: 1}`分片键，而不是`{name: "hashed"}`。这确保分片键不被哈希并按原样存储。现在，使用我们在第 5 步中使用的 JavaScript 函数加载数据，然后在数据加载后对集合执行`explain()`命令。观察数据如何在分片上分割（或不分割）。

## 还有更多...

现在一定会有很多问题涌现出来，比如什么是最佳实践？有什么技巧和窍门？MongoDB 在幕后是如何实现分片的，以使其对最终用户透明呢？

这里的配方只解释了基础知识。在管理部分，所有这些问题都将得到解答。


# 第二章：命令行操作和索引

在本章中，我们将涵盖以下主题：

+   创建测试数据

+   从 Mongo shell 执行简单的查询、投影和分页

+   从 shell 中更新和删除数据

+   创建索引并查看查询计划

+   在 shell 中创建背景和前景索引

+   创建和理解稀疏索引

+   使用 TTL 索引在固定间隔后过期文档

+   使用 TTL 索引在给定时间过期文档

# 介绍

在本章中，我们将使用 mongo shell 执行简单的查询。在本章后面，我们将详细了解常用的 MongoDB 索引。

# 创建测试数据

这个配方是为本章的一些配方以及本书后面的章节创建测试数据。我们将演示如何使用 mongo 导入实用程序将 CSV 文件加载到 mongo 数据库中。这是一个基本的配方，如果读者了解数据导入实用程序，他们可以直接从 Packt 网站下载 CSV 文件(`pincodes.csv`)，自己将其加载到集合中，并跳过其余的配方。我们将使用默认数据库`test`，集合将被命名为`postalCodes`。

## 准备工作

这里使用的数据是印度的邮政编码。从 Packt 网站下载`pincodes.csv`文件。该文件是一个包含 39,732 条记录的 CSV 文件；成功导入后应该创建 39,732 个文档。我们需要让 Mongo 服务器处于运行状态。参考第一章中的*安装单节点 MongoDB*配方，了解如何启动服务器的说明。服务器应该开始监听默认端口`27017`上的连接。

## 如何做…

1.  从 shell 中使用以下命令执行要导入的文件：

```sql
$ mongoimport --type csv -d test -c postalCodes --headerline --drop pincodes.csv

```

1.  通过在命令提示符上输入`mongo`来启动 mongo shell。

1.  在 shell 中，执行以下命令：

```sql
> db.postalCodes.count()

```

## 它是如何工作的…

假设服务器正在运行，CSV 文件已经下载并保存在本地目录中，我们在其中执行导入实用程序。让我们看看`mongoimport`实用程序中给出的选项及其含义：

| 命令行选项 | 描述 |
| --- | --- |
| `--type` | 这指定输入文件的类型为 CSV。它默认为 JSON；另一个可能的值是 TSV。 |
| `-d` | 这是要加载数据的目标数据库。 |
| `-c` | 这是前面提到的数据库中要加载数据的集合。 |
| `--headerline` | 这只在 TSV 或 CSV 文件的情况下相关。它指示文件的第一行是标题。相同的名称将用作文档中字段的名称。 |
| `--drop` | 在导入数据之前删除集合。 |

在给出所有选项后，命令提示符上的最终值是文件名`pincodes.csv`。

如果导入成功，您应该在控制台上看到类似以下内容的输出：

```sql
2015-05-19T06:51:54.131+0000	connected to: localhost
2015-05-19T06:51:54.132+0000	dropping: test.postalCodes
2015-05-19T06:51:54.810+0000	imported 39732 documents

```

最后，我们启动 mongo shell 并查找集合中文档的计数；正如在前面的导入日志中所看到的，它应该确实是 39,732。

### 注意

邮政编码数据来自[`github.com/kishorek/India-Codes/`](https://github.com/kishorek/India-Codes/)。这些数据不是来自官方来源，可能不准确，因为它是手动编译的，供公众免费使用。

## 另请参阅

*在 Mongo shell 中执行简单的查询、投影和分页*配方是关于在导入的数据上执行一些基本查询。

# 从 Mongo shell 执行简单的查询、投影和分页

在这个配方中，我们将通过一些查询来选择我们在前一个配方*创建测试数据*中设置的测试数据中的文档。在这个配方中没有什么奢侈的东西，熟悉查询语言基础知识的人可以跳过这个配方。其他不太熟悉基本查询或想要进行小小复习的人可以继续阅读配方的下一部分。此外，这个配方旨在让您感受到前一个配方中设置的测试数据。

## 准备工作

要执行简单的查询，我们需要有一个正在运行的服务器。一个简单的单节点就是我们需要的。请参考第一章中的*安装单节点 MongoDB*配方，了解如何启动服务器的说明。我们将要操作的数据需要导入到数据库中。导入数据的步骤在前一个配方*创建测试数据*中给出。您还需要启动 mongo shell 并连接到在本地主机上运行的服务器。一旦这些先决条件完成，我们就可以开始了。

## 如何做…

1.  让我们首先找到集合中文档的数量：

```sql
> db.postalCodes.count()

```

1.  让我们从`postalCodes`集合中找到一个文档：

```sql
> db.postalCodes.findOne()

```

1.  现在，我们按如下方式在集合中找到多个文档：

```sql
> db.postalCodes.find().pretty()

```

1.  前面的查询检索了前 20 个文档的所有键，并在 shell 上显示它们。在结果的末尾，您会注意到一行，上面写着`键入"it"以获取更多内容`。通过键入`"it"`，mongo shell 将遍历结果游标。现在让我们做一些事情；我们将只显示`city`、`state`和`pincode`字段。此外，我们想显示集合中编号为 91 到 100 的文档。让我们看看如何做到这一点：

```sql
> db.postalCodes.find({}, {_id:0, city:1, state:1, pincode:1}).skip(90).limit(10)

```

1.  让我们再进一步，编写一个稍微复杂的查询，在其中按照城市名称找到古吉拉特邦的前 10 个城市，并且与上一个查询类似，我们只选择`city`、`state`和`pincode`字段：

```sql
> db.postalCodes.find({state:'Gujarat'},{_id:0, city:1, state:1, pincode:1}).sort({city:1}).limit(10)

```

## 工作原理…

这个配方非常简单，让我们感受到了我们在前一个配方中设置的测试数据。尽管如此，和其他配方一样，我确实需要向大家解释一下我们在这里做了什么。

我们首先使用`db.postalCodes.count()`找到了集合中文档的数量，应该有 39,732 个文档。这应该与我们在导入邮政编码集合数据时看到的日志保持一致。接下来，我们使用`findOne`从集合中查询一个文档。这个方法返回查询结果集中的第一个文档。在没有查询或排序顺序的情况下，就像在这种情况下一样，它将是按其自然顺序排序的集合中的第一个文档。

接下来，我们执行`find`而不是`findOne`。它们之间的区别在于`find`操作返回结果集的迭代器，我们可以使用它来遍历`find`操作的结果，而`findOne`返回一个文档。对`find`操作添加一个 pretty 方法调用将以漂亮或格式化的方式打印结果。

### 提示

请注意，`pretty`方法只对`find`有效，而对`findOne`无效。这是因为`findOne`的返回值是一个文档，而返回的文档上没有`pretty`操作。

现在我们将在 mongo shell 上执行以下查询：

```sql
> db.postalCodes.find({}, {_id:0, city:1, state:1, pincode:1}).skip(90).limit(10) 

```

在这里，我们向`find`方法传递了两个参数：

+   第一个是`{}`，这是选择文档的查询，在这种情况下，我们要求 mongo 选择所有文档。

+   第二个参数是我们想要在结果文档中的字段集，也被称为**投影**。请记住，`_id`字段默认存在，除非我们明确指定`_id:0`。对于所有其他字段，我们需要说`<field_name>:1`或`<field_name>:true`。具有投影的查找部分与在关系世界中说`select field1``, field2 from table`是一样的，而不指定要选择的字段在查找中说`select * from table`在关系世界中。

接下来，我们只需要看一下`skip`和`limit`的作用：

+   `skip`函数从结果集中跳过给定数量的文档，直到最后一个文档

+   `limit`函数然后将结果限制为给定数量的文档

让我们通过一个例子来看看这意味着什么。通过执行.`skip(90).limit(10)`，我们说我们要跳过结果集中的前 90 个文档，并从第 91 个文档开始返回。然而，limit 表示我们将只从第 91 个文档返回 10 个文档。

现在，这里有一些边界条件，我们需要知道。如果 skip 提供的值大于集合中的文档总数会怎么样？在这种情况下，将不会返回任何文档。此外，如果提供给 limit 函数的数字大于集合中剩余的实际文档数量，则返回的文档数量将与集合中剩余的文档数量相同，并且在任一情况下都不会抛出异常。

# 从 shell 更新和删除数据

这将是一个简单的示例，将在测试集合上执行删除和更新。我们不会处理导入的相同测试数据，因为我们不想更新/删除任何数据，而是我们将在仅为此示例创建的测试集合上工作。

## 准备工作

对于此示例，我们将创建一个名为`updAndDelTest`的集合。我们需要服务器运行。有关如何启动服务器的说明，请参阅第一章中的*安装单节点 MongoDB*示例，*安装和启动服务器*。使用加载了`UpdAndDelTest.js`脚本的 shell 启动。此脚本可在 Packt 网站上下载。要了解如何使用预加载的脚本启动 shell，请参阅第一章中的*使用 JavaScript 连接 Mongo shell 中的单个节点*示例，*安装和启动服务器*。

## 操作步骤…

1.  启动 MongoDB shell 并预加载脚本：

```sql
$ mongo --shell updAndDelTest.js

```

1.  使用启动的 shell 和加载的脚本，在 shell 中执行以下操作：

```sql
> prepareTestData()

```

1.  如果一切顺利，您应该在控制台上看到`在 updAndDelTest 中插入了 20 个文档`的打印：

1.  为了了解集合的情况，让我们查询如下：

```sql
> db.updAndDelTest.find({}, {_id:0})

```

1.  我们应该看到对于`x`的每个值为`1`和`2`，我们有`y`从 1 到 10 递增的值。

1.  我们将首先更新一些文档并观察结果。执行以下更新：

```sql
> db.updAndDelTest.update({x:1}, {$set:{y:0}})

```

1.  执行以下`find`命令并观察结果；我们应该得到 10 个文档。对于每个文档，注意`y`的值。

```sql
> db.updAndDelTest.find({x:1}, {_id:0})

```

1.  我们现在将执行以下更新：

```sql
> db.updAndDelTest.update({x:1}, {$set:{y:0}}, {multi:true})

```

1.  再次执行步骤 6 中给出的查询以查看更新后的文档。它将显示我们之前看到的相同文档。再次注意`y`的值，并将其与我们上次执行此查询之前执行步骤 7 中给出的更新时看到的结果进行比较。

1.  我们现在将看看删除是如何工作的。我们将再次选择`x`为`1`的文档进行删除测试。让我们从集合中删除所有`x`为`1`的文档：

```sql
> db.updAndDelTest.remove({x:1})

```

1.  执行以下`find`命令并观察结果。我们将不会得到任何结果。似乎`remove`操作已删除所有`x`为`1`的文档。

```sql
> db.updAndDelTest.find({x:1}, {_id:0})

```

### 注意

当您在 mongo shell 中，并且想要查看函数的源代码时，只需输入函数名称而不带括号。例如，在这个示例中，我们可以通过输入函数名称`prepareTestData`（不带括号）来查看我们自定义函数的代码，并按下*Enter*键。

## 它是如何工作的...

首先，我们设置将用于更新和删除`test`的数据。我们已经看到了数据并知道它是什么。一个有趣的观察是，当我们执行更新操作，比如`db.updAndDelTest.update({x:1}, {$set:{y:0}})`，它只会更新与作为第一个参数提供的查询匹配的第一个文档。这是我们在此更新后查询集合时将观察到的事情。更新函数的格式如下：`db.<collection name>.update(query, update object, {upsert: <boolean>, multi:<boolean>})`。

我们将在后面的示例中看到 upsert 是什么。multi 参数默认设置为`false`。这意味着`update`方法不会更新多个文档；只有第一个匹配的文档会被更新。然而，当我们使用`db.updAndDelTest.update({x:1}, {$set:{y:0}}, {multi:true})`并将 multi 设置为`true`时，集合中匹配给定查询的所有文档都会被更新。这是我们在查询集合后可以验证的事情。

另一方面，删除的行为不同。默认情况下，`remove`操作会删除所有与提供的查询匹配的文档。然而，如果我们只想删除一个文档，我们可以将第二个参数明确传递为`true`。

### 注意

更新和删除的默认行为是不同的。默认情况下，`update`调用只会更新*第一个*匹配的文档，而`remove`会删除与查询匹配的*所有*文档。

# 创建索引并查看查询计划

在这个示例中，我们将查看如何查询数据，通过解释查询计划来分析其性能，然后通过创建索引来优化它。

## 准备工作

对于索引的创建，我们需要运行一个服务器。一个简单的单节点就是我们需要的。请参考第一章中的*安装单节点 MongoDB*示例，了解如何启动服务器的说明。我们将要操作的数据需要导入到数据库中。导入数据的步骤在前一个示例*创建测试数据*中给出。一旦这个先决条件完成，我们就可以开始了。

## 如何做...

我们正在尝试编写一个查询，该查询将找到给定州中的所有邮政编码。

1.  执行以下查询以查看此查询的计划：

```sql
> db.postalCodes.find({state:'Maharashtra'}).explain('executionStats')

```

在解释计划操作的结果中，注意以下字段：`stage`、`nReturned`、`totalDocsExamined`、`docsExamined`和`executionTimeMillis`。

1.  让我们再次执行相同的查询，但这次，我们将结果限制为仅 100 个结果：

```sql
> db.postalCodes.find({state:'Maharashtra'}).limit(100).explain()

```

1.  在结果中注意以下字段：`nReturned`、`totalDocsExamined`、`docsExamined`和`executionTimeMillis`。

1.  我们现在在`state`和`pincode`字段上创建索引，如下所示：

```sql
> db.postalCodes.createIndex({state:1, pincode:1})

```

1.  执行以下查询：

```sql
> db.postalCodes.find({state:'Maharashtra'}).explain()

```

注意以下字段：`stage`、`nReturned`、`totalDocsExamined`、`docsExamined`和`executionTimeMillis`。

1.  因为我们只想要邮政编码，所以我们修改查询如下并查看其计划：

```sql
> db.postalCodes.find({state:'Maharashtra'}, {pincode:1, _id:0}).explain()

```

在结果中注意以下字段：`stage`、`nReturned`、`totalDocsExamined`、`docsExamined`和`executionTimeMillis`。

## 它是如何工作的...

这里有很多要解释的地方。我们将首先讨论我们刚刚做的事情以及如何分析统计数据。接下来，我们将讨论索引创建时需要注意的一些要点和一些注意事项。

### 分析计划

好的，让我们看看我们执行的第一步并分析输出：

```sql
db.postalCodes.find({state:'Maharashtra'}).explain()

```

在我的机器上的输出如下：（我现在跳过了不相关的字段。）

```sql
{
        "stage" : "COLLSCAN",
...
        "nReturned" : 6446,
        "totalDocsExamined " : 39732, 
          …
    "docsExamined" : 39732, 
          …

        "executionTimeMillis" : 12,
…        
}
```

结果中`stage`字段的值为`COLLSCAN`，这意味着为了在整个集合中搜索匹配的文档，进行了完整的集合扫描（所有文档一个接一个地扫描）。`nReturned`的值为`6446`，这是与查询匹配的结果数量。`totalDocsExamined`和`docsExamined`字段的值为`39,732`，这是扫描集合以检索结果的文档数量。这也是集合中存在的文档总数，所有文档都被扫描以获取结果。最后，`executionTimeMillis`是检索结果所用的毫秒数。

### 提高查询执行时间

到目前为止，就性能而言，查询看起来并不太好，有很大的改进空间。为了演示应用于查询的限制如何影响查询计划，我们可以再次找到没有索引但有限制子句的查询计划，如下所示：

```sql
> db.postalCodes.find({state:'Maharashtra'}).limit(100).explain()

{
 "stage" : "COLLSCAN",…
 "nReturned" : 100,
 "totalDocsExamined" : 19951,

 …
 "docsExamined" : 19951,
 …
 "executionTimeMillis" : 8,
 …
}

```

这次的查询计划很有趣。虽然我们仍然没有创建索引，但我们确实看到了查询执行所需的时间和检索结果所需的对象数量有所改善。这是因为一旦达到了`limit`函数中指定的文档数量，mongo 就会忽略剩余文档的扫描。因此，我们可以得出结论，建议您使用`limit`函数来限制结果的数量，其中已知要访问的文档数量是有限的。这可能会提高查询性能。`可能`这个词很重要，因为在没有索引的情况下，如果匹配的文档数量不足，集合仍然可能被完全扫描。

### 使用索引进行改进

接着，我们在 state 和 pincode 字段上创建了一个复合索引。在这种情况下，索引的顺序是升序（因为值为 1），除非我们计划执行多键排序，否则这并不重要。这是一个决定性因素，决定了结果是否可以仅使用索引进行排序，还是 mongo 需要在返回结果之前在内存中对其进行排序。就查询计划而言，我们可以看到有了显著的改进：

```sql
{
"executionStages" : {
 "stage" : "FETCH",
…
"inputStage" : {
 "stage" : "IXSCAN",
…
 "nReturned" : 6446,
 "totalDocsExamined" : 6446,
 "docsExamined" : 6446,
 …
 "executionTimeMillis" : 4,
…
}

```

`inputStage`字段现在具有`IXSCAN`值，这表明现在确实使用了索引。结果的数量保持不变，仍为`6446`。在索引中扫描的对象数量和集合中扫描的文档数量现在已经减少到与结果中的文档数量相同。这是因为我们现在使用了一个索引，它给出了我们要扫描的起始文档，然后只扫描所需数量的文档。这类似于使用书的索引查找单词或扫描整本书以搜索单词。如预期的那样，`executionTimeMillis`中的时间也减少了。

### 使用覆盖索引进行改进

这留下了一个字段，`executionStages`，它是`FETCH`，我们将看看这意味着什么。要了解这个值是什么，我们需要简要了解索引是如何操作的。

索引存储了集合中原始文档的字段子集。索引中存在的字段与创建索引的字段相同。然而，这些字段按照在索引创建期间指定的顺序在索引中保持排序。除了字段之外，索引中还存储了一个额外的值，作为指向集合中原始文档的指针。因此，每当用户执行查询时，如果查询包含索引存在的字段，就会查询索引以获取一组匹配项。然后，与查询匹配的索引条目一起存储的指针被用于进行另一个 IO 操作，以从集合中获取完整的文档，然后返回给用户。

`executionStages`的值为`FETCH`，表示用户在查询中请求的数据并不完全存在于索引中，而是需要进行额外的 IO 操作，从索引指向的集合中检索整个文档。如果值本身存在于索引中，则不需要额外的操作来从集合中检索文档，而是会返回索引中的数据。这称为覆盖索引，在这种情况下，`executionStages`的值将是`IXSCAN`。

在我们的情况下，我们只需要邮政编码。那么，为什么不在我们的查询中使用投影来检索我们需要的内容呢？这也会使索引成为覆盖索引，因为索引条目只包含州名和邮政编码，所需的数据可以完全提供，而无需从集合中检索原始文档。在这种情况下，查询的计划也很有趣。

执行以下命令：

```sql
db.postalCodes.find({state:'Maharashtra'}, {pincode:1, _id:0}).explain()

```

这给我们带来了以下计划：

```sql
{
"executionStages" : {
 "stage" : "PROJECTION",
…
"inputStage" : {
 "stage" : "IXSCAN",
…
 "nReturned" : 6446,
 "totalDocsExamined" : 0,
 "totalKeysExamined": 6446
 "executionTimeMillis" : 4,
…
}

```

观察`totalDocsExamined`和`executionStage: PROJECTION`字段的值。如预期的那样，我们在投影中请求的数据可以仅从索引中提供。在这种情况下，我们扫描了索引中的 6446 个条目，因此`totalKeysExamined`的值为`6446`。

由于整个结果都是从索引中获取的，我们的查询没有从集合中获取任何文档。因此，`totalDocsExamined`的值为`0`。

由于这个集合很小，我们没有看到查询执行时间的显着差异。这在更大的集合上将更加明显。使用索引是很好的，可以给我们良好的性能。使用覆盖索引可以给我们更好的性能。

### 注意

MongoDB 版本 3.0 的解释结果功能进行了重大改进。我建议花几分钟阅读其文档：[`docs.mongodb.org/manual/reference/explain-results/`](http://docs.mongodb.org/manual/reference/explain-results/)。

还要记住的一件事是，如果您的文档有很多字段，请尝试使用投影仅检索我们需要的字段数量。默认情况下，`_id`字段会被检索。除非我们打算使用它，否则将`_id:0`设置为不检索它，如果它不是索引的一部分。执行覆盖查询是查询集合的最有效方式。

### 索引创建的一些注意事项

现在我们将看到索引创建中的一些陷阱以及在索引中使用数组字段时的一些事实。

一些不高效使用索引的运算符是`$where`，`$nin`和`$exists`运算符。每当在查询中使用这些运算符时，应该牢记，当数据量增加时可能会出现性能瓶颈。

同样，`$in`运算符必须优先于`$or`运算符，因为两者都可以用来实现或多或少相同的结果。作为练习，尝试在`postalCodes`集合中找到马哈拉施特拉邦和古吉拉特邦的邮政编码。编写两个查询：一个使用`$or`，一个使用`$in`运算符。解释这两个查询的计划。

当数组字段用于索引时会发生什么？

Mongo 为文档的数组字段中的每个元素创建一个索引条目。因此，如果文档的数组中有 10 个元素，将会有 10 个索引条目，每个数组中的元素都有一个。然而，在创建包含数组字段的索引时有一个约束。在使用多个字段创建索引时，不能有超过一个字段是数组类型，这是为了防止在数组中添加一个元素时可能导致索引数量激增。如果我们仔细考虑一下，我们会发现每个数组元素都会创建一个索引条目。如果允许多个数组字段成为索引的一部分，那么索引中的条目数量将会很大，这将是这些数组字段长度的乘积。例如，如果一个文档添加了两个长度为 10 的数组字段，如果允许使用这两个数组字段创建一个索引，将会向索引中添加 100 个条目。

这应该足够了，现在，来初步了解一个简单的、普通的索引。在接下来的几个配方中，我们将看到更多的选项和类型。

# 在 shell 中创建后台和前台索引

在我们之前的配方中，我们看到了如何分析查询，如何决定需要创建什么索引，以及如何创建索引。这本身是直接的，看起来相当简单。然而，对于大型集合，随着索引创建时间的增加，情况开始变得更糟。这个配方的目标是为这些概念扔一些光，避免在创建索引时遇到这些陷阱，特别是在大型集合上。

## 准备工作

为了创建索引，我们需要一个正在运行的服务器。一个简单的单节点就是我们需要的。请参考第一章中的*安装单节点 MongoDB*配方，了解如何启动服务器的说明。

通过在操作系统 shell 中键入`mongo`来连接两个 shell 到服务器。它们都将默认连接到`test`数据库。

我们的邮政编码测试数据太小，无法展示在大型集合上创建索引时遇到的问题。我们需要更多的数据，因此，我们将开始创建一些数据来模拟在创建索引过程中遇到的问题。这些数据没有实际意义，但足够测试概念。在其中一个已启动的 shell 中复制以下内容并执行：（这是一个相当容易输入的片段。）

```sql
for(i = 0; i < 5000000 ; i++) {
  doc = {}
  doc._id = i
  doc.value = 'Some text with no meaning and number ' + i + ' in between'
  db.indexTest.insert(doc)
}
```

这个集合中的文档看起来是这样的：

```sql
{ _id:0, value:"Some text with no meaning and number 0 in between" }
```

执行将需要相当长的时间，所以我们需要耐心等待。一旦执行完成，我们就可以开始操作了。

### 注意

如果你想知道集合中当前加载的文档数量，可以定期从第二个 shell 中评估以下内容：

```sql
db.indexTest.count()
```

## 如何做…

1.  在文档的`value`字段上创建索引，如下所示：

```sql
> db.indexTest.createIndex({value:1})

```

1.  在索引创建过程中，这应该需要相当长的时间，切换到第二个控制台并执行以下操作：

```sql
> db.indexTest.findOne()

```

1.  索引创建 shell 和我们执行`findOne`的 shell 都将被阻塞，直到索引创建完成，两者都不会显示提示。

1.  现在，这是默认的前台索引创建。我们想看看后台索引创建的行为。按照以下方式删除已创建的索引：

```sql
> db.indexTest.dropIndex({value:1})

```

1.  再次创建索引，但这次是在后台进行，如下所示：

```sql
> db.indexTest.createIndex({value:1}, {background:true})

```

1.  在第二个 mongo shell 中，执行以下`findOne`：

```sql
> db.indexTest.findOne()

```

1.  这应该返回一个文档，这与第一个实例不同，那里的操作会一直被阻塞，直到前台的索引创建完成。

1.  在第二个 shell 中，反复执行以下解释操作，每次解释计划调用之间间隔四到五秒，直到索引创建过程完成：

```sql
> db.indexTest.find({value:"Some text with no meaning and number 0 in between"}).explain()

```

## 它是如何工作的…

让我们现在分析一下我们刚刚做的事情。我们创建了大约五百万个没有实际重要性的文档，但我们只是想获取一些数据，这将花费大量时间来构建索引。

索引可以通过两种方式构建，前台和后台。在任何一种情况下，shell 在`createIndex`操作完成之前都不会显示提示，并且会阻塞所有操作，直到索引创建完成。为了说明前台和后台索引创建之间的区别，我们执行了第二个 mongo shell。

我们首先在前台创建了索引，这是默认行为。这个索引构建不允许我们查询集合（从第二个 shell）直到索引构建完成。`findOne`操作在整个索引构建完成之前（从第一个 shell）都会被阻塞。另一方面，在后台构建的索引不会阻塞`findOne`操作。如果您想在索引构建过程中尝试向集合中插入新文档，这应该能很好地工作。随时删除索引并在后台重新创建它，同时向`indexTest`集合中插入一个文档，您会注意到它可以顺利进行。

那么，这两种方法之间有什么区别，为什么不总是在后台构建索引？除了作为第二个参数传递给`createIndex`调用的额外参数`{background:true}`（也可以是`{background:1}`）之外，还有一些区别。后台索引创建过程将比前台创建的索引稍慢。此外，在内部——虽然与最终用户无关——在前台创建的索引将比在后台创建的索引更紧凑。

除此之外，没有其他显著的区别。实际上，如果系统正在运行并且需要在为最终用户提供服务时创建索引（虽然不建议，但有时可能需要在活动系统中进行索引创建），那么在后台创建索引是唯一的方法。有其他策略可以执行此类管理活动，我们将在管理部分的一些示例中看到。

对于前台索引创建来说，mongo 在索引创建期间获取的锁不是在集合级别，而是在数据库级别。为了解释这意味着什么，我们将不得不删除`indexTest`集合上的索引，并执行以下小练习：

1.  首先通过从 shell 执行以下命令来在前台创建索引：

```sql
> db.indexTest.createIndex({value:1})

```

1.  现在，将一个文档插入到 person 集合中，该集合此时可能存在，也可能不存在于测试数据库中，如下所示：

```sql
> db.person.insert({name:'Amol'})

```

我们将看到，person 集合中的此插入操作将在`indexTest`集合的索引创建过程中被阻塞。但是，如果此插入操作是在索引构建期间的不同数据库中的集合上执行的，它将正常执行而不会阻塞。（您也可以尝试一下。）这清楚地表明锁是在数据库级别而不是在集合或全局级别获取的。

### 注意

在 mongo 的 2.2 版本之前，锁是在全局级别，即在 mongod 进程级别，而不是在我们之前看到的数据库级别。当处理旧于 2.2 版本的 mongo 分布时，您需要记住这一点。

# 创建和理解稀疏索引

Mongo 的无模式设计是 Mongo 的基本特性之一。这允许集合中的文档具有不同的字段，一些文档中存在一些字段，而其他文档中不存在。换句话说，这些字段可能是稀疏的，这可能已经给你一个关于稀疏索引是什么的线索。在这个示例中，我们将创建一些随机测试数据，并查看稀疏索引在普通索引中的行为。我们将看到使用稀疏索引的优势和一个主要的缺陷。

## 准备工作

对于这个示例，我们需要创建一个名为`sparseTest`的集合。我们需要一个正在运行的服务器。有关如何启动服务器的说明，请参阅第一章中的*安装单节点 MongoDB*示例，*安装和启动服务器*。使用加载了`SparseIndexData.js`脚本的 shell 启动。此脚本可在 Packt 网站上下载。要了解如何使用预加载的脚本启动 shell，请参阅第一章中的*使用 JavaScript 在 Mongo shell 中连接到单个节点*示例，*安装和启动服务器*。

## 如何做…

1.  通过调用以下方法加载集合中的数据。这应该会在`sparseTest`集合中导入 100 个文档。

```sql
> createSparseIndexData()

```

1.  现在，通过执行以下查询来查看数据，注意顶部几个结果中的`y`字段：

```sql
> db.sparseTest.find({}, {_id:0})

```

1.  我们可以看到`y`字段不存在，或者如果存在的话是唯一的。然后执行以下查询：

```sql
> db.sparseTest.find({y:{$ne:2}}, {_id:0}).limit(15)

```

1.  注意结果；它包含符合条件的文档以及不包含给定字段`y`的字段。

1.  由于`y`的值似乎是唯一的，让我们按照以下方式在`y`字段上创建一个新的唯一索引：

```sql
> db.sparseTest.createIndex({y:1}, {unique:1})

```

这会抛出一个错误，抱怨值不是唯一的，冒犯的值是 null 值。

1.  我们将通过以下方式将此索引设置为稀疏：

```sql
> db.sparseTest.createIndex({y:1}, {unique:1, sparse:1})

```

1.  这应该解决我们的问题。为了确认索引已创建，请在 shell 上执行以下操作：

```sql
> db.sparseTest.getIndexes()

```

这应该显示两个索引，一个是默认的`_id`索引，另一个是我们刚刚在上一步中创建的索引。

1.  现在，再次执行我们在步骤 3 中执行的查询，并查看结果。

1.  查看结果并将其与创建索引之前看到的结果进行比较。重新执行查询，但使用以下提示强制进行完整集合扫描：

```sql
>db.sparseTest.find({y:{$ne:2}},{_id:0}).limit(15).hint({$natural:1})

```

1.  观察结果。

## 工作原理…

这些是我们刚刚执行的许多步骤。我们现在将深入探讨并解释使用稀疏索引查询集合时看到的奇怪行为的内部和推理。

我们使用 JavaScript 方法创建的测试数据只是创建了一个名为`x`的键的文档，其值是从一开始的数字，一直到 100。只有当`x`是三的倍数时，才设置`y`的值-它的值也是一个从一开始的递增数字，当`x`是`99`时，它应该最多达到 33。

然后执行查询并查看以下结果：

```sql
> db.sparseTest.find({y:{$ne:2}}, {_id:0}).limit(15)
{ "x" : 1 }
{ "x" : 2 }
{ "x" : 3, "y" : 1 }
{ "x" : 4 }
{ "x" : 5 }
{ "x" : 7 }
{ "x" : 8 }
{ "x" : 9, "y" : 3 }
{ "x" : 10 }
{ "x" : 11 }
{ "x" : 12, "y" : 4 }
{ "x" : 13 }
{ "x" : 14 }
{ "x" : 15, "y" : 5 }
{ "x" : 16 }

```

结果中缺少`y`为`2`的值，这正是我们想要的。请注意，结果中仍然可以看到`y`不存在的文档。我们现在计划在`y`字段上创建一个索引。由于该字段要么不存在，要么具有唯一值，因此唯一索引应该能够正常工作。

在内部，索引默认情况下会在索引中添加一个条目，即使原始文档中的字段在集合中不存在。然而，进入索引的值将是 null。这意味着索引中将有与集合中文档数量相同的条目。对于唯一索引，值（包括 null 值）应该在整个集合中是唯一的，这解释了为什么在创建稀疏字段的索引时会出现异常（字段不在所有文档中都存在）。

解决这个问题的一个方法是使索引稀疏化，我们所做的就是在选项中添加`sparse:1`以及`unique:1`。如果文档中不存在该字段，则不会在索引中放入条目。因此，索引现在将包含更少的条目。它只包含那些字段存在于文档中的条目。这不仅使索引变小，易于放入内存，而且解决了添加唯一约束的问题。我们最不希望的是，拥有数百万文档的集合的索引有数百万条目，而只有少数几百条目有一些值定义。

虽然我们可以看到创建稀疏索引确实使索引更有效，但它引入了一个新问题，即一些查询结果不一致。我们之前执行的相同查询产生了不同的结果。请参见以下输出：

```sql
> db.sparseTest.find({y:{$ne:2}}, {_id:0}).hint({y:1}).limit(15)
{ "x" : 3, "y" : 1 }
{ "x" : 9, "y" : 3 }
{ "x" : 12, "y" : 4 }
{ "x" : 15, "y" : 5 }
{ "x" : 18, "y" : 6 }
{ "x" : 21, "y" : 7 }
{ "x" : 24, "y" : 8 }
{ "x" : 27, "y" : 9 }
{ "x" : 30, "y" : 10 }
{ "x" : 33, "y" : 11 }
{ "x" : 36, "y" : 12 }
{ "x" : 39, "y" : 13 }
{ "x" : 42, "y" : 14 }
{ "x" : 45, "y" : 15 }
{ "x" : 48, "y" : 16 }

```

为什么会发生这种情况？答案在于这个查询的查询计划。执行以下操作查看此查询的计划：

```sql
>db.sparseTest.find({y:{$ne:2}}, {_id:0}). hint({y:1}).limit(15).explain()

```

这个计划表明它使用索引来获取匹配的结果。由于这是一个稀疏索引，所有没有`y`字段的文档都不在其中，它们也没有出现在结果中，尽管它们应该出现。这是一个我们在查询使用稀疏索引的集合时需要小心的陷阱。它会产生意想不到的结果。一个解决方案是强制进行全集合扫描，我们可以使用`hint`函数为查询分析器提供提示。提示用于强制查询分析器使用用户指定的索引。尽管通常不建议这样做，因为你真的需要知道你在做什么，但这是真正需要的情况之一。那么，我们如何强制进行全表扫描呢？我们只需在`hint`函数中提供`{$natural:1}`。集合的自然排序是指它在磁盘上存储的特定集合的顺序。这个`hint`强制进行全表扫描，现在我们得到了之前的结果。然而，对于大集合，查询性能会下降，因为现在使用了全表扫描。

如果字段存在于许多文档中（对于什么是*很多*没有正式的标准；对于一些人来说可能是 50%，对于其他人来说可能是 75%），并且不是真正稀疏的，那么使索引稀疏化除了当我们想要使其唯一之外就没有太多意义了。

### 注意

如果两个文档对于相同字段具有空值，唯一索引创建将失败，并且将其创建为稀疏索引也不会有帮助。

# 使用 TTL 索引在固定间隔后过期文档

Mongo 中一个有趣的特性是在预定的时间后自动删除集合中的数据。当我们想要清除一些比特定时间段更旧的数据时，这是一个非常有用的工具。对于关系数据库来说，通常不会有人设置每晚运行的批处理作业来执行此操作。

有了 Mongo 的 TTL 功能，您不必担心这个问题，因为数据库会自动处理。让我们看看如何实现这一点。

## 准备就绪

让我们在 Mongo 中创建一些数据，以便使用 TTL 索引进行操作。我们将为此目的创建一个名为`ttlTest`的集合。我们需要一个服务器正在运行。有关如何启动服务器的说明，请参阅第一章中的*安装单节点 MongoDB*配方，*安装和启动服务器*。使用加载了`TTLData.js`脚本的 shell 启动。此脚本可在 Packt 网站上下载。要了解如何使用预加载的脚本启动 shell，请参阅第一章中的*使用 JavaScript 在 Mongo shell 中连接到单节点*配方，*安装和启动服务器*。

## 如何做…

1.  假设服务器已启动，并且提供的脚本已加载到 shell 中，请从 mongo shell 中调用以下方法：

```sql
> addTTLTestData()

```

1.  在`createDate`字段上创建 TTL 索引如下：

```sql
> db.ttlTest.createIndex({createDate:1}, {expireAfterSeconds:300})

```

1.  现在，按以下方式查询集合：

```sql
> db.ttlTest.find()

```

1.  这应该给我们三个文件。重复这个过程，并且在大约 30-40 秒内执行`find`查询，以便看到三个文件被删除，直到整个集合中没有文件为止。

## 它是如何工作的...

让我们从打开`TTLData.js`文件开始，看看里面发生了什么。代码非常简单，它只是使用 new `Date()`获取当前日期。然后在这个脚本中的`addTTLTestData()`方法的执行中，我们有三个文档在`ttlTest`集合中，每个文档的创建时间相差一分钟。

下一步是 TTL 功能的核心：创建 TTL 索引。它类似于使用`createIndex`方法创建任何其他索引，只是它还接受一个 JSON 对象作为第二个参数。这两个参数如下：

+   第一个参数是`{createDate:1}`；这将告诉 mongo 在`createDate`字段上创建一个索引，索引的顺序是升序的，因为值是`1`（`-1`将是降序的）。

+   第二个参数`{expireAfterSeconds:300}`是使该索引成为 TTL 索引的关键，它告诉 Mongo 在 300 秒（五分钟）后自动使文档过期。

好吧，但是从什么时候开始的五分钟？它是它们被插入集合的时间还是其他时间戳？在这种情况下，它认为`createTime`字段是基础，因为这是我们创建索引的字段。

现在引发一个问题：如果一个字段被用作时间计算的基础，那么它的类型必须受到一定的限制。在一个`char`字段上创建 TTL 索引就没有意义，比如说，保存一个人名字的字段。

是的；正如我们猜测的那样，字段的类型可以是 BSON 类型的日期或日期数组。在数组中有多个日期的情况下会发生什么？在这种情况下会考虑什么？

结果是 Mongo 使用数组中可用的日期的最小值。尝试这种情况作为练习。

在一个文档中，对`updateField`字段放入两个相隔大约五分钟的日期，然后在这个字段上创建一个 TTL 索引，使文档在 10 分钟（600 秒）后过期。查询集合，看看文档何时从集合中删除。它应该在`updateField`数组中的最小时间值之后大约 10 分钟后被删除。

除了字段类型的约束外，还有一些其他约束：

+   如果一个字段已经有了索引，你就不能创建 TTL 索引。因为集合的`_id`字段已经默认有了索引，这实际上意味着你不能在`_id`字段上创建 TTL 索引。

+   TTL 索引不能是涉及多个字段的复合索引。

+   如果字段不存在，它将永远不会过期。（我想这很合乎逻辑。）

+   它不能在封闭集合上创建。如果你不知道封闭集合，它们是 Mongo 中的特殊集合，它们有一个大小限制，按照 FIFO 插入顺序删除旧文档，以便为新文档腾出空间。

### 注意

TTL 索引仅支持 Mongo 版本 2.2 及以上。请注意，文档不会在字段中给定的确切时间被删除。周期将以一分钟的粒度进行，这将删除自上次运行周期以来符合删除条件的所有文档。

## 另请参阅

使用情况可能不要求在固定时间间隔后删除所有文档。如果我们想要自定义文档在集合中停留的时间，也可以实现，这将在下一个示例“使用 TTL 索引在特定时间到期的文档”中进行演示。

# 使用 TTL 索引在特定时间到期的文档

在上一个示例“使用 TTL 索引在固定时间间隔后到期的文档”中，我们已经看到文档在固定时间段后到期的情况。但是，可能存在一些情况，我们希望文档在不同时间到期。这与上一个示例中所看到的情况不同。在本示例中，我们将看到如何指定文档可以到期的时间，对于不同的文档可能是不同的。

## 准备就绪

对于本示例，我们将创建一个名为`ttlTest2`的集合。我们需要一个正在运行的服务器。有关如何启动服务器的说明，请参阅第一章中的*安装单节点 MongoDB*示例，*安装和启动服务器*。使用加载了`TTLData.js`脚本的 shell。此脚本可在 Packt 网站上下载。要了解如何使用预加载脚本启动 shell，请参阅第一章中的*使用 JavaScript 连接 Mongo shell 中的单节点*示例，*安装和启动服务器*。

## 如何操作…

1.  使用`addTTLTestData2`方法在集合中加载所需的数据。在 mongo shell 上执行以下操作：

```sql
> addTTLTestData2()

```

1.  现在，按照以下步骤在`ttlTest2`集合上创建 TTL 索引：

```sql
> db.ttlTest2.createIndex({expiryDate :1}, {expireAfterSeconds:0})

```

1.  执行以下`find`查询以查看集合中的三个文档：

```sql
> db.ttlTest2.find()

```

1.  现在，大约四、五和七分钟后，查看 ID 为 2、1 和 3 的文档是否分别被删除。

## 工作原理…

让我们开始打开`TTLData.js`文件，看看里面发生了什么。我们本次示例感兴趣的方法是`addTTLTestData2`。该方法简单地在`tllTest2`集合中创建了三个文档，其`_id`分别为`1`、`2`和`3`，其`exipryDate`字段分别设置为当前时间之后的`5`、`4`和`7`分钟。请注意，与上一个示例中给出的创建日期不同，该字段具有未来日期。

接下来，我们创建一个索引：`db.ttlTest2.createIndex({expiryDate :1}, {expireAfterSeconds:0})`。这与我们在上一个示例中创建索引的方式不同，其中对象的`expireAfterSeconds`字段设置为非零值。这是`expireAfterSeconds`属性值的解释方式。如果值为非零，则这是文档将在 Mongo 中从集合中删除的基准时间之后经过的秒数。此基准时间是索引创建的字段中保存的值（如上一个示例中的`createTime`）。如果此值为零，则索引创建的日期值（在本例中为`expiryDate`）将是文档到期的时间。

总之，如果要在到期后删除文档，则 TTL 索引效果很好。有很多情况下，我们可能希望将文档移动到存档集合中，存档集合可能是基于年份和月份创建的。在任何这种情况下，TTL 索引都没有帮助，我们可能需要自己编写一个外部作业来完成这项工作。这样的作业还可以读取一系列文档，将它们添加到目标集合中，并从源集合中删除它们。MongoDB 的开发人员已经计划发布一个解决这个问题的功能。

## 另请参阅

在这个和前一个教程中，我们看了看 TTL 索引以及如何使用它们。然而，如果在创建了 TTL 索引之后，我们想要修改 TTL 值怎么办？这是可以通过使用`collMod`选项来实现的。在管理部分可以了解更多关于这个选项的信息。
