# MongoDB 基础知识（一）

> 原文：[`zh.annas-archive.org/md5/804E58DCB5DC268F1AD8C416CF504A25`](https://zh.annas-archive.org/md5/804E58DCB5DC268F1AD8C416CF504A25)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

# 关于本书

MongoDB 是处理大型数据集的最流行的数据库技术之一。这本书将帮助 MongoDB 初学者开发创建数据库和高效处理数据的知识和技能。

与其他 MongoDB 书籍不同，*MongoDB 基础*从一开始就深入探讨了云计算——向您展示如何在第一章中开始使用 Atlas。您将发现如何修改现有数据，向数据库添加新数据，并通过创建聚合管道处理复杂查询。随着学习的深入，您将了解 MongoDB 复制架构并配置一个简单的集群。您还将掌握用户身份验证以及数据备份和恢复技术。最后，您将使用 MongoDB Charts 进行数据可视化。

您将在以实际项目为基础的小型练习和活动中挑战自己，以愉快且可实现的方式进行学习。其中许多小型项目都是围绕电影数据库案例研究展开的，而最后一章则作为一个最终项目，您将使用 MongoDB 解决基于共享单车应用的真实世界问题。

通过本书，您将具备处理大量数据和使用 MongoDB 处理自己项目的技能和信心。

## 关于作者

*Amit Phaltankar*是一名软件开发人员和博主，拥有超过 13 年的轻量级和高效软件组件构建经验。他擅长编写基于 Web 的应用程序，并使用传统 SQL、NoSQL 和大数据技术处理大规模数据集。他在各种技术堆栈中有工作经验，热衷于学习和适应新的技术趋势。Amit 对提高自己的技能集充满热情，也喜欢指导和培养同行，并为博客做出贡献。在过去的 6 年中，他有效地利用 MongoDB 以各种方式构建更快的系统。

*Juned Ahsan*是一位拥有超过 14 年经验的软件专业人士。他为 Cisco、Nuamedia、IBM、Nokia、Telstra、Optus、Pizza Hut、AT&T、Hughes、Altran 等公司和客户构建软件产品和服务。Juned 在从零开始构建不同规模平台的软件产品和架构方面拥有丰富的经验。他热衷于帮助和指导他人，并是 Stack Overflow 的前 1%贡献者。Juned 对认知 CX、云计算、人工智能和 NoSQL 数据库充满热情。

*Michael Harrison*在澳大利亚电信领导者 Telstra 开始了他的职业生涯。他曾在他们的网络、大数据和自动化团队工作。他现在是 Southbank Software 的首席软件开发人员和创始成员，这是一家位于墨尔本的初创公司，致力于构建下一代数据库技术的工具。作为一名全栈工程师，Michael 领导开发了一个面向 MongoDB 的开源、平台无关的 IDE（dbKoda），以及一个基于 MongoDB 的区块链数据库，名为 ProvenDB。这两款产品都在纽约的 MongoDB World 大会上展出。考虑到 Michael 拥有一双 MongoDB 袜子，可以说他是一位狂热爱好者。

*Liviu Nedov*是一位资深顾问，拥有 20 多年的数据库技术经验。他为澳大利亚和欧洲的客户提供专业和咨询服务。在他的职业生涯中，他为 Wotif Group、Xstrata Copper/Glencore 和纽卡斯尔大学以及昆士兰能源等客户设计和实施了大型企业项目。他目前在 Data Intensity 工作，这是最大的多云服务提供商，为应用程序、数据库和商业智能提供服务。近年来，他积极参与 MongoDB、NoSQL 数据库项目、数据库迁移和云 DBaaS（数据库即服务）项目。

## 这本书是为谁写的

*MongoDB 基础*面向具有基本技术背景的读者，他们是第一次接触 MongoDB。任何数据库、JavaScript 或 JSON 经验都会有所帮助，但不是必需的。*MongoDB 基础*可能会简要涉及这些技术以及更高级的主题，但不需要背景知识即可从本书中获得价值。

## 关于章节

*第一章*，*MongoDB 简介*，包含了 MongoDB 的历史和背景、基本概念，以及设置第一个 MongoDB 实例的指南。

*第二章*，*文档和数据类型*，将教您有关 MongoDB 数据和命令的关键组件。

*第三章*，*服务器和客户端*，为您提供了管理 MongoDB 访问和连接所需的信息，包括数据库和集合的创建。

*第四章*，*查询文档*，是我们进入 MongoDB 核心的地方：查询数据库。本章提供了实际操作的练习，让您使用查询语法、操作符和修饰符。

*第五章*，*插入、更新和删除文档*，扩展了查询，允许您将查询转换为更新，修改现有数据。

*第六章*，*使用聚合管道和数组进行更新*，涵盖了更复杂的更新操作，使用管道和批量更新。

*第七章*，*数据聚合*，演示了 MongoDB 最强大的高级功能之一，允许您创建可重用的复杂查询管道，无法通过更直接的查询解决。

*第八章*，*在 MongoDB 中编写 JavaScript*，将带您从直接数据库交互到更常见于现实世界的方法：应用程序的查询。在本章中，您将创建一个简单的 Node.js 应用程序，可以与 MongoDB 进行编程交互。

*第九章*，*性能*，为您提供了确保您的查询有效运行的信息和工具，主要是通过使用索引和执行计划。

*第十章*，*复制*，更详细地研究了您可能在生产环境中遇到的标准 MongoDB 配置，即集群和副本集。

*第十一章*，*备份和恢复*，涵盖了作为管理数据库冗余和迁移的一部分所需的信息。这对于数据库管理至关重要，但也对加载样本数据和开发生命周期有用。

*第十二章*，*数据可视化*，解释了如何将原始数据转化为有意义的可视化，有助于发现和传达数据中的见解。

*第十三章*，*MongoDB* *案例研究*，是一个课程结束的案例研究，将在一个真实的例子中整合前几章涵盖的所有技能。

## 约定

文本形式的代码词、数据库和集合名称、文件和文件夹名称、shell 命令和用户输入使用以下格式：“`db.myCollection.findOne()`命令将返回`myCollection`中的第一个文档。”

较小的示例代码块及其输出将以以下格式进行格式化：

```js
use sample_mflix
var pipeline = []
var options  = {}
var cursor   = db.movies.aggregate(pipeline, options);
```

在大多数情况下，输出是一个单独的块，将以图的形式进行格式化，如下所示：

![图 0.1：输出作为一个图](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_Preface_01.jpg)

图 0.1：输出作为一个图

通常，在章节开始时，会介绍一些关键的新术语。在这些情况下，将使用以下格式：“`aggregate`命令在集合上操作，就像其他**创建、读取、更新、删除**（**CRUD**）命令一样。”

## 开始之前

如前所述，MongoDB 不仅仅是一个数据库。它是一个庞大而分散的工具和库集。因此，在我们全力投入 MongoDB 之前，最好确保我们已经为冒险做好了充分的准备。

## 安装 MongoDB

1.  从[`www.mongodb.com/try/download/community`](https://www.mongodb.com/try/download/community)下载 MongoDB Community tarball（`tgz`）。在“可用下载”部分，选择当前（4.4.1）版本，您的平台，并单击“下载”。

1.  将下载的`tgz`文件放入您选择的任何文件夹中并进行提取。在基于 Linux 的操作系统（包括 macOS）上，可以使用命令提示符将`tgz`文件提取到文件夹中。打开终端，导航到您复制`tgz`文件的目录，并发出以下命令：

```js
     tar -zxvf mongodb-macos-x86_64-4.4.1.tgz
```

请注意，`tgz`的名称可能会根据您的操作系统和下载的版本而有所不同。如果您查看提取的文件夹，您将找到所有 MongoDB 二进制文件，包括`mongod`和`mongo`，都放在`bin`目录中。

1.  可执行文件，如`mongod`和`mongo`，分别是 MongoDB 数据库和 Mongo Shell 的启动器。要能够从任何位置启动它们，您需要将这些命令添加到`PATH`变量中，或将二进制文件复制到`/usr/local/bin`目录中。或者，您可以将二进制文件保留在原地，并在`/usr/local/bin`目录中创建这些二进制文件的符号链接。要创建符号链接，您需要打开终端，导航到 MongoDB 安装目录，并执行此命令：

```js
     sudo ln -s /full_path/bin/* /usr/local/bin/
```

1.  要在本地运行 MongoDB，您必须创建一个数据目录。执行下一个命令并在任何您想要的文件夹中创建数据目录：

```js
     mkdir -p ~/mytools/mongodb
```

1.  要验证安装是否成功，请在本地运行 MongoDB。为此，您需要使用`mongo`命令并提供数据目录的路径：

```js
     mongod --dbpath ~/mytools/mongodb
```

执行此命令后，MongoDB 将在默认端口`27017`上启动，并且您应该看到 MongoDB 引导日志；最后一行包含`msg`：“等待连接”，这表明数据库已启动并正在等待客户端（例如 Mongo shell）进行连接。

1.  最后，您需要通过将其连接到数据库来验证 Mongo shell。下一个命令用于使用默认配置启动 Mongo shell：

```js
mongo
```

执行此命令后，您应该看到 shell 提示已启动。默认情况下，shell 连接到运行在`localhost 27017`端口上的数据库。在接下来的章节中，您将学习如何将 shell 连接到 MongoDB Atlas 集群。

1.  在 MongoDB 的官方安装手册中可以找到有关在 Windows 或任何特定操作系统上安装 MongoDB 的详细说明，该手册位于[`docs.mongodb.com/manual/installation/`](https://docs.mongodb.com/manual/installation/)。

## 编辑器和 IDE

MongoDB shell 允许您通过简单地在控制台中键入命令来直接与数据库交互。但是，这种方法只能让您走得更远，并且随着执行更高级操作，它最终会变得更加繁琐。因此，我们建议准备一个文本编辑器来编写您的命令，然后可以将这些命令复制到 shell 中。尽管任何文本编辑器都可以使用，但如果您还没有偏好，我们建议使用 Visual Studio Code，因为它具有一些对 MongoDB 有帮助的插件。也就是说，您熟悉的任何工具都足够用于本书。

此外，还有许多 MongoDB 工具可以帮助您顺利进行学习。我们不建议特定工具作为学习的最佳方式，但我们建议在网上搜索一些工具和插件，这些工具和插件可以在学习过程中为您提供额外的价值。

## 下载和安装 Visual Studio Code

让我们继续使用适当的 JavaScript IDE 进行设置。当然，您可以选择任何您喜欢的，但我们将在最初的章节中坚持使用 Visual Studio Code。这是一个专门针对 Web 技术的易于使用的编辑器，并且适用于所有主要操作系统：

1.  首先，您需要获取安装包。这可以通过不同的方式完成，取决于您的操作系统，但最直接的方法是访问 Visual Studio Code 网站，网址是[`code.visualstudio.com/`](https://code.visualstudio.com/)。

1.  该网站应该检测到您的操作系统，并向您呈现一个按钮，允许直接下载稳定版本。当然，您可以通过单击下拉箭头选择不同的版本以获得其他选项：![图 0.2：Visual Studio Code 下载提示](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_Preface_02.jpg)

图 0.2：Visual Studio Code 下载提示

1.  下载后，安装将取决于您的操作系统。同样，根据您选择的操作系统，安装将略有不同。

`.ZIP`存档。您需要解压该包以显示`.APP`应用程序文件。

`.EXE`文件已下载到您的本地计算机。

`.DEB`或`.RPM`包下载到您的本地环境。

1.  下载了安装程序包后，现在您必须运行一个依赖于我们选择的操作系统的安装例程：

`.APP`到`Applications`文件夹。这将使其通过 macOS 界面实用程序可用，例如`.DEB`或`.RPM`包。

1.  安装 Visual Studio Code 后，您现在只需要将其固定到**任务栏**、**Dock**或任何其他操作系统机制，以便快速轻松地访问该程序。

就是这样。Visual Studio Code 现在可以使用了。

到目前为止，我们已经看到了当今在使用 JavaScript 时可用的各种集成开发环境。我们还下载并安装了 Visual Studio Code，这是微软的现代 JavaScript 集成开发环境。现在我们将看到，在开始新的 JavaScript 项目时，使用适当的文件系统准备是非常重要的。

## 下载 Node.js

Node.js 是开源的，您可以从其官方网站下载所有平台的 Node.js。它支持所有三个主要平台：Windows、Linux 和 macOS。

### Windows

访问它们的官方网站并下载最新的稳定`.msi`安装程序。这个过程非常简单。只需执行`.msi`文件并按照说明在系统上安装它。会有一些关于接受许可协议的提示。您必须接受这些提示，然后点击`完成`。就是这样。

### Mac

Windows 和 Mac 的安装过程非常相似。您需要从官方网站下载`.pkg`文件并执行它。然后，按照说明进行操作。您可能需要接受许可协议。之后，按照提示完成安装过程。

### Linux

要在 Linux 上安装 Node.js，请按照提到的顺序执行以下命令：

+   `$ cd /tmp`

+   `$ wget http://nodejs.org/dist/v8.11.2/node-v8.11.2-linux-x64.tar.gz`

+   `$ tar xvfz node-v8.11.2-linux-x64.tar.gz`

+   `$ sudo mkdir -p /usr/local/nodejs`

+   `$ sudo mv node-v8.11.2-linux-x64/* /usr/local/nodejs`

请注意，只有在*不*以管理员身份登录时，您才需要在最后两个命令中使用`sudo`。在这里，您首先将当前活动目录更改为系统的临时目录（`tmp`）。其次，您从官方发布目录下载`node`的`tar`包。第三，您将`tar`包解压到`tmp`目录。该目录包含所有已编译和可执行文件。第四，您在系统中为`Node.js`创建一个目录。在最后一个命令中，您将包的所有已编译和可执行文件移动到该目录。

## 验证安装

安装完成后，您可以通过执行以下命令来验证系统上是否正确安装了它：

```js
$ node -v && npm -v
```

它将输出当前安装的 Node.js 和 npm 的版本：

![图 0.3：Node.js 和 npm 的已安装版本](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_Preface_03.jpg)

图 0.3：Node.js 和 npm 的已安装版本

这里显示系统上安装了 Node.js 的 8.11.2 版本，以及 npm 的 5.6.0 版本。

## 安装代码包

从 GitHub 上下载代码文件，网址为[`github.com/PacktPublishing/MongoDB-Fundamentals`](https://github.com/PacktPublishing/MongoDB-Fundamentals)。这里的文件包含每章的练习、活动和一些中间代码。当您遇到困难时，这可能是一个有用的参考。

您可以使用“下载 ZIP”选项将完整的代码下载为 ZIP 文件。或者，您可以使用`git`命令来检出存储库，如下面的代码片段所示：

```js
git clone https://github.com/PacktPublishing/MongoDB-Fundamentals.git
```

## 联系我们

我们始终欢迎读者的反馈意见。

`customercare@packtpub.com`。

**勘误**：尽管我们已经尽最大努力确保内容的准确性，但错误是难免的。如果您在本书中发现了错误，我们将不胜感激地接受您的报告。请访问[www.packtpub.com/support/errata](http://www.packtpub.com/support/errata) 并填写表格。

`copyright@packt.com` 并附上材料的链接。

**如果您有兴趣成为作者**：如果您在某个专业领域有专长，并且有兴趣撰写或为一本书作出贡献，请访问[authors.packtpub.com](http://authors.packtpub.com)。

## 请留下评论

请通过在亚马逊上留下详细、公正的评论来告诉我们您的想法。我们感谢所有的反馈意见 - 它帮助我们继续制作出优秀的产品，并帮助有抱负的开发者提升他们的技能。请花几分钟时间给出您的想法 - 这对我们来说意义重大。


# 第一章：MongoDB 简介

概述

本章将介绍 MongoDB 的基础知识，首先定义数据及其类型，然后探讨数据库如何解决数据存储挑战。您将了解不同类型的数据库以及如何为您的任务选择合适的数据库。一旦您对这些概念有了清晰的理解，我们将讨论 MongoDB、其特性、架构、许可和部署模型。到本章结束时，您将通过 Atlas（用于管理 MongoDB 的基于云的服务）获得使用 MongoDB 的实际经验，并与其基本元素（如数据库、集合和文档）一起工作。

# 介绍

数据库是一种安全、可靠且易于获取数据的平台。通常有两种类型的数据库：关系数据库和非关系数据库。非关系数据库通常被称为 NoSQL 数据库。NoSQL 数据库用于存储大量复杂和多样化的数据，如产品目录、日志、用户互动、分析等。MongoDB 是最成熟的 NoSQL 数据库之一，具有数据聚合、ACID（原子性、一致性、隔离性、持久性）事务、水平扩展和图表等功能，我们将在接下来的部分中详细探讨。

数据对于企业至关重要，特别是在存储、分析和可视化数据以做出数据驱动决策时。正因如此，像谷歌、Facebook、Adobe、思科、eBay、SAP、EA 等公司都信任并使用 MongoDB。

MongoDB 有不同的变体，可用于实验和实际应用。由于其直观的查询和命令语法，它比大多数其他数据库更容易设置和管理。MongoDB 可供任何人在自己的机器上安装，也可作为托管服务在云上使用。MongoDB 的云托管服务（名为 Atlas）对所有人免费开放，无论您是已建立的企业还是学生。在我们开始讨论 MongoDB 之前，让我们先了解数据库管理系统。

# 数据库管理系统

数据库管理系统（DBMS）提供存储和检索数据的能力。它使用查询语言来创建、更新、删除和检索数据。让我们来看看不同类型的 DBMS。

## 关系数据库管理系统

关系数据库管理系统（RDBMS）用于存储结构化数据。数据以表格形式存储，包括行和列。表格可以与其他表格建立关系，以描述实际的数据关系。例如，在大学关系数据库中，“学生”表可以通过共同的列（如 courseId）与“课程”和“成绩”表相关联。

## NoSQL 数据库管理系统

NoSQL 数据库是为解决存储非结构化和半结构化数据的问题而发明的。关系数据库要求在存储数据之前定义数据的结构。这种数据库结构定义通常称为模式，涉及数据实体及其属性和类型。RDBMS 客户端应用程序与模式紧密耦合。很难修改模式而不影响客户端。相比之下，NoSQL 数据库允许您在没有模式的情况下存储数据，并支持动态模式，这使客户端与严格的模式解耦，对于现代和实验性应用程序通常是必要的。

存储在 NoSQL 数据库中的数据因提供者而异，但通常以文档而不是表的形式存储。例如，库存管理数据库可以具有不同的产品属性，因此需要灵活的结构。同样，存储来自不同来源的数据的分析数据库也需要灵活的结构。

## 比较

让我们根据以下因素比较 NoSQL 数据库和 RDBMS。当您阅读本书时，您将深入了解这些内容。现在，以下表格提供了基本概述：

![图 1.1：关系数据库和 NoSQL 之间的区别](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_01.jpg)

图 1.1：关系数据库和 NoSQL 之间的区别

这就结束了我们关于数据库和各种数据库类型之间的差异的讨论。在下一节中，我们将开始探索 MongoDB。

# MongoDB 简介

MongoDB 是一种流行的 NoSQL 数据库，可以存储结构化和非结构化数据。该组织于 2007 年由 Kevin P. Ryan、Dwight Merriman 和 Eliot Horowitz 在纽约创立，最初被称为 10gen，后来更名为 MongoDB——这个词受到了“巨大”的启发。

它提供了存储真实世界大数据所需的基本和奢华功能。其基于文档的设计使其易于理解和使用。它旨在用于实验和真实世界应用，并且比大多数其他 NoSQL 数据库更容易设置和管理。其直观的查询和命令语法使其易于学习。

以下列表详细探讨了这些功能：

+   **灵活和动态的模式**：MongoDB 允许数据库使用灵活的模式。灵活的模式允许不同文档中的字段变化。简而言之，数据库中的每个记录可能具有相同数量的属性，也可能没有。它解决了存储不断发展的数据的需求，而无需对模式本身进行任何更改。

+   **丰富的查询语言**：MongoDB 支持直观且丰富的查询语言，这意味着简单而强大的查询。它配备了丰富的聚合框架，允许您根据需要对数据进行分组和过滤。它还具有内置的通用文本搜索和特定用途，如地理空间搜索的支持。

+   **多文档 ACID 事务**：**原子性、一致性、完整性和耐久性**（**ACID**）是允许存储和更新数据以保持其准确性的功能。事务用于组合需要一起执行的操作。MongoDB 支持单个文档和多文档事务中的 ACID。

+   **原子性**意味着全部或无，这意味着事务中的所有操作要么全部发生，要么全部不发生。这意味着如果其中一个操作失败，那么所有已执行的操作都将被回滚，以使事务操作受影响的数据保持在事务开始之前的状态。

+   事务中的**一致性**意味着根据数据库定义的规则保持数据一致。如果事务违反任何数据库一致性规则，则必须回滚。

+   **隔离性**强制在隔离中运行事务，这意味着事务不会部分提交数据，事务外的任何值只有在所有操作执行并完全提交后才会发生变化。

+   耐久性确保事务提交的更改。因此，如果事务已执行，则数据库将确保即使系统崩溃，更改也会被提交。

+   **高性能**：MongoDB 使用嵌入式数据模型提供高性能，以减少磁盘 I/O 使用。此外，对不同类型的数据进行索引的广泛支持使查询更快。索引是一种维护索引中相关数据指针的机制，就像书中的索引一样。

+   **高可用性**：MongoDB 支持最少三个节点的分布式集群。集群是指使用多个节点/机器进行数据存储和检索的数据库部署。故障转移是自动的，数据在辅助节点上异步复制。

+   **可扩展性**：MongoDB 提供了一种在数百个节点上水平扩展数据库的方法。因此，对于所有的大数据需求，MongoDB 是完美的解决方案。通过这些，我们已经了解了 MongoDB 的一些基本特性。

注意

MongoDB 1.0 于 2009 年 2 月首次正式发布为开源数据库。此后，该软件已经发布了几个稳定版本。有关不同版本和 MongoDB 演变的更多信息，请访问官方 MongoDB 网站（[`www.mongodb.com/evolved`](https://www.mongodb.com/evolved)）。

# MongoDB 版本

MongoDB 有两个不同的版本，以满足开发人员和企业的需求，如下：

**社区版**：社区版是为开发人员社区发布的，供那些想要学习和获得 MongoDB 实践经验的人使用。社区版是免费的，可在 Windows、Mac 和不同的 Linux 版本上安装，如 Red Hat、Ubuntu 等。您可以在社区服务器上运行生产工作负载；但是，对于高级企业功能和支持，您必须考虑付费的企业版。

企业版：企业版使用与社区版相同的基础软件，但附带一些额外的功能，包括以下内容：

+   *安全性*：**轻量级目录访问协议**（**LDAP**）和 Kerberos 身份验证。LDAP 是一种允许来自外部用户目录的身份验证的协议。这意味着您不需要在数据库中创建用户来进行身份验证，而是可以使用外部目录，如企业用户目录。这样可以节省大量时间，不需要在不同系统中复制用户，如数据库。

+   *内存存储引擎*：提供高吞吐量和低延迟。

+   *加密存储引擎*：这使您可以加密静态数据。

+   *SNMP 监控*：集中的数据收集和聚合。

+   *系统事件审计*：这使您可以以 JSON 格式记录事件。

## 将社区版迁移到企业版

MongoDB 允许您将社区版升级为企业版。这对于您最初使用社区版并最终构建了现在适合商业用途的数据库的情况很有用。对于这种情况，您可以简单地将社区版升级为企业版，而不是安装企业版并重新构建数据库，从而节省时间和精力。有关升级的更多信息，请访问此链接：[`docs.mongodb.com/manual/administration/upgrade-community-to-enterprise/`](https://docs.mongodb.com/manual/administration/upgrade-community-to-enterprise/)。

# MongoDB 部署模型

MongoDB 可以在多种平台上运行，包括 Windows、macOS 和不同版本的 Linux。您可以在单台机器或多台机器上安装 MongoDB。多台机器安装提供了高可用性和可扩展性。以下列表详细介绍了每种安装类型：

**独立版**

独立安装是单机安装，主要用于开发或实验目的。您可以参考*前言*中有关在系统上安装 MongoDB 的步骤。

**副本集**

在 MongoDB 中，复制集是一组进程或服务器，它们共同工作以提供数据冗余和高可用性。将 MongoDB 作为独立进程运行并不是非常可靠的，因为由于连接问题和磁盘故障，您可能会丢失对数据的访问。使用复制集可以解决这些问题，因为数据副本存储在多个服务器上。集群中至少需要三台服务器。这些服务器被配置为主服务器、次要服务器或仲裁者。您将在第九章“复制”中了解更多关于复制集及其好处的信息。

分片

分片部署允许您以分布式方式存储数据。它们适用于管理大量数据并期望高吞吐量的应用程序。一个分片包含数据的一个子集，每个分片必须使用复制集来提供其持有的数据的冗余。多个分片共同工作提供了一个分布式和复制的数据集。

# 管理 MongoDB

MongoDB 为用户提供了两种选择。根据您的需求，您可以在自己的系统上安装并自己管理数据库，或者利用 MongoDB（Atlas）提供的数据库即服务（DBaaS）选项。让我们更多地了解这两种选择。

## 自管理

MongoDB 可以下载并安装在您的机器上。机器可以是工作站、服务器、数据中心中的虚拟机，或者在云上。您可以将 MongoDB 安装为独立、复制集或分片集群。所有这些部署都适用于社区版和企业版。每种部署都有其优势和相关的复杂性。自管理的数据库可以用于您希望更精细地控制数据库或者只是想学习数据库管理和操作的场景。

## 托管服务：数据库即服务

托管服务是将一些流程、功能或部署外包给供应商的概念。DBaaS 是一个通常用于外包给外部供应商的数据库的术语。托管服务实施了一个共享责任模型。服务提供商管理基础设施，即安装、部署、故障转移、可伸缩性、磁盘空间、监控等。您可以管理数据和安全性、性能和调整设置。它允许您节省管理数据库的时间，专注于其他事情，比如应用程序开发。

在这一部分，我们了解了 MongoDB 的历史和发展。我们还了解了 MongoDB 的不同版本以及它们之间的区别。我们通过学习 MongoDB 的部署和管理方式来结束了这一部分。

# MongoDB Atlas

MongoDB Atlas 是 MongoDB Inc.提供的数据库即服务（DBaaS）产品。它允许您在云上提供数据库作为服务，可以用于您的应用程序。Atlas 使用来自不同云供应商的云基础设施。您可以选择要部署数据库的云供应商。与任何其他托管服务一样，您可以获得高可用性、安全的环境，并且几乎不需要或根本不需要维护。

## MongoDB Atlas 的好处

让我们来看看 MongoDB Atlas 的一些好处。

+   简单设置：在 Atlas 上设置数据库很容易，只需几个步骤即可完成。Atlas 在幕后运行各种自动化任务来设置您的多节点集群。

+   保证可用性：Atlas 每个复制集至少部署三个数据节点或服务器。每个节点都部署在不同的可用区（Amazon Web Services（AWS））、故障域（Microsoft Azure）或区域（Google Cloud Platform（GCP））。这样可以实现高可用性设置，并在发生故障或例行更新时保持持续的正常运行时间。

+   全球覆盖：MongoDB Atlas 在 AWS、GCP 和 Microsoft Azure 云中的不同区域都可用。对不同区域的支持允许您选择一个离您更近的区域进行低延迟读写。

+   **最佳性能**：MongoDB 的创始人管理 Atlas，并利用他们的专业知识和经验来保持 Atlas 中的数据库运行良好。此外，单击升级可用于升级到最新版本的 MongoDB。

+   **高度安全**：默认实施安全最佳实践，例如独立的 VPC（虚拟私有云）、网络加密、访问控制和防火墙以限制访问。

+   **自动备份**：您可以配置具有可定制计划和数据保留策略的自动备份。安全备份和恢复可用于在不同版本的数据库之间进行切换。

## 云提供商

MongoDB Atlas 目前支持三个云提供商，分别是**AWS**、**GCP**和**Microsoft Azure**。

## 可用区

**可用区**（**AZs**）是一组物理数据中心，距离较近，配备有计算、存储或网络资源。

## 区域

区域是一个地理区域，例如悉尼、孟买、伦敦等。一个区域通常包括两个或两个以上的 AZs。这些 AZs 通常位于彼此相距较远的不同城市/城镇，以提供在发生自然灾害时的容错能力。容错能力是系统在某一部分出现问题时仍然能够继续运行的能力。就 AZs 而言，如果一个 AZ 由于某种原因而宕机，另一个 AZ 仍应能够提供服务。

## MongoDB 支持的区域和可用区

MongoDB Atlas 允许您在 AWS、GCP 和 Azure 的多云全球基础设施中部署数据库。它使 MongoDB 能够支持大量的区域和 AZs。此外，随着云提供商不断增加，支持的区域和 AZs 的数量也在不断增加。请参考官方 MongoDB 网站上关于云提供商区域支持的链接：

+   AWS：[`docs.atlas.mongodb.com/reference/amazon-aws/#amazon-aws`](https://docs.atlas.mongodb.com/reference/amazon-aws/#amazon-aws)。

+   GCP：[`docs.atlas.mongodb.com/reference/google-gcp/#google-gcp`](https://docs.atlas.mongodb.com/reference/google-gcp/#google-gcp)。

+   Azure：[`docs.atlas.mongodb.com/reference/microsoft-azure/#microsoft-azure`](https://docs.atlas.mongodb.com/reference/microsoft-azure/#microsoft-azure)。

## Atlas 套餐

要在 MongoDB Atlas 中构建数据库集群，您需要选择一个**套餐**。套餐是您从集群中获得的数据库功率级别。在 Atlas 中配置数据库时，您会得到两个参数：RAM 和存储空间。根据您对这些参数的选择，将配置适当数量的数据库功率。您的集群成本与 RAM 和存储的选择相关联；更高的选择意味着更高的成本，更低的选择意味着更低的成本。

M0 是 MongoDB Atlas 中的免费套餐，提供 512MB 的共享 RAM 和存储空间。这是我们用于学习目的的套餐。免费套餐并非在所有区域都可用，因此如果在您的区域找不到它，请选择最接近的免费套餐区域。数据库的接近程度决定了操作的延迟。

选择套餐需要了解您的数据库使用情况以及您愿意花费多少。配置不足的数据库可能会在高峰使用时耗尽应用程序的容量，并可能导致应用程序错误。配置过多的数据库可以帮助应用程序表现良好，但成本更高。使用云数据库的优势之一是您可以根据需要随时修改集群大小。但您仍然需要找到适合您日常数据库使用的最佳容量。确定最大并发连接数是一个关键决策因素，可以帮助您为您的用例选择适当的 MongoDB Atlas 套餐。让我们看看不同的可用套餐：

![图 1.2：MongoDB Atlas 套餐配置](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_02.jpg)

图 1.2：MongoDB Atlas 层配置

### MongoDB Atlas 定价

容量规划是必不可少的，但估算数据库集群的成本也很重要。我们了解到 M0 集群是免费的，资源很少，非常适合原型设计和学习目的。对于付费的集群层，Atlas 会按小时收费。总成本包括多个因素，如服务器的类型和数量。让我们看一个示例，了解 Atlas 上 M30 类型副本集（三台服务器）的成本估算。

### 集群成本估算

让我们尝试了解如何估算您的 MongoDB Atlas 集群的成本。按照以下方式确定集群需求：

+   机器类型：M30

+   服务器数量：3（副本集）

+   运行时间：每天 24 小时

+   估算时间段：1 个月

一旦我们确定了我们的需求，估算成本可以计算如下：

+   每小时运行单个 M30 服务器的成本：$0.54

+   服务器运行的小时数：24（小时）x 30（天）= 720

+   一个月单台服务器的成本：720 x 0.54 = $388.8

+   运行三台服务器集群的成本：388.8 x 3 = $1166.4

因此，总成本应该降至$1166.4。

注意

除了集群的运行成本，您还应考虑额外服务的成本，如备份、数据传输和支持合同的成本。

让我们通过以下练习在一个示例场景中实施我们的学习。

## 练习 1.01：设置 MongoDB Atlas 帐户

MongoDB Atlas 为您提供免费注册以设置免费集群。在这个练习中，您将通过执行以下步骤创建一个帐户：

1.  转到[`www.mongodb.com`](https://www.mongodb.com)并单击“开始免费”。将出现以下窗口：![图 1.3：MongoDB Atlas 主页](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_03.jpg)

图 1.3：MongoDB Atlas 主页

1.  您可以使用您的 Google 帐户注册，也可以手动提供您的详细信息，如下图所示。在相应的字段中提供您的使用情况、“您的工作电子邮件”、“名字”、“姓氏”和“密码”详细信息，选择同意服务条款的复选框，然后单击“开始免费”。![图 1.4：开始页面](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_04.jpg)

图 1.4：开始页面

将出现以下窗口，您可以在其中输入组织和项目详细信息：

![图 1.5：输入组织和项目详细信息的页面](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_05.jpg)

图 1.5：输入组织和项目详细信息的页面

接下来，您应该看到以下页面，这意味着您的帐户已成功创建：

![图 1.6：确认页面](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_06.jpg)

图 1.6：确认页面

在这个练习中，您成功地创建了您的 MongoDB 帐户。

# MongoDB Atlas 组织、项目、用户和集群

MongoDB Atlas 对您的环境强制执行基本结构。这包括组织、项目、用户和集群的概念。MongoDB 提供了一个默认组织和一个项目，以帮助您轻松入门。本节将教您这些实体的含义以及如何设置它们。

## 组织

MongoDB Atlas 组织是您帐户中的顶级实体，包含其他元素，如项目、集群和用户。在任何其他资源之前，您需要首先设置一个组织。

## 练习 1.02：设置 MongoDB Atlas 组织

您已成功在 MongoDB Atlas 上创建了一个帐户，在这个练习中，您将根据自己的偏好设置一个组织：

1.  登录到您在*练习 1.01*中创建的 MongoDB 帐户，*设置 MongoDB Atlas 帐户*。要创建一个组织，请从您的帐户菜单中选择“组织”选项，如下图所示：![图 1.7：用户选项-组织](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_07.jpg)

图 1.7：用户选项-组织

1.  您将在组织列表中看到默认组织。要创建一个新组织，请单击右上角的“创建新组织”按钮：![图 1.8：组织列表](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_08.jpg)

图 1.8：组织列表

1.  在“命名您的组织”字段中输入组织名称。将“云服务”默认选择为`MongoDB Atlas`。单击“下一步”以继续下一步：![图 1.9：组织名称](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_09.jpg)

图 1.9：组织名称

您将看到以下屏幕：

![图 1.10：创建组织页面](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_10.jpg)

图 1.10：创建组织页面

1.  您将看到您的登录作为“组织所有者”。将一切保持默认设置，然后单击“创建组织”。

成功创建组织后，将出现以下“项目”屏幕：

![图 1.11：项目页面](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_11.jpg)

图 1.11：项目页面

因此，在本练习中，您已成功为您的 MongoDB 应用程序创建了组织。

## 项目

项目为特定目的提供了集群和用户的分组；例如，您想要将您的实验室、演示和生产环境进行分隔。同样，您可能希望为不同的环境设置不同的网络、区域和用户。项目允许您根据自己的组织需求进行分组。在下一个练习中，您将创建一个项目。

## 练习 1.03：创建 MongoDB Atlas 项目

在本练习中，您将使用以下步骤在 MongoDB Atlas 上设置一个项目：

1.  一旦您在*练习 1.02*中创建了一个组织，下次登录时将会出现“项目”屏幕。单击“新建项目”：![图 1.12：项目页面](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_12.jpg)

图 1.12：项目页面

1.  在“命名您的项目”选项卡上为您的项目提供一个名称。将项目命名为`myMongoProject`。单击“下一步”：![图 1.13：创建项目页面](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_13.jpg)

图 1.13：创建项目页面

1.  单击“创建项目”。“添加成员和设置权限”页面不是必需的，因此将其保留为默认设置。您的名称应该显示为“项目所有者”：![图 1.14：为项目添加成员并设置权限](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_14.jpg)

图 1.14：为项目添加成员并设置权限

您的项目现在已经设置好。设置集群的启动画面如下图所示：

![图 1.15：集群页面](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_15.jpg)

图 1.15：集群页面

现在您已经创建了一个项目，您可以创建您的第一个 MongoDB 云部署。

## MongoDB 集群

MongoDB 集群是 MongoDB Atlas 中用于数据库副本集或共享部署的术语。集群是用于数据存储和检索的一组分布式服务器。MongoDB 集群在最低级别上是一个由三个节点组成的副本集。在分片环境中，单个集群可能包含数百个节点/服务器，每个节点/服务器包含不同的副本集，每个副本集由至少三个节点/服务器组成。

## 练习 1.04：在 Atlas 上设置您的第一个免费 MongoDB 集群

在本节中，您将在 Atlas 免费版（M0）上设置您的第一个 MongoDB 副本集。以下是执行此操作的步骤：

1.  前往[`www.mongodb.com/cloud/atlas`](https://www.mongodb.com/cloud/atlas)并使用*练习 1.01*中使用的凭据登录您的账户，*设置 MongoDB Atlas 账户*。将出现以下屏幕：![图 1.16：集群页面](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_16.jpg)

图 1.16：集群页面

1.  单击“构建集群”以配置您的集群：![图 1.17：构建集群页面](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_17.jpg)

图 1.17：构建集群页面

将出现以下集群选项：

![图 1.18：可用的集群选项](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_18.jpg)

图 1.18：可用的集群选项

1.  选择标记为“免费”的“共享集群”选项，如前图所示。

1.  将呈现一个集群配置屏幕，以选择集群的不同选项。选择您选择的云提供商。在本练习中，您将使用 AWS，如下图所示：![图 1.19：选择云提供商和区域](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_19.jpg)

图 1.19：选择云提供商和区域

1.  选择最靠近您位置且免费的`推荐区域`。在本例中，您将选择`悉尼`，如下图所示：![图 1.20：选择推荐的区域](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_20.jpg)

图 1.20：选择推荐的区域

在区域选择页面上，您将根据您的选择看到您的集群设置。`Cluster Tier`将是`M0 Sandbox(Shared RAM, 512 MB storage)`，`Additional Settings`将是`MongoDB 4.2 No Backup`，`Cluster Name`将是`Cluster0`：

![图 1.21：集群的附加设置](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_21.jpg)

图 1.21：集群的附加设置

1.  确保在前面的步骤中正确进行选择，以便成本显示为“免费”。与前面步骤中推荐的选择不同的任何选择都可能为您的集群增加成本。点击“创建集群”：![图 1.22：免费套餐通知](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_22.jpg)

图 1.22：免费套餐通知

屏幕上会出现“正在创建您的集群…”的成功消息。通常需要几分钟来设置集群：

![图 1.23：MongoDB 集群正在创建](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_23.jpg)

图 1.23：正在创建 MongoDB 集群

几分钟后，您应该会看到您的新集群，如下图所示：

![图 1.24：MongoDB 集群已创建](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_24.jpg)

图 1.24：MongoDB 集群已创建

您已成功创建了一个新的集群。

## 连接到您的 MongoDB Atlas 集群

以下是连接到在云上运行的 MongoDB Atlas 集群的步骤：

1.  转到[`account.mongodb.com/account/login`](https://account.mongodb.com/account/login)。将出现以下窗口：![图 1.25：MongoDB Atlas 登录页面](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_25.jpg)

图 1.25：MongoDB Atlas 登录页面

1.  提供您的电子邮件地址并点击“下一步”：![图 1.26：MongoDB Atlas 登录页面（密码）](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_26.jpg)

图 1.26：MongoDB Atlas 登录页面（密码）

1.  现在输入您的`密码`并点击`登录`。`Clusters`窗口将如下图所示出现：![图 1.27：MongoDB Atlas 集群屏幕](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_27.jpg)

图 1.27：MongoDB Atlas 集群屏幕

1.  点击`Cluster0`下的`CONNECT`按钮。它将打开一个模态屏幕，如下所示：![图 1.28：MongoDB Atlas 模态屏幕](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_28.jpg)

图 1.28：MongoDB Atlas 模态屏幕

在连接到集群之前的第一步是将您的 IP 地址加入白名单。MongoDB Atlas 具有默认启用的内置安全功能，它会阻止从任何地方连接到数据库。因此，需要将客户端 IP 加入白名单才能连接到数据库。

1.  点击“添加您当前的 IP 地址”以将您的 IP 地址加入白名单，如下图所示：![图 1.29：添加您当前的 IP 地址](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_29.jpg)

图 1.29：添加您当前的 IP 地址

1.  屏幕上将显示您当前的 IP 地址；只需点击“添加 IP 地址”按钮。如果您希望将更多 IP 地址添加到白名单中，可以通过点击“添加不同的 IP 地址”选项手动添加（见上图）：![图 1.30：添加您当前的 IP 地址](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_30.jpg)

图 1.30：添加您当前的 IP 地址

一旦 IP 被加入白名单，将出现以下消息：

![图 1.31：IP 已加入白名单的消息](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_31.jpg)

图 1.31：IP 已加入白名单的消息

1.  要创建一个新的 MongoDB 用户，请为新用户提供`用户名`和`密码`，然后点击“创建数据库用户”按钮以创建用户，如下图所示：![图 1.32：创建 MongoDB 用户](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_32.jpg)

图 1.32：创建 MongoDB 用户

一旦详细信息成功更新，将出现以下屏幕：

![图 1.33：MongoDB 用户创建屏幕](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_33.jpg)

图 1.33：MongoDB 用户创建屏幕

1.  要选择连接方法，请单击“选择连接方法”按钮。选择如下所示的使用 mongo shell 连接的选项：![图 1.34：选择连接类型](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_34.jpg)

图 1.34：选择连接类型

1.  通过选择工作站/客户端机器的选项来下载和安装 mongo shell，如下截图所示：![图 1.35：安装 mongo shell](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_35.jpg)

图 1.35：安装 mongo shell

mongo shell 是连接到 Mongo 服务器的命令行客户端。您将在整本书中使用这个客户端，因此安装它是至关重要的。

1.  安装了 mongo shell 后，运行您在上一步中获取的连接字符串以连接到您的数据库。提示时，请输入您在上一步中为 MongoDB 用户使用的密码：![图 1.36：安装 mongo shell](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_36.jpg)

图 1.36：安装 mongo shell

如果一切顺利，您应该看到 mongo shell 已连接到您的 Atlas 集群。以下是连接字符串执行的示例输出：

![图 1.37：连接字符串执行的输出](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_37.jpg)

图 1.37：连接字符串执行的输出

忽略*图 1.37*中看到的警告。最后，您应该看到您的集群名称和命令提示符。您可以运行`show databases`命令来列出现有的数据库。您应该看到 MongoDB 用于管理目的的两个数据库。以下是`show databases`命令的一些示例输出：

```js
MongoDB Enterprise Cluster0-shard-0:PRIMARY> show databases
admin  0.000GB
local  4.215GB
```

您已成功连接到 MongoDB Atlas 实例。

## MongoDB 元素

让我们深入了解 MongoDB 的一些非常基本的元素，如数据库、集合和文档。数据库基本上是集合的聚合，而集合又由文档组成。文档是 MongoDB 中的基本构建块，包含以键值格式存储的各种字段的信息。

## 文档

MongoDB 将数据记录存储在文档中。文档是一组字段名称和值，以**JavaScript 对象表示法**（**JSON**）类似的格式结构化。JSON 是一种易于理解的键值对格式，用于描述数据。MongoDB 中的文档存储为 JSON 类型的扩展，称为 BSON（二进制 JSON）。它是 JSON 样式文档的二进制编码序列化。BSON 设计为比标准 JSON 更有效地利用空间。BSON 还包含扩展，允许表示无法在 JSON 中表示的数据类型。我们将在*第二章*，*文档和数据类型*中详细讨论这些。

## 文档结构

MongoDB 文档包含字段和值对，并遵循基本结构，如下所示：

```js
{
     "firstFieldName": firstFieldValue,
     "secondFieldName": secondFieldValue,
     …
     "nthFieldName": nthFieldValue
}
```

以下是一个包含有关个人详细信息的文档示例：

```js
{
    "_id":ObjectId("5da26111139a21bbe11f9e89"),
    "name":"Anita P",
    "placeOfBirth":"Koszalin",
    "profession":"Nursing"
}
```

以下是另一个包含来自 BSON 的一些字段和日期类型的示例：

```js
{
    "_id" : ObjectId("5da26553fb4ef99de45a6139"),
    "name" : "Roxana",
    "dateOfBirth" : new Date("Dec 25, 2007"),
    "placeOfBirth" : "Brisbane",
    "profession" : "Student"
}
```

以下文档示例包含一个数组和一个子文档。数组是一组值，当您需要为爱好等键存储多个值时可以使用。子文档允许您将相关属性包装在一个文档中，以对抗一个键，如地址：

```js
{
    "_id" : ObjectId("5da2685bfb4ef99de45a613a"),
    "name" : "Helen",
    "dateOfBirth" : new Date("Dec 25, 2007"),
    "placeOfBirth" : "Brisbane",
    "profession" : "Student",
    "hobbies" : [
     "painting",
     "football",
     "singing",
     "story-writing"],
    "address" : {
     "city" : "Sydney",
    "country" : "Australia",
    "postcode" : 2161
  }
}
```

在上面片段中显示的`_id`字段是由 MongoDB 自动生成的，用作文档的唯一标识符。我们将在接下来的章节中了解更多关于这个。

## 集合

在 MongoDB 中，文档存储在集合中。集合类似于关系数据库中的表。您需要在查询中使用集合名称进行操作，如插入、检索、删除等。

## 理解 MongoDB 数据库

数据库是一组集合的容器。每个数据库在文件系统上有几个文件，这些文件包含数据库元数据和集合中存储的实际数据。MongoDB 允许您拥有多个数据库，每个数据库可以有各种集合。反过来，每个集合可以有许多文档。这在下图中有所说明，显示了一个包含不同事件相关字段的事件数据库，如*Person*、*Location*和*Events*；这些又包含各种具体数据的文档：

![图 1.38：MongoDB 数据库的图示表示](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_01_38.jpg)

图 1.38：MongoDB 数据库的图示表示

## 创建一个数据库

在 MongoDB 中创建数据库非常简单。执行 mongo shell 中的`use`命令，如下所示，将`yourDatabaseName`替换为您自己选择的数据库名称：

```js
use yourDatabaseName
```

如果数据库不存在，Mongo 将创建数据库并将当前数据库切换到新数据库。如果数据库存在，Mongo 将引用现有数据库。以下是最后一个命令的输出：

```js
switched to db yourDatabaseName
```

注意

命名约定和使用逻辑名称总是有帮助的，即使您正在进行一个学习项目。项目名称应该被更有意义的内容替换，以便以后使用时更容易理解。这个规则适用于我们创建的任何资产的名称，所以尽量使用逻辑名称。

## 创建一个集合

您可以使用`createCollection`命令来创建一个集合。这个命令允许您为您的集合使用不同的选项，比如固定大小的集合、验证、排序等。创建集合的另一种方法是通过在不存在的集合中插入文档。在这种情况下，MongoDB 会检查集合是否存在，如果不存在，它将在插入传递的文档之前创建集合。我们将尝试利用这两种方法来创建一个集合。

要显式创建集合，请使用以下语法中的`createCollection`操作：

```js
db.createCollection( '<collectionName>',
{
     capped: <boolean>,
     autoIndexId: <boolean>,
     size: <number>,
     max: <number>,
     storageEngine: <document>,
     validator: <document>,
     validationLevel: <string>,
     validationAction: <string>,
     indexOptionDefaults: <document>,
     viewOn: <string>,
     pipeline: <pipeline>,
     collation: <document>,
     writeConcern: <document>
})
```

在下面的代码片段中，我们创建了一个最多包含 5 个文档的固定大小集合，每个文档的大小限制为 256 字节。固定大小集合的工作原理类似于循环队列，这意味着当达到最大大小时，旧文档将被删除以为最新插入腾出空间。

```js
db.createCollection('myCappedCollection',
{
     capped: true,
     size: 256,
     max: 5
})
```

以下是`createCollection`命令的输出：

```js
{
        «ok» : 1,
        «$clusterTime» : {
                «clusterTime» : Timestamp(1592064731, 1),
                «signature» : {
                        «hash» : BinData(0,»XJ2DOzjAagUkftFkLQIT                           9W2rKjc="),
                        «keyId» : NumberLong(«6834058563036381187»)
                }
        },
        «operationTime» : Timestamp(1592064731, 1)
}
```

不要太担心前面的选项，因为它们都不是必需的。如果您不需要设置其中任何一个，那么您的`createCollection`命令可以简化如下：

```js
db.createCollection('myFirstCollection')
```

这个命令的输出应该如下所示：

```js
{
        «ok» : 1,
        «$clusterTime» : {
                «clusterTime» : Timestamp(1597230876, 1),
                «signature» : {
                        «hash» : BinData(0,»YO8Flg5AglrxCV3XqEuZG                           aaLzZc="),
                        «keyId» : NumberLong(«6853300587753111555»)
                }
        },
        «operationTime» : Timestamp(1597230876, 1)
}
```

## 使用文档插入创建集合

在插入文档之前不需要创建集合。如果在第一次插入文档时集合不存在，MongoDB 会创建一个集合。您可以按照以下方法使用这种方法：

```js
use yourDatabaseName;
db.myCollectionName.insert(
{
    "name" : "Yahya A",  "company" :  "Sony"}
);
```

您的命令输出应该如下所示：

```js
WriteResult({ "nInserted" : 1 })
```

前面的输出返回插入到集合中的文档数量。由于您在不存在的集合中插入了一个文档，MongoDB 必须在插入此文档之前为我们创建集合。为了确认这一点，使用以下命令显示您的集合列表：

```js
show collections;
```

您的命令输出应该显示数据库中集合的列表，类似于这样：

```js
myCollectionName
```

## 创建文档

正如您在前一节中注意到的，我们使用`insert`命令将文档放入集合中。让我们看一下`insert`命令的几种变体。

### 插入单个文档

`insertOne`命令用于一次插入一个文档，如下所示：

```js
db.blogs.insertOne(
  { username: "Zakariya", noOfBlogs: 100, tags: ["science",    "fiction"]
})
```

`insertOne`操作返回新插入文档的`_id`值。以下是`insertOne`命令的输出：

```js
{
  "acknowledged" : true,
  "insertedId" : ObjectId("5ea3a1561df5c3fd4f752636")
}
```

注意

`insertedId`是插入的文档的唯一 ID，它不会与输出中提到的相同。

### 插入多个文档

`insertMany`命令一次插入多个文档。您可以将文档数组传递给命令，如下面的代码段中所述：

```js
db.blogs.insertMany(
[
      { username: "Thaha", noOfBlogs: 200, tags: ["science",       "robotics"]},
      { username: "Thayebbah", noOfBlogs: 500, tags: ["cooking",     "general knowledge"]},
      { username: "Thaherah", noOfBlogs: 50, tags: ["beauty",        "arts"]}
]
)
```

输出返回所有新插入文档的`_id`值：

```js
{
  «acknowledged» : true,
  «insertedIds» : [
    ObjectId(«5f33cf74592962df72246ae8»),
    ObjectId(«5f33cf74592962df72246ae9»),
    ObjectId(«5f33cf74592962df72246aea»)
  ]
}
```

### 从 MongoDB 获取文档

MongoDB 提供`find`命令从集合中获取文档。此命令对于检查插入的文档是否实际保存在集合中非常有用。以下是`find`命令的语法：

```js
db.collection.find(query, projection)
```

该命令接受两个可选参数：`query`和`projection`。`query`参数允许您传递一个文档以在`find`操作期间应用过滤器。`projection`参数允许您从返回的文档中选择所需的属性，而不是所有属性。当在`find`命令中不传递参数时，将返回所有文档。

### 使用`pretty()`方法格式化查找输出

当`find`命令返回多个记录时，有时很难阅读它们，因为它们没有适当的格式。MongoDB 提供了`pretty()`方法，可以在`find`命令的末尾以格式化的方式获取返回的记录。要查看它的操作，请在名为`records`的集合中插入一些记录：

```js
db.records.insertMany(
[
  { Name: "Aaliya A", City: "Sydney"},
  { Name: "Naseem A", City: "New Delhi"}
]
)
```

它应该生成以下输出：

```js
{
  "acknowledged" : true,
  "insertedIds" : [
    ObjectId("5f33cfac592962df72246aeb"),
    ObjectId("5f33cfac592962df72246aec")
  ]
}
```

首先，使用`find`命令而不使用`pretty`方法获取这些记录：

```js
db.records.find()
```

它应该返回如下所示的输出：

```js
{ "_id" : ObjectId("5f33cfac592962df72246aeb"), "Name" : "Aaliya A",   "City" : "Sydney" }
{ "_id" : ObjectId("5f33cfac592962df72246aec"), "Name" : "Naseem A",   "City" : "New Delhi" }
```

现在，使用`pretty`方法运行相同的`find`命令：

```js
db.records.find().pretty()
```

它应该以如下所示的美观格式返回相同的记录：

```js
{
  "_id" : ObjectId("5f33cfac592962df72246aeb"),
  "Name" : "Aaliya A",
  "City" : "Sydney"
}
{
  "_id" : ObjectId("5f33cfac592962df72246aec"),
  "Name" : "Naseem A",
  "City" : "New Delhi"
}
```

显然，当您查看多个或嵌套文档时，`pretty()`方法可能非常有用，因为输出更容易阅读。

## 活动 1.01：设置电影数据库

您是一家公司的创始人，该公司制作来自世界各地的电影软件。您的团队没有太多的数据库管理技能，也没有预算来雇佣数据库管理员。您的任务是提供部署策略和基本的数据库架构/结构，并设置电影数据库。

以下步骤将帮助您完成此活动：

1.  连接到您的数据库。

1.  创建名为`moviesDB`的电影数据库。

1.  创建一个电影集合并插入以下示例数据：[`packt.live/3lJXKuE`](https://packt.live/3lJXKuE)。

```js
[
    {
        "title": "Rocky",
        "releaseDate": new Date("Dec 3, 1976"),
        "genre": "Action",
        "about": "A small-time boxer gets a supremely rare chance           to fight a heavy-  weight champion in a bout in           which he strives to go the distance for his self-respect.",
        "countries": ["USA"],
        "cast" : ["Sylvester Stallone","Talia Shire",          "Burt Young"],
        "writers" : ["Sylvester Stallone"],
        "directors" : ["John G. Avildsen"]
    },
    {
        "title": "Rambo 4",
        "releaseDate ": new Date("Jan 25, 2008"),
        "genre": "Action",
        "about": "In Thailand, John Rambo joins a group of           mercenaries to venture into war-torn Burma, and rescue           a group of Christian aid workers who were kidnapped           by the ruthless local infantry unit.",
        "countries": ["USA"],
        "cast" : [" Sylvester Stallone", "Julie Benz",           "Matthew Marsden"],
        "writers" : ["Art Monterastelli",          "Sylvester Stallone"],
        "directors" : ["Sylvester Stallone"]
    }
]
```

1.  通过获取文档来检查文档是否已插入。

1.  使用以下数据创建一个`awards`集合中的一些记录：

```js
{
    "title": "Oscars",
    "year": "1976",
    "category": "Best Film",
    "nominees": ["Rocky","All The President's Men","Bound For       Glory","Network","Taxi Driver"],
    "winners" :
    [
        {
            "movie" : "Rocky"
        }
    ]
}
{
    "title": "Oscars",
    "year": "1976",
    "category": "Actor In A Leading Role",
    "nominees": ["PETER FINCH","ROBERT DE NIRO",      "GIANCARLO GIANNINI","WILLIAM  HOLDEN","SYLVESTER STALLONE"],
    "winners" :
    [
        {
            "actor" : "PETER FINCH",
            "movie" : "Network"
        }
    ]
}
```

1.  通过获取文档来检查您的插入是否按预期保存在集合中。

注意

此活动的解决方案可以通过此链接找到。

# 摘要

我们开始本章时，介绍了数据、数据库、RDBMS 和 NoSQL 数据库的基础知识。您了解了 RDBMS 和 NoSQL 数据库之间的区别，以及如何决定哪种数据库适合特定的场景。您了解到 MongoDB 可以用作自管理或作为 DbaaS，设置了 MongoDB Atlas 中的帐户，并审查了不同云平台上的 MongoDB 部署以及如何估算其成本。我们通过 MongoDB 结构及其基本组件（如数据库、集合和文档）结束了本章。在下一章中，您将利用这些概念来探索 MongoDB 组件及其数据模型。


# 第二章：文档和数据类型

概述

本章介绍了 MongoDB 文档、它们的结构和数据类型。对于那些对 JSON 模型不熟悉的人来说，本章也将作为 JSON 的简要介绍。您将识别 JSON 文档的基本概念和数据类型，并将 MongoDB 的基于文档的存储与关系数据库的表格存储进行比较。您将学习如何在 MongoDB 中使用嵌入对象和数组表示复杂的数据结构。通过本章的学习，您将了解对 MongoDB 文档的预防性限制和限制的需求。

# 介绍

在上一章中，我们了解了作为 NoSQL 数据库的 MongoDB 与传统关系数据库的不同之处。我们涵盖了 MongoDB 的基本特性，包括其架构、不同版本和 MongoDB Atlas。

MongoDB 是为现代应用程序设计的。我们生活在一个需求迅速变化的世界。我们希望构建轻量灵活的应用程序，能够快速适应这些新需求，并尽快将其部署到生产环境中。我们希望我们的数据库变得敏捷，以便能够适应应用程序不断变化的需求，减少停机时间，轻松扩展，并且性能高效。MongoDB 完全符合所有这些需求。

使 MongoDB 成为一种敏捷数据库的主要因素之一是其基于文档的数据模型。文档被广泛接受为传输信息的灵活方式。您可能已经遇到许多以 JSON 文档形式交换数据的应用程序。MongoDB 以二进制 JSON（BSON）格式存储数据，并以人类可读的 JSON 表示数据。这意味着当我们使用 MongoDB 时，我们看到的数据是以 JSON 格式呈现的。本章以 JSON 和 BSON 格式的概述开始，然后介绍 MongoDB 文档和数据类型的详细信息。

# JSON 介绍

JSON 是一种用于数据表示和传输的全文本、轻量级格式。JavaScript 对对象的简单表示形式催生了 JSON。道格拉斯·克罗克福德（Douglas Crockford）是 JavaScript 语言的开发人员之一，他提出了 JSON 规范的建议，定义了 JSON 语法的语法和数据类型。

JSON 规范于 2013 年成为标准。如果您已经开发了一段时间的应用程序，您可能已经看到应用程序从 XML 转换为 JSON 的过渡。JSON 提供了一种人类可读的纯文本表示数据的方式。与 XML 相比，其中信息被包裹在标签内，而且大量标签使其看起来笨重，JSON 提供了一种紧凑和自然的格式，您可以轻松地专注于信息。

为了以 JSON 或 XML 格式读取或写入信息，编程语言使用它们各自的解析器。由于 XML 文档受模式定义和标签库定义的约束，解析器需要做大量工作来读取和验证 XML 模式定义（XSD）和标签库描述符（TLD）。

另一方面，JSON 没有任何模式定义，JSON 解析器只需要处理开放和关闭括号以及冒号。不同的编程语言有不同的表示语言构造的方式，例如对象、列表、数组、变量等。当两个用不同编程语言编写的系统想要交换数据时，它们需要有一个共同约定的标准来表示信息。JSON 以其轻量级格式提供了这样的标准。任何编程语言的对象、集合和变量都可以自然地适应 JSON 结构。大多数编程语言都有解析器，可以将它们自己的对象转换为 JSON 文档，反之亦然。

注意

JSON 不会将 JavaScript 语言内部规定强加给其他语言。JSON 是语言无关数据表示的语法。定义 JSON 格式的语法是从 JavaScript 的语法派生出来的。然而，为了使用 JSON，程序员不需要了解 JavaScript 的内部。

## JSON 语法

JSON 文档或对象是一组零个或多个键值对的纯文本。键值对形成一个对象，如果值是零个或多个值的集合，它们形成一个数组。JSON 具有非常简单的结构，只需使用一组大括号`{}`、方括号`[]`、冒号`:`和逗号`,`，就可以以紧凑的形式表示任何复杂的信息。

在 JSON 对象中，键值对被包含在大括号`{}`中。在对象内，键始终是一个字符串。然而，值可以是 JSON 指定的任何类型。JSON 语法规范没有为 JSON 字段定义任何顺序，可以表示如下：

```js
{
  key : value
}
```

前面的文件代表一个有效的 JSON 对象，其中有一个键值对。接下来是 JSON 数组，数组是一组零个或多个值，这些值被包含在方括号`[]`中，并用逗号分隔。虽然大多数编程语言支持有序数组，但 JSON 的规范并未指定数组元素的顺序。让我们看一个例子，其中有三个字段，用逗号分隔：

```js
[
  value1,
  value2,
  value3
]
```

现在我们已经看过了 JSON 的语法，让我们考虑一个包含公司基本信息的示例 JSON 文档。这个例子展示了信息如何以文档格式自然地呈现，使其易于阅读：

```js
{
  "company_name" : "Sparter",
  "founded_year" : 2007,
  "twitter_username" : null,
  "address" : "15 East Street",
  "no_of_employees" : 7890,
  "revenue" : 879423000
}
```

从前面的文件中，我们可以看到以下内容：

+   公司名称和地址，都是字符串字段

+   成立年份、员工人数和收入作为数字字段

+   公司的 Twitter 用户名为空或没有信息

## JSON 数据类型

与许多编程语言不同，JSON 支持一组有限和基本的数据类型，如下：

+   **字符串**：指纯文本

+   **数字**：包括所有数字字段

+   `True`或`False`

+   **对象**：其他嵌入的 JSON 对象

+   **数组**：字段的集合

+   **Null**：特殊值，表示没有任何值的字段

JSON 被广泛接受的一个主要原因是它的独立于语言的格式。不同的语言有不同的数据类型。一些语言支持**静态类型变量**，而一些支持**动态类型变量**。如果 JSON 有许多数据类型，它将更符合许多语言，尽管不是所有语言。

JSON 是一种数据交换格式。当应用程序通过网络传输一条信息时，该信息被序列化为纯字符串。接收应用程序然后将信息反序列化为其对象，以便可以使用。JSON 提供的基本数据类型的存在减少了这个过程中的复杂性。

因此，JSON 在数据类型方面保持简单和最小化。特定于编程语言的 JSON 解析器可以将基本数据类型轻松地关联到语言提供的最具体的类型。

## JSON 和数字

根据 JSON 规范，数字只是一系列数字。它不区分诸如`整数`、`浮点数`或`长整数`之类的数字。此外，它限制了数字的范围限制。这导致在数据传输或表示时具有更大的灵活性。

然而，也存在一些挑战。大多数编程语言以`整数`、`浮点数`或`长整数`的形式表示数字。当一条信息以 JSON 格式呈现时，解析器无法预期整个文档中数值字段的确切格式或范围。为了避免数字格式损坏或数值字段精度丢失，交换数据的双方应事先达成一定的协议并遵循。

例如，假设您正在阅读以 JSON 文档形式呈现的电影记录集。当您查看第一条记录时，您发现`audience_rating`字段是一个`整数`。然而，当您到达下一条记录时，您意识到它是一个`浮点数`：

```js
{audience_rating: 6}
{audience_rating: 7.6}
```

我们将在即将到来的*BSON*部分中看看如何克服这个问题。

## JSON 和日期

您可能已经注意到，JSON 文档不支持`Date`数据类型，所有日期都表示为普通字符串。让我们看一个例子，其中有几个 JSON 文档，每个文档都有一个有效的日期表示：

```js
{"title": "A Swedish Love Story", released: "1970-04-24"}
{"title": "A Swedish Love Story", released: "24-04-1970"}
{"title": "A Swedish Love Story", released: "24th April 1970"}
{"title": "A Swedish Love Story", released: "Fri, 24 Apr 1970"}
```

尽管所有文档表示相同的日期，但它们以不同的格式编写。根据其本地标准，不同的系统使用不同的格式来编写相同的日期和时间实例。

与 JSON 数字的示例一样，交换信息的各方需要在传输过程中标准化`Date`格式。

注意

请记住，JSON 规范定义了数据表示的语法和语法。然而，您如何读取数据取决于语言的解释器和它们的数据交换协议。

## 练习 2.01：创建您自己的 JSON 文档

现在您已经学会了 JSON 语法的基础知识，是时候将这些知识付诸实践了。假设您的组织想要构建一个电影和系列节目的数据集，并且他们想要使用 MongoDB 来存储记录。作为概念验证，他们要求您选择一部随机电影，并以 JSON 格式表示它。

在这个练习中，您将从头开始编写您的第一个基本 JSON 文档，并验证它是否是一个语法上有效的文档。对于这个练习，您将考虑一部样本电影，`美女与野兽`，并参考`电影 ID`、`电影标题`、`发行年份`、`语言`、`IMDb 评分`、`类型`、`导演`和`时长`字段，其中包含以下信息：

```js
Movie Id = 14253
Movie Title = Beauty and the Beast
Release Year = 2016
Language = English
IMDb Rating = 6.4
Genre = Romance
Director = Christophe Gans
Runtime = 112
```

要成功地为上述列出的字段创建一个 JSON 文档，首先将每个字段区分为键值对。执行以下步骤以实现所需的结果：

1.  打开一个 JSON 验证器，例如[`jsonlint.com/`](https://jsonlint.com/)。

1.  将上述信息以 JSON 格式输入，如下所示：

```js
{
  "id" : 14253,
  "title" : "Beauty and the Beast",
  "year" : 2016,
  "language" : "English",
  "imdb_rating" : 6.4,
  "genre" : "Romance",
  "director" : "Christophe Gans",
  "runtime" : 112
}
```

请记住，JSON 文档总是以`{`开头，以`}`结尾。每个元素由冒号(`:`)分隔，键值对由逗号(`,`)分隔。

1.  单击`验证 JSON`以验证代码。以下屏幕截图显示了 JSON 文档的预期输出和有效性：![图 2.1：JSON 文档及其有效性检查](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_02_01.jpg)

图 2.1：JSON 文档及其有效性检查

在这个练习中，您将把一部电影记录建模成文档格式，并创建一个语法上有效的 JSON 对象。要更多地练习它，您可以考虑任何一般项目，比如您最近购买的产品或您阅读的一本书，并将其建模为一个有效的 JSON 文档。在下一节中，我们将简要概述 MongoDB 的 BSON。

# BSON

当您使用数据库客户端（如 mongo shell、MongoDB Compass 或 Mongo Atlas 中的 Collections Browser）与 MongoDB 一起工作时，您总是以人类可读的 JSON 格式看到文档。然而，在内部，MongoDB 文档以一种称为 BSON 的二进制格式存储。BSON 文档不是人类可读的，您永远不需要直接处理它们。在我们详细探讨 MongoDB 文档之前，让我们快速概述一下 BSON 的特性，这些特性有益于 MongoDB 文档结构。

与 JSON 一样，BSON 是由 MongoDB 在 2009 年引入的。尽管它是由 MongoDB 发明的，但许多其他系统也将其用作数据存储或传输的格式。BSON 规范主要基于 JSON，因为它继承了 JSON 的所有优点，如语法和灵活性。它还提供了一些额外的功能，专门设计用于提高存储效率，便于遍历，并避免类型冲突的一些数据类型增强，这些冲突是我们在*JSON 简介*部分中看到的。

由于我们已经详细介绍了 JSON 的特性，让我们专注于 BSON 提供的增强功能：

+   BSON 文档的设计旨在比 JSON 更高效，因为它们占用更少的空间并提供更快的遍历速度。

+   对于每个文档，BSON 存储一些**元信息**，例如字段的长度或子文档的长度。元信息使文档解析和遍历更快。

+   BSON 文档具有**有序数组**。数组中的每个元素都以其索引位置为前缀，并可以使用其索引号进行访问。

+   BSON 提供了许多**额外的数据类型**，如日期、整数、双精度、字节数组等。我们将在下一节中详细介绍 BSON 数据类型。

注意

由于二进制格式，BSON 文档在性质上是紧凑的。但是，一些较小的文档最终占用的空间比具有相同信息的 JSON 文档更多。这是因为每个文档都添加了元信息。但是，对于大型文档，BSON 更节省空间。

现在我们已经完成了对 JSON 和 BSON 增强功能的详细介绍，让我们现在学习一下 MongoDB 文档。

# MongoDB 文档

MongoDB 数据库由集合和文档组成。一个数据库可以有一个或多个集合，每个集合可以存储一个或多个相关的 BSON 文档。与关系型数据库相比，集合类似于表，文档类似于表中的行。但是，与表中的行相比，文档更加灵活。

关系型数据库由行和列组成的表格数据模型。但是，您的应用程序可能需要支持更复杂的数据结构，例如嵌套对象或对象集合。表格数据库限制了这种复杂数据结构的存储。在这种情况下，您将不得不将数据拆分成多个表，并相应地更改应用程序的对象结构。另一方面，MongoDB 的基于文档的数据模型允许您的应用程序存储和检索更复杂的对象结构，因为文档具有灵活的类似 JSON 的格式。

以下列表详细介绍了 MongoDB 基于文档的数据模型的一些主要特性：

1.  文档提供了一种灵活和自然的表示数据的方式。数据可以按原样存储，而无需将其转换为数据库结构。

1.  文档中的对象、嵌套对象和数组与您编程语言的对象结构容易相关联。

1.  具有灵活模式的能力使文档在实践中更加灵活。它们可以持续集成应用程序的变化和新功能，而无需进行任何重大的模式更改或停机。

1.  文档是自包含的数据片段。它们避免了阅读多个关系表和表连接以理解完整信息单元的需要。

1.  文档是可扩展的。您可以使用文档来存储整个对象结构，将其用作映射或字典，作为快速查找的键值对，或者具有类似关系表的扁平结构。

## 文档和灵活性

正如前面所述，MongoDB 文档是一种灵活的存储数据的方式。考虑以下示例。想象一下，您正在开发一个电影服务，需要创建一个电影数据库。一个简单的 MongoDB 文档中的电影记录将如下所示：

```js
{"title" : "A Swedish Love Story"}
```

然而，仅存储标题是不够的。您需要更多的字段。现在，让我们考虑一些更基本的字段。在 MongoDB 数据库中有一系列电影，文档将如下所示：

```js
{
  "id" : 1122,
  "title" : "A Swedish Love Story",
  "release_date" : ISODate("1970-04-24T00:00:00Z"),
  "user_rating" : 6.7
}
{
  "id" : 1123,
  "title" : "The Stunt Man",
  "release_date" : ISODate("1980-06-26T00:00:00Z"),
  "user_rating" : 7.8
}
```

假设您正在使用 RDBMS 表。在 RDBMS 平台上，您需要在开始时定义您的模式，为此，首先您必须考虑列和数据类型。然后，您可能会提出一个`CREATE TABLE`查询，如下所示：

```js
CREATE TABLE movies(
  id INT,
  title VARCHAR(250),
  release_date DATE,
  user_ratings FLOAT
);
```

这个查询清楚地表明，关系表受到一个叫做`id`字段的定义的限制，而`user_ratings`永远不能是一个字符串。

插入了一些记录后，表将显示为*图 2.2*。这个表和一个 MongoDB 文档一样好：

![图 2.2：电影表](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_02_02.jpg)

图 2.2：电影表

现在，假设您想要在表中列出的每部电影中包括 IMDb 评分，并且今后，所有电影都将在表中包括`imdb_ratings`。对于现有的电影列表，`imdb_ratings`可以设置为`null`：

为了满足这个要求，您将在您的语法中包含一个`ALTER TABLE`查询：

```js
ALTER TABLE movies
ADD COLUMN imdb_ratings FLOAT default null;
```

查询是正确的，但是在某些情况下，表的更改可能会阻塞表一段时间，特别是对于大型数据集。当表被阻塞时，其他读写操作将不得不等待表被更改，这可能导致停机。现在，让我们看看如何在 MongoDB 中解决同样的情况。

MongoDB 支持灵活的模式，并且没有特定的模式定义。在不改变数据库或集合上的任何内容的情况下，您可以简单地插入一个带有额外字段的新电影。集合的行为将与修改后的电影表完全相同，最新插入的将具有`imdb_ratings`，而之前的将返回`null`值。在 MongoDB 文档中，不存在的字段始终被视为`null`。

现在，整个集合将看起来类似于以下的屏幕截图。您会注意到最后一个电影有一个新字段，`imdb_ratings`：

![图 2.3：电影集合的 imdb_ratings 结果](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_02_03.jpg)

图 2.3：电影集合的 imdb_ratings 结果

前面的例子清楚地表明，与表格数据库相比，文档非常灵活。文档可以在不停机的情况下进行更改。

# MongoDB 数据类型

您已经学会了 MongoDB 如何存储类似 JSON 的文档。您还看到了各种文档，并读取了其中存储的信息，并看到了这些文档在存储不同类型的数据结构时有多灵活，无论您的数据有多复杂。

在本节中，您将了解 MongoDB 的 BSON 文档支持的各种数据类型。在文档中使用正确的数据类型非常重要，因为正确的数据类型可以帮助您更有效地使用数据库功能，避免数据损坏，并提高数据的可用性。MongoDB 支持 JSON 和 BSON 中的所有数据类型。让我们详细看看每种类型，以及示例。

## 字符串

字符串是用来表示文本字段的基本数据类型。它是一系列普通字符。在 MongoDB 中，字符串字段是 UTF-8 编码的，因此它们支持大多数国际字符。各种编程语言的 MongoDB 驱动程序在从集合中读取或写入数据时将字符串字段转换为 UTF-8。

一个包含纯文本字符的字符串如下所示：

```js
{
  "name" : "Tom Walter"
}
```

一个包含随机字符和空格的字符串将显示如下：

```js
{
  "random_txt" : "a ! *& ) ( f s f @#$ s"
}
```

在 JSON 中，用双引号括起来的值被视为字符串。考虑以下示例，其中一个有效的数字和日期被双引号括起来，都形成一个字符串：

```js
{
  "number_txt" : "112.1"
}
{
  "date_txt" : "1929-12-31"
}
```

有关 MongoDB 字符串字段的一个有趣事实是，它们支持使用正则表达式进行搜索。这意味着您可以通过提供文本字段的完整值或仅提供部分字符串值来使用正则表达式搜索文档。

## 数字

数字是 JSON 的基本数据类型。 JSON 文档不指定数字是整数，浮点数还是*长*：

```js
{
  "number_of_employees": 50342
}
{
  "pi": 3.14159265359
}
```

但是，MongoDB 支持以下类型的数字：

+   `double`：64 位浮点

+   `int`：32 位有符号整数

+   `long`：64 位无符号整数

+   `decimal`：128 位浮点 - 符合 IEE 754 标准

当您使用编程语言时，您不必担心这些数据类型。您可以简单地使用语言的本机数据类型进行编程。各种语言的 MongoDB 驱动程序负责将语言特定的数字编码为先前列出的数据类型之一。

如果您在 mongo shell 上工作，您将获得三个包装器来处理：`integer`，`long`和`decimal`。 Mongo shell 基于 JavaScript，因此所有文档都以 JSON 格式表示。默认情况下，它将任何数字视为 64 位浮点数。但是，如果要明确使用其他类型，可以使用以下包装器。

`NumberInt`：如果要将数字保存为 32 位整数而不是 64 位浮点数，则可以使用`NumberInt`构造函数：

```js
> var plainNum = 1299
> var explicitInt = NumberInt("1299")
> var explicitInt_double = NumberInt(1299)
```

+   在上面的片段中，第一个数字`plainNum`是使用未提及任何显式数据类型的数字序列初始化的。因此，默认情况下，它将被视为*64 位浮点数*（也称为**double**）。

+   但是，`explicitInt`是使用整数类型构造函数和数字的字符串表示初始化的，因此 MongoDB 将参数中的数字读取为*32 位整数*。

+   但是，在`explicitInt_double`初始化中，构造函数参数中提供的数字没有双引号。因此，它将被视为*64 位浮点数* - 也就是**double** - 并用于形成*32 位整数*。但是，由于提供的数字适合整数范围，因此不会看到任何更改。

+   当您打印上述数字时，它们看起来如下：

图 2.4：plainNum，explicitInt 和 explicitInt_double 的输出

](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_02_04.jpg)

图 2.4：plainNum，explicitInt 和 explicitInt_double 的输出

`NumberLong`：`NumberLong`包装器类似于`NumberInt`。唯一的区别是它们存储为 64 位整数。让我们在 shell 上尝试一下：

```js
> var explicitLong = NumberLong("777888222116643")
> var explicitLong_double = NumberLong(444333222111242)
```

让我们在 shell 中打印文档：

![图 2.5：MongoDB shell 输出](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_02_05.jpg)

图 2.5：MongoDB shell 输出

`NumberDecimal`：此包装器将给定数字存储为 128 位 IEEE 754 十进制格式。`NumberDecimal`构造函数接受数字的字符串和双精度表示：

```js
> var explicitDecimal = NumberDecimal("142.42")
> var explicitDecimal_double = NumberDecimal(142.42)
```

我们将一个十进制数的字符串表示传递给`explicitDecimal`。但是，`explicitDecimal_double`是使用`double`创建的。当我们打印结果时，它们看起来略有不同：

![图 2.6：explicitDecimal 和 explicitDecimal_double 的输出](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_02_06.jpg)

图 2.6：explicitDecimal 和 explicitDecimal_double 的输出

第二个数字已附加尾随零。这是由于数字的内部解析。当我们将双精度值传递给`NumberDecimal`时，参数被解析为 BSON 的双精度，然后转换为具有 15 位数字精度的 128 位小数。

在此转换过程中，十进制数将四舍五入并可能失去精度。让我们看下面的例子：

```js
> var dec = NumberDecimal("5999999999.99999999")
> var decDbl = NumberDecimal(5999999999.99999999)
```

让我们打印数字并检查输出：

图 2.7：dec 和 decDbl 的输出

](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_02_07.jpg)

图 2.7：dec 和 decDbl 的输出

很明显，当双精度值传递给`NumberDecimal`时，存在失去精度的可能。因此，在使用`NumberDecimal`时始终使用基于字符串的构造函数非常重要。

## 布尔值

布尔数据类型用于表示某事是真还是假。因此，有效布尔字段的值要么是`true`，要么是`false`：

```js
{
  "isMongoDBHard": false
}
{
  "amIEnjoying": true
}
```

值没有双引号。如果您用双引号括起来，它们将被视为字符串。

## 对象

对象字段用于表示嵌套或嵌入文档，即其值是另一个有效的 JSON 文档。

让我们看一下来自 airbnb 数据集的以下示例：

```js
{
  "listing_url": "https://www.airbnb.com/rooms/1001265",
  "name": "Ocean View Waikiki Marina w/prkg",
  "summary": "A great location that work perfectly for business,     education, or simple visit.",
  "host":{
    "host_id": "5448114",
    "host_name": "David",
    "host_location": "Honolulu, Hawaii, United States"
  }
}
```

主机字段的值是另一个有效的 JSON。MongoDB 使用点表示法（`.`）来访问嵌入对象。要访问嵌入文档，我们将在 mongo shell 上创建一个列表的变量：

```js
> var listing = {
  "listing_url": "https://www.airbnb.com/rooms/1001265",
  "name": "Ocean View Waikiki Marina w/prkg",
  "summary": "A great location that work perfectly for business,     education, or simple visit.",
  "host": {
    "host_id": "5448114",
    "host_name": "David",
    "host_location": "Honolulu, Hawaii, United States"
  }
}
```

要仅打印主机详细信息，请使用点表示法（`.`）获取嵌入对象，如下所示：

![图 2.8：嵌入对象的输出](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_02_08.jpg)

图 2.8：嵌入对象的输出

使用类似的表示法，您还可以访问嵌入文档的特定字段，如下所示：

```js
> listing.host.host_name
David
```

嵌入文档可以包含其中的更多文档。具有嵌入文档使 MongoDB 文档成为一个自包含的信息片段。要在 RDBMS 数据库中记录相同的信息，您将不得不创建列表和主机作为两个单独的表，并在两者之间创建一个外键引用，并从两个表中获取信息。

除了嵌入文档之外，MongoDB 还支持两个不同集合的文档之间的链接，这类似于具有外键引用。

## 练习 2.02：创建嵌套对象

到目前为止，您的组织对电影表示感到满意。现在他们提出了一个要求，要包括 IMDb 评分和导致评分的投票数。他们还希望包含番茄表评分，其中包括用户评分和评论家评分以及新鲜和烂的分数。您的任务是修改文档，更新`imdb`字段以包括投票数，并添加一个名为`tomatoes`的新字段，其中包含烂番茄评分。

回想一下您在*练习 2.01*中创建的样本电影记录的 JSON 文档，*创建您自己的 JSON 文档*：

```js
{
  "id": 14253,
  "title": "Beauty and the Beast",
  "year": 2016,
  "language": "English",
  "imdb_rating": 6.4,
  "genre": "Romance",
  "director": "Christophe Gans",
  "runtime": 112
}
```

以下步骤将帮助修改 IMDb 评分：

1.  现有的`imdb_rating`字段表示 IMDb 评分，因此添加一个额外的字段来表示投票数。然而，这两个字段彼此密切相关，并且将始终一起使用。因此，将它们组合在一个单独的文档中：

```js
{
  "rating": 6.4, 
  "votes": "17762"
}
```

1.  前面的文档具有两个字段，表示完整的 IMDb 评分。用您刚创建的字段替换当前的`imdb_rating`字段：

```js
{
  "id" : 14253,
  "Title" : "Beauty and the Beast",
  "year" : 2016,
  "language" : "English",
  "genre" : "Romance",
  "director" : "Christophe Gans",
  "runtime" : 112,
  "imdb" :
  {
    "rating": 6.4,
    "votes": "17762"
  }
}
```

这个带有嵌入对象值的`imdb`字段表示 IMDb 评分。现在，添加番茄表评分。

1.  如前所述，番茄表评分包括观众评分和评论家评分，以及新鲜分数和烂分数。与 IMDb 评分一样，`观众评分`和`评论家评分`都将有一个`评分`字段和一个`投票`字段。分别编写这两个文档：

```js
// Viewer Ratings
{
  "rating" : 3.9,
  "votes" : 238
}
// Critic Ratings
{
  "rating" : 4.2,
  "votes" : 8
}
```

1.  由于两个评分相关，将它们组合在一个单独的文档中：

```js
{
  "viewer" : {
    "rating" : 3.9,
    "votes" : 238
  },
  "critic" : {
    "rating" : 4.2,
    "votes" : 8
  }
}
```

1.  根据描述添加`fresh`和`rotten`分数：

```js
{
  "viewer" : {
    "rating" : 3.9,
    "votes" : 238
  },
  "critic" : {
    "rating" : 4.2,
    "votes" : 8
  },
  "fresh" : 96,
  "rotten" : 7
}
```

以下输出表示了我们电影记录中新的`tomatoes`字段的番茄表评分：

```js
{
    "id" : 14253,
    "Title" : "Beauty and the Beast",
    "year" : 2016,
    "language" : "English",
    "genre" : "Romance",
    "director" : "Christophe Gans",
    "runtime" : 112,
    "imdb" : {
        "rating": 6.4,
        "votes": "17762"
    },
    "tomatoes" : {
        "viewer" : {
            "rating" : 3.9,
            "votes" : 238
        },
        "critic" : {
            "rating" : 4.2,
            "votes" : 8
        },
       "fresh" : 96,
       "rotten" : 7
    }
}
```

1.  最后，使用任何在线 JSON 验证器（在我们的案例中，[`jsonlint.com/`](https://jsonlint.com/)）验证您的文档。单击“验证 JSON”以验证代码：![图 2.9：验证 JSON 文档](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_02_09.jpg)

图 2.9：验证 JSON 文档

您的电影记录现在已更新为详细的 IMBb 评分和新的`tomatoes`评分。在这个练习中，您练习了创建两个嵌套文档来表示 IMDb 评分和番茄表评分。现在我们已经涵盖了嵌套或嵌入对象，让我们了解一下数组。

## 数组

具有**数组**类型的字段具有零个或多个值的集合。在 MongoDB 中，数组可以包含的元素数量或文档可以拥有的数组数量没有限制。但是，整个文档大小不应超过 16 MB。考虑以下包含四个数字的示例数组：

```js
> var doc = {
  first_array: [
    4,
    3,
    2,
    1
  ]
}
```

可以使用其索引位置访问数组中的每个元素。在访问特定索引位置上的元素时，索引号用方括号括起来。让我们打印数组中的第三个元素：

```js
> doc.first_array[3]
1
```

注意

索引始终从零开始。索引位置`3`表示数组中的第四个元素。

使用索引位置，您还可以向现有数组添加新元素，如下例所示：

```js
> doc.first_array[4] = 99
```

打印数组后，您将看到第五个元素已正确添加，其中包含索引位置`4`：

```js
> doc.first_array
[ 4, 3, 2, 1, 99 ]
```

就像对象具有嵌入对象一样，数组也可以具有嵌入数组。以下语法将嵌入数组添加到第六个元素中：

```js
> doc.first_array[5] = [11, 12]
[ 11, 12 ]
```

如果打印数组，您将看到嵌入数组如下所示：

```js
> doc.first_array
[ 4, 3, 2, 1, 99, [11, 12]]
>
```

现在，您可以使用方括号`[]`来访问嵌入数组中特定索引的元素，如下所示：

```js
> doc.first_array[5][1]
12
```

数组可以包含任何 MongoDB 有效的数据类型字段。这可以在以下代码片段中看到：

```js
// array of strings
[ "this", "is", "a", "text" ] 
// array of doubles
[ 1.1, 3.2, 553.54 ]
// array of Json objects
[ { "a" : 1 }, { "a" : 2, "b" : 3 }, { "c" : 1 } ] 
// array of mixed elements
[ 12, "text", 4.35, [ 3, 2 ], { "type" : "object" } ]
```

## 练习 2.03：使用数组字段

为了为每部电影添加评论详细信息，您的组织希望您包括评论的全文以及用户详细信息，如姓名、电子邮件和日期。您的任务是准备两条虚拟评论并将它们添加到现有的电影记录中。在*练习 2.02*中，*创建嵌套对象*，您以文档格式开发了一条电影记录，如下所示：

```js
{
  "id" : 14253,
  "Title" : "Beauty and the Beast",
  "year" : 2016,
  "language" : "English",
  "genre" : "Romance",
  "director" : "Christophe Gans",
  "runtime" : 112,
  "imdb" : {
    "rating": 6.4,
    "votes": "17762"
  },
  "tomatoes" : {
    "viewer" : {
      "rating" : 3.9,
      "votes" : 238
    },
    "critic" : {
      "rating" : 4.2,
      "votes" : 8
    },
    "fresh" : 96,
    "rotten" : 7
  }
}
```

通过执行以下步骤构建此文档以添加附加信息：

1.  创建两条评论并列出详细信息：

```js
// Comment #1
Name = Talisa Maegyr
Email = oona_chaplin@gameofthron.es
Text = Rem itaque ad sit rem voluptatibus. Ad fugiat...
Date = 1998-08-22T11:45:03.000+00:00
// Comment #2
Name = Melisandre
Email = carice_van_houten@gameofthron.es
Text = Perspiciatis non debitis magnam. Voluptate...
Date = 1974-06-22T07:31:47.000+00:00
```

1.  将两个注释拆分为单独的文档，如下所示：

```js
// Comment #1
{
  "name" : "Talisa Maegyr",
  "email" : "oona_chaplin@gameofthron.es",
  "text" : "Rem itaque ad sit rem voluptatibus. Ad fugiat...",
  "date" : "1998-08-22T11:45:03.000+00:00"
}
// Comment #2
{
  "name" : "Melisandre",
  "email" : "carice_van_houten@gameofthron.es",
  "text" : "Perspiciatis non debitis magnam. Voluptate...",
  "date" : "1974-06-22T07:31:47.000+00:00"
}
```

有两条评论在两个单独的文档中，您可以轻松地将它们放入电影记录中作为`comment_1`和`comment_2`。但是，随着评论数量的增加，将很难计算它们的数量。为了克服这一点，我们将使用一个数组，它隐式地为每个元素分配索引位置。

1.  将两条评论添加到数组中，如下所示：

```js
[
  {
    "name": "Talisa Maegyr",
    "email": "oona_chaplin@gameofthron.es",
    "text": "Rem itaque ad sit rem voluptatibus. Ad fugiat...",
    "date": "1998-08-22T11:45:03.000+00:00"
  },
  {
    "name": "Melisandre",
    "email": "carice_van_houten@gameofthron.es",
    "text": "Perspiciatis non debitis magnam. Voluptate...",
    "date": "1974-06-22T07:31:47.000+00:00"
  }
]
```

数组为您提供了添加尽可能多的评论的机会。此外，由于隐式索引，您可以自由地通过其专用索引位置访问任何评论。一旦将此数组添加到电影记录中，输出将如下所示：

```js
{
  "id": 14253,
  "Title": "Beauty and the Beast",
  "year": 2016,
  "language": "English",
  "genre": "Romance",
  "director": "Christophe Gans",
  "runtime": 112,
  "imdb": {
    "rating": 6.4,
    "votes": "17762"
  },
  "tomatoes": {
    "viewer": {
      "rating": 3.9,
      "votes": 238
    },
    "critic": {
      "rating": 4.2,
      "votes": 8
    },
    "fresh": 96,
    "rotten": 7
  },
  "comments": [{
    "name": "Talisa Maegyr",
    "email": "oona_chaplin@gameofthron.es",
    "text": "Rem itaque ad sit rem voluptatibus. Ad fugiat...",
    "date": "1998-08-22T11:45:03.000+00:00"
  }, {
    "name": "Melisandre",
    "email": "carice_van_houten@gameofthron.es",
    "text": "Perspiciatis non debitis magnam. Voluptate...",
    "date": "1974-06-22T07:31:47.000+00:00"
  }]
}
```

1.  现在，使用在线验证器（例如，[`jsonlint.com/`](https://jsonlint.com/)）验证 JSON 文档。单击“验证 JSON”以验证代码：![图 2.10：验证 JSON 文档](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_02_10.jpg)

图 2.10：验证 JSON 文档

我们可以看到我们的电影记录现在有用户评论。在这个练习中，我们修改了我们的电影记录以练习创建数组字段。现在是时候转到下一个数据类型，`null`。

## Null

Null 是文档中的一种特殊数据类型，表示不包含值的字段。`null`字段只能有`null`作为值。在下面的示例中，您将打印对象，这将导致`null`值：

```js
> var obj = null
>
> obj
Null
```

在*数组*部分创建的数组上进行构建：

```js
> doc.first_array
[ 4, 3, 2, 1, 99, [11, 12]]
```

现在，创建一个新变量并将其初始化为`null`，通过将变量插入到下一个索引位置：

```js
> var nullField = null
> doc.first_array[6] = nullField
```

现在，打印此数组以查看`null`字段：

```js
> doc.first_array
[ 4, 3, 2, 1, 99, [11, 12], null]
```

## ObjectId

集合中的每个文档都必须有一个包含唯一值的`_id`。这个字段充当这些文档的*主键*。主键用于唯一标识文档，并且它们总是被索引的。`_id`字段的值在集合中必须是唯一的。当您使用任何数据集时，每个数据集代表不同的上下文，并且根据上下文，您可以确定您的数据是否有主键。例如，如果您处理用户数据，用户的电子邮件地址将始终是唯一的，并且可以被视为最合适的`_id`字段。然而，对于一些没有唯一键的数据集，您可以简单地省略`_id`字段。

如果您插入一个没有`_id`字段的文档，MongoDB 驱动程序将自动生成一个唯一 ID 并将其添加到文档中。因此，当您检索插入的文档时，您会发现`_id`是用随机文本的唯一值生成的。当驱动程序自动添加`_id`字段时，该值是使用`ObjectId`生成的。

`ObjectId`值旨在生成跨不同机器唯一的轻量级代码。它生成一个唯一值的 12 个字节，其中前 4 个字节表示时间戳，第 5 到 9 个字节表示随机值，最后 3 个字节是递增计数器。创建并打印`ObjectId`值如下：

```js
> var uniqueID = new ObjectId()
```

在下一行打印`uniqueID`：

```js
> uniqueID
ObjectId("5dv.8ff48dd98e621357bd50")
```

MongoDB 支持一种称为分片的技术，其中数据集被分布并存储在不同的机器上。当一个集合被分片时，它的文档被物理地位于不同的机器上。即使如此，`ObjectId`也可以确保在不同机器上的集合中的值是唯一的。如果使用`ObjectId`字段对集合进行排序，顺序将基于文档创建时间。然而，`ObjectId`中的时间戳是基于秒数到纪元时间。因此，在同一秒内插入的文档可能以随机顺序出现。`ObjectId`上的`getTimestamp()`方法告诉我们文档插入时间。

## 日期

JSON 规范不支持日期类型。JSON 文档中的所有日期都表示为纯字符串。日期的字符串表示形式很难解析、比较和操作。然而，MongoDB 的 BSON 格式明确支持**日期**类型。

MongoDB 日期以自 Unix 纪元以来的毫秒形式存储，即 1970 年 1 月 1 日。为了存储日期的毫秒表示，MongoDB 使用 64 位整数（`long`）。由于这个原因，日期字段的范围大约为自 Unix 纪元以来的+-290 百万年。需要注意的一点是所有日期都以*UTC*存储，并且没有与它们相关联的*时区*。

在 mongo shell 上工作时，您可以使用`Date()`、`new Date()`或`new ISODate()`创建`Date`实例。

注意

使用新的`Date()`构造函数或新的`ISODate()`构造函数创建的日期始终是 UTC 时间，而使用`Date()`创建的日期将是本地时区的时间。下面给出一个例子。

```js
var date = Date()// Sample output
Sat Sept 03 1989 07:28:46 GMT-0500 (CDT)
```

当使用`Date()`类型来构造日期时，它使用 JavaScript 的日期表示，这是以纯字符串形式的。这些日期表示基于您当前的时区的日期和时间。然而，作为字符串格式，它们对于比较或操作是没有用的。

如果将`new`关键字添加到`Date`构造函数中，您将得到包装在`ISODate()`中的 BSON 日期，如下所示：

```js
> var date = new Date()
// Sample output
ISODate("1989-09-03T10:11:23.357Z")
```

您还可以直接使用`ISODate()`构造函数创建`date`对象，如下所示：

```js
> var isoDate = new ISODate()
// Sample output
ISODate("1989-09-03T11:13:26.442Z")
```

这些日期可以被操作、比较和搜索。

注意

根据 MongoDB 文档，不是所有的驱动程序都支持 64 位日期编码。然而，所有的驱动程序都支持编码年份范围从 0 到 9999 的日期。

## 时间戳

时间戳是日期和时间的 64 位表示。在这 64 位中，前 32 位存储自 Unix 纪元时间以来的秒数，即 1970 年 1 月 1 日。另外 32 位表示一个递增的计数器。时间戳类型是 MongoDB 专门用于内部操作的。

## 二进制数据

二进制数据，也称为`BinData`，是一种用于存储以二进制格式存在的数据的 BSON 数据类型。这种数据类型使您能够在数据库中存储几乎任何东西，包括文本、视频、音乐等文件。`BinData`可以与编程语言中的二进制数组进行映射，如下所示：

![图 2.11：二进制数组](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_02_11.jpg)

图 2.11：二进制数组

`BinData`的第一个参数是一个二进制子类型，用于指示存储的信息类型。零值代表普通二进制数据，可以与文本或媒体文件一起使用。`BinData`的第二个参数是*base64*编码的文本文件。您可以在文档中使用二进制数据字段，如下所示：

```js
{
  "name" : "my_txt",
  "extension" : "txt",
  "content" : BinData(0,/
    "VGhpcyBpcyBhIHNpbXBsZSB0ZXh0IGZpbGUu")
}
```

我们将在接下来的部分介绍 MongoDB 的文档大小限制。

# 文档的限制和限制

到目前为止，我们已经讨论了使用文档的重要性和好处。文档在构建高效应用程序中起着重要作用，并且它们提高了整体数据的可用性。我们知道文档以最自然的形式提供了一种灵活的表示数据的方式。它们通常是自包含的，可以容纳完整的信息单元。自包含性来自嵌套对象和数组。

要有效地使用任何数据库，正确的数据结构是很重要的。您今天构建的不正确的数据结构可能会在未来带来很多痛苦。从长远来看，随着应用程序的使用量增加，数据量也会增加，最初似乎很小的问题变得更加明显。然后显而易见的问题就来了：您如何知道您的数据结构是否正确？

您的应用程序会告诉您答案。如果要访问某个信息，您的应用程序必须执行多个查询到数据库，并组合所有结果以获取最终信息，那么它将减慢整体吞吐量。相反，如果数据库上的单个查询返回了太多信息，您的应用程序将不得不扫描整个结果集并获取所需的信息。这将导致更高的内存消耗，过时的对象，最终导致性能下降。

因此，MongoDB 对文档进行了一些限制和限制。需要注意的一点是，这些限制并不是因为数据库的限制或缺陷。这些限制是为了使整体数据库平台能够高效运行。我们已经介绍了 MongoDB 文档提供的灵活性；现在重要的是要了解这些限制。

## 文档大小限制

包含过多信息的文档在许多方面都是不好的。因此，MongoDB 对集合中每个文档的大小限制为 16 MB。16 MB 的限制足以存储正确的信息。一个集合可以有任意多的文档。集合的大小没有限制。即使集合超出了底层系统的空间，您也可以使用垂直或水平扩展来增加集合的容量。

文档的灵活性和自包含性可能会诱使开发人员放入过多的信息并创建臃肿的文档。超大型文档通常是糟糕设计的表现。大多数情况下，您的应用程序并不需要所有的信息。良好的数据库设计考虑了应用程序的需求。

想象一下，你的应用程序是一个提供来自各种商店的销售信息的界面，用户可以按商品类型或商店位置搜索和找到已售出的商品。大部分时间，是你的应用程序会频繁访问数据库，并且使用类似的查询。因此，你的应用程序的需求在数据库设计中起着重要作用，特别是当用户基数增长，你的应用程序开始在短时间内获得成千上万的请求。你所希望的是更快的查询，更少的处理和更少的资源消耗。

超大的文档在资源使用方面也很昂贵。当文档从系统中读取时，它们会被保存在内存中，然后通过网络传输。网络传输总是比较慢的。然后，你的驱动程序会将接收到的信息映射到你编程语言的对象中。更大的文档会导致太多的庞大对象。考虑一个来自虚拟销售记录的样本文档，如下所示：

```js
{
     «_id" : ObjectId("5bd761dcae323e45a93ccff4"),
     «saleDate" : ISODate("2014-08-18T10:42:13.935Z"),
     «items" : [
          {
               «name" : "backpack",
               «tags" : [
                    «school»,
                    «travel»,
                    «kids»
               ],
               «price" : NumberDecimal("187.16"),
               «quantity" : 2
          },
          {
               «name" : "printer paper",
               «tags" : [
                    «office»,
                    «stationary»
               ],
               «price" : NumberDecimal("20.61"),
               «quantity" : 10
          },
          {
               «name" : "notepad",
               «tags" : [
                    «office»,
                    «writing»,
                    «school»
               ],
               «price" : NumberDecimal("23.75"),
               «quantity" : 5
          },
          {
               «name" : "envelopes",
               «tags" : [
                    «stationary»,
                    «office»,
                    «general»
               ],
               «price" : NumberDecimal("9.44"),
               «quantity" : 5
          }
     ],
     «storeLocation" : "San Diego",
     «customer" : {
          «gender" : "F",
          «age" : 59,
          «email" : "la@cevam.tj",
          «satisfaction" : 4
     },
     «couponUsed" : false,
     «purchaseMethod" : "In store"
}
```

虽然这个文档很好，但也有一些限制。`items`字段是`items`对象的数组。如果一个订单有太多的`items`，数组的大小会增加，这将导致整个文档的大小增加。如果你的应用程序允许每个订单有多个项目，并且你的商店有成千上万个独特的项目，这个文档很容易变得过大。处理这种复杂文档的最佳方法是将集合拆分为两个，并在其中嵌入文档链接。

## 嵌套深度限制

MongoDB BSON 文档支持嵌套达到 100 级，这已经足够了。嵌套文档是提供可读数据的好方法。它们一次性提供完整的信息，避免多次查询来收集一部分信息。

然而，随着嵌套级别的增加，性能和内存消耗问题会出现。例如，考虑一个将文档解析为对象结构的驱动程序。在扫描过程中，每当发现一个新的子文档时，扫描器会递归进入嵌套对象，同时保持一个已读信息的堆栈。这会导致内存利用率高和性能慢。

通过设置 100 级的嵌套限制，MongoDB 避免了这些问题。然而，如果无法避免这种深层嵌套，可以考虑将集合拆分为两个或更多，并引用文档。

# 字段名称规则

MongoDB 有一些关于文档字段名称的规则，列举如下：

1.  字段名称不能包含**空**字符。

1.  只有数组或嵌入文档中的字段才能以美元符号（`$`）开头。对于顶级字段，名称不能以美元（`$`）符号开头。

1.  不支持具有重复字段名称的文档。根据 MongoDB 文档，当插入具有重复字段名称的文档时，不会抛出错误，但文档也不会被插入。甚至驱动程序会悄悄地丢弃这些文档。然而，在 mongo shell 中，如果插入这样的文档，它会被正确插入。然而，结果文档只会有第二个字段。这意味着第二次出现的字段会覆盖第一个字段的值。

注意

MongoDB（截至版本 4.2.8）不建议字段名称以美元（`$`）符号或点（`.`）开头。MongoDB 查询语言可能无法正确处理这些字段。此外，驱动程序也不支持它们。

## 练习 2.04：将数据加载到 Atlas 集群中

现在您已经了解了文档及其结构，可以在业务用例上实施您的学习，并观察 MongoDB 文档。在*第一章*，*MongoDB 简介*中，您创建了一个 MongoDB Atlas 账户，并在云上初始化了一个集群。您将在这个集群中加载示例数据集。MongoDB Atlas 提供了可以通过执行几个简单步骤加载到集群中的示例数据集。这些示例数据库是大型的、真实的数据集，供练习使用。MongoDB Atlas 中的示例数据集包括以下数据库，每个数据库都有多个集合：

+   `sample_mflix`

+   `sample_airbnb`

+   `sample_geospatial`

+   `sample_supplies`

+   `sample_training`

+   `sample_weatherdata`

在所有这些数据集中，您将在本书中处理`sample_mflix`数据集。这是一个庞大的数据库，包括超过 23,000 部电影和系列记录，以及它们的评分、评论和其他详细信息。在了解数据库之前，将数据库导入到我们的集群中，并熟悉其结构和组件。

以下是要执行的步骤，以实现所需的结果：

1.  访问[`cloud.mongodb.com/`](https://cloud.mongodb.com/)，并点击登录到您的账户：![图 2.12：Atlas 登录页面](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_02_12.jpg)

图 2.12：Atlas 登录页面

由于您已经在云上创建了一个集群，登录后将显示以下显示集群详细信息的屏幕：

![图 2.13：集群视图](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_02_13.jpg)

图 2.13：集群视图

1.  点击`COLLECTIONS`旁边的（`…`）选项。将出现一个下拉列表，显示以下选项。点击“加载示例数据集”：![图 2.14：加载示例数据集选项](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_02_14.jpg)

图 2.14：加载示例数据集选项

这将打开一个确认对话框，显示将加载到您的集群中的示例数据集的总大小：

![图 2.15：加载示例数据集确认](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_02_15.jpg)

图 2.15：加载示例数据集确认

1.  点击“加载示例数据集”。您将在屏幕上看到一条消息，显示“正在加载您的示例数据集…”：![图 2.16：加载您的示例数据集…窗口](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_02_16.jpg)

图 2.16：加载您的示例数据集…窗口

加载数据并重新部署集群实例可能需要几分钟时间。

1.  数据集成功加载后，您将看到一个成功消息，显示“示例数据集成功加载”：![图 2.17：示例数据集成功加载](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_02_17.jpg)

图 2.17：示例数据集成功加载

数据集加载完成后，您还可以看到图表，显示有关数据集上执行的读取和写入操作数量、总连接数以及数据集的总大小的信息。

1.  现在，点击`COLLECTIONS`。在下一个屏幕上，您将看到以下可用数据库的列表：![图 2.18：示例数据库列表](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_02_18.jpg)

图 2.18：示例数据库列表

1.  点击`sample_mflix`旁边的向下箭头。

1.  选择`movies`集合。

您的前 20 个文档的结果将显示如下：

![图 2.19：集群上的电影集合](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_02_19.jpg)

图 2.19：集群上的电影集合

在这个练习中，我们成功将`sample_mflix`数据库加载到了我们的集群中。现在，让我们进行一个简单的活动，帮助我们将本章学到的所有内容付诸实践。

## 活动 2.01：将推文建模为 JSON 文档

现在您已经了解了 JSON 文档、MongoDB 支持的数据类型以及基于文档的存储模型，是时候练习将现实生活中的实体建模为有效的 JSON 文档格式了。

您的任务是准备一个有效的 JSON 文档来表示推文的数据。为此，请使用*图 2.20*中显示的虚拟推文，从这条推文中识别出所有各种信息，确定字段名称和它们可以表示的数据类型，准备一个包含所有字段的 JSON 文档，并验证您的文档：

![图 2.20：示例推文](https://github.com/OpenDocCN/freelearn-db-zh/raw/master/docs/mongo-fund/img/B15507_02_20.jpg)

图 2.20：示例推文

以下步骤将帮助您实现期望的结果：

1.  列出您在推文中看到的所有对象，例如用户 ID、名称、个人资料图片、推文文本、标签和提及。

1.  识别可以分组在一起的一组相关字段。这些字段组可以作为嵌入对象或数组放置。

1.  创建 JSON 文档后，使用在线可用的任何 JSON 验证器对其进行验证（例如，[`jsonlint.com/`](https://jsonlint.com/)）。

以下代码表示最终的 JSON 文档，只显示了一些字段：

```js
{
  "id": 1,
  "created_at": "Sun Apr 17 16:29:24 +0000 2011",
  "text": "Tweeps in the #north. The long nights are upon us..",
  ...,
  ...,
  ...
}
```

注意

此活动的解决方案可以通过此链接找到。

# 摘要

在本章中，我们已经涵盖了 MongoDB 文档和基于文档的模型的详细结构，在我们深入研究即将到来的更高级概念之前，这是很重要的。我们从以 JSON 样式的文档形式传输和存储信息开始讨论，这提供了一种灵活的、与语言无关的格式。我们研究了 JSON 文档的概述、文档结构和基本数据类型，接着是 BSON 文档规范，以及在各种参数上区分 BSON 和 JSON。

然后，我们涵盖了 MongoDB 文档，考虑到它们的灵活性、自包含性、关联性和灵活性，以及 BSON 提供的各种数据类型。最后，我们注意到了 MongoDB 文档的限制和限制，并学习了为什么会施加这些限制以及它们为什么重要。

在下一章中，我们将使用 mongo shell 和 Mongo Compass 连接到实际的 MongoDB 服务器，并管理用户身份验证和授权。
